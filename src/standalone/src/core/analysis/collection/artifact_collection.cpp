#include "artifact_collection.hpp"
#include "member_graph.hpp"

#include "../subrange_provider.hpp"
#include "../workspace/macho_image.hpp"
#include "../workspace/zip_container.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace aida::analysis {

namespace {

workspace_error_t collection_error(workspace_error_code_t code, std::string message,
                                   const char* phase) {
    return make_workspace_error(code, std::move(message), phase);
}

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = collection_error(workspace_error_code_t::deadline_exceeded,
                                      "collection operation deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = collection_error(workspace_error_code_t::cancelled,
                                  "collection operation cancelled", phase);
    error.cancellation = true;
    return error;
}

bool check_cancel(const cancellation_token_t& cancel, const char* phase) {
    return cancel.stop_requested();
}

constexpr std::uint32_t zip_local_signature = 0x04034b50u;
constexpr std::uint32_t zip_central_signature = 0x02014b50u;
constexpr std::uint32_t zip_eocd_signature = 0x06054b50u;
constexpr std::uint32_t zip64_eocd_locator_signature = 0x07064b50u;
constexpr std::uint32_t macho_fat_magic = 0xCAFEBABEu;
constexpr std::uint32_t macho_fat_64_magic = 0xBEBAFECAu;
constexpr std::uint32_t macho_magic_32_le = 0xFEEDFACEu;
constexpr std::uint32_t macho_magic_32_be = 0xCEFAEDFEu;
constexpr std::uint32_t macho_magic_64_le = 0xFEEDFACFu;
constexpr std::uint32_t macho_magic_64_be = 0xCFFAEDFEu;
constexpr std::uint32_t classfile_magic = 0xCAFEBABEu;
constexpr std::uint16_t pe_dos_signature = 0x5A4Du;
constexpr std::uint32_t pe_nt_signature = 0x00004550u;
constexpr std::uint8_t elf_magic_0 = 0x7Fu;
constexpr std::uint8_t elf_magic_1 = 0x45u;
constexpr std::uint8_t elf_magic_2 = 0x4Cu;
constexpr std::uint8_t elf_magic_3 = 0x46u;

bool probe_bytes(const byte_provider_t& provider, std::uint64_t offset,
                 const std::uint8_t* expected, std::size_t length,
                 const cancellation_token_t& cancel) {
    if (provider.size() < offset + length)
        return false;
    auto result = provider.read_exact(offset, nullptr, 0, cancel);
    if (!result)
        return false;
    std::array<std::uint8_t, 64> buffer{};
    if (length > buffer.size())
        return false;
    auto lease_result = provider.lease(offset, length, cancel);
    if (!lease_result)
        return false;
    const auto& view = lease_result.value();
    if (view.size() < length)
        return false;
    return std::memcmp(view.data(), expected, length) == 0;
}

bool is_zip(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 4)
        return false;
    std::array<std::uint8_t, 4> sig{};
    auto lease = provider.lease(0, 4, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 4)
        return false;
    std::memcpy(sig.data(), view.data(), 4);
    const std::uint32_t signature = static_cast<std::uint32_t>(sig[0]) |
        (static_cast<std::uint32_t>(sig[1]) << 8) |
        (static_cast<std::uint32_t>(sig[2]) << 16) |
        (static_cast<std::uint32_t>(sig[3]) << 24);
    if (signature == zip_local_signature)
        return true;
    if (provider.size() >= 22) {
        const std::uint64_t eocd_search_start = provider.size() > 65557
            ? provider.size() - 65557 : 0;
        const std::uint64_t eocd_search_end = provider.size() - 22;
        for (std::uint64_t offset = eocd_search_end; offset >= eocd_search_start; --offset) {
            auto eocd_lease = provider.lease(offset, 4, cancel);
            if (!eocd_lease)
                break;
            const auto& eocd_view = eocd_lease.value();
            if (eocd_view.size() >= 4) {
                std::uint32_t eocd_sig = static_cast<std::uint32_t>(eocd_view[0]) |
                    (static_cast<std::uint32_t>(eocd_view[1]) << 8) |
                    (static_cast<std::uint32_t>(eocd_view[2]) << 16) |
                    (static_cast<std::uint32_t>(eocd_view[3]) << 24);
                if (eocd_sig == zip_eocd_signature)
                    return true;
            }
            if (offset == 0)
                break;
        }
    }
    return false;
}

bool is_fat_macho(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 8)
        return false;
    auto lease = provider.lease(0, 4, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 4)
        return false;
    const std::uint32_t magic = static_cast<std::uint32_t>(view[0]) << 24 |
        static_cast<std::uint32_t>(view[1]) << 16 |
        static_cast<std::uint32_t>(view[2]) << 8 |
        static_cast<std::uint32_t>(view[3]);
    return magic == macho_fat_magic || magic == macho_fat_64_magic;
}

bool is_macho(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 4)
        return false;
    auto lease = provider.lease(0, 4, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 4)
        return false;
    const std::uint32_t magic = static_cast<std::uint32_t>(view[0]) |
        (static_cast<std::uint32_t>(view[1]) << 8) |
        (static_cast<std::uint32_t>(view[2]) << 16) |
        (static_cast<std::uint32_t>(view[3]) << 24);
    return magic == macho_magic_32_le || magic == macho_magic_32_be ||
           magic == macho_magic_64_le || magic == macho_magic_64_be;
}

bool is_pe(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 64)
        return false;
    auto lease = provider.lease(0, 2, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 2)
        return false;
    const std::uint16_t dos_sig = static_cast<std::uint16_t>(view[0]) |
        (static_cast<std::uint16_t>(view[1]) << 8);
    if (dos_sig != pe_dos_signature)
        return false;
    auto pe_offset_lease = provider.lease(60, 4, cancel);
    if (!pe_offset_lease)
        return false;
    const auto& pe_offset_view = pe_offset_lease.value();
    if (pe_offset_view.size() < 4)
        return false;
    const std::uint32_t pe_offset = static_cast<std::uint32_t>(pe_offset_view[0]) |
        (static_cast<std::uint32_t>(pe_offset_view[1]) << 8) |
        (static_cast<std::uint32_t>(pe_offset_view[2]) << 16) |
        (static_cast<std::uint32_t>(pe_offset_view[3]) << 24);
    if (pe_offset == 0 || pe_offset + 4 > provider.size())
        return false;
    auto nt_lease = provider.lease(pe_offset, 4, cancel);
    if (!nt_lease)
        return false;
    const auto& nt_view = nt_lease.value();
    if (nt_view.size() < 4)
        return false;
    const std::uint32_t nt_sig = static_cast<std::uint32_t>(nt_view[0]) |
        (static_cast<std::uint32_t>(nt_view[1]) << 8) |
        (static_cast<std::uint32_t>(nt_view[2]) << 16) |
        (static_cast<std::uint32_t>(nt_view[3]) << 24);
    return nt_sig == pe_nt_signature;
}

bool is_elf(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 5)
        return false;
    auto lease = provider.lease(0, 5, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 5)
        return false;
    return view[0] == elf_magic_0 && view[1] == elf_magic_1 &&
           view[2] == elf_magic_2 && view[3] == elf_magic_3;
}

bool is_classfile(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    if (provider.size() < 8)
        return false;
    auto lease = provider.lease(0, 4, cancel);
    if (!lease)
        return false;
    const auto& view = lease.value();
    if (view.size() < 4)
        return false;
    const std::uint32_t magic = static_cast<std::uint32_t>(view[0]) << 24 |
        static_cast<std::uint32_t>(view[1]) << 16 |
        static_cast<std::uint32_t>(view[2]) << 8 |
        static_cast<std::uint32_t>(view[3]);
    if (magic != classfile_magic)
        return false;
    auto minor_lease = provider.lease(4, 4, cancel);
    if (!minor_lease)
        return false;
    const auto& version_view = minor_lease.value();
    if (version_view.size() < 4)
        return false;
    const std::uint32_t major = (static_cast<std::uint32_t>(version_view[2]) << 8) |
        static_cast<std::uint32_t>(version_view[3]);
    return major >= 45 && major <= 255;
}

format_id_t detect_format_from_member_path(std::string_view path) noexcept {
    auto dot_pos = path.rfind('.');
    if (dot_pos == std::string_view::npos)
        return format_id_t::unknown;
    auto ext = path.substr(dot_pos);
    auto lower_compare = [](char c) noexcept {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };
    auto match_ext = [&](const char* expected) noexcept {
        std::size_t i = 0;
        for (; i < ext.size() && expected[i] != '\0'; ++i)
            if (lower_compare(ext[i]) != expected[i])
                return false;
        return ext.size() == i && expected[i] == '\0';
    };
    if (match_ext(".dex"))
        return format_id_t::dex;
    if (match_ext(".class"))
        return format_id_t::classfile;
    if (match_ext(".jar"))
        return format_id_t::jar;
    if (match_ext(".zip"))
        return format_id_t::zip;
    if (match_ext(".apk"))
        return format_id_t::apk;
    if (match_ext(".aab"))
        return format_id_t::apk;
    if (match_ext(".ipa"))
        return format_id_t::ipa;
    if (match_ext(".so"))
        return format_id_t::elf;
    if (match_ext(".dll"))
        return format_id_t::pe32_plus;
    if (match_ext(".exe"))
        return format_id_t::pe32_plus;
    if (match_ext(".dylib"))
        return format_id_t::macho;
    if (match_ext(".o"))
        return format_id_t::coff;
    if (match_ext(".pdb"))
        return format_id_t::unknown;
    return format_id_t::unknown;
}

collection_member_kind_t classify_member_by_path(std::string_view path) noexcept {
    auto dot_pos = path.rfind('.');
    if (dot_pos == std::string_view::npos) {
        auto slash_pos = path.rfind('/');
        auto name = slash_pos != std::string_view::npos
            ? path.substr(slash_pos + 1) : path;
        if (name == "AndroidManifest.xml")
            return collection_member_kind_t::manifest;
        if (name == "MANIFEST.MF")
            return collection_member_kind_t::manifest;
        return collection_member_kind_t::resource;
    }
    auto ext_lower = [](std::string_view ext) noexcept {
        std::string lower(ext);
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return lower;
    };
    auto ext = ext_lower(path.substr(dot_pos));
    if (ext == ".dex")
        return collection_member_kind_t::dex;
    if (ext == ".class")
        return collection_member_kind_t::classfile;
    if (ext == ".so" || ext == ".dll" || ext == ".dylib")
        return collection_member_kind_t::native_library;
    if (ext == ".zip" || ext == ".jar" || ext == ".apk" || ext == ".aab" ||
        ext == ".ipa" || ext == ".war" || ext == ".ear" || ext == ".apks" ||
        ext == ".xapk")
        return collection_member_kind_t::nested_archive;
    if (ext == ".pdb" || ext == ".dwarf" || ext == ".debug")
        return collection_member_kind_t::debug_companion;
    if (ext == ".xml") {
        auto slash_pos = path.rfind('/');
        auto name = slash_pos != std::string_view::npos
            ? path.substr(slash_pos + 1) : path;
        if (name == "AndroidManifest.xml")
            return collection_member_kind_t::manifest;
        return collection_member_kind_t::resource;
    }
    if (ext == ".mf") {
        auto slash_pos = path.rfind('/');
        auto name = slash_pos != std::string_view::npos
            ? path.substr(slash_pos + 1) : path;
        if (name == "MANIFEST.MF")
            return collection_member_kind_t::manifest;
        return collection_member_kind_t::resource;
    }
    return collection_member_kind_t::resource;
}

bool is_nested_archive_extension(std::string_view path) noexcept {
    auto dot_pos = path.rfind('.');
    if (dot_pos == std::string_view::npos)
        return false;
    auto ext_lower = [](std::string_view ext) noexcept {
        std::string lower(ext);
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return lower;
    };
    auto ext = ext_lower(path.substr(dot_pos));
    return ext == ".zip" || ext == ".jar" || ext == ".apk" || ext == ".aab" ||
           ext == ".ipa" || ext == ".war" || ext == ".ear" || ext == ".apks" ||
           ext == ".xapk";
}

bool is_debug_companion_extension(std::string_view path) noexcept {
    auto dot_pos = path.rfind('.');
    if (dot_pos == std::string_view::npos)
        return false;
    auto ext_lower = [](std::string_view ext) noexcept {
        std::string lower(ext);
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return lower;
    };
    auto ext = ext_lower(path.substr(dot_pos));
    return ext == ".pdb" || ext == ".dwarf" || ext == ".debug";
}

std::string display_name_from_path(std::string_view path) noexcept {
    auto slash_pos = path.rfind('/');
    if (slash_pos == std::string_view::npos)
        return std::string(path);
    return std::string(path.substr(slash_pos + 1));
}

std::string base_name_without_extension(std::string_view path) noexcept {
    auto slash_pos = path.rfind('/');
    auto name = slash_pos != std::string_view::npos
        ? path.substr(slash_pos + 1) : path;
    auto dot_pos = name.rfind('.');
    if (dot_pos != std::string_view::npos)
        name = name.substr(0, dot_pos);
    return std::string(name);
}

std::string companion_debug_path_for_binary(std::string_view binary_path) noexcept {
    auto slash_pos = binary_path.rfind('/');
    auto dir = slash_pos != std::string_view::npos
        ? binary_path.substr(0, slash_pos + 1) : std::string_view{};
    auto name = slash_pos != std::string_view::npos
        ? binary_path.substr(slash_pos + 1) : binary_path;
    auto dot_pos = name.rfind('.');
    if (dot_pos != std::string_view::npos) {
        auto ext_lower = [](std::string_view ext) noexcept {
            std::string lower(ext);
            for (auto& c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return lower;
        };
        auto ext = ext_lower(name.substr(dot_pos));
        auto base = name.substr(0, dot_pos);
        if (ext == ".dll" || ext == ".exe") {
            return std::string(dir) + std::string(base) + ".pdb";
        }
        if (ext == ".so") {
            return std::string(dir) + std::string(name) + ".debug";
        }
        if (ext == ".dylib") {
            return std::string(dir) + std::string(base) + ".dwarf";
        }
    }
    return std::string(dir) + std::string(name) + ".dSYM";
}

std::string companion_binary_path_for_debug(std::string_view debug_path) noexcept {
    auto slash_pos = debug_path.rfind('/');
    auto dir = slash_pos != std::string_view::npos
        ? debug_path.substr(0, slash_pos + 1) : std::string_view{};
    auto name = slash_pos != std::string_view::npos
        ? debug_path.substr(slash_pos + 1) : debug_path;
    auto dot_pos = name.rfind('.');
    if (dot_pos != std::string_view::npos) {
        auto ext_lower = [](std::string_view ext) noexcept {
            std::string lower(ext);
            for (auto& c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return lower;
        };
        auto ext = ext_lower(name.substr(dot_pos));
        auto base = name.substr(0, dot_pos);
        if (ext == ".pdb") {
            return std::string(dir) + std::string(base) + ".exe";
        }
        if (ext == ".debug") {
            auto without_debug = std::string(base);
            if (without_debug.size() > 3 && without_debug[without_debug.size()-3] == '.' &&
                tolower(static_cast<unsigned char>(without_debug[without_debug.size()-2])) == 's' &&
                tolower(static_cast<unsigned char>(without_debug[without_debug.size()-1])) == 'o')
                return std::string(dir) + without_debug;
            return std::string(dir) + std::string(base) + ".so";
        }
        if (ext == ".dwarf") {
            return std::string(dir) + std::string(base) + ".dylib";
        }
    }
    return {};
}

collection_kind_t classify_zip_kind(const std::vector<zip_member_t>& zip_members) {
    bool has_android_manifest = false;
    bool has_base_dir = false;
    bool has_payload_dir = false;
    bool has_manifest_mf = false;
    bool has_class_file = false;

    for (const auto& member : zip_members) {
        if (member.normalized_path == "AndroidManifest.xml")
            has_android_manifest = true;
        if (member.normalized_path.rfind("base/", 0) == 0)
            has_base_dir = true;
        if (member.normalized_path.rfind("Payload/", 0) == 0)
            has_payload_dir = true;
        if (member.normalized_path == "META-INF/MANIFEST.MF")
            has_manifest_mf = true;
        if (member.normalized_path.find(".class") != std::string::npos)
            has_class_file = true;
    }

    if (has_android_manifest && has_base_dir)
        return collection_kind_t::aab;
    if (has_android_manifest)
        return collection_kind_t::apk;
    if (has_payload_dir)
        return collection_kind_t::ipa;
    if (has_manifest_mf || has_class_file)
        return collection_kind_t::jar;
    return collection_kind_t::zip_archive;
}

architecture_id_t macho_cpu_type_to_arch(std::int32_t cpu_type) noexcept {
    constexpr std::int32_t CPU_TYPE_X86 = 7;
    constexpr std::int32_t CPU_TYPE_X86_64 = 0x01000007;
    constexpr std::int32_t CPU_TYPE_ARM = 12;
    constexpr std::int32_t CPU_TYPE_ARM64 = 0x0100000C;
    constexpr std::int32_t CPU_TYPE_POWERPC = 18;
    constexpr std::int32_t CPU_TYPE_POWERPC64 = 0x01000012;
    constexpr std::int32_t CPU_TYPE_MIPS = 8;

    switch (cpu_type) {
        case CPU_TYPE_X86: return architecture_id_t::x86;
        case CPU_TYPE_X86_64: return architecture_id_t::x86_64;
        case CPU_TYPE_ARM: return architecture_id_t::arm;
        case CPU_TYPE_ARM64: return architecture_id_t::aarch64;
        case CPU_TYPE_POWERPC: return architecture_id_t::ppc;
        case CPU_TYPE_POWERPC64: return architecture_id_t::ppc64;
        case CPU_TYPE_MIPS: return architecture_id_t::mips;
        default: return architecture_id_t::unknown;
    }
}

architecture_mode_t macho_cpu_type_to_mode(std::int32_t cpu_type) noexcept {
    constexpr std::int32_t CPU_TYPE_X86 = 7;
    constexpr std::int32_t CPU_TYPE_X86_64 = 0x01000007;
    constexpr std::int32_t CPU_TYPE_ARM = 12;
    constexpr std::int32_t CPU_TYPE_ARM64 = 0x0100000C;
    constexpr std::int32_t CPU_TYPE_POWERPC = 18;
    constexpr std::int32_t CPU_TYPE_POWERPC64 = 0x01000012;
    constexpr std::int32_t CPU_TYPE_MIPS = 8;

    switch (cpu_type) {
        case CPU_TYPE_X86: return architecture_mode_t::x86_32;
        case CPU_TYPE_X86_64: return architecture_mode_t::x86_64;
        case CPU_TYPE_ARM: return architecture_mode_t::arm_a32;
        case CPU_TYPE_ARM64: return architecture_mode_t::aarch64;
        case CPU_TYPE_POWERPC: return architecture_mode_t::ppc32;
        case CPU_TYPE_POWERPC64: return architecture_mode_t::ppc64;
        case CPU_TYPE_MIPS: return architecture_mode_t::mips32;
        default: return architecture_mode_t::unknown;
    }
}

format_id_t detect_standalone_format(const byte_provider_t& provider,
                                     const cancellation_token_t& cancel) {
    if (is_pe(provider, cancel))
        return format_id_t::pe32_plus;
    if (is_elf(provider, cancel))
        return format_id_t::elf;
    if (is_macho(provider, cancel))
        return format_id_t::macho;
    if (is_classfile(provider, cancel))
        return format_id_t::classfile;
    if (is_fat_macho(provider, cancel))
        return format_id_t::macho_fat;
    return format_id_t::unknown;
}

struct companion_link_t {
    std::size_t binary_index;
    std::size_t debug_index;
};

std::vector<companion_link_t>
detect_companions(const std::vector<collection_member_descriptor_t>& members) {
    std::vector<companion_link_t> links;
    for (std::size_t i = 0; i < members.size(); ++i) {
        if (members[i].member_kind == collection_member_kind_t::debug_companion) {
            const auto binary_path = companion_binary_path_for_debug(members[i].normalized_path);
            if (!binary_path.empty()) {
                for (std::size_t j = 0; j < members.size(); ++j) {
                    if (j == i)
                        continue;
                    if (members[j].normalized_path == binary_path &&
                        (members[j].member_kind == collection_member_kind_t::binary ||
                         members[j].member_kind == collection_member_kind_t::native_library)) {
                        links.push_back({j, i});
                        break;
                    }
                }
            }
        }
    }
    return links;
}

void apply_companion_links(std::vector<collection_member_descriptor_t>& members,
                           const std::vector<companion_link_t>& links) {
    for (const auto& link : links) {
        if (link.binary_index < members.size() && link.debug_index < members.size()) {
            members[link.binary_index].companion_debug_path =
                members[link.debug_index].normalized_path;
            members[link.debug_index].companion_binary_path =
                members[link.binary_index].normalized_path;
        }
    }
}

void compute_duplicate_names(std::vector<collection_member_descriptor_t>& members) {
    std::unordered_map<std::string, std::vector<std::size_t>> name_map;
    for (std::size_t i = 0; i < members.size(); ++i) {
        name_map[members[i].display_name].push_back(i);
    }
    for (auto& [name, indices] : name_map) {
        if (indices.size() > 1) {
            for (auto idx : indices) {
                for (auto other_idx : indices) {
                    if (other_idx != idx)
                        members[idx].duplicate_path_siblings.push_back(
                            members[other_idx].normalized_path);
                }
            }
        }
    }
}

}

collection_kind_t detect_collection_kind(const byte_provider_t& provider,
                                         const cancellation_token_t& cancel) {
    if (is_zip(provider, cancel)) {
        zip_container_limits_t zip_limits;
        zip_limits.max_nesting_depth = 1;
        auto zip_result = zip_container_t::open(
            std::shared_ptr<const byte_provider_t>(&provider, [](auto*){}),
            zip_limits, cancel);
        if (zip_result) {
            const auto& zip_members = zip_result.value()->members();
            return classify_zip_kind(zip_members);
        }
        return collection_kind_t::zip_archive;
    }
    if (is_fat_macho(provider, cancel))
        return collection_kind_t::fat_macho;
    if (is_pe(provider, cancel) || is_elf(provider, cancel) ||
        is_macho(provider, cancel) || is_classfile(provider, cancel))
        return collection_kind_t::standalone_binary;
    return collection_kind_t::unknown;
}

std::string_view collection_kind_name(collection_kind_t kind) noexcept {
    switch (kind) {
        case collection_kind_t::unknown: return "unknown";
        case collection_kind_t::zip_archive: return "zip_archive";
        case collection_kind_t::apk: return "apk";
        case collection_kind_t::aab: return "aab";
        case collection_kind_t::ipa: return "ipa";
        case collection_kind_t::jar: return "jar";
        case collection_kind_t::fat_macho: return "fat_macho";
        case collection_kind_t::multi_binary_project: return "multi_binary_project";
        case collection_kind_t::companion_debug: return "companion_debug";
        case collection_kind_t::standalone_binary: return "standalone_binary";
    }
    return "unknown";
}

std::string_view collection_member_kind_name(collection_member_kind_t kind) noexcept {
    switch (kind) {
        case collection_member_kind_t::unknown: return "unknown";
        case collection_member_kind_t::binary: return "binary";
        case collection_member_kind_t::dex: return "dex";
        case collection_member_kind_t::classfile: return "classfile";
        case collection_member_kind_t::native_library: return "native_library";
        case collection_member_kind_t::nested_archive: return "nested_archive";
        case collection_member_kind_t::debug_companion: return "debug_companion";
        case collection_member_kind_t::resource: return "resource";
        case collection_member_kind_t::manifest: return "manifest";
        case collection_member_kind_t::fat_slice: return "fat_slice";
    }
    return "unknown";
}

format_id_t collection_kind_to_format_hint(collection_kind_t kind) noexcept {
    switch (kind) {
        case collection_kind_t::zip_archive: return format_id_t::zip;
        case collection_kind_t::apk: return format_id_t::apk;
        case collection_kind_t::aab: return format_id_t::apk;
        case collection_kind_t::ipa: return format_id_t::ipa;
        case collection_kind_t::jar: return format_id_t::jar;
        case collection_kind_t::fat_macho: return format_id_t::macho_fat;
        case collection_kind_t::multi_binary_project: return format_id_t::unknown;
        case collection_kind_t::companion_debug: return format_id_t::unknown;
        case collection_kind_t::standalone_binary: return format_id_t::unknown;
        case collection_kind_t::unknown: return format_id_t::unknown;
    }
    return format_id_t::unknown;
}

bool collection_kind_is_zip_based(collection_kind_t kind) noexcept {
    return kind == collection_kind_t::zip_archive ||
           kind == collection_kind_t::apk ||
           kind == collection_kind_t::aab ||
           kind == collection_kind_t::ipa ||
           kind == collection_kind_t::jar;
}

bool collection_kind_is_container(collection_kind_t kind) noexcept {
    return kind != collection_kind_t::standalone_binary &&
           kind != collection_kind_t::unknown &&
           kind != collection_kind_t::companion_debug;
}

bool member_descriptor_is_nested_archive_candidate(
    const collection_member_descriptor_t& descriptor) noexcept {
    if (descriptor.member_kind == collection_member_kind_t::nested_archive)
        return true;
    if (is_nested_archive_extension(descriptor.normalized_path))
        return true;
    return false;
}

struct artifact_collection_t::state_t {
    std::shared_ptr<const byte_provider_t> provider;
    byte_provider_identity_t identity;
    collection_kind_t kind = collection_kind_t::unknown;
    collection_open_limits_t limits;
    std::vector<collection_member_descriptor_t> members;
    std::vector<collection_provenance_link_t> provenance;
    std::shared_ptr<member_graph_t> graph;
    std::uint64_t graph_node_value = 0;
    std::uint32_t depth = 0;
    std::atomic<bool> integrity_verified{false};

    std::shared_ptr<zip_container_t> zip_container;
    fat_image_t fat_image;
    bool is_zip_based = false;
    bool is_fat_macho = false;
    bool is_standalone = false;

    struct member_cache_entry_t {
        mutable std::mutex mutex;
        std::shared_ptr<byte_provider_t> provider;
        std::atomic<bool> opened{false};
    };
    mutable std::vector<std::unique_ptr<member_cache_entry_t>> member_cache;

    std::atomic<std::size_t> active_child_count{0};

    std::unordered_map<std::string, std::size_t> path_index;
    std::unordered_map<std::string, std::vector<std::size_t>> name_index;
    std::vector<std::string> duplicate_names_list;

    void build_indices() {
        path_index.clear();
        name_index.clear();
        duplicate_names_list.clear();
        for (std::size_t i = 0; i < members.size(); ++i) {
            path_index[members[i].normalized_path] = i;
            name_index[members[i].display_name].push_back(i);
        }
        for (const auto& [name, indices] : name_index) {
            if (indices.size() > 1)
                duplicate_names_list.push_back(name);
        }
    }
};

artifact_collection_t::artifact_collection_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

artifact_collection_t::~artifact_collection_t() = default;

workspace_result_t<std::shared_ptr<artifact_collection_t>>
artifact_collection_t::open(std::shared_ptr<const byte_provider_t> provider,
                            collection_open_limits_t limits,
                            const cancellation_token_t& cancel,
                            std::shared_ptr<member_graph_t> graph,
                            std::vector<collection_provenance_link_t> parent_provenance,
                            std::uint64_t parent_graph_node) {
    if (!provider)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::invalid_argument,
                            "collection open requires a non-null provider",
                            "artifact_collection"));
    if (provider->size() == 0)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::invalid_argument,
                            "collection open requires a non-empty provider",
                            "artifact_collection"));
    if (provider->size() > limits.max_collection_size)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::limit_exceeded,
                            "collection exceeds maximum collection size",
                            "artifact_collection"));

    const std::uint32_t current_depth = parent_provenance.empty()
        ? 0u : parent_provenance.back().depth + 1u;
    if (current_depth > limits.max_nesting_depth)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::limit_exceeded,
                            "collection nesting depth exceeds limit",
                            "artifact_collection"));

    auto state = std::make_shared<state_t>();
    state->provider = provider;
    state->identity = provider->identity();
    state->limits = limits;
    state->provenance = parent_provenance;
    state->graph = graph;
    state->depth = current_depth;

    if (check_cancel(cancel, "artifact_collection"))
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            stop_error(cancel, "artifact_collection"));

    const auto kind = detect_collection_kind(*provider, cancel);
    state->kind = kind;

    if (collection_kind_is_zip_based(kind)) {
        state->is_zip_based = true;
        zip_container_limits_t zip_limits;
        zip_limits.max_nesting_depth = limits.max_nesting_depth - current_depth;
        zip_limits.max_member_count = limits.max_member_count;
        zip_limits.max_member_uncompressed_size = limits.max_member_uncompressed_size;
        zip_limits.max_aggregate_uncompressed_size = limits.max_aggregate_uncompressed_size;
        zip_limits.max_elapsed = limits.max_elapsed;

        auto zip_result = zip_container_t::open(provider, zip_limits, cancel);
        if (!zip_result)
            return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                std::move(zip_result.error()));

        state->zip_container = zip_result.take_value();
        const auto& zip_members = state->zip_container->members();

        if (zip_members.size() > limits.max_member_count)
            return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                collection_error(workspace_error_code_t::limit_exceeded,
                                "collection member count exceeds limit",
                                "artifact_collection"));

        std::uint64_t aggregate_uncompressed = 0;
        for (const auto& zm : zip_members) {
            if (check_cancel(cancel, "artifact_collection"))
                return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                    stop_error(cancel, "artifact_collection"));

            if (zm.kind == zip_member_kind_t::directory)
                continue;

            aggregate_uncompressed += zm.uncompressed_size;
            if (aggregate_uncompressed > limits.max_aggregate_uncompressed_size)
                return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                    collection_error(workspace_error_code_t::limit_exceeded,
                                    "aggregate uncompressed size exceeds limit",
                                    "artifact_collection"));

            collection_member_descriptor_t descriptor;
            descriptor.normalized_path = zm.normalized_path;
            descriptor.display_name = display_name_from_path(zm.normalized_path);
            descriptor.member_kind = classify_member_by_path(zm.normalized_path);
            descriptor.format = detect_format_from_member_path(zm.normalized_path);
            descriptor.ordinal = zm.ordinal;
            descriptor.container_offset = zm.data_offset;
            descriptor.compressed_size = zm.compressed_size;
            descriptor.uncompressed_size = zm.uncompressed_size;
            descriptor.crc32 = zm.crc32;
            descriptor.depth = current_depth;
            descriptor.compressed = zm.compression_method != 0;
            descriptor.is_nested_collection = is_nested_archive_extension(zm.normalized_path);
            descriptor.provider_metadata = zm.provenance;
            descriptor.provider_metadata.normalized_member_path = zm.normalized_path;
            descriptor.provider_metadata.container_offset = zm.data_offset;
            descriptor.provider_metadata.compressed_size = zm.compressed_size;
            descriptor.provider_metadata.uncompressed_size = zm.uncompressed_size;
            descriptor.provider_metadata.depth = current_depth + 1;
            descriptor.provider_metadata.crc32 = zm.crc32;
            descriptor.provider_metadata.compressed = zm.compression_method != 0;

            descriptor.provenance_chain = parent_provenance;
            collection_provenance_link_t self_link;
            self_link.normalized_path = state->identity.normalized_source;
            self_link.kind = kind;
            self_link.container_offset = 0;
            self_link.member_size = provider->size();
            self_link.depth = current_depth;
            descriptor.provenance_chain.push_back(self_link);

            if (descriptor.is_nested_collection)
                descriptor.member_kind = collection_member_kind_t::nested_archive;

            state->members.push_back(std::move(descriptor));
        }
    } else if (kind == collection_kind_t::fat_macho) {
        state->is_fat_macho = true;
        auto fat_result = parse_fat_macho(*provider, cancel);
        if (!fat_result)
            return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                std::move(fat_result.error()));

        state->fat_image = fat_result.take_value();
        std::uint32_t slice_ordinal = 0;
        for (const auto& slice : state->fat_image.slices) {
            if (check_cancel(cancel, "artifact_collection"))
                return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
                    stop_error(cancel, "artifact_collection"));

            collection_member_descriptor_t descriptor;
            descriptor.normalized_path = "slice_" + std::to_string(slice_ordinal);
            descriptor.display_name = "slice_" + std::to_string(slice_ordinal);
            descriptor.member_kind = collection_member_kind_t::fat_slice;
            descriptor.format = format_id_t::macho;
            descriptor.architecture = slice.architecture;
            descriptor.architecture_mode = macho_cpu_type_to_mode(slice.cputype);
            descriptor.ordinal = slice_ordinal;
            descriptor.container_offset = slice.offset;
            descriptor.compressed_size = slice.size;
            descriptor.uncompressed_size = slice.size;
            descriptor.crc32 = 0;
            descriptor.depth = current_depth;
            descriptor.compressed = false;
            descriptor.is_nested_collection = false;
            descriptor.provider_metadata.normalized_member_path = descriptor.normalized_path;
            descriptor.provider_metadata.container_offset = slice.offset;
            descriptor.provider_metadata.compressed_size = slice.size;
            descriptor.provider_metadata.uncompressed_size = slice.size;
            descriptor.provider_metadata.depth = current_depth + 1;
            descriptor.provider_metadata.crc32 = 0;
            descriptor.provider_metadata.compressed = false;

            descriptor.provenance_chain = parent_provenance;
            collection_provenance_link_t self_link;
            self_link.normalized_path = state->identity.normalized_source;
            self_link.kind = kind;
            self_link.container_offset = 0;
            self_link.member_size = provider->size();
            self_link.depth = current_depth;
            descriptor.provenance_chain.push_back(self_link);

            state->members.push_back(std::move(descriptor));
            ++slice_ordinal;
        }
    } else {
        state->is_standalone = true;
        const auto fmt = detect_standalone_format(*provider, cancel);

        collection_member_descriptor_t descriptor;
        auto slash_pos = state->identity.normalized_source.rfind('/');
        auto slash_pos2 = state->identity.normalized_source.rfind('\\');
        std::size_t name_start = 0;
        if (slash_pos != std::string::npos)
            name_start = slash_pos + 1;
        if (slash_pos2 != std::string::npos && slash_pos2 + 1 > name_start)
            name_start = slash_pos2 + 1;
        descriptor.normalized_path = state->identity.normalized_source.substr(name_start);
        if (descriptor.normalized_path.empty())
            descriptor.normalized_path = "binary";
        descriptor.display_name = descriptor.normalized_path;
        descriptor.member_kind = collection_member_kind_t::binary;
        descriptor.format = fmt;
        descriptor.ordinal = 0;
        descriptor.container_offset = 0;
        descriptor.compressed_size = provider->size();
        descriptor.uncompressed_size = provider->size();
        descriptor.crc32 = 0;
        descriptor.depth = current_depth;
        descriptor.compressed = false;
        descriptor.is_nested_collection = false;
        descriptor.provider_metadata.normalized_member_path = descriptor.normalized_path;
        descriptor.provider_metadata.container_offset = 0;
        descriptor.provider_metadata.compressed_size = provider->size();
        descriptor.provider_metadata.uncompressed_size = provider->size();
        descriptor.provider_metadata.depth = current_depth + 1;
        descriptor.provider_metadata.crc32 = 0;
        descriptor.provider_metadata.compressed = false;

        descriptor.provenance_chain = parent_provenance;
        collection_provenance_link_t self_link;
        self_link.normalized_path = state->identity.normalized_source;
        self_link.kind = kind;
        self_link.container_offset = 0;
        self_link.member_size = provider->size();
        self_link.depth = current_depth;
        descriptor.provenance_chain.push_back(self_link);

        state->members.push_back(std::move(descriptor));
    }

    if (limits.enable_companion_detection) {
        auto companion_links = detect_companions(state->members);
        apply_companion_links(state->members, companion_links);
    }

    if (limits.enable_duplicate_name_tracking) {
        compute_duplicate_names(state->members);
    }

    state->build_indices();

    state->member_cache.resize(state->members.size());
    for (auto& entry : state->member_cache)
        entry = std::make_unique<state_t::member_cache_entry_t>();

    if (state->graph) {
        if (parent_graph_node != 0) {
            member_node_id_t parent_id;
            parent_id.value = parent_graph_node;
            for (const auto& member : state->members) {
                state->graph->register_child(parent_id, member,
                    member.is_nested_collection);
            }
            state->graph_node_value = parent_graph_node;
        } else {
            auto root_result = state->graph->register_root(
                state->kind, state->identity, state->provenance);
            if (root_result) {
                state->graph_node_value = root_result.value().value;
                for (const auto& member : state->members) {
                    state->graph->register_child(root_result.value(), member,
                        member.is_nested_collection);
                }
            }
        }
    }

    auto collection = std::shared_ptr<artifact_collection_t>(
        new artifact_collection_t(std::move(state)));
    return workspace_result_t<std::shared_ptr<artifact_collection_t>>::success(
        std::move(collection));
}

const byte_provider_identity_t& artifact_collection_t::source_identity() const noexcept {
    return state_->identity;
}

const std::shared_ptr<const byte_provider_t>&
artifact_collection_t::source_provider() const noexcept {
    return state_->provider;
}

collection_kind_t artifact_collection_t::kind() const noexcept {
    return state_->kind;
}

const collection_open_limits_t& artifact_collection_t::limits() const noexcept {
    return state_->limits;
}

const std::vector<collection_member_descriptor_t>&
artifact_collection_t::members() const noexcept {
    return state_->members;
}

const collection_member_descriptor_t*
artifact_collection_t::find_member(std::string_view normalized_path) const {
    auto it = state_->path_index.find(std::string(normalized_path));
    if (it == state_->path_index.end())
        return nullptr;
    return &state_->members[it->second];
}

const collection_member_descriptor_t*
artifact_collection_t::find_member_by_ordinal(std::uint64_t ordinal) const {
    for (const auto& member : state_->members) {
        if (member.ordinal == ordinal)
            return &member;
    }
    return nullptr;
}

std::size_t artifact_collection_t::member_count() const noexcept {
    return state_->members.size();
}

std::uint32_t artifact_collection_t::depth() const noexcept {
    return state_->depth;
}

const std::vector<collection_provenance_link_t>&
artifact_collection_t::provenance() const noexcept {
    return state_->provenance;
}

const std::shared_ptr<member_graph_t>&
artifact_collection_t::graph() const noexcept {
    return state_->graph;
}

std::uint64_t artifact_collection_t::graph_node() const noexcept {
    return state_->graph_node_value;
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
artifact_collection_t::open_member(std::size_t member_index,
                                   const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::out_of_range,
                            "member index out of range",
                            "artifact_collection"));
    if (check_cancel(cancel, "artifact_collection"))
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            stop_error(cancel, "artifact_collection"));

    auto& cache = state_->member_cache[member_index];
    std::lock_guard<std::mutex> lock(cache->mutex);
    if (cache->opened.load(std::memory_order_acquire)) {
        if (cache->provider)
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(
                cache->provider);
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::provider_unavailable,
                            "cached member provider was released",
                            "artifact_collection"));
    }

    std::shared_ptr<byte_provider_t> member_provider;

    if (state_->is_zip_based && state_->zip_container) {
        auto result = state_->zip_container->open_member_provider(member_index, cancel);
        if (!result)
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                std::move(result.error()));
        member_provider = result.take_value();
    } else if (state_->is_fat_macho) {
        const auto& member = state_->members[member_index];
        auto subrange_result = subrange_provider_t::create(
            state_->provider, member.container_offset, member.uncompressed_size,
            member.normalized_path);
        if (!subrange_result)
            return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
                std::move(subrange_result.error()));
        member_provider = subrange_result.take_value();
    } else {
        member_provider = std::const_pointer_cast<byte_provider_t>(state_->provider);
    }

    cache->provider = member_provider;
    cache->opened.store(true, std::memory_order_release);

    if (state_->graph && state_->graph_node_value != 0) {
        member_node_id_t node_id;
        node_id.value = state_->graph_node_value;
        const auto& children = state_->graph->children(node_id);
        if (member_index < children.size()) {
            state_->graph->mark_opened(children[member_index]);
        }
    }

    return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(
        std::move(member_provider));
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
artifact_collection_t::open_member(std::string_view normalized_path,
                                   const cancellation_token_t& cancel) const {
    auto it = state_->path_index.find(std::string(normalized_path));
    if (it == state_->path_index.end())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::target_not_found,
                            "member path not found in collection",
                            "artifact_collection"));
    return open_member(it->second, cancel);
}

workspace_result_t<std::shared_ptr<artifact_collection_t>>
artifact_collection_t::open_child_collection(std::size_t member_index,
                                              const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size())
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::out_of_range,
                            "member index out of range",
                            "artifact_collection"));

    const auto& member = state_->members[member_index];
    if (!member.is_nested_collection)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::unsupported_format,
                            "member is not a nested collection candidate",
                            "artifact_collection"));

    if (check_cancel(cancel, "artifact_collection"))
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            stop_error(cancel, "artifact_collection"));

    auto member_provider_result = open_member(member_index, cancel);
    if (!member_provider_result)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            std::move(member_provider_result.error()));

    auto member_provider = member_provider_result.take_value();

    std::vector<collection_provenance_link_t> child_provenance = member.provenance_chain;

    state_->active_child_count.fetch_add(1, std::memory_order_acq_rel);

    auto child_result = artifact_collection_t::open(
        member_provider, state_->limits, cancel, state_->graph,
        std::move(child_provenance), state_->graph_node_value);

    state_->active_child_count.fetch_sub(1, std::memory_order_acq_rel);

    if (!child_result)
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            std::move(child_result.error()));

    return workspace_result_t<std::shared_ptr<artifact_collection_t>>::success(
        child_result.take_value());
}

workspace_result_t<std::shared_ptr<artifact_collection_t>>
artifact_collection_t::open_child_collection(std::string_view normalized_path,
                                              const cancellation_token_t& cancel) const {
    auto it = state_->path_index.find(std::string(normalized_path));
    if (it == state_->path_index.end())
        return workspace_result_t<std::shared_ptr<artifact_collection_t>>::failure(
            collection_error(workspace_error_code_t::target_not_found,
                            "member path not found in collection",
                            "artifact_collection"));
    return open_child_collection(it->second, cancel);
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
artifact_collection_t::open_companion_debug(std::size_t member_index,
                                             const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::out_of_range,
                            "member index out of range",
                            "artifact_collection"));

    const auto& member = state_->members[member_index];
    if (!member.companion_debug_path.has_value())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::target_not_found,
                            "member has no companion debug artifact",
                            "artifact_collection"));

    return open_member(*member.companion_debug_path, cancel);
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
artifact_collection_t::open_companion_binary(std::size_t member_index,
                                             const cancellation_token_t& cancel) const {
    if (member_index >= state_->members.size())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::out_of_range,
                            "member index out of range",
                            "artifact_collection"));

    const auto& member = state_->members[member_index];
    if (!member.companion_binary_path.has_value())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(
            collection_error(workspace_error_code_t::target_not_found,
                            "member has no companion binary artifact",
                            "artifact_collection"));

    return open_member(*member.companion_binary_path, cancel);
}

workspace_result_t<void>
artifact_collection_t::verify_integrity(const cancellation_token_t& cancel) const {
    if (state_->is_zip_based && state_->zip_container) {
        auto result = state_->zip_container->verify_integrity(cancel);
        if (!result)
            return result;
        state_->integrity_verified.store(true, std::memory_order_release);
        return workspace_result_t<void>::success();
    }
    state_->integrity_verified.store(true, std::memory_order_release);
    return workspace_result_t<void>::success();
}

bool artifact_collection_t::integrity_verified() const noexcept {
    return state_->integrity_verified.load(std::memory_order_acquire);
}

workspace_result_t<sha256_digest_t>
artifact_collection_t::compute_member_hash(std::size_t member_index,
                                           const cancellation_token_t& cancel) const {
    auto provider_result = open_member(member_index, cancel);
    if (!provider_result)
        return workspace_result_t<sha256_digest_t>::failure(
            std::move(provider_result.error()));

    auto member_provider = provider_result.take_value();
    auto hash_result = member_provider->compute_content_sha256(cancel);
    if (!hash_result)
        return workspace_result_t<sha256_digest_t>::failure(
            std::move(hash_result.error()));

    auto hash = hash_result.take_value();

    if (state_->graph && state_->graph_node_value != 0) {
        member_node_id_t node_id;
        node_id.value = state_->graph_node_value;
        const auto& children = state_->graph->children(node_id);
        if (member_index < children.size()) {
            state_->graph->mark_hash_verified(children[member_index], hash);
        }
    }

    state_->members[member_index].content_hash = hash;

    return workspace_result_t<sha256_digest_t>::success(std::move(hash));
}

std::vector<std::string> artifact_collection_t::duplicate_member_names() const {
    return state_->duplicate_names_list;
}

std::vector<const collection_member_descriptor_t*>
artifact_collection_t::members_with_name(std::string_view name) const {
    std::vector<const collection_member_descriptor_t*> result;
    auto it = state_->name_index.find(std::string(name));
    if (it != state_->name_index.end()) {
        for (auto idx : it->second)
            result.push_back(&state_->members[idx]);
    }
    return result;
}

std::size_t artifact_collection_t::active_child_count() const noexcept {
    return state_->active_child_count.load(std::memory_order_acquire);
}

bool artifact_collection_t::has_unopened_members() const noexcept {
    for (const auto& cache : state_->member_cache) {
        if (cache && !cache->opened.load(std::memory_order_acquire))
            return true;
    }
    return false;
}

}
