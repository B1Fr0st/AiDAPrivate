#include "flirt_db_builder.hpp"

#include "../decompiler/api_prototype_table.hpp"
#include "../subrange_provider.hpp"
#include "../workspace/coff_image.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

namespace aida::analysis::flirt {
namespace {

constexpr std::uint32_t k_relocation_cover_bytes_default = 4;

struct relocation_cover_t {
    std::uint32_t offset;
    std::uint32_t bytes;
};

relocation_cover_t relocation_cover(std::uint16_t type) noexcept
{
    switch (type) {
    case 0x0001:
        return {0, 8};
    case 0x0005:
    case 0x0006:
    case 0x0007:
    case 0x0008:
    case 0x0009:
        return {static_cast<std::uint32_t>(type - 0x0004), 4};
    case 0x000A:
        return {0, 2};
    default:
        return {0, k_relocation_cover_bytes_default};
    }
}

bool noreturn_name(const std::string& name)
{
    if (auto hit = api_prototypes::find("ucrtbase", name))
        return hit->is_noreturn;
    if (auto hit = api_prototypes::find("kernel32.dll", name))
        return hit->is_noreturn;
    return false;
}

std::string env_value(const char* name)
{
    char buffer[1024]{};
    const DWORD length = GetEnvironmentVariableA(name, buffer, sizeof(buffer));
    if (length == 0 || length >= sizeof(buffer))
        return {};
    return std::string(buffer, length);
}

bool file_exists(const std::filesystem::path& path)
{
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec);
}

void append_default_libs(const std::filesystem::path& lib_dir, std::vector<std::string>& out)
{
    for (const char* name : {"libcmt.lib", "libvcruntime.lib", "libcpmt.lib"}) {
        const auto candidate = lib_dir / name;
        if (file_exists(candidate))
            out.push_back(candidate.string());
    }
}

workspace_result_t<void> harvest_object(const std::shared_ptr<const byte_provider_t>& parent,
                                        std::uint64_t payload_offset,
                                        std::uint64_t payload_size,
                                        std::uint16_t sig_flags,
                                        const flirt_db_builder_options_t& options,
                                        flirt_db_builder_stats_t& stats,
                                        std::vector<flirt_db_build_entry_t>& out,
                                        std::set<std::string>& emitted,
                                        const cancellation_token_t& cancel)
{
    auto sub = subrange_provider_t::create(parent, payload_offset, payload_size, "coff-member");
    if (!sub)
        return workspace_result_t<void>::failure(std::move(sub.error()));
    auto parsed = parse_coff_image(*sub.value(), cancel);
    if (!parsed)
        return workspace_result_t<void>::failure(std::move(parsed.error()));
    const auto& object = parsed.value();
    if (object.machine != coff_machine_amd64)
        return workspace_result_t<void>::success();
    ++stats.members_parsed;
    std::vector<std::vector<std::uint8_t>> section_bytes(object.sections.size() + 1);
    for (const auto& section : object.sections) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::cancelled, "FLIRT builder cancelled", "flirt.build"));
        if (!section.has_raw_data || section.raw_size == 0)
            continue;
        if ((section.characteristics & coff_section_cnt_code) == 0 ||
            (section.characteristics & coff_section_mem_execute) == 0)
            continue;
        if (section.index >= section_bytes.size())
            continue;
        auto bytes = sub.value()->read_vector(section.raw_offset, section.raw_size, 1ULL << 26, cancel);
        if (!bytes)
            continue;
        section_bytes[section.index] = bytes.take_value();
        ++stats.code_sections;
    }
    for (std::size_t section_ordinal = 0; section_ordinal < object.sections.size(); ++section_ordinal) {
        const auto& section = object.sections[section_ordinal];
        if (section.index >= section_bytes.size() || section_bytes[section.index].empty())
            continue;
        const auto& bytes = section_bytes[section.index];
        std::vector<const coff_symbol_t*> symbols;
        for (const auto& symbol : object.symbols) {
            if (!symbol.is_defined || symbol.section_number != static_cast<std::int32_t>(section.index))
                continue;
            if (symbol.name.empty() || symbol.name.size() > 240)
                continue;
            const bool external = symbol.storage_class == coff_storage_class_external ||
                symbol.storage_class == coff_storage_class_external_def;
            const bool static_sym = symbol.storage_class == coff_storage_class_static;
            if (!external && !(static_sym && !options.strip_static))
                continue;
            if (symbol.value >= bytes.size())
                continue;
            symbols.push_back(&symbol);
        }
        if (symbols.empty())
            continue;
        std::sort(symbols.begin(), symbols.end(), [](const auto* lhs, const auto* rhs) {
            if (lhs->value != rhs->value)
                return lhs->value < rhs->value;
            return lhs->name < rhs->name;
        });
        for (std::size_t ordinal = 0; ordinal < symbols.size(); ++ordinal) {
            const auto& symbol = *symbols[ordinal];
            ++stats.symbols_seen;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::cancelled, "FLIRT builder cancelled", "flirt.build"));
            const std::size_t available = bytes.size() - symbol.value;
            const std::size_t window = (std::min<std::size_t>)(available, k_afdb_max_pattern_bytes);
            if (window < k_afdb_min_pattern_bytes) {
                ++stats.dropped_short;
                continue;
            }
            std::uint32_t mask = window == 32 ? 0xFFFFFFFFu
                : ((std::uint32_t{1} << window) - 1u);
            for (const auto& relocation : object.relocations) {
                if (relocation.section_index != section.index)
                    continue;
                const relocation_cover_t cover = relocation_cover(relocation.type);
                const std::uint64_t cover_begin =
                    static_cast<std::uint64_t>(relocation.virtual_address) + cover.offset;
                if (cover_begin < symbol.value)
                    continue;
                const std::uint64_t begin = cover_begin - symbol.value;
                for (std::uint32_t b = 0; b < cover.bytes && begin + b < window; ++b)
                    mask &= ~(1u << (begin + b));
            }
            if ((mask & 0xFFu) != 0xFFu) {
                ++stats.dropped_prefix;
                continue;
            }
            std::uint32_t significant = 0;
            for (std::size_t b = 0; b < window; ++b)
                if ((mask & (1u << b)) != 0)
                    ++significant;
            if (significant < k_afdb_min_significant_bits) {
                ++stats.dropped_mask;
                continue;
            }
            flirt_db_build_entry_t entry;
            entry.pattern_len = static_cast<std::uint8_t>(window);
            entry.mask = mask;
            std::memcpy(entry.bytes, bytes.data() + symbol.value, window);
            std::memcpy(&entry.prefix8, entry.bytes, sizeof(entry.prefix8));
            entry.name = symbol.name;
            std::size_t next_distinct = ordinal + 1;
            while (next_distinct < symbols.size() &&
                   symbols[next_distinct]->value == symbol.value)
                ++next_distinct;
            if (next_distinct < symbols.size())
                entry.func_size = symbols[next_distinct]->value - symbol.value;
            else
                entry.func_size = static_cast<std::uint32_t>(
                    (std::min<std::uint64_t>)(bytes.size() - symbol.value, 0xFFFFFFFFull));
            entry.sig_flags = sig_flags;
            if (noreturn_name(symbol.name))
                entry.sig_flags |= k_afdb_sig_flag_noreturn;
            std::string dedupe_key;
            dedupe_key.reserve(4 + window + 2 + entry.name.size());
            dedupe_key.append(reinterpret_cast<const char*>(&mask), sizeof(mask));
            dedupe_key.push_back(static_cast<char>(entry.pattern_len));
            dedupe_key.append(reinterpret_cast<const char*>(entry.bytes), window);
            dedupe_key.append(entry.name);
            if (!emitted.insert(std::move(dedupe_key)).second) {
                ++stats.deduped;
                continue;
            }
            out.push_back(std::move(entry));
        }
    }
    return workspace_result_t<void>::success();
}

std::string sha256_hex(const std::uint8_t* data, std::size_t size)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<std::uint8_t, 32> digest{};
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hash, const_cast<std::uint8_t*>(data),
                           static_cast<ULONG>(size), 0) == 0)
            BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (const auto byte : digest) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0xF]);
    }
    return out;
}

}

workspace_result_t<std::vector<std::string>> discover_msvc_static_libs()
{
    std::vector<std::string> out;
    const std::string vc_tools = env_value("VCToolsInstallDir");
    if (!vc_tools.empty()) {
        append_default_libs(std::filesystem::path(vc_tools) / "lib" / "x64", out);
        if (!out.empty())
            return workspace_result_t<std::vector<std::string>>::success(std::move(out));
    }
    const std::string vs_install = env_value("VSINSTALLDIR");
    const std::string vc_version = env_value("VCToolsVersion");
    if (!vs_install.empty() && !vc_version.empty()) {
        append_default_libs(std::filesystem::path(vs_install) / "VC" / "Tools" / "MSVC" /
                            vc_version / "lib" / "x64", out);
        if (!out.empty())
            return workspace_result_t<std::vector<std::string>>::success(std::move(out));
    }
    const std::filesystem::path msvc_root =
        "C:/Program Files/Microsoft Visual Studio/2022";
    std::error_code ec;
    if (std::filesystem::is_directory(msvc_root, ec)) {
        std::vector<std::filesystem::path> candidates;
        for (const auto& edition : std::filesystem::directory_iterator(msvc_root, ec)) {
            if (!edition.is_directory(ec))
                continue;
            const auto tools_dir = edition.path() / "VC" / "Tools" / "MSVC";
            if (!std::filesystem::is_directory(tools_dir, ec))
                continue;
            for (const auto& version : std::filesystem::directory_iterator(tools_dir, ec)) {
                if (!version.is_directory(ec))
                    continue;
                const auto lib_dir = version.path() / "lib" / "x64";
                if (file_exists(lib_dir / "libcmt.lib"))
                    candidates.push_back(lib_dir);
            }
        }
        std::sort(candidates.begin(), candidates.end());
        if (!candidates.empty())
            append_default_libs(candidates.back(), out);
    }
    if (out.empty())
        return workspace_result_t<std::vector<std::string>>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "no MSVC v143 x64 static libraries were discovered on this host", "flirt.discover"));
    return workspace_result_t<std::vector<std::string>>::success(std::move(out));
}

workspace_result_t<flirt_db_builder_stats_t>
build_flirt_db_entries(const flirt_db_builder_options_t& options,
                       std::vector<flirt_db_build_entry_t>& out_entries,
                       const cancellation_token_t& cancel)
{
    flirt_db_builder_stats_t stats;
    out_entries.clear();
    std::set<std::string> emitted;
    std::vector<std::string> libraries = options.library_paths;
    if (libraries.empty()) {
        auto discovered = discover_msvc_static_libs();
        if (!discovered)
            return workspace_result_t<flirt_db_builder_stats_t>::failure(
                std::move(discovered.error()));
        libraries = discovered.take_value();
    }
    for (const auto& library : libraries) {
        if (cancel.stop_requested())
            return workspace_result_t<flirt_db_builder_stats_t>::failure(make_workspace_error(
                workspace_error_code_t::cancelled, "FLIRT builder cancelled", "flirt.build"));
        auto opened = mapped_file_provider_t::open(library);
        if (!opened)
            return workspace_result_t<flirt_db_builder_stats_t>::failure(
                std::move(opened.error()));
        auto provider = opened.take_value();
        auto archive = parse_coff_image(*provider, cancel);
        if (!archive)
            return workspace_result_t<flirt_db_builder_stats_t>::failure(
                std::move(archive.error()));
        const std::string leaf = std::filesystem::path(library).filename().string();
        std::uint16_t sig_flags = 0;
        if (leaf == "libcmt.lib" || leaf == "libvcruntime.lib")
            sig_flags |= k_afdb_sig_flag_crt_runtime;
        else if (leaf == "libcpmt.lib")
            sig_flags |= k_afdb_sig_flag_stl;
        std::uint64_t before = out_entries.size();
        std::shared_ptr<const byte_provider_t> provider_base = provider;
        for (const auto& member : archive.value().archive_members) {
            if (member.kind != coff_archive_member_kind_t::object ||
                member.payload_size < 4 || member.machine != coff_machine_amd64)
                continue;
            auto harvested = harvest_object(provider_base, member.payload_offset,
                                            member.payload_size, sig_flags, options, stats,
                                            out_entries, emitted, cancel);
            if (!harvested)
                return workspace_result_t<flirt_db_builder_stats_t>::failure(
                    std::move(harvested.error()));
        }
        ++stats.libraries_loaded;
        stats.library_names.push_back(leaf);
        diag::log_tagged_fmt("flirtbuild",
            "library=%s members=%llu signatures_added=%llu",
            leaf.c_str(),
            static_cast<unsigned long long>(stats.members_parsed),
            static_cast<unsigned long long>(out_entries.size() - before));
    }
    std::sort(out_entries.begin(), out_entries.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.prefix8 != rhs.prefix8)
            return lhs.prefix8 < rhs.prefix8;
        return lhs.name < rhs.name;
    });
    for (std::size_t index = 1; index < out_entries.size(); ++index) {
        const auto& previous = out_entries[index - 1];
        const auto& current = out_entries[index];
        if (previous.prefix8 == current.prefix8 && previous.name != current.name)
            ++stats.collisions_kept;
    }
    stats.signatures_emitted = out_entries.size();
    diag::log_tagged_fmt("flirtbuild",
        "build exit libraries=%llu members=%llu sections=%llu symbols=%llu emitted=%llu deduped=%llu collisions=%llu dropped_short=%llu dropped_prefix=%llu dropped_mask=%llu",
        static_cast<unsigned long long>(stats.libraries_loaded),
        static_cast<unsigned long long>(stats.members_parsed),
        static_cast<unsigned long long>(stats.code_sections),
        static_cast<unsigned long long>(stats.symbols_seen),
        static_cast<unsigned long long>(stats.signatures_emitted),
        static_cast<unsigned long long>(stats.deduped),
        static_cast<unsigned long long>(stats.collisions_kept),
        static_cast<unsigned long long>(stats.dropped_short),
        static_cast<unsigned long long>(stats.dropped_prefix),
        static_cast<unsigned long long>(stats.dropped_mask));
    return workspace_result_t<flirt_db_builder_stats_t>::success(std::move(stats));
}

workspace_result_t<std::string>
write_flirt_seed_header(const std::vector<std::uint8_t>& blob,
                        const std::string& toolset,
                        std::uint32_t entry_count,
                        const std::string& utf8_output_path)
{
    if (blob.empty())
        return workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "FLIRT seed blob is empty", "flirt.seed_header"));
    const std::string digest = sha256_hex(blob.data(), blob.size());
    std::ofstream out(utf8_output_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
        return workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::io_failure,
            "FLIRT seed header path cannot be opened for writing", "flirt.seed_header"));
    out << "#pragma once\n\n";
    out << "#include <cstddef>\n#include <cstdint>\n\n";
    out << "namespace aida::analysis::flirt {\n\n";
    out << "inline constexpr char k_afdb_seed_toolset[] = \"" << toolset << "\";\n";
    out << "inline constexpr std::uint32_t k_afdb_seed_entry_count = " << entry_count << "u;\n";
    out << "inline constexpr char k_afdb_seed_sha256[] =\n    \"" << digest << "\";\n\n";
    out << "inline constexpr std::uint8_t k_afdb_seed_blob[] = {\n";
    for (std::size_t index = 0; index < blob.size(); ++index) {
        if (index % 12 == 0)
            out << "    ";
        char text[8]{};
        _snprintf_s(text, sizeof(text), _TRUNCATE, "0x%02X,", blob[index]);
        out << text;
        if (index % 12 == 11 || index + 1 == blob.size())
            out << "\n";
        else
            out << ' ';
    }
    out << "};\n\n";
    out << "inline constexpr std::size_t k_afdb_seed_blob_size = sizeof(k_afdb_seed_blob);\n\n";
    out << "}\n";
    out.flush();
    if (!out.good())
        return workspace_result_t<std::string>::failure(make_workspace_error(
            workspace_error_code_t::io_failure,
            "FLIRT seed header write failed", "flirt.seed_header"));
    return workspace_result_t<std::string>::success(digest);
}

}
