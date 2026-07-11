#include "apk_container.hpp"

#include "elf_image.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace aida::analysis {
namespace {

struct archive_node_t {
    std::shared_ptr<zip_container_t> archive;
    std::size_t archive_index = 0;
    apk_container_kind_t kind = apk_container_kind_t::unknown;
    std::string container_path;
    std::vector<provider_member_metadata_t> provenance;
    apk_module_identity_t default_module;
};

struct record_route_t {
    std::size_t archive_index = 0;
    std::size_t member_index = 0;
};

struct build_result_t {
    apk_container_kind_t kind = apk_container_kind_t::unknown;
    std::vector<std::shared_ptr<zip_container_t>> archives;
    std::vector<apk_code_member_t> members;
    std::vector<record_route_t> routes;
    std::unordered_set<std::string> record_paths;
};

workspace_error_t apk_error(workspace_error_code_t code, std::string message,
                            std::string phase,
                            std::optional<std::uint64_t> offset = {},
                            std::optional<std::uint64_t> size = {}) {
    auto error = make_workspace_error(code, std::move(message), std::move(phase));
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t limit_error(std::string message, std::string phase,
                              std::uint64_t value, std::uint64_t limit) {
    auto error = apk_error(workspace_error_code_t::limit_exceeded,
                           std::move(message), std::move(phase));
    error.details.emplace_back("value", std::to_string(value));
    error.details.emplace_back("limit", std::to_string(limit));
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel,
                             std::string phase) {
    if (cancel.deadline_exceeded()) {
        auto error = apk_error(workspace_error_code_t::deadline_exceeded,
                               "Android container operation exceeded its deadline",
                               std::move(phase));
        error.deadline = true;
        return error;
    }
    auto error = apk_error(workspace_error_code_t::cancelled,
                           "Android container operation was cancelled",
                           std::move(phase));
    error.cancellation = true;
    return error;
}

std::string lower_ascii(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        result.push_back(character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : static_cast<char>(character));
    }
    return result;
}

bool ends_with(std::string_view value, std::string_view suffix) noexcept {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

std::vector<std::string_view> split_path(std::string_view value) {
    std::vector<std::string_view> parts;
    std::size_t begin = 0;
    while (begin < value.size()) {
        const std::size_t slash = value.find('/', begin);
        const std::size_t end = slash == std::string_view::npos ? value.size() : slash;
        if (end != begin)
            parts.push_back(value.substr(begin, end - begin));
        if (slash == std::string_view::npos)
            break;
        begin = slash + 1;
    }
    return parts;
}

std::string join_provenance_path(std::string_view container_path,
                                 std::string_view member_path) {
    std::string encoded_member;
    encoded_member.reserve(member_path.size());
    constexpr char hex[] = "0123456789ABCDEF";
    for (const unsigned char character : member_path) {
        if (character == '%' || character == '!') {
            encoded_member.push_back('%');
            encoded_member.push_back(hex[character >> 4U]);
            encoded_member.push_back(hex[character & 0x0FU]);
        } else {
            encoded_member.push_back(static_cast<char>(character));
        }
    }
    if (container_path.empty())
        return encoded_member;
    std::string result;
    result.reserve(container_path.size() + encoded_member.size() + 1);
    result.append(container_path);
    result.push_back('!');
    result.append(encoded_member);
    return result;
}

std::string basename(std::string_view path) {
    const std::size_t slash = path.rfind('/');
    return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

std::string extensionless_name(std::string_view path) {
    std::string result = basename(path);
    const std::size_t dot = result.rfind('.');
    if (dot != std::string::npos)
        result.resize(dot);
    return result;
}

apk_module_identity_t base_module() {
    apk_module_identity_t module;
    module.name = "base";
    module.normalized_path = "base";
    module.is_base = true;
    return module;
}

apk_module_identity_t module_from_archive_path(std::string_view path) {
    apk_module_identity_t module;
    module.name = extensionless_name(path);
    if (module.name.empty())
        module.name = "base";
    module.normalized_path = module.name;
    module.is_base = module.name == "base";
    module.is_split = !module.is_base;
    return module;
}

apk_module_identity_t module_from_aab_path(std::string_view path) {
    const auto parts = split_path(path);
    if (parts.size() >= 3 &&
        (lower_ascii(parts[1]) == "dex" || lower_ascii(parts[1]) == "lib")) {
        apk_module_identity_t module;
        module.name.assign(parts[0]);
        module.normalized_path.assign(parts[0]);
        module.is_base = module.name == "base";
        module.is_split = !module.is_base;
        return module;
    }
    return base_module();
}

bool is_regular_member(const zip_member_t& member) noexcept {
    return member.kind == zip_member_kind_t::regular_file;
}

bool is_nested_archive_name(std::string_view path) {
    const std::string lower = lower_ascii(path);
    return ends_with(lower, ".apk") || ends_with(lower, ".aab") ||
           ends_with(lower, ".apks") || ends_with(lower, ".zip") ||
           ends_with(lower, ".jar");
}

bool is_dex_name(std::string_view path) {
    return ends_with(lower_ascii(path), ".dex");
}

bool is_compact_dex_name(std::string_view path) {
    return ends_with(lower_ascii(path), ".cdex");
}

bool is_dex_member_name(std::string_view path) {
    return is_dex_name(path) || is_compact_dex_name(path);
}

bool is_oat_name(std::string_view path) {
    return ends_with(lower_ascii(path), ".oat");
}

bool is_vdex_name(std::string_view path) {
    return ends_with(lower_ascii(path), ".vdex");
}

struct abi_profile_t {
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    bool is_64bit = false;
};

std::optional<abi_profile_t> abi_profile(std::string_view abi_name) {
    const std::string lower = lower_ascii(abi_name);
    if (lower == "armeabi" || lower == "armeabi-v7a")
        return abi_profile_t{architecture_id_t::arm, architecture_mode_t::arm_a32,
                             abi_id_t::android_arm, false};
    if (lower == "arm64-v8a")
        return abi_profile_t{architecture_id_t::aarch64, architecture_mode_t::aarch64,
                             abi_id_t::android_aarch64, true};
    if (lower == "x86")
        return abi_profile_t{architecture_id_t::x86, architecture_mode_t::x86_32,
                             abi_id_t::android_x86, false};
    if (lower == "x86_64")
        return abi_profile_t{architecture_id_t::x86_64, architecture_mode_t::x86_64,
                             abi_id_t::android_x86_64, true};
    if (lower == "mips")
        return abi_profile_t{architecture_id_t::mips, architecture_mode_t::mips32,
                             abi_id_t::unknown, false};
    if (lower == "mips64")
        return abi_profile_t{architecture_id_t::mips64, architecture_mode_t::mips64,
                             abi_id_t::unknown, true};
    if (lower == "riscv64")
        return abi_profile_t{architecture_id_t::riscv64, architecture_mode_t::riscv64,
                             abi_id_t::unknown, true};
    return std::nullopt;
}

std::optional<std::string> native_abi_for_member(apk_container_kind_t kind,
                                                  std::string_view path) {
    const auto parts = split_path(path);
    if (kind == apk_container_kind_t::aab) {
        if (parts.size() == 4 && lower_ascii(parts[1]) == "lib" &&
            ends_with(lower_ascii(parts[3]), ".so") && abi_profile(parts[2]))
            return std::string(parts[2]);
        return std::nullopt;
    }
    if (parts.size() == 3 && lower_ascii(parts[0]) == "lib" &&
        ends_with(lower_ascii(parts[2]), ".so") && abi_profile(parts[1]))
        return std::string(parts[1]);
    return std::nullopt;
}

apk_container_kind_t classify_archive(const zip_container_t& archive,
                                      std::string_view source_name) {
    bool root_manifest = false;
    bool aab_marker = false;
    bool direct_code = false;
    bool nested_apk = false;
    for (const auto& member : archive.members()) {
        if (!is_regular_member(member))
            continue;
        const std::string lower = lower_ascii(member.normalized_path);
        if (lower == "androidmanifest.xml")
            root_manifest = true;
        if (lower == "bundleconfig.pb" || lower == "base/manifest/androidmanifest.xml")
            aab_marker = true;
        if (is_dex_member_name(lower) || is_oat_name(lower) || is_vdex_name(lower) ||
            native_abi_for_member(apk_container_kind_t::apk, lower) ||
            native_abi_for_member(apk_container_kind_t::aab, lower))
            direct_code = true;
        if (ends_with(lower, ".apk"))
            nested_apk = true;
    }
    if (aab_marker)
        return apk_container_kind_t::aab;
    const std::string source_lower = lower_ascii(source_name);
    if (ends_with(source_lower, ".apks") || (!root_manifest && !direct_code && nested_apk))
        return apk_container_kind_t::apk_set;
    if (root_manifest || direct_code)
        return apk_container_kind_t::apk;
    return apk_container_kind_t::unknown;
}

class enumeration_budget_t final {
public:
    enumeration_budget_t(const apk_container_limits_t& limits,
                         const cancellation_token_t& cancel)
        : limits_(limits), cancel_(cancel), started_(std::chrono::steady_clock::now()) {}

    workspace_result_t<void> poll(std::string phase) const {
        if (cancel_.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel_, std::move(phase)));
        if (std::chrono::steady_clock::now() - started_ > limits_.max_elapsed) {
            auto error = apk_error(workspace_error_code_t::deadline_exceeded,
                                   "Android container operation exceeded its configured deadline",
                                   std::move(phase));
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> enter_archive(const zip_container_t& archive) {
        auto polled = poll("apk_enumerate");
        if (!polled)
            return polled;
        auto archives = charge(total_archives_, 1, limits_.max_total_archives,
                               "Android nested archive count exceeds its limit", "apk_enumerate");
        if (!archives)
            return archives;
        auto members = charge(total_members_, archive.members().size(), limits_.max_total_members,
                              "Android aggregate member count exceeds its limit", "apk_enumerate");
        if (!members)
            return members;
        auto compressed = charge(total_compressed_, archive.aggregate_compressed_size(),
                                 limits_.max_total_compressed_size,
                                 "Android aggregate compressed size exceeds its limit", "apk_enumerate");
        if (!compressed)
            return compressed;
        return charge(total_uncompressed_, archive.aggregate_uncompressed_size(),
                      limits_.max_total_uncompressed_size,
                      "Android aggregate uncompressed size exceeds its limit", "apk_enumerate");
    }

    workspace_result_t<void> open_candidate(const zip_member_t& member) {
        auto polled = poll("apk_member_open");
        if (!polled)
            return polled;
        return charge(probe_bytes_, member.uncompressed_size, limits_.max_probe_bytes,
                      "Android code-member probe work exceeds its limit", "apk_member_open");
    }

    workspace_result_t<void> add_code_member() {
        return charge(code_members_, 1, limits_.max_code_members,
                      "Android code-member count exceeds its limit", "apk_enumerate");
    }

private:
    workspace_result_t<void> charge(std::uint64_t& current, std::uint64_t value,
                                    std::uint64_t limit, std::string message,
                                    std::string phase) {
        if (value > limit || current > limit - value)
            return workspace_result_t<void>::failure(limit_error(
                std::move(message), std::move(phase),
                value > (std::numeric_limits<std::uint64_t>::max)() - current
                    ? (std::numeric_limits<std::uint64_t>::max)()
                    : current + value,
                limit));
        current += value;
        return workspace_result_t<void>::success();
    }

    const apk_container_limits_t& limits_;
    const cancellation_token_t& cancel_;
    std::chrono::steady_clock::time_point started_;
    std::uint64_t total_archives_ = 0;
    std::uint64_t total_members_ = 0;
    std::uint64_t total_compressed_ = 0;
    std::uint64_t total_uncompressed_ = 0;
    std::uint64_t probe_bytes_ = 0;
    std::uint64_t code_members_ = 0;
};

workspace_result_t<void> validate_limits(const apk_container_limits_t& limits) {
    if (limits.max_total_archives == 0 || limits.max_total_members == 0 ||
        limits.max_code_members == 0 || limits.max_total_compressed_size == 0 ||
        limits.max_total_uncompressed_size == 0 || limits.max_probe_bytes == 0 ||
        limits.max_elapsed.count() <= 0) {
        return workspace_result_t<void>::failure(apk_error(
            workspace_error_code_t::invalid_argument,
            "Android container limits contain a zero or negative required budget",
            "apk_open"));
    }
    return workspace_result_t<void>::success();
}

workspace_error_t apk_member_error(workspace_error_t error,
                                   std::string_view provenance_path,
                                   std::string phase) {
    if (!error.phase.empty())
        error.details.emplace_back("source_phase", std::move(error.phase));
    error.details.emplace_back("apk_member", std::string(provenance_path));
    error.phase = std::move(phase);
    return error;
}

apk_module_identity_t module_for_member(const archive_node_t& node,
                                        std::string_view member_path);

workspace_result_t<std::uint32_t> dex_version_number(
    const dex_container_info_t& container, std::string_view phase) {
    if (container.version.size() != 3) {
        return workspace_result_t<std::uint32_t>::failure(apk_error(
            workspace_error_code_t::malformed_image,
            "Android DEX container version is malformed", std::string(phase)));
    }
    std::uint32_t version = 0;
    for (const unsigned char character : container.version) {
        if (character < '0' || character > '9') {
            return workspace_result_t<std::uint32_t>::failure(apk_error(
                workspace_error_code_t::malformed_image,
                "Android DEX container version is malformed", std::string(phase)));
        }
        version = version * 10U + static_cast<std::uint32_t>(character - '0');
    }
    return workspace_result_t<std::uint32_t>::success(version);
}

std::optional<apk_code_kind_t> apk_code_kind_from_dex(
    dex_container_kind_t kind) noexcept {
    switch (kind) {
        case dex_container_kind_t::dex:
            return apk_code_kind_t::dex;
        case dex_container_kind_t::compact_dex:
            return apk_code_kind_t::compact_dex;
        case dex_container_kind_t::oat:
            return apk_code_kind_t::oat;
        case dex_container_kind_t::vdex:
            return apk_code_kind_t::vdex;
        case dex_container_kind_t::unknown:
            return std::nullopt;
    }
    return std::nullopt;
}

std::optional<dex_container_kind_t> dex_kind_from_apk_code(
    apk_code_kind_t kind) noexcept {
    switch (kind) {
        case apk_code_kind_t::dex:
            return dex_container_kind_t::dex;
        case apk_code_kind_t::compact_dex:
            return dex_container_kind_t::compact_dex;
        case apk_code_kind_t::oat:
            return dex_container_kind_t::oat;
        case apk_code_kind_t::vdex:
            return dex_container_kind_t::vdex;
        case apk_code_kind_t::elf:
        case apk_code_kind_t::apk:
        case apk_code_kind_t::aab:
        case apk_code_kind_t::zip:
            return std::nullopt;
    }
    return std::nullopt;
}

bool is_dex_candidate_compatible(dex_container_kind_t detected,
                                 bool dex_candidate, bool oat_candidate,
                                 bool vdex_candidate) noexcept {
    if (dex_candidate)
        return detected == dex_container_kind_t::dex ||
               detected == dex_container_kind_t::compact_dex;
    if (oat_candidate)
        return detected == dex_container_kind_t::oat;
    if (vdex_candidate)
        return detected == dex_container_kind_t::vdex;
    return false;
}

workspace_result_t<apk_code_member_t> make_dex_record(
    const archive_node_t& node, const zip_member_t& member,
    dex_container_info_t container) {
    const auto code_kind = apk_code_kind_from_dex(container.kind);
    if (!code_kind) {
        return workspace_result_t<apk_code_member_t>::failure(apk_error(
            workspace_error_code_t::unsupported_format,
            "Android member does not contain a supported DEX container", "apk_member_probe",
            member.data_offset, member.uncompressed_size));
    }
    auto version_result = dex_version_number(container, "apk_member_probe");
    if (!version_result)
        return workspace_result_t<apk_code_member_t>::failure(std::move(version_result.error()));
    apk_code_member_t record;
    record.role = (*code_kind == apk_code_kind_t::oat || *code_kind == apk_code_kind_t::vdex)
        ? apk_member_role_t::runtime_artifact : apk_member_role_t::dex;
    record.code_kind = *code_kind;
    record.format = *code_kind == apk_code_kind_t::oat ? format_id_t::oat :
                    *code_kind == apk_code_kind_t::vdex ? format_id_t::vdex : format_id_t::dex;
    record.architecture = architecture_id_t::dalvik_bytecode;
    record.architecture_mode = architecture_mode_t::dalvik;
    record.abi = abi_id_t::dalvik;
    record.execution_profile = *code_kind == apk_code_kind_t::compact_dex ? "compact-dalvik" :
                               *code_kind == apk_code_kind_t::oat ? "art-oat" :
                               *code_kind == apk_code_kind_t::vdex ? "art-vdex" : "dalvik";
    record.module = module_for_member(node, member.normalized_path);
    record.format_version = version_result.take_value();
    record.dex_container = std::move(container);
    return workspace_result_t<apk_code_member_t>::success(std::move(record));
}

struct elf_profile_t {
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    std::uint16_t machine = 0;
    bool is_64bit = false;
};

workspace_result_t<elf_profile_t> read_elf_profile(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    auto elf_result = is_elf_file(provider, cancel);
    if (!elf_result)
        return workspace_result_t<elf_profile_t>::failure(std::move(elf_result.error()));
    if (!elf_result.value())
        return workspace_result_t<elf_profile_t>::failure(apk_error(
            workspace_error_code_t::malformed_image,
            "Android ABI library is not an ELF image", "apk_member_probe"));
    if (provider.size() < 20)
        return workspace_result_t<elf_profile_t>::failure(apk_error(
            workspace_error_code_t::malformed_image,
            "Android ABI library has a truncated ELF header", "apk_member_probe"));
    std::array<std::uint8_t, 20> header{};
    auto read = provider.read_exact(0, header.data(), header.size(), cancel);
    if (!read)
        return workspace_result_t<elf_profile_t>::failure(std::move(read.error()));
    if ((header[4] != 1 && header[4] != 2) || (header[5] != 1 && header[5] != 2) ||
        header[6] != 1)
        return workspace_result_t<elf_profile_t>::failure(apk_error(
            workspace_error_code_t::malformed_image,
            "Android ABI library has an invalid ELF identity", "apk_member_probe"));
    const bool little_endian = header[5] == 1;
    const std::uint16_t machine = little_endian
        ? static_cast<std::uint16_t>(header[18]) |
              static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[19]) << 8U)
        : static_cast<std::uint16_t>(header[19]) |
              static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[18]) << 8U);
    elf_profile_t profile;
    profile.machine = machine;
    profile.is_64bit = header[4] == 2;
    profile.architecture = elf_machine_to_arch(machine);
    if (profile.architecture == architecture_id_t::mips && profile.is_64bit)
        profile.architecture = architecture_id_t::mips64;
    if (profile.architecture == architecture_id_t::riscv)
        profile.architecture = profile.is_64bit ? architecture_id_t::riscv64
                                                : architecture_id_t::riscv32;
    switch (profile.architecture) {
        case architecture_id_t::x86:
            profile.mode = architecture_mode_t::x86_32;
            break;
        case architecture_id_t::x86_64:
            profile.mode = architecture_mode_t::x86_64;
            break;
        case architecture_id_t::arm:
            profile.mode = architecture_mode_t::arm_a32;
            break;
        case architecture_id_t::aarch64:
            profile.mode = architecture_mode_t::aarch64;
            break;
        case architecture_id_t::mips:
            profile.mode = architecture_mode_t::mips32;
            break;
        case architecture_id_t::mips64:
            profile.mode = architecture_mode_t::mips64;
            break;
        case architecture_id_t::riscv32:
            profile.mode = architecture_mode_t::riscv32;
            break;
        case architecture_id_t::riscv64:
            profile.mode = architecture_mode_t::riscv64;
            break;
        default:
            return workspace_result_t<elf_profile_t>::failure(apk_error(
                workspace_error_code_t::unsupported_format,
                "Android ABI library uses an unsupported ELF machine", "apk_member_probe"));
    }
    return workspace_result_t<elf_profile_t>::success(profile);
}

apk_module_identity_t module_for_member(const archive_node_t& node,
                                        std::string_view member_path) {
    if (node.kind == apk_container_kind_t::aab)
        return module_from_aab_path(member_path);
    return node.default_module;
}

workspace_result_t<void> append_record(
    build_result_t& build, enumeration_budget_t& budget,
    const archive_node_t& node, const zip_member_t& member,
    apk_code_member_t record) {
    auto code_budget = budget.add_code_member();
    if (!code_budget)
        return code_budget;
    record.normalized_path = member.normalized_path;
    record.container_path = node.container_path;
    record.provenance_path = join_provenance_path(node.container_path, member.normalized_path);
    record.size = member.uncompressed_size;
    record.provider_metadata = member.provenance;
    record.provenance = node.provenance;
    record.provenance.push_back(member.provenance);
    if (!build.record_paths.emplace(record.provenance_path).second) {
        return workspace_result_t<void>::failure(apk_error(
            workspace_error_code_t::integrity_failure,
            "Android code-member provenance path is duplicated", "apk_enumerate"));
    }
    build.routes.push_back({node.archive_index, static_cast<std::size_t>(member.ordinal)});
    build.members.push_back(std::move(record));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::shared_ptr<zip_container_t>> open_nested_archive(
    std::shared_ptr<const byte_provider_t> provider,
    const apk_container_limits_t& limits,
    const cancellation_token_t& cancel,
    enumeration_budget_t& budget) {
    auto polled = budget.poll("apk_nested_open");
    if (!polled)
        return workspace_result_t<std::shared_ptr<zip_container_t>>::failure(
            std::move(polled.error()));
    auto zip_limits = limits.zip;
    zip_limits.max_elapsed = (std::min)(zip_limits.max_elapsed, limits.max_elapsed);
    return zip_container_t::open(std::move(provider), std::move(zip_limits), cancel);
}

workspace_result_t<std::uint64_t> discover_archive(
    build_result_t& build, const archive_node_t& node,
    const apk_container_limits_t& limits, const cancellation_token_t& cancel,
    enumeration_budget_t& budget) {
    auto entered = budget.enter_archive(*node.archive);
    if (!entered)
        return workspace_result_t<std::uint64_t>::failure(std::move(entered.error()));
    std::uint64_t discovered = 0;
    const auto& members = node.archive->members();
    for (std::size_t index = 0; index < members.size(); ++index) {
        auto polled = budget.poll("apk_enumerate");
        if (!polled)
            return workspace_result_t<std::uint64_t>::failure(std::move(polled.error()));
        const auto& member = members[index];
        if (!is_regular_member(member))
            continue;
        const std::string lower = lower_ascii(member.normalized_path);
        const bool nested = is_nested_archive_name(lower);
        const bool dex_candidate = is_dex_member_name(lower);
        const bool oat_candidate = is_oat_name(lower);
        const bool vdex_candidate = is_vdex_name(lower);
        const auto native_abi = native_abi_for_member(node.kind, member.normalized_path);
        if (!nested && !dex_candidate && !oat_candidate && !vdex_candidate && !native_abi)
            continue;
        auto probe_budget = budget.open_candidate(member);
        if (!probe_budget)
            return workspace_result_t<std::uint64_t>::failure(std::move(probe_budget.error()));
        auto provider_result = node.archive->open_member_provider(index, cancel);
        if (!provider_result)
            return workspace_result_t<std::uint64_t>::failure(std::move(provider_result.error()));
        auto provider = provider_result.take_value();
        auto after_open = budget.poll("apk_member_open");
        if (!after_open)
            return workspace_result_t<std::uint64_t>::failure(std::move(after_open.error()));
        if (nested) {
            auto nested_result = open_nested_archive(provider, limits, cancel, budget);
            if (!nested_result) {
                if (ends_with(lower, ".apk") || ends_with(lower, ".aab") ||
                    ends_with(lower, ".apks"))
                    return workspace_result_t<std::uint64_t>::failure(
                        std::move(nested_result.error()));
            } else {
                auto nested_archive = nested_result.take_value();
                archive_node_t child;
                child.archive = std::move(nested_archive);
                child.archive_index = build.archives.size();
                child.kind = classify_archive(*child.archive, member.normalized_path);
                child.container_path = join_provenance_path(node.container_path,
                                                            member.normalized_path);
                child.provenance = node.provenance;
                child.provenance.push_back(member.provenance);
                child.default_module = module_from_archive_path(member.normalized_path);
                build.archives.push_back(child.archive);
                auto child_result = discover_archive(build, child, limits, cancel, budget);
                if (!child_result)
                    return child_result;
                if (child_result.value() != 0) {
                    apk_code_member_t record;
                    record.role = apk_member_role_t::nested_container;
                    record.code_kind = child.kind == apk_container_kind_t::aab
                        ? apk_code_kind_t::aab
                        : child.kind == apk_container_kind_t::apk
                            ? apk_code_kind_t::apk
                            : apk_code_kind_t::zip;
                    record.format = child.kind == apk_container_kind_t::unknown
                        ? format_id_t::zip : format_id_t::apk;
                    record.execution_profile = "container";
                    record.module = module_for_member(node, member.normalized_path);
                    auto appended = append_record(build, budget, node, member, std::move(record));
                    if (!appended)
                        return workspace_result_t<std::uint64_t>::failure(
                            std::move(appended.error()));
                    ++discovered;
                }
            }
            continue;
        }
        if (dex_candidate || oat_candidate || vdex_candidate) {
            const std::string provenance_path = join_provenance_path(
                node.container_path, member.normalized_path);
            auto detected_result = detect_dex_container(*provider, cancel);
            if (!detected_result) {
                return workspace_result_t<std::uint64_t>::failure(apk_member_error(
                    std::move(detected_result.error()), provenance_path, "apk_member_probe"));
            }
            auto detected = detected_result.take_value();
            if (!is_dex_candidate_compatible(detected.kind, dex_candidate, oat_candidate,
                                             vdex_candidate)) {
                auto error = apk_error(workspace_error_code_t::malformed_image,
                                       "Android code member does not match its DEX container type",
                                       "apk_member_probe", member.data_offset,
                                       member.uncompressed_size);
                error.details.emplace_back("apk_member", provenance_path);
                error.details.emplace_back("detected",
                                           dex_container_kind_name(detected.kind));
                error.details.emplace_back("expected", dex_candidate ? "dex-or-compact-dex" :
                                                      oat_candidate ? "oat" : "vdex");
                return workspace_result_t<std::uint64_t>::failure(std::move(error));
            }
            auto record_result = make_dex_record(node, member, std::move(detected));
            if (!record_result) {
                return workspace_result_t<std::uint64_t>::failure(apk_member_error(
                    std::move(record_result.error()), provenance_path, "apk_member_probe"));
            }
            auto appended = append_record(build, budget, node, member,
                                          record_result.take_value());
            if (!appended)
                return workspace_result_t<std::uint64_t>::failure(std::move(appended.error()));
            ++discovered;
            continue;
        }
        if (native_abi) {
            const auto expected = abi_profile(*native_abi);
            auto elf_result = read_elf_profile(*provider, cancel);
            if (!elf_result)
                return workspace_result_t<std::uint64_t>::failure(std::move(elf_result.error()));
            const auto actual = elf_result.take_value();
            if (!expected || actual.architecture != expected->architecture ||
                actual.mode != expected->mode || actual.is_64bit != expected->is_64bit) {
                auto error = apk_error(workspace_error_code_t::integrity_failure,
                                       "Android ABI path does not match the embedded ELF image",
                                       "apk_member_probe", member.data_offset,
                                       member.uncompressed_size);
                error.details.emplace_back("abi", *native_abi);
                error.details.emplace_back("machine", std::to_string(actual.machine));
                return workspace_result_t<std::uint64_t>::failure(std::move(error));
            }
            apk_code_member_t record;
            record.role = apk_member_role_t::native_library;
            record.code_kind = apk_code_kind_t::elf;
            record.format = format_id_t::elf;
            record.architecture = actual.architecture;
            record.architecture_mode = actual.mode;
            record.abi = expected->abi;
            record.abi_name = *native_abi;
            record.execution_profile = "native";
            record.module = module_for_member(node, member.normalized_path);
            record.machine = actual.machine;
            auto appended = append_record(build, budget, node, member, std::move(record));
            if (!appended)
                return workspace_result_t<std::uint64_t>::failure(std::move(appended.error()));
            ++discovered;
        }
    }
    return workspace_result_t<std::uint64_t>::success(discovered);
}

}

struct apk_container_t::state_t {
    std::shared_ptr<const byte_provider_t> source;
    apk_container_limits_t limits;
    apk_container_kind_t kind = apk_container_kind_t::unknown;
    std::vector<std::shared_ptr<zip_container_t>> archives;
    std::vector<apk_code_member_t> members;
    std::vector<record_route_t> routes;
};

apk_container_t::apk_container_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {}

workspace_result_t<std::shared_ptr<apk_container_t>> apk_container_t::open(
    std::shared_ptr<const byte_provider_t> provider, apk_container_limits_t limits,
    const cancellation_token_t& cancel) {
    if (!provider) {
        return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(apk_error(
            workspace_error_code_t::invalid_argument,
            "Android container source provider is null", "apk_open"));
    }
    auto limits_result = validate_limits(limits);
    if (!limits_result)
        return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(
            std::move(limits_result.error()));
    try {
        enumeration_budget_t budget(limits, cancel);
        auto start = budget.poll("apk_open");
        if (!start)
            return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(
                std::move(start.error()));
        auto root_result = open_nested_archive(provider, limits, cancel, budget);
        if (!root_result)
            return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(
                std::move(root_result.error()));
        build_result_t build;
        auto root = root_result.take_value();
        build.kind = classify_archive(*root, provider->identity().normalized_source);
        build.archives.push_back(root);
        archive_node_t root_node;
        root_node.archive = std::move(root);
        root_node.archive_index = 0;
        root_node.kind = build.kind;
        root_node.default_module = base_module();
        auto discovery_result = discover_archive(build, root_node, limits, cancel, budget);
        if (!discovery_result)
            return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(
                std::move(discovery_result.error()));
        if (build.kind == apk_container_kind_t::unknown && discovery_result.value() == 0) {
            return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(apk_error(
                workspace_error_code_t::unsupported_format,
                "ZIP container has no Android APK, AAB, or code-bearing split evidence",
                "apk_open"));
        }
        if (build.kind == apk_container_kind_t::unknown)
            build.kind = apk_container_kind_t::apk_set;
        auto complete = budget.poll("apk_open");
        if (!complete)
            return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(
                std::move(complete.error()));
        auto state = std::make_shared<state_t>();
        state->source = std::move(provider);
        state->limits = std::move(limits);
        state->kind = build.kind;
        state->archives = std::move(build.archives);
        state->members = std::move(build.members);
        state->routes = std::move(build.routes);
        return workspace_result_t<std::shared_ptr<apk_container_t>>::success(
            std::shared_ptr<apk_container_t>(new apk_container_t(std::move(state))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(apk_error(
            workspace_error_code_t::limit_exceeded,
            "Android container allocation failed within configured limits", "apk_open"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<apk_container_t>>::failure(apk_error(
            workspace_error_code_t::limit_exceeded,
            "Android container allocation exceeded an addressable size", "apk_open"));
    }
}

const byte_provider_identity_t& apk_container_t::source_identity() const noexcept {
    return state_->source->identity();
}

const std::shared_ptr<const byte_provider_t>& apk_container_t::source_provider() const noexcept {
    return state_->source;
}

const apk_container_limits_t& apk_container_t::limits() const noexcept {
    return state_->limits;
}

apk_container_kind_t apk_container_t::kind() const noexcept {
    return state_->kind;
}

const std::vector<apk_code_member_t>& apk_container_t::members() const noexcept {
    return state_->members;
}

workspace_result_t<std::shared_ptr<byte_provider_t>>
apk_container_t::open_member_provider(std::size_t member_index,
                                      const cancellation_token_t& cancel) const {
    if (member_index >= state_->routes.size() || member_index >= state_->members.size()) {
        auto error = apk_error(workspace_error_code_t::out_of_range,
                               "Android code-member index is out of range",
                               "apk_member_open");
        error.offset = member_index;
        error.details.emplace_back("member_count", std::to_string(state_->members.size()));
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(std::move(error));
    }
    const auto route = state_->routes[member_index];
    if (route.archive_index >= state_->archives.size()) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(apk_error(
            workspace_error_code_t::integrity_failure,
            "Android code-member route references an unavailable archive",
            "apk_member_open"));
    }
    const auto& member = state_->members[member_index];
    auto provider_result = state_->archives[route.archive_index]->open_member_provider(
        route.member_index, cancel);
    if (!provider_result) {
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(apk_member_error(
            std::move(provider_result.error()), member.provenance_path, "apk_member_open"));
    }
    auto provider = provider_result.take_value();
    if (!provider || !provider->member_metadata() ||
        *provider->member_metadata() != member.provider_metadata) {
        auto error = apk_error(workspace_error_code_t::provider_binding_mismatch,
                               "Android code-member provider provenance does not match",
                               "apk_member_open");
        error.details.emplace_back("apk_member", member.provenance_path);
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(std::move(error));
    }
    return workspace_result_t<std::shared_ptr<byte_provider_t>>::success(std::move(provider));
}

workspace_result_t<apk_dex_member_record_t>
apk_container_t::parse_dex_member(std::size_t member_index,
                                  const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        return workspace_result_t<apk_dex_member_record_t>::failure(
            stop_error(cancel, "apk_dex_member_parse"));
    }
    if (member_index >= state_->members.size()) {
        auto error = apk_error(workspace_error_code_t::out_of_range,
                               "Android DEX member index is out of range",
                               "apk_dex_member_parse");
        error.offset = member_index;
        error.details.emplace_back("member_count", std::to_string(state_->members.size()));
        return workspace_result_t<apk_dex_member_record_t>::failure(std::move(error));
    }
    const auto& member = state_->members[member_index];
    const auto expected_kind = dex_kind_from_apk_code(member.code_kind);
    if (!expected_kind) {
        auto error = apk_error(workspace_error_code_t::unsupported_format,
                               "Android code member is not a DEX, compact DEX, OAT, or VDEX member",
                               "apk_dex_member_parse");
        error.details.emplace_back("apk_member", member.provenance_path);
        return workspace_result_t<apk_dex_member_record_t>::failure(std::move(error));
    }
    auto provider_result = open_member_provider(member_index, cancel);
    if (!provider_result)
        return workspace_result_t<apk_dex_member_record_t>::failure(
            std::move(provider_result.error()));
    auto provider = provider_result.take_value();
    auto image_result = parse_dex_image(*provider, state_->limits.dex, cancel);
    if (!image_result) {
        return workspace_result_t<apk_dex_member_record_t>::failure(apk_member_error(
            std::move(image_result.error()), member.provenance_path, "apk_dex_member_parse"));
    }
    auto image = image_result.take_value();
    if (!member.dex_container || image.container.kind != *expected_kind ||
        member.dex_container->kind != image.container.kind ||
        member.dex_container->version != image.container.version) {
        auto error = apk_error(workspace_error_code_t::integrity_failure,
                               "Android DEX member container metadata changed after enumeration",
                               "apk_dex_member_parse");
        error.details.emplace_back("apk_member", member.provenance_path);
        error.details.emplace_back("expected", dex_container_kind_name(*expected_kind));
        error.details.emplace_back("actual", dex_container_kind_name(image.container.kind));
        return workspace_result_t<apk_dex_member_record_t>::failure(std::move(error));
    }
    auto version_result = dex_version_number(image.container, "apk_dex_member_parse");
    if (!version_result) {
        return workspace_result_t<apk_dex_member_record_t>::failure(apk_member_error(
            std::move(version_result.error()), member.provenance_path, "apk_dex_member_parse"));
    }
    if (version_result.value() != member.format_version ||
        image.normalized.format != member.format ||
        image.normalized.architecture != member.architecture ||
        image.normalized.architecture_mode != member.architecture_mode ||
        image.normalized.abi != member.abi) {
        auto error = apk_error(workspace_error_code_t::integrity_failure,
                               "Android DEX member normalization does not match its record",
                               "apk_dex_member_parse");
        error.details.emplace_back("apk_member", member.provenance_path);
        return workspace_result_t<apk_dex_member_record_t>::failure(std::move(error));
    }
    apk_dex_member_record_t record;
    record.member = member;
    record.image = std::move(image);
    record.provider = std::move(provider);
    return workspace_result_t<apk_dex_member_record_t>::success(std::move(record));
}

workspace_result_t<void> apk_container_t::verify_integrity(
    const cancellation_token_t& cancel) const {
    for (const auto& archive : state_->archives) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel, "apk_verify_integrity"));
        auto verified = archive->verify_integrity(cancel);
        if (!verified)
            return verified;
    }
    return workspace_result_t<void>::success();
}

bool apk_container_t::integrity_verified() const {
    return std::all_of(state_->archives.begin(), state_->archives.end(),
                       [](const std::shared_ptr<zip_container_t>& archive) {
                           return archive && archive->integrity_verified();
                       });
}

}
