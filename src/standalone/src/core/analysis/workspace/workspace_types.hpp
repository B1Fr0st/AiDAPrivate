#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace aida::analysis {

enum class target_kind_t : std::uint8_t {
    static_file = 0,
    live_snapshot = 1
};

enum class format_id_t : std::uint8_t {
    unknown = 0,
    pe32 = 1,
    pe32_plus = 2,
    elf = 3,
    jar = 4,
    macho = 5,
    macho_fat = 6,
    coff = 7,
    archive = 8,
    zip = 9,
    apk = 10,
    ipa = 11,
    dex = 12,
    oat = 13,
    vdex = 14,
    classfile = 15,
    raw_code = 16
};

enum class architecture_id_t : std::uint8_t {
    unknown = 0,
    x86 = 1,
    x86_64 = 2,
    arm = 3,
    aarch64 = 4,
    mips = 5,
    ppc = 6,
    ppc64 = 7,
    riscv = 8,
    jvm_bytecode = 9,
    arm64ec = 10,
    mips64 = 11,
    riscv32 = 12,
    riscv64 = 13,
    dalvik_bytecode = 14
};

enum class architecture_mode_t : std::uint8_t {
    unknown = 0,
    x86_16 = 1,
    x86_32 = 2,
    x86_64 = 3,
    arm_a32 = 4,
    arm_thumb = 5,
    aarch64 = 6,
    mips32 = 7,
    mips64 = 8,
    ppc32 = 9,
    ppc64 = 10,
    riscv32 = 11,
    riscv64 = 12,
    jvm = 13,
    dalvik = 14
};

enum class abi_id_t : std::uint8_t {
    unknown = 0,
    windows_x86 = 1,
    windows_x64 = 2,
    linux_x86 = 3,
    linux_x64 = 4,
    linux_arm = 5,
    linux_aarch64 = 6,
    sysv = 7,
    windows_arm64 = 8,
    windows_arm64ec = 9,
    linux_mips = 10,
    linux_ppc = 11,
    linux_ppc64 = 12,
    linux_riscv = 13,
    darwin = 14,
    darwin_x86_64 = 15,
    darwin_aarch64 = 16,
    android_arm = 17,
    android_aarch64 = 18,
    android_x86 = 19,
    android_x86_64 = 20,
    jvm = 21,
    dalvik = 22
};

enum class endian_t : std::uint8_t {
    little = 0,
    big = 1
};

enum class address_space_id_t : std::uint8_t {
    file_offset = 0,
    relative_virtual = 1,
    virtual_address = 2,
    live_virtual = 3
};

struct address_t {
    std::uint64_t value = 0;
    address_space_id_t space = address_space_id_t::relative_virtual;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;

    constexpr address_t() noexcept = default;

    constexpr address_t(address_space_id_t address_space, std::uint64_t address_value,
                        architecture_id_t address_architecture = architecture_id_t::unknown,
                        architecture_mode_t address_mode = architecture_mode_t::unknown) noexcept
        : value(address_value), space(address_space),
          architecture(address_architecture), mode(address_mode) {}

    friend bool operator==(const address_t& lhs, const address_t& rhs) noexcept {
        return lhs.space == rhs.space && lhs.value == rhs.value &&
               lhs.architecture == rhs.architecture && lhs.mode == rhs.mode;
    }

    friend bool operator!=(const address_t& lhs, const address_t& rhs) noexcept {
        return !(lhs == rhs);
    }

    friend bool operator<(const address_t& lhs, const address_t& rhs) noexcept {
        if (lhs.space != rhs.space)
            return lhs.space < rhs.space;
        if (lhs.value != rhs.value)
            return lhs.value < rhs.value;
        if (lhs.architecture != rhs.architecture)
            return lhs.architecture < rhs.architecture;
        return lhs.mode < rhs.mode;
    }
};

static_assert(sizeof(address_t) == 16,
              "address_t must remain 16 bytes for compact snapshot residency");
static_assert(alignof(address_t) == 8,
              "address_t must remain 8-byte aligned");
static_assert(offsetof(address_t, value) == 0,
              "address_t value must stay at offset 0");
static_assert(offsetof(address_t, space) == 8,
              "address_t space must stay at offset 8");
static_assert(std::is_trivially_copyable<address_t>::value,
              "address_t must remain trivially copyable");
static_assert(std::is_standard_layout<address_t>::value,
              "address_t must remain standard layout");

struct address_hash_t {
    std::size_t operator()(const address_t& address) const noexcept {
        std::uint64_t value = address.value;
        value ^= static_cast<std::uint64_t>(address.space) << 56;
        value ^= static_cast<std::uint64_t>(address.architecture) << 48;
        value ^= static_cast<std::uint64_t>(address.mode) << 40;
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdULL;
        value ^= value >> 33;
        value *= 0xc4ceb9fe1a85ec53ULL;
        value ^= value >> 33;
        return static_cast<std::size_t>(value);
    }
};

struct binary_id_t {
    std::array<std::uint8_t, 32> bytes{};

    bool empty() const noexcept;
    std::string to_hex() const;
    static std::optional<binary_id_t> from_hex(const std::string& text) noexcept;
    bool constant_time_equal(const binary_id_t& other) const noexcept;

    friend bool operator==(const binary_id_t& lhs, const binary_id_t& rhs) noexcept {
        return lhs.constant_time_equal(rhs);
    }

    friend bool operator!=(const binary_id_t& lhs, const binary_id_t& rhs) noexcept {
        return !lhs.constant_time_equal(rhs);
    }

    friend bool operator<(const binary_id_t& lhs, const binary_id_t& rhs) noexcept {
        return lhs.bytes < rhs.bytes;
    }
};

using sha256_digest_t = binary_id_t;

struct binary_id_hash_t {
    std::size_t operator()(const binary_id_t& id) const noexcept;
};

enum image_permission_flag_t : std::uint32_t {
    image_permission_none = 0,
    image_permission_read = 1U << 0,
    image_permission_write = 1U << 1,
    image_permission_execute = 1U << 2,
    image_permission_discardable = 1U << 3
};

enum class image_symbol_kind_t : std::uint8_t {
    unknown = 0,
    function = 1,
    object = 2,
    section = 3,
    import_symbol = 4,
    export_symbol = 5,
    debug_symbol = 6,
    type_symbol = 7,
    metadata = 8
};

enum class image_symbol_binding_t : std::uint8_t {
    unknown = 0,
    local = 1,
    global = 2,
    weak = 3,
    external = 4
};

struct image_address_mapping_t {
    address_space_id_t source_space = address_space_id_t::file_offset;
    address_space_id_t target_space = address_space_id_t::relative_virtual;
    std::uint64_t source_start = 0;
    std::uint64_t target_start = 0;
    std::uint64_t size = 0;
    std::uint32_t permissions = image_permission_none;
};

struct image_entry_point_t {
    address_t address;
    std::string provenance;
};

struct image_segment_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint64_t alignment = 0;
    std::uint64_t flags = 0;
    std::uint32_t permissions = image_permission_none;
};

struct image_section_t {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t virtual_address = 0;
    std::uint64_t virtual_size = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t file_size = 0;
    std::uint64_t flags = 0;
    std::uint32_t permissions = image_permission_none;
};

struct image_symbol_t {
    std::uint64_t ordinal = 0;
    std::string name;
    address_t address;
    std::uint64_t size = 0;
    image_symbol_kind_t kind = image_symbol_kind_t::unknown;
    image_symbol_binding_t binding = image_symbol_binding_t::unknown;
    bool defined = false;
    bool forwarded = false;
};

struct image_import_t {
    std::string library;
    std::optional<std::string> name;
    std::optional<std::uint64_t> ordinal;
    address_t lookup_address;
    address_t address;
    bool delayed = false;
};

struct image_export_t {
    std::optional<std::string> name;
    std::uint64_t ordinal = 0;
    address_t address;
    std::optional<std::string> forwarder;
};

struct image_relocation_t {
    address_t address;
    std::uint64_t type = 0;
    std::optional<address_t> target;
};

struct provider_member_metadata_t {
    std::string normalized_member_path;
    std::uint64_t container_offset = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint64_t ordinal = 0;
    std::uint32_t depth = 0;
    std::uint32_t crc32 = 0;
    bool compressed = false;

    friend bool operator==(const provider_member_metadata_t& lhs,
                           const provider_member_metadata_t& rhs) noexcept {
        return lhs.normalized_member_path == rhs.normalized_member_path &&
               lhs.container_offset == rhs.container_offset &&
               lhs.compressed_size == rhs.compressed_size &&
               lhs.uncompressed_size == rhs.uncompressed_size &&
               lhs.ordinal == rhs.ordinal && lhs.depth == rhs.depth &&
               lhs.crc32 == rhs.crc32 && lhs.compressed == rhs.compressed;
    }

    friend bool operator!=(const provider_member_metadata_t& lhs,
                           const provider_member_metadata_t& rhs) noexcept {
        return !(lhs == rhs);
    }
};

struct workspace_image_t {
    std::uint32_t schema_version = 1;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::uint8_t address_width_bits = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t header_size = 0;
    std::string format_name;
    std::vector<image_address_mapping_t> address_mappings;
    std::vector<image_entry_point_t> entry_points;
    std::vector<image_segment_t> segments;
    std::vector<image_section_t> sections;
    std::vector<image_symbol_t> symbols;
    std::vector<image_import_t> imports;
    std::vector<image_export_t> exports;
    std::vector<image_relocation_t> relocations;
    std::optional<provider_member_metadata_t> member;
    binary_id_t workspace_binary_id;
    sha256_digest_t provider_content_hash;
    std::string provider_source;
    std::uint64_t provider_size = 0;
    bool provider_binding_verified = false;
};

using normalized_workspace_image_t = workspace_image_t;

struct workspace_image_limits_t {
    std::uint64_t max_address_mappings = 1ULL << 20;
    std::uint64_t max_entries = 1ULL << 16;
    std::uint64_t max_segments = 1ULL << 20;
    std::uint64_t max_sections = 1ULL << 20;
    std::uint64_t max_symbols = 1ULL << 22;
    std::uint64_t max_imports = 1ULL << 22;
    std::uint64_t max_exports = 1ULL << 22;
    std::uint64_t max_relocations = 1ULL << 24;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_member_path_bytes = 32768;
    std::uint32_t max_member_depth = 64;
};

inline bool workspace_architecture_mode_matches(architecture_id_t architecture,
                                                architecture_mode_t mode) noexcept {
    switch (architecture) {
        case architecture_id_t::x86:
            return mode == architecture_mode_t::x86_16 ||
                   mode == architecture_mode_t::x86_32;
        case architecture_id_t::x86_64:
            return mode == architecture_mode_t::x86_64;
        case architecture_id_t::arm:
            return mode == architecture_mode_t::arm_a32 ||
                   mode == architecture_mode_t::arm_thumb;
        case architecture_id_t::aarch64:
        case architecture_id_t::arm64ec:
            return mode == architecture_mode_t::aarch64;
        case architecture_id_t::mips:
            return mode == architecture_mode_t::mips32 ||
                   mode == architecture_mode_t::mips64;
        case architecture_id_t::mips64:
            return mode == architecture_mode_t::mips64;
        case architecture_id_t::ppc:
            return mode == architecture_mode_t::ppc32;
        case architecture_id_t::ppc64:
            return mode == architecture_mode_t::ppc64;
        case architecture_id_t::riscv:
            return mode == architecture_mode_t::riscv32 ||
                   mode == architecture_mode_t::riscv64;
        case architecture_id_t::riscv32:
            return mode == architecture_mode_t::riscv32;
        case architecture_id_t::riscv64:
            return mode == architecture_mode_t::riscv64;
        case architecture_id_t::jvm_bytecode:
            return mode == architecture_mode_t::jvm;
        case architecture_id_t::dalvik_bytecode:
            return mode == architecture_mode_t::dalvik;
        case architecture_id_t::unknown:
            return false;
    }
    return false;
}

struct process_identity_t {
    std::uint32_t pid = 0;
    std::uint64_t creation_time_100ns = 0;
    std::string normalized_process_path;

    friend bool operator==(const process_identity_t& lhs, const process_identity_t& rhs) noexcept {
        return lhs.pid == rhs.pid && lhs.creation_time_100ns == rhs.creation_time_100ns &&
               lhs.normalized_process_path == rhs.normalized_process_path;
    }
};

struct module_identity_t {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string normalized_name;
    std::string normalized_path;
    std::optional<sha256_digest_t> content_hash;

    friend bool operator==(const module_identity_t& lhs, const module_identity_t& rhs) noexcept {
        return lhs.base == rhs.base && lhs.size == rhs.size &&
               lhs.normalized_name == rhs.normalized_name && lhs.normalized_path == rhs.normalized_path &&
               lhs.content_hash == rhs.content_hash;
    }
};

enum class workspace_error_code_t : std::uint16_t {
    none = 0,
    range_overflow,
    out_of_range,
    file_changed,
    malformed_pe,
    unsupported_pe_arch,
    cancelled,
    deadline_exceeded,
    stale_generation,
    target_required,
    target_conflict,
    target_ambiguous,
    target_not_found,
    target_stale,
    self_target_refused,
    live_target_bulk_analysis_unsupported,
    revision_conflict,
    persistence_failure,
    invalid_argument,
    io_failure,
    hash_failure,
    provider_unavailable,
    duplicate_target,
    workspace_closing,
    unsupported_address_space,
    limit_exceeded,
    decode_failure,
    integrity_failure,
    analysis_in_progress,
    service_conflict,
    substitution_rejected,
    malformed_image,
    unsupported_format,
    provider_binding_mismatch
};

const char* workspace_error_code_name(workspace_error_code_t code) noexcept;

struct workspace_error_t {
    workspace_error_code_t code = workspace_error_code_t::none;
    std::string message;
    std::string phase;
    std::optional<std::uint64_t> offset;
    std::optional<address_t> address;
    std::optional<std::uint64_t> size;
    std::optional<std::uint32_t> win32_status;
    std::optional<std::int64_t> sqlite_status;
    std::optional<std::int64_t> provider_status;
    bool cancellation = false;
    bool deadline = false;
    std::vector<std::pair<std::string, std::string>> details;

    std::string stable_code() const;
};

workspace_error_t make_workspace_error(workspace_error_code_t code, std::string message,
                                       std::string phase = {});

template <typename T>
class workspace_result_t {
public:
    static workspace_result_t success(T value) {
        return workspace_result_t(std::move(value));
    }

    static workspace_result_t failure(workspace_error_t error) {
        return workspace_result_t(std::move(error));
    }

    bool has_value() const noexcept {
        return std::holds_alternative<T>(storage_);
    }

    explicit operator bool() const noexcept {
        return has_value();
    }

    T& value() {
        return std::get<T>(storage_);
    }

    const T& value() const {
        return std::get<T>(storage_);
    }

    T take_value() {
        return std::move(std::get<T>(storage_));
    }

    workspace_error_t& error() {
        return std::get<workspace_error_t>(storage_);
    }

    const workspace_error_t& error() const {
        return std::get<workspace_error_t>(storage_);
    }

private:
    explicit workspace_result_t(T value) : storage_(std::move(value)) {}
    explicit workspace_result_t(workspace_error_t error) : storage_(std::move(error)) {}

    std::variant<T, workspace_error_t> storage_;
};

template <>
class workspace_result_t<void> {
public:
    static workspace_result_t success() {
        return workspace_result_t();
    }

    static workspace_result_t failure(workspace_error_t error) {
        return workspace_result_t(std::move(error));
    }

    bool has_value() const noexcept {
        return !error_.has_value();
    }

    explicit operator bool() const noexcept {
        return has_value();
    }

    workspace_error_t& error() {
        if (!error_)
            throw std::logic_error("workspace_result_t has no error");
        return *error_;
    }

    const workspace_error_t& error() const {
        if (!error_)
            throw std::logic_error("workspace_result_t has no error");
        return *error_;
    }

private:
    workspace_result_t() = default;
    explicit workspace_result_t(workspace_error_t error) : error_(std::move(error)) {}

    std::optional<workspace_error_t> error_;
};

class cancellation_token_t {
public:
    cancellation_token_t() = default;

    bool cancellation_requested() const noexcept;
    bool deadline_exceeded() const noexcept;
    bool stop_requested() const noexcept;
    std::optional<std::chrono::steady_clock::time_point> deadline() const noexcept;

private:
    struct state_t {
        std::atomic<bool> requested{false};
        std::atomic<std::int64_t> deadline_ticks{0};
    };

    explicit cancellation_token_t(std::shared_ptr<state_t> state) : state_(std::move(state)) {}
    std::shared_ptr<state_t> state_;

    friend class cancellation_source_t;
};

class cancellation_source_t {
public:
    cancellation_source_t();
    explicit cancellation_source_t(std::optional<std::chrono::steady_clock::time_point> deadline);

    cancellation_token_t token() const noexcept;
    void request_cancel() noexcept;
    void set_deadline(std::optional<std::chrono::steady_clock::time_point> deadline) noexcept;

private:
    std::shared_ptr<cancellation_token_t::state_t> state_;
};

inline bool workspace_image_span_within(std::uint64_t start, std::uint64_t size,
                                        std::uint64_t limit) noexcept {
    return start <= limit && size <= limit - start;
}

inline bool workspace_image_contains(const workspace_image_t& image,
                                     const address_t& address,
                                     std::uint64_t size = 1) noexcept {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return false;
    std::uint64_t rva = address.value;
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual) {
        if (rva < image.image_base)
            return false;
        rva -= image.image_base;
    } else if (address.space != address_space_id_t::relative_virtual) {
        return false;
    }
    if (!workspace_image_span_within(rva, size, image.image_size))
        return false;
    if (workspace_image_span_within(rva, size, image.header_size))
        return true;
    const auto contains_region = [&](const auto& region) noexcept {
        const std::uint64_t extent = region.virtual_size > region.file_size
            ? region.virtual_size : region.file_size;
        return workspace_image_span_within(region.virtual_address, extent, image.image_size) &&
               rva >= region.virtual_address &&
               workspace_image_span_within(rva - region.virtual_address, size, extent);
    };
    for (const auto& section : image.sections)
        if (contains_region(section))
            return true;
    for (const auto& segment : image.segments)
        if (contains_region(segment))
            return true;
    return false;
}

inline workspace_result_t<void> validate_workspace_image(
    const workspace_image_t& image, const workspace_image_limits_t& limits = {},
    bool require_provider_binding = false,
    const cancellation_token_t& cancel = {}) {
    std::uint64_t validation_visits = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((validation_visits++ & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(
                cancel.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "normalized image validation cancelled", "workspace_image");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        return workspace_result_t<void>::success();
    };
    auto stopped = poll();
    if (!stopped)
        return stopped;
    if (image.schema_version == 0 || image.format == format_id_t::unknown ||
        image.format > format_id_t::raw_code ||
        image.architecture == architecture_id_t::unknown ||
        image.architecture > architecture_id_t::dalvik_bytecode ||
        image.architecture_mode == architecture_mode_t::unknown ||
        image.architecture_mode > architecture_mode_t::dalvik ||
        image.abi == abi_id_t::unknown || image.abi > abi_id_t::dalvik ||
        !workspace_architecture_mode_matches(image.architecture, image.architecture_mode) ||
        image.endian > endian_t::big ||
        (image.address_width_bits != 8 && image.address_width_bits != 16 &&
         image.address_width_bits != 32 && image.address_width_bits != 64) ||
        image.image_size == 0 || image.header_size > image.image_size ||
        image.provider_size == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::malformed_image,
            "normalized image header is invalid", "workspace_image"));
    }
    if (image.address_mappings.size() > limits.max_address_mappings ||
        image.entry_points.size() > limits.max_entries ||
        image.segments.size() > limits.max_segments ||
        image.sections.size() > limits.max_sections ||
        image.symbols.size() > limits.max_symbols ||
        image.imports.size() > limits.max_imports ||
        image.exports.size() > limits.max_exports ||
        image.relocations.size() > limits.max_relocations) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "normalized image exceeds its record budget", "workspace_image"));
    }
    if (require_provider_binding &&
        (!image.provider_binding_verified || image.workspace_binary_id.empty() ||
         image.provider_content_hash.empty() || image.provider_source.empty())) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::provider_binding_mismatch,
            "normalized image is not bound to a verified provider", "workspace_image"));
    }
    std::uint64_t string_bytes = 0;
    const auto consume_string = [&](const std::string& value) {
        const auto length = static_cast<std::uint64_t>(value.size());
        if (length > limits.max_string_bytes - string_bytes)
            return false;
        string_bytes += length;
        return true;
    };
    if (!consume_string(image.format_name) || !consume_string(image.provider_source)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "normalized image string budget is exceeded", "workspace_image"));
    }
    constexpr std::uint32_t allowed_permissions = image_permission_read |
                                                  image_permission_write |
                                                  image_permission_execute |
                                                  image_permission_discardable;
    const auto mapping_span_valid = [&](address_space_id_t space,
                                        std::uint64_t start,
                                        std::uint64_t size) noexcept {
        switch (space) {
            case address_space_id_t::file_offset:
                return workspace_image_span_within(start, size, image.provider_size);
            case address_space_id_t::relative_virtual:
                return workspace_image_span_within(start, size, image.image_size);
            case address_space_id_t::virtual_address:
            case address_space_id_t::live_virtual:
                return start >= image.image_base &&
                       workspace_image_span_within(start - image.image_base,
                                                   size, image.image_size);
        }
        return false;
    };
    for (const auto& mapping : image.address_mappings) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if (mapping.source_space > address_space_id_t::live_virtual ||
            mapping.target_space > address_space_id_t::live_virtual ||
            (mapping.permissions & ~allowed_permissions) != 0 || mapping.size == 0 ||
            !mapping_span_valid(mapping.source_space, mapping.source_start, mapping.size) ||
            !mapping_span_valid(mapping.target_space, mapping.target_start, mapping.size)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image address mapping is invalid", "workspace_image"));
        }
    }
    const auto validate_range = [&](std::uint64_t virtual_address, std::uint64_t virtual_size,
                                    std::uint64_t file_offset, std::uint64_t file_size,
                                    std::uint32_t permissions,
                                    const std::string& name) -> workspace_result_t<void> {
        const std::uint64_t extent = virtual_size > file_size ? virtual_size : file_size;
        if (extent == 0 || !workspace_image_span_within(virtual_address, extent, image.image_size) ||
            !workspace_image_span_within(file_offset, file_size, image.provider_size) ||
            (permissions & ~allowed_permissions) != 0 ||
            !consume_string(name)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image range is invalid", "workspace_image"));
        }
        return workspace_result_t<void>::success();
    };
    for (const auto& segment : image.segments) {
        stopped = poll();
        if (!stopped)
            return stopped;
        auto result = validate_range(segment.virtual_address, segment.virtual_size,
                                     segment.file_offset, segment.file_size,
                                     segment.permissions, segment.name);
        if (!result)
            return result;
    }
    for (const auto& section : image.sections) {
        stopped = poll();
        if (!stopped)
            return stopped;
        auto result = validate_range(section.virtual_address, section.virtual_size,
                                     section.file_offset, section.file_size,
                                     section.permissions, section.name);
        if (!result)
            return result;
    }
    const auto validate_address = [&](const address_t& address) {
        return workspace_image_contains(image, address, 1);
    };
    for (const auto& entry : image.entry_points) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if (!validate_address(entry.address) || !consume_string(entry.provenance)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image entry point is invalid", "workspace_image"));
        }
    }
    for (const auto& symbol : image.symbols) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if ((!symbol.name.empty() && !consume_string(symbol.name)) ||
            (symbol.defined && !validate_address(symbol.address))) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image symbol is invalid", "workspace_image"));
        }
    }
    for (const auto& imported : image.imports) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if (imported.library.empty() || !consume_string(imported.library) ||
            (imported.name && !consume_string(*imported.name)) ||
            !validate_address(imported.lookup_address) ||
            !validate_address(imported.address)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image import is invalid", "workspace_image"));
        }
    }
    for (const auto& exported : image.exports) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if ((exported.name && !consume_string(*exported.name)) ||
            (exported.forwarder && !consume_string(*exported.forwarder)) ||
            !validate_address(exported.address)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image export is invalid", "workspace_image"));
        }
    }
    for (const auto& relocation : image.relocations) {
        stopped = poll();
        if (!stopped)
            return stopped;
        if (!validate_address(relocation.address) ||
            (relocation.target && !validate_address(*relocation.target))) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image relocation is invalid", "workspace_image"));
        }
    }
    if (image.member) {
        const auto& member = *image.member;
        if (member.normalized_member_path.empty() ||
            member.normalized_member_path.size() > limits.max_member_path_bytes ||
            member.normalized_member_path.front() == '/' ||
            member.normalized_member_path.find('\\') != std::string::npos ||
            member.normalized_member_path.find('\0') != std::string::npos ||
            member.depth == 0 || member.depth > limits.max_member_depth ||
            member.compressed_size == 0 ||
            member.uncompressed_size != image.provider_size ||
            (!member.compressed && member.compressed_size != member.uncompressed_size) ||
            !workspace_image_span_within(member.container_offset, member.compressed_size,
                                         (std::numeric_limits<std::uint64_t>::max)())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::malformed_image,
                "normalized image member metadata is invalid", "workspace_image"));
        }
        std::size_t component_start = 0;
        while (component_start < member.normalized_member_path.size()) {
            stopped = poll();
            if (!stopped)
                return stopped;
            const auto separator = member.normalized_member_path.find('/', component_start);
            const auto component_end = separator == std::string::npos
                ? member.normalized_member_path.size() : separator;
            const auto component_length = component_end - component_start;
            if (component_length == 0 ||
                (component_length == 1 &&
                 member.normalized_member_path[component_start] == '.') ||
                (component_length == 2 &&
                 member.normalized_member_path[component_start] == '.' &&
                 member.normalized_member_path[component_start + 1] == '.')) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::malformed_image,
                    "normalized image member path is invalid", "workspace_image"));
            }
            if (separator == std::string::npos)
                break;
            component_start = separator + 1;
        }
    }
    return workspace_result_t<void>::success();
}

struct target_selector_t {
    std::optional<binary_id_t> binary_id;
    std::optional<std::string> bin_name;
    std::optional<std::uint32_t> pid;
    std::optional<std::uint64_t> process_creation_time_100ns;
};

}
