#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace aida::analysis::c03 {

inline constexpr std::uint32_t c03_contract_schema_version = 3;
inline constexpr std::uint64_t kibibyte = 1024ULL;
inline constexpr std::uint64_t mebibyte = 1024ULL * kibibyte;
inline constexpr std::uint64_t gibibyte = 1024ULL * mebibyte;
inline constexpr std::uint64_t max_incremental_private_bytes = 8ULL * gibibyte;
inline constexpr std::uint64_t max_workspace_mapped_window_bytes = gibibyte;
inline constexpr std::uint64_t max_global_mapped_window_bytes = 2ULL * gibibyte;
inline constexpr std::uint64_t max_workspace_spill_bytes = gibibyte;
inline constexpr std::uint64_t max_global_spill_bytes = 2ULL * gibibyte;
inline constexpr std::uint64_t max_workspace_cache_bytes = gibibyte;
inline constexpr std::uint64_t max_global_cache_bytes = 2ULL * gibibyte;
inline constexpr std::uint32_t max_cancellation_checkpoint_milliseconds = 250U;

enum class contract_schema_t : std::uint16_t {
    workspace_identity = 1,
    target_identity = 2,
    generation_identity = 3,
    immutable_snapshot = 4,
    immutable_publication = 5,
    packed_analysis_id = 6,
    resource_budget = 7,
    cancellation_domain = 8,
    static_provider_provenance = 9,
    live_target_identity = 10
};

enum class contract_error_code_t : std::uint16_t {
    none = 0,
    invalid_workspace_identity = 1,
    invalid_target_identity = 2,
    invalid_generation_identity = 3,
    generation_mismatch = 4,
    invalid_publication_stage = 5,
    publication_transition_rejected = 6,
    packed_id_overflow = 7,
    invalid_packed_id = 8,
    invalid_resource_budget = 9,
    resource_budget_exceeded = 10,
    arithmetic_overflow = 11,
    invalid_cancellation_domain = 12,
    cancellation_domain_mismatch = 13,
    serialization_schema_mismatch = 14,
    invalid_static_provider_provenance = 15,
    invalid_live_target_identity = 16,
    target_identity_provenance_mismatch = 17,
    invalid_binary_format = 18,
    invalid_binary_architecture = 19,
    invalid_binary_mode = 20,
    invalid_binary_endian = 21,
    invalid_metadata_revision = 22,
    invalid_decompiler_cache_namespace = 23
};

struct contract_error_t final {
    contract_error_code_t code = contract_error_code_t::none;
    std::string_view stable_code;
    std::string_view phase;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr bool operator==(const contract_error_t& other) const noexcept {
        return code == other.code && stable_code == other.stable_code && phase == other.phase &&
            expected == other.expected && actual == other.actual;
    }

    constexpr bool operator!=(const contract_error_t& other) const noexcept {
        return !(*this == other);
    }
};

template <typename value_t>
class contract_result_t;

std::string_view contract_error_code_name(contract_error_code_t code) noexcept;
contract_error_t make_contract_error(contract_error_code_t code, std::string_view phase = {},
                                     std::uint64_t expected = 0,
                                     std::uint64_t actual = 0) noexcept;
std::uint32_t contract_schema_version_for(contract_schema_t schema) noexcept;
std::string_view contract_schema_name(contract_schema_t schema) noexcept;
contract_result_t<void> validate_contract_schema_version(contract_schema_t schema,
                                                         std::uint32_t version) noexcept;

template <typename value_t>
class contract_result_t final {
public:
    static contract_result_t success(value_t value) {
        return contract_result_t(std::move(value));
    }

    static contract_result_t failure(contract_error_t error) noexcept {
        return contract_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }

    const value_t& value() const & { return value_.value(); }
    value_t& value() & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const contract_error_t& error() const noexcept { return error_; }

private:
    explicit contract_result_t(value_t value) : value_(std::move(value)) {}
    explicit contract_result_t(contract_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    contract_error_t error_{};
};

template <>
class contract_result_t<void> final {
public:
    static constexpr contract_result_t success() noexcept { return contract_result_t(); }

    static constexpr contract_result_t failure(contract_error_t error) noexcept {
        return contract_result_t(error);
    }

    constexpr bool has_value() const noexcept { return error_.code == contract_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return has_value(); }
    constexpr const contract_error_t& error() const noexcept { return error_; }

private:
    constexpr contract_result_t() noexcept = default;
    constexpr explicit contract_result_t(contract_error_t error) noexcept : error_(error) {}

    contract_error_t error_{};
};

class workspace_id_t final {
public:
    using bytes_t = std::array<std::uint8_t, 16>;

    constexpr workspace_id_t() noexcept = default;
    workspace_id_t(const workspace_id_t&) = default;
    workspace_id_t(workspace_id_t&&) noexcept = default;
    workspace_id_t& operator=(const workspace_id_t&) = delete;
    workspace_id_t& operator=(workspace_id_t&&) = delete;

    static contract_result_t<workspace_id_t> from_bytes(const bytes_t& bytes) noexcept;

    constexpr const bytes_t& bytes() const noexcept { return bytes_; }
    constexpr bool valid() const noexcept { return valid_; }

    constexpr bool operator==(const workspace_id_t& other) const noexcept {
        return valid_ == other.valid_ && bytes_ == other.bytes_;
    }

    constexpr bool operator!=(const workspace_id_t& other) const noexcept {
        return !(*this == other);
    }

private:
    explicit constexpr workspace_id_t(bytes_t bytes) noexcept : bytes_(bytes), valid_(true) {}

    bytes_t bytes_{};
    bool valid_ = false;
};

class target_id_t final {
public:
    constexpr target_id_t() noexcept = default;
    target_id_t(const target_id_t&) = default;
    target_id_t(target_id_t&&) noexcept = default;
    target_id_t& operator=(const target_id_t&) = delete;
    target_id_t& operator=(target_id_t&&) = delete;

    static contract_result_t<target_id_t> from_value(std::uint64_t value) noexcept;

    constexpr std::uint64_t value() const noexcept { return value_; }
    constexpr bool valid() const noexcept { return value_ != 0; }

    constexpr bool operator==(const target_id_t& other) const noexcept {
        return value_ == other.value_;
    }

    constexpr bool operator!=(const target_id_t& other) const noexcept {
        return !(*this == other);
    }

private:
    explicit constexpr target_id_t(std::uint64_t value) noexcept : value_(value) {}

    std::uint64_t value_ = 0;
};

class generation_id_t final {
public:
    constexpr generation_id_t() noexcept = default;
    generation_id_t(const generation_id_t&) = default;
    generation_id_t(generation_id_t&&) noexcept = default;
    generation_id_t& operator=(const generation_id_t&) = delete;
    generation_id_t& operator=(generation_id_t&&) = delete;

    static contract_result_t<generation_id_t> from_value(std::uint64_t value) noexcept;

    constexpr std::uint64_t value() const noexcept { return value_; }
    constexpr bool valid() const noexcept { return value_ != 0; }

    constexpr bool operator==(const generation_id_t& other) const noexcept {
        return value_ == other.value_;
    }

    constexpr bool operator!=(const generation_id_t& other) const noexcept {
        return !(*this == other);
    }

private:
    explicit constexpr generation_id_t(std::uint64_t value) noexcept : value_(value) {}

    std::uint64_t value_ = 0;
};

enum class analysis_target_kind_t : std::uint8_t {
    unknown = 0,
    static_image = 1,
    live_module = 2,
    collection_member = 3
};

enum class static_provider_kind_t : std::uint8_t {
    unknown = 0,
    mapped_file = 1,
    subrange = 2,
    spill = 3,
    streaming = 4
};

enum class binary_format_t : std::uint8_t {
    unknown = 0,
    pe32 = 1,
    pe32_plus = 2,
    elf32 = 3,
    elf64 = 4,
    mach_o32 = 5,
    mach_o64 = 6,
    raw = 7
};

enum class binary_architecture_t : std::uint8_t {
    unknown = 0,
    x86 = 1,
    x64 = 2,
    arm = 3,
    aarch64 = 4,
    mips = 5,
    ppc = 6,
    riscv = 7
};

enum class binary_mode_t : std::uint8_t {
    unknown = 0,
    bit32 = 1,
    bit64 = 2,
    thumb = 3
};

enum class binary_endian_t : std::uint8_t {
    unknown = 0,
    little = 1,
    big = 2,
    mixed = 3
};

using identity_fingerprint_t = std::array<std::uint8_t, 32>;
using source_file_identity_t = std::array<std::uint8_t, 16>;
using decompiler_cache_namespace_t = std::array<std::uint8_t, 16>;

inline constexpr decompiler_cache_namespace_t default_decompiler_cache_namespace{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

template <std::size_t size>
constexpr bool identity_bytes_present(const std::array<std::uint8_t, size>& bytes) noexcept
{
    for (const auto byte : bytes) {
        if (byte != 0)
            return true;
    }
    return false;
}

constexpr bool range_is_present(std::uint64_t base, std::uint64_t size) noexcept
{
    return base != 0 && size != 0 && size <= (std::numeric_limits<std::uint64_t>::max)() - base;
}

constexpr bool is_known_binary_format(binary_format_t format) noexcept
{
    return format != binary_format_t::unknown;
}

constexpr bool is_known_binary_architecture(binary_architecture_t architecture) noexcept
{
    return architecture != binary_architecture_t::unknown;
}

constexpr bool is_known_binary_mode(binary_mode_t mode) noexcept
{
    return mode != binary_mode_t::unknown;
}

constexpr bool is_known_binary_endian(binary_endian_t endian) noexcept
{
    return endian != binary_endian_t::unknown;
}

constexpr bool decompiler_cache_namespace_present(
    const decompiler_cache_namespace_t& namespace_id) noexcept
{
    return identity_bytes_present(namespace_id);
}

contract_result_t<void> validate_binary_identity_fields(
    binary_format_t format, binary_architecture_t architecture,
    binary_mode_t mode, binary_endian_t endian) noexcept;

struct static_provider_provenance_t final {
    static_provider_kind_t provider_kind = static_provider_kind_t::unknown;
    identity_fingerprint_t provider_identity{};
    std::uint64_t provider_snapshot_generation = 0;
    identity_fingerprint_t canonical_path_fingerprint{};
    source_file_identity_t source_file_identity{};
    std::uint64_t source_length = 0;
    std::uint64_t last_write_identity = 0;
    identity_fingerprint_t content_fingerprint{};
    identity_fingerprint_t member_chain_fingerprint{};
    identity_fingerprint_t image_mapping_fingerprint{};

    constexpr bool valid() const noexcept {
        const bool known_provider = provider_kind == static_provider_kind_t::mapped_file ||
            provider_kind == static_provider_kind_t::subrange ||
            provider_kind == static_provider_kind_t::spill ||
            provider_kind == static_provider_kind_t::streaming;
        return known_provider && identity_bytes_present(provider_identity) &&
            provider_snapshot_generation != 0 &&
            identity_bytes_present(canonical_path_fingerprint) &&
            identity_bytes_present(source_file_identity) && source_length != 0 &&
            last_write_identity != 0 && identity_bytes_present(content_fingerprint) &&
            identity_bytes_present(member_chain_fingerprint) &&
            identity_bytes_present(image_mapping_fingerprint);
    }

    constexpr bool operator==(const static_provider_provenance_t& other) const noexcept {
        return provider_kind == other.provider_kind && provider_identity == other.provider_identity &&
            provider_snapshot_generation == other.provider_snapshot_generation &&
            canonical_path_fingerprint == other.canonical_path_fingerprint &&
            source_file_identity == other.source_file_identity && source_length == other.source_length &&
            last_write_identity == other.last_write_identity &&
            content_fingerprint == other.content_fingerprint &&
            member_chain_fingerprint == other.member_chain_fingerprint &&
            image_mapping_fingerprint == other.image_mapping_fingerprint;
    }

    constexpr bool operator!=(const static_provider_provenance_t& other) const noexcept {
        return !(*this == other);
    }
};

struct live_target_identity_t final {
    std::uint32_t process_id = 0;
    std::uint64_t process_creation_identity = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    identity_fingerprint_t module_fingerprint{};
    std::uint64_t capture_base = 0;
    std::uint64_t capture_size = 0;
    std::uint64_t attach_generation = 0;

    constexpr bool valid() const noexcept {
        if (process_id == 0 || process_creation_identity == 0 ||
            !range_is_present(module_base, module_size) ||
            !identity_bytes_present(module_fingerprint) ||
            !range_is_present(capture_base, capture_size) || attach_generation == 0)
            return false;
        const auto module_end = module_base + module_size;
        const auto capture_end = capture_base + capture_size;
        return capture_base >= module_base && capture_end <= module_end;
    }

    constexpr bool operator==(const live_target_identity_t& other) const noexcept {
        return process_id == other.process_id &&
            process_creation_identity == other.process_creation_identity &&
            module_base == other.module_base && module_size == other.module_size &&
            module_fingerprint == other.module_fingerprint && capture_base == other.capture_base &&
            capture_size == other.capture_size && attach_generation == other.attach_generation;
    }

    constexpr bool operator!=(const live_target_identity_t& other) const noexcept {
        return !(*this == other);
    }
};

contract_result_t<void> validate_static_provider_provenance(
    const static_provider_provenance_t& provenance) noexcept;
contract_result_t<void> validate_live_target_identity(
    const live_target_identity_t& identity) noexcept;

class workspace_contract_identity_t final {
public:
    constexpr workspace_contract_identity_t() noexcept = default;
    workspace_contract_identity_t(const workspace_contract_identity_t&) = default;
    workspace_contract_identity_t(workspace_contract_identity_t&&) noexcept = default;
    workspace_contract_identity_t& operator=(const workspace_contract_identity_t&) = delete;
    workspace_contract_identity_t& operator=(workspace_contract_identity_t&&) = delete;

    static contract_result_t<workspace_contract_identity_t>
        make(const workspace_id_t& workspace) noexcept;

    constexpr const workspace_id_t& workspace_id() const noexcept { return workspace_id_; }
    constexpr bool valid() const noexcept { return workspace_id_.valid(); }

    constexpr bool operator==(const workspace_contract_identity_t& other) const noexcept {
        return workspace_id_ == other.workspace_id_;
    }

    constexpr bool operator!=(const workspace_contract_identity_t& other) const noexcept {
        return !(*this == other);
    }

private:
    explicit constexpr workspace_contract_identity_t(workspace_id_t workspace) noexcept
        : workspace_id_(workspace) {}

    workspace_id_t workspace_id_{};
};

class target_contract_identity_t final {
public:
    constexpr target_contract_identity_t() noexcept = default;
    target_contract_identity_t(const target_contract_identity_t&) = default;
    target_contract_identity_t(target_contract_identity_t&&) noexcept = default;
    target_contract_identity_t& operator=(const target_contract_identity_t&) = delete;
    target_contract_identity_t& operator=(target_contract_identity_t&&) = delete;

    static contract_result_t<target_contract_identity_t>
        make(const workspace_contract_identity_t& workspace, const target_id_t& target,
             analysis_target_kind_t kind,
             std::optional<static_provider_provenance_t> static_provider_provenance,
             std::optional<live_target_identity_t> live_identity,
             binary_format_t format = binary_format_t::pe32_plus,
             binary_architecture_t architecture = binary_architecture_t::x64,
             binary_mode_t mode = binary_mode_t::bit64,
             binary_endian_t endian = binary_endian_t::little) noexcept;

    constexpr const workspace_contract_identity_t& workspace() const noexcept { return workspace_; }
    constexpr const target_id_t& target_id() const noexcept { return target_id_; }
    constexpr analysis_target_kind_t kind() const noexcept { return kind_; }
    constexpr const std::optional<static_provider_provenance_t>& static_provider_provenance() const noexcept {
        return static_provider_provenance_;
    }
    constexpr const std::optional<live_target_identity_t>& live_identity() const noexcept {
        return live_identity_;
    }
    constexpr binary_format_t format() const noexcept { return format_; }
    constexpr binary_architecture_t architecture() const noexcept { return architecture_; }
    constexpr binary_mode_t mode() const noexcept { return mode_; }
    constexpr binary_endian_t endian() const noexcept { return endian_; }
    constexpr bool valid() const noexcept {
        const bool static_kind = kind_ == analysis_target_kind_t::static_image ||
            kind_ == analysis_target_kind_t::collection_member;
        const bool binary_known = format_ != binary_format_t::unknown &&
            architecture_ != binary_architecture_t::unknown &&
            mode_ != binary_mode_t::unknown && endian_ != binary_endian_t::unknown;
        return workspace_.valid() && target_id_.valid() && binary_known &&
            ((static_kind && static_provider_provenance_ && static_provider_provenance_->valid() &&
              !live_identity_) ||
             (kind_ == analysis_target_kind_t::live_module && live_identity_ && live_identity_->valid() &&
               !static_provider_provenance_));
    }

    constexpr bool operator==(const target_contract_identity_t& other) const noexcept {
        return workspace_ == other.workspace_ && target_id_ == other.target_id_ && kind_ == other.kind_ &&
            static_provider_provenance_ == other.static_provider_provenance_ &&
            live_identity_ == other.live_identity_ && format_ == other.format_ &&
            architecture_ == other.architecture_ && mode_ == other.mode_ && endian_ == other.endian_;
    }

    constexpr bool operator!=(const target_contract_identity_t& other) const noexcept {
        return !(*this == other);
    }

private:
    constexpr target_contract_identity_t(workspace_contract_identity_t workspace, target_id_t target,
                                         analysis_target_kind_t kind,
                                         std::optional<static_provider_provenance_t> static_provider_provenance,
                                         std::optional<live_target_identity_t> live_identity,
                                         binary_format_t format,
                                         binary_architecture_t architecture,
                                         binary_mode_t mode,
                                         binary_endian_t endian) noexcept
        : workspace_(workspace),
          target_id_(target),
          kind_(kind),
          static_provider_provenance_(static_provider_provenance),
          live_identity_(live_identity),
          format_(format),
          architecture_(architecture),
          mode_(mode),
          endian_(endian) {}

    workspace_contract_identity_t workspace_{};
    target_id_t target_id_{};
    analysis_target_kind_t kind_ = analysis_target_kind_t::unknown;
    std::optional<static_provider_provenance_t> static_provider_provenance_;
    std::optional<live_target_identity_t> live_identity_;
    binary_format_t format_ = binary_format_t::unknown;
    binary_architecture_t architecture_ = binary_architecture_t::unknown;
    binary_mode_t mode_ = binary_mode_t::unknown;
    binary_endian_t endian_ = binary_endian_t::unknown;
};

class generation_contract_identity_t final {
public:
    constexpr generation_contract_identity_t() noexcept = default;
    generation_contract_identity_t(const generation_contract_identity_t&) = default;
    generation_contract_identity_t(generation_contract_identity_t&&) noexcept = default;
    generation_contract_identity_t& operator=(const generation_contract_identity_t&) = delete;
    generation_contract_identity_t& operator=(generation_contract_identity_t&&) = delete;

    static contract_result_t<generation_contract_identity_t>
        make(const target_contract_identity_t& target, const generation_id_t& generation) noexcept;

    constexpr const target_contract_identity_t& target() const noexcept { return target_; }
    constexpr const generation_id_t& generation_id() const noexcept { return generation_id_; }
    constexpr bool valid() const noexcept { return target_.valid() && generation_id_.valid(); }

    constexpr bool operator==(const generation_contract_identity_t& other) const noexcept {
        return target_ == other.target_ && generation_id_ == other.generation_id_;
    }

    constexpr bool operator!=(const generation_contract_identity_t& other) const noexcept {
        return !(*this == other);
    }

private:
    constexpr generation_contract_identity_t(target_contract_identity_t target,
                                             generation_id_t generation) noexcept
        : target_(target), generation_id_(generation) {}

    target_contract_identity_t target_{};
    generation_id_t generation_id_{};
};

enum class publication_stage_t : std::uint8_t {
    none = 0,
    metadata_ready = 1,
    baseline_ready = 2,
    retired = 3
};

std::string_view publication_stage_name(publication_stage_t stage) noexcept;
bool publication_stage_transition_allowed(publication_stage_t from,
                                          publication_stage_t to) noexcept;
contract_result_t<void> validate_publication_stage_transition(publication_stage_t from,
                                                              publication_stage_t to) noexcept;

class immutable_snapshot_contract_t final {
public:
    constexpr immutable_snapshot_contract_t() noexcept = default;
    immutable_snapshot_contract_t(const immutable_snapshot_contract_t&) = default;
    immutable_snapshot_contract_t(immutable_snapshot_contract_t&&) noexcept = default;
    immutable_snapshot_contract_t& operator=(const immutable_snapshot_contract_t&) = delete;
    immutable_snapshot_contract_t& operator=(immutable_snapshot_contract_t&&) = delete;

    static contract_result_t<immutable_snapshot_contract_t>
        make(const generation_contract_identity_t& generation, std::uint64_t snapshot_revision,
             std::uint64_t layout_revision, std::uint64_t overlay_revision,
             std::uint64_t metadata_revision = 1,
             decompiler_cache_namespace_t decompiler_cache_namespace = default_decompiler_cache_namespace) noexcept;

    constexpr const generation_contract_identity_t& generation() const noexcept { return generation_; }
    constexpr std::uint64_t snapshot_revision() const noexcept { return snapshot_revision_; }
    constexpr std::uint64_t layout_revision() const noexcept { return layout_revision_; }
    constexpr std::uint64_t overlay_revision() const noexcept { return overlay_revision_; }
    constexpr std::uint64_t metadata_revision() const noexcept { return metadata_revision_; }
    constexpr const decompiler_cache_namespace_t& decompiler_cache_namespace() const noexcept {
        return decompiler_cache_namespace_;
    }
    constexpr bool valid() const noexcept {
        return generation_.valid() && snapshot_revision_ != 0 && layout_revision_ != 0 &&
            metadata_revision_ != 0 && identity_bytes_present(decompiler_cache_namespace_);
    }

    constexpr bool operator==(const immutable_snapshot_contract_t& other) const noexcept {
        return generation_ == other.generation_ && snapshot_revision_ == other.snapshot_revision_ &&
            layout_revision_ == other.layout_revision_ && overlay_revision_ == other.overlay_revision_ &&
            metadata_revision_ == other.metadata_revision_ &&
            decompiler_cache_namespace_ == other.decompiler_cache_namespace_;
    }

    constexpr bool operator!=(const immutable_snapshot_contract_t& other) const noexcept {
        return !(*this == other);
    }

private:
    constexpr immutable_snapshot_contract_t(generation_contract_identity_t generation,
                                            std::uint64_t snapshot_revision,
                                            std::uint64_t layout_revision,
                                            std::uint64_t overlay_revision,
                                            std::uint64_t metadata_revision,
                                            decompiler_cache_namespace_t decompiler_cache_namespace) noexcept
        : generation_(generation),
          snapshot_revision_(snapshot_revision),
          layout_revision_(layout_revision),
          overlay_revision_(overlay_revision),
          metadata_revision_(metadata_revision),
          decompiler_cache_namespace_(decompiler_cache_namespace) {}

    generation_contract_identity_t generation_{};
    std::uint64_t snapshot_revision_ = 0;
    std::uint64_t layout_revision_ = 0;
    std::uint64_t overlay_revision_ = 0;
    std::uint64_t metadata_revision_ = 0;
    decompiler_cache_namespace_t decompiler_cache_namespace_{};
};

class immutable_publication_contract_t final {
public:
    constexpr immutable_publication_contract_t() noexcept = default;
    immutable_publication_contract_t(const immutable_publication_contract_t&) = default;
    immutable_publication_contract_t(immutable_publication_contract_t&&) noexcept = default;
    immutable_publication_contract_t& operator=(const immutable_publication_contract_t&) = delete;
    immutable_publication_contract_t& operator=(immutable_publication_contract_t&&) = delete;

    static contract_result_t<immutable_publication_contract_t>
        make(const generation_contract_identity_t& expected_generation,
             const immutable_snapshot_contract_t& snapshot, publication_stage_t stage,
             std::uint64_t publication_revision) noexcept;

    constexpr const immutable_snapshot_contract_t& snapshot() const noexcept { return snapshot_; }
    constexpr publication_stage_t stage() const noexcept { return stage_; }
    constexpr std::uint64_t publication_revision() const noexcept { return publication_revision_; }
    constexpr bool valid() const noexcept {
        return snapshot_.valid() && stage_ != publication_stage_t::none && publication_revision_ != 0;
    }

    constexpr bool operator==(const immutable_publication_contract_t& other) const noexcept {
        return snapshot_ == other.snapshot_ && stage_ == other.stage_ &&
            publication_revision_ == other.publication_revision_;
    }

    constexpr bool operator!=(const immutable_publication_contract_t& other) const noexcept {
        return !(*this == other);
    }

private:
    constexpr immutable_publication_contract_t(immutable_snapshot_contract_t snapshot,
                                                publication_stage_t stage,
                                                std::uint64_t publication_revision) noexcept
        : snapshot_(snapshot), stage_(stage), publication_revision_(publication_revision) {}

    immutable_snapshot_contract_t snapshot_{};
    publication_stage_t stage_ = publication_stage_t::none;
    std::uint64_t publication_revision_ = 0;
};

struct packed_analysis_id_parts_t final {
    std::uint16_t domain = 0;
    std::uint16_t shard = 0;
    std::uint32_t ordinal = 0;

    constexpr bool operator==(const packed_analysis_id_parts_t& other) const noexcept {
        return domain == other.domain && shard == other.shard && ordinal == other.ordinal;
    }

    constexpr bool operator!=(const packed_analysis_id_parts_t& other) const noexcept {
        return !(*this == other);
    }
};

class packed_analysis_id_t final {
public:
    packed_analysis_id_t(const packed_analysis_id_t&) = default;
    packed_analysis_id_t(packed_analysis_id_t&&) noexcept = default;
    packed_analysis_id_t& operator=(const packed_analysis_id_t&) = delete;
    packed_analysis_id_t& operator=(packed_analysis_id_t&&) = delete;

    static contract_result_t<packed_analysis_id_t>
        make(std::uint64_t domain, std::uint64_t shard, std::uint64_t ordinal) noexcept;

    constexpr std::uint64_t value() const noexcept { return value_; }
    constexpr bool valid() const noexcept { return value_ != 0; }
    constexpr packed_analysis_id_parts_t parts() const noexcept {
        return packed_analysis_id_parts_t{
            static_cast<std::uint16_t>(value_ >> 48U),
            static_cast<std::uint16_t>((value_ >> 32U) & 0xffffULL),
            static_cast<std::uint32_t>(value_ & 0xffffffffULL)};
    }

    constexpr bool operator==(const packed_analysis_id_t& other) const noexcept {
        return value_ == other.value_;
    }

    constexpr bool operator!=(const packed_analysis_id_t& other) const noexcept {
        return !(*this == other);
    }

private:
    explicit constexpr packed_analysis_id_t(std::uint64_t value) noexcept : value_(value) {}

    std::uint64_t value_ = 0;
};

struct analysis_resource_budget_t final {
    std::uint64_t max_incremental_private_bytes =
        ::aida::analysis::c03::max_incremental_private_bytes;
    std::uint64_t max_workspace_mapped_window_bytes =
        ::aida::analysis::c03::max_workspace_mapped_window_bytes;
    std::uint64_t max_global_mapped_window_bytes =
        ::aida::analysis::c03::max_global_mapped_window_bytes;
    std::uint64_t max_workspace_spill_bytes = ::aida::analysis::c03::max_workspace_spill_bytes;
    std::uint64_t max_global_spill_bytes = ::aida::analysis::c03::max_global_spill_bytes;
    std::uint64_t max_workspace_cache_bytes = ::aida::analysis::c03::max_workspace_cache_bytes;
    std::uint64_t max_global_cache_bytes = ::aida::analysis::c03::max_global_cache_bytes;
    std::uint32_t cancellation_checkpoint_milliseconds =
        ::aida::analysis::c03::max_cancellation_checkpoint_milliseconds;
};

struct analysis_resource_usage_t final {
    std::uint64_t incremental_private_bytes = 0;
    std::uint64_t workspace_mapped_window_bytes = 0;
    std::uint64_t global_mapped_window_bytes = 0;
    std::uint64_t workspace_spill_bytes = 0;
    std::uint64_t global_spill_bytes = 0;
    std::uint64_t workspace_cache_bytes = 0;
    std::uint64_t global_cache_bytes = 0;
};

contract_result_t<void> validate_analysis_resource_budget(
    const analysis_resource_budget_t& budget) noexcept;
contract_result_t<analysis_resource_usage_t> reserve_analysis_resources(
    const analysis_resource_budget_t& budget, const analysis_resource_usage_t& current,
    const analysis_resource_usage_t& requested) noexcept;

enum class cancellation_domain_scope_t : std::uint8_t {
    workspace = 1,
    target = 2,
    generation = 3
};

class cancellation_domain_t final {
public:
    cancellation_domain_t(const cancellation_domain_t&) = default;
    cancellation_domain_t(cancellation_domain_t&&) noexcept = default;
    cancellation_domain_t& operator=(const cancellation_domain_t&) = delete;
    cancellation_domain_t& operator=(cancellation_domain_t&&) = delete;

    static contract_result_t<cancellation_domain_t>
        for_workspace(const workspace_contract_identity_t& workspace, std::uint64_t epoch) noexcept;
    static contract_result_t<cancellation_domain_t>
        for_target(const target_contract_identity_t& target, std::uint64_t epoch) noexcept;
    static contract_result_t<cancellation_domain_t>
        for_generation(const generation_contract_identity_t& generation, std::uint64_t epoch) noexcept;

    constexpr cancellation_domain_scope_t scope() const noexcept { return scope_; }
    constexpr const workspace_contract_identity_t& workspace() const noexcept { return workspace_; }
    constexpr const std::optional<target_contract_identity_t>& target() const noexcept {
        return target_;
    }
    constexpr const std::optional<generation_contract_identity_t>& generation() const noexcept {
        return generation_;
    }
    constexpr std::uint64_t epoch() const noexcept { return epoch_; }
    constexpr bool valid() const noexcept {
        return epoch_ != 0 && workspace_.valid() &&
            ((scope_ == cancellation_domain_scope_t::workspace && !target_ && !generation_) ||
             (scope_ == cancellation_domain_scope_t::target && target_.has_value() && !generation_) ||
             (scope_ == cancellation_domain_scope_t::generation && generation_.has_value()));
    }

    constexpr bool operator==(const cancellation_domain_t& other) const noexcept {
        return scope_ == other.scope_ && workspace_ == other.workspace_ && target_ == other.target_ &&
            generation_ == other.generation_ && epoch_ == other.epoch_;
    }

    constexpr bool operator!=(const cancellation_domain_t& other) const noexcept {
        return !(*this == other);
    }

private:
    constexpr cancellation_domain_t(cancellation_domain_scope_t scope,
                                    workspace_contract_identity_t workspace,
                                    std::optional<target_contract_identity_t> target,
                                    std::optional<generation_contract_identity_t> generation,
                                    std::uint64_t epoch) noexcept
        : scope_(scope),
          workspace_(workspace),
          target_(target),
          generation_(generation),
          epoch_(epoch) {}

    cancellation_domain_scope_t scope_ = cancellation_domain_scope_t::workspace;
    workspace_contract_identity_t workspace_{};
    std::optional<target_contract_identity_t> target_;
    std::optional<generation_contract_identity_t> generation_;
    std::uint64_t epoch_ = 0;
};

contract_result_t<void> validate_cancellation_domain(
    const cancellation_domain_t& domain, const generation_contract_identity_t& generation) noexcept;

static_assert(sizeof(std::uint8_t) == 1, "C03 contracts require octet bytes");
static_assert(sizeof(std::uint16_t) == 2, "C03 contracts require 16-bit schema fields");
static_assert(sizeof(std::uint32_t) == 4, "C03 contracts require 32-bit schema fields");
static_assert(sizeof(std::uint64_t) == 8, "C03 contracts require 64-bit identifiers");
static_assert(sizeof(workspace_id_t::bytes_t) == 16, "C03 workspace identifiers are 128-bit");
static_assert(sizeof(source_file_identity_t) == 16, "C03 source file identities are 128-bit");
static_assert(sizeof(decompiler_cache_namespace_t) == 16, "C03 decompiler cache namespaces are 128-bit");
static_assert(sizeof(identity_fingerprint_t) == 32, "C03 identity fingerprints are 256-bit");
static_assert(sizeof(packed_analysis_id_t) == sizeof(std::uint64_t),
              "C03 packed analysis identifiers are 64-bit");
static_assert(static_cast<std::uint16_t>(contract_schema_t::workspace_identity) == 1,
              "C03 workspace schema value is stable");
static_assert(static_cast<std::uint16_t>(contract_schema_t::cancellation_domain) == 8,
              "C03 cancellation schema value is stable");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::generation_mismatch) == 4,
              "C03 generation mismatch code is stable");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::arithmetic_overflow) == 11,
              "C03 arithmetic overflow code is stable");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_binary_format) == 18,
              "C03 invalid binary format code is stable");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_metadata_revision) == 22,
              "C03 invalid metadata revision code is stable");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_decompiler_cache_namespace) == 23,
              "C03 invalid decompiler cache namespace code is stable");
static_assert(std::numeric_limits<std::uint64_t>::digits == 64,
              "C03 contracts require 64-bit unsigned arithmetic");

}
