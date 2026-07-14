#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace aida::analysis {

inline constexpr std::uint32_t k_overlay_journal_v9_schema = 9;
inline constexpr std::size_t k_overlay_managed_entity_serialization_limit = 16U << 10;

enum class overlay_target_kind_v9_t : std::uint8_t {
    invalid = 0,
    static_image = 1,
    live_image = 2
};

enum class overlay_architecture_v9_t : std::uint8_t {
    invalid = 0,
    x86 = 1,
    x86_64 = 2,
    arm = 3,
    arm64 = 4,
    mips = 5,
    ppc = 6,
    riscv = 7,
    jvm = 8,
    dalvik = 9
};

enum class overlay_target_discriminator_v9_t : std::uint8_t {
    native_address = 0,
    managed_entity = 1
};

enum class overlay_operation_kind_v9_t : std::uint8_t {
    comment = 0,
    name = 1,
    bookmark = 2,
    type_declaration = 3,
    define_function = 4,
    define_code = 5,
    define_data = 6,
    undefine = 7,
    stack_variable = 8,
    delete_stack_variable = 9,
    type_application = 10,
    byte_patch = 11,
    assembly_patch = 12,
    integer_patch = 13,
    comment_update = 14,
    type_update = 15,
    enum_definition = 16,
    reanalysis = 17
};

static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::comment) == 0);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::name) == 1);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::bookmark) == 2);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::type_declaration) == 3);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::define_function) == 4);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::define_code) == 5);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::define_data) == 6);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::undefine) == 7);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::stack_variable) == 8);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::delete_stack_variable) == 9);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::type_application) == 10);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::byte_patch) == 11);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::assembly_patch) == 12);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::integer_patch) == 13);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::comment_update) == 14);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::type_update) == 15);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::enum_definition) == 16);
static_assert(static_cast<std::uint8_t>(overlay_operation_kind_v9_t::reanalysis) == 17);

constexpr bool is_legacy_overlay_operation_ordinal(std::uint8_t ordinal) noexcept
{
    return ordinal <= static_cast<std::uint8_t>(overlay_operation_kind_v9_t::integer_patch);
}

std::optional<overlay_operation_kind_v9_t>
    overlay_operation_kind_from_ordinal(std::uint8_t ordinal) noexcept;
bool managed_overlay_operation_kind_v9(
    overlay_operation_kind_v9_t kind) noexcept;

struct overlay_target_identity_v9_t final {
    std::array<std::uint8_t, 32> image_hash{};
    std::array<std::uint8_t, 32> provenance_hash{};
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t generation = 0;
    overlay_target_kind_v9_t kind = overlay_target_kind_v9_t::invalid;
    overlay_architecture_v9_t architecture = overlay_architecture_v9_t::invalid;
    std::uint8_t address_width = 0;
    std::uint8_t reserved = 0;

    bool valid() const noexcept;
    bool operator==(const overlay_target_identity_v9_t& other) const noexcept;
    bool operator!=(const overlay_target_identity_v9_t& other) const noexcept;
};

static_assert(std::is_standard_layout_v<overlay_target_identity_v9_t>);
static_assert(std::is_trivially_copyable_v<overlay_target_identity_v9_t>);
static_assert(sizeof(overlay_target_identity_v9_t) == 96);

struct overlay_static_range_v9_t final {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;

    bool operator==(const overlay_static_range_v9_t& other) const noexcept;
    bool operator!=(const overlay_static_range_v9_t& other) const noexcept;
};

struct overlay_managed_entity_locator_v9_t final {
    std::array<std::uint8_t, 32> workspace_id{};
    std::array<std::uint8_t, 32> provider_hash{};
    std::array<std::uint8_t, 32> artifact_hash{};
    std::array<std::uint8_t, 32> entity_hash{};
    std::uint64_t provider_size = 0;
    std::uint64_t generation = 0;
    std::string serialized_entity;

    bool valid() const noexcept;
    bool stable_identity_equal(
        const overlay_managed_entity_locator_v9_t& other) const noexcept;
    bool stable_identity_less(
        const overlay_managed_entity_locator_v9_t& other) const noexcept;
    bool operator==(const overlay_managed_entity_locator_v9_t& other) const noexcept;
    bool operator!=(const overlay_managed_entity_locator_v9_t& other) const noexcept;
};

struct overlay_payload_v9_t final {
    std::string name;
    std::string text;
    std::string type;
    std::string variable;
    std::string signature;
    std::string assembly;
    std::string integer_type;
    std::string integer_value;
    std::vector<std::uint8_t> bytes;
    std::uint32_t reanalysis_flags = 0;
    std::int64_t stack_offset = 0;

    bool operator==(const overlay_payload_v9_t& other) const noexcept;
    bool operator!=(const overlay_payload_v9_t& other) const noexcept;
};

struct overlay_operation_v9_t final {
    overlay_operation_kind_v9_t kind = overlay_operation_kind_v9_t::comment;
    overlay_target_discriminator_v9_t target_discriminator =
        overlay_target_discriminator_v9_t::native_address;
    overlay_static_range_v9_t range;
    std::optional<overlay_managed_entity_locator_v9_t> managed_locator;
    overlay_payload_v9_t payload;
    bool remove = false;

    bool operator==(const overlay_operation_v9_t& other) const noexcept;
    bool operator!=(const overlay_operation_v9_t& other) const noexcept;
};

struct overlay_operation_record_v9_t final {
    overlay_target_identity_v9_t target;
    overlay_operation_v9_t operation;

    bool operator==(const overlay_operation_record_v9_t& other) const noexcept;
    bool operator!=(const overlay_operation_record_v9_t& other) const noexcept;
};

struct overlay_entity_key_v9_t final {
    overlay_operation_kind_v9_t domain = overlay_operation_kind_v9_t::comment;
    overlay_target_discriminator_v9_t target_discriminator =
        overlay_target_discriminator_v9_t::native_address;
    overlay_static_range_v9_t range;
    std::optional<overlay_managed_entity_locator_v9_t> managed_locator;
    std::int64_t stack_offset = 0;
    std::string qualifier;

    bool operator==(const overlay_entity_key_v9_t& other) const noexcept;
    bool operator!=(const overlay_entity_key_v9_t& other) const noexcept;
    bool operator<(const overlay_entity_key_v9_t& other) const noexcept;
};

overlay_entity_key_v9_t
    overlay_entity_key_for_operation_v9(const overlay_operation_v9_t& operation);
std::optional<overlay_operation_kind_v9_t> overlay_operation_kind_for_item_v9(
    const overlay_entity_key_v9_t& entity,
    const overlay_payload_v9_t& payload) noexcept;

std::string serialize_overlay_target_identity_v9(
    const overlay_target_identity_v9_t& target);
std::optional<overlay_target_identity_v9_t>
    deserialize_overlay_target_identity_v9(std::string_view serialized) noexcept;
std::string serialize_overlay_operation_record_v9(
    const overlay_operation_record_v9_t& record);
std::optional<overlay_operation_record_v9_t>
    deserialize_overlay_operation_record_v9(std::string_view serialized) noexcept;

struct overlay_change_v9_t final {
    overlay_entity_key_v9_t entity;
    overlay_operation_kind_v9_t operation_kind = overlay_operation_kind_v9_t::comment;
    std::optional<overlay_operation_kind_v9_t> before_kind;
    std::optional<overlay_operation_kind_v9_t> after_kind;
    std::optional<overlay_payload_v9_t> before;
    std::optional<overlay_payload_v9_t> after;
};

struct overlay_transaction_v9_t final {
    overlay_target_identity_v9_t target;
    std::uint64_t expected_revision = 0;
    std::vector<overlay_operation_v9_t> operations;
};

struct overlay_history_entry_v9_t final {
    overlay_target_identity_v9_t target;
    std::uint64_t transaction_id = 0;
    std::uint64_t generation = 0;
    std::uint64_t originating_revision = 0;
    std::vector<overlay_change_v9_t> changes;
};

struct overlay_static_state_v9_t final {
    overlay_target_identity_v9_t target;
    std::uint64_t revision = 0;
    std::uint64_t next_transaction_id = 1;
    std::uint64_t history_cursor = 0;
    std::uint64_t history_epoch = 1;
    std::map<overlay_entity_key_v9_t, overlay_payload_v9_t> items;
    std::vector<overlay_history_entry_v9_t> history;
};

struct overlay_apply_limits_v9_t final {
    std::size_t max_operations_per_transaction = 4096;
    std::size_t max_history_entries = 65536;
    std::size_t max_text_bytes = 256U << 10;
    std::size_t max_type_bytes = 64U << 10;
    std::size_t max_patch_bytes_per_operation = 1U << 20;
    std::size_t max_patch_bytes_per_transaction = 16U << 20;
    std::size_t max_transaction_payload_bytes = 32U << 20;
    std::size_t max_managed_entity_bytes =
        k_overlay_managed_entity_serialization_limit;
};

enum class overlay_apply_code_v9_t : std::uint8_t {
    ok = 0,
    invalid_target = 1,
    static_target_required = 2,
    stale_generation = 3,
    revision_conflict = 4,
    revision_overflow = 5,
    transaction_overflow = 6,
    history_overflow = 7,
    invalid_operation = 8,
    duplicate_entity = 9,
    limit_exceeded = 10,
    no_undo = 11,
    no_redo = 12,
    state_not_initialized = 13,
    state_already_initialized = 14,
    storage_failure = 15
};

struct overlay_apply_result_v9_t final {
    overlay_apply_code_v9_t code = overlay_apply_code_v9_t::ok;
    std::uint64_t revision = 0;
    std::uint64_t transaction_id = 0;
    std::uint64_t history_cursor = 0;
    std::vector<overlay_change_v9_t> changes;

    bool ok() const noexcept { return code == overlay_apply_code_v9_t::ok; }
};

class overlay_apply_engine_v9_t final {
public:
    static overlay_apply_result_v9_t initialize(
        overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target) noexcept;

    static overlay_apply_result_v9_t apply(
        overlay_static_state_v9_t& state, const overlay_transaction_v9_t& transaction,
        const overlay_apply_limits_v9_t& limits = {}) noexcept;

    static overlay_apply_result_v9_t undo(
        overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target,
        std::uint64_t expected_revision) noexcept;

    static overlay_apply_result_v9_t redo(
        overlay_static_state_v9_t& state, const overlay_target_identity_v9_t& target,
        std::uint64_t expected_revision) noexcept;
};

}
