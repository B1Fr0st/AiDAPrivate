#pragma once

#include "overlay_apply_engine.hpp"
#include "image_layout_index.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace aida {
namespace analysis {

enum class projection_stage_flag_t : std::uint32_t {
    none = 0,
    layout_index = 1U << 0U,
    disassembler = 1U << 1U,
    decompiler = 1U << 2U,
    string_table = 1U << 3U,
    xref_table = 1U << 4U,
    function_table = 1U << 5U,
    type_table = 1U << 6U,
    symbol_table = 1U << 7U,
    coverage_table = 1U << 8U,
    basic_block_table = 1U << 9U,
    all_stages = 0xFFFFFFFFU
};

constexpr projection_stage_flag_t operator|(projection_stage_flag_t lhs,
                                            projection_stage_flag_t rhs) noexcept
{
    return static_cast<projection_stage_flag_t>(
        static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
}

constexpr projection_stage_flag_t operator&(projection_stage_flag_t lhs,
                                            projection_stage_flag_t rhs) noexcept
{
    return static_cast<projection_stage_flag_t>(
        static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
}

constexpr bool stage_test(projection_stage_flag_t flags,
                          projection_stage_flag_t test) noexcept
{
    return (flags & test) != projection_stage_flag_t::none;
}

struct projected_range_t final {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    bool is_byte_patch = false;
    overlay_operation_kind_v9_t source_kind = overlay_operation_kind_v9_t::comment;

    bool overlaps(const projected_range_t& other) const noexcept
    {
        if (size == 0 || other.size == 0)
            return false;
        return offset < other.offset + other.size && other.offset < offset + size;
    }

    bool operator==(const projected_range_t& other) const noexcept
    {
        return offset == other.offset && size == other.size &&
               is_byte_patch == other.is_byte_patch && source_kind == other.source_kind;
    }

    bool operator!=(const projected_range_t& other) const noexcept
    {
        return !(*this == other);
    }
};

struct projected_entity_t final {
    overlay_entity_key_v9_t key;
    overlay_operation_kind_v9_t source_kind = overlay_operation_kind_v9_t::comment;
    bool invalidated = false;
    bool is_new = false;

    bool operator==(const projected_entity_t& other) const noexcept
    {
        return key == other.key && source_kind == other.source_kind &&
               invalidated == other.invalidated && is_new == other.is_new;
    }

    bool operator!=(const projected_entity_t& other) const noexcept
    {
        return !(*this == other);
    }
};

struct projection_invalidation_set_t final {
    std::vector<projected_range_t> affected_ranges;
    std::vector<projected_entity_t> affected_entities;
    projection_stage_flag_t invalidated_stages = projection_stage_flag_t::none;
    std::uint64_t total_patched_bytes = 0;
    std::uint64_t max_contiguous_range = 0;

    bool empty() const noexcept
    {
        return affected_ranges.empty() && affected_entities.empty() &&
               invalidated_stages == projection_stage_flag_t::none;
    }

    bool has_byte_patches() const noexcept
    {
        return std::any_of(affected_ranges.begin(), affected_ranges.end(),
                           [](const auto& range) { return range.is_byte_patch; });
    }
};

enum class projection_code_t : std::uint8_t {
    ok = 0,
    invalid_target = 1,
    stale_generation = 2,
    conflict_detected = 3,
    empty_projection = 4,
    state_not_initialized = 5,
    range_out_of_bounds = 6,
    publication_failed = 7,
    revision_conflict = 8,
    transaction_overflow = 9,
    apply_failure = 10
};

struct projection_result_t final {
    projection_code_t code = projection_code_t::ok;
    std::uint64_t new_generation = 0;
    std::uint64_t revision = 0;
    projection_invalidation_set_t invalidation;
    std::vector<overlay_change_v9_t> changes;
    std::vector<std::uint8_t> projected_bytes;
    std::string detail;

    bool ok() const noexcept { return code == projection_code_t::ok; }
    explicit operator bool() const noexcept { return ok(); }
};

struct projection_conflict_t final {
    projected_range_t range_a;
    projected_range_t range_b;
    std::size_t change_index_a = 0;
    std::size_t change_index_b = 0;

    bool valid() const noexcept { return range_a.overlaps(range_b); }
};

class overlay_projection_t final {
public:
    static projection_result_t project(
        const overlay_static_state_v9_t& state,
        std::string_view immutable_bytes,
        std::uint64_t current_generation);

    static projection_result_t project_transaction(
        const overlay_static_state_v9_t& state,
        const overlay_transaction_v9_t& transaction,
        std::string_view immutable_bytes,
        std::uint64_t current_generation,
        const overlay_apply_limits_v9_t& limits = {});

    static std::vector<projected_range_t> derive_affected_ranges(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<projected_entity_t> derive_affected_entities(
        const std::vector<overlay_change_v9_t>& changes);

    static projection_stage_flag_t derive_invalidated_stages(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<projection_conflict_t> detect_conflicts(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<std::uint8_t> apply_patches(
        std::string_view immutable_bytes,
        const overlay_static_state_v9_t& state);

    static projection_result_t publish_generation(
        overlay_static_state_v9_t& state,
        std::uint64_t expected_generation,
        const projection_invalidation_set_t& invalidation,
        const std::vector<overlay_change_v9_t>& changes);

    static projection_invalidation_set_t compute_invalidation(
        const std::vector<overlay_change_v9_t>& changes);

    static bool validate_ranges_in_bounds(
        const std::vector<projected_range_t>& ranges,
        std::uint64_t image_size) noexcept;

    static projection_stage_flag_t stage_flags_for_domain(
        overlay_operation_kind_v9_t domain) noexcept;
};

}
}
