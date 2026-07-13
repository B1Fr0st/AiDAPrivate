#pragma once

#include "overlay_apply_engine.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
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
        if (offset <= other.offset)
            return other.offset - offset < size;
        return offset - other.offset < other.size;
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
    std::optional<overlay_operation_kind_v9_t> before_kind;
    std::optional<overlay_operation_kind_v9_t> after_kind;
    bool invalidated = false;
    bool is_new = false;

    bool operator==(const projected_entity_t& other) const noexcept
    {
        return key == other.key && source_kind == other.source_kind &&
               before_kind == other.before_kind && after_kind == other.after_kind &&
               invalidated == other.invalidated && is_new == other.is_new;
    }

    bool operator!=(const projected_entity_t& other) const noexcept
    {
        return !(*this == other);
    }
};

struct packed_index_invalidation_request_t final {
    std::uint64_t source_generation = 0;
    std::uint64_t target_generation = 0;
    projection_stage_flag_t invalidated_stages = projection_stage_flag_t::none;
    std::vector<projected_range_t> affected_ranges;
    std::vector<projected_entity_t> affected_entities;
    bool rebuild_all = false;

    bool required() const noexcept
    {
        return source_generation != target_generation || rebuild_all ||
               invalidated_stages != projection_stage_flag_t::none;
    }
};

enum class decompiler_cache_invalidation_flag_t : std::uint8_t {
    none = 0,
    provider_ir = 1U << 0U,
    normalized_hir_ast = 1U << 1U,
    rendered_document = 1U << 2U,
    all_stages = 0x07U
};

struct decompiler_cache_invalidation_request_t final {
    std::uint64_t source_generation = 0;
    std::uint64_t target_generation = 0;
    decompiler_cache_invalidation_flag_t invalidated_stages =
        decompiler_cache_invalidation_flag_t::none;
    std::vector<projected_range_t> affected_ranges;
    std::vector<projected_entity_t> affected_entities;
    bool invalidate_workspace = false;

    bool required() const noexcept
    {
        return source_generation != target_generation || invalidate_workspace ||
               invalidated_stages != decompiler_cache_invalidation_flag_t::none;
    }
};

struct projection_invalidation_set_t final {
    std::vector<projected_range_t> affected_ranges;
    std::vector<projected_entity_t> affected_entities;
    projection_stage_flag_t invalidated_stages = projection_stage_flag_t::none;
    std::uint64_t total_patched_bytes = 0;
    std::uint64_t max_contiguous_range = 0;
    packed_index_invalidation_request_t packed_index;
    decompiler_cache_invalidation_request_t decompiler_cache;

    bool empty() const noexcept
    {
        return affected_ranges.empty() && affected_entities.empty() &&
               invalidated_stages == projection_stage_flag_t::none &&
               !packed_index.required() && !decompiler_cache.required();
    }

    bool has_byte_patches() const noexcept
    {
        return std::any_of(affected_ranges.begin(), affected_ranges.end(),
                           [](const auto& range) { return range.is_byte_patch; });
    }

    bool requires_cache_invalidation() const noexcept
    {
        return packed_index.required() || decompiler_cache.required();
    }
};

struct projection_invalidation_hook_result_t final {
    bool succeeded = false;
    std::size_t invalidated_entry_count = 0;
    std::string detail;

    explicit operator bool() const noexcept { return succeeded; }
};

using packed_index_invalidation_hook_t = std::function<projection_invalidation_hook_result_t(
    const packed_index_invalidation_request_t&)>;
using decompiler_cache_invalidation_hook_t = std::function<projection_invalidation_hook_result_t(
    const decompiler_cache_invalidation_request_t&)>;

struct projection_invalidation_hooks_t final {
    packed_index_invalidation_hook_t packed_index;
    decompiler_cache_invalidation_hook_t decompiler_cache;
};

enum class projection_invalidation_dispatch_code_t : std::uint8_t {
    ok = 0,
    missing_packed_index_hook = 1,
    missing_decompiler_cache_hook = 2,
    packed_index_rejected = 3,
    decompiler_cache_rejected = 4,
    hook_exception = 5
};

struct projection_invalidation_dispatch_result_t final {
    projection_invalidation_dispatch_code_t code =
        projection_invalidation_dispatch_code_t::ok;
    projection_invalidation_hook_result_t packed_index;
    projection_invalidation_hook_result_t decompiler_cache;
    bool packed_index_completed = false;
    bool decompiler_cache_completed = false;
    std::string detail;

    bool ok() const noexcept
    {
        return code == projection_invalidation_dispatch_code_t::ok;
    }

    bool satisfies(const projection_invalidation_set_t& invalidation) const noexcept
    {
        return ok() &&
               (!invalidation.packed_index.required() ||
                (packed_index_completed && packed_index.succeeded)) &&
               (!invalidation.decompiler_cache.required() ||
                (decompiler_cache_completed && decompiler_cache.succeeded));
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
    apply_failure = 10,
    invalid_patch_provenance = 11,
    invalid_publication = 12,
    finalizer_failed = 13
};

struct projection_state_version_t final {
    overlay_target_identity_v9_t target;
    std::uint64_t revision = 0;
    std::uint64_t next_transaction_id = 0;
    std::uint64_t history_cursor = 0;
    std::uint64_t history_epoch = 0;
    std::size_t item_count = 0;
    std::size_t history_size = 0;

    bool matches(const overlay_static_state_v9_t& state) const noexcept
    {
        return target == state.target && revision == state.revision &&
               next_transaction_id == state.next_transaction_id &&
               history_cursor == state.history_cursor && history_epoch == state.history_epoch &&
               item_count == state.items.size() && history_size == state.history.size();
    }
};

struct projection_result_t final {
    projection_code_t code = projection_code_t::ok;
    std::uint64_t source_generation = 0;
    std::uint64_t new_generation = 0;
    std::uint64_t source_revision = 0;
    std::uint64_t revision = 0;
    projection_state_version_t source_state;
    projection_invalidation_set_t invalidation;
    std::vector<overlay_change_v9_t> changes;
    std::vector<std::uint8_t> projected_bytes;
    std::optional<overlay_static_state_v9_t> projected_state;
    bool publication_ready = false;
    std::string detail;

    bool ok() const noexcept { return code == projection_code_t::ok; }
    explicit operator bool() const noexcept { return ok(); }
};

enum class projection_conflict_origin_t : std::uint8_t {
    transaction = 0,
    projected_state = 1
};

struct projection_conflict_t final {
    projected_range_t range_a;
    projected_range_t range_b;
    overlay_entity_key_v9_t entity_a;
    overlay_entity_key_v9_t entity_b;
    std::size_t change_index_a = 0;
    std::size_t change_index_b = 0;
    projection_conflict_origin_t origin_a = projection_conflict_origin_t::transaction;
    projection_conflict_origin_t origin_b = projection_conflict_origin_t::transaction;

    bool valid() const noexcept { return range_a.overlaps(range_b); }
    bool against_projected_state() const noexcept
    {
        return origin_a == projection_conflict_origin_t::projected_state ||
               origin_b == projection_conflict_origin_t::projected_state;
    }
};

struct projection_publication_view_t final {
    const overlay_static_state_v9_t& projected_state;
    const std::vector<std::uint8_t>& projected_bytes;
    const projection_invalidation_set_t& invalidation;
    const std::vector<overlay_change_v9_t>& changes;
    std::uint64_t source_generation = 0;
    std::uint64_t target_generation = 0;
    std::uint64_t source_revision = 0;
    std::uint64_t target_revision = 0;
};

struct projection_publication_commit_t final {
    bool committed = false;
    projection_invalidation_dispatch_result_t invalidation;
    std::string detail;

    bool ok(const projection_invalidation_set_t& expected_invalidation) const noexcept
    {
        return committed && invalidation.satisfies(expected_invalidation);
    }
};

using projection_publication_finalizer_t = std::function<projection_publication_commit_t(
    const projection_publication_view_t&,
    const projection_invalidation_hooks_t&)>;

struct projection_finalize_result_t final {
    projection_code_t code = projection_code_t::ok;
    std::uint64_t new_generation = 0;
    std::uint64_t revision = 0;
    projection_invalidation_dispatch_result_t invalidation;
    std::string detail;

    bool ok() const noexcept { return code == projection_code_t::ok; }
    explicit operator bool() const noexcept { return ok(); }
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

    static projection_finalize_result_t finalize_publication(
        overlay_static_state_v9_t& state,
        const projection_result_t& prepared,
        const projection_invalidation_hooks_t& hooks,
        const projection_publication_finalizer_t& finalizer);

    static std::vector<projected_range_t> derive_affected_ranges(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<projected_entity_t> derive_affected_entities(
        const std::vector<overlay_change_v9_t>& changes);

    static projection_stage_flag_t derive_invalidated_stages(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<projection_conflict_t> detect_conflicts(
        const std::vector<overlay_change_v9_t>& changes);

    static std::vector<projection_conflict_t> detect_conflicts(
        const std::vector<overlay_change_v9_t>& changes,
        const overlay_static_state_v9_t& projected_state);

    static std::vector<std::uint8_t> apply_patches(
        std::string_view immutable_bytes,
        const overlay_static_state_v9_t& state);

    static projection_invalidation_set_t compute_invalidation(
        const std::vector<overlay_change_v9_t>& changes,
        std::uint64_t image_size = 0);

    static projection_invalidation_dispatch_result_t dispatch_invalidation(
        const projection_invalidation_set_t& invalidation,
        const projection_invalidation_hooks_t& hooks);

    static bool validate_ranges_in_bounds(
        const std::vector<projected_range_t>& ranges,
        std::uint64_t image_size) noexcept;

    static projection_stage_flag_t stage_flags_for_domain(
        overlay_operation_kind_v9_t domain) noexcept;
};

}
}
