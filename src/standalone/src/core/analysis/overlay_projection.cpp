#include "overlay_projection.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <type_traits>
#include <utility>

namespace aida {
namespace analysis {

namespace {

static_assert(std::is_nothrow_move_assignable_v<overlay_static_state_v9_t>);
static_assert(std::is_nothrow_move_assignable_v<
              projection_invalidation_dispatch_result_t>);
static_assert(std::is_nothrow_move_constructible_v<projection_publication_commit_t>);

constexpr projection_stage_flag_t k_packed_index_stages =
    projection_stage_flag_t::layout_index |
    projection_stage_flag_t::disassembler |
    projection_stage_flag_t::string_table |
    projection_stage_flag_t::xref_table |
    projection_stage_flag_t::function_table |
    projection_stage_flag_t::type_table |
    projection_stage_flag_t::symbol_table |
    projection_stage_flag_t::coverage_table |
    projection_stage_flag_t::basic_block_table;

bool coherent_state(const overlay_static_state_v9_t& state) noexcept
{
    return state.target.valid() &&
           state.target.kind == overlay_target_kind_v9_t::static_image &&
           state.next_transaction_id != 0 && state.history_epoch != 0 &&
           state.history_cursor <= state.history.size();
}

projection_state_version_t capture_state_version(
    const overlay_static_state_v9_t& state) noexcept
{
    projection_state_version_t version;
    version.target = state.target;
    version.revision = state.revision;
    version.next_transaction_id = state.next_transaction_id;
    version.history_cursor = state.history_cursor;
    version.history_epoch = state.history_epoch;
    version.item_count = state.items.size();
    version.history_size = state.history.size();
    return version;
}

bool is_byte_patch_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::byte_patch ||
           kind == overlay_operation_kind_v9_t::assembly_patch ||
           kind == overlay_operation_kind_v9_t::integer_patch;
}

bool is_structural_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::define_function ||
           kind == overlay_operation_kind_v9_t::define_code ||
           kind == overlay_operation_kind_v9_t::define_data ||
           kind == overlay_operation_kind_v9_t::undefine;
}

overlay_operation_kind_v9_t canonical_entity_domain(
    overlay_operation_kind_v9_t kind) noexcept
{
    switch (kind) {
    case overlay_operation_kind_v9_t::comment_update:
        return overlay_operation_kind_v9_t::comment;
    case overlay_operation_kind_v9_t::delete_stack_variable:
        return overlay_operation_kind_v9_t::stack_variable;
    case overlay_operation_kind_v9_t::type_update:
        return overlay_operation_kind_v9_t::type_application;
    case overlay_operation_kind_v9_t::assembly_patch:
    case overlay_operation_kind_v9_t::integer_patch:
        return overlay_operation_kind_v9_t::byte_patch;
    default:
        return kind;
    }
}

std::optional<overlay_operation_kind_v9_t> before_kind_of(
    const overlay_change_v9_t& change) noexcept
{
    if (!change.before)
        return std::nullopt;
    if (change.before_kind)
        return change.before_kind;
    const auto inferred = overlay_operation_kind_for_item_v9(change.entity, *change.before);
    if (inferred)
        return inferred;
    return change.operation_kind;
}

std::optional<overlay_operation_kind_v9_t> after_kind_of(
    const overlay_change_v9_t& change) noexcept
{
    if (!change.after)
        return std::nullopt;
    if (change.after_kind)
        return change.after_kind;
    const auto inferred = overlay_operation_kind_for_item_v9(change.entity, *change.after);
    if (inferred)
        return inferred;
    return change.operation_kind;
}

overlay_operation_kind_v9_t effective_kind_of(
    const overlay_change_v9_t& change) noexcept
{
    const auto after_kind = after_kind_of(change);
    if (after_kind)
        return *after_kind;
    const auto before_kind = before_kind_of(change);
    if (before_kind)
        return *before_kind;
    return change.operation_kind;
}

std::uint64_t payload_byte_count(
    const std::optional<overlay_payload_v9_t>& payload) noexcept
{
    return payload ? static_cast<std::uint64_t>(payload->bytes.size()) : 0;
}

projected_range_t range_from_change(const overlay_change_v9_t& change)
{
    projected_range_t range;
    range.source_kind = effective_kind_of(change);
    const auto before_kind = before_kind_of(change);
    const auto after_kind = after_kind_of(change);
    range.is_byte_patch =
        (before_kind && is_byte_patch_kind(*before_kind)) ||
        (after_kind && is_byte_patch_kind(*after_kind));
    range.offset = change.entity.range.offset;
    if (range.is_byte_patch) {
        range.size = (std::max)(payload_byte_count(change.before),
                                payload_byte_count(change.after));
    } else if (is_structural_kind(range.source_kind) ||
               range.source_kind == overlay_operation_kind_v9_t::reanalysis) {
        range.size = change.entity.range.size;
    } else if (range.source_kind == overlay_operation_kind_v9_t::name) {
        range.size = change.entity.range.size > 0 ? change.entity.range.size : 1;
    }
    return range;
}

std::optional<projected_range_t> active_range_from_change(
    const overlay_change_v9_t& change) noexcept
{
    const auto kind = after_kind_of(change);
    if (!kind)
        return std::nullopt;
    projected_range_t range;
    range.offset = change.entity.range.offset;
    range.source_kind = *kind;
    range.is_byte_patch = is_byte_patch_kind(*kind);
    if (range.is_byte_patch)
        range.size = payload_byte_count(change.after);
    else if (is_structural_kind(*kind))
        range.size = change.entity.range.size;
    if (range.size == 0)
        return std::nullopt;
    return range;
}

projected_entity_t entity_from_change(const overlay_change_v9_t& change)
{
    projected_entity_t entity;
    entity.key = change.entity;
    entity.before_kind = before_kind_of(change);
    entity.after_kind = after_kind_of(change);
    entity.source_kind = effective_kind_of(change);
    projection_stage_flag_t flags = projection_stage_flag_t::none;
    if (entity.before_kind)
        flags = flags | overlay_projection_t::stage_flags_for_domain(*entity.before_kind);
    if (entity.after_kind)
        flags = flags | overlay_projection_t::stage_flags_for_domain(*entity.after_kind);
    entity.invalidated = flags != projection_stage_flag_t::none;
    entity.is_new = !change.before && change.after.has_value();
    return entity;
}

bool checked_range_end(const projected_range_t& range,
                       std::uint64_t& end) noexcept
{
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    if (range.size > maximum - range.offset)
        return false;
    end = range.offset + range.size;
    return true;
}

void merge_overlapping_ranges(std::vector<projected_range_t>& ranges)
{
    if (ranges.size() <= 1)
        return;
    std::sort(ranges.begin(), ranges.end(),
              [](const auto& lhs, const auto& rhs) {
                  if (lhs.offset != rhs.offset)
                      return lhs.offset < rhs.offset;
                  if (lhs.is_byte_patch != rhs.is_byte_patch)
                      return lhs.is_byte_patch < rhs.is_byte_patch;
                  return lhs.size < rhs.size;
              });
    std::vector<projected_range_t> merged;
    merged.reserve(ranges.size());
    merged.push_back(ranges.front());
    for (std::size_t index = 1; index < ranges.size(); ++index) {
        auto& last = merged.back();
        const auto& current = ranges[index];
        std::uint64_t last_end = 0;
        std::uint64_t current_end = 0;
        if (last.size == 0 || current.size == 0 ||
            last.is_byte_patch != current.is_byte_patch ||
            !checked_range_end(last, last_end) ||
            !checked_range_end(current, current_end) ||
            current.offset > last_end) {
            merged.push_back(current);
            continue;
        }
        const auto end = (std::max)(last_end, current_end);
        last.offset = (std::min)(last.offset, current.offset);
        last.size = end - last.offset;
    }
    ranges = std::move(merged);
}

bool conflicting_kinds(overlay_operation_kind_v9_t lhs,
                       overlay_operation_kind_v9_t rhs) noexcept
{
    const bool lhs_patch = is_byte_patch_kind(lhs);
    const bool rhs_patch = is_byte_patch_kind(rhs);
    const bool lhs_structural = is_structural_kind(lhs);
    const bool rhs_structural = is_structural_kind(rhs);
    return (lhs_patch && rhs_patch) ||
           (lhs_patch && rhs_structural) ||
           (rhs_patch && lhs_structural) ||
           (lhs_structural && rhs_structural);
}

struct indexed_active_range_t final {
    std::size_t index = 0;
    projected_range_t range;
    overlay_entity_key_v9_t entity;
    overlay_operation_kind_v9_t kind = overlay_operation_kind_v9_t::comment;
    projection_conflict_origin_t origin = projection_conflict_origin_t::transaction;
};

projection_conflict_t make_conflict(const indexed_active_range_t& lhs,
                                    const indexed_active_range_t& rhs)
{
    projection_conflict_t conflict;
    conflict.range_a = lhs.range;
    conflict.range_b = rhs.range;
    conflict.entity_a = lhs.entity;
    conflict.entity_b = rhs.entity;
    conflict.change_index_a = lhs.index;
    conflict.change_index_b = rhs.index;
    conflict.origin_a = lhs.origin;
    conflict.origin_b = rhs.origin;
    return conflict;
}

void sort_active_ranges(std::vector<indexed_active_range_t>& ranges)
{
    std::sort(ranges.begin(), ranges.end(),
              [](const auto& lhs, const auto& rhs) {
                  if (lhs.range.offset != rhs.range.offset)
                      return lhs.range.offset < rhs.range.offset;
                  if (lhs.origin != rhs.origin)
                      return static_cast<std::uint8_t>(lhs.origin) <
                             static_cast<std::uint8_t>(rhs.origin);
                  return lhs.index < rhs.index;
              });
}

bool persisted_entity_in_bounds(const overlay_entity_key_v9_t& entity,
                                const overlay_payload_v9_t& payload,
                                std::uint64_t image_size) noexcept
{
    if (entity.domain == overlay_operation_kind_v9_t::type_declaration ||
        entity.domain == overlay_operation_kind_v9_t::enum_definition)
        return entity.range.offset == 0 && entity.range.size == 0;
    if (entity.domain == overlay_operation_kind_v9_t::byte_patch) {
        const auto size = static_cast<std::uint64_t>(payload.bytes.size());
        return entity.range.size == 0 && size != 0 &&
               entity.range.offset < image_size &&
               size <= image_size - entity.range.offset;
    }
    if (entity.domain == overlay_operation_kind_v9_t::comment ||
        entity.domain == overlay_operation_kind_v9_t::stack_variable ||
        entity.domain == overlay_operation_kind_v9_t::type_application)
        return entity.range.size == 0 && entity.range.offset < image_size;
    return entity.range.size != 0 && entity.range.offset < image_size &&
           entity.range.size <= image_size - entity.range.offset;
}

bool persisted_state_in_bounds(const overlay_static_state_v9_t& state) noexcept
{
    return std::all_of(
        state.items.begin(), state.items.end(),
        [&](const auto& item) {
            return persisted_entity_in_bounds(
                item.first, item.second, state.target.image_size);
        });
}

std::optional<std::vector<overlay_change_v9_t>> changes_from_state(
    const overlay_static_state_v9_t& state)
{
    std::vector<overlay_change_v9_t> changes;
    changes.reserve(state.items.size());
    for (const auto& item : state.items) {
        const auto kind = overlay_operation_kind_for_item_v9(item.first, item.second);
        if (!kind)
            return std::nullopt;
        overlay_change_v9_t change;
        change.entity = item.first;
        change.operation_kind = *kind;
        change.after_kind = *kind;
        change.after = item.second;
        changes.push_back(std::move(change));
    }
    return changes;
}

void bind_invalidation_generations(projection_invalidation_set_t& invalidation,
                                   std::uint64_t source_generation,
                                   std::uint64_t target_generation) noexcept
{
    invalidation.packed_index.source_generation = source_generation;
    invalidation.packed_index.target_generation = target_generation;
    invalidation.decompiler_cache.source_generation = source_generation;
    invalidation.decompiler_cache.target_generation = target_generation;
}

bool packed_request_equal(const packed_index_invalidation_request_t& lhs,
                          const packed_index_invalidation_request_t& rhs) noexcept
{
    return lhs.source_generation == rhs.source_generation &&
           lhs.target_generation == rhs.target_generation &&
           lhs.invalidated_stages == rhs.invalidated_stages &&
           lhs.affected_ranges == rhs.affected_ranges &&
           lhs.affected_entities == rhs.affected_entities &&
           lhs.rebuild_all == rhs.rebuild_all;
}

bool decompiler_request_equal(
    const decompiler_cache_invalidation_request_t& lhs,
    const decompiler_cache_invalidation_request_t& rhs) noexcept
{
    return lhs.source_generation == rhs.source_generation &&
           lhs.target_generation == rhs.target_generation &&
           lhs.invalidated_stages == rhs.invalidated_stages &&
           lhs.affected_ranges == rhs.affected_ranges &&
           lhs.affected_entities == rhs.affected_entities &&
           lhs.invalidate_workspace == rhs.invalidate_workspace;
}

bool invalidation_equal(const projection_invalidation_set_t& lhs,
                        const projection_invalidation_set_t& rhs) noexcept
{
    return lhs.affected_ranges == rhs.affected_ranges &&
           lhs.affected_entities == rhs.affected_entities &&
           lhs.invalidated_stages == rhs.invalidated_stages &&
           lhs.total_patched_bytes == rhs.total_patched_bytes &&
           lhs.max_contiguous_range == rhs.max_contiguous_range &&
           packed_request_equal(lhs.packed_index, rhs.packed_index) &&
           decompiler_request_equal(lhs.decompiler_cache, rhs.decompiler_cache);
}

bool transition_matches_candidate(
    const overlay_static_state_v9_t& source,
    const overlay_static_state_v9_t& candidate,
    const std::vector<overlay_change_v9_t>& changes)
{
    if (changes.empty())
        return false;
    auto expected_items = source.items;
    std::set<overlay_entity_key_v9_t> seen;
    for (const auto& change : changes) {
        if (!seen.insert(change.entity).second ||
            !overlay_operation_kind_from_ordinal(
                static_cast<std::uint8_t>(change.operation_kind)) ||
            canonical_entity_domain(change.operation_kind) != change.entity.domain)
            return false;

        const auto source_item = source.items.find(change.entity);
        if (change.before.has_value() != (source_item != source.items.end()))
            return false;
        if (source_item != source.items.end()) {
            const auto source_kind = overlay_operation_kind_for_item_v9(
                source_item->first, source_item->second);
            if (!source_kind || !change.before_kind ||
                *change.before_kind != *source_kind ||
                *change.before != source_item->second)
                return false;
        } else if (change.before_kind) {
            return false;
        }

        const auto candidate_item = candidate.items.find(change.entity);
        if (change.after.has_value() != (candidate_item != candidate.items.end()))
            return false;
        if (candidate_item != candidate.items.end()) {
            const auto candidate_kind = overlay_operation_kind_for_item_v9(
                candidate_item->first, candidate_item->second);
            if (!candidate_kind || !change.after_kind ||
                canonical_entity_domain(*change.after_kind) != change.entity.domain ||
                (is_byte_patch_kind(*candidate_kind) &&
                 *change.after_kind != *candidate_kind) ||
                *change.after != candidate_item->second)
                return false;
            expected_items[change.entity] = *change.after;
        } else {
            if (change.after_kind)
                return false;
            expected_items.erase(change.entity);
        }
    }
    return expected_items == candidate.items;
}

bool changes_equal(const std::vector<overlay_change_v9_t>& lhs,
                   const std::vector<overlay_change_v9_t>& rhs) noexcept;

bool history_matches_candidate(const overlay_static_state_v9_t& source,
                               const overlay_static_state_v9_t& candidate) noexcept
{
    if (source.history_cursor > source.history.size() ||
        source.history_cursor == (std::numeric_limits<std::size_t>::max)() ||
        candidate.history.size() !=
            static_cast<std::size_t>(source.history_cursor) + 1)
        return false;
    for (std::size_t index = 0;
         index < static_cast<std::size_t>(source.history_cursor); ++index) {
        const auto& old_entry = source.history[index];
        const auto& new_entry = candidate.history[index];
        if (old_entry.target != source.target ||
            old_entry.generation != source.target.generation ||
            new_entry.target != candidate.target ||
            new_entry.generation != candidate.target.generation ||
            old_entry.transaction_id != new_entry.transaction_id ||
            old_entry.originating_revision != new_entry.originating_revision ||
            !changes_equal(old_entry.changes, new_entry.changes))
            return false;
    }
    return true;
}

void rebase_state_generation(overlay_static_state_v9_t& state,
                             std::uint64_t generation) noexcept
{
    state.target.generation = generation;
    for (auto& entry : state.history) {
        entry.target = state.target;
        entry.generation = generation;
    }
}

bool changes_equal(const std::vector<overlay_change_v9_t>& lhs,
                   const std::vector<overlay_change_v9_t>& rhs) noexcept
{
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin(),
                      [](const auto& left, const auto& right) {
                          return left.entity == right.entity &&
                                 left.operation_kind == right.operation_kind &&
                                 left.before_kind == right.before_kind &&
                                 left.after_kind == right.after_kind &&
                                 left.before == right.before &&
                                 left.after == right.after;
                      });
}

bool publication_state_coherent(const overlay_static_state_v9_t& state,
                                 const projection_result_t& prepared) noexcept
{
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    if (!coherent_state(state) || prepared.source_generation == maximum ||
        prepared.source_revision == maximum ||
        prepared.source_state.next_transaction_id == maximum ||
        prepared.source_generation != prepared.source_state.target.generation ||
        prepared.source_revision != prepared.source_state.revision ||
        prepared.new_generation != prepared.source_generation + 1 ||
        prepared.revision != prepared.source_revision + 1)
        return false;
    auto expected_target = prepared.source_state.target;
    expected_target.generation = prepared.new_generation;
    if (state.target != expected_target || state.revision != prepared.revision ||
        state.next_transaction_id != prepared.source_state.next_transaction_id + 1 ||
        prepared.source_state.history_cursor ==
            (std::numeric_limits<std::size_t>::max)())
        return false;
    const auto expected_history_size =
        static_cast<std::size_t>(prepared.source_state.history_cursor) + 1;
    if (state.history.size() != expected_history_size ||
        state.history_cursor != expected_history_size)
        return false;
    const bool truncated_redo = prepared.source_state.history_cursor !=
                                prepared.source_state.history_size;
    if (truncated_redo && prepared.source_state.history_epoch == maximum)
        return false;
    const auto expected_epoch = prepared.source_state.history_epoch +
                                (truncated_redo ? 1U : 0U);
    if (state.history_epoch != expected_epoch || state.history.empty())
        return false;
    const auto& latest = state.history.back();
    if (latest.transaction_id != prepared.source_state.next_transaction_id ||
        latest.originating_revision != prepared.revision ||
        !changes_equal(latest.changes, prepared.changes))
        return false;
    return std::all_of(state.history.begin(), state.history.end(),
                       [&](const auto& entry) {
                           return entry.target == state.target &&
                                  entry.generation == state.target.generation;
                       });
}

}

std::vector<projected_range_t> overlay_projection_t::derive_affected_ranges(
    const std::vector<overlay_change_v9_t>& changes)
{
    std::vector<projected_range_t> ranges;
    ranges.reserve(changes.size());
    for (const auto& change : changes) {
        auto range = range_from_change(change);
        if (range.size > 0)
            ranges.push_back(range);
    }
    merge_overlapping_ranges(ranges);
    return ranges;
}

std::vector<projected_entity_t> overlay_projection_t::derive_affected_entities(
    const std::vector<overlay_change_v9_t>& changes)
{
    std::vector<projected_entity_t> entities;
    entities.reserve(changes.size());
    for (const auto& change : changes)
        entities.push_back(entity_from_change(change));
    return entities;
}

projection_stage_flag_t overlay_projection_t::stage_flags_for_domain(
    overlay_operation_kind_v9_t domain) noexcept
{
    switch (domain) {
    case overlay_operation_kind_v9_t::byte_patch:
        return projection_stage_flag_t::disassembler |
               projection_stage_flag_t::decompiler |
               projection_stage_flag_t::string_table |
               projection_stage_flag_t::xref_table |
               projection_stage_flag_t::coverage_table |
               projection_stage_flag_t::basic_block_table;
    case overlay_operation_kind_v9_t::assembly_patch:
    case overlay_operation_kind_v9_t::integer_patch:
        return projection_stage_flag_t::disassembler |
               projection_stage_flag_t::decompiler |
               projection_stage_flag_t::xref_table |
               projection_stage_flag_t::basic_block_table;
    case overlay_operation_kind_v9_t::define_function:
        return projection_stage_flag_t::function_table |
               projection_stage_flag_t::decompiler |
               projection_stage_flag_t::xref_table |
               projection_stage_flag_t::basic_block_table;
    case overlay_operation_kind_v9_t::define_code:
    case overlay_operation_kind_v9_t::define_data:
        return projection_stage_flag_t::disassembler |
               projection_stage_flag_t::decompiler |
               projection_stage_flag_t::basic_block_table;
    case overlay_operation_kind_v9_t::undefine:
        return projection_stage_flag_t::disassembler |
               projection_stage_flag_t::decompiler |
               projection_stage_flag_t::basic_block_table |
               projection_stage_flag_t::xref_table;
    case overlay_operation_kind_v9_t::name:
        return projection_stage_flag_t::symbol_table;
    case overlay_operation_kind_v9_t::bookmark:
    case overlay_operation_kind_v9_t::comment:
    case overlay_operation_kind_v9_t::comment_update:
        return projection_stage_flag_t::none;
    case overlay_operation_kind_v9_t::type_declaration:
    case overlay_operation_kind_v9_t::enum_definition:
    case overlay_operation_kind_v9_t::type_application:
    case overlay_operation_kind_v9_t::type_update:
    case overlay_operation_kind_v9_t::stack_variable:
    case overlay_operation_kind_v9_t::delete_stack_variable:
        return projection_stage_flag_t::type_table |
               projection_stage_flag_t::decompiler;
    case overlay_operation_kind_v9_t::reanalysis:
        return projection_stage_flag_t::all_stages;
    }
    return projection_stage_flag_t::none;
}

projection_stage_flag_t overlay_projection_t::derive_invalidated_stages(
    const std::vector<overlay_change_v9_t>& changes)
{
    projection_stage_flag_t flags = projection_stage_flag_t::none;
    for (const auto& change : changes) {
        const auto before_kind = before_kind_of(change);
        const auto after_kind = after_kind_of(change);
        if (before_kind)
            flags = flags | stage_flags_for_domain(*before_kind);
        if (after_kind)
            flags = flags | stage_flags_for_domain(*after_kind);
        if (!before_kind && !after_kind)
            flags = flags | stage_flags_for_domain(change.operation_kind);
    }
    return flags;
}

std::vector<projection_conflict_t> overlay_projection_t::detect_conflicts(
    const std::vector<overlay_change_v9_t>& changes)
{
    std::vector<indexed_active_range_t> active;
    active.reserve(changes.size());
    for (std::size_t index = 0; index < changes.size(); ++index) {
        const auto range = active_range_from_change(changes[index]);
        const auto kind = after_kind_of(changes[index]);
        if (!range || !kind)
            continue;
        active.push_back({index, *range, changes[index].entity, *kind,
                          projection_conflict_origin_t::transaction});
    }
    sort_active_ranges(active);
    std::vector<projection_conflict_t> conflicts;
    for (std::size_t lhs = 0; lhs < active.size(); ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < active.size(); ++rhs) {
            if (active[rhs].range.offset - active[lhs].range.offset >=
                active[lhs].range.size)
                break;
            if (active[lhs].range.overlaps(active[rhs].range) &&
                conflicting_kinds(active[lhs].kind, active[rhs].kind))
                conflicts.push_back(make_conflict(active[lhs], active[rhs]));
        }
    }
    return conflicts;
}

std::vector<projection_conflict_t> overlay_projection_t::detect_conflicts(
    const std::vector<overlay_change_v9_t>& changes,
    const overlay_static_state_v9_t& projected_state)
{
    auto conflicts = detect_conflicts(changes);
    std::set<overlay_entity_key_v9_t> replaced_entities;
    for (const auto& change : changes)
        replaced_entities.insert(change.entity);

    std::vector<indexed_active_range_t> combined;
    if (projected_state.items.size() <= combined.max_size() - changes.size())
        combined.reserve(changes.size() + projected_state.items.size());
    for (std::size_t index = 0; index < changes.size(); ++index) {
        const auto range = active_range_from_change(changes[index]);
        const auto kind = after_kind_of(changes[index]);
        if (!range || !kind)
            continue;
        combined.push_back({index, *range, changes[index].entity, *kind,
                            projection_conflict_origin_t::transaction});
    }

    std::size_t existing_index = 0;
    for (const auto& item : projected_state.items) {
        if (replaced_entities.find(item.first) != replaced_entities.end()) {
            ++existing_index;
            continue;
        }
        const auto kind = overlay_operation_kind_for_item_v9(item.first, item.second);
        if (!kind) {
            ++existing_index;
            continue;
        }
        overlay_change_v9_t existing_change;
        existing_change.entity = item.first;
        existing_change.operation_kind = *kind;
        existing_change.after_kind = *kind;
        existing_change.after = item.second;
        const auto range = active_range_from_change(existing_change);
        if (!range) {
            ++existing_index;
            continue;
        }
        combined.push_back({
            existing_index, *range, item.first, *kind,
            projection_conflict_origin_t::projected_state});
        ++existing_index;
    }
    sort_active_ranges(combined);
    for (std::size_t lhs = 0; lhs < combined.size(); ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < combined.size(); ++rhs) {
            if (combined[rhs].range.offset - combined[lhs].range.offset >=
                combined[lhs].range.size)
                break;
            if (combined[lhs].origin == combined[rhs].origin ||
                !combined[lhs].range.overlaps(combined[rhs].range) ||
                !conflicting_kinds(combined[lhs].kind, combined[rhs].kind))
                continue;
            if (combined[lhs].origin == projection_conflict_origin_t::transaction)
                conflicts.push_back(make_conflict(combined[lhs], combined[rhs]));
            else
                conflicts.push_back(make_conflict(combined[rhs], combined[lhs]));
        }
    }
    return conflicts;
}

std::vector<std::uint8_t> overlay_projection_t::apply_patches(
    std::string_view immutable_bytes,
    const overlay_static_state_v9_t& state)
{
    std::vector<std::uint8_t> result(immutable_bytes.begin(), immutable_bytes.end());
    for (const auto& item : state.items) {
        if (item.first.domain != overlay_operation_kind_v9_t::byte_patch ||
            !overlay_operation_kind_for_item_v9(item.first, item.second))
            continue;
        const auto offset = item.first.range.offset;
        const auto patch_size = item.second.bytes.size();
        if (patch_size == 0 || offset > result.size() ||
            patch_size > result.size() - static_cast<std::size_t>(offset))
            continue;
        std::memcpy(result.data() + static_cast<std::size_t>(offset),
                    item.second.bytes.data(), patch_size);
    }
    return result;
}

projection_invalidation_set_t overlay_projection_t::compute_invalidation(
    const std::vector<overlay_change_v9_t>& changes,
    std::uint64_t image_size)
{
    projection_invalidation_set_t invalidation;
    invalidation.affected_ranges = derive_affected_ranges(changes);
    invalidation.affected_entities = derive_affected_entities(changes);
    invalidation.invalidated_stages = derive_invalidated_stages(changes);
    const bool full_reanalysis = image_size != 0 && std::any_of(
        changes.begin(), changes.end(), [](const auto& change) {
            const auto before_kind = before_kind_of(change);
            const auto after_kind = after_kind_of(change);
            return (before_kind &&
                    *before_kind == overlay_operation_kind_v9_t::reanalysis) ||
                   (after_kind &&
                    *after_kind == overlay_operation_kind_v9_t::reanalysis);
        });
    if (full_reanalysis) {
        invalidation.affected_ranges = {{
            0, image_size, false, overlay_operation_kind_v9_t::reanalysis}};
        invalidation.invalidated_stages = projection_stage_flag_t::all_stages;
    }
    for (const auto& range : invalidation.affected_ranges) {
        if (range.is_byte_patch) {
            const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
            invalidation.total_patched_bytes =
                range.size > maximum - invalidation.total_patched_bytes
                    ? maximum
                    : invalidation.total_patched_bytes + range.size;
        }
        invalidation.max_contiguous_range =
            (std::max)(invalidation.max_contiguous_range, range.size);
    }

    invalidation.packed_index.invalidated_stages =
        invalidation.invalidated_stages & k_packed_index_stages;
    invalidation.packed_index.rebuild_all =
        full_reanalysis ||
        invalidation.invalidated_stages == projection_stage_flag_t::all_stages;
    invalidation.packed_index.affected_ranges = invalidation.affected_ranges;
    invalidation.packed_index.affected_entities = invalidation.affected_entities;

    invalidation.decompiler_cache.affected_ranges = invalidation.affected_ranges;
    invalidation.decompiler_cache.affected_entities = invalidation.affected_entities;

    if (stage_test(invalidation.invalidated_stages,
                   projection_stage_flag_t::decompiler)) {
        invalidation.decompiler_cache.invalidated_stages =
            decompiler_cache_invalidation_flag_t::all_stages;
        invalidation.decompiler_cache.invalidate_workspace =
            full_reanalysis ||
            invalidation.invalidated_stages == projection_stage_flag_t::all_stages;
    }
    return invalidation;
}

projection_invalidation_dispatch_result_t overlay_projection_t::dispatch_invalidation(
    const projection_invalidation_set_t& invalidation,
    const projection_invalidation_hooks_t& hooks)
{
    projection_invalidation_dispatch_result_t result;
    if (invalidation.packed_index.required() && !hooks.packed_index) {
        result.code = projection_invalidation_dispatch_code_t::missing_packed_index_hook;
        result.detail = "packed-index invalidation hook is required";
        return result;
    }
    if (invalidation.decompiler_cache.required() && !hooks.decompiler_cache) {
        result.code = projection_invalidation_dispatch_code_t::missing_decompiler_cache_hook;
        result.detail = "decompiler-cache invalidation hook is required";
        return result;
    }
    try {
        if (invalidation.decompiler_cache.required()) {
            result.decompiler_cache = hooks.decompiler_cache(invalidation.decompiler_cache);
            if (!result.decompiler_cache) {
                result.code = projection_invalidation_dispatch_code_t::decompiler_cache_rejected;
                result.detail = result.decompiler_cache.detail;
                return result;
            }
            result.decompiler_cache_completed = true;
        }
        if (invalidation.packed_index.required()) {
            result.packed_index = hooks.packed_index(invalidation.packed_index);
            if (!result.packed_index) {
                result.code = projection_invalidation_dispatch_code_t::packed_index_rejected;
                result.detail = result.packed_index.detail;
                return result;
            }
            result.packed_index_completed = true;
        }
    } catch (...) {
        result.code = projection_invalidation_dispatch_code_t::hook_exception;
        result.detail = "invalidation hook raised an exception";
        return result;
    }
    return result;
}

projection_result_t overlay_projection_t::project(
    const overlay_static_state_v9_t& state,
    std::string_view immutable_bytes,
    std::uint64_t current_generation)
{
    projection_result_t result;
    result.source_state = capture_state_version(state);
    result.source_generation = state.target.generation;
    result.source_revision = state.revision;
    try {
        if (!coherent_state(state)) {
            result.code = projection_code_t::state_not_initialized;
            result.detail = "overlay state is not initialized or incoherent";
            return result;
        }
        if (current_generation != state.target.generation) {
            result.code = projection_code_t::stale_generation;
            result.detail = "current_generation does not match state.target.generation";
            return result;
        }
        if (immutable_bytes.size() < state.target.image_size) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "immutable_bytes smaller than image_size";
            return result;
        }
        if (!persisted_state_in_bounds(state)) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "projected state contains an out-of-bounds entity";
            return result;
        }
        auto changes = changes_from_state(state);
        if (!changes) {
            result.code = projection_code_t::invalid_patch_provenance;
            result.detail = "projected state contains invalid or ambiguous patch provenance";
            return result;
        }
        if (!detect_conflicts(*changes).empty()) {
            result.code = projection_code_t::conflict_detected;
            result.detail = "projected state contains conflicting active ranges";
            return result;
        }
        result.invalidation = compute_invalidation(*changes, state.target.image_size);
        bind_invalidation_generations(result.invalidation,
                                      current_generation, current_generation);
        if (!validate_ranges_in_bounds(result.invalidation.affected_ranges,
                                       state.target.image_size)) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "one or more projected ranges exceed image bounds";
            return result;
        }
        result.projected_bytes = apply_patches(immutable_bytes, state);
        result.changes = std::move(*changes);
        result.projected_state = state;
        result.new_generation = current_generation;
        result.revision = state.revision;
        result.code = projection_code_t::ok;
        return result;
    } catch (...) {
        result.code = projection_code_t::publication_failed;
        result.detail = "projection allocation or state preparation failed";
        return result;
    }
}

projection_result_t overlay_projection_t::project_transaction(
    const overlay_static_state_v9_t& state,
    const overlay_transaction_v9_t& transaction,
    std::string_view immutable_bytes,
    std::uint64_t current_generation,
    const overlay_apply_limits_v9_t& limits)
{
    projection_result_t result;
    result.source_state = capture_state_version(state);
    result.source_generation = state.target.generation;
    result.source_revision = state.revision;
    try {
        if (!coherent_state(state)) {
            result.code = projection_code_t::state_not_initialized;
            result.detail = "overlay state is not initialized or incoherent";
            return result;
        }
        if (current_generation != state.target.generation) {
            result.code = projection_code_t::stale_generation;
            result.detail = "current_generation does not match state.target.generation";
            return result;
        }
        if (transaction.target != state.target) {
            result.code = projection_code_t::invalid_target;
            result.detail = "transaction target does not match state target";
            return result;
        }
        if (transaction.operations.empty()) {
            result.code = projection_code_t::empty_projection;
            result.detail = "transaction has no operations";
            return result;
        }
        if (immutable_bytes.size() < state.target.image_size) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "immutable_bytes smaller than image_size";
            return result;
        }
        if (!persisted_state_in_bounds(state)) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "projected state contains an out-of-bounds entity";
            return result;
        }
        if (current_generation == (std::numeric_limits<std::uint64_t>::max)()) {
            result.code = projection_code_t::publication_failed;
            result.detail = "generation is exhausted";
            return result;
        }
        const auto existing_changes = changes_from_state(state);
        if (!existing_changes) {
            result.code = projection_code_t::invalid_patch_provenance;
            result.detail = "projected state contains invalid or ambiguous patch provenance";
            return result;
        }

        overlay_static_state_v9_t projected_state = state;
        const auto apply_result = overlay_apply_engine_v9_t::apply(
            projected_state, transaction, limits);
        if (!apply_result.ok()) {
            switch (apply_result.code) {
            case overlay_apply_code_v9_t::revision_conflict:
                result.code = projection_code_t::revision_conflict;
                break;
            case overlay_apply_code_v9_t::stale_generation:
                result.code = projection_code_t::stale_generation;
                break;
            case overlay_apply_code_v9_t::invalid_target:
            case overlay_apply_code_v9_t::static_target_required:
                result.code = projection_code_t::invalid_target;
                break;
            case overlay_apply_code_v9_t::revision_overflow:
            case overlay_apply_code_v9_t::transaction_overflow:
            case overlay_apply_code_v9_t::history_overflow:
                result.code = projection_code_t::transaction_overflow;
                break;
            default:
                result.code = projection_code_t::apply_failure;
                break;
            }
            result.detail = "overlay_apply_engine apply failed with code " +
                            std::to_string(static_cast<unsigned>(apply_result.code));
            return result;
        }
        const auto conflicts = detect_conflicts(apply_result.changes, state);
        if (!conflicts.empty()) {
            const auto existing_conflicts = static_cast<std::size_t>(
                std::count_if(conflicts.begin(), conflicts.end(),
                              [](const auto& conflict) {
                                  return conflict.against_projected_state();
                              }));
            result.code = projection_code_t::conflict_detected;
            result.detail = "detected " + std::to_string(conflicts.size()) +
                            " conflicting active range overlaps, including " +
                            std::to_string(existing_conflicts) +
                            " against projected state";
            return result;
        }
        const auto projected_changes = changes_from_state(projected_state);
        if (!projected_changes || !detect_conflicts(*projected_changes).empty()) {
            result.code = projection_code_t::conflict_detected;
            result.detail = "post-transaction projected state contains conflicting active ranges";
            return result;
        }
        result.changes = apply_result.changes;
        result.invalidation = compute_invalidation(
            result.changes, state.target.image_size);
        result.new_generation = current_generation + 1;
        bind_invalidation_generations(result.invalidation,
                                      current_generation, result.new_generation);
        if (!validate_ranges_in_bounds(result.invalidation.affected_ranges,
                                       state.target.image_size)) {
            result.code = projection_code_t::range_out_of_bounds;
            result.detail = "one or more affected ranges exceed image bounds";
            return result;
        }
        result.projected_bytes = apply_patches(immutable_bytes, projected_state);
        rebase_state_generation(projected_state, result.new_generation);
        result.projected_state = std::move(projected_state);
        result.revision = apply_result.revision;
        result.publication_ready = true;
        result.code = projection_code_t::ok;
        return result;
    } catch (...) {
        result.code = projection_code_t::publication_failed;
        result.detail = "transaction projection allocation or state preparation failed";
        return result;
    }
}

projection_finalize_result_t overlay_projection_t::finalize_publication(
    overlay_static_state_v9_t& state,
    const projection_result_t& prepared,
    const projection_invalidation_hooks_t& hooks,
    const projection_publication_finalizer_t& finalizer)
{
    projection_finalize_result_t result;
    result.code = projection_code_t::invalid_publication;
    if (!coherent_state(state)) {
        result.code = projection_code_t::state_not_initialized;
        result.detail = "overlay state is not initialized or incoherent";
        return result;
    }
    if (!prepared.ok() || !prepared.publication_ready ||
        !prepared.projected_state || !finalizer) {
        result.detail = "prepared projection is not publication-ready";
        return result;
    }
    if (!prepared.source_state.matches(state)) {
        result.code = state.target.generation == prepared.source_generation
            ? projection_code_t::revision_conflict
            : projection_code_t::stale_generation;
        result.detail = "overlay state changed after projection preparation";
        return result;
    }
    if (prepared.source_generation == (std::numeric_limits<std::uint64_t>::max)() ||
        prepared.new_generation != prepared.source_generation + 1 ||
        prepared.invalidation.packed_index.source_generation != prepared.source_generation ||
        prepared.invalidation.packed_index.target_generation != prepared.new_generation ||
        prepared.invalidation.decompiler_cache.source_generation != prepared.source_generation ||
        prepared.invalidation.decompiler_cache.target_generation != prepared.new_generation) {
        result.detail = "prepared projection generation contract is invalid";
        return result;
    }
    if (prepared.invalidation.packed_index.required() && !hooks.packed_index) {
        result.code = projection_code_t::finalizer_failed;
        result.invalidation.code =
            projection_invalidation_dispatch_code_t::missing_packed_index_hook;
        result.invalidation.detail = "packed-index invalidation hook is required";
        result.detail = result.invalidation.detail;
        return result;
    }
    if (prepared.invalidation.decompiler_cache.required() && !hooks.decompiler_cache) {
        result.code = projection_code_t::finalizer_failed;
        result.invalidation.code =
            projection_invalidation_dispatch_code_t::missing_decompiler_cache_hook;
        result.invalidation.detail = "decompiler-cache invalidation hook is required";
        result.detail = result.invalidation.detail;
        return result;
    }
    try {
        overlay_static_state_v9_t next_state = *prepared.projected_state;
        auto expected_invalidation = compute_invalidation(
            prepared.changes, next_state.target.image_size);
        bind_invalidation_generations(expected_invalidation,
                                      prepared.source_generation,
                                      prepared.new_generation);
        const auto active_changes = changes_from_state(next_state);
        if (!publication_state_coherent(next_state, prepared) ||
            next_state.target.image_size >
                static_cast<std::uint64_t>(prepared.projected_bytes.size()) ||
            !transition_matches_candidate(state, next_state, prepared.changes) ||
            !history_matches_candidate(state, next_state) ||
            !invalidation_equal(expected_invalidation, prepared.invalidation) ||
            !persisted_state_in_bounds(next_state) || !active_changes ||
            !detect_conflicts(*active_changes).empty()) {
            result.detail = "projected overlay metadata is not generation-coherent";
            return result;
        }
        const projection_publication_view_t view{
            next_state,
            prepared.projected_bytes,
            prepared.invalidation,
            prepared.changes,
            prepared.source_generation,
            prepared.new_generation,
            prepared.source_revision,
            prepared.revision};
        auto commit = finalizer(view, hooks);
        if (!commit.ok(prepared.invalidation)) {
            result.invalidation = std::move(commit.invalidation);
            result.code = projection_code_t::finalizer_failed;
            result.detail = commit.detail.empty()
                ? result.invalidation.detail : std::move(commit.detail);
            if (result.detail.empty())
                result.detail = "publication finalizer rejected the candidate";
            return result;
        }
        state = std::move(next_state);
        result.invalidation = std::move(commit.invalidation);
        result.code = projection_code_t::ok;
        result.new_generation = state.target.generation;
        result.revision = state.revision;
        return result;
    } catch (...) {
        result.code = projection_code_t::finalizer_failed;
        result.detail = "publication finalizer or candidate copy raised an exception";
        return result;
    }
}

bool overlay_projection_t::validate_ranges_in_bounds(
    const std::vector<projected_range_t>& ranges,
    std::uint64_t image_size) noexcept
{
    for (const auto& range : ranges) {
        if (range.size == 0)
            continue;
        if (range.offset >= image_size || range.size > image_size - range.offset)
            return false;
    }
    return true;
}

}
}
