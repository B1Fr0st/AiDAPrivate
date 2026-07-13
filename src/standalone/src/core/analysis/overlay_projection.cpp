#include "overlay_projection.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace aida {
namespace analysis {

namespace {

bool coherent_state(const overlay_static_state_v9_t& state) noexcept
{
    return state.target.valid() &&
           state.target.kind == overlay_target_kind_v9_t::static_image &&
           state.next_transaction_id != 0 && state.history_epoch != 0 &&
           state.history_cursor <= state.history.size();
}

bool is_byte_patch_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::byte_patch ||
           kind == overlay_operation_kind_v9_t::assembly_patch ||
           kind == overlay_operation_kind_v9_t::integer_patch;
}

bool is_define_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::define_function ||
           kind == overlay_operation_kind_v9_t::define_code ||
           kind == overlay_operation_kind_v9_t::define_data;
}

bool is_metadata_only_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::comment ||
           kind == overlay_operation_kind_v9_t::comment_update ||
           kind == overlay_operation_kind_v9_t::bookmark ||
           kind == overlay_operation_kind_v9_t::type_declaration ||
           kind == overlay_operation_kind_v9_t::type_application ||
           kind == overlay_operation_kind_v9_t::type_update ||
           kind == overlay_operation_kind_v9_t::enum_definition ||
           kind == overlay_operation_kind_v9_t::stack_variable ||
           kind == overlay_operation_kind_v9_t::delete_stack_variable;
}

bool is_range_bearing_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind != overlay_operation_kind_v9_t::type_declaration &&
           kind != overlay_operation_kind_v9_t::enum_definition;
}

std::uint64_t payload_byte_count(const overlay_payload_v9_t& payload) noexcept
{
    return static_cast<std::uint64_t>(payload.bytes.size());
}

projected_range_t range_from_change(const overlay_change_v9_t& change)
{
    projected_range_t range;
    range.source_kind = change.operation_kind;
    range.is_byte_patch = is_byte_patch_kind(change.operation_kind);
    if (range.is_byte_patch) {
        range.offset = change.entity.range.offset;
        if (change.after)
            range.size = payload_byte_count(*change.after);
        else if (change.before)
            range.size = payload_byte_count(*change.before);
    } else if (is_define_kind(change.operation_kind) ||
               change.operation_kind == overlay_operation_kind_v9_t::undefine ||
               change.operation_kind == overlay_operation_kind_v9_t::reanalysis) {
        range.offset = change.entity.range.offset;
        range.size = change.entity.range.size;
    } else if (change.operation_kind == overlay_operation_kind_v9_t::name) {
        range.offset = change.entity.range.offset;
        range.size = change.entity.range.size > 0 ? change.entity.range.size : 1;
    } else {
        range.offset = change.entity.range.offset;
        range.size = 0;
    }
    return range;
}

projected_entity_t entity_from_change(const overlay_change_v9_t& change)
{
    projected_entity_t entity;
    entity.key = change.entity;
    entity.source_kind = change.operation_kind;
    entity.invalidated = is_byte_patch_kind(change.operation_kind) ||
                         is_define_kind(change.operation_kind) ||
                         change.operation_kind == overlay_operation_kind_v9_t::undefine ||
                         change.operation_kind == overlay_operation_kind_v9_t::reanalysis;
    entity.is_new = !change.before && change.after.has_value();
    return entity;
}

void merge_overlapping_ranges(std::vector<projected_range_t>& ranges) noexcept
{
    if (ranges.size() <= 1)
        return;
    std::sort(ranges.begin(), ranges.end(),
              [](const auto& lhs, const auto& rhs) {
                  if (lhs.offset != rhs.offset)
                      return lhs.offset < rhs.offset;
                  return lhs.size < rhs.size;
              });
    std::vector<projected_range_t> merged;
    merged.reserve(ranges.size());
    merged.push_back(ranges[0]);
    for (std::size_t i = 1; i < ranges.size(); ++i) {
        auto& last = merged.back();
        const auto& current = ranges[i];
        if (current.size == 0) {
            merged.push_back(current);
            continue;
        }
        if (last.size == 0) {
            merged.push_back(current);
            continue;
        }
        if (current.offset <= last.offset + last.size) {
            const auto end = std::max(last.offset + last.size, current.offset + current.size);
            last.offset = std::min(last.offset, current.offset);
            last.size = end - last.offset;
            last.is_byte_patch = last.is_byte_patch || current.is_byte_patch;
        } else {
            merged.push_back(current);
        }
    }
    ranges = std::move(merged);
}

}

std::vector<projected_range_t> overlay_projection_t::derive_affected_ranges(
    const std::vector<overlay_change_v9_t>& changes)
{
    std::vector<projected_range_t> ranges;
    ranges.reserve(changes.size());
    for (const auto& change : changes) {
        auto range = range_from_change(change);
        if (range.size > 0 || range.is_byte_patch)
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
        return projection_stage_flag_t::none;
    case overlay_operation_kind_v9_t::comment:
    case overlay_operation_kind_v9_t::comment_update:
        return projection_stage_flag_t::none;
    case overlay_operation_kind_v9_t::type_declaration:
    case overlay_operation_kind_v9_t::enum_definition:
    case overlay_operation_kind_v9_t::type_application:
    case overlay_operation_kind_v9_t::type_update:
        return projection_stage_flag_t::type_table |
               projection_stage_flag_t::decompiler;
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
    std::uint32_t flags = 0;
    for (const auto& change : changes)
        flags |= static_cast<std::uint32_t>(stage_flags_for_domain(change.operation_kind));
    return static_cast<projection_stage_flag_t>(flags);
}

std::vector<projection_conflict_t> overlay_projection_t::detect_conflicts(
    const std::vector<overlay_change_v9_t>& changes)
{
    std::vector<projection_conflict_t> conflicts;
    std::vector<std::pair<std::size_t, projected_range_t>> indexed_ranges;
    indexed_ranges.reserve(changes.size());
    for (std::size_t i = 0; i < changes.size(); ++i) {
        auto range = range_from_change(changes[i]);
        if (range.size == 0 && !range.is_byte_patch)
            continue;
        if (range.size == 0 && range.is_byte_patch) {
            if (changes[i].after)
                range.size = payload_byte_count(*changes[i].after);
            else if (changes[i].before)
                range.size = payload_byte_count(*changes[i].before);
        }
        if (range.size == 0)
            continue;
        indexed_ranges.emplace_back(i, range);
    }
    for (std::size_t i = 0; i < indexed_ranges.size(); ++i) {
        for (std::size_t j = i + 1; j < indexed_ranges.size(); ++j) {
            const auto& [idx_a, range_a] = indexed_ranges[i];
            const auto& [idx_b, range_b] = indexed_ranges[j];
            if (range_a.overlaps(range_b)) {
                const bool both_patches = range_a.is_byte_patch && range_b.is_byte_patch;
                const bool patch_vs_define =
                    (range_a.is_byte_patch && is_define_kind(changes[idx_b].operation_kind)) ||
                    (range_b.is_byte_patch && is_define_kind(changes[idx_a].operation_kind));
                const bool both_define_same_kind =
                    is_define_kind(changes[idx_a].operation_kind) &&
                    is_define_kind(changes[idx_b].operation_kind);
                if (both_patches || patch_vs_define || both_define_same_kind) {
                    projection_conflict_t conflict;
                    conflict.range_a = range_a;
                    conflict.range_b = range_b;
                    conflict.change_index_a = idx_a;
                    conflict.change_index_b = idx_b;
                    conflicts.push_back(conflict);
                }
            }
        }
    }
    return conflicts;
}

std::vector<std::uint8_t> overlay_projection_t::apply_patches(
    std::string_view immutable_bytes,
    const overlay_static_state_v9_t& state)
{
    std::vector<std::uint8_t> result(immutable_bytes.begin(), immutable_bytes.end());
    for (const auto& [key, payload] : state.items) {
        if (key.domain != overlay_operation_kind_v9_t::byte_patch)
            continue;
        const std::uint64_t offset = key.range.offset;
        const std::size_t patch_size = payload.bytes.size();
        if (offset >= result.size())
            continue;
        if (offset + patch_size > result.size())
            continue;
        std::memcpy(result.data() + offset, payload.bytes.data(), patch_size);
    }
    return result;
}

projection_invalidation_set_t overlay_projection_t::compute_invalidation(
    const std::vector<overlay_change_v9_t>& changes)
{
    projection_invalidation_set_t invalidation;
    invalidation.affected_ranges = derive_affected_ranges(changes);
    invalidation.affected_entities = derive_affected_entities(changes);
    invalidation.invalidated_stages = derive_invalidated_stages(changes);
    invalidation.total_patched_bytes = 0;
    invalidation.max_contiguous_range = 0;
    for (const auto& range : invalidation.affected_ranges) {
        if (range.is_byte_patch)
            invalidation.total_patched_bytes += range.size;
        if (range.size > invalidation.max_contiguous_range)
            invalidation.max_contiguous_range = range.size;
    }
    return invalidation;
}

projection_result_t overlay_projection_t::project(
    const overlay_static_state_v9_t& state,
    std::string_view immutable_bytes,
    std::uint64_t current_generation)
{
    projection_result_t result;
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
    result.projected_bytes = apply_patches(immutable_bytes, state);
    std::vector<overlay_change_v9_t> all_changes;
    all_changes.reserve(state.items.size());
    for (const auto& [key, payload] : state.items) {
        overlay_change_v9_t change;
        change.entity = key;
        change.operation_kind = key.domain;
        change.after = payload;
        if (payload.bytes.empty() && key.domain == overlay_operation_kind_v9_t::byte_patch) {
            continue;
        }
        all_changes.push_back(std::move(change));
    }
    result.invalidation = compute_invalidation(all_changes);
    result.changes = std::move(all_changes);
    result.new_generation = current_generation;
    result.revision = state.revision;
    result.code = projection_code_t::ok;
    return result;
}

projection_result_t overlay_projection_t::project_transaction(
    const overlay_static_state_v9_t& state,
    const overlay_transaction_v9_t& transaction,
    std::string_view immutable_bytes,
    std::uint64_t current_generation,
    const overlay_apply_limits_v9_t& limits)
{
    projection_result_t result;
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
    overlay_static_state_v9_t temp_state = state;
    const auto apply_result = overlay_apply_engine_v9_t::apply(temp_state, transaction, limits);
    if (!apply_result.ok()) {
        result.code = projection_code_t::apply_failure;
        result.detail = "overlay_apply_engine apply failed with code " +
                        std::to_string(static_cast<unsigned>(apply_result.code));
        return result;
    }
    const auto conflicts = detect_conflicts(apply_result.changes);
    if (!conflicts.empty()) {
        result.code = projection_code_t::conflict_detected;
        result.detail = "detected " + std::to_string(conflicts.size()) +
                        " conflicting range overlaps in transaction";
        return result;
    }
    result.changes = apply_result.changes;
    result.invalidation = compute_invalidation(apply_result.changes);
    if (!validate_ranges_in_bounds(result.invalidation.affected_ranges,
                                    state.target.image_size)) {
        result.code = projection_code_t::range_out_of_bounds;
        result.detail = "one or more affected ranges exceed image bounds";
        return result;
    }
    result.projected_bytes = apply_patches(immutable_bytes, temp_state);
    result.new_generation = current_generation;
    result.revision = apply_result.revision;
    result.code = projection_code_t::ok;
    return result;
}

projection_result_t overlay_projection_t::publish_generation(
    overlay_static_state_v9_t& state,
    std::uint64_t expected_generation,
    const projection_invalidation_set_t& invalidation,
    const std::vector<overlay_change_v9_t>& changes)
{
    projection_result_t result;
    if (!coherent_state(state)) {
        result.code = projection_code_t::state_not_initialized;
        result.detail = "state is not initialized";
        return result;
    }
    if (expected_generation != state.target.generation) {
        result.code = projection_code_t::stale_generation;
        result.detail = "expected_generation does not match state.target.generation";
        return result;
    }
    if (state.target.generation == (std::numeric_limits<std::uint64_t>::max)()) {
        result.code = projection_code_t::publication_failed;
        result.detail = "generation at maximum value, cannot increment";
        return result;
    }
    state.target.generation += 1;
    result.new_generation = state.target.generation;
    result.revision = state.revision;
    result.invalidation = invalidation;
    result.changes = changes;
    result.code = projection_code_t::ok;
    return result;
}

bool overlay_projection_t::validate_ranges_in_bounds(
    const std::vector<projected_range_t>& ranges,
    std::uint64_t image_size) noexcept
{
    for (const auto& range : ranges) {
        if (range.size == 0)
            continue;
        if (range.offset >= image_size)
            return false;
        if (range.size > image_size - range.offset)
            return false;
    }
    return true;
}

}
}
