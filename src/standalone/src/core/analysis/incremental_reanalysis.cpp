#include "incremental_reanalysis.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace aida {
namespace analysis {

namespace {

std::optional<overlay_operation_kind_v9_t> before_kind_of(
    const overlay_change_v9_t& change) noexcept
{
    if (!change.before)
        return std::nullopt;
    if (change.before_kind)
        return change.before_kind;
    const auto inferred = overlay_operation_kind_for_item_v9(change.entity, *change.before);
    return inferred ? inferred : std::optional<overlay_operation_kind_v9_t>(change.operation_kind);
}

std::optional<overlay_operation_kind_v9_t> after_kind_of(
    const overlay_change_v9_t& change) noexcept
{
    if (!change.after)
        return std::nullopt;
    if (change.after_kind)
        return change.after_kind;
    const auto inferred = overlay_operation_kind_for_item_v9(change.entity, *change.after);
    return inferred ? inferred : std::optional<overlay_operation_kind_v9_t>(change.operation_kind);
}

bool change_requires_full_reanalysis(const overlay_change_v9_t& change) noexcept
{
    const auto before_kind = before_kind_of(change);
    const auto after_kind = after_kind_of(change);
    return (before_kind && *before_kind == overlay_operation_kind_v9_t::reanalysis) ||
           (after_kind && *after_kind == overlay_operation_kind_v9_t::reanalysis);
}

bool entity_address_in_bounds(const overlay_entity_key_v9_t& entity,
                              std::uint64_t image_size) noexcept
{
    if (entity.domain == overlay_operation_kind_v9_t::type_declaration ||
        entity.domain == overlay_operation_kind_v9_t::enum_definition)
        return entity.range.offset == 0 && entity.range.size == 0;
    return entity.range.offset < image_size;
}

void bind_invalidation_generation(projection_invalidation_set_t& invalidation,
                                  std::uint64_t generation) noexcept
{
    invalidation.packed_index.source_generation = generation;
    invalidation.packed_index.target_generation = generation;
    invalidation.decompiler_cache.source_generation = generation;
    invalidation.decompiler_cache.target_generation = generation;
}

std::uint64_t saturated_add(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    return rhs > maximum - lhs ? maximum : lhs + rhs;
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

void merge_ranges(std::vector<projected_range_t>& ranges)
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
        last.size = (std::max)(last_end, current_end) - last.offset;
    }
    ranges = std::move(merged);
}

}

reanalysis_result_t incremental_reanalysis_t::compute_scope(
    const std::vector<overlay_change_v9_t>& changes,
    const overlay_static_state_v9_t& state,
    std::uint64_t current_generation)
{
    reanalysis_result_t result;
    if (!state.target.valid() ||
        state.target.kind != overlay_target_kind_v9_t::static_image ||
        state.next_transaction_id == 0 || state.history_epoch == 0 ||
        state.history_cursor > state.history.size()) {
        result.detail = "static overlay state is not initialized or coherent";
        return result;
    }
    if (current_generation != state.target.generation) {
        result.detail = "current_generation does not match state.target.generation";
        return result;
    }
    if (changes.empty()) {
        result.detail = "no changes to compute scope from";
        return result;
    }

    result.invalidation = overlay_projection_t::compute_invalidation(
        changes, state.target.image_size);
    if (!overlay_projection_t::validate_ranges_in_bounds(
            result.invalidation.affected_ranges, state.target.image_size) ||
        !std::all_of(
            result.invalidation.affected_entities.begin(),
            result.invalidation.affected_entities.end(),
            [&](const auto& entity) {
                return entity_address_in_bounds(
                    entity.key, state.target.image_size);
            })) {
        result.detail = "one or more reanalysis ranges or entities exceed image bounds";
        return result;
    }
    bind_invalidation_generation(result.invalidation, current_generation);
    result.scope.generation = current_generation;
    result.scope.ranges = result.invalidation.affected_ranges;
    result.scope.stage_flags = result.invalidation.invalidated_stages;
    result.scope.total_patched_bytes = result.invalidation.total_patched_bytes;
    for (const auto& entity : result.invalidation.affected_entities)
        result.scope.entities.push_back(entity.key);
    result.scope.requires_full_reanalysis = std::any_of(
        changes.begin(), changes.end(), change_requires_full_reanalysis);
    result.ok = true;
    result.new_generation = current_generation;
    return result;
}

reanalysis_scope_t incremental_reanalysis_t::minimal_invalidation(
    const overlay_change_v9_t& change)
{
    const auto invalidation = overlay_projection_t::compute_invalidation({change});
    reanalysis_scope_t scope;
    scope.ranges = invalidation.affected_ranges;
    scope.stage_flags = invalidation.invalidated_stages;
    scope.total_patched_bytes = invalidation.total_patched_bytes;
    for (const auto& entity : invalidation.affected_entities)
        scope.entities.push_back(entity.key);
    scope.requires_full_reanalysis = change_requires_full_reanalysis(change);
    return scope;
}

bool incremental_reanalysis_t::stage_requires_reanalysis(
    reanalysis_stage_t stage,
    overlay_operation_kind_v9_t operation_kind) noexcept
{
    const auto flags = stage_flags_for_operation(operation_kind);
    switch (stage) {
    case reanalysis_stage_t::disassembly:
        return stage_test(flags, projection_stage_flag_t::disassembler);
    case reanalysis_stage_t::basic_blocks:
        return stage_test(flags, projection_stage_flag_t::basic_block_table);
    case reanalysis_stage_t::functions:
        return stage_test(flags, projection_stage_flag_t::function_table);
    case reanalysis_stage_t::decompilation:
        return stage_test(flags, projection_stage_flag_t::decompiler);
    case reanalysis_stage_t::xrefs:
        return stage_test(flags, projection_stage_flag_t::xref_table);
    case reanalysis_stage_t::strings:
        return stage_test(flags, projection_stage_flag_t::string_table);
    case reanalysis_stage_t::types:
        return stage_test(flags, projection_stage_flag_t::type_table);
    case reanalysis_stage_t::symbols:
        return stage_test(flags, projection_stage_flag_t::symbol_table);
    case reanalysis_stage_t::coverage:
        return stage_test(flags, projection_stage_flag_t::coverage_table);
    case reanalysis_stage_t::none:
        return false;
    }
    return false;
}

projection_stage_flag_t incremental_reanalysis_t::stage_flags_for_operation(
    overlay_operation_kind_v9_t kind) noexcept
{
    return overlay_projection_t::stage_flags_for_domain(kind);
}

undo_redo_identity_t incremental_reanalysis_t::validate_undo_redo_identity(
    const overlay_change_v9_t& forward_change,
    const overlay_change_v9_t& inverse_change)
{
    undo_redo_identity_t identity;
    identity.entity = forward_change.entity;
    identity.keys_match = forward_change.entity == inverse_change.entity;
    identity.forward_valid = identity.keys_match &&
        (forward_change.before.has_value() || forward_change.after.has_value());
    identity.inverse_valid = identity.keys_match &&
        (inverse_change.before.has_value() || inverse_change.after.has_value());
    if (!identity.forward_valid || !identity.inverse_valid)
        return identity;

    const bool forward_before_after = forward_change.before.has_value() &&
                                      forward_change.after.has_value();
    const bool inverse_before_after = inverse_change.before.has_value() &&
                                      inverse_change.after.has_value();
    if (forward_before_after && inverse_before_after) {
        identity.payloads_are_inverse =
            (*forward_change.before == *inverse_change.after) &&
            (*forward_change.after == *inverse_change.before);
    } else if (!forward_change.before && forward_change.after &&
               inverse_change.before && !inverse_change.after) {
        identity.payloads_are_inverse =
            *forward_change.after == *inverse_change.before;
    } else if (forward_change.before && !forward_change.after &&
               !inverse_change.before && inverse_change.after) {
        identity.payloads_are_inverse =
            *forward_change.before == *inverse_change.after;
    }

    identity.provenance_is_inverse =
        before_kind_of(forward_change) == after_kind_of(inverse_change) &&
        after_kind_of(forward_change) == before_kind_of(inverse_change);
    return identity;
}

std::vector<reanalysis_stage_t> incremental_reanalysis_t::stages_for_flags(
    projection_stage_flag_t flags)
{
    std::vector<reanalysis_stage_t> stages;
    if (stage_test(flags, projection_stage_flag_t::disassembler))
        stages.push_back(reanalysis_stage_t::disassembly);
    if (stage_test(flags, projection_stage_flag_t::basic_block_table))
        stages.push_back(reanalysis_stage_t::basic_blocks);
    if (stage_test(flags, projection_stage_flag_t::function_table))
        stages.push_back(reanalysis_stage_t::functions);
    if (stage_test(flags, projection_stage_flag_t::decompiler))
        stages.push_back(reanalysis_stage_t::decompilation);
    if (stage_test(flags, projection_stage_flag_t::xref_table))
        stages.push_back(reanalysis_stage_t::xrefs);
    if (stage_test(flags, projection_stage_flag_t::string_table))
        stages.push_back(reanalysis_stage_t::strings);
    if (stage_test(flags, projection_stage_flag_t::type_table))
        stages.push_back(reanalysis_stage_t::types);
    if (stage_test(flags, projection_stage_flag_t::symbol_table))
        stages.push_back(reanalysis_stage_t::symbols);
    if (stage_test(flags, projection_stage_flag_t::coverage_table))
        stages.push_back(reanalysis_stage_t::coverage);
    return stages;
}

bool incremental_reanalysis_t::scope_contains_range(
    const reanalysis_scope_t& scope,
    const projected_range_t& range) noexcept
{
    for (const auto& scope_range : scope.ranges) {
        if (scope_range.size == 0 || range.size == 0) {
            if (scope_range.size == 0 && range.size == 0 &&
                scope_range.offset == range.offset)
                return true;
            continue;
        }
        if (scope_range.offset > range.offset)
            continue;
        const auto offset_delta = range.offset - scope_range.offset;
        if (offset_delta <= scope_range.size &&
            range.size <= scope_range.size - offset_delta)
            return true;
    }
    return false;
}

reanalysis_scope_t incremental_reanalysis_t::merge_scopes(
    const reanalysis_scope_t& lhs,
    const reanalysis_scope_t& rhs)
{
    reanalysis_scope_t merged;
    merged.generation_conflict = lhs.generation_conflict || rhs.generation_conflict ||
        (lhs.generation != 0 && rhs.generation != 0 &&
         lhs.generation != rhs.generation);
    merged.generation = merged.generation_conflict
        ? 0
        : (std::max)(lhs.generation, rhs.generation);
    merged.requires_full_reanalysis = lhs.requires_full_reanalysis ||
                                      rhs.requires_full_reanalysis;
    merged.stage_flags = lhs.stage_flags | rhs.stage_flags;
    merged.ranges = lhs.ranges;
    merged.ranges.insert(merged.ranges.end(), rhs.ranges.begin(), rhs.ranges.end());
    merge_ranges(merged.ranges);
    for (const auto& range : merged.ranges) {
        if (range.is_byte_patch)
            merged.total_patched_bytes = saturated_add(
                merged.total_patched_bytes, range.size);
    }
    merged.entities = lhs.entities;
    merged.entities.insert(merged.entities.end(), rhs.entities.begin(), rhs.entities.end());
    std::sort(merged.entities.begin(), merged.entities.end());
    merged.entities.erase(
        std::unique(merged.entities.begin(), merged.entities.end()),
        merged.entities.end());
    if (merged.requires_full_reanalysis) {
        merged.stage_flags = projection_stage_flag_t::all_stages;
        merged.total_patched_bytes = 0;
    }
    return merged;
}

}
}
