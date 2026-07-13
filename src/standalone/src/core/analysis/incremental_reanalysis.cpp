#include "incremental_reanalysis.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace aida {
namespace analysis {

namespace {

bool is_byte_patch_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::byte_patch ||
           kind == overlay_operation_kind_v9_t::assembly_patch ||
           kind == overlay_operation_kind_v9_t::integer_patch;
}

bool is_metadata_only_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::comment ||
           kind == overlay_operation_kind_v9_t::comment_update ||
           kind == overlay_operation_kind_v9_t::bookmark;
}

bool is_define_kind(overlay_operation_kind_v9_t kind) noexcept
{
    return kind == overlay_operation_kind_v9_t::define_function ||
           kind == overlay_operation_kind_v9_t::define_code ||
           kind == overlay_operation_kind_v9_t::define_data;
}

bool ranges_overlap(std::uint64_t a_offset, std::uint64_t a_size,
                    std::uint64_t b_offset, std::uint64_t b_size) noexcept
{
    if (a_size == 0 || b_size == 0)
        return false;
    return a_offset < b_offset + b_size && b_offset < a_offset + a_size;
}

std::uint64_t range_end(const projected_range_t& range) noexcept
{
    return range.offset + range.size;
}

}

reanalysis_result_t incremental_reanalysis_t::compute_scope(
    const std::vector<overlay_change_v9_t>& changes,
    const overlay_static_state_v9_t& state,
    std::uint64_t current_generation)
{
    reanalysis_result_t result;
    if (!state.target.valid()) {
        result.detail = "state target is not valid";
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
    result.scope = reanalysis_scope_t{};
    result.scope.generation = current_generation;
    result.scope.ranges = overlay_projection_t::derive_affected_ranges(changes);
    result.scope.stage_flags = overlay_projection_t::derive_invalidated_stages(changes);
    result.scope.requires_full_reanalysis = false;
    result.scope.total_patched_bytes = 0;
    for (const auto& change : changes) {
        result.scope.entities.push_back(change.entity);
        if (change.operation_kind == overlay_operation_kind_v9_t::reanalysis) {
            result.scope.requires_full_reanalysis = true;
            result.scope.stage_flags = projection_stage_flag_t::all_stages;
        }
        if (is_byte_patch_kind(change.operation_kind)) {
            if (change.after)
                result.scope.total_patched_bytes += change.after->bytes.size();
            else if (change.before)
                result.scope.total_patched_bytes += change.before->bytes.size();
        }
    }
    if (result.scope.requires_full_reanalysis) {
        result.scope.ranges.clear();
        projected_range_t full_range;
        full_range.offset = 0;
        full_range.size = state.target.image_size;
        full_range.is_byte_patch = true;
        full_range.source_kind = overlay_operation_kind_v9_t::reanalysis;
        result.scope.ranges.push_back(full_range);
    }
    result.ok = true;
    result.new_generation = current_generation;
    return result;
}

reanalysis_scope_t incremental_reanalysis_t::minimal_invalidation(
    const overlay_change_v9_t& change)
{
    reanalysis_scope_t scope;
    scope.generation = 0;
    scope.stage_flags = stage_flags_for_operation(change.operation_kind);
    scope.requires_full_reanalysis =
        change.operation_kind == overlay_operation_kind_v9_t::reanalysis;
    scope.entities.push_back(change.entity);
    auto ranges = overlay_projection_t::derive_affected_ranges({change});
    scope.ranges = std::move(ranges);
    if (is_byte_patch_kind(change.operation_kind)) {
        if (change.after)
            scope.total_patched_bytes = change.after->bytes.size();
        else if (change.before)
            scope.total_patched_bytes = change.before->bytes.size();
    }
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
    identity.forward_valid = (forward_change.entity == inverse_change.entity);
    identity.keys_match = identity.forward_valid;
    if (!identity.keys_match) {
        identity.inverse_valid = false;
        identity.payloads_are_inverse = false;
        return identity;
    }
    identity.forward_valid = true;
    identity.inverse_valid = true;
    const bool forward_before_after = forward_change.before.has_value() &&
                                      forward_change.after.has_value();
    const bool inverse_before_after = inverse_change.before.has_value() &&
                                      inverse_change.after.has_value();
    if (forward_before_after && inverse_before_after) {
        identity.payloads_are_inverse =
            (*forward_change.before == *inverse_change.after) &&
            (*forward_change.after == *inverse_change.before);
    } else if (!forward_change.before.has_value() && forward_change.after.has_value() &&
               inverse_change.before.has_value() && !inverse_change.after.has_value()) {
        identity.payloads_are_inverse =
            (*forward_change.after == *inverse_change.before);
    } else if (forward_change.before.has_value() && !forward_change.after.has_value() &&
               !inverse_change.before.has_value() && inverse_change.after.has_value()) {
        identity.payloads_are_inverse =
            (*forward_change.before == *inverse_change.after);
    } else {
        identity.payloads_are_inverse = false;
    }
    return identity;
}

cache_invalidation_check_t incremental_reanalysis_t::check_cache_invalidation(
    const reanalysis_scope_t& scope,
    const overlay_static_state_v9_t& state)
{
    cache_invalidation_check_t check;
    check.cache_invalidated = false;
    check.invalidated_entry_count = 0;
    check.invalidated_stages = scope.stage_flags;
    if (scope.empty())
        return check;
    if (scope.requires_full_reanalysis) {
        check.cache_invalidated = true;
        check.invalidated_entry_count = state.items.size();
        check.invalidated_ranges = scope.ranges;
        check.invalidated_stages = projection_stage_flag_t::all_stages;
        return check;
    }
    std::size_t invalidated = 0;
    for (const auto& [key, payload] : state.items) {
        for (const auto& range : scope.ranges) {
            if (range.size == 0) {
                if (key.range.offset == range.offset) {
                    ++invalidated;
                    break;
                }
                continue;
            }
            if (ranges_overlap(key.range.offset, key.range.size > 0 ? key.range.size : 1,
                               range.offset, range.size)) {
                ++invalidated;
                break;
            }
        }
    }
    check.invalidated_entry_count = invalidated;
    check.cache_invalidated = invalidated > 0 || scope.stage_flags != projection_stage_flag_t::none;
    check.invalidated_ranges = scope.ranges;
    return check;
}

reanalysis_result_t incremental_reanalysis_t::publish_reanalysis(
    overlay_static_state_v9_t& state,
    std::uint64_t expected_generation,
    const reanalysis_scope_t& scope)
{
    reanalysis_result_t result;
    if (!state.target.valid()) {
        result.detail = "state target is not valid";
        return result;
    }
    if (expected_generation != state.target.generation) {
        result.detail = "expected_generation does not match state.target.generation";
        return result;
    }
    if (state.target.generation == (std::numeric_limits<std::uint64_t>::max)()) {
        result.detail = "generation at maximum, cannot publish";
        return result;
    }
    state.target.generation += 1;
    result.ok = true;
    result.scope = scope;
    result.scope.generation = state.target.generation;
    result.new_generation = state.target.generation;
    return result;
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
        if (scope_range.size == 0 && range.size == 0)
            return scope_range.offset == range.offset;
        if (scope_range.size == 0 || range.size == 0)
            continue;
        if (scope_range.offset <= range.offset &&
            scope_range.offset + scope_range.size >= range.offset + range.size)
            return true;
    }
    return false;
}

reanalysis_scope_t incremental_reanalysis_t::merge_scopes(
    const reanalysis_scope_t& lhs,
    const reanalysis_scope_t& rhs)
{
    reanalysis_scope_t merged;
    merged.generation = std::max(lhs.generation, rhs.generation);
    merged.requires_full_reanalysis = lhs.requires_full_reanalysis ||
                                      rhs.requires_full_reanalysis;
    merged.stage_flags = static_cast<projection_stage_flag_t>(
        static_cast<std::uint32_t>(lhs.stage_flags) |
        static_cast<std::uint32_t>(rhs.stage_flags));
    merged.total_patched_bytes = lhs.total_patched_bytes + rhs.total_patched_bytes;
    merged.ranges = lhs.ranges;
    for (const auto& range : rhs.ranges)
        merged.ranges.push_back(range);
    if (merged.ranges.size() > 1) {
        std::sort(merged.ranges.begin(), merged.ranges.end(),
                  [](const auto& a, const auto& b) {
                      return a.offset < b.offset;
                  });
    }
    merged.entities = lhs.entities;
    for (const auto& entity : rhs.entities)
        merged.entities.push_back(entity);
    if (merged.requires_full_reanalysis) {
        merged.stage_flags = projection_stage_flag_t::all_stages;
        merged.ranges.clear();
        merged.total_patched_bytes = 0;
    }
    return merged;
}

}
}
