#include "incremental_reanalysis.hpp"

#include "workspace/analysis_workspace.hpp"
#include "workspace/analysis_metrics.hpp"
#include "workspace/decompiler_service.hpp"
#include "workspace/byte_provider.hpp"
#include "workspace/compact_ir.hpp"
#include "workspace/data_discovery.hpp"
#include "workspace/function_recovery.hpp"
#include "workspace/pe_baseline_analyzer.hpp"
#include "provider_snapshot.hpp"
#include "workspace/search_index.hpp"
#include "workspace/string_discovery.hpp"
#include "workspace/symbol_type_candidates.hpp"
#include "workspace/workspace_types.hpp"
#include "workspace/xref_builder.hpp"
#include "workspace/arch_decoder.hpp"
#include "call_graph_builder.hpp"
#include "image_layout_index.hpp"
#include "tile_decode_orchestrator.hpp"

#include "../infra/taskflow_runtime.hpp"

#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <set>
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

overlay_operation_kind_v9_t canonical_entity_domain(
    overlay_operation_kind_v9_t kind) noexcept
{
    if (kind == overlay_operation_kind_v9_t::comment_update)
        return overlay_operation_kind_v9_t::comment;
    if (kind == overlay_operation_kind_v9_t::type_update)
        return overlay_operation_kind_v9_t::type_application;
    return kind;
}

bool managed_change_is_valid(const overlay_change_v9_t& change) noexcept
{
    if (change.entity.target_discriminator !=
        overlay_target_discriminator_v9_t::managed_entity)
        return true;
    if (!managed_overlay_operation_kind_v9(change.operation_kind) ||
        canonical_entity_domain(change.operation_kind) !=
            change.entity.domain ||
        (!change.before && !change.after))
        return false;
    const auto valid_side = [&](const std::optional<overlay_payload_v9_t>& payload,
                                const std::optional<overlay_operation_kind_v9_t>&
                                    kind) noexcept {
        if (!payload)
            return !kind;
        const auto inferred = overlay_operation_kind_for_item_v9(
            change.entity, *payload);
        return inferred &&
            (!kind ||
             (managed_overlay_operation_kind_v9(*kind) &&
              canonical_entity_domain(*kind) == change.entity.domain));
    };
    return valid_side(change.before, change.before_kind) &&
        valid_side(change.after, change.after_kind);
}

bool entity_address_in_bounds(const overlay_entity_key_v9_t& entity,
                              std::uint64_t image_size,
                              std::uint64_t generation,
                              const std::array<std::uint8_t, 32>&
                                  provider_hash) noexcept
{
    if (entity.target_discriminator ==
        overlay_target_discriminator_v9_t::managed_entity)
        return entity.managed_locator && entity.managed_locator->valid() &&
            entity.managed_locator->provider_hash == provider_hash &&
            entity.managed_locator->generation <= generation &&
            entity.range.offset == 0 && entity.range.size == 0;
    if (entity.target_discriminator !=
            overlay_target_discriminator_v9_t::native_address ||
        entity.managed_locator)
        return false;
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
    if (!std::all_of(changes.begin(), changes.end(),
                     managed_change_is_valid)) {
        result.detail = "managed reanalysis change identity or payload is invalid";
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
                    entity.key, state.target.image_size,
                    state.target.generation, state.target.image_hash);
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
    if (!managed_change_is_valid(change))
        return {};
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

namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;

std::optional<std::uint64_t> rva_of(const address_t& address,
                                    const workspace_image_t& image) noexcept {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value < image.image_size
            ? std::optional<std::uint64_t>(address.value)
            : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva < image.image_size ? std::optional<std::uint64_t>(rva)
                                      : std::nullopt;
    }
    return std::nullopt;
}

bool rva_overlaps_ranges(std::uint64_t rva, std::uint64_t size,
                         const std::vector<projected_range_t>& ranges) noexcept {
    if (size == 0)
        return false;
    for (const auto& range : ranges) {
        if (range.size == 0)
            continue;
        const auto range_end = range.offset + range.size;
        const auto rva_end = rva + size;
        if (rva < range_end && range.offset < rva_end)
            return true;
    }
    return false;
}

bool managed_bytecode_only_image(const workspace_image_t& image) noexcept {
    const auto jvm = image.format == format_id_t::classfile &&
        image.architecture == architecture_id_t::jvm_bytecode &&
        image.architecture_mode == architecture_mode_t::jvm &&
        image.abi == abi_id_t::jvm;
    const auto dalvik_format = image.format == format_id_t::dex ||
        image.format == format_id_t::oat || image.format == format_id_t::vdex;
    const auto dalvik = dalvik_format &&
        image.architecture == architecture_id_t::dalvik_bytecode &&
        image.architecture_mode == architecture_mode_t::dalvik &&
        image.abi == abi_id_t::dalvik;
    return jvm || dalvik;
}

struct merged_instruction_set_t {
    std::vector<instruction_record_t> instructions;
    std::vector<operand_fact_t> operand_facts;
    std::vector<target_fact_t> target_facts;
    std::vector<std::uint8_t> delay_slot_counts;
};

bool merge_instruction_sets(
    const workspace_image_t& image,
    const std::vector<projected_range_t>& ranges,
    const std::vector<instruction_record_t>& retained_instructions,
    const std::vector<operand_fact_t>& retained_operands,
    const std::vector<target_fact_t>& retained_targets,
    const std::vector<std::uint8_t>& retained_delay_slots,
    std::vector<instruction_record_t> new_instructions,
    std::vector<operand_fact_t> new_operands,
    std::vector<target_fact_t> new_targets,
    std::vector<std::uint8_t> new_delay_slots,
    merged_instruction_set_t& merged) {
    std::map<entity_id_t, entity_id_t> old_to_new_ids;
    merged.instructions.clear();
    merged.operand_facts.clear();
    merged.target_facts.clear();
    merged.delay_slot_counts.clear();

    for (const auto& instruction : retained_instructions) {
        const auto rva = rva_of(instruction.address, image);
        if (rva && rva_overlaps_ranges(*rva, instruction.length, ranges))
            continue;
        merged.instructions.push_back(instruction);
    }

    for (const auto& instruction : new_instructions) {
        const auto rva = rva_of(instruction.address, image);
        if (!rva || !rva_overlaps_ranges(*rva, instruction.length, ranges))
            continue;
        merged.instructions.push_back(instruction);
    }

    std::sort(merged.instructions.begin(), merged.instructions.end(),
        [&](const auto& lhs, const auto& rhs) {
            const auto lhs_rva = rva_of(lhs.address, image);
            const auto rhs_rva = rva_of(rhs.address, image);
            if (lhs_rva && rhs_rva && lhs_rva != rhs_rva)
                return *lhs_rva < *rhs_rva;
            if (lhs_rva && !rhs_rva)
                return true;
            if (!lhs_rva && rhs_rva)
                return false;
            return lhs.id < rhs.id;
        });

    merged.instructions.erase(
        std::unique(merged.instructions.begin(), merged.instructions.end(),
            [&](const auto& lhs, const auto& rhs) {
                const auto lhs_rva = rva_of(lhs.address, image);
                const auto rhs_rva = rva_of(rhs.address, image);
                return lhs_rva && rhs_rva && *lhs_rva == *rhs_rva;
            }),
        merged.instructions.end());

    merged.operand_facts.reserve(retained_operands.size() + new_operands.size());
    merged.target_facts.reserve(retained_targets.size() + new_targets.size());

    std::set<entity_id_t> retained_ids;
    for (const auto& instruction : merged.instructions) {
        const auto rva = rva_of(instruction.address, image);
        if (rva && rva_overlaps_ranges(*rva, instruction.length, ranges))
            continue;
        retained_ids.insert(instruction.id);
    }

    for (const auto& operand : retained_operands) {
        if (retained_ids.find(operand.instruction_id) == retained_ids.end())
            continue;
        merged.operand_facts.push_back(operand);
    }
    for (const auto& target : retained_targets) {
        if (retained_ids.find(target.instruction_id) == retained_ids.end())
            continue;
        merged.target_facts.push_back(target);
    }

    std::set<entity_id_t> new_ids;
    for (const auto& instruction : merged.instructions) {
        const auto rva = rva_of(instruction.address, image);
        if (!rva || !rva_overlaps_ranges(*rva, instruction.length, ranges))
            continue;
        new_ids.insert(instruction.id);
    }

    for (const auto& operand : new_operands) {
        if (new_ids.find(operand.instruction_id) == new_ids.end())
            continue;
        merged.operand_facts.push_back(operand);
    }
    for (const auto& target : new_targets) {
        if (new_ids.find(target.instruction_id) == new_ids.end())
            continue;
        merged.target_facts.push_back(target);
    }

    for (std::size_t index = 0; index < merged.instructions.size(); ++index) {
        const auto new_id = kInstructionEntityTag |
            static_cast<std::uint64_t>(index + 1);
        old_to_new_ids[merged.instructions[index].id] = new_id;
        merged.instructions[index].id = new_id;
    }

    for (auto& operand : merged.operand_facts) {
        const auto found = old_to_new_ids.find(operand.instruction_id);
        if (found == old_to_new_ids.end())
            return false;
        operand.instruction_id = found->second;
    }
    for (auto& target : merged.target_facts) {
        const auto found = old_to_new_ids.find(target.instruction_id);
        if (found == old_to_new_ids.end())
            return false;
        target.instruction_id = found->second;
    }

    std::sort(merged.operand_facts.begin(), merged.operand_facts.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.instruction_id < rhs.instruction_id;
        });
    std::sort(merged.target_facts.begin(), merged.target_facts.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.instruction_id < rhs.instruction_id;
        });

    std::size_t operand_index = 0;
    for (auto& instruction : merged.instructions) {
        const auto begin = operand_index;
        while (operand_index < merged.operand_facts.size() &&
               merged.operand_facts[operand_index].instruction_id == instruction.id)
            ++operand_index;
        instruction.operand_fact_begin = static_cast<std::uint32_t>(begin);
        instruction.operand_fact_count = static_cast<std::uint16_t>(
            operand_index - begin);
    }

    std::size_t target_index = 0;
    for (auto& instruction : merged.instructions) {
        const auto begin = target_index;
        while (target_index < merged.target_facts.size() &&
               merged.target_facts[target_index].instruction_id == instruction.id)
            ++target_index;
        instruction.target_fact_begin = static_cast<std::uint32_t>(begin);
        instruction.target_fact_count = static_cast<std::uint16_t>(
            target_index - begin);
    }

    merged.delay_slot_counts.reserve(merged.instructions.size());
    for (const auto& instruction : merged.instructions) {
        const auto rva = rva_of(instruction.address, image);
        bool in_range = rva && rva_overlaps_ranges(*rva, instruction.length, ranges);
        if (in_range) {
            for (std::size_t i = 0; i < new_delay_slots.size() && i < new_instructions.size(); ++i) {
                if (new_instructions[i].id == instruction.id) {
                    merged.delay_slot_counts.push_back(new_delay_slots[i]);
                    in_range = true;
                    break;
                }
                in_range = false;
            }
            if (!in_range)
                merged.delay_slot_counts.push_back(0);
        } else {
            for (std::size_t i = 0; i < retained_delay_slots.size() && i < retained_instructions.size(); ++i) {
                if (retained_instructions[i].id == instruction.id) {
                    merged.delay_slot_counts.push_back(retained_delay_slots[i]);
                    in_range = true;
                    break;
                }
                in_range = false;
            }
            if (!in_range)
                merged.delay_slot_counts.push_back(0);
        }
    }

    return merged.delay_slot_counts.size() == merged.instructions.size();
}

bool merge_coverage_spans(
    const workspace_image_t& image,
    const std::vector<projected_range_t>& ranges,
    const std::vector<coverage_span_t>& retained_coverage,
    std::vector<coverage_span_t> new_coverage,
    std::vector<coverage_span_t>& merged) {
    merged.clear();
    merged.reserve(retained_coverage.size() + new_coverage.size());

    for (const auto& span : retained_coverage) {
        const auto rva = rva_of(span.start, image);
        if (rva && rva_overlaps_ranges(*rva, span.size, ranges))
            continue;
        merged.push_back(span);
    }

    for (auto& span : new_coverage) {
        const auto rva = rva_of(span.start, image);
        if (!rva || !rva_overlaps_ranges(*rva, span.size, ranges))
            continue;
        merged.push_back(std::move(span));
    }

    std::sort(merged.begin(), merged.end(),
        [](const auto& lhs, const auto& rhs) {
            return std::tie(lhs.start, lhs.size, lhs.reason) <
                   std::tie(rhs.start, rhs.size, rhs.reason);
        });
    return true;
}

workspace_result_t<image_layout_index_t> build_layout_index(
    const workspace_image_t& image, const provider_snapshot_t& provider,
    const cancellation_token_t& cancel) {
    image_layout_definition_t definition;
    definition.identity.content_id = image.workspace_binary_id;
    definition.identity.format = image.format;
    definition.identity.endian = image.endian;
    definition.identity.address_width_bits = image.address_width_bits;
    definition.identity.image_base = image.image_base;
    definition.identity.provider_size = provider.size();
    definition.identity.member = image.member;
    if (image.member) {
        definition.members.push_back({0U, image.member->normalized_member_path,
            0U, provider.size()});
    }
    std::uint32_t mapping_id = 0;
    for (const auto& section : image.sections) {
        const auto virtual_size = (std::max)(section.virtual_size, section.file_size);
        if (virtual_size == 0)
            continue;
        image_layout_mapping_t mapping;
        mapping.id = mapping_id++;
        mapping.rva = section.virtual_address;
        mapping.virtual_address = image.image_base + section.virtual_address;
        mapping.virtual_size = virtual_size;
        mapping.file_offset = section.file_offset;
        mapping.file_size = section.file_size;
        mapping.permissions = section.permissions;
        mapping.section_id = section.index;
        definition.sections.push_back({section.index, section.name,
            section.virtual_address, virtual_size, section.file_offset,
            section.file_size, section.permissions});
        if (image.member)
            mapping.member_id = 0U;
        definition.mappings.push_back(std::move(mapping));
    }
    for (const auto& segment : image.segments) {
        const auto virtual_size = (std::max)(segment.virtual_size, segment.file_size);
        if (virtual_size == 0)
            continue;
        image_layout_mapping_t mapping;
        mapping.id = mapping_id++;
        mapping.rva = segment.virtual_address;
        mapping.virtual_address = image.image_base + segment.virtual_address;
        mapping.virtual_size = virtual_size;
        mapping.file_offset = segment.file_offset;
        mapping.file_size = segment.file_size;
        mapping.permissions = segment.permissions;
        mapping.segment_id = segment.index;
        definition.segments.push_back({segment.index, segment.name,
            segment.virtual_address, virtual_size, segment.file_offset,
            segment.file_size, segment.permissions});
        if (image.member)
            mapping.member_id = 0U;
        definition.mappings.push_back(std::move(mapping));
    }
    if (definition.mappings.empty())
        return workspace_result_t<image_layout_index_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "image layout has no valid mappings", "incremental_reanalysis"));
    if (cancel.stop_requested())
        return workspace_result_t<image_layout_index_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                "incremental reanalysis cancelled during layout build",
                "incremental_reanalysis"));
    return image_layout_index_t::build(std::move(definition));
}

std::vector<tile_decode_seed_t> collect_scoped_seeds(
    const workspace_image_t& image,
    const std::vector<function_record_t>& functions,
    const std::vector<projected_range_t>& ranges) {
    std::vector<tile_decode_seed_t> seeds;
    for (const auto& function : functions) {
        const auto rva = rva_of(function.start, image);
        if (rva && rva_overlaps_ranges(*rva, 1, ranges)) {
            tile_decode_seed_t seed;
            seed.address = function.start;
            seed.provenance = function.provenance;
            seed.confidence = function.confidence;
            seeds.push_back(seed);
        }
    }
    for (const auto& range : ranges) {
        if (range.size == 0)
            continue;
        tile_decode_seed_t seed;
        seed.address.space = address_space_id_t::relative_virtual;
        seed.address.value = range.offset;
        seed.address.architecture = image.architecture;
        seed.address.mode = image.architecture_mode;
        seed.provenance = fact_provenance_t::recursive_decode;
        seed.confidence = 50;
        seeds.push_back(seed);
    }
    return seeds;
}

workspace_result_t<void> recompute_snapshot_ledger(
    analysis_snapshot_t& snapshot, const cancellation_token_t& cancel) {
    std::uint64_t visits = 0;
    const auto poll = [&]() -> workspace_result_t<void> {
        if ((visits++ & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::cancelled,
                "incremental reanalysis cancelled during ledger recompute",
                "incremental_reanalysis"));
        return workspace_result_t<void>::success();
    };
    const auto overflow = [] {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "analysis memory accounting overflows", "memory_budget"));
    };
    std::uint64_t string_value_bytes = 0;
    for (const auto& string : snapshot.strings) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t updated = 0;
        if (!checked_add_u64(string_value_bytes,
                static_cast<std::uint64_t>(string.value.capacity()), updated))
            return overflow();
        string_value_bytes = updated;
    }
    std::uint64_t symbol_name_bytes = 0;
    for (const auto& symbol : snapshot.symbols) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t updated = 0;
        if (!checked_add_u64(symbol_name_bytes,
                static_cast<std::uint64_t>(symbol.name.capacity()), updated))
            return overflow();
        symbol_name_bytes = updated;
    }
    std::uint64_t function_chunk_bytes = 0;
    for (const auto& function : snapshot.functions) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(
                static_cast<std::uint64_t>(function.chunks.capacity()),
                static_cast<std::uint64_t>(sizeof(address_range_t)), bytes) ||
            !checked_add_u64(function_chunk_bytes, bytes, updated))
            return overflow();
        function_chunk_bytes = updated;
    }
    std::uint64_t type_candidate_text_bytes = 0;
    for (const auto& candidate : snapshot.rich_facts.type_candidates) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t updated = 0;
        if (!checked_add_u64(type_candidate_text_bytes,
                static_cast<std::uint64_t>(candidate.display_name.capacity() +
                    candidate.canonical_type.capacity() +
                    candidate.source_key.capacity()), updated))
            return overflow();
        type_candidate_text_bytes = updated;
    }
    std::uint64_t type_reference_key_bytes = 0;
    for (const auto& reference : snapshot.rich_facts.type_references) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t updated = 0;
        if (!checked_add_u64(type_reference_key_bytes,
                static_cast<std::uint64_t>(reference.source_key.capacity()), updated))
            return overflow();
        type_reference_key_bytes = updated;
    }
    std::uint64_t metadata_conflict_text_bytes = 0;
    for (const auto& conflict : snapshot.rich_facts.metadata_conflicts) {
        auto active = poll();
        if (!active)
            return active;
        std::uint64_t updated = 0;
        if (!checked_add_u64(metadata_conflict_text_bytes,
                static_cast<std::uint64_t>(conflict.identity.capacity() +
                    conflict.selected_value.capacity() +
                    conflict.rejected_value.capacity()), updated))
            return overflow();
        metadata_conflict_text_bytes = updated;
    }
    snapshot.string_value_bytes = string_value_bytes;
    snapshot.symbol_name_bytes = symbol_name_bytes;
    snapshot.function_chunk_bytes = function_chunk_bytes;
    snapshot.type_candidate_text_bytes = type_candidate_text_bytes;
    snapshot.type_reference_key_bytes = type_reference_key_bytes;
    snapshot.metadata_conflict_text_bytes = metadata_conflict_text_bytes;
    return workspace_result_t<void>::success();
}

}

incremental_reanalysis_executor_result_t
incremental_reanalysis_executor_t::execute(
    std::shared_ptr<analysis_workspace_t> workspace,
    const reanalysis_scope_t& scope,
    const projection_invalidation_set_t& invalidation,
    std::shared_ptr<const byte_provider_t> projected_provider,
    incremental_reanalysis_executor_settings_t settings,
    const cancellation_token_t& cancel) {
    incremental_reanalysis_executor_result_t result;
    result.metrics = std::make_shared<analysis_metrics_t>(scope.generation);

    if (!workspace || !projected_provider) {
        result.detail = "incremental reanalysis requires a workspace and projected provider";
        return result;
    }
    if (scope.requires_full_reanalysis || scope.generation_conflict) {
        result.fallback_to_full = true;
        result.ok = true;
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=%s generation=%llu",
            scope.requires_full_reanalysis ? "full_required" : "generation_conflict",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }
    if (scope.stage_flags == projection_stage_flag_t::none) {
        result.ok = true;
        result.detail = "no stages invalidated";
        return result;
    }
    if (cancel.stop_requested()) {
        result.detail = "cancelled before execution";
        return result;
    }

    const auto publication = workspace->analysis_publication();
    if (!publication || !publication->snapshot || !publication->provider) {
        result.detail = "workspace publication is unavailable";
        return result;
    }
    const auto source_snapshot = publication->snapshot;
    if (!source_snapshot->normalized_image) {
        result.detail = "workspace snapshot has no normalized image";
        return result;
    }
    const auto& image = *source_snapshot->normalized_image;
    const bool code_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::disassembler) ||
        stage_test(scope.stage_flags, projection_stage_flag_t::basic_block_table) ||
        stage_test(scope.stage_flags, projection_stage_flag_t::function_table);
    const bool metadata_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::type_table) ||
        stage_test(scope.stage_flags, projection_stage_flag_t::symbol_table);
    const bool decompiler_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::decompiler);
    const bool xref_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::xref_table);
    const bool coverage_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::coverage_table);
    const bool strings_invalidated =
        stage_test(scope.stage_flags, projection_stage_flag_t::string_table);

    if (code_invalidated && managed_bytecode_only_image(image)) {
        result.fallback_to_full = true;
        result.ok = true;
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=managed_bytecode generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto merged = std::make_shared<analysis_snapshot_t>();
    merged->binary_id = source_snapshot->binary_id;
    merged->load_profile_hash = source_snapshot->load_profile_hash;
    merged->generation = scope.generation;
    merged->analysis_revision = source_snapshot->analysis_revision + 1;
    merged->overlay_revision = source_snapshot->overlay_revision;
    merged->baseline_complete = source_snapshot->baseline_complete;
    merged->normalized_image = source_snapshot->normalized_image;
    merged->image = source_snapshot->image;

    if (!code_invalidated) {
        merged->instructions = source_snapshot->instructions;
        merged->operand_facts = source_snapshot->operand_facts;
        merged->target_facts = source_snapshot->target_facts;
        merged->delay_slot_counts = source_snapshot->delay_slot_counts;
        merged->blocks = source_snapshot->blocks;
        merged->functions = source_snapshot->functions;
        merged->function_chunks = source_snapshot->function_chunks;
        merged->function_block_memberships = source_snapshot->function_block_memberships;
        merged->edges = source_snapshot->edges;
        merged->call_graph = source_snapshot->call_graph;
        merged->coverage = source_snapshot->coverage;
        merged->strings = source_snapshot->strings;

        if (decompiler_invalidated) {
            auto decompiler = workspace->decompiler();
            if (decompiler) {
                for (const auto& function : source_snapshot->functions) {
                    if (cancel.stop_requested())
                        break;
                    const auto rva = rva_of(function.start, image);
                    if (!rva || !rva_overlaps_ranges(*rva, 1, scope.ranges))
                        continue;
                    (void)decompiler->invalidate(function.start, cancel);
                }
            }
            ::diag::log_tagged_fmt("incremental",
                "stage=decompiler invalidated affected_functions generation=%llu",
                static_cast<unsigned long long>(scope.generation));
        }

        if (metadata_invalidated) {
            auto limits = settings.baseline_settings.symbol_type_limits;
            limits.cancellation_check_interval = (std::min)(
                limits.cancellation_check_interval,
                settings.baseline_settings.cancellation_check_interval);
            symbol_type_metadata_sources_t metadata;
            auto built = symbol_type_candidate_builder_t::build(
                image, merged->functions,
                source_snapshot->rich_facts.data_candidates,
                metadata, limits, cancel);
            if (!built) {
                result.fallback_to_full = true;
                result.ok = true;
                result.detail = "metadata rebuild failed: " + built.error().message;
                ::diag::log_tagged_fmt("incremental",
                    "stage=metadata fallback reason=rebuild_failed generation=%llu",
                    static_cast<unsigned long long>(scope.generation));
                return result;
            }
            auto symbol_result = built.take_value();
            merged->symbols = std::move(symbol_result.symbols);
            merged->rich_facts.type_candidates = std::move(symbol_result.type_candidates);
            merged->rich_facts.type_references = std::move(symbol_result.type_references);
            merged->rich_facts.metadata_conflicts = std::move(symbol_result.conflicts);
            for (auto& function : merged->functions) {
                const auto found = std::find_if(
                    merged->symbols.begin(), merged->symbols.end(),
                    [&function](const symbol_record_t& symbol) {
                        return symbol.address == function.start &&
                            symbol.kind == symbol_kind_t::function;
                    });
                if (found != merged->symbols.end())
                    function.symbol_id = found->id;
            }
            ::diag::log_tagged_fmt("incremental",
                "stage=metadata symbols=%zu types=%zu generation=%llu",
                merged->symbols.size(),
                merged->rich_facts.type_candidates.size(),
                static_cast<unsigned long long>(scope.generation));
        }

        if (coverage_invalidated && !source_snapshot->instructions.empty()) {
            merged->coverage.clear();
            for (const auto& span : source_snapshot->coverage) {
                const auto rva = rva_of(span.start, image);
                if (rva && rva_overlaps_ranges(*rva, span.size, scope.ranges))
                    continue;
                merged->coverage.push_back(span);
            }
            for (const auto& range : scope.ranges) {
                if (range.size == 0)
                    continue;
                coverage_span_t pending;
                pending.start.space = address_space_id_t::relative_virtual;
                pending.start.value = range.offset;
                pending.start.architecture = image.architecture;
                pending.start.mode = image.architecture_mode;
                pending.size = range.size;
                pending.reason = coverage_reason_t::pending;
                merged->coverage.push_back(std::move(pending));
            }
            std::sort(merged->coverage.begin(), merged->coverage.end(),
                [](const auto& lhs, const auto& rhs) {
                    return std::tie(lhs.start, lhs.size, lhs.reason) <
                           std::tie(rhs.start, rhs.size, rhs.reason);
                });
            ::diag::log_tagged_fmt("incremental",
                "stage=coverage spans=%zu generation=%llu",
                merged->coverage.size(),
                static_cast<unsigned long long>(scope.generation));
        }

        auto ledger = recompute_snapshot_ledger(*merged, cancel);
        if (!ledger) {
            result.detail = ledger.error().message;
            return result;
        }
        result.ok = true;
        result.merged_snapshot = std::const_pointer_cast<
            const analysis_snapshot_t>(merged);
        ::diag::log_tagged_fmt("incremental",
            "execute ok path=metadata_only generation=%llu analysis_revision=%llu",
            static_cast<unsigned long long>(scope.generation),
            static_cast<unsigned long long>(merged->analysis_revision));
        return result;
    }

    const auto start_time = std::chrono::steady_clock::now();

    auto provider_snapshot = provider_snapshot_t::capture(
        projected_provider, scope.generation, cancel);
    if (!provider_snapshot) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "provider snapshot capture failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=snapshot_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto layout = build_layout_index(image, *provider_snapshot.value(), cancel);
    if (!layout) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "layout index build failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=layout_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto decoder_key = make_arch_decoder_key(image);
    auto registration = default_arch_decoder_registry().resolve(decoder_key);
    if (!registration) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "decoder registration failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=decoder_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto orchestrator = tile_decode_orchestrator_t::create(
        settings.baseline_settings.tile_decode_limits);
    if (!orchestrator) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "tile decode orchestrator creation failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=orchestrator_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    namespace taskflow = aida::infra::taskflow_runtime;
    std::uint32_t fabric_lane_lease = 2;
    const auto fabric_stats = taskflow::domain_stats(
        taskflow::executor_domain_t::feature_worker);
    if (fabric_stats.pool_size > 0) {
        fabric_lane_lease =
            static_cast<std::uint32_t>(fabric_stats.pool_size);
    }
    const auto decode_lanes =
        (std::min)(8U, (std::max)(2U, fabric_lane_lease / 4U));

    production_tile_decode_executor_options_t executor_options;
    executor_options.decoder_key = decoder_key;
    executor_options.worker_count = decode_lanes;
    executor_options.analysis_budget.max_queued_tasks = 4096;
    executor_options.analysis_budget.max_worker_slots = decode_lanes + 1;
    executor_options.analysis_budget.reserved_control_worker_slots = 1;
    executor_options.analysis_budget.max_private_bytes =
        settings.baseline_settings.max_analysis_memory_bytes;
    executor_options.analysis_budget.max_mapped_window_bytes =
        settings.baseline_settings.max_analysis_memory_bytes;
    executor_options.analysis_budget.max_spill_bytes =
        settings.baseline_settings.max_analysis_memory_bytes;
    executor_options.analysis_budget.max_cache_bytes =
        settings.baseline_settings.max_analysis_memory_bytes;
    executor_options.x86_limits.maximum_window_bytes = (std::min)(
        settings.baseline_settings.decode_read_window_bytes,
        decode::x86_tile_decode_limits_t::hard_maximum_window_bytes);
    executor_options.x86_limits.maximum_decode_attempts = (std::min)(
        static_cast<std::uint64_t>(
            settings.baseline_settings.max_trace_instructions),
        decode::x86_tile_decode_limits_t::hard_maximum_decode_attempts);
    executor_options.x86_limits.maximum_instructions = (std::min)(
        static_cast<std::uint64_t>(
            settings.baseline_settings.max_trace_instructions),
        decode::x86_tile_decode_limits_t::hard_maximum_instructions);

    auto executor = create_production_tile_decode_executor(
        std::move(executor_options), cancel);
    if (!executor) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "tile decode executor creation failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=executor_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto scoped_seeds = collect_scoped_seeds(
        image, source_snapshot->functions, scope.ranges);
    if (scoped_seeds.empty()) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "no seeds found for scoped re-decode";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=no_seeds generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    ::diag::log_tagged_fmt("incremental",
        "stage=disassembly seeds=%zu ranges=%zu generation=%llu",
        scoped_seeds.size(), scope.ranges.size(),
        static_cast<unsigned long long>(scope.generation));

    auto decode_result = orchestrator.value().run(
        *provider_snapshot.value(), layout.value(),
        std::move(scoped_seeds), *executor.value(), cancel);
    if (!decode_result) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "tile decode orchestrator run failed: " +
            decode_result.error().message;
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=decode_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    auto& tile_result = decode_result.value();
    if (!tile_result.packed_store || !tile_result.packed_store->valid()) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "tile decode packed store is invalid";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=invalid_store generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }
    auto packed_validated = tile_result.packed_store->validate();
    if (!packed_validated) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "tile decode packed store validation failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=validation_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    const auto packed_view = tile_result.packed_store->compatibility_view();
    std::vector<instruction_record_t> new_instructions;
    std::vector<operand_fact_t> new_operands;
    std::vector<target_fact_t> new_targets;
    std::map<entity_id_t, entity_id_t> new_instruction_ids;
    new_instructions.reserve(tile_result.packed_store->instruction_count());
    new_operands.reserve(tile_result.packed_store->operand_count());
    new_targets.reserve(tile_result.packed_store->target_fact_count());

    for (std::size_t index = 0;
         index < tile_result.packed_store->instruction_count(); ++index) {
        auto instruction = packed_view.instruction(index);
        if (!instruction) {
            result.fallback_to_full = true;
            result.ok = true;
            result.detail = "tile decode instruction row is missing";
            return result;
        }
        const auto replacement = kInstructionEntityTag |
            static_cast<std::uint64_t>(index + 1);
        new_instruction_ids.emplace(instruction->id, replacement);
        instruction->id = replacement;
        new_instructions.push_back(std::move(*instruction));
    }
    for (std::size_t index = 0;
         index < tile_result.packed_store->operand_count(); ++index) {
        auto operand = packed_view.operand(index);
        if (!operand)
            continue;
        const auto owner = new_instruction_ids.find(operand->instruction_id);
        if (owner == new_instruction_ids.end())
            continue;
        operand->instruction_id = owner->second;
        new_operands.push_back(std::move(*operand));
    }
    for (std::size_t index = 0;
         index < tile_result.packed_store->target_fact_count(); ++index) {
        auto target = packed_view.target_fact(index);
        if (!target)
            continue;
        const auto owner = new_instruction_ids.find(target->instruction_id);
        if (owner == new_instruction_ids.end())
            continue;
        target->instruction_id = owner->second;
        new_targets.push_back(std::move(*target));
    }

    merged_instruction_set_t merged_set;
    if (!merge_instruction_sets(
            image, scope.ranges,
            source_snapshot->instructions,
            source_snapshot->operand_facts,
            source_snapshot->target_facts,
            source_snapshot->delay_slot_counts,
            std::move(new_instructions),
            std::move(new_operands),
            std::move(new_targets),
            tile_result.delay_slot_counts,
            merged_set)) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "instruction set merge failed";
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=merge_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }

    merged->instructions = std::move(merged_set.instructions);
    merged->operand_facts = std::move(merged_set.operand_facts);
    merged->target_facts = std::move(merged_set.target_facts);
    merged->delay_slot_counts = std::move(merged_set.delay_slot_counts);

    const auto decode_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    ::diag::log_tagged_fmt("incremental",
        "stage=disassembly complete instructions=%zu elapsed=%llums generation=%llu",
        merged->instructions.size(),
        static_cast<unsigned long long>(decode_elapsed),
        static_cast<unsigned long long>(scope.generation));

    auto function_limits = settings.baseline_settings.function_limits;
    function_limits.cancellation_check_interval = (std::min)(
        function_limits.cancellation_check_interval,
        settings.baseline_settings.cancellation_check_interval);
    function_seed_sources_t seed_sources;
    for (const auto& function : source_snapshot->functions) {
        const auto rva = rva_of(function.start, image);
        if (rva && rva_overlaps_ranges(*rva, 1, scope.ranges)) {
            function_seed_t seed;
            seed.address = function.start;
            seed.kind = function_seed_kind_t::image_entry;
            seed.provenance = function.provenance;
            seed.confidence = function.confidence;
            seed.noreturn = function.noreturn;
            seed_sources.image_entries.push_back(seed);
        }
    }
    function_seed_evidence_t evidence;
    evidence.additional_sources = &seed_sources;

    auto recovered = function_recovery_t::recover(
        image, *projected_provider,
        merged->instructions, merged->operand_facts,
        merged->target_facts, evidence,
        merged->delay_slot_counts, function_limits, cancel);
    if (!recovered) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "function recovery failed: " + recovered.error().message;
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=recovery_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }
    auto function_result = recovered.take_value();
    merged->blocks = std::move(function_result.blocks);
    merged->functions = std::move(function_result.functions);
    merged->function_chunks = std::move(function_result.function_chunks);
    merged->function_block_memberships =
        std::move(function_result.function_block_memberships);
    merged->edges = std::move(function_result.edges);

    ::diag::log_tagged_fmt("incremental",
        "stage=basic_blocks functions=%zu blocks=%zu generation=%llu",
        merged->functions.size(), merged->blocks.size(),
        static_cast<unsigned long long>(scope.generation));

    auto call_graph_limits = settings.baseline_settings.call_graph_limits;
    call_graph_limits.cancellation_check_interval = (std::min)(
        call_graph_limits.cancellation_check_interval,
        settings.baseline_settings.cancellation_check_interval);
    std::vector<indirect_call_candidate_t> indirect_candidates;
    auto graph = call_graph_builder_t::build(
        merged->instructions, merged->target_facts,
        function_result, indirect_candidates,
        call_graph_limits, cancel);
    if (!graph) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "call graph build failed: " + graph.error().message;
        ::diag::log_tagged_fmt("incremental",
            "execute fallback reason=callgraph_failed generation=%llu",
            static_cast<unsigned long long>(scope.generation));
        return result;
    }
    auto call_graph_result = graph.take_value();
    auto published = call_graph_builder_t::publish(
        *merged, std::move(call_graph_result), cancel);
    if (!published) {
        result.fallback_to_full = true;
        result.ok = true;
        result.detail = "call graph publish failed";
        return result;
    }

    ::diag::log_tagged_fmt("incremental",
        "stage=functions call_graph_nodes=%zu generation=%llu",
        merged->call_graph.nodes.size(),
        static_cast<unsigned long long>(scope.generation));

    if (xref_invalidated || code_invalidated) {
        auto xref_limits = settings.baseline_settings.xref_limits;
        xref_limits.cancellation_check_interval = (std::min)(
            xref_limits.cancellation_check_interval,
            settings.baseline_settings.cancellation_check_interval);
        xref_limits.max_data_candidates = (std::min)(
            xref_limits.max_data_candidates,
            settings.baseline_settings.data_limits.max_candidates);
        xref_limits.max_pointer_facts = (std::min)(
            xref_limits.max_pointer_facts,
            settings.baseline_settings.data_limits.max_pointer_facts);
        xref_limits.max_data_conflicts = (std::min)(
            xref_limits.max_data_conflicts,
            settings.baseline_settings.data_limits.max_conflicts);

        std::vector<type_reference_fact_t> type_references;
        auto xref_built = xref_builder_t::build(
            image, *projected_provider,
            merged->instructions, merged->operand_facts,
            merged->target_facts, xref_limits, cancel);
        if (!xref_built) {
            result.fallback_to_full = true;
            result.ok = true;
            result.detail = "xref build failed: " + xref_built.error().message;
            ::diag::log_tagged_fmt("incremental",
                "execute fallback reason=xref_failed generation=%llu",
                static_cast<unsigned long long>(scope.generation));
            return result;
        }
        auto xref_result = xref_built.take_value();
        merged->xrefs = std::move(xref_result.xrefs);
        merged->rich_facts.data_candidates = std::move(xref_result.data_candidates);
        merged->rich_facts.data_pointer_facts = std::move(xref_result.data_pointer_facts);
        merged->rich_facts.data_conflicts = std::move(xref_result.data_conflicts);

        ::diag::log_tagged_fmt("incremental",
            "stage=xrefs xrefs=%zu data_candidates=%zu generation=%llu",
            merged->xrefs.size(),
            merged->rich_facts.data_candidates.size(),
            static_cast<unsigned long long>(scope.generation));
    } else {
        merged->xrefs = source_snapshot->xrefs;
        merged->rich_facts.data_candidates = source_snapshot->rich_facts.data_candidates;
        merged->rich_facts.data_pointer_facts = source_snapshot->rich_facts.data_pointer_facts;
        merged->rich_facts.data_conflicts = source_snapshot->rich_facts.data_conflicts;
    }

    if (metadata_invalidated || code_invalidated) {
        auto symbol_limits = settings.baseline_settings.symbol_type_limits;
        symbol_limits.cancellation_check_interval = (std::min)(
            symbol_limits.cancellation_check_interval,
            settings.baseline_settings.cancellation_check_interval);
        symbol_type_metadata_sources_t metadata;
        auto symbol_built = symbol_type_candidate_builder_t::build(
            image, merged->functions,
            merged->rich_facts.data_candidates,
            metadata, symbol_limits, cancel);
        if (!symbol_built) {
            result.fallback_to_full = true;
            result.ok = true;
            result.detail = "symbol/type rebuild failed: " +
                symbol_built.error().message;
            ::diag::log_tagged_fmt("incremental",
                "execute fallback reason=symbol_failed generation=%llu",
                static_cast<unsigned long long>(scope.generation));
            return result;
        }
        auto symbol_result = symbol_built.take_value();
        merged->symbols = std::move(symbol_result.symbols);
        merged->rich_facts.type_candidates = std::move(symbol_result.type_candidates);
        merged->rich_facts.type_references = std::move(symbol_result.type_references);
        merged->rich_facts.metadata_conflicts = std::move(symbol_result.conflicts);
        for (auto& function : merged->functions) {
            const auto found = std::find_if(
                merged->symbols.begin(), merged->symbols.end(),
                [&function](const symbol_record_t& symbol) {
                    return symbol.address == function.start &&
                        symbol.kind == symbol_kind_t::function;
                });
            if (found != merged->symbols.end())
                function.symbol_id = found->id;
        }

        ::diag::log_tagged_fmt("incremental",
            "stage=metadata symbols=%zu types=%zu generation=%llu",
            merged->symbols.size(),
            merged->rich_facts.type_candidates.size(),
            static_cast<unsigned long long>(scope.generation));
    } else {
        merged->symbols = source_snapshot->symbols;
        merged->rich_facts.type_candidates = source_snapshot->rich_facts.type_candidates;
        merged->rich_facts.type_references = source_snapshot->rich_facts.type_references;
        merged->rich_facts.metadata_conflicts = source_snapshot->rich_facts.metadata_conflicts;
    }

    if (strings_invalidated) {
        auto string_limits = settings.baseline_settings.string_limits;
        string_limits.cancellation_check_interval = (std::min)(
            string_limits.cancellation_check_interval,
            settings.baseline_settings.cancellation_check_interval);
        auto discovered = string_discovery_t::discover(
            image, *projected_provider, string_limits, cancel);
        if (discovered) {
            merged->strings = std::move(discovered.value().strings);
            ::diag::log_tagged_fmt("incremental",
                "stage=strings count=%zu generation=%llu",
                merged->strings.size(),
                static_cast<unsigned long long>(scope.generation));
        } else {
            merged->strings = source_snapshot->strings;
        }
    } else {
        merged->strings = source_snapshot->strings;
    }

    if (coverage_invalidated || code_invalidated) {
        std::vector<coverage_span_t> new_coverage;
        for (const auto& instruction : merged->instructions) {
            const auto rva = rva_of(instruction.address, image);
            if (!rva || instruction.length == 0)
                continue;
            coverage_span_t span;
            span.start = instruction.address;
            span.size = instruction.length;
            span.reason = instruction.coverage;
            span.provenance = instruction.provenance;
            span.confidence = instruction.confidence;
            new_coverage.push_back(std::move(span));
        }
        if (!merge_coverage_spans(image, scope.ranges,
                source_snapshot->coverage, std::move(new_coverage),
                merged->coverage)) {
            result.fallback_to_full = true;
            result.ok = true;
            result.detail = "coverage merge failed";
            ::diag::log_tagged_fmt("incremental",
                "execute fallback reason=coverage_merge_failed generation=%llu",
                static_cast<unsigned long long>(scope.generation));
            return result;
        }

        ::diag::log_tagged_fmt("incremental",
            "stage=coverage spans=%zu generation=%llu",
            merged->coverage.size(),
            static_cast<unsigned long long>(scope.generation));
    } else {
        merged->coverage = source_snapshot->coverage;
    }

    if (decompiler_invalidated) {
        auto decompiler = workspace->decompiler();
        if (decompiler) {
            for (const auto& function : merged->functions) {
                if (cancel.stop_requested())
                    break;
                const auto rva = rva_of(function.start, image);
                if (!rva || !rva_overlaps_ranges(*rva, 1, scope.ranges))
                    continue;
                (void)decompiler->invalidate(function.start, cancel);
            }
        }
        ::diag::log_tagged_fmt("incremental",
            "stage=decompiler invalidated affected_functions generation=%llu",
            static_cast<unsigned long long>(scope.generation));
    }

    merged->baseline_complete = false;

    auto ledger = recompute_snapshot_ledger(*merged, cancel);
    if (!ledger) {
        result.detail = ledger.error().message;
        return result;
    }

    const auto total_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    ::diag::log_tagged_fmt("incremental",
        "execute ok path=full_incremental instructions=%zu functions=%zu "
        "xrefs=%zu elapsed=%llums generation=%llu analysis_revision=%llu",
        merged->instructions.size(), merged->functions.size(),
        merged->xrefs.size(),
        static_cast<unsigned long long>(total_elapsed),
        static_cast<unsigned long long>(scope.generation),
        static_cast<unsigned long long>(merged->analysis_revision));

    result.ok = true;
    result.merged_snapshot = std::const_pointer_cast<
        const analysis_snapshot_t>(merged);
    return result;
}

}
}
