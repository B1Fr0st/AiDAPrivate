#include "call_graph_builder.hpp"

#include "workspace/checked_range.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint32_t kControlFlowMask =
    flow_branch | flow_call | flow_return | flow_interrupt | flow_terminal;

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase)
{
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "call graph deadline exceeded", phase);
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "call graph construction cancelled", phase);
    error.cancellation = true;
    return error;
}

bool valid_limits(const call_graph_builder_limits_t& limits) noexcept
{
    return limits.max_nodes != 0 && limits.max_sites != 0 &&
        limits.max_edges != 0 && limits.max_candidates != 0 &&
        limits.max_conflicts != 0 && limits.max_result_bytes != 0 &&
        limits.max_candidates_per_site != 0 &&
        limits.cancellation_check_interval != 0 &&
        limits.max_candidates_per_site <= limits.max_candidates;
}

template <typename T>
workspace_result_t<void> append_bounded(std::vector<T>& values, T value,
    std::uint64_t maximum_count, std::uint64_t maximum_bytes,
    std::uint64_t& storage_bytes, const char* phase, const char* message)
{
    if (values.size() >= maximum_count) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, phase));
    }
    if (values.size() == values.capacity()) {
        const auto current = static_cast<std::uint64_t>(values.capacity());
        std::uint64_t desired = current == 0
            ? std::min<std::uint64_t>(4096, maximum_count) : 0;
        if (current != 0 && !checked_add_u64(current, current / 2ULL, desired)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
        std::uint64_t minimum = 0;
        if (!checked_add_u64(current, 1, minimum)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
        desired = std::min(std::max(desired, minimum), maximum_count);
        std::uint64_t new_allocation = 0;
        std::uint64_t retained_delta = 0;
        std::uint64_t peak = 0;
        if (desired <= current ||
            !checked_mul_u64(desired, sizeof(T), new_allocation) ||
            !checked_mul_u64(desired - current, sizeof(T), retained_delta) ||
            !checked_add_u64(storage_bytes, new_allocation, peak) ||
            peak > maximum_bytes) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, message, phase));
        }
        values.reserve(static_cast<std::size_t>(desired));
        if (!checked_add_u64(storage_bytes, retained_delta, storage_bytes)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow, message, phase));
        }
    }
    values.push_back(std::move(value));
    return workspace_result_t<void>::success();
}

call_graph_quality_t quality_from(fact_provenance_t provenance,
                                  std::uint8_t confidence) noexcept
{
    call_graph_quality_t quality;
    quality.provenance = provenance;
    quality.confidence = confidence;
    quality.contributor_count = 1;
    return quality;
}

bool quality_preferred(const call_graph_quality_t& lhs,
                       const call_graph_quality_t& rhs) noexcept
{
    if (provenance_rank(lhs.provenance) != provenance_rank(rhs.provenance))
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    return lhs.confidence > rhs.confidence;
}

void merge_quality(call_graph_quality_t& existing,
                   const call_graph_quality_t& candidate) noexcept
{
    if (existing.contributor_count == 0) {
        existing = candidate;
        return;
    }
    if (existing.provenance != candidate.provenance ||
        existing.confidence != candidate.confidence)
        existing.conflicted = true;
    existing.contributor_count =
        existing.contributor_count >
            (std::numeric_limits<std::uint32_t>::max)() -
                candidate.contributor_count
        ? (std::numeric_limits<std::uint32_t>::max)()
        : existing.contributor_count + candidate.contributor_count;
    existing.conflicted = existing.conflicted || candidate.conflicted;
    if (quality_preferred(candidate, existing)) {
        existing.provenance = candidate.provenance;
        existing.confidence = candidate.confidence;
    }
}

std::uint8_t candidate_kind_rank(indirect_call_candidate_kind_t kind) noexcept
{
    switch (kind) {
        case indirect_call_candidate_kind_t::target_fact:
            return 7;
        case indirect_call_candidate_kind_t::import_slot:
            return 6;
        case indirect_call_candidate_kind_t::relocation:
            return 5;
        case indirect_call_candidate_kind_t::vtable:
            return 4;
        case indirect_call_candidate_kind_t::jump_table:
            return 3;
        case indirect_call_candidate_kind_t::decompiler:
            return 2;
        case indirect_call_candidate_kind_t::pointer_scan:
            return 1;
    }
    return 0;
}

const instruction_record_t* transfer_instruction(
    std::size_t block_index,
    const function_recovery_result_t& recovery,
    const std::vector<instruction_record_t>& instructions) noexcept
{
    if (block_index >= recovery.blocks.size())
        return nullptr;
    const auto& block = recovery.blocks[block_index];
    if (block.instruction_count == 0)
        return nullptr;
    const auto first = static_cast<std::size_t>(block.first_instruction);
    const auto end = first + block.instruction_count;
    if (end > instructions.size())
        return nullptr;
    if (recovery.terminator_instruction_indices.size() == recovery.blocks.size()) {
        const auto index = static_cast<std::size_t>(
            recovery.terminator_instruction_indices[block_index]);
        if (index >= first && index < end)
            return &instructions[index];
    }
    for (std::size_t index = end; index > first; --index) {
        if ((instructions[index - 1].flow_flags & kControlFlowMask) != 0)
            return &instructions[index - 1];
    }
    return &instructions[end - 1];
}

struct raw_candidate_t {
    address_t target;
    std::optional<entity_id_t> target_function_id;
    indirect_call_candidate_kind_t kind =
        indirect_call_candidate_kind_t::target_fact;
    call_graph_quality_t quality;
    std::uint64_t stable_source_id = 0;
    bool external_target = false;
};

struct candidate_key_t {
    address_t target;
    entity_id_t target_function_id = 0;
    bool external_target = false;

    bool operator<(const candidate_key_t& other) const noexcept
    {
        if (target != other.target)
            return target < other.target;
        if (target_function_id != other.target_function_id)
            return target_function_id < other.target_function_id;
        return external_target < other.external_target;
    }
};

bool candidate_rank_less(const raw_candidate_t& lhs,
                         const raw_candidate_t& rhs) noexcept
{
    if (quality_preferred(lhs.quality, rhs.quality))
        return true;
    if (quality_preferred(rhs.quality, lhs.quality))
        return false;
    if (candidate_kind_rank(lhs.kind) != candidate_kind_rank(rhs.kind))
        return candidate_kind_rank(lhs.kind) > candidate_kind_rank(rhs.kind);
    if (lhs.stable_source_id != rhs.stable_source_id)
        return lhs.stable_source_id < rhs.stable_source_id;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.target_function_id.value_or(0) !=
        rhs.target_function_id.value_or(0))
        return lhs.target_function_id.value_or(0) <
            rhs.target_function_id.value_or(0);
    return lhs.external_target < rhs.external_target;
}

struct raw_site_t {
    entity_id_t source_function_id = 0;
    entity_id_t source_block_id = 0;
    entity_id_t instruction_id = 0;
    address_t address;
    call_graph_quality_t quality;
    std::vector<raw_candidate_t> candidates;
    bool indirect = false;
    bool tail_call = false;
};

bool raw_site_less(const raw_site_t& lhs, const raw_site_t& rhs) noexcept
{
    if (lhs.source_function_id != rhs.source_function_id)
        return lhs.source_function_id < rhs.source_function_id;
    if (lhs.address != rhs.address)
        return lhs.address < rhs.address;
    if (lhs.source_block_id != rhs.source_block_id)
        return lhs.source_block_id < rhs.source_block_id;
    if (lhs.instruction_id != rhs.instruction_id)
        return lhs.instruction_id < rhs.instruction_id;
    if (lhs.tail_call != rhs.tail_call)
        return lhs.tail_call < rhs.tail_call;
    return lhs.indirect < rhs.indirect;
}

bool conflict_less(const call_graph_conflict_t& lhs,
                   const call_graph_conflict_t& rhs) noexcept
{
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.source_function_id != rhs.source_function_id)
        return lhs.source_function_id < rhs.source_function_id;
    if (lhs.call_site_rva != rhs.call_site_rva)
        return lhs.call_site_rva < rhs.call_site_rva;
    if (lhs.instruction_id != rhs.instruction_id)
        return lhs.instruction_id < rhs.instruction_id;
    if (lhs.selected_target_rva != rhs.selected_target_rva)
        return lhs.selected_target_rva < rhs.selected_target_rva;
    if (lhs.competing_target_rva != rhs.competing_target_rva)
        return lhs.competing_target_rva < rhs.competing_target_rva;
    if (lhs.selected_target_function_id != rhs.selected_target_function_id)
        return lhs.selected_target_function_id <
            rhs.selected_target_function_id;
    return lhs.competing_target_function_id <
        rhs.competing_target_function_id;
}

bool conflict_equal(const call_graph_conflict_t& lhs,
                    const call_graph_conflict_t& rhs) noexcept
{
    return !conflict_less(lhs, rhs) && !conflict_less(rhs, lhs);
}

}

workspace_result_t<call_graph_result_t> call_graph_builder_t::build(
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const function_recovery_result_t& recovery,
    const std::vector<indirect_call_candidate_t>& indirect_candidates,
    const call_graph_builder_limits_t& limits,
    const cancellation_token_t& cancel)
{
    if (!valid_limits(limits)) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "call graph limits are invalid", "call_graph"));
    }
    if (recovery.functions.size() > limits.max_nodes ||
        indirect_candidates.size() > limits.max_candidates) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph input exceeds analysis limits", "call_graph"));
    }
    if (!recovery.terminator_instruction_indices.empty() &&
        recovery.terminator_instruction_indices.size() != recovery.blocks.size()) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "call graph block terminator column is not aligned", "call_graph"));
    }
    call_graph_result_t result;
    const auto append_conflict = [&](call_graph_conflict_t conflict)
        -> workspace_result_t<void> {
        return append_bounded(result.conflicts, std::move(conflict),
            limits.max_conflicts, limits.max_result_bytes, result.storage_bytes,
            "call_graph", "call graph conflict storage exceeds analysis budget");
    };
    std::map<entity_id_t, std::size_t> instruction_by_id;
    std::map<address_t, entity_id_t> instruction_by_address;
    std::uint64_t checks = 0;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<call_graph_result_t>::failure(
                    stop_error(cancel, "call_graph.instructions"));
        }
        const auto& instruction = instructions[index];
        std::uint64_t target_end = 0;
        if (instruction.id == 0 ||
            !instruction_by_id.emplace(instruction.id, index).second ||
            !instruction_by_address.emplace(instruction.address,
                                             instruction.id).second ||
            !checked_add_u64(instruction.target_fact_begin,
                instruction.target_fact_count, target_end) ||
            target_end > targets.size()) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call graph instruction stream is malformed", "call_graph.instructions"));
        }
    }
    std::map<entity_id_t, std::size_t> function_by_id;
    std::map<address_t, entity_id_t> function_by_address;
    for (std::size_t index = 0; index < recovery.functions.size(); ++index) {
        const auto& function = recovery.functions[index];
        if (function.id == 0 || function.end.value <= function.start.value ||
            !function_by_id.emplace(function.id, index).second ||
            !function_by_address.emplace(function.start, function.id).second) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call graph function catalog is malformed", "call_graph.functions"));
        }
        call_graph_node_record_t node;
        node.function_id = function.id;
        node.address = function.start;
        auto appended = append_bounded(result.nodes, std::move(node),
            limits.max_nodes, limits.max_result_bytes, result.storage_bytes,
            "call_graph", "call graph node storage exceeds analysis budget");
        if (!appended)
            return workspace_result_t<call_graph_result_t>::failure(appended.error());
    }
    std::sort(result.nodes.begin(), result.nodes.end(),
        [](const call_graph_node_record_t& lhs,
           const call_graph_node_record_t& rhs) {
            if (lhs.address != rhs.address)
                return lhs.address < rhs.address;
            return lhs.function_id < rhs.function_id;
        });
    std::map<entity_id_t, std::size_t> node_by_function;
    for (std::size_t index = 0; index < result.nodes.size(); ++index)
        node_by_function.emplace(result.nodes[index].function_id, index);
    std::map<entity_id_t, std::size_t> block_by_id;
    std::map<entity_id_t, std::vector<entity_id_t>> callers_by_block;
    for (std::size_t index = 0; index < recovery.blocks.size(); ++index) {
        const auto& block = recovery.blocks[index];
        if (block.id == 0 || block.instruction_count == 0 ||
            block.first_instruction > instructions.size() ||
            block.instruction_count >
                instructions.size() - block.first_instruction ||
            function_by_id.find(block.function_id) == function_by_id.end() ||
            !block_by_id.emplace(block.id, index).second) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call graph block catalog is malformed", "call_graph.blocks"));
        }
        callers_by_block[block.id].push_back(block.function_id);
    }
    for (const auto& membership : recovery.function_block_memberships) {
        const auto block = block_by_id.find(membership.block_id);
        if (block == block_by_id.end() ||
            membership.block_index != block->second ||
            function_by_id.find(membership.function_id) == function_by_id.end()) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call graph function membership is malformed",
                    "call_graph.memberships"));
        }
        callers_by_block[membership.block_id].push_back(membership.function_id);
    }
    for (auto& entry : callers_by_block) {
        auto& callers = entry.second;
        std::sort(callers.begin(), callers.end());
        callers.erase(std::unique(callers.begin(), callers.end()), callers.end());
    }
    std::map<entity_id_t, std::vector<indirect_call_candidate_t>>
        evidence_by_instruction;
    for (const auto& candidate : indirect_candidates) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<call_graph_result_t>::failure(
                    stop_error(cancel, "call_graph.candidates"));
        }
        entity_id_t instruction_id = candidate.instruction_id;
        if (instruction_id == 0) {
            const auto found = instruction_by_address.find(candidate.call_site);
            if (found != instruction_by_address.end())
                instruction_id = found->second;
        }
        if (instruction_by_id.find(instruction_id) == instruction_by_id.end()) {
            call_graph_conflict_t conflict;
            conflict.kind = call_graph_conflict_kind_t::orphan_candidate;
            conflict.instruction_id = candidate.instruction_id;
            conflict.call_site_rva = candidate.call_site.value;
            conflict.competing_target_rva = candidate.target.value;
            conflict.competing_target_function_id =
                candidate.target_function_id.value_or(0);
            auto appended = append_conflict(std::move(conflict));
            if (!appended)
                return workspace_result_t<call_graph_result_t>::failure(
                    appended.error());
            continue;
        }
        auto normalized = candidate;
        normalized.instruction_id = instruction_id;
        if (normalized.call_site == address_t{})
            normalized.call_site =
                instructions[instruction_by_id[instruction_id]].address;
        evidence_by_instruction[instruction_id].push_back(std::move(normalized));
    }
    std::map<entity_id_t, std::vector<const edge_record_t*>> call_edges_by_block;
    std::map<entity_id_t, std::vector<const edge_record_t*>> tail_edges_by_block;
    for (const auto& edge : recovery.edges) {
        if (block_by_id.find(edge.source_entity) == block_by_id.end())
            continue;
        if (edge.kind == edge_kind_t::call)
            call_edges_by_block[edge.source_entity].push_back(&edge);
        else if (edge.kind == edge_kind_t::tail_call)
            tail_edges_by_block[edge.source_entity].push_back(&edge);
    }
    std::vector<raw_site_t> raw_sites;
    std::uint64_t raw_candidate_count = 0;
    const auto append_raw_site = [&](raw_site_t site)
        -> workspace_result_t<void> {
        if (raw_sites.size() >= limits.max_sites ||
            site.candidates.size() >
                limits.max_candidates - raw_candidate_count) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "raw call graph evidence exceeds analysis limits", "call_graph.sites"));
        }
        raw_candidate_count += site.candidates.size();
        raw_sites.push_back(std::move(site));
        return workspace_result_t<void>::success();
    };
    const auto edge_candidate = [&](const edge_record_t& edge) {
        raw_candidate_t candidate;
        candidate.target = edge.target;
        if (edge.target_entity &&
            function_by_id.find(*edge.target_entity) != function_by_id.end())
            candidate.target_function_id = *edge.target_entity;
        candidate.kind = indirect_call_candidate_kind_t::target_fact;
        candidate.quality = quality_from(edge.provenance, edge.confidence);
        candidate.stable_source_id = edge.id;
        candidate.external_target = !candidate.target_function_id.has_value();
        return candidate;
    };
    for (std::size_t block_index = 0;
         block_index < recovery.blocks.size(); ++block_index) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<call_graph_result_t>::failure(
                    stop_error(cancel, "call_graph.sites"));
        }
        const auto& block = recovery.blocks[block_index];
        const auto* transfer =
            transfer_instruction(block_index, recovery, instructions);
        if (!transfer)
            continue;
        const auto callers = callers_by_block.find(block.id);
        if (callers == callers_by_block.end() || callers->second.empty()) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call site has no recovered caller", "call_graph.sites"));
        }
        if ((transfer->flow_flags & flow_call) != 0) {
            raw_site_t prototype;
            prototype.source_block_id = block.id;
            prototype.instruction_id = transfer->id;
            prototype.address = transfer->address;
            prototype.quality =
                quality_from(transfer->provenance, transfer->confidence);
            prototype.indirect =
                (transfer->flow_flags & flow_indirect) != 0;
            const auto target_end =
                static_cast<std::size_t>(transfer->target_fact_begin) +
                transfer->target_fact_count;
            for (std::size_t index = transfer->target_fact_begin;
                 index < target_end; ++index) {
                const auto& target = targets[index];
                if (target.kind != target_kind_record_t::call &&
                    !(prototype.indirect &&
                      target.kind == target_kind_record_t::data))
                    continue;
                raw_candidate_t candidate;
                candidate.target = target.target;
                const auto function = function_by_address.find(target.target);
                if (function != function_by_address.end())
                    candidate.target_function_id = function->second;
                candidate.kind =
                    indirect_call_candidate_kind_t::target_fact;
                candidate.quality = prototype.quality;
                candidate.stable_source_id =
                    transfer->stable_source_id ^
                    static_cast<std::uint64_t>(index + 1);
                candidate.external_target =
                    target.is_external ||
                    !candidate.target_function_id.has_value();
                prototype.indirect = prototype.indirect || !target.direct;
                prototype.candidates.push_back(std::move(candidate));
            }
            const auto edge_evidence = call_edges_by_block.find(block.id);
            if (edge_evidence != call_edges_by_block.end()) {
                for (const auto* edge : edge_evidence->second)
                    prototype.candidates.push_back(edge_candidate(*edge));
            }
            const auto external = evidence_by_instruction.find(transfer->id);
            if (external != evidence_by_instruction.end()) {
                for (const auto& evidence : external->second) {
                    raw_candidate_t candidate;
                    candidate.target = evidence.target;
                    candidate.target_function_id =
                        evidence.target_function_id;
                    candidate.kind = evidence.kind;
                    candidate.quality = quality_from(
                        evidence.provenance, evidence.confidence);
                    candidate.stable_source_id =
                        evidence.stable_source_id;
                    candidate.external_target =
                        evidence.external_target;
                    prototype.candidates.push_back(std::move(candidate));
                }
                prototype.indirect = true;
            }
            for (const auto caller : callers->second) {
                auto site = prototype;
                site.source_function_id = caller;
                auto appended = append_raw_site(std::move(site));
                if (!appended)
                    return workspace_result_t<call_graph_result_t>::failure(
                        appended.error());
            }
        }
        const auto tail_evidence = tail_edges_by_block.find(block.id);
        if (tail_evidence == tail_edges_by_block.end())
            continue;
        raw_site_t prototype;
        prototype.source_block_id = block.id;
        prototype.instruction_id = transfer->id;
        prototype.address = transfer->address;
        prototype.quality =
            quality_from(transfer->provenance, transfer->confidence);
        prototype.indirect = (transfer->flow_flags & flow_indirect) != 0;
        prototype.tail_call = true;
        for (const auto* edge : tail_evidence->second)
            prototype.candidates.push_back(edge_candidate(*edge));
        const auto external = evidence_by_instruction.find(transfer->id);
        if (external != evidence_by_instruction.end()) {
            for (const auto& evidence : external->second) {
                raw_candidate_t candidate;
                candidate.target = evidence.target;
                candidate.target_function_id = evidence.target_function_id;
                candidate.kind = evidence.kind;
                candidate.quality =
                    quality_from(evidence.provenance, evidence.confidence);
                candidate.stable_source_id = evidence.stable_source_id;
                candidate.external_target = evidence.external_target;
                prototype.candidates.push_back(std::move(candidate));
            }
            prototype.indirect = true;
        }
        for (const auto caller : callers->second) {
            auto site = prototype;
            site.source_function_id = caller;
            auto appended = append_raw_site(std::move(site));
            if (!appended)
                return workspace_result_t<call_graph_result_t>::failure(
                    appended.error());
        }
    }
    std::sort(raw_sites.begin(), raw_sites.end(), raw_site_less);
    for (auto& raw_site : raw_sites) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<call_graph_result_t>::failure(
                    stop_error(cancel, "call_graph.resolve"));
        }
        std::map<candidate_key_t, raw_candidate_t> merged_candidates;
        for (auto& candidate : raw_site.candidates) {
            const auto exact = function_by_address.find(candidate.target);
            const auto supplied = candidate.target_function_id;
            const auto supplied_function = supplied
                ? function_by_id.find(*supplied) : function_by_id.end();
            if (supplied &&
                (supplied_function == function_by_id.end() ||
                 recovery.functions[supplied_function->second].start != candidate.target)) {
                call_graph_conflict_t conflict;
                conflict.kind =
                    call_graph_conflict_kind_t::candidate_identity_mismatch;
                conflict.instruction_id = raw_site.instruction_id;
                conflict.source_function_id = raw_site.source_function_id;
                conflict.call_site_rva = raw_site.address.value;
                conflict.selected_target_rva = candidate.target.value;
                if (exact != function_by_address.end())
                    conflict.selected_target_function_id = exact->second;
                conflict.competing_target_rva = candidate.target.value;
                conflict.competing_target_function_id = *supplied;
                auto appended = append_conflict(std::move(conflict));
                if (!appended)
                    return workspace_result_t<call_graph_result_t>::failure(
                        appended.error());
                candidate.target_function_id.reset();
            }
            if (exact != function_by_address.end()) {
                candidate.target_function_id = exact->second;
            }
            candidate.external_target = !candidate.target_function_id.has_value();
            candidate_key_t key;
            key.target = candidate.target;
            key.target_function_id =
                candidate.target_function_id.value_or(0);
            key.external_target = candidate.external_target;
            const auto found = merged_candidates.find(key);
            if (found == merged_candidates.end()) {
                merged_candidates.emplace(key, std::move(candidate));
                continue;
            }
            auto& existing = found->second;
            const bool replace = candidate_rank_less(candidate, existing);
            merge_quality(existing.quality, candidate.quality);
            if (replace) {
                existing.kind = candidate.kind;
                existing.stable_source_id = candidate.stable_source_id;
            }
        }
        std::vector<raw_candidate_t> ranked;
        ranked.reserve(merged_candidates.size());
        for (auto& entry : merged_candidates)
            ranked.push_back(std::move(entry.second));
        std::sort(ranked.begin(), ranked.end(), candidate_rank_less);
        if (ranked.size() > 1) {
            for (std::size_t index = 1; index < ranked.size(); ++index) {
                call_graph_conflict_t conflict;
                conflict.kind =
                    call_graph_conflict_kind_t::candidate_target_disagreement;
                conflict.instruction_id = raw_site.instruction_id;
                conflict.source_function_id = raw_site.source_function_id;
                conflict.call_site_rva = raw_site.address.value;
                conflict.selected_target_rva = ranked.front().target.value;
                conflict.competing_target_rva = ranked[index].target.value;
                conflict.selected_target_function_id =
                    ranked.front().target_function_id.value_or(0);
                conflict.competing_target_function_id =
                    ranked[index].target_function_id.value_or(0);
                auto appended = append_conflict(std::move(conflict));
                if (!appended)
                    return workspace_result_t<call_graph_result_t>::failure(
                        appended.error());
            }
        }
        if (ranked.size() > limits.max_candidates_per_site) {
            call_graph_conflict_t conflict;
            conflict.kind = call_graph_conflict_kind_t::candidate_limit;
            conflict.instruction_id = raw_site.instruction_id;
            conflict.source_function_id = raw_site.source_function_id;
            conflict.call_site_rva = raw_site.address.value;
            conflict.selected_target_rva = ranked.front().target.value;
            conflict.competing_target_rva =
                ranked[limits.max_candidates_per_site].target.value;
            auto appended = append_conflict(std::move(conflict));
            if (!appended)
                return workspace_result_t<call_graph_result_t>::failure(
                    appended.error());
            ranked.resize(limits.max_candidates_per_site);
            result.bounded = true;
        }
        recovered_call_site_t site;
        site.id = call_site_entity_tag |
            static_cast<std::uint64_t>(result.call_sites.size() + 1);
        site.source_function_id = raw_site.source_function_id;
        site.source_block_id = raw_site.source_block_id;
        site.instruction_id = raw_site.instruction_id;
        site.address = raw_site.address;
        site.first_candidate =
            static_cast<std::uint32_t>(result.candidates.size());
        site.candidate_count = static_cast<std::uint32_t>(ranked.size());
        site.indirect = raw_site.indirect;
        site.tail_call = raw_site.tail_call;
        site.unresolved = ranked.empty();
        const auto site_id = site.id;
        const auto site_index = result.call_sites.size();
        auto appended_site = append_bounded(result.call_sites, std::move(site),
            limits.max_sites, limits.max_result_bytes, result.storage_bytes,
            "call_graph", "call graph site storage exceeds analysis budget");
        if (!appended_site)
            return workspace_result_t<call_graph_result_t>::failure(
                appended_site.error());
        if (raw_site.indirect)
            ++result.indirect_site_count;
        if (ranked.empty()) {
            ++result.unresolved_site_count;
            call_graph_conflict_t conflict;
            conflict.kind = call_graph_conflict_kind_t::unresolved_site;
            conflict.instruction_id = raw_site.instruction_id;
            conflict.source_function_id = raw_site.source_function_id;
            conflict.call_site_rva = raw_site.address.value;
            auto appended = append_conflict(std::move(conflict));
            if (!appended)
                return workspace_result_t<call_graph_result_t>::failure(
                    appended.error());
            call_graph_edge_record_t edge;
            edge.id = call_edge_entity_tag |
                static_cast<std::uint64_t>(result.edges.size() + 1);
            edge.call_site_id = site_id;
            edge.source_function_id = raw_site.source_function_id;
            edge.source_block_id = raw_site.source_block_id;
            edge.call_site = raw_site.address;
            edge.target = raw_site.address;
            edge.target.value = 0;
            edge.resolution = call_graph_resolution_t::unresolved;
            edge.quality = raw_site.quality;
            auto appended_edge = append_bounded(result.edges, std::move(edge),
                limits.max_edges, limits.max_result_bytes, result.storage_bytes,
                "call_graph", "call graph edge storage exceeds analysis budget");
            if (!appended_edge)
                return workspace_result_t<call_graph_result_t>::failure(
                    appended_edge.error());
        } else {
            for (std::size_t rank = 0; rank < ranked.size(); ++rank) {
                const auto& candidate = ranked[rank];
                recovered_call_candidate_t output;
                output.id = call_candidate_entity_tag |
                    static_cast<std::uint64_t>(result.candidates.size() + 1);
                output.call_site_id = site_id;
                output.target = candidate.target;
                output.target_function_id =
                    candidate.target_function_id;
                output.kind = candidate.kind;
                output.quality = candidate.quality;
                output.stable_source_id = candidate.stable_source_id;
                output.rank = static_cast<std::uint32_t>(rank);
                output.external_target = candidate.external_target;
                auto appended_candidate = append_bounded(result.candidates,
                    std::move(output), limits.max_candidates,
                    limits.max_result_bytes, result.storage_bytes, "call_graph",
                    "call graph candidate storage exceeds analysis budget");
                if (!appended_candidate)
                    return workspace_result_t<call_graph_result_t>::failure(
                        appended_candidate.error());
                call_graph_edge_record_t edge;
                edge.id = call_edge_entity_tag |
                    static_cast<std::uint64_t>(result.edges.size() + 1);
                edge.call_site_id = site_id;
                edge.source_function_id = raw_site.source_function_id;
                edge.source_block_id = raw_site.source_block_id;
                edge.target_function_id =
                    candidate.target_function_id;
                edge.call_site = raw_site.address;
                edge.target = candidate.target;
                edge.resolution = raw_site.tail_call
                    ? call_graph_resolution_t::tail_call
                    : (raw_site.indirect
                        ? call_graph_resolution_t::indirect_candidate
                        : call_graph_resolution_t::direct);
                edge.quality = candidate.quality;
                edge.candidate_rank = static_cast<std::uint32_t>(rank);
                edge.external_target = candidate.external_target;
                if (candidate.target_function_id) {
                    const auto target =
                        function_by_id.find(*candidate.target_function_id);
                    edge.target_noreturn =
                        target != function_by_id.end() &&
                        recovery.functions[target->second].noreturn;
                }
                auto appended_edge = append_bounded(result.edges,
                    std::move(edge), limits.max_edges,
                    limits.max_result_bytes, result.storage_bytes, "call_graph",
                    "call graph edge storage exceeds analysis budget");
                if (!appended_edge)
                    return workspace_result_t<call_graph_result_t>::failure(
                        appended_edge.error());
            }
        }
        auto source_node = node_by_function.find(raw_site.source_function_id);
        if (source_node == node_by_function.end()) {
            return workspace_result_t<call_graph_result_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "call graph site references an unknown caller",
                    "call_graph.resolve"));
        }
        auto& source = result.nodes[source_node->second];
        const auto& committed_site = result.call_sites[site_index];
        if (committed_site.unresolved)
            ++source.unresolved_sites;
        const auto edge_begin = committed_site.unresolved
            ? result.edges.size() - 1
            : result.edges.size() - committed_site.candidate_count;
        for (std::size_t edge_index = edge_begin;
             edge_index < result.edges.size(); ++edge_index) {
            ++source.outgoing_edges;
            if (raw_site.indirect)
                ++source.indirect_edges;
            if (result.edges[edge_index].target_function_id) {
                const auto target_node = node_by_function.find(
                    *result.edges[edge_index].target_function_id);
                if (target_node != node_by_function.end())
                    ++result.nodes[target_node->second].incoming_edges;
            }
        }
    }
    std::sort(result.conflicts.begin(), result.conflicts.end(), conflict_less);
    result.conflicts.erase(std::unique(result.conflicts.begin(),
        result.conflicts.end(), conflict_equal), result.conflicts.end());
    for (std::size_t index = 0; index < result.conflicts.size(); ++index)
        result.conflicts[index].id = call_conflict_entity_tag |
            static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<call_graph_result_t>::success(std::move(result));
}

workspace_result_t<void> call_graph_builder_t::publish(
    analysis_snapshot_t& snapshot,
    call_graph_result_t result,
    const cancellation_token_t& cancel)
{
    call_graph_publication_t publication;
    publication.nodes = std::move(result.nodes);
    publication.call_sites = std::move(result.call_sites);
    publication.candidates = std::move(result.candidates);
    publication.edges = std::move(result.edges);
    publication.conflicts = std::move(result.conflicts);
    publication.indirect_site_count = result.indirect_site_count;
    publication.unresolved_site_count = result.unresolved_site_count;
    publication.bounded = result.bounded;
    auto validated = validate_call_graph_publication(snapshot, publication, cancel);
    if (!validated)
        return validated;
    snapshot.call_graph = std::move(publication);
    return workspace_result_t<void>::success();
}

}
