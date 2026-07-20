#include "tile_decode_orchestrator.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr const char* kPhase = "tile_decode_orchestrator";

workspace_error_t orchestrator_error(workspace_error_code_t code, std::string message,
                                     std::optional<std::uint64_t> rva = std::nullopt)
{
    auto error = make_workspace_error(code, std::move(message), kPhase);
    if (rva) {
        address_t address;
        address.space = address_space_id_t::relative_virtual;
        address.value = *rva;
        error.address = address;
    }
    return error;
}

workspace_error_t cancellation_error(const cancellation_token_t& cancellation,
                                     std::string message)
{
    const bool deadline = cancellation.deadline_exceeded();
    auto error = orchestrator_error(
        deadline ? workspace_error_code_t::deadline_exceeded
                 : workspace_error_code_t::cancelled,
        std::move(message));
    error.cancellation = !deadline;
    error.deadline = deadline;
    return error;
}

workspace_error_t limit_error(std::string resource, std::uint64_t limit,
                              std::uint64_t attempted,
                              std::optional<std::uint64_t> rva = std::nullopt)
{
    auto error = orchestrator_error(workspace_error_code_t::limit_exceeded,
                                    resource + " limit exhausted", rva);
    error.details.emplace_back("resource", std::move(resource));
    error.details.emplace_back("limit", std::to_string(limit));
    error.details.emplace_back("attempted", std::to_string(attempted));
    return error;
}

bool checked_add(std::uint64_t lhs, std::uint64_t rhs,
                 std::uint64_t& result) noexcept
{
    if (rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs)
        return false;
    result = lhs + rhs;
    return true;
}

bool checked_multiply(std::uint64_t lhs, std::uint64_t rhs,
                      std::uint64_t& result) noexcept
{
    if (lhs != 0 && rhs > (std::numeric_limits<std::uint64_t>::max)() / lhs)
        return false;
    result = lhs * rhs;
    return true;
}

workspace_result_t<void> validate_completion_storage(
    const std::vector<tile_decode_completion_t>& completions,
    std::uint64_t maximum_private_bytes)
{
    std::uint64_t retained_bytes = 0;
    const auto add = [&](std::uint64_t count, std::uint64_t width)
        -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_multiply(count, width, bytes) ||
            !checked_add(retained_bytes, bytes, updated)) {
            return workspace_result_t<void>::failure(
                limit_error("private_bytes", maximum_private_bytes,
                    (std::numeric_limits<std::uint64_t>::max)()));
        }
        if (updated > maximum_private_bytes) {
            return workspace_result_t<void>::failure(
                limit_error("private_bytes", maximum_private_bytes, updated));
        }
        retained_bytes = updated;
        return workspace_result_t<void>::success();
    };
    auto added = add(completions.capacity(), sizeof(tile_decode_completion_t));
    if (!added)
        return added;
    for (const auto& completion : completions) {
        const std::pair<std::uint64_t, std::uint64_t> allocations[] = {
            {completion.records.instructions.capacity(),
                sizeof(instruction_record_t)},
            {completion.records.operand_facts.capacity(), sizeof(operand_fact_t)},
            {completion.records.target_facts.capacity(), sizeof(target_fact_t)},
            {completion.records.delay_slot_counts.capacity(), sizeof(std::uint8_t)},
            {completion.records.coverage.capacity(), sizeof(coverage_span_t)}};
        for (const auto& allocation : allocations) {
            added = add(allocation.first, allocation.second);
            if (!added)
                return added;
        }
    }
    return workspace_result_t<void>::success();
}

edge_kind_t flow_to_edge_kind(std::uint32_t flow_flags) noexcept
{
    if ((flow_flags & flow_return) != 0)
        return edge_kind_t::return_edge;
    if ((flow_flags & flow_call) != 0) {
        if ((flow_flags & flow_branch) != 0)
            return edge_kind_t::tail_call;
        return edge_kind_t::call;
    }
    if ((flow_flags & flow_branch) != 0) {
        if ((flow_flags & flow_conditional) != 0)
            return edge_kind_t::conditional_taken;
        return edge_kind_t::unconditional;
    }
    if ((flow_flags & flow_indirect) != 0)
        return edge_kind_t::indirect;
    return edge_kind_t::fallthrough;
}

decode_frontier_seed_kind_t flow_to_target_seed_kind(std::uint32_t flow_flags) noexcept
{
    if ((flow_flags & flow_call) != 0)
        return decode_frontier_seed_kind_t::call_target;
    if ((flow_flags & flow_branch) != 0)
        return decode_frontier_seed_kind_t::branch_target;
    return decode_frontier_seed_kind_t::fallthrough;
}

bool control_flow_target_matches(std::uint32_t flow_flags,
                                 target_kind_record_t kind) noexcept
{
    if (kind == target_kind_record_t::call)
        return (flow_flags & flow_call) != 0;
    if (kind == target_kind_record_t::branch)
        return (flow_flags & flow_branch) != 0;
    return false;
}

bool instruction_stronger(const instruction_record_t& a,
                           const instruction_record_t& b) noexcept
{
    if (a.provenance != b.provenance)
        return provenance_rank(a.provenance) > provenance_rank(b.provenance);
    if (a.confidence != b.confidence)
        return a.confidence > b.confidence;
    if (a.stable_source_id != b.stable_source_id)
        return a.stable_source_id < b.stable_source_id;
    if (a.address != b.address)
        return a.address < b.address;
    if (a.length != b.length)
        return a.length > b.length;
    if (a.mnemonic_id != b.mnemonic_id)
        return a.mnemonic_id < b.mnemonic_id;
    if (a.opcode_id != b.opcode_id)
        return a.opcode_id < b.opcode_id;
    if (a.flow_flags != b.flow_flags)
        return a.flow_flags < b.flow_flags;
    return a.coverage < b.coverage;
}

bool target_less(const target_fact_t& lhs, const target_fact_t& rhs) noexcept
{
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.resolution != rhs.resolution)
        return lhs.resolution < rhs.resolution;
    if (lhs.operand_index != rhs.operand_index)
        return lhs.operand_index < rhs.operand_index;
    if (lhs.access_width_bits != rhs.access_width_bits)
        return lhs.access_width_bits < rhs.access_width_bits;
    if (lhs.access_count != rhs.access_count)
        return lhs.access_count < rhs.access_count;
    if (lhs.direct != rhs.direct)
        return lhs.direct < rhs.direct;
    if (lhs.is_external != rhs.is_external)
        return lhs.is_external < rhs.is_external;
    if (lhs.instruction_id != rhs.instruction_id)
        return lhs.instruction_id < rhs.instruction_id;
    if (lhs.operand_fact_id != rhs.operand_fact_id)
        return lhs.operand_fact_id < rhs.operand_fact_id;
    return lhs.address_expression_id < rhs.address_expression_id;
}

struct tile_instruction_entry_t {
    instruction_record_t record;
    std::vector<operand_fact_t> operands;
    std::vector<target_fact_t> targets;
    std::uint8_t delay_slots = 0;
    std::uint64_t duplicate_edge_count = 0;
};

struct tile_accumulator_t {
    const executable_decode_tile_t* tile = nullptr;
    std::map<std::uint64_t, tile_instruction_entry_t> instructions;
    std::vector<coverage_span_t> coverage;
    std::uint64_t invalid_bytes = 0;
    std::uint64_t invalid_runs = 0;
};

struct correlated_tile_decode_batch_t final {
    std::vector<tile_decode_completion_t> completions;
    std::vector<std::size_t> completion_indices;
};

struct instruction_acceptance_t final {
    bool accepted = false;
};

struct decoded_edge_key_t final {
    address_t source;
    address_t target;
    edge_kind_t kind = edge_kind_t::fallthrough;
};

struct decoded_edge_less_t final {
    bool operator()(const decoded_edge_key_t& lhs,
                    const decoded_edge_key_t& rhs) const noexcept
    {
        if (lhs.source != rhs.source)
            return lhs.source < rhs.source;
        if (lhs.target != rhs.target)
            return lhs.target < rhs.target;
        return lhs.kind < rhs.kind;
    }
};

struct cross_tile_edge_less_t final {
    bool operator()(const tile_decode_cross_tile_edge_t& lhs,
                    const tile_decode_cross_tile_edge_t& rhs) const noexcept
    {
        if (lhs.source_tile_id != rhs.source_tile_id)
            return lhs.source_tile_id < rhs.source_tile_id;
        if (lhs.target_tile_id != rhs.target_tile_id)
            return lhs.target_tile_id < rhs.target_tile_id;
        if (lhs.source != rhs.source)
            return lhs.source < rhs.source;
        if (lhs.target != rhs.target)
            return lhs.target < rhs.target;
        return lhs.kind < rhs.kind;
    }
};

void merge_coverage_into(std::vector<coverage_span_t>& dest,
                         const std::vector<coverage_span_t>& src)
{
    for (const auto& span : src) {
        if (span.size == 0)
            continue;
        dest.push_back(span);
    }
    std::sort(dest.begin(), dest.end(), [](const auto& a, const auto& b) {
        if (a.start != b.start)
            return a.start < b.start;
        if (a.reason != b.reason)
            return a.reason < b.reason;
        if (a.provenance != b.provenance)
            return a.provenance < b.provenance;
        if (a.confidence != b.confidence)
            return a.confidence < b.confidence;
        if (a.detail_code != b.detail_code)
            return a.detail_code < b.detail_code;
        return a.size < b.size;
    });
    std::vector<coverage_span_t> merged;
    merged.reserve(dest.size());
    for (auto& span : dest) {
        if (!merged.empty()) {
            auto& last = merged.back();
            std::uint64_t last_end = 0;
            std::uint64_t span_end = 0;
            if (last.start.space == span.start.space &&
                last.start.architecture == span.start.architecture &&
                last.start.mode == span.start.mode &&
                checked_add(last.start.value, last.size, last_end) &&
                checked_add(span.start.value, span.size, span_end) &&
                last_end >= span.start.value &&
                last.reason == span.reason &&
                last.provenance == span.provenance &&
                last.confidence == span.confidence &&
                last.detail_code == span.detail_code) {
                const auto end_val = (std::max)(last_end, span_end);
                last.size = end_val - last.start.value;
                continue;
            }
        }
        merged.push_back(span);
    }
    dest = std::move(merged);
}

workspace_result_t<correlated_tile_decode_batch_t> execute_correlated_batch(
    tile_decode_executor_t& executor,
    const provider_snapshot_t& snapshot,
    const std::vector<tile_decode_request_t>& requests,
    const cancellation_token_t& cancellation,
    const char* cancellation_message)
{
    if (cancellation.stop_requested())
        return workspace_result_t<correlated_tile_decode_batch_t>::failure(
            cancellation_error(cancellation, cancellation_message));

    auto batch_result = executor.execute_batch(snapshot, requests, cancellation);
    if (!batch_result) {
        if (cancellation.stop_requested())
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                cancellation_error(cancellation, cancellation_message));
        return workspace_result_t<correlated_tile_decode_batch_t>::failure(
            batch_result.error());
    }

    if (cancellation.stop_requested())
        return workspace_result_t<correlated_tile_decode_batch_t>::failure(
            cancellation_error(cancellation, cancellation_message));

    correlated_tile_decode_batch_t batch;
    batch.completions = batch_result.take_value();
    batch.completion_indices.assign(
        requests.size(), (std::numeric_limits<std::size_t>::max)());

    std::map<std::uint64_t, std::size_t> request_indices;
    for (std::size_t index = 0; index < requests.size(); ++index) {
        if (!request_indices.emplace(requests[index].request_id, index).second) {
            auto error = orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decode batch contains duplicate request identifiers");
            error.details.emplace_back("request_id",
                                       std::to_string(requests[index].request_id));
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                std::move(error));
        }
    }

    for (std::size_t index = 0; index < batch.completions.size(); ++index) {
        const auto request = request_indices.find(batch.completions[index].request_id);
        if (request == request_indices.end()) {
            auto error = orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decode completion has an unknown request identifier");
            error.details.emplace_back("request_id",
                std::to_string(batch.completions[index].request_id));
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                std::move(error));
        }
        auto& completion_index = batch.completion_indices[request->second];
        if (completion_index != (std::numeric_limits<std::size_t>::max)()) {
            auto error = orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decode batch contains duplicate completions");
            error.details.emplace_back("request_id",
                std::to_string(batch.completions[index].request_id));
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                std::move(error));
        }
        completion_index = index;
    }

    for (std::size_t index = 0; index < requests.size(); ++index) {
        const auto completion_index = batch.completion_indices[index];
        if (completion_index == (std::numeric_limits<std::size_t>::max)()) {
            auto error = orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decode batch is missing a completion");
            error.details.emplace_back("request_id",
                                       std::to_string(requests[index].request_id));
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                std::move(error));
        }

        const auto& completion = batch.completions[completion_index];
        if (!completion.succeeded()) {
            auto error = *completion.error;
            error.details.emplace_back("request_id",
                                       std::to_string(requests[index].request_id));
            error.details.emplace_back("tile_id",
                                       std::to_string(requests[index].tile_id));
            return workspace_result_t<correlated_tile_decode_batch_t>::failure(
                std::move(error));
        }
    }

    return workspace_result_t<correlated_tile_decode_batch_t>::success(
        std::move(batch));
}

workspace_result_t<std::optional<tile_instruction_entry_t>>
make_owned_instruction_entry(const tile_decode_records_t& records,
                             std::size_t instruction_index,
                             const tile_decode_request_t& request,
                             const executable_decode_tile_t& tile)
{
    const auto& instruction = records.instructions[instruction_index];
    if (instruction.length == 0) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decoder returned a zero-length instruction",
                instruction.address.value));
    }
    if (instruction.address.space != request.start.space ||
        instruction.address.architecture != request.start.architecture ||
        instruction.address.mode != request.start.mode) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decoder returned an instruction in the wrong address domain",
                instruction.address.value));
    }

    const auto rva = instruction.address.value;
    if (rva < request.start.value || rva < tile.start_rva ||
        rva >= request.owned_end_rva) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::success(
            std::nullopt);
    }

    std::uint64_t request_end = 0;
    std::uint64_t instruction_end = 0;
    if (!checked_add(request.start.value, request.byte_count, request_end) ||
        !checked_add(rva, instruction.length, instruction_end) ||
        instruction_end > request_end) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decoder returned an instruction outside its request window", rva));
    }

    const auto operand_begin = static_cast<std::size_t>(instruction.operand_fact_begin);
    const auto operand_count = static_cast<std::size_t>(instruction.operand_fact_count);
    if (operand_begin > records.operand_facts.size() ||
        operand_count > records.operand_facts.size() - operand_begin) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decoder returned an invalid operand fact range", rva));
    }

    const auto target_begin = static_cast<std::size_t>(instruction.target_fact_begin);
    const auto target_count = static_cast<std::size_t>(instruction.target_fact_count);
    if (target_begin > records.target_facts.size() ||
        target_count > records.target_facts.size() - target_begin) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decoder returned an invalid target fact range", rva));
    }

    tile_instruction_entry_t entry;
    entry.record = instruction;
    if (!records.delay_slot_counts.empty())
        entry.delay_slots = records.delay_slot_counts[instruction_index];
    entry.operands.insert(entry.operands.end(),
                          records.operand_facts.begin() + operand_begin,
                          records.operand_facts.begin() + operand_begin + operand_count);
    entry.targets.insert(entry.targets.end(),
                         records.target_facts.begin() + target_begin,
                         records.target_facts.begin() + target_begin + target_count);

    std::sort(entry.targets.begin(), entry.targets.end(), target_less);
    std::vector<target_fact_t> unique_targets;
    unique_targets.reserve(entry.targets.size());
    for (auto& target : entry.targets) {
        if (!unique_targets.empty() &&
            !target_less(unique_targets.back(), target) &&
            !target_less(target, unique_targets.back())) {
            ++entry.duplicate_edge_count;
            continue;
        }
        unique_targets.push_back(std::move(target));
    }
    entry.targets = std::move(unique_targets);

    return workspace_result_t<std::optional<tile_instruction_entry_t>>::success(
        std::optional<tile_instruction_entry_t>(std::move(entry)));
}

workspace_result_t<instruction_acceptance_t> accept_instruction(
    tile_accumulator_t& accumulator,
    tile_instruction_entry_t entry,
    const tile_decode_orchestrator_limits_t& limits,
    tile_decode_orchestrator_statistics_t& statistics,
    std::uint64_t& total_instructions,
    std::uint64_t& total_operand_facts,
    std::uint64_t& total_target_facts)
{
    const auto rva = entry.record.address.value;
    const auto existing = accumulator.instructions.find(rva);
    if (existing != accumulator.instructions.end()) {
        ++statistics.duplicate_instruction_candidates;
        if (!instruction_stronger(entry.record, existing->second.record))
            return workspace_result_t<instruction_acceptance_t>::success(
                instruction_acceptance_t{});

        const auto retained_operands =
            total_operand_facts - existing->second.operands.size();
        const auto retained_targets =
            total_target_facts - existing->second.targets.size();
        if (entry.operands.size() > limits.maximum_operand_facts - retained_operands) {
            return workspace_result_t<instruction_acceptance_t>::failure(
                limit_error("operand_facts", limits.maximum_operand_facts,
                            retained_operands + entry.operands.size(), rva));
        }
        if (entry.targets.size() > limits.maximum_target_facts - retained_targets) {
            return workspace_result_t<instruction_acceptance_t>::failure(
                limit_error("target_facts", limits.maximum_target_facts,
                            retained_targets + entry.targets.size(), rva));
        }
        total_operand_facts = retained_operands + entry.operands.size();
        total_target_facts = retained_targets + entry.targets.size();
        existing->second = std::move(entry);
        return workspace_result_t<instruction_acceptance_t>::success(
            instruction_acceptance_t{true});
    }

    std::vector<std::uint64_t> overlapping_rvas;
    std::uint64_t removed_operands = 0;
    std::uint64_t removed_targets = 0;
    for (const auto& [existing_rva, existing_entry] : accumulator.instructions) {
        std::uint64_t existing_end = 0;
        std::uint64_t candidate_end = 0;
        if (!checked_add(existing_rva, existing_entry.record.length, existing_end) ||
            !checked_add(rva, entry.record.length, candidate_end)) {
            return workspace_result_t<instruction_acceptance_t>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "instruction overlap range overflow", rva));
        }
        if (rva >= existing_end || candidate_end <= existing_rva)
            continue;
        overlapping_rvas.push_back(existing_rva);
        removed_operands += existing_entry.operands.size();
        removed_targets += existing_entry.targets.size();
        if (!instruction_stronger(entry.record, existing_entry.record)) {
            ++statistics.overlap_instruction_candidates;
            return workspace_result_t<instruction_acceptance_t>::success(
                instruction_acceptance_t{});
        }
    }

    if (!overlapping_rvas.empty())
        ++statistics.overlap_instruction_candidates;

    const auto retained_instructions = total_instructions - overlapping_rvas.size();
    if (retained_instructions >= limits.maximum_instructions) {
        return workspace_result_t<instruction_acceptance_t>::failure(
            limit_error("instructions", limits.maximum_instructions,
                        retained_instructions + 1, rva));
    }
    const auto retained_operands = total_operand_facts - removed_operands;
    const auto retained_targets = total_target_facts - removed_targets;
    if (entry.operands.size() > limits.maximum_operand_facts - retained_operands) {
        return workspace_result_t<instruction_acceptance_t>::failure(
            limit_error("operand_facts", limits.maximum_operand_facts,
                        retained_operands + entry.operands.size(), rva));
    }
    if (entry.targets.size() > limits.maximum_target_facts - retained_targets) {
        return workspace_result_t<instruction_acceptance_t>::failure(
            limit_error("target_facts", limits.maximum_target_facts,
                        retained_targets + entry.targets.size(), rva));
    }

    for (const auto existing_rva : overlapping_rvas) {
        accumulator.instructions.erase(existing_rva);
    }

    auto inserted = accumulator.instructions.emplace(rva, std::move(entry));
    total_instructions = retained_instructions + 1;
    total_operand_facts = retained_operands + inserted.first->second.operands.size();
    total_target_facts = retained_targets + inserted.first->second.targets.size();
    return workspace_result_t<instruction_acceptance_t>::success(
        instruction_acceptance_t{true});
}

workspace_result_t<void> merge_request_coverage(
    tile_accumulator_t& accumulator,
    const tile_decode_records_t& records,
    const tile_decode_request_t& request,
    const tile_decode_orchestrator_limits_t& limits,
    std::uint64_t& total_coverage_spans)
{
    std::vector<coverage_span_t> normalized;
    normalized.reserve(records.coverage.size());

    std::uint64_t request_end = 0;
    if (!checked_add(request.start.value, request.byte_count, request_end)) {
        return workspace_result_t<void>::failure(
            orchestrator_error(workspace_error_code_t::range_overflow,
                "tile decode coverage request range overflow",
                request.start.value));
    }
    const auto owned_end = (std::min)(request_end, request.owned_end_rva);

    for (const auto& span : records.coverage) {
        if (span.size == 0)
            continue;
        if (total_coverage_spans >= limits.maximum_coverage_spans) {
            return workspace_result_t<void>::failure(
                limit_error("coverage_spans", limits.maximum_coverage_spans,
                            total_coverage_spans + 1, span.start.value));
        }
        ++total_coverage_spans;

        if (span.start.space != request.start.space ||
            span.start.architecture != request.start.architecture ||
            span.start.mode != request.start.mode) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decoder returned coverage in the wrong address domain",
                    span.start.value));
        }

        std::uint64_t span_end = 0;
        if (!checked_add(span.start.value, span.size, span_end)) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decoder returned an overflowing coverage span",
                    span.start.value));
        }

        const auto owned_begin = (std::max)(
            request.start.value, accumulator.tile->start_rva);
        const auto clipped_begin = (std::max)(span.start.value, owned_begin);
        const auto clipped_end = (std::min)(span_end, owned_end);
        if (clipped_begin >= clipped_end)
            continue;

        auto clipped = span;
        clipped.start.value = clipped_begin;
        clipped.size = clipped_end - clipped_begin;
        normalized.push_back(std::move(clipped));
    }

    merge_coverage_into(accumulator.coverage, normalized);
    return workspace_result_t<void>::success();
}

class production_tile_decode_executor_t final : public tile_decode_executor_t {
public:
    static workspace_result_t<std::unique_ptr<tile_decode_executor_t>>
        create(production_tile_decode_executor_options_t options,
               const cancellation_token_t& cancellation)
    {
        auto key_validation = validate_arch_decoder_key(options.decoder_key);
        if (!key_validation)
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                key_validation.error());

        if (options.worker_count == 0)
            options.worker_count = 1;

        const auto budget_validation =
            validate_analysis_budget(options.analysis_budget);
        if (!budget_validation) {
            auto error = orchestrator_error(workspace_error_code_t::invalid_argument,
                "production tile decode resource budget is invalid");
            error.details.emplace_back("resource",
                std::string(analysis_resource_kind_name(budget_validation.kind)));
            error.details.emplace_back("reason",
                std::string(budget_validation.stable_code));
            error.details.emplace_back("limit",
                std::to_string(budget_validation.limit));
            error.details.emplace_back("requested",
                std::to_string(budget_validation.requested));
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                std::move(error));
        }
        const auto non_control_worker_slots =
            options.analysis_budget.max_worker_slots -
            options.analysis_budget.reserved_control_worker_slots;
        if (options.worker_count > non_control_worker_slots) {
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                limit_error("worker_slots", non_control_worker_slots,
                    options.worker_count));
        }

        const bool use_x86 =
            (options.decoder_key.architecture == architecture_id_t::x86 ||
             options.decoder_key.architecture == architecture_id_t::x86_64);

        tile_decode_executor_capabilities_t caps;
        caps.decoder_key = options.decoder_key;
        caps.worker_count = options.worker_count;
        caps.maximum_batch_requests = options.analysis_budget.max_queued_tasks;

        if (use_x86) {
            caps.maximum_request_bytes = options.x86_limits.maximum_window_bytes;
            caps.minimum_instruction_bytes = 1;
            caps.maximum_instruction_bytes = 15;
            caps.instruction_alignment = 1;
        } else {
            auto probe = decode::worker_owned_capstone_tile_decoder_t::create(
                options.decoder_key, options.capstone_options, cancellation);
            if (!probe)
                return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                    probe.error());
            const auto& reg = probe.value()->registration();
            caps.maximum_request_bytes = options.capstone_options.tile_limits.maximum_tile_bytes;
            caps.minimum_instruction_bytes = reg.limits.minimum_instruction_bytes;
            caps.maximum_instruction_bytes = reg.limits.maximum_instruction_bytes;
            caps.instruction_alignment = reg.limits.instruction_alignment;
        }

        std::uint64_t maximum_concurrent_window_bytes = 0;
        if (!checked_multiply(caps.maximum_request_bytes, options.worker_count,
                maximum_concurrent_window_bytes) ||
            maximum_concurrent_window_bytes >
                options.analysis_budget.max_mapped_window_bytes) {
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                limit_error("mapped_window_bytes",
                    options.analysis_budget.max_mapped_window_bytes,
                    maximum_concurrent_window_bytes == 0
                        ? (std::numeric_limits<std::uint64_t>::max)()
                        : maximum_concurrent_window_bytes));
        }

        auto* raw = new production_tile_decode_executor_t();
        raw->options_ = std::move(options);
        raw->capabilities_ = caps;
        raw->use_x86_ = use_x86;
        raw->creation_cancellation_ = cancellation;
        std::unique_ptr<tile_decode_executor_t> owned(raw);
        return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::success(
            std::move(owned));
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return capabilities_;
    }

    workspace_result_t<std::vector<tile_decode_completion_t>> execute_batch(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation) override
    {
        if (requests.size() > options_.analysis_budget.max_queued_tasks) {
            return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                limit_error("queued_decode_requests",
                    options_.analysis_budget.max_queued_tasks,
                    static_cast<std::uint64_t>(requests.size())));
        }

        std::uint64_t completion_storage = 0;
        if (!checked_multiply(requests.size(), sizeof(tile_decode_completion_t),
                completion_storage) ||
            completion_storage > options_.analysis_budget.max_private_bytes) {
            return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                limit_error("private_bytes",
                    options_.analysis_budget.max_private_bytes,
                    completion_storage == 0
                        ? (std::numeric_limits<std::uint64_t>::max)()
                        : completion_storage));
        }

        std::vector<tile_decode_completion_t> completions;
        completions.reserve(requests.size());

        if (capabilities_.worker_count <= 1) {
            for (const auto& request : requests) {
                if (cancellation.stop_requested()) {
                    tile_decode_completion_t cancelled;
                    cancelled.request_id = request.request_id;
                    auto err = make_workspace_error(
                        workspace_error_code_t::cancelled,
                        "tile decode batch cancelled", kPhase);
                    err.cancellation = true;
                    cancelled.error = std::move(err);
                    completions.push_back(std::move(cancelled));
                    continue;
                }
                completions.push_back(execute_one(snapshot, request, cancellation));
            }
        } else {
            completions = execute_parallel(snapshot, requests, cancellation);
        }
        auto storage = validate_completion_storage(
            completions, options_.analysis_budget.max_private_bytes);
        if (!storage) {
            return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                storage.error());
        }
        return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
            std::move(completions));
    }

private:
    production_tile_decode_executor_t() = default;

    production_tile_decode_executor_options_t options_;
    tile_decode_executor_capabilities_t capabilities_;
    bool use_x86_ = false;
    cancellation_token_t creation_cancellation_;
    std::unique_ptr<decode::worker_owned_capstone_tile_decoder_t> capstone_decoder_;
    std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86_decoder_;

    tile_decode_completion_t execute_one(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (use_x86_)
            return execute_x86(snapshot, request, cancellation);
        return execute_capstone(snapshot, request, cancellation);
    }

    tile_decode_completion_t execute_capstone(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (!capstone_decoder_) {
            auto created = decode::worker_owned_capstone_tile_decoder_t::create(
                options_.decoder_key, options_.capstone_options, creation_cancellation_);
            if (!created) {
                tile_decode_completion_t completion;
                completion.request_id = request.request_id;
                completion.error = created.error();
                return completion;
            }
            capstone_decoder_ = std::move(created.value());
        }

        decode::capstone_tile_identity_t identity;
        identity.decoder_key = options_.decoder_key;
        identity.start = request.start;
        identity.provider_offset = request.provider_offset;
        identity.runtime_address = request.runtime_address;
        identity.image_base = request.image_base;
        identity.image_size = request.image_size;
        identity.byte_count = request.byte_count;
        identity.snapshot_generation = snapshot.generation();
        identity.stable_source_id = request.stable_source_id;
        identity.provenance = request.provenance;
        identity.confidence = request.confidence;

        auto result = capstone_decoder_->decode_tile(snapshot, identity, cancellation);
        if (!result) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            completion.error = result.error();
            return completion;
        }

        auto decoded = result.take_value();
        tile_decode_completion_t completion;
        completion.request_id = request.request_id;
        completion.records.instructions = std::move(decoded.instructions);
        completion.records.operand_facts = std::move(decoded.operand_facts);
        completion.records.target_facts = std::move(decoded.target_facts);
        completion.records.delay_slot_counts = std::move(decoded.delay_slot_counts);
        completion.records.coverage = std::move(decoded.coverage);
        completion.records.bytes_consumed = decoded.usage.bytes_consumed;
        completion.records.invalid_bytes = decoded.usage.undecodable_bytes;
        return completion;
    }

    tile_decode_completion_t execute_x86(
        const provider_snapshot_t& snapshot,
        const tile_decode_request_t& request,
        const cancellation_token_t& cancellation)
    {
        if (!x86_decoder_) {
            auto created = decode::worker_owned_x86_tile_decoder_t::create(
                options_.decoder_key.mode);
            if (!created) {
                tile_decode_completion_t completion;
                completion.request_id = request.request_id;
                completion.error = created.error();
                return completion;
            }
            x86_decoder_ = std::move(created.value());
        }

        decode::x86_tile_decode_request_t x86_request;
        x86_request.start_address = request.start;
        x86_request.provider_offset = request.provider_offset;
        x86_request.byte_count = request.byte_count;
        x86_request.runtime_address = request.runtime_address;
        x86_request.image_base = request.image_base;
        x86_request.image_size = request.image_size;
        x86_request.provenance = request.provenance;
        x86_request.confidence = request.confidence;
        x86_request.stable_source_id = request.stable_source_id;
        x86_request.limits = options_.x86_limits;

        auto result = x86_decoder_->decode_tile(snapshot, x86_request, cancellation);
        if (!result) {
            tile_decode_completion_t completion;
            completion.request_id = request.request_id;
            completion.error = result.error();
            return completion;
        }

        auto decoded = result.take_value();
        tile_decode_completion_t completion;
        completion.request_id = request.request_id;
        completion.records.instructions = std::move(decoded.instructions);
        completion.records.operand_facts = std::move(decoded.operand_facts);
        completion.records.target_facts = std::move(decoded.target_facts);
        completion.records.coverage = std::move(decoded.coverage);
        completion.records.bytes_consumed = decoded.usage.bytes_consumed;
        completion.records.invalid_bytes = decoded.usage.invalid_bytes;
        completion.records.delay_slot_counts.resize(
            completion.records.instructions.size(), 0);
        return completion;
    }

    std::vector<tile_decode_completion_t> execute_parallel(
        const provider_snapshot_t& snapshot,
        const std::vector<tile_decode_request_t>& requests,
        const cancellation_token_t& cancellation)
    {
        const auto worker_count = (std::min)(
            static_cast<std::size_t>(capabilities_.worker_count),
            requests.size());
        if (worker_count == 0 || requests.empty())
            return {};

        std::vector<std::vector<std::size_t>> partitions(worker_count);
        for (std::size_t i = 0; i < requests.size(); ++i)
            partitions[i % worker_count].push_back(i);

        std::vector<tile_decode_completion_t> results(requests.size());

        auto worker_fn = [&](const std::vector<std::size_t>& indices) {
            std::unique_ptr<decode::worker_owned_capstone_tile_decoder_t> capstone;
            std::unique_ptr<decode::worker_owned_x86_tile_decoder_t> x86;

            if (use_x86_) {
                auto created = decode::worker_owned_x86_tile_decoder_t::create(
                    options_.decoder_key.mode);
                if (!created) {
                    for (auto idx : indices) {
                        tile_decode_completion_t c;
                        c.request_id = requests[idx].request_id;
                        c.error = created.error();
                        results[idx] = std::move(c);
                    }
                    return;
                }
                x86 = std::move(created.value());
            } else {
                auto created = decode::worker_owned_capstone_tile_decoder_t::create(
                    options_.decoder_key, options_.capstone_options,
                    creation_cancellation_);
                if (!created) {
                    for (auto idx : indices) {
                        tile_decode_completion_t c;
                        c.request_id = requests[idx].request_id;
                        c.error = created.error();
                        results[idx] = std::move(c);
                    }
                    return;
                }
                capstone = std::move(created.value());
            }

            for (auto idx : indices) {
                if (cancellation.stop_requested()) {
                    tile_decode_completion_t cancelled;
                    cancelled.request_id = requests[idx].request_id;
                    auto err = make_workspace_error(
                        workspace_error_code_t::cancelled,
                        "tile decode batch cancelled", kPhase);
                    err.cancellation = true;
                    cancelled.error = std::move(err);
                    results[idx] = std::move(cancelled);
                    continue;
                }

                const auto& req = requests[idx];

                if (use_x86_) {
                    decode::x86_tile_decode_request_t xr;
                    xr.start_address = req.start;
                    xr.provider_offset = req.provider_offset;
                    xr.byte_count = req.byte_count;
                    xr.runtime_address = req.runtime_address;
                    xr.image_base = req.image_base;
                    xr.image_size = req.image_size;
                    xr.provenance = req.provenance;
                    xr.confidence = req.confidence;
                    xr.stable_source_id = req.stable_source_id;
                    xr.limits = options_.x86_limits;

                    auto result = x86->decode_tile(snapshot, xr, cancellation);
                    if (!result) {
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.error = result.error();
                        results[idx] = std::move(c);
                    } else {
                        auto decoded = result.take_value();
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.records.instructions = std::move(decoded.instructions);
                        c.records.operand_facts = std::move(decoded.operand_facts);
                        c.records.target_facts = std::move(decoded.target_facts);
                        c.records.coverage = std::move(decoded.coverage);
                        c.records.bytes_consumed = decoded.usage.bytes_consumed;
                        c.records.invalid_bytes = decoded.usage.invalid_bytes;
                        c.records.delay_slot_counts.resize(
                            c.records.instructions.size(), 0);
                        results[idx] = std::move(c);
                    }
                } else {
                    decode::capstone_tile_identity_t identity;
                    identity.decoder_key = options_.decoder_key;
                    identity.start = req.start;
                    identity.provider_offset = req.provider_offset;
                    identity.runtime_address = req.runtime_address;
                    identity.image_base = req.image_base;
                    identity.image_size = req.image_size;
                    identity.byte_count = req.byte_count;
                    identity.snapshot_generation = snapshot.generation();
                    identity.stable_source_id = req.stable_source_id;
                    identity.provenance = req.provenance;
                    identity.confidence = req.confidence;

                    auto result = capstone->decode_tile(snapshot, identity, cancellation);
                    if (!result) {
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.error = result.error();
                        results[idx] = std::move(c);
                    } else {
                        auto decoded = result.take_value();
                        tile_decode_completion_t c;
                        c.request_id = req.request_id;
                        c.records.instructions = std::move(decoded.instructions);
                        c.records.operand_facts = std::move(decoded.operand_facts);
                        c.records.target_facts = std::move(decoded.target_facts);
                        c.records.delay_slot_counts = std::move(decoded.delay_slot_counts);
                        c.records.coverage = std::move(decoded.coverage);
                        c.records.bytes_consumed = decoded.usage.bytes_consumed;
                        c.records.invalid_bytes = decoded.usage.undecodable_bytes;
                        results[idx] = std::move(c);
                    }
                }
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(worker_count);
        for (std::size_t w = 0; w < worker_count; ++w)
            threads.emplace_back(worker_fn, std::cref(partitions[w]));
        for (auto& t : threads)
            t.join();

        return results;
    }
};

}

workspace_result_t<executable_decode_partition_t> partition_executable_decode_ranges(
    const image_layout_index_t& layout,
    const tile_decode_executor_capabilities_t& capabilities,
    const tile_decode_orchestrator_limits_t& limits,
    const cancellation_token_t& cancellation)
{
    if (limits.target_tile_bytes == 0 || limits.maximum_tiles == 0 ||
        capabilities.maximum_request_bytes == 0 ||
        capabilities.maximum_instruction_bytes == 0) {
        return workspace_result_t<executable_decode_partition_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "decode partition limits and capabilities must be non-zero"));
    }

    executable_decode_partition_t partition;

    std::uint32_t range_id = 0;
    std::uint32_t tile_id = 0;

    const auto& mappings = layout.mappings();
    for (const auto& mapping : mappings) {
        if ((mapping.permissions & image_permission_execute) == 0)
            continue;
        if (mapping.virtual_size == 0)
            continue;

        if (cancellation.stop_requested()) {
            auto err = make_workspace_error(
                cancellation.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "partition cancelled", kPhase);
            err.cancellation = !cancellation.deadline_exceeded();
            err.deadline = cancellation.deadline_exceeded();
            return workspace_result_t<executable_decode_partition_t>::failure(
                std::move(err));
        }

        const std::uint64_t initialized = (std::min)(mapping.file_size, mapping.virtual_size);
        const std::uint64_t zero_fill = mapping.virtual_size - initialized;
        std::uint64_t next_initialized = 0;
        std::uint64_t next_zero_fill = 0;
        if (!checked_add(partition.initialized_executable_bytes, initialized,
                         next_initialized) ||
            !checked_add(partition.zero_fill_executable_bytes, zero_fill,
                         next_zero_fill)) {
            return workspace_result_t<executable_decode_partition_t>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "executable decode partition byte accounting overflowed",
                    mapping.rva));
        }
        partition.initialized_executable_bytes = next_initialized;
        partition.zero_fill_executable_bytes = next_zero_fill;

        std::optional<std::uint32_t> initialized_range_id;
        if (initialized != 0) {
            executable_decode_range_t range;
            range.range_id = range_id++;
            range.mapping_id = mapping.id;
            range.start_rva = mapping.rva;
            range.start_virtual_address = mapping.virtual_address;
            range.provider_offset = mapping.file_offset;
            range.byte_count = initialized;
            initialized_range_id = range.range_id;
            partition.ranges.push_back(range);
        }

        if (zero_fill != 0) {
            executable_decode_range_t range;
            range.range_id = range_id++;
            range.mapping_id = mapping.id;
            if (!checked_add(mapping.rva, initialized, range.start_rva) ||
                !checked_add(mapping.virtual_address, initialized,
                             range.start_virtual_address) ||
                !checked_add(mapping.file_offset, initialized,
                             range.provider_offset)) {
                return workspace_result_t<executable_decode_partition_t>::failure(
                    orchestrator_error(workspace_error_code_t::range_overflow,
                        "executable zero-fill range overflowed", mapping.rva));
            }
            range.byte_count = zero_fill;
            partition.zero_fill_ranges.push_back(range);
        }

        std::uint64_t offset = 0;
        std::uint64_t remaining = initialized;
        while (remaining > 0) {
            if (tile_id >= limits.maximum_tiles) {
                return workspace_result_t<executable_decode_partition_t>::failure(
                    limit_error("tiles", limits.maximum_tiles,
                                static_cast<std::uint64_t>(tile_id) + 1,
                                mapping.rva + offset));
            }
            const auto tile_bytes = (std::min)(remaining, limits.target_tile_bytes);

            executable_decode_tile_t tile;
            tile.tile_id = tile_id++;
            tile.shard_id = static_cast<std::uint16_t>(
                (tile_id - 1) > 0xFFFF ? 0xFFFF : (tile_id - 1));
            tile.range_id = *initialized_range_id;
            tile.mapping_id = mapping.id;
            tile.start_rva = mapping.rva + offset;
            tile.start_virtual_address = mapping.virtual_address + offset;
            if (!checked_add(mapping.file_offset, offset, tile.provider_offset)) {
                return workspace_result_t<executable_decode_partition_t>::failure(
                    orchestrator_error(workspace_error_code_t::range_overflow,
                        "executable tile provider range overflowed",
                        mapping.rva + offset));
            }
            tile.byte_count = tile_bytes;
            tile.lookahead_bytes = (remaining > tile_bytes)
                ? (std::min)(static_cast<std::uint64_t>(capabilities.maximum_instruction_bytes),
                             remaining - tile_bytes)
                : 0;

            partition.tiles.push_back(tile);

            offset += tile_bytes;
            remaining -= tile_bytes;
        }
    }

    return workspace_result_t<executable_decode_partition_t>::success(
        std::move(partition));
}

workspace_result_t<std::unique_ptr<tile_decode_executor_t>>
create_production_tile_decode_executor(
    production_tile_decode_executor_options_t options,
    const cancellation_token_t& cancellation)
{
    return production_tile_decode_executor_t::create(std::move(options), cancellation);
}

tile_decode_orchestrator_t::tile_decode_orchestrator_t(
    tile_decode_orchestrator_limits_t limits) noexcept
    : limits_(std::move(limits))
{
}

workspace_result_t<tile_decode_orchestrator_t>
tile_decode_orchestrator_t::create(
    tile_decode_orchestrator_limits_t limits)
{
    if (limits.target_tile_bytes == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "target tile bytes must be non-zero"));
    if (limits.maximum_tiles == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum tiles must be non-zero"));
    if (limits.maximum_tiles >
        static_cast<std::uint64_t>((std::numeric_limits<std::uint16_t>::max)()) + 1ULL)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum tiles exceeds packed shard capacity"));
    if (limits.maximum_frontier_seeds == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum frontier seeds must be non-zero"));
    if (limits.maximum_frontier_wave == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum frontier wave must be non-zero"));
    if (limits.maximum_decode_requests == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "maximum decode requests must be non-zero"));
    if (limits.maximum_instructions == 0 ||
        limits.maximum_operand_facts == 0 ||
        limits.maximum_target_facts == 0 ||
        limits.maximum_edges == 0 ||
        limits.maximum_coverage_spans == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "packed analysis limits must be non-zero"));
    const auto packed_count_limit =
        static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)());
    if (limits.maximum_instructions > packed_count_limit ||
        limits.maximum_operand_facts > packed_count_limit ||
        limits.maximum_target_facts > packed_count_limit ||
        limits.maximum_edges > packed_count_limit ||
        limits.maximum_coverage_spans > packed_count_limit)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "packed analysis limits exceed 32-bit store capacity"));
    if (limits.invalid_run_policy.maximum_gap_resynchronization_bytes == 0 ||
        limits.invalid_run_policy.maximum_invalid_bytes_per_tile == 0 ||
        limits.invalid_run_policy.maximum_invalid_runs_per_tile == 0)
        return workspace_result_t<tile_decode_orchestrator_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "invalid-run policy limits must be non-zero"));

    return workspace_result_t<tile_decode_orchestrator_t>::success(
        tile_decode_orchestrator_t(std::move(limits)));
}

workspace_result_t<tile_decode_orchestration_result_t>
tile_decode_orchestrator_t::run(
    const provider_snapshot_t& snapshot,
    const image_layout_index_t& layout,
    std::vector<tile_decode_seed_t> seeds,
    tile_decode_executor_t& executor,
    const cancellation_token_t& cancellation) const
{
    const auto& caps = executor.capabilities();
    if (caps.maximum_request_bytes == 0 || caps.minimum_instruction_bytes == 0 ||
        caps.maximum_request_bytes < caps.minimum_instruction_bytes ||
        caps.maximum_instruction_bytes < caps.minimum_instruction_bytes ||
        caps.instruction_alignment == 0 ||
        caps.instruction_alignment > caps.maximum_instruction_bytes ||
        caps.worker_count == 0) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "tile decode executor capabilities are invalid"));
    }
    const auto batch_request_limit = caps.maximum_batch_requests == 0
        ? limits_.maximum_frontier_wave
        : (std::min)(limits_.maximum_frontier_wave,
            static_cast<std::uint64_t>(caps.maximum_batch_requests));

    auto partition_result = partition_executable_decode_ranges(
        layout, caps, limits_, cancellation);
    if (!partition_result)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            partition_result.error());
    auto partition = partition_result.take_value();

    std::vector<decode_frontier_tile_t> frontier_tiles;
    frontier_tiles.reserve(partition.tiles.size());
    for (const auto& tile : partition.tiles) {
        decode_frontier_tile_t ft;
        ft.id = tile.tile_id;
        ft.start_rva = tile.start_rva;
        ft.byte_count = tile.byte_count;
        frontier_tiles.push_back(ft);
    }

    auto frontier_build = decode_frontier_t::build(
        std::move(frontier_tiles), limits_.maximum_frontier_seeds);
    if (!frontier_build)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            frontier_build.error());
    auto frontier = frontier_build.take_value();

    std::sort(seeds.begin(), seeds.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.provenance != rhs.provenance)
            return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
        if (lhs.confidence != rhs.confidence)
            return lhs.confidence > rhs.confidence;
        return lhs.stable_source_id < rhs.stable_source_id;
    });

    for (const auto& seed : seeds) {
        decode_frontier_seed_t fs;
        fs.rva = seed.address.value;
        fs.kind = decode_frontier_seed_kind_t::explicit_entry;
        fs.provenance = seed.provenance;
        fs.confidence = seed.confidence;
        fs.stable_source_id = seed.stable_source_id;
        auto add_result = frontier.add_seed(fs);
        if (!add_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                add_result.error());
    }

    if (limits_.seed_executable_range_starts) {
        for (const auto& range : partition.ranges) {
            decode_frontier_seed_t fs;
            fs.rva = range.start_rva;
            fs.kind = decode_frontier_seed_kind_t::range_entry;
            fs.provenance = fact_provenance_t::linear_validation;
            fs.confidence = 80;
            auto add_result = frontier.add_seed(fs);
            if (!add_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    add_result.error());
        }
    }

    std::vector<tile_accumulator_t> accumulators(partition.tiles.size());
    for (std::size_t i = 0; i < partition.tiles.size(); ++i)
        accumulators[i].tile = &partition.tiles[i];

    tile_decode_orchestrator_statistics_t stats;
    stats.initialized_executable_bytes = partition.initialized_executable_bytes;
    stats.zero_fill_executable_bytes = partition.zero_fill_executable_bytes;

    const std::uint64_t image_base = layout.identity().image_base;
    std::uint64_t image_size = 0;
    for (const auto& mapping : layout.mappings()) {
        std::uint64_t mapping_end = 0;
        if (!checked_add(mapping.rva, mapping.virtual_size, mapping_end)) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "image layout virtual range overflowed", mapping.rva));
        }
        image_size = (std::max)(image_size, mapping_end);
    }

    std::uint64_t request_id_counter = 0;
    std::uint64_t total_decode_requests = 0;
    std::uint64_t total_instructions = 0;
    std::uint64_t total_operand_facts = 0;
    std::uint64_t total_target_facts = 0;
    std::uint64_t total_coverage_spans = 0;

    auto process_records = [&](const tile_decode_request_t& request,
                               const tile_decode_records_t& records,
                               bool route_frontier) -> workspace_result_t<void> {
        if (request.tile_id >= accumulators.size() ||
            accumulators[request.tile_id].tile == nullptr ||
            accumulators[request.tile_id].tile->tile_id != request.tile_id) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decode request ownership is invalid", request.start.value));
        }
        if (records.bytes_consumed != request.byte_count ||
            records.invalid_bytes > records.bytes_consumed) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decoder returned a partial or invalid usage record",
                    request.start.value));
        }
        if (!records.delay_slot_counts.empty() &&
            records.delay_slot_counts.size() != records.instructions.size()) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decoder returned misaligned delay-slot metadata",
                    request.start.value));
        }

        auto& accumulator = accumulators[request.tile_id];
        std::set<std::uint64_t> changed_instruction_rvas;
        for (std::size_t instruction_index = 0;
             instruction_index < records.instructions.size(); ++instruction_index) {
            auto entry_result = make_owned_instruction_entry(
                records, instruction_index, request, *accumulator.tile);
            if (!entry_result)
                return workspace_result_t<void>::failure(entry_result.error());
            auto optional_entry = entry_result.take_value();
            if (!optional_entry)
                continue;

            ++stats.decoded_instruction_candidates;
            const auto candidate_rva = optional_entry->record.address.value;
            auto acceptance_result = accept_instruction(
                accumulator, std::move(*optional_entry), limits_, stats,
                total_instructions, total_operand_facts, total_target_facts);
            if (!acceptance_result)
                return workspace_result_t<void>::failure(acceptance_result.error());
            const auto acceptance = acceptance_result.take_value();
            if (!acceptance.accepted)
                continue;

            if (route_frontier)
                changed_instruction_rvas.insert(candidate_rva);
        }

        for (const auto rva : changed_instruction_rvas) {
            const auto retained = accumulator.instructions.find(rva);
            if (retained == accumulator.instructions.end())
                continue;

            const auto& instruction = retained->second.record;

            auto claim_result = frontier.mark_claimed(request.tile_id, rva);
            if (!claim_result)
                return workspace_result_t<void>::failure(claim_result.error());

            if ((instruction.flow_flags & flow_fallthrough) != 0) {
                std::uint64_t fallthrough_rva = 0;
                if (!checked_add(rva, instruction.length, fallthrough_rva)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "instruction fallthrough address overflow", rva));
                }

                decode_frontier_seed_t seed;
                seed.rva = fallthrough_rva;
                seed.kind = decode_frontier_seed_kind_t::fallthrough;
                seed.provenance = instruction.provenance;
                seed.confidence = instruction.confidence;
                seed.stable_source_id = instruction.stable_source_id;
                seed.source_rva = rva;
                auto add_result = frontier.add_seed(seed, request.tile_id);
                if (!add_result)
                    return workspace_result_t<void>::failure(add_result.error());
            }

            for (const auto& target : retained->second.targets) {
                if (!control_flow_target_matches(
                        instruction.flow_flags, target.kind))
                    continue;
                if (target.target.space != address_space_id_t::relative_virtual)
                    continue;
                decode_frontier_seed_t seed;
                seed.rva = target.target.value;
                seed.kind = flow_to_target_seed_kind(instruction.flow_flags);
                seed.provenance = instruction.provenance;
                seed.confidence = instruction.confidence;
                seed.stable_source_id = instruction.stable_source_id;
                seed.source_rva = rva;
                auto add_result = frontier.add_seed(seed, request.tile_id);
                if (!add_result)
                    return workspace_result_t<void>::failure(add_result.error());
            }
        }

        auto coverage_result = merge_request_coverage(
            accumulator, records, request, limits_, total_coverage_spans);
        if (!coverage_result)
            return workspace_result_t<void>::failure(coverage_result.error());

        std::uint64_t next_accumulator_invalid = 0;
        std::uint64_t next_total_invalid = 0;
        if (!checked_add(accumulator.invalid_bytes, records.invalid_bytes,
                         next_accumulator_invalid) ||
            !checked_add(stats.invalid_bytes, records.invalid_bytes,
                         next_total_invalid)) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::limit_exceeded,
                    "invalid byte accounting overflow", request.start.value));
        }
        accumulator.invalid_bytes = next_accumulator_invalid;
        stats.invalid_bytes = next_total_invalid;
        if (records.invalid_bytes > 0) {
            ++accumulator.invalid_runs;
            ++stats.invalid_runs;
        }

        if (accumulator.invalid_bytes >
            limits_.invalid_run_policy.maximum_invalid_bytes_per_tile) {
            return workspace_result_t<void>::failure(
                limit_error("invalid_bytes_per_tile",
                    limits_.invalid_run_policy.maximum_invalid_bytes_per_tile,
                    accumulator.invalid_bytes, request.start.value));
        }
        if (accumulator.invalid_runs >
            limits_.invalid_run_policy.maximum_invalid_runs_per_tile) {
            return workspace_result_t<void>::failure(
                limit_error("invalid_runs_per_tile",
                    limits_.invalid_run_policy.maximum_invalid_runs_per_tile,
                    accumulator.invalid_runs, request.start.value));
        }

        return workspace_result_t<void>::success();
    };

    while (!frontier.empty()) {
        if (cancellation.stop_requested())
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                cancellation_error(cancellation,
                    "orchestrator recursive pass cancelled"));

        auto wave_result = frontier.take_wave(batch_request_limit);
        if (!wave_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                wave_result.error());
        auto wave = wave_result.take_value();
        if (wave.empty())
            break;

        std::vector<tile_decode_request_t> requests;
        requests.reserve(wave.size());

        for (const auto& seed : wave) {
            if (seed.tile_id >= partition.tiles.size())
                continue;

            const auto& tile = partition.tiles[seed.tile_id];
            if (total_decode_requests >= limits_.maximum_decode_requests) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    limit_error("decode_requests", limits_.maximum_decode_requests,
                                total_decode_requests ==
                                        (std::numeric_limits<std::uint64_t>::max)()
                                    ? total_decode_requests
                                    : total_decode_requests + 1,
                                seed.rva));
            }
            if (request_id_counter ==
                (std::numeric_limits<std::uint64_t>::max)()) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    limit_error("request_identifiers", request_id_counter,
                                request_id_counter, seed.rva));
            }

            const std::uint64_t offset_in_tile = seed.rva - tile.start_rva;
            const std::uint64_t remaining = tile.byte_count - offset_in_tile;
            std::uint64_t available_bytes = 0;
            if (!checked_add(remaining, tile.lookahead_bytes, available_bytes)) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::range_overflow,
                        "recursive decode request range overflow", seed.rva));
            }
            const std::uint64_t effective_bytes = (std::min)(
                available_bytes, caps.maximum_request_bytes);
            std::uint64_t provider_offset = 0;
            std::uint64_t runtime_address = 0;
            std::uint64_t owned_end = 0;
            if (!checked_add(tile.provider_offset, offset_in_tile,
                    provider_offset) ||
                !checked_add(tile.start_virtual_address, offset_in_tile,
                    runtime_address) ||
                !checked_add(tile.start_rva, tile.byte_count, owned_end)) {
                return workspace_result_t<
                    tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::range_overflow,
                        "recursive decode request range overflow", seed.rva));
            }

            tile_decode_request_t req;
            req.request_id = request_id_counter++;
            req.tile_id = seed.tile_id;
            req.pass = tile_decode_pass_t::recursive;
            req.seed_kind = seed.kind;
            req.start.space = address_space_id_t::relative_virtual;
            req.start.value = seed.rva;
            req.start.architecture = caps.decoder_key.architecture;
            req.start.mode = caps.decoder_key.mode;
            req.provider_offset = provider_offset;
            req.runtime_address = runtime_address;
            req.image_base = image_base;
            req.image_size = image_size;
            req.byte_count = effective_bytes;
            req.owned_end_rva = owned_end;
            req.stable_source_id = seed.stable_source_id;
            req.provenance = seed.provenance;
            req.confidence = seed.confidence;

            requests.push_back(req);
            ++total_decode_requests;
            ++stats.recursive_requests;
        }

        if (requests.empty())
            continue;

        auto batch_result = execute_correlated_batch(
            executor, snapshot, requests, cancellation,
            "orchestrator recursive batch cancelled");
        if (!batch_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                batch_result.error());
        auto batch = batch_result.take_value();

        for (std::size_t request_index = 0;
             request_index < requests.size(); ++request_index) {
            const auto& completion =
                batch.completions[batch.completion_indices[request_index]];
            auto process_result = process_records(
                requests[request_index], completion.records, true);
            if (!process_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    process_result.error());
        }
    }

    if (cancellation.stop_requested())
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            cancellation_error(cancellation, "orchestrator gap pass cancelled"));

    for (std::size_t tile_index = 0;
         tile_index < partition.tiles.size(); ++tile_index) {
        if (cancellation.stop_requested())
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                cancellation_error(cancellation, "orchestrator gap pass cancelled"));

        auto& accumulator = accumulators[tile_index];
        const auto* tile = accumulator.tile;
        if (tile == nullptr)
            continue;

        std::uint64_t tile_end = 0;
        if (!checked_add(tile->start_rva, tile->byte_count, tile_end)) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "gap decode tile range overflow", tile->start_rva));
        }
        std::uint64_t cursor = tile->start_rva;
        std::vector<tile_decode_request_t> gap_requests;
        const auto flush_gap_requests = [&]() -> workspace_result_t<void> {
            if (gap_requests.empty())
                return workspace_result_t<void>::success();
            auto batch_result = execute_correlated_batch(
                executor, snapshot, gap_requests, cancellation,
                "orchestrator gap batch cancelled");
            if (!batch_result)
                return workspace_result_t<void>::failure(batch_result.error());
            auto batch = batch_result.take_value();
            for (std::size_t request_index = 0;
                 request_index < gap_requests.size(); ++request_index) {
                const auto& completion =
                    batch.completions[batch.completion_indices[request_index]];
                auto process_result = process_records(
                    gap_requests[request_index], completion.records, false);
                if (!process_result)
                    return process_result;
            }
            gap_requests.clear();
            return workspace_result_t<void>::success();
        };

        while (cursor < tile_end) {
            if (cancellation.stop_requested())
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    cancellation_error(cancellation,
                        "orchestrator gap pass cancelled"));

            const auto decoded = accumulator.instructions.find(cursor);
            if (decoded != accumulator.instructions.end()) {
                cursor += decoded->second.record.length;
                continue;
            }

            const auto gap_start = cursor;
            while (cursor < tile_end &&
                   accumulator.instructions.find(cursor) ==
                       accumulator.instructions.end()) {
                if (cancellation.stop_requested()) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        cancellation_error(cancellation,
                            "orchestrator gap pass cancelled"));
                }
                ++cursor;
            }

            const auto gap_length = cursor - gap_start;
            if (gap_length == 0)
                continue;
            const auto request_capacity = (std::min)(
                caps.maximum_request_bytes,
                limits_.invalid_run_policy.maximum_gap_resynchronization_bytes);
            if (request_capacity < caps.minimum_instruction_bytes) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::invalid_argument,
                        "gap resynchronization window is below the decoder minimum",
                        gap_start));
            }
            const auto maximum_lookahead =
                static_cast<std::uint64_t>(caps.maximum_instruction_bytes -
                    caps.instruction_alignment);
            const auto minimum_owned_bytes = (std::min)(
                request_capacity,
                static_cast<std::uint64_t>(caps.instruction_alignment));
            const auto lookahead_reserve = (std::min)(maximum_lookahead,
                request_capacity - minimum_owned_bytes);
            auto owned_capacity = request_capacity - lookahead_reserve;
            if (owned_capacity >= caps.instruction_alignment) {
                owned_capacity -= owned_capacity % caps.instruction_alignment;
            }
            if (owned_capacity == 0) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::invalid_argument,
                        "gap resynchronization window has no aligned ownership",
                        gap_start));
            }

            std::uint64_t gap_offset = 0;
            while (gap_offset < gap_length) {
                if (cancellation.stop_requested()) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        cancellation_error(cancellation,
                            "orchestrator gap pass cancelled"));
                }
                if (total_decode_requests >= limits_.maximum_decode_requests) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        limit_error("decode_requests",
                            limits_.maximum_decode_requests,
                            total_decode_requests ==
                                    (std::numeric_limits<std::uint64_t>::max)()
                                ? total_decode_requests
                                : total_decode_requests + 1,
                            gap_start));
                }
                if (request_id_counter ==
                    (std::numeric_limits<std::uint64_t>::max)()) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        limit_error("request_identifiers", request_id_counter,
                            request_id_counter, gap_start));
                }

                std::uint64_t request_start = 0;
                std::uint64_t offset_in_tile = 0;
                if (!checked_add(gap_start, gap_offset, request_start) ||
                    request_start < tile->start_rva) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::range_overflow,
                            "gap decode request start overflowed", gap_start));
                }
                offset_in_tile = request_start - tile->start_rva;
                const auto remaining_gap_bytes = gap_length - gap_offset;
                const auto owned_bytes = (std::min)(
                    remaining_gap_bytes, owned_capacity);
                const auto lookahead_bytes = (std::min)({
                    remaining_gap_bytes - owned_bytes,
                    request_capacity - owned_bytes,
                    lookahead_reserve});
                std::uint64_t request_bytes = 0;
                std::uint64_t owned_end = 0;
                std::uint64_t provider_offset = 0;
                std::uint64_t runtime_address = 0;
                if (!checked_add(owned_bytes, lookahead_bytes, request_bytes) ||
                    !checked_add(request_start, owned_bytes, owned_end) ||
                    !checked_add(tile->provider_offset, offset_in_tile,
                        provider_offset) ||
                    !checked_add(tile->start_virtual_address, offset_in_tile,
                        runtime_address)) {
                    return workspace_result_t<
                        tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::range_overflow,
                            "gap decode request range overflowed", request_start));
                }

                tile_decode_request_t request;
                request.request_id = request_id_counter++;
                request.tile_id = tile->tile_id;
                request.pass = tile_decode_pass_t::gap;
                request.seed_kind = decode_frontier_seed_kind_t::fallthrough;
                request.start.space = address_space_id_t::relative_virtual;
                request.start.value = request_start;
                request.start.architecture = caps.decoder_key.architecture;
                request.start.mode = caps.decoder_key.mode;
                request.provider_offset = provider_offset;
                request.runtime_address = runtime_address;
                request.image_base = image_base;
                request.image_size = image_size;
                request.byte_count = request_bytes;
                request.owned_end_rva = owned_end;
                request.provenance = fact_provenance_t::gap_recovery;
                request.confidence = 50;

                gap_requests.push_back(request);
                ++total_decode_requests;
                ++stats.gap_requests;
                gap_offset += owned_bytes;
                if (gap_requests.size() >= batch_request_limit) {
                    auto flushed = flush_gap_requests();
                    if (!flushed) {
                        return workspace_result_t<
                            tile_decode_orchestration_result_t>::failure(
                            flushed.error());
                    }
                }
            }
        }

        auto flushed = flush_gap_requests();
        if (!flushed) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                flushed.error());
        }
    }

    struct retained_instruction_t final {
        std::size_t accumulator_index = 0;
        std::uint64_t rva = 0;
        tile_instruction_entry_t* entry = nullptr;
    };
    std::optional<retained_instruction_t> retained_instruction;
    std::vector<std::pair<std::size_t, std::uint64_t>> cross_tile_removals;
    std::uint64_t reconciliation_visits = 0;
    for (std::size_t accumulator_index = 0;
         accumulator_index < accumulators.size(); ++accumulator_index) {
        auto& accumulator = accumulators[accumulator_index];
        for (auto& [rva, entry] : accumulator.instructions) {
            if ((reconciliation_visits++ & 4095ULL) == 0 &&
                cancellation.stop_requested()) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    cancellation_error(cancellation,
                        "cross-tile instruction reconciliation cancelled"));
            }
            if (retained_instruction) {
                std::uint64_t retained_end = 0;
                if (rva < retained_instruction->rva ||
                    !checked_add(retained_instruction->rva,
                        retained_instruction->entry->record.length, retained_end)) {
                    return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "cross-tile instruction order is invalid", rva));
                }
                if (rva < retained_end) {
                    ++stats.overlap_instruction_candidates;
                    if (instruction_stronger(
                            entry.record, retained_instruction->entry->record)) {
                        cross_tile_removals.emplace_back(
                            retained_instruction->accumulator_index,
                            retained_instruction->rva);
                        --total_instructions;
                        total_operand_facts -=
                            retained_instruction->entry->operands.size();
                        total_target_facts -=
                            retained_instruction->entry->targets.size();
                    } else {
                        cross_tile_removals.emplace_back(accumulator_index, rva);
                        --total_instructions;
                        total_operand_facts -= entry.operands.size();
                        total_target_facts -= entry.targets.size();
                        continue;
                    }
                }
            }
            retained_instruction = retained_instruction_t{
                accumulator_index, rva, &entry};
        }
    }
    for (const auto& removal : cross_tile_removals)
        accumulators[removal.first].instructions.erase(removal.second);

    std::set<decoded_edge_key_t, decoded_edge_less_t> accepted_edges;
    std::set<tile_decode_cross_tile_edge_t, cross_tile_edge_less_t>
        unique_cross_tile_edges;

    auto record_edge = [&](decode_tile_id_t source_tile_id,
                           const address_t& source,
                           const address_t& target,
                           edge_kind_t kind) -> workspace_result_t<void> {
        decoded_edge_key_t key;
        key.source = source;
        key.target = target;
        key.kind = kind;

        if (accepted_edges.find(key) != accepted_edges.end()) {
            ++stats.duplicate_edges;
            return workspace_result_t<void>::success();
        }
        if (accepted_edges.size() >= limits_.maximum_edges) {
            return workspace_result_t<void>::failure(
                limit_error("edges", limits_.maximum_edges,
                            static_cast<std::uint64_t>(accepted_edges.size()) + 1,
                            source.value));
        }
        accepted_edges.insert(key);

        if (target.space != address_space_id_t::relative_virtual)
            return workspace_result_t<void>::success();
        const auto target_tile_id = frontier.locate_tile(target.value);
        if (!target_tile_id || *target_tile_id == source_tile_id)
            return workspace_result_t<void>::success();

        tile_decode_cross_tile_edge_t cross_tile_edge;
        cross_tile_edge.source_tile_id = source_tile_id;
        cross_tile_edge.target_tile_id = *target_tile_id;
        cross_tile_edge.source = source;
        cross_tile_edge.target = target;
        cross_tile_edge.kind = kind;
        unique_cross_tile_edges.insert(std::move(cross_tile_edge));
        return workspace_result_t<void>::success();
    };

    for (const auto& accumulator : accumulators) {
        if (accumulator.tile == nullptr)
            continue;
        for (const auto& [rva, entry] : accumulator.instructions) {
            stats.duplicate_edges += entry.duplicate_edge_count;
            if ((entry.record.flow_flags &
                 (flow_branch | flow_call | flow_return | flow_indirect)) != 0) {
                for (const auto& target : entry.targets) {
                    if (!control_flow_target_matches(
                            entry.record.flow_flags, target.kind))
                        continue;
                    auto edge_result = record_edge(
                        accumulator.tile->tile_id, entry.record.address,
                        target.target, flow_to_edge_kind(entry.record.flow_flags));
                    if (!edge_result)
                        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                            edge_result.error());
                }
            }

            if ((entry.record.flow_flags & flow_fallthrough) != 0) {
                std::uint64_t target_rva = 0;
                if (!checked_add(rva, entry.record.length, target_rva)) {
                    return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "instruction fallthrough address overflow", rva));
                }
                const auto target_tile_id = frontier.locate_tile(target_rva);
                if (target_tile_id &&
                    *target_tile_id != accumulator.tile->tile_id) {
                    auto target = entry.record.address;
                    target.value = target_rva;
                    auto edge_result = record_edge(
                        accumulator.tile->tile_id, entry.record.address,
                        target, edge_kind_t::fallthrough);
                    if (!edge_result)
                        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                            edge_result.error());
                }
            }
        }
    }

    stats.accepted_instructions = total_instructions;
    stats.accepted_operands = total_operand_facts;
    stats.accepted_target_facts = total_target_facts;
    stats.accepted_edges = accepted_edges.size();
    stats.cross_tile_edges = unique_cross_tile_edges.size();

    std::vector<tile_decode_cross_tile_edge_t> cross_tile_edges(
        unique_cross_tile_edges.begin(), unique_cross_tile_edges.end());

    std::vector<packed_analysis_shard_t> shards;
    std::vector<tile_decode_shard_summary_t> shard_summaries;
    std::vector<coverage_span_t> merged_coverage;
    std::vector<std::uint8_t> merged_delay_slot_counts;
    merged_delay_slot_counts.reserve(static_cast<std::size_t>(total_instructions));

    for (std::size_t tile_idx = 0; tile_idx < partition.tiles.size(); ++tile_idx) {
        if (cancellation.stop_requested())
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                cancellation_error(cancellation,
                    "orchestrator shard build cancelled"));

        const auto& acc = accumulators[tile_idx];
        if (!acc.tile)
            continue;

        packed_analysis_shard_builder_t builder(acc.tile->shard_id);

        std::uint64_t instruction_source_id = 1;
        std::uint64_t address_expression_source_id = 1;
        std::uint32_t instruction_count = 0;
        std::uint32_t operand_count = 0;
        std::uint32_t target_count = 0;
        std::uint32_t edge_count = 0;
        entity_id_t coverage_source_id = 1;

        for (const auto& [rva, entry] : acc.instructions) {
            packed_instruction_input_t instr_input;
            instr_input.source_id = instruction_source_id;
            instr_input.address = entry.record.address;
            instr_input.length = entry.record.length;
            instr_input.mnemonic_id = entry.record.mnemonic_id;
            instr_input.opcode_id = entry.record.opcode_id;
            instr_input.flow_flags = entry.record.flow_flags;
            instr_input.provenance = entry.record.provenance;
            instr_input.confidence = entry.record.confidence;
            instr_input.coverage = entry.record.coverage;
            instr_input.stable_source_id = entry.record.stable_source_id;

            auto instr_result = builder.add_instruction(instr_input);
            if (!instr_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store instruction add failed", rva));

            std::map<entity_id_t, entity_id_t> operand_source_ids;
            std::map<std::uint8_t, entity_id_t> operand_index_source_ids;
            std::map<entity_id_t, entity_id_t> address_expression_source_ids;
            std::map<entity_id_t, entity_id_t> operand_expression_source_ids;
            std::map<std::uint8_t, entity_id_t>
                operand_index_expression_source_ids;
            for (const auto& op : entry.operands) {
                packed_operand_input_t op_input;
                op_input.source_id = static_cast<entity_id_t>(operand_count + 1);
                op_input.instruction = packed_entity_reference_t::local(
                    packed_entity_domain_t::instruction, instruction_source_id);
                entity_id_t expression_source_id = 0;
                const auto existing_expression =
                    address_expression_source_ids.find(op.address_expression_id);
                if (op.address_expression_id != 0 &&
                    existing_expression != address_expression_source_ids.end()) {
                    expression_source_id = existing_expression->second;
                } else if (op.address_expression_id != 0 ||
                           op.address_expression != address_expression_kind_t::none ||
                           op.address_components != address_component_none) {
                    expression_source_id = address_expression_source_id++;
                    packed_address_expression_input_t expression_input;
                    expression_input.source_id = expression_source_id;
                    expression_input.instruction = packed_entity_reference_t::local(
                        packed_entity_domain_t::instruction, instruction_source_id);
                    expression_input.base_reg = op.base_reg;
                    expression_input.index_reg = op.index_reg;
                    expression_input.scale = op.scale;
                    expression_input.displacement = op.displacement;
                    expression_input.segment_reg = op.segment_reg;
                    expression_input.address_components = op.address_components;
                    expression_input.kind = op.address_expression;
                    expression_input.resolution = op.address_resolution;
                    expression_input.provenance = entry.record.provenance;
                    expression_input.confidence = entry.record.confidence;
                    auto expression_result =
                        builder.add_address_expression(expression_input);
                    if (!expression_result) {
                        return workspace_result_t<
                            tile_decode_orchestration_result_t>::failure(
                            orchestrator_error(
                                workspace_error_code_t::integrity_failure,
                                "packed store address expression add failed", rva));
                    }
                    if (op.address_expression_id != 0) {
                        address_expression_source_ids.emplace(
                            op.address_expression_id, expression_source_id);
                    }
                }
                if (expression_source_id != 0) {
                    op_input.address_expression =
                        packed_entity_reference_t::local(
                            packed_entity_domain_t::address_expression,
                            expression_source_id);
                    if (op.id != 0) {
                        operand_expression_source_ids.emplace(
                            op.id, expression_source_id);
                    }
                    operand_index_expression_source_ids.emplace(
                        op.operand_index, expression_source_id);
                }
                op_input.operand_index = op.operand_index;
                op_input.decoder_operand_id = op.decoder_operand_id;
                op_input.kind = op.kind;
                op_input.access = op.access;
                op_input.visibility = op.visibility;
                op_input.encoding = op.encoding;
                op_input.memory_type = op.memory_type;
                op_input.access_width = op.access_width;
                op_input.bit_width = op.bit_width;
                op_input.access_width_bits = op.access_width_bits;
                op_input.access_count = op.access_count;
                op_input.element_width_bits = op.element_width_bits;
                op_input.element_count = op.element_count;
                op_input.address_width_bits = op.address_width_bits;
                op_input.reg = op.reg;
                op_input.segment_reg = op.segment_reg;
                op_input.base_reg = op.base_reg;
                op_input.index_reg = op.index_reg;
                op_input.scale = op.scale;
                op_input.relative = op.relative;
                op_input.signed_value = op.signed_value;
                op_input.has_displacement = op.has_displacement;
                op_input.has_resolved_expression_value = op.has_resolved_expression_value;
                op_input.displacement = op.displacement;
                op_input.immediate = op.immediate;
                op_input.resolved_expression_value = op.resolved_expression_value;
                op_input.address_components = op.address_components;
                op_input.address_expression_kind = op.address_expression;
                op_input.address_resolution = op.address_resolution;

                auto op_result = builder.add_operand(op_input);
                if (!op_result)
                    return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "packed store operand add failed", rva));

                if (op.id != 0)
                    operand_source_ids.emplace(op.id, op_input.source_id);
                operand_index_source_ids.emplace(op.operand_index, op_input.source_id);
                ++operand_count;
            }

            for (const auto& target : entry.targets) {
                packed_target_fact_input_t target_input;
                target_input.source_id = static_cast<entity_id_t>(target_count + 1);
                target_input.instruction = packed_entity_reference_t::local(
                    packed_entity_domain_t::instruction, instruction_source_id);
                const auto source_by_id = operand_source_ids.find(target.operand_fact_id);
                const auto source_by_index = operand_index_source_ids.find(target.operand_index);
                if (source_by_id != operand_source_ids.end()) {
                    target_input.operand = packed_entity_reference_t::local(
                        packed_entity_domain_t::operand, source_by_id->second);
                } else if (source_by_index != operand_index_source_ids.end()) {
                    target_input.operand = packed_entity_reference_t::local(
                        packed_entity_domain_t::operand, source_by_index->second);
                }
                entity_id_t target_expression_source_id = 0;
                const auto by_expression_id =
                    address_expression_source_ids.find(
                        target.address_expression_id);
                if (by_expression_id != address_expression_source_ids.end()) {
                    target_expression_source_id = by_expression_id->second;
                } else {
                    const auto by_operand_id =
                        operand_expression_source_ids.find(
                            target.operand_fact_id);
                    if (by_operand_id != operand_expression_source_ids.end())
                        target_expression_source_id = by_operand_id->second;
                }
                if (target_expression_source_id == 0) {
                    const auto by_index = operand_index_expression_source_ids.find(
                        target.operand_index);
                    if (by_index != operand_index_expression_source_ids.end())
                        target_expression_source_id = by_index->second;
                }
                if (target_expression_source_id != 0) {
                    target_input.address_expression =
                        packed_entity_reference_t::local(
                            packed_entity_domain_t::address_expression,
                            target_expression_source_id);
                }
                target_input.target = target.target;
                target_input.kind = target.kind;
                target_input.resolution = target.resolution;
                target_input.operand_index = target.operand_index;
                target_input.access_width_bits = target.access_width_bits;
                target_input.access_count = target.access_count;
                target_input.direct = target.direct;
                target_input.is_external = target.is_external;
                target_input.provenance = entry.record.provenance;
                target_input.confidence = entry.record.confidence;

                auto target_result = builder.add_target_fact(target_input);
                if (!target_result)
                    return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "packed store target fact add failed", rva));

                ++target_count;
            }

            if ((entry.record.flow_flags & (flow_branch | flow_call | flow_return | flow_indirect)) != 0) {
                for (const auto& target : entry.targets) {
                    if (!control_flow_target_matches(
                            entry.record.flow_flags, target.kind))
                        continue;
                    packed_edge_input_t edge_input;
                    edge_input.source_id = static_cast<entity_id_t>(edge_count + 1);
                    edge_input.source_entity = packed_entity_reference_t::local(
                        packed_entity_domain_t::instruction, instruction_source_id);
                    edge_input.source = entry.record.address;
                    edge_input.target = target.target;
                    edge_input.kind = flow_to_edge_kind(entry.record.flow_flags);
                    edge_input.provenance = entry.record.provenance;
                    edge_input.confidence = entry.record.confidence;

                    auto edge_result = builder.add_edge(edge_input);
                    if (!edge_result)
                        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                            orchestrator_error(workspace_error_code_t::integrity_failure,
                                "packed store edge add failed", rva));

                    ++edge_count;
                }
            }

            ++instruction_source_id;
            ++instruction_count;
            merged_delay_slot_counts.push_back(entry.delay_slots);
        }

        for (const auto& span : acc.coverage) {
            packed_coverage_input_t cov_input;
            cov_input.source_id = coverage_source_id++;
            cov_input.span_begin = span.start;
            cov_input.span_end = span.start;
            if (!checked_add(span.start.value, span.size,
                             cov_input.span_end.value)) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store coverage range overflow", span.start.value));
            }
            cov_input.reason = span.reason;
            cov_input.undecodable_count = span.detail_code;
            cov_input.provenance = span.provenance;
            cov_input.confidence = span.confidence;

            auto cov_result = builder.add_coverage(cov_input);
            if (!cov_result)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store coverage add failed"));

            merged_coverage.push_back(span);
        }

        auto shard_result = std::move(builder).finalize();
        if (!shard_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store shard finalize failed"));

        shards.push_back(std::move(shard_result).take_value());

        tile_decode_shard_summary_t summary;
        summary.tile_id = acc.tile->tile_id;
        summary.shard_id = acc.tile->shard_id;
        summary.instruction_count = instruction_count;
        summary.operand_count = operand_count;
        summary.target_count = target_count;
        summary.edge_count = edge_count;
        shard_summaries.push_back(summary);
    }

    auto store_result = packed_analysis_store_t::merge(std::move(shards));
    if (!store_result)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "packed store merge failed"));

    for (const auto& range : partition.zero_fill_ranges) {
        if (total_coverage_spans >= limits_.maximum_coverage_spans) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                limit_error("coverage_spans", limits_.maximum_coverage_spans,
                    total_coverage_spans + 1, range.start_rva));
        }
        ++total_coverage_spans;
        coverage_span_t span;
        span.start.space = address_space_id_t::relative_virtual;
        span.start.architecture = caps.decoder_key.architecture;
        span.start.mode = caps.decoder_key.mode;
        span.start.value = range.start_rva;
        span.size = range.byte_count;
        span.reason = coverage_reason_t::undecodable;
        span.provenance = fact_provenance_t::linear_validation;
        span.confidence = 100;
        span.detail_code = static_cast<std::uint32_t>(tile_coverage_detail_t::zero_fill);
        merged_coverage.push_back(std::move(span));
    }

    merge_coverage_into(merged_coverage, {});

    std::sort(shard_summaries.begin(), shard_summaries.end(),
              [](const auto& a, const auto& b) { return a.tile_id < b.tile_id; });

    stats.frontier = frontier.snapshot();

    tile_decode_orchestration_result_t result;
    result.packed_store = std::make_unique<packed_analysis_store_t>(
        std::move(store_result).take_value());
    result.delay_slot_counts = std::move(merged_delay_slot_counts);
    result.coverage = std::move(merged_coverage);
    result.cross_tile_edges = std::move(cross_tile_edges);
    result.shards = std::move(shard_summaries);
    result.statistics = stats;

    return workspace_result_t<tile_decode_orchestration_result_t>::success(
        std::move(result));
}

}
