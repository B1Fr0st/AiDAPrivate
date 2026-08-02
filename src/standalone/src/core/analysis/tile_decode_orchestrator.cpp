#include "tile_decode_orchestrator.hpp"

#include "decode_worker_pool.hpp"
#include "workspace/parallel_pass.hpp"

#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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

std::uint32_t next_pow2(std::uint64_t value) noexcept
{
    std::uint64_t capacity = 1;
    while (capacity < value && capacity < (1ULL << 32))
        capacity <<= 1;
    return static_cast<std::uint32_t>(capacity);
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

bool stronger_claim(const decode_frontier_claim_t& left,
                    const decode_frontier_claim_t& right) noexcept
{
    const auto left_provenance = provenance_rank(left.provenance);
    const auto right_provenance = provenance_rank(right.provenance);
    if (left_provenance != right_provenance)
        return left_provenance > right_provenance;
    if (left.confidence != right.confidence)
        return left.confidence > right.confidence;
    return left.stable_source_id < right.stable_source_id;
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

struct coverage_span_less_t final {
    bool operator()(const coverage_span_t& a, const coverage_span_t& b) const noexcept
    {
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
    }
};

void stitch_sorted_coverage(std::vector<coverage_span_t>& dest)
{
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

struct tile_instruction_entry_t {
    instruction_record_t record;
    std::uint32_t operand_begin = 0;
    std::uint32_t operand_count = 0;
    std::uint32_t target_begin = 0;
    std::uint32_t target_count = 0;
    std::uint8_t delay_slots = 0;
    std::uint64_t duplicate_edge_count = 0;
    bool evicted = false;
    bool committed = false;
};

struct tile_instruction_index_t final {
    static constexpr std::uint32_t npos = 0xFFFFFFFFu;
    static constexpr std::uint32_t invalid = 0xFFFFFFFEu;

    std::vector<std::uint64_t> keys;
    std::vector<std::uint32_t> values;
    std::uint32_t size = 0;
    std::uint32_t mask = 0;

    std::uint32_t find(std::uint64_t rva) const noexcept
    {
        if (keys.empty())
            return npos;
        const std::uint64_t key = rva + 1;
        std::uint32_t slot = static_cast<std::uint32_t>(
            (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
        for (;;) {
            const auto current = keys[slot];
            if (current == 0)
                return npos;
            if (current == key && values[slot] != invalid)
                return values[slot];
            slot = (slot + 1) & mask;
        }
    }

    void insert(std::uint64_t rva, std::uint32_t value)
    {
        if (keys.empty()) {
            keys.assign(64, 0);
            values.assign(64, invalid);
            mask = 63;
        } else if ((static_cast<std::uint64_t>(size) + 1ULL) * 10ULL >=
                   static_cast<std::uint64_t>(keys.size()) * 7ULL) {
            grow();
        }
        const std::uint64_t key = rva + 1;
        std::uint32_t slot = static_cast<std::uint32_t>(
            (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
        while (keys[slot] != 0)
            slot = (slot + 1) & mask;
        keys[slot] = key;
        values[slot] = value;
        ++size;
    }

    void invalidate(std::uint64_t rva) noexcept
    {
        if (keys.empty())
            return;
        const std::uint64_t key = rva + 1;
        std::uint32_t slot = static_cast<std::uint32_t>(
            (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
        for (;;) {
            const auto current = keys[slot];
            if (current == 0)
                return;
            if (current == key) {
                if (values[slot] != invalid) {
                    values[slot] = invalid;
                    --size;
                }
                return;
            }
            slot = (slot + 1) & mask;
        }
    }

    void rebuild(std::size_t live_count)
    {
        const auto capacity = next_pow2((std::max)(64ULL,
            static_cast<std::uint64_t>(live_count) * 2ULL));
        keys.assign(capacity, 0);
        values.assign(capacity, invalid);
        mask = capacity - 1;
        size = 0;
    }

    void grow()
    {
        std::vector<std::uint64_t> previous_keys = std::move(keys);
        std::vector<std::uint32_t> previous_values = std::move(values);
        const std::size_t capacity = previous_keys.size() * 2;
        keys.assign(capacity, 0);
        values.assign(capacity, invalid);
        mask = static_cast<std::uint32_t>(capacity - 1);
        size = 0;
        for (std::size_t index = 0; index < previous_keys.size(); ++index) {
            const auto key = previous_keys[index];
            if (key == 0)
                continue;
            std::uint32_t slot = static_cast<std::uint32_t>(
                (key * 0x9E3779B97F4A7C15ULL) >> 32) & mask;
            while (keys[slot] != 0)
                slot = (slot + 1) & mask;
            keys[slot] = key;
            values[slot] = previous_values[index];
            if (previous_values[index] != invalid)
                ++size;
        }
    }
};

struct tile_accumulator_t {
    const executable_decode_tile_t* tile = nullptr;
    std::vector<tile_instruction_entry_t> entries;
    tile_instruction_index_t index;
    std::vector<operand_fact_t> operand_arena;
    std::vector<target_fact_t> target_arena;
    std::vector<coverage_span_t> coverage;
    std::uint64_t max_end_seen = 0;
    std::uint64_t invalid_bytes = 0;
    std::uint64_t invalid_runs = 0;
    bool sorted = false;
    bool coverage_sorted = false;

    const operand_fact_t* operands_of(
        const tile_instruction_entry_t& entry) const noexcept
    {
        if (entry.operand_count == 0)
            return nullptr;
        return operand_arena.data() + entry.operand_begin;
    }

    const target_fact_t* targets_of(
        const tile_instruction_entry_t& entry) const noexcept
    {
        if (entry.target_count == 0)
            return nullptr;
        return target_arena.data() + entry.target_begin;
    }
};

void ensure_tile_sorted(tile_accumulator_t& accumulator)
{
    if (!accumulator.sorted) {
        std::sort(accumulator.entries.begin(), accumulator.entries.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.record.address.value < rhs.record.address.value;
            });
        accumulator.index.rebuild(accumulator.entries.size());
        for (std::uint32_t slot = 0;
             slot < static_cast<std::uint32_t>(accumulator.entries.size()); ++slot) {
            if (accumulator.entries[slot].evicted)
                continue;
            accumulator.index.insert(
                accumulator.entries[slot].record.address.value, slot);
        }
        accumulator.sorted = true;
    }
    if (!accumulator.coverage_sorted) {
        std::sort(accumulator.coverage.begin(), accumulator.coverage.end(),
            coverage_span_less_t{});
        stitch_sorted_coverage(accumulator.coverage);
        accumulator.coverage_sorted = true;
    }
}

struct correlated_tile_decode_batch_t final {
    std::vector<tile_decode_completion_t> completions;
    std::vector<std::size_t> completion_indices;
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
    std::sort(dest.begin(), dest.end(), coverage_span_less_t{});
    stitch_sorted_coverage(dest);
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
make_owned_instruction_entry(tile_accumulator_t& accumulator,
                             const tile_decode_records_t& records,
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

    if (accumulator.operand_arena.capacity() == 0) {
        const std::uint64_t instruction_estimate =
            tile.byte_count / 4ULL + 1ULL;
        const std::uint64_t operand_reserve = (std::min)(
            instruction_estimate * 3ULL, 262'144ULL);
        const std::uint64_t target_reserve = (std::min)(
            instruction_estimate * 2ULL, 262'144ULL);
        accumulator.operand_arena.reserve(
            static_cast<std::size_t>(operand_reserve));
        accumulator.target_arena.reserve(
            static_cast<std::size_t>(target_reserve));
    }
    if (operand_count >
            (std::numeric_limits<std::uint32_t>::max)() -
                accumulator.operand_arena.size() ||
        target_count >
            (std::numeric_limits<std::uint32_t>::max)() -
                accumulator.target_arena.size()) {
        return workspace_result_t<std::optional<tile_instruction_entry_t>>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile instruction arena capacity is exhausted", rva));
    }

    tile_instruction_entry_t entry;
    entry.record = instruction;
    if (!records.delay_slot_counts.empty())
        entry.delay_slots = records.delay_slot_counts[instruction_index];

    entry.operand_begin =
        static_cast<std::uint32_t>(accumulator.operand_arena.size());
    accumulator.operand_arena.insert(accumulator.operand_arena.end(),
        records.operand_facts.begin() + operand_begin,
        records.operand_facts.begin() + operand_begin + operand_count);
    entry.operand_count = static_cast<std::uint32_t>(operand_count);

    entry.target_begin =
        static_cast<std::uint32_t>(accumulator.target_arena.size());
    accumulator.target_arena.insert(accumulator.target_arena.end(),
        records.target_facts.begin() + target_begin,
        records.target_facts.begin() + target_begin + target_count);

    auto* const slice = accumulator.target_arena.data() + entry.target_begin;
    std::sort(slice, slice + target_count, target_less);
    std::uint32_t unique_count = 0;
    for (std::uint32_t index = 0; index < target_count; ++index) {
        if (unique_count != 0 &&
            !target_less(slice[unique_count - 1], slice[index]) &&
            !target_less(slice[index], slice[unique_count - 1])) {
            ++entry.duplicate_edge_count;
            continue;
        }
        if (unique_count != index)
            slice[unique_count] = std::move(slice[index]);
        ++unique_count;
    }
    entry.target_count = unique_count;

    return workspace_result_t<std::optional<tile_instruction_entry_t>>::success(
        std::optional<tile_instruction_entry_t>(std::move(entry)));
}

struct decode_ledger_t final {
    std::atomic<std::uint64_t> instructions{0};
    std::atomic<std::uint64_t> operand_facts{0};
    std::atomic<std::uint64_t> target_facts{0};
    std::atomic<std::uint64_t> coverage_spans{0};
    std::atomic<std::uint64_t> decode_requests{0};

    static bool reserve_counter(std::atomic<std::uint64_t>& counter,
        std::uint64_t removed, std::uint64_t added, std::uint64_t maximum) noexcept
    {
        auto current = counter.load(std::memory_order_relaxed);
        for (;;) {
            const auto retained = current - removed;
            if (added > maximum - retained)
                return false;
            if (counter.compare_exchange_weak(current, retained + added,
                    std::memory_order_acq_rel))
                return true;
        }
    }

    static void release_counter(std::atomic<std::uint64_t>& counter,
        std::uint64_t removed, std::uint64_t added) noexcept
    {
        auto current = counter.load(std::memory_order_relaxed);
        while (!counter.compare_exchange_weak(current, current + removed - added,
                std::memory_order_acq_rel)) {
        }
    }

    workspace_result_t<void> reserve_instruction(
        const tile_decode_orchestrator_limits_t& limits,
        std::uint64_t removed_instructions,
        std::uint64_t removed_operands,
        std::uint64_t removed_targets,
        std::uint64_t added_instructions,
        std::uint64_t added_operands,
        std::uint64_t added_targets,
        std::uint64_t rva)
    {
        if (!reserve_counter(instructions, removed_instructions, added_instructions,
                limits.maximum_instructions)) {
            return workspace_result_t<void>::failure(
                limit_error("instructions", limits.maximum_instructions,
                    instructions.load(std::memory_order_acquire) -
                        removed_instructions + added_instructions, rva));
        }
        if (!reserve_counter(operand_facts, removed_operands, added_operands,
                limits.maximum_operand_facts)) {
            release_counter(instructions, removed_instructions, added_instructions);
            return workspace_result_t<void>::failure(
                limit_error("operand_facts", limits.maximum_operand_facts,
                    operand_facts.load(std::memory_order_acquire) -
                        removed_operands + added_operands, rva));
        }
        if (!reserve_counter(target_facts, removed_targets, added_targets,
                limits.maximum_target_facts)) {
            release_counter(operand_facts, removed_operands, added_operands);
            release_counter(instructions, removed_instructions, added_instructions);
            return workspace_result_t<void>::failure(
                limit_error("target_facts", limits.maximum_target_facts,
                    target_facts.load(std::memory_order_acquire) -
                        removed_targets + added_targets, rva));
        }
        return workspace_result_t<void>::success();
    }
};

struct tile_accept_deltas_t final {
    std::uint64_t removed_committed_instructions = 0;
    std::uint64_t removed_committed_operands = 0;
    std::uint64_t removed_committed_targets = 0;
    std::uint64_t added_instructions = 0;
    std::uint64_t added_operands = 0;
    std::uint64_t added_targets = 0;
    std::uint64_t last_accepted_rva = 0;
    std::vector<std::uint32_t> touched_slots;

    bool any() const noexcept
    {
        return removed_committed_instructions != 0 ||
               removed_committed_operands != 0 ||
               removed_committed_targets != 0 ||
               added_instructions != 0 ||
               added_operands != 0 ||
               added_targets != 0;
    }
};

workspace_result_t<bool> accept_instruction(
    std::uint16_t maximum_instruction_bytes,
    tile_accumulator_t& accumulator,
    tile_instruction_entry_t entry,
    tile_decode_orchestrator_statistics_t& statistics,
    tile_accept_deltas_t& deltas)
{
    const auto rva = entry.record.address.value;
    const auto existing_slot = accumulator.index.find(rva);
    if (existing_slot != tile_instruction_index_t::npos) {
        ++statistics.duplicate_instruction_candidates;
        auto& existing = accumulator.entries[existing_slot];
        if (!instruction_stronger(entry.record, existing.record))
            return workspace_result_t<bool>::success(false);

        std::uint64_t candidate_end = 0;
        if (!checked_add(rva, entry.record.length, candidate_end)) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "instruction overlap range overflow", rva));
        }
        if (existing.committed) {
            deltas.removed_committed_instructions += 1;
            deltas.removed_committed_operands += existing.operand_count;
            deltas.removed_committed_targets += existing.target_count;
            deltas.touched_slots.push_back(existing_slot);
        }
        existing = std::move(entry);
        accumulator.sorted = false;
        if (candidate_end > accumulator.max_end_seen)
            accumulator.max_end_seen = candidate_end;
        deltas.last_accepted_rva = rva;
        return workspace_result_t<bool>::success(true);
    }

    std::uint64_t candidate_end = 0;
    if (!checked_add(rva, entry.record.length, candidate_end)) {
        return workspace_result_t<bool>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "instruction overlap range overflow", rva));
    }

    std::vector<std::uint32_t> overlapping_slots;
    if (rva < accumulator.max_end_seen) {
        const std::uint64_t window_begin =
            rva >= static_cast<std::uint64_t>(maximum_instruction_bytes - 1)
                ? rva - static_cast<std::uint64_t>(maximum_instruction_bytes - 1)
                : 0;
        for (std::uint64_t probe = window_begin; probe < candidate_end; ++probe) {
            const auto slot = accumulator.index.find(probe);
            if (slot == tile_instruction_index_t::npos)
                continue;
            const auto& existing = accumulator.entries[slot];
            const std::uint64_t existing_rva = existing.record.address.value;
            if (existing_rva == rva)
                continue;
            std::uint64_t existing_end = 0;
            if (!checked_add(existing_rva, existing.record.length, existing_end)) {
                return workspace_result_t<bool>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "instruction overlap range overflow", rva));
            }
            if (rva >= existing_end || candidate_end <= existing_rva)
                continue;
            overlapping_slots.push_back(slot);
            if (!instruction_stronger(entry.record, existing.record)) {
                ++statistics.overlap_instruction_candidates;
                return workspace_result_t<bool>::success(false);
            }
        }
    }

    if (!overlapping_slots.empty())
        ++statistics.overlap_instruction_candidates;

    for (const auto slot : overlapping_slots) {
        auto& evicted_entry = accumulator.entries[slot];
        if (evicted_entry.committed) {
            deltas.removed_committed_instructions += 1;
            deltas.removed_committed_operands += evicted_entry.operand_count;
            deltas.removed_committed_targets += evicted_entry.target_count;
        }
        evicted_entry.evicted = true;
        accumulator.index.invalidate(evicted_entry.record.address.value);
    }

    const auto new_slot = static_cast<std::uint32_t>(accumulator.entries.size());
    deltas.touched_slots.push_back(new_slot);
    accumulator.entries.push_back(std::move(entry));
    accumulator.index.insert(rva, new_slot);
    accumulator.sorted = false;
    if (candidate_end > accumulator.max_end_seen)
        accumulator.max_end_seen = candidate_end;
    deltas.last_accepted_rva = rva;
    return workspace_result_t<bool>::success(true);
}

workspace_result_t<void> merge_request_coverage(
    decode_ledger_t& ledger,
    tile_accumulator_t& accumulator,
    const tile_decode_records_t& records,
    const tile_decode_request_t& request,
    const tile_decode_orchestrator_limits_t& limits)
{
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
        const auto consumed =
            ledger.coverage_spans.fetch_add(1, std::memory_order_acq_rel);
        if (consumed >= limits.maximum_coverage_spans) {
            return workspace_result_t<void>::failure(
                limit_error("coverage_spans", limits.maximum_coverage_spans,
                    consumed + 1, span.start.value));
        }

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
        accumulator.coverage.push_back(std::move(clipped));
        accumulator.coverage_sorted = false;
    }

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

        auto pool = decode_worker_pool_t::create(options.worker_count, options,
            options.maximum_frontier_wave, cancellation);
        if (!pool)
            return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::failure(
                pool.error());

        auto* raw = new production_tile_decode_executor_t();
        raw->options_ = std::move(options);
        raw->capabilities_ = caps;
        raw->pool_ = std::move(pool.value());
        std::unique_ptr<tile_decode_executor_t> owned(raw);
        return workspace_result_t<std::unique_ptr<tile_decode_executor_t>>::success(
            std::move(owned));
    }

    const tile_decode_executor_capabilities_t& capabilities() const noexcept override
    {
        return capabilities_;
    }

    decode_worker_pool_t* pool() noexcept
    {
        return pool_.get();
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
        if (requests.empty()) {
            return workspace_result_t<std::vector<tile_decode_completion_t>>::success(
                std::move(completions));
        }

        pool_->bind_snapshot(snapshot);
        const auto worker_count = (std::max)(pool_->worker_count(), 1U);
        const auto slot_modulus = (std::min)(worker_count,
            decode_worker_pool_t::maximum_shard_slots);

        std::unordered_map<std::uint64_t, std::size_t> index_of;
        index_of.reserve(requests.size());
        for (std::size_t index = 0; index < requests.size(); ++index) {
            if (!index_of.emplace(requests[index].request_id, index).second) {
                auto error = orchestrator_error(
                    workspace_error_code_t::integrity_failure,
                    "tile decode batch contains duplicate request identifiers");
                error.details.emplace_back("request_id",
                    std::to_string(requests[index].request_id));
                return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                    std::move(error));
            }
        }

        for (std::size_t index = 0; index < requests.size(); ++index) {
            decode_work_item_t item;
            item.request = requests[index];
            item.shard_index = static_cast<std::uint32_t>(index % slot_modulus);
            auto submitted = pool_->submit(
                static_cast<std::uint32_t>(index % worker_count), std::move(item));
            if (!submitted)
                return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                    submitted.error());
        }

        std::vector<std::optional<tile_decode_completion_t>> slots(requests.size());
        std::size_t remaining = requests.size();
        std::uint32_t cursor = 0;
        while (remaining > 0) {
            if (pool_->has_fatal()) {
                return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                    pool_->fatal_error());
            }
            bool progressed = false;
            for (std::uint32_t scan = 0; scan < slot_modulus && remaining > 0; ++scan) {
                const auto slot_index = (cursor + scan) % slot_modulus;
                tile_decode_completion_t completion;
                while (pool_->pop_completion(slot_index, completion)) {
                    const auto found = index_of.find(completion.request_id);
                    if (found == index_of.end()) {
                        auto error = orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "tile decode completion has an unknown request identifier");
                        error.details.emplace_back("request_id",
                            std::to_string(completion.request_id));
                        return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                            std::move(error));
                    }
                    if (slots[found->second].has_value()) {
                        auto error = orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "tile decode batch contains duplicate completions");
                        error.details.emplace_back("request_id",
                            std::to_string(completion.request_id));
                        return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                            std::move(error));
                    }
                    slots[found->second] = std::move(completion);
                    --remaining;
                    progressed = true;
                }
            }
            if (!progressed && remaining > 0) {
                tile_decode_completion_t waited;
                if (pool_->wait_completion(cursor % slot_modulus, waited)) {
                    const auto found = index_of.find(waited.request_id);
                    if (found == index_of.end()) {
                        auto error = orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "tile decode completion has an unknown request identifier");
                        error.details.emplace_back("request_id",
                            std::to_string(waited.request_id));
                        return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                            std::move(error));
                    }
                    if (slots[found->second].has_value()) {
                        auto error = orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "tile decode batch contains duplicate completions");
                        error.details.emplace_back("request_id",
                            std::to_string(waited.request_id));
                        return workspace_result_t<std::vector<tile_decode_completion_t>>::failure(
                            std::move(error));
                    }
                    slots[found->second] = std::move(waited);
                    --remaining;
                }
                ++cursor;
            }
        }

        completions.resize(requests.size());
        for (std::size_t index = 0; index < requests.size(); ++index)
            completions[index] = std::move(*slots[index]);

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
    std::unique_ptr<decode_worker_pool_t> pool_;
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

namespace {

struct seed_envelope_t final {
    std::uint64_t generation_ordinal = 0;
    std::uint32_t source_shard = 0;
    decode_frontier_seed_t seed;
    std::optional<decode_tile_id_t> source_tile;
};

struct lease_outgoing_t final {
    std::vector<tile_decode_request_t> requests;
};

struct retained_cursor_t final {
    bool valid = false;
    std::uint32_t shard = 0;
    std::size_t tile_local = 0;
    std::uint32_t slot = 0;
    std::uint64_t rva = 0;
    std::uint64_t end = 0;
};

struct decode_shard_context_t final {
    std::uint32_t shard_index = 0;
    decode_tile_id_t tile_begin = 0;
    decode_tile_id_t tile_end = 0;
    decode_frontier_t frontier;
    std::vector<tile_accumulator_t> accumulators;
    std::atomic<bool> lease_held{false};
    std::uint64_t next_request_seq = 0;
    std::map<std::uint64_t, tile_decode_completion_t> incoming;
    std::map<std::uint64_t, tile_decode_request_t> requests_in_flight;
    std::vector<std::deque<std::uint64_t>> apply_order;
    std::vector<std::uint64_t> mint_watermark;
    std::vector<std::uint64_t> mint_low;
    std::vector<decode_frontier_claim_t> mint_watermark_claim;
    std::atomic<std::uint32_t> in_flight{0};
    std::mutex inbound_mutex;
    std::vector<seed_envelope_t> inbound;
    std::uint64_t emitted_ordinal_counter = 0;
    std::uint64_t wave_index = 0;
    std::size_t next_gap_tile = 0;
    bool stage1_local_done = false;
    bool reconcile_done = false;
    bool cursor_valid = false;
    std::size_t cursor_tile_local = 0;
    std::uint32_t cursor_slot = 0;
    std::uint64_t cursor_rva = 0;
    std::uint64_t cursor_end = 0;
    bool edges_done = false;
    std::vector<decoded_edge_key_t> edges;
    std::vector<tile_decode_cross_tile_edge_t> cross_edges;
    std::size_t next_build_tile = 0;
    std::vector<std::optional<packed_analysis_shard_t>> built_shards;
    std::vector<tile_decode_shard_summary_t> built_summaries;
    std::vector<coverage_span_t> built_coverage;
    std::vector<std::uint8_t> built_delay_slots;
    tile_decode_orchestrator_statistics_t stats;
};

struct decode_run_context_t final {
    static constexpr std::uint32_t phase_recursive = 0;
    static constexpr std::uint32_t phase_gap = 1;
    static constexpr std::uint32_t phase_reconcile = 2;
    static constexpr std::uint32_t phase_edges = 3;
    static constexpr std::uint32_t phase_build = 4;
    static constexpr std::uint32_t phase_done = 5;

    const tile_decode_orchestrator_limits_t* limits = nullptr;
    const tile_decode_executor_capabilities_t* caps = nullptr;
    const provider_snapshot_t* snapshot = nullptr;
    const cancellation_token_t* cancellation = nullptr;
    tile_decode_executor_t* executor = nullptr;
    decode_worker_pool_t* pool = nullptr;
    decode_lane_seed_exchange_t* lane_exchange = nullptr;
    std::uint32_t lane_id = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t batch_request_limit = 0;
    decode_tile_id_t range_begin = 0;
    decode_tile_id_t range_end = 0;
    decode_ledger_t ledger;
    std::atomic<std::uint64_t> shared_seed_budget{0};
    const std::vector<executable_decode_tile_t>* all_tiles = nullptr;
    std::vector<std::unique_ptr<decode_shard_context_t>> shards;
    std::vector<std::uint32_t> shard_of_tile;
    std::vector<decode_tile_id_t> tiles_by_rva;
    std::atomic<std::uint32_t> phase{phase_recursive};
    std::atomic<bool> failed{false};
    tile_decode_pipeline_mode_t mode = tile_decode_pipeline_mode_t::gated;
    std::atomic<bool> recursive_globally_quiesced{false};
    std::atomic<std::uint64_t> recursive_quiesce_ns{0};
    std::atomic<std::uint32_t> edges_done_shard_count{0};
    std::atomic<std::uint64_t> edges_quiesce_ns{0};
    std::atomic<bool> fixup_done{false};
    std::mutex failure_mutex;
    std::optional<workspace_error_t> first_error;
    std::uint64_t supervisor_ordinal_counter = 0;
    std::mutex progress_mutex;
    std::condition_variable progress_cv;
    tile_decode_orchestrator_statistics_t stats;
};

void signal_progress(decode_run_context_t& ctx)
{
    {
        std::lock_guard<std::mutex> lock(ctx.progress_mutex);
    }
    ctx.progress_cv.notify_all();
}

void pool_completion_signal(void* context)
{
    signal_progress(*static_cast<decode_run_context_t*>(context));
}

void record_run_failure(decode_run_context_t& ctx, workspace_error_t error)
{
    {
        std::lock_guard<std::mutex> lock(ctx.failure_mutex);
        if (!ctx.first_error.has_value())
            ctx.first_error = std::move(error);
    }
    ctx.failed.store(true, std::memory_order_release);
    if (ctx.pool != nullptr)
        ctx.pool->request_stop();
    signal_progress(ctx);
}

std::optional<decode_tile_id_t> locate_tile_global(
    const decode_run_context_t& ctx,
    const std::vector<executable_decode_tile_t>& tiles,
    std::uint64_t rva) noexcept
{
    const auto found = std::upper_bound(ctx.tiles_by_rva.begin(),
        ctx.tiles_by_rva.end(), rva,
        [&](std::uint64_t value, decode_tile_id_t tile_id) {
            return value < tiles[tile_id].start_rva;
        });
    if (found == ctx.tiles_by_rva.begin())
        return std::nullopt;
    const auto tile_id = *(found - 1);
    const auto& tile = tiles[tile_id];
    if (rva < tile.start_rva || rva - tile.start_rva >= tile.byte_count)
        return std::nullopt;
    return tile_id;
}

std::uint64_t next_seed_ordinal(decode_run_context_t& ctx,
                                decode_shard_context_t& shard) noexcept
{
    return (((static_cast<std::uint64_t>(ctx.lane_id) << 7) |
             static_cast<std::uint64_t>(shard.shard_index)) << 48) |
           (++shard.emitted_ordinal_counter);
}

workspace_result_t<void> shard_emit_seed(decode_run_context_t& ctx,
    decode_shard_context_t& shard, decode_frontier_seed_t seed,
    decode_tile_id_t source_tile)
{
    const auto target_tile = locate_tile_global(ctx, *ctx.all_tiles, seed.rva);
    if (!target_tile) {
        auto add = shard.frontier.add_seed(seed, source_tile);
        if (!add)
            return workspace_result_t<void>::failure(add.error());
        return workspace_result_t<void>::success();
    }
    seed.tile_id = *target_tile;
    const auto target_shard = ctx.shard_of_tile[*target_tile];
    if (target_shard == shard.shard_index) {
        auto add = shard.frontier.add_seed(seed, source_tile);
        if (!add)
            return workspace_result_t<void>::failure(add.error());
        return workspace_result_t<void>::success();
    }
    if (*target_tile >= ctx.range_begin && *target_tile < ctx.range_end) {
        seed_envelope_t envelope;
        envelope.generation_ordinal = next_seed_ordinal(ctx, shard);
        envelope.source_shard = shard.shard_index;
        envelope.seed = seed;
        envelope.source_tile = source_tile;
        auto& target = *ctx.shards[target_shard];
        std::lock_guard<std::mutex> lock(target.inbound_mutex);
        target.inbound.push_back(std::move(envelope));
        return workspace_result_t<void>::success();
    }
    if (ctx.lane_exchange != nullptr) {
        decode_lane_seed_envelope_t envelope;
        envelope.generation_ordinal = next_seed_ordinal(ctx, shard);
        envelope.source_lane = ctx.lane_id;
        envelope.seed = seed;
        envelope.source_tile = source_tile;
        ctx.lane_exchange->forward_seed(ctx.lane_id, std::move(envelope));
        return workspace_result_t<void>::success();
    }
    return workspace_result_t<void>::failure(
        orchestrator_error(workspace_error_code_t::integrity_failure,
            "cross-lane decode seed has no exchange", seed.rva));
}

workspace_result_t<void> shard_process_records(
    decode_run_context_t& ctx, decode_shard_context_t& shard,
    const tile_decode_request_t& request,
    const tile_decode_records_t& records,
    bool route_frontier)
{
    if (request.tile_id < shard.tile_begin || request.tile_id >= shard.tile_end) {
        return workspace_result_t<void>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "tile decode request ownership is invalid", request.start.value));
    }
    auto& accumulator = shard.accumulators[request.tile_id - shard.tile_begin];
    if (accumulator.tile == nullptr ||
        accumulator.tile->tile_id != request.tile_id) {
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

    std::vector<std::uint64_t> changed_instruction_rvas;
    std::optional<std::uint64_t> previous_candidate_rva;
    tile_accept_deltas_t deltas;
    for (std::size_t instruction_index = 0;
         instruction_index < records.instructions.size(); ++instruction_index) {
        auto entry_result = make_owned_instruction_entry(
            accumulator, records, instruction_index, request, *accumulator.tile);
        if (!entry_result)
            return workspace_result_t<void>::failure(entry_result.error());
        auto optional_entry = entry_result.take_value();
        if (!optional_entry)
            continue;

        ++shard.stats.decoded_instruction_candidates;
        const auto candidate_rva = optional_entry->record.address.value;
        if (previous_candidate_rva.has_value() &&
            candidate_rva < *previous_candidate_rva) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decoder returned instructions out of order",
                    candidate_rva));
        }
        previous_candidate_rva = candidate_rva;

        auto acceptance_result = accept_instruction(
            ctx.caps->maximum_instruction_bytes, accumulator,
            std::move(*optional_entry), shard.stats, deltas);
        if (!acceptance_result)
            return workspace_result_t<void>::failure(acceptance_result.error());
        if (!acceptance_result.value())
            continue;

        if (route_frontier)
            changed_instruction_rvas.push_back(candidate_rva);
    }
    changed_instruction_rvas.erase(
        std::unique(changed_instruction_rvas.begin(), changed_instruction_rvas.end()),
        changed_instruction_rvas.end());

    if (!deltas.touched_slots.empty()) {
        std::uint64_t arena_visits = 0;
        for (const auto slot : deltas.touched_slots) {
            if ((arena_visits++ & 255ULL) == 0 &&
                ctx.cancellation->stop_requested()) {
                return workspace_result_t<void>::failure(
                    cancellation_error(*ctx.cancellation,
                        "tile decode acceptance commit cancelled"));
            }
            const auto& entry = accumulator.entries[slot];
            if (entry.evicted)
                continue;
            deltas.added_instructions += 1;
            deltas.added_operands += entry.operand_count;
            deltas.added_targets += entry.target_count;
        }
    }
    if (deltas.any()) {
        auto reserved = ctx.ledger.reserve_instruction(*ctx.limits,
            deltas.removed_committed_instructions,
            deltas.removed_committed_operands,
            deltas.removed_committed_targets,
            deltas.added_instructions, deltas.added_operands,
            deltas.added_targets, deltas.last_accepted_rva);
        if (!reserved)
            return workspace_result_t<void>::failure(reserved.error());
        for (const auto slot : deltas.touched_slots) {
            auto& entry = accumulator.entries[slot];
            if (!entry.evicted)
                entry.committed = true;
        }
    }

    if (route_frontier) {
        for (const auto rva : changed_instruction_rvas) {
            const auto slot = accumulator.index.find(rva);
            if (slot == tile_instruction_index_t::npos)
                continue;
            const auto& entry = accumulator.entries[slot];
            const auto& instruction = entry.record;

            const decode_frontier_claim_t claim{
                instruction.provenance, instruction.confidence,
                instruction.stable_source_id};
            auto claim_result = shard.frontier.mark_claimed(
                request.tile_id, rva, claim);
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
                auto emitted = shard_emit_seed(ctx, shard, seed, request.tile_id);
                if (!emitted)
                    return workspace_result_t<void>::failure(emitted.error());
            }

            const auto* targets = accumulator.targets_of(entry);
            for (std::uint32_t target_index = 0;
                 target_index < entry.target_count; ++target_index) {
                const auto& target = targets[target_index];
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
                auto emitted = shard_emit_seed(ctx, shard, seed, request.tile_id);
                if (!emitted)
                    return workspace_result_t<void>::failure(emitted.error());
            }
        }
    }

    auto coverage_result = merge_request_coverage(
        ctx.ledger, accumulator, records, request, *ctx.limits);
    if (!coverage_result)
        return workspace_result_t<void>::failure(coverage_result.error());

    std::uint64_t next_accumulator_invalid = 0;
    std::uint64_t next_total_invalid = 0;
    if (!checked_add(accumulator.invalid_bytes, records.invalid_bytes,
                     next_accumulator_invalid) ||
        !checked_add(shard.stats.invalid_bytes, records.invalid_bytes,
                     next_total_invalid)) {
        return workspace_result_t<void>::failure(
            orchestrator_error(workspace_error_code_t::limit_exceeded,
                "invalid byte accounting overflow", request.start.value));
    }
    accumulator.invalid_bytes = next_accumulator_invalid;
    shard.stats.invalid_bytes = next_total_invalid;
    if (records.invalid_bytes > 0) {
        ++accumulator.invalid_runs;
        ++shard.stats.invalid_runs;
    }

    if (accumulator.invalid_bytes >
        ctx.limits->invalid_run_policy.maximum_invalid_bytes_per_tile) {
        return workspace_result_t<void>::failure(
            limit_error("invalid_bytes_per_tile",
                ctx.limits->invalid_run_policy.maximum_invalid_bytes_per_tile,
                accumulator.invalid_bytes, request.start.value));
    }
    if (accumulator.invalid_runs >
        ctx.limits->invalid_run_policy.maximum_invalid_runs_per_tile) {
        return workspace_result_t<void>::failure(
            limit_error("invalid_runs_per_tile",
                ctx.limits->invalid_run_policy.maximum_invalid_runs_per_tile,
                accumulator.invalid_runs, request.start.value));
    }

    return workspace_result_t<void>::success();
}

void shard_evict_entry(decode_run_context_t& ctx,
                       decode_shard_context_t& shard,
                       std::size_t tile_local, std::uint32_t slot)
{
    auto& accumulator = shard.accumulators[tile_local];
    auto& entry = accumulator.entries[slot];
    entry.evicted = true;
    accumulator.index.invalidate(entry.record.address.value);
    ctx.ledger.instructions.fetch_sub(1, std::memory_order_acq_rel);
    ctx.ledger.operand_facts.fetch_sub(
        static_cast<std::uint64_t>(entry.operand_count), std::memory_order_acq_rel);
    ctx.ledger.target_facts.fetch_sub(
        static_cast<std::uint64_t>(entry.target_count), std::memory_order_acq_rel);
}

tile_instruction_entry_t& cursor_entry(decode_run_context_t& ctx,
                                       const retained_cursor_t& cursor)
{
    return ctx.shards[cursor.shard]->accumulators[cursor.tile_local]
        .entries[cursor.slot];
}

workspace_result_t<void> shard_reconcile_local(decode_run_context_t& ctx,
                                               decode_shard_context_t& shard)
{
    retained_cursor_t cursor;
    std::uint64_t visits = 0;
    for (std::size_t tile_local = 0; tile_local < shard.accumulators.size();
         ++tile_local) {
        auto& accumulator = shard.accumulators[tile_local];
        if (accumulator.tile == nullptr)
            continue;
        ensure_tile_sorted(accumulator);
        for (std::uint32_t slot = 0;
             slot < static_cast<std::uint32_t>(accumulator.entries.size()); ++slot) {
            auto& entry = accumulator.entries[slot];
            if (entry.evicted)
                continue;
            if ((visits++ & 255ULL) == 0 &&
                ctx.cancellation->stop_requested()) {
                return workspace_result_t<void>::failure(
                    cancellation_error(*ctx.cancellation,
                        "cross-tile instruction reconciliation cancelled"));
            }
            const auto rva = entry.record.address.value;
            std::uint64_t entry_end = 0;
            if (!checked_add(rva, entry.record.length, entry_end)) {
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "cross-tile instruction order is invalid", rva));
            }
            if (cursor.valid) {
                if (rva < cursor.rva) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "cross-tile instruction order is invalid", rva));
                }
                if (rva < cursor.end) {
                    ++shard.stats.overlap_instruction_candidates;
                    if (instruction_stronger(entry.record,
                            cursor_entry(ctx, cursor).record)) {
                        auto& cursor_shard = *ctx.shards[cursor.shard];
                        shard_evict_entry(ctx, cursor_shard, cursor.tile_local,
                            cursor.slot);
                        cursor.shard = shard.shard_index;
                        cursor.tile_local = tile_local;
                        cursor.slot = slot;
                        cursor.rva = rva;
                        cursor.end = entry_end;
                    } else {
                        shard_evict_entry(ctx, shard, tile_local, slot);
                        continue;
                    }
                } else {
                    cursor.shard = shard.shard_index;
                    cursor.tile_local = tile_local;
                    cursor.slot = slot;
                    cursor.rva = rva;
                    cursor.end = entry_end;
                }
            } else {
                cursor.valid = true;
                cursor.shard = shard.shard_index;
                cursor.tile_local = tile_local;
                cursor.slot = slot;
                cursor.rva = rva;
                cursor.end = entry_end;
            }
        }
    }
    shard.cursor_valid = cursor.valid;
    shard.cursor_tile_local = cursor.tile_local;
    shard.cursor_slot = cursor.slot;
    shard.cursor_rva = cursor.rva;
    shard.cursor_end = cursor.end;
    shard.reconcile_done = true;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> shard_record_edges(decode_run_context_t& ctx,
                                            decode_shard_context_t& shard)
{
    auto record_edge = [&](decode_tile_id_t source_tile_id,
                           const address_t& source,
                           const address_t& target,
                           edge_kind_t kind) -> workspace_result_t<void> {
        decoded_edge_key_t key;
        key.source = source;
        key.target = target;
        key.kind = kind;

        if (shard.edges.size() >= ctx.limits->maximum_edges) {
            return workspace_result_t<void>::failure(
                limit_error("edges", ctx.limits->maximum_edges,
                    static_cast<std::uint64_t>(shard.edges.size()) + 1,
                    source.value));
        }
        shard.edges.push_back(key);

        if (target.space != address_space_id_t::relative_virtual)
            return workspace_result_t<void>::success();
        const auto target_tile_id = locate_tile_global(ctx, *ctx.all_tiles,
            target.value);
        if (!target_tile_id || *target_tile_id == source_tile_id)
            return workspace_result_t<void>::success();

        tile_decode_cross_tile_edge_t cross_tile_edge;
        cross_tile_edge.source_tile_id = source_tile_id;
        cross_tile_edge.target_tile_id = *target_tile_id;
        cross_tile_edge.source = source;
        cross_tile_edge.target = target;
        cross_tile_edge.kind = kind;
        shard.cross_edges.push_back(std::move(cross_tile_edge));
        return workspace_result_t<void>::success();
    };

    std::uint64_t visits = 0;
    for (auto& accumulator : shard.accumulators) {
        if (accumulator.tile == nullptr)
            continue;
        ensure_tile_sorted(accumulator);
        for (auto& entry : accumulator.entries) {
            if (entry.evicted)
                continue;
            if ((visits++ & 255ULL) == 0 &&
                ctx.cancellation->stop_requested()) {
                return workspace_result_t<void>::failure(
                    cancellation_error(*ctx.cancellation,
                        "tile decode edge recording cancelled"));
            }
            const auto rva = entry.record.address.value;
            shard.stats.duplicate_edges += entry.duplicate_edge_count;
            if ((entry.record.flow_flags &
                 (flow_branch | flow_call | flow_return | flow_indirect)) != 0) {
                const auto* targets = accumulator.targets_of(entry);
                for (std::uint32_t target_index = 0;
                     target_index < entry.target_count; ++target_index) {
                    const auto& target = targets[target_index];
                    if (!control_flow_target_matches(
                            entry.record.flow_flags, target.kind))
                        continue;
                    auto edge_result = record_edge(
                        accumulator.tile->tile_id, entry.record.address,
                        target.target, flow_to_edge_kind(entry.record.flow_flags));
                    if (!edge_result)
                        return workspace_result_t<void>::failure(
                            edge_result.error());
                }
            }

            if ((entry.record.flow_flags & flow_fallthrough) != 0) {
                std::uint64_t target_rva = 0;
                if (!checked_add(rva, entry.record.length, target_rva)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "instruction fallthrough address overflow", rva));
                }
                const auto target_tile_id = locate_tile_global(ctx, *ctx.all_tiles,
                    target_rva);
                if (target_tile_id &&
                    *target_tile_id != accumulator.tile->tile_id) {
                    auto target = entry.record.address;
                    target.value = target_rva;
                    auto edge_result = record_edge(
                        accumulator.tile->tile_id, entry.record.address,
                        target, edge_kind_t::fallthrough);
                    if (!edge_result)
                        return workspace_result_t<void>::failure(
                            edge_result.error());
                }
            }
        }
    }
    shard.edges_done = true;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> shard_dedupe_edges(decode_run_context_t& ctx,
                                            decode_shard_context_t& shard)
{
    std::sort(shard.edges.begin(), shard.edges.end(), decoded_edge_less_t{});
    const auto pushed_edges =
        static_cast<std::uint64_t>(shard.edges.size());
    std::size_t unique_edges = 0;
    std::uint64_t visits = 0;
    for (std::size_t index = 0; index < shard.edges.size(); ++index) {
        if ((visits++ & 255ULL) == 0 &&
            ctx.cancellation->stop_requested()) {
            return workspace_result_t<void>::failure(
                cancellation_error(*ctx.cancellation,
                    "tile decode edge recording cancelled"));
        }
        if (unique_edges != 0 &&
            !decoded_edge_less_t{}(shard.edges[unique_edges - 1],
                                   shard.edges[index]) &&
            !decoded_edge_less_t{}(shard.edges[index],
                                   shard.edges[unique_edges - 1])) {
            continue;
        }
        if (unique_edges != index)
            shard.edges[unique_edges] = std::move(shard.edges[index]);
        ++unique_edges;
    }
    shard.edges.erase(shard.edges.begin() +
        static_cast<std::ptrdiff_t>(unique_edges), shard.edges.end());
    shard.stats.duplicate_edges +=
        pushed_edges - static_cast<std::uint64_t>(unique_edges);

    std::sort(shard.cross_edges.begin(), shard.cross_edges.end(),
        cross_tile_edge_less_t{});
    std::size_t unique_cross = 0;
    for (std::size_t index = 0; index < shard.cross_edges.size(); ++index) {
        if ((visits++ & 255ULL) == 0 &&
            ctx.cancellation->stop_requested()) {
            return workspace_result_t<void>::failure(
                cancellation_error(*ctx.cancellation,
                    "tile decode edge recording cancelled"));
        }
        if (unique_cross != 0 &&
            !cross_tile_edge_less_t{}(shard.cross_edges[unique_cross - 1],
                                      shard.cross_edges[index]) &&
            !cross_tile_edge_less_t{}(shard.cross_edges[index],
                                      shard.cross_edges[unique_cross - 1])) {
            continue;
        }
        if (unique_cross != index)
            shard.cross_edges[unique_cross] =
                std::move(shard.cross_edges[index]);
        ++unique_cross;
    }
    shard.cross_edges.erase(shard.cross_edges.begin() +
        static_cast<std::ptrdiff_t>(unique_cross), shard.cross_edges.end());
    return workspace_result_t<void>::success();
}

template <typename key_t>
struct inline_id_map_t final {
    static constexpr std::size_t capacity = 32;
    std::array<std::pair<key_t, entity_id_t>, capacity> slots{};
    std::size_t size = 0;

    void clear() noexcept { size = 0; }

    const entity_id_t* find(key_t key) const noexcept
    {
        for (std::size_t index = 0; index < size; ++index) {
            if (slots[index].first == key)
                return &slots[index].second;
        }
        return nullptr;
    }

    bool emplace(key_t key, entity_id_t value) noexcept
    {
        if (find(key) != nullptr)
            return true;
        if (size >= capacity)
            return false;
        slots[size++] = {key, value};
        return true;
    }
};

struct operand_link_scratch_t final {
    inline_id_map_t<entity_id_t> operand_source_ids;
    inline_id_map_t<std::uint8_t> operand_index_source_ids;
    inline_id_map_t<entity_id_t> address_expression_source_ids;
    inline_id_map_t<entity_id_t> operand_expression_source_ids;
    inline_id_map_t<std::uint8_t> operand_index_expression_source_ids;

    void clear() noexcept
    {
        operand_source_ids.clear();
        operand_index_source_ids.clear();
        address_expression_source_ids.clear();
        operand_expression_source_ids.clear();
        operand_index_expression_source_ids.clear();
    }
};

workspace_result_t<void> shard_build_tile(decode_run_context_t& ctx,
                                          decode_shard_context_t& shard)
{
    const auto tile_local = shard.next_build_tile;
    auto& acc = shard.accumulators[tile_local];
    if (acc.tile == nullptr) {
        ++shard.next_build_tile;
        return workspace_result_t<void>::success();
    }
    ensure_tile_sorted(acc);

    packed_analysis_shard_builder_t builder(acc.tile->shard_id);

    std::uint64_t instruction_source_id = 1;
    std::uint64_t address_expression_source_id = 1;
    std::uint32_t instruction_count = 0;
    std::uint32_t operand_count = 0;
    std::uint32_t target_count = 0;
    std::uint32_t edge_count = 0;
    entity_id_t coverage_source_id = 1;
    operand_link_scratch_t scratch;

    for (const auto& entry : acc.entries) {
        if (entry.evicted)
            continue;
        const auto rva = entry.record.address.value;
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
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store instruction add failed", rva));

        scratch.clear();
        const auto* operands = acc.operands_of(entry);
        for (std::uint32_t operand_index = 0;
             operand_index < entry.operand_count; ++operand_index) {
            const auto& op = operands[operand_index];
            packed_operand_input_t op_input;
            op_input.source_id = static_cast<entity_id_t>(operand_count + 1);
            op_input.instruction = packed_entity_reference_t::local(
                packed_entity_domain_t::instruction, instruction_source_id);
            entity_id_t expression_source_id = 0;
            const entity_id_t* existing_expression =
                scratch.address_expression_source_ids.find(
                    op.address_expression_id);
            if (op.address_expression_id != 0 &&
                existing_expression != nullptr) {
                expression_source_id = *existing_expression;
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
                    return workspace_result_t<void>::failure(
                        orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "packed store address expression add failed", rva));
                }
                if (op.address_expression_id != 0 &&
                    !scratch.address_expression_source_ids.emplace(
                        op.address_expression_id, expression_source_id)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "packed store operand link capacity exceeded", rva));
                }
            }
            if (expression_source_id != 0) {
                op_input.address_expression =
                    packed_entity_reference_t::local(
                        packed_entity_domain_t::address_expression,
                        expression_source_id);
                if (op.id != 0 &&
                    !scratch.operand_expression_source_ids.emplace(
                        op.id, expression_source_id)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "packed store operand link capacity exceeded", rva));
                }
                if (!scratch.operand_index_expression_source_ids.emplace(
                        op.operand_index, expression_source_id)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(
                            workspace_error_code_t::integrity_failure,
                            "packed store operand link capacity exceeded", rva));
                }
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
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store operand add failed", rva));

            if (op.id != 0 &&
                !scratch.operand_source_ids.emplace(op.id, op_input.source_id)) {
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store operand link capacity exceeded", rva));
            }
            if (!scratch.operand_index_source_ids.emplace(
                    op.operand_index, op_input.source_id)) {
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store operand link capacity exceeded", rva));
            }
            ++operand_count;
        }

        const auto* targets = acc.targets_of(entry);
        for (std::uint32_t target_index = 0;
             target_index < entry.target_count; ++target_index) {
            const auto& target = targets[target_index];
            packed_target_fact_input_t target_input;
            target_input.source_id = static_cast<entity_id_t>(target_count + 1);
            target_input.instruction = packed_entity_reference_t::local(
                packed_entity_domain_t::instruction, instruction_source_id);
            const entity_id_t* source_by_id =
                scratch.operand_source_ids.find(target.operand_fact_id);
            const entity_id_t* source_by_index =
                scratch.operand_index_source_ids.find(target.operand_index);
            if (source_by_id != nullptr) {
                target_input.operand = packed_entity_reference_t::local(
                    packed_entity_domain_t::operand, *source_by_id);
            } else if (source_by_index != nullptr) {
                target_input.operand = packed_entity_reference_t::local(
                    packed_entity_domain_t::operand, *source_by_index);
            }
            entity_id_t target_expression_source_id = 0;
            const entity_id_t* by_expression_id =
                scratch.address_expression_source_ids.find(
                    target.address_expression_id);
            if (by_expression_id != nullptr) {
                target_expression_source_id = *by_expression_id;
            } else {
                const entity_id_t* by_operand_id =
                    scratch.operand_expression_source_ids.find(
                        target.operand_fact_id);
                if (by_operand_id != nullptr)
                    target_expression_source_id = *by_operand_id;
            }
            if (target_expression_source_id == 0) {
                const entity_id_t* by_index =
                    scratch.operand_index_expression_source_ids.find(
                        target.operand_index);
                if (by_index != nullptr)
                    target_expression_source_id = *by_index;
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
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed store target fact add failed", rva));

            ++target_count;
        }

        if ((entry.record.flow_flags & (flow_branch | flow_call | flow_return | flow_indirect)) != 0) {
            for (std::uint32_t target_index = 0;
                 target_index < entry.target_count; ++target_index) {
                const auto& target = targets[target_index];
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
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "packed store edge add failed", rva));

                ++edge_count;
            }
        }

        ++instruction_source_id;
        ++instruction_count;
        shard.built_delay_slots.push_back(entry.delay_slots);
    }

    for (const auto& span : acc.coverage) {
        packed_coverage_input_t cov_input;
        cov_input.source_id = coverage_source_id++;
        cov_input.span_begin = span.start;
        cov_input.span_end = span.start;
        if (!checked_add(span.start.value, span.size,
                         cov_input.span_end.value)) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store coverage range overflow", span.start.value));
        }
        cov_input.reason = span.reason;
        cov_input.undecodable_count = span.detail_code;
        cov_input.provenance = span.provenance;
        cov_input.confidence = span.confidence;

        auto cov_result = builder.add_coverage(cov_input);
        if (!cov_result)
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store coverage add failed"));

        shard.built_coverage.push_back(span);
    }

    auto shard_result = std::move(builder).finalize();
    if (!shard_result)
        return workspace_result_t<void>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "packed store shard finalize failed"));

    shard.built_shards[tile_local] = std::move(shard_result).take_value();

    tile_decode_shard_summary_t summary;
    summary.tile_id = acc.tile->tile_id;
    summary.shard_id = acc.tile->shard_id;
    summary.instruction_count = instruction_count;
    summary.operand_count = operand_count;
    summary.target_count = target_count;
    summary.edge_count = edge_count;
    shard.built_summaries.push_back(summary);
    if (instruction_count != 0)
        ++shard.stats.accepted_tiles;

    ++shard.next_build_tile;
    return workspace_result_t<void>::success();
}

workspace_result_t<bool> shard_lease_recursive_wave(
    decode_run_context_t& ctx, decode_shard_context_t& shard,
    lease_outgoing_t& outgoing)
{
    if (shard.frontier.empty())
        return workspace_result_t<bool>::success(false);
    auto wave_result = shard.frontier.take_wave(ctx.batch_request_limit);
    if (!wave_result)
        return workspace_result_t<bool>::failure(wave_result.error());
    auto wave = wave_result.take_value();
    if (wave.empty())
        return workspace_result_t<bool>::success(false);
    std::uint32_t minted = 0;
    for (const auto& seed : wave) {
        if (seed.tile_id >= ctx.all_tiles->size())
            continue;
        const auto& tile = (*ctx.all_tiles)[seed.tile_id];
        const bool watermark_tracked =
            seed.tile_id >= shard.tile_begin && seed.tile_id < shard.tile_end;
        if (!watermark_tracked) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "recursive decode seed references a foreign tile", seed.rva));
        }
        const auto tile_local =
            static_cast<std::size_t>(seed.tile_id - shard.tile_begin);
        const auto watermark = shard.mint_watermark[tile_local];
        const decode_frontier_claim_t offer{
            seed.provenance, seed.confidence, seed.stable_source_id};
        if (shard.mint_low[tile_local] <= seed.rva && seed.rva < watermark &&
            !stronger_claim(offer, shard.mint_watermark_claim[tile_local])) {
            ++shard.stats.wave_seeds_coalesced;
            continue;
        }
        const auto consumed = ctx.ledger.decode_requests.fetch_add(1,
            std::memory_order_acq_rel);
        if (consumed >= ctx.limits->maximum_decode_requests) {
            return workspace_result_t<bool>::failure(
                limit_error("decode_requests",
                    ctx.limits->maximum_decode_requests,
                    consumed ==
                            (std::numeric_limits<std::uint64_t>::max)()
                        ? consumed
                        : consumed + 1,
                    seed.rva));
        }
        if (shard.next_request_seq >= (1ULL << 48)) {
            return workspace_result_t<bool>::failure(
                limit_error("request_identifiers",
                    shard.next_request_seq, shard.next_request_seq,
                    seed.rva));
        }

        const std::uint64_t offset_in_tile = seed.rva - tile.start_rva;
        const std::uint64_t remaining = tile.byte_count - offset_in_tile;
        std::uint64_t available_bytes = 0;
        if (!checked_add(remaining, tile.lookahead_bytes, available_bytes)) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "recursive decode request range overflow", seed.rva));
        }
        const std::uint64_t effective_bytes = (std::min)(
            available_bytes, ctx.caps->maximum_request_bytes);
        std::uint64_t provider_offset = 0;
        std::uint64_t runtime_address = 0;
        std::uint64_t owned_end = 0;
        if (!checked_add(tile.provider_offset, offset_in_tile,
                provider_offset) ||
            !checked_add(tile.start_virtual_address, offset_in_tile,
                runtime_address) ||
            !checked_add(tile.start_rva, tile.byte_count, owned_end)) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "recursive decode request range overflow", seed.rva));
        }

        tile_decode_request_t req;
        req.request_id =
            (static_cast<std::uint64_t>(shard.shard_index) << 48) |
            shard.next_request_seq;
        req.tile_id = seed.tile_id;
        req.pass = tile_decode_pass_t::recursive;
        req.seed_kind = seed.kind;
        req.start.space = address_space_id_t::relative_virtual;
        req.start.value = seed.rva;
        req.start.architecture = ctx.caps->decoder_key.architecture;
        req.start.mode = ctx.caps->decoder_key.mode;
        req.provider_offset = provider_offset;
        req.runtime_address = runtime_address;
        req.image_base = ctx.image_base;
        req.image_size = ctx.image_size;
        req.byte_count = effective_bytes;
        req.owned_end_rva = owned_end;
        req.stable_source_id = seed.stable_source_id;
        req.provenance = seed.provenance;
        req.confidence = seed.confidence;

        shard.requests_in_flight.emplace(shard.next_request_seq, req);
        std::uint64_t watermark_end = 0;
        if (!checked_add(seed.rva, req.byte_count, watermark_end)) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::range_overflow,
                    "recursive decode watermark overflow", seed.rva));
        }
        shard.mint_low[tile_local] =
            (std::min)(shard.mint_low[tile_local], seed.rva);
        shard.mint_watermark[tile_local] =
            (std::max)(shard.mint_watermark[tile_local], watermark_end);
        shard.mint_watermark_claim[tile_local] = decode_frontier_claim_t{
            seed.provenance, seed.confidence, seed.stable_source_id};
        shard.apply_order[tile_local].push_back(shard.next_request_seq);
        ++shard.next_request_seq;
        outgoing.requests.push_back(req);
        ++minted;
        ++shard.stats.recursive_requests;
        shard.stats.attempted_bytes += effective_bytes;
    }
    if (minted != 0) {
        shard.in_flight.fetch_add(minted, std::memory_order_acq_rel);
        ++shard.wave_index;
        ++shard.stats.frontier_waves;
    }
    return workspace_result_t<bool>::success(minted != 0);
}

workspace_result_t<bool> shard_lease_gap_step(
    decode_run_context_t& ctx, decode_shard_context_t& shard,
    lease_outgoing_t& outgoing)
{
    if (shard.next_gap_tile >= shard.accumulators.size())
        return workspace_result_t<bool>::success(false);
    auto& accumulator = shard.accumulators[shard.next_gap_tile];
    const auto* tile = accumulator.tile;
    if (tile == nullptr) {
        ++shard.next_gap_tile;
        return workspace_result_t<bool>::success(true);
    }
    ensure_tile_sorted(accumulator);
    std::uint64_t tile_end_rva = 0;
    if (!checked_add(tile->start_rva, tile->byte_count, tile_end_rva)) {
        return workspace_result_t<bool>::failure(
            orchestrator_error(workspace_error_code_t::range_overflow,
                "gap decode tile range overflow", tile->start_rva));
    }

    const auto request_capacity = (std::min)(
        ctx.caps->maximum_request_bytes,
        ctx.limits->invalid_run_policy.maximum_gap_resynchronization_bytes);
    if (request_capacity < ctx.caps->minimum_instruction_bytes) {
        return workspace_result_t<bool>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "gap resynchronization window is below the decoder minimum",
                tile->start_rva));
    }

    std::uint64_t cursor = tile->start_rva;
    std::uint64_t visits = 0;
    const auto emit_gap = [&](std::uint64_t gap_start,
                              std::uint64_t gap_length)
        -> workspace_result_t<void> {
        if (gap_length == 0)
            return workspace_result_t<void>::success();
        const auto maximum_lookahead =
            static_cast<std::uint64_t>(ctx.caps->maximum_instruction_bytes -
                ctx.caps->instruction_alignment);
        const auto minimum_owned_bytes = (std::min)(
            request_capacity,
            static_cast<std::uint64_t>(ctx.caps->instruction_alignment));
        const auto lookahead_reserve = (std::min)(maximum_lookahead,
            request_capacity - minimum_owned_bytes);
        auto owned_capacity = request_capacity - lookahead_reserve;
        if (owned_capacity >= ctx.caps->instruction_alignment) {
            owned_capacity -= owned_capacity % ctx.caps->instruction_alignment;
        }
        if (owned_capacity == 0) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::invalid_argument,
                    "gap resynchronization window has no aligned ownership",
                    gap_start));
        }

        std::uint64_t gap_offset = 0;
        while (gap_offset < gap_length) {
            if (ctx.cancellation->stop_requested()) {
                return workspace_result_t<void>::failure(
                    cancellation_error(*ctx.cancellation,
                        "orchestrator gap pass cancelled"));
            }
            const auto consumed = ctx.ledger.decode_requests.fetch_add(1,
                std::memory_order_acq_rel);
            if (consumed >= ctx.limits->maximum_decode_requests) {
                return workspace_result_t<void>::failure(
                    limit_error("decode_requests",
                        ctx.limits->maximum_decode_requests,
                        consumed ==
                                (std::numeric_limits<std::uint64_t>::max)()
                            ? consumed
                            : consumed + 1,
                        gap_start));
            }
            if (shard.next_request_seq >= (1ULL << 48)) {
                return workspace_result_t<void>::failure(
                    limit_error("request_identifiers",
                        shard.next_request_seq, shard.next_request_seq,
                        gap_start));
            }

            std::uint64_t request_start = 0;
            std::uint64_t offset_in_tile = 0;
            if (!checked_add(gap_start, gap_offset, request_start) ||
                request_start < tile->start_rva) {
                return workspace_result_t<void>::failure(
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
                return workspace_result_t<void>::failure(
                    orchestrator_error(workspace_error_code_t::range_overflow,
                        "gap decode request range overflowed", request_start));
            }

            tile_decode_request_t request;
            request.request_id =
                (static_cast<std::uint64_t>(shard.shard_index) << 48) |
                shard.next_request_seq;
            request.tile_id = tile->tile_id;
            request.pass = tile_decode_pass_t::gap;
            request.seed_kind = decode_frontier_seed_kind_t::fallthrough;
            request.start.space = address_space_id_t::relative_virtual;
            request.start.value = request_start;
            request.start.architecture = ctx.caps->decoder_key.architecture;
            request.start.mode = ctx.caps->decoder_key.mode;
            request.provider_offset = provider_offset;
            request.runtime_address = runtime_address;
            request.image_base = ctx.image_base;
            request.image_size = ctx.image_size;
            request.byte_count = request_bytes;
            request.owned_end_rva = owned_end;
            request.provenance = fact_provenance_t::gap_recovery;
            request.confidence = 50;

            shard.requests_in_flight.emplace(shard.next_request_seq, request);
            shard.apply_order[shard.next_gap_tile].push_back(
                shard.next_request_seq);
            ++shard.next_request_seq;
            outgoing.requests.push_back(request);
            shard.in_flight.fetch_add(1, std::memory_order_acq_rel);
            ++shard.stats.gap_requests;
            shard.stats.attempted_bytes += request_bytes;
            gap_offset += owned_bytes;
        }
        return workspace_result_t<void>::success();
    };

    for (const auto& entry : accumulator.entries) {
        if (entry.evicted)
            continue;
        if ((visits++ & 255ULL) == 0 &&
            ctx.cancellation->stop_requested()) {
            return workspace_result_t<bool>::failure(
                cancellation_error(*ctx.cancellation,
                    "orchestrator gap pass cancelled"));
        }
        const auto rva = entry.record.address.value;
        if (rva > cursor) {
            auto emitted = emit_gap(cursor, rva - cursor);
            if (!emitted)
                return workspace_result_t<bool>::failure(emitted.error());
        }
        std::uint64_t entry_end = 0;
        if (!checked_add(rva, entry.record.length, entry_end)) {
            return workspace_result_t<bool>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "gap decode instruction range overflow", rva));
        }
        cursor = (std::max)(cursor, entry_end);
    }
    if (cursor < tile_end_rva) {
        auto emitted = emit_gap(cursor, tile_end_rva - cursor);
        if (!emitted)
            return workspace_result_t<bool>::failure(emitted.error());
    }
    ++shard.next_gap_tile;
    return workspace_result_t<bool>::success(true);
}

workspace_result_t<bool> shard_lease_reconcile_step(
    decode_run_context_t& ctx, decode_shard_context_t& shard)
{
    if (shard.reconcile_done)
        return workspace_result_t<bool>::success(false);
    auto swept = shard_reconcile_local(ctx, shard);
    if (!swept)
        return workspace_result_t<bool>::failure(swept.error());
    return workspace_result_t<bool>::success(true);
}

workspace_result_t<bool> shard_lease_edges_step(
    decode_run_context_t& ctx, decode_shard_context_t& shard)
{
    if (shard.edges_done)
        return workspace_result_t<bool>::success(false);
    auto recorded = shard_record_edges(ctx, shard);
    if (!recorded)
        return workspace_result_t<bool>::failure(recorded.error());
    auto deduped = shard_dedupe_edges(ctx, shard);
    if (!deduped)
        return workspace_result_t<bool>::failure(deduped.error());
    if (ctx.mode == tile_decode_pipeline_mode_t::pipelined) {
        const auto done_count =
            ctx.edges_done_shard_count.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (done_count == ctx.shards.size()) {
            ctx.edges_quiesce_ns.store(
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count()),
                std::memory_order_release);
        }
    }
    return workspace_result_t<bool>::success(true);
}

workspace_result_t<bool> shard_lease_build_step(
    decode_run_context_t& ctx, decode_shard_context_t& shard)
{
    if (shard.next_build_tile >= shard.accumulators.size())
        return workspace_result_t<bool>::success(false);
    auto built = shard_build_tile(ctx, shard);
    if (!built)
        return workspace_result_t<bool>::failure(built.error());
    return workspace_result_t<bool>::success(true);
}

bool shard_inbound_empty(decode_shard_context_t& shard)
{
    std::lock_guard<std::mutex> lock(shard.inbound_mutex);
    return shard.inbound.empty();
}

workspace_result_t<bool> shard_lease_step(decode_run_context_t& ctx,
    decode_shard_context_t& shard, lease_outgoing_t& outgoing)
{
    const auto phase = ctx.phase.load(std::memory_order_acquire);
    bool did_work = false;

    if (ctx.pool != nullptr) {
        tile_decode_completion_t completion;
        while (ctx.pool->pop_completion(shard.shard_index, completion)) {
            const auto seq = completion.request_id & 0x0000FFFFFFFFFFFFULL;
            shard.incoming.emplace(seq, std::move(completion));
        }
    }
    std::uint64_t drain_visits = 0;
    for (;;) {
        bool applied_any = false;
        for (auto it = shard.incoming.begin(); it != shard.incoming.end();) {
            if ((drain_visits++ & 255ULL) == 0 &&
                ctx.cancellation->stop_requested()) {
                return workspace_result_t<bool>::failure(
                    cancellation_error(*ctx.cancellation,
                        "tile decode completion drain cancelled"));
            }
            const auto seq = it->first;
            const auto request_it = shard.requests_in_flight.find(seq);
            if (request_it == shard.requests_in_flight.end()) {
                return workspace_result_t<bool>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "tile decode completion has an unknown request sequence"));
            }
            const auto request_tile = request_it->second.tile_id;
            if (request_tile < shard.tile_begin || request_tile >= shard.tile_end) {
                return workspace_result_t<bool>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "tile decode completion references a foreign tile",
                        request_it->second.start.value));
            }
            auto& order =
                shard.apply_order[static_cast<std::size_t>(request_tile -
                    shard.tile_begin)];
            if (order.empty() || order.front() != seq) {
                ++it;
                continue;
            }
            auto completion = std::move(it->second);
            it = shard.incoming.erase(it);
            order.pop_front();
            const auto request = request_it->second;
            shard.requests_in_flight.erase(request_it);
            if (!completion.succeeded()) {
                auto error = *completion.error;
                error.details.emplace_back("request_id",
                    std::to_string(request.request_id));
                error.details.emplace_back("tile_id",
                    std::to_string(request.tile_id));
                return workspace_result_t<bool>::failure(std::move(error));
            }
            auto processed = shard_process_records(ctx, shard, request,
                completion.records, request.pass == tile_decode_pass_t::recursive);
            if (!processed)
                return workspace_result_t<bool>::failure(processed.error());
            shard.in_flight.fetch_sub(1, std::memory_order_acq_rel);
            did_work = true;
            applied_any = true;
        }
        if (!applied_any)
            break;
    }
    if (!shard.incoming.empty())
        ++shard.stats.apply_stall_count;

    std::vector<seed_envelope_t> envelopes;
    {
        std::lock_guard<std::mutex> lock(shard.inbound_mutex);
        if (!shard.inbound.empty())
            envelopes.swap(shard.inbound);
    }
    if (ctx.lane_exchange != nullptr) {
        std::vector<decode_lane_seed_envelope_t> lane_envelopes;
        ctx.lane_exchange->drain_seeds(ctx.lane_id, lane_envelopes);
        for (auto& lane_envelope : lane_envelopes) {
            seed_envelope_t envelope;
            envelope.generation_ordinal =
                lane_envelope.generation_ordinal;
            envelope.source_shard = 0xFFFFFFFFu;
            envelope.seed = lane_envelope.seed;
            envelope.source_tile = lane_envelope.source_tile;
            envelopes.push_back(std::move(envelope));
        }
    }
    if (!envelopes.empty()) {
        std::sort(envelopes.begin(), envelopes.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.generation_ordinal < rhs.generation_ordinal;
            });
        for (const auto& envelope : envelopes) {
            auto add = shard.frontier.add_seed(envelope.seed,
                envelope.source_tile);
            if (!add)
                return workspace_result_t<bool>::failure(add.error());
        }
        did_work = true;
    }

    if (ctx.mode == tile_decode_pipeline_mode_t::pipelined) {
        if (!ctx.recursive_globally_quiesced.load(std::memory_order_acquire)) {
            if (!shard.frontier.empty()) {
                auto waved = shard_lease_recursive_wave(ctx, shard, outgoing);
                if (!waved)
                    return workspace_result_t<bool>::failure(waved.error());
                if (waved.value())
                    did_work = true;
            } else if (shard.in_flight.load(std::memory_order_acquire) == 0 &&
                       shard.incoming.empty() && shard_inbound_empty(shard)) {
                shard.stage1_local_done = true;
            }
            return workspace_result_t<bool>::success(did_work);
        }
        if (shard.next_gap_tile < shard.accumulators.size()) {
            auto gapped = shard_lease_gap_step(ctx, shard, outgoing);
            if (!gapped)
                return workspace_result_t<bool>::failure(gapped.error());
            if (gapped.value())
                did_work = true;
            return workspace_result_t<bool>::success(did_work);
        }
        if (shard.in_flight.load(std::memory_order_acquire) != 0 ||
            !shard.incoming.empty()) {
            return workspace_result_t<bool>::success(did_work);
        }
        if (!shard.reconcile_done) {
            auto reconciled = shard_lease_reconcile_step(ctx, shard);
            if (!reconciled)
                return workspace_result_t<bool>::failure(reconciled.error());
            if (reconciled.value())
                did_work = true;
            return workspace_result_t<bool>::success(did_work);
        }
        if (ctx.fixup_done.load(std::memory_order_acquire)) {
            if (!shard.edges_done) {
                auto recorded = shard_lease_edges_step(ctx, shard);
                if (!recorded)
                    return workspace_result_t<bool>::failure(recorded.error());
                if (recorded.value())
                    did_work = true;
                return workspace_result_t<bool>::success(did_work);
            }
            if (shard.next_build_tile < shard.accumulators.size()) {
                auto built = shard_lease_build_step(ctx, shard);
                if (!built)
                    return workspace_result_t<bool>::failure(built.error());
                if (built.value())
                    did_work = true;
                return workspace_result_t<bool>::success(did_work);
            }
        }
        return workspace_result_t<bool>::success(did_work);
    }
    switch (phase) {
    case decode_run_context_t::phase_recursive: {
        auto waved = shard_lease_recursive_wave(ctx, shard, outgoing);
        if (!waved)
            return workspace_result_t<bool>::failure(waved.error());
        if (waved.value())
            did_work = true;
        break;
    }
    case decode_run_context_t::phase_gap: {
        auto gapped = shard_lease_gap_step(ctx, shard, outgoing);
        if (!gapped)
            return workspace_result_t<bool>::failure(gapped.error());
        if (gapped.value())
            did_work = true;
        break;
    }
    case decode_run_context_t::phase_reconcile: {
        auto reconciled = shard_lease_reconcile_step(ctx, shard);
        if (!reconciled)
            return workspace_result_t<bool>::failure(reconciled.error());
        if (reconciled.value())
            did_work = true;
        break;
    }
    case decode_run_context_t::phase_edges: {
        auto recorded = shard_lease_edges_step(ctx, shard);
        if (!recorded)
            return workspace_result_t<bool>::failure(recorded.error());
        if (recorded.value())
            did_work = true;
        break;
    }
    case decode_run_context_t::phase_build: {
        auto built = shard_lease_build_step(ctx, shard);
        if (!built)
            return workspace_result_t<bool>::failure(built.error());
        if (built.value())
            did_work = true;
        break;
    }
    default:
        break;
    }
    return workspace_result_t<bool>::success(did_work);
}

bool recursive_phase_done(decode_run_context_t& ctx);
void announce_recursive_quiesced(decode_run_context_t& ctx);

bool decode_lease_hook(void* context, std::uint32_t worker_index)
{
    auto& ctx = *static_cast<decode_run_context_t*>(context);
    if (ctx.failed.load(std::memory_order_acquire))
        return false;
    const auto phase = ctx.phase.load(std::memory_order_acquire);
    if (phase == decode_run_context_t::phase_done)
        return false;
    const auto count = static_cast<std::uint32_t>(ctx.shards.size());
    bool saw_local_quiesce = false;
    for (std::uint32_t attempt = 0; attempt < count; ++attempt) {
        const auto index = (worker_index + attempt) % count;
        auto& shard = *ctx.shards[index];
        bool expected = false;
        if (!shard.lease_held.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel))
            continue;
        lease_outgoing_t outgoing;
        auto step = shard_lease_step(ctx, shard, outgoing);
        if (step && step.value() && ctx.lane_exchange != nullptr &&
            ctx.phase.load(std::memory_order_acquire) ==
                decode_run_context_t::phase_recursive) {
            ctx.lane_exchange->note_recursive_activity(ctx.lane_id, true);
        }
        shard.lease_held.store(false, std::memory_order_release);
        if (!step) {
            record_run_failure(ctx, step.error());
            return false;
        }
        for (auto& request : outgoing.requests) {
            decode_work_item_t item;
            item.request = request;
            item.shard_index = index;
            auto submitted = ctx.pool->submit(index, std::move(item));
            if (!submitted) {
                record_run_failure(ctx, submitted.error());
                return false;
            }
        }
        if (step.value()) {
            signal_progress(ctx);
            return true;
        }
        saw_local_quiesce = saw_local_quiesce || shard.stage1_local_done;
    }
    if (saw_local_quiesce &&
        ctx.mode == tile_decode_pipeline_mode_t::pipelined &&
        !ctx.recursive_globally_quiesced.load(std::memory_order_acquire) &&
        recursive_phase_done(ctx)) {
        announce_recursive_quiesced(ctx);
    }
    return false;
}

bool recursive_phase_done(decode_run_context_t& ctx)
{
    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        if (shard.lease_held.load(std::memory_order_acquire))
            return false;
        if (!shard.frontier.empty() ||
            shard.in_flight.load(std::memory_order_acquire) != 0 ||
            !shard.incoming.empty() || !shard_inbound_empty(shard))
            return false;
    }
    if (ctx.pool != nullptr && !ctx.pool->drained())
        return false;
    if (ctx.lane_exchange != nullptr) {
        ctx.lane_exchange->note_recursive_activity(ctx.lane_id, false);
        if (!ctx.lane_exchange->drained(ctx.lane_id))
            return false;
    }
    return true;
}

bool gap_phase_done(decode_run_context_t& ctx)
{
    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        if (shard.lease_held.load(std::memory_order_acquire))
            return false;
        if (shard.next_gap_tile < shard.accumulators.size() ||
            shard.in_flight.load(std::memory_order_acquire) != 0 ||
            !shard.incoming.empty())
            return false;
    }
    if (ctx.pool != nullptr && !ctx.pool->drained())
        return false;
    return true;
}

std::uint64_t steady_now_ns() noexcept
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void announce_recursive_quiesced(decode_run_context_t& ctx)
{
    if (ctx.mode != tile_decode_pipeline_mode_t::pipelined)
        return;
    bool expected = false;
    if (!ctx.recursive_globally_quiesced.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        return;
    ctx.recursive_quiesce_ns.store(steady_now_ns(),
        std::memory_order_release);
    signal_progress(ctx);
}

bool pipelined_stage1_done(decode_run_context_t& ctx)
{
    return recursive_phase_done(ctx) && gap_phase_done(ctx);
}

bool reconcile_phase_done(decode_run_context_t& ctx)
{
    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        if (shard.lease_held.load(std::memory_order_acquire))
            return false;
        if (!shard.reconcile_done)
            return false;
    }
    return true;
}

bool edges_phase_done(decode_run_context_t& ctx)
{
    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        if (shard.lease_held.load(std::memory_order_acquire))
            return false;
        if (!shard.edges_done)
            return false;
    }
    return true;
}

bool build_phase_done(decode_run_context_t& ctx)
{
    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        if (shard.lease_held.load(std::memory_order_acquire))
            return false;
        if (shard.next_build_tile < shard.accumulators.size())
            return false;
    }
    return true;
}

bool edges_build_phase_done(decode_run_context_t& ctx)
{
    return edges_phase_done(ctx) && build_phase_done(ctx);
}

workspace_result_t<void> supervise_phase(decode_run_context_t& ctx,
    bool (*predicate)(decode_run_context_t&), const char* cancel_message)
{
    constexpr auto kWakeBackstop = std::chrono::milliseconds(25);
    for (;;) {
        if (ctx.failed.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(ctx.failure_mutex);
            if (ctx.first_error.has_value())
                return workspace_result_t<void>::failure(*ctx.first_error);
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decode orchestration failed"));
        }
        if (ctx.pool != nullptr && ctx.pool->has_fatal())
            return workspace_result_t<void>::failure(ctx.pool->fatal_error());
        if (ctx.cancellation->stop_requested())
            return workspace_result_t<void>::failure(
                cancellation_error(*ctx.cancellation, cancel_message));
        if (ctx.mode == tile_decode_pipeline_mode_t::pipelined &&
            !ctx.recursive_globally_quiesced.load(std::memory_order_acquire) &&
            recursive_phase_done(ctx)) {
            announce_recursive_quiesced(ctx);
        }
        if (predicate(ctx))
            return workspace_result_t<void>::success();
        std::unique_lock<std::mutex> lock(ctx.progress_mutex);
        ctx.progress_cv.wait_for(lock, kWakeBackstop, [&] {
            return ctx.failed.load(std::memory_order_acquire) ||
                (ctx.pool != nullptr && ctx.pool->has_fatal()) ||
                ctx.cancellation->stop_requested() ||
                predicate(ctx);
        });
    }
}

workspace_result_t<void> inline_drive_phase(decode_run_context_t& ctx,
    bool (*predicate)(decode_run_context_t&), const char* cancel_message,
    const char* batch_cancel_message)
{
    if (ctx.mode == tile_decode_pipeline_mode_t::pipelined &&
        !ctx.recursive_globally_quiesced.load(std::memory_order_acquire) &&
        recursive_phase_done(ctx)) {
        announce_recursive_quiesced(ctx);
    }
    while (!predicate(ctx)) {
        if (ctx.cancellation->stop_requested())
            return workspace_result_t<void>::failure(
                cancellation_error(*ctx.cancellation, cancel_message));
        bool any_progress = false;
        std::vector<tile_decode_request_t> round;
        std::vector<std::uint32_t> round_shards;
        const auto phase = ctx.phase.load(std::memory_order_acquire);
        for (auto& shard_ptr : ctx.shards) {
            auto& shard = *shard_ptr;
            shard.lease_held.store(true, std::memory_order_release);
            lease_outgoing_t outgoing;
            auto step = shard_lease_step(ctx, shard, outgoing);
            shard.lease_held.store(false, std::memory_order_release);
            if (!step)
                return workspace_result_t<void>::failure(step.error());
            if (step.value()) {
                any_progress = true;
                if (ctx.lane_exchange != nullptr &&
                    phase == decode_run_context_t::phase_recursive) {
                    ctx.lane_exchange->note_recursive_activity(
                        ctx.lane_id, true);
                }
            }
            for (const auto& request : outgoing.requests) {
                round.push_back(request);
                round_shards.push_back(shard.shard_index);
            }
        }
        if (!round.empty()) {
            auto batch = execute_correlated_batch(*ctx.executor, *ctx.snapshot,
                round, *ctx.cancellation, batch_cancel_message);
            if (!batch)
                return workspace_result_t<void>::failure(batch.error());
            auto completed = batch.take_value();
            for (std::size_t index = 0; index < round.size(); ++index) {
                auto& completion =
                    completed.completions[completed.completion_indices[index]];
                const auto seq = round[index].request_id & 0x0000FFFFFFFFFFFFULL;
                auto& shard = *ctx.shards[round_shards[index]];
                shard.incoming.emplace(seq, std::move(completion));
            }
            any_progress = true;
        }
        if (!any_progress &&
            ctx.mode == tile_decode_pipeline_mode_t::pipelined &&
            !ctx.recursive_globally_quiesced.load(std::memory_order_acquire) &&
            recursive_phase_done(ctx)) {
            announce_recursive_quiesced(ctx);
            any_progress = true;
        }
        if (!any_progress && !predicate(ctx)) {
            return workspace_result_t<void>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "tile decode orchestration made no progress"));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> drive_phase(decode_run_context_t& ctx,
    bool (*predicate)(decode_run_context_t&), const char* cancel_message,
    const char* batch_cancel_message)
{
    if (ctx.pool != nullptr)
        return supervise_phase(ctx, predicate, cancel_message);
    return inline_drive_phase(ctx, predicate, cancel_message,
        batch_cancel_message);
}

workspace_result_t<void> reconcile_boundary_fixup(decode_run_context_t& ctx)
{
    retained_cursor_t cursor;
    std::uint64_t visits = 0;
    for (std::uint32_t shard_index = 0;
         shard_index < static_cast<std::uint32_t>(ctx.shards.size());
         ++shard_index) {
        auto& shard = *ctx.shards[shard_index];
        if (!cursor.valid) {
            if (shard.cursor_valid) {
                cursor.valid = true;
                cursor.shard = shard_index;
                cursor.tile_local = shard.cursor_tile_local;
                cursor.slot = shard.cursor_slot;
                cursor.rva = shard.cursor_rva;
                cursor.end = shard.cursor_end;
            }
            continue;
        }
        bool closed = false;
        for (std::size_t tile_local = 0;
             tile_local < shard.accumulators.size() && !closed; ++tile_local) {
            auto& accumulator = shard.accumulators[tile_local];
            if (accumulator.tile == nullptr)
                continue;
            for (std::uint32_t slot = 0;
                 slot < static_cast<std::uint32_t>(accumulator.entries.size());
                 ++slot) {
                auto& entry = accumulator.entries[slot];
                if (entry.evicted)
                    continue;
                if ((visits++ & 255ULL) == 0 &&
                    ctx.cancellation->stop_requested()) {
                    return workspace_result_t<void>::failure(
                        cancellation_error(*ctx.cancellation,
                            "cross-tile instruction reconciliation cancelled"));
                }
                const auto rva = entry.record.address.value;
                std::uint64_t entry_end = 0;
                if (!checked_add(rva, entry.record.length, entry_end)) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "cross-tile instruction order is invalid", rva));
                }
                if (rva < cursor.rva) {
                    return workspace_result_t<void>::failure(
                        orchestrator_error(workspace_error_code_t::integrity_failure,
                            "cross-tile instruction order is invalid", rva));
                }
                if (rva >= cursor.end) {
                    closed = true;
                    break;
                }
                ++ctx.stats.overlap_instruction_candidates;
                if (instruction_stronger(entry.record,
                        cursor_entry(ctx, cursor).record)) {
                    shard_evict_entry(ctx, *ctx.shards[cursor.shard],
                        cursor.tile_local, cursor.slot);
                    cursor.shard = shard_index;
                    cursor.tile_local = tile_local;
                    cursor.slot = slot;
                    cursor.rva = rva;
                    cursor.end = entry_end;
                } else {
                    shard_evict_entry(ctx, shard, tile_local, slot);
                }
            }
        }
        if (closed && shard.cursor_valid) {
            cursor.shard = shard_index;
            cursor.tile_local = shard.cursor_tile_local;
            cursor.slot = shard.cursor_slot;
            cursor.rva = shard.cursor_rva;
            cursor.end = shard.cursor_end;
        }
    }
    return workspace_result_t<void>::success();
}

template <typename T, typename Less>
std::vector<T> kway_merge_unique(std::vector<std::vector<T>>& sources, Less less)
{
    std::size_t total = 0;
    for (const auto& source : sources)
        total += source.size();
    std::vector<T> merged;
    merged.reserve(total);
    struct heap_node_t final {
        const T* value = nullptr;
        std::size_t source = 0;
        std::size_t position = 0;
    };
    struct heap_compare_t final {
        Less less;
        bool operator()(const heap_node_t& lhs, const heap_node_t& rhs) const
        {
            if (less(*rhs.value, *lhs.value))
                return true;
            if (less(*lhs.value, *rhs.value))
                return false;
            return lhs.source > rhs.source;
        }
    };
    std::vector<heap_node_t> heap;
    heap_compare_t compare{less};
    for (std::size_t source = 0; source < sources.size(); ++source) {
        if (!sources[source].empty())
            heap.push_back(heap_node_t{&sources[source][0], source, 0});
    }
    std::make_heap(heap.begin(), heap.end(), compare);
    bool have_last = false;
    T last{};
    while (!heap.empty()) {
        std::pop_heap(heap.begin(), heap.end(), compare);
        auto node = heap.back();
        heap.pop_back();
        if (!have_last || less(last, *node.value) || less(*node.value, last)) {
            merged.push_back(*node.value);
            last = *node.value;
            have_last = true;
        }
        ++node.position;
        if (node.position < sources[node.source].size()) {
            node.value = &sources[node.source][node.position];
            heap.push_back(node);
            std::push_heap(heap.begin(), heap.end(), compare);
        }
    }
    return merged;
}

template <typename T, typename Less>
std::vector<T> merge_two_unique(const std::vector<T>& left,
                                const std::vector<T>& right, Less less)
{
    std::vector<T> merged;
    merged.reserve(left.size() + right.size());
    auto left_cursor = left.begin();
    auto right_cursor = right.begin();
    bool have_last = false;
    T last{};
    const auto push = [&](const T& value) {
        if (!have_last || less(last, value) || less(value, last)) {
            merged.push_back(value);
            last = value;
            have_last = true;
        }
    };
    while (left_cursor != left.end() && right_cursor != right.end()) {
        if (less(*right_cursor, *left_cursor)) {
            push(*right_cursor);
            ++right_cursor;
        } else {
            push(*left_cursor);
            ++left_cursor;
        }
    }
    while (left_cursor != left.end()) {
        push(*left_cursor);
        ++left_cursor;
    }
    while (right_cursor != right.end()) {
        push(*right_cursor);
        ++right_cursor;
    }
    return merged;
}

template <typename T, typename Less>
std::vector<T> parallel_kway_merge_unique(std::vector<std::vector<T>>& sources,
                                          Less less)
{
    std::size_t total = 0;
    std::size_t live_sources = 0;
    for (const auto& source : sources) {
        total += source.size();
        live_sources += source.empty() ? 0U : 1U;
    }
    if (live_sources < 4 || total < 65'536)
        return kway_merge_unique(sources, less);
    std::vector<std::vector<T>> runs;
    runs.reserve(live_sources);
    for (auto& source : sources) {
        if (!source.empty())
            runs.push_back(std::move(source));
    }
    while (runs.size() > 1) {
        const std::size_t pairs = runs.size() / 2;
        std::vector<std::vector<T>> next(pairs + (runs.size() % 2));
        parallel_executor_t::run(pairs, 0, "analysis.decode_edge_merge",
            [&](std::size_t index) {
                next[index] = merge_two_unique(
                    runs[index * 2], runs[index * 2 + 1], less);
            });
        if (runs.size() % 2 != 0)
            next[pairs] = std::move(runs.back());
        runs = std::move(next);
    }
    return std::move(runs.front());
}

workspace_result_t<void> parallel_coverage_union(
    std::vector<coverage_span_t>& decoded_coverage,
    std::vector<coverage_span_t>& zero_fill_coverage,
    const cancellation_token_t& cancellation)
{
    std::sort(zero_fill_coverage.begin(), zero_fill_coverage.end(),
        coverage_span_less_t{});
    if (!std::is_sorted(decoded_coverage.begin(), decoded_coverage.end(),
            coverage_span_less_t{})) {
        merge_coverage_into(decoded_coverage, zero_fill_coverage);
        return workspace_result_t<void>::success();
    }
    const std::size_t total =
        decoded_coverage.size() + zero_fill_coverage.size();
    const auto workers = parallel_worker_count();
    if (total < 65'536 || workers <= 1 || decoded_coverage.empty()) {
        std::vector<coverage_span_t> merged;
        merged.reserve(total);
        std::merge(decoded_coverage.begin(), decoded_coverage.end(),
            zero_fill_coverage.begin(), zero_fill_coverage.end(),
            std::back_inserter(merged), coverage_span_less_t{});
        stitch_sorted_coverage(merged);
        decoded_coverage = std::move(merged);
        return workspace_result_t<void>::success();
    }
    const auto shards = parallel_shards(decoded_coverage.size(), workers);
    std::vector<std::vector<coverage_span_t>> outputs(shards.size());
    std::atomic<bool> stopped{false};
    parallel_executor_t::run(shards.size(), 0, "analysis.decode_coverage_merge",
        [&](std::size_t index) {
            if (stopped.load(std::memory_order_acquire))
                return;
            if (cancellation.stop_requested()) {
                stopped.store(true, std::memory_order_release);
                return;
            }
            const auto& shard = shards[index];
            coverage_span_t boundary_key;
            boundary_key.start = decoded_coverage[shard.begin].start;
            const auto zero_begin = std::lower_bound(
                zero_fill_coverage.begin(), zero_fill_coverage.end(),
                boundary_key, coverage_span_less_t{});
            auto zero_end = zero_fill_coverage.end();
            if (shard.end < decoded_coverage.size()) {
                coverage_span_t end_key;
                end_key.start = decoded_coverage[shard.end].start;
                zero_end = std::lower_bound(zero_begin, zero_fill_coverage.end(),
                    end_key, coverage_span_less_t{});
            }
            std::vector<coverage_span_t> local;
            local.reserve(static_cast<std::size_t>(shard.end - shard.begin) +
                static_cast<std::size_t>(std::distance(zero_begin, zero_end)));
            std::merge(decoded_coverage.begin() +
                    static_cast<std::ptrdiff_t>(shard.begin),
                decoded_coverage.begin() +
                    static_cast<std::ptrdiff_t>(shard.end),
                zero_begin, zero_end, std::back_inserter(local),
                coverage_span_less_t{});
            stitch_sorted_coverage(local);
            outputs[index] = std::move(local);
        });
    if (stopped.load(std::memory_order_acquire)) {
        return workspace_result_t<void>::failure(cancellation_error(
            cancellation, "orchestrator coverage merge cancelled"));
    }
    std::vector<coverage_span_t> merged;
    merged.reserve(total);
    for (auto& output : outputs) {
        merged.insert(merged.end(),
            std::make_move_iterator(output.begin()),
            std::make_move_iterator(output.end()));
    }
    stitch_sorted_coverage(merged);
    decoded_coverage = std::move(merged);
    return workspace_result_t<void>::success();
}

}

workspace_result_t<tile_decode_orchestration_result_t>
tile_decode_orchestrator_t::run_impl(
    const provider_snapshot_t& snapshot,
    const image_layout_index_t& layout,
    const executable_decode_partition_t* precomputed_partition,
    std::vector<tile_decode_seed_t> seeds,
    tile_decode_executor_t& executor,
    const cancellation_token_t& cancellation,
    const decode_tile_range_t* tile_range,
    decode_lane_seed_exchange_t* lane_exchange,
    std::uint32_t lane_id,
    decode_worker_pool_t* shared_pool,
    bool tile_only_shard_formula,
    bool publish_unmerged_shards) const
{
    const auto run_start = std::chrono::steady_clock::now();
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
    if (lane_id >= 64) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "decode lane identifier exceeds mailbox capacity"));
    }
    const bool restricted_range =
        tile_range != nullptr && (tile_range->begin != 0 || tile_range->end != 0);
    if (restricted_range && lane_exchange == nullptr) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::invalid_argument,
                "a restricted decode tile range requires a lane seed exchange"));
    }
    const auto batch_request_limit = caps.maximum_batch_requests == 0
        ? limits_.maximum_frontier_wave
        : (std::min)(limits_.maximum_frontier_wave,
            static_cast<std::uint64_t>(caps.maximum_batch_requests));

    std::optional<executable_decode_partition_t> computed_partition;
    const executable_decode_partition_t* partition = precomputed_partition;
    if (partition == nullptr) {
        auto partition_result = partition_executable_decode_ranges(
            layout, caps, limits_, cancellation);
        if (!partition_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                partition_result.error());
        computed_partition = partition_result.take_value();
        partition = &*computed_partition;
    }

    const auto tile_count =
        static_cast<decode_tile_id_t>(partition->tiles.size());
    decode_tile_id_t range_begin = 0;
    decode_tile_id_t range_end = tile_count;
    if (tile_range != nullptr) {
        range_begin = tile_range->begin;
        range_end = tile_range->end == 0 ? tile_count : tile_range->end;
        if (range_begin > range_end || range_end > tile_count) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::invalid_argument,
                    "decode tile range is out of bounds"));
        }
    }

    decode_run_context_t ctx;
    ctx.limits = &limits_;
    ctx.caps = &caps;
    ctx.snapshot = &snapshot;
    ctx.cancellation = &cancellation;
    ctx.executor = &executor;
    ctx.lane_exchange = lane_exchange;
    ctx.lane_id = lane_id;
    ctx.image_base = layout.identity().image_base;
    ctx.batch_request_limit = batch_request_limit;
    ctx.range_begin = range_begin;
    ctx.range_end = range_end;
    ctx.all_tiles = &partition->tiles;
    ctx.mode = lane_exchange == nullptr
        ? limits_.pipeline_mode
        : tile_decode_pipeline_mode_t::gated;

    if (shared_pool != nullptr) {
        ctx.pool = shared_pool;
    } else {
        auto* production =
            dynamic_cast<production_tile_decode_executor_t*>(&executor);
        if (production != nullptr)
            ctx.pool = production->pool();
    }

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
    ctx.image_size = image_size;

    ctx.tiles_by_rva.resize(partition->tiles.size());
    for (decode_tile_id_t tile_id = 0; tile_id < tile_count; ++tile_id)
        ctx.tiles_by_rva[tile_id] = tile_id;
    std::sort(ctx.tiles_by_rva.begin(), ctx.tiles_by_rva.end(),
        [&](decode_tile_id_t lhs, decode_tile_id_t rhs) {
            const auto& left = partition->tiles[lhs];
            const auto& right = partition->tiles[rhs];
            if (left.start_rva != right.start_rva)
                return left.start_rva < right.start_rva;
            return lhs < rhs;
        });

    const std::uint64_t range_tile_count = range_end - range_begin;
    std::uint32_t shard_count = 0;
    if (range_tile_count != 0) {
        std::uint64_t desired = 0;
        if (tile_only_shard_formula) {
            desired = next_pow2(static_cast<std::uint64_t>((std::max)(
                4ULL, (std::min)(64ULL, range_tile_count / 128ULL))));
        } else {
            desired = next_pow2(static_cast<std::uint64_t>((std::max)(
                4ULL, (std::min)(64ULL,
                    static_cast<std::uint64_t>(caps.worker_count) * 2ULL))));
        }
        shard_count = static_cast<std::uint32_t>((std::min)(
            static_cast<std::uint64_t>(desired), range_tile_count));
    }

    ctx.shard_of_tile.assign(partition->tiles.size(),
        (std::numeric_limits<std::uint32_t>::max)());
    ctx.shards.reserve(shard_count);
    for (std::uint32_t shard_index = 0; shard_index < shard_count;
         ++shard_index) {
        auto shard = std::make_unique<decode_shard_context_t>();
        shard->shard_index = shard_index;
        shard->tile_begin = range_begin + static_cast<decode_tile_id_t>(
            (range_tile_count * shard_index) / shard_count);
        shard->tile_end = range_begin + static_cast<decode_tile_id_t>(
            (range_tile_count * (shard_index + 1ULL)) / shard_count);
        std::vector<decode_frontier_tile_t> frontier_tiles;
        frontier_tiles.reserve(shard->tile_end - shard->tile_begin);
        for (auto tile_id = shard->tile_begin; tile_id < shard->tile_end;
             ++tile_id) {
            const auto& tile = partition->tiles[tile_id];
            decode_frontier_tile_t frontier_tile;
            frontier_tile.id = tile.tile_id;
            frontier_tile.start_rva = tile.start_rva;
            frontier_tile.byte_count = tile.byte_count;
            frontier_tiles.push_back(frontier_tile);
            ctx.shard_of_tile[tile_id] = shard_index;
        }
        auto frontier_build = decode_frontier_t::build(
            std::move(frontier_tiles), limits_.maximum_frontier_seeds,
            &ctx.shared_seed_budget);
        if (!frontier_build)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                frontier_build.error());
        shard->frontier = frontier_build.take_value();
        shard->accumulators.resize(shard->tile_end - shard->tile_begin);
        for (auto tile_id = shard->tile_begin; tile_id < shard->tile_end;
             ++tile_id) {
            shard->accumulators[tile_id - shard->tile_begin].tile =
                &partition->tiles[tile_id];
        }
        const auto shard_tile_count = static_cast<std::size_t>(
            shard->tile_end - shard->tile_begin);
        shard->apply_order.resize(shard_tile_count);
        shard->mint_watermark.assign(shard_tile_count, 0);
        shard->mint_low.assign(shard_tile_count,
            (std::numeric_limits<std::uint64_t>::max)());
        shard->mint_watermark_claim.assign(shard_tile_count,
            decode_frontier_claim_t{fact_provenance_t::unknown, 0,
                (std::numeric_limits<std::uint64_t>::max)()});
        shard->built_shards.resize(shard->tile_end - shard->tile_begin);
        ctx.shards.push_back(std::move(shard));
    }

    std::sort(seeds.begin(), seeds.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.address != rhs.address)
            return lhs.address < rhs.address;
        if (lhs.provenance != rhs.provenance)
            return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
        if (lhs.confidence != rhs.confidence)
            return lhs.confidence > rhs.confidence;
        return lhs.stable_source_id < rhs.stable_source_id;
    });

    const auto seed_frontier = [&](decode_frontier_seed_t& seed)
        -> workspace_result_t<void> {
        const auto target_tile = locate_tile_global(ctx, partition->tiles,
            seed.rva);
        if (!target_tile) {
            if (ctx.shards.empty())
                return workspace_result_t<void>::success();
            auto add = ctx.shards[0]->frontier.add_seed(seed);
            if (!add)
                return workspace_result_t<void>::failure(add.error());
            return workspace_result_t<void>::success();
        }
        seed.tile_id = *target_tile;
        if (*target_tile >= range_begin && *target_tile < range_end) {
            const auto target_shard = ctx.shard_of_tile[*target_tile];
            auto add = ctx.shards[target_shard]->frontier.add_seed(seed);
            if (!add)
                return workspace_result_t<void>::failure(add.error());
            return workspace_result_t<void>::success();
        }
        if (lane_exchange != nullptr) {
            decode_lane_seed_envelope_t envelope;
            envelope.generation_ordinal =
                (((static_cast<std::uint64_t>(lane_id) << 7) | 64ULL) << 48) |
                (++ctx.supervisor_ordinal_counter);
            envelope.source_lane = lane_id;
            envelope.seed = seed;
            ctx.lane_exchange->forward_seed(lane_id, std::move(envelope));
            return workspace_result_t<void>::success();
        }
        return workspace_result_t<void>::failure(
            orchestrator_error(workspace_error_code_t::integrity_failure,
                "cross-lane decode seed has no exchange", seed.rva));
    };

    for (const auto& seed : seeds) {
        decode_frontier_seed_t fs;
        fs.rva = seed.address.value;
        fs.kind = decode_frontier_seed_kind_t::explicit_entry;
        fs.provenance = seed.provenance;
        fs.confidence = seed.confidence;
        fs.stable_source_id = seed.stable_source_id;
        auto seeded = seed_frontier(fs);
        if (!seeded)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                seeded.error());
    }

    if (limits_.seed_executable_range_starts) {
        for (const auto& range : partition->ranges) {
            decode_frontier_seed_t fs;
            fs.rva = range.start_rva;
            fs.kind = decode_frontier_seed_kind_t::range_entry;
            fs.provenance = fact_provenance_t::linear_validation;
            fs.confidence = 80;
            auto seeded = seed_frontier(fs);
            if (!seeded)
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    seeded.error());
        }
    }

    struct lease_hook_guard_t final {
        decode_worker_pool_t* pool = nullptr;
        ~lease_hook_guard_t() {
            if (pool != nullptr) {
                pool->clear_completion_signal();
                pool->clear_lease_hook();
            }
        }
    } hook_guard;

    if (ctx.pool != nullptr) {
        ctx.pool->bind_snapshot(snapshot);
        ctx.pool->set_completion_signal(pool_completion_signal, &ctx);
        ctx.pool->set_lease_hook(decode_lease_hook, &ctx);
        hook_guard.pool = ctx.pool;
    }

    const auto drive = [&](bool (*predicate)(decode_run_context_t&),
                           std::uint32_t phase, const char* cancel_message,
                           const char* batch_cancel_message)
        -> workspace_result_t<void> {
        ctx.phase.store(phase, std::memory_order_release);
        return drive_phase(ctx, predicate, cancel_message,
            batch_cancel_message);
    };

    const auto drive_timed = [&](bool (*predicate)(decode_run_context_t&),
                                 std::uint32_t phase, const char* phase_name,
                                 const char* cancel_message,
                                 const char* batch_cancel_message,
                                 std::uint64_t& phase_wall_ns)
        -> workspace_result_t<void> {
        const auto begin = std::chrono::steady_clock::now();
        auto result = drive(predicate, phase, cancel_message,
            batch_cancel_message);
        phase_wall_ns += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - begin).count());
        ::diag::log_tagged_fmt("tile_decode",
            result ? "phase=%s done wall_us=%llu tiles=%llu shards=%u"
                   : "phase=%s failed wall_us=%llu tiles=%llu shards=%u",
            phase_name,
            static_cast<unsigned long long>(phase_wall_ns / 1000ULL),
            static_cast<unsigned long long>(range_tile_count),
            shard_count);
        return result;
    };

    std::uint64_t recursive_phase_ns = 0;
    std::uint64_t gap_phase_ns = 0;
    std::uint64_t reconcile_phase_ns = 0;
    std::uint64_t edges_phase_ns = 0;
    std::uint64_t build_phase_ns = 0;

    const bool pipelined =
        ctx.mode == tile_decode_pipeline_mode_t::pipelined;

    if (pipelined) {
        const auto stage1_begin_ns = steady_now_ns();
        auto driven = drive(pipelined_stage1_done,
            decode_run_context_t::phase_recursive,
            "orchestrator recursive pass cancelled",
            "orchestrator recursive batch cancelled");
        const auto stage1_ns = steady_now_ns() - stage1_begin_ns;
        const auto quiesce_ns =
            ctx.recursive_quiesce_ns.load(std::memory_order_acquire);
        if (quiesce_ns > stage1_begin_ns && quiesce_ns <= stage1_begin_ns + stage1_ns) {
            recursive_phase_ns = quiesce_ns - stage1_begin_ns;
            gap_phase_ns = stage1_ns - recursive_phase_ns;
        } else {
            recursive_phase_ns = stage1_ns;
        }
        ::diag::log_tagged_fmt("tile_decode",
            driven ? "phase=stage1 done wall_us=%llu tiles=%llu shards=%u"
                   : "phase=stage1 failed wall_us=%llu tiles=%llu shards=%u",
            static_cast<unsigned long long>(stage1_ns / 1000ULL),
            static_cast<unsigned long long>(range_tile_count),
            shard_count);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());
    } else {
        auto driven = drive_timed(recursive_phase_done,
            decode_run_context_t::phase_recursive, "recursive",
            "orchestrator recursive pass cancelled",
            "orchestrator recursive batch cancelled", recursive_phase_ns);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());

        driven = drive_timed(gap_phase_done,
            decode_run_context_t::phase_gap, "gap",
            "orchestrator gap pass cancelled",
            "orchestrator gap batch cancelled", gap_phase_ns);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());
    }

    auto driven = drive_timed(reconcile_phase_done,
        decode_run_context_t::phase_reconcile, "reconcile",
        "cross-tile instruction reconciliation cancelled",
        "cross-tile instruction reconciliation cancelled", reconcile_phase_ns);
    if (!driven)
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            driven.error());

    {
        const auto fixup_begin = std::chrono::steady_clock::now();
        auto fixed = reconcile_boundary_fixup(ctx);
        const auto fixup_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - fixup_begin).count());
        reconcile_phase_ns += fixup_ns;
        ::diag::log_tagged_fmt("tile_decode",
            fixed ? "phase=reconcile_fixup done wall_us=%llu"
                  : "phase=reconcile_fixup failed wall_us=%llu",
            static_cast<unsigned long long>(fixup_ns / 1000ULL));
        if (!fixed)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                fixed.error());
    }

    ctx.fixup_done.store(true, std::memory_order_release);

    if (pipelined) {
        const auto edges_build_begin_ns = steady_now_ns();
        driven = drive(edges_build_phase_done,
            decode_run_context_t::phase_edges,
            "tile decode edge recording cancelled",
            "tile decode edge recording cancelled");
        const auto edges_build_ns = steady_now_ns() - edges_build_begin_ns;
        const auto edges_quiesce =
            ctx.edges_quiesce_ns.load(std::memory_order_acquire);
        if (edges_quiesce > edges_build_begin_ns &&
            edges_quiesce <= edges_build_begin_ns + edges_build_ns) {
            edges_phase_ns = edges_quiesce - edges_build_begin_ns;
            build_phase_ns = edges_build_ns - edges_phase_ns;
        } else {
            edges_phase_ns = edges_build_ns;
        }
        ::diag::log_tagged_fmt("tile_decode",
            driven ? "phase=edges_build done wall_us=%llu tiles=%llu shards=%u"
                   : "phase=edges_build failed wall_us=%llu tiles=%llu shards=%u",
            static_cast<unsigned long long>(edges_build_ns / 1000ULL),
            static_cast<unsigned long long>(range_tile_count),
            shard_count);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());
    } else {
        driven = drive_timed(edges_phase_done, decode_run_context_t::phase_edges,
            "edges", "tile decode edge recording cancelled",
            "tile decode edge recording cancelled", edges_phase_ns);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());

        driven = drive_timed(build_phase_done, decode_run_context_t::phase_build,
            "build", "orchestrator shard build cancelled",
            "orchestrator shard build cancelled", build_phase_ns);
        if (!driven)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                driven.error());
    }

    ctx.phase.store(decode_run_context_t::phase_done,
        std::memory_order_release);
    if (ctx.pool != nullptr) {
        ctx.pool->clear_completion_signal();
        ctx.pool->clear_lease_hook();
    }
    hook_guard.pool = nullptr;

    tile_decode_orchestrator_statistics_t stats;
    stats.initialized_executable_bytes = partition->initialized_executable_bytes;
    stats.zero_fill_executable_bytes = partition->zero_fill_executable_bytes;
    stats.recursive_phase_wall_ns = recursive_phase_ns;
    stats.gap_phase_wall_ns = gap_phase_ns;
    stats.reconcile_phase_wall_ns = reconcile_phase_ns;
    stats.edges_phase_wall_ns = edges_phase_ns;
    stats.build_phase_wall_ns = build_phase_ns;
    if (ctx.pool != nullptr) {
        const auto pool_stats = ctx.pool->statistics();
        stats.worker_completion_push_count = pool_stats.completion_push_count;
        stats.worker_steal_count = pool_stats.steal_count;
        stats.worker_backpressure_wait_count =
            pool_stats.backpressure_wait_count;
        stats.worker_inline_drain_count = pool_stats.inline_drain_count;
        stats.worker_max_queue_depth = pool_stats.max_queue_depth_seen;
    }

    std::vector<packed_analysis_shard_t> shards;
    std::vector<tile_decode_shard_summary_t> shard_summaries;
    std::vector<coverage_span_t> merged_coverage;
    std::vector<coverage_span_t> zero_fill_coverage;
    std::vector<std::uint8_t> merged_delay_slot_counts;
    merged_delay_slot_counts.reserve(static_cast<std::size_t>(
        ctx.ledger.instructions.load(std::memory_order_acquire)));

    std::vector<std::vector<decoded_edge_key_t>> edge_sources;
    std::vector<std::vector<tile_decode_cross_tile_edge_t>> cross_edge_sources;

    for (auto& shard_ptr : ctx.shards) {
        auto& shard = *shard_ptr;
        for (auto& built : shard.built_shards) {
            if (built.has_value())
                shards.push_back(std::move(*built));
        }
        shard_summaries.insert(shard_summaries.end(),
            shard.built_summaries.begin(), shard.built_summaries.end());
        merged_coverage.insert(merged_coverage.end(),
            shard.built_coverage.begin(), shard.built_coverage.end());
        merged_delay_slot_counts.insert(merged_delay_slot_counts.end(),
            shard.built_delay_slots.begin(), shard.built_delay_slots.end());
        edge_sources.emplace_back(shard.edges.begin(), shard.edges.end());
        cross_edge_sources.emplace_back(shard.cross_edges.begin(),
            shard.cross_edges.end());

        stats.recursive_requests += shard.stats.recursive_requests;
        stats.gap_requests += shard.stats.gap_requests;
        stats.decoded_instruction_candidates +=
            shard.stats.decoded_instruction_candidates;
        stats.duplicate_instruction_candidates +=
            shard.stats.duplicate_instruction_candidates;
        stats.overlap_instruction_candidates +=
            shard.stats.overlap_instruction_candidates;
        stats.invalid_bytes += shard.stats.invalid_bytes;
        stats.invalid_runs += shard.stats.invalid_runs;
        stats.frontier_waves += shard.stats.frontier_waves;
        stats.wave_seeds_coalesced += shard.stats.wave_seeds_coalesced;
        stats.attempted_bytes += shard.stats.attempted_bytes;
        stats.accepted_tiles += shard.stats.accepted_tiles;
        stats.duplicate_edges += shard.stats.duplicate_edges;
        stats.apply_stall_count += shard.stats.apply_stall_count;
        const auto snapshot_of = shard.frontier.snapshot();
        stats.frontier.unique_seed_count += snapshot_of.unique_seed_count;
        stats.frontier.pending_seed_count += snapshot_of.pending_seed_count;
        stats.frontier.claimed_seed_count += snapshot_of.claimed_seed_count;
        stats.frontier.duplicate_seed_count += snapshot_of.duplicate_seed_count;
        stats.frontier.strengthened_seed_count +=
            snapshot_of.strengthened_seed_count;
        stats.frontier.outside_seed_count += snapshot_of.outside_seed_count;
        stats.frontier.cross_tile_route_count +=
            snapshot_of.cross_tile_route_count;
    }
    stats.overlap_instruction_candidates +=
        ctx.stats.overlap_instruction_candidates;

    std::unique_ptr<packed_analysis_store_t> merged_store;
    if (publish_unmerged_shards) {
        std::unordered_set<std::uint16_t> published_ids;
        published_ids.reserve(shards.size());
        for (const auto& packed : shards) {
            if (!packed.valid()) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed shard publication is invalid"));
            }
            if (!published_ids.insert(packed.shard_id()).second) {
                return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                    orchestrator_error(workspace_error_code_t::integrity_failure,
                        "packed shard publication has a duplicate shard identifier"));
            }
        }
    } else {
        auto store_result = packed_analysis_store_t::merge(std::move(shards));
        if (!store_result)
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "packed store merge failed"));
        merged_store = std::make_unique<packed_analysis_store_t>(
            std::move(store_result).take_value());
    }

    auto merged_edges = parallel_kway_merge_unique(edge_sources,
        decoded_edge_less_t{});
    if (static_cast<std::uint64_t>(merged_edges.size()) >
        limits_.maximum_edges) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            limit_error("edges", limits_.maximum_edges,
                static_cast<std::uint64_t>(merged_edges.size())));
    }
    auto merged_cross_edges = parallel_kway_merge_unique(cross_edge_sources,
        cross_tile_edge_less_t{});

    stats.accepted_instructions =
        ctx.ledger.instructions.load(std::memory_order_acquire);
    stats.accepted_operands =
        ctx.ledger.operand_facts.load(std::memory_order_acquire);
    stats.accepted_target_facts =
        ctx.ledger.target_facts.load(std::memory_order_acquire);
    stats.accepted_edges = static_cast<std::uint64_t>(merged_edges.size());
    stats.cross_tile_edges =
        static_cast<std::uint64_t>(merged_cross_edges.size());

    const auto span_begin = range_tile_count == 0
        ? 0
        : partition->tiles[range_begin].start_rva;
    std::uint64_t span_end = 0;
    if (range_tile_count != 0 &&
        !checked_add(partition->tiles[range_end - 1].start_rva,
            partition->tiles[range_end - 1].byte_count, span_end)) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            orchestrator_error(workspace_error_code_t::range_overflow,
                "decode tile span overflowed",
                partition->tiles[range_end - 1].start_rva));
    }

    std::uint64_t zero_fill_visits = 0;
    for (const auto& range : partition->zero_fill_ranges) {
        if ((zero_fill_visits++ & 255ULL) == 0 &&
            cancellation.stop_requested()) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                cancellation_error(cancellation,
                    "orchestrator coverage merge cancelled"));
        }
        const bool in_span =
            (range.start_rva >= span_begin && range.start_rva < span_end) ||
            (range_begin == 0 && range.start_rva < span_begin) ||
            (range_end == tile_count && range.start_rva >= span_end);
        if (!in_span)
            continue;
        const auto consumed =
            ctx.ledger.coverage_spans.fetch_add(1, std::memory_order_acq_rel);
        if (consumed >= limits_.maximum_coverage_spans) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                limit_error("coverage_spans", limits_.maximum_coverage_spans,
                    consumed + 1, range.start_rva));
        }
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
        zero_fill_coverage.push_back(std::move(span));
    }

    auto coverage_merged = parallel_coverage_union(merged_coverage,
        zero_fill_coverage, cancellation);
    if (!coverage_merged) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            coverage_merged.error());
    }

    std::sort(shard_summaries.begin(), shard_summaries.end(),
              [](const auto& a, const auto& b) { return a.tile_id < b.tile_id; });

    stats.lane_wall_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - run_start).count());

    ::diag::log_tagged_fmt("tile_decode",
        "run done wall_us=%llu tiles=%llu shards=%u workers=%u requests=%llu instructions=%llu steals=%llu apply_stalls=%llu backpressure_waits=%llu max_queue_depth=%llu coalesced=%llu mode=%s",
        static_cast<unsigned long long>(stats.lane_wall_ns / 1000ULL),
        static_cast<unsigned long long>(range_tile_count),
        shard_count,
        caps.worker_count,
        static_cast<unsigned long long>(
            stats.recursive_requests + stats.gap_requests),
        static_cast<unsigned long long>(stats.accepted_instructions),
        static_cast<unsigned long long>(stats.worker_steal_count),
        static_cast<unsigned long long>(stats.apply_stall_count),
        static_cast<unsigned long long>(stats.worker_backpressure_wait_count),
        static_cast<unsigned long long>(stats.worker_max_queue_depth),
        static_cast<unsigned long long>(stats.wave_seeds_coalesced),
        pipelined ? "pipelined" : "gated");

    tile_decode_orchestration_result_t result;
    if (publish_unmerged_shards)
        result.packed_shards = std::move(shards);
    else
        result.packed_store = std::move(merged_store);
    result.delay_slot_counts = std::move(merged_delay_slot_counts);
    result.coverage = std::move(merged_coverage);
    result.cross_tile_edges = std::move(merged_cross_edges);
    result.shards = std::move(shard_summaries);
    result.statistics = stats;

    return workspace_result_t<tile_decode_orchestration_result_t>::success(
        std::move(result));
}

workspace_result_t<tile_decode_orchestration_result_t>
tile_decode_orchestrator_t::run(
    const provider_snapshot_t& snapshot,
    const image_layout_index_t& layout,
    std::vector<tile_decode_seed_t> seeds,
    tile_decode_executor_t& executor,
    const cancellation_token_t& cancellation,
    const decode_tile_range_t* tile_range,
    decode_lane_seed_exchange_t* lane_exchange,
    std::uint32_t lane_id) const
{
    return run_impl(snapshot, layout, nullptr, std::move(seeds), executor,
        cancellation, tile_range, lane_exchange, lane_id, nullptr, false,
        false);
}

workspace_result_t<tile_decode_orchestration_result_t>
tile_decode_orchestrator_t::run_shared(
    const provider_snapshot_t& snapshot,
    const image_layout_index_t& layout,
    const executable_decode_partition_t& partition,
    std::vector<tile_decode_seed_t> seeds,
    tile_decode_executor_t& executor,
    const cancellation_token_t& cancellation,
    decode_worker_pool_t* shared_pool) const
{
    if (static_cast<std::uint64_t>(partition.tiles.size()) >
        limits_.maximum_tiles) {
        return workspace_result_t<tile_decode_orchestration_result_t>::failure(
            limit_error("tiles", limits_.maximum_tiles,
                static_cast<std::uint64_t>(partition.tiles.size())));
    }
    for (std::size_t index = 0; index < partition.tiles.size(); ++index) {
        const auto& tile = partition.tiles[index];
        if (tile.tile_id != static_cast<decode_tile_id_t>(index) ||
            tile.byte_count == 0) {
            return workspace_result_t<tile_decode_orchestration_result_t>::failure(
                orchestrator_error(workspace_error_code_t::integrity_failure,
                    "precomputed decode partition is invalid", tile.start_rva));
        }
    }
    return run_impl(snapshot, layout, &partition, std::move(seeds), executor,
        cancellation, nullptr, nullptr, 0, shared_pool, true, true);
}

}
