#include "function_recovery.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <map>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kBlockEntityTag = 2ULL << 56;
constexpr std::uint64_t kFunctionEntityTag = 3ULL << 56;
constexpr std::uint64_t kEdgeEntityTag = 4ULL << 56;
constexpr std::uint64_t kFunctionChunkEntityTag = 11ULL << 56;

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", phase);
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", phase);
    error.cancellation = true;
    return error;
}

bool valid_limits(const function_recovery_limits_t& limits) noexcept {
    return limits.max_blocks != 0 && limits.max_functions != 0 &&
        limits.max_function_memberships != 0 && limits.max_edges != 0 &&
        limits.max_switches != 0 && limits.max_result_bytes != 0 &&
        limits.max_switch_cases != 0 && limits.max_blocks_per_function != 0 &&
        limits.cancellation_check_interval != 0;
}

address_t rva_address(const workspace_image_t& image, std::uint64_t rva) noexcept {
    return {address_space_id_t::relative_virtual, rva, image.architecture,
        image.architecture_mode};
}

std::optional<std::uint64_t> to_rva(const workspace_image_t& image,
                                    const address_t& address) noexcept {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode)
        return std::nullopt;
    if (address.space == address_space_id_t::relative_virtual)
        return address.value < image.image_size ? std::optional<std::uint64_t>(address.value)
                                                : std::nullopt;
    if ((address.space == address_space_id_t::virtual_address ||
         address.space == address_space_id_t::live_virtual) &&
        address.value >= image.image_base) {
        const auto rva = address.value - image.image_base;
        return rva < image.image_size ? std::optional<std::uint64_t>(rva) : std::nullopt;
    }
    return std::nullopt;
}

bool executable_rva(const workspace_image_t& image, std::uint64_t rva) noexcept {
    const auto contains = [rva](const auto& region) noexcept {
        const auto extent = std::max(region.virtual_size, region.file_size);
        return extent != 0 && rva >= region.virtual_address &&
            workspace_image_span_within(rva - region.virtual_address, 1, extent);
    };
    for (const auto& section : image.sections) {
        if ((section.permissions & image_permission_execute) != 0 && contains(section))
            return true;
    }
    for (const auto& segment : image.segments) {
        if ((segment.permissions & image_permission_execute) != 0 && contains(segment))
            return true;
    }
    return false;
}

std::uint64_t instruction_end(const instruction_record_t& instruction) noexcept {
    std::uint64_t end = 0;
    return checked_add_u64(instruction.address.value, instruction.length, end)
        ? end : std::numeric_limits<std::uint64_t>::max();
}

workspace_result_t<void> validate_instruction_stream(const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets) {
    std::uint64_t previous_end = 0;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& instruction = instructions[index];
        if (instruction.address.space != address_space_id_t::relative_virtual ||
            instruction.address.architecture != image.architecture ||
            instruction.address.mode != image.architecture_mode || instruction.length == 0 ||
            !workspace_image_span_within(instruction.address.value, instruction.length,
                image.image_size)) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction stream contains an invalid normalized record", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        std::uint64_t target_end = 0;
        if (!checked_add_u64(instruction.target_fact_begin,
                instruction.target_fact_count, target_end) || target_end > targets.size()) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction target-fact range is invalid", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const auto end = instruction_end(instruction);
        if (end == std::numeric_limits<std::uint64_t>::max() ||
            (index != 0 && instruction.address.value < previous_end)) {
            auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                "instruction stream is unsorted or overlapping", "blocks");
            error.address = instruction.address;
            return workspace_result_t<void>::failure(std::move(error));
        }
        previous_end = end;
    }
    return workspace_result_t<void>::success();
}

template <typename T>
workspace_result_t<void> append_bounded(std::vector<T>& values, T value,
    std::uint64_t maximum_count, std::uint64_t maximum_bytes,
    std::uint64_t& storage_bytes, const char* phase, const char* message) {
    if (values.size() >= maximum_count) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, phase));
    }
    if (values.size() == values.capacity()) {
        const auto current = static_cast<std::uint64_t>(values.capacity());
        std::uint64_t desired = current == 0 ? std::min<std::uint64_t>(4096, maximum_count) : 0;
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
        if (desired <= current || !checked_mul_u64(desired, sizeof(T), new_allocation) ||
            !checked_mul_u64(desired - current, sizeof(T), retained_delta) ||
            !checked_add_u64(storage_bytes, new_allocation, peak) || peak > maximum_bytes) {
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

bool edge_less(const edge_record_t& lhs, const edge_record_t& rhs) noexcept {
    if (lhs.source != rhs.source)
        return lhs.source < rhs.source;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.provenance != rhs.provenance)
        return provenance_rank(lhs.provenance) > provenance_rank(rhs.provenance);
    if (lhs.confidence != rhs.confidence)
        return lhs.confidence > rhs.confidence;
    return lhs.source_entity < rhs.source_entity;
}

bool edge_equal(const edge_record_t& lhs, const edge_record_t& rhs) noexcept {
    return lhs.source_entity == rhs.source_entity && lhs.source == rhs.source &&
        lhs.target == rhs.target && lhs.kind == rhs.kind;
}

const instruction_record_t* block_last_instruction(const basic_block_record_t& block,
    const std::vector<instruction_record_t>& instructions) noexcept {
    if (block.instruction_count == 0)
        return nullptr;
    const auto index = static_cast<std::uint64_t>(block.first_instruction) +
        block.instruction_count - 1ULL;
    return index < instructions.size() ? &instructions[static_cast<std::size_t>(index)]
                                       : nullptr;
}

bool ascii_equal(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        auto left = static_cast<unsigned char>(lhs[index]);
        auto right = static_cast<unsigned char>(rhs[index]);
        if (left >= 'A' && left <= 'Z')
            left = static_cast<unsigned char>(left + ('a' - 'A'));
        if (right >= 'A' && right <= 'Z')
            right = static_cast<unsigned char>(right + ('a' - 'A'));
        if (left != right)
            return false;
    }
    return true;
}

bool ascii_starts_with(std::string_view value, std::string_view prefix) noexcept {
    return value.size() >= prefix.size() && ascii_equal(value.substr(0, prefix.size()), prefix);
}

bool known_noreturn_name(std::string_view input) noexcept {
    const auto separator = input.find_last_of("!:");
    const auto name = separator != std::string_view::npos && separator + 1 < input.size()
        ? input.substr(separator + 1) : input;
    static constexpr std::array<const char*, 31> exact = {
        "_invoke_watson", "_invalid_parameter", "_invalid_parameter_noinfo",
        "_invalid_parameter_noinfo_noreturn", "_cxxthrowexception",
        "__report_gsfailure", "__report_rangecheckfailure",
        "__report_securityfailure", "__report_securityfailureex",
        "__std_terminate", "terminate", "abort", "_abort", "exit", "_exit",
        "_purecall", "_unrecoverable_error", "raiseexception",
        "raisefailfastexception", "exitprocess", "exitthread",
        "terminateprocess", "terminatethread", "fatalappexit", "fatalappexita",
        "fatalappexitw", "fatalexit", "__fastfail", "longjmp", "_longjmp",
        "__cxa_throw"
    };
    for (const auto candidate : exact)
        if (ascii_equal(name, candidate))
            return true;
    return ascii_starts_with(name, "_invalid_parameter") ||
        ascii_starts_with(name, "__report");
}

struct selected_seed_t {
    const function_seed_t* seed = nullptr;
    std::uint64_t start = 0;
    std::optional<std::uint64_t> end;
};

bool stronger_seed(const selected_seed_t& lhs, const selected_seed_t& rhs) noexcept {
    const auto lhs_rank = provenance_rank(lhs.seed->provenance);
    const auto rhs_rank = provenance_rank(rhs.seed->provenance);
    if (lhs_rank != rhs_rank)
        return lhs_rank > rhs_rank;
    if (lhs.seed->confidence != rhs.seed->confidence)
        return lhs.seed->confidence > rhs.seed->confidence;
    if (lhs.seed->stable_source_id != rhs.seed->stable_source_id)
        return lhs.seed->stable_source_id < rhs.seed->stable_source_id;
    return lhs.seed->kind < rhs.seed->kind;
}

bool selected_seed_less(const selected_seed_t& lhs, const selected_seed_t& rhs) noexcept {
    if (lhs.start != rhs.start)
        return lhs.start < rhs.start;
    if (stronger_seed(lhs, rhs))
        return true;
    if (stronger_seed(rhs, lhs))
        return false;
    return lhs.seed->name < rhs.seed->name;
}

} 

workspace_result_t<block_recovery_result_t> function_recovery_t::build_blocks(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<target_fact_t>& targets,
    const std::vector<function_seed_t>& seeds,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (!valid_limits(limits)) {
        return workspace_result_t<block_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "function recovery limits are invalid", "blocks"));
    }
    auto valid = validate_instruction_stream(image, instructions, targets);
    if (!valid)
        return workspace_result_t<block_recovery_result_t>::failure(valid.error());
    block_recovery_result_t result;
    if (instructions.empty())
        return workspace_result_t<block_recovery_result_t>::success(std::move(result));
    std::vector<bool> leaders(instructions.size(), false);
    leaders.front() = true;
    std::map<std::uint64_t, std::size_t> instruction_index;
    for (std::size_t index = 0; index < instructions.size(); ++index)
        instruction_index.emplace(instructions[index].address.value, index);
    std::uint64_t checks = 0;
    for (const auto& seed : seeds) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(stop_error(cancel, "blocks"));
        }
        const auto rva = to_rva(image, seed.address);
        const auto found = rva ? instruction_index.find(*rva) : instruction_index.end();
        if (found != instruction_index.end())
            leaders[found->second] = true;
    }
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(stop_error(cancel, "blocks"));
        }
        const auto& instruction = instructions[index];
        const auto target_end = static_cast<std::uint64_t>(instruction.target_fact_begin) +
            instruction.target_fact_count;
        for (std::uint64_t target_index = instruction.target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (!target.direct || (target.kind != target_kind_record_t::branch &&
                target.kind != target_kind_record_t::call))
                continue;
            const auto rva = to_rva(image, target.target);
            if (!rva)
                continue;
            const auto found = instruction_index.find(*rva);
            if (found != instruction_index.end())
                leaders[found->second] = true;
        }
        const auto ends_block = (instruction.flow_flags &
            (flow_branch | flow_call | flow_return | flow_interrupt | flow_terminal)) != 0;
        if (ends_block && index + 1 < instructions.size())
            leaders[index + 1] = true;
        if (index + 1 < instructions.size() &&
            instruction_end(instruction) != instructions[index + 1].address.value)
            leaders[index + 1] = true;
    }
    for (std::size_t first = 0; first < instructions.size();) {
        if (cancel.stop_requested())
            return workspace_result_t<block_recovery_result_t>::failure(stop_error(cancel, "blocks"));
        std::size_t end = first + 1;
        while (end < instructions.size() && !leaders[end])
            ++end;
        basic_block_record_t block;
        block.id = kBlockEntityTag | static_cast<std::uint64_t>(result.blocks.size() + 1);
        block.start = instructions[first].address;
        block.end = rva_address(image, instruction_end(instructions[end - 1]));
        block.first_instruction = static_cast<std::uint32_t>(first);
        block.instruction_count = static_cast<std::uint32_t>(end - first);
        block.provenance = instructions[first].provenance;
        block.confidence = instructions[first].confidence;
        for (std::size_t index = first + 1; index < end; ++index) {
            if (provenance_rank(instructions[index].provenance) >
                    provenance_rank(block.provenance) ||
                (instructions[index].provenance == block.provenance &&
                 instructions[index].confidence > block.confidence)) {
                block.provenance = instructions[index].provenance;
                block.confidence = instructions[index].confidence;
            }
        }
        auto appended = append_bounded(result.blocks, std::move(block), limits.max_blocks,
            limits.max_result_bytes, result.storage_bytes, "blocks",
            "basic block storage exceeds analysis budget");
        if (!appended)
            return workspace_result_t<block_recovery_result_t>::failure(appended.error());
        first = end;
    }
    std::map<std::uint64_t, const basic_block_record_t*> blocks_by_start;
    for (const auto& block : result.blocks)
        blocks_by_start.emplace(block.start.value, &block);
    for (const auto& block : result.blocks) {
        if (++checks >= limits.cancellation_check_interval) {
            checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<block_recovery_result_t>::failure(stop_error(cancel, "blocks"));
        }
        const auto* last = block_last_instruction(block, instructions);
        if (!last)
            continue;
        const auto append_edge = [&](const address_t& target, edge_kind_t kind)
            -> workspace_result_t<void> {
            edge_record_t edge;
            edge.source_entity = block.id;
            edge.source = last->address;
            edge.target = target;
            edge.kind = kind;
            edge.provenance = last->provenance;
            edge.confidence = last->confidence;
            return append_bounded(result.edges, std::move(edge), limits.max_edges,
                limits.max_result_bytes, result.storage_bytes, "blocks",
                "CFG edge storage exceeds analysis budget");
        };
        const auto target_end = static_cast<std::uint64_t>(last->target_fact_begin) +
            last->target_fact_count;
        for (std::uint64_t target_index = last->target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (!target.direct || (target.kind != target_kind_record_t::branch &&
                target.kind != target_kind_record_t::call))
                continue;
            const auto rva = to_rva(image, target.target);
            if (!rva || !executable_rva(image, *rva) ||
                blocks_by_start.find(*rva) == blocks_by_start.end())
                continue;
            const auto kind = target.kind == target_kind_record_t::call ? edge_kind_t::call :
                ((last->flow_flags & flow_conditional) != 0
                    ? edge_kind_t::conditional_taken : edge_kind_t::unconditional);
            auto appended = append_edge(target.target, kind);
            if (!appended)
                return workspace_result_t<block_recovery_result_t>::failure(appended.error());
        }
        if ((last->flow_flags & flow_fallthrough) != 0) {
            const auto next = instruction_end(*last);
            const auto found = blocks_by_start.find(next);
            if (found != blocks_by_start.end()) {
                auto appended = append_edge(found->second->start, edge_kind_t::fallthrough);
                if (!appended)
                    return workspace_result_t<block_recovery_result_t>::failure(appended.error());
            }
        }
    }
    std::sort(result.edges.begin(), result.edges.end(), edge_less);
    result.edges.erase(std::unique(result.edges.begin(), result.edges.end(), edge_equal),
        result.edges.end());
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id = kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<block_recovery_result_t>::success(std::move(result));
}

workspace_result_t<function_recovery_result_t> function_recovery_t::recover_functions(
    const workspace_image_t& image,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<function_seed_t>& seeds,
    block_recovery_result_t block_result,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (!valid_limits(limits)) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "function recovery limits are invalid", "functions"));
    }
    function_recovery_result_t result;
    result.blocks = std::move(block_result.blocks);
    result.edges = std::move(block_result.edges);
    result.storage_bytes = block_result.storage_bytes;
    std::map<std::uint64_t, std::size_t> block_by_start;
    for (std::size_t index = 0; index < result.blocks.size(); ++index)
        block_by_start.emplace(result.blocks[index].start.value, index);
    std::vector<selected_seed_t> selected;
    selected.reserve(seeds.size());
    for (const auto& seed : seeds) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "functions"));
        const auto start = to_rva(image, seed.address);
        if (!start || block_by_start.find(*start) == block_by_start.end())
            continue;
        std::optional<std::uint64_t> end;
        if (seed.known_end) {
            end = to_rva(image, *seed.known_end);
            if (!end || *end <= *start)
                end.reset();
        }
        selected.push_back({&seed, *start, end});
    }
    std::sort(selected.begin(), selected.end(), selected_seed_less);
    selected.erase(std::unique(selected.begin(), selected.end(),
        [](const selected_seed_t& lhs, const selected_seed_t& rhs) {
            return lhs.start == rhs.start;
        }), selected.end());
    if (selected.size() > limits.max_functions) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, "function seed count exceeds analysis budget", "functions"));
    }
    std::vector<std::vector<std::size_t>> successors(result.blocks.size());
    for (const auto& edge : result.edges) {
        if (edge.kind == edge_kind_t::call || edge.kind == edge_kind_t::tail_call ||
            edge.kind == edge_kind_t::exception_edge)
            continue;
        const auto source = static_cast<std::size_t>(edge.source_entity & 0x00FFFFFFFFFFFFFFULL);
        const auto target = to_rva(image, edge.target);
        const auto found = target ? block_by_start.find(*target) : block_by_start.end();
        if (source == 0 || source > result.blocks.size() || found == block_by_start.end())
            continue;
        successors[source - 1].push_back(found->second);
    }
    for (auto& values : successors) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    }
    std::vector<std::optional<selected_seed_t>> owners(result.blocks.size());
    for (const auto& selection : selected) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "functions"));
        const auto start = block_by_start.find(selection.start);
        if (start == block_by_start.end())
            continue;
        std::vector<std::uint8_t> visited(result.blocks.size(), 0);
        std::vector<std::size_t> reached;
        std::deque<std::size_t> pending;
        pending.push_back(start->second);
        while (!pending.empty()) {
            if (cancel.stop_requested())
                return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "functions"));
            const auto block_index = pending.front();
            pending.pop_front();
            if (visited[block_index] != 0)
                continue;
            if (result.blocks[block_index].start.value < selection.start ||
                (selection.end && result.blocks[block_index].start.value >= *selection.end))
                continue;
            visited[block_index] = 1;
            if (reached.size() >= limits.max_blocks_per_function) {
                return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "function reachability exceeds analysis budget", "functions"));
            }
            reached.push_back(block_index);
            for (const auto successor : successors[block_index])
                if (visited[successor] == 0)
                    pending.push_back(successor);
        }
        if (reached.empty())
            continue;
        std::sort(reached.begin(), reached.end());
        function_record_t function;
        function.id = kFunctionEntityTag | static_cast<std::uint64_t>(result.functions.size() + 1);
        function.start = rva_address(image, selection.start);
        function.end = result.blocks[reached.back()].end;
        function.provenance = selection.seed->provenance;
        function.confidence = selection.seed->confidence;
        function.noreturn = selection.seed->noreturn || known_noreturn_name(selection.seed->name);
        function.thunk = reached.size() == 1 && result.blocks[reached.front()].instruction_count == 1;
        function.first_chunk = static_cast<std::uint32_t>(result.function_chunks.size());
        function.first_block_membership = static_cast<std::uint32_t>(
            result.function_block_memberships.size());
        std::uint64_t range_bytes = 0;
        std::uint64_t range_peak = 0;
        if (!checked_mul_u64(reached.size(), sizeof(address_range_t), range_bytes) ||
            !checked_add_u64(result.storage_bytes, range_bytes, range_peak) ||
            range_peak > limits.max_result_bytes) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "function range storage exceeds analysis budget", "functions"));
        }
        result.storage_bytes = range_peak;
        function.chunks.reserve(reached.size());
        std::size_t run_begin = 0;
        while (run_begin < reached.size()) {
            std::size_t run_end = run_begin + 1;
            while (run_end < reached.size() && reached[run_end] == reached[run_end - 1] + 1 &&
                   result.blocks[reached[run_end - 1]].end ==
                       result.blocks[reached[run_end]].start)
                ++run_end;
            function_chunk_record_t chunk;
            chunk.id = kFunctionChunkEntityTag |
                static_cast<std::uint64_t>(result.function_chunks.size() + 1);
            chunk.function_id = function.id;
            chunk.first_block = static_cast<std::uint32_t>(reached[run_begin]);
            chunk.block_count = static_cast<std::uint32_t>(run_end - run_begin);
            chunk.start = result.blocks[reached[run_begin]].start;
            chunk.end = result.blocks[reached[run_end - 1]].end;
            chunk.provenance = function.provenance;
            chunk.confidence = function.confidence;
            auto appended_chunk = append_bounded(result.function_chunks, std::move(chunk),
                limits.max_function_memberships, limits.max_result_bytes, result.storage_bytes, "functions",
                "function chunk storage exceeds analysis budget");
            if (!appended_chunk)
                return workspace_result_t<function_recovery_result_t>::failure(appended_chunk.error());
            if (run_begin == 0) {
                function.first_block = static_cast<std::uint32_t>(reached[run_begin]);
                function.block_count = static_cast<std::uint32_t>(run_end - run_begin);
            }
            ++function.chunk_count;
            address_range_t range;
            range.rva_start = result.blocks[reached[run_begin]].start.value;
            range.rva_end = result.blocks[reached[run_end - 1]].end.value;
            function.chunks.push_back(range);
            run_begin = run_end;
        }
        for (std::uint32_t ordinal = 0; ordinal < reached.size(); ++ordinal) {
            const auto block_index = reached[ordinal];
            function_block_membership_record_t membership;
            membership.function_id = function.id;
            membership.chunk_id = result.function_chunks[function.first_chunk].id;
            for (const auto& chunk : result.function_chunks) {
                if (chunk.function_id != function.id)
                    continue;
                const auto chunk_end = static_cast<std::size_t>(chunk.first_block) + chunk.block_count;
                if (block_index >= chunk.first_block && block_index < chunk_end) {
                    membership.chunk_id = chunk.id;
                    break;
                }
            }
            membership.block_id = result.blocks[block_index].id;
            membership.block_index = static_cast<std::uint32_t>(block_index);
            membership.ordinal = ordinal;
            if (!owners[block_index] || stronger_seed(selection, *owners[block_index])) {
                owners[block_index] = selection;
                result.blocks[block_index].function_id = function.id;
            }
            membership.shared = result.blocks[block_index].function_id != function.id;
            auto appended_membership = append_bounded(result.function_block_memberships,
                std::move(membership), limits.max_function_memberships,
                limits.max_result_bytes, result.storage_bytes, "functions",
                "function membership storage exceeds analysis budget");
            if (!appended_membership)
                return workspace_result_t<function_recovery_result_t>::failure(
                    appended_membership.error());
        }
        function.block_membership_count = static_cast<std::uint32_t>(
            result.function_block_memberships.size() - function.first_block_membership);
        auto appended_function = append_bounded(result.functions, std::move(function),
            limits.max_functions, limits.max_result_bytes, result.storage_bytes, "functions",
            "function storage exceeds analysis budget");
        if (!appended_function)
            return workspace_result_t<function_recovery_result_t>::failure(appended_function.error());
    }
    std::vector<std::uint8_t> shared_chunks(result.function_chunks.size(), 0);
    for (auto& membership : result.function_block_memberships) {
        if (membership.block_index >= result.blocks.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "function membership references an invalid block", "functions"));
        }
        membership.shared = result.blocks[membership.block_index].function_id != membership.function_id;
        const auto chunk_ordinal = membership.chunk_id & 0x00FFFFFFFFFFFFFFULL;
        if (membership.shared && chunk_ordinal != 0 && chunk_ordinal <= shared_chunks.size())
            shared_chunks[static_cast<std::size_t>(chunk_ordinal - 1)] = 1;
    }
    for (std::size_t index = 0; index < result.function_chunks.size(); ++index)
        result.function_chunks[index].shared = shared_chunks[index] != 0;
    for (const auto& block : result.blocks) {
        if (block.function_id == 0) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "decoded block has no verified function seed", "functions"));
        }
    }
    for (const auto& function : result.functions) {
        const auto end = static_cast<std::uint64_t>(function.first_block) + function.block_count;
        if (end > result.blocks.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "function primary block range is invalid", "functions"));
        }
        for (std::uint64_t index = function.first_block; index < end; ++index) {
            if (result.blocks[static_cast<std::size_t>(index)].function_id != function.id) {
                return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "function primary block ownership is ambiguous", "functions"));
            }
        }
    }
    for (std::size_t index = 1; index < result.functions.size(); ++index) {
        if (result.functions[index - 1].end.value > result.functions[index].start.value) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "verified function recoveries overlap", "functions"));
        }
    }
    return workspace_result_t<function_recovery_result_t>::success(std::move(result));
}

workspace_result_t<function_recovery_result_t> function_recovery_t::finalize_cfg_calls(
    const workspace_image_t& image,
    const byte_provider_t&,
    const std::vector<instruction_record_t>& instructions,
    const std::vector<operand_fact_t>&,
    const std::vector<target_fact_t>& targets,
    function_recovery_result_t result,
    const function_recovery_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (!valid_limits(limits)) {
        return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "function recovery limits are invalid", "cfg_calls"));
    }
    std::map<std::uint64_t, const function_record_t*> functions_by_start;
    std::map<std::uint64_t, const basic_block_record_t*> blocks_by_start;
    std::map<std::uint64_t, const image_import_t*> imports_by_slot;
    for (const auto& function : result.functions)
        functions_by_start.emplace(function.start.value, &function);
    for (const auto& block : result.blocks)
        blocks_by_start.emplace(block.start.value, &block);
    for (const auto& imported : image.imports) {
        const auto slot = to_rva(image, imported.address);
        if (slot)
            imports_by_slot.emplace(*slot, &imported);
    }
    std::vector<std::uint8_t> noreturn_sources(result.blocks.size(), 0);
    const auto block_index = [&result](entity_id_t id) -> std::optional<std::size_t> {
        if ((id & 0xFF00000000000000ULL) != kBlockEntityTag)
            return std::nullopt;
        const auto ordinal = id & 0x00FFFFFFFFFFFFFFULL;
        if (ordinal == 0 || ordinal > result.blocks.size())
            return std::nullopt;
        const auto index = static_cast<std::size_t>(ordinal - 1);
        return result.blocks[index].id == id ? std::optional<std::size_t>(index) : std::nullopt;
    };
    for (auto& edge : result.edges) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "cfg_calls"));
        const auto target = to_rva(image, edge.target);
        if (!target)
            continue;
        const auto function = functions_by_start.find(*target);
        const auto source = block_index(edge.source_entity);
        if (edge.kind == edge_kind_t::unconditional && function != functions_by_start.end() &&
            source && result.blocks[*source].function_id != function->second->id) {
            edge.kind = edge_kind_t::tail_call;
            edge.target_entity = function->second->id;
        } else if ((edge.kind == edge_kind_t::call || edge.kind == edge_kind_t::tail_call) &&
            function != functions_by_start.end()) {
            edge.target_entity = function->second->id;
        } else if (const auto block = blocks_by_start.find(*target);
                   block != blocks_by_start.end()) {
            edge.target_entity = block->second->id;
        }
        if (source && edge.target_entity &&
            ((*edge.target_entity & 0xFF00000000000000ULL) == kFunctionEntityTag)) {
            const auto ordinal = *edge.target_entity & 0x00FFFFFFFFFFFFFFULL;
            if (ordinal != 0 && ordinal <= result.functions.size() &&
                result.functions[static_cast<std::size_t>(ordinal - 1)].noreturn)
                noreturn_sources[*source] = 1;
        }
    }
    for (std::size_t index = 0; index < result.blocks.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "cfg_calls"));
        const auto& block = result.blocks[index];
        const auto* call = block_last_instruction(block, instructions);
        if (!call || (call->flow_flags & flow_call) == 0)
            continue;
        std::uint64_t target_end = 0;
        if (!checked_add_u64(call->target_fact_begin, call->target_fact_count, target_end) ||
            target_end > targets.size()) {
            return workspace_result_t<function_recovery_result_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "call target-fact range is invalid", "cfg_calls"));
        }
        for (std::uint64_t target_index = call->target_fact_begin;
             target_index < target_end; ++target_index) {
            const auto& target = targets[static_cast<std::size_t>(target_index)];
            if (target.kind != target_kind_record_t::data &&
                target.kind != target_kind_record_t::call)
                continue;
            const auto slot = to_rva(image, target.target);
            const auto imported = slot ? imports_by_slot.find(*slot) : imports_by_slot.end();
            if (imported == imports_by_slot.end())
                continue;
            edge_record_t edge;
            edge.source_entity = block.id;
            edge.source = call->address;
            edge.target = target.target;
            edge.kind = edge_kind_t::call;
            edge.provenance = fact_provenance_t::relocation;
            edge.confidence = std::min<std::uint8_t>(call->confidence, 95);
            auto appended = append_bounded(result.edges, std::move(edge), limits.max_edges,
                limits.max_result_bytes, result.storage_bytes, "cfg_calls",
                "import call edge storage exceeds analysis budget");
            if (!appended)
                return workspace_result_t<function_recovery_result_t>::failure(appended.error());
            if (imported->second->name && known_noreturn_name(*imported->second->name))
                noreturn_sources[index] = 1;
            break;
        }
    }
    std::size_t output = 0;
    for (std::size_t index = 0; index < result.edges.size(); ++index) {
        if (cancel.stop_requested())
            return workspace_result_t<function_recovery_result_t>::failure(stop_error(cancel, "cfg_calls"));
        const auto& edge = result.edges[index];
        const auto source = block_index(edge.source_entity);
        const bool remove = edge.kind == edge_kind_t::fallthrough && source &&
            noreturn_sources[*source] != 0;
        if (!remove) {
            if (output != index)
                result.edges[output] = std::move(result.edges[index]);
            ++output;
        }
    }
    result.edges.resize(output);
    std::sort(result.edges.begin(), result.edges.end(), edge_less);
    result.edges.erase(std::unique(result.edges.begin(), result.edges.end(), edge_equal),
        result.edges.end());
    for (std::size_t index = 0; index < result.edges.size(); ++index)
        result.edges[index].id = kEdgeEntityTag | static_cast<std::uint64_t>(index + 1);
    return workspace_result_t<function_recovery_result_t>::success(std::move(result));
}

}
