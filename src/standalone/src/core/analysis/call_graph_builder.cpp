#include "call_graph_builder.hpp"

#include "workspace/checked_range.hpp"
#include "workspace/parallel_pass.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <thread>
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

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kBlockEntityTag = 2ULL << 56;
constexpr std::uint64_t kFunctionEntityTag = 3ULL << 56;
constexpr std::uint32_t kCancellationStride = 256;
constexpr std::size_t kIndexShardFloor = 65536;
constexpr std::size_t kCandidateShardFloor = 4096;

std::size_t pass_shard_count(std::size_t items, std::size_t floor) noexcept {
    if (items == 0 || floor == 0)
        return 0;
    const unsigned hardware = std::thread::hardware_concurrency();
    const std::size_t maximum = (std::max)(std::size_t{1},
        static_cast<std::size_t>(hardware == 0 ? 1u : 4u * hardware));
    const std::size_t wanted = (items + floor - 1) / floor;
    return (std::max)(std::size_t{1}, (std::min)(wanted, maximum));
}

struct shard_range_t {
    std::size_t begin = 0;
    std::size_t end = 0;
};

std::vector<shard_range_t> partition_shards(std::size_t items, std::size_t count) {
    std::vector<shard_range_t> shards;
    shards.reserve(count);
    const std::size_t base = count == 0 ? 0 : items / count;
    const std::size_t extra = count == 0 ? 0 : items % count;
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t size = base + (index < extra ? 1 : 0);
        shards.push_back({cursor, cursor + size});
        cursor += size;
    }
    return shards;
}

struct shard_failure_t {
    std::atomic<bool> failed{false};
    std::mutex mutex;
    std::size_t lowest_shard = (std::numeric_limits<std::size_t>::max)();
    workspace_error_t error{};

    void report(std::size_t shard, workspace_error_t value) {
        failed.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(mutex);
        if (shard < lowest_shard) {
            lowest_shard = shard;
            error = std::move(value);
        }
    }

    workspace_error_t take_error() {
        std::lock_guard<std::mutex> lock(mutex);
        return std::move(error);
    }
};

struct shard_poll_t {
    const cancellation_token_t* cancel = nullptr;
    shard_failure_t* failure = nullptr;
    std::size_t shard = 0;
    const char* phase = nullptr;

    bool stopped(std::size_t iteration) const {
        if ((iteration & (kCancellationStride - 1)) != 0)
            return false;
        if (failure->failed.load(std::memory_order_relaxed))
            return true;
        if (cancel->stop_requested()) {
            failure->report(shard, stop_error(*cancel, phase));
            return true;
        }
        return false;
    }
};

template <typename Fn>
void guarded_shard(shard_failure_t& failure, std::size_t shard,
                   const char* alloc_message, const char* phase, Fn&& fn) {
    try {
        fn();
    } catch (const std::bad_alloc&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, alloc_message, phase));
    } catch (const std::length_error&) {
        failure.report(shard, make_workspace_error(
            workspace_error_code_t::limit_exceeded, alloc_message, phase));
    }
}

template <typename Fn>
void run_sharded(std::size_t shard_total, Fn&& shard_fn) {
    parallel_executor_t::run(shard_total, parallel_worker_count(),
        "analysis.call_graph_builder", std::forward<Fn>(shard_fn));
}

template <typename T, typename Equal>
void parallel_unique_erase(std::vector<T>& values, Equal&& equal) {
    if (values.size() < 2)
        return;
    const std::size_t count = values.size();
    const auto shards = partition_shards(count,
        pass_shard_count(count, kIndexShardFloor));
    std::vector<std::uint8_t> keep(count, 0);
    std::vector<std::uint64_t> shard_keeps(shards.size(), 0);
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        std::uint64_t kept = 0;
        for (std::size_t index = range.begin; index < range.end; ++index) {
            const auto flagged = index == 0 || !equal(values[index - 1], values[index]);
            keep[index] = flagged ? static_cast<std::uint8_t>(1)
                                  : static_cast<std::uint8_t>(0);
            kept += flagged ? 1ULL : 0ULL;
        }
        shard_keeps[shard] = kept;
    });
    std::uint64_t total = 0;
    for (auto& base : shard_keeps) {
        const auto offset = total;
        total += base;
        base = offset;
    }
    std::vector<T> compacted(static_cast<std::size_t>(total));
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        auto cursor = shard_keeps[shard];
        for (std::size_t index = range.begin; index < range.end; ++index) {
            if (keep[index] != 0)
                compacted[static_cast<std::size_t>(cursor++)] = std::move(values[index]);
        }
    });
    values = std::move(compacted);
}

struct merge_clock_t {
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    std::uint64_t elapsed_ns() const {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<
            std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count());
    }
};

workspace_result_t<void> account_bytes(std::uint64_t& storage_bytes, std::uint64_t bytes,
    std::uint64_t maximum_bytes, const char* phase, const char* message) {
    std::uint64_t peak = 0;
    if (!checked_add_u64(storage_bytes, bytes, peak)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow, message, phase));
    }
    if (peak > maximum_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded, message, phase));
    }
    storage_bytes = peak;
    return workspace_result_t<void>::success();
}

std::optional<std::size_t> instruction_index_by_address(
    const std::vector<instruction_record_t>& instructions,
    const address_t& address) noexcept {
    const auto found = std::lower_bound(instructions.begin(), instructions.end(), address,
        [](const instruction_record_t& instruction, const address_t& value) {
            return instruction.address < value;
        });
    if (found != instructions.end() && found->address == address)
        return static_cast<std::size_t>(found - instructions.begin());
    return std::nullopt;
}

std::optional<std::size_t> function_index_by_address(
    const std::vector<function_record_t>& functions, const address_t& address) noexcept {
    const auto found = std::lower_bound(functions.begin(), functions.end(), address,
        [](const function_record_t& function, const address_t& value) {
            return function.start < value;
        });
    if (found != functions.end() && found->start == address)
        return static_cast<std::size_t>(found - functions.begin());
    return std::nullopt;
}

struct entity_id_index_t {
    std::uint64_t tag_mask = 0;
    std::size_t count = 0;
    bool identity = false;
    std::vector<std::uint32_t> ordinal_plus_one;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> sorted_entries;

    std::optional<std::size_t> find(entity_id_t id) const noexcept {
        if (identity) {
            if ((id & 0xFF00000000000000ULL) != tag_mask)
                return std::nullopt;
            const auto ordinal = id & entity_ordinal_mask;
            if (ordinal == 0 || ordinal > count)
                return std::nullopt;
            return static_cast<std::size_t>(ordinal - 1);
        }
        if (!ordinal_plus_one.empty()) {
            if ((id & 0xFF00000000000000ULL) != tag_mask)
                return std::nullopt;
            const auto ordinal = id & entity_ordinal_mask;
            if (ordinal == 0 || ordinal > ordinal_plus_one.size())
                return std::nullopt;
            const auto slot = ordinal_plus_one[static_cast<std::size_t>(ordinal - 1)];
            if (slot == 0)
                return std::nullopt;
            return static_cast<std::size_t>(slot - 1);
        }
        const auto found = std::lower_bound(sorted_entries.begin(), sorted_entries.end(),
            id,
            [](const std::pair<std::uint64_t, std::uint32_t>& entry, std::uint64_t value) {
                return entry.first < value;
            });
        if (found != sorted_entries.end() && found->first == id)
            return static_cast<std::size_t>(found->second);
        return std::nullopt;
    }
};

struct entity_id_index_build_t {
    entity_id_index_t index;
    bool duplicate = false;
};

template <typename Record, typename IdOf>
entity_id_index_build_t build_entity_id_index(const std::vector<Record>& records,
    std::uint64_t tag_mask, IdOf&& id_of, const cancellation_token_t& cancel) {
    entity_id_index_build_t built;
    built.index.tag_mask = tag_mask;
    built.index.count = records.size();
    if (records.empty()) {
        built.index.identity = true;
        return built;
    }
    const auto shards = partition_shards(records.size(),
        pass_shard_count(records.size(), kIndexShardFloor));
    std::vector<std::uint8_t> shard_identity(shards.size(), 1);
    std::vector<std::uint8_t> shard_tag_dense(shards.size(), 1);
    run_sharded(shards.size(), [&](std::size_t shard) {
        const auto range = shards[shard];
        bool identity = true;
        bool tag_dense = true;
        for (std::size_t row = range.begin; row < range.end; ++row) {
            if (((row - range.begin) & (kCancellationStride - 1)) == 0 &&
                cancel.stop_requested()) {
                identity = false;
                tag_dense = false;
                break;
            }
            const auto id = id_of(records[row]);
            const auto ordinal = id & entity_ordinal_mask;
            identity = identity && id == (tag_mask | (row + 1));
            tag_dense = tag_dense && (id & 0xFF00000000000000ULL) == tag_mask &&
                ordinal >= 1 && ordinal <= records.size();
        }
        shard_identity[shard] = identity ? 1 : 0;
        shard_tag_dense[shard] = tag_dense ? 1 : 0;
    });
    const auto all_identity = std::all_of(shard_identity.begin(), shard_identity.end(),
        [](std::uint8_t value) { return value != 0; });
    if (all_identity) {
        built.index.identity = true;
        return built;
    }
    const auto all_tag_dense = std::all_of(shard_tag_dense.begin(), shard_tag_dense.end(),
        [](std::uint8_t value) { return value != 0; });
    if (all_tag_dense) {
        std::vector<std::atomic<std::uint32_t>> slots(records.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row)
                slots[row].store(0, std::memory_order_relaxed);
        });
        std::atomic<bool> duplicate{false};
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row) {
                const auto ordinal = id_of(records[row]) & entity_ordinal_mask;
                auto& slot = slots[static_cast<std::size_t>(ordinal - 1)];
                const auto desired = static_cast<std::uint32_t>(row + 1);
                std::uint32_t observed = slot.load(std::memory_order_relaxed);
                for (;;) {
                    if (observed != 0) {
                        duplicate.store(true, std::memory_order_relaxed);
                        break;
                    }
                    if (slot.compare_exchange_weak(observed, desired,
                            std::memory_order_relaxed))
                        break;
                }
            }
        });
        if (duplicate.load(std::memory_order_relaxed)) {
            built.duplicate = true;
            return built;
        }
        built.index.ordinal_plus_one.resize(records.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t row = range.begin; row < range.end; ++row)
                built.index.ordinal_plus_one[row] =
                    slots[row].load(std::memory_order_relaxed);
        });
        return built;
    }
    built.index.sorted_entries.reserve(records.size());
    for (std::size_t row = 0; row < records.size(); ++row)
        built.index.sorted_entries.emplace_back(id_of(records[row]),
            static_cast<std::uint32_t>(row));
    std::stable_sort(built.index.sorted_entries.begin(),
        built.index.sorted_entries.end(),
        [](const std::pair<std::uint64_t, std::uint32_t>& lhs,
           const std::pair<std::uint64_t, std::uint32_t>& rhs) {
            return lhs.first < rhs.first;
        });
    for (std::size_t row = 1; row < built.index.sorted_entries.size(); ++row) {
        if (built.index.sorted_entries[row - 1].first ==
            built.index.sorted_entries[row].first) {
            built.duplicate = true;
            break;
        }
    }
    return built;
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
    shard_failure_t failure;
    {
        const auto shards = partition_shards(instructions.size(),
            pass_shard_count(instructions.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph.instructions", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.instructions"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& instruction = instructions[index];
                    std::uint64_t target_end = 0;
                    if (instruction.id == 0 ||
                        !checked_add_u64(instruction.target_fact_begin,
                            instruction.target_fact_count, target_end) ||
                        target_end > targets.size() ||
                        (index != 0 &&
                         !(instructions[index - 1].address < instruction.address))) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "call graph instruction stream is malformed",
                            "call_graph.instructions"));
                        return;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    }
    auto instruction_ids = build_entity_id_index(instructions, kInstructionEntityTag,
        [](const instruction_record_t& instruction) { return instruction.id; }, cancel);
    if (instruction_ids.duplicate) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "call graph instruction stream is malformed", "call_graph.instructions"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<call_graph_result_t>::failure(
            stop_error(cancel, "call_graph.instructions"));
    {
        const auto shards = partition_shards(recovery.functions.size(),
            pass_shard_count(recovery.functions.size(), kCandidateShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph.functions", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.functions"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& function = recovery.functions[index];
                    if (function.id == 0 ||
                        function.end.value <= function.start.value ||
                        (index != 0 &&
                         !(recovery.functions[index - 1].start < function.start))) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "call graph function catalog is malformed",
                            "call_graph.functions"));
                        return;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    }
    auto function_ids = build_entity_id_index(recovery.functions, kFunctionEntityTag,
        [](const function_record_t& function) { return function.id; }, cancel);
    if (function_ids.duplicate) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "call graph function catalog is malformed", "call_graph.functions"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<call_graph_result_t>::failure(
            stop_error(cancel, "call_graph.functions"));
    {
        const auto shards = partition_shards(recovery.functions.size(),
            pass_shard_count(recovery.functions.size(), kCandidateShardFloor));
        std::vector<std::vector<call_graph_node_record_t>> shard_nodes(shards.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph", [&]() {
                auto& nodes = shard_nodes[shard];
                const auto range = shards[shard];
                nodes.reserve(range.end - range.begin);
                shard_poll_t poll{&cancel, &failure, shard, "call_graph"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    call_graph_node_record_t node;
                    node.function_id = recovery.functions[index].id;
                    node.address = recovery.functions[index].start;
                    nodes.push_back(node);
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
        merge_clock_t node_clock;
        std::uint64_t node_total = 0;
        for (const auto& nodes : shard_nodes) {
            if (!checked_add_u64(node_total, nodes.size(), node_total)) {
                return workspace_result_t<call_graph_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "call graph node storage exceeds analysis budget", "call_graph"));
            }
        }
        if (node_total > limits.max_nodes) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "call graph node storage exceeds analysis budget", "call_graph"));
        }
        std::uint64_t node_bytes = 0;
        if (!checked_mul_u64(node_total, sizeof(call_graph_node_record_t), node_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph node storage exceeds analysis budget", "call_graph"));
        }
        auto accounted = account_bytes(result.storage_bytes, node_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph node storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
        result.nodes.resize(static_cast<std::size_t>(node_total));
        {
            std::vector<std::uint64_t> node_bases(shard_nodes.size(), 0);
            std::uint64_t node_cursor = 0;
            for (std::size_t index = 0; index < shard_nodes.size(); ++index) {
                node_bases[index] = node_cursor;
                node_cursor += shard_nodes[index].size();
            }
            run_sharded(shard_nodes.size(), [&](std::size_t shard) {
                auto& nodes = shard_nodes[shard];
                auto cursor = node_bases[shard];
                for (auto& node : nodes)
                    result.nodes[static_cast<std::size_t>(cursor++)] = std::move(node);
            });
        }
        parallel_sort(result.nodes.begin(), result.nodes.end(),
            [](const call_graph_node_record_t& lhs,
               const call_graph_node_record_t& rhs) {
                if (lhs.address != rhs.address)
                    return lhs.address < rhs.address;
                return lhs.function_id < rhs.function_id;
            });
        result.shard_merge_ns += node_clock.elapsed_ns();
    }
    auto node_by_function = build_entity_id_index(result.nodes, kFunctionEntityTag,
        [](const call_graph_node_record_t& node) { return node.function_id; }, cancel);
    if (cancel.stop_requested())
        return workspace_result_t<call_graph_result_t>::failure(
            stop_error(cancel, "call_graph"));
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph.blocks", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.blocks"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& block = recovery.blocks[index];
                    if (block.id == 0 || block.instruction_count == 0 ||
                        block.first_instruction > instructions.size() ||
                        block.instruction_count >
                            instructions.size() - block.first_instruction ||
                        !function_ids.index.find(block.function_id)) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "call graph block catalog is malformed", "call_graph.blocks"));
                        return;
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    }
    auto block_ids = build_entity_id_index(recovery.blocks, kBlockEntityTag,
        [](const basic_block_record_t& block) { return block.id; }, cancel);
    if (block_ids.duplicate) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "call graph block catalog is malformed", "call_graph.blocks"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<call_graph_result_t>::failure(
            stop_error(cancel, "call_graph.blocks"));
    std::vector<std::atomic<std::uint32_t>> caller_counts(recovery.blocks.size());
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index)
                caller_counts[index].store(0, std::memory_order_relaxed);
        });
    }
    {
        const auto shards = partition_shards(recovery.function_block_memberships.size(),
            pass_shard_count(recovery.function_block_memberships.size(),
                kCandidateShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph.memberships", [&]() {
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.memberships"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& membership = recovery.function_block_memberships[index];
                    const auto block = block_ids.index.find(membership.block_id);
                    if (!block || membership.block_index != *block ||
                        !function_ids.index.find(membership.function_id)) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "call graph function membership is malformed",
                            "call_graph.memberships"));
                        return;
                    }
                    caller_counts[*block].fetch_add(1, std::memory_order_relaxed);
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    }
    std::vector<std::uint64_t> caller_offsets(recovery.blocks.size() + 1, 0);
    for (std::size_t index = 0; index < recovery.blocks.size(); ++index)
        caller_offsets[index + 1] = caller_offsets[index] + 1 +
            caller_counts[index].load(std::memory_order_relaxed);
    std::vector<entity_id_t> callers_flat(
        static_cast<std::size_t>(caller_offsets.back()));
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index)
                callers_flat[static_cast<std::size_t>(caller_offsets[index])] =
                    recovery.blocks[index].function_id;
        });
    }
    std::vector<std::atomic<std::uint64_t>> caller_cursors(recovery.blocks.size());
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index)
                caller_cursors[index].store(caller_offsets[index] + 1,
                    std::memory_order_relaxed);
        });
    }
    {
        const auto shards = partition_shards(recovery.function_block_memberships.size(),
            pass_shard_count(recovery.function_block_memberships.size(),
                kCandidateShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                const auto& membership = recovery.function_block_memberships[index];
                const auto block = block_ids.index.find(membership.block_id);
                if (!block)
                    continue;
                const auto slot = caller_cursors[*block].fetch_add(1,
                    std::memory_order_relaxed);
                callers_flat[static_cast<std::size_t>(slot)] = membership.function_id;
            }
        });
    }
    std::vector<std::uint32_t> caller_unique(recovery.blocks.size(), 0);
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                const auto first = callers_flat.begin() +
                    static_cast<std::ptrdiff_t>(caller_offsets[index]);
                const auto last = callers_flat.begin() +
                    static_cast<std::ptrdiff_t>(caller_offsets[index + 1]);
                std::sort(first, last);
                caller_unique[index] = static_cast<std::uint32_t>(
                    std::unique(first, last) - first);
            }
        });
    }
    {
        std::uint64_t compacted = 0;
        for (std::size_t index = 0; index < recovery.blocks.size(); ++index) {
            const auto begin = caller_offsets[index];
            const auto count = static_cast<std::uint64_t>(caller_unique[index]);
            if (begin != compacted) {
                for (std::uint64_t offset = 0; offset < count; ++offset) {
                    callers_flat[static_cast<std::size_t>(compacted + offset)] =
                        std::move(callers_flat[static_cast<std::size_t>(begin + offset)]);
                }
            }
            caller_offsets[index] = compacted;
            compacted += count;
        }
        caller_offsets[recovery.blocks.size()] = compacted;
        callers_flat.resize(static_cast<std::size_t>(compacted));
    }
    struct evidence_pair_t {
        std::uint32_t instruction = 0;
        indirect_call_candidate_t candidate;
    };
    struct evidence_shard_output_t {
        std::vector<evidence_pair_t> pairs;
        std::vector<call_graph_conflict_t> conflicts;
    };
    std::vector<evidence_pair_t> evidence_pairs;
    {
        const auto shards = partition_shards(indirect_candidates.size(),
            pass_shard_count(indirect_candidates.size(), kCandidateShardFloor));
        std::vector<evidence_shard_output_t> evidence_outputs(shards.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard,
                "call graph conflict storage exceeds analysis budget",
                "call_graph.candidates", [&]() {
                auto& output = evidence_outputs[shard];
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.candidates"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& candidate = indirect_candidates[index];
                    entity_id_t instruction_id = candidate.instruction_id;
                    if (instruction_id == 0) {
                        const auto found = instruction_index_by_address(instructions,
                            candidate.call_site);
                        if (found)
                            instruction_id = instructions[*found].id;
                    }
                    const auto instruction = instruction_ids.index.find(instruction_id);
                    if (!instruction) {
                        call_graph_conflict_t conflict;
                        conflict.kind = call_graph_conflict_kind_t::orphan_candidate;
                        conflict.instruction_id = candidate.instruction_id;
                        conflict.call_site_rva = candidate.call_site.value;
                        conflict.competing_target_rva = candidate.target.value;
                        conflict.competing_target_function_id =
                            candidate.target_function_id.value_or(0);
                        output.conflicts.push_back(std::move(conflict));
                        continue;
                    }
                    auto normalized = candidate;
                    normalized.instruction_id = instruction_id;
                    if (normalized.call_site == address_t{})
                        normalized.call_site = instructions[*instruction].address;
                    output.pairs.push_back({static_cast<std::uint32_t>(*instruction),
                        std::move(normalized)});
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
        merge_clock_t evidence_clock;
        std::uint64_t pair_total = 0;
        std::uint64_t conflict_total = 0;
        for (const auto& output : evidence_outputs) {
            if (!checked_add_u64(pair_total, output.pairs.size(), pair_total) ||
                !checked_add_u64(conflict_total, output.conflicts.size(), conflict_total)) {
                return workspace_result_t<call_graph_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "call graph conflict storage exceeds analysis budget",
                        "call_graph"));
            }
        }
        if (conflict_total > limits.max_conflicts) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "call graph conflict storage exceeds analysis budget", "call_graph"));
        }
        std::uint64_t conflict_bytes = 0;
        if (!checked_mul_u64(conflict_total, sizeof(call_graph_conflict_t),
                conflict_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph conflict storage exceeds analysis budget", "call_graph"));
        }
        auto accounted = account_bytes(result.storage_bytes, conflict_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph conflict storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
        evidence_pairs.resize(static_cast<std::size_t>(pair_total));
        result.conflicts.resize(static_cast<std::size_t>(conflict_total));
        {
            std::vector<std::uint64_t> pair_bases(evidence_outputs.size(), 0);
            std::vector<std::uint64_t> conflict_bases(evidence_outputs.size(), 0);
            std::uint64_t pair_cursor = 0;
            std::uint64_t conflict_cursor = 0;
            for (std::size_t index = 0; index < evidence_outputs.size(); ++index) {
                pair_bases[index] = pair_cursor;
                conflict_bases[index] = conflict_cursor;
                pair_cursor += evidence_outputs[index].pairs.size();
                conflict_cursor += evidence_outputs[index].conflicts.size();
            }
            run_sharded(evidence_outputs.size(), [&](std::size_t shard) {
                auto& output = evidence_outputs[shard];
                auto pair_slot = pair_bases[shard];
                for (auto& pair : output.pairs)
                    evidence_pairs[static_cast<std::size_t>(pair_slot++)] =
                        std::move(pair);
                auto conflict_slot = conflict_bases[shard];
                for (auto& conflict : output.conflicts)
                    result.conflicts[static_cast<std::size_t>(conflict_slot++)] =
                        std::move(conflict);
            });
        }
        result.shard_merge_ns += evidence_clock.elapsed_ns();
    }
    std::vector<std::uint64_t> evidence_offsets(instructions.size() + 1, 0);
    for (const auto& pair : evidence_pairs)
        ++evidence_offsets[static_cast<std::size_t>(pair.instruction) + 1];
    for (std::size_t index = 0; index < instructions.size(); ++index)
        evidence_offsets[index + 1] += evidence_offsets[index];
    std::vector<indirect_call_candidate_t> evidence_flat(evidence_pairs.size());
    {
        std::vector<std::uint64_t> cursors(evidence_offsets.begin(),
            evidence_offsets.end() - 1);
        for (auto& pair : evidence_pairs) {
            auto& slot = cursors[pair.instruction];
            evidence_flat[static_cast<std::size_t>(slot)] = std::move(pair.candidate);
            ++slot;
        }
    }
    struct block_edge_ref_t {
        std::uint32_t block = 0;
        std::uint32_t edge = 0;
    };
    std::vector<std::uint64_t> call_edge_offsets(recovery.blocks.size() + 1, 0);
    std::vector<std::uint64_t> tail_edge_offsets(recovery.blocks.size() + 1, 0);
    std::vector<std::uint32_t> call_edge_flat;
    std::vector<std::uint32_t> tail_edge_flat;
    {
        struct edge_ref_shard_output_t {
            std::vector<block_edge_ref_t> calls;
            std::vector<block_edge_ref_t> tails;
        };
        const auto shards = partition_shards(recovery.edges.size(),
            pass_shard_count(recovery.edges.size(), kIndexShardFloor));
        std::vector<edge_ref_shard_output_t> edge_outputs(shards.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph node storage exceeds analysis budget",
                "call_graph", [&]() {
                auto& output = edge_outputs[shard];
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph"};
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    if (poll.stopped(index - range.begin))
                        return;
                    const auto& edge = recovery.edges[index];
                    const auto block = block_ids.index.find(edge.source_entity);
                    if (!block)
                        continue;
                    if (edge.kind == edge_kind_t::call) {
                        output.calls.push_back({static_cast<std::uint32_t>(*block),
                            static_cast<std::uint32_t>(index)});
                    } else if (edge.kind == edge_kind_t::tail_call) {
                        output.tails.push_back({static_cast<std::uint32_t>(*block),
                            static_cast<std::uint32_t>(index)});
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
        merge_clock_t edge_clock;
        std::uint64_t call_total = 0;
        std::uint64_t tail_total = 0;
        for (const auto& output : edge_outputs) {
            call_total += output.calls.size();
            tail_total += output.tails.size();
        }
        std::vector<block_edge_ref_t> call_refs(static_cast<std::size_t>(call_total));
        std::vector<block_edge_ref_t> tail_refs(static_cast<std::size_t>(tail_total));
        {
            std::vector<std::uint64_t> call_bases(edge_outputs.size(), 0);
            std::vector<std::uint64_t> tail_bases(edge_outputs.size(), 0);
            std::uint64_t call_cursor = 0;
            std::uint64_t tail_cursor = 0;
            for (std::size_t index = 0; index < edge_outputs.size(); ++index) {
                call_bases[index] = call_cursor;
                tail_bases[index] = tail_cursor;
                call_cursor += edge_outputs[index].calls.size();
                tail_cursor += edge_outputs[index].tails.size();
            }
            run_sharded(edge_outputs.size(), [&](std::size_t shard) {
                auto& output = edge_outputs[shard];
                auto call_slot = call_bases[shard];
                for (auto& ref : output.calls)
                    call_refs[static_cast<std::size_t>(call_slot++)] = std::move(ref);
                auto tail_slot = tail_bases[shard];
                for (auto& ref : output.tails)
                    tail_refs[static_cast<std::size_t>(tail_slot++)] = std::move(ref);
            });
        }
        for (const auto& ref : call_refs)
            ++call_edge_offsets[ref.block + 1];
        for (std::size_t index = 0; index < recovery.blocks.size(); ++index)
            call_edge_offsets[index + 1] += call_edge_offsets[index];
        for (const auto& ref : tail_refs)
            ++tail_edge_offsets[ref.block + 1];
        for (std::size_t index = 0; index < recovery.blocks.size(); ++index)
            tail_edge_offsets[index + 1] += tail_edge_offsets[index];
        call_edge_flat.resize(call_refs.size());
        tail_edge_flat.resize(tail_refs.size());
        std::vector<std::uint64_t> call_cursors(call_edge_offsets.begin(),
            call_edge_offsets.end() - 1);
        for (const auto& ref : call_refs) {
            auto& slot = call_cursors[ref.block];
            call_edge_flat[static_cast<std::size_t>(slot)] = ref.edge;
            ++slot;
        }
        std::vector<std::uint64_t> tail_cursors(tail_edge_offsets.begin(),
            tail_edge_offsets.end() - 1);
        for (const auto& ref : tail_refs) {
            auto& slot = tail_cursors[ref.block];
            tail_edge_flat[static_cast<std::size_t>(slot)] = ref.edge;
            ++slot;
        }
        result.shard_merge_ns += edge_clock.elapsed_ns();
    }
    struct site_shard_output_t {
        std::vector<raw_site_t> sites;
        std::uint64_t candidates = 0;
    };
    std::vector<raw_site_t> raw_sites;
    {
        const auto shards = partition_shards(recovery.blocks.size(),
            pass_shard_count(recovery.blocks.size(), kIndexShardFloor));
        std::vector<site_shard_output_t> site_outputs(shards.size());
        run_sharded(shards.size(), [&](std::size_t shard) {
            guarded_shard(failure, shard, "call graph site storage exceeds analysis budget",
                "call_graph.sites", [&]() {
                auto& output = site_outputs[shard];
                const auto range = shards[shard];
                shard_poll_t poll{&cancel, &failure, shard, "call_graph.sites"};
                const auto append_raw_site = [&](raw_site_t site)
                    -> workspace_result_t<void> {
                    if (output.sites.size() >= limits.max_sites ||
                        site.candidates.size() >
                            limits.max_candidates - output.candidates) {
                        return workspace_result_t<void>::failure(make_workspace_error(
                            workspace_error_code_t::limit_exceeded,
                            "raw call graph evidence exceeds analysis limits",
                            "call_graph.sites"));
                    }
                    output.candidates += site.candidates.size();
                    output.sites.push_back(std::move(site));
                    return workspace_result_t<void>::success();
                };
                const auto edge_candidate = [&](const edge_record_t& edge) {
                    raw_candidate_t candidate;
                    candidate.target = edge.target;
                    if (edge.target_entity &&
                        function_ids.index.find(*edge.target_entity))
                        candidate.target_function_id = *edge.target_entity;
                    candidate.kind = indirect_call_candidate_kind_t::target_fact;
                    candidate.quality = quality_from(edge.provenance, edge.confidence);
                    candidate.stable_source_id = edge.id;
                    candidate.external_target = !candidate.target_function_id.has_value();
                    return candidate;
                };
                for (std::size_t block_index = range.begin; block_index < range.end;
                     ++block_index) {
                    if (poll.stopped(block_index - range.begin))
                        return;
                    const auto& block = recovery.blocks[block_index];
                    const auto* transfer = transfer_instruction(block_index, recovery,
                        instructions);
                    if (!transfer)
                        continue;
                    const auto caller_begin = caller_offsets[block_index];
                    const auto caller_end = caller_offsets[block_index + 1];
                    if (caller_begin == caller_end) {
                        failure.report(shard, make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "call site has no recovered caller", "call_graph.sites"));
                        return;
                    }
                    const auto instruction =
                        instruction_ids.index.find(transfer->id);
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
                            const auto function =
                                function_index_by_address(recovery.functions,
                                    target.target);
                            if (function)
                                candidate.target_function_id =
                                    recovery.functions[*function].id;
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
                        for (std::uint64_t ref_index = call_edge_offsets[block_index];
                             ref_index < call_edge_offsets[block_index + 1]; ++ref_index) {
                            prototype.candidates.push_back(edge_candidate(
                                recovery.edges[call_edge_flat[
                                    static_cast<std::size_t>(ref_index)]]));
                        }
                        if (instruction) {
                            for (std::uint64_t evidence_index =
                                     evidence_offsets[*instruction];
                                 evidence_index < evidence_offsets[*instruction + 1];
                                 ++evidence_index) {
                                const auto& evidence = evidence_flat[
                                    static_cast<std::size_t>(evidence_index)];
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
                            if (evidence_offsets[*instruction + 1] !=
                                evidence_offsets[*instruction])
                                prototype.indirect = true;
                        }
                        for (std::uint64_t caller_index = caller_begin;
                             caller_index < caller_end; ++caller_index) {
                            auto site = prototype;
                            site.source_function_id =
                                callers_flat[static_cast<std::size_t>(caller_index)];
                            auto appended = append_raw_site(std::move(site));
                            if (!appended) {
                                failure.report(shard, appended.error());
                                return;
                            }
                        }
                    }
                    if (tail_edge_offsets[block_index] ==
                        tail_edge_offsets[block_index + 1])
                        continue;
                    raw_site_t prototype;
                    prototype.source_block_id = block.id;
                    prototype.instruction_id = transfer->id;
                    prototype.address = transfer->address;
                    prototype.quality =
                        quality_from(transfer->provenance, transfer->confidence);
                    prototype.indirect = (transfer->flow_flags & flow_indirect) != 0;
                    prototype.tail_call = true;
                    for (std::uint64_t ref_index = tail_edge_offsets[block_index];
                         ref_index < tail_edge_offsets[block_index + 1]; ++ref_index) {
                        prototype.candidates.push_back(edge_candidate(
                            recovery.edges[tail_edge_flat[
                                static_cast<std::size_t>(ref_index)]]));
                    }
                    if (instruction) {
                        for (std::uint64_t evidence_index = evidence_offsets[*instruction];
                             evidence_index < evidence_offsets[*instruction + 1];
                             ++evidence_index) {
                            const auto& evidence = evidence_flat[
                                static_cast<std::size_t>(evidence_index)];
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
                        if (evidence_offsets[*instruction + 1] !=
                            evidence_offsets[*instruction])
                            prototype.indirect = true;
                    }
                    for (std::uint64_t caller_index = caller_begin;
                         caller_index < caller_end; ++caller_index) {
                        auto site = prototype;
                        site.source_function_id =
                            callers_flat[static_cast<std::size_t>(caller_index)];
                        auto appended = append_raw_site(std::move(site));
                        if (!appended) {
                            failure.report(shard, appended.error());
                            return;
                        }
                    }
                }
            });
        });
        if (failure.failed.load(std::memory_order_relaxed))
            return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
        merge_clock_t site_clock;
        std::uint64_t site_total = 0;
        std::uint64_t candidate_total = 0;
        for (const auto& output : site_outputs) {
            if (!checked_add_u64(site_total, output.sites.size(), site_total) ||
                !checked_add_u64(candidate_total, output.candidates, candidate_total)) {
                return workspace_result_t<call_graph_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "raw call graph evidence exceeds analysis limits",
                        "call_graph.sites"));
            }
        }
        if (site_total > limits.max_sites || candidate_total > limits.max_candidates) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "raw call graph evidence exceeds analysis limits", "call_graph.sites"));
        }
        raw_sites.resize(static_cast<std::size_t>(site_total));
        {
            std::vector<std::uint64_t> site_bases(site_outputs.size(), 0);
            std::uint64_t site_cursor = 0;
            for (std::size_t index = 0; index < site_outputs.size(); ++index) {
                site_bases[index] = site_cursor;
                site_cursor += site_outputs[index].sites.size();
            }
            run_sharded(site_outputs.size(), [&](std::size_t shard) {
                auto& output = site_outputs[shard];
                auto cursor = site_bases[shard];
                for (auto& site : output.sites)
                    raw_sites[static_cast<std::size_t>(cursor++)] = std::move(site);
            });
        }
        parallel_sort(raw_sites.begin(), raw_sites.end(), raw_site_less);
        result.shard_merge_ns += site_clock.elapsed_ns();
    }
    struct resolved_site_t {
        recovered_call_site_t site;
        std::vector<recovered_call_candidate_t> candidates;
        std::vector<call_graph_edge_record_t> edges;
        std::uint64_t candidate_base = 0;
        std::uint64_t edge_base = 0;
    };
    struct resolve_shard_output_t {
        std::vector<resolved_site_t> sites;
        std::vector<call_graph_conflict_t> conflicts;
        std::uint64_t site_base = 0;
        std::uint64_t indirect_sites = 0;
        std::uint64_t unresolved_sites = 0;
        bool bounded = false;
    };
    std::vector<std::atomic<std::uint64_t>> node_unresolved(result.nodes.size());
    std::vector<std::atomic<std::uint64_t>> node_outgoing(result.nodes.size());
    std::vector<std::atomic<std::uint64_t>> node_indirect(result.nodes.size());
    std::vector<std::atomic<std::uint64_t>> node_incoming(result.nodes.size());
    {
        const auto shards = partition_shards(result.nodes.size(),
            pass_shard_count(result.nodes.size(), kCandidateShardFloor));
        run_sharded(shards.size(), [&](std::size_t shard) {
            const auto range = shards[shard];
            for (std::size_t index = range.begin; index < range.end; ++index) {
                node_unresolved[index].store(0, std::memory_order_relaxed);
                node_outgoing[index].store(0, std::memory_order_relaxed);
                node_indirect[index].store(0, std::memory_order_relaxed);
                node_incoming[index].store(0, std::memory_order_relaxed);
            }
        });
    }
    const auto resolve_shards = partition_shards(raw_sites.size(),
        pass_shard_count(raw_sites.size(), kCandidateShardFloor));
    std::vector<resolve_shard_output_t> resolve_outputs(resolve_shards.size());
    run_sharded(resolve_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "call graph site storage exceeds analysis budget",
            "call_graph.resolve", [&]() {
            auto& output = resolve_outputs[shard];
            const auto range = resolve_shards[shard];
            shard_poll_t poll{&cancel, &failure, shard, "call_graph.resolve"};
            for (std::size_t site_index = range.begin; site_index < range.end;
                 ++site_index) {
                if (poll.stopped(site_index - range.begin))
                    return;
                auto& raw_site = raw_sites[site_index];
                resolved_site_t resolved;
                std::map<candidate_key_t, raw_candidate_t> merged_candidates;
                for (auto& candidate : raw_site.candidates) {
                    const auto exact = function_index_by_address(recovery.functions,
                        candidate.target);
                    const auto supplied = candidate.target_function_id;
                    const auto supplied_function = supplied
                        ? function_ids.index.find(*supplied) : std::nullopt;
                    if (supplied &&
                        (!supplied_function ||
                         recovery.functions[*supplied_function].start !=
                             candidate.target)) {
                        call_graph_conflict_t conflict;
                        conflict.kind =
                            call_graph_conflict_kind_t::candidate_identity_mismatch;
                        conflict.instruction_id = raw_site.instruction_id;
                        conflict.source_function_id = raw_site.source_function_id;
                        conflict.call_site_rva = raw_site.address.value;
                        conflict.selected_target_rva = candidate.target.value;
                        if (exact)
                            conflict.selected_target_function_id =
                                recovery.functions[*exact].id;
                        conflict.competing_target_rva = candidate.target.value;
                        conflict.competing_target_function_id = *supplied;
                        output.conflicts.push_back(std::move(conflict));
                        candidate.target_function_id.reset();
                    }
                    if (exact)
                        candidate.target_function_id = recovery.functions[*exact].id;
                    candidate.external_target = !candidate.target_function_id.has_value();
                    candidate_key_t key;
                    key.target = candidate.target;
                    key.target_function_id = candidate.target_function_id.value_or(0);
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
                        output.conflicts.push_back(std::move(conflict));
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
                    output.conflicts.push_back(std::move(conflict));
                    ranked.resize(limits.max_candidates_per_site);
                    output.bounded = true;
                }
                auto& site = resolved.site;
                site.id = call_site_entity_tag |
                    static_cast<std::uint64_t>(site_index + 1);
                site.source_function_id = raw_site.source_function_id;
                site.source_block_id = raw_site.source_block_id;
                site.instruction_id = raw_site.instruction_id;
                site.address = raw_site.address;
                site.candidate_count = static_cast<std::uint32_t>(ranked.size());
                site.indirect = raw_site.indirect;
                site.tail_call = raw_site.tail_call;
                site.unresolved = ranked.empty();
                const auto site_id = site.id;
                if (raw_site.indirect)
                    ++output.indirect_sites;
                if (ranked.empty()) {
                    ++output.unresolved_sites;
                    call_graph_conflict_t conflict;
                    conflict.kind = call_graph_conflict_kind_t::unresolved_site;
                    conflict.instruction_id = raw_site.instruction_id;
                    conflict.source_function_id = raw_site.source_function_id;
                    conflict.call_site_rva = raw_site.address.value;
                    output.conflicts.push_back(std::move(conflict));
                    call_graph_edge_record_t edge;
                    edge.call_site_id = site_id;
                    edge.source_function_id = raw_site.source_function_id;
                    edge.source_block_id = raw_site.source_block_id;
                    edge.call_site = raw_site.address;
                    edge.target = raw_site.address;
                    edge.target.value = 0;
                    edge.resolution = call_graph_resolution_t::unresolved;
                    edge.quality = raw_site.quality;
                    resolved.edges.push_back(std::move(edge));
                } else {
                    for (std::size_t rank = 0; rank < ranked.size(); ++rank) {
                        const auto& candidate = ranked[rank];
                        recovered_call_candidate_t committed;
                        committed.call_site_id = site_id;
                        committed.target = candidate.target;
                        committed.target_function_id = candidate.target_function_id;
                        committed.kind = candidate.kind;
                        committed.quality = candidate.quality;
                        committed.stable_source_id = candidate.stable_source_id;
                        committed.rank = static_cast<std::uint32_t>(rank);
                        committed.external_target = candidate.external_target;
                        resolved.candidates.push_back(std::move(committed));
                        call_graph_edge_record_t edge;
                        edge.call_site_id = site_id;
                        edge.source_function_id = raw_site.source_function_id;
                        edge.source_block_id = raw_site.source_block_id;
                        edge.target_function_id = candidate.target_function_id;
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
                            const auto target = function_ids.index.find(
                                *candidate.target_function_id);
                            edge.target_noreturn = target &&
                                recovery.functions[*target].noreturn;
                        }
                        resolved.edges.push_back(std::move(edge));
                    }
                }
                const auto source_node = node_by_function.index.find(
                    raw_site.source_function_id);
                if (!source_node) {
                    failure.report(shard, make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "call graph site references an unknown caller",
                        "call_graph.resolve"));
                    return;
                }
                if (resolved.site.unresolved)
                    node_unresolved[*source_node].fetch_add(1, std::memory_order_relaxed);
                node_outgoing[*source_node].fetch_add(
                    static_cast<std::uint64_t>(resolved.edges.size()),
                    std::memory_order_relaxed);
                if (raw_site.indirect) {
                    node_indirect[*source_node].fetch_add(
                        static_cast<std::uint64_t>(resolved.edges.size()),
                        std::memory_order_relaxed);
                }
                for (const auto& edge : resolved.edges) {
                    if (edge.target_function_id) {
                        const auto target_node = node_by_function.index.find(
                            *edge.target_function_id);
                        if (target_node)
                            node_incoming[*target_node].fetch_add(1,
                                std::memory_order_relaxed);
                    }
                }
                output.sites.push_back(std::move(resolved));
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    merge_clock_t commit_clock;
    std::uint64_t total_sites = 0;
    std::uint64_t total_candidates = 0;
    std::uint64_t total_edges = 0;
    std::uint64_t total_conflicts = 0;
    for (auto& output : resolve_outputs) {
        output.site_base = total_sites;
        total_sites += output.sites.size();
        total_conflicts += output.conflicts.size();
        for (const auto& resolved : output.sites) {
            total_candidates += resolved.candidates.size();
            total_edges += resolved.edges.size();
        }
        result.indirect_site_count += output.indirect_sites;
        result.unresolved_site_count += output.unresolved_sites;
        result.bounded = result.bounded || output.bounded;
    }
    if (result.conflicts.size() + total_conflicts > limits.max_conflicts) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph conflict storage exceeds analysis budget", "call_graph"));
    }
    if (total_sites > limits.max_sites) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph site storage exceeds analysis budget", "call_graph"));
    }
    if (total_candidates > limits.max_candidates) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph candidate storage exceeds analysis budget", "call_graph"));
    }
    if (total_edges > limits.max_edges) {
        return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "call graph edge storage exceeds analysis budget", "call_graph"));
    }
    {
        std::uint64_t conflict_bytes = 0;
        if (!checked_mul_u64(total_conflicts, sizeof(call_graph_conflict_t),
                conflict_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph conflict storage exceeds analysis budget", "call_graph"));
        }
        auto accounted = account_bytes(result.storage_bytes, conflict_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph conflict storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
        std::uint64_t site_bytes = 0;
        if (!checked_mul_u64(total_sites, sizeof(recovered_call_site_t), site_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph site storage exceeds analysis budget", "call_graph"));
        }
        accounted = account_bytes(result.storage_bytes, site_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph site storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
        std::uint64_t candidate_bytes = 0;
        if (!checked_mul_u64(total_candidates, sizeof(recovered_call_candidate_t),
                candidate_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph candidate storage exceeds analysis budget", "call_graph"));
        }
        accounted = account_bytes(result.storage_bytes, candidate_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph candidate storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
        std::uint64_t edge_bytes = 0;
        if (!checked_mul_u64(total_edges, sizeof(call_graph_edge_record_t), edge_bytes)) {
            return workspace_result_t<call_graph_result_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "call graph edge storage exceeds analysis budget", "call_graph"));
        }
        accounted = account_bytes(result.storage_bytes, edge_bytes,
            limits.max_result_bytes, "call_graph",
            "call graph edge storage exceeds analysis budget");
        if (!accounted)
            return workspace_result_t<call_graph_result_t>::failure(accounted.error());
    }
    result.call_sites.resize(static_cast<std::size_t>(total_sites));
    result.candidates.resize(static_cast<std::size_t>(total_candidates));
    result.edges.resize(static_cast<std::size_t>(total_edges));
    {
        std::vector<std::uint64_t> conflict_bases(resolve_outputs.size(), 0);
        std::uint64_t conflict_cursor = result.conflicts.size();
        for (std::size_t index = 0; index < resolve_outputs.size(); ++index) {
            conflict_bases[index] = conflict_cursor;
            conflict_cursor += resolve_outputs[index].conflicts.size();
        }
        result.conflicts.resize(static_cast<std::size_t>(conflict_cursor));
        run_sharded(resolve_outputs.size(), [&](std::size_t shard) {
            auto& output = resolve_outputs[shard];
            auto cursor = conflict_bases[shard];
            for (auto& conflict : output.conflicts)
                result.conflicts[static_cast<std::size_t>(cursor++)] =
                    std::move(conflict);
        });
    }
    {
        std::uint64_t candidate_base = 0;
        std::uint64_t edge_base = 0;
        for (auto& output : resolve_outputs) {
            for (auto& resolved : output.sites) {
                resolved.site.first_candidate =
                    static_cast<std::uint32_t>(candidate_base);
                resolved.candidate_base = candidate_base;
                resolved.edge_base = edge_base;
                candidate_base += resolved.candidates.size();
                edge_base += resolved.edges.size();
            }
        }
    }
    run_sharded(resolve_shards.size(), [&](std::size_t shard) {
        guarded_shard(failure, shard, "call graph site storage exceeds analysis budget",
            "call_graph.resolve", [&]() {
            auto& output = resolve_outputs[shard];
            std::uint64_t site_slot = output.site_base;
            for (auto& resolved : output.sites) {
                result.call_sites[static_cast<std::size_t>(site_slot)] =
                    std::move(resolved.site);
                ++site_slot;
                for (std::size_t rank = 0; rank < resolved.candidates.size(); ++rank) {
                    const auto slot = resolved.candidate_base + rank;
                    auto committed = std::move(resolved.candidates[rank]);
                    committed.id = call_candidate_entity_tag |
                        static_cast<std::uint64_t>(slot + 1);
                    result.candidates[static_cast<std::size_t>(slot)] =
                        std::move(committed);
                }
                for (std::size_t edge_index = 0; edge_index < resolved.edges.size();
                     ++edge_index) {
                    const auto slot = resolved.edge_base + edge_index;
                    auto committed = std::move(resolved.edges[edge_index]);
                    committed.id = call_edge_entity_tag |
                        static_cast<std::uint64_t>(slot + 1);
                    result.edges[static_cast<std::size_t>(slot)] = std::move(committed);
                }
            }
        });
    });
    if (failure.failed.load(std::memory_order_relaxed))
        return workspace_result_t<call_graph_result_t>::failure(failure.take_error());
    for (std::size_t index = 0; index < result.nodes.size(); ++index) {
        result.nodes[index].unresolved_sites =
            node_unresolved[index].load(std::memory_order_relaxed);
        result.nodes[index].outgoing_edges =
            node_outgoing[index].load(std::memory_order_relaxed);
        result.nodes[index].indirect_edges =
            node_indirect[index].load(std::memory_order_relaxed);
        result.nodes[index].incoming_edges =
            node_incoming[index].load(std::memory_order_relaxed);
    }
    parallel_sort(result.conflicts.begin(), result.conflicts.end(), conflict_less);
    parallel_unique_erase(result.conflicts, conflict_equal);
    for (std::size_t index = 0; index < result.conflicts.size(); ++index)
        result.conflicts[index].id = call_conflict_entity_tag |
            static_cast<std::uint64_t>(index + 1);
    result.shard_merge_ns += commit_clock.elapsed_ns();
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
