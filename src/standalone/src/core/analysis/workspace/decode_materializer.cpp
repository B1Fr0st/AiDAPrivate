#include "decode_materializer.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"

#include "../packed_analysis_store.hpp"
#include "../tile_decode_orchestrator.hpp"

#include "compact_ir.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kCancellationStride = 256;

workspace_error_t materialize_cancellation_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", "decode_merge");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", "decode_merge");
    error.cancellation = true;
    return error;
}

void atomic_min_u32(std::atomic<std::uint32_t>& slot, std::uint32_t value) noexcept {
    auto current = slot.load(std::memory_order_relaxed);
    while (current > value &&
           !slot.compare_exchange_weak(current, value, std::memory_order_acq_rel,
               std::memory_order_relaxed)) {
    }
}

std::uint64_t retag_mix(std::uint64_t key) noexcept {
    key *= 0x9E3779B97F4A7C15ULL;
    key ^= key >> 33U;
    return key;
}

class id_retag_table_t {
public:
    void initialize(std::size_t count, std::uint32_t workers,
                    const cancellation_token_t& cancel) {
        std::uint64_t capacity = 16;
        const std::uint64_t target = static_cast<std::uint64_t>(count) * 2ULL;
        while (capacity < target)
            capacity <<= 1U;
        mask_ = capacity - 1ULL;
        keys_.resize(static_cast<std::size_t>(capacity));
        vals_.resize(static_cast<std::size_t>(capacity));
        const auto shards = parallel_shards(static_cast<std::size_t>(capacity), workers);
        auto initialized = parallel_run_shards(shards,
            [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
                for (std::size_t index = range.begin; index < range.end; ++index) {
                    keys_[index].store((std::numeric_limits<std::uint64_t>::max)(),
                        std::memory_order_relaxed);
                    vals_[index].store(0U, std::memory_order_relaxed);
                }
                return workspace_result_t<void>::success();
            }, cancel);
        static_cast<void>(initialized);
    }

    void insert(std::uint64_t key, std::uint32_t ordinal_plus_one) noexcept {
        auto slot = static_cast<std::size_t>(retag_mix(key) & mask_);
        for (;;) {
            const auto existing = keys_[slot].load(std::memory_order_acquire);
            if (existing == key) {
                atomic_min_u32(vals_[slot], ordinal_plus_one);
                return;
            }
            if (existing == (std::numeric_limits<std::uint64_t>::max)()) {
                auto expected = (std::numeric_limits<std::uint64_t>::max)();
                if (keys_[slot].compare_exchange_strong(expected, key,
                        std::memory_order_acq_rel, std::memory_order_acquire)) {
                    vals_[slot].store(ordinal_plus_one, std::memory_order_release);
                    return;
                }
                continue;
            }
            slot = (slot + 1) & mask_;
        }
    }

    void finish(std::uint32_t) noexcept {}

    std::uint32_t find(std::uint64_t key) const noexcept {
        auto slot = static_cast<std::size_t>(retag_mix(key) & mask_);
        for (;;) {
            const auto existing = keys_[slot].load(std::memory_order_acquire);
            if (existing == (std::numeric_limits<std::uint64_t>::max)())
                return 0;
            if (existing == key)
                return vals_[slot].load(std::memory_order_acquire);
            slot = (slot + 1) & mask_;
        }
    }

private:
    std::vector<std::atomic<std::uint64_t>> keys_;
    std::vector<std::atomic<std::uint32_t>> vals_;
    std::uint64_t mask_ = 0;
};

struct id_retag_record_t {
    std::uint64_t key = 0;
    std::uint32_t ordinal_plus_one = 0;
    std::uint32_t reserved = 0;
};

class id_retag_sorted_t {
public:
    void initialize(std::size_t count, std::uint32_t, const cancellation_token_t&) {
        records_.resize(count);
    }

    void insert_at(std::size_t index, std::uint64_t key,
                   std::uint32_t ordinal_plus_one) noexcept {
        records_[index] = {key, ordinal_plus_one, 0U};
    }

    void finish(std::uint32_t workers) {
        parallel_sort(records_.begin(), records_.end(),
            [](const id_retag_record_t& lhs, const id_retag_record_t& rhs) {
                if (lhs.key != rhs.key)
                    return lhs.key < rhs.key;
                return lhs.ordinal_plus_one < rhs.ordinal_plus_one;
            }, workers);
    }

    std::uint32_t find(std::uint64_t key) const noexcept {
        std::size_t lo = 0;
        std::size_t hi = records_.size();
        while (lo < hi) {
            const auto mid = lo + (hi - lo) / 2;
            if (records_[mid].key < key)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < records_.size() && records_[lo].key == key)
            return records_[lo].ordinal_plus_one;
        return 0;
    }

private:
    std::vector<id_retag_record_t> records_;
};

void retag_record(id_retag_table_t& table, std::size_t, std::uint64_t key,
                  std::uint32_t ordinal_plus_one) noexcept {
    table.insert(key, ordinal_plus_one);
}

void retag_record(id_retag_sorted_t& sorted, std::size_t index, std::uint64_t key,
                  std::uint32_t ordinal_plus_one) noexcept {
    sorted.insert_at(index, key, ordinal_plus_one);
}

template <typename Retag>
workspace_result_t<void> materialize_copy(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint32_t workers, const cancellation_token_t& cancel, Retag& retag) {
    const auto instruction_count =
        static_cast<std::size_t>(decoded.packed_store->instruction_count());
    const auto operand_count =
        static_cast<std::size_t>(decoded.packed_store->operand_count());
    const auto target_count =
        static_cast<std::size_t>(decoded.packed_store->target_fact_count());
    snapshot.instructions.clear();
    snapshot.operand_facts.clear();
    snapshot.target_facts.clear();
    snapshot.instructions.resize(instruction_count);
    snapshot.operand_facts.resize(operand_count);
    snapshot.target_facts.resize(target_count);
    const auto instruction_shards = parallel_shards(instruction_count, workers);
    auto instructions_done = parallel_run_shards(instruction_shards,
        [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
            const auto view = decoded.packed_store->compatibility_view();
            std::uint64_t polls = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (++polls >= kCancellationStride) {
                    polls = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            materialize_cancellation_error(cancel));
                }
                auto instruction = view.instruction(index);
                if (!instruction) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode instruction compatibility row is missing",
                        "decode_merge"));
                }
                const auto original = instruction->id;
                instruction->id = kInstructionEntityTag |
                    static_cast<std::uint64_t>(index + 1);
                retag_record(retag, index, original,
                    static_cast<std::uint32_t>(index + 1));
                snapshot.instructions[index] = std::move(*instruction);
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!instructions_done)
        return instructions_done;
    retag.finish(workers);
    const auto operand_shards = parallel_shards(operand_count, workers);
    auto operands_done = parallel_run_shards(operand_shards,
        [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
            const auto view = decoded.packed_store->compatibility_view();
            std::uint64_t polls = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (++polls >= kCancellationStride) {
                    polls = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            materialize_cancellation_error(cancel));
                }
                auto operand = view.operand(index);
                if (!operand) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode operand compatibility row is missing",
                        "decode_merge"));
                }
                const auto owner = retag.find(operand->instruction_id);
                if (owner == 0) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode operand references an unknown instruction",
                        "decode_merge"));
                }
                operand->instruction_id = kInstructionEntityTag |
                    static_cast<std::uint64_t>(owner);
                snapshot.operand_facts[index] = std::move(*operand);
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!operands_done)
        return operands_done;
    const auto target_shards = parallel_shards(target_count, workers);
    auto targets_done = parallel_run_shards(target_shards,
        [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
            const auto view = decoded.packed_store->compatibility_view();
            std::uint64_t polls = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (++polls >= kCancellationStride) {
                    polls = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            materialize_cancellation_error(cancel));
                }
                auto target = view.target_fact(index);
                if (!target) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode target compatibility row is missing",
                        "decode_merge"));
                }
                const auto owner = retag.find(target->instruction_id);
                if (owner == 0) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "tile decode target references an unknown instruction",
                        "decode_merge"));
                }
                target->instruction_id = kInstructionEntityTag |
                    static_cast<std::uint64_t>(owner);
                snapshot.target_facts[index] = std::move(*target);
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!targets_done)
        return targets_done;
    std::vector<std::pair<std::size_t, std::size_t>> ranges(instruction_shards.size());
    auto bounds_done = parallel_run_shards(instruction_shards,
        [&](std::size_t shard, parallel_shard_t range) -> workspace_result_t<void> {
            const auto& facts = snapshot.target_facts;
            const auto first_owner = kInstructionEntityTag |
                static_cast<std::uint64_t>(range.begin + 1);
            std::size_t lo = 0;
            std::size_t hi = facts.size();
            while (lo < hi) {
                const auto mid = lo + (hi - lo) / 2;
                if (facts[mid].instruction_id < first_owner)
                    lo = mid + 1;
                else
                    hi = mid;
            }
            std::size_t cursor = lo;
            const auto begin_cursor = cursor;
            std::uint64_t polls = 0;
            for (std::size_t index = range.begin; index < range.end; ++index) {
                if (++polls >= kCancellationStride) {
                    polls = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            materialize_cancellation_error(cancel));
                }
                if (cursor > (std::numeric_limits<std::uint32_t>::max)()) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "tile decode target table exceeds Compact IR capacity",
                        "decode_merge"));
                }
                const auto owner = kInstructionEntityTag |
                    static_cast<std::uint64_t>(index + 1);
                const auto begin = cursor;
                while (cursor < facts.size() &&
                       facts[cursor].instruction_id == owner)
                    ++cursor;
                const auto count = cursor - begin;
                if (count > (std::numeric_limits<std::uint16_t>::max)()) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "tile decode target count exceeds Compact IR capacity",
                        "decode_merge"));
                }
                snapshot.instructions[index].target_fact_begin =
                    static_cast<std::uint32_t>(begin);
                snapshot.instructions[index].target_fact_count =
                    static_cast<std::uint16_t>(count);
            }
            ranges[shard] = {begin_cursor, cursor};
            return workspace_result_t<void>::success();
        }, cancel);
    if (!bounds_done)
        return bounds_done;
    std::size_t expected = 0;
    bool grouped = true;
    for (const auto& range : ranges) {
        if (range.first != expected) {
            grouped = false;
            break;
        }
        expected = range.second;
    }
    if (!grouped || expected != snapshot.target_facts.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode target rows are not grouped by instruction", "decode_merge"));
    }
    if (decoded.delay_slot_counts.size() != snapshot.instructions.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode delay-slot metadata is not instruction-aligned", "decode_merge"));
    }
    snapshot.delay_slot_counts = std::move(decoded.delay_slot_counts);
    decoded.packed_store.reset();
    return workspace_result_t<void>::success();
}

}

namespace decode_materializer {

workspace_result_t<void> materialize(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint64_t remaining_budget_bytes, const cancellation_token_t& cancel) {
    if (!decoded.packed_store || !decoded.packed_store->valid()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode did not publish a valid packed store", "decode_merge"));
    }
    auto validated = decoded.packed_store->validate();
    if (!validated) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode packed store validation failed", "decode_merge"));
    }
    const auto workers = parallel_worker_count();
    const auto count =
        static_cast<std::size_t>(decoded.packed_store->instruction_count());
    if (remaining_budget_bytes < kLowMemoryR0Bytes) {
        id_retag_sorted_t retag;
        retag.initialize(count, workers, cancel);
        return materialize_copy(decoded, snapshot, workers, cancel, retag);
    }
    id_retag_table_t retag;
    retag.initialize(count, workers, cancel);
    return materialize_copy(decoded, snapshot, workers, cancel, retag);
}

}

}
