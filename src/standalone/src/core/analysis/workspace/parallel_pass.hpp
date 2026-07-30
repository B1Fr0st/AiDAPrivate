#pragma once

#include "workspace_types.hpp"

#include "../../infra/taskflow_runtime.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis {

struct parallel_shard_t {
    std::size_t begin;
    std::size_t end;
};

inline std::uint32_t parallel_worker_count() noexcept {
    const auto hardware = std::thread::hardware_concurrency();
    return (std::min<std::uint32_t>)(16U, (std::max<std::uint32_t>)(1U, hardware));
}

inline std::vector<parallel_shard_t> parallel_shards(std::size_t count,
    std::uint32_t workers) {
    std::vector<parallel_shard_t> shards;
    if (count == 0)
        return shards;
    const auto resolved = workers == 0 ? parallel_worker_count() : workers;
    const auto shard_count = static_cast<std::size_t>(
        (std::min<std::uint64_t>)(count, (std::max<std::uint32_t>)(1U, resolved)));
    shards.reserve(shard_count);
    const std::size_t base = count / shard_count;
    const std::size_t remainder = count % shard_count;
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < shard_count; ++index) {
        const std::size_t extent = base + (index < remainder ? 1U : 0U);
        shards.push_back(parallel_shard_t{cursor, cursor + extent});
        cursor += extent;
    }
    return shards;
}

namespace detail {

struct parallel_no_local_t {};

struct parallel_exec_state_base_t {
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> remaining{0};
    std::size_t item_count = 0;
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<std::exception_ptr> exceptions;

    virtual ~parallel_exec_state_base_t() = default;
    virtual void run_participant() = 0;

    void finish_item() noexcept {
        if (remaining.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            std::lock_guard<std::mutex> lock(mutex);
            cv.notify_all();
        }
    }

    void drain_abandoned() noexcept {
        for (;;) {
            const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
            if (index >= item_count)
                return;
            finish_item();
        }
    }

    void wait_complete() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] {
            return remaining.load(std::memory_order_acquire) == 0;
        });
    }

    void rethrow_first_exception() {
        for (const auto& exception : exceptions) {
            if (exception)
                std::rethrow_exception(exception);
        }
    }
};

template <typename Local, typename Gate, typename F>
struct parallel_exec_state_t final : parallel_exec_state_base_t {
    Gate gate;
    F fn;

    parallel_exec_state_t(Gate gate_in, F fn_in)
        : gate(std::move(gate_in)), fn(std::move(fn_in)) {}

    void run_participant() override {
        Local local{};
        for (;;) {
            const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
            if (index >= item_count)
                return;
            if (!gate()) {
                finish_item();
                continue;
            }
            try {
                if constexpr (std::is_same<Local, parallel_no_local_t>::value) {
                    fn(index);
                } else {
                    fn(index, local);
                }
            } catch (...) {
                exceptions[index] = std::current_exception();
                finish_item();
                drain_abandoned();
                return;
            }
            finish_item();
        }
    }
};

}

struct parallel_executor_t {
    template <typename F>
    static void run(std::size_t item_count, std::uint32_t workers,
                    const char* label, F&& item_fn) {
        const auto always_open = [] { return true; };
        execute<detail::parallel_no_local_t>(item_count, workers, label,
            always_open, std::forward<F>(item_fn));
    }

    template <typename Local, typename F>
    static void run_local(std::size_t item_count, std::uint32_t workers,
                          const char* label, F&& item_fn) {
        const auto always_open = [] { return true; };
        execute<Local>(item_count, workers, label, always_open,
            std::forward<F>(item_fn));
    }

    template <typename Gate, typename F>
    static void run_gated(std::size_t item_count, std::uint32_t workers,
                          const char* label, Gate&& schedule_gate, F&& item_fn) {
        execute<detail::parallel_no_local_t>(item_count, workers, label,
            std::forward<Gate>(schedule_gate), std::forward<F>(item_fn));
    }

private:
    template <typename Local, typename Gate, typename F>
    static void execute(std::size_t item_count, std::uint32_t workers,
                        const char* label, Gate&& schedule_gate, F&& item_fn) {
        if (item_count == 0)
            return;
        using state_t = detail::parallel_exec_state_t<Local,
            std::decay_t<Gate>, std::decay_t<F>>;
        auto state = std::make_shared<state_t>(
            std::forward<Gate>(schedule_gate), std::forward<F>(item_fn));
        state->item_count = item_count;
        state->remaining.store(item_count, std::memory_order_relaxed);
        state->exceptions.assign(item_count, nullptr);
        const auto resolved = workers == 0 ? parallel_worker_count() : workers;
        const std::size_t participants = (std::min<std::size_t>)(
            static_cast<std::size_t>((std::max<std::uint32_t>)(1U, resolved)),
            item_count);
        for (std::size_t helper = 1; helper < participants; ++helper) {
            aida::infra::taskflow_runtime::task_descriptor_t desc;
            desc.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
            desc.owner_subsystem = "analysis_workspace";
            desc.label = label;
            desc.body = [state]() { state->run_participant(); };
            static_cast<void>(aida::infra::taskflow_runtime::submit(std::move(desc)));
        }
        state->run_participant();
        state->wait_complete();
        state->rethrow_first_exception();
    }
};

template <typename F>
workspace_result_t<void> parallel_run_shards(
    const std::vector<parallel_shard_t>& shards, F&& shard_fn,
    const cancellation_token_t&) {
    struct slot_t {
        std::optional<workspace_error_t> error;
        std::exception_ptr exception;
    };
    const std::size_t count = shards.size();
    if (count == 0)
        return workspace_result_t<void>::success();
    std::vector<slot_t> slots(count);
    parallel_executor_t::run(count, static_cast<std::uint32_t>(count),
        "analysis.parallel_run_shards", [&](std::size_t index) {
            try {
                auto result = shard_fn(index, shards[index]);
                if (!result)
                    slots[index].error = std::move(result.error());
            } catch (...) {
                slots[index].exception = std::current_exception();
            }
        });
    for (auto& slot : slots) {
        if (slot.exception)
            std::rethrow_exception(slot.exception);
        if (slot.error)
            return workspace_result_t<void>::failure(std::move(*slot.error));
    }
    return workspace_result_t<void>::success();
}

template <typename RandomIt, typename Compare>
void parallel_sort(RandomIt first, RandomIt last, Compare comp,
                   std::uint32_t workers = 0) {
    using value_t = typename std::iterator_traits<RandomIt>::value_type;
    const std::size_t count = static_cast<std::size_t>(last - first);
    const auto requested = workers == 0 ? parallel_worker_count() : workers;
    const std::size_t worker_count = (std::min<std::size_t>)(256U,
        (std::max<std::uint32_t>)(1U, requested));
    if (count < 65536 || worker_count <= 1) {
        std::sort(first, last, comp);
        return;
    }
    const auto run_phase = [](std::size_t lanes, auto&& phase_fn) {
        parallel_executor_t::run(lanes, static_cast<std::uint32_t>(lanes),
            "analysis.parallel_sort", std::forward<decltype(phase_fn)>(phase_fn));
    };
    const std::size_t sample_target = 255U * worker_count;
    const std::size_t sample_stride = count / sample_target + 1U;
    std::vector<value_t> sample;
    sample.reserve(sample_target);
    for (std::size_t index = 0; index < count; index += sample_stride)
        sample.push_back(first[static_cast<std::ptrdiff_t>(index)]);
    std::sort(sample.begin(), sample.end(), comp);
    std::vector<value_t> splitters;
    splitters.reserve(worker_count - 1U);
    for (std::size_t rank = 1; rank < worker_count; ++rank)
        splitters.push_back(sample[(rank * sample.size()) / worker_count]);
    const auto bucket_of = [&](const value_t& value) {
        return static_cast<std::size_t>(std::upper_bound(
            splitters.begin(), splitters.end(), value, comp) - splitters.begin());
    };
    const auto regions = parallel_shards(count,
        static_cast<std::uint32_t>(worker_count));
    std::vector<std::size_t> histogram(worker_count * worker_count, 0);
    run_phase(worker_count, [&](std::size_t lane) {
        const auto& region = regions[lane];
        auto* counts = histogram.data() + lane * worker_count;
        for (std::size_t index = region.begin; index < region.end; ++index)
            ++counts[bucket_of(first[static_cast<std::ptrdiff_t>(index)])];
    });
    std::vector<std::size_t> bucket_begin(worker_count + 1U, 0);
    for (std::size_t bucket = 0; bucket < worker_count; ++bucket) {
        std::size_t total = 0;
        for (std::size_t lane = 0; lane < worker_count; ++lane)
            total += histogram[lane * worker_count + bucket];
        bucket_begin[bucket + 1U] = bucket_begin[bucket] + total;
    }
    std::vector<std::size_t> scatter(worker_count * worker_count, 0);
    for (std::size_t bucket = 0; bucket < worker_count; ++bucket) {
        std::size_t position = bucket_begin[bucket];
        for (std::size_t lane = 0; lane < worker_count; ++lane) {
            scatter[lane * worker_count + bucket] = position;
            position += histogram[lane * worker_count + bucket];
        }
    }
    std::vector<value_t> aux(count);
    run_phase(worker_count, [&](std::size_t lane) {
        const auto& region = regions[lane];
        auto* cursors = scatter.data() + lane * worker_count;
        for (std::size_t index = region.begin; index < region.end; ++index) {
            auto& value = first[static_cast<std::ptrdiff_t>(index)];
            aux[cursors[bucket_of(value)]++] = std::move(value);
        }
    });
    std::atomic<std::size_t> next_bucket{0};
    run_phase(worker_count, [&](std::size_t) {
        for (;;) {
            const auto bucket = next_bucket.fetch_add(1, std::memory_order_relaxed);
            if (bucket >= worker_count)
                return;
            const auto begin = bucket_begin[bucket];
            const auto end = bucket_begin[bucket + 1U];
            std::sort(aux.begin() + static_cast<std::ptrdiff_t>(begin),
                aux.begin() + static_cast<std::ptrdiff_t>(end), comp);
            for (std::size_t index = begin; index < end; ++index)
                first[static_cast<std::ptrdiff_t>(index)] =
                    std::move(aux[index]);
        }
    });
}

struct ordered_error_t {
    std::uint64_t ordinal = (std::numeric_limits<std::uint64_t>::max)();
    workspace_error_t error;
};

template <typename F>
workspace_result_t<void> parallel_validate_shards(
    const std::vector<parallel_shard_t>& shards,
    std::uint64_t ordinal_stride,
    F&& shard_validate_fn,
    const cancellation_token_t&) {
    struct slot_t {
        ordered_error_t result;
        std::exception_ptr exception;
    };
    const std::size_t count = shards.size();
    if (count == 0)
        return workspace_result_t<void>::success();
    std::vector<slot_t> slots(count);
    parallel_executor_t::run(count, static_cast<std::uint32_t>(count),
        "analysis.parallel_validate_shards", [&](std::size_t index) {
            try {
                slots[index].result = shard_validate_fn(index, shards[index]);
            } catch (...) {
                slots[index].exception = std::current_exception();
            }
        });
    std::size_t best_error = count;
    std::size_t best_exception = count;
    for (std::size_t index = 0; index < count; ++index) {
        if (slots[index].exception && best_exception == count)
            best_exception = index;
        if (slots[index].result.ordinal != (std::numeric_limits<std::uint64_t>::max)() &&
            (best_error == count ||
             slots[index].result.ordinal < slots[best_error].result.ordinal))
            best_error = index;
    }
    if (best_exception != count) {
        const auto exception_ordinal = ordinal_stride *
            static_cast<std::uint64_t>(shards[best_exception].begin);
        if (best_error == count ||
            exception_ordinal <= slots[best_error].result.ordinal)
            std::rethrow_exception(slots[best_exception].exception);
    }
    if (best_error != count)
        return workspace_result_t<void>::failure(
            std::move(slots[best_error].result.error));
    return workspace_result_t<void>::success();
}

template <typename T, typename F>
std::vector<T> parallel_prefix_sums(const std::vector<T>& shard_totals, F add) {
    std::vector<T> result;
    result.reserve(shard_totals.size());
    T running{};
    for (const auto& total : shard_totals) {
        result.push_back(running);
        running = add(std::move(running), total);
    }
    return result;
}

}
