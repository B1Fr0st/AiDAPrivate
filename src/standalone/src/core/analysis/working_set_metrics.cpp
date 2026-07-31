#include "working_set_metrics.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <condition_variable>
#include <iterator>
#include <limits>
#include <locale>
#include <mutex>
#include <sstream>
#include <system_error>
#include <thread>

namespace aida::analysis {

namespace {

std::size_t io_metric_index(workspace_io_metric_t metric) noexcept {
    const auto value = static_cast<std::size_t>(metric);
    return value < workspace_io_metric_count ? value : 0;
}

}

std::uint64_t workspace_io_metrics_snapshot_t::value(
    workspace_io_metric_t metric) const noexcept {
    return counters[io_metric_index(metric)];
}

std::string workspace_io_metrics_snapshot_t::to_json() const {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << "{\"io_metrics_schema_version\":1,\"counters\":{";
    for (std::size_t i = 0; i < counters.size(); ++i) {
        if (i != 0)
            out << ',';
        out << '\"' << workspace_io_metrics_t::metric_name(
            static_cast<workspace_io_metric_t>(i)) << "\":" << counters[i];
    }
    out << "}}";
    return out.str();
}

void workspace_io_metrics_t::add(workspace_io_metric_t metric,
                                 std::uint64_t value) noexcept {
    counters_[io_metric_index(metric)].fetch_add(value, std::memory_order_relaxed);
}

void workspace_io_metrics_t::set(workspace_io_metric_t metric,
                                 std::uint64_t value) noexcept {
    counters_[io_metric_index(metric)].store(value, std::memory_order_relaxed);
}

void workspace_io_metrics_t::set_max(workspace_io_metric_t metric,
                                     std::uint64_t value) noexcept {
    auto& target = counters_[io_metric_index(metric)];
    std::uint64_t current = target.load(std::memory_order_relaxed);
    while (current < value &&
           !target.compare_exchange_weak(current, value, std::memory_order_release,
                                         std::memory_order_relaxed)) {
    }
}

std::uint64_t workspace_io_metrics_t::value(workspace_io_metric_t metric) const noexcept {
    return counters_[io_metric_index(metric)].load(std::memory_order_relaxed);
}

workspace_io_metrics_snapshot_t workspace_io_metrics_t::snapshot() const noexcept {
    workspace_io_metrics_snapshot_t result;
    for (std::size_t i = 0; i < result.counters.size(); ++i)
        result.counters[i] = counters_[i].load(std::memory_order_relaxed);
    return result;
}

void workspace_io_metrics_t::reset() noexcept {
    for (auto& counter : counters_)
        counter.store(0, std::memory_order_relaxed);
}

const char* workspace_io_metrics_t::metric_name(workspace_io_metric_t metric) noexcept {
    static constexpr const char* names[] = {
        "governor_zone", "governor_rejections",
        "fact_page_cache_hits", "fact_page_cache_misses",
        "fact_page_cache_evictions", "fact_page_cache_bytes",
        "fact_page_cache_range_drops",
        "working_set_bytes", "working_set_peak_bytes",
        "private_bytes", "private_bytes_peak", "pagefile_bytes",
        "persist_commit_lag_ns_last", "persist_commit_lag_ns_max",
        "persist_commit_lag_ns_total", "persist_commit_lag_samples",
        "persist_coalesced_transactions", "persist_coalesced_operations",
        "persist_coalesced_rollbacks",
        "reader_pool_acquisitions", "reader_pool_wait_ns_total",
        "reader_pool_wait_ns_max", "reader_pool_timeouts",
        "statement_cache_hits", "statement_cache_misses"
    };
    static_assert(std::size(names) == workspace_io_metric_count);
    return names[io_metric_index(metric)];
}

workspace_io_metrics_t& workspace_io_metrics() noexcept {
    static workspace_io_metrics_t metrics;
    return metrics;
}

namespace working_set_metrics {

namespace {

std::uint64_t steady_now_ns() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::size_t subsystem_index(subsystem_t subsystem) noexcept {
    const auto value = static_cast<std::size_t>(subsystem);
    return value < subsystem_count ? value : 0;
}

std::atomic<std::uint64_t> g_commit_lag_samples{0};
std::atomic<std::uint64_t> g_commit_lag_total_ns{0};
std::atomic<std::uint64_t> g_commit_lag_max_ns{0};
std::atomic<std::uint64_t> g_commit_lag_last_ns{0};

void publish_sample_to_metrics(const process_sample_t& sample,
                               analysis_metrics_t* metrics) noexcept {
    workspace_io_metrics().set(workspace_io_metric_t::working_set_bytes,
                               sample.working_set_bytes);
    workspace_io_metrics().set_max(workspace_io_metric_t::working_set_peak_bytes,
                                   sample.peak_working_set_bytes);
    workspace_io_metrics().set(workspace_io_metric_t::private_bytes,
                               sample.private_bytes);
    workspace_io_metrics().set_max(workspace_io_metric_t::private_bytes_peak,
                                   sample.peak_private_bytes);
    workspace_io_metrics().set(workspace_io_metric_t::pagefile_bytes,
                               sample.pagefile_bytes);
    if (metrics) {
        metrics->set_max(analysis_metric_t::peak_private_bytes,
                         sample.private_bytes);
        metrics->set_max(analysis_metric_t::peak_committed_bytes,
                         sample.pagefile_bytes);
        metrics->set_max(analysis_metric_t::resident_bytes_peak,
                         sample.peak_working_set_bytes);
    }
}

}

process_sample_t sample_process_memory() noexcept {
    process_sample_t sample;
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                             static_cast<DWORD>(sizeof(counters)))) {
        sample.working_set_bytes = static_cast<std::uint64_t>(counters.WorkingSetSize);
        sample.peak_working_set_bytes =
            static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
        sample.private_bytes = static_cast<std::uint64_t>(counters.PrivateUsage);
        sample.peak_private_bytes =
            static_cast<std::uint64_t>(counters.PeakPagefileUsage);
        sample.pagefile_bytes = static_cast<std::uint64_t>(counters.PagefileUsage);
        sample.peak_pagefile_bytes =
            static_cast<std::uint64_t>(counters.PeakPagefileUsage);
    }
    sample.sampled_steady_ns = steady_now_ns();
    return sample;
}

const char* subsystem_name(subsystem_t subsystem) noexcept {
    static constexpr const char* names[] = {
        "mapped_windows", "fact_page_cache", "resident_facts",
        "persistence_staging", "decode_transient", "search_index",
        "decompiler_memory", "worker_snapshots", "xref_arenas",
        "sqlite_caches", "ui_misc"
    };
    static_assert(std::size(names) == subsystem_count);
    return names[subsystem_index(subsystem)];
}

void subsystem_ledger_t::publish_peak(slot_t& slot, std::uint64_t bytes) noexcept {
    std::uint64_t current = slot.peak_bytes.load(std::memory_order_relaxed);
    while (current < bytes &&
           !slot.peak_bytes.compare_exchange_weak(current, bytes,
                                                  std::memory_order_release,
                                                  std::memory_order_relaxed)) {
    }
}

void subsystem_ledger_t::add(subsystem_t subsystem,
                             std::int64_t delta_bytes) noexcept {
    auto& slot = slots_[subsystem_index(subsystem)];
    std::uint64_t current = slot.bytes.load(std::memory_order_relaxed);
    for (;;) {
        std::uint64_t next = current;
        if (delta_bytes < 0) {
            const auto magnitude =
                delta_bytes == (std::numeric_limits<std::int64_t>::min)()
                    ? (std::numeric_limits<std::uint64_t>::max)()
                    : static_cast<std::uint64_t>(-delta_bytes);
            next = magnitude >= current ? 0 : current - magnitude;
        } else {
            const auto magnitude = static_cast<std::uint64_t>(delta_bytes);
            next = magnitude >
                    (std::numeric_limits<std::uint64_t>::max)() - current
                ? (std::numeric_limits<std::uint64_t>::max)()
                : current + magnitude;
        }
        if (slot.bytes.compare_exchange_weak(current, next,
                                             std::memory_order_release,
                                             std::memory_order_relaxed)) {
            publish_peak(slot, next);
            return;
        }
    }
}

void subsystem_ledger_t::set(subsystem_t subsystem, std::uint64_t bytes) noexcept {
    auto& slot = slots_[subsystem_index(subsystem)];
    slot.bytes.store(bytes, std::memory_order_release);
    publish_peak(slot, bytes);
}

std::uint64_t subsystem_ledger_t::value(subsystem_t subsystem) const noexcept {
    return slots_[subsystem_index(subsystem)].bytes.load(std::memory_order_relaxed);
}

std::uint64_t subsystem_ledger_t::peak(subsystem_t subsystem) const noexcept {
    return slots_[subsystem_index(subsystem)].peak_bytes.load(std::memory_order_relaxed);
}

std::uint64_t subsystem_ledger_t::total() const noexcept {
    std::uint64_t total = 0;
    for (const auto& slot : slots_) {
        const std::uint64_t value = slot.bytes.load(std::memory_order_relaxed);
        total = value > (std::numeric_limits<std::uint64_t>::max)() - total
            ? (std::numeric_limits<std::uint64_t>::max)()
            : total + value;
    }
    return total;
}

subsystem_ledger_snapshot_t subsystem_ledger_t::snapshot() const noexcept {
    subsystem_ledger_snapshot_t result;
    for (std::size_t i = 0; i < slots_.size(); ++i) {
        result.bytes[i] = slots_[i].bytes.load(std::memory_order_relaxed);
        result.peak_bytes[i] = slots_[i].peak_bytes.load(std::memory_order_relaxed);
        const std::uint64_t value = result.bytes[i];
        result.total_bytes = value >
                (std::numeric_limits<std::uint64_t>::max)() - result.total_bytes
            ? (std::numeric_limits<std::uint64_t>::max)()
            : result.total_bytes + value;
    }
    return result;
}

void subsystem_ledger_t::reset() noexcept {
    for (auto& slot : slots_) {
        slot.bytes.store(0, std::memory_order_relaxed);
        slot.peak_bytes.store(0, std::memory_order_relaxed);
    }
}

subsystem_ledger_t& process_subsystem_ledger() noexcept {
    static subsystem_ledger_t ledger;
    return ledger;
}

void record_commit_lag(std::uint64_t lag_ns) noexcept {
    g_commit_lag_samples.fetch_add(1, std::memory_order_relaxed);
    g_commit_lag_total_ns.fetch_add(lag_ns, std::memory_order_relaxed);
    g_commit_lag_last_ns.store(lag_ns, std::memory_order_relaxed);
    std::uint64_t current = g_commit_lag_max_ns.load(std::memory_order_relaxed);
    while (current < lag_ns &&
           !g_commit_lag_max_ns.compare_exchange_weak(current, lag_ns,
                                                      std::memory_order_release,
                                                      std::memory_order_relaxed)) {
    }
    workspace_io_metrics().set(workspace_io_metric_t::persist_commit_lag_ns_last,
                               lag_ns);
    workspace_io_metrics().set_max(workspace_io_metric_t::persist_commit_lag_ns_max,
                                   lag_ns);
    workspace_io_metrics().add(workspace_io_metric_t::persist_commit_lag_ns_total,
                               lag_ns);
    workspace_io_metrics().add(workspace_io_metric_t::persist_commit_lag_samples, 1);
}

commit_lag_snapshot_t commit_lag() noexcept {
    commit_lag_snapshot_t result;
    result.samples = g_commit_lag_samples.load(std::memory_order_relaxed);
    result.total_ns = g_commit_lag_total_ns.load(std::memory_order_relaxed);
    result.max_ns = g_commit_lag_max_ns.load(std::memory_order_relaxed);
    result.last_ns = g_commit_lag_last_ns.load(std::memory_order_relaxed);
    return result;
}

void reset_commit_lag() noexcept {
    g_commit_lag_samples.store(0, std::memory_order_relaxed);
    g_commit_lag_total_ns.store(0, std::memory_order_relaxed);
    g_commit_lag_max_ns.store(0, std::memory_order_relaxed);
    g_commit_lag_last_ns.store(0, std::memory_order_relaxed);
}

struct sampler_t::state_t {
    explicit state_t(std::chrono::milliseconds interval_value)
        : interval(interval_value) {
    }

    void publish(const process_sample_t& sample) noexcept {
        working_set_bytes.store(sample.working_set_bytes, std::memory_order_relaxed);
        peak_working_set_bytes.store(sample.peak_working_set_bytes,
                                     std::memory_order_relaxed);
        private_bytes.store(sample.private_bytes, std::memory_order_relaxed);
        peak_private_bytes.store(sample.peak_private_bytes,
                                 std::memory_order_relaxed);
        pagefile_bytes.store(sample.pagefile_bytes, std::memory_order_relaxed);
        peak_pagefile_bytes.store(sample.peak_pagefile_bytes,
                                  std::memory_order_relaxed);
        sampled_steady_ns.store(sample.sampled_steady_ns,
                                std::memory_order_relaxed);
    }

    std::shared_ptr<analysis_metrics_t> attached_metrics() const noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        return metrics;
    }

    mutable std::mutex mutex;
    std::condition_variable cv;
    bool running = false;
    bool stop_requested = false;
    std::thread thread;
    std::chrono::milliseconds interval;
    std::shared_ptr<analysis_metrics_t> metrics;
    std::atomic<std::uint64_t> working_set_bytes{0};
    std::atomic<std::uint64_t> peak_working_set_bytes{0};
    std::atomic<std::uint64_t> private_bytes{0};
    std::atomic<std::uint64_t> peak_private_bytes{0};
    std::atomic<std::uint64_t> pagefile_bytes{0};
    std::atomic<std::uint64_t> peak_pagefile_bytes{0};
    std::atomic<std::uint64_t> sampled_steady_ns{0};
};

sampler_t::sampler_t(std::chrono::milliseconds interval)
    : state_(std::make_shared<state_t>(
        interval.count() < 50 ? std::chrono::milliseconds{50}
            : interval.count() > 5000 ? std::chrono::milliseconds{5000}
            : interval)) {
}

sampler_t::~sampler_t() {
    stop();
}

workspace_result_t<void> sampler_t::start() {
    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->running)
        return workspace_result_t<void>::success();
    state_->stop_requested = false;
    try {
        state_->thread = std::thread([state = state_] { run(state); });
    } catch (const std::system_error& error) {
        auto failure = make_workspace_error(
            workspace_error_code_t::io_failure,
            std::string("working-set sampler thread failed to start: ") + error.what(),
            "working_set_metrics.sampler");
        return workspace_result_t<void>::failure(std::move(failure));
    } catch (...) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::io_failure,
            "working-set sampler thread failed to start",
            "working_set_metrics.sampler"));
    }
    state_->running = true;
    return workspace_result_t<void>::success();
}

void sampler_t::stop() noexcept {
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->running && !state_->thread.joinable())
            return;
        state_->stop_requested = true;
        state_->cv.notify_all();
    }
    if (state_->thread.joinable()) {
        try {
            state_->thread.join();
        } catch (...) {
        }
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->running = false;
    state_->stop_requested = false;
}

bool sampler_t::running() const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->running;
}

process_sample_t sampler_t::latest() const noexcept {
    process_sample_t sample;
    sample.working_set_bytes = state_->working_set_bytes.load(std::memory_order_relaxed);
    sample.peak_working_set_bytes =
        state_->peak_working_set_bytes.load(std::memory_order_relaxed);
    sample.private_bytes = state_->private_bytes.load(std::memory_order_relaxed);
    sample.peak_private_bytes =
        state_->peak_private_bytes.load(std::memory_order_relaxed);
    sample.pagefile_bytes = state_->pagefile_bytes.load(std::memory_order_relaxed);
    sample.peak_pagefile_bytes =
        state_->peak_pagefile_bytes.load(std::memory_order_relaxed);
    sample.sampled_steady_ns = state_->sampled_steady_ns.load(std::memory_order_relaxed);
    return sample;
}

process_sample_t sampler_t::sample_now() noexcept {
    auto sample = sample_process_memory();
    state_->publish(sample);
    publish_sample_to_metrics(sample, state_->attached_metrics().get());
    return sample;
}

void sampler_t::attach_metrics(std::shared_ptr<analysis_metrics_t> metrics) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->metrics = std::move(metrics);
}

std::chrono::milliseconds sampler_t::interval() const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->interval;
}

void sampler_t::run(const std::shared_ptr<state_t>& state) noexcept {
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            state->cv.wait_for(lock, state->interval, [&] {
                return state->stop_requested;
            });
            if (state->stop_requested)
                return;
        }
        auto sample = sample_process_memory();
        state->publish(sample);
        publish_sample_to_metrics(sample, state->attached_metrics().get());
    }
}

sampler_t& process_sampler() noexcept {
    static sampler_t sampler;
    return sampler;
}

}

}
