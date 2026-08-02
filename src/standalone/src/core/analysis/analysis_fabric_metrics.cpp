#include "analysis_fabric_metrics.hpp"

#include "../infra/cancellation_watchdog.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../helpers/diag_log.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::analysis {

namespace rt = aida::infra::taskflow_runtime;

namespace {

constexpr std::size_t compute_domain_count = 3;
constexpr rt::executor_domain_t compute_domains[compute_domain_count] = {
    rt::executor_domain_t::feature_worker,
    rt::executor_domain_t::general,
    rt::executor_domain_t::external_tool
};

struct fabric_sampler_domain_state_t {
    std::atomic<std::uint64_t> busy_worker_ms{0};
    std::uint64_t prev_posted = 0;
    std::uint64_t prev_started = 0;
    std::uint64_t prev_finished = 0;
    std::uint64_t prev_cancelled = 0;
    std::uint64_t prev_failed = 0;
    std::uint64_t prev_timed_out = 0;
    std::uint64_t prev_fairness_wait_ns_total = 0;
};

struct fabric_sampler_state_t {
    std::atomic<bool> started{false};
    std::atomic<bool> active{false};
    std::atomic<bool> stop_requested{false};
    std::atomic<std::uint64_t> sample_sequence{0};
    std::atomic<std::uint64_t> sampler_job_id{0};
    std::uint64_t last_sample_ms = 0;
    std::array<fabric_sampler_domain_state_t, analysis_fabric_domain_count> domains{};
    std::shared_ptr<analysis_resource_metrics_t> resource =
        std::make_shared<analysis_resource_metrics_t>();
};

fabric_sampler_state_t& sampler_state() noexcept {
    static fabric_sampler_state_t* instance = new fabric_sampler_state_t();
    return *instance;
}

std::uint64_t monotonic_delta(std::uint64_t current, std::uint64_t& previous) noexcept {
    const std::uint64_t delta = current >= previous ? current - previous : 0;
    previous = current;
    return delta;
}

bool is_compute_domain(rt::executor_domain_t domain) noexcept {
    for (const auto compute : compute_domains) {
        if (compute == domain)
            return true;
    }
    return false;
}

void sample_once(fabric_sampler_state_t& state) noexcept {
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t elapsed = state.last_sample_ms != 0 && now > state.last_sample_ms
        ? now - state.last_sample_ms : 0;
    state.last_sample_ms = now;
    std::uint64_t fairness_delta_total = 0;
    std::uint64_t compute_active = 0;
    std::uint64_t compute_pending = 0;
    analysis_task_counts_t task_deltas{};
    std::string domains_text;
    char item[96];
    for (std::size_t index = 0; index < analysis_fabric_domain_count; ++index) {
        const auto domain = static_cast<rt::executor_domain_t>(index);
        const auto stats = rt::domain_stats(domain);
        auto& accumulated = state.domains[index];
        if (elapsed != 0 && stats.active != 0) {
            accumulated.busy_worker_ms.fetch_add(
                static_cast<std::uint64_t>(stats.active) * elapsed, std::memory_order_acq_rel);
        }
        task_deltas.queued += monotonic_delta(stats.posted, accumulated.prev_posted);
        task_deltas.started += monotonic_delta(stats.started, accumulated.prev_started);
        task_deltas.completed += monotonic_delta(stats.finished, accumulated.prev_finished);
        task_deltas.cancelled += monotonic_delta(stats.cancelled, accumulated.prev_cancelled);
        task_deltas.failed += monotonic_delta(stats.failed, accumulated.prev_failed) +
            monotonic_delta(stats.timed_out, accumulated.prev_timed_out);
        fairness_delta_total += monotonic_delta(stats.fairness_wait_ns_total,
            accumulated.prev_fairness_wait_ns_total);
        if (is_compute_domain(domain)) {
            compute_active += stats.active;
            compute_pending += stats.pending;
        }
        if (domains_text.size() < 700) {
            _snprintf_s(item, sizeof(item), _TRUNCATE, "%s%s=%u/%zu",
                domains_text.empty() ? "" : ";",
                rt::domain_name(domain),
                static_cast<unsigned>(stats.active),
                stats.pending);
            domains_text += item;
        }
    }
    if (state.resource) {
        if (fairness_delta_total != 0) {
            state.resource->record_phase_timing(analysis_resource_phase_t::analysis,
                0, 0, fairness_delta_total);
        }
        state.resource->record_task_counts(task_deltas);
    }
    const auto snap = rt::active_snapshot(128);
    std::uint64_t workspace_active = 0;
    for (const auto& job : snap.active_jobs) {
        if (job.owner_subsystem == "analysis_workspace")
            ++workspace_active;
    }
    if (state.resource)
        state.resource->observe_workspace_concurrency(workspace_active);
    const std::uint64_t sequence = state.sample_sequence.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    diag::log_tagged_fmt("fabric_metrics",
        "fabric_metrics domains=%s compute_active=%llu compute_pending=%llu oldest_active_ms=%llu workspace_active=%llu watchdog_lag_ms=%llu watchdog_registered=%llu sample=%llu",
        domains_text.c_str(),
        static_cast<unsigned long long>(compute_active),
        static_cast<unsigned long long>(compute_pending),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        static_cast<unsigned long long>(workspace_active),
        static_cast<unsigned long long>(aida::infra::cancellation_watchdog::last_sweep_lag_ms()),
        static_cast<unsigned long long>(aida::infra::cancellation_watchdog::registered_watch_count()),
        static_cast<unsigned long long>(sequence));
}

void submit_sampler_job();

void sampler_tick() {
    auto& state = sampler_state();
    if (!state.stop_requested.load(std::memory_order_acquire)) {
        try {
            sample_once(state);
        } catch (...) {
        }
    }
    if (state.stop_requested.load(std::memory_order_acquire) ||
        rt::g_shutdown_requested.load(std::memory_order_acquire) ||
        rt::g_stop_accepting.load(std::memory_order_acquire))
        return;
    submit_sampler_job();
}

void submit_sampler_job() {
    auto& state = sampler_state();
    rt::task_descriptor_t desc;
    desc.domain = rt::executor_domain_t::diagnostics;
    desc.owner_subsystem = "analysis_fabric_metrics";
    desc.label = "fabric_metrics.sampler";
    desc.priority = 7;
    desc.shutdown_policy = "cancel_pending";
    desc.cancellable_body = [](const rt::cancellation_token_t& token) {
        struct active_guard_t {
            std::atomic<bool>& flag;
            explicit active_guard_t(std::atomic<bool>& value) : flag(value) {
                flag.store(true, std::memory_order_release);
            }
            ~active_guard_t() { flag.store(false, std::memory_order_release); }
        } active_guard{sampler_state().active};
        for (int slice = 0; slice < 20; ++slice) {
            if (token.requested.load(std::memory_order_acquire))
                return;
            Sleep(50);
        }
        sampler_tick();
    };
    const auto result = rt::submit(std::move(desc));
    state.sampler_job_id.store(result.submitted ? result.handle.id : 0,
        std::memory_order_release);
}

}

analysis_fabric_metrics_t& analysis_fabric_metrics_t::instance() noexcept {
    static analysis_fabric_metrics_t* inst = new analysis_fabric_metrics_t();
    return *inst;
}

void analysis_fabric_metrics_t::ensure_sampler_started() noexcept {
    auto& state = sampler_state();
    bool expected = false;
    if (!state.started.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return;
    if (rt::g_shutdown_requested.load(std::memory_order_acquire) ||
        rt::g_stop_accepting.load(std::memory_order_acquire))
        return;
    try {
        submit_sampler_job();
    } catch (...) {
    }
}

bool analysis_fabric_metrics_t::sampler_running() const noexcept {
    return sampler_state().active.load(std::memory_order_acquire);
}

void analysis_fabric_metrics_t::stop_sampler() noexcept {
    auto& state = sampler_state();
    if (!state.started.load(std::memory_order_acquire))
        return;
    state.stop_requested.store(true, std::memory_order_release);
    const std::uint64_t job_id = state.sampler_job_id.load(std::memory_order_acquire);
    if (job_id != 0) {
        const rt::job_handle_t handle{job_id};
        rt::cancel(handle);
        static_cast<void>(rt::wait_for(handle, 2000));
    }
}

analysis_fabric_metrics_snapshot_t analysis_fabric_metrics_t::snapshot() const noexcept {
    return analysis_fabric_metrics_snapshot();
}

std::shared_ptr<analysis_resource_metrics_t> analysis_fabric_metrics_t::resource_metrics() const noexcept {
    return sampler_state().resource;
}

analysis_fabric_metrics_snapshot_t analysis_fabric_metrics_snapshot() noexcept {
    analysis_fabric_metrics_snapshot_t out;
    auto& state = sampler_state();
    out.sample_sequence = state.sample_sequence.load(std::memory_order_acquire);
    out.sampler_running = state.active.load(std::memory_order_acquire) ? 1 : 0;
    out.watchdog_lag_ms = aida::infra::cancellation_watchdog::last_sweep_lag_ms();
    out.watchdog_registered = aida::infra::cancellation_watchdog::registered_watch_count();
    out.watchdog_fired = aida::infra::cancellation_watchdog::fired_watch_count();
    for (std::size_t index = 0; index < analysis_fabric_domain_count; ++index) {
        const auto domain = static_cast<rt::executor_domain_t>(index);
        const auto stats = rt::domain_stats(domain);
        auto& entry = out.domains[index];
        entry.queue_depth = stats.pending;
        entry.in_flight = stats.lane_in_flight;
        entry.busy_worker_ms = state.domains[index].busy_worker_ms.load(std::memory_order_acquire);
        entry.posted = stats.posted;
        entry.started = stats.started;
        entry.finished = stats.finished;
        entry.rejected = stats.rejected;
        entry.cancelled = stats.cancelled;
        entry.failed = stats.failed;
        entry.timed_out = stats.timed_out;
        entry.active = stats.active;
        entry.workers = stats.workers;
        entry.oldest_active_ms = stats.oldest_active_ms;
        entry.fairness_wait_ns_total = stats.fairness_wait_ns_total;
        entry.fairness_wait_p50_ns = rt::fairness_wait_percentile_ns(domain, 0.5);
        entry.fairness_wait_p95_ns = rt::fairness_wait_percentile_ns(domain, 0.95);
        for (std::size_t lane = 0; lane < analysis_fabric_priority_lane_count; ++lane) {
            entry.lane_depth[lane] = stats.lane_depth[lane];
            entry.lane_admitted[lane] = stats.lane_admitted[lane];
        }
    }
    return out;
}

std::string analysis_fabric_metrics_snapshot_t::to_json() const {
    std::string out;
    out.reserve(4096);
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"schema_version\":%lu,\"generation\":%llu,\"sample_sequence\":%llu,\"sampler_running\":%llu,\"watchdog_lag_ms\":%llu,\"watchdog_registered\":%llu,\"watchdog_fired\":%llu,\"domains\":[",
        static_cast<unsigned long>(schema_version),
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(sample_sequence),
        static_cast<unsigned long long>(sampler_running),
        static_cast<unsigned long long>(watchdog_lag_ms),
        static_cast<unsigned long long>(watchdog_registered),
        static_cast<unsigned long long>(watchdog_fired));
    out += buf;
    for (std::size_t index = 0; index < analysis_fabric_domain_count; ++index) {
        const auto& entry = domains[index];
        if (index > 0)
            out += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"name\":\"%s\",\"queue_depth\":%llu,\"in_flight\":%llu,\"busy_worker_ms\":%llu,\"posted\":%llu,\"started\":%llu,\"finished\":%llu,\"rejected\":%llu,\"cancelled\":%llu,\"failed\":%llu,\"timed_out\":%llu,\"active\":%llu,\"workers\":%llu,\"oldest_active_ms\":%llu,\"fairness_wait_ns_total\":%llu,\"fairness_wait_p50_ns\":%llu,\"fairness_wait_p95_ns\":%llu,\"lane_depth\":[",
            aida::infra::taskflow_runtime::domain_name(
                static_cast<aida::infra::taskflow_runtime::executor_domain_t>(index)),
            static_cast<unsigned long long>(entry.queue_depth),
            static_cast<unsigned long long>(entry.in_flight),
            static_cast<unsigned long long>(entry.busy_worker_ms),
            static_cast<unsigned long long>(entry.posted),
            static_cast<unsigned long long>(entry.started),
            static_cast<unsigned long long>(entry.finished),
            static_cast<unsigned long long>(entry.rejected),
            static_cast<unsigned long long>(entry.cancelled),
            static_cast<unsigned long long>(entry.failed),
            static_cast<unsigned long long>(entry.timed_out),
            static_cast<unsigned long long>(entry.active),
            static_cast<unsigned long long>(entry.workers),
            static_cast<unsigned long long>(entry.oldest_active_ms),
            static_cast<unsigned long long>(entry.fairness_wait_ns_total),
            static_cast<unsigned long long>(entry.fairness_wait_p50_ns),
            static_cast<unsigned long long>(entry.fairness_wait_p95_ns));
        out += buf;
        for (std::size_t lane = 0; lane < analysis_fabric_priority_lane_count; ++lane) {
            if (lane > 0)
                out += ",";
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llu",
                static_cast<unsigned long long>(entry.lane_depth[lane]));
            out += buf;
        }
        out += "],\"lane_admitted\":[";
        for (std::size_t lane = 0; lane < analysis_fabric_priority_lane_count; ++lane) {
            if (lane > 0)
                out += ",";
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llu",
                static_cast<unsigned long long>(entry.lane_admitted[lane]));
            out += buf;
        }
        out += "]}";
    }
    out += "]}";
    return out;
}

}
