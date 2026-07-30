#include "analysis_metrics.hpp"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iterator>
#include <limits>
#include <locale>
#include <sstream>

namespace aida::analysis {
namespace {

std::uint64_t filetime_value(const FILETIME& value) noexcept {
    ULARGE_INTEGER converted{};
    converted.LowPart = value.dwLowDateTime;
    converted.HighPart = value.dwHighDateTime;
    return converted.QuadPart;
}

std::size_t phase_index(baseline_phase_t phase) noexcept {
    const auto value = static_cast<std::size_t>(phase);
    return value < baseline_phase_count ? value : 0;
}

std::size_t metric_index(analysis_metric_t metric) noexcept {
    const auto value = static_cast<std::size_t>(metric);
    return value < analysis_metric_count ? value : 0;
}

}

std::uint64_t analysis_metrics_snapshot_t::value(analysis_metric_t metric) const noexcept {
    return counters[metric_index(metric)];
}

std::string analysis_metrics_snapshot_t::to_json() const {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << "{\"generation\":" << generation
        << ",\"metrics_schema_version\":2"
        << ",\"started_steady_ns\":" << started_steady_ns
        << ",\"finished_steady_ns\":" << finished_steady_ns
        << ",\"wall_ns\":" << wall_ns
        << ",\"process_cpu_ns\":" << process_cpu_ns
        << ",\"counters\":{";
    for (std::size_t i = 0; i < counters.size(); ++i) {
        if (i != 0)
            out << ',';
        out << '\"' << analysis_metrics_t::metric_name(static_cast<analysis_metric_t>(i))
            << "\":" << counters[i];
    }
    out << "},\"phases\":[";
    bool first_phase = true;
    for (std::size_t i = 0; i < phases.size(); ++i) {
        if (phases[i].invocations == 0)
            continue;
        if (!first_phase)
            out << ',';
        first_phase = false;
        const auto& phase = phases[i];
        out << "{\"name\":\"" << analysis_metrics_t::phase_name(static_cast<baseline_phase_t>(i))
            << "\",\"invocations\":" << phase.invocations
            << ",\"wall_ns\":" << phase.wall_ns
            << ",\"cpu_ns\":" << phase.cpu_ns
            << ",\"bytes_in\":" << phase.bytes_in
            << ",\"bytes_out\":" << phase.bytes_out
            << ",\"work_items\":" << phase.work_items
            << ",\"cancellation_checks\":" << phase.cancellation_checks
            << ",\"failures\":" << phase.failures
            << ",\"queue_depth_peak\":" << phase.queue_depth_peak
            << ",\"active_workers_peak\":" << phase.active_workers_peak << '}';
    }
    out << "]}";
    return out.str();
}

analysis_metrics_t::analysis_metrics_t(std::uint64_t generation) noexcept {
    reset(generation);
}

void analysis_metrics_t::reset(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    for (auto& counter : counters_)
        counter.store(0, std::memory_order_relaxed);
    for (auto& phase : phases_) {
        phase.invocations.store(0, std::memory_order_relaxed);
        phase.wall_ns.store(0, std::memory_order_relaxed);
        phase.cpu_ns.store(0, std::memory_order_relaxed);
        phase.bytes_in.store(0, std::memory_order_relaxed);
        phase.bytes_out.store(0, std::memory_order_relaxed);
        phase.work_items.store(0, std::memory_order_relaxed);
        phase.cancellation_checks.store(0, std::memory_order_relaxed);
        phase.failures.store(0, std::memory_order_relaxed);
        phase.queue_depth_peak.store(0, std::memory_order_relaxed);
        phase.active_workers_peak.store(0, std::memory_order_relaxed);
        phase.active_invocations.store(0, std::memory_order_relaxed);
    }
    generation_.store(generation, std::memory_order_release);
    cancellation_requested_ns_.store(0, std::memory_order_release);
    finished_steady_ns_.store(0, std::memory_order_release);
    process_cpu_start_ns_.store(current_process_cpu_ns(), std::memory_order_release);
    started_steady_ns_.store(steady_now_ns(), std::memory_order_release);
    sample_process_memory();
    end_mutation();
}

void analysis_metrics_t::mark_finished() noexcept {
    sample_process_memory();
    std::uint64_t expected = 0;
    const auto now = steady_now_ns();
    finished_steady_ns_.compare_exchange_strong(expected, now,
        std::memory_order_acq_rel, std::memory_order_acquire);
}

void analysis_metrics_t::add(analysis_metric_t metric, std::uint64_t value) noexcept {
    atomic_add_saturating(counters_[metric_index(metric)], value);
}

void analysis_metrics_t::set(analysis_metric_t metric, std::uint64_t value) noexcept {
    counters_[metric_index(metric)].store(value, std::memory_order_release);
}

void analysis_metrics_t::atomic_set_max(std::atomic<std::uint64_t>& target,
    std::uint64_t value) noexcept {
    auto current = target.load(std::memory_order_relaxed);
    while (current < value && !target.compare_exchange_weak(current, value,
        std::memory_order_relaxed, std::memory_order_relaxed)) {
    }
}

void analysis_metrics_t::atomic_add_saturating(std::atomic<std::uint64_t>& target,
    std::uint64_t value) noexcept {
    auto current = target.load(std::memory_order_relaxed);
    for (;;) {
        const auto updated = value > std::numeric_limits<std::uint64_t>::max() - current
            ? std::numeric_limits<std::uint64_t>::max() : current + value;
        if (target.compare_exchange_weak(current, updated,
                std::memory_order_relaxed, std::memory_order_relaxed))
            return;
    }
}

void analysis_metrics_t::set_max(analysis_metric_t metric, std::uint64_t value) noexcept {
    atomic_set_max(counters_[metric_index(metric)], value);
}

phase_measurement_t analysis_metrics_t::begin_phase(baseline_phase_t phase) noexcept {
    phase_measurement_t measurement;
    measurement.phase = phase;
    measurement.wall_start_ns = steady_now_ns();
    measurement.cpu_start_ns = current_thread_cpu_ns();
    measurement.active = true;
    auto& phase_metrics = phases_[phase_index(phase)];
    atomic_add_saturating(phase_metrics.invocations, 1);
    phase_metrics.active_invocations.fetch_add(1, std::memory_order_acq_rel);
    atomic_set_max(phase_metrics.queue_depth_peak,
        counters_[metric_index(analysis_metric_t::peak_queue_depth)].load(
            std::memory_order_acquire));
    atomic_set_max(phase_metrics.active_workers_peak,
        counters_[metric_index(analysis_metric_t::peak_workers)].load(
            std::memory_order_acquire));
    sample_process_memory();
    return measurement;
}

void analysis_metrics_t::end_phase(phase_measurement_t& measurement,
    std::uint64_t bytes_in, std::uint64_t bytes_out, std::uint64_t work_items,
    std::uint64_t cancellation_checks, bool failed) noexcept {
    if (!measurement.active)
        return;
    const auto wall_now = steady_now_ns();
    const auto cpu_now = current_thread_cpu_ns();
    auto& phase = phases_[phase_index(measurement.phase)];
    atomic_add_saturating(phase.wall_ns, wall_now >= measurement.wall_start_ns
        ? wall_now - measurement.wall_start_ns : 0);
    atomic_add_saturating(phase.cpu_ns, cpu_now >= measurement.cpu_start_ns
        ? cpu_now - measurement.cpu_start_ns : 0);
    atomic_add_saturating(phase.bytes_in, bytes_in);
    atomic_add_saturating(phase.bytes_out, bytes_out);
    atomic_add_saturating(phase.work_items, work_items);
    atomic_add_saturating(phase.cancellation_checks, cancellation_checks);
    if (failed)
        atomic_add_saturating(phase.failures, 1);
    phase.active_invocations.fetch_sub(1, std::memory_order_acq_rel);
    add(analysis_metric_t::work_items, work_items);
    add(analysis_metric_t::cancellation_checks, cancellation_checks);
    measurement.active = false;
    sample_process_memory();
}

void analysis_metrics_t::record_runtime_pressure(std::uint64_t active_workers,
    std::uint64_t queue_depth) noexcept {
    set_max(analysis_metric_t::peak_workers, active_workers);
    set_max(analysis_metric_t::peak_queue_depth, queue_depth);
    add(analysis_metric_t::queue_depth_sum, queue_depth);
    add(analysis_metric_t::queue_depth_samples, 1);
    for (auto& phase : phases_) {
        if (phase.active_invocations.load(std::memory_order_acquire) == 0)
            continue;
        atomic_set_max(phase.queue_depth_peak, queue_depth);
        atomic_set_max(phase.active_workers_peak, active_workers);
    }
}

void analysis_metrics_t::sample_process_memory() noexcept {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
        return;
    }
    set_max(analysis_metric_t::peak_private_bytes,
        static_cast<std::uint64_t>(counters.PrivateUsage));
    set_max(analysis_metric_t::peak_committed_bytes,
        static_cast<std::uint64_t>(counters.PagefileUsage));
    set_max(analysis_metric_t::resident_bytes_peak,
        static_cast<std::uint64_t>(counters.PeakWorkingSetSize));
}

void analysis_metrics_t::record_cancellation_request() noexcept {
    add(analysis_metric_t::cancellation_requests);
    std::uint64_t expected = 0;
    const auto now = steady_now_ns();
    cancellation_requested_ns_.compare_exchange_strong(expected, now,
        std::memory_order_acq_rel, std::memory_order_acquire);
}

void analysis_metrics_t::record_cancellation_completion() noexcept {
    add(analysis_metric_t::cancellation_completions);
    const auto requested = cancellation_requested_ns_.load(std::memory_order_acquire);
    const auto now = steady_now_ns();
    if (requested != 0 && now >= requested)
        set_max(analysis_metric_t::cancellation_latency_ns, now - requested);
}

void analysis_metrics_t::record_workspace_concurrency(std::uint64_t concurrent_workspaces,
    std::uint64_t fairness_wait_ns, std::uint64_t service_units) noexcept {
    set_max(analysis_metric_t::concurrent_workspace_peak, concurrent_workspaces);
    add(analysis_metric_t::fairness_wait_ns, fairness_wait_ns);
    add(analysis_metric_t::fairness_service_units, service_units);
}

void analysis_metrics_t::record_mcp_latency(std::uint64_t latency_ns) noexcept {
    add(analysis_metric_t::mcp_calls);
    add(analysis_metric_t::mcp_latency_ns, latency_ns);
    set_max(analysis_metric_t::mcp_latency_max_ns, latency_ns);
}

void analysis_metrics_t::record_decompile_latency(bool warm, std::uint64_t latency_ns) noexcept {
    const auto calls = warm ? analysis_metric_t::decompile_warm_calls
        : analysis_metric_t::decompile_cold_calls;
    const auto total = warm ? analysis_metric_t::decompile_warm_latency_ns
        : analysis_metric_t::decompile_cold_latency_ns;
    const auto maximum = warm ? analysis_metric_t::decompile_warm_latency_max_ns
        : analysis_metric_t::decompile_cold_latency_max_ns;
    add(calls);
    add(total, latency_ns);
    set_max(maximum, latency_ns);
}

void analysis_metrics_t::begin_mutation() noexcept {
    coherence_sequence_.fetch_add(1, std::memory_order_acq_rel);
}

void analysis_metrics_t::end_mutation() noexcept {
    coherence_sequence_.fetch_add(1, std::memory_order_release);
}

analysis_metrics_snapshot_t analysis_metrics_t::load_snapshot_relaxed() const noexcept {
    analysis_metrics_snapshot_t result;
    for (std::size_t i = 0; i < counters_.size(); ++i)
        result.counters[i] = counters_[i].load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < phases_.size(); ++i) {
        const auto& source = phases_[i];
        auto& target = result.phases[i];
        target.invocations = source.invocations.load(std::memory_order_relaxed);
        target.wall_ns = source.wall_ns.load(std::memory_order_relaxed);
        target.cpu_ns = source.cpu_ns.load(std::memory_order_relaxed);
        target.bytes_in = source.bytes_in.load(std::memory_order_relaxed);
        target.bytes_out = source.bytes_out.load(std::memory_order_relaxed);
        target.work_items = source.work_items.load(std::memory_order_relaxed);
        target.cancellation_checks = source.cancellation_checks.load(std::memory_order_relaxed);
        target.failures = source.failures.load(std::memory_order_relaxed);
        target.queue_depth_peak = source.queue_depth_peak.load(std::memory_order_relaxed);
        target.active_workers_peak = source.active_workers_peak.load(std::memory_order_relaxed);
    }
    result.started_steady_ns = started_steady_ns_.load(std::memory_order_relaxed);
    result.finished_steady_ns = finished_steady_ns_.load(std::memory_order_relaxed);
    const auto end = result.finished_steady_ns != 0
        ? result.finished_steady_ns : steady_now_ns();
    result.wall_ns = end >= result.started_steady_ns ? end - result.started_steady_ns : 0;
    const auto cpu_now = current_process_cpu_ns();
    const auto cpu_start = process_cpu_start_ns_.load(std::memory_order_relaxed);
    result.process_cpu_ns = cpu_now >= cpu_start ? cpu_now - cpu_start : 0;
    result.generation = generation_.load(std::memory_order_relaxed);
    return result;
}

analysis_metrics_snapshot_t analysis_metrics_t::snapshot() const noexcept {
    constexpr std::size_t optimistic_attempt_count = 8;
    for (std::size_t attempt = 0; attempt < optimistic_attempt_count; ++attempt) {
        const auto sequence_before = coherence_sequence_.load(std::memory_order_acquire);
        if ((sequence_before & 1U) != 0)
            continue;
        auto result = load_snapshot_relaxed();
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const auto sequence_after = coherence_sequence_.load(std::memory_order_acquire);
        if (sequence_before == sequence_after)
            return result;
    }

    std::lock_guard<std::mutex> lock(mutation_mutex_);
    return load_snapshot_relaxed();
}

const char* analysis_metrics_t::phase_name(baseline_phase_t phase) noexcept {
    static constexpr const char* names[] = {
        "parse", "seed", "decode", "blocks", "functions", "cfg_calls",
        "xrefs", "strings_data", "metadata_symbols_types", "search_index",
        "persistence", "publish_ready", "decode_merge"
    };
    static_assert(std::size(names) == baseline_phase_count);
    return names[phase_index(phase)];
}

const char* analysis_metrics_t::metric_name(analysis_metric_t metric) noexcept {
    static constexpr const char* names[] = {
        "file_bytes", "executable_bytes", "mapped_bytes", "read_bytes",
        "copied_bytes", "decoded_bytes", "indexed_bytes", "provider_leases",
        "mapped_windows", "provider_revalidations", "instructions", "blocks",
        "functions", "cfg_edges", "call_edges", "xrefs", "strings",
        "data_candidates", "symbols", "types", "switches", "thunks",
        "noreturn_functions", "coverage_decoded_bytes", "coverage_data_bytes",
        "coverage_padding_bytes", "coverage_conflict_bytes",
        "coverage_undecodable_bytes", "tasks_scheduled", "tasks_completed",
        "tasks_rejected", "work_items", "cancellation_checks", "peak_workers",
        "peak_queue_depth", "peak_private_bytes", "peak_committed_bytes",
        "database_bytes", "database_bytes_written", "database_logical_bytes",
        "database_rows", "database_commit_elapsed_ns", "persistence_batches",
        "cache_hits", "cache_misses", "cache_invalidations",
        "cancellation_requests", "cancellation_completions",
        "cancellation_latency_ns", "concurrent_workspace_peak",
        "fairness_wait_ns", "fairness_service_units", "mcp_calls",
        "mcp_latency_ns", "mcp_latency_max_ns", "decompile_cold_calls",
        "decompile_cold_latency_ns", "decompile_cold_latency_max_ns",
        "decompile_warm_calls", "decompile_warm_latency_ns",
        "decompile_warm_latency_max_ns", "worker_slots_busy_ns",
        "worker_slots_scheduled_ns", "queue_wait_ns_total",
        "queue_wait_max_ns", "queue_depth_sum", "queue_depth_samples",
        "decode_tiles", "decode_requests", "decode_frontier_seeds",
        "decode_waves", "decode_cross_tile_edges", "decode_invalid_bytes",
        "decode_invalid_runs", "decode_duplicate_instructions",
        "decode_merge_ns", "decode_lane_wall_ns_max",
        "decode_bytes_attempted", "blocks_split", "function_seeds_processed",
        "cfg_indirect_sites", "xref_candidates", "strings_scanned_bytes",
        "pass_merge_ns", "index_entries", "index_trigram_postings",
        "index_text_bytes", "index_serialized_bytes",
        "type_candidates_evaluated", "persist_queue_wait_ns",
        "persist_queue_depth_peak", "persist_pages_written",
        "persist_wal_bytes_peak", "resident_bytes_peak",
        "mapped_window_bytes_peak", "mapped_window_bytes_global_peak",
        "spill_bytes_peak", "spill_bytes_written", "spill_bytes_read",
        "budget_rejections", "memory_pressure_events",
        "decompile_batch_calls", "decompile_batch_completed",
        "decompile_batch_failed", "decompile_batch_cancelled",
        "decompile_batch_wall_ns", "decompile_batch_queue_depth_peak",
        "decompile_memory_cache_hits", "decompile_persistent_cache_hits"
    };
    static_assert(std::size(names) == analysis_metric_count);
    return names[metric_index(metric)];
}

std::uint64_t analysis_metrics_t::steady_now_ns() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::uint64_t analysis_metrics_t::current_thread_cpu_ns() noexcept {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user))
        return 0;
    return (filetime_value(kernel) + filetime_value(user)) * 100ULL;
}

std::uint64_t analysis_metrics_t::current_process_cpu_ns() noexcept {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        return 0;
    return (filetime_value(kernel) + filetime_value(user)) * 100ULL;
}

}
