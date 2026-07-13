#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace aida::analysis {

enum class baseline_phase_t : std::uint8_t {
    parse = 0,
    seed,
    decode,
    blocks,
    functions,
    cfg_calls,
    xrefs,
    strings_data,
    metadata_symbols_types,
    search_index,
    persistence,
    publish_ready,
    count
};

enum class analysis_metric_t : std::uint8_t {
    file_bytes = 0,
    executable_bytes,
    mapped_bytes,
    read_bytes,
    copied_bytes,
    decoded_bytes,
    indexed_bytes,
    provider_leases,
    mapped_windows,
    provider_revalidations,
    instructions,
    blocks,
    functions,
    cfg_edges,
    call_edges,
    xrefs,
    strings,
    data_candidates,
    symbols,
    types,
    switches,
    thunks,
    noreturn_functions,
    coverage_decoded_bytes,
    coverage_data_bytes,
    coverage_padding_bytes,
    coverage_conflict_bytes,
    coverage_undecodable_bytes,
    tasks_scheduled,
    tasks_completed,
    tasks_rejected,
    work_items,
    cancellation_checks,
    peak_workers,
    peak_queue_depth,
    peak_private_bytes,
    peak_committed_bytes,
    database_bytes,
    database_bytes_written,
    database_logical_bytes,
    database_rows,
    database_commit_elapsed_ns,
    persistence_batches,
    cache_hits,
    cache_misses,
    cache_invalidations,
    cancellation_requests,
    cancellation_completions,
    cancellation_latency_ns,
    concurrent_workspace_peak,
    fairness_wait_ns,
    fairness_service_units,
    mcp_calls,
    mcp_latency_ns,
    mcp_latency_max_ns,
    decompile_cold_calls,
    decompile_cold_latency_ns,
    decompile_cold_latency_max_ns,
    decompile_warm_calls,
    decompile_warm_latency_ns,
    decompile_warm_latency_max_ns,
    count
};

inline constexpr std::size_t baseline_phase_count = static_cast<std::size_t>(baseline_phase_t::count);
inline constexpr std::size_t analysis_metric_count = static_cast<std::size_t>(analysis_metric_t::count);

struct phase_metrics_snapshot_t {
    std::uint64_t invocations = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t cpu_ns = 0;
    std::uint64_t bytes_in = 0;
    std::uint64_t bytes_out = 0;
    std::uint64_t work_items = 0;
    std::uint64_t cancellation_checks = 0;
    std::uint64_t failures = 0;
    std::uint64_t queue_depth_peak = 0;
    std::uint64_t active_workers_peak = 0;
};

struct analysis_metrics_snapshot_t {
    std::array<std::uint64_t, analysis_metric_count> counters{};
    std::array<phase_metrics_snapshot_t, baseline_phase_count> phases{};
    std::uint64_t started_steady_ns = 0;
    std::uint64_t finished_steady_ns = 0;
    std::uint64_t wall_ns = 0;
    std::uint64_t process_cpu_ns = 0;
    std::uint64_t generation = 0;

    std::uint64_t value(analysis_metric_t metric) const noexcept;
    std::string to_json() const;
};

struct phase_measurement_t {
    baseline_phase_t phase = baseline_phase_t::parse;
    std::uint64_t wall_start_ns = 0;
    std::uint64_t cpu_start_ns = 0;
    bool active = false;
};

class analysis_metrics_t final {
public:
    explicit analysis_metrics_t(std::uint64_t generation = 0) noexcept;

    void reset(std::uint64_t generation) noexcept;
    void mark_finished() noexcept;
    void add(analysis_metric_t metric, std::uint64_t value = 1) noexcept;
    void set(analysis_metric_t metric, std::uint64_t value) noexcept;
    void set_max(analysis_metric_t metric, std::uint64_t value) noexcept;
    phase_measurement_t begin_phase(baseline_phase_t phase) noexcept;
    void end_phase(phase_measurement_t& measurement, std::uint64_t bytes_in,
        std::uint64_t bytes_out, std::uint64_t work_items,
        std::uint64_t cancellation_checks, bool failed) noexcept;
    void record_runtime_pressure(std::uint64_t active_workers,
        std::uint64_t queue_depth) noexcept;
    void sample_process_memory() noexcept;
    void record_cancellation_request() noexcept;
    void record_cancellation_completion() noexcept;
    void record_workspace_concurrency(std::uint64_t concurrent_workspaces,
        std::uint64_t fairness_wait_ns, std::uint64_t service_units) noexcept;
    void record_mcp_latency(std::uint64_t latency_ns) noexcept;
    void record_decompile_latency(bool warm, std::uint64_t latency_ns) noexcept;
    analysis_metrics_snapshot_t snapshot() const noexcept;

    static const char* phase_name(baseline_phase_t phase) noexcept;
    static const char* metric_name(analysis_metric_t metric) noexcept;
    static std::uint64_t steady_now_ns() noexcept;

private:
    struct phase_atomic_t {
        std::atomic<std::uint64_t> invocations{0};
        std::atomic<std::uint64_t> wall_ns{0};
        std::atomic<std::uint64_t> cpu_ns{0};
        std::atomic<std::uint64_t> bytes_in{0};
        std::atomic<std::uint64_t> bytes_out{0};
        std::atomic<std::uint64_t> work_items{0};
        std::atomic<std::uint64_t> cancellation_checks{0};
        std::atomic<std::uint64_t> failures{0};
        std::atomic<std::uint64_t> queue_depth_peak{0};
        std::atomic<std::uint64_t> active_workers_peak{0};
        std::atomic<std::uint64_t> active_invocations{0};
    };

    static std::uint64_t current_thread_cpu_ns() noexcept;
    static std::uint64_t current_process_cpu_ns() noexcept;
    static void atomic_add_saturating(std::atomic<std::uint64_t>& target,
        std::uint64_t value) noexcept;
    static void atomic_set_max(std::atomic<std::uint64_t>& target, std::uint64_t value) noexcept;
    void begin_mutation() noexcept;
    void end_mutation() noexcept;
    analysis_metrics_snapshot_t load_snapshot_relaxed() const noexcept;

    mutable std::mutex mutation_mutex_;
    std::atomic<std::uint64_t> coherence_sequence_{0};
    std::array<std::atomic<std::uint64_t>, analysis_metric_count> counters_{};
    std::array<phase_atomic_t, baseline_phase_count> phases_{};
    std::atomic<std::uint64_t> started_steady_ns_{0};
    std::atomic<std::uint64_t> finished_steady_ns_{0};
    std::atomic<std::uint64_t> process_cpu_start_ns_{0};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> cancellation_requested_ns_{0};
};

}
