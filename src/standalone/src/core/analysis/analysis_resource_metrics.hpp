#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

namespace aida::analysis {

inline constexpr std::uint32_t analysis_resource_metrics_schema_version = 1;

enum class analysis_resource_phase_t : std::uint8_t {
    acquisition = 0,
    mapping,
    reading,
    analysis,
    indexing,
    persistence,
    query,
    publication,
    count
};

enum class analysis_resource_metric_t : std::uint8_t {
    phase_wall_ns = 0,
    phase_cpu_ns,
    phase_queue_wait_ns,
    mapped_bytes,
    read_bytes,
    spilled_bytes,
    private_bytes_estimate,
    resident_bytes_estimate,
    cache_hits,
    cancellation_lag_ns,
    tasks_queued,
    tasks_started,
    tasks_completed,
    tasks_cancelled,
    tasks_failed,
    publication_state,
    query_latency_ns,
    workspace_concurrency,
    sla_receipt_validity,
    count
};

enum class analysis_metric_aggregation_t : std::uint8_t {
    sum = 0,
    maximum,
    state,
    derived
};

enum class analysis_publication_state_t : std::uint8_t {
    not_started = 0,
    collecting,
    ready,
    published,
    cancelled,
    failed,
    count
};

enum class analysis_sla_receipt_validity_t : std::uint8_t {
    not_observed = 0,
    valid,
    invalid,
    mixed
};

inline constexpr std::size_t analysis_resource_phase_count =
    static_cast<std::size_t>(analysis_resource_phase_t::count);
inline constexpr std::size_t analysis_resource_metric_count =
    static_cast<std::size_t>(analysis_resource_metric_t::count);

struct analysis_resource_metric_descriptor_t {
    analysis_resource_metric_t metric = analysis_resource_metric_t::phase_wall_ns;
    std::string_view name;
    analysis_metric_aggregation_t aggregation = analysis_metric_aggregation_t::sum;
};

struct analysis_phase_resource_metrics_snapshot_t {
    std::uint64_t wall_ns = 0;
    std::uint64_t cpu_ns = 0;
    std::uint64_t queue_wait_ns = 0;
};

struct analysis_task_counts_t {
    std::uint64_t queued = 0;
    std::uint64_t started = 0;
    std::uint64_t completed = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t failed = 0;
};

struct analysis_resource_metrics_snapshot_t {
    std::uint32_t schema_version = analysis_resource_metrics_schema_version;
    std::uint64_t generation = 0;
    std::uint64_t sample_sequence = 0;
    std::array<analysis_phase_resource_metrics_snapshot_t, analysis_resource_phase_count> phases{};
    std::uint64_t phase_wall_ns = 0;
    std::uint64_t phase_cpu_ns = 0;
    std::uint64_t phase_queue_wait_ns = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t read_bytes = 0;
    std::uint64_t spilled_bytes = 0;
    std::uint64_t private_bytes_estimate = 0;
    std::uint64_t resident_bytes_estimate = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t cancellation_lag_ns = 0;
    std::uint64_t cancellation_count = 0;
    std::uint64_t cancellation_lag_max_ns = 0;
    analysis_task_counts_t tasks{};
    analysis_publication_state_t publication_state = analysis_publication_state_t::not_started;
    std::uint64_t query_latency_ns = 0;
    std::uint64_t query_count = 0;
    std::uint64_t query_latency_max_ns = 0;
    std::uint64_t workspace_concurrency = 0;
    std::uint64_t sla_receipts_observed = 0;
    std::uint64_t sla_receipts_valid = 0;
    std::uint64_t sla_receipts_invalid = 0;
    analysis_sla_receipt_validity_t sla_receipt_validity =
        analysis_sla_receipt_validity_t::not_observed;

    std::uint64_t value(analysis_resource_metric_t metric) const noexcept;
    std::string to_json() const;
};

const analysis_resource_metric_descriptor_t* analysis_resource_metric_descriptor(
    analysis_resource_metric_t metric) noexcept;
const char* analysis_resource_phase_name(analysis_resource_phase_t phase) noexcept;
const char* analysis_publication_state_name(analysis_publication_state_t state) noexcept;
const char* analysis_sla_receipt_validity_name(
    analysis_sla_receipt_validity_t validity) noexcept;
bool publication_state_transition_allowed(analysis_publication_state_t current,
    analysis_publication_state_t next) noexcept;

class analysis_resource_metrics_t final {
public:
    explicit analysis_resource_metrics_t(std::uint64_t generation = 0) noexcept;

    void reset(std::uint64_t generation) noexcept;
    bool record_phase_timing(analysis_resource_phase_t phase, std::uint64_t wall_ns,
        std::uint64_t cpu_ns, std::uint64_t queue_wait_ns) noexcept;
    void add_mapped_bytes(std::uint64_t bytes) noexcept;
    void add_read_bytes(std::uint64_t bytes) noexcept;
    void add_spilled_bytes(std::uint64_t bytes) noexcept;
    void observe_memory_estimates(std::uint64_t private_bytes,
        std::uint64_t resident_bytes) noexcept;
    void record_cache_hits(std::uint64_t hits = 1) noexcept;
    void record_cancellation_lag(std::uint64_t lag_ns) noexcept;
    void record_task_counts(const analysis_task_counts_t& counts) noexcept;
    void record_query_latency(std::uint64_t latency_ns) noexcept;
    void observe_workspace_concurrency(std::uint64_t concurrent_workspaces) noexcept;
    void record_sla_receipt_validity(bool valid) noexcept;
    bool set_publication_state(analysis_publication_state_t next) noexcept;
    analysis_resource_metrics_snapshot_t snapshot() const noexcept;

private:
    struct phase_atomic_t {
        std::atomic<std::uint64_t> wall_ns{0};
        std::atomic<std::uint64_t> cpu_ns{0};
        std::atomic<std::uint64_t> queue_wait_ns{0};
    };

    static void atomic_add_saturating(std::atomic<std::uint64_t>& target,
        std::uint64_t value) noexcept;
    static void atomic_set_max(std::atomic<std::uint64_t>& target,
        std::uint64_t value) noexcept;
    void begin_mutation() noexcept;
    void end_mutation() noexcept;
    void record_mutation() noexcept;
    analysis_resource_metrics_snapshot_t load_snapshot_relaxed() const noexcept;

    mutable std::mutex mutation_mutex_;
    std::atomic<std::uint64_t> coherence_sequence_{0};
    std::array<phase_atomic_t, analysis_resource_phase_count> phases_{};
    std::atomic<std::uint64_t> phase_wall_ns_{0};
    std::atomic<std::uint64_t> phase_cpu_ns_{0};
    std::atomic<std::uint64_t> phase_queue_wait_ns_{0};
    std::atomic<std::uint64_t> mapped_bytes_{0};
    std::atomic<std::uint64_t> read_bytes_{0};
    std::atomic<std::uint64_t> spilled_bytes_{0};
    std::atomic<std::uint64_t> private_bytes_estimate_{0};
    std::atomic<std::uint64_t> resident_bytes_estimate_{0};
    std::atomic<std::uint64_t> cache_hits_{0};
    std::atomic<std::uint64_t> cancellation_lag_ns_{0};
    std::atomic<std::uint64_t> cancellation_count_{0};
    std::atomic<std::uint64_t> cancellation_lag_max_ns_{0};
    std::atomic<std::uint64_t> tasks_queued_{0};
    std::atomic<std::uint64_t> tasks_started_{0};
    std::atomic<std::uint64_t> tasks_completed_{0};
    std::atomic<std::uint64_t> tasks_cancelled_{0};
    std::atomic<std::uint64_t> tasks_failed_{0};
    std::atomic<std::uint64_t> query_latency_ns_{0};
    std::atomic<std::uint64_t> query_count_{0};
    std::atomic<std::uint64_t> query_latency_max_ns_{0};
    std::atomic<std::uint64_t> workspace_concurrency_{0};
    std::atomic<std::uint64_t> sla_receipts_observed_{0};
    std::atomic<std::uint64_t> sla_receipts_valid_{0};
    std::atomic<std::uint64_t> sla_receipts_invalid_{0};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> mutation_sequence_{0};
    std::atomic<analysis_publication_state_t> publication_state_{
        analysis_publication_state_t::not_started};
};

}
