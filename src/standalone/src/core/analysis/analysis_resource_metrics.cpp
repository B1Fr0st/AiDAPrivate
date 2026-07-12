#include "analysis_resource_metrics.hpp"

#include <array>
#include <limits>
#include <locale>
#include <sstream>

namespace aida::analysis {
namespace {

constexpr std::array<analysis_resource_metric_descriptor_t, analysis_resource_metric_count>
    resource_metric_descriptors{{
        {analysis_resource_metric_t::phase_wall_ns, "phase_wall_ns", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::phase_cpu_ns, "phase_cpu_ns", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::phase_queue_wait_ns, "phase_queue_wait_ns", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::mapped_bytes, "mapped_bytes", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::read_bytes, "read_bytes", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::spilled_bytes, "spilled_bytes", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::private_bytes_estimate, "private_bytes_estimate", analysis_metric_aggregation_t::maximum},
        {analysis_resource_metric_t::resident_bytes_estimate, "resident_bytes_estimate", analysis_metric_aggregation_t::maximum},
        {analysis_resource_metric_t::cache_hits, "cache_hits", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::cancellation_lag_ns, "cancellation_lag_ns", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::tasks_queued, "tasks_queued", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::tasks_started, "tasks_started", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::tasks_completed, "tasks_completed", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::tasks_cancelled, "tasks_cancelled", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::tasks_failed, "tasks_failed", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::publication_state, "publication_state", analysis_metric_aggregation_t::state},
        {analysis_resource_metric_t::query_latency_ns, "query_latency_ns", analysis_metric_aggregation_t::sum},
        {analysis_resource_metric_t::workspace_concurrency, "workspace_concurrency", analysis_metric_aggregation_t::maximum},
        {analysis_resource_metric_t::sla_receipt_validity, "sla_receipt_validity", analysis_metric_aggregation_t::derived},
    }};

constexpr std::array<const char*, analysis_resource_phase_count> resource_phase_names{{
    "acquisition", "mapping", "reading", "analysis", "indexing", "persistence", "query", "publication"
}};

constexpr std::array<const char*, static_cast<std::size_t>(analysis_publication_state_t::count)>
    publication_state_names{{
        "not_started", "collecting", "ready", "published", "cancelled", "failed"
    }};

constexpr std::array<const char*, 4> sla_receipt_validity_names{{
    "not_observed", "valid", "invalid", "mixed"
}};

constexpr std::size_t phase_index(analysis_resource_phase_t phase) noexcept
{
    const auto value = static_cast<std::size_t>(phase);
    return value < analysis_resource_phase_count ? value : analysis_resource_phase_count;
}

constexpr std::size_t metric_index(analysis_resource_metric_t metric) noexcept
{
    const auto value = static_cast<std::size_t>(metric);
    return value < analysis_resource_metric_count ? value : analysis_resource_metric_count;
}

constexpr bool publication_state_valid(analysis_publication_state_t state) noexcept
{
    return static_cast<std::size_t>(state) < publication_state_names.size();
}

analysis_sla_receipt_validity_t derive_sla_receipt_validity(std::uint64_t observed,
    std::uint64_t valid, std::uint64_t invalid) noexcept
{
    if (observed == 0)
        return analysis_sla_receipt_validity_t::not_observed;
    if (invalid == 0 && valid == observed)
        return analysis_sla_receipt_validity_t::valid;
    if (valid == 0 && invalid == observed)
        return analysis_sla_receipt_validity_t::invalid;
    return analysis_sla_receipt_validity_t::mixed;
}

}

const analysis_resource_metric_descriptor_t* analysis_resource_metric_descriptor(
    analysis_resource_metric_t metric) noexcept
{
    const auto index = metric_index(metric);
    return index < resource_metric_descriptors.size() ? &resource_metric_descriptors[index] : nullptr;
}

const char* analysis_resource_phase_name(analysis_resource_phase_t phase) noexcept
{
    const auto index = phase_index(phase);
    return index < resource_phase_names.size() ? resource_phase_names[index] : "unknown";
}

const char* analysis_publication_state_name(analysis_publication_state_t state) noexcept
{
    const auto index = static_cast<std::size_t>(state);
    return index < publication_state_names.size() ? publication_state_names[index] : "unknown";
}

const char* analysis_sla_receipt_validity_name(
    analysis_sla_receipt_validity_t validity) noexcept
{
    const auto index = static_cast<std::size_t>(validity);
    return index < sla_receipt_validity_names.size() ? sla_receipt_validity_names[index] : "unknown";
}

bool publication_state_transition_allowed(analysis_publication_state_t current,
    analysis_publication_state_t next) noexcept
{
    if (!publication_state_valid(current) || !publication_state_valid(next))
        return false;
    if (current == next)
        return true;
    switch (current) {
    case analysis_publication_state_t::not_started:
        return next == analysis_publication_state_t::collecting ||
            next == analysis_publication_state_t::cancelled ||
            next == analysis_publication_state_t::failed;
    case analysis_publication_state_t::collecting:
        return next == analysis_publication_state_t::ready ||
            next == analysis_publication_state_t::cancelled ||
            next == analysis_publication_state_t::failed;
    case analysis_publication_state_t::ready:
        return next == analysis_publication_state_t::published ||
            next == analysis_publication_state_t::cancelled ||
            next == analysis_publication_state_t::failed;
    case analysis_publication_state_t::published:
    case analysis_publication_state_t::cancelled:
    case analysis_publication_state_t::failed:
    case analysis_publication_state_t::count:
        return false;
    }
    return false;
}

std::uint64_t analysis_resource_metrics_snapshot_t::value(
    analysis_resource_metric_t metric) const noexcept
{
    switch (metric) {
    case analysis_resource_metric_t::phase_wall_ns:
        return phase_wall_ns;
    case analysis_resource_metric_t::phase_cpu_ns:
        return phase_cpu_ns;
    case analysis_resource_metric_t::phase_queue_wait_ns:
        return phase_queue_wait_ns;
    case analysis_resource_metric_t::mapped_bytes:
        return mapped_bytes;
    case analysis_resource_metric_t::read_bytes:
        return read_bytes;
    case analysis_resource_metric_t::spilled_bytes:
        return spilled_bytes;
    case analysis_resource_metric_t::private_bytes_estimate:
        return private_bytes_estimate;
    case analysis_resource_metric_t::resident_bytes_estimate:
        return resident_bytes_estimate;
    case analysis_resource_metric_t::cache_hits:
        return cache_hits;
    case analysis_resource_metric_t::cancellation_lag_ns:
        return cancellation_lag_ns;
    case analysis_resource_metric_t::tasks_queued:
        return tasks.queued;
    case analysis_resource_metric_t::tasks_started:
        return tasks.started;
    case analysis_resource_metric_t::tasks_completed:
        return tasks.completed;
    case analysis_resource_metric_t::tasks_cancelled:
        return tasks.cancelled;
    case analysis_resource_metric_t::tasks_failed:
        return tasks.failed;
    case analysis_resource_metric_t::publication_state:
        return static_cast<std::uint64_t>(publication_state);
    case analysis_resource_metric_t::query_latency_ns:
        return query_latency_ns;
    case analysis_resource_metric_t::workspace_concurrency:
        return workspace_concurrency;
    case analysis_resource_metric_t::sla_receipt_validity:
        return static_cast<std::uint64_t>(sla_receipt_validity);
    case analysis_resource_metric_t::count:
        return 0;
    }
    return 0;
}

std::string analysis_resource_metrics_snapshot_t::to_json() const
{
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << "{\"schema\":\"aida.analysis.resource-metrics\""
        << ",\"schema_version\":" << schema_version
        << ",\"generation\":" << generation
        << ",\"sample_sequence\":" << sample_sequence
        << ",\"publication_state\":\""
        << analysis_publication_state_name(publication_state) << '\"'
        << ",\"sla_receipt_validity\":\""
        << analysis_sla_receipt_validity_name(sla_receipt_validity) << '\"'
        << ",\"phases\":[";
    for (std::size_t index = 0; index < phases.size(); ++index) {
        if (index != 0)
            out << ',';
        const auto& phase = phases[index];
        out << "{\"name\":\""
            << analysis_resource_phase_name(static_cast<analysis_resource_phase_t>(index))
            << "\",\"wall_ns\":" << phase.wall_ns
            << ",\"cpu_ns\":" << phase.cpu_ns
            << ",\"queue_wait_ns\":" << phase.queue_wait_ns << '}';
    }
    out << "],\"metrics\":{";
    for (std::size_t index = 0; index < resource_metric_descriptors.size(); ++index) {
        if (index != 0)
            out << ',';
        const auto metric = static_cast<analysis_resource_metric_t>(index);
        const auto& descriptor = resource_metric_descriptors[index];
        out << '\"' << descriptor.name << "\":";
        if (metric == analysis_resource_metric_t::publication_state) {
            out << '\"' << analysis_publication_state_name(publication_state) << '\"';
        } else if (metric == analysis_resource_metric_t::sla_receipt_validity) {
            out << '\"' << analysis_sla_receipt_validity_name(sla_receipt_validity) << '\"';
        } else {
            out << value(metric);
        }
    }
    out << "},\"cancellation\":{\"count\":" << cancellation_count
        << ",\"max_lag_ns\":" << cancellation_lag_max_ns
        << "},\"query\":{\"count\":" << query_count
        << ",\"max_latency_ns\":" << query_latency_max_ns
        << "},\"sla_receipts\":{\"observed\":" << sla_receipts_observed
        << ",\"valid\":" << sla_receipts_valid
        << ",\"invalid\":" << sla_receipts_invalid << "}}";
    return out.str();
}

analysis_resource_metrics_t::analysis_resource_metrics_t(std::uint64_t generation) noexcept
{
    reset(generation);
}

void analysis_resource_metrics_t::reset(std::uint64_t generation) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    for (auto& phase : phases_) {
        phase.wall_ns.store(0, std::memory_order_relaxed);
        phase.cpu_ns.store(0, std::memory_order_relaxed);
        phase.queue_wait_ns.store(0, std::memory_order_relaxed);
    }
    phase_wall_ns_.store(0, std::memory_order_relaxed);
    phase_cpu_ns_.store(0, std::memory_order_relaxed);
    phase_queue_wait_ns_.store(0, std::memory_order_relaxed);
    mapped_bytes_.store(0, std::memory_order_relaxed);
    read_bytes_.store(0, std::memory_order_relaxed);
    spilled_bytes_.store(0, std::memory_order_relaxed);
    private_bytes_estimate_.store(0, std::memory_order_relaxed);
    resident_bytes_estimate_.store(0, std::memory_order_relaxed);
    cache_hits_.store(0, std::memory_order_relaxed);
    cancellation_lag_ns_.store(0, std::memory_order_relaxed);
    cancellation_count_.store(0, std::memory_order_relaxed);
    cancellation_lag_max_ns_.store(0, std::memory_order_relaxed);
    tasks_queued_.store(0, std::memory_order_relaxed);
    tasks_started_.store(0, std::memory_order_relaxed);
    tasks_completed_.store(0, std::memory_order_relaxed);
    tasks_cancelled_.store(0, std::memory_order_relaxed);
    tasks_failed_.store(0, std::memory_order_relaxed);
    query_latency_ns_.store(0, std::memory_order_relaxed);
    query_count_.store(0, std::memory_order_relaxed);
    query_latency_max_ns_.store(0, std::memory_order_relaxed);
    workspace_concurrency_.store(0, std::memory_order_relaxed);
    sla_receipts_observed_.store(0, std::memory_order_relaxed);
    sla_receipts_valid_.store(0, std::memory_order_relaxed);
    sla_receipts_invalid_.store(0, std::memory_order_relaxed);
    publication_state_.store(analysis_publication_state_t::not_started,
        std::memory_order_relaxed);
    generation_.store(generation, std::memory_order_relaxed);
    mutation_sequence_.store(0, std::memory_order_relaxed);
    end_mutation();
}

void analysis_resource_metrics_t::atomic_add_saturating(std::atomic<std::uint64_t>& target,
    std::uint64_t value) noexcept
{
    auto current = target.load(std::memory_order_relaxed);
    for (;;) {
        const auto updated = value > (std::numeric_limits<std::uint64_t>::max)() - current
            ? (std::numeric_limits<std::uint64_t>::max)()
            : current + value;
        if (target.compare_exchange_weak(current, updated, std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return;
        }
    }
}

void analysis_resource_metrics_t::atomic_set_max(std::atomic<std::uint64_t>& target,
    std::uint64_t value) noexcept
{
    auto current = target.load(std::memory_order_relaxed);
    while (current < value && !target.compare_exchange_weak(current, value,
        std::memory_order_relaxed, std::memory_order_relaxed)) {
    }
}

void analysis_resource_metrics_t::begin_mutation() noexcept
{
    coherence_sequence_.fetch_add(1, std::memory_order_acq_rel);
}

void analysis_resource_metrics_t::end_mutation() noexcept
{
    coherence_sequence_.fetch_add(1, std::memory_order_release);
}

void analysis_resource_metrics_t::record_mutation() noexcept
{
    atomic_add_saturating(mutation_sequence_, 1);
}

bool analysis_resource_metrics_t::record_phase_timing(analysis_resource_phase_t phase,
    std::uint64_t wall_ns, std::uint64_t cpu_ns, std::uint64_t queue_wait_ns) noexcept
{
    const auto index = phase_index(phase);
    if (index == analysis_resource_phase_count)
        return false;
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    auto& phase_metrics = phases_[index];
    atomic_add_saturating(phase_metrics.wall_ns, wall_ns);
    atomic_add_saturating(phase_metrics.cpu_ns, cpu_ns);
    atomic_add_saturating(phase_metrics.queue_wait_ns, queue_wait_ns);
    atomic_add_saturating(phase_wall_ns_, wall_ns);
    atomic_add_saturating(phase_cpu_ns_, cpu_ns);
    atomic_add_saturating(phase_queue_wait_ns_, queue_wait_ns);
    record_mutation();
    end_mutation();
    return true;
}

void analysis_resource_metrics_t::add_mapped_bytes(std::uint64_t bytes) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(mapped_bytes_, bytes);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::add_read_bytes(std::uint64_t bytes) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(read_bytes_, bytes);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::add_spilled_bytes(std::uint64_t bytes) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(spilled_bytes_, bytes);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::observe_memory_estimates(std::uint64_t private_bytes,
    std::uint64_t resident_bytes) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_set_max(private_bytes_estimate_, private_bytes);
    atomic_set_max(resident_bytes_estimate_, resident_bytes);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::record_cache_hits(std::uint64_t hits) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(cache_hits_, hits);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::record_cancellation_lag(std::uint64_t lag_ns) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(cancellation_lag_ns_, lag_ns);
    atomic_add_saturating(cancellation_count_, 1);
    atomic_set_max(cancellation_lag_max_ns_, lag_ns);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::record_task_counts(const analysis_task_counts_t& counts) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(tasks_queued_, counts.queued);
    atomic_add_saturating(tasks_started_, counts.started);
    atomic_add_saturating(tasks_completed_, counts.completed);
    atomic_add_saturating(tasks_cancelled_, counts.cancelled);
    atomic_add_saturating(tasks_failed_, counts.failed);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::record_query_latency(std::uint64_t latency_ns) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(query_latency_ns_, latency_ns);
    atomic_add_saturating(query_count_, 1);
    atomic_set_max(query_latency_max_ns_, latency_ns);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::observe_workspace_concurrency(
    std::uint64_t concurrent_workspaces) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_set_max(workspace_concurrency_, concurrent_workspaces);
    record_mutation();
    end_mutation();
}

void analysis_resource_metrics_t::record_sla_receipt_validity(bool valid) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    begin_mutation();
    atomic_add_saturating(sla_receipts_observed_, 1);
    if (valid)
        atomic_add_saturating(sla_receipts_valid_, 1);
    else
        atomic_add_saturating(sla_receipts_invalid_, 1);
    record_mutation();
    end_mutation();
}

bool analysis_resource_metrics_t::set_publication_state(
    analysis_publication_state_t next) noexcept
{
    std::lock_guard<std::mutex> lock(mutation_mutex_);
    const auto current = publication_state_.load(std::memory_order_relaxed);
    if (!publication_state_transition_allowed(current, next))
        return false;
    if (current == next)
        return true;
    begin_mutation();
    publication_state_.store(next, std::memory_order_relaxed);
    record_mutation();
    end_mutation();
    return true;
}

analysis_resource_metrics_snapshot_t analysis_resource_metrics_t::load_snapshot_relaxed() const noexcept
{
    analysis_resource_metrics_snapshot_t result;
    result.generation = generation_.load(std::memory_order_relaxed);
    for (std::size_t index = 0; index < phases_.size(); ++index) {
        const auto& source = phases_[index];
        auto& target = result.phases[index];
        target.wall_ns = source.wall_ns.load(std::memory_order_relaxed);
        target.cpu_ns = source.cpu_ns.load(std::memory_order_relaxed);
        target.queue_wait_ns = source.queue_wait_ns.load(std::memory_order_relaxed);
    }
    result.phase_wall_ns = phase_wall_ns_.load(std::memory_order_relaxed);
    result.phase_cpu_ns = phase_cpu_ns_.load(std::memory_order_relaxed);
    result.phase_queue_wait_ns = phase_queue_wait_ns_.load(std::memory_order_relaxed);
    result.mapped_bytes = mapped_bytes_.load(std::memory_order_relaxed);
    result.read_bytes = read_bytes_.load(std::memory_order_relaxed);
    result.spilled_bytes = spilled_bytes_.load(std::memory_order_relaxed);
    result.private_bytes_estimate = private_bytes_estimate_.load(std::memory_order_relaxed);
    result.resident_bytes_estimate = resident_bytes_estimate_.load(std::memory_order_relaxed);
    result.cache_hits = cache_hits_.load(std::memory_order_relaxed);
    result.cancellation_lag_ns = cancellation_lag_ns_.load(std::memory_order_relaxed);
    result.cancellation_count = cancellation_count_.load(std::memory_order_relaxed);
    result.cancellation_lag_max_ns = cancellation_lag_max_ns_.load(std::memory_order_relaxed);
    result.tasks.queued = tasks_queued_.load(std::memory_order_relaxed);
    result.tasks.started = tasks_started_.load(std::memory_order_relaxed);
    result.tasks.completed = tasks_completed_.load(std::memory_order_relaxed);
    result.tasks.cancelled = tasks_cancelled_.load(std::memory_order_relaxed);
    result.tasks.failed = tasks_failed_.load(std::memory_order_relaxed);
    result.publication_state = publication_state_.load(std::memory_order_relaxed);
    result.query_latency_ns = query_latency_ns_.load(std::memory_order_relaxed);
    result.query_count = query_count_.load(std::memory_order_relaxed);
    result.query_latency_max_ns = query_latency_max_ns_.load(std::memory_order_relaxed);
    result.workspace_concurrency = workspace_concurrency_.load(std::memory_order_relaxed);
    result.sla_receipts_observed = sla_receipts_observed_.load(std::memory_order_relaxed);
    result.sla_receipts_valid = sla_receipts_valid_.load(std::memory_order_relaxed);
    result.sla_receipts_invalid = sla_receipts_invalid_.load(std::memory_order_relaxed);
    result.sla_receipt_validity = derive_sla_receipt_validity(result.sla_receipts_observed,
        result.sla_receipts_valid, result.sla_receipts_invalid);
    result.sample_sequence = mutation_sequence_.load(std::memory_order_relaxed);
    return result;
}

analysis_resource_metrics_snapshot_t analysis_resource_metrics_t::snapshot() const noexcept
{
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

}
