#include "metrics_contract_harness.hpp"

#include "../../src/core/analysis/analysis_resource_metrics.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <locale>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {

using namespace aida::analysis;
using json = nlohmann::json;

struct metric_contract_t final {
    analysis_resource_metric_t metric;
    std::string_view name;
    analysis_metric_aggregation_t aggregation;
};

constexpr std::array<analysis_resource_phase_t, 8> expected_phases{{
    analysis_resource_phase_t::acquisition,
    analysis_resource_phase_t::mapping,
    analysis_resource_phase_t::reading,
    analysis_resource_phase_t::analysis,
    analysis_resource_phase_t::indexing,
    analysis_resource_phase_t::persistence,
    analysis_resource_phase_t::query,
    analysis_resource_phase_t::publication,
}};

constexpr std::array<std::string_view, expected_phases.size()> expected_phase_names{{
    "acquisition",
    "mapping",
    "reading",
    "analysis",
    "indexing",
    "persistence",
    "query",
    "publication",
}};

constexpr std::array<metric_contract_t, 19> expected_metrics{{
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

constexpr std::array<analysis_metric_aggregation_t, 4> expected_aggregations{{
    analysis_metric_aggregation_t::sum,
    analysis_metric_aggregation_t::maximum,
    analysis_metric_aggregation_t::state,
    analysis_metric_aggregation_t::derived,
}};

constexpr std::array<analysis_publication_state_t, 6> expected_publication_states{{
    analysis_publication_state_t::not_started,
    analysis_publication_state_t::collecting,
    analysis_publication_state_t::ready,
    analysis_publication_state_t::published,
    analysis_publication_state_t::cancelled,
    analysis_publication_state_t::failed,
}};

constexpr std::array<std::string_view, expected_publication_states.size()>
    expected_publication_state_names{{
        "not_started",
        "collecting",
        "ready",
        "published",
        "cancelled",
        "failed",
    }};

constexpr std::array<analysis_sla_receipt_validity_t, 4> expected_sla_validities{{
    analysis_sla_receipt_validity_t::not_observed,
    analysis_sla_receipt_validity_t::valid,
    analysis_sla_receipt_validity_t::invalid,
    analysis_sla_receipt_validity_t::mixed,
}};

constexpr std::array<std::string_view, expected_sla_validities.size()>
    expected_sla_validity_names{{
        "not_observed",
        "valid",
        "invalid",
        "mixed",
    }};

template <typename enum_t, std::size_t size>
constexpr bool has_contiguous_ordinals(const std::array<enum_t, size>& values) noexcept
{
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (static_cast<std::size_t>(values[index]) != index)
            return false;
    }
    return true;
}

constexpr std::array<analysis_resource_metric_t, expected_metrics.size()> expected_metric_ordinals()
{
    std::array<analysis_resource_metric_t, expected_metrics.size()> values{};
    for (std::size_t index = 0; index < expected_metrics.size(); ++index)
        values[index] = expected_metrics[index].metric;
    return values;
}

static_assert(analysis_resource_metrics_schema_version == 1,
    "resource metrics schema version changed");
static_assert(analysis_resource_phase_count == expected_phases.size(),
    "resource metrics phase count changed");
static_assert(analysis_resource_metric_count == expected_metrics.size(),
    "resource metrics field count changed");
static_assert(static_cast<std::size_t>(analysis_publication_state_t::count) ==
        expected_publication_states.size(),
    "publication state count changed");
static_assert(has_contiguous_ordinals(expected_phases),
    "resource metrics phase ordinals changed");
static_assert(has_contiguous_ordinals(expected_metric_ordinals()),
    "resource metrics field ordinals changed");
static_assert(has_contiguous_ordinals(expected_aggregations),
    "resource metrics aggregation ordinals changed");
static_assert(has_contiguous_ordinals(expected_publication_states),
    "publication state ordinals changed");
static_assert(has_contiguous_ordinals(expected_sla_validities),
    "SLA receipt validity ordinals changed");

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

void require_exact_keys(const json& value,
    std::initializer_list<std::string_view> expected_keys,
    std::string_view path)
{
    require(value.is_object(), std::string(path) + " was not an object");
    require(value.size() == expected_keys.size(),
        std::string(path) + " key count changed");
    for (const auto key : expected_keys) {
        require(value.contains(std::string(key)),
            std::string(path) + " is missing key " + std::string(key));
    }
}

void require_unsigned_value(const json& value, std::uint64_t expected,
    std::string_view path)
{
    require(value.is_number_unsigned(),
        std::string(path) + " was not an unsigned JSON integer");
    require(value.get<std::uint64_t>() == expected,
        std::string(path) + " value changed");
}

void verify_schema_descriptors()
{
    for (std::size_t index = 0; index < expected_phases.size(); ++index) {
        require(std::string_view(analysis_resource_phase_name(expected_phases[index])) ==
                expected_phase_names[index],
            "resource phase name or order changed");
    }
    require(std::string_view(analysis_resource_phase_name(analysis_resource_phase_t::count)) ==
            "unknown",
        "out-of-range resource phase name was accepted");

    for (const auto& expected : expected_metrics) {
        const auto* descriptor = analysis_resource_metric_descriptor(expected.metric);
        require(descriptor != nullptr, "stable metrics descriptor is unavailable");
        require(descriptor->metric == expected.metric,
            "metrics descriptor ordinal identity changed");
        require(descriptor->name == expected.name,
            "metrics descriptor name changed");
        require(descriptor->aggregation == expected.aggregation,
            "metrics descriptor aggregation changed");
    }
    require(analysis_resource_metric_descriptor(analysis_resource_metric_t::count) == nullptr,
        "out-of-range metrics descriptor was accepted");

    for (std::size_t index = 0; index < expected_publication_states.size(); ++index) {
        require(std::string_view(analysis_publication_state_name(expected_publication_states[index])) ==
                expected_publication_state_names[index],
            "publication state name or order changed");
    }
    require(std::string_view(analysis_publication_state_name(analysis_publication_state_t::count)) ==
            "unknown",
        "out-of-range publication state name was accepted");

    for (std::size_t index = 0; index < expected_sla_validities.size(); ++index) {
        require(std::string_view(analysis_sla_receipt_validity_name(expected_sla_validities[index])) ==
                expected_sla_validity_names[index],
            "SLA receipt validity name or order changed");
    }
    require(std::string_view(analysis_sla_receipt_validity_name(
                static_cast<analysis_sla_receipt_validity_t>(expected_sla_validities.size()))) ==
            "unknown",
        "out-of-range SLA receipt validity name was accepted");
}

void verify_serialized_snapshot(const analysis_resource_metrics_snapshot_t& snapshot)
{
    const auto encoded = snapshot.to_json();
    const auto root = json::parse(encoded, nullptr, false);
    require(!root.is_discarded(), "resource metrics JSON was not parseable");
    require_exact_keys(root,
        {"schema", "schema_version", "generation", "sample_sequence",
            "publication_state", "sla_receipt_validity", "phases", "metrics",
            "cancellation", "query", "sla_receipts"},
        "root");
    require(root.at("schema").is_string() &&
            root.at("schema").get<std::string>() == "aida.analysis.resource-metrics",
        "resource metrics schema identity changed");
    require_unsigned_value(root.at("schema_version"), snapshot.schema_version,
        "schema_version");
    require_unsigned_value(root.at("generation"), snapshot.generation, "generation");
    require_unsigned_value(root.at("sample_sequence"), snapshot.sample_sequence,
        "sample_sequence");
    require(root.at("publication_state").is_string() &&
            root.at("publication_state").get<std::string>() ==
                analysis_publication_state_name(snapshot.publication_state),
        "top-level publication state type or value changed");
    require(root.at("sla_receipt_validity").is_string() &&
            root.at("sla_receipt_validity").get<std::string>() ==
                analysis_sla_receipt_validity_name(snapshot.sla_receipt_validity),
        "top-level SLA receipt validity type or value changed");

    const auto& phases = root.at("phases");
    require(phases.is_array() && phases.size() == expected_phases.size(),
        "serialized phase array shape changed");
    for (std::size_t index = 0; index < expected_phases.size(); ++index) {
        const auto& phase = phases.at(index);
        require_exact_keys(phase, {"name", "wall_ns", "cpu_ns", "queue_wait_ns"},
            "phase");
        require(phase.at("name").is_string() &&
                phase.at("name").get<std::string>() == std::string(expected_phase_names[index]),
            "serialized phase name or order changed");
        require_unsigned_value(phase.at("wall_ns"), snapshot.phases[index].wall_ns,
            "phase.wall_ns");
        require_unsigned_value(phase.at("cpu_ns"), snapshot.phases[index].cpu_ns,
            "phase.cpu_ns");
        require_unsigned_value(phase.at("queue_wait_ns"),
            snapshot.phases[index].queue_wait_ns, "phase.queue_wait_ns");
    }

    const auto& metrics = root.at("metrics");
    require(metrics.is_object() && metrics.size() == expected_metrics.size(),
        "serialized metrics object shape changed");
    for (const auto& expected : expected_metrics) {
        const auto key = std::string(expected.name);
        require(metrics.contains(key), "serialized metric field is missing");
        const auto& value = metrics.at(key);
        if (expected.metric == analysis_resource_metric_t::publication_state) {
            require(value.is_string() && value.get<std::string>() ==
                    analysis_publication_state_name(snapshot.publication_state),
                "serialized publication state metric type or value changed");
        } else if (expected.metric == analysis_resource_metric_t::sla_receipt_validity) {
            require(value.is_string() && value.get<std::string>() ==
                    analysis_sla_receipt_validity_name(snapshot.sla_receipt_validity),
                "serialized SLA receipt validity metric type or value changed");
        } else {
            require_unsigned_value(value, snapshot.value(expected.metric), expected.name);
        }
    }

    const auto& cancellation = root.at("cancellation");
    require_exact_keys(cancellation, {"count", "max_lag_ns"}, "cancellation");
    require_unsigned_value(cancellation.at("count"), snapshot.cancellation_count,
        "cancellation.count");
    require_unsigned_value(cancellation.at("max_lag_ns"),
        snapshot.cancellation_lag_max_ns, "cancellation.max_lag_ns");

    const auto& query = root.at("query");
    require_exact_keys(query, {"count", "max_latency_ns"}, "query");
    require_unsigned_value(query.at("count"), snapshot.query_count, "query.count");
    require_unsigned_value(query.at("max_latency_ns"), snapshot.query_latency_max_ns,
        "query.max_latency_ns");

    const auto& sla_receipts = root.at("sla_receipts");
    require_exact_keys(sla_receipts, {"observed", "valid", "invalid"},
        "sla_receipts");
    require_unsigned_value(sla_receipts.at("observed"), snapshot.sla_receipts_observed,
        "sla_receipts.observed");
    require_unsigned_value(sla_receipts.at("valid"), snapshot.sla_receipts_valid,
        "sla_receipts.valid");
    require_unsigned_value(sla_receipts.at("invalid"), snapshot.sla_receipts_invalid,
        "sla_receipts.invalid");

    for (const std::string_view forbidden :
        {"receipt_id", "receipt_sha256", "license", "token", "secret"}) {
        require(encoded.find(forbidden) == std::string::npos,
            "telemetry serialization exposed sensitive receipt material");
    }
}

void verify_metrics_accumulation()
{
    analysis_resource_metrics_t metrics{7};
    require(metrics.record_phase_timing(analysis_resource_phase_t::acquisition, 11, 5, 3),
        "acquisition timing was rejected");
    require(metrics.record_phase_timing(analysis_resource_phase_t::analysis, 17, 7, 5),
        "analysis timing was rejected");
    require(!metrics.record_phase_timing(analysis_resource_phase_t::count, 1, 1, 1),
        "out-of-range phase timing was accepted");

    metrics.add_mapped_bytes(31);
    metrics.add_read_bytes(47);
    metrics.add_spilled_bytes(13);
    metrics.observe_memory_estimates(101, 211);
    metrics.observe_memory_estimates(151, 199);
    metrics.record_cache_hits(2);
    metrics.record_cache_hits(3);
    metrics.record_cancellation_lag(11);
    metrics.record_cancellation_lag(17);
    metrics.record_task_counts(analysis_task_counts_t{7, 5, 3, 1, 1});
    metrics.record_task_counts(analysis_task_counts_t{2, 3, 4, 1, 0});
    metrics.record_query_latency(5);
    metrics.record_query_latency(17);
    metrics.observe_workspace_concurrency(3);
    metrics.observe_workspace_concurrency(2);
    metrics.record_sla_receipt_validity(true);

    require(metrics.set_publication_state(analysis_publication_state_t::collecting),
        "publication collection transition was rejected");
    require(metrics.set_publication_state(analysis_publication_state_t::ready),
        "publication ready transition was rejected");
    require(metrics.set_publication_state(analysis_publication_state_t::published),
        "publication transition was rejected");
    require(!metrics.set_publication_state(analysis_publication_state_t::ready),
        "publication state regression was accepted");

    auto snapshot = metrics.snapshot();
    require(snapshot.schema_version == analysis_resource_metrics_schema_version &&
            snapshot.generation == 7 && snapshot.sample_sequence == 21,
        "snapshot schema identity or mutation sequence changed");
    require(snapshot.phases[static_cast<std::size_t>(analysis_resource_phase_t::acquisition)].wall_ns == 11 &&
            snapshot.phases[static_cast<std::size_t>(analysis_resource_phase_t::analysis)].cpu_ns == 7,
        "per-phase timing was not retained");
    require(snapshot.phase_wall_ns == 28 && snapshot.phase_cpu_ns == 12 &&
            snapshot.phase_queue_wait_ns == 8,
        "phase timing aggregate changed");
    require(snapshot.mapped_bytes == 31 && snapshot.read_bytes == 47 &&
            snapshot.spilled_bytes == 13,
        "byte telemetry changed");
    require(snapshot.private_bytes_estimate == 151 &&
            snapshot.resident_bytes_estimate == 211,
        "memory estimate peak aggregation changed");
    require(snapshot.cache_hits == 5, "cache-hit aggregation changed");
    require(snapshot.cancellation_count == 2 && snapshot.cancellation_lag_ns == 28 &&
            snapshot.cancellation_lag_max_ns == 17,
        "cancellation-lag aggregation changed");
    require(snapshot.tasks.queued == 9 && snapshot.tasks.started == 8 &&
            snapshot.tasks.completed == 7 && snapshot.tasks.cancelled == 2 &&
            snapshot.tasks.failed == 1,
        "task-count aggregation changed");
    require(snapshot.query_count == 2 && snapshot.query_latency_ns == 22 &&
            snapshot.query_latency_max_ns == 17,
        "query-latency aggregation changed");
    require(snapshot.workspace_concurrency == 3,
        "workspace concurrency peak aggregation changed");
    require(snapshot.publication_state == analysis_publication_state_t::published,
        "publication state was not retained");
    require(snapshot.sla_receipt_validity == analysis_sla_receipt_validity_t::valid &&
            snapshot.sla_receipts_observed == 1 && snapshot.sla_receipts_valid == 1 &&
            snapshot.sla_receipts_invalid == 0,
        "SLA receipt validity aggregation changed");

    constexpr std::array<std::uint64_t, expected_metrics.size()> expected_values{{
        28, 12, 8, 31, 47, 13, 151, 211, 5, 28, 9, 8, 7, 2, 1,
        static_cast<std::uint64_t>(analysis_publication_state_t::published),
        22, 3, static_cast<std::uint64_t>(analysis_sla_receipt_validity_t::valid),
    }};
    for (std::size_t index = 0; index < expected_metrics.size(); ++index) {
        require(snapshot.value(expected_metrics[index].metric) == expected_values[index],
            "metric value projection changed");
    }
    require(snapshot.value(analysis_resource_metric_t::count) == 0,
        "out-of-range metric value projection changed");

    metrics.record_sla_receipt_validity(false);
    snapshot = metrics.snapshot();
    require(snapshot.sample_sequence == 22 &&
            snapshot.sla_receipt_validity == analysis_sla_receipt_validity_t::mixed &&
            snapshot.sla_receipts_observed == 2 && snapshot.sla_receipts_valid == 1 &&
            snapshot.sla_receipts_invalid == 1,
        "mixed SLA receipt validity was not represented");
    verify_serialized_snapshot(snapshot);

    metrics.reset(8);
    snapshot = metrics.snapshot();
    require(snapshot.generation == 8 && snapshot.sample_sequence == 0 &&
            snapshot.phase_wall_ns == 0 && snapshot.phase_cpu_ns == 0 &&
            snapshot.phase_queue_wait_ns == 0 && snapshot.mapped_bytes == 0 &&
            snapshot.read_bytes == 0 && snapshot.spilled_bytes == 0 &&
            snapshot.private_bytes_estimate == 0 && snapshot.resident_bytes_estimate == 0 &&
            snapshot.cache_hits == 0 && snapshot.cancellation_lag_ns == 0 &&
            snapshot.cancellation_count == 0 && snapshot.cancellation_lag_max_ns == 0 &&
            snapshot.tasks.queued == 0 && snapshot.tasks.started == 0 &&
            snapshot.tasks.completed == 0 && snapshot.tasks.cancelled == 0 &&
            snapshot.tasks.failed == 0 && snapshot.query_latency_ns == 0 &&
            snapshot.query_count == 0 && snapshot.query_latency_max_ns == 0 &&
            snapshot.workspace_concurrency == 0 && snapshot.sla_receipts_observed == 0 &&
            snapshot.sla_receipts_valid == 0 && snapshot.sla_receipts_invalid == 0 &&
            snapshot.publication_state == analysis_publication_state_t::not_started &&
            snapshot.sla_receipt_validity == analysis_sla_receipt_validity_t::not_observed,
        "metrics reset did not restore the full schema baseline");
    for (const auto& phase : snapshot.phases) {
        require(phase.wall_ns == 0 && phase.cpu_ns == 0 && phase.queue_wait_ns == 0,
            "metrics reset retained per-phase telemetry");
    }
    verify_serialized_snapshot(snapshot);
}

void verify_publication_transitions()
{
    constexpr std::array<std::array<bool, expected_publication_states.size()>,
        expected_publication_states.size()> expected{{
        {{true, true, false, false, true, true}},
        {{false, true, true, false, true, true}},
        {{false, false, true, true, true, true}},
        {{false, false, false, true, false, false}},
        {{false, false, false, false, true, false}},
        {{false, false, false, false, false, true}},
    }};
    for (std::size_t current = 0; current < expected_publication_states.size(); ++current) {
        for (std::size_t next = 0; next < expected_publication_states.size(); ++next) {
            require(publication_state_transition_allowed(expected_publication_states[current],
                        expected_publication_states[next]) == expected[current][next],
                "publication transition matrix changed");
        }
    }
    require(!publication_state_transition_allowed(analysis_publication_state_t::count,
                 analysis_publication_state_t::collecting),
        "out-of-range current publication state was accepted");
    require(!publication_state_transition_allowed(analysis_publication_state_t::collecting,
                 analysis_publication_state_t::count),
        "out-of-range next publication state was accepted");
}

class grouped_numpunct_t final : public std::numpunct<char> {
protected:
    char do_thousands_sep() const override { return '_'; }
    std::string do_grouping() const override { return "\3"; }
};

class global_locale_guard_t final {
public:
    explicit global_locale_guard_t(std::locale replacement)
        : previous_(std::locale())
    {
        std::locale::global(std::move(replacement));
    }

    ~global_locale_guard_t()
    {
        std::locale::global(previous_);
    }

    global_locale_guard_t(const global_locale_guard_t&) = delete;
    global_locale_guard_t& operator=(const global_locale_guard_t&) = delete;

private:
    std::locale previous_;
};

void verify_locale_invariant_json()
{
    analysis_resource_metrics_t metrics{1234567};
    metrics.record_phase_timing(analysis_resource_phase_t::acquisition,
        123456789, 87654321, 7654321);
    metrics.add_mapped_bytes((std::numeric_limits<std::uint64_t>::max)());
    metrics.record_task_counts(analysis_task_counts_t{123456789, 23456789, 3456789, 456789, 56789});
    metrics.record_sla_receipt_validity(true);
    metrics.record_sla_receipt_validity(false);
    require(metrics.set_publication_state(analysis_publication_state_t::collecting),
        "locale fixture publication transition was rejected");
    const auto snapshot = metrics.snapshot();

    global_locale_guard_t locale_guard(
        std::locale(std::locale::classic(), new grouped_numpunct_t));
    const auto encoded = snapshot.to_json();
    require(encoded.find('_') == std::string::npos,
        "resource metrics JSON inherited grouped numeric punctuation");
    verify_serialized_snapshot(snapshot);
}

void verify_snapshot_reset_coherence()
{
    analysis_resource_metrics_t metrics{1};
    std::atomic<bool> start{false};
    std::atomic<bool> done{false};
    std::atomic<bool> coherent{true};
    constexpr std::uint64_t generation_count = 2048;

    std::thread writer([&]() {
        while (!start.load(std::memory_order_acquire))
            std::this_thread::yield();
        for (std::uint64_t generation = 1; generation <= generation_count; ++generation) {
            metrics.reset(generation);
            if ((generation & 7U) == 0)
                std::this_thread::yield();
            metrics.record_task_counts(
                analysis_task_counts_t{generation, generation, generation, generation, generation});
        }
        done.store(true, std::memory_order_release);
    });

    start.store(true, std::memory_order_release);
    do {
        const auto snapshot = metrics.snapshot();
        const auto values_match = snapshot.tasks.queued == snapshot.tasks.started &&
            snapshot.tasks.queued == snapshot.tasks.completed &&
            snapshot.tasks.queued == snapshot.tasks.cancelled &&
            snapshot.tasks.queued == snapshot.tasks.failed;
        const auto reset_baseline = snapshot.sample_sequence == 0 &&
            snapshot.tasks.queued == 0;
        const auto populated_generation = snapshot.sample_sequence == 1 &&
            snapshot.tasks.queued == snapshot.generation;
        if (!values_match || (!reset_baseline && !populated_generation)) {
            coherent.store(false, std::memory_order_release);
            break;
        }
    } while (!done.load(std::memory_order_acquire));

    writer.join();
    require(coherent.load(std::memory_order_acquire),
        "snapshot crossed a reset generation or partial metrics mutation");
    const auto final_snapshot = metrics.snapshot();
    require(final_snapshot.generation == generation_count &&
            final_snapshot.sample_sequence == 1 &&
            final_snapshot.tasks.queued == generation_count &&
            final_snapshot.tasks.started == generation_count &&
            final_snapshot.tasks.completed == generation_count &&
            final_snapshot.tasks.cancelled == generation_count &&
            final_snapshot.tasks.failed == generation_count,
        "final coherent metrics generation changed");
}

}

namespace aida::analysis::c03 {

int run_metrics_contract_harness()
{
    try {
        verify_schema_descriptors();
        verify_metrics_accumulation();
        verify_publication_transitions();
        verify_locale_invariant_json();
        verify_snapshot_reset_coherence();
        std::cout << "metrics contract harness passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "metrics contract harness failed: " << error.what() << '\n';
        return 1;
    }
}

}

int main()
{
    return aida::analysis::c03::run_metrics_contract_harness();
}
