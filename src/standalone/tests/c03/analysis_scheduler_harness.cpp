#include "analysis_scheduler_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "../../src/core/analysis/analysis_scheduler.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <utility>

namespace aida::analysis::c03_test {
namespace {

void require(bool condition, const char* message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

class fake_clock_t final : public analysis_clock_t {
public:
    std::uint64_t now_milliseconds() const noexcept override { return now_milliseconds_; }

    void advance(std::uint64_t milliseconds) noexcept { now_milliseconds_ += milliseconds; }

private:
    std::uint64_t now_milliseconds_ = 0;
};

class strict_scheduler_model_t final {
public:
    explicit strict_scheduler_model_t(analysis_budget_t budget) : budget_(budget) {}

    void enqueue(analysis_execution_domain_t domain)
    {
        ++queued_[static_cast<std::size_t>(domain)];
    }

    std::optional<analysis_execution_domain_t> acquire()
    {
        for (std::size_t index = 0; index < analysis_execution_domain_count; ++index) {
            if (queued_[index] == 0)
                continue;
            const auto domain = static_cast<analysis_execution_domain_t>(index);
            if (active_workers_ >= budget_.max_worker_slots)
                return std::nullopt;
            if (domain != analysis_execution_domain_t::control &&
                active_non_control_workers_ >=
                    budget_.max_worker_slots - budget_.reserved_control_worker_slots) {
                return std::nullopt;
            }
            --queued_[index];
            ++active_workers_;
            if (domain == analysis_execution_domain_t::control)
                ++active_control_workers_;
            else
                ++active_non_control_workers_;
            return domain;
        }
        return std::nullopt;
    }

private:
    analysis_budget_t budget_;
    std::array<std::uint32_t, analysis_execution_domain_count> queued_{};
    std::uint32_t active_workers_ = 0;
    std::uint32_t active_control_workers_ = 0;
    std::uint32_t active_non_control_workers_ = 0;
};

analysis_scheduler_configuration_t scheduler_configuration(std::uint32_t scheduler_id,
                                                            std::uint32_t workers = 4,
                                                            std::uint32_t reserved_control = 1)
{
    analysis_scheduler_configuration_t configuration;
    configuration.scheduler_id = scheduler_id;
    configuration.max_retained_terminal_tasks = 32;
    configuration.budget.max_queued_tasks = 16;
    configuration.budget.max_worker_slots = workers;
    configuration.budget.reserved_control_worker_slots = reserved_control;
    configuration.budget.max_private_bytes = 256;
    configuration.budget.max_mapped_window_bytes = 256;
    configuration.budget.max_spill_bytes = 256;
    configuration.budget.max_cache_bytes = 256;
    configuration.budget.cancellation_checkpoint_milliseconds = 250;
    return configuration;
}

analysis_task_request_t task_request(analysis_execution_domain_t domain,
                                     analysis_resource_demand_t resources = {})
{
    analysis_task_request_t request;
    request.domain = domain;
    request.resources = resources;
    request.label = std::string(analysis_execution_domain_name(domain));
    request.body = [](const analysis_task_context_t&) {};
    return request;
}

void verify_deterministic_ids_and_priority_model()
{
    auto clock = std::make_shared<fake_clock_t>();
    const auto configuration = scheduler_configuration(0xC03B04U);
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "scheduler configuration was rejected");

    strict_scheduler_model_t model(configuration.budget);
    const auto background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    model.enqueue(analysis_execution_domain_t::background);
    const auto interactive = scheduler.submit(task_request(analysis_execution_domain_t::interactive));
    model.enqueue(analysis_execution_domain_t::interactive);
    require(background.accepted() && interactive.accepted(), "priority inputs were rejected");
    require(background.task_id == make_analysis_task_id(configuration.scheduler_id, 1),
            "first task ID was not deterministic");
    require(interactive.task_id == make_analysis_task_id(configuration.scheduler_id, 2),
            "second task ID was not deterministic");

    const auto expected_first = model.acquire();
    const auto first = scheduler.acquire_next();
    require(expected_first.has_value() && first.available(), "priority dispatch was unavailable");
    require(first.dispatch.domain() == *expected_first, "priority model and scheduler diverged");
    require(first.dispatch.domain() == analysis_execution_domain_t::interactive,
            "interactive task was not dispatched ahead of background work");
    const auto callable = first.dispatch.taskflow_callable();
    require(static_cast<bool>(callable), "Taskflow callable was not produced");
    callable();

    const auto expected_second = model.acquire();
    const auto second = scheduler.acquire_next();
    require(expected_second.has_value() && second.available(), "background dispatch was unavailable");
    require(second.dispatch.domain() == *expected_second, "background model and scheduler diverged");
    second.dispatch.taskflow_callable()();
    require(scheduler.verify_invariants().ok(), "priority scheduler invariants failed");
}

void verify_reserved_control_capacity()
{
    auto clock = std::make_shared<fake_clock_t>();
    const auto configuration = scheduler_configuration(0xC03B05U, 3, 1);
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "reserved scheduler configuration was rejected");

    const auto first_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    const auto second_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    const auto third_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    require(first_background.accepted() && second_background.accepted() && third_background.accepted(),
            "background tasks were rejected before capacity was reached");

    const auto first = scheduler.acquire_next();
    const auto second = scheduler.acquire_next();
    const auto blocked = scheduler.acquire_next();
    require(first.available() && second.available(), "non-control capacity was not dispatched");
    require(!blocked.available(), "reserved control capacity was borrowed by background work");
    require(blocked.error.code == analysis_scheduler_error_code_t::resource_rejected &&
                blocked.error.resource_error.code ==
                    analysis_resource_error_code_t::reserved_control_capacity_exhausted,
            "reserved control capacity returned the wrong error");

    const auto control = scheduler.submit(task_request(analysis_execution_domain_t::control));
    require(control.accepted(), "control task was rejected while reserved capacity was available");
    const auto control_dispatch = scheduler.acquire_next();
    require(control_dispatch.available() && control_dispatch.dispatch.domain() == analysis_execution_domain_t::control,
            "control task did not claim reserved capacity");

    first.dispatch.taskflow_callable()();
    second.dispatch.taskflow_callable()();
    control_dispatch.dispatch.taskflow_callable()();
    const auto remaining = scheduler.acquire_next();
    require(remaining.available() && remaining.dispatch.domain() == analysis_execution_domain_t::background,
            "blocked background task did not resume after capacity returned");
    remaining.dispatch.taskflow_callable()();
    require(scheduler.verify_invariants().ok(), "reserved capacity invariants failed");
}

void verify_non_control_capacity_is_physically_clamped()
{
    auto clock = std::make_shared<fake_clock_t>();
    const auto configuration = scheduler_configuration(0xC03B08U, 4, 1);
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "physical-capacity scheduler configuration was rejected");

    const auto first_control = scheduler.submit(task_request(analysis_execution_domain_t::control));
    const auto second_control = scheduler.submit(task_request(analysis_execution_domain_t::control));
    require(first_control.accepted() && second_control.accepted(),
            "control tasks were rejected before physical capacity was reached");
    const auto first_control_dispatch = scheduler.acquire_next();
    const auto second_control_dispatch = scheduler.acquire_next();
    require(first_control_dispatch.available() && second_control_dispatch.available(),
            "control tasks were not dispatched beyond the reserved minimum");

    auto snapshot = scheduler.snapshot();
    require(snapshot.budget.active_control_workers == 2 &&
                snapshot.budget.available_control_worker_slots == 2 &&
                snapshot.budget.available_non_control_worker_slots == 2,
            "non-control availability exceeded physical free capacity");

    const auto first_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    const auto second_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    const auto third_background = scheduler.submit(task_request(analysis_execution_domain_t::background));
    require(first_background.accepted() && second_background.accepted() && third_background.accepted(),
            "background tasks were rejected before queue capacity was reached");
    const auto first_background_dispatch = scheduler.acquire_next();
    const auto second_background_dispatch = scheduler.acquire_next();
    const auto blocked = scheduler.acquire_next();
    require(first_background_dispatch.available() && second_background_dispatch.available(),
            "physical non-control capacity was not dispatched");
    require(!blocked.available() &&
                blocked.error.resource_error.code ==
                    analysis_resource_error_code_t::worker_capacity_exhausted,
            "physical worker exhaustion returned the wrong result");
    snapshot = scheduler.snapshot();
    require(snapshot.budget.available_control_worker_slots == 0 &&
                snapshot.budget.available_non_control_worker_slots == 0,
            "worker availability remained nonzero at physical capacity");

    first_control_dispatch.dispatch.taskflow_callable()();
    second_control_dispatch.dispatch.taskflow_callable()();
    first_background_dispatch.dispatch.taskflow_callable()();
    second_background_dispatch.dispatch.taskflow_callable()();
    const auto remaining = scheduler.acquire_next();
    require(remaining.available(), "queued background work did not resume after physical capacity returned");
    remaining.dispatch.taskflow_callable()();
    require(scheduler.verify_invariants().ok(), "physical-capacity scheduler invariants failed");
}

void verify_resource_rejections()
{
    auto clock = std::make_shared<fake_clock_t>();
    auto configuration = scheduler_configuration(0xC03B06U);
    configuration.budget.max_queued_tasks = 2;
    configuration.budget.max_private_bytes = 64;
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "resource scheduler configuration was rejected");

    const auto first = scheduler.submit(task_request(analysis_execution_domain_t::background, {64, 0, 0, 0}));
    const auto second = scheduler.submit(task_request(analysis_execution_domain_t::background, {1, 0, 0, 0}));
    require(first.accepted(), "resource reservation at exact limit was rejected");
    require(!second.accepted(), "private memory limit was not enforced");
    require(second.error.code == analysis_scheduler_error_code_t::resource_rejected &&
                second.error.resource_error.code == analysis_resource_error_code_t::private_bytes_exhausted,
            "private memory rejection was not stable");

    const auto cancelled = scheduler.cancel_task(first.task_id);
    require(cancelled.error.ok() && cancelled.queued_cancelled == 1,
            "queued cancellation did not release resource reservation");
    const auto retry = scheduler.submit(task_request(analysis_execution_domain_t::background, {64, 0, 0, 0}));
    require(retry.accepted(), "resource reservation was not released after queued cancellation");
    require(scheduler.verify_invariants().ok(), "resource scheduler invariants failed");
}

void verify_cancellation_checkpoints_with_fake_clock()
{
    auto clock = std::make_shared<fake_clock_t>();
    const auto configuration = scheduler_configuration(0xC03B07U, 1, 1);
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "checkpoint scheduler configuration was rejected");

    bool interval_exceeded = false;
    bool cancellation_observed = false;
    analysis_task_request_t request = task_request(analysis_execution_domain_t::control);
    request.body = [&scheduler, &clock, &interval_exceeded, &cancellation_observed](const analysis_task_context_t& context) {
        clock->advance(251);
        const auto late = context.checkpoint();
        interval_exceeded = late.interval_exceeded &&
                            late.error.code == analysis_scheduler_error_code_t::checkpoint_interval_exceeded;
        const auto cancellation = scheduler.cancel_task(context.task_id());
        cancellation_observed = cancellation.error.ok() && cancellation.active_signalled == 1 &&
                                 context.checkpoint().cancellation_requested;
    };
    const auto submitted = scheduler.submit(std::move(request));
    require(submitted.accepted(), "checkpoint task was rejected");
    const auto dispatch = scheduler.acquire_next();
    require(dispatch.available(), "checkpoint task was not dispatched");
    dispatch.dispatch.taskflow_callable()();
    require(interval_exceeded, "fake clock did not expose checkpoint deadline breach");
    require(cancellation_observed, "cancellation checkpoint did not observe active cancellation");
    const auto task = scheduler.task_snapshot(submitted.task_id);
    require(task.found() && task.task.state == analysis_task_state_t::cancelled,
            "cancelled task did not reach terminal cancelled state");
    require(scheduler.snapshot().budget.active_workers == 0, "cancelled task retained worker capacity");
    require(scheduler.verify_invariants().ok(), "checkpoint scheduler invariants failed");
}

void verify_terminal_history_retention_and_pruning()
{
    auto clock = std::make_shared<fake_clock_t>();
    auto configuration = scheduler_configuration(0xC03B09U, 2, 1);
    configuration.max_retained_terminal_tasks = 2;
    analysis_scheduler_t scheduler(configuration, clock);
    require(scheduler.configuration_error().ok(), "retention scheduler configuration was rejected");

    const auto completed = scheduler.submit(task_request(analysis_execution_domain_t::foreground));
    require(completed.accepted(), "completed retention task was rejected");
    const auto completed_dispatch = scheduler.acquire_next();
    require(completed_dispatch.available(), "completed retention task was not dispatched");
    completed_dispatch.dispatch.taskflow_callable()();

    const auto cancelled = scheduler.submit(task_request(analysis_execution_domain_t::background));
    require(cancelled.accepted(), "cancelled retention task was rejected");
    const auto cancellation = scheduler.cancel_task(cancelled.task_id);
    require(cancellation.error.ok() && cancellation.queued_cancelled == 1,
            "queued retention task was not cancelled");

    auto failed_request = task_request(analysis_execution_domain_t::interactive);
    failed_request.body = [](const analysis_task_context_t&) {
        throw std::runtime_error("expected retention failure");
    };
    const auto failed = scheduler.submit(std::move(failed_request));
    require(failed.accepted(), "failed retention task was rejected");
    const auto failed_dispatch = scheduler.acquire_next();
    require(failed_dispatch.available(), "failed retention task was not dispatched");
    bool failure_observed = false;
    try {
        failed_dispatch.dispatch.taskflow_callable()();
    } catch (const std::runtime_error&) {
        failure_observed = true;
    }
    require(failure_observed, "failed retention task did not propagate its failure");

    const auto snapshot = scheduler.snapshot();
    require(snapshot.retained_terminal_tasks == 2 && snapshot.budget.queued_tasks == 0 &&
                snapshot.budget.active_workers == 0,
            "terminal history did not retain the configured bounded tail");
    const auto pruned = scheduler.task_snapshot(completed.task_id);
    require(!pruned.found() && pruned.error.code == analysis_scheduler_error_code_t::task_not_found,
            "oldest terminal task was not pruned");
    const auto retained_cancelled = scheduler.task_snapshot(cancelled.task_id);
    const auto retained_failed = scheduler.task_snapshot(failed.task_id);
    require(retained_cancelled.found() &&
                retained_cancelled.task.state == analysis_task_state_t::cancelled,
            "cancelled terminal task was not retained");
    require(retained_failed.found() && retained_failed.task.state == analysis_task_state_t::failed,
            "failed terminal task was not retained");
    require(scheduler.verify_invariants().ok(), "terminal retention invariants failed");
}

void verify_scheduler_metrics_consumer_path()
{
    auto clock = std::make_shared<fake_clock_t>();
    auto metrics = std::make_shared<analysis_resource_metrics_t>(73);
    const auto configuration = scheduler_configuration(0xC03B0AU, 2, 1);
    analysis_scheduler_t scheduler(configuration, clock, metrics);
    require(scheduler.configuration_error().ok(), "telemetry scheduler configuration was rejected");

    const auto completed = scheduler.submit(task_request(analysis_execution_domain_t::foreground));
    require(completed.accepted(), "telemetry completion task was rejected");
    const auto completed_dispatch = scheduler.acquire_next();
    require(completed_dispatch.available(), "telemetry completion task was not dispatched");
    completed_dispatch.dispatch.taskflow_callable()();

    const auto queued_cancelled = scheduler.submit(task_request(analysis_execution_domain_t::background));
    require(queued_cancelled.accepted(), "telemetry queued-cancellation task was rejected");
    const auto queued_cancellation = scheduler.cancel_task(queued_cancelled.task_id);
    require(queued_cancellation.error.ok() && queued_cancellation.queued_cancelled == 1,
            "telemetry queued-cancellation task was not cancelled");

    auto active_cancelled_request = task_request(analysis_execution_domain_t::interactive);
    active_cancelled_request.body = [&scheduler, &clock](const analysis_task_context_t& context) {
        clock->advance(4);
        const auto cancellation = scheduler.cancel_task(context.task_id());
        if (!cancellation.error.ok() || cancellation.active_signalled != 1)
            throw std::runtime_error("active telemetry cancellation failed");
        clock->advance(6);
    };
    const auto active_cancelled = scheduler.submit(std::move(active_cancelled_request));
    require(active_cancelled.accepted(), "telemetry active-cancellation task was rejected");
    const auto active_cancelled_dispatch = scheduler.acquire_next();
    require(active_cancelled_dispatch.available(), "telemetry active-cancellation task was not dispatched");
    active_cancelled_dispatch.dispatch.taskflow_callable()();

    auto failed_request = task_request(analysis_execution_domain_t::maintenance);
    failed_request.body = [](const analysis_task_context_t&) {
        throw std::runtime_error("expected telemetry failure");
    };
    const auto failed = scheduler.submit(std::move(failed_request));
    require(failed.accepted(), "telemetry failure task was rejected");
    const auto failed_dispatch = scheduler.acquire_next();
    require(failed_dispatch.available(), "telemetry failure task was not dispatched");
    bool failure_observed = false;
    try {
        failed_dispatch.dispatch.taskflow_callable()();
    } catch (const std::runtime_error&) {
        failure_observed = true;
    }
    require(failure_observed, "telemetry failure task did not propagate its failure");

    const auto scheduler_metrics = scheduler.metrics_snapshot();
    const auto injected_metrics = metrics->snapshot();
    require(scheduler_metrics.generation == 73 &&
                scheduler_metrics.sample_sequence == injected_metrics.sample_sequence,
            "scheduler telemetry did not use the injected production collector");
    require(scheduler_metrics.tasks.queued == 4 && scheduler_metrics.tasks.started == 3 &&
                scheduler_metrics.tasks.completed == 1 && scheduler_metrics.tasks.cancelled == 2 &&
                scheduler_metrics.tasks.failed == 1,
            "scheduler lifecycle telemetry counts changed");
    require(scheduler_metrics.cancellation_count == 1 &&
                scheduler_metrics.cancellation_lag_ns == 6000000 &&
                scheduler_metrics.cancellation_lag_max_ns == 6000000,
            "scheduler active-cancellation telemetry changed");
    require(scheduler.verify_invariants().ok(), "telemetry scheduler invariants failed");
}

}

bool run_analysis_scheduler_harness(std::string& failure)
{
    try {
        verify_deterministic_ids_and_priority_model();
        verify_reserved_control_capacity();
        verify_non_control_capacity_is_physically_clamped();
        verify_resource_rejections();
        verify_cancellation_checkpoints_with_fake_clock();
        verify_terminal_history_retention_and_pruning();
        verify_scheduler_metrics_consumer_path();
        failure.clear();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    if (!aida::analysis::c03_test::run_analysis_scheduler_harness(failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    std::cout << "analysis_scheduler_harness source contract satisfied\n";
    return 0;
}
