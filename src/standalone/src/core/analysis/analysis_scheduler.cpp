#include "analysis_scheduler.hpp"

#include "../infra/taskflow_runtime.hpp"
#include "../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <utility>

namespace aida::analysis {

namespace rt = aida::infra::taskflow_runtime;

namespace {

struct analysis_task_record_t final {
    analysis_task_id_t task_id = 0;
    analysis_execution_domain_t domain = analysis_execution_domain_t::background;
    analysis_priority_t priority = analysis_priority_t::background;
    analysis_task_state_t state = analysis_task_state_t::queued;
    analysis_resource_demand_t resources;
    std::string label;
    analysis_task_body_t body;
    std::shared_ptr<std::atomic<bool>> cancellation_requested;
    std::uint64_t submitted_milliseconds = 0;
    std::uint64_t dispatched_milliseconds = 0;
    std::uint64_t started_milliseconds = 0;
    std::uint64_t last_checkpoint_milliseconds = 0;
    std::uint64_t cancellation_requested_milliseconds = 0;
    std::uint64_t completed_milliseconds = 0;
};

constexpr std::size_t domain_index(analysis_execution_domain_t domain) noexcept
{
    return static_cast<std::size_t>(domain);
}

bool active_state(analysis_task_state_t state) noexcept
{
    return state == analysis_task_state_t::dispatched || state == analysis_task_state_t::running;
}

bool terminal_state(analysis_task_state_t state) noexcept
{
    return state == analysis_task_state_t::completed || state == analysis_task_state_t::cancelled ||
           state == analysis_task_state_t::failed;
}

std::uint64_t milliseconds_to_nanoseconds(std::uint64_t milliseconds) noexcept
{
    constexpr std::uint64_t nanoseconds_per_millisecond = 1000000;
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    return milliseconds > maximum / nanoseconds_per_millisecond
               ? maximum
               : milliseconds * nanoseconds_per_millisecond;
}

analysis_scheduler_error_t make_scheduler_error(analysis_scheduler_error_code_t code,
                                                analysis_task_id_t task_id = 0,
                                                analysis_resource_error_t resource_error = {}) noexcept
{
    return {code, analysis_scheduler_error_code_name(code), task_id, resource_error};
}

analysis_scheduler_error_t resource_scheduler_error(analysis_task_id_t task_id,
                                                    analysis_resource_error_t resource_error) noexcept
{
    return make_scheduler_error(analysis_scheduler_error_code_t::resource_rejected, task_id, resource_error);
}

}

struct analysis_scheduler_state_t final {
    analysis_scheduler_state_t(analysis_scheduler_configuration_t input_configuration,
                               std::shared_ptr<analysis_clock_t> input_clock,
                               std::shared_ptr<analysis_resource_metrics_t> input_metrics)
        : configuration(std::move(input_configuration)),
          clock(std::move(input_clock)),
          ledger(configuration.budget),
          policy(analysis_priority_reservation_policy(configuration.budget)),
          metrics(input_metrics ? std::move(input_metrics)
                                : std::make_shared<analysis_resource_metrics_t>())
    {
        if (!clock) {
            configuration_error = make_scheduler_error(analysis_scheduler_error_code_t::invalid_clock);
        } else if (configuration.scheduler_id == 0 || configuration.max_retained_terminal_tasks == 0) {
            configuration_error = make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration);
        } else {
            const auto budget_error = validate_analysis_budget(configuration.budget);
            if (!budget_error.ok()) {
                configuration_error = make_scheduler_error(
                    analysis_scheduler_error_code_t::invalid_scheduler_configuration, 0, budget_error);
            }
        }
    }

    analysis_scheduler_configuration_t configuration;
    std::shared_ptr<analysis_clock_t> clock;
    analysis_budget_ledger_t ledger;
    analysis_priority_reservation_policy_t policy;
    std::shared_ptr<analysis_resource_metrics_t> metrics;
    analysis_scheduler_error_t configuration_error;
    mutable std::mutex mutex;
    bool accepting = true;
    std::uint32_t next_ordinal = 1;
    std::array<std::deque<analysis_task_id_t>, analysis_execution_domain_count> queues;
    std::map<analysis_task_id_t, analysis_task_record_t> tasks;
    std::deque<analysis_task_id_t> terminal_history;
    std::condition_variable dispatcher_cv;
    std::uint64_t dispatcher_epoch = 0;
    std::atomic<bool> dispatcher_started{false};
    std::atomic<bool> dispatcher_active{false};
    std::atomic<bool> dispatcher_stop{false};
    rt::job_handle_t dispatcher_job;
};

struct analysis_task_context_state_t final {
    std::shared_ptr<analysis_scheduler_state_t> scheduler;
    analysis_task_id_t task_id = 0;
    std::shared_ptr<std::atomic<bool>> cancellation_requested;
};

struct analysis_task_dispatch_state_t final {
    std::shared_ptr<analysis_scheduler_state_t> scheduler;
    analysis_task_id_t task_id = 0;
    analysis_execution_domain_t domain = analysis_execution_domain_t::background;
    analysis_priority_t priority = analysis_priority_t::background;
    analysis_task_body_t body;
    analysis_task_context_t context;
    std::atomic<bool> revoked{false};
    std::atomic<bool> invoked{false};
};

namespace {

std::uint64_t scheduler_now(const analysis_scheduler_state_t& state) noexcept
{
    return state.clock ? state.clock->now_milliseconds() : 0;
}

void note_dispatcher_event_locked(analysis_scheduler_state_t& state) noexcept
{
    ++state.dispatcher_epoch;
    state.dispatcher_cv.notify_all();
}

rt::executor_domain_t fabric_domain_for(analysis_execution_domain_t domain) noexcept
{
    switch (domain) {
    case analysis_execution_domain_t::control:
        return rt::executor_domain_t::critical;
    case analysis_execution_domain_t::interactive:
        return rt::executor_domain_t::external_tool;
    case analysis_execution_domain_t::foreground:
        return rt::executor_domain_t::general;
    case analysis_execution_domain_t::background:
        return rt::executor_domain_t::feature_worker;
    case analysis_execution_domain_t::maintenance:
        return rt::executor_domain_t::diagnostics;
    }
    return rt::executor_domain_t::general;
}

int fabric_priority_for(analysis_execution_domain_t domain) noexcept
{
    switch (domain) {
    case analysis_execution_domain_t::control:
        return 0;
    case analysis_execution_domain_t::interactive:
        return 1;
    case analysis_execution_domain_t::foreground:
        return 3;
    case analysis_execution_domain_t::background:
        return 5;
    case analysis_execution_domain_t::maintenance:
        return 7;
    }
    return 3;
}

bool request_active_cancellation_locked(analysis_scheduler_state_t& state,
                                        analysis_task_record_t& task) noexcept
{
    if (task.cancellation_requested->exchange(true, std::memory_order_acq_rel))
        return false;
    task.cancellation_requested_milliseconds = scheduler_now(state);
    return true;
}

void record_terminal_metrics(analysis_scheduler_state_t& state,
                             const analysis_task_record_t& task,
                             analysis_task_completion_t completion) noexcept
{
    if (!state.metrics)
        return;

    analysis_task_counts_t counts;
    switch (completion) {
    case analysis_task_completion_t::completed:
        counts.completed = 1;
        break;
    case analysis_task_completion_t::cancelled:
        counts.cancelled = 1;
        break;
    case analysis_task_completion_t::failed:
        counts.failed = 1;
        break;
    }
    state.metrics->record_task_counts(counts);

    if (completion == analysis_task_completion_t::cancelled &&
        task.cancellation_requested->load(std::memory_order_acquire) &&
        task.completed_milliseconds >= task.cancellation_requested_milliseconds) {
        state.metrics->record_cancellation_lag(milliseconds_to_nanoseconds(
            task.completed_milliseconds - task.cancellation_requested_milliseconds));
    }
}

void remove_from_queue_locked(analysis_scheduler_state_t& state, const analysis_task_record_t& task)
{
    auto& queue = state.queues[domain_index(task.domain)];
    const auto position = std::find(queue.begin(), queue.end(), task.task_id);
    if (position != queue.end())
        queue.erase(position);
}

void prune_terminal_history_locked(analysis_scheduler_state_t& state)
{
    while (state.terminal_history.size() > state.configuration.max_retained_terminal_tasks) {
        const auto task_id = state.terminal_history.front();
        state.terminal_history.pop_front();
        const auto task = state.tasks.find(task_id);
        if (task != state.tasks.end() && terminal_state(task->second.state))
            state.tasks.erase(task);
    }
}

analysis_scheduler_error_t finish_active_locked(analysis_scheduler_state_t& state,
                                                analysis_task_record_t& task,
                                                analysis_task_completion_t completion)
{
    if (!active_state(task.state))
        return make_scheduler_error(analysis_scheduler_error_code_t::task_not_active, task.task_id);

    const auto resource_error = state.ledger.release_active(task.task_id);
    if (!resource_error.ok())
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task.task_id,
                                    resource_error);

    switch (completion) {
    case analysis_task_completion_t::completed:
        task.state = analysis_task_state_t::completed;
        break;
    case analysis_task_completion_t::cancelled:
        task.state = analysis_task_state_t::cancelled;
        break;
    case analysis_task_completion_t::failed:
        task.state = analysis_task_state_t::failed;
        break;
    }
    task.completed_milliseconds = scheduler_now(state);
    record_terminal_metrics(state, task, completion);
    state.terminal_history.push_back(task.task_id);
    prune_terminal_history_locked(state);
    note_dispatcher_event_locked(state);
    return {};
}

analysis_scheduler_error_t finish_queued_locked(analysis_scheduler_state_t& state,
                                                analysis_task_record_t& task)
{
    if (task.state != analysis_task_state_t::queued)
        return make_scheduler_error(analysis_scheduler_error_code_t::task_not_queued, task.task_id);

    const auto resource_error = state.ledger.release_queued(task.task_id);
    if (!resource_error.ok())
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task.task_id,
                                    resource_error);

    remove_from_queue_locked(state, task);
    task.state = analysis_task_state_t::cancelled;
    task.completed_milliseconds = scheduler_now(state);
    record_terminal_metrics(state, task, analysis_task_completion_t::cancelled);
    state.terminal_history.push_back(task.task_id);
    prune_terminal_history_locked(state);
    return {};
}

analysis_scheduler_error_t cancel_task_locked(analysis_scheduler_state_t& state,
                                              analysis_task_id_t task_id,
                                              analysis_cancellation_result_t& result)
{
    const auto task = state.tasks.find(task_id);
    if (task == state.tasks.end())
        return make_scheduler_error(analysis_scheduler_error_code_t::task_not_found, task_id);
    if (terminal_state(task->second.state))
        return make_scheduler_error(analysis_scheduler_error_code_t::task_terminal, task_id);
    if (task->second.state == analysis_task_state_t::queued) {
        const auto error = finish_queued_locked(state, task->second);
        if (error.ok())
            ++result.queued_cancelled;
        return error;
    }

    if (request_active_cancellation_locked(state, task->second))
        ++result.active_signalled;
    return {};
}

analysis_checkpoint_result_t checkpoint_task(const std::shared_ptr<analysis_scheduler_state_t>& state,
                                             analysis_task_id_t task_id) noexcept
{
    if (!state)
        return {false, false, make_scheduler_error(analysis_scheduler_error_code_t::task_not_active, task_id)};

    std::lock_guard<std::mutex> lock(state->mutex);
    const auto task = state->tasks.find(task_id);
    if (task == state->tasks.end()) {
        return {false, false,
                make_scheduler_error(analysis_scheduler_error_code_t::task_not_found, task_id)};
    }
    if (task->second.state != analysis_task_state_t::running) {
        return {task->second.cancellation_requested->load(std::memory_order_acquire), false,
                make_scheduler_error(analysis_scheduler_error_code_t::task_not_active, task_id)};
    }

    const auto now = scheduler_now(*state);
    if (now < task->second.last_checkpoint_milliseconds) {
        return {task->second.cancellation_requested->load(std::memory_order_acquire), false,
                make_scheduler_error(analysis_scheduler_error_code_t::clock_regressed, task_id)};
    }

    const auto elapsed = now - task->second.last_checkpoint_milliseconds;
    const auto interval_exceeded = elapsed > state->configuration.budget.cancellation_checkpoint_milliseconds;
    task->second.last_checkpoint_milliseconds = now;
    const auto error = interval_exceeded
                           ? make_scheduler_error(analysis_scheduler_error_code_t::checkpoint_interval_exceeded,
                                                  task_id)
                           : analysis_scheduler_error_t{};
    return {task->second.cancellation_requested->load(std::memory_order_acquire), interval_exceeded, error};
}

void execute_dispatch(const std::shared_ptr<analysis_task_dispatch_state_t>& dispatch) noexcept(false)
{
    if (!dispatch || dispatch->revoked.load(std::memory_order_acquire))
        return;
    if (dispatch->invoked.exchange(true, std::memory_order_acq_rel))
        return;

    const auto state = dispatch->scheduler;
    if (!state)
        return;

    {
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto task = state->tasks.find(dispatch->task_id);
        if (dispatch->revoked.load(std::memory_order_acquire) || task == state->tasks.end() ||
            task->second.state != analysis_task_state_t::dispatched) {
            return;
        }
        if (task->second.cancellation_requested->load(std::memory_order_acquire)) {
            finish_active_locked(*state, task->second, analysis_task_completion_t::cancelled);
            return;
        }
        task->second.state = analysis_task_state_t::running;
        task->second.started_milliseconds = scheduler_now(*state);
        task->second.last_checkpoint_milliseconds = task->second.started_milliseconds;
        if (state->metrics)
            state->metrics->record_task_counts(analysis_task_counts_t{0, 1, 0, 0, 0});
    }

    try {
        dispatch->body(dispatch->context);
    } catch (...) {
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto task = state->tasks.find(dispatch->task_id);
        if (task != state->tasks.end() && active_state(task->second.state))
            finish_active_locked(*state, task->second, analysis_task_completion_t::failed);
        throw;
    }

    std::lock_guard<std::mutex> lock(state->mutex);
    const auto task = state->tasks.find(dispatch->task_id);
    if (task == state->tasks.end() || !active_state(task->second.state))
        return;
    const auto completion = task->second.cancellation_requested->load(std::memory_order_acquire)
                                ? analysis_task_completion_t::cancelled
                                : analysis_task_completion_t::completed;
    finish_active_locked(*state, task->second, completion);
}

analysis_task_snapshot_t make_task_snapshot(const analysis_task_record_t& task)
{
    return {task.task_id,
            task.domain,
            task.priority,
            task.state,
            task.cancellation_requested->load(std::memory_order_acquire),
            task.submitted_milliseconds,
            task.dispatched_milliseconds,
            task.started_milliseconds,
            task.last_checkpoint_milliseconds,
            task.completed_milliseconds,
            task.resources,
            task.label};
}

}

std::string_view analysis_execution_domain_name(analysis_execution_domain_t domain) noexcept
{
    switch (domain) {
    case analysis_execution_domain_t::control:
        return "control";
    case analysis_execution_domain_t::interactive:
        return "interactive";
    case analysis_execution_domain_t::foreground:
        return "foreground";
    case analysis_execution_domain_t::background:
        return "background";
    case analysis_execution_domain_t::maintenance:
        return "maintenance";
    }
    return "invalid_domain";
}

std::string_view analysis_task_state_name(analysis_task_state_t state) noexcept
{
    switch (state) {
    case analysis_task_state_t::queued:
        return "queued";
    case analysis_task_state_t::dispatched:
        return "dispatched";
    case analysis_task_state_t::running:
        return "running";
    case analysis_task_state_t::completed:
        return "completed";
    case analysis_task_state_t::cancelled:
        return "cancelled";
    case analysis_task_state_t::failed:
        return "failed";
    }
    return "invalid_task_state";
}

std::string_view analysis_scheduler_error_code_name(analysis_scheduler_error_code_t code) noexcept
{
    switch (code) {
    case analysis_scheduler_error_code_t::none:
        return "ok";
    case analysis_scheduler_error_code_t::invalid_scheduler_configuration:
        return "invalid_scheduler_configuration";
    case analysis_scheduler_error_code_t::invalid_clock:
        return "invalid_clock";
    case analysis_scheduler_error_code_t::invalid_domain:
        return "invalid_domain";
    case analysis_scheduler_error_code_t::missing_task_body:
        return "missing_task_body";
    case analysis_scheduler_error_code_t::task_label_too_long:
        return "task_label_too_long";
    case analysis_scheduler_error_code_t::scheduler_stopped:
        return "scheduler_stopped";
    case analysis_scheduler_error_code_t::task_id_exhausted:
        return "task_id_exhausted";
    case analysis_scheduler_error_code_t::resource_rejected:
        return "resource_rejected";
    case analysis_scheduler_error_code_t::task_not_found:
        return "task_not_found";
    case analysis_scheduler_error_code_t::task_not_queued:
        return "task_not_queued";
    case analysis_scheduler_error_code_t::task_not_active:
        return "task_not_active";
    case analysis_scheduler_error_code_t::task_terminal:
        return "task_terminal";
    case analysis_scheduler_error_code_t::dispatch_not_owned:
        return "dispatch_not_owned";
    case analysis_scheduler_error_code_t::checkpoint_interval_exceeded:
        return "checkpoint_interval_exceeded";
    case analysis_scheduler_error_code_t::clock_regressed:
        return "clock_regressed";
    case analysis_scheduler_error_code_t::priority_policy_violation:
        return "priority_policy_violation";
    case analysis_scheduler_error_code_t::internal_invariant_violation:
        return "internal_invariant_violation";
    }
    return "unknown_scheduler_error";
}

bool is_valid_analysis_execution_domain(analysis_execution_domain_t domain) noexcept
{
    return static_cast<std::uint8_t>(domain) < analysis_execution_domain_count;
}

analysis_priority_t analysis_priority_for_domain(analysis_execution_domain_t domain) noexcept
{
    return static_cast<analysis_priority_t>(static_cast<std::uint8_t>(domain));
}

analysis_priority_reservation_policy_t analysis_priority_reservation_policy(const analysis_budget_t& budget) noexcept
{
    return {true, true, true, false, budget.reserved_control_worker_slots};
}

analysis_task_id_t make_analysis_task_id(std::uint32_t scheduler_id, std::uint32_t ordinal) noexcept
{
    return (static_cast<analysis_task_id_t>(scheduler_id) << 32U) | ordinal;
}

analysis_task_context_t::analysis_task_context_t(std::shared_ptr<analysis_task_context_state_t> state)
    : state_(std::move(state))
{
}

analysis_task_id_t analysis_task_context_t::task_id() const noexcept
{
    return state_ ? state_->task_id : 0;
}

bool analysis_task_context_t::cancellation_requested() const noexcept
{
    return state_ && state_->cancellation_requested &&
           state_->cancellation_requested->load(std::memory_order_acquire);
}

analysis_checkpoint_result_t analysis_task_context_t::checkpoint() const noexcept
{
    if (!state_) {
        return {false, false,
                make_scheduler_error(analysis_scheduler_error_code_t::task_not_active)};
    }
    return checkpoint_task(state_->scheduler, state_->task_id);
}

bool analysis_task_context_t::valid() const noexcept
{
    return state_ && state_->scheduler && state_->task_id != 0 && state_->cancellation_requested;
}

analysis_task_dispatch_t::analysis_task_dispatch_t(std::shared_ptr<analysis_task_dispatch_state_t> state)
    : state_(std::move(state))
{
}

analysis_task_id_t analysis_task_dispatch_t::task_id() const noexcept
{
    return state_ ? state_->task_id : 0;
}

analysis_execution_domain_t analysis_task_dispatch_t::domain() const noexcept
{
    return state_ ? state_->domain : analysis_execution_domain_t::background;
}

analysis_priority_t analysis_task_dispatch_t::priority() const noexcept
{
    return state_ ? state_->priority : analysis_priority_t::background;
}

bool analysis_task_dispatch_t::valid() const noexcept
{
    return state_ && state_->scheduler && state_->task_id != 0 && !state_->revoked.load(std::memory_order_acquire);
}

std::function<void()> analysis_task_dispatch_t::taskflow_callable() const
{
    if (!state_)
        return {};
    return [state = state_]() { execute_dispatch(state); };
}

bool analysis_dispatch_result_t::available() const noexcept
{
    return dispatch.valid() && error.ok();
}

analysis_scheduler_t::analysis_scheduler_t(analysis_scheduler_configuration_t configuration,
                                           std::shared_ptr<analysis_clock_t> clock,
                                           std::shared_ptr<analysis_resource_metrics_t> metrics)
    : state_(std::make_shared<analysis_scheduler_state_t>(
          std::move(configuration), std::move(clock), std::move(metrics)))
{
}

analysis_scheduler_t::~analysis_scheduler_t()
{
    try {
        shutdown();
    } catch (...) {
    }
}

analysis_scheduler_error_t analysis_scheduler_t::configuration_error() const noexcept
{
    return state_ ? state_->configuration_error
                  : make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration);
}

analysis_submit_result_t analysis_scheduler_t::submit(analysis_task_request_t request)
{
    if (!state_)
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration)};
    if (!state_->configuration_error.ok())
        return {0, state_->configuration_error};
    if (!is_valid_analysis_execution_domain(request.domain))
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::invalid_domain)};
    if (!request.body)
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::missing_task_body)};
    if (request.label.size() > max_analysis_task_label_bytes)
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::task_label_too_long)};

    std::lock_guard<std::mutex> lock(state_->mutex);
    if (!state_->accepting)
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::scheduler_stopped)};
    if (state_->next_ordinal == 0) {
        return {0, make_scheduler_error(analysis_scheduler_error_code_t::task_id_exhausted)};
    }

    const auto task_id = make_analysis_task_id(state_->configuration.scheduler_id, state_->next_ordinal);
    analysis_task_record_t task;
    task.task_id = task_id;
    task.domain = request.domain;
    task.priority = analysis_priority_for_domain(request.domain);
    task.resources = request.resources;
    task.label = std::move(request.label);
    task.body = std::move(request.body);
    task.cancellation_requested = std::make_shared<std::atomic<bool>>(false);
    task.submitted_milliseconds = scheduler_now(*state_);

    const auto resource_error = state_->ledger.reserve(task_id, request.resources);
    if (!resource_error.ok())
        return {0, resource_scheduler_error(task_id, resource_error)};

    try {
        const auto inserted = state_->tasks.emplace(task_id, std::move(task));
        if (!inserted.second) {
            const auto release_error = state_->ledger.release_queued(task_id);
            return {0, make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation,
                                            task_id, release_error)};
        }
        try {
            state_->queues[domain_index(request.domain)].push_back(task_id);
        } catch (...) {
            state_->tasks.erase(inserted.first);
            throw;
        }
    } catch (...) {
        state_->ledger.release_queued(task_id);
        throw;
    }
    ++state_->next_ordinal;
    note_dispatcher_event_locked(*state_);
    if (state_->metrics)
        state_->metrics->record_task_counts(analysis_task_counts_t{1, 0, 0, 0, 0});
    return {task_id, {}};
}

analysis_dispatch_result_t analysis_scheduler_t::acquire_next()
{
    return acquire_next_from_state(state_);
}

analysis_dispatch_result_t analysis_scheduler_t::acquire_next_from_state(
    const std::shared_ptr<analysis_scheduler_state_t>& state)
{
    if (!state) {
        return {{}, make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration)};
    }
    if (!state->configuration_error.ok())
        return {{}, state->configuration_error};

    std::lock_guard<std::mutex> lock(state->mutex);
    for (std::size_t index = 0; index < analysis_execution_domain_count; ++index) {
        auto& queue = state->queues[index];
        if (queue.empty())
            continue;

        const auto task_id = queue.front();
        const auto task = state->tasks.find(task_id);
        if (task == state->tasks.end() || task->second.state != analysis_task_state_t::queued) {
            return {{}, make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task_id)};
        }

        auto context_state = std::make_shared<analysis_task_context_state_t>();
        context_state->scheduler = state;
        context_state->task_id = task_id;
        context_state->cancellation_requested = task->second.cancellation_requested;

        auto dispatch_state = std::make_shared<analysis_task_dispatch_state_t>();
        dispatch_state->scheduler = state;
        dispatch_state->task_id = task_id;
        dispatch_state->domain = task->second.domain;
        dispatch_state->priority = task->second.priority;
        dispatch_state->body = task->second.body;
        dispatch_state->context = analysis_task_context_t(std::move(context_state));

        const auto resource_error = state->ledger.activate(
            task_id, task->second.domain == analysis_execution_domain_t::control);
        if (!resource_error.ok())
            return {{}, resource_scheduler_error(task_id, resource_error)};

        queue.pop_front();
        task->second.state = analysis_task_state_t::dispatched;
        task->second.dispatched_milliseconds = scheduler_now(*state);
        task->second.last_checkpoint_milliseconds = task->second.dispatched_milliseconds;
        return {analysis_task_dispatch_t(std::move(dispatch_state)), {}};
    }
    return {};
}

bool analysis_scheduler_t::dispatch_to_fabric(const std::shared_ptr<analysis_scheduler_state_t>& state,
                                              const analysis_task_dispatch_t& dispatch) noexcept
{
    if (!state || !dispatch.valid())
        return false;
    std::string label;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        const auto task = state->tasks.find(dispatch.task_id());
        if (task != state->tasks.end())
            label = task->second.label;
    }
    try {
        rt::task_descriptor_t desc;
        desc.domain = fabric_domain_for(dispatch.domain());
        desc.priority = fabric_priority_for(dispatch.domain());
        desc.owner_subsystem = "analysis_scheduler";
        desc.label = label.empty() ? "analysis.scheduler.task" : label.c_str();
        desc.shutdown_policy = "cancel_pending";
        desc.body = dispatch.taskflow_callable();
        const auto result = rt::submit(std::move(desc));
        if (!result.submitted) {
            const auto domain_text = analysis_execution_domain_name(dispatch.domain());
            diag::log_tagged_fmt("analysis_scheduler",
                "analysis_scheduler_dispatch_submit_failed task_id=%llu reason=%s domain=%.*s tid=%lu",
                static_cast<unsigned long long>(dispatch.task_id()),
                result.reject_reason.c_str(),
                static_cast<int>(domain_text.size()),
                domain_text.data(),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
        return result.submitted;
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("analysis_scheduler",
            "analysis_scheduler_dispatch_submit_exception task_id=%llu err=%s tid=%lu",
            static_cast<unsigned long long>(dispatch.task_id()),
            ex.what(),
            static_cast<unsigned long>(GetCurrentThreadId()));
    } catch (...) {
        diag::log_tagged_fmt("analysis_scheduler",
            "analysis_scheduler_dispatch_submit_exception task_id=%llu err=unknown tid=%lu",
            static_cast<unsigned long long>(dispatch.task_id()),
            static_cast<unsigned long>(GetCurrentThreadId()));
    }
    return false;
}

void analysis_scheduler_t::dispatcher_loop(const std::shared_ptr<analysis_scheduler_state_t>& state,
                                           const rt::cancellation_token_t& token) noexcept
{
    if (!state)
        return;
    struct active_guard_t {
        std::atomic<bool>& flag;
        explicit active_guard_t(std::atomic<bool>& value) : flag(value) {
            flag.store(true, std::memory_order_release);
        }
        ~active_guard_t() { flag.store(false, std::memory_order_release); }
    } active_guard{state->dispatcher_active};
    for (;;) {
        if (token.requested.load(std::memory_order_acquire) ||
            state->dispatcher_stop.load(std::memory_order_acquire))
            return;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!state->accepting)
                return;
        }
        analysis_dispatch_result_t acquired;
        try {
            acquired = acquire_next_from_state(state);
        } catch (...) {
            acquired = {{}, make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation)};
        }
        if (acquired.available()) {
            if (!dispatch_to_fabric(state, acquired.dispatch)) {
                std::lock_guard<std::mutex> lock(state->mutex);
                acquired.dispatch.state_->revoked.store(true, std::memory_order_release);
                const auto task = state->tasks.find(acquired.dispatch.task_id());
                if (task != state->tasks.end() && task->second.state == analysis_task_state_t::dispatched) {
                    finish_active_locked(*state, task->second, analysis_task_completion_t::cancelled);
                }
            }
            continue;
        }
        if (!acquired.error.ok() &&
            acquired.error.code != analysis_scheduler_error_code_t::resource_rejected) {
            diag::log_tagged_fmt("analysis_scheduler",
                "analysis_scheduler_dispatcher_halted code=%u stable=%.*s tid=%lu",
                static_cast<unsigned>(acquired.error.code),
                static_cast<int>(acquired.error.stable_code.size()),
                acquired.error.stable_code.data(),
                static_cast<unsigned long>(GetCurrentThreadId()));
            return;
        }
        std::unique_lock<std::mutex> lock(state->mutex);
        const auto seen_epoch = state->dispatcher_epoch;
        state->dispatcher_cv.wait_for(lock, std::chrono::milliseconds(25), [&] {
            return !state->accepting ||
                   state->dispatcher_stop.load(std::memory_order_acquire) ||
                   state->dispatcher_epoch != seen_epoch;
        });
    }
}

analysis_scheduler_error_t analysis_scheduler_t::run_dispatcher()
{
    if (!state_)
        return make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration);
    if (!state_->configuration_error.ok())
        return state_->configuration_error;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting)
            return make_scheduler_error(analysis_scheduler_error_code_t::scheduler_stopped);
    }
    bool expected = false;
    if (!state_->dispatcher_started.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel, std::memory_order_acquire))
        return {};
    state_->dispatcher_stop.store(false, std::memory_order_release);
    rt::task_descriptor_t desc;
    desc.domain = rt::executor_domain_t::critical;
    desc.priority = 0;
    desc.owner_subsystem = "analysis_scheduler";
    desc.label = "analysis.scheduler.dispatcher";
    desc.shutdown_policy = "cancel_pending";
    desc.cancellable_body = [state = state_](const rt::cancellation_token_t& token) {
        dispatcher_loop(state, token);
    };
    const auto result = rt::submit(std::move(desc));
    if (!result.submitted) {
        state_->dispatcher_started.store(false, std::memory_order_release);
        diag::log_tagged_fmt("analysis_scheduler",
            "analysis_scheduler_dispatcher_rejected reason=%s tid=%lu",
            result.reject_reason.c_str(),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation);
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->dispatcher_job = result.handle;
    }
    diag::log_tagged_fmt("analysis_scheduler",
        "analysis_scheduler_dispatcher_started job_id=%llu tid=%lu",
        static_cast<unsigned long long>(result.handle.id),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return {};
}

bool analysis_scheduler_t::dispatcher_running() const noexcept
{
    return state_ && state_->dispatcher_active.load(std::memory_order_acquire);
}

analysis_scheduler_error_t analysis_scheduler_t::requeue(const analysis_task_dispatch_t& dispatch)
{
    if (!state_ || !dispatch.state_ || dispatch.state_->scheduler.get() != state_.get()) {
        return make_scheduler_error(analysis_scheduler_error_code_t::dispatch_not_owned, dispatch.task_id());
    }
    if (!state_->configuration_error.ok())
        return state_->configuration_error;

    std::lock_guard<std::mutex> lock(state_->mutex);
    if (dispatch.state_->invoked.load(std::memory_order_acquire)) {
        return make_scheduler_error(analysis_scheduler_error_code_t::task_not_active, dispatch.task_id());
    }
    const auto task = state_->tasks.find(dispatch.task_id());
    if (task == state_->tasks.end())
        return make_scheduler_error(analysis_scheduler_error_code_t::task_not_found, dispatch.task_id());
    if (task->second.state != analysis_task_state_t::dispatched) {
        return make_scheduler_error(terminal_state(task->second.state) ? analysis_scheduler_error_code_t::task_terminal
                                                                        : analysis_scheduler_error_code_t::task_not_active,
                                    dispatch.task_id());
    }
    if (task->second.cancellation_requested->load(std::memory_order_acquire)) {
        dispatch.state_->revoked.store(true, std::memory_order_release);
        return finish_active_locked(*state_, task->second, analysis_task_completion_t::cancelled);
    }

    auto& queue = state_->queues[domain_index(task->second.domain)];
    queue.push_front(task->second.task_id);
    dispatch.state_->revoked.store(true, std::memory_order_release);
    const auto resource_error = state_->ledger.requeue(dispatch.task_id());
    if (!resource_error.ok()) {
        dispatch.state_->revoked.store(false, std::memory_order_release);
        queue.pop_front();
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, dispatch.task_id(),
                                    resource_error);
    }
    task->second.state = analysis_task_state_t::queued;
    task->second.dispatched_milliseconds = 0;
    task->second.last_checkpoint_milliseconds = 0;
    note_dispatcher_event_locked(*state_);
    return {};
}

analysis_cancellation_result_t analysis_scheduler_t::cancel_task(analysis_task_id_t task_id)
{
    analysis_cancellation_result_t result;
    if (!state_) {
        result.error = make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration, task_id);
        return result;
    }
    if (!state_->configuration_error.ok()) {
        result.error = state_->configuration_error;
        return result;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    result.error = cancel_task_locked(*state_, task_id, result);
    return result;
}

analysis_cancellation_result_t analysis_scheduler_t::cancel_domain(analysis_execution_domain_t domain)
{
    analysis_cancellation_result_t result;
    if (!state_) {
        result.error = make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration);
        return result;
    }
    if (!state_->configuration_error.ok()) {
        result.error = state_->configuration_error;
        return result;
    }
    if (!is_valid_analysis_execution_domain(domain)) {
        result.error = make_scheduler_error(analysis_scheduler_error_code_t::invalid_domain);
        return result;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    auto& queue = state_->queues[domain_index(domain)];
    while (!queue.empty()) {
        const auto task_id = queue.front();
        const auto error = cancel_task_locked(*state_, task_id, result);
        if (!error.ok()) {
            result.error = error;
            return result;
        }
    }
    for (auto& entry : state_->tasks) {
        auto& task = entry.second;
        if (task.domain == domain && active_state(task.state) &&
            request_active_cancellation_locked(*state_, task)) {
            ++result.active_signalled;
        }
    }
    return result;
}

analysis_cancellation_result_t analysis_scheduler_t::shutdown()
{
    analysis_cancellation_result_t result;
    if (!state_)
        return result;

    state_->dispatcher_stop.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->accepting = false;
        for (auto& queue : state_->queues) {
            while (!queue.empty()) {
                const auto task_id = queue.front();
                const auto error = cancel_task_locked(*state_, task_id, result);
                if (!error.ok()) {
                    result.error = error;
                    return result;
                }
            }
        }
        for (auto& entry : state_->tasks) {
            auto& task = entry.second;
            if (active_state(task.state) && request_active_cancellation_locked(*state_, task)) {
                ++result.active_signalled;
            }
        }
        note_dispatcher_event_locked(*state_);
    }
    if (state_->dispatcher_started.load(std::memory_order_acquire) &&
        state_->dispatcher_job.valid()) {
        rt::cancel(state_->dispatcher_job);
        const auto waited = rt::wait_for(state_->dispatcher_job, 1000);
        if (waited.timed_out) {
            diag::log_tagged_fmt("analysis_scheduler",
                "analysis_scheduler_dispatcher_stop_timeout job_id=%llu tid=%lu",
                static_cast<unsigned long long>(state_->dispatcher_job.id),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    }
    return result;
}

void analysis_scheduler_t::stop_accepting() noexcept
{
    if (!state_)
        return;
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->accepting = false;
    note_dispatcher_event_locked(*state_);
}

analysis_task_snapshot_result_t analysis_scheduler_t::task_snapshot(analysis_task_id_t task_id) const
{
    if (!state_) {
        return {{}, make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration, task_id)};
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto task = state_->tasks.find(task_id);
    if (task == state_->tasks.end())
        return {{}, make_scheduler_error(analysis_scheduler_error_code_t::task_not_found, task_id)};
    return {make_task_snapshot(task->second), {}};
}

analysis_scheduler_snapshot_t analysis_scheduler_t::snapshot() const
{
    if (!state_)
        return {};

    std::lock_guard<std::mutex> lock(state_->mutex);
    analysis_scheduler_snapshot_t snapshot;
    snapshot.accepting = state_->accepting && state_->configuration_error.ok();
    snapshot.policy = state_->policy;
    snapshot.budget = state_->ledger.snapshot();
    snapshot.retained_terminal_tasks = static_cast<std::uint32_t>(state_->terminal_history.size());
    snapshot.next_task_ordinal = state_->next_ordinal;
    const auto now = scheduler_now(*state_);
    for (const auto& entry : state_->tasks) {
        const auto& task = entry.second;
        if (task.state == analysis_task_state_t::queued)
            ++snapshot.queued_per_domain[domain_index(task.domain)];
        if (active_state(task.state)) {
            ++snapshot.active_per_domain[domain_index(task.domain)];
            if (now >= task.last_checkpoint_milliseconds &&
                now - task.last_checkpoint_milliseconds >
                    state_->configuration.budget.cancellation_checkpoint_milliseconds) {
                ++snapshot.overdue_checkpoint_count;
            }
        }
    }
    return snapshot;
}

analysis_resource_metrics_snapshot_t analysis_scheduler_t::metrics_snapshot() const noexcept
{
    return state_ && state_->metrics ? state_->metrics->snapshot()
                                     : analysis_resource_metrics_snapshot_t{};
}

std::vector<analysis_task_id_t> analysis_scheduler_t::overdue_checkpoint_tasks() const
{
    std::vector<analysis_task_id_t> task_ids;
    if (!state_)
        return task_ids;

    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto now = scheduler_now(*state_);
    for (const auto& entry : state_->tasks) {
        const auto& task = entry.second;
        if (active_state(task.state) && now >= task.last_checkpoint_milliseconds &&
            now - task.last_checkpoint_milliseconds >
                state_->configuration.budget.cancellation_checkpoint_milliseconds) {
            task_ids.push_back(task.task_id);
        }
    }
    return task_ids;
}

analysis_scheduler_error_t analysis_scheduler_t::verify_invariants() const
{
    if (!state_)
        return make_scheduler_error(analysis_scheduler_error_code_t::invalid_scheduler_configuration);
    if (!state_->configuration_error.ok())
        return state_->configuration_error;

    std::lock_guard<std::mutex> lock(state_->mutex);
    if (state_->terminal_history.size() > state_->configuration.max_retained_terminal_tasks)
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation);

    std::map<analysis_task_id_t, std::uint32_t> terminal_occurrences;
    for (const auto task_id : state_->terminal_history) {
        const auto task = state_->tasks.find(task_id);
        if (task == state_->tasks.end() || !terminal_state(task->second.state) ||
            ++terminal_occurrences[task_id] != 1) {
            return make_scheduler_error(
                analysis_scheduler_error_code_t::internal_invariant_violation, task_id);
        }
    }

    std::map<analysis_task_id_t, std::uint32_t> queue_occurrences;
    std::uint32_t queued_count = 0;
    for (std::size_t index = 0; index < analysis_execution_domain_count; ++index) {
        for (const auto task_id : state_->queues[index]) {
            const auto task = state_->tasks.find(task_id);
            if (task == state_->tasks.end() || task->second.state != analysis_task_state_t::queued ||
                domain_index(task->second.domain) != index || ++queue_occurrences[task_id] != 1) {
                return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task_id);
            }
            ++queued_count;
        }
    }

    std::uint32_t active_count = 0;
    std::uint32_t control_active_count = 0;
    std::uint32_t non_control_active_count = 0;
    for (const auto& entry : state_->tasks) {
        const auto& task = entry.second;
        if (task.state == analysis_task_state_t::queued && queue_occurrences[task.task_id] != 1) {
            return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task.task_id);
        }
        if (terminal_state(task.state) && terminal_occurrences[task.task_id] != 1) {
            return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation, task.task_id);
        }
        if (active_state(task.state)) {
            ++active_count;
            if (task.domain == analysis_execution_domain_t::control)
                ++control_active_count;
            else
                ++non_control_active_count;
        }
    }

    const auto budget = state_->ledger.snapshot();
    if (budget.queued_tasks != queued_count || budget.active_workers != active_count ||
        budget.active_control_workers != control_active_count ||
        budget.active_non_control_workers != non_control_active_count) {
        return make_scheduler_error(analysis_scheduler_error_code_t::internal_invariant_violation);
    }
    const auto non_control_limit = state_->configuration.budget.max_worker_slots -
                                   state_->configuration.budget.reserved_control_worker_slots;
    if (!state_->policy.no_priority_inversion || !state_->policy.control_capacity_reserved ||
        state_->policy.control_capacity_borrowing || non_control_active_count > non_control_limit) {
        return make_scheduler_error(analysis_scheduler_error_code_t::priority_policy_violation);
    }
    return {};
}

}
