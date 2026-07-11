#include "persistence_queue.hpp"

#include "../../infra/taskflow_runtime.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

workspace_error_t queue_error(workspace_error_code_t code, std::string message,
                              const char* phase) {
    return make_workspace_error(code, std::move(message), phase);
}

std::shared_future<workspace_result_t<void>> ready_failure(workspace_error_t error) {
    std::promise<workspace_result_t<void>> promise;
    auto future = promise.get_future().share();
    promise.set_value(workspace_result_t<void>::failure(std::move(error)));
    return future;
}

}

struct persistence_queue_t::state_t {
    struct queued_operation_t {
        std::uint64_t sequence = 0;
        std::string label;
        persistence_operation_t operation;
        cancellation_token_t cancel;
        std::promise<workspace_result_t<void>> promise;
    };

    binary_id_t workspace_id;
    std::string workspace_id_hex;
    persistence_queue_limits_t limits;
    mutable std::mutex mutex;
    std::condition_variable idle_cv;
    std::deque<std::shared_ptr<queued_operation_t>> pending;
    std::vector<std::shared_ptr<queued_operation_t>> active_batch;
    std::shared_ptr<aida::infra::taskflow_runtime::cancellation_token_t> active_drain_cancel;
    aida::infra::taskflow_runtime::job_handle_t active_drain_handle;
    bool accepting = true;
    bool drain_scheduled = false;
    bool drain_active = false;
    std::uint64_t next_sequence = 1;
    std::uint64_t submitted = 0;
    std::uint64_t completed = 0;
    std::uint64_t failed = 0;
    std::uint64_t rejected = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t drain_tasks = 0;
};

namespace {

using queue_state_t = persistence_queue_t::state_t;

void fail_operations(std::vector<std::shared_ptr<queue_state_t::queued_operation_t>> operations,
                     workspace_error_t error) {
    for (auto& operation : operations) {
        if (!operation)
            continue;
        try {
            operation->promise.set_value(workspace_result_t<void>::failure(error));
        } catch (...) {
        }
    }
}

void schedule_drain(const std::shared_ptr<queue_state_t>& state);

void run_drain(const std::shared_ptr<queue_state_t>& state,
               const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
    std::vector<std::shared_ptr<queue_state_t::queued_operation_t>> batch;
    const auto started = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->drain_active = true;
        ++state->drain_tasks;
        const std::size_t count = (std::min)(state->limits.max_operations_per_drain,
                                             state->pending.size());
        batch.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            batch.push_back(std::move(state->pending.front()));
            state->pending.pop_front();
        }
        state->active_batch = batch;
    }

    std::size_t processed = 0;
    for (; processed < batch.size(); ++processed) {
        auto& queued = batch[processed];
        workspace_result_t<void> result = workspace_result_t<void>::success();
        const bool runtime_cancelled =
            runtime_cancel.requested.load(std::memory_order_acquire) ||
            (state->active_drain_cancel &&
             state->active_drain_cancel->requested.load(std::memory_order_acquire));
        if (runtime_cancelled ||
            queued->cancel.stop_requested()) {
            auto error = queue_error(queued->cancel.deadline_exceeded()
                                         ? workspace_error_code_t::deadline_exceeded
                                         : workspace_error_code_t::cancelled,
                                     queued->cancel.deadline_exceeded()
                                         ? "persistence operation deadline exceeded"
                                         : "persistence operation cancelled",
                                     "persistence_queue");
            error.cancellation = !queued->cancel.deadline_exceeded();
            error.deadline = queued->cancel.deadline_exceeded();
            result = workspace_result_t<void>::failure(std::move(error));
        } else {
            try {
                result = queued->operation(queued->cancel);
            } catch (const std::exception& exception) {
                result = workspace_result_t<void>::failure(
                    queue_error(workspace_error_code_t::persistence_failure,
                                std::string("persistence operation threw: ") + exception.what(),
                                "persistence_queue"));
            } catch (...) {
                result = workspace_result_t<void>::failure(
                    queue_error(workspace_error_code_t::persistence_failure,
                                "persistence operation threw an unknown exception",
                                "persistence_queue"));
            }
        }

        const bool success = result.has_value();
        const bool cancelled = !success &&
            (result.error().code == workspace_error_code_t::cancelled ||
             result.error().code == workspace_error_code_t::deadline_exceeded);
        try {
            queued->promise.set_value(std::move(result));
        } catch (...) {
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (success)
                ++state->completed;
            else if (cancelled)
                ++state->cancelled;
            else
                ++state->failed;
        }

        if (std::chrono::steady_clock::now() - started >= state->limits.max_drain_wall_time) {
            ++processed;
            break;
        }
    }

    if (processed < batch.size()) {
        std::lock_guard<std::mutex> lock(state->mutex);
        for (std::size_t index = batch.size(); index > processed; --index)
            state->pending.push_front(std::move(batch[index - 1]));
    }

    bool schedule_more = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->drain_active = false;
        state->drain_scheduled = false;
        state->active_batch.clear();
        state->active_drain_cancel.reset();
        state->active_drain_handle = {};
        schedule_more = !state->pending.empty() && state->accepting;
        if (!schedule_more)
            state->idle_cv.notify_all();
    }
    if (schedule_more)
        schedule_drain(state);
}

void schedule_drain(const std::shared_ptr<queue_state_t>& state) {
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->drain_scheduled || state->drain_active || state->pending.empty())
            return;
        state->drain_scheduled = true;
        state->active_drain_cancel =
            std::make_shared<aida::infra::taskflow_runtime::cancellation_token_t>();
    }

    aida::infra::taskflow_runtime::graph_descriptor_t graph;
    graph.domain = aida::infra::taskflow_runtime::executor_domain_t::service;
    graph.owner_subsystem = "analysis_persistence";
    graph.label = "analysis.persistence.drain";
    graph.phase = "persistence";
    graph.target_id = state->workspace_id_hex.c_str();
    graph.priority = 2;
    aida::infra::taskflow_runtime::graph_node_descriptor_t node;
    node.node_id = 1;
    node.label = "analysis.persistence.drain_batch";
    node.cancellable_body = [state](const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        run_drain(state, cancel);
    };
    graph.nodes.push_back(std::move(node));
    auto submission = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
    if (submission.submitted) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->active_drain_handle = submission.handle;
        return;
    }

    std::vector<std::shared_ptr<queue_state_t::queued_operation_t>> rejected;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->drain_scheduled = false;
        state->active_drain_cancel.reset();
        state->active_drain_handle = {};
        rejected.assign(std::make_move_iterator(state->pending.begin()),
                        std::make_move_iterator(state->pending.end()));
        state->pending.clear();
        state->rejected += rejected.size();
        state->idle_cv.notify_all();
    }
    auto error = queue_error(workspace_error_code_t::persistence_failure,
                             std::string("persistence drain rejected: ") + submission.reject_reason,
                             "persistence_queue");
    fail_operations(std::move(rejected), std::move(error));
}

}

workspace_result_t<std::shared_ptr<persistence_queue_t>>
persistence_queue_t::create(binary_id_t workspace_id, persistence_queue_limits_t limits) {
    if (workspace_id.empty()) {
        return workspace_result_t<std::shared_ptr<persistence_queue_t>>::failure(
            queue_error(workspace_error_code_t::invalid_argument,
                        "persistence queue requires a non-empty workspace identity",
                        "persistence_queue"));
    }
    if (limits.max_pending_operations == 0 || limits.max_operations_per_drain == 0 ||
        limits.max_drain_wall_time <= std::chrono::milliseconds::zero()) {
        return workspace_result_t<std::shared_ptr<persistence_queue_t>>::failure(
            queue_error(workspace_error_code_t::invalid_argument,
                        "persistence queue limits must be positive",
                        "persistence_queue"));
    }
    auto state = std::make_shared<state_t>();
    state->workspace_id = workspace_id;
    state->workspace_id_hex = workspace_id.to_hex();
    state->limits = limits;
    return workspace_result_t<std::shared_ptr<persistence_queue_t>>::success(
        std::shared_ptr<persistence_queue_t>(new persistence_queue_t(std::move(state))));
}

persistence_queue_t::persistence_queue_t(std::shared_ptr<state_t> state)
    : state_(std::move(state)) {
}

persistence_queue_t::~persistence_queue_t() {
    request_cancel();
}

persistence_ticket_t persistence_queue_t::enqueue(std::string label,
                                                   persistence_operation_t operation,
                                                   cancellation_token_t cancel) {
    persistence_ticket_t ticket;
    if (!operation) {
        ticket.completion = ready_failure(queue_error(workspace_error_code_t::invalid_argument,
                                                      "persistence operation is empty",
                                                      "persistence_queue"));
        return ticket;
    }

    auto queued = std::make_shared<state_t::queued_operation_t>();
    queued->label = std::move(label);
    queued->operation = std::move(operation);
    queued->cancel = std::move(cancel);
    ticket.completion = queued->promise.get_future().share();
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting) {
            ++state_->rejected;
            queued->promise.set_value(workspace_result_t<void>::failure(
                queue_error(workspace_error_code_t::workspace_closing,
                            "persistence queue is closing", "persistence_queue")));
            return ticket;
        }
        if (state_->pending.size() >= state_->limits.max_pending_operations) {
            ++state_->rejected;
            queued->promise.set_value(workspace_result_t<void>::failure(
                queue_error(workspace_error_code_t::limit_exceeded,
                            "persistence queue capacity exceeded", "persistence_queue")));
            return ticket;
        }
        queued->sequence = state_->next_sequence++;
        ticket.sequence = queued->sequence;
        ticket.accepted = true;
        ++state_->submitted;
        state_->pending.push_back(queued);
    }
    schedule_drain(state_);
    return ticket;
}

persistence_queue_snapshot_t persistence_queue_t::snapshot() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    persistence_queue_snapshot_t result;
    result.submitted = state_->submitted;
    result.completed = state_->completed;
    result.failed = state_->failed;
    result.rejected = state_->rejected;
    result.cancelled = state_->cancelled;
    result.drain_tasks = state_->drain_tasks;
    result.pending = state_->pending.size();
    result.accepting = state_->accepting;
    result.drain_active = state_->drain_active || state_->drain_scheduled;
    return result;
}

bool persistence_queue_t::idle() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->pending.empty() && state_->active_batch.empty() &&
           !state_->drain_active && !state_->drain_scheduled;
}

void persistence_queue_t::request_cancel() noexcept {
    std::vector<std::shared_ptr<state_t::queued_operation_t>> cancelled;
    std::shared_ptr<aida::infra::taskflow_runtime::cancellation_token_t> active_drain_cancel;
    aida::infra::taskflow_runtime::job_handle_t active_drain_handle;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting && state_->pending.empty() &&
            !state_->drain_active && !state_->drain_scheduled)
            return;
        state_->accepting = false;
        cancelled.assign(std::make_move_iterator(state_->pending.begin()),
                         std::make_move_iterator(state_->pending.end()));
        state_->pending.clear();
        state_->cancelled += cancelled.size();
        active_drain_cancel = state_->active_drain_cancel;
        active_drain_handle = state_->active_drain_handle;
        if (!state_->drain_active && !state_->drain_scheduled)
            state_->idle_cv.notify_all();
    }
    if (active_drain_cancel)
        active_drain_cancel->requested.store(true, std::memory_order_release);
    if (active_drain_handle.valid())
        aida::infra::taskflow_runtime::cancel(active_drain_handle);
    auto error = queue_error(workspace_error_code_t::cancelled,
                             "persistence operation cancelled during workspace close",
                             "persistence_queue");
    error.cancellation = true;
    fail_operations(std::move(cancelled), std::move(error));
}

workspace_result_t<void>
persistence_queue_t::drain(std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(state_->mutex);
    while (!state_->pending.empty() || state_->drain_active || state_->drain_scheduled) {
        if (state_->idle_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            auto error = queue_error(workspace_error_code_t::deadline_exceeded,
                                     "persistence queue did not drain before deadline",
                                     "persistence_queue");
            error.deadline = true;
            return workspace_result_t<void>::failure(std::move(error));
        }
    }
    return workspace_result_t<void>::success();
}

}
