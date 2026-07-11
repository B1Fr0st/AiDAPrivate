#include "baseline_pipeline.hpp"

#include "checked_range.hpp"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {
namespace {

class baseline_job_lifecycle_t final : public workspace_lifecycle_participant_t {
public:
    explicit baseline_job_lifecycle_t(std::shared_ptr<pe_baseline_analyzer_t> analyzer)
        : analyzer_(std::move(analyzer)) {}

    void set_handle(aida::infra::taskflow_runtime::job_handle_t handle) noexcept {
        handle_id_.store(handle.id, std::memory_order_release);
    }

    void request_cancel() noexcept override {
        auto analyzer = analyzer_.lock();
        if (analyzer)
            analyzer->request_cancel();
        const auto id = handle_id_.load(std::memory_order_acquire);
        if (id != 0)
            aida::infra::taskflow_runtime::cancel(id);
    }

    workspace_result_t<void> drain(
        std::chrono::steady_clock::time_point deadline) override {
        const auto id = handle_id_.load(std::memory_order_acquire);
        if (id == 0)
            return workspace_result_t<void>::success();
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
                    "baseline analysis did not drain before the workspace deadline", "drain");
                error.deadline = true;
                return workspace_result_t<void>::failure(std::move(error));
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            const auto wait_ms = static_cast<std::uint32_t>(std::max<std::int64_t>(1,
                std::min<std::int64_t>(25, remaining.count())));
            const auto result = aida::infra::taskflow_runtime::wait_for(
                aida::infra::taskflow_runtime::job_handle_t{id}, wait_ms);
            if (result.completed)
                return workspace_result_t<void>::success();
            if (result.failed) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "baseline analysis graph failed while draining", "drain"));
            }
            if (result.cancelled)
                return workspace_result_t<void>::success();
        }
    }

private:
    std::weak_ptr<pe_baseline_analyzer_t> analyzer_;
    std::atomic<std::uint64_t> handle_id_{0};
};

class baseline_job_state_t final {
public:
    baseline_job_state_t(std::shared_ptr<pe_baseline_analyzer_t> analyzer,
        workspace_analysis_run_t analysis_run)
        : analyzer_(std::move(analyzer)), analysis_run_(std::move(analysis_run)) {}

    std::shared_ptr<pe_baseline_analyzer_t> begin_call() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!analyzer_ || terminal_)
            return {};
        ++active_calls_;
        return analyzer_;
    }

    std::shared_ptr<pe_baseline_analyzer_t> acquire_analyzer() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return analyzer_;
    }

    void retain_lifecycle(std::shared_ptr<baseline_job_lifecycle_t> lifecycle) {
        std::lock_guard<std::mutex> lock(mutex_);
        lifecycle_ = std::move(lifecycle);
    }

    void finish_call(bool terminal) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        terminal_ = terminal_ || terminal;
        if (active_calls_ != 0)
            --active_calls_;
        release_if_drained_locked();
    }

    void mark_terminal() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        terminal_ = true;
        release_if_drained_locked();
    }

private:
    void release_if_drained_locked() noexcept {
        if (!terminal_ || active_calls_ != 0)
            return;
        analyzer_.reset();
        analysis_run_.release();
    }

    mutable std::mutex mutex_;
    std::shared_ptr<pe_baseline_analyzer_t> analyzer_;
    workspace_analysis_run_t analysis_run_;
    std::shared_ptr<baseline_job_lifecycle_t> lifecycle_;
    std::uint64_t active_calls_ = 0;
    bool terminal_ = false;
};

class baseline_call_guard_t final {
public:
    explicit baseline_call_guard_t(std::shared_ptr<baseline_job_state_t> state)
        : state_(std::move(state)) {}

    ~baseline_call_guard_t() {
        state_->finish_call(terminal_);
    }

    void mark_terminal() noexcept {
        terminal_ = true;
    }

private:
    std::shared_ptr<baseline_job_state_t> state_;
    bool terminal_ = false;
};

std::uint64_t runtime_deadline_ms(
    const std::optional<std::chrono::steady_clock::time_point>& deadline) {
    if (!deadline)
        return 0;
    const auto now = std::chrono::steady_clock::now();
    if (*deadline <= now)
        return GetTickCount64();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        *deadline - now);
    const auto rounded = static_cast<std::uint64_t>(remaining.count()) + 1ULL;
    std::uint64_t result = 0;
    if (!checked_add_u64(GetTickCount64(), rounded, result))
        return std::numeric_limits<std::uint64_t>::max();
    return result;
}

template <typename Callable>
std::function<void(const aida::infra::taskflow_runtime::cancellation_token_t&)>
phase_body(std::shared_ptr<baseline_job_state_t> state, Callable callable,
    bool terminal = false) {
    return [state = std::move(state), callable = std::move(callable), terminal](
               const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        auto analyzer = state->begin_call();
        if (!analyzer)
            return;
        baseline_call_guard_t call_guard(state);
        bool reported = false;
        try {
        const auto before = aida::infra::taskflow_runtime::active_snapshot(64);
        analyzer->metrics()->record_runtime_pressure(before.total_active,
            before.work_queue_pending + before.service_queue_pending +
                before.critical_queue_pending);
        std::uint64_t concurrent_workspaces = 0;
        std::uint64_t fairness_wait_ns = 0;
        for (const auto& job : before.active_jobs) {
            if (job.owner_subsystem != "analysis_workspace")
                continue;
            ++concurrent_workspaces;
            if (job.started_ns >= job.queued_ns)
                fairness_wait_ns = std::max(fairness_wait_ns,
                    job.started_ns - job.queued_ns);
        }
        analyzer->metrics()->record_workspace_concurrency(concurrent_workspaces,
            fairness_wait_ns, 1);
        auto result = callable(*analyzer, cancel.requested);
        const auto after = aida::infra::taskflow_runtime::active_snapshot(64);
        analyzer->metrics()->record_runtime_pressure(after.total_active,
            after.work_queue_pending + after.service_queue_pending +
                after.critical_queue_pending);
        if (result) {
            analyzer->metrics()->add(analysis_metric_t::tasks_completed);
            if (terminal)
                call_guard.mark_terminal();
            return;
        }
        const auto error = result.error();
        analyzer->report_failure(error);
        reported = true;
        call_guard.mark_terminal();
        throw std::runtime_error(error.stable_code() + ":" + error.message);
        } catch (const std::exception& exception) {
            if (!reported) {
                auto error = make_workspace_error(workspace_error_code_t::integrity_failure,
                    "baseline phase raised an unexpected exception", "baseline_graph");
                error.details.emplace_back("exception", exception.what());
                analyzer->report_failure(error);
            }
            call_guard.mark_terminal();
            throw;
        } catch (...) {
            if (!reported) {
                analyzer->report_failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "baseline phase raised an unknown exception", "baseline_graph"));
            }
            call_guard.mark_terminal();
            throw;
        }
    };
}

}

workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>
baseline_analysis_service_t::start(
    std::shared_ptr<analysis_workspace_t> workspace,
    baseline_analysis_settings_t settings,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!workspace) {
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "baseline analysis requires a workspace", "submit"));
    }
    if (workspace->target_kind() != target_kind_t::static_file) {
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::live_target_bulk_analysis_unsupported,
                "bulk baseline analysis is not supported for live targets", "submit"));
    }
    const auto generation = workspace->generation();
    const auto analysis_revision = workspace->analysis_revision();
    if (deadline && *deadline <= std::chrono::steady_clock::now()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline deadline expired before graph submission", "submit");
        error.deadline = true;
        (void)workspace->record_analysis_attempt_failure(
            generation, analysis_revision, error);
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            std::move(error));
    }
    auto analysis_run = workspace->try_begin_analysis(generation);
    if (!analysis_run) {
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            analysis_run.error());
    }
    const auto task_priority = settings.task_priority;
    auto created = pe_baseline_analyzer_t::create(workspace, std::move(settings),
        generation, analysis_revision, deadline);
    if (!created)
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            created.error());
    auto analyzer = created.take_value();
    auto lifecycle = std::make_shared<baseline_job_lifecycle_t>(analyzer);
    auto state = std::make_shared<baseline_job_state_t>(analyzer,
        analysis_run.take_value());
    state->retain_lifecycle(lifecycle);
    auto registered = workspace->register_lifecycle_participant(lifecycle);
    if (!registered) {
        analyzer->report_failure(registered.error());
        state->mark_terminal();
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            registered.error());
    }
    aida::infra::taskflow_runtime::graph_descriptor_t graph;
    graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    graph.owner_subsystem = "analysis_workspace";
    graph.label = "normalized_baseline_analysis";
    graph.phase = "baseline";
    const auto target_id = workspace->identity().binary_id().to_hex();
    graph.target_id = target_id.c_str();
    graph.priority = task_priority;
    graph.deadline_ms = runtime_deadline_ms(deadline);
    graph.generation = generation;
    graph.cancel_hook = [state]() {
        if (auto locked = state->acquire_analyzer())
            locked->request_cancel();
        state->mark_terminal();
    };
    std::vector<std::string> labels;
    labels.reserve(analyzer->decode_lane_count() + 12);
    auto add_node = [&](std::uint64_t id, std::string label,
                        std::vector<std::uint64_t> dependencies,
                        std::function<void(
                            const aida::infra::taskflow_runtime::cancellation_token_t&)> body) {
        labels.push_back(std::move(label));
        aida::infra::taskflow_runtime::graph_node_descriptor_t node;
        node.node_id = id;
        node.label = labels.back().c_str();
        node.depends_on = std::move(dependencies);
        node.cancellable_body = std::move(body);
        graph.nodes.push_back(std::move(node));
    };
    add_node(1, "baseline.parse", {}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.parse_phase(cancel); }));
    add_node(2, "baseline.seed", {1}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.seed_phase(cancel); }));
    std::vector<std::uint64_t> decode_nodes;
    decode_nodes.reserve(analyzer->decode_lane_count());
    for (std::uint32_t lane = 0; lane < analyzer->decode_lane_count(); ++lane) {
        const auto node_id = 100ULL + lane;
        decode_nodes.push_back(node_id);
        add_node(node_id, "baseline.decode." + std::to_string(lane), {2},
            phase_body(state, [lane](auto& value, const auto& cancel) {
                return value.decode_lane_phase(lane, cancel);
            }));
    }
    add_node(200, "baseline.decode_merge", decode_nodes, phase_body(state,
        [](auto& value, const auto& cancel) { return value.decode_merge_phase(cancel); }));
    add_node(3, "baseline.blocks", {200}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.blocks_phase(cancel); }));
    add_node(4, "baseline.functions", {3}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.functions_phase(cancel); }));
    add_node(5, "baseline.cfg_calls", {4}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.cfg_calls_phase(cancel); }));
    add_node(6, "baseline.xrefs", {5}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.xrefs_phase(cancel); }));
    add_node(7, "baseline.strings_data", {6}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.strings_data_phase(cancel); }));
    add_node(8, "baseline.metadata_symbols_types", {7}, phase_body(state,
        [](auto& value, const auto& cancel) {
            return value.metadata_symbols_types_phase(cancel);
        }));
    add_node(9, "baseline.search_index", {8}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.search_index_phase(cancel); }));
    add_node(10, "baseline.persistence", {9}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.persistence_phase(cancel); }));
    add_node(11, "baseline.publish_ready", {10}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.publish_ready_phase(cancel); }, true));
    analyzer->metrics()->set(analysis_metric_t::tasks_scheduled, graph.nodes.size());
    auto submitted = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
    if (!submitted.submitted) {
        if (submitted.handle.id != 0) {
            lifecycle->set_handle(submitted.handle);
            lifecycle->request_cancel();
            const auto drain_deadline = std::min(
                deadline.value_or(std::chrono::steady_clock::now() +
                    std::chrono::seconds(5)),
                std::chrono::steady_clock::now() + std::chrono::seconds(5));
            const auto drained = lifecycle->drain(drain_deadline);
            if (!drained)
                state->mark_terminal();
        }
        analyzer->metrics()->add(analysis_metric_t::tasks_rejected);
        auto error = make_workspace_error(workspace_error_code_t::provider_unavailable,
            "Taskflow rejected the baseline analysis graph", "submit");
        error.details.emplace_back("reason", submitted.reject_reason);
        analyzer->report_failure(error);
        state->mark_terminal();
        return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::failure(
            std::move(error));
    }
    lifecycle->set_handle(submitted.handle);
    return workspace_result_t<aida::infra::taskflow_runtime::job_handle_t>::success(
        submitted.handle);
}

bool baseline_analysis_service_t::cancel(
    aida::infra::taskflow_runtime::job_handle_t handle) noexcept {
    return aida::infra::taskflow_runtime::cancel(handle);
}

}
