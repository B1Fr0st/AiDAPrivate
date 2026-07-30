#include "baseline_pipeline.hpp"

#include "checked_range.hpp"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
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

struct baseline_graph_schedule_t {
    std::atomic<std::uint64_t> submitted_ns{0};
    std::mutex finished_mutex;
    std::unordered_map<std::uint64_t, std::uint64_t> node_finished_ns;
};

struct phase_node_schedule_t {
    std::shared_ptr<baseline_graph_schedule_t> graph;
    std::uint64_t node_id = 0;
    std::vector<std::uint64_t> dependencies;
    std::uint64_t decode_lane_count = 0;
};

class busy_slot_guard_t final {
public:
    busy_slot_guard_t(std::shared_ptr<pe_baseline_analyzer_t> analyzer,
        std::chrono::steady_clock::time_point started) noexcept
        : analyzer_(std::move(analyzer)), started_(started) {}

    busy_slot_guard_t(const busy_slot_guard_t&) = delete;
    busy_slot_guard_t& operator=(const busy_slot_guard_t&) = delete;

    ~busy_slot_guard_t() noexcept {
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started_).count();
        if (elapsed > 0) {
            analyzer_->metrics()->add(analysis_metric_t::worker_slots_busy_ns,
                static_cast<std::uint64_t>(elapsed));
        }
    }

private:
    std::shared_ptr<pe_baseline_analyzer_t> analyzer_;
    std::chrono::steady_clock::time_point started_;
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
    phase_node_schedule_t schedule, bool terminal = false) {
    return [state = std::move(state), callable = std::move(callable),
            schedule = std::move(schedule), terminal](
               const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        const auto task_started = std::chrono::steady_clock::now();
        const auto task_started_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                task_started.time_since_epoch()).count());
        auto analyzer = state->begin_call();
        if (!analyzer)
            return;
        baseline_call_guard_t call_guard(state);
        busy_slot_guard_t busy_guard(analyzer, task_started);
        if (schedule.graph) {
            std::uint64_t queued_ns =
                schedule.graph->submitted_ns.load(std::memory_order_acquire);
            {
                std::lock_guard<std::mutex> lock(schedule.graph->finished_mutex);
                for (const auto dependency : schedule.dependencies) {
                    const auto finished =
                        schedule.graph->node_finished_ns.find(dependency);
                    if (finished != schedule.graph->node_finished_ns.end())
                        queued_ns = (std::max)(queued_ns, finished->second);
                }
            }
            if (queued_ns != 0 && task_started_ns >= queued_ns) {
                const auto wait_ns = task_started_ns - queued_ns;
                analyzer->metrics()->add(analysis_metric_t::queue_wait_ns_total,
                    wait_ns);
                analyzer->metrics()->set_max(analysis_metric_t::queue_wait_max_ns,
                    wait_ns);
            }
        }
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
            if (schedule.graph) {
                const auto finished_ns = analysis_metrics_t::steady_now_ns();
                std::lock_guard<std::mutex> lock(schedule.graph->finished_mutex);
                schedule.graph->node_finished_ns[schedule.node_id] = finished_ns;
            }
            if (terminal) {
                if (schedule.graph && schedule.decode_lane_count != 0) {
                    const auto submitted =
                        schedule.graph->submitted_ns.load(std::memory_order_acquire);
                    const auto completed_ns = analysis_metrics_t::steady_now_ns();
                    if (submitted != 0 && completed_ns >= submitted) {
                        std::uint64_t scheduled_ns = 0;
                        if (checked_mul_u64(schedule.decode_lane_count,
                                completed_ns - submitted, scheduled_ns)) {
                            analyzer->metrics()->add(
                                analysis_metric_t::worker_slots_scheduled_ns,
                                scheduled_ns);
                        }
                    }
                }
                call_guard.mark_terminal();
            }
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
    const auto enable_parallel_fact_passes = settings.enable_parallel_fact_passes;
    const auto overlap_strings_with_decode = settings.overlap_strings_with_decode;
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
    auto graph_schedule = std::make_shared<baseline_graph_schedule_t>();
    std::vector<std::string> labels;
    labels.reserve(analyzer->decode_lane_count() + 14);
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
        [](auto& value, const auto& cancel) { return value.parse_phase(cancel); },
        {graph_schedule, 1, {}}));
    add_node(2, "baseline.seed", {1}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.seed_phase(cancel); },
        {graph_schedule, 2, {1}}));
    std::vector<std::uint64_t> decode_nodes;
    decode_nodes.reserve(analyzer->decode_lane_count());
    for (std::uint32_t lane = 0; lane < analyzer->decode_lane_count(); ++lane) {
        const auto node_id = 100ULL + lane;
        decode_nodes.push_back(node_id);
        add_node(node_id, "baseline.decode." + std::to_string(lane), {2},
            phase_body(state, [lane](auto& value, const auto& cancel) {
                return value.decode_lane_phase(lane, cancel);
            }, {graph_schedule, node_id, {2}}));
    }
    add_node(200, "baseline.decode_merge", decode_nodes, phase_body(state,
        [](auto& value, const auto& cancel) { return value.decode_merge_phase(cancel); },
        {graph_schedule, 200, decode_nodes}));
    if (enable_parallel_fact_passes) {
        const auto strings_dependency = overlap_strings_with_decode ? 1ULL : 200ULL;
        add_node(3, "baseline.strings_data", {strings_dependency},
            phase_body(state,
                [](auto& value, const auto& cancel) {
                    return value.strings_data_phase(cancel);
                }, {graph_schedule, 3, {strings_dependency}}));
        add_node(210, "baseline.data_discovery", {200}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.data_discovery_phase(cancel);
            }, {graph_schedule, 210, {200}}));
        add_node(220, "baseline.function_recovery", {210}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.function_recovery_phase(cancel);
            }, {graph_schedule, 220, {210}}));
        add_node(230, "baseline.functions", {220}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.functions_phase(cancel); },
            {graph_schedule, 230, {220}}));
        add_node(240, "baseline.cfg_calls", {230}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.cfg_calls_phase(cancel); },
            {graph_schedule, 240, {230}}));
        add_node(250, "baseline.xrefs", {200, 210}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.xrefs_phase(cancel); },
            {graph_schedule, 250, {200, 210}}));
        add_node(260, "baseline.metadata_symbols_types", {240, 250, 3}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.metadata_symbols_types_phase(cancel);
            }, {graph_schedule, 260, {240, 250, 3}}));
    } else {
        add_node(210, "baseline.data_discovery", {200}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.data_discovery_phase(cancel);
            }, {graph_schedule, 210, {200}}));
        add_node(220, "baseline.function_recovery", {210}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.function_recovery_phase(cancel);
            }, {graph_schedule, 220, {210}}));
        add_node(230, "baseline.functions", {220}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.functions_phase(cancel); },
            {graph_schedule, 230, {220}}));
        add_node(240, "baseline.cfg_calls", {230}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.cfg_calls_phase(cancel); },
            {graph_schedule, 240, {230}}));
        add_node(250, "baseline.xrefs", {240}, phase_body(state,
            [](auto& value, const auto& cancel) { return value.xrefs_phase(cancel); },
            {graph_schedule, 250, {240}}));
        add_node(3, "baseline.strings_data", {250}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.strings_data_phase(cancel);
            }, {graph_schedule, 3, {250}}));
        add_node(260, "baseline.metadata_symbols_types", {3}, phase_body(state,
            [](auto& value, const auto& cancel) {
                return value.metadata_symbols_types_phase(cancel);
            }, {graph_schedule, 260, {3}}));
    }
    add_node(270, "baseline.search_index", {260}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.search_index_phase(cancel); },
        {graph_schedule, 270, {260}}));
    add_node(280, "baseline.persistence_submit", {270}, phase_body(state,
        [](auto& value, const auto& cancel) {
            return value.persistence_submit_phase(cancel);
        }, {graph_schedule, 280, {270}}));
    add_node(290, "baseline.persistence_commit", {280}, phase_body(state,
        [](auto& value, const auto& cancel) {
            return value.persistence_commit_phase(cancel);
        }, {graph_schedule, 290, {280}}));
    add_node(300, "baseline.publish_ready", {290}, phase_body(state,
        [](auto& value, const auto& cancel) { return value.publish_ready_phase(cancel); },
        {graph_schedule, 300, {290},
            static_cast<std::uint64_t>(decode_nodes.size())}, true));
    graph_schedule->submitted_ns.store(analysis_metrics_t::steady_now_ns(),
        std::memory_order_release);
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
