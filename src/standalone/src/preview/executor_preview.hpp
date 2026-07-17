#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "taskflow_runtime_preview.hpp"
#include "../core/infra/taskflow_evaluation.hpp"
#include "../core/diagnostics/metadata_ring.hpp"

namespace aida::infra::executor {

enum class domain_t : std::uint8_t {
    general = 0,
    service = 1,
    critical = 2,
    ui_dispatch = 3,
    external_tool = 4,
    long_running = 5,
    security_liveness = 6,
    feature_worker = 7,
    diagnostics = 8
};

inline constexpr std::size_t domain_count = 9;

inline const char* domain_name(domain_t domain) {
    switch (domain) {
    case domain_t::general: return "general";
    case domain_t::service: return "service";
    case domain_t::critical: return "critical";
    case domain_t::ui_dispatch: return "ui_dispatch";
    case domain_t::external_tool: return "external_tool";
    case domain_t::long_running: return "long_running";
    case domain_t::security_liveness: return "security_liveness";
    case domain_t::feature_worker: return "feature_worker";
    case domain_t::diagnostics: return "diagnostics";
    default: return "unknown";
    }
}

inline const char* domain_to_queue_name(domain_t domain) {
    switch (domain) {
    case domain_t::general: return "taskflow_runtime.general";
    case domain_t::service: return "taskflow_runtime.service";
    case domain_t::critical: return "taskflow_runtime.critical";
    case domain_t::ui_dispatch: return "taskflow_runtime.ui_dispatch";
    case domain_t::external_tool: return "taskflow_runtime.external_tool+capacity_governor";
    case domain_t::long_running: return "taskflow_runtime.long_running+downstream_governor";
    case domain_t::security_liveness: return "taskflow_runtime.security_liveness";
    case domain_t::feature_worker: return "taskflow_runtime.feature_worker+downstream_governor";
    case domain_t::diagnostics: return "taskflow_runtime.diagnostics";
    default: return "unknown";
    }
}

inline taskflow_runtime::executor_domain_t to_runtime_domain(domain_t domain) {
    using runtime_domain_t = taskflow_runtime::executor_domain_t;
    switch (domain) {
    case domain_t::service: return runtime_domain_t::service;
    case domain_t::critical: return runtime_domain_t::critical;
    case domain_t::ui_dispatch: return runtime_domain_t::ui_dispatch;
    case domain_t::external_tool: return runtime_domain_t::external_tool;
    case domain_t::long_running: return runtime_domain_t::long_running;
    case domain_t::security_liveness: return runtime_domain_t::security_liveness;
    case domain_t::feature_worker: return runtime_domain_t::feature_worker;
    case domain_t::diagnostics: return runtime_domain_t::diagnostics;
    case domain_t::general:
    default: return runtime_domain_t::general;
    }
}

inline domain_t from_runtime_domain(taskflow_runtime::executor_domain_t domain) {
    using runtime_domain_t = taskflow_runtime::executor_domain_t;
    switch (domain) {
    case runtime_domain_t::service: return domain_t::service;
    case runtime_domain_t::critical: return domain_t::critical;
    case runtime_domain_t::ui_dispatch: return domain_t::ui_dispatch;
    case runtime_domain_t::external_tool: return domain_t::external_tool;
    case runtime_domain_t::long_running: return domain_t::long_running;
    case runtime_domain_t::security_liveness: return domain_t::security_liveness;
    case runtime_domain_t::feature_worker: return domain_t::feature_worker;
    case runtime_domain_t::diagnostics: return domain_t::diagnostics;
    case runtime_domain_t::general:
    default: return domain_t::general;
    }
}

inline diagnostics::breadcrumb_category_t domain_to_breadcrumb_category(domain_t domain) {
    switch (domain) {
    case domain_t::general:
    case domain_t::service:
    case domain_t::feature_worker:
        return diagnostics::breadcrumb_category_t::work_queue;
    case domain_t::critical:
    case domain_t::security_liveness:
        return diagnostics::breadcrumb_category_t::critical_queue;
    case domain_t::external_tool:
        return diagnostics::breadcrumb_category_t::capacity_governor;
    case domain_t::long_running:
        return diagnostics::breadcrumb_category_t::downstream_producer;
    case domain_t::ui_dispatch:
        return diagnostics::breadcrumb_category_t::ui_dispatcher;
    case domain_t::diagnostics:
    default:
        return diagnostics::breadcrumb_category_t::thread_runtime;
    }
}

struct submission_t {
    const char* owner_subsystem = nullptr;
    const char* label = nullptr;
    const char* thread_class = nullptr;
    domain_t domain = domain_t::general;
    int priority = 3;
    std::function<void()> cancel_hook;
    std::uint64_t deadline_ms = 0;
    std::uint64_t capacity_lease = 0;
    const char* no_capacity_reason = nullptr;
    const char* session_id = nullptr;
    const char* target_id = nullptr;
    std::uint32_t target_pid = 0;
    std::uint64_t lease_token = 0;
    std::uint64_t generation = 0;
    const char* diagnostic_id = nullptr;
    const char* request_id = nullptr;
    const char* ui_access_policy = "none";
    const char* failure_policy = "reject_not_started";
    const char* shutdown_policy = "drain";
    std::function<void()> body;
};

struct submit_result_t {
    bool submitted = false;
    std::uint64_t task_id = 0;
    std::string reject_reason;
};

struct wait_result_t {
    bool completed = false;
    bool timed_out = false;
    bool rejected = false;
};

struct active_snapshot_t {
    std::uint32_t active_per_domain[domain_count] = {};
    std::uint64_t oldest_active_ms = 0;
    std::string labels_under_pressure;
    std::uint32_t total_active = 0;
    std::uint32_t work_queue_active = 0;
    std::uint32_t service_queue_active = 0;
    std::uint32_t critical_queue_active = 0;
    std::uint64_t work_queue_pending = 0;
    std::uint64_t service_queue_pending = 0;
    std::uint64_t critical_queue_pending = 0;
};

using preview_submission_observer_t = void (*)(const submission_t&);

inline std::atomic<std::uint64_t> total_submits{0};
inline std::atomic<std::uint64_t> total_rejected{0};
inline std::atomic<std::uint64_t> total_ui_wait_rejected{0};
inline std::atomic<std::uint64_t> total_cancels{0};
inline std::atomic<std::uint64_t> total_timeouts{0};
inline std::atomic<std::uint64_t> submits_per_domain[domain_count] = {};
inline std::atomic<std::uint64_t> rejects_per_domain[domain_count] = {};
inline std::atomic<DWORD> g_executor_ui_owner_tid{0};
inline std::atomic<bool> g_shutdown_requested{false};
inline std::mutex g_ui_owner_mutex;
inline std::thread::id g_ui_owner_thread;
inline std::mutex g_reject_reason_mutex;
inline std::map<std::string, std::uint64_t> g_reject_reasons;
inline constexpr std::size_t kMaxRejectReasonEntries = 32;
inline std::mutex g_deadline_reported_mutex;
inline std::map<std::uint64_t, bool> g_deadline_reported;
inline std::atomic<preview_submission_observer_t> g_preview_submission_observer{nullptr};

inline std::size_t domain_index(domain_t domain) {
    return static_cast<std::size_t>(domain);
}

inline void record_reject_reason(const char* reason) {
    if (!reason)
        return;
    std::lock_guard<std::mutex> lock(g_reject_reason_mutex);
    const auto found = g_reject_reasons.find(reason);
    if (found != g_reject_reasons.end()) {
        ++found->second;
    } else if (g_reject_reasons.size() < kMaxRejectReasonEntries) {
        g_reject_reasons[reason] = 1;
    } else {
        ++g_reject_reasons["other"];
    }
}

inline const char* taskflow_evaluation_status() {
    return taskflow_eval::kTaskflowEvaluationStatus;
}

inline void set_ui_owner_tid(DWORD tid) {
    g_executor_ui_owner_tid.store(tid);
    std::lock_guard<std::mutex> lock(g_ui_owner_mutex);
    g_ui_owner_thread = tid == 0 ? std::thread::id{} : std::this_thread::get_id();
}

inline bool is_ui_thread() {
    if (g_executor_ui_owner_tid.load() == 0)
        return false;
    std::lock_guard<std::mutex> lock(g_ui_owner_mutex);
    return g_ui_owner_thread == std::this_thread::get_id();
}

inline std::uint64_t now_ms() {
    return taskflow_runtime::preview_now_ms();
}

inline void set_preview_submission_observer(preview_submission_observer_t observer) {
    g_preview_submission_observer.store(observer);
}

inline void emit_breadcrumb(domain_t domain, const char* event, const submission_t& submission,
                            std::uint64_t task_id, std::uint16_t status_code) {
    diagnostics::breadcrumb_options_t options;
    options.category = domain_to_breadcrumb_category(domain);
    options.label = submission.label ? submission.label : "<unnamed>";
    options.reason = event;
    options.owner_subsystem = submission.owner_subsystem ? submission.owner_subsystem : "<unknown>";
    options.tool_or_request_id = submission.request_id
        ? submission.request_id
        : (submission.diagnostic_id ? submission.diagnostic_id : nullptr);
    options.session_or_target = submission.session_id
        ? submission.session_id
        : (submission.target_id ? submission.target_id : nullptr);
    options.lease_token = submission.lease_token;
    options.generation = submission.generation;
    options.status_code = status_code;
    options.priority = static_cast<std::uint8_t>(submission.priority > 5 ? 5 : submission.priority);
    diagnostics::emit(std::move(options));
    static_cast<void>(task_id);
}

inline void emit_simple_breadcrumb(domain_t domain, const char* label, const char* owner,
                                   const char* event, std::uint16_t status_code) {
    diagnostics::breadcrumb_options_t options;
    options.category = domain_to_breadcrumb_category(domain);
    options.label = label ? label : "<unnamed>";
    options.reason = event;
    options.owner_subsystem = owner ? owner : "<unknown>";
    options.status_code = status_code;
    diagnostics::emit(std::move(options));
}

inline submit_result_t reject_submission(const submission_t& submission, const char* reason) {
    submit_result_t result;
    result.reject_reason = reason ? reason : "rejected";
    total_rejected.fetch_add(1);
    const auto index = domain_index(submission.domain);
    if (index < domain_count)
        rejects_per_domain[index].fetch_add(1);
    record_reject_reason(result.reject_reason.c_str());
    emit_breadcrumb(submission.domain, "EXECUTOR-REJECT", submission, 0, 2);
    return result;
}

inline submit_result_t submit_immediate(submission_t&& submission, bool count_attempt = true) {
    if (count_attempt)
        total_submits.fetch_add(1);
    if (!submission.owner_subsystem || submission.owner_subsystem[0] == '\0')
        return reject_submission(submission, "missing_owner_subsystem");
    if (!submission.label || submission.label[0] == '\0')
        return reject_submission(submission, "missing_label");
    if (!submission.body)
        return reject_submission(submission, "missing_body");
    if (submission.domain == domain_t::ui_dispatch && is_ui_thread()) {
        total_ui_wait_rejected.fetch_add(1);
        return reject_submission(submission, "EXECUTOR-UI-WAIT-REJECTED");
    }
    if (g_shutdown_requested.load())
        return reject_submission(submission, "executor_shutdown_requested");

    taskflow_runtime::task_descriptor_t descriptor;
    descriptor.owner_subsystem = submission.owner_subsystem;
    descriptor.label = submission.label;
    descriptor.thread_class = submission.thread_class;
    descriptor.domain = to_runtime_domain(submission.domain);
    descriptor.priority = submission.priority;
    descriptor.cancel_hook = std::move(submission.cancel_hook);
    descriptor.deadline_ms = submission.deadline_ms;
    descriptor.capacity_lease = submission.capacity_lease;
    descriptor.no_capacity_reason = submission.no_capacity_reason;
    descriptor.session_id = submission.session_id;
    descriptor.target_id = submission.target_id;
    descriptor.target_pid = submission.target_pid;
    descriptor.lease_token = submission.lease_token;
    descriptor.generation = submission.generation;
    descriptor.diagnostic_id = submission.diagnostic_id;
    descriptor.request_id = submission.request_id;
    descriptor.ui_access_policy = submission.ui_access_policy;
    descriptor.failure_policy = submission.failure_policy;
    descriptor.shutdown_policy = submission.shutdown_policy;
    descriptor.body = std::move(submission.body);

    if (const auto observer = g_preview_submission_observer.load())
        observer(submission);
    const auto timed_out_before = taskflow_runtime::active_snapshot(0).total_timed_out;
    auto runtime_result = taskflow_runtime::submit(std::move(descriptor));
    const auto timed_out_after = taskflow_runtime::active_snapshot(0).total_timed_out;
    if (timed_out_after > timed_out_before)
        total_timeouts.fetch_add(timed_out_after - timed_out_before);
    if (!runtime_result.submitted) {
        submit_result_t result;
        result.reject_reason = runtime_result.reject_reason.empty()
            ? "taskflow_runtime_submit_failed"
            : std::move(runtime_result.reject_reason);
        total_rejected.fetch_add(1);
        const auto index = domain_index(submission.domain);
        if (index < domain_count)
            rejects_per_domain[index].fetch_add(1);
        record_reject_reason(result.reject_reason.c_str());
        emit_breadcrumb(submission.domain, "EXECUTOR-REJECT", submission, 0, 2);
        return result;
    }

    const auto index = domain_index(submission.domain);
    if (index < domain_count)
        submits_per_domain[index].fetch_add(1);
    emit_breadcrumb(submission.domain, "EXECUTOR-SUBMIT", submission, runtime_result.handle.id, 0);
    return {true, runtime_result.handle.id, {}};
}

inline submit_result_t submit(submission_t&& submission) {
    return submit_immediate(std::move(submission));
}

inline void drain_preview_frame() {
    taskflow_runtime::check_deadlines();
    static_cast<void>(taskflow_runtime::drain_preview_work(1));
}

inline active_snapshot_t active_snapshot() {
    active_snapshot_t result;
    const auto runtime = taskflow_runtime::active_snapshot();
    result.oldest_active_ms = runtime.oldest_active_ms;
    result.labels_under_pressure = runtime.labels_under_pressure;
    result.total_active = runtime.total_active;
    result.work_queue_active = runtime.work_queue_active;
    result.service_queue_active = runtime.service_queue_active;
    result.critical_queue_active = runtime.critical_queue_active;
    result.work_queue_pending = runtime.work_queue_pending;
    result.service_queue_pending = runtime.service_queue_pending;
    result.critical_queue_pending = runtime.critical_queue_pending;
    for (std::size_t index = 0;
         index < domain_count && index < taskflow_runtime::executor_domain_count;
         ++index) {
        result.active_per_domain[index] = runtime.active_per_domain[index];
    }
    return result;
}

inline wait_result_t wait_for(std::uint64_t task_id, std::uint32_t timeout_ms) {
    if (is_ui_thread()) {
        total_ui_wait_rejected.fetch_add(1);
        return {false, false, true};
    }
    const auto runtime = taskflow_runtime::wait_for(task_id, timeout_ms);
    if (runtime.timed_out)
        total_timeouts.fetch_add(1);
    return {
        runtime.completed || runtime.cancelled || runtime.failed,
        runtime.timed_out,
        runtime.rejected
    };
}

inline bool cancel(std::uint64_t task_id) {
    if (task_id == 0 || !taskflow_runtime::cancel(task_id))
        return false;
    total_cancels.fetch_add(1);
    return true;
}

inline void check_deadlines() {
    const auto current = now_ms();
    const auto snapshot = taskflow_runtime::active_snapshot(128);
    std::map<std::uint64_t, taskflow_runtime::active_job_snapshot_t> expired;
    {
        std::lock_guard<std::mutex> lock(g_deadline_reported_mutex);
        for (const auto& job : snapshot.active_jobs) {
            if (job.deadline_ms == 0 || current < job.deadline_ms || g_deadline_reported[job.job_id])
                continue;
            g_deadline_reported[job.job_id] = true;
            expired.emplace(job.job_id, job);
        }
    }
    taskflow_runtime::check_deadlines();
    for (const auto& entry : expired) {
        total_timeouts.fetch_add(1);
        const auto domain = from_runtime_domain(entry.second.domain);
        emit_simple_breadcrumb(domain, entry.second.label.c_str(),
            entry.second.owner_subsystem.c_str(), "EXECUTOR-TIMEOUT", 4);
    }
}

inline bool shutdown() {
    g_shutdown_requested.store(true, std::memory_order_release);
    diagnostics::breadcrumb_options_t options;
    options.category = diagnostics::breadcrumb_category_t::startup_shutdown;
    options.label = "executor_shutdown";
    options.reason = "EXECUTOR-SNAPSHOT";
    options.owner_subsystem = "executor";
    options.status_code = 5;
    diagnostics::emit(std::move(options));
    return taskflow_runtime::shutdown();
}

inline void json_append_escaped(std::string& output, const std::string& value) {
    for (const char character : value) {
        if (character == '"' || character == '\\')
            output += '\\';
        if (character == '\n')
            output += "\\n";
        else if (character == '\r')
            output += "\\r";
        else
            output += character;
    }
}

inline std::string snapshot_json_string() {
    const auto snapshot = active_snapshot();
    const auto runtime = taskflow_runtime::active_snapshot(64);
    std::string output = "{\"total_submits\":" + std::to_string(total_submits.load()) +
        ",\"total_rejected\":" + std::to_string(total_rejected.load()) +
        ",\"total_ui_wait_rejected\":" + std::to_string(total_ui_wait_rejected.load()) +
        ",\"total_cancels\":" + std::to_string(total_cancels.load()) +
        ",\"total_timeouts\":" + std::to_string(total_timeouts.load()) +
        ",\"taskflow_evaluation_status\":\"" + taskflow_evaluation_status() +
        "\",\"oldest_active_ms\":" + std::to_string(snapshot.oldest_active_ms) +
        ",\"total_active\":" + std::to_string(snapshot.total_active) +
        ",\"work_queue_active\":" + std::to_string(snapshot.work_queue_active) +
        ",\"service_queue_active\":" + std::to_string(snapshot.service_queue_active) +
        ",\"critical_queue_active\":" + std::to_string(snapshot.critical_queue_active) +
        ",\"work_queue_pending\":" + std::to_string(snapshot.work_queue_pending) +
        ",\"service_queue_pending\":" + std::to_string(snapshot.service_queue_pending) +
        ",\"critical_queue_pending\":" + std::to_string(snapshot.critical_queue_pending) +
        ",\"domains\":[";
    for (std::size_t index = 0; index < domain_count; ++index) {
        if (index != 0)
            output += ',';
        const auto domain = static_cast<domain_t>(index);
        output += "{\"name\":\"";
        output += domain_name(domain);
        output += "\",\"active\":" + std::to_string(snapshot.active_per_domain[index]) +
            ",\"submitted\":" + std::to_string(submits_per_domain[index].load()) +
            ",\"rejected\":" + std::to_string(rejects_per_domain[index].load()) +
            ",\"queue\":\"" + domain_to_queue_name(domain) + "\"}";
    }
    output += "],\"labels_under_pressure\":\"";
    json_append_escaped(output, snapshot.labels_under_pressure);
    output += "\",\"reject_reasons\":[";
    {
        std::lock_guard<std::mutex> lock(g_reject_reason_mutex);
        bool first = true;
        for (const auto& entry : g_reject_reasons) {
            if (!first)
                output += ',';
            first = false;
            output += "{\"reason\":\"";
            json_append_escaped(output, entry.first);
            output += "\",\"count\":" + std::to_string(entry.second) + '}';
        }
    }
    std::uint32_t capacity_lease_active = 0;
    for (const auto& job : runtime.active_jobs) {
        if (job.capacity_lease != 0)
            ++capacity_lease_active;
    }
    output += "],\"capacity_lease_active\":" + std::to_string(capacity_lease_active) +
        ",\"taskflow_runtime\":" + taskflow_runtime::snapshot_json_string() + '}';
    return output;
}

struct shutdown_guard_t {
    ~shutdown_guard_t() noexcept { try { static_cast<void>(shutdown()); } catch (...) {} }
};

inline shutdown_guard_t g_shutdown_guard;

static_assert(domain_count == taskflow_runtime::executor_domain_count);

}
