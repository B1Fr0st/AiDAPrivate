#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "win_thread.hpp"
#include "work_queue.hpp"
#include "critical_work_queue.hpp"
#include "../diagnostics/metadata_ring.hpp"
#include "../mcp/downstream_producer_governor.hpp"
#include "../../helpers/diag_log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace aida::executor {

inline constexpr std::size_t kMaxActiveSubmissions = 4096;
inline constexpr std::uint32_t kWaitPollIntervalMs = 5;

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

inline const char* domain_name(domain_t d) {
    switch (d) {
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

inline const char* domain_to_queue_name(domain_t d) {
    switch (d) {
    case domain_t::general: return "work_queue.general";
    case domain_t::service: return "work_queue.service";
    case domain_t::critical: return "critical_work_queue";
    case domain_t::ui_dispatch: return "ui_dispatcher";
    case domain_t::external_tool: return "work_queue.general+capacity_governor";
    case domain_t::long_running: return "work_queue.service+downstream_governor";
    case domain_t::security_liveness: return "critical_work_queue.reserved_p0";
    case domain_t::feature_worker: return "work_queue.general+downstream_governor.feature_worker";
    case domain_t::diagnostics: return "work_queue.general.low_priority";
    default: return "unknown";
    }
}

inline aida::diagnostics::breadcrumb_category_t domain_to_breadcrumb_category(domain_t d) {
    switch (d) {
    case domain_t::general:
    case domain_t::service:
    case domain_t::feature_worker:
        return aida::diagnostics::breadcrumb_category_t::work_queue;
    case domain_t::critical:
    case domain_t::security_liveness:
        return aida::diagnostics::breadcrumb_category_t::critical_queue;
    case domain_t::external_tool:
        return aida::diagnostics::breadcrumb_category_t::capacity_governor;
    case domain_t::long_running:
        return aida::diagnostics::breadcrumb_category_t::downstream_producer;
    case domain_t::ui_dispatch:
        return aida::diagnostics::breadcrumb_category_t::ui_dispatcher;
    case domain_t::diagnostics:
        return aida::diagnostics::breadcrumb_category_t::thread_runtime;
    default:
        return aida::diagnostics::breadcrumb_category_t::thread_runtime;
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

struct active_submission_t {
    std::uint64_t task_id = 0;
    domain_t domain = domain_t::general;
    std::string label;
    std::string owner_subsystem;
    std::uint64_t deadline_ms = 0;
    std::uint64_t submitted_ms = 0;
    std::function<void()> cancel_hook;
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

inline std::atomic<std::uint64_t> total_submits{0};
inline std::atomic<std::uint64_t> total_rejected{0};
inline std::atomic<std::uint64_t> total_ui_wait_rejected{0};
inline std::atomic<std::uint64_t> total_cancels{0};
inline std::atomic<std::uint64_t> total_timeouts{0};

inline std::atomic<std::uint64_t> submits_per_domain[domain_count] = {};
inline std::atomic<std::uint64_t> rejects_per_domain[domain_count] = {};

inline std::atomic<std::uint64_t> g_next_task_id{0};
inline std::atomic<DWORD> g_ui_owner_tid{0};
inline std::atomic<bool> g_shutdown_requested{false};

inline std::mutex g_active_mutex;
inline std::map<std::uint64_t, active_submission_t> g_active_submissions;

inline static const char* taskflow_evaluation_status() {
    return "not_integrated_rejected_by_cxx_standard";
}

inline void set_ui_owner_tid(DWORD tid) {
    g_ui_owner_tid.store(tid, std::memory_order_release);
    diag::log_tagged_fmt("executor",
        "EXECUTOR-UI-OWNER-TID-SET tid=%lu caller_tid=%lu",
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

inline bool is_ui_thread() {
    const DWORD owner = g_ui_owner_tid.load(std::memory_order_acquire);
    if (owner == 0)
        return false;
    return GetCurrentThreadId() == owner;
}

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

inline std::size_t domain_index(domain_t d) {
    return static_cast<std::size_t>(d);
}

inline void emit_breadcrumb(domain_t domain, const char* event, const submission_t& sub, std::uint64_t task_id, std::uint16_t status_code) {
    aida::diagnostics::breadcrumb_options_t opts;
    opts.category = domain_to_breadcrumb_category(domain);
    opts.label = sub.label ? sub.label : "<unnamed>";
    opts.reason = event;
    opts.owner_subsystem = sub.owner_subsystem ? sub.owner_subsystem : "<unknown>";
    opts.tool_or_request_id = sub.request_id ? sub.request_id : (sub.diagnostic_id ? sub.diagnostic_id : nullptr);
    opts.session_or_target = sub.session_id ? sub.session_id : (sub.target_id ? sub.target_id : nullptr);
    opts.lease_token = sub.lease_token;
    opts.generation = sub.generation;
    opts.status_code = status_code;
    opts.priority = static_cast<std::uint8_t>(sub.priority > 5 ? 5 : sub.priority);
    aida::diagnostics::emit(std::move(opts));
}

inline bool store_active_submission(std::uint64_t task_id, const submission_t& sub) {
    std::lock_guard<std::mutex> lk(g_active_mutex);
    if (g_active_submissions.size() >= kMaxActiveSubmissions) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-ACTIVE-MAP-FULL task_id=%llu label=%s owner=%s size=%zu max=%zu",
            static_cast<unsigned long long>(task_id),
            sub.label ? sub.label : "<unnamed>",
            sub.owner_subsystem ? sub.owner_subsystem : "<unknown>",
            g_active_submissions.size(),
            kMaxActiveSubmissions);
        return false;
    }
    active_submission_t entry;
    entry.task_id = task_id;
    entry.domain = sub.domain;
    entry.label = sub.label ? sub.label : "<unnamed>";
    entry.owner_subsystem = sub.owner_subsystem ? sub.owner_subsystem : "<unknown>";
    entry.deadline_ms = sub.deadline_ms;
    entry.submitted_ms = now_ms();
    entry.cancel_hook = sub.cancel_hook;
    g_active_submissions[task_id] = std::move(entry);
    return true;
}

inline void remove_active_submission(std::uint64_t task_id) {
    std::lock_guard<std::mutex> lk(g_active_mutex);
    g_active_submissions.erase(task_id);
}

inline submit_result_t submit(submission_t&& sub) {
    submit_result_t result;
    total_submits.fetch_add(1, std::memory_order_acq_rel);

    if (!sub.owner_subsystem || sub.owner_subsystem[0] == '\0') {
        result.reject_reason = "missing_owner_subsystem";
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=missing_owner_subsystem label=%s domain=%s priority=%d tid=%lu",
            sub.label ? sub.label : "<null>",
            domain_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }

    if (!sub.label || sub.label[0] == '\0') {
        result.reject_reason = "missing_label";
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=missing_label owner=%s domain=%s priority=%d tid=%lu",
            sub.owner_subsystem,
            domain_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }

    if (!sub.body) {
        result.reject_reason = "missing_body";
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=missing_body owner=%s label=%s domain=%s priority=%d tid=%lu",
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }

    if (sub.domain == domain_t::ui_dispatch && is_ui_thread()) {
        total_ui_wait_rejected.fetch_add(1, std::memory_order_acq_rel);
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        result.reject_reason = "EXECUTOR-UI-WAIT-REJECTED";
        diag::log_tagged_fmt("executor",
            "EXECUTOR-UI-WAIT-REJECTED owner=%s label=%s domain=ui_dispatch priority=%d thread_class=%s session=%s target=%s diag_id=%s request_id=%s tid=%lu",
            sub.owner_subsystem,
            sub.label,
            sub.priority,
            sub.thread_class ? sub.thread_class : "<none>",
            sub.session_id ? sub.session_id : "<none>",
            sub.target_id ? sub.target_id : "<none>",
            sub.diagnostic_id ? sub.diagnostic_id : "<none>",
            sub.request_id ? sub.request_id : "<none>",
            static_cast<unsigned long>(GetCurrentThreadId()));
        emit_breadcrumb(sub.domain, "EXECUTOR-UI-WAIT-REJECTED", sub, 0, 1);
        return result;
    }

    if (g_shutdown_requested.load(std::memory_order_acquire)) {
        result.reject_reason = "executor_shutdown_requested";
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=executor_shutdown_requested owner=%s label=%s domain=%s priority=%d tid=%lu",
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }

    const std::uint64_t task_id = g_next_task_id.fetch_add(1, std::memory_order_acq_rel) + 1;

    diag::log_tagged_fmt("executor",
        "EXECUTOR-SUBMIT task_id=%llu owner=%s label=%s domain=%s queue=%s priority=%d thread_class=%s deadline_ms=%llu capacity_lease=%llu no_capacity_reason=%s session=%s target=%s target_pid=%u lease_token=%llu generation=%llu diag_id=%s request_id=%s ui_access=%s failure_policy=%s shutdown_policy=%s tid=%lu",
        static_cast<unsigned long long>(task_id),
        sub.owner_subsystem,
        sub.label,
        domain_name(sub.domain),
        domain_to_queue_name(sub.domain),
        sub.priority,
        sub.thread_class ? sub.thread_class : "<none>",
        static_cast<unsigned long long>(sub.deadline_ms),
        static_cast<unsigned long long>(sub.capacity_lease),
        sub.no_capacity_reason ? sub.no_capacity_reason : "<none>",
        sub.session_id ? sub.session_id : "<none>",
        sub.target_id ? sub.target_id : "<none>",
        static_cast<unsigned>(sub.target_pid),
        static_cast<unsigned long long>(sub.lease_token),
        static_cast<unsigned long long>(sub.generation),
        sub.diagnostic_id ? sub.diagnostic_id : "<none>",
        sub.request_id ? sub.request_id : "<none>",
        sub.ui_access_policy ? sub.ui_access_policy : "none",
        sub.failure_policy ? sub.failure_policy : "reject_not_started",
        sub.shutdown_policy ? sub.shutdown_policy : "drain",
        static_cast<unsigned long>(GetCurrentThreadId()));

    bool posted = false;
    std::string post_reject_reason;

    auto body_fn = [task_id, owner = std::string(sub.owner_subsystem), label = std::string(sub.label), domain = sub.domain, body = std::move(sub.body)]() mutable {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-START task_id=%llu owner=%s label=%s domain=%s queue=%s tid=%lu note=start_observed_via_queue_diagnostics",
            static_cast<unsigned long long>(task_id),
            owner.c_str(),
            label.c_str(),
            domain_name(domain),
            domain_to_queue_name(domain),
            static_cast<unsigned long>(GetCurrentThreadId()));
        body();
        diag::log_tagged_fmt("executor",
            "EXECUTOR-FINISH task_id=%llu owner=%s label=%s domain=%s queue=%s tid=%lu note=finish_observed_via_queue_diagnostics",
            static_cast<unsigned long long>(task_id),
            owner.c_str(),
            label.c_str(),
            domain_name(domain),
            domain_to_queue_name(domain),
            static_cast<unsigned long>(GetCurrentThreadId()));
        remove_active_submission(task_id);
    };

    switch (sub.domain) {
    case domain_t::general:
        posted = work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "work_queue_general_post_failed";
        break;
    case domain_t::service:
        posted = work_queue::post_service_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "work_queue_service_post_failed";
        break;
    case domain_t::critical:
        posted = critical_work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "critical_work_queue_post_failed";
        break;
    case domain_t::ui_dispatch:
        posted = work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "ui_dispatch_work_queue_post_failed";
        break;
    case domain_t::external_tool: {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        diag::log_tagged_fmt("executor",
            "EXECUTOR-CAPACITY-AWARE domain=external_tool task_id=%llu label=%s governor_total_active=%zu governor_total_rejected=%zu p0_reserve=%zu p1_reserve=%zu",
            static_cast<unsigned long long>(task_id),
            sub.label,
            gov_snap.total_active,
            gov_snap.total_rejected,
            gov_snap.p0_reserve_available,
            gov_snap.p1_reserve_available);
        posted = work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "external_tool_work_queue_post_failed";
        break;
    }
    case domain_t::long_running: {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        diag::log_tagged_fmt("executor",
            "EXECUTOR-DOWNSTREAM-AWARE domain=long_running task_id=%llu label=%s governor_total_active=%zu governor_total_rejected=%zu shutdown_pending=%zu",
            static_cast<unsigned long long>(task_id),
            sub.label,
            gov_snap.total_active,
            gov_snap.total_rejected,
            gov_snap.shutdown_pending);
        posted = work_queue::post_service_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "long_running_service_post_failed";
        break;
    }
    case domain_t::security_liveness:
        posted = critical_work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "security_liveness_critical_queue_post_failed";
        break;
    case domain_t::feature_worker: {
        auto gov_snap = mcp_standalone::downstream::governor_t::instance().snapshot();
        std::size_t fw_active = 0;
        auto it = gov_snap.by_kind.find("feature_worker");
        if (it != gov_snap.by_kind.end())
            fw_active = it->second.active;
        diag::log_tagged_fmt("executor",
            "EXECUTOR-FEATURE-WORKER-AWARE domain=feature_worker task_id=%llu label=%s governor_fw_active=%zu governor_fw_total_admitted=%llu",
            static_cast<unsigned long long>(task_id),
            sub.label,
            fw_active,
            it != gov_snap.by_kind.end() ? static_cast<unsigned long long>(it->second.total_admitted) : 0ULL);
        posted = work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "feature_worker_work_queue_post_failed";
        break;
    }
    case domain_t::diagnostics:
        posted = work_queue::post_labeled(sub.label, std::move(body_fn));
        if (!posted) post_reject_reason = "diagnostics_work_queue_post_failed";
        break;
    default:
        post_reject_reason = "unknown_domain";
        break;
    }

    if (!posted) {
        total_rejected.fetch_add(1, std::memory_order_acq_rel);
        rejects_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);
        result.reject_reason = post_reject_reason;
        diag::log_tagged_fmt("executor",
            "EXECUTOR-REJECT reason=%s task_id=%llu owner=%s label=%s domain=%s queue=%s priority=%d tid=%lu",
            post_reject_reason.c_str(),
            static_cast<unsigned long long>(task_id),
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain),
            domain_to_queue_name(sub.domain),
            sub.priority,
            static_cast<unsigned long>(GetCurrentThreadId()));
        emit_breadcrumb(sub.domain, "EXECUTOR-REJECT", sub, task_id, 2);
        return result;
    }

    submits_per_domain[domain_index(sub.domain)].fetch_add(1, std::memory_order_acq_rel);

    if (!store_active_submission(task_id, sub)) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-ACTIVE-STORE-FAILED task_id=%llu owner=%s label=%s domain=%s note=task_posted_but_not_tracked_for_cancel",
            static_cast<unsigned long long>(task_id),
            sub.owner_subsystem,
            sub.label,
            domain_name(sub.domain));
    }

    emit_breadcrumb(sub.domain, "EXECUTOR-SUBMIT", sub, task_id, 0);

    result.submitted = true;
    result.task_id = task_id;
    return result;
}

inline active_snapshot_t active_snapshot() {
    active_snapshot_t snap;

    auto wq_stats = work_queue::stats();
    auto svc_stats = work_queue::service_stats();
    auto crit_stats = critical_work_queue::stats();

    snap.work_queue_active = wq_stats.active;
    snap.service_queue_active = svc_stats.active;
    snap.critical_queue_active = crit_stats.active;
    snap.work_queue_pending = wq_stats.pending;
    snap.service_queue_pending = svc_stats.pending;
    snap.critical_queue_pending = crit_stats.pending;
    snap.total_active = wq_stats.active + svc_stats.active + crit_stats.active;

    std::uint64_t oldest = 0;
    if (wq_stats.oldest_active_ms > oldest) oldest = wq_stats.oldest_active_ms;
    if (svc_stats.oldest_active_ms > oldest) oldest = svc_stats.oldest_active_ms;
    if (crit_stats.oldest_active_ms > oldest) oldest = crit_stats.oldest_active_ms;
    snap.oldest_active_ms = oldest;

    {
        std::unique_lock<std::mutex> lk(g_active_mutex, std::try_to_lock);
        if (lk.owns_lock()) {
            const std::uint64_t now = now_ms();
            for (const auto& kv : g_active_submissions) {
                const auto& entry = kv.second;
                std::size_t idx = domain_index(entry.domain);
                if (idx < domain_count)
                    ++snap.active_per_domain[idx];
                const std::uint64_t age = now >= entry.submitted_ms ? now - entry.submitted_ms : 0;
                if (age > snap.oldest_active_ms)
                    snap.oldest_active_ms = age;
            }
        }
    }

    if (!wq_stats.active_labels.empty()) {
        if (snap.labels_under_pressure.empty())
            snap.labels_under_pressure = "wq:" + wq_stats.active_labels;
        else
            snap.labels_under_pressure += ";wq:" + wq_stats.active_labels;
    }
    if (!crit_stats.active_labels.empty()) {
        if (snap.labels_under_pressure.empty())
            snap.labels_under_pressure = "crit:" + crit_stats.active_labels;
        else
            snap.labels_under_pressure += ";crit:" + crit_stats.active_labels;
    }

    return snap;
}

inline wait_result_t wait_for(std::uint64_t task_id, std::uint32_t timeout_ms) {
    wait_result_t result;

    if (is_ui_thread()) {
        result.rejected = true;
        total_ui_wait_rejected.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-UI-WAIT-REJECTED reason=wait_for_from_ui_thread task_id=%llu timeout_ms=%u tid=%lu",
            static_cast<unsigned long long>(task_id),
            static_cast<unsigned>(timeout_ms),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return result;
    }

    if (task_id == 0) {
        result.completed = true;
        return result;
    }

    {
        std::lock_guard<std::mutex> lk(g_active_mutex);
        if (g_active_submissions.find(task_id) == g_active_submissions.end()) {
            result.completed = true;
            return result;
        }
    }

    const std::uint64_t start = now_ms();
    const std::uint64_t deadline = start + static_cast<std::uint64_t>(timeout_ms);

    while (true) {
        const std::uint64_t current = now_ms();
        if (current >= deadline) {
            result.timed_out = true;
            diag::log_tagged_fmt("executor",
                "EXECUTOR-TIMEOUT task_id=%llu timeout_ms=%u elapsed_ms=%llu tid=%lu note=bounded_wait_expired",
                static_cast<unsigned long long>(task_id),
                static_cast<unsigned>(timeout_ms),
                static_cast<unsigned long long>(current - start),
                static_cast<unsigned long>(GetCurrentThreadId()));
            return result;
        }

        {
            std::lock_guard<std::mutex> lk(g_active_mutex);
            if (g_active_submissions.find(task_id) == g_active_submissions.end()) {
                result.completed = true;
                return result;
            }
        }

        Sleep(kWaitPollIntervalMs);
    }
}

inline bool cancel(std::uint64_t task_id) {
    if (task_id == 0)
        return false;

    active_submission_t entry;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_active_mutex);
        auto it = g_active_submissions.find(task_id);
        if (it != g_active_submissions.end()) {
            entry = it->second;
            found = true;
            g_active_submissions.erase(it);
        }
    }

    if (!found) {
        diag::log_tagged_fmt("executor",
            "EXECUTOR-CANCEL task_id=%llu result=not_found tid=%lu",
            static_cast<unsigned long long>(task_id),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }

    total_cancels.fetch_add(1, std::memory_order_acq_rel);

    if (entry.cancel_hook) {
        try {
            entry.cancel_hook();
        } catch (const std::exception& ex) {
            diag::log_tagged_fmt("executor",
                "EXECUTOR-CANCEL-HOOK-EXCEPTION task_id=%llu label=%s err=%s tid=%lu",
                static_cast<unsigned long long>(task_id),
                entry.label.c_str(),
                ex.what(),
                static_cast<unsigned long>(GetCurrentThreadId()));
        } catch (...) {
            diag::log_tagged_fmt("executor",
                "EXECUTOR-CANCEL-HOOK-EXCEPTION task_id=%llu label=%s err=unknown tid=%lu",
                static_cast<unsigned long long>(task_id),
                entry.label.c_str(),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
    }

    diag::log_tagged_fmt("executor",
        "EXECUTOR-CANCEL task_id=%llu result=cancelled label=%s owner=%s domain=%s deadline_ms=%llu tid=%lu",
        static_cast<unsigned long long>(task_id),
        entry.label.c_str(),
        entry.owner_subsystem.c_str(),
        domain_name(entry.domain),
        static_cast<unsigned long long>(entry.deadline_ms),
        static_cast<unsigned long>(GetCurrentThreadId()));

    aida::diagnostics::breadcrumb_options_t opts;
    opts.category = domain_to_breadcrumb_category(entry.domain);
    opts.label = entry.label.c_str();
    opts.reason = "EXECUTOR-CANCEL";
    opts.owner_subsystem = entry.owner_subsystem.c_str();
    opts.status_code = 3;
    aida::diagnostics::emit(std::move(opts));

    return true;
}

inline void check_deadlines() {
    const std::uint64_t now = now_ms();
    std::vector<std::uint64_t> expired_ids;
    std::vector<std::string> expired_labels;
    std::vector<domain_t> expired_domains;
    std::vector<std::uint64_t> expired_deadlines;

    {
        std::lock_guard<std::mutex> lk(g_active_mutex);
        for (const auto& kv : g_active_submissions) {
            const auto& entry = kv.second;
            if (entry.deadline_ms == 0)
                continue;
            if (now >= entry.deadline_ms) {
                expired_ids.push_back(kv.first);
                expired_labels.push_back(entry.label);
                expired_domains.push_back(entry.domain);
                expired_deadlines.push_back(entry.deadline_ms);
            }
        }
    }

    for (std::size_t i = 0; i < expired_ids.size(); ++i) {
        total_timeouts.fetch_add(1, std::memory_order_acq_rel);
        diag::log_tagged_fmt("executor",
            "EXECUTOR-TIMEOUT task_id=%llu label=%s domain=%s deadline_ms=%llu now_ms=%llu overdue_ms=%llu tid=%lu note=deadline_exceeded_still_active",
            static_cast<unsigned long long>(expired_ids[i]),
            expired_labels[i].c_str(),
            domain_name(expired_domains[i]),
            static_cast<unsigned long long>(expired_deadlines[i]),
            static_cast<unsigned long long>(now),
            static_cast<unsigned long long>(now - expired_deadlines[i]),
            static_cast<unsigned long>(GetCurrentThreadId()));

        aida::diagnostics::breadcrumb_options_t opts;
        opts.category = domain_to_breadcrumb_category(expired_domains[i]);
        opts.label = expired_labels[i].c_str();
        opts.reason = "EXECUTOR-TIMEOUT";
        opts.status_code = 4;
        aida::diagnostics::emit(std::move(opts));
    }
}

inline void shutdown() {
    g_shutdown_requested.store(true, std::memory_order_release);

    auto snap = active_snapshot();
    diag::log_tagged_fmt("executor",
        "EXECUTOR-SNAPSHOT phase=pre_shutdown total_active=%u work_queue_active=%u service_queue_active=%u critical_queue_active=%u work_queue_pending=%llu service_queue_pending=%llu critical_queue_pending=%llu oldest_active_ms=%llu total_submits=%llu total_rejected=%llu total_ui_wait_rejected=%llu total_cancels=%llu total_timeouts=%llu labels_under_pressure=%.800s tid=%lu",
        static_cast<unsigned>(snap.total_active),
        static_cast<unsigned>(snap.work_queue_active),
        static_cast<unsigned>(snap.service_queue_active),
        static_cast<unsigned>(snap.critical_queue_active),
        static_cast<unsigned long long>(snap.work_queue_pending),
        static_cast<unsigned long long>(snap.service_queue_pending),
        static_cast<unsigned long long>(snap.critical_queue_pending),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        static_cast<unsigned long long>(total_submits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_ui_wait_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_cancels.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_timeouts.load(std::memory_order_acquire)),
        snap.labels_under_pressure.c_str(),
        static_cast<unsigned long>(GetCurrentThreadId()));

    aida::diagnostics::breadcrumb_options_t opts;
    opts.category = aida::diagnostics::breadcrumb_category_t::startup_shutdown;
    opts.label = "executor_shutdown";
    opts.reason = "EXECUTOR-SNAPSHOT";
    opts.owner_subsystem = "executor";
    opts.status_code = 5;
    aida::diagnostics::emit(std::move(opts));

    {
        std::lock_guard<std::mutex> lk(g_active_mutex);
        std::size_t remaining = g_active_submissions.size();
        if (remaining > 0) {
            diag::log_tagged_fmt("executor",
                "EXECUTOR-SHUTDOWN-ACTIVE-REMAINING count=%zu note=active_submissions_not_removed_queues_will_drain",
                remaining);
        }
    }

    work_queue::shutdown();
    critical_work_queue::shutdown();

    diag::log_tagged_fmt("executor",
        "EXECUTOR-SHUTDOWN-COMPLETE tid=%lu",
        static_cast<unsigned long>(GetCurrentThreadId()));
}

inline std::string snapshot_json_string() {
    auto snap = active_snapshot();
    std::string out;
    out.reserve(4096);
    char buf[512];

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"total_submits\":%llu,\"total_rejected\":%llu,\"total_ui_wait_rejected\":%llu,\"total_cancels\":%llu,\"total_timeouts\":%llu,"
        "\"taskflow_evaluation_status\":\"%s\","
        "\"oldest_active_ms\":%llu,\"total_active\":%u,\"work_queue_active\":%u,\"service_queue_active\":%u,\"critical_queue_active\":%u,"
        "\"work_queue_pending\":%llu,\"service_queue_pending\":%llu,\"critical_queue_pending\":%llu,"
        "\"domains\":[",
        static_cast<unsigned long long>(total_submits.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_ui_wait_rejected.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_cancels.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(total_timeouts.load(std::memory_order_acquire)),
        taskflow_evaluation_status(),
        static_cast<unsigned long long>(snap.oldest_active_ms),
        static_cast<unsigned>(snap.total_active),
        static_cast<unsigned>(snap.work_queue_active),
        static_cast<unsigned>(snap.service_queue_active),
        static_cast<unsigned>(snap.critical_queue_active),
        static_cast<unsigned long long>(snap.work_queue_pending),
        static_cast<unsigned long long>(snap.service_queue_pending),
        static_cast<unsigned long long>(snap.critical_queue_pending));
    out += buf;

    const char* domain_names[] = {
        "general", "service", "critical", "ui_dispatch",
        "external_tool", "long_running", "security_liveness",
        "feature_worker", "diagnostics"
    };

    for (std::size_t i = 0; i < domain_count; ++i) {
        if (i > 0) out += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"name\":\"%s\",\"active\":%u,\"submitted\":%llu,\"rejected\":%llu,\"queue\":\"%s\"}",
            domain_names[i],
            static_cast<unsigned>(snap.active_per_domain[i]),
            static_cast<unsigned long long>(submits_per_domain[i].load(std::memory_order_acquire)),
            static_cast<unsigned long long>(rejects_per_domain[i].load(std::memory_order_acquire)),
            domain_to_queue_name(static_cast<domain_t>(i)));
        out += buf;
    }

    out += "],\"labels_under_pressure\":\"";
    for (char c : snap.labels_under_pressure) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    out += "\"}";
    return out;
}

struct shutdown_guard_t {
    ~shutdown_guard_t() { shutdown(); }
};

inline shutdown_guard_t g_shutdown_guard;

}
