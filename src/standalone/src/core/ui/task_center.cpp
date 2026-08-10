#include "task_center.hpp"

#include "../infra/executor.hpp"
#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"
#include "toast_notification.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "imgui/imgui.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/studio_semantics.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <mutex>
#include <unordered_set>
#include <utility>

namespace aida::ui::task_center {
namespace {

constexpr std::size_t k_success_limit = 256;
constexpr std::size_t k_failure_limit = 512;
constexpr std::size_t k_active_limit = 2048;
constexpr std::uint64_t k_success_retention_ms = 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t k_failure_retention_ms = 7ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t k_refresh_interval_ms = 100ULL;

struct record_t {
    task_snapshot_t snapshot;
    task_callbacks_t callbacks;
    std::shared_ptr<aida::analysis::analysis_scheduler_t> analysis_scheduler;
    aida::analysis::analysis_task_id_t analysis_task_id = 0;
    std::uint64_t runtime_job_id = 0;
    bool runtime_observed = false;
    bool explicit_registration = false;
};

struct diagnostic_record_t {
    diagnostic_snapshot_t snapshot;
    task_callbacks_t callbacks;
};

struct state_t {
    std::mutex mutex;
    std::map<std::string, record_t> records;
    std::map<std::string, diagnostic_record_t> diagnostics;
    immutable_snapshot_ptr published = std::make_shared<const immutable_snapshot_t>();
    std::uint64_t generation = 0;
    std::atomic<std::uint64_t> next_refresh_ms{0};
    std::atomic_flag refresh_in_progress = ATOMIC_FLAG_INIT;
};

state_t& state() {
    static state_t value;
    return value;
}

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool active_state(task_state_t state_value) {
    return state_value == task_state_t::queued || state_value == task_state_t::running ||
           state_value == task_state_t::cancellation_requested;
}

bool failure_state(task_state_t state_value) {
    return state_value == task_state_t::failed || state_value == task_state_t::timed_out ||
           state_value == task_state_t::interrupted || state_value == task_state_t::partial;
}

bool failure_retention_state(task_state_t state_value) {
    return failure_state(state_value) || state_value == task_state_t::cancelled;
}

std::string bounded_redacted(std::string value, std::size_t limit = 256) {
    for (char& ch : value) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 && ch != '\t')
            ch = ' ';
    }
    const std::string lower = [&] {
        std::string result = value;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return result;
    }();
    static const char* sensitive[] = {
        "authorization:", "bearer ", "api_key", "apikey", "private key",
        "session_token", "access_token", "refresh_token", "license_key"
    };
    for (const char* marker : sensitive) {
        if (lower.find(marker) != std::string::npos)
            return "[redacted sensitive task detail]";
    }
    if (value.size() > limit)
        value.resize(limit);
    return value;
}

void sanitize(task_snapshot_t& item) {
    item.id = bounded_redacted(std::move(item.id), 160);
    item.source = bounded_redacted(std::move(item.source), 64);
    item.owner = bounded_redacted(std::move(item.owner), 96);
    item.owner_view = bounded_redacted(std::move(item.owner_view), 128);
    item.owner_action = bounded_redacted(std::move(item.owner_action), 128);
    item.project = bounded_redacted(std::move(item.project), 128);
    item.session = bounded_redacted(std::move(item.session), 128);
    item.target = bounded_redacted(std::move(item.target), 192);
    item.label = bounded_redacted(std::move(item.label), 192);
    item.stage = bounded_redacted(std::move(item.stage), 160);
    item.result_summary = bounded_redacted(std::move(item.result_summary), 320);
    item.diagnostic_id = bounded_redacted(std::move(item.diagnostic_id), 160);
    item.log_link = bounded_redacted(std::move(item.log_link), 192);
    item.affected_entity = bounded_redacted(std::move(item.affected_entity), 192);
    if (!std::isfinite(item.progress) || item.progress < 0.0f)
        item.progress = -1.0f;
    else
        item.progress = (std::min)(1.0f, item.progress);
}

void sanitize(diagnostic_snapshot_t& item) {
    item.id = bounded_redacted(std::move(item.id), 160);
    item.task_id = bounded_redacted(std::move(item.task_id), 160);
    item.owner = bounded_redacted(std::move(item.owner), 96);
    item.target = bounded_redacted(std::move(item.target), 192);
    item.summary = bounded_redacted(std::move(item.summary), 320);
    item.details = bounded_redacted(std::move(item.details), 1024);
    item.log_link = bounded_redacted(std::move(item.log_link), 192);
}

const char* state_name(task_state_t value) {
    switch (value) {
    case task_state_t::queued: return "Queued";
    case task_state_t::running: return "Running";
    case task_state_t::cancellation_requested: return "Cancel requested";
    case task_state_t::completed: return "Completed";
    case task_state_t::partial: return "Partial";
    case task_state_t::cancelled: return "Cancelled";
    case task_state_t::failed: return "Failed";
    case task_state_t::timed_out: return "Timed out";
    case task_state_t::interrupted: return "Interrupted";
    }
    return "Unknown";
}

task_state_t runtime_state(aida::infra::taskflow_runtime::job_state_t value, bool cancellation_requested) {
    if (cancellation_requested)
        return task_state_t::cancellation_requested;
    switch (value) {
    case aida::infra::taskflow_runtime::job_state_t::queued:
    case aida::infra::taskflow_runtime::job_state_t::not_started: return task_state_t::queued;
    case aida::infra::taskflow_runtime::job_state_t::running: return task_state_t::running;
    case aida::infra::taskflow_runtime::job_state_t::completed: return task_state_t::completed;
    case aida::infra::taskflow_runtime::job_state_t::cancelled: return task_state_t::cancelled;
    case aida::infra::taskflow_runtime::job_state_t::failed: return task_state_t::failed;
    case aida::infra::taskflow_runtime::job_state_t::timed_out: return task_state_t::timed_out;
    }
    return task_state_t::failed;
}

task_state_t analysis_state(aida::analysis::analysis_task_state_t value, bool cancellation_requested) {
    if (cancellation_requested)
        return task_state_t::cancellation_requested;
    switch (value) {
    case aida::analysis::analysis_task_state_t::queued:
    case aida::analysis::analysis_task_state_t::dispatched: return task_state_t::queued;
    case aida::analysis::analysis_task_state_t::running: return task_state_t::running;
    case aida::analysis::analysis_task_state_t::completed: return task_state_t::completed;
    case aida::analysis::analysis_task_state_t::cancelled: return task_state_t::cancelled;
    case aida::analysis::analysis_task_state_t::failed: return task_state_t::failed;
    }
    return task_state_t::failed;
}

void retain_locked(state_t& store, std::uint64_t now) {
    std::vector<std::pair<std::uint64_t, std::string>> successes;
    std::vector<std::pair<std::uint64_t, std::string>> failures;
    std::vector<std::pair<std::uint64_t, std::string>> active;
    for (const auto& entry : store.records) {
        const task_snapshot_t& item = entry.second.snapshot;
        const std::uint64_t ended = item.ended_ms;
        if (active_state(item.state)) {
            active.emplace_back(item.queued_ms, entry.first);
        } else if (failure_retention_state(item.state)) {
            failures.emplace_back(ended, entry.first);
        } else if (ended != 0 && now >= ended && now - ended > k_success_retention_ms) {
            successes.emplace_back(ended, entry.first);
        } else {
            successes.emplace_back(ended, entry.first);
        }
    }
    auto oldest_first = [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; };
    std::sort(successes.begin(), successes.end(), oldest_first);
    std::sort(failures.begin(), failures.end(), oldest_first);
    std::sort(active.begin(), active.end(), oldest_first);
    std::unordered_set<std::string> erase;
    if (successes.size() > k_success_limit)
        for (std::size_t index = 0; index < successes.size() - k_success_limit; ++index)
            erase.insert(successes[index].second);
    for (const auto& item : successes) {
        const auto found = store.records.find(item.second);
        if (found != store.records.end() && found->second.snapshot.ended_ms != 0 &&
            now >= found->second.snapshot.ended_ms && now - found->second.snapshot.ended_ms > k_success_retention_ms)
            erase.insert(item.second);
    }
    if (failures.size() > k_failure_limit)
        for (std::size_t index = 0; index < failures.size() - k_failure_limit; ++index)
            erase.insert(failures[index].second);
    for (const auto& item : failures) {
        const auto found = store.records.find(item.second);
        if (found != store.records.end() && (found->second.snapshot.acknowledged ||
            (found->second.snapshot.ended_ms != 0 && now >= found->second.snapshot.ended_ms &&
             now - found->second.snapshot.ended_ms > k_failure_retention_ms)))
            erase.insert(item.second);
    }
    if (active.size() > k_active_limit)
        for (std::size_t index = 0; index < active.size() - k_active_limit; ++index)
            erase.insert(active[index].second);
    for (const std::string& id : erase)
        store.records.erase(id);

    std::vector<std::pair<std::uint64_t, std::string>> expired_diagnostics;
    for (const auto& entry : store.diagnostics) {
        const auto& item = entry.second.snapshot;
        if (item.acknowledged || (item.raised_ms != 0 && now >= item.raised_ms && now - item.raised_ms > k_failure_retention_ms))
            expired_diagnostics.emplace_back(item.raised_ms, entry.first);
    }
    std::sort(expired_diagnostics.begin(), expired_diagnostics.end(), oldest_first);
    for (const auto& item : expired_diagnostics)
        store.diagnostics.erase(item.second);
    if (store.diagnostics.size() > k_failure_limit) {
        std::vector<std::pair<std::uint64_t, std::string>> all;
        for (const auto& entry : store.diagnostics)
            all.emplace_back(entry.second.snapshot.raised_ms, entry.first);
        std::sort(all.begin(), all.end(), oldest_first);
        for (std::size_t index = 0; index < all.size() - k_failure_limit; ++index)
            store.diagnostics.erase(all[index].second);
    }
}

void publish_locked(state_t& store, std::uint64_t now) {
    retain_locked(store, now);
    auto next = std::make_shared<immutable_snapshot_t>();
    next->captured_ms = now;
    next->generation = ++store.generation;
    next->tasks.reserve(store.records.size());
    for (const auto& entry : store.records) {
        task_snapshot_t item = entry.second.snapshot;
        if (active_state(item.state)) {
            const std::uint64_t base = item.started_ms != 0 ? item.started_ms : item.queued_ms;
            item.elapsed_ms = base != 0 && now >= base ? now - base : 0;
        }
        next->tasks.push_back(std::move(item));
    }
    std::sort(next->tasks.begin(), next->tasks.end(), [](const task_snapshot_t& lhs, const task_snapshot_t& rhs) {
        if (active_state(lhs.state) != active_state(rhs.state))
            return active_state(lhs.state);
        const std::uint64_t left = lhs.started_ms != 0 ? lhs.started_ms : lhs.queued_ms;
        const std::uint64_t right = rhs.started_ms != 0 ? rhs.started_ms : rhs.queued_ms;
        return left > right;
    });
    next->diagnostics.reserve(store.diagnostics.size());
    for (const auto& entry : store.diagnostics)
        next->diagnostics.push_back(entry.second.snapshot);
    std::sort(next->diagnostics.begin(), next->diagnostics.end(),
        [](const diagnostic_snapshot_t& lhs, const diagnostic_snapshot_t& rhs) { return lhs.raised_ms > rhs.raised_ms; });
    for (const auto& item : next->tasks) {
        if (item.state == task_state_t::queued)
            ++next->status.queued;
        else if (item.state == task_state_t::running)
            ++next->status.running;
        else if (item.state == task_state_t::cancellation_requested)
            ++next->status.cancellation_requested;
        if (item.state == task_state_t::failed || item.state == task_state_t::timed_out)
            ++next->status.failures;
        else if (item.state == task_state_t::interrupted)
            ++next->status.interrupted;
        else if (item.state == task_state_t::partial)
            ++next->status.partial;
        if (active_state(item.state))
            next->status.oldest_active_ms = (std::max)(next->status.oldest_active_ms, item.elapsed_ms);
    }
    for (const auto& item : next->diagnostics)
        if (!item.acknowledged)
            ++next->status.unacknowledged_diagnostics;
    next->status.generation = next->generation;
    std::atomic_store_explicit(&store.published,
        std::static_pointer_cast<const immutable_snapshot_t>(next), std::memory_order_release);
}

void ensure_failure_diagnostic_locked(state_t& store, const record_t& record) {
    const task_snapshot_t& item = record.snapshot;
    if (!failure_state(item.state))
        return;
    diagnostic_record_t diagnostic;
    diagnostic.snapshot.id = item.diagnostic_id.empty() ? "diagnostic." + item.id : item.diagnostic_id;
    diagnostic.snapshot.task_id = item.id;
    diagnostic.snapshot.owner = item.owner;
    diagnostic.snapshot.target = item.target;
    diagnostic.snapshot.summary = item.result_summary.empty() ? item.label + " did not complete" : item.result_summary;
    diagnostic.snapshot.details = item.stage;
    diagnostic.snapshot.log_link = item.log_link;
    diagnostic.snapshot.severity = item.security_critical ? diagnostic_severity_t::security : diagnostic_severity_t::error;
    diagnostic.snapshot.raised_ms = item.ended_ms != 0 ? item.ended_ms : now_ms();
    diagnostic.snapshot.retryable = item.retryable;
    diagnostic.snapshot.focusable = item.focusable;
    diagnostic.snapshot.log_available = item.log_available;
    diagnostic.callbacks = record.callbacks;
    sanitize(diagnostic.snapshot);
    store.diagnostics[diagnostic.snapshot.id] = std::move(diagnostic);
}

std::string runtime_id(std::uint64_t id) {
    return "task.runtime." + std::to_string(id);
}

std::string analysis_id(aida::analysis::analysis_task_id_t id) {
    return "task.analysis." + std::to_string(id);
}

}

static bool register_task_impl(task_registration_t registration,
                        std::uint64_t runtime_job_id,
                        bool try_only) {
    if (registration.id.empty() || registration.label.empty() || registration.owner.empty())
        return false;
    record_t record;
    record.snapshot.id = std::move(registration.id);
    record.snapshot.source = registration.source.empty() ? "owner" : std::move(registration.source);
    record.snapshot.owner = std::move(registration.owner);
    record.snapshot.owner_view = std::move(registration.owner_view);
    record.snapshot.owner_action = std::move(registration.owner_action);
    record.snapshot.project = std::move(registration.project);
    record.snapshot.session = std::move(registration.session);
    record.snapshot.target = std::move(registration.target);
    record.snapshot.label = std::move(registration.label);
    record.snapshot.stage = std::move(registration.stage);
    record.snapshot.affected_entity = std::move(registration.affected_entity);
    record.snapshot.queued_ms = registration.queued_ms != 0 ? registration.queued_ms : now_ms();
    record.snapshot.started_ms = registration.started_ms;
    record.snapshot.progress = registration.progress;
    record.snapshot.state = registration.started_ms != 0 ? task_state_t::running : task_state_t::queued;
    record.snapshot.security_critical = registration.security_critical;
    record.callbacks = std::move(registration.callbacks);
    record.runtime_job_id = runtime_job_id;
    record.explicit_registration = true;
    record.snapshot.cancellable = registration.cancellation_is_safe && !record.snapshot.security_critical &&
                                  static_cast<bool>(record.callbacks.cancel);
    record.snapshot.retryable = static_cast<bool>(record.callbacks.retry);
    record.snapshot.focusable = static_cast<bool>(record.callbacks.focus);
    record.snapshot.log_available = static_cast<bool>(record.callbacks.open_log);
    sanitize(record.snapshot);
    const std::string key = record.snapshot.id;
    state_t& store = state();
    std::unique_lock<std::mutex> lock(store.mutex, std::defer_lock);
    if (try_only) {
        if (!lock.try_lock())
            return false;
    } else {
        lock.lock();
    }
    if (store.records.find(key) != store.records.end())
        return false;
    store.records.emplace(key, std::move(record));
    publish_locked(store, now_ms());
    return true;
}

bool register_task(task_registration_t registration) {
    return register_task_impl(std::move(registration), 0, false);
}

bool register_taskflow_job(aida::infra::taskflow_runtime::job_handle_t handle,
                           task_registration_t registration) {
    if (!handle.valid())
        return false;
    if (registration.id.empty())
        registration.id = runtime_id(handle.id);
    if (registration.source.empty())
        registration.source = "taskflow";
    if (registration.cancellation_is_safe && !registration.security_critical &&
        !registration.callbacks.cancel)
        registration.callbacks.cancel = [handle] { return aida::infra::taskflow_runtime::cancel(handle.id); };
    return register_task_impl(std::move(registration), handle.id, false);
}

bool register_executor_job(std::uint64_t task_id, task_registration_t registration) {
    if (task_id == 0)
        return false;
    registration.source = "executor";
    if (registration.id.empty())
        registration.id = runtime_id(task_id);
    if (registration.cancellation_is_safe && !registration.security_critical &&
        !registration.callbacks.cancel)
        registration.callbacks.cancel = [task_id] { return aida::infra::executor::cancel(task_id); };
    return register_taskflow_job({task_id}, std::move(registration));
}

bool try_register_executor_job(std::uint64_t task_id, task_registration_t registration) {
    if (task_id == 0)
        return false;
    registration.source = "executor";
    if (registration.id.empty())
        registration.id = runtime_id(task_id);
    if (registration.cancellation_is_safe && !registration.security_critical &&
        !registration.callbacks.cancel)
        registration.callbacks.cancel = [task_id] { return aida::infra::executor::cancel(task_id); };
    return register_task_impl(std::move(registration), task_id, true);
}

bool register_analysis_task(std::shared_ptr<aida::analysis::analysis_scheduler_t> scheduler,
                            aida::analysis::analysis_task_id_t task_id,
                            task_registration_t registration) {
    if (!scheduler || task_id == 0)
        return false;
    const auto initial = scheduler->task_snapshot(task_id);
    if (!initial.found())
        return false;
    if (registration.id.empty())
        registration.id = analysis_id(task_id);
    registration.source = "analysis_scheduler";
    if (registration.label.empty())
        registration.label = initial.task.label;
    registration.queued_ms = initial.task.submitted_milliseconds;
    registration.started_ms = initial.task.started_milliseconds;
    if (registration.cancellation_is_safe && !registration.security_critical &&
        !registration.callbacks.cancel)
        registration.callbacks.cancel = [scheduler, task_id] {
            const auto result = scheduler->cancel_task(task_id);
            return result.error.ok() && (result.queued_cancelled != 0 || result.active_signalled != 0);
        };
    const std::string key = registration.id;
    if (!register_task(std::move(registration)))
        return false;
    state_t& store = state();
    std::lock_guard<std::mutex> lock(store.mutex);
    const auto found = store.records.find(key);
    if (found != store.records.end()) {
        found->second.analysis_scheduler = std::move(scheduler);
        found->second.analysis_task_id = task_id;
    }
    return true;
}

bool update_task(const std::string& id, task_state_t new_state, float progress,
                 std::string stage, std::string result_summary,
                 std::string diagnostic_id, std::string log_link) {
    state_t& store = state();
    std::string completed_label;
    std::string failed_label;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.records.find(id);
        if (found == store.records.end())
            return false;
        task_snapshot_t& item = found->second.snapshot;
        item.state = new_state;
        item.progress = progress;
        item.stage = std::move(stage);
        item.result_summary = std::move(result_summary);
        item.diagnostic_id = std::move(diagnostic_id);
        item.log_link = std::move(log_link);
        item.log_available = item.log_available || !item.log_link.empty();
        if (new_state == task_state_t::running && item.started_ms == 0)
            item.started_ms = now_ms();
        if (!active_state(new_state))
            item.ended_ms = now_ms();
        if (new_state == task_state_t::cancellation_requested)
            item.cancellable = false;
        sanitize(item);
        if (new_state == task_state_t::completed)
            completed_label = item.label;
        if (failure_state(new_state))
            failed_label = item.label;
        ensure_failure_diagnostic_locked(store, found->second);
        publish_locked(store, now_ms());
    }
    if (!completed_label.empty())
        toast_notification::push("Completed: " + completed_label,
            toast_notification::toast_type_t::success, 3.0f);
    if (!failed_label.empty())
        toast_notification::push("Needs attention: " + failed_label,
            toast_notification::toast_type_t::error, 5.0f);
    return true;
}

bool raise_diagnostic(diagnostic_registration_t registration) {
    if (registration.id.empty() || registration.summary.empty())
        return false;
    diagnostic_record_t record;
    record.snapshot.id = std::move(registration.id);
    record.snapshot.task_id = std::move(registration.task_id);
    record.snapshot.owner = std::move(registration.owner);
    record.snapshot.target = std::move(registration.target);
    record.snapshot.summary = std::move(registration.summary);
    record.snapshot.details = std::move(registration.details);
    record.snapshot.log_link = std::move(registration.log_link);
    record.snapshot.severity = registration.severity;
    record.snapshot.raised_ms = registration.raised_ms != 0 ? registration.raised_ms : now_ms();
    record.callbacks = std::move(registration.callbacks);
    record.snapshot.retryable = static_cast<bool>(record.callbacks.retry);
    record.snapshot.focusable = static_cast<bool>(record.callbacks.focus);
    record.snapshot.log_available = static_cast<bool>(record.callbacks.open_log) || !record.snapshot.log_link.empty();
    sanitize(record.snapshot);
    const std::string key = record.snapshot.id;
    state_t& store = state();
    std::lock_guard<std::mutex> lock(store.mutex);
    const auto found = store.diagnostics.find(key);
    if (found == store.diagnostics.end())
        store.diagnostics.emplace(key, std::move(record));
    else
        found->second = std::move(record);
    publish_locked(store, now_ms());
    return true;
}

bool acknowledge_diagnostic(const std::string& id) {
    state_t& store = state();
    std::lock_guard<std::mutex> lock(store.mutex);
    const auto found = store.diagnostics.find(id);
    if (found == store.diagnostics.end())
        return false;
    found->second.snapshot.acknowledged = true;
    const auto task = store.records.find(found->second.snapshot.task_id);
    if (task != store.records.end())
        task->second.snapshot.acknowledged = true;
    publish_locked(store, now_ms());
    return true;
}

bool retry_diagnostic(const std::string& id) {
    std::function<bool()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.diagnostics.find(id);
        if (found == store.diagnostics.end() || !found->second.callbacks.retry)
            return false;
        callback = found->second.callbacks.retry;
    }
    try {
        return callback();
    } catch (...) {
        return false;
    }
}

bool focus_diagnostic(const std::string& id) {
    std::function<void()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.diagnostics.find(id);
        if (found == store.diagnostics.end() || !found->second.callbacks.focus)
            return false;
        callback = found->second.callbacks.focus;
    }
    try {
        callback();
        return true;
    } catch (...) {
        return false;
    }
}

bool open_diagnostic_log(const std::string& id) {
    std::function<void()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.diagnostics.find(id);
        if (found == store.diagnostics.end() || !found->second.callbacks.open_log)
            return false;
        callback = found->second.callbacks.open_log;
    }
    try {
        callback();
        return true;
    } catch (...) {
        return false;
    }
}

bool request_cancel(const std::string& task_id) {
    std::function<bool()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.records.find(task_id);
        if (found == store.records.end() || !found->second.snapshot.cancellable ||
            found->second.snapshot.security_critical || !found->second.callbacks.cancel)
            return false;
        callback = found->second.callbacks.cancel;
        found->second.snapshot.state = task_state_t::cancellation_requested;
        found->second.snapshot.cancellable = false;
        found->second.snapshot.stage = "Cancellation requested; waiting for owner confirmation";
        publish_locked(store, now_ms());
    }
    try {
        if (callback())
            return true;
    } catch (...) {
    }
    update_task(task_id, task_state_t::failed, -1.0f, "Cancellation request was rejected",
        "The task owner did not accept cancellation");
    return false;
}

bool retry(const std::string& task_id) {
    std::function<bool()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.records.find(task_id);
        if (found == store.records.end() || !found->second.snapshot.retryable || !found->second.callbacks.retry)
            return false;
        callback = found->second.callbacks.retry;
    }
    try {
        return callback();
    } catch (...) {
        return false;
    }
}

bool focus(const std::string& task_id) {
    std::function<void()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.records.find(task_id);
        if (found == store.records.end() || !found->second.snapshot.focusable || !found->second.callbacks.focus)
            return false;
        callback = found->second.callbacks.focus;
    }
    try {
        callback();
        return true;
    } catch (...) {
        return false;
    }
}

bool open_log(const std::string& task_id) {
    std::function<void()> callback;
    {
        state_t& store = state();
        std::lock_guard<std::mutex> lock(store.mutex);
        const auto found = store.records.find(task_id);
        if (found == store.records.end() || !found->second.callbacks.open_log)
            return false;
        callback = found->second.callbacks.open_log;
    }
    try {
        callback();
        return true;
    } catch (...) {
        return false;
    }
}

void refresh() {
    const std::uint64_t now = now_ms();
    state_t& store = state();
    const std::uint64_t scheduled = store.next_refresh_ms.load(std::memory_order_acquire);
    if (scheduled != 0 && now < scheduled)
        return;
    if (store.refresh_in_progress.test_and_set(std::memory_order_acquire))
        return;
    struct refresh_scope_t {
        state_t& store;
        ~refresh_scope_t() { store.refresh_in_progress.clear(std::memory_order_release); }
    } refresh_scope{store};
    std::uint64_t expected = scheduled;
    if (!store.next_refresh_ms.compare_exchange_strong(expected, now + k_refresh_interval_ms,
            std::memory_order_acq_rel, std::memory_order_acquire) && expected != 0 && now < expected)
        return;
    struct analysis_poll_t {
        std::string id;
        std::shared_ptr<aida::analysis::analysis_scheduler_t> scheduler;
        aida::analysis::analysis_task_id_t task_id = 0;
    };
    struct analysis_result_t {
        std::string id;
        aida::analysis::analysis_task_snapshot_result_t result;
    };
    std::vector<analysis_poll_t> analysis_polls;
    {
        std::lock_guard<std::mutex> lock(store.mutex);
        for (const auto& entry : store.records) {
            if (entry.second.analysis_scheduler && entry.second.analysis_task_id != 0)
                analysis_polls.push_back({entry.first, entry.second.analysis_scheduler, entry.second.analysis_task_id});
        }
    }
    const auto runtime = aida::infra::taskflow_runtime::active_snapshot(k_active_limit);
    std::vector<analysis_result_t> analysis_results;
    analysis_results.reserve(analysis_polls.size());
    for (const auto& poll : analysis_polls)
        analysis_results.push_back({poll.id, poll.scheduler->task_snapshot(poll.task_id)});
    std::lock_guard<std::mutex> lock(store.mutex);
    std::unordered_set<std::uint64_t> observed;
    for (const auto& source : runtime.active_jobs) {
        observed.insert(source.job_id);
        std::string key = runtime_id(source.job_id);
        auto found = store.records.find(key);
        if (found == store.records.end()) {
            found = std::find_if(store.records.begin(), store.records.end(), [&source](const auto& entry) {
                return entry.second.runtime_job_id == source.job_id;
            });
            if (found != store.records.end())
                key = found->first;
        }
        if (found == store.records.end()) {
            record_t record;
            record.snapshot.id = key;
            record.snapshot.source = "taskflow";
            record.snapshot.owner = source.owner_subsystem.empty() ? "runtime" : source.owner_subsystem;
            record.snapshot.target = source.target_id;
            record.snapshot.label = source.label.empty() ? "Background work" : source.label;
            record.snapshot.queued_ms = source.queued_ms;
            record.snapshot.started_ms = source.started_ms;
            record.snapshot.state = runtime_state(source.state, source.cancellation_requested);
            record.snapshot.security_critical = source.domain == aida::infra::taskflow_runtime::executor_domain_t::critical ||
                                                source.domain == aida::infra::taskflow_runtime::executor_domain_t::security_liveness;
            record.runtime_job_id = source.job_id;
            record.runtime_observed = true;
            record.explicit_registration = false;
            sanitize(record.snapshot);
            store.records.emplace(key, std::move(record));
        } else {
            task_snapshot_t& item = found->second.snapshot;
            if (!found->second.explicit_registration || active_state(item.state)) {
                item.state = runtime_state(source.state, source.cancellation_requested);
                item.queued_ms = source.queued_ms;
                item.started_ms = source.started_ms;
                item.target = bounded_redacted(source.target_id, 192);
                item.stage = source.graph ? "Graph execution" : state_name(item.state);
                if (source.domain == aida::infra::taskflow_runtime::executor_domain_t::critical ||
                    source.domain == aida::infra::taskflow_runtime::executor_domain_t::security_liveness) {
                    item.security_critical = true;
                    item.cancellable = false;
                }
            }
            found->second.runtime_observed = true;
        }
    }
    for (const auto& polled : analysis_results) {
        const auto found = store.records.find(polled.id);
        if (found == store.records.end() || !polled.result.found())
            continue;
        task_snapshot_t& item = found->second.snapshot;
        if (found->second.explicit_registration && !active_state(item.state))
            continue;
        item.state = analysis_state(polled.result.task.state, polled.result.task.cancellation_requested);
        item.queued_ms = polled.result.task.submitted_milliseconds;
        item.started_ms = polled.result.task.started_milliseconds;
        item.ended_ms = polled.result.task.completed_milliseconds;
        item.label = bounded_redacted(polled.result.task.label, 192);
        if (item.state == task_state_t::cancellation_requested)
            item.cancellable = false;
    }
    std::vector<std::string> remove_untracked;
    for (auto& entry : store.records) {
        record_t& record = entry.second;
        if (record.runtime_observed && record.runtime_job_id != 0 && observed.find(record.runtime_job_id) == observed.end() &&
            active_state(record.snapshot.state)) {
            if (!record.explicit_registration) {
                remove_untracked.push_back(entry.first);
            } else {
                record.snapshot.state = task_state_t::interrupted;
                record.snapshot.ended_ms = now;
                record.snapshot.result_summary = "The runtime stopped reporting this task before its owner published a terminal result";
                record.snapshot.cancellable = false;
            }
        }
    }
    for (const std::string& key : remove_untracked)
        store.records.erase(key);
    for (const auto& entry : store.records)
        ensure_failure_diagnostic_locked(store, entry.second);
    publish_locked(store, now);
}

immutable_snapshot_ptr snapshot() {
    state_t& store = state();
    return std::atomic_load_explicit(&store.published, std::memory_order_acquire);
}

status_summary_t status_summary() {
    const auto current = snapshot();
    return current ? current->status : status_summary_t{};
}

void clear_memory_history() {
    state_t& store = state();
    std::lock_guard<std::mutex> lock(store.mutex);
    for (auto it = store.records.begin(); it != store.records.end();) {
        if (!active_state(it->second.snapshot.state))
            it = store.records.erase(it);
        else
            ++it;
    }
    for (auto it = store.diagnostics.begin(); it != store.diagnostics.end();) {
        if (it->second.snapshot.acknowledged)
            it = store.diagnostics.erase(it);
        else
            ++it;
    }
    publish_locked(store, now_ms());
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
void clear_preview_state() {
    state_t& store = state();
    std::lock_guard<std::mutex> lock(store.mutex);
    store.records.clear();
    store.diagnostics.clear();
    store.next_refresh_ms.store(0, std::memory_order_release);
    publish_locked(store, now_ms());
}
#endif

void register_views(view_registry_t& registry) {
    view_descriptor_t tasks;
    tasks.id = stable_view_id_t("view.background_tasks");
    tasks.display_name = "Tasks";
    tasks.internal_name = "aida.view.background_tasks";
    tasks.category = view_category_t::output;
    tasks.role = view_presentation_role_t::bottom_panel;
    tasks.minimum_size = {420.0f, 180.0f};
    tasks.render = render_tasks_view;
    tasks.default_open = false;
    registry.register_view(std::move(tasks));

    view_descriptor_t diagnostics;
    diagnostics.id = stable_view_id_t("view.diagnostics");
    diagnostics.display_name = "Diagnostics";
    diagnostics.internal_name = "aida.view.diagnostics";
    diagnostics.category = view_category_t::output;
    diagnostics.role = view_presentation_role_t::bottom_panel;
    diagnostics.minimum_size = {420.0f, 180.0f};
    diagnostics.persistence_version = 2;
    diagnostics.persistence_aliases.emplace_back("view.problems");
    diagnostics.render = render_diagnostics_view;
    registry.register_view(std::move(diagnostics));
}

namespace {

std::string s_selected_task_id;
std::string s_selected_diagnostic_id;

const task_snapshot_t* find_task(const immutable_snapshot_t& current, const std::string& id) {
    const auto found = std::find_if(current.tasks.begin(), current.tasks.end(), [&](const task_snapshot_t& item) {
        return item.id == id;
    });
    return found == current.tasks.end() ? nullptr : &*found;
}

const diagnostic_snapshot_t* find_diagnostic(const immutable_snapshot_t& current,
                                             const std::string& id) {
    const auto found = std::find_if(current.diagnostics.begin(), current.diagnostics.end(),
        [&](const diagnostic_snapshot_t& item) { return item.id == id; });
    return found == current.diagnostics.end() ? nullptr : &*found;
}

bool context_key_pressed() {
    return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
        (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

design::semantic_t task_semantic(task_state_t value) {
    switch (value) {
    case task_state_t::completed: return design::semantic_t::success;
    case task_state_t::partial:
    case task_state_t::timed_out:
    case task_state_t::interrupted: return design::semantic_t::warning;
    case task_state_t::failed: return design::semantic_t::error;
    case task_state_t::cancelled: return design::semantic_t::stale;
    case task_state_t::running: return design::semantic_t::live;
    case task_state_t::cancellation_requested: return design::semantic_t::warning;
    case task_state_t::queued: return design::semantic_t::info;
    }
    return design::semantic_t::neutral;
}

const char* diagnostic_severity_name(diagnostic_severity_t value) {
    switch (value) {
    case diagnostic_severity_t::security: return "Security";
    case diagnostic_severity_t::error: return "Error";
    case diagnostic_severity_t::warning: return "Warning";
    case diagnostic_severity_t::information: return "Information";
    }
    return "Unknown";
}

design::semantic_t diagnostic_semantic(diagnostic_severity_t value) {
    switch (value) {
    case diagnostic_severity_t::security:
    case diagnostic_severity_t::error: return design::semantic_t::error;
    case diagnostic_severity_t::warning: return design::semantic_t::warning;
    case diagnostic_severity_t::information: return design::semantic_t::info;
    }
    return design::semantic_t::neutral;
}

std::string duration_text(std::uint64_t milliseconds) {
    const std::uint64_t seconds = milliseconds / 1000ULL;
    if (seconds < 60ULL) return std::to_string(seconds) + "s";
    char output[32]{};
    std::snprintf(output, sizeof(output), "%llum %02llus",
        static_cast<unsigned long long>(seconds / 60ULL),
        static_cast<unsigned long long>(seconds % 60ULL));
    return output;
}

std::string diagnostic_copy_text(const diagnostic_snapshot_t& item) {
    return item.id + "\n" + item.summary + "\n" + item.details;
}

application_ui::retained_entity_action_t retained_action(const char* id,
    bool enabled, const char* disabled_reason,
    std::function<action_handler_result_t()> invoke) {
    application_ui::retained_entity_action_t action;
    action.action_id = id;
    action.capability = enabled
        ? capability_state_t::available()
        : capability_state_t::unavailable(disabled_reason);
    action.invoke = std::move(invoke);
    return action;
}

void open_task_context(const task_snapshot_t& item, std::uint64_t snapshot_generation,
                       context_menu_open_origin_t origin) {
    application_ui::retained_entity_context_t context;
    context.owner_id = "task-center.tasks";
    context.entity_id = item.id;
    context.entity_generation = snapshot_generation;
    context.active_view = stable_view_id_t("view.background_tasks");
    const std::string id = item.id;
    const std::uint64_t queued_ms = item.queued_ms;
    const std::string owner = item.owner;
    const std::string label = item.label;
    context.validate_identity = [id, queued_ms, owner, label] {
        const auto current = snapshot();
        if (!current)
            return capability_state_t::unavailable("The task snapshot is unavailable");
        const auto* retained = find_task(*current, id);
        return retained && retained->queued_ms == queued_ms &&
                retained->owner == owner && retained->label == label
            ? capability_state_t::available()
            : capability_state_t::unavailable(
                "The retained task was removed or replaced; select it again");
    };
    context.actions.push_back(retained_action("task.focus_owner", item.focusable,
        "This task owner did not register a focus target.", [id] {
            return focus(id) ? action_handler_result_t::completed()
                             : action_handler_result_t::failed("The task owner could not be focused");
        }));
    context.actions.push_back(retained_action("task.open_log", item.log_available,
        "This task owner did not register a retained log target.", [id] {
            return open_log(id) ? action_handler_result_t::completed()
                                : action_handler_result_t::failed("The retained task log could not be opened");
        }));
    const bool can_retry = item.retryable && !active_state(item.state);
    context.actions.push_back(retained_action("task.retry", can_retry,
        active_state(item.state)
            ? "An active task cannot be retried until its owner reports a terminal state."
            : "This task owner did not register a retry operation.", [id] {
            return retry(id) ? action_handler_result_t::completed()
                             : action_handler_result_t::failed("The task owner rejected the retry request");
        }));
    const bool can_cancel = item.cancellable && active_state(item.state) &&
        !item.security_critical;
    const char* cancel_reason = item.state == task_state_t::cancellation_requested
        ? "Waiting for the task owner to confirm a terminal cancelled state."
        : item.security_critical
        ? "Security-critical and liveness jobs are fail-closed and cannot be cancelled here."
        : active_state(item.state)
        ? "This task owner did not register a safe cancellation operation."
        : "Only an active task can be cancelled.";
    context.actions.push_back(retained_action("task.request_cancel", can_cancel,
        cancel_reason, [id] {
            return request_cancel(id) ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The task owner rejected cancellation");
        }));
    context.actions.push_back(retained_action("task.view_diagnostic",
        !item.diagnostic_id.empty(), "This task has no retained diagnostic.", [] {
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.diagnostics"));
            return opened.ok() ? action_handler_result_t::completed()
                : action_handler_result_t::failed(opened.detail);
        }));
    context.actions.push_back(retained_action("task.copy_id", true, "", [id] {
        ImGui::SetClipboardText(id.c_str());
        return action_handler_result_t::completed();
    }));
    const std::string summary = item.id + "\n" + item.label + "\n" + item.stage +
        "\n" + item.result_summary;
    context.actions.push_back(retained_action("task.copy_summary", true, "", [summary] {
        ImGui::SetClipboardText(summary.c_str());
        return action_handler_result_t::completed();
    }));
    application_ui::open_retained_entity_context_menu(std::move(context), origin);
}

void open_diagnostic_context(const diagnostic_snapshot_t& item,
                             std::uint64_t snapshot_generation,
                             context_menu_open_origin_t origin) {
    application_ui::retained_entity_context_t context;
    context.owner_id = "task-center.diagnostics";
    context.entity_id = item.id;
    context.entity_generation = snapshot_generation;
    context.active_view = stable_view_id_t("view.diagnostics");
    const std::string id = item.id;
    const std::uint64_t raised_ms = item.raised_ms;
    const std::string owner = item.owner;
    const std::string summary = item.summary;
    context.validate_identity = [id, raised_ms, owner, summary] {
        const auto current = snapshot();
        if (!current)
            return capability_state_t::unavailable("The diagnostic snapshot is unavailable");
        const auto* retained = find_diagnostic(*current, id);
        return retained && retained->raised_ms == raised_ms &&
                retained->owner == owner && retained->summary == summary
            ? capability_state_t::available()
            : capability_state_t::unavailable(
                "The retained diagnostic was removed or replaced; select it again");
    };
    context.actions.push_back(retained_action("diagnostic.focus_owner", item.focusable,
        "This diagnostic has no registered owner focus target.", [id] {
            return focus_diagnostic(id) ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The diagnostic owner could not be focused");
        }));
    context.actions.push_back(retained_action("diagnostic.open_log", item.log_available,
        "This diagnostic has no retained log target.", [id] {
            return open_diagnostic_log(id) ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The diagnostic log could not be opened");
        }));
    context.actions.push_back(retained_action("diagnostic.retry", item.retryable,
        "The diagnostic owner did not register a safe retry operation.", [id] {
            return retry_diagnostic(id) ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The diagnostic owner rejected the retry request");
        }));
    context.actions.push_back(retained_action("diagnostic.acknowledge", !item.acknowledged,
        "This diagnostic is already acknowledged.", [id] {
            return acknowledge_diagnostic(id) ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The diagnostic could not be acknowledged");
        }));
    const std::string text = diagnostic_copy_text(item);
    context.actions.push_back(retained_action("diagnostic.copy", true, "", [text] {
        ImGui::SetClipboardText(text.c_str());
        return action_handler_result_t::completed();
    }));
    context.actions.push_back(retained_action("diagnostic.copy_id", true, "", [id] {
        ImGui::SetClipboardText(id.c_str());
        return action_handler_result_t::completed();
    }));
    aida::automation_ui::entity_evidence::snapshot_t evidence;
    evidence.workspace_id = item.target;
    evidence.source_view_id = "view.diagnostics";
    evidence.source_kind = "diagnostic";
    evidence.entity_id = item.id;
    evidence.display_label = item.summary;
    evidence.excerpt = "Diagnostic ID: " + item.id + "\nOwner: " + item.owner +
        "\nTarget: " + item.target + "\nTask ID: " + item.task_id +
        "\nRaised: " + std::to_string(item.raised_ms) +
        "\nSeverity: " + std::to_string(static_cast<unsigned>(item.severity)) +
        "\nSummary: " + item.summary + "\nDetails: " + item.details +
        "\nLog target: " + item.log_link;
    evidence.revision = item.raised_ms;
    evidence.generation = snapshot_generation;
    evidence.sensitive = true;
    evidence.return_to_source = [id, raised_ms, owner, summary](std::string& reason) {
        const auto current = snapshot();
        const auto* retained = current ? find_diagnostic(*current, id) : nullptr;
        if (!retained || retained->raised_ms != raised_ms ||
            retained->owner != owner || retained->summary != summary) {
            reason = "The retained diagnostic was removed or replaced; capture it again.";
            return false;
        }
        s_selected_diagnostic_id = id;
        const auto opened = application_views::open_or_focus(
            stable_view_id_t("view.diagnostics"));
        if (!opened.ok()) {
            reason = opened.detail;
            return false;
        }
        reason.clear();
        return true;
    };
    aida::automation_ui::entity_evidence::append_actions(context,
        std::move(evidence));
    application_ui::open_retained_entity_context_menu(std::move(context), origin);
}

}

void render_tasks_view(const view_render_context_t&) {
    const auto current = snapshot();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (design::tiny_view_required(available, ImVec2(320.0f, 96.0f))) {
        design::state_presentation_t tiny;
        tiny.stable_id = "task-center.tiny";
        tiny.state = design::view_state_t::tiny;
        tiny.title = "Tasks needs more room";
        tiny.message = "Resize or float this panel to inspect background work and its owner-provided actions.";
        static_cast<void>(design::render_state(tiny, available));
        return;
    }
    if (!current || current->tasks.empty()) {
        design::state_presentation_t empty;
        empty.stable_id = "task-center.empty";
        empty.state = design::view_state_t::empty;
        empty.title = "No background tasks";
        empty.message = "Long-running work appears here with owner, target, progress, cancellation, recovery, and diagnostics.";
        static_cast<void>(design::render_state(empty, available));
        return;
    }

    const auto& metrics = design::metrics();
    components::status_badge((std::to_string(current->status.running) + " running").c_str(),
        current->status.running ? components::status_kind_t::success : components::status_kind_t::neutral);
    ImGui::SameLine(0.0f, metrics.spacing_sm);
    components::status_badge((std::to_string(current->status.queued) + " queued").c_str(),
        current->status.queued ? components::status_kind_t::info : components::status_kind_t::neutral);
    if (current->status.cancellation_requested) {
        ImGui::SameLine(0.0f, metrics.spacing_sm);
        components::status_badge((std::to_string(current->status.cancellation_requested) + " cancelling").c_str(),
            components::status_kind_t::warning);
    }
    if (current->status.failures) {
        ImGui::SameLine(0.0f, metrics.spacing_sm);
        components::status_badge((std::to_string(current->status.failures) + " failed").c_str(),
            components::status_kind_t::error);
    }
    if (current->status.interrupted) {
        ImGui::SameLine(0.0f, metrics.spacing_sm);
        components::status_badge((std::to_string(current->status.interrupted) + " interrupted").c_str(),
            components::status_kind_t::warning);
    }
    if (current->status.partial) {
        ImGui::SameLine(0.0f, metrics.spacing_sm);
        components::status_badge((std::to_string(current->status.partial) + " partial").c_str(),
            components::status_kind_t::warning);
    }
    ImGui::Dummy(ImVec2(0.0f, metrics.spacing_xs));

    const ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable;
    if (design::begin_expert_table("task-center.table", 7, flags, ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Task", ImGuiTableColumnFlags_WidthStretch, 2.0f);
        ImGui::TableSetupColumn("Owner", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(116.0f, metrics.scale));
        ImGui::TableSetupColumn("Progress", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(132.0f, metrics.scale));
        ImGui::TableSetupColumn("Elapsed", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(72.0f, metrics.scale));
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(106.0f, metrics.scale));
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(current->tasks.size()), metrics.table_row_height);
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const task_snapshot_t& item = current->tasks[static_cast<std::size_t>(index)];
                ImGui::PushID(item.id.c_str());
                ImGui::TableNextRow(ImGuiTableRowFlags_None, metrics.table_row_height);
                ImGui::TableSetColumnIndex(0);
                const bool selected = s_selected_task_id == item.id;
                ImGui::Selectable("##task-row", selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                    ImVec2(0.0f, ImGui::GetTextLineHeight()));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string task_semantic_id = "aida.task.row-" +
                    aida::preview::semantics::entity_token(item.id);
                static_cast<void>(aida::preview::semantics::register_last_item(
                    task_semantic_id, "background-task-row"));
#endif
                if (ImGui::IsItemClicked()) s_selected_task_id = item.id;
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && item.focusable)
                    static_cast<void>(focus(item.id));
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    s_selected_task_id = item.id;
                    open_task_context(item, current->generation,
                        context_menu_open_origin_t::pointer);
                }
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(item.label.c_str());
                if (ImGui::IsItemHovered() && (!item.stage.empty() || !item.result_summary.empty()))
                    ImGui::SetTooltip("%s%s%s", item.stage.c_str(),
                        !item.stage.empty() && !item.result_summary.empty() ? "\n" : "",
                        item.result_summary.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(item.owner.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(item.target.empty() ? "-" : item.target.c_str());
                ImGui::TableSetColumnIndex(3);
                components::status_badge(state_name(item.state), design::component_status(task_semantic(item.state)));
                ImGui::TableSetColumnIndex(4);
                if (item.progress >= 0.0f) {
                    components::render_progress_bar(ImGui::GetCursorScreenPos(), ImGui::GetContentRegionAvail().x,
                        aida::ui::scale_px(5.0f, metrics.scale), (std::max)(0.0f, (std::min)(1.0f, item.progress)),
                        false, !design::reduced_motion());
                    ImGui::Dummy(ImVec2(0.0f, aida::ui::scale_px(6.0f, metrics.scale)));
                } else if (active_state(item.state)) {
                    if (design::reduced_motion()) ImGui::TextDisabled("Working");
                    else {
                        components::render_progress_bar(ImGui::GetCursorScreenPos(), ImGui::GetContentRegionAvail().x,
                            aida::ui::scale_px(5.0f, metrics.scale), 0.0f, true);
                        ImGui::Dummy(ImVec2(0.0f, aida::ui::scale_px(6.0f, metrics.scale)));
                    }
                } else ImGui::TextDisabled("-");
                ImGui::TableSetColumnIndex(5);
                ImGui::TextUnformatted(duration_text(item.elapsed_ms).c_str());
                ImGui::TableSetColumnIndex(6);
                if (item.state == task_state_t::cancellation_requested) {
                    ImGui::TextDisabled("Pending");
                } else if (item.cancellable && active_state(item.state)) {
                    const bool invoked = components::button("Cancel",
                        components::button_kind_t::destructive, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    static_cast<void>(aida::preview::semantics::register_last_item(
                        "aida.task.action-cancel-" +
                            aida::preview::semantics::entity_token(item.id),
                        "background-task-action", false, false, task_semantic_id));
#endif
                    if (invoked)
                        static_cast<void>(request_cancel(item.id));
                    design::tooltip_for_last_item("Request cancellation and wait for owner confirmation", nullptr,
                        "The task remains active until its owner reports a terminal state.");
                } else if (item.retryable && !active_state(item.state)) {
                    const bool invoked = components::button("Retry",
                        components::button_kind_t::secondary, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    static_cast<void>(aida::preview::semantics::register_last_item(
                        "aida.task.action-retry-" +
                            aida::preview::semantics::entity_token(item.id),
                        "background-task-action", false, false, task_semantic_id));
#endif
                    if (invoked)
                        static_cast<void>(retry(item.id));
                } else if (item.focusable) {
                    const bool invoked = components::button("Focus",
                        components::button_kind_t::ghost, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                    static_cast<void>(aida::preview::semantics::register_last_item(
                        "aida.task.action-focus-" +
                            aida::preview::semantics::entity_token(item.id),
                        "background-task-action", false, false, task_semantic_id));
#endif
                    if (invoked)
                        static_cast<void>(focus(item.id));
                } else ImGui::TextDisabled("-");
                application_ui::render_retained_entity_context_menu(
                    "task-center.tasks");
                ImGui::PopID();
            }
        }
        design::end_expert_table();
    }

    if (!s_selected_task_id.empty() &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        context_key_pressed()) {
        if (const auto* selected = find_task(*current, s_selected_task_id))
            open_task_context(*selected, current->generation,
                ImGui::IsKeyPressed(ImGuiKey_Menu, false)
                    ? context_menu_open_origin_t::menu_key
                    : context_menu_open_origin_t::shift_f10);
    }
    application_ui::render_retained_entity_context_menu("task-center.tasks");
}

void render_diagnostics_view(const view_render_context_t&) {
    const auto current = snapshot();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    if (design::tiny_view_required(available, ImVec2(320.0f, 96.0f))) {
        design::state_presentation_t tiny;
        tiny.stable_id = "diagnostics.tiny";
        tiny.state = design::view_state_t::tiny;
        tiny.title = "Diagnostics needs more room";
        tiny.message = "Resize or float this panel to inspect retained failures and recovery actions.";
        static_cast<void>(design::render_state(tiny, available));
        return;
    }
    if (!current || current->diagnostics.empty()) {
        design::state_presentation_t empty;
        empty.stable_id = "diagnostics.empty";
        empty.state = design::view_state_t::empty;
        empty.title = "No persistent diagnostics";
        empty.message = "Failures that require attention remain here after transient notifications disappear.";
        static_cast<void>(design::render_state(empty, available));
        return;
    }

    const auto& metrics = design::metrics();
    components::status_badge((std::to_string(current->status.unacknowledged_diagnostics) + " unacknowledged").c_str(),
        current->status.unacknowledged_diagnostics ? components::status_kind_t::warning
                                                   : components::status_kind_t::success);
    ImGui::Dummy(ImVec2(0.0f, metrics.spacing_xs));
    const float details_height = (std::min)(aida::ui::scale_px(118.0f, metrics.scale),
        (std::max)(aida::ui::scale_px(72.0f, metrics.scale), available.y * 0.34f));
    const float table_height = (std::max)(metrics.table_row_height * 2.0f,
        ImGui::GetContentRegionAvail().y - details_height - metrics.spacing_sm);
    if (design::begin_expert_table("diagnostics.table", 6, ImGuiTableFlags_ScrollY,
            ImVec2(0.0f, table_height))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(94.0f, metrics.scale));
        ImGui::TableSetupColumn("Summary", ImGuiTableColumnFlags_WidthStretch, 2.2f);
        ImGui::TableSetupColumn("Owner", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Age", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(72.0f, metrics.scale));
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed,
            aida::ui::scale_px(104.0f, metrics.scale));
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(current->diagnostics.size()), metrics.table_row_height);
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const diagnostic_snapshot_t& item = current->diagnostics[static_cast<std::size_t>(index)];
                ImGui::PushID(item.id.c_str());
                ImGui::TableNextRow(ImGuiTableRowFlags_None, metrics.table_row_height);
                ImGui::TableSetColumnIndex(0);
                components::status_badge(diagnostic_severity_name(item.severity),
                    design::component_status(diagnostic_semantic(item.severity)));
                ImGui::TableSetColumnIndex(1);
                const bool selected = s_selected_diagnostic_id == item.id;
                ImGui::Selectable("##diagnostic-row", selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                    ImVec2(0.0f, ImGui::GetTextLineHeight()));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string diagnostic_semantic_id = "aida.diagnostic.row-" +
                    aida::preview::semantics::entity_token(item.id);
                static_cast<void>(aida::preview::semantics::register_last_item(
                    diagnostic_semantic_id, "diagnostic-row"));
#endif
                if (ImGui::IsItemClicked()) s_selected_diagnostic_id = item.id;
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && item.focusable)
                    static_cast<void>(focus_diagnostic(item.id));
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    s_selected_diagnostic_id = item.id;
                    open_diagnostic_context(item, current->generation,
                        context_menu_open_origin_t::pointer);
                }
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextUnformatted(item.summary.c_str());
                if (ImGui::IsItemHovered() && !item.details.empty()) ImGui::SetTooltip("%s", item.details.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(item.owner.empty() ? "-" : item.owner.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(item.target.empty() ? "-" : item.target.c_str());
                ImGui::TableSetColumnIndex(4);
                const std::uint64_t age = current->captured_ms > item.raised_ms
                    ? current->captured_ms - item.raised_ms : 0;
                ImGui::TextUnformatted(duration_text(age).c_str());
                ImGui::TableSetColumnIndex(5);
                components::status_badge(item.acknowledged ? "Acknowledged" : "Attention",
                    item.acknowledged ? components::status_kind_t::neutral : components::status_kind_t::warning);
                application_ui::render_retained_entity_context_menu(
                    "task-center.diagnostics");
                ImGui::PopID();
            }
        }
        design::end_expert_table();
    }

    if (s_selected_diagnostic_id.empty() && !current->diagnostics.empty())
        s_selected_diagnostic_id = current->diagnostics.front().id;
    const diagnostic_snapshot_t* selected = find_diagnostic(*current, s_selected_diagnostic_id);
    if (!selected && !current->diagnostics.empty()) {
        s_selected_diagnostic_id = current->diagnostics.front().id;
        selected = &current->diagnostics.front();
    }
    if (selected) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const std::string selected_semantic_id = "aida.diagnostic.row-" +
            aida::preview::semantics::entity_token(selected->id);
#endif
        ImGui::BeginChild("##diagnostic-details", ImVec2(0.0f, 0.0f), true,
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysUseWindowPadding);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(design::semantic_color(
            diagnostic_semantic(selected->severity))), "%s", selected->summary.c_str());
        if (!selected->details.empty()) ImGui::TextWrapped("%s", selected->details.c_str());
        ImGui::TextDisabled("%s", selected->id.c_str());
        if (selected->focusable) {
            const bool invoked = components::button("Focus Owner",
                components::button_kind_t::secondary, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.diagnostic.action-focus-" +
                    aida::preview::semantics::entity_token(selected->id),
                "diagnostic-action", false, false, selected_semantic_id));
#endif
            if (invoked)
                static_cast<void>(focus_diagnostic(selected->id));
        }
        if (selected->log_available) {
            if (ImGui::GetContentRegionAvail().x >= aida::ui::scale_px(96.0f, metrics.scale))
                ImGui::SameLine();
            const bool invoked = components::button("Open Log",
                components::button_kind_t::ghost, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.diagnostic.action-log-" +
                    aida::preview::semantics::entity_token(selected->id),
                "diagnostic-action", false, false, selected_semantic_id));
#endif
            if (invoked)
                static_cast<void>(open_diagnostic_log(selected->id));
        }
        if (selected->retryable) {
            if (ImGui::GetContentRegionAvail().x >= aida::ui::scale_px(80.0f, metrics.scale))
                ImGui::SameLine();
            const bool invoked = components::button("Retry",
                components::button_kind_t::secondary, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.diagnostic.action-retry-" +
                    aida::preview::semantics::entity_token(selected->id),
                "diagnostic-action", false, false, selected_semantic_id));
#endif
            if (invoked)
                static_cast<void>(retry_diagnostic(selected->id));
        }
        if (!selected->acknowledged) {
            if (ImGui::GetContentRegionAvail().x >= aida::ui::scale_px(112.0f, metrics.scale))
                ImGui::SameLine();
            const bool invoked = components::button("Acknowledge",
                components::button_kind_t::ghost, components::size_t_::sm);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.diagnostic.action-acknowledge-" +
                    aida::preview::semantics::entity_token(selected->id),
                "diagnostic-action", false, false, selected_semantic_id));
#endif
            if (invoked)
                static_cast<void>(acknowledge_diagnostic(selected->id));
        }
        ImGui::EndChild();
    }

    if (!s_selected_diagnostic_id.empty() &&
        ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        context_key_pressed()) {
        if (const auto* retained = find_diagnostic(*current,
                s_selected_diagnostic_id))
            open_diagnostic_context(*retained, current->generation,
                ImGui::IsKeyPressed(ImGuiKey_Menu, false)
                    ? context_menu_open_origin_t::menu_key
                    : context_menu_open_origin_t::shift_f10);
    }
    application_ui::render_retained_entity_context_menu("task-center.diagnostics");
}

}
