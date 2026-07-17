#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/shell_preview_platform.hpp"
using UINT = unsigned int;
#else
#include <Windows.h>
#endif

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace aida::ui_thread {

using task_t = std::function<void()>;

enum class priority_t : int {
    low = 0,
    normal = 1,
    high = 2,
    critical = 3,
};

enum class enqueue_result_t : int {
    accepted = 0,
    rejected_shutdown,
    rejected_full,
    rejected_not_ui_ready,
    rejected_cancelled,
};

struct post_options_t {
    const char* subsystem = nullptr;
    const char* label = nullptr;
    const char* phase = nullptr;
    const char* owner = nullptr;
    priority_t priority = priority_t::normal;
    std::uint64_t deadline_ms = 0;
    std::function<bool()> cancelled;
};

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline const char* result_name(enqueue_result_t result) {
    switch (result) {
        case enqueue_result_t::accepted: return "accepted";
        case enqueue_result_t::rejected_shutdown: return "rejected_shutdown";
        case enqueue_result_t::rejected_full: return "rejected_full";
        case enqueue_result_t::rejected_not_ui_ready: return "rejected_not_ui_ready";
        case enqueue_result_t::rejected_cancelled: return "rejected_cancelled";
    }
    return "unknown";
}
inline const char* priority_name(priority_t priority) {
    switch (priority) {
        case priority_t::low: return "low";
        case priority_t::normal: return "normal";
        case priority_t::high: return "high";
        case priority_t::critical: return "critical";
    }
    return "unknown";
}
inline void capture_owner_tid(DWORD, const char*, const char*, const char*) {}
inline DWORD owner_tid() { return 1; }
inline bool is_owner_thread() { return true; }
inline bool require_owner(const char*, const char*, const char*) { return true; }
inline enqueue_result_t post(task_t task, post_options_t options) {
    if (options.cancelled && options.cancelled())
        return enqueue_result_t::rejected_cancelled;
    if (!task)
        return enqueue_result_t::rejected_full;
    task();
    return enqueue_result_t::accepted;
}
inline bool post(task_t task, const char*, const char*, const char*) {
    return post(std::move(task), {}) == enqueue_result_t::accepted;
}
inline bool wake(const char*, const char*, const char*) { return true; }
inline std::uint32_t drain(std::uint32_t, std::uint64_t, const char*) { return 0; }
inline std::size_t pending_count() { return 0; }
inline void format_snapshot(char* out, std::size_t cap) {
    if (out && cap > 0) out[0] = '\0';
}
inline std::uint64_t affinity_violation_count() { return 0; }
inline std::uint64_t last_drain_timestamp() { return 0; }
inline std::uint64_t last_wake_timestamp() { return 0; }
inline std::uint64_t task_budget_hit_count() { return 0; }
inline std::uint64_t time_budget_hit_count() { return 0; }
inline std::uint64_t budget_hit_count() { return 0; }
inline std::uint64_t rejected_count() { return 0; }
inline std::uint64_t drained_count() { return 0; }
inline bool wake_pending() { return false; }
inline std::uint64_t oldest_queued_age_ms() { return 0; }
inline std::string top_queued_labels(std::size_t) { return {}; }
inline bool is_wake_message(UINT) { return false; }
inline void acknowledge_wake_message() {}
inline void mark_ready(HWND, const char*, const char*, const char*) {}
inline void mark_window_destroying(HWND, const char*, const char*, const char*) {}
inline void shutdown() {}
#else
const char* result_name(enqueue_result_t result);
const char* priority_name(priority_t priority);
void capture_owner_tid(DWORD tid, const char* subsystem, const char* label, const char* phase);
DWORD owner_tid();
bool is_owner_thread();
bool require_owner(const char* subsystem, const char* label, const char* phase);
enqueue_result_t post(task_t task, post_options_t options);
bool post(task_t task, const char* subsystem, const char* label, const char* phase);
bool wake(const char* subsystem, const char* label, const char* phase);
std::uint32_t drain(std::uint32_t task_budget, std::uint64_t time_budget_ms, const char* phase);
    std::size_t pending_count();
    void format_snapshot(char* out, std::size_t cap);
    std::uint64_t affinity_violation_count();
    std::uint64_t last_drain_timestamp();
    std::uint64_t last_wake_timestamp();
    std::uint64_t task_budget_hit_count();
    std::uint64_t time_budget_hit_count();
    std::uint64_t budget_hit_count();
    std::uint64_t rejected_count();
    std::uint64_t drained_count();
    bool wake_pending();
    std::uint64_t oldest_queued_age_ms();
    std::string top_queued_labels(std::size_t max_entries);
bool is_wake_message(UINT msg);
void acknowledge_wake_message();
void mark_ready(HWND hwnd, const char* subsystem, const char* label, const char* phase);
void mark_window_destroying(HWND hwnd, const char* subsystem, const char* label, const char* phase);
void shutdown();
#endif

}
