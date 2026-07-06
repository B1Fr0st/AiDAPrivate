#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

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

}
