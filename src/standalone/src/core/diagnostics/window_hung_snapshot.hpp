#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "../../helpers/diag_log.hpp"
#include "metadata_ring.hpp"
#include "wer_correlation.hpp"

namespace aida::diagnostics::window_hung {

struct hung_context_t {
    HWND hwnd = nullptr;
    DWORD ui_owner_tid = 0;
    DWORD current_tid = 0;
    BOOL is_hung = FALSE;
    BOOL send_wm_null_ok = FALSE;
    DWORD send_wm_null_gle = 0;
    DWORD_PTR send_wm_null_lresult = 0;
    UINT send_timeout_ms = 0;
    UINT send_flags = 0;
    DWORD peek_queue_status = 0;
    DWORD current_queue_status = 0;
    DWORD peek_gle = 0;
    std::uint64_t peek_remove_flags = 0;
    std::uint64_t peek_filter_hwnd = 0;
    std::uint64_t peek_call_count = 0;
    std::uint64_t peek_return_count = 0;
    std::uint64_t send_only_defers = 0;
    std::uint64_t send_only_flushes = 0;
    std::uint64_t stall_streak = 0;
    std::uint64_t frame = 0;
    std::uint64_t heartbeat_tick_ms = 0;
    std::uint64_t heartbeat_age_ms = 0;
    const char* phase_name = nullptr;
    const char* render_section = nullptr;
    std::uint64_t phase_id = 0;
    const char* dispatch_stage = nullptr;
    UINT dispatch_msg = 0;
    UINT_PTR dispatch_hwnd = 0;
    const char* wndproc_stage = nullptr;
    UINT wndproc_msg = 0;
    UINT_PTR wndproc_hwnd = 0;
    DWORD render_tid = 0;
    std::uint64_t last_input_event_ms = 0;
    std::uint64_t last_successful_pump_return_ms = 0;
    std::size_t ui_dispatcher_queue_depth = 0;
    std::uint64_t ui_dispatcher_oldest_queued_age_ms = 0;
    bool ui_dispatcher_wake_pending = false;
    std::uint64_t ui_dispatcher_rejected_count = 0;
    std::uint64_t ui_dispatcher_drained_count = 0;
    std::uint64_t ui_dispatcher_budget_hit_count = 0;
    std::uint64_t ui_dispatcher_time_budget_hit_count = 0;
    std::uint64_t ui_dispatcher_affinity_violations = 0;
    const char* ui_dispatcher_top_labels = nullptr;
    std::size_t mcp_active_requests = 0;
    std::size_t mcp_active_leases = 0;
    const char* mcp_oldest_owner = nullptr;
    std::size_t mcp_pending_cancellation_count = 0;
    const char* capacity_pressure = nullptr;
    const char* downstream_pressure = nullptr;
    const char* testlab_step = nullptr;
    std::uint64_t testlab_step_elapsed_ms = 0;
    std::uint64_t driver_watchdog_ms = 0;
    const char* mcp_snapshot = nullptr;
    const char* queue_snapshot = nullptr;
    const char* ui_dispatch_snapshot = nullptr;
};

inline void log_window_hung_snapshot(const hung_context_t& ctx) {
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = ctx.current_tid ? ctx.current_tid : GetCurrentThreadId();
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t elapsed = metadata_ring::elapsed_ms();

    FILETIME system_time{};
    GetSystemTimeAsFileTime(&system_time);
    ULARGE_INTEGER utc_val;
    utc_val.LowPart = system_time.dwLowDateTime;
    utc_val.HighPart = system_time.dwHighDateTime;

    diag::log_tagged_critical_fmt("tracer",
        "WINDOW-HUNG-SNAPSHOT pid=%lu tid=%lu utc_100ns=%llu tick_ms=%llu elapsed_ms=%llu qpc_present=1 hwnd=0x%llX hwnd_valid=%d hwnd_pid_check=1 ui_owner_tid=%lu current_tid=%lu render_tid=%lu is_hung=%d send_wm_null_ok=%d send_wm_null_gle=%lu send_wm_null_lresult=0x%llX send_timeout_ms=%u send_flags=0x%08X queue_status=0x%08lX current_queue_status=0x%08lX peek_gle=%lu peek_flags=0x%08X peek_filter=0x%llX peek_calls=%llu peek_returns=%llu send_only_defers=%llu send_only_flushes=%llu stall_streak=%llu frame=%llu heartbeat_tick_ms=%llu heartbeat_age_ms=%llu last_input_event_ms=%llu last_pump_return_ms=%llu phase=%s section=%s phase_id=%llu dispatch_stage=%s dispatch_msg=%s(0x%04X) dispatch_hwnd=0x%llX wndproc_stage=%s wndproc_msg=%s(0x%04X) wndproc_hwnd=0x%llX ui_dispatch_qd=%zu ui_dispatch_oldest_age_ms=%llu ui_dispatch_wake_pending=%d ui_dispatch_rejected=%llu ui_dispatch_drained=%llu ui_dispatch_budget_hits=%llu ui_dispatch_time_budget_hits=%llu ui_dispatch_affinity_violations=%llu ui_dispatch_top_labels=%s mcp_active_requests=%zu mcp_active_leases=%zu mcp_oldest_owner=%s mcp_pending_cancellations=%zu capacity_pressure=%s downstream_pressure=%s testlab_step=%s testlab_step_elapsed_ms=%llu driver_watchdog_ms=%llu mcp={%.1300s} queues={%.2800s} ui_dispatch={%.1300s}",
        static_cast<unsigned long>(pid),
        static_cast<unsigned long>(tid),
        static_cast<unsigned long long>(utc_val.QuadPart),
        static_cast<unsigned long long>(now),
        static_cast<unsigned long long>(elapsed),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ctx.hwnd)),
        ctx.hwnd ? ::IsWindow(ctx.hwnd) : FALSE ? 1 : 0,
        static_cast<unsigned long>(ctx.ui_owner_tid),
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(ctx.render_tid),
        ctx.is_hung ? 1 : 0,
        ctx.send_wm_null_ok ? 1 : 0,
        static_cast<unsigned long>(ctx.send_wm_null_gle),
        static_cast<unsigned long long>(ctx.send_wm_null_lresult),
        ctx.send_timeout_ms,
        ctx.send_flags,
        static_cast<unsigned long>(ctx.peek_queue_status),
        static_cast<unsigned long>(ctx.current_queue_status),
        static_cast<unsigned long>(ctx.peek_gle),
        static_cast<unsigned long>(ctx.peek_remove_flags),
        static_cast<unsigned long long>(ctx.peek_filter_hwnd),
        static_cast<unsigned long long>(ctx.peek_call_count),
        static_cast<unsigned long long>(ctx.peek_return_count),
        static_cast<unsigned long long>(ctx.send_only_defers),
        static_cast<unsigned long long>(ctx.send_only_flushes),
        static_cast<unsigned long long>(ctx.stall_streak),
        static_cast<unsigned long long>(ctx.frame),
        static_cast<unsigned long long>(ctx.heartbeat_tick_ms),
        static_cast<unsigned long long>(ctx.heartbeat_age_ms),
        static_cast<unsigned long long>(ctx.last_input_event_ms),
        static_cast<unsigned long long>(ctx.last_successful_pump_return_ms),
        ctx.phase_name ? ctx.phase_name : "<null>",
        ctx.render_section ? ctx.render_section : "<null>",
        static_cast<unsigned long long>(ctx.phase_id),
        ctx.dispatch_stage ? ctx.dispatch_stage : "<null>",
        "WM_NULL",
        static_cast<unsigned>(ctx.dispatch_msg),
        static_cast<unsigned long long>(ctx.dispatch_hwnd),
        ctx.wndproc_stage ? ctx.wndproc_stage : "<null>",
        "WM_NULL",
        static_cast<unsigned>(ctx.wndproc_msg),
        static_cast<unsigned long long>(ctx.wndproc_hwnd),
        ctx.ui_dispatcher_queue_depth,
        static_cast<unsigned long long>(ctx.ui_dispatcher_oldest_queued_age_ms),
        ctx.ui_dispatcher_wake_pending ? 1 : 0,
        static_cast<unsigned long long>(ctx.ui_dispatcher_rejected_count),
        static_cast<unsigned long long>(ctx.ui_dispatcher_drained_count),
        static_cast<unsigned long long>(ctx.ui_dispatcher_budget_hit_count),
        static_cast<unsigned long long>(ctx.ui_dispatcher_time_budget_hit_count),
        static_cast<unsigned long long>(ctx.ui_dispatcher_affinity_violations),
        ctx.ui_dispatcher_top_labels ? ctx.ui_dispatcher_top_labels : "<null>",
        ctx.mcp_active_requests,
        ctx.mcp_active_leases,
        ctx.mcp_oldest_owner ? ctx.mcp_oldest_owner : "<null>",
        ctx.mcp_pending_cancellation_count,
        ctx.capacity_pressure ? ctx.capacity_pressure : "<null>",
        ctx.downstream_pressure ? ctx.downstream_pressure : "<null>",
        ctx.testlab_step ? ctx.testlab_step : "<null>",
        static_cast<unsigned long long>(ctx.testlab_step_elapsed_ms),
        static_cast<unsigned long long>(ctx.driver_watchdog_ms),
        ctx.mcp_snapshot && ctx.mcp_snapshot[0] ? ctx.mcp_snapshot : "empty=1",
        ctx.queue_snapshot && ctx.queue_snapshot[0] ? ctx.queue_snapshot : "empty=1",
        ctx.ui_dispatch_snapshot && ctx.ui_dispatch_snapshot[0] ? ctx.ui_dispatch_snapshot : "empty=1");

    metadata_ring::dump_to_log(32);

    wer::log_wer_correlation("window_hung_snapshot");

    const std::string log_paths = wer::known_log_paths_summary();
    diag::log_tagged_critical_fmt("tracer",
        "WINDOW-HUNG-SNAPSHOT-LOG-PATHS pid=%lu log_paths=%s",
        static_cast<unsigned long>(pid),
        log_paths.c_str());
}

inline void emit_hung_breadcrumb(HWND hwnd, std::uint64_t age_ms, const char* phase) {
    char reason[128];
    _snprintf_s(reason, sizeof(reason), _TRUNCATE,
        "hwnd=0x%llX age_ms=%llu phase=%s",
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(hwnd)),
        static_cast<unsigned long long>(age_ms),
        phase ? phase : "<null>");
    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::message_pump;
    opts.label = "window_hung_detected";
    opts.reason = reason;
    opts.force = true;
    metadata_ring::emit(std::move(opts));
}

}
