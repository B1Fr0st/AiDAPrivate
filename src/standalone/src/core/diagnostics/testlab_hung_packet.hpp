#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "../../helpers/diag_log.hpp"
#include "metadata_ring.hpp"
#include "wer_correlation.hpp"

namespace aida::diagnostics::testlab {

struct hung_packet_context_t {
    std::uint64_t test_run_id = 0;
    const char* suite = nullptr;
    const char* domain = nullptr;
    const char* test_name = nullptr;
    const char* phase = nullptr;
    const char* step_label = nullptr;
    std::uint64_t step_start_ms = 0;
    std::uint64_t step_elapsed_ms = 0;
    const char* target_executable_path = nullptr;
    const char* requested_cwd = nullptr;
    const char* effective_cwd = nullptr;
    std::uint32_t target_pid = 0;
    bool driver_attached = false;
    bool cancellation_requested = false;
    bool shutdown_requested = false;
    std::size_t mcp_active_leases = 0;
    std::size_t mcp_active_requests = 0;
    const char* downstream_summary = nullptr;
    std::size_t ui_dispatcher_backlog = 0;
    const char* work_queue_snapshot = nullptr;
    const char* critical_queue_snapshot = nullptr;
    std::uint64_t license_liveness_ms = 0;
    std::uint64_t arc_liveness_ms = 0;
    std::uint64_t driver_watchdog_ms = 0;
    const char* first_failure_marker = nullptr;
    const char* last_successful_marker = nullptr;
};

inline std::mutex& emitted_packets_mutex() {
    static std::mutex m;
    return m;
}

struct emitted_packet_key_t {
    std::uint64_t test_run_id;
    std::uint64_t step_start_ms;
    std::string step_label;
    bool emitted = false;
};

inline std::vector<emitted_packet_key_t>& emitted_packets() {
    static std::vector<emitted_packet_key_t> packets;
    return packets;
}

inline bool should_emit_packet(std::uint64_t test_run_id, std::uint64_t step_start_ms, const char* step_label) {
    std::lock_guard<std::mutex> lk(emitted_packets_mutex());
    auto& packets = emitted_packets();
    for (auto& p : packets) {
        if (p.test_run_id == test_run_id && p.step_start_ms == step_start_ms &&
            p.step_label == (step_label ? step_label : "")) {
            return !p.emitted;
        }
    }
    if (packets.size() > 64)
        packets.erase(packets.begin(), packets.begin() + static_cast<std::ptrdiff_t>(packets.size() - 32));
    emitted_packet_key_t key;
    key.test_run_id = test_run_id;
    key.step_start_ms = step_start_ms;
    key.step_label = step_label ? step_label : "";
    key.emitted = false;
    packets.push_back(std::move(key));
    return true;
}

inline void mark_packet_emitted(std::uint64_t test_run_id, std::uint64_t step_start_ms, const char* step_label) {
    std::lock_guard<std::mutex> lk(emitted_packets_mutex());
    auto& packets = emitted_packets();
    for (auto& p : packets) {
        if (p.test_run_id == test_run_id && p.step_start_ms == step_start_ms &&
            p.step_label == (step_label ? step_label : "")) {
            p.emitted = true;
            return;
        }
    }
}

inline void log_hung_diagnostic_packet(const hung_packet_context_t& ctx) {
    if (!should_emit_packet(ctx.test_run_id, ctx.step_start_ms, ctx.step_label))
        return;

    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t elapsed = metadata_ring::elapsed_ms();

    FILETIME system_time{};
    GetSystemTimeAsFileTime(&system_time);
    ULARGE_INTEGER utc_val;
    utc_val.LowPart = system_time.dwLowDateTime;
    utc_val.HighPart = system_time.dwHighDateTime;

    diag::log_tagged_critical_fmt("testlab",
        "TESTLAB-HUNG-DIAGNOSTIC-PACKET run_id=%llu suite=%s domain=%s test=%s phase=%s step=%s step_start_ms=%llu step_elapsed_ms=%llu utc_100ns=%llu tick_ms=%llu elapsed_ms=%llu pid=%lu tid=%lu target_path=%s requested_cwd=%s effective_cwd=%s target_pid=%u driver_attached=%d cancellation=%d shutdown=%d mcp_active_leases=%zu mcp_active_requests=%zu downstream=%s ui_backlog=%zu work_queues={%.1400s} critical_queues={%.1400s} license_ms=%llu arc_ms=%llu driver_watchdog_ms=%llu first_failure=%s last_success=%s",
        static_cast<unsigned long long>(ctx.test_run_id),
        ctx.suite ? ctx.suite : "<null>",
        ctx.domain ? ctx.domain : "<null>",
        ctx.test_name ? ctx.test_name : "<null>",
        ctx.phase ? ctx.phase : "<null>",
        ctx.step_label ? ctx.step_label : "<null>",
        static_cast<unsigned long long>(ctx.step_start_ms),
        static_cast<unsigned long long>(ctx.step_elapsed_ms),
        static_cast<unsigned long long>(utc_val.QuadPart),
        static_cast<unsigned long long>(now),
        static_cast<unsigned long long>(elapsed),
        static_cast<unsigned long>(pid),
        static_cast<unsigned long>(tid),
        ctx.target_executable_path ? ctx.target_executable_path : "<null>",
        ctx.requested_cwd ? ctx.requested_cwd : "<null>",
        ctx.effective_cwd ? ctx.effective_cwd : "<null>",
        static_cast<unsigned>(ctx.target_pid),
        ctx.driver_attached ? 1 : 0,
        ctx.cancellation_requested ? 1 : 0,
        ctx.shutdown_requested ? 1 : 0,
        ctx.mcp_active_leases,
        ctx.mcp_active_requests,
        ctx.downstream_summary ? ctx.downstream_summary : "<null>",
        ctx.ui_dispatcher_backlog,
        ctx.work_queue_snapshot && ctx.work_queue_snapshot[0] ? ctx.work_queue_snapshot : "empty=1",
        ctx.critical_queue_snapshot && ctx.critical_queue_snapshot[0] ? ctx.critical_queue_snapshot : "empty=1",
        static_cast<unsigned long long>(ctx.license_liveness_ms),
        static_cast<unsigned long long>(ctx.arc_liveness_ms),
        static_cast<unsigned long long>(ctx.driver_watchdog_ms),
        ctx.first_failure_marker ? ctx.first_failure_marker : "<null>",
        ctx.last_successful_marker ? ctx.last_successful_marker : "<null>");

    metadata_ring::dump_to_log(32);
    wer::log_wer_correlation("testlab_hung_packet");

    mark_packet_emitted(ctx.test_run_id, ctx.step_start_ms, ctx.step_label);
}

inline void reset_emitted_packets() {
    std::lock_guard<std::mutex> lk(emitted_packets_mutex());
    emitted_packets().clear();
}

inline void emit_testlab_breadcrumb(const char* phase, const char* step, bool is_start) {
    char label[128];
    _snprintf_s(label, sizeof(label), _TRUNCATE, "testlab_%s", is_start ? "step_start" : "step_finish");
    char reason[192];
    _snprintf_s(reason, sizeof(reason), _TRUNCATE, "phase=%s step=%s", phase ? phase : "<null>", step ? step : "<null>");
    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::testlab;
    opts.label = label;
    opts.reason = reason;
    opts.owner_subsystem = "testlab";
    opts.force = is_start;
    metadata_ring::emit(std::move(opts));
}

}
