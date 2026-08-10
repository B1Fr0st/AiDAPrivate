#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "../../helpers/diag_log.hpp"
#include "metadata_ring.hpp"
#include "wer_correlation.hpp"

namespace aida::diagnostics::health {

inline bool is_diagnostics_requested(const char* query_string) {
    if (!query_string || query_string[0] == '\0')
        return false;
    const char* p = std::strstr(query_string, "diagnostics=1");
    if (!p)
        return false;
    if (p == query_string || p[-1] == '&' || p[-1] == '?')
        return true;
    return false;
}

struct diagnostic_state_t {
    std::uint64_t generation = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::uint64_t timestamp_ms = 0;
    std::uint64_t elapsed_ms = 0;
    std::size_t mcp_active_requests = 0;
    const char* mcp_oldest_active_request = nullptr;
    std::size_t mcp_active_leases = 0;
    const char* mcp_lease_lanes = nullptr;
    std::size_t mcp_stale_leases = 0;
    std::size_t mcp_fenced_leases = 0;
    std::size_t mcp_tombstoned_leases = 0;
    std::uint64_t mcp_late_result_discards = 0;
    std::size_t mcp_pending_cancellations = 0;
    const char* capacity_snapshot = nullptr;
    const char* ingress_admission = nullptr;
    const char* tool_admission = nullptr;
    const char* downstream_snapshot = nullptr;
    const char* ui_dispatcher_snapshot = nullptr;
    const char* work_queue_snapshot = nullptr;
    const char* service_queue_snapshot = nullptr;
    const char* critical_queue_snapshot = nullptr;
    const char* thread_runtime_classes = nullptr;
    const char* testlab_state = nullptr;
    const char* camoufox_state = nullptr;
    const char* background_command_state = nullptr;
    std::uint64_t driver_watchdog_ms = 0;
    const char* metadata_ring_summary = nullptr;
    const char* wer_correlation = nullptr;
    const char* executor_snapshot = nullptr;
    const char* taskflow_evaluation = nullptr;
    bool overload_flag = false;
    const char* top_pressure_contributors = nullptr;
};

inline std::string build_diagnostics_json(const diagnostic_state_t& state) {
    std::string out;
    out.reserve(8192);
    char buf[2048];

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"diagnostics\":{\"generation\":%llu,\"pid\":%lu,\"tid\":%lu,\"timestamp_ms\":%llu,\"elapsed_ms\":%llu,",
        static_cast<unsigned long long>(state.generation),
        static_cast<unsigned long>(state.pid),
        static_cast<unsigned long>(state.tid),
        static_cast<unsigned long long>(state.timestamp_ms),
        static_cast<unsigned long long>(state.elapsed_ms));
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"mcp\":{\"active_requests\":%zu,\"oldest_active\":\"%s\",\"active_leases\":%zu,\"stale_leases\":%zu,\"fenced_leases\":%zu,\"tombstoned_leases\":%zu,\"late_result_discards\":%llu,\"pending_cancellations\":%zu},",
        state.mcp_active_requests,
        state.mcp_oldest_active_request ? state.mcp_oldest_active_request : "",
        state.mcp_active_leases,
        state.mcp_stale_leases,
        state.mcp_fenced_leases,
        state.mcp_tombstoned_leases,
        static_cast<unsigned long long>(state.mcp_late_result_discards),
        state.mcp_pending_cancellations);
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"capacity\":\"%s\",",
        state.capacity_snapshot ? state.capacity_snapshot : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"ingress_admission\":\"%s\",\"tool_admission\":\"%s\",",
        state.ingress_admission ? state.ingress_admission : "",
        state.tool_admission ? state.tool_admission : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"downstream\":\"%s\",",
        state.downstream_snapshot ? state.downstream_snapshot : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"ui_dispatcher\":\"%s\",",
        state.ui_dispatcher_snapshot ? state.ui_dispatcher_snapshot : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"work_queue\":\"%s\",\"service_queue\":\"%s\",\"critical_queue\":\"%s\",",
        state.work_queue_snapshot ? state.work_queue_snapshot : "",
        state.service_queue_snapshot ? state.service_queue_snapshot : "",
        state.critical_queue_snapshot ? state.critical_queue_snapshot : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"thread_runtime_classes\":\"%s\",",
        state.thread_runtime_classes ? state.thread_runtime_classes : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"testlab\":\"%s\",\"camoufox\":\"%s\",\"background_commands\":\"%s\",",
        state.testlab_state ? state.testlab_state : "",
        state.camoufox_state ? state.camoufox_state : "",
        state.background_command_state ? state.background_command_state : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"liveness\":{\"driver_watchdog_ms\":%llu},",
        static_cast<unsigned long long>(state.driver_watchdog_ms));
    out += buf;

    const std::string ring_summary = metadata_ring::category_summary_string();
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"metadata_ring\":{\"summary\":\"%s\",\"total_events\":%llu,\"dropped\":%llu,\"rate_limited\":%llu},",
        ring_summary.c_str(),
        static_cast<unsigned long long>(metadata_ring::global_ring().total_events.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(metadata_ring::global_ring().dropped_events.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(metadata_ring::global_ring().rate_limited_events.load(std::memory_order_acquire)));
    out += buf;

    const std::string wer_summary = wer::correlation_summary_string();
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"wer_correlation\":\"%s\",",
        wer_summary.c_str());
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"executor\":\"%s\",",
        state.executor_snapshot ? state.executor_snapshot : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"taskflow_evaluation\":\"%s\",",
        state.taskflow_evaluation ? state.taskflow_evaluation : "");
    out += buf;

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "\"overload\":%s,\"top_pressure\":\"%s\"}}",
        state.overload_flag ? "true" : "false",
        state.top_pressure_contributors ? state.top_pressure_contributors : "");
    out += buf;

    return out;
}

inline void log_mcp_diagnostic_snapshot(const char* mcp_snapshot) {
    diag::log_tagged_fmt("mcp_srv",
        "MCP-DIAGNOSTIC-SNAPSHOT pid=%lu tid=%lu mcp={%.1300s}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        mcp_snapshot && mcp_snapshot[0] ? mcp_snapshot : "empty=1");
}

inline void log_queue_diagnostic_snapshot(const char* general, const char* service, const char* critical) {
    diag::log_tagged_fmt("diag",
        "QUEUE-DIAGNOSTIC-SNAPSHOT pid=%lu tid=%lu general={%.1400s} service={%.1400s} critical={%.1400s}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        general && general[0] ? general : "empty=1",
        service && service[0] ? service : "empty=1",
        critical && critical[0] ? critical : "empty=1");
}

inline void log_thread_runtime_diagnostic_snapshot(const char* classes) {
    diag::log_tagged_fmt("diag",
        "THREAD-RUNTIME-DIAGNOSTIC-SNAPSHOT pid=%lu tid=%lu classes=%s",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        classes ? classes : "<null>");
}

inline void log_diagnostic_snapshot_failed(const char* reason) {
    diag::log_tagged_fmt("diag",
        "DIAGNOSTIC-SNAPSHOT-FAILED pid=%lu tid=%lu reason=%s",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        reason ? reason : "<null>");
}

}
