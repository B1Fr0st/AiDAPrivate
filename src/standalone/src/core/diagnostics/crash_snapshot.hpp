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

namespace aida::diagnostics::crash {

struct crash_context_t {
    DWORD exception_code = 0;
    DWORD exception_flags = 0;
    void* exception_address = nullptr;
    std::uint64_t exception_record_count = 0;
    const char* exception_label = nullptr;
    const char* crash_boundary_name = nullptr;
    DWORD current_tid = 0;
    DWORD ui_owner_tid = 0;
    const char* last_render_phase = nullptr;
    std::uint64_t last_render_tick_ms = 0;
    std::uint64_t render_heartbeat_age_ms = 0;
    const char* last_wndproc_stage = nullptr;
    const char* last_dispatch_stage = nullptr;
    const char* last_message_pump_phase = nullptr;
    std::uint64_t last_successful_pump_return_ms = 0;
    std::uint64_t last_input_event_ms = 0;
    const char* testlab_phase = nullptr;
    const char* testlab_step = nullptr;
    std::uint64_t testlab_step_start_ms = 0;
    const char* camoufox_longop = nullptr;
    std::uint64_t license_liveness_ms = 0;
    std::uint64_t arc_liveness_ms = 0;
    std::uint64_t driver_watchdog_ms = 0;
    const char* thread_runtime_active_classes = nullptr;
    const char* mcp_snapshot = nullptr;
    const char* queue_snapshot = nullptr;
    const char* ui_dispatch_snapshot = nullptr;
    const char* capacity_snapshot = nullptr;
    const char* lease_registry_snapshot = nullptr;
    const char* downstream_snapshot = nullptr;
};

struct module_info_t {
    bool valid = false;
    char path[MAX_PATH] = {};
    std::uint64_t base = 0;
    std::uint64_t end = 0;
    std::uint64_t size = 0;
    std::uint64_t rva = 0;
    DWORD gle = 0;
};

inline module_info_t resolve_faulting_module(void* address) {
    module_info_t info;
    if (!address) return info;

    HMODULE hmod = nullptr;
    BOOL ok = GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        static_cast<LPCSTR>(address),
        &hmod);
    if (!ok || !hmod) {
        info.gle = GetLastError();
        return info;
    }

    info.valid = true;
    DWORD path_len = GetModuleFileNameA(hmod, info.path, static_cast<DWORD>(sizeof(info.path)));
    if (path_len == 0 || path_len >= sizeof(info.path)) {
        info.gle = GetLastError();
    }

    MODULEINFO mi{};
    if (GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi))) {
        info.base = reinterpret_cast<std::uint64_t>(mi.lpBaseOfDll);
        info.size = mi.SizeOfImage;
        info.end = info.base + info.size;
        const std::uint64_t addr_val = reinterpret_cast<std::uint64_t>(address);
        info.rva = addr_val >= info.base ? addr_val - info.base : 0;
    } else {
        info.gle = GetLastError();
    }

    return info;
}

inline void log_crash_snapshot(const crash_context_t& ctx) {
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = ctx.current_tid ? ctx.current_tid : GetCurrentThreadId();
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t elapsed = metadata_ring::elapsed_ms();

    FILETIME system_time{};
    GetSystemTimeAsFileTime(&system_time);
    ULARGE_INTEGER utc_val;
    utc_val.LowPart = system_time.dwLowDateTime;
    utc_val.HighPart = system_time.dwHighDateTime;

    module_info_t mod = resolve_faulting_module(ctx.exception_address);

    diag::log_tagged_critical_fmt("diag",
        "CRASH-SNAPSHOT pid=%lu tid=%lu exception_code=0x%08lX exception_flags=0x%08lX exception_addr=0x%llX exception_records=%llu label=%s boundary=%s utc_100ns=%llu tick_ms=%llu elapsed_ms=%llu ui_owner_tid=%lu fault_module=%s module_base=0x%llX module_end=0x%llX module_size=%llu rva=0x%llX module_gle=%lu render_phase=%s render_tick_ms=%llu render_heartbeat_age_ms=%llu wndproc_stage=%s dispatch_stage=%s pump_phase=%s last_pump_return_ms=%llu last_input_event_ms=%llu testlab_phase=%s testlab_step=%s testlab_step_start_ms=%llu camoufox_longop=%s license_liveness_ms=%llu arc_liveness_ms=%llu driver_watchdog_ms=%llu thread_runtime_classes=%s mcp={%.1300s} queues={%.2800s} ui_dispatch={%.1300s} capacity={%.1300s} lease_registry={%.1300s} downstream={%.1300s}",
        static_cast<unsigned long>(pid),
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(ctx.exception_code),
        static_cast<unsigned long>(ctx.exception_flags),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(ctx.exception_address)),
        static_cast<unsigned long long>(ctx.exception_record_count),
        ctx.exception_label ? ctx.exception_label : "<null>",
        ctx.crash_boundary_name ? ctx.crash_boundary_name : "<null>",
        static_cast<unsigned long long>(utc_val.QuadPart),
        static_cast<unsigned long long>(now),
        static_cast<unsigned long long>(elapsed),
        static_cast<unsigned long>(ctx.ui_owner_tid),
        mod.valid ? mod.path : "<unresolved>",
        static_cast<unsigned long long>(mod.base),
        static_cast<unsigned long long>(mod.end),
        static_cast<unsigned long long>(mod.size),
        static_cast<unsigned long long>(mod.rva),
        static_cast<unsigned long>(mod.gle),
        ctx.last_render_phase ? ctx.last_render_phase : "<null>",
        static_cast<unsigned long long>(ctx.last_render_tick_ms),
        static_cast<unsigned long long>(ctx.render_heartbeat_age_ms),
        ctx.last_wndproc_stage ? ctx.last_wndproc_stage : "<null>",
        ctx.last_dispatch_stage ? ctx.last_dispatch_stage : "<null>",
        ctx.last_message_pump_phase ? ctx.last_message_pump_phase : "<null>",
        static_cast<unsigned long long>(ctx.last_successful_pump_return_ms),
        static_cast<unsigned long long>(ctx.last_input_event_ms),
        ctx.testlab_phase ? ctx.testlab_phase : "<null>",
        ctx.testlab_step ? ctx.testlab_step : "<null>",
        static_cast<unsigned long long>(ctx.testlab_step_start_ms),
        ctx.camoufox_longop ? ctx.camoufox_longop : "<null>",
        static_cast<unsigned long long>(ctx.license_liveness_ms),
        static_cast<unsigned long long>(ctx.arc_liveness_ms),
        static_cast<unsigned long long>(ctx.driver_watchdog_ms),
        ctx.thread_runtime_active_classes ? ctx.thread_runtime_active_classes : "<null>",
        ctx.mcp_snapshot && ctx.mcp_snapshot[0] ? ctx.mcp_snapshot : "empty=1",
        ctx.queue_snapshot && ctx.queue_snapshot[0] ? ctx.queue_snapshot : "empty=1",
        ctx.ui_dispatch_snapshot && ctx.ui_dispatch_snapshot[0] ? ctx.ui_dispatch_snapshot : "empty=1",
        ctx.capacity_snapshot && ctx.capacity_snapshot[0] ? ctx.capacity_snapshot : "empty=1",
        ctx.lease_registry_snapshot && ctx.lease_registry_snapshot[0] ? ctx.lease_registry_snapshot : "empty=1",
        ctx.downstream_snapshot && ctx.downstream_snapshot[0] ? ctx.downstream_snapshot : "empty=1");

    metadata_ring::dump_to_log(64);

    wer::log_wer_correlation("crash_snapshot");

    const std::string log_paths = wer::known_log_paths_summary();
    diag::log_tagged_critical_fmt("diag",
        "CRASH-SNAPSHOT-LOG-PATHS pid=%lu log_paths=%s",
        static_cast<unsigned long>(pid),
        log_paths.c_str());
}

inline void emit_crash_breadcrumb(DWORD exception_code, void* exception_address, const char* boundary_name) {
    char reason[128];
    _snprintf_s(reason, sizeof(reason), _TRUNCATE,
        "exception=0x%08lX addr=0x%llX boundary=%s",
        static_cast<unsigned long>(exception_code),
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(exception_address)),
        boundary_name ? boundary_name : "<unknown>");
    metadata_ring::breadcrumb_options_t opts;
    opts.category = metadata_ring::breadcrumb_category_t::crash_exception;
    opts.label = "crash_snapshot";
    opts.reason = reason;
    opts.owner_subsystem = boundary_name;
    opts.force = true;
    metadata_ring::emit(std::move(opts));
}

}
