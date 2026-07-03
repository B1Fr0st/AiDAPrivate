#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "work_queue.hpp"

#include "standalone_driver.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "../../helpers/diag_log.hpp"

namespace driver_bridge {
bool protect_memory_for_bounded(uint32_t pid, uint64_t address, uint64_t size,
                                uint32_t new_protect, uint32_t* old_protect,
                                uint32_t deadline_ms);
}

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace page_guard_engine {


struct pg_capture_t {
    uint64_t timestamp;
    uint64_t fault_addr;
    uint64_t rip;
    uint64_t ctx_rax;
    uint64_t ctx_rcx;
    uint64_t ctx_rdx;
    uint32_t exception_code;
    uint32_t access_type;
    uint8_t  pad[8];
};

static_assert(sizeof(pg_capture_t) == 64, "pg_capture_t must be 64 bytes");


struct pg_ring_header_t {
    volatile uint32_t write_idx;
    volatile uint32_t read_idx;
    uint32_t          reserved0;
    uint32_t          reserved1;
};

static_assert(sizeof(pg_ring_header_t) == 16, "pg_ring_header_t must be 16 bytes");

static constexpr uint32_t RING_ENTRIES    = 256;
static constexpr uint32_t RING_TOTAL_SIZE = sizeof(pg_ring_header_t) +
                                             RING_ENTRIES * sizeof(pg_capture_t);
static constexpr uint32_t PAYLOAD_PREVIEW_MAX = 128;
static constexpr uint32_t REMOTE_CALL_DEFAULT_TIMEOUT_MS = 5000;
static constexpr uint32_t REMOTE_CALL_MAX_TIMEOUT_MS = 30000;
static constexpr size_t INSTALL_QUARANTINE_MAX_ACTIVE = 8;
static inline std::atomic<std::uint64_t> g_driver_remote_call_sequence{1};
inline std::atomic<bool> g_install_ready{false};


static constexpr size_t SHELLCODE_SIZE          = 265;
static constexpr size_t PATCH_RING_BASE         = 50;
static constexpr size_t PATCH_PAGE_BASE         = 183;
static constexpr size_t PATCH_PAGE_SIZE         = 196;
static constexpr size_t PATCH_ORIG_PROTECT      = 208;
static constexpr size_t PATCH_VIRT_PROTECT      = 227;
static constexpr uint64_t VEH_REGISTER_DIAG_MAGIC = 0xA1DA565548444947ull;

struct veh_register_remote_diag_t {
    uint64_t magic = 0;
    uint64_t rtl_add_fn = 0;
    uint64_t handler = 0;
    uint64_t result = 0;
    uint64_t completed = 0;
    uint32_t last_error_before = 0;
    uint32_t last_error_after = 0;
};

static_assert(sizeof(veh_register_remote_diag_t) == 48, "veh_register_remote_diag_t must be 48 bytes");

struct process_mitigation_diag_t {
    bool open_ok = false;
    DWORD open_error = 0;
    bool dynamic_ok = false;
    DWORD dynamic_error = 0;
    DWORD dynamic_flags = 0;
    bool cfg_ok = false;
    DWORD cfg_error = 0;
    DWORD cfg_flags = 0;
};

struct remote_call_diag_snapshot_t {
    std::string lower_phase;
    std::string lower_completion_reason;
    std::string lower_worker_error_category;
    std::string lower_worker_error_message;
    uint64_t call_id = 0;
    uint64_t function_address = 0;
    uint64_t arg1 = 0;
    uint64_t arg2 = 0;
    uint64_t arg3 = 0;
    uint64_t arg4 = 0;
    uint64_t result = 0;
    uint64_t deadline_ms = 0;
    uint64_t deadline_remaining_ms = 0;
    uint64_t elapsed_ms = 0;
    uint64_t lower_generation_at_entry = 0;
    uint64_t lower_generation_after = 0;
    uint64_t lower_queue_wait_ms = 0;
    uint64_t lower_elapsed_ms = 0;
    uint64_t lower_deadline_remaining_at_queue_ms = 0;
    uint64_t lower_deadline_remaining_at_start_ms = 0;
    uint64_t lower_deadline_remaining_at_finish_ms = 0;
    uint32_t pid = 0;
    uint32_t active_pid_entry = 0;
    uint32_t active_pid_after = 0;
    uint32_t timeout_ms = 0;
    uint32_t gle = 0;
    uint32_t lower_gle = 0;
    uint32_t lower_worker_tid = 0;
    uint32_t lower_worker_alive = 0;
    uint32_t lower_queue_depth_at_submit = 0;
    uint32_t lower_queue_depth_at_start = 0;
    uint32_t lower_queue_depth_after_pop = 0;
    uint32_t lower_inflight_at_submit = 0;
    uint32_t lower_inflight_at_start = 0;
    uint32_t lower_inflight_after = 0;
    int lower_worker_error_value = 0;
    bool completed = false;
    bool ok = false;
    bool cancelled_before = false;
    bool cancelled_after = false;
    bool deadline_expired_before = false;
    bool deadline_expired_after = false;
    bool stale_pid = false;
    bool late_completion = false;
    bool lower_completed = false;
    bool lower_ok = false;
    bool lower_stale_generation = false;
    bool lower_cancelled = false;
    bool lower_deadline_expired = false;
    bool lower_uninterruptible = false;
    bool lower_lock_timeout = false;
    bool lower_worker_exception = false;
    bool lower_worker_creation_failed = false;
    bool lower_late_completion = false;
    bool allow_zero_result = false;
    bool zero_result_rejected = false;
    bool caller_abandoned = false;
    bool removed_from_queue = false;
    bool popped_from_queue = false;
    bool execution_started = false;
    bool executing_abandoned = false;
    bool seh_exception = false;
    uint32_t seh_exception_code = 0;
    uint64_t seh_exception_address = 0;
    uint64_t seh_fault_address = 0;
    uint64_t seh_rip = 0;
    uint64_t seh_rsp = 0;
    uint64_t seh_rbp = 0;
};

static thread_local remote_call_diag_snapshot_t g_last_driver_remote_call_diag{};

static inline remote_call_diag_snapshot_t last_driver_remote_call_diag() noexcept
{
    return g_last_driver_remote_call_diag;
}

static inline process_mitigation_diag_t query_process_mitigation_diag(uint32_t pid) noexcept
{
    process_mitigation_diag_t out{};
    if (pid == 0) {
        out.open_error = ERROR_INVALID_PARAMETER;
        return out;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        out.open_error = GetLastError();
        return out;
    }
    out.open_ok = true;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_policy{};
    SetLastError(ERROR_SUCCESS);
    if (GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &dynamic_policy, sizeof(dynamic_policy))) {
        out.dynamic_ok = true;
        out.dynamic_flags = dynamic_policy.Flags;
    } else {
        out.dynamic_error = GetLastError();
    }
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg_policy{};
    SetLastError(ERROR_SUCCESS);
    if (GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg_policy, sizeof(cfg_policy))) {
        out.cfg_ok = true;
        out.cfg_flags = cfg_policy.Flags;
    } else {
        out.cfg_error = GetLastError();
    }
    CloseHandle(process);
    return out;
}

static inline bool kernel_operation_ready(uint32_t pid,
                                          const char* label,
                                          const char* operation,
                                          ULONGLONG started)
{
    std::string session_reason;
    const bool loaded = driver_bridge::is_loaded();
    const bool kernel = driver_bridge::using_kernel_driver();
    const bool session = driver_bridge::kernel_session_available(&session_reason);
    const bool dyn_ready = driver_bridge::dynamic_ioctls_ready();
    const uint32_t active = driver_bridge::attached_pid();
    const bool ok = pid != 0 && loaded && kernel && session && dyn_ready && active == pid;
    if (!ok) {
        diag::log_tagged_fmt("pg_sniff",
            "kernel_operation_fail_closed op=%s label=%s pid=%u active_pid=%u loaded=%d kernel=%d session=%d dyn_ready=%d reason=%s status=%s last_error=%s elapsed_ms=%llu",
            operation ? operation : "",
            label ? label : "",
            pid,
            active,
            loaded ? 1 : 0,
            kernel ? 1 : 0,
            session ? 1 : 0,
            dyn_ready ? 1 : 0,
            session_reason.empty() ? "<empty>" : session_reason.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            static_cast<unsigned long long>(GetTickCount64() - started));
    }
    return ok;
}

static inline const char* cooperative_stop_reason() noexcept
{
    if (driver_bridge::current_remote_call_cancelled())
        return "mcp_cancelled";
    const std::uint64_t deadline = driver_bridge::current_remote_call_deadline_ms();
    if (deadline != 0) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            return "mcp_deadline";
    }
    return nullptr;
}

static inline std::uint64_t cooperative_deadline_remaining_ms(ULONGLONG now) noexcept
{
    const std::uint64_t deadline = driver_bridge::current_remote_call_deadline_ms();
    if (deadline == 0 || now >= deadline)
        return 0;
    return deadline - now;
}

static inline uint32_t bounded_remote_call_timeout_ms(uint32_t timeout_ms) noexcept
{
    if (timeout_ms == 0)
        return REMOTE_CALL_DEFAULT_TIMEOUT_MS;
    return timeout_ms > REMOTE_CALL_MAX_TIMEOUT_MS ? REMOTE_CALL_MAX_TIMEOUT_MS : timeout_ms;
}

static inline std::uint64_t saturated_remote_call_deadline_ms(ULONGLONG start, uint32_t timeout_ms) noexcept
{
    constexpr std::uint64_t max_value = 0xFFFFFFFFFFFFFFFFull;
    const std::uint64_t start64 = static_cast<std::uint64_t>(start);
    if (static_cast<std::uint64_t>(timeout_ms) > max_value - start64)
        return max_value;
    return start64 + timeout_ms;
}

static inline std::uint64_t effective_remote_call_deadline_ms(ULONGLONG start, uint32_t effective_timeout_ms) noexcept
{
    std::uint64_t deadline = saturated_remote_call_deadline_ms(start, effective_timeout_ms);
    const std::uint64_t outer_deadline = driver_bridge::current_remote_call_deadline_ms();
    if (outer_deadline != 0 && outer_deadline < deadline)
        deadline = outer_deadline;
    return deadline;
}

static inline const char* remote_call_tool_from_label(const char* label) noexcept
{
    if (!label || !label[0])
        return "page_guard_engine";
    if (std::strstr(label, "api_monitor"))
        return "api_monitor";
    if (std::strstr(label, "network_pg_sniff"))
        return "network_pg_sniff";
    if (std::strstr(label, "find_what_accesses"))
        return "find_what_accesses";
    if (std::strstr(label, "testlab") || std::strstr(label, "aida_test") || std::strstr(label, "hunt_integrity"))
        return "testlab";
    return "page_guard_engine";
}

static inline void log_driver_region(uint32_t pid,
                                     const char* label,
                                     const char* phase,
                                     uint64_t address)
{
    driver_bridge::memory_region_t region{};
    const bool ok = driver_bridge::query_memory_for(pid, address, region);
    diag::log_tagged_fmt("pg_sniff",
        "driver_remote_call_region label=%s pid=%u active_pid=%u phase=%s addr=0x%llX query=%d base=0x%llX size=0x%llX state=0x%08X protect=0x%08X type=0x%08X status=%s last_error=%s",
        label ? label : "",
        pid,
        driver_bridge::attached_pid(),
        phase ? phase : "",
        static_cast<unsigned long long>(address),
        ok ? 1 : 0,
        static_cast<unsigned long long>(region.base),
        static_cast<unsigned long long>(region.size),
        region.state,
        region.protect,
        region.type,
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
}

static inline uint64_t driver_remote_call_impl(uint32_t pid,
                                               uint64_t function_address,
                                               uint64_t arg1,
                                               uint64_t arg2,
                                               uint64_t arg3,
                                               uint64_t arg4,
                                               const char* label)
{
    const ULONGLONG call_start = GetTickCount64();
    const std::uint64_t call_deadline = driver_bridge::current_remote_call_deadline_ms();
    const uint64_t call_id = g_driver_remote_call_sequence.fetch_add(1, std::memory_order_acq_rel);
    remote_call_diag_snapshot_t call_diag{};
    call_diag.call_id = call_id;
    call_diag.function_address = function_address;
    call_diag.arg1 = arg1;
    call_diag.arg2 = arg2;
    call_diag.arg3 = arg3;
    call_diag.arg4 = arg4;
    call_diag.deadline_ms = call_deadline;
    call_diag.timeout_ms = driver_bridge::current_remote_call_timeout_ms();
    call_diag.pid = pid;
    call_diag.active_pid_entry = driver_bridge::attached_pid();
    call_diag.cancelled_before = driver_bridge::current_remote_call_cancelled();
    call_diag.deadline_expired_before = call_deadline != 0 && call_start >= call_deadline;
    call_diag.deadline_remaining_ms = cooperative_deadline_remaining_ms(call_start);
    g_last_driver_remote_call_diag = call_diag;
    diag::log_tagged_fmt("pg_sniff",
        "driver_remote_call_entry call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX caller_tid=%lu tick=%llu cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu",
        static_cast<unsigned long long>(call_id),
        label ? label : "",
        driver_bridge::current_remote_call_tool_name(),
        driver_bridge::current_remote_call_diag_id(),
        pid,
        call_diag.active_pid_entry,
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(arg1),
        static_cast<unsigned long long>(arg2),
        static_cast<unsigned long long>(arg3),
        static_cast<unsigned long long>(arg4),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(call_start),
        call_diag.cancelled_before ? 1 : 0,
        call_diag.timeout_ms,
        static_cast<unsigned long long>(call_deadline),
        static_cast<unsigned long long>(call_diag.deadline_remaining_ms));
    if (pid == 0 || function_address == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        call_diag.completed = true;
        call_diag.gle = ERROR_INVALID_PARAMETER;
        call_diag.active_pid_after = driver_bridge::attached_pid();
        call_diag.elapsed_ms = GetTickCount64() - call_start;
        g_last_driver_remote_call_diag = call_diag;
        diag::log_tagged_fmt("pg_sniff",
            "driver_remote_call_reject call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u fn=0x%llX reason=invalid_args elapsed_ms=%llu gle=%lu status=%s last_error=%s",
            static_cast<unsigned long long>(call_id),
            label ? label : "",
            driver_bridge::current_remote_call_tool_name(),
            driver_bridge::current_remote_call_diag_id(),
            pid,
            call_diag.active_pid_entry,
            call_diag.active_pid_after,
            static_cast<unsigned long long>(function_address),
            static_cast<unsigned long long>(call_diag.elapsed_ms),
            static_cast<unsigned long>(GetLastError()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return 0;
    }
    if (!kernel_operation_ready(pid, label, "driver_remote_call", call_start)) {
        SetLastError(ERROR_NOT_READY);
        call_diag.completed = true;
        call_diag.gle = ERROR_NOT_READY;
        call_diag.active_pid_after = driver_bridge::attached_pid();
        call_diag.stale_pid = call_diag.active_pid_after != pid;
        call_diag.elapsed_ms = GetTickCount64() - call_start;
        g_last_driver_remote_call_diag = call_diag;
        diag::log_tagged_fmt("pg_sniff",
            "driver_remote_call_reject call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u fn=0x%llX reason=kernel_not_ready stale_pid=%d elapsed_ms=%llu gle=%lu status=%s last_error=%s",
            static_cast<unsigned long long>(call_id),
            label ? label : "",
            driver_bridge::current_remote_call_tool_name(),
            driver_bridge::current_remote_call_diag_id(),
            pid,
            call_diag.active_pid_entry,
            call_diag.active_pid_after,
            static_cast<unsigned long long>(function_address),
            call_diag.stale_pid ? 1 : 0,
            static_cast<unsigned long long>(call_diag.elapsed_ms),
            static_cast<unsigned long>(GetLastError()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return 0;
    }

    if (const char* stop_reason = cooperative_stop_reason()) {
        SetLastError(std::strcmp(stop_reason, "mcp_deadline") == 0 ? ERROR_TIMEOUT : ERROR_CANCELLED);
        call_diag.completed = true;
        call_diag.cancelled_after = driver_bridge::current_remote_call_cancelled();
        call_diag.deadline_expired_after = std::strcmp(stop_reason, "mcp_deadline") == 0;
        call_diag.gle = GetLastError();
        call_diag.active_pid_after = driver_bridge::attached_pid();
        call_diag.stale_pid = call_diag.active_pid_after != pid;
        call_diag.elapsed_ms = GetTickCount64() - call_start;
        call_diag.late_completion = call_diag.cancelled_after || call_diag.deadline_expired_after || call_diag.stale_pid;
        g_last_driver_remote_call_diag = call_diag;
        diag::log_tagged_fmt("pg_sniff",
            "driver_remote_call_cancelled_before_wait call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u fn=0x%llX reason=%s cancelled=%d timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu gle=%lu stale_pid=%d status=%s last_error=%s",
            static_cast<unsigned long long>(call_id),
            label ? label : "",
            driver_bridge::current_remote_call_tool_name(),
            driver_bridge::current_remote_call_diag_id(),
            pid,
            call_diag.active_pid_entry,
            call_diag.active_pid_after,
            static_cast<unsigned long long>(function_address),
            stop_reason,
            call_diag.cancelled_after ? 1 : 0,
            call_diag.timeout_ms,
            static_cast<unsigned long long>(call_deadline),
            static_cast<unsigned long long>(call_diag.elapsed_ms),
            static_cast<unsigned long>(GetLastError()),
            call_diag.stale_pid ? 1 : 0,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return 0;
    }

    log_driver_region(pid, label, "function_before_call", function_address);
    SetLastError(ERROR_SUCCESS);
    diag::log_tagged_fmt("pg_sniff",
        "driver_remote_call_wait_begin call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        label ? label : "",
        driver_bridge::current_remote_call_tool_name(),
        driver_bridge::current_remote_call_diag_id(),
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(function_address),
        driver_bridge::current_remote_call_cancelled() ? 1 : 0,
        driver_bridge::current_remote_call_timeout_ms(),
        static_cast<unsigned long long>(call_deadline),
        static_cast<unsigned long long>(cooperative_deadline_remaining_ms(GetTickCount64())),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    const uint64_t result = driver_bridge::call_function(function_address, arg1, arg2, arg3, arg4);
    const driver_bridge::remote_call_execution_diag_t lower_diag = driver_bridge::last_remote_call_execution_diag();
    const bool lower_execution_completed = lower_diag.completed && lower_diag.lower_ok;
    DWORD gle = lower_execution_completed ? ERROR_SUCCESS : GetLastError();
    if (!lower_execution_completed && gle == ERROR_SUCCESS)
        gle = lower_diag.gle != ERROR_SUCCESS ? lower_diag.gle : ERROR_GEN_FAILURE;
    const ULONGLONG call_end = GetTickCount64();
    const bool deadline_expired_after = call_deadline != 0 && call_end >= call_deadline;
    const bool cancelled_after = driver_bridge::current_remote_call_cancelled();
    const uint32_t active_after = driver_bridge::attached_pid();
    const bool stale_pid = active_after != pid;
    call_diag.completed = true;
    call_diag.ok = lower_execution_completed && !deadline_expired_after && !cancelled_after && !stale_pid;
    call_diag.result = result;
    call_diag.gle = stale_pid ? ERROR_OPERATION_ABORTED : (deadline_expired_after ? ERROR_TIMEOUT : (cancelled_after ? ERROR_CANCELLED : gle));
    call_diag.active_pid_after = active_after;
    call_diag.cancelled_after = cancelled_after;
    call_diag.deadline_expired_after = deadline_expired_after;
    call_diag.stale_pid = stale_pid;
    call_diag.late_completion = deadline_expired_after || cancelled_after || stale_pid;
    call_diag.elapsed_ms = call_end - call_start;
    call_diag.lower_phase = lower_diag.phase;
    call_diag.lower_completion_reason = lower_diag.completion_reason;
    call_diag.lower_worker_error_category = lower_diag.worker_error_category;
    call_diag.lower_worker_error_message = lower_diag.worker_error_message;
    call_diag.lower_generation_at_entry = lower_diag.generation_at_entry;
    call_diag.lower_generation_after = lower_diag.generation_after;
    call_diag.lower_queue_wait_ms = lower_diag.queue_wait_ms;
    call_diag.lower_elapsed_ms = lower_diag.lower_elapsed_ms;
    call_diag.lower_deadline_remaining_at_queue_ms = lower_diag.deadline_remaining_at_queue_ms;
    call_diag.lower_deadline_remaining_at_start_ms = lower_diag.deadline_remaining_at_start_ms;
    call_diag.lower_deadline_remaining_at_finish_ms = lower_diag.deadline_remaining_at_finish_ms;
    call_diag.lower_gle = lower_diag.gle;
    call_diag.lower_worker_tid = lower_diag.worker_tid;
    call_diag.lower_worker_alive = lower_diag.worker_alive;
    call_diag.lower_queue_depth_at_submit = lower_diag.queue_depth_at_submit;
    call_diag.lower_queue_depth_at_start = lower_diag.queue_depth_at_start;
    call_diag.lower_queue_depth_after_pop = lower_diag.queue_depth_after_pop;
    call_diag.lower_inflight_at_submit = lower_diag.inflight_at_submit;
    call_diag.lower_inflight_at_start = lower_diag.inflight_at_start;
    call_diag.lower_inflight_after = lower_diag.inflight_after;
    call_diag.lower_worker_error_value = lower_diag.worker_error_value;
    call_diag.lower_completed = lower_diag.completed;
    call_diag.lower_ok = lower_diag.lower_ok;
    call_diag.lower_stale_generation = lower_diag.stale_generation;
    call_diag.lower_cancelled = lower_diag.cancelled;
    call_diag.lower_deadline_expired = lower_diag.deadline_expired;
    call_diag.lower_uninterruptible =
        lower_diag.executing_abandoned ||
        (!lower_diag.completed &&
         (lower_diag.completion_reason == "cancelled" || lower_diag.completion_reason == "deadline"));
    call_diag.lower_lock_timeout = lower_diag.lower_lock_timeout;
    call_diag.lower_worker_exception = lower_diag.worker_exception;
    call_diag.lower_worker_creation_failed = lower_diag.worker_creation_failed;
    call_diag.lower_late_completion = lower_diag.late_completion;
    call_diag.allow_zero_result = lower_diag.allow_zero_result;
    call_diag.zero_result_rejected = lower_diag.zero_result_rejected;
    call_diag.caller_abandoned = lower_diag.caller_abandoned;
    call_diag.removed_from_queue = lower_diag.removed_from_queue;
    call_diag.popped_from_queue = lower_diag.popped_from_queue;
    call_diag.execution_started = lower_diag.execution_started;
    call_diag.executing_abandoned = lower_diag.executing_abandoned;
    call_diag.seh_exception = lower_diag.seh_exception;
    call_diag.seh_exception_code = lower_diag.seh_exception_code;
    call_diag.seh_exception_address = lower_diag.seh_exception_address;
    call_diag.seh_fault_address = lower_diag.seh_fault_address;
    call_diag.seh_rip = lower_diag.seh_rip;
    call_diag.seh_rsp = lower_diag.seh_rsp;
    call_diag.seh_rbp = lower_diag.seh_rbp;
    g_last_driver_remote_call_diag = call_diag;
    diag::log_tagged_fmt("pg_sniff",
        "driver_remote_call_done call_id=%llu label=%s tool=%s diag_id=%s pid=%u active_pid=%u active_after=%u method=driver_bridge::call_function fn=0x%llX result=0x%llX ok=%d execution_completed=%d result_nonzero=%d gle=%lu status=%s last_error=%s cancelled=%d timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d stale_pid=%d late_completion=%d lower_uninterruptible=%d lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_worker_tid=%lu lower_worker_alive=%u lower_queue_depth_submit=%u lower_queue_depth_start=%u lower_queue_depth_after_pop=%u lower_inflight_submit=%u lower_inflight_start=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu lower_deadline_remaining_queue_ms=%llu lower_deadline_remaining_start_ms=%llu lower_deadline_remaining_finish_ms=%llu lower_worker_exception=%d lower_worker_creation_failed=%d zero_result_rejected=%d removed_from_queue=%d popped=%d execution_started=%d executing_abandoned=%d seh_exception=%d seh_code=0x%08lX lower_error_value=%d lower_error_category=%s lower_error_message=%s elapsed_ms=%llu",
        static_cast<unsigned long long>(call_id),
        label ? label : "",
        driver_bridge::current_remote_call_tool_name(),
        driver_bridge::current_remote_call_diag_id(),
        pid,
        call_diag.active_pid_entry,
        active_after,
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(result),
        call_diag.ok ? 1 : 0,
        lower_execution_completed ? 1 : 0,
        result != 0 ? 1 : 0,
        static_cast<unsigned long>(call_diag.gle),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str(),
        cancelled_after ? 1 : 0,
        call_diag.timeout_ms,
        static_cast<unsigned long long>(call_deadline),
        deadline_expired_after ? 1 : 0,
        stale_pid ? 1 : 0,
        call_diag.late_completion ? 1 : 0,
        call_diag.lower_uninterruptible ? 1 : 0,
        call_diag.lower_phase.c_str(),
        call_diag.lower_completion_reason.c_str(),
        call_diag.lower_completed ? 1 : 0,
        call_diag.lower_ok ? 1 : 0,
        static_cast<unsigned long>(call_diag.lower_gle),
        static_cast<unsigned long>(call_diag.lower_worker_tid),
        call_diag.lower_worker_alive,
        call_diag.lower_queue_depth_at_submit,
        call_diag.lower_queue_depth_at_start,
        call_diag.lower_queue_depth_after_pop,
        call_diag.lower_inflight_at_submit,
        call_diag.lower_inflight_at_start,
        call_diag.lower_inflight_after,
        static_cast<unsigned long long>(call_diag.lower_queue_wait_ms),
        static_cast<unsigned long long>(call_diag.lower_elapsed_ms),
        static_cast<unsigned long long>(call_diag.lower_deadline_remaining_at_queue_ms),
        static_cast<unsigned long long>(call_diag.lower_deadline_remaining_at_start_ms),
        static_cast<unsigned long long>(call_diag.lower_deadline_remaining_at_finish_ms),
        call_diag.lower_worker_exception ? 1 : 0,
        call_diag.lower_worker_creation_failed ? 1 : 0,
        call_diag.zero_result_rejected ? 1 : 0,
        call_diag.removed_from_queue ? 1 : 0,
        call_diag.popped_from_queue ? 1 : 0,
        call_diag.execution_started ? 1 : 0,
        call_diag.executing_abandoned ? 1 : 0,
        call_diag.seh_exception ? 1 : 0,
        static_cast<unsigned long>(call_diag.seh_exception_code),
        call_diag.lower_worker_error_value,
        call_diag.lower_worker_error_category.c_str(),
        call_diag.lower_worker_error_message.c_str(),
        static_cast<unsigned long long>(call_diag.elapsed_ms));
    if (deadline_expired_after || cancelled_after || stale_pid) {
        SetLastError(stale_pid ? ERROR_OPERATION_ABORTED : (cancelled_after ? ERROR_CANCELLED : ERROR_TIMEOUT));
        return 0;
    }
    if (!lower_execution_completed) {
        SetLastError(gle);
        return 0;
    }
    if (result == 0)
        SetLastError(ERROR_SUCCESS);
    return result;
}

static inline uint64_t driver_remote_call(uint32_t pid,
                                          uint64_t function_address,
                                          uint64_t arg1,
                                          uint64_t arg2 = 0,
                                          uint64_t arg3 = 0,
                                          uint64_t arg4 = 0,
                                          const char* label = "remote_call")
{
    const ULONGLONG context_start = GetTickCount64();
    const uint32_t inherited_timeout = driver_bridge::current_remote_call_timeout_ms();
    const uint32_t effective_timeout = inherited_timeout != 0 ? bounded_remote_call_timeout_ms(inherited_timeout) : REMOTE_CALL_DEFAULT_TIMEOUT_MS;
    const std::uint64_t inherited_deadline = driver_bridge::current_remote_call_deadline_ms();
    std::uint64_t deadline = inherited_deadline;
    if (deadline == 0)
        deadline = saturated_remote_call_deadline_ms(context_start, effective_timeout);
    char generated_diag_id[128] = {};
    const char* diag_id = driver_bridge::current_remote_call_diag_id();
    if (!diag_id || !diag_id[0]) {
        _snprintf_s(generated_diag_id, sizeof(generated_diag_id), _TRUNCATE,
            "pg-remote-%lu-%llu",
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(context_start));
        diag_id = generated_diag_id;
    }
    const char* tool = driver_bridge::current_remote_call_tool_name();
    if (!tool || !tool[0])
        tool = remote_call_tool_from_label(label);
    driver_bridge::remote_call_context_t context{};
    context.label = label;
    context.tool = tool;
    context.diag_id = diag_id;
    context.pid = pid;
    context.timeout_ms = effective_timeout;
    context.deadline_ms = deadline;
    context.cancel_token = mcp_standalone::current_cancel_token();
    context.require_deadline = true;
    driver_bridge::scoped_remote_call_context_t scoped_context(context);
    diag::log_tagged_fmt("pg_sniff",
        "driver_remote_call_context label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu inherited_deadline_ms=%llu cancelled=%d",
        label ? label : "",
        tool ? tool : "",
        diag_id ? diag_id : "",
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(function_address),
        effective_timeout,
        static_cast<unsigned long long>(deadline),
        static_cast<unsigned long long>(cooperative_deadline_remaining_ms(context_start)),
        static_cast<unsigned long long>(inherited_deadline),
        driver_bridge::current_remote_call_cancelled() ? 1 : 0);
    return driver_remote_call_impl(pid, function_address, arg1, arg2, arg3, arg4, label);
}

static inline uint64_t remote_thread_call(uint32_t pid,
                                          uint64_t function_address,
                                          uint64_t arg1,
                                          uint64_t arg2 = 0,
                                          uint64_t arg3 = 0,
                                          uint64_t arg4 = 0,
                                          uint32_t timeout_ms = 0,
                                          const char* label = "remote_call",
                                          bool allow_zero = false)
{
    const ULONGLONG call_start = GetTickCount64();
    const uint32_t effective_timeout = bounded_remote_call_timeout_ms(timeout_ms);
    const std::uint64_t deadline = effective_remote_call_deadline_ms(call_start, effective_timeout);
    char generated_diag_id[128] = {};
    const char* inherited_diag_id = mcp_standalone::current_call_diag_id();
    const char* diag_id = inherited_diag_id && inherited_diag_id[0] ? inherited_diag_id : nullptr;
    if (!diag_id) {
        _snprintf_s(generated_diag_id, sizeof(generated_diag_id), _TRUNCATE,
            "pg-thread-%lu-%llu",
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(call_start));
        diag_id = generated_diag_id;
    }
    const char* inherited_tool = mcp_standalone::current_call_tool_name();
    const char* tool = inherited_tool && inherited_tool[0] ? inherited_tool : remote_call_tool_from_label(label);
    driver_bridge::remote_call_context_t context{};
    context.label = label;
    context.tool = tool;
    context.diag_id = diag_id;
    context.pid = pid;
    context.timeout_ms = effective_timeout;
    context.deadline_ms = deadline;
    context.cancel_token = mcp_standalone::current_cancel_token();
    context.require_deadline = true;
    context.allow_zero_result = allow_zero;
    driver_bridge::scoped_remote_call_context_t scoped_context(context);
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_begin label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX requested_timeout_ms=%u effective_timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled=%d",
        label ? label : "",
        tool ? tool : "",
        diag_id ? diag_id : "",
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(function_address),
        timeout_ms,
        effective_timeout,
        static_cast<unsigned long long>(deadline),
        static_cast<unsigned long long>(cooperative_deadline_remaining_ms(call_start)),
        driver_bridge::current_remote_call_cancelled() ? 1 : 0);
    if (deadline == 0 || call_start >= deadline || driver_bridge::current_remote_call_cancelled()) {
        SetLastError(driver_bridge::current_remote_call_cancelled() ? ERROR_CANCELLED : ERROR_TIMEOUT);
        diag::log_tagged_fmt("pg_sniff",
            "remote_thread_call_preempt label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX requested_timeout_ms=%u effective_timeout_ms=%u deadline_ms=%llu elapsed_ms=%llu cancelled=%d gle=%lu status=%s last_error=%s",
            label ? label : "",
            tool ? tool : "",
            diag_id ? diag_id : "",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(function_address),
            timeout_ms,
            effective_timeout,
            static_cast<unsigned long long>(deadline),
            static_cast<unsigned long long>(GetTickCount64() - call_start),
            driver_bridge::current_remote_call_cancelled() ? 1 : 0,
            static_cast<unsigned long>(GetLastError()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return 0;
    }
    const uint64_t result = driver_remote_call(pid, function_address, arg1, arg2, arg3, arg4, label);
    const remote_call_diag_snapshot_t remote_diag = last_driver_remote_call_diag();
    DWORD gle = remote_diag.ok ? ERROR_SUCCESS : GetLastError();
    if (!remote_diag.ok && gle == ERROR_SUCCESS)
        gle = remote_diag.gle != ERROR_SUCCESS ? remote_diag.gle : ERROR_GEN_FAILURE;
    const ULONGLONG call_end = GetTickCount64();
    const bool late_completion = deadline != 0 && call_end >= deadline;
    const bool cancelled_after = driver_bridge::current_remote_call_cancelled();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_done label=%s tool=%s diag_id=%s pid=%u active_pid=%u fn=0x%llX result=0x%llX ok=%d execution_completed=%d result_nonzero=%d gle=%lu requested_timeout_ms=%u effective_timeout_ms=%u deadline_ms=%llu deadline_expired_after=%d late_completion=%d lower_uninterruptible=%d cancelled=%d lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_queue_depth_submit=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu elapsed_ms=%llu status=%s last_error=%s",
        label ? label : "",
        tool ? tool : "",
        diag_id ? diag_id : "",
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(result),
        remote_diag.ok ? 1 : 0,
        remote_diag.lower_completed && remote_diag.lower_ok ? 1 : 0,
        result != 0 ? 1 : 0,
        static_cast<unsigned long>(late_completion ? ERROR_TIMEOUT : (cancelled_after ? ERROR_CANCELLED : gle)),
        timeout_ms,
        effective_timeout,
        static_cast<unsigned long long>(deadline),
        late_completion ? 1 : 0,
        late_completion ? 1 : 0,
        remote_diag.lower_uninterruptible ? 1 : 0,
        cancelled_after ? 1 : 0,
        remote_diag.lower_phase.c_str(),
        remote_diag.lower_completion_reason.c_str(),
        remote_diag.lower_completed ? 1 : 0,
        remote_diag.lower_ok ? 1 : 0,
        static_cast<unsigned long>(remote_diag.lower_gle),
        remote_diag.lower_queue_depth_at_submit,
        remote_diag.lower_inflight_after,
        static_cast<unsigned long long>(remote_diag.lower_queue_wait_ms),
        static_cast<unsigned long long>(remote_diag.lower_elapsed_ms),
        static_cast<unsigned long long>(call_end - call_start),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    if (late_completion || cancelled_after) {
        SetLastError(cancelled_after ? ERROR_CANCELLED : ERROR_TIMEOUT);
        return 0;
    }
    if (result == 0)
        SetLastError(gle);
    return result;
}


static inline std::vector<uint8_t> generate_veh_register_wrapper_shellcode()
{
    std::vector<uint8_t> code;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        code.insert(code.end(), bytes.begin(), bytes.end());
    };
    auto emit_u64 = [&](uint64_t value) {
        for (int i = 0; i < 8; ++i)
            code.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    };
    emit({0x53});
    emit({0x48, 0x83, 0xEC, 0x20});
    emit({0x4C, 0x89, 0xCB});
    emit({0x48, 0xB8});
    emit_u64(VEH_REGISTER_DIAG_MAGIC);
    emit({0x48, 0x89, 0x03});
    emit({0x48, 0x89, 0x4B, 0x08});
    emit({0x4C, 0x89, 0x43, 0x10});
    emit({0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00});
    emit({0x89, 0x43, 0x28});
    emit({0x48, 0x89, 0xD1});
    emit({0x4C, 0x89, 0xC2});
    emit({0x48, 0x8B, 0x43, 0x08});
    emit({0xFF, 0xD0});
    emit({0x48, 0x89, 0x43, 0x18});
    emit({0x65, 0x8B, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00});
    emit({0x89, 0x43, 0x2C});
    emit({0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    emit({0x48, 0x89, 0x43, 0x20});
    emit({0x48, 0x8B, 0x43, 0x18});
    emit({0x48, 0x83, 0xC4, 0x20});
    emit({0x5B});
    emit({0xC3});
    return code;
}


static inline std::vector<uint8_t> generate_veh_shellcode(
        uint64_t ring_base,
        uint64_t page_base,
        uint64_t page_size,
        uint32_t orig_protect,
        uint64_t virt_protect_fn)
{


    static const uint8_t kTemplate[SHELLCODE_SIZE] = {

        0x53,
        0x56,
        0x57,
        0x41, 0x55,
        0x41, 0x56,
        0x48, 0x83, 0xEC, 0x28,
        0x49, 0x89, 0xCD,
        0x48, 0x8B, 0x19,
        0x8B, 0x03,
        0x3D, 0x01, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x12, 0x00, 0x00, 0x00,
        0x3D, 0x04, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x8C, 0x00, 0x00, 0x00,
        0x33, 0xC0,
        0xE9, 0xCD, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x8B, 0x00,
        0x45, 0x0F, 0xB6, 0xC0,
        0x41, 0xC1, 0xE0, 0x06,
        0x48, 0x8D, 0x48, 0x10,
        0x49, 0x03, 0xC8,
        0x48, 0x89, 0xC6,
        0x0F, 0x31,
        0x48, 0xC1, 0xE2, 0x20,
        0x48, 0x0B, 0xC2,
        0x48, 0x89, 0x01,
        0x48, 0x8B, 0x43, 0x28,
        0x48, 0x89, 0x41, 0x08,
        0x49, 0x8B, 0x55, 0x08,
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x10,
        0x48, 0x8B, 0x42, 0x78,
        0x48, 0x89, 0x41, 0x18,
        0x48, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x20,
        0x48, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x28,
        0x8B, 0x03,
        0x89, 0x41, 0x30,
        0x8B, 0x43, 0x20,
        0x89, 0x41, 0x34,
        0x8B, 0x06,
        0xFF, 0xC0,
        0x0F, 0xB6, 0xC0,
        0x89, 0x06,
        0x81, 0x4A, 0x44, 0x00, 0x01, 0x00, 0x00,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE9, 0x48, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC2,
        0xB8,
        0x00, 0x00, 0x00, 0x00,
        0x0D, 0x00, 0x01, 0x00, 0x00,
        0x41, 0x89, 0xC0,
        0x4C, 0x8D, 0x4C, 0x24, 0x20,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0x49, 0x8B, 0x4D, 0x08,
        0x81, 0x61, 0x44, 0xFF, 0xFE, 0xFF, 0xFF,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,

        0x48, 0x83, 0xC4, 0x28,
        0x41, 0x5E,
        0x41, 0x5D,
        0x5F,
        0x5E,
        0x5B,
        0xC3,
    };

    static_assert(sizeof(kTemplate) == SHELLCODE_SIZE,
                  "shellcode template size mismatch");

    std::vector<uint8_t> sc(kTemplate, kTemplate + SHELLCODE_SIZE);


    auto patch64 = [&](size_t off, uint64_t v) {
        memcpy(sc.data() + off, &v, 8);
    };
    auto patch32 = [&](size_t off, uint32_t v) {
        memcpy(sc.data() + off, &v, 4);
    };

    patch64(PATCH_RING_BASE,    ring_base);
    patch64(PATCH_PAGE_BASE,    page_base);
    patch64(PATCH_PAGE_SIZE,    page_size);
    patch32(PATCH_ORIG_PROTECT, orig_protect);
    patch64(PATCH_VIRT_PROTECT, virt_protect_fn);

    return sc;
}

struct pg_capture_record_t {
    pg_capture_t metadata{};
    uint64_t payload_addr = 0;
    uint64_t payload_offset = 0;
    uint32_t payload_size = 0;
    bool payload_read = false;
    bool payload_truncated = false;
    std::string payload_source;
    std::vector<uint8_t> payload;
};

static inline bool address_in_range(uint64_t base, uint64_t size, uint64_t address) noexcept {
    return size != 0 && address >= base && (address - base) < size;
}

static inline std::string hex_u64(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

static inline std::string payload_hex_preview(const std::vector<uint8_t>& bytes, size_t max_bytes = PAYLOAD_PREVIEW_MAX) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    const size_t show = std::min(bytes.size(), max_bytes);
    out.reserve(show * 3);
    for (size_t i = 0; i < show; ++i) {
        const uint8_t b = bytes[i];
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
        if (i + 1 != show)
            out.push_back(' ');
    }
    return out;
}

static inline std::string payload_plaintext_preview(const std::vector<uint8_t>& bytes, size_t max_chars = PAYLOAD_PREVIEW_MAX) {
    std::string out;
    const size_t show = std::min(bytes.size(), max_chars);
    out.reserve(show);
    for (size_t i = 0; i < show; ++i) {
        const uint8_t b = bytes[i];
        out.push_back((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.');
    }
    return out;
}

static inline bool has_payload_preview(const pg_capture_record_t& record) noexcept {
    return record.payload_read && record.payload_size != 0 && !record.payload.empty();
}

template <typename Json>
static inline void serialize_payload_fields(Json& out, const pg_capture_record_t& record) {
    out["payload_addr"] = hex_u64(record.payload_addr);
    out["payload_offset"] = record.payload_offset;
    out["payload_size"] = record.payload_size;
    out["payload_preview_size"] = static_cast<uint32_t>(record.payload.size());
    out["payload_available"] = has_payload_preview(record);
    out["payload_truncated"] = record.payload_truncated;
    out["payload_source"] = record.payload_source;
    out["hex_preview"] = payload_hex_preview(record.payload);
    out["plaintext_preview"] = payload_plaintext_preview(record.payload);
}

static inline uint64_t resolve_system_export_for_pid(uint32_t pid,
                                                     uint64_t module_base,
                                                     uint64_t module_size,
                                                     const char* module_name,
                                                     const char* function_name,
                                                     const char* phase,
                                                     ULONGLONG phase_start) {
    const ULONGLONG t0 = GetTickCount64();
    uint64_t va = driver_bridge::resolve_export_for_kernel_strict(pid, module_base, function_name);
    diag::log_tagged_fmt("pg_sniff",
        "export_resolve_driver phase=%s pid=%u active_pid=%u module=%s base=0x%llX function=%s va=0x%llX elapsed_ms=%llu phase_elapsed_ms=%llu outcome=%s",
        phase ? phase : "",
        pid,
        driver_bridge::attached_pid(),
        module_name ? module_name : "",
        static_cast<unsigned long long>(module_base),
        function_name ? function_name : "",
        static_cast<unsigned long long>(va),
        static_cast<unsigned long long>(GetTickCount64() - t0),
        static_cast<unsigned long long>(GetTickCount64() - phase_start),
        va != 0 ? "resolved" : "zero");
    if (va != 0)
        return va;

    diag::log_tagged_fmt("pg_sniff",
        "export_resolve_fail_closed phase=%s pid=%u active_pid=%u module=%s base=0x%llX size=0x%llX function=%s elapsed_ms=%llu phase_elapsed_ms=%llu status=%s last_error=%s",
        phase ? phase : "",
        pid,
        driver_bridge::attached_pid(),
        module_name ? module_name : "",
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(module_size),
        function_name ? function_name : "",
        static_cast<unsigned long long>(GetTickCount64() - t0),
        static_cast<unsigned long long>(GetTickCount64() - phase_start),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    return 0;
}

static inline uint64_t remove_vectored_exception_handler_remote(uint32_t pid,
                                                                uint64_t module_base,
                                                                uint64_t remove_fn,
                                                                uint64_t veh_handle,
                                                                const char* phase,
                                                                ULONGLONG phase_start) {
    const ULONGLONG t0 = GetTickCount64();
    const process_mitigation_diag_t mitigation = query_process_mitigation_diag(pid);
    diag::log_tagged_fmt("pg_sniff",
        "remove_veh_remote_begin phase=%s pid=%u active_pid=%u module=ntdll.dll base=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX handle=0x%llX mitigation_open=%d mitigation_open_error=%lu dyn_ok=%d dyn_error=%lu dyn_flags=0x%08lX cfg_ok=%d cfg_error=%lu cfg_flags=0x%08lX elapsed_ms=%llu",
        phase ? phase : "",
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(remove_fn),
        static_cast<unsigned long long>(veh_handle),
        mitigation.open_ok ? 1 : 0,
        static_cast<unsigned long>(mitigation.open_error),
        mitigation.dynamic_ok ? 1 : 0,
        static_cast<unsigned long>(mitigation.dynamic_error),
        static_cast<unsigned long>(mitigation.dynamic_flags),
        mitigation.cfg_ok ? 1 : 0,
        static_cast<unsigned long>(mitigation.cfg_error),
        static_cast<unsigned long>(mitigation.cfg_flags),
        static_cast<unsigned long long>(GetTickCount64() - phase_start));
    if (pid == 0 || remove_fn == 0 || veh_handle == 0) {
        diag::log_tagged_fmt("pg_sniff",
            "remove_veh_remote_skip phase=%s pid=%u active_pid=%u module=ntdll.dll base=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX handle=0x%llX elapsed_ms=%llu outcome=invalid_args gle=%lu",
            phase ? phase : "",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(remove_fn),
            static_cast<unsigned long long>(veh_handle),
            static_cast<unsigned long long>(GetTickCount64() - phase_start),
            static_cast<unsigned long>(ERROR_INVALID_PARAMETER));
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    SetLastError(ERROR_SUCCESS);
    const uint64_t removed = driver_remote_call(pid, remove_fn, veh_handle, 0, 0, 0, "RtlRemoveVectoredExceptionHandler");
    const DWORD gle = removed != 0 ? ERROR_SUCCESS : GetLastError();
    diag::log_tagged_fmt("pg_sniff",
        "remove_veh_remote_done phase=%s pid=%u active_pid=%u module=ntdll.dll base=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX handle=0x%llX result=0x%llX ok=%d gle=%lu status=%s last_error=%s elapsed_ms=%llu phase_elapsed_ms=%llu",
        phase ? phase : "",
        pid,
        driver_bridge::attached_pid(),
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(remove_fn),
        static_cast<unsigned long long>(veh_handle),
        static_cast<unsigned long long>(removed),
        removed != 0 ? 1 : 0,
        static_cast<unsigned long>(gle),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str(),
        static_cast<unsigned long long>(GetTickCount64() - t0),
        static_cast<unsigned long long>(GetTickCount64() - phase_start));
    if (removed == 0)
        SetLastError(gle);
    return removed;
}


struct pg_session_t {
    uint32_t session_id    = 0;
    uint32_t pid           = 0;
    uint64_t target_addr   = 0;
    uint64_t region_size   = 0;
    uint64_t ring_addr     = 0;
    uint64_t sc_addr       = 0;
    uint32_t orig_protect  = 0;
    uint64_t veh_handle    = 0;
    uint64_t ntdll_base    = 0;
    uint64_t ntdll_size    = 0;
    uint64_t rtl_remove_veh_fn = 0;

    std::mutex                      captures_mutex;
    std::mutex                      drain_mutex;
    std::mutex                      poll_wait_mutex;
    std::condition_variable         poll_cv;
    std::queue<pg_capture_record_t> captures;

    std::atomic<bool>          polling{false};
    std::atomic<bool>          exited{false};
    std::atomic<bool>          teardown_requested{false};
    std::atomic<bool>          protection_restored{false};
    std::atomic<bool>          veh_removed{false};


    uint32_t prev_write_idx     = 0;
    uint32_t prev_raw_write_idx = 0;
    bool     ring_initialized   = false;
    uint64_t total_captured     = 0;
    uint64_t estimated_drops    = 0;
    uint64_t header_read_failures = 0;
    uint64_t entry_read_failures  = 0;
    uint64_t rearm_attempts       = 0;
    uint64_t rearm_failures       = 0;
    std::atomic<size_t> payload_budget{static_cast<size_t>(-1)};
    std::atomic<size_t> payload_reads{0};
    std::atomic<bool> capture_payloads{true};
    std::atomic<uint32_t> max_records_per_drain{0};
    std::atomic<bool> auto_poll{true};
    std::atomic<bool> drain_active{false};

    pg_session_t() = default;
    ~pg_session_t() {
        polling.store(false, std::memory_order_release);
        poll_cv.notify_all();
        for (int i = 0; i < 2000; ++i) {
            if (exited.load(std::memory_order_acquire))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    pg_session_t(const pg_session_t&)            = delete;
    pg_session_t& operator=(const pg_session_t&) = delete;
};


class pg_engine_t {
    struct active_pid_scope_t {
        uint32_t previous_pid = 0;
        uint32_t entered_pid = 0;
        bool swapped = false;

        static bool pid_alive(uint32_t pid, uint32_t* exit_code_out = nullptr) {
            if (exit_code_out)
                *exit_code_out = 0;
            if (pid == 0)
                return false;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!process) {
                const DWORD err = GetLastError();
                if (exit_code_out)
                    *exit_code_out = err;
                return err == ERROR_ACCESS_DENIED;
            }
            DWORD exit_code = 0;
            const BOOL ok = GetExitCodeProcess(process, &exit_code);
            const DWORD err = ok ? 0 : GetLastError();
            CloseHandle(process);
            if (exit_code_out)
                *exit_code_out = ok ? static_cast<uint32_t>(exit_code) : err;
            return ok && exit_code == STILL_ACTIVE;
        }

        static bool attached_contains(uint32_t pid) {
            const auto pids = driver_bridge::attached_pids();
            for (auto attached : pids) {
                if (attached == pid)
                    return true;
            }
            return false;
        }

        bool enter(uint32_t pid) {
            previous_pid = driver_bridge::attached_pid();
            entered_pid = pid;
            if (previous_pid == pid)
                return true;
            bool already_attached = false;
            const auto pids = driver_bridge::attached_pids();
            for (auto attached : pids) {
                if (attached == pid) {
                    already_attached = true;
                    break;
                }
            }
            if (!already_attached && !driver_bridge::attach_additional(pid))
                return false;
            if (!driver_bridge::set_active_pid(pid))
                return false;
            swapped = previous_pid != pid;
            return driver_bridge::attached_pid() == pid;
        }

        ~active_pid_scope_t() {
            if (!swapped)
                return;
            uint32_t current_pid = driver_bridge::attached_pid();
            uint32_t current_exit = 0;
            const bool current_alive = current_pid != 0 && pid_alive(current_pid, &current_exit);
            if (current_pid != entered_pid && current_pid != 0 && current_alive) {
                diag::log_tagged_fmt("pg_sniff", "active_pid_scope_skip_restore entered=%u previous=%u current=%u current_alive=%d current_exit=0x%08X",
                    entered_pid,
                    previous_pid,
                    current_pid,
                    current_alive ? 1 : 0,
                    current_exit);
                return;
            }
            const DWORD restore_start = GetTickCount();
            uint32_t selected_pid = 0;
            uint32_t previous_exit = 0;
            bool previous_alive = false;
            bool previous_known = false;
            bool restored = false;
            const char* method = "none";
            if (previous_pid != 0) {
                previous_alive = pid_alive(previous_pid, &previous_exit);
                previous_known = attached_contains(previous_pid);
                if (!previous_known && previous_alive)
                    previous_known = driver_bridge::attach_additional(previous_pid);
                if (previous_known && previous_alive) {
                    method = "previous";
                    restored = driver_bridge::set_active_pid(previous_pid);
                    if (restored)
                        selected_pid = previous_pid;
                }
            }
            if (!restored) {
                const auto pids = driver_bridge::attached_pids();
                for (auto pid : pids) {
                    if (pid == 0 || pid == entered_pid)
                        continue;
                    uint32_t exit_code = 0;
                    if (!pid_alive(pid, &exit_code))
                        continue;
                    method = "fallback_live_attached";
                    restored = driver_bridge::set_active_pid(pid);
                    if (restored) {
                        selected_pid = pid;
                        break;
                    }
                }
            }
            if (!restored) {
                method = previous_pid == 0 ? "clear_no_previous" : "clear_no_live_restore";
                driver_bridge::clear_active_pid();
            }
            diag::log_tagged_fmt("pg_sniff",
                "active_pid_scope_restore entered=%u previous=%u current_before=%u previous_known=%d previous_alive=%d previous_exit=0x%08X method=%s restored=%d selected=%u active_after=%u status=%s last_error=%s elapsed_ms=%lu",
                entered_pid,
                previous_pid,
                current_pid,
                previous_known ? 1 : 0,
                previous_alive ? 1 : 0,
                previous_exit,
                method,
                restored ? 1 : 0,
                selected_pid,
                driver_bridge::attached_pid(),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long>(GetTickCount() - restore_start));
        }
    };

    struct install_quarantine_t {
        uint64_t quarantine_id = 0;
        uint64_t call_id = 0;
        uint64_t shellcode_addr = 0;
        uint64_t ring_addr = 0;
        uint64_t context_addr = 0;
        uint64_t wrapper_addr = 0;
        uint64_t diag_addr = 0;
        uint64_t rtl_add_fn = 0;
        uint64_t rtl_remove_fn = 0;
        uint64_t veh_result = 0;
        uint64_t install_generation = 0;
        uint64_t created_ms = 0;
        uint32_t pid = 0;
        uint32_t active_pid = 0;
        uint32_t remote_gle = 0;
        bool active = false;
        bool reserved = false;
    };

public:
    pg_engine_t() = default;
    ~pg_engine_t() {
        std::vector<std::shared_ptr<pg_session_t>> snapshot;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            snapshot.reserve(sessions_.size() + retired_sessions_.size());
            for (auto& [sid, sess] : sessions_) {
                (void)sid;
                if (sess)
                    snapshot.push_back(sess);
            }
            for (auto& sess : retired_sessions_) {
                if (sess)
                    snapshot.push_back(sess);
            }
            sessions_.clear();
            retired_sessions_.clear();
        }
        for (auto& sess : snapshot) {
            stop_session_poller(sess, 2000, "engine_destroy");
        }
    }

    pg_engine_t(const pg_engine_t&)            = delete;
    pg_engine_t& operator=(const pg_engine_t&) = delete;


    uint32_t install(uint32_t pid, uint64_t target_addr, uint64_t region_size, bool capture_payloads = true, uint32_t max_records_per_drain = 0, bool auto_poll = true) {
        const ULONGLONG install_start = GetTickCount64();
        const uint64_t requested_addr = target_addr;
        const uint64_t requested_size = region_size;
        const std::uint64_t install_generation = install_stop_generation_.load(std::memory_order_acquire);
        g_install_ready.store(false, std::memory_order_release);
        clear_install_failure(pid, requested_addr, requested_size);
        auto fail_install = [&](const char* reason,
                                const char* detail,
                                const driver_bridge::memory_region_t* region,
                                uint64_t guard_addr,
                                uint64_t guard_size,
                                uint32_t attempted_protect) -> uint32_t {
            const bool was_install_ready = g_install_ready.load(std::memory_order_acquire);
            record_install_failure(reason, detail, pid, requested_addr, requested_size,
                                   guard_addr, guard_size, region, attempted_protect, GetLastError());
            g_install_ready.store(false, std::memory_order_release);
            diag::log_tagged_fmt("page_guard",
                "install_fail_detail pid=%u reason=%s detail=%s g_install_ready=%d kernel=%d elapsed_ms=%llu",
                pid,
                reason ? reason : "",
                detail ? detail : "",
                was_install_ready ? 1 : 0,
                driver_bridge::using_kernel_driver() ? 1 : 0,
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return 0;
        };
        auto log_install_phase = [&](const char* phase) {
            const ULONGLONG now = GetTickCount64();
            diag::log_tagged_fmt("pg_sniff",
                "install_phase phase=%s pid=%u active_pid=%u target=0x%llX size=0x%llX generation=%llu current_generation=%llu cancelled=%d deadline_ms=%llu deadline_remaining_ms=%llu elapsed_ms=%llu diag_id=%s status=%s last_error=%s",
                phase ? phase : "",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size),
                static_cast<unsigned long long>(install_generation),
                static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
                driver_bridge::current_remote_call_cancelled() ? 1 : 0,
                static_cast<unsigned long long>(driver_bridge::current_remote_call_deadline_ms()),
                static_cast<unsigned long long>(cooperative_deadline_remaining_ms(now)),
                static_cast<unsigned long long>(now - install_start),
                driver_bridge::current_remote_call_diag_id(),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
        };
        auto install_stop_reason = [&]() -> const char* {
            if (const char* reason = cooperative_stop_reason())
                return reason;
            return install_stop_generation_.load(std::memory_order_acquire) != install_generation ? "engine_stop" : nullptr;
        };
        auto check_install_cancelled = [&](const char* phase) -> const char* {
            const char* reason = install_stop_reason();
            if (reason) {
                const ULONGLONG now = GetTickCount64();
                diag::log_tagged_fmt("pg_sniff",
                    "install_cancel_requested phase=%s pid=%u active_pid=%u reason=%s generation=%llu current_generation=%llu cancelled=%d deadline_ms=%llu elapsed_ms=%llu diag_id=%s",
                    phase ? phase : "",
                    pid,
                    driver_bridge::attached_pid(),
                    reason,
                    static_cast<unsigned long long>(install_generation),
                    static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
                    driver_bridge::current_remote_call_cancelled() ? 1 : 0,
                    static_cast<unsigned long long>(driver_bridge::current_remote_call_deadline_ms()),
                    static_cast<unsigned long long>(now - install_start),
                    driver_bridge::current_remote_call_diag_id());
            }
            return reason;
        };
        diag::log_tagged_fmt("pg_sniff", "install_start pid=%u target=0x%llX size=0x%llX kernel=%d attached=%u payloads=%d max_drain=%u auto_poll=%d generation=%llu cancelled=%d deadline_ms=%llu diag_id=%s",
            pid,
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            capture_payloads ? 1 : 0,
            max_records_per_drain,
            auto_poll ? 1 : 0,
            static_cast<unsigned long long>(install_generation),
            driver_bridge::current_remote_call_cancelled() ? 1 : 0,
            static_cast<unsigned long long>(driver_bridge::current_remote_call_deadline_ms()),
            driver_bridge::current_remote_call_diag_id());
        log_install_phase("entry");
        if (const char* reason = check_install_cancelled("entry"))
            return fail_install(reason, "page-guard install cancelled before validation", nullptr, 0, 0, 0);
        if (!driver_bridge::using_kernel_driver()) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=no_kernel_driver pid=%u", pid);
            return fail_install("no_kernel_driver", "kernel driver is not connected", nullptr, 0, 0, 0);
        }
        if (pid == 0 || target_addr == 0 || region_size == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=invalid_args pid=%u target=0x%llX size=0x%llX",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size));
            return fail_install("invalid_args", "pid, address, and size must be nonzero", nullptr, 0, 0, 0);
        }
        install_quarantine_t active_quarantine{};
        if (find_active_quarantine(pid, active_quarantine)) {
            const ULONGLONG quarantine_age = GetTickCount64() >= active_quarantine.created_ms ? GetTickCount64() - active_quarantine.created_ms : 0;
            if (quarantine_age > 30000) {
                diag::log_tagged_fmt("pg_sniff",
                    "install_quarantine_timeout_cleanup pid=%u active_pid=%u quarantine_id=%llu age_ms=%llu veh_result=0x%llX rtl_remove=0x%llX sc=0x%llX ring=0x%llX wrapper=0x%llX diag=0x%llX generation=%llu elapsed_ms=%llu",
                    pid,
                    active_quarantine.active_pid,
                    static_cast<unsigned long long>(active_quarantine.quarantine_id),
                    static_cast<unsigned long long>(quarantine_age),
                    static_cast<unsigned long long>(active_quarantine.veh_result),
                    static_cast<unsigned long long>(active_quarantine.rtl_remove_fn),
                    static_cast<unsigned long long>(active_quarantine.shellcode_addr),
                    static_cast<unsigned long long>(active_quarantine.ring_addr),
                    static_cast<unsigned long long>(active_quarantine.wrapper_addr),
                    static_cast<unsigned long long>(active_quarantine.diag_addr),
                    static_cast<unsigned long long>(install_generation),
                    static_cast<unsigned long long>(GetTickCount64() - install_start));
                if (active_quarantine.veh_result != 0 && active_quarantine.rtl_remove_fn != 0) {
                    remove_vectored_exception_handler_remote(pid,
                                                              0,
                                                              active_quarantine.rtl_remove_fn,
                                                              active_quarantine.veh_result,
                                                              "quarantine_timeout_cleanup",
                                                              install_start);
                }
                if (active_quarantine.shellcode_addr != 0)
                    driver_bridge::free_memory_for(pid, active_quarantine.shellcode_addr);
                if (active_quarantine.ring_addr != 0)
                    driver_bridge::free_memory_for(pid, active_quarantine.ring_addr);
                if (active_quarantine.wrapper_addr != 0)
                    driver_bridge::free_memory_for(pid, active_quarantine.wrapper_addr);
                if (active_quarantine.diag_addr != 0)
                    driver_bridge::free_memory_for(pid, active_quarantine.diag_addr);
                release_install_quarantine_reservation(active_quarantine.quarantine_id, "quarantine_timeout_expired");
                diag::log_tagged_fmt("pg_sniff",
                    "install_quarantine_timeout_cleaned pid=%u quarantine_id=%llu released=1 continuing_install=1 generation=%llu elapsed_ms=%llu",
                    pid,
                    static_cast<unsigned long long>(active_quarantine.quarantine_id),
                    static_cast<unsigned long long>(install_generation),
                    static_cast<unsigned long long>(GetTickCount64() - install_start));
            } else {
                diag::log_tagged_fmt("pg_sniff",
                    "install_failed reason=lower_executor_busy_or_quarantined pid=%u active_pid=%u quarantine_id=%llu reserved=%d call_id=%llu sc=0x%llX ring=0x%llX context=0x%llX rtl_add=0x%llX rtl_remove=0x%llX veh_result=0x%llX remote_gle=%lu install_generation=%llu quarantine_age_ms=%llu",
                    pid,
                    active_quarantine.active_pid,
                    static_cast<unsigned long long>(active_quarantine.quarantine_id),
                    active_quarantine.reserved ? 1 : 0,
                    static_cast<unsigned long long>(active_quarantine.call_id),
                    static_cast<unsigned long long>(active_quarantine.shellcode_addr),
                    static_cast<unsigned long long>(active_quarantine.ring_addr),
                    static_cast<unsigned long long>(active_quarantine.context_addr),
                    static_cast<unsigned long long>(active_quarantine.rtl_add_fn),
                    static_cast<unsigned long long>(active_quarantine.rtl_remove_fn),
                    static_cast<unsigned long long>(active_quarantine.veh_result),
                    static_cast<unsigned long>(active_quarantine.remote_gle),
                    static_cast<unsigned long long>(active_quarantine.install_generation),
                    static_cast<unsigned long long>(quarantine_age));
                record_install_failure("lower_executor_busy_or_quarantined",
                                       "page-guard install blocked by retained uncertain lower remote-call transaction",
                                       pid,
                                       requested_addr,
                                       requested_size,
                                       0,
                                       0,
                                       nullptr,
                                       0,
                                       ERROR_BUSY);
                {
                    std::lock_guard<std::mutex> lk(failure_mutex_);
                    last_install_failure_.quarantined = 1;
                    last_install_failure_.quarantine_id = active_quarantine.quarantine_id;
                    last_install_failure_.remote_call_id = active_quarantine.call_id;
                    last_install_failure_.shellcode_addr = active_quarantine.shellcode_addr;
                    last_install_failure_.ring_addr = active_quarantine.ring_addr;
                    last_install_failure_.context_addr = active_quarantine.context_addr;
                    last_install_failure_.rtl_add_veh = active_quarantine.rtl_add_fn;
                    last_install_failure_.rtl_remove_veh = active_quarantine.rtl_remove_fn;
                    last_install_failure_.veh_result = active_quarantine.veh_result;
                    last_install_failure_.remote_call_gle = active_quarantine.remote_gle;
                    last_install_failure_.install_generation = active_quarantine.install_generation;
                }
                SetLastError(ERROR_BUSY);
                return 0;
            }
        }

        active_pid_scope_t active;
        diag::log_tagged_fmt("pg_sniff",
            "install_active_pid_enter_begin pid=%u previous=%u generation=%llu elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (!active.enter(pid)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=active_pid_enter pid=%u status=%s last_error=%s",
                pid, driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
            return fail_install("active_pid_enter", "failed to select target pid for driver-backed memory operations", nullptr, 0, 0, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_active_pid_enter_done pid=%u active_pid=%u generation=%llu elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_active_pid_enter"))
            return fail_install(reason, "page-guard install cancelled after active pid selection", nullptr, 0, 0, 0);
        if (driver_bridge::attached_pid() != pid) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=active_pid_mismatch requested=%u attached=%u",
                pid, driver_bridge::attached_pid());
            return fail_install("active_pid_mismatch", "driver active pid differs from requested pid", nullptr, 0, 0, 0);
        }
        if (!kernel_operation_ready(pid, "install", "page_guard_install", install_start))
            return fail_install("kernel_unavailable", "kernel driver session is not ready for page-guard installation", nullptr, 0, 0, 0);


        driver_bridge::memory_region_t mri{};
        log_install_phase("query_memory_begin");
        if (!driver_bridge::query_memory_for(pid, target_addr, mri)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=query_memory pid=%u target=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(target_addr), driver_bridge::last_error().c_str());
            return fail_install("query_memory", "driver could not query the requested target address", nullptr, 0, 0, 0);
        }
        log_install_phase("query_memory_done");
        if (const char* reason = check_install_cancelled("after_query_memory"))
            return fail_install(reason, "page-guard install cancelled after target query", &mri, 0, 0, 0);
        uint32_t orig_protect = mri.protect;

        SYSTEM_INFO sys_info{};
        GetNativeSystemInfo(&sys_info);
        const uint64_t page_size = sys_info.dwPageSize ? static_cast<uint64_t>(sys_info.dwPageSize) : 0x1000ull;
        const uint64_t page_mask = page_size - 1u;
        const uint64_t region_end = mri.base + mri.size;
        if (region_end <= mri.base || target_addr < mri.base || target_addr >= region_end) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=target_outside_region pid=%u target=0x%llX region_base=0x%llX region_size=0x%llX state=0x%08X protect=0x%08X type=0x%08X",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(mri.base),
                static_cast<unsigned long long>(mri.size),
                mri.state,
                mri.protect,
                mri.type);
            return fail_install("target_outside_region", "queried region does not contain the target address", &mri, 0, 0, 0);
        }
        if (mri.state != MEM_COMMIT) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=region_not_committed pid=%u target=0x%llX state=0x%08X protect=0x%08X type=0x%08X",
                pid,
                static_cast<unsigned long long>(target_addr),
                mri.state,
                mri.protect,
                mri.type);
            return fail_install("region_not_committed", "target memory is not committed", &mri, 0, 0, 0);
        }
        if ((mri.protect & PAGE_NOACCESS) != 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=region_noaccess pid=%u target=0x%llX protect=0x%08X",
                pid,
                static_cast<unsigned long long>(target_addr),
                mri.protect);
            return fail_install("region_noaccess", "target memory has PAGE_NOACCESS protection", &mri, 0, 0, 0);
        }
        if ((mri.protect & PAGE_GUARD) != 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=region_already_guarded pid=%u target=0x%llX protect=0x%08X",
                pid,
                static_cast<unsigned long long>(target_addr),
                mri.protect);
            return fail_install("region_already_guarded", "target memory is already protected with PAGE_GUARD", &mri, 0, 0, 0);
        }
        if ((target_addr + region_size) < target_addr) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=request_range_overflow pid=%u target=0x%llX size=0x%llX",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size));
            return fail_install("request_range_overflow", "requested guard range overflows address space", &mri, 0, 0, 0);
        }
        uint64_t desired_end = target_addr + region_size;
        if (desired_end > region_end)
            desired_end = region_end;
        uint64_t guard_addr = target_addr & ~page_mask;
        if (guard_addr < mri.base)
            guard_addr = mri.base;
        uint64_t guard_end = (desired_end + page_mask) & ~page_mask;
        if (guard_end < desired_end || guard_end > region_end)
            guard_end = region_end;
        if (guard_end <= guard_addr) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=normalized_guard_empty pid=%u target=0x%llX size=0x%llX guard=0x%llX guard_end=0x%llX region_base=0x%llX region_end=0x%llX page=0x%llX",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size),
                static_cast<unsigned long long>(guard_addr),
                static_cast<unsigned long long>(guard_end),
                static_cast<unsigned long long>(mri.base),
                static_cast<unsigned long long>(region_end),
                static_cast<unsigned long long>(page_size));
            return fail_install("normalized_guard_empty", "normalized guard range is empty inside the committed region", &mri, guard_addr, 0, 0);
        }
        target_addr = guard_addr;
        region_size = guard_end - guard_addr;
        diag::log_tagged_fmt("pg_sniff", "install_region pid=%u requested=0x%llX size=0x%llX guard=0x%llX guard_size=0x%llX region_base=0x%llX region_size=0x%llX state=0x%08X protect=0x%08X type=0x%08X page=0x%llX",
            pid,
            static_cast<unsigned long long>(requested_addr),
            static_cast<unsigned long long>(requested_size),
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            static_cast<unsigned long long>(mri.base),
            static_cast<unsigned long long>(mri.size),
            mri.state,
            mri.protect,
            mri.type,
            static_cast<unsigned long long>(page_size));


        log_install_phase("module_scan_begin");
        driver_bridge::module_info_t kbase_mod = find_module_info(pid, "kernelbase.dll");
        driver_bridge::module_info_t k32_mod = find_module_info(pid, "kernel32.dll");
        diag::log_tagged_fmt("pg_sniff",
            "install_module_scan_done pid=%u active_pid=%u kernelbase=0x%llX kernelbase_size=0x%llX kernel32=0x%llX kernel32_size=0x%llX elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(kbase_mod.base),
            static_cast<unsigned long long>(kbase_mod.size),
            static_cast<unsigned long long>(k32_mod.base),
            static_cast<unsigned long long>(k32_mod.size),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_module_scan"))
            return fail_install(reason, "page-guard install cancelled after module scan", &mri, target_addr, region_size, 0);
        uint64_t virt_protect_fn = kbase_mod.base != 0
            ? resolve_system_export_for_pid(pid, kbase_mod.base, kbase_mod.size, "kernelbase.dll", "VirtualProtect", "install_virtualprotect_kernelbase", install_start)
            : 0;
        const char* virt_protect_module = virt_protect_fn != 0 ? "kernelbase.dll" : "kernel32.dll";
        if (virt_protect_fn == 0 && k32_mod.base != 0)
            virt_protect_fn = resolve_system_export_for_pid(pid, k32_mod.base, k32_mod.size, "kernel32.dll", "VirtualProtect", "install_virtualprotect_kernel32", install_start);
        if (const char* reason = check_install_cancelled("after_virtualprotect_export"))
            return fail_install(reason, "page-guard install cancelled after VirtualProtect export resolution", &mri, target_addr, region_size, 0);
        if (virt_protect_fn == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=virtualprotect_missing pid=%u kernelbase=0x%llX kernel32=0x%llX",
                pid,
                static_cast<unsigned long long>(kbase_mod.base),
                static_cast<unsigned long long>(k32_mod.base));
            return fail_install("virtualprotect_missing", "VirtualProtect export could not be resolved in the target process", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff", "install_virtualprotect pid=%u module=%s addr=0x%llX kernelbase=0x%llX kernel32=0x%llX",
            pid,
            virt_protect_module,
            static_cast<unsigned long long>(virt_protect_fn),
            static_cast<unsigned long long>(kbase_mod.base),
            static_cast<unsigned long long>(k32_mod.base));


        log_install_phase("ring_alloc_begin");
        uint64_t ring_addr = driver_bridge::allocate_memory_for(pid, RING_TOTAL_SIZE + 16);
        if (ring_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ring_alloc pid=%u bytes=%u last_error=%s",
                pid, RING_TOTAL_SIZE + 16, driver_bridge::last_error().c_str());
            return fail_install("ring_alloc", "failed to allocate the remote capture ring", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_ring_alloc_done pid=%u ring=0x%llX bytes=%u elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(ring_addr),
            RING_TOTAL_SIZE + 16,
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_ring_alloc")) {
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_ring_alloc pid=%u ring=0x%llX cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(ring_addr),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_ok ? "" : driver_bridge::last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after ring allocation", &mri, target_addr, region_size, 0);
        }
        if (driver_bridge::attached_pid() != pid) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=post_ring_active_mismatch requested=%u attached=%u ring=0x%llX",
                pid, driver_bridge::attached_pid(), static_cast<unsigned long long>(ring_addr));
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("post_ring_active_mismatch", "driver active pid changed after ring allocation", &mri, target_addr, region_size, 0);
        }

        log_install_phase("shellcode_alloc_begin");
        uint64_t sc_addr = driver_bridge::allocate_memory_for(pid, SHELLCODE_SIZE + 16);
        if (sc_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_alloc pid=%u bytes=%zu ring=0x%llX last_error=%s",
                pid, SHELLCODE_SIZE + 16, static_cast<unsigned long long>(ring_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("shellcode_alloc", "failed to allocate the remote VEH shellcode region", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_shellcode_alloc_done pid=%u sc=0x%llX bytes=%zu elapsed_ms=%llu",
            pid,
            static_cast<unsigned long long>(sc_addr),
            SHELLCODE_SIZE + 16,
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_shellcode_alloc")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_shellcode_alloc pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after shellcode allocation", &mri, target_addr, region_size, 0);
        }


        std::vector<uint8_t> zeroes(RING_TOTAL_SIZE, 0);
        log_install_phase("ring_zero_write_begin");
        if (!driver_bridge::write_memory_for(pid, ring_addr, zeroes)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ring_zero_write pid=%u ring=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(ring_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("ring_zero_write", "failed to initialize the remote capture ring", &mri, target_addr, region_size, 0);
        }
        log_install_phase("ring_zero_write_done");
        if (const char* reason = check_install_cancelled("after_ring_zero_write")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_ring_zero_write pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after ring initialization", &mri, target_addr, region_size, 0);
        }


        auto sc = generate_veh_shellcode(ring_addr, target_addr,
                                         region_size, orig_protect,
                                         virt_protect_fn);
        log_install_phase("shellcode_write_begin");
        if (!driver_bridge::write_memory_for(pid, sc_addr, sc)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_write pid=%u sc=0x%llX bytes=%zu last_error=%s",
                pid, static_cast<unsigned long long>(sc_addr), sc.size(), driver_bridge::last_error().c_str());
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("shellcode_write", "failed to write the remote VEH shellcode", &mri, target_addr, region_size, 0);
        }
        log_install_phase("shellcode_write_done");
        if (const char* reason = check_install_cancelled("after_shellcode_write")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_shellcode_write pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after shellcode write", &mri, target_addr, region_size, 0);
        }
        uint32_t old_sc_protect = 0;
        log_install_phase("shellcode_protect_begin");
        if (!driver_bridge::protect_memory_for(pid, sc_addr, SHELLCODE_SIZE,
                                               PAGE_EXECUTE_READ, &old_sc_protect)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_protect pid=%u sc=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(sc_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("shellcode_protect", "failed to make the remote VEH shellcode executable", &mri, target_addr, region_size, PAGE_EXECUTE_READ);
        }
        log_install_phase("shellcode_protect_done");
        if (const char* reason = check_install_cancelled("after_shellcode_protect")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_shellcode_protect pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after shellcode protect", &mri, target_addr, region_size, PAGE_EXECUTE_READ);
        }


        log_install_phase("ntdll_scan_begin");
        driver_bridge::module_info_t ntdll_mod_install = find_module_info(pid, "ntdll.dll");
        if (ntdll_mod_install.base == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ntdll_missing pid=%u", pid);
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("ntdll_missing", "ntdll.dll is not present in target module enumeration", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_ntdll_scan_done pid=%u active_pid=%u ntdll=0x%llX ntdll_size=0x%llX elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(ntdll_mod_install.base),
            static_cast<unsigned long long>(ntdll_mod_install.size),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_ntdll_scan")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_ntdll_scan pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after ntdll scan", &mri, target_addr, region_size, 0);
        }
        uint64_t rtl_add_fn = resolve_system_export_for_pid(pid,
                                                            ntdll_mod_install.base,
                                                            ntdll_mod_install.size,
                                                            "ntdll.dll",
                                                            "RtlAddVectoredExceptionHandler",
                                                            "install_rtladdveh",
                                                            install_start);
        if (const char* reason = check_install_cancelled("after_rtladdveh_export")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_rtladdveh_export pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after RtlAddVectoredExceptionHandler export resolution", &mri, target_addr, region_size, 0);
        }
        if (rtl_add_fn == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=rtladdveh_missing pid=%u ntdll=0x%llX",
                pid, static_cast<unsigned long long>(ntdll_mod_install.base));
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("rtladdveh_missing", "RtlAddVectoredExceptionHandler export could not be resolved", &mri, target_addr, region_size, 0);
        }
        uint64_t rtl_remove_fn = resolve_system_export_for_pid(pid,
                                                               ntdll_mod_install.base,
                                                               ntdll_mod_install.size,
                                                               "ntdll.dll",
                                                               "RtlRemoveVectoredExceptionHandler",
                                                               "install_cache_rtlremoveveh",
                                                               install_start);
        if (const char* reason = check_install_cancelled("after_rtlremoveveh_export")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_rtlremoveveh_export pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after RtlRemoveVectoredExceptionHandler export resolution", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_cache_rtlremoveveh pid=%u active_pid=%u module=ntdll.dll base=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX elapsed_ms=%llu outcome=%s",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(ntdll_mod_install.base),
            static_cast<unsigned long long>(rtl_remove_fn),
            static_cast<unsigned long long>(GetTickCount64() - install_start),
            rtl_remove_fn != 0 ? "cached" : "fail_closed");
        if (rtl_remove_fn == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=rtlremoveveh_missing pid=%u ntdll=0x%llX",
                pid, static_cast<unsigned long long>(ntdll_mod_install.base));
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("rtlremoveveh_missing", "RtlRemoveVectoredExceptionHandler export could not be resolved", &mri, target_addr, region_size, 0);
        }

        driver_bridge::memory_region_t veh_target_before = mri;
        driver_bridge::memory_region_t veh_handler_before{};
        driver_bridge::memory_region_t veh_ring_before{};
        const bool veh_handler_before_ok = driver_bridge::query_memory_for(pid, sc_addr, veh_handler_before);
        const std::string veh_handler_before_error = veh_handler_before_ok ? std::string() : driver_bridge::last_error();
        const bool veh_ring_before_ok = driver_bridge::query_memory_for(pid, ring_addr, veh_ring_before);
        const std::string veh_ring_before_error = veh_ring_before_ok ? std::string() : driver_bridge::last_error();
        const uint32_t proposed_guard_protect = orig_protect | PAGE_GUARD;
        const uint64_t veh_context_addr = ring_addr;
        const process_mitigation_diag_t veh_mitigation = query_process_mitigation_diag(pid);
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_begin pid=%u active_pid=%u caller_tid=%lu generation=%llu current_generation=%llu module=ntdll.dll ntdll_base=0x%llX ntdll_size=0x%llX function=RtlAddVectoredExceptionHandler va=0x%llX remove_va=0x%llX handler=0x%llX ring=0x%llX context=0x%llX method=driver_bridge::call_function target_base=0x%llX target_size=0x%llX target_state=0x%08X target_protect=0x%08X proposed_protect=0x%08X target_type=0x%08X handler_query=%d handler_base=0x%llX handler_size=0x%llX handler_state=0x%08X handler_protect=0x%08X handler_type=0x%08X handler_error=%s ring_query=%d ring_base=0x%llX ring_size=0x%llX ring_state=0x%08X ring_protect=0x%08X ring_type=0x%08X ring_error=%s mitigation_open=%d mitigation_open_error=%lu dyn_ok=%d dyn_error=%lu dyn_flags=0x%08lX cfg_ok=%d cfg_error=%lu cfg_flags=0x%08lX elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(ntdll_mod_install.base),
            static_cast<unsigned long long>(ntdll_mod_install.size),
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(rtl_remove_fn),
            static_cast<unsigned long long>(sc_addr),
            static_cast<unsigned long long>(ring_addr),
            static_cast<unsigned long long>(veh_context_addr),
            static_cast<unsigned long long>(veh_target_before.base),
            static_cast<unsigned long long>(veh_target_before.size),
            veh_target_before.state,
            veh_target_before.protect,
            proposed_guard_protect,
            veh_target_before.type,
            veh_handler_before_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_handler_before.base),
            static_cast<unsigned long long>(veh_handler_before.size),
            veh_handler_before.state,
            veh_handler_before.protect,
            veh_handler_before.type,
            veh_handler_before_error.c_str(),
            veh_ring_before_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_ring_before.base),
            static_cast<unsigned long long>(veh_ring_before.size),
            veh_ring_before.state,
            veh_ring_before.protect,
            veh_ring_before.type,
            veh_ring_before_error.c_str(),
            veh_mitigation.open_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.open_error),
            veh_mitigation.dynamic_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.dynamic_error),
            static_cast<unsigned long>(veh_mitigation.dynamic_flags),
            veh_mitigation.cfg_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.cfg_error),
            static_cast<unsigned long>(veh_mitigation.cfg_flags),
            static_cast<unsigned long long>(GetTickCount64() - install_start));

        if (const char* reason = check_install_cancelled("before_veh_register")) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=before_veh_register pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled before VEH registration", &mri, target_addr, region_size, 0);
        }
        const uint64_t quarantine_reservation_id = reserve_install_quarantine_slot(pid,
                                                                                   driver_bridge::attached_pid(),
                                                                                   install_generation,
                                                                                   install_start);
        if (quarantine_reservation_id == 0) {
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_failed reason=lower_executor_quarantine_capacity pid=%u active_pid=%u sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s generation=%llu elapsed_ms=%llu",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(install_generation),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            SetLastError(ERROR_BUSY);
            return fail_install("lower_executor_quarantine_capacity", "page-guard install could not reserve bounded quarantine tracking before remote VEH registration", &mri, target_addr, region_size, 0);
        }
        SetLastError(ERROR_SUCCESS);
        const uint64_t veh_expected_call_id = g_driver_remote_call_sequence.load(std::memory_order_acquire);
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_remote_call_expect expected_call_id=%llu pid=%u active_pid=%u function=RtlAddVectoredExceptionHandler va=0x%llX handler=0x%llX deadline_ms=%llu deadline_remaining_ms=%llu timeout_ms=%u generation=%llu current_generation=%llu elapsed_ms=%llu",
            static_cast<unsigned long long>(veh_expected_call_id),
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(sc_addr),
            static_cast<unsigned long long>(driver_bridge::current_remote_call_deadline_ms()),
            static_cast<unsigned long long>(cooperative_deadline_remaining_ms(GetTickCount64())),
            driver_bridge::current_remote_call_timeout_ms(),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        const ULONGLONG veh_call_start = GetTickCount64();
        if (mcp_standalone::current_call_cancelled()) {
            diag::log_tagged_fmt("pg_sniff",
                "veh_register_cancelled_before_call pid=%u active_pid=%u generation=%llu current_generation=%llu elapsed_ms=%llu",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(install_generation),
                static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            SetLastError(ERROR_CANCELLED);
            return fail_install("mcp_cancelled", "page-guard install cancelled before VEH remote call", &mri, target_addr, region_size, 0);
        }
        uint64_t veh_wrapper_addr = 0;
        uint64_t veh_diag_addr = 0;
        uint32_t veh_wrapper_old_protect = 0;
        auto fail_veh_register_setup = [&](const char* reason_code, const char* detail, DWORD win32_error) -> uint32_t {
            const bool cleanup_wrapper_ok = veh_wrapper_addr == 0 || driver_bridge::free_memory_for(pid, veh_wrapper_addr);
            const std::string cleanup_wrapper_error = cleanup_wrapper_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_diag_ok = veh_diag_addr == 0 || driver_bridge::free_memory_for(pid, veh_diag_addr);
            const std::string cleanup_diag_error = cleanup_diag_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            release_install_quarantine_reservation(quarantine_reservation_id, reason_code);
            diag::log_tagged_fmt("pg_sniff",
                "veh_register_wrapper_setup_failed pid=%u active_pid=%u reason=%s wrapper=0x%llX diag=0x%llX sc=0x%llX ring=0x%llX cleanup_wrapper_ok=%d cleanup_wrapper_error=%s cleanup_diag_ok=%d cleanup_diag_error=%s cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s win32=%lu elapsed_ms=%llu",
                pid,
                driver_bridge::attached_pid(),
                reason_code ? reason_code : "",
                static_cast<unsigned long long>(veh_wrapper_addr),
                static_cast<unsigned long long>(veh_diag_addr),
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_wrapper_ok ? 1 : 0,
                cleanup_wrapper_error.c_str(),
                cleanup_diag_ok ? 1 : 0,
                cleanup_diag_error.c_str(),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long>(win32_error),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            SetLastError(win32_error);
            return fail_install(reason_code, detail, &mri, target_addr, region_size, 0);
        };
        std::vector<uint8_t> veh_diag_zero(sizeof(veh_register_remote_diag_t), 0);
        veh_diag_addr = driver_bridge::allocate_memory_for(pid, sizeof(veh_register_remote_diag_t));
        if (veh_diag_addr == 0)
            return fail_veh_register_setup("veh_diag_alloc", "failed to allocate target-side VEH registration diagnostic block", GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY);
        if (!driver_bridge::write_memory_for(pid, veh_diag_addr, veh_diag_zero))
            return fail_veh_register_setup("veh_diag_write", "failed to initialize target-side VEH registration diagnostic block", GetLastError() ? GetLastError() : ERROR_WRITE_FAULT);
        std::vector<uint8_t> veh_wrapper = generate_veh_register_wrapper_shellcode();
        veh_wrapper_addr = driver_bridge::allocate_memory_for(pid, veh_wrapper.size() + 16);
        if (veh_wrapper_addr == 0)
            return fail_veh_register_setup("veh_wrapper_alloc", "failed to allocate target-side VEH registration wrapper", GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY);
        if (!driver_bridge::write_memory_for(pid, veh_wrapper_addr, veh_wrapper))
            return fail_veh_register_setup("veh_wrapper_write", "failed to write target-side VEH registration wrapper", GetLastError() ? GetLastError() : ERROR_WRITE_FAULT);
        if (!driver_bridge::protect_memory_for(pid, veh_wrapper_addr, veh_wrapper.size(), PAGE_EXECUTE_READ, &veh_wrapper_old_protect))
            return fail_veh_register_setup("veh_wrapper_protect", "failed to make target-side VEH registration wrapper executable", GetLastError() ? GetLastError() : ERROR_ACCESS_DENIED);
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_wrapper_ready pid=%u active_pid=%u wrapper=0x%llX wrapper_size=%zu diag=0x%llX diag_size=%zu wrapper_old_protect=0x%08X rtl_add=0x%llX handler=0x%llX generation=%llu current_generation=%llu elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(veh_wrapper_addr),
            veh_wrapper.size(),
            static_cast<unsigned long long>(veh_diag_addr),
            sizeof(veh_register_remote_diag_t),
            veh_wrapper_old_protect,
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(sc_addr),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        const char* veh_diag_id = driver_bridge::current_remote_call_diag_id();
        char veh_generated_diag_id[128] = {};
        if (!veh_diag_id || !veh_diag_id[0]) {
            _snprintf_s(veh_generated_diag_id, sizeof(veh_generated_diag_id), _TRUNCATE,
                "pg-veh-%lu-%llu",
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(veh_call_start));
            veh_diag_id = veh_generated_diag_id;
        }
        const uint32_t veh_inherited_timeout = driver_bridge::current_remote_call_timeout_ms();
        const uint32_t veh_timeout_ms = bounded_remote_call_timeout_ms((std::max<uint32_t>)(veh_inherited_timeout, 8000));
        const uint64_t veh_inherited_deadline = driver_bridge::current_remote_call_deadline_ms();
        const uint64_t veh_deadline = saturated_remote_call_deadline_ms(veh_call_start, veh_timeout_ms);
        driver_bridge::remote_call_context_t veh_ctx{};
        veh_ctx.label = "RtlAddVectoredExceptionHandler";
        veh_ctx.tool = remote_call_tool_from_label("RtlAddVectoredExceptionHandler");
        veh_ctx.diag_id = veh_diag_id;
        veh_ctx.pid = pid;
        veh_ctx.timeout_ms = veh_timeout_ms;
        veh_ctx.deadline_ms = veh_deadline;
        veh_ctx.cancel_token = mcp_standalone::current_cancel_token();
        veh_ctx.require_deadline = true;
        driver_bridge::scoped_remote_call_context_t veh_scoped(veh_ctx);
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_remote_call_context pid=%u active_pid=%u veh_timeout_ms=%u veh_deadline_ms=%llu inherited_timeout_ms=%u inherited_deadline_ms=%llu deadline_remaining_ms=%llu cancelled=%d inflight=%u lower_abandoned=%d generation=%llu current_generation=%llu elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            veh_timeout_ms,
            static_cast<unsigned long long>(veh_deadline),
            veh_inherited_timeout,
            static_cast<unsigned long long>(veh_inherited_deadline),
            static_cast<unsigned long long>(cooperative_deadline_remaining_ms(veh_call_start)),
            driver_bridge::current_remote_call_cancelled() ? 1 : 0,
            driver_bridge::detail::remote_call_um_inflight_count_global(),
            driver_bridge::lower_remote_call_last_abandoned() ? 1 : 0,
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        uint64_t veh_handle = driver_remote_call_impl(pid, veh_wrapper_addr, rtl_add_fn, 1, sc_addr, veh_diag_addr, "RtlAddVectoredExceptionHandler.wrapper");
        remote_call_diag_snapshot_t veh_remote_diag = last_driver_remote_call_diag();
        uint64_t veh_call_elapsed = GetTickCount64() - veh_call_start;
        DWORD veh_call_gle = veh_handle != 0 ? ERROR_SUCCESS : GetLastError();
        std::string veh_call_status = driver_bridge::status();
        std::string veh_call_last_error = driver_bridge::last_error();
        veh_register_remote_diag_t veh_target_diag{};
        std::vector<uint8_t> veh_target_diag_bytes;
        const bool veh_target_diag_read_ok =
            driver_bridge::read_memory_for(pid, veh_diag_addr, sizeof(veh_target_diag), veh_target_diag_bytes) &&
            veh_target_diag_bytes.size() >= sizeof(veh_target_diag);
        if (veh_target_diag_read_ok)
            std::memcpy(&veh_target_diag, veh_target_diag_bytes.data(), sizeof(veh_target_diag));
        const bool veh_target_diag_magic_ok = veh_target_diag_read_ok && veh_target_diag.magic == VEH_REGISTER_DIAG_MAGIC;
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_target_diag pid=%u active_pid=%u wrapper=0x%llX diag=0x%llX read_ok=%d bytes=%zu magic=0x%llX magic_ok=%d completed=%llu rtl_add=0x%llX handler=0x%llX result=0x%llX last_error_before=%lu last_error_after=%lu lower_result=0x%llX lower_gle=%lu elapsed_ms=%llu generation=%llu current_generation=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(veh_wrapper_addr),
            static_cast<unsigned long long>(veh_diag_addr),
            veh_target_diag_read_ok ? 1 : 0,
            veh_target_diag_bytes.size(),
            static_cast<unsigned long long>(veh_target_diag.magic),
            veh_target_diag_magic_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_target_diag.completed),
            static_cast<unsigned long long>(veh_target_diag.rtl_add_fn),
            static_cast<unsigned long long>(veh_target_diag.handler),
            static_cast<unsigned long long>(veh_target_diag.result),
            static_cast<unsigned long>(veh_target_diag.last_error_before),
            static_cast<unsigned long>(veh_target_diag.last_error_after),
            static_cast<unsigned long long>(veh_remote_diag.result),
            static_cast<unsigned long>(veh_call_gle),
            static_cast<unsigned long long>(veh_call_elapsed),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)));
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_remote_call_result call_id=%llu expected_call_id=%llu pid=%u active_pid_entry=%u active_pid_after=%u function=RtlAddVectoredExceptionHandler va=0x%llX wrapper=0x%llX diag=0x%llX handler=0x%llX result=0x%llX target_result=0x%llX target_last_error_after=%lu ok=%d completed=%d gle=%lu timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled_before=%d cancelled_after=%d deadline_expired_before=%d deadline_expired_after=%d stale_pid=%d late_completion=%d lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_worker_tid=%lu lower_worker_alive=%u lower_queue_depth_submit=%u lower_queue_depth_after_pop=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu lower_deadline_remaining_finish_ms=%llu lower_worker_exception=%d lower_worker_creation_failed=%d zero_result_rejected=%d removed_from_queue=%d popped=%d execution_started=%d executing_abandoned=%d seh_exception=%d seh_code=0x%08lX seh_addr=0x%llX seh_fault=0x%llX seh_rip=0x%llX lower_error_value=%d lower_error_category=%s lower_error_message=%s remote_elapsed_ms=%llu measured_elapsed_ms=%llu generation=%llu current_generation=%llu status=%s last_error=%s",
            static_cast<unsigned long long>(veh_remote_diag.call_id),
            static_cast<unsigned long long>(veh_expected_call_id),
            pid,
            veh_remote_diag.active_pid_entry,
            veh_remote_diag.active_pid_after,
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(veh_wrapper_addr),
            static_cast<unsigned long long>(veh_diag_addr),
            static_cast<unsigned long long>(sc_addr),
            static_cast<unsigned long long>(veh_remote_diag.result),
            static_cast<unsigned long long>(veh_target_diag.result),
            static_cast<unsigned long>(veh_target_diag.last_error_after),
            veh_remote_diag.ok ? 1 : 0,
            veh_remote_diag.completed ? 1 : 0,
            static_cast<unsigned long>(veh_call_gle),
            veh_remote_diag.timeout_ms,
            static_cast<unsigned long long>(veh_remote_diag.deadline_ms),
            static_cast<unsigned long long>(veh_remote_diag.deadline_remaining_ms),
            veh_remote_diag.cancelled_before ? 1 : 0,
            veh_remote_diag.cancelled_after ? 1 : 0,
            veh_remote_diag.deadline_expired_before ? 1 : 0,
            veh_remote_diag.deadline_expired_after ? 1 : 0,
            veh_remote_diag.stale_pid ? 1 : 0,
            veh_remote_diag.late_completion ? 1 : 0,
            veh_remote_diag.lower_phase.c_str(),
            veh_remote_diag.lower_completion_reason.c_str(),
            veh_remote_diag.lower_completed ? 1 : 0,
            veh_remote_diag.lower_ok ? 1 : 0,
            static_cast<unsigned long>(veh_remote_diag.lower_gle),
            static_cast<unsigned long>(veh_remote_diag.lower_worker_tid),
            veh_remote_diag.lower_worker_alive,
            veh_remote_diag.lower_queue_depth_at_submit,
            veh_remote_diag.lower_queue_depth_after_pop,
            veh_remote_diag.lower_inflight_after,
            static_cast<unsigned long long>(veh_remote_diag.lower_queue_wait_ms),
            static_cast<unsigned long long>(veh_remote_diag.lower_elapsed_ms),
            static_cast<unsigned long long>(veh_remote_diag.lower_deadline_remaining_at_finish_ms),
            veh_remote_diag.lower_worker_exception ? 1 : 0,
            veh_remote_diag.lower_worker_creation_failed ? 1 : 0,
            veh_remote_diag.zero_result_rejected ? 1 : 0,
            veh_remote_diag.removed_from_queue ? 1 : 0,
            veh_remote_diag.popped_from_queue ? 1 : 0,
            veh_remote_diag.execution_started ? 1 : 0,
            veh_remote_diag.executing_abandoned ? 1 : 0,
            veh_remote_diag.seh_exception ? 1 : 0,
            static_cast<unsigned long>(veh_remote_diag.seh_exception_code),
            static_cast<unsigned long long>(veh_remote_diag.seh_exception_address),
            static_cast<unsigned long long>(veh_remote_diag.seh_fault_address),
            static_cast<unsigned long long>(veh_remote_diag.seh_rip),
            veh_remote_diag.lower_worker_error_value,
            veh_remote_diag.lower_worker_error_category.c_str(),
            veh_remote_diag.lower_worker_error_message.c_str(),
            static_cast<unsigned long long>(veh_remote_diag.elapsed_ms),
            static_cast<unsigned long long>(veh_call_elapsed),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            veh_call_status.c_str(),
            veh_call_last_error.c_str());
        driver_bridge::memory_region_t veh_target_after{};
        driver_bridge::memory_region_t veh_handler_after{};
        driver_bridge::memory_region_t veh_ring_after{};
        const bool veh_target_after_ok = driver_bridge::query_memory_for(pid, target_addr, veh_target_after);
        const std::string veh_target_after_error = veh_target_after_ok ? std::string() : driver_bridge::last_error();
        const bool veh_handler_after_ok = driver_bridge::query_memory_for(pid, sc_addr, veh_handler_after);
        const std::string veh_handler_after_error = veh_handler_after_ok ? std::string() : driver_bridge::last_error();
        const bool veh_ring_after_ok = driver_bridge::query_memory_for(pid, ring_addr, veh_ring_after);
        const std::string veh_ring_after_error = veh_ring_after_ok ? std::string() : driver_bridge::last_error();
        if (veh_handle == 0) {
            const bool lower_started = veh_remote_diag.executing_abandoned ||
                                       veh_remote_diag.execution_started;
            const bool lower_uncertain = lower_started &&
                (veh_remote_diag.executing_abandoned ||
                 veh_remote_diag.lower_uninterruptible ||
                 veh_remote_diag.lower_worker_exception ||
                 veh_remote_diag.seh_exception ||
                 veh_remote_diag.lower_late_completion ||
                 veh_remote_diag.late_completion ||
                 veh_remote_diag.cancelled_after ||
                 veh_remote_diag.deadline_expired_after ||
                 veh_remote_diag.stale_pid ||
                 veh_remote_diag.lower_cancelled ||
                 veh_remote_diag.lower_deadline_expired ||
                 veh_remote_diag.lower_stale_generation ||
                 !veh_remote_diag.lower_completed);
            const bool known_late_handle = veh_remote_diag.result != 0 &&
                                           veh_remote_diag.lower_completed &&
                                           !veh_remote_diag.seh_exception;
            bool cleanup_veh_remove_attempted = false;
            bool cleanup_veh_remove_ok = false;
            bool cleanup_sc_ok = false;
            bool cleanup_ring_ok = false;
            bool cleanup_wrapper_ok = false;
            bool cleanup_diag_ok = false;
            bool retained_sc = false;
            bool retained_ring = false;
            bool retained_wrapper = false;
            bool retained_diag = false;
            uint64_t cleanup_removed = 0;
            uint64_t quarantine_id = 0;
            const char* cleanup_decision = "definite_no_handler_free";
            std::string cleanup_sc_error;
            std::string cleanup_ring_error;
            std::string cleanup_wrapper_error;
            std::string cleanup_diag_error;
            if (lower_uncertain) {
                cleanup_decision = known_late_handle ? "known_late_handle_remove_then_free" : "retain_uncertain_handler_resources";
                if (known_late_handle && driver_bridge::attached_pid() == pid) {
                    cleanup_veh_remove_attempted = true;
                    cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                               ntdll_mod_install.base,
                                                                               rtl_remove_fn,
                                                                               veh_remote_diag.result,
                                                                               "install_uncertain_veh_register_cleanup",
                                                                               install_start);
                    cleanup_veh_remove_ok = cleanup_removed != 0;
                    if (cleanup_veh_remove_ok) {
                        cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
                        cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
                        cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
                        cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
                        retained_sc = !cleanup_sc_ok;
                        retained_ring = !cleanup_ring_ok;
                    } else {
                        cleanup_sc_error = "veh_remove_failed";
                        cleanup_ring_error = "veh_remove_failed";
                        retained_sc = true;
                        retained_ring = true;
                    }
                    cleanup_wrapper_ok = driver_bridge::free_memory_for(pid, veh_wrapper_addr);
                    cleanup_wrapper_error = cleanup_wrapper_ok ? std::string() : driver_bridge::last_error();
                    cleanup_diag_ok = driver_bridge::free_memory_for(pid, veh_diag_addr);
                    cleanup_diag_error = cleanup_diag_ok ? std::string() : driver_bridge::last_error();
                    veh_wrapper_addr = cleanup_wrapper_ok ? 0 : veh_wrapper_addr;
                    veh_diag_addr = cleanup_diag_ok ? 0 : veh_diag_addr;
                    retained_wrapper = !cleanup_wrapper_ok;
                    retained_diag = !cleanup_diag_ok;
                } else {
                    cleanup_sc_error = "retained_uncertain_remote_handler";
                    cleanup_ring_error = "retained_uncertain_remote_handler";
                    cleanup_wrapper_error = "retained_uncertain_remote_wrapper";
                    cleanup_diag_error = "retained_uncertain_remote_wrapper";
                    retained_sc = true;
                    retained_ring = true;
                    retained_wrapper = true;
                    retained_diag = true;
                }
                if (retained_sc || retained_ring || retained_wrapper || retained_diag) {
                    quarantine_id = add_install_quarantine(quarantine_reservation_id,
                                                           pid,
                                                           driver_bridge::attached_pid(),
                                                           veh_remote_diag.call_id,
                                                           sc_addr,
                                                           ring_addr,
                                                           veh_context_addr,
                                                           retained_wrapper ? veh_wrapper_addr : 0,
                                                           retained_diag ? veh_diag_addr : 0,
                                                           rtl_add_fn,
                                                           rtl_remove_fn,
                                                           veh_remote_diag.result,
                                                           veh_call_gle,
                                                           install_generation);
                } else {
                    release_install_quarantine_reservation(quarantine_reservation_id,
                                                           cleanup_veh_remove_attempted ? "veh_register_cleanup_completed" : "veh_register_definite_failure");
                }
            } else {
                cleanup_sc_ok = driver_bridge::free_memory_for(pid, sc_addr);
                cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
                cleanup_ring_ok = driver_bridge::free_memory_for(pid, ring_addr);
                cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
                cleanup_wrapper_ok = driver_bridge::free_memory_for(pid, veh_wrapper_addr);
                cleanup_wrapper_error = cleanup_wrapper_ok ? std::string() : driver_bridge::last_error();
                cleanup_diag_ok = driver_bridge::free_memory_for(pid, veh_diag_addr);
                cleanup_diag_error = cleanup_diag_ok ? std::string() : driver_bridge::last_error();
                veh_wrapper_addr = cleanup_wrapper_ok ? 0 : veh_wrapper_addr;
                veh_diag_addr = cleanup_diag_ok ? 0 : veh_diag_addr;
                retained_wrapper = !cleanup_wrapper_ok;
                retained_diag = !cleanup_diag_ok;
                release_install_quarantine_reservation(quarantine_reservation_id, "veh_register_definite_failure");
            }
            diag::log_tagged_fmt("pg_sniff",
                "veh_register_cleanup_decision pid=%u active_pid=%u call_id=%llu expected_call_id=%llu decision=%s lower_uncertain=%d lower_started=%d known_late_handle=%d known_handle=0x%llX quarantine_id=%llu retained_sc=%d retained_ring=%d retained_wrapper=%d retained_diag=%d remove_attempted=%d remove_ok=%d removed=0x%llX sc=0x%llX ring=0x%llX context=0x%llX wrapper=0x%llX diag=0x%llX cleanup_wrapper_ok=%d cleanup_wrapper_error=%s cleanup_diag_ok=%d cleanup_diag_error=%s zero_result_rejected=%d removed_from_queue=%d popped=%d execution_started=%d executing_abandoned=%d seh_exception=%d seh_code=0x%08lX deadline_expired_after=%d stale_pid=%d lower_phase=%s lower_reason=%s elapsed_ms=%llu",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(veh_remote_diag.call_id),
                static_cast<unsigned long long>(veh_expected_call_id),
                cleanup_decision,
                lower_uncertain ? 1 : 0,
                lower_started ? 1 : 0,
                known_late_handle ? 1 : 0,
                static_cast<unsigned long long>(veh_remote_diag.result),
                static_cast<unsigned long long>(quarantine_id),
                retained_sc ? 1 : 0,
                retained_ring ? 1 : 0,
                retained_wrapper ? 1 : 0,
                retained_diag ? 1 : 0,
                cleanup_veh_remove_attempted ? 1 : 0,
                cleanup_veh_remove_ok ? 1 : 0,
                static_cast<unsigned long long>(cleanup_removed),
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                static_cast<unsigned long long>(veh_context_addr),
                static_cast<unsigned long long>(veh_wrapper_addr),
                static_cast<unsigned long long>(veh_diag_addr),
                cleanup_wrapper_ok ? 1 : 0,
                cleanup_wrapper_error.c_str(),
                cleanup_diag_ok ? 1 : 0,
                cleanup_diag_error.c_str(),
                veh_remote_diag.zero_result_rejected ? 1 : 0,
                veh_remote_diag.removed_from_queue ? 1 : 0,
                veh_remote_diag.popped_from_queue ? 1 : 0,
                veh_remote_diag.execution_started ? 1 : 0,
                veh_remote_diag.executing_abandoned ? 1 : 0,
                veh_remote_diag.seh_exception ? 1 : 0,
                static_cast<unsigned long>(veh_remote_diag.seh_exception_code),
                veh_remote_diag.deadline_expired_after ? 1 : 0,
                veh_remote_diag.stale_pid ? 1 : 0,
                veh_remote_diag.lower_phase.c_str(),
                veh_remote_diag.lower_completion_reason.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            diag::log_tagged_fmt("pg_sniff",
                "veh_register_failed pid=%u active_pid=%u caller_tid=%lu generation=%llu current_generation=%llu module=ntdll.dll ntdll_base=0x%llX ntdll_size=0x%llX function=RtlAddVectoredExceptionHandler va=0x%llX remove_va=0x%llX handler=0x%llX ring=0x%llX context=0x%llX method=driver_bridge::call_function result=0x%llX gle=%lu remote_elapsed_ms=%llu remote_status=%s remote_last_error=%s original_protect=0x%08X proposed_protect=0x%08X target_before_base=0x%llX target_before_size=0x%llX target_before_state=0x%08X target_before_protect=0x%08X target_before_type=0x%08X target_after_query=%d target_after_base=0x%llX target_after_size=0x%llX target_after_state=0x%08X target_after_protect=0x%08X target_after_type=0x%08X target_after_error=%s handler_before_query=%d handler_before_base=0x%llX handler_before_size=0x%llX handler_before_state=0x%08X handler_before_protect=0x%08X handler_before_type=0x%08X handler_after_query=%d handler_after_base=0x%llX handler_after_size=0x%llX handler_after_state=0x%08X handler_after_protect=0x%08X handler_after_type=0x%08X handler_after_error=%s ring_before_query=%d ring_before_base=0x%llX ring_before_size=0x%llX ring_before_state=0x%08X ring_before_protect=0x%08X ring_before_type=0x%08X ring_after_query=%d ring_after_base=0x%llX ring_after_size=0x%llX ring_after_state=0x%08X ring_after_protect=0x%08X ring_after_type=0x%08X ring_after_error=%s mitigation_open=%d mitigation_open_error=%lu dyn_ok=%d dyn_error=%lu dyn_flags=0x%08lX cfg_ok=%d cfg_error=%lu cfg_flags=0x%08lX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(install_generation),
                static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(ntdll_mod_install.base),
                static_cast<unsigned long long>(ntdll_mod_install.size),
                static_cast<unsigned long long>(rtl_add_fn),
                static_cast<unsigned long long>(rtl_remove_fn),
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                static_cast<unsigned long long>(veh_context_addr),
                static_cast<unsigned long long>(veh_handle),
                static_cast<unsigned long>(veh_call_gle),
                static_cast<unsigned long long>(veh_call_elapsed),
                veh_call_status.c_str(),
                veh_call_last_error.c_str(),
                orig_protect,
                proposed_guard_protect,
                static_cast<unsigned long long>(veh_target_before.base),
                static_cast<unsigned long long>(veh_target_before.size),
                veh_target_before.state,
                veh_target_before.protect,
                veh_target_before.type,
                veh_target_after_ok ? 1 : 0,
                static_cast<unsigned long long>(veh_target_after.base),
                static_cast<unsigned long long>(veh_target_after.size),
                veh_target_after.state,
                veh_target_after.protect,
                veh_target_after.type,
                veh_target_after_error.c_str(),
                veh_handler_before_ok ? 1 : 0,
                static_cast<unsigned long long>(veh_handler_before.base),
                static_cast<unsigned long long>(veh_handler_before.size),
                veh_handler_before.state,
                veh_handler_before.protect,
                veh_handler_before.type,
                veh_handler_after_ok ? 1 : 0,
                static_cast<unsigned long long>(veh_handler_after.base),
                static_cast<unsigned long long>(veh_handler_after.size),
                veh_handler_after.state,
                veh_handler_after.protect,
                veh_handler_after.type,
                veh_handler_after_error.c_str(),
                veh_ring_before_ok ? 1 : 0,
                static_cast<unsigned long long>(veh_ring_before.base),
                static_cast<unsigned long long>(veh_ring_before.size),
                veh_ring_before.state,
                veh_ring_before.protect,
                veh_ring_before.type,
                veh_ring_after_ok ? 1 : 0,
                static_cast<unsigned long long>(veh_ring_after.base),
                static_cast<unsigned long long>(veh_ring_after.size),
                veh_ring_after.state,
                veh_ring_after.protect,
                veh_ring_after.type,
                veh_ring_after_error.c_str(),
                veh_mitigation.open_ok ? 1 : 0,
                static_cast<unsigned long>(veh_mitigation.open_error),
                veh_mitigation.dynamic_ok ? 1 : 0,
                static_cast<unsigned long>(veh_mitigation.dynamic_error),
                static_cast<unsigned long>(veh_mitigation.dynamic_flags),
                veh_mitigation.cfg_ok ? 1 : 0,
                static_cast<unsigned long>(veh_mitigation.cfg_error),
                static_cast<unsigned long>(veh_mitigation.cfg_flags),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            diag::log_tagged_fmt("pg_sniff",
                "veh_register_failed_remote_diag call_id=%llu expected_call_id=%llu pid=%u active_pid_entry=%u active_pid_after=%u completed=%d ok=%d gle=%lu timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled_before=%d cancelled_after=%d deadline_expired_before=%d deadline_expired_after=%d stale_pid=%d late_completion=%d lower_phase=%s lower_reason=%s lower_completed=%d lower_ok=%d lower_gle=%lu lower_worker_tid=%lu lower_worker_alive=%u lower_queue_depth_submit=%u lower_queue_depth_after_pop=%u lower_inflight_after=%u lower_queue_wait_ms=%llu lower_elapsed_ms=%llu lower_deadline_remaining_finish_ms=%llu lower_worker_exception=%d lower_worker_creation_failed=%d zero_result_rejected=%d removed_from_queue=%d popped=%d execution_started=%d executing_abandoned=%d seh_exception=%d seh_code=0x%08lX seh_addr=0x%llX seh_fault=0x%llX seh_rip=0x%llX lower_error_value=%d lower_error_category=%s lower_error_message=%s remote_elapsed_ms=%llu measured_elapsed_ms=%llu status=%s last_error=%s",
                static_cast<unsigned long long>(veh_remote_diag.call_id),
                static_cast<unsigned long long>(veh_expected_call_id),
                pid,
                veh_remote_diag.active_pid_entry,
                veh_remote_diag.active_pid_after,
                veh_remote_diag.completed ? 1 : 0,
                veh_remote_diag.ok ? 1 : 0,
                static_cast<unsigned long>(veh_call_gle),
                veh_remote_diag.timeout_ms,
                static_cast<unsigned long long>(veh_remote_diag.deadline_ms),
                static_cast<unsigned long long>(veh_remote_diag.deadline_remaining_ms),
                veh_remote_diag.cancelled_before ? 1 : 0,
                veh_remote_diag.cancelled_after ? 1 : 0,
                veh_remote_diag.deadline_expired_before ? 1 : 0,
                veh_remote_diag.deadline_expired_after ? 1 : 0,
                veh_remote_diag.stale_pid ? 1 : 0,
                veh_remote_diag.late_completion ? 1 : 0,
                veh_remote_diag.lower_phase.c_str(),
                veh_remote_diag.lower_completion_reason.c_str(),
                veh_remote_diag.lower_completed ? 1 : 0,
                veh_remote_diag.lower_ok ? 1 : 0,
                static_cast<unsigned long>(veh_remote_diag.lower_gle),
                static_cast<unsigned long>(veh_remote_diag.lower_worker_tid),
                veh_remote_diag.lower_worker_alive,
                veh_remote_diag.lower_queue_depth_at_submit,
                veh_remote_diag.lower_queue_depth_after_pop,
                veh_remote_diag.lower_inflight_after,
                static_cast<unsigned long long>(veh_remote_diag.lower_queue_wait_ms),
                static_cast<unsigned long long>(veh_remote_diag.lower_elapsed_ms),
                static_cast<unsigned long long>(veh_remote_diag.lower_deadline_remaining_at_finish_ms),
                veh_remote_diag.lower_worker_exception ? 1 : 0,
                veh_remote_diag.lower_worker_creation_failed ? 1 : 0,
                veh_remote_diag.zero_result_rejected ? 1 : 0,
                veh_remote_diag.removed_from_queue ? 1 : 0,
                veh_remote_diag.popped_from_queue ? 1 : 0,
                veh_remote_diag.execution_started ? 1 : 0,
                veh_remote_diag.executing_abandoned ? 1 : 0,
                veh_remote_diag.seh_exception ? 1 : 0,
                static_cast<unsigned long>(veh_remote_diag.seh_exception_code),
                static_cast<unsigned long long>(veh_remote_diag.seh_exception_address),
                static_cast<unsigned long long>(veh_remote_diag.seh_fault_address),
                static_cast<unsigned long long>(veh_remote_diag.seh_rip),
                veh_remote_diag.lower_worker_error_value,
                veh_remote_diag.lower_worker_error_category.c_str(),
                veh_remote_diag.lower_worker_error_message.c_str(),
                static_cast<unsigned long long>(veh_remote_diag.elapsed_ms),
                static_cast<unsigned long long>(veh_call_elapsed),
                veh_call_status.c_str(),
                veh_call_last_error.c_str());
            record_install_failure(lower_uncertain ? "veh_register_quarantined" : "veh_register_failed",
                                   lower_uncertain ? "remote RtlAddVectoredExceptionHandler result is uncertain; page-guard resources quarantined or removed only after proven handle cleanup" : "remote RtlAddVectoredExceptionHandler call returned NULL",
                                   pid,
                                   requested_addr,
                                   requested_size,
                                   target_addr,
                                   region_size,
                                   &mri,
                                   proposed_guard_protect,
                                   veh_call_gle);
            record_install_veh_failure_detail(driver_bridge::attached_pid(),
                                              ring_addr,
                                              sc_addr,
                                              veh_context_addr,
                                              ntdll_mod_install.base,
                                               ntdll_mod_install.size,
                                               rtl_add_fn,
                                               rtl_remove_fn,
                                               known_late_handle ? veh_remote_diag.result : veh_handle,
                                               veh_call_gle,
                                              veh_call_elapsed,
                                              orig_protect,
                                              proposed_guard_protect,
                                              cleanup_sc_ok ? 1u : 0u,
                                              cleanup_ring_ok ? 1u : 0u,
                                              GetTickCount64() - install_start,
                                              install_generation,
                                              install_stop_generation_.load(std::memory_order_acquire),
                                              veh_mitigation,
                                              veh_remote_diag,
                                               veh_call_status,
                                               veh_call_last_error);
            if (lower_uncertain || quarantine_id != 0 || cleanup_veh_remove_attempted) {
                std::lock_guard<std::mutex> lk(failure_mutex_);
                last_install_failure_.quarantined = (quarantine_id != 0 || retained_sc || retained_ring) ? 1u : 0u;
                last_install_failure_.quarantine_id = quarantine_id;
                last_install_failure_.quarantine_cleanup_attempted = cleanup_veh_remove_attempted || cleanup_sc_ok || cleanup_ring_ok ? 1u : 0u;
                last_install_failure_.quarantine_veh_remove_attempted = cleanup_veh_remove_attempted ? 1u : 0u;
                last_install_failure_.quarantine_veh_remove_ok = cleanup_veh_remove_ok ? 1u : 0u;
                last_install_failure_.quarantine_retained_shellcode = retained_sc ? 1u : 0u;
                last_install_failure_.quarantine_retained_ring = retained_ring ? 1u : 0u;
                if (!last_install_failure_.detail.empty())
                    last_install_failure_.detail += " ";
                last_install_failure_.detail += std::string("cleanup_decision=") + cleanup_decision +
                    " quarantine_id=" + std::to_string(quarantine_id) +
                    " retained_sc=" + std::to_string(retained_sc ? 1 : 0) +
                    " retained_ring=" + std::to_string(retained_ring ? 1 : 0) +
                    " veh_remove_attempted=" + std::to_string(cleanup_veh_remove_attempted ? 1 : 0) +
                    " veh_remove_ok=" + std::to_string(cleanup_veh_remove_ok ? 1 : 0);
            }
            SetLastError(veh_call_gle);
            return 0;
        }
        release_install_quarantine_reservation(quarantine_reservation_id, "veh_register_success");
        const uint64_t veh_wrapper_addr_registered = veh_wrapper_addr;
        const uint64_t veh_diag_addr_registered = veh_diag_addr;
        const bool veh_cleanup_wrapper_ok = veh_wrapper_addr == 0 || driver_bridge::free_memory_for(pid, veh_wrapper_addr);
        const std::string veh_cleanup_wrapper_error = veh_cleanup_wrapper_ok ? std::string() : driver_bridge::last_error();
        if (veh_cleanup_wrapper_ok)
            veh_wrapper_addr = 0;
        const bool veh_cleanup_diag_ok = veh_diag_addr == 0 || driver_bridge::free_memory_for(pid, veh_diag_addr);
        const std::string veh_cleanup_diag_error = veh_cleanup_diag_ok ? std::string() : driver_bridge::last_error();
        if (veh_cleanup_diag_ok)
            veh_diag_addr = 0;
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_wrapper_cleanup pid=%u active_pid=%u wrapper=0x%llX diag=0x%llX cleanup_wrapper_ok=%d cleanup_wrapper_error=%s cleanup_diag_ok=%d cleanup_diag_error=%s handle=0x%llX target_result=0x%llX target_last_error_after=%lu elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(veh_wrapper_addr_registered),
            static_cast<unsigned long long>(veh_diag_addr_registered),
            veh_cleanup_wrapper_ok ? 1 : 0,
            veh_cleanup_wrapper_error.c_str(),
            veh_cleanup_diag_ok ? 1 : 0,
            veh_cleanup_diag_error.c_str(),
            static_cast<unsigned long long>(veh_handle),
            static_cast<unsigned long long>(veh_target_diag.result),
            static_cast<unsigned long>(veh_target_diag.last_error_after),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        if (const char* reason = check_install_cancelled("after_veh_register")) {
            uint64_t removed = remove_vectored_exception_handler_remote(pid,
                                                                         ntdll_mod_install.base,
                                                                         rtl_remove_fn,
                                                                         veh_handle,
                                                                         "install_cancel_after_veh_register",
                                                                         install_start);
            const bool cleanup_sc_ok = removed != 0 && driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = removed != 0 && driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_veh_register pid=%u veh=0x%llX removed=0x%llX sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                static_cast<unsigned long long>(veh_handle),
                static_cast<unsigned long long>(removed),
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after VEH registration", &mri, target_addr, region_size, 0);
        }
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_done pid=%u active_pid=%u caller_tid=%lu generation=%llu current_generation=%llu module=ntdll.dll ntdll_base=0x%llX ntdll_size=0x%llX function=RtlAddVectoredExceptionHandler va=0x%llX handler=0x%llX ring=0x%llX context=0x%llX handle=0x%llX method=driver_bridge::call_function gle=%lu remote_elapsed_ms=%llu original_protect=0x%08X proposed_protect=0x%08X mitigation_open=%d mitigation_open_error=%lu dyn_ok=%d dyn_error=%lu dyn_flags=0x%08lX cfg_ok=%d cfg_error=%lu cfg_flags=0x%08lX target_after_query=%d target_after_base=0x%llX target_after_size=0x%llX target_after_state=0x%08X target_after_protect=0x%08X target_after_type=0x%08X handler_after_query=%d handler_after_base=0x%llX handler_after_size=0x%llX handler_after_state=0x%08X handler_after_protect=0x%08X handler_after_type=0x%08X ring_after_query=%d ring_after_base=0x%llX ring_after_size=0x%llX ring_after_state=0x%08X ring_after_protect=0x%08X ring_after_type=0x%08X elapsed_ms=%llu",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(install_stop_generation_.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(ntdll_mod_install.base),
            static_cast<unsigned long long>(ntdll_mod_install.size),
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(sc_addr),
            static_cast<unsigned long long>(ring_addr),
            static_cast<unsigned long long>(veh_context_addr),
            static_cast<unsigned long long>(veh_handle),
            static_cast<unsigned long>(veh_call_gle),
            static_cast<unsigned long long>(veh_call_elapsed),
            orig_protect,
            proposed_guard_protect,
            veh_mitigation.open_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.open_error),
            veh_mitigation.dynamic_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.dynamic_error),
            static_cast<unsigned long>(veh_mitigation.dynamic_flags),
            veh_mitigation.cfg_ok ? 1 : 0,
            static_cast<unsigned long>(veh_mitigation.cfg_error),
            static_cast<unsigned long>(veh_mitigation.cfg_flags),
            veh_target_after_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_target_after.base),
            static_cast<unsigned long long>(veh_target_after.size),
            veh_target_after.state,
            veh_target_after.protect,
            veh_target_after.type,
            veh_handler_after_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_handler_after.base),
            static_cast<unsigned long long>(veh_handler_after.size),
            veh_handler_after.state,
            veh_handler_after.protect,
            veh_handler_after.type,
            veh_ring_after_ok ? 1 : 0,
            static_cast<unsigned long long>(veh_ring_after.base),
            static_cast<unsigned long long>(veh_ring_after.size),
            veh_ring_after.state,
            veh_ring_after.protect,
            veh_ring_after.type,
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        diag::log_tagged_fmt("pg_sniff",
            "veh_register_done_remote_diag call_id=%llu expected_call_id=%llu pid=%u active_pid_entry=%u active_pid_after=%u completed=%d ok=%d gle=%lu timeout_ms=%u deadline_ms=%llu deadline_remaining_ms=%llu cancelled_before=%d cancelled_after=%d deadline_expired_before=%d deadline_expired_after=%d stale_pid=%d late_completion=%d remote_elapsed_ms=%llu measured_elapsed_ms=%llu status=%s last_error=%s",
            static_cast<unsigned long long>(veh_remote_diag.call_id),
            static_cast<unsigned long long>(veh_expected_call_id),
            pid,
            veh_remote_diag.active_pid_entry,
            veh_remote_diag.active_pid_after,
            veh_remote_diag.completed ? 1 : 0,
            veh_remote_diag.ok ? 1 : 0,
            static_cast<unsigned long>(veh_call_gle),
            veh_remote_diag.timeout_ms,
            static_cast<unsigned long long>(veh_remote_diag.deadline_ms),
            static_cast<unsigned long long>(veh_remote_diag.deadline_remaining_ms),
            veh_remote_diag.cancelled_before ? 1 : 0,
            veh_remote_diag.cancelled_after ? 1 : 0,
            veh_remote_diag.deadline_expired_before ? 1 : 0,
            veh_remote_diag.deadline_expired_after ? 1 : 0,
            veh_remote_diag.stale_pid ? 1 : 0,
            veh_remote_diag.late_completion ? 1 : 0,
            static_cast<unsigned long long>(veh_remote_diag.elapsed_ms),
            static_cast<unsigned long long>(veh_call_elapsed),
            veh_call_status.c_str(),
            veh_call_last_error.c_str());

        uint32_t old_prot = 0;
        if (const char* reason = check_install_cancelled("before_target_guard_protect")) {
            uint64_t removed = remove_vectored_exception_handler_remote(pid,
                                                                         ntdll_mod_install.base,
                                                                         rtl_remove_fn,
                                                                         veh_handle,
                                                                         "install_cancel_before_target_guard_protect",
                                                                         install_start);
            if (removed == 0)
                diag::log_tagged_fmt("pg_sniff", "veh_remove_failed pid=%u handle=0x%llX phase=before_target_guard_protect",
                    pid, static_cast<unsigned long long>(veh_handle));
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install(reason, "page-guard install cancelled before PAGE_GUARD protection", &mri, target_addr, region_size, 0);
        }
        log_install_phase("target_guard_protect_begin");
        if (!driver_bridge::protect_memory_for_bounded(pid, target_addr, region_size,
                                                       orig_protect | PAGE_GUARD, &old_prot, 5000)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=target_guard_protect pid=%u target=0x%llX size=0x%llX orig=0x%08X last_error=%s",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size),
                orig_protect,
                driver_bridge::last_error().c_str());
            uint64_t removed = remove_vectored_exception_handler_remote(pid,
                                                                         ntdll_mod_install.base,
                                                                         rtl_remove_fn,
                                                                         veh_handle,
                                                                         "install_guard_cleanup",
                                                                         install_start);
            if (removed == 0)
                diag::log_tagged_fmt("pg_sniff", "veh_remove_failed pid=%u handle=0x%llX",
                    pid, static_cast<unsigned long long>(veh_handle));
            driver_bridge::free_memory_for(pid, sc_addr);
            driver_bridge::free_memory_for(pid, ring_addr);
            return fail_install("target_guard_protect", "driver or OS refused PAGE_GUARD protection for the normalized target region", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }
        log_install_phase("target_guard_protect_done");
        if (const char* reason = check_install_cancelled("after_target_guard_protect")) {
            uint32_t cleanup_old_protect = 0;
            const bool cleanup_restored = driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, &cleanup_old_protect);
            bool cleanup_removed = false;
            if (cleanup_restored)
                cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                           ntdll_mod_install.base,
                                                                           rtl_remove_fn,
                                                                           veh_handle,
                                                                           "install_cancel_after_target_guard",
                                                                           install_start) != 0;
            const bool cleanup_sc_ok = cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=after_target_guard_protect pid=%u restored=%d old=0x%08X removed=%d sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                pid,
                cleanup_restored ? 1 : 0,
                cleanup_old_protect,
                cleanup_removed ? 1 : 0,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled after PAGE_GUARD protection", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }


        auto session         = std::make_shared<pg_session_t>();
        session->pid         = pid;
        session->target_addr = target_addr;
        session->region_size = region_size;
        session->ring_addr   = ring_addr;
        session->sc_addr     = sc_addr;
        session->orig_protect= orig_protect;
        session->veh_handle  = veh_handle;
        session->ntdll_base   = ntdll_mod_install.base;
        session->ntdll_size   = ntdll_mod_install.size;
        session->rtl_remove_veh_fn = rtl_remove_fn;
        session->polling.store(true);
        session->exited.store(!auto_poll, std::memory_order_release);
        session->capture_payloads.store(capture_payloads, std::memory_order_release);
        session->max_records_per_drain.store(max_records_per_drain, std::memory_order_release);
        session->auto_poll.store(auto_poll, std::memory_order_release);

        uint32_t sid = next_id_++;
        session->session_id = sid;

        if (const char* reason = check_install_cancelled("before_poller_post")) {
            uint32_t cleanup_old_protect = 0;
            const bool cleanup_restored = driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, &cleanup_old_protect);
            bool cleanup_removed = false;
            if (cleanup_restored)
                cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                           ntdll_mod_install.base,
                                                                           rtl_remove_fn,
                                                                           veh_handle,
                                                                           "install_cancel_before_poller_post",
                                                                           install_start) != 0;
            const bool cleanup_sc_ok = cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            session->polling.store(false);
            session->exited.store(true);
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=before_poller_post sid=%u pid=%u restored=%d old=0x%08X removed=%d sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                sid,
                pid,
                cleanup_restored ? 1 : 0,
                cleanup_old_protect,
                cleanup_removed ? 1 : 0,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled before poll worker scheduling", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }
        log_install_phase("poller_post_begin");
        if (auto_poll && !work_queue::post([worker_session = session]() mutable {
            poll_ring(std::move(worker_session));
        })) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=poll_worker_post pid=%u target=0x%llX",
                pid, static_cast<unsigned long long>(target_addr));
            uint32_t cleanup_old_protect = 0;
            const bool cleanup_restored = driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, &cleanup_old_protect);
            bool cleanup_removed = false;
            if (cleanup_restored && rtl_remove_fn)
                cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                           ntdll_mod_install.base,
                                                                           rtl_remove_fn,
                                                                           veh_handle,
                                                                           "install_worker_post_cleanup",
                                                                           install_start) != 0;
            diag::log_tagged_fmt("pg_sniff", "install_failed_cleanup pid=%u restored=%d old=0x%08X rtl_rm=0x%llX removed=%d sc=0x%llX ring=0x%llX",
                pid,
                cleanup_restored ? 1 : 0,
                cleanup_old_protect,
                static_cast<unsigned long long>(rtl_remove_fn),
                cleanup_removed ? 1 : 0,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr));
            if (cleanup_restored && cleanup_removed) {
                driver_bridge::free_memory_for(pid, sc_addr);
                driver_bridge::free_memory_for(pid, ring_addr);
            }
            session->polling.store(false);
            session->exited.store(true);
            return fail_install("poll_worker_post", "failed to schedule the page-guard poll worker", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }

        if (const char* reason = check_install_cancelled("before_session_register")) {
            session->teardown_requested.store(true, std::memory_order_release);
            session->polling.store(false, std::memory_order_release);
            session->poll_cv.notify_all();
            const bool poller_exited = stop_session_poller(session, 1000, "install_cancel_before_register");
            uint32_t cleanup_old_protect = 0;
            const bool cleanup_restored = driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, &cleanup_old_protect);
            bool cleanup_removed = false;
            if (cleanup_restored)
                cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                           ntdll_mod_install.base,
                                                                           rtl_remove_fn,
                                                                           veh_handle,
                                                                           "install_cancel_before_register",
                                                                           install_start) != 0;
            const bool cleanup_sc_ok = poller_exited && cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = poller_exited && cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=before_session_register sid=%u pid=%u poller_exited=%d restored=%d old=0x%08X removed=%d sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                sid,
                pid,
                poller_exited ? 1 : 0,
                cleanup_restored ? 1 : 0,
                cleanup_old_protect,
                cleanup_removed ? 1 : 0,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled before session registration", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_session_register_begin sid=%u pid=%u active_pid=%u target=0x%llX size=0x%llX elapsed_ms=%llu",
            sid,
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        std::unique_lock<std::mutex> lk(sessions_mutex_);
        if (const char* reason = check_install_cancelled("inside_session_register_lock")) {
            lk.unlock();
            session->teardown_requested.store(true, std::memory_order_release);
            session->polling.store(false, std::memory_order_release);
            session->poll_cv.notify_all();
            const bool poller_exited = stop_session_poller(session, 1000, "install_cancel_inside_register_lock");
            uint32_t cleanup_old_protect = 0;
            const bool cleanup_restored = driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, &cleanup_old_protect);
            bool cleanup_removed = false;
            if (cleanup_restored)
                cleanup_removed = remove_vectored_exception_handler_remote(pid,
                                                                           ntdll_mod_install.base,
                                                                           rtl_remove_fn,
                                                                           veh_handle,
                                                                           "install_cancel_inside_register_lock",
                                                                           install_start) != 0;
            const bool cleanup_sc_ok = poller_exited && cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, sc_addr);
            const std::string cleanup_sc_error = cleanup_sc_ok ? std::string() : driver_bridge::last_error();
            const bool cleanup_ring_ok = poller_exited && cleanup_restored && cleanup_removed && driver_bridge::free_memory_for(pid, ring_addr);
            const std::string cleanup_ring_error = cleanup_ring_ok ? std::string() : driver_bridge::last_error();
            diag::log_tagged_fmt("pg_sniff",
                "install_cancel_cleanup phase=inside_session_register_lock sid=%u pid=%u poller_exited=%d restored=%d old=0x%08X removed=%d sc=0x%llX ring=0x%llX cleanup_sc_ok=%d cleanup_sc_error=%s cleanup_ring_ok=%d cleanup_ring_error=%s elapsed_ms=%llu",
                sid,
                pid,
                poller_exited ? 1 : 0,
                cleanup_restored ? 1 : 0,
                cleanup_old_protect,
                cleanup_removed ? 1 : 0,
                static_cast<unsigned long long>(sc_addr),
                static_cast<unsigned long long>(ring_addr),
                cleanup_sc_ok ? 1 : 0,
                cleanup_sc_error.c_str(),
                cleanup_ring_ok ? 1 : 0,
                cleanup_ring_error.c_str(),
                static_cast<unsigned long long>(GetTickCount64() - install_start));
            return fail_install(reason, "page-guard install cancelled while acquiring session registration lock", &mri, target_addr, region_size, orig_protect | PAGE_GUARD);
        }
        sessions_[sid] = session;
        g_install_ready.store(true, std::memory_order_release);
        diag::log_tagged_fmt("pg_sniff", "install_ok sid=%u pid=%u target=0x%llX size=0x%llX ring=0x%llX sc=0x%llX orig=0x%08X old_guard=0x%08X veh=0x%llX payloads=%d max_drain=%u auto_poll=%d generation=%llu elapsed_ms=%llu",
            sid,
            pid,
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            static_cast<unsigned long long>(ring_addr),
            static_cast<unsigned long long>(sc_addr),
            orig_protect,
            old_prot,
            static_cast<unsigned long long>(veh_handle),
            capture_payloads ? 1 : 0,
            max_records_per_drain,
            auto_poll ? 1 : 0,
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        return sid;
    }


    std::vector<pg_capture_t> get_captures(uint32_t session_id) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return {};
            sess = it->second;
        }
        if (!sess) return {};
        if (driver_bridge::using_kernel_driver())
            drain_ring(sess.get());
        std::lock_guard<std::mutex> slk(sess->captures_mutex);
        std::vector<pg_capture_t> out;
        while (!sess->captures.empty()) {
            out.push_back(sess->captures.front().metadata);
            sess->captures.pop();
        }
        return out;
    }

    std::vector<pg_capture_record_t> get_capture_records(uint32_t session_id) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return {};
            sess = it->second;
        }
        if (!sess) return {};
        if (driver_bridge::using_kernel_driver())
            drain_ring(sess.get());
        std::lock_guard<std::mutex> slk(sess->captures_mutex);
        std::vector<pg_capture_record_t> out;
        while (!sess->captures.empty()) {
            out.push_back(std::move(sess->captures.front()));
            sess->captures.pop();
        }
        return out;
    }

    bool set_payload_budget(uint32_t session_id, size_t budget) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return false;
            sess = it->second;
        }
        if (!sess) return false;
        sess->payload_budget.store(budget, std::memory_order_release);
        sess->payload_reads.store(0, std::memory_order_release);
        diag::log_tagged_fmt("pg_sniff", "payload_budget sid=%u budget=%zu", session_id, budget);
        return true;
    }


    bool uninstall(uint32_t session_id) {
        const ULONGLONG cleanup_start = GetTickCount64();
        diag::log_tagged_fmt("pg_sniff",
            "uninstall_session_release_begin sid=%u active_pid=%u elapsed_ms=0",
            session_id,
            driver_bridge::attached_pid());
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) {
                diag::log_tagged_fmt("pg_sniff",
                    "uninstall_session_release_missing sid=%u active_pid=%u elapsed_ms=%llu",
                    session_id,
                    driver_bridge::attached_pid(),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                return false;
            }
            sess = std::move(it->second);
            sessions_.erase(it);
        }
        diag::log_tagged_fmt("pg_sniff",
            "uninstall_session_release_done sid=%u pid=%u active_pid=%u elapsed_ms=%llu",
            session_id,
            sess ? sess->pid : 0,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
        sess->teardown_requested.store(true, std::memory_order_release);
        diag::log_tagged_fmt("pg_sniff", "uninstall_start sid=%u pid=%u target=0x%llX size=0x%llX exited=%d",
            session_id,
            sess->pid,
            static_cast<unsigned long long>(sess->target_addr),
            static_cast<unsigned long long>(sess->region_size),
            sess->exited.load() ? 1 : 0);

        ULONGLONG poller_elapsed_ms = 0;
        ULONGLONG active_elapsed_ms = 0;
        ULONGLONG query_before_elapsed_ms = 0;
        ULONGLONG restore_elapsed_ms = 0;
        ULONGLONG query_after_elapsed_ms = 0;
        ULONGLONG veh_elapsed_ms = 0;
        ULONGLONG free_elapsed_ms = 0;
        const ULONGLONG poller_t0 = GetTickCount64();
        bool poller_exited = stop_session_poller(sess, 1000, "uninstall");
        poller_elapsed_ms = GetTickCount64() - poller_t0;
        diag::log_tagged_fmt("pg_sniff", "uninstall_poller_state sid=%u exited=%d elapsed_ms=%llu",
            session_id,
            poller_exited ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

        bool cleanup_complete = false;
        if (driver_bridge::using_kernel_driver()) {
            active_pid_scope_t active;
            const ULONGLONG active_t0 = GetTickCount64();
            const bool active_ok = active.enter(sess->pid);
            active_elapsed_ms = GetTickCount64() - active_t0;
            diag::log_tagged_fmt("pg_sniff", "uninstall_active_pid sid=%u active_ok=%d attached=%u elapsed_ms=%llu",
                session_id,
                active_ok ? 1 : 0,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

            driver_bridge::memory_region_t before_restore{};
            const ULONGLONG query_before_t0 = GetTickCount64();
            const bool before_query_ok = active_ok && driver_bridge::query_memory_for(sess->pid, sess->target_addr, before_restore);
            query_before_elapsed_ms = GetTickCount64() - query_before_t0;
            diag::log_tagged_fmt("pg_sniff", "uninstall_region_before_restore sid=%u query_ok=%d base=0x%llX size=0x%llX state=0x%08X protect=0x%08X type=0x%08X elapsed_ms=%llu",
                session_id,
                before_query_ok ? 1 : 0,
                static_cast<unsigned long long>(before_restore.base),
                static_cast<unsigned long long>(before_restore.size),
                before_restore.state,
                before_restore.protect,
                before_restore.type,
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

            bool restore_ok = false;
            uint32_t old_restore_protect = 0;
            if (active_ok) {
                const ULONGLONG restore_t0 = GetTickCount64();
                diag::log_tagged_fmt("pg_sniff", "uninstall_restore_protect_begin sid=%u target=0x%llX size=0x%llX orig=0x%08X elapsed_ms=%llu",
                    session_id,
                    static_cast<unsigned long long>(sess->target_addr),
                    static_cast<unsigned long long>(sess->region_size),
                    sess->orig_protect,
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                restore_ok = driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                                               sess->orig_protect, &old_restore_protect);
                restore_elapsed_ms = GetTickCount64() - restore_t0;
                sess->protection_restored.store(restore_ok, std::memory_order_release);
                diag::log_tagged_fmt("pg_sniff", "uninstall_restore_protect_done sid=%u ok=%d old=0x%08X elapsed_ms=%llu last_error=%s",
                    session_id,
                    restore_ok ? 1 : 0,
                    old_restore_protect,
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start),
                    driver_bridge::last_error().c_str());
            }

            driver_bridge::memory_region_t after_restore{};
            const ULONGLONG query_after_t0 = GetTickCount64();
            const bool after_query_ok = active_ok && driver_bridge::query_memory_for(sess->pid, sess->target_addr, after_restore);
            query_after_elapsed_ms = GetTickCount64() - query_after_t0;
            diag::log_tagged_fmt("pg_sniff", "uninstall_region_after_restore sid=%u query_ok=%d base=0x%llX size=0x%llX state=0x%08X protect=0x%08X type=0x%08X elapsed_ms=%llu",
                session_id,
                after_query_ok ? 1 : 0,
                static_cast<unsigned long long>(after_restore.base),
                static_cast<unsigned long long>(after_restore.size),
                after_restore.state,
                after_restore.protect,
                after_restore.type,
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

            const bool guard_cleared = restore_ok && after_query_ok && ((after_restore.protect & PAGE_GUARD) == 0);
            if (restore_ok && before_query_ok && (before_restore.protect & PAGE_GUARD))
                Sleep(25);

            bool veh_removed = sess->veh_handle == 0;
            if (active_ok && sess->veh_handle && guard_cleared) {
                const ULONGLONG veh_t0 = GetTickCount64();
                uint64_t ntdll_base = sess->ntdll_base;
                uint64_t ntdll_size = sess->ntdll_size;
                if (ntdll_base == 0) {
                    driver_bridge::module_info_t ntdll_mod = find_module_info(sess->pid, "ntdll.dll");
                    ntdll_base = ntdll_mod.base;
                    ntdll_size = ntdll_mod.size;
                }
                uint64_t rtl_rm = sess->rtl_remove_veh_fn;
                diag::log_tagged_fmt("pg_sniff", "uninstall_remove_veh_cached sid=%u pid=%u active_pid=%u handle=0x%llX ntdll=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX elapsed_ms=%llu outcome=%s",
                    session_id,
                    sess->pid,
                    driver_bridge::attached_pid(),
                    static_cast<unsigned long long>(sess->veh_handle),
                    static_cast<unsigned long long>(ntdll_base),
                    static_cast<unsigned long long>(rtl_rm),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start),
                    rtl_rm != 0 ? "hit" : "miss");
                if (rtl_rm == 0 && ntdll_base != 0) {
                    rtl_rm = resolve_system_export_for_pid(sess->pid,
                                                           ntdll_base,
                                                           ntdll_size,
                                                           "ntdll.dll",
                                                           "RtlRemoveVectoredExceptionHandler",
                                                           "uninstall_resolve_rtlremoveveh",
                                                           cleanup_start);
                }
                if (ntdll_base != 0 && rtl_rm != 0) {
                    uint64_t removed = remove_vectored_exception_handler_remote(sess->pid,
                                                                                 ntdll_base,
                                                                                 rtl_rm,
                                                                                 sess->veh_handle,
                                                                                 "uninstall",
                                                                                 cleanup_start);
                    veh_removed = removed != 0;
                    sess->veh_removed.store(veh_removed, std::memory_order_release);
                    if (!veh_removed)
                        diag::log_tagged_fmt("pg_sniff", "veh_remove_failed pid=%u handle=0x%llX",
                            sess->pid, static_cast<unsigned long long>(sess->veh_handle));
                } else {
                    diag::log_tagged_fmt("pg_sniff", "uninstall_remove_veh_fail_closed sid=%u pid=%u active_pid=%u handle=0x%llX ntdll=0x%llX function=RtlRemoveVectoredExceptionHandler va=0x%llX elapsed_ms=%llu",
                        session_id,
                        sess->pid,
                        driver_bridge::attached_pid(),
                        static_cast<unsigned long long>(sess->veh_handle),
                        static_cast<unsigned long long>(ntdll_base),
                        static_cast<unsigned long long>(rtl_rm),
                        static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                }
                veh_elapsed_ms = GetTickCount64() - veh_t0;
            } else if (active_ok && sess->veh_handle) {
                diag::log_tagged_fmt("pg_sniff", "uninstall_remove_veh_skipped sid=%u handle=0x%llX guard_cleared=%d restore_ok=%d after_query_ok=%d after_protect=0x%08X elapsed_ms=%llu",
                    session_id,
                    static_cast<unsigned long long>(sess->veh_handle),
                    guard_cleared ? 1 : 0,
                    restore_ok ? 1 : 0,
                    after_query_ok ? 1 : 0,
                    after_restore.protect,
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
            }

            poller_exited = sess->exited.load(std::memory_order_acquire);
            cleanup_complete = active_ok && poller_exited && veh_removed && guard_cleared;
            if (cleanup_complete) {
                const ULONGLONG free_t0 = GetTickCount64();
                diag::log_tagged_fmt("pg_sniff", "uninstall_free_begin sid=%u sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                    session_id,
                    static_cast<unsigned long long>(sess->sc_addr),
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                const bool free_sc_ok = sess->sc_addr == 0 || driver_bridge::free_memory_for(sess->pid, sess->sc_addr);
                const std::string free_sc_error = free_sc_ok ? std::string() : driver_bridge::last_error();
                const bool free_ring_ok = sess->ring_addr == 0 || driver_bridge::free_memory_for(sess->pid, sess->ring_addr);
                const std::string free_ring_error = free_ring_ok ? std::string() : driver_bridge::last_error();
                if (free_sc_ok)
                    sess->sc_addr = 0;
                if (free_ring_ok)
                    sess->ring_addr = 0;
                cleanup_complete = free_sc_ok && free_ring_ok;
                free_elapsed_ms = GetTickCount64() - free_t0;
                diag::log_tagged_fmt("pg_sniff", "uninstall_free_done sid=%u sc_ok=%d sc_error=%s ring_ok=%d ring_error=%s cleanup_complete=%d elapsed_ms=%llu",
                    session_id,
                    free_sc_ok ? 1 : 0,
                    free_sc_error.c_str(),
                    free_ring_ok ? 1 : 0,
                    free_ring_error.c_str(),
                    cleanup_complete ? 1 : 0,
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                if (!cleanup_complete) {
                    diag::log_tagged_fmt("pg_sniff", "uninstall_retired_free_failed sid=%u sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                        session_id,
                        static_cast<unsigned long long>(sess->sc_addr),
                        static_cast<unsigned long long>(sess->ring_addr),
                        static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                    std::lock_guard<std::mutex> lk(sessions_mutex_);
                    retired_sessions_.push_back(std::move(sess));
                }
            } else {
                diag::log_tagged_fmt("pg_sniff", "uninstall_retired sid=%u active_ok=%d exited=%d veh_removed=%d restore_ok=%d guard_cleared=%d sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                    session_id,
                    active_ok ? 1 : 0,
                    poller_exited ? 1 : 0,
                    veh_removed ? 1 : 0,
                    restore_ok ? 1 : 0,
                    guard_cleared ? 1 : 0,
                    static_cast<unsigned long long>(sess->sc_addr),
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                std::lock_guard<std::mutex> lk(sessions_mutex_);
                retired_sessions_.push_back(std::move(sess));
            }
        } else {
            diag::log_tagged_fmt("pg_sniff", "uninstall_fail_closed_no_kernel sid=%u pid=%u sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                session_id,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(sess ? sess->sc_addr : 0),
                static_cast<unsigned long long>(sess ? sess->ring_addr : 0),
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            retired_sessions_.push_back(std::move(sess));
        }
        diag::log_tagged_fmt("pg_sniff", "uninstall_phase_timing sid=%u cleanup_complete=%d poller_ms=%llu active_pid_ms=%llu query_before_ms=%llu restore_ms=%llu query_after_ms=%llu veh_ms=%llu free_ms=%llu total_ms=%llu",
            session_id,
            cleanup_complete ? 1 : 0,
            static_cast<unsigned long long>(poller_elapsed_ms),
            static_cast<unsigned long long>(active_elapsed_ms),
            static_cast<unsigned long long>(query_before_elapsed_ms),
            static_cast<unsigned long long>(restore_elapsed_ms),
            static_cast<unsigned long long>(query_after_elapsed_ms),
            static_cast<unsigned long long>(veh_elapsed_ms),
            static_cast<unsigned long long>(free_elapsed_ms),
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
        diag::log_tagged_fmt("pg_sniff", "uninstall_done sid=%u cleanup_complete=%d elapsed_ms=%llu",
            session_id,
            cleanup_complete ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
        return cleanup_complete;
    }

    size_t signal_stop_all() {
        const ULONGLONG started = GetTickCount64();
        const std::uint64_t generation = install_stop_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::vector<std::shared_ptr<pg_session_t>> snapshot;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            snapshot.reserve(sessions_.size());
            for (auto& [sid, sess] : sessions_) {
                (void)sid;
                if (sess)
                    snapshot.push_back(sess);
            }
        }
        diag::log_tagged_fmt("pg_sniff",
            "signal_stop_all_begin sessions=%zu generation=%llu cancelled=%d deadline_ms=%llu diag_id=%s",
            snapshot.size(),
            static_cast<unsigned long long>(generation),
            driver_bridge::current_remote_call_cancelled() ? 1 : 0,
            static_cast<unsigned long long>(driver_bridge::current_remote_call_deadline_ms()),
            driver_bridge::current_remote_call_diag_id());
        size_t signalled = 0;
        for (auto& sess : snapshot) {
            if (!sess)
                continue;
            sess->polling.store(false, std::memory_order_release);
            sess->poll_cv.notify_all();
            ++signalled;
            diag::log_tagged_fmt("pg_sniff", "signal_stop sid=%u pid=%u target=0x%llX",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr));
        }
        diag::log_tagged_fmt("pg_sniff",
            "signal_stop_all_done sessions=%zu signalled=%zu generation=%llu elapsed_ms=%llu",
            snapshot.size(),
            signalled,
            static_cast<unsigned long long>(generation),
            static_cast<unsigned long long>(GetTickCount64() - started));
        return signalled;
    }

    std::uint64_t current_install_stop_generation() const noexcept {
        return install_stop_generation_.load(std::memory_order_acquire);
    }


    struct session_info_t {
        uint32_t session_id;
        uint32_t pid;
        uint64_t target_addr;
        uint64_t region_size;
        size_t   pending_captures;
    };

    struct install_failure_info_t {
        std::string reason;
        std::string detail;
        std::string driver_status;
        std::string driver_last_error;
        std::string remote_call_driver_status;
        std::string remote_call_driver_last_error;
        std::string remote_call_lower_phase;
        std::string remote_call_lower_completion_reason;
        std::string remote_call_lower_worker_error_category;
        std::string remote_call_lower_worker_error_message;
        uint32_t pid = 0;
        uint32_t active_pid = 0;
        uint32_t win32_error = 0;
        uint32_t remote_call_gle = 0;
        uint32_t remote_call_lower_gle = 0;
        uint32_t remote_call_lower_worker_tid = 0;
        uint32_t remote_call_lower_worker_alive = 0;
        uint32_t remote_call_lower_queue_depth_at_submit = 0;
        uint32_t remote_call_lower_queue_depth_at_start = 0;
        uint32_t remote_call_lower_queue_depth_after_pop = 0;
        uint32_t remote_call_lower_inflight_at_submit = 0;
        uint32_t remote_call_lower_inflight_at_start = 0;
        uint32_t remote_call_lower_inflight_after = 0;
        int remote_call_lower_worker_error_value = 0;
        uint32_t remote_call_active_pid_entry = 0;
        uint32_t remote_call_active_pid_after = 0;
        uint32_t remote_call_timeout_ms = 0;
        uint32_t remote_call_completed = 0;
        uint32_t remote_call_ok = 0;
        uint32_t remote_call_cancelled_before = 0;
        uint32_t remote_call_cancelled_after = 0;
        uint32_t remote_call_deadline_expired_before = 0;
        uint32_t remote_call_deadline_expired_after = 0;
        uint32_t remote_call_stale_pid = 0;
        uint32_t remote_call_late_completion = 0;
        uint32_t remote_call_lower_completed = 0;
        uint32_t remote_call_lower_ok = 0;
        uint32_t remote_call_lower_stale_generation = 0;
        uint32_t remote_call_lower_cancelled = 0;
        uint32_t remote_call_lower_deadline_expired = 0;
        uint32_t remote_call_lower_lock_timeout = 0;
        uint32_t remote_call_lower_worker_exception = 0;
        uint32_t remote_call_lower_worker_creation_failed = 0;
        uint32_t remote_call_lower_late_completion = 0;
        uint32_t remote_call_allow_zero_result = 0;
        uint32_t remote_call_zero_result_rejected = 0;
        uint32_t remote_call_caller_abandoned = 0;
        uint32_t remote_call_removed_from_queue = 0;
        uint32_t remote_call_popped_from_queue = 0;
        uint32_t remote_call_execution_started = 0;
        uint32_t remote_call_executing_abandoned = 0;
        uint32_t remote_call_seh_exception = 0;
        uint32_t remote_call_seh_exception_code = 0;
        uint32_t quarantined = 0;
        uint32_t quarantine_cleanup_attempted = 0;
        uint32_t quarantine_veh_remove_attempted = 0;
        uint32_t quarantine_veh_remove_ok = 0;
        uint32_t quarantine_retained_shellcode = 0;
        uint32_t quarantine_retained_ring = 0;
        uint32_t region_state = 0;
        uint32_t region_protect = 0;
        uint32_t region_type = 0;
        uint32_t attempted_protect = 0;
        uint32_t original_protect = 0;
        uint32_t proposed_protect = 0;
        uint32_t cleanup_shellcode_ok = 0;
        uint32_t cleanup_ring_ok = 0;
        uint32_t mitigation_open_ok = 0;
        uint32_t mitigation_open_error = 0;
        uint32_t mitigation_dynamic_ok = 0;
        uint32_t mitigation_dynamic_error = 0;
        uint32_t mitigation_dynamic_flags = 0;
        uint32_t mitigation_cfg_ok = 0;
        uint32_t mitigation_cfg_error = 0;
        uint32_t mitigation_cfg_flags = 0;
        uint64_t requested_addr = 0;
        uint64_t requested_size = 0;
        uint64_t guard_addr = 0;
        uint64_t guard_size = 0;
        uint64_t region_base = 0;
        uint64_t region_size = 0;
        uint64_t ring_addr = 0;
        uint64_t shellcode_addr = 0;
        uint64_t context_addr = 0;
        uint64_t ntdll_base = 0;
        uint64_t ntdll_size = 0;
        uint64_t rtl_add_veh = 0;
        uint64_t rtl_remove_veh = 0;
        uint64_t veh_result = 0;
        uint64_t remote_call_id = 0;
        uint64_t remote_call_function = 0;
        uint64_t remote_call_result = 0;
        uint64_t remote_call_deadline_ms = 0;
        uint64_t remote_call_deadline_remaining_ms = 0;
        uint64_t remote_call_elapsed_ms = 0;
        uint64_t remote_call_lower_generation_at_entry = 0;
        uint64_t remote_call_lower_generation_after = 0;
        uint64_t remote_call_lower_queue_wait_ms = 0;
        uint64_t remote_call_lower_elapsed_ms = 0;
        uint64_t remote_call_lower_deadline_remaining_at_queue_ms = 0;
        uint64_t remote_call_lower_deadline_remaining_at_start_ms = 0;
        uint64_t remote_call_lower_deadline_remaining_at_finish_ms = 0;
        uint64_t remote_call_seh_exception_address = 0;
        uint64_t remote_call_seh_fault_address = 0;
        uint64_t remote_call_seh_rip = 0;
        uint64_t remote_call_seh_rsp = 0;
        uint64_t remote_call_seh_rbp = 0;
        uint64_t quarantine_id = 0;
        uint64_t install_elapsed_ms = 0;
        uint64_t install_generation = 0;
        uint64_t current_generation = 0;
    };

    std::vector<session_info_t> list_sessions() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        std::vector<session_info_t> out;
        for (auto& [sid, sess] : sessions_) {
            session_info_t si;
            si.session_id  = sid;
            si.pid         = sess->pid;
            si.target_addr = sess->target_addr;
            si.region_size = sess->region_size;
            {
                std::lock_guard<std::mutex> slk(sess->captures_mutex);
                si.pending_captures = sess->captures.size();
            }
            out.push_back(si);
        }
        return out;
    }

    install_failure_info_t last_install_failure() const {
        std::lock_guard<std::mutex> lk(failure_mutex_);
        return last_install_failure_;
    }


    static driver_bridge::module_info_t find_module_info(uint32_t pid, const char* name_lower) noexcept {
        auto modules = driver_bridge::enumerate_modules_for(pid);
        for (const auto& m : modules) {
            std::string lower_name = m.name;
            for (char& c : lower_name)
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            if (lower_name == name_lower)
                return m;
        }
        return {};
    }

    static uint64_t find_module_base(uint32_t pid, const char* name_lower) noexcept {
        return find_module_info(pid, name_lower).base;
    }

private:
    std::vector<std::shared_ptr<pg_session_t>> retired_sessions_;
    mutable std::mutex quarantine_mutex_;
    std::vector<install_quarantine_t> quarantines_;
    std::atomic<std::uint64_t> quarantine_sequence_{1};
    std::atomic<std::uint64_t> install_stop_generation_{0};

    void prune_install_quarantines(const char* phase) {
        std::vector<install_quarantine_t> retired;
        const ULONGLONG now = GetTickCount64();
        {
            std::lock_guard<std::mutex> lk(quarantine_mutex_);
            auto it = quarantines_.begin();
            while (it != quarantines_.end()) {
                bool retire = !it->active;
                uint32_t exit_code = 0;
                if (!retire && !it->reserved && it->pid != 0 && !active_pid_scope_t::pid_alive(it->pid, &exit_code))
                    retire = true;
                if (retire) {
                    retired.push_back(*it);
                    it = quarantines_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& quarantine : retired) {
            diag::log_tagged_fmt("pg_sniff",
                "install_quarantine_retired phase=%s pid=%u active_pid=%u quarantine_id=%llu call_id=%llu reserved=%d sc=0x%llX ring=0x%llX context=0x%llX wrapper=0x%llX diag=0x%llX rtl_add=0x%llX rtl_remove=0x%llX veh_result=0x%llX remote_gle=%lu age_ms=%llu",
                phase ? phase : "",
                quarantine.pid,
                quarantine.active_pid,
                static_cast<unsigned long long>(quarantine.quarantine_id),
                static_cast<unsigned long long>(quarantine.call_id),
                quarantine.reserved ? 1 : 0,
                static_cast<unsigned long long>(quarantine.shellcode_addr),
                static_cast<unsigned long long>(quarantine.ring_addr),
                static_cast<unsigned long long>(quarantine.context_addr),
                static_cast<unsigned long long>(quarantine.wrapper_addr),
                static_cast<unsigned long long>(quarantine.diag_addr),
                static_cast<unsigned long long>(quarantine.rtl_add_fn),
                static_cast<unsigned long long>(quarantine.rtl_remove_fn),
                static_cast<unsigned long long>(quarantine.veh_result),
                static_cast<unsigned long>(quarantine.remote_gle),
                static_cast<unsigned long long>(now >= quarantine.created_ms ? now - quarantine.created_ms : 0));
        }
    }

    bool find_active_quarantine(uint32_t pid, install_quarantine_t& out) {
        prune_install_quarantines("find_active");
        std::lock_guard<std::mutex> lk(quarantine_mutex_);
        for (const auto& quarantine : quarantines_) {
            if (quarantine.active && quarantine.pid == pid) {
                out = quarantine;
                return true;
            }
        }
        return false;
    }

    uint64_t reserve_install_quarantine_slot(uint32_t pid,
                                             uint32_t active_pid,
                                             uint64_t install_generation,
                                             ULONGLONG install_start) {
        prune_install_quarantines("reserve");
        install_quarantine_t reservation{};
        size_t active_count = 0;
        {
            std::lock_guard<std::mutex> lk(quarantine_mutex_);
            for (const auto& quarantine : quarantines_) {
                if (!quarantine.active)
                    continue;
                ++active_count;
                if (quarantine.pid == pid) {
                    diag::log_tagged_fmt("pg_sniff",
                        "install_quarantine_reserve_blocked reason=pid_already_quarantined pid=%u active_pid=%u existing_quarantine_id=%llu existing_reserved=%d active_count=%zu max_active=%zu generation=%llu elapsed_ms=%llu",
                        pid,
                        active_pid,
                        static_cast<unsigned long long>(quarantine.quarantine_id),
                        quarantine.reserved ? 1 : 0,
                        active_count,
                        INSTALL_QUARANTINE_MAX_ACTIVE,
                        static_cast<unsigned long long>(install_generation),
                        static_cast<unsigned long long>(GetTickCount64() - install_start));
                    return 0;
                }
            }
            if (active_count >= INSTALL_QUARANTINE_MAX_ACTIVE) {
                diag::log_tagged_fmt("pg_sniff",
                    "install_quarantine_reserve_blocked reason=capacity pid=%u active_pid=%u active_count=%zu max_active=%zu generation=%llu elapsed_ms=%llu",
                    pid,
                    active_pid,
                    active_count,
                    INSTALL_QUARANTINE_MAX_ACTIVE,
                    static_cast<unsigned long long>(install_generation),
                    static_cast<unsigned long long>(GetTickCount64() - install_start));
                return 0;
            }
            reservation.quarantine_id = quarantine_sequence_.fetch_add(1, std::memory_order_acq_rel);
            reservation.install_generation = install_generation;
            reservation.created_ms = GetTickCount64();
            reservation.pid = pid;
            reservation.active_pid = active_pid;
            reservation.active = true;
            reservation.reserved = true;
            quarantines_.push_back(reservation);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_quarantine_reserved pid=%u active_pid=%u quarantine_id=%llu active_count=%zu max_active=%zu generation=%llu elapsed_ms=%llu",
            pid,
            active_pid,
            static_cast<unsigned long long>(reservation.quarantine_id),
            active_count + 1,
            INSTALL_QUARANTINE_MAX_ACTIVE,
            static_cast<unsigned long long>(install_generation),
            static_cast<unsigned long long>(GetTickCount64() - install_start));
        return reservation.quarantine_id;
    }

    void release_install_quarantine_reservation(uint64_t quarantine_id, const char* reason) {
        if (quarantine_id == 0)
            return;
        install_quarantine_t released{};
        bool found = false;
        {
            std::lock_guard<std::mutex> lk(quarantine_mutex_);
            auto it = std::find_if(quarantines_.begin(), quarantines_.end(), [&](const install_quarantine_t& quarantine) {
                return quarantine.quarantine_id == quarantine_id && quarantine.reserved;
            });
            if (it != quarantines_.end()) {
                released = *it;
                quarantines_.erase(it);
                found = true;
            }
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_quarantine_reservation_release quarantine_id=%llu found=%d reason=%s pid=%u active_pid=%u generation=%llu age_ms=%llu",
            static_cast<unsigned long long>(quarantine_id),
            found ? 1 : 0,
            reason ? reason : "",
            released.pid,
            released.active_pid,
            static_cast<unsigned long long>(released.install_generation),
            static_cast<unsigned long long>(found && GetTickCount64() >= released.created_ms ? GetTickCount64() - released.created_ms : 0));
    }

    uint64_t add_install_quarantine(uint64_t reservation_id,
                                    uint32_t pid,
                                    uint32_t active_pid,
                                    uint64_t call_id,
                                    uint64_t shellcode_addr,
                                    uint64_t ring_addr,
                                    uint64_t context_addr,
                                    uint64_t wrapper_addr,
                                    uint64_t diag_addr,
                                    uint64_t rtl_add_fn,
                                    uint64_t rtl_remove_fn,
                                    uint64_t veh_result,
                                    uint32_t remote_gle,
                                    uint64_t install_generation) {
        prune_install_quarantines("commit");
        install_quarantine_t committed{};
        bool used_reservation = false;
        {
            std::lock_guard<std::mutex> lk(quarantine_mutex_);
            auto it = std::find_if(quarantines_.begin(), quarantines_.end(), [&](const install_quarantine_t& quarantine) {
                return quarantine.quarantine_id == reservation_id && quarantine.reserved;
            });
            if (it != quarantines_.end()) {
                committed = *it;
                used_reservation = true;
            } else {
                committed.quarantine_id = quarantine_sequence_.fetch_add(1, std::memory_order_acq_rel);
                committed.created_ms = GetTickCount64();
            }
            committed.call_id = call_id;
            committed.shellcode_addr = shellcode_addr;
            committed.ring_addr = ring_addr;
            committed.context_addr = context_addr;
            committed.wrapper_addr = wrapper_addr;
            committed.diag_addr = diag_addr;
            committed.rtl_add_fn = rtl_add_fn;
            committed.rtl_remove_fn = rtl_remove_fn;
            committed.veh_result = veh_result;
            committed.install_generation = install_generation;
            committed.pid = pid;
            committed.active_pid = active_pid;
            committed.remote_gle = remote_gle;
            committed.active = true;
            committed.reserved = false;
            if (used_reservation)
                *it = committed;
            else
                quarantines_.push_back(committed);
        }
        diag::log_tagged_fmt("pg_sniff",
            "install_quarantine_committed pid=%u active_pid=%u quarantine_id=%llu reservation_id=%llu used_reservation=%d call_id=%llu sc=0x%llX ring=0x%llX context=0x%llX wrapper=0x%llX diag=0x%llX rtl_add=0x%llX rtl_remove=0x%llX veh_result=0x%llX remote_gle=%lu generation=%llu",
            pid,
            active_pid,
            static_cast<unsigned long long>(committed.quarantine_id),
            static_cast<unsigned long long>(reservation_id),
            used_reservation ? 1 : 0,
            static_cast<unsigned long long>(call_id),
            static_cast<unsigned long long>(shellcode_addr),
            static_cast<unsigned long long>(ring_addr),
            static_cast<unsigned long long>(context_addr),
            static_cast<unsigned long long>(wrapper_addr),
            static_cast<unsigned long long>(diag_addr),
            static_cast<unsigned long long>(rtl_add_fn),
            static_cast<unsigned long long>(rtl_remove_fn),
            static_cast<unsigned long long>(veh_result),
            static_cast<unsigned long>(remote_gle),
            static_cast<unsigned long long>(install_generation));
        return committed.quarantine_id;
    }

    void clear_install_failure(uint32_t pid, uint64_t requested_addr, uint64_t requested_size) {
        std::lock_guard<std::mutex> lk(failure_mutex_);
        last_install_failure_ = {};
        last_install_failure_.pid = pid;
        last_install_failure_.requested_addr = requested_addr;
        last_install_failure_.requested_size = requested_size;
    }

    void record_install_failure(const char* reason,
                                const char* detail,
                                uint32_t pid,
                                uint64_t requested_addr,
                                uint64_t requested_size,
                                uint64_t guard_addr,
                                uint64_t guard_size,
                                const driver_bridge::memory_region_t* region,
                                uint32_t attempted_protect,
                                uint32_t win32_error) {
        std::lock_guard<std::mutex> lk(failure_mutex_);
        last_install_failure_.reason = reason ? reason : "";
        last_install_failure_.detail = detail ? detail : "";
        last_install_failure_.driver_status = driver_bridge::status();
        last_install_failure_.driver_last_error = driver_bridge::last_error();
        last_install_failure_.pid = pid;
        last_install_failure_.requested_addr = requested_addr;
        last_install_failure_.requested_size = requested_size;
        last_install_failure_.guard_addr = guard_addr;
        last_install_failure_.guard_size = guard_size;
        last_install_failure_.attempted_protect = attempted_protect;
        last_install_failure_.win32_error = win32_error;
        if (region) {
            last_install_failure_.region_base = region->base;
            last_install_failure_.region_size = region->size;
            last_install_failure_.region_state = region->state;
            last_install_failure_.region_protect = region->protect;
            last_install_failure_.region_type = region->type;
        }
    }

    void record_install_veh_failure_detail(uint32_t active_pid,
                                           uint64_t ring_addr,
                                           uint64_t shellcode_addr,
                                           uint64_t context_addr,
                                           uint64_t ntdll_base,
                                           uint64_t ntdll_size,
                                           uint64_t rtl_add_fn,
                                           uint64_t rtl_remove_fn,
                                           uint64_t veh_result,
                                           uint32_t remote_call_gle,
                                           uint64_t remote_call_elapsed_ms,
                                           uint32_t original_protect,
                                           uint32_t proposed_protect,
                                           uint32_t cleanup_shellcode_ok,
                                           uint32_t cleanup_ring_ok,
                                           uint64_t install_elapsed_ms,
                                           uint64_t install_generation,
                                           uint64_t current_generation,
                                           const process_mitigation_diag_t& mitigation,
                                           const remote_call_diag_snapshot_t& remote_diag,
                                           const std::string& remote_call_status,
                                           const std::string& remote_call_last_error) {
        std::lock_guard<std::mutex> lk(failure_mutex_);
        last_install_failure_.active_pid = active_pid;
        last_install_failure_.ring_addr = ring_addr;
        last_install_failure_.shellcode_addr = shellcode_addr;
        last_install_failure_.context_addr = context_addr;
        last_install_failure_.ntdll_base = ntdll_base;
        last_install_failure_.ntdll_size = ntdll_size;
        last_install_failure_.rtl_add_veh = rtl_add_fn;
        last_install_failure_.rtl_remove_veh = rtl_remove_fn;
        last_install_failure_.veh_result = veh_result;
        last_install_failure_.remote_call_gle = remote_call_gle;
        last_install_failure_.remote_call_id = remote_diag.call_id;
        last_install_failure_.remote_call_function = remote_diag.function_address;
        last_install_failure_.remote_call_result = remote_diag.result;
        last_install_failure_.remote_call_deadline_ms = remote_diag.deadline_ms;
        last_install_failure_.remote_call_deadline_remaining_ms = remote_diag.deadline_remaining_ms;
        last_install_failure_.remote_call_active_pid_entry = remote_diag.active_pid_entry;
        last_install_failure_.remote_call_active_pid_after = remote_diag.active_pid_after;
        last_install_failure_.remote_call_timeout_ms = remote_diag.timeout_ms;
        last_install_failure_.remote_call_completed = remote_diag.completed ? 1u : 0u;
        last_install_failure_.remote_call_ok = remote_diag.ok ? 1u : 0u;
        last_install_failure_.remote_call_cancelled_before = remote_diag.cancelled_before ? 1u : 0u;
        last_install_failure_.remote_call_cancelled_after = remote_diag.cancelled_after ? 1u : 0u;
        last_install_failure_.remote_call_deadline_expired_before = remote_diag.deadline_expired_before ? 1u : 0u;
        last_install_failure_.remote_call_deadline_expired_after = remote_diag.deadline_expired_after ? 1u : 0u;
        last_install_failure_.remote_call_stale_pid = remote_diag.stale_pid ? 1u : 0u;
        last_install_failure_.remote_call_late_completion = remote_diag.late_completion ? 1u : 0u;
        last_install_failure_.remote_call_elapsed_ms = remote_call_elapsed_ms;
        last_install_failure_.original_protect = original_protect;
        last_install_failure_.proposed_protect = proposed_protect;
        last_install_failure_.cleanup_shellcode_ok = cleanup_shellcode_ok;
        last_install_failure_.cleanup_ring_ok = cleanup_ring_ok;
        last_install_failure_.install_elapsed_ms = install_elapsed_ms;
        last_install_failure_.install_generation = install_generation;
        last_install_failure_.current_generation = current_generation;
        last_install_failure_.mitigation_open_ok = mitigation.open_ok ? 1u : 0u;
        last_install_failure_.mitigation_open_error = mitigation.open_error;
        last_install_failure_.mitigation_dynamic_ok = mitigation.dynamic_ok ? 1u : 0u;
        last_install_failure_.mitigation_dynamic_error = mitigation.dynamic_error;
        last_install_failure_.mitigation_dynamic_flags = mitigation.dynamic_flags;
        last_install_failure_.mitigation_cfg_ok = mitigation.cfg_ok ? 1u : 0u;
        last_install_failure_.mitigation_cfg_error = mitigation.cfg_error;
        last_install_failure_.mitigation_cfg_flags = mitigation.cfg_flags;
        last_install_failure_.remote_call_driver_status = remote_call_status;
        last_install_failure_.remote_call_driver_last_error = remote_call_last_error;
        last_install_failure_.remote_call_lower_phase = remote_diag.lower_phase;
        last_install_failure_.remote_call_lower_completion_reason = remote_diag.lower_completion_reason;
        last_install_failure_.remote_call_lower_worker_error_category = remote_diag.lower_worker_error_category;
        last_install_failure_.remote_call_lower_worker_error_message = remote_diag.lower_worker_error_message;
        last_install_failure_.remote_call_lower_gle = remote_diag.lower_gle;
        last_install_failure_.remote_call_lower_worker_tid = remote_diag.lower_worker_tid;
        last_install_failure_.remote_call_lower_worker_alive = remote_diag.lower_worker_alive;
        last_install_failure_.remote_call_lower_queue_depth_at_submit = remote_diag.lower_queue_depth_at_submit;
        last_install_failure_.remote_call_lower_queue_depth_at_start = remote_diag.lower_queue_depth_at_start;
        last_install_failure_.remote_call_lower_queue_depth_after_pop = remote_diag.lower_queue_depth_after_pop;
        last_install_failure_.remote_call_lower_inflight_at_submit = remote_diag.lower_inflight_at_submit;
        last_install_failure_.remote_call_lower_inflight_at_start = remote_diag.lower_inflight_at_start;
        last_install_failure_.remote_call_lower_inflight_after = remote_diag.lower_inflight_after;
        last_install_failure_.remote_call_lower_worker_error_value = remote_diag.lower_worker_error_value;
        last_install_failure_.remote_call_lower_completed = remote_diag.lower_completed ? 1u : 0u;
        last_install_failure_.remote_call_lower_ok = remote_diag.lower_ok ? 1u : 0u;
        last_install_failure_.remote_call_lower_stale_generation = remote_diag.lower_stale_generation ? 1u : 0u;
        last_install_failure_.remote_call_lower_cancelled = remote_diag.lower_cancelled ? 1u : 0u;
        last_install_failure_.remote_call_lower_deadline_expired = remote_diag.lower_deadline_expired ? 1u : 0u;
        last_install_failure_.remote_call_lower_lock_timeout = remote_diag.lower_lock_timeout ? 1u : 0u;
        last_install_failure_.remote_call_lower_worker_exception = remote_diag.lower_worker_exception ? 1u : 0u;
        last_install_failure_.remote_call_lower_worker_creation_failed = remote_diag.lower_worker_creation_failed ? 1u : 0u;
        last_install_failure_.remote_call_lower_late_completion = remote_diag.lower_late_completion ? 1u : 0u;
        last_install_failure_.remote_call_allow_zero_result = remote_diag.allow_zero_result ? 1u : 0u;
        last_install_failure_.remote_call_zero_result_rejected = remote_diag.zero_result_rejected ? 1u : 0u;
        last_install_failure_.remote_call_caller_abandoned = remote_diag.caller_abandoned ? 1u : 0u;
        last_install_failure_.remote_call_removed_from_queue = remote_diag.removed_from_queue ? 1u : 0u;
        last_install_failure_.remote_call_popped_from_queue = remote_diag.popped_from_queue ? 1u : 0u;
        last_install_failure_.remote_call_execution_started = remote_diag.execution_started ? 1u : 0u;
        last_install_failure_.remote_call_executing_abandoned = remote_diag.executing_abandoned ? 1u : 0u;
        last_install_failure_.remote_call_seh_exception = remote_diag.seh_exception ? 1u : 0u;
        last_install_failure_.remote_call_seh_exception_code = remote_diag.seh_exception_code;
        last_install_failure_.remote_call_lower_generation_at_entry = remote_diag.lower_generation_at_entry;
        last_install_failure_.remote_call_lower_generation_after = remote_diag.lower_generation_after;
        last_install_failure_.remote_call_lower_queue_wait_ms = remote_diag.lower_queue_wait_ms;
        last_install_failure_.remote_call_lower_elapsed_ms = remote_diag.lower_elapsed_ms;
        last_install_failure_.remote_call_lower_deadline_remaining_at_queue_ms = remote_diag.lower_deadline_remaining_at_queue_ms;
        last_install_failure_.remote_call_lower_deadline_remaining_at_start_ms = remote_diag.lower_deadline_remaining_at_start_ms;
        last_install_failure_.remote_call_lower_deadline_remaining_at_finish_ms = remote_diag.lower_deadline_remaining_at_finish_ms;
        last_install_failure_.remote_call_seh_exception_address = remote_diag.seh_exception_address;
        last_install_failure_.remote_call_seh_fault_address = remote_diag.seh_fault_address;
        last_install_failure_.remote_call_seh_rip = remote_diag.seh_rip;
        last_install_failure_.remote_call_seh_rsp = remote_diag.seh_rsp;
        last_install_failure_.remote_call_seh_rbp = remote_diag.seh_rbp;
        std::string lower_summary = "lower_phase=" + remote_diag.lower_phase +
            " lower_reason=" + remote_diag.lower_completion_reason +
            " lower_gle=" + std::to_string(remote_diag.lower_gle) +
            " lower_worker_tid=" + std::to_string(remote_diag.lower_worker_tid) +
            " lower_worker_alive=" + std::to_string(remote_diag.lower_worker_alive) +
            " lower_queue_depth=" + std::to_string(remote_diag.lower_queue_depth_at_submit) +
            " lower_inflight_after=" + std::to_string(remote_diag.lower_inflight_after) +
            " lower_queue_wait_ms=" + std::to_string(remote_diag.lower_queue_wait_ms) +
            " lower_elapsed_ms=" + std::to_string(remote_diag.lower_elapsed_ms) +
            " lower_worker_creation_failed=" + std::to_string(remote_diag.lower_worker_creation_failed ? 1 : 0) +
            " zero_result_rejected=" + std::to_string(remote_diag.zero_result_rejected ? 1 : 0) +
            " removed_from_queue=" + std::to_string(remote_diag.removed_from_queue ? 1 : 0) +
            " popped=" + std::to_string(remote_diag.popped_from_queue ? 1 : 0) +
            " execution_started=" + std::to_string(remote_diag.execution_started ? 1 : 0) +
            " executing_abandoned=" + std::to_string(remote_diag.executing_abandoned ? 1 : 0) +
            " seh_exception=" + std::to_string(remote_diag.seh_exception ? 1 : 0) +
            " seh_code=" + std::to_string(remote_diag.seh_exception_code);
        if (!remote_diag.lower_worker_error_message.empty())
            lower_summary += " lower_worker_error=" + remote_diag.lower_worker_error_message;
        if (!last_install_failure_.detail.empty())
            last_install_failure_.detail += " ";
        last_install_failure_.detail += lower_summary;
        if (!last_install_failure_.remote_call_driver_last_error.empty())
            last_install_failure_.remote_call_driver_last_error += " ";
        last_install_failure_.remote_call_driver_last_error += lower_summary;
    }

    static bool stop_session_poller(const std::shared_ptr<pg_session_t>& sess, DWORD timeout_ms, const char* reason) {
        if (!sess)
            return true;
        const ULONGLONG stop_start = GetTickCount64();
        sess->polling.store(false, std::memory_order_release);
        sess->poll_cv.notify_all();
        bool poller_exited = sess->exited.load(std::memory_order_acquire);
        while (!poller_exited && GetTickCount64() - stop_start < timeout_ms) {
            std::unique_lock<std::mutex> lk(sess->poll_wait_mutex);
            sess->poll_cv.wait_for(lk, std::chrono::milliseconds(5), [&sess]() {
                return sess->exited.load(std::memory_order_acquire);
            });
            poller_exited = sess->exited.load(std::memory_order_acquire);
        }
        size_t queued = 0;
        {
            std::lock_guard<std::mutex> slk(sess->captures_mutex);
            queued = sess->captures.size();
        }
        diag::log_tagged_fmt("pg_sniff", "poller_stop reason=%s sid=%u pid=%u exited=%d auto_poll=%d polling=%d queued=%zu elapsed_ms=%llu",
            reason ? reason : "unknown",
            sess->session_id,
            sess->pid,
            poller_exited ? 1 : 0,
            sess->auto_poll.load(std::memory_order_acquire) ? 1 : 0,
            sess->polling.load(std::memory_order_acquire) ? 1 : 0,
            queued,
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
        return poller_exited;
    }

    static void poll_ring(std::shared_ptr<pg_session_t> sess) {
        if (!sess)
            return;
        while (sess->polling.load(std::memory_order_acquire)) {
            if (driver_bridge::using_kernel_driver()) {
                drain_ring(sess.get());
            }

            if (sess->polling.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lk(sess->poll_wait_mutex);
                sess->poll_cv.wait_for(lk, std::chrono::milliseconds(50), [&sess]() {
                    return !sess->polling.load(std::memory_order_acquire);
                });
            }
        }
        sess->exited.store(true, std::memory_order_release);
        sess->poll_cv.notify_all();
        diag::log_tagged_fmt("pg_sniff", "poller_exit sid=%u pid=%u ring=0x%llX sc=0x%llX",
            sess->session_id,
            sess->pid,
            static_cast<unsigned long long>(sess->ring_addr),
            static_cast<unsigned long long>(sess->sc_addr));
    }

    static void drain_ring(pg_session_t* sess) {
        const ULONGLONG t0 = GetTickCount64();
        std::unique_lock<std::mutex> drain_lk(sess->drain_mutex, std::try_to_lock);
        if (!drain_lk.owns_lock()) {
            size_t queued = 0;
            {
                std::lock_guard<std::mutex> slk(sess->captures_mutex);
                queued = sess->captures.size();
            }
            diag::log_tagged_fmt("pg_sniff", "drain_skip_busy sid=%u pid=%u ring=0x%llX queued=%zu drain_active=%d auto_poll=%d polling=%d total=%llu elapsed_ms=%llu",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->ring_addr),
                queued,
                sess->drain_active.load(std::memory_order_acquire) ? 1 : 0,
                sess->auto_poll.load(std::memory_order_acquire) ? 1 : 0,
                sess->polling.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long long>(sess->total_captured),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return;
        }
        struct drain_activity_scope_t {
            pg_session_t* sess;
            explicit drain_activity_scope_t(pg_session_t* s) : sess(s) {
                if (sess)
                    sess->drain_active.store(true, std::memory_order_release);
            }
            ~drain_activity_scope_t() {
                if (sess)
                    sess->drain_active.store(false, std::memory_order_release);
            }
        } drain_scope(sess);

        active_pid_scope_t active;
        if (!active.enter(sess->pid)) {
            diag::log_tagged_fmt("pg_sniff", "drain_active_pid_failed sid=%u pid=%u active_pid=%u status=%s last_error=%s elapsed_ms=%llu",
                sess->session_id,
                sess->pid,
                driver_bridge::attached_pid(),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long long>(GetTickCount64() - t0));
            return;
        }
        if (!kernel_operation_ready(sess->pid, "drain", "page_guard_drain", t0))
            return;

        pg_ring_header_t hdr{};
        std::vector<uint8_t> hdr_buf;
        if (!driver_bridge::read_memory_for(sess->pid, sess->ring_addr, sizeof(hdr), hdr_buf) || hdr_buf.size() < sizeof(hdr)) {
            ++sess->header_read_failures;
            if (sess->header_read_failures <= 4 || (sess->header_read_failures % 20) == 0) {
                std::string err = driver_bridge::last_error();
                if (err.empty())
                    err = std::string("empty_last_error status=") + driver_bridge::status() + " gle=" + std::to_string(GetLastError());
                diag::log_tagged_fmt("pg_sniff", "drain_header_read_failed sid=%u pid=%u ring=0x%llX failures=%llu read=%zu last_error=%s",
                    sess->session_id,
                    sess->pid,
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(sess->header_read_failures),
                    hdr_buf.size(),
                    err.c_str());
            }
            return;
        }
        std::memcpy(&hdr, hdr_buf.data(), sizeof(hdr));

        uint32_t raw_w = hdr.write_idx;
        uint32_t raw_r = hdr.read_idx;
        uint32_t w = raw_w & (RING_ENTRIES - 1);
        uint32_t r = raw_r & (RING_ENTRIES - 1);

        sess->prev_raw_write_idx = raw_w;
        sess->ring_initialized = true;
        sess->prev_write_idx = w;

        uint64_t drained = 0;
        uint64_t entry_failures = 0;
        uint32_t initial_r = r;
        const bool capture_payloads = sess->capture_payloads.load(std::memory_order_acquire);
        const uint32_t max_records = sess->max_records_per_drain.load(std::memory_order_acquire);
        uint32_t available = (w + RING_ENTRIES - r) & (RING_ENTRIES - 1);
        uint32_t to_drain = available;
        if (max_records != 0 && to_drain > max_records)
            to_drain = max_records;

        auto push_entry = [&](const pg_capture_t& entry) {
            pg_capture_record_t record;
            if (capture_payloads) {
                const size_t budget = sess->payload_budget.load(std::memory_order_acquire);
                const bool unlimited = budget == static_cast<size_t>(-1);
                const bool include_payload = unlimited || sess->payload_reads.load(std::memory_order_acquire) < budget;
                record = build_capture_record(sess, entry, include_payload);
                if (!include_payload && sess->payload_reads.load(std::memory_order_relaxed) == budget) {
                    diag::log_tagged_fmt("pg_sniff", "payload_budget_exhausted sid=%u budget=%zu total=%llu",
                        sess->session_id,
                        budget,
                        static_cast<unsigned long long>(sess->total_captured));
                }
                if (!unlimited && record.payload_read)
                    sess->payload_reads.fetch_add(1, std::memory_order_acq_rel);
            } else {
                record.metadata = entry;
                record.payload_source = "metadata_only";
            }
            std::lock_guard<std::mutex> lk(sess->captures_mutex);
            sess->captures.push(std::move(record));
        };

        auto drain_segment = [&](uint32_t start_index, uint32_t count) {
            if (count == 0)
                return;
            const uint64_t entry_addr = sess->ring_addr + sizeof(pg_ring_header_t)
                                      + static_cast<uint64_t>(start_index) * sizeof(pg_capture_t);
            std::vector<uint8_t> segment_buf;
            const size_t byte_count = static_cast<size_t>(count) * sizeof(pg_capture_t);
            if (driver_bridge::read_memory_for(sess->pid, entry_addr, byte_count, segment_buf) &&
                segment_buf.size() >= byte_count) {
                for (uint32_t i = 0; i < count; ++i) {
                    pg_capture_t entry{};
                    std::memcpy(&entry, segment_buf.data() + static_cast<size_t>(i) * sizeof(pg_capture_t), sizeof(entry));
                    push_entry(entry);
                }
                drained += count;
                return;
            }

            for (uint32_t i = 0; i < count; ++i) {
                pg_capture_t entry{};
                const uint64_t single_addr = sess->ring_addr + sizeof(pg_ring_header_t)
                                           + static_cast<uint64_t>(start_index + i) * sizeof(pg_capture_t);
                std::vector<uint8_t> entry_buf;
                if (driver_bridge::read_memory_for(sess->pid, single_addr, sizeof(entry), entry_buf) &&
                    entry_buf.size() >= sizeof(entry)) {
                    std::memcpy(&entry, entry_buf.data(), sizeof(entry));
                    push_entry(entry);
                } else {
                    ++entry_failures;
                    ++sess->entry_read_failures;
                }
                ++drained;
            }
        };

        const uint32_t first_count = std::min<uint32_t>(to_drain, RING_ENTRIES - r);
        const uint32_t second_count = to_drain - first_count;
        drain_segment(r, first_count);
        if (second_count != 0)
            drain_segment(0, second_count);
        r = (initial_r + static_cast<uint32_t>(drained)) & (RING_ENTRIES - 1);
        sess->total_captured += drained;
        if (drained > 0 || entry_failures > 0) {
            diag::log_tagged_fmt("pg_sniff", "drain sid=%u pid=%u raw_w=%u raw_r=%u w=%u r0=%u r1=%u available=%u requested=%u drained=%llu entry_failures=%llu total=%llu drops=%llu rearm=%llu/%llu payloads=%d max_drain=%u elapsed_ms=%llu",
                sess->session_id,
                sess->pid,
                raw_w,
                raw_r,
                w,
                initial_r,
                r,
                available,
                to_drain,
                static_cast<unsigned long long>(drained),
                static_cast<unsigned long long>(entry_failures),
                static_cast<unsigned long long>(sess->total_captured),
                static_cast<unsigned long long>(sess->estimated_drops),
                static_cast<unsigned long long>(sess->rearm_attempts),
                static_cast<unsigned long long>(sess->rearm_failures),
                capture_payloads ? 1 : 0,
                max_records,
                static_cast<unsigned long long>(GetTickCount64() - t0));
        }

        if (drained > 0 || r != initial_r) {

            uint32_t new_r = r;
            std::vector<uint8_t> r_buf(sizeof(new_r));
            std::memcpy(r_buf.data(), &new_r, sizeof(new_r));
            driver_bridge::write_memory_for(sess->pid, sess->ring_addr + offsetof(pg_ring_header_t, read_idx), r_buf);
        }
    }

    static bool readable_protect(uint32_t protect) noexcept {
        const uint32_t base = protect & 0xFFu;
        return base != PAGE_NOACCESS;
    }

    static uint64_t region_remaining(const pg_session_t* sess, uint64_t address) noexcept {
        if (!address_in_range(sess->target_addr, sess->region_size, address))
            return 0;
        return sess->region_size - (address - sess->target_addr);
    }

    static uint64_t choose_payload_address(const pg_session_t* sess, const pg_capture_t& entry, std::string& source) {
        struct candidate_t {
            uint64_t address;
            const char* source;
        };
        const candidate_t candidates[] = {
            {entry.fault_addr, "fault_addr"},
            {entry.ctx_rdx, "rdx"},
            {entry.ctx_rcx, "rcx"},
            {entry.ctx_rax, "rax"},
            {sess->target_addr, "region_base"}
        };
        for (const auto& c : candidates) {
            if (address_in_range(sess->target_addr, sess->region_size, c.address)) {
                source = c.source;
                return c.address;
            }
        }
        source = "unavailable";
        return 0;
    }

    static void rearm_guard(pg_session_t* sess) {
        if (!sess->polling.load(std::memory_order_acquire) ||
            sess->teardown_requested.load(std::memory_order_acquire))
            return;
        const ULONGLONG t0 = GetTickCount64();
        if (!kernel_operation_ready(sess->pid, "rearm", "page_guard_rearm", t0))
            return;
        ++sess->rearm_attempts;
        uint32_t old_protect = 0;
        const bool ok = driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                                          sess->orig_protect | PAGE_GUARD, &old_protect);
        if (!ok) {
            ++sess->rearm_failures;
            diag::log_tagged_fmt("pg_sniff", "rearm_failed sid=%u pid=%u target=0x%llX size=0x%llX orig=0x%08X attempt=%llu failures=%llu last_error=%s",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr),
                static_cast<unsigned long long>(sess->region_size),
                sess->orig_protect,
                static_cast<unsigned long long>(sess->rearm_attempts),
                static_cast<unsigned long long>(sess->rearm_failures),
                driver_bridge::last_error().c_str());
        } else if (sess->rearm_attempts <= 3 || (sess->rearm_attempts % 16) == 0) {
            diag::log_tagged_fmt("pg_sniff", "rearm_ok sid=%u pid=%u target=0x%llX size=0x%llX old=0x%08X attempt=%llu",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr),
                static_cast<unsigned long long>(sess->region_size),
                old_protect,
                static_cast<unsigned long long>(sess->rearm_attempts));
        }
    }

    static pg_capture_record_t build_capture_record(pg_session_t* sess, const pg_capture_t& entry, bool include_payload = true) {
        pg_capture_record_t record;
        record.metadata = entry;
        record.payload_addr = choose_payload_address(sess, entry, record.payload_source);
        const ULONGLONG t0 = GetTickCount64();
        if (!kernel_operation_ready(sess ? sess->pid : 0, "payload", "page_guard_payload", t0))
            return record;
        if (record.payload_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "payload_addr_unavailable sid=%u fault=0x%llX rip=0x%llX access=%u source=%s",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(entry.fault_addr),
                static_cast<unsigned long long>(entry.rip),
                entry.access_type,
                record.payload_source.c_str());
            return record;
        }
        record.payload_offset = record.payload_addr - sess->target_addr;
        if (!include_payload) {
            diag::log_tagged_fmt("pg_sniff", "payload_skipped sid=%u addr=0x%llX source=%s reason=budget",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(record.payload_addr),
                record.payload_source.c_str());
            return record;
        }

        const uint64_t available = region_remaining(sess, record.payload_addr);
        if (available == 0) {
            diag::log_tagged_fmt("pg_sniff", "payload_region_empty sid=%u addr=0x%llX target=0x%llX size=0x%llX source=%s",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(sess ? sess->target_addr : 0),
                static_cast<unsigned long long>(sess ? sess->region_size : 0),
                record.payload_source.c_str());
            return record;
        }

        const size_t requested = static_cast<size_t>(std::min<uint64_t>(available, PAYLOAD_PREVIEW_MAX));
        driver_bridge::memory_region_t mri{};
        if (!driver_bridge::query_memory_for(sess->pid, record.payload_addr, mri) || !readable_protect(mri.protect)) {
            diag::log_tagged_fmt("pg_sniff", "payload_query_failed sid=%u pid=%u addr=0x%llX query_base=0x%llX query_size=0x%llX protect=0x%08X state=0x%08X source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(mri.base),
                static_cast<unsigned long long>(mri.size),
                mri.protect,
                mri.state,
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            return record;
        }

        std::vector<uint8_t> bytes;
        bool ok = driver_bridge::read_memory_for(sess->pid, record.payload_addr, requested, bytes);
        if (!ok || bytes.empty()) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_retry sid=%u pid=%u addr=0x%llX requested=%zu ok=%d bytes=%zu source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                requested,
                ok ? 1 : 0,
                bytes.size(),
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                              sess->orig_protect, nullptr);
            ok = driver_bridge::read_memory_for(sess->pid, record.payload_addr, requested, bytes);
        }
        rearm_guard(sess);

        if (!ok || bytes.empty()) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_failed sid=%u pid=%u addr=0x%llX requested=%zu ok=%d bytes=%zu source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                requested,
                ok ? 1 : 0,
                bytes.size(),
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            return record;
        }
        if (bytes.size() > requested)
            bytes.resize(requested);

        record.payload = std::move(bytes);
        record.payload_read = true;
        record.payload_size = static_cast<uint32_t>(record.payload.size());
        record.payload_truncated = available > record.payload.size();
        if (sess && sess->payload_reads.load(std::memory_order_relaxed) < 16) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_ok sid=%u pid=%u addr=0x%llX offset=0x%llX bytes=%u truncated=%d source=%s",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(record.payload_offset),
                record.payload_size,
                record.payload_truncated ? 1 : 0,
                record.payload_source.c_str());
        }
        return record;
    }

    std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<pg_session_t>> sessions_;
    mutable std::mutex failure_mutex_;
    install_failure_info_t last_install_failure_;
    uint32_t next_id_ = 1;
};

inline pg_engine_t g_pg_engine;

}
