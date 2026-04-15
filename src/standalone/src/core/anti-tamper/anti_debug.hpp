#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#include <cstdint>
#include <string>

#include "webhook.hpp"
#include "syscall.hpp"
#include "../standalone_driver.hpp"

namespace anti_tamper {
namespace anti_debug {

struct debug_report_t
{
    bool peb_being_debugged = false;
    bool peb_nt_global_flag = false;
    bool peb_heap_flags = false;
    bool debug_port = false;
    bool debug_object_handle = false;
    bool debug_flags = false;
    bool remote_debugger = false;
    bool is_debugger_present = false;
    bool close_handle_trap = false;
    bool output_debug_string = false;
    bool hw_breakpoints_local = false;
    bool hw_breakpoints_kernel = false;
    bool kernel_debugger = false;
    bool kd_shared_data = false;
    bool rdtsc_timing = false;
    bool qpc_timing = false;
    bool thread_hidden = false;
    bool instrumentation_callback = false;
    std::string summary;

    bool any_detected() const
    {
        return peb_being_debugged || peb_nt_global_flag || peb_heap_flags
            || debug_port || debug_object_handle || debug_flags
            || remote_debugger || is_debugger_present || close_handle_trap
            || output_debug_string || hw_breakpoints_local || hw_breakpoints_kernel
            || kernel_debugger || kd_shared_data || thread_hidden
            || instrumentation_callback;
    }
};

inline bool check_being_debugged()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    return *(peb + 0x02) != 0;
}

inline bool check_nt_global_flag()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    const uint32_t nt_global = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    return (nt_global & 0x70u) != 0;
}

inline bool check_heap_flags()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;

    const uint64_t process_heap = *reinterpret_cast<const uint64_t*>(peb + 0x30);
    if (process_heap == 0) return false;

    const auto* heap = reinterpret_cast<const uint8_t*>(process_heap);
    const uint32_t flags = *reinterpret_cast<const uint32_t*>(heap + 0x70);
    const uint32_t force_flags = *reinterpret_cast<const uint32_t*>(heap + 0x74);

    if (force_flags != 0) return true;
    if ((flags & ~0x02u) != 0) return true;

    return false;
}

inline bool check_debug_port()
{
    if (!syscall::is_initialized()) return false;

    ULONG_PTR debug_port = 0;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
    return st >= 0 && debug_port != 0;
}

inline bool check_debug_object_handle()
{
    if (!syscall::is_initialized()) return false;

    HANDLE debug_obj = nullptr;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 0x1E, &debug_obj, sizeof(debug_obj), nullptr);
    if (st >= 0 && debug_obj != nullptr)
    {
        syscall::NtClose()(debug_obj);
        return true;
    }
    return false;
}

inline bool check_debug_flags()
{
    if (!syscall::is_initialized()) return false;

    ULONG debug_flags = 0;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 0x1F, &debug_flags, sizeof(debug_flags), nullptr);
    return st >= 0 && debug_flags == 0;
}

inline bool check_remote_debugger()
{
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present)
        return true;
    return false;
}

inline bool check_is_debugger_present()
{
    return IsDebuggerPresent() != FALSE;
}

inline bool check_close_handle_trap()
{
    if (!syscall::is_initialized()) return false;

    __try
    {
        syscall::NtClose()(reinterpret_cast<HANDLE>(0xDEADBEEFull));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
    return false;
}

inline bool check_output_debug_string()
{
    SetLastError(0xDEAD);
    OutputDebugStringW(L"AT_PROBE");
    return GetLastError() != 0xDEAD;
}

inline bool check_hw_breakpoints_local()
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
    {
        uint64_t dr7 = ctx.Dr7;
        for (int i = 0; i < 4; ++i)
        {
            bool local = (dr7 >> (i * 2)) & 1;
            bool global = (dr7 >> (i * 2 + 1)) & 1;
            if (local || global) return true;
        }
    }
    return false;
}

inline bool check_hw_breakpoints_kernel(uint64_t mod_base, uint64_t mod_end)
{
    if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
        return false;

    auto threads = driver_bridge::enumerate_threads();
    for (const auto& t : threads)
    {
        driver_bridge::thread_context_t ctx{};
        if (!driver_bridge::get_thread_context(t.tid, ctx))
            continue;

        const uint64_t dr_values[] = { ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3 };
        const uint64_t dr7 = ctx.dr7;

        for (int i = 0; i < 4; ++i)
        {
            if (dr_values[i] == 0) continue;

            const bool enabled_local  = (dr7 >> (i * 2))     & 1;
            const bool enabled_global = (dr7 >> (i * 2 + 1)) & 1;
            if (!enabled_local && !enabled_global) continue;

            if (dr_values[i] >= mod_base && dr_values[i] < mod_end)
                return true;
        }
    }
    return false;
}

inline bool check_kernel_debugger()
{
    if (!syscall::is_initialized()) return false;

    struct { BOOLEAN KernelDebuggerEnabled; BOOLEAN KernelDebuggerNotPresent; } kd_info{};
    NTSTATUS st = syscall::NtQuerySystemInformation()(
        0x23, &kd_info, sizeof(kd_info), nullptr);
    return st >= 0 && kd_info.KernelDebuggerEnabled && !kd_info.KernelDebuggerNotPresent;
}

inline bool check_kd_shared_data()
{
    const auto* kuser = reinterpret_cast<const uint8_t*>(0x7FFE0000ULL);
    __try
    {
        uint8_t kd_enabled = *(kuser + 0x2D4);
        return kd_enabled != 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

inline bool check_rdtsc_timing()
{
    volatile uint64_t t0 = __rdtsc();

    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 100; ++i)
        acc += i * i;

    volatile uint64_t t1 = __rdtsc();
    return (t1 - t0) > 10000000ULL;
}

inline bool check_qpc_timing()
{
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 100; ++i)
        acc += i * i;

    QueryPerformanceCounter(&t1);

    double elapsed_us = static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000000.0 / freq.QuadPart;
    return elapsed_us > 50000.0;
}

inline bool check_thread_hidden()
{
    if (!syscall::is_initialized()) return false;

    ULONG hidden = 0;
    NTSTATUS st = syscall::NtQueryInformationThread()(
        GetCurrentThread(), 0x11, &hidden, sizeof(hidden), nullptr);
    return st >= 0 && hidden != 0;
}

inline bool check_instrumentation_callback()
{
    if (!syscall::is_initialized()) return false;

    struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
    {
        ULONG Version;
        ULONG Reserved;
        PVOID Callback;
    } info{};

    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 40, &info, sizeof(info), nullptr);
    return st >= 0 && info.Callback != nullptr;
}

inline void hide_thread_from_debugger(HANDLE thread)
{
    if (!syscall::is_initialized()) return;
    syscall::NtSetInformationThread()(thread, 0x11, nullptr, 0);
}

inline debug_report_t full_scan(uint64_t mod_base = 0, uint64_t mod_end = 0)
{
    debug_report_t report{};

    report.peb_being_debugged = check_being_debugged();
    if (report.peb_being_debugged)
        webhook::send_debug_log("peb_being_debugged", "BeingDebugged=1", true);

    report.peb_nt_global_flag = check_nt_global_flag();
    if (report.peb_nt_global_flag)
        webhook::send_debug_log("peb_nt_global_flag", "NtGlobalFlag&0x70", true);

    report.peb_heap_flags = check_heap_flags();
    if (report.peb_heap_flags)
        webhook::send_debug_log("peb_heap_flags", "ForceFlags!=0", true);

    report.debug_port = check_debug_port();
    if (report.debug_port)
        webhook::send_debug_log("debug_port", "ProcessDebugPort!=0", true);

    report.debug_object_handle = check_debug_object_handle();
    if (report.debug_object_handle)
        webhook::send_debug_log("debug_object", "DebugObjectHandle!=NULL", true);

    report.debug_flags = check_debug_flags();
    if (report.debug_flags)
        webhook::send_debug_log("debug_flags", "ProcessDebugFlags==0", true);

    report.remote_debugger = check_remote_debugger();
    if (report.remote_debugger)
        webhook::send_debug_log("remote_debugger", "CheckRemoteDebugger=TRUE", true);

    report.is_debugger_present = check_is_debugger_present();
    if (report.is_debugger_present)
        webhook::send_debug_log("is_debugger_present", "IsDebuggerPresent=TRUE", true);

    report.close_handle_trap = check_close_handle_trap();
    if (report.close_handle_trap)
        webhook::send_debug_log("close_handle_trap", "STATUS_INVALID_HANDLE", true);

    report.output_debug_string = check_output_debug_string();
    if (report.output_debug_string)
        webhook::send_debug_log("output_debug_string", "GetLastError_changed", true);

    report.hw_breakpoints_local = check_hw_breakpoints_local();
    if (report.hw_breakpoints_local)
        webhook::send_debug_log("hw_bp_local", "DR_active_local", true);

    if (mod_base != 0 && mod_end != 0)
    {
        report.hw_breakpoints_kernel = check_hw_breakpoints_kernel(mod_base, mod_end);
        if (report.hw_breakpoints_kernel)
            webhook::send_debug_log("hw_bp_kernel", "DR_in_code_range", true);
    }

    report.kernel_debugger = check_kernel_debugger();
    if (report.kernel_debugger)
        webhook::send_debug_log("kernel_debugger", "KdEnabled", true);

    report.kd_shared_data = check_kd_shared_data();
    if (report.kd_shared_data)
        webhook::send_debug_log("kd_shared_data", "KUSER_SharedData.KdDebuggerEnabled", true);

    report.thread_hidden = check_thread_hidden();
    if (report.thread_hidden)
        webhook::send_debug_log("thread_hidden", "ThreadHideFromDebugger_set", true);

    report.instrumentation_callback = check_instrumentation_callback();
    if (report.instrumentation_callback)
        webhook::send_debug_log("instrumentation_cb", "InstrumentationCallback!=NULL", true);

    if (report.peb_being_debugged) report.summary += "peb ";
    if (report.peb_nt_global_flag) report.summary += "ntglobal ";
    if (report.peb_heap_flags) report.summary += "heap ";
    if (report.debug_port) report.summary += "port ";
    if (report.debug_object_handle) report.summary += "dbgobj ";
    if (report.debug_flags) report.summary += "flags ";
    if (report.remote_debugger) report.summary += "remote ";
    if (report.is_debugger_present) report.summary += "isdbg ";
    if (report.close_handle_trap) report.summary += "closeh ";
    if (report.output_debug_string) report.summary += "outdbg ";
    if (report.hw_breakpoints_local) report.summary += "hwbp_l ";
    if (report.hw_breakpoints_kernel) report.summary += "hwbp_k ";
    if (report.kernel_debugger) report.summary += "kd ";
    if (report.kd_shared_data) report.summary += "kuser ";
    if (report.rdtsc_timing) report.summary += "rdtsc ";
    if (report.qpc_timing) report.summary += "qpc ";
    if (report.thread_hidden) report.summary += "thidden ";
    if (report.instrumentation_callback) report.summary += "instcb ";

    return report;
}

}
}
