#pragma once

#include <windows.h>
#include "work_queue.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "standalone_settings.hpp"
#include "toast_notification.hpp"
#include "standalone_anti_dump.hpp"
#include "anti-tamper/virtualizer.hpp"
#include "anti-tamper/vm_compiler.hpp"
#include "standalone_anti_ai.hpp"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "obfuscation.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

#include "anti-tamper/webhook.hpp"

namespace standalone_anti_tamper
{

namespace webhook
{
    inline void send_debug_log(const std::string& check_name, const std::string& detail, bool violation)
    {
        anti_tamper::webhook::send_debug_log(check_name.c_str(), detail, violation);
    }
    inline void send_violation_alert(const std::string& reason, const std::string& extra_detail = "")
    {
        anti_tamper::webhook::send_violation_alert(reason.c_str(), extra_detail);
    }
}

namespace detect
{

    inline bool check_peb_debug_flags()
    {
        const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
        if (!peb) return false;

        if (*(peb + 0x02) != 0) return true;

        const uint32_t nt_global = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
        if ((nt_global & 0x70u) != 0) return true;

        return false;
    }

    inline bool check_debug_port()
    {
        using NtQueryInfoProc_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pNtQuery = reinterpret_cast<NtQueryInfoProc_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!pNtQuery) return false;

        ULONG_PTR debug_port = 0;
        NTSTATUS st = pNtQuery(GetCurrentProcess(), 7, &debug_port,
            sizeof(debug_port), nullptr);
        if (st >= 0 && debug_port != 0) return true;

        HANDLE debug_obj = nullptr;
        st = pNtQuery(GetCurrentProcess(), 0x1E, &debug_obj,
            sizeof(debug_obj), nullptr);
        if (st >= 0 && debug_obj != nullptr)
        {
            CloseHandle(debug_obj);
            return true;
        }

        return false;
    }

    inline bool check_remote_debugger()
    {
        BOOL present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present)
            return true;
        if (IsDebuggerPresent())
            return true;
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

    inline bool check_timing_anomaly()
    {
        volatile uint64_t t0 = __rdtsc();

        volatile uint64_t acc = 0;
        for (volatile int i = 0; i < 100; ++i)
            acc += i * i;

        volatile uint64_t t1 = __rdtsc();
        uint64_t delta = t1 - t0;

        return delta > 10000000ULL;
    }

    inline bool check_kernel_debugger()
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION kd_info{};
        using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto pQuery = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        if (!pQuery) return false;

        NTSTATUS st = pQuery(0x23, &kd_info, sizeof(kd_info), nullptr);
        if (st >= 0 && kd_info.KernelDebuggerEnabled && !kd_info.KernelDebuggerNotPresent)
            return true;

        return false;
    }

    inline bool check_thread_hiding()
    {
        using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pQuery = reinterpret_cast<NtQueryInformationThread_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        if (!pQuery) return false;

        ULONG hidden = 0;
        NTSTATUS st = pQuery(GetCurrentThread(), 0x11, &hidden, sizeof(hidden), nullptr);
        if (st >= 0 && hidden != 0)
            return true;

        return false;
    }

}


namespace integrity
{

    __forceinline uint64_t hash_memory(const void* data, size_t size)
    {
        const auto* ptr = static_cast<const uint8_t*>(data);
        uint64_t h1 = 0xFFFFFFFFULL;
        uint64_t h2 = 0x85EBCA6BULL;

        const size_t chunks = size / 8;
        const auto* ptr64 = reinterpret_cast<const uint64_t*>(ptr);

        for (size_t i = 0; i < chunks; ++i)
        {
            h1 = _mm_crc32_u64(h1, ptr64[i]);
            h2 = _mm_crc32_u64(h2, ptr64[i] ^ 0xA5A5A5A5A5A5A5A5ULL);
        }

        const size_t remaining = size % 8;
        const auto* tail = ptr + chunks * 8;
        for (size_t i = 0; i < remaining; ++i)
        {
            h1 = _mm_crc32_u8(static_cast<uint32_t>(h1), tail[i]);
            h2 = _mm_crc32_u8(static_cast<uint32_t>(h2), tail[i] ^ 0xA5u);
        }

        return (h1 & 0xFFFFFFFF) | ((h2 & 0xFFFFFFFF) << 32);
    }

    struct code_snapshot_t
    {
        uint64_t text_base = 0;
        uint32_t text_size = 0;
        uint64_t text_hash = 0;
        uint64_t module_base = 0;
        uint64_t module_end = 0;
    };

    inline bool snapshot_code(code_snapshot_t& snap)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0
                && sec[i].Misc.VirtualSize > 0)
            {
                snap.text_base = reinterpret_cast<uint64_t>(mod) + sec[i].VirtualAddress;
                snap.text_size = sec[i].Misc.VirtualSize;
                snap.text_hash = hash_memory(
                    reinterpret_cast<const void*>(snap.text_base), snap.text_size);
                break;
            }
        }

        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        {
            snap.module_base = reinterpret_cast<uint64_t>(mod);
            snap.module_end = snap.module_base + mi.SizeOfImage;
        }

        return snap.text_hash != 0;
    }

    inline bool verify_usermode(const code_snapshot_t& snap)
    {
        if (snap.text_base == 0 || snap.text_size == 0 || snap.text_hash == 0)
            return true;

        uint64_t current = hash_memory(
            reinterpret_cast<const void*>(snap.text_base), snap.text_size);
        return current == snap.text_hash;
    }

    inline bool verify_page_protections(const code_snapshot_t& snap)
    {
        if (snap.text_base == 0 || snap.text_size == 0)
            return true;

        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = snap.text_base;
        const uint64_t end = snap.text_base + snap.text_size;

        while (addr < end)
        {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
                return false;

            constexpr DWORD writable = PAGE_EXECUTE_READWRITE | PAGE_READWRITE
                | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            if (mbi.Protect & writable)
                return false;

            addr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return true;
    }

    struct iat_entry_t
    {
        uint64_t slot_va;
        uint64_t resolved_va;
    };

    inline bool snapshot_iat(std::vector<iat_entry_t>& entries)
    {
        entries.clear();
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        const auto* base = reinterpret_cast<const uint8_t*>(mod);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return true;

        const auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            base + dir.VirtualAddress);

        while (imp->Name != 0)
        {
            if (imp->FirstThunk == 0) { ++imp; continue; }

            const auto* thunk = reinterpret_cast<const uint64_t*>(
                base + imp->FirstThunk);
            uint64_t slot = reinterpret_cast<uint64_t>(thunk);

            while (*thunk != 0)
            {
                entries.push_back({ slot, *thunk });
                ++thunk;
                slot += sizeof(uint64_t);
            }
            ++imp;
        }
        return true;
    }

    inline bool verify_iat(const std::vector<iat_entry_t>& entries)
    {
        for (const auto& e : entries)
        {
            const auto current = *reinterpret_cast<const volatile uint64_t*>(e.slot_va);
            if (current != e.resolved_va)
                return false;
        }
        return true;
    }

}


namespace process_scan
{

    inline bool scan_for_re_tools_with_our_binary()
    {
        DWORD my_pid = GetCurrentProcessId();

        wchar_t my_exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, my_exe, MAX_PATH);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        bool violation = false;
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !violation;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0
                || pe.th32ProcessID == 4)
                continue;

            wchar_t lower[MAX_PATH] = {};
            for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
                lower[i] = towlower(pe.szExeFile[i]);

            bool is_re_tool = false;
            if (wcsstr(lower, L"ghidra") || wcsstr(lower, L"binja")
                || wcsstr(lower, L"binaryninja") || wcsstr(lower, L"cutter")
                || wcsstr(lower, L"radare2") || wcsstr(lower, L"r2.exe")
                || wcsstr(lower, L"rizin") || wcsstr(lower, L"x64dbg")
                || wcsstr(lower, L"x32dbg") || wcsstr(lower, L"windbg")
                || wcsstr(lower, L"ollydbg") || wcsstr(lower, L"dnspy")
                || wcsstr(lower, L"dotpeek") || wcsstr(lower, L"pestudio")
                || wcsstr(lower, L"die.exe")
                || wcsstr(lower, L"ida64.exe") || wcsstr(lower, L"ida.exe"))
            {
                is_re_tool = true;
            }

            if (!is_re_tool) continue;

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HMODULE mods[512] = {};
            DWORD cb = 0;
            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL))
            {
                DWORD count = cb / sizeof(HMODULE);
                for (DWORD i = 0; i < count && !violation; ++i)
                {
                    wchar_t mod_path[MAX_PATH] = {};
                    if (GetModuleFileNameExW(hProc, mods[i], mod_path, MAX_PATH) == 0)
                        continue;

                    if (_wcsicmp(mod_path, my_exe) == 0)
                        violation = true;
                }
            }
            CloseHandle(hProc);
        }
        CloseHandle(snap);
        return violation;
    }

}


namespace state
{
    struct runtime_t
    {
        std::mutex mtx;
        std::atomic<bool> initialized{false};
        std::atomic<bool> violation_latched{false};
        std::atomic<bool> monitors_running{false};

        integrity::code_snapshot_t code_snap{};
        std::vector<integrity::iat_entry_t> iat_snap;

        uint32_t verify_counter = 0;
        std::string violation_reason;

        anti_tamper::virtualizer::detail::vm_state_t integrity_vm{};
        std::vector<uint8_t> integrity_bytecode;
        bool integrity_vm_ready = false;
        std::atomic<uint32_t> soft_violation_count{0};
        std::atomic<uint64_t> soft_violation_window_tick{0};
    };

    inline runtime_t& get()
    {
        static runtime_t inst;
        return inst;
    }

}


inline void enforce_violation(const char* reason, const std::string& extra = "")
{
    auto& rt = state::get();

    if (rt.violation_latched.exchange(true))
        return;

    {
        std::lock_guard<std::mutex> lk(rt.mtx);
        rt.violation_reason = reason ? reason : "standalone_tamper";
    }

    webhook::send_violation_alert(reason ? reason : "standalone_tamper", extra);

    standalone_license::shutdown();

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        driver_bridge::trigger_kernel_bsod(
            0x0002u,
            rt.code_snap.text_hash
        );
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
            ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
        using NtRaiseHardError_t = NTSTATUS(NTAPI*)(
            NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

        auto pAdjust = reinterpret_cast<RtlAdjustPrivilege_t>(
            GetProcAddress(ntdll, "RtlAdjustPrivilege"));
        auto pRaise = reinterpret_cast<NtRaiseHardError_t>(
            GetProcAddress(ntdll, "NtRaiseHardError"));

        if (pAdjust && pRaise)
        {
            BOOLEAN wasEnabled = FALSE;
            pAdjust(19, TRUE, FALSE, &wasEnabled);

            ULONG response = 0;
            pRaise(static_cast<NTSTATUS>(0xC0000420),
                0, 0, nullptr, 6, &response);
        }
    }

    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}


inline bool run_verification_cycle()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (!rt.initialized.load()) return true;
    if (rt.violation_latched.load()) return false;

    ++rt.verify_counter;
    const bool deep_check = (rt.verify_counter & 3u) == 0;


    {
        bool peb_hit = detect::check_peb_debug_flags();
        bool port_hit = detect::check_debug_port();
        bool remote_hit = detect::check_remote_debugger();

        if (peb_hit || port_hit || remote_hit)
        {
            std::string detail;
            if (peb_hit) detail += "peb ";
            if (port_hit) detail += "debug_port ";
            if (remote_hit) detail += "remote ";

            webhook::send_debug_log("debugger_check", detail, true);
            enforce_violation("debugger_attached", detail);
            return false;
        }
    }


    if (!integrity::verify_usermode(rt.code_snap))
    {
        uint64_t current = integrity::hash_memory(
            reinterpret_cast<const void*>(rt.code_snap.text_base),
            rt.code_snap.text_size);

        char detail[128];
        snprintf(detail, sizeof(detail), "expected=%llx got=%llx",
            rt.code_snap.text_hash, current);

        webhook::send_debug_log("code_integrity", detail, true);
        enforce_violation("code_integrity_mismatch", detail);
        return false;
    }


    if (!integrity::verify_iat(rt.iat_snap))
    {
        std::string detail;
        for (const auto& e : rt.iat_snap)
        {
            const auto cur = *reinterpret_cast<const volatile uint64_t*>(e.slot_va);
            if (cur != e.resolved_va)
            {
                char buf[128];
                snprintf(buf, sizeof(buf), "slot=%llx was=%llx now=%llx",
                    e.slot_va, e.resolved_va, cur);
                detail = buf;
                break;
            }
        }

        webhook::send_debug_log("iat_verify", detail, true);
        enforce_violation("iat_hook_detected", detail);
        return false;
    }


    if (!integrity::verify_page_protections(rt.code_snap))
    {
        webhook::send_debug_log("page_protection", "writable_code_page", true);
        enforce_violation("writable_code_page");
        return false;
    }


    if (deep_check)
    {

        if (detect::check_hw_breakpoints_kernel(
            rt.code_snap.module_base, rt.code_snap.module_end))
        {
            webhook::send_debug_log("hw_breakpoint", "breakpoint_in_code_range", true);
            enforce_violation("hardware_breakpoint_in_code");
            return false;
        }


        if (detect::check_kernel_debugger())
        {
            webhook::send_debug_log("kernel_debugger", "kd_active", true);
            enforce_violation("kernel_debugger_active");
            return false;
        }


        if (process_scan::scan_for_re_tools_with_our_binary())
        {
            webhook::send_debug_log("re_tool_scan", "tool_loaded_our_binary", true);
            enforce_violation("re_tool_loaded_binary");
            return false;
        }


        auto ai_report = standalone_anti_ai::combined::full_scan();

        if (ai_report.mcp_detected || ai_report.llm_detected
            || ai_report.memory_scanner_detected || ai_report.handle_to_us_detected)
        {
            uint64_t now_tick = GetTickCount64();
            uint64_t first_tick = rt.soft_violation_window_tick.load(std::memory_order_relaxed);
            uint32_t c;
            if (first_tick == 0 || (now_tick - first_tick) > 120000ULL)
            {
                rt.soft_violation_window_tick.store(now_tick, std::memory_order_relaxed);
                rt.soft_violation_count.store(1, std::memory_order_relaxed);
                c = 1;
            }
            else
            {
                c = rt.soft_violation_count.fetch_add(1, std::memory_order_relaxed) + 1;
            }
            if (c >= 3)
            {
                const char* viol_reason;
                std::string detail = ai_report.summary;
                if (ai_report.mcp_detected)
                {
                    viol_reason = "mcp_bridge_detected";
                    webhook::send_debug_log("anti_mcp", detail, true);
                }
                else if (ai_report.llm_detected)
                {
                    viol_reason = "local_llm_analysis";
                    webhook::send_debug_log("anti_llm", detail, true);
                }
                else if (ai_report.memory_scanner_detected)
                {
                    viol_reason = "memory_scanner_attached";
                    webhook::send_debug_log("mem_scanner", detail, true);
                }
                else
                {
                    viol_reason = "foreign_handle_detected";
                    webhook::send_debug_log("handle_leak", detail, true);
                }
                enforce_violation(viol_reason, detail);
                return false;
            }
            webhook::send_debug_log("soft_violation_pending",
                std::to_string(c) + "/3 " + ai_report.summary, false);
        }
        else
        {
            rt.soft_violation_count.store(0, std::memory_order_relaxed);
            rt.soft_violation_window_tick.store(0, std::memory_order_relaxed);
        }


        if (detect::check_timing_anomaly())
        {
            webhook::send_debug_log("timing", "rdtsc_anomaly (informational)", false);
        }
    }


    if ((rt.verify_counter & 7u) == 0)
    {
        if (rt.integrity_vm_ready)
        {
            uint64_t vm_result = anti_tamper::virtualizer::detail::vm_execute(
                rt.integrity_vm,
                rt.integrity_bytecode.data(),
                static_cast<uint32_t>(rt.integrity_bytecode.size()));

            if (vm_result != 1)
            {
                char detail[128];
                snprintf(detail, sizeof(detail), "vm_integrity_failed_result=%llx", vm_result);
                webhook::send_debug_log("vm_integrity", detail, true);
                enforce_violation("vm_integrity_check_failed", detail);
                return false;
            }
        }
    }

    return true;
}


inline void start_monitors()
{
    auto& rt = state::get();
    if (rt.monitors_running.exchange(true))
        return;

    work_queue::post([]() {
        Sleep(5000);

        auto& rt = state::get();
        while (rt.monitors_running.load() && !rt.violation_latched.load())
        {
            run_verification_cycle();
            Sleep(3000);
        }
    });
}


inline bool initialize()
{
    auto& rt = state::get();
    std::lock_guard<std::mutex> lk(rt.mtx);

    if (rt.initialized.load()) return true;

    webhook::send_debug_log("init", "anti-tamper initializing", false);

    if (!integrity::snapshot_code(rt.code_snap))
        return false;

    integrity::snapshot_iat(rt.iat_snap);

    {
        uint64_t vm_seed = __rdtsc() ^ reinterpret_cast<uint64_t>(&rt) ^ GetCurrentProcessId();
        anti_tamper::virtualizer::detail::init_vm(rt.integrity_vm, vm_seed);
        rt.integrity_bytecode = anti_tamper::vm_compiler::build_integrity_check_program(
            rt.code_snap.text_hash,
            rt.code_snap.text_base,
            rt.code_snap.text_size,
            rt.integrity_vm.rolling_key,
            rt.integrity_vm.opcode_map);
        rt.integrity_vm_ready = !rt.integrity_bytecode.empty();
    }

    if (detect::check_peb_debug_flags() || detect::check_debug_port()
        || detect::check_remote_debugger())
    {
        webhook::send_debug_log("init", "debugger_at_startup", true);
        enforce_violation("debugger_at_startup");
        return false;
    }

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
    {
        driver_bridge::register_dll_protection(
            rt.code_snap.module_base,
            rt.code_snap.text_base,
            rt.code_snap.text_size,
            rt.code_snap.text_hash,
            2000
        );
    }

    standalone_anti_dump::initialize();

    rt.initialized.store(true);

    char info[256];
    snprintf(info, sizeof(info), "text=%llx size=%u hash=%llx",
        rt.code_snap.text_base, rt.code_snap.text_size, rt.code_snap.text_hash);
    webhook::send_debug_log("init", std::string("initialized: ") + info, false);

    start_monitors();

    return true;
}


inline bool guard()
{
    auto& rt = state::get();
    return !rt.violation_latched.load(std::memory_order_acquire);
}

inline void shutdown()
{
    auto& rt = state::get();
    rt.monitors_running.store(false);
    standalone_anti_dump::shutdown();

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        driver_bridge::unregister_dll_protection();
}

}
