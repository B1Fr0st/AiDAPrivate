#pragma once

#include <windows.h>
#include <intrin.h>
#include <psapi.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "anti_debug.hpp"
#include "process_scan.hpp"
#include "../standalone_driver.hpp"
#include "../standalone_license.hpp"

namespace anti_tamper {
namespace re_detect {

constexpr uint32_t SIGNAL_PROC_SCAN        = 1u << 0;
constexpr uint32_t SIGNAL_FOREIGN_HANDLE   = 1u << 1;
constexpr uint32_t SIGNAL_INJECTED_MODULE  = 1u << 2;
constexpr uint32_t SIGNAL_KERNEL_DEBUG     = 1u << 3;
constexpr uint32_t SIGNAL_DR_SET           = 1u << 4;
constexpr uint32_t SIGNAL_DEBUG_PORT       = 1u << 5;
constexpr uint32_t SIGNAL_PEB_CLASSIC      = 1u << 6;
constexpr uint32_t SIGNAL_API_IS_DBG       = 1u << 7;
constexpr uint32_t SIGNAL_TOOL_PIPE        = 1u << 8;
constexpr uint32_t SIGNAL_DEBUG_ATTACH     = 1u << 9;
constexpr uint32_t SIGNAL_DBGUI_BREAKIN    = 1u << 10;

constexpr uint32_t FAMILY_TARGET    = 0x01;
constexpr uint32_t FAMILY_HANDLE    = 0x02;
constexpr uint32_t FAMILY_INJECTION = 0x04;
constexpr uint32_t FAMILY_KDEBUG    = 0x08;
constexpr uint32_t FAMILY_DR        = 0x10;
constexpr uint32_t FAMILY_DPORT     = 0x20;
constexpr uint32_t FAMILY_CLASSIC   = 0x40;
constexpr uint32_t FAMILY_PIPE      = 0x80;
constexpr uint32_t FAMILY_ATTACH    = 0x100;

constexpr uint32_t THRESHOLD_CONFIRMED = 100;
constexpr uint32_t PERSISTENCE_TICKS   = 3;
constexpr uint32_t TICK_INTERVAL_MS    = 500;

struct signal_desc_t
{
    uint32_t bit;
    uint32_t weight;
    uint32_t family;
};

inline const signal_desc_t& signals(uint32_t bit)
{
    static const signal_desc_t table[] = {
        { SIGNAL_PROC_SCAN,       80, FAMILY_TARGET },
        { SIGNAL_FOREIGN_HANDLE,  70, FAMILY_HANDLE },
        { SIGNAL_INJECTED_MODULE, 60, FAMILY_INJECTION },
        { SIGNAL_KERNEL_DEBUG,    90, FAMILY_KDEBUG },
        { SIGNAL_DR_SET,          95, FAMILY_DR },
        { SIGNAL_DEBUG_PORT,      95, FAMILY_DPORT },
        { SIGNAL_PEB_CLASSIC,     60, FAMILY_CLASSIC },
        { SIGNAL_API_IS_DBG,      30, FAMILY_CLASSIC },
        { SIGNAL_TOOL_PIPE,       50, FAMILY_PIPE },
        { SIGNAL_DEBUG_ATTACH,   100, FAMILY_ATTACH },
        { SIGNAL_DBGUI_BREAKIN,   80, FAMILY_ATTACH },
    };
    static const signal_desc_t zero = { 0, 0, 0 };
    for (const auto& d : table) {
        if (d.bit == bit) return d;
    }
    return zero;
}

struct engine_state_t
{
    std::atomic<bool> running{ false };
    std::atomic<uint32_t> last_mask{ 0 };
    std::atomic<uint32_t> persist_mask{ 0 };
    std::atomic<uint32_t> persist_count{ 0 };
    std::atomic<uint64_t> verify_counter{ 0 };
    std::atomic<uint64_t> last_tick_tsc{ 0 };
    std::thread worker;
    std::thread watchdog;
    std::mutex mtx;
};

inline engine_state_t& state_ref()
{
    static engine_state_t s;
    return s;
}

namespace detail {

    inline bool is_devmode_hwid_allowlisted()
    {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "Software\\AiDA", 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        DWORD type = 0;
        DWORD value = 0;
        DWORD sz = sizeof(value);
        LONG st = RegQueryValueExA(hk, "DevMode", nullptr, &type,
            reinterpret_cast<LPBYTE>(&value), &sz);
        RegCloseKey(hk);
        if (st != ERROR_SUCCESS || type != REG_DWORD)
            return false;
        return value == 1;
    }

    inline bool detect_foreign_vm_write_handle()
    {
        DWORD my_pid = GetCurrentProcessId();
        ULONG buf_size = 1024 * 1024;
        std::vector<uint8_t> buf(buf_size);
        ULONG ret_len = 0;

        if (!syscall::is_initialized())
            return false;

        NTSTATUS st = syscall::NtQuerySystemInformation()(
            64, buf.data(), buf_size, &ret_len);
        if (st == static_cast<NTSTATUS>(0xC0000004) && ret_len > buf_size) {
            buf_size = ret_len + 65536;
            buf.resize(buf_size);
            st = syscall::NtQuerySystemInformation()(
                64, buf.data(), buf_size, &ret_len);
        }
        if (st < 0) return false;

        struct handle_entry_t {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ACCESS_MASK GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };
        struct handle_info_ex_t {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            handle_entry_t Handles[1];
        };

        auto* info = reinterpret_cast<handle_info_ex_t*>(buf.data());
        constexpr ACCESS_MASK DEBUG_GRADE =
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
            PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION;

        for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
            const auto& h = info->Handles[i];
            if (static_cast<DWORD>(h.UniqueProcessId) == my_pid) continue;
            if ((h.GrantedAccess & DEBUG_GRADE) == 0) continue;

            HANDLE src_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
                static_cast<DWORD>(h.UniqueProcessId));
            if (!src_proc) continue;

            HANDLE dup = nullptr;
            BOOL dup_ok = DuplicateHandle(
                src_proc,
                reinterpret_cast<HANDLE>(h.HandleValue),
                GetCurrentProcess(),
                &dup,
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                0);
            CloseHandle(src_proc);
            if (!dup_ok || !dup) continue;

            DWORD target_pid = GetProcessId(dup);
            CloseHandle(dup);
            if (target_pid == my_pid) {
                return true;
            }
        }
        return false;
    }

    inline bool detect_injected_module()
    {
        HMODULE mods[512] = {};
        DWORD cb = 0;
        if (!EnumProcessModulesEx(GetCurrentProcess(),
                mods, sizeof(mods), &cb, LIST_MODULES_ALL))
            return false;
        DWORD count = cb / sizeof(HMODULE);

        static const wchar_t* suspicious[] = {
            L"scyllahide", L"titanhide", L"hyperdbg", L"frida",
            L"detours64.dll", L"minhook", L"polyhook", L"easyhook",
            L"reclass", L"capstone.dll", L"zydis.dll"
        };

        wchar_t system_dir[MAX_PATH] = {};
        GetSystemDirectoryW(system_dir, MAX_PATH);
        size_t sys_len = wcslen(system_dir);

        for (DWORD i = 0; i < count; ++i) {
            wchar_t path[MAX_PATH] = {};
            if (!GetModuleFileNameExW(GetCurrentProcess(), mods[i], path, MAX_PATH))
                continue;
            wchar_t lower[MAX_PATH] = {};
            for (int j = 0; j < MAX_PATH && path[j]; ++j)
                lower[j] = towlower(path[j]);

            for (const wchar_t* s : suspicious) {
                if (wcsstr(lower, s)) return true;
            }

            if (wcsstr(lower, L"dbghelp.dll")) {
                wchar_t lower_sys[MAX_PATH] = {};
                for (size_t j = 0; j < sys_len && j < MAX_PATH; ++j)
                    lower_sys[j] = towlower(system_dir[j]);
                if (wcsstr(lower, lower_sys) == nullptr)
                    return true;
            }
        }
        return false;
    }

    inline bool detect_tool_pipe()
    {
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
        if (h == INVALID_HANDLE_VALUE) return false;
        bool hit = false;
        do {
            wchar_t lower[MAX_PATH] = {};
            for (int i = 0; i < MAX_PATH && fd.cFileName[i]; ++i)
                lower[i] = towlower(fd.cFileName[i]);
            if (wcsstr(lower, L"x64dbg") || wcsstr(lower, L"x32dbg") ||
                wcsstr(lower, L"ida_") || wcsstr(lower, L"windbg") ||
                wcsstr(lower, L"scyllahide")) {
                hit = true;
                break;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        return hit;
    }

    inline bool detect_dr_on_self_text()
    {
        auto& rt = state::get();
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx))
            return false;
        uint64_t drs[4] = { ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 };
        uint64_t text_start = rt.code_snap.text_base;
        uint64_t text_end   = rt.code_snap.text_base + rt.code_snap.text_size;
        for (int i = 0; i < 4; ++i) {
            if (drs[i] != 0 && drs[i] >= text_start && drs[i] < text_end)
                return true;
        }
        return (ctx.Dr7 & 0x55ULL) != 0;
    }

    inline bool detect_peb_classic_triple()
    {
        auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
        uint8_t being_dbg = peb[2];
        uint32_t ngf = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
        uint64_t heap_ptr = *reinterpret_cast<const uint64_t*>(peb + 0x30);
        uint32_t heap_flags = 0;
        uint32_t heap_force = 0;
        if (heap_ptr) {
            __try {
                heap_flags = *reinterpret_cast<const uint32_t*>(heap_ptr + 0x70);
                heap_force = *reinterpret_cast<const uint32_t*>(heap_ptr + 0x74);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }
        int hits = 0;
        if (being_dbg != 0) ++hits;
        if ((ngf & 0x70) != 0) ++hits;
        if ((heap_flags & ~0x2u) != 0 || heap_force != 0) ++hits;
        return hits >= 3;
    }

    inline bool detect_debug_attach_thread()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        auto breakin = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "DbgUiRemoteBreakin"));
        if (!breakin) return false;
        if (breakin[0] == 0xC3 || breakin[0] == 0xCC || breakin[0] == 0xE9)
            return true;
        return false;
    }

    inline uint32_t collect_signals()
    {
        uint32_t mask = 0;

        if (process_scan::scan_re_tools_with_binary())
            mask |= SIGNAL_PROC_SCAN;

        if (detect_foreign_vm_write_handle())
            mask |= SIGNAL_FOREIGN_HANDLE;

        if (detect_injected_module())
            mask |= SIGNAL_INJECTED_MODULE;

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
            driver_bridge::anti_debug_result_t ar{};
            if (driver_bridge::kernel_anti_debug_query(ar)) {
                if ((ar.result_flags & 0x1u) != 0)
                    mask |= SIGNAL_KERNEL_DEBUG;
            }
        }

        if (detect_dr_on_self_text())
            mask |= SIGNAL_DR_SET;

        if (detect_peb_classic_triple())
            mask |= SIGNAL_PEB_CLASSIC;

        BOOL isDbg = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg) && isDbg)
            mask |= SIGNAL_API_IS_DBG;

        if (detect_tool_pipe())
            mask |= SIGNAL_TOOL_PIPE;

        if (detect_debug_attach_thread())
            mask |= SIGNAL_DBGUI_BREAKIN;

        return mask;
    }

    inline bool score_exceeds_threshold(uint32_t mask)
    {
        uint32_t score = 0;
        uint32_t families = 0;
        int family_count = 0;
        for (int bit = 0; bit < 32; ++bit) {
            if ((mask & (1u << bit)) == 0) continue;
            const auto& d = signals(1u << bit);
            score += d.weight;
            if ((families & d.family) == 0) {
                families |= d.family;
                ++family_count;
            }
        }
        return score >= THRESHOLD_CONFIRMED && family_count >= 2;
    }

    inline uint64_t hash_evidence(uint32_t mask)
    {
        uint64_t h = 0xCBF29CE484222325ULL;
        h ^= static_cast<uint64_t>(mask);
        h *= 0x100000001B3ULL;
        h ^= static_cast<uint64_t>(GetCurrentProcessId());
        h *= 0x100000001B3ULL;
        h ^= __rdtsc();
        h *= 0x100000001B3ULL;
        return h;
    }
}

inline void tick();

inline bool should_bsod(uint32_t mask)
{
    if (detail::is_devmode_hwid_allowlisted())
        return false;
    return detail::score_exceeds_threshold(mask);
}

inline void tick()
{
    auto& s = state_ref();
    s.verify_counter.fetch_add(1);
    s.last_tick_tsc.store(__rdtsc());

    uint32_t mask = detail::collect_signals();
    s.last_mask.store(mask);

    uint32_t prev = s.persist_mask.load();
    uint32_t intersect = prev & mask;
    if (intersect != 0) {
        uint32_t c = s.persist_count.fetch_add(1) + 1;
        if (c >= PERSISTENCE_TICKS && should_bsod(intersect)) {
            uint64_t evidence = detail::hash_evidence(intersect);
            standalone_license::fold_integrity_token(evidence);
            std::string detail_str = "re_detected mask=0x" +
                std::to_string(intersect) + " evidence=0x" +
                std::to_string(evidence);
            webhook::send_debug_log("re_detect", detail_str, true);
            webhook::post_critical_then_enforce("re_detected", detail_str, intersect);
            if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
                uint32_t reason = 0x0000DEEEu;
                if (intersect & SIGNAL_DR_SET)           reason = 0x0000D7D7u;
                else if (intersect & SIGNAL_DEBUG_PORT)  reason = 0x0000DBDBu;
                else if (intersect & SIGNAL_FOREIGN_HANDLE) reason = 0x0000AD7Du;
                else if (intersect & SIGNAL_INJECTED_MODULE) reason = 0x0000114Du;
                else if (intersect & SIGNAL_DEBUG_ATTACH) reason = 0x0000DBDBu;
                driver_bridge::trigger_kernel_bsod(reason, evidence);
            }
            enforce_violation("re_detected", detail_str);
            s.persist_count.store(0);
            s.persist_mask.store(0);
            return;
        }
    } else {
        s.persist_count.store(0);
    }
    s.persist_mask.store(mask);
}

inline void worker_loop()
{
    Sleep(2000);
    auto& s = state_ref();
    while (s.running.load()) {
        tick();
        Sleep(TICK_INTERVAL_MS);
    }
}

inline void watchdog_loop()
{
    auto& s = state_ref();
    auto& rt = state::get();
    uint64_t last_counter = 0;
    while (s.running.load()) {
        Sleep(2000);
        uint64_t current = s.verify_counter.load();
        bool monitors_ok = rt.monitors_running.load();
        bool advanced = current != last_counter;
        if (!advanced || !monitors_ok) {
            uint32_t mask = detail::collect_signals();
            if (detail::score_exceeds_threshold(mask)) {
                uint64_t evidence = detail::hash_evidence(mask);
                standalone_license::fold_integrity_token(evidence);
                webhook::send_debug_log("re_watchdog",
                    "watchdog_stall mask=0x" + std::to_string(mask), true);
                webhook::post_critical_then_enforce("re_watchdog_stall",
                    "mask=0x" + std::to_string(mask), mask);
                if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
                    driver_bridge::trigger_kernel_bsod(0x0000DEDDu, evidence);
                }
                enforce_violation("re_watchdog_stall");
                return;
            }
        }
        last_counter = current;
    }
}

inline void initialize()
{
    auto& s = state_ref();
    if (s.running.exchange(true))
        return;
    s.worker = std::thread(worker_loop);
    s.watchdog = std::thread(watchdog_loop);
    s.worker.detach();
    s.watchdog.detach();
}

inline void shutdown()
{
    auto& s = state_ref();
    s.running.store(false);
}

}
}
