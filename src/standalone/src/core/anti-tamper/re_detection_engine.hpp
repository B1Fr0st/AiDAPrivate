#pragma once

#include <windows.h>
#include <intrin.h>
#include <psapi.h>
#include <tlhelp32.h>

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
#include "../standalone_driver.hpp"
#include "../standalone_license.hpp"

namespace anti_tamper {
namespace re_detect {

constexpr uint32_t SIGNAL_FOREIGN_HANDLE   = 1u << 1;
constexpr uint32_t SIGNAL_INJECTED_MODULE  = 1u << 2;
constexpr uint32_t SIGNAL_KERNEL_DEBUG     = 1u << 3;
constexpr uint32_t SIGNAL_DR_SET           = 1u << 4;
constexpr uint32_t SIGNAL_DEBUG_PORT       = 1u << 5;
constexpr uint32_t SIGNAL_PEB_CLASSIC      = 1u << 6;
constexpr uint32_t SIGNAL_API_IS_DBG       = 1u << 7;
constexpr uint32_t SIGNAL_DEBUG_ATTACH     = 1u << 9;
constexpr uint32_t SIGNAL_DBGUI_BREAKIN    = 1u << 10;
constexpr uint32_t SIGNAL_TEXT_WRITABLE     = 1u << 13;
constexpr uint32_t SIGNAL_PROC_DEBUG_HANDLE = 1u << 14;
constexpr uint32_t SIGNAL_THREAD_SUSPENDED  = 1u << 17;
constexpr uint32_t SIGNAL_VEH_TAMPERED      = 1u << 18;
constexpr uint32_t SIGNAL_DEBUG_REATTACH    = 1u << 19;
constexpr uint32_t SIGNAL_KD_TARGETING_US   = 1u << 22;

constexpr uint32_t FAMILY_TARGET    = 0x01;
constexpr uint32_t FAMILY_HANDLE    = 0x02;
constexpr uint32_t FAMILY_INJECTION = 0x04;
constexpr uint32_t FAMILY_KDEBUG    = 0x08;
constexpr uint32_t FAMILY_DR        = 0x10;
constexpr uint32_t FAMILY_DPORT     = 0x20;
constexpr uint32_t FAMILY_CLASSIC   = 0x40;
constexpr uint32_t FAMILY_ATTACH    = 0x100;
constexpr uint32_t FAMILY_MEMORY    = 0x200;
constexpr uint32_t FAMILY_DPORT_X   = 0x400;
constexpr uint32_t FAMILY_SIDECHANNEL = 0x2000;

constexpr uint64_t EVIDENCE_MAGIC = 0x5645444149414941ULL;
constexpr uint32_t EVIDENCE_VERSION = 1u;

struct re_evidence_blob_t
{
    uint64_t magic;
    uint32_t version;
    uint32_t signal_family;
    uint32_t signal_id;
    uint32_t score;
    uint32_t pid;
    uint32_t reserved0;
    uint64_t caller_image_hash;
    uint64_t signals_bitmap_hash;
    uint64_t timestamp;
};

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
        { SIGNAL_FOREIGN_HANDLE,  70, FAMILY_HANDLE },
        { SIGNAL_INJECTED_MODULE, 60, FAMILY_INJECTION },
        { SIGNAL_KERNEL_DEBUG,    90, FAMILY_KDEBUG },
        { SIGNAL_DR_SET,          95, FAMILY_DR },
        { SIGNAL_DEBUG_PORT,      95, FAMILY_DPORT },
        { SIGNAL_PEB_CLASSIC,     60, FAMILY_CLASSIC },
        { SIGNAL_API_IS_DBG,      30, FAMILY_CLASSIC },
        { SIGNAL_DEBUG_ATTACH,   100, FAMILY_ATTACH },
        { SIGNAL_DBGUI_BREAKIN,   80, FAMILY_ATTACH },
        { SIGNAL_TEXT_WRITABLE,     100, FAMILY_MEMORY },
        { SIGNAL_PROC_DEBUG_HANDLE,  95, FAMILY_DPORT_X },
        { SIGNAL_THREAD_SUSPENDED,   90, FAMILY_TARGET },
        { SIGNAL_VEH_TAMPERED,       85, FAMILY_INJECTION },
        { SIGNAL_DEBUG_REATTACH,     95, FAMILY_ATTACH },
        { SIGNAL_KD_TARGETING_US,   100, FAMILY_KDEBUG },
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
            PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION |
            PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;

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
            L"frida", L"detours64.dll", L"minhook", L"polyhook", L"easyhook"
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

    inline bool detect_text_writable()
    {
        auto& rt = state::get();
        if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0)
            return false;

        ULONG_PTR base = static_cast<ULONG_PTR>(rt.code_snap.text_base);
        ULONG_PTR end  = base + rt.code_snap.text_size;
        ULONG_PTR addr = base;
        int iter = 0;
        bool writable = false;

        __try
        {
            MEMORY_BASIC_INFORMATION mbi{};
            while (addr < end && iter < 256)
            {
                SIZE_T q = VirtualQuery(
                    reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
                if (q == 0) break;

                const DWORD mask_writable =
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
                    | PAGE_WRITECOPY | PAGE_READWRITE;

                if ((mbi.Protect & mask_writable) != 0)
                {
                    writable = true;
                    break;
                }

                ULONG_PTR next = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress)
                    + mbi.RegionSize;
                if (next <= addr) break;
                addr = next;
                ++iter;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            writable = false;
        }

        return writable;
    }

    inline bool detect_process_debug_handle()
    {
        if (!syscall::is_initialized()) return false;

        bool hit = false;
        __try
        {
            HANDLE dbg_obj = nullptr;
            NTSTATUS st = syscall::NtQueryInformationProcess()(
                GetCurrentProcess(), 30, &dbg_obj, sizeof(dbg_obj), nullptr);
            if (st >= 0 && dbg_obj != nullptr)
            {
                syscall::NtClose()(dbg_obj);
                hit = true;
            }

            if (!hit)
            {
                ULONG dbg_flags = 1;
                st = syscall::NtQueryInformationProcess()(
                    GetCurrentProcess(), 31,
                    &dbg_flags, sizeof(dbg_flags), nullptr);
                if (st >= 0 && dbg_flags == 0)
                    hit = true;
            }

            if (!hit)
            {
                ULONG_PTR dbg_port = 0;
                st = syscall::NtQueryInformationProcess()(
                    GetCurrentProcess(), 7,
                    &dbg_port, sizeof(dbg_port), nullptr);
                if (st >= 0 && dbg_port != 0)
                    hit = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            hit = false;
        }

        return hit;
    }

    inline bool detect_thread_suspended()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return false;

        DWORD pid = GetCurrentProcessId();
        DWORD main_tid = GetCurrentThreadId();
        int suspended_count = 0;
        int total_threads = 0;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != pid)
                    continue;
                if (te.th32ThreadID == main_tid)
                    continue;
                ++total_threads;

                HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (!th) continue;

                DWORD prev = SuspendThread(th);
                if (prev != (DWORD)-1)
                {
                    ResumeThread(th);
                    if (prev > 0)
                        ++suspended_count;
                }
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);

        if (total_threads < 2)
            return false;

        return suspended_count >= 2
            || (total_threads > 0 && suspended_count * 2 >= total_threads);
    }

    inline bool detect_veh_tampered()
    {
        auto& rt_veh = state::get();
        if (!rt_veh.veh_baseline_captured.load(std::memory_order_acquire))
            return false;

        typedef struct _VEH_ENTRY {
            LIST_ENTRY list;
            PVOID handler;
        } VEH_ENTRY;

        auto ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;

        using NtQueryInfoProcess_t = LONG(NTAPI*)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = reinterpret_cast<NtQueryInfoProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!NtQIP) return false;

        ULONG handler_count = 0;
        ULONG ret_len = 0;
        LONG st = NtQIP(GetCurrentProcess(), 83,
            &handler_count, sizeof(handler_count), &ret_len);
        if (st < 0)
        {
            ULONG_PTR peb_addr = reinterpret_cast<ULONG_PTR>(NtCurrentTeb()->ProcessEnvironmentBlock);
            ULONG_PTR ldr = *reinterpret_cast<ULONG_PTR*>(peb_addr + 0x18);
            (void)ldr;
            return false;
        }

        uint32_t baseline = rt_veh.veh_baseline_count;

        if (handler_count < baseline && baseline > 0)
            return true;
        if (handler_count > baseline + 3)
            return true;

        return false;
    }

    inline bool detect_debug_reattach()
    {
        auto ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        using NtQueryInfoProcess_t = LONG(NTAPI*)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = reinterpret_cast<NtQueryInfoProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!NtQIP) return false;

        ULONG dbg_flags = 1;
        LONG st = NtQIP(GetCurrentProcess(), 31,
            &dbg_flags, sizeof(dbg_flags), nullptr);
        bool debug_port_present = false;
        if (st >= 0 && dbg_flags == 0)
            debug_port_present = true;

        if (!debug_port_present)
        {
            ULONG_PTR dbg_port = 0;
            st = NtQIP(GetCurrentProcess(), 7,
                &dbg_port, sizeof(dbg_port), nullptr);
            if (st >= 0 && dbg_port != 0)
                debug_port_present = true;
        }

        auto& rt_dbg = state::get();
        uint8_t prev = rt_dbg.last_debug_port_present.exchange(
            debug_port_present ? 1 : 0, std::memory_order_acq_rel);

        if (debug_port_present && prev == 0)
        {
            uint8_t prev_peb = rt_dbg.last_peb_being_debugged.load(
                std::memory_order_acquire);
            if (prev_peb == 0)
                return true;
        }

        auto* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        uint8_t being_dbg = peb->BeingDebugged;
        rt_dbg.last_peb_being_debugged.store(
            being_dbg, std::memory_order_release);

        return false;
    }

    inline bool detect_kd_targeting_us()
    {
        __try {
            auto* shared = reinterpret_cast<const volatile uint8_t*>(0x7FFE0000ULL);
            uint8_t kd_enabled = *(shared + 0x2D4);
            if (kd_enabled == 0)
                return false;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        auto fn = reinterpret_cast<LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG)>(nullptr);
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt)
            fn = reinterpret_cast<decltype(fn)>(
                GetProcAddress(nt, "NtQuerySystemInformation"));
        if (!fn)
            return false;

        struct {
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        } kdi = {};
        ULONG ret = 0;
        LONG st = fn(0x23, &kdi, sizeof(kdi), &ret);
        if (st < 0)
            return false;

        return kdi.KernelDebuggerEnabled != 0 && kdi.KernelDebuggerNotPresent == 0;
    }

    inline uint64_t module_image_hash()
    {
        static std::atomic<uint64_t> cached{ 0 };
        uint64_t v = cached.load(std::memory_order_acquire);
        if (v != 0) return v;

        wchar_t path[MAX_PATH] = {};
        DWORD got = GetModuleFileNameW(nullptr, path, MAX_PATH);
        uint64_t h = 0xCBF29CE484222325ULL;
        for (DWORD i = 0; i < got; ++i)
        {
            h ^= static_cast<uint64_t>(path[i]);
            h *= 0x100000001B3ULL;
        }
        if (h == 0) h = 1;
        cached.store(h, std::memory_order_release);
        return h;
    }

    inline uint64_t hash_evidence(uint32_t mask);

    inline re_evidence_blob_t build_evidence_blob(uint32_t mask, uint32_t family,
                                                  uint32_t signal_id)
    {
        re_evidence_blob_t ev{};
        ev.magic = EVIDENCE_MAGIC;
        ev.version = EVIDENCE_VERSION;
        ev.signal_family = family;
        ev.signal_id = signal_id;
        ev.pid = GetCurrentProcessId();
        ev.reserved0 = 0;
        ev.caller_image_hash = module_image_hash();

        uint32_t score = 0;
        uint32_t families_hit = 0;
        for (int bit = 0; bit < 32; ++bit)
        {
            if ((mask & (1u << bit)) == 0) continue;
            const auto& d = signals(1u << bit);
            score += d.weight;
            families_hit |= d.family;
        }
        ev.score = score;

        uint64_t sh = hash_evidence(mask);
        sh ^= static_cast<uint64_t>(families_hit) * 0x9E3779B97F4A7C15ULL;
        ev.signals_bitmap_hash = sh;
        ev.timestamp = __rdtsc();
        return ev;
    }

    inline uint32_t family_from_signal_bit(uint32_t bit)
    {
        return signals(bit).family;
    }

    inline uint32_t collect_signals()
    {
        uint32_t mask = 0;

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

        if (detect_debug_attach_thread())
            mask |= SIGNAL_DBGUI_BREAKIN;

        if (detect_text_writable())
            mask |= SIGNAL_TEXT_WRITABLE;

        if (detect_process_debug_handle())
            mask |= SIGNAL_PROC_DEBUG_HANDLE;

        if (detect_thread_suspended())
            mask |= SIGNAL_THREAD_SUSPENDED;

        if (detect_veh_tampered())
            mask |= SIGNAL_VEH_TAMPERED;

        if (detect_debug_reattach())
            mask |= SIGNAL_DEBUG_REATTACH;

        if (detect_kd_targeting_us())
            mask |= SIGNAL_KD_TARGETING_US;

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

    static std::atomic<uint32_t> s_tick_num{0};
    uint32_t tn = s_tick_num.fetch_add(1);
    {

        uint32_t _sc = 0, _fam = 0; int _fc = 0;
        for (int _b = 0; _b < 32; ++_b) {
            if ((mask & (1u << _b)) == 0) continue;
            const auto& _d = signals(1u << _b);
            _sc += _d.weight;
            if ((_fam & _d.family) == 0) { _fam |= _d.family; ++_fc; }
        }
        bool _dev = detail::is_devmode_hwid_allowlisted();
        bool _exc = _sc >= THRESHOLD_CONFIRMED && _fc >= 2;
        char tb[192];
        _snprintf_s(tb, sizeof(tb), _TRUNCATE,
            "re_tick tick=%u mask=0x%X score=%u families=%d threshold=%u exceeds=%d devmode=%d",
            tn, mask, _sc, _fc, THRESHOLD_CONFIRMED, (int)_exc, (int)_dev);
        webhook::write_log("re_tick", tb);
    }

    uint32_t prev = s.persist_mask.load();
    uint32_t intersect = prev & mask;
    if (intersect != 0) {
        uint32_t c = s.persist_count.fetch_add(1) + 1;
        {
            char pb[128];
            _snprintf_s(pb, sizeof(pb), _TRUNCATE,
                "re_persist intersect=0x%X count=%u persistence_ticks=%u should_bsod=%d",
                intersect, c, PERSISTENCE_TICKS, (int)should_bsod(intersect));
            webhook::write_log("re_tick", pb);
        }
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
                if (intersect & SIGNAL_DR_SET)                reason = 0x0000D7D7u;
                else if (intersect & SIGNAL_DEBUG_PORT)        reason = 0x0000DBDBu;
                else if (intersect & SIGNAL_FOREIGN_HANDLE)    reason = 0x0000AD7Du;
                else if (intersect & SIGNAL_INJECTED_MODULE)   reason = 0x0000114Du;
                else if (intersect & SIGNAL_DEBUG_ATTACH)      reason = 0x0000DBDBu;
                else if (intersect & SIGNAL_PROC_DEBUG_HANDLE) reason = 0x0000DBDBu;
                else if (intersect & SIGNAL_TEXT_WRITABLE)     reason = 0x0000D7ECu;
                else if (intersect & SIGNAL_KD_TARGETING_US)   reason = 0x00007A63u;
                driver_bridge::latch_targeting_from_usermode(reason);
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

inline int __declspec(noinline) seh_tick_wrapper()
{
    __try {
        tick();
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<int>(GetExceptionCode());
    }
}

inline void worker_loop()
{
    Sleep(2000);
    auto& s = state_ref();
    while (s.running.load()) {
        int rc = seh_tick_wrapper();
        if (rc != 0) {
            char tb[64];
            _snprintf_s(tb, sizeof(tb), _TRUNCATE, "seh_crash code=0x%X", rc);
            webhook::write_log("re_worker", tb);
        }
        Sleep(TICK_INTERVAL_MS);
    }
}

inline int __declspec(noinline) seh_watchdog_step(
    engine_state_t* s, state::runtime_t* rt, uint64_t* last_counter)
{
    __try {
        uint64_t current = s->verify_counter.load();
        bool monitors_ok = rt->monitors_running.load();
        bool advanced = current != *last_counter;
        if (!advanced || !monitors_ok) {
            uint32_t mask = detail::collect_signals();
            if (detail::score_exceeds_threshold(mask)) {
                *last_counter = current;
                return static_cast<int>(mask);
            }
        }
        *last_counter = current;
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -static_cast<int>(GetExceptionCode());
    }
}

inline void watchdog_loop()
{
    auto& s = state_ref();
    auto& rt = state::get();
    uint64_t last_counter = 0;
    while (s.running.load()) {
        Sleep(2000);
        int rc = seh_watchdog_step(&s, &rt, &last_counter);
        if (rc < 0) {
            char tb[64];
            _snprintf_s(tb, sizeof(tb), _TRUNCATE, "seh_crash code=0x%X", -rc);
            webhook::write_log("re_watchdog", tb);
        } else if (rc > 0) {
            uint32_t mask = static_cast<uint32_t>(rc);
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
}

inline void initialize()
{
    auto& s = state_ref();
    if (s.running.exchange(true))
        return;

    if (!state::get().veh_baseline_captured.load(std::memory_order_acquire))
    {
        auto ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
            using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto NtQIP = reinterpret_cast<NtQIP_t>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
            if (NtQIP)
            {
                ULONG count = 0;
                LONG st = NtQIP(GetCurrentProcess(), 83,
                    &count, sizeof(count), nullptr);
                if (st >= 0)
                {
                    state::get().veh_baseline_count = count;
                    state::get().veh_baseline_captured.store(
                        true, std::memory_order_release);
                }
            }
        }
    }

    try
    {
        s.worker = std::thread(worker_loop);
        s.worker.detach();
    }
    catch (...) {}

    try
    {
        s.watchdog = std::thread(watchdog_loop);
        s.watchdog.detach();
    }
    catch (...) {}
}

inline void shutdown()
{
    auto& s = state_ref();
    s.running.store(false);
}

}
}
