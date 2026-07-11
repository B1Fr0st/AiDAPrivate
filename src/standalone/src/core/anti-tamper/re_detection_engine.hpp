#pragma once

#include <windows.h>
#include <intrin.h>
#include <psapi.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "enforcement.hpp"
#include "anti_debug.hpp"
#include "dr_check.hpp"
#include "kernel_adbg_classifier.hpp"
#include "standalone_driver.hpp"
#include "standalone_license.hpp"
#include "self_guard.hpp"
#include "../infra/win_thread.hpp"

extern "C" IMAGE_DOS_HEADER __ImageBase;

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
constexpr uint32_t SIGNAL_INT3_BREAKPOINT  = 1u << 20;
constexpr uint32_t SIGNAL_VTABLE_HOOKED         = 1u << 23;
constexpr uint32_t SIGNAL_KERNEL_CALLBACK_HOOKED = 1u << 24;
constexpr uint32_t SIGNAL_SELF_HOOK_DETECTED     = 1u << 25;
constexpr uint32_t SIGNAL_PROLOGUE_SERVER_MISMATCH = 1u << 26;

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
    uint32_t signal_count;
    uint32_t pid;
    uint32_t reserved0;
    uint64_t caller_image_hash;
    uint64_t signals_bitmap_hash;
    uint64_t timestamp;
};

constexpr uint32_t TICK_INTERVAL_MS    = 500;

struct signal_desc_t
{
    uint32_t bit;
    uint32_t family;
    const char* name;
};

inline const signal_desc_t& signals(uint32_t bit)
{
    static const signal_desc_t table[] = {
        { SIGNAL_FOREIGN_HANDLE, FAMILY_HANDLE, "foreign_handle" },
        { SIGNAL_INJECTED_MODULE, FAMILY_INJECTION, "injected_module" },
        { SIGNAL_KERNEL_DEBUG, FAMILY_KDEBUG, "kernel_debug" },
        { SIGNAL_DR_SET, FAMILY_DR, "hardware_breakpoint" },
        { SIGNAL_DEBUG_PORT, FAMILY_DPORT, "debug_port" },
        { SIGNAL_PEB_CLASSIC, FAMILY_CLASSIC, "peb_debug_flags" },
        { SIGNAL_API_IS_DBG, FAMILY_CLASSIC, "debugger_api" },
        { SIGNAL_DEBUG_ATTACH, FAMILY_ATTACH, "debug_attach" },
        { SIGNAL_DBGUI_BREAKIN, FAMILY_ATTACH, "dbgui_breakin" },
        { SIGNAL_TEXT_WRITABLE, FAMILY_MEMORY, "text_writable" },
        { SIGNAL_PROC_DEBUG_HANDLE, FAMILY_DPORT_X, "process_debug_handle" },
        { SIGNAL_THREAD_SUSPENDED, FAMILY_TARGET, "thread_suspended" },
        { SIGNAL_VEH_TAMPERED, FAMILY_INJECTION, "veh_tampered" },
        { SIGNAL_DEBUG_REATTACH, FAMILY_ATTACH, "debug_reattach" },
        { SIGNAL_INT3_BREAKPOINT, FAMILY_MEMORY, "int3_breakpoint" },
        { SIGNAL_KD_TARGETING_US, FAMILY_KDEBUG, "kernel_debug_targeting_us" },
    };
    static const signal_desc_t zero = { 0, 0, "unknown" };
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
    std::atomic<DWORD> worker_tid{ 0 };
    std::atomic<DWORD> watchdog_tid{ 0 };
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

    struct foreign_handle_observation_t
    {
        bool valid = false;
        DWORD self_pid = 0;
        DWORD owner_pid = 0;
        ULONG_PTR handle_value = 0;
        ACCESS_MASK access = 0;
        bool high_risk = false;
        uint32_t ordinal = 0;
        uint64_t tsc = 0;
        std::string owner_image;
        std::string owner_path;
    };

    inline std::mutex& foreign_handle_observation_mutex()
    {
        static std::mutex m;
        return m;
    }

    inline foreign_handle_observation_t& foreign_handle_observation_ref()
    {
        static foreign_handle_observation_t o;
        return o;
    }

    inline std::string basename_from_path(const std::string& path)
    {
        const char* slash = std::strrchr(path.c_str(), '\\');
        if (slash && slash[1])
            return std::string(slash + 1);
        const char* fslash = std::strrchr(path.c_str(), '/');
        return fslash && fslash[1] ? std::string(fslash + 1) : path;
    }

    inline std::string process_image_path_for_log(DWORD pid)
    {
        char path[MAX_PATH] = {};
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hp)
            return "?";
        DWORD len = static_cast<DWORD>(sizeof(path));
        BOOL ok = QueryFullProcessImageNameA(hp, 0, path, &len);
        CloseHandle(hp);
        if (!ok || len == 0)
            return "?";
        return std::string(path);
    }

    inline std::string process_image_for_log(DWORD pid)
    {
        std::string path = process_image_path_for_log(pid);
        return path == "?" ? path : basename_from_path(path);
    }

    inline void store_foreign_handle_observation(DWORD owner_pid,
                                                 ULONG_PTR handle_value,
                                                 ACCESS_MASK access,
                                                 bool high_risk,
                                                 uint32_t ordinal,
                                                 const std::string& owner_path,
                                                 const std::string& owner_image)
    {
        std::lock_guard<std::mutex> lock(foreign_handle_observation_mutex());
        auto& obs = foreign_handle_observation_ref();
        obs.valid = true;
        obs.self_pid = GetCurrentProcessId();
        obs.owner_pid = owner_pid;
        obs.handle_value = handle_value;
        obs.access = access;
        obs.high_risk = high_risk;
        obs.ordinal = ordinal;
        obs.tsc = __rdtsc();
        obs.owner_path = owner_path;
        obs.owner_image = owner_image;
    }

    inline foreign_handle_observation_t last_foreign_handle_observation()
    {
        std::lock_guard<std::mutex> lock(foreign_handle_observation_mutex());
        return foreign_handle_observation_ref();
    }

    inline bool streq_ci(const char* a, const char* b)
    {
        return a && b && _stricmp(a, b) == 0;
    }

    inline bool path_has_dir_prefix_ci(const std::string& path, const std::string& dir)
    {
        if (path.empty() || path == "?" || dir.empty())
            return false;
        size_t n = dir.size();
        while (n > 0 && (dir[n - 1] == '\\' || dir[n - 1] == '/'))
            --n;
        if (path.size() <= n)
            return false;
        if (_strnicmp(path.c_str(), dir.c_str(), n) != 0)
            return false;
        return path[n] == '\\' || path[n] == '/';
    }

    inline std::string lower_path_copy(std::string value)
    {
        for (char& ch : value)
        {
            if (ch >= 'A' && ch <= 'Z')
                ch = static_cast<char>(ch - 'A' + 'a');
            else if (ch == '/')
                ch = '\\';
        }
        return value;
    }

    inline bool trusted_windows_system_owner(const foreign_handle_observation_t& obs)
    {
        if (!obs.valid || obs.owner_path.empty() || obs.owner_path == "?")
            return false;
        const char* image = obs.owner_image.c_str();
        const bool core_image =
            streq_ci(image, "lsass.exe") ||
            streq_ci(image, "csrss.exe") ||
            streq_ci(image, "wininit.exe") ||
            streq_ci(image, "services.exe") ||
            streq_ci(image, "svchost.exe") ||
            streq_ci(image, "winlogon.exe") ||
            streq_ci(image, "smss.exe");
        if (!core_image)
            return false;

        char system_dir[MAX_PATH] = {};
        const UINT system_len = GetSystemDirectoryA(system_dir, MAX_PATH);
        if (system_len > 0 && system_len < MAX_PATH &&
            path_has_dir_prefix_ci(obs.owner_path, std::string(system_dir)))
            return true;
        return false;
    }

    inline bool passive_system_handle_access(ACCESS_MASK access)
    {
        constexpr ACCESS_MASK ACTIVE_MUTATION =
            PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_SET_INFORMATION |
            PROCESS_SUSPEND_RESUME;
        return (access & ACTIVE_MUTATION) == 0;
    }

    inline std::string format_handle_access_flags(ACCESS_MASK access)
    {
        std::string flags;
        auto add = [&flags](const char* name) {
            if (!flags.empty())
                flags += "|";
            flags += name;
        };
        if (access & PROCESS_TERMINATE) add("terminate");
        if (access & PROCESS_CREATE_THREAD) add("create_thread");
        if (access & PROCESS_VM_OPERATION) add("vm_operation");
        if (access & PROCESS_VM_READ) add("vm_read");
        if (access & PROCESS_VM_WRITE) add("vm_write");
        if (access & PROCESS_DUP_HANDLE) add("dup_handle");
        if (access & PROCESS_SET_INFORMATION) add("set_information");
        if (access & PROCESS_QUERY_INFORMATION) add("query_information");
        if (access & PROCESS_SUSPEND_RESUME) add("suspend_resume");
        if (access & PROCESS_QUERY_LIMITED_INFORMATION) add("query_limited");
        return flags.empty() ? "none" : flags;
    }

    inline void log_foreign_handle_observation(DWORD owner_pid,
                                               ULONG_PTR handle_value,
                                               ACCESS_MASK access,
                                               bool high_risk)
    {
        static std::atomic<uint32_t> s_log_count{0};
        uint32_t n = s_log_count.fetch_add(1, std::memory_order_acq_rel);
        if (!high_risk && n >= 32 && (n % 256) != 0)
            return;
        std::string path = process_image_path_for_log(owner_pid);
        std::string image = path == "?" ? "?" : basename_from_path(path);
        uint32_t ordinal = n + 1;
        store_foreign_handle_observation(owner_pid, handle_value, access,
            high_risk, ordinal, path, image);
        const std::string flags = format_handle_access_flags(access);
        char buf[768];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "foreign_handle_observed self_pid=%lu owner_pid=%lu owner=%s owner_path='%s' handle=0x%llX access=0x%08lX access_flags=%s high_risk=%d ordinal=%u",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(owner_pid),
            image.c_str(),
            path.c_str(),
            static_cast<unsigned long long>(handle_value),
            static_cast<unsigned long>(access),
            flags.c_str(),
            high_risk ? 1 : 0,
            ordinal);
        webhook::write_log("re_handle_probe", buf);
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
        constexpr ACCESS_MASK HIGH_RISK =
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
            PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION |
            PROCESS_VM_OPERATION;
        constexpr ACCESS_MASK OBSERVE_ONLY =
            PROCESS_VM_READ | PROCESS_DUP_HANDLE;
        constexpr ACCESS_MASK INTERESTING = HIGH_RISK | OBSERVE_ONLY;

        for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
            const auto& h = info->Handles[i];
            if (static_cast<DWORD>(h.UniqueProcessId) == my_pid) continue;
            if ((h.GrantedAccess & INTERESTING) == 0) continue;

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
                std::string owner_path = process_image_path_for_log(static_cast<DWORD>(h.UniqueProcessId));
                std::string owner_image = owner_path == "?" ? "?" : basename_from_path(owner_path);
                const bool high_risk = (h.GrantedAccess & HIGH_RISK) != 0;
                log_foreign_handle_observation(
                    static_cast<DWORD>(h.UniqueProcessId),
                    h.HandleValue,
                    h.GrantedAccess,
                    high_risk);
                if (high_risk)
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
            L"frida", L"detours64.dll", L"minhook", L"polyhook", L"easyhook",
            L"scyllahide", L"hooklibraryx64", L"hooklibrary",
            L"titanhide", L"hyperhide", L"strongod", L"sharpod",
            L"apimonitor", L"wpe pro", L"cheatengine"
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

    inline bool detect_int3_breakpoints()
    {
        auto& rt = state::get();
        if (rt.code_snap.text_base == 0 || rt.code_snap.text_size == 0)
            return false;
        if (rt.code_snap.module_base == 0)
            return false;

        const UINT8* module_base = reinterpret_cast<const UINT8*>(rt.code_snap.module_base);

        const DWORD e_lfanew = *reinterpret_cast<const DWORD*>(module_base + 0x3C);
        if (e_lfanew <= 0 || e_lfanew > 0x100000)
            return false;

        const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(module_base + e_lfanew);
        if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
            return false;
        if (nt_hdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;
        if (nt_hdrs->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            return false;

        const auto& exc_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc_dir.VirtualAddress == 0 || exc_dir.Size == 0)
            return false;

        const UINT32 func_count = exc_dir.Size / 12;
        if (func_count == 0)
            return false;

        static std::atomic<uint32_t> scan_rotation{0};
        const uint32_t batch_idx = scan_rotation.fetch_add(1, std::memory_order_relaxed);
        const uint32_t per_tick = (func_count + 7) / 8;
        const uint32_t start = (batch_idx * per_tick) % func_count;

        const RUNTIME_FUNCTION* rf_base = reinterpret_cast<const RUNTIME_FUNCTION*>(
            module_base + exc_dir.VirtualAddress);

        for (uint32_t i = 0; i < per_tick; ++i)
        {
            const uint32_t idx = (start + i) % func_count;
            const RUNTIME_FUNCTION* rf = rf_base + idx;
            const UINT8* entry_ptr = module_base + rf->BeginAddress;

            if (reinterpret_cast<uint64_t>(entry_ptr) < rt.code_snap.module_base ||
                reinterpret_cast<uint64_t>(entry_ptr) >= rt.code_snap.module_end)
                continue;

            const UINT8 current_byte = *entry_ptr;
            if (current_byte == 0xCC)
            {
                uint8_t orig_byte = 0;
                const uint64_t rva = rf->BeginAddress;
                if (rva < rt.code_snap.text_size)
                {
                    const UINT8* text_base_ptr = reinterpret_cast<const UINT8*>(rt.code_snap.text_base);
                    const uint64_t text_rva = rva - (rt.code_snap.text_base - rt.code_snap.module_base);
                    if (text_rva < rt.code_snap.text_size)
                        orig_byte = text_base_ptr[text_rva];
                }

                if (orig_byte != 0xCC)
                {
                    char buf[192];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "int3_breakpoint_detected rva=0x%X module_base=0x%llX orig_byte=0x%02X current_byte=0xCC",
                        rf->BeginAddress,
                        static_cast<unsigned long long>(rt.code_snap.module_base),
                        orig_byte);
                    webhook::write_log("re_int3", buf);

                    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
                    {
                        driver_bridge::trigger_kernel_bsod(0xA1DA0002,
                            (uint64_t)rf->BeginAddress | (0xCCULL << 32));
                    }
                    return true;
                }
            }
        }
        return false;
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
        if (anti_tamper::state::get().full_test_running.load(std::memory_order_acquire)) {
            static std::atomic<uint32_t> s_skip_logs{0};
            const uint32_t n = s_skip_logs.fetch_add(1, std::memory_order_acq_rel);
            if (n < 8 || (n % 128) == 0)
                webhook::write_log("re_thread_probe", "thread_suspended_probe_skipped_full_test");
            return false;
        }
        uint64_t suppression_remaining = 0;
        if (anti_tamper::state::full_test_suppression_active(&suppression_remaining)) {
            static std::atomic<uint32_t> s_post_skip_logs{0};
            const uint32_t n = s_post_skip_logs.fetch_add(1, std::memory_order_acq_rel);
            if (n < 8 || (n % 128) == 0) {
                char sb[128];
                _snprintf_s(sb, sizeof(sb), _TRUNCATE,
                    "thread_suspended_probe_skipped_post_full_test remaining_ms=%llu",
                    static_cast<unsigned long long>(suppression_remaining));
                webhook::write_log("re_thread_probe", sb);
            }
            return false;
        }

        static std::atomic_flag s_probe_active = ATOMIC_FLAG_INIT;
        if (s_probe_active.test_and_set(std::memory_order_acq_rel)) {
            static std::atomic<uint32_t> s_concurrent_logs{0};
            const uint32_t n = s_concurrent_logs.fetch_add(1, std::memory_order_acq_rel);
            if (n < 8 || (n % 128) == 0)
                webhook::write_log("re_thread_probe", "thread_suspended_probe_skipped_concurrent_probe");
            return false;
        }
        struct probe_guard_t {
            std::atomic_flag& flag;
            ~probe_guard_t() { flag.clear(std::memory_order_release); }
        } guard{ s_probe_active };

        struct unicode_string_local_t {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR Buffer;
        };
        struct system_process_information_local_t {
            ULONG NextEntryOffset;
            ULONG NumberOfThreads;
            UCHAR Reserved1[48];
            unicode_string_local_t ImageName;
            LONG BasePriority;
            HANDLE UniqueProcessId;
            PVOID Reserved2;
            ULONG HandleCount;
            ULONG SessionId;
            PVOID Reserved3;
            SIZE_T PeakVirtualSize;
            SIZE_T VirtualSize;
            ULONG Reserved4;
            SIZE_T PeakWorkingSetSize;
            SIZE_T WorkingSetSize;
            PVOID Reserved5;
            SIZE_T QuotaPagedPoolUsage;
            PVOID Reserved6;
            SIZE_T QuotaNonPagedPoolUsage;
            SIZE_T PagefileUsage;
            SIZE_T PeakPagefileUsage;
            SIZE_T PrivatePageCount;
            LARGE_INTEGER Reserved7[6];
        };
        struct client_id_local_t {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        };
        struct system_thread_information_local_t {
            LARGE_INTEGER Reserved1[3];
            ULONG Reserved2;
            PVOID StartAddress;
            client_id_local_t ClientId;
            LONG Priority;
            LONG BasePriority;
            ULONG Reserved3;
            ULONG ThreadState;
            ULONG WaitReason;
        };
        static_assert(sizeof(system_process_information_local_t) == 256, "Unexpected system process information size");
        static_assert(sizeof(system_thread_information_local_t) == 80, "Unexpected system thread information size");

        if (!syscall::is_initialized())
            return false;

        DWORD pid = GetCurrentProcessId();
        DWORD main_tid = GetCurrentThreadId();
        auto& eng = state_ref();
        const DWORD worker_tid = eng.worker_tid.load(std::memory_order_acquire);
        const DWORD watchdog_tid = eng.watchdog_tid.load(std::memory_order_acquire);
        int suspended_count = 0;
        int total_threads = 0;
        int critical_suspended = 0;
        char sample[512] = {};
        size_t sample_len = 0;

        ULONG buffer_size = 1024 * 1024;
        ULONG return_length = 0;
        std::vector<uint8_t> buffer(buffer_size);
        NTSTATUS st = syscall::NtQuerySystemInformation()(
            5, buffer.data(), buffer_size, &return_length);
        for (int attempt = 0;
             st == static_cast<NTSTATUS>(0xC0000004) && attempt < 3;
             ++attempt)
        {
            buffer_size = return_length > buffer_size ? return_length + 65536 : buffer_size * 2;
            buffer.assign(buffer_size, 0);
            return_length = 0;
            st = syscall::NtQuerySystemInformation()(
                5, buffer.data(), buffer_size, &return_length);
        }
        if (st < 0) {
            static std::atomic<uint32_t> s_query_fail_logs{0};
            const uint32_t n = s_query_fail_logs.fetch_add(1, std::memory_order_acq_rel);
            if (n < 8 || (n % 128) == 0) {
                char qb[160];
                _snprintf_s(qb, sizeof(qb), _TRUNCATE,
                    "thread_suspended_probe_query_failed status=0x%08lX return_length=%lu buffer_size=%lu",
                    static_cast<unsigned long>(st),
                    static_cast<unsigned long>(return_length),
                    static_cast<unsigned long>(buffer_size));
                webhook::write_log("re_thread_probe", qb);
            }
            return false;
        }

        uint8_t* cursor = buffer.data();
        uint8_t* end = buffer.data() + buffer.size();
        bool found_process = false;
        for (uint32_t process_guard = 0;
             static_cast<size_t>(end - cursor) >= sizeof(system_process_information_local_t) && process_guard < 131072;
             ++process_guard)
        {
            auto* info = reinterpret_cast<system_process_information_local_t*>(cursor);
            if (static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info->UniqueProcessId)) == pid) {
                found_process = true;
                const size_t max_threads =
                    (static_cast<size_t>(end - cursor) > sizeof(system_process_information_local_t))
                        ? (static_cast<size_t>(end - cursor) - sizeof(system_process_information_local_t)) / sizeof(system_thread_information_local_t)
                        : 0;
                const ULONG thread_count = info->NumberOfThreads <= max_threads
                    ? info->NumberOfThreads
                    : static_cast<ULONG>(max_threads);
                auto* threads = reinterpret_cast<system_thread_information_local_t*>(
                    cursor + sizeof(system_process_information_local_t));
                for (ULONG i = 0; i < thread_count; ++i) {
                    const DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread));
                    if (tid == 0 || tid == main_tid)
                        continue;
                    ++total_threads;
                    const bool suspended_wait =
                        threads[i].ThreadState == 5 &&
                        (threads[i].WaitReason == 5 || threads[i].WaitReason == 12);
                    if (!suspended_wait)
                        continue;
                    ++suspended_count;
                    const bool critical =
                        (worker_tid != 0 && tid == worker_tid) ||
                        (watchdog_tid != 0 && tid == watchdog_tid);
                    if (critical)
                        ++critical_suspended;
                    if (sample_len < sizeof(sample) - 1) {
                        const char* role =
                            tid == worker_tid ? "re_worker" :
                            (tid == watchdog_tid ? "re_watchdog" : "app");
                        char one[96];
                        _snprintf_s(one, sizeof(one), _TRUNCATE,
                            "%s%lu:%lu/%lu:%s",
                            sample_len == 0 ? "" : ",",
                            static_cast<unsigned long>(tid),
                            static_cast<unsigned long>(threads[i].ThreadState),
                            static_cast<unsigned long>(threads[i].WaitReason),
                            role);
                        const size_t one_len = strlen(one);
                        const size_t room = sizeof(sample) - sample_len - 1;
                        const size_t copy_len = one_len < room ? one_len : room;
                        if (copy_len != 0) {
                            memcpy(sample + sample_len, one, copy_len);
                            sample_len += copy_len;
                            sample[sample_len] = '\0';
                        }
                    }
                }
                break;
            }
            if (info->NextEntryOffset == 0)
                break;
            const size_t remaining = static_cast<size_t>(end - cursor);
            if (info->NextEntryOffset < sizeof(system_process_information_local_t) ||
                info->NextEntryOffset > remaining)
                break;
            cursor += info->NextEntryOffset;
        }
        if (!found_process)
            return false;

        if (total_threads < 2)
            return false;

        static std::atomic<uint32_t> s_candidate_hits{0};
        static std::atomic<uint64_t> s_candidate_until{0};
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());

        if (suspended_count == 0) {
            const uint32_t prior_hits = s_candidate_hits.exchange(0, std::memory_order_acq_rel);
            const uint64_t prior_until = s_candidate_until.exchange(0, std::memory_order_acq_rel);
            if (prior_hits != 0) {
                char rb[192];
                _snprintf_s(rb, sizeof(rb), _TRUNCATE,
                    "thread_suspended_probe_clean_reset total=%d prior_hits=%u prior_until=%llu worker_tid=%lu watchdog_tid=%lu",
                    total_threads,
                    prior_hits,
                    static_cast<unsigned long long>(prior_until),
                    static_cast<unsigned long>(worker_tid),
                    static_cast<unsigned long>(watchdog_tid));
                webhook::write_log("re_thread_probe", rb);
            }
            return false;
        }

        const bool high_ratio = total_threads >= 4 && suspended_count * 4 >= total_threads * 3;
        const bool high_count = suspended_count >= 6;
        const bool critical = critical_suspended > 0;
        const bool candidate = critical || high_ratio || high_count;
        uint64_t trusted_remaining = 0;
        uint32_t trusted_depth = 0;
        if (candidate &&
            critical_suspended == 0 &&
            anti_tamper::state::trusted_thread_suspension_window_active(&trusted_remaining, &trusted_depth)) {
            s_candidate_hits.store(0, std::memory_order_release);
            s_candidate_until.store(0, std::memory_order_release);
            char tb[896];
            _snprintf_s(tb, sizeof(tb), _TRUNCATE,
                "thread_suspended_probe_skipped_trusted_internal total=%d suspended=%d critical=%d high_ratio=%d high_count=%d candidate=%d active_depth=%u remaining_ms=%llu worker_tid=%lu watchdog_tid=%lu sample=%s",
                total_threads,
                suspended_count,
                critical_suspended,
                high_ratio ? 1 : 0,
                high_count ? 1 : 0,
                candidate ? 1 : 0,
                trusted_depth,
                static_cast<unsigned long long>(trusted_remaining),
                static_cast<unsigned long>(worker_tid),
                static_cast<unsigned long>(watchdog_tid),
                sample_len != 0 ? sample : "none");
            webhook::write_log("re_thread_probe", tb);
            return false;
        }
        uint32_t hits = 0;
        uint32_t required_hits = candidate ? 2u : 0u;
        const uint64_t until = s_candidate_until.load(std::memory_order_acquire);
        if (candidate) {
            if (now >= until) {
                s_candidate_hits.store(1, std::memory_order_release);
                s_candidate_until.store(now + 5000, std::memory_order_release);
                hits = 1;
            } else {
                hits = s_candidate_hits.fetch_add(1, std::memory_order_acq_rel) + 1;
                s_candidate_until.store(now + 5000, std::memory_order_release);
            }
        } else {
            s_candidate_hits.store(0, std::memory_order_release);
            s_candidate_until.store(0, std::memory_order_release);
        }
        const bool enforce = required_hits != 0 && hits >= required_hits;

        char buf[896];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "thread_suspended_probe_sample total=%d suspended=%d critical=%d high_ratio=%d high_count=%d candidate=%d hits=%u required=%u window_ms=5000 enforce=%d worker_tid=%lu watchdog_tid=%lu sample=%s",
            total_threads,
            suspended_count,
            critical_suspended,
            high_ratio ? 1 : 0,
            high_count ? 1 : 0,
            candidate ? 1 : 0,
            hits,
            required_hits,
            enforce ? 1 : 0,
            static_cast<unsigned long>(worker_tid),
            static_cast<unsigned long>(watchdog_tid),
            sample_len != 0 ? sample : "none");
        webhook::write_log("re_thread_probe", buf);

        return enforce;
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

        uint32_t signal_count = 0;
        uint32_t families_hit = 0;
        for (int bit = 0; bit < 32; ++bit)
        {
            if ((mask & (1u << bit)) == 0) continue;
            const auto& d = signals(1u << bit);
            ++signal_count;
            families_hit |= d.family;
        }
        ev.signal_count = signal_count;

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

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver() && driver_bridge::dynamic_ioctls_ready()) {
            driver_bridge::anti_debug_result_t ar{};
            const bool query_ok = driver_bridge::kernel_anti_debug_query(ar);
            auto in = query_ok
                ? kernel_adbg::make_input(ar, "re_tick", "collect_signals")
                : kernel_adbg::input_t{};
            if (!query_ok) {
                in.native = kernel_adbg::query_native_kernel_debugger_state();
                in.phase = "re_tick";
                in.source = "collect_signals";
            }
            uint64_t scan_pid = 0;
            if (!query_ok || ar.result_flags != 0 || ar.detected_debugger_pid != 0 || in.native.active) {
                in.scan_sampled = true;
                in.scan_ok = driver_bridge::kernel_anti_debug_scan_debuggers(&scan_pid);
                in.scan_pid = scan_pid;
            }
            const auto decision = kernel_adbg::classify(in);
            if (!query_ok || ar.result_flags != 0 || ar.detected_debugger_pid != 0 || scan_pid != 0 || in.native.active || decision.enforce) {
                const std::string decision_line = kernel_adbg::format_decision(in, decision);
                webhook::write_log("re_tick", decision_line.c_str());
            }
            if (decision.enforce)
                mask |= SIGNAL_KERNEL_DEBUG;
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

        if (detect_int3_breakpoints())
            mask |= SIGNAL_INT3_BREAKPOINT;

        return mask;
    }

    inline bool has_confirmed_signal(uint32_t mask)
    {
        for (int bit = 0; bit < 32; ++bit) {
            if ((mask & (1u << bit)) == 0) continue;
            const auto& d = signals(1u << bit);
            if (d.bit != 0)
                return true;
        }
        return false;
    }

    inline std::string describe_signals(uint32_t mask)
    {
        std::string names;
        for (int bit = 0; bit < 32; ++bit) {
            if ((mask & (1u << bit)) == 0) continue;
            const auto& d = signals(1u << bit);
            if (d.bit == 0) continue;
            if (!names.empty())
                names += ",";
            names += d.name;
        }
        return names.empty() ? "none" : names;
    }

    inline std::string format_signal_detail(uint32_t mask, uint64_t evidence)
    {
        char buf[192];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "mask=0x%08X evidence=0x%016llX signals=%s",
            mask,
            static_cast<unsigned long long>(evidence),
            describe_signals(mask).c_str());
        return std::string(buf);
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

    inline bool foreign_handle_only(uint32_t mask)
    {
        return (mask & SIGNAL_FOREIGN_HANDLE) != 0 &&
            (mask & ~SIGNAL_FOREIGN_HANDLE) == 0;
    }

    inline bool foreign_handle_only_should_enforce(uint32_t mask,
                                                   const char* path,
                                                   const std::string& detail_str)
    {
        if (!foreign_handle_only(mask))
            return true;

        const foreign_handle_observation_t obs = last_foreign_handle_observation();
        const bool trusted_system = trusted_windows_system_owner(obs);
        const bool passive_system_access =
            obs.valid && trusted_system && passive_system_handle_access(obs.access);
        const bool kernel_ready =
            driver_bridge::is_loaded() &&
            driver_bridge::using_kernel_driver() &&
            driver_bridge::dynamic_ioctls_ready();
        driver_bridge::anti_debug_result_t query{};
        bool query_ok = false;
        uint64_t scan_pid = 0;
        bool scan_ok = false;
        bool confirmed = false;
        if (kernel_ready) {
            query_ok = driver_bridge::kernel_anti_debug_query(query);
            scan_ok = driver_bridge::kernel_anti_debug_scan_debuggers(&scan_pid);
            auto in = query_ok
                ? kernel_adbg::make_input(query, path ? path : "re_detect", "foreign_handle_confirmation")
                : kernel_adbg::input_t{};
            if (!query_ok) {
                in.native = kernel_adbg::query_native_kernel_debugger_state();
                in.phase = path ? path : "re_detect";
                in.source = "foreign_handle_confirmation";
            }
            in.scan_sampled = true;
            in.scan_ok = scan_ok;
            in.scan_pid = scan_pid;
            in.corroborated_hard_signals = mask & ~SIGNAL_FOREIGN_HANDLE;
            const auto decision = kernel_adbg::classify(in);
            const std::string decision_line = kernel_adbg::format_decision(in, decision);
            webhook::write_log(path ? path : "re_detect", decision_line.c_str());
            confirmed = decision.enforce;
        }

        const bool suppress_unconfirmed_system =
            !confirmed && trusted_system && passive_system_access;
        const bool enforce = confirmed;
        const char* decision = confirmed ? "enforce_confirmed_kernel_evidence" :
            (suppress_unconfirmed_system ? "suppress_unconfirmed_trusted_system_handle" :
             (kernel_ready && query_ok && scan_ok ? "suppress_unconfirmed_kernel_clean_foreign_handle" :
              "suppress_unconfirmed_foreign_handle"));
        const std::string flags = obs.valid ? format_handle_access_flags(obs.access) : "none";

        char buf[1152];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "foreign_handle_decision path=%s decision=%s should_bsod=%d kernel_ready=%d confirmed=%d query_ok=%d query_flags=0x%08X query_pid=%llu scan_ok=%d scan_pid=%llu owner_valid=%d self_pid=%lu owner_pid=%lu owner=%s owner_path='%s' handle=0x%llX access=0x%08lX access_flags=%s high_risk=%d trusted_system_owner=%d passive_system_access=%d ordinal=%u %s",
            path ? path : "re_detect",
            decision,
            enforce ? 1 : 0,
            kernel_ready ? 1 : 0,
            confirmed ? 1 : 0,
            query_ok ? 1 : 0,
            query.result_flags,
            static_cast<unsigned long long>(query.detected_debugger_pid),
            scan_ok ? 1 : 0,
            static_cast<unsigned long long>(scan_pid),
            obs.valid ? 1 : 0,
            static_cast<unsigned long>(obs.valid ? obs.self_pid : GetCurrentProcessId()),
            static_cast<unsigned long>(obs.valid ? obs.owner_pid : 0),
            obs.valid ? obs.owner_image.c_str() : "?",
            obs.valid ? obs.owner_path.c_str() : "?",
            static_cast<unsigned long long>(obs.valid ? obs.handle_value : 0),
            static_cast<unsigned long>(obs.valid ? obs.access : 0),
            flags.c_str(),
            obs.valid && obs.high_risk ? 1 : 0,
            trusted_system ? 1 : 0,
            passive_system_access ? 1 : 0,
            obs.valid ? obs.ordinal : 0,
            detail_str.c_str());
        webhook::write_log(path ? path : "re_detect", buf);
        if (!kernel_ready) {
            char legacy[512];
            _snprintf_s(legacy, sizeof(legacy), _TRUNCATE,
                "foreign_handle_no_kernel_confirmation_path path=%s kernel_ready=0 decision=%s should_bsod=%d %s",
                path ? path : "re_detect",
                decision,
                enforce ? 1 : 0,
                detail_str.c_str());
            webhook::write_log(path ? path : "re_detect", legacy);
        } else {
            char legacy[768];
            _snprintf_s(legacy, sizeof(legacy), _TRUNCATE,
                "foreign_handle_kernel_confirmation path=%s confirmed=%d query_ok=%d query_flags=0x%08X query_pid=%llu scan_ok=%d scan_pid=%llu decision=%s should_bsod=%d %s",
                path ? path : "re_detect",
                confirmed ? 1 : 0,
                query_ok ? 1 : 0,
                query.result_flags,
                static_cast<unsigned long long>(query.detected_debugger_pid),
                scan_ok ? 1 : 0,
                static_cast<unsigned long long>(scan_pid),
                decision,
                enforce ? 1 : 0,
                detail_str.c_str());
            webhook::write_log(path ? path : "re_detect", legacy);
        }
        return enforce;
    }
}

inline void tick();

inline void tick()
{
    dr_check::on_gate_call_random_check(0xA1DA0001u);

    auto& s = state_ref();
    s.verify_counter.fetch_add(1);
    s.last_tick_tsc.store(__rdtsc());

    self_guard::verify_self_guard_integrity();

    uint32_t mask = detail::collect_signals();
    s.last_mask.store(mask);

    if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
        driver_bridge::kernel_anti_debug_clear_dr();

        auto& rt = state::get();
        if (rt.code_snap.module_base != 0) {
            __try {
                const UINT8* mod_base = reinterpret_cast<const UINT8*>(rt.code_snap.module_base);
                const DWORD e_lfanew = *reinterpret_cast<const DWORD*>(mod_base + 0x3C);
                if (e_lfanew > 0 && e_lfanew < 0x100000) {
                    const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mod_base + e_lfanew);
                    if (nt_hdrs->Signature == IMAGE_NT_SIGNATURE &&
                        nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                        nt_hdrs->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
                        const auto& exc_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                        if (exc_dir.VirtualAddress != 0 && exc_dir.Size != 0) {
                            uint64_t kernel_hit_rva = 0;
                            driver_bridge::kernel_anti_debug_scan_text(
                                rt.code_snap.module_base,
                                exc_dir.VirtualAddress,
                                exc_dir.Size,
                                &kernel_hit_rva);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    static std::atomic<uint32_t> s_tick_num{0};
    s_tick_num.fetch_add(1);
    if (detail::has_confirmed_signal(mask)) {
        uint64_t evidence = detail::hash_evidence(mask);
        std::string detail_str = detail::format_signal_detail(mask, evidence);
        if (detail::is_devmode_hwid_allowlisted()) {
            char db[256];
            _snprintf_s(db, sizeof(db), _TRUNCATE,
                "re_signal mask=0x%08X should_bsod=0 decision=devmode_allowlist %s",
                mask,
                detail_str.c_str());
            webhook::write_log("re_tick", db);
            s.persist_count.store(0);
            s.persist_mask.store(mask);
            return;
        }
        uint64_t suppression_remaining = 0;
        const bool full_test_active =
            anti_tamper::state::get().full_test_running.load(std::memory_order_acquire);
        const bool post_full_test_suppressed =
            anti_tamper::state::full_test_suppression_active(&suppression_remaining);
        if (full_test_active || post_full_test_suppressed) {
            char sb[96];
            _snprintf_s(sb, sizeof(sb), _TRUNCATE,
                "full_test_signal_suppressed latch=%d post_full_test_ms=%llu decision=full_test_suppressed should_bsod=0 ",
                full_test_active ? 1 : 0,
                static_cast<unsigned long long>(suppression_remaining));
            std::string msg = std::string(sb) + detail_str;
            webhook::write_log("re_tick", msg.c_str());
            s.persist_count.store(0);
            s.persist_mask.store(mask);
            return;
        }
        if (!detail::foreign_handle_only_should_enforce(mask, "re_tick", detail_str)) {
            char rb[256];
            _snprintf_s(rb, sizeof(rb), _TRUNCATE,
                "re_signal mask=0x%08X should_bsod=0 decision=suppressed_foreign_handle %s",
                mask,
                detail_str.c_str());
            webhook::write_log("re_tick", rb);
            s.persist_count.store(0);
            s.persist_mask.store(mask);
            return;
        }
        {
            char pb[256];
            _snprintf_s(pb, sizeof(pb), _TRUNCATE,
                "re_signal mask=0x%08X should_bsod=1 decision=enforce %s",
                mask,
                detail_str.c_str());
            webhook::write_log("re_tick", pb);
        }
        standalone_license::fold_integrity_token(evidence);
        webhook::send_debug_log("re_detect", detail_str, true);
        webhook::post_critical_then_enforce("re_detected", detail_str, mask);
        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
            uint32_t reason = 0x0000DEEEu;
            if (mask & SIGNAL_DR_SET)                reason = 0x0000D7D7u;
            else if (mask & SIGNAL_DEBUG_PORT)        reason = 0x0000DBDBu;
            else if (mask & SIGNAL_FOREIGN_HANDLE)    reason = 0x0000AD7Du;
            else if (mask & SIGNAL_INJECTED_MODULE)   reason = 0x0000114Du;
            else if (mask & SIGNAL_DEBUG_ATTACH)      reason = 0x0000DBDBu;
            else if (mask & SIGNAL_PROC_DEBUG_HANDLE) reason = 0x0000DBDBu;
            else if (mask & SIGNAL_TEXT_WRITABLE)     reason = 0x0000D7ECu;
            else if (mask & SIGNAL_KD_TARGETING_US)   reason = 0x00007A63u;
            else if (mask & SIGNAL_INT3_BREAKPOINT)    reason = 0xA1DA0002u;
            driver_bridge::latch_targeting_from_usermode(reason);
            driver_bridge::trigger_kernel_bsod(reason, evidence);
        }
        enforce_violation("re_detected", detail_str);
        s.persist_count.store(0);
        s.persist_mask.store(0);
        return;
    }
    if ((s_tick_num.load(std::memory_order_relaxed) & 3u) == 0)
    {
        auto& rt = state::get();
        auto dbg = anti_debug::full_scan(rt.code_snap.module_base, rt.code_snap.module_end);
        if (dbg.any_detected())
        {
            uint32_t bug_check = dbg.get_bug_check_code_or(0xA1DA0005u);
            uint64_t evidence = detail::hash_evidence(mask | 0x80000000u);
            std::string detail_str = "periodic_full_scan " + dbg.summary;
            webhook::write_log_critical_fmt("re_tick",
                "periodic_full_scan_detected bug_check=0x%08X summary=%s",
                static_cast<unsigned long>(bug_check),
                dbg.summary.c_str());
            standalone_license::fold_integrity_token(evidence);
            webhook::send_debug_log("re_detect", detail_str, true);
            webhook::post_critical_then_enforce("re_detected_periodic_scan", detail_str, mask);
            if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
            {
                driver_bridge::trigger_kernel_bsod(bug_check, evidence);
            }
            enforce_violation("re_detected_periodic_scan", detail_str);
            s.persist_count.store(0);
            s.persist_mask.store(0);
            return;
        }
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
    auto& s = state_ref();
    s.worker_tid.store(GetCurrentThreadId(), std::memory_order_release);
    Sleep(2000);
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
            if (detail::has_confirmed_signal(mask)) {
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
    s.watchdog_tid.store(GetCurrentThreadId(), std::memory_order_release);
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
            std::string detail_str = "watchdog_stall " + detail::format_signal_detail(mask, evidence);
            uint64_t suppression_remaining = 0;
            const bool full_test_active =
                anti_tamper::state::get().full_test_running.load(std::memory_order_acquire);
            const bool post_full_test_suppressed =
                anti_tamper::state::full_test_suppression_active(&suppression_remaining);
            if (full_test_active || post_full_test_suppressed) {
                char sb[112];
                _snprintf_s(sb, sizeof(sb), _TRUNCATE,
                    "watchdog_signal_suppressed latch=%d post_full_test_ms=%llu decision=full_test_suppressed should_bsod=0 ",
                    full_test_active ? 1 : 0,
                    static_cast<unsigned long long>(suppression_remaining));
                std::string msg = std::string(sb) + detail_str;
                webhook::write_log("re_watchdog", msg.c_str());
                continue;
            }
            if (!detail::foreign_handle_only_should_enforce(mask, "re_watchdog", detail_str))
                continue;
            standalone_license::fold_integrity_token(evidence);
            webhook::send_debug_log("re_watchdog", detail_str, true);
            webhook::post_critical_then_enforce("re_watchdog_stall",
                detail_str, mask);
            if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver()) {
                driver_bridge::trigger_kernel_bsod(0x0000DEDDu, evidence);
            }
            enforce_violation("re_watchdog_stall", detail_str);
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

    std::string worker_error;
    if (!aida::infra::win_thread::start_detached(worker_loop,
            &worker_error,
            aida::infra::win_thread::default_stack_reserve,
            "re_detection_worker"))
    {
        webhook::write_log("re_detect",
            worker_error.empty() ? "worker_start_failed" : worker_error.c_str());
    }

    std::string watchdog_error;
    if (!aida::infra::win_thread::start_detached(watchdog_loop,
            &watchdog_error,
            aida::infra::win_thread::default_stack_reserve,
            "re_detection_watchdog"))
    {
        webhook::write_log("re_detect",
            watchdog_error.empty() ? "watchdog_start_failed" : watchdog_error.c_str());
    }
}

inline void shutdown()
{
    auto& s = state_ref();
    s.running.store(false);
}

}
}
