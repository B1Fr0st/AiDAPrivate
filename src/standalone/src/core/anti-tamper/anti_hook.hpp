#pragma once

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "syscall.hpp"

namespace anti_tamper {
namespace anti_hook {

struct hook_report_t
{
    bool iat_modified = false;
    bool ntdll_inline_hooked = false;
    bool kernel32_inline_hooked = false;
    bool syscall_stubs_modified = false;
    bool eat_hooked = false;
    std::string hooked_function;
    std::string summary;

    bool any_detected() const
    {
        return iat_modified || ntdll_inline_hooked || kernel32_inline_hooked
            || syscall_stubs_modified || eat_hooked;
    }
};

namespace detail {

    inline bool check_inline_hook_bytes(const uint8_t* func, const char* name)
    {
        __try
        {
            if (func[0] == 0xE9)
                return true;

            if (func[0] == 0xFF && func[1] == 0x25)
                return true;

            if (func[0] == 0x48 && func[1] == 0xB8 && func[10] == 0xFF && func[11] == 0xE0)
                return true;

            if (func[0] == 0x68 && func[5] == 0xC3)
                return true;

            if (func[0] == 0xEB)
                return true;

            if (func[0] == 0xCC)
                return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    inline bool verify_syscall_stub(const uint8_t* func)
    {
        __try
        {
            if (func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1)
                return false;

            if (func[3] != 0xB8)
                return false;

            if (func[8] == 0xF6 && func[12] == 0x75)
            {
                return true;
            }

            if (func[8] == 0x0F && func[9] == 0x05)
                return true;

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    struct module_range_t
    {
        uint64_t base;
        uint64_t end;
    };

    inline bool get_module_range(HMODULE mod, module_range_t& range)
    {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
            return false;
        range.base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        range.end = range.base + mi.SizeOfImage;
        return true;
    }

}

namespace detail {

    __declspec(noinline) inline bool safe_read_uint64(uint64_t addr, uint64_t* out)
    {
        __try {
            *out = *reinterpret_cast<const volatile uint64_t*>(addr);
            return true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            *out = 0;
            return false;
        }
    }

}

inline bool verify_iat_entries(const std::vector<state::iat_entry_t>& snapshot)
{
    for (size_t idx = 0; idx < snapshot.size(); ++idx)
    {
        const auto& e = snapshot[idx];

        uint64_t current = 0;
        if (!detail::safe_read_uint64(e.slot_va, &current))
        {
            static int s_iat_exc_logged = 0;
            if (s_iat_exc_logged < 5) {
                ++s_iat_exc_logged;
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "iat_read_exception slot_va=0x%llX idx=%zu",
                    e.slot_va, idx);
                webhook::write_log("iat_hook", dbg);
            }
            return false;
        }

        if (current != e.resolved_va)
        {
            static int s_iat_fail_logged = 0;
            if (s_iat_fail_logged < 5) {
                ++s_iat_fail_logged;
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "iat_mismatch idx=%zu slot_va=0x%llX expected=0x%llX got=0x%llX",
                    idx, e.slot_va, e.resolved_va, current);
                webhook::write_log("iat_hook", dbg);
            }
            return false;
        }
    }
    return true;
}

inline bool verify_iat_target_modules(const std::vector<state::iat_entry_t>& snapshot)
{
    HMODULE mods[256] = {};
    DWORD cb = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &cb, LIST_MODULES_ALL))
        return true;

    DWORD count = cb / sizeof(HMODULE);

    struct mod_range { uint64_t base; uint64_t end; };
    std::vector<mod_range> ranges;
    ranges.reserve(count);

    for (DWORD i = 0; i < count; ++i)
    {
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi)))
        {
            uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
            ranges.push_back({b, b + mi.SizeOfImage});
        }
    }

    for (const auto& e : snapshot)
    {
        uint64_t current = 0;
        if (!detail::safe_read_uint64(e.slot_va, &current))
            return false;
        bool in_module = false;
        for (const auto& r : ranges)
        {
            if (current >= r.base && current < r.end)
            {
                in_module = true;
                break;
            }
        }
        if (!in_module)
            return false;
    }
    return true;
}

inline bool scan_inline_hooks_ntdll(std::string& hooked_name)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    const char* critical_funcs[] = {
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "NtSetInformationThread",
        "NtClose",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "LdrLoadDll",
        "NtCreateFile",
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtQueryVirtualMemory",
    };

    for (const auto& name : critical_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
        if (!addr) continue;

        if (detail::check_inline_hook_bytes(addr, name))
        {
            hooked_name = name;
            return true;
        }
    }
    return false;
}

inline bool scan_inline_hooks_kernel32(std::string& hooked_name)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;

    const char* critical_funcs[] = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "VirtualProtect",
        "VirtualQuery",
        "GetModuleHandleW",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualFree",
    };

    for (const auto& name : critical_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(k32, name));
        if (!addr) continue;

        if (detail::check_inline_hook_bytes(addr, name))
        {
            hooked_name = name;
            return true;
        }
    }
    return false;
}

inline bool verify_syscall_stubs()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return true;

    const char* syscall_funcs[] = {
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "NtSetInformationThread",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtClose",
        "NtOpenProcess",
    };

    for (const auto& name : syscall_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
        if (!addr) continue;

        if (!detail::verify_syscall_stub(addr))
            return false;
    }
    return true;
}

inline bool verify_export_addresses(HMODULE mod)
{
    if (!mod) return true;

    detail::module_range_t range{};
    if (!detail::get_module_range(mod, range))
        return true;

    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return true;

    const auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0) return true;

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + exp_dir.VirtualAddress);
    const auto* funcs = reinterpret_cast<const DWORD*>(
        base + exports->AddressOfFunctions);

    uint64_t exp_start = reinterpret_cast<uint64_t>(base) + exp_dir.VirtualAddress;
    uint64_t exp_end = exp_start + exp_dir.Size;

    for (DWORD i = 0; i < exports->NumberOfFunctions; ++i)
    {
        uint64_t func_va = reinterpret_cast<uint64_t>(base) + funcs[i];

        if (func_va >= exp_start && func_va < exp_end)
            continue;

        if (func_va < range.base || func_va >= range.end)
            return false;
    }
    return true;
}

inline hook_report_t full_scan(const std::vector<state::iat_entry_t>& iat_snap)
{
    hook_report_t report{};

    report.iat_modified = !verify_iat_entries(iat_snap);
    if (report.iat_modified)
        webhook::send_debug_log("iat_hook", "iat_entry_modified", true);

    if (!report.iat_modified)
    {
        bool targets_ok = verify_iat_target_modules(iat_snap);
        if (!targets_ok)
        {
            report.iat_modified = true;
            webhook::send_debug_log("iat_target", "iat_target_outside_module", true);
        }
    }

    std::string ntdll_hooked;
    report.ntdll_inline_hooked = scan_inline_hooks_ntdll(ntdll_hooked);
    if (report.ntdll_inline_hooked)
    {
        report.hooked_function = ntdll_hooked;
        webhook::send_debug_log("ntdll_hook", "inline_hook: " + ntdll_hooked, true);
    }

    std::string k32_hooked;
    report.kernel32_inline_hooked = scan_inline_hooks_kernel32(k32_hooked);
    if (report.kernel32_inline_hooked)
    {
        report.hooked_function = k32_hooked;
        webhook::send_debug_log("k32_hook", "inline_hook: " + k32_hooked, true);
    }

    report.syscall_stubs_modified = !verify_syscall_stubs();
    if (report.syscall_stubs_modified)
        webhook::send_debug_log("syscall_hook", "syscall_stub_modified", true);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    report.eat_hooked = !verify_export_addresses(ntdll);
    if (report.eat_hooked)
        webhook::send_debug_log("eat_hook", "ntdll_eat_rva_outside_module", true);

    if (syscall::is_initialized())
    {
        std::string disk_hooked;
        if (syscall::detect_ntdll_hooks(disk_hooked))
        {
            if (!report.ntdll_inline_hooked)
            {
                report.ntdll_inline_hooked = true;
                report.hooked_function = disk_hooked;
            }
            webhook::send_debug_log("disk_hook", "disk_mismatch: " + disk_hooked, true);
        }
    }

    if (report.iat_modified) report.summary += "iat ";
    if (report.ntdll_inline_hooked) report.summary += "ntdll:" + ntdll_hooked + " ";
    if (report.kernel32_inline_hooked) report.summary += "k32:" + k32_hooked + " ";
    if (report.syscall_stubs_modified) report.summary += "syscall ";
    if (report.eat_hooked) report.summary += "eat ";

    return report;
}

}
}
