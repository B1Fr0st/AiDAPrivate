#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <algorithm>
#include <string>

#include "obfuscation.hpp"
#include "../../helpers/diag_log.hpp"

namespace anti_tamper {
namespace hv_preflight {

enum class result_t
{
    allow,
    refuse_hv,
    refuse_hv_nested,
    refuse_kernel_debug,
    refuse_test_signing
};

struct report_t
{
    result_t result;
    wchar_t vendor[16];
    bool hv_bit_set;
    bool hvci_enabled;
    bool vbs_enabled;
    bool xsetbv_forwarded;
    uint32_t timing_median;
    bool firmware_hit;
    bool process_hit;
    bool kd_enabled;
    bool test_signing;
};

namespace detail {

using NtQuerySystemInformation_t = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);

struct system_code_integrity_information_t
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

struct system_kernel_debugger_information_t
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

struct system_isolated_user_mode_information_t
{
    BOOLEAN SecureKernelRunning;
    BOOLEAN HvciEnabled;
    BOOLEAN HvciStrictMode;
    BOOLEAN DebugEnabled;
    BOOLEAN FirmwarePageProtection;
    BOOLEAN EncryptionKeyAvailable;
    BOOLEAN SpareFlags;
    BOOLEAN TrustletRunning;
    BOOLEAN HvciDisableAllowed;
    BOOLEAN Reserved[7];
};

constexpr ULONG kSystemKernelDebuggerInformation = 35;
constexpr ULONG kSystemCodeIntegrityInformation = 103;
constexpr ULONG kSystemIsolatedUserModeInformation = 165;

constexpr ULONG kCodeIntegrityEnabled = 0x01;
constexpr ULONG kCodeIntegrityTestSign = 0x02;
constexpr ULONG kCodeIntegrityHvciKmciEnabled = 0x400;

inline NtQuerySystemInformation_t resolve_nt_query()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(nt, "NtQuerySystemInformation"));
}

inline bool devmode_bypass_set()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\AiDA", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(key, L"DevMode", nullptr, &type,
        reinterpret_cast<BYTE*>(&value), &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_DWORD && value == 1;
}

inline bool read_cpuid_hv_bit()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;
}

inline void read_hv_vendor(char out12[12])
{
    int regs[4] = {};
    __cpuid(regs, 0x40000000);
    std::memcpy(out12 + 0, &regs[1], 4);
    std::memcpy(out12 + 4, &regs[2], 4);
    std::memcpy(out12 + 8, &regs[3], 4);
}

inline bool is_microsoft_hv(const char v[12])
{
    return std::memcmp(v, "Microsoft Hv", 12) == 0;
}

inline bool is_known_non_ms_hv(const char v[12])
{
    static const char* known[] = {
        "KVMKVMKVM\0\0\0",
        "VMwareVMware",
        "XenVMMXenVMM",
        "VBoxVBoxVBox",
        "TCGTCGTCGTCG",
        "bhyve bhyve ",
        "prl hyperv  ",
        "ACRNACRNACRN",
        "QNXQVMBSQG  "
    };
    for (const char* k : known)
        if (std::memcmp(v, k, 12) == 0) return true;
    return false;
}

inline bool query_code_integrity(ULONG& options_out)
{
    options_out = 0;
    auto fn = resolve_nt_query();
    if (!fn) return false;
    system_code_integrity_information_t sci{};
    sci.Length = sizeof(sci);
    ULONG ret = 0;
    LONG status = fn(kSystemCodeIntegrityInformation, &sci, sizeof(sci), &ret);
    if (status < 0) return false;
    options_out = sci.CodeIntegrityOptions;
    return true;
}

inline bool query_isolated_user_mode(system_isolated_user_mode_information_t& out)
{
    std::memset(&out, 0, sizeof(out));
    auto fn = resolve_nt_query();
    if (!fn) return false;
    ULONG ret = 0;
    LONG status = fn(kSystemIsolatedUserModeInformation, &out, sizeof(out), &ret);
    return status >= 0;
}

inline bool query_kernel_debugger(bool& enabled_out)
{
    enabled_out = false;
    auto fn = resolve_nt_query();
    if (!fn) return false;
    system_kernel_debugger_information_t kdi{};
    ULONG ret = 0;
    LONG status = fn(kSystemKernelDebuggerInformation, &kdi, sizeof(kdi), &ret);
    if (status < 0) return false;
    enabled_out = kdi.KernelDebuggerEnabled != 0 && kdi.KernelDebuggerNotPresent == 0;
    return true;
}

inline bool scan_firmware_rsmb()
{
    UINT size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0 || size >= 1024u * 1024u) return false;
    auto* buf = static_cast<uint8_t*>(std::malloc(size));
    if (!buf) return false;
    bool hit = false;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) == size)
    {
        static const char* needles[] = {
            "VMware", "VirtualBox", "QEMU", "innotek", "Xen", "Parallels", "Bochs"
        };
        for (const char* n : needles)
        {
            size_t nlen = std::strlen(n);
            if (size < nlen) continue;
            for (UINT i = 0; i + nlen <= size; ++i)
            {
                if (std::memcmp(buf + i, n, nlen) == 0) { hit = true; break; }
            }
            if (hit) break;
        }
        if (!hit)
        {
            bool has_ms_corp = false;
            bool has_virtual_machine = false;
            static const char ms[] = "Microsoft Corporation";
            static const char vm[] = "Virtual Machine";
            size_t mslen = sizeof(ms) - 1;
            size_t vmlen = sizeof(vm) - 1;
            for (UINT i = 0; i + mslen <= size; ++i)
            {
                if (std::memcmp(buf + i, ms, mslen) == 0) { has_ms_corp = true; break; }
            }
            for (UINT i = 0; i + vmlen <= size; ++i)
            {
                if (std::memcmp(buf + i, vm, vmlen) == 0) { has_virtual_machine = true; break; }
            }
            if (has_ms_corp && has_virtual_machine) hit = true;
        }
    }
    std::free(buf);
    return hit;
}

inline bool scan_vm_processes()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    static const wchar_t* names[] = {
        L"vmtoolsd.exe",
        L"vboxservice.exe",
        L"vmwareuser.exe",
        L"qemu-ga.exe",
        L"prl_tools.exe",
        L"xenservice.exe"
    };

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool hit = false;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            wchar_t lower[MAX_PATH];
            size_t i = 0;
            for (; i + 1 < MAX_PATH && pe.szExeFile[i] != L'\0'; ++i)
                lower[i] = static_cast<wchar_t>(towlower(pe.szExeFile[i]));
            lower[i] = L'\0';
            for (const wchar_t* n : names)
            {
                if (wcsstr(lower, n) != nullptr) { hit = true; break; }
            }
            if (hit) break;
        }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

inline bool cpu_supports_xsave()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 26)) != 0 && (regs[2] & (1 << 27)) != 0;
}

inline bool xsetbv_probe()
{
    if (!cpu_supports_xsave())
        return false;

    unsigned long long xcr0 = _xgetbv(0);
    if ((xcr0 & 1ULL) == 0)
        return false;
    return false;
}

inline uint32_t timing_probe_median()
{
    uint32_t samples[32]{};
    for (int i = 0; i < 32; ++i)
    {
        int dummy[4] = {};
        unsigned long long t0 = __rdtsc();
        __cpuid(dummy, 0);
        unsigned long long t1 = __rdtsc();
        unsigned long long d = t1 - t0;
        samples[i] = d > 0xFFFFFFFFULL ? 0xFFFFFFFFu : static_cast<uint32_t>(d);
    }
    std::sort(samples, samples + 32);
    return samples[16];
}

inline bool validate_ms_hv_features()
{
    int regs[4] = {};
    __cpuid(regs, 0x40000003);
    constexpr uint32_t kAccessVpRuntime    = 1u << 0;
    constexpr uint32_t kAccessPartRefCount = 1u << 1;
    constexpr uint32_t kAccessSyntheticTimers = 1u << 3;
    constexpr uint32_t kAccessAPIC = 1u << 4;
    constexpr uint32_t kAccessHypercall = 1u << 5;
    uint32_t part_priv = static_cast<uint32_t>(regs[0]);
    uint32_t expected = kAccessVpRuntime | kAccessPartRefCount
        | kAccessHypercall;
    return (part_priv & expected) == expected;
}

inline uint32_t get_windows_build_number()
{
    auto* shared = reinterpret_cast<const uint8_t*>(0x7FFE0000ULL);
    __try
    {
        return *reinterpret_cast<const uint32_t*>(shared + 0x260);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

}

inline bool g_ms_hv_approved = false;

inline report_t run()
{
    report_t r{};
    r.result = result_t::allow;
    r.vendor[0] = L'\0';

    diag::log_tagged("hv_pf", "enter");

    if (detail::devmode_bypass_set())
    {
        diag::log_tagged("hv_pf", "devmode_bypass_return");
        return r;
    }

    diag::log_tagged("hv_pf", "query_kernel_debugger_start");
    bool kd = false;
    detail::query_kernel_debugger(kd);
    r.kd_enabled = kd;
    diag::log_tagged_fmt("hv_pf", "query_kernel_debugger_done kd=%d", kd ? 1 : 0);

    diag::log_tagged("hv_pf", "query_code_integrity_start");
    ULONG ci_options = 0;
    bool ci_ok = detail::query_code_integrity(ci_options);
    r.hvci_enabled = ci_ok && (ci_options & detail::kCodeIntegrityHvciKmciEnabled) != 0;
    r.test_signing = ci_ok && (ci_options & detail::kCodeIntegrityTestSign) != 0;
    diag::log_tagged_fmt("hv_pf", "query_code_integrity_done ok=%d opts=0x%lX", ci_ok ? 1 : 0, static_cast<unsigned long>(ci_options));

    diag::log_tagged("hv_pf", "query_isolated_user_mode_start");
    detail::system_isolated_user_mode_information_t ium{};
    if (detail::query_isolated_user_mode(ium))
    {
        r.vbs_enabled = ium.SecureKernelRunning != 0;
        if (ium.HvciEnabled) r.hvci_enabled = true;
    }
    diag::log_tagged("hv_pf", "query_isolated_user_mode_done");

    diag::log_tagged("hv_pf", "read_cpuid_hv_bit_start");
    r.hv_bit_set = detail::read_cpuid_hv_bit();
    diag::log_tagged_fmt("hv_pf", "read_cpuid_hv_bit_done set=%d", r.hv_bit_set ? 1 : 0);

    char vendor12[12] = {};
    if (r.hv_bit_set)
    {
        diag::log_tagged("hv_pf", "read_hv_vendor_start");
        detail::read_hv_vendor(vendor12);
        for (int i = 0; i < 12; ++i)
            r.vendor[i] = static_cast<wchar_t>(static_cast<unsigned char>(vendor12[i]));
        r.vendor[12] = L'\0';
        diag::log_tagged("hv_pf", "read_hv_vendor_done");
    }

    diag::log_tagged("hv_pf", "scan_firmware_rsmb_start");
    r.firmware_hit = detail::scan_firmware_rsmb();
    diag::log_tagged_fmt("hv_pf", "scan_firmware_rsmb_done hit=%d", r.firmware_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_vm_processes_start");
    r.process_hit = detail::scan_vm_processes();
    diag::log_tagged_fmt("hv_pf", "scan_vm_processes_done hit=%d", r.process_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "xsetbv_probe_start");
    r.xsetbv_forwarded = detail::xsetbv_probe();
    diag::log_tagged_fmt("hv_pf", "xsetbv_probe_done fwd=%d", r.xsetbv_forwarded ? 1 : 0);

    diag::log_tagged("hv_pf", "timing_probe_start");
    r.timing_median = detail::timing_probe_median();
    diag::log_tagged_fmt("hv_pf", "timing_probe_done median=%u", r.timing_median);

    if (r.kd_enabled)
    {
        r.result = result_t::refuse_kernel_debug;
        diag::log_tagged("hv_pf", "decision=refuse_kernel_debug");
        return r;
    }
    if (r.test_signing)
    {
        r.result = result_t::refuse_test_signing;
        diag::log_tagged("hv_pf", "decision=refuse_test_signing");
        return r;
    }

    const bool ms_hv = r.hv_bit_set && detail::is_microsoft_hv(vendor12);
    const bool known_non_ms = r.hv_bit_set && detail::is_known_non_ms_hv(vendor12);

    if (ms_hv)
    {
        bool genuine_ms = detail::validate_ms_hv_features();

        if (!genuine_ms)
        {
            r.result = result_t::refuse_hv;
            diag::log_tagged("hv_pf", "decision=refuse_hv_ms_not_genuine");
            return r;
        }

        g_ms_hv_approved = true;
        r.result = result_t::allow;
        diag::log_tagged("hv_pf", "decision=allow_ms_hv");
        return r;
    }

    if (known_non_ms)
    {
        r.result = result_t::refuse_hv;
        diag::log_tagged("hv_pf", "decision=refuse_hv_known_non_ms");
        return r;
    }

    if (r.hv_bit_set)
    {
        r.result = result_t::refuse_hv;
        diag::log_tagged("hv_pf", "decision=refuse_hv_bit_set");
        return r;
    }

    if (r.firmware_hit)
    {
        r.result = result_t::refuse_hv;
        diag::log_tagged("hv_pf", "decision=refuse_hv_firmware_hit");
        return r;
    }

    r.result = result_t::allow;
    diag::log_tagged("hv_pf", "decision=allow");
    return r;
}

inline void show_refuse_ui_and_exit(const report_t& r)
{
    std::wstring message;
    switch (r.result)
    {
    case result_t::refuse_kernel_debug:
        message = WOBFSTR(L"AiDA cannot start while the Windows kernel debugger is enabled. Reboot without /debug to continue.");
        break;
    case result_t::refuse_test_signing:
        message = WOBFSTR(L"AiDA cannot start while test-signing mode is enabled. Disable test-signing and reboot.");
        break;
    case result_t::refuse_hv:
    case result_t::refuse_hv_nested:
    default:
    {
        std::wstring vendor_str(r.vendor);
        if (vendor_str.empty() || vendor_str[0] == L'\0')
            vendor_str = L"unknown";
        message = L"AiDA cannot start: a non-Microsoft hypervisor was detected (vendor: "
            + vendor_str + L"). Disable it and restart your PC.";
        if (r.firmware_hit)
            message += L"\n\nAdditional: VM firmware signatures detected in SMBIOS.";
        if (r.process_hit)
            message += L"\n\nAdditional: VM guest agent processes are running.";
        break;
    }
    }

    std::wstring title = WOBFSTR(L"AiDA");

    MessageBoxW(nullptr, message.c_str(), title.c_str(),
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);

    ExitProcess(1);
}

}
}
