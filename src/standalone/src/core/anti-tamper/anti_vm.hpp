#pragma once

#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <string>
#include <vector>

#include "webhook.hpp"

#pragma comment(lib, "iphlpapi.lib")

namespace anti_tamper {
namespace anti_vm {

struct vm_report_t
{
    bool cpuid_hypervisor_bit = false;
    bool cpuid_vendor_vm = false;
    bool registry_vm_services = false;
    bool registry_vm_hardware = false;
    bool timing_overhead = false;
    bool vm_mac_prefix = false;
    bool vm_processes = false;
    bool firmware_vm_string = false;
    std::string vendor_name;
    std::string summary;

    bool any_detected() const
    {
        return cpuid_hypervisor_bit || cpuid_vendor_vm || registry_vm_services
            || registry_vm_hardware || vm_mac_prefix || vm_processes
            || firmware_vm_string;
    }
};

inline bool check_cpuid_hypervisor_bit()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;
}

inline std::string check_cpuid_vendor_string()
{
    int regs[4] = {};
    __cpuid(regs, 0x40000000);

    char vendor[13] = {};
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    const char* known_vm_vendors[] = {
        "VMwareVMware",
        "Microsoft Hv",
        "KVMKVMKVM\0\0\0",
        "VBoxVBoxVBox",
        "XenVMMXenVMM",
        "prl hyperv \0",
        "bhyve bhyve ",
        "TCGTCGTCGTCG",
    };

    for (const auto& kv : known_vm_vendors)
    {
        if (memcmp(vendor, kv, 12) == 0)
            return std::string(vendor, 12);
    }
    return "";
}

inline bool check_vm_registry_keys()
{
    const wchar_t* services[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SYSTEM\\CurrentControlSet\\Services\\vmci",
        L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk",
        L"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\vm3dmp",
        L"SYSTEM\\CurrentControlSet\\Services\\vmgid",
        L"SYSTEM\\CurrentControlSet\\Services\\VirtualBox Guest Additions",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
    };

    for (const auto& svc : services)
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svc, 0, KEY_READ, &key) == ERROR_SUCCESS)
        {
            RegCloseKey(key);
            return true;
        }
    }
    return false;
}

inline bool check_vm_hardware_ids()
{
    HKEY enum_key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Enum\\PCI", 0, KEY_READ, &enum_key) != ERROR_SUCCESS)
        return false;

    wchar_t subkey_name[256];
    DWORD idx = 0;
    bool found = false;

    while (!found && RegEnumKeyW(enum_key, idx++, subkey_name, 256) == ERROR_SUCCESS)
    {
        wchar_t lower[256] = {};
        for (int i = 0; i < 255 && subkey_name[i]; ++i)
            lower[i] = towlower(subkey_name[i]);

        if (wcsstr(lower, L"ven_15ad") || wcsstr(lower, L"ven_80ee")
            || wcsstr(lower, L"ven_1af4") || wcsstr(lower, L"ven_1b36")
            || wcsstr(lower, L"subsys_20001ab8"))
        {
            found = true;
        }
    }

    RegCloseKey(enum_key);
    return found;
}

inline bool check_vm_timing_overhead()
{
    constexpr int samples = 11;
    uint64_t results[samples];

    for (int s = 0; s < samples; ++s)
    {
        uint64_t t0 = __rdtsc();
        int regs[4];
        __cpuid(regs, 0);
        uint64_t t1 = __rdtsc();
        results[s] = t1 - t0;
    }

    for (int i = 0; i < samples - 1; ++i)
        for (int j = 0; j < samples - i - 1; ++j)
            if (results[j] > results[j + 1])
            {
                uint64_t tmp = results[j];
                results[j] = results[j + 1];
                results[j + 1] = tmp;
            }

    uint64_t median = results[samples / 2];
    return median > 1500;
}

inline bool check_vm_mac_prefixes()
{
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &buf_size);
    if (buf_size == 0) return false;

    auto* buf = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(buf_size));
    if (!buf) return false;

    bool found = false;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, buf, &buf_size) == NO_ERROR)
    {
        struct vm_oui { uint8_t b[3]; };
        const vm_oui known[] = {
            {{0x00, 0x05, 0x69}},
            {{0x00, 0x0C, 0x29}},
            {{0x00, 0x1C, 0x14}},
            {{0x00, 0x50, 0x56}},
            {{0x08, 0x00, 0x27}},
            {{0x52, 0x54, 0x00}},
            {{0x00, 0x16, 0x3E}},
            {{0x00, 0x1A, 0x4A}},
        };

        for (auto* adapter = buf; adapter && !found; adapter = adapter->Next)
        {
            if (adapter->PhysicalAddressLength < 3) continue;

            for (const auto& oui : known)
            {
                if (adapter->PhysicalAddress[0] == oui.b[0]
                    && adapter->PhysicalAddress[1] == oui.b[1]
                    && adapter->PhysicalAddress[2] == oui.b[2])
                {
                    found = true;
                    break;
                }
            }
        }
    }

    free(buf);
    return found;
}

inline bool check_vm_processes()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
         ok = Process32NextW(snap, &pe))
    {
        wchar_t lower[MAX_PATH] = {};
        for (int i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
            lower[i] = towlower(pe.szExeFile[i]);

        if (wcsstr(lower, L"vmtoolsd.exe")
            || wcsstr(lower, L"vboxservice.exe")
            || wcsstr(lower, L"vboxtray.exe")
            || wcsstr(lower, L"vmwaretray.exe")
            || wcsstr(lower, L"vmwareuser.exe")
            || wcsstr(lower, L"qemu-ga.exe")
            || wcsstr(lower, L"xenservice.exe")
            || wcsstr(lower, L"vgauthservice.exe"))
        {
            found = true;
        }
    }

    CloseHandle(snap);
    return found;
}

inline bool check_firmware_tables()
{
    UINT size = 0;

    size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size > 0 && size < 1024 * 1024)
    {
        auto* buf = static_cast<uint8_t*>(malloc(size));
        if (buf)
        {
            if (GetSystemFirmwareTable('RSMB', 0, buf, size) == size)
            {
                for (UINT i = 0; i + 6 <= size; ++i)
                {
                    if (memcmp(buf + i, "VBOX", 4) == 0
                        || memcmp(buf + i, "VMWARE", 6) == 0
                        || memcmp(buf + i, "QEMU", 4) == 0
                        || memcmp(buf + i, "VirtualBox", 10) == 0
                        || memcmp(buf + i, "innotek", 7) == 0)
                    {
                        free(buf);
                        return true;
                    }
                }
            }
            free(buf);
        }
    }
    return false;
}

inline vm_report_t full_scan()
{
    vm_report_t report{};

    report.cpuid_hypervisor_bit = check_cpuid_hypervisor_bit();

    report.vendor_name = check_cpuid_vendor_string();
    report.cpuid_vendor_vm = !report.vendor_name.empty();

    report.registry_vm_services = check_vm_registry_keys();

    report.registry_vm_hardware = check_vm_hardware_ids();

    report.timing_overhead = check_vm_timing_overhead();

    report.vm_mac_prefix = check_vm_mac_prefixes();

    report.vm_processes = check_vm_processes();

    report.firmware_vm_string = check_firmware_tables();

    if (report.cpuid_hypervisor_bit) report.summary += "cpuid_hv ";
    if (report.cpuid_vendor_vm) report.summary += "vendor:" + report.vendor_name + " ";
    if (report.registry_vm_services) report.summary += "reg_svc ";
    if (report.registry_vm_hardware) report.summary += "reg_hw ";
    if (report.timing_overhead) report.summary += "timing ";
    if (report.vm_mac_prefix) report.summary += "mac ";
    if (report.vm_processes) report.summary += "procs ";
    if (report.firmware_vm_string) report.summary += "firmware ";

    return report;
}

}
}
