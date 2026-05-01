#pragma once

#include <windows.h>
#include <winioctl.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "hv_preflight.hpp"
#include "standalone_driver.hpp"

#pragma comment(lib, "iphlpapi.lib")

namespace anti_tamper {
namespace anti_vm {

struct vm_report_t
{
    bool cpuid_hypervisor_bit = false;
    bool cpuid_vendor_vm = false;
    bool cpuid_hyperv_guest = false;
    bool registry_vm_services = false;
    bool registry_vm_hardware = false;
    bool vm_mac_prefix = false;
    bool firmware_vm_string = false;
    bool kernel_zero_fp_vm = false;
    bool kernel_low_fp_vm = false;
    bool kernel_hv_failed_majority = false;
    bool disk_vm_hardware = false;
    bool acpi_vm_oem = false;
    bool acpi_waet_table = false;
    bool hyperv_interface_mismatch = false;
    bool edid_vm_manufacturer = false;
    uint8_t kernel_hv_failed_count = 0;
    uint8_t kernel_total_run = 0;
    std::string vendor_name;
    std::string summary;

    bool any_zero_fp_signal() const
    {
        return cpuid_vendor_vm
            || cpuid_hyperv_guest
            || firmware_vm_string
            || registry_vm_services
            || kernel_zero_fp_vm
            || kernel_hv_failed_majority
            || disk_vm_hardware
            || acpi_vm_oem
            || hyperv_interface_mismatch
            || edid_vm_manufacturer;
    }

    int low_fp_count() const
    {
        return (registry_vm_hardware ? 1 : 0)
             + (vm_mac_prefix ? 1 : 0)
             + (kernel_low_fp_vm ? 1 : 0)
             + (acpi_waet_table ? 1 : 0);
    }

    bool any_low_fp_signal() const
    {
        return low_fp_count() > 0;
    }

    bool any_detected() const
    {
        return any_zero_fp_signal() || (low_fp_count() >= 2);
    }
};

inline bool check_cpuid_hypervisor_bit()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;
}

inline bool is_microsoft_hyperv_root_partition()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return false;

    __cpuid(regs, 0x40000000);
    char vendor[12];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);
    const char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
    if (memcmp(vendor, hv, 12) != 0)
        return false;

    __cpuid(regs, 0x40000001);
    if (static_cast<uint32_t>(regs[0]) != 0x31237648u)
        return false;

    __cpuid(regs, 0x40000003);
    uint32_t partition_caps = static_cast<uint32_t>(regs[1]);
    const uint32_t root_bits = (1u << 0) | (1u << 5);
    return (partition_caps & root_bits) != 0;
}

inline bool is_microsoft_hyperv_guest_partition()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return false;

    __cpuid(regs, 0x40000000);
    char vendor[12];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);
    const char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
    if (memcmp(vendor, hv, 12) != 0)
        return false;

    __cpuid(regs, 0x40000001);
    if (static_cast<uint32_t>(regs[0]) != 0x31237648u)
        return false;

    __cpuid(regs, 0x40000003);
    uint32_t partition_caps = static_cast<uint32_t>(regs[1]);
    const uint32_t root_bits = (1u << 0) | (1u << 5);
    return (partition_caps & root_bits) == 0;
}

inline std::string check_cpuid_vendor_string()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return "";

    __cpuid(regs, 0x40000000);

    char vendor[13] = {};
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);

    static const char* known_vm_vendors[] = {
        "VMwareVMware",
        "KVMKVMKVM\0\0\0",
        "VBoxVBoxVBox",
        "XenVMMXenVMM",
        "prl hyperv \0",
        " lrpepyh vr",
        "bhyve bhyve ",
        "TCGTCGTCGTCG",
        "ACRNACRNACRN",
    };

    for (const auto* kv : known_vm_vendors)
    {
        if (memcmp(vendor, kv, 12) == 0)
            return std::string(vendor, 12);
    }
    return "";
}

inline bool check_hyperv_interface_mismatch()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if ((regs[2] & (1 << 31)) == 0)
        return false;

    __cpuid(regs, 0x40000000);
    char vendor[12];
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[2], 4);
    memcpy(vendor + 8, &regs[3], 4);
    const char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
    if (memcmp(vendor, hv, 12) != 0)
        return false;

    __cpuid(regs, 0x40000001);
    return static_cast<uint32_t>(regs[0]) != 0x31237648u;
}

inline bool check_vm_registry_keys()
{
    static const wchar_t* services[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
        L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk",
        L"SYSTEM\\CurrentControlSet\\Services\\vmusbmouse",
        L"SYSTEM\\CurrentControlSet\\Services\\vm3dmp",
        L"SYSTEM\\CurrentControlSet\\Services\\vmgid",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_tg",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_pv32",
        L"SYSTEM\\CurrentControlSet\\Services\\prl_strg",
        L"SYSTEM\\CurrentControlSet\\Services\\xenevtchn",
        L"SYSTEM\\CurrentControlSet\\Services\\xenbus",
        L"SYSTEM\\CurrentControlSet\\Services\\xennet",
        L"SYSTEM\\CurrentControlSet\\Services\\xenvbd",
        L"SYSTEM\\CurrentControlSet\\Services\\viostor",
        L"SYSTEM\\CurrentControlSet\\Services\\vioscsi",
        L"SYSTEM\\CurrentControlSet\\Services\\NetKVM",
        L"SYSTEM\\CurrentControlSet\\Services\\Balloon",
        L"SYSTEM\\CurrentControlSet\\Services\\pvpanic",
        L"SYSTEM\\CurrentControlSet\\Services\\qemupciserial",
        L"SYSTEM\\CurrentControlSet\\Services\\qemufwcfg",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
    };

    for (const auto* svc : services)
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
            || wcsstr(lower, L"ven_5853")
            || wcsstr(lower, L"subsys_20001ab8"))
        {
            found = true;
        }
    }

    RegCloseKey(enum_key);
    return found;
}

inline bool check_vm_mac_prefixes(bool skip_hyperv_oui)
{
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &buf_size);
    if (buf_size == 0) return false;

    auto* buf = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(buf_size));
    if (!buf) return false;

    bool found = false;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, buf, &buf_size) == NO_ERROR)
    {
        struct vm_oui { uint8_t b[3]; bool is_hyperv; };
        const vm_oui known[] = {
            {{0x00, 0x05, 0x69}, false},
            {{0x00, 0x0C, 0x29}, false},
            {{0x00, 0x1C, 0x14}, false},
            {{0x00, 0x50, 0x56}, false},
            {{0x08, 0x00, 0x27}, false},
            {{0x52, 0x54, 0x00}, false},
            {{0x00, 0x16, 0x3E}, false},
            {{0x00, 0x1C, 0x42}, false},
            {{0x00, 0x15, 0x5D}, true},
        };

        for (auto* adapter = buf; adapter && !found; adapter = adapter->Next)
        {
            if (adapter->PhysicalAddressLength < 3) continue;

            for (const auto& oui : known)
            {
                if (skip_hyperv_oui && oui.is_hyperv)
                    continue;

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

inline bool check_firmware_tables()
{
    UINT size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0 || size > 1024 * 1024)
        return false;

    auto* buf = static_cast<uint8_t*>(malloc(size));
    if (!buf)
        return false;

    bool found = false;
    if (GetSystemFirmwareTable('RSMB', 0, buf, size) == size)
    {
        for (UINT i = 0; i + 6 <= size && !found; ++i)
        {
            const char* p = reinterpret_cast<const char*>(buf + i);
            const UINT remaining = size - i;

            if (remaining >= 4 && memcmp(p, "QEMU", 4) == 0) { found = true; break; }
            if (remaining >= 4 && memcmp(p, "VBOX", 4) == 0) { found = true; break; }
            if (remaining >= 6 && memcmp(p, "VMware", 6) == 0) { found = true; break; }
            if (remaining >= 6 && memcmp(p, "VMWARE", 6) == 0) { found = true; break; }
            if (remaining >= 10 && memcmp(p, "VirtualBox", 10) == 0) { found = true; break; }
            if (remaining >= 7 && memcmp(p, "innotek", 7) == 0) { found = true; break; }
            if (remaining >= 5 && memcmp(p, "BOCHS", 5) == 0) { found = true; break; }
            if (remaining >= 5 && memcmp(p, "Bochs", 5) == 0) { found = true; break; }
            if (remaining >= 9 && memcmp(p, "Parallels", 9) == 0) { found = true; break; }
            if (remaining >= 7 && memcmp(p, "SeaBIOS", 7) == 0) { found = true; break; }
            if (remaining >= 4 && memcmp(p, "BXPC", 4) == 0) { found = true; break; }
            if (remaining >= 4 && memcmp(p, "OVMF", 4) == 0) { found = true; break; }
            if (remaining >= 6 && memcmp(p, "EDK II", 6) == 0) { found = true; break; }
            if (remaining >= 9 && memcmp(p, "Tianocore", 9) == 0) { found = true; break; }
            if (remaining >= 14 && memcmp(p, "Standard PC (Q35", 14) == 0) { found = true; break; }
            if (remaining >= 17 && memcmp(p, "Microsoft Hyper-V", 17) == 0) { found = true; break; }
            if (remaining >= 7 && memcmp(p, "Xen HVM", 7) == 0) { found = true; break; }
            if (remaining >= 8 && memcmp(p, "Xen domU", 8) == 0) { found = true; break; }
        }
    }
    free(buf);
    return found;
}

inline bool icontains_ascii(const char* hay, size_t hay_len, const char* needle)
{
    const size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) return false;
    for (size_t i = 0; i + nlen <= hay_len; ++i)
    {
        size_t j = 0;
        for (; j < nlen; ++j)
        {
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 32);
            if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 32);
            if (a != b) break;
        }
        if (j == nlen) return true;
    }
    return false;
}

inline bool check_qemu_disk_hardware()
{
    static const char* vm_disk_signatures[] = {
        "QEMU HARDDISK",
        "QEMU DVD-ROM",
        "ATA QEMU",
        "Red Hat VirtIO",
        "VBOX HARDDISK",
        "VBOX CD-ROM",
        "VMware Virtual",
        "VMware, VMware",
        "VMware NVMe",
        "Msft Virtual Disk",
        "Xen Virtual SCSI",
        "Parallels"
    };

    for (int drive_index = 0; drive_index < 8; ++drive_index)
    {
        wchar_t path[64];
        swprintf_s(path, 64, L"\\\\.\\PhysicalDrive%d", drive_index);

        HANDLE h = CreateFileW(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            continue;

        STORAGE_PROPERTY_QUERY q = {};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;

        std::vector<uint8_t> out(2048, 0);
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
            &q, sizeof(q), out.data(), static_cast<DWORD>(out.size()),
            &returned, nullptr);
        CloseHandle(h);

        if (!ok || returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
            continue;

        auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(out.data());
        const size_t desc_size = static_cast<size_t>(returned);

        const char* base = reinterpret_cast<const char*>(out.data());

        auto check_offset = [&](DWORD off) -> bool
        {
            if (off == 0 || static_cast<size_t>(off) >= desc_size)
                return false;
            const char* s = base + off;
            const size_t maxlen = desc_size - off;
            size_t slen = 0;
            while (slen < maxlen && s[slen] != 0) ++slen;
            if (slen == 0) return false;
            for (const char* sig : vm_disk_signatures)
            {
                if (icontains_ascii(s, slen, sig))
                    return true;
            }
            return false;
        };

        if (check_offset(desc->VendorIdOffset)) return true;
        if (check_offset(desc->ProductIdOffset)) return true;
    }

    return false;
}

inline bool check_acpi_oem_signatures(bool& out_waet_present)
{
    out_waet_present = false;

    UINT enum_size = EnumSystemFirmwareTables('ACPI', nullptr, 0);
    if (enum_size == 0 || enum_size > 4096)
        return false;

    std::vector<uint8_t> ids(enum_size, 0);
    if (EnumSystemFirmwareTables('ACPI', ids.data(), enum_size) != enum_size)
        return false;

    static const char* vm_oem_ids[] = {
        "BOCHS",
        "BXPC",
        "KVMKVM",
        "VBOX",
        "VRTUAL",
        "Parallels",
        "QEMU"
    };

    bool oem_hit = false;
    const UINT entries = enum_size / 4;
    for (UINT i = 0; i < entries; ++i)
    {
        DWORD table_id = 0;
        memcpy(&table_id, ids.data() + i * 4, 4);

        char tag[5] = {};
        memcpy(tag, &table_id, 4);
        if (memcmp(tag, "WAET", 4) == 0)
        {
            out_waet_present = true;
        }

        UINT table_size = GetSystemFirmwareTable('ACPI', table_id, nullptr, 0);
        if (table_size < 36 || table_size > 1024 * 1024)
            continue;

        std::vector<uint8_t> table(table_size, 0);
        if (GetSystemFirmwareTable('ACPI', table_id, table.data(), table_size) != table_size)
            continue;

        const char* oem_id = reinterpret_cast<const char*>(table.data() + 10);
        const char* oem_table_id = reinterpret_cast<const char*>(table.data() + 16);

        for (const char* sig : vm_oem_ids)
        {
            const size_t slen = strlen(sig);
            if (slen <= 6 && icontains_ascii(oem_id, 6, sig))
            {
                oem_hit = true;
                break;
            }
            if (slen <= 8 && icontains_ascii(oem_table_id, 8, sig))
            {
                oem_hit = true;
                break;
            }
        }

        if (oem_hit && out_waet_present)
            break;
    }

    return oem_hit;
}

inline bool check_edid_manufacturer()
{
    HKEY display_key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
        0, KEY_READ, &display_key) != ERROR_SUCCESS)
        return false;

    bool found = false;
    wchar_t monitor_class[256] = {};
    DWORD class_idx = 0;

    while (!found && RegEnumKeyW(display_key, class_idx++, monitor_class, 256) == ERROR_SUCCESS)
    {
        HKEY class_key = nullptr;
        if (RegOpenKeyExW(display_key, monitor_class, 0, KEY_READ, &class_key) != ERROR_SUCCESS)
            continue;

        wchar_t instance[256] = {};
        DWORD inst_idx = 0;
        while (!found && RegEnumKeyW(class_key, inst_idx++, instance, 256) == ERROR_SUCCESS)
        {
            wchar_t edid_path[1024];
            swprintf_s(edid_path, 1024, L"%s\\%s\\Device Parameters", monitor_class, instance);

            HKEY params_key = nullptr;
            if (RegOpenKeyExW(display_key, edid_path, 0, KEY_READ, &params_key) != ERROR_SUCCESS)
                continue;

            uint8_t edid[256] = {};
            DWORD edid_size = sizeof(edid);
            DWORD type = 0;
            if (RegQueryValueExW(params_key, L"EDID", nullptr, &type,
                edid, &edid_size) == ERROR_SUCCESS && type == REG_BINARY && edid_size >= 10)
            {
                static const uint8_t edid_header[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
                if (memcmp(edid, edid_header, 8) == 0)
                {
                    const uint16_t mfg = static_cast<uint16_t>((edid[8] << 8) | edid[9]);
                    char letters[3];
                    letters[0] = static_cast<char>('A' + ((mfg >> 10) & 0x1F) - 1);
                    letters[1] = static_cast<char>('A' + ((mfg >> 5) & 0x1F) - 1);
                    letters[2] = static_cast<char>('A' + (mfg & 0x1F) - 1);

                    if (letters[0] >= 'A' && letters[0] <= 'Z'
                        && letters[1] >= 'A' && letters[1] <= 'Z'
                        && letters[2] >= 'A' && letters[2] <= 'Z')
                    {
                        if ((letters[0] == 'Q' && letters[1] == 'E' && letters[2] == 'M')
                            || (letters[0] == 'R' && letters[1] == 'H' && letters[2] == 'T')
                            || (letters[0] == 'B' && letters[1] == 'O' && letters[2] == 'C'))
                        {
                            found = true;
                        }
                    }
                }
            }
            RegCloseKey(params_key);
        }
        RegCloseKey(class_key);
    }

    RegCloseKey(display_key);
    return found;
}

inline bool synthetic_vm_trip_active()
{
    DWORD len = GetEnvironmentVariableA("_AIDA_TEST_VM_TRIP", nullptr, 0);
    if (len == 0) return false;
    char buf[8] = {};
    DWORD got = GetEnvironmentVariableA("_AIDA_TEST_VM_TRIP", buf, sizeof(buf));
    if (got == 0 || got >= sizeof(buf)) return false;
    return buf[0] == '1';
}

inline vm_report_t full_scan()
{
    vm_report_t report{};

    const bool ms_hv_approved = hv_preflight::g_ms_hv_approved;
    if (ms_hv_approved) {
        report.summary = "ms_hv_approved_by_preflight ";
    }

    report.cpuid_hypervisor_bit = check_cpuid_hypervisor_bit();

    report.vendor_name = check_cpuid_vendor_string();
    report.cpuid_vendor_vm = !report.vendor_name.empty();

    report.cpuid_hyperv_guest = is_microsoft_hyperv_guest_partition();
    if (report.cpuid_hyperv_guest && report.vendor_name.empty()) {
        report.vendor_name = "HyperV-Guest";
    }

    report.hyperv_interface_mismatch = check_hyperv_interface_mismatch();

    report.registry_vm_services = check_vm_registry_keys();

    report.registry_vm_hardware = check_vm_hardware_ids();

    report.vm_mac_prefix = check_vm_mac_prefixes(ms_hv_approved);

    report.firmware_vm_string = check_firmware_tables();

    report.disk_vm_hardware = check_qemu_disk_hardware();

    {
        bool waet_present = false;
        report.acpi_vm_oem = check_acpi_oem_signatures(waet_present);
        report.acpi_waet_table = ms_hv_approved ? false : waet_present;
    }

    report.edid_vm_manufacturer = check_edid_manufacturer();

    {
        driver_bridge::hv_kernel_detect_result_t kresult{};
        if (driver_bridge::run_kernel_hv_detection(kresult)) {
            const uint8_t kernel_hard_count =
                kresult.vmf_cpuid_vendor + kresult.vmf_hyperv_guest +
                kresult.vmf_smbios_vm + kresult.vmf_acpi_vm +
                kresult.vmf_disk_vm + kresult.vmf_registry_vm;
            const uint8_t kernel_soft_count =
                kresult.vmf_pci_vm + kresult.vmf_mac_vm;

            report.kernel_zero_fp_vm = (kernel_hard_count > 0) || (kresult.is_virtual_machine != 0);
            report.kernel_low_fp_vm = kernel_soft_count >= 2;

            const uint8_t hv_failed_count =
                kresult.sidt_lock_prefix + kresult.sidt_invalid_pf + kresult.sidt_tlb_only +
                kresult.sidt_timing + kresult.sidt_compat_mode + kresult.sidt_noncanonical_gp +
                kresult.sidt_noncanonical_ss + kresult.sidt_cpl3_umip_off + kresult.sidt_cpl3_umip_on +
                kresult.lidt_lock_prefix + kresult.lidt_invalid_pf + kresult.lidt_tlb_only +
                kresult.lidt_timing + kresult.lidt_noncanonical_gp + kresult.lidt_noncanonical_ss +
                kresult.lidt_cpl3_gp +
                kresult.ve_trigger + kresult.ve_lbr_stack + kresult.ve_xsetbv_gp + kresult.ve_cr4_vmxe;

            report.kernel_hv_failed_count = hv_failed_count;
            report.kernel_total_run = kresult.total_run;

            report.kernel_hv_failed_majority = (kresult.ms_hv_root == 0) && (hv_failed_count >= 6);

            if (report.vendor_name.empty() && kresult.vm_vendor_name[0] != 0) {
                size_t n = 0;
                while (n < sizeof(kresult.vm_vendor_name) && kresult.vm_vendor_name[n] != 0) ++n;
                report.vendor_name.assign(kresult.vm_vendor_name, n);
            }
        }
    }

    if (synthetic_vm_trip_active())
    {
        report.firmware_vm_string = true;
        report.summary += "synthetic_test_trip ";
    }

    if (report.cpuid_hypervisor_bit) report.summary += "cpuid_hv ";
    if (report.cpuid_vendor_vm) report.summary += "vendor:" + report.vendor_name + " ";
    if (report.cpuid_hyperv_guest) report.summary += "hyperv_guest ";
    if (report.hyperv_interface_mismatch) report.summary += "hv_iface_mismatch ";
    if (report.registry_vm_services) report.summary += "reg_svc ";
    if (report.registry_vm_hardware) report.summary += "reg_hw ";
    if (report.vm_mac_prefix) report.summary += "mac ";
    if (report.firmware_vm_string) report.summary += "firmware ";
    if (report.disk_vm_hardware) report.summary += "disk_hw ";
    if (report.acpi_vm_oem) report.summary += "acpi_oem ";
    if (report.acpi_waet_table) report.summary += "acpi_waet ";
    if (report.edid_vm_manufacturer) report.summary += "edid_vm ";
    if (report.kernel_zero_fp_vm) report.summary += "kernel_vm_fp ";
    if (report.kernel_low_fp_vm) report.summary += "kernel_vm_corroborated ";
    if (report.kernel_hv_failed_majority) {
        report.summary += "kernel_hv_majority(";
        report.summary += std::to_string(report.kernel_hv_failed_count);
        report.summary += "/";
        report.summary += std::to_string(report.kernel_total_run);
        report.summary += ") ";
    }

    return report;
}

}
}
