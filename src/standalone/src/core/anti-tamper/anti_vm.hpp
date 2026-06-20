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
#include "standalone_license.hpp"

#pragma comment(lib, "iphlpapi.lib")

namespace anti_tamper {
namespace anti_vm {

constexpr uint32_t kPolicyVersion = 0x20260605u;
constexpr uint32_t kFamilyCpuid = 1u << 0;
constexpr uint32_t kFamilyTiming = 1u << 1;
constexpr uint32_t kFamilyFirmware = 1u << 2;
constexpr uint32_t kFamilyDevice = 1u << 3;
constexpr uint32_t kFamilyOsArtifact = 1u << 4;
constexpr uint32_t kFamilyKernelHvdt = 1u << 5;
constexpr uint32_t kContradictionHiddenHv = 1u << 0;
constexpr uint32_t kContradictionCpuidLeaf = 1u << 1;
constexpr uint32_t kContradictionTscQpc = 1u << 2;
constexpr uint32_t kContradictionSyntheticHv = 1u << 3;
constexpr uint32_t kContradictionHvInterface = 1u << 4;
constexpr uint32_t kContradictionHvGuest = 1u << 5;
constexpr uint32_t kContradictionKernelSideChannel = 1u << 6;

inline uint32_t vm_popcount32(uint32_t v)
{
    uint32_t n = 0;
    while (v)
    {
        v &= v - 1;
        ++n;
    }
    return n;
}

struct vm_report_t
{
    bool cpuid_hypervisor_bit = false;
    bool cpuid_vendor_vm = false;
    bool cpuid_hyperv_guest = false;
    bool untrusted_hypervisor = false;
    bool ms_hv_approved = false;
    bool hvci_enabled = false;
    bool vbs_enabled = false;
    bool hidden_hypervisor_suspected = false;
    bool cpuid_leaf_inconsistent = false;
    bool tsc_qpc_unstable = false;
    bool synthetic_hv_behavior = false;
    bool hypervisor_hijack_contradiction = false;
    bool kernel_hv_quarantine_deny = false;
    bool registry_vm_services = false;
    bool registry_vm_services_present = false;
    bool registry_vm_services_active = false;
    bool registry_vm_hardware = false;
    bool vm_mac_prefix = false;
    bool vm_mac_prefix_active = false;
    bool firmware_vm_string = false;
    bool kernel_zero_fp_vm = false;
    bool kernel_low_fp_vm = false;
    bool kernel_hv_failed_majority = false;
    bool kernel_cpuid_vendor = false;
    bool kernel_hyperv_guest = false;
    bool kernel_smbios_vm = false;
    bool kernel_acpi_vm = false;
    bool kernel_pci_vm = false;
    bool kernel_disk_vm = false;
    bool kernel_mac_vm = false;
    bool kernel_registry_vm = false;
    bool disk_vm_hardware = false;
    bool acpi_vm_oem = false;
    bool acpi_waet_table = false;
    bool hyperv_interface_mismatch = false;
    bool edid_vm_manufacturer = false;
    bool kernel_query_ok = false;
    bool kernel_hv_untrusted = false;
    bool kernel_hv_previous_incomplete = false;
    bool kernel_hv_deferred = false;
    bool kernel_hv_suppressed_previous_incomplete = false;
    bool kernel_hv_marker_io_failed = false;
    bool kernel_hv_heartbeat_failed = false;
    bool kernel_hv_query_failed = false;
    DWORD kernel_hv_error = ERROR_SUCCESS;
    uint32_t registry_vm_service_present_count = 0;
    uint32_t registry_vm_service_active_count = 0;
    uint32_t registry_vm_service_disabled_count = 0;
    uint32_t vm_mac_candidate_count = 0;
    uint32_t vm_mac_active_count = 0;
    uint32_t vm_mac_hyperv_skipped_count = 0;
    uint8_t kernel_hv_failed_count = 0;
    uint8_t kernel_total_run = 0;
    uint8_t kernel_ms_hv_root = 0;
    uint8_t kernel_hard_count = 0;
    uint8_t kernel_soft_count = 0;
    uint32_t signal_family_mask = 0;
    uint32_t medium_family_mask = 0;
    uint32_t contradiction_mask = 0;
    uint32_t hard_signal_total = 0;
    uint32_t medium_signal_total = 0;
    uint32_t medium_family_total = 0;
    std::string vendor_name;
    std::string summary;

    int hard_signal_count() const
    {
        return (untrusted_hypervisor ? 1 : 0)
             + (cpuid_vendor_vm ? 1 : 0)
             + (cpuid_hyperv_guest ? 1 : 0)
             + (firmware_vm_string ? 1 : 0)
             + (kernel_zero_fp_vm ? 1 : 0)
             + (kernel_hv_failed_majority ? 1 : 0)
             + (disk_vm_hardware ? 1 : 0)
             + (acpi_vm_oem ? 1 : 0)
             + (hyperv_interface_mismatch ? 1 : 0)
             + (edid_vm_manufacturer ? 1 : 0)
             + (hypervisor_hijack_contradiction && !hyperv_interface_mismatch ? 1 : 0);
    }

    bool any_zero_fp_signal() const
    {
        return hard_signal_count() > 0;
    }

    int low_fp_count() const
    {
        return (registry_vm_services_active ? 1 : 0)
             + (registry_vm_hardware ? 1 : 0)
             + (vm_mac_prefix_active ? 1 : 0)
             + (kernel_low_fp_vm ? 1 : 0)
             + (acpi_waet_table ? 1 : 0);
    }

    bool any_low_fp_signal() const
    {
        return low_fp_count() > 0;
    }

    uint32_t independent_medium_family_count() const
    {
        return vm_popcount32(medium_family_mask);
    }

    bool any_detected() const
    {
        if (kernel_hv_trust_failure())
            return true;
        if (kernel_hv_quarantine_deny)
            return true;
        if (any_zero_fp_signal())
            return true;
        if (hypervisor_hijack_contradiction)
            return true;
        return independent_medium_family_count() >= 2;
    }

    bool kernel_hv_trust_failure() const
    {
        return kernel_hv_untrusted;
    }

    const char* action_name() const
    {
        if (kernel_hv_trust_failure())
            return "fail_closed";
        if (any_zero_fp_signal() || hypervisor_hijack_contradiction)
            return "block";
        if (kernel_hv_quarantine_deny)
            return "quarantine";
        if (independent_medium_family_count() >= 2)
            return "block";
        return "allow";
    }
};

inline uint64_t vm_fnv1a_bytes(const void* data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

inline uint64_t vm_fnv1a_wstr(const wchar_t* s)
{
    if (!s) return 0;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; s[i]; ++i) {
        wchar_t c = towlower(s[i]);
        h ^= static_cast<uint8_t>(c & 0xFF);
        h *= 1099511628211ULL;
        h ^= static_cast<uint8_t>((c >> 8) & 0xFF);
        h *= 1099511628211ULL;
    }
    return h;
}

inline uint64_t vm_tick_ms();

struct kernel_hv_pending_marker_t
{
    bool present = false;
    bool parse_ok = false;
    bool stale = false;
    bool reboot_since_marker = false;
    DWORD pid = 0;
    DWORD tid = 0;
    DWORD driver_loaded = 0;
    DWORD driver_kernel = 0;
    uint64_t tick_ms = 0;
    uint64_t wall_filetime = 0;
    uint64_t preflight_hash = 0;
    uint64_t age_ms = 0;
    DWORD last_error = ERROR_SUCCESS;
};

inline uint64_t kernel_hv_wall_filetime()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui{};
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    return ui.QuadPart;
}

inline bool kernel_hv_startup_probe_enabled()
{
    char value[16] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_ENABLE_KERNEL_HVDT_STARTUP", value, static_cast<DWORD>(sizeof(value)));
    return n > 0 && n < sizeof(value) && value[0] == '1' && value[1] == '\0';
}

inline bool kernel_hv_marker_path(char* out, size_t out_size, uint64_t* path_hash = nullptr)
{
    if (!out || out_size == 0)
        return false;
    out[0] = '\0';

    char exe[MAX_PATH] = {};
    DWORD exe_len = GetModuleFileNameA(nullptr, exe, static_cast<DWORD>(sizeof(exe)));
    uint64_t exe_hash = exe_len > 0 && exe_len < sizeof(exe)
        ? vm_fnv1a_bytes(exe, exe_len)
        : static_cast<uint64_t>(GetCurrentProcessId());

    char dir[MAX_PATH] = {};
    DWORD dir_len = GetTempPathA(static_cast<DWORD>(sizeof(dir)), dir);
    if (dir_len == 0 || dir_len >= sizeof(dir))
    {
        if (exe_len == 0 || exe_len >= sizeof(exe))
            return false;
        char* last = strrchr(exe, '\\');
        if (last)
            *(last + 1) = '\0';
        else
            exe[0] = '\0';
        strcpy_s(dir, exe);
    }

    int written = _snprintf_s(out, out_size, _TRUNCATE,
        "%saida_kernel_hv_%016llX.pending",
        dir,
        static_cast<unsigned long long>(exe_hash));
    if (written <= 0)
        return false;
    if (path_hash)
        *path_hash = vm_fnv1a_bytes(out, strlen(out));
    return true;
}

inline kernel_hv_pending_marker_t kernel_hv_read_pending_marker()
{
    kernel_hv_pending_marker_t marker{};
    char path[MAX_PATH] = {};
    uint64_t path_hash = 0;
    if (!kernel_hv_marker_path(path, sizeof(path), &path_hash))
    {
        marker.last_error = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_path_failed phase=read pid=%lu tid=%lu err=%lu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long>(marker.last_error));
        return marker;
    }

    SetLastError(ERROR_SUCCESS);
    HANDLE h = CreateFileA(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        marker.last_error = err;
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_read_absent path_hash=0x%016llX err=%lu",
            static_cast<unsigned long long>(path_hash),
            static_cast<unsigned long>(err));
        return marker;
    }

    char buf[512] = {};
    DWORD got = 0;
    BOOL read_ok = ReadFile(h, buf, static_cast<DWORD>(sizeof(buf) - 1), &got, nullptr);
    DWORD read_err = read_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    marker.present = true;
    marker.last_error = read_err;
    if (!read_ok)
    {
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_read_failed path_hash=0x%016llX err=%lu",
            static_cast<unsigned long long>(path_hash),
            static_cast<unsigned long>(read_err));
        return marker;
    }
    buf[got] = '\0';

    unsigned long pid = 0;
    unsigned long tid = 0;
    unsigned long loaded = 0;
    unsigned long kernel = 0;
    unsigned long long tick = 0;
    unsigned long long wall = 0;
    unsigned long long prehash = 0;
    int parsed = sscanf_s(buf,
        "AIDA_HVDT_PENDING_V1 pid=%lu tid=%lu tick=%llu wall=%llu loaded=%lu kernel=%lu prehash=%llx",
        &pid,
        &tid,
        &tick,
        &wall,
        &loaded,
        &kernel,
        &prehash);
    marker.parse_ok = parsed == 7;
    if (marker.parse_ok)
    {
        marker.pid = static_cast<DWORD>(pid);
        marker.tid = static_cast<DWORD>(tid);
        marker.tick_ms = static_cast<uint64_t>(tick);
        marker.wall_filetime = static_cast<uint64_t>(wall);
        marker.driver_loaded = static_cast<DWORD>(loaded);
        marker.driver_kernel = static_cast<DWORD>(kernel);
        marker.preflight_hash = static_cast<uint64_t>(prehash);
        const uint64_t now_tick = vm_tick_ms();
        const uint64_t now_wall = kernel_hv_wall_filetime();
        marker.reboot_since_marker = now_tick < marker.tick_ms;
        if (now_wall >= marker.wall_filetime)
            marker.age_ms = (now_wall - marker.wall_filetime) / 10000ULL;
        else
            marker.age_ms = 0;
        marker.stale = marker.wall_filetime == 0 || marker.age_ms > 12ULL * 60ULL * 60ULL * 1000ULL;
    }

    webhook::write_log_critical_fmt("anti_vm",
        "kernel_hv_marker_read present=%d parse=%d stale=%d reboot=%d pid=%lu tid=%lu age_ms=%llu tick=%llu loaded=%lu kernel=%lu prehash=0x%016llX path_hash=0x%016llX",
        marker.present ? 1 : 0,
        marker.parse_ok ? 1 : 0,
        marker.stale ? 1 : 0,
        marker.reboot_since_marker ? 1 : 0,
        static_cast<unsigned long>(marker.pid),
        static_cast<unsigned long>(marker.tid),
        static_cast<unsigned long long>(marker.age_ms),
        static_cast<unsigned long long>(marker.tick_ms),
        static_cast<unsigned long>(marker.driver_loaded),
        static_cast<unsigned long>(marker.driver_kernel),
        static_cast<unsigned long long>(marker.preflight_hash),
        static_cast<unsigned long long>(path_hash));

    if (!marker.parse_ok || marker.stale)
    {
        SetLastError(ERROR_SUCCESS);
        BOOL deleted = DeleteFileA(path);
        DWORD del_err = deleted ? ERROR_SUCCESS : GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_delete_after_read reason=%s ok=%d err=%lu path_hash=0x%016llX",
            !marker.parse_ok ? "parse_failed" : "stale",
            deleted ? 1 : 0,
            static_cast<unsigned long>(del_err),
            static_cast<unsigned long long>(path_hash));
        marker.present = false;
    }

    return marker;
}

inline bool kernel_hv_write_pending_marker(const vm_report_t& report, bool driver_loaded, bool driver_kernel)
{
    char path[MAX_PATH] = {};
    uint64_t path_hash = 0;
    if (!kernel_hv_marker_path(path, sizeof(path), &path_hash))
    {
        SetLastError(ERROR_PATH_NOT_FOUND);
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_path_failed phase=write pid=%lu tid=%lu err=%lu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long>(GetLastError()));
        return false;
    }

    const uint64_t now_tick = vm_tick_ms();
    const uint64_t now_wall = kernel_hv_wall_filetime();
    const uint64_t prehash = vm_fnv1a_bytes(report.summary.data(), report.summary.size())
        ^ (static_cast<uint64_t>(report.hard_signal_count()) << 32)
        ^ static_cast<uint64_t>(report.low_fp_count());

    char content[256];
    int len = _snprintf_s(content, sizeof(content), _TRUNCATE,
        "AIDA_HVDT_PENDING_V1 pid=%lu tid=%lu tick=%llu wall=%llu loaded=%lu kernel=%lu prehash=%016llX\r\n",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(now_tick),
        static_cast<unsigned long long>(now_wall),
        driver_loaded ? 1ul : 0ul,
        driver_kernel ? 1ul : 0ul,
        static_cast<unsigned long long>(prehash));
    if (len <= 0)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    webhook::write_log_critical_fmt("anti_vm",
        "kernel_hv_marker_write_pre pid=%lu tid=%lu tick=%llu path_hash=0x%016llX prehash=0x%016llX",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(now_tick),
        static_cast<unsigned long long>(path_hash),
        static_cast<unsigned long long>(prehash));

    SetLastError(ERROR_SUCCESS);
    HANDLE h = CreateFileA(path, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_write_open_failed err=%lu path_hash=0x%016llX",
            static_cast<unsigned long>(err),
            static_cast<unsigned long long>(path_hash));
        return false;
    }

    DWORD written = 0;
    BOOL write_ok = WriteFile(h, content, static_cast<DWORD>(len), &written, nullptr);
    DWORD write_err = write_ok ? ERROR_SUCCESS : GetLastError();
    BOOL flush_ok = write_ok ? FlushFileBuffers(h) : FALSE;
    DWORD flush_err = flush_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);

    webhook::write_log_critical_fmt("anti_vm",
        "kernel_hv_marker_write_post ok=%d err=%lu flush=%d flush_err=%lu bytes=%lu expected=%d path_hash=0x%016llX elapsed_ms=%llu",
        write_ok && written == static_cast<DWORD>(len) && flush_ok ? 1 : 0,
        static_cast<unsigned long>(write_err),
        flush_ok ? 1 : 0,
        static_cast<unsigned long>(flush_err),
        static_cast<unsigned long>(written),
        len,
        static_cast<unsigned long long>(path_hash),
        static_cast<unsigned long long>(vm_tick_ms() - now_tick));

    if (!write_ok)
        SetLastError(write_err);
    else if (written != static_cast<DWORD>(len))
        SetLastError(ERROR_WRITE_FAULT);
    else if (!flush_ok)
        SetLastError(flush_err);

    return write_ok && written == static_cast<DWORD>(len) && flush_ok;
}

inline void kernel_hv_clear_pending_marker(const char* phase)
{
    char path[MAX_PATH] = {};
    uint64_t path_hash = 0;
    if (!kernel_hv_marker_path(path, sizeof(path), &path_hash))
    {
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_marker_path_failed phase=clear pid=%lu tid=%lu err=%lu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long>(GetLastError()));
        return;
    }

    SetLastError(ERROR_SUCCESS);
    BOOL ok = DeleteFileA(path);
    DWORD err = ok ? ERROR_SUCCESS : GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "kernel_hv_marker_clear phase=%s ok=%d err=%lu path_hash=0x%016llX",
        phase ? phase : "unknown",
        ok ? 1 : 0,
        static_cast<unsigned long>(err),
        static_cast<unsigned long long>(path_hash));
}

inline void kernel_hv_mark_untrusted(vm_report_t& report, const char* reason, DWORD err)
{
    report.kernel_hv_untrusted = true;
    report.kernel_hv_error = err;
    if (reason && *reason)
    {
        report.summary += reason;
        if (err != ERROR_SUCCESS)
        {
            report.summary += "(";
            report.summary += std::to_string(static_cast<unsigned long>(err));
            report.summary += ")";
        }
        report.summary += " ";
    }
}

inline uint64_t vm_tick_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

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

struct registry_vm_scan_t
{
    uint32_t present = 0;
    uint32_t active = 0;
    uint32_t disabled = 0;
};

inline bool query_service_running(const wchar_t* service_name)
{
    if (!service_name || !service_name[0])
    {
        webhook::write_log_critical_fmt("anti_vm",
            "service_status_exit reason=invalid_name pid=%lu tid=%lu tick=%llu",
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(vm_tick_ms()));
        return false;
    }
    const uint64_t started = vm_tick_ms();
    const uint64_t name_hash = vm_fnv1a_wstr(service_name);
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_pre name_hash=0x%016llX pid=%lu tid=%lu tick=%llu",
        static_cast<unsigned long long>(name_hash),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    DWORD err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_scm_post name_hash=0x%016llX ok=%d err=%lu elapsed_ms=%llu",
        static_cast<unsigned long long>(name_hash),
        scm ? 1 : 0,
        err,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (!scm)
    {
        webhook::write_log_critical_fmt("anti_vm",
            "service_status_exit reason=scm_open_failed name_hash=0x%016llX err=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(name_hash),
            err,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS);
    err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_open_post name_hash=0x%016llX ok=%d err=%lu elapsed_ms=%llu",
        static_cast<unsigned long long>(name_hash),
        svc ? 1 : 0,
        err,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (!svc)
    {
        CloseServiceHandle(scm);
        webhook::write_log_critical_fmt("anti_vm",
            "service_status_exit reason=service_open_failed name_hash=0x%016llX err=%lu elapsed_ms=%llu",
            static_cast<unsigned long long>(name_hash),
            err,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_query_pre name_hash=0x%016llX elapsed_ms=%llu",
        static_cast<unsigned long long>(name_hash),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    BOOL query_ok = QueryServiceStatusEx(
        svc,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp),
        sizeof(ssp),
        &needed);
    err = GetLastError();
    bool running = query_ok != FALSE && ssp.dwCurrentState == SERVICE_RUNNING;
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_query_post name_hash=0x%016llX ok=%d err=%lu state=%lu needed=%lu running=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(name_hash),
        query_ok ? 1 : 0,
        err,
        static_cast<unsigned long>(ssp.dwCurrentState),
        static_cast<unsigned long>(needed),
        running ? 1 : 0,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    webhook::write_log_critical_fmt("anti_vm",
        "service_status_exit reason=queried name_hash=0x%016llX running=%d elapsed_ms=%llu",
        static_cast<unsigned long long>(name_hash),
        running ? 1 : 0,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return running;
}

inline const wchar_t* service_name_from_registry_path(const wchar_t* path)
{
    static const wchar_t prefix[] = L"SYSTEM\\CurrentControlSet\\Services\\";
    const size_t prefix_len = (sizeof(prefix) / sizeof(prefix[0])) - 1;
    if (!path || _wcsnicmp(path, prefix, prefix_len) != 0)
        return nullptr;
    return path + prefix_len;
}

inline registry_vm_scan_t check_vm_registry_keys()
{
    const uint64_t started = vm_tick_ms();
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

    webhook::write_log_critical_fmt("anti_vm",
        "registry_services_enter count=%zu pid=%lu tid=%lu tick=%llu",
        sizeof(services) / sizeof(services[0]),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    registry_vm_scan_t scan{};
    uint32_t idx = 0;
    for (const auto* svc : services)
    {
        const uint64_t key_hash = vm_fnv1a_wstr(svc);
        const uint64_t probe_started = vm_tick_ms();
        webhook::write_log_critical_fmt("anti_vm",
            "registry_services_probe_pre idx=%u key_hash=0x%016llX elapsed_ms=%llu",
            idx,
            static_cast<unsigned long long>(key_hash),
            static_cast<unsigned long long>(probe_started - started));
        HKEY key = nullptr;
        LSTATUS open_status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, svc, 0, KEY_READ, &key);
        webhook::write_log_critical_fmt("anti_vm",
            "registry_services_probe_open_post idx=%u key_hash=0x%016llX status=%ld opened=%d probe_elapsed_ms=%llu total_elapsed_ms=%llu",
            idx,
            static_cast<unsigned long long>(key_hash),
            static_cast<long>(open_status),
            open_status == ERROR_SUCCESS ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - probe_started),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        if (open_status == ERROR_SUCCESS)
        {
            ++scan.present;
            DWORD start = 0xFFFFFFFFu;
            DWORD type = REG_DWORD;
            DWORD size = sizeof(start);
            LSTATUS query_status = RegQueryValueExW(
                key, L"Start", nullptr, &type, reinterpret_cast<LPBYTE>(&start), &size);
            const bool has_start = query_status == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(start);
            webhook::write_log_critical_fmt("anti_vm",
                "registry_services_start_post idx=%u key_hash=0x%016llX status=%ld type=%lu size=%lu has_start=%d start=%lu total_elapsed_ms=%llu",
                idx,
                static_cast<unsigned long long>(key_hash),
                static_cast<long>(query_status),
                static_cast<unsigned long>(type),
                static_cast<unsigned long>(size),
                has_start ? 1 : 0,
                static_cast<unsigned long>(has_start ? start : 0xFFFFFFFFu),
                static_cast<unsigned long long>(vm_tick_ms() - started));
            const wchar_t* service_name = service_name_from_registry_path(svc);
            const bool running = query_service_running(service_name);
            const bool disabled = has_start && start == SERVICE_DISABLED;
            const bool active = running;
            if (active)
                ++scan.active;
            else if (disabled)
                ++scan.disabled;
            char msg[256];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "vm_detect_signal category=reg_svc key_hash=0x%016llX service=%d start_known=%d start=%lu running=%d active=%d",
                static_cast<unsigned long long>(vm_fnv1a_wstr(svc)),
                service_name ? 1 : 0,
                has_start ? 1 : 0,
                static_cast<unsigned long>(has_start ? start : 0xFFFFFFFFu),
                running ? 1 : 0,
                active ? 1 : 0);
            webhook::write_log("init", msg);
            RegCloseKey(key);
        }
        ++idx;
    }
    webhook::write_log_critical_fmt("anti_vm",
        "registry_services_exit present=%u active=%u disabled=%u elapsed_ms=%llu",
        scan.present,
        scan.active,
        scan.disabled,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return scan;
}

inline bool check_vm_hardware_ids()
{
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "pci_hardware_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    HKEY enum_key = nullptr;
    LSTATUS open_status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Enum\\PCI", 0, KEY_READ, &enum_key);
    webhook::write_log_critical_fmt("anti_vm",
        "pci_hardware_scan_open_post status=%ld opened=%d err=%lu elapsed_ms=%llu",
        static_cast<long>(open_status),
        open_status == ERROR_SUCCESS ? 1 : 0,
        GetLastError(),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (open_status != ERROR_SUCCESS)
    {
        webhook::write_log_critical_fmt("anti_vm",
            "pci_hardware_scan_exit reason=open_failed status=%ld elapsed_ms=%llu",
            static_cast<long>(open_status),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

    wchar_t subkey_name[256];
    DWORD idx = 0;
    bool found = false;

    while (!found)
    {
        const DWORD current_idx = idx++;
        LSTATUS enum_status = RegEnumKeyW(enum_key, current_idx, subkey_name, 256);
        if (enum_status != ERROR_SUCCESS)
        {
            webhook::write_log_critical_fmt("anti_vm",
                "pci_hardware_scan_enum_done idx=%lu status=%ld found=%d elapsed_ms=%llu",
                static_cast<unsigned long>(current_idx),
                static_cast<long>(enum_status),
                found ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - started));
            break;
        }
        webhook::write_log_critical_fmt("anti_vm",
            "pci_hardware_scan_enum_post idx=%lu key_hash=0x%016llX elapsed_ms=%llu",
            static_cast<unsigned long>(current_idx),
            static_cast<unsigned long long>(vm_fnv1a_wstr(subkey_name)),
            static_cast<unsigned long long>(vm_tick_ms() - started));
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
    webhook::write_log_critical_fmt("anti_vm",
        "pci_hardware_scan_exit found=%d count=%lu elapsed_ms=%llu",
        found ? 1 : 0,
        static_cast<unsigned long>(idx),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return found;
}

struct mac_vm_scan_t
{
    uint32_t candidates = 0;
    uint32_t active = 0;
    uint32_t hyperv_skipped = 0;
};

inline bool adapter_is_enforcement_relevant(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (!adapter)
        return false;
    if (adapter->OperStatus != IfOperStatusUp)
        return false;
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
        return false;
    return true;
}

inline mac_vm_scan_t check_vm_mac_prefixes(bool skip_hyperv_oui)
{
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_scan_enter skip_hyperv=%d pid=%lu tid=%lu tick=%llu",
        skip_hyperv_oui ? 1 : 0,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    ULONG buf_size = 0;
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_size_query_pre elapsed_ms=%llu",
        static_cast<unsigned long long>(vm_tick_ms() - started));
    ULONG size_status = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &buf_size);
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_size_query_post status=%lu buf_size=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(size_status),
        static_cast<unsigned long>(buf_size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (buf_size == 0) {
        webhook::write_log_critical_fmt("anti_vm",
            "mac_prefix_scan_exit reason=no_buffer elapsed_ms=%llu",
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return {};
    }

    auto* buf = static_cast<IP_ADAPTER_ADDRESSES*>(malloc(buf_size));
    if (!buf) {
        webhook::write_log_critical_fmt("anti_vm",
            "mac_prefix_scan_exit reason=alloc_failed bytes=%lu elapsed_ms=%llu",
            static_cast<unsigned long>(buf_size),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return {};
    }

    mac_vm_scan_t scan{};
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_fetch_pre bytes=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(buf_size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    ULONG fetch_status = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, buf, &buf_size);
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_fetch_post status=%lu bytes=%lu elapsed_ms=%llu",
        static_cast<unsigned long>(fetch_status),
        static_cast<unsigned long>(buf_size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (fetch_status == NO_ERROR)
    {
        struct vm_oui { uint8_t b[3]; bool is_hyperv; const char* vendor; };
        const vm_oui known[] = {
            {{0x00, 0x05, 0x69}, false, "vmware"},
            {{0x00, 0x0C, 0x29}, false, "vmware"},
            {{0x00, 0x1C, 0x14}, false, "vmware"},
            {{0x00, 0x50, 0x56}, false, "vmware"},
            {{0x08, 0x00, 0x27}, false, "virtualbox"},
            {{0x52, 0x54, 0x00}, false, "qemu"},
            {{0x00, 0x16, 0x3E}, false, "xen"},
            {{0x00, 0x1C, 0x42}, false, "parallels"},
            {{0x00, 0x15, 0x5D}, true, "hyperv"},
        };

        uint32_t adapter_idx = 0;
        for (auto* adapter = buf; adapter; adapter = adapter->Next)
        {
            webhook::write_log_critical_fmt("anti_vm",
                "mac_prefix_adapter idx=%u phy_len=%lu oper=%u iftype=%lu friendly_hash=0x%016llX elapsed_ms=%llu",
                adapter_idx,
                static_cast<unsigned long>(adapter->PhysicalAddressLength),
                static_cast<unsigned>(adapter->OperStatus),
                static_cast<unsigned long>(adapter->IfType),
                static_cast<unsigned long long>(vm_fnv1a_wstr(adapter->FriendlyName)),
                static_cast<unsigned long long>(vm_tick_ms() - started));
            if (adapter->PhysicalAddressLength < 3) {
                ++adapter_idx;
                continue;
            }

            for (const auto& oui : known)
            {
                if (adapter->PhysicalAddress[0] == oui.b[0]
                    && adapter->PhysicalAddress[1] == oui.b[1]
                    && adapter->PhysicalAddress[2] == oui.b[2])
                {
                    if (skip_hyperv_oui && oui.is_hyperv)
                    {
                        ++scan.hyperv_skipped;
                        break;
                    }
                    ++scan.candidates;
                    const bool active = adapter_is_enforcement_relevant(adapter);
                    if (active)
                        ++scan.active;
                    char msg[320];
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                        "vm_detect_signal category=mac vendor=%s hyperv=%d active=%d oper=%u iftype=%lu addr_hash=0x%016llX friendly_hash=0x%016llX",
                        oui.vendor,
                        oui.is_hyperv ? 1 : 0,
                        active ? 1 : 0,
                        static_cast<unsigned>(adapter->OperStatus),
                        static_cast<unsigned long>(adapter->IfType),
                        static_cast<unsigned long long>(vm_fnv1a_bytes(adapter->PhysicalAddress, adapter->PhysicalAddressLength)),
                        static_cast<unsigned long long>(vm_fnv1a_wstr(adapter->FriendlyName)));
                    webhook::write_log("init", msg);
                    break;
                }
            }
            ++adapter_idx;
        }
    }

    free(buf);
    webhook::write_log_critical_fmt("anti_vm",
        "mac_prefix_scan_exit candidates=%u active=%u hyperv_skipped=%u elapsed_ms=%llu",
        scan.candidates,
        scan.active,
        scan.hyperv_skipped,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return scan;
}

inline bool check_firmware_tables()
{
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_size_query_pre elapsed_ms=%llu",
        static_cast<unsigned long long>(vm_tick_ms() - started));
    UINT size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    DWORD size_err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_size_query_post size=%u err=%lu elapsed_ms=%llu",
        static_cast<unsigned>(size),
        size_err,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (size == 0 || size > 1024 * 1024) {
        webhook::write_log_critical_fmt("anti_vm",
            "rsmb_scan_exit reason=invalid_size size=%u elapsed_ms=%llu",
            static_cast<unsigned>(size),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

    auto* buf = static_cast<uint8_t*>(malloc(size));
    if (!buf) {
        webhook::write_log_critical_fmt("anti_vm",
            "rsmb_scan_exit reason=alloc_failed size=%u elapsed_ms=%llu",
            static_cast<unsigned>(size),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

    bool found = false;
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_fetch_pre size=%u elapsed_ms=%llu",
        static_cast<unsigned>(size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    UINT fetched = GetSystemFirmwareTable('RSMB', 0, buf, size);
    DWORD fetch_err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_fetch_post fetched=%u err=%lu expected=%u elapsed_ms=%llu",
        static_cast<unsigned>(fetched),
        fetch_err,
        static_cast<unsigned>(size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (fetched == size)
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
    webhook::write_log_critical_fmt("anti_vm",
        "rsmb_scan_exit found=%d size=%u elapsed_ms=%llu",
        found ? 1 : 0,
        static_cast<unsigned>(size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
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
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "disk_hardware_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
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

        const uint64_t drive_started = vm_tick_ms();
        webhook::write_log_critical_fmt("anti_vm",
            "disk_hardware_open_pre drive=%d elapsed_ms=%llu",
            drive_index,
            static_cast<unsigned long long>(drive_started - started));
        HANDLE h = CreateFileW(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        DWORD open_err = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "disk_hardware_open_post drive=%d ok=%d err=%lu drive_elapsed_ms=%llu total_elapsed_ms=%llu",
            drive_index,
            h != INVALID_HANDLE_VALUE ? 1 : 0,
            open_err,
            static_cast<unsigned long long>(vm_tick_ms() - drive_started),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        if (h == INVALID_HANDLE_VALUE)
            continue;

        STORAGE_PROPERTY_QUERY q = {};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;

        std::vector<uint8_t> out(2048, 0);
        DWORD returned = 0;
        webhook::write_log_critical_fmt("anti_vm",
            "disk_hardware_ioctl_pre drive=%d ioctl=0x%08lX out=%zu elapsed_ms=%llu",
            drive_index,
            static_cast<unsigned long>(IOCTL_STORAGE_QUERY_PROPERTY),
            out.size(),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
            &q, sizeof(q), out.data(), static_cast<DWORD>(out.size()),
            &returned, nullptr);
        DWORD ioctl_err = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "disk_hardware_ioctl_post drive=%d ok=%d err=%lu returned=%lu elapsed_ms=%llu",
            drive_index,
            ok ? 1 : 0,
            ioctl_err,
            static_cast<unsigned long>(returned),
            static_cast<unsigned long long>(vm_tick_ms() - started));
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

        if (check_offset(desc->VendorIdOffset)) {
            webhook::write_log_critical_fmt("anti_vm",
                "disk_hardware_scan_exit found=1 drive=%d source=vendor elapsed_ms=%llu",
                drive_index,
                static_cast<unsigned long long>(vm_tick_ms() - started));
            return true;
        }
        if (check_offset(desc->ProductIdOffset)) {
            webhook::write_log_critical_fmt("anti_vm",
                "disk_hardware_scan_exit found=1 drive=%d source=product elapsed_ms=%llu",
                drive_index,
                static_cast<unsigned long long>(vm_tick_ms() - started));
            return true;
        }
    }

    webhook::write_log_critical_fmt("anti_vm",
        "disk_hardware_scan_exit found=0 elapsed_ms=%llu",
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return false;
}

inline bool check_acpi_oem_signatures(bool& out_waet_present)
{
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "acpi_oem_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    out_waet_present = false;

    webhook::write_log_critical_fmt("anti_vm",
        "acpi_enum_size_pre elapsed_ms=%llu",
        static_cast<unsigned long long>(vm_tick_ms() - started));
    UINT enum_size = EnumSystemFirmwareTables('ACPI', nullptr, 0);
    DWORD enum_err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "acpi_enum_size_post size=%u err=%lu elapsed_ms=%llu",
        static_cast<unsigned>(enum_size),
        enum_err,
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (enum_size == 0 || enum_size > 4096) {
        webhook::write_log_critical_fmt("anti_vm",
            "acpi_oem_scan_exit reason=invalid_enum_size size=%u waet=%d elapsed_ms=%llu",
            static_cast<unsigned>(enum_size),
            out_waet_present ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

    std::vector<uint8_t> ids(enum_size, 0);
    webhook::write_log_critical_fmt("anti_vm",
        "acpi_enum_fetch_pre size=%u elapsed_ms=%llu",
        static_cast<unsigned>(enum_size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    UINT enum_fetched = EnumSystemFirmwareTables('ACPI', ids.data(), enum_size);
    DWORD fetch_enum_err = GetLastError();
    webhook::write_log_critical_fmt("anti_vm",
        "acpi_enum_fetch_post fetched=%u err=%lu expected=%u elapsed_ms=%llu",
        static_cast<unsigned>(enum_fetched),
        fetch_enum_err,
        static_cast<unsigned>(enum_size),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (enum_fetched != enum_size)
    {
        webhook::write_log_critical_fmt("anti_vm",
            "acpi_oem_scan_exit reason=enum_fetch_mismatch fetched=%u expected=%u waet=%d elapsed_ms=%llu",
            static_cast<unsigned>(enum_fetched),
            static_cast<unsigned>(enum_size),
            out_waet_present ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

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

        webhook::write_log_critical_fmt("anti_vm",
            "acpi_table_size_pre idx=%u table=0x%08lX waet=%d elapsed_ms=%llu",
            static_cast<unsigned>(i),
            static_cast<unsigned long>(table_id),
            out_waet_present ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        UINT table_size = GetSystemFirmwareTable('ACPI', table_id, nullptr, 0);
        DWORD table_size_err = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "acpi_table_size_post idx=%u table=0x%08lX size=%u err=%lu elapsed_ms=%llu",
            static_cast<unsigned>(i),
            static_cast<unsigned long>(table_id),
            static_cast<unsigned>(table_size),
            table_size_err,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        if (table_size < 36 || table_size > 1024 * 1024)
            continue;

        std::vector<uint8_t> table(table_size, 0);
        webhook::write_log_critical_fmt("anti_vm",
            "acpi_table_fetch_pre idx=%u table=0x%08lX size=%u elapsed_ms=%llu",
            static_cast<unsigned>(i),
            static_cast<unsigned long>(table_id),
            static_cast<unsigned>(table_size),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        UINT table_fetched = GetSystemFirmwareTable('ACPI', table_id, table.data(), table_size);
        DWORD table_fetch_err = GetLastError();
        webhook::write_log_critical_fmt("anti_vm",
            "acpi_table_fetch_post idx=%u table=0x%08lX fetched=%u err=%lu elapsed_ms=%llu",
            static_cast<unsigned>(i),
            static_cast<unsigned long>(table_id),
            static_cast<unsigned>(table_fetched),
            table_fetch_err,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        if (table_fetched != table_size)
            continue;

        const char* oem_id = reinterpret_cast<const char*>(table.data() + 10);
        const char* oem_table_id = reinterpret_cast<const char*>(table.data() + 16);

        for (const char* sig : vm_oem_ids)
        {
            const size_t slen = strlen(sig);
            if (slen <= 6 && icontains_ascii(oem_id, 6, sig))
            {
                oem_hit = true;
                webhook::write_log_critical_fmt("anti_vm",
                    "acpi_oem_hit idx=%u table=0x%08lX source=oem_id sig_hash=0x%016llX elapsed_ms=%llu",
                    static_cast<unsigned>(i),
                    static_cast<unsigned long>(table_id),
                    static_cast<unsigned long long>(vm_fnv1a_bytes(sig, slen)),
                    static_cast<unsigned long long>(vm_tick_ms() - started));
                break;
            }
            if (slen <= 8 && icontains_ascii(oem_table_id, 8, sig))
            {
                oem_hit = true;
                webhook::write_log_critical_fmt("anti_vm",
                    "acpi_oem_hit idx=%u table=0x%08lX source=oem_table_id sig_hash=0x%016llX elapsed_ms=%llu",
                    static_cast<unsigned>(i),
                    static_cast<unsigned long>(table_id),
                    static_cast<unsigned long long>(vm_fnv1a_bytes(sig, slen)),
                    static_cast<unsigned long long>(vm_tick_ms() - started));
                break;
            }
        }

        if (oem_hit && out_waet_present)
            break;
    }

    webhook::write_log_critical_fmt("anti_vm",
        "acpi_oem_scan_exit found=%d waet=%d entries=%u elapsed_ms=%llu",
        oem_hit ? 1 : 0,
        out_waet_present ? 1 : 0,
        static_cast<unsigned>(entries),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    return oem_hit;
}

inline bool check_edid_manufacturer()
{
    const uint64_t started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "edid_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(started));
    HKEY display_key = nullptr;
    LSTATUS display_status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
        0, KEY_READ, &display_key);
    webhook::write_log_critical_fmt("anti_vm",
        "edid_display_open_post status=%ld opened=%d err=%lu elapsed_ms=%llu",
        static_cast<long>(display_status),
        display_status == ERROR_SUCCESS ? 1 : 0,
        GetLastError(),
        static_cast<unsigned long long>(vm_tick_ms() - started));
    if (display_status != ERROR_SUCCESS)
    {
        webhook::write_log_critical_fmt("anti_vm",
            "edid_scan_exit reason=display_open_failed status=%ld elapsed_ms=%llu",
            static_cast<long>(display_status),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        return false;
    }

    bool found = false;
    wchar_t monitor_class[256] = {};
    DWORD class_idx = 0;

    while (!found)
    {
        const DWORD current_class_idx = class_idx++;
        LSTATUS class_enum_status = RegEnumKeyW(display_key, current_class_idx, monitor_class, 256);
        if (class_enum_status != ERROR_SUCCESS)
        {
            webhook::write_log_critical_fmt("anti_vm",
                "edid_class_enum_done idx=%lu status=%ld found=%d elapsed_ms=%llu",
                static_cast<unsigned long>(current_class_idx),
                static_cast<long>(class_enum_status),
                found ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - started));
            break;
        }
        const uint64_t class_hash = vm_fnv1a_wstr(monitor_class);
        webhook::write_log_critical_fmt("anti_vm",
            "edid_class_enum_post idx=%lu class_hash=0x%016llX elapsed_ms=%llu",
            static_cast<unsigned long>(current_class_idx),
            static_cast<unsigned long long>(class_hash),
            static_cast<unsigned long long>(vm_tick_ms() - started));
        HKEY class_key = nullptr;
        LSTATUS class_open_status = RegOpenKeyExW(display_key, monitor_class, 0, KEY_READ, &class_key);
        webhook::write_log_critical_fmt("anti_vm",
            "edid_class_open_post idx=%lu class_hash=0x%016llX status=%ld opened=%d elapsed_ms=%llu",
            static_cast<unsigned long>(current_class_idx),
            static_cast<unsigned long long>(class_hash),
            static_cast<long>(class_open_status),
            class_open_status == ERROR_SUCCESS ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - started));
        if (class_open_status != ERROR_SUCCESS)
            continue;

        wchar_t instance[256] = {};
        DWORD inst_idx = 0;
        while (!found)
        {
            const DWORD current_inst_idx = inst_idx++;
            LSTATUS inst_enum_status = RegEnumKeyW(class_key, current_inst_idx, instance, 256);
            if (inst_enum_status != ERROR_SUCCESS)
            {
                webhook::write_log_critical_fmt("anti_vm",
                    "edid_instance_enum_done class_idx=%lu inst_idx=%lu status=%ld found=%d elapsed_ms=%llu",
                    static_cast<unsigned long>(current_class_idx),
                    static_cast<unsigned long>(current_inst_idx),
                    static_cast<long>(inst_enum_status),
                    found ? 1 : 0,
                    static_cast<unsigned long long>(vm_tick_ms() - started));
                break;
            }
            const uint64_t instance_hash = vm_fnv1a_wstr(instance);
            webhook::write_log_critical_fmt("anti_vm",
                "edid_instance_enum_post class_idx=%lu inst_idx=%lu instance_hash=0x%016llX elapsed_ms=%llu",
                static_cast<unsigned long>(current_class_idx),
                static_cast<unsigned long>(current_inst_idx),
                static_cast<unsigned long long>(instance_hash),
                static_cast<unsigned long long>(vm_tick_ms() - started));
            wchar_t edid_path[1024];
            swprintf_s(edid_path, 1024, L"%s\\%s\\Device Parameters", monitor_class, instance);

            HKEY params_key = nullptr;
            LSTATUS params_open_status = RegOpenKeyExW(display_key, edid_path, 0, KEY_READ, &params_key);
            webhook::write_log_critical_fmt("anti_vm",
                "edid_params_open_post class_idx=%lu inst_idx=%lu path_hash=0x%016llX status=%ld opened=%d elapsed_ms=%llu",
                static_cast<unsigned long>(current_class_idx),
                static_cast<unsigned long>(current_inst_idx),
                static_cast<unsigned long long>(vm_fnv1a_wstr(edid_path)),
                static_cast<long>(params_open_status),
                params_open_status == ERROR_SUCCESS ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - started));
            if (params_open_status != ERROR_SUCCESS)
                continue;

            uint8_t edid[256] = {};
            DWORD edid_size = sizeof(edid);
            DWORD type = 0;
            LSTATUS query_status = RegQueryValueExW(params_key, L"EDID", nullptr, &type,
                edid, &edid_size);
            webhook::write_log_critical_fmt("anti_vm",
                "edid_value_query_post class_idx=%lu inst_idx=%lu status=%ld type=%lu size=%lu elapsed_ms=%llu",
                static_cast<unsigned long>(current_class_idx),
                static_cast<unsigned long>(current_inst_idx),
                static_cast<long>(query_status),
                static_cast<unsigned long>(type),
                static_cast<unsigned long>(edid_size),
                static_cast<unsigned long long>(vm_tick_ms() - started));
            if (query_status == ERROR_SUCCESS && type == REG_BINARY && edid_size >= 10)
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
                            webhook::write_log_critical_fmt("anti_vm",
                                "edid_vm_mfg_hit class_idx=%lu inst_idx=%lu mfg=%c%c%c elapsed_ms=%llu",
                                static_cast<unsigned long>(current_class_idx),
                                static_cast<unsigned long>(current_inst_idx),
                                letters[0],
                                letters[1],
                                letters[2],
                                static_cast<unsigned long long>(vm_tick_ms() - started));
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
    webhook::write_log_critical_fmt("anti_vm",
        "edid_scan_exit found=%d classes=%lu elapsed_ms=%llu",
        found ? 1 : 0,
        static_cast<unsigned long>(class_idx),
        static_cast<unsigned long long>(vm_tick_ms() - started));
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

inline bool vm_report_has_vm_artifact(const vm_report_t& report)
{
    return report.registry_vm_services_active
        || report.registry_vm_hardware
        || report.vm_mac_prefix_active
        || report.firmware_vm_string
        || report.disk_vm_hardware
        || report.acpi_vm_oem
        || report.acpi_waet_table
        || report.edid_vm_manufacturer
        || report.kernel_zero_fp_vm
        || report.kernel_low_fp_vm
        || report.kernel_registry_vm
        || report.kernel_mac_vm
        || report.kernel_pci_vm;
}

inline bool vm_report_user_suspicion_above_threshold(const vm_report_t& report)
{
    if (report.any_zero_fp_signal())
        return true;
    if (report.hypervisor_hijack_contradiction)
        return true;
    if (report.untrusted_hypervisor)
        return true;
    if (report.independent_medium_family_count() >= 2)
        return true;
    return report.hidden_hypervisor_suspected && vm_report_has_vm_artifact(report);
}

inline void finalize_signal_policy(vm_report_t& report)
{
    report.untrusted_hypervisor = report.cpuid_hypervisor_bit
        && !report.ms_hv_approved
        && !report.cpuid_vendor_vm
        && !report.cpuid_hyperv_guest;

    report.signal_family_mask = 0;
    report.medium_family_mask = 0;
    report.contradiction_mask = 0;

    if (report.cpuid_hypervisor_bit || report.cpuid_vendor_vm || report.cpuid_hyperv_guest ||
        report.untrusted_hypervisor || report.hyperv_interface_mismatch ||
        report.cpuid_leaf_inconsistent || report.synthetic_hv_behavior)
    {
        report.signal_family_mask |= kFamilyCpuid;
    }
    if (report.hidden_hypervisor_suspected || report.tsc_qpc_unstable || report.kernel_hv_failed_majority)
        report.signal_family_mask |= kFamilyTiming;
    if (report.firmware_vm_string || report.acpi_vm_oem || report.acpi_waet_table || report.edid_vm_manufacturer)
        report.signal_family_mask |= kFamilyFirmware;
    if (report.registry_vm_hardware || report.vm_mac_prefix || report.disk_vm_hardware ||
        report.kernel_pci_vm || report.kernel_mac_vm || report.kernel_registry_vm)
    {
        report.signal_family_mask |= kFamilyDevice;
    }
    if (report.registry_vm_services_present)
        report.signal_family_mask |= kFamilyOsArtifact;
    if (report.kernel_query_ok || report.kernel_hv_deferred || report.kernel_hv_trust_failure() ||
        report.kernel_zero_fp_vm || report.kernel_low_fp_vm)
    {
        report.signal_family_mask |= kFamilyKernelHvdt;
    }

    if (report.tsc_qpc_unstable || report.hidden_hypervisor_suspected)
        report.medium_family_mask |= kFamilyTiming;
    if (report.registry_vm_hardware || report.vm_mac_prefix_active)
        report.medium_family_mask |= kFamilyDevice;
    if (report.registry_vm_services_active)
        report.medium_family_mask |= kFamilyOsArtifact;
    if (report.kernel_low_fp_vm)
        report.medium_family_mask |= kFamilyKernelHvdt;
    if (report.acpi_waet_table && !report.ms_hv_approved)
        report.medium_family_mask |= kFamilyFirmware;

    if (report.hidden_hypervisor_suspected)
        report.contradiction_mask |= kContradictionHiddenHv;
    if (report.cpuid_leaf_inconsistent)
        report.contradiction_mask |= kContradictionCpuidLeaf;
    if (report.tsc_qpc_unstable)
        report.contradiction_mask |= kContradictionTscQpc;
    if (report.synthetic_hv_behavior && !report.cpuid_hypervisor_bit)
        report.contradiction_mask |= kContradictionSyntheticHv;
    if (report.hyperv_interface_mismatch)
        report.contradiction_mask |= kContradictionHvInterface;
    if (report.cpuid_hyperv_guest)
        report.contradiction_mask |= kContradictionHvGuest;
    if (report.kernel_hv_failed_majority)
        report.contradiction_mask |= kContradictionKernelSideChannel;

    const bool hidden_with_artifact = report.hidden_hypervisor_suspected && vm_report_has_vm_artifact(report);
    const bool synthetic_without_windows_security = report.synthetic_hv_behavior
        && !report.cpuid_hypervisor_bit
        && !report.hvci_enabled
        && !report.vbs_enabled;
    report.hypervisor_hijack_contradiction =
        report.hyperv_interface_mismatch ||
        hidden_with_artifact ||
        (report.cpuid_leaf_inconsistent && synthetic_without_windows_security);

    if (report.hypervisor_hijack_contradiction)
        report.contradiction_mask |= kContradictionHiddenHv;

    report.medium_family_total = report.independent_medium_family_count();
    report.medium_signal_total = static_cast<uint32_t>(report.low_fp_count())
        + (report.tsc_qpc_unstable ? 1u : 0u)
        + (report.hidden_hypervisor_suspected ? 1u : 0u);

    const bool kernel_deferred_problem = report.kernel_hv_deferred &&
        (report.kernel_hv_marker_io_failed || report.kernel_hv_heartbeat_failed ||
         report.kernel_hv_query_failed || report.kernel_hv_previous_incomplete ||
         report.kernel_hv_suppressed_previous_incomplete);
    if (kernel_deferred_problem && vm_report_user_suspicion_above_threshold(report))
        report.kernel_hv_quarantine_deny = true;

    report.hard_signal_total = static_cast<uint32_t>(report.hard_signal_count());
}

inline vm_report_t full_scan()
{
    const uint64_t scan_started = vm_tick_ms();
    webhook::write_log_critical_fmt("anti_vm",
        "full_scan_enter pid=%lu tid=%lu tick=%llu",
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        static_cast<unsigned long long>(scan_started));
    auto step_pre = [&](const char* step) -> uint64_t {
        const uint64_t step_started = vm_tick_ms();
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_pre step=%s pid=%lu tid=%lu tick=%llu total_elapsed_ms=%llu",
            step,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(step_started),
            static_cast<unsigned long long>(step_started - scan_started));
        return step_started;
    };
    auto step_post = [&](const char* step, uint64_t step_started, int result) {
        const uint64_t now = vm_tick_ms();
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_post step=%s result=%d err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
            step,
            result,
            GetLastError(),
            static_cast<unsigned long long>(now - step_started),
            static_cast<unsigned long long>(now - scan_started));
    };
    vm_report_t report{};

    const bool ms_hv_approved = hv_preflight::g_ms_hv_approved;
    report.ms_hv_approved = ms_hv_approved;
    report.hvci_enabled = hv_preflight::g_hvci_enabled;
    report.vbs_enabled = hv_preflight::g_vbs_enabled;
    report.hidden_hypervisor_suspected = hv_preflight::g_hidden_hypervisor_suspected;
    report.cpuid_leaf_inconsistent = hv_preflight::g_cpuid_leaf_inconsistent;
    report.tsc_qpc_unstable = hv_preflight::g_tsc_qpc_unstable;
    report.synthetic_hv_behavior = hv_preflight::g_synthetic_hv_behavior;
    report.hyperv_interface_mismatch = hv_preflight::g_hv_interface_signature_mismatch;
    report.cpuid_hyperv_guest = hv_preflight::g_hyperv_guest_partition;
    if (ms_hv_approved) {
        report.summary = "ms_hv_approved_by_preflight ";
    }

    webhook::write_log_critical_fmt("anti_vm",
        "full_scan_preflight ms_hv=%d hvci=%d vbs=%d hidden_hv=%d cpuid_leaf=%d tsc_qpc=%d synthetic=%d hv_iface=%d hv_guest=%d elapsed_ms=%llu",
        report.ms_hv_approved ? 1 : 0,
        report.hvci_enabled ? 1 : 0,
        report.vbs_enabled ? 1 : 0,
        report.hidden_hypervisor_suspected ? 1 : 0,
        report.cpuid_leaf_inconsistent ? 1 : 0,
        report.tsc_qpc_unstable ? 1 : 0,
        report.synthetic_hv_behavior ? 1 : 0,
        report.hyperv_interface_mismatch ? 1 : 0,
        report.cpuid_hyperv_guest ? 1 : 0,
        static_cast<unsigned long long>(vm_tick_ms() - scan_started));

    uint64_t step_started = step_pre("cpuid_hypervisor_bit");
    report.cpuid_hypervisor_bit = check_cpuid_hypervisor_bit();
    step_post("cpuid_hypervisor_bit", step_started, report.cpuid_hypervisor_bit ? 1 : 0);

    step_started = step_pre("cpuid_vendor_string");
    report.vendor_name = check_cpuid_vendor_string();
    report.cpuid_vendor_vm = !report.vendor_name.empty();
    webhook::write_log_critical_fmt("anti_vm",
        "full_scan_step_post step=cpuid_vendor_string result=%d vendor_len=%zu vendor_hash=0x%016llX err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
        report.cpuid_vendor_vm ? 1 : 0,
        report.vendor_name.size(),
        static_cast<unsigned long long>(vm_fnv1a_bytes(report.vendor_name.data(), report.vendor_name.size())),
        GetLastError(),
        static_cast<unsigned long long>(vm_tick_ms() - step_started),
        static_cast<unsigned long long>(vm_tick_ms() - scan_started));

    step_started = step_pre("hyperv_guest_partition");
    report.cpuid_hyperv_guest = report.cpuid_hyperv_guest || is_microsoft_hyperv_guest_partition();
    if (report.cpuid_hyperv_guest && report.vendor_name.empty()) {
        report.vendor_name = "HyperV-Guest";
    }
    step_post("hyperv_guest_partition", step_started, report.cpuid_hyperv_guest ? 1 : 0);

    step_started = step_pre("hyperv_interface_mismatch");
    report.hyperv_interface_mismatch = report.hyperv_interface_mismatch || check_hyperv_interface_mismatch();
    step_post("hyperv_interface_mismatch", step_started, report.hyperv_interface_mismatch ? 1 : 0);

    {
        step_started = step_pre("registry_services");
        registry_vm_scan_t reg = check_vm_registry_keys();
        report.registry_vm_service_present_count = reg.present;
        report.registry_vm_service_active_count = reg.active;
        report.registry_vm_service_disabled_count = reg.disabled;
        report.registry_vm_services_present = reg.present != 0;
        report.registry_vm_services_active = reg.active != 0;
        report.registry_vm_services = report.registry_vm_services_active;
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_post step=registry_services result=%d present=%u active=%u disabled=%u err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
            report.registry_vm_services ? 1 : 0,
            reg.present,
            reg.active,
            reg.disabled,
            GetLastError(),
            static_cast<unsigned long long>(vm_tick_ms() - step_started),
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
    }

    step_started = step_pre("pci_hardware_ids");
    report.registry_vm_hardware = check_vm_hardware_ids();
    step_post("pci_hardware_ids", step_started, report.registry_vm_hardware ? 1 : 0);

    {
        step_started = step_pre("mac_prefixes");
        mac_vm_scan_t mac = check_vm_mac_prefixes(ms_hv_approved);
        report.vm_mac_candidate_count = mac.candidates;
        report.vm_mac_active_count = mac.active;
        report.vm_mac_hyperv_skipped_count = mac.hyperv_skipped;
        report.vm_mac_prefix = mac.candidates != 0;
        report.vm_mac_prefix_active = mac.active != 0;
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_post step=mac_prefixes result=%d candidates=%u active=%u hyperv_skipped=%u err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
            report.vm_mac_prefix ? 1 : 0,
            mac.candidates,
            mac.active,
            mac.hyperv_skipped,
            GetLastError(),
            static_cast<unsigned long long>(vm_tick_ms() - step_started),
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
    }

    step_started = step_pre("rsmb_firmware_tables");
    report.firmware_vm_string = check_firmware_tables();
    step_post("rsmb_firmware_tables", step_started, report.firmware_vm_string ? 1 : 0);

    step_started = step_pre("disk_hardware");
    report.disk_vm_hardware = check_qemu_disk_hardware();
    step_post("disk_hardware", step_started, report.disk_vm_hardware ? 1 : 0);

    {
        bool waet_present = false;
        step_started = step_pre("acpi_oem_signatures");
        report.acpi_vm_oem = check_acpi_oem_signatures(waet_present);
        report.acpi_waet_table = ms_hv_approved ? false : waet_present;
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_post step=acpi_oem_signatures result=%d waet=%d enforced_waet=%d err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
            report.acpi_vm_oem ? 1 : 0,
            waet_present ? 1 : 0,
            report.acpi_waet_table ? 1 : 0,
            GetLastError(),
            static_cast<unsigned long long>(vm_tick_ms() - step_started),
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
    }

    step_started = step_pre("edid_manufacturer");
    report.edid_vm_manufacturer = check_edid_manufacturer();
    step_post("edid_manufacturer", step_started, report.edid_vm_manufacturer ? 1 : 0);

    {
        const bool driver_loaded = driver_bridge::is_loaded();
        const bool driver_kernel = driver_loaded && driver_bridge::using_kernel_driver();
        const driver_bridge::dynamic_ioctl_state_t dyn = driver_bridge::dynamic_ioctl_state();
        const std::string run_id = standalone_license::run_correlation_id();
        step_started = step_pre("kernel_hv_detection");
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_detection_state run_id=%s loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X trust_failure=%d elapsed_ms=%llu",
            run_id.c_str(),
            driver_loaded ? 1 : 0,
            driver_kernel ? 1 : 0,
            dyn.connected ? 1 : 0,
            dyn.ready ? 1 : 0,
            dyn.instance_server_seed,
            dyn.instance_ioctl_seed,
            dyn.global_server_seed,
            dyn.global_ioctl_seed,
            dyn.ioctl_seed_hash,
            dyn.heartbeat_ioctl_seed_hash,
            report.kernel_hv_trust_failure() ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        const bool startup_hvdt_enabled = kernel_hv_startup_probe_enabled();
        webhook::write_log_critical_fmt("anti_vm",
            "kernel_hv_detection_policy run_id=%s startup_hvdt_enabled=%d loaded=%d kernel=%d dyn_ready=%d elapsed_ms=%llu",
            run_id.c_str(),
            startup_hvdt_enabled ? 1 : 0,
            driver_loaded ? 1 : 0,
            driver_kernel ? 1 : 0,
            dyn.ready ? 1 : 0,
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        driver_bridge::hv_kernel_detect_result_t kresult{};
        bool kernel_call_ok = false;
        DWORD kernel_call_err = ERROR_SUCCESS;
        bool kernel_call_allowed = false;
        kernel_hv_pending_marker_t prior_marker = kernel_hv_read_pending_marker();
        if (prior_marker.present && !prior_marker.parse_ok)
        {
            report.kernel_hv_marker_io_failed = true;
            report.kernel_hv_deferred = true;
            report.kernel_hv_error = prior_marker.last_error;
            report.summary += "kernel_hv_marker_read_failed_deferred ";
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_blocked_marker_read_failed err=%lu current_loaded=%d current_kernel=%d total_elapsed_ms=%llu",
                static_cast<unsigned long>(prior_marker.last_error),
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        else if (prior_marker.present && prior_marker.parse_ok && !prior_marker.stale)
        {
            report.kernel_hv_previous_incomplete = true;
            report.kernel_hv_suppressed_previous_incomplete = true;
            report.kernel_hv_deferred = true;
            report.kernel_hv_error = ERROR_TIMEOUT;
            report.summary += "kernel_hv_previous_incomplete_suppressed ";
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_suppressed_previous_incomplete marker_pid=%lu marker_tid=%lu marker_age_ms=%llu reboot=%d marker_loaded=%lu marker_kernel=%lu current_loaded=%d current_kernel=%d prehash=0x%016llX total_elapsed_ms=%llu",
                static_cast<unsigned long>(prior_marker.pid),
                static_cast<unsigned long>(prior_marker.tid),
                static_cast<unsigned long long>(prior_marker.age_ms),
                prior_marker.reboot_since_marker ? 1 : 0,
                static_cast<unsigned long>(prior_marker.driver_loaded),
                static_cast<unsigned long>(prior_marker.driver_kernel),
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                static_cast<unsigned long long>(prior_marker.preflight_hash),
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        else if (driver_kernel && !startup_hvdt_enabled)
        {
            report.kernel_hv_deferred = true;
            report.kernel_hv_error = ERROR_NOT_READY;
            report.summary += "kernel_hv_startup_deferred ";
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_deferred_startup run_id=%s loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X prior_present=%d startup_hvdt_enabled=%d total_elapsed_ms=%llu",
                run_id.c_str(),
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                dyn.connected ? 1 : 0,
                dyn.ready ? 1 : 0,
                dyn.instance_server_seed,
                dyn.instance_ioctl_seed,
                dyn.global_server_seed,
                dyn.global_ioctl_seed,
                dyn.ioctl_seed_hash,
                dyn.heartbeat_ioctl_seed_hash,
                prior_marker.present ? 1 : 0,
                startup_hvdt_enabled ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        else if (driver_kernel && !dyn.ready)
        {
            report.kernel_hv_deferred = true;
            report.kernel_hv_error = ERROR_NOT_READY;
            report.summary += "kernel_hv_dynamic_ioctl_not_ready_deferred ";
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_deferred_dynamic_ioctl_not_ready run_id=%s loaded=%d kernel=%d connected=%d dyn_ready=%d inst_seed=%u/%u global_seed=%u/%u ioctl_seed_hash=0x%08X hb_ioctl_seed_hash=0x%08X startup_hvdt_enabled=%d total_elapsed_ms=%llu",
                run_id.c_str(),
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                dyn.connected ? 1 : 0,
                dyn.ready ? 1 : 0,
                dyn.instance_server_seed,
                dyn.instance_ioctl_seed,
                dyn.global_server_seed,
                dyn.global_ioctl_seed,
                dyn.ioctl_seed_hash,
                dyn.heartbeat_ioctl_seed_hash,
                startup_hvdt_enabled ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        else if (driver_kernel)
        {
            SetLastError(ERROR_SUCCESS);
            const uint64_t heartbeat_tick = vm_tick_ms();
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_heartbeat_pre pid=%lu tid=%lu tick=%llu loaded=%d kernel=%d",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(heartbeat_tick),
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0);
            bool heartbeat_ok = driver_bridge::refresh_heartbeat();
            DWORD heartbeat_err = heartbeat_ok ? ERROR_SUCCESS : GetLastError();
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_heartbeat_post ok=%d err=%lu elapsed_ms=%llu loaded_after=%d kernel_after=%d",
                heartbeat_ok ? 1 : 0,
                static_cast<unsigned long>(heartbeat_err),
                static_cast<unsigned long long>(vm_tick_ms() - heartbeat_tick),
                driver_bridge::is_loaded() ? 1 : 0,
                driver_bridge::using_kernel_driver() ? 1 : 0);
            if (!heartbeat_ok)
            {
                report.kernel_hv_heartbeat_failed = true;
                report.kernel_hv_deferred = true;
                report.kernel_hv_error = heartbeat_err;
                report.summary += "kernel_hv_heartbeat_failed_deferred ";
            }
            else if (!kernel_hv_write_pending_marker(report, driver_loaded, driver_kernel))
            {
                report.kernel_hv_marker_io_failed = true;
                report.kernel_hv_deferred = true;
                report.kernel_hv_error = GetLastError();
                report.summary += "kernel_hv_marker_write_failed_deferred ";
            }
            else
            {
                kernel_call_allowed = true;
            }
        }
        else
        {
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_not_invoked_no_kernel loaded=%d kernel=%d elapsed_ms=%llu",
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        if (kernel_call_allowed)
        {
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_call_pre pid=%lu tid=%lu tick=%llu elapsed_ms=%llu",
                GetCurrentProcessId(),
                GetCurrentThreadId(),
                static_cast<unsigned long long>(vm_tick_ms()),
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
            SetLastError(ERROR_SUCCESS);
            const uint64_t kernel_call_tick = vm_tick_ms();
            kernel_call_ok = driver_bridge::run_kernel_hv_detection(kresult);
            kernel_call_err = kernel_call_ok ? ERROR_SUCCESS : GetLastError();
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_detection_call_post ok=%d err=%lu elapsed_ms=%llu total_elapsed_ms=%llu",
                kernel_call_ok ? 1 : 0,
                static_cast<unsigned long>(kernel_call_err),
                static_cast<unsigned long long>(vm_tick_ms() - kernel_call_tick),
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
            kernel_hv_clear_pending_marker(kernel_call_ok ? "post_success" : "post_failure");
        }
        if (kernel_call_ok) {
            report.kernel_query_ok = true;
            report.kernel_cpuid_vendor = kresult.vmf_cpuid_vendor != 0;
            report.kernel_hyperv_guest = kresult.vmf_hyperv_guest != 0;
            report.kernel_smbios_vm = kresult.vmf_smbios_vm != 0;
            report.kernel_acpi_vm = kresult.vmf_acpi_vm != 0;
            report.kernel_pci_vm = kresult.vmf_pci_vm != 0;
            report.kernel_disk_vm = kresult.vmf_disk_vm != 0;
            report.kernel_mac_vm = kresult.vmf_mac_vm != 0;
            report.kernel_registry_vm = kresult.vmf_registry_vm != 0;
            const uint8_t kernel_identity_count =
                kresult.vmf_cpuid_vendor + kresult.vmf_hyperv_guest +
                kresult.vmf_smbios_vm + kresult.vmf_acpi_vm +
                kresult.vmf_disk_vm;
            const uint8_t kernel_artifact_count =
                kresult.vmf_pci_vm + kresult.vmf_mac_vm + kresult.vmf_registry_vm;
            const uint8_t kernel_hard_count = kernel_identity_count;
            const uint8_t kernel_soft_count =
                kernel_artifact_count;
            report.kernel_hard_count = kernel_hard_count;
            report.kernel_soft_count = kernel_soft_count;
            report.kernel_ms_hv_root = kresult.ms_hv_root;

            report.kernel_zero_fp_vm = (kernel_identity_count > 0);
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
            if (report.kernel_hv_failed_majority)
                report.kernel_zero_fp_vm = true;

            {
                char kdbg[512];
                _snprintf_s(kdbg, sizeof(kdbg), _TRUNCATE,
                    "kernel_hv_result cpuid=%u hyperv_guest=%u smbios=%u acpi=%u pci=%u disk=%u mac=%u registry=%u identity=%u artifact=%u is_vm=%u ms_hv_root=%u hv_failed=%u/%u total_failed=%u hmac_hash=0x%016llX",
                    static_cast<unsigned>(kresult.vmf_cpuid_vendor),
                    static_cast<unsigned>(kresult.vmf_hyperv_guest),
                    static_cast<unsigned>(kresult.vmf_smbios_vm),
                    static_cast<unsigned>(kresult.vmf_acpi_vm),
                    static_cast<unsigned>(kresult.vmf_pci_vm),
                    static_cast<unsigned>(kresult.vmf_disk_vm),
                    static_cast<unsigned>(kresult.vmf_mac_vm),
                    static_cast<unsigned>(kresult.vmf_registry_vm),
                    static_cast<unsigned>(kernel_identity_count),
                    static_cast<unsigned>(kernel_artifact_count),
                    static_cast<unsigned>(kresult.is_virtual_machine),
                    static_cast<unsigned>(kresult.ms_hv_root),
                    static_cast<unsigned>(hv_failed_count),
                    static_cast<unsigned>(kresult.total_run),
                    static_cast<unsigned>(kresult.total_failed),
                    static_cast<unsigned long long>(vm_fnv1a_bytes(kresult.measurements_hmac, sizeof(kresult.measurements_hmac))));
                webhook::write_log("init", kdbg);
            }

            if (report.vendor_name.empty() && kresult.vm_vendor_name[0] != 0) {
                size_t n = 0;
                while (n < sizeof(kresult.vm_vendor_name) && kresult.vm_vendor_name[n] != 0) ++n;
                report.vendor_name.assign(kresult.vm_vendor_name, n);
            }
        } else if (driver_kernel && !report.kernel_hv_deferred && !report.kernel_hv_trust_failure()) {
            report.kernel_hv_query_failed = true;
            report.kernel_hv_deferred = true;
            report.kernel_hv_error = kernel_call_err;
            report.summary += "kernel_hv_query_failed_deferred ";
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_result query_failed err=%lu total_elapsed_ms=%llu",
                static_cast<unsigned long>(kernel_call_err),
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        } else if (report.kernel_hv_deferred) {
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_result deferred err=%lu previous=%d marker_io=%d heartbeat=%d query=%d suppressed_previous=%d total_elapsed_ms=%llu",
                static_cast<unsigned long>(report.kernel_hv_error),
                report.kernel_hv_previous_incomplete ? 1 : 0,
                report.kernel_hv_marker_io_failed ? 1 : 0,
                report.kernel_hv_heartbeat_failed ? 1 : 0,
                report.kernel_hv_query_failed ? 1 : 0,
                report.kernel_hv_suppressed_previous_incomplete ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        } else if (!driver_kernel) {
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_result skipped_no_kernel loaded=%d kernel=%d total_elapsed_ms=%llu",
                driver_loaded ? 1 : 0,
                driver_kernel ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        } else {
            webhook::write_log_critical_fmt("anti_vm",
                "kernel_hv_result skipped_untrusted err=%lu previous=%d marker_io=%d heartbeat=%d query=%d deferred=%d total_elapsed_ms=%llu",
                static_cast<unsigned long>(report.kernel_hv_error),
                report.kernel_hv_previous_incomplete ? 1 : 0,
                report.kernel_hv_marker_io_failed ? 1 : 0,
                report.kernel_hv_heartbeat_failed ? 1 : 0,
                report.kernel_hv_query_failed ? 1 : 0,
                report.kernel_hv_deferred ? 1 : 0,
                static_cast<unsigned long long>(vm_tick_ms() - scan_started));
        }
        webhook::write_log_critical_fmt("anti_vm",
            "full_scan_step_post step=kernel_hv_detection result=%d kernel_ok=%d trust_failure=%d deferred=%d hard=%u soft=%u hv_failed=%u/%u err=%lu step_elapsed_ms=%llu total_elapsed_ms=%llu",
            report.kernel_zero_fp_vm || report.kernel_low_fp_vm || report.kernel_hv_failed_majority ? 1 : 0,
            report.kernel_query_ok ? 1 : 0,
            report.kernel_hv_trust_failure() ? 1 : 0,
            report.kernel_hv_deferred ? 1 : 0,
            static_cast<unsigned>(report.kernel_hard_count),
            static_cast<unsigned>(report.kernel_soft_count),
            static_cast<unsigned>(report.kernel_hv_failed_count),
            static_cast<unsigned>(report.kernel_total_run),
            GetLastError(),
            static_cast<unsigned long long>(vm_tick_ms() - step_started),
            static_cast<unsigned long long>(vm_tick_ms() - scan_started));
    }

    step_started = step_pre("synthetic_vm_trip");
    if (synthetic_vm_trip_active())
    {
        report.firmware_vm_string = true;
        report.summary += "synthetic_test_trip ";
    }
    step_post("synthetic_vm_trip", step_started, report.firmware_vm_string ? 1 : 0);

    finalize_signal_policy(report);

    if (report.cpuid_hypervisor_bit) report.summary += "cpuid_hv ";
    if (report.untrusted_hypervisor) report.summary += "untrusted_hv ";
    if (report.cpuid_vendor_vm) report.summary += "vendor:" + report.vendor_name + " ";
    if (report.cpuid_hyperv_guest) report.summary += "hyperv_guest ";
    if (report.hyperv_interface_mismatch) report.summary += "hv_iface_mismatch ";
    if (report.hidden_hypervisor_suspected) report.summary += "hidden_hv_suspected ";
    if (report.cpuid_leaf_inconsistent) report.summary += "cpuid_leaf_inconsistent ";
    if (report.tsc_qpc_unstable) report.summary += "tsc_qpc_unstable ";
    if (report.synthetic_hv_behavior) report.summary += "synthetic_hv_behavior ";
    if (report.hvci_enabled) report.summary += "hvci_allowed ";
    if (report.vbs_enabled) report.summary += "vbs_allowed ";
    if (report.registry_vm_services_present) {
        report.summary += "reg_svc_present(";
        report.summary += std::to_string(report.registry_vm_service_present_count);
        report.summary += ") ";
    }
    if (report.registry_vm_services_active) {
        report.summary += "reg_svc_active(";
        report.summary += std::to_string(report.registry_vm_service_active_count);
        report.summary += ") ";
    }
    if (report.registry_vm_hardware) report.summary += "reg_hw ";
    if (report.vm_mac_prefix) {
        report.summary += "mac_candidate(";
        report.summary += std::to_string(report.vm_mac_candidate_count);
        report.summary += ") ";
    }
    if (report.vm_mac_prefix_active) {
        report.summary += "mac_active(";
        report.summary += std::to_string(report.vm_mac_active_count);
        report.summary += ") ";
    }
    if (report.vm_mac_hyperv_skipped_count) {
        report.summary += "mac_hyperv_skipped(";
        report.summary += std::to_string(report.vm_mac_hyperv_skipped_count);
        report.summary += ") ";
    }
    if (report.firmware_vm_string) report.summary += "firmware ";
    if (report.disk_vm_hardware) report.summary += "disk_hw ";
    if (report.acpi_vm_oem) report.summary += "acpi_oem ";
    if (report.acpi_waet_table) report.summary += "acpi_waet ";
    if (report.edid_vm_manufacturer) report.summary += "edid_vm ";
    if (report.kernel_zero_fp_vm) report.summary += "kernel_vm_fp ";
    if (report.kernel_low_fp_vm) report.summary += "kernel_vm_corroborated ";
    if (report.kernel_registry_vm) report.summary += "kernel_registry_artifact ";
    if (report.kernel_mac_vm) report.summary += "kernel_mac_artifact ";
    if (report.kernel_pci_vm) report.summary += "kernel_pci_artifact ";
    if (report.kernel_hv_failed_majority) {
        report.summary += "kernel_hv_majority(";
        report.summary += std::to_string(report.kernel_hv_failed_count);
        report.summary += "/";
        report.summary += std::to_string(report.kernel_total_run);
        report.summary += ") ";
    }
    if (report.kernel_hv_quarantine_deny) report.summary += "kernel_hv_quarantine ";
    {
        char decision[1024];
        _snprintf_s(decision, sizeof(decision), _TRUNCATE,
            "vm_detect_decision version=0x%08X action=%s hard=%u low=%d medium_signals=%u medium_families=%u family_mask=0x%08X medium_mask=0x%08X contradiction_mask=0x%08X reg_present=%u reg_active=%u reg_disabled=%u mac_candidate=%u mac_active=%u kernel_ok=%d kernel_trust_failure=%d kernel_deferred=%d kernel_marker_io=%d kernel_heartbeat=%d kernel_query=%d kernel_previous=%d kernel_err=%lu kernel_hard=%u kernel_soft=%u kernel_hv_failed=%u/%u ms_hv=%d hvci=%d vbs=%d summary_hash=0x%016llX",
            kPolicyVersion,
            report.action_name(),
            report.hard_signal_total,
            report.low_fp_count(),
            report.medium_signal_total,
            report.medium_family_total,
            report.signal_family_mask,
            report.medium_family_mask,
            report.contradiction_mask,
            report.registry_vm_service_present_count,
            report.registry_vm_service_active_count,
            report.registry_vm_service_disabled_count,
            report.vm_mac_candidate_count,
            report.vm_mac_active_count,
            report.kernel_query_ok ? 1 : 0,
            report.kernel_hv_trust_failure() ? 1 : 0,
            report.kernel_hv_deferred ? 1 : 0,
            report.kernel_hv_marker_io_failed ? 1 : 0,
            report.kernel_hv_heartbeat_failed ? 1 : 0,
            report.kernel_hv_query_failed ? 1 : 0,
            report.kernel_hv_previous_incomplete ? 1 : 0,
            static_cast<unsigned long>(report.kernel_hv_error),
            static_cast<unsigned>(report.kernel_hard_count),
            static_cast<unsigned>(report.kernel_soft_count),
            static_cast<unsigned>(report.kernel_hv_failed_count),
            static_cast<unsigned>(report.kernel_total_run),
            report.ms_hv_approved ? 1 : 0,
            report.hvci_enabled ? 1 : 0,
            report.vbs_enabled ? 1 : 0,
            static_cast<unsigned long long>(vm_fnv1a_bytes(report.summary.data(), report.summary.size())));
        webhook::write_log("init", decision);
    }

    webhook::write_log_critical_fmt("anti_vm",
        "full_scan_exit version=0x%08X action=%s hard=%u low=%d medium_families=%u family_mask=0x%08X contradiction_mask=0x%08X kernel_trust_failure=%d kernel_deferred=%d kernel_quarantine=%d kernel_err=%lu ms_hv=%d hvci=%d vbs=%d summary_hash=0x%016llX elapsed_ms=%llu",
        kPolicyVersion,
        report.action_name(),
        report.hard_signal_total,
        report.low_fp_count(),
        report.medium_family_total,
        report.signal_family_mask,
        report.contradiction_mask,
        report.kernel_hv_trust_failure() ? 1 : 0,
        report.kernel_hv_deferred ? 1 : 0,
        report.kernel_hv_quarantine_deny ? 1 : 0,
        static_cast<unsigned long>(report.kernel_hv_error),
        report.ms_hv_approved ? 1 : 0,
        report.hvci_enabled ? 1 : 0,
        report.vbs_enabled ? 1 : 0,
        static_cast<unsigned long long>(vm_fnv1a_bytes(report.summary.data(), report.summary.size())),
        static_cast<unsigned long long>(vm_tick_ms() - scan_started));

    return report;
}

}
}
