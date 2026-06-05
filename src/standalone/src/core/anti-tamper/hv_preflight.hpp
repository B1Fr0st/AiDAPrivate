#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winioctl.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <algorithm>
#include <string>
#include <vector>

#include "obfuscation.hpp"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")

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
    bool nvram_vm_string_hit;
    bool disk_vm_string_hit;
    bool edid_vm_manufacturer_hit;
    bool hv_interface_signature_mismatch;
    bool hidden_hypervisor_suspected;
    bool cpuid_leaf_inconsistent;
    bool tsc_qpc_unstable;
    bool synthetic_hv_behavior;
    bool hyperv_guest_partition;
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
constexpr uint32_t kPolicyVersion = 0x20260605u;
constexpr uint32_t kArtifactFirmware = 1u << 0;
constexpr uint32_t kArtifactProcess = 1u << 1;
constexpr uint32_t kArtifactNvram = 1u << 2;
constexpr uint32_t kArtifactDisk = 1u << 3;
constexpr uint32_t kArtifactEdid = 1u << 4;
constexpr uint32_t kContradictionHiddenHv = 1u << 0;
constexpr uint32_t kContradictionCpuidLeaf = 1u << 1;
constexpr uint32_t kContradictionTscQpc = 1u << 2;
constexpr uint32_t kContradictionSyntheticHv = 1u << 3;
constexpr uint32_t kContradictionHvInterface = 1u << 4;
constexpr uint32_t kContradictionHvGuest = 1u << 5;

inline NtQuerySystemInformation_t resolve_nt_query()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(nt, "NtQuerySystemInformation"));
}

inline constexpr uint8_t kDevModeReceiptMacKey[32] = {
    0x9D, 0x4A, 0x71, 0xF8, 0x2C, 0xE6, 0x55, 0x18,
    0xB7, 0x03, 0x1E, 0xCA, 0x8F, 0x6B, 0x40, 0x29,
    0x77, 0x52, 0x9C, 0x3D, 0xAB, 0xF1, 0x14, 0x8E,
    0x60, 0x35, 0xD7, 0x21, 0x4F, 0x88, 0xCB, 0x12
};

inline constexpr uint32_t kDevModeReceiptVersion = 0x4156AD01u;
inline constexpr uint32_t kDevModeReceiptMinSize = 4 + 16 + 32 + 32;
inline constexpr uint32_t kDevModeReceiptMaxSize = 4 + 16 + 256 + 32;

inline bool hmac_sha256_verify(const uint8_t* key, uint32_t key_len,
                                const uint8_t* data, uint32_t data_len,
                                const uint8_t mac_expected[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                    nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;
    bool ok = false;
    if (BCryptCreateHash(alg, &hash, nullptr, 0,
                         const_cast<PUCHAR>(key), key_len, 0) == 0)
    {
        if (BCryptHashData(hash, const_cast<PUCHAR>(data), data_len, 0) == 0)
        {
            uint8_t mac_actual[32] = {};
            if (BCryptFinishHash(hash, mac_actual, 32, 0) == 0)
            {
                uint32_t diff = 0;
                for (int i = 0; i < 32; ++i)
                    diff |= static_cast<uint32_t>(mac_actual[i] ^ mac_expected[i]);
                ok = (diff == 0);
            }
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

inline bool tpm_provider_available()
{
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(
        &prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st != ERROR_SUCCESS)
        return false;
    NCryptFreeObject(prov);
    return true;
}

inline bool compute_local_quote(uint8_t out_quote[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;
    bool ok = false;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0)
    {
        DWORD vol_serial = 0;
        wchar_t sys_root[MAX_PATH] = {};
        UINT got = GetSystemWindowsDirectoryW(sys_root, MAX_PATH);
        if (got > 0 && got < MAX_PATH)
        {
            wchar_t root_path[8] = { sys_root[0], L':', L'\\', 0 };
            DWORD comp_len = 0, fs_flags = 0;
            GetVolumeInformationW(root_path, nullptr, 0, &vol_serial, &comp_len, &fs_flags, nullptr, 0);
        }
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(&vol_serial), sizeof(vol_serial), 0);
        wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD cn_len = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(computer_name, &cn_len) && cn_len > 0)
        {
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(computer_name),
                static_cast<ULONG>(cn_len * sizeof(wchar_t)), 0);
        }
        uint8_t tpm_marker = 0x00u;
        BCryptHashData(hash, &tpm_marker, 1, 0);
        ok = (BCryptFinishHash(hash, out_quote, 32, 0) == 0);
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

inline bool verify_devmode_receipt(const uint8_t* receipt, uint32_t size)
{
    if (size < kDevModeReceiptMinSize || size > kDevModeReceiptMaxSize)
        return false;

    uint32_t version = 0;
    std::memcpy(&version, receipt, 4);
    if (version != kDevModeReceiptVersion)
        return false;

    uint32_t mac_offset = size - 32;
    const uint8_t* mac_expected = receipt + mac_offset;
    if (!hmac_sha256_verify(kDevModeReceiptMacKey, 32,
        receipt, mac_offset, mac_expected))
        return false;

    uint8_t local_quote[32] = {};
    if (!compute_local_quote(local_quote))
        return false;

    uint32_t quote_offset = 4 + 16;
    if (mac_offset < quote_offset + 32)
        return false;

    uint32_t diff = 0;
    for (int i = 0; i < 32; ++i)
        diff |= static_cast<uint32_t>(local_quote[i] ^ receipt[quote_offset + i]);
    if (diff != 0)
        return false;

    return true;
}

inline bool devmode_bypass_set()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\AiDA", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;

    DWORD type = 0;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(key, L"DevModeReceipt", nullptr, &type,
        nullptr, &size);
    if (rc != ERROR_SUCCESS || type != REG_BINARY ||
        size < kDevModeReceiptMinSize || size > kDevModeReceiptMaxSize)
    {
        RegCloseKey(key);
        return false;
    }

    std::vector<uint8_t> receipt(size, 0);
    rc = RegQueryValueExW(key, L"DevModeReceipt", nullptr, &type,
        receipt.data(), &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS)
        return false;

    return verify_devmode_receipt(receipt.data(), size);
}

inline bool read_cpuid_hv_bit()
{
    int regs[4] = {};
    __try
    {
        __cpuid(regs, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return (regs[2] & (1 << 31)) != 0;
}

inline bool safe_cpuidex(int regs[4], int leaf, int subleaf)
{
    std::memset(regs, 0, sizeof(int) * 4);
    __try
    {
        __cpuidex(regs, leaf, subleaf);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        std::memset(regs, 0, sizeof(int) * 4);
        return false;
    }
}

inline bool safe_rdtscp(unsigned long long& value, unsigned int& aux)
{
    value = 0;
    aux = 0;
    __try
    {
        value = __rdtscp(&aux);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        value = 0;
        aux = 0;
        return false;
    }
}

inline void read_hv_vendor(char out12[12])
{
    int regs[4] = {};
    std::memset(out12, 0, 12);
    __try
    {
        __cpuid(regs, 0x40000000);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return;
    }
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

inline bool hypervisor_leaf_present(char out12[12], uint32_t& max_leaf)
{
    if (out12)
        std::memset(out12, 0, 12);
    max_leaf = 0;
    int regs[4] = {};
    if (!safe_cpuidex(regs, 0x40000000, 0))
        return false;
    max_leaf = static_cast<uint32_t>(regs[0]);
    char vendor[12] = {};
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    bool vendor_nonzero = false;
    bool vendor_printable = true;
    for (int i = 0; i < 12; ++i)
    {
        vendor_nonzero = vendor_nonzero || vendor[i] != 0;
        unsigned char c = static_cast<unsigned char>(vendor[i]);
        if (c != 0 && (c < 0x20 || c > 0x7E))
            vendor_printable = false;
    }
    if (out12)
        std::memcpy(out12, vendor, 12);
    return max_leaf >= 0x40000000u && max_leaf <= 0x4000FFFFu && vendor_nonzero && vendor_printable;
}

inline bool cpuid_leaf_inconsistent_probe(bool hv_bit_set)
{
    char vendor[12] = {};
    uint32_t max_leaf = 0;
    const bool leaf_present = hypervisor_leaf_present(vendor, max_leaf);
    if (!hv_bit_set)
        return leaf_present;
    if (!leaf_present)
        return true;
    bool vendor_nonzero = false;
    for (int i = 0; i < 12; ++i)
        vendor_nonzero = vendor_nonzero || vendor[i] != 0;
    return !vendor_nonzero || max_leaf < 0x40000001u;
}

inline bool synthetic_hv_behavior_probe()
{
    char vendor[12] = {};
    uint32_t max_leaf = 0;
    if (!hypervisor_leaf_present(vendor, max_leaf))
        return false;
    int regs[4] = {};
    if (max_leaf >= 0x40000001u && safe_cpuidex(regs, 0x40000001, 0))
    {
        if (static_cast<uint32_t>(regs[0]) == 0x31237648u)
            return true;
    }
    if (max_leaf >= 0x40000003u && safe_cpuidex(regs, 0x40000003, 0))
    {
        uint32_t feature_union = static_cast<uint32_t>(regs[0]) |
            static_cast<uint32_t>(regs[1]) |
            static_cast<uint32_t>(regs[2]) |
            static_cast<uint32_t>(regs[3]);
        if (feature_union != 0)
            return true;
    }
    return false;
}

inline bool hyperv_guest_partition_probe()
{
    int regs[4] = {};
    if (!safe_cpuidex(regs, 1, 0))
        return false;
    if ((regs[2] & (1 << 31)) == 0)
        return false;
    if (!safe_cpuidex(regs, 0x40000000, 0))
        return false;
    char vendor[12];
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    if (!is_microsoft_hv(vendor))
        return false;
    if (!safe_cpuidex(regs, 0x40000001, 0))
        return false;
    if (static_cast<uint32_t>(regs[0]) != 0x31237648u)
        return false;
    if (!safe_cpuidex(regs, 0x40000003, 0))
        return false;
    uint32_t partition_caps = static_cast<uint32_t>(regs[1]);
    constexpr uint32_t root_bits = (1u << 0) | (1u << 5);
    return (partition_caps & root_bits) == 0;
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
            "VMware", "VirtualBox", "QEMU", "innotek", "Xen", "Parallels", "Bochs",
            "BXPC", "OVMF", "EDK II", "Tianocore", "Standard PC (Q35", "SeaBIOS", "VBOX"
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
    __try
    {
        __cpuid(regs, 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    return (regs[2] & (1 << 26)) != 0 && (regs[2] & (1 << 27)) != 0;
}

inline bool xsetbv_probe()
{
    if (!cpu_supports_xsave())
        return false;

    unsigned long long xcr0 = 0;
    __try
    {
        xcr0 = _xgetbv(0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    if ((xcr0 & 1ULL) == 0)
        return false;
    return false;
}

inline uint32_t timing_probe_median()
{
    constexpr int kSamples = 1024;
    std::vector<uint32_t> samples(static_cast<size_t>(kSamples), 0u);

    HANDLE thread = GetCurrentThread();
    DWORD_PTR previous_mask = 0;
    DWORD_PTR active_processors = 0;
    DWORD_PTR system_processors = 0;
    bool affinity_set = false;
    if (GetProcessAffinityMask(GetCurrentProcess(), &active_processors, &system_processors) && active_processors != 0)
    {
        DWORD_PTR target_mask = active_processors & (~active_processors + 1);
        DWORD_PTR prev = SetThreadAffinityMask(thread, target_mask);
        if (prev != 0)
        {
            previous_mask = prev;
            affinity_set = true;
        }
    }

    int previous_priority = GetThreadPriority(thread);
    bool priority_set = false;
    if (previous_priority != THREAD_PRIORITY_ERROR_RETURN)
    {
        if (SetThreadPriority(thread, THREAD_PRIORITY_TIME_CRITICAL))
            priority_set = true;
    }

    for (int i = 0; i < kSamples; ++i)
    {
        int dummy[4] = {};
        unsigned int aux0 = 0;
        unsigned int aux1 = 0;
        unsigned long long t0 = __rdtscp(&aux0);
        __cpuid(dummy, 0);
        unsigned long long t1 = __rdtscp(&aux1);
        unsigned long long d = t1 - t0;
        samples[static_cast<size_t>(i)] = d > 0xFFFFFFFFULL ? 0xFFFFFFFFu : static_cast<uint32_t>(d);
    }

    if (priority_set)
        SetThreadPriority(thread, previous_priority);
    if (affinity_set)
        SetThreadAffinityMask(thread, previous_mask);

    std::sort(samples.begin(), samples.end());
    return samples[static_cast<size_t>(kSamples / 2)];
}

inline bool tsc_qpc_stability_probe()
{
    LARGE_INTEGER freq{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart < 1000 || freq.QuadPart > 1000000000LL)
        return true;

    HANDLE thread = GetCurrentThread();
    DWORD_PTR previous_mask = 0;
    DWORD_PTR active_processors = 0;
    DWORD_PTR system_processors = 0;
    bool affinity_set = false;
    if (GetProcessAffinityMask(GetCurrentProcess(), &active_processors, &system_processors) && active_processors != 0)
    {
        DWORD_PTR target_mask = active_processors & (~active_processors + 1);
        DWORD_PTR prev = SetThreadAffinityMask(thread, target_mask);
        if (prev != 0)
        {
            previous_mask = prev;
            affinity_set = true;
        }
    }

    bool probe_failed = false;
    uint32_t backwards = 0;
    uint32_t zero_qpc_spans = 0;
    uint32_t excessive = 0;
    unsigned long long deltas[128] = {};
    uint32_t count = 0;

    for (uint32_t i = 0; i < 128; ++i)
    {
        LARGE_INTEGER q0{};
        LARGE_INTEGER q1{};
        unsigned long long t0 = 0;
        unsigned long long t1 = 0;
        unsigned int aux0 = 0;
        unsigned int aux1 = 0;
        int regs[4] = {};
        if (!QueryPerformanceCounter(&q0))
        {
            probe_failed = true;
            break;
        }
        if (!safe_rdtscp(t0, aux0))
        {
            probe_failed = true;
            break;
        }
        __cpuid(regs, 0);
        if (!safe_rdtscp(t1, aux1))
        {
            probe_failed = true;
            break;
        }
        if (!QueryPerformanceCounter(&q1))
        {
            probe_failed = true;
            break;
        }
        if (q1.QuadPart < q0.QuadPart || t1 < t0)
            ++backwards;
        if (q1.QuadPart == q0.QuadPart)
            ++zero_qpc_spans;
        if (count < 128)
            deltas[count++] = t1 >= t0 ? t1 - t0 : 0;
    }

    if (affinity_set)
        SetThreadAffinityMask(thread, previous_mask);

    if (probe_failed)
        return true;
    if (backwards != 0)
        return true;
    if (count == 0)
        return false;
    std::sort(deltas, deltas + count);
    unsigned long long median = deltas[count / 2];
    if (median == 0)
        return zero_qpc_spans > 96;
    unsigned long long limit = median * 64ULL + 50000ULL;
    for (uint32_t i = 0; i < count; ++i)
    {
        if (deltas[i] > limit)
            ++excessive;
    }
    return excessive >= 8 || zero_qpc_spans > 120;
}

inline bool validate_ms_hv_features()
{
    int regs[4] = {};
    if (!safe_cpuidex(regs, 0x40000003, 0))
        return false;
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

inline bool acquire_system_environment_privilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid))
    {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &tp,
                                          sizeof(tp), nullptr, nullptr);
    DWORD adj_err = GetLastError();
    CloseHandle(token);

    if (!adjusted)
        return false;
    if (adj_err == ERROR_NOT_ALL_ASSIGNED)
        return false;
    return true;
}

inline bool case_insensitive_substr_ascii(const uint8_t* hay, size_t hay_len,
                                          const char* needle)
{
    size_t nlen = std::strlen(needle);
    if (nlen == 0 || hay_len < nlen) return false;
    for (size_t i = 0; i + nlen <= hay_len; ++i)
    {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j)
        {
            unsigned char a = hay[i + j];
            unsigned char b = static_cast<unsigned char>(needle[j]);
            if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + 32);
            if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + 32);
            if (a != b) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

inline bool scan_nvram_boot_order()
{
    using GetFwExW_t = DWORD (WINAPI*)(LPCWSTR, LPCWSTR, PVOID, DWORD, PDWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;
    auto get_fw = reinterpret_cast<GetFwExW_t>(
        GetProcAddress(k32, "GetFirmwareEnvironmentVariableExW"));
    if (!get_fw) return false;

    if (!acquire_system_environment_privilege())
        return false;

    static const wchar_t kEfiGlobal[] = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
    static const wchar_t* kVarNames[] = {
        L"BootOrder", L"PK", L"KEK", L"db", L"dbx",
        L"PKDefault", L"KEKDefault", L"dbDefault", L"dbxDefault"
    };
    static const char* kNeedles[] = {
        "Tianocore", "EDK II", "OVMF", "Red Hat", "QEMU"
    };

    bool hit = false;
    for (const wchar_t* var_name : kVarNames)
    {
        std::vector<uint8_t> buf(8192, 0u);
        DWORD attrs = 0;
        SetLastError(0);
        DWORD got = get_fw(var_name, kEfiGlobal, buf.data(),
                           static_cast<DWORD>(buf.size()), &attrs);
        if (got == 0)
            continue;
        if (got > buf.size()) got = static_cast<DWORD>(buf.size());

        std::vector<char> ascii;
        ascii.reserve(got * 2);
        for (DWORD i = 0; i < got; ++i)
        {
            uint8_t b = buf[i];
            if (b >= 0x20 && b < 0x7F)
                ascii.push_back(static_cast<char>(b));
        }
        std::vector<char> wide_low;
        if ((got & 1u) == 0)
        {
            wide_low.reserve(got / 2);
            for (DWORD i = 0; i + 1 < got; i += 2)
            {
                uint16_t w = static_cast<uint16_t>(buf[i]) |
                             (static_cast<uint16_t>(buf[i + 1]) << 8);
                if (w >= 0x20 && w < 0x7F)
                    wide_low.push_back(static_cast<char>(w & 0xFF));
            }
        }

        for (const char* needle : kNeedles)
        {
            if (!ascii.empty() &&
                case_insensitive_substr_ascii(reinterpret_cast<const uint8_t*>(ascii.data()),
                                              ascii.size(), needle))
            {
                hit = true;
                break;
            }
            if (!wide_low.empty() &&
                case_insensitive_substr_ascii(reinterpret_cast<const uint8_t*>(wide_low.data()),
                                              wide_low.size(), needle))
            {
                hit = true;
                break;
            }
        }
        if (hit) break;
    }
    return hit;
}

inline bool scan_disk_model_strings()
{
    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0",
                               0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr,
                               OPEN_EXISTING,
                               0,
                               nullptr);
    if (drive == INVALID_HANDLE_VALUE)
        return false;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER header{};
    DWORD bytes = 0;
    if (!DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY,
                         &query, sizeof(query),
                         &header, sizeof(header),
                         &bytes, nullptr) || header.Size == 0)
    {
        CloseHandle(drive);
        return false;
    }

    std::vector<uint8_t> buf(header.Size, 0u);
    if (!DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY,
                         &query, sizeof(query),
                         buf.data(), static_cast<DWORD>(buf.size()),
                         &bytes, nullptr))
    {
        CloseHandle(drive);
        return false;
    }
    CloseHandle(drive);
    if (buf.size() < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        return false;

    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf.data());

    auto extract_str = [&](DWORD off) -> std::string {
        std::string out;
        if (off == 0 || off >= buf.size()) return out;
        size_t i = static_cast<size_t>(off);
        while (i < buf.size() && buf[i] != 0)
        {
            out.push_back(static_cast<char>(buf[i]));
            ++i;
            if (out.size() > 1024) break;
        }
        return out;
    };

    std::string vendor = extract_str(desc->VendorIdOffset);
    std::string product = extract_str(desc->ProductIdOffset);
    std::string combined;
    combined.reserve(vendor.size() + 1 + product.size());
    combined.append(vendor);
    combined.push_back(' ');
    combined.append(product);

    static const char* kNeedles[] = {
        "QEMU HARDDISK", "QEMU DVD-ROM", "ATA QEMU",
        "VBOX HARDDISK", "VBOX CD-ROM",
        "VMware Virtual", "VMware NVMe", "VMware, VMware",
        "Virtual HD,", "Msft Virtual Disk",
        "Xen Virtual SCSI", "Parallels", "Red Hat VirtIO"
    };

    const uint8_t* hay = reinterpret_cast<const uint8_t*>(combined.data());
    size_t hay_len = combined.size();
    for (const char* needle : kNeedles)
    {
        if (case_insensitive_substr_ascii(hay, hay_len, needle))
            return true;
    }
    return false;
}

inline bool edid_manufacturer_matches(const uint8_t* edid)
{
    uint16_t mfg = (static_cast<uint16_t>(edid[8]) << 8) |
                   static_cast<uint16_t>(edid[9]);
    char id[4] = {};
    id[0] = static_cast<char>(((mfg >> 10) & 0x1F) + 'A' - 1);
    id[1] = static_cast<char>(((mfg >> 5) & 0x1F) + 'A' - 1);
    id[2] = static_cast<char>((mfg & 0x1F) + 'A' - 1);
    id[3] = '\0';
    static const char* kBadIds[] = { "QEM", "RHT", "BOC" };
    for (const char* candidate : kBadIds)
    {
        if (std::memcmp(id, candidate, 3) == 0)
            return true;
    }
    return false;
}

inline bool edid_validate_one(const uint8_t* edid, size_t len,
                              bool& header_ok_out,
                              bool& checksum_ok_out)
{
    header_ok_out = false;
    checksum_ok_out = false;
    if (!edid || len < 128) return false;

    static const uint8_t kMagic[8] = {
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
    };
    header_ok_out = std::memcmp(edid, kMagic, 8) == 0;

    uint32_t sum = 0;
    for (size_t i = 0; i < 128; ++i)
        sum += edid[i];
    checksum_ok_out = (sum & 0xFFu) == 0;

    return edid_manufacturer_matches(edid);
}

inline bool walk_edid_subkeys(HKEY parent, bool& mfg_hit_out)
{
    bool any_examined = false;
    DWORD index = 0;
    wchar_t name[512];
    DWORD name_len = 0;

    for (;;)
    {
        name_len = static_cast<DWORD>(_countof(name));
        LONG rc = RegEnumKeyExW(parent, index, name, &name_len,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        ++index;
        if (rc != ERROR_SUCCESS) continue;

        HKEY child = nullptr;
        if (RegOpenKeyExW(parent, name, 0, KEY_READ, &child) != ERROR_SUCCESS)
            continue;

        HKEY params = nullptr;
        if (RegOpenKeyExW(child, L"Device Parameters", 0,
                          KEY_READ, &params) == ERROR_SUCCESS)
        {
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExW(params, L"EDID", nullptr, &type,
                                 nullptr, &size) == ERROR_SUCCESS &&
                type == REG_BINARY && size >= 128 && size <= 4096)
            {
                std::vector<uint8_t> buf(size, 0u);
                if (RegQueryValueExW(params, L"EDID", nullptr, &type,
                                     buf.data(), &size) == ERROR_SUCCESS)
                {
                    bool header_ok = false;
                    bool checksum_ok = false;
                    bool mfg_match = edid_validate_one(buf.data(), size,
                                                      header_ok, checksum_ok);
                    any_examined = true;
                    if (mfg_match) mfg_hit_out = true;
                }
            }
            RegCloseKey(params);
        }
        else
        {
            bool sub_examined = walk_edid_subkeys(child, mfg_hit_out);
            if (sub_examined) any_examined = true;
        }
        RegCloseKey(child);
        if (mfg_hit_out) break;
    }
    return any_examined;
}

inline bool scan_edid_manufacturer()
{
    HKEY display = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
                      0, KEY_READ, &display) != ERROR_SUCCESS)
        return false;
    bool mfg_hit = false;
    walk_edid_subkeys(display, mfg_hit);
    RegCloseKey(display);
    return mfg_hit;
}

inline bool hv_interface_signature_is_hv1()
{
    int regs[4] = {};
    if (!safe_cpuidex(regs, 0x40000001, 0))
        return false;
    return static_cast<uint32_t>(regs[0]) == 0x31237648u;
}

}

inline bool g_ms_hv_approved = false;
inline bool g_hvci_enabled = false;
inline bool g_vbs_enabled = false;
inline bool g_hidden_hypervisor_suspected = false;
inline bool g_cpuid_leaf_inconsistent = false;
inline bool g_tsc_qpc_unstable = false;
inline bool g_synthetic_hv_behavior = false;
inline bool g_hv_interface_signature_mismatch = false;
inline bool g_hyperv_guest_partition = false;

inline report_t run()
{
    report_t r{};
    r.result = result_t::allow;
    r.vendor[0] = L'\0';
    g_ms_hv_approved = false;
    g_hidden_hypervisor_suspected = false;
    g_cpuid_leaf_inconsistent = false;
    g_tsc_qpc_unstable = false;
    g_synthetic_hv_behavior = false;
    g_hv_interface_signature_mismatch = false;
    g_hyperv_guest_partition = false;

    char vendor12[12] = {};
    bool ms_hv_vendor = false;
    bool known_non_ms = false;
    bool genuine_ms = false;
    uint32_t artifact_mask = 0;
    uint32_t contradiction_mask = 0;

    auto refresh_masks = [&]() {
        artifact_mask = 0;
        if (r.firmware_hit) artifact_mask |= detail::kArtifactFirmware;
        if (r.process_hit) artifact_mask |= detail::kArtifactProcess;
        if (r.nvram_vm_string_hit) artifact_mask |= detail::kArtifactNvram;
        if (r.disk_vm_string_hit) artifact_mask |= detail::kArtifactDisk;
        if (r.edid_vm_manufacturer_hit) artifact_mask |= detail::kArtifactEdid;
        contradiction_mask = 0;
        if (r.hidden_hypervisor_suspected) contradiction_mask |= detail::kContradictionHiddenHv;
        if (r.cpuid_leaf_inconsistent) contradiction_mask |= detail::kContradictionCpuidLeaf;
        if (r.tsc_qpc_unstable) contradiction_mask |= detail::kContradictionTscQpc;
        if (r.synthetic_hv_behavior && !r.hv_bit_set) contradiction_mask |= detail::kContradictionSyntheticHv;
        if (r.hv_interface_signature_mismatch) contradiction_mask |= detail::kContradictionHvInterface;
        if (r.hyperv_guest_partition) contradiction_mask |= detail::kContradictionHvGuest;
    };

    auto finish = [&](result_t result, const char* decision) -> report_t {
        r.result = result;
        refresh_masks();
        g_hvci_enabled = r.hvci_enabled;
        g_vbs_enabled = r.vbs_enabled;
        g_hidden_hypervisor_suspected = r.hidden_hypervisor_suspected;
        g_cpuid_leaf_inconsistent = r.cpuid_leaf_inconsistent;
        g_tsc_qpc_unstable = r.tsc_qpc_unstable;
        g_synthetic_hv_behavior = r.synthetic_hv_behavior;
        g_hv_interface_signature_mismatch = r.hv_interface_signature_mismatch;
        g_hyperv_guest_partition = r.hyperv_guest_partition;
        uint64_t summary_hash = 14695981039346656037ULL;
        auto mix = [&](uint64_t value) {
            for (int i = 0; i < 8; ++i)
            {
                summary_hash ^= static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
                summary_hash *= 1099511628211ULL;
            }
        };
        mix(static_cast<uint64_t>(detail::kPolicyVersion));
        mix(static_cast<uint64_t>(artifact_mask));
        mix(static_cast<uint64_t>(contradiction_mask));
        mix(static_cast<uint64_t>(r.hv_bit_set ? 1 : 0));
        mix(static_cast<uint64_t>(ms_hv_vendor ? 1 : 0));
        mix(static_cast<uint64_t>(known_non_ms ? 1 : 0));
        mix(static_cast<uint64_t>(genuine_ms ? 1 : 0));
        mix(static_cast<uint64_t>(r.hvci_enabled ? 1 : 0));
        mix(static_cast<uint64_t>(r.vbs_enabled ? 1 : 0));
        mix(static_cast<uint64_t>(r.timing_median));
        diag::log_tagged_fmt("hv_pf",
            "policy_decision version=0x%08X decision=%s hv_bit=%d ms_hv=%d known_non_ms=%d genuine_ms=%d hvci=%d vbs=%d guest=%d artifacts=0x%08X contradictions=0x%08X timing_median=%u summary_hash=0x%016llX",
            detail::kPolicyVersion,
            decision ? decision : "unknown",
            r.hv_bit_set ? 1 : 0,
            ms_hv_vendor ? 1 : 0,
            known_non_ms ? 1 : 0,
            genuine_ms ? 1 : 0,
            r.hvci_enabled ? 1 : 0,
            r.vbs_enabled ? 1 : 0,
            r.hyperv_guest_partition ? 1 : 0,
            artifact_mask,
            contradiction_mask,
            r.timing_median,
            static_cast<unsigned long long>(summary_hash));
        diag::log_tagged_fmt("hv_pf", "decision=%s", decision ? decision : "unknown");
        return r;
    };

    diag::log_tagged("hv_pf", "enter");

    if (detail::devmode_bypass_set())
    {
        diag::log_tagged("hv_pf", "devmode_bypass_return_tpm_receipt_validated");
        return finish(result_t::allow, "allow_devmode_receipt");
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
    g_hvci_enabled = r.hvci_enabled;
    diag::log_tagged_fmt("hv_pf", "query_code_integrity_done ok=%d opts=0x%lX", ci_ok ? 1 : 0, static_cast<unsigned long>(ci_options));

    diag::log_tagged("hv_pf", "query_isolated_user_mode_start");
    detail::system_isolated_user_mode_information_t ium{};
    if (detail::query_isolated_user_mode(ium))
    {
        r.vbs_enabled = ium.SecureKernelRunning != 0;
        if (ium.HvciEnabled) r.hvci_enabled = true;
        g_vbs_enabled = r.vbs_enabled;
        g_hvci_enabled = r.hvci_enabled;
    }
    diag::log_tagged_fmt("hv_pf", "query_isolated_user_mode_done vbs=%d hvci=%d",
        r.vbs_enabled ? 1 : 0,
        r.hvci_enabled ? 1 : 0);

    diag::log_tagged("hv_pf", "read_cpuid_hv_bit_start");
    r.hv_bit_set = detail::read_cpuid_hv_bit();
    diag::log_tagged_fmt("hv_pf", "read_cpuid_hv_bit_done set=%d", r.hv_bit_set ? 1 : 0);

    if (r.hv_bit_set)
    {
        diag::log_tagged("hv_pf", "read_hv_vendor_start");
        detail::read_hv_vendor(vendor12);
        for (int i = 0; i < 12; ++i)
            r.vendor[i] = static_cast<wchar_t>(static_cast<unsigned char>(vendor12[i]));
        r.vendor[12] = L'\0';
        diag::log_tagged("hv_pf", "read_hv_vendor_done");
    }

    diag::log_tagged("hv_pf", "cpuid_leaf_consistency_start");
    r.cpuid_leaf_inconsistent = detail::cpuid_leaf_inconsistent_probe(r.hv_bit_set);
    diag::log_tagged_fmt("hv_pf", "cpuid_leaf_consistency_done inconsistent=%d", r.cpuid_leaf_inconsistent ? 1 : 0);

    diag::log_tagged("hv_pf", "synthetic_hv_behavior_start");
    r.synthetic_hv_behavior = detail::synthetic_hv_behavior_probe();
    diag::log_tagged_fmt("hv_pf", "synthetic_hv_behavior_done present=%d", r.synthetic_hv_behavior ? 1 : 0);

    diag::log_tagged("hv_pf", "hyperv_guest_partition_start");
    r.hyperv_guest_partition = detail::hyperv_guest_partition_probe();
    diag::log_tagged_fmt("hv_pf", "hyperv_guest_partition_done guest=%d", r.hyperv_guest_partition ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_firmware_rsmb_start");
    r.firmware_hit = detail::scan_firmware_rsmb();
    diag::log_tagged_fmt("hv_pf", "scan_firmware_rsmb_done hit=%d", r.firmware_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_vm_processes_start");
    r.process_hit = detail::scan_vm_processes();
    diag::log_tagged_fmt("hv_pf", "scan_vm_processes_done hit=%d", r.process_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_nvram_boot_order_start");
    r.nvram_vm_string_hit = detail::scan_nvram_boot_order();
    diag::log_tagged_fmt("hv_pf", "scan_nvram_boot_order_done hit=%d", r.nvram_vm_string_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_disk_model_strings_start");
    r.disk_vm_string_hit = detail::scan_disk_model_strings();
    diag::log_tagged_fmt("hv_pf", "scan_disk_model_strings_done hit=%d", r.disk_vm_string_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "scan_edid_manufacturer_start");
    r.edid_vm_manufacturer_hit = detail::scan_edid_manufacturer();
    diag::log_tagged_fmt("hv_pf", "scan_edid_manufacturer_done hit=%d", r.edid_vm_manufacturer_hit ? 1 : 0);

    diag::log_tagged("hv_pf", "xsetbv_probe_start");
    r.xsetbv_forwarded = detail::xsetbv_probe();
    diag::log_tagged_fmt("hv_pf", "xsetbv_probe_done fwd=%d", r.xsetbv_forwarded ? 1 : 0);

    diag::log_tagged("hv_pf", "timing_probe_start");
    r.timing_median = detail::timing_probe_median();
    diag::log_tagged_fmt("hv_pf", "timing_probe_done median=%u", r.timing_median);

    diag::log_tagged("hv_pf", "tsc_qpc_stability_start");
    r.tsc_qpc_unstable = detail::tsc_qpc_stability_probe();
    diag::log_tagged_fmt("hv_pf", "tsc_qpc_stability_done unstable=%d", r.tsc_qpc_unstable ? 1 : 0);

    r.hidden_hypervisor_suspected = !r.hv_bit_set &&
        (r.cpuid_leaf_inconsistent || r.synthetic_hv_behavior || r.tsc_qpc_unstable);
    diag::log_tagged_fmt("hv_pf",
        "hidden_hypervisor_assessment hidden=%d cpuid_leaf=%d synthetic=%d tsc_qpc=%d",
        r.hidden_hypervisor_suspected ? 1 : 0,
        r.cpuid_leaf_inconsistent ? 1 : 0,
        r.synthetic_hv_behavior ? 1 : 0,
        r.tsc_qpc_unstable ? 1 : 0);

    if (r.kd_enabled)
    {
        return finish(result_t::refuse_kernel_debug, "refuse_kernel_debug");
    }
    if (r.test_signing)
    {
        return finish(result_t::refuse_test_signing, "refuse_test_signing");
    }

    ms_hv_vendor = r.hv_bit_set && detail::is_microsoft_hv(vendor12);
    known_non_ms = r.hv_bit_set && detail::is_known_non_ms_hv(vendor12);

    if (ms_hv_vendor)
    {
        const bool hv1_signature = detail::hv_interface_signature_is_hv1();
        r.hv_interface_signature_mismatch = !hv1_signature;
        if (!hv1_signature)
        {
            return finish(result_t::refuse_hv, "refuse_hv_interface_signature_mismatch");
        }

        if (r.hyperv_guest_partition)
        {
            return finish(result_t::refuse_hv_nested, "refuse_hv_guest_partition");
        }

        genuine_ms = detail::validate_ms_hv_features();

        if (!genuine_ms)
        {
            return finish(result_t::refuse_hv, "refuse_hv_ms_not_genuine");
        }

        refresh_masks();
        if ((artifact_mask & (detail::kArtifactFirmware | detail::kArtifactNvram |
                              detail::kArtifactDisk | detail::kArtifactEdid)) != 0)
        {
            return finish(result_t::refuse_hv, "refuse_ms_hv_with_vm_artifact");
        }

        g_ms_hv_approved = true;
        return finish(result_t::allow, "allow_ms_hv");
    }

    if (known_non_ms)
    {
        return finish(result_t::refuse_hv, "refuse_hv_known_non_ms");
    }

    if (r.hv_bit_set)
    {
        return finish(result_t::refuse_hv, "refuse_hv_bit_set");
    }

    refresh_masks();
    if (r.hidden_hypervisor_suspected && artifact_mask != 0)
    {
        return finish(result_t::refuse_hv, "refuse_hidden_hv_with_vm_artifact");
    }

    if (r.firmware_hit)
    {
        return finish(result_t::refuse_hv, "refuse_hv_firmware_hit");
    }

    if (r.nvram_vm_string_hit)
    {
        return finish(result_t::refuse_hv, "refuse_hv_nvram_hit");
    }

    if (r.disk_vm_string_hit)
    {
        return finish(result_t::refuse_hv, "refuse_hv_disk_hit");
    }

    if (r.edid_vm_manufacturer_hit)
    {
        return finish(result_t::refuse_hv, "refuse_hv_edid_manufacturer_hit");
    }

    return finish(result_t::allow, "allow");
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
    case result_t::refuse_hv_nested:
        message = L"AiDA cannot start: the system is running inside a Hyper-V guest partition. Run AiDA only on trusted bare metal or an approved Windows security root.";
        if (r.hv_interface_signature_mismatch)
            message += L"\n\nAdditional: the Hyper-V interface signature did not validate.";
        break;
    case result_t::refuse_hv:
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
        if (r.nvram_vm_string_hit)
            message += L"\n\nAdditional: VM firmware was found in UEFI NVRAM.";
        if (r.disk_vm_string_hit)
            message += L"\n\nAdditional: VM virtual disk hardware was detected.";
        if (r.edid_vm_manufacturer_hit)
            message += L"\n\nAdditional: VM virtual display was detected.";
        if (r.hv_interface_signature_mismatch)
            message += L"\n\nAdditional: a hypervisor masqueraded as Microsoft Hyper-V with the wrong interface signature.";
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
