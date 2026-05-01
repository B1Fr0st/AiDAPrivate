#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace vbs_enforcement {

enum class plan_tier_t : uint32_t {
    standard = 0,
    pro = 1,
    pro_tpm = 2,
    enterprise = 3,
};

inline plan_tier_t parse_plan_tier(const std::string& plan)
{
    if (plan == "enterprise") return plan_tier_t::enterprise;
    if (plan == "pro_tpm") return plan_tier_t::pro_tpm;
    if (plan == "pro") return plan_tier_t::pro;
    return plan_tier_t::standard;
}

namespace detail {

struct system_isolated_user_mode_information_t
{
    BOOLEAN SecureKernelRunning;
    BOOLEAN HvciEnabled;
    BOOLEAN HvciStrictMode;
    BOOLEAN DebugEnabled;
    BOOLEAN FirmwarePageProtection;
    BOOLEAN EncryptionKeyAvailable;
    BOOLEAN Spare0[2];
    ULONG64 TrustletRunningInstanceId;
    ULONG64 HvciDisallowedImages;
    ULONG64 SecureKernelEntropyBytes;
    ULONG64 Reserved[7];
};

constexpr uint32_t kSystemIsolatedUserModeInformation = 165;
constexpr uint32_t kVmCfgCallTargetInformation = 1;
constexpr uint32_t kMemExtendedParameterInvalidType = static_cast<uint32_t>(-1);

using nt_query_system_information_t = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);

inline nt_query_system_information_t resolve_nt_query()
{
    static nt_query_system_information_t fn = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
        HMODULE h = GetModuleHandleW(L"ntdll.dll");
        if (h)
            fn = reinterpret_cast<nt_query_system_information_t>(GetProcAddress(h, "NtQuerySystemInformation"));
    });
    return fn;
}

inline bool query_isolated_user_mode_info(system_isolated_user_mode_information_t& out)
{
    auto fn = resolve_nt_query();
    if (!fn) return false;
    ULONG returned = 0;
    LONG rc = fn(kSystemIsolatedUserModeInformation, &out, sizeof(out), &returned);
    if (rc != 0 || returned < sizeof(BOOLEAN) * 2) {
        return false;
    }
    return true;
}

inline std::atomic<bool>& detected_vbs_flag()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::atomic<bool>& detected_hvci_flag()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::atomic<bool>& detection_done_flag()
{
    static std::atomic<bool> v{false};
    return v;
}

inline std::atomic<uint32_t>& guarded_pages_counter()
{
    static std::atomic<uint32_t> v{0};
    return v;
}

}

inline void detect_capabilities()
{
    if (detail::detection_done_flag().load(std::memory_order_acquire)) return;
    detail::system_isolated_user_mode_information_t ium{};
    if (detail::query_isolated_user_mode_info(ium)) {
        detail::detected_vbs_flag().store(ium.SecureKernelRunning != 0, std::memory_order_release);
        detail::detected_hvci_flag().store(ium.HvciEnabled != 0, std::memory_order_release);
    }
    detail::detection_done_flag().store(true, std::memory_order_release);
}

inline bool vbs_active()
{
    detect_capabilities();
    return detail::detected_vbs_flag().load(std::memory_order_acquire);
}

inline bool hvci_active()
{
    detect_capabilities();
    return detail::detected_hvci_flag().load(std::memory_order_acquire);
}

inline bool tier_eligible(plan_tier_t tier)
{
    return tier == plan_tier_t::enterprise;
}

inline bool enforce_text_pages_no_write(plan_tier_t tier)
{
    if (!tier_eligible(tier)) return false;
    if (!vbs_active()) return false;

    HMODULE module_base = GetModuleHandleW(nullptr);
    if (!module_base) return false;

    auto base = reinterpret_cast<const uint8_t*>(module_base);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    uint32_t guarded_count = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) continue;

        void* region_base = const_cast<uint8_t*>(base + sec->VirtualAddress);
        size_t region_size = sec->Misc.VirtualSize;
        if (region_size == 0) continue;

        DWORD old_protect = 0;
        if (!VirtualProtect(region_base, region_size, PAGE_EXECUTE_READ, &old_protect))
            continue;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(region_base, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            (void)mbi;
        }

        using set_proc_mitig_t = BOOL(WINAPI*)(int, PVOID, SIZE_T);
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        set_proc_mitig_t set_mitig = k32 ? reinterpret_cast<set_proc_mitig_t>(
            GetProcAddress(k32, "SetProcessMitigationPolicy")) : nullptr;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{};
        dyn.ProhibitDynamicCode = 1;
        dyn.AllowThreadOptOut = 0;
        dyn.AllowRemoteDowngrade = 0;
        if (set_mitig) set_mitig(7, &dyn, sizeof(dyn));
        ++guarded_count;
    }
    detail::guarded_pages_counter().store(guarded_count, std::memory_order_release);
    return guarded_count > 0;
}

inline uint32_t guarded_page_count()
{
    return detail::guarded_pages_counter().load(std::memory_order_acquire);
}

inline std::string status_summary(plan_tier_t tier)
{
    detect_capabilities();
    std::string s;
    s.reserve(96);
    s += "tier=";
    switch (tier) {
        case plan_tier_t::enterprise: s += "enterprise"; break;
        case plan_tier_t::pro_tpm:    s += "pro_tpm"; break;
        case plan_tier_t::pro:        s += "pro"; break;
        default:                      s += "standard"; break;
    }
    s += " vbs=";
    s += detail::detected_vbs_flag().load(std::memory_order_acquire) ? "1" : "0";
    s += " hvci=";
    s += detail::detected_hvci_flag().load(std::memory_order_acquire) ? "1" : "0";
    s += " guarded=";
    char num[16];
    _snprintf_s(num, sizeof(num), _TRUNCATE, "%u",
                detail::guarded_pages_counter().load(std::memory_order_acquire));
    s += num;
    return s;
}

}
