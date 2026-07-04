#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "standalone_driver.hpp"
#include "hv_preflight.hpp"

namespace anti_tamper::kernel_adbg {

constexpr uint32_t DETECT_KERNEL_DEBUGGER = 0x00000001u;
constexpr uint32_t DETECT_HYPERVISOR = 0x00000002u;
constexpr uint32_t DETECT_ETW_ACTIVE = 0x00000004u;
constexpr uint32_t DETECT_INSTRUMENTATION = 0x00000008u;
constexpr uint32_t DETECT_TIMING_ATTACK = 0x00000010u;
constexpr uint32_t DETECT_PAGE_GUARD = 0x00000020u;
constexpr uint32_t DETECT_SIDT_ANOMALY = 0x00000040u;

constexpr uint32_t kKnownMask =
    DETECT_KERNEL_DEBUGGER |
    DETECT_HYPERVISOR |
    DETECT_ETW_ACTIVE |
    DETECT_INSTRUMENTATION |
    DETECT_TIMING_ATTACK |
    DETECT_PAGE_GUARD |
    DETECT_SIDT_ANOMALY;

constexpr uint32_t kHardMask =
    DETECT_KERNEL_DEBUGGER |
    DETECT_ETW_ACTIVE |
    DETECT_INSTRUMENTATION |
    DETECT_PAGE_GUARD;

constexpr uint32_t kSoftMask =
    DETECT_HYPERVISOR |
    DETECT_TIMING_ATTACK |
    DETECT_SIDT_ANOMALY;

struct native_kd_state_t
{
    bool queried = false;
    bool ok = false;
    bool active = false;
    BOOLEAN enabled = 0;
    BOOLEAN not_present = 1;
    LONG status = 0;
    ULONG returned = 0;
};

struct hv_context_t
{
    bool sampled = false;
    bool cpuid_hv = false;
    bool cpuid_vendor_ms = false;
    bool cpuid_vendor_known_non_ms = false;
    bool ms_hv = false;
    bool vbs = false;
    bool hvci = false;
    bool hidden_hv = false;
    bool cpuid_leaf_inconsistent = false;
    bool synthetic_hv = false;
    bool tsc_qpc = false;
    bool hyperv_guest = false;
    uint64_t vendor_hash = 0;
    char vendor[13]{};
};

inline uint64_t fnv1a_bytes(const void* data, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
    {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

inline bool known_non_ms_hv_vendor(const char vendor[13])
{
    static const char* const kKnown[] = {
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
    for (const char* name : kKnown)
    {
        if (std::memcmp(vendor, name, 12) == 0)
            return true;
    }
    return false;
}

inline hv_context_t sample_hv_context()
{
    hv_context_t out{};
    out.sampled = true;
    int regs[4] = {};
    __cpuid(regs, 1);
    out.cpuid_hv = (regs[2] & (1 << 31)) != 0;
    if (out.cpuid_hv)
    {
        __cpuid(regs, 0x40000000);
        std::memcpy(out.vendor + 0, &regs[1], 4);
        std::memcpy(out.vendor + 4, &regs[2], 4);
        std::memcpy(out.vendor + 8, &regs[3], 4);
        out.vendor[12] = '\0';
        for (size_t i = 0; i < 12; ++i)
        {
            unsigned char ch = static_cast<unsigned char>(out.vendor[i]);
            if (ch < 0x20 || ch > 0x7E)
                out.vendor[i] = '_';
        }
        static const char kMsHv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
        out.cpuid_vendor_ms = std::memcmp(out.vendor, kMsHv, 12) == 0;
        out.cpuid_vendor_known_non_ms = known_non_ms_hv_vendor(out.vendor);
        out.vendor_hash = fnv1a_bytes(out.vendor, 12);
        if (out.cpuid_vendor_ms)
        {
            __cpuid(regs, 0x40000003);
            const uint32_t partition_caps = static_cast<uint32_t>(regs[1]);
            const uint32_t root_bits = (1u << 0) | (1u << 5);
            out.hyperv_guest = (partition_caps & root_bits) == 0;
        }
    }
    out.ms_hv = anti_tamper::hv_preflight::g_ms_hv_approved || out.cpuid_vendor_ms;
    out.vbs = anti_tamper::hv_preflight::g_vbs_enabled;
    out.hvci = anti_tamper::hv_preflight::g_hvci_enabled;
    out.hidden_hv = anti_tamper::hv_preflight::g_hidden_hypervisor_suspected;
    out.cpuid_leaf_inconsistent = anti_tamper::hv_preflight::g_cpuid_leaf_inconsistent;
    out.synthetic_hv = anti_tamper::hv_preflight::g_synthetic_hv_behavior;
    out.tsc_qpc = anti_tamper::hv_preflight::g_tsc_qpc_unstable;
    out.hyperv_guest = out.hyperv_guest || anti_tamper::hv_preflight::g_hyperv_guest_partition;
    return out;
}

struct input_t
{
    uint32_t flags = 0;
    uint64_t debugger_pid = 0;
    uint64_t dr_clear_count = 0;
    native_kd_state_t native{};
    hv_context_t hv = sample_hv_context();
    bool scan_sampled = false;
    bool scan_ok = false;
    uint64_t scan_pid = 0;
    bool settle_sampled = false;
    bool settle_active = false;
    bool persistence_sampled = false;
    uint32_t persistence_count = 0;
    uint32_t corroborated_hard_signals = 0;
    bool require_scan_for_sidt_observe = true;
    const char* phase = "unknown";
    const char* source = "unknown";
};

struct decision_t
{
    uint32_t flags = 0;
    uint32_t hard_mask = 0;
    uint32_t soft_mask = 0;
    uint32_t unknown_mask = 0;
    uint32_t page_guard_mask = 0;
    bool isolated_soft = false;
    bool isolated_sidt = false;
    bool multiple_soft = false;
    bool enforce = false;
    const char* reason = "no_flags";
    std::string decoded;
};

inline native_kd_state_t query_native_kernel_debugger_state()
{
    native_kd_state_t state{};
    state.queried = true;
    using nt_query_system_information_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
    {
        state.status = static_cast<LONG>(0xC0000135u);
        return state;
    }
    auto query = reinterpret_cast<nt_query_system_information_t>(
        GetProcAddress(nt, "NtQuerySystemInformation"));
    if (!query)
    {
        state.status = static_cast<LONG>(0xC0000139u);
        return state;
    }
    struct kernel_debugger_information_t
    {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } kdi{};
    ULONG returned = 0;
    const LONG status = query(35, &kdi, sizeof(kdi), &returned);
    state.status = status;
    state.returned = returned;
    if (status < 0)
        return state;
    state.ok = true;
    state.enabled = kdi.KernelDebuggerEnabled;
    state.not_present = kdi.KernelDebuggerNotPresent;
    state.active = kdi.KernelDebuggerEnabled != 0 && kdi.KernelDebuggerNotPresent == 0;
    return state;
}

inline const char* flag_name(uint32_t bit)
{
    switch (bit)
    {
    case DETECT_KERNEL_DEBUGGER: return "DETECT_KERNEL_DEBUGGER";
    case DETECT_HYPERVISOR: return "DETECT_HYPERVISOR";
    case DETECT_ETW_ACTIVE: return "DETECT_ETW_ACTIVE";
    case DETECT_INSTRUMENTATION: return "DETECT_INSTRUMENTATION";
    case DETECT_TIMING_ATTACK: return "DETECT_TIMING_ATTACK";
    case DETECT_PAGE_GUARD: return "DETECT_PAGE_GUARD";
    case DETECT_SIDT_ANOMALY: return "DETECT_SIDT_ANOMALY";
    default: return nullptr;
    }
}

inline std::string decode_names(uint32_t flags)
{
    if (flags == 0)
        return "none";
    std::string names;
    for (uint32_t bit = 1u; bit != 0; bit <<= 1)
    {
        if ((flags & bit) == 0)
            continue;
        if (!names.empty())
            names += ",";
        if (const char* name = flag_name(bit))
        {
            names += name;
        }
        else
        {
            char unk[24];
            _snprintf_s(unk, sizeof(unk), _TRUNCATE, "UNKNOWN_0x%08X", bit);
            names += unk;
        }
    }
    return names.empty() ? "none" : names;
}

inline bool single_bit(uint32_t mask)
{
    return mask != 0 && (mask & (mask - 1u)) == 0;
}

inline input_t make_input(const driver_bridge::anti_debug_result_t& result,
                          const char* phase,
                          const char* source)
{
    input_t in{};
    in.flags = result.result_flags;
    in.debugger_pid = result.detected_debugger_pid;
    in.dr_clear_count = result.dr_clear_count;
    in.native = query_native_kernel_debugger_state();
    in.phase = phase ? phase : "unknown";
    in.source = source ? source : "unknown";
    return in;
}

inline decision_t classify(const input_t& in)
{
    decision_t out{};
    out.flags = in.flags;
    out.hard_mask = in.flags & kHardMask;
    out.soft_mask = in.flags & kSoftMask;
    out.unknown_mask = in.flags & ~kKnownMask;
    out.page_guard_mask = in.flags & DETECT_PAGE_GUARD;
    out.isolated_soft = in.flags != 0 && in.flags == out.soft_mask && single_bit(out.soft_mask);
    out.isolated_sidt = in.flags == DETECT_SIDT_ANOMALY;
    out.multiple_soft = out.soft_mask != 0 && !single_bit(out.soft_mask);
    out.decoded = decode_names(in.flags);

    if (in.native.queried && in.native.ok && in.native.active)
    {
        out.enforce = true;
        out.reason = "native_kernel_debugger_active";
        return out;
    }

    if (in.debugger_pid != 0)
    {
        out.enforce = true;
        out.reason = "debugger_pid_nonzero";
        return out;
    }

    if (in.scan_sampled && in.scan_ok && in.scan_pid != 0)
    {
        out.enforce = true;
        out.reason = "scan_pid_nonzero";
        return out;
    }

    if (out.unknown_mask != 0)
    {
        out.enforce = true;
        out.reason = "unknown_kernel_flags";
        return out;
    }

    if ((in.flags & DETECT_KERNEL_DEBUGGER) != 0)
    {
        out.enforce = true;
        if (!in.native.queried || !in.native.ok)
            out.reason = "kernel_debugger_flag_native_unavailable";
        else if (in.native.active)
            out.reason = "kernel_debugger_flag_native_active";
        else
            out.reason = "kernel_debugger_flag_driver_hard";
        return out;
    }

    if (out.hard_mask != 0)
    {
        out.enforce = true;
        if ((out.hard_mask & DETECT_PAGE_GUARD) != 0)
            out.reason = "hard_page_guard_flag";
        else if ((out.hard_mask & DETECT_INSTRUMENTATION) != 0)
            out.reason = "hard_instrumentation_flag";
        else if ((out.hard_mask & DETECT_ETW_ACTIVE) != 0)
            out.reason = "hard_etw_active_flag";
        else
            out.reason = "hard_kernel_flags";
        return out;
    }

    if (in.corroborated_hard_signals != 0)
    {
        out.enforce = true;
        out.reason = "corroborated_hard_anti_debug_signal";
        return out;
    }

    if (in.flags == 0)
    {
        out.enforce = false;
        out.reason = "no_flags";
        return out;
    }

    if (out.multiple_soft)
    {
        if (in.settle_sampled && in.settle_active)
        {
            out.enforce = false;
            out.reason = "settle_active_multiple_soft_observed";
            return out;
        }
        out.enforce = true;
        out.reason = "multiple_soft_flags";
        return out;
    }

    if (out.isolated_sidt)
    {
        if (!in.native.queried || !in.native.ok)
        {
            out.enforce = true;
            out.reason = "isolated_sidt_native_unavailable";
            return out;
        }
        if (in.native.active)
        {
            out.enforce = true;
            out.reason = "isolated_sidt_native_active";
            return out;
        }
        if (in.require_scan_for_sidt_observe && (!in.scan_sampled || !in.scan_ok))
        {
            out.enforce = true;
            out.reason = "isolated_sidt_scan_unavailable";
            return out;
        }
        if (in.scan_sampled && in.scan_ok && in.scan_pid != 0)
        {
            out.enforce = true;
            out.reason = "isolated_sidt_scan_pid_nonzero";
            return out;
        }
        out.enforce = false;
        out.reason = "isolated_sidt_anomaly_native_clean";
        return out;
    }

    if (out.isolated_soft)
    {
        if (in.settle_sampled && in.settle_active)
        {
            out.enforce = false;
            out.reason = "settle_active_isolated_soft_observed";
            return out;
        }
        if (in.persistence_sampled && in.persistence_count >= 3)
        {
            out.enforce = true;
            out.reason = "repeated_soft_flag_without_compatibility";
            return out;
        }
        out.enforce = false;
        out.reason = "isolated_soft_pending_persistence";
        return out;
    }

    out.enforce = true;
    out.reason = "unclassified_kernel_flags";
    return out;
}

inline std::string format_decision(const input_t& in, const decision_t& decision)
{
    char buf[3072];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "kernel_adbg_decision phase=%s source=%s flags=0x%08X decoded=%s hard=0x%08X soft=0x%08X unknown=0x%08X page_guard=0x%08X native_queried=%d native_ok=%d native_enabled=%u native_not_present=%u native_active=%d native_status=0x%08lX native_returned=%lu hv_sampled=%d ms_hv=%d vbs=%d hvci=%d hidden_hv=%d cpuid_hv=%d cpuid_vendor='%s' cpuid_vendor_hash=0x%016llX cpuid_vendor_ms=%d cpuid_vendor_non_ms=%d cpuid_leaf=%d synthetic_hv=%d tsc_qpc=%d hyperv_guest=%d scan_sampled=%d scan_ok=%d scan_pid=%llu debugger_pid=%llu dr_clear=%llu settle_sampled=%d settle_active=%d persistence_sampled=%d persist=%u corroborated=0x%08X decision=%s reason=%s",
        in.phase ? in.phase : "unknown",
        in.source ? in.source : "unknown",
        decision.flags,
        decision.decoded.c_str(),
        decision.hard_mask,
        decision.soft_mask,
        decision.unknown_mask,
        decision.page_guard_mask,
        in.native.queried ? 1 : 0,
        in.native.ok ? 1 : 0,
        static_cast<unsigned>(in.native.enabled),
        static_cast<unsigned>(in.native.not_present),
        in.native.active ? 1 : 0,
        static_cast<unsigned long>(in.native.status),
        static_cast<unsigned long>(in.native.returned),
        in.hv.sampled ? 1 : 0,
        in.hv.ms_hv ? 1 : 0,
        in.hv.vbs ? 1 : 0,
        in.hv.hvci ? 1 : 0,
        in.hv.hidden_hv ? 1 : 0,
        in.hv.cpuid_hv ? 1 : 0,
        in.hv.vendor[0] ? in.hv.vendor : "none",
        static_cast<unsigned long long>(in.hv.vendor_hash),
        in.hv.cpuid_vendor_ms ? 1 : 0,
        in.hv.cpuid_vendor_known_non_ms ? 1 : 0,
        in.hv.cpuid_leaf_inconsistent ? 1 : 0,
        in.hv.synthetic_hv ? 1 : 0,
        in.hv.tsc_qpc ? 1 : 0,
        in.hv.hyperv_guest ? 1 : 0,
        in.scan_sampled ? 1 : 0,
        in.scan_ok ? 1 : 0,
        static_cast<unsigned long long>(in.scan_pid),
        static_cast<unsigned long long>(in.debugger_pid),
        static_cast<unsigned long long>(in.dr_clear_count),
        in.settle_sampled ? 1 : 0,
        in.settle_active ? 1 : 0,
        in.persistence_sampled ? 1 : 0,
        in.persistence_count,
        in.corroborated_hard_signals,
        decision.enforce ? "enforce" : "observe",
        decision.reason ? decision.reason : "unknown");
    return std::string(buf);
}

}
