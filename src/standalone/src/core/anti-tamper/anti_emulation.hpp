#pragma once

#include <windows.h>
#include <intrin.h>

#include <cstdint>
#include <string>

#include "webhook.hpp"

namespace anti_tamper {
namespace anti_emulation {

struct emulation_report_t
{
    bool burn_loop_timing = false;
    bool cpuid_features = false;
    bool fpu_precision = false;
    bool self_modifying_code = false;
    std::string summary;

    bool any_detected() const
    {
        return burn_loop_timing || cpuid_features || fpu_precision || self_modifying_code;
    }
};

inline bool check_burn_loop_timing()
{
    volatile uint64_t t0 = __rdtsc();

    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 1000000; ++i)
        acc += static_cast<uint64_t>(i) * static_cast<uint64_t>(i);

    volatile uint64_t t1 = __rdtsc();
    uint64_t delta = t1 - t0;

    return delta > 500000000ULL;
}

inline bool check_cpuid_features()
{
    int regs[4] = {};
    __cpuid(regs, 1);

    bool has_sse42 = (regs[2] & (1 << 20)) != 0;

    __cpuidex(regs, 7, 0);
    bool has_bmi1 = (regs[1] & (1 << 3)) != 0;

    if (!has_sse42)
        return true;

    __try
    {
        volatile uint32_t test = _mm_crc32_u32(0, 0x12345678);
        (void)test;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }

    return false;
}

inline bool check_fpu_precision()
{
    uint16_t cw = 0;

    __try
    {
#ifdef _MSC_VER
        unsigned int fpcw = 0;
        _controlfp_s(&fpcw, 0, 0);
        cw = static_cast<uint16_t>(fpcw);
#endif

        volatile double a = 1.0;
        volatile double b = 3.0;
        volatile double c = a / b;
        volatile double d = c * b;

        if (d != 1.0)
        {
            volatile double diff = d - 1.0;
            if (diff > 1e-10 || diff < -1e-10)
                return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }

    return false;
}

inline bool check_self_modifying_code()
{
    DWORD old_prot = 0;
    uint8_t code_page[64];

    code_page[0] = 0xC3;
    for (int i = 1; i < 64; ++i)
        code_page[i] = 0x90;

    void* exec_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return false;

    memcpy(exec_mem, code_page, 64);

    __try
    {
        using void_fn = void(*)();
        auto fn = reinterpret_cast<void_fn>(exec_mem);
        fn();

        auto* ptr = static_cast<uint8_t*>(exec_mem);
        ptr[0] = 0xB8;
        *reinterpret_cast<uint32_t*>(ptr + 1) = 0x42424242;
        ptr[5] = 0xC3;

        FlushInstructionCache(GetCurrentProcess(), exec_mem, 64);

        using int_fn = uint32_t(*)();
        auto fn2 = reinterpret_cast<int_fn>(exec_mem);
        volatile uint32_t result = fn2();

        VirtualFree(exec_mem, 0, MEM_RELEASE);

        if (result != 0x42424242)
            return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return true;
    }

    return false;
}

inline emulation_report_t full_scan()
{
    emulation_report_t report{};

    report.cpuid_features = check_cpuid_features();
    if (report.cpuid_features)
        webhook::send_debug_log("emu_cpuid", "feature_mismatch", true);

    report.fpu_precision = check_fpu_precision();
    if (report.fpu_precision)
        webhook::send_debug_log("emu_fpu", "fpu_precision_anomaly", true);

    report.self_modifying_code = check_self_modifying_code();
    if (report.self_modifying_code)
        webhook::send_debug_log("emu_smc", "smc_execution_failed", true);

    report.burn_loop_timing = check_burn_loop_timing();
    if (report.burn_loop_timing)
        webhook::send_debug_log("emu_timing", "burn_loop_too_slow", false);

    if (report.burn_loop_timing) report.summary += "timing ";
    if (report.cpuid_features) report.summary += "cpuid ";
    if (report.fpu_precision) report.summary += "fpu ";
    if (report.self_modifying_code) report.summary += "smc ";

    return report;
}

}
}
