#pragma once

#include <windows.h>
#include <intrin.h>
#include <bcrypt.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include "webhook.hpp"
#include "key_pipeline.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace anti_tamper {
namespace anti_emulation {

struct emulation_report_t
{
    bool burn_loop_timing = false;
    bool cpuid_features = false;
    bool fpu_precision = false;
    bool self_modifying_code = false;
    bool partial_register_anomaly = false;
    bool rdpmc_unsupported = false;
    bool symbolic_lookup_anomaly = false;
    bool smc_race_inconsistent = false;
    bool smc_prefetch_inconsistent = false;
    std::string summary;

    bool any_detected() const
    {
        return burn_loop_timing || cpuid_features || fpu_precision
            || self_modifying_code || partial_register_anomaly
            || rdpmc_unsupported || symbolic_lookup_anomaly
            || smc_race_inconsistent || smc_prefetch_inconsistent;
    }
};

namespace detail {

    inline bool fill_secure_random(void* buf, size_t bytes)
    {
        return BCryptGenRandom(nullptr,
            static_cast<PUCHAR>(buf), static_cast<ULONG>(bytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline uint64_t random_u64()
    {
        uint64_t v = 0;
        if (!fill_secure_random(&v, sizeof(v)))
            v = static_cast<uint64_t>(__rdtsc());
        return v;
    }

}

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
    (void)has_bmi1;

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
    __try
    {
#ifdef _MSC_VER
        unsigned int fpcw = 0;
        _controlfp_s(&fpcw, 0, 0);
        (void)fpcw;
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

inline bool check_partial_register_zero_extension()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    size_t off = 0;
    code[off++] = 0x48; code[off++] = 0xB8;
    uint64_t pre_mask = 0;
    {
        uint8_t derived[8] = {};
        if (!key_pipeline::derive(
                "aida.anti_emu.partial_reg",
                nullptr, 0,
                derived, sizeof(derived)))
        {
            VirtualFree(code_pg, 0, MEM_RELEASE);
            return false;
        }
        memcpy(&pre_mask, derived, sizeof(pre_mask));
        SecureZeroMemory(derived, sizeof(derived));
    }
    memcpy(code + off, &pre_mask, 8); off += 8;
    code[off++] = 0xB0; code[off++] = 0xFF;
    code[off++] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    bool exception = false;
    uint64_t observed = 0;

    __try
    {
        using fn_t = uint64_t(*)();
        auto fn = reinterpret_cast<fn_t>(code);
        observed = fn();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (exception) return true;
    if ((observed & 0xFFu) != 0xFFu)
        return true;
    uint64_t high = observed & 0xFFFFFFFFFFFFFF00ULL;
    if (high != (pre_mask & 0xFFFFFFFFFFFFFF00ULL))
        return true;

    return false;
}

inline bool check_rdpmc_supported()
{
    int regs[4] = {};
    __cpuid(regs, 0x0A);
    int version_id = regs[0] & 0xFFu;
    int num_counters = (regs[0] >> 8) & 0xFFu;

    if (version_id == 0 || num_counters == 0)
        return false;

    __try
    {
        volatile uint64_t a = __readpmc(0);
        volatile uint64_t b = __readpmc(0);

        if (a == 0 && b == 0)
            return true;

        if (a == b)
        {
            volatile uint64_t spin = 0;
            for (volatile uint32_t i = 0; i < 50000; ++i)
                spin += i;
            volatile uint64_t c = __readpmc(0);
            if (c == a)
                return true;
        }
    }
    __except (GetExceptionCode() == EXCEPTION_PRIV_INSTRUCTION
              || GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
    return false;
}

inline bool check_symbolic_lookup_via_guard_page()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* table_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!table_pg) return false;

    auto* table = static_cast<uint64_t*>(table_pg);
    constexpr size_t k_count = 16;
    uint64_t expected[k_count]{};
    for (size_t i = 0; i < k_count; ++i)
    {
        uint64_t v = detail::random_u64();
        table[i] = v;
        expected[i] = v;
    }

    DWORD old_prot = 0;
    if (!VirtualProtect(table_pg, page_size,
        PAGE_NOACCESS, &old_prot))
    {
        VirtualFree(table_pg, 0, MEM_RELEASE);
        return false;
    }

    if (!VirtualProtect(table_pg, page_size,
        PAGE_READWRITE | PAGE_GUARD, &old_prot))
    {
        VirtualFree(table_pg, 0, MEM_RELEASE);
        return false;
    }

    bool guard_observed = false;
    bool mismatch = false;

    for (size_t i = 0; i < k_count; ++i)
    {
        bool ex_seen = false;
        uint64_t got = 0;
        __try
        {
            got = table[i];
        }
        __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION
                  ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            ex_seen = true;
        }

        if (ex_seen)
        {
            guard_observed = true;
            __try
            {
                got = table[i];
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                mismatch = true;
                break;
            }
        }

        if (got != expected[i])
        {
            mismatch = true;
            break;
        }

        if (!VirtualProtect(table_pg, page_size,
            PAGE_READWRITE | PAGE_GUARD, &old_prot))
        {
            mismatch = true;
            break;
        }
    }

    VirtualProtect(table_pg, page_size, PAGE_READWRITE, &old_prot);
    VirtualFree(table_pg, 0, MEM_RELEASE);

    if (mismatch) return true;
    if (!guard_observed) return true;
    return false;
}

inline bool check_smc_race_between_threads()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0xB8;
    *reinterpret_cast<uint32_t*>(code + 1) = 0xAAAAAAAA;
    code[5] = 0xC3;
    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint32_t(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    std::atomic<bool> stop{false};
    std::atomic<bool> writer_started{false};

    std::thread writer([&]() {
        writer_started.store(true);
        uint8_t toggle = 0;
        while (!stop.load(std::memory_order_acquire))
        {
            uint32_t imm = (toggle & 1) ? 0xCCCCCCCC : 0xDDDDDDDD;
            *reinterpret_cast<volatile uint32_t*>(code + 1) = imm;
            FlushInstructionCache(GetCurrentProcess(), code_pg, 8);
            ++toggle;
            if ((toggle & 0x3F) == 0)
                std::this_thread::yield();
        }
    });

    while (!writer_started.load(std::memory_order_acquire))
        std::this_thread::yield();

    uint32_t observed_distinct = 0;
    uint32_t last = 0;
    bool first = true;
    bool failure = false;

    struct probe_state_t
    {
        uint32_t (*fn)();
        uint32_t observed_distinct;
        uint32_t last;
        bool first;
        bool failure;
    };
    auto seh_probe = [](probe_state_t* s) {
        __try
        {
            for (uint32_t i = 0; i < 8000 && s->observed_distinct < 4; ++i)
            {
                volatile uint32_t r = s->fn();
                if (s->first || r != s->last)
                {
                    ++s->observed_distinct;
                    s->last = r;
                    s->first = false;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            s->failure = true;
        }
    };

    probe_state_t state{ fn, 0, 0, true, false };
    seh_probe(&state);
    observed_distinct = state.observed_distinct;
    last = state.last;
    first = state.first;
    failure = state.failure;

    stop.store(true, std::memory_order_release);
    if (writer.joinable()) writer.join();

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (failure) return true;
    if (observed_distinct < 2) return true;
    return false;
}

inline bool check_smc_at_instruction_boundary()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);

    code[0] = 0xB8;
    *reinterpret_cast<uint32_t*>(code + 1) = 0x11111111;
    code[5] = 0x05;
    *reinterpret_cast<uint32_t*>(code + 6) = 0x00000000;
    code[10] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint32_t(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    bool any_failure = false;
    uint32_t mismatch_count = 0;

    for (int trial = 0; trial < 32; ++trial)
    {
        uint32_t mov_imm = 0;
        uint32_t add_imm = 0;
        if (!detail::fill_secure_random(&mov_imm, sizeof(mov_imm)))
            mov_imm = static_cast<uint32_t>(__rdtsc());
        if (!detail::fill_secure_random(&add_imm, sizeof(add_imm)))
            add_imm = static_cast<uint32_t>(__rdtsc() >> 16);

        *reinterpret_cast<volatile uint32_t*>(code + 1) = mov_imm;
        *reinterpret_cast<volatile uint32_t*>(code + 6) = add_imm;
        FlushInstructionCache(GetCurrentProcess(), code_pg, 11);

        uint32_t observed = 0;
        __try
        {
            observed = fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            any_failure = true;
            break;
        }

        uint32_t expected = mov_imm + add_imm;
        if (observed != expected)
            ++mismatch_count;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (any_failure) return true;
    if (mismatch_count > 0) return true;
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

    report.partial_register_anomaly = check_partial_register_zero_extension();
    if (report.partial_register_anomaly)
        webhook::send_debug_log("emu_partial_reg", "partial_register_anomaly", true);

    report.rdpmc_unsupported = check_rdpmc_supported();
    if (report.rdpmc_unsupported)
        webhook::send_debug_log("emu_rdpmc", "rdpmc_unavailable_or_static", true);

    report.symbolic_lookup_anomaly = check_symbolic_lookup_via_guard_page();
    if (report.symbolic_lookup_anomaly)
        webhook::send_debug_log("emu_symbolic", "guard_page_lookup_anomaly", true);

    report.smc_race_inconsistent = check_smc_race_between_threads();
    if (report.smc_race_inconsistent)
        webhook::send_debug_log("emu_smc_race", "smc_race_inconsistent", true);

    report.smc_prefetch_inconsistent = check_smc_at_instruction_boundary();
    if (report.smc_prefetch_inconsistent)
        webhook::send_debug_log("emu_smc_prefetch", "smc_prefetch_inconsistent", true);

    report.burn_loop_timing = check_burn_loop_timing();
    if (report.burn_loop_timing)
        webhook::send_debug_log("emu_timing", "burn_loop_too_slow", false);

    if (report.burn_loop_timing) report.summary += "timing ";
    if (report.cpuid_features) report.summary += "cpuid ";
    if (report.fpu_precision) report.summary += "fpu ";
    if (report.self_modifying_code) report.summary += "smc ";
    if (report.partial_register_anomaly) report.summary += "partial_reg ";
    if (report.rdpmc_unsupported) report.summary += "rdpmc ";
    if (report.symbolic_lookup_anomaly) report.summary += "symbolic ";
    if (report.smc_race_inconsistent) report.summary += "smc_race ";
    if (report.smc_prefetch_inconsistent) report.summary += "smc_prefetch ";

    return report;
}

}
}
