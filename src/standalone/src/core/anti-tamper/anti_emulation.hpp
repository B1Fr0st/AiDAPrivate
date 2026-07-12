#pragma once

#include <windows.h>
#include <intrin.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include "webhook.hpp"
#include "key_pipeline.hpp"
#include "../infra/win_thread.hpp"

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

    inline thread_local LONG g_expected_privileged_instruction_probe = 0;

    inline bool expected_privileged_instruction_probe_active()
    {
        return g_expected_privileged_instruction_probe > 0;
    }

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
    return false;
}

inline bool expected_privileged_instruction_probe_active()
{
    return detail::expected_privileged_instruction_probe_active();
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

    aida::infra::win_thread::joinable_thread_t writer;
    try
    {
        std::string err;
        if (!writer.start([&]() {
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
        },
            &err,
            aida::infra::win_thread::default_stack_reserve,
            "anti_emulation_smc_writer"))
        {
            webhook::send_debug_log("emu_smc_race", std::string("worker_unavailable: ") + err, false);
            VirtualFree(code_pg, 0, MEM_RELEASE);
            return false;
        }
    }
    catch (const std::exception& ex)
    {
        webhook::send_debug_log("emu_smc_race", std::string("worker_unavailable: ") + ex.what(), false);
        VirtualFree(code_pg, 0, MEM_RELEASE);
        return false;
    }
    catch (...)
    {
        webhook::send_debug_log("emu_smc_race", "worker_unavailable_unknown", false);
        VirtualFree(code_pg, 0, MEM_RELEASE);
        return false;
    }

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

inline void show_message_and_exit(const wchar_t* message)
{
    MessageBoxW(nullptr, message, L"AiDA",
        MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    ExitProcess(1);
}

inline bool is_hypervisor_vendor_known_good()
{
    int regs[4] = {};
    __try
    {
        __cpuid(regs, 0x40000000);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    char vendor[12] = {};
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);

    static const char kKnownGoodVendors[6][12] = {
        {'M','i','c','r','o','s','o','f','t',' ','H','v'},
        {'V','M','w','a','r','e','V','M','w','a','r','e'},
        {'K','V','M','K','V','M','K','V','M', 0, 0, 0},
        {'X','e','n','V','M','M','X','e','n','V','M','M'},
        {'V','B','o','x','V','B','o','x','V','B','o','x'},
        {'P','a','r','a','l','l','e','l','s', 0, 0, 0},
    };

    for (int i = 0; i < 6; ++i)
    {
        if (std::memcmp(vendor, kKnownGoodVendors[i], 12) == 0)
            return true;
    }
    return false;
}

inline bool check_hypervisor_timing_uniform()
{
    constexpr uint32_t kSamples = 100;

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

    uint64_t deltas[kSamples] = {};
    uint32_t count = 0;

    for (uint32_t i = 0; i < kSamples; ++i)
    {
        int dummy[4] = {};
        unsigned int aux0 = 0;
        unsigned int aux1 = 0;
        uint64_t t0 = __rdtscp(&aux0);
        __cpuid(dummy, 0);
        uint64_t t1 = __rdtscp(&aux1);
        uint64_t d = t1 >= t0 ? t1 - t0 : 0;
        deltas[count++] = d;
    }

    if (priority_set)
        SetThreadPriority(thread, previous_priority);
    if (affinity_set)
        SetThreadAffinityMask(thread, previous_mask);

    if (count < 50)
        return false;

    double sum = 0.0;
    for (uint32_t i = 0; i < count; ++i)
        sum += static_cast<double>(deltas[i]);
    double mean = sum / static_cast<double>(count);

    if (mean < 1.0)
        return true;

    double sq_sum = 0.0;
    for (uint32_t i = 0; i < count; ++i)
    {
        double diff = static_cast<double>(deltas[i]) - mean;
        sq_sum += diff * diff;
    }
    double variance = sq_sum / static_cast<double>(count - 1);
    double stdev = sqrt(variance);
    double cv = stdev / mean;

    return cv < 0.001;
}

inline bool check_unicorn_syscall_handling()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    size_t off = 0;
    code[off++] = 0x4D; code[off++] = 0x31; code[off++] = 0xDF;
    code[off++] = 0xB8; code[off++] = 0xFF; code[off++] = 0xFF;
    code[off++] = 0x00; code[off++] = 0x00;
    code[off++] = 0x0F; code[off++] = 0x05;
    code[off++] = 0x4C; code[off++] = 0x89; code[off++] = 0xD8;
    code[off++] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint64_t(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    uint64_t r11_after = 0;
    bool exception = false;

    __try
    {
        r11_after = fn();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (exception)
        return true;

    return r11_after == 0;
}

inline bool check_unicorn_rdrand_deterministic()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if (!((regs[2] >> 30) & 1))
        return false;

    uint64_t samples[32] = {};
    for (int i = 0; i < 32; ++i)
    {
        bool got_value = false;
        for (int retry = 0; retry < 10; ++retry)
        {
            unsigned __int64 val = 0;
            if (_rdrand64_step(&val))
            {
                samples[i] = static_cast<uint64_t>(val);
                got_value = true;
                break;
            }
        }
        if (!got_value)
            samples[i] = 0;
    }

    uint64_t sorted[32];
    std::memcpy(sorted, samples, sizeof(sorted));
    std::sort(sorted, sorted + 32);

    int distinct = 1;
    for (int i = 1; i < 32; ++i)
    {
        if (sorted[i] != sorted[i - 1])
            ++distinct;
    }

    return distinct < 30;
}

inline bool check_unicorn_xgetbv_ecx1()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if (!((regs[2] >> 26) & 1) || !((regs[2] >> 27) & 1))
        return false;

    unsigned __int64 xcr0 = 0;
    unsigned __int64 xcr1 = 0;
    bool xcr0_ok = false;
    bool xcr1_ok = false;

    __try
    {
        xcr0 = _xgetbv(0);
        xcr0_ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try
    {
        xcr1 = _xgetbv(1);
        xcr1_ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!xcr0_ok || xcr0 == 0)
        return false;

    if (!xcr1_ok)
        return false;

    return xcr1 == 0;
}

inline bool check_unicorn_emulation_preflight()
{
    int emulation_signals = 0;

    if (check_unicorn_syscall_handling())
        emulation_signals++;
    if (check_unicorn_rdrand_deterministic())
        emulation_signals++;
    if (check_unicorn_xgetbv_ecx1())
        emulation_signals++;

    return emulation_signals == 3;
}

using timing_canary_fn_t = bool(*)();
inline timing_canary_fn_t& timing_canary_fn_storage()
{
    static timing_canary_fn_t fn = nullptr;
    return fn;
}
inline void set_timing_canary_fn(timing_canary_fn_t fn)
{
    timing_canary_fn_storage() = fn;
}

inline void run_diagnostic_probes();

inline bool run_anti_emulation_preflight()
{
    if (check_unicorn_emulation_preflight())
    {
        webhook::send_debug_log("anti_emu", "emulation_detected_unicorn_3probe_gate", true);
        show_message_and_exit(L"Unsupported environment");
        return false;
    }

    run_diagnostic_probes();

    int cpuid_data[4] = {};
    __cpuid(cpuid_data, 1);
    bool hypervisor_present = (cpuid_data[2] >> 31) & 1;

    if (hypervisor_present)
    {
        if (!is_hypervisor_vendor_known_good())
        {
            webhook::send_debug_log("anti_emu", "unsupported_hypervisor_vendor", true);
            show_message_and_exit(L"Unsupported virtualization environment");
            return false;
        }

        auto canary_fn = timing_canary_fn_storage();
        bool timing_suspicious = canary_fn ? canary_fn() : check_hypervisor_timing_uniform();
        if (timing_suspicious)
        {
            webhook::send_debug_log("anti_emu", "hijacked_hypervisor_uniform_timing", true);
            show_message_and_exit(L"Unsupported virtualization environment");
            return false;
        }
    }

    return true;
}

inline bool check_unicorn_page_fault_behavior()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* page = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_NOACCESS);
    if (!page) return false;

    DWORD exception_code = 0;
    bool got_exception = false;

    __try
    {
        volatile uint64_t val = *static_cast<volatile uint64_t*>(page);
        (void)val;
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualFree(page, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ACCESS_VIOLATION;
}

inline bool check_unicorn_no_tlb()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* page = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!page) return false;

    auto* ptr = static_cast<volatile uint64_t*>(page);
    *ptr = 0xDEADBEEFCAFEBABEULL;
    volatile uint64_t warm = *ptr;
    (void)warm;

    DWORD old_prot = 0;
    if (!VirtualProtect(page, page_size, PAGE_NOACCESS, &old_prot))
    {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    Sleep(1);

    bool got_exception = false;
    DWORD exception_code = 0;

    __try
    {
        volatile uint64_t val = *ptr;
        (void)val;
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualProtect(page, page_size, PAGE_READWRITE, &old_prot);
    VirtualFree(page, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ACCESS_VIOLATION;
}

inline bool check_unicorn_invlpg_no_ud()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0x33; code[1] = 0xC0;
    code[2] = 0x0F; code[3] = 0x01; code[4] = 0x38;
    code[5] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = void(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    DWORD exception_code = 0;
    bool got_exception = false;

    __try
    {
        fn();
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ILLEGAL_INSTRUCTION;
}

inline bool check_unicorn_wbinvd_no_ud()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0x0F; code[1] = 0x09;
    code[2] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = void(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    DWORD exception_code = 0;
    bool got_exception = false;

    __try
    {
        fn();
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ILLEGAL_INSTRUCTION;
}

inline bool check_unicorn_vmx_unmodeled()
{
    int regs[4] = {};
    __cpuid(regs, 1);
    if (!((regs[2] >> 5) & 1))
        return false;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0x48; code[1] = 0x8D; code[2] = 0x04; code[3] = 0x24;
    code[4] = 0xF3; code[5] = 0x0F; code[6] = 0xC7; code[7] = 0x30;
    code[8] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = void(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    DWORD exception_code = 0;
    bool got_exception = false;

    __try
    {
        fn();
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ILLEGAL_INSTRUCTION;
}

inline bool check_unicorn_sgx_unmodeled()
{
    int regs[4] = {};
    __cpuidex(regs, 7, 0);
    if (!((regs[1] >> 2) & 1))
        return false;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0x0F; code[1] = 0x01; code[2] = 0xD7;
    code[3] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = void(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    DWORD exception_code = 0;
    bool got_exception = false;

    __try
    {
        fn();
    }
    __except ((exception_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER)
    {
        got_exception = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (!got_exception)
        return true;

    return exception_code != EXCEPTION_ILLEGAL_INSTRUCTION;
}

inline bool check_unicorn_rdpid_zeros()
{
    int regs[4] = {};
    __cpuidex(regs, 7, 0);
    if (!((regs[2] >> 22) & 1))
        return false;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0xF3; code[1] = 0x0F; code[2] = 0xC7; code[3] = 0xC0;
    code[4] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint64_t(*)();
    auto fn = reinterpret_cast<fn_t>(code);

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

    uint64_t values[4] = {};
    bool exception = false;

    for (int i = 0; i < 4; ++i)
    {
        __try
        {
            values[i] = fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            exception = true;
            values[i] = 0;
        }
    }

    if (affinity_set)
        SetThreadAffinityMask(thread, previous_mask);

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (exception)
        return true;

    if (values[0] == 0 && values[1] == 0 && values[2] == 0 && values[3] == 0)
        return true;

    return false;
}

inline bool check_unicorn_rdpmc_zeros()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);
    code[0] = 0x33; code[1] = 0xC9;
    code[2] = 0x0F; code[3] = 0x33;
    code[4] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint64_t(*)();
    auto fn = reinterpret_cast<fn_t>(code);

    uint64_t values[16] = {};
    bool any_exception = false;

    for (int i = 0; i < 16; ++i)
    {
        __try
        {
            values[i] = fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            any_exception = true;
            values[i] = 0;
        }
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (any_exception)
        return false;

    bool all_zero = true;
    for (int i = 0; i < 16; ++i)
    {
        if (values[i] != 0) { all_zero = false; break; }
    }
    if (all_zero)
        return true;

    bool all_same = true;
    for (int i = 1; i < 16; ++i)
    {
        if (values[i] != values[0]) { all_same = false; break; }
    }
    return all_same;
}

inline bool check_unicorn_endbr_behavior()
{
    int regs[4] = {};
    __cpuidex(regs, 7, 0);
    if (!((regs[3] >> 20) & 1)) return false;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000;

    void* code_pg = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!code_pg) return false;

    auto* code = static_cast<uint8_t*>(code_pg);

    size_t off = 0;
    code[off++] = 0xF3; code[off++] = 0x0F; code[off++] = 0x1E; code[off++] = 0xFA;
    code[off++] = 0xB8; code[off++] = 0x41; code[off++] = 0x41; code[off++] = 0x41; code[off++] = 0x41;
    code[off++] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    using fn_t = uint32_t(*)();
    auto fn1 = reinterpret_cast<fn_t>(code);

    uint32_t result1 = 0;
    bool exception1 = false;

    __try
    {
        result1 = fn1();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        exception1 = true;
    }

    if (exception1 || result1 != 0x41414141)
    {
        VirtualFree(code_pg, 0, MEM_RELEASE);
        return true;
    }

    off = 0;
    code[off++] = 0xF3; code[off++] = 0x0F; code[off++] = 0x1E; code[off++] = 0xFB;
    code[off++] = 0xB8; code[off++] = 0x42; code[off++] = 0x42; code[off++] = 0x42; code[off++] = 0x42;
    code[off++] = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), code_pg, page_size);

    auto fn2 = reinterpret_cast<fn_t>(code);

    uint32_t result2 = 0;
    bool exception2 = false;

    __try
    {
        result2 = fn2();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        exception2 = true;
    }

    VirtualFree(code_pg, 0, MEM_RELEASE);

    if (exception2 || result2 != 0x42424242)
        return true;

    return false;
}

inline bool check_unicorn_rdseed_deterministic()
{
    int regs[4] = {};
    __cpuidex(regs, 7, 0);
    if (!((regs[1] >> 18) & 1))
        return false;

    uint64_t samples[32] = {};
    for (int i = 0; i < 32; ++i)
    {
        bool got_value = false;
        for (int retry = 0; retry < 10; ++retry)
        {
            unsigned __int64 val = 0;
            if (_rdseed64_step(&val))
            {
                samples[i] = static_cast<uint64_t>(val);
                got_value = true;
                break;
            }
        }
        if (!got_value)
            samples[i] = 0;
    }

    uint64_t sorted[32];
    std::memcpy(sorted, samples, sizeof(sorted));
    std::sort(sorted, sorted + 32);

    int distinct = 1;
    for (int i = 1; i < 32; ++i)
    {
        if (sorted[i] != sorted[i - 1])
            ++distinct;
    }

    return distinct < 30;
}

inline void run_diagnostic_probes()
{
    struct probe_entry_t
    {
        const char* name;
        bool (*fn)();
    };

    static const probe_entry_t probes[] = {
        {"page_fault", check_unicorn_page_fault_behavior},
        {"no_tlb", check_unicorn_no_tlb},
        {"invlpg", check_unicorn_invlpg_no_ud},
        {"wbinvd", check_unicorn_wbinvd_no_ud},
        {"vmx", check_unicorn_vmx_unmodeled},
        {"sgx", check_unicorn_sgx_unmodeled},
        {"rdpid", check_unicorn_rdpid_zeros},
        {"rdpmc", check_unicorn_rdpmc_zeros},
        {"endbr", check_unicorn_endbr_behavior},
        {"rdseed", check_unicorn_rdseed_deterministic},
    };

    for (const auto& p : probes)
    {
        bool result = false;
        __try
        {
            result = p.fn();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = false;
        }

        char buf[128];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "diagnostic_probe name=%s result=%d",
            p.name, result ? 1 : 0);
        webhook::write_log("anti_emu", buf);
    }
}

}
}
