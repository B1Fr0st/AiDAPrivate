#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#include <atomic>
#include <array>
#include <cstdint>
#include <string>

#include "webhook.hpp"
#include "syscall.hpp"
#include "standalone_driver.hpp"
#include "kernel_adbg_classifier.hpp"

namespace anti_tamper {
namespace anti_debug {

inline bool check_kd_shared_data();

struct debug_report_t
{
    bool peb_being_debugged = false;
    bool peb_nt_global_flag = false;
    bool peb_heap_flags = false;
    bool debug_port = false;
    bool debug_object_handle = false;
    bool debug_flags = false;
    bool remote_debugger = false;
    bool is_debugger_present = false;
    bool close_handle_trap = false;
    bool output_debug_string = false;
    bool hw_breakpoints_local = false;
    bool hw_breakpoints_kernel = false;
    bool kernel_debugger = false;
    bool kd_shared_data = false;
    bool rdtsc_timing = false;
    bool qpc_timing = false;
    bool thread_hidden = false;
    bool instrumentation_callback = false;
    bool branch_miss_flat = false;
    bool page_fault_timing_anomaly = false;
    bool ipi_latency_anomaly = false;
    bool cache_coherency_anomaly = false;
    bool function_call_timing_anomaly = false;
    bool trap_flag = false;
    std::string summary;

    bool any_detected() const
    {
        return peb_being_debugged || peb_nt_global_flag || peb_heap_flags
            || debug_port || debug_object_handle || debug_flags
            || remote_debugger || is_debugger_present || close_handle_trap
            || output_debug_string || hw_breakpoints_local || hw_breakpoints_kernel
            || kernel_debugger || kd_shared_data || thread_hidden
            || instrumentation_callback || trap_flag;
    }

    bool any_timing_anomaly() const
    {
        return branch_miss_flat || page_fault_timing_anomaly
            || ipi_latency_anomaly || cache_coherency_anomaly
            || function_call_timing_anomaly;
    }

    uint32_t get_bug_check_code_or(uint32_t fallback) const
    {
        if (debug_port || debug_object_handle || debug_flags)
            return 0x0000DBDBu;
        if (hw_breakpoints_local || hw_breakpoints_kernel)
            return 0x0000D7D7u;
        if (kernel_debugger || kd_shared_data)
            return 0x00007A63u;
        if (instrumentation_callback || trap_flag)
            return 0xA1DA0002u;
        if (peb_being_debugged || peb_nt_global_flag || peb_heap_flags
            || remote_debugger || is_debugger_present
            || close_handle_trap || output_debug_string)
            return 0x0000DEEEu;
        if (thread_hidden)
            return 0x0000D7D7u;
        return fallback;
    }
};

struct timing_sample_t
{
    uint32_t kind;
    uint32_t flags;
    uint64_t value_a;
    uint64_t value_b;
    uint64_t timestamp;
};

constexpr uint32_t TIMING_KIND_FN_ENTRY_EXIT = 1u;
constexpr uint32_t TIMING_KIND_BRANCH_MISS   = 2u;
constexpr uint32_t TIMING_KIND_PAGE_FAULT    = 3u;
constexpr uint32_t TIMING_KIND_IPI_LATENCY   = 4u;
constexpr uint32_t TIMING_KIND_CACHE_COHERENCY = 5u;

constexpr uint32_t TIMING_FLAG_ANOMALY = 0x1u;
constexpr uint32_t TIMING_FLAG_FLAT    = 0x2u;
constexpr uint32_t TIMING_FLAG_ABSURD  = 0x4u;

inline constexpr size_t TIMING_RING_CAPACITY = 256;

struct timing_ring_t
{
    std::array<timing_sample_t, TIMING_RING_CAPACITY> slots{};
    std::atomic<uint64_t> head{0};
    std::atomic<uint64_t> dropped{0};
};

inline timing_ring_t& timing_ring()
{
    static timing_ring_t inst;
    return inst;
}

inline void timing_ring_push(uint32_t kind, uint32_t flags, uint64_t a, uint64_t b)
{
    auto& ring = timing_ring();
    const uint64_t slot_index = ring.head.fetch_add(1, std::memory_order_acq_rel);
    timing_sample_t& slot = ring.slots[static_cast<size_t>(slot_index % TIMING_RING_CAPACITY)];
    slot.kind = kind;
    slot.flags = flags;
    slot.value_a = a;
    slot.value_b = b;
    slot.timestamp = __rdtsc();
}

inline uint64_t timing_ring_total_pushed()
{
    return timing_ring().head.load(std::memory_order_acquire);
}

inline size_t timing_ring_snapshot(timing_sample_t* out, size_t out_max)
{
    if (out == nullptr || out_max == 0)
        return 0;
    auto& ring = timing_ring();
    const uint64_t total = ring.head.load(std::memory_order_acquire);
    const uint64_t available = (total > TIMING_RING_CAPACITY) ? TIMING_RING_CAPACITY : total;
    const size_t to_copy = (available > out_max) ? out_max : static_cast<size_t>(available);
    if (to_copy == 0)
        return 0;
    const uint64_t newest_idx = (total - 1ull) % TIMING_RING_CAPACITY;
    for (size_t i = 0; i < to_copy; ++i) {
        const size_t idx = static_cast<size_t>((newest_idx + TIMING_RING_CAPACITY - i) % TIMING_RING_CAPACITY);
        out[i] = ring.slots[idx];
    }
    return to_copy;
}

class function_entry_exit_rdtsc_t
{
public:
    explicit function_entry_exit_rdtsc_t(uint32_t site_id) noexcept
        : site_id_(site_id)
    {
        unsigned int aux = 0;
        _mm_lfence();
        start_ = __rdtscp(&aux);
        cpu_in_ = aux & 0xFFFu;
    }

    ~function_entry_exit_rdtsc_t()
    {
        unsigned int aux = 0;
        const uint64_t end = __rdtscp(&aux);
        _mm_lfence();
        const uint32_t cpu_out = aux & 0xFFFu;
        const uint64_t delta = end - start_;
        uint32_t flags = 0;
        if (delta == 0)
            flags |= TIMING_FLAG_FLAT;
        if (delta > 50000000ULL)
            flags |= TIMING_FLAG_ABSURD;
        if (cpu_out != cpu_in_)
            flags |= TIMING_FLAG_ANOMALY;
        timing_ring_push(TIMING_KIND_FN_ENTRY_EXIT,
                         flags | (static_cast<uint32_t>(site_id_) << 8),
                         delta,
                         (static_cast<uint64_t>(cpu_in_) << 32) | cpu_out);
    }

    function_entry_exit_rdtsc_t(const function_entry_exit_rdtsc_t&) = delete;
    function_entry_exit_rdtsc_t& operator=(const function_entry_exit_rdtsc_t&) = delete;

private:
    uint32_t site_id_;
    uint32_t cpu_in_ = 0;
    uint64_t start_ = 0;
};

inline bool check_being_debugged()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    return *(peb + 0x02) != 0;
}

inline bool check_nt_global_flag()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    const uint32_t nt_global = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
    return (nt_global & 0x70u) != 0;
}

inline bool check_heap_flags()
{
    const auto peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;

    const uint64_t process_heap = *reinterpret_cast<const uint64_t*>(peb + 0x30);
    if (process_heap == 0) return false;

    const auto* heap = reinterpret_cast<const uint8_t*>(process_heap);
    const uint32_t flags = *reinterpret_cast<const uint32_t*>(heap + 0x70);
    const uint32_t force_flags = *reinterpret_cast<const uint32_t*>(heap + 0x74);

    if (force_flags != 0) return true;
    if ((flags & ~0x02u) != 0) return true;

    return false;
}

inline bool check_debug_port()
{
    if (!syscall::is_initialized()) return false;

    ULONG_PTR debug_port = 0;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
    return (st >= 0 && debug_port != 0);
}

inline bool check_debug_object_handle()
{
    if (!syscall::is_initialized()) return false;

    HANDLE debug_obj = nullptr;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 0x1E, &debug_obj, sizeof(debug_obj), nullptr);
    if (st >= 0 && debug_obj != nullptr)
    {
        syscall::NtClose()(debug_obj);
        return true;
    }
    return false;
}

inline bool check_debug_flags()
{
    if (!syscall::is_initialized()) return false;

    ULONG debug_flags = 0;
    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 0x1F, &debug_flags, sizeof(debug_flags), nullptr);
    return (st >= 0 && debug_flags == 0);
}

inline bool check_remote_debugger()
{
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present)
        return true;
    return false;
}

inline bool check_is_debugger_present()
{
    return IsDebuggerPresent() != FALSE;
}

inline bool check_close_handle_trap()
{
    if (!syscall::is_initialized()) return false;

    __try
    {
        syscall::NtClose()(reinterpret_cast<HANDLE>(0xDEADBEEFull));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
    return false;
}

inline bool check_output_debug_string()
{
    int triggered = 0;
    for (int sample = 0; sample < 3; ++sample)
    {
        SetLastError(0xDEAD);
        OutputDebugStringW(L"AT_PROBE");
        if (GetLastError() != 0xDEAD)
            ++triggered;

        for (int spin = 0; spin < 256; ++spin)
            _mm_pause();
    }

    if (triggered < 2)
        return false;

    return check_kd_shared_data();
}

inline bool check_hw_breakpoints_local()
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
    {
        uint64_t dr7 = ctx.Dr7;
        for (int i = 0; i < 4; ++i)
        {
            bool local = (dr7 >> (i * 2)) & 1;
            bool global = (dr7 >> (i * 2 + 1)) & 1;
            if (local || global) return true;
        }
    }
    return false;
}

inline bool check_hw_breakpoints_kernel(uint64_t mod_base, uint64_t mod_end)
{
    if (!driver_bridge::is_loaded() || !driver_bridge::using_kernel_driver())
        return false;

    auto threads = driver_bridge::enumerate_threads();
    for (const auto& t : threads)
    {
        driver_bridge::thread_context_t ctx{};
        if (!driver_bridge::get_thread_context(t.tid, ctx))
            continue;

        const uint64_t dr_values[] = { ctx.dr0, ctx.dr1, ctx.dr2, ctx.dr3 };
        const uint64_t dr7 = ctx.dr7;

        for (int i = 0; i < 4; ++i)
        {
            if (dr_values[i] == 0) continue;

            const bool enabled_local  = (dr7 >> (i * 2))     & 1;
            const bool enabled_global = (dr7 >> (i * 2 + 1)) & 1;
            if (!enabled_local && !enabled_global) continue;

            if (dr_values[i] >= mod_base && dr_values[i] < mod_end)
                return true;
        }
    }
    return false;
}

inline bool check_kernel_debugger()
{
    if (!syscall::is_initialized()) return false;

    const auto kd = kernel_adbg::query_native_kernel_debugger_state();
    if (!kd.queried || !kd.ok)
    {
        char buf[192];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "native_kernel_debugger_query_failed status=0x%08lX returned=%lu",
            static_cast<unsigned long>(kd.status),
            static_cast<unsigned long>(kd.returned));
        webhook::write_log("anti_debug", buf);
        return false;
    }
    return kd.active;
}

inline bool check_kd_shared_data()
{
    const auto* kuser = reinterpret_cast<const uint8_t*>(0x7FFE0000ULL);
    __try
    {
        uint8_t kd_enabled = *(kuser + 0x2D4);
        uint8_t kd_not_present = *(kuser + 0x2D5);
        return kd_enabled != 0 && kd_not_present == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

inline bool check_rdtsc_timing()
{
    volatile uint64_t t0 = __rdtsc();

    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 100; ++i)
        acc += i * i;

    volatile uint64_t t1 = __rdtsc();
    return (t1 - t0) > 10000000ULL;
}

inline bool check_qpc_timing()
{
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 100; ++i)
        acc += i * i;

    QueryPerformanceCounter(&t1);

    double elapsed_us = static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000000.0 / freq.QuadPart;
    return elapsed_us > 50000.0;
}

inline bool check_thread_hidden()
{
    if (!syscall::is_initialized()) return false;

    ULONG hidden = 0;
    NTSTATUS st = syscall::NtQueryInformationThread()(
        GetCurrentThread(), 0x11, &hidden, sizeof(hidden), nullptr);
    return st >= 0 && hidden != 0;
}

inline bool check_branch_miss_flat()
{
    if (!driver_bridge::dynamic_ioctls_ready())
        return false;

    driver_bridge::anti_debug_result_t kernel{};
    if (!driver_bridge::kernel_anti_debug_query(kernel))
        return false;

    const bool timing_attack = (kernel.result_flags & kernel_adbg::DETECT_TIMING_ATTACK) != 0;
    timing_ring_push(TIMING_KIND_BRANCH_MISS,
                     timing_attack ? TIMING_FLAG_ANOMALY : 0u,
                     kernel.result_flags,
                     kernel.dr_clear_count);
    return timing_attack;
}

inline bool check_page_fault_timing_anomaly()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const SIZE_T page_size = si.dwPageSize ? si.dwPageSize : 4096u;

    LPVOID region = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (region == nullptr)
        return false;

    *static_cast<volatile uint8_t*>(region) = 0xCD;

    DWORD old_protect = 0;
    if (!VirtualProtect(region, page_size, PAGE_NOACCESS, &old_protect)) {
        VirtualFree(region, 0, MEM_RELEASE);
        return false;
    }

    constexpr int ROUNDS = 8;
    uint64_t deltas[ROUNDS] = {};
    int captured = 0;

    for (int i = 0; i < ROUNDS; ++i) {
        DWORD restored = 0;
        VirtualProtect(region, page_size, PAGE_READWRITE, &restored);
        FlushInstructionCache(GetCurrentProcess(), region, page_size);
        VirtualProtect(region, page_size, PAGE_NOACCESS, &restored);

        unsigned int aux = 0;
        _mm_lfence();
        const uint64_t t0 = __rdtscp(&aux);
        DWORD restored2 = 0;
        const BOOL ok = VirtualProtect(region, page_size, PAGE_READWRITE, &restored2);
        _mm_lfence();
        const uint64_t t1 = __rdtscp(&aux);
        if (!ok)
            continue;

        deltas[captured++] = t1 - t0;
    }

    VirtualFree(region, 0, MEM_RELEASE);
    if (captured < 4)
        return false;

    for (int i = 0; i < captured - 1; ++i) {
        for (int j = i + 1; j < captured; ++j) {
            if (deltas[j] < deltas[i]) {
                const uint64_t tmp = deltas[i];
                deltas[i] = deltas[j];
                deltas[j] = tmp;
            }
        }
    }
    const uint64_t median = deltas[captured / 2];

    const bool too_flat = median < 80ULL;
    const bool too_high = median > 80000ULL;
    const uint32_t flags = (too_flat ? TIMING_FLAG_FLAT : 0u)
                         | (too_high ? TIMING_FLAG_ABSURD : 0u)
                         | ((too_flat || too_high) ? TIMING_FLAG_ANOMALY : 0u);
    timing_ring_push(TIMING_KIND_PAGE_FAULT, flags, median, static_cast<uint64_t>(captured));
    return too_flat || too_high;
}

inline VOID CALLBACK ipi_apc_proc(ULONG_PTR param)
{
    auto* counter = reinterpret_cast<std::atomic<uint64_t>*>(param);
    if (counter)
        counter->fetch_add(1, std::memory_order_acq_rel);
}

inline DWORD WINAPI ipi_alertable_thread(LPVOID arg)
{
    auto* signal = reinterpret_cast<std::atomic<uint64_t>*>(arg);
    SleepEx(120, TRUE);
    if (signal)
        signal->fetch_or(0x80000000ULL, std::memory_order_release);
    return 0;
}

inline bool check_ipi_latency_anomaly()
{
    DWORD_PTR proc_mask = 0;
    DWORD_PTR sys_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask))
        return false;

    int active_cores = 0;
    int candidate_a = -1;
    int candidate_b = -1;
    for (int bit = 0; bit < 64; ++bit) {
        if (((proc_mask >> bit) & 1ull) != 0) {
            ++active_cores;
            if (candidate_a < 0) candidate_a = bit;
            else if (candidate_b < 0) { candidate_b = bit; }
        }
    }
    if (active_cores < 2 || candidate_a < 0 || candidate_b < 0)
        return false;

    HANDLE this_thread = GetCurrentThread();
    const DWORD_PTR prev_mask = SetThreadAffinityMask(this_thread, 1ull << candidate_a);
    if (prev_mask == 0)
        return false;

    std::atomic<uint64_t> remote_signal{0};
    HANDLE remote_handle = CreateThread(nullptr, 0, &ipi_alertable_thread, &remote_signal, CREATE_SUSPENDED, nullptr);
    if (remote_handle == nullptr) {
        SetThreadAffinityMask(this_thread, prev_mask);
        return false;
    }
    SetThreadAffinityMask(remote_handle, 1ull << candidate_b);
    ResumeThread(remote_handle);

    Sleep(2);

    constexpr int ROUNDS = 6;
    uint64_t deltas[ROUNDS] = {};
    int captured = 0;
    std::atomic<uint64_t> apc_counter{0};

    for (int i = 0; i < ROUNDS; ++i) {
        const uint64_t before = apc_counter.load(std::memory_order_acquire);
        unsigned int aux = 0;
        _mm_lfence();
        const uint64_t t0 = __rdtscp(&aux);
        const DWORD ok = QueueUserAPC(&ipi_apc_proc, remote_handle, reinterpret_cast<ULONG_PTR>(&apc_counter));
        if (ok == 0) continue;
        while (apc_counter.load(std::memory_order_acquire) == before) {
            _mm_pause();
            unsigned int aux_now = 0;
            const uint64_t now = __rdtscp(&aux_now);
            if ((now - t0) > 50000000ULL)
                break;
        }
        const uint64_t t1 = __rdtscp(&aux);
        _mm_lfence();
        if (apc_counter.load(std::memory_order_acquire) > before)
            deltas[captured++] = t1 - t0;
    }

    remote_signal.store(0xC0000001ULL, std::memory_order_release);
    WaitForSingleObject(remote_handle, 200);
    CloseHandle(remote_handle);
    SetThreadAffinityMask(this_thread, prev_mask);

    if (captured < 3)
        return false;

    for (int i = 0; i < captured - 1; ++i) {
        for (int j = i + 1; j < captured; ++j) {
            if (deltas[j] < deltas[i]) {
                const uint64_t tmp = deltas[i];
                deltas[i] = deltas[j];
                deltas[j] = tmp;
            }
        }
    }
    const uint64_t median = deltas[captured / 2];

    const bool too_flat = median < 1000ULL;
    const bool too_high = median > 5000000ULL;
    const uint32_t flags = (too_flat ? TIMING_FLAG_FLAT : 0u)
                         | (too_high ? TIMING_FLAG_ABSURD : 0u)
                         | ((too_flat || too_high) ? TIMING_FLAG_ANOMALY : 0u);
    timing_ring_push(TIMING_KIND_IPI_LATENCY, flags, median, static_cast<uint64_t>(captured));
    return too_flat || too_high;
}

inline bool check_cache_coherency_anomaly()
{
    constexpr size_t LINE_SIZE = 64;
    constexpr size_t BUFFER_BYTES = LINE_SIZE * 16;
    void* raw = _aligned_malloc(BUFFER_BYTES, LINE_SIZE);
    if (raw == nullptr)
        return false;

    auto* probe = static_cast<volatile uint8_t*>(raw);
    for (size_t i = 0; i < BUFFER_BYTES; ++i)
        probe[i] = static_cast<uint8_t>(i ^ 0x5A);

    constexpr int ROUNDS = 32;
    uint64_t flushed[ROUNDS] = {};
    uint64_t cached[ROUNDS] = {};

    for (int i = 0; i < ROUNDS; ++i) {
        for (size_t off = 0; off < BUFFER_BYTES; off += LINE_SIZE)
            _mm_clflush(const_cast<const uint8_t*>(probe + off));
        _mm_mfence();

        unsigned int aux = 0;
        _mm_lfence();
        const uint64_t t0 = __rdtscp(&aux);
        volatile uint64_t acc = 0;
        for (size_t off = 0; off < BUFFER_BYTES; off += LINE_SIZE)
            acc += probe[off];
        _mm_lfence();
        const uint64_t t1 = __rdtscp(&aux);
        flushed[i] = t1 - t0;

        _mm_lfence();
        const uint64_t t2 = __rdtscp(&aux);
        for (size_t off = 0; off < BUFFER_BYTES; off += LINE_SIZE)
            acc += probe[off];
        _mm_lfence();
        const uint64_t t3 = __rdtscp(&aux);
        cached[i] = t3 - t2;
        (void)acc;
    }

    _aligned_free(raw);

    for (int i = 0; i < ROUNDS - 1; ++i) {
        for (int j = i + 1; j < ROUNDS; ++j) {
            if (flushed[j] < flushed[i]) { const uint64_t t = flushed[i]; flushed[i] = flushed[j]; flushed[j] = t; }
            if (cached[j] < cached[i])   { const uint64_t t = cached[i];  cached[i]  = cached[j];  cached[j]  = t; }
        }
    }
    const uint64_t median_flushed = flushed[ROUNDS / 2];
    const uint64_t median_cached  = cached[ROUNDS / 2];

    bool anomaly = false;
    uint32_t flags = 0;
    if (median_flushed == 0 || median_cached == 0) {
        flags |= TIMING_FLAG_FLAT | TIMING_FLAG_ANOMALY;
        anomaly = true;
    }
    if (median_cached >= median_flushed) {
        flags |= TIMING_FLAG_ANOMALY;
        anomaly = true;
    }
    if (median_flushed > 5000000ULL) {
        flags |= TIMING_FLAG_ABSURD | TIMING_FLAG_ANOMALY;
        anomaly = true;
    }
    timing_ring_push(TIMING_KIND_CACHE_COHERENCY, flags, median_flushed, median_cached);
    return anomaly;
}

inline bool check_function_call_timing_anomaly()
{
    constexpr int CALLS = 32;
    uint64_t durations[CALLS] = {};

    for (int i = 0; i < CALLS; ++i) {
        const uint64_t pre = timing_ring_total_pushed();
        {
            function_entry_exit_rdtsc_t guard(0xA1DA0000u | static_cast<uint32_t>(i));
            volatile uint64_t spin = 0;
            for (int k = 0; k < 64; ++k)
                spin += static_cast<uint64_t>(k) * 1315423911u;
            (void)spin;
        }
        const uint64_t post = timing_ring_total_pushed();
        if (post == pre) {
            durations[i] = 0;
            continue;
        }
        auto& ring = timing_ring();
        const uint64_t idx = (post - 1ull) % TIMING_RING_CAPACITY;
        durations[i] = ring.slots[static_cast<size_t>(idx)].value_a;
    }

    for (int i = 0; i < CALLS - 1; ++i) {
        for (int j = i + 1; j < CALLS; ++j) {
            if (durations[j] < durations[i]) {
                const uint64_t tmp = durations[i];
                durations[i] = durations[j];
                durations[j] = tmp;
            }
        }
    }
    const uint64_t median = durations[CALLS / 2];
    const uint64_t lo = durations[2];
    const uint64_t hi = durations[CALLS - 3];

    const bool too_flat = (median == 0) || (hi == lo && median < 50ULL);
    const bool too_high = median > 1000000ULL;
    const uint32_t flags = (too_flat ? TIMING_FLAG_FLAT : 0u)
                         | (too_high ? TIMING_FLAG_ABSURD : 0u)
                         | ((too_flat || too_high) ? TIMING_FLAG_ANOMALY : 0u);
    timing_ring_push(TIMING_KIND_FN_ENTRY_EXIT, flags | 0x80000000u, median, hi - lo);
    return too_flat || too_high;
}

inline bool check_instrumentation_callback()
{
    if (!syscall::is_initialized()) return false;

    struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
    {
        ULONG Version;
        ULONG Reserved;
        PVOID Callback;
    } info{};

    NTSTATUS st = syscall::NtQueryInformationProcess()(
        GetCurrentProcess(), 40, &info, sizeof(info), nullptr);
    return st >= 0 && info.Callback != nullptr;
}

inline bool check_trap_flag()
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;
    return (ctx.EFlags & 0x100u) != 0;
}

inline void hide_thread_from_debugger(HANDLE thread)
{
    if (!syscall::is_initialized()) return;
    syscall::NtSetInformationThread()(thread, 0x11, nullptr, 0);
}

inline debug_report_t full_scan(uint64_t mod_base = 0, uint64_t mod_end = 0)
{
    debug_report_t report{};

    report.peb_being_debugged = check_being_debugged();
    if (report.peb_being_debugged)
        webhook::send_debug_log("peb_being_debugged", "BeingDebugged=1", true);

    report.peb_nt_global_flag = check_nt_global_flag();
    if (report.peb_nt_global_flag)
        webhook::send_debug_log("peb_nt_global_flag", "NtGlobalFlag&0x70", true);

    report.peb_heap_flags = check_heap_flags();
    if (report.peb_heap_flags)
        webhook::send_debug_log("peb_heap_flags", "ForceFlags!=0", true);

    report.debug_port = check_debug_port();
    if (report.debug_port)
        webhook::send_debug_log("debug_port", "ProcessDebugPort!=0", true);

    report.debug_object_handle = check_debug_object_handle();
    if (report.debug_object_handle)
        webhook::send_debug_log("debug_object", "DebugObjectHandle!=NULL", true);

    report.debug_flags = check_debug_flags();
    if (report.debug_flags)
        webhook::send_debug_log("debug_flags", "ProcessDebugFlags==0", true);

    report.remote_debugger = check_remote_debugger();
    if (report.remote_debugger)
        webhook::send_debug_log("remote_debugger", "CheckRemoteDebugger=TRUE", true);

    report.is_debugger_present = check_is_debugger_present();
    if (report.is_debugger_present)
        webhook::send_debug_log("is_debugger_present", "IsDebuggerPresent=TRUE", true);

    report.close_handle_trap = check_close_handle_trap();
    if (report.close_handle_trap)
        webhook::send_debug_log("close_handle_trap", "STATUS_INVALID_HANDLE", true);

    report.output_debug_string = check_output_debug_string();
    if (report.output_debug_string)
        webhook::send_debug_log("output_debug_string", "GetLastError_changed", true);

    report.hw_breakpoints_local = check_hw_breakpoints_local();
    if (report.hw_breakpoints_local)
        webhook::send_debug_log("hw_bp_local", "DR_active_local", true);

    if (mod_base != 0 && mod_end != 0)
    {
        report.hw_breakpoints_kernel = check_hw_breakpoints_kernel(mod_base, mod_end);
        if (report.hw_breakpoints_kernel)
            webhook::send_debug_log("hw_bp_kernel", "DR_in_code_range", true);
    }

    report.kernel_debugger = check_kernel_debugger();
    if (report.kernel_debugger)
        webhook::send_debug_log("kernel_debugger", "KdEnabled", true);

    report.kd_shared_data = check_kd_shared_data();
    if (report.kd_shared_data)
        webhook::send_debug_log("kd_shared_data", "KUSER_SharedData.KdDebuggerEnabled", true);

    report.thread_hidden = check_thread_hidden();
    if (report.thread_hidden)
        webhook::send_debug_log("thread_hidden", "ThreadHideFromDebugger_set", true);

    report.instrumentation_callback = check_instrumentation_callback();
    if (report.instrumentation_callback)
        webhook::send_debug_log("instrumentation_cb", "InstrumentationCallback!=NULL", true);

    report.trap_flag = check_trap_flag();
    if (report.trap_flag)
        webhook::send_debug_log("trap_flag", "EFLAGS.TF=1", true);

    report.branch_miss_flat = check_branch_miss_flat();
    if (report.branch_miss_flat)
        webhook::send_debug_log("branch_miss_flat", "kernel_timing_attack", true);

    report.page_fault_timing_anomaly = check_page_fault_timing_anomaly();
    if (report.page_fault_timing_anomaly)
        webhook::send_debug_log("pf_timing", "VirtualProtect_median_outside_native_band", true);

    report.ipi_latency_anomaly = check_ipi_latency_anomaly();
    if (report.ipi_latency_anomaly)
        webhook::send_debug_log("ipi_latency", "QueueUserAPC_cross_core_anomaly", true);

    report.cache_coherency_anomaly = check_cache_coherency_anomaly();
    if (report.cache_coherency_anomaly)
        webhook::send_debug_log("cache_coherency", "clflush_reload_profile_inverted", true);

    report.function_call_timing_anomaly = check_function_call_timing_anomaly();
    if (report.function_call_timing_anomaly)
        webhook::send_debug_log("fn_call_timing", "rdtscp_entry_exit_distribution_flat", true);

    if (report.peb_being_debugged) report.summary += "peb ";
    if (report.peb_nt_global_flag) report.summary += "ntglobal ";
    if (report.peb_heap_flags) report.summary += "heap ";
    if (report.debug_port) report.summary += "port ";
    if (report.debug_object_handle) report.summary += "dbgobj ";
    if (report.debug_flags) report.summary += "flags ";
    if (report.remote_debugger) report.summary += "remote ";
    if (report.is_debugger_present) report.summary += "isdbg ";
    if (report.close_handle_trap) report.summary += "closeh ";
    if (report.output_debug_string) report.summary += "outdbg ";
    if (report.hw_breakpoints_local) report.summary += "hwbp_l ";
    if (report.hw_breakpoints_kernel) report.summary += "hwbp_k ";
    if (report.kernel_debugger) report.summary += "kd ";
    if (report.kd_shared_data) report.summary += "kuser ";
    if (report.rdtsc_timing) report.summary += "rdtsc ";
    if (report.qpc_timing) report.summary += "qpc ";
    if (report.thread_hidden) report.summary += "thidden ";
    if (report.instrumentation_callback) report.summary += "instcb ";
    if (report.trap_flag) report.summary += "trapflag ";
    if (report.branch_miss_flat) report.summary += "brmissflat ";
    if (report.page_fault_timing_anomaly) report.summary += "pftime ";
    if (report.ipi_latency_anomaly) report.summary += "ipi ";
    if (report.cache_coherency_anomaly) report.summary += "coh ";
    if (report.function_call_timing_anomaly) report.summary += "fncall ";

    return report;
}

}
}
