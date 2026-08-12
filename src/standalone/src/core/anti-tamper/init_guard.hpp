#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>

#include "state.hpp"
#include "webhook.hpp"
#include "../../helpers/diag_log.hpp"

namespace anti_tamper {
namespace init_guard {

inline std::atomic<bool> g_in_progress{false};
inline std::atomic<uint32_t> g_owner_pid{0};
inline std::atomic<uint32_t> g_owner_tid{0};
inline std::atomic<uint64_t> g_generation{0};
inline std::atomic<uint64_t> g_active_generation{0};
inline std::atomic<uint64_t> g_started_ms{0};
inline std::atomic<uint64_t> g_phase_ms{0};
inline std::atomic<const char*> g_phase{"idle"};

inline uint64_t now_ms()
{
    return static_cast<uint64_t>(GetTickCount64());
}

inline const char* phase()
{
    const char* p = g_phase.load(std::memory_order_acquire);
    return p ? p : "<null>";
}

inline bool owner_is_current_thread()
{
    return g_in_progress.load(std::memory_order_acquire) &&
        g_owner_pid.load(std::memory_order_acquire) == GetCurrentProcessId() &&
        g_owner_tid.load(std::memory_order_acquire) == GetCurrentThreadId();
}

inline void set_phase(const char* value)
{
    const uint64_t now = now_ms();
    g_phase.store(value && *value ? value : "<empty>", std::memory_order_release);
    g_phase_ms.store(now, std::memory_order_release);
    webhook::write_log_critical_fmt("init",
        "initialize_phase phase=%s gen=%llu pid=%lu tid=%lu elapsed_ms=%llu",
        phase(),
        static_cast<unsigned long long>(g_active_generation.load(std::memory_order_acquire)),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(now - g_started_ms.load(std::memory_order_acquire)));
}

inline bool begin(const char* caller)
{
    bool expected = false;
    if (!g_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
        return false;

    const uint64_t now = now_ms();
    const uint64_t gen = g_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    g_active_generation.store(gen, std::memory_order_release);
    g_owner_pid.store(GetCurrentProcessId(), std::memory_order_release);
    g_owner_tid.store(GetCurrentThreadId(), std::memory_order_release);
    g_started_ms.store(now, std::memory_order_release);
    g_phase_ms.store(now, std::memory_order_release);
    g_phase.store(caller && *caller ? caller : "initialize", std::memory_order_release);
    webhook::write_log_critical_fmt("init",
        "initialize_guard_begin caller=%s gen=%llu pid=%lu tid=%lu tick=%llu initialized=%d violation=%d driver_hardening=%d hardening_active=%d",
        caller && *caller ? caller : "<null>",
        static_cast<unsigned long long>(gen),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(now),
        state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
        state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0);
    return true;
}

inline void finish(const char* outcome, bool ok)
{
    const uint64_t now = now_ms();
    webhook::write_log_critical_fmt("init",
        "initialize_guard_finish outcome=%s ok=%d gen=%llu owner_pid=%u owner_tid=%u caller_pid=%lu caller_tid=%lu elapsed_ms=%llu phase=%s phase_age_ms=%llu initialized=%d violation=%d driver_hardening=%d hardening_active=%d",
        outcome && *outcome ? outcome : "<null>",
        ok ? 1 : 0,
        static_cast<unsigned long long>(g_active_generation.load(std::memory_order_acquire)),
        g_owner_pid.load(std::memory_order_acquire),
        g_owner_tid.load(std::memory_order_acquire),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(now - g_started_ms.load(std::memory_order_acquire)),
        phase(),
        static_cast<unsigned long long>(now - g_phase_ms.load(std::memory_order_acquire)),
        state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
        state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0);
    g_owner_pid.store(0, std::memory_order_release);
    g_owner_tid.store(0, std::memory_order_release);
    g_phase.store(ok ? "complete" : "failed", std::memory_order_release);
    g_phase_ms.store(now, std::memory_order_release);
    g_in_progress.store(false, std::memory_order_release);
}

inline bool wait_for_completion(const char* caller, uint64_t timeout_ms)
{
    const uint64_t started = now_ms();
    const uint32_t owner_pid = g_owner_pid.load(std::memory_order_acquire);
    const uint32_t owner_tid = g_owner_tid.load(std::memory_order_acquire);
    const uint64_t owner_started = g_started_ms.load(std::memory_order_acquire);
    const uint64_t gen = g_active_generation.load(std::memory_order_acquire);
    webhook::write_log_critical_fmt("init",
        "initialize_guard_wait_begin caller=%s gen=%llu caller_pid=%lu caller_tid=%lu owner_pid=%u owner_tid=%u owner_age_ms=%llu phase=%s initialized=%d violation=%d",
        caller && *caller ? caller : "<null>",
        static_cast<unsigned long long>(gen),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        owner_pid,
        owner_tid,
        static_cast<unsigned long long>(started - owner_started),
        phase(),
        state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
        state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0);

    if (owner_is_current_thread())
    {
        webhook::write_log_critical_fmt("init",
            "initialize_guard_wait_reentrant_same_thread caller=%s gen=%llu owner_pid=%u owner_tid=%u phase=%s initialized=%d violation=%d",
            caller && *caller ? caller : "<null>",
            static_cast<unsigned long long>(gen),
            owner_pid,
            owner_tid,
            phase(),
            state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
            state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0);
        return state::get().initialized.load(std::memory_order_acquire);
    }

    const uint64_t checkpoints[] = { 1000ULL, 5000ULL, 15000ULL, 30000ULL, 60000ULL, 90000ULL };
    size_t checkpoint_index = 0;
    while (g_in_progress.load(std::memory_order_acquire))
    {
        const uint64_t now = now_ms();
        const uint64_t elapsed = now - started;
        while (checkpoint_index < sizeof(checkpoints) / sizeof(checkpoints[0]) && elapsed >= checkpoints[checkpoint_index])
        {
            webhook::write_log_critical_fmt("init",
                "initialize_guard_wait_progress caller=%s gen=%llu elapsed_ms=%llu owner_pid=%u owner_tid=%u owner_age_ms=%llu phase=%s phase_age_ms=%llu initialized=%d violation=%d driver_hardening=%d hardening_active=%d",
                caller && *caller ? caller : "<null>",
                static_cast<unsigned long long>(g_active_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(elapsed),
                g_owner_pid.load(std::memory_order_acquire),
                g_owner_tid.load(std::memory_order_acquire),
                static_cast<unsigned long long>(now - g_started_ms.load(std::memory_order_acquire)),
                phase(),
                static_cast<unsigned long long>(now - g_phase_ms.load(std::memory_order_acquire)),
                state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
                state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
                state::get().driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
                state::get().driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0);
            ++checkpoint_index;
        }
        if (elapsed >= timeout_ms)
        {
            webhook::write_log_critical_fmt("init",
                "initialize_guard_wait_timeout caller=%s gen=%llu timeout_ms=%llu owner_pid=%u owner_tid=%u phase=%s initialized=%d violation=%d",
                caller && *caller ? caller : "<null>",
                static_cast<unsigned long long>(g_active_generation.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(timeout_ms),
                g_owner_pid.load(std::memory_order_acquire),
                g_owner_tid.load(std::memory_order_acquire),
                phase(),
                state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
                state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0);
            return state::get().initialized.load(std::memory_order_acquire);
        }
        Sleep(25);
    }

    const bool initialized = state::get().initialized.load(std::memory_order_acquire);
    webhook::write_log_critical_fmt("init",
        "initialize_guard_wait_done caller=%s gen=%llu elapsed_ms=%llu initialized=%d violation=%d driver_hardening=%d",
        caller && *caller ? caller : "<null>",
        static_cast<unsigned long long>(gen),
        static_cast<unsigned long long>(now_ms() - started),
        initialized ? 1 : 0,
        state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0);
    return initialized;
}

inline void mark_seh_abort(uint32_t code, const char* boundary)
{
    const uint64_t now = now_ms();
    const bool active = g_in_progress.load(std::memory_order_acquire);
    const uint32_t owner_pid = g_owner_pid.load(std::memory_order_acquire);
    const uint32_t owner_tid = g_owner_tid.load(std::memory_order_acquire);
    const bool owner_current =
        owner_pid == GetCurrentProcessId() &&
        owner_tid == GetCurrentThreadId();
    webhook::write_log_critical_fmt("init",
        "initialize_guard_seh_abort boundary=%s code=0x%08X active=%d owner_current=%d gen=%llu owner_pid=%u owner_tid=%u caller_pid=%lu caller_tid=%lu elapsed_ms=%llu phase=%s phase_age_ms=%llu initialized=%d violation=%d driver_hardening=%d hardening_active=%d",
        boundary && *boundary ? boundary : "<null>",
        code,
        active ? 1 : 0,
        owner_current ? 1 : 0,
        static_cast<unsigned long long>(g_active_generation.load(std::memory_order_acquire)),
        owner_pid,
        owner_tid,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(now - g_started_ms.load(std::memory_order_acquire)),
        phase(),
        static_cast<unsigned long long>(now - g_phase_ms.load(std::memory_order_acquire)),
        state::get().initialized.load(std::memory_order_acquire) ? 1 : 0,
        state::get().violation_latched.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_done.load(std::memory_order_acquire) ? 1 : 0,
        state::get().driver_hardening_active.load(std::memory_order_acquire) ? 1 : 0);
    if (!active || !owner_current)
        return;
    g_owner_pid.store(0, std::memory_order_release);
    g_owner_tid.store(0, std::memory_order_release);
    g_phase.store("seh_abort", std::memory_order_release);
    g_phase_ms.store(now, std::memory_order_release);
    g_in_progress.store(false, std::memory_order_release);
}

}
}
