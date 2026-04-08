#pragma once
#include <core/SelfProtect.h>
#include <core/Integrity.h>
#include <core/DispatchGuard.h>
#include <core/ThreadGuard.h>
#include <core/Heartbeat.h>
#include <core/EtwDisable.h>
#include <core/CallbackScanner.h>
#include <core/PoolScrub.h>
#include <core/ObjectGuard.h>


namespace guardian {

    // Increased from 3 seconds (-30'000'000) to 10 seconds.
    // 3s was far too aggressive — the DPC callback does CRC32 over megabytes,
    // IPI broadcasts to all CPUs, module list walks, and pattern scans.
    // 10s is the industry standard for periodic integrity checks and still
    // detects tampering well within any practical attack window.
    constexpr LONG64 CHECK_INTERVAL = -100'000'000LL;

    inline KTIMER       g_timer = {};
    inline KDPC         g_dpc = {};
    inline volatile LONG g_cycle_count = 0;
    inline volatile LONG g_running = 0;
    inline volatile LONG g_timer_active = 0;


    static void NTAPI dpc_callback(
        PKDPC ,
        PVOID ,
        PVOID ,
        PVOID )
    {


        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) {
            SN_LOG("guardian::dpc: SKIP (already running)");
            return;
        }

        LONG cycle = _InterlockedIncrement(&g_cycle_count);
        SN_LOG("guardian::dpc: cycle=%ld", cycle);


        self_protect::verify_own_integrity();


        integrity::verify();


        dispatch_guard::verify();

        // IPI broadcast moved from every tick to every 5th tick.
        // KeIpiGenericCall interrupts ALL CPU cores simultaneously, forcing
        // context switches on every core. On an 8-core machine that was
        // 8 forced interrupts × 20 ticks/min = 160 cross-core disruptions/min.
        // At every 5th tick (50s effective), this drops to ~10/min while still
        // clearing hardware breakpoints faster than useful data can be extracted.
        if ((cycle % 5) == 0) {
            SN_LOG("guardian::dpc: IPI clear (cycle %ld)", cycle);
            thread_guard::ipi_clear_all_cpus();
        }


        SN_LOG("guardian::dpc: calling heartbeat::update_and_check (bridge=%p init=%ld)",
            heartbeat::g_bridge, heartbeat::g_initialized);
        heartbeat::update_and_check();


        etw_disable::monitor_reenablement();


        if ((cycle % 5) == 0) {
            callback_scanner::verify();
        }


        if ((cycle % 10) == 0) {
            pool_scrub::periodic_scrub();
        }

        _InterlockedExchange(&g_running, 0);
        SN_LOG("guardian::dpc: cycle=%ld done", cycle);
    }


    __forceinline bool start() {
        SN_LOG("guardian::start: checking function pointers");
        if (!_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx) {
            SN_LOG("guardian::start: FAIL - missing function pointers: dpc=%p timer=%p settimer=%p",
                _KeInitializeDpc, _KeInitializeTimerEx, _KeSetTimerEx);
            return false;
        }


        _KeInitializeTimerEx(&g_timer, NotificationTimer);
        _KeInitializeDpc(&g_dpc, dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = CHECK_INTERVAL;

        // Timer period increased from 3000ms to 10000ms to match CHECK_INTERVAL.
        // Cuts DPC firing rate from 20/min to 6/min (3.3x reduction).
        _KeSetTimerEx(&g_timer, due_time, 10000, &g_dpc);

        _InterlockedExchange(&g_timer_active, 1);
        SN_LOG("guardian::start: SUCCESS - timer active, interval=%lld period=10000ms", CHECK_INTERVAL);
        return true;
    }


    __forceinline void stop() {
        if (!_InterlockedCompareExchange(&g_timer_active, 0, 1))
            return;

        if (_KeCancelTimer)
            _KeCancelTimer(&g_timer);


        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
    }
}
