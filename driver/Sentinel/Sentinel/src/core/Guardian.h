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


    constexpr LONG64 CHECK_INTERVAL = -30'000'000LL;

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


        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0)
            return;

        LONG cycle = _InterlockedIncrement(&g_cycle_count);


        self_protect::verify_own_integrity();


        integrity::verify();


        dispatch_guard::verify();


        thread_guard::ipi_clear_all_cpus();


        heartbeat::update_and_check();


        etw_disable::monitor_reenablement();


        if ((cycle % 5) == 0) {
            callback_scanner::verify();
        }


        if ((cycle % 10) == 0) {
            pool_scrub::periodic_scrub();
        }

        _InterlockedExchange(&g_running, 0);
    }


    __forceinline bool start() {
        if (!_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx) {
            return false;
        }


        _KeInitializeTimerEx(&g_timer, NotificationTimer);
        _KeInitializeDpc(&g_dpc, dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = CHECK_INTERVAL;


        BOOLEAN ok = _KeSetTimerEx(&g_timer, due_time, 3000, &g_dpc);

        _InterlockedExchange(&g_timer_active, 1);
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
