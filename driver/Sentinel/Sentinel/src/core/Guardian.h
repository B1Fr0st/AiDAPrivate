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
        if (integrity::g_integrity_strikes >= integrity::INTEGRITY_STRIKE_THRESHOLD) {
            heartbeat::send_command(heartbeat::BRIDGE_CMD_INTEGRITY_FAIL,
                static_cast<ULONG>(integrity::g_integrity_strikes));
        }


        dispatch_guard::verify();


        if ((cycle % 5) == 0) {
            SN_LOG("guardian::dpc: IPI clear (cycle %ld)", cycle);
            thread_guard::ipi_clear_all_cpus();
        }


        SN_LOG("guardian::dpc: calling heartbeat::update_and_check (bridge=%p init=%ld)",
            heartbeat::g_bridge, heartbeat::g_initialized);
        heartbeat::update_and_check();


        etw_disable::monitor_reenablement();
        if (etw_disable::g_provider_handle && _MmIsAddressValid((PVOID)etw_disable::g_provider_handle)) {
            __try {
                volatile UINT64 val = *static_cast<volatile UINT64*>((PVOID)etw_disable::g_provider_handle);
                if (val != 0) {
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_ETW_REACTIVATED, 0);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }


        if ((cycle % 5) == 0) {
            callback_scanner::verify();
        }


        if ((cycle % 10) == 0) {
            pool_scrub::periodic_scrub();
        }

        if ((cycle % 3) == 0) {
            object_guard::scan_suspicious_handles();
        }

        if ((cycle % 7) == 0) {
            if (!heartbeat::verify_module_presence()) {
                SN_LOG("guardian::dpc: WhosWho UNLOADED from module list!");
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(0xDEAD5E07, 0, 0, 0, static_cast<ULONG_PTR>(cycle));
                }
            }
        }

        if ((cycle % 6) == 0) {
            heartbeat::verify_challenge_response();
            heartbeat::issue_challenge();
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
