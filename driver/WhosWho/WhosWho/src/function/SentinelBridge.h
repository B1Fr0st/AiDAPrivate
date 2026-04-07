#pragma once


namespace sentinel_bridge {


    constexpr ULONG BRIDGE_MAGIC   = 0x57484F53;
    constexpr ULONG BRIDGE_VERSION = 1;


    constexpr ULONG BUGCHECK_SENTINEL_ABSENT = 0xDEAD5E10;


    struct bridge_t {
        volatile ULONG   magic;
        volatile ULONG   version;
        volatile PVOID   code_base;
        volatile ULONG   code_size;
        volatile LONG64  whoswho_tsc;
        volatile LONG64  sentinel_tsc;
    };


    inline bridge_t g_bridge = {
        BRIDGE_MAGIC,
        BRIDGE_VERSION,
        nullptr,
        0,
        0,
        0
    };


    // Decreased the watchdog period from 10000ms to 3000ms to guarantee 
    // we update our heartbeat TSC more frequently than Sentinel's timeout,
    // safely accommodating high-frequency / Turbo-Boost CPU scaling scenarios.
    constexpr LONG WATCHDOG_PERIOD_MS    = 3000;
    constexpr LONG GRACE_PERIOD_MS       = 90000;
    constexpr LONG SENTINEL_TIMEOUT_MS   = 30000;

    inline KTIMER  g_watchdog_timer  = {};
    inline KDPC    g_watchdog_dpc    = {};
    inline volatile LONG64  g_last_seen_sentinel_tsc = 0;
    inline volatile LONG    g_stale_streak           = 0;
    inline volatile LONG64  g_watchdog_start_qpc     = 0;
    inline volatile LONG    g_watchdog_active        = 0;


    // Relocated the tick() prototype above the DPC routine so it can be 
    // autonomously fired by the kernel without requiring forward-declarations.
    __forceinline void tick() {
        _InterlockedExchange64(&g_bridge.whoswho_tsc, static_cast<LONG64>(__rdtsc()));
    }

    inline VOID NTAPI watchdog_dpc_callback(
        PKDPC  ,
        PVOID  ,
        PVOID  ,
        PVOID  )
    {
        if (!_InterlockedCompareExchange(&g_watchdog_active, 0, 0))
            return;

        // Periodically update the TSC so Sentinel knows WhosWho is alive
        // independently of the user-mode application's heartbeat IOCTLs.
        // This prevents bugcheck 0xDEAD5E05 when the UM app exits.
        tick();

        constexpr LONG64 TSC_PER_MS_LOW = 2000000LL;
        constexpr LONG64 GRACE_TSC      = static_cast<LONG64>(GRACE_PERIOD_MS) * TSC_PER_MS_LOW;

        LONG64 now_tsc  = static_cast<LONG64>(__rdtsc());
        LONG64 start    = _InterlockedCompareExchange64(&g_watchdog_start_qpc, 0, 0);
        LONG64 elapsed  = now_tsc - start;

        if (elapsed < GRACE_TSC) {
            return;
        }

        LONG64 current_sentinel_tsc = _InterlockedCompareExchange64(
            &g_bridge.sentinel_tsc, 0, 0);

        LONG64 last = _InterlockedCompareExchange64(
            &g_last_seen_sentinel_tsc, 0, 0);

        if (current_sentinel_tsc != last) {
            // Sentinel is alive
            _InterlockedExchange64(&g_last_seen_sentinel_tsc, current_sentinel_tsc);
            _InterlockedExchange(&g_stale_streak, 0);
            return;
        }

        // Sentinel is dead
        LONG streak = _InterlockedIncrement(&g_stale_streak);

        constexpr LONG STALE_THRESHOLD = SENTINEL_TIMEOUT_MS / WATCHDOG_PERIOD_MS;

        if (streak >= STALE_THRESHOLD) {
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    BUGCHECK_SENTINEL_ABSENT,
                    static_cast<ULONG_PTR>(last),
                    static_cast<ULONG_PTR>(current_sentinel_tsc),
                    static_cast<ULONG_PTR>(elapsed),
                    static_cast<ULONG_PTR>(streak));
            }
        }
    }


    __forceinline void init(PVOID text_base, ULONG text_size) {
        g_bridge.code_base = text_base;
        g_bridge.code_size = text_size;
    }


    __forceinline void start_watchdog() {
        if (_InterlockedCompareExchange(&g_watchdog_active, 1, 0) != 0)
            return;

        _InterlockedExchange64(&g_watchdog_start_qpc, static_cast<LONG64>(__rdtsc()));

        
        _InterlockedExchange64(&g_last_seen_sentinel_tsc,
            _InterlockedCompareExchange64(&g_bridge.sentinel_tsc, 0, 0));

        _InterlockedExchange(&g_stale_streak, 0);

        _KeInitializeTimerEx(&g_watchdog_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_watchdog_dpc, watchdog_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(WATCHDOG_PERIOD_MS) * 10000LL;

        _KeSetTimerEx(&g_watchdog_timer, due_time, WATCHDOG_PERIOD_MS, &g_watchdog_dpc);
    }
}