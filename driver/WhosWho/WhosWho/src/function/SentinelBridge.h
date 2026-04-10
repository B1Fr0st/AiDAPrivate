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


    constexpr LONG WATCHDOG_PERIOD_MS    = 10000;
    constexpr LONG GRACE_PERIOD_MS       = 90000;
    constexpr LONG SENTINEL_TIMEOUT_MS   = 60000;

    inline KTIMER  g_watchdog_timer  = {};
    inline KDPC    g_watchdog_dpc    = {};
    inline volatile LONG64  g_last_seen_sentinel_tsc = 0;
    inline volatile LONG    g_stale_streak           = 0;
    inline volatile LONG64  g_watchdog_start_qpc     = 0;
    inline volatile LONG    g_watchdog_active        = 0;


    __forceinline void tick() {
        LONG64 tsc = static_cast<LONG64>(__rdtsc());
        _InterlockedExchange64(&g_bridge.whoswho_tsc, tsc);
        WW_LOG("tick: wrote whoswho_tsc=%lld", tsc);
    }

    inline VOID NTAPI watchdog_dpc_callback(
        PKDPC  ,
        PVOID  ,
        PVOID  ,
        PVOID  )
    {
        if (!_InterlockedCompareExchange(&g_watchdog_active, 0, 0)) {
            WW_LOG("watchdog_dpc: NOT active, returning");
            return;
        }

        tick();

        constexpr LONG64 TSC_PER_MS_LOW = 2000000LL;
        constexpr LONG64 GRACE_TSC      = static_cast<LONG64>(GRACE_PERIOD_MS) * TSC_PER_MS_LOW;

        LONG64 now_tsc  = static_cast<LONG64>(__rdtsc());
        LONG64 start    = _InterlockedCompareExchange64(&g_watchdog_start_qpc, 0, 0);
        LONG64 elapsed  = now_tsc - start;

        WW_LOG("watchdog_dpc: now_tsc=%lld start=%lld elapsed=%lld grace_tsc=%lld",
            now_tsc, start, elapsed, GRACE_TSC);

        if (elapsed < GRACE_TSC) {
            WW_LOG("watchdog_dpc: still in grace period (%lld < %lld), skipping",
                elapsed, GRACE_TSC);
            return;
        }

        LONG64 current_sentinel_tsc = _InterlockedCompareExchange64(
            &g_bridge.sentinel_tsc, 0, 0);

        LONG64 last = _InterlockedCompareExchange64(
            &g_last_seen_sentinel_tsc, 0, 0);

        WW_LOG("watchdog_dpc: sentinel_tsc=%lld last_seen=%lld bridge_addr=%p",
            current_sentinel_tsc, last, &g_bridge);

        if (current_sentinel_tsc != last) {
            _InterlockedExchange64(&g_last_seen_sentinel_tsc, current_sentinel_tsc);
            _InterlockedExchange(&g_stale_streak, 0);
            WW_LOG("watchdog_dpc: Sentinel ALIVE, tsc changed from %lld to %lld",
                last, current_sentinel_tsc);
            return;
        }

        LONG streak = _InterlockedIncrement(&g_stale_streak);

        constexpr LONG STALE_THRESHOLD = SENTINEL_TIMEOUT_MS / WATCHDOG_PERIOD_MS;

        WW_LOG("watchdog_dpc: Sentinel STALE! streak=%ld threshold=%ld sentinel_tsc=%lld last_seen=%lld",
            streak, STALE_THRESHOLD, current_sentinel_tsc, last);

        if (streak >= STALE_THRESHOLD) {
            WW_LOG("watchdog_dpc: BUGCHECK! streak=%ld >= threshold=%ld, sentinel_tsc=%lld, last=%lld, elapsed=%lld",
                streak, STALE_THRESHOLD, current_sentinel_tsc, last, elapsed);
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
        WW_LOG("bridge::init: code_base=%p code_size=0x%lx bridge_addr=%p magic=0x%lx version=%lu",
            text_base, text_size, &g_bridge, g_bridge.magic, g_bridge.version);
    }


    __forceinline void start_watchdog() {
        if (_InterlockedCompareExchange(&g_watchdog_active, 1, 0) != 0) {
            WW_LOG("start_watchdog: already active, skipping");
            return;
        }

        _InterlockedExchange64(&g_watchdog_start_qpc, static_cast<LONG64>(__rdtsc()));

        LONG64 initial_sentinel_tsc = _InterlockedCompareExchange64(&g_bridge.sentinel_tsc, 0, 0);
        _InterlockedExchange64(&g_last_seen_sentinel_tsc, initial_sentinel_tsc);

        _InterlockedExchange(&g_stale_streak, 0);

        _KeInitializeTimerEx(&g_watchdog_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_watchdog_dpc, watchdog_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(WATCHDOG_PERIOD_MS) * 10000LL;

        _KeSetTimerEx(&g_watchdog_timer, due_time, WATCHDOG_PERIOD_MS, &g_watchdog_dpc);

        WW_LOG("start_watchdog: armed, period=%ldms grace=%ldms timeout=%ldms initial_sentinel_tsc=%lld bridge=%p",
            WATCHDOG_PERIOD_MS, GRACE_PERIOD_MS, SENTINEL_TIMEOUT_MS,
            initial_sentinel_tsc, &g_bridge);
    }
}
