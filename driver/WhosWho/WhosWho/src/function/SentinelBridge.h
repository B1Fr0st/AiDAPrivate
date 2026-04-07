#pragma once


namespace sentinel_bridge {


    constexpr ULONG BRIDGE_MAGIC   = 0x57484F53;
    constexpr ULONG BRIDGE_VERSION = 1;


    // BSOD code when Sentinel is confirmed absent — WhosWho refuses to
    // operate without its watchdog.  Distinct from all Sentinel bug-check
    // codes so the crash dump makes the root cause immediately obvious.
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


    // ── Watchdog state ──────────────────────────────────────────────
    //
    // A periodic DPC fires every 10 seconds and reads g_bridge.sentinel_tsc.
    // If Sentinel is alive it stamps that field via its own DPC on every 3-second
    // guardian tick, so the value will always advance between our checks.
    //
    // Grace period:  The first 90 seconds after start_watchdog() are grace —
    //                Sentinel may still be loading, mapping, or initializing.
    //                No enforcement during this window.
    //
    // After grace:   If sentinel_tsc has not changed for SENTINEL_TIMEOUT_MS
    //                (30 seconds = 3 consecutive DPC firings), Sentinel is dead
    //                and we bug-check.

    constexpr LONG WATCHDOG_PERIOD_MS    = 10000;   // DPC fires every 10 s
    constexpr LONG GRACE_PERIOD_MS       = 90000;   // 90 s initial grace
    constexpr LONG SENTINEL_TIMEOUT_MS   = 30000;   // 30 s stale → BSOD

    inline KTIMER  g_watchdog_timer  = {};
    inline KDPC    g_watchdog_dpc    = {};
    inline volatile LONG64  g_last_seen_sentinel_tsc = 0;
    inline volatile LONG    g_stale_streak           = 0;
    inline volatile LONG64  g_watchdog_start_qpc     = 0;
    inline volatile LONG    g_watchdog_active        = 0;


    // Called at DISPATCH_LEVEL by the kernel timer subsystem.
    inline VOID NTAPI watchdog_dpc_callback(
        PKDPC  /*Dpc*/,
        PVOID  /*DeferredContext*/,
        PVOID  /*SystemArgument1*/,
        PVOID  /*SystemArgument2*/)
    {
        if (!_InterlockedCompareExchange(&g_watchdog_active, 0, 0))
            return;

        // ── Grace period check ──
        // Use __rdtsc for a monotonic, lock-free timestamp.  Approximate
        // conversion: modern CPUs run 2.5-3.5 GHz, so 90 s ≈ 225-315 billion
        // ticks.  We use a conservative 2 GHz estimate (180 billion ticks)
        // to avoid cutting grace short on slower clocks.
        constexpr LONG64 TSC_PER_MS_LOW = 2000000LL;            // 2 GHz floor
        constexpr LONG64 GRACE_TSC      = static_cast<LONG64>(GRACE_PERIOD_MS) * TSC_PER_MS_LOW;

        LONG64 now_tsc  = static_cast<LONG64>(__rdtsc());
        LONG64 start    = _InterlockedCompareExchange64(&g_watchdog_start_qpc, 0, 0);
        LONG64 elapsed  = now_tsc - start;

        if (elapsed < GRACE_TSC)
            return;   // still in grace window — do nothing

        // ── Read Sentinel's heartbeat TSC ──
        LONG64 current_sentinel_tsc = _InterlockedCompareExchange64(
            &g_bridge.sentinel_tsc, 0, 0);

        LONG64 last = _InterlockedCompareExchange64(
            &g_last_seen_sentinel_tsc, 0, 0);

        if (current_sentinel_tsc != last) {
            // Sentinel is alive — reset streak and remember new value
            _InterlockedExchange64(&g_last_seen_sentinel_tsc, current_sentinel_tsc);
            _InterlockedExchange(&g_stale_streak, 0);
            return;
        }

        // sentinel_tsc unchanged since last DPC — increment streak
        LONG streak = _InterlockedIncrement(&g_stale_streak);

        // 3 consecutive stale checks × 10 s period = 30 s without update
        constexpr LONG STALE_THRESHOLD = SENTINEL_TIMEOUT_MS / WATCHDOG_PERIOD_MS;

        if (streak >= STALE_THRESHOLD) {
            // Sentinel is confirmed dead.  BSOD with descriptive parameters:
            //   P1 = last sentinel_tsc we saw
            //   P2 = current (stale) sentinel_tsc
            //   P3 = elapsed TSC ticks since watchdog start
            //   P4 = stale streak count
            _KeBugCheckEx(
                BUGCHECK_SENTINEL_ABSENT,
                static_cast<ULONG_PTR>(last),
                static_cast<ULONG_PTR>(current_sentinel_tsc),
                static_cast<ULONG_PTR>(elapsed),
                static_cast<ULONG_PTR>(streak));
        }
    }


    __forceinline void init(PVOID text_base, ULONG text_size) {
        g_bridge.code_base = text_base;
        g_bridge.code_size = text_size;
    }


    __forceinline void tick() {
        _InterlockedExchange64(&g_bridge.whoswho_tsc, static_cast<LONG64>(__rdtsc()));
    }


    // Call once from DriverEntry (PASSIVE_LEVEL) after init().
    // Starts the periodic DPC that enforces Sentinel's presence.
    __forceinline void start_watchdog() {
        if (_InterlockedCompareExchange(&g_watchdog_active, 1, 0) != 0)
            return;   // already started

        // Snapshot TSC at start so grace period is measured from now
        _InterlockedExchange64(&g_watchdog_start_qpc, static_cast<LONG64>(__rdtsc()));

        // Seed last-seen with current value so the first real check
        // after grace compares against an up-to-date baseline
        _InterlockedExchange64(&g_last_seen_sentinel_tsc,
            _InterlockedCompareExchange64(&g_bridge.sentinel_tsc, 0, 0));

        _InterlockedExchange(&g_stale_streak, 0);

        _KeInitializeTimerEx(&g_watchdog_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_watchdog_dpc, watchdog_dpc_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(WATCHDOG_PERIOD_MS) * 10000LL;  // relative, 100-ns units

        _KeSetTimerEx(&g_watchdog_timer, due_time, WATCHDOG_PERIOD_MS, &g_watchdog_dpc);
    }
}
