#pragma once
#include <imports/Defs.h>

namespace targeting_latch {

    constexpr ULONG BUGCHECK_RE_TARGETING_CONFIRMED = 0xDEADDEADu;

    constexpr ULONG RE_REASON_DR_ON_TEXT        = 0x0000D7D7u;
    constexpr ULONG RE_REASON_OB_WRITE          = 0x0000AB01u;
    constexpr ULONG RE_REASON_OB_CREATE_THREAD  = 0x0000AB02u;
    constexpr ULONG RE_REASON_OB_SUSPEND        = 0x0000AB03u;
    constexpr ULONG RE_REASON_DEBUG_PORT_TRAP   = 0x0000AB04u;
    constexpr ULONG RE_REASON_DMA_CANARY        = 0x00005E43u;
    constexpr ULONG RE_REASON_TEXT_WRITABLE     = 0x0000D7ECu;
    constexpr ULONG RE_REASON_HEADER_RESTORE     = 0x0000D7EDu;
    constexpr ULONG RE_REASON_TEXT_PAGE_ACCESSED = 0x0000D7EEu;

    inline volatile LONG   g_targeting_confirmed = 0;
    inline KTIMER          g_latch_timer = {};
    inline KDPC            g_latch_dpc = {};
    inline volatile ULONG  g_latch_reason = 0;
    inline volatile UINT64 g_latch_evidence[4] = {};
    inline volatile LONG   g_timer_initialized = 0;

    static VOID NTAPI latch_dpc_callback(PKDPC, PVOID, PVOID, PVOID)
    {
        ULONG  reason = g_latch_reason;
        UINT64 e0 = g_latch_evidence[0];
        UINT64 e1 = g_latch_evidence[1];
        UINT64 e2 = g_latch_evidence[2];
        UINT64 e3 = g_latch_evidence[3];
        (void)e3;

        if (_KeBugCheckEx) {
            _KeBugCheckEx(
                BUGCHECK_RE_TARGETING_CONFIRMED,
                (ULONG_PTR)reason,
                (ULONG_PTR)e0,
                (ULONG_PTR)e1,
                (ULONG_PTR)e2
            );
        }
    }

    __forceinline void init()
    {
        if (!_KeInitializeTimerEx || !_KeInitializeDpc)
            return;

        _KeInitializeTimerEx(&g_latch_timer, NotificationTimer);
        _KeInitializeDpc(&g_latch_dpc, latch_dpc_callback, nullptr);
        _InterlockedExchange(&g_timer_initialized, 1);
    }

    __forceinline void latch_targeting(ULONG reason, UINT64 e0, UINT64 e1, UINT64 e2, UINT64 e3)
    {
        if (!_InterlockedCompareExchange(&g_timer_initialized, 1, 1))
            return;

        if (_InterlockedCompareExchange(&g_targeting_confirmed, 1, 0) != 0)
            return;

        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_latch_reason),
            static_cast<LONG>(reason));
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_latch_evidence[0]),
            static_cast<LONG64>(e0));
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_latch_evidence[1]),
            static_cast<LONG64>(e1));
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_latch_evidence[2]),
            static_cast<LONG64>(e2));
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_latch_evidence[3]),
            static_cast<LONG64>(e3));

        ULONG seed = (ULONG)(__rdtsc() & 0xFFFFFFFF);
        ULONG rnd = RtlRandomEx(&seed);
        ULONG delay_sec = 45u + (rnd % 136u);
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)delay_sec * 10000000LL;

        if (_KeSetTimerEx) {
            _KeSetTimerEx(&g_latch_timer, due, 0, &g_latch_dpc);
        }
    }
}
