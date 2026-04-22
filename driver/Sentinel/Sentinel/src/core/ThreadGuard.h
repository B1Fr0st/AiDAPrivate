#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>


namespace thread_guard {

    inline volatile UINT64 g_target_base = 0;
    inline volatile UINT64 g_target_size = 0;
    inline volatile LONG   g_initialized = 0;


    inline volatile LONG   g_targeted_debug_strikes = 0;
    constexpr LONG         STRIKE_THRESHOLD = 10;

    __forceinline bool init(UINT64 target_base, UINT64 target_size) {
        SN_LOG("thread_guard::init: target_base=%p target_size=0x%llx", (PVOID)target_base, target_size);
        if (!target_base || !target_size) {
            SN_LOG("thread_guard::init: FAIL - null base or zero size");
            return false;
        }

        g_target_base = target_base;
        g_target_size = target_size;
        _InterlockedExchange(&g_initialized, 1);
        SN_LOG("thread_guard::init: SUCCESS");
        return true;
    }


    __forceinline ULONG_PTR NTAPI ipi_clear_callback(ULONG_PTR Context) {
        UNREFERENCED_PARAMETER(Context);


        UINT64 dr0 = __readdr(0);
        UINT64 dr1 = __readdr(1);
        UINT64 dr2 = __readdr(2);
        UINT64 dr3 = __readdr(3);

        UINT64 base = g_target_base;
        UINT64 end  = base + g_target_size;

        volatile LONG* flag = (volatile LONG*)Context;


        if (base && end > base) {
            if ((dr0 >= base && dr0 < end) ||
                (dr1 >= base && dr1 < end) ||
                (dr2 >= base && dr2 < end) ||
                (dr3 >= base && dr3 < end)) {
                if (flag)
                    _InterlockedExchange(flag, 1);
            }
        }


        __writedr(0, 0);
        __writedr(1, 0);
        __writedr(2, 0);
        __writedr(3, 0);
        __writedr(7, 0);

        return 0;
    }


    __forceinline void clear_debug_registers_current_cpu() {
        __writedr(0, 0);
        __writedr(1, 0);
        __writedr(2, 0);
        __writedr(3, 0);
        __writedr(7, 0);
    }


    __forceinline bool ipi_clear_all_cpus() {
        if (!_InterlockedCompareExchange(&g_initialized, 1, 1)) {
            SN_LOG("thread_guard::ipi_clear: not initialized, skip");
            return true;
        }

        if (!_KeIpiGenericCall) {
            SN_LOG("thread_guard::ipi_clear: no _KeIpiGenericCall");
            return true;
        }

        volatile LONG targeted_debug_detected = 0;

        __try {
            _KeIpiGenericCall(
                (PKIPI_BROADCAST_WORKER)ipi_clear_callback,
                (ULONG_PTR)&targeted_debug_detected
            );
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("thread_guard::ipi_clear: EXCEPTION in IPI call");

            clear_debug_registers_current_cpu();
            return true;
        }

        if (_InterlockedCompareExchange(&targeted_debug_detected, 0, 0) != 0) {

            LONG strikes = _InterlockedIncrement(&g_targeted_debug_strikes);

            if (strikes >= STRIKE_THRESHOLD) {
                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_DR_ON_TEXT,
                    g_target_base,
                    g_target_size,
                    static_cast<UINT64>(strikes),
                    0
                );
            }


            return true;
        }


        _InterlockedExchange(&g_targeted_debug_strikes, 0);

        return true;
    }
}
