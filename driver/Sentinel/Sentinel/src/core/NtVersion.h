#pragma once
#include <imports/Defs.h>

namespace nt_version {

    inline volatile ULONG g_build_number = 0;
    inline volatile LONG g_state = 0;

    __forceinline void wait_brief() {
        if (_KeDelayExecutionThread && KeGetCurrentIrql() == PASSIVE_LEVEL) {
            LARGE_INTEGER wait;
            wait.QuadPart = -10000LL;
            _KeDelayExecutionThread(KernelMode, FALSE, &wait);
        } else {
            YieldProcessor();
        }
    }

    __forceinline ULONG build_number() {
        LONG state = _InterlockedCompareExchange(&g_state, 0, 0);
        if (state == 2)
            return g_build_number;

        LONG prev = _InterlockedCompareExchange(&g_state, 1, 0);
        if (prev == 2)
            return g_build_number;
        if (prev == 1) {
            for (ULONG i = 0; i < 400; ++i) {
                if (_InterlockedCompareExchange(&g_state, 2, 2) == 2)
                    return g_build_number;
                wait_brief();
            }
            return g_build_number;
        }

        RTL_OSVERSIONINFOW ver = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&ver)))
            g_build_number = ver.dwBuildNumber;
        else
            g_build_number = 19045;

        KeMemoryBarrier();
        _InterlockedExchange(&g_state, 2);
        return g_build_number;
    }

    __forceinline bool is_windows_11_or_newer() {
        return build_number() >= 22000;
    }

    __forceinline bool is_windows_11_24h2_or_newer() {
        return build_number() >= 26100;
    }

    __forceinline ULONG_PTR kthread_apc_state_offset() {
        return 0x98;
    }

    __forceinline ULONG_PTR kthread_apc_state_process_offset() {
        return 0x20;
    }

    __forceinline ULONG_PTR kthread_apc_state_process_absolute_offset() {
        return 0xB8;
    }

    __forceinline ULONG_PTR kthread_apc_state_size() {
        return 0x30;
    }
}
