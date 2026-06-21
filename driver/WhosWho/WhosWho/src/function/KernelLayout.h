#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

namespace whoswho_kernel_layout {
    inline volatile ULONG g_build_number = 0;
    inline volatile LONG g_build_resolved = 0;

    __forceinline void cpu_pause() {
        _mm_pause();
    }

    __forceinline ULONG build_number() {
        LONG state = _InterlockedCompareExchange(&g_build_resolved, 0, 0);
        if (state == 2)
            return g_build_number;

        LONG prev = _InterlockedCompareExchange(&g_build_resolved, 1, 0);
        if (prev == 2)
            return g_build_number;
        if (prev == 1) {
            for (ULONG wait = 0; wait < 10000; ++wait) {
                if (_InterlockedCompareExchange(&g_build_resolved, 0, 0) == 2)
                    return g_build_number;
                cpu_pause();
            }
            return 0;
        }

        RTL_OSVERSIONINFOW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&version)))
            g_build_number = version.dwBuildNumber;
        else
            g_build_number = 0;

        KeMemoryBarrier();
        _InterlockedExchange(&g_build_resolved, 2);
        return g_build_number;
    }

    __forceinline BOOLEAN is_windows_11_or_newer() {
        ULONG build = build_number();
        return build >= 22000;
    }

    __forceinline SIZE_T eprocess_unique_process_id_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x1D0;
        if (build >= 17763) return 0x440;
        return 0;
    }

    __forceinline SIZE_T eprocess_active_process_links_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x1D8;
        if (build >= 17763) return 0x448;
        return 0;
    }

    __forceinline SIZE_T eprocess_object_table_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x300;
        if (build >= 17763) return 0x570;
        return 0;
    }

    __forceinline SIZE_T eprocess_debug_port_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x308;
        if (build >= 19041) return 0x578;
        if (build >= 17763) return 0x550;
        return 0;
    }

    __forceinline SIZE_T eprocess_instrumentation_callback_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x168;
        if (build >= 17763) return 0x460;
        return 0;
    }

    __forceinline SIZE_T eprocess_active_threads_offset() {
        ULONG build = build_number();
        if (build >= 22000) return 0x380;
        if (build >= 17763) return 0x5F0;
        return 0;
    }
}
