#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif

#ifndef DISPATCH_LEVEL
#define DISPATCH_LEVEL 2
#endif

#ifndef HIGH_LEVEL
#define HIGH_LEVEL 15
#endif

namespace anti_debug {

    constexpr UINT32 DETECT_NONE             = 0x00000000u;
    constexpr UINT32 DETECT_KERNEL_DEBUGGER  = 0x00000001u;
    constexpr UINT32 DETECT_HYPERVISOR       = 0x00000002u;
    constexpr UINT32 DETECT_ETW_ACTIVE       = 0x00000004u;
    constexpr UINT32 DETECT_INSTRUMENTATION  = 0x00000008u;
    constexpr UINT32 DETECT_TIMING_ATTACK    = 0x00000010u;
    constexpr UINT32 DETECT_PAGE_GUARD       = 0x00000020u;

    inline volatile UINT32 g_detection_flags = DETECT_NONE;
    inline volatile UINT64 g_last_check_tsc = 0;
    inline volatile LONG g_check_lock = 0;

    constexpr UINT64 CHECK_INTERVAL_TSC = 300000000ULL;

    __forceinline void acquire_lock() {
        while (_InterlockedCompareExchange(&g_check_lock, 1, 0) != 0) {
            YieldProcessor();
        }
        KeMemoryBarrier();
    }

    __forceinline void release_lock() {
        KeMemoryBarrier();
        _InterlockedExchange(&g_check_lock, 0);
    }

    __forceinline BOOLEAN check_kernel_debugger() {
        __try {
            if (KD_DEBUGGER_ENABLED) {
                return TRUE;
            }

            if (!KD_DEBUGGER_NOT_PRESENT) {
                return TRUE;
            }

            PKUSER_SHARED_DATA shared_data = reinterpret_cast<PKUSER_SHARED_DATA>(0xFFFFF78000000000ULL);
            if (shared_data && _MmIsAddressValid(shared_data)) {
                if (shared_data->KdDebuggerEnabled) {
                    return TRUE;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return TRUE;
        }

        return FALSE;
    }

    __forceinline BOOLEAN check_hypervisor() {
        int cpuInfo[4] = { 0 };

        __try {
            __cpuid(cpuInfo, 1);

            if (cpuInfo[2] & (1 << 31)) {
                int vendorInfo[4] = { 0 };
                __cpuid(vendorInfo, 0x40000000);

                if (vendorInfo[0] >= 0x40000001) {
                    char vendor_id[13] = { 0 };
                    *(int*)&vendor_id[0] = vendorInfo[1];
                    *(int*)&vendor_id[4] = vendorInfo[2];
                    *(int*)&vendor_id[8] = vendorInfo[3];
                    vendor_id[12] = '\0';

                    if (vendor_id[0] == 'M' && vendor_id[1] == 'i' &&
                        vendor_id[2] == 'c' && vendor_id[3] == 'r' &&
                        vendor_id[4] == 'o' && vendor_id[5] == 's' &&
                        vendor_id[6] == 'o' && vendor_id[7] == 'f' &&
                        vendor_id[8] == 't' && vendor_id[9] == ' ' &&
                        vendor_id[10] == 'H' && vendor_id[11] == 'v') {
                        return FALSE;
                    }

                    if (vendor_id[0] == 'V' && vendor_id[1] == 'M' &&
                        vendor_id[2] == 'w' && vendor_id[3] == 'a' &&
                        vendor_id[4] == 'r' && vendor_id[5] == 'e' &&
                        vendor_id[6] == 'V' && vendor_id[7] == 'M' &&
                        vendor_id[8] == 'w' && vendor_id[9] == 'a' &&
                        vendor_id[10] == 'r' && vendor_id[11] == 'e') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'V' && vendor_id[1] == 'B' &&
                        vendor_id[2] == 'o' && vendor_id[3] == 'x' &&
                        vendor_id[4] == 'V' && vendor_id[5] == 'B' &&
                        vendor_id[6] == 'o' && vendor_id[7] == 'x' &&
                        vendor_id[8] == 'V' && vendor_id[9] == 'B' &&
                        vendor_id[10] == 'o' && vendor_id[11] == 'x') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'K' && vendor_id[1] == 'V' &&
                        vendor_id[2] == 'M' && vendor_id[3] == 'K' &&
                        vendor_id[4] == 'V' && vendor_id[5] == 'M' &&
                        vendor_id[6] == 'K' && vendor_id[7] == 'V' &&
                        vendor_id[8] == 'M') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'X' && vendor_id[1] == 'e' &&
                        vendor_id[2] == 'n' && vendor_id[3] == 'V' &&
                        vendor_id[4] == 'M' && vendor_id[5] == 'M' &&
                        vendor_id[6] == 'X' && vendor_id[7] == 'e' &&
                        vendor_id[8] == 'n' && vendor_id[9] == 'V' &&
                        vendor_id[10] == 'M' && vendor_id[11] == 'M') {
                        return TRUE;
                    }

                    return FALSE;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    __forceinline BOOLEAN check_timing_attack() {
        __try {


            UINT64 old_irql = __readcr8();
            __writecr8(2);

            constexpr UINT32 NUM_TRIALS = 3;
            constexpr UINT64 TIMING_THRESHOLD = 2000000ULL;
            UINT32 fail_count = 0;

            for (UINT32 trial = 0; trial < NUM_TRIALS; trial++) {
                UINT64 start = __rdtsc();

                volatile UINT64 dummy = 0;
                for (int i = 0; i < 16; i++) {
                    dummy += __rdtsc();
                    KeMemoryBarrier();
                }

                UINT64 end = __rdtsc();
                UINT64 elapsed = end - start;

                if (elapsed > TIMING_THRESHOLD) {
                    fail_count++;
                }
            }

            __writecr8(old_irql);


            if (fail_count >= 2) {
                return TRUE;
            }


            UINT64 times[4];
            for (int i = 0; i < 4; i++) {
                UINT64 s = __rdtsc();
                for (int j = 0; j < 8; j++) {
                    YieldProcessor();
                }
                times[i] = __rdtsc() - s;
            }

            UINT64 variance = 0;
            for (int i = 1; i < 4; i++) {
                UINT64 diff = (times[i] > times[0]) ? (times[i] - times[0]) : (times[0] - times[i]);
                variance += diff;
            }

            if (variance < 3 && times[0] > 500) {
                return TRUE;
            }

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    __forceinline BOOLEAN check_instrumentation() {
        __try {
            KIRQL current_irql = (KIRQL)__readcr8();

            if (current_irql > DISPATCH_LEVEL &&
                current_irql != HIGH_LEVEL) {
                return TRUE;
            }

            UINT64 rflags = __readeflags();

            if (rflags & 0x100) {
                return TRUE;
            }

            if ((rflags & 0x10000) && (rflags & 0x100)) {
                return TRUE;
            }

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    __forceinline UINT32 run_all_checks() {
        UINT32 flags = DETECT_NONE;

        if (check_kernel_debugger()) {
            flags |= DETECT_KERNEL_DEBUGGER;
        }

        if (check_hypervisor()) {
            flags |= DETECT_HYPERVISOR;
        }

        if (check_timing_attack()) {
            flags |= DETECT_TIMING_ATTACK;
        }

        if (check_instrumentation()) {
            flags |= DETECT_INSTRUMENTATION;
        }

        return flags;
    }

    __forceinline UINT32 get_detection_flags() {
        UINT64 current_tsc = __rdtsc();
        UINT64 last_check = g_last_check_tsc;

        if (current_tsc - last_check < CHECK_INTERVAL_TSC) {
            return g_detection_flags;
        }

        acquire_lock();

        if (__rdtsc() - g_last_check_tsc < CHECK_INTERVAL_TSC) {
            UINT32 cached = g_detection_flags;
            release_lock();
            return cached;
        }

        UINT32 new_flags = run_all_checks();
        g_detection_flags = new_flags;
        g_last_check_tsc = __rdtsc();

        release_lock();
        return new_flags;
    }

    __forceinline BOOLEAN is_safe_to_operate() {
        return TRUE;
    }

    __forceinline UINT32 refresh_detection() {
        acquire_lock();
        UINT32 flags = run_all_checks();
        g_detection_flags = flags;
        g_last_check_tsc = __rdtsc();
        release_lock();
        return flags;
    }
}
