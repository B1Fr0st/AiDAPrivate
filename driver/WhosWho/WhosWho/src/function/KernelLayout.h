#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

namespace whoswho_kernel_layout {
    inline volatile ULONG g_build_number = 0;
    inline volatile LONG g_build_resolved = 0;
    inline volatile LONG g_static_layout_logged = 0;
    inline volatile LONG g_debug_port_scan_resolved = 0;
    inline volatile SIZE_T g_debug_port_scanned_offset = 0;

    __forceinline void cpu_pause() {
        _mm_pause();
    }

    __forceinline void log_static_layout_once(ULONG build) {
        if (_InterlockedCompareExchange(&g_static_layout_logged, 1, 0) != 0)
            return;

        SIZE_T unique_pid = 0;
        SIZE_T active_links = 0;
        SIZE_T object_table = 0;
        SIZE_T debug_port = 0;
        SIZE_T instrumentation_callback = 0;
        SIZE_T active_threads = 0;
        const char* source = "unsupported_build";

        if (build >= 26100) {
            unique_pid = 0x1D0;
            active_links = 0x1D8;
            object_table = 0x300;
            debug_port = 0x308;
            instrumentation_callback = 0x168;
            active_threads = 0x380;
            source = "static_table_win11_24h2";
        } else if (build >= 19041) {
            unique_pid = 0x440;
            active_links = 0x448;
            object_table = 0x570;
            debug_port = 0x578;
            instrumentation_callback = 0x460;
            active_threads = 0x5F0;
            source = "static_table_win10_2004_plus";
        } else if (build >= 17763) {
            unique_pid = 0x440;
            active_links = 0x448;
            object_table = 0x570;
            debug_port = 0x578;
            instrumentation_callback = 0x460;
            active_threads = 0x5F0;
            source = "static_table_win10_1809";
        }

        BOOLEAN valid = (build != 0 && unique_pid != 0 && active_links != 0 &&
            object_table != 0 && debug_port != 0 &&
            instrumentation_callback != 0 && active_threads != 0);
        WW_LOG("KVALIDATE build=%lu kind=layout name=EPROCESS source=%s offset=0x%llx validation=%s evidence=\"UniqueProcessId=0x%llx ActiveProcessLinks=0x%llx ObjectTable=0x%llx DebugPort=0x%llx InstrumentationCallback=0x%llx ActiveThreads=0x%llx ApcState=0x98 ApcStateProcess=0xB8\" fail_closed=%s",
            build,
            source,
            static_cast<unsigned long long>(unique_pid),
            ww_kernel_validation_state(valid),
            static_cast<unsigned long long>(unique_pid),
            static_cast<unsigned long long>(active_links),
            static_cast<unsigned long long>(object_table),
            static_cast<unsigned long long>(debug_port),
            static_cast<unsigned long long>(instrumentation_callback),
            static_cast<unsigned long long>(active_threads),
            valid ? "none" : "unsupported_or_unknown_build");
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
        log_static_layout_once(g_build_number);
        return g_build_number;
    }

    __forceinline BOOLEAN is_windows_11_or_newer() {
        ULONG build = build_number();
        return build >= 22000;
    }

    __forceinline SIZE_T eprocess_unique_process_id_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x1D0;
        if (build >= 17763) return 0x440;
        return 0;
    }

    __forceinline SIZE_T eprocess_active_process_links_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x1D8;
        if (build >= 17763) return 0x448;
        return 0;
    }

    __forceinline SIZE_T eprocess_object_table_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x300;
        if (build >= 17763) return 0x570;
        return 0;
    }

    __forceinline SIZE_T scan_debug_port_offset() {
        LONG state = _InterlockedCompareExchange(&g_debug_port_scan_resolved, 0, 0);
        if (state == 2)
            return g_debug_port_scanned_offset;

        LONG prev = _InterlockedCompareExchange(&g_debug_port_scan_resolved, 1, 0);
        if (prev == 2)
            return g_debug_port_scanned_offset;
        if (prev == 1) {
            for (ULONG wait = 0; wait < 10000; ++wait) {
                if (_InterlockedCompareExchange(&g_debug_port_scan_resolved, 0, 0) == 2)
                    return g_debug_port_scanned_offset;
                cpu_pause();
            }
            return 0;
        }

        SIZE_T resolved = 0;
        PVOID fn_addr = nullptr;

        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            UNICODE_STRING fn_name;
            RtlInitUnicodeString(&fn_name, L"PsGetProcessDebugPort");
            fn_addr = MmGetSystemRoutineAddress(&fn_name);

            if (fn_addr) {
                __try {
                    UINT8* bytes = static_cast<UINT8*>(fn_addr);
                    if (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0x81) {
                        UINT32 disp = *reinterpret_cast<UINT32*>(bytes + 3);
                        if (disp > 0 && disp < 0x10000) {
                            resolved = static_cast<SIZE_T>(disp);
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    resolved = 0;
                }
            }
        }

        g_debug_port_scanned_offset = resolved;
        KeMemoryBarrier();
        _InterlockedExchange(&g_debug_port_scan_resolved, 2);

        BOOLEAN valid = (resolved != 0);
        WW_LOG("KVALIDATE build=%lu kind=pattern_scan name=EPROCESS.DebugPort source=PsGetProcessDebugPort offset=0x%llx validation=%s evidence=\"fn_addr=%p instruction_prefix=48_8B_81\" fail_closed=%s",
            build_number(),
            static_cast<unsigned long long>(resolved),
            ww_kernel_validation_state(valid),
            fn_addr,
            valid ? "none" : "pattern_scan_failed");

        return resolved;
    }

    __forceinline SIZE_T eprocess_debug_port_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x308;
        if (build >= 19041) return 0x578;
        if (build >= 17763) return 0x578;
        return scan_debug_port_offset();
    }

    __forceinline SIZE_T eprocess_instrumentation_callback_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x168;
        if (build >= 17763) return 0x460;
        return 0;
    }

    __forceinline SIZE_T eprocess_active_threads_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x380;
        if (build >= 17763) return 0x5F0;
        return 0;
    }

    __forceinline SIZE_T eprocess_peb_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x2E0;
        if (build >= 17763) return 0x550;
        return 0;
    }

    __forceinline SIZE_T eprocess_vadroot_offset() {
        ULONG build = build_number();
        if (build >= 26100) return 0x558;
        if (build >= 17763) return 0x7D8;
        return 0;
    }

    __forceinline SIZE_T kthread_apc_state_offset() {
        return 0x98;
    }

    __forceinline SIZE_T kthread_apc_state_process_offset() {
        return 0x20;
    }

    __forceinline SIZE_T kthread_apc_state_process_absolute_offset() {
        return 0xB8;
    }

    __forceinline SIZE_T kthread_apc_state_size() {
        return 0x30;
    }
}
