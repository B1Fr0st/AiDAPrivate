#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>

namespace debug_port_trap {

    __forceinline bool resolve_offsets(ULONG_PTR* debug_port_offset, ULONG_PTR* debug_object_offset)
    {
        *debug_port_offset = 0;
        *debug_object_offset = 0;

        RTL_OSVERSIONINFOW ver = {};
        ver.dwOSVersionInfoSize = sizeof(ver);
        if (!_RtlGetVersion || !NT_SUCCESS(_RtlGetVersion(&ver)))
            return false;

        if (ver.dwBuildNumber >= 19041) {
            *debug_port_offset = 0x578;
            return true;
        }
        if (ver.dwBuildNumber >= 17763) {
            *debug_port_offset = 0x550;
            return true;
        }
        return false;
    }

    __forceinline bool is_kernel_pointer(ULONG_PTR value)
    {
        return value >= 0xFFFF800000000000ull;
    }

    __forceinline ULONG_PTR read_eprocess_ptr(PEPROCESS proc, ULONG_PTR offset)
    {
        ULONG_PTR val = 0;
        __try {
            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(proc) + offset;
            if (_MmIsAddressValid(reinterpret_cast<PVOID>(addr)))
                val = *reinterpret_cast<volatile ULONG_PTR*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            val = 0;
        }
        return val;
    }

    __forceinline void check(HANDLE client_pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        if (!client_pid)
            return;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(client_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return;

        __try {
            ULONG_PTR debug_port_offset = 0;
            ULONG_PTR debug_object_offset = 0;
            if (!resolve_offsets(&debug_port_offset, &debug_object_offset)) {
                _ObfDereferenceObject(proc);
                return;
            }

            ULONG_PTR debug_port = debug_port_offset ? read_eprocess_ptr(proc, debug_port_offset) : 0;
            ULONG_PTR debug_object = debug_object_offset ? read_eprocess_ptr(proc, debug_object_offset) : 0;

            if ((debug_port != 0 && is_kernel_pointer(debug_port)) ||
                (debug_object != 0 && is_kernel_pointer(debug_object))) {
                UINT64 pid_val = (UINT64)(ULONG_PTR)client_pid;
                UINT64 port_hash = debug_port ^ (debug_port >> 17);
                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_DEBUG_PORT_TRAP,
                    pid_val,
                    port_hash,
                    debug_object,
                    0
                );
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        _ObfDereferenceObject(proc);
    }
}
