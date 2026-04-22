#pragma once
#include <imports/Defs.h>
#include <core/TargetingLatch.h>

namespace debug_port_trap {

    constexpr ULONG_PTR DEBUG_PORT_OFFSET = 0x400;
    constexpr ULONG_PTR DEBUG_OBJECT_OFFSET = 0x408;

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
        if (!client_pid)
            return;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(client_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return;

        __try {
            ULONG_PTR debug_port   = read_eprocess_ptr(proc, DEBUG_PORT_OFFSET);
            ULONG_PTR debug_object = read_eprocess_ptr(proc, DEBUG_OBJECT_OFFSET);

            if (debug_port != 0 || debug_object != 0) {
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
