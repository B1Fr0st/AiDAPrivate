#include <function/Functions.h>
#include <imports/Defs.h>
#include "driver/Strong.h"
#include "../CoreSecurity.h"

namespace base_guard {
    inline volatile ULONG g_base_entropy = 0xFEEDFACEu;
    
    __forceinline void timing_scatter() {
        ULONG x = g_base_entropy ^ (ULONG)(__rdtsc() & 0xFFFFu);
        x ^= x << 13;
        g_base_entropy = x;
        volatile ULONG spin = (x & 0x3) + 1;
        while (spin--) YieldProcessor();
    }
    
    __forceinline BOOLEAN is_valid_target_pid(UINT32 pid) {
        if (pid <= 4) return FALSE;
        if (pid < 100) return FALSE;
        return TRUE;
    }
}

NTSTATUS functions::handle777f(p_base_address request) {
    if (!request || !request->outAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!base_guard::is_valid_target_pid(request->pid)) {
        return STATUS_ACCESS_DENIED;
    }
    
    base_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = stack_spoof::spoofed_PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);

    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    stack_spoof::pre_call_setup();
    
    volatile auto func = _PsGetProcessSectionBaseAddress;
    KeMemoryBarrier();
    
    const ULONGLONG image_base = (ULONGLONG)func(process);
    
    stack_spoof::post_call_cleanup();
    
    stack_spoof::spoofed_ObfDereferenceObject(process);
    
    if (!image_base) {
        return STATUS_NOT_FOUND;
    }

    __try {
        *request->outAddress = image_base;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}