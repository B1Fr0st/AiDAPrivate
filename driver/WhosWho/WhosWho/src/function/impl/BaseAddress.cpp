#include <function/Functions.h>
#include <imports/Defs.h>
#include "driver/Strong.h"
#include "../CoreSecurity.h"

#ifndef WW_LOG
#define WW_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] " fmt "\n", __VA_ARGS__)
#define WW_LOG0(msg) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] %s\n", msg)
#endif

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
        WW_LOG("handle777f: bad request (req=%p)", request);
        return STATUS_INVALID_PARAMETER;
    }

    if (request->pid == 0) {
        WW_LOG0("handle777f: pid is 0");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle777f: pid=%u", request->pid);

    if (!base_guard::is_valid_target_pid(request->pid)) {
        WW_LOG("handle777f: invalid target pid=%u (<=100)", request->pid);
        return STATUS_ACCESS_DENIED;
    }

    base_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = stack_spoof::spoofed_PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);

    if (!NT_SUCCESS(status) || !process) {
        WW_LOG("handle777f: PsLookupProcessByProcessId FAILED status=0x%08X", status);
        return status;
    }

    stack_spoof::pre_call_setup();

    volatile auto func = _PsGetProcessSectionBaseAddress;
    KeMemoryBarrier();

    const ULONGLONG image_base = (ULONGLONG)func(process);

    stack_spoof::post_call_cleanup();

    stack_spoof::spoofed_ObfDereferenceObject(process);

    if (!image_base) {
        WW_LOG("handle777f: image_base is NULL for pid=%u", request->pid);
        return STATUS_NOT_FOUND;
    }

    __try {
        *request->outAddress = image_base;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WW_LOG0("handle777f: ACCESS_VIOLATION writing outAddress");
        return STATUS_ACCESS_VIOLATION;
    }

    WW_LOG("handle777f: SUCCESS pid=%u base=0x%llX", request->pid, image_base);

    return STATUS_SUCCESS;
}
