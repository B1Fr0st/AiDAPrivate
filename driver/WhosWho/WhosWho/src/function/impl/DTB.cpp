#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"

#define KPROCESS_DIRECTORYTABLEBASE_OFFSET 0x28

namespace dtb_guard {
    inline volatile ULONG g_dtb_entropy = 0xDEADBEEFu;

    __forceinline void timing_scatter() {
        ULONG x = g_dtb_entropy ^ (ULONG)(__rdtsc() & 0xFFFFFFFFu);
        x ^= x << 13;
        g_dtb_entropy = x;
        volatile ULONG spin = (x & 0x3) + 1;
        while (spin--) YieldProcessor();
    }

    __forceinline BOOLEAN is_valid_target_pid(UINT32 pid) {
        if (pid == 0) return FALSE;
        return TRUE;
    }

    __forceinline BOOLEAN is_valid_dtb(UINT64 dtb) {
        UINT64 pfn = (dtb >> 12) & 0xFFFFFFFFFULL;
        if (pfn == 0) return FALSE;
        if (pfn > 0x1000000) return FALSE;

        if ((dtb & 0x000FFFFFFFFFF000ULL) == 0) return FALSE;

        return TRUE;
    }
}

NTSTATUS functions::handle777d(p_dtb_solve request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!dtb_guard::is_valid_target_pid(request->pid)) {
        return STATUS_ACCESS_DENIED;
    }

    dtb_guard::timing_scatter();

    UINT64 cached_dtb = 0;
    if (LookupDTBCache(request->pid, &cached_dtb)) {
        request->dtb = cached_dtb;
        dtb_guard::timing_scatter();
        return STATUS_SUCCESS;
    }
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS process = nullptr;

    status = stack_spoof::spoofed_PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    UINT64 dir_base = 0;

    __try {
        dir_base = *(UINT64*)((UCHAR*)process + KPROCESS_DIRECTORYTABLEBASE_OFFSET);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        stack_spoof::spoofed_ObfDereferenceObject(process);
        return STATUS_ACCESS_VIOLATION;
    }

    stack_spoof::spoofed_ObfDereferenceObject(process);

    if (dir_base != 0 && dtb_guard::is_valid_dtb(dir_base)) {
        request->dtb = dir_base & 0x000FFFFFFFFFF000ULL;

        InsertDTBCache(request->pid, request->dtb);
        status = STATUS_SUCCESS;
    } else {
        request->dtb = 0;
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}
