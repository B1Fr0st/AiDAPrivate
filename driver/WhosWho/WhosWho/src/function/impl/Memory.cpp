#include <function/Functions.h>
#include "driver/Strong.h"
#include <imports/Defs.h>

#ifndef WW_LOG
#define WW_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] " fmt "\n", __VA_ARGS__)
#define WW_LOG0(msg) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] %s\n", msg)
#endif

namespace mem_guard {
    inline volatile ULONG g_mem_entropy = 0xC0DEBEEFu;

    __forceinline void timing_scatter() {
        ULONG x = g_mem_entropy ^ (ULONG)(__rdtsc() & 0x1FFu);
        x ^= x << 13;
        g_mem_entropy = x;
        if ((x & 0xF) < 3) {
            volatile ULONG spin = (x & 0x3) + 1;
            while (spin--) YieldProcessor();
        }
    }

    __forceinline BOOLEAN is_valid_user_range(UINT64 addr) {
        return (addr > 0x10000ULL && addr < 0x00007FFFFFFFFFFFULL);
    }

    __forceinline BOOLEAN is_safe_size(SIZE_T size) {
        return (size > 0 && size <= 0x1000000);
    }
}

NTSTATUS functions::handle777e(p_physical_rw request) {
    if (!request) {
        WW_LOG0("handle777e: null request");
        return STATUS_INVALID_PARAMETER;
    }

    mem_guard::timing_scatter();

    WW_LOG("handle777e: dtb=0x%llX addr=%p size=%llu write=%u buffer=%p",
        request->dtb, request->address, (UINT64)request->size,
        (UINT32)request->shouldWrite, request->buffer);

    if (!request->buffer || request->size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->dtb == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->size > 0x4000000) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    const UINT64 target_addr = (UINT64)request->address;
    if (target_addr == 0) {
        return STATUS_ACCESS_DENIED;
    }


    const UINT64 process_dir_base = request->dtb;

    SIZE_T total_bytes_transferred = 0;
    SIZE_T remaining_size = request->size;
    SIZE_T current_offset = 0;

    while (remaining_size > 0) {
        const UINT64 current_virtual_address = (UINT64)request->address + current_offset;


        const SIZE_T page_remaining = 0x1000 - (current_virtual_address & 0xFFF);
        const SIZE_T transfer_size = (page_remaining < remaining_size) ? page_remaining : remaining_size;

        const UINT64 physical_address = strong::translate_virtual_address(process_dir_base, current_virtual_address);

        if (physical_address) {
            SIZE_T bytes_transferred = 0;
            NTSTATUS operation_status = STATUS_UNSUCCESSFUL;

            if (request->shouldWrite) {
                operation_status = strong::write_physical(
                    (PVOID)physical_address,
                    (PVOID)((ULONG_PTR)request->buffer + current_offset),
                    transfer_size,
                    &bytes_transferred
                );
            }
            else {
                operation_status = strong::read_physical(
                    physical_address,
                    (PVOID)((ULONG_PTR)request->buffer + current_offset),
                    transfer_size,
                    &bytes_transferred
                );
            }

            if (NT_SUCCESS(operation_status) && bytes_transferred > 0) {
                total_bytes_transferred += bytes_transferred;
                remaining_size -= bytes_transferred;
                current_offset += bytes_transferred;
                continue;
            }
        }


        __try {
            strong::kmemset((PVOID)((ULONG_PTR)request->buffer + current_offset), 0, transfer_size);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        total_bytes_transferred += transfer_size;
        remaining_size -= transfer_size;
        current_offset += transfer_size;

        if ((total_bytes_transferred & 0x3FFF) == 0) {
            mem_guard::timing_scatter();
        }
    }

    request->retSize = total_bytes_transferred;

    WW_LOG("handle777e: transferred=%llu/%llu status=%s",
        (UINT64)total_bytes_transferred, (UINT64)request->size,
        (total_bytes_transferred > 0) ? "SUCCESS" : "FAIL");

    return (total_bytes_transferred > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
