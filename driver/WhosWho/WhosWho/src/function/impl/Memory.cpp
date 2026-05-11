#include <function/Functions.h>
#include "driver/Strong.h"
#include <imports/Defs.h>
#include <function/CoreSecurity.h>

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
        return STATUS_INVALID_PARAMETER;
    }

    mem_guard::timing_scatter();


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
    const UINT32 target_pid = request->pid;
    const BOOLEAN is_write = (request->shouldWrite != 0);

    const BOOLEAN softfault_eligible =
        (!is_write) &&
        (target_pid != 0) &&
        (_PsLookupProcessByProcessId != nullptr) &&
        (_KeStackAttachProcess != nullptr) &&
        (_KeUnstackDetachProcess != nullptr) &&
        (_ObfDereferenceObject != nullptr);

    SIZE_T total_bytes_transferred = 0;
    SIZE_T remaining_size = request->size;
    SIZE_T current_offset = 0;

    PEPROCESS target_proc = nullptr;
    BOOLEAN proc_lookup_attempted = FALSE;
    PVOID km_staging = nullptr;

    while (remaining_size > 0) {
        const UINT64 current_virtual_address = (UINT64)request->address + current_offset;


        const SIZE_T page_remaining = 0x1000 - (current_virtual_address & 0xFFF);
        const SIZE_T transfer_size = (page_remaining < remaining_size) ? page_remaining : remaining_size;

        const UINT64 physical_address = strong::translate_virtual_address(process_dir_base, current_virtual_address);
        BOOLEAN chunk_done = FALSE;

        if (physical_address) {
            SIZE_T bytes_transferred = 0;
            NTSTATUS operation_status = STATUS_UNSUCCESSFUL;

            if (is_write) {
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

        if (softfault_eligible &&
            mem_guard::is_valid_user_range(current_virtual_address) &&
            mem_guard::is_valid_user_range(current_virtual_address + transfer_size - 1))
        {
            if (!proc_lookup_attempted) {
                proc_lookup_attempted = TRUE;
                NTSTATUS lookup_status = stack_spoof::spoofed_PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)target_pid, &target_proc);
                if (!NT_SUCCESS(lookup_status)) {
                    target_proc = nullptr;
                }
            }

            if (target_proc) {
                if (!km_staging) {
                    km_staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'sFwW');
                }

                if (km_staging) {
                    KAPC_STATE local_apc{};
                    BOOLEAN read_ok = FALSE;
                    SIZE_T bytes_staged = 0;

                    stack_spoof::spoofed_KeStackAttachProcess(target_proc, &local_apc);

                    __try {
                        ProbeForRead((PVOID)current_virtual_address, transfer_size, 1);
                        strong::kmemcpy(km_staging, (PVOID)current_virtual_address, transfer_size);
                        bytes_staged = transfer_size;
                        read_ok = TRUE;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        read_ok = FALSE;
                    }

                    stack_spoof::spoofed_KeUnstackDetachProcess(&local_apc);

                    if (read_ok && bytes_staged > 0) {
                        __try {
                            strong::kmemcpy(
                                (PVOID)((ULONG_PTR)request->buffer + current_offset),
                                km_staging,
                                bytes_staged
                            );

                            total_bytes_transferred += bytes_staged;
                            remaining_size -= bytes_staged;
                            current_offset += bytes_staged;
                            chunk_done = TRUE;
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            chunk_done = FALSE;
                        }
                    }
                }
            }
        }

        if (chunk_done) {
            if ((total_bytes_transferred & 0x3FFF) == 0) {
                mem_guard::timing_scatter();
            }
            continue;
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

    if (km_staging) {
        ExFreePoolWithTag(km_staging, 'sFwW');
    }
    if (target_proc) {
        stack_spoof::spoofed_ObfDereferenceObject(target_proc);
    }

    request->retSize = total_bytes_transferred;


    return (total_bytes_transferred > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
