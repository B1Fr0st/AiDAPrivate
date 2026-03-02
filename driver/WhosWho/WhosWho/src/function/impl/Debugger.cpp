#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"


namespace dbg_guard {
    inline volatile ULONG g_dbg_entropy = 0xABCD1234u;

    __forceinline void timing_scatter() {
        ULONG x = g_dbg_entropy ^ (ULONG)(__rdtsc() & 0xFFFFu);
        x ^= x << 13;
        g_dbg_entropy = x;
        volatile ULONG spin = (x & 0x3) + 1;
        while (spin--) YieldProcessor();
    }
}


NTSTATUS functions::handle_thread_ctx(p_thread_ctx request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_PsGetContextThread || !_PsSetContextThread ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess ||
        !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        _ObfDereferenceObject(process);
        return status;
    }

    dbg_guard::timing_scatter();

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    CONTEXT ctx;
    strong::kmemset(&ctx, 0, sizeof(ctx));

    if (request->should_set == 0) {

        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        status = _PsGetContextThread(thread, &ctx, UserMode);

        if (NT_SUCCESS(status)) {
            request->rax = ctx.Rax;
            request->rbx = ctx.Rbx;
            request->rcx = ctx.Rcx;
            request->rdx = ctx.Rdx;
            request->rsi = ctx.Rsi;
            request->rdi = ctx.Rdi;
            request->rbp = ctx.Rbp;
            request->rsp = ctx.Rsp;
            request->r8  = ctx.R8;
            request->r9  = ctx.R9;
            request->r10 = ctx.R10;
            request->r11 = ctx.R11;
            request->r12 = ctx.R12;
            request->r13 = ctx.R13;
            request->r14 = ctx.R14;
            request->r15 = ctx.R15;
            request->rip = ctx.Rip;
            request->rflags = ctx.EFlags;
            request->cs  = ctx.SegCs;
            request->ss  = ctx.SegSs;
            request->dr0 = ctx.Dr0;
            request->dr1 = ctx.Dr1;
            request->dr2 = ctx.Dr2;
            request->dr3 = ctx.Dr3;
            request->dr6 = ctx.Dr6;
            request->dr7 = ctx.Dr7;
        }
    }
    else {

        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        status = _PsGetContextThread(thread, &ctx, UserMode);

        if (NT_SUCCESS(status)) {

            UINT64 mask = request->register_mask;
            if (mask & (1ULL << 0))  ctx.Rax    = request->rax;
            if (mask & (1ULL << 1))  ctx.Rbx    = request->rbx;
            if (mask & (1ULL << 2))  ctx.Rcx    = request->rcx;
            if (mask & (1ULL << 3))  ctx.Rdx    = request->rdx;
            if (mask & (1ULL << 4))  ctx.Rsi    = request->rsi;
            if (mask & (1ULL << 5))  ctx.Rdi    = request->rdi;
            if (mask & (1ULL << 6))  ctx.Rbp    = request->rbp;
            if (mask & (1ULL << 7))  ctx.Rsp    = request->rsp;
            if (mask & (1ULL << 8))  ctx.R8     = request->r8;
            if (mask & (1ULL << 9))  ctx.R9     = request->r9;
            if (mask & (1ULL << 10)) ctx.R10    = request->r10;
            if (mask & (1ULL << 11)) ctx.R11    = request->r11;
            if (mask & (1ULL << 12)) ctx.R12    = request->r12;
            if (mask & (1ULL << 13)) ctx.R13    = request->r13;
            if (mask & (1ULL << 14)) ctx.R14    = request->r14;
            if (mask & (1ULL << 15)) ctx.R15    = request->r15;
            if (mask & (1ULL << 16)) ctx.Rip    = request->rip;
            if (mask & (1ULL << 17)) ctx.EFlags = (ULONG)request->rflags;
            if (mask & (1ULL << 18)) ctx.Dr0    = request->dr0;
            if (mask & (1ULL << 19)) ctx.Dr1    = request->dr1;
            if (mask & (1ULL << 20)) ctx.Dr2    = request->dr2;
            if (mask & (1ULL << 21)) ctx.Dr3    = request->dr3;
            if (mask & (1ULL << 22)) ctx.Dr6    = request->dr6;
            if (mask & (1ULL << 23)) ctx.Dr7    = request->dr7;

            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            status = _PsSetContextThread(thread, &ctx, UserMode);
        }
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_thread_enum(p_thread_enum request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_PsGetNextProcessThread || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    dbg_guard::timing_scatter();

    UINT32 count = 0;
    PETHREAD thread = nullptr;


    thread = _PsGetNextProcessThread(process, nullptr);
    while (thread != nullptr && count < MAX_ENUM_THREADS) {
        __try {
            HANDLE tid = _PsGetThreadId(thread);
            request->entries[count].tid = (UINT32)(ULONG_PTR)tid;
            request->entries[count].state = 0;


            request->entries[count].rip = 0;

            count++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }

        thread = _PsGetNextProcessThread(process, thread);
    }

    _ObfDereferenceObject(process);
    request->thread_count = count;

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_suspend_resume_thread(p_suspend_resume_thread request) {
    if (!request || request->tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupThreadByThreadId || !_PsSuspendThread || !_PsResumeThread ||
        !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PETHREAD thread = nullptr;
    NTSTATUS status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        return status;
    }

    ULONG prev_count = 0;
    if (request->should_resume == 0) {
        status = _PsSuspendThread(thread, &prev_count);
    }
    else {
        status = _PsResumeThread(thread, &prev_count);
    }

    request->previous_count = prev_count;
    _ObfDereferenceObject(thread);

    return status;
}


NTSTATUS functions::handle_query_memory(p_query_memory request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    MEMORY_BASIC_INFORMATION mbi;
    strong::kmemset(&mbi, 0, sizeof(mbi));
    SIZE_T returned_length = 0;

    status = _ZwQueryVirtualMemory(
        (HANDLE)-1,
        (PVOID)request->address,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &returned_length);

    if (NT_SUCCESS(status)) {
        request->region_base    = (UINT64)mbi.BaseAddress;
        request->region_size    = (UINT64)mbi.RegionSize;
        request->state          = mbi.State;
        request->protect        = mbi.Protect;
        request->type           = mbi.Type;
        request->allocation_base = (UINT64)mbi.AllocationBase;
        request->allocation_protect = mbi.AllocationProtect;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_protect_memory(p_protect_memory request) {
    if (!request || request->pid == 0 || request->size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwProtectVirtualMemory || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    PVOID base_addr = (PVOID)request->address;
    SIZE_T region_size = (SIZE_T)request->size;
    ULONG old_protect = 0;

    status = _ZwProtectVirtualMemory(
        (HANDLE)-1,
        &base_addr,
        &region_size,
        request->new_protect,
        &old_protect);

    if (NT_SUCCESS(status)) {
        request->old_protect = old_protect;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_enum_regions(p_enum_regions request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    UINT32 count = 0;
    UINT64 addr = request->start_address;
    UINT64 max_addr = 0x00007FFFFFFFFFFFULL;
    if (request->max_address != 0 && request->max_address < max_addr) {
        max_addr = request->max_address;
    }

    while (addr < max_addr && count < MAX_ENUM_REGIONS) {
        MEMORY_BASIC_INFORMATION mbi;
        strong::kmemset(&mbi, 0, sizeof(mbi));
        SIZE_T returned = 0;

        status = _ZwQueryVirtualMemory(
            (HANDLE)-1,
            (PVOID)addr,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returned);

        if (!NT_SUCCESS(status) || mbi.RegionSize == 0) {
            break;
        }


        if (mbi.State == MEM_COMMIT || request->include_all) {
            request->entries[count].base    = (UINT64)mbi.BaseAddress;
            request->entries[count].size    = (UINT64)mbi.RegionSize;
            request->entries[count].state   = mbi.State;
            request->entries[count].protect = mbi.Protect;
            request->entries[count].type    = mbi.Type;
            count++;
        }

        UINT64 next = (UINT64)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    request->region_count = count;
    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_read_peb(p_read_peb request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    PVOID peb = (PVOID)_PsGetProcessPeb(process);
    if (!peb) {
        _ObfDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    request->peb_address = (UINT64)peb;


    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);


    __try {
        UCHAR* peb_base = (UCHAR*)peb;
        request->image_base      = *(UINT64*)(peb_base + 0x10);
        request->being_debugged  = *(UCHAR*)(peb_base + 0x02);
        request->nt_global_flag  = *(UINT32*)(peb_base + 0xBC);
        request->ldr_address     = *(UINT64*)(peb_base + 0x18);
        request->process_heap    = *(UINT64*)(peb_base + 0x30);
        request->number_of_heaps = *(UINT32*)(peb_base + 0xE8);
        request->max_heaps       = *(UINT32*)(peb_base + 0xEC);
        request->process_heaps   = *(UINT64*)(peb_base + 0xF0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _KeUnstackDetachProcess(&apc_state);
        _ObfDereferenceObject(process);
        return STATUS_ACCESS_VIOLATION;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_spoof_debug_flags(p_spoof_debug request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    UINT32 cleared = 0;


    {
        ULONG build = strong::get_windows_version();
        ULONG debug_port_offset = 0;
        if (build >= 22000) {
            debug_port_offset = 0x578;
        }
        else if (build >= 19041) {
            debug_port_offset = 0x578;
        }
        else if (build >= 17763) {
            debug_port_offset = 0x550;
        }
        else {
            debug_port_offset = 0x420;
        }

        if (debug_port_offset > 0) {
            __try {
                UINT64* debug_port = (UINT64*)((UCHAR*)process + debug_port_offset);
                if (*debug_port != 0) {
                    *debug_port = 0;
                    cleared |= 1;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

            }
        }
    }


    PVOID peb = (PVOID)_PsGetProcessPeb(process);
    if (peb) {
        KAPC_STATE apc_state;
        _KeStackAttachProcess(process, &apc_state);

        __try {
            UCHAR* peb_base = (UCHAR*)peb;
            if (*(UCHAR*)(peb_base + 0x02) != 0) {
                *(UCHAR*)(peb_base + 0x02) = 0;
                cleared |= 2;
            }
            if (*(UINT32*)(peb_base + 0xBC) != 0) {

                *(UINT32*)(peb_base + 0xBC) &= ~(0x70u);
                cleared |= 4;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }

        _KeUnstackDetachProcess(&apc_state);
    }

    _ObfDereferenceObject(process);

    request->result_flags = cleared;
    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_get_module_export(p_module_export request) {
    if (!request || request->module_base == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->dtb == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    dbg_guard::timing_scatter();

    UINT64 dtb = request->dtb;
    UINT64 base = request->module_base;


    UINT8 dos_hdr[64];
    SIZE_T bytes_read = 0;
    UINT64 phys = strong::translate_virtual_address(dtb, base);
    if (!phys) return STATUS_INVALID_ADDRESS;

    NTSTATUS status = strong::read_physical(phys, dos_hdr, 64, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 64) return STATUS_UNSUCCESSFUL;
    if (*(UINT16*)dos_hdr != 0x5A4D) return STATUS_INVALID_IMAGE_FORMAT;

    UINT32 pe_off = *(UINT32*)(dos_hdr + 0x3C);
    if (pe_off > 0x1000) return STATUS_INVALID_IMAGE_FORMAT;


    UINT8 pe_hdr[0x200];
    phys = strong::translate_virtual_address(dtb, base + pe_off);
    if (!phys) return STATUS_INVALID_ADDRESS;
    status = strong::read_physical(phys, pe_hdr, 0x200, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 0x100) return STATUS_UNSUCCESSFUL;
    if (*(UINT32*)pe_hdr != 0x00004550) return STATUS_INVALID_IMAGE_FORMAT;

    UINT16 opt_magic = *(UINT16*)(pe_hdr + 0x18);
    UINT32 export_rva = 0;
    if (opt_magic == 0x020B) {
        export_rva = *(UINT32*)(pe_hdr + 0x18 + 0x70);
    }
    else if (opt_magic == 0x010B) {
        export_rva = *(UINT32*)(pe_hdr + 0x18 + 0x60);
    }

    if (export_rva == 0) return STATUS_NOT_FOUND;


    UINT8 exp_dir[40];
    phys = strong::translate_virtual_address(dtb, base + export_rva);
    if (!phys) return STATUS_INVALID_ADDRESS;
    status = strong::read_physical(phys, exp_dir, 40, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 40) return STATUS_UNSUCCESSFUL;

    UINT32 num_names         = *(UINT32*)(exp_dir + 24);
    UINT32 addr_of_funcs_rva = *(UINT32*)(exp_dir + 28);
    UINT32 addr_of_names_rva = *(UINT32*)(exp_dir + 32);
    UINT32 addr_of_ords_rva  = *(UINT32*)(exp_dir + 36);
    UINT32 ordinal_base      = *(UINT32*)(exp_dir + 16);


    char target_name[128];
    strong::kmemset(target_name, 0, sizeof(target_name));
    for (int i = 0; i < 127 && request->export_name[i]; i++) {
        target_name[i] = request->export_name[i];
    }


    for (UINT32 i = 0; i < num_names && i < 8192; i++) {

        UINT32 name_rva = 0;
        phys = strong::translate_virtual_address(dtb, base + addr_of_names_rva + i * 4);
        if (!phys) continue;
        strong::read_physical(phys, &name_rva, 4, &bytes_read);
        if (name_rva == 0) continue;


        char exp_name[128];
        strong::kmemset(exp_name, 0, sizeof(exp_name));
        phys = strong::translate_virtual_address(dtb, base + name_rva);
        if (!phys) continue;
        strong::read_physical(phys, exp_name, 127, &bytes_read);
        exp_name[127] = 0;


        bool match = true;
        for (int c = 0; c < 127; c++) {
            if (target_name[c] == 0 && exp_name[c] == 0) break;
            if (target_name[c] != exp_name[c]) { match = false; break; }
        }

        if (match) {

            UINT16 ordinal = 0;
            phys = strong::translate_virtual_address(dtb, base + addr_of_ords_rva + i * 2);
            if (!phys) return STATUS_UNSUCCESSFUL;
            strong::read_physical(phys, &ordinal, 2, &bytes_read);


            UINT32 func_rva = 0;
            phys = strong::translate_virtual_address(dtb, base + addr_of_funcs_rva + ordinal * 4);
            if (!phys) return STATUS_UNSUCCESSFUL;
            strong::read_physical(phys, &func_rva, 4, &bytes_read);

            request->resolved_address = base + func_rva;
            request->ordinal = ordinal_base + ordinal;
            return STATUS_SUCCESS;
        }
    }

    request->resolved_address = 0;
    return STATUS_NOT_FOUND;
}


NTSTATUS functions::handle_virt_to_phys(p_virt_to_phys request) {
    if (!request || request->dtb == 0 || request->virtual_address == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT64 physical = strong::translate_virtual_address(request->dtb, request->virtual_address);
    request->physical_address = physical;

    return (physical != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
