#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"

typedef struct _SYSTEM_PROCESS_INFORMATION_LOCAL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION_LOCAL, *PSYSTEM_PROCESS_INFORMATION_LOCAL;

typedef struct _SYSTEM_THREAD_INFORMATION_LOCAL {
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_LOCAL, *PSYSTEM_THREAD_INFORMATION_LOCAL;

static_assert(sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL) == 256, "Unexpected SYSTEM_PROCESS_INFORMATION_LOCAL size");
static_assert(sizeof(SYSTEM_THREAD_INFORMATION_LOCAL) == 80, "Unexpected SYSTEM_THREAD_INFORMATION_LOCAL size");

namespace sysinfo_guard {
    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL kSystemProcessInformationClass =
        static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(5);
    constexpr ULONG kThreadInfoTag = 'hTwW';
}


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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: invalid params (request=%p pid=%u tid=%u)\n",
            request, request ? request->pid : 0, request ? request->tid : 0);
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: PID=%u TID=%u %s mask=0x%llX\n",
        request->pid, request->tid, request->should_set ? "SET" : "GET", request->register_mask);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: func ptrs PsLookupProcess=%p PsLookupThread=%p PsGetCtx=%p PsSetCtx=%p ObDeref=%p\n",
        _PsLookupProcessByProcessId, _PsLookupThreadByThreadId,
        _PsGetContextThread, _PsSetContextThread, _ObfDereferenceObject);

    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_PsGetContextThread || !_PsSetContextThread ||
        !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: required functions not resolved: PsLookupProcess=%d PsLookupThread=%d PsGetCtx=%d PsSetCtx=%d ObDeref=%d\n",
            _PsLookupProcessByProcessId != nullptr, _PsLookupThreadByThreadId != nullptr,
            _PsGetContextThread != nullptr, _PsSetContextThread != nullptr, _ObfDereferenceObject != nullptr);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: process lookup OK EPROCESS=%p\n", process);

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: thread lookup FAILED TID=%u status=0x%08X\n", request->tid, status);
        _ObfDereferenceObject(process);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: thread lookup OK ETHREAD=%p\n", thread);

    // Verify the thread belongs to the correct process
    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: WARNING thread EPROCESS=%p != target EPROCESS=%p\n",
                thread_process, process);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: thread belongs to correct process confirmed\n");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: exception verifying thread ownership\n");
    }

    dbg_guard::timing_scatter();

    // Log current IRQL and thread state for diagnostics
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: current IRQL=%u calling thread=%p\n",
        (ULONG)KeGetCurrentIrql(), PsGetCurrentThread());

    // PsGetContextThread/PsSetContextThread use APC-based context exchange.
    // The target thread MUST be suspended for the APC to deliver reliably.
    // Without suspension, PsGetContextThread returns STATUS_UNSUCCESSFUL (0xC0000001)
    // because the kernel APC cannot fire on an actively running thread.
    HANDLE ctx_thread_handle = nullptr;
    BOOLEAN ctx_thread_suspended = FALSE;

    if (_ObOpenObjectByPointer && _ZwClose) {
        NTSTATUS open_status = _ObOpenObjectByPointer(
            thread,
            OBJ_KERNEL_HANDLE,
            nullptr,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            *PsThreadType,
            KernelMode,
            &ctx_thread_handle);

        if (NT_SUCCESS(open_status) && ctx_thread_handle) {
            ULONG prev_count = 0;
            NTSTATUS suspend_status = STATUS_PROCEDURE_NOT_FOUND;

            if (_PsSuspendThread) {
                suspend_status = _PsSuspendThread(thread, &prev_count);
            } else if (_ZwSuspendThread) {
                suspend_status = _ZwSuspendThread(ctx_thread_handle, &prev_count);
            } else if (ssdt_resolver::resolve_suspend_resume()) {
                suspend_status = ssdt_resolver::call_NtSuspendThread(ctx_thread_handle, &prev_count);
            }

            if (NT_SUCCESS(suspend_status)) {
                ctx_thread_suspended = TRUE;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: suspended thread TID=%u prev_count=%u\n",
                    request->tid, prev_count);
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: suspend FAILED TID=%u status=0x%08X\n",
                    request->tid, suspend_status);
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: ObOpenObjectByPointer FAILED status=0x%08X\n", open_status);
        }
    }

    CONTEXT ctx;
    strong::kmemset(&ctx, 0, sizeof(ctx));
    BOOLEAN use_nt_context = (ctx_thread_handle != nullptr) && ssdt_resolver::resolve_thread_context();

    if (request->should_set == 0) {

        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (use_nt_context) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET: calling NtGetContextThread(handle=%p, ctx=%p) ContextFlags=0x%X\n",
                ctx_thread_handle, &ctx, ctx.ContextFlags);
            status = ssdt_resolver::call_NtGetContextThread(ctx_thread_handle, &ctx);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET: calling PsGetContextThread(thread=%p, ctx=%p, mode=KernelMode) ContextFlags=0x%X\n",
                thread, &ctx, ctx.ContextFlags);
            status = _PsGetContextThread(thread, &ctx, KernelMode);
        }

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET SUCCESS: RIP=0x%llX RSP=0x%llX RAX=0x%llX RBX=0x%llX\n",
                ctx.Rip, ctx.Rsp, ctx.Rax, ctx.Rbx);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET SUCCESS: DR0=0x%llX DR1=0x%llX DR2=0x%llX DR3=0x%llX DR6=0x%llX DR7=0x%llX\n",
                ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET SUCCESS: CS=0x%X SS=0x%X Flags=0x%X ContextFlags=0x%X\n",
                ctx.SegCs, ctx.SegSs, ctx.EFlags, ctx.ContextFlags);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET FAILED: PsGetContextThread returned 0x%08X for TID=%u ETHREAD=%p\n",
                status, request->tid, thread);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx GET FAILED: ContextFlags after call=0x%X (requested CONTEXT_FULL|CONTEXT_DEBUG_REGISTERS=0x%X)\n",
                ctx.ContextFlags, (ULONG)(CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS));
        }
    }
    else {

        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: first reading current context from TID=%u\n", request->tid);
        if (use_nt_context) {
            status = ssdt_resolver::call_NtGetContextThread(ctx_thread_handle, &ctx);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: NtGetContextThread status=0x%08X (for reading before set)\n", status);
        } else {
            status = _PsGetContextThread(thread, &ctx, KernelMode);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: PsGetContextThread status=0x%08X (for reading before set)\n", status);
        }

        if (NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: current RIP=0x%llX RSP=0x%llX before applying mask=0x%llX\n",
                ctx.Rip, ctx.Rsp, request->register_mask);

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: calling %s ContextFlags=0x%X\n",
                use_nt_context ? "NtSetContextThread" : "PsSetContextThread", ctx.ContextFlags);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: values to write: RIP=0x%llX RSP=0x%llX DR0=0x%llX DR7=0x%llX\n",
                ctx.Rip, ctx.Rsp, ctx.Dr0, ctx.Dr7);
            status = use_nt_context
                ? ssdt_resolver::call_NtSetContextThread(ctx_thread_handle, &ctx)
                : _PsSetContextThread(thread, &ctx, KernelMode);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET: final set mask=0x%llX status=0x%08X\n",
                mask, status);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx SET FAILED: could not read current context first, status=0x%08X\n", status);
        }
    }

    // Resume the thread if we suspended it for context access
    if (ctx_thread_suspended && ctx_thread_handle) {
        ULONG prev_count = 0;
        NTSTATUS resume_status = STATUS_PROCEDURE_NOT_FOUND;

        if (_PsResumeThread) {
            resume_status = _PsResumeThread(thread, &prev_count);
        } else if (_ZwResumeThread) {
            resume_status = _ZwResumeThread(ctx_thread_handle, &prev_count);
        } else if (ssdt_resolver::g_NtResumeThread) {
            resume_status = ssdt_resolver::call_NtResumeThread(ctx_thread_handle, &prev_count);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: resumed thread TID=%u prev_count=%u resume_status=0x%08X\n",
            request->tid, prev_count, resume_status);
    }
    if (ctx_thread_handle) {
        _ZwClose(ctx_thread_handle);
    }

    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadCtx: completed status=0x%08X\n", status);

    return status;
}


NTSTATUS functions::handle_thread_enum(p_thread_enum request) {
    if (!request || request->pid == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: PID=%u\n", request->pid);
    if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: required functions not resolved\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
        return status;
    }

    dbg_guard::timing_scatter();

    ULONG required_length = 0;
    status = ZwQuerySystemInformation(
        sysinfo_guard::kSystemProcessInformationClass,
        nullptr,
        0,
        &required_length);

    if (status != STATUS_INFO_LENGTH_MISMATCH || required_length < sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL)) {
        _ObfDereferenceObject(process);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: initial query FAILED status=0x%08X len=0x%X\n", status, required_length);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    ULONG buffer_length = required_length + 0x4000;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
    if (!buffer) {
        _ObfDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        status = ZwQuerySystemInformation(
            sysinfo_guard::kSystemProcessInformationClass,
            buffer,
            buffer_length,
            &required_length);

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }

        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        buffer_length = required_length + 0x4000;
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
        if (!buffer) {
            _ObfDereferenceObject(process);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        _ObfDereferenceObject(process);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: query FAILED status=0x%08X\n", status);
        return status;
    }

    UINT32 count = 0;
    BOOLEAN process_found = FALSE;
    PUCHAR cursor = (PUCHAR)buffer;

    while (TRUE) {
        auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_LOCAL>(cursor);
        if ((UINT32)(ULONG_PTR)info->UniqueProcessId == request->pid) {
            process_found = TRUE;
            auto threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION_LOCAL>(cursor + sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL));

            for (ULONG index = 0; index < info->NumberOfThreads && count < MAX_ENUM_THREADS; ++index) {
                request->entries[count].tid = (UINT32)(ULONG_PTR)threads[index].ClientId.UniqueThread;
                request->entries[count].state = threads[index].ThreadState;
                request->entries[count].rip = (UINT64)threads[index].StartAddress;
                count++;
            }
            break;
        }

        if (info->NextEntryOffset == 0) {
            break;
        }

        cursor += info->NextEntryOffset;
    }

    ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);

    _ObfDereferenceObject(process);
    request->thread_count = count;

    if (!process_found) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: PID=%u not present in system snapshot\n", request->pid);
        return STATUS_NOT_FOUND;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ThreadEnum: found %u threads\n", count);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_suspend_resume_thread(p_suspend_resume_thread request) {
    if (!request || request->tid == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: TID=%u %s\n",
        request->tid, request->should_resume ? "RESUME" : "SUSPEND");

    BOOLEAN use_ps = (_PsSuspendThread != nullptr && _PsResumeThread != nullptr);
    BOOLEAN use_zw = (_ObOpenObjectByPointer != nullptr && _ZwSuspendThread != nullptr && _ZwResumeThread != nullptr && _ZwClose != nullptr);
    BOOLEAN use_ssdt = FALSE;

    if (!use_ps && !use_zw) {
        // Neither Ps nor Zw functions available - try SSDT-based resolution
        // This resolves NtSuspendThread/NtResumeThread by reading syscall indices
        // from ntdll in the calling process and looking up the SSDT
        if (_ObOpenObjectByPointer != nullptr && _ZwClose != nullptr &&
            ssdt_resolver::resolve_suspend_resume()) {
            use_ssdt = TRUE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: using SSDT-resolved NtSuspendThread/NtResumeThread\n");
        }
    }

    if (!_PsLookupThreadByThreadId || !_ObfDereferenceObject || (!use_ps && !use_zw && !use_ssdt)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: required functions not resolved (Ps=%d Zw=%d Ssdt=%d)\n", use_ps, use_zw, use_ssdt);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PETHREAD thread = nullptr;
    NTSTATUS status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: thread lookup FAILED TID=%u status=0x%08X\n", request->tid, status);
        return status;
    }

    ULONG prev_count = 0;

    if (use_ps) {
        if (request->should_resume == 0) {
            status = _PsSuspendThread(thread, &prev_count);
        }
        else {
            status = _PsResumeThread(thread, &prev_count);
        }
    }
    else {
        // Zw or SSDT path: both need a thread handle via ObOpenObjectByPointer
        HANDLE thread_handle = nullptr;
        status = _ObOpenObjectByPointer(
            thread,
            OBJ_KERNEL_HANDLE,
            nullptr,
            THREAD_SUSPEND_RESUME,
            *PsThreadType,
            KernelMode,
            &thread_handle);

        if (NT_SUCCESS(status) && thread_handle) {
            if (use_zw) {
                if (request->should_resume == 0) {
                    status = _ZwSuspendThread(thread_handle, &prev_count);
                }
                else {
                    status = _ZwResumeThread(thread_handle, &prev_count);
                }
            }
            else {
                // SSDT path: call NtSuspendThread/NtResumeThread resolved from SSDT
                // with PreviousMode temporarily set to KernelMode so kernel pointers
                // pass the Nt probe checks
                if (request->should_resume == 0) {
                    status = ssdt_resolver::call_NtSuspendThread(thread_handle, &prev_count);
                }
                else {
                    status = ssdt_resolver::call_NtResumeThread(thread_handle, &prev_count);
                }
            }
            _ZwClose(thread_handle);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: ObOpenObjectByPointer FAILED status=0x%08X\n", status);
        }
    }

    request->previous_count = prev_count;
    _ObfDereferenceObject(thread);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SuspendResume: prev_count=%u status=0x%08X\n", prev_count, status);

    return status;
}


NTSTATUS functions::handle_query_memory(p_query_memory request) {
    if (!request || request->pid == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] QueryMem: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] QueryMem: PID=%u addr=0x%llX\n",
        request->pid, request->address);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] QueryMem: base=0x%llX size=0x%llX state=0x%X protect=0x%X\n",
            (UINT64)mbi.BaseAddress, (UINT64)mbi.RegionSize, mbi.State, mbi.Protect);
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] QueryMem: status=0x%08X\n", status);

    return status;
}


NTSTATUS functions::handle_protect_memory(p_protect_memory request) {
    if (!request || request->pid == 0 || request->size == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ProtectMem: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ProtectMem: PID=%u addr=0x%llX size=0x%llX new_protect=0x%X\n",
        request->pid, request->address, request->size, request->new_protect);
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwProtectVirtualMemory || !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ProtectMem: required functions not resolved\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ProtectMem: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ProtectMem: old_protect=0x%X status=0x%08X\n", old_protect, status);
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_enum_regions(p_enum_regions request) {
    if (!request || request->pid == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] EnumRegions: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] EnumRegions: PID=%u start=0x%llX\n",
        request->pid, request->start_address);
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory || !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] EnumRegions: required functions not resolved\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] EnumRegions: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] EnumRegions: found %u regions\n", count);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_read_peb(p_read_peb request) {
    if (!request || request->pid == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: PID=%u\n", request->pid);
    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: required functions not resolved\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
        return status;
    }

    PVOID peb = (PVOID)_PsGetProcessPeb(process);
    if (!peb) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: PEB is NULL for PID=%u\n", request->pid);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: peb=0x%llX image_base=0x%llX debugged=%u heap=0x%llX\n",
            (UINT64)peb, request->image_base, request->being_debugged, request->process_heap);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ReadPEB: access violation reading PEB for PID=%u\n", request->pid);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SpoofDebug: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SpoofDebug: PID=%u\n", request->pid);
    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SpoofDebug: required functions not resolved\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SpoofDebug: process lookup FAILED PID=%u status=0x%08X\n", request->pid, status);
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] SpoofDebug: cleared_flags=0x%X\n", cleared);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_get_module_export(p_module_export request) {
    if (!request || request->module_base == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ModExport: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (request->dtb == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ModExport: DTB is zero\n");
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ModExport: DTB=0x%llX base=0x%llX name=%s\n",
        request->dtb, request->module_base, request->export_name);

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ModExport: FOUND addr=0x%llX ordinal=%u\n",
                base + func_rva, ordinal_base + ordinal);
            return STATUS_SUCCESS;
        }
    }

    request->resolved_address = 0;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] ModExport: NOT FOUND\n");
    return STATUS_NOT_FOUND;
}


NTSTATUS functions::handle_virt_to_phys(p_virt_to_phys request) {
    if (!request || request->dtb == 0 || request->virtual_address == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] VirtToPhys: invalid params\n");
        return STATUS_INVALID_PARAMETER;
    }

    UINT64 physical = strong::translate_virtual_address(request->dtb, request->virtual_address);
    request->physical_address = physical;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho] VirtToPhys: DTB=0x%llX virt=0x%llX phys=0x%llX\n",
        request->dtb, request->virtual_address, physical);

    return (physical != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
