#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"

#ifndef WW_LOG
#define WW_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] " fmt "\n", __VA_ARGS__)
#define WW_LOG0(msg) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WhosWho-KM] %s\n", msg)
#endif

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


namespace trapframe_ctx {

    constexpr ULONG KTHREAD_TRAPFRAME_OFFSET = 0x90;
    constexpr ULONG KTHREAD_DEBUG_ACTIVE     = 0x03;
    constexpr ULONG DR7_USER_MASK            = 0xFFFF0355;
    constexpr ULONG DR7_ACTIVE_BITS          = 0x0355;


    constexpr ULONG TF_RAX    = 0x30;
    constexpr ULONG TF_RCX    = 0x38;
    constexpr ULONG TF_RDX    = 0x40;
    constexpr ULONG TF_R8     = 0x48;
    constexpr ULONG TF_R9     = 0x50;
    constexpr ULONG TF_R10    = 0x58;
    constexpr ULONG TF_R11    = 0x60;
    constexpr ULONG TF_DR0    = 0xD8;
    constexpr ULONG TF_DR1    = 0xE0;
    constexpr ULONG TF_DR2    = 0xE8;
    constexpr ULONG TF_DR3    = 0xF0;
    constexpr ULONG TF_DR6    = 0xF8;
    constexpr ULONG TF_DR7    = 0x100;
    constexpr ULONG TF_RBX    = 0x140;
    constexpr ULONG TF_RDI    = 0x148;
    constexpr ULONG TF_RSI    = 0x150;
    constexpr ULONG TF_RBP    = 0x158;
    constexpr ULONG TF_RIP    = 0x168;
    constexpr ULONG TF_SEGCS  = 0x170;
    constexpr ULONG TF_EFLAGS = 0x178;
    constexpr ULONG TF_RSP    = 0x180;
    constexpr ULONG TF_SEGSS  = 0x188;

    NTSTATUS get_context(PETHREAD thread, p_thread_ctx request) {
        __try {
            PUCHAR kthread = (PUCHAR)thread;
            PUCHAR tf = *(PUCHAR*)(kthread + KTHREAD_TRAPFRAME_OFFSET);

            WW_LOG("trapframe_ctx::get_context: KTHREAD=0x%p TrapFrame=0x%p", kthread, tf);

            if (!tf || !_MmIsAddressValid(tf) || !_MmIsAddressValid(tf + TF_SEGSS + 7)) {
                WW_LOG("trapframe_ctx::get_context: TrapFrame invalid (ptr=0x%p valid=%u)",
                    tf, tf ? (_MmIsAddressValid(tf) ? 1u : 0u) : 0u);
                return STATUS_UNSUCCESSFUL;
            }


            UINT16 cs_check = *(UINT16*)(tf + TF_SEGCS);
            WW_LOG("trapframe_ctx::get_context: CS=0x%X (need 0x33 for user-mode)", cs_check);
            if (cs_check != 0x33) {
                PUCHAR user_tf = nullptr;

                for (ULONG off = 0x190; off < 0x4000; off += 8) {
                    PUCHAR candidate = tf + off;
                    if (!_MmIsAddressValid(candidate + TF_SEGSS + 7))
                        break;
                    UINT16 cand_cs  = *(UINT16*)(candidate + TF_SEGCS);
                    UINT16 cand_ss  = *(UINT16*)(candidate + TF_SEGSS);
                    UINT64 cand_rip = *(UINT64*)(candidate + TF_RIP);
                    UINT64 cand_rsp = *(UINT64*)(candidate + TF_RSP);

                    if (cand_cs == 0x33 && cand_ss == 0x2B &&
                        cand_rip < 0x7FFFFFFFFFFULL && cand_rsp < 0x7FFFFFFFFFFULL) {
                        user_tf = candidate;
                        break;
                    }
                }
                if (user_tf) {
                    tf = user_tf;
                } else {
                }
            }

            request->rax = *(UINT64*)(tf + TF_RAX);
            request->rcx = *(UINT64*)(tf + TF_RCX);
            request->rdx = *(UINT64*)(tf + TF_RDX);
            request->r8  = *(UINT64*)(tf + TF_R8);
            request->r9  = *(UINT64*)(tf + TF_R9);
            request->r10 = *(UINT64*)(tf + TF_R10);
            request->r11 = *(UINT64*)(tf + TF_R11);
            request->rdi = *(UINT64*)(tf + TF_RDI);
            request->rsi = *(UINT64*)(tf + TF_RSI);
            request->rbp = *(UINT64*)(tf + TF_RBP);
            request->rip = *(UINT64*)(tf + TF_RIP);
            request->rsp = *(UINT64*)(tf + TF_RSP);
            request->rflags = (UINT64)*(UINT32*)(tf + TF_EFLAGS);
            request->cs  = (UINT64)*(UINT16*)(tf + TF_SEGCS);
            request->ss  = (UINT64)*(UINT16*)(tf + TF_SEGSS);

            UINT8 debug_active = *(volatile UINT8*)(kthread + KTHREAD_DEBUG_ACTIVE);
            if (debug_active & 0x01) {
                request->dr0 = *(UINT64*)(tf + TF_DR0);
                request->dr1 = *(UINT64*)(tf + TF_DR1);
                request->dr2 = *(UINT64*)(tf + TF_DR2);
                request->dr3 = *(UINT64*)(tf + TF_DR3);
                request->dr6 = *(UINT64*)(tf + TF_DR6);
                request->dr7 = *(UINT64*)(tf + TF_DR7);
            } else {
                request->dr0 = 0; request->dr1 = 0;
                request->dr2 = 0; request->dr3 = 0;
                request->dr6 = 0; request->dr7 = 0;
                WW_LOG("trapframe_ctx::get_context: DebugActive=0x%02X, DR values not saved by kernel", debug_active);
            }


            request->rbx = *(UINT64*)(tf + TF_RBX);
            request->r12 = 0;
            request->r13 = 0;
            request->r14 = 0;
            request->r15 = 0;


            return STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    NTSTATUS set_context(PETHREAD thread, p_thread_ctx request) {
        __try {
            PUCHAR kthread = (PUCHAR)thread;
            PUCHAR tf = *(PUCHAR*)(kthread + KTHREAD_TRAPFRAME_OFFSET);

            if (!tf || !_MmIsAddressValid(tf) || !_MmIsAddressValid(tf + TF_SEGSS + 7)) {
                return STATUS_UNSUCCESSFUL;
            }


            UINT16 cs_check = *(UINT16*)(tf + TF_SEGCS);
            if (cs_check != 0x33) {
                for (ULONG off = 0x190; off < 0x4000; off += 8) {
                    PUCHAR candidate = tf + off;
                    if (!_MmIsAddressValid(candidate + TF_SEGSS + 7))
                        break;
                    UINT16 cand_cs  = *(UINT16*)(candidate + TF_SEGCS);
                    UINT16 cand_ss  = *(UINT16*)(candidate + TF_SEGSS);
                    UINT64 cand_rip = *(UINT64*)(candidate + TF_RIP);
                    UINT64 cand_rsp = *(UINT64*)(candidate + TF_RSP);
                    if (cand_cs == 0x33 && cand_ss == 0x2B &&
                        cand_rip < 0x7FFFFFFFFFFULL && cand_rsp < 0x7FFFFFFFFFFULL) {
                        tf = candidate;
                        break;
                    }
                }
            }

            UINT64 mask = request->register_mask;

            if (mask & (1ULL << 0))  *(UINT64*)(tf + TF_RAX) = request->rax;
            if (mask & (1ULL << 2))  *(UINT64*)(tf + TF_RCX) = request->rcx;
            if (mask & (1ULL << 3))  *(UINT64*)(tf + TF_RDX) = request->rdx;
            if (mask & (1ULL << 4))  *(UINT64*)(tf + TF_RSI) = request->rsi;
            if (mask & (1ULL << 5))  *(UINT64*)(tf + TF_RDI) = request->rdi;
            if (mask & (1ULL << 6))  *(UINT64*)(tf + TF_RBP) = request->rbp;
            if (mask & (1ULL << 7))  *(UINT64*)(tf + TF_RSP) = request->rsp;
            if (mask & (1ULL << 8))  *(UINT64*)(tf + TF_R8) = request->r8;
            if (mask & (1ULL << 9))  *(UINT64*)(tf + TF_R9) = request->r9;
            if (mask & (1ULL << 10)) *(UINT64*)(tf + TF_R10) = request->r10;
            if (mask & (1ULL << 11)) *(UINT64*)(tf + TF_R11) = request->r11;
            if (mask & (1ULL << 1))  *(UINT64*)(tf + TF_RBX) = request->rbx;

            if (mask & (1ULL << 16)) *(UINT64*)(tf + TF_RIP) = request->rip;
            if (mask & (1ULL << 17)) *(UINT32*)(tf + TF_EFLAGS) = (UINT32)request->rflags;
            if (mask & (1ULL << 18)) *(UINT64*)(tf + TF_DR0) = request->dr0;
            if (mask & (1ULL << 19)) *(UINT64*)(tf + TF_DR1) = request->dr1;
            if (mask & (1ULL << 20)) *(UINT64*)(tf + TF_DR2) = request->dr2;
            if (mask & (1ULL << 21)) *(UINT64*)(tf + TF_DR3) = request->dr3;
            if (mask & (1ULL << 22)) *(UINT64*)(tf + TF_DR6) = request->dr6;
            if (mask & (1ULL << 23)) {
                UINT64 sanitized = request->dr7 & DR7_USER_MASK;
                *(UINT64*)(tf + TF_DR7) = sanitized;
            }

            constexpr UINT64 DR_MASK = (1ULL<<18)|(1ULL<<19)|(1ULL<<20)|(1ULL<<21)|(1ULL<<22)|(1ULL<<23);
            if (mask & DR_MASK) {
                UINT64 dr7_val = *(UINT64*)(tf + TF_DR7);
                volatile LONG* header = reinterpret_cast<volatile LONG*>(kthread);
                if (dr7_val & DR7_ACTIVE_BITS)
                    _interlockedbittestandset(header, 24);
                else
                    _interlockedbittestandreset(header, 24);
                WW_LOG("trapframe_ctx::set_context: DR7=0x%llX DebugActive %s",
                    dr7_val, (dr7_val & DR7_ACTIVE_BITS) ? "SET" : "CLEAR");
            }

            return STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
}


NTSTATUS functions::handle_thread_ctx(p_thread_ctx request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        WW_LOG("handle_thread_ctx: bad params (pid=%u tid=%u)",
            request ? request->pid : 0, request ? request->tid : 0);
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_thread_ctx: pid=%u tid=%u set=%u mask=0x%llX",
        request->pid, request->tid, request->should_set, request->register_mask);


    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
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


    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            return STATUS_INVALID_CID;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    dbg_guard::timing_scatter();


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
                WW_LOG("handle_thread_ctx: suspend via PsSuspendThread status=0x%08X prev=%u", suspend_status, prev_count);
            } else if (_ZwSuspendThread) {
                suspend_status = _ZwSuspendThread(ctx_thread_handle, &prev_count);
                WW_LOG("handle_thread_ctx: suspend via ZwSuspendThread status=0x%08X prev=%u", suspend_status, prev_count);
            } else if (ssdt_resolver::resolve_suspend_resume()) {
                suspend_status = ssdt_resolver::call_NtSuspendThread(ctx_thread_handle, &prev_count);
                WW_LOG("handle_thread_ctx: suspend via SSDT NtSuspendThread status=0x%08X prev=%u", suspend_status, prev_count);
            } else {
                WW_LOG0("handle_thread_ctx: NO suspension method available");
            }

            if (NT_SUCCESS(suspend_status)) {
                ctx_thread_suspended = TRUE;
            } else {
                WW_LOG("handle_thread_ctx: suspension FAILED status=0x%08X", suspend_status);
            }
        } else {
            WW_LOG("handle_thread_ctx: ObOpenObjectByPointer failed status=0x%08X", open_status);
        }
    }

    CONTEXT ctx;
    strong::kmemset(&ctx, 0, sizeof(ctx));


    BOOLEAN has_ps_get = (_PsGetContextThread != nullptr);
    BOOLEAN has_ps_set = (_PsSetContextThread != nullptr);
    BOOLEAN has_nt_context = (ctx_thread_handle != nullptr) && ssdt_resolver::resolve_thread_context();

    WW_LOG("handle_thread_ctx: capabilities: ps_get=%u ps_set=%u nt_ctx=%u suspended=%u handle=0x%p",
        has_ps_get, has_ps_set, has_nt_context, ctx_thread_suspended, ctx_thread_handle);

    if (request->should_set == 0) {

        WW_LOG0("handle_thread_ctx: GET — trying KTRAP_FRAME first");
        status = trapframe_ctx::get_context(thread, request);

        if (!NT_SUCCESS(status)) {
            WW_LOG("handle_thread_ctx: trapframe GET failed 0x%08X, trying APC fallback", status);
            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            status = STATUS_PROCEDURE_NOT_FOUND;
            if (has_ps_get) {
                status = _PsGetContextThread(thread, &ctx, KernelMode);
                WW_LOG("handle_thread_ctx: PsGetContextThread status=0x%08X rip=0x%llX",
                    status, NT_SUCCESS(status) ? ctx.Rip : 0ULL);
            }

            if (!NT_SUCCESS(status) && has_nt_context) {
                status = ssdt_resolver::call_NtGetContextThread(ctx_thread_handle, &ctx);
                WW_LOG("handle_thread_ctx: SSDT NtGetContextThread status=0x%08X rip=0x%llX",
                    status, NT_SUCCESS(status) ? ctx.Rip : 0ULL);
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
            }
        } else {
            WW_LOG("handle_thread_ctx: trapframe GET OK rip=0x%llX rsp=0x%llX", request->rip, request->rsp);
        }
    }
    else {

        WW_LOG0("handle_thread_ctx: SET — trying KTRAP_FRAME first");
        status = trapframe_ctx::set_context(thread, request);

        if (!NT_SUCCESS(status)) {
            WW_LOG("handle_thread_ctx: trapframe SET failed 0x%08X, trying APC fallback", status);

            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
            NTSTATUS get_status = STATUS_PROCEDURE_NOT_FOUND;
            if (has_ps_get) {
                get_status = _PsGetContextThread(thread, &ctx, KernelMode);
            }
            if (!NT_SUCCESS(get_status) && has_nt_context) {
                get_status = ssdt_resolver::call_NtGetContextThread(ctx_thread_handle, &ctx);
            }

            if (NT_SUCCESS(get_status)) {
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
                status = STATUS_PROCEDURE_NOT_FOUND;
                if (has_ps_set) {
                    status = _PsSetContextThread(thread, &ctx, KernelMode);
                }
                if (!NT_SUCCESS(status) && has_nt_context) {
                    status = ssdt_resolver::call_NtSetContextThread(ctx_thread_handle, &ctx);
                }
            }
        } else {
            WW_LOG0("handle_thread_ctx: trapframe SET OK");
        }
    }


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

    }
    if (ctx_thread_handle) {
        _ZwClose(ctx_thread_handle);
    }

    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    WW_LOG("handle_thread_ctx: DONE status=0x%08X (rip=0x%llX rsp=0x%llX)",
        status, request->rip, request->rsp);

    return status;
}


NTSTATUS functions::handle_thread_enum(p_thread_enum request) {
    if (!request || request->pid == 0) {
        WW_LOG("handle_thread_enum: bad params (pid=%u)", request ? request->pid : 0);
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_thread_enum: pid=%u", request->pid);

    if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject) {
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

    ULONG required_length = 0;
    status = ZwQuerySystemInformation(
        sysinfo_guard::kSystemProcessInformationClass,
        nullptr,
        0,
        &required_length);

    if (status != STATUS_INFO_LENGTH_MISMATCH || required_length < sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL)) {
        _ObfDereferenceObject(process);
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
        WW_LOG("handle_thread_enum: process pid=%u NOT FOUND in system info", request->pid);
        return STATUS_NOT_FOUND;
    }

    WW_LOG("handle_thread_enum: SUCCESS pid=%u count=%u", request->pid, count);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_suspend_resume_thread(p_suspend_resume_thread request) {
    if (!request || request->tid == 0) {
        WW_LOG("handle_suspend_resume: bad params (tid=%u)", request ? request->tid : 0);
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_suspend_resume: tid=%u resume=%u", request->tid, request->should_resume);


    BOOLEAN use_ps = (_PsSuspendThread != nullptr && _PsResumeThread != nullptr);
    BOOLEAN use_zw = (_ObOpenObjectByPointer != nullptr && _ZwSuspendThread != nullptr && _ZwResumeThread != nullptr && _ZwClose != nullptr);
    BOOLEAN use_ssdt = FALSE;

    if (!use_ps && !use_zw) {


        if (_ObOpenObjectByPointer != nullptr && _ZwClose != nullptr &&
            ssdt_resolver::resolve_suspend_resume()) {
            use_ssdt = TRUE;
        }
    }

    if (!_PsLookupThreadByThreadId || !_ObfDereferenceObject || (!use_ps && !use_zw && !use_ssdt)) {
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

    if (use_ps) {
        if (request->should_resume == 0) {
            status = _PsSuspendThread(thread, &prev_count);
        }
        else {
            status = _PsResumeThread(thread, &prev_count);
        }
    }
    else {

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
        }
    }

    request->previous_count = prev_count;
    _ObfDereferenceObject(thread);

    WW_LOG("handle_suspend_resume: DONE status=0x%08X prev_count=%u", status, prev_count);

    return status;
}


NTSTATUS functions::handle_query_memory(p_query_memory request) {
    if (!request || request->pid == 0) {
        WW_LOG("handle_query_memory: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_query_memory: pid=%u addr=0x%llX", request->pid, request->address);

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

    WW_LOG("handle_query_memory: status=0x%08X state=0x%X protect=0x%X size=0x%llX",
        status, request->state, request->protect, request->region_size);

    return status;
}


NTSTATUS functions::handle_protect_memory(p_protect_memory request) {
    if (!request || request->pid == 0 || request->size == 0) {
        WW_LOG0("handle_protect_memory: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_protect_memory: pid=%u addr=0x%llX size=0x%llX new_prot=0x%X",
        request->pid, request->address, request->size, request->new_protect);

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
        WW_LOG0("handle_enum_regions: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_enum_regions: pid=%u start=0x%llX max=0x%llX",
        request->pid, request->start_address, request->max_address);

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

    WW_LOG("handle_enum_regions: DONE pid=%u count=%u", request->pid, count);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_read_peb(p_read_peb request) {
    if (!request || request->pid == 0) {
        WW_LOG0("handle_read_peb: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_read_peb: pid=%u", request->pid);

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
        WW_LOG0("handle_spoof_debug: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_spoof_debug: pid=%u", request->pid);

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

    WW_LOG("handle_spoof_debug: DONE pid=%u cleared=0x%X", request->pid, cleared);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_get_module_export(p_module_export request) {
    if (!request || request->module_base == 0) {
        WW_LOG0("handle_get_module_export: bad params");
        return STATUS_INVALID_PARAMETER;
    }
    if (request->dtb == 0) {
        WW_LOG0("handle_get_module_export: dtb=0");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_get_module_export: base=0x%llX dtb=0x%llX name=%.32s",
        request->module_base, request->dtb, request->export_name);


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
        WW_LOG0("handle_virt_to_phys: bad params");
        return STATUS_INVALID_PARAMETER;
    }

    WW_LOG("handle_virt_to_phys: dtb=0x%llX vaddr=0x%llX", request->dtb, request->virtual_address);

    UINT64 physical = strong::translate_virtual_address(request->dtb, request->virtual_address);
    request->physical_address = physical;

    WW_LOG("handle_virt_to_phys: phys=0x%llX %s", physical, physical ? "SUCCESS" : "FAIL");

    return (physical != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
