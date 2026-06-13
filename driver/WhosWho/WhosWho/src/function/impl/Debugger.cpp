#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"
#include "../AntiDebug.h"
#include "../SentinelBridge.h"
#include "../Dispatcher.h"
#include "driver/FileHandleScanner.h"

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

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

namespace tctx_diag {
    constexpr ULONG kContextBaseFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    constexpr ULONG kContextDebugFlags = kContextBaseFlags | CONTEXT_DEBUG_REGISTERS;
    constexpr UINT64 kDebugRegisterMask =
        (1ULL << 18) | (1ULL << 19) | (1ULL << 20) |
        (1ULL << 21) | (1ULL << 22) | (1ULL << 23);

    struct os_version_snapshot_t {
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        ULONG major = 0;
        ULONG minor = 0;
        ULONG build = 0;
    };

    struct thread_snapshot_t {
        NTSTATUS status = STATUS_NOT_FOUND;
        BOOLEAN found = FALSE;
        ULONG scanned_processes = 0;
        ULONG scanned_threads = 0;
        ULONG process_thread_count = 0;
        ULONG thread_state = 0xFFFFFFFFu;
        ULONG wait_reason = 0xFFFFFFFFu;
        PVOID start_address = nullptr;
        KPRIORITY priority = 0;
        LONG base_priority = 0;
        HANDLE client_pid = nullptr;
        HANDLE client_tid = nullptr;
    };

    __forceinline BOOLEAN core_registers_present(const CONTEXT& ctx) {
        return ctx.Rip != 0 && ctx.Rsp != 0;
    }

    __forceinline BOOLEAN debug_registers_requested(UINT64 mask) {
        return (mask & kDebugRegisterMask) != 0;
    }

    __forceinline ULONGLONG elapsed_ms(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart) {
            return 0;
        }
        return static_cast<ULONGLONG>(((now.QuadPart - start.QuadPart) * 1000) / freq.QuadPart);
    }

    os_version_snapshot_t query_os_version() {
        os_version_snapshot_t out;
        if (!_RtlGetVersion) {
            return out;
        }
        RTL_OSVERSIONINFOW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        out.status = _RtlGetVersion(&version);
        if (NT_SUCCESS(out.status)) {
            out.major = version.dwMajorVersion;
            out.minor = version.dwMinorVersion;
            out.build = version.dwBuildNumber;
        }
        return out;
    }

    thread_snapshot_t query_thread_snapshot(UINT32 pid, UINT32 tid) {
        thread_snapshot_t out;
        if (pid == 0 || tid == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) {
            out.status = STATUS_INVALID_PARAMETER;
            return out;
        }

        ULONG required_length = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            sysinfo_guard::kSystemProcessInformationClass,
            nullptr,
            0,
            &required_length);
        if (status != STATUS_INFO_LENGTH_MISMATCH || required_length < sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL)) {
            out.status = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
            return out;
        }

        ULONG buffer_length = required_length + 0x4000;
        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
        if (!buffer) {
            out.status = STATUS_INSUFFICIENT_RESOURCES;
            return out;
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
                out.status = STATUS_INSUFFICIENT_RESOURCES;
                return out;
            }
        }

        if (!NT_SUCCESS(status)) {
            out.status = status;
            ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
            return out;
        }

        PUCHAR cursor = static_cast<PUCHAR>(buffer);
        while (TRUE) {
            auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_LOCAL>(cursor);
            out.scanned_processes++;
            if ((UINT32)(ULONG_PTR)info->UniqueProcessId == pid) {
                out.process_thread_count = info->NumberOfThreads;
                auto threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION_LOCAL>(cursor + sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL));
                for (ULONG index = 0; index < info->NumberOfThreads; ++index) {
                    out.scanned_threads++;
                    if ((UINT32)(ULONG_PTR)threads[index].ClientId.UniqueThread != tid) {
                        continue;
                    }
                    out.found = TRUE;
                    out.status = STATUS_SUCCESS;
                    out.thread_state = threads[index].ThreadState;
                    out.wait_reason = threads[index].WaitReason;
                    out.start_address = threads[index].StartAddress;
                    out.priority = threads[index].Priority;
                    out.base_priority = threads[index].BasePriority;
                    out.client_pid = threads[index].ClientId.UniqueProcess;
                    out.client_tid = threads[index].ClientId.UniqueThread;
                    break;
                }
                break;
            }

            if (info->NextEntryOffset == 0) {
                break;
            }
            cursor += info->NextEntryOffset;
        }

        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        return out;
    }

    __forceinline NTSTATUS attach_process(PEPROCESS process, PKAPC_STATE apc_state, PBOOLEAN attached) {
        *attached = FALSE;
        if (!process || !_KeStackAttachProcess || !_KeUnstackDetachProcess || process == PsGetCurrentProcess()) {
            return STATUS_SUCCESS;
        }
        NTSTATUS status = STATUS_SUCCESS;
        __try {
            _KeStackAttachProcess(process, apc_state);
            *attached = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
            *attached = FALSE;
        }
        return status;
    }

    __forceinline void detach_process(PKAPC_STATE apc_state, BOOLEAN attached) {
        if (!attached || !_KeUnstackDetachProcess) {
            return;
        }
        __try {
            _KeUnstackDetachProcess(apc_state);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    __forceinline NTSTATUS call_ps_get(PEPROCESS process, PETHREAD thread, PCONTEXT ctx, BOOLEAN attach, NTSTATUS* attach_status, PBOOLEAN attached) {
        KAPC_STATE apc_state = {};
        *attach_status = attach ? attach_process(process, &apc_state, attached) : STATUS_SUCCESS;
        if (!NT_SUCCESS(*attach_status)) {
            return *attach_status;
        }
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        __try {
            status = _PsGetContextThread(thread, ctx, KernelMode);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        detach_process(&apc_state, *attached);
        return status;
    }

    __forceinline NTSTATUS call_ps_set(PEPROCESS process, PETHREAD thread, PCONTEXT ctx, BOOLEAN attach, NTSTATUS* attach_status, PBOOLEAN attached) {
        KAPC_STATE apc_state = {};
        *attach_status = attach ? attach_process(process, &apc_state, attached) : STATUS_SUCCESS;
        if (!NT_SUCCESS(*attach_status)) {
            return *attach_status;
        }
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        __try {
            status = _PsSetContextThread(thread, ctx, KernelMode);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        detach_process(&apc_state, *attached);
        return status;
    }

    __forceinline void log_context(const char* prefix, const char* phase, const char* source, ULONG attempt, NTSTATUS status, NTSTATUS attach_status, BOOLEAN attached, const CONTEXT& ctx, const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        WW_LOG("TCTX %s phase=%s source=%s attempt=%u status=0x%08X attach_status=0x%08X attached=%u flags=0x%08X rip=0x%llX rsp=0x%llX rbp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX core_valid=%u elapsed_ms=%llu",
            prefix,
            phase,
            source,
            attempt,
            (ULONG)status,
            (ULONG)attach_status,
            attached ? 1u : 0u,
            ctx.ContextFlags,
            (unsigned long long)ctx.Rip,
            (unsigned long long)ctx.Rsp,
            (unsigned long long)ctx.Rbp,
            (unsigned long long)ctx.EFlags,
            (unsigned long long)ctx.Dr0,
            (unsigned long long)ctx.Dr1,
            (unsigned long long)ctx.Dr2,
            (unsigned long long)ctx.Dr3,
            (unsigned long long)ctx.Dr6,
            (unsigned long long)ctx.Dr7,
            core_registers_present(ctx) ? 1u : 0u,
            elapsed_ms(start, freq));
    }
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

    __forceinline ULONGLONG elapsed_ms(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart) {
            return 0;
        }
        return static_cast<ULONGLONG>(((now.QuadPart - start.QuadPart) * 1000) / freq.QuadPart);
    }

    __forceinline void short_context_retry_delay() {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}


namespace trapframe_ctx {

    constexpr ULONG DR7_USER_MASK            = 0xFFFF0355;
    constexpr UINT64 DR7_GLOBAL_ENABLE_BITS  = 0xAAULL;

    __forceinline UINT64 sanitize_user_dr7(UINT64 dr7) {
        return (dr7 & DR7_USER_MASK) & ~DR7_GLOBAL_ENABLE_BITS;
    }

    __forceinline void copy_context_to_request(const CONTEXT& ctx, p_thread_ctx request) {
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

    __forceinline void apply_request_to_context(p_thread_ctx request, PCONTEXT ctx) {
        UINT64 mask = request->register_mask;
        if (mask & (1ULL << 0))  ctx->Rax    = request->rax;
        if (mask & (1ULL << 1))  ctx->Rbx    = request->rbx;
        if (mask & (1ULL << 2))  ctx->Rcx    = request->rcx;
        if (mask & (1ULL << 3))  ctx->Rdx    = request->rdx;
        if (mask & (1ULL << 4))  ctx->Rsi    = request->rsi;
        if (mask & (1ULL << 5))  ctx->Rdi    = request->rdi;
        if (mask & (1ULL << 6))  ctx->Rbp    = request->rbp;
        if (mask & (1ULL << 7))  ctx->Rsp    = request->rsp;
        if (mask & (1ULL << 8))  ctx->R8     = request->r8;
        if (mask & (1ULL << 9))  ctx->R9     = request->r9;
        if (mask & (1ULL << 10)) ctx->R10    = request->r10;
        if (mask & (1ULL << 11)) ctx->R11    = request->r11;
        if (mask & (1ULL << 12)) ctx->R12    = request->r12;
        if (mask & (1ULL << 13)) ctx->R13    = request->r13;
        if (mask & (1ULL << 14)) ctx->R14    = request->r14;
        if (mask & (1ULL << 15)) ctx->R15    = request->r15;
        if (mask & (1ULL << 16)) ctx->Rip    = request->rip;
        if (mask & (1ULL << 17)) ctx->EFlags = (ULONG)request->rflags;
        if (mask & (1ULL << 18)) ctx->Dr0    = request->dr0;
        if (mask & (1ULL << 19)) ctx->Dr1    = request->dr1;
        if (mask & (1ULL << 20)) ctx->Dr2    = request->dr2;
        if (mask & (1ULL << 21)) ctx->Dr3    = request->dr3;
        if (mask & (1ULL << 22)) ctx->Dr6    = request->dr6;
        if (mask & (1ULL << 23)) ctx->Dr7    = sanitize_user_dr7(request->dr7);
    }

    struct native_context_attempt_t {
        const char* source;
        ULONG flags;
        BOOLEAN ps_path;
        BOOLEAN attach;
    };

    NTSTATUS read_native_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, PCONTEXT ctx, p_thread_ctx request, const char* phase) {
        if (!process || !thread || !ctx || !request) {
            return STATUS_INVALID_PARAMETER;
        }

        LARGE_INTEGER phase_freq = {};
        LARGE_INTEGER phase_start = KeQueryPerformanceCounter(&phase_freq);
        KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
        NTSTATUS ps_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS nt_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        const char* selected_source = "none";
        ULONG selected_flags = 0;
        BOOLEAN selected_attached = FALSE;
        BOOLEAN zero_context_seen = FALSE;
        native_context_attempt_t attempts[] = {
            { "ps_kernel_debug", tctx_diag::kContextDebugFlags, TRUE, FALSE },
            { "ps_attach_debug", tctx_diag::kContextDebugFlags, TRUE, TRUE },
            { "ps_kernel_base", tctx_diag::kContextBaseFlags, TRUE, FALSE },
            { "ps_attach_base", tctx_diag::kContextBaseFlags, TRUE, TRUE },
            { "nt_handle_debug", tctx_diag::kContextDebugFlags, FALSE, FALSE },
            { "nt_handle_base", tctx_diag::kContextBaseFlags, FALSE, FALSE },
            { "ps_kernel_legacy", CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, TRUE, FALSE },
            { "ps_attach_legacy", CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, TRUE, TRUE }
        };

        WW_LOG("TCTX %s read_begin pid=%u tid=%u previous_mode=%u requestor_mode=%u ps_get=%p zw_get=%p nt_get=%p handle=%p attach_available=%u",
            phase,
            request->pid,
            request->tid,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            _PsGetContextThread,
            _ZwGetContextThread,
            ssdt_resolver::g_NtGetContextThread,
            thread_handle,
            (_KeStackAttachProcess && _KeUnstackDetachProcess) ? 1u : 0u);

        ULONG attempt_index = 0;
        for (ULONG route = 0; route < sizeof(attempts) / sizeof(attempts[0]); ++route) {
            const native_context_attempt_t& current = attempts[route];
            if (current.ps_path && !_PsGetContextThread) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                ps_status = status;
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                tctx_diag::log_context("read_missing", phase, current.source, attempt_index++, status, STATUS_PROCEDURE_NOT_FOUND, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }
            if (!current.ps_path && !thread_handle) {
                status = STATUS_INVALID_HANDLE;
                nt_status = status;
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                tctx_diag::log_context("read_skipped", phase, current.source, attempt_index++, status, STATUS_INVALID_HANDLE, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }

            for (ULONG retry = 0; retry < 4; ++retry) {
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                NTSTATUS attach_status = STATUS_SUCCESS;
                BOOLEAN attached = FALSE;
                __try {
                    if (current.ps_path) {
                        status = tctx_diag::call_ps_get(process, thread, ctx, current.attach, &attach_status, &attached);
                        ps_status = status;
                    } else {
                        status = ssdt_resolver::call_NtGetContextThread(thread_handle, ctx);
                        nt_status = status;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = (NTSTATUS)GetExceptionCode();
                    if (current.ps_path) {
                        ps_status = status;
                    } else {
                        nt_status = status;
                    }
                }
                tctx_diag::log_context("read_attempt", phase, current.source, attempt_index++, status, attach_status, attached, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status) && tctx_diag::core_registers_present(*ctx)) {
                    selected_source = current.source;
                    selected_flags = ctx->ContextFlags;
                    selected_attached = attached;
                    WW_LOG("TCTX %s read_selected source=%s status=0x%08X flags=0x%08X attached=%u elapsed_ms=%llu",
                        phase,
                        selected_source,
                        (ULONG)status,
                        selected_flags,
                        selected_attached ? 1u : 0u,
                        dbg_guard::elapsed_ms(phase_start, phase_freq));
                    return status;
                }
                if (NT_SUCCESS(status)) {
                    zero_context_seen = TRUE;
                    status = STATUS_UNSUCCESSFUL;
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
        }

        if (zero_context_seen && NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }
        const UINT32 unsupported_state = (!NT_SUCCESS(status) &&
            !_PsGetContextThread && !_ZwGetContextThread && !ssdt_resolver::g_NtGetContextThread) ? 1u : 0u;
        const UINT32 zero_context = (NT_SUCCESS(status) && (ctx->Rip == 0 || ctx->Rsp == 0)) ? 1u : 0u;
        if (!NT_SUCCESS(status) || zero_context) {
            WW_LOG("TCTX %s read_fail_detail pid=%u tid=%u status=0x%08X ps_status=0x%08X nt_status=0x%08X previous_mode=%u requestor_mode=%u handle=%p unsupported_state=%u zero_context=%u zero_seen=%u elapsed_ms=%llu",
                phase,
                request->pid,
                request->tid,
                (ULONG)status,
                (ULONG)ps_status,
                (ULONG)nt_status,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                thread_handle,
                unsupported_state,
                zero_context,
                zero_context_seen ? 1u : 0u,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }
        WW_LOG("TCTX %s read_exit status=0x%08X selected_source=%s selected_flags=0x%08X flags=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            phase,
            (ULONG)status,
            selected_source,
            selected_flags,
            ctx->ContextFlags,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            dbg_guard::elapsed_ms(phase_start, phase_freq));
        return status;
    }

    NTSTATUS write_native_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, PCONTEXT ctx, p_thread_ctx request) {
        if (!process || !thread || !ctx || !request) {
            return STATUS_INVALID_PARAMETER;
        }

        LARGE_INTEGER phase_freq = {};
        LARGE_INTEGER phase_start = KeQueryPerformanceCounter(&phase_freq);
        KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
        const BOOLEAN needs_debug = tctx_diag::debug_registers_requested(request->register_mask);
        const ULONG write_flags = needs_debug ? tctx_diag::kContextDebugFlags : tctx_diag::kContextBaseFlags;
        native_context_attempt_t attempts[] = {
            { "ps_kernel_write", write_flags, TRUE, FALSE },
            { "ps_attach_write", write_flags, TRUE, TRUE },
            { "nt_handle_write", write_flags, FALSE, FALSE }
        };
        ctx->ContextFlags = write_flags;
        WW_LOG("TCTX set write_begin pid=%u tid=%u mask=0x%llX flags=0x%08X needs_debug=%u rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX previous_mode=%u requestor_mode=%u ps_set=%p zw_set=%p nt_set=%p handle=%p",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            ctx->ContextFlags,
            needs_debug ? 1u : 0u,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            _PsSetContextThread,
            _ZwSetContextThread,
            ssdt_resolver::g_NtSetContextThread,
            thread_handle);

        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS ps_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS nt_status = STATUS_PROCEDURE_NOT_FOUND;
        const char* selected_source = "none";
        ULONG selected_flags = 0;
        BOOLEAN selected_attached = FALSE;
        ULONG attempt_index = 0;

        for (ULONG route = 0; route < sizeof(attempts) / sizeof(attempts[0]); ++route) {
            const native_context_attempt_t& current = attempts[route];
            if (current.ps_path && !_PsSetContextThread) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                ps_status = status;
                tctx_diag::log_context("write_missing", "set", current.source, attempt_index++, status, STATUS_PROCEDURE_NOT_FOUND, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }
            if (!current.ps_path && !thread_handle) {
                status = STATUS_INVALID_HANDLE;
                nt_status = status;
                tctx_diag::log_context("write_skipped", "set", current.source, attempt_index++, status, STATUS_INVALID_HANDLE, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }

            for (ULONG retry = 0; retry < 3; ++retry) {
                ctx->ContextFlags = current.flags;
                NTSTATUS attach_status = STATUS_SUCCESS;
                BOOLEAN attached = FALSE;
                __try {
                    if (current.ps_path) {
                        status = tctx_diag::call_ps_set(process, thread, ctx, current.attach, &attach_status, &attached);
                        ps_status = status;
                    } else {
                        status = ssdt_resolver::call_NtSetContextThread(thread_handle, ctx);
                        nt_status = status;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = (NTSTATUS)GetExceptionCode();
                    if (current.ps_path) {
                        ps_status = status;
                    } else {
                        nt_status = status;
                    }
                }
                tctx_diag::log_context("write_attempt", "set", current.source, attempt_index++, status, attach_status, attached, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status)) {
                    selected_source = current.source;
                    selected_flags = current.flags;
                    selected_attached = attached;
                    break;
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
            if (NT_SUCCESS(status)) {
                break;
            }
        }

        if (!NT_SUCCESS(status)) {
            const UINT32 unsupported_state = (!_PsSetContextThread && !_ZwSetContextThread && !ssdt_resolver::g_NtSetContextThread) ? 1u : 0u;
            WW_LOG("TCTX set write_fail_detail pid=%u tid=%u status=0x%08X ps_status=0x%08X nt_status=0x%08X previous_mode=%u requestor_mode=%u handle=%p unsupported_state=%u elapsed_ms=%llu",
                request->pid,
                request->tid,
                (ULONG)status,
                (ULONG)ps_status,
                (ULONG)nt_status,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                thread_handle,
                unsupported_state,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }
        WW_LOG("TCTX set write_exit status=0x%08X selected_source=%s selected_flags=0x%08X selected_attached=%u flags=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            (ULONG)status,
            selected_source,
            selected_flags,
            selected_attached ? 1u : 0u,
            ctx->ContextFlags,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            dbg_guard::elapsed_ms(phase_start, phase_freq));
        return status;
    }

    NTSTATUS get_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, p_thread_ctx request, PCONTEXT ctx) {
        NTSTATUS status = read_native_context(process, thread, thread_handle, ctx, request, "get");
        if (NT_SUCCESS(status)) {
            copy_context_to_request(*ctx, request);
        }
        return status;
    }

    NTSTATUS set_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, p_thread_ctx request, PCONTEXT ctx) {
        const BOOLEAN needs_debug = tctx_diag::debug_registers_requested(request->register_mask);
        NTSTATUS status = read_native_context(process, thread, thread_handle, ctx, request, "set_base");
        if (!NT_SUCCESS(status)) {
            WW_LOG("TCTX set base_read_failed status=0x%08X pid=%u tid=%u mask=0x%llX",
                (ULONG)status,
                request ? request->pid : 0,
                request ? request->tid : 0,
                request ? (unsigned long long)request->register_mask : 0ULL);
            return status;
        }
        if (needs_debug && ((ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == 0)) {
            WW_LOG("TCTX set base_read_rejected_no_debug pid=%u tid=%u mask=0x%llX flags=0x%08X",
                request->pid,
                request->tid,
                (unsigned long long)request->register_mask,
                ctx->ContextFlags);
            return STATUS_INVALID_DEVICE_STATE;
        }

        apply_request_to_context(request, ctx);
        ctx->ContextFlags = needs_debug ? tctx_diag::kContextDebugFlags : tctx_diag::kContextBaseFlags;
        WW_LOG("TCTX set applied pid=%u tid=%u mask=0x%llX flags=0x%08X needs_debug=%u rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            ctx->ContextFlags,
            needs_debug ? 1u : 0u,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7);
        return write_native_context(process, thread, thread_handle, ctx, request);
    }
}


NTSTATUS functions::handle_thread_ctx(p_thread_ctx request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        WW_LOG("TCTX reject invalid_request request=%p", request);
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER tctx_freq = {};
    LARGE_INTEGER tctx_start = KeQueryPerformanceCounter(&tctx_freq);
    KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        WW_LOG("TCTX reject bad_irql pid=%u tid=%u set=%u irql=%u previous_mode=%u requestor_mode=%u",
            request->pid,
            request->tid,
            request->should_set,
            (ULONG)KeGetCurrentIrql(),
            (ULONG)previous_mode,
            (ULONG)previous_mode);
        return STATUS_INVALID_DEVICE_STATE;
    }

    POBJECT_TYPE thread_type = (PsThreadType && *PsThreadType) ? *PsThreadType : nullptr;
    tctx_diag::os_version_snapshot_t os_version = tctx_diag::query_os_version();
    tctx_diag::thread_snapshot_t thread_before = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    WW_LOG("TCTX entry pid=%u tid=%u set=%u mask=0x%llX irql=%u previous_mode=%u requestor_mode=%u current_pid=%p current_tid=%p os_status=0x%08X os=%lu.%lu.%lu thread_found=%u thread_status=0x%08X thread_state=%lu wait_reason=%lu start=%p client_pid=%p client_tid=%p process_thread_count=%lu scanned_processes=%lu scanned_threads=%lu ps_get=%p ps_set=%p zw_get=%p zw_set=%p ps_suspend=%p ps_resume=%p zw_suspend=%p zw_resume=%p ob_open=%p zw_close=%p thread_type_ptr=%p thread_type=%p stack_attach=%p stack_detach=%p",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        (ULONG)KeGetCurrentIrql(),
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        PsGetCurrentProcessId(),
        PsGetCurrentThreadId(),
        (ULONG)os_version.status,
        os_version.major,
        os_version.minor,
        os_version.build,
        thread_before.found ? 1u : 0u,
        (ULONG)thread_before.status,
        thread_before.thread_state,
        thread_before.wait_reason,
        thread_before.start_address,
        thread_before.client_pid,
        thread_before.client_tid,
        thread_before.process_thread_count,
        thread_before.scanned_processes,
        thread_before.scanned_threads,
        _PsGetContextThread,
        _PsSetContextThread,
        _ZwGetContextThread,
        _ZwSetContextThread,
        _PsSuspendThread,
        _PsResumeThread,
        _ZwSuspendThread,
        _ZwResumeThread,
        _ObOpenObjectByPointer,
        _ZwClose,
        PsThreadType,
        thread_type,
        _KeStackAttachProcess,
        _KeUnstackDetachProcess);

    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_ObfDereferenceObject) {
        WW_LOG("TCTX reject missing_lookup pid=%u tid=%u lookup_process=%p lookup_thread=%p deref=%p",
            request->pid,
            request->tid,
            _PsLookupProcessByProcessId,
            _PsLookupThreadByThreadId,
            _ObfDereferenceObject);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    WW_LOG("TCTX lookup_process pid=%u status=0x%08X process=%p",
        request->pid,
        (ULONG)status,
        process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    WW_LOG("TCTX lookup_thread tid=%u status=0x%08X thread=%p",
        request->tid,
        (ULONG)status,
        thread);
    if (!NT_SUCCESS(status) || !thread) {
        _ObfDereferenceObject(process);
        return status;
    }


    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            WW_LOG("TCTX reject process_mismatch pid=%u tid=%u process=%p thread_process=%p",
                request->pid,
                request->tid,
                process,
                thread_process);
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            return STATUS_INVALID_CID;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        WW_LOG("TCTX reject process_check_exception pid=%u tid=%u code=0x%08X",
            request->pid,
            request->tid,
            (ULONG)GetExceptionCode());
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    dbg_guard::timing_scatter();


    HANDLE ctx_thread_handle = nullptr;
    BOOLEAN ctx_thread_suspended = FALSE;
    NTSTATUS open_status = STATUS_PROCEDURE_NOT_FOUND;
    NTSTATUS suspend_status = STATUS_PROCEDURE_NOT_FOUND;
    ULONG suspend_prev_count = 0;
    BOOLEAN tried_ps_suspend = FALSE;
    BOOLEAN ctx_thread_suspended_via_ps = FALSE;
    const char* open_strategy = "not_attempted";
    const char* suspend_strategy = "none";

    if (_ObOpenObjectByPointer && _ZwClose && thread_type) {
        open_strategy = "obopen_thread_object";
        ACCESS_MASK desired_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
        if (request->should_set != 0) {
            desired_access |= THREAD_SET_CONTEXT;
        }

        __try {
            open_status = _ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                desired_access,
                thread_type,
                KernelMode,
                &ctx_thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            open_status = (NTSTATUS)GetExceptionCode();
            ctx_thread_handle = nullptr;
        }

        WW_LOG("TCTX open_handle pid=%u tid=%u desired=0x%08X status=0x%08X handle=%p thread_type=%p",
            request->pid,
            request->tid,
            (ULONG)desired_access,
            (ULONG)open_status,
            ctx_thread_handle,
            thread_type);

        if (NT_SUCCESS(open_status) && ctx_thread_handle) {
            if (_PsSuspendThread && (_PsResumeThread || _ZwResumeThread)) {
                tried_ps_suspend = TRUE;
                __try {
                    suspend_status = _PsSuspendThread(thread, &suspend_prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    suspend_status = (NTSTATUS)GetExceptionCode();
                }
                WW_LOG("TCTX suspend_ps_with_handle pid=%u tid=%u status=0x%08X prev=%lu ps_suspend=%p handle=%p",
                    request->pid,
                    request->tid,
                    (ULONG)suspend_status,
                    suspend_prev_count,
                    _PsSuspendThread,
                    ctx_thread_handle);
                if (NT_SUCCESS(suspend_status)) {
                    ctx_thread_suspended = TRUE;
                    ctx_thread_suspended_via_ps = TRUE;
                    suspend_strategy = "ps_with_handle";
                }
            }
            if (!ctx_thread_suspended) {
                suspend_prev_count = 0;
                __try {
                    suspend_status = ssdt_resolver::call_NtSuspendThread(ctx_thread_handle, &suspend_prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    suspend_status = (NTSTATUS)GetExceptionCode();
                }
                WW_LOG("TCTX suspend_nt_with_handle pid=%u tid=%u status=0x%08X prev=%lu zw_suspend=%p nt_suspend=%p handle=%p",
                    request->pid,
                    request->tid,
                    (ULONG)suspend_status,
                    suspend_prev_count,
                    _ZwSuspendThread,
                    ssdt_resolver::g_NtSuspendThread,
                    ctx_thread_handle);
                if (NT_SUCCESS(suspend_status)) {
                    ctx_thread_suspended = TRUE;
                    ctx_thread_suspended_via_ps = FALSE;
                    suspend_strategy = "nt_with_handle";
                }
            }

            WW_LOG("TCTX suspend_with_handle pid=%u tid=%u status=0x%08X prev=%lu ps_suspend=%p zw_suspend=%p handle=%p via_ps=%u",
                request->pid,
                request->tid,
                (ULONG)suspend_status,
                suspend_prev_count,
                _PsSuspendThread,
                _ZwSuspendThread,
                ctx_thread_handle,
                ctx_thread_suspended_via_ps ? 1u : 0u);
        }
    } else {
        WW_LOG("TCTX open_skipped pid=%u tid=%u ob_open=%p zw_close=%p thread_type_ptr=%p thread_type=%p",
            request->pid,
            request->tid,
            _ObOpenObjectByPointer,
            _ZwClose,
            PsThreadType,
            thread_type);
        open_strategy = "missing_open_primitives";
    }

    if (!ctx_thread_suspended && !tried_ps_suspend && _PsSuspendThread && _PsResumeThread) {
        suspend_prev_count = 0;
        tried_ps_suspend = TRUE;
        __try {
            suspend_status = _PsSuspendThread(thread, &suspend_prev_count);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            suspend_status = (NTSTATUS)GetExceptionCode();
        }
        WW_LOG("TCTX suspend_ps_direct pid=%u tid=%u status=0x%08X prev=%lu ps_suspend=%p",
            request->pid,
            request->tid,
            (ULONG)suspend_status,
            suspend_prev_count,
            _PsSuspendThread);
        if (NT_SUCCESS(suspend_status)) {
            ctx_thread_suspended = TRUE;
            ctx_thread_suspended_via_ps = TRUE;
            suspend_strategy = "ps_direct";
        }
    }

    if (!ctx_thread_suspended && request->should_set != 0) {
        WW_LOG("TCTX reject suspend_failed pid=%u tid=%u open_status=0x%08X suspend_status=0x%08X handle=%p ps_suspend=%p zw_suspend=%p",
            request->pid,
            request->tid,
            (ULONG)open_status,
            (ULONG)suspend_status,
            ctx_thread_handle,
            _PsSuspendThread,
            _ZwSuspendThread);
        if (ctx_thread_handle) {
            _ZwClose(ctx_thread_handle);
        }
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!ctx_thread_suspended) {
        WW_LOG("TCTX read_without_suspend pid=%u tid=%u open_status=0x%08X suspend_status=0x%08X handle=%p ps_get=%p zw_get=%p",
            request->pid,
            request->tid,
            (ULONG)open_status,
            (ULONG)suspend_status,
            ctx_thread_handle,
            _PsGetContextThread,
            _ZwGetContextThread);
    } else {
        for (ULONG settle = 0; settle < 4; ++settle) {
            dbg_guard::short_context_retry_delay();
            tctx_diag::thread_snapshot_t settle_snapshot = tctx_diag::query_thread_snapshot(request->pid, request->tid);
            WW_LOG("TCTX suspend_settle pid=%u tid=%u index=%lu strategy=%s found=%u status=0x%08X state=%lu wait_reason=%lu elapsed_ms=%llu",
                request->pid,
                request->tid,
                settle,
                suspend_strategy,
                settle_snapshot.found ? 1u : 0u,
                (ULONG)settle_snapshot.status,
                settle_snapshot.thread_state,
                settle_snapshot.wait_reason,
                dbg_guard::elapsed_ms(tctx_start, tctx_freq));
        }
    }

    CONTEXT ctx;
    strong::kmemset(&ctx, 0, sizeof(ctx));

    ULONGLONG context_start_ms = dbg_guard::elapsed_ms(tctx_start, tctx_freq);
    WW_LOG("TCTX context_begin pid=%u tid=%u set=%u handle=%p open_strategy=%s suspend_strategy=%s suspended=%u via_ps=%u open_status=0x%08X suspend_status=0x%08X previous_mode=%u requestor_mode=%u attach_available=%u elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        ctx_thread_handle,
        open_strategy,
        suspend_strategy,
        ctx_thread_suspended ? 1u : 0u,
        ctx_thread_suspended_via_ps ? 1u : 0u,
        (ULONG)open_status,
        (ULONG)suspend_status,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        (_KeStackAttachProcess && _KeUnstackDetachProcess) ? 1u : 0u,
        context_start_ms);

    if (request->should_set == 0) {
        status = trapframe_ctx::get_context(process, thread, ctx_thread_handle, request, &ctx);
    }
    else {
        status = trapframe_ctx::set_context(process, thread, ctx_thread_handle, request, &ctx);
    }

    WW_LOG("TCTX context_end pid=%u tid=%u set=%u status=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX flags=0x%08X elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        (ULONG)status,
        (unsigned long long)request->rip,
        (unsigned long long)request->rsp,
        (unsigned long long)request->rflags,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        ctx.ContextFlags,
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));

    if (NT_SUCCESS(status) && request->should_set == 0 && (request->rip == 0 || request->rsp == 0)) {
        WW_LOG("TCTX reject zero_context pid=%u tid=%u rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX flags=0x%08X previous_mode=%u requestor_mode=%u",
            request->pid,
            request->tid,
            (unsigned long long)request->rip,
            (unsigned long long)request->rsp,
            (unsigned long long)request->rflags,
            (unsigned long long)request->dr0,
            (unsigned long long)request->dr1,
            (unsigned long long)request->dr2,
            (unsigned long long)request->dr3,
            (unsigned long long)request->dr6,
            (unsigned long long)request->dr7,
            ctx.ContextFlags,
            (ULONG)previous_mode,
            (ULONG)previous_mode);
        status = STATUS_UNSUCCESSFUL;
    }

    if (ctx_thread_suspended && ctx_thread_handle) {
        ULONG prev_count = 0;
        NTSTATUS resume_status = STATUS_PROCEDURE_NOT_FOUND;

        if (ctx_thread_suspended_via_ps && _PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        } else if (_ZwResumeThread || ssdt_resolver::g_NtResumeThread || ctx_thread_handle) {
            __try {
                resume_status = ssdt_resolver::call_NtResumeThread(ctx_thread_handle, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        } else if (_PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        }

        WW_LOG("TCTX resume_with_handle pid=%u tid=%u status=0x%08X prev=%lu ps_resume=%p zw_resume=%p handle=%p via_ps=%u final_before=0x%08X",
            request->pid,
            request->tid,
            (ULONG)resume_status,
            prev_count,
            _PsResumeThread,
            ssdt_resolver::g_NtResumeThread ? ssdt_resolver::g_NtResumeThread : _ZwResumeThread,
            ctx_thread_handle,
            ctx_thread_suspended_via_ps ? 1u : 0u,
            (ULONG)status);
        if (NT_SUCCESS(status) && !NT_SUCCESS(resume_status)) {
            status = resume_status;
        }
    } else if (ctx_thread_suspended) {
        ULONG prev_count = 0;
        NTSTATUS resume_status = STATUS_PROCEDURE_NOT_FOUND;
        if (_PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        }
        WW_LOG("TCTX resume_ps_direct pid=%u tid=%u status=0x%08X prev=%lu ps_resume=%p final_before=0x%08X",
            request->pid,
            request->tid,
            (ULONG)resume_status,
            prev_count,
            _PsResumeThread,
            (ULONG)status);
        if (NT_SUCCESS(status) && !NT_SUCCESS(resume_status)) {
            status = resume_status;
        }
    }
    if (ctx_thread_handle) {
        _ZwClose(ctx_thread_handle);
    }

    tctx_diag::thread_snapshot_t thread_after = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    WW_LOG("TCTX exit pid=%u tid=%u set=%u status=0x%08X open_status=0x%08X suspend_status=0x%08X open_strategy=%s suspend_strategy=%s suspended=%u via_ps=%u previous_mode=%u requestor_mode=%u thread_after_found=%u thread_after_status=0x%08X thread_after_state=%lu thread_after_wait_reason=%lu rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        (ULONG)status,
        (ULONG)open_status,
        (ULONG)suspend_status,
        open_strategy,
        suspend_strategy,
        ctx_thread_suspended ? 1u : 0u,
        ctx_thread_suspended_via_ps ? 1u : 0u,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        thread_after.found ? 1u : 0u,
        (ULONG)thread_after.status,
        thread_after.thread_state,
        thread_after.wait_reason,
        (unsigned long long)request->rip,
        (unsigned long long)request->rsp,
        (unsigned long long)request->rflags,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));

    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_thread_enum(p_thread_enum request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

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
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_suspend_resume_thread(p_suspend_resume_thread request) {
    if (!request || request->tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    POBJECT_TYPE thread_type = (PsThreadType && *PsThreadType) ? *PsThreadType : nullptr;
    BOOLEAN use_ps = (_PsSuspendThread != nullptr && _PsResumeThread != nullptr);
    BOOLEAN use_handle = (_ObOpenObjectByPointer != nullptr && _ZwClose != nullptr && thread_type != nullptr);

    if (!_PsLookupThreadByThreadId || !_ObfDereferenceObject || (!use_ps && !use_handle)) {
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
        __try {
            if (request->should_resume == 0) {
                status = _PsSuspendThread(thread, &prev_count);
            }
            else {
                status = _PsResumeThread(thread, &prev_count);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        WW_LOG("TSR ps pid=0 tid=%u resume=%u status=0x%08X prev=%lu",
            request->tid,
            request->should_resume,
            (ULONG)status,
            prev_count);
    }
    if ((!use_ps || !NT_SUCCESS(status)) && use_handle) {

        HANDLE thread_handle = nullptr;
        prev_count = 0;
        __try {
            status = _ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SUSPEND_RESUME,
                thread_type,
                KernelMode,
                &thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
            thread_handle = nullptr;
        }
        WW_LOG("TSR open tid=%u resume=%u status=0x%08X handle=%p thread_type=%p",
            request->tid,
            request->should_resume,
            (ULONG)status,
            thread_handle,
            thread_type);

        if (NT_SUCCESS(status) && thread_handle) {
            prev_count = 0;
            __try {
                if (request->should_resume == 0) {
                    status = ssdt_resolver::call_NtSuspendThread(thread_handle, &prev_count);
                }
                else {
                    status = ssdt_resolver::call_NtResumeThread(thread_handle, &prev_count);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = (NTSTATUS)GetExceptionCode();
            }
            WW_LOG("TSR nt tid=%u resume=%u status=0x%08X prev=%lu zw_suspend=%p zw_resume=%p nt_suspend=%p nt_resume=%p",
                request->tid,
                request->should_resume,
                (ULONG)status,
                prev_count,
                _ZwSuspendThread,
                _ZwResumeThread,
                ssdt_resolver::g_NtSuspendThread,
                ssdt_resolver::g_NtResumeThread);
            _ZwClose(thread_handle);
        }
        else {
            WW_LOG("TSR open_failed tid=%u resume=%u status=0x%08X use_ps=%u use_handle=%u",
                request->tid,
                request->should_resume,
                (ULONG)status,
                use_ps ? 1u : 0u,
                use_handle ? 1u : 0u);
        }
    }

    request->previous_count = prev_count;
    _ObfDereferenceObject(thread);

    return status;
}


NTSTATUS functions::handle_query_memory(p_query_memory request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
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
    if (!request) {
        WW_LOG("memory::protect_memory: REJECT request=null");
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        WW_LOG("memory::protect_memory: REJECT irql=%lu", KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    WW_LOG("memory::protect_memory: handle ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X",
        (ULONG)request->pid,
        (unsigned long long)request->address,
        (unsigned long long)request->size,
        (ULONG)request->new_protect);

    if (request->pid == 0 || request->size == 0) {
        WW_LOG("memory::protect_memory: REJECT pid_or_size_zero pid=%lu size=0x%llX",
            (ULONG)request->pid, (unsigned long long)request->size);
        return STATUS_INVALID_PARAMETER;
    }

    if (request->address == 0) {
        WW_LOG("memory::protect_memory: REJECT addr_zero");
        return STATUS_INVALID_PARAMETER;
    }

    const UINT64 kUserAddressMax = 0x00007FFFFFFFFFFFULL;
    if (request->address >= kUserAddressMax) {
        WW_LOG("memory::protect_memory: REJECT addr_kernel_range addr=0x%016llX",
            (unsigned long long)request->address);
        return STATUS_INVALID_ADDRESS;
    }

    if (request->size > 0x00000000FFFFFFFFULL) {
        WW_LOG("memory::protect_memory: REJECT size_too_large size=0x%llX",
            (unsigned long long)request->size);
        return STATUS_INVALID_PARAMETER;
    }

    if ((request->address + request->size) < request->address ||
        (request->address + request->size) >= kUserAddressMax) {
        WW_LOG("memory::protect_memory: REJECT range_overflow addr=0x%016llX size=0x%llX",
            (unsigned long long)request->address,
            (unsigned long long)request->size);
        return STATUS_INVALID_ADDRESS;
    }

    const ULONG kAllowedProtect =
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    if ((request->new_protect & ~kAllowedProtect) != 0 || request->new_protect == 0) {
        WW_LOG("memory::protect_memory: REJECT bad_protect_flags new=0x%08X mask=0x%08X",
            (ULONG)request->new_protect, (ULONG)kAllowedProtect);
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwProtectVirtualMemory || !_ObfDereferenceObject) {
        WW_LOG("memory::protect_memory: REJECT procedures_missing PsLookup=%p KeStack=%p KeUnstack=%p ZwProtect=%p ObfDeref=%p",
            _PsLookupProcessByProcessId, _KeStackAttachProcess,
            _KeUnstackDetachProcess, _ZwProtectVirtualMemory, _ObfDereferenceObject);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        WW_LOG("memory::protect_memory: PsLookupProcessByProcessId FAIL pid=%lu status=0x%08X process=%p",
            (ULONG)request->pid, (ULONG)status, process);
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    PVOID base_addr = (PVOID)request->address;
    SIZE_T region_size = (SIZE_T)request->size;
    ULONG old_protect = 0;

    __try {
        status = _ZwProtectVirtualMemory(
            (HANDLE)-1,
            &base_addr,
            &region_size,
            request->new_protect,
            &old_protect);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        WW_LOG("memory::protect_memory: EXCEPTION pid=%lu addr=0x%016llX code=0x%08X",
            (ULONG)request->pid,
            (unsigned long long)request->address,
            (ULONG)status);
    }

    WW_LOG("memory::protect_memory: ZwProtectVirtualMemory RESULT pid=%lu in_addr=0x%016llX out_addr=0x%016llX in_size=0x%llX out_size=0x%llX new=0x%08X old=0x%08X status=0x%08X",
        (ULONG)request->pid,
        (unsigned long long)request->address,
        (unsigned long long)(ULONG_PTR)base_addr,
        (unsigned long long)request->size,
        (unsigned long long)region_size,
        (ULONG)request->new_protect,
        (ULONG)old_protect,
        (ULONG)status);

    if (NT_SUCCESS(status)) {
        request->old_protect = old_protect;
    }
    else {
        request->old_protect = 0;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_enum_regions(p_enum_regions request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
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

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
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

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
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

namespace debug_attach_monitor {

    inline KTIMER   g_timer;
    inline KDPC     g_dpc;
    inline WORK_QUEUE_ITEM g_work_item;
    inline volatile LONG g_strikes = 0;
    inline volatile LONG g_running = 0;
    inline volatile LONG g_work_queued = 0;
    inline volatile ULONG g_pending_pid = 0;

    __forceinline ULONG resolve_debug_port_offset() {
        ULONG build = strong::get_windows_version();
        if (build >= 22000) return 0x578;
        if (build >= 19041) return 0x578;
        if (build >= 17763) return 0x550;
        return 0x420;
    }

    __forceinline bool attribute_debugger_to_re_tool(HANDLE target_pid) {
        if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject)
            return false;

        ULONG buf_size = 4 * 1024 * 1024;
        PVOID buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'dAaW');
        if (!buf) return false;

        ULONG ret_len = 0;
        NTSTATUS st = ZwQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
            buf, buf_size, &ret_len);
        if (st == STATUS_INFO_LENGTH_MISMATCH && ret_len > buf_size) {
            ExFreePoolWithTag(buf, 'dAaW');
            buf_size = ret_len + 65536;
            buf = ExAllocatePool2(POOL_FLAG_PAGED, buf_size, 'dAaW');
            if (!buf) return false;
            st = ZwQuerySystemInformation(
                (SYSTEM_INFORMATION_CLASS_INTERNAL)64,
                buf, buf_size, &ret_len);
        }
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(buf, 'dAaW');
            return false;
        }

        struct HANDLE_ENTRY_EX {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ACCESS_MASK GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };
        struct HANDLE_INFO_EX {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            HANDLE_ENTRY_EX Handles[1];
        };

        auto* info = (HANDLE_INFO_EX*)buf;
        bool found_re = false;
        constexpr ACCESS_MASK DBG_ACCESS =
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;

        for (ULONG_PTR i = 0; i < info->NumberOfHandles && i < 500000; ++i) {
            auto& h = info->Handles[i];
            if ((HANDLE)h.UniqueProcessId == target_pid) continue;
            if ((h.GrantedAccess & DBG_ACCESS) != DBG_ACCESS) continue;

            PEPROCESS owner_proc = nullptr;
            if (!NT_SUCCESS(_PsLookupProcessByProcessId((HANDLE)h.UniqueProcessId, &owner_proc)))
                continue;

            UCHAR* image = PsGetProcessImageFileName(owner_proc);
            bool is_re = file_handle_scanner::_match_tool((const char*)image);
            _ObfDereferenceObject(owner_proc);

            if (is_re) {
                PEPROCESS handle_target = nullptr;
                __try {
                    if (_MmIsAddressValid && _MmIsAddressValid(h.Object)) {
                        HANDLE hval = (HANDLE)h.HandleValue;
                        HANDLE owner_handle = nullptr;
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = (HANDLE)h.UniqueProcessId;
                        cid.UniqueThread = nullptr;
                        OBJECT_ATTRIBUTES oa = {};
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        if (_ZwOpenProcess && NT_SUCCESS(_ZwOpenProcess(&owner_handle, PROCESS_DUP_HANDLE, &oa, &cid))) {
                            HANDLE dup = nullptr;
                            OBJECT_ATTRIBUTES dup_oa = {};
                            InitializeObjectAttributes(&dup_oa, nullptr, 0, nullptr, nullptr);
                            if (ZwDuplicateObject(owner_handle, hval, NtCurrentProcess(),
                                    &dup, 0x1000 , 0, 0) >= 0 && dup) {
                                PROCESS_BASIC_INFORMATION pbi = {};
                                ULONG pbi_ret = 0;


                                if (NT_SUCCESS(ZwQueryInformationProcess(dup,
                                        ProcessBasicInformation, &pbi, sizeof(pbi), &pbi_ret))) {
                                    if ((HANDLE)(ULONG_PTR)pbi.UniqueProcessId == target_pid) {
                                        found_re = true;
                                    }
                                }
                                if (_ZwClose) _ZwClose(dup);
                            }
                            if (_ZwClose) _ZwClose(owner_handle);
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                if (found_re) break;
            }
        }

        ExFreePoolWithTag(buf, 'dAaW');
        return found_re;
    }

    static VOID NTAPI work_routine(PVOID) {
        ULONG pid = static_cast<ULONG>(_InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_pending_pid), 0));
        if (pid == 0) {
            _InterlockedExchange(&g_work_queued, 0);
            return;
        }

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &proc)) || !proc) {
            _InterlockedExchange(&g_work_queued, 0);
            return;
        }

        PVOID debug_port = nullptr;
        ULONG debug_port_offset = resolve_debug_port_offset();
        if (debug_port_offset != 0) {
            __try {
                debug_port = *reinterpret_cast<PVOID*>(reinterpret_cast<UCHAR*>(proc) + debug_port_offset);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                debug_port = nullptr;
            }
        }
        ObDereferenceObject(proc);

        if (debug_port != nullptr &&
            reinterpret_cast<UINT64>(debug_port) < 0xFFFF800000000000ull) {
            debug_port = nullptr;
        }

        BOOLEAN kd_enabled_now = anti_debug::kd_transitioned_to_enabled();
        bool debug_port_confirmed = false;
        ULONG evidence_reason = sentinel_bridge::RE_REASON_DEBUG_ATTACH;

        if (debug_port != nullptr) {
            HANDLE pid_handle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
            debug_port_confirmed = attribute_debugger_to_re_tool(pid_handle);
            if (debug_port_confirmed)
                evidence_reason = sentinel_bridge::RE_REASON_DEBUG_BY_RE_TOOL;
            else {
                UINT64 port_value = reinterpret_cast<UINT64>(debug_port);
                UINT32 port_tag = static_cast<UINT32>((port_value >> 32) ^ port_value ^ 0x0A1DDB6u);
                WW_LOG("debug_attach_monitor: unconfirmed debug port pid=%lu tag=0x%08X", pid, port_tag);
            }
        }

        if (debug_port_confirmed || kd_enabled_now) {
            LONG strikes = _InterlockedIncrement(&g_strikes);

            sentinel_bridge::populate_evidence_blob(
                0x20u,
                evidence_reason,
                100,
                pid,
                0,
                0,
                0);

            ULONG cmd   = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
            ULONG param = pid;
            sentinel_bridge::bridge_encrypt_cmd(cmd, param);
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd), static_cast<LONG>(cmd));
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&sentinel_bridge::g_bridge.sentinel_cmd_param), static_cast<LONG>(param));

            if (strikes >= 2) {
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(
                        sentinel_bridge::BUGCHECK_RE_USERMODE_CONFIRMED,
                        sentinel_bridge::RE_REASON_DEBUG_ATTACH,
                        sentinel_bridge::g_evidence_blob_offset,
                        static_cast<ULONG_PTR>(pid),
                        0);
                }
            }
        } else {
            _InterlockedExchange(&g_strikes, 0);
        }

        _InterlockedExchange(&g_work_queued, 0);
    }

    static VOID NTAPI dpc_routine(_KDPC*, PVOID, PVOID, PVOID) {
        if (!_InterlockedCompareExchange(&g_running, 0, 0)) return;
        if (!dispatcher::is_session_valid()) return;

        HANDLE pid_handle = caller_validation::g_registered_client_pid;
        ULONG pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(pid_handle));
        if (pid == 0) return;

        if (_InterlockedCompareExchange(&g_work_queued, 1, 0) != 0) return;

        _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_pending_pid), static_cast<LONG>(pid));
        ExInitializeWorkItem(&g_work_item, work_routine, nullptr);
        ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
    }

    VOID start() {
        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0) return;
        _KeInitializeTimerEx(&g_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_dpc, dpc_routine, nullptr);
        LARGE_INTEGER due;
        due.QuadPart = -10000000LL;
        _KeSetTimerEx(&g_timer, due, 1000, &g_dpc);
    }

    VOID stop() {
        if (_InterlockedCompareExchange(&g_running, 0, 1) != 1) return;
        _KeCancelTimer(&g_timer);
        _KeFlushQueuedDpcs();
    }

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

NTSTATUS functions::handle_query_ssdt(p_ssdt_query request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }

    request->lstar = 0;
    request->descriptor_address = 0;
    request->service_table = 0;
    request->counter_table = 0;
    request->argument_table = 0;
    request->service_limit = 0;
    request->flags = 0;

    __try {
        request->lstar = __readmsr(0xC0000082);
        if (request->lstar >= 0xFFFF800000000000ULL) {
            request->flags |= 0x2u;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        request->lstar = ssdt_resolver::g_lstar;
    }

    if (!ssdt_resolver::find_ssdt() || !ssdt_resolver::g_ssdt) {
        return STATUS_NOT_FOUND;
    }

    ssdt_resolver::PKSERVICE_TABLE_DESCRIPTOR ssdt = ssdt_resolver::g_ssdt;

    __try {
        request->descriptor_address = reinterpret_cast<UINT64>(ssdt);
        request->service_table = reinterpret_cast<UINT64>(ssdt->ServiceTable);
        request->counter_table = reinterpret_cast<UINT64>(ssdt->CounterTable);
        request->argument_table = reinterpret_cast<UINT64>(ssdt->ArgumentTable);
        request->service_limit = static_cast<UINT32>(ssdt->ServiceLimit);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        request->descriptor_address = 0;
        request->service_table = 0;
        request->counter_table = 0;
        request->argument_table = 0;
        request->service_limit = 0;
        return STATUS_UNSUCCESSFUL;
    }

    if (request->lstar == 0) {
        request->lstar = ssdt_resolver::g_lstar;
    }

    if (request->descriptor_address < 0xFFFF800000000000ULL ||
        request->service_table < 0xFFFF800000000000ULL ||
        request->service_limit == 0 ||
        request->service_limit > 0x2000) {
        return STATUS_INVALID_ADDRESS;
    }

    if (!_MmIsAddressValid || !_MmIsAddressValid(reinterpret_cast<PVOID>(request->descriptor_address)) ||
        !_MmIsAddressValid(reinterpret_cast<PVOID>(request->service_table))) {
        return STATUS_INVALID_ADDRESS;
    }

    request->flags |= 0x1u;
    if (request->descriptor_address != 0 && request->service_table != 0) {
        request->flags |= 0x4u;
    }

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_anti_debug(p_anti_debug_request request) {
    if (!request) return STATUS_INVALID_PARAMETER;

    dbg_guard::timing_scatter();

    switch (request->operation) {
    case ADBG_OP_QUERY:
    {
        request->result_flags = anti_debug::refresh_detection();
        request->dr_clear_count = anti_debug::g_dr_clear_count;
        return STATUS_SUCCESS;
    }

    case ADBG_OP_CLEAR_DR:
    {
        NTSTATUS status = anti_debug::clear_debug_registers_all_cpus();
        request->dr_clear_count = anti_debug::g_dr_clear_count;
        request->result_flags = NT_SUCCESS(status) ? 0 : 0xFFFFFFFFu;
        return status;
    }

    case ADBG_OP_SCAN_DEBUGGERS:
    {
        UINT64 dbg_pid = 0;
        NTSTATUS status = anti_debug::scan_for_debugger_processes(&dbg_pid);
        NTSTATUS raw_status = status;
        if (status == STATUS_NOT_FOUND && dbg_pid == 0)
            status = STATUS_SUCCESS;
        request->detected_debugger_pid = dbg_pid;
        request->result_flags = (dbg_pid != 0) ? 1 : 0;
        WW_LOG("[ADBG] handle_scan_debuggers raw_status=0x%08X return_status=0x%08X dbg_pid=%llu flags=0x%08X", raw_status, status, dbg_pid, request->result_flags);
        return status;
    }

    case ADBG_OP_HIDE_THREAD:
    {
        if (request->pid == 0 || request->tid == 0)
            return STATUS_INVALID_PARAMETER;
        return anti_debug::hide_thread_from_debugger(request->pid, request->tid);
    }

    case ADBG_OP_CLEAR_PROC_DR:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        NTSTATUS status = anti_debug::clear_process_debug_registers(request->pid);
        request->dr_clear_count = anti_debug::g_thread_dr_clear_count;
        request->result_flags = NT_SUCCESS(status) ? 0 : 0xFFFFFFFFu;
        return status;
    }

    case ADBG_OP_HIDE_ALL_THREADS:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        return anti_debug::hide_all_process_threads(request->pid);
    }

    case ADBG_OP_INSTALL_INSTR_CB:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        return anti_debug::install_instrumentation_callback(
            request->pid,
            reinterpret_cast<PVOID>(request->detected_debugger_pid));
    }

    case ADBG_OP_REMOVE_INSTR_CB:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        return anti_debug::remove_instrumentation_callback(request->pid);
    }

    case ADBG_OP_START_CONTINUOUS:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        continuous_anti_debug::start(request->pid);
        request->result_flags = 1;
        request->dr_clear_count = continuous_anti_debug::g_cycle_count;
        return STATUS_SUCCESS;
    }

    case ADBG_OP_STOP_CONTINUOUS:
    {
        continuous_anti_debug::stop();
        request->result_flags = 0;
        request->dr_clear_count = continuous_anti_debug::g_violations;
        return STATUS_SUCCESS;
    }

    case ADBG_OP_CLEAR_DEBUG_OBJ:
    {
        if (request->pid == 0)
            return STATUS_INVALID_PARAMETER;
        return anti_debug::clear_debug_objects(request->pid);
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }
}
