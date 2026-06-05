#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include <function/CoreSecurity.h>
#include "SentinelBridge.h"
#include "impl/AntiDumpKernel.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif

#ifndef DISPATCH_LEVEL
#define DISPATCH_LEVEL 2
#endif

#ifndef HIGH_LEVEL
#define HIGH_LEVEL 15
#endif

namespace anti_debug {

    constexpr UINT32 DETECT_NONE             = 0x00000000u;
    constexpr UINT32 DETECT_KERNEL_DEBUGGER  = 0x00000001u;
    constexpr UINT32 DETECT_HYPERVISOR       = 0x00000002u;
    constexpr UINT32 DETECT_ETW_ACTIVE       = 0x00000004u;
    constexpr UINT32 DETECT_INSTRUMENTATION  = 0x00000008u;
    constexpr UINT32 DETECT_TIMING_ATTACK    = 0x00000010u;
    constexpr UINT32 DETECT_PAGE_GUARD       = 0x00000020u;
    constexpr UINT32 DETECT_SIDT_ANOMALY     = 0x00000040u;

    inline volatile UINT32 g_detection_flags = DETECT_NONE;
    inline volatile UINT64 g_last_check_tsc = 0;
    inline volatile LONG g_check_lock = 0;

    constexpr UINT64 CHECK_INTERVAL_TSC = 300000000ULL;

    inline volatile UCHAR g_kd_baseline = 0;
    inline volatile LONG  g_kd_baseline_captured = 0;

    typedef struct _ADBG_SYSTEM_PROCESS_INFORMATION {
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
    } ADBG_SYSTEM_PROCESS_INFORMATION, *PADBG_SYSTEM_PROCESS_INFORMATION;
    static_assert(sizeof(ADBG_SYSTEM_PROCESS_INFORMATION) == 256, "ADBG_SYSTEM_PROCESS_INFORMATION size must be 256 bytes");

    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL ADBG_SYSTEM_PROCESS_INFORMATION_CLASS =
        static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(5);
    constexpr ULONG ADBG_PROCESS_SCAN_TAG = 'pDaW';

    __forceinline char lowercase_ascii_char(char ch)
    {
        if (ch >= 'A' && ch <= 'Z')
            return static_cast<char>(ch + ('a' - 'A'));
        return ch;
    }

    __forceinline bool image_file_name_matches_ascii_prefix(const UCHAR* image_name, const char* target)
    {
        if (!image_name || !target)
            return false;

        ULONG index = 0;
        __try {
            for (; target[index] != '\0'; ++index) {
                if (index >= 15)
                    return false;
                char lhs = lowercase_ascii_char(static_cast<char>(image_name[index]));
                char rhs = lowercase_ascii_char(target[index]);
                if (lhs == '\0')
                    return false;
                if (lhs != rhs)
                    return false;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return index != 0;
    }

    __forceinline NTSTATUS hide_thread_object_from_debugger(PETHREAD thread)
    {
        if (!thread || !_ObOpenObjectByPointer || !_ZwSetInformationThread ||
            !PsThreadType || !*PsThreadType)
            return STATUS_NOT_SUPPORTED;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        HANDLE thread_handle = nullptr;
        NTSTATUS status = _ObOpenObjectByPointer(
            thread,
            OBJ_KERNEL_HANDLE,
            nullptr,
            THREAD_SET_INFORMATION,
            *PsThreadType,
            KernelMode,
            &thread_handle);
        if (!NT_SUCCESS(status))
            return status;

        status = _ZwSetInformationThread(
            thread_handle,
            0x11u,
            nullptr,
            0);
        _ZwClose(thread_handle);
        return status;
    }

    __forceinline UCHAR read_kd_shared_byte() {
        UCHAR volatile* kud = reinterpret_cast<UCHAR volatile*>(0xFFFFF78000000000ULL + 0x2D4);
        return *kud;
    }

    __forceinline void initialize_kd_baseline() {
        if (_InterlockedCompareExchange(&g_kd_baseline_captured, 1, 0) == 0) {
            g_kd_baseline = read_kd_shared_byte();
        }
    }

    __forceinline BOOLEAN kd_transitioned_to_enabled() {
        if (_KdRefreshDebuggerNotPresent) {
            _KdRefreshDebuggerNotPresent();
        }
        UCHAR current = read_kd_shared_byte();
        UCHAR baseline = g_kd_baseline;
        return (current != 0) && (baseline == 0);
    }

    __forceinline void acquire_lock() {
        while (_InterlockedCompareExchange(&g_check_lock, 1, 0) != 0) {
            YieldProcessor();
        }
        KeMemoryBarrier();
    }

    __forceinline void release_lock() {
        KeMemoryBarrier();
        _InterlockedExchange(&g_check_lock, 0);
    }

    __forceinline BOOLEAN check_kernel_debugger() {
        __try {
            if (KD_DEBUGGER_ENABLED) {
                return TRUE;
            }

            if (!KD_DEBUGGER_NOT_PRESENT) {
                return TRUE;
            }

            PKUSER_SHARED_DATA shared_data = reinterpret_cast<PKUSER_SHARED_DATA>(0xFFFFF78000000000ULL);
            if (shared_data && _MmIsAddressValid(shared_data)) {
                if (shared_data->KdDebuggerEnabled) {
                    return TRUE;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return TRUE;
        }

        return FALSE;
    }

    __forceinline BOOLEAN check_hypervisor() {
        int cpuInfo[4] = { 0 };

        __try {
            __cpuid(cpuInfo, 1);

            if (cpuInfo[2] & (1 << 31)) {
                int vendorInfo[4] = { 0 };
                __cpuid(vendorInfo, 0x40000000);

                if (vendorInfo[0] >= 0x40000001) {
                    char vendor_id[13] = { 0 };
                    *(int*)&vendor_id[0] = vendorInfo[1];
                    *(int*)&vendor_id[4] = vendorInfo[2];
                    *(int*)&vendor_id[8] = vendorInfo[3];
                    vendor_id[12] = '\0';

                    if (vendor_id[0] == 'M' && vendor_id[1] == 'i' &&
                        vendor_id[2] == 'c' && vendor_id[3] == 'r' &&
                        vendor_id[4] == 'o' && vendor_id[5] == 's' &&
                        vendor_id[6] == 'o' && vendor_id[7] == 'f' &&
                        vendor_id[8] == 't' && vendor_id[9] == ' ' &&
                        vendor_id[10] == 'H' && vendor_id[11] == 'v') {

                        return FALSE;
                    }

                    if (vendor_id[0] == 'V' && vendor_id[1] == 'M' &&
                        vendor_id[2] == 'w' && vendor_id[3] == 'a' &&
                        vendor_id[4] == 'r' && vendor_id[5] == 'e' &&
                        vendor_id[6] == 'V' && vendor_id[7] == 'M' &&
                        vendor_id[8] == 'w' && vendor_id[9] == 'a' &&
                        vendor_id[10] == 'r' && vendor_id[11] == 'e') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'V' && vendor_id[1] == 'B' &&
                        vendor_id[2] == 'o' && vendor_id[3] == 'x' &&
                        vendor_id[4] == 'V' && vendor_id[5] == 'B' &&
                        vendor_id[6] == 'o' && vendor_id[7] == 'x' &&
                        vendor_id[8] == 'V' && vendor_id[9] == 'B' &&
                        vendor_id[10] == 'o' && vendor_id[11] == 'x') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'K' && vendor_id[1] == 'V' &&
                        vendor_id[2] == 'M' && vendor_id[3] == 'K' &&
                        vendor_id[4] == 'V' && vendor_id[5] == 'M' &&
                        vendor_id[6] == 'K' && vendor_id[7] == 'V' &&
                        vendor_id[8] == 'M') {
                        return TRUE;
                    }

                    if (vendor_id[0] == 'X' && vendor_id[1] == 'e' &&
                        vendor_id[2] == 'n' && vendor_id[3] == 'V' &&
                        vendor_id[4] == 'M' && vendor_id[5] == 'M' &&
                        vendor_id[6] == 'X' && vendor_id[7] == 'e' &&
                        vendor_id[8] == 'n' && vendor_id[9] == 'V' &&
                        vendor_id[10] == 'M' && vendor_id[11] == 'M') {
                        return TRUE;
                    }

                    return FALSE;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    #pragma pack(push, 1)
    struct idt_descriptor_t {
        USHORT limit;
        ULONG_PTR base;
    };
    #pragma pack(pop)

    __forceinline BOOLEAN check_sidt_compat_anomaly() {
        __try {
            idt_descriptor_t idt1 = {};
            __sidt(&idt1);

            idt_descriptor_t idt2 = {};
            __sidt(&idt2);

            if (idt1.base != idt2.base)
                return TRUE;

            if (idt1.base == 0 || idt1.limit == 0)
                return TRUE;

            if (idt1.limit < 0x07FFu)
                return TRUE;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
        return FALSE;
    }

    __forceinline BOOLEAN check_timing_attack() {
        __try {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
                return FALSE;
            }

            constexpr UINT32 NUM_TRIALS = 3;
            constexpr UINT64 TIMING_THRESHOLD = 10000000ULL;
            UINT32 fail_count = 0;

            for (UINT32 trial = 0; trial < NUM_TRIALS; trial++) {
                UINT64 start = __rdtsc();

                volatile UINT64 dummy = 0;
                for (int i = 0; i < 16; i++) {
                    dummy += __rdtsc();
                    KeMemoryBarrier();
                }

                UINT64 end = __rdtsc();
                UINT64 elapsed = end - start;

                if (elapsed > TIMING_THRESHOLD) {
                    fail_count++;
                }
            }

            if (fail_count == NUM_TRIALS) {
                return TRUE;
            }

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    __forceinline BOOLEAN check_instrumentation() {
        __try {
            KIRQL current_irql = (KIRQL)__readcr8();

            if (current_irql > DISPATCH_LEVEL &&
                current_irql != HIGH_LEVEL) {
                return TRUE;
            }

            UINT64 rflags = __readeflags();

            if (rflags & 0x100) {
                return TRUE;
            }

            if ((rflags & 0x10000) && (rflags & 0x100)) {
                return TRUE;
            }

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return FALSE;
    }

    __forceinline UINT32 run_all_checks() {
        UINT32 flags = DETECT_NONE;

        if (check_kernel_debugger()) {
            flags |= DETECT_KERNEL_DEBUGGER;
        }

        if (check_hypervisor()) {
            flags |= DETECT_HYPERVISOR;
        }

        if (check_timing_attack()) {
            flags |= DETECT_TIMING_ATTACK;
        }

        if (check_instrumentation()) {
            flags |= DETECT_INSTRUMENTATION;
        }

        if (check_sidt_compat_anomaly()) {
            flags |= DETECT_SIDT_ANOMALY;
        }

        return flags;
    }

    __forceinline UINT32 get_detection_flags() {
        UINT64 current_tsc = __rdtsc();
        UINT64 last_check = g_last_check_tsc;

        if (current_tsc - last_check < CHECK_INTERVAL_TSC) {
            return g_detection_flags;
        }

        acquire_lock();

        if (__rdtsc() - g_last_check_tsc < CHECK_INTERVAL_TSC) {
            UINT32 cached = g_detection_flags;
            release_lock();
            return cached;
        }

        UINT32 new_flags = run_all_checks();
        g_detection_flags = new_flags;
        g_last_check_tsc = __rdtsc();

        release_lock();
        return new_flags;
    }

    __forceinline BOOLEAN is_safe_to_operate() {
        return TRUE;
    }

    __forceinline UINT32 refresh_detection() {
        acquire_lock();
        UINT32 flags = run_all_checks();
        g_detection_flags = flags;
        g_last_check_tsc = __rdtsc();
        release_lock();
        return flags;
    }

    inline volatile UINT64 g_dr_clear_count = 0;

    typedef struct _DR_CLEAR_DPC_CONTEXT {
        KDPC dpc;
        KEVENT event;
        UINT32 target_pid;
    } DR_CLEAR_DPC_CONTEXT;

    static void dr_clear_dpc_routine(
        PKDPC Dpc,
        PVOID DeferredContext,
        PVOID SystemArgument1,
        PVOID SystemArgument2)
    {
        UNREFERENCED_PARAMETER(Dpc);
        UNREFERENCED_PARAMETER(SystemArgument1);
        UNREFERENCED_PARAMETER(SystemArgument2);

        __try {
            __writedr(0, 0);
            __writedr(1, 0);
            __writedr(2, 0);
            __writedr(3, 0);
            __writedr(6, 0);
            __writedr(7, 0);
            InterlockedIncrement64((volatile LONG64*)&g_dr_clear_count);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        DR_CLEAR_DPC_CONTEXT* ctx = (DR_CLEAR_DPC_CONTEXT*)DeferredContext;
        if (ctx) {
            KeSetEvent(&ctx->event, 0, FALSE);
        }
    }

    inline NTSTATUS clear_debug_registers_all_cpus()
    {
        ULONG num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (num_cpus == 0) return STATUS_UNSUCCESSFUL;

        DR_CLEAR_DPC_CONTEXT* contexts = (DR_CLEAR_DPC_CONTEXT*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(DR_CLEAR_DPC_CONTEXT) * num_cpus, 'ADBC');
        if (!contexts) return STATUS_INSUFFICIENT_RESOURCES;

        for (ULONG i = 0; i < num_cpus; ++i) {
            KeInitializeEvent(&contexts[i].event, SynchronizationEvent, FALSE);
            KeInitializeDpc(&contexts[i].dpc, dr_clear_dpc_routine, &contexts[i]);

            PROCESSOR_NUMBER proc_num;
            NTSTATUS ks = KeGetProcessorNumberFromIndex(i, &proc_num);
            if (NT_SUCCESS(ks)) {
                KeSetTargetProcessorDpcEx(&contexts[i].dpc, &proc_num);
                KeInsertQueueDpc(&contexts[i].dpc, nullptr, nullptr);
            }
        }

        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL;
        for (ULONG i = 0; i < num_cpus; ++i) {
            KeWaitForSingleObject(&contexts[i].event, Executive, KernelMode, FALSE, &timeout);
        }

        ExFreePoolWithTag(contexts, 'ADBC');
        return STATUS_SUCCESS;
    }

    inline NTSTATUS scan_for_debugger_processes(UINT64* out_debugger_pid)
    {
        if (!out_debugger_pid)
            return STATUS_INVALID_PARAMETER;
        *out_debugger_pid = 0;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X reason=bad_irql irql=%u", STATUS_INVALID_DEVICE_STATE, KeGetCurrentIrql());
            return STATUS_INVALID_DEVICE_STATE;
        }

        const char* debugger_names[] = {
            "x64dbg.exe", "x32dbg.exe", "windbg.exe",
            "ollydbg.exe", "ida.exe", "ida64.exe",
            "idaq.exe", "idaq64.exe", "dnspy.exe",
            "cheatengine", "ce.exe", "processhacker",
            "apimonitor", "scylla", "titanhide",
            "hyperdbg.exe", "radare2.exe"
        };
        constexpr int num_names = sizeof(debugger_names) / sizeof(debugger_names[0]);

        ULONG required_length = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            ADBG_SYSTEM_PROCESS_INFORMATION_CLASS,
            nullptr,
            0,
            &required_length);
        WW_LOG("[ADBG] scan_debuggers_probe status=0x%08X required=%lu", status, required_length);

        ULONG buffer_length = required_length;
        if (buffer_length < 0x100000)
            buffer_length = 0x100000;
        else
            buffer_length += 0x10000;

        PVOID buffer = nullptr;
        for (int attempt = 0; attempt < 3; ++attempt) {
            buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, ADBG_PROCESS_SCAN_TAG);
            if (!buffer) {
                WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X reason=alloc_failed attempt=%d size=%lu", STATUS_INSUFFICIENT_RESOURCES, attempt, buffer_length);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = ZwQuerySystemInformation(
                ADBG_SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer,
                buffer_length,
                &required_length);
            WW_LOG("[ADBG] scan_debuggers_query attempt=%d status=0x%08X size=%lu required=%lu", attempt, status, buffer_length, required_length);

            if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
                break;

            ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
            buffer = nullptr;

            ULONG next_length = required_length;
            if (next_length <= buffer_length)
                next_length = buffer_length * 2;
            if (next_length < buffer_length)
                return STATUS_INTEGER_OVERFLOW;
            buffer_length = next_length + 0x10000;
            if (buffer_length < next_length)
                return STATUS_INTEGER_OVERFLOW;
        }

        if (!buffer)
            return STATUS_UNSUCCESSFUL;

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
            WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X reason=query_failed", status);
            return status;
        }

        PUCHAR cursor = static_cast<PUCHAR>(buffer);
        PUCHAR end = cursor + buffer_length;
        ULONG scanned = 0;
        ULONG lookup_misses = 0;

        while (cursor + sizeof(ADBG_SYSTEM_PROCESS_INFORMATION) <= end && scanned < 131072) {
            auto info = reinterpret_cast<PADBG_SYSTEM_PROCESS_INFORMATION>(cursor);
            ++scanned;

            if (info->UniqueProcessId != nullptr) {
                PEPROCESS process = nullptr;
                NTSTATUS lookup_status = PsLookupProcessByProcessId(info->UniqueProcessId, &process);
                if (NT_SUCCESS(lookup_status) && process) {
                    bool matched = false;
                    UCHAR* image_name = PsGetProcessImageFileName(process);
                    if (image_name) {
                        for (int n = 0; n < num_names; ++n) {
                            if (image_file_name_matches_ascii_prefix(image_name, debugger_names[n])) {
                                *out_debugger_pid = (UINT64)(ULONG_PTR)info->UniqueProcessId;
                                matched = true;
                                break;
                            }
                        }
                    }
                    ObDereferenceObject(process);
                    if (matched) {
                        ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
                        WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X result=hit scanned=%lu lookup_misses=%lu pid=%llu", STATUS_SUCCESS, scanned, lookup_misses, *out_debugger_pid);
                        return STATUS_SUCCESS;
                    }
                } else {
                    ++lookup_misses;
                }
            }

            if (info->NextEntryOffset == 0)
                break;
            if (info->NextEntryOffset < sizeof(ADBG_SYSTEM_PROCESS_INFORMATION) ||
                cursor + info->NextEntryOffset <= cursor ||
                cursor + info->NextEntryOffset > end) {
                ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
                WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X reason=bad_next offset=%lu scanned=%lu", STATUS_DATA_ERROR, info->NextEntryOffset, scanned);
                return STATUS_DATA_ERROR;
            }
            cursor += info->NextEntryOffset;
        }

        ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
        WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X result=none scanned=%lu lookup_misses=%lu", STATUS_NOT_FOUND, scanned, lookup_misses);

        return STATUS_NOT_FOUND;
    }

    inline NTSTATUS hide_thread_from_debugger(UINT32 pid, UINT32 tid)
    {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        PETHREAD thread = nullptr;
        status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &thread);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }

        __try {
            status = hide_thread_object_from_debugger(thread);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return status;
    }


    inline volatile UINT64 g_thread_dr_clear_count = 0;

    inline NTSTATUS clear_process_debug_registers(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!_PsGetNextProcessThread) return STATUS_NOT_SUPPORTED;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        UINT32 cleared = 0;

        __try {
            PETHREAD thread = nullptr;
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr)
            {
                HANDLE thread_handle = nullptr;
                NTSTATUS hs = _ObOpenObjectByPointer(
                    thread, OBJ_KERNEL_HANDLE, nullptr,
                    THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
                    *PsThreadType, KernelMode, &thread_handle);

                if (!NT_SUCCESS(hs)) continue;

                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                hs = _PsGetContextThread(thread, &ctx, KernelMode);
                if (NT_SUCCESS(hs)) {
                    BOOLEAN need_clear = (ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
                                          ctx.Dr2 != 0 || ctx.Dr3 != 0 ||
                                          (ctx.Dr7 & 0xFF) != 0);
                    if (need_clear) {
                        ctx.Dr0 = 0;
                        ctx.Dr1 = 0;
                        ctx.Dr2 = 0;
                        ctx.Dr3 = 0;
                        ctx.Dr6 = 0;
                        ctx.Dr7 = 0x400;

                        hs = _PsSetContextThread(thread, &ctx, KernelMode);
                        if (NT_SUCCESS(hs)) cleared++;
                    }
                }
                _ZwClose(thread_handle);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        InterlockedAdd64((volatile LONG64*)&g_thread_dr_clear_count, cleared);
        return STATUS_SUCCESS;
    }


    inline NTSTATUS hide_all_process_threads(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
        if (!_PsGetNextProcessThread) return STATUS_NOT_SUPPORTED;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        UINT32 hidden = 0;

        __try {
            PETHREAD thread = nullptr;
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr)
            {
                NTSTATUS hs = hide_thread_object_from_debugger(thread);
                if (NT_SUCCESS(hs)) hidden++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        WW_LOG("anti_debug: hid %u threads for pid=%u", hidden, pid);
        return status;
    }


    typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
        ULONG  Version;
        ULONG  Reserved;
        PVOID  Callback;
    } PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

    inline volatile PVOID g_instrumentation_callback = nullptr;

    inline NTSTATUS install_instrumentation_callback(UINT32 pid, PVOID callback_addr)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        HANDLE proc_handle = nullptr;
        status = _ObOpenObjectByPointer(
            process, OBJ_KERNEL_HANDLE, nullptr,
            PROCESS_SET_INFORMATION, *PsProcessType, KernelMode, &proc_handle);

        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = {};
        info.Version  = 0;
        info.Reserved = 0;
        info.Callback = callback_addr;

        typedef NTSTATUS(NTAPI* fn_ZwSetInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG);

        static fn_ZwSetInformationProcess pZwSetInfoProc = nullptr;
        if (!pZwSetInfoProc) {
            PVOID nt_base = (PVOID)get_nt_base();
            if (nt_base) {
                CHAR name[] = { 'Z','w','S','e','t','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };
                pZwSetInfoProc = (fn_ZwSetInformationProcess)GetProcAddress(nt_base, name);
            }
        }

        if (pZwSetInfoProc) {
            status = pZwSetInfoProc(
                proc_handle,
                40,
                &info,
                sizeof(info));

            if (NT_SUCCESS(status)) {
                g_instrumentation_callback = callback_addr;
                WW_LOG("anti_debug: instrumentation callback installed for pid=%u", pid);
            }
        } else {
            status = STATUS_NOT_FOUND;
        }

        _ZwClose(proc_handle);
        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS remove_instrumentation_callback(UINT32 pid)
    {
        return install_instrumentation_callback(pid, nullptr);
    }

    inline NTSTATUS clear_debug_objects(UINT32 pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        __try {
            UINT8* eprocess = (UINT8*)process;
            volatile PVOID* debug_port = (volatile PVOID*)(eprocess + 0x578);
            if (_MmIsAddressValid((PVOID)debug_port) && *debug_port != nullptr) {
                UINT64 port_value = reinterpret_cast<UINT64>(*debug_port);
                UINT32 port_tag = static_cast<UINT32>((port_value >> 32) ^ port_value ^ 0x0A1DAD57u);
                WW_LOG("anti_debug: debug port present for pid=%u tag=0x%08X", pid, port_tag);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS clear_instrumentation_callback_eprocess(UINT32 pid)
    {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        __try {
            UINT8* eprocess = (UINT8*)process;

            RTL_OSVERSIONINFOW osver = {};
            osver.dwOSVersionInfoSize = sizeof(osver);
            if (_RtlGetVersion) _RtlGetVersion(&osver);

            UCHAR* img_name = PsGetProcessImageFileName(process);

            WW_LOG("[INSTR-DUMP] pid=%u name=%s eprocess_redacted=1 build=%lu.%lu g_instr_cb_redacted=1",
                pid,
                img_name ? (const char*)img_name : "?",
                osver.dwMajorVersion * 1000 + osver.dwMinorVersion,
                osver.dwBuildNumber);

            volatile PVOID* instr_cb = (volatile PVOID*)(eprocess + 0x460);
            PVOID cur = *instr_cb;
            BOOLEAN is_canonical = (cur == nullptr) ||
                ((UINT64)cur < 0x00007FFFFFFFFFFull) ||
                ((UINT64)cur >= 0xFFFF800000000000ull);

            UINT64 cur_value = reinterpret_cast<UINT64>(cur);
            UINT32 cur_tag = static_cast<UINT32>((cur_value >> 32) ^ cur_value ^ 0x0A1DA460u);
            UINT64 own_value = reinterpret_cast<UINT64>(g_instrumentation_callback);
            UINT32 own_tag = static_cast<UINT32>((own_value >> 32) ^ own_value ^ 0x0A1DA461u);

            WW_LOG("[INSTR-DUMP] offset=0x460 present=%d is_canonical=%d matches_own=%d cur_tag=0x%08X own_tag=0x%08X",
                cur != nullptr ? 1 : 0,
                is_canonical ? 1 : 0,
                (cur == g_instrumentation_callback) ? 1 : 0,
                cur_tag,
                own_tag);

            if (cur != nullptr && !is_canonical) {
                WW_LOG("[INSTR-DUMP] noncanonical cb ignored for pid=%u build=%lu cur_tag=0x%08X",
                    pid, osver.dwBuildNumber, cur_tag);
            } else if (cur != nullptr && cur != g_instrumentation_callback) {
                WW_LOG("[INSTR-DUMP] WOULD_CLEAR pid=%u cur_tag=0x%08X own_tag=0x%08X",
                    pid, cur_tag, own_tag);
            } else {
                WW_LOG("[INSTR-DUMP] no foreign cb at 0x460 for pid=%u present=%d", pid, cur != nullptr ? 1 : 0);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("[INSTR-DUMP] EXCEPTION during dump for pid=%u", pid);
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        return status;
    }
}

namespace continuous_anti_debug {

    inline KTIMER   g_timer = {};
    inline KDPC     g_dpc   = {};
    inline volatile LONG   g_active = 0;
    inline volatile UINT32 g_target_pid = 0;
    inline volatile UINT64 g_cycle_count = 0;
    inline volatile UINT64 g_violations = 0;
    inline WORK_QUEUE_ITEM g_work_item = {};
    inline volatile LONG   g_work_item_queued = 0;

    constexpr LONG TIMER_PERIOD_MS = 5000;

    inline VOID NTAPI work_item_callback(PVOID)
    {
        if (!_InterlockedCompareExchange(&g_active, 0, 0)) {
            _InterlockedExchange(&g_work_item_queued, 0);
            return;
        }

        UINT32 pid = g_target_pid;
        if (pid == 0) {
            _InterlockedExchange(&g_work_item_queued, 0);
            return;
        }

        InterlockedIncrement64((volatile LONG64*)&g_cycle_count);
        UINT64 cycle = g_cycle_count;

        UINT32 det_flags = anti_debug::run_all_checks();
        if (det_flags & (anti_debug::DETECT_KERNEL_DEBUGGER | anti_debug::DETECT_TIMING_ATTACK)) {
            InterlockedIncrement64((volatile LONG64*)&g_violations);
            sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
            sentinel_bridge::g_bridge.sentinel_cmd_param = det_flags;
        }

        anti_debug::clear_process_debug_registers(pid);

        if ((cycle & 0x1) == 0) {
            anti_debug::clear_debug_registers_all_cpus();
        }

        if ((cycle % 3) == 0) {
            anti_debug::clear_debug_objects(pid);
            WW_LOG("[CONT-ADBG] cycle=%llu calling clear_instrumentation_callback_eprocess pid=%u", cycle, pid);
            anti_debug::clear_instrumentation_callback_eprocess(pid);
        }

        if ((cycle % 5) == 0) {


            BOOLEAN target_being_debugged = FALSE;
            {
                PEPROCESS target_proc = nullptr;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &target_proc)) && target_proc) {
                    __try {


                        ULONG_PTR* debug_port_ptr = (ULONG_PTR*)((UINT8*)target_proc + 0x578);
                        if (_MmIsAddressValid(debug_port_ptr) && *debug_port_ptr != 0)
                            target_being_debugged = TRUE;
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    ObDereferenceObject(target_proc);
                }
            }

            if (target_being_debugged) {
                UINT64 dbg_pid = 0;
                NTSTATUS st = anti_debug::scan_for_debugger_processes(&dbg_pid);
                if (NT_SUCCESS(st) && dbg_pid != 0) {
                    InterlockedIncrement64((volatile LONG64*)&g_violations);
                    sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_DEBUGGER_FOUND;
                    sentinel_bridge::g_bridge.sentinel_cmd_param = (ULONG)(dbg_pid & 0xFFFFFFFF);

                    if (anti_dump_kernel::is_permitted_pid((UINT32)(dbg_pid & 0xFFFFFFFF))) {
                        WW_LOG("continuous_adbg: skipped debugger kill for permitted pid=%llu", dbg_pid);
                    }
                    else if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = (HANDLE)(ULONG_PTR)dbg_pid;
                        HANDLE hProc = nullptr;
                        if (NT_SUCCESS(_ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid)) && hProc) {
                            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                            _ZwClose(hProc);
                            WW_LOG("continuous_adbg: killed debugger pid=%llu (was attached to protected pid=%u)", dbg_pid, pid);
                        }
                    }
                }
            }
        }

        if ((cycle % 4) == 0) {
            anti_debug::hide_all_process_threads(pid);
        }

        _InterlockedExchange(&g_work_item_queued, 0);
    }

    inline VOID NTAPI timer_callback(
        PKDPC,
        PVOID,
        PVOID,
        PVOID)
    {
        if (!_InterlockedCompareExchange(&g_active, 0, 0))
            return;

        if (_InterlockedCompareExchange(&g_work_item_queued, 1, 0) == 0) {
            ExInitializeWorkItem(&g_work_item, work_item_callback, nullptr);
            _ExQueueWorkItem(&g_work_item, DelayedWorkQueue);
        }
    }

    inline void start(UINT32 pid)
    {
        if (_InterlockedCompareExchange(&g_active, 1, 0) != 0) {
            _InterlockedExchange(reinterpret_cast<volatile LONG*>(&g_target_pid),
                static_cast<LONG>(pid));
            WW_LOG("continuous_adbg: retarget pid=%u (was already active)", pid);
            return;
        }

        g_target_pid = pid;
        g_cycle_count = 0;
        g_violations = 0;

        _KeInitializeTimerEx(&g_timer, SynchronizationTimer);
        _KeInitializeDpc(&g_dpc, timer_callback, nullptr);

        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(TIMER_PERIOD_MS) * 10000LL;

        _KeSetTimerEx(&g_timer, due_time, TIMER_PERIOD_MS, &g_dpc);

        WW_LOG("continuous_adbg: started for pid=%u period=%dms", pid, TIMER_PERIOD_MS);
    }

    inline void stop()
    {
        if (_InterlockedCompareExchange(&g_active, 0, 1) != 1)
            return;

        KeCancelTimer(&g_timer);
        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();
        g_target_pid = 0;
        WW_LOG("continuous_adbg: stopped");
    }

    inline void stop_if_target(UINT32 pid)
    {
        if (pid == 0) return;
        LONG prev = _InterlockedCompareExchange(
            reinterpret_cast<volatile LONG*>(&g_target_pid),
            0,
            static_cast<LONG>(pid));
        if (prev == static_cast<LONG>(pid)) {
            WW_LOG("continuous_adbg: cleared target pid=%u (process exiting)", pid);
        }
    }
}
