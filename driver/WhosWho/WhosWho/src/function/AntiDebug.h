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
            if (KeGetCurrentIrql() > APC_LEVEL) {
                return FALSE;
            }

            BOOLEAN hvci_on = hvci_detect::is_hvci_enabled();
            UINT64 old_irql = 0;
            if (!hvci_on) {
                old_irql = __readcr8();
                __writecr8(2);
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

            if (!hvci_on) {
                __writecr8(old_irql);
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
        *out_debugger_pid = 0;

        __try {
            PEPROCESS proc = nullptr;
            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial) return STATUS_UNSUCCESSFUL;

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + 0x448);
            PLIST_ENTRY entry = list_head->Flink;

            const char* debugger_names[] = {
                "x64dbg.exe", "x32dbg.exe", "windbg.exe",
                "ollydbg.exe", "ida.exe", "ida64.exe",
                "idaq.exe", "idaq64.exe", "dnspy.exe",
                "cheatengine", "ce.exe", "processhacker",
                "apimonitor", "scylla", "titanhide",
                "hyperdbg.exe", "radare2.exe"
            };
            constexpr int num_names = sizeof(debugger_names) / sizeof(debugger_names[0]);

            for (int iter = 0; iter < 1024 && entry != list_head; ++iter, entry = entry->Flink)
            {
                PEPROCESS current = (PEPROCESS)((UINT8*)entry - 0x448);
                if (!_MmIsAddressValid(current)) continue;

                UCHAR* image_name = PsGetProcessImageFileName(current);
                if (!image_name || !_MmIsAddressValid(image_name)) continue;

                for (int n = 0; n < num_names; ++n) {
                    const char* target = debugger_names[n];
                    BOOLEAN match = TRUE;
                    for (int c = 0; target[c] != '\0'; ++c) {
                        char a = (char)(image_name[c] | 0x20);
                        char b = (char)(target[c] | 0x20);
                        if (a != b) { match = FALSE; break; }
                    }
                    if (match) {
                        HANDLE pid_handle = PsGetProcessId(current);
                        *out_debugger_pid = (UINT64)(ULONG_PTR)pid_handle;
                        return STATUS_SUCCESS;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_UNSUCCESSFUL;
        }

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
            UINT8* thread_ptr = (UINT8*)thread;
            volatile ULONG* cross_flags = (volatile ULONG*)(thread_ptr + 0x74);
            InterlockedOr((volatile LONG*)cross_flags, 0x4);
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

                UINT8* thread_ptr = (UINT8*)PsGetCurrentThread();
                KPROCESSOR_MODE* prev_mode = (KPROCESSOR_MODE*)(thread_ptr + 0x232);
                KPROCESSOR_MODE old_mode = *prev_mode;
                *prev_mode = KernelMode;

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

                *prev_mode = old_mode;
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
        if (!_PsGetNextProcessThread) return STATUS_NOT_SUPPORTED;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        UINT32 hidden = 0;

        __try {
            PETHREAD thread = nullptr;
            while ((thread = _PsGetNextProcessThread(process, thread)) != nullptr)
            {
                UINT8* thread_ptr = (UINT8*)thread;
                volatile ULONG* cross_flags = (volatile ULONG*)(thread_ptr + 0x74);
                ULONG old_flags = InterlockedOr((volatile LONG*)cross_flags, 0x4);
                if (!(old_flags & 0x4)) hidden++;
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

        typedef NTSTATUS(NTAPI* fn_NtSetInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG);

        static fn_NtSetInformationProcess pNtSetInfoProc = nullptr;
        if (!pNtSetInfoProc) {
            PVOID nt_base = (PVOID)get_nt_base();
            if (nt_base) {
                CHAR name[] = { 'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };
                pNtSetInfoProc = (fn_NtSetInformationProcess)GetProcAddress(nt_base, name);
            }
        }

        if (pNtSetInfoProc) {
            UINT8* thread_ptr = (UINT8*)PsGetCurrentThread();
            KPROCESSOR_MODE* prev_mode = (KPROCESSOR_MODE*)(thread_ptr + 0x232);
            KPROCESSOR_MODE old_mode = *prev_mode;
            *prev_mode = KernelMode;

            status = pNtSetInfoProc(
                proc_handle,
                40,
                &info,
                sizeof(info));

            *prev_mode = old_mode;

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
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) return status;

        __try {
            UINT8* eprocess = (UINT8*)process;
            volatile PVOID* debug_port = (volatile PVOID*)(eprocess + 0x578);
            if (*debug_port != nullptr) {
                InterlockedExchangePointer(debug_port, nullptr);
                WW_LOG("anti_debug: cleared debug port for pid=%u", pid);
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

            PVOID val_430 = *(volatile PVOID*)(eprocess + 0x430);
            PVOID val_438 = *(volatile PVOID*)(eprocess + 0x438);
            PVOID val_440 = *(volatile PVOID*)(eprocess + 0x440);
            PVOID val_448 = *(volatile PVOID*)(eprocess + 0x448);
            PVOID val_450 = *(volatile PVOID*)(eprocess + 0x450);
            PVOID val_458 = *(volatile PVOID*)(eprocess + 0x458);
            PVOID val_460 = *(volatile PVOID*)(eprocess + 0x460);
            PVOID val_468 = *(volatile PVOID*)(eprocess + 0x468);
            PVOID val_470 = *(volatile PVOID*)(eprocess + 0x470);
            PVOID val_478 = *(volatile PVOID*)(eprocess + 0x478);
            PVOID val_4D0 = *(volatile PVOID*)(eprocess + 0x4D0);
            PVOID val_4D8 = *(volatile PVOID*)(eprocess + 0x4D8);
            PVOID val_4E0 = *(volatile PVOID*)(eprocess + 0x4E0);
            PVOID val_4E8 = *(volatile PVOID*)(eprocess + 0x4E8);
            PVOID val_5C0 = *(volatile PVOID*)(eprocess + 0x5C0);
            PVOID val_5C8 = *(volatile PVOID*)(eprocess + 0x5C8);

            WW_LOG("[INSTR-DUMP] pid=%u name=%s eprocess=%p build=%lu.%lu g_instr_cb=%p",
                pid,
                img_name ? (const char*)img_name : "?",
                (PVOID)eprocess,
                osver.dwMajorVersion * 1000 + osver.dwMinorVersion,
                osver.dwBuildNumber,
                g_instrumentation_callback);

            WW_LOG("[INSTR-DUMP] +0x430=%p +0x438=%p +0x440=%p +0x448=%p",
                val_430, val_438, val_440, val_448);
            WW_LOG("[INSTR-DUMP] +0x450=%p +0x458=%p +0x460=%p +0x468=%p",
                val_450, val_458, val_460, val_468);
            WW_LOG("[INSTR-DUMP] +0x470=%p +0x478=%p",
                val_470, val_478);
            WW_LOG("[INSTR-DUMP] +0x4D0=%p +0x4D8=%p +0x4E0=%p +0x4E8=%p",
                val_4D0, val_4D8, val_4E0, val_4E8);
            WW_LOG("[INSTR-DUMP] +0x5C0=%p +0x5C8=%p",
                val_5C0, val_5C8);

            volatile PVOID* instr_cb = (volatile PVOID*)(eprocess + 0x460);
            PVOID cur = *instr_cb;
            BOOLEAN is_canonical = (cur == nullptr) ||
                ((UINT64)cur < 0x00007FFFFFFFFFFull) ||
                ((UINT64)cur >= 0xFFFF800000000000ull);

            WW_LOG("[INSTR-DUMP] offset=0x460 cur=%p is_canonical=%d matches_own=%d",
                cur, is_canonical ? 1 : 0,
                (cur == g_instrumentation_callback) ? 1 : 0);

            if (cur != nullptr && cur != g_instrumentation_callback) {
                WW_LOG("[INSTR-DUMP] WOULD_CLEAR pid=%u cur=%p g=%p — SKIPPING CLEAR, logging only",
                    pid, cur, g_instrumentation_callback);
            } else {
                WW_LOG("[INSTR-DUMP] no foreign cb at 0x460 for pid=%u (cur=%p)", pid, cur);
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
