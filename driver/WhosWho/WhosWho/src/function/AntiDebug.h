#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include <function/CoreSecurity.h>
#include "KernelLayout.h"
#include "SentinelBridge.h"
#include "KernelCrypto.h"
#include "impl/AntiDumpKernel.h"

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

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

    namespace process_guard_fwd {
        void register_re_tool_pid(HANDLE pid);
    }

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

    inline UINT8 g_re_tool_hashes[16][32] = {};
    inline volatile LONG g_re_tool_hash_count = 0;
    inline KSPIN_LOCK g_re_tool_hash_lock = {};
    inline volatile LONG g_re_tool_hash_lock_init = 0;

    __forceinline void ensure_re_tool_hash_lock() {
        if (_InterlockedCompareExchange(&g_re_tool_hash_lock_init, 1, 0) == 0) {
            KeInitializeSpinLock(&g_re_tool_hash_lock);
        }
    }

    __forceinline void update_re_tool_hashes(const UINT8* hashes, ULONG count) {
        if (!hashes || count == 0) return;
        if (count > 16) count = 16;
        ensure_re_tool_hash_lock();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_re_tool_hash_lock, &old_irql);
        RtlSecureZeroMemory(g_re_tool_hashes, sizeof(g_re_tool_hashes));
        RtlCopyMemory(g_re_tool_hashes, hashes, count * 32);
        _InterlockedExchange(&g_re_tool_hash_count, static_cast<LONG>(count));
        KeReleaseSpinLock(&g_re_tool_hash_lock, old_irql);
        WW_LOG("[ADBG] re_tool_hashes_updated count=%lu", count);
    }

    __forceinline bool match_re_tool_hash(const UINT8 hash[32]) {
        if (!hash) return false;
        ensure_re_tool_hash_lock();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_re_tool_hash_lock, &old_irql);
        bool matched = false;
        LONG count = g_re_tool_hash_count;
        if (count > 16) count = 16;
        for (LONG i = 0; i < count; ++i) {
            const UINT8* entry = g_re_tool_hashes[i];
            bool same = true;
            for (int j = 0; j < 32; ++j) {
                if (entry[j] != hash[j]) { same = false; break; }
            }
            if (same) { matched = true; break; }
        }
        KeReleaseSpinLock(&g_re_tool_hash_lock, old_irql);
        return matched;
    }

    __forceinline NTSTATUS compute_file_sha256(
        PCUNICODE_STRING image_path,
        UINT8 out_hash[32])
    {
        if (!image_path || !image_path->Buffer || image_path->Length == 0 || !out_hash)
            return STATUS_INVALID_PARAMETER;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        UNICODE_STRING local_path;
        local_path.Length = image_path->Length;
        local_path.MaximumLength = image_path->Length;
        local_path.Buffer = image_path->Buffer;

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &local_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        IO_STATUS_BLOCK iosb;
        HANDLE hFile = nullptr;
        NTSTATUS status = ZwCreateFile(
            &hFile,
            FILE_READ_DATA | SYNCHRONIZE,
            &oa, &iosb, nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr, 0);

        if (!NT_SUCCESS(status) || !hFile) {
            return status;
        }

        kernel_crypto::sha256_ctx_t ctx;
        kernel_crypto::sha256_init(&ctx);

        constexpr ULONG READ_CHUNK = 65536;
        PUCHAR chunk = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, READ_CHUNK, 'HASH'));
        if (!chunk) {
            ZwClose(hFile);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        LARGE_INTEGER offset = {};
        for (;;) {
            IO_STATUS_BLOCK read_iosb;
            status = ZwReadFile(
                hFile, nullptr, nullptr, nullptr,
                &read_iosb, chunk, READ_CHUNK, &offset, nullptr);

            if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE) {
                ExFreePoolWithTag(chunk, 'HASH');
                ZwClose(hFile);
                return status;
            }

            ULONG bytes_read = static_cast<ULONG>(read_iosb.Information);
            if (bytes_read == 0)
                break;

            kernel_crypto::sha256_update(&ctx, chunk, bytes_read);
            offset.QuadPart += bytes_read;

            if (status == STATUS_END_OF_FILE || bytes_read < READ_CHUNK)
                break;
        }

        kernel_crypto::sha256_final(&ctx, out_hash);
        RtlSecureZeroMemory(&ctx, sizeof(ctx));
        ExFreePoolWithTag(chunk, 'HASH');
        ZwClose(hFile);
        return STATUS_SUCCESS;
    }

    __forceinline NTSTATUS get_process_image_path(
        HANDLE pid,
        UNICODE_STRING* out_path,
        WCHAR* path_buffer,
        USHORT buffer_capacity_bytes)
    {
        if (!pid || !out_path || !path_buffer || buffer_capacity_bytes == 0)
            return STATUS_INVALID_PARAMETER;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
        if (!NT_SUCCESS(status) || !process)
            return status;

        HANDLE hProc = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
        CLIENT_ID cid = {};
        cid.UniqueProcess = pid;

        status = _ZwOpenProcess
            ? _ZwOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid)
            : STATUS_NOT_SUPPORTED;

        if (!NT_SUCCESS(status) || !hProc) {
            ObDereferenceObject(process);
            return status;
        }

        ULONG return_len = 0;
        constexpr ULONG ProcessImageFileName = 27;
        status = ZwQueryInformationProcess(
            hProc,
            static_cast<PROCESSINFOCLASS>(ProcessImageFileName),
            path_buffer,
            buffer_capacity_bytes,
            &return_len);

        _ZwClose(hProc);
        ObDereferenceObject(process);

        if (!NT_SUCCESS(status) || return_len == 0)
            return status;

        struct PROCESS_IMAGE_NAME_INFO {
            USHORT NameLength;
            WCHAR Name[1];
        };
        auto* name_info = reinterpret_cast<PROCESS_IMAGE_NAME_INFO*>(path_buffer);
        USHORT name_bytes = name_info->NameLength;
        if (name_bytes == 0 || name_bytes > buffer_capacity_bytes - sizeof(USHORT))
            return STATUS_BUFFER_TOO_SMALL;

        USHORT copy_chars = name_bytes / sizeof(WCHAR);
        if (copy_chars > 0) {
            RtlMoveMemory(path_buffer, name_info->Name, name_bytes);
        }
        out_path->Length = name_bytes;
        out_path->MaximumLength = name_bytes;
        out_path->Buffer = path_buffer;
        return STATUS_SUCCESS;
    }

    __forceinline bool is_pid_re_tool_by_hash(HANDLE pid) {
        if (!pid) return false;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return false;

        WCHAR path_buf[520] = {};
        UNICODE_STRING image_path = {};
        NTSTATUS status = get_process_image_path(pid, &image_path, path_buf, sizeof(path_buf) - sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            return false;

        UINT8 file_hash[32] = {};
        status = compute_file_sha256(&image_path, file_hash);
        if (!NT_SUCCESS(status))
            return false;

        bool matched = match_re_tool_hash(file_hash);
        if (matched) {
            WW_LOG("[ADBG] hash_match pid=%llu", reinterpret_cast<UINT64>(pid));
        }
        RtlSecureZeroMemory(file_hash, sizeof(file_hash));
        return matched;
    }

    constexpr UINT64 CHECK_INTERVAL_TSC = 300000000ULL;

    inline volatile UCHAR g_kd_baseline = 0;
    inline volatile LONG  g_kd_baseline_captured = 0;
    inline volatile LONG  g_kd_state_log = -1;

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

    __forceinline bool image_file_name_equals_ascii(const UCHAR* image_name, const char* target)
    {
        if (!image_name || !target)
            return false;

        ULONG index = 0;
        __try {
            for (; index < 15; ++index) {
                char lhs = lowercase_ascii_char(static_cast<char>(image_name[index]));
                char rhs = lowercase_ascii_char(target[index]);
                if (rhs == '\0')
                    return lhs == '\0';
                if (lhs == '\0' || lhs != rhs)
                    return false;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        return target[index] == '\0';
    }

    __forceinline bool image_file_name_is_supported_ida_host(const UCHAR* image_name)
    {
        static const char* supported_ida_hosts[] = {
            "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
            "idat.exe", "idat64.exe", "idaw.exe", "idaw64.exe"
        };
        for (int i = 0; i < static_cast<int>(sizeof(supported_ida_hosts) / sizeof(supported_ida_hosts[0])); ++i) {
            if (image_file_name_equals_ascii(image_name, supported_ida_hosts[i]))
                return true;
        }
        return false;
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

    __forceinline BOOLEAN kd_shared_enabled(UCHAR value) {
        return (value & 0x1u) != 0 ? TRUE : FALSE;
    }

    __forceinline BOOLEAN kd_shared_not_present(UCHAR value) {
        return (value & 0x2u) != 0 ? TRUE : FALSE;
    }

    __forceinline BOOLEAN kd_shared_active(UCHAR value) {
        return (kd_shared_enabled(value) && !kd_shared_not_present(value)) ? TRUE : FALSE;
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
        return kd_shared_active(current) && !kd_shared_active(baseline);
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
            if (_KdRefreshDebuggerNotPresent) {
                _KdRefreshDebuggerNotPresent();
            }

            const BOOLEAN kd_enabled = KD_DEBUGGER_ENABLED ? TRUE : FALSE;
            const BOOLEAN kd_not_present = KD_DEBUGGER_NOT_PRESENT ? TRUE : FALSE;
            UCHAR shared_state = 0;

            PKUSER_SHARED_DATA shared_data = reinterpret_cast<PKUSER_SHARED_DATA>(0xFFFFF78000000000ULL);
            if (shared_data && _MmIsAddressValid(shared_data)) {
                shared_state = shared_data->KdDebuggerEnabled;
            }

            const BOOLEAN macro_active = (kd_enabled && !kd_not_present) ? TRUE : FALSE;
            const BOOLEAN shared_active = kd_shared_active(shared_state);
            const BOOLEAN active = (macro_active || shared_active) ? TRUE : FALSE;
            const LONG packed_state =
                (kd_enabled ? 0x1L : 0L) |
                (kd_not_present ? 0x2L : 0L) |
                (kd_shared_enabled(shared_state) ? 0x4L : 0L) |
                (kd_shared_not_present(shared_state) ? 0x8L : 0L) |
                (macro_active ? 0x10L : 0L) |
                (shared_active ? 0x20L : 0L) |
                (active ? 0x40L : 0L);
            const LONG previous_state = _InterlockedExchange(&g_kd_state_log, packed_state);
            if (active || previous_state != packed_state) {
                WW_LOG("[ADBG] kernel_debugger_state kd_enabled=%u kd_not_present=%u shared_state=0x%02x shared_enabled=%u shared_not_present=%u macro_active=%u shared_active=%u active=%u previous=0x%lx current=0x%lx",
                    kd_enabled ? 1u : 0u,
                    kd_not_present ? 1u : 0u,
                    static_cast<unsigned>(shared_state),
                    kd_shared_enabled(shared_state) ? 1u : 0u,
                    kd_shared_not_present(shared_state) ? 1u : 0u,
                    macro_active ? 1u : 0u,
                    shared_active ? 1u : 0u,
                    active ? 1u : 0u,
                    previous_state,
                    packed_state);
            }

            return active;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("[ADBG] kernel_debugger_state_exception active=1");
            return TRUE;
        }
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
        LONG hash_count = g_re_tool_hash_count;

        while (cursor + sizeof(ADBG_SYSTEM_PROCESS_INFORMATION) <= end && scanned < 131072) {
            auto info = reinterpret_cast<PADBG_SYSTEM_PROCESS_INFORMATION>(cursor);
            ++scanned;

            if (info->UniqueProcessId != nullptr) {
                HANDLE current_pid = info->UniqueProcessId;
                if (reinterpret_cast<UINT64>(current_pid) <= 4) {
                    if (info->NextEntryOffset == 0) break;
                    cursor += info->NextEntryOffset;
                    continue;
                }

                if (hash_count > 0) {
                    bool hash_matched = is_pid_re_tool_by_hash(current_pid);
                    if (hash_matched) {
                        process_guard_fwd::register_re_tool_pid(current_pid);
                        *out_debugger_pid = (UINT64)(ULONG_PTR)current_pid;
                        ExFreePoolWithTag(buffer, ADBG_PROCESS_SCAN_TAG);
                        WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X result=hash_hit scanned=%lu lookup_misses=%lu pid=%llu",
                            STATUS_SUCCESS, scanned, lookup_misses, *out_debugger_pid);
                        return STATUS_SUCCESS;
                    }
                }

                PEPROCESS process = nullptr;
                NTSTATUS lookup_status = PsLookupProcessByProcessId(current_pid, &process);
                if (NT_SUCCESS(lookup_status) && process) {
                    UCHAR* image_name = PsGetProcessImageFileName(process);
                    if (image_name && image_file_name_is_supported_ida_host(image_name)) {
                        WW_LOG("[ADBG] supported_ida_host_ignored pid=%llu image=%.15s",
                            (UINT64)(ULONG_PTR)current_pid, image_name);
                        ObDereferenceObject(process);
                        if (info->NextEntryOffset == 0) break;
                        cursor += info->NextEntryOffset;
                        continue;
                    }
                    ObDereferenceObject(process);
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

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (client_pid) {
            NTSTATUS dbg_status = check_debug_object_handles_targeting_pid(
                static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(client_pid)));
            if (NT_SUCCESS(dbg_status)) {
                WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X result=debug_object_hit scanned=%lu",
                    STATUS_SUCCESS, scanned);
                *out_debugger_pid = 0;
                return STATUS_SUCCESS;
            }
        }

        WW_LOG("[ADBG] scan_debuggers_exit status=0x%08X result=none scanned=%lu lookup_misses=%lu", STATUS_NOT_FOUND, scanned, lookup_misses);
        return STATUS_NOT_FOUND;
    }

    inline NTSTATUS check_debug_object_handles_targeting_pid(UINT32 target_pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;
        if (!target_pid)
            return STATUS_INVALID_PARAMETER;

        struct HANDLE_ENTRY_D {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ACCESS_MASK GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };
        struct HANDLE_INFO_EX_D {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            HANDLE_ENTRY_D Handles[1];
        };

        constexpr ULONG POOL_TAG_DOBJ = 'DOBJ';
        constexpr SYSTEM_INFORMATION_CLASS_INTERNAL HandleInfoClass =
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(64);

        ULONG buffer_size = 0x100000;
        ULONG return_length = 0;
        PVOID hbuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_DOBJ);
        if (!hbuf) return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS hstatus = ZwQuerySystemInformation(
            HandleInfoClass, hbuf, buffer_size, &return_length);

        for (int attempt = 0; attempt < 3; ++attempt) {
            if (hstatus != STATUS_INFO_LENGTH_MISMATCH &&
                hstatus != STATUS_BUFFER_TOO_SMALL &&
                hstatus != STATUS_BUFFER_OVERFLOW)
                break;
            ExFreePoolWithTag(hbuf, POOL_TAG_DOBJ);
            buffer_size = return_length > buffer_size
                ? return_length + 0x10000
                : buffer_size * 2;
            hbuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_DOBJ);
            if (!hbuf) return STATUS_INSUFFICIENT_RESOURCES;
            return_length = 0;
            hstatus = ZwQuerySystemInformation(
                HandleInfoClass, hbuf, buffer_size, &return_length);
        }

        if (!NT_SUCCESS(hstatus)) {
            ExFreePoolWithTag(hbuf, POOL_TAG_DOBJ);
            return hstatus;
        }

        auto* info = reinterpret_cast<HANDLE_INFO_EX_D*>(hbuf);
        UINT32 debug_handle_count = 0;

        for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
            const auto& h = info->Handles[i];
            if (!h.Object) continue;

            POBJECT_TYPE obj_type = nullptr;
            __try {
                if (_ObGetObjectType)
                    obj_type = _ObGetObjectType(h.Object);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            if (!obj_type) continue;

            const WCHAR* type_name = nullptr;
            __try {
                type_name = reinterpret_cast<const WCHAR*>(obj_type->Name.Buffer);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            bool is_debug_object = false;
            if (type_name && obj_type->Name.Length >= sizeof(WCHAR) * 11) {
                const WCHAR debug_str[] = L"DebugObject";
                bool match = true;
                for (int c = 0; c < 11; ++c) {
                    if (type_name[c] != debug_str[c]) { match = false; break; }
                }
                is_debug_object = match;
            }

            if (!is_debug_object) continue;

            UINT32 holder_pid = static_cast<UINT32>(h.UniqueProcessId);
            if (holder_pid == target_pid) continue;

            debug_handle_count++;

            WW_LOG("[ADBG] debug_object_handle holder_pid=%u handle=0x%llx target_pid=%u",
                holder_pid,
                static_cast<UINT64>(h.HandleValue),
                target_pid);
        }

        ExFreePoolWithTag(hbuf, POOL_TAG_DOBJ);

        if (debug_handle_count > 0) {
            WW_LOG("[ADBG] debug_object_detected target_pid=%u handles=%u",
                target_pid, debug_handle_count);
#ifndef AIDA_DEV_MODE
            KeBugCheckEx(0xA1DA0005,
                static_cast<ULONG_PTR>(target_pid),
                static_cast<ULONG_PTR>(debug_handle_count),
                0, 0);
#endif
            return STATUS_SUCCESS;
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
            SIZE_T debug_port_offset = whoswho_kernel_layout::eprocess_debug_port_offset();
            if (debug_port_offset == 0) {
                WW_LOG("anti_debug: debug port inspect fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                    pid,
                    whoswho_kernel_layout::build_number());
                ObDereferenceObject(process);
                return STATUS_NOT_SUPPORTED;
            }
            volatile PVOID* debug_port = (volatile PVOID*)(eprocess + debug_port_offset);
            if (_MmIsAddressValid((PVOID)debug_port) && *debug_port != nullptr) {
                UINT64 port_value = reinterpret_cast<UINT64>(*debug_port);
                UINT32 port_tag = static_cast<UINT32>((port_value >> 32) ^ port_value ^ 0x0A1DAD57u);
                WW_LOG("anti_debug: debug port present for pid=%u offset=0x%llx tag=0x%08X",
                    pid,
                    static_cast<unsigned long long>(debug_port_offset),
                    port_tag);
#ifndef AIDA_DEV_MODE
                KeBugCheckEx(0xA1DA0005, (ULONG_PTR)pid, (ULONG_PTR)port_value, 0, 0);
#endif
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

            SIZE_T instr_offset = whoswho_kernel_layout::eprocess_instrumentation_callback_offset();
            if (instr_offset == 0) {
                WW_LOG("[INSTR-DUMP] fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                    pid,
                    whoswho_kernel_layout::build_number());
                ObDereferenceObject(process);
                return STATUS_NOT_SUPPORTED;
            }

            volatile PVOID* instr_cb = (volatile PVOID*)(eprocess + instr_offset);
            PVOID cur = *instr_cb;
            BOOLEAN is_canonical = (cur == nullptr) ||
                ((UINT64)cur < 0x00007FFFFFFFFFFull) ||
                ((UINT64)cur >= 0xFFFF800000000000ull);

            UINT64 cur_value = reinterpret_cast<UINT64>(cur);
            UINT32 cur_tag = static_cast<UINT32>((cur_value >> 32) ^ cur_value ^ 0x0A1DA460u);
            UINT64 own_value = reinterpret_cast<UINT64>(g_instrumentation_callback);
            UINT32 own_tag = static_cast<UINT32>((own_value >> 32) ^ own_value ^ 0x0A1DA461u);

            WW_LOG("[INSTR-DUMP] offset=0x%llx present=%d is_canonical=%d matches_own=%d cur_tag=0x%08X own_tag=0x%08X",
                static_cast<unsigned long long>(instr_offset),
                cur != nullptr ? 1 : 0,
                is_canonical ? 1 : 0,
                (cur == g_instrumentation_callback) ? 1 : 0,
                cur_tag,
                own_tag);

            if (cur != nullptr && !is_canonical) {
                WW_LOG("[INSTR-DUMP] noncanonical cb ignored for pid=%u build=%lu cur_tag=0x%08X",
                    pid, osver.dwBuildNumber, cur_tag);
            } else if (cur != nullptr && cur != g_instrumentation_callback) {
                WW_LOG("[INSTR-DUMP] foreign cb observed inspect_only pid=%u cur_tag=0x%08X own_tag=0x%08X",
                    pid, cur_tag, own_tag);
            } else {
                WW_LOG("[INSTR-DUMP] no foreign cb at offset=0x%llx for pid=%u present=%d",
                    static_cast<unsigned long long>(instr_offset),
                    pid,
                    cur != nullptr ? 1 : 0);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            WW_LOG("[INSTR-DUMP] EXCEPTION during dump for pid=%u", pid);
            status = STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(process);
        return status;
    }

    inline NTSTATUS enumerate_foreign_thread_handles(UINT32 target_pid)
    {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;
        if (!_PsLookupThreadByThreadId || !_PsGetThreadId || !_ObGetObjectType ||
            !_PsGetContextThread || !_PsSetContextThread)
            return STATUS_NOT_SUPPORTED;
        if (!PsThreadType || !*PsThreadType)
            return STATUS_NOT_SUPPORTED;

        if (target_pid == 0)
            return STATUS_INVALID_PARAMETER;

        struct HANDLE_ENTRY_T {
            PVOID Object;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR HandleValue;
            ACCESS_MASK GrantedAccess;
            USHORT CreatorBackTraceIndex;
            USHORT ObjectTypeIndex;
            ULONG HandleAttributes;
            ULONG Reserved;
        };
        struct HANDLE_INFO_EX_T {
            ULONG_PTR NumberOfHandles;
            ULONG_PTR Reserved;
            HANDLE_ENTRY_T Handles[1];
        };

        constexpr ULONG POOL_TAG_FTHE = 'FTHE';
        constexpr SYSTEM_INFORMATION_CLASS_INTERNAL HandleInfoClass =
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(64);
        constexpr ACCESS_MASK HOSTILE_THREAD_CTX =
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;

        ULONG buffer_size = 0x100000;
        ULONG return_length = 0;
        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_FTHE);
        if (!buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        NTSTATUS status = ZwQuerySystemInformation(
            HandleInfoClass, buffer, buffer_size, &return_length);

        for (int attempt = 0; attempt < 3; ++attempt) {
            if (status != STATUS_INFO_LENGTH_MISMATCH &&
                status != STATUS_BUFFER_TOO_SMALL &&
                status != STATUS_BUFFER_OVERFLOW)
                break;
            ExFreePoolWithTag(buffer, POOL_TAG_FTHE);
            buffer_size = return_length > buffer_size
                ? return_length + 0x10000
                : buffer_size * 2;
            buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, POOL_TAG_FTHE);
            if (!buffer)
                return STATUS_INSUFFICIENT_RESOURCES;
            return_length = 0;
            status = ZwQuerySystemInformation(
                HandleInfoClass, buffer, buffer_size, &return_length);
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, POOL_TAG_FTHE);
            WW_LOG("[CONT-ADBG] foreign_thread_enum_query_failed status=0x%08X", status);
            return status;
        }

        auto* info = reinterpret_cast<HANDLE_INFO_EX_T*>(buffer);
        POBJECT_TYPE thread_type = *PsThreadType;
        UINT32 foreign_count = 0;
        UINT32 dr_cleared = 0;
        UINT32 hidden = 0;

        for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
            const auto& h = info->Handles[i];

            if (static_cast<UINT32>(h.UniqueProcessId) == target_pid)
                continue;
            if (!h.Object)
                continue;
            if ((h.GrantedAccess & HOSTILE_THREAD_CTX) == 0)
                continue;

            __try {
                if (_ObGetObjectType(h.Object) != thread_type)
                    continue;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            PETHREAD thread = static_cast<PETHREAD>(h.Object);
            PEPROCESS thread_owner = nullptr;
            __try {
                thread_owner = IoThreadToProcess(thread);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            if (!thread_owner)
                continue;

            HANDLE owner_pid = PsGetProcessId(thread_owner);
            if (static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(owner_pid)) != target_pid)
                continue;

            ++foreign_count;

            HANDLE tid = nullptr;
            __try {
                tid = _PsGetThreadId(thread);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                tid = nullptr;
            }

            WW_LOG("[CONT-ADBG] foreign_thread_handle foreign_pid=%llu tid=%llu access=0x%08X target_pid=%u",
                (UINT64)h.UniqueProcessId,
                (UINT64)(ULONG_PTR)tid,
                (ULONG)h.GrantedAccess,
                target_pid);

            __try {
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                NTSTATUS ctx_st = _PsGetContextThread(thread, &ctx, KernelMode);
                if (NT_SUCCESS(ctx_st)) {
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
                        ctx_st = _PsSetContextThread(thread, &ctx, KernelMode);
                        if (NT_SUCCESS(ctx_st)) {
                            ++dr_cleared;
                            WW_LOG("[CONT-ADBG] foreign_thread_dr_cleared tid=%llu target_pid=%u foreign_pid=%llu",
                                (UINT64)(ULONG_PTR)tid, target_pid,
                                (UINT64)h.UniqueProcessId);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                WW_LOG("[CONT-ADBG] foreign_thread_dr_clear_exception tid=%llu",
                    (UINT64)(ULONG_PTR)tid);
            }

            __try {
                NTSTATUS hide_st = hide_thread_object_from_debugger(thread);
                if (NT_SUCCESS(hide_st))
                    ++hidden;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }

        ExFreePoolWithTag(buffer, POOL_TAG_FTHE);

        if (foreign_count > 0) {
            WW_LOG("[CONT-ADBG] foreign_thread_enum_complete target_pid=%u foreign_handles=%u dr_cleared=%u threads_hidden=%u",
                target_pid, foreign_count, dr_cleared, hidden);
        }

        return STATUS_SUCCESS;
    }

    inline NTSTATUS scan_text_for_int3(PEPROCESS process, UINT64 module_base,
        UINT64 exception_dir_va, DWORD exception_dir_size, UINT64* hit_rva)
    {
        if (!process || module_base == 0 || exception_dir_va == 0 ||
            exception_dir_size == 0 || !hit_rva)
            return STATUS_INVALID_PARAMETER;

        *hit_rva = 0;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;

        if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_MmIsAddressValid)
            return STATUS_NOT_SUPPORTED;

        struct _RF {
            DWORD BeginAddress;
            DWORD EndAddress;
            DWORD UnwindData;
        };

        const DWORD runtime_function_size = sizeof(_RF);
        const DWORD func_count = exception_dir_size / runtime_function_size;
        if (func_count == 0)
            return STATUS_INVALID_PARAMETER;

        KAPC_STATE apc;
        _KeStackAttachProcess(process, &apc);

        NTSTATUS status = STATUS_SUCCESS;

        __try {
            const UINT8* mod_base_ptr = reinterpret_cast<const UINT8*>(module_base);
            const _RF* rf_base = reinterpret_cast<const _RF*>(
                mod_base_ptr + exception_dir_va);

            if (!_MmIsAddressValid((PVOID)rf_base)) {
                status = STATUS_ACCESS_VIOLATION;
            } else {
                for (DWORD i = 0; i < func_count; ++i) {
                    const _RF* rf = rf_base + i;

                    if (!_MmIsAddressValid((PVOID)rf))
                        continue;

                    DWORD begin_addr = rf->BeginAddress;
                    if (begin_addr == 0)
                        continue;

                    const UINT8* entry_ptr = mod_base_ptr + begin_addr;

                    if (!_MmIsAddressValid((PVOID)entry_ptr))
                        continue;

                    const UINT8 first_byte = *entry_ptr;

                    if (first_byte == 0xCC) {
                        *hit_rva = static_cast<UINT64>(begin_addr);
                        WW_LOG("[ADBG] int3_detected rva=0x%X module_base=0x%llX func_index=%lu",
                            begin_addr,
                            static_cast<unsigned long long>(module_base),
                            i);
#ifndef AIDA_DEV_MODE
                        KeBugCheckEx(0xA1DA0002, (ULONG_PTR)begin_addr, 0xCC, 0, 0);
#endif
                        status = STATUS_DEBUGGER_INACTIVE;
                        break;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNSUCCESSFUL;
        }

        _KeUnstackDetachProcess(&apc);

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

    constexpr LONG TIMER_PERIOD_MS = 2000;

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
            WW_LOG("[CONT-ADBG] cycle=%llu calling inspect_instrumentation_callback_eprocess pid=%u", cycle, pid);
            anti_debug::clear_instrumentation_callback_eprocess(pid);

            if (_PsGetProcessSectionBaseAddress && _KeStackAttachProcess &&
                _KeUnstackDetachProcess && _MmIsAddressValid) {
                PEPROCESS scan_proc = nullptr;
                NTSTATUS lookup_st = PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)pid, &scan_proc);
                if (NT_SUCCESS(lookup_st) && scan_proc) {
                    PVOID section_base = _PsGetProcessSectionBaseAddress(scan_proc);
                    if (section_base) {
                        UINT64 mod_base = reinterpret_cast<UINT64>(section_base);
                        UINT64 exc_dir_va = 0;
                        DWORD exc_dir_size = 0;

                        KAPC_STATE pe_apc;
                        _KeStackAttachProcess(scan_proc, &pe_apc);
                        __try {
                            const UINT8* base_ptr = reinterpret_cast<const UINT8*>(mod_base);
                            if (_MmIsAddressValid((PVOID)base_ptr)) {
                                const IMAGE_DOS_HEADER* dos =
                                    reinterpret_cast<const IMAGE_DOS_HEADER*>(base_ptr);
                                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                                    LONG e_lfanew = dos->e_lfanew;
                                    if (e_lfanew > 0 && e_lfanew < 0x100000) {
                                        const IMAGE_NT_HEADERS64* nt =
                                            reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                                                base_ptr + e_lfanew);
                                        if (_MmIsAddressValid((PVOID)nt) &&
                                            nt->Signature == IMAGE_NT_SIGNATURE &&
                                            nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                                            if (nt->OptionalHeader.NumberOfRvaAndSizes >
                                                IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
                                                exc_dir_va = nt->OptionalHeader.DataDirectory[
                                                    IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
                                                exc_dir_size = nt->OptionalHeader.DataDirectory[
                                                    IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
                                            }
                                        }
                                    }
                                }
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            exc_dir_va = 0;
                            exc_dir_size = 0;
                        }
                        _KeUnstackDetachProcess(&pe_apc);

                        if (exc_dir_va != 0 && exc_dir_size != 0) {
                            UINT64 hit_rva = 0;
                            NTSTATUS scan_st = anti_debug::scan_text_for_int3(
                                scan_proc, mod_base, exc_dir_va, exc_dir_size, &hit_rva);
                            WW_LOG("[CONT-ADBG] int3_scan cycle=%llu pid=%u status=0x%08X hit_rva=0x%llX",
                                cycle, pid, (ULONG)scan_st,
                                static_cast<unsigned long long>(hit_rva));
                        }
                    }
                    ObDereferenceObject(scan_proc);
                }
            }
        }

        if ((cycle % 5) == 0) {


            BOOLEAN target_being_debugged = FALSE;
            {
                PEPROCESS target_proc = nullptr;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &target_proc)) && target_proc) {
                    __try {


                        SIZE_T debug_port_offset = whoswho_kernel_layout::eprocess_debug_port_offset();
                        if (debug_port_offset == 0) {
                            WW_LOG("[CONT-ADBG] debug_port fail_closed pid=%u build=%lu reason=unsupported_eprocess_layout",
                                pid,
                                whoswho_kernel_layout::build_number());
                        } else {
                            ULONG_PTR* debug_port_ptr = (ULONG_PTR*)((UINT8*)target_proc + debug_port_offset);
                            if (_MmIsAddressValid(debug_port_ptr) && *debug_port_ptr != 0) {
                                target_being_debugged = TRUE;
#ifndef AIDA_DEV_MODE
                                KeBugCheckEx(0xA1DA0005, (ULONG_PTR)pid, (ULONG_PTR)*debug_port_ptr, 0, 0);
#endif
                            }
                        }
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
            anti_debug::enumerate_foreign_thread_handles(pid);
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
        LONG queued = _InterlockedCompareExchange(&g_work_item_queued, 0, 0);
        LONG active_before = _InterlockedCompareExchange(&g_active, 0, 0);
        LONG prev = _InterlockedCompareExchange(
            reinterpret_cast<volatile LONG*>(&g_target_pid),
            0,
            static_cast<LONG>(pid));
        if (prev == static_cast<LONG>(pid)) {
            LONG stopped = _InterlockedExchange(&g_active, 0);
            KeCancelTimer(&g_timer);
            if (_KeFlushQueuedDpcs && KeGetCurrentIrql() < DISPATCH_LEVEL)
                _KeFlushQueuedDpcs();
            WW_LOG("continuous_adbg: stopped target pid=%u process_exiting active_before=%ld stopped=%ld queued_before=%ld queued_after=%ld irql=%lu",
                pid,
                active_before,
                stopped,
                queued,
                _InterlockedCompareExchange(&g_work_item_queued, 0, 0),
                static_cast<ULONG>(KeGetCurrentIrql()));
        }
    }
}

namespace process_hide {

    typedef NTSTATUS (NTAPI* fn_NtQuerySystemInfo)(
        SYSTEM_INFORMATION_CLASS_INTERNAL, PVOID, ULONG, PULONG);

    inline volatile LONG g_installed = 0;
    inline fn_NtQuerySystemInfo g_original = nullptr;
    inline LONG g_saved_entry = 0;
    inline ULONG g_ssn = 0xFFFFFFFFu;

    __forceinline void disable_write_protect()
    {
        ULONG_PTR cr0 = __readcr0();
        cr0 &= ~(1ULL << 16);
        __writecr0(cr0);
    }

    __forceinline void enable_write_protect()
    {
        ULONG_PTR cr0 = __readcr0();
        cr0 |= (1ULL << 16);
        __writecr0(cr0);
    }

    NTSTATUS NTAPI hooked_query_system_info(
        SYSTEM_INFORMATION_CLASS_INTERNAL SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength)
    {
        if (!g_original)
            return STATUS_PROCEDURE_NOT_FOUND;

        NTSTATUS status = STATUS_SUCCESS;
        __try {
            status = g_original(SystemInformationClass, SystemInformation,
                                SystemInformationLength, ReturnLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return (NTSTATUS)GetExceptionCode();
        }

        if (!NT_SUCCESS(status) || !SystemInformation)
            return status;

        KPROCESSOR_MODE prev_mode = ExGetPreviousMode();
        if (prev_mode != UserMode)
            return status;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return status;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return status;

        if (SystemInformationClass == static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(5)) {
            PUCHAR cursor = static_cast<PUCHAR>(SystemInformation);
            PUCHAR buffer_end = cursor + SystemInformationLength;
            PUCHAR prev_entry = nullptr;
            ULONG prev_offset_accum = 0;

            __try {
                while (cursor + sizeof(anti_debug::ADBG_SYSTEM_PROCESS_INFORMATION) <= buffer_end) {
                    auto info = reinterpret_cast<anti_debug::PADBG_SYSTEM_PROCESS_INFORMATION>(cursor);

                    if (info->UniqueProcessId == client_pid) {
                        if (prev_entry) {
                            if (info->NextEntryOffset == 0) {
                                reinterpret_cast<anti_debug::PADBG_SYSTEM_PROCESS_INFORMATION>(prev_entry)->NextEntryOffset = 0;
                            } else {
                                ULONG new_offset = prev_offset_accum + info->NextEntryOffset;
                                reinterpret_cast<anti_debug::PADBG_SYSTEM_PROCESS_INFORMATION>(prev_entry)->NextEntryOffset = new_offset;
                            }
                        } else {
                            if (info->NextEntryOffset != 0 &&
                                cursor + info->NextEntryOffset + sizeof(anti_debug::ADBG_SYSTEM_PROCESS_INFORMATION) <= buffer_end) {
                                ULONG remaining = static_cast<ULONG>(buffer_end - (cursor + info->NextEntryOffset));
                                RtlCopyMemory(cursor, cursor + info->NextEntryOffset, remaining);
                                if (ReturnLength && *ReturnLength >= info->NextEntryOffset)
                                    *ReturnLength -= info->NextEntryOffset;
                            } else {
                                info->UniqueProcessId = nullptr;
                                info->ImageName.Length = 0;
                                info->ImageName.MaximumLength = 0;
                                info->ImageName.Buffer = nullptr;
                                info->NextEntryOffset = 0;
                            }
                        }
                        WW_LOG("[PHIDE] filtered pid=%llu from SystemProcessInformation caller_pid=%llu",
                            reinterpret_cast<UINT64>(client_pid),
                            reinterpret_cast<UINT64>(caller_pid));
                        break;
                    }

                    if (info->NextEntryOffset == 0)
                        break;
                    prev_entry = cursor;
                    prev_offset_accum = info->NextEntryOffset;
                    cursor += info->NextEntryOffset;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return status;
            }
        }
        else if (SystemInformationClass == static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(37)) {
            __try {
                HANDLE queried_pid = *reinterpret_cast<HANDLE*>(SystemInformation);
                if (queried_pid == client_pid) {
                    WW_LOG("[PHIDE] filtered pid=%llu from SystemProcessIdInformation caller_pid=%llu",
                        reinterpret_cast<UINT64>(client_pid),
                        reinterpret_cast<UINT64>(caller_pid));
                    return STATUS_NOT_FOUND;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return status;
            }
        }

        return status;
    }

    inline NTSTATUS install()
    {
        if (_InterlockedCompareExchange(&g_installed, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (!ssdt_resolver::find_ssdt() || !ssdt_resolver::g_ssdt) {
            WW_LOG("[PHIDE] install failed: ssdt not found");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        ssdt_resolver::ntdll_lookup_result_t ntdll{};
        if (!ssdt_resolver::locate_current_ntdll(&ntdll)) {
            WW_LOG("[PHIDE] install failed: ntdll not found reason=%s", ntdll.reason);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        CHAR query_name[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
        PVOID stub = GetProcAddress(ntdll.ntdll_base, query_name);
        if (!stub) {
            WW_LOG("[PHIDE] install failed: NtQuerySystemInformation export not found");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        PUCHAR bytes = static_cast<PUCHAR>(stub);
        if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 || bytes[3] != 0xB8) {
            WW_LOG("[PHIDE] install failed: unexpected ntdll stub bytes");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        g_ssn = *reinterpret_cast<PULONG>(&bytes[4]);
        if (g_ssn >= static_cast<ULONG>(ssdt_resolver::g_ssdt->ServiceLimit)) {
            WW_LOG("[PHIDE] install failed: ssn=%lu out of range limit=%lu",
                g_ssn, static_cast<ULONG>(ssdt_resolver::g_ssdt->ServiceLimit));
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        g_saved_entry = ssdt_resolver::g_ssdt->ServiceTable[g_ssn];
        g_original = reinterpret_cast<fn_NtQuerySystemInfo>(
            ssdt_resolver::get_ssdt_entry(g_ssn));

        if (!g_original) {
            WW_LOG("[PHIDE] install failed: original function is null");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        ULONG_PTR hook_addr = reinterpret_cast<ULONG_PTR>(&hooked_query_system_info);
        ULONG_PTR table_base = reinterpret_cast<ULONG_PTR>(ssdt_resolver::g_ssdt->ServiceTable);
        LONG64 offset = static_cast<LONG64>(hook_addr - table_base);

        if (offset > 0x07FFFFFFLL || offset < -0x08000000LL) {
            WW_LOG("[PHIDE] install failed: hook offset out of range offset=%lld table=%p hook=%p",
                offset, reinterpret_cast<PVOID>(table_base), reinterpret_cast<PVOID>(hook_addr));
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_SUPPORTED;
        }

        LONG new_entry = static_cast<LONG>((offset << 4) | (g_saved_entry & 0xF));

        disable_write_protect();
        ssdt_resolver::g_ssdt->ServiceTable[g_ssn] = new_entry;
        enable_write_protect();

        WW_LOG("[PHIDE] installed ssn=%lu table=%p original=%p hook=%p offset=%lld saved=0x%08lX new=0x%08lX",
            g_ssn,
            reinterpret_cast<PVOID>(table_base),
            reinterpret_cast<PVOID>(g_original),
            reinterpret_cast<PVOID>(hook_addr),
            offset,
            static_cast<ULONG>(g_saved_entry),
            static_cast<ULONG>(new_entry));

        return STATUS_SUCCESS;
    }

    inline void uninstall()
    {
        if (_InterlockedCompareExchange(&g_installed, 0, 1) != 1)
            return;

        if (g_ssn == 0xFFFFFFFFu || !ssdt_resolver::g_ssdt)
            return;

        disable_write_protect();
        ssdt_resolver::g_ssdt->ServiceTable[g_ssn] = g_saved_entry;
        enable_write_protect();

        WW_LOG("[PHIDE] uninstalled ssn=%lu restored=0x%08lX", g_ssn, static_cast<ULONG>(g_saved_entry));
    }
}

namespace context_guard {

    typedef ssdt_resolver::fn_NtGetContextThread fn_NtGetContextThread_t;
    typedef ssdt_resolver::fn_NtSetContextThread fn_NtSetContextThread_t;

    inline volatile LONG g_installed = 0;
    inline fn_NtGetContextThread_t g_orig_NtGetContextThread = nullptr;
    inline fn_NtSetContextThread_t g_orig_NtSetContextThread = nullptr;
    inline ULONG g_get_ssn = 0xFFFFFFFFu;
    inline ULONG g_set_ssn = 0xFFFFFFFFu;
    inline LONG g_get_saved_entry = 0;
    inline LONG g_set_saved_entry = 0;

    __forceinline void disable_write_protect()
    {
        ULONG_PTR cr0 = __readcr0();
        cr0 &= ~(1ULL << 16);
        __writecr0(cr0);
    }

    __forceinline void enable_write_protect()
    {
        ULONG_PTR cr0 = __readcr0();
        cr0 |= (1ULL << 16);
        __writecr0(cr0);
    }

    NTSTATUS NTAPI hooked_NtGetContextThread(HANDLE thread_handle, PCONTEXT ctx)
    {
        if (g_orig_NtGetContextThread &&
            ExGetPreviousMode() == UserMode &&
            caller_validation::g_registered_client_pid != nullptr) {

            HANDLE caller_pid = PsGetCurrentProcessId();
            if (caller_pid != caller_validation::g_registered_client_pid) {
                PETHREAD thread = nullptr;
                NTSTATUS lookup = PsLookupThreadByThreadId(thread_handle, &thread);
                if (NT_SUCCESS(lookup) && thread) {
                    PEPROCESS owner_proc = IoThreadToProcess(thread);
                    HANDLE owner_pid = PsGetProcessId(owner_proc);
                    ObDereferenceObject(thread);
                    if (owner_pid == caller_validation::g_registered_client_pid) {
                        WW_LOG("[CTXGUARD] blocked NtGetContextThread caller_pid=%llu target_pid=%llu",
                            (UINT64)(ULONG_PTR)caller_pid,
                            (UINT64)(ULONG_PTR)owner_pid);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }

        if (!g_orig_NtGetContextThread)
            return STATUS_PROCEDURE_NOT_FOUND;

        return g_orig_NtGetContextThread(thread_handle, ctx);
    }

    NTSTATUS NTAPI hooked_NtSetContextThread(HANDLE thread_handle, PCONTEXT ctx)
    {
        if (g_orig_NtSetContextThread &&
            ExGetPreviousMode() == UserMode &&
            caller_validation::g_registered_client_pid != nullptr) {

            HANDLE caller_pid = PsGetCurrentProcessId();
            if (caller_pid != caller_validation::g_registered_client_pid) {
                PETHREAD thread = nullptr;
                NTSTATUS lookup = PsLookupThreadByThreadId(thread_handle, &thread);
                if (NT_SUCCESS(lookup) && thread) {
                    PEPROCESS owner_proc = IoThreadToProcess(thread);
                    HANDLE owner_pid = PsGetProcessId(owner_proc);
                    ObDereferenceObject(thread);
                    if (owner_pid == caller_validation::g_registered_client_pid) {
                        WW_LOG("[CTXGUARD] blocked NtSetContextThread caller_pid=%llu target_pid=%llu",
                            (UINT64)(ULONG_PTR)caller_pid,
                            (UINT64)(ULONG_PTR)owner_pid);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }

        if (!g_orig_NtSetContextThread)
            return STATUS_PROCEDURE_NOT_FOUND;

        return g_orig_NtSetContextThread(thread_handle, ctx);
    }

    __forceinline NTSTATUS install()
    {
        if (_InterlockedCompareExchange(&g_installed, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (!ssdt_resolver::find_ssdt() || !ssdt_resolver::g_ssdt) {
            WW_LOG("[CTXGUARD] install failed: ssdt not found");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        ssdt_resolver::ntdll_lookup_result_t ntdll{};
        if (!ssdt_resolver::locate_current_ntdll(&ntdll)) {
            WW_LOG("[CTXGUARD] install failed: ntdll not found reason=%s", ntdll.reason);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        CHAR get_name[] = { 'N','t','G','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
        CHAR set_name[] = { 'N','t','S','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
        PUCHAR get_stub = static_cast<PUCHAR>(GetProcAddress(ntdll.ntdll_base, get_name));
        PUCHAR set_stub = static_cast<PUCHAR>(GetProcAddress(ntdll.ntdll_base, set_name));

        if (!get_stub || !set_stub) {
            WW_LOG("[CTXGUARD] install failed: ntdll export missing get=%p set=%p", get_stub, set_stub);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        if (get_stub[0] != 0x4C || get_stub[1] != 0x8B || get_stub[2] != 0xD1 || get_stub[3] != 0xB8 ||
            set_stub[0] != 0x4C || set_stub[1] != 0x8B || set_stub[2] != 0xD1 || set_stub[3] != 0xB8) {
            WW_LOG("[CTXGUARD] install failed: unexpected stub bytes");
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        g_get_ssn = *reinterpret_cast<PULONG>(&get_stub[4]);
        g_set_ssn = *reinterpret_cast<PULONG>(&set_stub[4]);

        if (g_get_ssn >= static_cast<ULONG>(ssdt_resolver::g_ssdt->ServiceLimit) ||
            g_set_ssn >= static_cast<ULONG>(ssdt_resolver::g_ssdt->ServiceLimit)) {
            WW_LOG("[CTXGUARD] install failed: ssn out of range get=%lu set=%lu limit=%lu",
                g_get_ssn, g_set_ssn, static_cast<ULONG>(ssdt_resolver::g_ssdt->ServiceLimit));
            _InterlockedExchange(&g_installed, 0);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        g_get_saved_entry = ssdt_resolver::g_ssdt->ServiceTable[g_get_ssn];
        g_set_saved_entry = ssdt_resolver::g_ssdt->ServiceTable[g_set_ssn];

        g_orig_NtGetContextThread = reinterpret_cast<fn_NtGetContextThread_t>(
            ssdt_resolver::get_ssdt_entry(g_get_ssn));
        g_orig_NtSetContextThread = reinterpret_cast<fn_NtSetContextThread_t>(
            ssdt_resolver::get_ssdt_entry(g_set_ssn));

        if (!g_orig_NtGetContextThread || !g_orig_NtSetContextThread) {
            WW_LOG("[CTXGUARD] install failed: original function null get=%p set=%p",
                g_orig_NtGetContextThread, g_orig_NtSetContextThread);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_FOUND;
        }

        ULONG_PTR table_base = reinterpret_cast<ULONG_PTR>(ssdt_resolver::g_ssdt->ServiceTable);

        ULONG_PTR get_hook_addr = reinterpret_cast<ULONG_PTR>(&hooked_NtGetContextThread);
        LONG64 get_offset = static_cast<LONG64>(get_hook_addr - table_base);
        if (get_offset > 0x07FFFFFFLL || get_offset < -0x08000000LL) {
            WW_LOG("[CTXGUARD] install failed: get hook offset out of range offset=%lld", get_offset);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_SUPPORTED;
        }
        LONG get_new_entry = static_cast<LONG>((get_offset << 4) | (g_get_saved_entry & 0xF));

        ULONG_PTR set_hook_addr = reinterpret_cast<ULONG_PTR>(&hooked_NtSetContextThread);
        LONG64 set_offset = static_cast<LONG64>(set_hook_addr - table_base);
        if (set_offset > 0x07FFFFFFLL || set_offset < -0x08000000LL) {
            WW_LOG("[CTXGUARD] install failed: set hook offset out of range offset=%lld", set_offset);
            _InterlockedExchange(&g_installed, 0);
            return STATUS_NOT_SUPPORTED;
        }
        LONG set_new_entry = static_cast<LONG>((set_offset << 4) | (g_set_saved_entry & 0xF));

        disable_write_protect();
        ssdt_resolver::g_ssdt->ServiceTable[g_get_ssn] = get_new_entry;
        ssdt_resolver::g_ssdt->ServiceTable[g_set_ssn] = set_new_entry;
        enable_write_protect();

        WW_LOG("[CTXGUARD] installed get_ssn=%lu set_ssn=%lu table=%p get_orig=%p get_hook=%p set_orig=%p set_hook=%p get_saved=0x%08lX get_new=0x%08lX set_saved=0x%08lX set_new=0x%08lX",
            g_get_ssn, g_set_ssn,
            reinterpret_cast<PVOID>(table_base),
            reinterpret_cast<PVOID>(g_orig_NtGetContextThread),
            reinterpret_cast<PVOID>(get_hook_addr),
            reinterpret_cast<PVOID>(g_orig_NtSetContextThread),
            reinterpret_cast<PVOID>(set_hook_addr),
            static_cast<ULONG>(g_get_saved_entry),
            static_cast<ULONG>(get_new_entry),
            static_cast<ULONG>(g_set_saved_entry),
            static_cast<ULONG>(set_new_entry));

        return STATUS_SUCCESS;
    }

    __forceinline void uninstall()
    {
        if (_InterlockedCompareExchange(&g_installed, 0, 1) != 1)
            return;

        if (!ssdt_resolver::g_ssdt)
            return;

        disable_write_protect();
        if (g_get_ssn != 0xFFFFFFFFu)
            ssdt_resolver::g_ssdt->ServiceTable[g_get_ssn] = g_get_saved_entry;
        if (g_set_ssn != 0xFFFFFFFFu)
            ssdt_resolver::g_ssdt->ServiceTable[g_set_ssn] = g_set_saved_entry;
        enable_write_protect();

        WW_LOG("[CTXGUARD] uninstalled get_ssn=%lu set_ssn=%lu get_restored=0x%08lX set_restored=0x%08lX",
            g_get_ssn, g_set_ssn,
            static_cast<ULONG>(g_get_saved_entry),
            static_cast<ULONG>(g_set_saved_entry));

        g_orig_NtGetContextThread = nullptr;
        g_orig_NtSetContextThread = nullptr;
        g_get_ssn = 0xFFFFFFFFu;
        g_set_ssn = 0xFFFFFFFFu;
        g_get_saved_entry = 0;
        g_set_saved_entry = 0;
    }
}
