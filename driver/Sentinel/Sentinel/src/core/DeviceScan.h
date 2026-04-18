#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>
#include <core/ProcessNotify.h>


namespace device_scan {

    inline KTIMER g_timer = {};
    inline KDPC   g_dpc = {};
    inline volatile LONG g_running = 0;
    inline volatile LONG g_work_queued = 0;
    inline WORK_QUEUE_ITEM g_work = {};

    constexpr LONG64 SCAN_INTERVAL = -50'000'000LL;
    constexpr LONG   SCAN_PERIOD_MS = 5000;

    struct target_t { const wchar_t* name; };

    static const target_t kTargets[] = {
        { L"\\Device\\DBK64" },
        { L"\\Device\\DBK32" },
        { L"\\Device\\DBKProcList64" },
        { L"\\Device\\CEDriver" },
        { L"\\Device\\PCILeech" },
        { L"\\Device\\HyperDbg" },
        { L"\\Device\\WinIo" },
        { L"\\Device\\PhysMem" },
        { L"\\Device\\physmem" },
        { L"\\Device\\RwDrv" },
        { L"\\Device\\CAPCOM" },
        { L"\\Device\\GIO" },
        { L"\\Device\\DumpIt" },
    };

    __forceinline ULONG64 fnv64_wstr_lower(const wchar_t* s) {
        ULONG64 h = 0xCBF29CE484222325ULL;
        if (!s) return h;
        for (; *s; ++s) {
            WCHAR c = *s;
            if (c >= L'A' && c <= L'Z') c = static_cast<WCHAR>(c + 0x20);
            h ^= static_cast<ULONG64>(c);
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    __forceinline NTSTATUS probe_one(const wchar_t* name) {
        if (!name) return STATUS_INVALID_PARAMETER;

        UNICODE_STRING us;
        RtlInitUnicodeString(&us, name);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};

        NTSTATUS status = ZwOpenFile(
            &hFile,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &iosb,
            0,
            FILE_SYNCHRONOUS_IO_NONALERT);

        if (NT_SUCCESS(status) && hFile) {
            if (_ZwClose) _ZwClose(hFile);
            else ZwClose(hFile);
        }

        return status;
    }

    __forceinline VOID scan_once() {
        for (ULONG i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); ++i) {
            NTSTATUS st = probe_one(kTargets[i].name);
            if (!NT_SUCCESS(st))
                continue;

            ULONG64 name_hash = fnv64_wstr_lower(kTargets[i].name);

            HANDLE prot_pid = reinterpret_cast<HANDLE>(
                _InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(&process_notify::g_protected_pid), 0, 0));

            if (prot_pid) {
                heartbeat::send_command(heartbeat::BRIDGE_CMD_HOSTILE_DEVICE,
                    static_cast<ULONG>(name_hash & 0xFFFFFFFF));
                SN_LOG("device_scan: HOSTILE DEVICE %ws while AiDA running - BUGCHECK", kTargets[i].name);
                if (_KeBugCheckEx) {
                    _KeBugCheckEx(heartbeat::BUGCHECK_HOSTILE_DEVICE_OBJECT,
                        static_cast<ULONG_PTR>(name_hash),
                        0, 0, 0);
                }
            } else {
                SN_LOG("device_scan: HOSTILE DEVICE %ws (AiDA not running) signaling preload", kTargets[i].name);
                heartbeat::send_command(heartbeat::BRIDGE_CMD_TIER_A_PRE_LOADED,
                    static_cast<ULONG>(name_hash & 0xFFFFFFFF));
            }
            break;
        }
    }

    static VOID work_routine(PVOID ctx) {
        UNREFERENCED_PARAMETER(ctx);
        __try {
            scan_once();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("device_scan::work_routine: EXCEPTION");
        }
        _InterlockedExchange(&g_work_queued, 0);
    }

    static VOID dpc_routine(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
        UNREFERENCED_PARAMETER(Dpc);
        UNREFERENCED_PARAMETER(DeferredContext);
        UNREFERENCED_PARAMETER(SystemArgument1);
        UNREFERENCED_PARAMETER(SystemArgument2);

        if (_InterlockedCompareExchange(&g_running, 0, 0) == 0)
            return;

        if (_InterlockedCompareExchange(&g_work_queued, 1, 0) != 0)
            return;

        ExInitializeWorkItem(&g_work, work_routine, nullptr);
        ExQueueWorkItem(&g_work, DelayedWorkQueue);
    }

    __forceinline VOID start() {
        if (_InterlockedCompareExchange(&g_running, 1, 0) != 0)
            return;

        if (!_KeInitializeDpc || !_KeInitializeTimerEx || !_KeSetTimerEx) {
            _InterlockedExchange(&g_running, 0);
            SN_LOG("device_scan::start: missing function pointers");
            return;
        }

        _KeInitializeTimerEx(&g_timer, NotificationTimer);
        _KeInitializeDpc(&g_dpc, dpc_routine, nullptr);

        LARGE_INTEGER due;
        due.QuadPart = SCAN_INTERVAL;
        _KeSetTimerEx(&g_timer, due, SCAN_PERIOD_MS, &g_dpc);
        SN_LOG("device_scan::start: active, period=%lums", SCAN_PERIOD_MS);
    }

    __forceinline VOID stop() {
        if (_InterlockedCompareExchange(&g_running, 0, 1) != 1)
            return;

        if (_KeCancelTimer)
            _KeCancelTimer(&g_timer);

        if (_KeFlushQueuedDpcs)
            _KeFlushQueuedDpcs();

        while (_InterlockedCompareExchange(&g_work_queued, 0, 0) != 0) {
            LARGE_INTEGER wait;
            wait.QuadPart = -1'000'000LL;
            if (_KeDelayExecutionThread)
                _KeDelayExecutionThread(KernelMode, FALSE, &wait);
            else
                break;
        }
    }
}
