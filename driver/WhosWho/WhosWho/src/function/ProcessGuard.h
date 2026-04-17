#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "CoreSecurity.h"
#include "SentinelBridge.h"

namespace process_guard {

    inline PVOID g_ob_handle = nullptr;
    inline PVOID g_bridge_ob_handle = nullptr;
    inline volatile LONG g_initialized = 0;
    inline volatile UINT64 g_bridge_region_start = 0;
    inline volatile UINT64 g_bridge_region_end = 0;
    inline volatile LONG g_create_notify_registered = 0;
    inline volatile LONG g_thread_notify_registered = 0;

    constexpr ACCESS_MASK DEBUG_GRADE_ACCESS =
        PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
        PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION;

    struct debugger_sig_t {
        const char* prefix;
        int len;
    };

    constexpr debugger_sig_t g_debugger_images[] = {
        { "x64dbg",      6 },
        { "x32dbg",      6 },
        { "windbg",      6 },
        { "ollydbg",     7 },
        { "ida64",       5 },
        { "ida32",       5 },
        { "idaq",        4 },
        { "ghidra",      6 },
        { "dnspy",       5 },
        { "reclass",     7 },
        { "cheatengine", 11 },
        { "frida",       5 },
        { "titanhide",   9 },
        { "scyllahide",  10 },
        { "hyperdbg",    8 },
        { "radare2",     7 },
        { "rizin",       5 },
        { "binja",       5 },
        { "binaryninja", 11 },
        { "cutter",      6 },
        { "pestudio",    8 },
    };
    constexpr int g_debugger_image_count =
        sizeof(g_debugger_images) / sizeof(g_debugger_images[0]);

    __forceinline bool debugger_name_match_ci(const UCHAR* name, const char* prefix, int prefix_len) {
        for (int i = 0; i < prefix_len; ++i) {
            char a = (char)(name[i] | 0x20);
            char b = (char)(prefix[i] | 0x20);
            if (a != b) return false;
        }
        return true;
    }

    __forceinline bool is_debugger_image(HANDLE caller_pid) {
        if (!caller_pid) return false;
        PEPROCESS caller_proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(caller_pid, &caller_proc);
        if (!NT_SUCCESS(st) || !caller_proc)
            return false;
        bool match = false;
        __try {
            UCHAR* img = PsGetProcessImageFileName(caller_proc);
            if (img && _MmIsAddressValid(img)) {
                for (int t = 0; t < g_debugger_image_count; ++t) {
                    if (debugger_name_match_ci(img,
                            g_debugger_images[t].prefix,
                            g_debugger_images[t].len)) {
                        match = true;
                        break;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            match = false;
        }
        ObDereferenceObject(caller_proc);
        return match;
    }

    constexpr ACCESS_MASK STRIPPED_PROCESS_ACCESS =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

    constexpr ACCESS_MASK STRIPPED_THREAD_ACCESS =
        THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT |
        THREAD_GET_CONTEXT | THREAD_TERMINATE;

    inline OB_PREOP_CALLBACK_STATUS NTAPI process_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle)
            return OB_PREOP_SUCCESS;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE target_pid = PsGetProcessId(static_cast<PEPROCESS>(Info->Object));
        if (target_pid != client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        ACCESS_MASK requested = 0;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

        if ((requested & DEBUG_GRADE_ACCESS) != 0 && is_debugger_image(caller_pid)) {
            WW_LOG("process_guard: named debugger pid=%llu requested 0x%lx on client - BSOD",
                (UINT64)(ULONG_PTR)caller_pid, requested);
            sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_PRE_BSOD_INTENT;
            sentinel_bridge::g_bridge.sentinel_cmd_param = sentinel_bridge::RE_REASON_FOREIGN_HND;
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    0xDEAD0001u,
                    (ULONG_PTR)sentinel_bridge::RE_REASON_FOREIGN_HND,
                    (ULONG_PTR)caller_pid,
                    (ULONG_PTR)requested,
                    0xAD7DAD7Du);
            }
        }

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIPPED_PROCESS_ACCESS;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIPPED_PROCESS_ACCESS;

        return OB_PREOP_SUCCESS;
    }

    inline OB_PREOP_CALLBACK_STATUS NTAPI thread_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle)
            return OB_PREOP_SUCCESS;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return OB_PREOP_SUCCESS;

        PEPROCESS owner = IoThreadToProcess(static_cast<PETHREAD>(Info->Object));
        if (!owner)
            return OB_PREOP_SUCCESS;

        HANDLE thread_owner_pid = PsGetProcessId(owner);
        if (thread_owner_pid != client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIPPED_THREAD_ACCESS;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIPPED_THREAD_ACCESS;

        return OB_PREOP_SUCCESS;
    }

    __forceinline void set_bridge_region(PVOID base, ULONG size)
    {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_region_start),
            reinterpret_cast<LONG64>(base));
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_bridge_region_end),
            reinterpret_cast<LONG64>(static_cast<UINT8*>(base) + size));
    }

    inline OB_PREOP_CALLBACK_STATUS NTAPI bridge_pre_callback(
        PVOID,
        POB_PRE_OPERATION_INFORMATION Info)
    {
        if (!Info || !Info->Object)
            return OB_PREOP_SUCCESS;

        if (Info->KernelHandle)
            return OB_PREOP_SUCCESS;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return OB_PREOP_SUCCESS;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return OB_PREOP_SUCCESS;

        UINT64 bridge_start = g_bridge_region_start;
        UINT64 bridge_end = g_bridge_region_end;
        if (bridge_start == 0 || bridge_end == 0)
            return OB_PREOP_SUCCESS;

        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            Info->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE);

        return OB_PREOP_SUCCESS;
    }

    inline VOID NTAPI thread_create_notify(
        HANDLE ProcessId,
        HANDLE ThreadId,
        BOOLEAN Create)
    {
        if (!Create)
            return;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return;

        if (ProcessId != client_pid)
            return;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == client_pid)
            return;
        if (reinterpret_cast<UINT64>(caller_pid) == 4)
            return;

        if (is_debugger_image(caller_pid)) {
            WW_LOG("thread_guard: named debugger pid=%llu created thread %llu in client - BSOD",
                (UINT64)(ULONG_PTR)caller_pid,
                (UINT64)(ULONG_PTR)ThreadId);
            sentinel_bridge::g_bridge.sentinel_cmd = sentinel_bridge::BRIDGE_CMD_PRE_BSOD_INTENT;
            sentinel_bridge::g_bridge.sentinel_cmd_param = sentinel_bridge::RE_REASON_INJECTED_DLL;
            if (_KeBugCheckEx) {
                _KeBugCheckEx(
                    0xDEAD0001u,
                    (ULONG_PTR)sentinel_bridge::RE_REASON_INJECTED_DLL,
                    (ULONG_PTR)caller_pid,
                    (ULONG_PTR)ThreadId,
                    0x114D114Du);
            }
        }
    }

    // Process creation notification: deny creation of processes that request
    // debug/injection access to the protected client on startup.
    inline VOID NTAPI create_process_notify(
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        UNREFERENCED_PARAMETER(Process);
        UNREFERENCED_PARAMETER(ProcessId);

        // Only interested in process creation (not termination)
        if (!CreateInfo)
            return;

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return;

        // If the new process's parent is not our client, check if it lists
        // our client's image as the file to open (DLL injection via process)
        HANDLE parent_pid = CreateInfo->ParentProcessId;

        // Allow the client to spawn children normally
        if (parent_pid == client_pid)
            return;

        // System process is always allowed
        if (reinterpret_cast<UINT64>(parent_pid) == 4)
            return;

        // Deny if the creating process has an open handle to our client
        // with dangerous permissions (indicates injection attempt)
        // This is a lightweight check - just log for now
        WW_LOG("create_process_notify: pid=%llu parent=%llu creating process near client",
            reinterpret_cast<UINT64>(ProcessId),
            reinterpret_cast<UINT64>(parent_pid));
    }

    inline NTSTATUS init()
    {
        if (_InterlockedCompareExchange(&g_initialized, 1, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        if (!_ObRegisterCallbacks) {
            WW_LOG("process_guard::init: ObRegisterCallbacks not resolved");
            _InterlockedExchange(&g_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }

        OB_OPERATION_REGISTRATION op_reg[2] = {};

        op_reg[0].ObjectType = PsProcessType;
        op_reg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg[0].PreOperation = process_pre_callback;
        op_reg[0].PostOperation = nullptr;

        op_reg[1].ObjectType = PsThreadType;
        op_reg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        op_reg[1].PreOperation = thread_pre_callback;
        op_reg[1].PostOperation = nullptr;

        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"321124");

        OB_CALLBACK_REGISTRATION cb_reg = {};
        cb_reg.Version = OB_FLT_REGISTRATION_VERSION;
        cb_reg.OperationRegistrationCount = 2;
        cb_reg.Altitude = altitude;
        cb_reg.RegistrationContext = nullptr;
        cb_reg.OperationRegistration = op_reg;

        NTSTATUS status = _ObRegisterCallbacks(&cb_reg, &g_ob_handle);

        if (!NT_SUCCESS(status)) {
            WW_LOG("process_guard::init: ObRegisterCallbacks FAILED status=0x%08lx", status);
            g_ob_handle = nullptr;
            _InterlockedExchange(&g_initialized, 0);
        } else {
            WW_LOG("process_guard::init: ObRegisterCallbacks OK handle=%p", g_ob_handle);
        }

        if (NT_SUCCESS(status) && g_bridge_region_start != 0)
        {
            OB_OPERATION_REGISTRATION bridge_op[1] = {};

            bridge_op[0].ObjectType = PsProcessType;
            bridge_op[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
            bridge_op[0].PreOperation = bridge_pre_callback;
            bridge_op[0].PostOperation = nullptr;

            UNICODE_STRING bridge_altitude;
            RtlInitUnicodeString(&bridge_altitude, L"321125");

            OB_CALLBACK_REGISTRATION bridge_cb = {};
            bridge_cb.Version = OB_FLT_REGISTRATION_VERSION;
            bridge_cb.OperationRegistrationCount = 1;
            bridge_cb.Altitude = bridge_altitude;
            bridge_cb.RegistrationContext = nullptr;
            bridge_cb.OperationRegistration = bridge_op;

            NTSTATUS bridge_st = _ObRegisterCallbacks(&bridge_cb, &g_bridge_ob_handle);
            if (!NT_SUCCESS(bridge_st)) {
                WW_LOG("process_guard::init: bridge ObRegisterCallbacks FAILED 0x%08lx", bridge_st);
                g_bridge_ob_handle = nullptr;
            }
        }

        // Register process creation notification for injection detection
        if (NT_SUCCESS(status) && _PsSetCreateProcessNotifyRoutineEx)
        {
            NTSTATUS notify_st = _PsSetCreateProcessNotifyRoutineEx(
                create_process_notify, FALSE);
            if (NT_SUCCESS(notify_st)) {
                _InterlockedExchange(&g_create_notify_registered, 1);
                WW_LOG("process_guard::init: PsSetCreateProcessNotifyRoutineEx OK");
            } else {
                WW_LOG("process_guard::init: PsSetCreateProcessNotifyRoutineEx FAILED 0x%08lx", notify_st);
            }
        }

        if (NT_SUCCESS(status)) {
            NTSTATUS thr_st = PsSetCreateThreadNotifyRoutine(thread_create_notify);
            if (NT_SUCCESS(thr_st)) {
                _InterlockedExchange(&g_thread_notify_registered, 1);
                WW_LOG("process_guard::init: PsSetCreateThreadNotifyRoutine OK");
            } else {
                WW_LOG("process_guard::init: PsSetCreateThreadNotifyRoutine FAILED 0x%08lx", thr_st);
            }
        }

        return status;
    }

    inline void cleanup()
    {
        if (_InterlockedCompareExchange(&g_thread_notify_registered, 0, 1) == 1) {
            PsRemoveCreateThreadNotifyRoutine(thread_create_notify);
        }
        if (_InterlockedCompareExchange(&g_create_notify_registered, 0, 1) == 1) {
            if (_PsSetCreateProcessNotifyRoutineEx)
                _PsSetCreateProcessNotifyRoutineEx(create_process_notify, TRUE);
        }
        if (g_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_ob_handle);
            g_ob_handle = nullptr;
        }
        if (g_bridge_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_bridge_ob_handle);
            g_bridge_ob_handle = nullptr;
        }
        _InterlockedExchange(&g_initialized, 0);
    }

}
