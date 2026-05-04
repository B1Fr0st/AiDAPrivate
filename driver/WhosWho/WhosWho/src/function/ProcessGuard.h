#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "CoreSecurity.h"
#include "SentinelBridge.h"
#include "TargetingLatch.h"
#include "DmaCanary.h"
#include "AntiDebug.h"
#include "impl/AntiDumpKernel.h"

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

    __forceinline bool is_allowlisted_system_caller(HANDLE caller_pid) {
        static const char* const ALLOWLIST[] = {
            "csrss", "services", "wininit", "lsass",
            "msmpeng", "securityheal", "werfault"
        };
        static const int ALLOWLIST_LENS[] = { 5, 8, 7, 5, 7, 12, 8 };
        constexpr int ALLOWLIST_COUNT = 7;

        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(caller_pid, &proc)) || !proc)
            return false;

        bool allowed = false;
        __try {
            UCHAR* img = PsGetProcessImageFileName(proc);
            if (img && _MmIsAddressValid(img)) {
                for (int i = 0; i < ALLOWLIST_COUNT; ++i) {
                    const char* prefix = ALLOWLIST[i];
                    int plen = ALLOWLIST_LENS[i];
                    bool match = true;
                    for (int c = 0; c < plen; ++c) {
                        char a = (char)(img[c] | 0x20);
                        char b = (char)(prefix[c] | 0x20);
                        if (a != b) { match = false; break; }
                    }
                    if (match) { allowed = true; break; }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { allowed = false; }

        _ObfDereferenceObject(proc);
        return allowed;
    }

    __forceinline bool is_werfault_caller(HANDLE caller_pid) {
        PEPROCESS proc = nullptr;
        if (!NT_SUCCESS(PsLookupProcessByProcessId(caller_pid, &proc)) || !proc)
            return false;
        bool is_wer = false;
        __try {
            UCHAR* img = PsGetProcessImageFileName(proc);
            if (img && _MmIsAddressValid(img)) {
                const char prefix[] = "werfault";
                bool match = true;
                for (int c = 0; c < 8; ++c) {
                    if ((char)(img[c] | 0x20) != prefix[c]) { match = false; break; }
                }
                is_wer = match;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { is_wer = false; }
        _ObfDereferenceObject(proc);
        return is_wer;
    }

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

        if (is_werfault_caller(caller_pid))
            return OB_PREOP_SUCCESS;

        constexpr ACCESS_MASK HOSTILE_PROC =
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
            PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION;
        constexpr ACCESS_MASK STRIP_READ = PROCESS_VM_READ;

        bool is_system = is_allowlisted_system_caller(caller_pid);

        if (requested & HOSTILE_PROC) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~(HOSTILE_PROC | STRIP_READ);
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(HOSTILE_PROC | STRIP_READ);

            if (!is_system) {
                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_WRITE,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)requested,
                    0, 0
                );
            }
        } else if (requested & STRIP_READ) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_READ;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_READ;
        }

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

        if (is_werfault_caller(caller_pid))
            return OB_PREOP_SUCCESS;

        ACCESS_MASK requested = 0;
        if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
            requested = Info->Parameters->CreateHandleInformation.DesiredAccess;
        else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            requested = Info->Parameters->DuplicateHandleInformation.DesiredAccess;

        constexpr ACCESS_MASK HOSTILE_THR =
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
        constexpr ACCESS_MASK STRIP_THR = HOSTILE_THR | THREAD_GET_CONTEXT;

        bool is_system = is_allowlisted_system_caller(caller_pid);

        if (requested & HOSTILE_THR) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_THR;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_THR;

            if (!is_system) {
                targeting_latch::latch_targeting(
                    sentinel_bridge::RE_REASON_OB_SUSPEND,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)requested,
                    0, 0
                );
            }
        } else if (requested & THREAD_GET_CONTEXT) {
            if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
                Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
            else
                Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
        }

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

        UNREFERENCED_PARAMETER(ThreadId);
    }


    inline VOID NTAPI create_process_notify(
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        UNREFERENCED_PARAMETER(Process);

        if (!CreateInfo) {
            UINT32 dying_pid = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(ProcessId));
            if (dying_pid != 0 && dying_pid != 4) {
                ULONG cleared = anti_dma_canary::cleanup_for_pid(dying_pid);
                continuous_anti_debug::stop_if_target(dying_pid);
                continuous_anti_dump::stop_if_target(dying_pid);
                HANDLE registered = caller_validation::g_registered_client_pid;
                if (registered &&
                    reinterpret_cast<UINT64>(registered) == static_cast<UINT64>(dying_pid)) {
                    caller_validation::unregister_client();
                    WW_LOG("create_process_notify: registered client pid=%u exited, unregistered (canaries_cleared=%lu)",
                        dying_pid, cleared);
                } else if (cleared) {
                    WW_LOG("create_process_notify: pid=%u exited, canaries_cleared=%lu",
                        dying_pid, cleared);
                }
            }
            return;
        }

        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid)
            return;


        HANDLE parent_pid = CreateInfo->ParentProcessId;


        if (parent_pid == client_pid)
            return;


        if (reinterpret_cast<UINT64>(parent_pid) == 4)
            return;


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
