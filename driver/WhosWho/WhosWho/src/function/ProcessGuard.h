#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "CoreSecurity.h"

namespace process_guard {

    inline PVOID g_ob_handle = nullptr;
    inline volatile LONG g_initialized = 0;

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

        return status;
    }

    inline void cleanup()
    {
        if (g_ob_handle && _ObUnRegisterCallbacks) {
            _ObUnRegisterCallbacks(g_ob_handle);
            g_ob_handle = nullptr;
        }
        _InterlockedExchange(&g_initialized, 0);
    }

}
