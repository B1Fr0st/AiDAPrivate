#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>
#include <core/TargetingLatch.h>


namespace object_guard {

    inline volatile LONG g_initialized = 0;
    inline PVOID g_ob_callback_handle = nullptr;
    inline volatile UINT64 g_last_suspicious_pid = 0;
    inline volatile UINT32 g_suspicious_handle_count = 0;
    inline volatile HANDLE g_protected_pid = nullptr;

    __forceinline void set_protected_pid(HANDLE pid) {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_protected_pid),
            reinterpret_cast<LONG64>(pid));
    }

    OB_PREOP_CALLBACK_STATUS pre_operation_callback(PVOID, POB_PRE_OPERATION_INFORMATION info) {
        if (!info || !info->ObjectType || !info->Object)
            return OB_PREOP_SUCCESS;

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
        if (!prot_pid)
            return OB_PREOP_SUCCESS;

        HANDLE caller_pid = PsGetCurrentProcessId();
        if (caller_pid == prot_pid || (ULONG_PTR)caller_pid == 4)
            return OB_PREOP_SUCCESS;

        ACCESS_MASK desired = 0;
        HANDLE target_pid = nullptr;

        if (info->ObjectType == *PsProcessType) {
            target_pid = PsGetProcessId(reinterpret_cast<PEPROCESS>(info->Object));
            if (target_pid != prot_pid)
                return OB_PREOP_SUCCESS;

            if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                desired = info->Parameters->CreateHandleInformation.DesiredAccess;
            else
                desired = info->Parameters->DuplicateHandleInformation.DesiredAccess;

            constexpr ACCESS_MASK HOSTILE_PROC =
                PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
                PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION;

            if (desired & HOSTILE_PROC) {
                if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                    info->Parameters->CreateHandleInformation.DesiredAccess &= ~HOSTILE_PROC;
                else
                    info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~HOSTILE_PROC;

                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_OB_WRITE,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)desired,
                    0, 0
                );
            } else if (desired & PROCESS_VM_READ) {
                if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                    info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
                else
                    info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            }
        }
        else if (info->ObjectType == *PsThreadType) {
            target_pid = PsGetThreadProcessId(reinterpret_cast<PETHREAD>(info->Object));
            if (target_pid != prot_pid)
                return OB_PREOP_SUCCESS;

            if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                desired = info->Parameters->CreateHandleInformation.DesiredAccess;
            else
                desired = info->Parameters->DuplicateHandleInformation.DesiredAccess;

            constexpr ACCESS_MASK HOSTILE_THR =
                THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
            constexpr ACCESS_MASK STRIP_THR =
                HOSTILE_THR | THREAD_GET_CONTEXT;

            if (desired & HOSTILE_THR) {
                if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                    info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_THR;
                else
                    info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_THR;

                targeting_latch::latch_targeting(
                    targeting_latch::RE_REASON_OB_SUSPEND,
                    (UINT64)(ULONG_PTR)caller_pid,
                    (UINT64)desired,
                    0, 0
                );
            } else if (desired & THREAD_GET_CONTEXT) {
                if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                    info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
                else
                    info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_GET_CONTEXT;
            }
        }

        return OB_PREOP_SUCCESS;
    }

    __forceinline bool install_ob_callbacks() {
        if (!_ObRegisterCallbacks || !PsProcessType || !PsThreadType)
            return false;

        static OB_OPERATION_REGISTRATION operations[2] = {};
        static OB_CALLBACK_REGISTRATION registration = {};
        static UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321125.0");

        operations[0].ObjectType = PsProcessType;
        operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operations[0].PreOperation = pre_operation_callback;
        operations[0].PostOperation = nullptr;

        operations[1].ObjectType = PsThreadType;
        operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operations[1].PreOperation = pre_operation_callback;
        operations[1].PostOperation = nullptr;

        registration.Version = OB_FLT_REGISTRATION_VERSION;
        registration.OperationRegistrationCount = 2;
        registration.Altitude = altitude;
        registration.RegistrationContext = nullptr;
        registration.OperationRegistration = operations;

        NTSTATUS st = _ObRegisterCallbacks(&registration, &g_ob_callback_handle);
        if (!NT_SUCCESS(st)) {
            g_ob_callback_handle = nullptr;
            SN_LOG("object_guard::install_ob_callbacks failed status=0x%08lx", st);
            return false;
        }

        SN_LOG("object_guard::install_ob_callbacks installed altitude=321125.0");
        return true;
    }


    __forceinline bool hide_device_and_symlink(PDRIVER_OBJECT target_driver_object) {
        if (!target_driver_object || !_MmIsAddressValid(target_driver_object))
            return false;

        __try {
            PDEVICE_OBJECT device = target_driver_object->DeviceObject;
            if (!device || !_MmIsAddressValid(device))
                return false;


            UCHAR* obj_header_addr = reinterpret_cast<UCHAR*>(device) - 0x30;

            if (_MmIsAddressValid(obj_header_addr)) {


                UCHAR info_mask = obj_header_addr[0x1A];
                if (info_mask & 0x02) {


                    device->Flags |= DO_DEVICE_INITIALIZING;
                }
            }

            _InterlockedExchange(&g_initialized, 1);
            return true;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    __forceinline bool init(PDRIVER_OBJECT target_driver_object) {
        SN_LOG("object_guard::init: target_driver_object=%p", target_driver_object);
        bool result = hide_device_and_symlink(target_driver_object);
        bool cb_ok = install_ob_callbacks();
        SN_LOG("object_guard::init: hide=%d ob_callbacks=%d", (int)result, (int)cb_ok);
        return result && cb_ok;
    }
}
