#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>


namespace object_guard {

    inline volatile LONG g_initialized = 0;
    inline PVOID g_ob_callback_handle = nullptr;
    inline volatile UINT64 g_last_suspicious_pid = 0;
    inline volatile UINT32 g_suspicious_handle_count = 0;

    inline const char* g_dump_tools[] = {
        "procdump", "processdump", "hollowshunt",
        "pe-sieve", "scylla", "taskdmp", "minidump",
        "dumper", "processhacker", "x64dbg", "x32dbg",
        "windbg", "ida", "ida64", "idaq", "idaq64",
        "ghidra", "binaryninja", "dnspy", "ilspy",
        "cheatengine", "ce.exe", "apimonitor",
        "ollydbg", "reshack", "pestudio", "radare2",
        "cutter", "hyperdbg", "reclass", "classinfo",
        "sigmaker", "peid", "die.exe", "titanhide",
        "scyllahide", "volatility", "rekall",
        "vmmap.exe", "apispy", "procmon", "rweverything",
        "pcihunter", "pchunter", "winobj", "kerneldetect"
    };
    constexpr int g_dump_tool_count = sizeof(g_dump_tools) / sizeof(g_dump_tools[0]);

    __forceinline bool is_dump_tool_name(const char* name) {
        if (!name)
            return false;

        for (int t = 0; t < g_dump_tool_count; ++t) {
            const char* target = g_dump_tools[t];
            bool match = true;
            for (int c = 0; target[c] != '\0'; ++c) {
                char a = (char)(name[c] | 0x20);
                char b = (char)(target[c] | 0x20);
                if (a != b) { match = false; break; }
            }
            if (match)
                return true;
        }
        return false;
    }

    OB_PREOP_CALLBACK_STATUS pre_operation_callback(PVOID, POB_PRE_OPERATION_INFORMATION info) {
        if (!info || !info->ObjectType)
            return OB_PREOP_SUCCESS;

        PEPROCESS caller = PsGetCurrentProcess();
        if (!caller || !_MmIsAddressValid(caller))
            return OB_PREOP_SUCCESS;

        const char* caller_name = reinterpret_cast<const char*>(PsGetProcessImageFileName(caller));
        if (!caller_name || !is_dump_tool_name(caller_name))
            return OB_PREOP_SUCCESS;

        ACCESS_MASK deny_mask_process = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_DUP_HANDLE | PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;
        ACCESS_MASK deny_mask_thread = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_SUSPEND_RESUME | THREAD_TERMINATE;

        if (info->ObjectType == *PsProcessType) {
            if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
                info->Parameters->CreateHandleInformation.DesiredAccess &= ~deny_mask_process;
            }
            else if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~deny_mask_process;
            }
        }
        else if (info->ObjectType == *PsThreadType) {
            if (info->Operation == OB_OPERATION_HANDLE_CREATE) {
                info->Parameters->CreateHandleInformation.DesiredAccess &= ~deny_mask_thread;
            }
            else if (info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~deny_mask_thread;
            }
        }

        HANDLE pid = PsGetCurrentProcessId();
        g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
        InterlockedIncrement((volatile LONG*)&g_suspicious_handle_count);
        heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
            static_cast<ULONG>((ULONG_PTR)pid & 0xFFFFFFFF));
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

    __forceinline void scan_suspicious_handles() {
        __try {
            PEPROCESS initial = PsInitialSystemProcess;
            if (!initial || !_MmIsAddressValid(initial)) return;

            PLIST_ENTRY list_head = (PLIST_ENTRY)((UINT8*)initial + 0x448);
            PLIST_ENTRY entry = list_head->Flink;

            for (int iter = 0; iter < 1024 && entry != list_head; ++iter, entry = entry->Flink) {
                PEPROCESS proc = (PEPROCESS)((UINT8*)entry - 0x448);
                if (!_MmIsAddressValid(proc)) continue;

                UCHAR* name = PsGetProcessImageFileName(proc);
                if (!name || !_MmIsAddressValid(name)) continue;

                if (is_dump_tool_name(reinterpret_cast<const char*>(name))) {
                    HANDLE pid = PsGetProcessId(proc);
                    g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
                    InterlockedIncrement((volatile LONG*)&g_suspicious_handle_count);
                    SN_LOG("object_guard::scan: DUMP TOOL DETECTED pid=%llu name=%.15s — TERMINATING",
                        (UINT64)(ULONG_PTR)pid, name);


                    if (_ZwOpenProcess && _ZwTerminateProcess && _ZwClose) {
                        OBJECT_ATTRIBUTES oa;
                        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                        CLIENT_ID cid = {};
                        cid.UniqueProcess = pid;
                        HANDLE hProc = nullptr;
                        NTSTATUS term_st = _ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid);
                        if (NT_SUCCESS(term_st) && hProc) {
                            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
                            _ZwClose(hProc);
                            SN_LOG("object_guard::scan: terminated dump tool pid=%llu",
                                (UINT64)(ULONG_PTR)pid);
                        }
                    }


                    heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                        static_cast<ULONG>((ULONG_PTR)pid & 0xFFFFFFFF));

                    return;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
}
