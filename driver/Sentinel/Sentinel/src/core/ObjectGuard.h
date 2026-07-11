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
    inline volatile LONG g_hide_thread_active = 0;
    inline volatile LONG g_device_hidden = 0;
    inline PDRIVER_OBJECT g_target_driver_object = nullptr;

    struct allowlist_entry_t {
        const char* name;
        int         len;
    };

    constexpr allowlist_entry_t g_allowlist[] = {
        { "csrss.exe",               10 },
        { "lsass.exe",                9 },
        { "svchost.exe",             11 },
        { "services.exe",            12 },
        { "wininit.exe",             12 },
        { "winlogon.exe",            13 },
        { "smss.exe",                 8 },
        { "MsMpEng.exe",             12 },
        { "SecurityHealthService",   23 },
        { "WerFault.exe",            13 },
        { "devenv.exe",              11 },
        { "SearchIndexer.exe",       19 },
        { "dwm.exe",                  7 },
        { "fontdrvhost.exe",         15 },
        { "audiodg.exe",             12 },
        { "explorer.exe",            13 },
    };
    constexpr int g_allowlist_count = sizeof(g_allowlist) / sizeof(g_allowlist[0]);

    constexpr ACCESS_MASK TIER_ALLOW_MASK = PROCESS_QUERY_INFORMATION;
    constexpr ACCESS_MASK TIER_LOG_MASK   = PROCESS_VM_READ;
    constexpr ACCESS_MASK TIER_BLOCK_MASK = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

    constexpr ULONG BUGCHECK_HOSTILE_HANDLE = 0xA1DA0003u;

    __forceinline bool is_caller_allowlisted(HANDLE caller_pid) {
        if (!caller_pid || (ULONG_PTR)caller_pid == 4)
            return true;

        PEPROCESS proc = nullptr;
        NTSTATUS st = PsLookupProcessByProcessId(caller_pid, &proc);
        if (!NT_SUCCESS(st) || !proc)
            return false;

        bool allowlisted = false;
        __try {
            UCHAR* name = PsGetProcessImageFileName(proc);
            if (name) {
                for (int i = 0; i < g_allowlist_count; ++i) {
                    int j = 0;
                    bool match = true;
                    while (j < g_allowlist[i].len) {
                        char a = (char)(name[j] | 0x20);
                        char b = (char)(g_allowlist[i].name[j] | 0x20);
                        if (a != b) { match = false; break; }
                        ++j;
                    }
                    if (match && name[j] == 0) {
                        allowlisted = true;
                        break;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        _ObfDereferenceObject(proc);
        return allowlisted;
    }

    __forceinline void set_protected_pid(HANDLE pid) {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_protected_pid),
            reinterpret_cast<LONG64>(pid));
    }

    __forceinline HANDLE get_effective_protected_pid() {
        HANDLE bridge_pid = heartbeat::get_bridge_protected_pid();
        if (bridge_pid)
            return bridge_pid;
        return reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
    }

    OB_PREOP_CALLBACK_STATUS pre_operation_callback(PVOID, POB_PRE_OPERATION_INFORMATION info) {
        if (!info || !info->ObjectType || !info->Object)
            return OB_PREOP_SUCCESS;

        HANDLE prot_pid = get_effective_protected_pid();
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

            bool caller_allowlisted = is_caller_allowlisted(caller_pid);

            constexpr ACCESS_MASK HOSTILE_PROC =
                PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
                PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION |
                PROCESS_DUP_HANDLE;
            constexpr ACCESS_MASK STRIP_READ = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
            constexpr ACCESS_MASK ALLOWLIST_STRIP =
                PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

            if (desired & TIER_BLOCK_MASK) {
                if (!caller_allowlisted) {
                    SN_LOG("object_guard: BLOCK TIER non-allowlisted pid=%llu desired=0x%08x -- BSOD",
                        (UINT64)(ULONG_PTR)caller_pid, (UINT32)desired);

                    targeting_latch::latch_targeting(
                        targeting_latch::RE_REASON_OB_WRITE,
                        (UINT64)(ULONG_PTR)caller_pid,
                        (UINT64)desired,
                        0, 0
                    );

                    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                        info->Parameters->CreateHandleInformation.DesiredAccess &= ~(HOSTILE_PROC | STRIP_READ);
                    else
                        info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(HOSTILE_PROC | STRIP_READ);

#ifndef AIDA_DEV_MODE
                    if (_KeBugCheckEx) {
                        _KeBugCheckEx(BUGCHECK_HOSTILE_HANDLE, (ULONG_PTR)caller_pid, (ULONG_PTR)desired, 0, 0);
                    }
#endif
                } else {
                    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                        info->Parameters->CreateHandleInformation.DesiredAccess &= ~ALLOWLIST_STRIP;
                    else
                        info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~ALLOWLIST_STRIP;

                    SN_LOG("object_guard: BLOCK TIER allowlisted pid=%llu desired=0x%08x -- strip write only",
                        (UINT64)(ULONG_PTR)caller_pid, (UINT32)desired);
                }
            } else if (desired & TIER_LOG_MASK) {
                if (!caller_allowlisted) {
                    SN_LOG("object_guard: LOG TIER non-allowlisted VM_READ pid=%llu -- log + strip",
                        (UINT64)(ULONG_PTR)caller_pid);

                    _InterlockedExchange64(
                        reinterpret_cast<volatile LONG64*>(&g_last_suspicious_pid),
                        reinterpret_cast<LONG64>(caller_pid));
                    _InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_suspicious_handle_count));

                    targeting_latch::latch_targeting(
                        targeting_latch::RE_REASON_OB_WRITE,
                        (UINT64)(ULONG_PTR)caller_pid,
                        (UINT64)desired,
                        0, 0
                    );

                    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
                        info->Parameters->CreateHandleInformation.DesiredAccess &= ~STRIP_READ;
                    else
                        info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~STRIP_READ;
                }
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


    __forceinline bool set_device_open_state(PDRIVER_OBJECT target_driver_object, BOOLEAN hidden, const char* phase) {
        if (!target_driver_object || !_MmIsAddressValid(target_driver_object))
            return false;

        __try {
            PDEVICE_OBJECT device = target_driver_object->DeviceObject;
            if (!device || !_MmIsAddressValid(device))
                return false;

            UCHAR* obj_header_addr = reinterpret_cast<UCHAR*>(device) - 0x30;
            ULONG flags_before = device->Flags;
            CSHORT refs = device->ReferenceCount;
            UCHAR info_mask = 0;

            if (_MmIsAddressValid(obj_header_addr)) {
                info_mask = obj_header_addr[0x1A];
                device->Flags &= ~DO_DEVICE_INITIALIZING;
            } else {
                device->Flags &= ~DO_DEVICE_INITIALIZING;
            }

            ULONG flags_after = device->Flags;
            _InterlockedExchange(&g_device_hidden, 0);
            SN_LOG("object_guard::device_open_state phase=%s requested_hidden=%u openable=1 device=%p info_mask=0x%02x refs=%d flags_before=0x%lx flags_after=0x%lx first_hb=%ld bridge=%p whoswho_tsc=%llu",
                phase ? phase : "unknown",
                hidden ? 1u : 0u,
                device,
                info_mask,
                static_cast<int>(refs),
                flags_before,
                flags_after,
                _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0),
                heartbeat::g_bridge,
                heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->whoswho_tsc) : 0ull);
            return true;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SN_LOG("object_guard::device_open_state exception phase=%s hidden=%u",
                phase ? phase : "unknown",
                hidden ? 1u : 0u);
            return false;
        }
    }

    __forceinline bool hide_device_and_symlink(PDRIVER_OBJECT target_driver_object) {
        bool ok = set_device_open_state(target_driver_object, TRUE, "hide");
        if (ok)
            _InterlockedExchange(&g_initialized, 1);
        return ok;
    }

    __forceinline bool restore_device_openable(PDRIVER_OBJECT target_driver_object, const char* phase) {
        bool ok = set_device_open_state(target_driver_object, FALSE, phase);
        if (ok)
            _InterlockedExchange(&g_initialized, 1);
        return ok;
    }

    __forceinline BOOLEAN first_client_heartbeat_seen() {
        if (_InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0) == 0)
            return FALSE;
        if (!heartbeat::g_bridge || !_MmIsAddressValid(reinterpret_cast<PVOID>(
                const_cast<heartbeat::sentinel_bridge_t*>(heartbeat::g_bridge))))
            return FALSE;
        return heartbeat::g_bridge->whoswho_tsc != 0 ? TRUE : FALSE;
    }

    __forceinline CSHORT device_open_reference_count(PDRIVER_OBJECT target_driver_object) {
        if (!target_driver_object || !_MmIsAddressValid(target_driver_object))
            return 0;

        __try {
            PDEVICE_OBJECT device = target_driver_object->DeviceObject;
            if (!device || !_MmIsAddressValid(device))
                return 0;
            return device->ReferenceCount;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    inline VOID NTAPI deferred_hide_thread(PVOID) {
        _InterlockedExchange(&g_hide_thread_active, 1);

        PDRIVER_OBJECT target = g_target_driver_object;
        SN_LOG("object_guard::deferred_hide_thread entry target=%p bridge=%p first_hb=%ld",
            target,
            heartbeat::g_bridge,
            _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0));

        bool hidden = false;
        for (ULONG i = 0; i < 240; ++i) {
            BOOLEAN first_hb = first_client_heartbeat_seen();
            CSHORT refs = device_open_reference_count(target);
            if (first_hb && refs > 0) {
                hidden = hide_device_and_symlink(target);
                SN_LOG("object_guard::deferred_hide_thread hide_attempt poll=%lu hidden=%u refs=%d first_hb=%u",
                    i,
                    hidden ? 1u : 0u,
                    static_cast<int>(refs),
                    first_hb ? 1u : 0u);
                break;
            }
            if ((i < 8) || ((i % 20) == 0)) {
                SN_LOG("object_guard::deferred_hide_thread wait poll=%lu refs=%d first_hb=%u bridge=%p whoswho_tsc=%llu",
                    i,
                    static_cast<int>(refs),
                    first_hb ? 1u : 0u,
                    heartbeat::g_bridge,
                    heartbeat::g_bridge ? static_cast<unsigned long long>(heartbeat::g_bridge->whoswho_tsc) : 0ull);
            }
            if (_KeDelayExecutionThread) {
                LARGE_INTEGER wait;
                wait.QuadPart = -2500000LL;
                _KeDelayExecutionThread(KernelMode, FALSE, &wait);
            }
        }

        if (!hidden) {
            restore_device_openable(target, "deferred_no_client");
            SN_LOG("object_guard::deferred_hide_thread no_client_seen target=%p bridge=%p first_hb=%ld",
                target,
                heartbeat::g_bridge,
                _InterlockedCompareExchange(&heartbeat::g_first_heartbeat_seen, 0, 0));
        }

        _InterlockedExchange(&g_hide_thread_active, 0);
        if (_PsTerminateSystemThread)
            _PsTerminateSystemThread(STATUS_SUCCESS);
    }

    __forceinline bool start_deferred_hide(PDRIVER_OBJECT target_driver_object) {
        if (!target_driver_object || !_PsCreateSystemThread || !_ZwClose)
            return false;
        if (_InterlockedCompareExchange(&g_hide_thread_active, 1, 0) != 0)
            return true;

        g_target_driver_object = target_driver_object;
        HANDLE thread_handle = nullptr;
        NTSTATUS st = _PsCreateSystemThread(
            &thread_handle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            reinterpret_cast<PKSTART_ROUTINE>(deferred_hide_thread),
            nullptr);
        SN_LOG("object_guard::start_deferred_hide status=0x%08lx handle=%p target=%p", st, thread_handle, target_driver_object);
        if (NT_SUCCESS(st)) {
            _ZwClose(thread_handle);
            return true;
        }
        _InterlockedExchange(&g_hide_thread_active, 0);
        g_target_driver_object = nullptr;
        return false;
    }

    __forceinline bool init(PDRIVER_OBJECT target_driver_object) {
        SN_LOG("object_guard::init: target_driver_object=%p", target_driver_object);
        bool cb_ok = install_ob_callbacks();
        bool open_ok = restore_device_openable(target_driver_object, "init_pre_client");
        _InterlockedExchange(&g_hide_thread_active, 0);
        g_target_driver_object = target_driver_object;
        SN_LOG("object_guard::init: openable=%d hide_deferred=0 ob_callbacks=%d", (int)open_ok, (int)cb_ok);
        return open_ok && cb_ok;
    }
}
