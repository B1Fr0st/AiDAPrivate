#pragma once
#include <imports/Defs.h>
#include <core/Heartbeat.h>
#include <core/ObjectGuard.h>

namespace process_notify {

    inline volatile LONG g_registered = 0;
    inline volatile LONG g_image_registered = 0;

    inline volatile HANDLE g_protected_pid = nullptr;

    struct tool_sig_t {
        const char* prefix;
        int         len;
    };

    __forceinline bool match_prefix_ci(const UCHAR* name, const char* prefix, int prefix_len) {
        for (int i = 0; i < prefix_len; ++i) {
            char a = static_cast<char>(name[i] | 0x20);
            char b = static_cast<char>(prefix[i] | 0x20);
            if (a != b) return false;
        }
        return true;
    }

    static VOID process_create_callback_ex(
        PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO create_info)
    {
        UNREFERENCED_PARAMETER(process);
        UNREFERENCED_PARAMETER(pid);

        if (!create_info)
            return;

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
        if (!prot_pid)
            return;

        if (!create_info->ImageFileName || !create_info->ImageFileName->Buffer)
            return;

        __try {
            PCUNICODE_STRING img = create_info->ImageFileName;
            USHORT chars = img->Length / sizeof(WCHAR);
            USHORT name_start = chars;
            for (USHORT i = chars; i > 0; --i) {
                if (img->Buffer[i - 1] == L'\\' || img->Buffer[i - 1] == L'/') {
                    name_start = i;
                    break;
                }
            }

            char narrow[64] = {};
            USHORT copy_len = chars - name_start;
            if (copy_len > 63) copy_len = 63;
            for (USHORT i = 0; i < copy_len; ++i)
                narrow[i] = (char)(img->Buffer[name_start + i] & 0x7F);

            UNREFERENCED_PARAMETER(narrow);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    static VOID process_create_callback(HANDLE, HANDLE pid, BOOLEAN create) {
        if (!create)
            return;

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
        if (!prot_pid)
            return;

        __try {
            PEPROCESS proc = nullptr;
            NTSTATUS st = PsLookupProcessByProcessId(pid, &proc);
            if (!NT_SUCCESS(st) || !proc)
                return;

            UCHAR* name = PsGetProcessImageFileName(proc);
            UNREFERENCED_PARAMETER(name);
            _ObfDereferenceObject(proc);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    __forceinline void set_protected_pid(HANDLE pid) {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_protected_pid),
            reinterpret_cast<LONG64>(pid));
        object_guard::set_protected_pid(pid);
        SN_LOG("process_notify: protected_pid set to %llu", (UINT64)(ULONG_PTR)pid);
    }

    struct suspicious_dll_t {
        const char* name;
        int         len;
    };

    constexpr suspicious_dll_t g_suspicious_dlls[] = {
        { "frida",      5 },
        { "titanh",     6 },
        { "hyperdbg",   8 },
        { "dbghelp",    7 },
        { "symsrv",     6 },
        { "minhook",    7 },
        { "detours",    7 },
        { "easyhook",   8 },
        { "polyhook",   8 },
        { "inject",     6 },
    };
    constexpr int g_num_suspicious_dlls = sizeof(g_suspicious_dlls) / sizeof(g_suspicious_dlls[0]);

    static VOID image_load_callback(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo)
    {
        UNREFERENCED_PARAMETER(ImageInfo);

        HANDLE prot_pid = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
        if (!prot_pid || ProcessId != prot_pid)
            return;

        if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0)
            return;

        __try {
            USHORT chars = FullImageName->Length / sizeof(WCHAR);
            USHORT name_start = chars;
            for (USHORT i = chars; i > 0; --i) {
                if (FullImageName->Buffer[i - 1] == L'\\' || FullImageName->Buffer[i - 1] == L'/') {
                    name_start = i;
                    break;
                }
            }

            char narrow[64] = {};
            USHORT copy_len = chars - name_start;
            if (copy_len > 63) copy_len = 63;
            for (USHORT i = 0; i < copy_len; ++i) {
                narrow[i] = (char)(FullImageName->Buffer[name_start + i] & 0x7F);
            }

            for (int d = 0; d < g_num_suspicious_dlls; ++d) {
                if (match_prefix_ci((const UCHAR*)narrow, g_suspicious_dlls[d].name, g_suspicious_dlls[d].len)) {
                    SN_LOG("process_notify: SUSPICIOUS DLL loaded into protected process: %.60s pid=%llu",
                        narrow, (UINT64)(ULONG_PTR)ProcessId);
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                        static_cast<ULONG>((ULONG_PTR)ProcessId & 0xFFFFFFFF));
                    return;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    inline volatile LONG g_thread_notify_registered = 0;

    static VOID thread_create_callback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
        UNREFERENCED_PARAMETER(ThreadId);
        UNREFERENCED_PARAMETER(ProcessId);
        UNREFERENCED_PARAMETER(Create);
    }

    __forceinline bool init() {
        NTSTATUS st;

        if (_PsSetCreateProcessNotifyRoutineEx) {
            st = _PsSetCreateProcessNotifyRoutineEx(process_create_callback_ex, FALSE);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_registered, 1);
                SN_LOG("process_notify::init: registered Ex callback (pre-create blocking)");
            } else {
                SN_LOG("process_notify::init: Ex FAILED 0x%lx, falling back", st);
                goto fallback;
            }
        } else {
fallback:
            if (!_PsSetCreateProcessNotifyRoutine)
                return false;
            st = _PsSetCreateProcessNotifyRoutine(process_create_callback, FALSE);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_registered, 1);
                SN_LOG("process_notify::init: registered legacy callback");
            } else {
                SN_LOG("process_notify::init: FAILED status=0x%lx", st);
                return false;
            }
        }

        if (_PsSetLoadImageNotifyRoutine) {
            st = _PsSetLoadImageNotifyRoutine(image_load_callback);
            if (NT_SUCCESS(st)) {
                _InterlockedExchange(&g_image_registered, 1);
                SN_LOG("process_notify::init: registered image load callback");
            }
        }

        st = PsSetCreateThreadNotifyRoutine(thread_create_callback);
        if (NT_SUCCESS(st)) {
            _InterlockedExchange(&g_thread_notify_registered, 1);
            SN_LOG("process_notify::init: registered thread create callback");
        } else {
            SN_LOG("process_notify::init: PsSetCreateThreadNotifyRoutine failed 0x%lx", st);
        }

        return true;
    }

    __forceinline void cleanup() {
        if (_InterlockedCompareExchange(&g_thread_notify_registered, 0, 1) == 1) {
            PsRemoveCreateThreadNotifyRoutine(thread_create_callback);
        }
        if (_InterlockedCompareExchange(&g_registered, 0, 1) == 1) {
            if (_PsSetCreateProcessNotifyRoutine)
                _PsSetCreateProcessNotifyRoutine(process_create_callback, TRUE);
        }
        if (_InterlockedCompareExchange(&g_image_registered, 0, 1) == 1) {
            if (_PsRemoveLoadImageNotifyRoutine)
                _PsRemoveLoadImageNotifyRoutine(image_load_callback);
        }
    }
}
