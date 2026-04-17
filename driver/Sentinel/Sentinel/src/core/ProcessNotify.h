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

    constexpr tool_sig_t g_dump_tools[] = {
        { "procdump",     8 },
        { "processdump",  11 },
        { "hollowshunt",  11 },
        { "pe-sieve",     8 },
        { "scylla",       6 },
        { "taskdmp",      7 },
        { "minidump",     8 },
        { "processhack",  11 },
        { "x64dbg",       6 },
        { "x32dbg",       6 },
        { "ollydbg",      7 },
        { "windbg",       6 },
        { "ida64",        5 },
        { "ida32",        5 },
        { "idaq",         4 },
        { "cheatengine",  11 },
        { "reclass",      7 },
        { "hmpalert",     8 },
        { "apimonitor",   10 },
        { "procmon",      7 },
    };
    constexpr int g_num_dump_tools = sizeof(g_dump_tools) / sizeof(g_dump_tools[0]);

    __forceinline bool match_prefix_ci(const UCHAR* name, const char* prefix, int prefix_len) {
        for (int i = 0; i < prefix_len; ++i) {
            char a = static_cast<char>(name[i] | 0x20);
            char b = static_cast<char>(prefix[i] | 0x20);
            if (a != b) return false;
        }
        return true;
    }

    __forceinline bool is_dump_tool(const UCHAR* name) {
        for (int t = 0; t < g_num_dump_tools; ++t) {
            if (match_prefix_ci(name, g_dump_tools[t].prefix, g_dump_tools[t].len))
                return true;
        }
        return false;
    }

    __forceinline bool process_has_handle_to_target(HANDLE tool_pid, HANDLE target_pid) {
        if (!_ZwOpenProcess || !_ZwClose)
            return false;

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        CLIENT_ID cid = {};
        cid.UniqueProcess = tool_pid;

        HANDLE hToolProc = nullptr;
        NTSTATUS st = _ZwOpenProcess(&hToolProc, PROCESS_QUERY_INFORMATION, &oa, &cid);
        if (!NT_SUCCESS(st) || !hToolProc)
            return false;

        _ZwClose(hToolProc);

        PEPROCESS target_proc = nullptr;
        st = PsLookupProcessByProcessId(target_pid, &target_proc);
        if (!NT_SUCCESS(st) || !target_proc)
            return false;

        UCHAR* target_name = PsGetProcessImageFileName(target_proc);
        _ObfDereferenceObject(target_proc);

        if (!target_name || !_MmIsAddressValid(target_name))
            return false;

        return true;
    }

    __forceinline void terminate_process_by_pid(HANDLE pid) {
        if (!_ZwOpenProcess || !_ZwTerminateProcess || !_ZwClose)
            return;

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
        CLIENT_ID cid = {};
        cid.UniqueProcess = pid;

        HANDLE hProc = nullptr;
        NTSTATUS st = _ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid);
        if (NT_SUCCESS(st) && hProc) {
            _ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
            _ZwClose(hProc);
        }
    }

    static VOID process_create_callback_ex(
        PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO create_info)
    {
        UNREFERENCED_PARAMETER(process);

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

            if (is_dump_tool(reinterpret_cast<const UCHAR*>(narrow))) {
                SN_LOG("process_notify_ex: BLOCKED dump tool pre-create pid=%llu name=%.60s",
                    (UINT64)(ULONG_PTR)pid, narrow);
                create_info->CreationStatus = STATUS_ACCESS_DENIED;
                object_guard::g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
                InterlockedIncrement((volatile LONG*)&object_guard::g_suspicious_handle_count);
                heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                    static_cast<ULONG>((ULONG_PTR)pid & 0xFFFFFFFF));
                return;
            }
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
            if (name && _MmIsAddressValid(name)) {
                if (is_dump_tool(name)) {
                    SN_LOG("process_notify: dump tool launched pid=%llu name=%.15s, TERMINATING",
                        (UINT64)(ULONG_PTR)pid, name);
                    object_guard::g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
                    InterlockedIncrement((volatile LONG*)&object_guard::g_suspicious_handle_count);
                    _ObfDereferenceObject(proc);
                    terminate_process_by_pid(pid);
                    heartbeat::send_command(heartbeat::BRIDGE_CMD_DUMP_TOOL_FOUND,
                        static_cast<ULONG>((ULONG_PTR)pid & 0xFFFFFFFF));
                    return;
                }
            }

            _ObfDereferenceObject(proc);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    __forceinline void set_protected_pid(HANDLE pid) {
        _InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_protected_pid),
            reinterpret_cast<LONG64>(pid));
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

        return true;
    }

    __forceinline void cleanup() {
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
