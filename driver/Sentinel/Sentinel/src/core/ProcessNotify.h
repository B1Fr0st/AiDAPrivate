#pragma once
#include <imports/Defs.h>

namespace process_notify {

    inline volatile LONG g_registered = 0;

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

    static VOID process_create_callback(HANDLE, HANDLE pid, BOOLEAN create) {
        if (!create)
            return;

        HANDLE protected = reinterpret_cast<HANDLE>(
            _InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64*>(&g_protected_pid), 0, 0));
        if (!protected)
            return;

        __try {
            PEPROCESS proc = nullptr;
            NTSTATUS st = PsLookupProcessByProcessId(pid, &proc);
            if (!NT_SUCCESS(st) || !proc)
                return;

            UCHAR* name = PsGetProcessImageFileName(proc);
            if (name && _MmIsAddressValid(name)) {
                if (is_dump_tool(name)) {
                    SN_LOG("process_notify: dump tool launched pid=%llu name=%.15s, will monitor",
                        (UINT64)(ULONG_PTR)pid, name);
                    object_guard::g_last_suspicious_pid = (UINT64)(ULONG_PTR)pid;
                    InterlockedIncrement((volatile LONG*)&object_guard::g_suspicious_handle_count);
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

    __forceinline bool init() {
        if (!_PsSetCreateProcessNotifyRoutine)
            return false;

        NTSTATUS st = _PsSetCreateProcessNotifyRoutine(process_create_callback, FALSE);
        if (NT_SUCCESS(st)) {
            _InterlockedExchange(&g_registered, 1);
            SN_LOG("process_notify::init: registered process notify callback");
            return true;
        }
        SN_LOG("process_notify::init: FAILED status=0x%lx", st);
        return false;
    }

    __forceinline void cleanup() {
        if (_InterlockedCompareExchange(&g_registered, 0, 1) == 1) {
            if (_PsSetCreateProcessNotifyRoutine)
                _PsSetCreateProcessNotifyRoutine(process_create_callback, TRUE);
        }
    }
}
