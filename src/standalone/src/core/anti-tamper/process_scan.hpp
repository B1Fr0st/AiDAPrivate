#pragma once

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace anti_tamper {
namespace process_scan {

struct process_info_t {
    DWORD pid;
    std::string image_name;
    std::string image_path;
    bool has_handle_to_us;
    ACCESS_MASK handle_access;
    bool is_known_re_tool;
    bool is_suspicious;
};

inline std::string get_process_image_name(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char name[MAX_PATH] = {};
    DWORD len = MAX_PATH;
    if (QueryFullProcessImageNameA(h, 0, name, &len)) {
        std::string full(name, len);
        CloseHandle(h);
        size_t pos = full.find_last_of("\\/");
        if (pos != std::string::npos) return full.substr(pos + 1);
        return full;
    }
    CloseHandle(h);
    return "";
}

inline std::string get_process_image_path(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char name[MAX_PATH] = {};
    DWORD len = MAX_PATH;
    if (QueryFullProcessImageNameA(h, 0, name, &len)) {
        CloseHandle(h);
        return std::string(name, len);
    }
    CloseHandle(h);
    return "";
}

inline std::vector<process_info_t> scan_for_threats(DWORD self_pid)
{
    std::vector<process_info_t> results;

    DWORD pids[1024];
    DWORD bytes_returned = 0;
    if (!EnumProcesses(pids, sizeof(pids), &bytes_returned))
        return results;
    DWORD proc_count = bytes_returned / sizeof(DWORD);

    static const char* system_procs[] = {
        "csrss.exe", "lsass.exe", "svchost.exe", "services.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "msmpeng.exe",
        "securityhealthservice.exe", "werfault.exe", "explorer.exe",
        "dwm.exe", "system", "idle", "registry"
    };

    for (DWORD i = 0; i < proc_count; ++i) {
        if (pids[i] == self_pid || pids[i] == 0) continue;

        process_info_t info = {};
        info.pid = pids[i];
        info.image_name = get_process_image_name(pids[i]);
        info.image_path = get_process_image_path(pids[i]);
        info.has_handle_to_us = false;
        info.handle_access = 0;
        info.is_known_re_tool = false;
        info.is_suspicious = false;

        bool is_system = false;
        for (const char* s : system_procs) {
            if (_stricmp(info.image_name.c_str(), s) == 0) {
                is_system = true;
                break;
            }
        }

        if (!is_system && !info.image_name.empty()) {
            static const char* re_tool_names[] = {
                "cheatengine", "ce.exe", "x64dbg", "x32dbg", "windbg",
                "ida", "ida64", "idaq", "ghidra", "processhacker",
                "ollydbg", "dnspy", "hxd", "scylla", "apimonitor",
                "hyperdbg", "radare2", "cetrainer", "ceserver",
                "memrecon", "artmoney", "hexworkshop", "010editor"
            };
            for (const char* re : re_tool_names) {
                if (_stricmp(info.image_name.c_str(), re) == 0) {
                    info.is_known_re_tool = true;
                    info.is_suspicious = true;
                    break;
                }
            }
        }

        results.push_back(info);
    }

    return results;
}

inline bool any_process_has_vm_access(DWORD self_pid)
{
    typedef LONG(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    static NtQuerySystemInformation_t pNtQuerySystemInformation = nullptr;
    if (!pNtQuerySystemInformation) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (!pNtQuerySystemInformation) return false;
    }

    struct SYSTEM_HANDLE_ENTRY_X {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ACCESS_MASK GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    ULONG buf_size = 0x100000;
    std::vector<BYTE> buffer(buf_size);
    ULONG ret_len = 0;
    LONG status = pNtQuerySystemInformation(64, buffer.data(), buf_size, &ret_len);
    if (status == static_cast<LONG>(0xC0000004L) && ret_len > buf_size) {
        buf_size = ret_len + 65536;
        buffer.resize(buf_size);
        ret_len = 0;
        status = pNtQuerySystemInformation(64, buffer.data(), buf_size, &ret_len);
    }
    if (status < 0) return false;

    struct handle_info_ex {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_ENTRY_X Handles[1];
    };

    auto* info = reinterpret_cast<handle_info_ex*>(buffer.data());

    static const char* system_procs[] = {
        "csrss.exe", "lsass.exe", "svchost.exe", "services.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "msmpeng.exe",
        "securityhealthservice.exe", "werfault.exe"
    };

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& h = info->Handles[i];
        if (static_cast<DWORD>(h.UniqueProcessId) == self_pid) continue;
        if (static_cast<DWORD>(h.UniqueProcessId) <= 4) continue;

        ACCESS_MASK access = h.GrantedAccess;
        if ((access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) == 0)
            continue;

        HANDLE src_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
            static_cast<DWORD>(h.UniqueProcessId));
        if (!src_proc) continue;

        HANDLE dup = nullptr;
        BOOL dup_ok = DuplicateHandle(
            src_proc,
            reinterpret_cast<HANDLE>(h.HandleValue),
            GetCurrentProcess(),
            &dup,
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            0);
        CloseHandle(src_proc);
        if (!dup_ok || !dup) continue;

        DWORD target_pid = GetProcessId(dup);
        CloseHandle(dup);

        if (target_pid == self_pid) {
            std::string owner_name = get_process_image_name(static_cast<DWORD>(h.UniqueProcessId));
            bool is_system = false;
            for (const char* s : system_procs) {
                if (_stricmp(owner_name.c_str(), s) == 0) { is_system = true; break; }
            }
            if (!is_system && !owner_name.empty()) return true;
        }
    }
    return false;
}

inline bool is_ce_behavioral_match(const process_info_t& info)
{
    if (!info.has_handle_to_us) return false;
    if ((info.handle_access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) == 0)
        return false;
    static const char* system_procs[] = {
        "csrss.exe", "lsass.exe", "svchost.exe", "services.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "msmpeng.exe",
        "securityhealthservice.exe", "werfault.exe"
    };
    for (const char* s : system_procs) {
        if (_stricmp(info.image_name.c_str(), s) == 0) return false;
    }
    return true;
}

} // namespace process_scan
} // namespace anti_tamper
