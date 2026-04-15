#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <cstdint>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "syscall.hpp"

namespace anti_tamper {
namespace process_scan {

struct scan_report_t
{
    bool re_tool_with_binary = false;
    bool re_tool_running = false;
    bool suspicious_window_title = false;
    bool injected_dll = false;
    bool sideloaded_system_dll = false;
    std::string detail;

    bool any_detected() const
    {
        return re_tool_with_binary || injected_dll || sideloaded_system_dll;
    }
};

namespace detail {

    struct SYSTEM_PROCESS_INFORMATION_ENTRY
    {
        ULONG  NextEntryOffset;
        ULONG  NumberOfThreads;
        BYTE   Reserved1[48];
        UNICODE_STRING ImageName;
        LONG   BasePriority;
        HANDLE UniqueProcessId;
    };

    inline bool is_re_tool_name(const wchar_t* lower_name)
    {
        return wcsstr(lower_name, L"ghidra") || wcsstr(lower_name, L"binja")
            || wcsstr(lower_name, L"binaryninja") || wcsstr(lower_name, L"cutter")
            || wcsstr(lower_name, L"radare2") || wcsstr(lower_name, L"r2.exe")
            || wcsstr(lower_name, L"rizin") || wcsstr(lower_name, L"x64dbg")
            || wcsstr(lower_name, L"x32dbg") || wcsstr(lower_name, L"windbg")
            || wcsstr(lower_name, L"ollydbg") || wcsstr(lower_name, L"dnspy")
            || wcsstr(lower_name, L"dotpeek") || wcsstr(lower_name, L"pestudio")
            || wcsstr(lower_name, L"die.exe") || wcsstr(lower_name, L"ida64.exe")
            || wcsstr(lower_name, L"ida.exe") || wcsstr(lower_name, L"hxd.exe")
            || wcsstr(lower_name, L"reclass") || wcsstr(lower_name, L"apimonitor")
            || wcsstr(lower_name, L"winapioverride") || wcsstr(lower_name, L"rohitab")
            || wcsstr(lower_name, L"dumpbin") || wcsstr(lower_name, L"immunity")
            || wcsstr(lower_name, L"frida") || wcsstr(lower_name, L"pin.exe")
            || wcsstr(lower_name, L"pintool");
    }

}

inline bool scan_re_tools_with_binary()
{
    DWORD my_pid = GetCurrentProcessId();

    wchar_t my_exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, my_exe, MAX_PATH);

    bool use_syscall = syscall::is_initialized();

    if (use_syscall)
    {
        ULONG buf_size = 1024 * 256;
        std::vector<uint8_t> buf(buf_size);
        ULONG ret_len = 0;

        NTSTATUS st = syscall::NtQuerySystemInformation()(
            5, buf.data(), buf_size, &ret_len);

        if (st == 0xC0000004 && ret_len > buf_size)
        {
            buf_size = ret_len + 4096;
            buf.resize(buf_size);
            st = syscall::NtQuerySystemInformation()(
                5, buf.data(), buf_size, &ret_len);
        }

        if (st >= 0)
        {
            auto* entry = reinterpret_cast<detail::SYSTEM_PROCESS_INFORMATION_ENTRY*>(buf.data());
            while (true)
            {
                auto pid = reinterpret_cast<uintptr_t>(entry->UniqueProcessId);
                if (pid != my_pid && pid != 0 && pid != 4
                    && entry->ImageName.Buffer && entry->ImageName.Length > 0)
                {
                    wchar_t lower[MAX_PATH] = {};
                    USHORT chars = entry->ImageName.Length / sizeof(wchar_t);
                    for (USHORT i = 0; i < chars && i < MAX_PATH - 1; ++i)
                        lower[i] = towlower(entry->ImageName.Buffer[i]);

                    if (detail::is_re_tool_name(lower))
                    {
                        HANDLE hProc = OpenProcess(
                            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                            FALSE, static_cast<DWORD>(pid));
                        if (hProc)
                        {
                            HMODULE mods[512] = {};
                            DWORD cb = 0;
                            if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL))
                            {
                                DWORD count = cb / sizeof(HMODULE);
                                for (DWORD i = 0; i < count; ++i)
                                {
                                    wchar_t mod_path[MAX_PATH] = {};
                                    if (GetModuleFileNameExW(hProc, mods[i], mod_path, MAX_PATH) > 0)
                                    {
                                        if (_wcsicmp(mod_path, my_exe) == 0)
                                        {
                                            CloseHandle(hProc);
                                            return true;
                                        }
                                    }
                                }
                            }
                            CloseHandle(hProc);
                        }
                    }
                }

                if (entry->NextEntryOffset == 0) break;
                entry = reinterpret_cast<detail::SYSTEM_PROCESS_INFORMATION_ENTRY*>(
                    reinterpret_cast<uint8_t*>(entry) + entry->NextEntryOffset);
            }
            return false;
        }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    bool violation = false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    for (BOOL ok = Process32FirstW(snap, &pe); ok && !violation;
         ok = Process32NextW(snap, &pe))
    {
        if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0
            || pe.th32ProcessID == 4)
            continue;

        wchar_t lower[MAX_PATH] = {};
        for (size_t i = 0; i < MAX_PATH - 1 && pe.szExeFile[i]; ++i)
            lower[i] = towlower(pe.szExeFile[i]);

        if (!detail::is_re_tool_name(lower)) continue;

        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, pe.th32ProcessID);
        if (!hProc) continue;

        HMODULE mods[512] = {};
        DWORD cb = 0;
        if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL))
        {
            DWORD count = cb / sizeof(HMODULE);
            for (DWORD i = 0; i < count && !violation; ++i)
            {
                wchar_t mod_path[MAX_PATH] = {};
                if (GetModuleFileNameExW(hProc, mods[i], mod_path, MAX_PATH) == 0)
                    continue;
                if (_wcsicmp(mod_path, my_exe) == 0)
                    violation = true;
            }
        }
        CloseHandle(hProc);
    }
    CloseHandle(snap);
    return violation;
}

inline bool scan_window_titles(std::string& found_title)
{
    struct enum_ctx
    {
        bool found;
        std::string title;
        DWORD my_pid;
    } ctx{false, "", GetCurrentProcessId()};

    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<enum_ctx*>(lp);

        DWORD wnd_pid = 0;
        GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid == c->my_pid) return TRUE;

        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, 256) == 0) return TRUE;

        wchar_t lower[256] = {};
        for (int i = 0; i < 255 && title[i]; ++i)
            lower[i] = towlower(title[i]);

        bool has_re_context = wcsstr(lower, L"disassembl") || wcsstr(lower, L"debugg")
            || wcsstr(lower, L"decompil") || wcsstr(lower, L"hex editor")
            || wcsstr(lower, L"memory view") || wcsstr(lower, L"breakpoint")
            || wcsstr(lower, L"x64dbg") || wcsstr(lower, L"ida ")
            || wcsstr(lower, L"ghidra") || wcsstr(lower, L"ollydbg")
            || wcsstr(lower, L"cheat engine")
            || wcsstr(lower, L"reclass");

        if (!has_re_context) return TRUE;

        bool targets_aida = wcsstr(lower, L"aida") || wcsstr(lower, L"arc.dll")
            || wcsstr(lower, L"aidastan");

        if (!targets_aida) return TRUE;

        char narrow[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, title, -1, narrow, 256, nullptr, nullptr);
        c->title = narrow;
        c->found = true;
        return FALSE;

    }, reinterpret_cast<LPARAM>(&ctx));

    found_title = ctx.title;
    return ctx.found;
}

inline bool check_injected_dlls(std::string& dll_name)
{
    HMODULE mods[512] = {};
    DWORD cb = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &cb, LIST_MODULES_ALL))
        return false;

    wchar_t sys_dir[MAX_PATH] = {};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    wchar_t win_dir[MAX_PATH] = {};
    GetWindowsDirectoryW(win_dir, MAX_PATH);
    wchar_t prog_files[MAX_PATH] = {};
    GetEnvironmentVariableW(L"ProgramFiles", prog_files, MAX_PATH);
    wchar_t prog_files_x86[MAX_PATH] = {};
    GetEnvironmentVariableW(L"ProgramFiles(x86)", prog_files_x86, MAX_PATH);
    wchar_t our_dir[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, our_dir, MAX_PATH);
    for (int i = static_cast<int>(wcslen(our_dir)) - 1; i >= 0; --i)
    {
        if (our_dir[i] == L'\\' || our_dir[i] == L'/')
        {
            our_dir[i] = 0;
            break;
        }
    }

    DWORD count = cb / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i)
    {
        wchar_t mod_path[MAX_PATH] = {};
        if (GetModuleFileNameExW(GetCurrentProcess(), mods[i], mod_path, MAX_PATH) == 0)
            continue;

        wchar_t lower_path[MAX_PATH] = {};
        for (int j = 0; j < MAX_PATH - 1 && mod_path[j]; ++j)
            lower_path[j] = towlower(mod_path[j]);

        bool known_location = false;
        if (wcsstr(lower_path, L"\\windows\\")
            || wcsstr(lower_path, L"\\program files\\")
            || wcsstr(lower_path, L"\\program files (x86)\\"))
        {
            known_location = true;
        }

        wchar_t lower_our[MAX_PATH] = {};
        for (int j = 0; j < MAX_PATH - 1 && our_dir[j]; ++j)
            lower_our[j] = towlower(our_dir[j]);

        if (wcsstr(lower_path, lower_our))
            known_location = true;

        if (wcsstr(lower_path, L"\\microsoft.net\\")
            || wcsstr(lower_path, L"\\winsxs\\")
            || wcsstr(lower_path, L"\\nvidia")
            || wcsstr(lower_path, L"\\amd\\")
            || wcsstr(lower_path, L"\\intel\\"))
        {
            known_location = true;
        }

        if (!known_location)
        {
            char narrow[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, mod_path, -1, narrow, MAX_PATH, nullptr, nullptr);
            dll_name = narrow;
            return true;
        }
    }
    return false;
}

inline bool verify_system_dll_paths()
{
    struct dll_check { const wchar_t* name; const wchar_t* expected_dir; };

    wchar_t sys_dir[MAX_PATH] = {};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    size_t sys_len = wcslen(sys_dir);

    const wchar_t* critical_dlls[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
    };

    for (const auto& dll : critical_dlls)
    {
        HMODULE mod = GetModuleHandleW(dll);
        if (!mod) continue;

        wchar_t path[MAX_PATH] = {};
        if (GetModuleFileNameW(mod, path, MAX_PATH) == 0) continue;

        wchar_t lower[MAX_PATH] = {};
        for (int i = 0; i < MAX_PATH - 1 && path[i]; ++i)
            lower[i] = towlower(path[i]);

        wchar_t lower_sys[MAX_PATH] = {};
        for (size_t i = 0; i < sys_len && i < MAX_PATH - 1; ++i)
            lower_sys[i] = towlower(sys_dir[i]);

        if (wcsncmp(lower, lower_sys, sys_len) != 0)
            return false;
    }
    return true;
}

inline scan_report_t full_scan()
{
    scan_report_t report{};

    report.re_tool_with_binary = scan_re_tools_with_binary();
    if (report.re_tool_with_binary)
    {
        report.detail += "re_tool_binary ";
        webhook::send_debug_log("re_tool_scan", "tool_loaded_our_binary", true);
    }

    std::string title;
    report.suspicious_window_title = scan_window_titles(title);
    if (report.suspicious_window_title)
    {
        report.detail += "window:" + title + " ";
        webhook::send_debug_log("window_scan", "suspicious_title: " + title, false);
    }

    std::string dll;
    report.injected_dll = check_injected_dlls(dll);
    if (report.injected_dll)
    {
        report.detail += "dll:" + dll + " ";
        webhook::send_debug_log("dll_inject", "unknown_dll: " + dll, true);
    }

    report.sideloaded_system_dll = !verify_system_dll_paths();
    if (report.sideloaded_system_dll)
    {
        report.detail += "sideloaded_sysdll ";
        webhook::send_debug_log("dll_sideload", "system_dll_wrong_path", true);
    }

    return report;
}

}
}
