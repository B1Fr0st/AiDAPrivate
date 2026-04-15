#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../../obfuscation.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace standalone_anti_ai
{

namespace detail
{

    inline void to_lower_w(const wchar_t* src, wchar_t* dst, size_t max_len)
    {
        for (size_t i = 0; i < max_len - 1 && src[i]; ++i)
            dst[i] = towlower(src[i]);
    }

    inline bool contains_w(const wchar_t* haystack, const wchar_t* needle)
    {
        return wcsstr(haystack, needle) != nullptr;
    }

    inline bool ends_with_w(const wchar_t* str, const wchar_t* suffix)
    {
        size_t str_len = wcslen(str);
        size_t suffix_len = wcslen(suffix);
        if (suffix_len > str_len) return false;
        return _wcsicmp(str + str_len - suffix_len, suffix) == 0;
    }

}


namespace mcp_detect
{

    struct mcp_indicator_t
    {
        bool named_pipe_found;
        bool mcp_process_found;
        bool mcp_port_active;
        bool websocket_bridge;
        std::string detail;
    };

    inline bool scan_named_pipes()
    {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
        if (h == INVALID_HANDLE_VALUE) return false;

        bool found = false;
        do
        {
            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(fd.cFileName, lower, MAX_PATH);

            if (detail::contains_w(lower, L"mcp")
                || detail::contains_w(lower, L"model-context")
                || detail::contains_w(lower, L"claude-bridge")
                || detail::contains_w(lower, L"anthropic")
                || detail::contains_w(lower, L"openai-bridge")
                || detail::contains_w(lower, L"copilot-mcp")
                || detail::contains_w(lower, L"cursor-mcp")
                || detail::contains_w(lower, L"windsurf-mcp")
                || detail::contains_w(lower, L"aider-mcp")
                || detail::contains_w(lower, L"cline-mcp")
                || detail::contains_w(lower, L"roo-mcp")
                || detail::contains_w(lower, L"llm-bridge")
                || detail::contains_w(lower, L"ai-agent")
                || detail::contains_w(lower, L"json-rpc-driver")
                || detail::contains_w(lower, L"tool-server"))
            {
                found = true;
                break;
            }
        }
        while (FindNextFileW(h, &fd));

        FindClose(h);
        return found;
    }

    inline bool scan_mcp_processes()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        DWORD my_pid = GetCurrentProcessId();
        bool found = false;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0)
                continue;

            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(pe.szExeFile, lower, MAX_PATH);

            bool is_host = false;
            if (detail::contains_w(lower, L"node.exe")
                || detail::contains_w(lower, L"python.exe")
                || detail::contains_w(lower, L"python3")
                || detail::contains_w(lower, L"pythonw.exe")
                || detail::contains_w(lower, L"bun.exe")
                || detail::contains_w(lower, L"deno.exe"))
            {
                is_host = true;
            }

            if (!is_host) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            wchar_t cmdline_path[MAX_PATH] = {};
            DWORD path_size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, cmdline_path, &path_size))
            {
                wchar_t lower_path[MAX_PATH] = {};
                detail::to_lower_w(cmdline_path, lower_path, MAX_PATH);

                if (detail::contains_w(lower_path, L"mcp")
                    || detail::contains_w(lower_path, L"model-context")
                    || detail::contains_w(lower_path, L"claude")
                    || detail::contains_w(lower_path, L"anthropic"))
                {
                    found = true;
                }
            }

            CloseHandle(hProc);
        }

        CloseHandle(snap);
        return found;
    }

    inline bool scan_mcp_ports()
    {
        DWORD tcp_table_size = 0;
        GetExtendedTcpTable(nullptr, &tcp_table_size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0);

        if (tcp_table_size == 0) return false;

        auto* table = static_cast<MIB_TCPTABLE_OWNER_PID*>(malloc(tcp_table_size));
        if (!table) return false;

        bool found = false;

        if (GetExtendedTcpTable(table, &tcp_table_size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            DWORD my_pid = GetCurrentProcessId();

            for (DWORD i = 0; i < table->dwNumEntries && !found; ++i)
            {
                auto& row = table->table[i];
                if (row.dwOwningPid == my_pid) continue;

                uint16_t local_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));

                if (local_port == 3000 || local_port == 3001 || local_port == 3100
                    || local_port == 8080 || local_port == 8765 || local_port == 5173
                    || local_port == 4000 || local_port == 4001)
                {
                    if (row.dwState == MIB_TCP_STATE_LISTEN
                        || row.dwState == MIB_TCP_STATE_ESTAB)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                            FALSE, row.dwOwningPid);
                        if (hProc)
                        {
                            wchar_t img_path[MAX_PATH] = {};
                            DWORD sz = MAX_PATH;
                            if (QueryFullProcessImageNameW(hProc, 0, img_path, &sz))
                            {
                                wchar_t lower_path[MAX_PATH] = {};
                                detail::to_lower_w(img_path, lower_path, MAX_PATH);
                                if (detail::contains_w(lower_path, L"node")
                                    || detail::contains_w(lower_path, L"python")
                                    || detail::contains_w(lower_path, L"deno")
                                    || detail::contains_w(lower_path, L"bun"))
                                {
                                    found = true;
                                }
                            }
                            CloseHandle(hProc);
                        }
                    }
                }
            }
        }

        free(table);
        return found;
    }

    inline mcp_indicator_t full_scan()
    {
        mcp_indicator_t result{};
        result.named_pipe_found = scan_named_pipes();
        result.mcp_process_found = scan_mcp_processes();
        result.mcp_port_active = scan_mcp_ports();

        if (result.named_pipe_found) result.detail += "named_pipe ";
        if (result.mcp_process_found) result.detail += "mcp_proc ";
        if (result.mcp_port_active) result.detail += "mcp_port ";

        return result;
    }

}


namespace llm_detect
{

    struct llm_indicator_t
    {
        bool inference_engine_found;
        bool gpu_inference_active;
        bool model_files_loaded;
        std::string engine_name;
    };

    inline bool scan_llm_processes()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        DWORD my_pid = GetCurrentProcessId();
        bool found = false;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0)
                continue;

            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(pe.szExeFile, lower, MAX_PATH);

            if (detail::contains_w(lower, L"ollama")
                || detail::contains_w(lower, L"llama-server")
                || detail::contains_w(lower, L"llama-cli")
                || detail::contains_w(lower, L"llama.cpp")
                || detail::contains_w(lower, L"llamafile")
                || detail::contains_w(lower, L"koboldcpp")
                || detail::contains_w(lower, L"text-generation")
                || detail::contains_w(lower, L"vllm")
                || detail::contains_w(lower, L"localai")
                || detail::contains_w(lower, L"lm-studio")
                || detail::contains_w(lower, L"lmstudio")
                || detail::contains_w(lower, L"jan.exe")
                || detail::contains_w(lower, L"gpt4all")
                || detail::contains_w(lower, L"oobabooga")
                || detail::contains_w(lower, L"tabbyapi")
                || detail::contains_w(lower, L"exllama")
                || detail::contains_w(lower, L"mlc-chat")
                || detail::contains_w(lower, L"mlc_llm")
                || detail::contains_w(lower, L"tgi-server")
                || detail::contains_w(lower, L"chatd")
                || detail::contains_w(lower, L"privateGPT")
                || detail::contains_w(lower, L"privategpt"))
            {
                found = true;
            }
        }

        CloseHandle(snap);
        return found;
    }

    inline bool scan_ollama_api()
    {
        DWORD tcp_table_size = 0;
        GetExtendedTcpTable(nullptr, &tcp_table_size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0);
        if (tcp_table_size == 0) return false;

        auto* table = static_cast<MIB_TCPTABLE_OWNER_PID*>(malloc(tcp_table_size));
        if (!table) return false;

        bool found = false;
        if (GetExtendedTcpTable(table, &tcp_table_size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < table->dwNumEntries && !found; ++i)
            {
                uint16_t port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));
                if (port == 11434 || port == 11435)
                {
                    if (table->table[i].dwState == MIB_TCP_STATE_LISTEN)
                        found = true;
                }
            }
        }

        free(table);
        return found;
    }

    inline llm_indicator_t full_scan()
    {
        llm_indicator_t result{};
        result.inference_engine_found = scan_llm_processes();
        result.gpu_inference_active = scan_ollama_api();
        result.model_files_loaded = false;

        if (result.inference_engine_found) result.engine_name = "local_llm_engine";
        if (result.gpu_inference_active) result.engine_name += " ollama_api";

        return result;
    }

}


namespace ai_tool_detect
{

    inline bool scan_ai_coding_tools()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        DWORD my_pid = GetCurrentProcessId();
        bool found = false;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0)
                continue;

            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(pe.szExeFile, lower, MAX_PATH);

            if (detail::contains_w(lower, L"cursor.exe")
                || detail::contains_w(lower, L"windsurf")
                || detail::contains_w(lower, L"aider")
                || detail::contains_w(lower, L"continue.exe")
                || detail::contains_w(lower, L"cline")
                || detail::contains_w(lower, L"roo-cline")
                || detail::contains_w(lower, L"claude")
                || detail::contains_w(lower, L"codegen")
                || detail::contains_w(lower, L"devin"))
            {
                found = true;
            }
        }

        CloseHandle(snap);
        return found;
    }

    inline bool scan_clipboard_monitoring()
    {
        HWND viewer = GetClipboardViewer();
        if (viewer == nullptr) return false;

        DWORD viewer_pid = 0;
        GetWindowThreadProcessId(viewer, &viewer_pid);
        if (viewer_pid == 0 || viewer_pid == GetCurrentProcessId())
            return false;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, viewer_pid);
        if (!hProc) return false;

        wchar_t path[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        bool suspicious = false;

        if (QueryFullProcessImageNameW(hProc, 0, path, &sz))
        {
            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(path, lower, MAX_PATH);

            if (detail::contains_w(lower, L"python")
                || detail::contains_w(lower, L"node")
                || detail::contains_w(lower, L"cursor")
                || detail::contains_w(lower, L"claude"))
            {
                suspicious = true;
            }
        }

        CloseHandle(hProc);
        return suspicious;
    }

}


namespace self_analysis
{

    inline bool detect_memory_scanners()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        DWORD my_pid = GetCurrentProcessId();
        bool found = false;

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        for (BOOL ok = Process32FirstW(snap, &pe); ok && !found;
             ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == my_pid || pe.th32ProcessID == 0)
                continue;

            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(pe.szExeFile, lower, MAX_PATH);

            if (detail::contains_w(lower, L"cheatengine")
                || detail::contains_w(lower, L"ce.exe")
                || detail::contains_w(lower, L"processhacker")
                || detail::contains_w(lower, L"systeminformer")
                || detail::contains_w(lower, L"processhacker")
                || detail::contains_w(lower, L"apimonitor")
                || detail::contains_w(lower, L"procmon")
                || detail::contains_w(lower, L"procexp")
                || detail::contains_w(lower, L"hmpalert")
                || detail::contains_w(lower, L"scylla")
                || detail::contains_w(lower, L"importrec")
                || detail::contains_w(lower, L"pe-bear")
                || detail::contains_w(lower, L"pe-sieve")
                || detail::contains_w(lower, L"pebear")
                || detail::contains_w(lower, L"hollowshunter"))
            {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE, pe.th32ProcessID);
                if (hProc)
                {
                    found = true;
                    CloseHandle(hProc);
                }
            }
        }

        CloseHandle(snap);
        return found;
    }

    inline bool detect_handle_to_us()
    {
        using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto pQuery = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        if (!pQuery) return false;

        DWORD my_pid = GetCurrentProcessId();

        ULONG buf_size = 1 << 20;
        auto* buf = static_cast<uint8_t*>(malloc(buf_size));
        if (!buf) return false;

        NTSTATUS st = pQuery(16, buf, buf_size, &buf_size);
        if (st == 0xC0000004)
        {
            free(buf);
            buf = static_cast<uint8_t*>(malloc(buf_size));
            if (!buf) return false;
            st = pQuery(16, buf, buf_size, &buf_size);
        }

        bool found = false;
        if (st >= 0)
        {
            struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
            {
                USHORT UniqueProcessId;
                USHORT CreatorBackTraceIndex;
                UCHAR ObjectTypeIndex;
                UCHAR HandleAttributes;
                USHORT HandleValue;
                PVOID Object;
                ULONG GrantedAccess;
            };

            struct SYSTEM_HANDLE_INFORMATION
            {
                ULONG NumberOfHandles;
                SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
            };

            auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buf);
            for (ULONG i = 0; i < info->NumberOfHandles && !found; ++i)
            {
                auto& h = info->Handles[i];
                if (h.UniqueProcessId == my_pid) continue;

                if (h.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
                {
                    HANDLE foreign_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE, h.UniqueProcessId);
                    if (foreign_proc)
                    {
                        HANDLE dup_handle = nullptr;
                        HANDLE source = OpenProcess(PROCESS_DUP_HANDLE, FALSE, h.UniqueProcessId);
                        if (source)
                        {
                            if (DuplicateHandle(source,
                                reinterpret_cast<HANDLE>(static_cast<uintptr_t>(h.HandleValue)),
                                GetCurrentProcess(), &dup_handle,
                                0, FALSE, DUPLICATE_SAME_ACCESS))
                            {
                                if (GetProcessId(dup_handle) == my_pid)
                                {
                                    found = true;
                                }
                                CloseHandle(dup_handle);
                            }
                            CloseHandle(source);
                        }
                        CloseHandle(foreign_proc);
                    }
                }
            }
        }

        free(buf);
        return found;
    }

    inline bool detect_window_hooks()
    {
        HWND our_window = FindWindowW(L"AiDAStandaloneWindow", nullptr);
        if (!our_window) return false;

        DWORD our_pid = GetCurrentProcessId();
        DWORD wnd_thread = GetWindowThreadProcessId(our_window, nullptr);
        if (wnd_thread == 0) return false;

        HHOOK test_hook = SetWindowsHookExW(WH_CALLWNDPROC, nullptr, nullptr, wnd_thread);
        if (test_hook)
        {
            UnhookWindowsHookEx(test_hook);
        }

        return false;
    }

}


namespace combined
{

    struct threat_report_t
    {
        bool mcp_detected;
        bool llm_detected;
        bool ai_tool_detected;
        bool memory_scanner_detected;
        bool handle_to_us_detected;
        bool clipboard_monitored;
        std::string summary;

        bool any_threat() const
        {
            return mcp_detected || llm_detected || memory_scanner_detected
                || handle_to_us_detected;
        }

        bool ai_threat() const
        {
            return mcp_detected || llm_detected || ai_tool_detected;
        }
    };

    inline threat_report_t full_scan()
    {
        threat_report_t report{};

        auto mcp = mcp_detect::full_scan();
        report.mcp_detected = mcp.named_pipe_found || mcp.mcp_process_found;

        auto llm = llm_detect::full_scan();
        report.llm_detected = llm.inference_engine_found || llm.gpu_inference_active;

        report.ai_tool_detected = ai_tool_detect::scan_ai_coding_tools();
        report.memory_scanner_detected = self_analysis::detect_memory_scanners();
        report.handle_to_us_detected = self_analysis::detect_handle_to_us();
        report.clipboard_monitored = ai_tool_detect::scan_clipboard_monitoring();

        if (report.mcp_detected) report.summary += "MCP_BRIDGE ";
        if (report.llm_detected) report.summary += "LOCAL_LLM ";
        if (report.ai_tool_detected) report.summary += "AI_TOOL ";
        if (report.memory_scanner_detected) report.summary += "MEM_SCANNER ";
        if (report.handle_to_us_detected) report.summary += "HANDLE_LEAK ";
        if (report.clipboard_monitored) report.summary += "CLIP_MON ";

        return report;
    }

}

}
