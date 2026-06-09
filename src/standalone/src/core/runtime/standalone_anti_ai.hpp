#pragma once

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "obfuscation.hpp"
#include "../../helpers/diag_log.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace standalone_anti_ai
{

enum category_bits : uint32_t
{
    category_mcp_pipe              = 1u << 0,
    category_mcp_process           = 1u << 1,
    category_mcp_port              = 1u << 2,
    category_mcp_command_server    = 1u << 3,
    category_ai_coding_tool        = 1u << 4,
    category_local_llm             = 1u << 5,
    category_memory_scanner        = 1u << 6,
    category_re_tool               = 1u << 7,
    category_debugger_tool         = 1u << 8,
    category_dump_tool             = 1u << 9,
    category_foreign_read_handle   = 1u << 10,
    category_foreign_write_handle  = 1u << 11,
    category_foreign_vm_operation  = 1u << 12,
    category_foreign_create_thread = 1u << 13,
    category_clipboard_monitor     = 1u << 14,
    category_targets_aida          = 1u << 15,
    category_offensive_mcp_tool    = 1u << 16
};

namespace detail
{

    inline wchar_t lower_ch(wchar_t ch)
    {
        return static_cast<wchar_t>(std::towlower(ch));
    }

    inline void to_lower_w(const wchar_t* src, wchar_t* dst, size_t max_len)
    {
        if (!dst || max_len == 0)
            return;
        size_t i = 0;
        if (src)
        {
            for (; i + 1 < max_len && src[i]; ++i)
                dst[i] = lower_ch(src[i]);
        }
        dst[i] = 0;
    }

    inline std::wstring lower_copy(const wchar_t* src)
    {
        std::wstring out;
        if (!src)
            return out;
        for (const wchar_t* p = src; *p; ++p)
            out.push_back(lower_ch(*p));
        return out;
    }

    inline std::wstring lower_copy(const std::wstring& src)
    {
        std::wstring out;
        out.reserve(src.size());
        for (wchar_t ch : src)
            out.push_back(lower_ch(ch));
        return out;
    }

    inline bool contains_w(const wchar_t* haystack, const wchar_t* needle)
    {
        return haystack && needle && wcsstr(haystack, needle) != nullptr;
    }

    inline bool contains_w(const std::wstring& haystack, const wchar_t* needle)
    {
        return needle && haystack.find(needle) != std::wstring::npos;
    }

    inline std::wstring fold_metadata_w(const std::wstring& src, bool compact)
    {
        std::wstring out;
        out.reserve(src.size());
        bool last_space = true;
        for (wchar_t ch : src)
        {
            wchar_t lower = lower_ch(ch);
            const bool keep = (lower >= L'a' && lower <= L'z') || (lower >= L'0' && lower <= L'9');
            if (keep)
            {
                out.push_back(lower);
                last_space = false;
            }
            else if (!compact && !last_space)
            {
                out.push_back(L' ');
                last_space = true;
            }
        }
        if (!compact && !out.empty() && out.back() == L' ')
            out.pop_back();
        return out;
    }

    inline bool folded_contains_token_w(const std::wstring& folded, const wchar_t* token)
    {
        if (!token || !*token)
            return false;
        std::wstring needle = fold_metadata_w(token, false);
        if (needle.empty())
            return false;
        return folded.find(needle) != std::wstring::npos;
    }

    inline bool compact_contains_token_w(const std::wstring& compacted, const wchar_t* token)
    {
        if (!token || !*token)
            return false;
        std::wstring needle = fold_metadata_w(token, true);
        if (needle.empty())
            return false;
        return compacted.find(needle) != std::wstring::npos;
    }

    inline bool contains_offensive_mcp_tool_text(const std::wstring& text)
    {
        if (text.empty())
            return false;
        static const wchar_t* const tokens[] = {
            L"frida", L"x64dbg", L"x32dbg", L"windbg", L"cdb", L"kd debugger",
            L"ida pro", L"hex rays", L"ghidra", L"binary ninja", L"radare",
            L"rizin", L"dnspy", L"ilspy", L"cheat engine", L"process hacker",
            L"system informer", L"scylla", L"pe sieve", L"hollows hunter",
            L"openprocess", L"readprocessmemory", L"writeprocessmemory",
            L"virtualprotectex", L"createremotethread", L"debugactiveprocess",
            L"sedebugprivilege", L"process memory", L"read process memory",
            L"write process memory", L"virtual memory", L"dump process",
            L"process dump", L"minidump", L"dump memory", L"memory dump",
            L"memory scanner", L"memory scan", L"scan memory", L"attach debugger",
            L"debug process", L"inject dll", L"dll injection", L"remote thread",
            L"hook function", L"patch bytes", L"patch memory", L"disassemble process",
            L"decompile process", L"execute command", L"run command", L"shell command",
            L"powershell", L"cmd exe", L"terminal command", L"keylogger",
            L"credential dump", L"lsass dump", L"mimikatz", L"packet capture",
            L"mitm", L"proxy intercept"
        };
        const std::wstring folded = fold_metadata_w(text, false);
        const std::wstring compacted = fold_metadata_w(text, true);
        for (const wchar_t* token : tokens)
        {
            if (folded_contains_token_w(folded, token) || compact_contains_token_w(compacted, token))
                return true;
        }
        return false;
    }

    inline bool equals_w(const wchar_t* lhs, const wchar_t* rhs)
    {
        return lhs && rhs && wcscmp(lhs, rhs) == 0;
    }

    template <size_t N>
    inline bool contains_any_w(const wchar_t* value, const wchar_t* const (&needles)[N])
    {
        if (!value)
            return false;
        for (size_t i = 0; i < N; ++i)
        {
            if (contains_w(value, needles[i]))
                return true;
        }
        return false;
    }

    template <size_t N>
    inline bool contains_any_w(const std::wstring& value, const wchar_t* const (&needles)[N])
    {
        for (size_t i = 0; i < N; ++i)
        {
            if (contains_w(value, needles[i]))
                return true;
        }
        return false;
    }

    template <size_t N>
    inline bool equals_any_w(const wchar_t* value, const wchar_t* const (&needles)[N])
    {
        if (!value)
            return false;
        for (size_t i = 0; i < N; ++i)
        {
            if (equals_w(value, needles[i]))
                return true;
        }
        return false;
    }

    inline bool path_has_dir_prefix_w(const std::wstring& path, const std::wstring& dir)
    {
        if (path.empty() || dir.empty())
            return false;
        size_t n = dir.size();
        while (n > 0 && (dir[n - 1] == L'\\' || dir[n - 1] == L'/'))
            --n;
        if (path.size() <= n)
            return false;
        if (path.compare(0, n, dir, 0, n) != 0)
            return false;
        return path[n] == L'\\' || path[n] == L'/';
    }

    inline std::wstring trim_w(const std::wstring& value)
    {
        size_t first = 0;
        while (first < value.size() && std::iswspace(value[first]))
            ++first;
        size_t last = value.size();
        while (last > first && std::iswspace(value[last - 1]))
            --last;
        return value.substr(first, last - first);
    }

    inline bool ends_with_w(const std::wstring& value, const std::wstring& suffix)
    {
        if (suffix.size() > value.size())
            return false;
        return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    inline std::wstring canonical_path_lower_w(const std::wstring& path)
    {
        if (path.empty())
            return {};
        DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        std::wstring out;
        if (needed > 0 && needed < 32768)
        {
            out.resize(needed + 1);
            DWORD got = GetFullPathNameW(path.c_str(), static_cast<DWORD>(out.size()), out.data(), nullptr);
            if (got > 0 && got < out.size())
                out.resize(got);
            else
                out = path;
        }
        else
        {
            out = path;
        }
        out = lower_copy(out.c_str());
        if (out.rfind(L"\\??\\", 0) == 0 || out.rfind(L"\\\\?\\", 0) == 0)
            out.erase(0, 4);
        for (wchar_t& ch : out)
        {
            if (ch == L'/')
                ch = L'\\';
        }
        while (out.size() > 3 && out.back() == L'\\')
            out.pop_back();
        return out;
    }

    inline std::wstring current_module_dir_lower_w()
    {
        wchar_t buf[32768] = {};
        DWORD got = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])));
        if (got == 0 || got >= static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])))
            return {};
        std::wstring path = canonical_path_lower_w(std::wstring(buf, got));
        size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
            return {};
        return path.substr(0, slash);
    }

    inline bool path_under_current_module_subdir_w(const std::wstring& path, const wchar_t* subdir)
    {
        if (!subdir || !*subdir)
            return false;
        std::wstring module_dir = current_module_dir_lower_w();
        if (module_dir.empty())
            return false;
        std::wstring root = module_dir;
        if (!root.empty() && root.back() != L'\\')
            root.push_back(L'\\');
        root.append(subdir);
        return path_has_dir_prefix_w(canonical_path_lower_w(path), canonical_path_lower_w(root));
    }

    inline const wchar_t* basename_ptr(const wchar_t* path)
    {
        if (!path)
            return L"";
        const wchar_t* slash1 = wcsrchr(path, L'\\');
        const wchar_t* slash2 = wcsrchr(path, L'/');
        const wchar_t* slash = slash1;
        if (!slash || (slash2 && slash2 > slash))
            slash = slash2;
        return slash ? slash + 1 : path;
    }

    inline std::string wide_to_utf8_lossy(const std::wstring& value)
    {
        if (value.empty())
            return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return {};
        std::string out(static_cast<size_t>(needed), '\0');
        int written = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
        if (written <= 0)
            return {};
        out.resize(static_cast<size_t>(written));
        for (char& ch : out)
        {
            if (ch == '\r' || ch == '\n' || ch == '\t')
                ch = ' ';
        }
        return out;
    }

    inline bool trusted_windows_core_basename_w(const std::wstring& exe_lower)
    {
        static const wchar_t* const core_images[] = {
            L"lsass.exe",
            L"csrss.exe",
            L"wininit.exe",
            L"services.exe",
            L"winlogon.exe",
            L"smss.exe"
        };
        return equals_any_w(exe_lower.c_str(), core_images);
    }

    inline uint64_t fnv1a64_bytes(const void* data, size_t len)
    {
        const auto* p = static_cast<const uint8_t*>(data);
        uint64_t h = 1469598103934665603ull;
        for (size_t i = 0; i < len; ++i)
        {
            h ^= p[i];
            h *= 1099511628211ull;
        }
        return h;
    }

    inline uint64_t hash_string(const std::string& value)
    {
        return fnv1a64_bytes(value.data(), value.size());
    }

    inline uint64_t hash_wide_lower(const wchar_t* value)
    {
        uint64_t h = 1469598103934665603ull;
        if (!value)
            return h;
        for (const wchar_t* p = value; *p; ++p)
        {
            wchar_t ch = lower_ch(*p);
            h ^= static_cast<uint8_t>(ch & 0xFFu);
            h *= 1099511628211ull;
            h ^= static_cast<uint8_t>((ch >> 8) & 0xFFu);
            h *= 1099511628211ull;
        }
        return h;
    }

    inline uint64_t basename_hash_w(const wchar_t* value)
    {
        return hash_wide_lower(basename_ptr(value));
    }

    inline uint64_t mix_hash(uint64_t seed, uint64_t value)
    {
        seed ^= value + 0x9E3779B97F4A7C15ull + (seed << 6) + (seed >> 2);
        return seed;
    }

    inline uint32_t popcount32(uint32_t value)
    {
        uint32_t count = 0;
        while (value)
        {
            value &= value - 1u;
            ++count;
        }
        return count;
    }

    inline void append_token(std::string& out, const char* token)
    {
        if (!token || !*token)
            return;
        if (!out.empty())
            out.push_back(' ');
        out += token;
    }

    inline void append_hex_token(std::string& out, const char* key, uint64_t value)
    {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s=0x%016llX", key, static_cast<unsigned long long>(value));
        append_token(out, buf);
    }

    inline std::wstring query_process_command_line(HANDLE process)
    {
        using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto* ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return {};
        auto* query = reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!query)
            return {};
        ULONG needed = 0;
        constexpr ULONG kProcessCommandLineInformation = 60;
        NTSTATUS st = query(process, kProcessCommandLineInformation, nullptr, 0, &needed);
        if (needed == 0 || needed > 65536)
            needed = 32768;
        std::vector<uint8_t> buf(static_cast<size_t>(needed) + sizeof(wchar_t) * 2u);
        st = query(process, kProcessCommandLineInformation, buf.data(), static_cast<ULONG>(buf.size()), &needed);
        if (st < 0 || buf.size() < sizeof(USHORT) * 2u + sizeof(PWSTR))
            return {};
        struct local_unicode_string_t
        {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR Buffer;
        };
        auto* us = reinterpret_cast<local_unicode_string_t*>(buf.data());
        if (!us->Buffer || us->Length == 0 || us->Length > 32768)
            return {};
        uintptr_t base = reinterpret_cast<uintptr_t>(buf.data());
        uintptr_t end = base + buf.size();
        uintptr_t ptr = reinterpret_cast<uintptr_t>(us->Buffer);
        if (ptr < base || ptr + us->Length > end)
            return {};
        return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
    }

    struct process_probe_t
    {
        DWORD pid = 0;
        DWORD parent_pid = 0;
        std::wstring exe_lower;
        std::wstring image_lower;
        std::wstring command_lower;
        uint64_t basename_hash = 0;
        bool query_ok = false;
    };

    inline std::string probe_image_for_log(const process_probe_t* probe)
    {
        if (!probe)
            return {};
        if (!probe->exe_lower.empty())
            return wide_to_utf8_lossy(probe->exe_lower);
        if (!probe->image_lower.empty())
            return wide_to_utf8_lossy(basename_ptr(probe->image_lower.c_str()));
        return {};
    }

    inline std::string probe_path_for_log(const process_probe_t* probe)
    {
        if (!probe || probe->image_lower.empty())
            return {};
        return wide_to_utf8_lossy(probe->image_lower);
    }

    inline bool trusted_windows_system_process(const process_probe_t& probe)
    {
        static const wchar_t* const core_images[] = {
            L"lsass.exe",
            L"csrss.exe",
            L"wininit.exe",
            L"services.exe",
            L"winlogon.exe",
            L"smss.exe"
        };
        if (!equals_any_w(probe.exe_lower.c_str(), core_images))
            return false;
        wchar_t system_dir[MAX_PATH] = {};
        UINT system_len = GetSystemDirectoryW(system_dir, MAX_PATH);
        if (system_len == 0 || system_len >= MAX_PATH)
            return false;
        return path_has_dir_prefix_w(probe.image_lower, lower_copy(system_dir));
    }

    inline bool trusted_kernel_system_owner(DWORD owner_pid)
    {
        return owner_pid == 4;
    }

    inline bool passive_system_handle_access(DWORD access)
    {
        constexpr DWORD active_mutation =
            PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_SET_INFORMATION |
            PROCESS_SUSPEND_RESUME;
        return (access & active_mutation) == 0;
    }

    inline std::string format_process_handle_access_flags(DWORD access)
    {
        std::string flags;
        auto add = [&flags](const char* name) {
            if (!flags.empty())
                flags += "|";
            flags += name;
        };
        if (access & PROCESS_TERMINATE) add("terminate");
        if (access & PROCESS_CREATE_THREAD) add("create_thread");
        if (access & PROCESS_VM_OPERATION) add("vm_operation");
        if (access & PROCESS_VM_READ) add("vm_read");
        if (access & PROCESS_VM_WRITE) add("vm_write");
        if (access & PROCESS_DUP_HANDLE) add("dup_handle");
        if (access & PROCESS_SET_INFORMATION) add("set_information");
        if (access & PROCESS_QUERY_INFORMATION) add("query_information");
        if (access & PROCESS_SUSPEND_RESUME) add("suspend_resume");
        if (access & PROCESS_QUERY_LIMITED_INFORMATION) add("query_limited");
        return flags.empty() ? "none" : flags;
    }

    inline std::vector<process_probe_t> collect_processes()
    {
        std::vector<process_probe_t> result;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return result;
        DWORD self_pid = GetCurrentProcessId();
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == self_pid || pe.th32ProcessID == 0)
                continue;
            process_probe_t probe{};
            probe.pid = pe.th32ProcessID;
            probe.parent_pid = pe.th32ParentProcessID;
            probe.exe_lower = lower_copy(pe.szExeFile);
            probe.basename_hash = basename_hash_w(probe.exe_lower.c_str());
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (process)
            {
                wchar_t image_path[MAX_PATH] = {};
                DWORD path_size = MAX_PATH;
                if (QueryFullProcessImageNameW(process, 0, image_path, &path_size))
                {
                    probe.image_lower = lower_copy(image_path);
                    probe.basename_hash = basename_hash_w(image_path);
                }
                std::wstring command = query_process_command_line(process);
                if (!command.empty())
                    probe.command_lower = lower_copy(command);
                probe.query_ok = true;
                CloseHandle(process);
            }
            result.push_back(std::move(probe));
        }
        CloseHandle(snap);
        return result;
    }

    inline const process_probe_t* find_probe(const std::vector<process_probe_t>& probes, DWORD pid)
    {
        for (const auto& probe : probes)
        {
            if (probe.pid == pid)
                return &probe;
        }
        return nullptr;
    }

    inline bool probe_contains_any(const process_probe_t& probe, const wchar_t* const* needles, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            if (contains_w(probe.exe_lower, needles[i]) ||
                contains_w(probe.image_lower, needles[i]) ||
                contains_w(probe.command_lower, needles[i]))
            {
                return true;
            }
        }
        return false;
    }

    template <size_t N>
    inline bool probe_contains_any(const process_probe_t& probe, const wchar_t* const (&needles)[N])
    {
        return probe_contains_any(probe, needles, N);
    }

    inline bool probe_identity_contains_any(const process_probe_t& probe, const wchar_t* const* needles, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            if (contains_w(probe.exe_lower, needles[i]) ||
                contains_w(probe.image_lower, needles[i]))
            {
                return true;
            }
        }
        return false;
    }

    template <size_t N>
    inline bool probe_identity_contains_any(const process_probe_t& probe, const wchar_t* const (&needles)[N])
    {
        return probe_identity_contains_any(probe, needles, N);
    }

    template <size_t N>
    inline bool basename_equals_any(const process_probe_t& probe, const wchar_t* const (&needles)[N])
    {
        const wchar_t* exe_base = basename_ptr(probe.exe_lower.c_str());
        const wchar_t* image_base = basename_ptr(probe.image_lower.empty() ? probe.exe_lower.c_str() : probe.image_lower.c_str());
        return equals_any_w(exe_base, needles) || equals_any_w(image_base, needles);
    }

    inline bool is_shell_or_interpreter(const process_probe_t& probe)
    {
        static const wchar_t* const exact_names[] = {
            L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"bash.exe", L"wsl.exe",
            L"python.exe", L"pythonw.exe", L"python3.exe", L"node.exe", L"npm.exe",
            L"npx.exe", L"pnpm.exe", L"yarn.exe", L"bun.exe", L"deno.exe", L"uvx.exe",
            L"uv.exe", L"tsx.exe", L"ts-node.exe", L"docker.exe", L"dotnet.exe"
        };
        if (basename_equals_any(probe, exact_names))
            return true;
        static const wchar_t* const contains_names[] = {
            L"python3", L"nodejs", L"node-v", L"bun-v", L"deno-v"
        };
        return probe_contains_any(probe, contains_names);
    }

    inline bool has_mcp_command_evidence(const process_probe_t& probe)
    {
        static const wchar_t* const tokens[] = {
            L"mcp", L"model-context-protocol", L"modelcontextprotocol", L"mcp-server",
            L"server-mcp", L"stdio-mcp", L"claude mcp", L"codex mcp", L"tools/list",
            L"json-rpc", L"jsonrpc", L"tool-server", L"toolserver", L"cline-mcp",
            L"roo-mcp", L"cursor-mcp", L"windsurf-mcp", L"copilot-mcp", L"qwen-mcp",
            L"gemini-mcp", L"opencode-mcp", L"aider-mcp", L"mcp-stdio"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool has_offensive_mcp_tool_metadata_evidence(const process_probe_t& probe)
    {
        return contains_offensive_mcp_tool_text(probe.exe_lower) ||
            contains_offensive_mcp_tool_text(probe.image_lower) ||
            contains_offensive_mcp_tool_text(probe.command_lower);
    }

    inline bool has_aida_target_evidence(const process_probe_t& probe)
    {
        static const wchar_t* const explicit_target_tokens[] = {
            L"aidastandalone", L"aidastandalone.exe", L"aida.exe",
            L"aida_core", L"aida_core.dll", L"aida_plugin",
            L"aida_debug.log", L"aida_full_test.log", L"aida_kernel.log"
        };
        if (contains_any_w(probe.command_lower, explicit_target_tokens))
            return true;
        static const wchar_t* const broad_target_tokens[] = {
            L" aida ", L"\"aida\"", L"'aida'", L"=aida", L":aida"
        };
        if (!contains_any_w(probe.command_lower, broad_target_tokens))
            return false;
        static const wchar_t* const action_tokens[] = {
            L" attach", L" --pid", L" -pid", L" -p ", L" process",
            L" dump", L" read", L" write", L" memory", L" inject",
            L" debug", L" trace", L" hook", L" patch", L" scan",
            L" disassemble", L" decompile"
        };
        return contains_any_w(probe.command_lower, action_tokens);
    }

    inline bool command_has_camoufox_mcp_module(const std::wstring& command)
    {
        std::wstring folded;
        folded.reserve(command.size() + 2);
        folded.push_back(L' ');
        bool last_space = true;
        for (wchar_t ch : command)
        {
            wchar_t out = std::iswspace(ch) ? L' ' : ch;
            if (out == L' ' && last_space)
                continue;
            folded.push_back(out);
            last_space = out == L' ';
        }
        if (!folded.empty() && folded.back() != L' ')
            folded.push_back(L' ');
        return contains_w(folded, L" -m camoufox_reverse_mcp ") ||
            contains_w(folded, L" -m \"camoufox_reverse_mcp\" ") ||
            contains_w(folded, L" -m 'camoufox_reverse_mcp' ") ||
            contains_w(folded, L" -m camoufox-reverse-mcp ") ||
            contains_w(folded, L" -m \"camoufox-reverse-mcp\" ") ||
            contains_w(folded, L" -m 'camoufox-reverse-mcp' ");
    }

    inline bool is_trusted_aida_internal_camoufox_mcp_process(const process_probe_t& probe)
    {
        if (probe.parent_pid != GetCurrentProcessId())
            return false;
        static const wchar_t* const reverse_mcp_names[] = {
            L"aida_camoufoxreversemcp.exe", L"camoufox-reverse-mcp.exe", L"camoufox_reverse_mcp.exe"
        };
        if (basename_equals_any(probe, reverse_mcp_names))
            return path_under_current_module_subdir_w(probe.image_lower, L"deps") ||
                path_under_current_module_subdir_w(probe.image_lower, L"camoufox-reverse-mcp");
        static const wchar_t* const python_names[] = {
            L"python.exe", L"pythonw.exe"
        };
        if (!basename_equals_any(probe, python_names))
            return false;
        const std::wstring command = trim_w(probe.command_lower);
        if (!command_has_camoufox_mcp_module(command))
            return false;
        return path_under_current_module_subdir_w(probe.image_lower, L"deps\\camoufox-runtime") ||
            path_under_current_module_subdir_w(probe.image_lower, L"camoufox-runtime");
    }

    inline bool is_ai_coding_tool(const process_probe_t& probe)
    {
        static const wchar_t* const tokens[] = {
            L"cursor.exe", L"windsurf", L"aider", L"continue.exe", L"cline",
            L"roo-cline", L"roo.exe", L"claude.exe", L"claude-code", L"codex.exe",
            L"openai-codex", L"codegen", L"devin", L"gemini.exe", L"qwen.exe",
            L"opencode", L"goose", L"kiro.exe", L"trae.exe", L"copilot"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool is_local_llm_tool(const process_probe_t& probe)
    {
        static const wchar_t* const tokens[] = {
            L"ollama", L"llama-server", L"llama-cli", L"llama.cpp", L"llamafile",
            L"koboldcpp", L"text-generation", L"vllm", L"localai", L"lm-studio",
            L"lmstudio", L"jan.exe", L"gpt4all", L"oobabooga", L"tabbyapi",
            L"exllama", L"mlc-chat", L"mlc_llm", L"tgi-server", L"chatd",
            L"privategpt", L"private-gpt"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool is_memory_scanner_tool(const process_probe_t& probe)
    {
        static const wchar_t* const exact_names[] = {
            L"cheatengine.exe", L"ce.exe", L"processhacker.exe", L"systeminformer.exe",
            L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe",
            L"vmmap.exe", L"rammap.exe", L"apimonitor.exe", L"reclass.net.exe",
            L"reclass.exe", L"xenos.exe", L"extreme injector.exe"
        };
        if (basename_equals_any(probe, exact_names))
            return true;
        static const wchar_t* const tokens[] = {
            L"cheatengine", L"processhacker", L"systeminformer", L"api monitor",
            L"apimonitor", L"procmon", L"procexp", L"memory scanner", L"memoryscanner",
            L"reclass", L"xenos", L"hollows_hunter", L"hollowshunter", L"artmoney",
            L"gameconqueror", L"scanmem", L"memory viewer"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool is_debugger_tool(const process_probe_t& probe)
    {
        static const wchar_t* const exact_names[] = {
            L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe", L"windbgx.exe", L"cdb.exe",
            L"kd.exe", L"ntsd.exe", L"dbgview.exe", L"dbgview64.exe", L"ollydbg.exe",
            L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe", L"frida.exe",
            L"frida-server.exe", L"frida-trace.exe", L"frida-inject.exe"
        };
        if (basename_equals_any(probe, exact_names))
            return true;
        static const wchar_t* const tokens[] = {
            L"x64dbg", L"x32dbg", L"windbg", L"debugger", L"ollydbg", L"immunitydebugger",
            L"frida", L"scyllahide", L"titanhide", L"vehdebug", L"hardware breakpoint"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool is_re_tool(const process_probe_t& probe)
    {
        static const wchar_t* const exact_names[] = {
            L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe", L"ghidrarun.bat",
            L"ghidra.exe", L"binaryninja.exe", L"cutter.exe", L"r2.exe", L"radare2.exe",
            L"dnspy.exe", L"ilspy.exe", L"hiew32.exe", L"hiew64.exe"
        };
        if (basename_equals_any(probe, exact_names))
            return true;
        static const wchar_t* const tokens[] = {
            L"ghidra", L"ida pro", L"hex-rays", L"binary ninja", L"binaryninja",
            L"radare", L"rizin", L"cutter", L"dnspy", L"ilspy", L"hopper disassembler",
            L"retdec", L"jeb", L"reversing", L"disassembler", L"decompiler"
        };
        return probe_contains_any(probe, tokens);
    }

    inline bool is_dump_tool(const process_probe_t& probe)
    {
        static const wchar_t* const exact_names[] = {
            L"scylla.exe", L"scylla_x64.exe", L"scylla_x86.exe", L"importrec.exe",
            L"pe-sieve.exe", L"procdump.exe", L"procdump64.exe", L"dumpbin.exe",
            L"lordpe.exe", L"pebear.exe", L"die.exe", L"cff explorer.exe"
        };
        if (basename_equals_any(probe, exact_names))
            return true;
        static const wchar_t* const identity_tokens[] = {
            L"scylla", L"importrec", L"pe-sieve", L"pebear", L"pe-bear",
            L"hollowshunter", L"hollows_hunter", L"procdump", L"minidump",
            L"processdump", L"memdump", L"lordpe", L"cff explorer",
            L"detect it easy", L"die64", L"petools", L"reshacker"
        };
        if (probe_identity_contains_any(probe, identity_tokens))
            return true;
        static const wchar_t* const command_tokens[] = {
            L" procdump ", L" procdump.exe ", L" procdump64 ", L" procdump64.exe ",
            L" pe-sieve ", L" pe-sieve.exe ", L" scylla.exe ", L" importrec.exe ",
            L" dumpbin.exe ", L" lordpe.exe ", L" pebear.exe "
        };
        std::wstring padded_command;
        if (!probe.command_lower.empty())
        {
            padded_command.reserve(probe.command_lower.size() + 2);
            padded_command.push_back(L' ');
            padded_command.append(probe.command_lower);
            padded_command.push_back(L' ');
            for (const wchar_t* token : command_tokens)
            {
                if (contains_w(padded_command, token))
                    return true;
            }
        }
        return false;
    }

    inline bool env_flag_enabled_a(const char* name)
    {
        char value[16] = {};
        DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
        if (n == 0 || n >= static_cast<DWORD>(sizeof(value)))
            return false;
        return !(value[0] == '0' && (value[1] == '\0' || value[1] == ' ' || value[1] == '\t'));
    }

    inline bool env_value_present_a(const char* name)
    {
        char value[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
        return n > 0 && n < static_cast<DWORD>(sizeof(value));
    }

    inline DWORD current_parent_pid()
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;
        DWORD self = GetCurrentProcessId();
        DWORD parent = 0;
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        {
            if (pe.th32ProcessID == self)
            {
                parent = pe.th32ParentProcessID;
                break;
            }
        }
        CloseHandle(snap);
        return parent;
    }

    inline bool current_module_is_fileless_host()
    {
        wchar_t path[MAX_PATH] = {};
        DWORD got = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
        if (got == 0 || got >= static_cast<DWORD>(sizeof(path) / sizeof(path[0])))
            return false;
        std::wstring image = lower_copy(basename_ptr(path));
        static const wchar_t* const hosts[] = {
            L"powershell.exe",
            L"pwsh.exe"
        };
        return equals_any_w(image.c_str(), hosts);
    }

    inline bool fileless_bootstrap_context_active()
    {
        return env_flag_enabled_a("AIDA_FILELESS_LAUNCH") &&
            env_flag_enabled_a("AIDA_FILELESS_NO_DISK_WRITE") &&
            env_value_present_a("AIDA_FILELESS_DEBUG_LOG_PATH") &&
            env_value_present_a("AIDA_FILELESS_BOOTSTRAP_LOG_PATH") &&
            env_value_present_a("AIDA_FILELESS_IMAGE_BASE") &&
            env_value_present_a("AIDA_FILELESS_IMAGE_SIZE") &&
            env_value_present_a("AIDA_FILELESS_ENTRY_RVA") &&
            current_module_is_fileless_host();
    }

    inline bool is_fileless_bootstrap_parent_owner(const process_probe_t* probe,
                                                   DWORD owner_pid,
                                                   DWORD parent_pid)
    {
        if (!probe || parent_pid == 0 || owner_pid != parent_pid)
            return false;
        if (!fileless_bootstrap_context_active())
            return false;
        static const wchar_t* const terminal_hosts[] = {
            L"windowsterminal.exe",
            L"wt.exe",
            L"conhost.exe",
            L"openconsole.exe"
        };
        if (!basename_equals_any(*probe, terminal_hosts))
            return false;
        if (is_memory_scanner_tool(*probe) || is_re_tool(*probe) ||
            is_debugger_tool(*probe) || is_dump_tool(*probe) ||
            has_mcp_command_evidence(*probe) || is_ai_coding_tool(*probe) ||
            has_aida_target_evidence(*probe))
            return false;
        return true;
    }

    struct process_evidence_t
    {
        bool mcp_process = false;
        bool mcp_command_server = false;
        bool ai_tool = false;
        bool llm_tool = false;
        bool memory_scanner = false;
        bool re_tool = false;
        bool debugger_tool = false;
        bool dump_tool = false;
        bool offensive_mcp_tool = false;
        bool targets_aida = false;
        uint32_t evidence_count = 0;
        uint64_t evidence_hash = 1469598103934665603ull;
        uint64_t dump_tool_hash = 0;
    };

    inline void add_process_evidence(process_evidence_t& out, const process_probe_t& probe)
    {
        ++out.evidence_count;
        uint64_t h = probe.basename_hash;
        if (!probe.image_lower.empty())
            h = mix_hash(h, hash_wide_lower(probe.image_lower.c_str()));
        if (!probe.command_lower.empty())
            h = mix_hash(h, hash_wide_lower(probe.command_lower.c_str()));
        out.evidence_hash = mix_hash(out.evidence_hash, h);
    }

    inline process_evidence_t classify_processes(const std::vector<process_probe_t>& probes)
    {
        process_evidence_t out{};
        for (const auto& probe : probes)
        {
            const bool mcp_evidence = has_mcp_command_evidence(probe);
            const bool mcp_command = is_shell_or_interpreter(probe) && mcp_evidence;
            const bool ai_tool = is_ai_coding_tool(probe);
            const bool llm_tool = is_local_llm_tool(probe);
            const bool memory_tool = is_memory_scanner_tool(probe);
            const bool re_tool = is_re_tool(probe);
            const bool debugger_tool = is_debugger_tool(probe);
            const bool dump_tool = is_dump_tool(probe);
            const bool high_value_tool = mcp_evidence || ai_tool || memory_tool || re_tool || debugger_tool || dump_tool;
            const bool trusted_internal_camoufox = is_trusted_aida_internal_camoufox_mcp_process(probe);
            if (trusted_internal_camoufox)
            {
                diag::log_tagged_fmt("guard",
                    "ai_tool_posture_trusted_internal_camoufox_ignored pid=%lu parent_pid=%lu exe_hash=0x%016llX image_hash=0x%016llX command_hash=0x%016llX mcp=%d mcp_cmd=%d target=%d",
                    static_cast<unsigned long>(probe.pid),
                    static_cast<unsigned long>(probe.parent_pid),
                    static_cast<unsigned long long>(probe.basename_hash),
                    static_cast<unsigned long long>(hash_wide_lower(probe.image_lower.c_str())),
                    static_cast<unsigned long long>(hash_wide_lower(probe.command_lower.c_str())),
                    mcp_evidence ? 1 : 0,
                    mcp_command ? 1 : 0,
                    has_aida_target_evidence(probe) ? 1 : 0);
                continue;
            }
            bool counted = false;
            if (mcp_evidence)
            {
                out.mcp_process = true;
                counted = true;
            }
            if (mcp_command)
            {
                out.mcp_command_server = true;
                counted = true;
            }
            if (ai_tool)
            {
                out.ai_tool = true;
                counted = true;
            }
            if (llm_tool)
            {
                out.llm_tool = true;
                counted = true;
            }
            if (memory_tool)
            {
                out.memory_scanner = true;
                counted = true;
            }
            if (re_tool)
            {
                out.re_tool = true;
                counted = true;
            }
            if (debugger_tool)
            {
                out.debugger_tool = true;
                counted = true;
            }
            if (dump_tool)
            {
                out.dump_tool = true;
                uint64_t h = probe.basename_hash;
                if (!probe.image_lower.empty())
                    h = mix_hash(h, hash_wide_lower(probe.image_lower.c_str()));
                if (!probe.command_lower.empty())
                    h = mix_hash(h, hash_wide_lower(probe.command_lower.c_str()));
                out.dump_tool_hash = out.dump_tool_hash ? mix_hash(out.dump_tool_hash, h) : h;
                counted = true;
            }
            if (high_value_tool && has_aida_target_evidence(probe))
            {
                out.targets_aida = true;
                counted = true;
            }
            if (counted)
            {
                diag::log_tagged_fmt("guard",
                    "ai_tool_posture_process_evidence pid=%lu parent_pid=%lu exe_hash=0x%016llX image_hash=0x%016llX command_hash=0x%016llX mcp=%d mcp_cmd=%d ai=%d llm=%d mem=%d re=%d dbg=%d dump=%d target=%d",
                    static_cast<unsigned long>(probe.pid),
                    static_cast<unsigned long>(probe.parent_pid),
                    static_cast<unsigned long long>(probe.basename_hash),
                    static_cast<unsigned long long>(hash_wide_lower(probe.image_lower.c_str())),
                    static_cast<unsigned long long>(hash_wide_lower(probe.command_lower.c_str())),
                    mcp_evidence ? 1 : 0,
                    mcp_command ? 1 : 0,
                    ai_tool ? 1 : 0,
                    llm_tool ? 1 : 0,
                    memory_tool ? 1 : 0,
                    re_tool ? 1 : 0,
                    debugger_tool ? 1 : 0,
                    dump_tool ? 1 : 0,
                    has_aida_target_evidence(probe) ? 1 : 0);
                add_process_evidence(out, probe);
            }
        }
        return out;
    }

    inline bool is_mcp_specific_port(uint16_t port)
    {
        switch (port)
        {
        case 6274:
        case 6277:
        case 8765:
        case 4000:
        case 4001:
        case 3100:
            return true;
        default:
            return false;
        }
    }

    inline bool is_mcp_candidate_port(uint16_t port)
    {
        switch (port)
        {
        case 3000:
        case 3001:
        case 3100:
        case 3333:
        case 4000:
        case 4001:
        case 5000:
        case 5001:
        case 5173:
        case 6274:
        case 6277:
        case 8080:
        case 8765:
        case 8787:
        case 8790:
            return true;
        default:
            return false;
        }
    }

    struct port_report_t
    {
        bool active = false;
        bool websocket_bridge = false;
        uint64_t owner_hash = 0;
    };

    inline port_report_t scan_mcp_ports(const std::vector<process_probe_t>* probes)
    {
        DWORD tcp_table_size = 0;
        GetExtendedTcpTable(nullptr, &tcp_table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        port_report_t out{};
        if (tcp_table_size == 0)
            return out;
        auto* table = static_cast<MIB_TCPTABLE_OWNER_PID*>(std::malloc(tcp_table_size));
        if (!table)
            return out;
        if (GetExtendedTcpTable(table, &tcp_table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            DWORD my_pid = GetCurrentProcessId();
            for (DWORD i = 0; i < table->dwNumEntries && !out.active; ++i)
            {
                auto& row = table->table[i];
                if (row.dwOwningPid == my_pid)
                    continue;
                if (row.dwState != MIB_TCP_STATE_LISTEN && row.dwState != MIB_TCP_STATE_ESTAB)
                    continue;
                uint16_t local_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                if (!is_mcp_candidate_port(local_port))
                    continue;
                const process_probe_t* probe = probes ? find_probe(*probes, row.dwOwningPid) : nullptr;
                process_probe_t fallback{};
                if (!probe)
                {
                    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
                    if (process)
                    {
                        fallback.pid = row.dwOwningPid;
                        wchar_t image_path[MAX_PATH] = {};
                        DWORD path_size = MAX_PATH;
                        if (QueryFullProcessImageNameW(process, 0, image_path, &path_size))
                        {
                            fallback.image_lower = lower_copy(image_path);
                            fallback.exe_lower = lower_copy(basename_ptr(image_path));
                            fallback.basename_hash = basename_hash_w(image_path);
                        }
                        std::wstring command = query_process_command_line(process);
                        if (!command.empty())
                            fallback.command_lower = lower_copy(command);
                        CloseHandle(process);
                        probe = &fallback;
                    }
                }
                if (!probe)
                    continue;
                bool mcp_named = has_mcp_command_evidence(*probe);
                bool host = is_shell_or_interpreter(*probe);
                if ((mcp_named && host) || (is_mcp_specific_port(local_port) && host))
                {
                    out.active = true;
                    out.websocket_bridge = true;
                    out.owner_hash = probe->basename_hash;
                }
            }
        }
        std::free(table);
        return out;
    }

    struct clipboard_report_t
    {
        bool suspicious = false;
        uint64_t owner_hash = 0;
    };

    inline clipboard_report_t scan_clipboard_monitoring(const std::vector<process_probe_t>* probes)
    {
        clipboard_report_t out{};
        HWND viewer = GetClipboardViewer();
        HWND owner = GetClipboardOwner();
        HWND open_window = GetOpenClipboardWindow();
        HWND candidates[3] = { viewer, owner, open_window };
        DWORD my_pid = GetCurrentProcessId();
        for (HWND hwnd : candidates)
        {
            if (!hwnd)
                continue;
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == 0 || pid == my_pid)
                continue;
            const process_probe_t* probe = probes ? find_probe(*probes, pid) : nullptr;
            process_probe_t fallback{};
            if (!probe)
            {
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (process)
                {
                    wchar_t image_path[MAX_PATH] = {};
                    DWORD path_size = MAX_PATH;
                    if (QueryFullProcessImageNameW(process, 0, image_path, &path_size))
                    {
                        fallback.pid = pid;
                        fallback.image_lower = lower_copy(image_path);
                        fallback.exe_lower = lower_copy(basename_ptr(image_path));
                        fallback.basename_hash = basename_hash_w(image_path);
                        probe = &fallback;
                    }
                    CloseHandle(process);
                }
            }
            if (!probe)
                continue;
            if (is_ai_coding_tool(*probe) || has_mcp_command_evidence(*probe) ||
                is_memory_scanner_tool(*probe) || is_re_tool(*probe) || is_debugger_tool(*probe))
            {
                out.suspicious = true;
                out.owner_hash = probe->basename_hash;
                break;
            }
        }
        return out;
    }

    struct window_scan_context_t
    {
        const std::vector<process_probe_t>* probes = nullptr;
        bool targeted = false;
        uint64_t owner_hash = 0;
    };

    inline BOOL CALLBACK enum_windows_target_proc(HWND hwnd, LPARAM lparam)
    {
        auto* ctx = reinterpret_cast<window_scan_context_t*>(lparam);
        if (!ctx || ctx->targeted || !IsWindowVisible(hwnd))
            return TRUE;
        wchar_t title[512] = {};
        if (GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0]))) <= 0)
            return TRUE;
        std::wstring lower_title = lower_copy(title);
        static const wchar_t* const title_tokens[] = {
            L"aidastandalone", L"aida.exe", L"aidaprivate", L"aida_core", L"aida_debug.log"
        };
        if (!contains_any_w(lower_title, title_tokens))
            return TRUE;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == 0 || pid == GetCurrentProcessId())
            return TRUE;
        const process_probe_t* probe = ctx->probes ? find_probe(*ctx->probes, pid) : nullptr;
        if (!probe)
            return TRUE;
        if (is_ai_coding_tool(*probe) || has_mcp_command_evidence(*probe) ||
            is_memory_scanner_tool(*probe) || is_re_tool(*probe) ||
            is_debugger_tool(*probe) || is_dump_tool(*probe))
        {
            ctx->targeted = true;
            ctx->owner_hash = probe->basename_hash;
            return FALSE;
        }
        return TRUE;
    }

    inline window_scan_context_t scan_windows_for_aida_targeting(const std::vector<process_probe_t>& probes)
    {
        window_scan_context_t ctx{};
        ctx.probes = &probes;
        EnumWindows(enum_windows_target_proc, reinterpret_cast<LPARAM>(&ctx));
        return ctx;
    }

}

namespace mcp_detect
{

    struct mcp_indicator_t
    {
        bool named_pipe_found = false;
        bool mcp_process_found = false;
        bool mcp_port_active = false;
        bool websocket_bridge = false;
        bool mcp_command_server = false;
        uint64_t evidence_hash = 0;
        std::string detail;
    };

    inline bool scan_named_pipes(uint64_t* evidence_hash = nullptr)
    {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        bool found = false;
        do
        {
            wchar_t lower[MAX_PATH] = {};
            detail::to_lower_w(fd.cFileName, lower, MAX_PATH);
            static const wchar_t* const tokens[] = {
                L"mcp", L"model-context", L"modelcontextprotocol", L"claude-bridge",
                L"anthropic", L"openai-bridge", L"copilot-mcp", L"cursor-mcp",
                L"windsurf-mcp", L"aider-mcp", L"cline-mcp", L"roo-mcp",
                L"llm-bridge", L"ai-agent", L"json-rpc-driver", L"tool-server",
                L"mcp-server", L"vscode-mcp", L"codex-mcp"
            };
            if (detail::contains_any_w(lower, tokens))
            {
                found = true;
                if (evidence_hash)
                    *evidence_hash = detail::hash_wide_lower(lower);
                break;
            }
        }
        while (FindNextFileW(h, &fd));
        FindClose(h);
        return found;
    }

    inline bool scan_mcp_processes()
    {
        auto processes = detail::collect_processes();
        auto evidence = detail::classify_processes(processes);
        return evidence.mcp_process || evidence.mcp_command_server;
    }

    inline bool scan_mcp_ports()
    {
        auto processes = detail::collect_processes();
        return detail::scan_mcp_ports(&processes).active;
    }

    inline mcp_indicator_t full_scan()
    {
        mcp_indicator_t result{};
        auto processes = detail::collect_processes();
        auto process_evidence = detail::classify_processes(processes);
        uint64_t pipe_hash = 0;
        result.named_pipe_found = scan_named_pipes(&pipe_hash);
        result.mcp_process_found = process_evidence.mcp_process;
        result.mcp_command_server = process_evidence.mcp_command_server;
        auto ports = detail::scan_mcp_ports(&processes);
        result.mcp_port_active = ports.active;
        result.websocket_bridge = ports.websocket_bridge;
        result.evidence_hash = process_evidence.evidence_hash;
        if (pipe_hash)
            result.evidence_hash = detail::mix_hash(result.evidence_hash, pipe_hash);
        if (ports.owner_hash)
            result.evidence_hash = detail::mix_hash(result.evidence_hash, ports.owner_hash);
        if (result.named_pipe_found) detail::append_token(result.detail, "named_pipe");
        if (result.mcp_process_found) detail::append_token(result.detail, "mcp_proc");
        if (result.mcp_command_server) detail::append_token(result.detail, "mcp_cmd");
        if (result.mcp_port_active) detail::append_token(result.detail, "mcp_port");
        if (result.evidence_hash) detail::append_hex_token(result.detail, "mcp_hash", result.evidence_hash);
        return result;
    }

}

namespace llm_detect
{

    struct llm_indicator_t
    {
        bool inference_engine_found = false;
        bool gpu_inference_active = false;
        bool model_files_loaded = false;
        std::string engine_name;
    };

    inline bool scan_llm_processes()
    {
        auto processes = detail::collect_processes();
        auto evidence = detail::classify_processes(processes);
        return evidence.llm_tool;
    }

    inline bool scan_ollama_api()
    {
        DWORD tcp_table_size = 0;
        GetExtendedTcpTable(nullptr, &tcp_table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (tcp_table_size == 0)
            return false;
        auto* table = static_cast<MIB_TCPTABLE_OWNER_PID*>(std::malloc(tcp_table_size));
        if (!table)
            return false;
        bool found = false;
        if (GetExtendedTcpTable(table, &tcp_table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < table->dwNumEntries && !found; ++i)
            {
                uint16_t port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));
                if ((port == 11434 || port == 11435) &&
                    table->table[i].dwState == MIB_TCP_STATE_LISTEN)
                {
                    found = true;
                }
            }
        }
        std::free(table);
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
        auto processes = detail::collect_processes();
        auto evidence = detail::classify_processes(processes);
        return evidence.ai_tool;
    }

    inline bool scan_clipboard_monitoring()
    {
        auto processes = detail::collect_processes();
        return detail::scan_clipboard_monitoring(&processes).suspicious;
    }

}

namespace self_analysis
{

    struct scanner_report_t
    {
        bool memory_scanner = false;
        bool re_tool = false;
        bool debugger_tool = false;
        bool dump_tool = false;
        bool targets_aida = false;
        uint64_t evidence_hash = 0;
        uint32_t evidence_count = 0;
    };

    inline scanner_report_t scan_tool_processes()
    {
        auto processes = detail::collect_processes();
        auto evidence = detail::classify_processes(processes);
        scanner_report_t out{};
        out.memory_scanner = evidence.memory_scanner;
        out.re_tool = evidence.re_tool;
        out.debugger_tool = evidence.debugger_tool;
        out.dump_tool = evidence.dump_tool;
        out.targets_aida = evidence.targets_aida;
        out.evidence_hash = evidence.evidence_hash;
        out.evidence_count = evidence.evidence_count;
        return out;
    }

    inline bool detect_memory_scanners()
    {
        return scan_tool_processes().memory_scanner;
    }

    struct handle_report_t
    {
        bool any = false;
        bool vm_read = false;
        bool vm_write = false;
        bool vm_operation = false;
        bool create_thread = false;
        bool owner_tool = false;
        bool owner_targets_aida = false;
        bool trusted_system_ignored = false;
        bool fileless_bootstrap_parent_ignored = false;
        DWORD access_mask = 0;
        DWORD first_owner_pid = 0;
        DWORD first_access_mask = 0;
        uint64_t first_handle_value = 0;
        uint64_t first_owner_hash = 0;
        std::string first_owner_image;
        std::string first_owner_path;
        bool first_owner_query_ok = false;
        bool first_owner_tool = false;
        bool first_owner_targets_aida = false;
        bool first_owner_core_system = false;
        bool first_owner_mcp = false;
        bool first_owner_ai = false;
        bool first_owner_memory = false;
        bool first_owner_re = false;
        bool first_owner_debugger = false;
        bool first_owner_dump = false;
        uint64_t owner_hash = 0;
        uint64_t trusted_system_owner_hash = 0;
        uint64_t fileless_bootstrap_parent_owner_hash = 0;
        DWORD trusted_system_access_mask = 0;
        DWORD fileless_bootstrap_parent_access_mask = 0;
        DWORD fileless_bootstrap_parent_owner_pid = 0;
        std::string fileless_bootstrap_parent_owner_image;
        std::string fileless_bootstrap_parent_owner_path;
        uint32_t trusted_system_ignored_count = 0;
        uint32_t fileless_bootstrap_parent_ignored_count = 0;
        uint32_t observed_handle_count = 0;
    };

    inline handle_report_t detect_handle_to_us_report(const std::vector<detail::process_probe_t>* probes = nullptr)
    {
        using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto* query = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        handle_report_t out{};
        if (!query)
            return out;
        ULONG buf_size = 1u << 20;
        auto* buf = static_cast<uint8_t*>(std::malloc(buf_size));
        if (!buf)
            return out;
        constexpr ULONG kSystemExtendedHandleInformation = 64;
        NTSTATUS st = query(kSystemExtendedHandleInformation, buf, buf_size, &buf_size);
        constexpr NTSTATUS status_info_length_mismatch = static_cast<NTSTATUS>(0xC0000004u);
        constexpr NTSTATUS status_buffer_too_small = static_cast<NTSTATUS>(0xC0000023u);
        if (st == status_info_length_mismatch || st == status_buffer_too_small)
        {
            std::free(buf);
            buf = static_cast<uint8_t*>(std::malloc(buf_size));
            if (!buf)
                return out;
            st = query(kSystemExtendedHandleInformation, buf, buf_size, &buf_size);
        }
        if (st >= 0)
        {
            struct system_handle_table_entry_info_ex_t
            {
                PVOID Object;
                ULONG_PTR UniqueProcessId;
                ULONG_PTR HandleValue;
                ULONG GrantedAccess;
                USHORT CreatorBackTraceIndex;
                USHORT ObjectTypeIndex;
                ULONG HandleAttributes;
                ULONG Reserved;
            };
            struct system_handle_information_ex_t
            {
                ULONG_PTR NumberOfHandles;
                ULONG_PTR Reserved;
                system_handle_table_entry_info_ex_t Handles[1];
            };
            auto* info = reinterpret_cast<system_handle_information_ex_t*>(buf);
            DWORD my_pid = GetCurrentProcessId();
            DWORD fileless_parent_pid = detail::fileless_bootstrap_context_active() ?
                detail::current_parent_pid() : 0;
            PVOID self_process_object = nullptr;
            HANDLE self_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, my_pid);
            if (self_process)
            {
                ULONG_PTR self_handle_value = reinterpret_cast<ULONG_PTR>(self_process);
                for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
                {
                    auto& h = info->Handles[i];
                    if (static_cast<DWORD>(h.UniqueProcessId) == my_pid &&
                        h.HandleValue == self_handle_value)
                    {
                        self_process_object = h.Object;
                        break;
                    }
                }
                CloseHandle(self_process);
            }
            for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
            {
                auto& h = info->Handles[i];
                DWORD owner_pid = static_cast<DWORD>(h.UniqueProcessId);
                if (owner_pid == 0 || owner_pid == my_pid)
                    continue;
                constexpr DWORD interesting_access =
                    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                    PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE;
                if ((h.GrantedAccess & interesting_access) == 0)
                    continue;
                bool targets_self = self_process_object != nullptr && h.Object == self_process_object;
                if (!targets_self)
                {
                    HANDLE source = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner_pid);
                    if (!source)
                        continue;
                    HANDLE dup_handle = nullptr;
                    BOOL duplicated = DuplicateHandle(
                        source,
                        reinterpret_cast<HANDLE>(h.HandleValue),
                        GetCurrentProcess(),
                        &dup_handle,
                        0,
                        FALSE,
                        DUPLICATE_SAME_ACCESS);
                    CloseHandle(source);
                    if (!duplicated)
                        continue;
                    DWORD target_pid = GetProcessId(dup_handle);
                    CloseHandle(dup_handle);
                    if (target_pid != my_pid)
                        continue;
                    targets_self = true;
                }
                if (!targets_self)
                    continue;
                const detail::process_probe_t* probe = probes ? detail::find_probe(*probes, owner_pid) : nullptr;
                detail::process_probe_t fallback{};
                if (!probe)
                {
                    HANDLE owner = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner_pid);
                    if (owner)
                    {
                        wchar_t image_path[MAX_PATH] = {};
                        DWORD path_size = MAX_PATH;
                        fallback.pid = owner_pid;
                        fallback.query_ok = true;
                        if (QueryFullProcessImageNameW(owner, 0, image_path, &path_size))
                        {
                            fallback.image_lower = detail::lower_copy(image_path);
                            fallback.exe_lower = detail::lower_copy(detail::basename_ptr(image_path));
                            fallback.basename_hash = detail::basename_hash_w(image_path);
                        }
                        std::wstring command = detail::query_process_command_line(owner);
                        if (!command.empty())
                            fallback.command_lower = detail::lower_copy(command);
                        CloseHandle(owner);
                        probe = &fallback;
                    }
                }
                if (detail::is_fileless_bootstrap_parent_owner(probe, owner_pid, fileless_parent_pid))
                {
                    std::string owner_image = detail::probe_image_for_log(probe);
                    std::string owner_path = detail::probe_path_for_log(probe);
                    std::string flags = detail::format_process_handle_access_flags(h.GrantedAccess);
                    out.fileless_bootstrap_parent_ignored = true;
                    ++out.fileless_bootstrap_parent_ignored_count;
                    out.fileless_bootstrap_parent_access_mask |= h.GrantedAccess;
                    out.fileless_bootstrap_parent_owner_pid = owner_pid;
                    out.fileless_bootstrap_parent_owner_hash = detail::mix_hash(
                        out.fileless_bootstrap_parent_owner_hash,
                        probe ? probe->basename_hash : 0);
                    if (out.fileless_bootstrap_parent_owner_image.empty())
                        out.fileless_bootstrap_parent_owner_image = owner_image;
                    if (out.fileless_bootstrap_parent_owner_path.empty())
                        out.fileless_bootstrap_parent_owner_path = owner_path;
                    diag::log_tagged_critical_fmt("guard",
                        "ai_tool_posture_fileless_parent_handle_ignored owner_pid=%lu parent_pid=%lu handle=0x%016llX access=0x%08lX access_flags=%s owner_hash=0x%016llX owner_image=%s owner_path=%s ignored_count=%u",
                        static_cast<unsigned long>(owner_pid),
                        static_cast<unsigned long>(fileless_parent_pid),
                        static_cast<unsigned long long>(h.HandleValue),
                        static_cast<unsigned long>(h.GrantedAccess),
                        flags.c_str(),
                        static_cast<unsigned long long>(probe ? probe->basename_hash : 0),
                        owner_image.empty() ? "<empty>" : owner_image.c_str(),
                        owner_path.empty() ? "<empty>" : owner_path.c_str(),
                        out.fileless_bootstrap_parent_ignored_count);
                    continue;
                }
                if (detail::trusted_kernel_system_owner(owner_pid))
                {
                    out.trusted_system_ignored = true;
                    ++out.trusted_system_ignored_count;
                    out.trusted_system_access_mask |= h.GrantedAccess;
                    uint64_t owner_hash = probe ? probe->basename_hash : 0;
                    if (owner_hash == 0)
                        owner_hash = detail::hash_wide_lower(L"system");
                    out.trusted_system_owner_hash = detail::mix_hash(
                        out.trusted_system_owner_hash,
                        owner_hash);
                    continue;
                }
                if (probe &&
                    detail::trusted_windows_system_process(*probe) &&
                    detail::passive_system_handle_access(h.GrantedAccess))
                {
                    out.trusted_system_ignored = true;
                    ++out.trusted_system_ignored_count;
                    out.trusted_system_access_mask |= h.GrantedAccess;
                    out.trusted_system_owner_hash = detail::mix_hash(
                        out.trusted_system_owner_hash,
                        probe->basename_hash);
                    continue;
                }
                bool owner_memory = false;
                bool owner_re = false;
                bool owner_debugger = false;
                bool owner_dump = false;
                bool owner_mcp = false;
                bool owner_ai = false;
                bool owner_targets = false;
                uint64_t owner_hash = 0;
                bool owner_query_ok = false;
                bool owner_core_system = false;
                if (probe)
                {
                    owner_hash = probe->basename_hash;
                    owner_query_ok = probe->query_ok;
                    owner_core_system = detail::trusted_windows_core_basename_w(probe->exe_lower);
                    owner_memory = detail::is_memory_scanner_tool(*probe);
                    owner_re = detail::is_re_tool(*probe);
                    owner_debugger = detail::is_debugger_tool(*probe);
                    owner_dump = detail::is_dump_tool(*probe);
                    owner_mcp = detail::has_mcp_command_evidence(*probe);
                    owner_ai = detail::is_ai_coding_tool(*probe);
                    owner_targets = detail::has_aida_target_evidence(*probe);
                }
                out.any = true;
                ++out.observed_handle_count;
                out.access_mask |= h.GrantedAccess;
                out.vm_read = out.vm_read || ((h.GrantedAccess & PROCESS_VM_READ) != 0);
                out.vm_write = out.vm_write || ((h.GrantedAccess & PROCESS_VM_WRITE) != 0);
                out.vm_operation = out.vm_operation || ((h.GrantedAccess & PROCESS_VM_OPERATION) != 0);
                out.create_thread = out.create_thread || ((h.GrantedAccess & PROCESS_CREATE_THREAD) != 0);
                if (out.first_owner_pid == 0)
                {
                    out.first_owner_pid = owner_pid;
                    out.first_access_mask = h.GrantedAccess;
                    out.first_handle_value = static_cast<uint64_t>(h.HandleValue);
                    out.first_owner_hash = owner_hash;
                    out.first_owner_image = detail::probe_image_for_log(probe);
                    out.first_owner_path = detail::probe_path_for_log(probe);
                    out.first_owner_query_ok = owner_query_ok;
                    out.first_owner_core_system = owner_core_system;
                    out.first_owner_mcp = owner_mcp;
                    out.first_owner_ai = owner_ai;
                    out.first_owner_memory = owner_memory;
                    out.first_owner_re = owner_re;
                    out.first_owner_debugger = owner_debugger;
                    out.first_owner_dump = owner_dump;
                    out.first_owner_targets_aida = owner_targets;
                    out.first_owner_tool = owner_memory || owner_re || owner_debugger || owner_dump || owner_mcp || owner_ai;
                }
                if (probe)
                {
                    out.owner_hash = owner_hash;
                    out.owner_tool = out.owner_tool || owner_memory || owner_re ||
                        owner_debugger || owner_dump || owner_mcp || owner_ai;
                    out.owner_targets_aida = out.owner_targets_aida || owner_targets;
                }
                if (out.vm_write || out.vm_operation || out.create_thread)
                    break;
            }
        }
        std::free(buf);
        return out;
    }

    inline bool detect_handle_to_us()
    {
        auto report = detect_handle_to_us_report();
        return report.any;
    }

}

namespace combined
{

    struct threat_report_t
    {
        bool mcp_detected = false;
        bool mcp_pipe_detected = false;
        bool mcp_process_detected = false;
        bool mcp_port_detected = false;
        bool mcp_command_server_detected = false;
        bool llm_detected = false;
        bool local_llm_detected = false;
        bool ai_tool_detected = false;
        bool memory_scanner_detected = false;
        bool re_tool_detected = false;
        bool debugger_tool_detected = false;
        bool dump_tool_detected = false;
        bool offensive_mcp_tool_detected = false;
        bool handle_to_us_detected = false;
        bool foreign_vm_read_handle = false;
        bool foreign_vm_write_handle = false;
        bool foreign_vm_operation_handle = false;
        bool foreign_create_thread_handle = false;
        bool handle_owner_tool = false;
        bool clipboard_monitored = false;
        bool tool_targets_aida = false;
        bool trusted_system_handle_ignored = false;
        bool fileless_bootstrap_parent_handle_ignored = false;
        uint32_t trusted_system_handle_ignored_count = 0;
        uint32_t fileless_bootstrap_parent_handle_ignored_count = 0;
        uint32_t observed_handle_count = 0;
        DWORD handle_access_mask = 0;
        DWORD first_handle_owner_pid = 0;
        DWORD first_handle_access_mask = 0;
        uint64_t first_handle_value = 0;
        uint64_t first_handle_owner_hash = 0;
        std::string first_handle_owner_image;
        std::string first_handle_owner_path;
        bool first_handle_owner_query_ok = false;
        bool first_handle_owner_tool = false;
        bool first_handle_owner_targets_aida = false;
        bool first_handle_owner_core_system = false;
        bool first_handle_owner_mcp = false;
        bool first_handle_owner_ai = false;
        bool first_handle_owner_memory = false;
        bool first_handle_owner_re = false;
        bool first_handle_owner_debugger = false;
        bool first_handle_owner_dump = false;
        DWORD trusted_system_handle_access_mask = 0;
        DWORD fileless_bootstrap_parent_handle_access_mask = 0;
        DWORD fileless_bootstrap_parent_handle_owner_pid = 0;
        uint64_t trusted_system_handle_owner_hash = 0;
        uint64_t fileless_bootstrap_parent_handle_owner_hash = 0;
        std::string fileless_bootstrap_parent_handle_owner_image;
        std::string fileless_bootstrap_parent_handle_owner_path;
        uint32_t category_mask = 0;
        uint32_t high_risk_mask = 0;
        uint32_t high_risk_count = 0;
        uint32_t evidence_count = 0;
        uint64_t evidence_hash = 0;
        uint64_t dump_tool_hash = 0;
        uint64_t summary_hash = 0;
        std::string summary;

        bool any_threat() const
        {
            return category_mask != 0;
        }

        bool ai_threat() const
        {
            return mcp_detected || llm_detected || ai_tool_detected;
        }

        bool confirmed_high_risk() const
        {
            return high_risk_count != 0;
        }
    };

    inline void set_category(threat_report_t& report, uint32_t bit, const char* token)
    {
        report.category_mask |= bit;
        detail::append_token(report.summary, token);
    }

    inline void set_high_risk(threat_report_t& report, uint32_t bit)
    {
        report.high_risk_mask |= bit;
    }

    inline threat_report_t full_scan()
    {
        threat_report_t report{};
        auto processes = detail::collect_processes();
        auto process_evidence = detail::classify_processes(processes);
        uint64_t pipe_hash = 0;
        report.mcp_pipe_detected = mcp_detect::scan_named_pipes(&pipe_hash);
        report.mcp_process_detected = process_evidence.mcp_process;
        report.mcp_command_server_detected = process_evidence.mcp_command_server;
        auto port_report = detail::scan_mcp_ports(&processes);
        report.mcp_port_detected = port_report.active;
        report.mcp_detected = report.mcp_pipe_detected || report.mcp_process_detected ||
            report.mcp_port_detected || report.mcp_command_server_detected;
        report.local_llm_detected = process_evidence.llm_tool || llm_detect::scan_ollama_api();
        report.ai_tool_detected = process_evidence.ai_tool;
        report.memory_scanner_detected = process_evidence.memory_scanner;
        report.re_tool_detected = process_evidence.re_tool;
        report.debugger_tool_detected = process_evidence.debugger_tool;
        report.dump_tool_detected = process_evidence.dump_tool;
        report.dump_tool_hash = process_evidence.dump_tool_hash;
        report.offensive_mcp_tool_detected = process_evidence.offensive_mcp_tool;
        auto handle_report = self_analysis::detect_handle_to_us_report(&processes);
        report.handle_to_us_detected = handle_report.any;
        report.foreign_vm_read_handle = handle_report.vm_read;
        report.foreign_vm_write_handle = handle_report.vm_write;
        report.foreign_vm_operation_handle = handle_report.vm_operation;
        report.foreign_create_thread_handle = handle_report.create_thread;
        report.handle_owner_tool = handle_report.owner_tool;
        report.trusted_system_handle_ignored = handle_report.trusted_system_ignored;
        report.trusted_system_handle_ignored_count = handle_report.trusted_system_ignored_count;
        report.fileless_bootstrap_parent_handle_ignored = handle_report.fileless_bootstrap_parent_ignored;
        report.fileless_bootstrap_parent_handle_ignored_count = handle_report.fileless_bootstrap_parent_ignored_count;
        report.observed_handle_count = handle_report.observed_handle_count;
        report.handle_access_mask = handle_report.access_mask;
        report.first_handle_owner_pid = handle_report.first_owner_pid;
        report.first_handle_access_mask = handle_report.first_access_mask;
        report.first_handle_value = handle_report.first_handle_value;
        report.first_handle_owner_hash = handle_report.first_owner_hash;
        report.first_handle_owner_image = handle_report.first_owner_image;
        report.first_handle_owner_path = handle_report.first_owner_path;
        report.first_handle_owner_query_ok = handle_report.first_owner_query_ok;
        report.first_handle_owner_tool = handle_report.first_owner_tool;
        report.first_handle_owner_targets_aida = handle_report.first_owner_targets_aida;
        report.first_handle_owner_core_system = handle_report.first_owner_core_system;
        report.first_handle_owner_mcp = handle_report.first_owner_mcp;
        report.first_handle_owner_ai = handle_report.first_owner_ai;
        report.first_handle_owner_memory = handle_report.first_owner_memory;
        report.first_handle_owner_re = handle_report.first_owner_re;
        report.first_handle_owner_debugger = handle_report.first_owner_debugger;
        report.first_handle_owner_dump = handle_report.first_owner_dump;
        report.trusted_system_handle_access_mask = handle_report.trusted_system_access_mask;
        report.trusted_system_handle_owner_hash = handle_report.trusted_system_owner_hash;
        report.fileless_bootstrap_parent_handle_access_mask = handle_report.fileless_bootstrap_parent_access_mask;
        report.fileless_bootstrap_parent_handle_owner_pid = handle_report.fileless_bootstrap_parent_owner_pid;
        report.fileless_bootstrap_parent_handle_owner_hash = handle_report.fileless_bootstrap_parent_owner_hash;
        report.fileless_bootstrap_parent_handle_owner_image = handle_report.fileless_bootstrap_parent_owner_image;
        report.fileless_bootstrap_parent_handle_owner_path = handle_report.fileless_bootstrap_parent_owner_path;
        auto clipboard = detail::scan_clipboard_monitoring(&processes);
        report.clipboard_monitored = clipboard.suspicious;
        auto window_target = detail::scan_windows_for_aida_targeting(processes);
        report.tool_targets_aida = process_evidence.targets_aida || handle_report.owner_targets_aida || window_target.targeted;
        report.llm_detected = report.local_llm_detected && (report.mcp_detected ||
            report.ai_tool_detected || report.memory_scanner_detected ||
            report.re_tool_detected || report.debugger_tool_detected ||
            report.dump_tool_detected || report.handle_to_us_detected ||
            report.tool_targets_aida);
        report.evidence_hash = process_evidence.evidence_hash;
        if (pipe_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, pipe_hash);
        if (port_report.owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, port_report.owner_hash);
        if (handle_report.owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, handle_report.owner_hash);
        if (handle_report.trusted_system_owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, handle_report.trusted_system_owner_hash);
        if (handle_report.fileless_bootstrap_parent_owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, handle_report.fileless_bootstrap_parent_owner_hash);
        if (clipboard.owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, clipboard.owner_hash);
        if (window_target.owner_hash)
            report.evidence_hash = detail::mix_hash(report.evidence_hash, window_target.owner_hash);
        report.evidence_count = process_evidence.evidence_count;
        if (report.mcp_pipe_detected) set_category(report, category_mcp_pipe, "MCP_PIPE");
        if (report.mcp_process_detected) set_category(report, category_mcp_process, "MCP_PROCESS");
        if (report.mcp_port_detected) set_category(report, category_mcp_port, "MCP_PORT");
        if (report.mcp_command_server_detected) set_category(report, category_mcp_command_server, "MCP_CMD");
        if (report.ai_tool_detected) set_category(report, category_ai_coding_tool, "AI_TOOL");
        if (report.local_llm_detected) set_category(report, category_local_llm, "LOCAL_LLM");
        if (report.memory_scanner_detected) set_category(report, category_memory_scanner, "MEM_SCANNER");
        if (report.re_tool_detected) set_category(report, category_re_tool, "RE_TOOL");
        if (report.debugger_tool_detected) set_category(report, category_debugger_tool, "DBG_TOOL");
        if (report.dump_tool_detected) set_category(report, category_dump_tool, "DUMP_TOOL");
        if (report.offensive_mcp_tool_detected) set_category(report, category_offensive_mcp_tool, "MCP_OFFENSIVE_TOOL");
        if (report.foreign_vm_read_handle) set_category(report, category_foreign_read_handle, "HANDLE_READ");
        if (report.foreign_vm_write_handle) set_category(report, category_foreign_write_handle, "HANDLE_WRITE");
        if (report.foreign_vm_operation_handle) set_category(report, category_foreign_vm_operation, "HANDLE_VMOP");
        if (report.foreign_create_thread_handle) set_category(report, category_foreign_create_thread, "HANDLE_THREAD");
        if (report.clipboard_monitored) set_category(report, category_clipboard_monitor, "CLIP_MON");
        if (report.tool_targets_aida) set_category(report, category_targets_aida, "TARGET_AIDA");
        if (report.trusted_system_handle_ignored) {
            char ignored_buf[64];
            _snprintf_s(ignored_buf, sizeof(ignored_buf), _TRUNCATE,
                "IGNORED_SYSTEM_HANDLE=%u",
                report.trusted_system_handle_ignored_count);
            detail::append_token(report.summary, ignored_buf);
        }
        if (report.fileless_bootstrap_parent_handle_ignored) {
            char ignored_buf[80];
            _snprintf_s(ignored_buf, sizeof(ignored_buf), _TRUNCATE,
                "IGNORED_FILELESS_PARENT_HANDLE=%u",
                report.fileless_bootstrap_parent_handle_ignored_count);
            detail::append_token(report.summary, ignored_buf);
        }
        const bool mcp_correlated_risk = report.mcp_detected &&
            (report.memory_scanner_detected || report.re_tool_detected ||
             report.debugger_tool_detected || report.dump_tool_detected ||
             report.offensive_mcp_tool_detected ||
             report.foreign_vm_write_handle || report.foreign_vm_operation_handle ||
             report.foreign_create_thread_handle || report.tool_targets_aida ||
             (report.foreign_vm_read_handle && report.handle_owner_tool));
        if (mcp_correlated_risk)
            set_high_risk(report, report.category_mask & (category_mcp_pipe | category_mcp_process | category_mcp_port | category_mcp_command_server));
        if (report.memory_scanner_detected)
            set_high_risk(report, category_memory_scanner);
        if (report.re_tool_detected)
            set_high_risk(report, category_re_tool);
        if (report.debugger_tool_detected)
            set_high_risk(report, category_debugger_tool);
        if (report.dump_tool_detected)
            set_high_risk(report, category_dump_tool);
        if (report.offensive_mcp_tool_detected)
            set_high_risk(report, category_offensive_mcp_tool);
        if (report.foreign_vm_write_handle)
            set_high_risk(report, category_foreign_write_handle);
        if (report.foreign_vm_operation_handle)
            set_high_risk(report, category_foreign_vm_operation);
        if (report.foreign_create_thread_handle)
            set_high_risk(report, category_foreign_create_thread);
        if (report.tool_targets_aida)
            set_high_risk(report, category_targets_aida);
        if (report.llm_detected)
            set_high_risk(report, category_local_llm);
        report.high_risk_count = detail::popcount32(report.high_risk_mask);
        if (report.evidence_hash)
            detail::append_hex_token(report.summary, "evidence_hash", report.evidence_hash);
        if (report.dump_tool_hash)
            detail::append_hex_token(report.summary, "dump_hash", report.dump_tool_hash);
        char mask_buf[96];
        _snprintf_s(mask_buf, sizeof(mask_buf), _TRUNCATE,
            "cat=0x%08X high=0x%08X count=%u",
            report.category_mask,
            report.high_risk_mask,
            report.high_risk_count);
        detail::append_token(report.summary, mask_buf);
        report.summary_hash = detail::hash_string(report.summary);
        return report;
    }

}

inline combined::threat_report_t full_scan()
{
    return combined::full_scan();
}

}
