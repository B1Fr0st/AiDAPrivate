


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"
#include "../infra/work_queue.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../anti-tamper/state.hpp"
#include "../../helpers/diag_log.hpp"

#include <Zydis/Zydis.h>
#include "zydis_disasm.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <regex>
#include <unordered_map>
#include <vector>
#include <process.h>

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace driver_tools
{

static std::string to_lower_ascii_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

static bool full_test_mode_active()
{
    if (anti_tamper::state::get().full_test_running.load(std::memory_order_acquire))
        return true;
    char buf[8] = {};
    DWORD n = GetEnvironmentVariableA("AIDA_FULL_TEST_RUNNING", buf, static_cast<DWORD>(sizeof(buf)));
    return n > 0 && (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y');
}

static bool ranges_overlap(std::uint64_t a_start, std::uint64_t a_size, std::uint64_t b_start, std::uint64_t b_size)
{
    if (a_size == 0 || b_size == 0)
        return false;
    std::uint64_t a_end = a_start + a_size - 1;
    std::uint64_t b_end = b_start + b_size - 1;
    if (a_end < a_start)
        a_end = std::numeric_limits<std::uint64_t>::max();
    if (b_end < b_start)
        b_end = std::numeric_limits<std::uint64_t>::max();
    return a_start <= b_end && b_start <= a_end;
}

static bool range_intersects_system_module(std::uint64_t address, std::uint64_t size, std::string& module_name, std::string& module_path)
{
    const std::uint32_t pid = driver_bridge::attached_pid();
    if (pid == 0)
        return false;
    for (const auto& mod : driver_bridge::enumerate_modules_for(pid))
    {
        const std::uint64_t start = mod.base;
        const std::uint64_t mod_size = static_cast<std::uint64_t>(mod.size);
        if (start == 0 || mod_size == 0 || !ranges_overlap(address, size, start, mod_size))
            continue;
        module_name = mod.name;
        module_path = mod.path;
        const std::string name = to_lower_ascii_copy(mod.name);
        const std::string path = to_lower_ascii_copy(mod.path);
        if (path.find("\\windows\\") != std::string::npos ||
            path.find("/windows/") != std::string::npos ||
            name == "ntdll.dll" ||
            name == "kernel32.dll" ||
            name == "kernelbase.dll" ||
            name == "apphelp.dll" ||
            name == "win32u.dll")
            return true;
        return false;
    }
    return false;
}

static std::optional<tool_result_t> reject_full_test_system_mutation(std::uint64_t address, std::uint64_t size, const char* tool_name)
{
    if (!full_test_mode_active())
        return std::nullopt;
    std::string module_name;
    std::string module_path;
    if (!range_intersects_system_module(address, size, module_name, module_path))
        return std::nullopt;
    diag::log_tagged_fmt("drv_tools",
        "%s rejected full-test system module mutation addr=0x%llX size=%llu module=%s path=%s",
        tool_name ? tool_name : "driver_tool",
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(size),
        module_name.c_str(),
        module_path.c_str());
    return tool_result_t::error(
        OBFSTR("Full Test Lab refuses to mutate system module memory. Use a private target fixture address instead."));
}

static bool is_ida_host_process_name(const std::string& process_name)
{
    const std::string lower = to_lower_ascii_copy(process_name);
    return lower.find("ida.exe") != std::string::npos
        || lower.find("ida64.exe") != std::string::npos
        || lower.find("idat.exe") != std::string::npos
        || lower.find("idat64.exe") != std::string::npos;
}

static bool is_self_target_process_name(const std::string& process_name)
{
    const std::string lower = to_lower_ascii_copy(process_name);
    return lower.find("aidastan") != std::string::npos
        || lower.find("aida_stan") != std::string::npos
        || lower == "aida.exe";
}

static bool is_self_target_pid(uint32_t pid)
{
    return pid != 0 && pid == static_cast<uint32_t>(GetCurrentProcessId());
}

static std::string trim_ascii_copy(const std::string& text)
{
    const std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

static bool parse_u32_id_value(const json& value, std::uint32_t& out)
{
    if (value.is_number_unsigned())
    {
        const auto v = value.get<std::uint64_t>();
        if (v == 0 || v > 0xFFFFFFFFULL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (value.is_number_integer())
    {
        const auto v = value.get<std::int64_t>();
        if (v <= 0 || v > 0xFFFFFFFFLL)
            return false;
        out = static_cast<std::uint32_t>(v);
        return true;
    }

    if (!value.is_string())
        return false;

    std::string s = trim_ascii_copy(value.get<std::string>());
    if (s.empty())
        return false;

    try
    {
        std::size_t idx = 0;
        std::uint64_t parsed = 0;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            parsed = std::stoull(s, &idx, 16);
        else
            parsed = std::stoull(s, &idx, 10);

        if (idx != s.size() || parsed == 0 || parsed > 0xFFFFFFFFULL)
            return false;

        out = static_cast<std::uint32_t>(parsed);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

static bool parse_single_hex_byte_token(const std::string& raw_token, std::uint8_t& out)
{
    std::string token = trim_ascii_copy(raw_token);
    if (token.empty())
        return false;

    if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
        token = token.substr(2);

    if (token.empty())
        return false;

    const bool all_hex = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; });
    const bool has_hex_alpha = std::any_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isalpha(c) != 0; });

    if (all_hex)
    {
        try
        {
            std::uint64_t v16 = std::stoull(token, nullptr, 16);
            if (v16 <= 0xFFULL && (has_hex_alpha || token.size() <= 2))
            {
                out = static_cast<std::uint8_t>(v16);
                return true;
            }
        }
        catch (...) {}
    }

    const bool all_digits = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isdigit(c) != 0; });
    if (all_digits)
    {
        try
        {
            std::uint64_t v10 = std::stoull(token, nullptr, 10);
            if (v10 <= 0xFFULL)
            {
                out = static_cast<std::uint8_t>(v10);
                return true;
            }
        }
        catch (...) {}
    }

    return false;
}

static bool parse_byte_sequence(const json& bytes_value, std::vector<std::uint8_t>& out, std::string& error)
{
    out.clear();

    if (bytes_value.is_array())
    {
        for (std::size_t i = 0; i < bytes_value.size(); ++i)
        {
            const auto& item = bytes_value[i];
            if (item.is_number_integer())
            {
                const auto v = item.get<std::int64_t>();
                if (v < 0 || v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_number_unsigned())
            {
                const auto v = item.get<std::uint64_t>();
                if (v > 255)
                {
                    error = "Byte array value out of range at index " + std::to_string(i) + " (expected 0..255).";
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(v));
                continue;
            }

            if (item.is_string())
            {
                std::uint8_t b = 0;
                if (!parse_single_hex_byte_token(item.get<std::string>(), b))
                {
                    error = "Invalid byte token at index " + std::to_string(i) + ".";
                    return false;
                }
                out.push_back(b);
                continue;
            }

            error = "Unsupported bytes array element type at index " + std::to_string(i) + ".";
            return false;
        }

        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (!bytes_value.is_string())
    {
        error = "'bytes' must be either a string or an array.";
        return false;
    }

    std::string text = trim_ascii_copy(bytes_value.get<std::string>());
    if (text.empty())
    {
        error = "No bytes were provided.";
        return false;
    }

    if (!text.empty() && text.front() == '[')
    {
        try
        {
            json parsed = json::parse(text);
            if (!parsed.is_array())
            {
                error = "String bytes payload starts with '[' but is not a valid array.";
                return false;
            }
            return parse_byte_sequence(parsed, out, error);
        }
        catch (...)
        {
            error = "Failed to parse bytes array string.";
            return false;
        }
    }

    std::string tokenized = text;
    std::replace(tokenized.begin(), tokenized.end(), ',', ' ');
    if (tokenized.find(' ') != std::string::npos || tokenized.find('\t') != std::string::npos ||
        tokenized.find('\n') != std::string::npos || tokenized.find('\r') != std::string::npos)
    {
        std::istringstream iss(tokenized);
        std::string token;
        std::size_t index = 0;
        while (iss >> token)
        {
            std::uint8_t b = 0;
            if (!parse_single_hex_byte_token(token, b))
            {
                error = "Invalid hex byte token '" + token + "' at position " + std::to_string(index) + ".";
                return false;
            }
            out.push_back(b);
            ++index;
        }
        if (out.empty())
            error = "No bytes were provided.";
        return !out.empty();
    }

    if (tokenized.size() > 2 && tokenized[0] == '0' && (tokenized[1] == 'x' || tokenized[1] == 'X'))
        tokenized = tokenized.substr(2);

    if (tokenized.size() % 2 != 0)
    {
        error = "Packed hex string must contain an even number of hex digits.";
        return false;
    }

    if (!std::all_of(tokenized.begin(), tokenized.end(),
        [](unsigned char c) { return std::isxdigit(c) != 0; }))
    {
        error = "Packed hex string contains non-hex characters.";
        return false;
    }

    for (std::size_t i = 0; i < tokenized.size(); i += 2)
    {
        const std::string byte_str = tokenized.substr(i, 2);
        out.push_back(static_cast<std::uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }

    if (out.empty())
        error = "No bytes were provided.";

    return !out.empty();
}

static bool is_process_alive(std::uint32_t pid)
{
    if (pid == 0)
        return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return false;

    DWORD exit_code = 0;
    const bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
    CloseHandle(h);

    return ok && exit_code == STILL_ACTIVE;
}

static std::optional<tool_result_t> ensure_attached_process_context(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    std::uint32_t requested_pid = 0;
    for (const char* key : {"target_pid", "process_id", "pid"})
    {
        if (!params.contains(key))
            continue;
        if (!parse_u32_id_value(params[key], requested_pid))
            return tool_result_t::error(std::string(OBFSTR("Invalid ")) + key + OBFSTR(". Expected a positive decimal PID or 0x-prefixed hex PID."));
        if (requested_pid != 0)
            break;
    }

    if (requested_pid != 0 && is_self_target_pid(requested_pid))
        return tool_result_t::error(OBFSTR("Cannot target AiDA's own process."));

    const std::uint32_t current_pid = driver_bridge::attached_pid();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        if (!is_process_alive(requested_pid))
            return tool_result_t::error(OBFSTR("target_pid ") + std::to_string(requested_pid) + OBFSTR(" is not alive."));

        const auto attached = driver_bridge::attached_pids();
        bool in_map = false;
        for (auto p : attached) { if (p == requested_pid) { in_map = true; break; } }
        if (!in_map)
        {
            if (!driver_bridge::attach_additional(requested_pid))
            {
                return tool_result_t::error(OBFSTR("attach_additional failed for target_pid ") + std::to_string(requested_pid) +
                                            OBFSTR(": ") + driver_bridge::last_error());
            }
        }

        if (current_pid != 0)
            stealth_engine::disable_for_detach(current_pid, "driver_tools.ensure_attached_context.replace");

        if (!driver_bridge::set_active_pid(requested_pid))
        {
            if (current_pid != 0 && driver_bridge::attached_pid() == current_pid)
                (void)stealth_engine::ensure_default_enabled(current_pid, "driver_tools.ensure_attached_context.restore_failed_switch");
            return tool_result_t::error(OBFSTR("set_active_pid failed for target_pid ") + std::to_string(requested_pid) +
                                        OBFSTR(": ") + driver_bridge::last_error());
        }

        (void)stealth_engine::ensure_default_enabled(requested_pid, "driver_tools.ensure_attached_context");

        if (device->get_dtb() == 0)
        {
            device->solve_dtb();
            if (device->get_dtb() == 0)
                return tool_result_t::error(OBFSTR("Failed to solve DTB for target_pid ") + std::to_string(requested_pid) + OBFSTR("."));
        }
    }

    if (driver_bridge::attached_pid() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Use sessions_manage action=attach_pid or pass target_pid."));

    if (!is_process_alive(driver_bridge::attached_pid()))
    {
        const std::uint32_t dead_pid = driver_bridge::attached_pid();
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Attached process PID ") + std::to_string(dead_pid) + OBFSTR(" is no longer alive. Reattach with sessions_manage action=attach_pid."));
    }

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB for the attached process."));
    }

    return std::nullopt;
}

static std::optional<std::uint32_t> parse_tid_param(const json& params)
{
    if (!params.contains("tid"))
        return std::nullopt;

    std::uint32_t tid = 0;
    if (!parse_u32_id_value(params["tid"], tid) || tid == 0)
        return std::nullopt;
    return tid;
}

static bool thread_belongs_to_attached_process(HANDLE thread, std::uint32_t tid)
{
    const std::uint32_t attached_pid = driver_bridge::attached_pid();
    if (attached_pid == 0)
        return false;
    const DWORD owner_pid = GetProcessIdOfThread(thread);
    if (owner_pid == 0) {
        diag::log_tagged_fmt("drv_tools", "thread owner lookup failed tid=%u gle=%lu", tid, static_cast<unsigned long>(GetLastError()));
        return false;
    }
    if (owner_pid != attached_pid) {
        diag::log_tagged_fmt("drv_tools", "thread owner mismatch tid=%u owner_pid=%lu attached_pid=%u", tid, static_cast<unsigned long>(owner_pid), attached_pid);
        return false;
    }
    return true;
}

static bool set_thread_context_win32_fallback(std::uint32_t tid,
                                              const voyager::device_t::thread_context& requested,
                                              std::uint64_t mask)
{
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!thread) {
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback OpenThread failed tid=%u gle=%lu", tid, static_cast<unsigned long>(GetLastError()));
        return false;
    }

    auto close_and_return = [&](bool result) {
        CloseHandle(thread);
        return result;
    };

    if (!thread_belongs_to_attached_process(thread, tid))
        return close_and_return(false);

    const DWORD suspend_previous = SuspendThread(thread);
    if (suspend_previous == static_cast<DWORD>(-1)) {
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback SuspendThread failed tid=%u gle=%lu", tid, static_cast<unsigned long>(GetLastError()));
        return close_and_return(false);
    }

    CONTEXT native{};
    native.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &native)) {
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback GetThreadContext failed tid=%u gle=%lu", tid, static_cast<unsigned long>(GetLastError()));
        (void)ResumeThread(thread);
        return close_and_return(false);
    }

    if (mask & (1ULL << 0)) native.Rax = requested.rax;
    if (mask & (1ULL << 1)) native.Rbx = requested.rbx;
    if (mask & (1ULL << 2)) native.Rcx = requested.rcx;
    if (mask & (1ULL << 3)) native.Rdx = requested.rdx;
    if (mask & (1ULL << 4)) native.Rsi = requested.rsi;
    if (mask & (1ULL << 5)) native.Rdi = requested.rdi;
    if (mask & (1ULL << 6)) native.Rbp = requested.rbp;
    if (mask & (1ULL << 7)) native.Rsp = requested.rsp;
    if (mask & (1ULL << 8)) native.R8 = requested.r8;
    if (mask & (1ULL << 9)) native.R9 = requested.r9;
    if (mask & (1ULL << 10)) native.R10 = requested.r10;
    if (mask & (1ULL << 11)) native.R11 = requested.r11;
    if (mask & (1ULL << 12)) native.R12 = requested.r12;
    if (mask & (1ULL << 13)) native.R13 = requested.r13;
    if (mask & (1ULL << 14)) native.R14 = requested.r14;
    if (mask & (1ULL << 15)) native.R15 = requested.r15;
    if (mask & (1ULL << 16)) native.Rip = requested.rip;
    if (mask & (1ULL << 17)) native.EFlags = static_cast<DWORD>(requested.rflags);
    if (mask & (1ULL << 18)) native.Dr0 = requested.dr0;
    if (mask & (1ULL << 19)) native.Dr1 = requested.dr1;
    if (mask & (1ULL << 20)) native.Dr2 = requested.dr2;
    if (mask & (1ULL << 21)) native.Dr3 = requested.dr3;
    if (mask & (1ULL << 22)) native.Dr6 = requested.dr6;
    if (mask & (1ULL << 23)) native.Dr7 = requested.dr7;

    const bool ok = SetThreadContext(thread, &native) != FALSE;
    if (!ok)
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback SetThreadContext failed tid=%u mask=0x%llX gle=%lu", tid, static_cast<unsigned long long>(mask), static_cast<unsigned long>(GetLastError()));
    else
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback succeeded tid=%u mask=0x%llX suspend_previous=%lu", tid, static_cast<unsigned long long>(mask), static_cast<unsigned long>(suspend_previous));

    if (ResumeThread(thread) == static_cast<DWORD>(-1))
        diag::log_tagged_fmt("drv_tools", "set_thread_context fallback ResumeThread failed tid=%u gle=%lu", tid, static_cast<unsigned long>(GetLastError()));

    return close_and_return(ok);
}

static bool is_probably_kernel_address(std::uint64_t address);

struct native_client_id_t
{
    void* unique_process = nullptr;
    void* unique_thread = nullptr;
};

struct native_thread_basic_information_t
{
    NTSTATUS exit_status = 0;
    void* teb_base_address = nullptr;
    native_client_id_t client_id{};
    std::uintptr_t affinity_mask = 0;
    LONG priority = 0;
    LONG base_priority = 0;
};

static bool query_thread_teb_address(std::uint32_t tid, std::uint64_t& out_teb, std::string& error)
{
    out_teb = 0;
    native_thread_basic_information_t tbi{};
    std::uint32_t returned = 0;
    if (!driver_bridge::query_thread_information(tid, 0, &tbi, static_cast<std::uint32_t>(sizeof(tbi)), &returned))
    {
        error = OBFSTR("NtQueryInformationThread(ThreadBasicInformation) failed for TID ") + std::to_string(tid);
        return false;
    }

    const std::uint64_t teb = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(tbi.teb_base_address));
    if (teb == 0 || is_probably_kernel_address(teb))
    {
        error = OBFSTR("ThreadBasicInformation returned an invalid TEB address for TID ") + std::to_string(tid);
        return false;
    }

    const std::uint32_t attached_pid = driver_bridge::attached_pid();
    const std::uint32_t tbi_pid = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(tbi.client_id.unique_process) & 0xFFFFFFFFu);
    if (attached_pid != 0 && tbi_pid != 0 && tbi_pid != attached_pid)
    {
        error = OBFSTR("TID ") + std::to_string(tid) + OBFSTR(" belongs to PID ") +
            std::to_string(tbi_pid) + OBFSTR(", not attached PID ") + std::to_string(attached_pid);
        return false;
    }

    out_teb = teb;
    return true;
}

static bool resolve_teb_address_for_thread(std::uint32_t tid,
                                           const voyager::device_t::thread_context& ctx,
                                           std::uint64_t& out_teb,
                                           std::string& source,
                                           std::string& error)
{
    out_teb = ctx.kernel_gs_base;
    source = OBFSTR("thread_context.kernel_gs_base");
    if (out_teb != 0 && !is_probably_kernel_address(out_teb))
        return true;

    if (query_thread_teb_address(tid, out_teb, error))
    {
        source = OBFSTR("NtQueryInformationThread.ThreadBasicInformation.TebBaseAddress");
        return true;
    }

    if (ctx.kernel_gs_base != 0 && is_probably_kernel_address(ctx.kernel_gs_base))
        error = OBFSTR("thread context reported a kernel GS base instead of a user TEB and ") + error;
    return false;
}

static bool resolve_teb_address_for_thread(std::uint32_t tid,
                                           const driver_bridge::thread_context_t& ctx,
                                           std::uint64_t& out_teb,
                                           std::string& source,
                                           std::string& error)
{
    out_teb = 0;
    if (query_thread_teb_address(tid, out_teb, error))
    {
        source = OBFSTR("NtQueryInformationThread.ThreadBasicInformation.TebBaseAddress");
        return true;
    }
    source = OBFSTR("bridge_thread_context");
    if (ctx.rip == 0 || ctx.rsp == 0)
        error = OBFSTR("bridge context did not contain a valid RIP/RSP and ") + error;
    return false;
}

static bool is_probably_kernel_address(std::uint64_t address)
{
    return address >= 0xFFFF000000000000ULL;
}

static std::string read_remote_unicode_ascii(voyager::device_t* dev,
                                             std::uint64_t ptr,
                                             std::uint16_t byte_len,
                                             std::uint16_t max_len)
{
    if (dev == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
        return {};

    std::vector<std::uint8_t> raw(byte_len, 0);
    if (dev->read_raw(ptr, raw.data(), byte_len) == 0)
        return {};

    std::string text;
    text.reserve(byte_len / 2);
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
    {
        const std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
        if (wc == 0)
            break;
        text += (wc >= 32 && wc < 128) ? static_cast<char>(wc) : '?';
    }

    return text;
}

static bool resolve_loaded_module_base(const std::string& query,
                                       std::uint64_t& out_base,
                                       std::string& out_name)
{
    out_base = 0;
    out_name.clear();

    if (!device || !device->is_connected() || device->get_process_id() == 0 || query.empty())
        return false;

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return false;

    const std::string needle = to_lower_ascii_copy(query);
    const std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t current = device->read<std::uint64_t>(list_head);
    if (current == 0 || current == list_head)
        return false;

    auto basename_of_path = [](const std::string& path) {
        const std::size_t pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    };

    std::uint64_t partial_base = 0;
    std::string partial_name;
    int max_iter = 1024;

    while (current != list_head && current != 0 && max_iter-- > 0)
    {
        const std::uint64_t base = device->read<std::uint64_t>(current + 0x30);
        const std::string module_name = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x60),
            device->read<std::uint16_t>(current + 0x58),
            520);
        const std::string module_path = read_remote_unicode_ascii(
            device.get(),
            device->read<std::uint64_t>(current + 0x50),
            device->read<std::uint16_t>(current + 0x48),
            1024);

        const std::string lower_name = to_lower_ascii_copy(module_name);
        const std::string lower_path = to_lower_ascii_copy(module_path);
        const std::string lower_file = to_lower_ascii_copy(basename_of_path(module_path));

        const bool exact_match = (lower_name == needle || lower_path == needle || lower_file == needle);
        const bool partial_match = !exact_match &&
            (lower_name.find(needle) != std::string::npos ||
             lower_path.find(needle) != std::string::npos ||
             lower_file.find(needle) != std::string::npos);

        if (base != 0 && exact_match)
        {
            out_base = base;
            out_name = module_name.empty() ? module_path : module_name;
            return true;
        }

        if (base != 0 && partial_match && partial_base == 0)
        {
            partial_base = base;
            partial_name = module_name.empty() ? module_path : module_name;
        }

        const std::uint64_t next = device->read<std::uint64_t>(current);
        if (next == current || next == 0)
            break;
        current = next;
    }

    if (partial_base != 0)
    {
        out_base = partial_base;
        out_name = partial_name;
        return true;
    }

    return false;
}









struct vad_dump_plan_t
{
    std::uint64_t module_base = 0;
    std::uint64_t pe_size_of_image = 0;
    std::uint64_t total_span = 0;
    std::uint64_t total_committed_bytes = 0;
    int committed_region_count = 0;
    bool used_vad = false;

    struct region_t
    {
        std::uint64_t offset;
        std::uint64_t size;
        std::uint32_t protect;
    };
    std::vector<region_t> regions;
};


static std::vector<voyager::detail::region_entry> enumerate_all_memory_regions_paginated(
    voyager::device_t* dev,
    std::uint64_t start,
    std::uint64_t end_addr,
    bool include_all)
{


    std::vector<voyager::detail::region_entry> all_regions;
    std::uint64_t current_start = start;
    constexpr int MAX_PAGINATION_ROUNDS = 256;

    for (int round = 0; round < MAX_PAGINATION_ROUNDS; round++)
    {
        if (current_start >= end_addr)
            break;

        auto batch = dev->enumerate_memory_regions(current_start, end_addr, include_all);
        if (batch.empty())
            break;

        std::uint64_t batch_max_end = 0;
        for (const auto& r : batch)
        {
            all_regions.push_back(r);
            std::uint64_t rend = r.base + r.size;
            if (rend > batch_max_end)
                batch_max_end = rend;
        }


        if (batch.size() < voyager::detail::MAX_ENUM_REGIONS)
            break;


        if (batch_max_end <= current_start)
            break;
        current_start = batch_max_end;
    }

    return all_regions;
}

static std::uint64_t get_ldr_module_size(voyager::device_t* dev, std::uint64_t module_base)
{


    struct ldr_module_info_t
    {
        std::uint64_t base = 0;
        std::uint64_t entry_point = 0;
        std::uint32_t size = 0;
        std::string name;
        std::string path;
    };

    auto to_lower_ascii = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    };

    auto read_remote_unicode_ascii = [](voyager::device_t* device,
                                        std::uint64_t ptr,
                                        std::uint16_t byte_len,
                                        std::uint16_t max_len) -> std::string {
        if (device == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
            return {};

        std::vector<std::uint8_t> raw(byte_len, 0);
        if (device->read_raw(ptr, raw.data(), byte_len) == 0)
            return {};

        std::string text;
        text.reserve(byte_len / 2);
        for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
        {
            std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
            if (wc == 0)
                break;
            text += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        return text;
    };

    auto visit_ldr_modules = [&](const std::function<bool(const ldr_module_info_t&)>& visitor) -> bool {
        if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
            return false;

        voyager::device_t::peb_info peb{};
        if (!dev->read_peb(peb) || peb.ldr_address == 0)
            return false;

        std::uint64_t list_head = peb.ldr_address + 0x10;
        std::uint64_t first_entry = dev->read<std::uint64_t>(list_head);
        if (first_entry == 0 || first_entry == list_head)
            return false;

        std::uint64_t current = first_entry;
        int max_iter = 1024;

        while (current != list_head && current != 0 && max_iter-- > 0)
        {
            ldr_module_info_t info;
            info.base        = dev->read<std::uint64_t>(current + 0x30);
            info.entry_point = dev->read<std::uint64_t>(current + 0x38);
            info.size        = dev->read<std::uint32_t>(current + 0x40);
            info.path        = read_remote_unicode_ascii(
                dev,
                dev->read<std::uint64_t>(current + 0x50),
                dev->read<std::uint16_t>(current + 0x48),
                1024);
            info.name        = read_remote_unicode_ascii(
                dev,
                dev->read<std::uint64_t>(current + 0x60),
                dev->read<std::uint16_t>(current + 0x58),
                520);

            if (info.base != 0 && !info.name.empty() && visitor(info))
                return true;

            std::uint64_t next = dev->read<std::uint64_t>(current);
            if (next == current)
                break;
            current = next;
        }

        return true;
    };

    ldr_module_info_t found;
    bool matched = false;
    visit_ldr_modules([&](const ldr_module_info_t& info) {
        if (info.base != module_base)
            return false;
        found = info;
        matched = true;
        return true;
    });
    return matched ? static_cast<std::uint64_t>(found.size) : 0;
}

static void cleanup_exception_directory(
    std::vector<std::uint8_t>& image,
    bool is_pe64)
{


    if (image.size() < 0x200 || !is_pe64)
        return;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    std::uint32_t opt_off = pe_off + 24;


    std::uint32_t dd_base = opt_off + 112;
    std::uint32_t exc_dir_off = dd_base + 3 * 8;
    if (exc_dir_off + 8 > static_cast<std::uint32_t>(image.size()))
        return;

    std::uint32_t exc_rva  = *reinterpret_cast<std::uint32_t*>(&image[exc_dir_off]);
    std::uint32_t exc_size = *reinterpret_cast<std::uint32_t*>(&image[exc_dir_off + 4]);

    if (exc_rva == 0 || exc_size == 0)
        return;
    if (exc_rva >= static_cast<std::uint32_t>(image.size()))
        return;


    constexpr std::uint32_t RTFUNC_SIZE = 12;
    std::uint32_t image_size = static_cast<std::uint32_t>(image.size());
    int cleaned = 0;

    for (std::uint32_t off = exc_rva; off + RTFUNC_SIZE <= exc_rva + exc_size && off + RTFUNC_SIZE <= image_size; off += RTFUNC_SIZE)
    {
        std::uint32_t begin_addr   = *reinterpret_cast<std::uint32_t*>(&image[off]);
        std::uint32_t end_addr     = *reinterpret_cast<std::uint32_t*>(&image[off + 4]);
        std::uint32_t unwind_addr  = *reinterpret_cast<std::uint32_t*>(&image[off + 8]);

        if (begin_addr == 0 && end_addr == 0 && unwind_addr == 0)
            continue;

        bool valid = true;


        if (begin_addr >= image_size || end_addr >= image_size)
            valid = false;
        if (begin_addr >= end_addr)
            valid = false;
        if (unwind_addr >= image_size)
            valid = false;


        if (valid && unwind_addr > 0 && unwind_addr < image_size)
        {
            std::uint8_t version = image[unwind_addr] & 0x07;
            if (version != 1 && version != 2)
                valid = false;
        }

        if (!valid)
        {
            std::memset(&image[off], 0, RTFUNC_SIZE);
            cleaned++;
        }
    }

    if (cleaned > 0)
        msg(OBFSTR_C("AiDA: Cleaned %d invalid runtime function entries from exception directory\n"), cleaned);
}


struct pe_fix_result_t
{
    bool success = false;
    std::string error;
    int sections_fixed = 0;
    int iat_entries_restored = 0;
    int import_dlls_found = 0;
    bool entry_point_valid = false;
    bool entry_point_fixed = false;
    std::uint32_t original_ep_rva = 0;
    std::uint32_t fixed_ep_rva = 0;
    bool security_dir_cleared = false;
    bool debug_dir_cleared = false;
    bool checksum_cleared = false;
    bool file_alignment_fixed = false;
    bool is_pe64 = false;
    bool reloc_dir_cleared = false;
    bool relocs_stripped_flag_set = false;
    bool reloc_section_zeroed = false;
    bool tls_dir_cleared = false;
    bool loadconfig_dir_cleared = false;
    bool delay_import_dir_cleared = false;
    bool com_dir_cleared = false;
    bool is_dotnet = false;
    bool dotnet_com_preserved = false;
    bool dotnet_com_restored = false;
    bool imagebase_updated = false;
    std::uint64_t original_imagebase = 0;
    std::uint64_t updated_imagebase = 0;
    bool ep_prologue_scanned = false;
    std::vector<std::string> import_dll_names;
    bool extended_image = false;
    std::uint32_t original_size_of_image = 0;
    std::uint32_t updated_size_of_image = 0;
    bool vad_section_added = false;
    int vad_sections_added = 0;
};

static pe_fix_result_t fix_dumped_pe_image(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base)
{
    pe_fix_result_t result;

    if (image.size() < 0x100)
    {
        result.error = "Image too small for PE";
        return result;
    }

    if (image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid MZ signature";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()))
    {
        result.error = "PE header offset out of range";
        return result;
    }

    if (image[pe_off] != 'P' || image[pe_off + 1] != 'E' ||
        image[pe_off + 2] != 0   || image[pe_off + 3] != 0)
    {
        result.error = "Invalid PE signature";
        return result;
    }

    std::uint16_t num_sections  = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size  = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off       = pe_off + 24;

    if (opt_off + 2 >= static_cast<std::uint32_t>(image.size()))
    {
        result.error = "Optional header out of range";
        return result;
    }

    std::uint16_t opt_magic = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    result.is_pe64 = (opt_magic == 0x020B);
    bool is_pe32   = (opt_magic == 0x010B);

    if (!result.is_pe64 && !is_pe32)
    {
        result.error = "Unknown PE optional header magic";
        return result;
    }

    std::uint32_t image_size_from_header = 0;
    if (opt_off + 60 <= static_cast<std::uint32_t>(image.size()))
        image_size_from_header = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]);

    std::uint32_t section_table_off = pe_off + 24 + opt_hdr_size;

    std::uint32_t dd_base = result.is_pe64 ? (opt_off + 112) : (opt_off + 96);

    if (opt_off + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::uint32_t sec_align = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
        std::uint32_t fil_align = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 36]);
        if (sec_align != 0 && fil_align != sec_align)
        {
            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 36]) = sec_align;
            result.file_alignment_fixed = true;
        }
    }

    if (module_base != 0)
    {
        if (result.is_pe64)
        {
            if (opt_off + 32 <= static_cast<std::uint32_t>(image.size()))
            {
                result.original_imagebase = *reinterpret_cast<std::uint64_t*>(&image[opt_off + 24]);
                *reinterpret_cast<std::uint64_t*>(&image[opt_off + 24]) = module_base;
                result.updated_imagebase = module_base;
                result.imagebase_updated = (result.original_imagebase != module_base);
            }
        }
        else
        {
            if (opt_off + 32 <= static_cast<std::uint32_t>(image.size()))
            {
                result.original_imagebase = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 28]);
                *reinterpret_cast<std::uint32_t*>(&image[opt_off + 28]) =
                    static_cast<std::uint32_t>(module_base);
                result.updated_imagebase = module_base;
                result.imagebase_updated = (result.original_imagebase != module_base);
            }
        }
    }

    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t sec_off = section_table_off + i * 40;
        if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t virt_size = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
        std::uint32_t virt_addr = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
        std::uint32_t raw_size  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);

        if (virt_addr == 0 || virt_size == 0) continue;

        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 20]) = virt_addr;

        std::uint32_t new_raw = (virt_size > raw_size) ? virt_size : raw_size;
        if (virt_addr + new_raw > static_cast<std::uint32_t>(image.size()))
            new_raw = static_cast<std::uint32_t>(image.size()) - virt_addr;
        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]) = new_raw;

        *reinterpret_cast<std::uint32_t*>(&image[sec_off + 24]) = 0;
        *reinterpret_cast<std::uint16_t*>(&image[sec_off + 32]) = 0;
        *reinterpret_cast<std::uint16_t*>(&image[sec_off + 34]) = 0;

        result.sections_fixed++;
    }

    if (opt_off + 68 <= static_cast<std::uint32_t>(image.size()))
    {
        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 64]) = 0;
        result.checksum_cleared = true;
    }

    {
        std::uint32_t sec_dir_off = dd_base + 4 * 8;
        if (sec_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t sec_rva = *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off]);
            if (sec_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[sec_dir_off + 4]) = 0;
                result.security_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t dbg_dir_off = dd_base + 6 * 8;
        if (dbg_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t dbg_rva = *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off]);
            if (dbg_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[dbg_dir_off + 4]) = 0;
                result.debug_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t reloc_dir_off = dd_base + 5 * 8;
        if (reloc_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t reloc_rva = *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off]);
            if (reloc_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[reloc_dir_off + 4]) = 0;
                result.reloc_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t tls_dir_off = dd_base + 9 * 8;
        if (tls_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t tls_rva = *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off]);
            if (tls_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[tls_dir_off + 4]) = 0;
                result.tls_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t lc_dir_off = dd_base + 10 * 8;
        if (lc_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t lc_rva = *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off]);
            if (lc_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[lc_dir_off + 4]) = 0;
                result.loadconfig_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t di_dir_off = dd_base + 13 * 8;
        if (di_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t di_rva = *reinterpret_cast<std::uint32_t*>(&image[di_dir_off]);
            if (di_rva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[di_dir_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[di_dir_off + 4]) = 0;
                result.delay_import_dir_cleared = true;
            }
        }
    }

    {
        std::uint32_t com_dir_off = dd_base + 14 * 8;

        bool dotnet_detected = false;
        std::uint32_t bsjb_rva = 0;
        {
            constexpr std::size_t SCAN_LIMIT = 0x800000;
            std::size_t scan_end = std::min(image.size(), SCAN_LIMIT);
            for (std::size_t i = 0x200; i + 4 <= scan_end; i++)
            {
                if (image[i] == 0x42 && image[i + 1] == 0x53 &&
                    image[i + 2] == 0x4A && image[i + 3] == 0x42)
                {
                    dotnet_detected = true;
                    bsjb_rva = static_cast<std::uint32_t>(i);
                    break;
                }
            }
        }

        result.is_dotnet = dotnet_detected;

        if (dotnet_detected)
        {
            if (com_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t com_rva  = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off]);
                std::uint32_t com_size = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]);

                if (com_rva != 0 && com_rva < static_cast<std::uint32_t>(image.size()) && com_size >= 72)
                {
                    result.dotnet_com_preserved = true;
                }
                else if (bsjb_rva > 0)
                {
                    std::uint32_t metadata_rva = 0;
                    std::uint32_t metadata_size = 0;

                    if (bsjb_rva >= 16)
                    {
                        for (std::uint32_t scan = bsjb_rva - 16; scan > 0x200 && scan > bsjb_rva - 0x2000; scan--)
                        {
                            if (scan + 72 > static_cast<std::uint32_t>(image.size())) continue;

                            std::uint32_t cb = *reinterpret_cast<std::uint32_t*>(&image[scan]);
                            if (cb < 72 || cb > 0x1000) continue;

                            std::uint16_t major = *reinterpret_cast<std::uint16_t*>(&image[scan + 4]);
                            std::uint16_t minor = *reinterpret_cast<std::uint16_t*>(&image[scan + 6]);
                            if (major < 1 || major > 5) continue;
                            if (minor > 10) continue;

                            std::uint32_t meta_rva  = *reinterpret_cast<std::uint32_t*>(&image[scan + 8]);
                            std::uint32_t meta_size = *reinterpret_cast<std::uint32_t*>(&image[scan + 12]);

                            if (meta_rva > 0 && meta_rva < static_cast<std::uint32_t>(image.size()) &&
                                meta_size > 0 && meta_rva + meta_size <= static_cast<std::uint32_t>(image.size()))
                            {
                                if (meta_rva <= bsjb_rva && bsjb_rva < meta_rva + meta_size)
                                {
                                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off])     = scan;
                                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]) = cb;
                                    result.dotnet_com_restored = true;
                                    metadata_rva = meta_rva;
                                    metadata_size = meta_size;
                                    break;
                                }
                            }
                        }
                    }

                    if (!result.dotnet_com_restored)
                    {
                        result.dotnet_com_preserved = true;
                    }
                }
            }
        }
        else
        {
            if (com_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t com_rva = *reinterpret_cast<std::uint32_t*>(&image[com_dir_off]);
                if (com_rva != 0)
                {
                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off])     = 0;
                    *reinterpret_cast<std::uint32_t*>(&image[com_dir_off + 4]) = 0;
                    result.com_dir_cleared = true;
                }
            }
        }
    }

    {
        std::uint32_t chars_off = pe_off + 18;
        if (chars_off + 2 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint16_t characteristics = *reinterpret_cast<std::uint16_t*>(&image[chars_off]);
            if (!(characteristics & 0x0001))
            {
                characteristics |= 0x0001;
                *reinterpret_cast<std::uint16_t*>(&image[chars_off]) = characteristics;
                result.relocs_stripped_flag_set = true;
            }
        }
    }

    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t sec_off = section_table_off + i * 40;
        if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

        char sec_name[9] = {};
        std::memcpy(sec_name, &image[sec_off], 8);

        if (std::strcmp(sec_name, ".reloc") == 0)
        {
            std::uint32_t virt_addr = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
            std::uint32_t raw_size  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);

            if (virt_addr > 0 && virt_addr < static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t zero_end = virt_addr + raw_size;
                if (zero_end > static_cast<std::uint32_t>(image.size()))
                    zero_end = static_cast<std::uint32_t>(image.size());
                std::memset(&image[virt_addr], 0, zero_end - virt_addr);
                result.reloc_section_zeroed = true;
            }
            break;
        }
    }

    {
        std::uint32_t ep_rva = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]);
        result.original_ep_rva = ep_rva;
        result.fixed_ep_rva    = ep_rva;

        bool ep_ok = false;

        if (ep_rva > 0 && ep_rva < static_cast<std::uint32_t>(image.size()))
        {
            for (int i = 0; i < num_sections && i < 96; i++)
            {
                std::uint32_t sec_off = section_table_off + i * 40;
                if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                std::uint32_t va  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                std::uint32_t vs  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
                std::uint32_t ch  = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                if (ep_rva >= va && ep_rva < va + vs && (ch & 0x20000000))
                {
                    if (image[ep_rva] != 0x00 && image[ep_rva] != 0xCC)
                        ep_ok = true;
                    break;
                }
            }
        }

        if (!ep_ok && (ep_rva == 0 || ep_rva >= static_cast<std::uint32_t>(image.size())))
        {
            if (dd_base + 8 <= static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&image[dd_base]);
                std::uint32_t export_size = *reinterpret_cast<std::uint32_t*>(&image[dd_base + 4]);
                (void)export_size;

                if (export_rva != 0 && export_rva + 40 <= static_cast<std::uint32_t>(image.size()))
                {
                    std::uint32_t num_funcs   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 20]);
                    std::uint32_t num_names   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 24]);
                    std::uint32_t funcs_rva   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 28]);
                    std::uint32_t names_rva   = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 32]);
                    std::uint32_t ords_rva    = *reinterpret_cast<std::uint32_t*>(&image[export_rva + 36]);
                    (void)num_funcs;

                    static const char* const entry_names[] = {
                        "DriverEntry", "GsDriverEntry", "DllMain",
                        "DllEntryPoint", "main", "wmain", "WinMain",
                        "wWinMain", "_DllMainCRTStartup", "mainCRTStartup"
                    };

                    for (std::uint32_t j = 0; j < num_names && j < 10000; j++)
                    {
                        if (names_rva + (j + 1) * 4 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint32_t nrva = *reinterpret_cast<std::uint32_t*>(
                            &image[names_rva + j * 4]);
                        if (nrva == 0 || nrva >= static_cast<std::uint32_t>(image.size())) continue;

                        const char* exp_name = reinterpret_cast<const char*>(&image[nrva]);
                        bool matched = false;
                        for (auto en : entry_names)
                        {
                            if (std::strcmp(exp_name, en) == 0) { matched = true; break; }
                        }
                        if (!matched) continue;

                        if (ords_rva + (j + 1) * 2 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint16_t ordinal = *reinterpret_cast<std::uint16_t*>(
                            &image[ords_rva + j * 2]);
                        if (funcs_rva + (ordinal + 1) * 4 > static_cast<std::uint32_t>(image.size())) break;
                        std::uint32_t frva = *reinterpret_cast<std::uint32_t*>(
                            &image[funcs_rva + ordinal * 4]);

                        if (frva > 0 && frva < static_cast<std::uint32_t>(image.size()))
                        {
                            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = frva;
                            result.fixed_ep_rva      = frva;
                            result.entry_point_fixed = true;
                            ep_ok = true;
                        }
                        break;
                    }
                }
            }
        }

        if (!ep_ok && ep_rva > 0 && ep_rva < static_cast<std::uint32_t>(image.size()) &&
            (image[ep_rva] == 0x00 || image[ep_rva] == 0xCC))
        {
            static const struct { const std::uint8_t bytes[8]; int len; } prologues[] = {
                {{0x48, 0x89, 0x5C, 0x24},          4},
                {{0x48, 0x83, 0xEC},                 3},
                {{0x48, 0x8B, 0xC4},                 3},
                {{0x4C, 0x8B, 0xDC},                 3},
                {{0x48, 0x89, 0x4C, 0x24},           4},
                {{0x40, 0x55},                       2},
                {{0x40, 0x53},                       2},
                {{0x55, 0x48, 0x8B, 0xEC},           4},
                {{0x48, 0x81, 0xEC},                 3},
                {{0x48, 0x8D, 0x6C, 0x24},           4},
                {{0xE9},                             1},
                {{0x55, 0x8B, 0xEC},                 3},
            };

            bool found_prologue = false;
            for (int i = 0; i < num_sections && i < 96 && !found_prologue; i++)
            {
                std::uint32_t sec_off = section_table_off + i * 40;
                if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
                std::uint32_t ch = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                if (!(ch & 0x20000000) || va == 0 || vs == 0) continue;

                std::uint32_t scan_end = va + vs;
                if (scan_end > static_cast<std::uint32_t>(image.size()))
                    scan_end = static_cast<std::uint32_t>(image.size());

                if (scan_end - va > 0x10000) scan_end = va + 0x10000;

                for (std::uint32_t off = va; off + 8 < scan_end; off++)
                {
                    if (image[off] == 0x00 || image[off] == 0xCC) continue;

                    for (const auto& p : prologues)
                    {
                        if (off + p.len > scan_end) continue;
                        if (std::memcmp(&image[off], p.bytes, p.len) == 0)
                        {
                            *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = off;
                            result.fixed_ep_rva      = off;
                            result.entry_point_fixed = true;
                            result.ep_prologue_scanned = true;
                            ep_ok = true;
                            found_prologue = true;
                            break;
                        }
                    }
                    if (found_prologue) break;
                }
            }

            if (!found_prologue)
            {
                for (int i = 0; i < num_sections && i < 96; i++)
                {
                    std::uint32_t sec_off = section_table_off + i * 40;
                    if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;

                    std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
                    std::uint32_t ch = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 36]);

                    if ((ch & 0x20000000) && va > 0 && va < static_cast<std::uint32_t>(image.size()) &&
                        image[va] != 0x00)
                    {
                        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 16]) = va;
                        result.fixed_ep_rva      = va;
                        result.entry_point_fixed = true;
                        ep_ok = true;
                        break;
                    }
                }
            }
        }

        result.entry_point_valid = ep_ok;
    }

    {
        std::uint32_t import_dir_off = dd_base + 1 * 8;
        if (import_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t import_rva  = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off]);
            std::uint32_t import_size = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off + 4]);
            (void)import_size;

            if (import_rva != 0 && import_rva < static_cast<std::uint32_t>(image.size()))
            {
                std::uint32_t thunk_size = result.is_pe64 ? 8u : 4u;
                std::uint64_t ordinal_flag = result.is_pe64
                    ? 0x8000000000000000ULL : 0x80000000ULL;

                for (std::uint32_t imp_idx = 0; imp_idx < 0x2000; imp_idx++)
                {
                    std::uint32_t desc_off = import_rva + imp_idx * 20;
                    if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;

                    std::uint32_t int_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
                    std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
                    std::uint32_t iat_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);

                    if (int_rva == 0 && name_rva == 0 && iat_rva == 0) break;
                    if (iat_rva == 0) continue;

                    if (name_rva > 0 && name_rva < static_cast<std::uint32_t>(image.size()))
                    {
                        std::string dll_name;
                        for (std::uint32_t k = name_rva;
                             k < static_cast<std::uint32_t>(image.size()) && image[k] != 0;
                             k++)
                        {
                            if (dll_name.size() >= 260) break;
                            dll_name += static_cast<char>(image[k]);
                        }
                        if (!dll_name.empty())
                            result.import_dll_names.push_back(dll_name);
                    }
                    result.import_dlls_found++;

                    *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4]) = 0;
                    *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8]) = static_cast<std::uint32_t>(-1);

                    if (int_rva == 0 || int_rva == iat_rva) continue;
                    if (int_rva >= static_cast<std::uint32_t>(image.size()) ||
                        iat_rva >= static_cast<std::uint32_t>(image.size())) continue;

                    bool int_valid = true;
                    int  thunk_count = 0;

                    for (int t = 0; t < 0x10000; t++)
                    {
                        std::uint32_t ie = int_rva + t * thunk_size;
                        if (ie + thunk_size > static_cast<std::uint32_t>(image.size()))
                        { int_valid = false; break; }

                        std::uint64_t tv = 0;
                        if (result.is_pe64)
                            tv = *reinterpret_cast<std::uint64_t*>(&image[ie]);
                        else
                            tv = *reinterpret_cast<std::uint32_t*>(&image[ie]);

                        if (tv == 0) break;

                        if (!(tv & ordinal_flag))
                        {
                            std::uint32_t nva = static_cast<std::uint32_t>(tv & 0x7FFFFFFF);
                            if (nva == 0 || nva + 3 >= static_cast<std::uint32_t>(image.size()))
                            { int_valid = false; break; }

                            bool printable = false;
                            for (int k = 2; k < 8 && nva + k < static_cast<std::uint32_t>(image.size()); k++)
                            {
                                char c = static_cast<char>(image[nva + k]);
                                if (c == 0) { printable = (k > 2); break; }
                                if (c >= 0x21 && c <= 0x7E) { printable = true; break; }
                            }
                            if (!printable) { int_valid = false; break; }
                        }
                        thunk_count++;
                    }

                    if (int_valid && thunk_count > 0)
                    {
                        for (int t = 0; t <= thunk_count; t++)
                        {
                            std::uint32_t src = int_rva + t * thunk_size;
                            std::uint32_t dst = iat_rva + t * thunk_size;
                            if (src + thunk_size > static_cast<std::uint32_t>(image.size()) ||
                                dst + thunk_size > static_cast<std::uint32_t>(image.size()))
                                break;
                            std::memcpy(&image[dst], &image[src], thunk_size);
                        }
                        result.iat_entries_restored += thunk_count;
                    }
                }
            }
        }
    }

    {
        std::uint32_t bound_off = dd_base + 11 * 8;
        if (bound_off + 8 <= static_cast<std::uint32_t>(image.size()))
        {
            std::uint32_t brva = *reinterpret_cast<std::uint32_t*>(&image[bound_off]);
            if (brva != 0)
            {
                *reinterpret_cast<std::uint32_t*>(&image[bound_off])     = 0;
                *reinterpret_cast<std::uint32_t*>(&image[bound_off + 4]) = 0;
            }
        }
    }

    result.original_size_of_image = image_size_from_header;

    std::uint32_t sec_align_val = 0x1000;
    if (opt_off + 36 <= static_cast<std::uint32_t>(image.size()))
    {
        std::uint32_t sa = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
        if (sa >= 0x200 && sa <= 0x100000)
            sec_align_val = sa;
    }

    if (static_cast<std::uint32_t>(image.size()) > image_size_from_header)
    {
        result.extended_image = true;

        std::uint32_t last_sec_end = 0;
        for (int i = 0; i < num_sections && i < 96; i++)
        {
            std::uint32_t sec_off = section_table_off + i * 40;
            if (sec_off + 40 > static_cast<std::uint32_t>(image.size())) break;
            std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 12]);
            std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 8]);
            std::uint32_t raw = *reinterpret_cast<std::uint32_t*>(&image[sec_off + 16]);
            std::uint32_t end = va + ((vs > raw) ? vs : raw);
            if (end > last_sec_end)
                last_sec_end = end;
        }

        std::uint32_t aligned_last = (last_sec_end + sec_align_val - 1) & ~(sec_align_val - 1);
        if (aligned_last < image_size_from_header)
            aligned_last = image_size_from_header;

        if (static_cast<std::uint32_t>(image.size()) > aligned_last)
        {
            std::uint16_t cur_num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
            std::uint32_t cur_sec_table_off = pe_off + 24 + opt_hdr_size;

            std::uint32_t remaining_start = aligned_last;
            std::uint32_t remaining_total = static_cast<std::uint32_t>(image.size()) - remaining_start;

            constexpr std::uint32_t MAX_VAD_SECTION_SIZE = 0x40000000u;
            int vad_idx = 0;

            while (remaining_total > 0 && vad_idx < 16)
            {
                std::uint32_t chunk_size = remaining_total;
                if (chunk_size > MAX_VAD_SECTION_SIZE)
                    chunk_size = MAX_VAD_SECTION_SIZE;

                std::uint32_t chunk_aligned = (chunk_size + sec_align_val - 1) & ~(sec_align_val - 1);

                std::uint32_t new_sec_header_off = cur_sec_table_off + cur_num_sections * 40;
                if (new_sec_header_off + 40 > remaining_start &&
                    new_sec_header_off + 40 > static_cast<std::uint32_t>(image.size()))
                    break;

                if (new_sec_header_off + 40 > remaining_start)
                    break;

                char sec_name_buf[9] = {};
                if (vad_idx == 0)
                    std::memcpy(sec_name_buf, ".vad\0\0\0\0", 8);
                else
                    qsnprintf(sec_name_buf, sizeof(sec_name_buf), ".vad%d", vad_idx);

                std::memset(&image[new_sec_header_off], 0, 40);
                std::memcpy(&image[new_sec_header_off], sec_name_buf, 8);
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 8])  = chunk_aligned;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 12]) = remaining_start;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 16]) = chunk_aligned;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 20]) = remaining_start;
                *reinterpret_cast<std::uint32_t*>(&image[new_sec_header_off + 36]) = 0xE0000060u;

                cur_num_sections++;
                result.vad_sections_added++;
                result.sections_fixed++;

                remaining_start += chunk_aligned;
                remaining_total = (remaining_start < static_cast<std::uint32_t>(image.size()))
                    ? static_cast<std::uint32_t>(image.size()) - remaining_start
                    : 0;
                vad_idx++;
            }

            *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) = cur_num_sections;
            result.vad_section_added = (result.vad_sections_added > 0);
        }

        std::uint32_t new_soi = (static_cast<std::uint32_t>(image.size()) + sec_align_val - 1)
                                & ~(sec_align_val - 1);
        *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_soi;
        result.updated_size_of_image = new_soi;
    }
    else
    {
        result.updated_size_of_image = image_size_from_header;
    }

    result.success = true;
    return result;
}

static nlohmann::json pe_fix_to_json(const pe_fix_result_t& fix)
{
    auto fmt_rva = [](std::uint32_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << v;
        return ss.str();
    };

    auto fmt_addr = [](std::uint64_t v) -> std::string {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << v;
        return ss.str();
    };

    nlohmann::json j;
    j["pe_fixed"]              = fix.success;
    j["sections_fixed"]        = fix.sections_fixed;
    j["iat_entries_restored"]  = fix.iat_entries_restored;
    j["import_dlls_found"]     = fix.import_dlls_found;
    j["entry_point_valid"]     = fix.entry_point_valid;
    j["entry_point_fixed"]     = fix.entry_point_fixed;
    if (fix.ep_prologue_scanned)
        j["ep_prologue_scanned"] = true;
    j["original_ep_rva"]       = fmt_rva(fix.original_ep_rva);
    j["fixed_ep_rva"]          = fmt_rva(fix.fixed_ep_rva);
    j["security_dir_cleared"]  = fix.security_dir_cleared;
    j["debug_dir_cleared"]     = fix.debug_dir_cleared;
    j["checksum_cleared"]      = fix.checksum_cleared;
    j["file_alignment_fixed"]  = fix.file_alignment_fixed;
    j["reloc_dir_cleared"]     = fix.reloc_dir_cleared;
    j["relocs_stripped"]       = fix.relocs_stripped_flag_set;
    if (fix.reloc_section_zeroed)
        j["reloc_section_zeroed"] = true;
    if (fix.tls_dir_cleared)
        j["tls_dir_cleared"]     = true;
    if (fix.loadconfig_dir_cleared)
        j["loadconfig_dir_cleared"] = true;
    if (fix.delay_import_dir_cleared)
        j["delay_import_dir_cleared"] = true;
    if (fix.com_dir_cleared)
        j["com_dir_cleared"]     = true;
    if (fix.is_dotnet)
    {
        j["is_dotnet"]           = true;
        if (fix.dotnet_com_preserved)
            j["dotnet_com_preserved"] = true;
        if (fix.dotnet_com_restored)
            j["dotnet_com_restored"]  = true;
    }
    if (fix.imagebase_updated)
    {
        j["imagebase_updated"]       = true;
        j["original_imagebase"]      = fmt_addr(fix.original_imagebase);
        j["updated_imagebase"]       = fmt_addr(fix.updated_imagebase);
    }
    if (!fix.import_dll_names.empty())
        j["import_dlls"]       = fix.import_dll_names;
    if (fix.extended_image)
    {
        j["extended_image"]         = true;
        j["original_size_of_image"] = fmt_rva(fix.original_size_of_image);
        j["updated_size_of_image"]  = fmt_rva(fix.updated_size_of_image);
        if (fix.vad_section_added)
            j["vad_sections_added"]  = fix.vad_sections_added;
    }
    if (!fix.error.empty())
        j["pe_fix_error"]      = fix.error;
    return j;
}

struct module_range_t
{
    std::string name;
    std::uint64_t base;
    std::uint64_t size;
};

struct iat_rebuild_result_t
{
    bool success = false;
    int imports_resolved = 0;
    int imports_failed = 0;
    int descriptors_rebuilt = 0;
    bool section_added = false;
    std::vector<std::string> resolved_dlls;
    std::string error;
};

static std::vector<module_range_t> enumerate_ldr_modules_for_iat(
    voyager::device_t* dev)
{
    std::vector<module_range_t> modules;

    if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
        return modules;

    voyager::device_t::peb_info peb{};
    if (!dev->read_peb(peb) || peb.ldr_address == 0)
        return modules;

    std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t first_entry = dev->read<std::uint64_t>(list_head);

    if (first_entry == 0 || first_entry == list_head)
        return modules;

    std::uint64_t current = first_entry;
    int max_iter = 1024;

    while (current != list_head && current != 0 && max_iter-- > 0)
    {
        module_range_t m;
        m.base = dev->read<std::uint64_t>(current + 0x30);
        m.size = static_cast<std::uint64_t>(dev->read<std::uint32_t>(current + 0x40));

        std::uint16_t name_len = dev->read<std::uint16_t>(current + 0x58);
        std::uint64_t name_ptr = dev->read<std::uint64_t>(current + 0x58 + 8);

        if (name_len > 0 && name_len < 520 && name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(name_len, 0);
            dev->read_raw(name_ptr, raw.data(), name_len);
            m.name.reserve(name_len / 2);
            for (std::size_t i = 0; i + 1 < name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                m.name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }

        if (m.base != 0 && m.size != 0 && !m.name.empty())
            modules.push_back(m);

        std::uint64_t next = dev->read<std::uint64_t>(current);
        if (next == current) break;
        current = next;
    }

    return modules;
}

static std::vector<module_range_t> enumerate_kernel_modules_for_iat()
{
    std::vector<module_range_t> modules;

    struct km_entry_t
    {
        HANDLE   Section;
        PVOID    MappedBase;
        PVOID    ImageBase;
        ULONG    ImageSize;
        ULONG    Flags;
        USHORT   LoadOrderIndex;
        USHORT   InitOrderIndex;
        USHORT   LoadCount;
        USHORT   OffsetToFileName;
        UCHAR    FullPathName[256];
    };

    struct km_info_t
    {
        ULONG       NumberOfModules;
        km_entry_t  Modules[1];
    };

    typedef LONG(NTAPI* NtQSI_fn)(ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return modules;

    auto pNtQSI = reinterpret_cast<NtQSI_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQSI) return modules;

    constexpr ULONG SysModInfo = 11;
    ULONG needed = 0;
    pNtQSI(SysModInfo, nullptr, 0, &needed);
    if (needed == 0) needed = 256 * 1024;
    needed += 16384;

    std::vector<std::uint8_t> buf(needed, 0);
    LONG status = pNtQSI(SysModInfo, buf.data(),
        static_cast<ULONG>(buf.size()), &needed);
    if (status < 0) return modules;

    auto* info = reinterpret_cast<km_info_t*>(buf.data());
    modules.reserve(info->NumberOfModules);
    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& e = info->Modules[i];
        module_range_t mr;
        mr.name = std::string(reinterpret_cast<const char*>(
            e.FullPathName + e.OffsetToFileName));
        mr.base = reinterpret_cast<std::uintptr_t>(e.ImageBase);
        mr.size = e.ImageSize;
        modules.push_back(mr);
    }

    return modules;
}

static bool resolve_import_address(
    voyager::device_t* dev,
    const std::vector<module_range_t>& modules,
    std::uint64_t resolved_addr,
    bool is_kernel,
    std::string& out_dll,
    std::string& out_func,
    std::uint16_t& out_hint,
    bool& out_by_ordinal,
    std::uint16_t& out_ordinal)
{
    out_dll.clear();
    out_func.clear();
    out_hint = 0;
    out_ordinal = 0;
    out_by_ordinal = false;

    const module_range_t* target = nullptr;
    for (const auto& m : modules)
    {
        if (resolved_addr >= m.base && resolved_addr < m.base + m.size)
        {
            target = &m;
            break;
        }
    }
    if (!target) return false;

    out_dll = target->name;

    std::uint8_t pe_hdr[0x1000];
    std::size_t hdr_read = is_kernel
        ? dev->read_kernel_raw(target->base, pe_hdr, sizeof(pe_hdr))
        : dev->read_raw(target->base, pe_hdr, sizeof(pe_hdr));

    if (hdr_read < 0x100 || pe_hdr[0] != 'M' || pe_hdr[1] != 'Z')
        return false;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    if (pe_off + 0x18 >= hdr_read ||
        pe_hdr[pe_off] != 'P' || pe_hdr[pe_off + 1] != 'E')
        return false;

    std::uint16_t opt_magic = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 0x18]);
    bool pe64 = (opt_magic == 0x020B);

    std::uint32_t dd_off = pe_off + 0x18 + (pe64 ? 112 : 96);
    if (dd_off + 8 > hdr_read) return false;

    std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&pe_hdr[dd_off]);
    if (export_rva == 0) return false;

    std::uint8_t edir[40];
    std::size_t er = is_kernel
        ? dev->read_kernel_raw(target->base + export_rva, edir, 40)
        : dev->read_raw(target->base + export_rva, edir, 40);
    if (er < 40) return false;

    std::uint32_t ordinal_base  = *reinterpret_cast<std::uint32_t*>(&edir[16]);
    std::uint32_t num_functions = *reinterpret_cast<std::uint32_t*>(&edir[20]);
    std::uint32_t num_names     = *reinterpret_cast<std::uint32_t*>(&edir[24]);
    std::uint32_t funcs_rva     = *reinterpret_cast<std::uint32_t*>(&edir[28]);
    std::uint32_t names_rva     = *reinterpret_cast<std::uint32_t*>(&edir[32]);
    std::uint32_t ords_rva      = *reinterpret_cast<std::uint32_t*>(&edir[36]);

    if (num_functions == 0 || num_functions > 200000) return false;

    std::size_t ft_bytes = num_functions * 4;
    if (ft_bytes > 0x200000) return false;
    std::vector<std::uint32_t> func_rvas(num_functions);

    std::size_t ft_read = is_kernel
        ? dev->read_kernel_raw(target->base + funcs_rva, func_rvas.data(), ft_bytes)
        : dev->read_raw(target->base + funcs_rva, func_rvas.data(), ft_bytes);
    if (ft_read < ft_bytes) return false;

    std::uint32_t target_rva = static_cast<std::uint32_t>(resolved_addr - target->base);
    std::uint32_t found_idx = UINT32_MAX;

    for (std::uint32_t i = 0; i < num_functions; i++)
    {
        if (func_rvas[i] == target_rva)
        {
            found_idx = i;
            break;
        }
    }
    if (found_idx == UINT32_MAX) return false;

    out_ordinal = static_cast<std::uint16_t>(found_idx + ordinal_base);

    if (num_names == 0)
    {
        out_by_ordinal = true;
        return true;
    }

    std::vector<std::uint16_t> ordinals(num_names);
    is_kernel
        ? dev->read_kernel_raw(target->base + ords_rva, ordinals.data(), num_names * 2)
        : dev->read_raw(target->base + ords_rva, ordinals.data(), num_names * 2);

    for (std::uint32_t ni = 0; ni < num_names; ni++)
    {
        if (ordinals[ni] == found_idx)
        {
            std::uint32_t name_rva = 0;
            is_kernel
                ? dev->read_kernel_raw(target->base + names_rva + ni * 4, &name_rva, 4)
                : dev->read_raw(target->base + names_rva + ni * 4, &name_rva, 4);

            if (name_rva != 0)
            {
                char nbuf[300] = {};
                is_kernel
                    ? dev->read_kernel_raw(target->base + name_rva, nbuf, sizeof(nbuf) - 1)
                    : dev->read_raw(target->base + name_rva, nbuf, sizeof(nbuf) - 1);

                out_func = nbuf;
                out_hint = static_cast<std::uint16_t>(ni);
                return true;
            }
        }
    }

    out_by_ordinal = true;
    return true;
}

static iat_rebuild_result_t reconstruct_iat_runtime(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base,
    voyager::device_t* dev,
    bool is_kernel)
{
    iat_rebuild_result_t result;

    if (!dev || !dev->is_connected())
    {
        result.error = "Device not connected";
        return result;
    }

    if (image.size() < 0x200)
    {
        result.error = "Image too small for PE";
        return result;
    }

    if (image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid MZ signature";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()) ||
        image[pe_off] != 'P' || image[pe_off + 1] != 'E')
    {
        result.error = "Invalid PE header";
        return result;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off      = pe_off + 24;
    std::uint16_t opt_magic    = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    bool is_pe64 = (opt_magic == 0x020B);

    if (!is_pe64 && opt_magic != 0x010B)
    {
        result.error = "Unknown PE optional header magic";
        return result;
    }

    std::uint32_t section_alignment = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
    if (section_alignment == 0) section_alignment = 0x1000;

    std::uint32_t dd_base = is_pe64 ? (opt_off + 112) : (opt_off + 96);
    std::uint32_t import_dir_off = dd_base + 1 * 8;
    if (import_dir_off + 8 > static_cast<std::uint32_t>(image.size()))
    {
        result.success = true;
        return result;
    }

    std::uint32_t import_rva = *reinterpret_cast<std::uint32_t*>(&image[import_dir_off]);
    if (import_rva == 0 || import_rva >= static_cast<std::uint32_t>(image.size()))
    {
        result.success = true;
        return result;
    }

    std::uint32_t thunk_size = is_pe64 ? 8u : 4u;
    std::uint64_t ordinal_flag = is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL;

    std::vector<module_range_t> modules;
    if (is_kernel)
        modules = enumerate_kernel_modules_for_iat();
    else
        modules = enumerate_ldr_modules_for_iat(dev);

    if (modules.empty())
    {
        result.error = "No modules found for IAT resolution";
        return result;
    }

    struct thunk_info_t
    {
        std::uint64_t resolved_addr;
        std::string   func_name;
        std::uint16_t hint;
        std::uint16_t ordinal;
        bool by_ordinal;
        bool needs_fix;
        bool is_null;
    };

    struct descriptor_info_t
    {
        std::uint32_t desc_off;
        std::uint32_t iat_rva;
        std::string   dll_name;
        std::vector<thunk_info_t> thunks;
        bool needs_rebuild;
    };

    std::vector<descriptor_info_t> descriptors;

    for (std::uint32_t di = 0; di < 0x2000; di++)
    {
        std::uint32_t desc_off = import_rva + di * 20;
        if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t int_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
        std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
        std::uint32_t iat_rva  = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);

        if (int_rva == 0 && name_rva == 0 && iat_rva == 0) break;
        if (iat_rva == 0) continue;

        std::string dll_name;
        if (name_rva > 0 && name_rva < static_cast<std::uint32_t>(image.size()))
        {
            for (std::uint32_t k = name_rva;
                 k < static_cast<std::uint32_t>(image.size()) && image[k] != 0;
                 k++)
            {
                if (dll_name.size() >= 260) break;
                dll_name += static_cast<char>(image[k]);
            }
        }

        descriptor_info_t di_info;
        di_info.desc_off = desc_off;
        di_info.iat_rva  = iat_rva;
        di_info.dll_name = dll_name;
        di_info.needs_rebuild = false;

        for (int ti = 0; ti < 0x10000; ti++)
        {
            std::uint32_t iat_off = iat_rva + ti * thunk_size;
            if (iat_off + thunk_size > static_cast<std::uint32_t>(image.size())) break;

            std::uint64_t thunk_val = 0;
            if (is_pe64)
                thunk_val = *reinterpret_cast<std::uint64_t*>(&image[iat_off]);
            else
                thunk_val = *reinterpret_cast<std::uint32_t*>(&image[iat_off]);

            thunk_info_t ti_info;
            ti_info.resolved_addr = 0;
            ti_info.hint = 0;
            ti_info.ordinal = 0;
            ti_info.by_ordinal = false;
            ti_info.needs_fix = false;
            ti_info.is_null = false;

            if (thunk_val == 0)
            {
                ti_info.is_null = true;
                di_info.thunks.push_back(ti_info);
                break;
            }

            if (thunk_val & ordinal_flag)
            {
                di_info.thunks.push_back(ti_info);
                continue;
            }

            bool already_valid = false;
            if (thunk_val < static_cast<std::uint64_t>(image.size()) &&
                thunk_val + 3 < static_cast<std::uint64_t>(image.size()))
            {
                char c = static_cast<char>(image[static_cast<std::size_t>(thunk_val) + 2]);
                if (c >= 0x21 && c <= 0x7E)
                    already_valid = true;
            }

            if (already_valid)
            {
                di_info.thunks.push_back(ti_info);
                continue;
            }

            std::uint64_t live_addr = 0;
            if (is_kernel)
                dev->read_kernel_raw(module_base + iat_off, &live_addr, thunk_size);
            else
                dev->read_raw(module_base + iat_off, &live_addr, thunk_size);

            if (!is_pe64)
                live_addr &= 0xFFFFFFFF;

            if (live_addr == 0)
                live_addr = thunk_val;

            ti_info.resolved_addr = live_addr;
            ti_info.needs_fix = true;
            di_info.needs_rebuild = true;

            std::string mod, func;
            std::uint16_t hint = 0, ordinal = 0;
            bool by_ord = false;

            if (live_addr != 0 &&
                resolve_import_address(dev, modules, live_addr, is_kernel,
                                       mod, func, hint, by_ord, ordinal))
            {
                ti_info.func_name  = func;
                ti_info.hint       = hint;
                ti_info.ordinal    = ordinal;
                ti_info.by_ordinal = by_ord;
                result.imports_resolved++;
            }
            else
            {
                result.imports_failed++;
            }

            di_info.thunks.push_back(ti_info);
        }

        if (di_info.needs_rebuild)
            descriptors.push_back(di_info);
    }

    if (descriptors.empty())
    {
        result.success = true;
        return result;
    }

    std::uint32_t original_image_size = static_cast<std::uint32_t>(image.size());
    std::uint32_t new_section_rva =
        (original_image_size + section_alignment - 1) & ~(section_alignment - 1);

    std::size_t names_total = 0;
    for (const auto& desc : descriptors)
    {
        for (const auto& tk : desc.thunks)
        {
            if (tk.needs_fix && !tk.func_name.empty() && !tk.by_ordinal)
            {
                std::size_t entry = 2 + tk.func_name.size() + 1;
                if (entry & 1) entry++;
                names_total += entry;
            }
        }
    }

    std::size_t int_total = 0;
    for (const auto& desc : descriptors)
        int_total += (desc.thunks.size() + 1) * thunk_size;

    std::size_t new_data_raw = names_total + int_total;
    std::uint32_t new_section_vsize =
        (static_cast<std::uint32_t>(new_data_raw) + section_alignment - 1) & ~(section_alignment - 1);

    if (new_section_vsize == 0)
        new_section_vsize = section_alignment;

    image.resize(new_section_rva + new_section_vsize, 0);

    std::uint32_t sec_table_off = pe_off + 24 + opt_hdr_size;
    std::uint32_t new_sec_off   = sec_table_off + num_sections * 40;

    if (new_sec_off + 40 <= new_section_rva && new_sec_off + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::memset(&image[new_sec_off], 0, 40);
        std::memcpy(&image[new_sec_off], ".aidat\0\0", 8);
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 8])  = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 12]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 16]) = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 20]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_off + 36]) = 0xC0000040;

        *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) =
            static_cast<std::uint16_t>(num_sections + 1);
        result.section_added = true;
    }

    *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_section_rva + new_section_vsize;

    struct name_loc_t { std::uint32_t rva; int desc_idx; int thunk_idx; };
    std::vector<name_loc_t> name_locs;

    std::uint32_t cursor = new_section_rva;

    for (int d = 0; d < static_cast<int>(descriptors.size()); d++)
    {
        for (int t = 0; t < static_cast<int>(descriptors[d].thunks.size()); t++)
        {
            const auto& tk = descriptors[d].thunks[t];
            if (!tk.needs_fix || tk.func_name.empty() || tk.by_ordinal)
                continue;

            std::uint32_t entry_rva = cursor;

            *reinterpret_cast<std::uint16_t*>(&image[cursor]) = tk.hint;
            cursor += 2;

            std::memcpy(&image[cursor], tk.func_name.c_str(), tk.func_name.size());
            cursor += static_cast<std::uint32_t>(tk.func_name.size());
            image[cursor++] = 0;

            if (cursor & 1) cursor++;

            name_locs.push_back({entry_rva, d, t});
        }
    }

    for (int d = 0; d < static_cast<int>(descriptors.size()); d++)
    {
        auto& desc = descriptors[d];
        std::uint32_t new_int_rva = cursor;

        if (desc.desc_off + 20 <= static_cast<std::uint32_t>(image.size()))
            *reinterpret_cast<std::uint32_t*>(&image[desc.desc_off]) = new_int_rva;

        for (int t = 0; t < static_cast<int>(desc.thunks.size()); t++)
        {
            const auto& tk = desc.thunks[t];
            std::uint64_t new_val = 0;

            if (tk.is_null)
            {
                new_val = 0;
            }
            else if (!tk.needs_fix)
            {
                std::uint32_t iat_off = desc.iat_rva + t * thunk_size;
                if (iat_off + thunk_size <= static_cast<std::uint32_t>(image.size()))
                {
                    if (is_pe64)
                        new_val = *reinterpret_cast<std::uint64_t*>(&image[iat_off]);
                    else
                        new_val = *reinterpret_cast<std::uint32_t*>(&image[iat_off]);
                }
            }
            else if (tk.by_ordinal)
            {
                new_val = ordinal_flag | tk.ordinal;
            }
            else if (!tk.func_name.empty())
            {
                for (const auto& nl : name_locs)
                {
                    if (nl.desc_idx == d && nl.thunk_idx == t)
                    {
                        new_val = nl.rva;
                        break;
                    }
                }
            }

            if (cursor + thunk_size <= static_cast<std::uint32_t>(image.size()))
            {
                if (is_pe64)
                    *reinterpret_cast<std::uint64_t*>(&image[cursor]) = new_val;
                else
                    *reinterpret_cast<std::uint32_t*>(&image[cursor]) =
                        static_cast<std::uint32_t>(new_val);
            }
            cursor += thunk_size;

            if (tk.needs_fix || tk.is_null)
            {
                std::uint32_t iat_off = desc.iat_rva + t * thunk_size;
                if (iat_off + thunk_size <= static_cast<std::uint32_t>(image.size()))
                {
                    if (is_pe64)
                        *reinterpret_cast<std::uint64_t*>(&image[iat_off]) = new_val;
                    else
                        *reinterpret_cast<std::uint32_t*>(&image[iat_off]) =
                            static_cast<std::uint32_t>(new_val);
                }
            }
        }

        if (cursor + thunk_size <= static_cast<std::uint32_t>(image.size()))
        {
            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        }
        cursor += thunk_size;

        result.descriptors_rebuilt++;
        if (!desc.dll_name.empty())
        {
            bool already = false;
            for (const auto& rd : result.resolved_dlls)
                if (rd == desc.dll_name) { already = true; break; }
            if (!already)
                result.resolved_dlls.push_back(desc.dll_name);
        }
    }

    for (std::uint32_t di = 0; di < 0x2000; di++)
    {
        std::uint32_t desc_off = import_rva + di * 20;
        if (desc_off + 20 > static_cast<std::uint32_t>(image.size())) break;
        std::uint32_t v0 = *reinterpret_cast<std::uint32_t*>(&image[desc_off]);
        std::uint32_t v3 = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]);
        std::uint32_t v4 = *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]);
        if (v0 == 0 && v3 == 0 && v4 == 0) break;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4]) = 0;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8]) = static_cast<std::uint32_t>(-1);
    }

    result.success = true;
    return result;
}

static nlohmann::json iat_rebuild_to_json(const iat_rebuild_result_t& r)
{
    nlohmann::json j;
    j["iat_runtime_rebuild"]  = r.success;
    j["imports_resolved"]     = r.imports_resolved;
    j["imports_failed"]       = r.imports_failed;
    j["descriptors_rebuilt"]  = r.descriptors_rebuilt;
    j["section_added"]        = r.section_added;
    if (!r.resolved_dlls.empty())
        j["resolved_import_dlls"] = r.resolved_dlls;
    if (!r.error.empty())
        j["iat_rebuild_error"]    = r.error;
    return j;
}

struct export_entry_info_t
{
    std::string   dll_name;
    std::string   func_name;
    std::uint16_t hint;
    std::uint16_t ordinal;
    bool          by_ordinal;
};

static std::unordered_map<std::uint64_t, export_entry_info_t> build_module_export_map(
    voyager::device_t* dev,
    const std::vector<module_range_t>& modules,
    bool is_kernel)
{
    std::unordered_map<std::uint64_t, export_entry_info_t> map;
    map.reserve(32768);

    for (const auto& m : modules)
    {
        std::uint8_t hdr[0x1000];
        std::size_t hdr_read = is_kernel
            ? dev->read_kernel_raw(m.base, hdr, sizeof(hdr))
            : dev->read_raw(m.base, hdr, sizeof(hdr));

        if (hdr_read < 0x100 || hdr[0] != 'M' || hdr[1] != 'Z')
            continue;

        std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&hdr[0x3C]);
        if (pe_off + 0x18 >= hdr_read) continue;
        if (hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') continue;

        std::uint16_t opt_mag = *reinterpret_cast<std::uint16_t*>(&hdr[pe_off + 0x18]);
        bool pe64 = (opt_mag == 0x020B);
        std::uint32_t dd_off = pe_off + 0x18 + (pe64 ? 112 : 96);
        if (dd_off + 8 > hdr_read) continue;

        std::uint32_t export_rva  = *reinterpret_cast<std::uint32_t*>(&hdr[dd_off]);
        std::uint32_t export_size = *reinterpret_cast<std::uint32_t*>(&hdr[dd_off + 4]);
        if (export_rva == 0 || export_size == 0) continue;

        std::uint8_t edir[40];
        std::size_t er = is_kernel
            ? dev->read_kernel_raw(m.base + export_rva, edir, 40)
            : dev->read_raw(m.base + export_rva, edir, 40);
        if (er < 40) continue;

        std::uint32_t ordinal_base  = *reinterpret_cast<std::uint32_t*>(&edir[16]);
        std::uint32_t num_functions = *reinterpret_cast<std::uint32_t*>(&edir[20]);
        std::uint32_t num_names     = *reinterpret_cast<std::uint32_t*>(&edir[24]);
        std::uint32_t funcs_rva     = *reinterpret_cast<std::uint32_t*>(&edir[28]);
        std::uint32_t names_rva     = *reinterpret_cast<std::uint32_t*>(&edir[32]);
        std::uint32_t ords_rva      = *reinterpret_cast<std::uint32_t*>(&edir[36]);

        if (num_functions == 0 || num_functions > 200000) continue;

        std::size_t ft_bytes = static_cast<std::size_t>(num_functions) * 4;
        if (ft_bytes > 0x200000) continue;
        std::vector<std::uint32_t> func_rvas(num_functions);
        std::size_t ft_read = is_kernel
            ? dev->read_kernel_raw(m.base + funcs_rva, func_rvas.data(), ft_bytes)
            : dev->read_raw(m.base + funcs_rva, func_rvas.data(), ft_bytes);
        if (ft_read < ft_bytes) continue;

        std::unordered_map<std::uint32_t, std::pair<std::string, std::uint16_t>> ord_to_name;
        if (num_names > 0 && num_names <= 200000)
        {
            std::vector<std::uint16_t> ordinals(num_names);
            std::vector<std::uint32_t> name_rva_arr(num_names);
            is_kernel
                ? dev->read_kernel_raw(m.base + ords_rva, ordinals.data(), num_names * 2)
                : dev->read_raw(m.base + ords_rva, ordinals.data(), num_names * 2);
            is_kernel
                ? dev->read_kernel_raw(m.base + names_rva, name_rva_arr.data(), num_names * 4)
                : dev->read_raw(m.base + names_rva, name_rva_arr.data(), num_names * 4);

            for (std::uint32_t ni = 0; ni < num_names; ni++)
            {
                if (name_rva_arr[ni] == 0) continue;
                char nbuf[300] = {};
                is_kernel
                    ? dev->read_kernel_raw(m.base + name_rva_arr[ni], nbuf, sizeof(nbuf) - 1)
                    : dev->read_raw(m.base + name_rva_arr[ni], nbuf, sizeof(nbuf) - 1);
                if (nbuf[0] != 0)
                    ord_to_name[ordinals[ni]] = { std::string(nbuf), static_cast<std::uint16_t>(ni) };
            }
        }

        std::string dll_name = m.name;
        auto slash_pos = dll_name.find_last_of("\\/");
        if (slash_pos != std::string::npos)
            dll_name = dll_name.substr(slash_pos + 1);

        for (std::uint32_t i = 0; i < num_functions; i++)
        {
            if (func_rvas[i] == 0) continue;
            if (func_rvas[i] >= export_rva && func_rvas[i] < export_rva + export_size)
                continue;

            std::uint64_t addr = m.base + func_rvas[i];

            export_entry_info_t info;
            info.dll_name = dll_name;
            info.ordinal  = static_cast<std::uint16_t>(i + ordinal_base);

            auto nit = ord_to_name.find(i);
            if (nit != ord_to_name.end())
            {
                info.func_name  = nit->second.first;
                info.hint       = nit->second.second;
                info.by_ordinal = false;
            }
            else
            {
                info.by_ordinal = true;
                info.hint       = 0;
            }

            map.emplace(addr, std::move(info));
        }
    }

    return map;
}

static int patch_import_call_references(
    std::vector<std::uint8_t>& image,
    const std::unordered_map<std::uint32_t, std::uint32_t>& old_iat_to_new_iat,
    bool is_pe64)
{
    if (!is_pe64 || old_iat_to_new_iat.empty())
        return 0;

    if (image.size() < 0x200)
        return 0;

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_size     = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 0x14]);
    std::uint32_t sec_table    = pe_off + 0x18 + opt_size;

    int patched = 0;

    for (int si = 0; si < num_sections && si < 96; si++)
    {
        std::uint32_t soff = sec_table + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
        std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
        std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

        if (!(chars & 0x20000000)) continue;
        if (vrva == 0 || vsize == 0) continue;

        std::uint32_t scan_end = vrva + vsize;
        if (scan_end > static_cast<std::uint32_t>(image.size()))
            scan_end = static_cast<std::uint32_t>(image.size());

        for (std::uint32_t off = vrva; off + 6 < scan_end; off++)
        {
            bool is_call = (image[off] == 0xFF && image[off + 1] == 0x15);
            bool is_jmp  = (off + 7 < scan_end &&
                            image[off] == 0x48 && image[off + 1] == 0xFF && image[off + 2] == 0x25);

            bool is_mov_rip = (off + 7 < scan_end &&
                               (image[off] == 0x48 || image[off] == 0x4C) &&
                               image[off + 1] == 0x8B &&
                               (image[off + 2] & 0xC7) == 0x05);

            if (!is_call && !is_jmp && !is_mov_rip) continue;

            std::uint32_t disp_off = is_call ? (off + 2) : (off + 3);
            std::uint32_t inst_end = is_call ? (off + 6) : (off + 7);

            if (disp_off + 4 > static_cast<std::uint32_t>(image.size())) continue;

            std::int32_t disp = *reinterpret_cast<std::int32_t*>(&image[disp_off]);
            std::uint32_t target_rva = static_cast<std::uint32_t>(
                static_cast<std::int64_t>(inst_end) + disp);

            auto it = old_iat_to_new_iat.find(target_rva);
            if (it == old_iat_to_new_iat.end()) continue;

            std::int32_t new_disp = static_cast<std::int32_t>(
                static_cast<std::int64_t>(it->second) - static_cast<std::int64_t>(inst_end));
            *reinterpret_cast<std::int32_t*>(&image[disp_off]) = new_disp;
            patched++;
        }
    }

    return patched;
}

static iat_rebuild_result_t full_iat_scan_and_rebuild(
    std::vector<std::uint8_t>& image,
    std::uint64_t module_base,
    voyager::device_t* dev,
    bool is_kernel)
{
    iat_rebuild_result_t result;

    if (!dev || !dev->is_connected())
    {
        result.error = "Device not connected";
        return result;
    }

    if (image.size() < 0x200 || image[0] != 'M' || image[1] != 'Z')
    {
        result.error = "Invalid PE image";
        return result;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&image[0x3C]);
    if (pe_off + 0x18 >= static_cast<std::uint32_t>(image.size()) ||
        image[pe_off] != 'P' || image[pe_off + 1] != 'E')
    {
        result.error = "Invalid PE header";
        return result;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]);
    std::uint16_t opt_hdr_size = *reinterpret_cast<std::uint16_t*>(&image[pe_off + 20]);
    std::uint32_t opt_off      = pe_off + 24;
    std::uint16_t opt_magic    = *reinterpret_cast<std::uint16_t*>(&image[opt_off]);
    bool is_pe64 = (opt_magic == 0x020B);

    if (!is_pe64 && opt_magic != 0x010B)
    {
        result.error = "Unknown PE magic";
        return result;
    }

    std::uint32_t section_alignment = *reinterpret_cast<std::uint32_t*>(&image[opt_off + 32]);
    if (section_alignment == 0) section_alignment = 0x1000;

    std::uint32_t sec_table_off = pe_off + 24 + opt_hdr_size;
    std::uint32_t thunk_size    = is_pe64 ? 8u : 4u;
    std::uint32_t dd_base       = is_pe64 ? (opt_off + 112) : (opt_off + 96);

    std::vector<module_range_t> modules;
    if (is_kernel)
        modules = enumerate_kernel_modules_for_iat();
    else
        modules = enumerate_ldr_modules_for_iat(dev);

    if (modules.empty())
    {
        result.error = "No modules found for export map";
        return result;
    }

    msg(OBFSTR_C("AiDA: Building export address map from %zu modules...\n"), modules.size());
    auto export_map = build_module_export_map(dev, modules, is_kernel);

    if (export_map.empty())
    {
        result.error = "Export map empty -- no module exports readable";
        return result;
    }

    msg(OBFSTR_C("AiDA: Export map built with %zu entries, scanning image for imports...\n"),
        export_map.size());

    struct found_import_t
    {
        std::uint32_t iat_offset;
        std::string   dll_name;
        std::string   func_name;
        std::uint16_t hint;
        std::uint16_t ordinal;
        bool          by_ordinal;
    };

    std::map<std::string, std::vector<found_import_t>> dll_imports;
    std::set<std::uint32_t> found_offsets;

    auto try_resolve = [&](std::uint32_t off, std::uint64_t val) -> bool
    {
        if (val == 0 || found_offsets.count(off))
            return false;

        auto it = export_map.find(val);
        if (it == export_map.end())
            return false;

        if (val >= module_base && val < module_base + static_cast<std::uint64_t>(image.size()))
            return false;

        const auto& info = it->second;
        found_offsets.insert(off);

        std::string dll_key = info.dll_name;
        for (auto& c : dll_key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        found_import_t fi;
        fi.iat_offset  = off;
        fi.dll_name    = info.dll_name;
        fi.func_name   = info.func_name;
        fi.hint        = info.hint;
        fi.ordinal     = info.ordinal;
        fi.by_ordinal  = info.by_ordinal;
        dll_imports[dll_key].push_back(fi);
        return true;
    };

    for (int si = 0; si < num_sections && si < 96; si++)
    {
        std::uint32_t soff  = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

        std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
        std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
        std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

        if (vrva == 0 || vsize == 0) continue;
        if (chars & 0x20000000) continue;

        std::uint32_t scan_end = vrva + vsize;
        if (scan_end > static_cast<std::uint32_t>(image.size()))
            scan_end = static_cast<std::uint32_t>(image.size());

        for (std::uint32_t off = vrva; off + thunk_size <= scan_end; off += thunk_size)
        {
            std::uint64_t dump_val = 0;
            if (is_pe64)
                dump_val = *reinterpret_cast<std::uint64_t*>(&image[off]);
            else
                dump_val = *reinterpret_cast<std::uint32_t*>(&image[off]);

            if (dump_val == 0) continue;

            if (try_resolve(off, dump_val))
                continue;

            std::uint64_t live_val = 0;
            if (is_kernel)
                dev->read_kernel_raw(module_base + off, &live_val, thunk_size);
            else
                dev->read_raw(module_base + off, &live_val, thunk_size);
            if (!is_pe64)
                live_val &= 0xFFFFFFFF;

            if (live_val != 0 && live_val != dump_val)
                try_resolve(off, live_val);
        }
    }

    if (is_pe64)
    {
        for (int si = 0; si < num_sections && si < 96; si++)
        {
            std::uint32_t soff  = sec_table_off + si * 40;
            if (soff + 40 > static_cast<std::uint32_t>(image.size())) break;

            std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(&image[soff + 12]);
            std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(&image[soff + 8]);
            std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(&image[soff + 36]);

            if (!(chars & 0x20000000)) continue;
            if (vrva == 0 || vsize == 0) continue;

            std::uint32_t scan_end = vrva + vsize;
            if (scan_end > static_cast<std::uint32_t>(image.size()))
                scan_end = static_cast<std::uint32_t>(image.size());

            for (std::uint32_t off = vrva; off + 7 < scan_end; off++)
            {
                bool is_call = (image[off] == 0xFF && image[off + 1] == 0x15);
                bool is_jmp  = (off + 7 < scan_end &&
                                image[off] == 0x48 && image[off + 1] == 0xFF && image[off + 2] == 0x25);

                if (!is_call && !is_jmp) continue;

                std::uint32_t disp_off = is_call ? (off + 2) : (off + 3);
                std::uint32_t inst_end = is_call ? (off + 6) : (off + 7);
                if (disp_off + 4 > static_cast<std::uint32_t>(image.size())) continue;

                std::int32_t disp = *reinterpret_cast<std::int32_t*>(&image[disp_off]);
                std::int64_t target_rva64 = static_cast<std::int64_t>(inst_end) + disp;
                if (target_rva64 < 0 || target_rva64 + static_cast<std::int64_t>(thunk_size) >
                    static_cast<std::int64_t>(image.size()))
                    continue;

                std::uint32_t target_off = static_cast<std::uint32_t>(target_rva64);

                std::uint64_t slot_val = *reinterpret_cast<std::uint64_t*>(&image[target_off]);
                if (slot_val == 0) continue;

                if (!try_resolve(target_off, slot_val))
                {
                    std::uint64_t live_val = 0;
                    if (is_kernel)
                        dev->read_kernel_raw(module_base + target_off, &live_val, 8);
                    else
                        dev->read_raw(module_base + target_off, &live_val, 8);
                    if (live_val != 0 && live_val != slot_val)
                        try_resolve(target_off, live_val);
                }
            }
        }
    }

    int total_imports = 0;
    for (const auto& [k, v] : dll_imports)
        total_imports += static_cast<int>(v.size());

    if (total_imports == 0)
    {
        result.success = true;
        return result;
    }

    msg(OBFSTR_C("AiDA: Full IAT scan found %d imports across %zu DLLs\n"),
        total_imports, dll_imports.size());

    std::size_t descriptors_size = (dll_imports.size() + 1) * 20;
    std::size_t dll_names_size   = 0;
    std::size_t hint_names_size  = 0;
    std::size_t ilt_total        = 0;
    std::size_t iat_total        = 0;

    for (const auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        dll_names_size += entries[0].dll_name.size() + 1;
        if (dll_names_size & 1) dll_names_size++;

        for (const auto& e : entries)
        {
            if (!e.by_ordinal && !e.func_name.empty())
            {
                std::size_t entry = 2 + e.func_name.size() + 1;
                if (entry & 1) entry++;
                hint_names_size += entry;
            }
        }

        ilt_total += (entries.size() + 1) * thunk_size;
        iat_total += (entries.size() + 1) * thunk_size;
    }

    std::size_t new_data_raw = descriptors_size + dll_names_size + hint_names_size + ilt_total + iat_total;

    std::uint32_t original_image_size = static_cast<std::uint32_t>(image.size());
    std::uint32_t new_section_rva =
        (original_image_size + section_alignment - 1) & ~(section_alignment - 1);
    std::uint32_t new_section_vsize =
        (static_cast<std::uint32_t>(new_data_raw) + section_alignment - 1) & ~(section_alignment - 1);
    if (new_section_vsize == 0) new_section_vsize = section_alignment;

    image.resize(new_section_rva + new_section_vsize, 0);

    std::uint32_t new_sec_hdr = sec_table_off + num_sections * 40;
    if (new_sec_hdr + 40 <= new_section_rva &&
        new_sec_hdr + 40 <= static_cast<std::uint32_t>(image.size()))
    {
        std::memset(&image[new_sec_hdr], 0, 40);
        std::memcpy(&image[new_sec_hdr], ".aidai\0\0", 8);
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 8])  = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 12]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 16]) = new_section_vsize;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 20]) = new_section_rva;
        *reinterpret_cast<std::uint32_t*>(&image[new_sec_hdr + 36]) = 0xC0000040;

        *reinterpret_cast<std::uint16_t*>(&image[pe_off + 6]) =
            static_cast<std::uint16_t>(num_sections + 1);
        result.section_added = true;
    }

    *reinterpret_cast<std::uint32_t*>(&image[opt_off + 56]) = new_section_rva + new_section_vsize;

    std::uint32_t cursor = new_section_rva;

    std::uint32_t descriptors_rva = cursor;
    std::uint32_t descriptors_end = cursor + static_cast<std::uint32_t>(descriptors_size);
    cursor = descriptors_end;

    struct dll_layout_t
    {
        std::string dll_key;
        std::uint32_t name_rva;
        std::uint32_t ilt_rva;
        std::uint32_t iat_rva;
        std::vector<std::uint32_t> hint_name_rvas;
        std::vector<bool> by_ordinal_flags;
        std::vector<std::uint16_t> ordinals;
    };
    std::vector<dll_layout_t> layouts;

    for (const auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        dll_layout_t layout;
        layout.dll_key = dll_key;

        layout.name_rva = cursor;
        const std::string& dn = entries[0].dll_name;
        std::memcpy(&image[cursor], dn.c_str(), dn.size());
        cursor += static_cast<std::uint32_t>(dn.size());
        image[cursor++] = 0;
        if (cursor & 1) cursor++;

        for (const auto& e : entries)
        {
            layout.by_ordinal_flags.push_back(e.by_ordinal);
            layout.ordinals.push_back(e.ordinal);

            if (!e.by_ordinal && !e.func_name.empty())
            {
                std::uint32_t hn_rva = cursor;
                *reinterpret_cast<std::uint16_t*>(&image[cursor]) = e.hint;
                cursor += 2;
                std::memcpy(&image[cursor], e.func_name.c_str(), e.func_name.size());
                cursor += static_cast<std::uint32_t>(e.func_name.size());
                image[cursor++] = 0;
                if (cursor & 1) cursor++;
                layout.hint_name_rvas.push_back(hn_rva);
            }
            else
            {
                layout.hint_name_rvas.push_back(0);
            }
        }

        layouts.push_back(std::move(layout));
    }

    std::unordered_map<std::uint32_t, std::uint32_t> old_to_new_iat;

    int layout_idx = 0;
    for (auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        auto& layout = layouts[layout_idx++];

        layout.ilt_rva = cursor;
        for (std::size_t i = 0; i < entries.size(); i++)
        {
            std::uint64_t val = 0;
            if (layout.by_ordinal_flags[i])
                val = (is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL) | layout.ordinals[i];
            else
                val = layout.hint_name_rvas[i];

            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = val;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = static_cast<std::uint32_t>(val);
            cursor += thunk_size;
        }
        if (is_pe64)
            *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
        else
            *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        cursor += thunk_size;

        layout.iat_rva = cursor;
        for (std::size_t i = 0; i < entries.size(); i++)
        {
            std::uint64_t val = 0;
            if (layout.by_ordinal_flags[i])
                val = (is_pe64 ? 0x8000000000000000ULL : 0x80000000ULL) | layout.ordinals[i];
            else
                val = layout.hint_name_rvas[i];

            if (is_pe64)
                *reinterpret_cast<std::uint64_t*>(&image[cursor]) = val;
            else
                *reinterpret_cast<std::uint32_t*>(&image[cursor]) = static_cast<std::uint32_t>(val);

            old_to_new_iat[entries[i].iat_offset] = cursor;
            cursor += thunk_size;
        }
        if (is_pe64)
            *reinterpret_cast<std::uint64_t*>(&image[cursor]) = 0;
        else
            *reinterpret_cast<std::uint32_t*>(&image[cursor]) = 0;
        cursor += thunk_size;
    }

    layout_idx = 0;
    for (auto& [dll_key, entries] : dll_imports)
    {
        if (entries.empty()) continue;
        auto& layout = layouts[layout_idx];
        std::uint32_t desc_off = descriptors_rva + layout_idx * 20;

        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 0])  = layout.ilt_rva;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 4])  = 0;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 8])  = static_cast<std::uint32_t>(-1);
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 12]) = layout.name_rva;
        *reinterpret_cast<std::uint32_t*>(&image[desc_off + 16]) = layout.iat_rva;

        layout_idx++;

        bool dll_already = false;
        for (const auto& rd : result.resolved_dlls)
            if (rd == entries[0].dll_name) { dll_already = true; break; }
        if (!dll_already)
            result.resolved_dlls.push_back(entries[0].dll_name);
    }

    std::uint32_t null_desc_off = descriptors_rva + layout_idx * 20;
    if (null_desc_off + 20 <= static_cast<std::uint32_t>(image.size()))
        std::memset(&image[null_desc_off], 0, 20);

    std::uint32_t import_dir_off = dd_base + 1 * 8;
    if (import_dir_off + 8 <= static_cast<std::uint32_t>(image.size()))
    {
        *reinterpret_cast<std::uint32_t*>(&image[import_dir_off])     = descriptors_rva;
        *reinterpret_cast<std::uint32_t*>(&image[import_dir_off + 4]) =
            static_cast<std::uint32_t>(descriptors_size);
    }

    for (auto& [dll_key, entries] : dll_imports)
    {
        for (const auto& e : entries)
        {
            std::uint32_t off = e.iat_offset;
            if (off + thunk_size > original_image_size) continue;

            auto new_it = old_to_new_iat.find(off);
            if (new_it == old_to_new_iat.end()) continue;

            std::uint32_t new_iat_off = new_it->second;
            if (new_iat_off + thunk_size > static_cast<std::uint32_t>(image.size())) continue;

            if (is_pe64)
            {
                std::uint64_t new_val = *reinterpret_cast<std::uint64_t*>(&image[new_iat_off]);
                *reinterpret_cast<std::uint64_t*>(&image[off]) = new_val;
            }
            else
            {
                std::uint32_t new_val = *reinterpret_cast<std::uint32_t*>(&image[new_iat_off]);
                *reinterpret_cast<std::uint32_t*>(&image[off]) = new_val;
            }
        }
    }

    int xrefs_patched = patch_import_call_references(image, old_to_new_iat, is_pe64);
    if (xrefs_patched > 0)
        msg(OBFSTR_C("AiDA: Patched %d import call/jmp cross-references to new IAT\n"), xrefs_patched);

    result.success = true;
    result.imports_resolved = total_imports;
    result.descriptors_rebuilt = static_cast<int>(dll_imports.size());

    msg(OBFSTR_C("AiDA: Full IAT rebuild complete -- %d imports, %d DLLs, %d xrefs patched\n"),
        total_imports, static_cast<int>(dll_imports.size()), xrefs_patched);

    return result;
}


static std::string get_ldr_module_file_path(
    voyager::device_t* dev,
    std::uint64_t module_base)
{
    return {};
}


static int try_fill_from_disk_pe(
    std::vector<std::uint8_t>& image,
    const std::vector<std::size_t>& failed_offsets,
    const std::string& disk_path,
    nlohmann::json& steps_log)
{
    if (disk_path.empty() || failed_offsets.empty())
        return 0;

    HANDLE hFile = CreateFileA(disk_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return 0;

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(hFile, &file_size_li) || file_size_li.QuadPart < 0x100)
    {
        CloseHandle(hFile);
        return 0;
    }


    std::vector<std::uint8_t> disk_hdr(std::min<std::size_t>(
        static_cast<std::size_t>(file_size_li.QuadPart), 0x1000), 0);
    DWORD hdr_read = 0;
    if (!ReadFile(hFile, disk_hdr.data(), static_cast<DWORD>(disk_hdr.size()), &hdr_read, nullptr) ||
        hdr_read < 0x100 || disk_hdr[0] != 'M' || disk_hdr[1] != 'Z')
    {
        CloseHandle(hFile);
        return 0;
    }

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&disk_hdr[0x3C]);
    if (pe_off + 0x18 >= hdr_read || disk_hdr[pe_off] != 'P' || disk_hdr[pe_off + 1] != 'E')
    {
        CloseHandle(hFile);
        return 0;
    }

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&disk_hdr[pe_off + 6]);
    std::uint16_t opt_size = *reinterpret_cast<std::uint16_t*>(&disk_hdr[pe_off + 0x14]);
    std::uint32_t sec_table = pe_off + 0x18 + opt_size;


    struct sec_map_t {
        std::uint32_t rva;
        std::uint32_t vsize;
        std::uint32_t raw_offset;
        std::uint32_t raw_size;
    };
    std::vector<sec_map_t> sec_map;
    for (int i = 0; i < num_sections && i < 96; i++)
    {
        std::uint32_t soff = sec_table + i * 40;
        if (soff + 40 > hdr_read) break;
        sec_map_t sm;
        sm.vsize      = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 8]);
        sm.rva        = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 12]);
        sm.raw_size   = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 16]);
        sm.raw_offset = *reinterpret_cast<std::uint32_t*>(&disk_hdr[soff + 20]);
        if (sm.rva > 0 && sm.raw_size > 0 && sm.raw_offset > 0)
            sec_map.push_back(sm);
    }

    constexpr std::size_t PAGE_SIZE = 0x1000;
    int recovered = 0;

    for (std::size_t pg_off : failed_offsets)
    {
        if (pg_off >= image.size()) continue;
        std::size_t pg_sz = std::min(PAGE_SIZE, image.size() - pg_off);


        bool has_data = false;
        for (std::size_t i = 0; i < pg_sz; i++)
        {
            if (image[pg_off + i] != 0) { has_data = true; break; }
        }
        if (has_data) continue;


        for (const auto& sm : sec_map)
        {
            if (pg_off >= sm.rva && pg_off < sm.rva + sm.vsize)
            {
                std::uint32_t offset_in_sec = static_cast<std::uint32_t>(pg_off - sm.rva);
                if (offset_in_sec < sm.raw_size)
                {
                    std::uint32_t file_offset = sm.raw_offset + offset_in_sec;
                    std::uint32_t copy_size = std::min<std::uint32_t>(
                        static_cast<std::uint32_t>(pg_sz),
                        sm.raw_size - offset_in_sec);

                    LARGE_INTEGER seek_pos;
                    seek_pos.QuadPart = file_offset;
                    if (SetFilePointerEx(hFile, seek_pos, nullptr, FILE_BEGIN))
                    {
                        DWORD rd = 0;
                        if (ReadFile(hFile, image.data() + pg_off, copy_size, &rd, nullptr) && rd > 0)
                            recovered++;
                    }
                }
                break;
            }
        }
    }

    CloseHandle(hFile);

    if (recovered > 0)
    {
        steps_log.push_back({{"step", "disk_fallback"}, {"ok", true},
            {"detail", std::to_string(recovered) + " pages recovered from on-disk PE: " + disk_path}});
        msg(OBFSTR_C("AiDA: Disk fallback recovered %d pages from %s\n"),
            recovered, disk_path.c_str());
    }

    return recovered;
}


static vad_dump_plan_t build_vad_dump_plan(
    voyager::device_t* dev,
    std::uint64_t module_base,
    std::uint64_t pe_size_of_image,
    nlohmann::json& steps_log)
{
    (void)dev;

    vad_dump_plan_t plan;
    plan.module_base = module_base;
    plan.pe_size_of_image = pe_size_of_image;
    plan.total_span = pe_size_of_image;

    if (plan.total_span == 0)
        plan.total_span = 0x1000;

    plan.regions.push_back({0, plan.total_span, 0});
    plan.total_committed_bytes = plan.total_span;
    plan.committed_region_count = 1;
    plan.used_vad = false;

    std::ostringstream detail_ss;
    detail_ss << "raw runtime snapshot over exact module span 0x"
              << std::hex << std::uppercase << plan.total_span
              << " (" << std::dec << (plan.total_span / (1024 * 1024)) << " MB)"
              << ", 1 region, no VAD expansion or reconstruction";

    steps_log.push_back({{"step", "module_range"}, {"ok", true}, {"detail", detail_ss.str()}});

    return plan;
}


static double calculate_page_entropy(const std::uint8_t* data, std::size_t size)
{
    if (size == 0) return 0.0;
    std::uint32_t freq[256] = {};
    for (std::size_t i = 0; i < size; i++)
        freq[data[i]]++;
    double entropy = 0.0;
    double inv_size = 1.0 / static_cast<double>(size);
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) * inv_size;
        entropy -= p * std::log2(p);
    }
    return entropy;
}


struct protection_analysis_t
{
    bool is_packed = false;
    bool is_vmprotected = false;
    bool is_themida = false;
    bool is_upx = false;
    bool has_encrypted_sections = false;
    bool header_was_wiped = false;
    int zero_code_pages = 0;
    int high_entropy_pages = 0;
    int total_code_pages = 0;
    int encrypted_section_count = 0;
    double avg_code_entropy = 0.0;
    std::vector<std::string> detected_protections;
};


static protection_analysis_t analyze_module_protection(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    bool header_wiped,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    bool is_kernel,
    nlohmann::json& steps)
{
    protection_analysis_t result;
    result.header_was_wiped = header_wiped;

    if (header_wiped)
        result.detected_protections.push_back(OBFSTR("Header wiped (anti-dump/anti-cheat)"));

    if (!has_valid_pe || hdr_read < 0x200)
    {
        steps.push_back({{"step", "dynamic_analysis"}, {"ok", true},
            {"detail", "PE header invalid/wiped - skipping detailed analysis, will use aggressive dump strategy"}});
        return result;
    }

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        char sec_name[9] = {};
        std::memcpy(sec_name, pe_hdr + soff, 8);

        if (std::strstr(sec_name, ".vmp") || std::strstr(sec_name, "VMPr") ||
            std::strstr(sec_name, ".VMP"))
        {
            result.is_vmprotected = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("VMProtect (section: ") + std::string(sec_name) + ")");
        }
        else if (std::strstr(sec_name, ".them") || std::strstr(sec_name, ".winl") ||
                 std::strcmp(sec_name, ".boot") == 0)
        {
            result.is_themida = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("Themida/WinLicense (section: ") + std::string(sec_name) + ")");
        }
        else if (std::strcmp(sec_name, "UPX0") == 0 || std::strcmp(sec_name, "UPX1") == 0 ||
                 std::strcmp(sec_name, "UPX2") == 0 || std::strcmp(sec_name, ".UPX0") == 0)
        {
            result.is_upx = true;
            result.is_packed = true;
            result.detected_protections.push_back(
                OBFSTR("UPX (section: ") + std::string(sec_name) + ")");
        }
    }

    double total_entropy = 0.0;
    int entropy_pages = 0;
    constexpr std::size_t ENTROPY_PAGE = 0x1000;

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
        std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
        std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);

        if (vsize == 0 || vrva == 0) continue;
        if (!(chars & 0x20) && !(chars & 0x20000000)) continue;

        std::uint32_t max_sample_pages = std::min<std::uint32_t>(vsize / static_cast<std::uint32_t>(ENTROPY_PAGE), 64);
        if (max_sample_pages == 0) max_sample_pages = 1;
        std::vector<std::uint8_t> page_buf(ENTROPY_PAGE);

        int sec_zero_pages = 0;
        int sec_high_entropy_pages = 0;
        int sec_total_pages = 0;

        for (std::uint32_t pi = 0; pi < max_sample_pages; pi++)
        {
            std::uint64_t pg_addr = base + vrva + pi * ENTROPY_PAGE;
            if (vrva + pi * ENTROPY_PAGE + ENTROPY_PAGE > image_size) break;

            std::memset(page_buf.data(), 0, ENTROPY_PAGE);
            std::size_t got = is_kernel
                ? dev->read_kernel_raw(pg_addr, page_buf.data(), ENTROPY_PAGE)
                : dev->read_raw(pg_addr, page_buf.data(), ENTROPY_PAGE);
            result.total_code_pages++;
            sec_total_pages++;

            if (got < ENTROPY_PAGE)
            {
                result.zero_code_pages++;
                sec_zero_pages++;
                continue;
            }

            bool is_empty = true;
            for (std::size_t i = 0; i < ENTROPY_PAGE; i++)
            {
                if (page_buf[i] != 0x00 && page_buf[i] != 0xCC)
                {
                    is_empty = false;
                    break;
                }
            }

            if (is_empty)
            {
                result.zero_code_pages++;
                sec_zero_pages++;
                continue;
            }

            double ent = calculate_page_entropy(page_buf.data(), ENTROPY_PAGE);
            total_entropy += ent;
            entropy_pages++;

            if (ent > 7.0)
            {
                result.high_entropy_pages++;
                sec_high_entropy_pages++;
            }
        }

        if (sec_total_pages > 0 &&
            (sec_zero_pages == sec_total_pages ||
             sec_high_entropy_pages > sec_total_pages / 2))
        {
            result.encrypted_section_count++;
        }
    }

    if (entropy_pages > 0)
        result.avg_code_entropy = total_entropy / entropy_pages;

    if (result.zero_code_pages > 0)
    {
        result.has_encrypted_sections = true;
        result.detected_protections.push_back(
            OBFSTR("Encrypted/guarded code sections (") + std::to_string(result.zero_code_pages) +
            "/" + std::to_string(result.total_code_pages) + OBFSTR(" pages empty)"));
    }

    if (result.high_entropy_pages > entropy_pages / 2 && entropy_pages > 4)
    {
        result.has_encrypted_sections = true;
        std::ostringstream ent_ss;
        ent_ss << std::fixed << std::setprecision(2) << result.avg_code_entropy;
        result.detected_protections.push_back(
            OBFSTR("High entropy code (") + std::to_string(result.high_entropy_pages) +
            "/" + std::to_string(entropy_pages) + OBFSTR(" pages >7.0 bits, avg=") +
            ent_ss.str() + ")");
    }

    std::string detail;
    if (result.detected_protections.empty())
    {
        std::ostringstream ent_ss;
        ent_ss << std::fixed << std::setprecision(2) << result.avg_code_entropy;
        detail = OBFSTR("No known protections detected, avg code entropy = ") + ent_ss.str();
    }
    else
    {
        detail = OBFSTR("Detected: ");
        for (std::size_t i = 0; i < result.detected_protections.size(); i++)
        {
            if (i > 0) detail += "; ";
            detail += result.detected_protections[i];
        }
    }

    steps.push_back({{"step", "dynamic_analysis"}, {"ok", true}, {"detail", detail}});
    msg(OBFSTR_C("AiDA: Pre-dump dynamic analysis - %s\n"), detail.c_str());

    return result;
}


static int force_decrypt_via_shellcode(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    nlohmann::json& steps)
{
    if (!dev || !dev->is_connected() || dev->get_process_id() == 0)
        return 0;


    struct page_range_t { std::uint64_t start; std::uint64_t end; };
    std::vector<page_range_t> code_ranges;

    if (has_valid_pe)
    {
        for (int si = 0; si < sections_count && si < 96; si++)
        {
            std::uint32_t soff = sec_table_off + si * 40;
            if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;
            std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
            std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
            std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);
            if (vsize == 0 || vrva == 0) continue;

            if (chars & (0x20000000 | 0x00000020))
            {
                std::uint64_t sec_start = base + vrva;
                std::uint64_t sec_end = sec_start + std::min<std::uint64_t>(vsize,
                    (vrva < image_size) ? (image_size - vrva) : 0);
                if (sec_end > sec_start)
                    code_ranges.push_back({sec_start, sec_end});
            }
        }
    }
    else
    {

        code_ranges.push_back({base, base + image_size});
    }

    if (code_ranges.empty())
        return 0;


    constexpr std::uint32_t VMEM_COMMIT = 0x1000;
    constexpr std::uint32_t PROT_NOACCESS = 0x01;

    auto all_regions = enumerate_all_memory_regions_paginated(dev, base, base + image_size, true);

    std::vector<std::uint64_t> noaccess_pages;
    for (const auto& r : all_regions)
    {
        if (!(r.state & VMEM_COMMIT) || r.protect != PROT_NOACCESS)
            continue;


        for (const auto& cr : code_ranges)
        {
            std::uint64_t overlap_start = std::max(r.base, cr.start);
            std::uint64_t overlap_end = std::min(r.base + r.size, cr.end);
            if (overlap_start >= overlap_end) continue;


            for (std::uint64_t addr = overlap_start & ~0xFFFULL; addr < overlap_end; addr += 0x1000)
            {
                if (addr >= cr.start && addr < cr.end)
                    noaccess_pages.push_back(addr);
            }
        }
    }

    if (noaccess_pages.empty())
    {


        static const std::uint8_t touch_sc[] = {
            0x53,
            0x56,
            0x57,
            0x48, 0x89, 0xCB,
            0x48, 0x89, 0xD6,
            0x31, 0xFF,

            0x48, 0x39, 0xF7,
            0x7D, 0x0F,
            0x0F, 0xB6, 0x03,
            0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00,
            0x48, 0xFF, 0xC7,
            0xEB, 0xEC,

            0x48, 0x89, 0xF8,
            0x5F,
            0x5E,
            0x5B,
            0xC3
        };

        std::uint64_t sc_mem = dev->allocate_memory(0x1000);
        if (sc_mem == 0) return 0;

        dev->write_raw(sc_mem, touch_sc, sizeof(touch_sc));

        int total_touched = 0;
        for (const auto& cr : code_ranges)
        {
            std::uint64_t page_count = (cr.end - cr.start + 0xFFF) / 0x1000;
            std::uint64_t ret = dev->call_function(sc_mem, cr.start, page_count, 0, 0);
            total_touched += static_cast<int>(ret);
        }

        dev->free_memory(sc_mem);

        if (total_touched > 0)
        {
            Sleep(100);
            steps.push_back({{"step", "decrypt_shellcode"}, {"ok", true},
                {"detail", std::to_string(total_touched) +
                    " code pages touched via usermode fault-trigger (no NOACCESS regions detected, full sweep)"}});
            msg(OBFSTR_C("AiDA: Shellcode touched %d code pages (full sweep, no NOACCESS pages found)\n"),
                total_touched);
        }
        return total_touched;
    }


    std::size_t addr_list_size = noaccess_pages.size() * sizeof(std::uint64_t);
    std::size_t alloc_size = 0x1000 + ((addr_list_size + 0xFFF) & ~0xFFFULL);
    if (alloc_size > 0x1000000) alloc_size = 0x1000000;

    std::uint64_t sc_mem = dev->allocate_memory(alloc_size);
    if (sc_mem == 0)
    {
        steps.push_back({{"step", "decrypt_shellcode"}, {"ok", false},
            {"detail", "Failed to allocate shellcode memory in target process"}});
        return 0;
    }


    static const std::uint8_t list_sc[] = {
        0x53,
        0x56,
        0x57,
        0x48, 0x89, 0xCB,
        0x48, 0x89, 0xD6,
        0x31, 0xFF,

        0x48, 0x39, 0xF7,
        0x7D, 0x0C,
        0x48, 0x8B, 0x0C, 0xFB,
        0x0F, 0xB6, 0x01,
        0x48, 0xFF, 0xC7,
        0xEB, 0xEF,

        0x48, 0x89, 0xF8,
        0x5F,
        0x5E,
        0x5B,
        0xC3
    };


    dev->write_raw(sc_mem, list_sc, sizeof(list_sc));


    std::uint64_t addr_list_base = sc_mem + 0x100;
    std::size_t max_entries = (alloc_size - 0x100) / sizeof(std::uint64_t);
    std::size_t entries = std::min(noaccess_pages.size(), max_entries);

    dev->write_raw(addr_list_base, noaccess_pages.data(),
        entries * sizeof(std::uint64_t));

    msg(OBFSTR_C("AiDA: Injecting decrypt shellcode - %zu NOACCESS code pages to trigger...\n"),
        entries);


    std::uint64_t ret = dev->call_function(sc_mem, addr_list_base, entries, 0, 0);

    dev->free_memory(sc_mem);

    int pages_decrypted = static_cast<int>(ret);

    if (pages_decrypted > 0)
        Sleep(100);

    steps.push_back({{"step", "decrypt_shellcode"}, {"ok", pages_decrypted > 0},
        {"detail", std::to_string(pages_decrypted) + "/" + std::to_string(entries) +
            " NOACCESS code pages triggered via usermode exception-based decryption"}});
    msg(OBFSTR_C("AiDA: Shellcode decryption complete - %d/%zu pages triggered\n"),
        pages_decrypted, entries);

    return pages_decrypted;
}


static int force_code_pages_in_memory(
    voyager::device_t* dev,
    std::uint64_t base,
    const std::uint8_t* pe_hdr,
    std::size_t hdr_read,
    bool has_valid_pe,
    std::uint32_t pe_off,
    std::uint16_t sections_count,
    std::uint32_t sec_table_off,
    std::uint32_t image_size,
    nlohmann::json& steps)
{
    if (!has_valid_pe || !dev || !dev->is_connected() || dev->get_process_id() == 0)
        return 0;

    auto modules = enumerate_ldr_modules_for_iat(dev);

    std::uint64_t kernel32_base = 0;
    for (const auto& m : modules)
    {
        std::string lower = m.name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "kernel32.dll")
        {
            kernel32_base = m.base;
            break;
        }
    }

    if (kernel32_base == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "kernel32.dll not found in target - skipping active page forcing"}});
        return 0;
    }

    std::uint64_t vp_addr = dev->resolve_export(kernel32_base, "VirtualProtect");
    if (vp_addr == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "Could not resolve VirtualProtect - skipping active page forcing"}});
        return 0;
    }

    std::uint64_t old_prot_buf = dev->allocate_memory(0x1000);
    if (old_prot_buf == 0)
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "Could not allocate scratch buffer - skipping active page forcing"}});
        return 0;
    }

    int pages_forced = 0;
    constexpr std::uint32_t kPageExecReadWrite = 0x40;
    constexpr std::uint64_t VP_CHUNK = 0x10000;

    for (int si = 0; si < sections_count && si < 96; si++)
    {
        std::uint32_t soff = sec_table_off + si * 40;
        if (soff + 40 > static_cast<std::uint32_t>(hdr_read)) break;

        std::uint32_t vsize = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 8);
        std::uint32_t vrva  = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 12);
        std::uint32_t chars = *reinterpret_cast<const std::uint32_t*>(pe_hdr + soff + 36);

        if (vsize == 0 || vrva == 0 || !(chars & 0x20000000)) continue;

        std::uint64_t sec_addr = base + vrva;
        std::uint64_t sec_size = std::min<std::uint64_t>(vsize,
            (vrva < image_size) ? (image_size - vrva) : 0);
        if (sec_size == 0) continue;

        for (std::uint64_t off = 0; off < sec_size; off += VP_CHUNK)
        {
            std::uint64_t chunk_size = std::min(VP_CHUNK, sec_size - off);
            std::uint64_t ret = dev->call_function(vp_addr,
                sec_addr + off,
                chunk_size,
                kPageExecReadWrite,
                old_prot_buf);

            if (ret != 0)
                pages_forced += static_cast<int>(chunk_size / 0x1000);
        }
    }

    dev->free_memory(old_prot_buf);

    if (pages_forced > 0)
    {
        Sleep(150);

        steps.push_back({{"step", "force_page_in"}, {"ok", true},
            {"detail", std::to_string(pages_forced) +
                " code pages forced via VirtualProtect to trigger decryption/COW"}});
        msg(OBFSTR_C("AiDA: Forced %d code pages into memory via VirtualProtect\n"), pages_forced);
    }
    else
    {
        steps.push_back({{"step", "force_page_in"}, {"ok", false},
            {"detail", "VirtualProtect calls returned 0 - anti-cheat may have blocked protection changes"}});
    }

    return pages_forced;
}


tool_result_t driver_dump_module(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_dump_module entry");
    json steps = json::array();
    auto log = [&](const std::string& step, bool ok, const std::string& detail = "") {
        steps.push_back({{"step", step}, {"ok", ok}, {"detail", detail}});
    };

    if (!device->is_connected())
    {
        bool ok = device->connect();
        log("connect_driver", ok, ok ? "Connected to kernel driver" : "Failed");
        if (!ok)
            return tool_result_t::error(OBFSTR("Failed to connect to kernel driver. Is the driver loaded?"));
    }
    else
        log("connect_driver", true, "Already connected");

    if (params.contains("process"))
    {
        std::string process_name = params["process"].get<std::string>();
        if (is_ida_host_process_name(process_name))
            return tool_result_t::error(OBFSTR("Refusing to attach dump context to IDA host process name."));

        std::uint32_t pid = device->find_process(process_name.c_str());
        log("find_process", pid != 0, "PID: " + (pid ? std::to_string(pid) : "not found"));
        if (pid == 0)
            return tool_result_t::error(OBFSTR("Process not found: ") + process_name);
    }

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("No process attached. Provide 'process' param or use sessions_manage action=attach_pid."));

    if (device->get_dtb() == 0)
        device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    log("solve_dtb", dtb != 0, sa_format_address(dtb));

    struct resolved_module_t
    {
        std::uint64_t base = 0;
        std::uint64_t entry_point = 0;
        std::uint32_t size = 0;
        std::string name;
        std::string path;
    };

    auto to_lower_ascii = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    };

    auto basename_of_path = [](const std::string& path) {
        std::string::size_type pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    };

    auto read_remote_unicode_ascii = [](voyager::device_t* dev,
                                        std::uint64_t ptr,
                                        std::uint16_t byte_len,
                                        std::uint16_t max_len) -> std::string {
        if (dev == nullptr || ptr == 0 || byte_len == 0 || byte_len > max_len)
            return {};

        std::vector<std::uint8_t> raw(byte_len, 0);
        if (dev->read_raw(ptr, raw.data(), byte_len) == 0)
            return {};

        std::string text;
        text.reserve(byte_len / 2);
        for (std::size_t i = 0; i + 1 < raw.size(); i += 2)
        {
            std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
            if (wc == 0)
                break;
            text += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        return text;
    };

    auto visit_ldr_modules = [&](const std::function<bool(const resolved_module_t&)>& visitor) -> bool {
        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb) || peb.ldr_address == 0)
            return false;

        std::uint64_t list_head = peb.ldr_address + 0x10;
        std::uint64_t first_entry = device->read<std::uint64_t>(list_head);
        if (first_entry == 0 || first_entry == list_head)
            return false;

        std::uint64_t current = first_entry;
        int max_iter = 1024;

        while (current != list_head && current != 0 && max_iter-- > 0)
        {
            resolved_module_t info;
            info.base        = device->read<std::uint64_t>(current + 0x30);
            info.entry_point = device->read<std::uint64_t>(current + 0x38);
            info.size        = device->read<std::uint32_t>(current + 0x40);
            info.path        = read_remote_unicode_ascii(
                device.get(),
                device->read<std::uint64_t>(current + 0x50),
                device->read<std::uint16_t>(current + 0x48),
                1024);
            info.name        = read_remote_unicode_ascii(
                device.get(),
                device->read<std::uint64_t>(current + 0x60),
                device->read<std::uint16_t>(current + 0x58),
                520);

            if (info.base != 0 && !info.name.empty() && visitor(info))
                return true;

            std::uint64_t next = device->read<std::uint64_t>(current);
            if (next == current || next == 0)
                break;
            current = next;
        }

        return true;
    };

    auto find_ldr_module_by_base = [&](std::uint64_t module_base, resolved_module_t* out) {
        bool found = false;
        visit_ldr_modules([&](const resolved_module_t& info) {
            if (info.base != module_base)
                return false;
            if (out != nullptr)
                *out = info;
            found = true;
            return true;
        });
        return found;
    };

    auto find_ldr_module_by_query = [&](const std::string& query, resolved_module_t* out) {
        if (query.empty())
            return false;

        const std::string needle = to_lower_ascii(query);
        bool exact_found = false;
        bool partial_found = false;
        resolved_module_t exact_match;
        resolved_module_t partial_match;

        visit_ldr_modules([&](const resolved_module_t& info) {
            const std::string lower_name = to_lower_ascii(info.name);
            const std::string lower_path = to_lower_ascii(info.path);
            const std::string lower_file = to_lower_ascii(basename_of_path(info.path));
            const bool exact = lower_name == needle || lower_path == needle || lower_file == needle;
            const bool partial = !exact && (
                lower_name.find(needle) != std::string::npos ||
                lower_path.find(needle) != std::string::npos ||
                lower_file.find(needle) != std::string::npos);

            if (exact)
            {
                exact_match = info;
                exact_found = true;
                return true;
            }
            if (!partial_found && partial)
            {
                partial_match = info;
                partial_found = true;
            }
            return false;
        });

        if (exact_found)
        {
            if (out != nullptr)
                *out = exact_match;
            return true;
        }
        if (partial_found)
        {
            if (out != nullptr)
                *out = partial_match;
            return true;
        }
        return false;
    };

    const std::string module_query = params.value("module", std::string());
    if (params.contains("decrypt_timeout"))
        log("decrypt_timeout", true, "Ignored: raw runtime dump mode does not perform decrypt polling");

    uint64_t base = 0xFFFFFFFFFFFFFFFFULL;
    if (params.contains("address"))
    {
        auto a = sa_parse_address(params["address"].get<std::string>());
        if (a) base = *a;
    }

    resolved_module_t resolved_module;
    bool have_resolved_module = false;

    if ((base == 0xFFFFFFFFFFFFFFFFULL || base == 0) && !module_query.empty())
    {
        have_resolved_module = find_ldr_module_by_query(module_query, &resolved_module);
        if (!have_resolved_module)
            return tool_result_t::error(OBFSTR("Loaded module not found: ") + module_query);
        base = static_cast<uint64_t>(resolved_module.base);
        log("resolve_module", true,
            resolved_module.name + " @ " + sa_format_address(base));
    }

    if (base == 0xFFFFFFFFFFFFFFFFULL || base == 0)
    {
        std::uint64_t img_base = device->find_image();
        if (img_base == 0) img_base = device->get_base_address();
        base = static_cast<uint64_t>(img_base);
    }
    if (base == 0 || base == 0xFFFFFFFFFFFFFFFFULL)
        return tool_result_t::error(OBFSTR("Invalid module base. Provide 'address' or attach to a process first."));


    if (!have_resolved_module)
        have_resolved_module = find_ldr_module_by_base(static_cast<std::uint64_t>(base), &resolved_module);

    log("find_image_base", true, sa_format_address(base));

    bool header_wiped = false;
    bool has_valid_pe = false;
    std::uint8_t pe_hdr[0x1000];
    std::memset(pe_hdr, 0, sizeof(pe_hdr));
    std::size_t hdr_read = device->read_raw(base, pe_hdr, sizeof(pe_hdr));

    std::uint32_t pe_off = 0;
    std::uint16_t opt_magic      = 0x020B;
    std::uint16_t sections_count = 0;
    std::uint16_t opt_size       = 0;
    std::uint32_t sec_table_off  = 0;
    std::uint32_t pe_size_of_image = 0;

    if (hdr_read >= 0x200 && *(std::uint16_t*)pe_hdr == 0x5A4D)
    {
        pe_off = *(std::uint32_t*)(pe_hdr + 0x3C);
        if (pe_off + 0x100 <= sizeof(pe_hdr) && *(std::uint32_t*)(pe_hdr + pe_off) == 0x00004550)
        {
            has_valid_pe = true;
            opt_magic      = *(std::uint16_t*)(pe_hdr + pe_off + 0x18);
            sections_count = *(std::uint16_t*)(pe_hdr + pe_off + 0x06);
            opt_size       = *(std::uint16_t*)(pe_hdr + pe_off + 0x14);
            sec_table_off  = pe_off + 0x18 + opt_size;
            if (opt_magic == 0x020B || opt_magic == 0x010B)
                pe_size_of_image = *(std::uint32_t*)(pe_hdr + pe_off + 0x18 + 0x38);

            log("read_pe_header", true, std::to_string(hdr_read) + " bytes, " +
                std::to_string(sections_count) + " sections, SizeOfImage=0x" +
                sa_format_address(static_cast<uint64_t>(pe_size_of_image)));
        }
        else
        {
            header_wiped = true;
            log("read_pe_header", false, "MZ found but PE signature invalid/corrupt - will synthesize header after dump");
        }
    }
    else
    {
        header_wiped = true;
        msg(OBFSTR_C("AiDA: WARNING - MZ signature not found at base %s (read %zu bytes). "
            "Header likely wiped by anti-cheat. Will synthesize PE header after dump.\n"),
            sa_format_address(base).c_str(), hdr_read);
        log("read_pe_header", false,
            "MZ signature wiped/missing - anti-cheat header erasure detected. Will synthesize after dump.");
    }

    std::uint64_t ldr_sz = 0;
    if (have_resolved_module && resolved_module.size > 0)
        ldr_sz = resolved_module.size;
    else
        ldr_sz = get_ldr_module_size(device.get(), base);

    if (params.contains("size"))
        pe_size_of_image = static_cast<std::uint32_t>(params.value("size", static_cast<std::size_t>(pe_size_of_image)));
    else if (ldr_sz > 0)
        pe_size_of_image = static_cast<std::uint32_t>(ldr_sz);
    else if (pe_size_of_image == 0)
        pe_size_of_image = 0x2000000;

    std::string module_name = have_resolved_module && !resolved_module.name.empty()
        ? resolved_module.name
        : params.value("process", std::string("module"));


    std::string module_disk_path = have_resolved_module && !resolved_module.path.empty()
        ? resolved_module.path
        : get_ldr_module_file_path(device.get(), base);
    if (!module_disk_path.empty())
        log("resolve_disk_path", true, module_disk_path);

    device->solve_dtb();
    if (device->get_dtb() == 0)
        return tool_result_t::error(OBFSTR("DTB solve failed before dump. Cannot read process memory."));

    protection_analysis_t protection = analyze_module_protection(
        device.get(), base, pe_hdr, hdr_read, has_valid_pe, header_wiped,
        pe_off, sections_count, sec_table_off, pe_size_of_image, false, steps);

    vad_dump_plan_t vad_plan = build_vad_dump_plan(device.get(), base, pe_size_of_image, steps);

    std::size_t module_size = static_cast<std::size_t>(vad_plan.total_span);
    if (module_size == 0)
        module_size = static_cast<std::size_t>(pe_size_of_image);
    if (module_size > 0x200000000ULL)
        return tool_result_t::error(OBFSTR("Module size too large (>8GB): ") + std::to_string(module_size));

    msg(OBFSTR_C("AiDA: Module dump plan - %d region, span 0x%zX (%zu MB), image size 0x%X (%u MB)\n"),
        vad_plan.committed_region_count, module_size, module_size / (1024 * 1024),
        pe_size_of_image, pe_size_of_image / (1024 * 1024));


    std::vector<std::uint32_t> suspended_tids;
    {
        auto threads = device->enumerate_threads();
        for (const auto& t : threads)
        {
            std::uint32_t prev = 0;
            if (device->suspend_thread(t.tid, &prev))
                suspended_tids.push_back(t.tid);
        }
        log("suspend_threads", !suspended_tids.empty(),
            std::to_string(suspended_tids.size()) + "/" + std::to_string(threads.size()) +
            " threads suspended for consistent snapshot");
        if (!suspended_tids.empty())
            msg(OBFSTR_C("AiDA: Suspended %zu/%zu threads for dump consistency\n"),
                suspended_tids.size(), threads.size());
    }


    struct thread_resume_guard_t {
        voyager::device_t* dev;
        std::vector<std::uint32_t>& tids;
        bool released = false;
        ~thread_resume_guard_t() { if (!released) resume(); }
        void resume() {
            for (std::uint32_t tid : tids) dev->resume_thread(tid);
            released = true;
        }
    } thread_guard{device.get(), suspended_tids};

    std::vector<std::uint8_t> module_data(module_size, 0);
    std::size_t total_read = 0;
    int failed_pages = 0;

    std::memcpy(module_data.data(), pe_hdr, std::min<std::size_t>(hdr_read, module_size));
    total_read = std::min<std::size_t>(hdr_read, module_size);

    show_wait_box("HIDECANCEL\nAiDA: Dumping %s via kernel - %d regions, 0x%zX bytes (%zu MB)...",
                  module_name.c_str(), vad_plan.committed_region_count, module_size,
                  module_size / (1024 * 1024));

    constexpr std::size_t DUMP_CHUNK = 0x10000;
    constexpr std::size_t DUMP_PAGE  = 0x1000;
    std::vector<std::size_t> failed_offsets;
    int region_idx = 0;


    struct code_section_range_t {
        std::size_t offset;
        std::size_t size;
    };
    std::vector<code_section_range_t> code_sections;
    if (has_valid_pe)
    {
        std::uint32_t fixed_pe_off = pe_off;
        std::uint16_t fixed_nsec = sections_count;
        std::uint32_t fixed_sec_table = sec_table_off;
        for (int si = 0; si < fixed_nsec && si < 96; si++)
        {
            std::uint32_t soff = fixed_sec_table + si * 40;
            if (soff + 40 > sizeof(pe_hdr)) break;
            std::uint32_t vsize = *(std::uint32_t*)(pe_hdr + soff + 8);
            std::uint32_t vrva  = *(std::uint32_t*)(pe_hdr + soff + 12);
            std::uint32_t chars = *(std::uint32_t*)(pe_hdr + soff + 36);
            if (vsize == 0 || vrva == 0) continue;
            if (chars & 0x20)
            {
                std::size_t sec_end = static_cast<std::size_t>(vrva) + vsize;
                if (sec_end > module_size) sec_end = module_size;
                if (vrva < module_size)
                    code_sections.push_back({static_cast<std::size_t>(vrva), sec_end - vrva});
            }
        }
    }

    for (const auto& region : vad_plan.regions)
    {
        region_idx++;
        if (region.offset >= module_size) continue;

        std::size_t read_size = static_cast<std::size_t>(
            std::min(region.size, static_cast<std::uint64_t>(module_size - region.offset)));

        std::size_t start_off = 0;
        if (region.offset == 0)
            start_off = std::min<std::size_t>(hdr_read, read_size);

        for (std::size_t chunk_off = start_off; chunk_off < read_size; chunk_off += DUMP_CHUNK)
        {
            std::size_t buf_offset = static_cast<std::size_t>(region.offset) + chunk_off;

            if (buf_offset % 0x400000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Dumping %s - region %d/%d (0x%zX / 0x%zX, %.1f%%)...",
                                 module_name.c_str(), region_idx, vad_plan.committed_region_count,
                                 buf_offset, module_size, (buf_offset * 100.0) / module_size);

            std::size_t to_read = std::min(DUMP_CHUNK, read_size - chunk_off);
            std::size_t got = device->read_raw(base + buf_offset, module_data.data() + buf_offset, to_read);

            if (got >= to_read)
            {
                total_read += got;
                continue;
            }

            for (std::size_t pg = 0; pg < to_read; pg += DUMP_PAGE)
            {
                std::size_t pg_off = buf_offset + pg;
                if (pg_off >= module_size) break;
                std::size_t pg_sz  = std::min(DUMP_PAGE, module_size - pg_off);
                std::size_t pg_got = device->read_raw(
                    base + pg_off, module_data.data() + pg_off, pg_sz);
                if (pg_got > 0)
                    total_read += pg_got;
                else
                {
                    failed_pages++;
                    failed_offsets.push_back(pg_off);
                }
            }
        }
    }


    if (!failed_offsets.empty())
    {
        replace_wait_box("HIDECANCEL\nAiDA: Re-solving DTB and retrying %d failed pages...",
                         static_cast<int>(failed_offsets.size()));
        device->solve_dtb();

        int recovered = 0;
        for (std::size_t fo : failed_offsets)
        {
            if (fo >= module_size) continue;
            std::size_t pg_sz  = std::min(DUMP_PAGE, module_size - fo);
            std::size_t pg_got = device->read_raw(
                base + fo, module_data.data() + fo, pg_sz);
            if (pg_got > 0)
            {
                total_read += pg_got;
                recovered++;
            }
        }

        if (recovered > 0)
            msg(OBFSTR_C("AiDA: DTB re-solve recovered %d/%d failed pages\n"),
                recovered, static_cast<int>(failed_offsets.size()));

        failed_pages -= recovered;
    }


    hide_wait_box();

    log("dump_image", total_read > 0, std::to_string(total_read) + "/" + std::to_string(module_size) + " bytes" +
        (failed_pages > 0 ? (", " + std::to_string(failed_pages) + " pages unreadable") : ""));


    thread_guard.resume();
    log("resume_threads", true, std::to_string(suspended_tids.size()) + " threads resumed");


    std::string output_path = params.value("output_path", std::string());
    if (output_path.empty())
    {
        output_path = get_downloads_folder() + "dumped_" + module_name + "_" +
                      sa_format_address(base) + ".bin";
    }
    ensure_parent_dir_exists(output_path);
    {
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            const std::uint8_t* write_ptr = module_data.data();
            std::size_t remaining = module_size;
            bool write_ok = true;

            while (remaining > 0)
            {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 0x40000000ULL));
                DWORD written = 0;
                if (!WriteFile(hFile, write_ptr, chunk, &written, nullptr) || written != chunk)
                {
                    write_ok = false;
                    msg(OBFSTR_C("AiDA: WARNING - WriteFile failed at offset 0x%zX (error %lu)\n"),
                        module_size - remaining, GetLastError());
                    break;
                }
                write_ptr += written;
                remaining -= written;
            }

            CloseHandle(hFile);
            if (write_ok)
                msg(OBFSTR_C("AiDA: Dump saved to %s (%zu bytes, %zu MB)\n"),
                    output_path.c_str(), module_size, module_size / (1024 * 1024));
        }
        else
            msg(OBFSTR_C("AiDA: WARNING - Failed to save dump file: %s (error %lu)\n"),
                output_path.c_str(), GetLastError());
    }
    log("save_to_disk", true, output_path);

    bool patch_idb = params.value("patch_idb", true);
    std::size_t patched = 0;
    int segs_created = 0;
    json segs_info = json::array();

    if (patch_idb)
    {
        show_wait_box("HIDECANCEL\nAiDA: Creating IDB segments and patching bytes...");

        std::uint16_t fixed_sections_count = sections_count;
        std::uint32_t fixed_sec_table_off  = sec_table_off;
        if (has_valid_pe && module_size > 0x200)
        {
            std::uint32_t fixed_pe_off = *reinterpret_cast<std::uint32_t*>(module_data.data() + 0x3C);
            if (fixed_pe_off + 0x18 < module_size)
            {
                fixed_sections_count = *reinterpret_cast<std::uint16_t*>(module_data.data() + fixed_pe_off + 6);
                std::uint16_t fixed_opt_size = *reinterpret_cast<std::uint16_t*>(module_data.data() + fixed_pe_off + 0x14);
                fixed_sec_table_off = fixed_pe_off + 0x18 + fixed_opt_size;
            }
        }

        for (int si = 0; si < fixed_sections_count && si < 96; si++)
        {
            std::uint32_t soff = fixed_sec_table_off + si * 40;
            if (soff + 40 > module_size) break;

            const std::uint8_t* sec = module_data.data() + soff;

            char name[9] = {0};
            memcpy(name, sec, 8);
            std::uint32_t vsize = *(std::uint32_t*)(sec + 8);
            std::uint32_t vrva  = *(std::uint32_t*)(sec + 12);
            std::uint32_t chars = *(std::uint32_t*)(sec + 36);
            if (vsize == 0 || vrva == 0) continue;

            uint64_t sec_start = base + vrva;
            uint64_t sec_end   = sec_start + vsize;

            uchar perm = 0;
            if (chars & 0x40000000) perm |= SEGPERM_READ;
            if (chars & 0x80000000) perm |= SEGPERM_WRITE;
            if (chars & 0x20000000) perm |= SEGPERM_EXEC;

            if (!getseg(sec_start))
            {
                segment_t new_seg;
                new_seg.start_ea = sec_start;
                new_seg.end_ea   = sec_end;
                new_seg.type     = (perm & SEGPERM_EXEC) ? SEG_CODE : SEG_DATA;
                new_seg.bitness  = (opt_magic == 0x020B) ? 2 : 1;
                new_seg.perm     = perm;
                new_seg.align    = saRelByte;
                new_seg.comb     = scPub;
                const char* sclass = (perm & SEGPERM_EXEC) ? "CODE" : "DATA";
                if (add_segm_ex(&new_seg, name, sclass, ADDSEG_QUIET | ADDSEG_NOSREG))
                {
                    segment_t* seg = getseg(sec_start);
                    if (seg) { seg->perm = perm; seg->update(); }
                    segs_created++;
                    segs_info.push_back({{"name", std::string(name)},
                                         {"start", sa_format_address(sec_start)},
                                         {"size", vsize}});
                }
            }

            if (vrva < module_size && vsize > 0)
            {
                std::uint32_t copy_len = vsize;
                if (vrva + copy_len > module_size)
                    copy_len = static_cast<std::uint32_t>(module_size - vrva);
                if (copy_len > 0 && is_mapped(sec_start))
                {
                    put_bytes(sec_start, module_data.data() + vrva, copy_len);
                    patched += copy_len;
                }
            }
        }

        if (patched == 0 && module_size > 0)
        {
            if (!getseg(base))
            {
                segment_t raw_seg;
                raw_seg.start_ea = base;
                raw_seg.end_ea   = base + module_size;
                raw_seg.type     = SEG_NORM;
                raw_seg.bitness  = (opt_magic == 0x020B) ? 2 : 1;
                raw_seg.perm     = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
                raw_seg.align    = saRelByte;
                raw_seg.comb     = scPub;

                const char* seg_name = module_name.empty() ? "runtime_dump" : module_name.c_str();
                if (add_segm_ex(&raw_seg, seg_name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG))
                {
                    segs_created++;
                    segs_info.push_back({{"name", std::string(seg_name)},
                                         {"start", sa_format_address(base)},
                                         {"size", module_size}});
                }
            }

            if (is_mapped(base))
            {
                put_bytes(base, module_data.data(), module_size);
                patched = module_size;
            }
        }

        hide_wait_box();
        log("patch_idb", patched > 0, std::to_string(patched) + " bytes patched, " +
            std::to_string(segs_created) + " segments created");
    }

    bool hb = device->send_heartbeat();
    log("heartbeat", hb, hb ? "Session maintained" : "Failed (non-fatal)");

    json result;
    result["base"]            = sa_format_address(base);
    result["module_name"]     = module_name;
    result["image_size"]      = module_size;
    result["pe_size_of_image"] = static_cast<std::size_t>(pe_size_of_image);
    result["bytes_dumped"]    = total_read;
    result["coverage_pct"]    = module_size ? (int)((total_read * 100) / module_size) : 0;
    result["saved_to"]        = output_path;
    result["can_load_in_ida"] = has_valid_pe && !header_wiped;
    result["raw_runtime_dump"] = true;
    result["post_processing_applied"] = false;
    result["header_valid"]    = has_valid_pe;
    result["header_wiped"]    = header_wiped;
    result["threads_suspended"]  = static_cast<int>(suspended_tids.size());
    if (!module_disk_path.empty())
        result["module_path"] = module_disk_path;
    if (!protection.detected_protections.empty())
    {
        result["protections_detected"] = protection.detected_protections;
        result["is_packed"] = protection.is_packed;
        if (protection.is_vmprotected) result["vmprotect"] = true;
        if (protection.is_themida) result["themida"] = true;
        if (protection.is_upx) result["upx"] = true;
    }
    if (protection.total_code_pages > 0)
    {
        json analysis;
        analysis["total_code_pages"] = protection.total_code_pages;
        analysis["zero_pages"] = protection.zero_code_pages;
        analysis["high_entropy_pages"] = protection.high_entropy_pages;
        analysis["avg_entropy"] = protection.avg_code_entropy;
        result["pre_dump_analysis"] = analysis;
    }
    result["steps"]           = steps;
    if (vad_plan.used_vad)
    {
        result["vad_regions"]          = vad_plan.committed_region_count;
        result["vad_committed_bytes"]  = vad_plan.total_committed_bytes;
        result["vad_extended"]         = (vad_plan.total_span > vad_plan.pe_size_of_image);
        if (vad_plan.total_span > vad_plan.pe_size_of_image)
            result["vad_extension_mb"] = (vad_plan.total_span - vad_plan.pe_size_of_image) / (1024 * 1024);
    }
    if (patch_idb)
    {
        result["patched_idb"]      = true;
        result["bytes_patched"]    = patched;
        result["sections_created"] = segs_created;
        if (!segs_info.empty())
            result["segments"] = segs_info;
    }
    result["note"] = std::string(
        OBFSTR("This dump preserves the module exactly as it existed in target memory. "
               "No decryption, devirtualization, header synthesis, IAT reconstruction, or disk fallback was applied. ")) +
        (header_wiped || !has_valid_pe
            ? OBFSTR("The in-memory image does not currently expose a clean PE header. "
                     "Open the saved file with manual load and set the image base to ") + sa_format_address(base) + OBFSTR(".")
            : OBFSTR("Open the saved file in a clean disassembler session. If needed, use manual load with image base ") + sa_format_address(base) + OBFSTR("."));

    return tool_result_t::ok(OBFSTR("Module dumped: ") + std::to_string(total_read) + "/" +
                             std::to_string(module_size) + " bytes -> " + output_path +
                             OBFSTR(". Open this file in a clean disassembler session for proper analysis."), result);
}


tool_result_t driver_read_pointer_chain(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_pointer_chain entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::string base_address;
    if (params.contains("address") && params["address"].is_string())
        base_address = params["address"].get<std::string>();
    else if (params.contains("base_address") && params["base_address"].is_string())
        base_address = params["base_address"].get<std::string>();

    auto ea_opt = sa_parse_address(base_address);
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address. Use address='0x...' (alias base_address is supported)."));

    std::vector<std::int64_t> offsets;
    if (params.contains("offsets") && params["offsets"].is_array())
    {
        for (const auto& off : params["offsets"])
        {
            if (off.is_number_integer())
                offsets.push_back(off.get<std::int64_t>());
            else if (off.is_string())
            {
                auto o = sa_parse_address(off.get<std::string>());
                if (o) offsets.push_back(static_cast<std::int64_t>(*o));
            }
        }
    }


    json chain = json::array();
    std::uint64_t current = *ea_opt;
    chain.push_back({{"step", 0}, {"address", sa_format_address(current)}, {"type", "base"}});

    for (std::size_t i = 0; i < offsets.size(); i++)
    {

        std::uint64_t ptr = device->read<std::uint64_t>(current);
        if (ptr == 0)
        {
            chain.push_back({{"step", (int)(i + 1)}, {"error", "null pointer"}, {"offset", offsets[i]}});
            break;
        }
        std::uint64_t next = ptr + offsets[i];
        chain.push_back({{"step", (int)(i + 1)},
                         {"deref", sa_format_address(ptr)},
                         {"offset", offsets[i]},
                         {"address", sa_format_address(next)}});
        current = next;
    }

    std::uint64_t final_val = device->read<std::uint64_t>(current);

    json result;
    result["initial_address"]    = sa_format_address(*ea_opt);
    result["final_address"]      = sa_format_address(current);
    result["final_value"]        = sa_format_address(final_val);
    result["final_value_decimal"] = final_val;
    result["chain"]              = chain;
    return tool_result_t::ok(OBFSTR("Pointer chain traversed"), result);
}

static std::string resolve_nt_path_to_win32(const std::string& nt_path)
{
    std::string result = nt_path;
    std::replace(result.begin(), result.end(), '/', '\\');

    if (result.size() >= 12)
    {
        std::string prefix_lower = result.substr(0, 12);
        std::transform(prefix_lower.begin(), prefix_lower.end(), prefix_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (prefix_lower == "\\systemroot\\")
        {
            char win_dir[MAX_PATH] = {};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            result = std::string(win_dir) + "\\" + result.substr(12);
        }
    }

    if (result.size() >= 4 && result.substr(0, 4) == "\\??\\")
        result = result.substr(4);

    return result;
}

struct sys_module_entry_t
{
    HANDLE   Section;
    PVOID    MappedBase;
    PVOID    ImageBase;
    ULONG    ImageSize;
    ULONG    Flags;
    USHORT   LoadOrderIndex;
    USHORT   InitOrderIndex;
    USHORT   LoadCount;
    USHORT   OffsetToFileName;
    UCHAR    FullPathName[256];
};

struct sys_module_info_t
{
    ULONG              NumberOfModules;
    sys_module_entry_t Modules[1];
};

static std::string bounded_kernel_module_path(const sys_module_entry_t& m)
{
    const char* p = reinterpret_cast<const char*>(m.FullPathName);
    std::size_t len = 0;
    while (len < sizeof(m.FullPathName) && p[len] != '\0')
        ++len;
    return std::string(p, len);
}

static std::string bounded_kernel_module_name(const sys_module_entry_t& m)
{
    std::string path = bounded_kernel_module_path(m);
    if (m.OffsetToFileName < path.size())
        return path.substr(m.OffsetToFileName);
    std::size_t slash = path.find_last_of("\\/");
    return (slash == std::string::npos) ? path : path.substr(slash + 1);
}

typedef LONG(NTAPI* NtQuerySystemInformation_fn)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static bool query_kernel_modules(
    std::vector<std::uint8_t>& out_buffer,
    sys_module_info_t*& out_info,
    std::string& error_msg)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        error_msg = OBFSTR("Cannot resolve ntdll.dll");
        return false;
    }

    auto pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation)
    {
        error_msg = OBFSTR("Cannot resolve NtQuerySystemInformation");
        return false;
    }

    constexpr ULONG SystemModuleInformation = 11;
    ULONG needed = 0;
    diag::log_tagged_fmt("drv_tools", "query_kernel_modules entry");
    pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0)
        needed = 256 * 1024;
    needed += 16384;

    out_buffer.resize(needed, 0);
    LONG status = pNtQuerySystemInformation(
        SystemModuleInformation, out_buffer.data(),
        static_cast<ULONG>(out_buffer.size()), &needed);

    if (status < 0)
    {
        error_msg = OBFSTR("NtQuerySystemInformation(SystemModuleInformation) failed: NTSTATUS 0x")
            + sa_format_address(static_cast<uint64_t>(static_cast<unsigned long>(status)));
        return false;
    }

    out_info = reinterpret_cast<sys_module_info_t*>(out_buffer.data());
    if (out_buffer.size() < sizeof(ULONG))
    {
        error_msg = OBFSTR("System module buffer is too small");
        return false;
    }
    const ULONG count = out_info->NumberOfModules;
    const std::size_t min_size =
        sizeof(ULONG) + static_cast<std::size_t>(count) * sizeof(sys_module_entry_t);
    if (count > 4096 || min_size > out_buffer.size())
    {
        error_msg = OBFSTR("System module buffer failed bounds validation: count=") +
            std::to_string(count) + OBFSTR(" buffer=") + std::to_string(out_buffer.size());
        return false;
    }
    diag::log_tagged_fmt("drv_tools", "query_kernel_modules ok count=%lu bytes=%zu",
        static_cast<unsigned long>(count), out_buffer.size());
    return true;
}

tool_result_t driver_enumerate_kernel_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_kernel_modules entry");
    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(err);

    std::string filter;
    if (params.contains("filter") && params["filter"].is_string())
        filter = params["filter"].get<std::string>();

    int limit = params.value("limit", 500);

    json modules_arr = json::array();
    for (ULONG i = 0; i < info->NumberOfModules && static_cast<int>(modules_arr.size()) < limit; i++)
    {
        const auto& m = info->Modules[i];
        std::string full_path = bounded_kernel_module_path(m);
        std::string name = bounded_kernel_module_name(m);

        if (!filter.empty())
        {
            std::string lower_name = name;
            std::string lower_filter = filter;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lower_name.find(lower_filter) == std::string::npos)
            {
                std::string lower_path = full_path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (lower_path.find(lower_filter) == std::string::npos)
                    continue;
            }
        }

        std::string resolved_path = resolve_nt_path_to_win32(full_path);

        json entry;
        entry["name"]           = name;
        entry["nt_path"]        = full_path;
        entry["disk_path"]      = resolved_path;
        entry["base_address"]   = sa_format_address(
            static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(m.ImageBase)));
        entry["size"]           = m.ImageSize;
        entry["size_hex"]       = sa_format_address(static_cast<uint64_t>(m.ImageSize));
        entry["load_order"]     = m.LoadOrderIndex;
        modules_arr.push_back(entry);
    }

    json result;
    result["modules"]        = modules_arr;
    result["total_loaded"]   = info->NumberOfModules;
    result["returned"]       = modules_arr.size();

    return tool_result_t::ok(
        OBFSTR("Enumerated ") + std::to_string(modules_arr.size()) + OBFSTR(" kernel modules") +
        (filter.empty() ? "" : OBFSTR(" matching '") + filter + "'"), result);
}





tool_result_t driver_allocate_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_allocate_memory entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::size_t size = 0;
    if (params.contains("size"))
    {
        if (params["size"].is_number())
            size = params["size"].get<std::size_t>();
        else if (params["size"].is_string())
        {
            auto addr = sa_parse_address(params["size"].get<std::string>());
            if (addr) size = static_cast<std::size_t>(*addr);
        }
    }
    if (size == 0 || size > 0x1000000)
        return tool_result_t::error(OBFSTR("Invalid size. Must be 1 to 16777216 (16MB)."));

    std::uint64_t allocated = device->allocate_memory(size);
    if (allocated == 0)
        return tool_result_t::error(OBFSTR("Failed to allocate memory in target process."));

    json result;
    result["address"]    = sa_format_address(static_cast<uint64_t>(allocated));
    result["size"]       = size;
    result["protection"] = "PAGE_EXECUTE_READWRITE";
    result["process_id"] = device->get_process_id();
    return tool_result_t::ok(
        OBFSTR("Allocated ") + std::to_string(size) + OBFSTR(" bytes at ") +
        sa_format_address(static_cast<uint64_t>(allocated)), result);
}

tool_result_t driver_free_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_free_memory entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt || *addr_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid address."));

    std::uint64_t address = static_cast<std::uint64_t>(*addr_opt);

    voyager::device_t::memory_region_info before{};
    const bool query_before_free = device->query_memory(address, before);

    bool ok = device->free_memory(address);

    json result;
    result["address"]    = sa_format_address(*addr_opt);
    result["freed"]      = ok;
    result["process_id"] = device->get_process_id();
    result["query_before_free"] = query_before_free;
    if (query_before_free)
    {
        result["region_base"] = sa_format_address(static_cast<uint64_t>(before.base));
        result["region_size"] = sa_format_address(static_cast<uint64_t>(before.size));
        result["region_protect"] = before.protect;
    }

    if (ok)
        return tool_result_t::ok(OBFSTR("Memory freed at ") + sa_format_address(*addr_opt), result);
    else
        return tool_result_t::error(OBFSTR("Failed to free memory at ") + sa_format_address(*addr_opt) +
            OBFSTR(". If the region was modified through kernel-space writes, verify address space consistency and attached PID."));
}

tool_result_t driver_call_function(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_call_function entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto func_opt = sa_parse_address(params["address"].get<std::string>());
    if (!func_opt || *func_opt == 0)
        return tool_result_t::error(OBFSTR("Invalid function address."));

    std::uint64_t func_addr = static_cast<std::uint64_t>(*func_opt);


    const bool dry_run = params.value("dry_run", false);
    const bool unsafe_confirmed =
        params.value("confirm_unsafe", false) ||
        params.value("allow_unsafe", false) ||
        params.value("unsafe", false);

    if (dry_run)
    {
        json preview;
        preview["function"] = sa_format_address(static_cast<uint64_t>(func_addr));
        preview["process_id"] = device->get_process_id();
        preview["note"] = "Dry-run only. No remote execution performed.";
        return tool_result_t::ok(OBFSTR("driver_call_function dry-run completed."), preview);
    }

    if (!unsafe_confirmed)
    {
        return tool_result_t::error(
            OBFSTR("driver_call_function is high-risk and may crash the target process. "
                   "Re-run with confirm_unsafe=true (or allow_unsafe=true) to execute, "
                   "or dry_run=true to preview only."));
    }

    std::uint64_t args[4] = {0, 0, 0, 0};
    const char* arg_names[] = {"arg1", "arg2", "arg3", "arg4"};
    for (int i = 0; i < 4; ++i)
    {
        if (params.contains(arg_names[i]))
        {
            const auto& val = params[arg_names[i]];
            if (val.is_number())
                args[i] = val.get<std::uint64_t>();
            else if (val.is_string())
            {
                auto a = sa_parse_address(val.get<std::string>());
                if (a) args[i] = static_cast<std::uint64_t>(*a);
            }
        }
    }

    std::uint64_t ret = device->call_function(func_addr, args[0], args[1], args[2], args[3]);

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t crashed_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Target process PID ") + std::to_string(crashed_pid) +
            OBFSTR(" terminated during driver_call_function. Process context was detached for safety."));
    }

    json result;
    result["function"]   = sa_format_address(static_cast<uint64_t>(func_addr));
    result["arg1"]       = sa_format_address(static_cast<uint64_t>(args[0]));
    result["arg2"]       = sa_format_address(static_cast<uint64_t>(args[1]));
    result["arg3"]       = sa_format_address(static_cast<uint64_t>(args[2]));
    result["arg4"]       = sa_format_address(static_cast<uint64_t>(args[3]));
    result["return_value"] = sa_format_address(static_cast<uint64_t>(ret));
    result["return_decimal"] = ret;
    result["process_id"] = device->get_process_id();
    return tool_result_t::ok(
        OBFSTR("Function at ") + sa_format_address(static_cast<uint64_t>(func_addr)) +
        OBFSTR(" returned ") + sa_format_address(static_cast<uint64_t>(ret)), result);
}






tool_result_t driver_protect_memory(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_protect_memory entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(OBFSTR("Address is required"));

    std::uint64_t size = 0x1000;
    if (params.contains("size")) {
        if (params["size"].is_string())
            size = sa_parse_address(params["size"].get<std::string>()).value_or(0x1000);
        else
            size = params["size"].get<std::uint64_t>();
    }
    if (size == 0)
        return tool_result_t::error(OBFSTR("Size is required"));


    std::uint32_t new_protect = 0x40;
    if (params.contains("protect")) {
        if (params["protect"].is_string())
            new_protect = static_cast<std::uint32_t>(sa_parse_address(params["protect"].get<std::string>()).value_or(0x40));
        else
            new_protect = params["protect"].get<std::uint32_t>();
    }

    if (auto reject = reject_full_test_system_mutation(address, size, "driver_protect_memory"))
        return *reject;

    std::uint32_t old_protect = 0;
    if (!device->protect_memory(address, size, new_protect, &old_protect))
        return tool_result_t::error(OBFSTR("Failed to change protection at ") + sa_format_address(static_cast<uint64_t>(address)));

    json result;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["size"] = sa_format_address(static_cast<uint64_t>(size));
    result["new_protect"] = new_protect;
    result["old_protect"] = old_protect;
    return tool_result_t::ok(OBFSTR("Memory protection changed"), result);
}


tool_result_t driver_read_peb(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_peb entry");
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    voyager::device_t::peb_info info{};
    if (!device->read_peb(info))
        return tool_result_t::error(OBFSTR("Failed to read PEB"));

    json result;
    result["peb_address"] = sa_format_address(static_cast<uint64_t>(info.peb_address));
    result["image_base"] = sa_format_address(static_cast<uint64_t>(info.image_base));
    result["being_debugged"] = info.being_debugged ? true : false;
    result["nt_global_flag"] = sa_format_address(static_cast<uint64_t>(info.nt_global_flag));
    result["ldr_address"] = sa_format_address(static_cast<uint64_t>(info.ldr_address));
    result["process_heap"] = sa_format_address(static_cast<uint64_t>(info.process_heap));
    result["number_of_heaps"] = info.number_of_heaps;
    result["max_heaps"] = info.max_heaps;
    result["process_heaps"] = sa_format_address(static_cast<uint64_t>(info.process_heaps));
    return tool_result_t::ok(OBFSTR("PEB info for PID ") + std::to_string(device->get_process_id()), result);
}


tool_result_t driver_set_hw_breakpoint(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_set_hw_breakpoint entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0) return tool_result_t::error(OBFSTR("Address is required"));


    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    int type = 0;
    if (params.contains("type")) {
        std::string t = params["type"].get<std::string>();
        if (t == "write") type = 1;
        else if (t == "readwrite" || t == "rw") type = 3;
        else type = 0;
    }

    int size = 0;
    if (params.contains("size")) {
        int s = params["size"].get<int>();
        if (s == 2) size = 1;
        else if (s == 4) size = 3;
        else if (s == 8) size = 2;
        else size = 0;
    }

    if (!driver_bridge::set_hardware_breakpoint(tid, index, address, type, size))
        return tool_result_t::error(OBFSTR("Failed to set hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["type"] = (type == 0) ? "execute" : (type == 1) ? "write" : "readwrite";
    return tool_result_t::ok(OBFSTR("Hardware breakpoint set on DR") + std::to_string(index), result);
}

tool_result_t driver_clear_hw_breakpoint(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_clear_hw_breakpoint entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    if (!driver_bridge::clear_hardware_breakpoint(tid, index))
        return tool_result_t::error(OBFSTR("Failed to clear hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    return tool_result_t::ok(OBFSTR("Hardware breakpoint cleared on DR") + std::to_string(index), result);
}

tool_result_t driver_resolve_export(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_resolve_export entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::string export_name;
    if (params.contains("name") && params["name"].is_string())
        export_name = trim_ascii_copy(params["name"].get<std::string>());
    else if (params.contains("export_name") && params["export_name"].is_string())
        export_name = trim_ascii_copy(params["export_name"].get<std::string>());

    if (export_name.empty())
        return tool_result_t::error(OBFSTR("Export name is required. Use name='GetTickCount' (alias export_name is supported)."));

    std::uint64_t module_base = 0;
    std::string resolved_module_name;
    std::string module_query;
    bool explicit_module_param = false;

    if (params.contains("module_base") && params["module_base"].is_string())
    {
        explicit_module_param = true;
        module_base = sa_parse_address(params["module_base"].get<std::string>()).value_or(0);
    }

    if (module_base == 0 && params.contains("module"))
    {
        explicit_module_param = true;
        if (params["module"].is_string())
            module_query = trim_ascii_copy(params["module"].get<std::string>());
    }

    if (module_base == 0 && module_query.empty() && params.contains("module_name") && params["module_name"].is_string())
    {
        explicit_module_param = true;
        module_query = trim_ascii_copy(params["module_name"].get<std::string>());
    }

    if (module_base == 0 && !module_query.empty())
    {
        if (auto parsed = sa_parse_address(module_query))
            module_base = static_cast<std::uint64_t>(*parsed);
        else if (!resolve_loaded_module_base(module_query, module_base, resolved_module_name))
            return tool_result_t::error(OBFSTR("Could not resolve module '") + module_query +
                OBFSTR("'. Provide module_base='0x...' or a loaded module name/path."));
    }

    if (module_base == 0)
        module_base = device->get_base_address();
    if (module_base == 0)
        return tool_result_t::error(OBFSTR("Module base required. Provide module_base or module/module_name."));


    std::uint64_t addr = device->resolve_export(module_base, export_name.c_str());
    if (addr == 0)
    {
        std::string detail = OBFSTR("Export '") + export_name + OBFSTR("' not found in module ") +
            sa_format_address(static_cast<uint64_t>(module_base));
        if (!module_query.empty())
            detail += OBFSTR(" (query: '") + module_query + OBFSTR("')");
        return tool_result_t::error(detail);
    }

    json result;
    result["export_name"] = export_name;
    result["module_base"] = sa_format_address(static_cast<uint64_t>(module_base));
    if (!module_query.empty())
        result["module_query"] = module_query;
    if (!resolved_module_name.empty())
        result["resolved_module_name"] = resolved_module_name;
    result["explicit_module_param"] = explicit_module_param;
    result["resolved_address"] = sa_format_address(static_cast<uint64_t>(addr));
    return tool_result_t::ok(OBFSTR("Export resolved: ") + export_name + OBFSTR(" -> ") + sa_format_address(static_cast<uint64_t>(addr)), result);
}

tool_result_t driver_virtual_to_physical(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_virtual_to_physical entry");
    if (!device->is_connected() || device->get_dtb() == 0)
        return tool_result_t::error(OBFSTR("Driver not connected or DTB not solved"));

    std::uint64_t vaddr = 0;
    if (params.contains("address"))
        vaddr = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (vaddr == 0) return tool_result_t::error(OBFSTR("Address is required"));


    std::uint64_t paddr = device->virtual_to_physical(vaddr);
    if (paddr == 0)
        return tool_result_t::error(OBFSTR("Translation failed for ") + sa_format_address(static_cast<uint64_t>(vaddr)));

    json result;
    result["virtual_address"] = sa_format_address(static_cast<uint64_t>(vaddr));
    result["physical_address"] = sa_format_address(static_cast<uint64_t>(paddr));
    return tool_result_t::ok(OBFSTR("Virtual -> Physical translation"), result);
}


#ifndef idaapi
#define idaapi
#endif
#ifndef _SSIZE_T_DEFINED
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif
struct exec_request_t
{
    virtual ssize_t idaapi execute() { return 0; }
    virtual ~exec_request_t() = default;
};
static constexpr int MFF_READ  = 0;
static constexpr int MFF_WRITE = 1;
inline int execute_sync(exec_request_t& req, int )
{

    return static_cast<int>(req.execute());
}

enum class deferred_status
{
    pending,
    watching,
    triggered,
    completed,
    failed,
    cancelled,
    timed_out
};

struct deferred_action_result_t
{
    std::string action_type;
    bool        success = false;
    std::string message;
    json        data;
};

struct deferred_action_t
{
    struct queued_tool_call_t
    {
        std::string tool_name;
        json        params;
    };

    int                                     id = 0;
    std::chrono::steady_clock::time_point   created;
    std::chrono::steady_clock::time_point   triggered_at;
    std::string                             condition_type;
    std::string                             target_name;
    int                                     timeout_seconds   = 300;
    int                                     poll_interval_ms  = 50;
    std::vector<queued_tool_call_t>         tool_calls;
    std::vector<deferred_action_result_t>   results;
    std::atomic<deferred_status>            status{deferred_status::pending};
    std::atomic<bool>                       watcher_done{true};
    std::string                             trigger_info;
    std::string                             error;
};

struct deferred_action_snapshot_t
{
    int                                     id = 0;
    std::string                             condition_type;
    std::string                             target_name;
    int                                     timeout_seconds = 0;
    std::vector<deferred_action_t::queued_tool_call_t> tool_calls;
    std::vector<deferred_action_result_t>   results;
    deferred_status                         status = deferred_status::pending;
    std::string                             trigger_info;
    std::string                             error;
};

class DeferredActionManager
{
public:
    static DeferredActionManager& instance();
    ~DeferredActionManager();

    void shutdown();
    int  register_action(std::unique_ptr<deferred_action_t> action, bool& watcher_started, std::string* watcher_error = nullptr);
    bool cancel_action(int id);
    bool get_action_snapshot(int id, deferred_action_snapshot_t& out) const;
    std::vector<deferred_action_snapshot_t> get_all_action_snapshots() const;

    bool poll_kernel_module_load(const std::string& target,
                                 std::uint64_t& out_base,
                                 std::uint32_t& out_size,
                                 std::string& out_name,
                                 std::string& out_path);
    bool poll_process_start(const std::string& target, std::uint32_t& out_pid);

private:
    DeferredActionManager() = default;
    void watcher_thread_func(int action_id);
    void execute_deferred_tools(deferred_action_t& action, const json& context);
    std::string resolve_template(const std::string& value, const json& context);
    json resolve_params(const json& params, const json& context);

    std::map<int, std::unique_ptr<deferred_action_t>> _actions;
    mutable std::mutex                                _mutex;
    int                                               _next_id = 1;
    std::atomic<bool>                                 _shutdown{false};
};


static const std::vector<mcp_standalone::tool_def_t>* s_deferred_tool_list = nullptr;

static const mcp_standalone::tool_def_t* get_deferred_tool_def(const std::string& name)
{
    if (!s_deferred_tool_list) return nullptr;
    for (const auto& t : *s_deferred_tool_list)
        if (t.name == name && t.visibility != mcp_standalone::tool_visibility_t::ide_chat_only) return &t;
    return nullptr;
}

static tool_result_t execute_deferred_tool(const std::string& name, const json& params)
{
    const auto* def = get_deferred_tool_def(name);
    if (!def)
        return tool_result_t::error(OBFSTR("Unknown deferred tool: ") + name);
    return def->handler(params);
}


DeferredActionManager& DeferredActionManager::instance()
{
    static DeferredActionManager mgr;
    return mgr;
}

DeferredActionManager::~DeferredActionManager()
{
    shutdown();
}

void DeferredActionManager::shutdown()
{
    _shutdown.store(true);
    std::vector<deferred_action_t*> actions_snapshot;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (auto& [id, action] : _actions)
        {
            auto st = action->status.load();
            if (st == deferred_status::pending || st == deferred_status::watching)
                action->status.store(deferred_status::cancelled);
            actions_snapshot.push_back(action.get());
        }
    }
    for (deferred_action_t* action : actions_snapshot)
    {
        while (!action->watcher_done.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int DeferredActionManager::register_action(std::unique_ptr<deferred_action_t> action, bool& watcher_started, std::string* watcher_error)
{
    watcher_started = false;
    if (watcher_error)
        watcher_error->clear();
    int id = 0;
    action->id = id;
    action->created = std::chrono::steady_clock::now();
    action->status.store(deferred_status::pending);
    action->watcher_done.store(false, std::memory_order_release);

    deferred_action_t* action_ptr = action.get();
    {
        std::lock_guard<std::mutex> lock(_mutex);
        id = _next_id++;
        action_ptr->id = id;
        _actions[id] = std::move(action);
    }

    bool posted = false;
    try
    {
        posted = work_queue::post([this, id, action_ptr]() {
            const DWORD tid = GetCurrentThreadId();
            const ULONGLONG start_ms = GetTickCount64();
            diag::log_tagged_fmt("drv_tools",
                "deferred_watcher_enter id=%d pid=%lu tid=%lu",
                id,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(tid));
            try
            {
                watcher_thread_func(id);
            }
            catch (const std::exception& ex)
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action_ptr->status.store(deferred_status::failed);
                action_ptr->error = std::string("Deferred watcher escaped exception: ") + ex.what();
            }
            catch (...)
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action_ptr->status.store(deferred_status::failed);
                action_ptr->error = "Deferred watcher escaped unknown exception";
            }
            diag::log_tagged_fmt("drv_tools",
                "deferred_watcher_exit id=%d tid=%lu status=%d elapsed_ms=%llu",
                id,
                static_cast<unsigned long>(tid),
                static_cast<int>(action_ptr->status.load()),
                static_cast<unsigned long long>(GetTickCount64() - start_ms));
            action_ptr->watcher_done.store(true, std::memory_order_release);
        });
    }
    catch (...)
    {
        posted = false;
    }

    if (posted)
    {
        watcher_started = true;
        const auto qs = work_queue::stats();
        diag::log_tagged_fmt("drv_tools",
            "deferred_watcher_posted id=%d cq_alive=%d cq_shutdown=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            id,
            qs.alive ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            qs.pending,
            qs.active,
            static_cast<unsigned long long>(qs.started),
            static_cast<unsigned long long>(qs.finished));
    }
    else
    {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            action_ptr->status.store(deferred_status::failed);
            action_ptr->error = "Deferred watcher work queue post failed";
        }
        action_ptr->watcher_done.store(true, std::memory_order_release);
        const auto qs = work_queue::stats();
        diag::log_tagged_fmt("drv_tools",
            "deferred_watcher_post_failed id=%d cq_alive=%d cq_shutdown=%d cq_pending=%zu cq_active=%u cq_posted=%llu cq_rejected=%llu",
            id,
            qs.alive ? 1 : 0,
            qs.shutting_down ? 1 : 0,
            qs.pending,
            qs.active,
            static_cast<unsigned long long>(qs.posted),
            static_cast<unsigned long long>(qs.rejected));
    }

    if (!watcher_started)
    {
        if (watcher_error)
            *watcher_error = action_ptr->error.empty() ? std::string("Deferred watcher work queue post failed") : action_ptr->error;
        std::lock_guard<std::mutex> lock(_mutex);
        _actions.erase(id);
        diag::log_tagged_fmt("drv_tools", "deferred_watcher_registration_removed_after_post_failure id=%d", id);
        return 0;
    }

    return id;
}

bool DeferredActionManager::cancel_action(int id)
{
    std::unique_lock<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    if (it == _actions.end())
        return false;

    auto st = it->second->status.load();
    if (st == deferred_status::pending || st == deferred_status::watching)
    {
        it->second->status.store(deferred_status::cancelled);
        deferred_action_t* action_ptr = it->second.get();
        lock.unlock();
        while (!action_ptr->watcher_done.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return true;
    }
    return false;
}

static deferred_action_snapshot_t make_deferred_action_snapshot(const deferred_action_t& action)
{
    deferred_action_snapshot_t snapshot;
    snapshot.id = action.id;
    snapshot.condition_type = action.condition_type;
    snapshot.target_name = action.target_name;
    snapshot.timeout_seconds = action.timeout_seconds;
    snapshot.tool_calls = action.tool_calls;
    snapshot.results = action.results;
    snapshot.status = action.status.load();
    snapshot.trigger_info = action.trigger_info;
    snapshot.error = action.error;
    return snapshot;
}

bool DeferredActionManager::get_action_snapshot(int id, deferred_action_snapshot_t& out) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    if (it == _actions.end())
        return false;
    out = make_deferred_action_snapshot(*it->second);
    return true;
}

std::vector<deferred_action_snapshot_t> DeferredActionManager::get_all_action_snapshots() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<deferred_action_snapshot_t> result;
    result.reserve(_actions.size());
    for (const auto& [id, action] : _actions)
        result.push_back(make_deferred_action_snapshot(*action));
    return result;
}

bool DeferredActionManager::poll_kernel_module_load(
    const std::string& target,
    std::uint64_t& out_base,
    std::uint32_t& out_size,
    std::string& out_name,
    std::string& out_path)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_fn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation) return false;

    constexpr ULONG SystemModuleInformation = 11;
    ULONG needed = 0;
    pNtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (needed == 0) needed = 256 * 1024;
    needed += 16384;

    std::vector<std::uint8_t> buf(needed, 0);
    LONG status = pNtQuerySystemInformation(
        SystemModuleInformation, buf.data(),
        static_cast<ULONG>(buf.size()), &needed);
    if (status < 0) return false;

    auto* info = reinterpret_cast<sys_module_info_t*>(buf.data());

    std::string lower_target = target;
    std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (ULONG i = 0; i < info->NumberOfModules; i++)
    {
        const auto& m = info->Modules[i];
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));
        std::string full_path(reinterpret_cast<const char*>(m.FullPathName));

        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (lower_name == lower_target || lower_name.find(lower_target) != std::string::npos)
        {
            out_base = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            out_size = m.ImageSize;
            out_name = name;
            out_path = full_path;
            return true;
        }
    }
    return false;
}

bool DeferredActionManager::poll_process_start(
    const std::string& target,
    std::uint32_t& out_pid)
{
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(snapshot, &entry))
    {
        do {
            std::string exe_name;
            for (int i = 0; entry.szExeFile[i]; i++)
                exe_name.push_back(static_cast<char>(entry.szExeFile[i]));

            std::string lower_exe = exe_name;
            std::string lower_target = target;
            std::transform(lower_exe.begin(), lower_exe.end(), lower_exe.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (lower_exe == lower_target || lower_exe.find(lower_target) != std::string::npos)
            {
                out_pid = entry.th32ProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

std::string DeferredActionManager::resolve_template(const std::string& value, const json& context)
{
    std::string result = value;

    auto replace_all = [&](const std::string& placeholder, const std::string& replacement) {
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos)
        {
            result.replace(pos, placeholder.size(), replacement);
            pos += replacement.size();
        }
    };

    if (context.contains("module_base"))
        replace_all("${module_base}", context["module_base"].get<std::string>());
    if (context.contains("module_size"))
        replace_all("${module_size}", context["module_size"].get<std::string>());
    if (context.contains("module_name"))
        replace_all("${module_name}", context["module_name"].get<std::string>());
    if (context.contains("pid"))
        replace_all("${pid}", context["pid"].get<std::string>());
    if (context.contains("base_address"))
        replace_all("${base_address}", context["base_address"].get<std::string>());


    static const std::regex offset_re("0x([0-9A-Fa-f]+)\\+0x([0-9A-Fa-f]+)");
    std::smatch match;
    if (std::regex_match(result, match, offset_re))
    {
        std::uint64_t base_val = std::stoull(match[1].str(), nullptr, 16);
        std::uint64_t offset_val = std::stoull(match[2].str(), nullptr, 16);
        std::ostringstream ss;
        ss << "0x" << std::hex << std::uppercase << (base_val + offset_val);
        result = ss.str();
    }

    return result;
}

json DeferredActionManager::resolve_params(const json& params, const json& context)
{
    if (params.is_string())
        return resolve_template(params.get<std::string>(), context);

    if (params.is_object())
    {
        json resolved = json::object();
        for (auto it = params.begin(); it != params.end(); ++it)
            resolved[it.key()] = resolve_params(it.value(), context);
        return resolved;
    }

    if (params.is_array())
    {
        json resolved = json::array();
        for (const auto& item : params)
            resolved.push_back(resolve_params(item, context));
        return resolved;
    }

    return params;
}

void DeferredActionManager::execute_deferred_tools(deferred_action_t& action, const json& context)
{
    std::vector<deferred_action_t::queued_tool_call_t> tool_calls;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        tool_calls = action.tool_calls;
    }
    std::vector<deferred_action_result_t> results;


    struct deferred_exec_request_t : public exec_request_t
    {
        std::string tool_name;
        json params;
        tool_result_t tool_result;

        ssize_t idaapi execute() override
        {
            tool_result = execute_deferred_tool(tool_name, params);
            return 0;
        }
    };

    for (const auto& tc : tool_calls)
    {
        json resolved_params = resolve_params(tc.params, context);
        deferred_action_result_t result;
        result.action_type = tc.tool_name;

        try
        {
            const auto* tool_def = get_deferred_tool_def(tc.tool_name);
            int mff_flag = (tool_def && tool_def->read_only) ? MFF_READ : MFF_WRITE;

            deferred_exec_request_t req;
            req.tool_name = tc.tool_name;
            req.params = resolved_params;


            execute_sync(req, mff_flag);

            result.success = req.tool_result.success;
            result.message = req.tool_result.text;
            result.data = req.tool_result.data;
        }
        catch (const std::exception& e)
        {
            result.success = false;
            result.message = std::string("Exception: ") + e.what();
        }

        results.push_back(std::move(result));
    }

    {
        std::lock_guard<std::mutex> lock(_mutex);
        action.results = std::move(results);
    }
}

void DeferredActionManager::watcher_thread_func(int action_id)
{
    deferred_action_t* action = nullptr;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _actions.find(action_id);
        if (it == _actions.end()) return;
        action = it->second.get();
        if (action->status.load() == deferred_status::cancelled)
            return;
        action->status.store(deferred_status::watching);
    }

    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(action->timeout_seconds);
    auto poll_interval = std::chrono::milliseconds(action->poll_interval_ms);

    msg(OBFSTR_C("AiDA: Deferred action #%d watching for %s '%s' (timeout: %ds, poll: %dms)\n"),
        action->id, action->condition_type.c_str(), action->target_name.c_str(),
        action->timeout_seconds, action->poll_interval_ms);

    json trigger_context;

    while (!_shutdown.load())
    {
        auto st = action->status.load();
        if (st == deferred_status::cancelled)
        {
            msg(OBFSTR_C("AiDA: Deferred action #%d cancelled\n"), action->id);
            return;
        }


        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= timeout)
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                action->status.store(deferred_status::timed_out);
                action->error = OBFSTR("Timed out waiting for ") + action->condition_type +
                    OBFSTR(": ") + action->target_name;
            }
            msg(OBFSTR_C("AiDA: Deferred action #%d timed out after %ds\n"),
                action->id, action->timeout_seconds);
            return;
        }

        bool condition_met = false;

        if (action->condition_type == "kernel_module_load")
        {
            std::uint64_t base = 0;
            std::uint32_t size = 0;
            std::string name, path;
            if (poll_kernel_module_load(action->target_name, base, size, name, path))
            {
                condition_met = true;
                std::ostringstream base_ss, size_ss;
                base_ss << "0x" << std::hex << std::uppercase << base;
                size_ss << "0x" << std::hex << std::uppercase << size;

                trigger_context["module_base"] = base_ss.str();
                trigger_context["module_size"] = size_ss.str();
                trigger_context["module_name"] = name;
                trigger_context["module_path"] = path;

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    action->trigger_info = trigger_context.dump();
                }
            }
        }
        else if (action->condition_type == "process_start")
        {
            std::uint32_t pid = 0;
            if (poll_process_start(action->target_name, pid))
            {
                condition_met = true;
                trigger_context["pid"] = std::to_string(pid);


                if (device && !device->is_connected())
                    device->connect();

                if (device && device->is_connected())
                {
                    device->clear_process_context();
                    device->set_process_id(pid);
                    std::uint64_t img_base = device->find_image();
                    device->solve_dtb();

                    std::ostringstream base_ss;
                    base_ss << "0x" << std::hex << std::uppercase << img_base;
                    trigger_context["base_address"] = base_ss.str();
                    trigger_context["pid"] = std::to_string(device->get_process_id());
                }

                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    action->trigger_info = trigger_context.dump();
                }
            }
        }

        if (condition_met)
        {
            action->triggered_at = std::chrono::steady_clock::now();
            action->status.store(deferred_status::triggered);

            auto trigger_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                action->triggered_at - start_time).count();
            msg(OBFSTR_C("AiDA: Deferred action #%d TRIGGERED! %s '%s' detected after %lldms. "
                "Executing %zu queued tool call(s) IMMEDIATELY...\n"),
                action->id, action->condition_type.c_str(), action->target_name.c_str(),
                trigger_elapsed, action->tool_calls.size());


            execute_deferred_tools(*action, trigger_context);

            bool any_failed = false;
            std::vector<deferred_action_result_t> results_snapshot;
            {
                std::lock_guard<std::mutex> lock(_mutex);
                results_snapshot = action->results;
            }
            for (const auto& r : results_snapshot)
            {
                msg(OBFSTR_C("AiDA: Deferred action #%d - %s: %s - %s\n"),
                    action->id, r.action_type.c_str(),
                    r.success ? "OK" : "FAIL", r.message.c_str());
                if (!r.success) any_failed = true;
            }

            action->status.store(any_failed ? deferred_status::failed : deferred_status::completed);

            msg(OBFSTR_C("AiDA: Deferred action #%d %s. %zu/%zu actions succeeded.\n"),
                action->id,
                any_failed ? "completed with failures" : "completed successfully",
                std::count_if(results_snapshot.begin(), results_snapshot.end(),
                    [](const deferred_action_result_t& r) { return r.success; }),
                results_snapshot.size());

            return;
        }

        std::this_thread::sleep_for(poll_interval);
    }
}


static std::string deferred_status_to_string(deferred_status s)
{
    switch (s)
    {
        case deferred_status::pending:    return "pending";
        case deferred_status::watching:   return "watching";
        case deferred_status::triggered:  return "triggered";
        case deferred_status::completed:  return "completed";
        case deferred_status::failed:     return "failed";
        case deferred_status::cancelled:  return "cancelled";
        case deferred_status::timed_out:  return "timed_out";
        default: return "unknown";
    }
}

tool_result_t driver_defer_action(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_defer_action entry");
    json normalized = params;

    if (!normalized.contains("actions") && normalized.contains("action"))
    {
        json one = json::object();
        one["tool"] = normalized["action"];
        one["params"] = normalized.contains("params") ? normalized["params"] : json::object();
        normalized["actions"] = json::array({one});
    }

    if (normalized.contains("actions") && normalized["actions"].is_array())
    {
        for (auto& act : normalized["actions"])
        {
            if (act.is_object() && !act.contains("tool") && act.contains("action"))
                act["tool"] = act["action"];
            if (act.is_object() && !act.contains("params"))
                act["params"] = json::object();
        }
    }

    std::string wait_for;
    if (normalized.contains("wait_for"))
    {
        if (!normalized["wait_for"].is_string())
            return tool_result_t::error(OBFSTR("'wait_for' must be a string enum: 'process_start' or 'kernel_module_load'."));
        wait_for = normalized["wait_for"].get<std::string>();
    }
    if (wait_for.empty())
        return tool_result_t::error(OBFSTR("'wait_for' is required: 'kernel_module_load' or 'process_start'."));

    if (wait_for != "kernel_module_load" && wait_for != "process_start")
        return tool_result_t::error(OBFSTR("Invalid 'wait_for'. Allowed values: 'kernel_module_load', 'process_start'."));

    std::string target;
    if (normalized.contains("target"))
    {
        if (!normalized["target"].is_string())
            return tool_result_t::error(OBFSTR("'target' must be a string (module or process name)."));
        target = normalized["target"].get<std::string>();
    }
    if (target.empty())
        return tool_result_t::error(OBFSTR("'target' is required: module or process name to watch for"));

    int timeout = normalized.value("timeout", 300);
    int poll_interval = normalized.value("poll_interval", 50);

    if (!normalized.contains("actions") || !normalized["actions"].is_array() || normalized["actions"].empty())
        return tool_result_t::error(OBFSTR("'actions' array is required with at least one tool call. Format: [{\"tool\":\"read_memory\",\"params\":{...}}]."));

    auto action = std::make_unique<deferred_action_t>();
    action->condition_type = wait_for;
    action->target_name = target;
    action->timeout_seconds = timeout;
    action->poll_interval_ms = poll_interval;

    for (const auto& act : normalized["actions"])
    {
        if (!act.contains("tool") || !act["tool"].is_string())
            return tool_result_t::error(OBFSTR("Each action must have a string 'tool' field (full tool name, e.g. 'read_memory')."));

        deferred_action_t::queued_tool_call_t tc;
        tc.tool_name = act["tool"].get<std::string>();
        tc.params = act.contains("params") ? act["params"] : json::object();


        if (!get_deferred_tool_def(tc.tool_name))
            return tool_result_t::error(OBFSTR("Unknown tool: ") + tc.tool_name);

        action->tool_calls.push_back(std::move(tc));
    }


    bool already_met = false;
    if (wait_for == "kernel_module_load")
    {
        std::uint64_t base = 0;
        std::uint32_t size = 0;
        std::string name, path;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_kernel_module_load(target, base, size, name, path))
            already_met = true;
    }
    else if (wait_for == "process_start")
    {
        std::uint32_t pid = 0;
        auto& mgr = DeferredActionManager::instance();
        if (mgr.poll_process_start(target, pid))
            already_met = true;
    }

    const std::size_t queued_actions = action->tool_calls.size();
    bool watcher_started = false;
    std::string watcher_error;
    int action_id = DeferredActionManager::instance().register_action(std::move(action), watcher_started, &watcher_error);
    if (action_id == 0 || !watcher_started)
    {
        if (watcher_error.empty())
            watcher_error = "Deferred watcher thread start failed";
        diag::log_tagged_fmt("drv_tools", "driver_defer_action watcher_start_unavailable target='%s' err='%s'", target.c_str(), watcher_error.c_str());
        return tool_result_t::error(watcher_error);
    }
    deferred_action_snapshot_t registered_action;
    const bool have_registered_action = DeferredActionManager::instance().get_action_snapshot(action_id, registered_action);

    json result;
    result["action_id"] = action_id;
    result["condition"] = wait_for;
    result["target"] = target;
    result["timeout_seconds"] = timeout;
    result["poll_interval_ms"] = poll_interval;
    result["num_queued_actions"] = queued_actions;
    result["watcher_started"] = watcher_started;
    if (have_registered_action && registered_action.status == deferred_status::failed)
    {
        result["status"] = "failed";
        result["error"] = registered_action.error;
        return tool_result_t::error(OBFSTR("Deferred action #") + std::to_string(action_id) +
            OBFSTR(" watcher failed to start: ") + registered_action.error);
    }
    result["status"] = already_met ? "target_already_loaded_executing_now" : "watching";
    result["note"] = already_met
        ? OBFSTR("Target '") + target + OBFSTR("' is ALREADY loaded! Actions are being executed immediately.")
        : OBFSTR("Background watcher started. Actions will execute THE INSTANT '") + target +
          OBFSTR("' loads. Use driver_get_deferred_results with action_id=") +
          std::to_string(action_id) + OBFSTR(" to check results.");

    return tool_result_t::ok(
        already_met
            ? OBFSTR("Deferred action #") + std::to_string(action_id) + OBFSTR(" - target already loaded, executing immediately!")
            : OBFSTR("Deferred action #") + std::to_string(action_id) + OBFSTR(" registered - watching for '") + target + "'",
        result);
}

tool_result_t driver_list_deferred_actions(const json&)
{
    diag::log_tagged_fmt("drv_tools", "driver_list_deferred_actions entry");
    auto actions = DeferredActionManager::instance().get_all_action_snapshots();

    json arr = json::array();
    for (const auto& action : actions)
    {
        json entry;
        entry["id"] = action.id;
        entry["condition"] = action.condition_type;
        entry["target"] = action.target_name;
        entry["status"] = deferred_status_to_string(action.status);
        entry["num_actions"] = action.tool_calls.size();
        entry["timeout_seconds"] = action.timeout_seconds;

        if (!action.trigger_info.empty())
        {
            try { entry["trigger_info"] = json::parse(action.trigger_info); }
            catch (...) { entry["trigger_info"] = action.trigger_info; }
        }

        if (!action.error.empty())
            entry["error"] = action.error;

        entry["num_results"] = action.results.size();
        int succeeded = 0;
        for (const auto& r : action.results)
            if (r.success) succeeded++;
        entry["succeeded"] = succeeded;
        entry["failed"] = static_cast<int>(action.results.size()) - succeeded;

        arr.push_back(entry);
    }

    json result;
    result["actions"] = arr;
    result["total"] = arr.size();
    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(arr.size()) + OBFSTR(" deferred action(s)"), result);
}

tool_result_t driver_cancel_deferred_action(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_cancel_deferred_action entry");
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(OBFSTR("'action_id' is required"));

    if (DeferredActionManager::instance().cancel_action(id))
    {
        json result;
        result["action_id"] = id;
        result["status"] = "cancelled";
        return tool_result_t::ok(OBFSTR("Deferred action #") + std::to_string(id) + OBFSTR(" cancelled"), result);
    }

    return tool_result_t::error(OBFSTR("Cannot cancel action #") + std::to_string(id) +
        OBFSTR(" - not found or already completed/triggered"));
}

tool_result_t driver_get_deferred_results(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_get_deferred_results entry");
    int id = 0;
    if (params.contains("action_id"))
    {
        if (params["action_id"].is_string())
            id = std::stoi(params["action_id"].get<std::string>());
        else
            id = params["action_id"].get<int>();
    }
    if (id == 0)
        return tool_result_t::error(OBFSTR("'action_id' is required"));

    deferred_action_snapshot_t action;
    if (!DeferredActionManager::instance().get_action_snapshot(id, action))
        return tool_result_t::error(OBFSTR("Action #") + std::to_string(id) + OBFSTR(" not found"));

    json result;
    result["action_id"] = action.id;
    result["condition"] = action.condition_type;
    result["target"] = action.target_name;
    result["status"] = deferred_status_to_string(action.status);

    if (!action.trigger_info.empty())
    {
        try { result["trigger_info"] = json::parse(action.trigger_info); }
        catch (...) { result["trigger_info"] = action.trigger_info; }
    }

    if (!action.error.empty())
        result["error"] = action.error;

    json results_arr = json::array();
    for (const auto& r : action.results)
    {
        json rj;
        rj["tool"] = r.action_type;
        rj["success"] = r.success;
        rj["message"] = r.message;
        if (!r.data.is_null() && !r.data.empty())
            rj["data"] = r.data;
        results_arr.push_back(rj);
    }
    result["results"] = results_arr;

    int succeeded = 0;
    for (const auto& r : action.results)
        if (r.success) succeeded++;
    result["succeeded"] = succeeded;
    result["failed"] = static_cast<int>(action.results.size()) - succeeded;
    result["total_actions"] = action.tool_calls.size();

    std::string status_str = deferred_status_to_string(action.status);
    return tool_result_t::ok(
        OBFSTR("Deferred action #") + std::to_string(id) + OBFSTR(": ") + status_str, result);
}


static std::string reg_index_to_name(std::uint32_t idx) {
    static const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    if (idx < 16) return names[idx];
    return "reg" + std::to_string(idx);
}

static json sniff_captures_to_json(const std::vector<voyager::device_t::sniff_result>& captures)
{
    json arr = json::array();
    for (const auto& cap : captures) {
        json c;
        c["timestamp"] = cap.timestamp;
        c["thread_id"] = sa_format_address(static_cast<uint64_t>(cap.thread_id));
        c["size"] = cap.buffer.size();
        std::string hex;
        std::size_t show = (cap.buffer.size() < 256) ? cap.buffer.size() : 256;
        for (std::size_t i = 0; i < show; i++) {
            char hb[4];
            qsnprintf(hb, sizeof(hb), "%02X ", cap.buffer[i]);
            hex += hb;
            if ((i + 1) % 16 == 0) hex += "\n";
        }
        if (show < cap.buffer.size())
            hex += "... (" + std::to_string(cap.buffer.size() - show) + " more)";
        c["hex_dump"] = hex;
        std::string ascii;
        for (std::size_t i = 0; i < show; i++) {
            char ch = static_cast<char>(cap.buffer[i]);
            ascii += (ch >= 0x20 && ch < 0x7F) ? ch : '.';
        }
        c["ascii"] = ascii;
        arr.push_back(std::move(c));
    }
    return arr;
}

tool_result_t driver_sniff_network_buffers(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_sniff_network_buffers entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;


    if (params.contains("operation")) {
        std::string op = params["operation"].get<std::string>();

        if (op == "stop") {
            bool active_before = false;
            auto captures = device->sniff_net_buffers_get(active_before);
            if (!device->sniff_net_buffers_stop())
                return tool_result_t::error(OBFSTR("Failed to stop sniff session"));
            bool active_after = false;
            (void)device->sniff_net_buffers_get(active_after);
            json result;
            result["operation"] = "stop";
            result["stopped"] = true;
            result["active"] = active_after;
            result["active_before_stop"] = active_before;
            result["capture_count"] = captures.size();
            result["captures"] = sniff_captures_to_json(captures);
            result["driver_error"] = driver_bridge::last_error();
            return tool_result_t::ok(OBFSTR("Sniff session stopped"), result);
        }
        if (op == "store") {
            const json* bytes_value = nullptr;
            if (params.contains("bytes")) bytes_value = &params["bytes"];
            else if (params.contains("data")) bytes_value = &params["data"];
            else if (params.contains("hex")) bytes_value = &params["hex"];
            if (!bytes_value)
                return tool_result_t::error(OBFSTR("'bytes', 'data', or 'hex' is required for store operation"));
            std::vector<std::uint8_t> bytes;
            std::string parse_error;
            if (!parse_byte_sequence(*bytes_value, bytes, parse_error))
                return tool_result_t::error(OBFSTR("Invalid capture bytes: ") + parse_error);
            std::uint64_t timestamp = GetTickCount64();
            if (params.contains("timestamp")) {
                if (params["timestamp"].is_number_unsigned())
                    timestamp = params["timestamp"].get<std::uint64_t>();
                else if (params["timestamp"].is_number_integer())
                    timestamp = static_cast<std::uint64_t>(params["timestamp"].get<std::int64_t>());
                else if (params["timestamp"].is_string())
                    timestamp = sa_parse_address(params["timestamp"].get<std::string>()).value_or(timestamp);
            }
            std::uint64_t thread_id = GetCurrentThreadId();
            if (params.contains("thread_id")) {
                if (params["thread_id"].is_number_unsigned())
                    thread_id = params["thread_id"].get<std::uint64_t>();
                else if (params["thread_id"].is_number_integer())
                    thread_id = static_cast<std::uint64_t>(params["thread_id"].get<std::int64_t>());
                else if (params["thread_id"].is_string())
                    thread_id = sa_parse_address(params["thread_id"].get<std::string>()).value_or(thread_id);
            }
            if (!device->sniff_net_buffers_store(timestamp, thread_id, bytes.data(), static_cast<std::uint32_t>(bytes.size())))
                return tool_result_t::error(OBFSTR("Failed to store sniff capture"));
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);
            json result;
            result["operation"] = "store";
            result["stored"] = true;
            result["active"] = active;
            result["capture_count"] = captures.size();
            result["stored_size"] = bytes.size();
            result["captures"] = sniff_captures_to_json(captures);
            result["driver_error"] = driver_bridge::last_error();
            return tool_result_t::ok(OBFSTR("Sniff capture stored"), result);
        }
        if (op == "get" || op == "results") {
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);
            diag::log_tagged_fmt("drv_tools", "driver_sniff_network_buffers get active=%d captures=%zu",
                active ? 1 : 0, captures.size());

            json result;
            result["active"] = active;
            result["capture_count"] = captures.size();
            result["captures"] = sniff_captures_to_json(captures);

            return tool_result_t::ok(
                std::to_string(captures.size()) + OBFSTR(" capture(s) retrieved"), result);
        }
    }


    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        return tool_result_t::error(OBFSTR("Address of send/recv/encrypt function required"));


    auto reg_name_to_index = [](const std::string& name) -> std::uint32_t {
        static const std::pair<const char*, std::uint32_t> regs[] = {
            {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
            {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
            {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
            {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}
        };
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& [n, i] : regs)
            if (lower == n) return i;
        return 0;
    };

    std::uint32_t buf_reg = 1;
    if (params.contains("buffer_register"))
        buf_reg = reg_name_to_index(params["buffer_register"].get<std::string>());

    std::uint32_t size_reg = 2;
    if (params.contains("size_register"))
        size_reg = reg_name_to_index(params["size_register"].get<std::string>());

    std::uint32_t max_packets = params.value("max_packets", 1);
    if (max_packets > 16) max_packets = 16;

    std::uint32_t tid = 0;
    if (params.contains("tid"))
        tid = params["tid"].get<std::uint32_t>();

    std::uint32_t bp_index = params.value("bp_index", 0);
    if (bp_index > 3) bp_index = 0;

    if (!device->sniff_net_buffers_start(address, buf_reg, size_reg, max_packets, tid, bp_index))
        return tool_result_t::error(OBFSTR("Failed to start sniff session"));
    diag::log_tagged_fmt("drv_tools",
        "driver_sniff_network_buffers start address=0x%llX buf_reg=%u size_reg=%u max_packets=%u tid=%u bp_index=%u",
        static_cast<unsigned long long>(address), buf_reg, size_reg, max_packets, tid, bp_index);

    json result;
    result["status"] = "started";
    result["target_address"] = sa_format_address(static_cast<uint64_t>(address));
    result["buffer_register"] = reg_index_to_name(buf_reg);
    result["size_register"] = reg_index_to_name(size_reg);
    result["max_captures"] = max_packets;
    result["bp_index"] = bp_index;
    result["note"] = OBFSTR("Sniff session initialized. The HW breakpoint must be set separately via "
        "driver_set_hw_breakpoint on the target address. Then poll with operation='get' to retrieve captures. "
        "After each BP hit, read the buffer from memory using read_memory at the register value, "
        "then call this tool with operation='store' to record it.");

    return tool_result_t::ok(OBFSTR("Sniff session started"), result);
}

static bool parse_ip_string(const std::string& ip, std::uint8_t* out16, std::uint32_t* af) {
    std::memset(out16, 0, 16);

    unsigned a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256) {
        out16[0] = static_cast<std::uint8_t>(a);
        out16[1] = static_cast<std::uint8_t>(b);
        out16[2] = static_cast<std::uint8_t>(c);
        out16[3] = static_cast<std::uint8_t>(d);
        if (af) *af = 2;
        return true;
    }

    if (ip.find(':') != std::string::npos) {
        if (af) *af = 23;

        unsigned vals[8] = {};
        int count = sscanf(ip.c_str(), "%x:%x:%x:%x:%x:%x:%x:%x",
            &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7]);
        for (int i = 0; i < count && i < 8; i++) {
            out16[i*2]   = static_cast<std::uint8_t>((vals[i] >> 8) & 0xFF);
            out16[i*2+1] = static_cast<std::uint8_t>(vals[i] & 0xFF);
        }
        return count > 0;
    }
    return false;
}

tool_result_t driver_reassemble_stream(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_reassemble_stream entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::uint32_t op_code = 3;
    if (operation == "start") op_code = 0;
    else if (operation == "stop") op_code = 1;
    else if (operation == "get" || operation == "get_data") op_code = 2;
    else if (operation == "list") op_code = 3;
    else if (operation == "clear") op_code = 4;

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t pid = params.value("pid", 0u);
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, nullptr);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, nullptr);
    diag::log_tagged_fmt("drv_tools",
        "driver_reassemble_stream request operation=%s op_code=%u src_port=%u dst_port=%u pid=%u has_src_addr=%d has_dst_addr=%d",
        operation.c_str(), op_code, src_port, dst_port, pid,
        params.contains("src_addr") ? 1 : 0, params.contains("dst_addr") ? 1 : 0);

    std::vector<std::uint8_t> data;
    std::uint32_t packets = 0, truncated = 0;
    bool ok = device->stream_reassemble_op(op_code, src_port, dst_port, pid,
                                            src_addr, dst_addr, &data, &packets, &truncated);
    diag::log_tagged_fmt("drv_tools",
        "driver_reassemble_stream result ok=%d operation=%s bytes=%zu packets=%u truncated=%u",
        ok ? 1 : 0, operation.c_str(), data.size(), packets, truncated);
    if (!ok) return tool_result_t::error(OBFSTR("Stream operation failed"));

    json result;
    result["operation"] = operation;
    result["total_packets"] = packets;
    result["stream_size"] = data.size();
    result["empty_evidence"] = data.empty() && packets == 0;
    if (truncated) result["truncated"] = true;
    if (!data.empty()) {
        std::string hex;
        size_t preview = (data.size() > 256) ? 256 : data.size();
        for (size_t i = 0; i < preview; i++) {
            char buf[4];
            qsnprintf(buf, sizeof(buf), "%02X ", data[i]);
            hex += buf;
        }
        result["hex_preview"] = hex;

        std::string ascii;
        for (size_t i = 0; i < preview; i++)
            ascii += (data[i] >= 0x20 && data[i] < 0x7f) ? static_cast<char>(data[i]) : '.';
        result["ascii_preview"] = ascii;
    }

    return tool_result_t::ok(OBFSTR("Stream reassembly ") + operation + OBFSTR(": ") +
        std::to_string(data.size()) + OBFSTR(" bytes, ") + std::to_string(packets) + OBFSTR(" packets"), result);
}

tool_result_t driver_enum_kernel_callbacks(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enum_kernel_callbacks entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(mod_buf, info, err))
        return tool_result_t::error(err);


    std::uint64_t ntos_base = 0;
    std::uint64_t ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos ||
            lower.find("ntkrnlpa") != std::string::npos || lower.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }

    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not locate ntoskrnl.exe base via NtQuerySystemInformation"));

    json result;
    result["ntoskrnl_base"] = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["ntoskrnl_size"] = ntos_size;


    struct cb_type {
        const char* name;
        const char* export_name;
        int max_slots;
    };
    cb_type types[] = {
        {"PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutine", 64},
        {"PsSetCreateThreadNotifyRoutine",  "PsSetCreateThreadNotifyRoutine",  64},
        {"PsSetLoadImageNotifyRoutine",     "PsSetLoadImageNotifyRoutine",     64},
        {"CmRegisterCallback",              "CmRegisterCallbackEx",            64},
        {"ObRegisterCallbacks",             "ObRegisterCallbacks",             64},
    };

    json all_callbacks = json::array();
    for (const auto& t : types)
    {
        std::uint64_t fn_addr = device->resolve_export(ntos_base, t.export_name);
        if (fn_addr == 0) continue;

        json cb;
        cb["type"] = t.name;
        cb["registration_function"] = sa_format_address(static_cast<uint64_t>(fn_addr));


        std::uint8_t code[128] = {};
        device->read_kernel_raw(fn_addr, code, sizeof(code));

        json array_refs = json::array();
        for (int off = 0; off + 7 <= 128; ++off)
        {

            if ((code[off] == 0x48 || code[off] == 0x4C) &&
                code[off + 1] == 0x8D &&
                (code[off + 2] & 0xC7) == 0x05)
            {
                std::int32_t disp;
                std::memcpy(&disp, &code[off + 3], 4);
                std::uint64_t target = fn_addr + off + 7 + disp;

                if (is_probably_kernel_address(target))
                {
                    json ref;
                    ref["array_address"] = sa_format_address(static_cast<uint64_t>(target));
                    ref["instruction_offset"] = off;


                    json entries = json::array();
                    for (int slot = 0; slot < t.max_slots; ++slot)
                    {
                        std::uint64_t entry = 0;
                        device->read_kernel_raw(target + slot * 8, &entry, 8);
                        if (entry == 0) break;


                        std::uint64_t cb_body = entry & ~0xFULL;
                        if (!is_probably_kernel_address(cb_body)) continue;


                        std::uint64_t routine = 0;
                        device->read_kernel_raw(cb_body + 8, &routine, 8);

                        json e;
                        e["slot"]    = slot;
                        e["raw"]     = sa_format_address(static_cast<uint64_t>(entry));
                        e["block"]   = sa_format_address(static_cast<uint64_t>(cb_body));
                        e["routine"] = sa_format_address(static_cast<uint64_t>(routine));


                        if (is_probably_kernel_address(routine))
                        {
                            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                            {
                                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                                if (routine >= mb && routine < me)
                                {
                                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                                    auto slash = fp.find_last_of("\\/");
                                    e["owner_module"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                                    break;
                                }
                            }
                        }
                        entries.push_back(std::move(e));
                    }
                    ref["callbacks"] = std::move(entries);
                    ref["count"]     = ref["callbacks"].size();
                    array_refs.push_back(std::move(ref));
                }
            }
        }
        cb["arrays"] = std::move(array_refs);
        all_callbacks.push_back(std::move(cb));
    }

    result["callback_types"] = std::move(all_callbacks);
    result["note"] = OBFSTR("Kernel callbacks are used by anti-cheats (EAC/BattlEye/Vanguard) to monitor "
                            "process creation, thread creation, image loading, and registry access.");
    return tool_result_t::ok(OBFSTR("Kernel callback enumeration complete"), result);
}


tool_result_t driver_detect_integrity_checks(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_integrity_checks entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    std::vector<std::uint8_t> mod_buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(mod_buf, info, err))
        return tool_result_t::error(err);


    std::uint64_t ntos_base = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string path(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ntoskrnl") != std::string::npos || lower.find("ntkrnlmp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not locate ntoskrnl.exe base"));


    static const char* critical_exports[] = {
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtQueryVirtualMemory",
        "NtCreateThreadEx", "NtDeviceIoControlFile", "NtQuerySystemInformation",
        "NtSetInformationThread", "NtClose", "NtDuplicateObject",
        "MmCopyVirtualMemory", "KeStackAttachProcess", "KeUnstackDetachProcess",
        "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
        "ObOpenObjectByPointer", "MmProbeAndLockPages",
        nullptr
    };

    json hooks = json::array();
    json clean = json::array();
    int checked = 0;

    for (int fi = 0; critical_exports[fi]; ++fi)
    {
        std::uint64_t fn = device->resolve_export(ntos_base, critical_exports[fi]);
        if (fn == 0) continue;
        ++checked;


        std::uint8_t bytes[16] = {};
        device->read_kernel_raw(fn, bytes, 16);

        std::string hook_type;
        std::uint64_t hook_target = 0;


        if (bytes[0] == 0xE9)
        {
            std::int32_t rel;
            std::memcpy(&rel, &bytes[1], 4);
            hook_target = fn + 5 + rel;
            hook_type = "jmp_rel32";
        }
        else if (bytes[0] == 0xFF && bytes[1] == 0x25)
        {
            std::int32_t disp;
            std::memcpy(&disp, &bytes[2], 4);
            std::uint64_t ptr = fn + 6 + disp;
            device->read_kernel_raw(ptr, &hook_target, 8);
            hook_type = "jmp_indirect_rip";
        }
        else if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
        {
            std::memcpy(&hook_target, &bytes[2], 8);
            hook_type = "mov_rax_jmp_rax";
        }
        else if (bytes[0] == 0xCC)
        {
            hook_type = "int3_breakpoint";
        }

        if (!hook_type.empty())
        {
            json h;
            h["function"] = critical_exports[fi];
            h["address"]  = sa_format_address(static_cast<uint64_t>(fn));
            h["hook_type"] = hook_type;
            if (hook_target != 0)
            {
                h["target"] = sa_format_address(static_cast<uint64_t>(hook_target));

                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;
                    if (hook_target >= mb && hook_target < me)
                    {
                        std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                        auto slash = fp.find_last_of("\\/");
                        h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                        break;
                    }
                }
            }
            std::ostringstream hex;
            for (int b = 0; b < 16; ++b) { if (b) hex << " "; hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[b]); }
            h["prologue_bytes"] = hex.str();
            hooks.push_back(std::move(h));
        }
        else
        {
            json c;
            c["function"] = critical_exports[fi];
            c["address"]  = sa_format_address(static_cast<uint64_t>(fn));
            c["status"]   = "clean";
            clean.push_back(std::move(c));
        }
    }

    json result;
    result["ntoskrnl_base"]     = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["functions_checked"] = checked;
    result["hooks_found"]       = hooks.size();
    result["hooked_functions"]  = std::move(hooks);
    result["clean_functions"]   = std::move(clean);
    result["note"] = OBFSTR("Kernel function hooks indicate anti-cheat monitoring. Hooked functions route through "
                            "the anti-cheat driver, which can block, log, or alter calls from target processes.");
    return tool_result_t::ok(OBFSTR("Kernel integrity: ") + std::to_string(result["hooks_found"].get<std::size_t>()) +
                             OBFSTR(" hooks in ") + std::to_string(checked) + OBFSTR(" functions"), result);
}


tool_result_t driver_detect_ssdt_hooks(const json&)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err)) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks query_kernel_modules_failed err=%s", err.c_str());
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks modules=%lu kernel_dtb=0x%llX",
        static_cast<unsigned long>(info ? info->NumberOfModules : 0),
        static_cast<unsigned long long>(device->get_kernel_dtb()));

    std::uint64_t ntos_base = 0, ntos_size = 0;
    std::string ntos_path;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            ntos_path = reinterpret_cast<const char*>(info->Modules[i].FullPathName);
            break;
        }
    }
    if (ntos_base == 0) {
        for (ULONG i = 0; i < info->NumberOfModules && i < 12; ++i) {
            diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks module[%lu] base=0x%llX size=0x%lX path=%s",
                static_cast<unsigned long>(i),
                static_cast<unsigned long long>(reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase)),
                static_cast<unsigned long>(info->Modules[i].ImageSize),
                reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        }
        return tool_result_t::error(OBFSTR("Could not find ntoskrnl base address"));
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ntos base=0x%llX size=0x%llX path=%s",
        static_cast<unsigned long long>(ntos_base),
        static_cast<unsigned long long>(ntos_size),
        ntos_path.c_str());

    struct ssdt_entry_t {
        std::uint64_t service_table;
        std::uint64_t counter_table;
        std::uint32_t num_services;
        std::uint32_t _pad;
        std::uint64_t param_table;
    };
    ssdt_entry_t ssdt{};

    std::uint64_t ssdt_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTable");
    const bool export_available = (ssdt_addr != 0);
    std::string ssdt_resolution_source = "export";
    std::uint64_t ssdt_lstar = 0;
    std::uint32_t ssdt_flags = 0;

    if (export_available) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ssdt_addr=0x%llX source=export",
            static_cast<unsigned long long>(ssdt_addr));

        size_t ssdt_read = device->read_kernel_raw(ssdt_addr, &ssdt, sizeof(ssdt));
        if (ssdt_read < sizeof(ssdt)) {
            diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks read_ssdt_failed addr=0x%llX read=%zu need=%zu",
                static_cast<unsigned long long>(ssdt_addr), ssdt_read, sizeof(ssdt));
            return tool_result_t::error(OBFSTR("Failed to read SSDT structure"));
        }
    } else {
        std::uint64_t shadow_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTableShadow");
        std::uint64_t nt_close = device->resolve_export(ntos_base, "NtClose");
        std::uint64_t zw_close = device->resolve_export(ntos_base, "ZwClose");
        diag::log_tagged_fmt("drv_tools",
            "driver_detect_ssdt_hooks ssdt_export_missing ntos=0x%llX shadow=0x%llX NtClose=0x%llX ZwClose=0x%llX",
            static_cast<unsigned long long>(ntos_base),
            static_cast<unsigned long long>(shadow_addr),
            static_cast<unsigned long long>(nt_close),
            static_cast<unsigned long long>(zw_close));

        voyager::device_t::ssdt_info query{};
        if (!device->query_ssdt(query)) {
            diag::log_tagged_fmt("drv_tools",
                "driver_detect_ssdt_hooks ssdt_query_failed ntos=0x%llX kernel_dtb=0x%llX",
                static_cast<unsigned long long>(ntos_base),
                static_cast<unsigned long long>(device->get_kernel_dtb()));
            return tool_result_t::error(OBFSTR("Could not resolve SSDT through export or syscall-entry fallback"));
        }

        ssdt_addr = query.descriptor_address;
        ssdt.service_table = query.service_table;
        ssdt.counter_table = query.counter_table;
        ssdt.num_services = query.service_limit;
        ssdt.param_table = query.argument_table;
        ssdt_lstar = query.lstar;
        ssdt_flags = query.flags;
        ssdt_resolution_source = "lstar_syscall_entry";

        diag::log_tagged_fmt("drv_tools",
            "driver_detect_ssdt_hooks ssdt_query_ok lstar=0x%llX desc=0x%llX table=0x%llX counter=0x%llX arg=0x%llX limit=%u flags=0x%X",
            static_cast<unsigned long long>(query.lstar),
            static_cast<unsigned long long>(query.descriptor_address),
            static_cast<unsigned long long>(query.service_table),
            static_cast<unsigned long long>(query.counter_table),
            static_cast<unsigned long long>(query.argument_table),
            query.service_limit,
            query.flags);
    }
    diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks ssdt service_table=0x%llX counter=0x%llX num=%u param=0x%llX",
        static_cast<unsigned long long>(ssdt.service_table),
        static_cast<unsigned long long>(ssdt.counter_table),
        ssdt.num_services,
        static_cast<unsigned long long>(ssdt.param_table));

    if (ssdt.num_services == 0 || ssdt.num_services > 2048) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks invalid_service_count=%u", ssdt.num_services);
        return tool_result_t::error(OBFSTR("Invalid SSDT service count: ") + std::to_string(ssdt.num_services));
    }
    if (!is_probably_kernel_address(ssdt.service_table)) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks invalid_service_table=0x%llX",
            static_cast<unsigned long long>(ssdt.service_table));
        return tool_result_t::error(OBFSTR("ServiceTableBase is not a valid kernel address"));
    }


    std::vector<std::int32_t> entries(ssdt.num_services);
    size_t read_sz = ssdt.num_services * sizeof(std::int32_t);
    size_t entries_read = device->read_kernel_raw(ssdt.service_table, entries.data(), read_sz);
    if (entries_read < read_sz) {
        diag::log_tagged_fmt("drv_tools", "driver_detect_ssdt_hooks read_entries_failed table=0x%llX read=%zu need=%zu",
            static_cast<unsigned long long>(ssdt.service_table), entries_read, read_sz);
        return tool_result_t::error(OBFSTR("Failed to read SSDT entries"));
    }

    json hooked = json::array();
    json clean_count_json;
    int hooks_found = 0, clean_count = 0;
    std::uint64_t ntos_end = ntos_base + ntos_size;

    for (std::uint32_t i = 0; i < ssdt.num_services; ++i)
    {

        std::uint64_t fn = ssdt.service_table + (static_cast<std::uint64_t>(entries[i]) >> 4);

        bool inside_ntos = (fn >= ntos_base && fn < ntos_end);
        if (!inside_ntos)
        {
            json h;
            h["syscall_id"]    = i;
            h["address"]       = sa_format_address(static_cast<uint64_t>(fn));
            h["status"]        = "hooked";


            for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
            {
                std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                std::uint64_t me = mb + info->Modules[mi].ImageSize;
                if (fn >= mb && fn < me)
                {
                    std::string fp(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                    auto slash = fp.find_last_of("\\/");
                    h["hook_owner"] = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;
                    break;
                }
            }
            hooked.push_back(std::move(h));
            ++hooks_found;
        }
        else
        {
            ++clean_count;
        }
    }

    json result;
    result["ssdt_address"]      = sa_format_address(static_cast<uint64_t>(ssdt_addr));
    result["ssdt_descriptor_address"] = sa_format_address(static_cast<uint64_t>(ssdt_addr));
    result["ssdt_resolution_source"] = ssdt_resolution_source;
    result["export_available"] = export_available;
    result["lstar"] = sa_format_address(static_cast<uint64_t>(ssdt_lstar));
    result["ssdt_flags"] = ssdt_flags;
    result["service_table"]     = sa_format_address(static_cast<uint64_t>(ssdt.service_table));
    result["total_services"]    = ssdt.num_services;
    result["hooks_found"]       = hooks_found;
    result["clean_services"]    = clean_count;
    result["ntoskrnl_range"]    = sa_format_address(static_cast<uint64_t>(ntos_base)) + " - " +
                                  sa_format_address(static_cast<uint64_t>(ntos_end));
    result["hooked_entries"]    = std::move(hooked);
    result["note"] = OBFSTR("SSDT hooks redirect syscalls to third-party kernel code. Anti-cheats commonly hook "
                            "NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess to intercept memory access.");

    return tool_result_t::ok(OBFSTR("SSDT: ") + std::to_string(hooks_found) + OBFSTR(" hooks in ") +
                             std::to_string(ssdt.num_services) + OBFSTR(" services"), result);
}


tool_result_t driver_enum_minifilters(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enum_minifilters entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);


    std::uint64_t fltmgr_base = 0, fltmgr_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("fltmgr.sys") != std::string::npos)
        {
            fltmgr_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            fltmgr_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (fltmgr_base == 0)
        return tool_result_t::error(OBFSTR("Filter Manager (fltmgr.sys) not found in loaded modules"));


    uint8_t pe_hdr[0x1000];
    device->read_kernel_raw(fltmgr_base, pe_hdr, sizeof(pe_hdr));

    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    if (pe_off + 0x18 + 0x70 > sizeof(pe_hdr))
        return tool_result_t::error(OBFSTR("Invalid fltmgr PE header"));

    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_off  = pe_off + 24 + opt_hdr_sz;

    std::uint64_t data_rva = 0, data_size = 0;
    for (int s = 0; s < num_sections && (section_off + 40 <= sizeof(pe_hdr)); ++s, section_off += 40)
    {
        char name[9] = {};
        std::memcpy(name, &pe_hdr[section_off], 8);
        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_off + 12]);
        if (std::string(name) == ".data")
        {
            data_rva  = va;
            data_size = vs;
            break;
        }
    }
    if (data_rva == 0)
        return tool_result_t::error(OBFSTR("Could not find fltmgr .data section"));


    std::uint64_t data_addr = fltmgr_base + data_rva;
    size_t scan_sz = static_cast<size_t>(std::min(data_size, std::uint64_t{0x20000}));
    std::vector<uint8_t> data_buf(scan_sz);
    device->read_kernel_raw(data_addr, data_buf.data(), scan_sz);


    json filters = json::array();
    std::set<std::uint64_t> visited;

    for (size_t off = 0; off + 16 <= scan_sz; off += 8)
    {
        std::uint64_t flink = *reinterpret_cast<std::uint64_t*>(&data_buf[off]);
        std::uint64_t blink = *reinterpret_cast<std::uint64_t*>(&data_buf[off + 8]);

        if (!is_probably_kernel_address(flink) || !is_probably_kernel_address(blink)) continue;

        std::uint64_t head = data_addr + off;
        if (flink == head) continue;
        if (visited.count(flink)) continue;


        std::uint64_t cur = flink;
        int walk_count = 0;
        bool valid_chain = true;
        std::vector<std::uint64_t> entries_found;

        while (cur != head && walk_count < 64)
        {
            if (!is_probably_kernel_address(cur)) { valid_chain = false; break; }
            entries_found.push_back(cur);
            visited.insert(cur);


            std::uint64_t next = 0;
            if (device->read_kernel_raw(cur, &next, 8) < 8) { valid_chain = false; break; }
            if (next == cur) { valid_chain = false; break; }
            cur = next;
            ++walk_count;
        }

        if (!valid_chain || entries_found.empty() || walk_count < 1) continue;


        for (auto& entry_addr : entries_found)
        {

            uint8_t block[0x200];
            if (device->read_kernel_raw(entry_addr, block, sizeof(block)) < sizeof(block)) continue;


            for (int noff : {0x28, 0x38, 0x48, 0x58, 0x68, 0x78})
            {
                if (noff + 16 > (int)sizeof(block)) break;
                std::uint16_t len     = *reinterpret_cast<std::uint16_t*>(&block[noff]);
                std::uint16_t max_len = *reinterpret_cast<std::uint16_t*>(&block[noff + 2]);
                std::uint64_t buf_ptr = *reinterpret_cast<std::uint64_t*>(&block[noff + 8]);

                if (len == 0 || len > 512 || max_len < len || !is_probably_kernel_address(buf_ptr)) continue;


                std::vector<wchar_t> name_buf(len / 2 + 1, 0);
                if (device->read_kernel_raw(buf_ptr, name_buf.data(), len) < len) continue;

                std::wstring wname(name_buf.data());
                if (wname.empty()) continue;


                bool looks_valid = true;
                for (auto wc : wname)
                {
                    if (wc == 0) break;
                    if (wc < 0x20 || wc > 0x7E) { looks_valid = false; break; }
                }
                if (!looks_valid) continue;

                std::string name_str;
                for (wchar_t wc : wname) { if (wc == 0) break; name_str += static_cast<char>(wc); }


                std::string altitude_str;
                if (noff + 0x20 + 16 <= (int)sizeof(block))
                {
                    std::uint16_t alen  = *reinterpret_cast<std::uint16_t*>(&block[noff + 0x10]);
                    std::uint64_t abuf  = *reinterpret_cast<std::uint64_t*>(&block[noff + 0x18]);
                    if (alen > 0 && alen <= 64 && is_probably_kernel_address(abuf))
                    {
                        std::vector<wchar_t> abuf_data(alen / 2 + 1, 0);
                        if (device->read_kernel_raw(abuf, abuf_data.data(), alen) >= alen)
                        {
                            std::wstring walt(abuf_data.data());
                            altitude_str.clear();
                            for (wchar_t wc : walt) altitude_str += static_cast<char>(wc);
                        }
                    }
                }

                json f;
                f["address"]  = sa_format_address(static_cast<uint64_t>(entry_addr));
                f["name"]     = name_str;
                if (!altitude_str.empty()) f["altitude"] = altitude_str;


                for (ULONG mi = 0; mi < info->NumberOfModules; ++mi)
                {
                    std::uint64_t mb = reinterpret_cast<std::uint64_t>(info->Modules[mi].ImageBase);
                    std::uint64_t me = mb + info->Modules[mi].ImageSize;

                    for (int poff = 0; poff + 8 <= (int)sizeof(block); poff += 8)
                    {
                        std::uint64_t ptr = *reinterpret_cast<std::uint64_t*>(&block[poff]);
                        if (ptr >= mb && ptr < me)
                        {
                            std::string mpth(reinterpret_cast<const char*>(info->Modules[mi].FullPathName));
                            auto slash = mpth.find_last_of("\\/");
                            f["owner_module"] = (slash != std::string::npos) ? mpth.substr(slash + 1) : mpth;
                            goto owner_found;
                        }
                    }
                }
                owner_found:


                bool dup = false;
                for (const auto& existing : filters)
                    if (existing["name"] == name_str) { dup = true; break; }
                if (!dup) filters.push_back(std::move(f));
                break;
            }
        }
    }

    json result;
    result["fltmgr_base"]     = sa_format_address(static_cast<uint64_t>(fltmgr_base));
    result["filter_count"]    = filters.size();
    result["filters"]         = std::move(filters);
    result["note"] = OBFSTR("Minifilter drivers intercept filesystem I/O. Anti-cheats use minifilters to monitor file access, "
                            "prevent dumps, and detect injection DLLs. Altitude determines callback priority order.");

    return tool_result_t::ok(OBFSTR("Minifilters: ") + std::to_string(result["filter_count"].get<std::size_t>()) +
                             OBFSTR(" registered filter drivers"), result);
}


tool_result_t driver_detect_etw_monitors(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_etw_monitors entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB is not resolved. Attach with sessions_manage action=attach_pid first."));

    std::vector<uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + err);

    std::uint64_t ntos_base = 0, ntos_size = 0;
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        std::transform(fp.begin(), fp.end(), fp.begin(), ::tolower);
        if (fp.find("ntoskrnl") != std::string::npos || fp.find("ntkrnlmp") != std::string::npos ||
            fp.find("ntkrnlpa") != std::string::npos || fp.find("ntkrpamp") != std::string::npos)
        {
            ntos_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
            ntos_size = info->Modules[i].ImageSize;
            break;
        }
    }
    if (ntos_base == 0)
        return tool_result_t::error(OBFSTR("Could not find ntoskrnl base address"));


    std::uint64_t etw_threat_intel = device->resolve_export(ntos_base, "EtwThreatIntProvRegHandle");
    std::uint64_t etw_register     = device->resolve_export(ntos_base, "EtwRegister");

    json providers = json::array();


    if (etw_threat_intel != 0)
    {

        std::uint64_t reg_handle = 0;
        device->read_kernel_raw(etw_threat_intel, &reg_handle, 8);

        json ti;
        ti["name"]    = "Microsoft-Windows-Threat-Intelligence";
        ti["address"] = sa_format_address(static_cast<uint64_t>(etw_threat_intel));
        ti["status"]  = (reg_handle != 0) ? "active" : "inactive";
        ti["note"]    = OBFSTR("ETW-TI monitors process injection, executable memory allocation, and other "
                               "security-sensitive operations. Used by EDR and anti-cheat for real-time telemetry.");
        if (reg_handle != 0)
            ti["reg_handle"] = sa_format_address(static_cast<uint64_t>(reg_handle));
        providers.push_back(std::move(ti));
    }


    struct known_guid_t {
        const char* name;
        uint8_t bytes[16];
    };
    static const known_guid_t known_guids[] = {
        {"Microsoft-Windows-Kernel-Audit-API-Calls",
         {0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}},
        {"Microsoft-Windows-Kernel-Process",
         {0x27, 0x09, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}},
    };


    uint8_t pe_hdr[0x1000];
    device->read_kernel_raw(ntos_base, pe_hdr, sizeof(pe_hdr));
    std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&pe_hdr[0x3C]);
    std::uint16_t num_sections = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 6]);
    std::uint16_t opt_hdr_sz   = *reinterpret_cast<std::uint16_t*>(&pe_hdr[pe_off + 20]);
    std::uint32_t section_tbl  = pe_off + 24 + opt_hdr_sz;

    for (int s = 0; s < num_sections && (section_tbl + 40 <= sizeof(pe_hdr)); ++s, section_tbl += 40)
    {
        char sn[9] = {};
        std::memcpy(sn, &pe_hdr[section_tbl], 8);
        if (std::string(sn) != ".data" && std::string(sn) != ".rdata") continue;

        std::uint32_t vs = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 8]);
        std::uint32_t va = *reinterpret_cast<std::uint32_t*>(&pe_hdr[section_tbl + 12]);
        std::uint64_t sec_addr = ntos_base + va;
        size_t sec_sz  = std::min(vs, (std::uint32_t)0x100000);

        std::vector<uint8_t> sec_data(sec_sz);
        device->read_kernel_raw(sec_addr, sec_data.data(), sec_sz);

        for (const auto& g : known_guids)
        {
            for (size_t off = 0; off + 16 <= sec_sz; ++off)
            {
                if (std::memcmp(&sec_data[off], g.bytes, 16) == 0)
                {
                    json prov;
                    prov["name"]    = g.name;
                    prov["address"] = sa_format_address(static_cast<uint64_t>(sec_addr + off));
                    prov["status"]  = "guid_found";
                    providers.push_back(std::move(prov));
                    break;
                }
            }
        }
    }


    json etw_modules = json::array();
    for (ULONG i = 0; i < info->NumberOfModules; ++i)
    {
        std::uint64_t mod_base = reinterpret_cast<std::uint64_t>(info->Modules[i].ImageBase);
        std::string fp(reinterpret_cast<const char*>(info->Modules[i].FullPathName));
        auto slash = fp.find_last_of("\\/");
        std::string mod_name = (slash != std::string::npos) ? fp.substr(slash + 1) : fp;

        std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);

        if (mod_name.find("ntoskrnl") != std::string::npos || mod_name.find("ntkrnl") != std::string::npos ||
            mod_name.find("hal.dll") != std::string::npos || mod_name.find("ci.dll") != std::string::npos ||
            mod_name.find("fltmgr") != std::string::npos || mod_name.find("nt.") != std::string::npos)
            continue;


        uint8_t mod_hdr[0x400];
        if (device->read_kernel_raw(mod_base, mod_hdr, sizeof(mod_hdr)) < 0x100) continue;
        if (mod_hdr[0] != 'M' || mod_hdr[1] != 'Z') continue;

        std::uint32_t mod_pe_off = *reinterpret_cast<std::uint32_t*>(&mod_hdr[0x3C]);
        if (mod_pe_off + 0x90 > sizeof(mod_hdr)) continue;


        uint8_t scan_buf[0x1000];
        device->read_kernel_raw(mod_base, scan_buf, sizeof(scan_buf));


        for (size_t off = 0; off + 11 < sizeof(scan_buf); ++off)
        {
            if (std::memcmp(&scan_buf[off], "EtwRegis", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwWrite", 8) == 0 ||
                std::memcmp(&scan_buf[off], "EtwEventW", 9) == 0)
            {
                json em;
                em["module"]  = mod_name;
                em["address"] = sa_format_address(static_cast<uint64_t>(mod_base));
                em["etw_api_found"] = std::string(reinterpret_cast<const char*>(&scan_buf[off]),
                                                   std::min((size_t)32, sizeof(scan_buf) - off));

                auto& s = em["etw_api_found"].get_ref<std::string&>();
                auto nul = s.find('\0');
                if (nul != std::string::npos) s.resize(nul);
                etw_modules.push_back(std::move(em));
                break;
            }
        }
    }

    json result;
    result["ntoskrnl_base"]     = sa_format_address(static_cast<uint64_t>(ntos_base));
    result["etw_register"]      = (etw_register != 0) ? sa_format_address(static_cast<uint64_t>(etw_register)) : "not_found";
    result["threat_intel"]      = (etw_threat_intel != 0) ? sa_format_address(static_cast<uint64_t>(etw_threat_intel)) : "not_exported";
    result["providers"]         = std::move(providers);
    result["etw_consumer_modules"] = std::move(etw_modules);
    result["note"] = OBFSTR("ETW (Event Tracing for Windows) provides kernel-level telemetry. The Threat Intelligence "
                            "provider detects process injection, executable memory allocation, and suspicious API sequences. "
                            "Anti-cheats and EDRs subscribe to these events for real-time detection.");

    return tool_result_t::ok(OBFSTR("ETW monitors: ") + std::to_string(result["providers"].size()) +
                             OBFSTR(" providers, ") + std::to_string(result["etw_consumer_modules"].size()) +
                             OBFSTR(" consumer modules"), result);
}


tool_result_t driver_detect_hidden_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_detect_hidden_modules entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));
    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("No target process attached. Use sessions_manage action=attach_pid first."));

    bool scan_kernel = params.value("kernel", false);

    json hidden = json::array();
    json legitimate = json::array();

    if (!scan_kernel)
    {


        voyager::device_t::peb_info peb{};
        if (!device->read_peb(peb))
            return tool_result_t::error(OBFSTR("Failed to read PEB"));


        auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);


        std::set<std::uint64_t> peb_bases;


        std::uint64_t peb_addr = 0;


        auto modules = device->enumerate_memory_regions(0x10000, 0x7FFFFFFFFFFF, false);


        struct known_module_t {
            std::uint64_t base;
            std::uint64_t size;
            std::string name;
        };
        std::vector<known_module_t> known_modules;


        std::uint64_t ldr = 0;
        device->read_raw(peb.peb_address + 0x18, &ldr, 8);
        if (ldr != 0 && ldr < 0x7FFFFFFFFFFF)
        {

            std::uint64_t head = ldr + 0x10;
            std::uint64_t flink = 0;
            device->read_raw(head, &flink, 8);

            std::uint64_t cur = flink;
            int count = 0;
            while (cur != head && cur != 0 && count < 1024)
            {

                std::uint64_t dll_base = 0;
                std::uint32_t dll_size = 0;
                device->read_raw(cur + 0x30, &dll_base, 8);
                device->read_raw(cur + 0x40, &dll_size, 4);


                std::uint16_t name_len = 0;
                std::uint64_t name_buf = 0;
                device->read_raw(cur + 0x48, &name_len, 2);
                device->read_raw(cur + 0x48 + 8, &name_buf, 8);

                std::string name_str;
                if (name_len > 0 && name_len < 1024 && name_buf != 0)
                {
                    std::vector<wchar_t> wbuf(name_len / 2 + 1, 0);
                    device->read_raw(name_buf, wbuf.data(), name_len);
                    std::wstring wname(wbuf.data());
                    for (wchar_t wc : wname) name_str += static_cast<char>(wc);
                }

                if (dll_base != 0)
                {
                    known_modules.push_back({dll_base, dll_size, name_str});
                    peb_bases.insert(dll_base);
                }


                device->read_raw(cur, &cur, 8);
                ++count;
            }
        }


        for (const auto& reg : regions)
        {
            if (reg.size < 0x1000) continue;


            uint8_t mz[2] = {};
            device->read_raw(reg.base, mz, 2);
            if (mz[0] != 'M' || mz[1] != 'Z') continue;


            if (peb_bases.count(reg.base) == 0)
            {

                json h;
                h["address"] = sa_format_address(static_cast<uint64_t>(reg.base));
                h["size"]    = reg.size;
                h["status"]  = "hidden_pe";


                uint8_t pe_buf[0x400];
                if (device->read_raw(reg.base, pe_buf, sizeof(pe_buf)) >= 0x100)
                {
                    std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                    if (pe_off2 + 0x90 <= sizeof(pe_buf))
                    {

                        std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                        if (export_rva > 0 && export_rva < 0x1000000)
                        {

                            uint8_t exp_dir[0x28];
                            if (device->read_raw(reg.base + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                            {
                                std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                                if (name_rva > 0 && name_rva < 0x1000000)
                                {
                                    char exp_name[128] = {};
                                    device->read_raw(reg.base + name_rva, exp_name, sizeof(exp_name) - 1);
                                    if (exp_name[0]) h["export_name"] = std::string(exp_name);
                                }
                            }
                        }

                        std::uint16_t chars = *reinterpret_cast<std::uint16_t*>(&pe_buf[pe_off2 + 0x16]);
                        h["is_dll"] = (chars & 0x2000) != 0;
                    }
                }

                hidden.push_back(std::move(h));
            }
            else
            {

                for (const auto& km : known_modules)
                {
                    if (km.base == reg.base)
                    {
                        json l;
                        l["address"] = sa_format_address(static_cast<uint64_t>(reg.base));
                        l["size"]    = km.size;
                        l["name"]    = km.name;
                        legitimate.push_back(std::move(l));
                        break;
                    }
                }
            }
        }
    }
    else
    {

        std::vector<uint8_t> mod_buf;
        sys_module_info_t* kinfo = nullptr;
        std::string kerr;
        if (!query_kernel_modules(mod_buf, kinfo, kerr))
            return tool_result_t::error(OBFSTR("Failed to enumerate kernel modules: ") + kerr);

        std::set<std::uint64_t> known_bases;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
            known_bases.insert(reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase));


        std::vector<std::pair<std::uint64_t, std::uint64_t>> scan_ranges;
        for (ULONG i = 0; i < kinfo->NumberOfModules; ++i)
        {
            std::uint64_t base = reinterpret_cast<std::uint64_t>(kinfo->Modules[i].ImageBase);
            std::uint64_t size = kinfo->Modules[i].ImageSize;

            if (base >= 0x10000)
                scan_ranges.push_back({base - 0x10000, base});
            scan_ranges.push_back({base + size, base + size + 0x10000});
        }

        int pages_scanned = 0;
        for (const auto& [start, end] : scan_ranges)
        {
            if (pages_scanned > 2048) break;
            for (std::uint64_t addr = start; addr < end; addr += 0x1000)
            {
                if (known_bases.count(addr)) continue;
                ++pages_scanned;

                uint8_t mz[2] = {};
                if (device->read_kernel_raw(addr, mz, 2) < 2) continue;
                if (mz[0] != 'M' || mz[1] != 'Z') continue;


                uint8_t pe_buf[0x400];
                if (device->read_kernel_raw(addr, pe_buf, sizeof(pe_buf)) < 0x100) continue;

                std::uint32_t pe_off2 = *reinterpret_cast<std::uint32_t*>(&pe_buf[0x3C]);
                if (pe_off2 > 0x300 || pe_off2 < 4) continue;
                if (pe_buf[pe_off2] != 'P' || pe_buf[pe_off2 + 1] != 'E') continue;

                json h;
                h["address"] = sa_format_address(static_cast<uint64_t>(addr));
                h["status"]  = "hidden_kernel_pe";
                h["mode"]    = "kernel";

                std::uint32_t img_size = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x50]);
                h["image_size"] = img_size;


                std::uint32_t export_rva = *reinterpret_cast<std::uint32_t*>(&pe_buf[pe_off2 + 0x88]);
                if (export_rva > 0 && export_rva < img_size)
                {
                    uint8_t exp_dir[0x28];
                    if (device->read_kernel_raw(addr + export_rva, exp_dir, sizeof(exp_dir)) >= sizeof(exp_dir))
                    {
                        std::uint32_t name_rva = *reinterpret_cast<std::uint32_t*>(&exp_dir[0x0C]);
                        if (name_rva > 0 && name_rva < img_size)
                        {
                            char exp_name[128] = {};
                            device->read_kernel_raw(addr + name_rva, exp_name, sizeof(exp_name) - 1);
                            if (exp_name[0]) h["export_name"] = std::string(exp_name);
                        }
                    }
                }

                hidden.push_back(std::move(h));
            }
        }
    }

    json result;
    result["mode"]           = scan_kernel ? "kernel" : "usermode";
    result["hidden_count"]   = hidden.size();
    result["hidden_modules"] = std::move(hidden);
    if (!scan_kernel)
    {
        result["legitimate_count"]  = legitimate.size();
        result["legitimate_modules"] = std::move(legitimate);
    }
    result["note"] = OBFSTR("Hidden modules are PE images present in memory but not in the PEB module list (usermode) "
                            "or NtQuerySystemInformation module list (kernel). Common for manual-mapped DLLs, "
                            "anti-cheat drivers, and injected payloads.");

    return tool_result_t::ok(OBFSTR("Hidden modules: ") + std::to_string(result["hidden_count"].get<std::size_t>()) +
                             OBFSTR(" found"), result);
}


tool_result_t driver_walk_heap(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_walk_heap entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::uint32_t pid = device->get_process_id();
    const int max_entries = std::min(params.value("limit", 500), 5000);
    const std::uint64_t filter_min = params.contains("min_size") ? params["min_size"].get<std::uint64_t>() : 0;
    const std::uint64_t filter_max = params.contains("max_size") ? params["max_size"].get<std::uint64_t>() : 0;
    const bool free_only = params.value("free_only", false);

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb))
        return tool_result_t::error(OBFSTR("Failed to read PEB"));

    const std::uint64_t peb_addr = peb.peb_address;
    if (peb_addr == 0)
        return tool_result_t::error(OBFSTR("PEB address is null"));


    const std::uint32_t num_heaps = device->read<std::uint32_t>(peb_addr + 0xE8);
    const std::uint64_t heaps_ptr = device->read<std::uint64_t>(peb_addr + 0xF0);
    diag::log_tagged_fmt("drv_tools",
        "driver_walk_heap peb=0x%llX num_heaps=%u heaps_ptr=0x%llX limit=%d min=%llu max=%llu free_only=%d",
        static_cast<unsigned long long>(peb_addr),
        num_heaps,
        static_cast<unsigned long long>(heaps_ptr),
        max_entries,
        static_cast<unsigned long long>(filter_min),
        static_cast<unsigned long long>(filter_max),
        free_only ? 1 : 0);

    if (num_heaps == 0 || num_heaps > 256 || heaps_ptr == 0)
        return tool_result_t::error(OBFSTR("No heaps found or invalid PEB heap data"));

    json heaps_arr = json::array();
    int total_entries = 0;

    for (std::uint32_t h = 0; h < num_heaps && total_entries < max_entries; ++h)
    {
        const std::uint64_t heap_base = device->read<std::uint64_t>(heaps_ptr + h * 8);
        if (heap_base == 0) continue;


        const std::uint32_t signature = device->read<std::uint32_t>(heap_base);
        const std::uint64_t total_free = device->read<std::uint64_t>(heap_base + 0x40);
        const std::uint64_t num_pages = device->read<std::uint64_t>(heap_base + 0x38);
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap heap[%u] base=0x%llX sig=0x%08X total_free=%llu pages=%llu",
            h,
            static_cast<unsigned long long>(heap_base),
            signature,
            static_cast<unsigned long long>(total_free),
            static_cast<unsigned long long>(num_pages));

        json heap_info;
        heap_info["heap_index"] = h;
        heap_info["heap_base"] = sa_format_address(static_cast<uint64_t>(heap_base));
        heap_info["signature"] = sa_format_address(static_cast<uint64_t>(signature));
        heap_info["total_free_size"] = total_free;
        heap_info["committed_pages"] = num_pages;


        const std::uint64_t seg_list_head = heap_base + 0x120;
        std::uint64_t seg_flink = device->read<std::uint64_t>(seg_list_head);

        json segments_arr = json::array();
        int seg_iter = 0;
        constexpr int MAX_SEGS = 64;

        while (seg_flink != 0 && seg_flink != seg_list_head && seg_iter++ < MAX_SEGS && total_entries < max_entries)
        {

            const std::uint64_t segment_base = seg_flink - 0x18;
            const std::uint64_t seg_base_addr = device->read<std::uint64_t>(segment_base + 0x0);
            const std::uint32_t seg_num_pages = device->read<std::uint32_t>(segment_base + 0x10);
            const std::uint64_t first_entry = device->read<std::uint64_t>(segment_base + 0x28);
            const std::uint64_t last_entry = device->read<std::uint64_t>(segment_base + 0x48);
            diag::log_tagged_fmt("drv_tools",
                "driver_walk_heap heap[%u] segment[%d] segment_base=0x%llX seg_base_addr=0x%llX pages=%u first=0x%llX last=0x%llX",
                h,
                seg_iter - 1,
                static_cast<unsigned long long>(segment_base),
                static_cast<unsigned long long>(seg_base_addr),
                seg_num_pages,
                static_cast<unsigned long long>(first_entry),
                static_cast<unsigned long long>(last_entry));


            std::uint64_t entry_addr = first_entry;
            int entry_iter = 0;
            constexpr int MAX_ENTRIES_PER_SEG = 2048;
            json entries_arr = json::array();

            while (entry_addr != 0 && entry_addr < last_entry && entry_iter++ < MAX_ENTRIES_PER_SEG && total_entries < max_entries)
            {


                std::uint16_t raw_size = device->read<std::uint16_t>(entry_addr);
                std::uint8_t flags = device->read<std::uint8_t>(entry_addr + 0x2);
                std::uint8_t unused_bytes = device->read<std::uint8_t>(entry_addr + 0x7);

                std::uint64_t block_size = static_cast<std::uint64_t>(raw_size) * 16;
                if (block_size == 0) break;

                bool is_busy = (flags & 0x01) != 0;
                bool is_extra = (flags & 0x02) != 0;
                bool is_fill = (flags & 0x04) != 0;
                bool is_virtual = (flags & 0x08) != 0;
                bool is_last = (flags & 0x10) != 0;

                bool include = true;
                if (free_only && is_busy) include = false;
                if (filter_min > 0 && block_size < filter_min) include = false;
                if (filter_max > 0 && block_size > filter_max) include = false;

                if (include)
                {
                    json entry;
                    entry["address"] = sa_format_address(static_cast<uint64_t>(entry_addr));
                    entry["user_address"] = sa_format_address(static_cast<uint64_t>(entry_addr + 0x10));
                    entry["block_size"] = block_size;
                    entry["user_size"] = block_size > unused_bytes ? block_size - unused_bytes - 0x10 : 0;
                    entry["flags"] = {
                        {"busy", is_busy}, {"extra", is_extra}, {"fill", is_fill},
                        {"virtual_alloc", is_virtual}, {"last_entry", is_last}
                    };
                    entries_arr.push_back(std::move(entry));
                    ++total_entries;
                }

                entry_addr += block_size;
                if (is_last) break;
            }

            json seg;
            seg["segment_base"] = sa_format_address(static_cast<uint64_t>(segment_base));
            seg["pages"] = seg_num_pages;
            seg["entries"] = std::move(entries_arr);
            segments_arr.push_back(std::move(seg));

            seg_flink = device->read<std::uint64_t>(seg_flink);
        }

        heap_info["segments"] = std::move(segments_arr);
        heaps_arr.push_back(std::move(heap_info));
    }

    json fallback_regions = json::array();
    std::string walk_mode = "heap_entries";
    if (total_entries == 0)
    {
        int fallback_count = 0;
        auto regions = enumerate_all_memory_regions_paginated(
            device.get(), 0x10000, 0x7FFFFFFFFFFF, false);
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap no_entries fallback_regions_scan regions=%zu",
            regions.size());
        for (const auto& region : regions)
        {
            if (fallback_count >= max_entries) break;
            if ((region.state & 0x1000) == 0) continue;
            if (region.type != 0x20000) continue;
            const std::uint32_t prot = region.protect & 0xFF;
            if ((prot & 0xCC) == 0) continue;
            if (filter_min > 0 && region.size < filter_min) continue;
            if (filter_max > 0 && region.size > filter_max) continue;
            json entry;
            entry["address"] = sa_format_address(static_cast<uint64_t>(region.base));
            entry["user_address"] = sa_format_address(static_cast<uint64_t>(region.base));
            entry["block_size"] = region.size;
            entry["user_size"] = region.size;
            entry["flags"] = {
                {"busy", true},
                {"extra", false},
                {"fill", false},
                {"virtual_alloc", true},
                {"last_entry", false}
            };
            entry["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
            entry["source"] = "committed_private_region_fallback";
            fallback_regions.push_back(std::move(entry));
            ++fallback_count;
        }
        total_entries = fallback_count;
        walk_mode = "committed_private_region_fallback";
        diag::log_tagged_fmt("drv_tools",
            "driver_walk_heap fallback_done returned=%d",
            fallback_count);
    }

    json result;
    result["process_id"] = pid;
    result["heap_count"] = num_heaps;
    result["entries_returned"] = total_entries;
    result["walk_mode"] = walk_mode;
    result["heaps"] = std::move(heaps_arr);
    if (!fallback_regions.empty())
        result["fallback_regions"] = std::move(fallback_regions);
    return tool_result_t::ok(OBFSTR("Walked ") + std::to_string(num_heaps) + OBFSTR(" heaps, ") +
                             std::to_string(total_entries) + OBFSTR(" entries"), result);
}

tool_result_t driver_enumerate_handles(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_handles entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    const std::uint32_t filter_pid = params.value("pid", 0u);
    const std::string filter_type = params.value("type_filter", "");
    const int limit = std::min(params.value("limit", 500), 10000);


    typedef struct {
        ULONG NumberOfHandles;
    } SYSTEM_HANDLE_INFORMATION_HEAD;

    typedef struct {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO;


    auto type_name_from_index = [](std::uint8_t idx) -> std::string {
        switch (idx) {
            case 7:  return "Process";
            case 8:  return "Thread";
            case 5:  return "Token";
            case 37: return "Section";
            case 39: return "Key";
            case 36: return "File";
            case 28: return "Event";
            case 30: return "Mutant";
            case 31: return "Semaphore";
            case 32: return "Timer";
            case 44: return "Directory";
            case 45: return "SymbolicLink";
            default: return "Type_" + std::to_string(idx);
        }
    };

    ULONG bufsize = 1 << 22;
    std::vector<std::uint8_t> buffer(bufsize);
    NTSTATUS status;
    using NtQuerySystemInformationFn = NTSTATUS(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation)
        return tool_result_t::error(OBFSTR("Failed to resolve NtQuerySystemInformation"));

    ULONG returned_length = 0;
    for (int attempt = 0; attempt < 5; ++attempt)
    {
        status = NtQuerySystemInformation(16 , buffer.data(),
                                          static_cast<ULONG>(buffer.size()), &returned_length);
        if (status == 0) break;
        if (status == 0xC0000004 )
        {
            bufsize = returned_length + (1 << 20);
            if (bufsize > (1u << 28))
                return tool_result_t::error(OBFSTR("Handle table too large"));
            buffer.resize(bufsize);
            continue;
        }
        return tool_result_t::error(OBFSTR("NtQuerySystemInformation failed: 0x") +
                                    sa_format_address(static_cast<uint64_t>(status)));
    }

    const auto* head = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_HEAD*>(buffer.data());
    const auto* entries = reinterpret_cast<const SYSTEM_HANDLE_TABLE_ENTRY_INFO*>(buffer.data() + sizeof(ULONG));
    const ULONG count = head->NumberOfHandles;

    const std::string filter_type_lower = to_lower_ascii_copy(filter_type);
    json handles_arr = json::array();
    int matched = 0;

    for (ULONG i = 0; i < count && matched < limit; ++i)
    {
        const auto& e = entries[i];
        if (filter_pid != 0 && e.UniqueProcessId != static_cast<USHORT>(filter_pid))
            continue;

        std::string type_name = type_name_from_index(e.ObjectTypeIndex);
        if (!filter_type_lower.empty())
        {
            std::string lower_type = to_lower_ascii_copy(type_name);
            if (lower_type.find(filter_type_lower) == std::string::npos)
                continue;
        }

        json h;
        h["pid"] = static_cast<std::uint32_t>(e.UniqueProcessId);
        h["handle"] = static_cast<std::uint32_t>(e.HandleValue);
        h["type"] = type_name;
        h["type_index"] = e.ObjectTypeIndex;
        h["object_address"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(e.Object)));
        h["access"] = sa_format_address(static_cast<uint64_t>(e.GrantedAccess));
        h["attributes"] = e.HandleAttributes;
        handles_arr.push_back(std::move(h));
        ++matched;
    }

    json result;
    result["total_system_handles"] = count;
    result["returned"] = matched;
    if (filter_pid != 0) result["filter_pid"] = filter_pid;
    if (!filter_type.empty()) result["filter_type"] = filter_type;
    result["handles"] = std::move(handles_arr);
    return tool_result_t::ok(std::to_string(matched) + OBFSTR(" handles returned (") +
                             std::to_string(count) + OBFSTR(" total system-wide)"), result);
}





tool_result_t driver_enumerate_windows(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_enumerate_windows entry");
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    const std::uint32_t filter_pid = params.value("pid", device->get_process_id());
    const bool include_children = params.value("include_children", true);
    const int limit = std::min(params.value("limit", 200), 2000);

    if (filter_pid == 0)
        return tool_result_t::error(OBFSTR("No process attached and no pid specified."));

    struct window_info_t {
        HWND hwnd;
        HWND parent;
        DWORD pid;
        DWORD tid;
        char class_name[256];
        char title[512];
        RECT rect;
        bool visible;
        LONG style;
        LONG ex_style;
    };

    std::vector<window_info_t> windows;

    struct enum_ctx_t {
        std::vector<window_info_t>* windows;
        DWORD target_pid;
        int limit;
        bool include_children;
    };

    enum_ctx_t ctx_data;
    ctx_data.windows = &windows;
    ctx_data.target_pid = filter_pid;
    ctx_data.limit = limit;
    ctx_data.include_children = include_children;

    auto enum_proc = [](HWND hwnd, LPARAM lparam) -> BOOL {
        auto* ctx2 = reinterpret_cast<enum_ctx_t*>(lparam);
        if (static_cast<int>(ctx2->windows->size()) >= ctx2->limit)
            return FALSE;

        DWORD wnd_pid = 0;
        DWORD wnd_tid = GetWindowThreadProcessId(hwnd, &wnd_pid);
        if (wnd_pid != ctx2->target_pid)
            return TRUE;

        window_info_t info{};
        info.hwnd = hwnd;
        info.parent = GetParent(hwnd);
        info.pid = wnd_pid;
        info.tid = wnd_tid;
        GetClassNameA(hwnd, info.class_name, sizeof(info.class_name));
        GetWindowTextA(hwnd, info.title, sizeof(info.title));
        GetWindowRect(hwnd, &info.rect);
        info.visible = IsWindowVisible(hwnd) != FALSE;
        info.style = GetWindowLongA(hwnd, GWL_STYLE);
        info.ex_style = GetWindowLongA(hwnd, GWL_EXSTYLE);
        ctx2->windows->push_back(info);
        return TRUE;
    };

    EnumWindows(enum_proc, reinterpret_cast<LPARAM>(&ctx_data));

    json windows_arr = json::array();
    for (const auto& w : windows)
    {
        json wj;
        wj["hwnd"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(w.hwnd)));
        wj["parent"] = sa_format_address(static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(w.parent)));
        wj["tid"] = w.tid;
        wj["class_name"] = w.class_name;
        wj["title"] = w.title;
        wj["visible"] = w.visible;
        wj["rect"] = { {"left", w.rect.left}, {"top", w.rect.top},
                       {"right", w.rect.right}, {"bottom", w.rect.bottom} };
        wj["style"] = sa_format_address(static_cast<uint64_t>(w.style));
        wj["ex_style"] = sa_format_address(static_cast<uint64_t>(w.ex_style));
        windows_arr.push_back(std::move(wj));
    }

    json result;
    result["pid"] = filter_pid;
    result["window_count"] = windows.size();
    result["windows"] = std::move(windows_arr);
    return tool_result_t::ok(std::to_string(windows.size()) + OBFSTR(" windows found for PID ") +
                             std::to_string(filter_pid), result);
}


tool_result_t driver_assemble(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_assemble entry");
    const std::string assembly_text = params.value("assembly", "");
    if (assembly_text.empty())
        return tool_result_t::error(OBFSTR("Missing required parameter: assembly"));

    const std::uint64_t address = [&]() -> std::uint64_t {
        if (params.contains("address"))
        {
            auto a = sa_parse_address(params["address"].get<std::string>());
            return a ? *a : 0x140000000ULL;
        }
        return 0x140000000ULL;
    }();


    std::vector<std::uint8_t> output;
    std::string error_msg;

    auto trim = [](const std::string& s) -> std::string {
        const auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        return s.substr(start, s.find_last_not_of(" \t\r\n") - start + 1);
    };

    auto to_upper = [](std::string s) -> std::string {
        std::transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    };

    auto reg_to_idx = [](const std::string& reg) -> int {
        if (reg == "RAX" || reg == "EAX" || reg == "AX" || reg == "AL") return 0;
        if (reg == "RCX" || reg == "ECX" || reg == "CX" || reg == "CL") return 1;
        if (reg == "RDX" || reg == "EDX" || reg == "DX" || reg == "DL") return 2;
        if (reg == "RBX" || reg == "EBX" || reg == "BX" || reg == "BL") return 3;
        if (reg == "RSP" || reg == "ESP" || reg == "SP") return 4;
        if (reg == "RBP" || reg == "EBP" || reg == "BP") return 5;
        if (reg == "RSI" || reg == "ESI" || reg == "SI") return 6;
        if (reg == "RDI" || reg == "EDI" || reg == "DI") return 7;
        if (reg == "R8" || reg == "R8D" || reg == "R8W" || reg == "R8B") return 8;
        if (reg == "R9" || reg == "R9D") return 9;
        if (reg == "R10" || reg == "R10D") return 10;
        if (reg == "R11" || reg == "R11D") return 11;
        if (reg == "R12" || reg == "R12D") return 12;
        if (reg == "R13" || reg == "R13D") return 13;
        if (reg == "R14" || reg == "R14D") return 14;
        if (reg == "R15" || reg == "R15D") return 15;
        return -1;
    };

    auto is_reg64 = [](const std::string& reg) -> bool {
        return reg.size() >= 2 && (reg[0] == 'R' || (reg[0] == 'R' && std::isdigit(reg[1])));
    };


    std::istringstream stream(assembly_text);
    std::string line;
    int line_num = 0;
    std::uint64_t current_addr = address;

    while (std::getline(stream, line))
    {
        ++line_num;
        line = trim(line);
        if (line.empty() || line[0] == ';') continue;


        auto semi_pos = line.find(';');
        if (semi_pos != std::string::npos)
            line = trim(line.substr(0, semi_pos));

        std::string upper = to_upper(line);

        if (upper == "NOP")
        {
            output.push_back(0x90);
        }
        else if (upper == "RET" || upper == "RETN")
        {
            output.push_back(0xC3);
        }
        else if (upper == "INT3" || upper == "INT 3")
        {
            output.push_back(0xCC);
        }
        else if (upper.substr(0, 4) == "PUSH")
        {
            std::string operand = trim(upper.substr(4));
            int idx = reg_to_idx(operand);
            if (idx < 0) { error_msg = "Unknown register in PUSH at line " + std::to_string(line_num); break; }
            if (idx >= 8) { output.push_back(0x41); idx -= 8; }
            output.push_back(static_cast<std::uint8_t>(0x50 + idx));
        }
        else if (upper.substr(0, 3) == "POP")
        {
            std::string operand = trim(upper.substr(3));
            int idx = reg_to_idx(operand);
            if (idx < 0) { error_msg = "Unknown register in POP at line " + std::to_string(line_num); break; }
            if (idx >= 8) { output.push_back(0x41); idx -= 8; }
            output.push_back(static_cast<std::uint8_t>(0x58 + idx));
        }
        else if (upper.substr(0, 3) == "XOR")
        {

            auto comma = upper.find(',');
            if (comma == std::string::npos) { error_msg = "Invalid XOR at line " + std::to_string(line_num); break; }
            std::string op1 = trim(upper.substr(3, comma - 3));
            std::string op2 = trim(upper.substr(comma + 1));
            int r1 = reg_to_idx(op1), r2 = reg_to_idx(op2);
            if (r1 < 0 || r2 < 0) { error_msg = "Unknown register in XOR at line " + std::to_string(line_num); break; }

            if (is_reg64(op1))
            {
                std::uint8_t rex = 0x48;
                if (r1 >= 8) { rex |= 0x04; r1 -= 8; }
                if (r2 >= 8) { rex |= 0x01; r2 -= 8; }
                output.push_back(rex);
            }
            else
            {
                if (r1 >= 8 || r2 >= 8)
                {
                    std::uint8_t rex = 0x40;
                    if (r1 >= 8) { rex |= 0x04; r1 -= 8; }
                    if (r2 >= 8) { rex |= 0x01; r2 -= 8; }
                    output.push_back(rex);
                }
            }
            output.push_back(0x31);
            output.push_back(static_cast<std::uint8_t>(0xC0 | (r1 << 3) | r2));
        }
        else if (upper.substr(0, 3) == "MOV")
        {

            auto comma = upper.find(',');
            if (comma == std::string::npos) { error_msg = "Invalid MOV at line " + std::to_string(line_num); break; }
            std::string dest = trim(upper.substr(3, comma - 3));
            std::string src = trim(upper.substr(comma + 1));
            int rd = reg_to_idx(dest);
            if (rd < 0) { error_msg = "Unknown register in MOV at line " + std::to_string(line_num); break; }


            std::uint64_t imm = 0;
            try {
                if (src.size() > 2 && src[0] == '0' && (src[1] == 'X' || src[1] == 'x'))
                    imm = std::stoull(src.substr(2), nullptr, 16);
                else
                    imm = std::stoull(src, nullptr, 0);
            } catch (...) {
                error_msg = "Invalid immediate in MOV at line " + std::to_string(line_num);
                break;
            }

            if (is_reg64(dest))
            {

                std::uint8_t rex = 0x48;
                int r = rd;
                if (r >= 8) { rex |= 0x01; r -= 8; }
                output.push_back(rex);
                output.push_back(static_cast<std::uint8_t>(0xB8 + r));
                for (int b = 0; b < 8; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
            else
            {

                int r = rd;
                if (r >= 8) { output.push_back(0x41); r -= 8; }
                output.push_back(static_cast<std::uint8_t>(0xB8 + r));
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 3) == "JMP" || upper.substr(0, 4) == "CALL")
        {
            bool is_call = upper[0] == 'C';
            std::string operand = trim(upper.substr(is_call ? 4 : 3));


            int reg = reg_to_idx(operand);
            if (reg >= 0)
            {
                if (reg >= 8)
                {
                    output.push_back(0x41);
                    reg -= 8;
                }
                output.push_back(0xFF);
                output.push_back(static_cast<std::uint8_t>((is_call ? 0xD0 : 0xE0) + reg));
            }
            else
            {

                std::uint64_t target_addr = 0;
                try {
                    if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                        target_addr = std::stoull(operand.substr(2), nullptr, 16);
                    else
                        target_addr = std::stoull(operand, nullptr, 0);
                } catch (...) {
                    error_msg = std::string(is_call ? "CALL" : "JMP") + " invalid operand at line " + std::to_string(line_num);
                    break;
                }

                std::uint64_t next_rip = current_addr + output.size() + 5;
                std::int64_t rel = static_cast<std::int64_t>(target_addr) - static_cast<std::int64_t>(next_rip);
                if (rel < INT32_MIN || rel > INT32_MAX)
                {
                    error_msg = "Relative offset too large for " + std::string(is_call ? "CALL" : "JMP") +
                                " at line " + std::to_string(line_num);
                    break;
                }

                output.push_back(is_call ? 0xE8 : 0xE9);
                std::int32_t rel32 = static_cast<std::int32_t>(rel);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((rel32 >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 7) == "SUB RSP")
        {
            std::string operand = trim(upper.substr(8));
            std::uint32_t imm = 0;
            try {
                if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                    imm = static_cast<std::uint32_t>(std::stoul(operand.substr(2), nullptr, 16));
                else
                    imm = static_cast<std::uint32_t>(std::stoul(operand, nullptr, 0));
            } catch (...) { error_msg = "Invalid immediate in SUB RSP at line " + std::to_string(line_num); break; }

            output.push_back(0x48);
            if (imm <= 0x7F) {
                output.push_back(0x83);
                output.push_back(0xEC);
                output.push_back(static_cast<std::uint8_t>(imm));
            } else {
                output.push_back(0x81);
                output.push_back(0xEC);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else if (upper.substr(0, 7) == "ADD RSP")
        {
            std::string operand = trim(upper.substr(8));
            std::uint32_t imm = 0;
            try {
                if (operand.size() > 2 && operand[0] == '0' && (operand[1] == 'X' || operand[1] == 'x'))
                    imm = static_cast<std::uint32_t>(std::stoul(operand.substr(2), nullptr, 16));
                else
                    imm = static_cast<std::uint32_t>(std::stoul(operand, nullptr, 0));
            } catch (...) { error_msg = "Invalid immediate in ADD RSP at line " + std::to_string(line_num); break; }

            output.push_back(0x48);
            if (imm <= 0x7F) {
                output.push_back(0x83);
                output.push_back(0xC4);
                output.push_back(static_cast<std::uint8_t>(imm));
            } else {
                output.push_back(0x81);
                output.push_back(0xC4);
                for (int b = 0; b < 4; ++b)
                    output.push_back(static_cast<std::uint8_t>((imm >> (b * 8)) & 0xFF));
            }
        }
        else
        {
            error_msg = "Unsupported instruction at line " + std::to_string(line_num) + ": " + line +
                        ". Supported: NOP, RET, INT3, PUSH, POP, XOR, MOV, JMP, CALL, SUB RSP, ADD RSP.";
            break;
        }
    }

    if (!error_msg.empty())
        return tool_result_t::error(error_msg);

    if (output.empty())
        return tool_result_t::error(OBFSTR("No instructions assembled"));


    std::ostringstream hex_ss;
    for (std::size_t i = 0; i < output.size(); ++i)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(output[i]);
    }

    json result;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["size"] = output.size();
    result["hex"] = hex_ss.str();
    result["bytes"] = json::array();
    for (auto b : output) result["bytes"].push_back(b);


    if (params.contains("write_to"))
    {
        auto write_addr = sa_parse_address(params["write_to"].get<std::string>());
        if (write_addr && device->is_connected() && device->get_process_id() != 0)
        {

            std::size_t written = device->write_raw(*write_addr, output.data(), output.size());
            result["written_to"] = sa_format_address(static_cast<uint64_t>(*write_addr));
            result["bytes_written"] = written;
        }
    }

    return tool_result_t::ok(std::to_string(output.size()) + OBFSTR(" bytes assembled"), result);
}


static std::map<std::string, std::vector<std::uint8_t>> s_memory_snapshots;
static std::mutex s_snapshot_mutex;


tool_result_t driver_find_references(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_find_references entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::string target_str = params.value("target_address", "");
    if (target_str.empty())
        return tool_result_t::error(OBFSTR("Missing required parameter: target_address"));

    auto target_opt = sa_parse_address(target_str);
    if (!target_opt) return tool_result_t::error(OBFSTR("Invalid target_address"));

    const std::uint64_t target = *target_opt;
    const int limit = std::min(params.value("limit", 100), 5000);
    const bool scan_code = params.value("scan_code", true);
    const bool scan_data = params.value("scan_data", true);


    std::uint8_t target_bytes[8];
    std::memcpy(target_bytes, &target, 8);

    auto regions = enumerate_all_memory_regions_paginated(
        device.get(), 0x10000, 0x7FFFFFFFFFFF, false);

    json refs = json::array();
    int found = 0;

    for (const auto& region : regions)
    {
        if (found >= limit) break;
        if (region.size == 0 || region.size > 0x10000000) continue;
        if ((region.state & 0x1000) == 0) continue;
        if ((region.protect & 0x01) || (region.protect & 0x100)) continue;

        bool is_exec = (region.protect & 0x10) || (region.protect & 0x20) ||
                       (region.protect & 0x40) || (region.protect & 0x80);

        if (is_exec && !scan_code) continue;
        if (!is_exec && !scan_data) continue;

        constexpr std::size_t CHUNK = 0x10000;
        for (std::uint64_t off3 = 0; off3 < region.size && found < limit; off3 += CHUNK)
        {
            const std::size_t to_read = std::min<std::size_t>(CHUNK, region.size - off3);
            if (to_read < 8) continue;

            std::vector<std::uint8_t> buf(to_read);
            if (device->read_raw(region.base + off3, buf.data(), to_read) == 0)
                continue;


            for (std::size_t i = 0; i + 8 <= to_read && found < limit; ++i)
            {
                if (std::memcmp(&buf[i], target_bytes, 8) == 0)
                {
                    json ref;
                    ref["address"] = sa_format_address(static_cast<uint64_t>(region.base + off3 + i));
                    ref["type"] = is_exec ? "code" : "data";
                    ref["region_base"] = sa_format_address(static_cast<uint64_t>(region.base));
                    ref["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
                    refs.push_back(std::move(ref));
                    ++found;
                }
            }


            if (is_exec && scan_code)
            {
                for (std::size_t i = 0; i + 4 <= to_read && found < limit; ++i)
                {
                    std::int32_t rel32;
                    std::memcpy(&rel32, &buf[i], 4);
                    std::uint64_t effective = region.base + off3 + i + 4 + rel32;
                    if (effective == target)
                    {

                        if (i >= 1)
                        {
                            std::uint8_t prev = buf[i - 1];

                            if (prev == 0x8D || prev == 0x8B || prev == 0x05 || prev == 0x0D ||
                                prev == 0x15 || prev == 0x1D || prev == 0x25 || prev == 0x2D ||
                                prev == 0x35 || prev == 0x3D)
                            {
                                json ref;
                                ref["address"] = sa_format_address(
                                    static_cast<uint64_t>(region.base + off3 + i - 1));
                                ref["type"] = "rip_relative";
                                ref["displacement"] = rel32;
                                refs.push_back(std::move(ref));
                                ++found;
                            }
                        }
                    }
                }
            }
        }
    }

    json result;
    result["target_address"] = sa_format_address(static_cast<uint64_t>(target));
    result["references_found"] = found;
    result["references"] = std::move(refs);
    return tool_result_t::ok(std::to_string(found) + OBFSTR(" references to ") +
                             sa_format_address(static_cast<uint64_t>(target)), result);
}

tool_result_t driver_read_teb(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_read_teb entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Missing or invalid tid parameter."));

    const std::uint32_t tid = *tid_opt;

    driver_bridge::thread_context_t ctx{};
    if (!driver_bridge::get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));

    std::uint64_t teb_addr = 0;
    std::string teb_source;
    std::string teb_error;
    if (!resolve_teb_address_for_thread(tid, ctx, teb_addr, teb_source, teb_error))
        return tool_result_t::error(OBFSTR("TEB address unavailable for TID ") +
                                    std::to_string(tid) + OBFSTR(": ") + teb_error);


    json teb;
    teb["teb_address"] = sa_format_address(static_cast<uint64_t>(teb_addr));
    teb["thread_id"] = tid;
    teb["teb_source"] = teb_source;


    teb["exception_list"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x00)));
    teb["stack_base"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x08)));
    teb["stack_limit"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x10)));
    teb["sub_system_tib"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x18)));
    teb["fiber_data"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x20)));
    teb["arbitrary_user_pointer"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x28)));
    teb["self"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x30)));


    teb["environment_pointer"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x38)));
    teb["client_id_process"] = device->read<std::uint64_t>(teb_addr + 0x40);
    teb["client_id_thread"] = device->read<std::uint64_t>(teb_addr + 0x48);
    teb["active_rpc_handle"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x50)));
    teb["tls_pointer"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x58)));
    teb["peb_address"] = sa_format_address(static_cast<uint64_t>(device->read<std::uint64_t>(teb_addr + 0x60)));
    teb["last_error_value"] = device->read<std::uint32_t>(teb_addr + 0x68);
    teb["count_of_owned_critical_sections"] = device->read<std::uint32_t>(teb_addr + 0x6C);


    json tls_slots = json::array();
    for (int i = 0; i < 64; ++i)
    {
        std::uint64_t slot_val = device->read<std::uint64_t>(teb_addr + 0x1480 + i * 8);
        if (slot_val != 0)
        {
            json slot;
            slot["index"] = i;
            slot["value"] = sa_format_address(static_cast<uint64_t>(slot_val));
            tls_slots.push_back(std::move(slot));
        }
    }
    teb["active_tls_slots"] = std::move(tls_slots);


    std::uint64_t dealloc_stack = device->read<std::uint64_t>(teb_addr + 0x1478);
    teb["deallocation_stack"] = sa_format_address(static_cast<uint64_t>(dealloc_stack));


    std::uint64_t stack_base_val = device->read<std::uint64_t>(teb_addr + 0x08);
    std::uint64_t stack_limit_val = device->read<std::uint64_t>(teb_addr + 0x10);
    if (stack_base_val > stack_limit_val)
        teb["stack_size"] = stack_base_val - stack_limit_val;

    json result;
    result["teb"] = std::move(teb);
    return tool_result_t::ok(OBFSTR("TEB read for TID ") + std::to_string(tid), result);
}

tool_result_t driver_map_peb_modules(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_map_peb_modules entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::string order = params.value("order", "all");
    const std::string filter = to_lower_ascii_copy(params.value("filter", ""));

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return tool_result_t::error(OBFSTR("Failed to read PEB or LDR address is null"));


    struct ldr_entry_offsets_t {
        std::uint64_t list_head_offset;
        std::uint64_t base_dll_field_offset;
        std::string name;
    };

    std::vector<ldr_entry_offsets_t> lists_to_walk;

    if (order == "load" || order == "all")
        lists_to_walk.push_back({0x10, 0x30, "InLoadOrder"});
    if (order == "memory" || order == "all")
        lists_to_walk.push_back({0x20, 0x20, "InMemoryOrder"});
    if (order == "init" || order == "all")
        lists_to_walk.push_back({0x30, 0x10, "InInitializationOrder"});

    json all_lists;

    for (const auto& list_info : lists_to_walk)
    {
        const std::uint64_t list_head = peb.ldr_address + list_info.list_head_offset;
        std::uint64_t current = device->read<std::uint64_t>(list_head);

        json modules_arr = json::array();
        int iter = 0;
        constexpr int MAX_ITER = 1024;

        while (current != 0 && current != list_head && iter++ < MAX_ITER)
        {


            std::uint64_t ldr_entry;
            if (list_info.list_head_offset == 0x10)
                ldr_entry = current;
            else if (list_info.list_head_offset == 0x20)
                ldr_entry = current - 0x10;
            else
                ldr_entry = current - 0x20;

            const std::uint64_t base = device->read<std::uint64_t>(ldr_entry + 0x30);
            const std::uint64_t entry_point = device->read<std::uint64_t>(ldr_entry + 0x38);
            const std::uint32_t size = device->read<std::uint32_t>(ldr_entry + 0x40);

            const std::string name = read_remote_unicode_ascii(device.get(),
                device->read<std::uint64_t>(ldr_entry + 0x60),
                device->read<std::uint16_t>(ldr_entry + 0x58), 520);

            const std::string path = read_remote_unicode_ascii(device.get(),
                device->read<std::uint64_t>(ldr_entry + 0x50),
                device->read<std::uint16_t>(ldr_entry + 0x48), 1024);

            const std::uint32_t flags = device->read<std::uint32_t>(ldr_entry + 0x68);
            const std::uint16_t load_count = device->read<std::uint16_t>(ldr_entry + 0x70);
            const std::uint16_t tls_index = device->read<std::uint16_t>(ldr_entry + 0x72);

            if (base == 0 && name.empty())
            {
                std::uint64_t next = device->read<std::uint64_t>(current);
                if (next == current) break;
                current = next;
                continue;
            }

            if (!filter.empty())
            {
                std::string lower_name = to_lower_ascii_copy(name);
                std::string lower_path = to_lower_ascii_copy(path);
                if (lower_name.find(filter) == std::string::npos &&
                    lower_path.find(filter) == std::string::npos)
                {
                    std::uint64_t next = device->read<std::uint64_t>(current);
                    if (next == current) break;
                    current = next;
                    continue;
                }
            }

            json mod;
            mod["order_index"] = iter - 1;
            mod["base_address"] = sa_format_address(static_cast<uint64_t>(base));
            mod["entry_point"] = sa_format_address(static_cast<uint64_t>(entry_point));
            mod["size"] = size;
            mod["name"] = name;
            mod["full_path"] = path;
            mod["flags"] = sa_format_address(static_cast<uint64_t>(flags));
            mod["load_count"] = load_count;
            mod["tls_index"] = tls_index;


            json flag_details;
            flag_details["packed_redirected"] = (flags & 0x00000002) != 0;
            flag_details["static_import"] = (flags & 0x00000020) != 0;
            flag_details["image_dll"] = (flags & 0x00000004) != 0;
            flag_details["load_in_progress"] = (flags & 0x00001000) != 0;
            flag_details["entry_processed"] = (flags & 0x00004000) != 0;
            flag_details["dont_call_for_threads"] = (flags & 0x00040000) != 0;
            flag_details["process_attach_called"] = (flags & 0x00080000) != 0;
            mod["flag_details"] = std::move(flag_details);

            modules_arr.push_back(std::move(mod));

            std::uint64_t next = device->read<std::uint64_t>(current);
            if (next == current) break;
            current = next;
        }

        all_lists[list_info.name] = std::move(modules_arr);
    }

    json result;
    result["peb_address"] = sa_format_address(static_cast<uint64_t>(peb.peb_address));
    result["ldr_address"] = sa_format_address(static_cast<uint64_t>(peb.ldr_address));
    result["image_base"] = sa_format_address(static_cast<uint64_t>(peb.image_base));
    result["lists"] = std::move(all_lists);
    if (!filter.empty()) result["filter"] = filter;
    return tool_result_t::ok(OBFSTR("PEB LDR module lists enumerated"), result);
}

tool_result_t driver_set_page_guard(const json& params)
{
    diag::log_tagged_fmt("drv_tools", "driver_set_page_guard entry");
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::string operation = params.value("operation", "set");

    if (!params.contains("address"))
        return tool_result_t::error(OBFSTR("Missing required parameter: address"));

    auto addr_opt = sa_parse_address(params["address"].get<std::string>());
    if (!addr_opt) return tool_result_t::error(OBFSTR("Invalid address"));

    const std::uint64_t target_addr = *addr_opt;
    const std::size_t size = params.value("size", 4096);


    if (operation == "set")
    {

        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(OBFSTR("Failed to query memory at ") +
                                        sa_format_address(static_cast<uint64_t>(target_addr)));

        std::uint32_t current_protect = region.protect;
        std::uint32_t new_protect = current_protect | 0x100;

        std::uint32_t old_protect = 0;
        if (!device->protect_memory(target_addr, size, new_protect, &old_protect))
            return tool_result_t::error(OBFSTR("Failed to set PAGE_GUARD at ") +
                                        sa_format_address(static_cast<uint64_t>(target_addr)));

        json result;
        result["operation"] = "set";
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["size"] = size;
        result["old_protection"] = sa_format_address(static_cast<uint64_t>(old_protect));
        result["new_protection"] = sa_format_address(static_cast<uint64_t>(new_protect));
        result["note"] = OBFSTR("PAGE_GUARD set. Next access triggers STATUS_GUARD_PAGE_VIOLATION (0x80000001). "
                                "Guard is automatically cleared after first hit. Re-apply as needed.");
        return tool_result_t::ok(OBFSTR("PAGE_GUARD set at ") +
                                 sa_format_address(static_cast<uint64_t>(target_addr)), result);
    }
    else if (operation == "remove")
    {
        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(OBFSTR("Failed to query memory"));

        std::uint32_t new_protect = region.protect & ~0x100u;
        std::uint32_t old_protect = 0;
        if (!device->protect_memory(target_addr, size, new_protect, &old_protect))
            return tool_result_t::error(OBFSTR("Failed to remove PAGE_GUARD"));

        json result;
        result["operation"] = "remove";
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["old_protection"] = sa_format_address(static_cast<uint64_t>(old_protect));
        result["new_protection"] = sa_format_address(static_cast<uint64_t>(new_protect));
        return tool_result_t::ok(OBFSTR("PAGE_GUARD removed at ") +
                                 sa_format_address(static_cast<uint64_t>(target_addr)), result);
    }
    else if (operation == "query")
    {
        voyager::device_t::memory_region_info region{};
        if (!device->query_memory(target_addr, region))
            return tool_result_t::error(OBFSTR("Failed to query memory"));

        json result;
        result["address"] = sa_format_address(static_cast<uint64_t>(target_addr));
        result["base_address"] = sa_format_address(static_cast<uint64_t>(region.base));
        result["region_size"] = region.size;
        result["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
        result["has_guard"] = (region.protect & 0x100) != 0;
        result["state"] = sa_format_address(static_cast<uint64_t>(region.state));
        return tool_result_t::ok(
            (region.protect & 0x100) ? OBFSTR("PAGE_GUARD is active") : OBFSTR("PAGE_GUARD is not set"),
            result);
    }

    return tool_result_t::error(OBFSTR("Invalid operation. Use 'set', 'remove', or 'query'."));
}


void register_driver_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged_fmt("drv_tools", "register_driver_tools entry");
    s_deferred_tool_list = &srv.get_tools();







    register_compat(srv, {
        OBFSTR("driver_dump_module"), OBFSTR("driver"),
         OBFSTR("Dump a module from the target process using kernel memory reads. "
             "Captures the module exactly as it exists in runtime memory without decryption, "
             "devirtualization, header reconstruction, or import rebuilding. "
             "Can resolve a loaded sub-module by name or path via the 'module' parameter. "
             "Creates IDA segments and patches dumped bytes into the database. "
               "Can auto-connect to a process by name via the 'process' parameter."),
        {{OBFSTR("process"), OBFSTR("string"),
          OBFSTR("Target process name to auto-connect (e.g. 'game.exe'). "
                 "If omitted, uses currently attached process."), false},
          {OBFSTR("module"), OBFSTR("string"),
           OBFSTR("Loaded module name or full/partial path to dump (e.g. 'steam_api64.dll'). "
               "If omitted, dumps the main image unless 'address' is provided."), false},
         {OBFSTR("address"), OBFSTR("string"),
           OBFSTR("Explicit module base address (overrides automatic module resolution)"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Override image size in bytes (default: auto from PE header)"), false},
         {OBFSTR("output_path"), OBFSTR("string"), OBFSTR("Save dump to file path (e.g. 'C:\\\\dump.bin')"), false},
          {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Patch dumped runtime bytes into IDA database (default true)"), false}},
        driver_dump_module, false});



    register_compat(srv, {
        OBFSTR("driver_read_pointer_chain"), OBFSTR("driver"),
        OBFSTR("Follow a chain of pointer dereferences through target process memory via kernel driver. "
               "Useful for traversing linked lists, object hierarchies, and obfuscated data structures."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Starting virtual address"), false},
          {OBFSTR("base_address"), OBFSTR("string"), OBFSTR("Alias for address."), false},
         {OBFSTR("offsets"), OBFSTR("array"),
          OBFSTR("Array of byte offsets to apply after each dereference (e.g. [0, 48, 24])"), false, {},
           json::object({{"type", "number"}})},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_read_pointer_chain, false});


    register_compat(srv, {
        OBFSTR("driver_enumerate_kernel_modules"), OBFSTR("driver"),
        OBFSTR("Enumerate ALL loaded kernel drivers and modules via NtQuerySystemInformation. "
               "Returns each driver's name, NT path, resolved disk path, kernel base address, "
               "and image size. Does NOT require the kernel driver to be connected - works "
               "purely from usermode. Use filter to search for a specific driver "
               "(e.g. filter='EasyAntiCheat' or filter='eac')."),
        {{OBFSTR("filter"), OBFSTR("string"),
          OBFSTR("Case-insensitive substring filter applied to module name and path (e.g. 'eac', 'ntfs')"), false},
         {OBFSTR("limit"), OBFSTR("number"),
          OBFSTR("Maximum number of modules to return (default 500)"), false}},
        driver_enumerate_kernel_modules, false});




    register_compat(srv, {
        OBFSTR("driver_allocate_memory"), OBFSTR("driver"),
        OBFSTR("Allocate RWX memory in the attached target process. "
               "Uses kernel-level ZwAllocateVirtualMemory with PAGE_EXECUTE_READWRITE. "
               "Max 16MB per allocation. Useful for injecting shellcode, writing strings "
               "for function arguments, or setting up data structures remotely. "
               "Requires driver connected and process attached."),
        {{OBFSTR("size"), OBFSTR("string"),
                    OBFSTR("Number of bytes to allocate (max 16777216 = 16MB)"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_allocate_memory, false});

    register_compat(srv, {
        OBFSTR("driver_free_memory"), OBFSTR("driver"),
        OBFSTR("Free previously allocated memory in the attached target process. "
               "Uses kernel-level ZwFreeVirtualMemory with MEM_RELEASE. "
               "Requires driver connected and process attached."),
        {{OBFSTR("address"), OBFSTR("string"),
                    OBFSTR("Address of the memory block to free (hex string like '0x...')"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_free_memory, false});

    register_compat(srv, {
        OBFSTR("driver_call_function"), OBFSTR("driver"),
        OBFSTR("Execute ANY function inside the attached target process via thread hijack. "
               "Suspends a target thread, redirects execution to injected shellcode that calls "
               "the specified function with up to 4 arguments, polls for completion, restores "
               "original thread context. Call stack is spoofed via JMP-RBX gadget. "
               "WARNING: Calling incorrect addresses or wrong arguments can crash the process. "
               "Common patterns: call LoadLibraryA to load DLLs, call LdrGetProcedureAddress "
               "to resolve exports, call VirtualProtect to change protections, call any "
               "game/anticheat function to observe behavior. "
                             "Requires driver connected, process attached, DTB solved. "
                             "For safety, execution requires confirm_unsafe=true unless dry_run=true."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the function to call in the target process (hex)"), true},
         {OBFSTR("arg1"), OBFSTR("string"),
          OBFSTR("First argument (RCX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg2"), OBFSTR("string"),
          OBFSTR("Second argument (RDX). Hex address or integer. Default 0"), false},
         {OBFSTR("arg3"), OBFSTR("string"),
          OBFSTR("Third argument (R8). Hex address or integer. Default 0"), false},
         {OBFSTR("arg4"), OBFSTR("string"),
                    OBFSTR("Fourth argument (R9). Hex address or integer. Default 0"), false},
                 {OBFSTR("confirm_unsafe"), OBFSTR("boolean"), OBFSTR("Required for live execution. Must be true unless dry_run=true."), false},
         {OBFSTR("allow_unsafe"), OBFSTR("boolean"), OBFSTR("Alias of confirm_unsafe."), false},
         {OBFSTR("unsafe"), OBFSTR("boolean"), OBFSTR("Alias of confirm_unsafe."), false},
                 {OBFSTR("dry_run"), OBFSTR("boolean"), OBFSTR("Preview call metadata without executing."), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_call_function, false});








    register_compat(srv, {
        OBFSTR("driver_protect_memory"), OBFSTR("driver"),
        OBFSTR("Change virtual memory protection in the attached process via kernel ZwProtectVirtualMemory. "
               "Bypasses usermode hooks on VirtualProtect. Can set any protection including executable. "
               "Returns the old protection value."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address"), true},
         {OBFSTR("size"), OBFSTR("string"), OBFSTR("Region size (default 0x1000)"), false},
         {OBFSTR("protect"), OBFSTR("string"),
          OBFSTR("New protection value: 0x40=PAGE_EXECUTE_READWRITE, 0x20=PAGE_EXECUTE_READ, "
             "0x04=PAGE_READWRITE, 0x02=PAGE_READONLY"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_protect_memory, false});


    register_compat(srv, {
        OBFSTR("driver_read_peb"), OBFSTR("driver"),
        OBFSTR("Read the Process Environment Block (PEB) of the attached process via kernel. "
               "Returns PEB address, image base, BeingDebugged flag, NtGlobalFlag, "
               "loader data address, process heap, and heap info."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}}, driver_read_peb, true});


    register_compat(srv, {
        OBFSTR("driver_set_hw_breakpoint"), OBFSTR("driver"),
        OBFSTR("Set a hardware breakpoint on a thread in the attached process using debug registers. "
               "Uses DR0-DR3 (4 breakpoints max per thread). Operates via kernel PsSetContextThread "
               "so it's invisible to usermode anti-debug. Types: execute (break on execution), "
               "write (break on memory write), readwrite (break on read or write). "
               "After setting, the thread will trigger a SINGLE_STEP exception when the breakpoint fires."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Address to break on"), true},
         {OBFSTR("index"), OBFSTR("number"),
          OBFSTR("Debug register index 0-3 (default 0). Each thread supports 4 HW breakpoints."), false},
         {OBFSTR("type"), OBFSTR("string"),
          OBFSTR("Breakpoint type: execute (default), write, readwrite"), false,
          {OBFSTR("execute"), OBFSTR("write"), OBFSTR("readwrite")}},
         {OBFSTR("size"), OBFSTR("number"),
                    OBFSTR("Watched region size in bytes: 1 (default), 2, 4, or 8"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_set_hw_breakpoint, false});

    register_compat(srv, {
        OBFSTR("driver_clear_hw_breakpoint"), OBFSTR("driver"),
        OBFSTR("Clear a hardware breakpoint on a thread. Removes the address from the specified "
               "debug register and disables it in DR7."),
                {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("index"), OBFSTR("number"),
                    OBFSTR("Debug register index 0-3 to clear (default 0)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_clear_hw_breakpoint, false});

    register_compat(srv, {
        OBFSTR("driver_resolve_export"), OBFSTR("driver"),
        OBFSTR("Resolve an export function address from a PE module in the attached process. "
               "Walks the PE export directory via physical memory reads. Useful for finding API "
               "addresses without relying on import tables (which may be obfuscated by packers)."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Export function name to resolve. Alias: export_name."), false},
          {OBFSTR("export_name"), OBFSTR("string"), OBFSTR("Alias for name."), false},
         {OBFSTR("module_base"), OBFSTR("string"),
           OBFSTR("Module base address (default: attached process image base)"), false},
          {OBFSTR("module"), OBFSTR("string"), OBFSTR("Module name/path or base address string. Alias: module_name."), false},
          {OBFSTR("module_name"), OBFSTR("string"), OBFSTR("Alias for module."), false},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override (alias: target_pid). When set, the bridge's active PID is swapped to this for the duration of the call. The PID must be alive; if it is not in the attached set the bridge will open a handle automatically."), false}},
        driver_resolve_export, true});

    register_compat(srv, {
        OBFSTR("driver_virtual_to_physical"), OBFSTR("driver"),
        OBFSTR("Translate a virtual address to its physical address using the process DTB. "
               "Performs a full 4-level page table walk (PML4->PDPT->PD->PT) in kernel."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address to translate"), true}},
        driver_virtual_to_physical, true});


    register_compat(srv, {
        OBFSTR("driver_defer_action"), OBFSTR("driver"),
        OBFSTR("PRE-SCHEDULE driver tool calls to execute THE INSTANT a kernel module loads "
               "or a process starts. This solves the critical timing problem: many drivers "
               "(EAC, BattlEye, Vanguard) wipe their IAT, decrypt code, or perform anti-RE "
               "operations during initialization. By the time you can manually react, the "
               "evidence is already destroyed. This tool lets you queue actions (read memory, "
               "set HW breakpoints, dump module, etc.) that fire IMMEDIATELY when the target "
               "appears - before its init routine runs. "
               "\n\nTemplate parameters in action params are resolved at trigger time:\n"
               "  ${module_base} - runtime kernel base address of the loaded module\n"
               "  ${module_size} - module image size\n"
               "  ${module_name} - resolved module filename\n"
               "  ${pid} - process ID (for process_start)\n"
               "  ${base_address} - process image base (for process_start)\n"
               "\nAddress arithmetic: '${module_base}+0x17C000' computes base+offset automatically.\n"
               "\nExample: to capture EAC's IAT before it's wiped:\n"
               "  wait_for='kernel_module_load', target='EasyAntiCheat_EOS.sys',\n"
               "  actions=[{tool:'driver_read_kernel_memory', params:{address:'${module_base}+0x17C000', size:64}}]"),
        {{OBFSTR("wait_for"), OBFSTR("string"),
          OBFSTR("Condition type: 'kernel_module_load' or 'process_start'"), true, {},
          {OBFSTR("kernel_module_load"), OBFSTR("process_start")}},
         {OBFSTR("target"), OBFSTR("string"),
          OBFSTR("Module or process name to watch for (case-insensitive substring match). "
                 "E.g. 'EasyAntiCheat_EOS.sys', 'BEService.exe'"), true},
         {OBFSTR("actions"), OBFSTR("array"),
          OBFSTR("Array of tool calls to execute when condition is met. "
                 "Each entry: {\"tool\": \"tool_name\", \"params\": {...}}. "
                 "Compatibility aliases accepted: top-level {action, params} and per-entry {action, params}. "
             "Params may use ${module_base}, ${module_size}, ${pid}, ${base_address} templates."), false, {},
          json::object({{"type", "object"},
                        {"properties", json::object({
                            {"tool", json::object({{"type", "string"}})},
                            {"action", json::object({{"type", "string"}})},
                            {"params", json::object({{"type", "object"}})}
                        })}
          })},
         {OBFSTR("timeout"), OBFSTR("number"),
          OBFSTR("Maximum seconds to wait for the condition (default 300 = 5 minutes)"), false},
         {OBFSTR("poll_interval"), OBFSTR("number"),
          OBFSTR("Milliseconds between condition checks (default 50ms). Lower = faster reaction "
                 "but more CPU. For IAT capture, use 10-25ms."), false}},
        driver_defer_action, false});

    register_compat(srv, {
        OBFSTR("driver_list_deferred_actions"), OBFSTR("driver"),
        OBFSTR("List all registered deferred actions and their current status "
               "(pending, watching, triggered, completed, failed, cancelled, timed_out). "
               "Shows condition, target, number of queued actions, trigger info, and result counts."),
        {},
        driver_list_deferred_actions, false});

    register_compat(srv, {
        OBFSTR("driver_cancel_deferred_action"), OBFSTR("driver"),
        OBFSTR("Cancel a pending/watching deferred action by its action_id. "
               "Only works if the action hasn't been triggered yet."),
        {{OBFSTR("action_id"), OBFSTR("number"),
          OBFSTR("The action ID returned by driver_defer_action"), true}},
        driver_cancel_deferred_action, false});

    register_compat(srv, {
        OBFSTR("driver_get_deferred_results"), OBFSTR("driver"),
        OBFSTR("Get the detailed results of a deferred action after it has been triggered. "
               "Returns the trigger context (module base, PID, etc.), the status of each "
               "queued tool call (success/failure, output data), and timing information. "
               "Use this to retrieve data captured by pre-scheduled actions."),
        {{OBFSTR("action_id"), OBFSTR("number"),
          OBFSTR("The action ID returned by driver_defer_action"), true}},
        driver_get_deferred_results, false});




    register_compat(srv, {
        OBFSTR("driver_sniff_network_buffers"), OBFSTR("driver"),
        OBFSTR("Manage a kernel-level network buffer sniff session that works with hardware breakpoints to "
               "capture plaintext network buffers in memory BEFORE encryption. Wireshark only sees encrypted "
               "payloads; this tool captures the data before it reaches ws2_32.dll!send, "
               "afd.sys!AfdFastIoDeviceControl, or a custom game/malware encryption function.\n\n"
               "Workflow:\n"
               "1. Call with address + buffer_register + size_register to START session\n"
               "2. Set HW breakpoint on the address via driver_set_hw_breakpoint\n"
               "3. When BP fires, read thread context, read buffer from memory, call with operation='store'\n"
               "4. Call with operation='get' to retrieve all captured buffers\n"
               "5. Call with operation='stop' when done\n\n"
               "This is a composite tool that coordinates with driver_set_hw_breakpoint and read_memory."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the send/recv/encrypt function (for 'start' operation)"), false},
         {OBFSTR("buffer_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer pointer (e.g., 'rcx', 'rdx', 'r8')"), false},
         {OBFSTR("size_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer size (e.g., 'rdx', 'r8', 'r9')"), false},
         {OBFSTR("max_packets"), OBFSTR("number"),
          OBFSTR("Max captures before auto-stop (default 1, max 16)"), false},
         {OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'start' (default), 'store', 'get'/'results', 'stop'"), false, {},
          {OBFSTR("start"), OBFSTR("store"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("results")}},
         {OBFSTR("bytes"), OBFSTR("string"),
          OBFSTR("Capture bytes for operation='store' as hex bytes, hex string, or text"), false},
         {OBFSTR("data"), OBFSTR("string"),
          OBFSTR("Alias for bytes when operation='store'"), false},
         {OBFSTR("hex"), OBFSTR("string"),
          OBFSTR("Alias for bytes when operation='store'"), false},
         {OBFSTR("timestamp"), OBFSTR("number"),
          OBFSTR("Capture timestamp for operation='store' (defaults to GetTickCount64)"), false},
         {OBFSTR("thread_id"), OBFSTR("number"),
          OBFSTR("Capture thread id for operation='store' (defaults to current thread)"), false},
         {OBFSTR("tid"), OBFSTR("number"),
          OBFSTR("Thread ID for breakpoint (default: 0 = first thread)"), false},
         {OBFSTR("bp_index"), OBFSTR("number"),
          OBFSTR("Debug register index 0-3 (default: 0)"), false}},
        driver_sniff_network_buffers, false});






    register_compat(srv, {
        OBFSTR("driver_reassemble_stream"), OBFSTR("driver"),
        OBFSTR("TCP stream reassembly engine. Like Wireshark's 'Follow TCP Stream' but from the kernel. "
               "Tracks TCP connections and reassembles the byte stream in order. Supports up to 8 "
               "concurrent streams, 64KB each. Operations: start, stop, get_data, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', 'get'/'get_data', 'list', 'clear'"), false,
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("get_data"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP of the connection to track"), false},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by PID"), false}},
        driver_reassemble_stream, false});









    register_compat(srv, {
        OBFSTR("driver_enum_kernel_callbacks"), OBFSTR("driver"),
        OBFSTR("Enumerate kernel notification callbacks: process creation (PsSetCreateProcessNotifyRoutine), "
               "thread creation (PsSetCreateThreadNotifyRoutine), image load (PsSetLoadImageNotifyRoutine), "
               "registry (CmRegisterCallbackEx), object (ObRegisterCallbacks). Identifies which driver module "
               "registered each callback. Essential for understanding anti-cheat monitoring."),
        {},
        driver_enum_kernel_callbacks, true});

    register_compat(srv, {
        OBFSTR("driver_detect_integrity_checks"), OBFSTR("driver"),
        OBFSTR("Check critical ntoskrnl exports for inline hooks (jmp, mov rax + jmp, int3). "
               "Scans NtReadVirtualMemory, NtWriteVirtualMemory, NtOpenProcess, MmCopyVirtualMemory, "
               "KeStackAttachProcess, and 14 other critical functions. Identifies hook owner module. "
               "Reveals which kernel functions anti-cheats are monitoring."),
        {},
        driver_detect_integrity_checks, true});

    register_compat(srv, {
        OBFSTR("driver_detect_ssdt_hooks"), OBFSTR("driver"),
        OBFSTR("Detect SSDT (System Service Descriptor Table) hooks. Reads KeServiceDescriptorTable, "
               "resolves all syscall function pointers, and identifies entries redirected outside ntoskrnl. "
               "Anti-cheats hook SSDT to intercept NtReadVirtualMemory, NtOpenProcess, etc. "
               "Returns hooked syscall IDs, target addresses, and hook owner modules."),
        {},
        driver_detect_ssdt_hooks, true});

    register_compat(srv, {
        OBFSTR("driver_enum_minifilters"), OBFSTR("driver"),
        OBFSTR("Enumerate registered filesystem minifilter drivers via Filter Manager (fltmgr.sys). "
               "Minifilters intercept file I/O - anti-cheats use them to monitor file access, "
               "prevent memory dumps, and detect injection DLLs. Returns filter names, altitudes, and owner modules."),
        {},
        driver_enum_minifilters, true});

    register_compat(srv, {
        OBFSTR("driver_detect_etw_monitors"), OBFSTR("driver"),
        OBFSTR("Detect active ETW (Event Tracing for Windows) monitoring. Checks if the Threat Intelligence "
               "provider is active (monitors process injection, executable memory allocation). "
               "Scans for known security ETW provider GUIDs and identifies kernel modules that import EtwRegister/EtwWrite."),
        {},
        driver_detect_etw_monitors, true});

    register_compat(srv, {
        OBFSTR("driver_detect_hidden_modules"), OBFSTR("driver"),
        OBFSTR("Detect manually mapped or hidden PE modules not in the PEB module list (usermode) or "
               "NtQuerySystemInformation list (kernel). Scans memory for PE headers at non-listed addresses. "
               "Finds injected DLLs, manual-mapped anti-cheat drivers, and stealth payloads. "
               "Returns hidden module addresses, sizes, and export names when available."),
        {{OBFSTR("kernel"), OBFSTR("boolean"), OBFSTR("Scan kernel space instead of attached process (default: false)"), false}},
        driver_detect_hidden_modules, true});


    register_compat(srv, {
        OBFSTR("driver_walk_heap"), OBFSTR("driver"),
        OBFSTR("Walk the NT heap structures of the attached process via kernel memory reads. "
               "Enumerates all process heaps from PEB.ProcessHeaps, walks segment chains, and lists "
               "heap entries with their addresses, sizes, and busy/free flags. Equivalent to Cheat Engine's "
               "dissect data/structures and x64dbg's heap view. Filter by min/max block size or free-only."),
        {{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max heap entries to return (default 500, max 5000)"), false},
         {OBFSTR("min_size"), OBFSTR("number"), OBFSTR("Only return entries >= this size in bytes"), false},
         {OBFSTR("max_size"), OBFSTR("number"), OBFSTR("Only return entries <= this size in bytes"), false},
         {OBFSTR("free_only"), OBFSTR("boolean"), OBFSTR("Only return free (non-busy) blocks (default false)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_walk_heap, true});

    register_compat(srv, {
        OBFSTR("driver_enumerate_handles"), OBFSTR("driver"),
        OBFSTR("Enumerate kernel object handles system-wide or for a specific process via NtQuerySystemInformation. "
               "Returns handle values, types (Process, Thread, File, Section, Key, Event, Mutant, etc.), "
               "kernel object addresses, and granted access masks. Equivalent to x64dbg's Handles tab "
               "and Process Hacker's handle list. Filter by PID or object type name."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all processes)"), false},
         {OBFSTR("type_filter"), OBFSTR("string"), OBFSTR("Filter by type name substring (e.g. 'Process', 'File')"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max handles to return (default 500, max 10000)"), false}},
        driver_enumerate_handles, true});





    register_compat(srv, {
        OBFSTR("driver_enumerate_windows"), OBFSTR("driver"),
        OBFSTR("List all windows (HWND) owned by a process. Returns window handle, parent, class name, "
               "title text, visibility, position/size rect, and style flags. Equivalent to x64dbg's "
               "Window tab and Spy++ functionality. Useful for finding game overlay windows, "
               "anti-cheat UI, hidden dialogs, and message-only windows."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (default: attached PID)"), false},
         {OBFSTR("include_children"), OBFSTR("boolean"), OBFSTR("Include child windows (default true)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max windows (default 200, max 2000)"), false}},
        driver_enumerate_windows, true});


    register_compat(srv, {
        OBFSTR("driver_assemble"), OBFSTR("driver"),
        OBFSTR("Assemble x86-64 instructions to machine code bytes. Supports common instructions: "
               "NOP, RET, INT3, PUSH/POP reg, MOV reg/imm64, XOR reg/reg, JMP/CALL (reg or address), "
               "SUB RSP/imm, ADD RSP/imm. Multi-line input (one instruction per line). "
               "Optionally writes assembled bytes to target process memory. "
               "Equivalent to x64dbg's built-in assembler and Cheat Engine's auto-assembler."),
        {{OBFSTR("assembly"), OBFSTR("string"), OBFSTR("Assembly text (one instruction per line)"), true},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Base address for relative calculations (default 0x140000000)"), false},
         {OBFSTR("write_to"), OBFSTR("string"), OBFSTR("If specified, write assembled bytes to this address in the attached process"), false}},
        driver_assemble, false});


    register_compat(srv, {
        OBFSTR("driver_find_references"), OBFSTR("driver"),
        OBFSTR("Find all memory locations that reference a target address. Scans for both direct "
               "64-bit pointer matches and RIP-relative (rel32) references in code sections. "
               "Equivalent to x64dbg's 'Find References' and IDA's xrefs but in live runtime memory. "
               "Useful for finding vtable entries, function pointer tables, and cross-references "
               "that only exist at runtime."),
        {{OBFSTR("target_address"), OBFSTR("string"), OBFSTR("Address to find references to (hex)"), true},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max references (default 100, max 5000)"), false},
         {OBFSTR("scan_code"), OBFSTR("boolean"), OBFSTR("Scan executable regions (default true)"), false},
         {OBFSTR("scan_data"), OBFSTR("boolean"), OBFSTR("Scan data regions (default true)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_find_references, true});

    register_compat(srv, {
        OBFSTR("driver_read_teb"), OBFSTR("driver"),
        OBFSTR("Read the Thread Environment Block (TEB) for a thread via kernel driver. "
               "Extracts: NT_TIB (exception list, stack base/limit), TLS slots with values, "
               "PEB address, client ID, last error, critical section count, stack size. "
               "Equivalent to x64dbg's TEB view. Requires tid of the target thread."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_read_teb, true});

    register_compat(srv, {
        OBFSTR("driver_map_peb_modules"), OBFSTR("driver"),
        OBFSTR("Walk ALL three PEB LDR linked lists: InLoadOrder, InMemoryOrder, InInitializationOrder. "
               "Returns complete module details: base, entry point, size, name, full path, flags "
               "(static import, entry processed, process attach called, etc.), load count, TLS index. "
               "Order differences reveal manually mapped modules and load-order anomalies. "
               "More detailed than basic module enumeration - shows all three orderings and decoded flags."),
        {{OBFSTR("order"), OBFSTR("string"), OBFSTR("Which list: load, memory, init, or all (default all)"), false,
          {OBFSTR("load"), OBFSTR("memory"), OBFSTR("init"), OBFSTR("all")}},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Module name/path substring filter (case-insensitive)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_map_peb_modules, true});

    register_compat(srv, {
        OBFSTR("driver_set_page_guard"), OBFSTR("driver"),
        OBFSTR("Set, remove, or query PAGE_GUARD protection on memory in the attached process. "
               "PAGE_GUARD triggers STATUS_GUARD_PAGE_VIOLATION exception on first access - "
               "equivalent to Cheat Engine's memory breakpoint / 'Break on Access'. "
               "The guard auto-clears after first hit. Operations: set, remove, query."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'set', 'remove', or 'query'"), true,
          {OBFSTR("set"), OBFSTR("remove"), OBFSTR("query")}},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Target memory address (hex)"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Size of the guarded region in bytes (default 4096)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_set_page_guard, false});
    diag::log_tagged_fmt("drv_tools", "register_driver_tools done");
}

}
