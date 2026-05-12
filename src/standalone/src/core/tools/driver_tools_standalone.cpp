


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"

#include <Zydis/Zydis.h>
#include "zydis_disasm.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <regex>
#include <unordered_map>
#include <vector>

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
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    std::uint32_t requested_pid = 0;
    if (params.contains("process_id"))
    {
        if (!parse_u32_id_value(params["process_id"], requested_pid))
            return tool_result_t::error(OBFSTR("Invalid process_id. Expected a positive decimal PID or 0x-prefixed hex PID."));
    }
    else if (params.contains("pid"))
    {
        if (!parse_u32_id_value(params["pid"], requested_pid))
            return tool_result_t::error(OBFSTR("Invalid pid. Expected a positive decimal PID or 0x-prefixed hex PID."));
    }

    if (requested_pid != 0 && is_self_target_pid(requested_pid))
        return tool_result_t::error(OBFSTR("Cannot target AiDA's own process."));

    const std::uint32_t current_pid = device->get_process_id();
    if (requested_pid != 0 && requested_pid != current_pid)
    {
        if (!is_process_alive(requested_pid))
            return tool_result_t::error(OBFSTR("process_id ") + std::to_string(requested_pid) + OBFSTR(" is not alive."));

        device->clear_process_context();
        device->set_process_id(requested_pid);
        (void)device->find_image();
        device->solve_dtb();

        if (device->get_dtb() == 0)
        {
            device->clear_process_context();
            return tool_result_t::error(OBFSTR("Failed to solve DTB for process_id ") + std::to_string(requested_pid) + OBFSTR(". Reattach by name with driver_attach."));
        }
    }

    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_attach first or pass process_id."));

    if (!is_process_alive(device->get_process_id()))
    {
        const std::uint32_t dead_pid = device->get_process_id();
        device->clear_process_context();
        return tool_result_t::error(OBFSTR("Attached process PID ") + std::to_string(dead_pid) + OBFSTR(" is no longer alive. Call driver_attach again."));
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

tool_result_t driver_connect(const json& params)
{
    (void)params;
    if (device->is_connected())
    {
        bool cleared_self_target = false;
        if (device->get_process_id() != 0 && is_self_target_pid(device->get_process_id()))
        {
            device->clear_process_context();
            cleared_self_target = true;
        }

        if (device->get_kernel_dtb() == 0)
            device->solve_kernel_dtb();

        if (cleared_self_target)
        {
            json result;
            result["connected"] = true;
            result["process_id"] = device->get_process_id();
            result["kernel_dtb"] = sa_format_address(device->get_kernel_dtb());
            return tool_result_t::ok(OBFSTR("Driver connected. Cleared stale AiDA self-attach context."), result);
        }

        return tool_result_t::ok(OBFSTR("Driver already connected"));
    }

    if (!device->connect())
        return tool_result_t::error(OBFSTR("Failed to connect to kernel driver. Ensure the driver is loaded and running."));

    device->solve_kernel_dtb();

    json result;
    result["connected"] = true;
    result["kernel_dtb"] = sa_format_address(device->get_kernel_dtb());
    result["note"] = OBFSTR("Connected via obfuscated device path. Kernel DTB solved for full kernel memory access.");
    return tool_result_t::ok(OBFSTR("Kernel driver connected"), result);
}

tool_result_t driver_status(const json&)
{
    const std::uint32_t attached_pid = device->get_process_id();
    const bool self_target = is_self_target_pid(attached_pid);

    json result;
    result["connected"]    = device->is_connected();
    result["process_id"]   = attached_pid;
    result["base_address"] = sa_format_address(device->get_base_address());
    result["dtb"]          = sa_format_address(device->get_dtb());
    result["kernel_dtb"]   = sa_format_address(device->get_kernel_dtb());
    result["has_process"]  = attached_pid != 0;
    result["has_kernel"]   = device->get_kernel_dtb() != 0;
    result["is_self_target"] = self_target;

    if (self_target)
        result["warning"] = "Driver target is AiDA's own process. Call driver_unattach and driver_attach <target>.exe.";

    if (device->is_connected() && attached_pid != 0)
        result["heartbeat"] = device->send_heartbeat() ? "ok" : "failed";

    return tool_result_t::ok(OBFSTR("Driver status"), result);
}

tool_result_t driver_attach(const json& params)
{
    if (!device->is_connected())
    {
        if (!device->connect())
            return tool_result_t::error(OBFSTR("Cannot connect to kernel driver. Load the driver first."));
    }

    std::string process_name;
    if (params.contains("process") && params["process"].is_string())
        process_name = trim_ascii_copy(params["process"].get<std::string>());
    else if (params.contains("process_name") && params["process_name"].is_string())
        process_name = trim_ascii_copy(params["process_name"].get<std::string>());
    else if (params.contains("name") && params["name"].is_string())
        process_name = trim_ascii_copy(params["name"].get<std::string>());

    if (process_name.empty())
        return tool_result_t::error(OBFSTR("Missing process name. Use process='target.exe'. Aliases supported: process_name, name."));

    if (is_ida_host_process_name(process_name))
        return tool_result_t::error(OBFSTR("Refusing to attach kernel driver to IDA host process name."));

    if (is_self_target_process_name(process_name))
        return tool_result_t::error(OBFSTR("Cannot attach to AiDA's own process."));

    std::uint32_t pid = device->find_process(process_name.c_str());
    if (pid == 0)
        return tool_result_t::error(OBFSTR("Process not found: ") + process_name);

    if (is_self_target_pid(pid))
        return tool_result_t::error(OBFSTR("Cannot attach to AiDA's own process."));

    std::uint64_t base = device->find_image();
    if (base == 0)
        return tool_result_t::error(OBFSTR("Failed to locate image base for process: ") + process_name);

    device->solve_dtb();

    json result;
    result["process_name"] = process_name;
    result["process_id"]   = pid;
    result["base_address"] = sa_format_address(base);
    result["dtb"]          = sa_format_address(device->get_dtb());
    return tool_result_t::ok(OBFSTR("Attached to process: ") + process_name, result);
}

tool_result_t driver_unattach(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    const std::uint32_t previous_pid = device->get_process_id();
    const std::uint64_t previous_base = device->get_base_address();
    const std::uint64_t previous_dtb = device->get_dtb();

    device->clear_process_context();

    json result;
    result["previous_process_id"] = previous_pid;
    result["previous_base_address"] = sa_format_address(static_cast<uint64_t>(previous_base));
    result["previous_dtb"] = sa_format_address(static_cast<uint64_t>(previous_dtb));
    result["connected"] = device->is_connected();
    result["process_id"] = device->get_process_id();
    result["base_address"] = sa_format_address(device->get_base_address());
    result["dtb"] = sa_format_address(device->get_dtb());
    result["kernel_dtb"] = sa_format_address(device->get_kernel_dtb());

    if (previous_pid == 0)
        return tool_result_t::ok(OBFSTR("No process was attached. Driver connection remains active."), result);

    return tool_result_t::ok(OBFSTR("Detached from attached process context. Driver connection remains active."), result);
}

tool_result_t driver_read_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = sa_parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t size = params.value("size", 256);
    if (size > 65536)
        return tool_result_t::error(OBFSTR("Size too large (max 65536)"));


    std::vector<std::uint8_t> buffer(size);
    std::size_t bytes_read = device->read_raw(*ea_opt, buffer.data(), size);
    if (bytes_read == 0)
        return tool_result_t::error(OBFSTR("Kernel read failed at ") + sa_format_address(*ea_opt));

    std::ostringstream hex_ss, ascii_ss;
    for (std::size_t i = 0; i < bytes_read; i++)
    {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
        char c = static_cast<char>(buffer[i]);
        ascii_ss << (c >= 32 && c < 127 ? c : '.');
    }

    json result;
    result["address"]       = sa_format_address(*ea_opt);
    result["size_requested"] = size;
    result["size_read"]     = bytes_read;
    result["hex"]           = hex_ss.str();
    result["ascii"]         = ascii_ss.str();
    result["bytes"]         = json::array();
    for (std::size_t i = 0; i < bytes_read; i++)
        result["bytes"].push_back(buffer[i]);

    if (params.value("patch_idb", false))
    {
        for (std::size_t i = 0; i < bytes_read; i++)
            put_byte(*ea_opt + i, buffer[i]);
        result["patched_idb"] = true;
    }

    return tool_result_t::ok(OBFSTR("Kernel read: ") + std::to_string(bytes_read) + " bytes", result);
}

tool_result_t driver_write_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = sa_parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));


    std::vector<std::uint8_t> bytes;
    std::string parse_error;
    if (!parse_byte_sequence(params["bytes"], bytes, parse_error))
    {
        return tool_result_t::error(
            OBFSTR("Invalid bytes format. Use one of: 'DE AD BE EF', 'DEADBEEF', [222,173,190,239], ['DE','AD',...]. Detail: ") +
            parse_error);
    }

    std::size_t written = device->write_raw(*ea_opt, bytes.data(), bytes.size());
    if (written == 0)
        return tool_result_t::error(OBFSTR("Kernel write failed at ") + sa_format_address(*ea_opt));

    json result;
    result["address"]       = sa_format_address(*ea_opt);
    result["bytes_written"] = written;
    result["requested"]     = bytes.size();
    return tool_result_t::ok(OBFSTR("Kernel write: ") + std::to_string(written) + " bytes", result);
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
        return tool_result_t::error(OBFSTR("No process attached. Provide 'process' param or call driver_attach first."));

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
            : OBFSTR("Open the saved file in a new IDA Pro instance. If needed, use manual load with image base ") + sa_format_address(base) + OBFSTR("."));

    return tool_result_t::ok(OBFSTR("Module dumped: ") + std::to_string(total_read) + "/" +
                             std::to_string(module_size) + " bytes -> " + output_path +
                             OBFSTR(". Open this file in a NEW IDA Pro instance for proper analysis."), result);
}

tool_result_t driver_scan_pattern(const json& params)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    std::string pattern_str = params["pattern"].get<std::string>();

    int limit = 20;
    if (params.contains("limit")) {
        if (params["limit"].is_number())
            limit = params["limit"].get<int>();
        else if (params["limit"].is_string()) {
            try { limit = std::stoi(params["limit"].get<std::string>()); } catch (...) {}
        }
    }

    std::uint64_t scan_size = 0x200000;
    if (params.contains("size")) {
        if (params["size"].is_number())
            scan_size = params["size"].get<std::uint64_t>();
        else if (params["size"].is_string()) {
            auto sz = sa_parse_address(params["size"].get<std::string>());
            if (sz) scan_size = *sz;
        }
    }

    constexpr std::uint64_t MAX_SCAN_SIZE = 0x40000000ULL;
    if (scan_size > MAX_SCAN_SIZE)
        scan_size = MAX_SCAN_SIZE;

    uint64_t start_addr = static_cast<uint64_t>(device->get_base_address());
    if (start_addr == 0)
        return tool_result_t::error(OBFSTR("Process base address is 0 - not attached or invalid target"));
    uint64_t end_addr   = start_addr + (uint64_t)scan_size;
    if (params.contains("start"))
    {
        auto s = sa_parse_address(params["start"].get<std::string>());
        if (s) start_addr = *s;
    }
    if (params.contains("end"))
    {
        auto e = sa_parse_address(params["end"].get<std::string>());
        if (e) end_addr = *e;
    }

    if (start_addr == 0)
        return tool_result_t::error(OBFSTR("Scan start address is 0 - provide a valid start address"));

    if (end_addr <= start_addr)
        return tool_result_t::error(OBFSTR("Scan end must be greater than start"));

    if ((end_addr - start_addr) > MAX_SCAN_SIZE)
        end_addr = start_addr + MAX_SCAN_SIZE;


    std::vector<std::uint8_t> pat;
    std::vector<bool> mask;
    {
        std::istringstream iss(pattern_str);
        std::string tok;
        while (iss >> tok)
        {
            if (tok == "??" || tok == "?")
            {
                pat.push_back(0);
                mask.push_back(false);
            }
            else
            {
                try
                {
                    pat.push_back(static_cast<std::uint8_t>(std::stoul(tok, nullptr, 16)));
                    mask.push_back(true);
                }
                catch (...) { return tool_result_t::error(OBFSTR("Invalid pattern token: ") + tok); }
            }
        }
    }
    if (pat.empty())
        return tool_result_t::error(OBFSTR("Empty pattern"));

    json matches = json::array();
    const std::size_t chunk_sz = 0x10000;
    std::vector<std::uint8_t> chunk(chunk_sz + pat.size());

    constexpr int MAX_CONSEC_FAILURES = 256;
    constexpr int SCAN_TIMEOUT_SEC    = 30;
    int consec_failures = 0;
    auto scan_start_time = std::chrono::steady_clock::now();

    show_wait_box("HIDECANCEL\nAiDA: Kernel pattern scan...");
    for (uint64_t addr = start_addr; addr < end_addr && (int)matches.size() < limit; addr += chunk_sz)
    {
        auto elapsed = std::chrono::steady_clock::now() - scan_start_time;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= SCAN_TIMEOUT_SEC)
        {
            hide_wait_box();
            json timeout_result;
            timeout_result["matches"] = matches;
            timeout_result["scanned_to"] = sa_format_address(addr);
            timeout_result["timeout"] = true;
            return tool_result_t::ok(OBFSTR("Pattern scan timed out after 30s: ") +
                                     std::to_string(matches.size()) + " matches so far", timeout_result);
        }

        replace_wait_box("HIDECANCEL\nAiDA: Kernel scan 0x%llX (%d found)...",
                         (unsigned long long)addr, (int)matches.size());
        std::size_t to_read = std::min((std::size_t)(end_addr - addr) + pat.size(), chunk_sz + pat.size());
        std::size_t got = device->read_raw(addr, chunk.data(), to_read);
        if (got < pat.size())
        {
            if (++consec_failures >= MAX_CONSEC_FAILURES)
            {
                hide_wait_box();
                json bail_result;
                bail_result["matches"] = matches;
                bail_result["scanned_to"] = sa_format_address(addr);
                bail_result["aborted"] = true;
                bail_result["reason"] = OBFSTR("Too many consecutive unreadable pages (16 MB gap)");
                return tool_result_t::ok(OBFSTR("Pattern scan aborted (unreadable region): ") +
                                         std::to_string(matches.size()) + " matches", bail_result);
            }
            continue;
        }
        consec_failures = 0;

        for (std::size_t i = 0; i + pat.size() <= got && (int)matches.size() < limit; i++)
        {
            bool found = true;
            for (std::size_t j = 0; j < pat.size(); j++)
            {
                if (mask[j] && chunk[i + j] != pat[j]) { found = false; break; }
            }
            if (found)
            {
                uint64_t m = addr + i;
                matches.push_back({{"address", sa_format_address(m)},
                                   {"name", sa_format_address(m)}});
            }
        }
    }
    hide_wait_box();

    return tool_result_t::ok(OBFSTR("Pattern scan: ") + std::to_string(matches.size()) + " matches", matches);
}

tool_result_t driver_read_string(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto ea_opt = sa_parse_address(params["address"].get<std::string>());
    if (!ea_opt)
        return tool_result_t::error(OBFSTR("Invalid address"));

    std::size_t max_len = params.value("max_length", 512);
    std::string type    = params.value("type", "auto");


    std::vector<std::uint8_t> buf(max_len * 2 + 4, 0);
    std::size_t got = device->read_raw(*ea_opt, buf.data(), buf.size());
    if (got == 0)
        return tool_result_t::error(OBFSTR("Failed to read from ") + sa_format_address(*ea_opt));

    json result;
    result["address"] = sa_format_address(*ea_opt);

    bool try_ascii = (type == "auto" || type == "ascii");
    bool try_wide  = (type == "auto" || type == "wide");

    if (try_wide && got >= 2)
    {
        std::string narrow;
        for (std::size_t i = 0; i + 1 < got; i += 2)
        {
            std::uint16_t wc = buf[i] | ((std::uint16_t)buf[i + 1] << 8);
            if (wc == 0) break;
            narrow += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
        }
        if (!narrow.empty())
        {
            result["wide_string"] = narrow;
            result["wide_length"] = narrow.length();
        }
    }

    if (try_ascii)
    {
        std::string ascii;
        for (std::size_t i = 0; i < got; i++)
        {
            if (buf[i] == 0) break;
            ascii += static_cast<char>(buf[i]);
        }
        result["string"]       = ascii;
        result["ascii_length"] = ascii.length();
    }

    return tool_result_t::ok(OBFSTR("String read via kernel"), result);
}

tool_result_t driver_read_pointer_chain(const json& params)
{
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

tool_result_t driver_enumerate_modules(const json&)
{
    if (!device->is_connected() || device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("Not attached. Call driver_connect then driver_attach first."));

    if (device->get_dtb() == 0)
    {
        device->solve_dtb();
        if (device->get_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve DTB. Cannot enumerate modules."));
    }

    voyager::device_t::peb_info peb{};
    if (!device->read_peb(peb) || peb.ldr_address == 0)
        return tool_result_t::error(OBFSTR("Failed to read PEB or PEB_LDR_DATA is null. "
            "Ensure the process is running and fully initialized."));


    std::uint64_t list_head = peb.ldr_address + 0x10;
    std::uint64_t first_entry = device->read<std::uint64_t>(list_head);

    if (first_entry == 0 || first_entry == list_head)
        return tool_result_t::error(OBFSTR("InLoadOrderModuleList is empty or unreadable."));

    json modules = json::array();
    std::uint64_t current = first_entry;
    int max_iter = 1024;
    std::uint64_t main_base = device->get_base_address();

    while (current != list_head && current != 0 && max_iter-- > 0)
    {


        std::uint64_t dll_base    = device->read<std::uint64_t>(current + 0x30);
        std::uint64_t entry_point = device->read<std::uint64_t>(current + 0x38);
        std::uint32_t size_of_img = device->read<std::uint32_t>(current + 0x40);


        std::uint16_t base_name_len = device->read<std::uint16_t>(current + 0x58);
        std::uint64_t base_name_ptr = device->read<std::uint64_t>(current + 0x60);

        std::string base_name;
        if (base_name_len > 0 && base_name_len < 520 && base_name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(base_name_len, 0);
            device->read_raw(base_name_ptr, raw.data(), base_name_len);
            base_name.reserve(base_name_len / 2);
            for (std::size_t i = 0; i + 1 < base_name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                base_name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }


        std::uint16_t full_name_len = device->read<std::uint16_t>(current + 0x48);
        std::uint64_t full_name_ptr = device->read<std::uint64_t>(current + 0x50);

        std::string full_name;
        if (full_name_len > 0 && full_name_len < 1024 && full_name_ptr != 0)
        {
            std::vector<std::uint8_t> raw(full_name_len, 0);
            device->read_raw(full_name_ptr, raw.data(), full_name_len);
            full_name.reserve(full_name_len / 2);
            for (std::size_t i = 0; i + 1 < full_name_len; i += 2)
            {
                std::uint16_t wc = raw[i] | (static_cast<std::uint16_t>(raw[i + 1]) << 8);
                if (wc == 0) break;
                full_name += (wc < 128 && wc >= 32) ? static_cast<char>(wc) : '?';
            }
        }

        if (dll_base != 0 && !base_name.empty())
        {
            json entry;
            entry["name"]        = base_name;
            entry["base"]        = sa_format_address(static_cast<uint64_t>(dll_base));
            entry["size"]        = size_of_img;
            entry["size_hex"]    = sa_format_address(static_cast<uint64_t>(size_of_img));
            entry["entry_point"] = sa_format_address(static_cast<uint64_t>(entry_point));
            if (!full_name.empty())
                entry["path"]    = full_name;
            entry["is_main"]     = (dll_base == main_base);
            modules.push_back(entry);
        }

        std::uint64_t next = device->read<std::uint64_t>(current);
        if (next == current || next == 0) break;
        current = next;
    }

    json result;
    result["modules"]      = modules;
    result["module_count"] = modules.size();
    result["process_id"]   = device->get_process_id();
    result["peb_address"]  = sa_format_address(static_cast<uint64_t>(peb.peb_address));
    result["ldr_address"]  = sa_format_address(static_cast<uint64_t>(peb.ldr_address));
    result["image_base"]   = sa_format_address(static_cast<uint64_t>(main_base));
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(modules.size()) +
        OBFSTR(" modules via PEB InLoadOrderModuleList"), result);
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
    return true;
}

tool_result_t driver_enumerate_kernel_modules(const json& params)
{
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
        std::string full_path(reinterpret_cast<const char*>(m.FullPathName));
        std::string name(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));

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

tool_result_t driver_dump_kernel_module(const json& params)
{
    std::string module_name = params["module"].get<std::string>();
    std::string output_path = params.value("output_path", std::string());
    bool use_memory = params.value("from_memory", true);
    bool patch_idb  = params.value("patch_idb", true);
    bool analyze    = params.value("analyze", true);

    std::vector<std::uint8_t> buf;
    sys_module_info_t* info = nullptr;
    std::string err;
    if (!query_kernel_modules(buf, info, err))
        return tool_result_t::error(err);

    std::string found_name, found_nt_path;
    std::uintptr_t found_base = 0;
    ULONG found_size = 0;
    bool found = false;

    std::string lower_target = module_name;
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
            found_name    = name;
            found_nt_path = full_path;
            found_base    = reinterpret_cast<std::uintptr_t>(m.ImageBase);
            found_size    = m.ImageSize;
            found = true;
            break;
        }
    }

    if (!found)
        return tool_result_t::error(
            OBFSTR("Kernel module not found: ") + module_name +
            OBFSTR(". Use driver_enumerate_kernel_modules with filter to list loaded drivers."));

    if (use_memory)
    {
        if (!device || !device->is_connected())
            return tool_result_t::error(
                OBFSTR("Driver not connected. Call driver_connect first for in-memory kernel dump."));

        if (device->get_kernel_dtb() == 0)
        {
            device->solve_kernel_dtb();
            if (device->get_kernel_dtb() == 0)
                return tool_result_t::error(
                    OBFSTR("Failed to solve kernel DTB (System process PID 4). "
                           "Cannot read kernel memory."));
        }

        if (output_path.empty())
        {
            output_path = get_downloads_folder() + "dumped_" + found_name;
        }

        std::uint64_t base_addr = static_cast<std::uint64_t>(found_base);
        std::uint32_t image_size = found_size;

        json steps = json::array();
        auto log = [&](const std::string& step, bool ok, const std::string& detail) {
            steps.push_back({{"step", step}, {"ok", ok}, {"detail", detail}});
        };

        std::vector<std::uint8_t> header_buf(0x1000, 0);
        std::size_t header_read = device->read_kernel_raw(base_addr, header_buf.data(), 0x1000);

        bool has_valid_mz = (header_read >= 0x40 && header_buf[0] == 'M' && header_buf[1] == 'Z');
        bool has_valid_pe = false;
        bool header_wiped = false;

        std::uint16_t machine        = 0x8664;
        std::uint16_t num_sections   = 0;
        std::uint16_t opt_hdr_size   = 0;
        std::uint32_t pe_image_size  = 0;
        std::uint32_t pe_off         = 0;
        std::uint32_t section_table_off = 0;

        if (has_valid_mz)
        {
            pe_off = *reinterpret_cast<std::uint32_t*>(&header_buf[0x3C]);
            if (pe_off + 0x18 <= header_read &&
                header_buf[pe_off] == 'P' && header_buf[pe_off + 1] == 'E' &&
                header_buf[pe_off + 2] == 0 && header_buf[pe_off + 3] == 0)
            {
                has_valid_pe    = true;
                machine         = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 4]);
                num_sections    = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 6]);
                opt_hdr_size    = *reinterpret_cast<std::uint16_t*>(&header_buf[pe_off + 20]);
                pe_image_size   = *reinterpret_cast<std::uint32_t*>(&header_buf[pe_off + 24 + 56]);
                section_table_off = pe_off + 24 + opt_hdr_size;
            }

            log("read_header", true, has_valid_pe
                ? ("MZ+PE valid, " + std::to_string(num_sections) + " sections, SizeOfImage=0x" +
                   sa_format_address(static_cast<uint64_t>(pe_image_size)))
                : "MZ found but PE signature invalid/corrupt");
        }
        else
        {
            header_wiped = true;
            msg(OBFSTR_C("AiDA: WARNING - MZ signature not found at kernel base %s (read %zu bytes). "
                "Header likely wiped by anti-cheat. Using module info as source of truth.\n"),
                sa_format_address(static_cast<uint64_t>(base_addr)).c_str(), header_read);
            log("read_header", false,
                "MZ signature wiped/missing at base " +
                sa_format_address(static_cast<uint64_t>(base_addr)) +
                " - anti-cheat header erasure detected. Will synthesize PE header.");
        }


        protection_analysis_t kd_protection = analyze_module_protection(
            device.get(), base_addr, header_buf.data(), header_read,
            has_valid_pe, header_wiped, pe_off, num_sections,
            section_table_off, image_size, true, steps);

        if (kd_protection.is_packed || kd_protection.is_vmprotected ||
            kd_protection.is_themida)
        {
            msg(OBFSTR_C("AiDA: kernel module protection detected - VMProtect=%s Themida=%s Packed=%s "
                "encrypted_sections=%d high_entropy_pages=%d\n"),
                kd_protection.is_vmprotected ? "YES" : "no",
                kd_protection.is_themida ? "YES" : "no",
                kd_protection.is_packed ? "YES" : "no",
                kd_protection.encrypted_section_count,
                kd_protection.high_entropy_pages);
            log("protection_analysis", true,
                "Kernel module protections: VMProtect=" +
                std::string(kd_protection.is_vmprotected ? "YES" : "no") +
                " Themida=" + std::string(kd_protection.is_themida ? "YES" : "no") +
                " packed=" + std::string(kd_protection.is_packed ? "YES" : "no") +
                " encrypted_sections=" + std::to_string(kd_protection.encrypted_section_count) +
                " avg_entropy=" + std::to_string(kd_protection.avg_code_entropy));
        }

        std::uint32_t dump_size = image_size;
        if (has_valid_pe && pe_image_size > dump_size)
            dump_size = pe_image_size;
        if (dump_size == 0)
            dump_size = 0x100000;
        if (dump_size > 0x40000000u)
            return tool_result_t::error(OBFSTR("Image size exceeds 1GB limit: ") + std::to_string(dump_size));

        log("size_source", true,
            "Module info ImageSize=0x" + sa_format_address(static_cast<uint64_t>(image_size)) +
            (has_valid_pe ? (", PE SizeOfImage=0x" + sa_format_address(static_cast<uint64_t>(pe_image_size))) : "") +
            ", using dump_size=0x" + sa_format_address(static_cast<uint64_t>(dump_size)));

        constexpr std::uint32_t PROBE_CHUNK = 0x10000;
        constexpr int MAX_EMPTY_RUNS = 32;
        int empty_run = 0;
        std::uint32_t extended_end = dump_size;
        std::vector<std::uint8_t> probe_buf(PROBE_CHUNK, 0);
        std::uint64_t probe_limit = static_cast<std::uint64_t>(dump_size) * 4;
        if (probe_limit > 0x40000000ULL) probe_limit = 0x40000000ULL;

        for (std::uint64_t probe_off = dump_size; probe_off < probe_limit; probe_off += PROBE_CHUNK)
        {
            std::memset(probe_buf.data(), 0, PROBE_CHUNK);
            std::size_t probe_got = device->read_kernel_raw(
                base_addr + probe_off, probe_buf.data(), PROBE_CHUNK);
            if (probe_got == 0)
                break;

            bool all_zero = true;
            for (std::size_t i = 0; i < probe_got; i++)
            {
                if (probe_buf[i] != 0) { all_zero = false; break; }
            }

            if (all_zero)
            {
                empty_run++;
                if (empty_run >= MAX_EMPTY_RUNS) break;
            }
            else
            {
                empty_run = 0;
                extended_end = static_cast<std::uint32_t>(probe_off + PROBE_CHUNK);
            }
        }

        if (extended_end > dump_size)
        {
            msg(OBFSTR_C("AiDA: Extended kernel dump from 0x%X to 0x%X (+%u MB beyond base size)\n"),
                dump_size, extended_end, (extended_end - dump_size) / (1024 * 1024));
            log("probe_extend", true,
                "Extended dump by " + std::to_string((extended_end - dump_size) / (1024 * 1024)) +
                " MB via memory probing");
            dump_size = extended_end;
        }

        std::vector<std::uint8_t> dump_data(dump_size, 0);

        std::memcpy(dump_data.data(), header_buf.data(), std::min<std::size_t>(header_read, dump_size));

        show_wait_box("HIDECANCEL\nAiDA: Dumping kernel module %s from memory (0x%X bytes, %u MB)...",
                      found_name.c_str(), dump_size, dump_size / (1024 * 1024));

        constexpr std::size_t KD_CHUNK = 0x10000;
        constexpr std::size_t KD_PAGE  = 0x1000;
        std::size_t total_read = std::min<std::size_t>(header_read, dump_size);
        int kd_failed_pages = 0;
        std::vector<std::uint32_t> kd_failed_offsets;

        for (std::uint32_t offset = static_cast<std::uint32_t>(
                 std::min<std::size_t>(header_read, dump_size));
             offset < dump_size; offset += static_cast<std::uint32_t>(KD_CHUNK))
        {
            std::size_t to_read = KD_CHUNK;
            if (offset + to_read > dump_size)
                to_read = dump_size - offset;

            std::size_t bytes_got = device->read_kernel_raw(
                base_addr + offset, dump_data.data() + offset, to_read);

            if (bytes_got >= to_read)
            {
                total_read += bytes_got;
            }
            else
            {

                for (std::size_t pg = 0; pg < to_read; pg += KD_PAGE)
                {
                    std::size_t pg_sz  = std::min(KD_PAGE, to_read - pg);
                    std::size_t pg_got = device->read_kernel_raw(
                        base_addr + offset + pg,
                        dump_data.data() + offset + static_cast<std::uint32_t>(pg), pg_sz);
                    if (pg_got > 0)
                        total_read += pg_got;
                    else
                    {
                        kd_failed_pages++;
                        kd_failed_offsets.push_back(offset + static_cast<std::uint32_t>(pg));
                    }
                }
            }

            if (offset % 0x40000 == 0)
                replace_wait_box("HIDECANCEL\nAiDA: Dumping %s: 0x%X / 0x%X (%.1f%%)",
                                 found_name.c_str(), offset, dump_size,
                                 (offset * 100.0) / dump_size);
        }


        if (!kd_failed_offsets.empty())
        {
            replace_wait_box("HIDECANCEL\nAiDA: Re-solving kernel DTB and retrying %d pages...",
                             static_cast<int>(kd_failed_offsets.size()));
            device->solve_kernel_dtb();

            int kd_recovered = 0;
            for (std::uint32_t fo : kd_failed_offsets)
            {
                std::size_t pg_sz  = std::min(KD_PAGE, static_cast<std::size_t>(dump_size - fo));
                std::size_t pg_got = device->read_kernel_raw(
                    base_addr + fo, dump_data.data() + fo, pg_sz);
                if (pg_got > 0)
                {
                    total_read += pg_got;
                    kd_recovered++;
                }
            }

            if (kd_recovered > 0)
                msg(OBFSTR_C("AiDA: Kernel DTB re-solve recovered %d/%d failed pages\n"),
                    kd_recovered, static_cast<int>(kd_failed_offsets.size()));

            kd_failed_pages -= kd_recovered;
        }


        if (!kd_failed_offsets.empty())
        {
            std::string kd_disk_path = resolve_nt_path_to_win32(found_nt_path);
            if (!kd_disk_path.empty())
            {
                std::vector<std::size_t> kd_fail_sizes;
                kd_fail_sizes.reserve(kd_failed_offsets.size());
                for (std::uint32_t fo : kd_failed_offsets)
                    kd_fail_sizes.push_back(static_cast<std::size_t>(fo));

                int disk_recovered = try_fill_from_disk_pe(dump_data, kd_fail_sizes, kd_disk_path, steps);
                if (disk_recovered > 0)
                {
                    kd_failed_pages -= disk_recovered;
                    total_read += static_cast<std::size_t>(disk_recovered) * KD_PAGE;
                }
            }
        }

        hide_wait_box();

        log("dump_memory", total_read > 0,
            std::to_string(total_read) + "/" + std::to_string(dump_size) + " bytes" +
            (kd_failed_pages > 0 ? (", " + std::to_string(kd_failed_pages) + " pages unreadable (paged-out/shadow)") : ""));

        if (header_wiped || !has_valid_pe)
        {
            msg(OBFSTR_C("AiDA: Synthesizing PE header for headerless kernel dump...\n"));

            struct discovered_section_t {
                std::uint32_t rva;
                std::uint32_t size;
                bool is_executable;
                bool is_writable;
                bool has_data;
            };
            std::vector<discovered_section_t> discovered;

            constexpr std::uint32_t SCAN_GRANULARITY = 0x1000;
            std::uint32_t current_start = 0;
            bool in_section = false;
            bool sec_exec = false;
            bool sec_write = false;
            bool sec_has_data = false;

            for (std::uint32_t off = 0; off < dump_size; off += SCAN_GRANULARITY)
            {
                bool page_has_data = false;
                bool page_looks_code = false;
                std::uint32_t page_end = std::min(off + SCAN_GRANULARITY, dump_size);

                for (std::uint32_t i = off; i < page_end; i++)
                {
                    if (dump_data[i] != 0) { page_has_data = true; break; }
                }

                if (page_has_data && page_end - off >= 16)
                {
                    int code_heuristic = 0;
                    for (std::uint32_t i = off; i < page_end - 4; i += 64)
                    {
                        std::uint8_t b = dump_data[i];
                        if (b == 0xCC || b == 0xC3 || b == 0xC2 ||
                            b == 0xE8 || b == 0xE9 || b == 0xFF ||
                            b == 0x48 || b == 0x4C || b == 0x41 ||
                            b == 0x0F || b == 0x55 || b == 0x53)
                            code_heuristic++;
                    }
                    page_looks_code = (code_heuristic > 3);
                }

                if (page_has_data && !in_section)
                {
                    current_start = off;
                    in_section = true;
                    sec_exec = page_looks_code;
                    sec_write = !page_looks_code;
                    sec_has_data = true;
                }
                else if (page_has_data && in_section)
                {
                    if (page_looks_code) sec_exec = true;
                    sec_has_data = true;
                }
                else if (!page_has_data && in_section)
                {
                    std::uint32_t lookahead_end = std::min(off + 0x10000, dump_size);
                    bool resumes = false;
                    for (std::uint32_t la = off + SCAN_GRANULARITY; la < lookahead_end; la += SCAN_GRANULARITY)
                    {
                        for (std::uint32_t i = la; i < std::min(la + SCAN_GRANULARITY, dump_size); i++)
                        {
                            if (dump_data[i] != 0) { resumes = true; break; }
                        }
                        if (resumes) break;
                    }

                    if (!resumes)
                    {
                        discovered.push_back({current_start, off - current_start,
                                              sec_exec, sec_write, sec_has_data});
                        in_section = false;
                    }
                }
            }

            if (in_section)
            {
                discovered.push_back({current_start, dump_size - current_start,
                                      sec_exec, sec_write, sec_has_data});
            }

            if (discovered.empty())
            {
                discovered.push_back({0, dump_size, true, false, true});
            }

            int max_synth_sections = std::min<int>(static_cast<int>(discovered.size()), 16);
            std::uint32_t synth_pe_off = 0x80;
            std::uint32_t synth_opt_size = 0xF0;
            std::uint32_t synth_sec_table = synth_pe_off + 0x18 + synth_opt_size;
            std::uint32_t synth_header_end = synth_sec_table + max_synth_sections * 40;

            if (synth_header_end > 0x1000) synth_header_end = 0x1000;

            dump_data[0x00] = 'M'; dump_data[0x01] = 'Z';
            dump_data[0x02] = 0x90; dump_data[0x03] = 0x00;
            *reinterpret_cast<std::uint32_t*>(&dump_data[0x3C]) = synth_pe_off;

            dump_data[synth_pe_off + 0] = 'P';
            dump_data[synth_pe_off + 1] = 'E';
            dump_data[synth_pe_off + 2] = 0;
            dump_data[synth_pe_off + 3] = 0;

            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 4]) = 0x8664;
            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 6]) =
                static_cast<std::uint16_t>(max_synth_sections);

            std::uint16_t pe_characteristics = 0x0022;
            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 0x16]) = pe_characteristics;

            *reinterpret_cast<std::uint16_t*>(&dump_data[synth_pe_off + 0x14]) = synth_opt_size;

            std::uint32_t opt_off = synth_pe_off + 0x18;
            *reinterpret_cast<std::uint16_t*>(&dump_data[opt_off + 0]) = 0x020B;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x38]) =
                (dump_size + 0xFFF) & ~0xFFFu;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x3C]) = 0x1000;
            *reinterpret_cast<std::uint64_t*>(&dump_data[opt_off + 0x18]) = base_addr;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x10]) =
                discovered.empty() ? 0x1000 : discovered[0].rva;
            *reinterpret_cast<std::uint16_t*>(&dump_data[opt_off + 0x44]) = 0x0A;
            *reinterpret_cast<std::uint32_t*>(&dump_data[opt_off + 0x6C]) = 0;

            for (int si = 0; si < max_synth_sections; si++)
            {
                const auto& ds = discovered[si];
                std::uint32_t sec_off = synth_sec_table + si * 40;
                if (sec_off + 40 > 0x1000) break;

                char sname[9] = {};
                if (ds.is_executable)
                    qsnprintf(sname, sizeof(sname), ".text%d", si);
                else
                    qsnprintf(sname, sizeof(sname), ".data%d", si);
                if (si == 0 && ds.is_executable) std::memcpy(sname, ".text\0\0\0", 8);
                if (si == 0 && !ds.is_executable) std::memcpy(sname, ".data\0\0\0", 8);

                std::memcpy(&dump_data[sec_off], sname, 8);
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 8]) = ds.size;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 12]) = ds.rva;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 16]) = ds.size;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 20]) = ds.rva;

                std::uint32_t chars = 0x40000000u;
                if (ds.is_executable) chars |= 0x20000000u | 0x00000020u;
                if (ds.is_writable)   chars |= 0x80000000u;
                chars |= 0x00000040u;
                *reinterpret_cast<std::uint32_t*>(&dump_data[sec_off + 36]) = chars;
            }

            machine         = 0x8664;
            num_sections    = static_cast<std::uint16_t>(max_synth_sections);
            pe_off          = synth_pe_off;
            opt_hdr_size    = synth_opt_size;
            section_table_off = synth_sec_table;
            pe_image_size   = dump_size;
            has_valid_pe    = true;

            log("synthesize_header", true,
                "Built synthetic PE header with " + std::to_string(max_synth_sections) +
                " discovered sections from memory content analysis");
            msg(OBFSTR_C("AiDA: Synthesized PE header - %d sections discovered via memory scanning\n"),
                max_synth_sections);
        }


        pe_fix_result_t pe_fix = fix_dumped_pe_image(dump_data, base_addr);
        if (pe_fix.success)
        {
            msg(OBFSTR_C("AiDA: PE fixed - %d sections, %d IAT entries restored, EP %s\n"),
                pe_fix.sections_fixed, pe_fix.iat_entries_restored,
                pe_fix.entry_point_valid ? "valid" : "fallback");
            log("pe_fix", true, std::to_string(pe_fix.sections_fixed) + " sections, " +
                std::to_string(pe_fix.iat_entries_restored) + " IAT entries");
        }

        cleanup_exception_directory(dump_data, pe_fix.is_pe64 || (machine == 0x8664));
        log("exception_cleanup", true, "Invalid runtime function entries cleaned");

        {
            std::uint16_t kd_sec_count = num_sections;
            std::uint32_t kd_sec_table = section_table_off;
            if (pe_fix.success && dump_size > 0x200)
            {
                std::uint32_t fpo = *reinterpret_cast<std::uint32_t*>(dump_data.data() + 0x3C);
                if (fpo + 0x18 < dump_size)
                {
                    kd_sec_count = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 6);
                    std::uint16_t fo = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 0x14);
                    kd_sec_table = fpo + 0x18 + fo;
                }
            }

            int kd_nop_filled = 0;
            for (int si = 0; si < kd_sec_count && si < 96; si++)
            {
                std::uint32_t soff = kd_sec_table + si * 40;
                if (soff + 40 > dump_size) break;

                std::uint32_t vsize = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 8);
                std::uint32_t vrva  = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 12);
                std::uint32_t chars = *reinterpret_cast<std::uint32_t*>(dump_data.data() + soff + 36);

                if (vsize == 0 || vrva == 0 || !(chars & 0x20000000)) continue;

                for (std::uint32_t pg_off = vrva; pg_off < vrva + vsize; pg_off += 0x1000)
                {
                    if (pg_off >= dump_size) break;
                    std::uint32_t pg_sz = std::min<std::uint32_t>(0x1000, dump_size - pg_off);

                    bool is_all_zero = true;
                    for (std::uint32_t i = 0; i < pg_sz; i++)
                    {
                        if (dump_data[pg_off + i] != 0x00)
                        {
                            is_all_zero = false;
                            break;
                        }
                    }
                    if (is_all_zero)
                    {
                        std::memset(dump_data.data() + pg_off, 0x90, pg_sz);
                        kd_nop_filled++;
                    }
                }
            }

            if (kd_nop_filled > 0)
            {
                log("nop_fill", true, std::to_string(kd_nop_filled) +
                    " zero code pages NOP-filled to prevent IDA treating them as data");
                msg(OBFSTR_C("AiDA: NOP-filled %d zero code pages in kernel dump\n"), kd_nop_filled);
            }
        }

        iat_rebuild_result_t iat_rebuild = reconstruct_iat_runtime(dump_data, base_addr, device.get(), true);
        if (iat_rebuild.success && iat_rebuild.descriptors_rebuilt > 0)
        {
            msg(OBFSTR_C("AiDA: Kernel IAT reconstruction - %d imports resolved, %d failed, %d descriptors rebuilt\n"),
                iat_rebuild.imports_resolved, iat_rebuild.imports_failed, iat_rebuild.descriptors_rebuilt);
            log("iat_rebuild", true, std::to_string(iat_rebuild.imports_resolved) + " imports, " +
                std::to_string(iat_rebuild.descriptors_rebuilt) + " descriptors");
        }
        else if (!iat_rebuild.error.empty())
        {
            msg(OBFSTR_C("AiDA: Kernel IAT rebuild note: %s\n"), iat_rebuild.error.c_str());
            log("iat_rebuild", false, iat_rebuild.error);
        }

        if (iat_rebuild.descriptors_rebuilt == 0 || iat_rebuild.imports_resolved == 0)
        {
            msg(OBFSTR_C("AiDA: Standard kernel IAT rebuild found nothing - running full export-scan reconstruction...\n"));
            iat_rebuild_result_t scan_result = full_iat_scan_and_rebuild(dump_data, base_addr, device.get(), true);
            if (scan_result.success && scan_result.imports_resolved > 0)
            {
                iat_rebuild = scan_result;
                msg(OBFSTR_C("AiDA: Kernel full IAT scan - %d imports resolved, %d DLLs\n"),
                    scan_result.imports_resolved, scan_result.descriptors_rebuilt);
                log("iat_full_scan", true, std::to_string(scan_result.imports_resolved) +
                    " imports via full scan, " + std::to_string(scan_result.descriptors_rebuilt) + " DLLs");
            }
            else
            {
                msg(OBFSTR_C("AiDA: Kernel full IAT scan found no additional imports\n"));
                log("iat_full_scan", false, scan_result.error.empty() ? "No imports found" : scan_result.error);
            }
        }

        show_wait_box("HIDECANCEL\nAiDA: Writing memory dump to %s...", output_path.c_str());
        ensure_parent_dir_exists(output_path);

        HANDLE hOut = CreateFileA(
            output_path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hOut == INVALID_HANDLE_VALUE)
        {
            hide_wait_box();
            return tool_result_t::error(
                OBFSTR("Failed to create output file: ") + output_path +
                OBFSTR(". Win32 error: ") + std::to_string(GetLastError()));
        }

        DWORD bytes_written = 0;
        {
            const std::uint8_t* wp = dump_data.data();
            std::size_t rem = dump_size;
            bool wok = true;
            while (rem > 0 && wok)
            {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 0x40000000ULL));
                DWORD w = 0;
                if (!WriteFile(hOut, wp, chunk, &w, nullptr) || w != chunk)
                    wok = false;
                else { wp += w; rem -= w; bytes_written += w; }
            }
        }
        CloseHandle(hOut);
        hide_wait_box();
        msg(OBFSTR_C("AiDA: Dump saved to %s (%u bytes, %u MB)\n"),
            output_path.c_str(), dump_size, dump_size / (1024 * 1024));
        log("save_to_disk", true, output_path + " (" + std::to_string(dump_size) + " bytes)");

        std::size_t patched = 0;
        json sections_arr = json::array();

        if (patch_idb)
        {
            show_wait_box("HIDECANCEL\nAiDA: Creating IDB segments and patching bytes...");

            std::uint16_t final_num_sections = num_sections;
            std::uint32_t final_section_table_off = section_table_off;
            if (pe_fix.success && dump_size > 0x200)
            {
                std::uint32_t fpo = *reinterpret_cast<std::uint32_t*>(dump_data.data() + 0x3C);
                if (fpo + 0x18 < dump_size)
                {
                    final_num_sections = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 6);
                    std::uint16_t fo = *reinterpret_cast<std::uint16_t*>(dump_data.data() + fpo + 0x14);
                    final_section_table_off = fpo + 0x18 + fo;
                }
            }

            for (int s = 0; s < final_num_sections && s < 96; s++)
            {
                std::uint32_t s_off = final_section_table_off + s * 40;
                if (s_off + 40 > dump_size) break;

                const std::uint8_t* sec = dump_data.data() + s_off;
                char sec_name[9] = {};
                std::memcpy(sec_name, sec, 8);

                std::uint32_t virt_size       = *reinterpret_cast<const std::uint32_t*>(sec + 8);
                std::uint32_t virt_addr       = *reinterpret_cast<const std::uint32_t*>(sec + 12);
                std::uint32_t sec_chars       = *reinterpret_cast<const std::uint32_t*>(sec + 36);

                if (virt_size == 0) continue;

                uint64_t seg_start = static_cast<uint64_t>(base_addr + virt_addr);
                uint64_t seg_end   = seg_start + virt_size;

                if (!getseg(seg_start))
                {
                    segment_t seg;
                    seg.start_ea = seg_start;
                    seg.end_ea   = seg_end;
                    seg.type     = (sec_chars & 0x20000000) ? SEG_CODE : SEG_DATA;
                    seg.bitness  = 2;
                    seg.perm     = 0;
                    if (sec_chars & 0x20000000) seg.perm |= SEGPERM_EXEC;
                    if (sec_chars & 0x40000000) seg.perm |= SEGPERM_READ;
                    if (sec_chars & 0x80000000) seg.perm |= SEGPERM_WRITE;
                    add_segm_ex(&seg, sec_name, nullptr, ADDSEG_QUIET | ADDSEG_NOSREG);
                }

                std::uint32_t copy_len = virt_size;
                if (virt_addr + copy_len > dump_size) copy_len = dump_size - virt_addr;

                std::size_t sec_patched = 0;
                if (copy_len > 0 && is_mapped(seg_start))
                {
                    put_bytes(seg_start, dump_data.data() + virt_addr, copy_len);
                    sec_patched = copy_len;
                }
                patched += sec_patched;

                json sec_info;
                sec_info["name"]            = sec_name;
                sec_info["virtual_address"] = sa_format_address(static_cast<uint64_t>(virt_addr));
                sec_info["virtual_size"]    = virt_size;
                sec_info["characteristics"] = sa_format_address(static_cast<uint64_t>(sec_chars));
                sec_info["bytes_patched"]   = sec_patched;
                sections_arr.push_back(sec_info);
            }

            hide_wait_box();
            log("patch_idb", patched > 0, std::to_string(patched) + " bytes patched into IDB");
        }

        std::string pe_arch = "unknown";
        if (machine == 0x8664) pe_arch = "AMD64";
        else if (machine == 0x014C) pe_arch = "i386";
        else if (machine == 0xAA64) pe_arch = "ARM64";

        int coverage = dump_size ? static_cast<int>((total_read * 100) / dump_size) : 0;

        json result;
        result["module_name"]        = found_name;
        result["nt_path"]            = found_nt_path;
        result["kernel_base"]        = sa_format_address(static_cast<uint64_t>(found_base));
        result["image_size"]         = dump_size;
        result["module_info_size"]   = image_size;
        result["bytes_read"]         = total_read;
        result["coverage_pct"]       = coverage;
        result["output_path"]        = output_path;
        result["saved_to"]           = output_path;
        result["valid_pe"]           = has_valid_pe;
        result["header_wiped"]       = header_wiped;
        result["header_synthesized"] = header_wiped || !has_valid_mz;
        result["architecture"]       = pe_arch;
        result["num_sections"]       = static_cast<int>(num_sections);
        result["dump_source"]        = "kernel_memory";
        result["can_load_in_ida"]    = true;
        result["analyzed"]           = analyze && patch_idb;
        result["steps"]              = steps;
        if (kd_failed_pages > 0)
            result["unreadable_pages"] = kd_failed_pages;
        if (patch_idb)
        {
            result["bytes_patched"] = patched;
            result["sections"]      = sections_arr;
        }
        if (pe_fix.success)
            result["pe_fix"] = pe_fix_to_json(pe_fix);
        if (iat_rebuild.success && iat_rebuild.descriptors_rebuilt > 0)
            result["iat_rebuild"] = iat_rebuild_to_json(iat_rebuild);

        result["protections_detected"] = kd_protection.is_packed ||
            kd_protection.is_vmprotected || kd_protection.is_themida;
        result["vmprotect"]  = kd_protection.is_vmprotected;
        result["themida"]    = kd_protection.is_themida;
        result["upx"]        = kd_protection.is_upx;
        result["is_packed"]  = kd_protection.is_packed;
        {
            json pa;
            pa["total_code_pages"]    = kd_protection.total_code_pages;
            pa["zero_pages"]          = kd_protection.zero_code_pages;
            pa["high_entropy_pages"]  = kd_protection.high_entropy_pages;
            pa["avg_entropy"]         = kd_protection.avg_code_entropy;
            pa["encrypted_sections"]  = kd_protection.encrypted_section_count;

            result["pre_dump_analysis"] = pa;
        }

        std::string note_str;
        if (header_wiped)
            note_str = OBFSTR("WARNING: Original PE header was wiped by anti-cheat. "
                "A synthetic header has been constructed from memory analysis. "
                "Section boundaries are approximate. ");
        note_str += OBFSTR("Live kernel memory dump - contains runtime-decrypted code. "
            "Open this file in a NEW IDA Pro instance for proper analysis. ");
        if (kd_failed_pages > 0)
            note_str += std::to_string(kd_failed_pages) +
                OBFSTR(" pages were unreadable (paged-out, shadow-mapped, or EPT-protected). ");
        result["note"] = note_str;

        return tool_result_t::ok(
            OBFSTR("Kernel module dumped: ") + found_name + OBFSTR(" (") +
            std::to_string(total_read) + OBFSTR("/") + std::to_string(dump_size) +
            OBFSTR(" bytes, ") + std::to_string(coverage) + OBFSTR("% coverage") +
            (header_wiped ? OBFSTR(", header synthesized") : "") +
            OBFSTR(") -> ") + output_path +
            OBFSTR(". Open this file in a NEW IDA Pro instance for proper analysis."), result);
    }

    std::string disk_path = resolve_nt_path_to_win32(found_nt_path);

    if (output_path.empty())
    {
        output_path = get_downloads_folder() + "dumped_" + found_name;
    }

    HANDLE hFile = CreateFileA(
        disk_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        hFile = CreateFileA(
            found_nt_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD last_err = GetLastError();
        return tool_result_t::error(
            OBFSTR("Cannot open driver file: ") + disk_path +
            OBFSTR(" (Win32 error: ") + std::to_string(last_err) +
            OBFSTR("). Connect the kernel driver and use from_memory=true for live dump."));
    }

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(hFile, &file_size_li) || file_size_li.QuadPart == 0)
    {
        CloseHandle(hFile);
        return tool_result_t::error(OBFSTR("Cannot determine file size for: ") + disk_path);
    }

    if (file_size_li.QuadPart > 256LL * 1024 * 1024)
    {
        CloseHandle(hFile);
        return tool_result_t::error(
            OBFSTR("Driver file exceeds 256 MB limit: ") +
            std::to_string(file_size_li.QuadPart) + OBFSTR(" bytes"));
    }

    std::size_t file_size = static_cast<std::size_t>(file_size_li.QuadPart);
    std::vector<std::uint8_t> file_data(file_size);

    show_wait_box("HIDECANCEL\nAiDA: Reading kernel module %s from disk (%zu bytes)...",
                  found_name.c_str(), file_size);

    DWORD total_read = 0;
    while (total_read < static_cast<DWORD>(file_size))
    {
        DWORD to_read = static_cast<DWORD>(
            std::min<std::size_t>(file_size - total_read, 0x100000));
        DWORD bytes_read = 0;
        if (!ReadFile(hFile, file_data.data() + total_read, to_read, &bytes_read, nullptr) || bytes_read == 0)
            break;
        total_read += bytes_read;
    }
    CloseHandle(hFile);
    hide_wait_box();

    if (total_read == 0)
        return tool_result_t::error(OBFSTR("Failed to read any bytes from: ") + disk_path);

    ensure_parent_dir_exists(output_path);
    HANDLE hOut = CreateFileA(
        output_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hOut == INVALID_HANDLE_VALUE)
    {
        return tool_result_t::error(
            OBFSTR("Failed to create output file: ") + output_path +
            OBFSTR(". Win32 error: ") + std::to_string(GetLastError()));
    }

    DWORD bytes_written = 0;
    WriteFile(hOut, file_data.data(), total_read, &bytes_written, nullptr);
    CloseHandle(hOut);

    bool is_valid_pe = false;
    std::string pe_arch = "unknown";
    if (file_data.size() >= 0x40 && file_data[0] == 'M' && file_data[1] == 'Z')
    {
        std::uint32_t pe_off = *reinterpret_cast<std::uint32_t*>(&file_data[0x3C]);
        if (pe_off + 6 < file_data.size() &&
            file_data[pe_off] == 'P' && file_data[pe_off + 1] == 'E' &&
            file_data[pe_off + 2] == 0 && file_data[pe_off + 3] == 0)
        {
            is_valid_pe = true;
            std::uint16_t machine = *reinterpret_cast<std::uint16_t*>(&file_data[pe_off + 4]);
            if (machine == 0x8664) pe_arch = "AMD64";
            else if (machine == 0x014C) pe_arch = "i386";
            else if (machine == 0xAA64) pe_arch = "ARM64";
        }
    }

    json result;
    result["module_name"]       = found_name;
    result["nt_path"]           = found_nt_path;
    result["disk_path"]         = disk_path;
    result["kernel_base"]       = sa_format_address(static_cast<uint64_t>(found_base));
    result["kernel_size"]       = found_size;
    result["file_size"]         = total_read;
    result["output_path"]       = output_path;
    result["valid_pe"]          = is_valid_pe;
    result["architecture"]      = pe_arch;
    result["dump_source"]       = "disk";
    result["can_load_in_ida"]   = is_valid_pe;
    result["note"]              = OBFSTR(
        "ON-DISK dump (not live memory). Contains static file contents only. "
        "For runtime-decrypted code, use from_memory=true with driver connected.");

    return tool_result_t::ok(
        OBFSTR("Kernel module disk-dumped: ") + found_name + OBFSTR(" (") +
        std::to_string(bytes_written) + OBFSTR(" bytes) -> ") + output_path, result);
}

tool_result_t driver_read_kernel_memory(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_kernel_dtb() == 0)
    {
        device->solve_kernel_dtb();
        if (device->get_kernel_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve kernel DTB."));
    }

    std::string addr_str = params["address"].get<std::string>();
    auto addr_opt = sa_parse_address(addr_str);
    if (!addr_opt.has_value())
        return tool_result_t::error(OBFSTR("Invalid address: ") + addr_str);

    std::uint64_t address = static_cast<std::uint64_t>(addr_opt.value());
    if (!is_probably_kernel_address(address))
        return tool_result_t::error(OBFSTR("Address is not a canonical kernel virtual address. Use driver_read_memory for user-mode addresses."));

    std::size_t size = params.value("size", 256);
    if (size > 65536) size = 65536;
    if (size == 0) size = 256;

    bool patch_idb = params.value("patch_idb", false);

    std::vector<std::uint8_t> buffer(size, 0);
    std::size_t bytes_read = device->read_kernel_raw(address, buffer.data(), size);

    if (bytes_read == 0)
        return tool_result_t::error(
            OBFSTR("Failed to read kernel memory at ") +
            sa_format_address(static_cast<uint64_t>(address)));

    std::ostringstream hex_dump;
    hex_dump << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes_read; i++)
    {
        if (i > 0 && (i % 16) == 0) hex_dump << "\n";
        else if (i > 0) hex_dump << " ";
        hex_dump << std::setw(2) << static_cast<int>(buffer[i]);
    }

    std::string ascii;
    ascii.reserve(bytes_read);
    for (std::size_t i = 0; i < bytes_read; i++)
        ascii += (buffer[i] >= 0x20 && buffer[i] < 0x7F) ? static_cast<char>(buffer[i]) : '.';

    std::size_t patched = 0;
    if (patch_idb)
    {
        uint64_t ea = static_cast<uint64_t>(address);
        for (std::size_t i = 0; i < bytes_read; i++)
        {
            if (is_mapped(ea + static_cast<uint64_t>(i)))
            {
                patch_byte(ea + static_cast<uint64_t>(i), buffer[i]);
                patched++;
            }
        }
    }

    json result;
    result["address"]       = sa_format_address(static_cast<uint64_t>(address));
    result["bytes_read"]    = bytes_read;
    result["requested"]     = size;
    result["hex"]           = hex_dump.str();
    result["ascii"]         = ascii;
    result["source"]        = "kernel_memory";
    result["kernel_dtb"]    = sa_format_address(static_cast<uint64_t>(device->get_kernel_dtb()));
    if (patch_idb)
        result["bytes_patched"] = patched;

    return tool_result_t::ok(
        OBFSTR("Read ") + std::to_string(bytes_read) + OBFSTR(" bytes from kernel address ") +
        sa_format_address(static_cast<uint64_t>(address)), result);
}

tool_result_t driver_write_kernel_memory(const json& params)
{
    if (!device || !device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

    if (device->get_kernel_dtb() == 0)
    {
        device->solve_kernel_dtb();
        if (device->get_kernel_dtb() == 0)
            return tool_result_t::error(OBFSTR("Failed to solve kernel DTB."));
    }

    std::string addr_str = params["address"].get<std::string>();
    auto addr_opt = sa_parse_address(addr_str);
    if (!addr_opt.has_value())
        return tool_result_t::error(OBFSTR("Invalid address: ") + addr_str);

    std::uint64_t address = static_cast<std::uint64_t>(addr_opt.value());

    if (!is_probably_kernel_address(address))
        return tool_result_t::error(OBFSTR("Address is not a canonical kernel virtual address. Use driver_write_memory for user-mode addresses."));

    std::vector<std::uint8_t> data;
    std::string parse_error;
    if (!parse_byte_sequence(params["bytes"], data, parse_error))
        return tool_result_t::error(OBFSTR("Invalid bytes format. ") + parse_error);

    if (data.size() > 4096)
        return tool_result_t::error(OBFSTR("Write size exceeds 4096 byte limit."));

    std::size_t written = device->write_kernel_raw(address, data.data(), data.size());

    json result;
    result["address"]       = sa_format_address(static_cast<uint64_t>(address));
    result["bytes_written"] = written;
    result["requested"]     = data.size();
    result["source"]        = "kernel_memory";

    if (written == 0)
        return tool_result_t::error(
            OBFSTR("Failed to write kernel memory at ") +
            sa_format_address(static_cast<uint64_t>(address)));

    return tool_result_t::ok(
        OBFSTR("Wrote ") + std::to_string(written) + OBFSTR(" bytes to kernel address ") +
        sa_format_address(static_cast<uint64_t>(address)), result);
}

tool_result_t driver_allocate_memory(const json& params)
{
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


tool_result_t driver_get_thread_context(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["rax"] = sa_format_address(static_cast<uint64_t>(ctx.rax));
    result["rbx"] = sa_format_address(static_cast<uint64_t>(ctx.rbx));
    result["rcx"] = sa_format_address(static_cast<uint64_t>(ctx.rcx));
    result["rdx"] = sa_format_address(static_cast<uint64_t>(ctx.rdx));
    result["rsi"] = sa_format_address(static_cast<uint64_t>(ctx.rsi));
    result["rdi"] = sa_format_address(static_cast<uint64_t>(ctx.rdi));
    result["rbp"] = sa_format_address(static_cast<uint64_t>(ctx.rbp));
    result["rsp"] = sa_format_address(static_cast<uint64_t>(ctx.rsp));
    result["r8"]  = sa_format_address(static_cast<uint64_t>(ctx.r8));
    result["r9"]  = sa_format_address(static_cast<uint64_t>(ctx.r9));
    result["r10"] = sa_format_address(static_cast<uint64_t>(ctx.r10));
    result["r11"] = sa_format_address(static_cast<uint64_t>(ctx.r11));
    result["r12"] = sa_format_address(static_cast<uint64_t>(ctx.r12));
    result["r13"] = sa_format_address(static_cast<uint64_t>(ctx.r13));
    result["r14"] = sa_format_address(static_cast<uint64_t>(ctx.r14));
    result["r15"] = sa_format_address(static_cast<uint64_t>(ctx.r15));
    result["rip"] = sa_format_address(static_cast<uint64_t>(ctx.rip));
    result["rflags"] = sa_format_address(static_cast<uint64_t>(ctx.rflags));
    result["dr0"] = sa_format_address(static_cast<uint64_t>(ctx.dr0));
    result["dr1"] = sa_format_address(static_cast<uint64_t>(ctx.dr1));
    result["dr2"] = sa_format_address(static_cast<uint64_t>(ctx.dr2));
    result["dr3"] = sa_format_address(static_cast<uint64_t>(ctx.dr3));
    result["dr6"] = sa_format_address(static_cast<uint64_t>(ctx.dr6));
    result["dr7"] = sa_format_address(static_cast<uint64_t>(ctx.dr7));

    return tool_result_t::ok(OBFSTR("Thread context for TID ") + std::to_string(tid), result);
}

tool_result_t driver_set_thread_context(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    voyager::device_t::thread_context ctx{};
    std::uint64_t mask = 0;

    auto set_reg = [&](const char* name, std::uint64_t& reg, int bit) {
        if (params.contains(name)) {
            if (params[name].is_string())
                reg = sa_parse_address(params[name].get<std::string>()).value_or(0);
            else
                reg = params[name].get<std::uint64_t>();
            mask |= (1ULL << bit);
        }
    };

    set_reg("rax", ctx.rax, 0);  set_reg("rbx", ctx.rbx, 1);
    set_reg("rcx", ctx.rcx, 2);  set_reg("rdx", ctx.rdx, 3);
    set_reg("rsi", ctx.rsi, 4);  set_reg("rdi", ctx.rdi, 5);
    set_reg("rbp", ctx.rbp, 6);  set_reg("rsp", ctx.rsp, 7);
    set_reg("r8",  ctx.r8,  8);  set_reg("r9",  ctx.r9,  9);
    set_reg("r10", ctx.r10, 10); set_reg("r11", ctx.r11, 11);
    set_reg("r12", ctx.r12, 12); set_reg("r13", ctx.r13, 13);
    set_reg("r14", ctx.r14, 14); set_reg("r15", ctx.r15, 15);
    set_reg("rip", ctx.rip, 16); set_reg("rflags", ctx.rflags, 17);
    set_reg("dr0", ctx.dr0, 18); set_reg("dr1", ctx.dr1, 19);
    set_reg("dr2", ctx.dr2, 20); set_reg("dr3", ctx.dr3, 21);
    set_reg("dr6", ctx.dr6, 22); set_reg("dr7", ctx.dr7, 23);

    if (mask == 0) return tool_result_t::error(OBFSTR("No registers specified to set"));

    if (!device->set_thread_context(tid, ctx, mask))
        return tool_result_t::error(OBFSTR("Failed to set thread context for TID ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["register_mask"] = sa_format_address(static_cast<uint64_t>(mask));
    return tool_result_t::ok(OBFSTR("Thread context updated for TID ") + std::to_string(tid), result);
}

tool_result_t driver_enumerate_threads(const json& params)
{
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto threads = device->enumerate_threads();
    if (threads.empty())
        return tool_result_t::error(OBFSTR("No threads found or enumeration failed"));

    json result;
    result["process_id"] = device->get_process_id();
    result["thread_count"] = threads.size();
    json arr = json::array();
    for (const auto& t : threads) {
        json tj;
        tj["tid"] = t.tid;
        tj["state"] = t.state;
        if (t.rip) tj["rip"] = sa_format_address(static_cast<uint64_t>(t.rip));
        arr.push_back(tj);
    }
    result["threads"] = arr;
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(threads.size()) + OBFSTR(" threads"), result);
}

tool_result_t driver_suspend_thread(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint32_t prev = 0;
    if (!device->suspend_thread(tid, &prev))
        return tool_result_t::error(OBFSTR("Failed to suspend thread ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["previous_suspend_count"] = prev;
    return tool_result_t::ok(OBFSTR("Thread ") + std::to_string(tid) + OBFSTR(" suspended"), result);
}

tool_result_t driver_resume_thread(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    std::uint32_t prev = 0;
    if (!device->resume_thread(tid, &prev))
        return tool_result_t::error(OBFSTR("Failed to resume thread ") + std::to_string(tid));

    json result;
    result["tid"] = tid;
    result["previous_suspend_count"] = prev;
    return tool_result_t::ok(OBFSTR("Thread ") + std::to_string(tid) + OBFSTR(" resumed"), result);
}

tool_result_t driver_query_memory(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t address = 0;
    if (params.contains("address"))
        address = sa_parse_address(params["address"].get<std::string>()).value_or(0);
    if (address == 0)
        address = device->get_base_address();


    voyager::device_t::memory_region_info info{};
    if (!device->query_memory(address, info))
        return tool_result_t::error(OBFSTR("Failed to query memory at ") + sa_format_address(static_cast<uint64_t>(address)));

    auto prot_str = [](std::uint32_t p) -> std::string {
        std::string s;
        if (p & 0x10) s += "EXECUTE ";
        if (p & 0x20) s += "EXECUTE_READ ";
        if (p & 0x40) s += "EXECUTE_READWRITE ";
        if (p & 0x80) s += "EXECUTE_WRITECOPY ";
        if (p & 0x01) s += "NOACCESS ";
        if (p & 0x02) s += "READONLY ";
        if (p & 0x04) s += "READWRITE ";
        if (p & 0x08) s += "WRITECOPY ";
        if (p & 0x100) s += "GUARD ";
        if (p & 0x200) s += "NOCACHE ";
        if (s.empty()) s = "UNKNOWN";
        return s;
    };

    json result;
    result["address"] = sa_format_address(static_cast<uint64_t>(address));
    result["region_base"] = sa_format_address(static_cast<uint64_t>(info.base));
    result["region_size"] = sa_format_address(static_cast<uint64_t>(info.size));
    result["state"] = (info.state == 0x1000) ? "MEM_COMMIT" :
                      (info.state == 0x2000) ? "MEM_RESERVE" :
                      (info.state == 0x10000) ? "MEM_FREE" : std::to_string(info.state);
    result["protect"] = prot_str(info.protect);
    result["protect_raw"] = info.protect;
    result["type"] = (info.type == 0x20000) ? "MEM_PRIVATE" :
                     (info.type == 0x40000) ? "MEM_MAPPED" :
                     (info.type == 0x1000000) ? "MEM_IMAGE" : std::to_string(info.type);
    result["allocation_base"] = sa_format_address(static_cast<uint64_t>(info.allocation_base));
    result["allocation_protect"] = prot_str(info.allocation_protect);

    return tool_result_t::ok(OBFSTR("Memory region info"), result);
}

tool_result_t driver_protect_memory(const json& params)
{
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


    std::uint32_t new_protect = 0x40;
    if (params.contains("protect")) {
        if (params["protect"].is_string())
            new_protect = static_cast<std::uint32_t>(sa_parse_address(params["protect"].get<std::string>()).value_or(0x40));
        else
            new_protect = params["protect"].get<std::uint32_t>();
    }

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

tool_result_t driver_enumerate_memory_regions(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint64_t start = 0;
    if (params.contains("start"))
        start = sa_parse_address(params["start"].get<std::string>()).value_or(0);

    std::uint64_t end_addr = 0;
    if (params.contains("end"))
        end_addr = sa_parse_address(params["end"].get<std::string>()).value_or(0);

    bool include_all = false;
    if (params.contains("include_all") && params["include_all"].is_boolean())
        include_all = params["include_all"].get<bool>();

    auto regions = device->enumerate_memory_regions(start, end_addr, include_all);
    if (regions.empty())
        return tool_result_t::error(OBFSTR("No memory regions found"));

    auto prot_str = [](std::uint32_t p) -> std::string {
        if (p & 0x40) return "ERW";
        if (p & 0x20) return "ER";
        if (p & 0x10) return "E";
        if (p & 0x04) return "RW";
        if (p & 0x02) return "R";
        if (p & 0x01) return "NA";
        return std::to_string(p);
    };

    json result;
    result["process_id"] = device->get_process_id();
    result["region_count"] = regions.size();
    json arr = json::array();
    for (const auto& r : regions) {
        json rj;
        rj["base"] = sa_format_address(static_cast<uint64_t>(r.base));
        rj["size"] = sa_format_address(static_cast<uint64_t>(r.size));
        rj["state"] = (r.state == 0x1000) ? "COMMIT" :
                      (r.state == 0x2000) ? "RESERVE" : "FREE";
        rj["protect"] = prot_str(r.protect);
        rj["type"] = (r.type == 0x20000) ? "PRIVATE" :
                     (r.type == 0x40000) ? "MAPPED" :
                     (r.type == 0x1000000) ? "IMAGE" : std::to_string(r.type);
        arr.push_back(rj);
    }
    result["regions"] = arr;
    return tool_result_t::ok(OBFSTR("Enumerated ") + std::to_string(regions.size()) + OBFSTR(" regions"), result);
}

tool_result_t driver_read_peb(const json& params)
{
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

tool_result_t driver_spoof_debug_flags(const json& params)
{
    (void)params;
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint32_t flags = 0;
    if (!device->spoof_debug_flags(&flags))
        return tool_result_t::error(OBFSTR("Failed to spoof debug flags"));

    json result;
    result["process_id"] = device->get_process_id();
    result["cleared_debug_port"] = (flags & 1) != 0;
    result["cleared_being_debugged"] = (flags & 2) != 0;
    result["cleared_nt_global_flag"] = (flags & 4) != 0;
    return tool_result_t::ok(OBFSTR("Anti-debug flags cleared"), result);
}

tool_result_t driver_set_hw_breakpoint(const json& params)
{
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

    if (!device->set_hardware_breakpoint(tid, index, address, type, size))
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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Thread ID (tid) is required and must be a decimal integer or 0x-prefixed hex."));
    const std::uint32_t tid = *tid_opt;

    int index = 0;
    if (params.contains("index")) index = params["index"].get<int>();

    if (!device->clear_hardware_breakpoint(tid, index))
        return tool_result_t::error(OBFSTR("Failed to clear hardware breakpoint"));

    json result;
    result["tid"] = tid;
    result["index"] = index;
    return tool_result_t::ok(OBFSTR("Hardware breakpoint cleared on DR") + std::to_string(index), result);
}

tool_result_t driver_resolve_export(const json& params)
{
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
    std::string                             trigger_info;
    std::string                             error;
};

class DeferredActionManager
{
public:
    static DeferredActionManager& instance();
    ~DeferredActionManager();

    void shutdown();
    int  register_action(std::unique_ptr<deferred_action_t> action);
    bool cancel_action(int id);
    const deferred_action_t*                get_action(int id) const;
    std::vector<const deferred_action_t*>   get_all_actions() const;

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
    std::map<int, std::thread>                        _watchers;
    mutable std::mutex                                _mutex;
    int                                               _next_id = 1;
    std::atomic<bool>                                 _shutdown{false};
};


static const std::vector<mcp_standalone::tool_def_t>* s_deferred_tool_list = nullptr;

static const mcp_standalone::tool_def_t* get_deferred_tool_def(const std::string& name)
{
    if (!s_deferred_tool_list) return nullptr;
    for (const auto& t : *s_deferred_tool_list)
        if (t.name == name) return &t;
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
    std::lock_guard<std::mutex> lock(_mutex);
    for (auto& [id, action] : _actions)
    {
        auto st = action->status.load();
        if (st == deferred_status::pending || st == deferred_status::watching)
            action->status.store(deferred_status::cancelled);
    }
    for (auto& [id, thread] : _watchers)
    {
        if (thread.joinable())
            thread.join();
    }
    _watchers.clear();
}

int DeferredActionManager::register_action(std::unique_ptr<deferred_action_t> action)
{
    std::lock_guard<std::mutex> lock(_mutex);
    int id = _next_id++;
    action->id = id;
    action->created = std::chrono::steady_clock::now();
    action->status.store(deferred_status::pending);

    _actions[id] = std::move(action);

    _watchers[id] = std::thread(&DeferredActionManager::watcher_thread_func, this, id);

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
        auto wit = _watchers.find(id);
        if (wit != _watchers.end() && wit->second.joinable())
        {
            std::thread th = std::move(wit->second);
            _watchers.erase(wit);
            lock.unlock();
            th.join();
        }
        return true;
    }
    return false;
}

const deferred_action_t* DeferredActionManager::get_action(int id) const
{
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _actions.find(id);
    return (it != _actions.end()) ? it->second.get() : nullptr;
}

std::vector<const deferred_action_t*> DeferredActionManager::get_all_actions() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<const deferred_action_t*> result;
    for (const auto& [id, action] : _actions)
        result.push_back(action.get());
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

    for (const auto& tc : action.tool_calls)
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

        action.results.push_back(std::move(result));
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
    }

    action->status.store(deferred_status::watching);

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
            action->status.store(deferred_status::timed_out);
            action->error = OBFSTR("Timed out waiting for ") + action->condition_type +
                OBFSTR(": ") + action->target_name;
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

                action->trigger_info = trigger_context.dump();
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

                action->trigger_info = trigger_context.dump();
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
            for (const auto& r : action->results)
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
                std::count_if(action->results.begin(), action->results.end(),
                    [](const deferred_action_result_t& r) { return r.success; }),
                action->results.size());

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
        return tool_result_t::error(OBFSTR("'actions' array is required with at least one tool call. Format: [{\"tool\":\"driver_read_memory\",\"params\":{...}}]."));

    auto action = std::make_unique<deferred_action_t>();
    action->condition_type = wait_for;
    action->target_name = target;
    action->timeout_seconds = timeout;
    action->poll_interval_ms = poll_interval;

    for (const auto& act : normalized["actions"])
    {
        if (!act.contains("tool") || !act["tool"].is_string())
            return tool_result_t::error(OBFSTR("Each action must have a string 'tool' field (full tool name, e.g. 'driver_read_memory')."));

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
    int action_id = DeferredActionManager::instance().register_action(std::move(action));

    json result;
    result["action_id"] = action_id;
    result["condition"] = wait_for;
    result["target"] = target;
    result["timeout_seconds"] = timeout;
    result["poll_interval_ms"] = poll_interval;
    result["num_queued_actions"] = queued_actions;
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
    auto actions = DeferredActionManager::instance().get_all_actions();

    json arr = json::array();
    for (const auto* action : actions)
    {
        json entry;
        entry["id"] = action->id;
        entry["condition"] = action->condition_type;
        entry["target"] = action->target_name;
        entry["status"] = deferred_status_to_string(action->status.load());
        entry["num_actions"] = action->tool_calls.size();
        entry["timeout_seconds"] = action->timeout_seconds;

        if (!action->trigger_info.empty())
        {
            try { entry["trigger_info"] = json::parse(action->trigger_info); }
            catch (...) { entry["trigger_info"] = action->trigger_info; }
        }

        if (!action->error.empty())
            entry["error"] = action->error;

        entry["num_results"] = action->results.size();
        int succeeded = 0;
        for (const auto& r : action->results)
            if (r.success) succeeded++;
        entry["succeeded"] = succeeded;
        entry["failed"] = static_cast<int>(action->results.size()) - succeeded;

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

    const auto* action = DeferredActionManager::instance().get_action(id);
    if (!action)
        return tool_result_t::error(OBFSTR("Action #") + std::to_string(id) + OBFSTR(" not found"));

    json result;
    result["action_id"] = action->id;
    result["condition"] = action->condition_type;
    result["target"] = action->target_name;
    result["status"] = deferred_status_to_string(action->status.load());

    if (!action->trigger_info.empty())
    {
        try { result["trigger_info"] = json::parse(action->trigger_info); }
        catch (...) { result["trigger_info"] = action->trigger_info; }
    }

    if (!action->error.empty())
        result["error"] = action->error;

    json results_arr = json::array();
    for (const auto& r : action->results)
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
    for (const auto& r : action->results)
        if (r.success) succeeded++;
    result["succeeded"] = succeeded;
    result["failed"] = static_cast<int>(action->results.size()) - succeeded;
    result["total_actions"] = action->tool_calls.size();

    std::string status_str = deferred_status_to_string(action->status.load());
    return tool_result_t::ok(
        OBFSTR("Deferred action #") + std::to_string(id) + OBFSTR(": ") + status_str, result);
}


static std::string format_recon_ip(const std::uint8_t* addr, std::uint32_t af) {
    char buf[64] = {};
    if (af == 23) {
        qsnprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    } else {
        qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

static const char* tcp_state_str(std::uint32_t state) {
    static const char* names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
        "TIME_WAIT", "DELETE_TCB"
    };
    if (state < 12) return names[state];
    return "UNKNOWN";
}

static std::string reg_index_to_name(std::uint32_t idx) {
    static const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    if (idx < 16) return names[idx];
    return "reg" + std::to_string(idx);
}

tool_result_t driver_enumerate_wfp_callouts(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string filter;
    if (params.contains("filter_module"))
        filter = params["filter_module"].get<std::string>();

    auto callouts = device->enumerate_wfp_callouts(filter);
    if (callouts.empty())
        return tool_result_t::ok(OBFSTR("No WFP callouts found"), json::object());

    json result;
    result["count"] = callouts.size();
    json arr = json::array();
    for (const auto& c : callouts) {
        json entry;
        entry["callout_id"] = c.callout_id;
        entry["callout_key"] = c.callout_key_str;
        entry["applicable_layer"] = c.applicable_layer_str;
        entry["flags"] = c.flags;
        entry["owning_module"] = c.owning_module;
        if (c.classify_fn != 0)
            entry["classify_fn"] = sa_format_address(static_cast<uint64_t>(c.classify_fn));
        if (c.notify_fn != 0)
            entry["notify_fn"] = sa_format_address(static_cast<uint64_t>(c.notify_fn));
        if (c.flow_delete_fn != 0)
            entry["flow_delete_fn"] = sa_format_address(static_cast<uint64_t>(c.flow_delete_fn));
        if (c.owning_module_base != 0)
            entry["module_base"] = sa_format_address(static_cast<uint64_t>(c.owning_module_base));
        arr.push_back(std::move(entry));
    }
    result["callouts"] = std::move(arr);

    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(callouts.size()) + OBFSTR(" WFP callout(s)"), result);
}

tool_result_t driver_get_socket_handles(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    std::uint32_t target_pid = 0;
    if (params.contains("target_pid"))
        target_pid = params["target_pid"].get<std::uint32_t>();

    auto sockets = device->get_socket_handles(target_pid);
    if (sockets.empty())
        return tool_result_t::ok(OBFSTR("No AFD socket handles found"), json::object());

    json result;
    result["count"] = sockets.size();
    json arr = json::array();
    for (const auto& s : sockets) {
        json entry;
        entry["handle"] = sa_format_address(static_cast<uint64_t>(s.handle_value));
        entry["afd_endpoint"] = sa_format_address(static_cast<uint64_t>(s.afd_endpoint_addr));
        entry["pid"] = s.pid;
        entry["protocol"] = (s.protocol == 6) ? "TCP" : (s.protocol == 17) ? "UDP" : std::to_string(s.protocol);
        entry["state"] = tcp_state_str(s.state);
        entry["address_family"] = (s.address_family == 2) ? "IPv4" : (s.address_family == 23) ? "IPv6" : "unknown";
        entry["local"] = format_recon_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        entry["remote"] = format_recon_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        arr.push_back(std::move(entry));
    }
    result["sockets"] = std::move(arr);

    return tool_result_t::ok(
        OBFSTR("Found ") + std::to_string(sockets.size()) + OBFSTR(" socket handle(s)"), result);
}

tool_result_t driver_sniff_network_buffers(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;


    if (params.contains("operation")) {
        std::string op = params["operation"].get<std::string>();

        if (op == "stop") {
            if (!device->sniff_net_buffers_stop())
                return tool_result_t::error(OBFSTR("Failed to stop sniff session"));
            return tool_result_t::ok(OBFSTR("Sniff session stopped"), json::object());
        }
        if (op == "get" || op == "results") {
            bool active = false;
            auto captures = device->sniff_net_buffers_get(active);

            json result;
            result["active"] = active;
            result["capture_count"] = captures.size();
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
            result["captures"] = std::move(arr);

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

    json result;
    result["status"] = "started";
    result["target_address"] = sa_format_address(static_cast<uint64_t>(address));
    result["buffer_register"] = reg_index_to_name(buf_reg);
    result["size_register"] = reg_index_to_name(size_reg);
    result["max_captures"] = max_packets;
    result["bp_index"] = bp_index;
    result["note"] = OBFSTR("Sniff session initialized. The HW breakpoint must be set separately via "
        "driver_set_hw_breakpoint on the target address. Then poll with operation='get' to retrieve captures. "
        "After each BP hit, read the buffer from memory using driver_read_memory at the register value, "
        "then call this tool with operation='store' to record it.");

    return tool_result_t::ok(OBFSTR("Sniff session started"), result);
}

tool_result_t driver_dump_tcpip_connections(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t target_pid = 0;
    if (params.contains("target_pid"))
        target_pid = params["target_pid"].get<std::uint32_t>();

    std::uint32_t filter_proto = 0;
    if (params.contains("filter_protocol")) {
        auto& fp = params["filter_protocol"];
        if (fp.is_number()) {
            filter_proto = fp.get<std::uint32_t>();
        } else if (fp.is_string()) {
            std::string s = fp.get<std::string>();
            std::transform(s.begin(), s.end(), s.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (s == "tcp") filter_proto = 6;
            else if (s == "udp") filter_proto = 17;
        }
    }

    auto connections = device->dump_tcpip_connections(target_pid, filter_proto);
    if (connections.empty())
        return tool_result_t::ok(OBFSTR("No connections found"), json::object());

    json result;
    result["count"] = connections.size();
    if (target_pid != 0) result["filtered_pid"] = target_pid;


    std::uint32_t tcp_count = 0, udp_count = 0;
    json arr = json::array();
    for (const auto& c : connections) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = (c.protocol == 6) ? "TCP" : (c.protocol == 17) ? "UDP" : std::to_string(c.protocol);
        entry["state"] = tcp_state_str(c.state);
        entry["local"] = format_recon_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        entry["remote"] = format_recon_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        entry["address_family"] = (c.address_family == 2) ? "IPv4" : "IPv6";

        if (c.create_time != 0)
            entry["create_time"] = c.create_time;
        if (c.tcb_address != 0)
            entry["tcb_address"] = sa_format_address(static_cast<uint64_t>(c.tcb_address));
        if (c.bytes_in != 0 || c.bytes_out != 0) {
            entry["bytes_in"] = c.bytes_in;
            entry["bytes_out"] = c.bytes_out;
        }

        if (c.protocol == 6) tcp_count++;
        else if (c.protocol == 17) udp_count++;

        arr.push_back(std::move(entry));
    }
    result["connections"] = std::move(arr);
    result["tcp_count"] = tcp_count;
    result["udp_count"] = udp_count;

    return tool_result_t::ok(
        OBFSTR("Kernel netstat: ") + std::to_string(connections.size()) +
        OBFSTR(" connection(s) (") + std::to_string(tcp_count) + OBFSTR(" TCP, ") +
        std::to_string(udp_count) + OBFSTR(" UDP)"), result);
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

static std::string format_mac(const std::uint8_t* mac) {
    char buf[24];
    qsnprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::uint32_t proto_from_param(const json& params, const char* key) {
    if (!params.contains(key)) return 0;
    auto& v = params[key];
    if (v.is_number()) return v.get<std::uint32_t>();
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (s == "tcp") return 6;
        if (s == "udp") return 17;
    }
    return 0;
}

tool_result_t driver_inject_packet(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t direction = 1;
    if (params.contains("direction")) {
        auto& d = params["direction"];
        if (d.is_number()) direction = d.get<std::uint32_t>();
        else if (d.is_string()) {
            std::string s = d.get<std::string>();
            if (s == "inbound" || s == "in") direction = 0;
        }
    }

    std::uint32_t protocol = proto_from_param(params, "protocol");
    if (protocol == 0) protocol = 6;

    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, &af);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, &af);

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t tcp_flags = params.value("tcp_flags", 0u);
    std::uint32_t tcp_seq = params.value("tcp_seq", 0u);
    std::uint32_t tcp_ack = params.value("tcp_ack", 0u);


    std::vector<std::uint8_t> payload_bytes;
    if (params.contains("payload")) {
        std::string error;
        if (!parse_byte_sequence(params["payload"], payload_bytes, error))
            return tool_result_t::error(OBFSTR("Invalid payload: ") + error);
    }
    if (payload_bytes.empty())
        return tool_result_t::error(OBFSTR("Payload is required"));

    bool ok = device->inject_packet(direction, protocol, af, src_port, dst_port,
                                     src_addr, dst_addr, payload_bytes.data(),
                                     static_cast<std::uint32_t>(payload_bytes.size()),
                                     tcp_flags, tcp_seq, tcp_ack);
    if (!ok) return tool_result_t::error(OBFSTR("Packet injection failed"));

    json result;
    result["direction"] = direction == 0 ? "inbound" : "outbound";
    result["protocol"] = protocol == 6 ? "TCP" : "UDP";
    result["payload_size"] = payload_bytes.size();
    result["dst_port"] = dst_port;
    return tool_result_t::ok(OBFSTR("Packet injected successfully"), result);
}

tool_result_t driver_modify_packet_rule(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_packet_mod_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["direction"] = r.direction == 0 ? "in" : r.direction == 1 ? "out" : "both";
            e["protocol"] = r.protocol == 6 ? "TCP" : r.protocol == 17 ? "UDP" : "any";
            e["port"] = r.port;
            e["pid"] = r.pid;
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Packet modification rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code = 0;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t dir = 2;
    if (params.contains("direction")) {
        std::string ds = params["direction"].get<std::string>();
        if (ds == "in" || ds == "inbound") dir = 0;
        else if (ds == "out" || ds == "outbound") dir = 1;
    }

    std::uint32_t proto = proto_from_param(params, "protocol");
    std::uint32_t port = params.value("port", 0u);
    std::uint32_t pid = params.value("pid", 0u);

    std::vector<std::uint8_t> pattern_bytes, replace_bytes;
    if (params.contains("pattern")) {
        std::string err;
        if (!parse_byte_sequence(params["pattern"], pattern_bytes, err))
            return tool_result_t::error(OBFSTR("Invalid pattern: ") + err);
    }
    if (params.contains("replacement")) {
        std::string err;
        if (!parse_byte_sequence(params["replacement"], replace_bytes, err))
            return tool_result_t::error(OBFSTR("Invalid replacement: ") + err);
    }

    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id"))
        rule_id = params["rule_id"].get<std::uint32_t>();

    std::uint32_t out_id = 0;
    bool ok = device->packet_mod_rule_op(op_code, rule_id, dir, proto, port, pid,
                                          pattern_bytes.data(), static_cast<std::uint32_t>(pattern_bytes.size()),
                                          replace_bytes.data(), static_cast<std::uint32_t>(replace_bytes.size()),
                                          &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("Packet mod rule operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("Packet mod rule ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_redirect_traffic(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_redirect_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["protocol"] = r.protocol == 6 ? "TCP" : r.protocol == 17 ? "UDP" : "any";
            e["match_port"] = r.match_port;
            e["redirect_port"] = r.redirect_port;
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Redirect rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code = 0;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t proto = proto_from_param(params, "protocol");
    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id")) {
        rule_id = params["rule_id"].get<std::uint32_t>();
    }
    std::uint32_t match_port = params.value("match_port", 0u);
    std::uint32_t redirect_port = params.value("redirect_port", 0u);
    std::uint8_t match_addr[16] = {}, redir_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("match_addr")) parse_ip_string(params["match_addr"].get<std::string>(), match_addr, &af);
    if (params.contains("redirect_addr")) parse_ip_string(params["redirect_addr"].get<std::string>(), redir_addr, &af);

    std::uint32_t out_id = 0;
    bool ok = device->traffic_redirect_op(op_code, rule_id, proto, match_port, match_addr,
                                           redirect_port, redir_addr, af, &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("Redirect operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("Traffic redirect ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_reassemble_stream(const json& params)
{
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

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t pid = params.value("pid", 0u);
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, nullptr);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, nullptr);

    std::vector<std::uint8_t> data;
    std::uint32_t packets = 0, truncated = 0;
    bool ok = device->stream_reassemble_op(op_code, src_port, dst_port, pid,
                                            src_addr, dst_addr, &data, &packets, &truncated);
    if (!ok) return tool_result_t::error(OBFSTR("Stream operation failed"));

    json result;
    result["operation"] = operation;
    result["total_packets"] = packets;
    if (truncated) result["truncated"] = true;
    if (!data.empty()) {
        result["stream_size"] = data.size();

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

tool_result_t driver_deep_inspect(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint32_t filter_port = params.value("filter_port", 0u);
    std::uint32_t flags = 0;
    if (params.value("http_only", false)) flags |= 1;
    if (params.value("tls_only", false)) flags |= 2;
    if (params.value("dns_only", false)) flags |= 4;

    auto results = device->get_dpi_results(filter_pid, filter_proto, filter_port, flags);
    if (results.empty())
        return tool_result_t::ok(OBFSTR("No DPI results"), json::object());

    static const char* http_methods[] = {"NONE", "GET", "POST", "PUT", "DELETE", "HEAD", "OTHER"};
    json j;
    j["count"] = results.size();
    json arr = json::array();
    for (const auto& d : results) {
        json e;
        e["direction"] = d.direction == 0 ? "in" : "out";
        e["protocol"] = d.protocol == 6 ? "TCP" : d.protocol == 17 ? "UDP" : std::to_string(d.protocol);
        e["pid"] = d.pid;
        e["src"] = format_recon_ip(d.src_addr, d.af) + ":" + std::to_string(d.src_port);
        e["dst"] = format_recon_ip(d.dst_addr, d.af) + ":" + std::to_string(d.dst_port);
        e["payload_size"] = d.payload_size;
        if (d.is_http) {
            e["type"] = "HTTP";
            e["http_method"] = (d.http_method < 7) ? http_methods[d.http_method] : "?";
            if (!d.http_host.empty()) e["http_host"] = d.http_host;
            if (!d.http_path.empty()) e["http_path"] = d.http_path;
        }
        if (d.is_tls) {
            e["type"] = "TLS";
            char ver[16];
            qsnprintf(ver, sizeof(ver), "0x%04X", d.tls_version);
            e["tls_version"] = ver;
            if (!d.tls_sni.empty()) e["tls_sni"] = d.tls_sni;
            e["tls_content_type"] = d.tls_content_type;
        }
        if (d.is_dns) e["type"] = "DNS";
        if (d.tcp_flags != 0) {
            std::string fl;
            if (d.tcp_flags & 0x02) fl += "SYN ";
            if (d.tcp_flags & 0x10) fl += "ACK ";
            if (d.tcp_flags & 0x04) fl += "RST ";
            if (d.tcp_flags & 0x01) fl += "FIN ";
            if (d.tcp_flags & 0x08) fl += "PSH ";
            e["tcp_flags"] = fl;
        }
        arr.push_back(std::move(e));
    }
    j["packets"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Deep packet inspection: ") + std::to_string(results.size()) + OBFSTR(" packets"), j);
}

tool_result_t driver_intercept_hold(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "status");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "get" || operation == "get_held") {
        auto held = device->get_held_packets();
        json result;
        result["held_count"] = held.size();
        json arr = json::array();
        for (const auto& h : held) {
            json e;
            e["hold_id"] = h.hold_id;
            e["direction"] = h.direction == 0 ? "in" : "out";
            e["protocol"] = h.protocol == 6 ? "TCP" : "UDP";
            e["pid"] = h.pid;
            e["src"] = format_recon_ip(h.src_addr, h.af) + ":" + std::to_string(h.src_port);
            e["dst"] = format_recon_ip(h.dst_addr, h.af) + ":" + std::to_string(h.dst_port);
            e["payload_size"] = h.payload_size;
            if (!h.payload.empty()) {
                std::string hex;
                size_t preview = (h.payload.size() > 128) ? 128 : h.payload.size();
                for (size_t i = 0; i < preview; i++) {
                    char buf[4];
                    qsnprintf(buf, sizeof(buf), "%02X ", h.payload[i]);
                    hex += buf;
                }
                e["payload_hex_preview"] = hex;
            }
            arr.push_back(std::move(e));
        }
        result["packets"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Held packets: ") + std::to_string(held.size()), result);
    }

    std::uint32_t op_code;
    if (operation == "enable") op_code = 0;
    else if (operation == "disable") op_code = 1;
    else if (operation == "release") op_code = 3;
    else if (operation == "drop") op_code = 4;
    else if (operation == "modify" || operation == "modify_release") op_code = 5;
    else if (operation == "status") {
        std::uint32_t held_count = 0;
        bool active = false;
        device->intercept_op(2, 0, 0, 0, 0, nullptr, 0, &held_count, &active);
        json r;
        r["intercepting"] = active;
        r["held_count"] = held_count;
        return tool_result_t::ok(active ? OBFSTR("Intercept active") : OBFSTR("Intercept inactive"), r);
    }
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_port = params.value("filter_port", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint64_t hold_id = params.value("hold_id", std::uint64_t(0));

    std::vector<std::uint8_t> mod_payload;
    if (op_code == 5 && params.contains("modify_payload")) {
        std::string err;
        if (!parse_byte_sequence(params["modify_payload"], mod_payload, err))
            return tool_result_t::error(OBFSTR("Invalid modify_payload: ") + err);
    }

    std::uint32_t held_count = 0;
    bool active = false;
    bool ok = device->intercept_op(op_code, filter_pid, filter_port, filter_proto, hold_id,
                                    mod_payload.empty() ? nullptr : mod_payload.data(),
                                    static_cast<std::uint32_t>(mod_payload.size()),
                                    &held_count, &active);
    if (!ok) return tool_result_t::error(OBFSTR("Intercept operation failed"));

    json result;
    result["operation"] = operation;
    result["intercepting"] = active;
    result["held_count"] = held_count;
    return tool_result_t::ok(OBFSTR("Intercept ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_kill_connection(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t af = 2;
    if (params.contains("src_addr")) parse_ip_string(params["src_addr"].get<std::string>(), src_addr, &af);
    if (params.contains("dst_addr")) parse_ip_string(params["dst_addr"].get<std::string>(), dst_addr, &af);

    std::uint32_t src_port = params.value("src_port", 0u);
    std::uint32_t dst_port = params.value("dst_port", 0u);
    std::uint32_t proto = proto_from_param(params, "protocol");
    if (proto == 0) proto = 6;
    std::uint32_t pid = params.value("pid", 0u);

    bool ok = device->kill_connection(proto, af, src_port, dst_port, src_addr, dst_addr, pid);
    if (!ok) return tool_result_t::error(OBFSTR("Connection kill failed"));

    json result;
    result["killed"] = true;
    result["src_port"] = src_port;
    result["dst_port"] = dst_port;
    return tool_result_t::ok(OBFSTR("TCP connection killed via RST injection"), result);
}

tool_result_t driver_spoof_dns(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "list");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "list") {
        auto rules = device->list_dns_spoof_rules();
        json result;
        result["rule_count"] = rules.size();
        json arr = json::array();
        for (const auto& r : rules) {
            json e;
            e["rule_id"] = r.rule_id;
            e["domain"] = r.domain;
            e["address_family"] = r.af == 2 ? "IPv4" : "IPv6";
            e["match_count"] = r.match_count;
            e["active"] = r.active != 0;
            e["ttl"] = r.ttl;
            arr.push_back(std::move(e));
        }
        result["rules"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("DNS spoof rules: ") + std::to_string(rules.size()), result);
    }

    std::uint32_t op_code;
    if (operation == "add") op_code = 0;
    else if (operation == "remove") op_code = 1;
    else if (operation == "clear") op_code = 3;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t rule_id = 0;
    if (op_code == 1 && params.contains("rule_id")) {
        rule_id = params["rule_id"].get<std::uint32_t>();
    }

    std::string domain = params.value("domain", "");
    std::uint8_t spoof[16] = {};
    std::uint32_t af = 2;
    if (params.contains("spoof_addr")) parse_ip_string(params["spoof_addr"].get<std::string>(), spoof, &af);
    std::uint32_t ttl = params.value("ttl", 300u);

    std::uint32_t out_id = 0;
    bool ok = device->dns_spoof_op(op_code, rule_id, domain.c_str(), spoof, af, ttl, &out_id);
    if (!ok) return tool_result_t::error(OBFSTR("DNS spoof operation failed"));

    json result;
    result["operation"] = operation;
    if (op_code == 0) result["rule_id"] = out_id;
    return tool_result_t::ok(OBFSTR("DNS spoof ") + operation + OBFSTR(" success"), result);
}

tool_result_t driver_bandwidth_monitor(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "status");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::uint32_t op_code;
    if (operation == "start") op_code = 0;
    else if (operation == "stop") op_code = 1;
    else if (operation == "status" || operation == "get" || operation == "stats") op_code = 2;
    else if (operation == "reset") op_code = 3;
    else if (operation == "per_process") op_code = 4;
    else return tool_result_t::error(OBFSTR("Unknown operation: ") + operation);

    std::uint32_t filter_pid = params.value("filter_pid", 0u);

    if (op_code == 4) {
        auto procs = device->get_bw_per_process(filter_pid);
        json result;
        result["process_count"] = procs.size();
        json arr = json::array();
        for (const auto& p : procs) {
            json e;
            e["pid"] = p.pid;
            e["bytes_sent"] = p.bytes_sent;
            e["bytes_recv"] = p.bytes_recv;
            e["packets_sent"] = p.packets_sent;
            e["packets_recv"] = p.packets_recv;
            arr.push_back(std::move(e));
        }
        result["processes"] = std::move(arr);
        return tool_result_t::ok(OBFSTR("Per-process bandwidth: ") + std::to_string(procs.size()) + OBFSTR(" processes"), result);
    }

    voyager::device_t::bw_stats stats{};
    bool ok = device->bw_monitor_op(op_code, filter_pid, &stats);
    if (!ok) return tool_result_t::error(OBFSTR("Bandwidth monitor operation failed"));

    json result;
    result["operation"] = operation;
    result["monitoring_active"] = stats.active;
    result["total_bytes_sent"] = stats.total_bytes_sent;
    result["total_bytes_recv"] = stats.total_bytes_recv;
    result["total_packets_sent"] = stats.total_packets_sent;
    result["total_packets_recv"] = stats.total_packets_recv;
    result["bytes_per_second_in"] = stats.bps_in;
    result["bytes_per_second_out"] = stats.bps_out;
    return tool_result_t::ok(OBFSTR("Bandwidth monitor ") + operation, result);
}

tool_result_t driver_list_interfaces(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    auto ifaces = device->enumerate_interfaces();
    if (ifaces.empty())
        return tool_result_t::ok(OBFSTR("No network interfaces found"), json::object());

    json result;
    result["count"] = ifaces.size();
    json arr = json::array();
    for (const auto& iface : ifaces) {
        json e;
        e["index"] = iface.if_index;
        e["type"] = iface.if_type == 6 ? "Ethernet" : iface.if_type == 71 ? "WiFi" :
                    iface.if_type == 24 ? "Loopback" : std::to_string(iface.if_type);
        e["mtu"] = iface.mtu;
        e["status"] = iface.oper_status == 1 ? "Up" : "Down";
        e["speed_mbps"] = iface.speed / 1000000;
        e["mac"] = format_mac(iface.mac_addr);
        char ipv4[20];
        qsnprintf(ipv4, sizeof(ipv4), "%u.%u.%u.%u", iface.ipv4_addr[0], iface.ipv4_addr[1],
                  iface.ipv4_addr[2], iface.ipv4_addr[3]);
        e["ipv4"] = ipv4;
        if (!iface.name.empty()) e["name"] = iface.name;
        if (!iface.description.empty()) e["description"] = iface.description;
        e["in_bytes"] = iface.in_octets;
        e["out_bytes"] = iface.out_octets;
        arr.push_back(std::move(e));
    }
    result["interfaces"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Network interfaces: ") + std::to_string(ifaces.size()), result);
}

tool_result_t driver_export_pcap(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::uint32_t filter_pid = params.value("filter_pid", 0u);
    std::uint32_t filter_proto = proto_from_param(params, "filter_protocol");
    std::uint32_t max_packets = params.value("max_packets", 64u);

    voyager::device_t::pcap_export_result pcap{};
    bool ok = device->export_pcap(filter_pid, filter_proto, max_packets, &pcap);
    if (!ok) return tool_result_t::error(OBFSTR("PCAP export failed"));


    if (params.contains("output_path")) {
        std::string path = params["output_path"].get<std::string>();
        FILE* fp = fopen(path.c_str(), "wb");
        if (fp) {
            fwrite(&pcap.header, 1, sizeof(pcap.header), fp);
            for (const auto& pkt : pcap.packets) {
                std::uint32_t hdr[4] = { pkt.ts_sec, pkt.ts_usec,
                    static_cast<std::uint32_t>(pkt.data.size()),
                    static_cast<std::uint32_t>(pkt.data.size()) };
                fwrite(hdr, 1, sizeof(hdr), fp);
                fwrite(pkt.data.data(), 1, pkt.data.size(), fp);
            }
            fclose(fp);
        }

        json result;
        result["output_path"] = path;
        result["packet_count"] = pcap.packets.size();
        return tool_result_t::ok(OBFSTR("PCAP saved: ") + std::to_string(pcap.packets.size()) +
            OBFSTR(" packets -> ") + path, result);
    }

    json result;
    result["packet_count"] = pcap.packets.size();
    result["link_type"] = pcap.header.network;
    json arr = json::array();
    for (const auto& pkt : pcap.packets) {
        json e;
        e["ts_sec"] = pkt.ts_sec;
        e["ts_usec"] = pkt.ts_usec;
        e["size"] = pkt.data.size();
        if (!pkt.data.empty()) {
            std::string hex;
            size_t preview = (pkt.data.size() > 64) ? 64 : pkt.data.size();
            for (size_t i = 0; i < preview; i++) {
                char buf[4];
                qsnprintf(buf, sizeof(buf), "%02X ", pkt.data[i]);
                hex += buf;
            }
            e["hex_preview"] = hex;
        }
        arr.push_back(std::move(e));
    }
    result["packets"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("PCAP export: ") + std::to_string(pcap.packets.size()) + OBFSTR(" packets"), result);
}

tool_result_t driver_network_fingerprint(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected"));

    std::string operation = params.value("operation", "get");
    std::transform(operation.begin(), operation.end(), operation.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (operation == "enable") {
        bool ok = device->fingerprint_op(0);
        return ok ? tool_result_t::ok(OBFSTR("Fingerprinting enabled"), json::object())
                  : tool_result_t::error(OBFSTR("Failed to enable fingerprinting"));
    }
    if (operation == "disable") {
        bool ok = device->fingerprint_op(1);
        return ok ? tool_result_t::ok(OBFSTR("Fingerprinting disabled"), json::object())
                  : tool_result_t::error(OBFSTR("Failed to disable fingerprinting"));
    }


    auto fps = device->get_fingerprints();
    if (fps.empty())
        return tool_result_t::ok(OBFSTR("No fingerprint results"), json::object());

    json result;
    result["count"] = fps.size();
    json arr = json::array();
    for (const auto& f : fps) {
        json e;
        e["remote"] = format_recon_ip(f.remote_addr, f.af);
        e["ttl"] = f.ttl;
        e["window_size"] = f.window_size;
        e["mss"] = f.mss;
        e["window_scale"] = f.window_scale;
        e["df_flag"] = f.df_flag != 0;
        e["sack"] = f.sack_permitted != 0;
        if (!f.os_guess.empty()) e["os_guess"] = f.os_guess;
        arr.push_back(std::move(e));
    }
    result["fingerprints"] = std::move(arr);

    return tool_result_t::ok(OBFSTR("Network fingerprints: ") + std::to_string(fps.size()) + OBFSTR(" hosts"), result);
}


tool_result_t driver_enum_kernel_callbacks(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

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


tool_result_t driver_detect_ssdt_hooks(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

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


    std::uint64_t ssdt_addr = device->resolve_export(ntos_base, "KeServiceDescriptorTable");
    if (ssdt_addr == 0)
        return tool_result_t::error(OBFSTR("Could not resolve KeServiceDescriptorTable export"));


    struct ssdt_entry_t {
        std::uint64_t service_table;
        std::uint64_t counter_table;
        std::uint32_t num_services;
        std::uint32_t _pad;
        std::uint64_t param_table;
    };
    ssdt_entry_t ssdt{};
    if (device->read_kernel_raw(ssdt_addr, &ssdt, sizeof(ssdt)) < sizeof(ssdt))
        return tool_result_t::error(OBFSTR("Failed to read SSDT structure"));

    if (ssdt.num_services == 0 || ssdt.num_services > 2048)
        return tool_result_t::error(OBFSTR("Invalid SSDT service count: ") + std::to_string(ssdt.num_services));
    if (!is_probably_kernel_address(ssdt.service_table))
        return tool_result_t::error(OBFSTR("ServiceTableBase is not a valid kernel address"));


    std::vector<std::int32_t> entries(ssdt.num_services);
    size_t read_sz = ssdt.num_services * sizeof(std::int32_t);
    if (device->read_kernel_raw(ssdt.service_table, entries.data(), read_sz) < read_sz)
        return tool_result_t::error(OBFSTR("Failed to read SSDT entries"));

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_kernel_dtb() == 0)
        return tool_result_t::error(OBFSTR("Kernel DTB not resolved. Call driver_connect first."));

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));
    if (device->get_process_id() == 0)
        return tool_result_t::error(OBFSTR("No target process attached. Call driver_attach first."));

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

    json result;
    result["process_id"] = pid;
    result["heap_count"] = num_heaps;
    result["entries_returned"] = total_entries;
    result["heaps"] = std::move(heaps_arr);
    return tool_result_t::ok(OBFSTR("Walked ") + std::to_string(num_heaps) + OBFSTR(" heaps, ") +
                             std::to_string(total_entries) + OBFSTR(" entries"), result);
}

tool_result_t driver_enumerate_handles(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

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

tool_result_t driver_walk_seh_chain(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Missing or invalid tid parameter. Provide the thread ID."));

    const std::uint32_t tid = *tid_opt;


    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));


    const std::uint64_t teb_addr = ctx.kernel_gs_base;
    if (teb_addr == 0)
        return tool_result_t::error(OBFSTR("TEB address is null (kernel_gs_base=0)"));


    std::uint64_t seh_head = device->read<std::uint64_t>(teb_addr);

    json seh_chain = json::array();
    int max_walk = 256;
    std::uint64_t current = seh_head;

    while (current != 0 && current != 0xFFFFFFFFFFFFFFFF && max_walk-- > 0)
    {

        std::uint64_t next = device->read<std::uint64_t>(current);
        std::uint64_t handler = device->read<std::uint64_t>(current + 8);

        json entry;
        entry["record_address"] = sa_format_address(static_cast<uint64_t>(current));
        entry["handler_address"] = sa_format_address(static_cast<uint64_t>(handler));
        entry["next"] = (next == 0xFFFFFFFFFFFFFFFF) ? "END" : sa_format_address(static_cast<uint64_t>(next));


        std::uint64_t mod_base = 0;
        std::string mod_name;
        if (handler != 0 && resolve_loaded_module_base("", mod_base, mod_name))
        {

            voyager::device_t::peb_info peb{};
            if (device->read_peb(peb) && peb.ldr_address != 0)
            {
                const std::uint64_t list_head = peb.ldr_address + 0x10;
                std::uint64_t ldr_current = device->read<std::uint64_t>(list_head);
                int ldr_iter = 1024;
                while (ldr_current != list_head && ldr_current != 0 && ldr_iter-- > 0)
                {
                    const std::uint64_t base = device->read<std::uint64_t>(ldr_current + 0x30);
                    const std::uint32_t size = device->read<std::uint32_t>(ldr_current + 0x40);
                    if (handler >= base && handler < base + size)
                    {
                        entry["module"] = read_remote_unicode_ascii(device.get(),
                            device->read<std::uint64_t>(ldr_current + 0x60),
                            device->read<std::uint16_t>(ldr_current + 0x58), 520);
                        entry["handler_offset"] = sa_format_address(static_cast<uint64_t>(handler - base));
                        break;
                    }
                    std::uint64_t n = device->read<std::uint64_t>(ldr_current);
                    if (n == ldr_current) break;
                    ldr_current = n;
                }
            }
        }

        seh_chain.push_back(std::move(entry));

        if (next == 0xFFFFFFFFFFFFFFFF || next == current)
            break;
        current = next;
    }


    json veh_chain = json::array();
    std::uint64_t ntdll_base = 0;
    std::string ntdll_name;
    if (resolve_loaded_module_base("ntdll.dll", ntdll_base, ntdll_name) && ntdll_base != 0)
    {
        const std::uint64_t add_veh = device->resolve_export(ntdll_base, "RtlAddVectoredExceptionHandler");
        if (add_veh != 0)
        {
            std::uint8_t prologue[128] = {};
            const std::size_t prologue_read = device->read_raw(add_veh, prologue, sizeof(prologue));
            if (prologue_read >= 16)
            {
                zydis_detail::ensure_init();

                std::uint64_t list_head_va = 0;
                std::size_t off = 0;
                std::uint64_t va = add_veh;
                int decoded = 0;

                ZydisDecodedInstruction instr;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

                while (off < prologue_read && decoded < 48 && list_head_va == 0)
                {
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                            &zydis_detail::decoder(),
                            prologue + off,
                            prologue_read - off,
                            &instr, operands)))
                    {
                        ++off;
                        ++va;
                        continue;
                    }

                    ++decoded;

                    if (instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        instr.operand_count_visible >= 2 &&
                        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                        operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                        operands[1].mem.disp.size > 0)
                    {
                        const ZydisRegister reg = operands[0].reg.value;
                        if (reg == ZYDIS_REGISTER_RCX || reg == ZYDIS_REGISTER_RDX)
                        {
                            ZyanU64 abs_addr = 0;
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &operands[1], va, &abs_addr)) &&
                                abs_addr >= ntdll_base &&
                                abs_addr < ntdll_base + 0x10000000ULL)
                            {
                                list_head_va = static_cast<std::uint64_t>(abs_addr);
                                break;
                            }
                        }
                    }

                    if (instr.meta.category == ZYDIS_CATEGORY_RET ||
                        instr.mnemonic == ZYDIS_MNEMONIC_INT3)
                        break;

                    off += instr.length;
                    va += instr.length;
                }

                if (list_head_va != 0)
                {
                    const std::uint64_t list_entry_va = list_head_va + 0x8;
                    const std::uint64_t cookie_va = 0x7FFE0000ULL + 0x330ULL;
                    std::uint64_t pointer_cookie = 0;
                    device->read_raw(cookie_va, &pointer_cookie, sizeof(pointer_cookie));

                    std::uint64_t entry = device->read<std::uint64_t>(list_entry_va);
                    int veh_iter = 0;
                    int idx = 0;

                    auto modules_snapshot = enumerate_ldr_modules_for_iat(device.get());

                    auto resolve_in_modules = [&](std::uint64_t addr,
                                                  std::string& out_module,
                                                  std::uint64_t& out_offset) {
                        for (const auto& m : modules_snapshot)
                        {
                            if (m.base != 0 && addr >= m.base && addr < m.base + m.size)
                            {
                                std::string base_name = m.name;
                                const auto slash = base_name.find_last_of("\\/");
                                if (slash != std::string::npos)
                                    base_name = base_name.substr(slash + 1);
                                out_module = base_name;
                                out_offset = addr - m.base;
                                return true;
                            }
                        }
                        return false;
                    };

                    while (entry != 0 &&
                           entry != list_entry_va &&
                           veh_iter++ < 256)
                    {
                        const std::uint64_t flink = device->read<std::uint64_t>(entry);
                        const std::uint32_t ref_count = device->read<std::uint32_t>(entry + 0x10);
                        const std::uint32_t flags = device->read<std::uint32_t>(entry + 0x14);
                        const std::uint64_t handler_raw = device->read<std::uint64_t>(entry + 0x18);

                        std::uint64_t handler_decoded = handler_raw;
                        if (handler_raw != 0 && pointer_cookie != 0)
                        {
                            const std::uint32_t rot = static_cast<std::uint32_t>(pointer_cookie & 0x3F);
                            const std::uint64_t xored = handler_raw ^ pointer_cookie;
                            handler_decoded = (xored >> rot) | (xored << (64 - rot));
                        }

                        json veh_entry;
                        veh_entry["index"] = idx++;
                        veh_entry["entry_address"] = sa_format_address(static_cast<uint64_t>(entry));
                        veh_entry["ref_count"] = ref_count;
                        veh_entry["flags"] = sa_format_address(static_cast<uint64_t>(flags));
                        veh_entry["handler_encoded"] = sa_format_address(static_cast<uint64_t>(handler_raw));
                        veh_entry["handler_va"] = sa_format_address(static_cast<uint64_t>(handler_decoded));

                        std::string mod_label;
                        std::uint64_t mod_off = 0;
                        if (resolve_in_modules(handler_decoded, mod_label, mod_off))
                        {
                            veh_entry["module"] = mod_label;
                            veh_entry["offset"] = sa_format_address(static_cast<uint64_t>(mod_off));
                        }
                        else if (handler_raw != handler_decoded &&
                                 resolve_in_modules(handler_raw, mod_label, mod_off))
                        {
                            veh_entry["module"] = mod_label;
                            veh_entry["offset"] = sa_format_address(static_cast<uint64_t>(mod_off));
                            veh_entry["handler_va"] = sa_format_address(static_cast<uint64_t>(handler_raw));
                        }

                        veh_chain.push_back(std::move(veh_entry));

                        if (flink == entry || flink == 0)
                            break;
                        entry = flink;
                    }
                }
            }
        }
    }

    json result;
    result["thread_id"] = tid;
    result["teb_address"] = sa_format_address(static_cast<uint64_t>(teb_addr));
    result["seh_entries"] = seh_chain.size();
    result["seh_chain"] = std::move(seh_chain);
    result["veh_entries"] = veh_chain.size();
    result["veh_chain"] = std::move(veh_chain);
    result["rip"] = sa_format_address(static_cast<uint64_t>(ctx.rip));
    return tool_result_t::ok(OBFSTR("SEH chain: ") + std::to_string(result["seh_entries"].get<int>()) +
                             OBFSTR(" handlers, VEH chain: ") +
                             std::to_string(result["veh_entries"].get<int>()) +
                             OBFSTR(" handlers for TID ") + std::to_string(tid), result);
}

tool_result_t driver_find_code_caves(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::size_t min_size = params.value("min_size", 64);
    const int limit = std::min(params.value("limit", 50), 500);
    const std::uint8_t fill_byte = static_cast<std::uint8_t>(params.value("fill_byte", 0x00));
    const bool executable_only = params.value("executable_only", true);


    auto regions = enumerate_all_memory_regions_paginated(
        device.get(), 0x10000, 0x7FFFFFFFFFFF, false);

    if (regions.empty())
        return tool_result_t::error(OBFSTR("No memory regions found."));

    json caves = json::array();
    int found = 0;

    for (const auto& region : regions)
    {
        if (found >= limit) break;
        if (region.size == 0 || region.size > 0x10000000) continue;


        bool is_exec = (region.protect & 0x10) ||
                       (region.protect & 0x20) ||
                       (region.protect & 0x40) ||
                       (region.protect & 0x80);

        if (executable_only && !is_exec)
            continue;


        if ((region.state & 0x1000) == 0)
            continue;


        constexpr std::size_t CHUNK = 0x10000;
        for (std::uint64_t offset = 0; offset < region.size && found < limit; offset += CHUNK)
        {
            const std::size_t to_read = std::min<std::size_t>(CHUNK, region.size - offset);
            std::vector<std::uint8_t> buf(to_read);
            if (device->read_raw(region.base + offset, buf.data(), to_read) == 0)
                continue;


            std::size_t run_start = 0;
            bool in_run = false;

            for (std::size_t i = 0; i <= to_read; ++i)
            {
                bool is_fill = (i < to_read) && (buf[i] == fill_byte);

                if (is_fill && !in_run)
                {
                    run_start = i;
                    in_run = true;
                }
                else if (!is_fill && in_run)
                {
                    std::size_t run_len = i - run_start;
                    if (run_len >= min_size)
                    {
                        json cave;
                        cave["address"] = sa_format_address(
                            static_cast<uint64_t>(region.base + offset + run_start));
                        cave["size"] = run_len;
                        cave["fill_byte"] = sa_format_address(static_cast<uint64_t>(fill_byte));
                        cave["executable"] = is_exec;
                        cave["protection"] = sa_format_address(static_cast<uint64_t>(region.protect));
                        cave["region_base"] = sa_format_address(static_cast<uint64_t>(region.base));
                        caves.push_back(std::move(cave));
                        ++found;
                        if (found >= limit) break;
                    }
                    in_run = false;
                }
            }
        }
    }

    json result;
    result["caves_found"] = found;
    result["min_size_filter"] = min_size;
    result["executable_only"] = executable_only;
    result["fill_byte"] = sa_format_address(static_cast<uint64_t>(fill_byte));
    result["caves"] = std::move(caves);
    return tool_result_t::ok(std::to_string(found) + OBFSTR(" code caves found (>= ") +
                             std::to_string(min_size) + OBFSTR(" bytes)"), result);
}

tool_result_t driver_scan_memory_value(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;


    const std::string value_type = params.value("value_type", "int32");
    const std::string scan_mode = params.value("scan_mode", "exact");
    const int limit = std::min(params.value("limit", 100), 10000);


    std::uint64_t scan_start = 0x10000;
    std::uint64_t scan_end = 0x7FFFFFFFFFFF;
    if (params.contains("start"))
    {
        auto s = sa_parse_address(params["start"].get<std::string>());
        if (s) scan_start = *s;
    }
    if (params.contains("end"))
    {
        auto e = sa_parse_address(params["end"].get<std::string>());
        if (e) scan_end = *e;
    }


    std::size_t value_size = 4;
    std::vector<std::uint8_t> search_bytes;
    std::vector<std::uint8_t> search_bytes_max;

    if (value_type == "byte")
    {
        value_size = 1;
        std::uint8_t v = static_cast<std::uint8_t>(params.value("value", 0));
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 1);
    }
    else if (value_type == "int16")
    {
        value_size = 2;
        std::int16_t v = static_cast<std::int16_t>(params.value("value", 0));
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 2);
    }
    else if (value_type == "int32")
    {
        value_size = 4;
        std::int32_t v = static_cast<std::int32_t>(params.value("value", 0));
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 4);
    }
    else if (value_type == "int64")
    {
        value_size = 8;
        std::int64_t v = static_cast<std::int64_t>(params.value("value", 0));
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 8);
    }
    else if (value_type == "float")
    {
        value_size = 4;
        float v = params.value("value", 0.0f);
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 4);
    }
    else if (value_type == "double")
    {
        value_size = 8;
        double v = params.value("value", 0.0);
        search_bytes.assign(reinterpret_cast<const std::uint8_t*>(&v),
                           reinterpret_cast<const std::uint8_t*>(&v) + 8);
    }
    else if (value_type == "string")
    {
        const std::string str_val = params.value("value_string", "");
        if (str_val.empty()) return tool_result_t::error(OBFSTR("value_string required for string type"));
        search_bytes.assign(str_val.begin(), str_val.end());
        value_size = search_bytes.size();
    }
    else if (value_type == "aob")
    {

        return tool_result_t::error(OBFSTR("Use driver_scan_pattern for AOB/wildcard scans"));
    }
    else
    {
        return tool_result_t::error(OBFSTR("Invalid value_type. Use: byte, int16, int32, int64, float, double, string"));
    }

    if (scan_mode == "range")
    {

        if (value_type == "int32")
        {
            std::int32_t v = static_cast<std::int32_t>(params.value("value_max", 0));
            search_bytes_max.assign(reinterpret_cast<const std::uint8_t*>(&v),
                                   reinterpret_cast<const std::uint8_t*>(&v) + 4);
        }
        else if (value_type == "float")
        {
            float v = params.value("value_max", 0.0f);
            search_bytes_max.assign(reinterpret_cast<const std::uint8_t*>(&v),
                                   reinterpret_cast<const std::uint8_t*>(&v) + 4);
        }

    }


    auto regions = enumerate_all_memory_regions_paginated(
        device.get(), scan_start, scan_end, false);

    json matches = json::array();
    int found = 0;

    for (const auto& region : regions)
    {
        if (found >= limit) break;
        if (region.size == 0 || region.size > 0x10000000) continue;
        if ((region.state & 0x1000) == 0) continue;
        if (region.base < scan_start || region.base >= scan_end) continue;


        if ((region.protect & 0x01) ||
            (region.protect & 0x100))
            continue;

        constexpr std::size_t CHUNK = 0x10000;
        for (std::uint64_t offset = 0; offset < region.size && found < limit; offset += CHUNK)
        {
            const std::size_t to_read = std::min<std::size_t>(CHUNK, region.size - offset);
            if (to_read < value_size) continue;

            std::vector<std::uint8_t> buf(to_read);
            if (device->read_raw(region.base + offset, buf.data(), to_read) == 0)
                continue;


            if (scan_mode == "exact" && !search_bytes.empty())
            {
                for (std::size_t i = 0; i + value_size <= to_read && found < limit; ++i)
                {
                    if (std::memcmp(&buf[i], search_bytes.data(), value_size) == 0)
                    {
                        json m;
                        m["address"] = sa_format_address(static_cast<uint64_t>(region.base + offset + i));


                        if (value_type == "float")
                        {
                            float fv;
                            std::memcpy(&fv, &buf[i], 4);
                            m["value"] = fv;
                        }
                        else if (value_type == "double")
                        {
                            double dv;
                            std::memcpy(&dv, &buf[i], 8);
                            m["value"] = dv;
                        }
                        else if (value_type == "string")
                        {
                            m["value"] = std::string(buf.begin() + i, buf.begin() + i + value_size);
                        }
                        else
                        {
                            std::int64_t iv = 0;
                            std::memcpy(&iv, &buf[i], std::min<std::size_t>(value_size, 8));
                            m["value"] = iv;
                        }
                        m["region_protect"] = sa_format_address(static_cast<uint64_t>(region.protect));
                        matches.push_back(std::move(m));
                        ++found;
                    }
                }
            }
            else if (scan_mode == "range" && !search_bytes.empty() && !search_bytes_max.empty())
            {

                for (std::size_t i = 0; i + value_size <= to_read && found < limit; i += value_size)
                {
                    bool in_range = false;
                    if (value_type == "int32")
                    {
                        std::int32_t current_val, min_val, max_val;
                        std::memcpy(&current_val, &buf[i], 4);
                        std::memcpy(&min_val, search_bytes.data(), 4);
                        std::memcpy(&max_val, search_bytes_max.data(), 4);
                        in_range = (current_val >= min_val && current_val <= max_val);
                        if (in_range)
                        {
                            json m;
                            m["address"] = sa_format_address(static_cast<uint64_t>(region.base + offset + i));
                            m["value"] = current_val;
                            matches.push_back(std::move(m));
                            ++found;
                        }
                    }
                    else if (value_type == "float")
                    {
                        float current_val, min_val, max_val;
                        std::memcpy(&current_val, &buf[i], 4);
                        std::memcpy(&min_val, search_bytes.data(), 4);
                        std::memcpy(&max_val, search_bytes_max.data(), 4);
                        in_range = (current_val >= min_val && current_val <= max_val);
                        if (in_range)
                        {
                            json m;
                            m["address"] = sa_format_address(static_cast<uint64_t>(region.base + offset + i));
                            m["value"] = current_val;
                            matches.push_back(std::move(m));
                            ++found;
                        }
                    }
                }
            }
        }
    }

    json result;
    result["value_type"] = value_type;
    result["scan_mode"] = scan_mode;
    result["matches_found"] = found;
    result["matches"] = std::move(matches);
    return tool_result_t::ok(std::to_string(found) + OBFSTR(" matches found"), result);
}

tool_result_t driver_pointer_scan(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::string target_addr_str = params.value("target_address", "");
    if (target_addr_str.empty())
        return tool_result_t::error(OBFSTR("Missing required parameter: target_address"));

    auto target_opt = sa_parse_address(target_addr_str);
    if (!target_opt)
        return tool_result_t::error(OBFSTR("Invalid target_address"));

    const std::uint64_t target = *target_opt;
    const int max_depth = std::min(params.value("max_depth", 3), 7);
    const std::uint64_t max_offset = params.value("max_offset", 0x1000);
    const int limit = std::min(params.value("limit", 50), 500);


    const std::uint64_t image_base = device->get_base_address();


    auto regions = enumerate_all_memory_regions_paginated(
        device.get(), 0x10000, 0x7FFFFFFFFFFF, false);


    struct ptr_hit_t {
        std::uint64_t address;
        std::uint64_t value;
        std::int64_t offset;
        bool is_static;
        std::string module_name;
    };

    auto find_pointers_to_range = [&](std::uint64_t range_start, std::uint64_t range_end,
                                      int current_limit) -> std::vector<ptr_hit_t>
    {
        std::vector<ptr_hit_t> hits;
        for (const auto& region : regions)
        {
            if (static_cast<int>(hits.size()) >= current_limit) break;
            if (region.size == 0 || region.size > 0x10000000) continue;
            if ((region.state & 0x1000) == 0) continue;
            if ((region.protect & 0x01) || (region.protect & 0x100)) continue;

            constexpr std::size_t CHUNK = 0x10000;
            for (std::uint64_t off2 = 0; off2 < region.size && static_cast<int>(hits.size()) < current_limit; off2 += CHUNK)
            {
                const std::size_t to_read = std::min<std::size_t>(CHUNK, region.size - off2);
                if (to_read < 8) continue;

                std::vector<std::uint8_t> buf(to_read);
                if (device->read_raw(region.base + off2, buf.data(), to_read) == 0)
                    continue;

                for (std::size_t i = 0; i + 8 <= to_read && static_cast<int>(hits.size()) < current_limit; i += 8)
                {
                    std::uint64_t val;
                    std::memcpy(&val, &buf[i], 8);
                    if (val >= range_start && val <= range_end)
                    {
                        ptr_hit_t hit;
                        hit.address = region.base + off2 + i;
                        hit.value = val;
                        hit.offset = static_cast<std::int64_t>(val) - static_cast<std::int64_t>(range_start + max_offset);
                        hit.is_static = false;
                        hits.push_back(std::move(hit));
                    }
                }
            }
        }
        return hits;
    };


    std::uint64_t range_lo = target > max_offset ? target - max_offset : 0;
    std::uint64_t range_hi = target + max_offset;
    auto level0 = find_pointers_to_range(range_lo, range_hi, limit * 10);

    json chains = json::array();
    int chain_count = 0;


    for (auto& hit : level0)
    {
        if (chain_count >= limit) break;

        json chain;
        chain["depth"] = 1;
        chain["base_address"] = sa_format_address(static_cast<uint64_t>(hit.address));
        chain["pointer_value"] = sa_format_address(static_cast<uint64_t>(hit.value));
        chain["final_offset"] = static_cast<std::int64_t>(hit.value - target);


        bool is_static = false;
        voyager::device_t::peb_info peb{};
        if (device->read_peb(peb) && peb.ldr_address != 0)
        {
            const std::uint64_t list_head = peb.ldr_address + 0x10;
            std::uint64_t ldr_curr = device->read<std::uint64_t>(list_head);
            int ldr_iter = 512;
            while (ldr_curr != list_head && ldr_curr != 0 && ldr_iter-- > 0)
            {
                const std::uint64_t base = device->read<std::uint64_t>(ldr_curr + 0x30);
                const std::uint32_t size = device->read<std::uint32_t>(ldr_curr + 0x40);
                if (hit.address >= base && hit.address < base + size)
                {
                    is_static = true;
                    chain["module"] = read_remote_unicode_ascii(device.get(),
                        device->read<std::uint64_t>(ldr_curr + 0x60),
                        device->read<std::uint16_t>(ldr_curr + 0x58), 520);
                    chain["module_offset"] = sa_format_address(static_cast<uint64_t>(hit.address - base));
                    break;
                }
                std::uint64_t n = device->read<std::uint64_t>(ldr_curr);
                if (n == ldr_curr) break;
                ldr_curr = n;
            }
        }

        chain["is_static"] = is_static;
        chains.push_back(std::move(chain));
        ++chain_count;
    }

    json result;
    result["target_address"] = sa_format_address(static_cast<uint64_t>(target));
    result["max_depth"] = max_depth;
    result["max_offset"] = max_offset;
    result["chains_found"] = chain_count;
    result["chains"] = std::move(chains);
    result["note"] = OBFSTR("Static pointers (is_static=true) with module+offset are stable across "
                            "restarts. Use module base + module_offset + final_offset to reach target.");
    return tool_result_t::ok(std::to_string(chain_count) + OBFSTR(" pointer chains found"), result);
}

tool_result_t driver_enumerate_windows(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

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

tool_result_t driver_walk_stack(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Missing or invalid tid parameter."));

    const std::uint32_t tid = *tid_opt;
    const int max_frames = std::min(params.value("max_frames", 64), 256);

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));


    const std::uint64_t rsp = ctx.rsp;
    const std::uint64_t rbp = ctx.rbp;
    const std::uint64_t rip = ctx.rip;


    struct mod_info_t {
        std::uint64_t base;
        std::uint32_t size;
        std::string name;
    };
    std::vector<mod_info_t> modules;

    voyager::device_t::peb_info peb{};
    if (device->read_peb(peb) && peb.ldr_address != 0)
    {
        const std::uint64_t list_head = peb.ldr_address + 0x10;
        std::uint64_t ldr_curr = device->read<std::uint64_t>(list_head);
        int ldr_iter = 1024;
        while (ldr_curr != list_head && ldr_curr != 0 && ldr_iter-- > 0)
        {
            mod_info_t mi;
            mi.base = device->read<std::uint64_t>(ldr_curr + 0x30);
            mi.size = device->read<std::uint32_t>(ldr_curr + 0x40);
            mi.name = read_remote_unicode_ascii(device.get(),
                device->read<std::uint64_t>(ldr_curr + 0x60),
                device->read<std::uint16_t>(ldr_curr + 0x58), 520);
            if (mi.base != 0 && mi.size != 0)
                modules.push_back(std::move(mi));
            std::uint64_t n = device->read<std::uint64_t>(ldr_curr);
            if (n == ldr_curr) break;
            ldr_curr = n;
        }
    }

    auto resolve_module = [&](std::uint64_t addr) -> std::pair<std::string, std::uint64_t> {
        for (const auto& m : modules)
        {
            if (addr >= m.base && addr < m.base + m.size)
                return {m.name, addr - m.base};
        }
        return {"", 0};
    };

    json frames = json::array();


    {
        json f;
        f["frame"] = 0;
        f["rip"] = sa_format_address(static_cast<uint64_t>(rip));
        f["rsp"] = sa_format_address(static_cast<uint64_t>(rsp));
        f["rbp"] = sa_format_address(static_cast<uint64_t>(rbp));
        auto [mod, off] = resolve_module(rip);
        if (!mod.empty()) { f["module"] = mod; f["offset"] = sa_format_address(static_cast<uint64_t>(off)); }
        frames.push_back(std::move(f));
    }


    constexpr std::size_t STACK_READ_SIZE = 0x2000;
    std::vector<std::uint8_t> stack_buf(STACK_READ_SIZE);
    const std::size_t stack_read = device->read_raw(rsp, stack_buf.data(), STACK_READ_SIZE);

    int frame_idx = 1;
    std::set<std::uint64_t> seen_addresses;

    for (std::size_t i = 0; i + 8 <= stack_read && frame_idx < max_frames; i += 8)
    {
        std::uint64_t candidate;
        std::memcpy(&candidate, &stack_buf[i], 8);


        if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF)
            continue;

        auto [mod, off] = resolve_module(candidate);
        if (mod.empty()) continue;
        if (seen_addresses.count(candidate)) continue;
        seen_addresses.insert(candidate);


        std::uint8_t pre_bytes[8] = {};
        device->read_raw(candidate - 8, pre_bytes, 8);


        bool looks_like_ret_addr = false;
        if (pre_bytes[3] == 0xE8) looks_like_ret_addr = true;
        if (pre_bytes[2] == 0xFF && (pre_bytes[3] & 0x38) == 0x10)
            looks_like_ret_addr = true;
        if (pre_bytes[6] == 0xFF && pre_bytes[7] >= 0xD0 && pre_bytes[7] <= 0xD7)
            looks_like_ret_addr = true;

        if (!looks_like_ret_addr) continue;

        json f;
        f["frame"] = frame_idx;
        f["return_address"] = sa_format_address(static_cast<uint64_t>(candidate));
        f["stack_offset"] = sa_format_address(static_cast<uint64_t>(rsp + i));
        f["module"] = mod;
        f["offset"] = sa_format_address(static_cast<uint64_t>(off));
        frames.push_back(std::move(f));
        ++frame_idx;
    }

    json result;
    result["thread_id"] = tid;
    result["rip"] = sa_format_address(static_cast<uint64_t>(rip));
    result["rsp"] = sa_format_address(static_cast<uint64_t>(rsp));
    result["rbp"] = sa_format_address(static_cast<uint64_t>(rbp));
    result["frame_count"] = frames.size();
    result["frames"] = std::move(frames);
    result["method"] = OBFSTR("heuristic_stack_scan");
    return tool_result_t::ok(std::to_string(result["frame_count"].get<int>()) +
                             OBFSTR(" stack frames for TID ") + std::to_string(tid), result);
}

tool_result_t driver_assemble(const json& params)
{
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

tool_result_t driver_compare_memory_snapshot(const json& params)
{
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    const std::string operation = params.value("operation", "take");
    const std::string snapshot_name = params.value("name", "default");

    if (operation == "take")
    {
        if (!params.contains("address"))
            return tool_result_t::error(OBFSTR("Missing required parameter: address"));

        auto addr_opt = sa_parse_address(params["address"].get<std::string>());
        if (!addr_opt) return tool_result_t::error(OBFSTR("Invalid address"));

        std::size_t size = params.value("size", 4096);
        if (size > 0x100000) return tool_result_t::error(OBFSTR("Size too large (max 1MB)"));

        std::vector<std::uint8_t> buffer(size);
        std::size_t read = device->read_raw(*addr_opt, buffer.data(), size);
        if (read == 0) return tool_result_t::error(OBFSTR("Failed to read memory for snapshot"));
        buffer.resize(read);

        std::string key = snapshot_name + "|" + sa_format_address(*addr_opt) + "|" + std::to_string(read);
        {
            std::lock_guard<std::mutex> lock(s_snapshot_mutex);
            s_memory_snapshots[key] = std::move(buffer);
        }

        json result;
        result["operation"] = "take";
        result["name"] = snapshot_name;
        result["address"] = sa_format_address(*addr_opt);
        result["size"] = read;
        result["snapshot_key"] = key;
        return tool_result_t::ok(OBFSTR("Snapshot taken: ") + key, result);
    }
    else if (operation == "compare")
    {
        if (!params.contains("address"))
            return tool_result_t::error(OBFSTR("Missing required parameter: address"));

        auto addr_opt = sa_parse_address(params["address"].get<std::string>());
        if (!addr_opt) return tool_result_t::error(OBFSTR("Invalid address"));


        std::vector<std::uint8_t> old_snapshot;
        std::string found_key;
        {
            std::lock_guard<std::mutex> lock(s_snapshot_mutex);
            for (const auto& [k, v] : s_memory_snapshots)
            {
                if (k.find(snapshot_name + "|") == 0 && k.find(sa_format_address(*addr_opt)) != std::string::npos)
                {
                    old_snapshot = v;
                    found_key = k;
                    break;
                }
            }
        }

        if (old_snapshot.empty())
            return tool_result_t::error(OBFSTR("No snapshot found with name '") + snapshot_name +
                                        OBFSTR("' at address ") + sa_format_address(*addr_opt));

        const std::size_t size = old_snapshot.size();
        std::vector<std::uint8_t> current(size);
        std::size_t read = device->read_raw(*addr_opt, current.data(), size);
        if (read == 0) return tool_result_t::error(OBFSTR("Failed to read current memory for comparison"));


        json diffs = json::array();
        int diff_count = 0;
        const int max_diffs = std::min(params.value("max_diffs", 200), 5000);

        for (std::size_t i = 0; i < std::min(old_snapshot.size(), static_cast<std::size_t>(read)); ++i)
        {
            if (old_snapshot[i] != current[i])
            {
                if (diff_count < max_diffs)
                {
                    json d;
                    d["offset"] = i;
                    d["address"] = sa_format_address(static_cast<uint64_t>(*addr_opt + i));
                    d["old_value"] = old_snapshot[i];
                    d["new_value"] = current[i];
                    diffs.push_back(std::move(d));
                }
                ++diff_count;
            }
        }

        json result;
        result["operation"] = "compare";
        result["name"] = snapshot_name;
        result["address"] = sa_format_address(*addr_opt);
        result["snapshot_size"] = old_snapshot.size();
        result["current_read"] = read;
        result["total_diffs"] = diff_count;
        result["identical"] = diff_count == 0;
        result["diffs"] = std::move(diffs);
        return tool_result_t::ok(diff_count == 0
            ? OBFSTR("Memory identical to snapshot")
            : std::to_string(diff_count) + OBFSTR(" bytes changed since snapshot"), result);
    }
    else if (operation == "list")
    {
        std::lock_guard<std::mutex> lock(s_snapshot_mutex);
        json snapshots = json::array();
        for (const auto& [k, v] : s_memory_snapshots)
        {
            json s;
            s["key"] = k;
            s["size"] = v.size();
            snapshots.push_back(std::move(s));
        }
        json result;
        result["snapshots"] = std::move(snapshots);
        return tool_result_t::ok(std::to_string(s_memory_snapshots.size()) + OBFSTR(" snapshots stored"), result);
    }
    else if (operation == "clear")
    {
        std::lock_guard<std::mutex> lock(s_snapshot_mutex);
        int count = static_cast<int>(s_memory_snapshots.size());
        s_memory_snapshots.clear();
        return tool_result_t::ok(std::to_string(count) + OBFSTR(" snapshots cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'take', 'compare', 'list', or 'clear'."));
}

tool_result_t driver_find_references(const json& params)
{
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
    if (auto ctx_err = ensure_attached_process_context(params))
        return *ctx_err;

    auto tid_opt = parse_tid_param(params);
    if (!tid_opt)
        return tool_result_t::error(OBFSTR("Missing or invalid tid parameter."));

    const std::uint32_t tid = *tid_opt;

    voyager::device_t::thread_context ctx{};
    if (!device->get_thread_context(tid, ctx))
        return tool_result_t::error(OBFSTR("Failed to get thread context for TID ") + std::to_string(tid));

    const std::uint64_t teb_addr = ctx.kernel_gs_base;
    if (teb_addr == 0)
        return tool_result_t::error(OBFSTR("TEB address is null"));


    json teb;
    teb["teb_address"] = sa_format_address(static_cast<uint64_t>(teb_addr));
    teb["thread_id"] = tid;


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

    s_deferred_tool_list = &srv.get_tools();

        register_compat(srv, {
        OBFSTR("driver_connect"), OBFSTR("driver"),
        OBFSTR("Connect to the AiDA kernel driver. Must be called before any other driver_ tools. "
               "Operates in the kernel to bypass all usermode anti-debugging and anti-RE protections."),
        {}, driver_connect, false});

    register_compat(srv, {
        OBFSTR("driver_status"), OBFSTR("driver"),
        OBFSTR("Get kernel driver connection status: connected flag, attached process ID, "
               "image base address, DirectoryTableBase (DTB), and heartbeat result."),
        {}, driver_status, true});

    register_compat(srv, {
        OBFSTR("driver_attach"), OBFSTR("driver"),
        OBFSTR("Attach the kernel driver to a running process by name. "
               "Finds the process, locates the image base, and solves the DTB for physical memory access. "
               "Bypasses all process isolation and memory protection."),
        {{OBFSTR("process"), OBFSTR("string"),
                    OBFSTR("Target process executable name (e.g. 'target.exe'). Case-insensitive. Aliases: process_name, name."), false},
                 {OBFSTR("process_name"), OBFSTR("string"),
                    OBFSTR("Alias of process."), false},
                 {OBFSTR("name"), OBFSTR("string"),
                    OBFSTR("Alias of process."), false}},
        driver_attach, false});

    register_compat(srv, {
        OBFSTR("driver_unattach"), OBFSTR("driver"),
        OBFSTR("Clear the currently attached target process context without disconnecting the kernel driver. "
               "Resets attached PID, image base, process DTB, and temporary remote-call state. "
               "Use this before attaching to a different process to avoid stale context confusion."),
        {}, driver_unattach, false});

    register_compat(srv, {
        OBFSTR("driver_read_memory"), OBFSTR("driver"),
        OBFSTR("Read raw bytes from the target process via kernel driver. "
               "Bypasses all memory protection, DEP, guard pages, and anti-read hooks. "
             "Optionally patches the bytes into the IDA database. "
             "Supports optional process_id override to avoid stale attach context."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to read (default 256, max 65536)"), false},
          {OBFSTR("patch_idb"), OBFSTR("boolean"), OBFSTR("Write read bytes to IDA database (default false)"), false},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override. If different from attached PID, context is switched safely."), false}},
        driver_read_memory, false});

    register_compat(srv, {
        OBFSTR("driver_write_memory"), OBFSTR("driver"),
        OBFSTR("Write bytes to the target process via kernel driver. "
             "Bypasses all memory protection including DEP, guard pages, and write protection. "
             "Accepted bytes formats: 'DE AD BE EF', 'DEADBEEF', [222,173,...], ['DE','AD',...]."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Virtual address in target process"), true},
          {OBFSTR("bytes"), OBFSTR("string"), OBFSTR("Bytes payload in hex string or JSON array."), true},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override. If different from attached PID, context is switched safely."), false}},
        driver_write_memory, false});

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
        OBFSTR("driver_scan_pattern"), OBFSTR("driver"),
        OBFSTR("Scan target process memory for a byte pattern via kernel driver. "
               "Supports wildcard '??' bytes. Scans the attached module range by default."),
        {{OBFSTR("pattern"), OBFSTR("string"),
          OBFSTR("Hex byte pattern with '??' wildcards (e.g. '48 8B ?? ?? 89 ?? 00')"), true},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (default: image base)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Scan size from start in bytes (default 0x200000)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum matches to return (default 20)"), false}},
        driver_scan_pattern, false});

    register_compat(srv, {
        OBFSTR("driver_read_string"), OBFSTR("driver"),
        OBFSTR("Read a null-terminated ASCII or UTF-16 string from target process memory via kernel driver."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Address of the string in target process"), true},
         {OBFSTR("max_length"), OBFSTR("number"), OBFSTR("Maximum string character length (default 512)"), false},
         {OBFSTR("type"), OBFSTR("string"), OBFSTR("String encoding: auto, ascii, wide (default auto)"), false,
                    {OBFSTR("auto"), OBFSTR("ascii"), OBFSTR("wide")}},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_read_string, false});

    register_compat(srv, {
        OBFSTR("driver_read_pointer_chain"), OBFSTR("driver"),
        OBFSTR("Follow a chain of pointer dereferences through target process memory via kernel driver. "
               "Useful for traversing linked lists, object hierarchies, and obfuscated data structures."),
        {{OBFSTR("address"), OBFSTR("string"), OBFSTR("Starting virtual address"), false},
          {OBFSTR("base_address"), OBFSTR("string"), OBFSTR("Alias for address."), false},
         {OBFSTR("offsets"), OBFSTR("array"),
          OBFSTR("Array of byte offsets to apply after each dereference (e.g. [0, 48, 24])"), false, {},
           json::object({{"type", "number"}})},
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_read_pointer_chain, false});

    register_compat(srv, {
        OBFSTR("driver_enumerate_modules"), OBFSTR("driver"),
        OBFSTR("Enumerate ALL modules loaded in the attached process by walking the PEB LDR "
               "InLoadOrderModuleList. Returns each module's name, base address, size, entry point, "
               "full path, and whether it is the main executable. Requires driver_attach first."),
        {}, driver_enumerate_modules, false});

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
        OBFSTR("driver_dump_kernel_module"), OBFSTR("driver"),
        OBFSTR("UNIVERSAL kernel module dump tool. By default dumps from LIVE KERNEL MEMORY "
               "using physical memory reads (requires driver connected). Captures runtime-decrypted, "
               "devirtualized, unpacked code as it exists in RAM. Set from_memory=false to fall back "
               "to reading the on-disk .sys file. "
               "When patch_idb=true, creates IDA segments for each PE section and patches live bytes. "
               "Use this to dump ANY kernel driver: EasyAntiCheat (EAC), BattlEye, Vanguard, "
               "ntkrnlmp.exe, win32kfull.sys, etc. The dump file can be loaded in IDA Pro."),
        {{OBFSTR("module"), OBFSTR("string"),
          OBFSTR("Kernel module name or substring (e.g. 'EasyAntiCheat.sys', 'eac', 'ntoskrnl')"), true},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Full file path to save the dump (e.g. 'C:\\\\dumps\\\\dumped_eac.sys'). "
                 "If omitted, saves to %%TEMP%%\\\\dumped_<module_name>"), false},
         {OBFSTR("from_memory"), OBFSTR("boolean"),
          OBFSTR("True (default) = dump live kernel memory via driver. "
                 "False = read on-disk file (no driver needed)."), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"),
          OBFSTR("Create IDA segments and patch dumped bytes into the database (default true)"), false},
         {OBFSTR("analyze"), OBFSTR("boolean"),
          OBFSTR("Run analysis after patching (default true)"), false}},
        driver_dump_kernel_module, false});

    register_compat(srv, {
        OBFSTR("driver_read_kernel_memory"), OBFSTR("driver"),
        OBFSTR("Read raw bytes from ANY kernel virtual address via physical memory translation. "
               "Requires driver connected. Solves System DTB automatically. "
               "Bypasses all kernel integrity checks, PatchGuard, and memory protections. "
               "Can read anticheat driver memory, ntoskrnl internals, SSDT, IDT, anything."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Kernel virtual address to read (e.g. 'FFFFF80012345000')"), true},
         {OBFSTR("size"), OBFSTR("number"),
          OBFSTR("Bytes to read (default 256, max 65536)"), false},
         {OBFSTR("patch_idb"), OBFSTR("boolean"),
          OBFSTR("Patch read bytes into IDA database at the same address (default false)"), false}},
        driver_read_kernel_memory, false});

    register_compat(srv, {
        OBFSTR("driver_write_kernel_memory"), OBFSTR("driver"),
        OBFSTR("Write raw bytes to ANY kernel virtual address via physical memory translation. "
               "Requires driver connected. Bypasses all memory protection, write-protection, "
               "PatchGuard, code integrity. WARNING: Writing to kernel memory can cause BSOD "
                             "if done incorrectly. Use with extreme caution. User-mode addresses are rejected."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Kernel virtual address to write (e.g. 'FFFFF80012345000')"), true},
         {OBFSTR("bytes"), OBFSTR("string"),
                    OBFSTR("Bytes payload in hex string or JSON array."), true}},
        driver_write_kernel_memory, false});


    register_compat(srv, {
        OBFSTR("driver_allocate_memory"), OBFSTR("driver"),
        OBFSTR("Allocate RWX memory in the attached target process. "
               "Uses kernel-level ZwAllocateVirtualMemory with PAGE_EXECUTE_READWRITE. "
               "Max 16MB per allocation. Useful for injecting shellcode, writing strings "
               "for function arguments, or setting up data structures remotely. "
               "Requires driver connected and process attached."),
        {{OBFSTR("size"), OBFSTR("string"),
                    OBFSTR("Number of bytes to allocate (max 16777216 = 16MB)"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_allocate_memory, false});

    register_compat(srv, {
        OBFSTR("driver_free_memory"), OBFSTR("driver"),
        OBFSTR("Free previously allocated memory in the attached target process. "
               "Uses kernel-level ZwFreeVirtualMemory with MEM_RELEASE. "
               "Requires driver connected and process attached."),
        {{OBFSTR("address"), OBFSTR("string"),
                    OBFSTR("Address of the memory block to free (hex string like '0x...')"), true},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
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
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_call_function, false});


    register_compat(srv, {
        OBFSTR("driver_get_thread_context"), OBFSTR("driver"),
        OBFSTR("Get the full register state of a thread in the attached process via kernel PsGetContextThread. "
               "Returns all general purpose registers (RAX-R15), RIP, RFLAGS, and debug registers (DR0-DR7). "
               "Thread must exist in the attached process. Bypasses all anti-debug since it operates from kernel."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_get_thread_context, true});

    register_compat(srv, {
        OBFSTR("driver_set_thread_context"), OBFSTR("driver"),
        OBFSTR("Set registers of a thread in the attached process via kernel PsSetContextThread. "
               "Only specified registers are modified; unspecified registers are untouched. "
               "Can set RIP to redirect execution, modify debug registers for HW breakpoints, "
               "change RSP, or any other register. Operates from kernel, bypasses all protection."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("rax"), OBFSTR("string"), OBFSTR("RAX value (hex)"), false},
         {OBFSTR("rbx"), OBFSTR("string"), OBFSTR("RBX value"), false},
         {OBFSTR("rcx"), OBFSTR("string"), OBFSTR("RCX value"), false},
         {OBFSTR("rdx"), OBFSTR("string"), OBFSTR("RDX value"), false},
         {OBFSTR("rsi"), OBFSTR("string"), OBFSTR("RSI value"), false},
         {OBFSTR("rdi"), OBFSTR("string"), OBFSTR("RDI value"), false},
         {OBFSTR("rbp"), OBFSTR("string"), OBFSTR("RBP value"), false},
         {OBFSTR("rsp"), OBFSTR("string"), OBFSTR("RSP value"), false},
         {OBFSTR("r8"), OBFSTR("string"), OBFSTR("R8 value"), false},
         {OBFSTR("r9"), OBFSTR("string"), OBFSTR("R9 value"), false},
         {OBFSTR("r10"), OBFSTR("string"), OBFSTR("R10 value"), false},
         {OBFSTR("r11"), OBFSTR("string"), OBFSTR("R11 value"), false},
         {OBFSTR("r12"), OBFSTR("string"), OBFSTR("R12 value"), false},
         {OBFSTR("r13"), OBFSTR("string"), OBFSTR("R13 value"), false},
         {OBFSTR("r14"), OBFSTR("string"), OBFSTR("R14 value"), false},
         {OBFSTR("r15"), OBFSTR("string"), OBFSTR("R15 value"), false},
         {OBFSTR("rip"), OBFSTR("string"), OBFSTR("RIP value"), false},
         {OBFSTR("rflags"), OBFSTR("string"), OBFSTR("RFLAGS value"), false},
         {OBFSTR("dr0"), OBFSTR("string"), OBFSTR("DR0 value"), false},
         {OBFSTR("dr1"), OBFSTR("string"), OBFSTR("DR1 value"), false},
         {OBFSTR("dr2"), OBFSTR("string"), OBFSTR("DR2 value"), false},
         {OBFSTR("dr3"), OBFSTR("string"), OBFSTR("DR3 value"), false},
         {OBFSTR("dr6"), OBFSTR("string"), OBFSTR("DR6 value"), false},
         {OBFSTR("dr7"), OBFSTR("string"), OBFSTR("DR7 value"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_set_thread_context, false});

    register_compat(srv, {
        OBFSTR("driver_enumerate_threads"), OBFSTR("driver"),
        OBFSTR("Enumerate all threads in the attached process via kernel PsGetNextProcessThread. "
               "Returns each thread's TID. Useful for finding threads to suspend, set breakpoints on, "
               "or inspect context of."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_enumerate_threads, true});

    register_compat(srv, {
        OBFSTR("driver_suspend_thread"), OBFSTR("driver"),
        OBFSTR("Suspend a thread in the attached process via kernel PsSuspendThread. "
               "Thread execution is paused until resumed. Returns previous suspend count."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to suspend. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_suspend_thread, false});

    register_compat(srv, {
        OBFSTR("driver_resume_thread"), OBFSTR("driver"),
        OBFSTR("Resume a suspended thread in the attached process via kernel PsResumeThread. "
               "Returns previous suspend count. Thread resumes execution."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to resume. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_resume_thread, false});

    register_compat(srv, {
        OBFSTR("driver_query_memory"), OBFSTR("driver"),
        OBFSTR("Query virtual memory region information at an address in the attached process. "
               "Uses kernel ZwQueryVirtualMemory. Returns region base, size, state (commit/reserve/free), "
               "protection (RWX flags), and type (private/mapped/image)."),
        {{OBFSTR("address"), OBFSTR("string"),
                    OBFSTR("Virtual address to query (default: image base)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_query_memory, true});

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
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_protect_memory, false});

    register_compat(srv, {
        OBFSTR("driver_enumerate_memory_regions"), OBFSTR("driver"),
        OBFSTR("Walk the entire virtual address space of the attached process, enumerating all "
               "committed memory regions. Returns base, size, state, protection, and type for each. "
               "Useful for finding all executable regions, mapped images, private memory, etc."),
        {{OBFSTR("start"), OBFSTR("string"), OBFSTR("Start address (default 0)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("End address (default max user-mode)"), false},
         {OBFSTR("include_all"), OBFSTR("boolean"),
                    OBFSTR("Include free/reserved regions too (default false, only committed)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_enumerate_memory_regions, true});

    register_compat(srv, {
        OBFSTR("driver_read_peb"), OBFSTR("driver"),
        OBFSTR("Read the Process Environment Block (PEB) of the attached process via kernel. "
               "Returns PEB address, image base, BeingDebugged flag, NtGlobalFlag, "
               "loader data address, process heap, and heap info."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_read_peb, true});

    register_compat(srv, {
        OBFSTR("driver_spoof_debug_flags"), OBFSTR("driver"),
        OBFSTR("Clear ALL anti-debug indicators in the attached process from kernel space. "
               "Zeroes EPROCESS.DebugPort, PEB.BeingDebugged, clears PEB.NtGlobalFlag heap debug flags. "
               "Completely invisible to the target process. Call this before the target's anti-debug "
               "checks run to bypass IsDebuggerPresent, NtQueryInformationProcess, etc."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}}, driver_spoof_debug_flags, false});

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
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
        driver_set_hw_breakpoint, false});

    register_compat(srv, {
        OBFSTR("driver_clear_hw_breakpoint"), OBFSTR("driver"),
        OBFSTR("Clear a hardware breakpoint on a thread. Removes the address from the specified "
               "debug register and disables it in DR7."),
                {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID. Decimal string recommended; 0x-prefixed hex supported."), true},
         {OBFSTR("index"), OBFSTR("number"),
                    OBFSTR("Debug register index 0-3 to clear (default 0)"), false},
                 {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
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
          {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override."), false}},
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
        OBFSTR("driver_enumerate_wfp_callouts"), OBFSTR("driver"),
        OBFSTR("Enumerate Windows Filtering Platform (WFP) callouts directly from kernel memory. "
               "Anti-cheats (EAC/BE/Vanguard), firewalls, and EDRs use WFP to intercept network traffic. "
               "Returns the owning driver/module name, the callout ID, the callout GUID, and the applicable "
               "WFP layer GUID, allowing the AI to immediately identify which drivers are inspecting network "
               "packets and at what layer. Use this to discover hidden network filters installed by anti-cheat "
               "or EDR software."),
        {{OBFSTR("filter_module"), OBFSTR("string"),
          OBFSTR("Optional: filter by driver/module name substring (e.g., 'EasyAntiCheat', 'vgk', 'BEDaisy')"), false}},
        driver_enumerate_wfp_callouts, true});

    register_compat(srv, {
        OBFSTR("driver_get_socket_handles"), OBFSTR("driver"),
        OBFSTR("Walk the EPROCESS handle table of the attached process from kernel space, looking exclusively "
               "for socket objects (\\Device\\Afd). Extracts the local IP/Port, remote IP/Port, and protocol "
               "(TCP/UDP) directly from the kernel AFD endpoint structure. Completely bypasses user-mode "
               "rootkits or anti-cheats that hide their network connections from netstat/TCPView. "
               "Returns the raw handle value and kernel AFD_ENDPOINT address for further analysis."),
        {{OBFSTR("target_pid"), OBFSTR("number"),
          OBFSTR("Optional: PID to examine (default: attached process)"), false}},
        driver_get_socket_handles, true});

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
               "This is a composite tool that coordinates with driver_set_hw_breakpoint and driver_read_memory."),
        {{OBFSTR("address"), OBFSTR("string"),
          OBFSTR("Address of the send/recv/encrypt function (for 'start' operation)"), false},
         {OBFSTR("buffer_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer pointer (e.g., 'rcx', 'rdx', 'r8')"), false},
         {OBFSTR("size_register"), OBFSTR("string"),
          OBFSTR("Register containing the buffer size (e.g., 'rdx', 'r8', 'r9')"), false},
         {OBFSTR("max_packets"), OBFSTR("number"),
          OBFSTR("Max captures before auto-stop (default 1, max 16)"), false},
         {OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'start' (default), 'stop', 'get'/'results'"), false, {},
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("results")}},
         {OBFSTR("tid"), OBFSTR("number"),
          OBFSTR("Thread ID for breakpoint (default: 0 = first thread)"), false},
         {OBFSTR("bp_index"), OBFSTR("number"),
          OBFSTR("Debug register index 0-3 (default: 0)"), false}},
        driver_sniff_network_buffers, false});

    register_compat(srv, {
        OBFSTR("driver_dump_tcpip_connections"), OBFSTR("driver"),
        OBFSTR("Read the internal TCP/UDP connection tables directly from tcpip.sys/netio.sys memory via NSI. "
               "Functions as a 'kernel netstat' that cannot be lied to by user-mode hooks. "
               "Returns ALL active connections with states, process IDs, creation timestamps, and byte counters. "
               "Includes both established connections and listeners. "
               "Unlike the network_enumerate_connections tool, this uses direct kernel NSI enumeration "
               "(NsiEnumerateObjectsAllParameters) and includes TCP listeners and creation timestamps."),
        {{OBFSTR("target_pid"), OBFSTR("number"),
          OBFSTR("Optional: Only return connections for this PID (0 = all)"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"),
          OBFSTR("Optional: 'tcp', 'udp', or protocol number (0 = all)"), false}},
        driver_dump_tcpip_connections, true});


    register_compat(srv, {
        OBFSTR("driver_inject_packet"), OBFSTR("driver"),
        OBFSTR("Inject a crafted raw network packet into the network stack via WFP injection APIs. "
               "Supports both inbound and outbound injection of TCP/UDP packets. "
               "Can spoof source addresses and ports. Useful for testing firewalls, triggering specific "
               "protocol handlers, and advanced network analysis."),
        {{OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound'/'in' or 'outbound'/'out' (default out)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default tcp)"), false},
         {OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP address (e.g. '192.168.1.1')"), false},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("payload"), OBFSTR("string"), OBFSTR("Hex payload bytes (e.g. '48 45 4C 4C 4F')"), true},
         {OBFSTR("tcp_flags"), OBFSTR("number"), OBFSTR("TCP flags: SYN=2, ACK=16, RST=4, FIN=1, PSH=8"), false},
         {OBFSTR("tcp_seq"), OBFSTR("number"), OBFSTR("TCP sequence number"), false},
         {OBFSTR("tcp_ack"), OBFSTR("number"), OBFSTR("TCP acknowledgment number"), false}},
        driver_inject_packet, false});

    register_compat(srv, {
        OBFSTR("driver_modify_packet_rule"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level packet modification rules. Like Fiddler's AutoResponder but at the "
               "kernel level. Finds byte patterns in live network packets and replaces them in-place. "
               "Works on both TCP and UDP. Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'in', 'out', or 'both' (default both)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or 'any' (default any)"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Filter by port (0=any)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by PID (0=any)"), false},
         {OBFSTR("pattern"), OBFSTR("string"), OBFSTR("Hex bytes to search for in packets"), false},
         {OBFSTR("replacement"), OBFSTR("string"), OBFSTR("Hex bytes to replace pattern with"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("Rule ID for remove operation"), false}},
        driver_modify_packet_rule, false});

    register_compat(srv, {
        OBFSTR("driver_redirect_traffic"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level traffic redirection rules. Redirects network connections matching "
               "protocol/port/address criteria to a different destination. Like mitmproxy's upstream "
               "proxy but at the kernel WFP layer. Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', 'any'"), false},
         {OBFSTR("match_port"), OBFSTR("number"), OBFSTR("Original destination port to match"), false},
         {OBFSTR("match_addr"), OBFSTR("string"), OBFSTR("Original destination IP to match"), false},
         {OBFSTR("redirect_port"), OBFSTR("number"), OBFSTR("New destination port"), false},
         {OBFSTR("redirect_addr"), OBFSTR("string"), OBFSTR("New destination IP"), false}},
        driver_redirect_traffic, false});

    register_compat(srv, {
        OBFSTR("driver_reassemble_stream"), OBFSTR("driver"),
        OBFSTR("TCP stream reassembly engine. Like Wireshark's 'Follow TCP Stream' but from the kernel. "
               "Tracks TCP connections and reassembles the byte stream in order. Supports up to 8 "
               "concurrent streams, 64KB each. Operations: start, stop, get_data, list."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', 'get'/'get_data', 'list'"), false,
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("get"), OBFSTR("get_data"), OBFSTR("list")}},
         {OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP of the connection to track"), false},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by PID"), false}},
        driver_reassemble_stream, false});

    register_compat(srv, {
        OBFSTR("driver_deep_inspect"), OBFSTR("driver"),
        OBFSTR("Deep Packet Inspection engine. Analyzes live network traffic at the kernel level. "
               "Automatically detects and parses HTTP (method, host, path), TLS (version, SNI, content type), "
               "and DNS packets. Shows TCP flags, sequence numbers, and window sizes. "
               "Like Wireshark's protocol dissectors but running inside the kernel."),
        {{OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Only show packets from this PID (0=all)"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or number (0=all)"), false},
         {OBFSTR("filter_port"), OBFSTR("number"), OBFSTR("Only show packets on this port (0=all)"), false},
         {OBFSTR("http_only"), OBFSTR("boolean"), OBFSTR("Only show HTTP packets"), false},
         {OBFSTR("tls_only"), OBFSTR("boolean"), OBFSTR("Only show TLS packets"), false},
         {OBFSTR("dns_only"), OBFSTR("boolean"), OBFSTR("Only show DNS packets"), false}},
        driver_deep_inspect, true});

    register_compat(srv, {
        OBFSTR("driver_intercept_hold"), OBFSTR("driver"),
        OBFSTR("Burp Suite-style intercept-and-hold at the kernel level. When enabled, matching packets "
               "are BLOCKED and held in a buffer. You can inspect them, then release (forward), drop, or "
               "modify-and-release each packet. Up to 32 packets can be held simultaneously. "
               "Operations: enable, disable, status, get/get_held, release, drop, modify/modify_release."),
        {{OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'enable', 'disable', 'status', 'get'/'get_held', 'release', 'drop', 'modify'/'modify_release'"), false,
          {OBFSTR("enable"), OBFSTR("disable"), OBFSTR("status"), OBFSTR("get"), OBFSTR("get_held"),
           OBFSTR("release"), OBFSTR("drop"), OBFSTR("modify"), OBFSTR("modify_release")}},
         {OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("PID filter for enable"), false},
         {OBFSTR("filter_port"), OBFSTR("number"), OBFSTR("Port filter for enable"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("Protocol filter for enable"), false},
         {OBFSTR("hold_id"), OBFSTR("number"), OBFSTR("Packet ID for release/drop/modify"), false},
         {OBFSTR("modify_payload"), OBFSTR("string"), OBFSTR("New hex payload for modify_release"), false}},
        driver_intercept_hold, false});

    register_compat(srv, {
        OBFSTR("driver_kill_connection"), OBFSTR("driver"),
        OBFSTR("Kill a TCP connection by injecting a RST packet via the kernel WFP injection API. "
               "Instantly terminates the connection from the kernel level. Cannot be blocked by "
               "usermode firewalls or anti-cheat."),
        {{OBFSTR("src_addr"), OBFSTR("string"), OBFSTR("Source IP of the connection"), true},
         {OBFSTR("dst_addr"), OBFSTR("string"), OBFSTR("Destination IP"), true},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), true},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' (default)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Optional PID filter"), false}},
        driver_kill_connection, false});

    register_compat(srv, {
        OBFSTR("driver_spoof_dns"), OBFSTR("driver"),
        OBFSTR("Manage kernel-level DNS spoofing rules. When a DNS query matches a rule domain, "
               "a fake response with the configured IP is returned. Supports wildcard domains "
               "(e.g. '*.example.com'). Operations: add, remove, list, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', 'list', 'clear'"), false,
          {OBFSTR("add"), OBFSTR("remove"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("domain"), OBFSTR("string"), OBFSTR("Domain to match (e.g. '*.evil.com')"), false},
         {OBFSTR("spoof_addr"), OBFSTR("string"), OBFSTR("Fake IP to return (e.g. '127.0.0.1')"), false},
         {OBFSTR("ttl"), OBFSTR("number"), OBFSTR("TTL for spoofed response (default 300)"), false}},
        driver_spoof_dns, false});

    register_compat(srv, {
        OBFSTR("driver_bandwidth_monitor"), OBFSTR("driver"),
        OBFSTR("Per-process bandwidth monitoring from the kernel. Tracks bytes/packets sent and received "
               "for every process on the system with rate calculation. Like NetLimiter/GlassWire but "
               "from kernel WFP. Operations: start, stop, status/get, reset, per_process."),
        {{OBFSTR("operation"), OBFSTR("string"),
          OBFSTR("'start', 'stop', 'status'/'get', 'reset', 'per_process'"), false,
          {OBFSTR("start"), OBFSTR("stop"), OBFSTR("status"), OBFSTR("get"), OBFSTR("reset"), OBFSTR("per_process")}},
         {OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Filter by PID (0=all)"), false}},
        driver_bandwidth_monitor, false});

    register_compat(srv, {
        OBFSTR("driver_list_interfaces"), OBFSTR("driver"),
        OBFSTR("Enumerate all network interfaces from the kernel via GetIfTable2. Returns interface index, "
               "type (Ethernet/WiFi/Loopback), MTU, operational status, link speed, MAC address, "
               "IPv4 address, interface name, description, and byte counters."),
        {},
        driver_list_interfaces, true});

    register_compat(srv, {
        OBFSTR("driver_export_pcap"), OBFSTR("driver"),
        OBFSTR("Export captured network packets in standard PCAP format that can be opened in Wireshark. "
               "Builds proper PCAP file headers (magic 0xa1b2c3d4, v2.4, LINKTYPE_RAW). "
               "Optionally saves directly to a .pcap file. Requires capture to be active first."),
        {{OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("Only export packets from this PID"), false},
         {OBFSTR("filter_protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or number"), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Maximum packets to export (default 64, max 256)"), false},
         {OBFSTR("output_path"), OBFSTR("string"),
          OBFSTR("Save to this file path (e.g. 'C:\\\\capture.pcap'). If omitted, returns data inline."), false}},
        driver_export_pcap, false});

    register_compat(srv, {
        OBFSTR("driver_network_fingerprint"), OBFSTR("driver"),
        OBFSTR("Passive OS fingerprinting from TCP SYN packets (p0f-style). Analyzes TTL, TCP window size, "
               "MSS, window scale, SACK, and TCP options ordering to identify the remote operating system. "
               "Runs entirely in the kernel WFP layer. Operations: enable, disable, get."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable', 'disable', 'get' (default get)"), false,
          {OBFSTR("enable"), OBFSTR("disable"), OBFSTR("get")}}},
        driver_network_fingerprint, true});

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
        OBFSTR("driver_walk_seh_chain"), OBFSTR("driver"),
        OBFSTR("Walk the SEH (Structured Exception Handler) chain for a thread by reading the TEB exception list. "
               "For each handler, returns the record address, handler function address, and resolves which module "
               "owns the handler. Also provides VEH (Vectored Exception Handler) enumeration hints. "
               "Equivalent to x64dbg's SEH tab. Requires TID and attached process."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to walk SEH chain for"), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_walk_seh_chain, true});

    register_compat(srv, {
        OBFSTR("driver_find_code_caves"), OBFSTR("driver"),
        OBFSTR("Scan the attached process memory for code caves - contiguous regions of a fill byte "
               "(default 0x00) large enough to hold injected code. Scans executable regions by default. "
               "Equivalent to x64dbg's 'Find Code Caves' plugin. Returns address, size, and protection "
               "for each cave. Use for shellcode injection, detour trampolines, or hook stubs."),
        {{OBFSTR("min_size"), OBFSTR("number"), OBFSTR("Minimum cave size in bytes (default 64)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max caves to return (default 50, max 500)"), false},
         {OBFSTR("fill_byte"), OBFSTR("number"), OBFSTR("Byte value to treat as empty (default 0x00, use 0xCC for INT3 padding)"), false},
         {OBFSTR("executable_only"), OBFSTR("boolean"), OBFSTR("Only scan executable regions (default true)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_find_code_caves, true});

    register_compat(srv, {
        OBFSTR("driver_scan_memory_value"), OBFSTR("driver"),
        OBFSTR("Cheat Engine-style value scanner. Scan the target process memory for a specific value "
               "with type awareness: byte, int16, int32, int64, float, double, string. "
               "Supports exact match and range scan modes. For differential scans (changed/unchanged/"
               "increased/decreased), use driver_compare_memory_snapshot. "
               "Equivalent to Cheat Engine's First Scan. Filter by address range."),
        {{OBFSTR("value"), OBFSTR("number"), OBFSTR("Numeric value to search for"), false},
         {OBFSTR("value_string"), OBFSTR("string"), OBFSTR("String value (for value_type='string')"), false},
         {OBFSTR("value_max"), OBFSTR("number"), OBFSTR("Upper bound for range scan"), false},
         {OBFSTR("value_type"), OBFSTR("string"), OBFSTR("Data type: byte, int16, int32, int64, float, double, string (default int32)"), false,
          {OBFSTR("byte"), OBFSTR("int16"), OBFSTR("int32"), OBFSTR("int64"), OBFSTR("float"), OBFSTR("double"), OBFSTR("string")}},
         {OBFSTR("scan_mode"), OBFSTR("string"), OBFSTR("Scan mode: exact, range (default exact)"), false,
          {OBFSTR("exact"), OBFSTR("range")}},
         {OBFSTR("start"), OBFSTR("string"), OBFSTR("Scan start address (default 0x10000)"), false},
         {OBFSTR("end"), OBFSTR("string"), OBFSTR("Scan end address (default 0x7FFFFFFFFFFF)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max matches (default 100, max 10000)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_scan_memory_value, true});

    register_compat(srv, {
        OBFSTR("driver_pointer_scan"), OBFSTR("driver"),
        OBFSTR("Cheat Engine-style pointer scanner. Find all pointers in the target process that point "
               "to or near a target address (within max_offset). Identifies static pointers (in module .data sections) "
               "that can survive process restarts. Returns pointer address, value, offset from target, "
               "owning module, and module+offset for static references. "
               "Equivalent to CE's Pointer Scan with configurable depth and offset bounds."),
        {{OBFSTR("target_address"), OBFSTR("string"), OBFSTR("Address to find pointers to (hex)"), true},
         {OBFSTR("max_depth"), OBFSTR("number"), OBFSTR("Max pointer chain depth (default 3, max 7)"), false},
         {OBFSTR("max_offset"), OBFSTR("number"), OBFSTR("Max +/- offset from target (default 0x1000)"), false},
         {OBFSTR("limit"), OBFSTR("number"), OBFSTR("Max chains to return (default 50, max 500)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_pointer_scan, true});

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
        OBFSTR("driver_walk_stack"), OBFSTR("driver"),
        OBFSTR("Full stack walk for any thread via kernel driver. Gets thread context, reads RSP stack memory, "
               "and identifies return addresses by cross-referencing with loaded modules and verifying "
               "call instruction patterns. Resolves each frame to module+offset. "
               "Equivalent to x64dbg's Call Stack panel. Uses heuristic stack scanning for x64 code."),
        {{OBFSTR("tid"), OBFSTR("string"), OBFSTR("Thread ID to walk stack for"), true},
         {OBFSTR("max_frames"), OBFSTR("number"), OBFSTR("Max stack frames (default 64, max 256)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_walk_stack, true});

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
        OBFSTR("driver_compare_memory_snapshot"), OBFSTR("driver"),
        OBFSTR("Take and compare memory snapshots for differential analysis. Operations: "
               "'take' captures a snapshot, 'compare' diffs current memory against a saved snapshot, "
               "'list' shows all snapshots, 'clear' removes all. Enables Cheat Engine-style "
               "changed/unchanged/increased/decreased value scanning by comparing snapshots over time."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'take', 'compare', 'list', or 'clear'"), true,
          {OBFSTR("take"), OBFSTR("compare"), OBFSTR("list"), OBFSTR("clear")}},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Memory address for take/compare"), false},
         {OBFSTR("size"), OBFSTR("number"), OBFSTR("Bytes to snapshot (default 4096, max 1MB)"), false},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Snapshot name (default 'default')"), false},
         {OBFSTR("max_diffs"), OBFSTR("number"), OBFSTR("Max diffs to report on compare (default 200)"), false},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Optional PID override"), false}},
        driver_compare_memory_snapshot, false});

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
               "More detailed than driver_enumerate_modules - shows all three orderings and decoded flags."),
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
}

}
