#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_tools_fwd.hpp"
#include "sandbox.hpp"
#include "standalone_driver.hpp"
#include "guest_lab_bridge.hpp"
#include "standalone_settings.hpp"
#include "zydis_disasm.hpp"
#include "source_reconstructor.hpp"
#include "../../helpers/diag_log.hpp"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace
{
    std::string hex_addr(uint64_t value)
    {
        char buf[24];
        snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
        return buf;
    }

    bool parse_addr(const std::string& text, uint64_t& out)
    {
        try {
            if (text.size() > 2 && text[0] == '0' && (text[1] == 'b' || text[1] == 'B')) {
                uint64_t value = 0;
                for (size_t i = 2; i < text.size(); ++i) {
                    const char c = text[i];
                    if (c != '0' && c != '1')
                        return false;
                    value = (value << 1) | static_cast<uint64_t>(c == '1');
                }
                out = value;
                return true;
            }
            size_t idx = 0;
            out = std::stoull(text, &idx, 0);
            return idx == text.size();
        } catch (...) {
            return false;
        }
    }

    std::optional<uint64_t> parse_addr_opt(const json& params, const char* key)
    {
        if (!params.contains(key) || !params[key].is_string())
            return std::nullopt;
        uint64_t value = 0;
        if (!parse_addr(params[key].get<std::string>(), value))
            return std::nullopt;
        return value;
    }

    std::string trim(std::string text)
    {
        auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            return {};
        auto last = text.find_last_not_of(" \t\r\n");
        return text.substr(first, last - first + 1);
    }

    std::string to_lower(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }

    std::string wide_to_utf8_lossy(const std::wstring& text)
    {
        if (text.empty())
            return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) {
            const DWORD err = GetLastError();
            diag::log_tagged_fmt("mcp_tools", "wide_to_utf8 failed len=%zu err=%lu",
                text.size(), static_cast<unsigned long>(err));
            return {};
        }
        std::string out(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), len, nullptr, nullptr);
        return out;
    }

    std::string path_to_utf8(const fs::path& path)
    {
        return wide_to_utf8_lossy(path.native());
    }

    std::string prot_string(uint32_t protect)
    {
        switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "R--";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_WRITECOPY:         return "RWC";
        case PAGE_EXECUTE:           return "--X";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RWXC";
        default: break;
        }
        return hex_addr(protect);
    }

    std::string state_string(uint32_t state)
    {
        switch (state) {
        case MEM_COMMIT: return "COMMIT";
        case MEM_FREE: return "FREE";
        case MEM_RESERVE: return "RESERVE";
        default: return "UNKNOWN";
        }
    }

    std::string file_to_utf8(const fs::path& path)
    {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open())
            return {};
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    tool_result_t error(const std::string& text)
    {
        return tool_result_t::error(text);
    }

    std::string requested_target(const json& params)
    {
        if (params.contains("target") && params["target"].is_string())
            return to_lower(params["target"].get<std::string>());
        return "auto";
    }

    bool wants_guest_target(const json& params)
    {
        if (!guest_lab::is_active())
            return false;
        const std::string target = requested_target(params);
        return target != "host";
    }

    uint32_t guest_timeout_ms(const json& params)
    {
        uint32_t timeout = 5000;
        if (params.contains("timeout_ms")) {
            const auto& value = params["timeout_ms"];
            uint64_t raw = 0;
            if (value.is_number_unsigned()) {
                raw = value.get<uint64_t>();
            } else if (value.is_number_integer()) {
                const int64_t signed_raw = value.get<int64_t>();
                if (signed_raw > 0)
                    raw = static_cast<uint64_t>(signed_raw);
            }
            if (raw > 0)
                timeout = static_cast<uint32_t>(raw > 300000 ? 300000 : raw);
        }
        return timeout;
    }

    json guest_params_from(const json& params)
    {
        json p = params.is_object() ? params : json::object();
        p.erase("target");
        p.erase("timeout_ms");
        return p;
    }

    void enrich_guest_data(json& data)
    {
        data["backend"] = "windows_sandbox_guest";
        auto session = guest_lab::current();
        data["sandbox_dir"] = wide_to_utf8_lossy(session.session_dir);
        data["guest_bridge_dir"] = wide_to_utf8_lossy(session.bridge_dir);
        if (data.contains("artifact_name") && data["artifact_name"].is_string()) {
            std::string host_path = guest_lab::artifact_host_path(data["artifact_name"].get<std::string>());
            if (!host_path.empty())
                data["host_artifact_path"] = host_path;
        }
    }

    tool_result_t guest_call(const std::string& command, const json& params, const std::string& message)
    {
        std::string err;
        json response = guest_lab::request(command, guest_params_from(params), guest_timeout_ms(params), &err);
        if (!err.empty())
            return error(err);
        json data = response.value("data", json::object());
        enrich_guest_data(data);
        return tool_result_t::ok(message, data);
    }

    bool hex_to_bytes_string(const std::string& hex, std::vector<uint8_t>& out)
    {
        out.clear();
        if (hex.size() % 2 != 0)
            return false;
        out.reserve(hex.size() / 2);
        auto nibble = [](char c, uint8_t& v) {
            if (c >= '0' && c <= '9') {
                v = static_cast<uint8_t>(c - '0');
                return true;
            }
            if (c >= 'a' && c <= 'f') {
                v = static_cast<uint8_t>(c - 'a' + 10);
                return true;
            }
            if (c >= 'A' && c <= 'F') {
                v = static_cast<uint8_t>(c - 'A' + 10);
                return true;
            }
            return false;
        };
        for (size_t i = 0; i < hex.size(); i += 2) {
            uint8_t hi = 0, lo = 0;
            if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo))
                return false;
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return true;
    }

    std::mutex& s_last_web_error_mtx()
    {
        static std::mutex m;
        return m;
    }

    std::string& s_last_web_error_ref()
    {
        static std::string s;
        return s;
    }

    void set_last_web_error(const std::string& text)
    {
        std::lock_guard<std::mutex> lk(s_last_web_error_mtx());
        s_last_web_error_ref() = text;
    }

    tool_result_t handle_driver_status(const json&)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_driver_status entry");
        json out;
        out["ready"] = driver_bridge::is_loaded();
        out["kernel_backend"] = driver_bridge::using_kernel_driver();
        out["attached_pid"] = driver_bridge::attached_pid();
        out["attached_process"] = driver_bridge::attached_process_name();
        out["status"] = driver_bridge::status();
        if (!driver_bridge::last_error().empty())
            out["last_error"] = driver_bridge::last_error();
        return tool_result_t::ok(driver_bridge::status(), out);
    }

    tool_result_t handle_guest_lab_status(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_status entry");
        auto session = guest_lab::current();
        json out;
        out["active"] = session.active;
        out["sandbox_dir"] = wide_to_utf8_lossy(session.session_dir);
        out["guest_bridge_dir"] = wide_to_utf8_lossy(session.bridge_dir);
        out["sample_path"] = wide_to_utf8_lossy(session.sample_path);
        out["started_ms"] = session.started_ms;
        out["backend"] = "windows_sandbox_guest";
        if (!session.active)
            return tool_result_t::ok("No active Windows Sandbox guest lab.", out);
        std::string err;
        json response = guest_lab::request("status", json::object(), guest_timeout_ms(params), &err);
        if (!err.empty()) {
            out["agent_ready"] = false;
            out["agent_error"] = err;
            return tool_result_t::ok("Windows Sandbox guest lab is active, but the agent is not ready.", out);
        }
        json data = response.value("data", json::object());
        enrich_guest_data(data);
        out["agent_ready"] = true;
        out["agent"] = data;
        const char* keys[] = {
            "agent_pid",
            "active_pid",
            "sample_pid",
            "sample_path",
            "sample_args",
            "sample_alive",
            "sample_exit_code",
            "process_alive",
            "attached_pid",
            "launch_error"
        };
        for (const char* key : keys) {
            if (data.contains(key))
                out[key] = data[key];
        }
        return tool_result_t::ok("Windows Sandbox guest lab is active.", out);
    }

    tool_result_t handle_guest_lab_attach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_attach entry");
        return guest_call("attach", params, "Attached to guest process.");
    }

    tool_result_t handle_guest_lab_detach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_detach entry");
        return guest_call("detach", params, "Detached from guest process.");
    }

    tool_result_t handle_guest_lab_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_list_processes entry");
        return guest_call("list_processes", params, "Enumerated guest processes.");
    }

    tool_result_t handle_guest_lab_memory_map(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_memory_map entry");
        return guest_call("memory_map", params, "Enumerated guest memory map.");
    }

    tool_result_t handle_guest_lab_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_query_memory entry");
        return guest_call("query_memory", params, "Queried guest memory region.");
    }

    tool_result_t handle_guest_lab_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_read_memory entry");
        return guest_call("read_memory", params, "Read guest process memory.");
    }

    tool_result_t handle_guest_lab_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_read_string entry");
        return guest_call("read_string", params, "Read guest process string.");
    }

    tool_result_t handle_guest_lab_enumerate_modules(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_enumerate_modules entry");
        return guest_call("modules", params, "Enumerated guest modules.");
    }

    tool_result_t handle_guest_lab_enumerate_threads(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_enumerate_threads entry");
        return guest_call("threads", params, "Enumerated guest threads.");
    }

    tool_result_t handle_guest_lab_dump_region(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_dump_region entry");
        return guest_call("dump_region", params, "Dumped guest memory region.");
    }

    tool_result_t handle_guest_lab_search_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_guest_lab_search_memory entry");
        return guest_call("search_memory", params, "Searched guest process memory.");
    }

    tool_result_t handle_driver_load(const json&)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_driver_load entry");
        if (!driver_bridge::load_kernel_driver())
            return error(driver_bridge::last_error().empty() ? "Failed to load kernel driver." : driver_bridge::last_error());
        return handle_driver_status({});
    }

    tool_result_t handle_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_list_processes entry");
        if (wants_guest_target(params))
            return handle_guest_lab_list_processes(params);
        const std::string filter = to_lower(params.value("filter", std::string()));
        json items = json::array();
        for (const auto& proc : driver_bridge::enumerate_processes()) {
            if (!filter.empty() && to_lower(proc.name).find(filter) == std::string::npos)
                continue;
            items.push_back({{"pid", proc.pid}, {"name", proc.name}});
        }
        return tool_result_t::ok("Enumerated processes", json{{"processes", items}});
    }

    tool_result_t handle_driver_attach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_driver_attach entry");
        if (wants_guest_target(params))
            return handle_guest_lab_attach(params);
        if (params.contains("pid") && params["pid"].is_number_integer()) {
            uint32_t pid = params["pid"].get<uint32_t>();
            if (pid == static_cast<uint32_t>(GetCurrentProcessId()))
                return error("Cannot attach to AiDA's own process.");
            if (driver_bridge::attach(pid))
                return handle_driver_status({});
            return error(driver_bridge::last_error());
        }
        if (params.contains("process") && params["process"].is_string()) {
            std::string name = params["process"].get<std::string>();
            std::string lower = to_lower(name);
            if (lower.find("aidastan") != std::string::npos
                || lower.find("aida_stan") != std::string::npos
                || lower == "aida.exe")
                return error("Cannot attach to AiDA's own process.");
            if (driver_bridge::attach_by_name(name))
                return handle_driver_status({});
            return error(driver_bridge::last_error());
        }
        return error("Provide either a numeric pid or a process name.");
    }

    tool_result_t handle_driver_detach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_driver_detach entry");
        if (wants_guest_target(params))
            return handle_guest_lab_detach(params);
        driver_bridge::detach();
        return tool_result_t::ok("Detached from the live process.");
    }

    tool_result_t ensure_attached()
    {
        if (driver_bridge::attached_pid() == 0)
            return error("No process is attached. Call driver_attach first.");
        return tool_result_t::ok("");
    }

    tool_result_t handle_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_memory entry");
        if (wants_guest_target(params))
            return handle_guest_lab_read_memory(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        const auto size = static_cast<size_t>(params.value("size", 256));
        std::vector<uint8_t> bytes;
        if (!driver_bridge::read_memory(*address, size, bytes))
            return error("Memory read failed. Ensure the kernel driver is loaded and attached.");

        std::string hex;
        for (uint8_t b : bytes) {
            char chunk[4];
            snprintf(chunk, sizeof(chunk), "%02X", b);
            hex += chunk;
        }

        std::string ascii;
        ascii.reserve(bytes.size());
        for (uint8_t b : bytes)
            ascii.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');

        json out;
        out["address"] = hex_addr(*address);
        out["size"] = bytes.size();
        out["hex"] = hex;
        out["ascii"] = ascii;
        return tool_result_t::ok("Read process memory.", out);
    }

    tool_result_t handle_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_string entry");
        if (wants_guest_target(params))
            return handle_guest_lab_read_string(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        std::string text;
        if (!driver_bridge::read_string(*address, static_cast<size_t>(params.value("max_length", 256)), text))
            return error("Could not read a string at the requested address.");

        return tool_result_t::ok("Read string.", json{{"address", hex_addr(*address)}, {"text", text}});
    }

    tool_result_t handle_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_query_memory entry");
        if (wants_guest_target(params))
            return handle_guest_lab_query_memory(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        driver_bridge::memory_region_t region;
        if (!driver_bridge::query_memory(*address, region))
            return error("Memory query failed. Ensure the kernel driver is loaded and attached.");

        json out;
        out["base"] = hex_addr(region.base);
        out["size"] = region.size;
        out["state"] = state_string(region.state);
        out["protect"] = prot_string(region.protect);
        out["type"] = hex_addr(region.type);
        return tool_result_t::ok("Queried memory region.", out);
    }

    tool_result_t handle_enumerate_modules(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_enumerate_modules entry");
        if (wants_guest_target(params))
            return handle_guest_lab_enumerate_modules(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        json modules = json::array();
        for (const auto& mod : driver_bridge::enumerate_modules()) {
            modules.push_back({
                {"name", mod.name},
                {"path", mod.path},
                {"base", hex_addr(mod.base)},
                {"size", mod.size}
            });
        }
        return tool_result_t::ok("Enumerated modules.", json{{"modules", modules}});
    }

    tool_result_t handle_enumerate_threads(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_enumerate_threads entry");
        if (wants_guest_target(params))
            return handle_guest_lab_enumerate_threads(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        json threads = json::array();
        for (const auto& thread : driver_bridge::enumerate_threads()) {
            threads.push_back({
                {"tid", thread.tid},
                {"owner_pid", thread.owner_pid},
                {"priority", thread.priority}
            });
        }
        return tool_result_t::ok("Enumerated threads.", json{{"threads", threads}});
    }

    tool_result_t handle_disassemble_address(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_disassemble_address entry");
        if (wants_guest_target(params)) {
            const auto address = parse_addr_opt(params, "address");
            if (!address)
                return error("Missing or invalid address.");
            const size_t bytes_to_read = static_cast<size_t>(params.value("size", 128));
            const size_t max_count = static_cast<size_t>(params.value("count", 32));
            json read_params = guest_params_from(params);
            read_params["size"] = bytes_to_read;
            std::string err;
            json response = guest_lab::request("read_memory", read_params, guest_timeout_ms(params), &err);
            if (!err.empty())
                return error(err);
            json data = response.value("data", json::object());
            std::string hex = data.value("hex", std::string());
            std::vector<uint8_t> bytes;
            if (!hex_to_bytes_string(hex, bytes))
                return error("Guest memory response contained invalid hex.");
            json instructions = json::array();
            uint64_t cursor = *address;
            size_t offset = 0;
            while (offset < bytes.size() && instructions.size() < max_count) {
                const auto insn = zydis_decode_one(bytes.data() + offset,
                                                   static_cast<int>(bytes.size() - offset), cursor);
                instructions.push_back({
                    {"address", hex_addr(insn.addr)},
                    {"mnemonic", insn.mnem},
                    {"operands", insn.ops},
                    {"length", insn.len}
                });
                const int advance = (insn.len > 1) ? insn.len : 1;
                offset += static_cast<size_t>(advance);
                cursor += static_cast<uint64_t>(advance);
            }
            json out;
            out["address"] = hex_addr(*address);
            out["instructions"] = instructions;
            out["bytes_read"] = bytes.size();
            enrich_guest_data(out);
            return tool_result_t::ok("Disassembled guest process memory.", out);
        }
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        const size_t bytes_to_read = static_cast<size_t>(params.value("size", 128));
        const size_t max_count = static_cast<size_t>(params.value("count", 32));

        std::vector<uint8_t> bytes;
        if (!driver_bridge::read_memory(*address, bytes_to_read, bytes))
            return error("Could not read the requested memory.");

        json instructions = json::array();
        uint64_t cursor = *address;
        size_t offset = 0;
        while (offset < bytes.size() && instructions.size() < max_count) {
            const auto insn = zydis_decode_one(bytes.data() + offset,
                                               static_cast<int>(bytes.size() - offset), cursor);
            instructions.push_back({
                {"address", hex_addr(insn.addr)},
                {"mnemonic", insn.mnem},
                {"operands", insn.ops},
                {"length", insn.len}
            });
            const int advance = (insn.len > 1) ? insn.len : 1;
            offset += static_cast<size_t>(advance);
            cursor += static_cast<uint64_t>(advance);
        }

        return tool_result_t::ok("Disassembled live memory.",
                                 json{{"address", hex_addr(*address)}, {"instructions", instructions}});
    }

    tool_result_t handle_disassemble_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_disassemble_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");

        DisasmFile file;
        const auto path = params["path"].get<std::string>();
        const size_t limit = static_cast<size_t>(params.value("count", 64));
        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file load_start path='%s' count=%zu",
            path.c_str(), limit);
        if (!disasm::load_pe(path, file))
            return error(file.err.empty() ? "Unable to load PE file." : file.err);
        size_t exec_sections = 0;
        size_t exec_bytes = 0;
        for (const auto& section : file.sections) {
            if (section.is_executable) {
                ++exec_sections;
                exec_bytes += section.bytes.size();
            }
        }
        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file load_done path='%s' image=0x%llX sections=%zu exec_sections=%zu exec_bytes=%zu",
            path.c_str(),
            static_cast<unsigned long long>(file.image_base),
            file.sections.size(),
            exec_sections,
            exec_bytes);

        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file decode_start path='%s' max_instrs=%zu",
            path.c_str(), limit);
        disasm::decode_section_limited(file, limit);
        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file decode_done path='%s' instrs=%zu",
            path.c_str(), file.instrs.size());
        json instructions = json::array();
        for (size_t i = 0; i < file.instrs.size() && i < limit; ++i) {
            const auto& insn = file.instrs[i];
            instructions.push_back({
                {"address", hex_addr(insn.addr)},
                {"mnemonic", insn.mnem},
                {"operands", insn.ops},
                {"length", insn.len}
            });
        }

        json out;
        out["path"] = path;
        out["image_base"] = hex_addr(file.image_base);
        out["entry_point"] = hex_addr(file.entry_point);
        out["instruction_count"] = file.instrs.size();
        out["exec_section_count"] = exec_sections;
        out["exec_byte_count"] = exec_bytes;
        out["decode_limited"] = true;
        out["instructions"] = instructions;
        return tool_result_t::ok("Disassembled PE file.", out);
    }

    tool_result_t handle_sandbox_execute(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_sandbox_execute entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        if (!g_sa_settings.sandbox.enabled)
            return error("Windows Sandbox execution is disabled in settings.");

        sandbox::config cfg;
        const auto exe_path = params["path"].get<std::string>();
        cfg.exe_path = std::wstring(exe_path.begin(), exe_path.end());
        if (params.contains("arguments") && params["arguments"].is_string()) {
            const auto arg_text = params["arguments"].get<std::string>();
            cfg.arguments = std::wstring(arg_text.begin(), arg_text.end());
        }
        if (params.contains("working_dir") && params["working_dir"].is_string()) {
            const auto work_dir = params["working_dir"].get<std::string>();
            cfg.working_dir = std::wstring(work_dir.begin(), work_dir.end());
        }
        cfg.timeout_ms = static_cast<uint32_t>(params.value("timeout_ms", g_sa_settings.sandbox.timeout_ms));
        cfg.max_memory = static_cast<uint64_t>(g_sa_settings.sandbox.memory_limit_mb) * 1024ULL * 1024ULL;
        cfg.max_memory_mb = static_cast<uint32_t>(g_sa_settings.sandbox.memory_limit_mb);
        cfg.capture_stdout = params.value("capture_stdout", true);
        cfg.capture_stderr = params.value("capture_stderr", true);
        cfg.allow_network = g_sa_settings.sandbox.network_mode == "default";
        cfg.cancel_token = mcp_standalone::current_cancel_token();

        const auto run = sandbox::execute(cfg);
        if (run.cancelled)
            return error(run.error.empty() ? std::string("Sandbox execution cancelled by client request.") : run.error);
        if (!run.success && !run.timed_out)
            return error(run.error);

        json out;
        out["success"] = run.success;
        out["exit_code"] = run.exit_code;
        out["pid"] = run.pid;
        out["timed_out"] = run.timed_out;
        out["killed"] = run.killed;
        out["cancelled"] = run.cancelled;
        out["elapsed_ms"] = run.elapsed_ms;
        out["session_dir"] = run.session_dir;
        out["wsb_path"] = run.wsb_path;
        if (!run.stdout_data.empty())
            out["stdout"] = run.stdout_data;
        if (!run.stderr_data.empty())
            out["stderr"] = run.stderr_data;
        return tool_result_t::ok("Executed sample inside Windows Sandbox.", out);
    }

    tool_result_t handle_convert_number(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_convert_number entry");
        auto value_text = [](const json& v) -> std::optional<std::string> {
            if (v.is_string())
                return v.get<std::string>();
            if (v.is_number_unsigned())
                return std::to_string(v.get<uint64_t>());
            if (v.is_number_integer())
                return std::to_string(v.get<int64_t>());
            return std::nullopt;
        };

        auto parse_radix = [](const json& root) -> int {
            const char* radix_key = root.contains("input_base") ? "input_base" : root.contains("from") ? "from" : nullptr;
            if (radix_key) {
                const auto& v = root[radix_key];
                if (v.is_number_integer())
                    return v.get<int>();
                if (v.is_string()) {
                    const auto s = to_lower(trim(v.get<std::string>()));
                    if (s == "auto")
                        return 0;
                    if (s == "hex" || s == "hexadecimal")
                        return 16;
                    if (s == "dec" || s == "decimal")
                        return 10;
                    if (s == "bin" || s == "binary")
                        return 2;
                    if (s == "oct" || s == "octal")
                        return 8;
                }
            }
            if (root.contains("base")) {
                const auto& v = root["base"];
                if (v.is_number_integer()) {
                    const int base = v.get<int>();
                    if (base == 0 || base == 2 || base == 8 || base == 10 || base == 16)
                        return base;
                }
                if (v.is_string()) {
                    const auto s = to_lower(trim(v.get<std::string>()));
                    if (s == "auto")
                        return 0;
                    if (s == "hex" || s == "hexadecimal")
                        return 16;
                    if (s == "dec" || s == "decimal")
                        return 10;
                    if (s == "bin" || s == "binary")
                        return 2;
                    if (s == "oct" || s == "octal")
                        return 8;
                    try {
                        const int base = std::stoi(s);
                        if (base == 0 || base == 2 || base == 8 || base == 10 || base == 16)
                            return base;
                    } catch (...) {
                    }
                }
            }
            return 0;
        };

        struct parsed_number_t {
            uint64_t value = 0;
            std::string normalized;
            std::string input_base;
            bool negative = false;
        };

        auto parse_number = [](std::string text, int forced_base) -> std::optional<parsed_number_t> {
            text = trim(text);
            if (text.empty())
                return std::nullopt;

            std::string compact;
            compact.reserve(text.size());
            for (char c : text) {
                if (c != '_' && c != '\'' && c != '`' && !std::isspace(static_cast<unsigned char>(c)))
                    compact.push_back(c);
            }
            if (compact.empty())
                return std::nullopt;

            bool negative = false;
            if (compact.front() == '+' || compact.front() == '-') {
                negative = compact.front() == '-';
                compact.erase(compact.begin());
            }
            if (compact.empty())
                return std::nullopt;

            int base = forced_base;
            if (base != 0 && base != 2 && base != 8 && base != 10 && base != 16)
                return std::nullopt;

            std::string digits = compact;
            if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
                if (base != 0 && base != 16)
                    return std::nullopt;
                base = 16;
                digits = digits.substr(2);
            } else if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'b' || digits[1] == 'B')) {
                if (base != 0 && base != 2)
                    return std::nullopt;
                base = 2;
                digits = digits.substr(2);
            } else if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'o' || digits[1] == 'O')) {
                if (base != 0 && base != 8)
                    return std::nullopt;
                base = 8;
                digits = digits.substr(2);
            } else if (!digits.empty()) {
                const char suffix = static_cast<char>(std::tolower(static_cast<unsigned char>(digits.back())));
                if (suffix == 'h' || suffix == 'b' || suffix == 'o' || suffix == 'd') {
                    const int suffix_base = suffix == 'h' ? 16 : suffix == 'b' ? 2 : suffix == 'o' ? 8 : 10;
                    if (base != 0 && base != suffix_base)
                        return std::nullopt;
                    base = suffix_base;
                    digits.pop_back();
                }
            }

            if (digits.empty())
                return std::nullopt;
            if (base == 0)
                base = (digits.size() > 1 && digits[0] == '0') ? 8 : 10;

            auto digit_value = [](char c) -> int {
                if (c >= '0' && c <= '9')
                    return c - '0';
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                return -1;
            };

            uint64_t magnitude = 0;
            for (char c : digits) {
                const int d = digit_value(c);
                if (d < 0 || d >= base)
                    return std::nullopt;
                const uint64_t ubase = static_cast<uint64_t>(base);
                if (magnitude > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(d)) / ubase)
                    return std::nullopt;
                magnitude = magnitude * ubase + static_cast<uint64_t>(d);
            }

            parsed_number_t parsed;
            parsed.value = negative ? (0ULL - magnitude) : magnitude;
            parsed.normalized = (negative ? "-" : "") + digits;
            parsed.input_base = base == 16 ? "hexadecimal" : base == 10 ? "decimal" : base == 8 ? "octal" : "binary";
            parsed.negative = negative;
            return parsed;
        };

        std::optional<std::string> input_opt;
        std::string inferred_kind;
        if (params.contains("value")) {
            input_opt = value_text(params["value"]);
        } else {
            for (const char* key : {"va", "rva", "file_offset", "foa"}) {
                if (!params.contains(key))
                    continue;
                input_opt = value_text(params[key]);
                inferred_kind = key;
                break;
            }
        }
        if (!input_opt)
            return error("Provide value, va, rva, file_offset, or foa as a string or integer.");

        const auto parsed = parse_number(*input_opt, parse_radix(params));
        if (!parsed)
            return error("Unable to parse the provided number.");

        const uint64_t value = parsed->value;

        auto mask_bits = [](int bits) -> uint64_t {
            return bits >= 64 ? std::numeric_limits<uint64_t>::max() : ((1ULL << bits) - 1ULL);
        };

        auto signed_value = [&](int bits) -> int64_t {
            const uint64_t mask = mask_bits(bits);
            const uint64_t masked = value & mask;
            if (bits >= 64)
                return static_cast<int64_t>(masked);
            const uint64_t sign = 1ULL << (bits - 1);
            if ((masked & sign) == 0)
                return static_cast<int64_t>(masked);
            const uint64_t magnitude = ((~masked) & mask) + 1ULL;
            return -static_cast<int64_t>(magnitude);
        };

        auto hex_width = [](uint64_t v, int digits) -> std::string {
            std::ostringstream ss;
            ss << "0x" << std::uppercase << std::hex << std::setw(digits) << std::setfill('0') << v;
            return ss.str();
        };

        auto octal_text = [](uint64_t v) -> std::string {
            std::ostringstream ss;
            ss << "0o" << std::oct << v;
            return ss.str();
        };

        auto binary_text = [](uint64_t v, int bits) -> std::string {
            std::string s;
            s.reserve(static_cast<size_t>(bits) + 2);
            for (int i = bits - 1; i >= 0; --i)
                s.push_back(((v >> i) & 1ULL) ? '1' : '0');
            const auto first = s.find_first_not_of('0');
            if (first == std::string::npos)
                s = "0";
            else
                s.erase(0, first);
            return "0b" + s;
        };

        auto bytes_hex = [&](uint64_t v, int bytes, bool little) -> std::string {
            std::ostringstream ss;
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                if (n)
                    ss << ' ';
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned int>((v >> (i * 8)) & 0xFFULL);
            }
            return ss.str();
        };

        auto byte_array = [&](uint64_t v, int bytes, bool little) -> json {
            json arr = json::array();
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                arr.push_back(static_cast<unsigned int>((v >> (i * 8)) & 0xFFULL));
            }
            return arr;
        };

        auto ascii_for = [&](uint64_t v, int bytes, bool little) -> std::string {
            std::string s;
            s.reserve(static_cast<size_t>(bytes));
            for (int n = 0; n < bytes; ++n) {
                const int i = little ? n : bytes - 1 - n;
                const char c = static_cast<char>((v >> (i * 8)) & 0xFFULL);
                s.push_back(c >= 32 && c < 127 ? c : '.');
            }
            return s;
        };

        auto bit_count = [](uint64_t v) -> int {
            int n = 0;
            while (v) {
                v &= v - 1ULL;
                ++n;
            }
            return n;
        };

        auto low_bit_index = [](uint64_t v) -> int {
            if (!v)
                return -1;
            int i = 0;
            while ((v & 1ULL) == 0) {
                v >>= 1;
                ++i;
            }
            return i;
        };

        auto high_bit_index = [](uint64_t v) -> int {
            if (!v)
                return -1;
            int i = 63;
            while (((v >> i) & 1ULL) == 0)
                --i;
            return i;
        };

        auto align_down = [](uint64_t v, uint64_t a) -> uint64_t {
            return a ? (v / a) * a : v;
        };

        auto align_up = [](uint64_t v, uint64_t a) -> uint64_t {
            if (!a)
                return v;
            const uint64_t down = (v / a) * a;
            if (down == v)
                return v;
            if (down > std::numeric_limits<uint64_t>::max() - a)
                return std::numeric_limits<uint64_t>::max();
            return down + a;
        };

        auto min_bytes = [](uint64_t v) -> int {
            if (v <= 0xFFULL)
                return 1;
            if (v <= 0xFFFFULL)
                return 2;
            if (v <= 0xFFFFFFFFULL)
                return 4;
            return 8;
        };

        int display_bytes = min_bytes(value);
        if (params.contains("size") && params["size"].is_number_integer()) {
            const int requested = params["size"].get<int>();
            if (requested == 1 || requested == 2 || requested == 4 || requested == 8)
                display_bytes = requested;
        } else if (params.contains("bytes") && params["bytes"].is_number_integer()) {
            const int requested = params["bytes"].get<int>();
            if (requested == 1 || requested == 2 || requested == 4 || requested == 8)
                display_bytes = requested;
        } else if (params.contains("bits") && params["bits"].is_number_integer()) {
            const int requested = params["bits"].get<int>();
            if (requested == 8 || requested == 16 || requested == 32 || requested == 64)
                display_bytes = requested / 8;
        }

        json out;
        out["input"] = *input_opt;
        out["normalized_input"] = parsed->normalized;
        out["input_base"] = parsed->input_base;
        out["negative_input"] = parsed->negative;
        out["decimal"] = value;
        out["decimal_string"] = std::to_string(value);
        out["signed_decimal"] = static_cast<int64_t>(value);
        out["hex"] = hex_addr(value);
        out["hex_u64"] = hex_width(value, 16);
        out["octal"] = octal_text(value);
        out["binary"] = binary_text(value, std::max(1, high_bit_index(value) + 1));
        out["min_size_bytes"] = min_bytes(value);
        out["display_size_bytes"] = display_bytes;
        out["bytes_le"] = bytes_hex(value, display_bytes, true);
        out["bytes_be"] = bytes_hex(value, display_bytes, false);
        out["byte_array_le"] = byte_array(value, display_bytes, true);
        out["byte_array_be"] = byte_array(value, display_bytes, false);
        out["ascii"] = ascii_for(value, display_bytes, true);
        out["ascii_le"] = out["ascii"];
        out["ascii_be"] = ascii_for(value, display_bytes, false);

        json integers;
        for (int bits : {8, 16, 32, 64}) {
            const uint64_t masked = value & mask_bits(bits);
            json view;
            view["unsigned"] = masked;
            view["unsigned_hex"] = hex_width(masked, bits / 4);
            view["signed"] = signed_value(bits);
            view["bytes_le"] = bytes_hex(masked, bits / 8, true);
            view["bytes_be"] = bytes_hex(masked, bits / 8, false);
            integers["u" + std::to_string(bits)] = view;
        }
        out["integer_views"] = integers;
        out["u8"] = integers["u8"]["unsigned"];
        out["i8"] = integers["u8"]["signed"];
        out["u16"] = integers["u16"]["unsigned"];
        out["i16"] = integers["u16"]["signed"];
        out["u32"] = integers["u32"]["unsigned"];
        out["i32"] = integers["u32"]["signed"];
        out["u64"] = integers["u64"]["unsigned"];
        out["i64"] = integers["u64"]["signed"];

        json bits;
        bits["low8"] = value & 0xFFULL;
        bits["high8"] = (value >> 56) & 0xFFULL;
        bits["low16"] = value & 0xFFFFULL;
        bits["high16"] = (value >> 48) & 0xFFFFULL;
        bits["low32"] = value & 0xFFFFFFFFULL;
        bits["high32"] = (value >> 32) & 0xFFFFFFFFULL;
        bits["popcount"] = bit_count(value);
        bits["parity"] = bit_count(value) & 1;
        bits["lowest_set_bit"] = low_bit_index(value);
        bits["highest_set_bit"] = high_bit_index(value);
        bits["bit_length"] = value ? high_bit_index(value) + 1 : 0;
        bits["is_power_of_two"] = value != 0 && (value & (value - 1ULL)) == 0;
        bits["not"] = hex_addr(~value);
        out["bit_fields"] = bits;

        json floats;
        const uint32_t f_bits = static_cast<uint32_t>(value & 0xFFFFFFFFULL);
        float f = 0.0f;
        std::memcpy(&f, &f_bits, sizeof(f));
        if (std::isfinite(f))
            floats["float32"] = f;
        double d = 0.0;
        std::memcpy(&d, &value, sizeof(d));
        if (std::isfinite(d))
            floats["float64"] = d;
        out["floating_point"] = floats;

        json alignment;
        for (uint64_t a : {2ULL, 4ULL, 8ULL, 16ULL, 32ULL, 64ULL, 256ULL, 4096ULL}) {
            json view;
            view["down"] = hex_addr(align_down(value, a));
            view["up"] = hex_addr(align_up(value, a));
            view["offset"] = value % a;
            alignment[std::to_string(a)] = view;
        }
        out["alignment"] = alignment;

        auto parse_optional_value = [&](const char* key) -> std::optional<uint64_t> {
            if (!params.contains(key))
                return std::nullopt;
            const auto text = value_text(params[key]);
            if (!text)
                return std::nullopt;
            const auto parsed_value = parse_number(*text, 0);
            if (!parsed_value)
                return std::nullopt;
            return parsed_value->value;
        };

        std::optional<uint64_t> module_base = parse_optional_value("module_base");
        if (!module_base)
            module_base = parse_optional_value("image_base");
        std::optional<uint64_t> module_size = parse_optional_value("module_size");
        std::string module_name;
        if (params.contains("module_name") && params["module_name"].is_string()) {
            module_name = params["module_name"].get<std::string>();
            const auto target = to_lower(module_name);
            for (const auto& mod : driver_bridge::enumerate_modules()) {
                const auto name = to_lower(mod.name);
                const auto path = to_lower(mod.path);
                if (name == target || path.find(target) != std::string::npos) {
                    module_base = mod.base;
                    module_size = mod.size;
                    module_name = mod.name;
                    break;
                }
            }
        }

        json address;
        if (module_base) {
            address["module_base"] = hex_addr(*module_base);
            if (module_size)
                address["module_size"] = *module_size;
            if (!module_name.empty())
                address["module_name"] = module_name;

            json as_va;
            as_va["va"] = hex_addr(value);
            if (value >= *module_base) {
                const uint64_t rva = value - *module_base;
                as_va["rva"] = hex_addr(rva);
                as_va["rva_decimal"] = rva;
                if (module_size)
                    as_va["inside_module"] = rva < *module_size;
                as_va["module_expr"] = (!module_name.empty() ? module_name : std::string("module")) + "+" + hex_addr(rva);
            } else {
                as_va["inside_module"] = false;
            }
            address["assuming_value_is_va"] = as_va;

            json as_rva;
            as_rva["rva"] = hex_addr(value);
            if (value <= std::numeric_limits<uint64_t>::max() - *module_base) {
                const uint64_t va = *module_base + value;
                as_rva["va"] = hex_addr(va);
                as_rva["va_decimal"] = va;
                if (module_size)
                    as_rva["inside_module"] = value < *module_size;
                as_rva["module_expr"] = (!module_name.empty() ? module_name : std::string("module")) + "+" + hex_addr(value);
            }
            address["assuming_value_is_rva"] = as_rva;

            const auto kind = !inferred_kind.empty()
                ? inferred_kind
                : params.contains("kind") && params["kind"].is_string()
                ? to_lower(trim(params["kind"].get<std::string>()))
                : params.contains("type") && params["type"].is_string()
                    ? to_lower(trim(params["type"].get<std::string>()))
                    : std::string();
            if (kind == "rva") {
                address["selected_kind"] = "rva";
                address["va"] = as_rva.value("va", "");
                address["rva"] = hex_addr(value);
            } else if (kind == "va") {
                address["selected_kind"] = "va";
                address["va"] = hex_addr(value);
                if (value >= *module_base)
                    address["rva"] = hex_addr(value - *module_base);
            }
        }

        const auto section_rva = parse_optional_value("section_rva").value_or(
            parse_optional_value("section_virtual_address").value_or(0));
        const auto section_va = parse_optional_value("section_va");
        const auto section_raw = parse_optional_value("section_raw").value_or(
            parse_optional_value("section_raw_offset").value_or(
                parse_optional_value("section_file_offset").value_or(0)));
        const auto section_virtual_size = parse_optional_value("section_virtual_size").value_or(0);
        const auto section_raw_size = parse_optional_value("section_raw_size").value_or(0);
        const uint64_t section_span = std::max<uint64_t>(section_virtual_size, section_raw_size);
        if ((section_rva || section_va) && section_span) {
            uint64_t base_rva = section_rva;
            if (section_va && module_base && *section_va >= *module_base)
                base_rva = *section_va - *module_base;

            auto in_range = [](uint64_t v, uint64_t start, uint64_t size) -> bool {
                return v >= start && v - start < size;
            };

            json pe;
            pe["section_rva"] = hex_addr(base_rva);
            pe["section_raw_offset"] = hex_addr(section_raw);
            pe["section_span"] = section_span;
            if (in_range(value, base_rva, section_span)) {
                const uint64_t file_offset = section_raw + (value - base_rva);
                pe["assuming_value_is_rva"] = json{{"file_offset", hex_addr(file_offset)}, {"file_offset_decimal", file_offset}};
            }
            if (module_base && value >= *module_base) {
                const uint64_t rva = value - *module_base;
                if (in_range(rva, base_rva, section_span)) {
                    const uint64_t file_offset = section_raw + (rva - base_rva);
                    pe["assuming_value_is_va"] = json{{"rva", hex_addr(rva)}, {"file_offset", hex_addr(file_offset)}, {"file_offset_decimal", file_offset}};
                }
            }
            if (in_range(value, section_raw, section_span)) {
                const uint64_t rva = base_rva + (value - section_raw);
                json foa{{"rva", hex_addr(rva)}, {"rva_decimal", rva}};
                if (module_base)
                    foa["va"] = hex_addr(*module_base + rva);
                pe["assuming_value_is_file_offset"] = foa;
            }
            out["pe_address_conversion"] = pe;
        }

        if (!address.empty())
            out["address_conversion"] = address;

        return tool_result_t::ok("Converted number.", out);
    }

    tool_result_t handle_read_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const fs::path path = params["path"].get<std::string>();
        if (!fs::exists(path) || !fs::is_regular_file(path))
            return error("File does not exist.");
        const auto content = file_to_utf8(path);
        return tool_result_t::ok("Read file.", json{{"path", path.string()}, {"content", content}});
    }

    tool_result_t handle_write_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_write_file entry");
        if (!params.contains("path") || !params["path"].is_string() ||
            !params.contains("content") || !params["content"].is_string())
            return error("Provide path and content.");
        const fs::path path = params["path"].get<std::string>();
        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
            return error("Could not open the file for writing.");
        ofs << params["content"].get<std::string>();
        return tool_result_t::ok("Wrote file.", json{{"path", path.string()}});
    }

    tool_result_t handle_edit_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_edit_file entry");
        if (!params.contains("path") || !params["path"].is_string() ||
            !params.contains("find_text") || !params["find_text"].is_string() ||
            !params.contains("replace_text") || !params["replace_text"].is_string())
            return error("Provide path, find_text, and replace_text.");

        const fs::path path = params["path"].get<std::string>();
        auto content = file_to_utf8(path);
        if (content.empty() && !fs::exists(path))
            return error("Target file does not exist.");

        const std::string find_text = params["find_text"].get<std::string>();
        const std::string replace_text = params["replace_text"].get<std::string>();
        const bool replace_all = params.value("replace_all", true);

        size_t replacements = 0;
        size_t pos = 0;
        while ((pos = content.find(find_text, pos)) != std::string::npos) {
            content.replace(pos, find_text.size(), replace_text);
            pos += replace_text.size();
            ++replacements;
            if (!replace_all)
                break;
        }

        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
            return error("Could not open the file for editing.");
        ofs << content;
        return tool_result_t::ok("Edited file.", json{{"path", path.string()}, {"replacements", replacements}});
    }

    tool_result_t handle_delete_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_delete_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        std::error_code ec;
        const auto removed = fs::remove(params["path"].get<std::string>(), ec);
        if (!removed || ec)
            return error("Could not delete the requested file.");
        return tool_result_t::ok("Deleted file.");
    }

    tool_result_t handle_create_directory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_create_directory entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        std::error_code ec;
        fs::create_directories(params["path"].get<std::string>(), ec);
        if (ec)
            return error("Failed to create the requested directory.");
        return tool_result_t::ok("Created directory.");
    }

    tool_result_t handle_list_directory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_list_directory entry");
        const fs::path root = params.contains("path") && params["path"].is_string()
            ? fs::path(params["path"].get<std::string>())
            : fs::current_path();
        if (!fs::exists(root) || !fs::is_directory(root))
            return error("Directory does not exist.");

        json entries = json::array();
        for (const auto& entry : fs::directory_iterator(root)) {
            entries.push_back({
                {"name", entry.path().filename().string()},
                {"path", entry.path().string()},
                {"is_directory", entry.is_directory()},
                {"size", entry.is_regular_file() ? static_cast<uint64_t>(entry.file_size()) : 0ULL}
            });
        }
        return tool_result_t::ok("Listed directory.", json{{"path", root.string()}, {"entries", entries}});
    }

    tool_result_t handle_search_files(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_search_files entry");
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const fs::path root = fs::u8path(params["root"].get<std::string>());
        const std::string needle = to_lower(params["pattern"].get<std::string>());
        const size_t limit = static_cast<size_t>(params.value("limit", 100));
        diag::log_tagged_fmt("mcp_tools", "handle_search_files root='%s' pattern='%s' limit=%zu",
            path_to_utf8(root).c_str(), needle.c_str(), limit);
        json matches = json::array();
        std::error_code ec;
        size_t visited = 0;
        size_t conversion_failures = 0;
        for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
            if (ec) {
                diag::log_tagged_fmt("mcp_tools", "handle_search_files iterator_error after=%zu err=%s",
                    visited, ec.message().c_str());
                break;
            }
            ++visited;
            std::string filename = path_to_utf8(entry.path().filename());
            std::string full_path = path_to_utf8(entry.path());
            if (filename.empty() && !entry.path().filename().empty()) {
                ++conversion_failures;
                diag::log_tagged_fmt("mcp_tools", "handle_search_files path_conversion_empty visited=%zu native_len=%zu",
                    visited, entry.path().native().size());
                continue;
            }
            if (to_lower(filename).find(needle) != std::string::npos) {
                matches.push_back(full_path);
                diag::log_tagged_fmt("mcp_tools", "handle_search_files match[%zu]='%s'",
                    matches.size(), full_path.c_str());
            }
            if (matches.size() >= limit)
                break;
        }
        if (ec) {
            diag::log_tagged_fmt("mcp_tools", "handle_search_files final_iterator_error visited=%zu matches=%zu err=%s",
                visited, matches.size(), ec.message().c_str());
        }
        diag::log_tagged_fmt("mcp_tools", "handle_search_files done visited=%zu matches=%zu conversion_failures=%zu",
            visited, matches.size(), conversion_failures);
        return tool_result_t::ok("Searched files.", json{
            {"matches", matches},
            {"visited", visited},
            {"conversion_failures", conversion_failures}
        });
    }

    tool_result_t handle_grep_in_files(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_grep_in_files entry");
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const fs::path root = params["root"].get<std::string>();
        const std::regex rx(params["pattern"].get<std::string>(), std::regex::icase);
        json matches = json::array();

        std::error_code ec;
        for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
            if (ec)
                break;
            if (!entry.is_regular_file(ec))
                continue;
            const auto content = file_to_utf8(entry.path());
            std::smatch match;
            std::string::const_iterator search_start(content.cbegin());
            size_t line = 1;
            size_t offset = 0;
            while (std::regex_search(search_start, content.cend(), match, rx)) {
                offset = static_cast<size_t>(match.position(0) + std::distance(content.cbegin(), search_start));
                line = 1 + static_cast<size_t>(std::count(content.begin(), content.begin() + static_cast<long long>(offset), '\n'));
                matches.push_back({
                    {"path", entry.path().string()},
                    {"line", line},
                    {"match", match.str(0)}
                });
                search_start = match.suffix().first;
                if (matches.size() >= static_cast<size_t>(params.value("limit", 100)))
                    break;
            }
            if (matches.size() >= static_cast<size_t>(params.value("limit", 100)))
                break;
        }

        return tool_result_t::ok("Searched file contents.", json{{"matches", matches}});
    }

    tool_result_t handle_web_search(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_web_search entry");
        if (!params.contains("query") || !params["query"].is_string())
            return error("Provide a search query.");

        const std::string query = params["query"].get<std::string>();
        const int max_results = params.value("max_results", 5);


        std::string encoded_query;
        for (unsigned char c : query) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded_query += static_cast<char>(c);
            } else if (c == ' ') {
                encoded_query += '+';
            } else {
                char hex[4];
                snprintf(hex, sizeof(hex), "%%%02X", c);
                encoded_query += hex;
            }
        }

        json results = json::array();

        std::string transport_error;
        try {
            httplib::SSLClient client("api.duckduckgo.com");
            client.set_connection_timeout(10);
            client.set_read_timeout(15);
            client.set_follow_location(true);
            client.set_default_headers({
                {"Accept", "application/json"},
                {"User-Agent", "AiDAStandalone/1.0"}
            });
            client.enable_server_certificate_verification(false);

            std::string path = "/?q=" + encoded_query + "&format=json&no_redirect=1&no_html=1";
            auto res = client.Get(path.c_str());

            if (!res) {
                transport_error = "no response from api.duckduckgo.com";
            } else if (res->status != 200) {
                transport_error = "HTTP status " + std::to_string(res->status);
            } else {
                auto j = json::parse(res->body, nullptr, false);
                if (j.is_discarded() || !j.is_object()) {
                    transport_error = "invalid JSON in response body";
                } else {
                    if (j.contains("Abstract") && !j["Abstract"].get<std::string>().empty()) {
                        results.push_back({
                            {"title", j.value("Heading", "Answer")},
                            {"snippet", j["Abstract"].get<std::string>()},
                            {"url", j.value("AbstractURL", "")}
                        });
                    }
                    if (j.contains("RelatedTopics") && j["RelatedTopics"].is_array()) {
                        for (auto& topic : j["RelatedTopics"]) {
                            if ((int)results.size() >= max_results) break;
                            if (topic.contains("Text") && topic["Text"].is_string()) {
                                results.push_back({
                                    {"title", topic.value("Text", "").substr(0, 120)},
                                    {"snippet", topic.value("Text", "")},
                                    {"url", topic.value("FirstURL", "")}
                                });
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            transport_error = e.what();
        } catch (...) {
            transport_error = "unknown network error";
        }

        std::string wikipedia_error;
        if (results.empty()) {
            try {
                httplib::SSLClient wiki("en.wikipedia.org");
                wiki.set_connection_timeout(10);
                wiki.set_read_timeout(15);
                wiki.set_follow_location(true);
                wiki.set_default_headers({
                    {"Accept", "application/json"},
                    {"User-Agent", "AiDAStandalone/1.0"}
                });
                wiki.enable_server_certificate_verification(false);
                std::string path = "/w/api.php?action=opensearch&search=" + encoded_query +
                                   "&limit=" + std::to_string(std::max(1, max_results)) +
                                   "&namespace=0&format=json";
                auto res = wiki.Get(path.c_str());
                if (!res) {
                    wikipedia_error = "no response from en.wikipedia.org";
                } else if (res->status != 200) {
                    wikipedia_error = "HTTP status " + std::to_string(res->status);
                } else {
                    auto j = json::parse(res->body, nullptr, false);
                    if (j.is_discarded() || !j.is_array() || j.size() < 4 ||
                        !j[1].is_array() || !j[2].is_array() || !j[3].is_array()) {
                        wikipedia_error = "invalid JSON in Wikipedia opensearch response";
                    } else {
                        const size_t take = std::min<size_t>(
                            static_cast<size_t>(std::max(1, max_results)), j[1].size());
                        for (size_t i = 0; i < take; ++i) {
                            if (!j[1][i].is_string())
                                continue;
                            const std::string title = j[1][i].get<std::string>();
                            const std::string snippet =
                                i < j[2].size() && j[2][i].is_string() ? j[2][i].get<std::string>() : std::string();
                            const std::string url =
                                i < j[3].size() && j[3][i].is_string() ? j[3][i].get<std::string>() : std::string();
                            results.push_back({
                                {"title", title},
                                {"snippet", snippet.empty() ? title : snippet},
                                {"url", url}
                            });
                        }
                    }
                }
            } catch (const std::exception& e) {
                wikipedia_error = e.what();
            } catch (...) {
                wikipedia_error = "unknown Wikipedia network error";
            }
        }

        if (!transport_error.empty() && results.empty()) {
            std::string msg = "web_search: " + transport_error;
            if (!wikipedia_error.empty())
                msg += "; wikipedia: " + wikipedia_error;
            set_last_web_error(msg);
            return tool_result_t::error(msg);
        }

        if (results.empty()) {
            return tool_result_t::ok(
                "Web search returned no results for: " + query +
                "\nNote: Web search uses the DuckDuckGo Instant Answer API.",
                json{{"results", results}});
        }

        return tool_result_t::ok(
            "Found " + std::to_string(results.size()) + " results for: " + query,
            json{{"results", results}});
    }

    bool webfetch_split_url(const std::string& full,
                            std::string& scheme,
                            std::string& host,
                            int& port,
                            std::string& path_out,
                            bool& is_https)
    {
        scheme.clear();
        host.clear();
        path_out = "/";
        port = 0;
        is_https = false;
        const auto sp = full.find("://");
        if (sp == std::string::npos)
            return false;
        scheme = full.substr(0, sp);
        std::string rest = full.substr(sp + 3);
        const auto slash = rest.find('/');
        std::string host_port;
        if (slash == std::string::npos) {
            host_port = rest;
            path_out = "/";
        } else {
            host_port = rest.substr(0, slash);
            path_out = rest.substr(slash);
        }
        const auto colon = host_port.find(':');
        if (colon == std::string::npos) {
            host = host_port;
        } else {
            host = host_port.substr(0, colon);
            try {
                port = std::stoi(host_port.substr(colon + 1));
            } catch (...) {
                return false;
            }
        }
        if (scheme == "https") {
            is_https = true;
            if (port == 0) port = 443;
        } else if (scheme == "http") {
            is_https = false;
            if (port == 0) port = 80;
        } else {
            return false;
        }
        if (host.empty())
            return false;
        return true;
    }

    std::string webfetch_strip_blocks(const std::string& html)
    {
        std::string out = html;
        static const std::regex script_block("<script\\b[^>]*>[\\s\\S]*?</script>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex style_block("<style\\b[^>]*>[\\s\\S]*?</style>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex noscript_block("<noscript\\b[^>]*>[\\s\\S]*?</noscript>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex iframe_block("<iframe\\b[^>]*>[\\s\\S]*?</iframe>",
            std::regex::icase | std::regex::ECMAScript);
        static const std::regex html_comment("<!--[\\s\\S]*?-->", std::regex::ECMAScript);
        out = std::regex_replace(out, script_block, "");
        out = std::regex_replace(out, style_block, "");
        out = std::regex_replace(out, noscript_block, "");
        out = std::regex_replace(out, iframe_block, "");
        out = std::regex_replace(out, html_comment, "");
        return out;
    }

    std::string webfetch_decode_entities(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        size_t i = 0;
        while (i < s.size()) {
            if (s[i] != '&') { out.push_back(s[i]); ++i; continue; }
            const auto semi = s.find(';', i + 1);
            if (semi == std::string::npos || semi - i > 12) { out.push_back(s[i]); ++i; continue; }
            const std::string entity = s.substr(i + 1, semi - i - 1);
            if (entity == "amp")        out.push_back('&');
            else if (entity == "lt")    out.push_back('<');
            else if (entity == "gt")    out.push_back('>');
            else if (entity == "quot")  out.push_back('"');
            else if (entity == "apos")  out.push_back('\'');
            else if (entity == "nbsp")  out.push_back(' ');
            else if (entity == "copy")  out.append("(c)");
            else if (entity == "reg")   out.append("(r)");
            else if (entity == "trade") out.append("(tm)");
            else if (entity == "hellip") out.append("...");
            else if (entity == "mdash") out.append("--");
            else if (entity == "ndash") out.append("-");
            else if (!entity.empty() && entity[0] == '#') {
                long codepoint = 0;
                bool ok = false;
                try {
                    if (entity.size() > 1 && (entity[1] == 'x' || entity[1] == 'X'))
                        codepoint = std::stol(entity.substr(2), nullptr, 16);
                    else
                        codepoint = std::stol(entity.substr(1), nullptr, 10);
                    ok = true;
                } catch (...) { ok = false; }
                if (ok && codepoint > 0 && codepoint <= 0x7F) {
                    out.push_back(static_cast<char>(codepoint));
                } else if (ok && codepoint > 0x7F && codepoint <= 0x7FF) {
                    out.push_back(static_cast<char>(0xC0 | ((codepoint >> 6) & 0x1F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else if (ok && codepoint > 0x7FF && codepoint <= 0xFFFF) {
                    out.push_back(static_cast<char>(0xE0 | ((codepoint >> 12) & 0x0F)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else if (ok && codepoint > 0xFFFF && codepoint <= 0x10FFFF) {
                    out.push_back(static_cast<char>(0xF0 | ((codepoint >> 18) & 0x07)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else {
                    out.append(s.substr(i, semi - i + 1));
                }
            } else {
                out.append(s.substr(i, semi - i + 1));
            }
            i = semi + 1;
        }
        return out;
    }

    std::string webfetch_collapse_whitespace(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        bool prev_blank = true;
        size_t consecutive_newlines = 0;
        for (char c : s) {
            if (c == '\r') continue;
            if (c == '\n') {
                if (consecutive_newlines < 2)
                    out.push_back('\n');
                ++consecutive_newlines;
                prev_blank = true;
                continue;
            }
            if (c == ' ' || c == '\t') {
                if (!prev_blank) out.push_back(' ');
                prev_blank = true;
                continue;
            }
            out.push_back(c);
            prev_blank = false;
            consecutive_newlines = 0;
        }
        while (!out.empty() && (out.back() == ' ' || out.back() == '\n')) out.pop_back();
        return out;
    }

    std::string webfetch_html_to_text(const std::string& html_in)
    {
        std::string s = webfetch_strip_blocks(html_in);
        static const std::regex tag_rx("<[^>]+>", std::regex::ECMAScript);
        s = std::regex_replace(s, tag_rx, " ");
        s = webfetch_decode_entities(s);
        s = webfetch_collapse_whitespace(s);
        return s;
    }

    std::string webfetch_html_to_markdown(const std::string& html_in)
    {
        const std::string s = webfetch_strip_blocks(html_in);

        std::string out;
        out.reserve(s.size());
        const std::regex any_tag(
            "<(/?)([a-zA-Z][a-zA-Z0-9]*)\\b([^>]*)>",
            std::regex::ECMAScript);
        std::smatch match;
        std::string::const_iterator search_start = s.cbegin();
        std::string list_indent;
        bool in_pre = false;
        while (std::regex_search(search_start, s.cend(), match, any_tag)) {
            const auto prefix_begin = search_start;
            const auto prefix_end = match[0].first;
            std::string prefix(prefix_begin, prefix_end);
            out += prefix;

            const bool closing = match[1].length() == 1;
            std::string tag = match[2].str();
            std::string attrs = match[3].str();
            std::transform(tag.begin(), tag.end(), tag.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

            if (tag.size() == 2 && tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6') {
                if (!closing) {
                    out.append("\n\n");
                    const int level = tag[1] - '0';
                    out.append(static_cast<size_t>(level), '#');
                    out.push_back(' ');
                } else {
                    out.append("\n\n");
                }
            } else if (tag == "p" || tag == "div" || tag == "section" || tag == "article" ||
                       tag == "header" || tag == "footer" || tag == "main" || tag == "aside" ||
                       tag == "nav" || tag == "blockquote") {
                out.append("\n\n");
            } else if (tag == "br") {
                out.append("\n");
            } else if (tag == "hr") {
                out.append("\n\n---\n\n");
            } else if (tag == "ul" || tag == "ol") {
                if (!closing) list_indent.push_back('\t');
                else if (!list_indent.empty()) list_indent.pop_back();
                out.append("\n");
            } else if (tag == "li") {
                if (!closing) {
                    out.push_back('\n');
                    out.append(list_indent.empty() ? std::string() : list_indent.substr(1));
                    out.append("- ");
                }
            } else if (tag == "strong" || tag == "b") {
                out.append("**");
            } else if (tag == "em" || tag == "i") {
                out.push_back('*');
            } else if (tag == "code") {
                if (!in_pre) out.push_back('`');
            } else if (tag == "pre") {
                if (!closing) { out.append("\n\n```\n"); in_pre = true; }
                else { out.append("\n```\n\n"); in_pre = false; }
            } else if (tag == "a" && !closing) {
                std::string href;
                static const std::regex href_rx("href\\s*=\\s*\"([^\"]*)\"|href\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                std::smatch href_match;
                if (std::regex_search(attrs, href_match, href_rx)) {
                    href = href_match[1].matched ? href_match[1].str() : href_match[2].str();
                }
                out.append("__AIDA_A_OPEN__");
                out.append(href);
                out.append("__AIDA_A_HREF__");
            } else if (tag == "a" && closing) {
                out.append("__AIDA_A_CLOSE__");
            } else if (tag == "img" && !closing) {
                std::string alt, src;
                static const std::regex alt_rx("alt\\s*=\\s*\"([^\"]*)\"|alt\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                static const std::regex src_rx("src\\s*=\\s*\"([^\"]*)\"|src\\s*=\\s*'([^']*)'",
                    std::regex::icase | std::regex::ECMAScript);
                std::smatch a_match, s_match;
                if (std::regex_search(attrs, a_match, alt_rx))
                    alt = a_match[1].matched ? a_match[1].str() : a_match[2].str();
                if (std::regex_search(attrs, s_match, src_rx))
                    src = s_match[1].matched ? s_match[1].str() : s_match[2].str();
                out.push_back('!');
                out.push_back('[');
                out.append(alt);
                out.append("](");
                out.append(src);
                out.push_back(')');
            }

            search_start = match[0].second;
        }
        out.append(search_start, s.cend());

        std::string final_out;
        final_out.reserve(out.size());
        size_t i = 0;
        while (i < out.size()) {
            const auto open_pos = out.find("__AIDA_A_OPEN__", i);
            if (open_pos == std::string::npos) {
                final_out.append(out, i, std::string::npos);
                break;
            }
            final_out.append(out, i, open_pos - i);
            const auto href_pos = out.find("__AIDA_A_HREF__", open_pos + 15);
            if (href_pos == std::string::npos) {
                final_out.append(out, open_pos, std::string::npos);
                break;
            }
            const auto close_pos = out.find("__AIDA_A_CLOSE__", href_pos + 15);
            std::string href = out.substr(open_pos + 15, href_pos - (open_pos + 15));
            std::string text;
            if (close_pos != std::string::npos)
                text = out.substr(href_pos + 15, close_pos - (href_pos + 15));
            else
                text = out.substr(href_pos + 15);
            const std::string trimmed_text = trim(text);
            if (!href.empty() && !trimmed_text.empty()) {
                final_out.push_back('[');
                final_out.append(trimmed_text);
                final_out.push_back(']');
                final_out.push_back('(');
                final_out.append(href);
                final_out.push_back(')');
            } else if (!trimmed_text.empty()) {
                final_out.append(trimmed_text);
            } else if (!href.empty()) {
                final_out.append(href);
            }
            i = (close_pos == std::string::npos) ? out.size() : close_pos + 16;
        }

        std::string decoded = webfetch_decode_entities(final_out);
        return webfetch_collapse_whitespace(decoded);
    }

    tool_result_t handle_webfetch(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_webfetch entry");
        if (!params.contains("url") || !params["url"].is_string())
            return error("Missing required parameter: url");

        if (mcp_standalone::current_call_cancelled())
            return error("webfetch cancelled by client request.");

        const std::string url = params["url"].get<std::string>();
        if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0)
            return error("URL must start with http:// or https://");

        std::string format = "markdown";
        if (params.contains("format") && params["format"].is_string()) {
            const std::string requested = params["format"].get<std::string>();
            if (requested == "markdown" || requested == "text" || requested == "html")
                format = requested;
            else
                return error("format must be one of: markdown, text, html");
        }

        int timeout_sec = 30;
        if (params.contains("timeout")) {
            if (params["timeout"].is_number_integer())
                timeout_sec = params["timeout"].get<int>();
            else if (params["timeout"].is_number())
                timeout_sec = static_cast<int>(params["timeout"].get<double>());
        }
        if (timeout_sec < 1) timeout_sec = 1;
        if (timeout_sec > 120) timeout_sec = 120;

        std::string scheme;
        std::string host;
        int port = 0;
        std::string path;
        bool is_https = false;
        if (!webfetch_split_url(url, scheme, host, port, path, is_https))
            return error("Invalid URL: " + url);

        std::string base;
        if (is_https) base = "https://"; else base = "http://";
        base += host;
        base += ":";
        base += std::to_string(port);

        httplib::Client cli(base);
        cli.set_connection_timeout(timeout_sec, 0);
        cli.set_read_timeout(timeout_sec, 0);
        cli.set_write_timeout(timeout_sec, 0);
        cli.set_follow_location(true);
        cli.enable_server_certificate_verification(true);

        std::string accept_header;
        if (format == "markdown")
            accept_header = "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1";
        else if (format == "text")
            accept_header = "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1";
        else
            accept_header = "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1";

        httplib::Headers headers = {
            { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" },
            { "Accept", accept_header },
            { "Accept-Language", "en-US,en;q=0.9" }
        };

        auto res = cli.Get(path, headers);
        if (mcp_standalone::current_call_cancelled())
            return error("webfetch cancelled by client request.");
        if (!res)
            return error("HTTP request failed: " + httplib::to_string(res.error()) + " for " + url);
        if (res->status < 200 || res->status >= 300)
            return error("HTTP status " + std::to_string(res->status) + " for " + url);

        constexpr size_t MAX_RAW_BYTES = 5u * 1024u * 1024u;
        std::string body = res->body;
        if (body.size() > MAX_RAW_BYTES)
            body.resize(MAX_RAW_BYTES);

        std::string content_type;
        auto ct_iter = res->headers.find("Content-Type");
        if (ct_iter != res->headers.end()) content_type = ct_iter->second;
        std::string ct_lower = to_lower(content_type);
        const bool is_html = ct_lower.find("text/html") != std::string::npos
                          || ct_lower.find("application/xhtml") != std::string::npos;

        std::string output;
        if (format == "html") {
            output = std::move(body);
        } else if (format == "text") {
            output = is_html ? webfetch_html_to_text(body) : body;
        } else {
            output = is_html ? webfetch_html_to_markdown(body) : body;
        }

        constexpr size_t MAX_OUTPUT_BYTES = 200000u;
        bool truncated = false;
        if (output.size() > MAX_OUTPUT_BYTES) {
            output.resize(MAX_OUTPUT_BYTES);
            truncated = true;
        }

        json data;
        data["url"] = url;
        data["status"] = res->status;
        data["format"] = format;
        data["content_type"] = content_type;
        data["bytes"] = static_cast<int64_t>(output.size());
        data["truncated"] = truncated;

        std::string text;
        text.reserve(output.size() + 128);
        text += "Fetched ";
        text += url;
        text += " (";
        text += std::to_string(res->status);
        text += ", ";
        text += content_type.empty() ? std::string("application/octet-stream") : content_type;
        text += ")\n\n";
        text += output;
        if (truncated)
            text += "\n\n[truncated to " + std::to_string(MAX_OUTPUT_BYTES) + " bytes]";

        return tool_result_t::ok(text, data);
    }

    tool_result_t handle_reconstruct_source(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_reconstruct_source entry");
        if (source_reconstructor::is_running())
            return error("Source reconstruction is already running.");

        if (!driver_bridge::is_loaded())
            return error("Kernel driver not loaded. Call driver_load first.");

        source_reconstructor::reconstruction_config_t config;
        config.project_name = params.value("project_name", "reconstructed");
        config.output_dir = params.value("output_dir", "");
        config.module_name = params.value("module_name", "");
        config.include_imports = params.value("include_imports", true);
        config.include_exports = params.value("include_exports", true);
        config.generate_cmake = params.value("generate_cmake", true);
        config.use_ai_refinement = params.value("use_ai", true);
        config.max_functions = params.value("max_functions", 0);

        if (config.output_dir.empty())
            return error("Missing required parameter: output_dir");


        if (!config.module_name.empty()) {
            for (auto& mod : driver_bridge::enumerate_modules()) {
                if (to_lower(mod.name) == to_lower(config.module_name)) {
                    config.module_base = mod.base;
                    config.module_size = mod.size;
                    break;
                }
            }
            if (config.module_base == 0)
                return error("Module not found: " + config.module_name);
        } else {

            auto base_opt = parse_addr_opt(params, "module_base");
            if (!base_opt.has_value())
                return error("Provide either module_name or module_base.");
            config.module_base = base_opt.value();
            config.module_size = params.value("module_size", 0u);
            if (config.module_size == 0)
                return error("module_size is required when using module_base.");
        }

        source_reconstructor::reconstruct(config);

        return tool_result_t::ok("Source reconstruction started for " +
            config.module_name + " → " + config.output_dir,
            json{{"status", "started"}, {"module_base", hex_addr(config.module_base)},
                 {"module_size", config.module_size}, {"output_dir", config.output_dir}});
    }

    tool_result_t handle_reconstruct_status(const json&)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_reconstruct_status entry");
        json result;
        result["running"] = source_reconstructor::is_running();
        result["progress"] = source_reconstructor::get_progress();
        result["status"] = source_reconstructor::get_status();

        if (!source_reconstructor::is_running()) {
            auto& last = source_reconstructor::get_last_result();
            bool has_last_run = !last.output_dir.empty() || last.total_functions != 0 ||
                last.decompiled_functions != 0 || last.modules_created != 0 ||
                !last.files_created.empty() || !last.error.empty();
            result["has_last_run"] = has_last_run;
            result["last_success"] = has_last_run ? last.success : false;
            result["last_error"] = last.error;
            result["total_functions"] = last.total_functions;
            result["decompiled_functions"] = last.decompiled_functions;
            result["modules_created"] = last.modules_created;
            result["files_created"] = static_cast<int>(last.files_created.size());
            result["output_dir"] = last.output_dir;
        }

        return tool_result_t::ok(result);
    }

    tool_result_t handle_reconstruct_cancel(const json&)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_reconstruct_cancel entry");
        if (!source_reconstructor::is_running())
            return tool_result_t::ok("No reconstruction is running.", json{{"running", false}, {"cancelled", false}});
        source_reconstructor::cancel();
        return tool_result_t::ok("Reconstruction cancellation requested.", json{{"running", true}, {"cancelled", true}});
    }
}

namespace mcp_standalone
{
    void register_standalone_tools(server_t& srv)
    {
        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools entry");

        srv.register_tool({"get_tool_descriptions",
            "Return full descriptions and parameter schemas for selected MCP tool names.",
            {{"names", "array", "Tool names to describe", false},
             {"name", "string", "Single tool name to describe", false},
             {"prefix", "string", "Tool name prefix to search", false},
             {"query", "string", "Tool name or description search text", false},
             {"limit", "number", "Maximum matching tools to return", false},
             {"include_schema", "boolean", "Include parameter names, types, and descriptions", false}},
            true,
            [&srv](const json& params) { return srv.describe_tools(params); }});

        srv.register_tool({"driver_load", "Load and connect the host kernel driver backend for host live analysis.", {}, false, handle_driver_load});
        srv.register_tool({"driver_detach", "Detach from the current process. If a Windows Sandbox guest lab is active this detaches the guest active process by default; pass target='host' for host detach.",
            {{"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            false, handle_driver_detach});
        srv.register_tool({"guest_lab_status", "Return the active interactive Windows Sandbox malware lab and guest agent status.", {{"timeout_ms", "number", "Guest bridge timeout", false}}, true, handle_guest_lab_status});
        srv.register_tool({"guest_lab_attach", "Attach the guest agent to a process inside the Windows Sandbox VM by pid or process name.",
            {{"pid", "number", "Guest process id", false}, {"process", "string", "Guest process image name", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            false, handle_guest_lab_attach});
        srv.register_tool({"guest_lab_detach", "Detach the guest agent from the active guest process.", {{"timeout_ms", "number", "Guest bridge timeout", false}}, false, handle_guest_lab_detach});
        srv.register_tool({"guest_lab_list_processes", "Enumerate processes inside the active Windows Sandbox VM.",
            {{"filter", "string", "Optional substring filter", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_list_processes});
        srv.register_tool({"guest_lab_memory_map", "Enumerate the memory map of the active or supplied guest process.",
            {{"pid", "number", "Guest process id; defaults to active guest attach", false}, {"limit", "number", "Maximum regions", false}, {"readable_only", "boolean", "Only readable committed regions", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_memory_map});
        srv.register_tool({"guest_lab_query_memory", "Query a guest memory region containing an address.",
            {{"address", "string", "Guest virtual address", true}, {"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_query_memory});
        srv.register_tool({"guest_lab_read_memory", "Read bytes from a guest process inside the Windows Sandbox VM.",
            {{"address", "string", "Guest virtual address", true}, {"size", "number", "Bytes to read, capped in the guest", false}, {"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_read_memory});
        srv.register_tool({"guest_lab_read_string", "Read an ASCII or UTF-16 string from a guest process inside the Windows Sandbox VM.",
            {{"address", "string", "Guest virtual address", true}, {"max_length", "number", "Maximum characters", false}, {"encoding", "string", "ascii|utf16", false}, {"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_read_string});
        srv.register_tool({"guest_lab_enumerate_modules", "List modules for the active or supplied guest process.",
            {{"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_enumerate_modules});
        srv.register_tool({"guest_lab_enumerate_threads", "List threads for the active or supplied guest process.",
            {{"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_enumerate_threads});
        srv.register_tool({"guest_lab_dump_region", "Dump guest process memory to the sandbox output artifacts folder and return the host artifact path.",
            {{"address", "string", "Guest virtual address", true}, {"size", "number", "Bytes to dump; 0 dumps the containing region up to the cap", false}, {"pid", "number", "Guest process id; defaults to active guest attach", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_dump_region});
        srv.register_tool({"guest_lab_search_memory", "Search readable guest process memory for a hex pattern; use ?? for wildcard bytes.",
            {{"pattern", "string", "Hex pattern such as 48 8B ?? ??", true}, {"pid", "number", "Guest process id; defaults to active guest attach", false}, {"max_hits", "number", "Maximum hits", false}, {"max_scan_mb", "number", "Maximum readable memory to scan", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_guest_lab_search_memory});
        srv.register_tool({"list_processes", "Enumerate processes. If a Windows Sandbox guest lab is active this lists guest processes by default; pass target='host' for host processes.",
            {{"filter", "string", "Optional substring filter", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}}, true, handle_list_processes});
        srv.register_tool({"read_memory", "Read bytes from the attached process. If a Windows Sandbox guest lab is active this reads guest memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"size", "number", "Bytes to read", false}, {"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_read_memory});
        srv.register_tool({"read_string", "Read a UTF-8/ASCII string from the attached process. If a Windows Sandbox guest lab is active this reads guest memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"max_length", "number", "Maximum bytes to inspect", false}, {"encoding", "string", "ascii|utf16 for guest reads", false}, {"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_read_string});
        srv.register_tool({"query_memory", "Query the memory region containing an address. If a Windows Sandbox guest lab is active this queries guest memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}}, true, handle_query_memory});
        srv.register_tool({"enumerate_modules", "List modules for the attached process. If a Windows Sandbox guest lab is active this lists guest modules by default; pass target='host' for host modules.",
            {{"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}}, true, handle_enumerate_modules});
        srv.register_tool({"enumerate_threads", "List threads for the attached process. If a Windows Sandbox guest lab is active this lists guest threads by default; pass target='host' for host threads.",
            {{"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}}, true, handle_enumerate_threads});
        srv.register_tool({"disassemble_address", "Disassemble bytes from the attached process using Zydis. If a Windows Sandbox guest lab is active this reads guest memory by default; pass target='host' for host memory.",
            {{"address", "string", "Start address", true}, {"size", "number", "Bytes to read", false}, {"count", "number", "Maximum instructions", false}, {"pid", "number", "Guest process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "Guest bridge timeout", false}},
            true, handle_disassemble_address});
        srv.register_tool({"disassemble_file", "Disassemble a PE file from disk using Zydis.",
            {{"path", "string", "Path to an EXE/DLL/SYS file", true}, {"count", "number", "Maximum instructions", false}},
            true, handle_disassemble_file});
        srv.register_tool({"sandbox_execute", "Run a binary inside Windows Sandbox and collect the execution artifacts.",
            {{"path", "string", "Path to the executable", true}, {"arguments", "string", "Optional argument string", false},
             {"working_dir", "string", "Optional working directory to stage into the sandbox", false},
             {"timeout_ms", "number", "Execution timeout in milliseconds", false},
             {"capture_stdout", "boolean", "Capture stdout", false}, {"capture_stderr", "boolean", "Capture stderr", false}},
            false, handle_sandbox_execute});
        srv.register_tool({"convert_number", "Convert a number across integer, endian, ASCII, IEEE-754, alignment, VA, RVA, and PE file-offset representations.",
            {{"value", "string", "Numeric literal or integer value: decimal, 0x hex, hex h suffix, 0b binary, 0o/0 octal, or negative", false},
             {"input_base", "string", "Optional input radix: auto, hex, decimal, binary, octal, or 2/8/10/16", false},
             {"from", "string", "Alias for input_base", false},
             {"size", "number", "Optional display byte width: 1, 2, 4, or 8", false},
             {"bits", "number", "Optional display bit width: 8, 16, 32, or 64", false},
             {"va", "string", "Virtual address input alias; infers kind=va", false},
             {"rva", "string", "Relative virtual address input alias; infers kind=rva", false},
             {"file_offset", "string", "Raw file offset input alias; infers kind=file_offset", false},
             {"foa", "string", "Alias for file_offset", false},
             {"module_base", "string", "Optional module/image base for VA/RVA conversion", false},
             {"image_base", "string", "Alias for module_base", false},
             {"module_size", "string", "Optional module size for inside-module checks", false},
             {"module_name", "string", "Optional attached-process module name to resolve base and size", false},
             {"kind", "string", "Optional selected address kind: va, rva, file_offset, or foa", false},
             {"section_rva", "string", "Optional PE section RVA for RVA/FOA conversion", false},
             {"section_va", "string", "Optional PE section VA for VA/FOA conversion", false},
             {"section_raw_offset", "string", "Optional PE section raw file offset", false},
             {"section_raw_size", "string", "Optional PE section raw size", false},
             {"section_virtual_size", "string", "Optional PE section virtual size", false}},
            true, handle_convert_number});
        srv.register_tool({"delete_file", "Delete a file on disk.", {{"path", "string", "Target path", true}}, false, handle_delete_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"create_directory", "Create a directory tree on disk.", {{"path", "string", "Target path", true}}, false, handle_create_directory, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"search_files", "Search for file names under a root directory.",
            {{"root", "string", "Root directory", true}, {"pattern", "string", "Substring to search for", true}, {"limit", "number", "Maximum matches", false}},
            true, handle_search_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"grep_in_files", "Search file contents with a regular expression.",
            {{"root", "string", "Root directory", true}, {"pattern", "string", "Regex pattern", true}, {"limit", "number", "Maximum matches", false}},
            true, handle_grep_in_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"web_search", "Search the web using DuckDuckGo Instant Answer API.",
            {{"query", "string", "Search query text", true}, {"max_results", "number", "Maximum results to return (default 5)", false}},
            true, handle_web_search, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"webfetch",
            "Fetch the contents of a URL via HTTPS and return them as markdown, plain text, or raw HTML. "
            "Follows redirects, verifies certificates, strips script/style/noscript/iframe blocks before HTML conversion. "
            "Output capped at ~200 KB; max timeout 120 seconds.",
            {{"url", "string", "Absolute http:// or https:// URL", true},
             {"format", "string", "Output format: markdown (default), text, or html", false},
             {"timeout", "number", "Request timeout in seconds (1-120, default 30)", false}},
            true, handle_webfetch, mcp_standalone::tool_visibility_t::internal_only});


        driver_tools::register_driver_tools(srv);
        network_tools::register_network_tools(srv);
        net_security_tools::register_net_security_tools(srv);
        emulation_tools::register_emulation_tools(srv);
        debugger_tools::register_debugger_tools(srv);
        coding_tools::register_coding_tools(srv);
        workflow_tools::register_workflow_tools(srv);
        scanner_tools::register_scanner_tools(srv);
        analysis_tools::register_analysis_tools(srv);
        disasm_tools::register_disasm_tools(srv);
        decompile_tools::register_decompile_tools(srv);
        session_tools_ext::register_tools(srv);


        srv.register_tool({"reconstruct_source",
            "Reconstruct a compilable C project from a loaded module. "
            "Discovers functions, decompiles them, groups into modules, and generates headers, source files, and CMakeLists.txt.",
            {{"output_dir", "string", "Directory to write the reconstructed project", true},
             {"module_name", "string", "Name of the module to reconstruct (e.g., 'game.exe')", false},
             {"module_base", "string", "Base address of the module (hex). Use if module_name is not provided.", false},
             {"module_size", "number", "Size of the module in bytes. Required with module_base.", false},
             {"project_name", "string", "Name for the reconstructed project (default: 'reconstructed')", false},
             {"include_imports", "boolean", "Include import declarations (default: true)", false},
             {"include_exports", "boolean", "Include export declarations (default: true)", false},
             {"generate_cmake", "boolean", "Generate CMakeLists.txt (default: true)", false},
             {"use_ai", "boolean", "Use AI refinement during decompilation (default: true)", false},
             {"max_functions", "number", "Maximum functions to decompile (0 = all, default: 0)", false}},
            false, handle_reconstruct_source});
        srv.register_tool({"reconstruct_status",
            "Check the progress and results of an in-flight source reconstruction.",
            {}, true, handle_reconstruct_status});
        srv.register_tool({"reconstruct_cancel",
            "Cancel a running source reconstruction.",
            {}, false, handle_reconstruct_cancel});
        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools done");
    }
}
