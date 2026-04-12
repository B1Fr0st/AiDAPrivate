#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_tools_fwd.hpp"
#include "sandbox.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "zydis_disasm.hpp"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
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

    tool_result_t handle_driver_status(const json&)
    {
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

    tool_result_t handle_driver_load(const json&)
    {
        if (!driver_bridge::load_kernel_driver())
            return error(driver_bridge::last_error().empty() ? "Failed to load kernel driver." : driver_bridge::last_error());
        return handle_driver_status({});
    }

    tool_result_t handle_list_processes(const json& params)
    {
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
        if (params.contains("pid") && params["pid"].is_number_integer()) {
            if (driver_bridge::attach(params["pid"].get<uint32_t>()))
                return handle_driver_status({});
            return error(driver_bridge::last_error());
        }
        if (params.contains("process") && params["process"].is_string()) {
            if (driver_bridge::attach_by_name(params["process"].get<std::string>()))
                return handle_driver_status({});
            return error(driver_bridge::last_error());
        }
        return error("Provide either a numeric pid or a process name.");
    }

    tool_result_t handle_driver_detach(const json&)
    {
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

    tool_result_t handle_enumerate_modules(const json&)
    {
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

    tool_result_t handle_enumerate_threads(const json&)
    {
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
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");

        DisasmFile file;
        const auto path = params["path"].get<std::string>();
        if (!disasm::load_pe(path, file))
            return error(file.err.empty() ? "Unable to load PE file." : file.err);

        disasm::decode_section(file);
        const size_t limit = static_cast<size_t>(params.value("count", 64));
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
        out["instructions"] = instructions;
        return tool_result_t::ok("Disassembled PE file.", out);
    }

    tool_result_t handle_sandbox_execute(const json& params)
    {
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

        const auto run = sandbox::execute(cfg);
        if (!run.success && !run.timed_out)
            return error(run.error);

        json out;
        out["success"] = run.success;
        out["exit_code"] = run.exit_code;
        out["pid"] = run.pid;
        out["timed_out"] = run.timed_out;
        out["killed"] = run.killed;
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
        if (!params.contains("value") || !params["value"].is_string())
            return error("Missing required parameter: value");

        const auto input = params["value"].get<std::string>();
        uint64_t value = 0;
        if (!parse_addr(input, value))
            return error("Unable to parse the provided number.");

        std::string binary;
        for (int i = 63; i >= 0; --i)
            binary.push_back(((value >> i) & 1ULL) ? '1' : '0');
        binary.erase(0, binary.find_first_not_of('0'));
        if (binary.empty())
            binary = "0";

        json out;
        out["decimal"] = value;
        out["hex"] = hex_addr(value);
        out["binary"] = "0b" + binary;
        out["signed_decimal"] = static_cast<int64_t>(value);
        if (value >= 32 && value < 127)
            out["ascii"] = std::string(1, static_cast<char>(value));
        return tool_result_t::ok("Converted number.", out);
    }

    tool_result_t handle_read_file(const json& params)
    {
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
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const fs::path root = params["root"].get<std::string>();
        const std::string needle = to_lower(params["pattern"].get<std::string>());
        json matches = json::array();
        std::error_code ec;
        for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
            if (ec)
                break;
            if (to_lower(entry.path().filename().string()).find(needle) != std::string::npos)
                matches.push_back(entry.path().string());
            if (matches.size() >= static_cast<size_t>(params.value("limit", 100)))
                break;
        }
        return tool_result_t::ok("Searched files.", json{{"matches", matches}});
    }

    tool_result_t handle_grep_in_files(const json& params)
    {
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


        try {
            httplib::SSLClient client("api.duckduckgo.com");
            client.set_connection_timeout(10);
            client.set_read_timeout(15);
            client.enable_server_certificate_verification(false);

            std::string path = "/?q=" + encoded_query + "&format=json&no_redirect=1&no_html=1";
            auto res = client.Get(path.c_str());

            if (res && res->status == 200) {
                auto j = json::parse(res->body, nullptr, false);
                if (!j.is_discarded() && j.is_object()) {

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
        } catch (...) {

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
}

namespace mcp_standalone
{
    void register_standalone_tools(server_t& srv)
    {


        srv.register_tool({"driver_load", "Load and connect the kernel driver backend for deep runtime analysis.", {}, false, handle_driver_load});
        srv.register_tool({"driver_detach", "Detach from the current live process.", {}, false, handle_driver_detach});
        srv.register_tool({"list_processes", "Enumerate currently running processes.",
            {{"filter", "string", "Optional substring filter", false}}, true, handle_list_processes});
        srv.register_tool({"read_memory", "Read bytes from the attached process.",
            {{"address", "string", "Target address", true}, {"size", "number", "Bytes to read", false}},
            true, handle_read_memory});
        srv.register_tool({"read_string", "Read a UTF-8/ASCII string from the attached process.",
            {{"address", "string", "Target address", true}, {"max_length", "number", "Maximum bytes to inspect", false}},
            true, handle_read_string});
        srv.register_tool({"query_memory", "Query the memory region containing an address.",
            {{"address", "string", "Target address", true}}, true, handle_query_memory});
        srv.register_tool({"enumerate_modules", "List modules for the attached process.", {}, true, handle_enumerate_modules});
        srv.register_tool({"enumerate_threads", "List threads for the attached process.", {}, true, handle_enumerate_threads});
        srv.register_tool({"disassemble_address", "Disassemble bytes from the attached process using Zydis.",
            {{"address", "string", "Start address", true}, {"size", "number", "Bytes to read", false}, {"count", "number", "Maximum instructions", false}},
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
        srv.register_tool({"convert_number", "Convert a number between common representations.",
            {{"value", "string", "Hex, decimal, octal, or binary input", true}},
            true, handle_convert_number});
        srv.register_tool({"read_file", "Read a text file from disk.", {{"path", "string", "Target path", true}}, true, handle_read_file});
        srv.register_tool({"write_file", "Overwrite a file on disk.",
            {{"path", "string", "Target path", true}, {"content", "string", "New file contents", true}},
            false, handle_write_file});
        srv.register_tool({"edit_file", "Replace text in an existing file.",
            {{"path", "string", "Target path", true}, {"find_text", "string", "Text to replace", true},
             {"replace_text", "string", "Replacement text", true}, {"replace_all", "boolean", "Replace every occurrence", false}},
            false, handle_edit_file});
        srv.register_tool({"delete_file", "Delete a file on disk.", {{"path", "string", "Target path", true}}, false, handle_delete_file});
        srv.register_tool({"create_directory", "Create a directory tree on disk.", {{"path", "string", "Target path", true}}, false, handle_create_directory});
        srv.register_tool({"list_directory", "List the contents of a directory.", {{"path", "string", "Directory path", false}}, true, handle_list_directory});
        srv.register_tool({"search_files", "Search for file names under a root directory.",
            {{"root", "string", "Root directory", true}, {"pattern", "string", "Substring to search for", true}, {"limit", "number", "Maximum matches", false}},
            true, handle_search_files});
        srv.register_tool({"grep_in_files", "Search file contents with a regular expression.",
            {{"root", "string", "Root directory", true}, {"pattern", "string", "Regex pattern", true}, {"limit", "number", "Maximum matches", false}},
            true, handle_grep_in_files});
        srv.register_tool({"web_search", "Search the web using DuckDuckGo Instant Answer API.",
            {{"query", "string", "Search query text", true}, {"max_results", "number", "Maximum results to return (default 5)", false}},
            true, handle_web_search});


        driver_tools::register_driver_tools(srv);
        network_tools::register_network_tools(srv);
        net_security_tools::register_net_security_tools(srv);
        emulation_tools::register_emulation_tools(srv);
        debugger_tools::register_debugger_tools(srv);
        coding_tools::register_coding_tools(srv);
        workflow_tools::register_workflow_tools(srv);
        scanner_tools::register_scanner_tools(srv);
        analysis_tools::register_analysis_tools(srv);
    }
}
