#define WIN32_LEAN_AND_MEAN
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_tools_fwd.hpp"
#include "sandbox.hpp"
#include "standalone_driver.hpp"
#include "standalone_settings.hpp"
#include "zydis_disasm.hpp"
#include "source_reconstructor.hpp"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
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

        std::string transport_error;
        try {
            httplib::SSLClient client("api.duckduckgo.com");
            client.set_connection_timeout(10);
            client.set_read_timeout(15);
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

        if (!transport_error.empty()) {
            const std::string msg = "web_search: " + transport_error;
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
        json result;
        result["running"] = source_reconstructor::is_running();
        result["progress"] = source_reconstructor::get_progress();
        result["status"] = source_reconstructor::get_status();

        if (!source_reconstructor::is_running()) {
            auto& last = source_reconstructor::get_last_result();
            result["success"] = last.success;
            result["error"] = last.error;
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
        if (!source_reconstructor::is_running())
            return error("No reconstruction is running.");
        source_reconstructor::cancel();
        return tool_result_t::ok("Reconstruction cancellation requested.");
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
        srv.register_tool({"read_file", "Read a text file from disk.", {{"path", "string", "Target path", true}}, true, handle_read_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"write_file", "Overwrite a file on disk.",
            {{"path", "string", "Target path", true}, {"content", "string", "New file contents", true}},
            false, handle_write_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"edit_file", "Replace text in an existing file.",
            {{"path", "string", "Target path", true}, {"find_text", "string", "Text to replace", true},
             {"replace_text", "string", "Replacement text", true}, {"replace_all", "boolean", "Replace every occurrence", false}},
            false, handle_edit_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"delete_file", "Delete a file on disk.", {{"path", "string", "Target path", true}}, false, handle_delete_file, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"create_directory", "Create a directory tree on disk.", {{"path", "string", "Target path", true}}, false, handle_create_directory, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"list_directory", "List the contents of a directory.", {{"path", "string", "Directory path", false}}, true, handle_list_directory, mcp_standalone::tool_visibility_t::internal_only});
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
    }
}
