#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "mcp_standalone.hpp"
#include "standalone_tools_fwd.hpp"
#include "calculator_tool.hpp"
#include "compat/debugger_lane.hpp"
#include "compat/effect_policy.hpp"
#include "compat/handlers/analysis.hpp"
#include "compat/handlers/composite.hpp"
#include "compat/handlers/core.hpp"
#include "compat/handlers/debugger.hpp"
#include "compat/handlers/memory.h"
#include "compat/handlers/modify.hpp"
#include "compat/handlers/python.hpp"
#include "compat/handlers/routing_extensions.hpp"
#include "compat/handlers/signatures.h"
#include "compat/handlers/stack.hpp"
#include "compat/handlers/survey.hpp"
#include "compat/handlers/types.hpp"
#include "compat/live_routing_integration.hpp"
#include "compat/mcp_server_integration.hpp"
#include "compat/python_worker_host.hpp"
#include "ida_compat_mut.hpp"
#include "ida_compat_read.hpp"
#include "schema_validator.hpp"
#include "sandbox.hpp"
#include "standalone_driver.hpp"
#include "vm_guest_bridge.hpp"
#include "standalone_settings.hpp"
#include "zydis_disasm.hpp"
#include "../anti-tamper/self_guard.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "../session/analysis_session.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../analysis/workspace/live_snapshot_provider.hpp"
#include "../analysis/provider_snapshot.hpp"
#include "../analysis/workspace/query_index.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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

    fs::path active_workspace_root()
    {
        std::string root = g_sa_settings.workspace.root_path.empty()
            ? file_browser::current_dir
            : g_sa_settings.workspace.root_path;
        if (root.empty())
            return {};
        std::error_code ec;
        auto canonical = fs::weakly_canonical(fs::u8path(root), ec);
        if (!ec)
            return canonical;
        return fs::u8path(root).lexically_normal();
    }

    std::wstring normalized_path_key(const fs::path& p)
    {
        std::wstring s = p.lexically_normal().wstring();
        for (wchar_t& c : s) {
            if (c == L'/')
                c = L'\\';
        }
        while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/'))
            s.pop_back();
        std::transform(s.begin(), s.end(), s.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        return s;
    }

    bool path_within_workspace_root(const fs::path& p, const fs::path& workspace)
    {
        if (workspace.empty())
            return false;
        auto ws_str = normalized_path_key(workspace);
        auto p_str = normalized_path_key(p);
        if (ws_str == p_str)
            return true;
        if (!ws_str.empty() && ws_str.back() != L'\\')
            ws_str.push_back(L'\\');
        return p_str.rfind(ws_str, 0) == 0;
    }

    bool resolve_workspace_path_checked(const std::string& raw, fs::path& out, fs::path* workspace_out, std::string& err)
    {
        if (raw.empty()) {
            err = "Path is empty.";
            return false;
        }
        if (raw.find('\0') != std::string::npos) {
            err = "Path contains an embedded NUL byte.";
            return false;
        }
        fs::path workspace = active_workspace_root();
        if (workspace.empty()) {
            err = "No active workspace is open.";
            return false;
        }
        fs::path requested = fs::u8path(raw);
        if (requested.has_root_name() && !requested.is_absolute()) {
            err = "Drive-relative paths are not accepted.";
            return false;
        }
        fs::path candidate = requested.is_absolute() ? requested : workspace / requested;
        std::error_code ec;
        fs::path resolved = fs::weakly_canonical(candidate, ec);
        if (ec) {
            ec.clear();
            resolved = fs::absolute(candidate, ec);
            if (ec)
                resolved = candidate;
            resolved = resolved.lexically_normal();
        }
        if (!path_within_workspace_root(resolved, workspace)) {
            err = "Path is outside the active workspace.";
            return false;
        }
        out = resolved;
        if (workspace_out)
            *workspace_out = workspace;
        return true;
    }

    fs::path resolve_workspace_path(const std::string& raw)
    {
        fs::path resolved;
        std::string err;
        if (resolve_workspace_path_checked(raw, resolved, nullptr, err))
            return resolved;
        return fs::u8path(raw).lexically_normal();
    }

    bool path_within_current_workspace(const fs::path& p)
    {
        return path_within_workspace_root(p, active_workspace_root());
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

    std::string web_tool_url_encode(const std::string& text)
    {
        std::string out;
        out.reserve(text.size() * 3);
        for (unsigned char c : text) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                out += static_cast<char>(c);
            } else if (c == ' ') {
                out += '+';
            } else {
                char hex[4];
                snprintf(hex, sizeof(hex), "%%%02X", c);
                out += hex;
            }
        }
        return out;
    }

    json camoufox_value_json(const aida::burp::camoufox::call_result_t& result)
    {
        if (result.data.is_object()) {
            auto value = result.data.find("value");
            if (value != result.data.end())
                return *value;
            auto raw = result.data.find("value_raw");
            if (raw != result.data.end() && raw->is_string()) {
                auto parsed = json::parse(raw->get<std::string>(), nullptr, false);
                if (!parsed.is_discarded())
                    return parsed;
            }
        }
        return result.data;
    }

    std::string json_string_field(const json& value, const char* key)
    {
        if (!value.is_object())
            return {};
        auto it = value.find(key);
        if (it == value.end() || !it->is_string())
            return {};
        return it->get<std::string>();
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

    std::wstring utf8_to_wide_lossy(const std::string& text)
    {
        if (text.empty())
            return {};
        int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
        if (len <= 0) {
            const DWORD err = GetLastError();
            diag::log_tagged_fmt("mcp_tools", "utf8_to_wide failed len=%zu err=%lu",
                text.size(), static_cast<unsigned long>(err));
            return {};
        }
        std::wstring out(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), len);
        return out;
    }

    std::string path_to_utf8(const fs::path& path)
    {
        return wide_to_utf8_lossy(path.native());
    }

    std::string current_cwd_utf8()
    {
        std::error_code ec;
        fs::path cwd = fs::current_path(ec);
        return ec ? std::string() : path_to_utf8(cwd);
    }

    size_t bounded_size_param(const json& params, const char* name, size_t fallback, size_t minimum, size_t maximum)
    {
        size_t value = fallback;
        auto it = params.find(name);
        if (it != params.end()) {
            if (it->is_number_unsigned()) {
                value = it->get<size_t>();
            } else if (it->is_number_integer()) {
                const int64_t signed_value = it->get<int64_t>();
                if (signed_value >= 0)
                    value = static_cast<size_t>(signed_value);
            }
        }
        if (value < minimum)
            return minimum;
        if (value > maximum)
            return maximum;
        return value;
    }

    uint32_t bounded_u32_param(const json& params, const char* name, uint32_t fallback, uint32_t minimum, uint32_t maximum)
    {
        uint32_t value = fallback;
        auto it = params.find(name);
        if (it != params.end()) {
            if (it->is_number_unsigned()) {
                const uint64_t unsigned_value = it->get<uint64_t>();
                value = unsigned_value > maximum ? maximum : static_cast<uint32_t>(unsigned_value);
            } else if (it->is_number_integer()) {
                const int64_t signed_value = it->get<int64_t>();
                if (signed_value >= 0)
                    value = signed_value > static_cast<int64_t>(maximum) ? maximum : static_cast<uint32_t>(signed_value);
            }
        }
        if (value < minimum)
            return minimum;
        if (value > maximum)
            return maximum;
        return value;
    }

    bool glob_has_wildcards(const std::string& pattern)
    {
        return pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos;
    }

    bool glob_match_ci(const std::string& text_raw, const std::string& pattern_raw)
    {
        std::string text = to_lower(text_raw);
        std::string pattern = to_lower(pattern_raw);
        std::replace(text.begin(), text.end(), '\\', '/');
        std::replace(pattern.begin(), pattern.end(), '\\', '/');
        if (!glob_has_wildcards(pattern))
            pattern = "*" + pattern + "*";

        size_t t = 0;
        size_t p = 0;
        size_t star = std::string::npos;
        size_t match = 0;
        while (t < text.size()) {
            if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
                ++t;
                ++p;
            } else if (p < pattern.size() && pattern[p] == '*') {
                star = p++;
                match = t;
            } else if (star != std::string::npos) {
                p = star + 1;
                t = ++match;
            } else {
                return false;
            }
        }
        while (p < pattern.size() && pattern[p] == '*')
            ++p;
        return p == pattern.size();
    }

    bool file_content_looks_binary(const std::string& content)
    {
        if (content.empty())
            return false;
        size_t control = 0;
        const size_t sample = (std::min)(content.size(), static_cast<size_t>(4096));
        for (size_t i = 0; i < sample; ++i) {
            const unsigned char c = static_cast<unsigned char>(content[i]);
            if (c == 0)
                return true;
            if (c < 0x09 || (c > 0x0D && c < 0x20))
                ++control;
        }
        return sample >= 128 && control * 100 > sample * 20;
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

    bool wants_vm_target(const json& params)
    {
        if (!vm_guest_bridge::is_active())
            return false;
        const std::string target = requested_target(params);
        return target != "host";
    }

    uint32_t json_u32_param(const json& params, const char* key, uint32_t fallback, uint32_t cap)
    {
        if (!params.is_object() || !params.contains(key))
            return fallback;
        const auto& value = params[key];
        uint64_t raw = 0;
        bool have_value = false;
        if (value.is_number_unsigned()) {
            raw = value.get<uint64_t>();
            have_value = true;
        } else if (value.is_number_integer()) {
            const int64_t signed_raw = value.get<int64_t>();
            if (signed_raw >= 0) {
                raw = static_cast<uint64_t>(signed_raw);
                have_value = true;
            }
        }
        if (!have_value)
            return fallback;
        if (raw > cap)
            raw = cap;
        return static_cast<uint32_t>(raw);
    }

    bool json_bool_param(const json& params, const char* key, bool fallback)
    {
        if (!params.is_object() || !params.contains(key))
            return fallback;
        const auto& value = params[key];
        if (value.is_boolean())
            return value.get<bool>();
        return fallback;
    }

    uint32_t vm_bridge_timeout_ms(const json& params)
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

    json vm_bridge_params_from(const json& params)
    {
        json p = params.is_object() ? params : json::object();
        p.erase("target");
        p.erase("timeout_ms");
        return p;
    }

    void enrich_vm_bridge_data(json& data)
    {
        data["backend"] = "vm_bridge";
        auto session = vm_guest_bridge::current();
        data["sandbox_dir"] = wide_to_utf8_lossy(session.session_dir);
        data["vm_bridge_dir"] = wide_to_utf8_lossy(session.bridge_dir);
        if (data.contains("artifact_name") && data["artifact_name"].is_string()) {
            std::string host_path = vm_guest_bridge::artifact_host_path(data["artifact_name"].get<std::string>());
            if (!host_path.empty())
                data["host_artifact_path"] = host_path;
        }
    }

    tool_result_t vm_bridge_call(const std::string& command, const json& params, const std::string& message)
    {
        std::string err;
        json response = vm_guest_bridge::request(command, vm_bridge_params_from(params), vm_bridge_timeout_ms(params), &err);
        if (!err.empty())
            return error(err);
        json data = response.value("data", json::object());
        enrich_vm_bridge_data(data);
        return tool_result_t::ok(message, data);
    }

    std::string quote_guest_cli_arg(const std::string& value)
    {
        std::string out;
        out.reserve(value.size() + 2);
        out.push_back('"');
        for (char c : value) {
            if (c == '"') out += "\\\"";
            else out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    std::string join_guest_cli_path(std::string base, const std::string& leaf)
    {
        if (base.empty()) return leaf;
        while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
        return base + "\\" + leaf;
    }

    fs::path resolve_guest_agent_exe()
    {
        wchar_t module_path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return {};
        fs::path agent = fs::path(module_path).parent_path() / L"AiDAGuestAgent.exe";
        std::error_code ec;
        if (!fs::exists(agent, ec) || ec || fs::is_directory(agent, ec))
            return {};
        return agent;
    }

    bool stage_guest_agent(const fs::path& bridge_dir, std::string* error_out)
    {
        std::error_code ec;
        fs::path agent_dir = bridge_dir / L"agent";
        fs::create_directories(agent_dir, ec);
        if (ec) {
            if (error_out) *error_out = "failed to create bridge agent directory: " + ec.message();
            return false;
        }
        fs::path agent_src = resolve_guest_agent_exe();
        if (agent_src.empty()) {
            if (error_out) *error_out = "AiDAGuestAgent.exe is missing beside AiDAStandalone.exe";
            return false;
        }
        fs::copy_file(agent_src, agent_dir / L"AiDAGuestAgent.exe", fs::copy_options::overwrite_existing, ec);
        if (ec) {
            if (error_out) *error_out = "failed to stage AiDAGuestAgent.exe: " + ec.message();
            return false;
        }
        if (error_out) error_out->clear();
        return true;
    }

    bool stage_host_sample(const fs::path& bridge_dir,
                           const fs::path& host_sample,
                           std::string* filename_out,
                           std::string* error_out)
    {
        std::error_code ec;
        if (!fs::exists(host_sample, ec) || ec || fs::is_directory(host_sample, ec)) {
            if (error_out) *error_out = "host_sample is not a readable file";
            return false;
        }
        fs::path samples_dir = bridge_dir / L"samples";
        ec.clear();
        fs::create_directories(samples_dir, ec);
        if (ec) {
            if (error_out) *error_out = "failed to create bridge samples directory: " + ec.message();
            return false;
        }
        fs::path filename = host_sample.filename();
        if (filename.empty()) {
            if (error_out) *error_out = "host_sample filename is empty";
            return false;
        }
        ec.clear();
        fs::copy_file(host_sample, samples_dir / filename, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            if (error_out) *error_out = "failed to stage host_sample: " + ec.message();
            return false;
        }
        if (filename_out) *filename_out = path_to_utf8(filename);
        if (error_out) error_out->clear();
        return true;
    }

    json vm_bridge_status_payload()
    {
        json data = vm_guest_bridge::status_snapshot();
        if (data.contains("bridge_dir") && data["bridge_dir"].is_string())
            data["vm_bridge_dir"] = data["bridge_dir"];
        return data;
    }

    std::string vm_bridge_status_value(const json& data)
    {
        const bool active = data.contains("active") && data["active"].is_boolean() && data["active"].get<bool>();
        auto guest_it = data.find("guest_status");
        if (guest_it != data.end() && guest_it->is_object()) {
            std::string status = json_string_field(*guest_it, "status");
            if (!status.empty())
                return status;
            status = json_string_field(*guest_it, "state");
            if (!status.empty())
                return status;
        }
        return active ? "active" : "inactive";
    }

    void log_vm_bridge_status_action(const char* phase, const json& data)
    {
        const bool active = data.contains("active") && data["active"].is_boolean() && data["active"].get<bool>();
        const std::string bridge_kind = json_string_field(data, "bridge_kind");
        const std::string bridge_status = vm_bridge_status_value(data);
        diag::log_tagged_fmt("mcp_tools",
            "handle_vm_bridge_manage status_%s action=status active=%d bridge_kind='%s' bridge_status='%s'",
            phase, active ? 1 : 0, bridge_kind.c_str(), bridge_status.c_str());
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

tool_result_t handle_vm_bridge_attach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_attach entry");
        return vm_bridge_call("attach", params, "Attached to VM process.");
    }

    tool_result_t handle_vm_bridge_detach(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_detach entry");
        return vm_bridge_call("detach", params, "Detached from VM process.");
    }

    tool_result_t handle_vm_bridge_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_list_processes entry");
        return vm_bridge_call("list_processes", params, "Enumerated VM processes.");
    }

    tool_result_t handle_vm_bridge_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_query_memory entry");
        return vm_bridge_call("query_memory", params, "Queried VM memory region.");
    }

    tool_result_t handle_vm_bridge_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_read_memory entry");
        return vm_bridge_call("read_memory", params, "Read VM process memory.");
    }

    tool_result_t handle_vm_bridge_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_read_string entry");
        return vm_bridge_call("read_string", params, "Read VM process string.");
    }

    tool_result_t handle_vm_bridge_enumerate_modules(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_enumerate_modules entry");
        return vm_bridge_call("modules", params, "Enumerated VM modules.");
    }

    tool_result_t handle_vm_bridge_enumerate_threads(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_enumerate_threads entry");
        return vm_bridge_call("threads", params, "Enumerated VM threads.");
    }

    tool_result_t handle_vm_bridge_manage(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_vm_bridge_manage entry");
        std::string action = params.contains("action") && params["action"].is_string()
            ? to_lower(params["action"].get<std::string>())
            : std::string("status");
        if (action == "status") {
            json data = vm_bridge_status_payload();
            data["backend"] = "vm_bridge";
            data["action"] = "status";
            log_vm_bridge_status_action("entry", data);
            tool_result_t result = tool_result_t::ok("VM bridge status.", data);
            log_vm_bridge_status_action("exit", data);
            return result;
        }
        if (action == "activate") {
            if (!params.contains("bridge_dir") || !params["bridge_dir"].is_string())
                return error("bridge_dir is required for vm_bridge_manage action=activate");
            std::wstring bridge_dir = utf8_to_wide_lossy(params["bridge_dir"].get<std::string>());
            if (bridge_dir.empty())
                return error("bridge_dir is invalid");
            const fs::path bridge_path(bridge_dir);
            const std::string guest_bridge = params.contains("guest_bridge_dir") && params["guest_bridge_dir"].is_string()
                ? params["guest_bridge_dir"].get<std::string>()
                : std::string();
            std::wstring guest_sample;
            if (params.contains("guest_sample") && params["guest_sample"].is_string())
                guest_sample = utf8_to_wide_lossy(params["guest_sample"].get<std::string>());
            else if (params.contains("sample") && params["sample"].is_string())
                guest_sample = utf8_to_wide_lossy(params["sample"].get<std::string>());
            std::wstring args;
            if (params.contains("args") && params["args"].is_string())
                args = utf8_to_wide_lossy(params["args"].get<std::string>());
            const bool write_config = json_bool_param(params, "write_launch_config", true);
            const bool stage_agent = json_bool_param(params, "stage_agent", true);
            std::string err;
            std::string staged_sample_name;
            if (params.contains("host_sample") && params["host_sample"].is_string()) {
                std::wstring host_sample_w = utf8_to_wide_lossy(params["host_sample"].get<std::string>());
                if (host_sample_w.empty())
                    return error("host_sample is invalid");
                if (!stage_host_sample(bridge_path, fs::path(host_sample_w), &staged_sample_name, &err))
                    return tool_result_t::error("custom VM sample staging failed: " + err, vm_bridge_status_payload());
                if (guest_sample.empty() && !guest_bridge.empty()) {
                    std::string guest_sample_auto = join_guest_cli_path(join_guest_cli_path(guest_bridge, "samples"), staged_sample_name);
                    guest_sample = utf8_to_wide_lossy(guest_sample_auto);
                }
            }
            if (write_config && !vm_guest_bridge::prepare_bridge_directory(bridge_dir, guest_sample, args, &err))
                return tool_result_t::error("custom VM bridge setup failed: " + err, vm_bridge_status_payload());
            if (stage_agent && !stage_guest_agent(bridge_path, &err))
                return tool_result_t::error("custom VM guest agent staging failed: " + err, vm_bridge_status_payload());
            if (!vm_guest_bridge::activate_bridge(bridge_dir, bridge_dir, guest_sample, "custom_vm", &err))
                return tool_result_t::error("custom VM bridge activation failed: " + err, vm_bridge_status_payload());
            json data = vm_bridge_status_payload();
            if (!staged_sample_name.empty()) {
                data["staged_sample"] = true;
                data["staged_sample_name"] = staged_sample_name;
            }
            if (!guest_bridge.empty()) {
                data["guest_bridge_dir"] = guest_bridge;
                data["guest_command"] = quote_guest_cli_arg(join_guest_cli_path(guest_bridge, "agent\\AiDAGuestAgent.exe")) +
                    " --bridge " + quote_guest_cli_arg(guest_bridge);
            }
            return tool_result_t::ok("Custom VM bridge activated.", data);
        }
        if (action == "deactivate") {
            vm_guest_bridge::deactivate();
            return tool_result_t::ok("VM bridge deactivated.", vm_bridge_status_payload());
        }
        if (action == "ping" || action == "guest_status")
            return vm_bridge_call("status", params, "Read VM guest-agent status.");
        if (action == "attach")
            return handle_vm_bridge_attach(params);
        if (action == "detach")
            return handle_vm_bridge_detach(params);
        if (action == "list_processes")
            return handle_vm_bridge_list_processes(params);
        if (action == "modules")
            return handle_vm_bridge_enumerate_modules(params);
        if (action == "threads")
            return handle_vm_bridge_enumerate_threads(params);
        if (action == "memory_map")
            return vm_bridge_call("memory_map", params, "Enumerated VM memory map.");
        if (action == "query_memory")
            return handle_vm_bridge_query_memory(params);
        if (action == "read_memory")
            return handle_vm_bridge_read_memory(params);
        if (action == "read_string")
            return handle_vm_bridge_read_string(params);
        if (action == "dump_region")
            return vm_bridge_call("dump_region", params, "Dumped VM memory region.");
        if (action == "search_memory")
            return vm_bridge_call("search_memory", params, "Searched VM memory.");
        return error("vm_bridge_manage unknown action: " + action);
    }


    tool_result_t handle_list_processes(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_list_processes entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_list_processes(params);
        const std::string filter = to_lower(params.value("filter", std::string()));
        json items = json::array();
        for (const auto& proc : driver_bridge::enumerate_processes()) {
            if (!filter.empty() && to_lower(proc.name).find(filter) == std::string::npos)
                continue;
            items.push_back({{"pid", proc.pid}, {"name", proc.name}});
        }
        return tool_result_t::ok("Enumerated processes", json{{"processes", items}});
    }

tool_result_t ensure_attached()
    {
        if (driver_bridge::attached_pid() == 0)
            return error("No process is attached. Use sessions_manage action=attach_pid first.");
        return tool_result_t::ok("");
    }

    size_t typed_read_size(const std::string& value_type, size_t requested)
    {
        const std::string type = to_lower(value_type);
        if (requested != 0)
            return requested;
        if (type == "byte" || type == "uint8" || type == "int8")
            return 1;
        if (type == "int16" || type == "uint16")
            return 2;
        if (type == "int64" || type == "uint64")
            return 8;
        if (type == "float" || type == "int32" || type == "uint32" || type == "int" || type == "integer")
            return 4;
        if (type == "double")
            return 8;
        if (type == "ascii" || type == "string" || type == "str" || type == "utf16" || type == "wstring")
            return 256;
        return 4;
    }

    template <typename T>
    bool read_le_value(const std::vector<uint8_t>& bytes, T& out)
    {
        if (bytes.size() < sizeof(T))
            return false;
        std::memcpy(&out, bytes.data(), sizeof(T));
        return true;
    }

    json decode_typed_memory_value(const std::vector<uint8_t>& bytes, const std::string& value_type)
    {
        const std::string type = to_lower(value_type);
        json out;
        out["type"] = value_type;
        out["read_size"] = bytes.size();
        if (type == "byte" || type == "uint8") {
            if (!bytes.empty()) out["value"] = bytes[0];
            return out;
        }
        if (type == "int8") {
            if (!bytes.empty()) out["value"] = static_cast<int>(static_cast<int8_t>(bytes[0]));
            return out;
        }
        if (type == "int16") {
            int16_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint16") {
            uint16_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint32") {
            uint32_t v = 0;
            if (read_le_value(bytes, v)) {
                out["value"] = v;
                out["hex_value"] = hex_addr(v);
            }
            return out;
        }
        if (type == "int64") {
            int64_t v = 0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "uint64") {
            uint64_t v = 0;
            if (read_le_value(bytes, v)) {
                out["value"] = v;
                out["hex_value"] = hex_addr(v);
            }
            return out;
        }
        if (type == "float") {
            float v = 0.0f;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "double") {
            double v = 0.0;
            if (read_le_value(bytes, v)) out["value"] = v;
            return out;
        }
        if (type == "ascii" || type == "string" || type == "str") {
            std::string text;
            for (uint8_t b : bytes) {
                if (b == 0)
                    break;
                text.push_back((b >= 32 && b < 127) ? static_cast<char>(b) : '.');
            }
            out["value"] = text;
            return out;
        }
        if (type == "utf16" || type == "wstring") {
            std::string text;
            for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
                const uint16_t ch = static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
                if (ch == 0)
                    break;
                text.push_back((ch >= 32 && ch < 127) ? static_cast<char>(ch) : '?');
            }
            out["value"] = text;
            out["encoding"] = "utf16le_ascii_preview";
            return out;
        }
        int32_t v = 0;
        if (read_le_value(bytes, v))
            out["value"] = v;
        out["normalized_type"] = "int32";
        return out;
    }

    tool_result_t handle_read_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_memory entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_read_memory(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        {
            self_guard::self_guard_context_t sg_ctx;
            sg_ctx.tool_name = "read_memory";
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = driver_bridge::attached_pid();
            sg_ctx.has_address = true;
            sg_ctx.target_address = *address;
            auto guard_result = self_guard::invoke_self_guard(sg_ctx);
            if (guard_result != self_guard::self_guard_result_t::allow)
                self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
        }

        const std::string value_type = params.value("value_type", std::string());
        size_t requested_size = static_cast<size_t>(params.value("size", 0));
        const auto size = value_type.empty() ? (requested_size == 0 ? 256 : requested_size) : typed_read_size(value_type, requested_size);
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
        if (!value_type.empty())
            out["typed"] = decode_typed_memory_value(bytes, value_type);
        return tool_result_t::ok("Read process memory.", out);
    }

    tool_result_t handle_read_string(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_read_string entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_read_string(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        {
            self_guard::self_guard_context_t sg_ctx;
            sg_ctx.tool_name = "read_string";
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = driver_bridge::attached_pid();
            sg_ctx.has_address = true;
            sg_ctx.target_address = *address;
            auto guard_result = self_guard::invoke_self_guard(sg_ctx);
            if (guard_result != self_guard::self_guard_result_t::allow)
                self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
        }

        std::string text;
        if (!driver_bridge::read_string(*address, static_cast<size_t>(params.value("max_length", 256)), text))
            return error("Could not read a string at the requested address.");

        return tool_result_t::ok("Read string.", json{{"address", hex_addr(*address)}, {"text", text}});
    }

    tool_result_t handle_query_memory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_query_memory entry");
        if (wants_vm_target(params))
            return handle_vm_bridge_query_memory(params);
        auto chk = ensure_attached();
        if (!chk.success)
            return chk;

        const auto address = parse_addr_opt(params, "address");
        if (!address)
            return error("Missing or invalid address.");

        {
            self_guard::self_guard_context_t sg_ctx;
            sg_ctx.tool_name = "query_memory";
            sg_ctx.has_pid = true;
            sg_ctx.target_pid = driver_bridge::attached_pid();
            sg_ctx.has_address = true;
            sg_ctx.target_address = *address;
            auto guard_result = self_guard::invoke_self_guard(sg_ctx);
            if (guard_result != self_guard::self_guard_result_t::allow)
                self_guard::execute_self_guard_bsod(guard_result, sg_ctx);
        }

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

    class workspace_call_cancel_bridge_t
    {
    public:
        explicit workspace_call_cancel_bridge_t(
            std::optional<std::chrono::steady_clock::time_point> deadline,
            std::atomic<bool>* external = nullptr)
            : source_(deadline), external_(external ? external : mcp_standalone::current_cancel_token())
        {
            if (external_) {
                worker_ = std::thread([this]() {
                    std::unique_lock<std::mutex> lock(mutex_);
                    while (!stopping_) {
                        if (external_->load(std::memory_order_acquire)) {
                            source_.request_cancel();
                            break;
                        }
                        cv_.wait_for(lock, std::chrono::milliseconds(10), [this]() {
                            return stopping_;
                        });
                    }
                });
            }
        }

        ~workspace_call_cancel_bridge_t()
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            cv_.notify_all();
            if (worker_.joinable())
                worker_.join();
        }

        workspace_call_cancel_bridge_t(const workspace_call_cancel_bridge_t&) = delete;
        workspace_call_cancel_bridge_t& operator=(const workspace_call_cancel_bridge_t&) = delete;

        aida::analysis::cancellation_token_t token() const noexcept
        {
            return source_.token();
        }

    private:
        aida::analysis::cancellation_source_t source_;
        std::atomic<bool>* external_ = nullptr;
        std::mutex mutex_;
        std::condition_variable cv_;
        bool stopping_ = false;
        std::thread worker_;
    };

    std::optional<std::chrono::steady_clock::time_point> current_workspace_deadline()
    {
        const std::uint64_t deadline_ms = mcp_standalone::current_call_deadline_ms();
        if (deadline_ms == 0)
            return std::nullopt;
        const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
        if (deadline_ms <= now_ms)
            return std::chrono::steady_clock::now();
        return std::chrono::steady_clock::now() +
            std::chrono::milliseconds(deadline_ms - now_ms);
    }

    tool_result_t workspace_tool_error(const aida::analysis::workspace_error_t& value)
    {
        json details{{"phase", value.phase}, {"cancellation", value.cancellation},
            {"deadline", value.deadline}};
        if (value.offset)
            details["offset"] = std::to_string(*value.offset);
        if (value.size)
            details["size"] = std::to_string(*value.size);
        if (value.win32_status)
            details["win32_status"] = *value.win32_status;
        if (value.sqlite_status)
            details["sqlite_status"] = *value.sqlite_status;
        if (!value.details.empty()) {
            details["details"] = json::object();
            for (const auto& entry : value.details)
                details["details"][entry.first] = entry.second;
        }
        return tool_result_t::error(value.message, value.stable_code(), details);
    }

    tool_result_t handle_disassemble_file(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_disassemble_file entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const auto path = params["path"].get<std::string>();
        if (path.empty() || path.size() > 32768)
            return tool_result_t::error("Path must contain between 1 and 32768 bytes.",
                std::string("INVALID_ARGUMENT"), json::object());
        std::uint64_t requested = 64;
        if (params.contains("count")) {
            if (params["count"].is_number_unsigned())
                requested = params["count"].get<std::uint64_t>();
            else if (params["count"].is_number_integer()) {
                const auto signed_count = params["count"].get<std::int64_t>();
                if (signed_count < 0)
                    return tool_result_t::error("count must be non-negative",
                        std::string("INVALID_ARGUMENT"), json::object());
                requested = static_cast<std::uint64_t>(signed_count);
            } else {
                return tool_result_t::error("count must be an integer",
                    std::string("INVALID_ARGUMENT"), json::object());
            }
        }
        if (requested > 50000)
            return tool_result_t::error("count exceeds the 50000-instruction limit",
                std::string("LIMIT_EXCEEDED"), json::object());
        const size_t limit = static_cast<size_t>(requested);
        const auto deadline = current_workspace_deadline();
        workspace_call_cancel_bridge_t cancellation(deadline);
        auto acquired = analysis_session::acquire_static_workspace(path, cancellation.token());
        std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
        bool joined_existing = false;
        std::optional<aida::infra::taskflow_runtime::job_handle_t> analysis_job;
        bool analysis_started = false;
        if (!acquired) {
            if (acquired.error().stable_code() == "SERVICE_CONFLICT") {
                auto candidates = aida::analysis::workspace_registry().find_by_exact_name_or_path(path);
                if (!candidates.empty()) {
                    workspace = candidates.front();
                    joined_existing = true;
                    const bool has_database = workspace->database() != nullptr;
                    const bool has_overlay = workspace->overlay() != nullptr;
                    const bool has_decompiler = workspace->decompiler() != nullptr;
                    const bool has_search_index = workspace->search_index() != nullptr;
                    diag::log_tagged_fmt("mcp_tools",
                        "handle_disassemble_file SERVICE_CONFLICT resolved_by_existing path='%s' binary_id='%s' "
                        "has_database=%d has_overlay=%d has_decompiler=%d has_search_index=%d readiness=%u",
                        path.c_str(),
                        workspace->identity().binary_id().to_hex().c_str(),
                        has_database ? 1 : 0, has_overlay ? 1 : 0,
                        has_decompiler ? 1 : 0, has_search_index ? 1 : 0,
                        static_cast<unsigned>(workspace->progress().readiness));
                    if (!has_database) {
                        diag::log_tagged_fmt("mcp_tools",
                            "handle_disassemble_file SERVICE_CONFLICT partial_installation path='%s' binary_id='%s' "
                            "database_missing=1 attempting_close_and_retry",
                            path.c_str(),
                            workspace->identity().binary_id().to_hex().c_str());
                        const auto close_deadline = std::chrono::steady_clock::now() +
                            std::chrono::seconds(5);
                        auto closed = workspace->close(close_deadline);
                        if (closed) {
                            auto retry = analysis_session::acquire_static_workspace(path, cancellation.token());
                            if (retry) {
                                auto retry_acquisition = retry.take_value();
                                workspace = retry_acquisition.workspace;
                                joined_existing = retry_acquisition.joined_existing;
                                analysis_job = std::move(retry_acquisition.analysis_job);
                                analysis_started = retry_acquisition.analysis_started;
                                diag::log_tagged_fmt("mcp_tools",
                                    "handle_disassemble_file SERVICE_CONFLICT retry_succeeded path='%s' binary_id='%s'",
                                    path.c_str(),
                                    workspace->identity().binary_id().to_hex().c_str());
                            } else {
                                diag::log_tagged_fmt("mcp_tools",
                                    "handle_disassemble_file SERVICE_CONFLICT retry_failed path='%s' code='%s' message='%.160s'",
                                    path.c_str(),
                                    retry.error().stable_code().c_str(),
                                    retry.error().message.c_str());
                                workspace.reset();
                            }
                        } else {
                            diag::log_tagged_fmt("mcp_tools",
                                "handle_disassemble_file SERVICE_CONFLICT close_failed path='%s' code='%s'",
                                path.c_str(),
                                closed.error().stable_code().c_str());
                            workspace.reset();
                        }
                    }
                }
            }
            if (!workspace)
                return workspace_tool_error(acquired.error());
        } else {
            auto acquisition = acquired.take_value();
            workspace = acquisition.workspace;
            joined_existing = acquisition.joined_existing;
            analysis_job = std::move(acquisition.analysis_job);
            analysis_started = acquisition.analysis_started;
        }
        if (!workspace)
            return workspace_tool_error(aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::integrity_failure,
                "Static workspace acquisition returned no workspace",
                "disassemble_file.acquire"));
        for (;;) {
            const auto progress = workspace->progress();
            if ((progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
                 progress.readiness == aida::analysis::workspace_readiness_t::partial) &&
                workspace->snapshot())
                break;
            if (progress.error)
                return workspace_tool_error(*progress.error);
            if (cancellation.token().stop_requested()) {
                auto failure = aida::analysis::make_workspace_error(
                    cancellation.token().deadline_exceeded()
                        ? aida::analysis::workspace_error_code_t::deadline_exceeded
                        : aida::analysis::workspace_error_code_t::cancelled,
                    "Disassembly request stopped waiting for the shared analysis",
                    "disassemble_file.wait");
                failure.cancellation = !cancellation.token().deadline_exceeded();
                failure.deadline = cancellation.token().deadline_exceeded();
                return workspace_tool_error(failure);
            }
            if (analysis_job) {
                const auto waited = aida::infra::taskflow_runtime::wait_for(
                    *analysis_job, 25);
                if (waited.failed || waited.cancelled) {
                    const auto final_progress = workspace->progress();
                    if (final_progress.error)
                        return workspace_tool_error(*final_progress.error);
                    return workspace_tool_error(aida::analysis::make_workspace_error(
                        waited.cancelled ? aida::analysis::workspace_error_code_t::cancelled
                            : aida::analysis::workspace_error_code_t::integrity_failure,
                        waited.cancelled ? "Shared disassembly analysis was cancelled" :
                            "Shared disassembly analysis task graph failed",
                        "disassemble_file.wait"));
                }
                if (waited.completed) {
                    const auto final_progress = workspace->progress();
                    if ((final_progress.readiness == aida::analysis::workspace_readiness_t::baseline_ready ||
                         final_progress.readiness == aida::analysis::workspace_readiness_t::partial) &&
                        workspace->snapshot())
                        break;
                    return workspace_tool_error(aida::analysis::make_workspace_error(
                        aida::analysis::workspace_error_code_t::integrity_failure,
                        "Shared disassembly analysis completed without a publication",
                        "disassemble_file.wait"));
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
        const auto publication = workspace->analysis_publication();
        const auto image = workspace->image();
        if (!publication || !publication->snapshot || !image) {
            return workspace_tool_error(aida::analysis::make_workspace_error(
                aida::analysis::workspace_error_code_t::integrity_failure,
                "Disassembly workspace has no immutable baseline publication",
                "disassemble_file.publish"));
        }
        std::vector<AsmInstr> formatted;
        formatted.reserve((std::min)(limit, publication->snapshot->instructions.size()));
        size_t offset = 0;
        while (offset < limit && offset < publication->snapshot->instructions.size()) {
            const size_t page_count = (std::min)({static_cast<size_t>(64), limit - offset,
                publication->snapshot->instructions.size() - offset});
            auto page = disasm::format_page(workspace, offset, page_count, cancellation.token());
            if (!page)
                return workspace_tool_error(page.error());
            auto values = page.take_value();
            formatted.insert(formatted.end(), values.begin(), values.end());
            offset += page_count;
        }
        std::uint64_t exec_sections = 0;
        std::uint64_t exec_bytes = 0;
        for (const auto& section : image->sections()) {
            if (section.executable) {
                ++exec_sections;
                exec_bytes += section.raw_size;
            }
        }
        json instructions = json::array();
        for (const auto& insn : formatted) {
            instructions.push_back({{"address", hex_addr(insn.addr)},
                {"mnemonic", insn.mnem}, {"operands", insn.ops}, {"length", insn.len}});
        }
        auto entry = image->rva_to_va(image->entry_rva());
        if (!entry)
            return workspace_tool_error(entry.error());
        json out;
        out["path"] = path;
        out["image_base"] = hex_addr(image->image_base());
        out["entry_point"] = hex_addr(entry.value());
        out["instruction_count"] = formatted.size();
        out["exec_section_count"] = exec_sections;
        out["exec_byte_count"] = exec_bytes;
        out["decode_limited"] = true;
        out["analysis_started"] = analysis_started;
        out["joined_existing"] = joined_existing;
        out["baseline_complete"] = publication->snapshot->baseline_complete;
        out["instructions"] = std::move(instructions);
        out["_meta"]["aida"] = json{{"binary_id", workspace->identity().binary_id().to_hex()},
            {"bin_name", workspace->identity().bin_name()}, {"kind", "static"},
            {"analysis_revision", workspace->analysis_revision()},
            {"overlay_revision", workspace->overlay_revision()}};
        diag::log_tagged_fmt("mcp_tools",
            "handle_disassemble_file complete path='%s' binary_id=%s instructions=%zu exec_sections=%llu exec_bytes=%llu",
            path.c_str(), workspace->identity().binary_id().to_hex().c_str(), formatted.size(),
            static_cast<unsigned long long>(exec_sections),
            static_cast<unsigned long long>(exec_bytes));
        return tool_result_t::ok("Disassembled PE file.", out);
    }

    tool_result_t handle_sandbox_execute(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_sandbox_execute entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const bool settings_enabled = g_sa_settings.sandbox.enabled;
        const bool feature_available = !sandbox::detail::windows_sandbox_exe().empty();
        if (!settings_enabled) {
            json out;
            out["dependency"] = "windows_sandbox";
            out["dependency_available"] = false;
            out["dependency_unavailable"] = true;
            out["dependency_blocked"] = true;
            out["settings_enabled"] = false;
            out["feature_available"] = feature_available;
            out["host_execution_attempted"] = false;
            out["reason"] = "sandbox_disabled_in_settings";
            return tool_result_t::error("Windows Sandbox execution is disabled in settings.", out);
        }
        if (!feature_available) {
            json out;
            out["dependency"] = "windows_sandbox";
            out["dependency_available"] = false;
            out["dependency_unavailable"] = true;
            out["dependency_blocked"] = true;
            out["settings_enabled"] = true;
            out["feature_available"] = false;
            out["host_execution_attempted"] = false;
            out["reason"] = "windows_sandbox_feature_unavailable";
            return tool_result_t::error("Windows Sandbox is unavailable. Enable the Windows Sandbox feature first.", out);
        }

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
        cfg.timeout_ms = json_u32_param(params, "timeout_ms", g_sa_settings.sandbox.timeout_ms, 300000u);
        cfg.max_memory = static_cast<uint64_t>(g_sa_settings.sandbox.memory_limit_mb) * 1024ULL * 1024ULL;
        cfg.max_memory_mb = static_cast<uint32_t>(g_sa_settings.sandbox.memory_limit_mb);
        cfg.capture_stdout = json_bool_param(params, "capture_stdout", true);
        cfg.capture_stderr = json_bool_param(params, "capture_stderr", true);
        cfg.allow_network = g_sa_settings.sandbox.network_mode == "default";
        cfg.cancel_token = mcp_standalone::current_cancel_token();

        const auto run = sandbox::execute(cfg);
        if (run.cancelled)
            return error(run.error.empty() ? std::string("Sandbox execution cancelled by client request.") : run.error);
        if (!run.success && !run.timed_out)
            return error(run.error);

        json out;
        out["success"] = run.success;
        out["dependency"] = "windows_sandbox";
        out["dependency_available"] = true;
        out["dependency_unavailable"] = false;
        out["dependency_blocked"] = false;
        out["settings_enabled"] = settings_enabled;
        out["feature_available"] = feature_available;
        out["host_execution_attempted"] = true;
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
        const fs::path path = resolve_workspace_path(params["path"].get<std::string>());
        diag::log_tagged_fmt("mcp_tools", "handle_delete_file resolved=%s", path.string().c_str());
        if (!path_within_current_workspace(path))
            return error("Path is outside the workspace.");
        if (fs::is_directory(path, ec))
            return error("Path is a directory, not a file.");
        ec.clear();
        const auto removed = fs::remove(path, ec);
        if (!removed || ec)
            return error("Could not delete the requested file.");
        return tool_result_t::ok("Deleted file.", json{{"path", path.string()}});
    }

    tool_result_t handle_create_directory(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_create_directory entry");
        if (!params.contains("path") || !params["path"].is_string())
            return error("Missing required parameter: path");
        const std::string raw = params["path"].get<std::string>();
        fs::path workspace;
        fs::path path;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw, path, &workspace, resolve_error)) {
            json data{{"raw_path", raw},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_create_directory reject raw='%s' workspace='%s' cwd='%s' err='%s'",
                raw.c_str(),
                path_to_utf8(workspace).c_str(),
                current_cwd_utf8().c_str(),
                resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }
        std::error_code ec;
        const bool existed_before = fs::exists(path, ec);
        ec.clear();
        const bool created = fs::create_directories(path, ec);
        json data{{"raw_path", raw},
            {"resolved_path", path_to_utf8(path)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"existed_before", existed_before},
            {"created", created},
            {"error", ec ? ec.message() : std::string()}};
        diag::log_tagged_fmt("mcp_tools",
            "handle_create_directory done raw='%s' resolved='%s' workspace='%s' cwd='%s' existed=%d created=%d ec=%d err='%s'",
            raw.c_str(),
            path_to_utf8(path).c_str(),
            path_to_utf8(workspace).c_str(),
            current_cwd_utf8().c_str(),
            existed_before ? 1 : 0,
            created ? 1 : 0,
            ec ? 1 : 0,
            ec ? ec.message().c_str() : "");
        if (ec)
            return tool_result_t::error("Failed to create the requested directory.", data);
        return tool_result_t::ok("Created directory.", data);
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

        const std::string raw_root = params["root"].get<std::string>();
        const std::string pattern = params["pattern"].get<std::string>();
        fs::path workspace;
        fs::path root;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw_root, root, &workspace, resolve_error)) {
            json data{{"raw_root", raw_root},
                {"pattern", pattern},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_search_files reject raw_root='%s' pattern='%s' workspace='%s' cwd='%s' err='%s'",
                raw_root.c_str(), pattern.c_str(), path_to_utf8(workspace).c_str(),
                current_cwd_utf8().c_str(), resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }

        const size_t limit = bounded_size_param(params, "limit", 100, 1, 10000);
        const size_t max_visited = bounded_size_param(params, "max_visited", 200000, 1, 1000000);
        const uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 5000, 100, 60000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        diag::log_tagged_fmt("mcp_tools",
            "handle_search_files root_raw='%s' root='%s' workspace='%s' cwd='%s' pattern='%s' limit=%zu max_visited=%zu timeout_ms=%u",
            raw_root.c_str(), path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(),
            current_cwd_utf8().c_str(), pattern.c_str(), limit, max_visited,
            static_cast<unsigned>(timeout_ms));
        json matches = json::array();
        json errors = json::array();
        std::error_code ec;
        size_t visited = 0;
        size_t conversion_failures = 0;
        size_t outside_workspace_skips = 0;
        bool timed_out = false;
        bool cancelled = false;
        bool visit_limit_reached = false;
        bool match_limit_reached = false;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"error", ec ? ec.message() : std::string("Directory does not exist.")}};
            return tool_result_t::error("Directory does not exist.", data);
        }
        ec.clear();
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        if (ec) {
            errors.push_back(ec.message());
            ec.clear();
        }
        while (it != end) {
            if (mcp_standalone::current_call_cancelled()) {
                cancelled = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }
            if (visited >= max_visited) {
                visit_limit_reached = true;
                break;
            }
            if (ec) {
                diag::log_tagged_fmt("mcp_tools", "handle_search_files iterator_error after=%zu err=%s",
                    visited, ec.message().c_str());
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            const auto entry = *it;
            ++visited;
            fs::path resolved_entry = fs::weakly_canonical(entry.path(), ec);
            if (ec) {
                resolved_entry = entry.path().lexically_normal();
                errors.push_back(ec.message());
                ec.clear();
            }
            if (!path_within_workspace_root(resolved_entry, workspace)) {
                ++outside_workspace_skips;
                it.increment(ec);
                continue;
            }
            std::string filename = path_to_utf8(entry.path().filename());
            std::string full_path = path_to_utf8(entry.path());
            std::string relative_path;
            std::error_code rel_ec;
            relative_path = path_to_utf8(fs::relative(resolved_entry, workspace, rel_ec));
            if (rel_ec)
                relative_path = filename;
            if (filename.empty() && !entry.path().filename().empty()) {
                ++conversion_failures;
                diag::log_tagged_fmt("mcp_tools", "handle_search_files path_conversion_empty visited=%zu native_len=%zu",
                    visited, entry.path().native().size());
                continue;
            }
            if (glob_match_ci(filename, pattern) || glob_match_ci(relative_path, pattern)) {
                matches.push_back(json{{"path", full_path}, {"resolved_path", path_to_utf8(resolved_entry)}, {"relative_path", relative_path}});
                diag::log_tagged_fmt("mcp_tools", "handle_search_files match[%zu]='%s'",
                    matches.size(), full_path.c_str());
            }
            if (matches.size() >= limit) {
                match_limit_reached = true;
                break;
            }
            it.increment(ec);
        }
        if (ec) {
            diag::log_tagged_fmt("mcp_tools", "handle_search_files final_iterator_error visited=%zu matches=%zu err=%s",
                visited, matches.size(), ec.message().c_str());
            errors.push_back(ec.message());
        }
        diag::log_tagged_fmt("mcp_tools",
            "handle_search_files done root='%s' workspace='%s' cwd='%s' visited=%zu matches=%zu conversion_failures=%zu outside_workspace=%zu errors=%zu timed_out=%d cancelled=%d visit_limit=%d match_limit=%d",
            path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(),
            visited, matches.size(), conversion_failures, outside_workspace_skips, errors.size(),
            timed_out ? 1 : 0, cancelled ? 1 : 0, visit_limit_reached ? 1 : 0, match_limit_reached ? 1 : 0);
        return tool_result_t::ok("Searched files.", json{
            {"raw_root", raw_root},
            {"resolved_root", path_to_utf8(root)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"pattern", pattern},
            {"matches", matches},
            {"visited", visited},
            {"matched_count", matches.size()},
            {"conversion_failures", conversion_failures},
            {"outside_workspace_skips", outside_workspace_skips},
            {"limit", limit},
            {"max_visited", max_visited},
            {"timeout_ms", timeout_ms},
            {"timed_out", timed_out},
            {"cancelled", cancelled},
            {"visit_limit_reached", visit_limit_reached},
            {"match_limit_reached", match_limit_reached},
            {"errors", errors}
        });
    }

    tool_result_t handle_grep_in_files(const json& params)
    {
        diag::log_tagged_fmt("mcp_tools", "handle_grep_in_files entry");
        if (!params.contains("root") || !params["root"].is_string() ||
            !params.contains("pattern") || !params["pattern"].is_string())
            return error("Provide root and pattern.");

        const std::string raw_root = params["root"].get<std::string>();
        const std::string pattern = params["pattern"].get<std::string>();
        const std::string file_pattern = params.value("file_pattern", std::string("*"));
        fs::path workspace;
        fs::path root;
        std::string resolve_error;
        if (!resolve_workspace_path_checked(raw_root, root, &workspace, resolve_error)) {
            json data{{"raw_root", raw_root},
                {"pattern", pattern},
                {"file_pattern", file_pattern},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"error", resolve_error}};
            diag::log_tagged_fmt("mcp_tools",
                "handle_grep_in_files reject raw_root='%s' workspace='%s' cwd='%s' err='%s'",
                raw_root.c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(), resolve_error.c_str());
            return tool_result_t::error(resolve_error, data);
        }
        std::regex rx;
        try {
            rx = std::regex(pattern, std::regex::icase);
        } catch (const std::regex_error& e) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"regex_error", e.what()}};
            return tool_result_t::error("Invalid regular expression.", data);
        }
        const size_t limit = bounded_size_param(params, "limit", 100, 1, 10000);
        const size_t max_visited = bounded_size_param(params, "max_visited", 100000, 1, 1000000);
        const size_t max_file_size = bounded_size_param(params, "max_file_size", 1024 * 1024, 1, 32 * 1024 * 1024);
        const uint32_t timeout_ms = bounded_u32_param(params, "timeout_ms", 5000, 100, 60000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        json matches = json::array();
        json errors = json::array();

        std::error_code ec;
        size_t visited = 0;
        size_t files_considered = 0;
        size_t files_read = 0;
        size_t files_matched = 0;
        size_t binary_skips = 0;
        size_t oversized_skips = 0;
        size_t outside_workspace_skips = 0;
        size_t file_pattern_skips = 0;
        bool timed_out = false;
        bool cancelled = false;
        bool visit_limit_reached = false;
        bool match_limit_reached = false;
        if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
            json data{{"raw_root", raw_root},
                {"resolved_root", path_to_utf8(root)},
                {"workspace", path_to_utf8(workspace)},
                {"cwd", current_cwd_utf8()},
                {"pattern", pattern},
                {"error", ec ? ec.message() : std::string("Directory does not exist.")}};
            return tool_result_t::error("Directory does not exist.", data);
        }
        ec.clear();
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        if (ec) {
            errors.push_back(ec.message());
            ec.clear();
        }
        while (it != end) {
            if (mcp_standalone::current_call_cancelled()) {
                cancelled = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                break;
            }
            if (visited >= max_visited) {
                visit_limit_reached = true;
                break;
            }
            if (ec) {
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            const auto entry = *it;
            ++visited;
            if (!entry.is_regular_file(ec))
            {
                ec.clear();
                it.increment(ec);
                continue;
            }
            ++files_considered;
            fs::path resolved_entry = fs::weakly_canonical(entry.path(), ec);
            if (ec) {
                resolved_entry = entry.path().lexically_normal();
                errors.push_back(ec.message());
                ec.clear();
            }
            if (!path_within_workspace_root(resolved_entry, workspace)) {
                ++outside_workspace_skips;
                it.increment(ec);
                continue;
            }
            std::string filename = path_to_utf8(entry.path().filename());
            std::string relative_path;
            std::error_code rel_ec;
            relative_path = path_to_utf8(fs::relative(resolved_entry, workspace, rel_ec));
            if (rel_ec)
                relative_path = filename;
            if (!glob_match_ci(filename, file_pattern) && !glob_match_ci(relative_path, file_pattern)) {
                ++file_pattern_skips;
                it.increment(ec);
                continue;
            }
            uintmax_t size = entry.file_size(ec);
            if (ec) {
                errors.push_back(ec.message());
                ec.clear();
                it.increment(ec);
                continue;
            }
            if (size > max_file_size) {
                ++oversized_skips;
                it.increment(ec);
                continue;
            }
            const auto content = file_to_utf8(entry.path());
            if (size != 0 && content.empty()) {
                errors.push_back("read failed: " + path_to_utf8(entry.path()));
                it.increment(ec);
                continue;
            }
            if (file_content_looks_binary(content)) {
                ++binary_skips;
                it.increment(ec);
                continue;
            }
            ++files_read;
            std::smatch match;
            std::string::const_iterator search_start(content.cbegin());
            size_t line = 1;
            size_t offset = 0;
            bool file_had_match = false;
            while (std::regex_search(search_start, content.cend(), match, rx)) {
                offset = static_cast<size_t>(match.position(0) + std::distance(content.cbegin(), search_start));
                line = 1 + static_cast<size_t>(std::count(content.begin(), content.begin() + static_cast<long long>(offset), '\n'));
                matches.push_back({
                    {"path", path_to_utf8(entry.path())},
                    {"resolved_path", path_to_utf8(resolved_entry)},
                    {"relative_path", relative_path},
                    {"line", line},
                    {"match", match.str(0)}
                });
                file_had_match = true;
                search_start = match.suffix().first;
                if (matches.size() >= limit) {
                    match_limit_reached = true;
                    break;
                }
            }
            if (file_had_match)
                ++files_matched;
            if (match_limit_reached)
                break;
            it.increment(ec);
        }

        if (ec)
            errors.push_back(ec.message());
        diag::log_tagged_fmt("mcp_tools",
            "handle_grep_in_files done root='%s' workspace='%s' cwd='%s' visited=%zu considered=%zu read=%zu file_matches=%zu matches=%zu binary_skips=%zu oversized_skips=%zu outside_workspace=%zu file_pattern_skips=%zu errors=%zu timed_out=%d cancelled=%d visit_limit=%d match_limit=%d max_file_size=%zu",
            path_to_utf8(root).c_str(), path_to_utf8(workspace).c_str(), current_cwd_utf8().c_str(),
            visited, files_considered, files_read, files_matched, matches.size(), binary_skips,
            oversized_skips, outside_workspace_skips, file_pattern_skips, errors.size(),
            timed_out ? 1 : 0, cancelled ? 1 : 0, visit_limit_reached ? 1 : 0,
            match_limit_reached ? 1 : 0, max_file_size);
        return tool_result_t::ok("Searched file contents.", json{
            {"raw_root", raw_root},
            {"resolved_root", path_to_utf8(root)},
            {"workspace", path_to_utf8(workspace)},
            {"cwd", current_cwd_utf8()},
            {"pattern", pattern},
            {"file_pattern", file_pattern},
            {"matches", matches},
            {"visited", visited},
            {"files_considered", files_considered},
            {"files_read", files_read},
            {"files_matched", files_matched},
            {"matched_count", matches.size()},
            {"binary_skips", binary_skips},
            {"oversized_skips", oversized_skips},
            {"outside_workspace_skips", outside_workspace_skips},
            {"file_pattern_skips", file_pattern_skips},
            {"limit", limit},
            {"max_visited", max_visited},
            {"max_file_size", max_file_size},
            {"timeout_ms", timeout_ms},
            {"timed_out", timed_out},
            {"cancelled", cancelled},
            {"visit_limit_reached", visit_limit_reached},
            {"match_limit_reached", match_limit_reached},
            {"errors", errors}
        });
    }

    long long web_tool_elapsed_ms_since(const std::chrono::steady_clock::time_point& start)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
    }

    bool web_tool_is_loopback_fixture_url(const std::string& url)
    {
        std::string lower = url;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        const size_t scheme = lower.find("://");
        if (scheme == std::string::npos)
            return false;
        const size_t host_start = scheme + 3;
        if (host_start >= lower.size())
            return false;
        std::string host;
        if (lower[host_start] == '[') {
            const size_t host_end = lower.find(']', host_start + 1);
            if (host_end == std::string::npos)
                return false;
            host = lower.substr(host_start, host_end - host_start + 1);
        } else {
            const size_t host_end = lower.find_first_of("/:?#", host_start);
            host = lower.substr(host_start, host_end == std::string::npos ? std::string::npos : host_end - host_start);
        }
        return host == "localhost" || host == "[::1]" || host == "::1" || host.rfind("127.", 0) == 0;
    }

    bool web_tool_diagnostic_mode(const json& params)
    {
        return json_bool_param(params, "diagnostic", false)
            || json_bool_param(params, "diagnostics", false)
            || json_bool_param(params, "include_diagnostics", false);
    }

    json web_tool_navigation_summary(const aida::burp::camoufox::call_result_t& nav)
    {
        json summary;
        summary["ok"] = nav.ok;
        summary["error_length"] = nav.error.size();
        summary["text_length"] = nav.text.size();
        json payload = camoufox_value_json(nav);
        summary["payload_object"] = payload.is_object();
        if (payload.is_object()) {
            if (payload.contains("final_status"))
                summary["final_status"] = payload["final_status"];
            else if (payload.contains("status"))
                summary["final_status"] = payload["status"];
            if (payload.contains("navigation_timed_out"))
                summary["navigation_timed_out"] = payload["navigation_timed_out"];
            const std::string final_url = json_string_field(payload, "final_url");
            const std::string title = json_string_field(payload, "title");
            if (!final_url.empty())
                summary["final_url_length"] = final_url.size();
            if (!title.empty())
                summary["title_length"] = title.size();
            if (payload.contains("response_chain") && payload["response_chain"].is_array())
                summary["response_chain_count"] = payload["response_chain"].size();
        }
        return summary;
    }

    tool_result_t handle_web_search(const json& params)
    {
        const auto handler_start = std::chrono::steady_clock::now();
        diag::log_tagged_fmt("mcp_tools", "handle_web_search entry transport=camoufox");
        if (!params.contains("query") || !params["query"].is_string())
            return error("Provide a search query.");

        const std::string query = trim(params["query"].get<std::string>());
        if (query.empty())
            return error("Provide a non-empty search query.");
        const int max_results = std::clamp(params.value("max_results", 5), 1, 20);
        const int timeout_seconds = std::clamp(params.value("timeout", 15), 1, 60);
        const int timeout_ms = std::clamp(timeout_seconds * 1000 + 15000, 20000, 60000);
        const std::string encoded_query = web_tool_url_encode(query);

        const auto ready_start = std::chrono::steady_clock::now();
        if (!aida::burp::camoufox::ensure_ready()) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty())
                msg = "Camoufox browser is not ready for web_search.";
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_not_ready err=%s ready_ms=%lld total_ms=%lld",
                msg.c_str(),
                web_tool_elapsed_ms_since(ready_start),
                web_tool_elapsed_ms_since(handler_start));
            set_last_web_error(msg);
            return tool_result_t::error(msg);
        }
        const long long ready_ms = web_tool_elapsed_ms_since(ready_start);

        const std::string extract_js = R"JS((() => {
const maxResults = )JS" + std::to_string(max_results) + R"JS(;
const clean = (value) => String(value || '').replace(/\s+/g, ' ').trim();
const absolutize = (href) => { try { return new URL(href || '', location.href).href; } catch (_) { return ''; } };
const unwrapDuckDuckGo = (href) => {
  let url = absolutize(href);
  try {
    const parsed = new URL(url);
    if (parsed.hostname.endsWith('duckduckgo.com') && parsed.pathname.indexOf('/l/') === 0) {
      const target = parsed.searchParams.get('uddg');
      if (target) url = decodeURIComponent(target);
    }
  } catch (_) {}
  return url;
};
const blockedHost = (href) => {
  try {
    const host = new URL(href).hostname.toLowerCase();
    return host === location.hostname.toLowerCase() || host.endsWith('.duckduckgo.com') || host.endsWith('.bing.com') || host.endsWith('.microsoft.com/images');
  } catch (_) { return true; }
};
const resultContainer = (a) => a.closest('.result, .web-result, article, li.b_algo, li, div') || a.parentElement;
const readSnippet = (container, title) => {
  if (!container) return '';
  const selectors = ['.result__snippet', '.result__body', '.b_caption p', '[data-result="snippet"]', 'p', '.snippet'];
  for (const selector of selectors) {
    const node = container.querySelector(selector);
    const text = clean(node && node.innerText);
    if (text && text !== title) return text;
  }
  const text = clean(container.innerText);
  if (!text) return '';
  if (text.indexOf(title) === 0) return clean(text.slice(title.length));
  return text;
};
const anchors = Array.from(document.querySelectorAll('a.result__a, li.b_algo h2 a, article h2 a, [data-testid="result-title-a"], h2 a, a[href]'));
const results = [];
const seen = new Set();
for (const a of anchors) {
  if (results.length >= maxResults) break;
  const title = clean(a.innerText || a.textContent || a.getAttribute('aria-label'));
  let url = unwrapDuckDuckGo(a.getAttribute('href') || a.href || '');
  if (!title || !url || url.indexOf('javascript:') === 0 || url.indexOf('mailto:') === 0 || blockedHost(url)) continue;
  const key = url.replace(/#.*$/, '');
  if (seen.has(key)) continue;
  seen.add(key);
  const container = resultContainer(a);
  let snippet = readSnippet(container, title);
  if (!snippet) snippet = title;
  results.push({ title, snippet, url });
}
return { browser: 'camoufox', engine_url: location.href, page_title: document.title || '', candidates: anchors.length, results };
})())JS";

        struct provider_t { const char* name; std::string url; };
        const provider_t providers[] = {
            {"duckduckgo_html", "https://duckduckgo.com/html/?q=" + encoded_query},
            {"bing", "https://www.bing.com/search?q=" + encoded_query}
        };

        std::string failures;
        for (const auto& provider : providers) {
            const auto provider_start = std::chrono::steady_clock::now();
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error("web_search cancelled by client request.");
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_begin provider=%s timeout_ms=%d query_len=%zu", provider.name, timeout_ms, query.size());
            json nav_args;
            nav_args["url"] = provider.url;
            nav_args["wait_until"] = "domcontentloaded";
            nav_args["collect_response_chain"] = true;
            nav_args["clear_network_capture"] = true;
            nav_args["include_title"] = true;
            const auto nav_start = std::chrono::steady_clock::now();
            auto nav = aida::burp::camoufox::call_tool("navigate", nav_args, timeout_ms);
            const long long nav_ms = web_tool_elapsed_ms_since(nav_start);
            if (!nav.ok) {
                std::string err = nav.error.empty() ? nav.text : nav.error;
                if (err.empty()) err = "navigate failed";
                diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_nav_failed provider=%s nav_ms=%lld err=%s", provider.name, nav_ms, err.c_str());
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": " + err;
                continue;
            }
            const auto eval_start = std::chrono::steady_clock::now();
            auto eval = aida::burp::camoufox::evaluate_js(extract_js, true);
            const long long eval_ms = web_tool_elapsed_ms_since(eval_start);
            if (!eval.ok) {
                std::string err = eval.error.empty() ? eval.text : eval.error;
                if (err.empty()) err = "evaluate_js failed";
                diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_eval_failed provider=%s nav_ms=%lld eval_ms=%lld err=%s", provider.name, nav_ms, eval_ms, err.c_str());
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": " + err;
                continue;
            }
            json payload = camoufox_value_json(eval);
            json results = json::array();
            if (payload.is_object() && payload.contains("results") && payload["results"].is_array())
                results = payload["results"];
            const size_t count = results.is_array() ? results.size() : 0;
            diag::log_tagged_fmt("mcp_tools", "handle_web_search camoufox_provider_result provider=%s results=%zu payload_object=%d final_url_len=%zu title_len=%zu",
                provider.name,
                count,
                payload.is_object() ? 1 : 0,
                json_string_field(payload, "engine_url").size(),
                json_string_field(payload, "page_title").size());
            if (count == 0) {
                if (!failures.empty()) failures += "; ";
                failures += std::string(provider.name) + ": browser returned zero parseable results";
                continue;
            }
            if (results.size() > static_cast<size_t>(max_results))
                results.erase(results.begin() + max_results, results.end());
            json data;
            data["results"] = std::move(results);
            data["transport"] = "camoufox";
            data["browser"] = "camoufox";
            data["provider"] = provider.name;
            data["query"] = query;
            data["final_url"] = json_string_field(payload, "engine_url");
            data["page_title"] = json_string_field(payload, "page_title");
            data["candidate_links"] = payload.is_object() && payload.contains("candidates") ? payload["candidates"] : json(0);
            data["navigation_summary"] = web_tool_navigation_summary(nav);
            data["diagnostics_compact"] = true;
            data["timing_ms"] = {
                {"ready", ready_ms},
                {"navigation", nav_ms},
                {"evaluate", eval_ms},
                {"provider_total", web_tool_elapsed_ms_since(provider_start)},
                {"total", web_tool_elapsed_ms_since(handler_start)}
            };
            diag::log_tagged_fmt("mcp_tools",
                "handle_web_search camoufox_provider_timing provider=%s ready_ms=%lld nav_ms=%lld eval_ms=%lld provider_total_ms=%lld total_ms=%lld results=%zu",
                provider.name,
                ready_ms,
                nav_ms,
                eval_ms,
                web_tool_elapsed_ms_since(provider_start),
                web_tool_elapsed_ms_since(handler_start),
                count);
            return tool_result_t::ok("Found " + std::to_string(data["results"].size()) + " Camoufox browser result(s) for: " + query, data);
        }

        std::string msg = "Camoufox browser web_search returned no results for: " + query;
        if (!failures.empty())
            msg += " (" + failures + ")";
        set_last_web_error(msg);
        return tool_result_t::error(msg);
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
        const auto handler_start = std::chrono::steady_clock::now();
        char trace_id[64] = {};
        _snprintf_s(trace_id, sizeof(trace_id), _TRUNCATE,
            "webfetch-%lu-%llu",
            static_cast<unsigned long>(GetCurrentThreadId()),
            static_cast<unsigned long long>(GetTickCount64()));
        const auto status_entry = aida::burp::camoufox::get_status();
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch entry transport=camoufox trace_id=%s bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu cleanup_pending=%d",
            trace_id,
            static_cast<int>(status_entry.state),
            status_entry.child_pid,
            status_entry.child_alive ? 1 : 0,
            status_entry.browser_open ? 1 : 0,
            status_entry.page_verified ? 1 : 0,
            status_entry.page_count,
            status_entry.active_page_url.size(),
            static_cast<unsigned long long>(status_entry.total_calls),
            static_cast<unsigned long long>(status_entry.total_errors),
            status_entry.cleanup_pending ? 1 : 0);
        if (!params.contains("url") || !params["url"].is_string())
            return error("Missing required parameter: url");

        if (mcp_standalone::current_call_cancelled())
            return error("webfetch cancelled by client request.");

        const std::string url = trim(params["url"].get<std::string>());
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
        timeout_sec = std::clamp(timeout_sec, 1, 120);
        const int timeout_ms = std::clamp(timeout_sec * 1000 + 10000, 15000, 130000);
        const bool local_fixture = web_tool_is_loopback_fixture_url(url);
        const bool diagnostic_mode = web_tool_diagnostic_mode(params);

        const auto ready_start = std::chrono::steady_clock::now();
        if (!aida::burp::camoufox::ensure_ready()) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty())
                msg = "Camoufox browser is not ready for webfetch.";
            const auto status_failed = aida::burp::camoufox::get_status();
            diag::log_tagged_fmt("mcp_tools", "handle_webfetch camoufox_not_ready err=%s ready_ms=%lld total_ms=%lld",
                msg.c_str(),
                web_tool_elapsed_ms_since(ready_start),
                web_tool_elapsed_ms_since(handler_start));
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_not_ready_status trace_id=%s bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu cleanup_pending=%d last_error_len=%zu",
                trace_id,
                static_cast<int>(status_failed.state),
                status_failed.child_pid,
                status_failed.child_alive ? 1 : 0,
                status_failed.browser_open ? 1 : 0,
                status_failed.page_verified ? 1 : 0,
                status_failed.page_count,
                status_failed.active_page_url.size(),
                static_cast<unsigned long long>(status_failed.total_calls),
                static_cast<unsigned long long>(status_failed.total_errors),
                status_failed.cleanup_pending ? 1 : 0,
                status_failed.last_error.size());
            return tool_result_t::error(msg);
        }
        const long long ready_ms = web_tool_elapsed_ms_since(ready_start);
        const auto status_ready = aida::burp::camoufox::get_status();

        const int nav_timeout_ms = local_fixture ? std::min(timeout_ms, 15000) : timeout_ms;
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_ready trace_id=%s ready_ms=%lld bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu cleanup_pending=%d",
            trace_id,
            ready_ms,
            static_cast<int>(status_ready.state),
            status_ready.child_pid,
            status_ready.child_alive ? 1 : 0,
            status_ready.browser_open ? 1 : 0,
            status_ready.page_verified ? 1 : 0,
            status_ready.page_count,
            status_ready.active_page_url.size(),
            status_ready.active_page_title.size(),
            static_cast<unsigned long long>(status_ready.total_calls),
            static_cast<unsigned long long>(status_ready.total_errors),
            static_cast<unsigned long long>(status_ready.last_call_ms),
            static_cast<unsigned long long>(status_ready.last_nav_ms),
            status_ready.cleanup_pending ? 1 : 0);
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_navigate_begin trace_id=%s url_len=%zu format=%s timeout_ms=%d nav_timeout_ms=%d local_fixture=%d diagnostic=%d wait_until=domcontentloaded collect_response_chain=%d clear_network_capture=%d fast_ready=%d",
            trace_id,
            url.size(),
            format.c_str(),
            timeout_ms,
            nav_timeout_ms,
            local_fixture ? 1 : 0,
            diagnostic_mode ? 1 : 0,
            (!local_fixture || diagnostic_mode) ? 1 : 0,
            (!local_fixture || diagnostic_mode) ? 1 : 0,
            (local_fixture && !diagnostic_mode) ? 1 : 0);
        json nav_args;
        nav_args["url"] = url;
        nav_args["wait_until"] = "domcontentloaded";
        nav_args["collect_response_chain"] = !local_fixture || diagnostic_mode;
        nav_args["clear_network_capture"] = !local_fixture || diagnostic_mode;
        nav_args["include_title"] = true;
        nav_args["diagnostic"] = diagnostic_mode;
        nav_args["aida_local_fixture_fast_ready"] = local_fixture && !diagnostic_mode;
        nav_args["aida_trace_id"] = trace_id;
        const auto nav_start = std::chrono::steady_clock::now();
        auto nav = aida::burp::camoufox::call_tool("navigate", nav_args, nav_timeout_ms);
        const long long nav_ms = web_tool_elapsed_ms_since(nav_start);
        const auto status_after_nav = aida::burp::camoufox::get_status();
        json nav_status_payload = camoufox_value_json(nav);
        if (!nav.ok) {
            std::string msg = nav.error.empty() ? nav.text : nav.error;
            if (msg.empty()) msg = "Camoufox navigation failed for webfetch.";
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_navigate_failed trace_id=%s err=%s ready_ms=%lld nav_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu payload_object=%d final_status_present=%d response_chain_count=%zu last_error_len=%zu",
                trace_id,
                msg.c_str(),
                ready_ms,
                nav_ms,
                web_tool_elapsed_ms_since(handler_start),
                local_fixture ? 1 : 0,
                static_cast<int>(status_after_nav.state),
                status_after_nav.child_pid,
                status_after_nav.child_alive ? 1 : 0,
                status_after_nav.browser_open ? 1 : 0,
                status_after_nav.page_verified ? 1 : 0,
                status_after_nav.page_count,
                status_after_nav.active_page_url.size(),
                status_after_nav.active_page_title.size(),
                static_cast<unsigned long long>(status_after_nav.total_calls),
                static_cast<unsigned long long>(status_after_nav.total_errors),
                static_cast<unsigned long long>(status_after_nav.last_call_ms),
                static_cast<unsigned long long>(status_after_nav.last_nav_ms),
                nav_status_payload.is_object() ? 1 : 0,
                nav_status_payload.is_object() && (nav_status_payload.contains("final_status") || nav_status_payload.contains("status")) ? 1 : 0,
                nav_status_payload.is_object() && nav_status_payload.contains("response_chain") && nav_status_payload["response_chain"].is_array() ? nav_status_payload["response_chain"].size() : 0,
                status_after_nav.last_error.size());
            return tool_result_t::error(msg);
        }
        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_navigate_ok trace_id=%s ready_ms=%lld nav_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu payload_object=%d final_status_present=%d response_chain_count=%zu",
            trace_id,
            ready_ms,
            nav_ms,
            web_tool_elapsed_ms_since(handler_start),
            local_fixture ? 1 : 0,
            static_cast<int>(status_after_nav.state),
            status_after_nav.child_pid,
            status_after_nav.child_alive ? 1 : 0,
            status_after_nav.browser_open ? 1 : 0,
            status_after_nav.page_verified ? 1 : 0,
            status_after_nav.page_count,
            status_after_nav.active_page_url.size(),
            status_after_nav.active_page_title.size(),
            static_cast<unsigned long long>(status_after_nav.total_calls),
            static_cast<unsigned long long>(status_after_nav.total_errors),
            static_cast<unsigned long long>(status_after_nav.last_call_ms),
            static_cast<unsigned long long>(status_after_nav.last_nav_ms),
            nav_status_payload.is_object() ? 1 : 0,
            nav_status_payload.is_object() && (nav_status_payload.contains("final_status") || nav_status_payload.contains("status")) ? 1 : 0,
            nav_status_payload.is_object() && nav_status_payload.contains("response_chain") && nav_status_payload["response_chain"].is_array() ? nav_status_payload["response_chain"].size() : 0);

        const size_t max_browser_chars = 5u * 1024u * 1024u;
        const std::string extract_js = R"JS((() => {
const maxChars = )JS" + std::to_string(max_browser_chars) + R"JS(;
const root = document.documentElement;
const body = document.body;
let html = root ? root.outerHTML : '';
let text = body ? body.innerText : (root ? root.textContent : '');
let htmlTruncated = false;
let textTruncated = false;
if (html.length > maxChars) { html = html.slice(0, maxChars); htmlTruncated = true; }
if (text.length > maxChars) { text = text.slice(0, maxChars); textTruncated = true; }
const fixtureMarker = !!document.querySelector('[data-aida-fixture], [data-aida-fixture-ready], #aida-mcp-fixture, #aida-webfetch-fixture, [data-testid="aida-webfetch-fixture"]')
  || /AIDA_MCP_FIXTURE|AIDA_WEBFETCH_FIXTURE|aida-webfetch-fixture/i.test(text || '')
  || /AIDA_MCP_FIXTURE|AIDA_WEBFETCH_FIXTURE|aida-webfetch-fixture/i.test(html || '');
return {
  browser: 'camoufox',
  url: location.href,
  title: document.title || '',
  content_type: document.contentType || '',
  charset: document.characterSet || '',
  ready_state: document.readyState || '',
  html,
  text,
  body_length: text.length,
  html_length: html.length,
  fixture_marker: fixtureMarker,
  html_truncated: htmlTruncated,
  text_truncated: textTruncated
};
})())JS";

        const auto extract_start = std::chrono::steady_clock::now();
        auto extracted = aida::burp::camoufox::evaluate_js(extract_js, true);
        const long long extract_ms = web_tool_elapsed_ms_since(extract_start);
        const auto status_after_extract = aida::burp::camoufox::get_status();
        if (!extracted.ok) {
            std::string msg = extracted.error.empty() ? extracted.text : extracted.error;
            if (msg.empty()) msg = "Camoufox page extraction failed for webfetch.";
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_extract_failed trace_id=%s err=%s ready_ms=%lld nav_ms=%lld extract_ms=%lld total_ms=%lld local_fixture=%d bridge_state=%d child_pid=%u child_alive=%d browser_open=%d page_verified=%d page_count=%u active_page_len=%zu active_title_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu",
                trace_id,
                msg.c_str(),
                ready_ms,
                nav_ms,
                extract_ms,
                web_tool_elapsed_ms_since(handler_start),
                local_fixture ? 1 : 0,
                static_cast<int>(status_after_extract.state),
                status_after_extract.child_pid,
                status_after_extract.child_alive ? 1 : 0,
                status_after_extract.browser_open ? 1 : 0,
                status_after_extract.page_verified ? 1 : 0,
                status_after_extract.page_count,
                status_after_extract.active_page_url.size(),
                status_after_extract.active_page_title.size(),
                static_cast<unsigned long long>(status_after_extract.total_calls),
                static_cast<unsigned long long>(status_after_extract.total_errors),
                static_cast<unsigned long long>(status_after_extract.last_call_ms),
                static_cast<unsigned long long>(status_after_extract.last_nav_ms));
            return tool_result_t::error(msg);
        }

        json payload = camoufox_value_json(extracted);
        if (!payload.is_object()) {
            diag::log_tagged_fmt("mcp_tools",
                "handle_webfetch camoufox_extract_unexpected payload_object=0 ready_ms=%lld nav_ms=%lld extract_ms=%lld total_ms=%lld",
                ready_ms,
                nav_ms,
                extract_ms,
                web_tool_elapsed_ms_since(handler_start));
            return tool_result_t::error("Camoufox page extraction returned an unexpected payload.");
        }

        const auto convert_start = std::chrono::steady_clock::now();
        std::string html = json_string_field(payload, "html");
        std::string page_text = json_string_field(payload, "text");
        const std::string final_url = json_string_field(payload, "url");
        const std::string title = json_string_field(payload, "title");
        const std::string content_type = json_string_field(payload, "content_type");
        if (html.empty() && page_text.empty())
            return tool_result_t::error("Camoufox webfetch extracted an empty page.");

        std::string output;
        if (format == "html") {
            output = std::move(html);
        } else if (format == "text") {
            output = std::move(page_text);
        } else {
            output = html.empty() ? page_text : webfetch_html_to_markdown(html);
        }

        constexpr size_t MAX_OUTPUT_BYTES = 200000u;
        bool truncated = false;
        if (output.size() > MAX_OUTPUT_BYTES) {
            output.resize(MAX_OUTPUT_BYTES);
            truncated = true;
        }
        const long long convert_ms = web_tool_elapsed_ms_since(convert_start);

        json nav_payload = nav_status_payload;
        json data;
        data["trace_id"] = trace_id;
        data["url"] = final_url.empty() ? url : final_url;
        data["requested_url"] = url;
        data["title"] = title;
        data["format"] = format;
        data["content_type"] = content_type;
        data["charset"] = json_string_field(payload, "charset");
        data["ready_state"] = json_string_field(payload, "ready_state");
        data["bytes"] = static_cast<int64_t>(output.size());
        data["truncated"] = truncated;
        data["transport"] = "camoufox";
        data["browser"] = "camoufox";
        data["status_source"] = "camoufox_response_chain";
        data["status"] = 0;
        if (nav_payload.is_object()) {
            if (nav_payload.contains("final_status") && nav_payload["final_status"].is_number_integer())
                data["status"] = nav_payload["final_status"];
            else if (nav_payload.contains("status") && nav_payload["status"].is_number_integer())
                data["status"] = nav_payload["status"];
            else
                data["status_source"] = "not_reported";
            if ((diagnostic_mode || !local_fixture) && nav_payload.contains("response_chain"))
                data["response_chain"] = nav_payload["response_chain"];
            else if (nav_payload.contains("response_chain") && nav_payload["response_chain"].is_array())
                data["response_chain_count"] = nav_payload["response_chain"].size();
        } else {
            data["status_source"] = "not_reported";
        }
        data["local_fixture"] = local_fixture;
        data["fixture_marker"] = payload.contains("fixture_marker") && payload["fixture_marker"].is_boolean() ? payload["fixture_marker"] : json(false);
        data["diagnostics_compact"] = local_fixture && !diagnostic_mode;
        data["navigation_summary"] = web_tool_navigation_summary(nav);
        data["timing_ms"] = {
            {"ready", ready_ms},
            {"navigation", nav_ms},
            {"extract", extract_ms},
            {"convert", convert_ms},
            {"total", web_tool_elapsed_ms_since(handler_start)}
        };
        data["camoufox_status"] = {
            {"bridge_state", static_cast<int>(status_after_extract.state)},
            {"child_pid", status_after_extract.child_pid},
            {"child_alive", status_after_extract.child_alive},
            {"browser_open", status_after_extract.browser_open},
            {"page_verified", status_after_extract.page_verified},
            {"page_count", status_after_extract.page_count},
            {"active_page_url_len", status_after_extract.active_page_url.size()},
            {"active_page_title_len", status_after_extract.active_page_title.size()},
            {"total_calls", status_after_extract.total_calls},
            {"total_errors", status_after_extract.total_errors},
            {"last_call_ms", status_after_extract.last_call_ms},
            {"last_nav_ms", status_after_extract.last_nav_ms},
            {"cleanup_pending", status_after_extract.cleanup_pending}
        };
        data["html_truncated_in_browser"] = payload.contains("html_truncated") && payload["html_truncated"].is_boolean() ? payload["html_truncated"] : json(false);
        data["text_truncated_in_browser"] = payload.contains("text_truncated") && payload["text_truncated"].is_boolean() ? payload["text_truncated"] : json(false);

        diag::log_tagged_fmt("mcp_tools",
            "handle_webfetch camoufox_ok trace_id=%s final_url_len=%zu title_len=%zu format=%s bytes=%zu status=%lld status_source=%s truncated=%d local_fixture=%d fixture_marker=%d ready_ms=%lld nav_ms=%lld extract_ms=%lld convert_ms=%lld total_ms=%lld bridge_state=%d child_pid=%u child_alive=%d page_count=%u active_page_len=%zu total_calls=%llu total_errors=%llu last_call_ms=%llu last_nav_ms=%llu",
            trace_id,
            data["url"].is_string() ? data["url"].get<std::string>().size() : 0,
            title.size(),
            format.c_str(),
            output.size(),
            data["status"].is_number_integer() ? static_cast<long long>(data["status"].get<int64_t>()) : 0LL,
            json_string_field(data, "status_source").c_str(),
            truncated ? 1 : 0,
            local_fixture ? 1 : 0,
            data["fixture_marker"].is_boolean() && data["fixture_marker"].get<bool>() ? 1 : 0,
            ready_ms,
            nav_ms,
            extract_ms,
            convert_ms,
            web_tool_elapsed_ms_since(handler_start),
            static_cast<int>(status_after_extract.state),
            status_after_extract.child_pid,
            status_after_extract.child_alive ? 1 : 0,
            status_after_extract.page_count,
            status_after_extract.active_page_url.size(),
            static_cast<unsigned long long>(status_after_extract.total_calls),
            static_cast<unsigned long long>(status_after_extract.total_errors),
            static_cast<unsigned long long>(status_after_extract.last_call_ms),
            static_cast<unsigned long long>(status_after_extract.last_nav_ms));

        std::string text;
        text.reserve(output.size() + 160);
        text += "Fetched via Camoufox ";
        text += final_url.empty() ? url : final_url;
        text += " (";
        text += content_type.empty() ? std::string("browser-rendered") : content_type;
        text += ")\n\n";
        text += output;
        if (truncated)
            text += "\n\n[truncated to " + std::to_string(MAX_OUTPUT_BYTES) + " bytes]";

        return tool_result_t::ok(text, data);
    }

}

namespace mcp_standalone
{
    namespace
    {
        namespace python_compat = aida::standalone::mcp::compat;

        std::optional<fs::path> standalone_package_root()
        {
            std::vector<wchar_t> path(32768U, L'\0');
            const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (length == 0 || length >= path.size())
                return std::nullopt;
            path.resize(length);
            const fs::path executable(path);
            if (executable.parent_path().empty())
                return std::nullopt;
            return executable.parent_path();
        }

        std::optional<std::uint64_t> json_nonnegative_u64(const json& value)
        {
            if (value.is_number_unsigned())
                return value.get<std::uint64_t>();
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0)
                    return static_cast<std::uint64_t>(signed_value);
            }
            return std::nullopt;
        }

        python_compat::python_workspace_response_t isolated_python_workspace_error(
            std::string code, std::string message)
        {
            python_compat::python_workspace_response_t response;
            response.error_code = std::move(code);
            response.error_message = std::move(message);
            return response;
        }

        python_compat::python_workspace_response_t isolated_python_workspace_api(
            const python_compat::python_workspace_query_t& query,
            const workspace_request_context_t& context)
        {
            if (context.cancellation_requested())
                return isolated_python_workspace_error("CANCELLED", "workspace request was cancelled");
            if (!context.workspace || context.kind != aida::analysis::target_kind_t::static_file)
                return isolated_python_workspace_error("LIVE_TARGET_DENIED", "isolated Python worker requires a static workspace target");
            if (!query.arguments.is_object())
                return isolated_python_workspace_error("INVALID_ARGUMENTS", "workspace API arguments must be an object");
            tool_result_t tool_result;
            if (query.operation == "read_bytes") {
                const auto offset = query.arguments.find("offset");
                const auto size = query.arguments.find("size");
                if (query.arguments.size() != 2U || offset == query.arguments.end() || size == query.arguments.end())
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "read_bytes requires offset and size only");
                const auto offset_value = json_nonnegative_u64(*offset);
                const auto size_value = json_nonnegative_u64(*size);
                if (!offset_value || !size_value || *size_value == 0 || *size_value > 65536U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "read_bytes arguments exceed the approved limit");
                tool_result = ida_compat::tool_get_bytes(
                    json{{"address", "file:" + std::to_string(*offset_value)}, {"size", *size_value}}, context);
            } else if (query.operation == "find") {
                const auto text = query.arguments.find("query");
                const auto limit = query.arguments.find("limit");
                if ((query.arguments.size() != 1U && query.arguments.size() != 2U) || text == query.arguments.end() ||
                    !text->is_string() || text->get<std::string>().empty() || text->get<std::string>().size() > 4096U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "find requires a bounded query string");
                std::uint64_t limit_value = 100;
                if (limit != query.arguments.end()) {
                    const auto parsed = json_nonnegative_u64(*limit);
                    if (!parsed || *parsed == 0 || *parsed > 1000U)
                        return isolated_python_workspace_error("INVALID_ARGUMENTS", "find limit exceeds the approved limit");
                    limit_value = *parsed;
                }
                tool_result = ida_compat::tool_find(
                    json{{"query", text->get<std::string>()}, {"limit", limit_value}}, context);
            } else if (query.operation == "list_functions") {
                const auto offset = query.arguments.find("offset");
                const auto limit = query.arguments.find("limit");
                if ((query.arguments.size() != 0U && query.arguments.size() != 1U && query.arguments.size() != 2U) ||
                    (offset != query.arguments.end() && !json_nonnegative_u64(*offset)) ||
                    (limit != query.arguments.end() && !json_nonnegative_u64(*limit)))
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "list_functions arguments are invalid");
                const std::uint64_t offset_value = offset == query.arguments.end()
                    ? 0U : *json_nonnegative_u64(*offset);
                const std::uint64_t limit_value = limit == query.arguments.end()
                    ? 100U : *json_nonnegative_u64(*limit);
                if (limit_value == 0 || limit_value > 1000U)
                    return isolated_python_workspace_error("INVALID_ARGUMENTS", "list_functions limit exceeds the approved limit");
                tool_result = ida_compat::tool_list_funcs(
                    json{{"offset", offset_value}, {"limit", limit_value}}, context);
            } else {
                return isolated_python_workspace_error("WORKSPACE_OPERATION_DENIED", "workspace operation is not approved");
            }
            if (!tool_result.success)
                return isolated_python_workspace_error(
                    tool_result.error_code.empty() ? "WORKSPACE_API_REJECTED" : tool_result.error_code,
                    tool_result.text.empty() ? "approved workspace API rejected request" : tool_result.text);
            python_compat::python_workspace_response_t response;
            response.success = true;
            response.data = std::move(tool_result.data);
            return response;
        }

        json isolated_python_workspace_metadata(const workspace_request_context_t& context)
        {
            return {
                {"binary_id", context.binary_id.to_hex()},
                {"binary_name", context.workspace->identity().bin_name()},
                {"analysis_revision", context.analysis_revision},
                {"overlay_revision", context.overlay_revision},
                {"target_kind", "static_file"}
            };
        }

        namespace wave_c_compat = aida::standalone::mcp::compat;
        namespace wave_c_handlers = aida::standalone::mcp::compat::handlers;
        namespace wave_c_integration = aida::standalone::mcp::integration;
        namespace wave_c_protocol = aida::standalone::mcp::protocol;

        template <typename names_t>
        bool wave_c_name_in(const names_t& names, std::string_view name)
        {
            return std::find(names.begin(), names.end(), name) != names.end();
        }

        using wave_c_debugger_identity_result_t = wave_c_compat::debugger_adapter_result_t<
            wave_c_compat::debugger_target_identity_t>;
        using wave_c_debugger_response_result_t = wave_c_compat::debugger_adapter_result_t<
            wave_c_compat::debugger_adapter_response_t>;
        using wave_c_live_snapshot_result_t = wave_c_compat::adapter_result_t<
            wave_c_compat::bounded_live_snapshot_t>;
        using wave_c_survey_lease_result_t = wave_c_compat::adapter_result_t<
            wave_c_handlers::survey_generation_lease_t>;
        using wave_c_python_lease_result_t = wave_c_compat::adapter_result_t<
            wave_c_handlers::python_target_lease_t>;

        wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>
        wave_c_adapter_result(tool_result_t result)
        {
            if (!result.success) {
                return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                    {wave_c_compat::adapter_error_code_t::backend_rejected,
                     "workspace_backend_rejected", 0, 0});
            }
            wave_c_compat::adapter_response_t response;
            response.payload = std::move(result.data).dump();
            return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::success(
                std::move(response));
        }

        wave_c_protocol::mcp_result_t wave_c_protocol_result(
            tool_result_t result,
            const json& metadata = json::object())
        {
            if (!result.success) {
                json details = result.error_details.is_object()
                    ? result.error_details : json::object();
                if (!result.error_code.empty())
                    details["backend_error_code"] = result.error_code;
                return wave_c_protocol::mcp_result_t::failure(
                    wave_c_protocol::result_error_code_t::handler_failed,
                    result.text.empty() ? "Workspace backend rejected the request." : result.text,
                    details, metadata);
            }
            return wave_c_protocol::mcp_result_t::success(
                result.text.empty() ? "Tool completed." : result.text,
                std::move(result.data), metadata);
        }

        std::optional<std::uint64_t> wave_c_address_value(const json& value)
        {
            if (value.is_number_unsigned())
                return value.get<std::uint64_t>();
            if (value.is_number_integer()) {
                const auto signed_value = value.get<std::int64_t>();
                if (signed_value >= 0)
                    return static_cast<std::uint64_t>(signed_value);
                return std::nullopt;
            }
            if (!value.is_string())
                return std::nullopt;
            std::uint64_t parsed = 0;
            return parse_addr(value.get_ref<const std::string&>(), parsed)
                ? std::optional<std::uint64_t>(parsed) : std::nullopt;
        }

        std::uint64_t wave_c_workspace_generation(
            const workspace_request_context_t& context) noexcept
        {
            return (std::max)(std::uint64_t{1}, context.workspace->generation());
        }

        std::optional<std::chrono::steady_clock::time_point> wave_c_deadline(
            const workspace_request_context_t& context) noexcept
        {
            if (context.deadline_ms == 0)
                return std::nullopt;
            const auto steady_now = std::chrono::steady_clock::now();
            const auto tick_now = static_cast<std::uint64_t>(GetTickCount64());
            if (context.deadline_ms <= tick_now)
                return steady_now;
            return steady_now + std::chrono::milliseconds(context.deadline_ms - tick_now);
        }

        wave_c_compat::target_selector_t wave_c_target_selector(
            const workspace_request_context_t& context)
        {
            wave_c_compat::target_selector_t selector;
            selector.pid = context.pid;
            selector.bin_name = context.workspace->identity().bin_name();
            return selector;
        }

        bool wave_c_adapter_symbol_matches(std::string_view name,
                                           std::string_view adapter_symbol)
        {
            if (name == "py_exec_file")
                return adapter_symbol ==
                    "aida::standalone::mcp::compat::python_worker_host_t::execute";
            return adapter_symbol ==
                "aida::standalone::mcp::compat::adapters::" + std::string(name);
        }

        wave_c_compat::target_record_t wave_c_target_record(
            const workspace_request_context_t& context)
        {
            wave_c_compat::target_record_t record;
            record.target_id = static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(context.workspace.get()));
            if (record.target_id == 0)
                record.target_id = 1;
            record.pid = context.pid.value_or(1U);
            record.bin_name = context.workspace->identity().bin_name();
            record.generation = wave_c_workspace_generation(context);
            record.attach_generation = (std::max)(std::uint64_t{1}, context.analysis_revision);
            record.process_creation_identity = static_cast<std::uint64_t>(
                aida::analysis::binary_id_hash_t{}(context.binary_id));
            if (record.process_creation_identity == 0)
                record.process_creation_identity = record.target_id;
            record.live = context.kind == aida::analysis::target_kind_t::live_snapshot;
            if (const auto& process = context.workspace->identity().process()) {
                record.pid = process->pid;
                record.process_creation_identity = process->creation_time_100ns;
            }
            if (record.live) {
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                if (provider) {
                    const auto& metadata = provider->metadata();
                    record.live_capture_base = metadata.capture_address;
                    record.live_capture_size = metadata.capture_size;
                    record.live_snapshot_permitted = metadata.capture_size != 0 &&
                        provider->validate_current_identity().has_value();
                    record.live_snapshot_maximum_bytes = record.live_snapshot_permitted
                        ? (std::min)(metadata.capture_size,
                            wave_c_compat::live_routing_limits_t{}
                                .maximum_snapshot_bytes)
                        : 0;
                    record.pid = metadata.process.pid;
                    record.process_creation_identity = metadata.process.creation_time_100ns;
                }
            }
            return record;
        }

        class wave_c_signature_source_t final
            : public wave_c_handlers::signature_source_t {
        public:
            explicit wave_c_signature_source_t(const workspace_request_context_t& context)
                : context_(context), snapshot_(context.workspace->snapshot()),
                  image_(context.workspace->normalized_image()) {}

            std::optional<std::uint64_t> resolve_address(
                std::string_view query) const override
            {
                std::uint64_t parsed = 0;
                if (parse_addr(std::string(query), parsed))
                    return normalize_rva(parsed);
                if (!snapshot_)
                    return std::nullopt;
                const auto found = std::find_if(
                    snapshot_->symbols.begin(), snapshot_->symbols.end(),
                    [query](const auto& symbol) { return symbol.name == query; });
                return found == snapshot_->symbols.end()
                    ? std::nullopt
                    : std::optional<std::uint64_t>(found->address.value);
            }

            std::optional<wave_c_handlers::signature_instruction_t> instruction_at(
                std::uint64_t address) const override
            {
                if (!snapshot_)
                    return std::nullopt;
                address = normalize_rva(address);
                const auto found = std::find_if(
                    snapshot_->instructions.begin(), snapshot_->instructions.end(),
                    [address](const auto& instruction) {
                        return instruction.address.value == address;
                    });
                if (found == snapshot_->instructions.end() || found->length == 0)
                    return std::nullopt;
                wave_c_handlers::signature_instruction_t result;
                result.address = address;
                result.architecture = signature_architecture();
                if (!read_bytes(address, found->length, result.bytes))
                    return std::nullopt;
                result.stable_mask.assign(result.bytes.size(), 0xffU);
                apply_operand_stability_mask(result);
                return result;
            }

            std::optional<wave_c_handlers::signature_function_t> function_containing(
                std::uint64_t address) const override
            {
                if (!snapshot_)
                    return std::nullopt;
                address = normalize_rva(address);
                const auto found = std::find_if(
                    snapshot_->functions.begin(), snapshot_->functions.end(),
                    [address](const auto& function) {
                        return function.start.value <= address && address < function.end.value;
                    });
                if (found == snapshot_->functions.end())
                    return std::nullopt;
                wave_c_handlers::signature_function_t result;
                result.start = found->start.value;
                result.end = found->end.value;
                if (found->symbol_id) {
                    const auto symbol = std::find_if(
                        snapshot_->symbols.begin(), snapshot_->symbols.end(),
                        [id = *found->symbol_id](const auto& value) { return value.id == id; });
                    if (symbol != snapshot_->symbols.end())
                        result.name = symbol->name;
                }
                if (result.name.empty())
                    result.name = "sub_" + hex_addr(found->start.value).substr(2);
                return result;
            }

            std::vector<wave_c_handlers::signature_xref_t> xrefs_to(
                std::uint64_t address) const override
            {
                std::vector<wave_c_handlers::signature_xref_t> result;
                if (!snapshot_)
                    return result;
                address = normalize_rva(address);
                for (const auto& xref : snapshot_->xrefs) {
                    if (xref.target.value != address)
                        continue;
                    result.push_back({
                        xref.source.value,
                        xref.kind == aida::analysis::xref_kind_t::code ||
                            xref.kind == aida::analysis::xref_kind_t::call});
                }
                std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
                    return lhs.from < rhs.from;
                });
                return result;
            }

            bool read_bytes(std::uint64_t address, std::size_t size,
                            std::vector<std::uint8_t>& bytes) const override
            {
                if (!image_ || size == 0)
                    return false;
                const auto offset = file_offset_for(normalize_rva(address), size);
                if (!offset)
                    return false;
                const auto read = context_.workspace->provider().read_vector(
                    *offset, size, size);
                if (!read)
                    return false;
                bytes = read.value();
                return bytes.size() == size;
            }

            wave_c_handlers::signature_match_result_t find_matches(
                const std::vector<std::uint8_t>& bytes,
                const std::vector<std::uint8_t>& stable_mask,
                std::size_t maximum_results,
                const wave_c_protocol::cancellation_token_t& cancellation) const override
            {
                wave_c_handlers::signature_match_result_t result;
                if (!snapshot_ || bytes.empty() || bytes.size() != stable_mask.size() ||
                    maximum_results == 0)
                    return result;
                result.exhausted = false;
                for (const auto& instruction : snapshot_->instructions) {
                    if (cancellation.cancelled()) {
                        result.exhausted = true;
                        result.error = "cancelled";
                        return result;
                    }
                    std::vector<std::uint8_t> candidate;
                    if (!read_bytes(instruction.address.value, bytes.size(), candidate))
                        continue;
                    bool equal = true;
                    for (std::size_t index = 0; index < bytes.size(); ++index) {
                        if ((candidate[index] & stable_mask[index]) !=
                            (bytes[index] & stable_mask[index])) {
                            equal = false;
                            break;
                        }
                    }
                    if (!equal)
                        continue;
                    result.addresses.push_back(instruction.address.value);
                    if (result.addresses.size() >= maximum_results) {
                        result.exhausted = true;
                        break;
                    }
                }
                return result;
            }

        private:
            static void clear_mask_range(
                std::vector<std::uint8_t>& mask,
                std::uint8_t offset,
                std::uint8_t bit_size) noexcept
            {
                const std::size_t begin = offset;
                const std::size_t count = bit_size / 8U;
                if (count == 0 || begin > mask.size() || count > mask.size() - begin)
                    return;
                std::fill(mask.begin() + begin, mask.begin() + begin + count, 0U);
            }

            static bool has_dynamic_x86_operand(
                const ZydisDecodedInstruction& instruction,
                const ZydisDecodedOperand* operands) noexcept
            {
                for (std::size_t index = 0; index < instruction.operand_count; ++index) {
                    const auto& operand = operands[index];
                    if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        (operand.imm.is_relative || instruction.raw.imm[0].size >= 32U))
                        return true;
                    if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        (operand.mem.base == ZYDIS_REGISTER_RIP ||
                         (operand.mem.disp.has_displacement != ZYAN_FALSE &&
                          instruction.raw.disp.size >= 32U)))
                        return true;
                }
                return false;
            }

            static void apply_operand_stability_mask(
                wave_c_handlers::signature_instruction_t& result) noexcept
            {
                if (result.architecture != wave_c_handlers::signature_architecture_t::x86 &&
                    result.architecture != wave_c_handlers::signature_architecture_t::x64)
                    return;
                ZydisDecoder decoder;
                const bool x64 = result.architecture ==
                    wave_c_handlers::signature_architecture_t::x64;
                if (!ZYAN_SUCCESS(ZydisDecoderInit(
                        &decoder,
                        x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                        x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32)))
                    return;
                ZydisDecodedInstruction instruction{};
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                        &decoder, result.bytes.data(), result.bytes.size(),
                        &instruction, operands)) ||
                    instruction.length != result.bytes.size() ||
                    !has_dynamic_x86_operand(instruction, operands))
                    return;
                clear_mask_range(
                    result.stable_mask, instruction.raw.disp.offset,
                    instruction.raw.disp.size);
                for (const auto& immediate : instruction.raw.imm)
                    clear_mask_range(
                        result.stable_mask, immediate.offset, immediate.size);
            }

            std::uint64_t normalize_rva(std::uint64_t address) const noexcept
            {
                return image_ && image_->image_base != 0 && address >= image_->image_base
                    ? address - image_->image_base : address;
            }

            std::optional<std::uint64_t> file_offset_for(
                std::uint64_t rva, std::uint64_t size) const noexcept
            {
                if (!image_ || size > image_->provider_size)
                    return std::nullopt;
                if (rva <= image_->header_size && size <= image_->header_size - rva)
                    return rva;
                for (const auto& section : image_->sections) {
                    if (rva < section.virtual_address)
                        continue;
                    const std::uint64_t delta = rva - section.virtual_address;
                    if (delta <= section.file_size && size <= section.file_size - delta &&
                        section.file_offset <= image_->provider_size &&
                        delta <= image_->provider_size - section.file_offset &&
                        size <= image_->provider_size - section.file_offset - delta)
                        return section.file_offset + delta;
                }
                for (const auto& segment : image_->segments) {
                    if (rva < segment.virtual_address)
                        continue;
                    const std::uint64_t delta = rva - segment.virtual_address;
                    if (delta <= segment.file_size && size <= segment.file_size - delta &&
                        segment.file_offset <= image_->provider_size &&
                        delta <= image_->provider_size - segment.file_offset &&
                        size <= image_->provider_size - segment.file_offset - delta)
                        return segment.file_offset + delta;
                }
                return std::nullopt;
            }

            wave_c_handlers::signature_architecture_t signature_architecture() const noexcept
            {
                if (!image_)
                    return wave_c_handlers::signature_architecture_t::unknown;
                using architecture_t = aida::analysis::architecture_id_t;
                switch (image_->architecture) {
                case architecture_t::x86:
                    return wave_c_handlers::signature_architecture_t::x86;
                case architecture_t::x86_64:
                    return wave_c_handlers::signature_architecture_t::x64;
                case architecture_t::arm:
                    return wave_c_handlers::signature_architecture_t::arm;
                case architecture_t::aarch64:
                case architecture_t::arm64ec:
                    return wave_c_handlers::signature_architecture_t::aarch64;
                case architecture_t::mips:
                case architecture_t::mips64:
                    return wave_c_handlers::signature_architecture_t::mips;
                case architecture_t::ppc:
                case architecture_t::ppc64:
                    return wave_c_handlers::signature_architecture_t::ppc;
                case architecture_t::riscv:
                case architecture_t::riscv32:
                    return wave_c_handlers::signature_architecture_t::riscv;
                case architecture_t::jvm_bytecode:
                    return wave_c_handlers::signature_architecture_t::jvm;
                default:
                    return wave_c_handlers::signature_architecture_t::unknown;
                }
            }

            const workspace_request_context_t& context_;
            std::shared_ptr<const aida::analysis::analysis_snapshot_t> snapshot_;
            std::shared_ptr<const aida::analysis::workspace_image_t> image_;
        };

        class wave_c_debugger_adapter_t final
            : public wave_c_compat::debugger_adapter_t {
        public:
            explicit wave_c_debugger_adapter_t(const workspace_request_context_t& context)
                : context_(context), target_(wave_c_target_record(context)) {}

            wave_c_compat::debugger_adapter_result_t<
                wave_c_compat::debugger_target_identity_t> identity(
                const wave_c_protocol::cancellation_token_t& cancellation,
                std::chrono::steady_clock::time_point deadline) override
            {
                if (cancellation.cancelled())
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= deadline)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                if (!target_.live)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::unavailable);
                const std::uint32_t attached_pid = driver_bridge::attached_pid();
                if (attached_pid == 0)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::attach_lost,
                        target_.pid, attached_pid);
                if (attached_pid != target_.pid)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::pid_reused,
                        target_.pid, attached_pid);
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context_.workspace->provider_handle());
                if (!provider)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::unavailable);
                const auto current_identity = provider->validate_current_identity();
                if (!current_identity)
                    return wave_c_debugger_identity_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::pid_reused);
                wave_c_compat::debugger_target_identity_t result;
                result.pid = target_.pid;
                result.process_creation_identity = target_.process_creation_identity;
                result.attach_generation = target_.attach_generation;
                result.module_base = target_.live_capture_base;
                result.module_size = target_.live_capture_size;
                result.attached = result.pid != 0 && result.module_size != 0;
                return wave_c_debugger_identity_result_t::success(std::move(result));
            }

            wave_c_compat::debugger_adapter_result_t<
                wave_c_compat::debugger_adapter_response_t> execute(
                const wave_c_compat::debugger_adapter_request_t& request) override
            {
                if (request.cancellation.cancelled())
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::cancelled);
                if (std::chrono::steady_clock::now() >= request.deadline)
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::deadline_exceeded);
                if (driver_bridge::attached_pid() != request.expected_identity.pid)
                    return wave_c_debugger_response_result_t::failure(
                        wave_c_compat::debugger_adapter_error_code_t::attach_lost,
                        request.expected_identity.pid, driver_bridge::attached_pid());
                json structured;
                if (request.tool_name == "dbg_add_bp" ||
                    request.tool_name == "dbg_delete_bp") {
                    structured = breakpoint_addresses(request);
                } else if (request.tool_name == "dbg_bps") {
                    structured = breakpoint_inventory();
                } else if (request.tool_name == "dbg_toggle_bp") {
                    structured = toggle_breakpoints(request);
                } else if (request.tool_name == "dbg_set_bp_condition") {
                    structured = set_breakpoint_conditions(request);
                } else if (request.tool_name == "dbg_gpregs" ||
                           request.tool_name == "dbg_regs" ||
                           request.tool_name == "dbg_regs_named" ||
                           request.tool_name == "dbg_regs_named_remote") {
                    const auto registers = current_registers(request);
                    if (!registers)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *registers;
                } else if (request.tool_name == "dbg_gpregs_remote" ||
                           request.tool_name == "dbg_regs_remote") {
                    structured = remote_registers(request);
                } else if (request.tool_name == "dbg_regs_all") {
                    const auto registers = all_registers(request);
                    if (!registers)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *registers;
                } else if (request.tool_name == "dbg_stacktrace") {
                    structured = stack_trace();
                } else if (request.tool_name == "dbg_read") {
                    structured = read_regions(request);
                } else if (request.tool_name == "dbg_write") {
                    structured = write_regions(request);
                } else {
                    const auto control = execute_control(request);
                    if (!control)
                        return wave_c_debugger_response_result_t::failure(
                            wave_c_compat::debugger_adapter_error_code_t::request_rejected);
                    structured = *control;
                }
                wave_c_compat::debugger_adapter_response_t response;
                response.structured = std::move(structured);
                return wave_c_debugger_response_result_t::success(std::move(response));
            }

        private:
            static json scalar_or_array(const json& value)
            {
                if (value.is_array())
                    return value;
                return json::array({value});
            }

            static std::string uppercase_trimmed(std::string value)
            {
                const auto first = value.find_first_not_of(" \t\r\n");
                if (first == std::string::npos)
                    return {};
                const auto last = value.find_last_not_of(" \t\r\n");
                value = value.substr(first, last - first + 1);
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::toupper(ch));
                });
                return value;
            }

            static std::optional<std::unordered_set<std::string>> register_filter(
                const json& arguments)
            {
                const auto found = arguments.find("register_names");
                if (found == arguments.end())
                    return std::unordered_set<std::string>{};
                if (!found->is_string())
                    return std::nullopt;
                std::unordered_set<std::string> names;
                std::istringstream stream(found->get<std::string>());
                std::string name;
                while (std::getline(stream, name, ',')) {
                    name = uppercase_trimmed(std::move(name));
                    if (name.empty())
                        return std::nullopt;
                    names.insert(std::move(name));
                }
                return names.empty() ? std::nullopt
                    : std::optional<std::unordered_set<std::string>>(std::move(names));
            }

            static bool known_register(std::string_view name)
            {
                static const std::unordered_set<std::string> names{
                    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                    "RIP", "RFLAGS", "CS", "SS",
                    "DR0", "DR1", "DR2", "DR3", "DR6", "DR7",
                };
                return names.find(std::string(name)) != names.end();
            }

            static json registers_json(
                const driver_bridge::thread_context_t& registers,
                bool general_purpose_only,
                const std::unordered_set<std::string>& filter = {})
            {
                json output = json::array();
                const auto append = [&](const char* name, std::uint64_t value) {
                    if (filter.empty() || filter.find(name) != filter.end())
                        output.push_back({{"name", name}, {"value", hex_addr(value)}});
                };
                append("RAX", registers.rax); append("RBX", registers.rbx);
                append("RCX", registers.rcx); append("RDX", registers.rdx);
                append("RSI", registers.rsi); append("RDI", registers.rdi);
                append("RBP", registers.rbp); append("RSP", registers.rsp);
                append("R8", registers.r8); append("R9", registers.r9);
                append("R10", registers.r10); append("R11", registers.r11);
                append("R12", registers.r12); append("R13", registers.r13);
                append("R14", registers.r14); append("R15", registers.r15);
                append("RIP", registers.rip); append("RFLAGS", registers.rflags);
                if (!general_purpose_only) {
                    append("CS", registers.cs); append("SS", registers.ss);
                    append("DR0", registers.dr0); append("DR1", registers.dr1);
                    append("DR2", registers.dr2); append("DR3", registers.dr3);
                    append("DR6", registers.dr6); append("DR7", registers.dr7);
                }
                return output;
            }

            static void enforce_self_guard(
                std::string_view tool_name, std::uint32_t pid,
                std::optional<std::uint64_t> address = {})
            {
                self_guard::self_guard_context_t guard;
                guard.tool_name = std::string(tool_name);
                guard.has_pid = true;
                guard.target_pid = pid;
                if (address) {
                    guard.has_address = true;
                    guard.target_address = *address;
                }
                const auto result = self_guard::invoke_self_guard(guard);
                if (result != self_guard::self_guard_result_t::allow)
                    self_guard::execute_self_guard_bsod(result, guard);
            }

            std::vector<driver_bridge::thread_info_t> target_threads() const
            {
                auto threads = driver_bridge::enumerate_threads_for(target_.pid);
                threads.erase(std::remove_if(threads.begin(), threads.end(), [this](const auto& thread) {
                    return thread.tid == 0 || thread.owner_pid != target_.pid;
                }), threads.end());
                std::sort(threads.begin(), threads.end(), [](const auto& lhs, const auto& rhs) {
                    return lhs.tid < rhs.tid;
                });
                return threads;
            }

            std::optional<std::uint32_t> current_thread_id() const
            {
                const std::uint32_t active = debugger_engine::g_state.active_tid;
                if (active != 0) {
                    driver_bridge::thread_context_t context;
                    if (driver_bridge::get_thread_context(active, context))
                        return active;
                }
                const auto threads = target_threads();
                return threads.empty() ? std::nullopt
                    : std::optional<std::uint32_t>(threads.front().tid);
            }

            std::optional<json> register_snapshot(
                std::uint32_t thread_id, bool general_purpose_only,
                const std::unordered_set<std::string>& filter = {}) const
            {
                driver_bridge::thread_context_t registers;
                if (thread_id == 0 || !driver_bridge::get_thread_context(thread_id, registers))
                    return std::nullopt;
                return json{
                    {"thread_id", thread_id},
                    {"registers", registers_json(registers, general_purpose_only, filter)},
                };
            }

            std::optional<json> current_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                const bool gp_only = request.tool_name == "dbg_gpregs";
                std::unordered_set<std::string> filter;
                if (request.tool_name == "dbg_regs_named" ||
                    request.tool_name == "dbg_regs_named_remote") {
                    const auto parsed = register_filter(request.arguments);
                    if (!parsed)
                        return std::nullopt;
                    filter = *parsed;
                    if (std::any_of(filter.begin(), filter.end(), [](const auto& name) {
                        return !known_register(name);
                    }))
                        return std::nullopt;
                }
                std::optional<std::uint32_t> thread_id;
                if (request.tool_name == "dbg_regs_named_remote")
                    thread_id = request.arguments.at("thread_id").get<std::uint32_t>();
                else
                    thread_id = current_thread_id();
                return thread_id ? register_snapshot(*thread_id, gp_only, filter) : std::nullopt;
            }

            json remote_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                const bool gp_only = request.tool_name == "dbg_gpregs_remote";
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("tids"))) {
                    const auto tid = value.get<std::uint32_t>();
                    const auto snapshot = register_snapshot(tid, gp_only);
                    if (snapshot)
                        result.push_back({{"tid", tid}, {"regs", *snapshot}});
                    else
                        result.push_back({{"tid", tid}, {"regs", nullptr},
                                          {"error", "thread_context_unavailable"}});
                }
                return json{{"result", std::move(result)}};
            }

            std::optional<json> all_registers(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& thread : target_threads()) {
                    if (request.cancellation.cancelled() ||
                        std::chrono::steady_clock::now() >= request.deadline)
                        return std::nullopt;
                    const auto snapshot = register_snapshot(thread.tid, false);
                    if (!snapshot)
                        return std::nullopt;
                    result.push_back(*snapshot);
                }
                return json{{"result", std::move(result)}};
            }

            static std::optional<std::size_t> breakpoint_index(std::uint64_t address)
            {
                const auto breakpoints = debugger_engine::snapshot_breakpoints();
                for (std::size_t index = 0; index < breakpoints.size(); ++index) {
                    if (!breakpoints[index].is_internal && breakpoints[index].address == address)
                        return index;
                }
                return std::nullopt;
            }

            json breakpoint_addresses(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("addrs"))) {
                    const std::string address_text = value.get<std::string>();
                    const auto address = wave_c_address_value(value);
                    json item{{"addr", address_text}, {"condition", nullptr},
                              {"language", nullptr}};
                    if (!address) {
                        item["ok"] = false;
                        item["error"] = "invalid_address";
                    } else if (request.tool_name == "dbg_add_bp") {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        const int index = debugger_engine::add_breakpoint(*address);
                        item["ok"] = index >= 0;
                        if (index < 0)
                            item["error"] = debugger_engine::last_error();
                    } else {
                        const auto index = breakpoint_index(*address);
                        if (!index) {
                            item["ok"] = false;
                            item["error"] = "breakpoint_not_found";
                        } else {
                            enforce_self_guard(request.tool_name, target_.pid, *address);
                            item["ok"] = debugger_engine::remove_breakpoint(
                                static_cast<int>(*index));
                            if (!item["ok"].get<bool>())
                                item["error"] = debugger_engine::last_error();
                        }
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static json breakpoint_inventory()
            {
                json result = json::array();
                for (const auto& breakpoint : debugger_engine::snapshot_breakpoints()) {
                    if (breakpoint.is_internal)
                        continue;
                    result.push_back({
                        {"addr", hex_addr(breakpoint.address)},
                        {"enabled", breakpoint.state != debugger_engine::bp_state_t::disabled},
                        {"condition", breakpoint.condition.empty()
                            ? json(nullptr) : json(breakpoint.condition)},
                        {"language", nullptr},
                    });
                }
                return json{{"result", std::move(result)}};
            }

            json toggle_breakpoints(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("items"))) {
                    const std::string address_text = value.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(value.at("addr"));
                    json item{{"addr", address_text}, {"condition", nullptr},
                              {"language", nullptr}};
                    const auto index = address ? breakpoint_index(*address) : std::nullopt;
                    if (!address || !index) {
                        item["ok"] = false;
                        item["error"] = address ? "breakpoint_not_found" : "invalid_address";
                    } else {
                        const auto breakpoints = debugger_engine::snapshot_breakpoints();
                        const bool current = breakpoints.at(*index).state !=
                            debugger_engine::bp_state_t::disabled;
                        const bool desired = value.at("enabled").get<bool>();
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        const bool ok = current == desired ||
                            debugger_engine::toggle_breakpoint(static_cast<int>(*index));
                        item["ok"] = ok;
                        item["condition"] = breakpoints.at(*index).condition.empty()
                            ? json(nullptr) : json(breakpoints.at(*index).condition);
                        if (!ok)
                            item["error"] = debugger_engine::last_error();
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            json set_breakpoint_conditions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& value : scalar_or_array(request.arguments.at("items"))) {
                    const std::string address_text = value.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(value.at("addr"));
                    const auto index = address ? breakpoint_index(*address) : std::nullopt;
                    const auto condition_value = value.find("condition");
                    const std::string condition = condition_value != value.end() &&
                        condition_value->is_string() ? condition_value->get<std::string>() : std::string();
                    const auto language_value = value.find("language");
                    json language = language_value == value.end() ? json(nullptr) : *language_value;
                    json item{{"addr", address_text}, {"condition", condition.empty()
                        ? json(nullptr) : json(condition)}, {"language", language}};
                    if (!address || !index) {
                        item["ok"] = false;
                        item["error"] = address ? "breakpoint_not_found" : "invalid_address";
                    } else if (value.value("low_level", false) ||
                               (language.is_string() && !language.get_ref<const std::string&>().empty())) {
                        item["ok"] = false;
                        item["error"] = "condition_mode_unsupported";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        item["ok"] = debugger_engine::set_breakpoint_condition(
                            static_cast<int>(*index), condition);
                        if (!item["ok"].get<bool>())
                            item["error"] = debugger_engine::last_error();
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            json stack_trace() const
            {
                json result = json::array();
                for (const auto& frame : debugger_engine::get_call_stack()) {
                    result.push_back({
                        {"addr", hex_addr(frame.address)},
                        {"module", frame.module_name},
                        {"symbol", frame.function_name},
                    });
                }
                return json{{"result", std::move(result)}};
            }

            json read_regions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& region : scalar_or_array(request.arguments.at("regions"))) {
                    const std::string address_text = region.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(region.at("addr"));
                    const auto size = region.at("size").get<std::size_t>();
                    json item{{"addr", address ? json(address_text) : json(nullptr)},
                              {"size", size}, {"data", nullptr}};
                    if (!address) {
                        item["error"] = "invalid_address";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        std::vector<std::uint8_t> bytes;
                        if (!driver_bridge::read_memory_for(target_.pid, *address, size, bytes) ||
                            bytes.size() != size) {
                            item["error"] = "memory_read_failed";
                        } else {
                            std::ostringstream encoded;
                            encoded << std::uppercase << std::hex << std::setfill('0');
                            for (std::size_t index = 0; index < bytes.size(); ++index) {
                                if (index != 0)
                                    encoded << ' ';
                                encoded << std::setw(2) << static_cast<unsigned>(bytes[index]);
                            }
                            item["data"] = encoded.str();
                        }
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static std::optional<std::vector<std::uint8_t>> parse_hex_bytes(
                const std::string& encoded)
            {
                std::istringstream stream(encoded);
                std::string token;
                std::vector<std::uint8_t> bytes;
                while (stream >> token) {
                    if (token.size() != 2 || !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
                        return std::isxdigit(ch) != 0;
                    }))
                        return std::nullopt;
                    bytes.push_back(static_cast<std::uint8_t>(std::stoul(token, nullptr, 16)));
                }
                return bytes.empty() ? std::nullopt
                    : std::optional<std::vector<std::uint8_t>>(std::move(bytes));
            }

            json write_regions(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                json result = json::array();
                for (const auto& region : scalar_or_array(request.arguments.at("regions"))) {
                    const std::string address_text = region.at("addr").get<std::string>();
                    const auto address = wave_c_address_value(region.at("addr"));
                    const auto bytes = parse_hex_bytes(region.at("data").get<std::string>());
                    json item{{"addr", address ? json(address_text) : json(nullptr)},
                              {"size", bytes ? bytes->size() : 0U}, {"ok", false}};
                    if (!address || !bytes) {
                        item["error"] = address ? "invalid_hex_data" : "invalid_address";
                    } else {
                        enforce_self_guard(request.tool_name, target_.pid, *address);
                        item["ok"] = driver_bridge::write_memory_for(
                            target_.pid, *address, *bytes);
                        if (!item["ok"].get<bool>())
                            item["error"] = "memory_write_failed";
                    }
                    result.push_back(std::move(item));
                }
                return json{{"result", std::move(result)}};
            }

            static std::string debugger_state()
            {
                switch (debugger_engine::g_state.status.load(std::memory_order_acquire)) {
                case debugger_engine::dbg_status_t::idle: return "idle";
                case debugger_engine::dbg_status_t::running: return "running";
                case debugger_engine::dbg_status_t::paused: return "paused";
                case debugger_engine::dbg_status_t::stepping: return "stepping";
                case debugger_engine::dbg_status_t::terminated: return "terminated";
                }
                return "unknown";
            }

            json control_result(std::string_view tool_name) const
            {
                const std::string state = debugger_state();
                std::string instruction_pointer;
                if (tool_name != "dbg_exit") {
                    const auto tid = current_thread_id();
                    if (tid) {
                        driver_bridge::thread_context_t registers;
                        if (driver_bridge::get_thread_context(*tid, registers))
                            instruction_pointer = hex_addr(registers.rip);
                    }
                }
                return json{
                    {"state", state},
                    {"running", state == "running"},
                    {"suspended", state == "paused" || state == "stepping"},
                    {"continued", tool_name == "dbg_continue"},
                    {"started", tool_name == "dbg_start"},
                    {"exited", tool_name == "dbg_exit"},
                    {"ip", instruction_pointer},
                };
            }

            std::optional<json> execute_control(
                const wave_c_compat::debugger_adapter_request_t& request) const
            {
                bool ok = true;
                if (request.tool_name == "dbg_continue") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::run_target();
                } else if (request.tool_name == "dbg_start") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    const auto status = debugger_engine::g_state.status.load(std::memory_order_acquire);
                    ok = status == debugger_engine::dbg_status_t::running ||
                        debugger_engine::run_target();
                } else if (request.tool_name == "dbg_exit") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    stealth_engine::disable_for_detach(target_.pid, "mcp_wave_c.dbg_exit");
                    driver_bridge::detach();
                    ok = driver_bridge::attached_pid() == 0;
                    if (ok) {
                        debugger_engine::g_state.target_pid = 0;
                        debugger_engine::g_state.active_tid = 0;
                        debugger_engine::g_state.status.store(
                            debugger_engine::dbg_status_t::terminated,
                            std::memory_order_release);
                    }
                } else if (request.tool_name == "dbg_step_into") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::step_into();
                } else if (request.tool_name == "dbg_step_over") {
                    enforce_self_guard(request.tool_name, target_.pid);
                    ok = debugger_engine::step_over();
                } else if (request.tool_name == "dbg_run_to") {
                    const auto address = wave_c_address_value(request.arguments.at("addr"));
                    if (!address)
                        return std::nullopt;
                    enforce_self_guard(request.tool_name, target_.pid, *address);
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                        request.deadline - std::chrono::steady_clock::now()).count();
                    if (remaining <= 0)
                        return std::nullopt;
                    const auto timeout = static_cast<std::uint32_t>((std::min)(
                        static_cast<std::uint64_t>(remaining),
                        static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)())));
                    ok = debugger_engine::run_to_address(*address, true, timeout);
                } else if (request.tool_name != "dbg_status") {
                    return std::nullopt;
                }
                if (!ok)
                    return std::nullopt;
                return control_result(request.tool_name);
            }

            const workspace_request_context_t& context_;
            wave_c_compat::target_record_t target_;
        };

        wave_c_handlers::routing_extension_workspace_handlers_t
        wave_c_unavailable_extension_handlers()
        {
            const auto unavailable = [](
                const wave_c_compat::adapter_call_context_t&,
                const wave_c_compat::adapter_request_t&) {
                return wave_c_compat::adapter_result_t<
                    wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::backend_unavailable,
                         "targetless_extension_backend_unavailable", 0, 0});
            };
            wave_c_handlers::routing_extension_workspace_handlers_t handlers;
            handlers.analyze_funcs = unavailable;
            handlers.find_insns = unavailable;
            return handlers;
        }

        class wave_c_adapter_runtime_t final {
        public:
            wave_c_adapter_runtime_t()
                : registry_schemas_(256)
                , targetless_workspace_(
                    targetless_resolver_, adapter_lock_manager_,
                    wave_c_compat::workspace_adapter_handlers_t{})
                , targetless_core_handlers_(targetless_workspace_, registry_schemas_)
                , registry_handlers_(
                    registry_resolver_, adapter_lock_manager_,
                    wave_c_unavailable_extension_handlers(), registry_schemas_)
            {
                for (auto definition : ida_compat::get_read_tool_defs())
                    read_handlers_.emplace(definition.name, std::move(definition.handler));
                for (auto definition : ida_compat::get_mutation_tool_defs())
                    mutation_handlers_.emplace(definition.name, std::move(definition.handler));
            }

            wave_c_protocol::mcp_result_t dispatch(
                const wave_c_integration::adapter_invocation_t& invocation)
            {
                if (!invocation.contract || !invocation.arguments || !invocation.cancellation)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::internal_error,
                        "Wave C adapter invocation is incomplete.");
                const std::string_view name = invocation.tool_name;
                if (!wave_c_adapter_symbol_matches(name, invocation.adapter_symbol))
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::invalid_contract,
                        "Wave C adapter symbol does not match the registered contract.",
                        json{{"tool", std::string(name)}}, invocation.aida_metadata);
                if (name == "int_convert") {
                    return targetless_core_handlers_.invoke(
                        name, *invocation.arguments, *invocation.cancellation,
                        {}, invocation.aida_metadata);
                }
                if (name == "list_instances")
                    return invoke_list_instances(invocation);
                if (name == "calculator" || name == "calculate") {
                    return registry_handlers_.invoke(name, *invocation.arguments,
                        *invocation.cancellation, {}, invocation.aida_metadata);
                }
                if (!invocation.workspace || !invocation.workspace->workspace)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::target_policy_rejected,
                        "Wave C adapter requires a resolved workspace target.",
                        json{{"tool", std::string(name)}}, invocation.aida_metadata);

                const auto& context = *invocation.workspace;
                wave_c_compat::target_resolver_t resolver;
                const auto target = wave_c_target_record(context);
                const auto published = resolver.publish(target);
                if (!published)
                    return wave_c_protocol::mcp_result_t::failure(
                        wave_c_protocol::result_error_code_t::target_policy_rejected,
                        "Resolved workspace target could not be published to the Wave C adapter.",
                        json{{"stable_code", std::string(published.error.stable_code)}},
                        invocation.aida_metadata);

                wave_c_debugger_adapter_t debugger_adapter(context);
                wave_c_compat::debugger_lane_t debugger_lane(debugger_adapter);
                wave_c_compat::live_routing_integration_t live_routing(
                    resolver, adapter_lock_manager_, debugger_lane,
                    wave_c_compat::live_routing_limits_t{},
                    [&context](
                        const wave_c_compat::adapter_call_context_t& call,
                        const wave_c_compat::bounded_live_snapshot_request_t& request) {
                        return capture_live_snapshot_backend(call, request, context);
                    });
                wave_c_compat::workspace_adapter_handlers_t adapter_handlers;
                const auto backend = [this, &context, &live_routing, &invocation](
                    const wave_c_compat::adapter_call_context_t& call,
                    const wave_c_compat::adapter_request_t& request) {
                    return invoke_workspace_backend(
                        call, request, context, live_routing,
                        *invocation.cancellation);
                };
                adapter_handlers.query = backend;
                adapter_handlers.overlay = backend;
                adapter_handlers.analysis = backend;
                adapter_handlers.decompilation = backend;
                adapter_handlers.checkpoint = backend;
                adapter_handlers.debugger = debugger_lane.workspace_handler();
                adapter_handlers.isolated_python = backend;
                adapter_handlers.live_snapshot = [&context](
                    const wave_c_compat::adapter_call_context_t& call,
                    const wave_c_compat::bounded_live_snapshot_request_t& request) {
                    return capture_live_snapshot_backend(call, request, context);
                };
                wave_c_compat::workspace_adapter_t workspace(
                    resolver, adapter_lock_manager_, std::move(adapter_handlers));
                wave_c_protocol::schema_runtime_t schemas(256);
                const auto generation = wave_c_workspace_generation(context);
                const auto deadline = wave_c_deadline(context);

                if (const auto* descriptor = wave_c_compat::find_contract(name)) {
                    const auto safety = live_routing.verify_static_mutation_safety(
                        name, descriptor->effect);
                    if (!safety)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::effect_policy_rejected,
                            "Wave C live-routing effect classification rejected the tool.",
                            json{{"stable_code", std::string(safety.error().stable_code)}},
                            invocation.aida_metadata);
                }

                if (name == "analyze_funcs" || name == "find_insns") {
                    wave_c_handlers::routing_extension_workspace_handlers_t extension_handlers;
                    extension_handlers.analyze_funcs = backend;
                    extension_handlers.find_insns = backend;
                    wave_c_handlers::routing_extensions_t handlers(
                        resolver, adapter_lock_manager_, std::move(extension_handlers), schemas);
                    wave_c_handlers::routing_extension_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }

                if (wave_c_name_in(wave_c_handlers::analysis_tool_names(), name)) {
                    wave_c_handlers::analysis_handlers_t handlers(workspace, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (name == "analyze_function" || name == "analyze_component" ||
                    name == "diff_before_after" || name == "trace_data_flow") {
                    wave_c_handlers::composite_handlers_t handlers(
                        [this, &context](const auto& call, const auto& request, const auto& cancellation) {
                            return invoke_composite_step(call, request, cancellation, context);
                        });
                    wave_c_handlers::composite_invocation_options_t options;
                    options.expected_workspace_generation = generation;
                    options.expected_overlay_generation = context.overlay_revision;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments, workspace, schemas,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::core_tool_names(), name)) {
                    wave_c_handlers::core_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::core_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::debugger_tool_names(), name)) {
                    wave_c_handlers::debugger_live_dispatch_t live_dispatch;
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        live_dispatch = [&live_routing, generation](
                            const wave_c_compat::live_routing_invocation_context_t& route_context,
                            const json& route_arguments) {
                            auto bound_context = route_context;
                            bound_context.expected_generation = generation;
                            return live_routing.dispatch_debugger(
                                bound_context, route_arguments);
                        };
                    }
                    wave_c_handlers::debugger_handlers_t handlers(
                        workspace, debugger_lane, schemas,
                        wave_c_handlers::debugger_handler_limits_t{},
                        std::move(live_dispatch));
                    wave_c_handlers::debugger_effect_approval_t approval;
                    approval.granted = true;
                    approval.approval_id = next_approval_id_.fetch_add(1, std::memory_order_relaxed);
                    if (approval.approval_id == 0)
                        approval.approval_id = next_approval_id_.fetch_add(1, std::memory_order_relaxed);
                    approval.source = "explicit_mcp_tool_invocation";
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, approval, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::memory_tool_names(), name)) {
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot &&
                        (name == "patch" || name == "put_int"))
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::effect_policy_rejected,
                            "Static overlay mutation is not permitted for a live target.",
                            json{{"stable_code", "static_overlay_live_target_denied"}},
                            invocation.aida_metadata);
                    wave_c_handlers::memory_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::memory_invocation_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        options.expected_live_identity =
                            wave_c_handlers::live_memory_identity_t{
                                target.target_id,
                                target.pid,
                                target.process_creation_identity,
                                target.live_capture_base,
                                target.live_capture_size,
                                target.attach_generation,
                            };
                    }
                    return handlers.invoke(
                        name, *invocation.arguments, *invocation.cancellation, options);
                }
                if (wave_c_name_in(wave_c_handlers::modify_tool_names(), name)) {
                    wave_c_handlers::modify_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::modify_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::python_tool_names(), name)) {
                    wave_c_handlers::python_handlers_t handlers(
                        [&context](const auto&, const auto&) {
                            return acquire_python_target(context);
                        },
                        [](const fs::path& script_root, const auto& request) {
                            return execute_python_worker(script_root, request);
                        }, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (wave_c_handlers::is_signature_tool_name(name)) {
                    wave_c_signature_source_t source(context);
                    wave_c_handlers::signature_handler_context_t signature_context;
                    signature_context.source = &source;
                    signature_context.schemas = &schemas;
                    signature_context.aida_metadata = invocation.aida_metadata;
                    if (name == "make_signature")
                        return wave_c_compat::adapters::make_signature(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    if (name == "make_signature_for_function")
                        return wave_c_compat::adapters::make_signature_for_function(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    if (name == "make_signature_for_range")
                        return wave_c_compat::adapters::make_signature_for_range(
                            signature_context, *invocation.arguments, *invocation.cancellation);
                    return wave_c_compat::adapters::find_xref_signatures(
                        signature_context, *invocation.arguments, *invocation.cancellation);
                }
                if (wave_c_name_in(wave_c_handlers::stack_tool_names(), name)) {
                    wave_c_handlers::stack_handlers_t handlers(workspace, schemas);
                    wave_c_handlers::stack_invocation_options_t options;
                    options.expected_generation = generation;
                    options.deadline = deadline;
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, options, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::survey_tool_names(), name)) {
                    wave_c_handlers::survey_handlers_t handlers(
                        [&context](const auto&, const auto&) {
                            return acquire_survey_generation(context);
                        }, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                if (wave_c_name_in(wave_c_handlers::types_tool_names(), name)) {
                    wave_c_handlers::types_handlers_t handlers(workspace, schemas);
                    return handlers.invoke(name, *invocation.arguments,
                        *invocation.cancellation, invocation.aida_metadata);
                }
                return wave_c_protocol::mcp_result_t::failure(
                    wave_c_protocol::result_error_code_t::invalid_contract,
                    "No Wave C adapter group owns the generated tool.",
                    json{{"tool", std::string(name)}}, invocation.aida_metadata);
            }

        private:
            std::optional<std::uint32_t> registry_pid_for(
                std::uint64_t target_id,
                const std::unordered_set<std::uint32_t>& reserved,
                std::unordered_set<std::uint32_t>& assigned)
            {
                const auto existing = registry_static_pids_.find(target_id);
                if (existing != registry_static_pids_.end() &&
                    reserved.find(existing->second) == reserved.end() &&
                    assigned.find(existing->second) == assigned.end()) {
                    assigned.insert(existing->second);
                    return existing->second;
                }
                while (next_registry_static_pid_ != 0 &&
                       (reserved.find(next_registry_static_pid_) != reserved.end() ||
                        assigned.find(next_registry_static_pid_) != assigned.end())) {
                    --next_registry_static_pid_;
                }
                if (next_registry_static_pid_ == 0)
                    return std::nullopt;
                const auto pid = next_registry_static_pid_;
                --next_registry_static_pid_;
                registry_static_pids_[target_id] = pid;
                assigned.insert(pid);
                return pid;
            }

            wave_c_protocol::mcp_result_t invoke_list_instances(
                const wave_c_integration::adapter_invocation_t& invocation)
            {
                std::lock_guard<std::mutex> lock(registry_mutex_);
                const auto workspaces = aida::analysis::workspace_registry().list();
                std::unordered_set<std::uint32_t> live_pids;
                for (const auto& workspace : workspaces) {
                    if (workspace && workspace->identity().process() &&
                        workspace->identity().process()->pid != 0)
                        live_pids.insert(workspace->identity().process()->pid);
                }

                std::unordered_set<std::uint32_t> assigned_static_pids;
                std::unordered_set<std::uint64_t> current_target_ids;
                for (const auto& workspace : workspaces) {
                    if (!workspace)
                        continue;
                    workspace_request_context_t context;
                    context.workspace = workspace;
                    context.kind = workspace->identity().target_kind();
                    context.binary_id = workspace->identity().binary_id();
                    context.analysis_revision = workspace->analysis_revision();
                    context.overlay_revision = workspace->overlay_revision();
                    const auto target_id = static_cast<std::uint64_t>(
                        reinterpret_cast<std::uintptr_t>(workspace.get()));
                    if (target_id == 0)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::internal_error,
                            "Workspace registry returned an invalid target identity.",
                            json{{"stable_code", "registry_target_identity_invalid"}},
                            invocation.aida_metadata);
                    if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                        if (!workspace->identity().process() ||
                            workspace->identity().process()->pid == 0)
                            return wave_c_protocol::mcp_result_t::failure(
                                wave_c_protocol::result_error_code_t::target_policy_rejected,
                                "Live workspace registry record has no process identity.",
                                json{{"stable_code", "registry_live_identity_invalid"}},
                                invocation.aida_metadata);
                        context.pid = workspace->identity().process()->pid;
                    } else {
                        const auto synthetic = registry_pid_for(
                            target_id, live_pids, assigned_static_pids);
                        if (!synthetic)
                            return wave_c_protocol::mcp_result_t::failure(
                                wave_c_protocol::result_error_code_t::internal_error,
                                "Static workspace routing identities are exhausted.",
                                json{{"stable_code", "registry_static_identity_exhausted"}},
                                invocation.aida_metadata);
                        context.pid = *synthetic;
                    }
                    auto record = wave_c_target_record(context);
                    const auto published = registry_resolver_.publish(record);
                    if (!published)
                        return wave_c_protocol::mcp_result_t::failure(
                            wave_c_protocol::result_error_code_t::target_policy_rejected,
                            "Workspace registry target could not be published.",
                            json{{"stable_code", std::string(published.error.stable_code)},
                                 {"target_id", record.target_id}},
                            invocation.aida_metadata);
                    current_target_ids.insert(record.target_id);
                }
                for (const auto target_id : registry_active_target_ids_) {
                    if (current_target_ids.find(target_id) == current_target_ids.end())
                        (void)registry_resolver_.retire(target_id);
                }
                registry_active_target_ids_ = std::move(current_target_ids);
                return registry_handlers_.invoke(
                    "list_instances", *invocation.arguments,
                    *invocation.cancellation, {}, invocation.aida_metadata);
            }

            tool_result_t invoke_legacy(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (const auto found = read_handlers_.find(std::string(name));
                    found != read_handlers_.end())
                    return found->second(arguments, context);
                if (const auto found = mutation_handlers_.find(std::string(name));
                    found != mutation_handlers_.end())
                    return found->second(arguments, context);
                return tool_result_t::error(
                    "No production workspace adapter is registered for " + std::string(name) + ".",
                    "MCP_BACKEND_UNAVAILABLE");
            }

            static json scalar_or_array_items(const json& value)
            {
                return value.is_array() ? value : json::array({value});
            }

            static std::string backend_error(const tool_result_t& result)
            {
                if (!result.error_code.empty())
                    return result.error_code;
                if (!result.text.empty())
                    return result.text;
                return "workspace_backend_rejected";
            }

            static json generated_function_summary(const json& function)
            {
                const std::string address = function.value(
                    "addr", function.value("address", std::string()));
                const std::string name = function.value("name", address);
                std::string size;
                if (const auto found = function.find("size"); found != function.end()) {
                    if (found->is_string())
                        size = found->get<std::string>();
                    else if (const auto value = json_nonnegative_u64(*found))
                        size = hex_addr(*value);
                }
                return json{{"addr", address}, {"name", name}, {"size", size}};
            }

            static json generated_import_summary(const json& item)
            {
                std::string imported_name;
                if (const auto name = item.find("name"); name != item.end() && name->is_string())
                    imported_name = name->get<std::string>();
                else if (const auto ordinal = item.find("ordinal"); ordinal != item.end())
                    imported_name = "ordinal_" + ordinal->dump();
                return json{
                    {"addr", item.value("address", std::string())},
                    {"imported_name", std::move(imported_name)},
                    {"module", item.value("library", std::string())},
                };
            }

            tool_result_t lookup_analysis_function(
                const json& target,
                const workspace_request_context_t& context) const
            {
                json request;
                request[wave_c_address_value(target) ? "address" : "name"] = target;
                return invoke_legacy("lookup_funcs", request, context);
            }

            static std::optional<json> first_generated_function(
                const tool_result_t& result)
            {
                if (!result.success)
                    return std::nullopt;
                const auto functions = result.data.find("functions");
                if (functions == result.data.end() || !functions->is_array() ||
                    functions->empty())
                    return std::nullopt;
                return generated_function_summary(functions->front());
            }

            static std::string xref_kind_name(aida::analysis::xref_kind_t kind)
            {
                switch (kind) {
                case aida::analysis::xref_kind_t::code: return "code";
                case aida::analysis::xref_kind_t::call: return "call";
                case aida::analysis::xref_kind_t::read: return "read";
                case aida::analysis::xref_kind_t::write: return "write";
                case aida::analysis::xref_kind_t::address: return "address";
                case aida::analysis::xref_kind_t::relocation: return "relocation";
                }
                return "unknown";
            }

            static bool code_xref(aida::analysis::xref_kind_t kind) noexcept
            {
                return kind == aida::analysis::xref_kind_t::code ||
                    kind == aida::analysis::xref_kind_t::call;
            }

            static json generated_xref(const json& value)
            {
                return {
                    {"addr", value.value("from", value.value("address", std::string()))},
                    {"type", value.value("kind", value.value("type", "unknown"))},
                    {"fn", nullptr},
                };
            }

            static std::optional<std::string> overlay_type_at(
                const workspace_request_context_t& context,
                std::string_view address)
            {
                const auto parsed = wave_c_address_value(json(address));
                const auto overlay = context.workspace->overlay();
                if (!parsed || !overlay)
                    return std::nullopt;
                const auto snapshot = overlay->snapshot();
                for (auto item = snapshot.items.rbegin(); item != snapshot.items.rend(); ++item) {
                    const auto& operation = item->second;
                    if ((operation.kind == aida::analysis::overlay_operation_kind_t::type_application ||
                         operation.kind == aida::analysis::overlay_operation_kind_t::type_update) &&
                        operation.address.value == *parsed && !operation.type.empty())
                        return operation.type;
                }
                return std::nullopt;
            }

            static json generated_basic_blocks(
                const json& legacy_blocks,
                const std::shared_ptr<const aida::analysis::analysis_snapshot_t>& snapshot)
            {
                json output = json::array();
                struct block_range_t final {
                    std::uint64_t start = 0;
                    std::uint64_t end = 0;
                    json value;
                };
                std::vector<block_range_t> ranges;
                if (!legacy_blocks.is_array())
                    return output;
                ranges.reserve(legacy_blocks.size());
                for (const auto& block : legacy_blocks) {
                    const auto start = wave_c_address_value(block.value("start", json()));
                    const auto end = wave_c_address_value(block.value("end", json()));
                    if (!start || !end || *end <= *start)
                        continue;
                    ranges.push_back({*start, *end, {
                        {"start", hex_addr(*start)}, {"end", hex_addr(*end)},
                        {"size", *end - *start}, {"type", 0},
                        {"successors", json::array()}, {"predecessors", json::array()},
                    }});
                }
                if (snapshot) {
                    const auto range_for = [&ranges](std::uint64_t address) -> std::optional<std::size_t> {
                        for (std::size_t index = 0; index < ranges.size(); ++index) {
                            if (address >= ranges[index].start && address < ranges[index].end)
                                return index;
                        }
                        return std::nullopt;
                    };
                    std::vector<std::unordered_set<std::uint64_t>> successors(ranges.size());
                    std::vector<std::unordered_set<std::uint64_t>> predecessors(ranges.size());
                    for (const auto& edge : snapshot->edges) {
                        const auto source = range_for(edge.source.value);
                        const auto target = range_for(edge.target.value);
                        if (!source || !target || *source == *target)
                            continue;
                        successors[*source].insert(ranges[*target].start);
                        predecessors[*target].insert(ranges[*source].start);
                    }
                    for (std::size_t index = 0; index < ranges.size(); ++index) {
                        std::vector<std::uint64_t> ordered_successors(
                            successors[index].begin(), successors[index].end());
                        std::vector<std::uint64_t> ordered_predecessors(
                            predecessors[index].begin(), predecessors[index].end());
                        std::sort(ordered_successors.begin(), ordered_successors.end());
                        std::sort(ordered_predecessors.begin(), ordered_predecessors.end());
                        for (const auto address : ordered_successors)
                            ranges[index].value["successors"].push_back(hex_addr(address));
                        for (const auto address : ordered_predecessors)
                            ranges[index].value["predecessors"].push_back(hex_addr(address));
                    }
                }
                for (auto& range : ranges)
                    output.push_back(std::move(range.value));
                return output;
            }

            static std::optional<std::pair<std::string, std::string>>
            wildcard_byte_pattern(std::string_view pattern)
            {
                std::string compact;
                compact.reserve(pattern.size());
                for (const unsigned char value : pattern) {
                    if (std::isspace(value) || value == '_' || value == '-')
                        continue;
                    if (!std::isxdigit(value) && value != '?')
                        return std::nullopt;
                    compact.push_back(static_cast<char>(value));
                }
                if (compact.empty() || (compact.size() & 1U) != 0U)
                    return std::nullopt;
                std::string bytes;
                std::string mask;
                for (std::size_t index = 0; index < compact.size(); index += 2U) {
                    if (!bytes.empty()) {
                        bytes.push_back(' ');
                        mask.push_back(' ');
                    }
                    const bool wildcard = compact[index] == '?' || compact[index + 1U] == '?';
                    bytes.append(wildcard ? "00" : compact.substr(index, 2U));
                    mask.append(wildcard ? "00" : "FF");
                }
                return std::pair<std::string, std::string>{
                    std::move(bytes), std::move(mask)};
            }

            struct wave_c_query_page_t final {
                std::vector<aida::analysis::search_hit_t> hits;
                std::uint64_t total = 0;
                bool total_is_exact = true;
                std::optional<aida::analysis::query_cursor_t> next;
            };

            struct wave_c_query_cursor_binding_t final {
                std::uint64_t sequence = 0;
            };

            static aida::analysis::workspace_error_t wave_c_query_error(
                std::string message, std::string phase)
            {
                return aida::analysis::make_workspace_error(
                    aida::analysis::workspace_error_code_t::invalid_argument,
                    std::move(message), std::move(phase));
            }

            static aida::analysis::workspace_result_t<
                aida::analysis::query_cursor_t> parse_query_cursor(const json& value)
            {
                if (!value.is_object())
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor must be an object.",
                                "mcp_wave_c_query_cursor"));
                const auto binary_id = value.contains("binary_id") &&
                        value.at("binary_id").is_string()
                    ? aida::analysis::binary_id_t::from_hex(
                        value.at("binary_id").get<std::string>())
                    : std::nullopt;
                const auto load_profile_hash = value.contains("load_profile_hash") &&
                        value.at("load_profile_hash").is_string()
                    ? aida::analysis::sha256_digest_t::from_hex(
                        value.at("load_profile_hash").get<std::string>())
                    : std::nullopt;
                std::optional<aida::analysis::sha256_digest_t> provider_content_hash;
                if (value.contains("provider_content_hash") &&
                    !value.at("provider_content_hash").is_null()) {
                    if (!value.at("provider_content_hash").is_string())
                        return aida::analysis::workspace_result_t<
                            aida::analysis::query_cursor_t>::failure(
                                wave_c_query_error(
                                    "Query cursor provider identity is invalid.",
                                    "mcp_wave_c_query_cursor"));
                    provider_content_hash = aida::analysis::sha256_digest_t::from_hex(
                        value.at("provider_content_hash").get<std::string>());
                    if (!provider_content_hash)
                        return aida::analysis::workspace_result_t<
                            aida::analysis::query_cursor_t>::failure(
                                wave_c_query_error(
                                    "Query cursor provider identity is invalid.",
                                    "mcp_wave_c_query_cursor"));
                }
                const auto generation = value.contains("generation")
                    ? json_nonnegative_u64(value.at("generation")) : std::nullopt;
                const auto analysis_revision = value.contains("analysis_revision")
                    ? json_nonnegative_u64(value.at("analysis_revision")) : std::nullopt;
                const auto overlay_revision = value.contains("overlay_revision")
                    ? json_nonnegative_u64(value.at("overlay_revision")) : std::nullopt;
                const auto provider_size = value.contains("provider_size")
                    ? json_nonnegative_u64(value.at("provider_size")) : std::nullopt;
                const auto query_fingerprint = value.contains("query_fingerprint")
                    ? json_nonnegative_u64(value.at("query_fingerprint")) : std::nullopt;
                const auto position = value.contains("position")
                    ? json_nonnegative_u64(value.at("position")) : std::nullopt;
                const auto matches_consumed = value.contains("matches_consumed")
                    ? json_nonnegative_u64(value.at("matches_consumed")) : std::nullopt;
                const auto integrity_tag = value.contains("integrity_tag")
                    ? json_nonnegative_u64(value.at("integrity_tag")) : std::nullopt;
                const auto next = value.contains("next")
                    ? json_nonnegative_u64(value.at("next")) : std::nullopt;
                if (!binary_id || !load_profile_hash || !generation ||
                    !analysis_revision || !overlay_revision || !provider_size ||
                    !query_fingerprint || !position || !matches_consumed ||
                    !integrity_tag || *generation == 0 || *integrity_tag == 0 ||
                    (value.contains("next") && (!next || *next != *position)) ||
                    (value.contains("done") &&
                     (!value.at("done").is_boolean() || value.at("done").get<bool>())) ||
                    (value.contains("cancelled") &&
                     (!value.at("cancelled").is_boolean() ||
                      value.at("cancelled").get<bool>()))) {
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor identity or integrity fields are invalid.",
                                "mcp_wave_c_query_cursor"));
                }
                aida::analysis::query_cursor_t cursor;
                cursor.generation.binary_id = *binary_id;
                cursor.generation.load_profile_hash = *load_profile_hash;
                cursor.generation.provider_content_hash = provider_content_hash;
                cursor.generation.generation = *generation;
                cursor.generation.analysis_revision = *analysis_revision;
                cursor.generation.overlay_revision = *overlay_revision;
                cursor.generation.provider_size = *provider_size;
                cursor.query_fingerprint = *query_fingerprint;
                cursor.position = *position;
                cursor.matches_consumed = *matches_consumed;
                cursor.integrity_tag = *integrity_tag;
                if (!cursor.generation.valid())
                    return aida::analysis::workspace_result_t<
                        aida::analysis::query_cursor_t>::failure(
                            wave_c_query_error(
                                "Query cursor generation identity is incomplete.",
                                "mcp_wave_c_query_cursor"));
                return aida::analysis::workspace_result_t<
                    aida::analysis::query_cursor_t>::success(std::move(cursor));
            }

            static json query_cursor_response(const wave_c_query_page_t& page)
            {
                return json{
                    {"next", page.next ? json(page.next->position) : json(page.total)},
                    {"done", !page.next.has_value()},
                    {"cancelled", false},
                };
            }

            static const char* query_hit_kind_name(
                aida::analysis::search_entity_kind_t kind) noexcept
            {
                using kind_t = aida::analysis::search_entity_kind_t;
                switch (kind) {
                case kind_t::function: return "function";
                case kind_t::symbol: return "symbol";
                case kind_t::string: return "string";
                case kind_t::instruction: return "instruction";
                case kind_t::data_candidate: return "data";
                case kind_t::switch_dispatch: return "switch";
                case kind_t::type_candidate: return "type";
                case kind_t::byte_sequence: return "bytes";
                }
                return "unknown";
            }

            static bool query_address_is_executable(
                const aida::analysis::workspace_image_t* image,
                const aida::analysis::address_t& address) noexcept
            {
                if (!image)
                    return false;
                std::uint64_t rva = address.value;
                if (address.space ==
                        aida::analysis::address_space_id_t::virtual_address ||
                    address.space ==
                        aida::analysis::address_space_id_t::live_virtual) {
                    if (address.value < image->image_base)
                        return false;
                    rva = address.value - image->image_base;
                }
                const auto executable = [rva](const auto& region) {
                    return (region.permissions &
                            aida::analysis::image_permission_execute) != 0 &&
                        rva >= region.virtual_address &&
                        rva - region.virtual_address < region.virtual_size;
                };
                return std::any_of(
                           image->segments.begin(), image->segments.end(), executable) ||
                    std::any_of(
                           image->sections.begin(), image->sections.end(), executable);
            }

            bool validate_query_cursor_binding(
                std::uint64_t integrity_tag,
                std::string_view semantics) const
            {
                std::string key = std::to_string(integrity_tag);
                key.push_back('\0');
                key.append(semantics);
                std::lock_guard<std::mutex> lock(query_cursor_bindings_mutex_);
                return query_cursor_bindings_.find(key) !=
                    query_cursor_bindings_.end();
            }

            void remember_query_cursor_binding(
                std::uint64_t integrity_tag,
                std::string_view semantics) const
            {
                std::string key = std::to_string(integrity_tag);
                key.push_back('\0');
                key.append(semantics);
                std::lock_guard<std::mutex> lock(query_cursor_bindings_mutex_);
                auto found = query_cursor_bindings_.find(key);
                if (found == query_cursor_bindings_.end() &&
                    query_cursor_bindings_.size() >= k_query_cursor_binding_capacity) {
                    const auto oldest = (std::min_element)(
                        query_cursor_bindings_.begin(), query_cursor_bindings_.end(),
                        [](const auto& left, const auto& right) {
                            return left.second.sequence < right.second.sequence;
                        });
                    if (oldest != query_cursor_bindings_.end())
                        query_cursor_bindings_.erase(oldest);
                }
                if (query_cursor_binding_sequence_ ==
                    (std::numeric_limits<std::uint64_t>::max)()) {
                    query_cursor_binding_sequence_ = 0;
                    for (auto& entry : query_cursor_bindings_)
                        entry.second.sequence = 0;
                }
                const auto sequence = ++query_cursor_binding_sequence_;
                query_cursor_bindings_[std::move(key)] = {sequence};
            }

            aida::analysis::workspace_result_t<wave_c_query_page_t>
            execute_query_index(
                const workspace_request_context_t& context,
                const aida::analysis::search_query_t& query,
                std::uint64_t offset,
                std::uint64_t limit,
                const json* serialized_cursor,
                std::string_view route_semantics) const
            {
                const auto search = context.workspace->search_index();
                if (!search)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(
                            aida::analysis::make_workspace_error(
                                aida::analysis::workspace_error_code_t::provider_unavailable,
                                "Workspace search index is unavailable.",
                                "mcp_wave_c_query_index"));
                if (serialized_cursor && offset != 0)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(
                            wave_c_query_error(
                                "Query cursor and nonzero offset cannot be combined.",
                                "mcp_wave_c_query_index"));

                const auto deadline = wave_c_deadline(context);
                workspace_call_cancel_bridge_t cancellation(
                    deadline, context.cancellation);
                std::shared_ptr<const aida::analysis::provider_snapshot_t> provider;
                if (std::holds_alternative<
                        aida::analysis::byte_search_query_t>(query)) {
                    auto captured = aida::analysis::provider_snapshot_t::capture(
                        context.workspace->provider_handle(), search->generation(),
                        cancellation.token());
                    if (!captured)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(captured.error());
                    provider = captured.take_value();
                }
                auto built = aida::analysis::query_index_t::build(
                    search, std::move(provider));
                if (!built)
                    return aida::analysis::workspace_result_t<
                        wave_c_query_page_t>::failure(built.error());
                auto index = built.take_value();

                std::optional<aida::analysis::query_cursor_t> cursor;
                if (serialized_cursor) {
                    auto parsed = parse_query_cursor(*serialized_cursor);
                    if (!parsed)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(parsed.error());
                    cursor = parsed.take_value();
                    if (!validate_query_cursor_binding(
                            cursor->integrity_tag, route_semantics)) {
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(
                                wave_c_query_error(
                                    "Query cursor is not valid for this route request.",
                                    "mcp_wave_c_query_cursor_binding"));
                    }
                }

                wave_c_query_page_t output;
                bool source_exhausted = false;
                std::uint64_t skip = offset;
                while (skip != 0) {
                    aida::analysis::query_page_request_t request;
                    request.limit = static_cast<std::uint32_t>((std::min)(
                        skip, static_cast<std::uint64_t>(index->limits().max_page_size)));
                    request.cursor = cursor;
                    auto page = index->query(query, request, cancellation.token());
                    if (!page)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(page.error());
                    auto value = page.take_value();
                    output.total = value.total;
                    output.total_is_exact = value.total_is_exact;
                    const auto consumed = static_cast<std::uint64_t>(value.hits.size());
                    skip = consumed >= skip ? 0 : skip - consumed;
                    cursor = value.next;
                    if (!cursor) {
                        source_exhausted = true;
                        break;
                    }
                }

                std::uint64_t remaining = limit;
                while (!source_exhausted && remaining != 0) {
                    aida::analysis::query_page_request_t request;
                    request.limit = static_cast<std::uint32_t>((std::min)(
                        remaining,
                        static_cast<std::uint64_t>(index->limits().max_page_size)));
                    request.cursor = cursor;
                    auto page = index->query(query, request, cancellation.token());
                    if (!page)
                        return aida::analysis::workspace_result_t<
                            wave_c_query_page_t>::failure(page.error());
                    auto value = page.take_value();
                    output.total = value.total;
                    output.total_is_exact = value.total_is_exact;
                    const auto returned = static_cast<std::uint64_t>(value.hits.size());
                    output.hits.insert(
                        output.hits.end(),
                        std::make_move_iterator(value.hits.begin()),
                        std::make_move_iterator(value.hits.end()));
                    remaining = returned >= remaining ? 0 : remaining - returned;
                    cursor = value.next;
                    if (!cursor)
                        source_exhausted = true;
                }
                output.next = source_exhausted ? std::nullopt : cursor;
                if (output.next) {
                    remember_query_cursor_binding(
                        output.next->integrity_tag, route_semantics);
                }
                return aida::analysis::workspace_result_t<
                    wave_c_query_page_t>::success(std::move(output));
            }

            tool_result_t invoke_analysis_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                const auto cancelled = [&context]() {
                    return context.cancellation_requested();
                };
                if (name == "decompile") {
                    const auto legacy = invoke_legacy(
                        "decompile", json{{"address", arguments.at("addr")}}, context);
                    if (!legacy.success)
                        return tool_result_t::ok(json{
                            {"addr", arguments.at("addr")}, {"code", nullptr},
                            {"error", backend_error(legacy)}});
                    json refs = json::array();
                    for (const auto& callee : legacy.data.value("callees", json::array())) {
                        refs.push_back({
                            {"addr", callee.value("address", std::string())},
                            {"name", callee.value("name", std::string())},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"addr", legacy.data.value(
                            "address", arguments.at("addr").get<std::string>())},
                        {"code", legacy.data.value("pseudocode", std::string())},
                        {"refs", std::move(refs)},
                    });
                }

                if (name == "disasm") {
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto maximum = arguments.value("max_instructions", std::uint64_t{5000});
                    const auto requested = offset > (std::numeric_limits<std::uint64_t>::max)() - maximum
                        ? (std::numeric_limits<std::uint64_t>::max)() : offset + maximum;
                    const auto legacy = invoke_legacy(
                        "disasm", json{{"address", arguments.at("addr")},
                                   {"max_instructions", (std::min)(requested, std::uint64_t{4096})}},
                        context);
                    if (!legacy.success)
                        return tool_result_t::ok(json{
                            {"addr", arguments.at("addr")}, {"asm", nullptr},
                            {"error", backend_error(legacy)}});
                    const auto function = first_generated_function(
                        lookup_analysis_function(arguments.at("addr"), context));
                    json lines = json::array();
                    const auto instructions = legacy.data.value("instructions", json::array());
                    const std::size_t begin = (std::min)(
                        static_cast<std::size_t>(offset), instructions.size());
                    const std::size_t end = (std::min)(
                        instructions.size(), begin + static_cast<std::size_t>(maximum));
                    for (std::size_t index = begin; index < end; ++index) {
                        const auto& instruction = instructions[index];
                        json line{
                            {"addr", instruction.value("address", std::string())},
                            {"instruction", instruction.value(
                                "text", "db " + instruction.value("bytes", std::string()))},
                        };
                        if (const auto comment = instruction.find("comment");
                            comment != instruction.end() && comment->is_string())
                            line["comments"] = json::array({*comment});
                        lines.push_back(std::move(line));
                    }
                    const bool done = end >= instructions.size() &&
                        legacy.data.value("termination", std::string()) == "completed";
                    json assembly{
                        {"name", function ? function->value("name", std::string()) :
                            arguments.at("addr").get<std::string>()},
                        {"start_ea", function ? function->value("addr", std::string()) :
                            arguments.at("addr").get<std::string>()},
                        {"lines", std::move(lines)},
                    };
                    return tool_result_t::ok(json{
                        {"addr", assembly.at("start_ea")}, {"asm", std::move(assembly)},
                        {"instruction_count", end - begin},
                        {"total_instructions", arguments.value("include_total", false)
                            ? json(instructions.size()) : json(nullptr)},
                        {"cursor", json{{"next", end}, {"done", done}, {"cancelled", false}}},
                    });
                }

                if (name == "xrefs_to") {
                    json output = json::array();
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto legacy = invoke_legacy(
                            "xrefs_to", json{{"address", target},
                                       {"limit", arguments.value("limit", 100U)}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json xrefs = json::array();
                            for (const auto& value : legacy.data.value("xrefs", json::array()))
                                xrefs.push_back(generated_xref(value));
                            item["xref_count"] = xrefs.size();
                            item["more"] = xrefs.size() >= arguments.value("limit", 100U);
                            item["xrefs"] = std::move(xrefs);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "xrefs_to_field") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto legacy = invoke_legacy(
                            "xrefs_to_field", json{{"struct_name", query.at("struct")},
                                       {"field_name", query.at("field")}}, context);
                        json item{{"struct", query.at("struct")}, {"field", query.at("field")}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json xrefs = json::array();
                            for (const auto& value : legacy.data.value("xrefs", json::array()))
                                xrefs.push_back(generated_xref(value));
                            item["xrefs"] = std::move(xrefs);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "callees") {
                    json output = json::array();
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto legacy = invoke_legacy(
                            "callees", json{{"address", target}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            json callees = json::array();
                            for (const auto& value : legacy.data.value("callees", json::array())) {
                                callees.push_back({
                                    {"addr", value.value("address", std::string())},
                                    {"name", value.value(
                                        "name", value.value("address", std::string()))},
                                    {"type", value.value("kind", "call")},
                                });
                                if (callees.size() >= arguments.value("limit", 200U))
                                    break;
                            }
                            item["callees"] = std::move(callees);
                            item["more"] = legacy.data.value("count", 0U) >
                                arguments.value("limit", 200U);
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "func_profile") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::string target = query.value("addr", "*");
                        std::vector<json> functions;
                        std::string error;
                        if (!target.empty() && target != "*") {
                            const auto lookup = lookup_analysis_function(target, context);
                            if (!lookup.success) {
                                error = backend_error(lookup);
                            } else {
                                for (const auto& value : lookup.data.value("functions", json::array()))
                                    functions.push_back(value);
                            }
                        } else {
                            const auto listed = invoke_legacy(
                                "list_funcs", json{{"offset", 0}, {"limit", 10000},
                                                   {"filter", query.value("filter", std::string())}},
                                context);
                            if (!listed.success)
                                error = backend_error(listed);
                            else
                                for (const auto& value : listed.data.value("functions", json::array()))
                                    functions.push_back(value);
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(functions.begin(), functions.end(), [&sort_by](const json& lhs, const json& rhs) {
                            if (sort_by == "name")
                                return lhs.value("name", std::string()) < rhs.value("name", std::string());
                            if (sort_by == "size")
                                return json_nonnegative_u64(lhs.value("size", json(0))).value_or(0) <
                                    json_nonnegative_u64(rhs.value("size", json(0))).value_or(0);
                            return lhs.value("address", std::string()) < rhs.value("address", std::string());
                        });
                        if (query.value("descending", false))
                            std::reverse(functions.begin(), functions.end());
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 100, 10000));
                        const std::size_t begin = (std::min)(offset, functions.size());
                        const std::size_t end = (std::min)(functions.size(), begin + count);
                        json data = json::array();
                        for (std::size_t index = begin; index < end; ++index) {
                            const auto& value = functions[index];
                            auto item = generated_function_summary(value);
                            item["basic_block_count"] = value.value("blocks", 0U);
                            item["has_type"] = false;
                            item["error"] = nullptr;
                            if (query.value("include_prototype", false)) {
                                const auto prototype = overlay_type_at(
                                    context, item.value("addr", std::string()));
                                item["prototype"] = prototype ? json(*prototype) : json(nullptr);
                                item["has_type"] = prototype.has_value();
                            }
                            if (query.value("include_lists", false)) {
                                const auto maximum = query.value("max_items", 100U);
                                const auto related = invoke_legacy(
                                    "callees", json{{"address", item.at("addr")}}, context);
                                json callees = json::array();
                                if (related.success) {
                                    for (const auto& callee : related.data.value("callees", json::array())) {
                                        callees.push_back(callee);
                                        if (callees.size() >= maximum)
                                            break;
                                    }
                                }
                                item["callees"] = std::move(callees);
                                item["callee_count"] = item["callees"].size();
                                item["callees_truncated"] = related.success &&
                                    related.data.value("count", 0U) > maximum;
                                item["callers"] = json::array();
                                item["caller_count"] = 0;
                                item["callers_truncated"] = false;
                                item["strings"] = json::array();
                                item["string_ref_count"] = 0;
                                item["strings_truncated"] = false;
                                item["constants"] = json::array();
                                item["constant_count"] = 0;
                                item["constants_truncated"] = false;
                            }
                            data.push_back(std::move(item));
                        }
                        output.push_back({
                            {"target", target}, {"data", std::move(data)},
                            {"next_offset", end < functions.size() ? json(end) : json(nullptr)},
                            {"error", error.empty() ? json(nullptr) : json(error)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "analyze_batch") {
                    json output = json::array();
                    const auto snapshot = context.workspace->snapshot();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::string target = query.at("addr").get<std::string>();
                        const auto lookup = lookup_analysis_function(query.at("addr"), context);
                        const auto function = first_generated_function(lookup);
                        if (!function) {
                            output.push_back({
                                {"target", target}, {"addr", nullptr}, {"name", nullptr},
                                {"analysis", nullptr},
                                {"error", lookup.success
                                    ? std::string("function_not_found") : backend_error(lookup)},
                            });
                            continue;
                        }
                        json analysis{{"size", function->at("size")}};
                        if (query.value("include_proto", false)) {
                            const auto prototype = overlay_type_at(
                                context, function->value("addr", std::string()));
                            analysis["prototype"] = prototype ? json(*prototype) : json(nullptr);
                        }
                        if (query.value("include_basic_blocks", false)) {
                            const auto blocks = invoke_legacy(
                                "basic_blocks", json{{"address", function->at("addr")}}, context);
                            if (blocks.success) {
                                json values = generated_basic_blocks(
                                    blocks.data.value("blocks", json::array()), snapshot);
                                const auto maximum = query.value("max_blocks", 1000U);
                                const bool truncated = values.size() > maximum;
                                while (values.size() > maximum)
                                    values.erase(values.end() - 1);
                                analysis["basic_block_count"] = values.size();
                                analysis["basic_blocks"] = std::move(values);
                                analysis["basic_blocks_truncated"] = truncated;
                            } else {
                                analysis["basic_blocks"] = nullptr;
                            }
                        }
                        if (query.value("include_callees", false)) {
                            const auto related = invoke_legacy(
                                "callees", json{{"address", function->at("addr")}}, context);
                            json values = related.success
                                ? related.data.value("callees", json::array()) : json::array();
                            const auto maximum = query.value("max_callees", 200U);
                            const bool truncated = values.size() > maximum;
                            while (values.size() > maximum)
                                values.erase(values.end() - 1);
                            analysis["callees"] = std::move(values);
                            analysis["callee_count"] = analysis["callees"].size();
                            analysis["callees_truncated"] = truncated;
                        }
                        if (query.value("include_callers", false) ||
                            query.value("include_xrefs", false)) {
                            const auto incoming = invoke_legacy(
                                "xrefs_to", json{{"address", function->at("addr")},
                                                 {"limit", query.value("max_callers", 200U)}},
                                context);
                            json values = incoming.success
                                ? incoming.data.value("xrefs", json::array()) : json::array();
                            if (query.value("include_callers", false)) {
                                analysis["callers"] = values;
                                analysis["caller_count"] = values.size();
                                analysis["callers_truncated"] = incoming.success &&
                                    incoming.data.value("count", 0U) > values.size();
                            }
                            if (query.value("include_xrefs", false)) {
                                analysis["xrefs"] = {
                                    {"to", values}, {"from", json::array()},
                                    {"to_truncated", false}, {"from_truncated", false},
                                    {"to_count", values.size()}, {"from_count", 0},
                                };
                            }
                        }
                        if (query.value("include_decompile", false)) {
                            const auto decompiled = invoke_legacy(
                                "decompile", json{{"address", function->at("addr")}}, context);
                            analysis["decompile"] = decompiled.success
                                ? json(decompiled.data.value("pseudocode", std::string())) : json(nullptr);
                            analysis["decompile_error"] = decompiled.success
                                ? json(nullptr) : json(backend_error(decompiled));
                        }
                        if (query.value("include_disasm", false)) {
                            const auto disassembled = invoke_legacy(
                                "disasm", json{{"address", function->at("addr")},
                                               {"max_instructions", query.value(
                                                   "max_disasm_insns", 1000U)}}, context);
                            if (disassembled.success) {
                                json lines = json::array();
                                for (const auto& instruction :
                                     disassembled.data.value("instructions", json::array()))
                                    lines.push_back(instruction.value(
                                        "text", "db " + instruction.value("bytes", std::string())));
                                analysis["disasm"] = {
                                    {"lines", std::move(lines)},
                                    {"instruction_count", disassembled.data.value("count", 0U)},
                                    {"truncated", disassembled.data.value(
                                        "termination", std::string()) != "completed"},
                                };
                            } else {
                                analysis["disasm"] = nullptr;
                            }
                        }
                        if (query.value("include_strings", false)) {
                            analysis["strings"] = json::array();
                            analysis["string_ref_count"] = 0;
                            analysis["strings_truncated"] = false;
                        }
                        if (query.value("include_constants", false)) {
                            analysis["constants"] = json::array();
                            analysis["constant_count"] = 0;
                            analysis["constants_truncated"] = false;
                        }
                        output.push_back({
                            {"target", target}, {"addr", function->at("addr")},
                            {"name", function->at("name")}, {"analysis", std::move(analysis)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "xref_query") {
                    const auto snapshot = context.workspace->snapshot();
                    if (!snapshot)
                        return tool_result_t::error(
                            "Xref query requires an analysis snapshot.", "NO_SNAPSHOT");
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::string target = query.at("addr").get<std::string>();
                        auto address = wave_c_address_value(query.at("addr"));
                        if (!address) {
                            const auto function = first_generated_function(
                                lookup_analysis_function(query.at("addr"), context));
                            if (function)
                                address = wave_c_address_value(function->at("addr"));
                        }
                        if (!address) {
                            output.push_back({
                                {"target", target}, {"resolved_addr", nullptr},
                                {"data", json::array()}, {"total", 0},
                                {"next_offset", nullptr}, {"error", "target_not_found"},
                            });
                            continue;
                        }
                        const std::string direction = query.value("direction", "both");
                        const std::string type_filter = query.value("xref_type", "any");
                        std::vector<json> matches;
                        for (const auto& xref : snapshot->xrefs) {
                            const bool incoming = xref.target.value == *address;
                            const bool outgoing = xref.source.value == *address;
                            if ((direction == "to" && !incoming) ||
                                (direction == "from" && !outgoing) ||
                                (direction == "both" && !incoming && !outgoing))
                                continue;
                            if ((type_filter == "code" && !code_xref(xref.kind)) ||
                                (type_filter == "data" && code_xref(xref.kind)))
                                continue;
                            const std::string from = hex_addr(xref.source.value);
                            const std::string to = hex_addr(xref.target.value);
                            matches.push_back({
                                {"addr", incoming ? from : to}, {"from", from}, {"to", to},
                                {"type", xref_kind_name(xref.kind)},
                                {"direction", incoming ? "to" : "from"}, {"fn", nullptr},
                            });
                        }
                        if (query.value("dedup", false)) {
                            std::unordered_set<std::string> seen;
                            matches.erase(std::remove_if(matches.begin(), matches.end(), [&seen](const json& value) {
                                return !seen.insert(value.at("addr").get<std::string>() + "\n" +
                                    value.at("type").get<std::string>()).second;
                            }), matches.end());
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(matches.begin(), matches.end(), [&sort_by](const json& lhs, const json& rhs) {
                            return lhs.at(sort_by == "type" ? "type" : "addr").get<std::string>() <
                                rhs.at(sort_by == "type" ? "type" : "addr").get<std::string>();
                        });
                        if (query.value("descending", false))
                            std::reverse(matches.begin(), matches.end());
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 200, 5000));
                        const std::size_t begin = (std::min)(offset, matches.size());
                        const std::size_t end = (std::min)(matches.size(), begin + count);
                        json data = json::array();
                        for (std::size_t index = begin; index < end; ++index)
                            data.push_back(matches[index]);
                        output.push_back({
                            {"target", target}, {"resolved_addr", hex_addr(*address)},
                            {"direction", direction}, {"xref_type", type_filter},
                            {"data", std::move(data)}, {"total", matches.size()},
                            {"next_offset", end < matches.size() ? json(end) : json(nullptr)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find_bytes") {
                    json output = json::array();
                    const auto limit = arguments.value("limit", std::uint64_t{1000});
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto patterns = scalar_or_array_items(arguments.at("patterns"));
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end()) {
                        if (patterns.size() != 1)
                            return tool_result_t::error(
                                "A find_bytes cursor requires exactly one pattern.",
                                "INVALID_QUERY_CURSOR");
                        cursor = &*found;
                    }
                    for (const auto& pattern_value : patterns) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::string pattern = pattern_value.get<std::string>();
                        const auto translated = wildcard_byte_pattern(pattern);
                        if (!translated) {
                            output.push_back({
                                {"pattern", pattern}, {"matches", json::array()}, {"n", 0},
                                {"error", "invalid_byte_pattern"},
                            });
                            continue;
                        }
                        const auto bytes = decode_hex_bytes(translated->first);
                        const auto mask = decode_hex_bytes(translated->second);
                        if (!bytes || !mask)
                            return tool_result_t::error(
                                "Byte pattern normalization failed.",
                                "INVALID_BYTE_PATTERN");
                        aida::analysis::byte_search_query_t query;
                        query.pattern = *bytes;
                        query.mask = *mask;
                        const std::string route_semantics = json{
                            {"tool", "find_bytes"}, {"pattern", pattern}}.dump();
                        auto queried = execute_query_index(
                            context, aida::analysis::search_query_t{std::move(query)},
                            offset, limit, cursor, route_semantics);
                        if (!queried)
                            return workspace_tool_error(queried.error());
                        auto page = queried.take_value();
                        json matches = json::array();
                        for (const auto& hit : page.hits)
                            matches.push_back(hex_addr(hit.address.value));
                        output.push_back({
                            {"pattern", pattern}, {"n", matches.size()}, {"matches", matches},
                            {"cursor", query_cursor_response(page)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "basic_blocks") {
                    json output = json::array();
                    const auto snapshot = context.workspace->snapshot();
                    const std::size_t offset = arguments.value("offset", std::size_t{0});
                    const std::size_t maximum = arguments.value("max_blocks", std::size_t{1000});
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto legacy = invoke_legacy(
                            "basic_blocks", json{{"address", target}}, context);
                        json item{{"addr", target.get<std::string>()}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            const json all_blocks = generated_basic_blocks(
                                legacy.data.value("blocks", json::array()), snapshot);
                            const std::size_t begin = (std::min)(offset, all_blocks.size());
                            const std::size_t end = (std::min)(all_blocks.size(), begin + maximum);
                            json blocks = json::array();
                            for (std::size_t index = begin; index < end; ++index)
                                blocks.push_back(all_blocks[index]);
                            item["blocks"] = std::move(blocks);
                            item["count"] = item["blocks"].size();
                            item["total_blocks"] = all_blocks.size();
                            item["cursor"] = {
                                {"next", end}, {"done", end >= all_blocks.size()},
                                {"cancelled", false},
                            };
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find") {
                    json output = json::array();
                    const std::string search_type = arguments.at("type").get<std::string>();
                    const auto limit = arguments.value("limit", std::uint64_t{1000});
                    const auto offset = arguments.value("offset", std::uint64_t{0});
                    const auto snapshot = context.workspace->snapshot();
                    const auto targets = scalar_or_array_items(arguments.at("targets"));
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end()) {
                        if (targets.size() != 1)
                            return tool_result_t::error(
                                "A find cursor requires exactly one target.",
                                "INVALID_QUERY_CURSOR");
                        cursor = &*found;
                    }
                    for (const auto& target : targets) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::string route_semantics = json{
                            {"tool", "find"}, {"type", search_type},
                            {"target", target}}.dump();
                        json matches = json::array();
                        wave_c_query_page_t page;
                        if (search_type == "data_ref" || search_type == "code_ref") {
                            const auto address = wave_c_address_value(target);
                            if (!address || !snapshot) {
                                return tool_result_t::error(
                                    address ? "Analysis snapshot is unavailable." :
                                        "Reference target is invalid.",
                                    address ? "NO_SNAPSHOT" : "INVALID_REFERENCE_TARGET");
                            }
                            std::unordered_set<std::uint64_t> sources;
                            for (const auto& xref : snapshot->xrefs) {
                                if (xref.target.value == *address &&
                                    (search_type == "code_ref") == code_xref(xref.kind))
                                    sources.insert(xref.source.value);
                            }
                            if (sources.empty()) {
                                if (cursor)
                                    return tool_result_t::error(
                                        "Reference query cursor has no current source set.",
                                        "INVALID_QUERY_CURSOR");
                            } else {
                                const auto bounds = (std::minmax_element)(
                                    sources.begin(), sources.end());
                                if (*bounds.second ==
                                    (std::numeric_limits<std::uint64_t>::max)()) {
                                    return tool_result_t::error(
                                        "Reference sources cannot be represented as an address range.",
                                        "INVALID_REFERENCE_TARGET");
                                }
                                aida::analysis::address_search_query_t address_query;
                                address_query.begin = {
                                    aida::analysis::address_space_id_t::relative_virtual,
                                    *bounds.first,
                                    context.workspace->identity().architecture(),
                                    context.workspace->identity().architecture_mode(),
                                };
                                address_query.end = address_query.begin;
                                address_query.end.value = *bounds.second + 1U;
                                auto queried = execute_query_index(
                                    context,
                                    aida::analysis::search_query_t{address_query},
                                    offset, limit, cursor, route_semantics);
                                if (!queried)
                                    return workspace_tool_error(queried.error());
                                page = queried.take_value();
                                std::unordered_set<std::uint64_t> emitted;
                                for (const auto& hit : page.hits) {
                                    if (sources.find(hit.address.value) != sources.end() &&
                                        emitted.insert(hit.address.value).second) {
                                        matches.push_back(hex_addr(hit.address.value));
                                    }
                                }
                            }
                        } else {
                            aida::analysis::search_query_t query;
                            if (search_type == "string") {
                                aida::analysis::literal_search_query_t literal;
                                literal.text = target.is_string()
                                    ? target.get<std::string>() : target.dump();
                                literal.case_sensitive = false;
                                query = std::move(literal);
                            } else {
                                const auto immediate = wave_c_address_value(target);
                                if (!immediate)
                                    return tool_result_t::error(
                                        "Immediate search target is invalid.",
                                        "INVALID_IMMEDIATE_TARGET");
                                aida::analysis::instruction_search_query_t instruction;
                                instruction.filter.immediate = *immediate;
                                query = std::move(instruction);
                            }
                            auto queried = execute_query_index(
                                context, query, offset, limit, cursor,
                                route_semantics);
                            if (!queried)
                                return workspace_tool_error(queried.error());
                            page = queried.take_value();
                            for (const auto& hit : page.hits) {
                                if (search_type == "string" && hit.kind !=
                                    aida::analysis::search_entity_kind_t::string)
                                    continue;
                                matches.push_back(hex_addr(hit.address.value));
                            }
                        }
                        output.push_back({
                            {"query", target}, {"matches", matches}, {"count", matches.size()},
                            {"cursor", query_cursor_response(page)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "insn_query") {
                    const auto snapshot = context.workspace->snapshot();
                    if (!snapshot)
                        return tool_result_t::error(
                            "Instruction query requires an analysis snapshot.", "NO_SNAPSHOT");
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const std::size_t offset = query.value("offset", std::size_t{0});
                        const std::size_t count = static_cast<std::size_t>(
                            query_count(query, 100, 5000));
                        std::optional<std::uint64_t> range_start;
                        std::optional<std::uint64_t> range_end;
                        if (const auto start = query.find("start"); start != query.end())
                            range_start = wave_c_address_value(*start);
                        if (const auto end = query.find("end"); end != query.end())
                            range_end = wave_c_address_value(*end);
                        if (const auto function = query.find("func");
                            function != query.end() && function->is_string()) {
                            const auto resolved = first_generated_function(
                                lookup_analysis_function(*function, context));
                            if (resolved) {
                                range_start = wave_c_address_value(resolved->at("addr"));
                                const auto size = wave_c_address_value(resolved->at("size"));
                                if (range_start && size && *size <=
                                    (std::numeric_limits<std::uint64_t>::max)() - *range_start)
                                    range_end = *range_start + *size;
                            }
                        }
                        json raw_matches = json::array();
                        std::size_t scanned = 0;
                        bool truncated = false;
                        std::string error;
                        const std::string mnemonic = query.value("mnem", std::string());
                        if (!mnemonic.empty()) {
                            std::string operand;
                            for (const char* field : {"op_any", "op0", "op1", "op2"}) {
                                const auto found = query.find(field);
                                if (found != query.end()) {
                                    operand = found->is_string()
                                        ? found->get<std::string>() : found->dump();
                                    break;
                                }
                            }
                            const auto legacy = invoke_legacy(
                                "find_insns", json{{"mnemonic", mnemonic},
                                                   {"operand_pattern", operand}, {"offset", 0},
                                                   {"limit", query.value("max_scan_insns", 50000U)}},
                                context);
                            if (!legacy.success) {
                                error = backend_error(legacy);
                            } else {
                                raw_matches = legacy.data.value("results", json::array());
                                scanned = legacy.data.value(
                                    "formatted", legacy.data.value("count", std::size_t{0}));
                                truncated = legacy.data.value("format_scan_truncated", false);
                            }
                        } else {
                            scanned = snapshot->instructions.size();
                            for (const auto& instruction : snapshot->instructions) {
                                raw_matches.push_back({
                                    {"address", hex_addr(instruction.address.value)},
                                    {"mnemonic_id", instruction.mnemonic_id},
                                });
                            }
                        }
                        json filtered = json::array();
                        for (const auto& value : raw_matches) {
                            const auto address = wave_c_address_value(
                                value.value("address", json()));
                            if (!address || (range_start && *address < *range_start) ||
                                (range_end && *address >= *range_end))
                                continue;
                            filtered.push_back(value);
                        }
                        const std::size_t begin = (std::min)(offset, filtered.size());
                        const std::size_t end = (std::min)(filtered.size(), begin + count);
                        json matches = json::array();
                        for (std::size_t index = begin; index < end; ++index) {
                            const auto& value = filtered[index];
                            json match{{"addr", value.value("address", std::string())}};
                            if (query.value("include_disasm", false))
                                match["disasm"] = value.value("text", std::string());
                            if (query.value("include_fn", false)) {
                                const auto function = first_generated_function(
                                    lookup_analysis_function(match.at("addr"), context));
                                match["fn"] = function ? json(*function) : json(nullptr);
                            }
                            matches.push_back(std::move(match));
                        }
                        json normalized_query = json::object();
                        for (const char* field : {
                                 "allow_broad", "count", "end", "func", "max_scan_insns",
                                 "mnem", "offset", "op0", "op1", "op2", "op_any",
                                 "segment", "start"}) {
                            if (query.contains(field))
                                normalized_query[field] = query.at(field);
                        }
                        json ranges = json::array();
                        if (range_start && range_end)
                            ranges.push_back({
                                {"start", hex_addr(*range_start)}, {"end", hex_addr(*range_end)}});
                        output.push_back({
                            {"query", std::move(normalized_query)}, {"matches", std::move(matches)},
                            {"count", end - begin}, {"scanned", scanned}, {"ranges", std::move(ranges)},
                            {"truncated", truncated || end < filtered.size()},
                            {"next_start", end < filtered.size()
                                ? json(filtered[end].value("address", std::string())) : json(nullptr)},
                            {"cursor", json{{"next", end}, {"done", end >= filtered.size()},
                                             {"cancelled", false}}},
                            {"error", error.empty() ? json(nullptr) : json(error)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "export_funcs") {
                    const std::string format = arguments.value("format", "json");
                    json functions = json::array();
                    std::string header;
                    for (const auto& target : scalar_or_array_items(arguments.at("addrs"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto lookup = lookup_analysis_function(target, context);
                        const auto function = first_generated_function(lookup);
                        if (!function) {
                            if (format == "json")
                                functions.push_back({
                                    {"addr", target.get<std::string>()},
                                    {"error", backend_error(lookup)},
                                });
                            else
                                functions.push_back({{"name", nullptr}});
                            continue;
                        }
                        const auto prototype = overlay_type_at(
                            context, function->value("addr", std::string()));
                        if (format == "c_header") {
                            if (prototype) {
                                header.append(*prototype);
                                if (header.empty() || header.back() != ';')
                                    header.push_back(';');
                                header.push_back('\n');
                            }
                            continue;
                        }
                        if (format == "prototypes") {
                            json item{{"name", function->at("name")}};
                            if (prototype)
                                item["prototype"] = *prototype;
                            functions.push_back(std::move(item));
                            continue;
                        }
                        json item{
                            {"addr", function->at("addr")}, {"name", function->at("name")},
                            {"size", function->at("size")},
                            {"prototype", prototype ? json(*prototype) : json(nullptr)},
                        };
                        const auto decompiled = invoke_legacy(
                            "decompile", json{{"address", function->at("addr")}}, context);
                        item["code"] = decompiled.success
                            ? json(decompiled.data.value("pseudocode", std::string())) : json(nullptr);
                        item["decompile_error"] = decompiled.success
                            ? json(nullptr) : json(backend_error(decompiled));
                        const auto disassembled = invoke_legacy(
                            "disasm", json{{"address", function->at("addr")},
                                           {"max_instructions", 4096}}, context);
                        if (disassembled.success) {
                            std::string assembly;
                            for (const auto& instruction :
                                 disassembled.data.value("instructions", json::array())) {
                                assembly.append(instruction.value("address", std::string()));
                                assembly.append("  ");
                                assembly.append(instruction.value(
                                    "text", "db " + instruction.value("bytes", std::string())));
                                assembly.push_back('\n');
                            }
                            item["asm"] = std::move(assembly);
                        }
                        functions.push_back(std::move(item));
                    }
                    if (format == "c_header")
                        return tool_result_t::ok(json{{"format", format}, {"content", std::move(header)}});
                    return tool_result_t::ok(json{{"format", format}, {"functions", std::move(functions)}});
                }

                if (name == "callgraph") {
                    json output = json::array();
                    const auto max_nodes = arguments.value("max_nodes", std::size_t{1000});
                    const auto max_edges = arguments.value("max_edges", std::size_t{5000});
                    for (const auto& root : scalar_or_array_items(arguments.at("roots"))) {
                        if (cancelled())
                            return tool_result_t::error("Analysis request cancelled.", "CANCELLED");
                        const auto legacy = invoke_legacy(
                            "callgraph", json{{"address", root},
                                       {"depth", arguments.value("max_depth", 5U)},
                                       {"direction", "both"},
                                       {"limit", (std::min)(max_nodes, std::size_t{5000})}},
                            context);
                        if (!legacy.success) {
                            output.push_back({
                                {"root", root.get<std::string>()}, {"nodes", json::array()},
                                {"edges", json::array()}, {"truncated", false},
                                {"limit_reason", nullptr}, {"error", backend_error(legacy)},
                            });
                            continue;
                        }
                        json nodes = json::array();
                        for (const auto& value : legacy.data.value("nodes", json::array())) {
                            if (nodes.size() >= max_nodes)
                                break;
                            nodes.push_back({
                                {"addr", value.value("address", std::string())},
                                {"name", value.contains("name") ? value.at("name") : json(nullptr)},
                                {"depth", value.value("depth", 0)},
                            });
                        }
                        json edges = json::array();
                        for (const auto& value : legacy.data.value("edges", json::array())) {
                            if (edges.size() >= max_edges)
                                break;
                            edges.push_back({
                                {"from", value.value("from", std::string())},
                                {"to", value.value("to", std::string())},
                                {"type", value.value("kind", "call")},
                            });
                        }
                        const bool truncated = legacy.data.value("truncated", false) ||
                            legacy.data.value("node_count", nodes.size()) > nodes.size() ||
                            legacy.data.value("edge_count", edges.size()) > edges.size();
                        output.push_back({
                            {"root", root.get<std::string>()}, {"nodes", std::move(nodes)},
                            {"edges", std::move(edges)},
                            {"max_depth", arguments.value("max_depth", 5U)},
                            {"max_nodes", max_nodes}, {"max_edges", max_edges},
                            {"max_edges_per_func", arguments.value("max_edges_per_func", 200U)},
                            {"per_func_capped", false}, {"truncated", truncated},
                            {"limit_reason", truncated ? json("bounded_graph_limit") : json(nullptr)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                return tool_result_t::error(
                    "Analysis adapter is not registered for " + std::string(name) + ".",
                    "MCP_BACKEND_UNAVAILABLE");
            }

            static std::uint64_t query_count(
                const json& query, std::uint64_t fallback,
                std::uint64_t maximum)
            {
                const auto found = query.find("count");
                if (found == query.end())
                    return fallback;
                const auto value = json_nonnegative_u64(*found);
                if (!value || *value == 0)
                    return maximum;
                return (std::min)(*value, maximum);
            }

            tool_result_t invoke_core_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (name == "server_health") {
                    const auto snapshot = context.workspace->snapshot();
                    const auto image = context.workspace->normalized_image();
                    return tool_result_t::ok(json{
                        {"status", "ok"},
                        {"uptime_sec", static_cast<std::uint64_t>(GetTickCount64() / 1000ULL)},
                        {"idb_path", nullptr},
                        {"module", context.workspace->identity().bin_name()},
                        {"input_path", context.workspace->identity().normalized_source_path()},
                        {"imagebase", image ? hex_addr(image->image_base) : std::string("0x0")},
                        {"auto_analysis_ready", snapshot && snapshot->baseline_complete},
                        {"hexrays_ready", false},
                        {"strings_cache_ready", snapshot != nullptr},
                        {"strings_cache_size", snapshot ? snapshot->strings.size() : 0U},
                    });
                }
                if (name == "idb_save")
                    return checkpoint_workspace(context);

                if (name == "lookup_funcs") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const std::string query_text = query.get<std::string>();
                        json request;
                        request[wave_c_address_value(query) ? "address" : "name"] = query;
                        const auto legacy = invoke_legacy("lookup_funcs", request, context);
                        json item{{"query", query_text}, {"fn", nullptr}, {"error", nullptr}};
                        if (!legacy.success) {
                            item["error"] = backend_error(legacy);
                        } else {
                            const auto functions = legacy.data.find("functions");
                            if (functions != legacy.data.end() && functions->is_array() &&
                                !functions->empty())
                                item["fn"] = generated_function_summary(functions->front());
                            else
                                item["error"] = "function_not_found";
                        }
                        output.push_back(std::move(item));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "list_funcs" || name == "list_globals") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const json request{
                            {"offset", offset}, {"limit", count},
                            {"filter", query.value("filter", std::string())},
                        };
                        const auto legacy = name == "list_funcs"
                            ? invoke_legacy("list_funcs", request, context)
                            : invoke_legacy("list_globals", request, context);
                        if (!legacy.success)
                            return legacy;
                        const char* collection = name == "list_funcs" ? "functions" : "globals";
                        json data = json::array();
                        const auto values = legacy.data.find(collection);
                        if (values != legacy.data.end() && values->is_array()) {
                            for (const auto& value : *values) {
                                if (name == "list_funcs") {
                                    data.push_back(generated_function_summary(value));
                                } else {
                                    data.push_back({
                                        {"addr", value.value("address", std::string())},
                                        {"name", value.value("name", std::string())},
                                    });
                                }
                            }
                        }
                        output.push_back({
                            {"data", std::move(data)},
                            {"next_offset", legacy.data.value("next_offset", json(nullptr))},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "func_query") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const auto legacy = invoke_legacy(
                            "list_funcs",
                            json{{"offset", 0}, {"limit", 10000},
                                 {"filter", query.value("filter", std::string())}},
                            context);
                        if (!legacy.success) {
                            output.push_back({
                                {"data", json::array()}, {"next_offset", nullptr},
                                {"error", backend_error(legacy)},
                            });
                            continue;
                        }
                        std::optional<std::regex> name_pattern;
                        if (const auto regex_value = query.find("name_regex");
                            regex_value != query.end() && regex_value->is_string() &&
                            !regex_value->get_ref<const std::string&>().empty()) {
                            try {
                                name_pattern.emplace(
                                    regex_value->get<std::string>(),
                                    std::regex::ECMAScript | std::regex::optimize);
                            } catch (const std::regex_error&) {
                                output.push_back({
                                    {"data", json::array()}, {"next_offset", nullptr},
                                    {"error", "invalid_name_regex"},
                                });
                                continue;
                            }
                        }
                        std::vector<json> matches;
                        for (const auto& value : legacy.data.value("functions", json::array())) {
                            const auto size = json_nonnegative_u64(value.value("size", json(0))).value_or(0);
                            const auto minimum = query.value("min_size", std::uint64_t{0});
                            const auto maximum = query.value(
                                "max_size", (std::numeric_limits<std::uint64_t>::max)());
                            const std::string function_name = value.value("name", std::string());
                            if (size < minimum || size > maximum ||
                                (name_pattern && !std::regex_search(function_name, *name_pattern)) ||
                                query.value("has_type", false))
                                continue;
                            auto item = generated_function_summary(value);
                            item["size_int"] = size;
                            item["has_type"] = false;
                            matches.push_back(std::move(item));
                        }
                        const std::string sort_by = query.value("sort_by", "addr");
                        std::sort(matches.begin(), matches.end(), [&sort_by](const json& lhs, const json& rhs) {
                            if (sort_by == "name")
                                return lhs.at("name").get_ref<const std::string&>() <
                                    rhs.at("name").get_ref<const std::string&>();
                            if (sort_by == "size")
                                return lhs.at("size_int").get<std::uint64_t>() <
                                    rhs.at("size_int").get<std::uint64_t>();
                            return lhs.at("addr").get_ref<const std::string&>() <
                                rhs.at("addr").get_ref<const std::string&>();
                        });
                        if (query.value("descending", false))
                            std::reverse(matches.begin(), matches.end());
                        json data = json::array();
                        const std::size_t begin = (std::min)(
                            static_cast<std::size_t>(offset), matches.size());
                        const std::size_t end = (std::min)(
                            matches.size(), begin + static_cast<std::size_t>(count));
                        for (std::size_t index = begin; index < end; ++index)
                            data.push_back(matches[index]);
                        output.push_back({
                            {"data", std::move(data)},
                            {"next_offset", end < matches.size() ? json(end) : json(nullptr)},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "imports" || name == "imports_query") {
                    const auto execute = [this, &context](const json& query) {
                        const auto offset = query.value("offset", std::uint64_t{0});
                        const auto count = query_count(query, 100, 10000);
                        const auto legacy = invoke_legacy(
                            "imports",
                            json{{"offset", offset}, {"limit", count},
                                 {"module", query.value("module", std::string())}},
                            context);
                        if (!legacy.success)
                            return std::pair<tool_result_t, json>{legacy, json()};
                        json data = json::array();
                        const std::string filter = query.value("filter", std::string());
                        for (const auto& value : legacy.data.value("imports", json::array())) {
                            const auto item = generated_import_summary(value);
                            if (!filter.empty() &&
                                item.at("imported_name").get_ref<const std::string&>().find(filter) ==
                                    std::string::npos)
                                continue;
                            data.push_back(item);
                        }
                        return std::pair<tool_result_t, json>{
                            tool_result_t::ok(""),
                            json{{"data", std::move(data)},
                                 {"next_offset", legacy.data.value("next_offset", json(nullptr))}},
                        };
                    };
                    if (name == "imports") {
                        auto [status, value] = execute(arguments);
                        return status.success ? tool_result_t::ok(value) : status;
                    }
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        auto [status, value] = execute(query);
                        if (!status.success)
                            return status;
                        output.push_back(std::move(value));
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "entity_query") {
                    json output = json::array();
                    for (const auto& query : scalar_or_array_items(arguments.at("queries"))) {
                        const std::string kind = query.at("kind").get<std::string>();
                        aida::analysis::entity_search_query_t entity_query;
                        using entity_kind_t = aida::analysis::search_entity_kind_t;
                        if (kind == "functions")
                            entity_query.filter.kind = entity_kind_t::function;
                        else if (kind == "globals")
                            entity_query.filter.kind = entity_kind_t::data_candidate;
                        else if (kind == "imports" || kind == "symbols")
                            entity_query.filter.kind = entity_kind_t::symbol;
                        else if (kind == "strings")
                            entity_query.filter.kind = entity_kind_t::string;
                        else if (kind == "types")
                            entity_query.filter.kind = entity_kind_t::type_candidate;
                        const std::string filter = query.value("filter", std::string());
                        const std::string regex_text = query.value("regex", std::string());
                        std::shared_ptr<const aida::analysis::regex_query_t> pattern;
                        if (!regex_text.empty()) {
                            auto compiled = aida::analysis::regex_query_t::compile(regex_text);
                            if (!compiled)
                                return workspace_tool_error(compiled.error());
                            pattern = compiled.take_value();
                        }
                        auto queried = execute_query_index(
                            context,
                            aida::analysis::search_query_t{std::move(entity_query)},
                            query.value("offset", std::uint64_t{0}),
                            query_count(query, 100, 10000), nullptr,
                            json{{"tool", "entity_query"}, {"query", query}}.dump());
                        if (!queried)
                            return workspace_tool_error(queried.error());
                        auto page = queried.take_value();
                        json data = json::array();
                        for (const auto& hit : page.hits) {
                            if (context.cancellation_requested())
                                return tool_result_t::error(
                                    "Entity query was cancelled.", "CANCELLED");
                            if (!filter.empty() && hit.text.find(filter) == std::string::npos)
                                continue;
                            if (pattern) {
                                auto matched = pattern->match(hit.text);
                                if (!matched)
                                    return workspace_tool_error(matched.error());
                                if (!matched.value().matched)
                                    continue;
                            }
                            if (kind == "strings") {
                                data.push_back({
                                    {"addr", hex_addr(hit.address.value)},
                                    {"value", hit.text},
                                    {"length", hit.text.size()},
                                });
                            } else {
                                data.push_back({
                                    {"addr", hex_addr(hit.address.value)},
                                    {kind == "imports" ? "imported_name" : "name", hit.text},
                                });
                            }
                        }
                        output.push_back({
                            {"kind", kind}, {"data", std::move(data)},
                            {"total", page.total},
                            {"next_offset", page.next
                                ? json(page.next->position) : json(nullptr)},
                            {"error", nullptr},
                        });
                    }
                    return tool_result_t::ok(json{{"result", std::move(output)}});
                }

                if (name == "find_regex") {
                    aida::analysis::regex_search_query_t query;
                    query.pattern = arguments.at("pattern").get<std::string>();
                    query.options.case_sensitive = false;
                    auto compiled = aida::analysis::regex_query_t::compile(
                        query.pattern, query.options);
                    if (!compiled)
                        return workspace_tool_error(compiled.error());
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end())
                        cursor = &*found;
                    auto queried = execute_query_index(
                        context,
                        aida::analysis::search_query_t{std::move(query)},
                        arguments.value("offset", std::uint64_t{0}),
                        arguments.value("limit", std::uint64_t{30}),
                        cursor,
                        json{{"tool", "find_regex"},
                             {"pattern", arguments.at("pattern")},
                             {"case_sensitive", false}}.dump());
                    if (!queried)
                        return workspace_tool_error(queried.error());
                    auto page = queried.take_value();
                    json matches = json::array();
                    for (const auto& hit : page.hits) {
                        if (hit.kind != aida::analysis::search_entity_kind_t::string)
                            continue;
                        matches.push_back({
                            {"address", hex_addr(hit.address.value)},
                            {"text", hit.text},
                            {"kind", query_hit_kind_name(hit.kind)},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"matches", matches}, {"n", matches.size()},
                        {"error", nullptr},
                        {"cursor", query_cursor_response(page)},
                    });
                }

                if (name == "search_text") {
                    const bool use_regex = arguments.value("regex", false);
                    const bool case_sensitive = arguments.value("case_sensitive", false);
                    const std::string pattern = arguments.at("pattern").get<std::string>();
                    aida::analysis::search_query_t query;
                    if (use_regex) {
                        aida::analysis::regex_search_query_t regex_query;
                        regex_query.pattern = pattern;
                        regex_query.options.case_sensitive = case_sensitive;
                        auto compiled = aida::analysis::regex_query_t::compile(
                            regex_query.pattern, regex_query.options);
                        if (!compiled)
                            return workspace_tool_error(compiled.error());
                        query = std::move(regex_query);
                    } else {
                        aida::analysis::literal_search_query_t literal;
                        literal.text = pattern;
                        literal.case_sensitive = case_sensitive;
                        query = std::move(literal);
                    }
                    const json* cursor = nullptr;
                    if (const auto found = arguments.find("cursor"); found != arguments.end())
                        cursor = &*found;
                    wave_c_signature_source_t address_source(context);
                    const auto resolve_bound = [&arguments, &address_source](
                        const char* key) -> std::optional<std::uint64_t> {
                        const auto found = arguments.find(key);
                        if (found == arguments.end() || found->is_null() ||
                            (found->is_string() && found->get_ref<
                                const std::string&>().empty()))
                            return std::nullopt;
                        if (found->is_string())
                            return address_source.resolve_address(
                                found->get_ref<const std::string&>());
                        return wave_c_address_value(*found);
                    };
                    const auto start = resolve_bound("start");
                    const auto end = resolve_bound("end");
                    if ((arguments.contains("start") &&
                         !arguments.at("start").is_null() &&
                         !(arguments.at("start").is_string() &&
                           arguments.at("start").get_ref<
                               const std::string&>().empty()) && !start) ||
                        (arguments.contains("end") &&
                         !arguments.at("end").is_null() &&
                         !(arguments.at("end").is_string() &&
                           arguments.at("end").get_ref<
                               const std::string&>().empty()) && !end) ||
                        (start && end && *end < *start)) {
                        return tool_result_t::error(
                            "Search text bounds are invalid.",
                            "INVALID_SEARCH_RANGE");
                    }
                    const bool code_only = arguments.value("code_only", true);
                    const std::string include_mode =
                        arguments.value("include", std::string("all"));
                    const std::string route_semantics = json{
                        {"tool", "search_text"}, {"pattern", pattern},
                        {"regex", use_regex}, {"case_sensitive", case_sensitive},
                        {"start", start ? json(*start) : json(nullptr)},
                        {"end", end ? json(*end) : json(nullptr)},
                        {"code_only", code_only}, {"include", include_mode}}.dump();
                    auto queried = execute_query_index(
                        context, query, 0,
                        arguments.value("limit", std::uint64_t{30}), cursor,
                        route_semantics);
                    if (!queried)
                        return workspace_tool_error(queried.error());
                    auto page = queried.take_value();
                    const auto image = context.workspace->normalized_image();
                    json hits = json::array();
                    for (const auto& hit : page.hits) {
                        const std::string kind = query_hit_kind_name(hit.kind);
                        const bool executable = query_address_is_executable(
                            image.get(), hit.address);
                        if ((start && hit.address.value < *start) ||
                            (end && hit.address.value >= *end) ||
                            (code_only && !executable) ||
                            (include_mode == "disasm" && !executable) ||
                            (include_mode == "comments" && hit.kind ==
                                aida::analysis::search_entity_kind_t::instruction))
                            continue;
                        hits.push_back({
                            {"addr", hex_addr(hit.address.value)},
                            {"matches", json::array({json{
                                {"kind", kind}, {"text", hit.text}}})},
                        });
                    }
                    return tool_result_t::ok(json{
                        {"hits", hits}, {"n", hits.size()},
                        {"cursor", query_cursor_response(page)},
                    });
                }

                if (name == "int_convert")
                    return invoke_legacy("int_convert", arguments, context);
                return tool_result_t::error(
                    "Core adapter is not registered for " + std::string(name) + ".",
                    "MCP_BACKEND_UNAVAILABLE");
            }

            struct assembly_register_t final {
                int index = -1;
                std::uint8_t width = 0;
            };

            static std::string assembly_trim(std::string value)
            {
                const auto begin = value.find_first_not_of(" \t\r\n");
                if (begin == std::string::npos)
                    return {};
                const auto end = value.find_last_not_of(" \t\r\n");
                value = value.substr(begin, end - begin + 1U);
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
                    return static_cast<char>(std::toupper(ch));
                });
                return value;
            }

            static std::optional<assembly_register_t> assembly_register(
                std::string value)
            {
                value = assembly_trim(std::move(value));
                static const std::array<const char*, 8> registers64{
                    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"};
                static const std::array<const char*, 8> registers32{
                    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
                static const std::array<const char*, 8> registers16{
                    "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"};
                static const std::array<const char*, 4> registers8{
                    "AL", "CL", "DL", "BL"};
                for (std::size_t index = 0; index < registers64.size(); ++index) {
                    if (value == registers64[index])
                        return assembly_register_t{static_cast<int>(index), 64};
                    if (value == registers32[index])
                        return assembly_register_t{static_cast<int>(index), 32};
                    if (value == registers16[index])
                        return assembly_register_t{static_cast<int>(index), 16};
                }
                for (std::size_t index = 0; index < registers8.size(); ++index) {
                    if (value == registers8[index])
                        return assembly_register_t{static_cast<int>(index), 8};
                }
                if (value.size() < 2U || value.front() != 'R' ||
                    value[1] < '8' || value[1] > '9')
                    return std::nullopt;
                std::size_t digit_end = 1U;
                while (digit_end < value.size() && std::isdigit(
                    static_cast<unsigned char>(value[digit_end])))
                    ++digit_end;
                int index = -1;
                try {
                    index = std::stoi(value.substr(1U, digit_end - 1U));
                } catch (...) {
                    return std::nullopt;
                }
                if (index < 8 || index > 15)
                    return std::nullopt;
                const std::string suffix = value.substr(digit_end);
                if (suffix.empty())
                    return assembly_register_t{index, 64};
                if (suffix == "D")
                    return assembly_register_t{index, 32};
                if (suffix == "W")
                    return assembly_register_t{index, 16};
                if (suffix == "B")
                    return assembly_register_t{index, 8};
                return std::nullopt;
            }

            static std::optional<std::int64_t> assembly_integer(std::string value)
            {
                value = assembly_trim(std::move(value));
                for (const std::string prefix : {"SHORT ", "NEAR ", "OFFSET "}) {
                    if (value.rfind(prefix, 0) == 0)
                        value.erase(0, prefix.size());
                }
                if (value.empty())
                    return std::nullopt;
                try {
                    std::size_t consumed = 0;
                    int base = 0;
                    if (value.size() > 1U && value.back() == 'H') {
                        value.pop_back();
                        base = 16;
                    }
                    const auto parsed = std::stoll(value, &consumed, base);
                    return consumed == value.size()
                        ? std::optional<std::int64_t>(parsed) : std::nullopt;
                } catch (...) {
                    return std::nullopt;
                }
            }

            static void append_little_endian(
                std::vector<std::uint8_t>& output,
                std::uint64_t value,
                std::size_t width)
            {
                for (std::size_t index = 0; index < width; ++index)
                    output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
            }

            static bool append_rex(
                std::vector<std::uint8_t>& output,
                std::uint8_t width,
                int reg,
                int base,
                bool force = false)
            {
                if (width == 16)
                    output.push_back(0x66U);
                if (width == 8 && (reg >= 4 || base >= 4) && reg < 8 && base < 8)
                    return false;
                std::uint8_t rex = 0x40U;
                if (width == 64)
                    rex |= 0x08U;
                if (reg >= 8)
                    rex |= 0x04U;
                if (base >= 8)
                    rex |= 0x01U;
                if (rex != 0x40U || force)
                    output.push_back(rex);
                return true;
            }

            static bool append_relative32(
                std::vector<std::uint8_t>& output,
                std::uint64_t target,
                std::uint64_t next)
            {
                const auto difference = target >= next
                    ? static_cast<std::uint64_t>(target - next)
                    : static_cast<std::uint64_t>(next - target);
                if (difference > static_cast<std::uint64_t>(
                    (std::numeric_limits<std::int32_t>::max)()) + (target < next ? 1ULL : 0ULL))
                    return false;
                const auto relative = target >= next
                    ? static_cast<std::int64_t>(difference)
                    : -static_cast<std::int64_t>(difference);
                append_little_endian(
                    output, static_cast<std::uint32_t>(static_cast<std::int32_t>(relative)), 4U);
                return true;
            }

            static std::optional<std::uint64_t> assembly_next_address(
                std::uint64_t base_address,
                std::size_t encoded_size,
                std::size_t trailing_size)
            {
                const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
                if (encoded_size > maximum - base_address)
                    return std::nullopt;
                const auto encoded_end = base_address + encoded_size;
                if (trailing_size > maximum - encoded_end)
                    return std::nullopt;
                return encoded_end + trailing_size;
            }

            static std::optional<std::vector<std::uint8_t>> assemble_x86_overlay(
                std::string assembly,
                std::uint64_t base_address,
                bool mode64,
                std::string& error)
            {
                std::replace(assembly.begin(), assembly.end(), ';', '\n');
                std::istringstream stream(assembly);
                std::vector<std::uint8_t> output;
                std::string line;
                std::size_t line_number = 0;
                while (std::getline(stream, line)) {
                    ++line_number;
                    line = assembly_trim(std::move(line));
                    if (line.empty())
                        continue;
                    const auto separator = line.find_first_of(" \t");
                    const std::string mnemonic = separator == std::string::npos
                        ? line : line.substr(0, separator);
                    const std::string operands = separator == std::string::npos
                        ? std::string() : assembly_trim(line.substr(separator + 1U));
                    std::vector<std::string> values;
                    std::size_t begin = 0;
                    while (begin <= operands.size() && !operands.empty()) {
                        const auto comma = operands.find(',', begin);
                        values.push_back(assembly_trim(operands.substr(
                            begin, comma == std::string::npos
                                ? operands.size() - begin : comma - begin)));
                        if (comma == std::string::npos)
                            break;
                        begin = comma + 1U;
                    }
                    const auto reject = [&error, line_number, &line](std::string reason) {
                        error = "assembly line " + std::to_string(line_number) +
                            " rejected: " + std::move(reason) + " [" + line + "]";
                        return std::optional<std::vector<std::uint8_t>>{};
                    };
                    if (mnemonic == "NOP" && values.empty()) {
                        output.push_back(0x90U);
                        continue;
                    }
                    if (mnemonic == "INT3" && values.empty()) {
                        output.push_back(0xCCU);
                        continue;
                    }
                    if (mnemonic == "UD2" && values.empty()) {
                        output.insert(output.end(), {0x0FU, 0x0BU});
                        continue;
                    }
                    if (mnemonic == "LEAVE" && values.empty()) {
                        output.push_back(0xC9U);
                        continue;
                    }
                    if (mnemonic == "SYSCALL" && values.empty() && mode64) {
                        output.insert(output.end(), {0x0FU, 0x05U});
                        continue;
                    }
                    if ((mnemonic == "RET" || mnemonic == "RETN") && values.size() <= 1U) {
                        if (values.empty()) {
                            output.push_back(0xC3U);
                        } else {
                            const auto immediate = assembly_integer(values.front());
                            if (!immediate || *immediate < 0 || *immediate > 0xFFFF)
                                return reject("RET immediate must fit uint16");
                            output.push_back(0xC2U);
                            append_little_endian(output, static_cast<std::uint64_t>(*immediate), 2U);
                        }
                        continue;
                    }
                    if (mnemonic == "DB" && !values.empty()) {
                        for (const auto& value : values) {
                            const auto byte = assembly_integer(value);
                            if (!byte || *byte < 0 || *byte > 0xFF)
                                return reject("DB values must fit uint8");
                            output.push_back(static_cast<std::uint8_t>(*byte));
                        }
                        continue;
                    }
                    if ((mnemonic == "PUSH" || mnemonic == "POP") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (reg) {
                            if ((mode64 && reg->width != 64) || (!mode64 && reg->width != 32) ||
                                (!mode64 && reg->index >= 8))
                                return reject("register width is incompatible with target mode");
                            if (reg->index >= 8)
                                output.push_back(0x41U);
                            output.push_back(static_cast<std::uint8_t>(
                                (mnemonic == "PUSH" ? 0x50U : 0x58U) + (reg->index & 7)));
                            continue;
                        }
                        if (mnemonic == "POP")
                            return reject("POP requires a register operand");
                        const auto immediate = assembly_integer(values.front());
                        if (!immediate || *immediate < (std::numeric_limits<std::int32_t>::min)() ||
                            *immediate > (std::numeric_limits<std::int32_t>::max)())
                            return reject("PUSH immediate must fit int32");
                        if (*immediate >= -128 && *immediate <= 127) {
                            output.push_back(0x6AU);
                            output.push_back(static_cast<std::uint8_t>(*immediate));
                        } else {
                            output.push_back(0x68U);
                            append_little_endian(output, static_cast<std::uint32_t>(*immediate), 4U);
                        }
                        continue;
                    }
                    if (mnemonic == "MOV" && values.size() == 2U) {
                        const auto destination = assembly_register(values[0]);
                        if (!destination || (!mode64 && destination->index >= 8) ||
                            (destination->width == 64 && !mode64))
                            return reject("MOV destination register is incompatible with target mode");
                        const auto source_register = assembly_register(values[1]);
                        if (source_register) {
                            if (source_register->width != destination->width ||
                                (!mode64 && source_register->index >= 8) ||
                                !append_rex(output, destination->width,
                                    source_register->index, destination->index))
                                return reject("MOV register operands are incompatible");
                            output.push_back(destination->width == 8 ? 0x88U : 0x89U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((source_register->index & 7) << 3) |
                                (destination->index & 7)));
                            continue;
                        }
                        const auto immediate = assembly_integer(values[1]);
                        if (!immediate)
                            return reject("MOV source must be a register or integer immediate");
                        if (!append_rex(output, destination->width, 0, destination->index))
                            return reject("MOV register encoding is unsupported");
                        output.push_back(static_cast<std::uint8_t>(
                            (destination->width == 8 ? 0xB0U : 0xB8U) +
                            (destination->index & 7)));
                        const std::size_t width = destination->width == 64
                            ? 8U : destination->width == 32 ? 4U : destination->width == 16 ? 2U : 1U;
                        const std::uint64_t maximum = width == 8U
                            ? (std::numeric_limits<std::uint64_t>::max)()
                            : (std::uint64_t{1} << (width * 8U)) - 1U;
                        const std::int64_t minimum = width == 8U
                            ? (std::numeric_limits<std::int64_t>::min)()
                            : -(std::int64_t{1} << (width * 8U - 1U));
                        if (*immediate < minimum)
                            return reject("MOV negative immediate exceeds destination width");
                        if (*immediate >= 0 && static_cast<std::uint64_t>(*immediate) > maximum)
                            return reject("MOV immediate exceeds destination width");
                        append_little_endian(output, static_cast<std::uint64_t>(*immediate), width);
                        continue;
                    }
                    if ((mnemonic == "XOR" || mnemonic == "ADD" || mnemonic == "SUB" ||
                         mnemonic == "CMP" || mnemonic == "TEST") && values.size() == 2U) {
                        const auto destination = assembly_register(values[0]);
                        const auto source = assembly_register(values[1]);
                        if (destination && source) {
                            if (destination->width != source->width ||
                                (destination->width == 64 && !mode64) ||
                                (!mode64 && (destination->index >= 8 || source->index >= 8)) ||
                                !append_rex(output, destination->width,
                                    source->index, destination->index))
                                return reject("binary register operands are incompatible");
                            const std::uint8_t opcode = destination->width == 8
                                ? mnemonic == "XOR" ? 0x30U : mnemonic == "ADD" ? 0x00U :
                                    mnemonic == "SUB" ? 0x28U : mnemonic == "CMP" ? 0x38U : 0x84U
                                : mnemonic == "XOR" ? 0x31U : mnemonic == "ADD" ? 0x01U :
                                    mnemonic == "SUB" ? 0x29U : mnemonic == "CMP" ? 0x39U : 0x85U;
                            output.push_back(opcode);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((source->index & 7) << 3) |
                                (destination->index & 7)));
                            continue;
                        }
                        if (!destination || mnemonic == "XOR" || mnemonic == "TEST" ||
                            (destination->width == 64 && !mode64) || destination->width == 8 ||
                            (!mode64 && destination->index >= 8))
                            return reject("immediate form is unsupported for this instruction");
                        const auto immediate = assembly_integer(values[1]);
                        const std::uint8_t immediate_width = destination->width == 16 ? 16 : 32;
                        const std::int64_t minimum = -(std::int64_t{1} << (immediate_width - 1U));
                        const std::uint64_t maximum = destination->width == 64
                            ? static_cast<std::uint64_t>((std::numeric_limits<std::int32_t>::max)())
                            : (std::uint64_t{1} << immediate_width) - 1U;
                        if (!immediate || *immediate < minimum ||
                            (*immediate >= 0 && static_cast<std::uint64_t>(*immediate) > maximum))
                            return reject("arithmetic immediate exceeds the encodable operand width");
                        if (!append_rex(output, destination->width, 0, destination->index))
                            return reject("arithmetic register encoding is unsupported");
                        const int extension = mnemonic == "ADD" ? 0 : mnemonic == "SUB" ? 5 : 7;
                        if (*immediate >= -128 && *immediate <= 127) {
                            output.push_back(0x83U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | (extension << 3) | (destination->index & 7)));
                            output.push_back(static_cast<std::uint8_t>(*immediate));
                        } else {
                            output.push_back(0x81U);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | (extension << 3) | (destination->index & 7)));
                            append_little_endian(
                                output, static_cast<std::uint64_t>(*immediate),
                                destination->width == 16 ? 2U : 4U);
                        }
                        continue;
                    }
                    if ((mnemonic == "INC" || mnemonic == "DEC") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (!reg || (reg->width == 64 && !mode64) ||
                            (!mode64 && reg->index >= 8) ||
                            !append_rex(output, reg->width, 0, reg->index))
                            return reject("INC/DEC register is incompatible with target mode");
                        output.push_back(reg->width == 8 ? 0xFEU : 0xFFU);
                        output.push_back(static_cast<std::uint8_t>(
                            0xC0U | ((mnemonic == "DEC" ? 1 : 0) << 3) | (reg->index & 7)));
                        continue;
                    }
                    if ((mnemonic == "JMP" || mnemonic == "CALL") && values.size() == 1U) {
                        const auto reg = assembly_register(values.front());
                        if (reg) {
                            if ((mode64 && reg->width != 64) || (!mode64 && reg->width != 32) ||
                                (!mode64 && reg->index >= 8))
                                return reject("indirect branch register is incompatible with target mode");
                            if (reg->index >= 8)
                                output.push_back(0x41U);
                            output.push_back(0xFFU);
                            output.push_back(static_cast<std::uint8_t>(
                                0xC0U | ((mnemonic == "CALL" ? 2 : 4) << 3) | (reg->index & 7)));
                            continue;
                        }
                        const auto target = assembly_integer(values.front());
                        if (!target || *target < 0)
                            return reject("direct branch target must be a non-negative address");
                        output.push_back(mnemonic == "CALL" ? 0xE8U : 0xE9U);
                        const auto next = assembly_next_address(base_address, output.size(), 4U);
                        if (!next)
                            return reject("direct branch address calculation overflowed");
                        if (!append_relative32(output, static_cast<std::uint64_t>(*target),
                            *next))
                            return reject("direct branch target exceeds rel32 range");
                        continue;
                    }
                    const auto conditional_opcode = mnemonic == "JE" || mnemonic == "JZ" ? 0x84 :
                        mnemonic == "JNE" || mnemonic == "JNZ" ? 0x85 :
                        mnemonic == "JA" ? 0x87 : mnemonic == "JAE" ? 0x83 :
                        mnemonic == "JB" ? 0x82 : mnemonic == "JBE" ? 0x86 : -1;
                    if (conditional_opcode >= 0 && values.size() == 1U) {
                        const auto target = assembly_integer(values.front());
                        if (!target || *target < 0)
                            return reject("conditional branch target must be a non-negative address");
                        output.insert(output.end(), {0x0FU, static_cast<std::uint8_t>(conditional_opcode)});
                        const auto next = assembly_next_address(base_address, output.size(), 4U);
                        if (!next)
                            return reject("conditional branch address calculation overflowed");
                        if (!append_relative32(output, static_cast<std::uint64_t>(*target),
                            *next))
                            return reject("conditional branch target exceeds rel32 range");
                        continue;
                    }
                    return reject("instruction form is not supported by the bounded overlay assembler");
                }
                if (output.empty()) {
                    error = "assembly patch contains no instructions";
                    return std::nullopt;
                }
                return output;
            }

            static std::optional<std::vector<std::uint8_t>> decode_hex_bytes(
                std::string_view encoded)
            {
                std::vector<std::uint8_t> bytes;
                int high_nibble = -1;
                for (std::size_t index = 0; index < encoded.size(); ++index) {
                    const unsigned char value = static_cast<unsigned char>(encoded[index]);
                    if (std::isspace(value) || value == ',' || value == ':' ||
                        value == '_' || value == '-') {
                        if (high_nibble != -1)
                            return std::nullopt;
                        continue;
                    }
                    if (value == '0' && index + 1 < encoded.size() &&
                        (encoded[index + 1] == 'x' || encoded[index + 1] == 'X') &&
                        high_nibble == -1) {
                        ++index;
                        continue;
                    }
                    if (!std::isxdigit(value))
                        return std::nullopt;
                    const int nibble = std::isdigit(value)
                        ? value - '0'
                        : std::tolower(value) - 'a' + 10;
                    if (high_nibble == -1) {
                        high_nibble = nibble;
                    } else {
                        bytes.push_back(static_cast<std::uint8_t>(
                            (high_nibble << 4) | nibble));
                        high_nibble = -1;
                    }
                }
                if (high_nibble != -1 || bytes.empty())
                    return std::nullopt;
                return bytes;
            }

            static std::string encode_hex_bytes(
                const std::vector<std::uint8_t>& bytes)
            {
                static constexpr char digits[] = "0123456789ABCDEF";
                std::string encoded;
                if (!bytes.empty())
                    encoded.reserve(bytes.size() * 3U - 1U);
                for (std::size_t index = 0; index < bytes.size(); ++index) {
                    if (index != 0)
                        encoded.push_back(' ');
                    encoded.push_back(digits[(bytes[index] >> 4U) & 0x0fU]);
                    encoded.push_back(digits[bytes[index] & 0x0fU]);
                }
                return encoded;
            }

            struct wave_c_snapshot_bytes_t final {
                std::vector<std::uint8_t> bytes;
                std::optional<wave_c_compat::live_routing_identity_binding_t> binding;
            };

            static std::optional<wave_c_snapshot_bytes_t> read_snapshot_bytes(
                const workspace_request_context_t& context,
                std::uint64_t address, std::size_t size,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation)
            {
                if (size == 0 || !context.workspace)
                    return std::nullopt;
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    wave_c_compat::live_routing_snapshot_request_t request;
                    request.target = wave_c_target_selector(context);
                    request.expected_generation = wave_c_workspace_generation(context);
                    request.address = address;
                    request.size = static_cast<std::uint64_t>(size);
                    request.cancellation = cancellation;
                    request.deadline = wave_c_deadline(context);
                    auto captured = live_routing.capture_bounded_snapshot(request);
                    if (!captured)
                        return std::nullopt;
                    auto snapshot = std::move(captured).take_value();
                    wave_c_snapshot_bytes_t result;
                    result.bytes = std::move(snapshot.bytes);
                    result.binding = snapshot.binding;
                    return result;
                }
                wave_c_signature_source_t source(context);
                wave_c_snapshot_bytes_t result;
                if (!source.read_bytes(address, size, result.bytes) ||
                    result.bytes.size() != size)
                    return std::nullopt;
                return result;
            }

            static bool live_snapshot_identity_current(
                const workspace_request_context_t& context)
            {
                if (context.kind != aida::analysis::target_kind_t::live_snapshot)
                    return true;
                if (context.cancellation_requested() ||
                    (context.deadline_ms != 0 &&
                     static_cast<std::uint64_t>(GetTickCount64()) >= context.deadline_ms))
                    return false;
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                return provider && provider->validate_current_identity().has_value();
            }

            static json memory_snapshot_receipt(
                const workspace_request_context_t& context,
                std::uint64_t bytes_read,
                const std::optional<
                    wave_c_compat::live_routing_identity_binding_t>& binding)
            {
                json receipt{
                    {"generation", binding
                        ? binding->workspace_generation
                        : wave_c_workspace_generation(context)},
                    {"bytes_read", bytes_read},
                    {"read_only", true},
                };
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    if (!binding)
                        return json::object();
                    receipt["source"] = "bounded_live_snapshot";
                    receipt["module_boundary_validated"] = true;
                    receipt["identity_revalidated"] = true;
                    receipt["target_id"] = binding->target_id;
                    receipt["pid"] = binding->pid;
                    receipt["process_creation_identity"] =
                        binding->process_creation_identity;
                    receipt["module_base"] = binding->module_base;
                    receipt["module_size"] = binding->module_size;
                    receipt["attach_generation"] = binding->attach_generation;
                } else {
                    receipt["source"] = "immutable_workspace_snapshot";
                    receipt["immutable"] = true;
                }
                return receipt;
            }

            tool_result_t invoke_memory_read_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory adapter intent is missing.", "MCP_MEMORY_INTENT_INVALID");
                if (!live_snapshot_identity_current(context))
                    return tool_result_t::error(
                        "Live snapshot identity is stale or unavailable.",
                        "LIVE_SNAPSHOT_IDENTITY_INVALID");
                const auto ranges = memory->find("ranges");
                if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                    std::size_t requested = 0;
                    if (name == "get_global_value") {
                        const auto queries = arguments.find("queries");
                        if (queries != arguments.end())
                            requested = queries->is_array()
                                ? queries->size() : std::size_t{1};
                    } else if (ranges != memory->end()) {
                        requested = ranges->is_array()
                            ? ranges->size() : std::size_t{1};
                    }
                    if (requested >
                        live_routing.limits().maximum_snapshots_per_request) {
                        return tool_result_t::error(
                            "Live memory request exceeds the snapshot quota.",
                            "LIVE_SNAPSHOT_BUDGET_EXCEEDED");
                    }
                }
                json result = json::array();
                std::uint64_t bytes_read = 0;
                std::optional<wave_c_compat::live_routing_identity_binding_t> binding;
                const auto accept_binding = [&binding](
                    const std::optional<wave_c_compat::live_routing_identity_binding_t>& candidate) {
                    if (!candidate)
                        return true;
                    if (!binding) {
                        binding = candidate;
                        return true;
                    }
                    return binding->target_id == candidate->target_id &&
                        binding->pid == candidate->pid &&
                        binding->process_creation_identity ==
                            candidate->process_creation_identity &&
                        binding->module_base == candidate->module_base &&
                        binding->module_size == candidate->module_size &&
                        binding->attach_generation == candidate->attach_generation &&
                        binding->workspace_generation == candidate->workspace_generation;
                };
                const auto account_bytes = [&bytes_read](std::size_t count) {
                    const auto value = static_cast<std::uint64_t>(count);
                    if (value > (std::numeric_limits<std::uint64_t>::max)() - bytes_read)
                        return false;
                    bytes_read += value;
                    return true;
                };

                if (name == "get_global_value") {
                    const auto queries = arguments.find("queries");
                    if (queries == arguments.end())
                        return tool_result_t::error(
                            "Global value queries are missing.", "MCP_MEMORY_INTENT_INVALID");
                    const json values = queries->is_array()
                        ? *queries : json::array({*queries});
                    for (const auto& query : values) {
                        if (context.cancellation_requested())
                            return tool_result_t::error(
                                "Memory request was cancelled.", "CANCELLED");
                        const std::string query_text = query.get<std::string>();
                        if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                            auto address = wave_c_address_value(query);
                            if (!address) {
                                const auto snapshot = context.workspace->snapshot();
                                if (snapshot) {
                                    const auto symbol = std::find_if(
                                        snapshot->symbols.begin(), snapshot->symbols.end(),
                                        [&query_text](const auto& value) {
                                            return value.name == query_text;
                                        });
                                    if (symbol != snapshot->symbols.end()) {
                                        const auto provider = std::dynamic_pointer_cast<
                                            const aida::analysis::live_snapshot_provider_t>(
                                                context.workspace->provider_handle());
                                        if (provider && symbol->address.value <=
                                            (std::numeric_limits<std::uint64_t>::max)() -
                                                provider->metadata().capture_address)
                                            address = provider->metadata().capture_address +
                                                symbol->address.value;
                                    }
                                }
                            }
                            const auto snapshot_bytes = address
                                ? read_snapshot_bytes(
                                    context, *address, std::size_t{8},
                                    live_routing, cancellation)
                                : std::nullopt;
                            if (!snapshot_bytes ||
                                !accept_binding(snapshot_bytes->binding) ||
                                !account_bytes(snapshot_bytes->bytes.size())) {
                                result.push_back({
                                    {"query", query_text}, {"value", nullptr},
                                    {"error", "memory_read_failed"},
                                });
                            } else {
                                result.push_back({
                                    {"query", query_text},
                                    {"value", encode_hex_bytes(snapshot_bytes->bytes)},
                                });
                            }
                            continue;
                        }
                        auto item = invoke_legacy(
                            "get_global_value",
                            json{{"address", query_text}, {"size", 8}, {"as_type", "hex"}},
                            context);
                        if (!item.success) {
                            result.push_back({
                                {"query", query_text}, {"value", nullptr},
                                {"error", item.error_code.empty()
                                    ? "memory_read_failed" : item.error_code},
                            });
                        } else {
                            result.push_back({
                                {"query", query_text},
                                {"value", item.data.value("value", json(nullptr))},
                            });
                        }
                    }
                } else {
                    if (ranges == memory->end() || !ranges->is_array())
                        return tool_result_t::error(
                            "Memory ranges are missing.", "MCP_MEMORY_INTENT_INVALID");
                    for (const auto& range : *ranges) {
                        if (context.cancellation_requested())
                            return tool_result_t::error(
                                "Memory request was cancelled.", "CANCELLED");
                        const std::string address_text = range.at("addr").get<std::string>();
                        const auto address = range.at("address").get<std::uint64_t>();
                        const auto size = range.at("size").get<std::size_t>();
                        if (name == "get_string") {
                            if (context.kind == aida::analysis::target_kind_t::live_snapshot) {
                                const auto snapshot_bytes = read_snapshot_bytes(
                                    context, address, size, live_routing, cancellation);
                                if (!snapshot_bytes ||
                                    !accept_binding(snapshot_bytes->binding) ||
                                    !account_bytes(snapshot_bytes->bytes.size())) {
                                    result.push_back({
                                        {"addr", address_text}, {"value", nullptr},
                                        {"error", "memory_read_failed"},
                                    });
                                } else {
                                    std::string value;
                                    for (const auto byte : snapshot_bytes->bytes) {
                                        if (byte == 0)
                                            break;
                                        if (byte >= 0x20U && byte <= 0x7eU) {
                                            value.push_back(static_cast<char>(byte));
                                        } else {
                                            static constexpr char digits[] =
                                                "0123456789ABCDEF";
                                            value.append("\\x");
                                            value.push_back(digits[(byte >> 4U) & 0x0fU]);
                                            value.push_back(digits[byte & 0x0fU]);
                                        }
                                    }
                                    result.push_back({
                                        {"addr", address_text}, {"value", std::move(value)},
                                    });
                                }
                                continue;
                            }
                            auto item = invoke_legacy(
                                "get_string",
                                json{{"address", address_text},
                                     {"max_length", size}, {"encoding", "auto"}},
                                context);
                            if (!item.success) {
                                result.push_back({
                                    {"addr", address_text}, {"value", nullptr},
                                    {"error", item.error_code.empty()
                                        ? "memory_read_failed" : item.error_code},
                                });
                            } else {
                                result.push_back({
                                    {"addr", address_text},
                                    {"value", item.data.value("value", json(nullptr))},
                                });
                            }
                            continue;
                        }
                        const auto bytes = read_snapshot_bytes(
                            context, address, size, live_routing, cancellation);
                        if (!bytes || !accept_binding(bytes->binding) ||
                            !account_bytes(bytes->bytes.size())) {
                            result.push_back({
                                {"addr", address_text}, {"data", nullptr},
                                {"error", "memory_read_failed"},
                            });
                            continue;
                        }
                        result.push_back({
                            {"addr", address_text},
                            {"data", encode_hex_bytes(bytes->bytes)},
                        });
                    }
                }

                if (!live_snapshot_identity_current(context))
                    return tool_result_t::error(
                        "Live snapshot identity changed during the memory request.",
                        "LIVE_SNAPSHOT_IDENTITY_CHANGED");
                if (context.kind == aida::analysis::target_kind_t::live_snapshot && !binding)
                    return tool_result_t::error(
                        "Live memory response has no resolved target binding.",
                        "LIVE_SNAPSHOT_BINDING_MISSING");

                return tool_result_t::ok(json{
                    {"result", std::move(result)},
                    {"_aida_memory", json{{"snapshot",
                        memory_snapshot_receipt(context, bytes_read, binding)}}},
                });
            }

            tool_result_t invoke_memory_overlay_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                if (context.kind == aida::analysis::target_kind_t::live_snapshot)
                    return tool_result_t::error(
                        "Static overlay mutation is denied for live targets.",
                        "STATIC_OVERLAY_LIVE_TARGET_DENIED");
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory overlay intent is missing.", "MCP_MEMORY_INTENT_INVALID");
                const auto operations = memory->find("operations");
                if (operations == memory->end() || !operations->is_array() ||
                    operations->empty())
                    return tool_result_t::error(
                        "Memory overlay operations are missing.", "MCP_MEMORY_INTENT_INVALID");

                json legacy_items = json::array();
                json receipts = json::array();
                for (const auto& operation : *operations) {
                    if (context.cancellation_requested())
                        return tool_result_t::error(
                            "Memory overlay request was cancelled.", "CANCELLED");
                    const auto address = operation.at("address").get<std::uint64_t>();
                    const auto size = operation.at("size").get<std::size_t>();
                    const auto before = read_snapshot_bytes(
                        context, address, size, live_routing, cancellation);
                    const auto after = decode_hex_bytes(
                        operation.at("after").get_ref<const std::string&>());
                    if (!before || !after || after->size() != size)
                        return tool_result_t::error(
                            "Memory overlay bytes could not be captured.",
                            "MCP_MEMORY_SNAPSHOT_FAILED");
                    if (name == "patch") {
                        legacy_items.push_back({
                            {"address", operation.at("addr")},
                            {"bytes", operation.at("after")},
                        });
                    } else {
                        legacy_items.push_back({
                            {"address", operation.at("addr")},
                            {"ty", operation.at("ty")},
                            {"value", operation.at("value")},
                        });
                    }
                    receipts.push_back({
                        {"index", operation.at("index")},
                        {"kind", operation.at("kind")},
                        {"addr", operation.at("addr")},
                        {"size", size},
                        {"before", encode_hex_bytes(before->bytes)},
                        {"after", encode_hex_bytes(*after)},
                    });
                }

                json legacy_arguments{
                    {"items", std::move(legacy_items)},
                    {"aida_tx", json{{"expected_revision", context.overlay_revision}}},
                };
                if (name != "patch" && name != "put_int")
                    return tool_result_t::error(
                        "Memory overlay tool has no production handler.",
                        "MCP_BACKEND_UNAVAILABLE");
                auto committed = name == "patch"
                    ? invoke_legacy("patch", legacy_arguments, context)
                    : invoke_legacy("put_int", legacy_arguments, context);
                if (!committed.success)
                    return committed;
                const auto transaction_id = committed.data.find("transaction_id");
                const auto revision = committed.data.find("revision");
                if (transaction_id == committed.data.end() ||
                    revision == committed.data.end() ||
                    !transaction_id->is_number_unsigned() ||
                    !revision->is_number_unsigned())
                    return tool_result_t::error(
                        "Memory overlay receipt is incomplete.",
                        "MCP_MEMORY_RECEIPT_INVALID");
                const auto transaction_value = transaction_id->get<std::uint64_t>();
                const auto revision_after = revision->get<std::uint64_t>();
                if (transaction_value == 0 || revision_after <= context.overlay_revision)
                    return tool_result_t::error(
                        "Memory overlay revision did not advance.",
                        "MCP_MEMORY_RECEIPT_INVALID");

                committed.data["_aida_memory"]["transaction"] = {
                    {"transaction_id", std::to_string(transaction_value)},
                    {"committed", true},
                    {"reversible", true},
                    {"undo_supported", true},
                    {"undo_token", "overlay:" + std::to_string(transaction_value)},
                    {"live_write_performed", false},
                    {"generation", (std::max)(
                        std::uint64_t{1}, context.workspace->generation())},
                    {"overlay_revision_before", context.overlay_revision},
                    {"overlay_revision_after", revision_after},
                    {"operations", std::move(receipts)},
                };
                committed.text = committed.data.dump(2);
                return committed;
            }

            tool_result_t invoke_memory_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                const auto memory = arguments.find("_aida_memory");
                if (memory == arguments.end() || !memory->is_object())
                    return tool_result_t::error(
                        "Memory adapter intent is missing.", "MCP_MEMORY_INTENT_INVALID");
                const std::string operation = memory->value("operation", std::string());
                if (operation == "read")
                    return invoke_memory_read_backend(
                        name, arguments, context, live_routing, cancellation);
                if (operation == "overlay_transaction")
                    return invoke_memory_overlay_backend(
                        name, arguments, context, live_routing, cancellation);
                return tool_result_t::error(
                    "Memory adapter operation is invalid.", "MCP_MEMORY_INTENT_INVALID");
            }

            static std::optional<aida::analysis::address_t> generated_overlay_address(
                const json& value, const workspace_request_context_t& context)
            {
                std::optional<std::uint64_t> parsed;
                bool explicit_va = false;
                if (value.is_string()) {
                    std::string text = value.get<std::string>();
                    if (text.rfind("rva:", 0) == 0 || text.rfind("RVA:", 0) == 0)
                        text.erase(0, 4);
                    else if (text.rfind("va:", 0) == 0 || text.rfind("VA:", 0) == 0) {
                        text.erase(0, 3);
                        explicit_va = true;
                    }
                    parsed = wave_c_address_value(text);
                } else {
                    parsed = wave_c_address_value(value);
                }
                if (!parsed)
                    return std::nullopt;
                const auto image = context.workspace->normalized_image();
                if (image && (explicit_va ||
                    (*parsed >= image->image_base && *parsed - image->image_base < image->image_size))) {
                    if (*parsed < image->image_base || *parsed - image->image_base >= image->image_size)
                        return std::nullopt;
                    *parsed -= image->image_base;
                }
                aida::analysis::address_t address;
                address.space = aida::analysis::address_space_id_t::relative_virtual;
                address.value = *parsed;
                address.architecture = context.workspace->identity().architecture();
                address.mode = context.workspace->identity().architecture_mode();
                return address;
            }

            static std::string canonical_overlay_address(
                const aida::analysis::address_t& address)
            {
                return hex_addr(address.value);
            }

            static std::optional<aida::analysis::address_t> generated_item_address(
                const json& item, const workspace_request_context_t& context)
            {
                const auto found = item.find("addr");
                return found == item.end()
                    ? std::nullopt : generated_overlay_address(*found, context);
            }

            static std::optional<aida::analysis::address_t> generated_item_end(
                const json& item, const workspace_request_context_t& context)
            {
                const auto found = item.find("end");
                return found == item.end()
                    ? std::nullopt : generated_overlay_address(*found, context);
            }

            static bool comment_contains_exact_line(
                std::string_view existing, std::string_view comment)
            {
                std::size_t begin = 0;
                while (begin <= existing.size()) {
                    const auto end = existing.find('\n', begin);
                    const auto line = existing.substr(
                        begin, end == std::string_view::npos ? existing.size() - begin : end - begin);
                    if (line == comment)
                        return true;
                    if (end == std::string_view::npos)
                        break;
                    begin = end + 1U;
                }
                return false;
            }

            static std::string existing_overlay_comment(
                const aida::analysis::overlay_snapshot_t& snapshot,
                const aida::analysis::address_t& address)
            {
                for (auto item = snapshot.items.rbegin(); item != snapshot.items.rend(); ++item) {
                    const auto& operation = item->second;
                    if ((operation.kind == aida::analysis::overlay_operation_kind_t::comment ||
                         operation.kind == aida::analysis::overlay_operation_kind_t::comment_update) &&
                        operation.address.space == address.space &&
                        operation.address.value == address.value)
                        return operation.text;
                }
                return {};
            }

            tool_result_t commit_generated_overlay(
                std::string_view name,
                std::vector<aida::analysis::overlay_operation_t> operations,
                json generated_output,
                const workspace_request_context_t& context,
                bool dry_run = false) const
            {
                if (context.kind != aida::analysis::target_kind_t::static_file)
                    return tool_result_t::error(
                        "Generated modify tools require a static analysis workspace.",
                        "MCP_LIVE_MUTATION_DENIED");
                const auto overlay = context.workspace->overlay();
                if (!overlay)
                    return tool_result_t::error(
                        "Reversible overlay journal is unavailable.", "NO_OVERLAY");
                if (operations.empty())
                    return tool_result_t::error(
                        "Generated modify transaction contains no operations.",
                        "MCP_EMPTY_MUTATION");
                const auto before = overlay->snapshot().revision;
                if (before != context.overlay_revision)
                    return tool_result_t::error(
                        "Overlay generation changed before the generated mutation committed.",
                        "MCP_STALE_OVERLAY");
                aida::analysis::overlay_transaction_request_t transaction;
                transaction.operations = std::move(operations);
                transaction.dry_run = dry_run;
                transaction.expected_revision = before;
                aida::analysis::cancellation_source_t cancellation;
                if (context.cancellation_requested())
                    cancellation.request_cancel();
                if (context.deadline_ms != 0) {
                    const auto now = static_cast<std::uint64_t>(GetTickCount64());
                    if (now >= context.deadline_ms)
                        return tool_result_t::error(
                            "Generated modify transaction deadline expired.",
                            "DEADLINE_EXCEEDED");
                    cancellation.set_deadline(
                        std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(context.deadline_ms - now));
                }
                auto committed = overlay->transact(transaction, cancellation.token());
                if (!committed)
                    return tool_result_t::error(
                        committed.error().message.empty()
                            ? "Generated modify transaction failed."
                            : committed.error().message,
                        "MCP_OVERLAY_TRANSACTION_FAILED");
                const auto& receipt = committed.value();
                if (receipt.operations.size() != transaction.operations.size())
                    return tool_result_t::error(
                        "Generated modify transaction returned an incomplete receipt.",
                        "MCP_OVERLAY_RECEIPT_INVALID");
                std::uint64_t transaction_id = receipt.transaction_id;
                if (transaction_id == 0) {
                    transaction_id = next_receipt_id_.fetch_add(1, std::memory_order_relaxed);
                    if (transaction_id == 0)
                        transaction_id = next_receipt_id_.fetch_add(1, std::memory_order_relaxed);
                }
                generated_output["committed"] = receipt.committed;
                generated_output["dry_run"] = receipt.dry_run;
                generated_output["item_count"] = transaction.operations.size();
                generated_output["items"] = json::array();
                generated_output["revision"] = receipt.revision;
                generated_output["transaction_id"] = transaction_id;
                generated_output["operations"] = receipt.operations.size();
                generated_output["_meta"]["aida"] = {
                    {"adapter", "ida_compat_mut"}, {"tool", std::string(name)},
                    {"mutation_mode", "reversible_overlay"},
                    {"target_binding", "workspace_request_context"},
                    {"ui_switched", false}, {"target_kind", "static_file"},
                    {"live_write", false}, {"target_file_write", false},
                    {"non_overlapping", true}, {"overlay_revision", before},
                };
                return tool_result_t::ok(std::move(generated_output));
            }

            tool_result_t invoke_modify_backend(
                std::string_view name, const json& arguments,
                const workspace_request_context_t& context) const
            {
                if (name == "add_bookmark") {
                    const auto address = generated_overlay_address(arguments.at("addr"), context);
                    if (!address)
                        return tool_result_t::error("Bookmark address is invalid.", "INVALID_ADDRESS");
                    const std::string prefix = arguments.value("prefix", "idaMCP: ");
                    const std::string title = prefix + arguments.at("name").get<std::string>();
                    aida::analysis::overlay_operation_t operation;
                    operation.kind = aida::analysis::overlay_operation_kind_t::bookmark;
                    operation.address = *address;
                    operation.name = title;
                    return commit_generated_overlay(
                        name, {std::move(operation)},
                        json{{"addr", canonical_overlay_address(*address)},
                             {"ea", canonical_overlay_address(*address)}, {"title", title},
                             {"prefix", prefix}, {"slot", nullptr}, {"ok", true}},
                        context);
                }

                if (name == "set_comments" || name == "append_comments") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    const auto overlay = context.workspace->overlay();
                    if (!overlay)
                        return tool_result_t::error(
                            "Reversible overlay journal is unavailable.", "NO_OVERLAY");
                    const auto snapshot = overlay->snapshot();
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error("Comment address is invalid.", "INVALID_ADDRESS");
                        const std::string comment = value.at("comment").get<std::string>();
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::comment_update;
                        operation.address = *address;
                        bool skipped = false;
                        if (name == "append_comments") {
                            const std::string existing = existing_overlay_comment(snapshot, *address);
                            skipped = value.value("dedupe", true) &&
                                comment_contains_exact_line(existing, comment);
                            operation.text = existing;
                            if (!skipped) {
                                if (!operation.text.empty())
                                    operation.text.push_back('\n');
                                operation.text.append(comment);
                            }
                            result.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"appended", !skipped}, {"skipped", skipped},
                                {"scope", value.value("scope", "auto")},
                            });
                        } else {
                            operation.text = comment;
                            result.push_back({{"addr", canonical_overlay_address(*address)}});
                        }
                        operations.push_back(std::move(operation));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "define_code" || name == "define_func" || name == "undefine") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Definition address is invalid.", "INVALID_ADDRESS");
                        auto end = generated_item_end(value, context);
                        if (!end && name != "define_func") {
                            const auto size = value.value("size", std::uint64_t{1});
                            if (size == 0 || size >
                                (std::numeric_limits<std::uint64_t>::max)() - address->value)
                                return tool_result_t::error(
                                    "Definition size is invalid.", "INVALID_RANGE");
                            end = *address;
                            end->value += size;
                        }
                        if (end && end->value <= address->value)
                            return tool_result_t::error(
                                "Definition range is not increasing.", "INVALID_RANGE");
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = name == "define_code"
                            ? aida::analysis::overlay_operation_kind_t::define_code
                            : name == "define_func"
                                ? aida::analysis::overlay_operation_kind_t::define_function
                                : aida::analysis::overlay_operation_kind_t::undefine;
                        operation.address = *address;
                        operation.end = end;
                        json item{
                            {"addr", canonical_overlay_address(*address)},
                            {"start", canonical_overlay_address(*address)},
                            {"ea", canonical_overlay_address(*address)},
                        };
                        if (end) {
                            item["end"] = canonical_overlay_address(*end);
                            item["size"] = end->value - address->value;
                            item["length"] = end->value - address->value;
                        }
                        operations.push_back(std::move(operation));
                        result.push_back(std::move(item));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "make_data") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address || !value.contains("type") || !value.at("type").is_string() ||
                            value.at("type").get_ref<const std::string&>().empty())
                            return tool_result_t::error(
                                "Data definition requires a valid address and type.",
                                "INVALID_DATA_DEFINITION");
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::define_data;
                        operation.address = *address;
                        operation.type = value.at("type").get<std::string>();
                        operation.name = value.value("name", std::string());
                        json item{
                            {"addr", canonical_overlay_address(*address)},
                            {"type", operation.type}, {"ok", true},
                        };
                        if (!operation.name.empty())
                            item["name"] = operation.name;
                        operations.push_back(std::move(operation));
                        result.push_back(std::move(item));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "patch_asm") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    const auto image = context.workspace->normalized_image();
                    if (!image)
                        return tool_result_t::error(
                            "Assembly patching requires a normalized image.",
                            "ANALYSIS_UNAVAILABLE");
                    using architecture_t = aida::analysis::architecture_id_t;
                    if (image->architecture != architecture_t::x86 &&
                        image->architecture != architecture_t::x86_64)
                        return tool_result_t::error(
                            "Assembly patching supports x86 and x86-64 workspaces only.",
                            "UNSUPPORTED_ARCHITECTURE");
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Assembly patch address is invalid.", "INVALID_ADDRESS");
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::assembly_patch;
                        operation.address = *address;
                        operation.assembly = value.at("asm").get<std::string>();
                        if (address->value >
                            (std::numeric_limits<std::uint64_t>::max)() - image->image_base)
                            return tool_result_t::error(
                                "Assembly patch address overflows the workspace image base.",
                                "INVALID_ADDRESS");
                        std::string assembly_error;
                        auto assembled = assemble_x86_overlay(
                            operation.assembly, image->image_base + address->value,
                            image->architecture == architecture_t::x86_64,
                            assembly_error);
                        if (!assembled)
                            return tool_result_t::error(
                                assembly_error.empty()
                                    ? "Assembly patch could not be encoded."
                                    : std::move(assembly_error),
                                "ASSEMBLY_ENCODING_FAILED");
                        operation.bytes = std::move(*assembled);
                        operations.push_back(std::move(operation));
                        result.push_back({{"addr", canonical_overlay_address(*address)}});
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "force_recompile") {
                    json values = arguments.contains("items") && !arguments.at("items").is_null()
                        ? scalar_or_array_items(arguments.at("items")) : json::array();
                    const bool full_workspace = values.empty();
                    if (full_workspace) {
                        json address = "0x0";
                        const auto snapshot = context.workspace->snapshot();
                        if (snapshot && !snapshot->functions.empty())
                            address = hex_addr(snapshot->functions.front().start.value);
                        values.push_back(json{{"addr", std::move(address)}});
                    }
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        if (!address)
                            return tool_result_t::error(
                                "Recompile address is invalid.", "INVALID_ADDRESS");
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::reanalysis;
                        operation.address = *address;
                        operation.reanalysis_flags = full_workspace
                            ? (std::numeric_limits<std::uint32_t>::max)() : 0U;
                        operations.push_back(std::move(operation));
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json::object(), context);
                }

                if (name == "set_op_type") {
                    const auto values = scalar_or_array_items(arguments.at("items"));
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json result = json::array();
                    operations.reserve(values.size());
                    for (const auto& value : values) {
                        const auto address = generated_item_address(value, context);
                        const std::string kind = value.value("kind", std::string());
                        if (!address || kind.empty())
                            return tool_result_t::error(
                                "Operand type requires a valid address and kind.",
                                "INVALID_OPERAND_TYPE");
                        const auto operand = value.value("op_n", std::uint64_t{0});
                        aida::analysis::overlay_operation_t operation;
                        operation.kind = aida::analysis::overlay_operation_kind_t::type_update;
                        operation.address = *address;
                        operation.name = "operand_" + std::to_string(operand);
                        operation.variable = value.value("struct", std::string());
                        operation.type = kind;
                        if (value.contains("target_addr"))
                            operation.type.append(":" + value.at("target_addr").get<std::string>());
                        if (value.contains("delta"))
                            operation.type.append(":" + value.at("delta").dump());
                        operations.push_back(std::move(operation));
                        result.push_back({
                            {"addr", canonical_overlay_address(*address)},
                            {"kind", kind}, {"op_n", operand}, {"ok", true},
                        });
                    }
                    return commit_generated_overlay(
                        name, std::move(operations), json{{"result", std::move(result)}}, context);
                }

                if (name == "rename") {
                    const auto& batch = arguments.at("batch");
                    std::vector<aida::analysis::overlay_operation_t> operations;
                    json function_results = json::array();
                    json data_results = json::array();
                    json local_results = json::array();
                    json stack_results = json::array();
                    const auto append_functions = [&](const json& collection) -> bool {
                        for (const auto& value : scalar_or_array_items(collection)) {
                            const auto address = generated_item_address(value, context);
                            if (!address)
                                return false;
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::name;
                            operation.address = *address;
                            operation.name = value.at("name").get<std::string>();
                            operations.push_back(std::move(operation));
                            function_results.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"name", value.at("name")},
                                {"new", value.at("name")},
                                {"dry_run", batch.value("dry_run", false)},
                            });
                        }
                        return true;
                    };
                    if (batch.contains("func") && !append_functions(batch.at("func")))
                        return tool_result_t::error(
                            "Function rename address is invalid.", "INVALID_ADDRESS");
                    if (batch.contains("data")) {
                        const auto snapshot = context.workspace->snapshot();
                        if (!snapshot)
                            return tool_result_t::error(
                                "Data rename requires an analysis snapshot.", "NO_SNAPSHOT");
                        for (const auto& value : scalar_or_array_items(batch.at("data"))) {
                            const std::string old_name = value.at("old").get<std::string>();
                            const auto symbol = std::find_if(
                                snapshot->symbols.begin(), snapshot->symbols.end(),
                                [&old_name](const auto& candidate) {
                                    return candidate.name == old_name;
                                });
                            if (symbol == snapshot->symbols.end())
                                return tool_result_t::error(
                                    "Data rename source symbol was not found.", "SYMBOL_NOT_FOUND");
                            const auto address = generated_overlay_address(
                                hex_addr(symbol->address.value), context);
                            if (!address)
                                return tool_result_t::error(
                                    "Data rename address is invalid.", "INVALID_ADDRESS");
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::name;
                            operation.address = *address;
                            operation.name = value.at("new").get<std::string>();
                            operations.push_back(std::move(operation));
                            data_results.push_back({
                                {"addr", canonical_overlay_address(*address)},
                                {"old", old_name}, {"new", value.at("new")},
                                {"dry_run", batch.value("dry_run", false)},
                            });
                        }
                    }
                    const auto append_scoped = [&](const json& collection, bool local) -> bool {
                        for (const auto& value : scalar_or_array_items(collection)) {
                            const auto function_address = generated_overlay_address(
                                value.at("func_addr"), context);
                            if (!function_address)
                                return false;
                            const std::string old_name = value.at("old").get<std::string>();
                            const auto frame = invoke_legacy(
                                "stack_frame", json{{"address", value.at("func_addr")}}, context);
                            if (!frame.success)
                                return false;
                            const auto slots = frame.data.find("slots");
                            if (slots == frame.data.end() || !slots->is_array())
                                return false;
                            const auto slot = std::find_if(
                                slots->begin(), slots->end(), [&old_name, local](const json& candidate) {
                                    return candidate.is_object() &&
                                        candidate.value("name", std::string()) == old_name &&
                                        (!local || candidate.value("is_local", false) ||
                                         candidate.value("source", std::string()).find("declared") !=
                                             std::string::npos);
                                });
                            if (slot == slots->end() || !slot->contains("offset") ||
                                !slot->at("offset").is_number_integer())
                                return false;
                            const std::string type = slot->value("type", std::string());
                            if (type.empty())
                                return false;
                            aida::analysis::overlay_operation_t operation;
                            operation.kind = aida::analysis::overlay_operation_kind_t::stack_variable;
                            operation.address = *function_address;
                            operation.stack_offset = slot->at("offset").get<std::int64_t>();
                            operation.variable = value.at("new").get<std::string>();
                            operation.type = type;
                            operations.push_back(std::move(operation));
                            json item{
                                {"func_addr", canonical_overlay_address(*function_address)},
                                {"old", old_name}, {"new", value.at("new")},
                                {"dry_run", batch.value("dry_run", false)},
                            };
                            (local ? local_results : stack_results).push_back(std::move(item));
                        }
                        return true;
                    };
                    if (batch.contains("local") &&
                        !append_scoped(batch.at("local"), true))
                        return tool_result_t::error(
                            "Local rename source has no stable declared stack-slot identity.",
                            "MCP_LOCAL_RENAME_UNRESOLVED");
                    if (batch.contains("stack") &&
                        !append_scoped(batch.at("stack"), false))
                        return tool_result_t::error(
                            "Stack rename source has no stable declared slot identity.",
                            "MCP_STACK_RENAME_UNRESOLVED");
                    json output{
                        {"func", std::move(function_results)}, {"data", std::move(data_results)},
                        {"local", std::move(local_results)}, {"stack", std::move(stack_results)},
                        {"global_alias", json::array()},
                    };
                    output["summary"] = {
                        {"total", operations.size()}, {"ok", operations.size()}, {"failed", 0},
                        {"dry_run", batch.value("dry_run", false)},
                        {"allow_overwrite", batch.value("allow_overwrite", false)},
                        {"stop_on_error", batch.value("stop_on_error", false)}, {"stopped", false},
                    };
                    return commit_generated_overlay(
                        name, std::move(operations), std::move(output), context,
                        batch.value("dry_run", false));
                }

                return tool_result_t::error(
                    "Modify adapter is not registered for " + std::string(name) + ".",
                    "MCP_BACKEND_UNAVAILABLE");
            }

            wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>
            invoke_workspace_backend(
                const wave_c_compat::adapter_call_context_t& call,
                const wave_c_compat::adapter_request_t& request,
                const workspace_request_context_t& context,
                const wave_c_compat::live_routing_integration_t& live_routing,
                const wave_c_protocol::cancellation_token_t& cancellation) const
            {
                if (!call.contract)
                    return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::invalid_request,
                         "workspace_contract_missing", 0, 0});
                const auto current_generation = wave_c_workspace_generation(context);
                if (request.expected_generation &&
                    *request.expected_generation != current_generation)
                    return wave_c_compat::adapter_result_t<
                        wave_c_compat::adapter_response_t>::failure(
                            {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                             "workspace_generation_stale",
                             *request.expected_generation, current_generation});
                json arguments = json::parse(request.payload, nullptr, false);
                if (arguments.is_discarded() || !arguments.is_object())
                    return wave_c_compat::adapter_result_t<wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::invalid_request,
                         "workspace_payload_invalid", 0, 0});
                if (wave_c_name_in(wave_c_handlers::types_tool_names(), call.contract->name)) {
                    return call.effect.mutates_workspace
                        ? types_store_.handle_overlay(call, request)
                        : types_store_.handle_query(call, request);
                }
                if (wave_c_name_in(wave_c_handlers::modify_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_modify_backend(call.contract->name, arguments, context));
                }
                if (wave_c_name_in(wave_c_handlers::memory_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_memory_backend(
                            call.contract->name, arguments, context,
                            live_routing, cancellation));
                }
                if (wave_c_name_in(wave_c_handlers::analysis_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_analysis_backend(call.contract->name, arguments, context));
                }
                if (wave_c_name_in(wave_c_handlers::core_tool_names(), call.contract->name)) {
                    return wave_c_adapter_result(
                        invoke_core_backend(call.contract->name, arguments, context));
                }
                if (call.contract->name == "stack_frame")
                    return wave_c_adapter_result(
                        invoke_legacy("stack_frame", arguments, context));
                if (call.contract->name == "declare_stack")
                    return wave_c_adapter_result(
                        invoke_legacy("declare_stack", arguments, context));
                if (call.contract->name == "delete_stack")
                    return wave_c_adapter_result(
                        invoke_legacy("delete_stack", arguments, context));
                if (call.contract->name == "analyze_funcs")
                    return wave_c_adapter_result(
                        invoke_legacy("analyze_funcs", arguments, context));
                if (call.contract->name == "find_insns")
                    return wave_c_adapter_result(
                        invoke_legacy("find_insns", arguments, context));
                return wave_c_compat::adapter_result_t<
                    wave_c_compat::adapter_response_t>::failure(
                        {wave_c_compat::adapter_error_code_t::backend_unavailable,
                         "workspace_adapter_group_unregistered", 0, 0});
            }

            static wave_c_compat::adapter_result_t<
                wave_c_compat::bounded_live_snapshot_t> capture_live_snapshot_backend(
                const wave_c_compat::adapter_call_context_t& call,
                const wave_c_compat::bounded_live_snapshot_request_t& request,
                const workspace_request_context_t& context)
            {
                if (!call.target || !call.target->target().live)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_denied,
                         "live_snapshot_target_unbound", 0, request.size});
                const auto& target = call.target->target();
                const auto generation_before = wave_c_workspace_generation(context);
                if (generation_before != target.generation)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                         "live_snapshot_generation_stale",
                         target.generation, generation_before});
                const auto provider = std::dynamic_pointer_cast<
                    const aida::analysis::live_snapshot_provider_t>(
                        context.workspace->provider_handle());
                if (!provider || request.size == 0)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_denied,
                         "live_snapshot_denied", 0, request.size});
                if (request.deadline &&
                    std::chrono::steady_clock::now() >= *request.deadline)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_deadline_exceeded", 0, request.size});
                const auto identity_before = provider->validate_current_identity();
                if (!identity_before)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_identity_invalid", 0, request.size});
                const auto& metadata = provider->metadata();
                if (metadata.process.pid != target.pid ||
                    metadata.process.creation_time_100ns !=
                        target.process_creation_identity ||
                    metadata.capture_address != target.live_capture_base ||
                    metadata.capture_size != target.live_capture_size)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_resolved_identity_mismatch",
                         target.process_creation_identity,
                         metadata.process.creation_time_100ns});
                if (request.address < metadata.capture_address ||
                    request.address - metadata.capture_address > metadata.capture_size ||
                    request.size > metadata.capture_size -
                        (request.address - metadata.capture_address))
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_bounds,
                         "live_snapshot_bounds", metadata.capture_size, request.size});
                const auto read = provider->read_vector(
                    request.address - metadata.capture_address,
                    request.size, request.size);
                if (!read || read.value().size() != request.size)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_invalid", request.size, 0});
                const auto identity_after = provider->validate_current_identity();
                if (!identity_after)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::live_snapshot_invalid,
                         "live_snapshot_identity_changed", request.size, 0});
                const auto generation_after = wave_c_workspace_generation(context);
                if (generation_after != target.generation)
                    return wave_c_live_snapshot_result_t::failure(
                        {wave_c_compat::adapter_error_code_t::target_resolution_failed,
                         "live_snapshot_generation_changed",
                         target.generation, generation_after});
                wave_c_compat::bounded_live_snapshot_t result;
                result.bytes = read.value();
                result.process_creation_identity = target.process_creation_identity;
                result.attach_generation = target.attach_generation;
                result.generation = target.generation;
                return wave_c_live_snapshot_result_t::success(std::move(result));
            }

            wave_c_handlers::composite_step_response_t invoke_composite_step(
                const wave_c_compat::adapter_call_context_t&,
                const wave_c_handlers::composite_step_request_t& request,
                const wave_c_protocol::cancellation_token_t& cancellation,
                const workspace_request_context_t& context) const
            {
                wave_c_handlers::composite_step_response_t response;
                response.workspace_generation = wave_c_workspace_generation(context);
                response.observed_overlay_generation =
                    context.workspace->overlay_revision();
                if (cancellation.cancelled()) {
                    response.status = wave_c_handlers::composite_step_status_t::cancelled;
                    response.diagnostic_code = "cancelled";
                    return response;
                }
                const auto snapshot = context.workspace->snapshot();
                const auto parsed = wave_c_address_value(request.subject);
                const std::uint64_t address = parsed.value_or(0);
                if (request.kind == wave_c_handlers::composite_step_kind_t::decompile_function ||
                    request.kind == wave_c_handlers::composite_step_kind_t::disassemble_function) {
                    const bool decompile = request.kind ==
                        wave_c_handlers::composite_step_kind_t::decompile_function;
                    auto result = decompile
                        ? invoke_legacy(
                            "decompile", json{{"address", request.subject}}, context)
                        : invoke_legacy(
                            "disasm", json{{"address", request.subject}}, context);
                    wave_c_handlers::composite_text_snapshot_t text;
                    if (result.success) {
                        const json normalized = result.data;
                        text.text = normalized.contains("result")
                            ? normalized["result"].dump() : result.text;
                        response.status = wave_c_handlers::composite_step_status_t::complete;
                    } else {
                        text.error = result.text;
                        response.status = wave_c_handlers::composite_step_status_t::unavailable;
                    }
                    response.payload = std::move(text);
                    return response;
                }
                if (!snapshot || !parsed) {
                    response.status = wave_c_handlers::composite_step_status_t::unavailable;
                    response.diagnostic_code = "snapshot_or_address_unavailable";
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::function_snapshot) {
                    const auto function = std::find_if(
                        snapshot->functions.begin(), snapshot->functions.end(),
                        [address](const auto& value) {
                            return value.start.value <= address && address < value.end.value;
                        });
                    if (function == snapshot->functions.end()) {
                        response.status = wave_c_handlers::composite_step_status_t::unavailable;
                        response.diagnostic_code = "function_not_found";
                        return response;
                    }
                    wave_c_handlers::composite_function_snapshot_t value;
                    value.addr = hex_addr(function->start.value);
                    value.name = "sub_" + value.addr.substr(2);
                    value.size = function->end.value - function->start.value;
                    value.basic_block_count = function->block_count;
                    value.comments = json::object();
                    for (const auto& edge : snapshot->edges) {
                        if (edge.source.value >= function->start.value &&
                            edge.source.value < function->end.value &&
                            (edge.kind == aida::analysis::edge_kind_t::call ||
                             edge.kind == aida::analysis::edge_kind_t::tail_call))
                            value.callees.push_back(hex_addr(edge.target.value));
                    }
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::xref_neighbors) {
                    wave_c_handlers::composite_xref_batch_t value;
                    for (const auto& xref : snapshot->xrefs) {
                        const bool outgoing = xref.source.value == address;
                        const bool incoming = xref.target.value == address;
                        if ((!outgoing && !incoming) ||
                            (request.direction == "out" && !outgoing) ||
                            (request.direction == "in" && !incoming))
                            continue;
                        value.neighbors.push_back({
                            hex_addr(outgoing ? xref.target.value : xref.source.value),
                            outgoing ? "out" : "in"});
                        if (request.max_items != 0 &&
                            value.neighbors.size() >= request.max_items)
                            break;
                    }
                    response.items_consumed = value.neighbors.size();
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::address_snapshot) {
                    wave_c_handlers::composite_address_snapshot_t value;
                    value.addr = hex_addr(address);
                    value.type = "address";
                    const auto function = std::find_if(
                        snapshot->functions.begin(), snapshot->functions.end(),
                        [address](const auto& item) {
                            return item.start.value <= address && address < item.end.value;
                        });
                    if (function != snapshot->functions.end())
                        value.function = "sub_" + hex_addr(function->start.value).substr(2);
                    const auto instruction = std::find_if(
                        snapshot->instructions.begin(), snapshot->instructions.end(),
                        [address](const auto& item) { return item.address.value == address; });
                    if (instruction != snapshot->instructions.end())
                        value.instruction = "mnemonic_" + std::to_string(instruction->mnemonic_id);
                    response.payload = std::move(value);
                    response.status = wave_c_handlers::composite_step_status_t::complete;
                    return response;
                }
                if (request.kind == wave_c_handlers::composite_step_kind_t::apply_overlay_action) {
                    if (request.expected_overlay_generation &&
                        *request.expected_overlay_generation !=
                            *response.observed_overlay_generation) {
                        response.status =
                            wave_c_handlers::composite_step_status_t::rejected;
                        response.diagnostic_code = "overlay_generation_stale";
                        return response;
                    }
                    json item{{"address", request.subject}};
                    if (request.action == "rename_func") {
                        item["name"] = request.action_arguments.at("name");
                    } else if (request.action == "set_type") {
                        item["type"] = request.action_arguments.at("type");
                    } else if (request.action == "set_comment") {
                        item["comment"] = request.action_arguments.at("comment");
                    } else {
                        response.status =
                            wave_c_handlers::composite_step_status_t::rejected;
                        response.diagnostic_code = "unsupported_overlay_action";
                        return response;
                    }
                    const json backend_arguments{
                        {"items", json::array({std::move(item)})},
                        {"aida_tx", json{{"expected_revision",
                            *response.observed_overlay_generation}}},
                    };
                    auto result = request.action == "rename_func"
                        ? invoke_legacy("rename", backend_arguments, context)
                        : request.action == "set_type"
                            ? invoke_legacy("set_type", backend_arguments, context)
                            : invoke_legacy(
                                "set_comments", backend_arguments, context);
                    response.payload = wave_c_handlers::composite_overlay_result_t{
                        result.success, request.action};
                    response.status = result.success
                        ? wave_c_handlers::composite_step_status_t::complete
                        : wave_c_handlers::composite_step_status_t::rejected;
                    response.diagnostic_message = result.text;
                    response.diagnostic_code = result.error_code;
                    if (result.success) {
                        const auto revision = result.data.contains("revision")
                            ? json_nonnegative_u64(result.data.at("revision"))
                            : std::nullopt;
                        if (!revision || *revision <=
                                *response.observed_overlay_generation) {
                            response.payload =
                                wave_c_handlers::composite_overlay_result_t{
                                    false, request.action};
                            response.status =
                                wave_c_handlers::composite_step_status_t::rejected;
                            response.diagnostic_code =
                                "overlay_commit_receipt_invalid";
                        } else {
                            response.committed_overlay_generation = *revision;
                            response.items_consumed = 1;
                        }
                    }
                    return response;
                }
                response.status = wave_c_handlers::composite_step_status_t::rejected;
                response.diagnostic_code = "unsupported_composite_step";
                return response;
            }

            static wave_c_compat::adapter_result_t<
                wave_c_handlers::survey_generation_lease_t> acquire_survey_generation(
                const workspace_request_context_t& context)
            {
                wave_c_handlers::survey_generation_lease_t lease;
                lease.owner = std::static_pointer_cast<const void>(context.workspace);
                lease.identity.workspace_id = context.binary_id.to_hex();
                lease.identity.pid = context.pid;
                lease.identity.bin_name = context.workspace->identity().bin_name();
                lease.identity.normalized_source_path =
                    context.workspace->identity().normalized_source_path();
                lease.identity.sha256 = context.binary_id.to_hex();
                lease.identity.generation = wave_c_workspace_generation(context);
                lease.identity.analysis_revision = context.analysis_revision;
                lease.identity.overlay_revision = context.overlay_revision;
                lease.identity.live =
                    context.kind == aida::analysis::target_kind_t::live_snapshot;
                if (lease.identity.live) {
                    const auto provider = std::dynamic_pointer_cast<
                        const aida::analysis::live_snapshot_provider_t>(
                            context.workspace->provider_handle());
                    lease.identity.live_snapshot_current = provider &&
                        provider->validate_current_identity().has_value();
                }
                lease.image = context.workspace->normalized_image();
                lease.analysis = context.workspace->snapshot();
                return wave_c_survey_lease_result_t::success(std::move(lease));
            }

            static wave_c_compat::adapter_result_t<
                wave_c_handlers::python_target_lease_t> acquire_python_target(
                const workspace_request_context_t& context)
            {
                wave_c_handlers::python_target_lease_t lease;
                lease.owner = std::static_pointer_cast<const void>(context.workspace);
                lease.workspace_id = context.binary_id.to_hex();
                lease.pid = context.pid;
                lease.bin_name = context.workspace->identity().bin_name();
                lease.normalized_source_path =
                    context.workspace->identity().normalized_source_path();
                lease.generation = context.workspace->generation();
                lease.analysis_revision = context.analysis_revision;
                lease.overlay_revision = context.overlay_revision;
                lease.live = context.kind == aida::analysis::target_kind_t::live_snapshot;
                lease.workspace_metadata = isolated_python_workspace_metadata(context);
                lease.workspace_api = [&context](const auto& query, const std::atomic<bool>*) {
                    return isolated_python_workspace_api(query, context);
                };
                return wave_c_python_lease_result_t::success(std::move(lease));
            }

            static python_compat::python_worker_execution_result_t execute_python_worker(
                const fs::path& script_root,
                const python_compat::python_worker_execution_request_t& request)
            {
                python_compat::python_worker_execution_result_t rejected;
                const auto package_root = standalone_package_root();
                if (!package_root) {
                    rejected.error_code = "PYTHON_WORKER_PACKAGE_REJECTED";
                    return rejected;
                }
                auto contract = python_compat::resolve_python_worker_launch_contract(
                    *package_root, script_root);
                if (!contract.valid() || !contract.value) {
                    rejected.error_code = contract.error.empty()
                        ? "PYTHON_WORKER_PACKAGE_REJECTED" : contract.error;
                    return rejected;
                }
                python_compat::python_worker_host_t host(std::move(*contract.value));
                return host.execute(request);
            }

            static tool_result_t checkpoint_workspace(
                const workspace_request_context_t& context)
            {
                const auto database = context.workspace->database();
                if (!database)
                    return tool_result_t::error(
                        "Workspace persistence is unavailable.", "WORKSPACE_DATABASE_UNAVAILABLE");
                auto ticket = database->checkpoint(false);
                if (!ticket.accepted || !ticket.completion.valid())
                    return tool_result_t::error(
                        "Workspace checkpoint was not accepted.", "WORKSPACE_CHECKPOINT_REJECTED");
                const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(30);
                if (ticket.completion.wait_until(deadline) != std::future_status::ready)
                    return tool_result_t::error(
                        "Workspace checkpoint exceeded its bounded deadline.",
                        "WORKSPACE_CHECKPOINT_TIMEOUT");
                const auto result = ticket.completion.get();
                if (!result)
                    return tool_result_t::error(
                        "Workspace checkpoint failed.", "WORKSPACE_CHECKPOINT_FAILED");
                return tool_result_t::ok(json{{"ok", true}, {"path", database->path()}});
            }

            std::unordered_map<std::string, ida_compat::read_handler_t> read_handlers_;
            std::unordered_map<std::string, ida_compat::mut_handler_t> mutation_handlers_;
            mutable wave_c_handlers::types_overlay_store_t types_store_;
            static constexpr std::size_t k_query_cursor_binding_capacity = 1024U;
            mutable std::mutex query_cursor_bindings_mutex_;
            mutable std::unordered_map<
                std::string, wave_c_query_cursor_binding_t> query_cursor_bindings_;
            mutable std::uint64_t query_cursor_binding_sequence_ = 0;
            wave_c_compat::effect_lock_manager_t adapter_lock_manager_;
            wave_c_compat::target_resolver_t targetless_resolver_;
            wave_c_compat::target_resolver_t registry_resolver_;
            wave_c_protocol::schema_runtime_t registry_schemas_;
            wave_c_compat::workspace_adapter_t targetless_workspace_;
            wave_c_handlers::core_handlers_t targetless_core_handlers_;
            wave_c_handlers::routing_extensions_t registry_handlers_;
            std::mutex registry_mutex_;
            std::unordered_map<std::uint64_t, std::uint32_t> registry_static_pids_;
            std::unordered_set<std::uint64_t> registry_active_target_ids_;
            std::uint32_t next_registry_static_pid_ =
                (std::numeric_limits<std::uint32_t>::max)();
            std::atomic<std::uint64_t> next_approval_id_{1};
            mutable std::atomic<std::uint64_t> next_receipt_id_{1};
        };

        std::optional<wave_c_integration::extension_tool_binding_t>
        wave_c_extension_binding(std::string_view name)
        {
            const json* input_schema = ida_compat::find_schema(std::string(name));
            if (!input_schema)
                return std::nullopt;
            wave_c_integration::extension_tool_binding_t binding;
            binding.contract.name = std::string(name);
            binding.contract.description = name == "analyze_funcs"
                ? "ida-pro-mcp compatible mutation: analyze_funcs"
                : name == "find_insns"
                    ? "ida-pro-mcp compatible: find_insns"
                    : name == "calculator"
                        ? "ida-pro-mcp compatible calculator."
                        : "Safe target-independent integer, bytes, hash, floating-point, and address mapping calculator";
            binding.contract.input_schema = *input_schema;
            binding.contract.output_schema = json{{"type", "object"}};
            binding.contract.annotations = json::object();
            binding.contract.effect_policy.unsafe = false;
            if (name == "analyze_funcs") {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::optional;
                binding.contract.target_policy.accepts_pid = true;
                binding.contract.target_policy.accepts_bin_name = true;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::workspace_overlay_mutation;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::workspace_overlay_transaction;
                binding.contract.effect_policy.read_only = false;
            } else if (name == "find_insns") {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::optional;
                binding.contract.target_policy.accepts_pid = true;
                binding.contract.target_policy.accepts_bin_name = true;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::workspace_read;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::workspace_shared;
                binding.contract.effect_policy.read_only = true;
            } else {
                binding.contract.target_policy.requirement =
                    wave_c_protocol::target_requirement_t::independent;
                binding.contract.effect_policy.effect =
                    wave_c_protocol::tool_effect_t::registry_read;
                binding.contract.effect_policy.lock =
                    wave_c_protocol::effect_lock_t::registry_read;
                binding.contract.effect_policy.read_only = true;
            }
            binding.contract.annotations["readOnlyHint"] =
                binding.contract.effect_policy.read_only;
            binding.contract.annotations["destructiveHint"] =
                !binding.contract.effect_policy.read_only;
            binding.adapter_symbol =
                "aida::standalone::mcp::compat::adapters::" + std::string(name);
            return binding;
        }

        void install_ida_compat_schema_validation()
        {
            ida_compat::register_schema_validator();
            set_pre_dispatch_validation_hook([](const tool_def_t& tool, const json& arguments) {
                const auto validation = ida_compat::validate_tool_args(
                    tool.name, arguments, tool.input_schema);
                if (validation.valid)
                    return tool_result_t::ok("");
                json errors = json::array();
                for (const auto& error : validation.errors) {
                    errors.push_back({
                        {"path", error.path},
                        {"message", error.message},
                        {"schema_fragment", error.schema_fragment}
                    });
                }
                return tool_result_t::error(validation.summary(),
                    "MCP_TOOL_INPUT_SCHEMA_INVALID", {{"errors", std::move(errors)}});
            });
        }

        void register_wave_c_compatibility_tools(server_t& server)
        {
            try {
                if (!wave_c_integration::mcp_server_integration_t::validate_union_count())
                    throw std::runtime_error("generated compatibility union cardinality is invalid");
                auto runtime = std::make_shared<wave_c_adapter_runtime_t>();
                wave_c_integration::server_integration_config_t config;
                config.adapter_dispatcher = [runtime](const auto& invocation) {
                    return runtime->dispatch(invocation);
                };
                config.extension_binding_provider = wave_c_extension_binding;
                auto integration = wave_c_integration::mcp_server_integration_t::create(
                    server, std::move(config));
                integration->register_generated_tools();
                integration->register_extension_tools();
                const auto names = integration->union_tool_names();
                const std::unordered_set<std::string> unique_names(names.begin(), names.end());
                if (names.size() != wave_c_compat::k_union_tool_count ||
                    unique_names.size() != wave_c_compat::k_union_tool_count ||
                    integration->registered_tool_count() != wave_c_compat::k_union_tool_count ||
                    unique_names.find("list_instances") == unique_names.end() ||
                    unique_names.find("py_eval") != unique_names.end())
                    throw std::runtime_error("generated compatibility registration inventory is invalid");
                diag::log_tagged_fmt(
                    "mcp_tools", "wave_c compatibility registration complete generated=%zu extensions=%zu union=%zu",
                    wave_c_compat::k_archive_tool_count,
                    wave_c_compat::k_aida_extension_count,
                    unique_names.size());
            } catch (const std::exception& error) {
                diag::log_tagged_fmt(
                    "mcp_tools", "wave_c compatibility registration failed error='%s'", error.what());
                throw;
            }
        }
    }

    void register_standalone_tools(server_t& srv)
    {
        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools entry");

        install_ida_compat_schema_validation();

        srv.register_tool({"get_tool_descriptions",
            "Return full descriptions and parameter schemas for selected MCP tool names or grouped packs such as browser, network, and burp.",
            {{"names", "array", "Tool names to describe", false},
             {"name", "string", "Single tool name to describe", false},
             {"prefix", "string", "Tool name prefix to search", false},
             {"query", "string", "Tool name or description search text; exact group aliases include all browser tools, all network tools, and all burp tools", false},
             {"group", "string", "Direct grouped pack name: browser|network|burp", false},
             {"limit", "number", "Maximum matching tools to return", false},
             {"include_schema", "boolean", "Include parameter names, types, and descriptions", false}},
            true,
            [&srv](const json& params) { return srv.describe_tools(params); }});

        srv.register_tool({"vm_bridge_manage", "Activate, inspect, and operate a custom VM shared-folder bridge. Use this for VMware, VirtualBox, QEMU, Hyper-V, or manually managed Windows VMs while keeping AiDAStandalone.exe on the host.",
            {{"action", "string", "status|activate|deactivate|ping|attach|detach|list_processes|modules|threads|memory_map|query_memory|read_memory|read_string|dump_region|search_memory", false},
             {"bridge_dir", "string", "Host path to the shared bridge folder for action=activate", false},
             {"guest_bridge_dir", "string", "Guest-visible path to the same bridge folder; returned in guest_command", false},
             {"host_sample", "string", "Optional host-side sample path copied into bridge\\samples during activation", false},
             {"guest_sample", "string", "Optional guest-visible sample path written to launch_config.json", false},
             {"sample", "string", "Alias for guest_sample", false},
             {"args", "string", "Optional sample arguments written to launch_config.json", false},
             {"write_launch_config", "boolean", "Write launch_config.json during activation (default true)", false},
             {"stage_agent", "boolean", "Copy AiDAGuestAgent.exe into bridge\\agent during activation (default true)", false},
             {"pid", "number", "Guest process id for attach or memory operations", false},
             {"process", "string", "Guest process name for action=attach", false},
             {"address", "string", "Guest process virtual address for memory operations", false},
             {"size", "number", "Byte count for read_memory or dump_region", false},
             {"pattern", "string", "Hex byte pattern for search_memory; use ?? wildcards", false},
             {"target", "string", "Accepted for consistency; VM bridge actions always address the guest", false},
             {"timeout_ms", "number", "Guest bridge timeout in milliseconds", false}},
            false, handle_vm_bridge_manage});

        srv.register_tool({"list_processes", "Enumerate processes. If a VM bridge is active this lists VM processes by default; pass target='host' for host processes.",
            {{"filter", "string", "Optional substring filter", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}}, true, handle_list_processes});
        srv.register_tool({"read_memory", "Read bytes or a typed scalar/string from the attached process. If a VM bridge is active this reads VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"size", "number", "Bytes to read", false}, {"value_type", "string", "Optional typed decode: byte/int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double/ascii/utf16", false}, {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, handle_read_memory});
        srv.register_tool({"read_string", "Read a UTF-8/ASCII string from the attached process. If a VM bridge is active this reads VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"max_length", "number", "Maximum bytes to inspect", false}, {"encoding", "string", "ascii|utf16 for VM reads", false}, {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}},
            true, handle_read_string});
        srv.register_tool({"query_memory", "Query the memory region containing an address. If a VM bridge is active this queries VM memory by default; pass target='host' for host memory.",
            {{"address", "string", "Target address", true}, {"pid", "number", "VM process id when target is guest", false}, {"target", "string", "auto|guest|host", false}, {"timeout_ms", "number", "VM bridge timeout", false}}, true, handle_query_memory});
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
        srv.register_tool({"search_files", "Search for file names under a workspace-relative root directory with case-insensitive glob matching.",
            {{"root", "string", "Workspace-relative root directory", true}, {"pattern", "string", "Case-insensitive glob using * and ?", true}, {"limit", "number", "Maximum matches", false}, {"max_visited", "number", "Maximum entries to visit", false}, {"timeout_ms", "number", "Traversal deadline in milliseconds", false}},
            true, handle_search_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"grep_in_files", "Search workspace file contents with a regular expression, bounded traversal, file glob filtering, and binary-file skips.",
            {{"root", "string", "Workspace-relative root directory", true}, {"pattern", "string", "Regex pattern", true}, {"file_pattern", "string", "Case-insensitive file glob using * and ?", false}, {"limit", "number", "Maximum matches", false}, {"max_visited", "number", "Maximum entries to visit", false}, {"max_file_size", "number", "Maximum file size to read", false}, {"timeout_ms", "number", "Traversal deadline in milliseconds", false}},
            true, handle_grep_in_files, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"web_search", "Search the web through the bundled Camoufox browser and extract visible result links from rendered search pages.",
            {{"query", "string", "Search query text", true}, {"max_results", "number", "Maximum results to return (default 5)", false}, {"timeout", "number", "Browser navigation timeout in seconds (1-60, default 8)", false}, {"diagnostic", "boolean", "Preserve expanded browser diagnostics when available", false}},
            true, handle_web_search, mcp_standalone::tool_visibility_t::internal_only});
        srv.register_tool({"webfetch",
            "Open a URL in the bundled Camoufox browser and return rendered markdown, plain text, or raw HTML. "
            "Uses browser navigation, redirects, cookies, scripts, and TLS behavior; strips script/style/noscript/iframe blocks before HTML conversion. "
            "Output capped at ~200 KB; max timeout 120 seconds.",
            {{"url", "string", "Absolute http:// or https:// URL", true},
             {"format", "string", "Output format: markdown (default), text, or html", false},
             {"timeout", "number", "Browser navigation timeout in seconds (1-120, default 30)", false},
             {"diagnostic", "boolean", "Preserve expanded browser diagnostics instead of compact local-fixture success summaries", false}},
            true, handle_webfetch, mcp_standalone::tool_visibility_t::internal_only});


        driver_tools::register_driver_tools(srv);
        network_tools::register_network_tools(srv);
        gameproto_tools::register_gameproto_tools(srv);
        net_proto_tools::register_net_proto_tools(srv);
        net_security_tools::register_net_security_tools(srv);
        emulation_tools::register_emulation_tools(srv);
        debugger_tools::register_debugger_tools(srv);
        thread_intel_tools::register_thread_intel_tools(srv);
        coding_tools::register_coding_tools(srv);
        re_tools::register_re_tools(srv);
        protected_re_tools::register_protected_re_tools(srv);
        workflow_tools::register_workflow_tools(srv);
        scanner_tools::register_scanner_tools(srv);
        analysis_tools::register_analysis_tools(srv);
        disasm_tools::register_disasm_tools(srv);
        decompile_tools::register_decompile_tools(srv);
        register_wave_c_compatibility_tools(srv);
        session_tools_ext::register_tools(srv);

        diag::log_tagged_fmt("mcp_tools", "register_standalone_tools done");
    }
}
