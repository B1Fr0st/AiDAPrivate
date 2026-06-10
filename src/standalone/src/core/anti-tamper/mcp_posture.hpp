#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../mcp/mcp_client.hpp"
#include "../settings/standalone_settings.hpp"
#include "../../helpers/diag_log.hpp"

namespace anti_tamper::mcp_posture
{
    enum class transport_t
    {
        unknown,
        http_sse,
        stdio
    };

    struct finding_t
    {
        std::string source;
        std::string reason;
        std::uint64_t path_hash = 0;
        std::uint64_t server_hash = 0;
        std::uint64_t command_hash = 0;
        std::uint64_t url_host_hash = 0;
        std::size_t name_len = 0;
        int port = 0;
        transport_t transport = transport_t::unknown;
        bool enabled = true;
        bool managed_name = false;
        bool localhost = false;
        bool high_risk_command = false;
        bool launcher_command = false;
        bool high_risk_url = false;
        bool offensive_tool_metadata = false;
        std::uint64_t metadata_hash = 0;
        std::size_t metadata_count = 0;
        bool deny = false;
    };

    struct report_t
    {
        bool scanned = false;
        bool trusted = true;
        bool denied = false;
        bool latched = false;
        std::uint64_t summary_hash = 0;
        std::size_t files_seen = 0;
        std::size_t files_with_mcp = 0;
        std::size_t servers_seen = 0;
        std::size_t managed_allowed = 0;
        std::size_t enabled_unknown = 0;
        std::size_t disabled_unknown = 0;
        std::size_t suspicious = 0;
        std::size_t parse_failures = 0;
        std::string reason;
        std::vector<finding_t> findings;
    };

    namespace detail
    {
        using json = nlohmann::json;

        enum class source_format_t
        {
            json,
            toml
        };

        struct config_source_t
        {
            const char* label;
            const char* path_template;
            source_format_t format;
        };

        struct server_entry_t
        {
            std::string source;
            std::uint64_t path_hash = 0;
            std::string name;
            std::string url;
            std::string command;
            std::vector<std::string> args;
            std::vector<std::string> tool_metadata;
            transport_t transport = transport_t::unknown;
            bool enabled = true;
        };

        struct url_info_t
        {
            bool valid = false;
            bool localhost = false;
            bool userinfo = false;
            int port = 0;
            std::string scheme;
            std::string host;
            std::string path;
        };

        inline std::mutex g_mutex;
        inline report_t g_cached_report;
        inline std::atomic<bool> g_scanned{false};
        inline std::atomic<bool> g_cached_trusted{false};
        inline std::atomic<bool> g_latched_denied{false};
        inline std::atomic<int> g_configured_port{29117};
        inline std::atomic<std::uint64_t> g_cached_summary_hash{0};

        inline std::uint64_t fnv1a_bytes(const void* data, std::size_t len)
        {
            if (!data)
                return 0;
            const auto* p = static_cast<const unsigned char*>(data);
            std::uint64_t h = 14695981039346656037ULL;
            for (std::size_t i = 0; i < len; ++i) {
                h ^= static_cast<std::uint64_t>(p[i]);
                h *= 1099511628211ULL;
            }
            return h;
        }

        inline void fnv_mix(std::uint64_t& h, std::uint64_t v)
        {
            for (unsigned i = 0; i < 8; ++i) {
                h ^= static_cast<unsigned char>((v >> (i * 8)) & 0xFFu);
                h *= 1099511628211ULL;
            }
        }

        inline std::uint64_t fnv1a_string(const std::string& text)
        {
            return fnv1a_bytes(text.data(), text.size());
        }

        inline std::string trim(const std::string& s)
        {
            const auto first = s.find_first_not_of(" \t\r\n");
            if (first == std::string::npos)
                return {};
            return s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
        }

        inline std::string lower_ascii(std::string text)
        {
            std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return text;
        }

        inline std::string normalized_name_key(std::string text)
        {
            text = lower_ascii(trim(text));
            for (char& c : text) {
                if (c == '_')
                    c = '-';
            }
            return text;
        }

        inline bool is_dynamic_camoufox_reverse_name_key(const std::string& n)
        {
            constexpr const char* prefix = "camoufox-reverse-";
            constexpr size_t prefix_len = 17;
            if (n.rfind(prefix, 0) != 0)
                return false;
            const size_t suffix_len = n.size() - prefix_len;
            if (suffix_len == 0 || suffix_len > 96)
                return false;
            for (size_t i = prefix_len; i < n.size(); ++i) {
                const unsigned char c = static_cast<unsigned char>(n[i]);
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ':'))
                    return false;
            }
            return true;
        }

        inline bool is_aida_managed_name(const std::string& name)
        {
            const std::string n = normalized_name_key(name);
            return n == "aida-standalone-mcp" ||
                   n == "aida-pro-mcp";
        }

        inline bool is_managed_name(const std::string& name)
        {
            const std::string n = normalized_name_key(name);
            return is_aida_managed_name(n) ||
                   n == "camoufox-reverse-mcp" ||
                   n == "camoufox-reverse" ||
                   is_dynamic_camoufox_reverse_name_key(n);
        }

        inline const char* transport_name(transport_t t)
        {
            switch (t) {
            case transport_t::http_sse: return "http_sse";
            case transport_t::stdio: return "stdio";
            default: return "unknown";
            }
        }

        inline std::string read_env(const char* name)
        {
            if (!name || !*name)
                return {};
            char buf[32768] = {};
            DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
            if (n == 0 || n >= sizeof(buf))
                return {};
            return std::string(buf, n);
        }

        inline std::string home_dir()
        {
            std::string home = read_env("USERPROFILE");
            if (!home.empty())
                return home;
            char buf[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, buf)))
                return buf;
            return {};
        }

        inline std::string current_dir()
        {
            char buf[MAX_PATH] = {};
            DWORD n = GetCurrentDirectoryA(static_cast<DWORD>(sizeof(buf)), buf);
            if (n == 0 || n >= static_cast<DWORD>(sizeof(buf)))
                return {};
            return std::string(buf, n);
        }

        inline std::string executable_dir()
        {
            std::vector<char> buf(32768);
            DWORD n = GetModuleFileNameA(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
            if (n == 0 || n >= static_cast<DWORD>(buf.size()))
                return {};
            std::filesystem::path p(std::string(buf.data(), n));
            return p.parent_path().string();
        }

        inline std::string unquote_path_token(std::string text)
        {
            text = trim(text);
            if (text.size() >= 2) {
                const char first = text.front();
                const char last = text.back();
                if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
                    text = text.substr(1, text.size() - 2);
            }
            return text;
        }

        inline std::string canonical_lower_path(std::string path)
        {
            path = unquote_path_token(path);
            if (path.empty())
                return {};
            std::error_code ec;
            std::filesystem::path p(path);
            if (p.is_relative())
                p = std::filesystem::absolute(p, ec);
            if (!ec) {
                std::filesystem::path canonical = std::filesystem::weakly_canonical(p, ec);
                if (!ec)
                    p = canonical;
            }
            if (ec)
                p = p.lexically_normal();
            std::string out = lower_ascii(p.string());
            for (char& c : out) {
                if (c == '/')
                    c = '\\';
            }
            while (!out.empty() && (out.back() == '\\' || out.back() == '/'))
                out.pop_back();
            return out;
        }

        inline bool path_under_or_equal(const std::string& child, const std::string& parent)
        {
            const std::string c = canonical_lower_path(child);
            const std::string p = canonical_lower_path(parent);
            if (c.empty() || p.empty())
                return false;
            if (c == p)
                return true;
            return c.size() > p.size() && c.compare(0, p.size(), p) == 0 && c[p.size()] == '\\';
        }

        inline std::string expand_path_template(const char* tmpl)
        {
            if (!tmpl || !*tmpl)
                return {};
            std::string path(tmpl);
            if (!path.empty() && path[0] == '~') {
                std::string home = home_dir();
                if (home.empty())
                    return {};
                if (path.size() == 1)
                    path = home;
                else if (path[1] == '/' || path[1] == '\\')
                    path = home + path.substr(1);
            }

            char expanded[32768] = {};
            DWORD n = ExpandEnvironmentStringsA(path.c_str(), expanded, static_cast<DWORD>(sizeof(expanded)));
            if (n > 0 && n < sizeof(expanded))
                path.assign(expanded, n - 1);
            if (path.find('%') != std::string::npos)
                return {};
            for (char& c : path) {
                if (c == '/')
                    c = '\\';
            }
            std::error_code ec;
            std::filesystem::path fs_path(path);
            if (fs_path.is_relative())
                fs_path = std::filesystem::absolute(fs_path, ec);
            if (!ec)
                path = fs_path.lexically_normal().string();
            return path;
        }

        inline const std::vector<config_source_t>& config_sources()
        {
            static const std::vector<config_source_t> sources = {
                {"Cline", "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", source_format_t::json},
                {"Roo Code", "%APPDATA%/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json", source_format_t::json},
                {"Kilo Code", "%APPDATA%/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json", source_format_t::json},
                {"Claude", "%APPDATA%/Claude/claude_desktop_config.json", source_format_t::json},
                {"Cursor", "~/.cursor/mcp.json", source_format_t::json},
                {"Windsurf", "~/.codeium/windsurf/mcp_config.json", source_format_t::json},
                {"Claude Code", "~/.claude.json", source_format_t::json},
                {"Claude Code Project", ".mcp.json", source_format_t::json},
                {"LM Studio", "~/.lmstudio/mcp.json", source_format_t::json},
                {"Codex", "~/.codex/config.toml", source_format_t::toml},
                {"Codex Home", "%CODEX_HOME%/config.toml", source_format_t::toml},
                {"Codex Workspace", ".codex/config.toml", source_format_t::toml},
                {"Zed", "%APPDATA%/Zed/settings.json", source_format_t::json},
                {"Gemini CLI", "~/.gemini/settings.json", source_format_t::json},
                {"Qwen Coder", "~/.qwen/settings.json", source_format_t::json},
                {"Copilot CLI", "~/.copilot/mcp-config.json", source_format_t::json},
                {"Crush", "~/crush.json", source_format_t::json},
                {"Augment Code", "%APPDATA%/Code/User/settings.json", source_format_t::json},
                {"Qodo Gen", "%APPDATA%/Code/User/settings.json", source_format_t::json},
                {"Antigravity IDE", "~/.gemini/antigravity/mcp_config.json", source_format_t::json},
                {"Warp", "~/.warp/mcp_config.json", source_format_t::json},
                {"Amazon Q", "~/.aws/amazonq/mcp_config.json", source_format_t::json},
                {"Opencode", "~/.config/opencode/opencode.json", source_format_t::json},
                {"Kiro", "~/.kiro/settings/mcp.json", source_format_t::json},
                {"Kiro Legacy", "~/.kiro/mcp_config.json", source_format_t::json},
                {"Trae", "~/.trae/mcp_config.json", source_format_t::json},
                {"VS Code", "%APPDATA%/Code/User/settings.json", source_format_t::json},
                {"VS Code Insiders", "%APPDATA%/Code - Insiders/User/settings.json", source_format_t::json},
                {"VS Code MCP", "%APPDATA%/Code/User/mcp.json", source_format_t::json},
                {"VS Code Insiders MCP", "%APPDATA%/Code - Insiders/User/mcp.json", source_format_t::json},
                {"VS Code Workspace MCP", ".vscode/mcp.json", source_format_t::json},
                {"VS Code Workspace Settings", ".vscode/settings.json", source_format_t::json},
                {"Workspace MCP", ".mcp.json", source_format_t::json}
            };
            return sources;
        }

        inline bool read_file_limited(const std::string& path, std::string& out)
        {
            out.clear();
            std::error_code ec;
            if (!std::filesystem::exists(path, ec) || ec)
                return false;
            if (!std::filesystem::is_regular_file(path, ec) || ec)
                return false;
            const auto size = std::filesystem::file_size(path, ec);
            if (ec || size > 4ULL * 1024ULL * 1024ULL)
                return false;
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs)
                return false;
            out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
            return ifs.good() || ifs.eof();
        }

        inline std::string strip_jsonc(const std::string& input)
        {
            std::string result;
            result.reserve(input.size());
            bool in_string = false;
            bool in_line = false;
            bool in_block = false;
            for (std::size_t i = 0; i < input.size(); ++i) {
                const char c = input[i];
                if (in_line) {
                    if (c == '\n') {
                        in_line = false;
                        result += '\n';
                    }
                    continue;
                }
                if (in_block) {
                    if (c == '*' && i + 1 < input.size() && input[i + 1] == '/') {
                        in_block = false;
                        ++i;
                    }
                    continue;
                }
                if (in_string) {
                    result += c;
                    if (c == '\\' && i + 1 < input.size())
                        result += input[++i];
                    else if (c == '"')
                        in_string = false;
                    continue;
                }
                if (c == '"') {
                    in_string = true;
                    result += c;
                    continue;
                }
                if (c == '/' && i + 1 < input.size()) {
                    if (input[i + 1] == '/') {
                        in_line = true;
                        ++i;
                        continue;
                    }
                    if (input[i + 1] == '*') {
                        in_block = true;
                        ++i;
                        continue;
                    }
                }
                if (c == ',') {
                    std::size_t j = i + 1;
                    while (j < input.size() && (input[j] == ' ' || input[j] == '\t' || input[j] == '\r' || input[j] == '\n'))
                        ++j;
                    if (j < input.size() && (input[j] == '}' || input[j] == ']'))
                        continue;
                }
                result += c;
            }
            return result;
        }

        inline bool parse_json_text(const std::string& raw, json& out)
        {
            try {
                out = json::parse(raw);
                return true;
            } catch (const json::parse_error&) {
            }
            try {
                out = json::parse(strip_jsonc(raw));
                return true;
            } catch (const json::parse_error&) {
                return false;
            }
        }

        inline bool text_has_mcp_marker(const std::string& text)
        {
            std::string lower = lower_ascii(text);
            return lower.find("mcp") != std::string::npos ||
                   lower.find("aida-standalone-mcp") != std::string::npos ||
                   lower.find("aida-pro-mcp") != std::string::npos ||
                   lower.find("camoufox-reverse") != std::string::npos;
        }

        inline bool path_has_mcp_marker(const std::string& path)
        {
            std::string lower = lower_ascii(path);
            return lower.find("mcp") != std::string::npos ||
                   lower.find("claude_desktop_config") != std::string::npos ||
                   lower.find(".claude.json") != std::string::npos ||
                   lower.find("config.toml") != std::string::npos;
        }

        inline std::string json_string_field(const json& obj, const char* key)
        {
            if (obj.is_object() && obj.contains(key) && obj[key].is_string())
                return trim(obj[key].get<std::string>());
            return {};
        }

        inline bool json_bool_field(const json& obj, const char* key, bool fallback)
        {
            if (!obj.is_object() || !obj.contains(key))
                return fallback;
            const auto& v = obj[key];
            if (v.is_boolean())
                return v.get<bool>();
            if (v.is_number_integer())
                return v.get<int>() != 0;
            if (v.is_string()) {
                const std::string s = lower_ascii(trim(v.get<std::string>()));
                if (s == "true" || s == "1" || s == "yes")
                    return true;
                if (s == "false" || s == "0" || s == "no")
                    return false;
            }
            return fallback;
        }

        inline void append_json_args(const json& obj, const char* key, std::vector<std::string>& args)
        {
            if (!obj.is_object() || !obj.contains(key))
                return;
            const auto& v = obj[key];
            if (v.is_string()) {
                args.push_back(v.get<std::string>());
            } else if (v.is_array()) {
                for (const auto& item : v) {
                    if (item.is_string())
                        args.push_back(item.get<std::string>());
                    else if (item.is_number_integer() || item.is_boolean())
                        args.push_back(item.dump());
                }
            }
        }

        inline void append_json_tool_metadata_value(const json& v, std::vector<std::string>& out, bool tool_context, int depth)
        {
            if (depth > 5 || out.size() > 256)
                return;
            if (v.is_string()) {
                if (tool_context)
                    out.push_back(v.get<std::string>());
                return;
            }
            if (v.is_array()) {
                for (const auto& item : v)
                    append_json_tool_metadata_value(item, out, tool_context, depth + 1);
                return;
            }
            if (!v.is_object())
                return;
            const bool object_has_tool_fields =
                (v.contains("name") && v["name"].is_string()) ||
                (v.contains("description") && v["description"].is_string()) ||
                (v.contains("summary") && v["summary"].is_string()) ||
                (v.contains("title") && v["title"].is_string());
            if (tool_context && object_has_tool_fields) {
                static const char* fields[] = {"name", "description", "summary", "title"};
                for (const char* field : fields) {
                    if (v.contains(field) && v[field].is_string())
                        out.push_back(v[field].get<std::string>());
                }
            }
            for (auto it = v.begin(); it != v.end(); ++it) {
                const std::string key = lower_ascii(it.key());
                const bool child_tool_context = tool_context ||
                    key.find("tool") != std::string::npos;
                append_json_tool_metadata_value(it.value(), out, child_tool_context, depth + 1);
            }
        }

        inline void append_json_tool_metadata(const json& obj, std::vector<std::string>& out)
        {
            append_json_tool_metadata_value(obj, out, false, 0);
        }

        inline bool add_json_server_entry(const std::string& source, std::uint64_t path_hash, const std::string& name, const json& value, std::vector<server_entry_t>& out)
        {
            server_entry_t e;
            e.source = source;
            e.path_hash = path_hash;
            e.name = name;
            if (value.is_string()) {
                std::string s = trim(value.get<std::string>());
                if (lower_ascii(s).find("://") != std::string::npos) {
                    e.url = s;
                    e.transport = transport_t::http_sse;
                } else {
                    e.command = s;
                    e.transport = transport_t::stdio;
                }
                out.push_back(std::move(e));
                return true;
            }
            if (!value.is_object())
                return false;
            e.enabled = !json_bool_field(value, "disabled", false);
            e.enabled = json_bool_field(value, "enabled", e.enabled);
            e.command = json_string_field(value, "command");
            if (e.command.empty())
                e.command = json_string_field(value, "cmd");
            if (e.command.empty())
                e.command = json_string_field(value, "executable");
            e.url = json_string_field(value, "url");
            if (e.url.empty())
                e.url = json_string_field(value, "serverUrl");
            if (e.url.empty())
                e.url = json_string_field(value, "server_url");
            if (e.url.empty())
                e.url = json_string_field(value, "endpoint");
            if (e.url.empty() && value.contains("settings") && value["settings"].is_object()) {
                e.url = json_string_field(value["settings"], "url");
                if (e.url.empty())
                    e.url = json_string_field(value["settings"], "serverUrl");
            }
            append_json_args(value, "args", e.args);
            append_json_args(value, "arguments", e.args);
            append_json_args(value, "enabled_tools", e.args);
            append_json_args(value, "enabledTools", e.args);
            append_json_args(value, "tool_approval_mode", e.args);
            append_json_tool_metadata(value, e.tool_metadata);
            std::string type = lower_ascii(json_string_field(value, "type"));
            std::string transport = lower_ascii(json_string_field(value, "transport"));
            if (transport.empty())
                transport = lower_ascii(json_string_field(value, "transportType"));
            const std::string discriminator = type + " " + transport;
            if (!e.command.empty() || discriminator.find("stdio") != std::string::npos)
                e.transport = transport_t::stdio;
            else if (!e.url.empty() || discriminator.find("http") != std::string::npos || discriminator.find("sse") != std::string::npos || discriminator.find("remote") != std::string::npos)
                e.transport = transport_t::http_sse;
            out.push_back(std::move(e));
            return true;
        }

        inline void add_json_server_map(const std::string& source, std::uint64_t path_hash, const json& obj, std::vector<server_entry_t>& out)
        {
            if (!obj.is_object())
                return;
            for (auto it = obj.begin(); it != obj.end(); ++it)
                add_json_server_entry(source, path_hash, it.key(), it.value(), out);
        }

        inline bool json_value_looks_like_server(const json& value)
        {
            if (value.is_string())
                return lower_ascii(value.get<std::string>()).find("://") != std::string::npos;
            if (!value.is_object())
                return false;
            if (value.contains("command") || value.contains("cmd") || value.contains("executable") ||
                value.contains("url") || value.contains("serverUrl") || value.contains("server_url") ||
                value.contains("endpoint") || value.contains("type") || value.contains("transport") ||
                value.contains("transportType") || value.contains("args") || value.contains("arguments"))
                return true;
            return value.contains("settings") && value["settings"].is_object() &&
                (value["settings"].contains("url") || value["settings"].contains("serverUrl"));
        }

        inline std::vector<server_entry_t> extract_json_entries(const std::string& source, std::uint64_t path_hash, const std::string& path, const json& root)
        {
            std::vector<server_entry_t> entries;
            if (!root.is_object())
                return entries;
            if (root.contains("mcpServers") && root["mcpServers"].is_object())
                add_json_server_map(source, path_hash, root["mcpServers"], entries);
            if (root.contains("mcp_servers") && root["mcp_servers"].is_object())
                add_json_server_map(source, path_hash, root["mcp_servers"], entries);
            if (root.contains("context_servers") && root["context_servers"].is_object())
                add_json_server_map(source, path_hash, root["context_servers"], entries);
            if (root.contains("mcp") && root["mcp"].is_object()) {
                const auto& mcp = root["mcp"];
                if (mcp.contains("servers") && mcp["servers"].is_object())
                    add_json_server_map(source, path_hash, mcp["servers"], entries);
                else
                    add_json_server_map(source, path_hash, mcp, entries);
            }
            if (root.contains("servers") && root["servers"].is_object() && path_has_mcp_marker(path))
                add_json_server_map(source, path_hash, root["servers"], entries);
            if (entries.empty() && path_has_mcp_marker(path)) {
                bool direct_map = false;
                for (auto it = root.begin(); it != root.end(); ++it) {
                    if (json_value_looks_like_server(it.value())) {
                        direct_map = true;
                        break;
                    }
                }
                if (direct_map)
                    add_json_server_map(source, path_hash, root, entries);
            }
            return entries;
        }

        inline std::string strip_toml_comment(const std::string& line)
        {
            bool in_string = false;
            char quote = '\0';
            for (std::size_t i = 0; i < line.size(); ++i) {
                const char c = line[i];
                if (in_string) {
                    if (c == '\\' && i + 1 < line.size()) {
                        ++i;
                        continue;
                    }
                    if (c == quote) {
                        in_string = false;
                        quote = '\0';
                    }
                    continue;
                }
                if (c == '"' || c == '\'') {
                    in_string = true;
                    quote = c;
                    continue;
                }
                if (c == '#')
                    return line.substr(0, i);
            }
            return line;
        }

        inline std::string toml_unquote(std::string v)
        {
            v = trim(v);
            if (v.size() >= 2 && ((v.front() == '"' && v.back() == '"') || (v.front() == '\'' && v.back() == '\''))) {
                std::string out;
                out.reserve(v.size() - 2);
                for (std::size_t i = 1; i + 1 < v.size(); ++i) {
                    if (v[i] == '\\' && i + 2 < v.size()) {
                        ++i;
                        out.push_back(v[i]);
                    } else {
                        out.push_back(v[i]);
                    }
                }
                return out;
            }
            return v;
        }

        inline bool toml_bool_value(const std::string& v, bool fallback)
        {
            const std::string s = lower_ascii(trim(v));
            if (s == "true" || s == "1" || s == "yes")
                return true;
            if (s == "false" || s == "0" || s == "no")
                return false;
            return fallback;
        }

        inline void toml_append_values(const std::string& raw, std::vector<std::string>& out)
        {
            std::string v = trim(raw);
            if (v.empty())
                return;
            if (v.front() != '[') {
                out.push_back(toml_unquote(v));
                return;
            }
            bool in_string = false;
            char quote = '\0';
            std::string cur;
            for (std::size_t i = 0; i < v.size(); ++i) {
                const char c = v[i];
                if (in_string) {
                    if (c == '\\' && i + 1 < v.size()) {
                        cur.push_back(v[++i]);
                    } else if (c == quote) {
                        in_string = false;
                        out.push_back(cur);
                        cur.clear();
                    } else {
                        cur.push_back(c);
                    }
                    continue;
                }
                if (c == '"' || c == '\'') {
                    in_string = true;
                    quote = c;
                }
            }
        }

        inline std::string parse_toml_section_name(const std::string& section)
        {
            std::string s = trim(section);
            const std::string prefix = "mcp_servers.";
            if (s.rfind(prefix, 0) != 0)
                return {};
            s = trim(s.substr(prefix.size()));
            return toml_unquote(s);
        }

        inline bool extract_toml_entries(const std::string& source, std::uint64_t path_hash, const std::string& raw, std::vector<server_entry_t>& out, bool& saw_mcp_marker)
        {
            saw_mcp_marker = lower_ascii(raw).find("mcp_servers") != std::string::npos;
            server_entry_t current;
            bool in_server = false;
            bool had_error = false;
            auto flush = [&]() {
                if (in_server) {
                    if (!current.command.empty())
                        current.transport = transport_t::stdio;
                    else if (!current.url.empty())
                        current.transport = transport_t::http_sse;
                    out.push_back(std::move(current));
                    current = server_entry_t{};
                    in_server = false;
                }
            };
            std::istringstream iss(raw);
            std::string line;
            while (std::getline(iss, line)) {
                line = trim(strip_toml_comment(line));
                if (line.empty())
                    continue;
                if (line.front() == '[') {
                    const auto close = line.find(']');
                    if (close == std::string::npos) {
                        had_error = true;
                        break;
                    }
                    flush();
                    std::string section = line.substr(1, close - 1);
                    std::string name = parse_toml_section_name(section);
                    if (!name.empty()) {
                        in_server = true;
                        current = server_entry_t{};
                        current.source = source;
                        current.path_hash = path_hash;
                        current.name = name;
                    }
                    continue;
                }
                if (!in_server)
                    continue;
                const auto eq = line.find('=');
                if (eq == std::string::npos)
                    continue;
                std::string key = lower_ascii(trim(line.substr(0, eq)));
                std::string val = trim(line.substr(eq + 1));
                if (key == "url" || key == "server_url" || key == "serverurl") {
                    current.url = toml_unquote(val);
                } else if (key == "command" || key == "cmd") {
                    current.command = toml_unquote(val);
                } else if (key == "args" || key == "arguments" || key == "enabled_tools" || key == "tool_approval_mode" || key == "default_tools_approval_mode") {
                    toml_append_values(val, current.args);
                    if (key == "enabled_tools")
                        toml_append_values(val, current.tool_metadata);
                } else if (key == "enabled") {
                    current.enabled = toml_bool_value(val, current.enabled);
                } else if (key == "disabled") {
                    current.enabled = !toml_bool_value(val, !current.enabled);
                } else if (key == "transport" || key == "type") {
                    std::string t = lower_ascii(toml_unquote(val));
                    if (t.find("stdio") != std::string::npos)
                        current.transport = transport_t::stdio;
                    else if (t.find("http") != std::string::npos || t.find("sse") != std::string::npos || t.find("remote") != std::string::npos)
                        current.transport = transport_t::http_sse;
                }
            }
            flush();
            if (saw_mcp_marker && out.empty())
                had_error = true;
            return !had_error;
        }

        inline std::string basename_for_hash(const std::string& path)
        {
            std::error_code ec;
            std::filesystem::path p(path);
            std::string name = p.filename().string();
            if (name.empty())
                name = path;
            return lower_ascii(name);
        }

        inline std::string module_dir()
        {
            char buf[32768] = {};
            DWORD n = GetModuleFileNameA(nullptr, buf, static_cast<DWORD>(sizeof(buf)));
            if (n == 0 || n >= sizeof(buf))
                return {};
            std::error_code ec;
            std::filesystem::path p(std::string(buf, n));
            p = p.parent_path();
            if (p.empty())
                return {};
            p = p.lexically_normal();
            return lower_ascii(p.string());
        }

        inline std::string normalized_path_for_compare(const std::string& raw)
        {
            std::string path = trim(raw);
            if (path.empty())
                return {};
            for (char& c : path) {
                if (c == '/')
                    c = '\\';
            }
            std::error_code ec;
            std::filesystem::path p(path);
            if (p.is_relative())
                p = std::filesystem::absolute(p, ec);
            if (!ec) {
                std::filesystem::path canonical = std::filesystem::weakly_canonical(p, ec);
                if (!ec && !canonical.empty())
                    p = canonical;
            }
            p = p.lexically_normal();
            return lower_ascii(p.string());
        }

        inline bool path_under_root(const std::string& child, const std::string& root)
        {
            if (child.empty() || root.empty())
                return false;
            std::string r = root;
            if (!r.empty() && r.back() != '\\')
                r.push_back('\\');
            return child == root || child.rfind(r, 0) == 0;
        }

        inline bool command_is_app_local_python(const std::string& command)
        {
            const std::string base = basename_for_hash(command);
            if (base != "python.exe" && base != "python3.exe" && base != "python" && base != "python3")
                return false;
            const std::string cmd = normalized_path_for_compare(command);
            if (cmd.empty())
                return false;
            const std::string mod_dir = module_dir();
            if (!mod_dir.empty() && path_under_root(cmd, mod_dir))
                return true;
            const std::string cwd = normalized_path_for_compare(current_dir());
            return !cwd.empty() && path_under_root(cmd, cwd);
        }

        inline bool command_is_app_local_reverse_mcp_executable(const std::string& command)
        {
            const std::string base = basename_for_hash(command);
            if (base != "aida_camoufoxreversemcp.exe" &&
                base != "camoufox-reverse-mcp.exe" &&
                base != "camoufox_reverse_mcp.exe")
                return false;
            const std::string cmd = normalized_path_for_compare(command);
            if (cmd.empty())
                return false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(cmd, ec) || ec)
                return false;
            const std::string mod_dir = module_dir();
            if (!mod_dir.empty() && path_under_root(cmd, mod_dir))
                return true;
            const std::string cwd = normalized_path_for_compare(current_dir());
            return !cwd.empty() && path_under_root(cmd, cwd);
        }

        inline bool boundary_char(char c)
        {
            unsigned char u = static_cast<unsigned char>(c);
            return !(std::isalnum(u) || c == '_');
        }

        template <std::size_t N>
        inline bool contains_token_from_set(const std::string& text, const char* const (&tokens)[N])
        {
            const std::string lower = lower_ascii(text);
            for (const char* token : tokens) {
                const std::string needle(token);
                std::size_t pos = 0;
                while ((pos = lower.find(needle, pos)) != std::string::npos) {
                    const bool left = pos == 0 || boundary_char(lower[pos - 1]);
                    const std::size_t end = pos + needle.size();
                    const bool right = end >= lower.size() || boundary_char(lower[end]) ||
                        std::isdigit(static_cast<unsigned char>(lower[end])) != 0;
                    if (left && right)
                        return true;
                    pos = end;
                }
            }
            return false;
        }

        inline bool contains_high_risk_token(const std::string& text)
        {
            static const char* risks[] = {
                "cmd", "powershell", "pwsh", "bash", "wsl", "ida", "ghidra", "x64dbg", "windbg", "cdb", "kd",
                "frida", "cheatengine", "scylla", "xenos", "reclass", "dnspy", "ilspy", "de4dot", "hollows",
                "procmon", "procexp", "processhacker", "apimonitor", "dump", "dumper", "minidump", "memory",
                "debugger", "debug", "inject", "hook", "trace", "tracer", "browser", "filesystem", "registry",
                "shell", "proxy", "mitm", "pcap", "wireshark", "fiddler", "burp", "aida"
            };
            return contains_token_from_set(text, risks);
        }

        inline bool contains_launcher_token(const std::string& text)
        {
            static const char* launchers[] = {
                "python", "python3", "py", "node", "nodejs", "npx", "npm", "pnpm", "yarn", "bun", "deno", "uv", "uvx", "docker"
            };
            return contains_token_from_set(text, launchers);
        }

        inline bool is_internal_camoufox_stdio(const server_entry_t& e)
        {
            const std::string name = normalized_name_key(e.name);
            if (name != "camoufox-reverse" && name != "camoufox-reverse-mcp")
                return false;
            if (e.transport != transport_t::stdio || e.command.empty())
                return false;
            if (command_is_app_local_reverse_mcp_executable(e.command)) {
                for (const auto& raw : e.args) {
                    const std::string arg = lower_ascii(trim(raw));
                    if (!arg.empty() && contains_high_risk_token(arg))
                        return false;
                }
                return true;
            }
            if (!command_is_app_local_python(e.command))
                return false;
            bool module_ok = false;
            for (std::size_t i = 0; i < e.args.size(); ++i) {
                const std::string arg = lower_ascii(trim(e.args[i]));
                if (arg.empty())
                    continue;
                if (arg == "-m" && i + 1 < e.args.size()) {
                    const std::string module = lower_ascii(trim(e.args[i + 1]));
                    if (module == "camoufox_reverse_mcp" || module == "camoufox-reverse-mcp") {
                        module_ok = true;
                        ++i;
                        continue;
                    }
                    return false;
                }
                if (contains_high_risk_token(arg))
                    return false;
            }
            return module_ok;
        }

        inline std::string fold_metadata_ascii(const std::string& text, bool compact)
        {
            std::string out;
            out.reserve(text.size());
            bool last_space = true;
            for (unsigned char c : text) {
                const char lower = static_cast<char>(std::tolower(c));
                const bool keep = (lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9');
                if (keep) {
                    out.push_back(lower);
                    last_space = false;
                } else if (!compact && !last_space) {
                    out.push_back(' ');
                    last_space = true;
                }
            }
            if (!compact && !out.empty() && out.back() == ' ')
                out.pop_back();
            return out;
        }

        inline bool folded_contains_metadata_token(const std::string& folded, const char* token)
        {
            const std::string needle = fold_metadata_ascii(token ? token : "", false);
            return !needle.empty() && folded.find(needle) != std::string::npos;
        }

        inline bool compact_contains_metadata_token(const std::string& compacted, const char* token)
        {
            const std::string needle = fold_metadata_ascii(token ? token : "", true);
            return !needle.empty() && compacted.find(needle) != std::string::npos;
        }

        inline bool tool_metadata_text_offensive(const std::string& text)
        {
            if (trim(text).empty())
                return false;
            static const char* tokens[] = {
                "frida", "x64dbg", "x32dbg", "windbg", "cdb", "kd debugger",
                "ida pro", "hex rays", "ghidra", "binary ninja", "radare",
                "rizin", "dnspy", "ilspy", "cheat engine", "process hacker",
                "system informer", "scylla", "pe sieve", "hollows hunter",
                "openprocess", "readprocessmemory", "writeprocessmemory",
                "virtualprotectex", "createremotethread", "debugactiveprocess",
                "sedebugprivilege", "process memory", "read process memory",
                "write process memory", "virtual memory", "dump process",
                "process dump", "minidump", "dump memory", "memory dump",
                "memory scanner", "memory scan", "scan memory", "attach debugger",
                "debug process", "inject dll", "dll injection", "remote thread",
                "hook function", "patch bytes", "patch memory", "disassemble process",
                "decompile process", "execute command", "run command", "shell command",
                "powershell", "cmd exe", "terminal command", "keylogger",
                "credential dump", "lsass dump", "mimikatz", "packet capture",
                "mitm", "proxy intercept"
            };
            const std::string folded = fold_metadata_ascii(text, false);
            const std::string compacted = fold_metadata_ascii(text, true);
            for (const char* token : tokens) {
                if (folded_contains_metadata_token(folded, token) || compact_contains_metadata_token(compacted, token))
                    return true;
            }
            return false;
        }

        inline bool entry_has_offensive_tool_metadata(const server_entry_t& e, std::uint64_t& metadata_hash, std::size_t& metadata_count)
        {
            metadata_hash = 14695981039346656037ULL;
            metadata_count = 0;
            bool offensive = false;
            for (const auto& value : e.tool_metadata) {
                if (trim(value).empty())
                    continue;
                ++metadata_count;
                fnv_mix(metadata_hash, fnv1a_string(value));
                if (tool_metadata_text_offensive(value))
                    offensive = true;
            }
            if (metadata_count == 0)
                metadata_hash = 0;
            return offensive;
        }

        inline bool command_has_high_risk(const server_entry_t& e)
        {
            if (!e.name.empty() && contains_high_risk_token(e.name))
                return true;
            if (!e.command.empty() && contains_high_risk_token(basename_for_hash(e.command)))
                return true;
            for (const auto& arg : e.args) {
                if (contains_high_risk_token(arg))
                    return true;
            }
            return false;
        }

        inline bool command_uses_launcher(const server_entry_t& e)
        {
            if (!e.command.empty() && contains_launcher_token(basename_for_hash(e.command)))
                return true;
            for (const auto& arg : e.args) {
                if (contains_launcher_token(arg))
                    return true;
            }
            return false;
        }

        inline bool is_camoufox_managed_name(const std::string& name)
        {
            const std::string n = normalized_name_key(name);
            return n == "camoufox-reverse-mcp" ||
                   n == "camoufox-reverse" ||
                   is_dynamic_camoufox_reverse_name_key(n);
        }

        inline std::string parent_path_string(const std::string& path)
        {
            if (path.empty())
                return {};
            std::error_code ec;
            std::filesystem::path p(path);
            p = p.parent_path();
            if (p.empty())
                return {};
            if (p.is_relative())
                p = std::filesystem::absolute(p, ec);
            if (!ec) {
                std::filesystem::path canonical = std::filesystem::weakly_canonical(p, ec);
                if (!ec)
                    p = canonical;
            }
            return p.lexically_normal().string();
        }

        inline std::string join_path_string(const std::string& base, const char* leaf)
        {
            if (base.empty() || !leaf || !*leaf)
                return {};
            std::filesystem::path p(base);
            p /= leaf;
            return p.lexically_normal().string();
        }

        inline void add_unique_camoufox_root(std::vector<std::string>& roots, const std::string& path)
        {
            const std::string canonical = canonical_lower_path(path);
            if (canonical.empty())
                return;
            for (const auto& existing : roots) {
                if (canonical_lower_path(existing) == canonical)
                    return;
            }
            roots.push_back(path);
        }

        inline void add_path_and_ancestors_to_roots(std::vector<std::string>& roots, const std::string& path, std::size_t depth)
        {
            std::string current = unquote_path_token(path);
            for (std::size_t i = 0; i < depth && !current.empty(); ++i) {
                add_unique_camoufox_root(roots, current);
                current = parent_path_string(current);
            }
        }

        inline void add_env_path_and_ancestors_to_roots(std::vector<std::string>& roots, const char* name, std::size_t depth)
        {
            const std::string value = read_env(name);
            if (!trim(value).empty())
                add_path_and_ancestors_to_roots(roots, value, depth);
        }

        inline void add_camoufox_sidecar_roots(std::vector<std::string>& roots)
        {
            add_env_path_and_ancestors_to_roots(roots, "AIDA_CAMOUFOX_EXECUTABLE", 6);
            add_env_path_and_ancestors_to_roots(roots, "AIDA_CAMOUFOX_PYTHON", 6);
            add_env_path_and_ancestors_to_roots(roots, "AIDA_CAMOUFOX_MCP_EXECUTABLE", 6);
            const std::string local = read_env("LOCALAPPDATA");
            if (!local.empty()) {
                const std::string aida_root = join_path_string(local, "AiDA");
                add_unique_camoufox_root(roots, aida_root);
                add_unique_camoufox_root(roots, join_path_string(join_path_string(aida_root, "camoufox"), "current"));
                add_unique_camoufox_root(roots, join_path_string(join_path_string(join_path_string(aida_root, "embedded"), "camoufox"), "current"));
            }
            const std::string temp = read_env("TEMP").empty() ? read_env("TMP") : read_env("TEMP");
            if (!temp.empty()) {
                add_unique_camoufox_root(roots, join_path_string(temp, "AiDA"));
                add_unique_camoufox_root(roots, join_path_string(join_path_string(temp, "AiDA"), "camoufox"));
                add_unique_camoufox_root(roots, join_path_string(join_path_string(join_path_string(temp, "AiDA"), "camoufox"), "current"));
                add_unique_camoufox_root(roots, join_path_string(temp, "aida-camoufox"));
                add_unique_camoufox_root(roots, join_path_string(join_path_string(temp, "aida-camoufox"), "current"));
            }
        }

        inline bool path_matches_env_path(const std::string& path, const char* name)
        {
            const std::string value = read_env(name);
            if (trim(value).empty())
                return false;
            return canonical_lower_path(unquote_path_token(path)) == canonical_lower_path(unquote_path_token(value));
        }

        inline std::vector<std::string> camoufox_trusted_runtime_roots()
        {
            std::vector<std::string> roots;
            add_camoufox_sidecar_roots(roots);
            const std::string exe_dir = executable_dir();
            add_unique_camoufox_root(roots, exe_dir);
            add_unique_camoufox_root(roots, current_dir());
            add_unique_camoufox_root(roots, parent_path_string(exe_dir));
            add_unique_camoufox_root(roots, parent_path_string(parent_path_string(exe_dir)));
            const std::string local = read_env("LOCALAPPDATA");
            if (!local.empty()) {
                const std::string aida_root = join_path_string(local, "AiDA");
                add_unique_camoufox_root(roots, join_path_string(join_path_string(aida_root, "camoufox"), "current"));
                add_unique_camoufox_root(roots, join_path_string(join_path_string(join_path_string(aida_root, "embedded"), "camoufox"), "current"));
            }
            return roots;
        }

        inline bool is_trusted_camoufox_runtime_python(const std::string& command)
        {
            const std::string command_path = unquote_path_token(command);
            const std::string command_base = basename_for_hash(command_path);
            if (command_base != "python.exe" && command_base != "pythonw.exe")
                return false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(command_path, ec) || ec)
                return false;
            if (path_matches_env_path(command_path, "AIDA_CAMOUFOX_PYTHON"))
                return true;
            static const char* runtime_dirs[] = {
                "deps\\camoufox-runtime",
                "camoufox-runtime",
                "deps\\camoufox-python",
                "camoufox-python",
                "deps\\python",
                "python",
                "deps\\python-3.12",
                "python-3.12",
                "deps\\python-3.12.10-x64",
                "python-3.12.10-x64",
                "deps\\Python312",
                "Python312",
                "deps\\Python312-3.12.10-x64",
                "Python312-3.12.10-x64"
            };
            for (const auto& root : camoufox_trusted_runtime_roots()) {
                for (const char* rel : runtime_dirs) {
                    const std::string runtime_dir = join_path_string(root, rel);
                    if (!runtime_dir.empty() && path_under_or_equal(command_path, runtime_dir))
                        return true;
                }
            }
            return false;
        }

        inline bool flag_enabled_value(const std::string& value)
        {
            const std::string v = lower_ascii(trim(value));
            return v == "1" || v == "true" || v == "yes" || v == "on";
        }

        inline bool is_explicit_system_camoufox_runtime_python(const std::string& command, const std::string* configured_python, const std::string* allow_system)
        {
            if (!allow_system || !flag_enabled_value(*allow_system) || !configured_python || trim(*configured_python).empty())
                return false;
            const std::string command_path = unquote_path_token(command);
            const std::string configured_path = unquote_path_token(*configured_python);
            const std::string command_base = basename_for_hash(command_path);
            if (command_base != "python.exe" && command_base != "pythonw.exe")
                return false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(command_path, ec) || ec)
                return false;
            return canonical_lower_path(command_path) == canonical_lower_path(configured_path);
        }

        inline bool is_trusted_camoufox_reverse_mcp_executable(const std::string& command)
        {
            const std::string command_path = unquote_path_token(command);
            const std::string command_base = basename_for_hash(command_path);
            if (command_base != "aida_camoufoxreversemcp.exe" &&
                command_base != "camoufox-reverse-mcp.exe" &&
                command_base != "camoufox_reverse_mcp.exe")
                return false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(command_path, ec) || ec)
                return false;
            if (path_matches_env_path(command_path, "AIDA_CAMOUFOX_MCP_EXECUTABLE"))
                return true;
            std::vector<std::string> roots;
            add_camoufox_sidecar_roots(roots);
            const std::string exe_dir = executable_dir();
            add_unique_camoufox_root(roots, exe_dir);
            add_unique_camoufox_root(roots, current_dir());
            add_unique_camoufox_root(roots, parent_path_string(exe_dir));
            add_unique_camoufox_root(roots, parent_path_string(parent_path_string(exe_dir)));
            const std::string local = read_env("LOCALAPPDATA");
            if (!local.empty()) {
                const std::string aida_root = join_path_string(local, "AiDA");
                add_unique_camoufox_root(roots, join_path_string(aida_root, "current"));
                add_unique_camoufox_root(roots, join_path_string(aida_root, "runtime"));
                add_unique_camoufox_root(roots, join_path_string(aida_root, "embedded"));
            }
            for (const auto& root : roots) {
                const std::string deps_dir = join_path_string(root, "deps");
                const std::string mcp_dir = join_path_string(deps_dir, "camoufox-reverse-mcp");
                if ((!deps_dir.empty() && path_under_or_equal(command_path, deps_dir)) ||
                    (!mcp_dir.empty() && path_under_or_equal(command_path, mcp_dir)) ||
                    path_under_or_equal(command_path, root))
                    return true;
            }
            return false;
        }

        inline bool is_trusted_camoufox_browser_path(const std::string& path)
        {
            const std::string browser_path = unquote_path_token(path);
            if (basename_for_hash(browser_path) != "camoufox.exe")
                return false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(browser_path, ec) || ec)
                return false;
            if (path_matches_env_path(browser_path, "AIDA_CAMOUFOX_EXECUTABLE"))
                return true;
            const std::string canonical = canonical_lower_path(browser_path);
            if (canonical.find("\\camoufox-") == std::string::npos)
                return false;
            for (const auto& root : camoufox_trusted_runtime_roots()) {
                const std::string deps_dir = join_path_string(root, "deps");
                if ((!deps_dir.empty() && path_under_or_equal(browser_path, deps_dir)) ||
                    path_under_or_equal(browser_path, root))
                    return true;
            }
            return false;
        }

        inline std::string local_appdata_aida_dir()
        {
            const std::string local = read_env("LOCALAPPDATA");
            if (local.empty())
                return {};
            return join_path_string(local, "AiDA");
        }

        inline bool is_trusted_camoufox_working_dir(const std::string& path)
        {
            const std::string work_dir = unquote_path_token(path);
            if (work_dir.empty())
                return false;
            std::error_code ec;
            if (!std::filesystem::is_directory(work_dir, ec) || ec)
                return false;
            const std::string canonical = canonical_lower_path(work_dir);
            if (canonical.empty())
                return false;
            for (const auto& root : camoufox_trusted_runtime_roots()) {
                if (canonical == canonical_lower_path(root))
                    return true;
            }
            return false;
        }

        inline bool is_trusted_camoufox_profile_root(const std::string& path)
        {
            const std::string profile_root = unquote_path_token(path);
            if (profile_root.empty())
                return false;
            std::vector<std::string> roots;
            const std::string local_root = local_appdata_aida_dir();
            if (!local_root.empty())
                roots.push_back(join_path_string(local_root, "camoufox-profiles"));
            for (const auto& runtime_root : camoufox_trusted_runtime_roots())
                roots.push_back(join_path_string(runtime_root, "camoufox-profiles"));
            for (const auto& root : roots) {
                if (!root.empty() && path_under_or_equal(profile_root, root))
                    return true;
            }
            return false;
        }

        inline bool camoufox_args_trusted(const std::vector<std::string>& args, std::string& reason)
        {
            std::size_t module_index = 0;
            while (module_index < args.size() && trim(args[module_index]) == "-I")
                ++module_index;
            if (args.size() < module_index + 2) {
                reason = "args_missing_module";
                return false;
            }
            if (trim(args[module_index]) != "-m") {
                reason = "args_missing_module_switch";
                return false;
            }
            if (lower_ascii(trim(args[module_index + 1])) != "camoufox_reverse_mcp") {
                reason = "args_module_mismatch";
                return false;
            }
            for (std::size_t i = module_index + 2; i < args.size(); ++i) {
                const std::string arg = lower_ascii(trim(args[i]));
                if (arg.empty())
                    continue;
                if (arg.find("://") != std::string::npos ||
                    arg.find("url") != std::string::npos ||
                    arg.find("uri") != std::string::npos ||
                    arg.find("host") != std::string::npos ||
                    arg.find("port") != std::string::npos ||
                    arg.find("api") != std::string::npos ||
                    arg.find("key") != std::string::npos ||
                    arg.find("token") != std::string::npos ||
                    arg.find("oauth") != std::string::npos) {
                    reason = "args_external_shape";
                    return false;
                }
                if (contains_high_risk_token(arg)) {
                    reason = "args_high_risk";
                    return false;
                }
            }
            return true;
        }

        inline bool camoufox_executable_args_trusted(const std::vector<std::string>& args, std::string& reason)
        {
            for (const auto& raw : args) {
                const std::string arg = lower_ascii(trim(raw));
                if (arg.empty())
                    continue;
                if (arg.find("://") != std::string::npos ||
                    arg.find("url") != std::string::npos ||
                    arg.find("uri") != std::string::npos ||
                    arg.find("host") != std::string::npos ||
                    arg.find("port") != std::string::npos ||
                    arg.find("api") != std::string::npos ||
                    arg.find("key") != std::string::npos ||
                    arg.find("token") != std::string::npos ||
                    arg.find("oauth") != std::string::npos) {
                    reason = "args_external_shape";
                    return false;
                }
                if (contains_high_risk_token(arg)) {
                    reason = "args_high_risk";
                    return false;
                }
            }
            return true;
        }

        inline const std::string* env_value(const mcp_client::server_config_t& cfg, const char* key)
        {
            if (!key || !*key)
                return nullptr;
            auto it = cfg.env.find(key);
            return it == cfg.env.end() ? nullptr : &it->second;
        }

        inline bool camoufox_session_name_matches_env(const std::string& name, const std::string& session_id)
        {
            const std::string n = normalized_name_key(name);
            const std::string s = normalized_name_key(session_id.empty() ? std::string("default") : session_id);
            if (s.empty() || s.size() > 96)
                return false;
            if (n == "camoufox-reverse" || n == "camoufox-reverse-mcp")
                return true;
            constexpr const char* prefix = "camoufox-reverse-";
            constexpr size_t prefix_len = 17;
            return n.rfind(prefix, 0) == 0 && n.substr(prefix_len) == s;
        }

        inline bool is_internal_camoufox_runtime_server(const mcp_client::server_config_t& cfg, std::string* deny_reason = nullptr)
        {
            auto fail = [&](const char* reason) {
                if (deny_reason)
                    *deny_reason = reason ? reason : "camoufox_predicate_failed";
                return false;
            };
            if (!is_camoufox_managed_name(cfg.name))
                return fail("name_not_camoufox_managed");
            if (cfg.transport != mcp_client::transport_type_t::stdio)
                return fail("transport_not_stdio");
            if (!cfg.enabled || cfg.command.empty() || !cfg.url.empty() || !cfg.api_key.empty())
                return fail("external_server_shape");
            if (cfg.auto_connect || cfg.oauth_enabled || !cfg.oauth_client_id.empty() || !cfg.oauth_client_secret.empty() ||
                !cfg.oauth_scope.empty() || !cfg.oauth_redirect_uri.empty())
                return fail("oauth_shape");
            const bool direct_executable = is_trusted_camoufox_reverse_mcp_executable(cfg.command);
            std::string args_reason;
            if (direct_executable) {
                if (!camoufox_executable_args_trusted(cfg.args, args_reason))
                    return fail(args_reason.c_str());
            } else if (!camoufox_args_trusted(cfg.args, args_reason)) {
                return fail(args_reason.c_str());
            }
            const std::string* configured_python = env_value(cfg, "AIDA_CAMOUFOX_PYTHON");
            const std::string* allow_system_python = env_value(cfg, "AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON");
            if (!direct_executable &&
                !is_trusted_camoufox_runtime_python(cfg.command) &&
                !is_explicit_system_camoufox_runtime_python(cfg.command, configured_python, allow_system_python))
                return fail("python_runtime_untrusted");
            const std::string* browser = env_value(cfg, "AIDA_CAMOUFOX_EXECUTABLE");
            if (!browser || trim(*browser).empty())
                return fail("browser_env_missing");
            if (!is_trusted_camoufox_browser_path(*browser))
                return fail("browser_runtime_untrusted");
            const std::string* session_id = env_value(cfg, "AIDA_CAMOUFOX_SESSION_ID");
            if (!session_id || trim(*session_id).empty())
                return fail("session_env_missing");
            if (!camoufox_session_name_matches_env(cfg.name, *session_id))
                return fail("session_name_mismatch");
            const std::string* work_dir = env_value(cfg, "AIDA_CAMOUFOX_WORKING_DIR");
            if (!work_dir || !is_trusted_camoufox_working_dir(*work_dir))
                return fail("working_dir_untrusted");
            const std::string* profile_root = env_value(cfg, "AIDA_CAMOUFOX_PROFILE_ROOT");
            if (!profile_root || !is_trusted_camoufox_profile_root(*profile_root))
                return fail("profile_root_untrusted");
            if (deny_reason)
                *deny_reason = "trusted";
            return true;
        }

        inline url_info_t parse_url(const std::string& raw)
        {
            url_info_t info;
            std::string url = trim(raw);
            std::string lower = lower_ascii(url);
            if (lower.rfind("http://", 0) == 0) {
                info.scheme = "http";
                info.port = 80;
                url = url.substr(7);
            } else if (lower.rfind("https://", 0) == 0) {
                info.scheme = "https";
                info.port = 443;
                url = url.substr(8);
            } else {
                return info;
            }
            const auto slash = url.find('/');
            std::string authority = slash == std::string::npos ? url : url.substr(0, slash);
            info.path = slash == std::string::npos ? "/" : url.substr(slash);
            const auto at = authority.rfind('@');
            if (at != std::string::npos) {
                info.userinfo = true;
                authority = authority.substr(at + 1);
            }
            if (authority.empty())
                return info;
            if (!authority.empty() && authority.front() == '[') {
                const auto end = authority.find(']');
                if (end == std::string::npos)
                    return info;
                info.host = lower_ascii(authority.substr(1, end - 1));
                if (end + 1 < authority.size() && authority[end + 1] == ':')
                    info.port = std::atoi(authority.c_str() + end + 2);
            } else {
                const auto colon = authority.rfind(':');
                if (colon != std::string::npos) {
                    info.host = lower_ascii(authority.substr(0, colon));
                    info.port = std::atoi(authority.c_str() + colon + 1);
                } else {
                    info.host = lower_ascii(authority);
                }
            }
            if (info.port <= 0)
                info.port = info.scheme == "https" ? 443 : 80;
            info.localhost = info.host == "127.0.0.1" || info.host == "localhost" || info.host == "::1";
            info.valid = !info.host.empty() && !info.scheme.empty();
            return info;
        }

        inline bool is_exact_managed_url(const std::string& url, int configured_port)
        {
            const std::string exact_mcp = "http://127.0.0.1:" + std::to_string(configured_port) + "/mcp";
            const std::string exact_sse = "http://127.0.0.1:" + std::to_string(configured_port) + "/sse";
            return trim(url) == exact_mcp || trim(url) == exact_sse;
        }

        inline bool is_aida_managed_endpoint_path(const std::string& path)
        {
            return path == "/mcp" || path == "/sse";
        }

        inline bool is_stale_aida_managed_local_url(const server_entry_t& e, const url_info_t& u, int configured_port)
        {
            const std::string url = trim(e.url);
            constexpr const char* prefix = "http://127.0.0.1:";
            constexpr std::size_t prefix_len = 17;
            if (url.rfind(prefix, 0) != 0)
                return false;
            const auto path_pos = url.find('/', prefix_len);
            if (path_pos == std::string::npos)
                return false;
            const std::string port_text = url.substr(prefix_len, path_pos - prefix_len);
            if (port_text.empty())
                return false;
            int parsed_port = 0;
            for (const char c : port_text) {
                if (c < '0' || c > '9')
                    return false;
                parsed_port = parsed_port * 10 + (c - '0');
                if (parsed_port > 65535)
                    return false;
            }
            const std::string path = url.substr(path_pos);
            return is_aida_managed_name(e.name) &&
                   e.transport == transport_t::http_sse &&
                   e.command.empty() &&
                   e.args.empty() &&
                   u.valid &&
                   !u.userinfo &&
                   u.scheme == "http" &&
                   u.host == "127.0.0.1" &&
                   u.port == parsed_port &&
                   parsed_port >= 1024 &&
                   u.port != configured_port &&
                   is_aida_managed_endpoint_path(path);
        }

        inline bool url_is_high_risk(const std::string& url)
        {
            if (trim(url).empty())
                return false;
            url_info_t info = parse_url(url);
            if (!info.valid)
                return true;
            if (info.userinfo)
                return true;
            if (!info.localhost)
                return true;
            if (contains_high_risk_token(info.host) || contains_high_risk_token(info.path))
                return true;
            return false;
        }

        inline void apply_decision(report_t& report, finding_t finding)
        {
            report.findings.push_back(finding);
            if (finding.deny) {
                report.trusted = false;
                report.denied = true;
                ++report.suspicious;
                if (report.reason.empty())
                    report.reason = finding.reason;
            }
            diag::log_tagged_fmt("mcp_posture",
                "entry source='%s' path_hash=0x%016llX server_hash=0x%016llX name_len=%zu transport=%s enabled=%d managed=%d localhost=%d port=%d cmd_hash=0x%016llX host_hash=0x%016llX metadata_hash=0x%016llX metadata_count=%zu high_cmd=%d launcher=%d high_url=%d offensive_meta=%d deny=%d reason=%s",
                finding.source.c_str(),
                static_cast<unsigned long long>(finding.path_hash),
                static_cast<unsigned long long>(finding.server_hash),
                finding.name_len,
                transport_name(finding.transport),
                finding.enabled ? 1 : 0,
                finding.managed_name ? 1 : 0,
                finding.localhost ? 1 : 0,
                finding.port,
                static_cast<unsigned long long>(finding.command_hash),
                static_cast<unsigned long long>(finding.url_host_hash),
                static_cast<unsigned long long>(finding.metadata_hash),
                finding.metadata_count,
                finding.high_risk_command ? 1 : 0,
                finding.launcher_command ? 1 : 0,
                finding.high_risk_url ? 1 : 0,
                finding.offensive_tool_metadata ? 1 : 0,
                finding.deny ? 1 : 0,
                finding.reason.c_str());
        }

        inline finding_t evaluate_entry(const server_entry_t& e, int configured_port, bool force_enabled, bool deny_enabled_unknown, bool allow_stale_aida_local)
        {
            finding_t f;
            f.source = e.source;
            f.enabled = force_enabled ? true : e.enabled;
            f.transport = e.transport;
            f.path_hash = e.path_hash;
            f.server_hash = fnv1a_string(normalized_name_key(e.name));
            f.name_len = e.name.size();
            f.managed_name = is_managed_name(e.name);
            f.high_risk_command = command_has_high_risk(e);
            f.launcher_command = command_uses_launcher(e);
            f.high_risk_url = url_is_high_risk(e.url);
            f.offensive_tool_metadata = entry_has_offensive_tool_metadata(e, f.metadata_hash, f.metadata_count);
            f.command_hash = e.command.empty() ? 0 : fnv1a_string(basename_for_hash(e.command));
            url_info_t u = parse_url(e.url);
            f.localhost = u.localhost;
            f.port = u.port;
            f.url_host_hash = u.host.empty() ? 0 : fnv1a_string(u.host);

            if (f.managed_name) {
                if (is_internal_camoufox_stdio(e)) {
                    f.reason = "managed_internal_camoufox_stdio";
                } else if (!is_aida_managed_name(e.name)) {
                    f.deny = true;
                    f.reason = "managed_name_spoof";
                } else if (f.offensive_tool_metadata || f.metadata_count != 0) {
                    f.deny = true;
                    f.reason = f.offensive_tool_metadata ? "offensive_tool_metadata" : "managed_name_spoof";
                } else if (e.transport != transport_t::http_sse || !e.command.empty() || !e.args.empty()) {
                    f.deny = true;
                    f.reason = "managed_name_spoof";
                } else if (is_exact_managed_url(e.url, configured_port)) {
                    f.reason = "managed_aida_local";
                } else if (allow_stale_aida_local && is_stale_aida_managed_local_url(e, u, configured_port)) {
                    f.reason = "managed_aida_local_stale_port";
                } else {
                    f.deny = true;
                    f.reason = "managed_name_spoof";
                }
                return f;
            }

            if (f.high_risk_command) {
                f.deny = true;
                f.reason = "high_risk_command";
                return f;
            }

            if (f.high_risk_url && (!u.localhost || f.enabled)) {
                f.deny = true;
                f.reason = "high_risk_url";
                return f;
            }

            if (f.offensive_tool_metadata) {
                f.deny = true;
                f.reason = "offensive_tool_metadata";
                return f;
            }

            if (f.enabled) {
                if (deny_enabled_unknown) {
                    f.deny = true;
                    f.reason = "enabled_unknown";
                } else {
                    f.reason = f.launcher_command ? "enabled_unknown_launcher_observed" : "enabled_unknown_observed";
                }
            } else {
                f.reason = "disabled_unknown";
            }
            return f;
        }

        inline std::uint64_t sanitized_summary_hash(const report_t& r)
        {
            std::uint64_t h = 14695981039346656037ULL;
            fnv_mix(h, r.trusted ? 1 : 0);
            fnv_mix(h, r.files_seen);
            fnv_mix(h, r.files_with_mcp);
            fnv_mix(h, r.servers_seen);
            fnv_mix(h, r.managed_allowed);
            fnv_mix(h, r.enabled_unknown);
            fnv_mix(h, r.disabled_unknown);
            fnv_mix(h, r.suspicious);
            fnv_mix(h, r.parse_failures);
            for (const auto& f : r.findings) {
                fnv_mix(h, f.path_hash);
                fnv_mix(h, f.server_hash);
                fnv_mix(h, f.command_hash);
                fnv_mix(h, f.url_host_hash);
                fnv_mix(h, f.metadata_hash);
                fnv_mix(h, f.metadata_count);
                fnv_mix(h, f.enabled ? 1 : 0);
                fnv_mix(h, f.managed_name ? 1 : 0);
                fnv_mix(h, f.high_risk_command ? 1 : 0);
                fnv_mix(h, f.launcher_command ? 1 : 0);
                fnv_mix(h, f.high_risk_url ? 1 : 0);
                fnv_mix(h, f.offensive_tool_metadata ? 1 : 0);
                fnv_mix(h, f.deny ? 1 : 0);
                fnv_mix(h, static_cast<std::uint64_t>(f.transport));
                fnv_mix(h, fnv1a_string(f.reason));
            }
            return h;
        }

        inline void cache_report(const report_t& report)
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_cached_report = report;
            if (report.denied)
                g_latched_denied.store(true, std::memory_order_release);
            const bool trusted = report.trusted && !g_latched_denied.load(std::memory_order_acquire);
            g_cached_report.latched = g_latched_denied.load(std::memory_order_acquire);
            g_cached_report.trusted = trusted;
            g_cached_trusted.store(trusted, std::memory_order_release);
            g_cached_summary_hash.store(g_cached_report.summary_hash, std::memory_order_release);
            g_scanned.store(true, std::memory_order_release);
        }

        inline void latch_runtime_denial(const finding_t& finding)
        {
            report_t r;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                r = g_cached_report;
                if (!r.scanned)
                    r.scanned = true;
                r.trusted = false;
                r.denied = true;
                r.latched = true;
                if (r.reason.empty())
                    r.reason = finding.reason.empty() ? "runtime_untrusted" : finding.reason;
                r.findings.push_back(finding);
                r.summary_hash = sanitized_summary_hash(r);
                g_cached_report = r;
                g_latched_denied.store(true, std::memory_order_release);
                g_cached_trusted.store(false, std::memory_order_release);
                g_cached_summary_hash.store(r.summary_hash, std::memory_order_release);
                g_scanned.store(true, std::memory_order_release);
            }
            diag::log_tagged_critical_fmt("mcp_posture",
                "runtime_latched_denial summary_hash=0x%016llX reason=%s",
                static_cast<unsigned long long>(r.summary_hash),
                r.reason.c_str());
        }
    }

    inline std::uint64_t sanitized_summary_hash(const report_t& report)
    {
        return detail::sanitized_summary_hash(report);
    }

    inline report_t cached_report()
    {
        std::lock_guard<std::mutex> lk(detail::g_mutex);
        return detail::g_cached_report;
    }

    inline bool is_current_posture_trusted()
    {
        if (!detail::g_scanned.load(std::memory_order_acquire)) {
            diag::log_tagged_critical("mcp_posture", "runtime_posture_unscanned_fail_closed");
            return false;
        }
        return detail::g_cached_trusted.load(std::memory_order_acquire) &&
               !detail::g_latched_denied.load(std::memory_order_acquire);
    }

    inline std::uint64_t cached_summary_hash()
    {
        return detail::g_cached_summary_hash.load(std::memory_order_acquire);
    }

    inline report_t scan_startup_posture(const settings_sa_t& settings)
    {
        report_t report;
        report.scanned = true;
        report.trusted = true;
        const int configured_port = settings.mcp_port > 0 ? settings.mcp_port : 29117;
        detail::g_configured_port.store(configured_port, std::memory_order_release);
        std::set<std::string> seen_paths;
        diag::log_tagged_fmt("mcp_posture", "startup_scan_start port=%d cwd_hash=0x%016llX",
            configured_port,
            static_cast<unsigned long long>(detail::fnv1a_string(detail::lower_ascii(detail::current_dir()))));
        for (const auto& source : detail::config_sources()) {
            const std::string path = detail::expand_path_template(source.path_template);
            if (path.empty())
                continue;
            const std::string path_key = detail::lower_ascii(path);
            if (!seen_paths.insert(path_key).second)
                continue;
            std::error_code ec;
            const bool exists = std::filesystem::exists(path, ec);
            if (ec || !exists)
                continue;
            ++report.files_seen;
            const std::uint64_t path_hash = detail::fnv1a_string(path_key);
            std::string raw;
            if (!detail::read_file_limited(path, raw)) {
                finding_t f;
                f.source = source.label;
                f.path_hash = path_hash;
                f.reason = "config_inaccessible";
                f.deny = true;
                ++report.parse_failures;
                detail::apply_decision(report, f);
                continue;
            }
            const bool marker = detail::text_has_mcp_marker(raw) || detail::path_has_mcp_marker(path);
            std::vector<detail::server_entry_t> entries;
            bool parsed = true;
            bool saw_toml_mcp = false;
            if (source.format == detail::source_format_t::toml) {
                parsed = detail::extract_toml_entries(source.label, path_hash, raw, entries, saw_toml_mcp);
            } else {
                detail::json root;
                parsed = detail::parse_json_text(raw, root);
                if (parsed)
                    entries = detail::extract_json_entries(source.label, path_hash, path, root);
            }
            if (!parsed && (marker || saw_toml_mcp)) {
                finding_t f;
                f.source = source.label;
                f.path_hash = path_hash;
                f.reason = "config_parse_failure";
                f.deny = true;
                ++report.parse_failures;
                detail::apply_decision(report, f);
                continue;
            }
            if (marker || !entries.empty())
                ++report.files_with_mcp;
            for (const auto& entry : entries) {
                ++report.servers_seen;
                finding_t f = detail::evaluate_entry(entry, configured_port, false, false, true);
                if (f.managed_name && !f.deny)
                    ++report.managed_allowed;
                else if (f.enabled && !f.managed_name)
                    ++report.enabled_unknown;
                else if (!f.enabled && !f.managed_name)
                    ++report.disabled_unknown;
                detail::apply_decision(report, std::move(f));
            }
        }
        report.summary_hash = detail::sanitized_summary_hash(report);
        report.latched = report.denied;
        detail::cache_report(report);
        report = cached_report();
        diag::log_tagged_critical_fmt("mcp_posture",
            "startup_scan_done trusted=%d denied=%d latched=%d files=%zu mcp_files=%zu servers=%zu managed=%zu enabled_unknown=%zu disabled_unknown=%zu suspicious=%zu parse_failures=%zu summary_hash=0x%016llX reason=%s",
            report.trusted ? 1 : 0,
            report.denied ? 1 : 0,
            report.latched ? 1 : 0,
            report.files_seen,
            report.files_with_mcp,
            report.servers_seen,
            report.managed_allowed,
            report.enabled_unknown,
            report.disabled_unknown,
            report.suspicious,
            report.parse_failures,
            static_cast<unsigned long long>(report.summary_hash),
            report.reason.empty() ? "none" : report.reason.c_str());
        return report;
    }

    inline bool is_runtime_trusted_server(const mcp_client::server_config_t& cfg, bool force_enabled)
    {
        detail::server_entry_t e;
        e.source = "runtime";
        e.path_hash = 0;
        e.name = cfg.name;
        e.url = cfg.url;
        e.command = cfg.command;
        e.args = cfg.args;
        e.transport = cfg.transport == mcp_client::transport_type_t::stdio ? transport_t::stdio : transport_t::http_sse;
        e.enabled = cfg.enabled;
        const int configured_port = detail::g_configured_port.load(std::memory_order_acquire) > 0
            ? detail::g_configured_port.load(std::memory_order_acquire)
            : 29117;
        report_t cached = cached_report();
        finding_t f = detail::evaluate_entry(e, configured_port, force_enabled, true, false);
        std::string camoufox_predicate;
        const bool camoufox_named = detail::is_camoufox_managed_name(cfg.name);
        if (camoufox_named) {
            const std::string source_reason = f.reason.empty() ? std::string("none") : f.reason;
            if (!detail::is_internal_camoufox_runtime_server(cfg, &camoufox_predicate)) {
                f.deny = true;
                f.reason = camoufox_predicate.empty() ? "camoufox_internal_predicate_failed" : camoufox_predicate;
                const auto browser_it = cfg.env.find("AIDA_CAMOUFOX_EXECUTABLE");
                const auto work_it = cfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
                const auto profile_it = cfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT");
                diag::log_tagged_fmt("mcp_posture",
                    "runtime_camoufox_internal_reject server_hash=0x%016llX name_len=%zu source_reason=%s predicate=%s command_hash=0x%016llX browser_hash=0x%016llX work_hash=0x%016llX profile_hash=0x%016llX args=%zu env=%zu summary_hash=0x%016llX",
                    static_cast<unsigned long long>(f.server_hash),
                    f.name_len,
                    source_reason.c_str(),
                    f.reason.c_str(),
                    static_cast<unsigned long long>(detail::fnv1a_string(detail::canonical_lower_path(cfg.command))),
                    static_cast<unsigned long long>(browser_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(browser_it->second))),
                    static_cast<unsigned long long>(work_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(work_it->second))),
                    static_cast<unsigned long long>(profile_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(profile_it->second))),
                    cfg.args.size(),
                    cfg.env.size(),
                    static_cast<unsigned long long>(cached_summary_hash()));
                detail::apply_decision(cached, f);
                detail::latch_runtime_denial(f);
                return false;
            }
            if (!is_current_posture_trusted()) {
                f.deny = true;
                f.reason = "posture_not_trusted";
                detail::latch_runtime_denial(f);
                return false;
            }
            const auto browser_it = cfg.env.find("AIDA_CAMOUFOX_EXECUTABLE");
            const auto work_it = cfg.env.find("AIDA_CAMOUFOX_WORKING_DIR");
            const auto profile_it = cfg.env.find("AIDA_CAMOUFOX_PROFILE_ROOT");
            diag::log_tagged_fmt("mcp_posture",
                "runtime_camoufox_internal_allow server_hash=0x%016llX name_len=%zu source_reason=%s predicate=%s command_hash=0x%016llX browser_hash=0x%016llX work_hash=0x%016llX profile_hash=0x%016llX args=%zu env=%zu summary_hash=0x%016llX",
                static_cast<unsigned long long>(f.server_hash),
                f.name_len,
                source_reason.c_str(),
                camoufox_predicate.empty() ? "trusted" : camoufox_predicate.c_str(),
                static_cast<unsigned long long>(detail::fnv1a_string(detail::canonical_lower_path(cfg.command))),
                static_cast<unsigned long long>(browser_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(browser_it->second))),
                static_cast<unsigned long long>(work_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(work_it->second))),
                static_cast<unsigned long long>(profile_it == cfg.env.end() ? 0 : detail::fnv1a_string(detail::canonical_lower_path(profile_it->second))),
                cfg.args.size(),
                cfg.env.size(),
                static_cast<unsigned long long>(cached_summary_hash()));
            return true;
        }
        if (f.deny) {
            detail::apply_decision(cached, f);
            detail::latch_runtime_denial(f);
            return false;
        }
        if ((force_enabled || cfg.enabled) && !is_current_posture_trusted()) {
            f.deny = true;
            f.reason = "posture_not_trusted";
            detail::latch_runtime_denial(f);
            return false;
        }
        diag::log_tagged_fmt("mcp_posture",
            "runtime_server_allow server_hash=0x%016llX name_len=%zu transport=%s enabled=%d managed=%d summary_hash=0x%016llX",
            static_cast<unsigned long long>(f.server_hash),
            f.name_len,
            detail::transport_name(f.transport),
            (force_enabled || cfg.enabled) ? 1 : 0,
            f.managed_name ? 1 : 0,
            static_cast<unsigned long long>(cached_summary_hash()));
        return true;
    }

    inline bool is_runtime_trusted_server(const mcp_client::server_config_t& cfg)
    {
        return is_runtime_trusted_server(cfg, false);
    }

    inline bool is_remote_tool_metadata_trusted(const std::string& server_name, const std::string& tool_name, const std::string& description)
    {
        if (!is_current_posture_trusted()) {
            diag::log_tagged_fmt("mcp_posture",
                "runtime_tool_metadata_block_posture_not_trusted server_hash=0x%016llX name_len=%zu tool_hash=0x%016llX",
                static_cast<unsigned long long>(detail::fnv1a_string(detail::normalized_name_key(server_name))),
                server_name.size(),
                static_cast<unsigned long long>(detail::fnv1a_string(tool_name)));
            return false;
        }
        if (detail::is_managed_name(server_name) || detail::is_camoufox_managed_name(server_name)) {
            diag::log_tagged_fmt("mcp_posture",
                "runtime_tool_metadata_allow_managed server_hash=0x%016llX name_len=%zu tool_hash=0x%016llX desc_len=%zu summary_hash=0x%016llX",
                static_cast<unsigned long long>(detail::fnv1a_string(detail::normalized_name_key(server_name))),
                server_name.size(),
                static_cast<unsigned long long>(detail::fnv1a_string(tool_name)),
                description.size(),
                static_cast<unsigned long long>(cached_summary_hash()));
            return true;
        }
        detail::server_entry_t e;
        e.source = "runtime_tools";
        e.name = server_name;
        e.enabled = true;
        e.transport = transport_t::stdio;
        e.tool_metadata.push_back(tool_name);
        if (!description.empty())
            e.tool_metadata.push_back(description);
        std::uint64_t metadata_hash = 0;
        std::size_t metadata_count = 0;
        if (!detail::entry_has_offensive_tool_metadata(e, metadata_hash, metadata_count))
            return true;
        finding_t f;
        f.source = e.source;
        f.server_hash = detail::fnv1a_string(detail::normalized_name_key(server_name));
        f.name_len = server_name.size();
        f.transport = e.transport;
        f.enabled = true;
        f.offensive_tool_metadata = true;
        f.metadata_hash = metadata_hash;
        f.metadata_count = metadata_count;
        f.deny = true;
        f.reason = "runtime_offensive_tool_metadata";
        report_t cached = cached_report();
        detail::apply_decision(cached, f);
        detail::latch_runtime_denial(f);
        return false;
    }
}
