#include "camoufox_bridge_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "../../settings/standalone_compat.hpp"

#ifdef small
#undef small
#endif

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace aida {
namespace burp {

namespace {

using mcp_standalone::tool_result_t;
using nlohmann::json;

const char* state_label(camoufox::bridge_state_t s)
{
    switch (s)
    {
        case camoufox::bridge_state_t::stopped:  return "stopped";
        case camoufox::bridge_state_t::starting: return "starting";
        case camoufox::bridge_state_t::ready:    return "ready";
        case camoufox::bridge_state_t::error:    return "error";
    }
    return "unknown";
}

json status_to_json(const camoufox::bridge_status_t& s)
{
    json j;
    j["session_id"]       = s.session_id;
    j["active_session_id"] = s.active_session_id;
    j["state"]            = state_label(s.state);
    j["last_error"]       = s.last_error;
    j["server_command"]   = s.server_command;
    j["child_pid"]        = s.child_pid;
    j["launched_ms"]      = s.launched_ms;
    j["last_call_ms"]     = s.last_call_ms;
    j["total_calls"]      = s.total_calls;
    j["total_errors"]     = s.total_errors;
    j["browser_open"]     = s.browser_open;
    j["active_page_id"]   = s.active_page_id;
    j["active_page_url"]  = s.active_page_url;
    j["active_page_title"] = s.active_page_title;
    j["page_count"]       = s.page_count;
    j["session_count"]    = s.session_count;
    j["browser_instance_count"] = s.browser_instance_count;
    j["child_process_count"] = s.child_process_count;
    j["browser_process_count"] = s.browser_process_count;
    j["pages"]            = json::array();
    for (const auto& p : s.pages)
    {
        j["pages"].push_back({
            {"page_id", p.page_id},
            {"context_id", p.context_id},
            {"url", p.url},
            {"title", p.title},
            {"guid", p.guid},
            {"active", p.active},
            {"closed", p.closed},
            {"created_ms", p.created_ms},
            {"last_used_ms", p.last_used_ms},
        });
    }
    j["active_profile_dir"] = s.active_profile_dir;
    j["active_profile_generated"] = s.active_profile_generated;
    j["effective_ua_policy"] = s.effective_ua_policy;
    j["ua_override"] = s.ua_override;
    j["ua_override_string"] = s.ua_override_string;
    j["webrtc_blocked"] = s.webrtc_blocked;
    j["privacy_verified"] = s.privacy_verified;
    j["privacy_diagnostics"] = s.privacy_diagnostics.is_object() ? s.privacy_diagnostics : json::object();
    j["page_verified"]    = s.page_verified;
    j["child_alive"]      = s.child_alive;
    j["cleanup_pending"]  = s.cleanup_pending;
    j["generation"]       = s.generation;
    j["last_launch_ms"]   = s.last_launch_ms;
    j["last_nav_ms"]      = s.last_nav_ms;
    j["last_cleanup_ms"]  = s.last_cleanup_ms;
    j["last_verified_ms"] = s.last_verified_ms;
    j["ready"]            = s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.privacy_verified && s.child_alive && !s.cleanup_pending;
    return j;
}

bool bridge_ready(const camoufox::bridge_status_t& s)
{
    return s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.privacy_verified && s.child_alive && !s.cleanup_pending;
}

void attach_privacy_status(tool_result_t& out, const camoufox::bridge_status_t& s)
{
    if (!out.data.is_object())
        out.data = json{{"value", out.data}};
    json privacy = json::object();
    privacy["effective_ua_policy"] = s.effective_ua_policy;
    privacy["ua_override"] = s.ua_override;
    privacy["ua_override_string"] = s.ua_override_string;
    privacy["webrtc_blocked"] = s.webrtc_blocked;
    privacy["privacy_verified"] = s.privacy_verified;
    privacy["page_verified"] = s.page_verified;
    privacy["active_profile_generated"] = s.active_profile_generated;
    privacy["browser_instance_count"] = s.browser_instance_count;
    privacy["child_process_count"] = s.child_process_count;
    privacy["browser_process_count"] = s.browser_process_count;
    privacy["diagnostics"] = s.privacy_diagnostics.is_object() ? s.privacy_diagnostics : json::object();
    out.data["aida_privacy"] = std::move(privacy);
}

camoufox::bridge_status_t wait_for_ready_status(int timeout_ms)
{
    if (timeout_ms < 0)
        timeout_ms = 0;
    const auto start = std::chrono::steady_clock::now();
    camoufox::bridge_status_t s = camoufox::get_status();
    while (!bridge_ready(s))
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeout_ms)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        s = camoufox::get_status();
    }
    return s;
}

const char* json_type_name(const json& j)
{
    if (j.is_object()) return "object";
    if (j.is_array()) return "array";
    if (j.is_string()) return "string";
    if (j.is_boolean()) return "boolean";
    if (j.is_number()) return "number";
    if (j.is_null()) return "null";
    return "other";
}

std::string json_shape(const json& j, size_t max_keys = 12)
{
    std::ostringstream oss;
    oss << json_type_name(j);
    if (j.is_object())
    {
        oss << "{";
        size_t n = 0;
        for (auto it = j.begin(); it != j.end() && n < max_keys; ++it, ++n)
        {
            if (n) oss << ",";
            oss << it.key() << ":" << json_type_name(it.value());
        }
        if (j.size() > max_keys) oss << ",...";
        oss << "}";
    }
    else if (j.is_array())
    {
        oss << "[" << j.size() << "]";
    }
    return oss.str();
}

struct url_log_t
{
    std::string host;
    std::string path;
    bool has_query = false;
    bool has_fragment = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    size_t host_start = 0;
    size_t scheme = url.find("://");
    if (scheme != std::string::npos) host_start = scheme + 3;
    size_t host_end = url.find_first_of("/?#", host_start);
    if (host_end == std::string::npos) host_end = url.size();
    if (host_end > host_start) out.host = url.substr(host_start, host_end - host_start);
    size_t path_start = url.find('/', host_start);
    size_t query_pos = url.find('?', host_start);
    size_t frag_pos = url.find('#', host_start);
    out.has_query = query_pos != std::string::npos;
    out.has_fragment = frag_pos != std::string::npos;
    size_t path_end = url.size();
    if (query_pos != std::string::npos) path_end = query_pos;
    if (frag_pos != std::string::npos && frag_pos < path_end) path_end = frag_pos;
    if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    if (out.path.empty()) out.path = "/";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    if (out.host.empty()) out.host = "<relative>";
    return out;
}


int json_int_param(const json& params, const char* name, int fallback)
{
    if (!params.is_object() || !params.contains(name))
        return fallback;
    const json& v = params[name];
    try
    {
        if (v.is_number_integer())
            return v.get<int>();
        if (v.is_number())
            return static_cast<int>(v.get<double>());
    }
    catch (...) {}
    return fallback;
}

bool json_bool_param(const json& params, const char* name, bool fallback)
{
    if (!params.is_object() || !params.contains(name) || !params[name].is_boolean())
        return fallback;
    return params[name].get<bool>();
}

std::string json_string_param(const json& params, const char* name, const std::string& fallback = std::string())
{
    if (!params.is_object() || !params.contains(name) || !params[name].is_string())
        return fallback;
    return params[name].get<std::string>();
}

std::string lower_ascii_copy(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::wstring utf8_to_wide_local(const std::string& s)
{
    if (s.empty())
        return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0)
        return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

bool decode_base64_string(const std::string& b64, std::vector<unsigned char>& decoded)
{
    static const signed char table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    decoded.clear();
    decoded.reserve((b64.size() / 4) * 3);
    int value = 0;
    int bits = 0;
    bool saw_data = false;
    for (char c : b64)
    {
        const unsigned char uc = static_cast<unsigned char>(c);
        const int v = table[uc];
        if (v == -2)
            break;
        if (v < 0)
            continue;
        saw_data = true;
        value = (value << 6) | v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            decoded.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
        }
    }
    return saw_data && !decoded.empty();
}

uint32_t read_be_u32(const std::vector<unsigned char>& bytes, size_t offset)
{
    if (bytes.size() < offset + 4)
        return 0;
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

json png_dimensions(const std::vector<unsigned char>& bytes)
{
    static const unsigned char sig[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    json out = json::object();
    if (bytes.size() < 24 || !std::equal(sig, sig + 8, bytes.begin()))
        return out;
    out["width"] = read_be_u32(bytes, 16);
    out["height"] = read_be_u32(bytes, 20);
    return out;
}

bool write_binary_file_utf8(const std::string& path, const std::vector<unsigned char>& bytes, std::string& error)
{
    if (path.empty())
    {
        error = "empty path";
        return false;
    }
    ensure_parent_dir_exists(path);
    std::wstring wpath = utf8_to_wide_local(path);
    if (wpath.empty())
    {
        error = "path conversion failed";
        return false;
    }
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        error = "CreateFileW failed gle=" + std::to_string(GetLastError());
        return false;
    }
    size_t offset = 0;
    bool ok = true;
    while (offset < bytes.size())
    {
        const size_t remaining = bytes.size() - offset;
        const DWORD chunk = static_cast<DWORD>((std::min)(remaining, static_cast<size_t>(1 << 20)));
        DWORD written = 0;
        if (!WriteFile(h, bytes.data() + offset, chunk, &written, nullptr) || written != chunk)
        {
            error = "WriteFile failed gle=" + std::to_string(GetLastError());
            ok = false;
            break;
        }
        offset += written;
    }
    CloseHandle(h);
    return ok;
}

std::string default_screenshot_path()
{
    char temp[MAX_PATH] = {};
    DWORD len = GetTempPathA(static_cast<DWORD>(sizeof(temp)), temp);
    std::filesystem::path root = (len > 0 && len < static_cast<DWORD>(sizeof(temp))) ? std::filesystem::path(temp) : std::filesystem::temp_directory_path();
    root /= "AiDA";
    root /= "camoufox-screenshots";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    char name[128] = {};
    std::snprintf(name, sizeof(name), "camoufox_%lu_%lu_%llu.png",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(GetTickCount64()));
    return (root / name).string();
}

int screenshot_inline_limit(const json& params)
{
    int limit = json_int_param(params, "max_base64_chars", 4096);
    if (limit < 0)
        limit = 0;
    if (limit > 16384)
        limit = 16384;
    return limit;
}

void compact_screenshot_response(tool_result_t& out, const json& params)
{
    if (!out.success || !out.data.is_object())
        return;
    auto b64_it = out.data.find("screenshot_base64");
    if (b64_it == out.data.end() || !b64_it->is_string())
        return;
    const std::string b64 = b64_it->get<std::string>();
    std::vector<unsigned char> bytes;
    const bool decoded = decode_base64_string(b64, bytes);
    out.data["screenshot_base64_total_chars"] = b64.size();
    out.data["screenshot_inline_policy"] = "compact_by_default";
    if (decoded)
    {
        out.data["screenshot_bytes"] = bytes.size();
        json dims = png_dimensions(bytes);
        if (!dims.empty())
            out.data["image"] = dims;
        std::string save_path = json_string_param(params, "save_path", std::string());
        if (save_path.empty())
            save_path = default_screenshot_path();
        std::string write_error;
        if (write_binary_file_utf8(save_path, bytes, write_error))
        {
            out.data["artifact_path"] = save_path;
        }
        else
        {
            out.data["artifact_write_error"] = write_error;
        }
    }
    const bool include_base64 = json_bool_param(params, "include_base64", false);
    const int max_chars = screenshot_inline_limit(params);
    if (include_base64 && max_chars > 0)
    {
        const size_t returned = (std::min)(b64.size(), static_cast<size_t>(max_chars));
        out.data["screenshot_base64"] = b64.substr(0, returned);
        out.data["screenshot_base64_returned_chars"] = returned;
        out.data["screenshot_base64_truncated"] = returned < b64.size();
    }
    else
    {
        out.data.erase("screenshot_base64");
        out.data["screenshot_base64_omitted"] = true;
        out.data["screenshot_base64_returned_chars"] = 0;
    }
    out.text = out.data.dump(2);
}

std::string evaluate_js_hint_for_error(const std::string& error)
{
    const std::string low = lower_ascii_copy(error);
    if (low.find("takes exactly") != std::string::npos && low.find("argument") != std::string::npos)
        return "The JavaScript expression or browser callback was invoked with the wrong arity. The MCP tool itself expects arguments {expression:string, await_promise?:boolean, session_id?:string, page_id?:string}; inspect the target function's name and length before calling it, or call it with the required parameters inside an IIFE.";
    if (low.find("expected expression") != std::string::npos || low.find("unexpected token") != std::string::npos)
        return "Playwright evaluate expects one JavaScript expression. Wrap statements in an IIFE such as (() => { const x = 1; return x; })().";
    if (low.find("not serializable") != std::string::npos || low.find("serialize") != std::string::npos || low.find("cloneable") != std::string::npos)
        return "Return primitives, arrays, or plain JSON objects. Convert DOM nodes, Symbols, functions, and circular objects to strings or explicit fields.";
    if (low.find("timeout") != std::string::npos || low.find("exceeded") != std::string::npos)
        return "The page did not finish the evaluation before the timeout. Check page responsiveness, reduce the expression, or keep await_promise enabled for Promise-returning code.";
    return "evaluate_js expects {expression:string, await_promise?:boolean}. Use a single expression and return serializable data.";
}

tool_result_t validate_evaluate_js_params(const json& params)
{
    if (!params.is_object())
        return tool_result_t::error("evaluate_js expects an arguments object with `expression` as a string.");
    auto it = params.find("expression");
    if (it == params.end() || !it->is_string() || it->get<std::string>().empty())
    {
        json data;
        data["error"] = "missing_expression";
        data["expected_arguments"] = json::array({"expression", "await_promise", "session_id", "page_id"});
        data["schema"] = json{{"expression", "string"}, {"await_promise", "boolean"}, {"session_id", "string"}, {"page_id", "string"}};
        data["hint"] = "Call evaluate_js with arguments like {\"expression\":\"document.title\",\"await_promise\":true}.";
        return {false, "evaluate_js missing required string argument `expression`.", data};
    }
    return tool_result_t::ok(json{{"status", "ok"}});
}

void enrich_evaluate_js_response(tool_result_t& out)
{
    if (out.success)
        return;
    std::string error = out.text;
    if (error.empty() && out.data.is_object())
    {
        auto it = out.data.find("error");
        if (it != out.data.end() && it->is_string())
            error = it->get<std::string>();
    }
    if (out.data.is_null() || !out.data.is_object())
        out.data = json::object();
    out.data["error"] = error.empty() ? std::string("evaluate_js failed") : error;
    if (!out.data.contains("hint") || out.data["hint"].is_null() || (out.data["hint"].is_string() && out.data["hint"].get<std::string>().empty()))
        out.data["hint"] = evaluate_js_hint_for_error(error);
    out.data["playwright_evaluate_signature"] = "page.evaluate(expression, arg?)";
    out.data["mcp_arguments"] = json::array({"expression", "await_promise", "session_id", "page_id"});
}

bool reverse_tool_needs_action(const std::string& tool_name)
{
    return tool_name == "network_capture" ||
        tool_name == "cookies" ||
        tool_name == "instrumentation" ||
        tool_name == "intercept_request" ||
        tool_name == "scripts";
}

json camoufox_args(const json& params, bool preserve_action)
{
    json args = params.is_object() ? params : json::object();
    args.erase("binary_id");
    args.erase("session_id");
    args.erase("call_timeout_ms");
    args.erase("launch_timeout_ms");
    args.erase("python_executable");
    args.erase("browser_executable");
    args.erase("server_executable");
    args.erase("server_module");
    if (!preserve_action)
        args.erase("action");
    args.erase("operation");
    args.erase("payload");
    return args;
}

int camoufox_timeout_ms(const json& params, int fallback)
{
    int timeout_ms = fallback > 0 ? fallback : 30000;
    timeout_ms = json_int_param(params, "call_timeout_ms", timeout_ms);
    timeout_ms = json_int_param(params, "timeout_ms", timeout_ms);
    const int timeout = json_int_param(params, "timeout", 0);
    if (timeout > 0)
        timeout_ms = (std::max)(timeout_ms, timeout + 5000);
    const int duration = json_int_param(params, "duration", 0);
    if (duration > 0)
        timeout_ms = (std::max)(timeout_ms, duration * 1000 + 15000);
    if (timeout_ms < 5000) timeout_ms = 5000;
    if (timeout_ms > 300000) timeout_ms = 300000;
    return timeout_ms;
}

tool_result_t bridge_result_to_tool_result(const camoufox::call_result_t& r)
{
    if (r.ok)
    {
        if (!r.data.is_null())
            return tool_result_t::ok(r.data);
        if (!r.text.empty())
            return tool_result_t::ok(r.text);
        return tool_result_t::ok(json{{"status", "ok"}});
    }

    tool_result_t out;
    out.success = false;
    out.text = r.error.empty() ? (r.text.empty() ? std::string("camoufox tool failed") : r.text) : r.error;
    if (!r.data.is_null())
        out.data = r.data;
    return out;
}

tool_result_t tool_camoufox_click(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    const std::string selector = params["selector"].get<std::string>();
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_click_direct entry selector=%s state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("click", args, 5000, session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_click_direct exit selector=%s success=%d elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

tool_result_t tool_camoufox_type_text(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    if (!params.contains("text") || !params["text"].is_string())
        return tool_result_t::error("missing_text");
    const std::string selector = params["selector"].get<std::string>();
    const std::string text = params["text"].get<std::string>();
    const int delay = json_int_param(params, "delay", 0);
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_type_direct entry selector=%s text_len=%zu delay=%d state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        text.size(),
        delay,
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    args["text"] = text;
    args["delay"] = delay;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("type_text", args, 5000, session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_type_direct exit selector=%s success=%d text_len=%zu elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s out_text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        text.size(),
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

tool_result_t tool_camoufox_wait_for_selector(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    const std::string selector = params["selector"].get<std::string>();
    int timeout_ms = json_int_param(params, "timeout", 5000);
    if (timeout_ms < 1) timeout_ms = 5000;
    if (timeout_ms > 60000) timeout_ms = 60000;
    const std::string session_id = json_string_param(params, "session_id", "default");
    const std::string page_id = json_string_param(params, "page_id", std::string());
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_wait_direct entry selector=%s timeout_ms=%d state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        timeout_ms,
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    args["timeout"] = timeout_ms;
    if (!page_id.empty()) args["page_id"] = page_id;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("wait_for", args, timeout_ms + 5000, session_id));
    auto after = camoufox::get_status(session_id);
    if (out.data.is_object())
        out.data["bridge"] = status_to_json(after);
    diag::log_tagged_fmt("mcp_burp", "camoufox_wait_direct exit selector=%s success=%d timeout_ms=%d elapsed_ms=%llu state=%s child_pid=%lu data_shape=%s text_len=%zu",
        selector.c_str(),
        static_cast<int>(out.success),
        timeout_ms,
        static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()),
        state_label(after.state),
        static_cast<unsigned long>(after.child_pid),
        json_shape(out.data).c_str(),
        out.text.size());
    return out;
}

camoufox::launch_config_t launch_config_from_mcp_params(const json& params)
{
    camoufox::launch_config_t cfg;
    cfg.session_id = json_string_param(params, "session_id", cfg.session_id);
    cfg.headless = json_bool_param(params, "headless", cfg.headless);
    cfg.proxy = json_string_param(params, "proxy", cfg.proxy);
    cfg.os = json_string_param(params, "os_type", json_string_param(params, "os", cfg.os));
    cfg.locale = json_string_param(params, "locale", cfg.locale);
    cfg.humanize = json_bool_param(params, "humanize", cfg.humanize);
    cfg.geoip = json_bool_param(params, "geoip", cfg.geoip);
    cfg.block_images = json_bool_param(params, "block_images", cfg.block_images);
    cfg.block_webrtc = json_bool_param(params, "block_webrtc", cfg.block_webrtc);
    cfg.block_webrtc = true;
    cfg.user_agent = json_string_param(params, "user_agent", json_string_param(params, "userAgent", cfg.user_agent));
    cfg.ua_policy = json_string_param(params, "ua_policy",
        json_string_param(params, "user_agent_profile",
            json_string_param(params, "user_agent_mode", cfg.ua_policy)));
    cfg.persistent_context = json_bool_param(params, "persistent_context", cfg.persistent_context);
    cfg.profile_dir = json_string_param(params, "profile_dir", cfg.profile_dir);
    cfg.user_data_dir = json_string_param(params, "user_data_dir", cfg.user_data_dir);
    cfg.enable_trace = json_bool_param(params, "enable_trace", cfg.enable_trace);
    cfg.python_executable = json_string_param(params, "python_executable", cfg.python_executable);
    cfg.browser_executable = json_string_param(params, "browser_executable", cfg.browser_executable);
    cfg.server_executable = json_string_param(params, "server_executable", cfg.server_executable);
    cfg.launch_timeout_ms = json_int_param(params, "launch_timeout_ms", cfg.launch_timeout_ms);
    cfg.window_width = json_int_param(params, "window_width", json_int_param(params, "width", cfg.window_width));
    cfg.window_height = json_int_param(params, "window_height", json_int_param(params, "height", cfg.window_height));
    cfg.testlab_fast_probe = json_bool_param(params, "aida_testlab_fast_probe", json_bool_param(params, "testlab_fast_probe", cfg.testlab_fast_probe));
    return cfg;
}

tool_result_t tool_launch_browser(const json& params)
{
    camoufox::launch_config_t cfg = launch_config_from_mcp_params(params);
    bool ok = camoufox::start_bridge(cfg);
    auto status = camoufox::get_status(cfg.session_id);
    json j = status_to_json(status);
    if (!ok)
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox launch_browser failed"));
        out.data = j;
        return out;
    }
    if (!bridge_ready(status))
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox launch_browser did not become ready"));
        out.data = j;
        return out;
    }
    return tool_result_t::ok(j);
}

tool_result_t tool_close_browser(const json& params)
{
    const std::string session_id = json_string_param(params, "session_id", "default");
    bool ok = camoufox::stop_bridge(session_id, "camoufox_mcp.close_browser");
    json j = status_to_json(camoufox::get_status(session_id));
    if (!ok)
    {
        tool_result_t out;
        out.success = false;
        out.text = j.value("last_error", std::string("camoufox close_browser failed"));
        out.data = j;
        return out;
    }
    return tool_result_t::ok(j);
}

tool_result_t tool_camoufox_passthrough(const std::string& tool_name, const json& params, int default_timeout_ms)
{
    json args = camoufox_args(params, reverse_tool_needs_action(tool_name));
    int timeout_ms = camoufox_timeout_ms(params, default_timeout_ms);
    const std::string session_id = json_string_param(params, "session_id", "default");
    auto before = camoufox::get_status(session_id);
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_passthrough entry tool=%s timeout_ms=%d args_shape=%s bridge_state=%s child_pid=%lu browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        tool_name.c_str(), timeout_ms, json_shape(args).c_str(), state_label(before.state),
        static_cast<unsigned long>(before.child_pid), static_cast<int>(before.browser_open),
        static_cast<int>(before.page_verified), static_cast<int>(before.child_alive), static_cast<int>(before.cleanup_pending));
    if (tool_name == "click")
        return tool_camoufox_click(params);
    if (tool_name == "type_text")
        return tool_camoufox_type_text(params);
    if (tool_name == "wait_for" && params.is_object() && params.contains("selector") && params["selector"].is_string())
        return tool_camoufox_wait_for_selector(params);
    if (tool_name == "evaluate_js")
    {
        tool_result_t validation = validate_evaluate_js_params(params);
        if (!validation.success)
            return validation;
    }
    json capture_info = json::object();
    if (tool_name == "take_screenshot")
    {
        args.erase("include_base64");
        args.erase("max_base64_chars");
        args.erase("save_path");
    }
    if (tool_name == "navigate")
    {
        const bool capture_from_start = json_bool_param(params, "capture_from_start", false);
        const bool capture_body = json_bool_param(params, "capture_body", false);
        const std::string capture_pattern = json_string_param(params, "capture_url_pattern", "**/*");
        args.erase("capture_from_start");
        args.erase("capture_body");
        args.erase("capture_url_pattern");
        if (capture_from_start)
        {
            json clear_args;
            clear_args["action"] = "clear";
            camoufox::call_result_t clear_result = camoufox::call_tool("network_capture", clear_args, 10000, session_id);
            json start_args;
            start_args["action"] = "start";
            start_args["url_pattern"] = capture_pattern.empty() ? std::string("**/*") : capture_pattern;
            start_args["capture_body"] = capture_body;
            camoufox::call_result_t start_result = camoufox::call_tool("network_capture", start_args, 10000, session_id);
            capture_info["requested"] = true;
            capture_info["pattern"] = start_args["url_pattern"];
            capture_info["capture_body"] = capture_body;
            capture_info["clear_ok"] = clear_result.ok;
            capture_info["start_ok"] = start_result.ok;
            if (!clear_result.ok)
                capture_info["clear_error"] = clear_result.error;
            if (!start_result.ok)
            {
                capture_info["start_error"] = start_result.error;
                tool_result_t fail;
                fail.success = false;
                fail.text = start_result.error.empty() ? std::string("network capture start failed before navigate") : start_result.error;
                fail.data = json{{"error", fail.text}, {"network_capture", capture_info}};
                return fail;
            }
        }
    }
    camoufox::call_result_t bridge_result = camoufox::call_tool(tool_name, args, timeout_ms, session_id);
    tool_result_t out = bridge_result_to_tool_result(bridge_result);
    if (tool_name == "take_screenshot")
        compact_screenshot_response(out, params);
    if (tool_name == "evaluate_js")
        enrich_evaluate_js_response(out);
    if (tool_name == "navigate" && !capture_info.empty() && capture_info.value("requested", false))
    {
        if (out.data.is_null() || !out.data.is_object())
            out.data = json::object();
        out.data["network_capture"] = capture_info;
    }
    auto after = camoufox::get_status(session_id);
    if (tool_name == "compare_env" || tool_name == "check_environment")
        attach_privacy_status(out, after);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    std::string failure_phase;
    try
    {
        if (!out.success && out.data.is_object())
        {
            auto it = out.data.find("phase");
            if (it != out.data.end() && it->is_string())
                failure_phase = it->get<std::string>();
        }
    }
    catch (...) {}
    diag::log_tagged_fmt("mcp_burp", "camoufox_passthrough exit tool=%s success=%d elapsed_ms=%lld data_shape=%s text_len=%zu failure_phase=%s bridge_state=%s child_pid=%lu browser_open=%d page_verified=%d child_alive=%d cleanup_pending=%d",
        tool_name.c_str(), static_cast<int>(out.success), static_cast<long long>(elapsed_ms),
        json_shape(out.data).c_str(), out.text.size(), failure_phase.c_str(), state_label(after.state),
        static_cast<unsigned long>(after.child_pid), static_cast<int>(after.browser_open),
        static_cast<int>(after.page_verified), static_cast<int>(after.child_alive), static_cast<int>(after.cleanup_pending));
    return out;
}

struct camoufox_tool_spec_t
{
    const char* name;
    const char* description;
    std::vector<compat_param_t> params;
    bool read_only;
    int timeout_ms;
};

struct camoufox_action_entry_t
{
    const char* action;
    const char* internal_tool;
    int default_timeout_ms;
};

const camoufox_action_entry_t* find_camoufox_action(
    const std::string& action,
    const camoufox_action_entry_t* entries,
    size_t entry_count)
{
    for (size_t i = 0; i < entry_count; ++i)
    {
        if (action == entries[i].action)
            return &entries[i];
    }
    return nullptr;
}

json camoufox_group_payload(const json& params)
{
    json out = params.is_object() ? params : json::object();
    out.erase("action");
    out.erase("operation");
    out.erase("payload");
    if (params.contains("payload") && params["payload"].is_object())
    {
        for (auto it = params["payload"].begin(); it != params["payload"].end(); ++it)
            out[it.key()] = it.value();
    }
    return out;
}

tool_result_t dispatch_camoufox_browser_group(
    const json& params,
    const char* group_name,
    const camoufox_action_entry_t* actions,
    size_t action_count)
{
    std::string action = lower_ascii_copy(json_string_param(params, "action", ""));
    if (action.empty())
        action = lower_ascii_copy(json_string_param(params, "operation", ""));
    if (action.empty())
        return tool_result_t::error(std::string(group_name) + " requires action");

    const camoufox_action_entry_t* action_spec = find_camoufox_action(action, actions, action_count);
    if (!action_spec)
        return tool_result_t::error("Unsupported " + std::string(group_name) + " action: " + action);

    const json forwarded = camoufox_group_payload(params);
    if (std::string(action_spec->internal_tool) == "launch_browser")
        return tool_launch_browser(forwarded);
    if (std::string(action_spec->internal_tool) == "close_browser")
        return tool_close_browser(forwarded);

    return tool_camoufox_passthrough(
        action_spec->internal_tool,
        forwarded,
        action_spec->default_timeout_ms);
}

tool_result_t tool_browser_lifecycle(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"launch", "launch_browser", 60000},
        {"close", "close_browser", 30000},
        {"list", "list_pages", 15000},
        {"new", "new_page", 30000},
        {"select", "select_page", 15000},
        {"close_page", "close_page", 15000},
    };
    return dispatch_camoufox_browser_group(params, "browser_lifecycle",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_navigation(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"navigate", "navigate", 60000},
        {"reload", "reload", 45000},
        {"wait", "wait_for", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_navigation",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_interaction(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"click", "click", 30000},
        {"type", "type_text", 30000},
        {"evaluate", "evaluate_js", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_interaction",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_inspect(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"screenshot", "take_screenshot", 60000},
        {"snapshot", "take_snapshot", 30000},
        {"info", "get_page_info", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_inspect",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_state(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"cookies", "cookies", 30000},
        {"storage", "get_storage", 30000},
        {"export", "export_state", 30000},
        {"import", "import_state", 30000},
        {"reset", "reset_browser_state", 45000},
    };
    return dispatch_camoufox_browser_group(params, "browser_state",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_network(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"capture", "network_capture", 30000},
        {"list", "list_network_requests", 30000},
        {"get", "get_network_request", 30000},
        {"initiator", "get_request_initiator", 30000},
        {"intercept", "intercept_request", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_network",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_hooks(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"hook", "hook_function", 45000},
        {"init_script", "add_init_script", 30000},
        {"preset", "inject_hook_preset", 30000},
        {"remove", "remove_hooks", 30000},
    };
    return dispatch_camoufox_browser_group(params, "browser_hooks",
        actions, sizeof(actions) / sizeof(actions[0]));
}

tool_result_t tool_browser_instrumentation(const json& params)
{
    static const camoufox_action_entry_t actions[] =
    {
        {"manage", "instrumentation", 60000},
        {"jsvmp", "hook_jsvmp_interpreter", 60000},
        {"trace", "trace_property_access", 120000},
        {"list_files", "list_trace_files", 30000},
        {"query_file", "query_trace_file", 60000},
    };
    return dispatch_camoufox_browser_group(params, "browser_instrumentation",
        actions, sizeof(actions) / sizeof(actions[0]));
}

std::vector<camoufox_tool_spec_t> camoufox_tool_specs()
{
    return {
        {"browser_lifecycle", "Consolidated Camoufox lifecycle management. Set action to launch, close, list, new, select, or close_page.",
            {{"action", "string", "launch|close|list|new|select|close_page", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"url", "string", "Optional URL for a new page", false},
             {"make_active", "boolean", "Make a new page active", false},
             {"headless", "boolean", "Run in headless mode", false},
             {"os_type", "string", "Spoofed OS: auto, windows, macos, or linux", false},
             {"locale", "string", "Browser locale such as en-US", false},
             {"proxy", "string", "Proxy URL such as http://127.0.0.1:8443", false},
             {"humanize", "boolean", "Enable humanized mouse movement", false},
             {"geoip", "boolean", "Infer geolocation from proxy IP", false},
             {"block_images", "boolean", "Block image loading", false},
             {"block_webrtc", "boolean", "Force WebRTC blocking; AiDA enforces this on", false},
             {"user_agent", "string", "Custom Camoufox user agent", false},
             {"userAgent", "string", "Alias for user_agent", false},
             {"ua_policy", "string", "camoufox_native, camoufox_auto, camoufox_windows, camoufox_macos, camoufox_linux, random_camoufox_desktop, or custom with user_agent", false},
             {"user_agent_profile", "string", "Alias for ua_policy", false},
             {"user_agent_mode", "string", "Alias for ua_policy", false},
             {"persistent_context", "boolean", "Use a persistent Camoufox browser context", false},
             {"profile_dir", "string", "Persistent Camoufox profile directory", false},
             {"user_data_dir", "string", "Alias for persistent profile directory", false},
             {"enable_trace", "boolean", "Enable engine-level property access tracing", false},
             {"python_executable", "string", "Optional Python path for developer sessions", false},
             {"browser_executable", "string", "Optional camoufox.exe path", false},
             {"server_executable", "string", "Optional AiDA-owned frozen reverse-MCP executable path", false},
             {"launch_timeout_ms", "number", "Requested launch timeout in milliseconds", false},
             {"window_width", "number", "Initial browser window width", false},
             {"window_height", "number", "Initial browser window height", false}}, false, 60000},
        {"browser_navigation", "Consolidated Camoufox navigation operations. Set action to navigate, reload, or wait.",
            {{"action", "string", "navigate|reload|wait", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"url", "string", "Target URL", false},
             {"wait_until", "string", "load, domcontentloaded, or networkidle", false},
             {"selector", "string", "CSS selector to wait for", false},
             {"url_pattern", "string", "URL pattern to wait for", false},
             {"timeout", "number", "Wait timeout in milliseconds", false},
             {"pre_inject_hooks", "array", "Hook preset names to register before navigation", false},
             {"collect_response_chain", "boolean", "Record response chain", false},
             {"clear_network_capture", "boolean", "Clear stale network capture before navigating", false},
             {"capture_from_start", "boolean", "Start network capture before navigation", false},
             {"capture_body", "boolean", "Capture response bodies", false},
             {"capture_url_pattern", "string", "Network capture URL glob", false},
             {"include_title", "boolean", "Return page title when available", false}}, false, 60000},
        {"browser_interaction", "Consolidated Camoufox interaction operations. Set action to click, type, or evaluate.",
            {{"action", "string", "click|type|evaluate", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"selector", "string", "CSS selector", false},
             {"text", "string", "Text to type", false},
             {"delay", "number", "Delay between key presses in milliseconds", false},
             {"expression", "string", "JavaScript expression", false},
             {"await_promise", "boolean", "Await promise return values", false}}, false, 45000},
        {"browser_inspect", "Consolidated Camoufox inspection operations. Set action to screenshot, snapshot, or info.",
            {{"action", "string", "screenshot|snapshot|info", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"full_page", "boolean", "Capture the full scrollable page", false},
             {"selector", "string", "CSS selector for an element screenshot", false},
             {"save_path", "string", "Optional PNG file path", false},
             {"include_base64", "boolean", "Return bounded inline base64", false},
             {"max_base64_chars", "number", "Maximum inline base64 characters", false}}, false, 60000},
        {"browser_state", "Consolidated Camoufox state operations. Set action to cookies, storage, export, import, or reset.",
            {{"action", "string", "cookies|storage|export|import|reset", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"session_id", "string", "Browser session id", false},
             {"domain", "string", "Cookie domain filter", false},
             {"cookies_list", "array", "Cookie objects to set", false},
             {"name", "string", "Cookie name", false},
             {"storage_type", "string", "local or session", false},
             {"save_path", "string", "Destination JSON path", false},
             {"state_path", "string", "Source JSON path", false},
             {"clear_persistent_hooks", "boolean", "Remove persistent init scripts", false},
             {"clear_network_capture", "boolean", "Clear network capture buffer and stop captures", false},
             {"clear_active_routes", "boolean", "Clear instrumentation routes", false},
             {"clear_cookies", "boolean", "Clear browser cookies", false},
             {"clear_storage", "boolean", "Clear localStorage and sessionStorage", false}}, false, 45000},
        {"browser_network", "Consolidated Camoufox network operations. Set action to capture, list, get, initiator, or intercept.",
            {{"action", "string", "capture|list|get|initiator|intercept", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted; use payload.action for capture start, stop, clear, or status", false},
             {"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", false},
             {"request_id", "number", "Captured request id", false},
             {"url_pattern", "string", "URL glob pattern", false},
             {"url_filter", "string", "Substring filter for URLs", false},
             {"url_contains_domain", "string", "Domain substring filter", false},
             {"method", "string", "HTTP method filter", false},
             {"resource_type", "string", "Resource type filter", false},
             {"status_code", "number", "HTTP status code filter", false},
             {"capture_body", "boolean", "Capture response bodies", false},
             {"include_body", "boolean", "Include response body", false},
             {"include_headers", "boolean", "Include request and response headers", false},
             {"max_body_size", "number", "Maximum body characters", false},
             {"modify_headers", "object", "Headers to add or override", false},
             {"modify_body", "string", "Replacement request body", false},
             {"mock_response", "object", "Mock response object", false}}, false, 30000},
        {"browser_hooks", "Consolidated Camoufox hook operations. Set action to hook, init_script, preset, or remove.",
            {{"action", "string", "hook|init_script|preset|remove", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted", false},
             {"function_path", "string", "Path such as window.encrypt", false},
             {"mode", "string", "intercept or trace", false},
             {"hook_code", "string", "Custom hook code", false},
             {"position", "string", "before, after, or replace", false},
             {"non_overridable", "boolean", "Install a non-overridable descriptor", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"log_args", "boolean", "Capture function arguments", false},
             {"log_return", "boolean", "Capture return values", false},
             {"log_stack", "boolean", "Capture stack traces", false},
             {"max_captures", "number", "Maximum captures to keep", false},
             {"script", "string", "JavaScript source", false},
             {"name", "string", "Optional script or preset name", false},
             {"preset", "string", "Built-in hook preset", false},
             {"keep_persistent", "boolean", "Keep persistent init scripts registered", false}}, false, 45000},
        {"browser_instrumentation", "Consolidated Camoufox instrumentation operations. Set action to manage, jsvmp, trace, list_files, or query_file.",
            {{"action", "string", "manage|jsvmp|trace|list_files|query_file", true},
             {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted; use payload.action for instrumentation install, status, log, stop, or reload", false},
             {"session_id", "string", "Browser session id", false},
             {"script_url", "string", "Optional script URL focus", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"mode", "string", "Instrumentation or trace mode", false},
             {"track_calls", "boolean", "Track calls", false},
             {"track_props", "boolean", "Track property access", false},
             {"track_reflect", "boolean", "Track Reflect APIs", false},
             {"proxy_objects", "array", "Global objects to proxy", false},
             {"max_entries", "number", "Maximum log entries", false},
             {"url_pattern", "string", "URL glob to instrument", false},
             {"tag", "string", "Instrumentation tag", false},
             {"rewrite_member_access", "boolean", "Rewrite member property access", false},
             {"rewrite_calls", "boolean", "Rewrite calls", false},
             {"max_rewrites", "number", "Maximum rewrites", false},
             {"fallback_on_error", "boolean", "Fall back when AST rewrite fails", false},
             {"ignore_csp", "boolean", "Bypass CSP for injected scripts", false},
             {"clear_log", "boolean", "Clear log before reload", false},
             {"wait_until", "string", "Navigation wait state for reload", false},
             {"tag_filter", "string", "Filter instrumentation log by tag", false},
             {"type_filter", "string", "Filter instrumentation log by event type", false},
             {"key_filter", "string", "Filter instrumentation log by key", false},
             {"limit", "number", "Maximum events or files", false},
             {"clear", "boolean", "Clear log after retrieval", false},
             {"filter_property_names", "array", "Property-name allowlist", false},
             {"filter_object_names", "array", "Object-name allowlist", false},
             {"max_file_size", "number", "Maximum script size to rewrite", false},
             {"on_oversized", "string", "Oversized script policy", false},
             {"duration", "number", "Trace duration in seconds", false},
             {"filter_object", "string", "Trace object filter", false},
             {"search_query", "string", "Trace search query", false},
             {"bucket_ms", "number", "Timeline bucket size", false},
             {"collect_values", "boolean", "Collect property values", false},
             {"file_path", "string", "Trace JSONL path", false}}, false, 120000},
        {"get_console_logs", "Return console output collected from Camoufox pages.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id filter", false},
             {"level", "string", "Filter by log, warn, error, or info", false},
             {"keyword", "string", "Filter logs containing this text", false},
             {"clear", "boolean", "Clear the log buffer after retrieval", false}}, true, 30000},
        {"scripts", "List loaded scripts, get source for one script, or save a script to disk.",
            {{"action", "string", "list, get, or save", true},
             {"url", "string", "Script URL for get or save", false},
             {"save_path", "string", "Destination path for save", false}}, false, 30000},
        {"search_code", "Search loaded scripts for a keyword.",
            {{"keyword", "string", "Keyword to search for", true},
             {"script_url", "string", "Optional script URL to limit the search", false},
             {"context_chars", "number", "Characters of context around matches", false},
             {"context_lines", "number", "Lines of context around matches", false},
             {"max_results", "number", "Maximum matches", false}}, true, 30000},
        {"compare_env", "Collect browser environment fingerprint data for comparison.",
            {{"properties", "array", "Specific properties to check", false}}, true, 65000},
        {"check_environment", "Run reverse-MCP dependency, browser, privacy, and runtime state checks.",
            {{"session_id", "string", "Browser session id", false}}, true, 30000},
        {"verify_signer_offline", "Verify a candidate JavaScript signing function against captured samples offline.",
            {{"signer_code", "string", "Candidate signer source", true},
             {"samples", "array", "Request/signature samples", true},
             {"compare_params", "array", "Parameter names to compare", false}}, true, 30000},
        {"analyze_cookie_sources", "Attribute observed cookies to HTTP headers or JavaScript writes.",
            {{"name_filter", "string", "Optional cookie-name filter", false}}, true, 30000}
    };
}

}

void register_camoufox_reverse_tools(mcp_standalone::server_t& srv)
{
    for (const auto& spec : camoufox_tool_specs())
    {
        const std::string tool_name = spec.name;
        const int timeout_ms = spec.timeout_ms;
        auto handler = [tool_name, timeout_ms](const json& params) -> tool_result_t {
            if (tool_name == "browser_lifecycle")
                return tool_browser_lifecycle(params);
            if (tool_name == "browser_navigation")
                return tool_browser_navigation(params);
            if (tool_name == "browser_interaction")
                return tool_browser_interaction(params);
            if (tool_name == "browser_inspect")
                return tool_browser_inspect(params);
            if (tool_name == "browser_state")
                return tool_browser_state(params);
            if (tool_name == "browser_network")
                return tool_browser_network(params);
            if (tool_name == "browser_hooks")
                return tool_browser_hooks(params);
            if (tool_name == "browser_instrumentation")
                return tool_browser_instrumentation(params);
            return tool_camoufox_passthrough(tool_name, params, timeout_ms);
        };
        register_compat(srv, {
            spec.name,
            "camoufox_reverse",
            spec.description,
            spec.params,
            handler,
            spec.read_only
        });
    }
}
void register_camoufox_tools(mcp_standalone::server_t& srv)
{
    register_camoufox_reverse_tools(srv);
}

}
}
