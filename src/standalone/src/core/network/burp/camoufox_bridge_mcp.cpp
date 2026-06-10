#include "camoufox_bridge_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"
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

const char* install_state_label(camoufox::install::install_state_t s)
{
    switch (s)
    {
        case camoufox::install::install_state_t::unknown:         return "unknown";
        case camoufox::install::install_state_t::checking:        return "checking";
        case camoufox::install::install_state_t::available:       return "available";
        case camoufox::install::install_state_t::missing_python:  return "missing_python";
        case camoufox::install::install_state_t::missing_module:  return "missing_module";
        case camoufox::install::install_state_t::missing_browser: return "missing_browser";
        case camoufox::install::install_state_t::installing:      return "installing";
        case camoufox::install::install_state_t::install_failed:  return "install_failed";
        case camoufox::install::install_state_t::ok:              return "ok";
    }
    return "unknown";
}

json install_status_to_json(const camoufox::install::status_t& s)
{
    json j;
    j["state"] = install_state_label(s.state);
    j["python_path"] = s.python_path;
    j["module_version"] = s.module_version;
    j["browser_path"] = s.browser_path;
    j["last_message"] = s.last_message;
    j["ready"] = s.state == camoufox::install::install_state_t::ok;
    return j;
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
    j["page_verified"]    = s.page_verified;
    j["child_alive"]      = s.child_alive;
    j["cleanup_pending"]  = s.cleanup_pending;
    j["generation"]       = s.generation;
    j["last_launch_ms"]   = s.last_launch_ms;
    j["last_nav_ms"]      = s.last_nav_ms;
    j["last_cleanup_ms"]  = s.last_cleanup_ms;
    j["last_verified_ms"] = s.last_verified_ms;
    j["ready"]            = s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.child_alive && !s.cleanup_pending;
    return j;
}

bool bridge_ready(const camoufox::bridge_status_t& s)
{
    return s.state == camoufox::bridge_state_t::ready && s.browser_open && s.page_verified && s.child_alive && !s.cleanup_pending;
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

json camoufox_args(const json& params)
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
    if (tool_name == "check_environment")
    {
        (void)params;
        auto install_status = camoufox::install::probe();
        auto bridge_status = camoufox::get_status();
        json data;
        data["install"] = install_status_to_json(install_status);
        data["bridge"] = status_to_json(bridge_status);
        data["dependencies_ready"] = install_status.state == camoufox::install::install_state_t::ok;
        data["bridge_ready"] = bridge_status.state == camoufox::bridge_state_t::ready &&
            bridge_status.browser_open && bridge_status.page_verified && bridge_status.child_alive &&
            !bridge_status.cleanup_pending;
        data["ready"] = data["dependencies_ready"].get<bool>();
        const std::string instructions = camoufox::install::setup_instructions();
        if (!data["dependencies_ready"].get<bool>())
            data["setup_instructions"] = instructions;
        std::string text = data["dependencies_ready"].get<bool>()
            ? std::string("Camoufox dependencies are ready.")
            : std::string("Camoufox dependencies are not ready: ") + install_status.last_message;
        if (!data["dependencies_ready"].get<bool>() && text.find(instructions) == std::string::npos)
            text += "\n" + instructions;
        diag::log_tagged_fmt("mcp_burp", "camoufox_check_environment deps_ready=%d install_state=%s bridge_state=%s message=%s",
            data["dependencies_ready"].get<bool>() ? 1 : 0,
            install_state_label(install_status.state),
            state_label(bridge_status.state),
            install_status.last_message.c_str());
        if (!data["dependencies_ready"].get<bool>())
            return {false, text, data};
        return tool_result_t::ok(text, data);
    }
    json args = camoufox_args(params);
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

std::vector<camoufox_tool_spec_t> camoufox_tool_specs()
{
    return {
        {"launch_browser", "Launch Camoufox through AiDA's private bridge with WebRTC disabled; on fresh machines the PowerShell launcher prepares the verified sidecar.",
            {{"session_id", "string", "Independent browser session id; default keeps legacy behavior", false},
             {"headless", "boolean", "Run in headless mode; AiDA defaults to visible headed Camoufox", false},
             {"os_type", "string", "Spoofed OS: auto, windows, macos, or linux", false},
             {"locale", "string", "Browser locale such as en-US; auto uses the system locale", false},
             {"proxy", "string", "Proxy URL such as http://127.0.0.1:8443", false},
             {"humanize", "boolean", "Enable humanized mouse movement", false},
             {"geoip", "boolean", "Infer geolocation from proxy IP", false},
             {"block_images", "boolean", "Block image loading", false},
             {"block_webrtc", "boolean", "Compatibility field; AiDA always blocks WebRTC before launch", false},
             {"enable_trace", "boolean", "Enable engine-level property access tracing", false},
             {"python_executable", "string", "Optional Python 3.10-3.13 path; the launcher enables system Python for this session", false},
             {"browser_executable", "string", "Optional camoufox.exe path; normally set by the PowerShell launcher", false},
             {"server_executable", "string", "Optional AiDA-owned frozen camoufox reverse MCP executable path", false},
             {"launch_timeout_ms", "number", "Requested launch timeout in milliseconds; AiDA bounds the readiness handshake internally", false},
             {"window_width", "number", "Initial outer browser window width in pixels", false},
             {"window_height", "number", "Initial outer browser window height in pixels", false}}, false, 60000},
        {"close_browser", "Close Camoufox and stop the selected private Python bridge.",
            {{"session_id", "string", "Browser session id; default closes the legacy session", false}}, false, 30000},
        {"list_pages", "List pages/tabs in a Camoufox browser session.",
            {{"session_id", "string", "Browser session id", false}}, true, 15000},
        {"new_page", "Create a new Camoufox tab/page in a browser session.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id to request", false},
             {"url", "string", "Optional URL to navigate after creating the page", false},
             {"make_active", "boolean", "Make the new page the session active page", false}}, false, 30000},
        {"select_page", "Select a page as the active target for legacy calls in a browser session.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", true}}, false, 15000},
        {"close_page", "Close a specific Camoufox tab/page without stopping the browser session.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id", true}}, false, 15000},
        {"navigate", "Navigate a Camoufox page with optional hook pre-injection and redirect tracing.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"url", "string", "Target URL", true},
             {"wait_until", "string", "load, domcontentloaded, or networkidle", false},
             {"pre_inject_hooks", "array", "Hook preset names to register before navigation", false},
             {"collect_response_chain", "boolean", "Record response chain for final status resolution", false},
             {"clear_network_capture", "boolean", "Clear stale network capture before navigating", false},
             {"capture_from_start", "boolean", "Start network capture immediately before navigation", false},
             {"capture_body", "boolean", "Capture response bodies when capture_from_start is true", false},
             {"capture_url_pattern", "string", "Network capture URL glob when capture_from_start is true", false},
             {"include_title", "boolean", "Return page title when available", false}}, false, 60000},
        {"reload", "Reload a Camoufox page while preserving init scripts.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"wait_until", "string", "load, domcontentloaded, or networkidle", false}}, false, 45000},
        {"take_screenshot", "Capture a compact PNG screenshot artifact of a Camoufox page or selected element.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"full_page", "boolean", "Capture the full scrollable page", false},
             {"selector", "string", "CSS selector for an element screenshot", false},
             {"save_path", "string", "Optional PNG file path; omitted writes a temp artifact", false},
             {"include_base64", "boolean", "Return bounded inline base64; default omits it", false},
             {"max_base64_chars", "number", "Maximum inline base64 characters, capped at 16384; default 4096", false}}, true, 60000},
        {"take_snapshot", "Return a token-efficient accessibility snapshot of a Camoufox page.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false}}, true, 30000},
        {"click", "Click an element matching a CSS selector in a Camoufox page.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"selector", "string", "CSS selector", true}}, false, 30000},
        {"type_text", "Type text into an element with realistic keystroke delay.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"selector", "string", "CSS selector", true},
             {"text", "string", "Text to type", true},
             {"delay", "number", "Delay between key presses in milliseconds", false}}, false, 30000},
        {"wait_for", "Wait for a selector or URL pattern in Camoufox.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"selector", "string", "CSS selector to wait for", false},
             {"url_pattern", "string", "URL pattern to wait for", false},
             {"timeout", "number", "Wait timeout in milliseconds", false}}, true, 45000},
        {"get_page_info", "Return page URL, title, viewport size, and page identity.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false}}, true, 30000},
        {"reset_browser_state", "Clear Camoufox residual state such as persistent hooks, capture buffers, routes, cookies, or storage.",
            {{"clear_persistent_hooks", "boolean", "Remove persistent init scripts", false},
             {"clear_network_capture", "boolean", "Clear network capture buffer and stop captures", false},
             {"clear_active_routes", "boolean", "Clear instrumentation routes", false},
             {"clear_cookies", "boolean", "Clear browser cookies", false},
             {"clear_storage", "boolean", "Clear localStorage and sessionStorage", false}}, false, 45000},
        {"evaluate_js", "Execute one JavaScript expression in a Camoufox page context and return serializable data.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses the selected page", false},
             {"expression", "string", "JavaScript expression", true},
             {"await_promise", "boolean", "Await promise return values", false}}, false, 45000},
        {"hook_function", "Hook or trace a JavaScript function by path.",
            {{"function_path", "string", "Path such as window.encrypt or XMLHttpRequest.prototype.open", true},
             {"mode", "string", "intercept or trace", false},
             {"hook_code", "string", "Custom hook code for intercept mode", false},
             {"position", "string", "before, after, or replace", false},
             {"non_overridable", "boolean", "Install a non-overridable descriptor", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"log_args", "boolean", "Capture function arguments", false},
             {"log_return", "boolean", "Capture return values", false},
             {"log_stack", "boolean", "Capture stack traces", false},
             {"max_captures", "number", "Maximum captures to keep", false}}, false, 45000},
        {"add_init_script", "Register JavaScript to run before page scripts on future navigations.",
            {{"script", "string", "JavaScript source", true},
             {"name", "string", "Optional script name", false}}, false, 30000},
        {"inject_hook_preset", "Inject a built-in hook preset such as xhr, fetch, crypto, websocket, cookie, or runtime_probe.",
            {{"preset", "string", "Preset name", true},
             {"persistent", "boolean", "Persist across navigations", false}}, false, 30000},
        {"remove_hooks", "Remove installed JavaScript hooks and restore originals.",
            {{"keep_persistent", "boolean", "Keep persistent init scripts registered", false}}, false, 30000},
        {"get_console_logs", "Return console output collected from Camoufox pages.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id filter", false},
             {"level", "string", "Filter by log, warn, error, or info", false},
             {"keyword", "string", "Filter logs containing this text", false},
             {"clear", "boolean", "Clear the log buffer after retrieval", false}}, true, 30000},
        {"network_capture", "Start, stop, clear, or report Camoufox network capture.",
            {{"session_id", "string", "Browser session id", false},
             {"action", "string", "start, stop, clear, or status", true},
             {"url_pattern", "string", "URL glob pattern", false},
             {"capture_body", "boolean", "Capture response bodies", false}}, false, 30000},
        {"list_network_requests", "List captured network requests with optional filters.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id filter", false},
             {"url_filter", "string", "Substring filter for URLs", false},
             {"url_contains_domain", "string", "Domain substring filter", false},
             {"method", "string", "HTTP method filter", false},
             {"resource_type", "string", "Resource type filter", false},
             {"status_code", "number", "HTTP status code filter", false}}, true, 30000},
        {"get_network_request", "Return full details for a captured network request.",
            {{"request_id", "number", "Request id from list_network_requests", true},
             {"include_body", "boolean", "Include response body", false},
             {"include_headers", "boolean", "Include request and response headers", false},
             {"max_body_size", "number", "Maximum body characters", false}}, true, 30000},
        {"get_request_initiator", "Return the JavaScript call stack that initiated a captured request.",
            {{"session_id", "string", "Browser session id", false},
             {"page_id", "string", "Stable AiDA page id; omitted uses request page or selected page", false},
             {"request_id", "number", "Request id from list_network_requests", true}}, true, 30000},
        {"intercept_request", "Intercept matching network requests and log, block, modify, mock, or stop routing.",
            {{"url_pattern", "string", "URL glob pattern", true},
             {"action", "string", "log, block, modify, mock, or stop", false},
             {"modify_headers", "object", "Headers to add or override", false},
             {"modify_body", "string", "Replacement request body", false},
             {"mock_response", "object", "Mock response object", false}}, false, 30000},
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
        {"cookies", "Get, set, or delete browser cookies.",
            {{"action", "string", "get, set, or delete", true},
             {"domain", "string", "Domain filter", false},
             {"cookies_list", "array", "Cookie objects to set", false},
             {"name", "string", "Cookie name for delete", false}}, false, 30000},
        {"get_storage", "Return localStorage or sessionStorage from the selected page.",
            {{"storage_type", "string", "local or session", false}}, true, 30000},
        {"export_state", "Export cookies and storage to a JSON file.",
            {{"save_path", "string", "Destination JSON path", true}}, false, 30000},
        {"import_state", "Import cookies and storage from a JSON file into a new context.",
            {{"state_path", "string", "Source JSON path", true}}, false, 30000},
        {"hook_jsvmp_interpreter", "Install a JSVMP runtime probe for interpreter analysis.",
            {{"script_url", "string", "Optional script URL focus", false},
             {"persistent", "boolean", "Persist across navigations", false},
             {"mode", "string", "Probe mode", false},
             {"track_calls", "boolean", "Track calls", false},
             {"track_props", "boolean", "Track property access", false},
             {"track_reflect", "boolean", "Track Reflect APIs", false},
             {"proxy_objects", "array", "Global objects to proxy", false},
             {"max_entries", "number", "Maximum log entries", false}}, false, 60000},
        {"compare_env", "Collect browser environment fingerprint data for comparison.",
            {{"properties", "array", "Specific properties to check", false}}, true, 30000},
        {"instrumentation", "Install, query, stop, or reload source-level JSVMP instrumentation.",
            {{"action", "string", "install, status, log, stop, or reload", true},
             {"url_pattern", "string", "URL glob to instrument", false},
             {"mode", "string", "ast or regex", false},
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
             {"limit", "number", "Maximum log entries", false},
             {"clear", "boolean", "Clear log after retrieval", false},
             {"filter_property_names", "array", "Property-name allowlist", false},
             {"filter_object_names", "array", "Object-name allowlist", false},
             {"max_file_size", "number", "Maximum script size to rewrite", false},
             {"on_oversized", "string", "Oversized script policy", false}}, false, 60000},
        {"check_environment", "Check Camoufox MCP dependencies and browser state.", {}, true, 5000},
        {"verify_signer_offline", "Verify a candidate JavaScript signing function against captured samples offline.",
            {{"signer_code", "string", "Candidate signer source", true},
             {"samples", "array", "Request/signature samples", true},
             {"compare_params", "array", "Parameter names to compare", false}}, true, 30000},
        {"trace_property_access", "Collect engine-level DOM property access trace data.",
            {{"duration", "number", "Trace duration in seconds", false},
             {"mode", "string", "summary, timeline, sequence, or search", false},
             {"filter_object", "string", "Object name filter", false},
             {"search_query", "string", "Search query", false},
             {"limit", "number", "Maximum events", false},
             {"bucket_ms", "number", "Timeline bucket size in milliseconds", false},
             {"collect_values", "boolean", "Collect property values", false}}, true, 120000},
        {"list_trace_files", "List persisted Camoufox property trace files.",
            {{"limit", "number", "Maximum files", false}}, true, 30000},
        {"query_trace_file", "Query a persisted Camoufox property trace file.",
            {{"file_path", "string", "Trace JSONL path", true},
             {"mode", "string", "summary, timeline, sequence, or search", false},
             {"filter_object", "string", "Object name filter", false},
             {"search_query", "string", "Search query", false},
             {"limit", "number", "Maximum events", false},
             {"bucket_ms", "number", "Timeline bucket size in milliseconds", false}}, true, 60000},
        {"analyze_cookie_sources", "Attribute observed cookies to HTTP headers or JavaScript writes.",
            {{"name_filter", "string", "Optional cookie-name filter", false}}, true, 30000}
    };
}

void register_camoufox_reverse_tools(mcp_standalone::server_t& srv)
{
    for (const auto& spec : camoufox_tool_specs())
    {
        const std::string tool_name = spec.name;
        const int timeout_ms = spec.timeout_ms;
        auto handler = [tool_name, timeout_ms](const json& params) -> tool_result_t {
            if (tool_name == "launch_browser")
                return tool_launch_browser(params);
            if (tool_name == "close_browser")
                return tool_close_browser(params);
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

















}

void register_camoufox_tools(mcp_standalone::server_t& srv)
{
    register_camoufox_reverse_tools(srv);

















}

}
}
