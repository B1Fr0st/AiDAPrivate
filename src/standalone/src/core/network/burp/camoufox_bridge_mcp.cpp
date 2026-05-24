#include "camoufox_bridge_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "../../settings/standalone_compat.hpp"

#ifdef small
#undef small
#endif

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <sstream>
#include <string>

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
    j["state"]            = state_label(s.state);
    j["last_error"]       = s.last_error;
    j["server_command"]   = s.server_command;
    j["child_pid"]        = s.child_pid;
    j["launched_ms"]      = s.launched_ms;
    j["last_call_ms"]     = s.last_call_ms;
    j["total_calls"]      = s.total_calls;
    j["total_errors"]     = s.total_errors;
    j["browser_open"]     = s.browser_open;
    j["active_page_url"]  = s.active_page_url;
    j["ready"]            = s.state == camoufox::bridge_state_t::ready;
    return j;
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

tool_result_t tool_headless_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_start entry params_shape=%s", json_shape(params).c_str());
    camoufox::launch_config_t cfg;
    if (params.is_object())
    {
        if (params.contains("headless") && params["headless"].is_boolean())
            cfg.headless = params["headless"].get<bool>();
        if (params.contains("proxy") && params["proxy"].is_string())
            cfg.proxy = params["proxy"].get<std::string>();
        if (params.contains("os") && params["os"].is_string())
            cfg.os = params["os"].get<std::string>();
        if (params.contains("locale") && params["locale"].is_string())
            cfg.locale = params["locale"].get<std::string>();
        if (params.contains("humanize") && params["humanize"].is_boolean())
            cfg.humanize = params["humanize"].get<bool>();
        if (params.contains("block_images") && params["block_images"].is_boolean())
            cfg.block_images = params["block_images"].get<bool>();
        if (params.contains("block_webrtc") && params["block_webrtc"].is_boolean())
            cfg.block_webrtc = params["block_webrtc"].get<bool>();
        if (params.contains("python_executable") && params["python_executable"].is_string())
            cfg.python_executable = params["python_executable"].get<std::string>();
        if (params.contains("server_module") && params["server_module"].is_string())
            cfg.server_module = params["server_module"].get<std::string>();
        if (params.contains("launch_timeout_ms") && params["launch_timeout_ms"].is_number_integer())
            cfg.launch_timeout_ms = params["launch_timeout_ms"].get<int>();
    }
    diag::log_tagged_fmt("mcp_burp", "headless_start config headless=%d has_proxy=%d proxy_len=%zu os=%s locale=%s humanize=%d block_images=%d block_webrtc=%d python=%s module=%s timeout_ms=%d",
        (int)cfg.headless, (int)!cfg.proxy.empty(), cfg.proxy.size(), cfg.os.c_str(), cfg.locale.c_str(),
        (int)cfg.humanize, (int)cfg.block_images, (int)cfg.block_webrtc,
        cfg.python_executable.c_str(), cfg.server_module.c_str(), cfg.launch_timeout_ms);
    bool ok = camoufox::start_bridge(cfg);
    auto s = camoufox::get_status();
    json j = status_to_json(s);
    if (!ok)
    {
        std::string err = s.last_error.empty() ? camoufox::last_error() : s.last_error;
        diag::log_tagged_fmt("mcp_burp", "headless_start failed state=%s browser_open=%d calls=%llu errors=%llu err_len=%zu err=%s",
            state_label(s.state), (int)s.browser_open, static_cast<unsigned long long>(s.total_calls),
            static_cast<unsigned long long>(s.total_errors), err.size(), err.c_str());
        return tool_result_t::error(err.empty() ? std::string("camoufox start failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_start ok state=%s browser_open=%d calls=%llu errors=%llu response_shape=%s",
        state_label(s.state), (int)s.browser_open, static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), json_shape(j).c_str());
    return tool_result_t::ok(j);
}

tool_result_t tool_headless_stop(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "headless_stop entry");
    bool ok = camoufox::stop_bridge();
    auto s = camoufox::get_status();
    json j = status_to_json(s);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "headless_stop failed err=%s", camoufox::last_error().c_str());
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("camoufox stop failed") : camoufox::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "headless_stop ok");
    return tool_result_t::ok(j);
}

tool_result_t tool_headless_status(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "headless_status entry");
    auto s = camoufox::get_status();
    json j = status_to_json(s);
    const url_log_t u = summarize_url_for_log(s.active_page_url);
    diag::log_tagged_fmt("mcp_burp", "headless_status ok state=%s calls=%llu errors=%llu browser_open=%d active_host=%s active_path=%s query=%d response_shape=%s",
        state_label(s.state), static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), (int)s.browser_open,
        u.host.c_str(), u.path.c_str(), (int)u.has_query, json_shape(j).c_str());
    return tool_result_t::ok(j);
}

tool_result_t tool_headless_navigate(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_navigate entry params_shape=%s", json_shape(params).c_str());
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_navigate missing_url");
        return tool_result_t::error("missing_url");
    }
    std::string url = params["url"].get<std::string>();
    std::string wait_until = "load";
    int timeout_ms = 30000;
    if (params.contains("wait_until") && params["wait_until"].is_string())
        wait_until = params["wait_until"].get<std::string>();
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = params["timeout_ms"].get<int>();
    const url_log_t u = summarize_url_for_log(url);
    diag::log_tagged_fmt("mcp_burp", "headless_navigate host=%s path=%s query=%d fragment=%d url_len=%zu wait_until=%s timeout_ms=%d",
        u.host.c_str(), u.path.c_str(), (int)u.has_query, (int)u.has_fragment, u.length, wait_until.c_str(), timeout_ms);
    if (!camoufox::ensure_ready())
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_navigate bridge_not_ready err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("camoufox bridge not ready") : err);
    }
    if (!camoufox::navigate(url, wait_until, timeout_ms))
    {
        diag::log_tagged_fmt("mcp_burp", "headless_navigate failed err=%s", camoufox::last_error().c_str());
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("navigate failed") : camoufox::last_error());
    }
    diag::log_tagged_fmt("mcp_burp", "headless_navigate ok host=%s path=%s query=%d", u.host.c_str(), u.path.c_str(), (int)u.has_query);
    auto page = camoufox::get_page_info();
    if (page.ok)
    {
        diag::log_tagged_fmt("mcp_burp", "headless_navigate page_info ok response_shape=%s", json_shape(page.data).c_str());
        return tool_result_t::ok(page.data);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_navigate page_info unavailable error_len=%zu", page.error.size());
    return tool_result_t::ok(json{{"status", "navigated"}, {"url", url}});
}

tool_result_t tool_headless_reload(const json& params)
{
    std::string wait_until = "load";
    if (params.is_object() && params.contains("wait_until") && params["wait_until"].is_string())
        wait_until = params["wait_until"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_reload wait_until=%s", wait_until.c_str());
    if (!camoufox::reload(wait_until))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_reload failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("reload failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_reload ok");
    auto page = camoufox::get_page_info();
    if (page.ok) return tool_result_t::ok(page.data);
    return tool_result_t::ok(json{{"status", "reloaded"}});
}

tool_result_t tool_headless_evaluate(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_evaluate entry");
    if (!params.is_object() || !params.contains("expression") || !params["expression"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_evaluate missing_expression");
        return tool_result_t::error("missing_expression");
    }
    std::string expr = params["expression"].get<std::string>();
    bool await_promise = true;
    if (params.contains("await_promise") && params["await_promise"].is_boolean())
        await_promise = params["await_promise"].get<bool>();
    diag::log_tagged_fmt("mcp_burp", "headless_evaluate expr_len=%zu await=%d", expr.size(), (int)await_promise);
    auto r = camoufox::evaluate_js(expr, await_promise);
    if (!r.ok)
    {
        diag::log_tagged_fmt("mcp_burp", "headless_evaluate failed err=%s", r.error.c_str());
        return tool_result_t::error(r.error.empty() ? std::string("evaluate_js failed") : r.error);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_evaluate ok response_shape=%s text_len=%zu", json_shape(r.data).c_str(), r.text.size());
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_screenshot(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_screenshot entry");
    if (!params.is_object() || !params.contains("output_path") || !params["output_path"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_screenshot missing_output_path");
        return tool_result_t::error("missing_output_path");
    }
    std::string path = params["output_path"].get<std::string>();
    bool full_page = true;
    if (params.contains("full_page") && params["full_page"].is_boolean())
        full_page = params["full_page"].get<bool>();
    diag::log_tagged_fmt("mcp_burp", "headless_screenshot path=%s full_page=%d", path.c_str(), (int)full_page);
    if (!camoufox::take_screenshot(path, full_page))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_screenshot failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("screenshot failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_screenshot ok path=%s", path.c_str());
    return tool_result_t::ok(json{{"path", path}, {"full_page", full_page}});
}

tool_result_t tool_headless_snapshot(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "headless_snapshot entry");
    std::string text;
    if (!camoufox::take_snapshot(text))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_snapshot failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("snapshot failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_snapshot ok len=%zu", text.size());
    return tool_result_t::ok(json{{"snapshot", text}});
}

tool_result_t tool_headless_click(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_click entry");
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_click missing_selector");
        return tool_result_t::error("missing_selector");
    }
    const std::string sel = params["selector"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_click selector=%s", sel.c_str());
    if (!camoufox::click(sel))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_click failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("click failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_click ok selector=%s", sel.c_str());
    return tool_result_t::ok(json{{"status", "clicked"}});
}

tool_result_t tool_headless_type(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_type entry");
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_type missing_selector");
        return tool_result_t::error("missing_selector");
    }
    if (!params.contains("text") || !params["text"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_type missing_text");
        return tool_result_t::error("missing_text");
    }
    const std::string sel = params["selector"].get<std::string>();
    const std::string txt = params["text"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_type selector=%s text_len=%zu", sel.c_str(), txt.size());
    if (!camoufox::type_text(sel, txt))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_type failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("type failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_type ok selector=%s", sel.c_str());
    return tool_result_t::ok(json{{"status", "typed"}});
}

tool_result_t tool_headless_wait_for(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_wait_for entry");
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_wait_for missing_selector");
        return tool_result_t::error("missing_selector");
    }
    int timeout_ms = 5000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = params["timeout_ms"].get<int>();
    const std::string sel = params["selector"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_wait_for selector=%s timeout_ms=%d", sel.c_str(), timeout_ms);
    if (!camoufox::wait_for(sel, timeout_ms))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_wait_for failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("wait_for failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_wait_for ok selector=%s", sel.c_str());
    return tool_result_t::ok(json{{"status", "found"}});
}

tool_result_t tool_headless_console_logs(const json& params)
{
    size_t max_records = 200;
    if (params.is_object() && params.contains("max_records") && params["max_records"].is_number_unsigned())
        max_records = params["max_records"].get<size_t>();
    diag::log_tagged_fmt("mcp_burp", "headless_console_logs max_records=%zu", max_records);
    auto r = camoufox::get_console_logs(max_records);
    if (!r.ok)
    {
        diag::log_tagged_fmt("mcp_burp", "headless_console_logs failed err=%s", r.error.c_str());
        return tool_result_t::error(r.error.empty() ? std::string("get_console_logs failed") : r.error);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_console_logs ok response_shape=%s", json_shape(r.data).c_str());
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_network_requests(const json& params)
{
    size_t max_records = 200;
    if (params.is_object() && params.contains("max_records") && params["max_records"].is_number_unsigned())
        max_records = params["max_records"].get<size_t>();
    diag::log_tagged_fmt("mcp_burp", "headless_network_requests max_records=%zu", max_records);
    auto r = camoufox::list_network_requests(max_records);
    if (!r.ok)
    {
        diag::log_tagged_fmt("mcp_burp", "headless_network_requests failed err=%s", r.error.c_str());
        return tool_result_t::error(r.error.empty() ? std::string("list_network_requests failed") : r.error);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_network_requests ok response_shape=%s", json_shape(r.data).c_str());
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_inject_hook(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_inject_hook entry");
    if (!params.is_object() || !params.contains("preset_name") || !params["preset_name"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_inject_hook missing_preset_name");
        return tool_result_t::error("missing_preset_name");
    }
    const std::string preset = params["preset_name"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_inject_hook preset=%s", preset.c_str());
    if (!camoufox::inject_hook_preset(preset))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_inject_hook failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("inject_hook_preset failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_inject_hook ok preset=%s", preset.c_str());
    return tool_result_t::ok(json{{"status", "injected"}, {"preset", params["preset_name"]}});
}

tool_result_t tool_headless_hook_function(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_hook_function entry");
    if (!params.is_object() || !params.contains("target") || !params["target"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "headless_hook_function missing_target");
        return tool_result_t::error("missing_target");
    }
    const std::string target = params["target"].get<std::string>();
    std::string mode = "trace";
    if (params.contains("mode") && params["mode"].is_string()) mode = params["mode"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_hook_function target=%s mode=%s", target.c_str(), mode.c_str());
    if (!camoufox::hook_function(target, mode))
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_hook_function failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("hook_function failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_hook_function ok target=%s", target.c_str());
    return tool_result_t::ok(json{{"status", "hooked"}, {"target", params["target"]}, {"mode", mode}});
}

tool_result_t tool_headless_remove_hooks(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "headless_remove_hooks entry");
    if (!camoufox::remove_hooks())
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_remove_hooks failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("remove_hooks failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_remove_hooks ok");
    return tool_result_t::ok(json{{"status", "removed"}});
}

tool_result_t tool_headless_reset_state(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "headless_reset_state entry");
    if (!camoufox::reset_browser_state())
    {
        std::string err = camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_reset_state failed err=%s", err.c_str());
        return tool_result_t::error(err.empty() ? std::string("reset_browser_state failed") : err);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_reset_state ok");
    return tool_result_t::ok(json{{"status", "reset"}});
}

}

void register_camoufox_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_headless_start",
        "headless_browser",
        "Start the visible Camoufox anti-detect browser bridge. Spawns the Python MCP server "
        "in-process and launches a Firefox-derived browser with engine-level fingerprint spoofing. "
        "Optional proxy points at AiDA's MITM proxy for capturing intercepted DOM-XSS traffic.",
        {
            {"headless",          "boolean", "Compatibility flag; AiDA forces visible headed Camoufox", false},
            {"proxy",             "string",  "Proxy URL, e.g. http://127.0.0.1:8443", false},
            {"os",                "string",  "Spoofed OS: auto/windows/macos/linux", false},
            {"locale",            "string",  "Browser locale, default auto", false},
            {"humanize",          "boolean", "Enable humanized mouse movement", false},
            {"block_images",      "boolean", "Block image loading", false},
            {"block_webrtc",      "boolean", "Block WebRTC to prevent IP leaks", false},
            {"python_executable", "string",  "Override python interpreter path", false},
            {"server_module",     "string",  "MCP server module name (default camoufox_reverse_mcp)", false},
            {"launch_timeout_ms", "number",  "Launch handshake timeout in ms (default 5000, max 5000)", false},
        },
        tool_headless_start,
        false
    });

    register_compat(srv, {
        "burp_headless_stop",
        "headless_browser",
        "Stop the Camoufox headless browser bridge and terminate the Python MCP server.",
        {},
        tool_headless_stop,
        false
    });

    register_compat(srv, {
        "burp_headless_status",
        "headless_browser",
        "Return current Camoufox bridge state, browser status, and call counters.",
        {},
        tool_headless_status,
        true
    });

    register_compat(srv, {
        "burp_headless_navigate",
        "headless_browser",
        "Open visible Camoufox if needed, then navigate it to a URL. Returns page info with final URL/title/status.",
        {
            {"url",        "string", "Target URL", true},
            {"wait_until", "string", "load/domcontentloaded/networkidle (default load)", false},
            {"timeout_ms", "number", "Page-load timeout in ms (default 30000)", false},
        },
        tool_headless_navigate,
        false
    });

    register_compat(srv, {
        "burp_headless_reload",
        "headless_browser",
        "Reload the current page in the headless browser preserving any persistent init scripts.",
        {
            {"wait_until", "string", "load/domcontentloaded/networkidle (default load)", false},
        },
        tool_headless_reload,
        false
    });

    register_compat(srv, {
        "burp_headless_evaluate",
        "headless_browser",
        "Execute a JavaScript expression in the active page context. Must be a single expression. "
        "Returns structured value with type info.",
        {
            {"expression",    "string",  "JavaScript expression (single expression, no statements)", true},
            {"await_promise", "boolean", "Await promise return values (default true)", false},
        },
        tool_headless_evaluate,
        false
    });

    register_compat(srv, {
        "burp_headless_screenshot",
        "headless_browser",
        "Capture a PNG screenshot of the current page and write to disk.",
        {
            {"output_path", "string",  "Absolute or relative file path for the PNG", true},
            {"full_page",   "boolean", "Capture full scrollable page (default true)", false},
        },
        tool_headless_screenshot,
        false
    });

    register_compat(srv, {
        "burp_headless_snapshot",
        "headless_browser",
        "Get an accessibility-tree snapshot of the page (token-efficient text representation).",
        {},
        tool_headless_snapshot,
        true
    });

    register_compat(srv, {
        "burp_headless_click",
        "headless_browser",
        "Click an element matching the CSS selector.",
        {
            {"selector", "string", "CSS selector", true},
        },
        tool_headless_click,
        false
    });

    register_compat(srv, {
        "burp_headless_type",
        "headless_browser",
        "Type text into an input element matching the CSS selector.",
        {
            {"selector", "string", "CSS selector", true},
            {"text",     "string", "Text to type", true},
        },
        tool_headless_type,
        false
    });

    register_compat(srv, {
        "burp_headless_wait_for",
        "headless_browser",
        "Wait for a CSS selector to appear on the page.",
        {
            {"selector",   "string", "CSS selector to wait for", true},
            {"timeout_ms", "number", "Wait timeout in ms (default 5000)", false},
        },
        tool_headless_wait_for,
        true
    });

    register_compat(srv, {
        "burp_headless_console_logs",
        "headless_browser",
        "Retrieve captured browser console logs (info/warn/error/log).",
        {
            {"max_records", "number", "Maximum log records to return (default 200)", false},
        },
        tool_headless_console_logs,
        true
    });

    register_compat(srv, {
        "burp_headless_network_requests",
        "headless_browser",
        "Retrieve captured network request summaries (id/url/method/status/type/ms/size).",
        {
            {"max_records", "number", "Maximum request records to return (default 200)", false},
        },
        tool_headless_network_requests,
        true
    });

    register_compat(srv, {
        "burp_headless_inject_hook",
        "headless_browser",
        "Inject a pre-built persistent JS hook preset into the browser. Presets: xhr, fetch, crypto, "
        "websocket, debugger_bypass, cookie, runtime_probe (also xss_sentinel/alert_capture/eval_capture/"
        "function_capture/setTimeout_capture/location_capture if installed).",
        {
            {"preset_name", "string", "Preset name", true},
        },
        tool_headless_inject_hook,
        false
    });

    register_compat(srv, {
        "burp_headless_hook_function",
        "headless_browser",
        "Hook or trace a JS function by dotted path (e.g. window.eval, document.write).",
        {
            {"target", "string", "Dotted function path", true},
            {"mode",   "string", "intercept or trace (default trace)", false},
        },
        tool_headless_hook_function,
        false
    });

    register_compat(srv, {
        "burp_headless_remove_hooks",
        "headless_browser",
        "Remove installed JS hooks and restore originals.",
        {},
        tool_headless_remove_hooks,
        false
    });

    register_compat(srv, {
        "burp_headless_reset_state",
        "headless_browser",
        "Reset MCP-side residual state (hooks, network buffer, instrumentation routes) without closing the browser.",
        {},
        tool_headless_reset_state,
        false
    });
}

}
}
