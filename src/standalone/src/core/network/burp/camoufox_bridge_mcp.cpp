#include "camoufox_bridge_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "../../settings/standalone_compat.hpp"

#ifdef small
#undef small
#endif

#include <nlohmann/json.hpp>

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
    return j;
}

tool_result_t tool_headless_start(const json& params)
{
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
    bool ok = camoufox::start_bridge(cfg);
    auto s = camoufox::get_status();
    json j = status_to_json(s);
    if (!ok)
    {
        std::string err = s.last_error.empty() ? camoufox::last_error() : s.last_error;
        return tool_result_t::error(err.empty() ? std::string("camoufox start failed") : err);
    }
    return tool_result_t::ok(j);
}

tool_result_t tool_headless_stop(const json& params)
{
    (void)params;
    bool ok = camoufox::stop_bridge();
    auto s = camoufox::get_status();
    json j = status_to_json(s);
    if (!ok) return tool_result_t::error(camoufox::last_error().empty() ? std::string("camoufox stop failed") : camoufox::last_error());
    return tool_result_t::ok(j);
}

tool_result_t tool_headless_status(const json& params)
{
    (void)params;
    auto s = camoufox::get_status();
    return tool_result_t::ok(status_to_json(s));
}

tool_result_t tool_headless_navigate(const json& params)
{
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string())
        return tool_result_t::error("missing_url");
    std::string url = params["url"].get<std::string>();
    std::string wait_until = "load";
    int timeout_ms = 30000;
    if (params.contains("wait_until") && params["wait_until"].is_string())
        wait_until = params["wait_until"].get<std::string>();
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = params["timeout_ms"].get<int>();
    if (!camoufox::navigate(url, wait_until, timeout_ms))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("navigate failed") : camoufox::last_error());
    auto page = camoufox::get_page_info();
    if (page.ok) return tool_result_t::ok(page.data);
    return tool_result_t::ok(json{{"status", "navigated"}, {"url", url}});
}

tool_result_t tool_headless_reload(const json& params)
{
    std::string wait_until = "load";
    if (params.is_object() && params.contains("wait_until") && params["wait_until"].is_string())
        wait_until = params["wait_until"].get<std::string>();
    if (!camoufox::reload(wait_until))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("reload failed") : camoufox::last_error());
    auto page = camoufox::get_page_info();
    if (page.ok) return tool_result_t::ok(page.data);
    return tool_result_t::ok(json{{"status", "reloaded"}});
}

tool_result_t tool_headless_evaluate(const json& params)
{
    if (!params.is_object() || !params.contains("expression") || !params["expression"].is_string())
        return tool_result_t::error("missing_expression");
    std::string expr = params["expression"].get<std::string>();
    bool await_promise = true;
    if (params.contains("await_promise") && params["await_promise"].is_boolean())
        await_promise = params["await_promise"].get<bool>();
    auto r = camoufox::evaluate_js(expr, await_promise);
    if (!r.ok) return tool_result_t::error(r.error.empty() ? std::string("evaluate_js failed") : r.error);
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_screenshot(const json& params)
{
    if (!params.is_object() || !params.contains("output_path") || !params["output_path"].is_string())
        return tool_result_t::error("missing_output_path");
    std::string path = params["output_path"].get<std::string>();
    bool full_page = true;
    if (params.contains("full_page") && params["full_page"].is_boolean())
        full_page = params["full_page"].get<bool>();
    if (!camoufox::take_screenshot(path, full_page))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("screenshot failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"path", path}, {"full_page", full_page}});
}

tool_result_t tool_headless_snapshot(const json& params)
{
    (void)params;
    std::string text;
    if (!camoufox::take_snapshot(text))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("snapshot failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"snapshot", text}});
}

tool_result_t tool_headless_click(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    if (!camoufox::click(params["selector"].get<std::string>()))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("click failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "clicked"}});
}

tool_result_t tool_headless_type(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    if (!params.contains("text") || !params["text"].is_string())
        return tool_result_t::error("missing_text");
    if (!camoufox::type_text(params["selector"].get<std::string>(), params["text"].get<std::string>()))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("type failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "typed"}});
}

tool_result_t tool_headless_wait_for(const json& params)
{
    if (!params.is_object() || !params.contains("selector") || !params["selector"].is_string())
        return tool_result_t::error("missing_selector");
    int timeout_ms = 5000;
    if (params.contains("timeout_ms") && params["timeout_ms"].is_number_integer())
        timeout_ms = params["timeout_ms"].get<int>();
    if (!camoufox::wait_for(params["selector"].get<std::string>(), timeout_ms))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("wait_for failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "found"}});
}

tool_result_t tool_headless_console_logs(const json& params)
{
    size_t max_records = 200;
    if (params.is_object() && params.contains("max_records") && params["max_records"].is_number_unsigned())
        max_records = params["max_records"].get<size_t>();
    auto r = camoufox::get_console_logs(max_records);
    if (!r.ok) return tool_result_t::error(r.error.empty() ? std::string("get_console_logs failed") : r.error);
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_network_requests(const json& params)
{
    size_t max_records = 200;
    if (params.is_object() && params.contains("max_records") && params["max_records"].is_number_unsigned())
        max_records = params["max_records"].get<size_t>();
    auto r = camoufox::list_network_requests(max_records);
    if (!r.ok) return tool_result_t::error(r.error.empty() ? std::string("list_network_requests failed") : r.error);
    return tool_result_t::ok(r.data);
}

tool_result_t tool_headless_inject_hook(const json& params)
{
    if (!params.is_object() || !params.contains("preset_name") || !params["preset_name"].is_string())
        return tool_result_t::error("missing_preset_name");
    if (!camoufox::inject_hook_preset(params["preset_name"].get<std::string>()))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("inject_hook_preset failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "injected"}, {"preset", params["preset_name"]}});
}

tool_result_t tool_headless_hook_function(const json& params)
{
    if (!params.is_object() || !params.contains("target") || !params["target"].is_string())
        return tool_result_t::error("missing_target");
    std::string mode = "trace";
    if (params.contains("mode") && params["mode"].is_string()) mode = params["mode"].get<std::string>();
    if (!camoufox::hook_function(params["target"].get<std::string>(), mode))
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("hook_function failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "hooked"}, {"target", params["target"]}, {"mode", mode}});
}

tool_result_t tool_headless_remove_hooks(const json& params)
{
    (void)params;
    if (!camoufox::remove_hooks())
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("remove_hooks failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "removed"}});
}

tool_result_t tool_headless_reset_state(const json& params)
{
    (void)params;
    if (!camoufox::reset_browser_state())
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("reset_browser_state failed") : camoufox::last_error());
    return tool_result_t::ok(json{{"status", "reset"}});
}

}

void register_camoufox_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_headless_start",
        "headless_browser",
        "Start the Camoufox anti-detect headless browser bridge. Spawns the Python MCP server "
        "in-process and launches a Firefox-derived browser with engine-level fingerprint spoofing. "
        "Optional proxy points at AiDA's MITM proxy for capturing intercepted DOM-XSS traffic.",
        {
            {"headless",          "boolean", "Run browser headless (default true)", false},
            {"proxy",             "string",  "Proxy URL, e.g. http://127.0.0.1:8443", false},
            {"os",                "string",  "Spoofed OS: auto/windows/macos/linux", false},
            {"locale",            "string",  "Browser locale, default auto", false},
            {"humanize",          "boolean", "Enable humanized mouse movement", false},
            {"block_images",      "boolean", "Block image loading", false},
            {"block_webrtc",      "boolean", "Block WebRTC to prevent IP leaks", false},
            {"python_executable", "string",  "Override python interpreter path", false},
            {"server_module",     "string",  "MCP server module name (default camoufox_reverse_mcp)", false},
            {"launch_timeout_ms", "number",  "Launch handshake timeout in ms (default 60000)", false},
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
        "Navigate the headless browser to a URL. Returns page info with final URL/title/status.",
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
