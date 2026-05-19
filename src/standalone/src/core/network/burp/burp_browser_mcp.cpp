#include "burp_browser_mcp.hpp"
#include "browser_launch.hpp"
#include "../mitm_proxy.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace browser {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_param_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

uint16_t default_proxy_port()
{
    uint16_t p = mitm_proxy::g_state.config.bind_port;
    return p == 0 ? static_cast<uint16_t>(8443) : p;
}

tool_result_t status_to_json(const browser_status_t& s)
{
    json j;
    j["pid"]          = s.pid;
    j["running"]      = s.running;
    j["browser_path"] = s.browser_path;
    j["profile_path"] = s.profile_path;
    j["proxy_port"]   = s.proxy_port;
    j["launched_ms"]  = s.launched_ms;
    return tool_result_t::ok(j);
}

tool_result_t tool_launch(const json& params)
{
    browser_launch_config_t cfg;
    cfg.proxy_host = "127.0.0.1";
    cfg.proxy_port = default_proxy_port();

    if (params.is_object()) {
        if (params.contains("proxy_host") && params["proxy_host"].is_string())
            cfg.proxy_host = params["proxy_host"].get<std::string>();
        if (params.contains("proxy_port") && params["proxy_port"].is_number_unsigned()) {
            uint32_t p = params["proxy_port"].get<uint32_t>();
            if (p > 0 && p <= 65535) cfg.proxy_port = static_cast<uint16_t>(p);
        }
        if (params.contains("profile_subdir") && params["profile_subdir"].is_string())
            cfg.profile_subdir = params["profile_subdir"].get<std::string>();
        if (params.contains("initial_url") && params["initial_url"].is_string())
            cfg.initial_url = params["initial_url"].get<std::string>();
        if (params.contains("prefer_chrome") && params["prefer_chrome"].is_boolean())
            cfg.prefer_chrome = params["prefer_chrome"].get<bool>();
        if (params.contains("ignore_cert_errors") && params["ignore_cert_errors"].is_boolean())
            cfg.ignore_cert_errors = params["ignore_cert_errors"].get<bool>();
        if (params.contains("clear_profile_first") && params["clear_profile_first"].is_boolean())
            cfg.clear_profile_first = params["clear_profile_first"].get<bool>();
    }

    uint32_t pid = 0;
    if (!launch(cfg, pid)) {
        return tool_result_t::error(last_error().empty() ? std::string("launch_failed") : last_error());
    }
    json j;
    j["pid"]          = pid;
    j["proxy_host"]   = cfg.proxy_host;
    j["proxy_port"]   = cfg.proxy_port;
    j["profile_path"] = compute_profile_path(cfg.profile_subdir);
    return tool_result_t::ok(j);
}

tool_result_t tool_kill(const json& params)
{
    if (!params.is_object() || !params.contains("pid") || !params["pid"].is_number_unsigned()) {
        return tool_result_t::error("missing_pid");
    }
    uint32_t pid = params["pid"].get<uint32_t>();
    bool ok = kill(pid);
    json j;
    j["pid"] = pid;
    j["killed"] = ok;
    j["error"] = ok ? std::string() : last_error();
    return ok ? tool_result_t::ok(j) : tool_result_t::error(last_error().empty() ? std::string("kill_failed") : last_error());
}

tool_result_t tool_kill_all(const json& params)
{
    (void)params;
    bool ok = kill_all();
    json j;
    j["ok"] = ok;
    return tool_result_t::ok(j);
}

tool_result_t tool_list(const json& params)
{
    (void)params;
    auto items = list_running();
    json arr = json::array();
    for (const auto& s : items) {
        json j;
        j["pid"]          = s.pid;
        j["running"]      = s.running;
        j["browser_path"] = s.browser_path;
        j["profile_path"] = s.profile_path;
        j["proxy_port"]   = s.proxy_port;
        j["launched_ms"]  = s.launched_ms;
        arr.push_back(j);
    }
    json out;
    out["count"] = arr.size();
    out["items"] = arr;
    return tool_result_t::ok(out);
}

tool_result_t tool_detect(const json& params)
{
    (void)params;
    std::string edge, chrome;
    bool edge_ok = detect_edge_path(edge);
    bool chrome_ok = detect_chrome_path(chrome);
    json j;
    j["edge_detected"]   = edge_ok;
    j["edge_path"]       = edge;
    j["chrome_detected"] = chrome_ok;
    j["chrome_path"]     = chrome;
    j["profile_root"]    = profile_root();
    return tool_result_t::ok(j);
}

}

void register_browser_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_browser_launch";
        t.description = "Launch a Chromium-based browser (Edge / Chrome) preconfigured to use AiDA's MITM proxy. "
                        "Returns the launched process id. Use this to give users a one-click 'open browser' "
                        "intercepted experience without changing their default system browser settings.";
        t.params = {
            {"proxy_host", "string", "Proxy host (defaults to 127.0.0.1)", false},
            {"proxy_port", "number", "Proxy port (defaults to active MITM proxy port)", false},
            {"profile_subdir", "string", "Subdirectory under %LOCALAPPDATA%\\AiDA for the browser profile", false},
            {"initial_url", "string", "URL to open initially. Defaults to about:blank.", false},
            {"prefer_chrome", "boolean", "Prefer Chrome over Edge when both are installed", false},
            {"ignore_cert_errors", "boolean", "Pass --ignore-certificate-errors", false},
            {"clear_profile_first", "boolean", "Delete the profile directory before launching", false},
        };
        t.read_only = false;
        t.handler = tool_launch;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_kill";
        t.description = "Terminate a previously-launched Burp browser process by PID.";
        t.params = { {"pid", "number", "Browser process ID", true} };
        t.read_only = false;
        t.handler = tool_kill;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_kill_all";
        t.description = "Terminate every tracked Burp browser process.";
        t.params = {};
        t.read_only = false;
        t.handler = tool_kill_all;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_list";
        t.description = "List all tracked Burp browser processes with PID, profile, and run state.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_list;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_detect";
        t.description = "Detect Edge / Chrome installations and report profile root.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_detect;
        srv.register_tool(std::move(t));
    }
}

}
}
}
