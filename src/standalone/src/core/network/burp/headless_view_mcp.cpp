#include "headless_view_mcp.hpp"
#include "headless_view.hpp"
#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"

#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_param_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

const char* bridge_state_name(aida::burp::camoufox::bridge_state_t s)
{
    switch (s) {
        case aida::burp::camoufox::bridge_state_t::stopped:  return "stopped";
        case aida::burp::camoufox::bridge_state_t::starting: return "starting";
        case aida::burp::camoufox::bridge_state_t::ready:    return "ready";
        case aida::burp::camoufox::bridge_state_t::error:    return "error";
    }
    return "unknown";
}

json bridge_status_to_json(const aida::burp::camoufox::bridge_status_t& s)
{
    json j;
    j["state"]           = bridge_state_name(s.state);
    j["last_error"]      = s.last_error;
    j["child_pid"]       = s.child_pid;
    j["launched_ms"]     = s.launched_ms;
    j["last_call_ms"]    = s.last_call_ms;
    j["total_calls"]     = s.total_calls;
    j["total_errors"]    = s.total_errors;
    j["browser_open"]    = s.browser_open;
    j["active_page_url"] = s.active_page_url;
    return j;
}

json install_status_to_json(const aida::burp::camoufox::install::status_t& s)
{
    json j;
    j["ready"]           = (s.state == aida::burp::camoufox::install::install_state_t::ok);
    j["python_path"]     = s.python_path;
    j["module_version"]  = s.module_version;
    j["browser_path"]    = s.browser_path;
    j["last_message"]    = s.last_message;
    return j;
}

std::string compact_text(std::string s, size_t limit = 900)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    s = s.substr(a, b - a);
    for (char& c : s) {
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
    }
    if (s.size() > limit) {
        s.resize(limit);
        s += "...";
    }
    return s;
}

std::string install_error_message(const char* action, const aida::burp::camoufox::install::status_t& s, const std::string& log)
{
    std::string msg = aida::burp::camoufox::install::last_error();
    if (msg.empty()) msg = s.last_message;
    if (msg.empty()) msg = action ? std::string(action) + " failed" : std::string("camoufox setup failed");
    const std::string detail = compact_text(log);
    if (!detail.empty() && msg.find(detail) == std::string::npos)
        msg += ": " + detail;
    return msg;
}

tool_result_t tool_status(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_view_status entry");
    json out;
    const bool refresh = params.is_object() && params.value("refresh", false);
    try {
        aida::burp::camoufox::bridge_status_t bs = aida::burp::camoufox::get_status();
        out["bridge"] = bridge_status_to_json(bs);
    } catch (...) {
        out["bridge"] = nullptr;
    }
    try {
        aida::burp::camoufox::install::status_t is = refresh
            ? aida::burp::camoufox::install::probe()
            : aida::burp::camoufox::install::get_status();
        out["install"] = install_status_to_json(is);
    } catch (...) {
        out["install"] = nullptr;
    }
    out["view_last_error"] = aida::burp::headless_view::last_error();
    diag::log_tagged_fmt("mcp_burp", "headless_view_status ok");
    return tool_result_t::ok(out);
}

tool_result_t tool_quick_navigate(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate entry");
    if (!params.is_object() || !params.contains("url") || !params["url"].is_string()) {
        diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate missing_url");
        return tool_result_t::error("missing_url");
    }
    const std::string url = params["url"].get<std::string>();
    diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate url=%s", url.c_str());
    std::string eval_after;
    if (params.contains("eval_after_load") && params["eval_after_load"].is_string()) {
        eval_after = params["eval_after_load"].get<std::string>();
    }
    int wait_ms = 30000;
    if (params.contains("wait_ms") && params["wait_ms"].is_number_unsigned()) {
        const uint32_t v = params["wait_ms"].get<uint32_t>();
        if (v > 0 && v <= 120000) wait_ms = static_cast<int>(v);
    }

    if (!aida::burp::camoufox::ensure_ready()) {
        std::string msg = aida::burp::camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate bridge_not_ready err=%s", msg.c_str());
        return tool_result_t::error(msg.empty() ? std::string("bridge_not_ready") : msg);
    }

    bool nav_ok = false;
    try { nav_ok = aida::burp::camoufox::navigate(url, std::string("load"), wait_ms); }
    catch (...) { nav_ok = false; }
    if (!nav_ok) {
        std::string msg = aida::burp::camoufox::last_error();
        diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate navigate_failed err=%s", msg.c_str());
        return tool_result_t::error(msg.empty() ? std::string("navigate_failed") : msg);
    }

    json out;
    out["url"] = url;
    out["navigated"] = true;

    if (!eval_after.empty()) {
        aida::burp::camoufox::call_result_t r;
        try { r = aida::burp::camoufox::evaluate_js(eval_after, true); }
        catch (...) { r.ok = false; r.error = "evaluate_js_threw"; }
        json eval_section;
        eval_section["ok"]    = r.ok;
        eval_section["error"] = r.error;
        try { eval_section["data"] = r.data; } catch (...) { eval_section["data"] = nullptr; }
        eval_section["text"]  = r.text;
        out["eval"] = eval_section;
    } else {
        out["eval"] = nullptr;
    }

    diag::log_tagged_fmt("mcp_burp", "headless_view_quick_navigate ok url=%s eval=%d", url.c_str(), (int)!eval_after.empty());
    return tool_result_t::ok(out);
}

tool_result_t tool_install(const json& params)
{
    std::string action = "ensure";
    if (params.is_object() && params.contains("action") && params["action"].is_string()) {
        action = params["action"].get<std::string>();
    }
    for (char& c : action) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    diag::log_tagged_fmt("mcp_burp", "headless_view_install action=%s", action.c_str());

    if (action == "probe") {
        aida::burp::camoufox::install::status_t s;
        try { s = aida::burp::camoufox::install::probe(); } catch (...) {}
        diag::log_tagged_fmt("mcp_burp", "headless_view_install probe ok ready=%d", (int)(s.state == aida::burp::camoufox::install::install_state_t::ok));
        return tool_result_t::ok(install_status_to_json(s));
    }
    if (action == "ensure" || action == "setup" || action == "install") {
        std::string log;
        bool ok = false;
        try { ok = aida::burp::camoufox::install::ensure_ready(log); } catch (...) { ok = false; }
        aida::burp::camoufox::install::status_t s;
        try { s = aida::burp::camoufox::install::get_status(); } catch (...) {}
        if (!ok || s.state != aida::burp::camoufox::install::install_state_t::ok) {
            std::string msg = install_error_message("camoufox setup", s, log);
            diag::log_tagged_fmt("mcp_burp", "headless_view_install ensure failed err=%s", msg.c_str());
            return tool_result_t::error(msg);
        }
        json out = install_status_to_json(s);
        out["action"] = "ensure";
        diag::log_tagged_fmt("mcp_burp", "headless_view_install ensure ok");
        return tool_result_t::ok(out);
    }
    if (action == "install_module" || action == "pip_install") {
        std::string log;
        bool ok = false;
        try { ok = aida::burp::camoufox::install::pip_install_module(log); } catch (...) { ok = false; }
        aida::burp::camoufox::install::status_t s;
        try { s = aida::burp::camoufox::install::probe(); } catch (...) {}
        if (!ok || s.state == aida::burp::camoufox::install::install_state_t::missing_module) {
            std::string msg = install_error_message("camoufox module install", s, log);
            diag::log_tagged_fmt("mcp_burp", "headless_view_install install_module failed err=%s", msg.c_str());
            return tool_result_t::error(msg);
        }
        json out = install_status_to_json(s);
        out["action"] = "install_module";
        diag::log_tagged_fmt("mcp_burp", "headless_view_install install_module ok");
        return tool_result_t::ok(out);
    }
    if (action == "fetch_browser" || action == "download_browser") {
        std::string log;
        bool ok = false;
        try { ok = aida::burp::camoufox::install::fetch_browser(log); } catch (...) { ok = false; }
        aida::burp::camoufox::install::status_t s;
        try { s = aida::burp::camoufox::install::probe(); } catch (...) {}
        if (!ok || s.state == aida::burp::camoufox::install::install_state_t::missing_browser) {
            std::string msg = install_error_message("camoufox browser fetch", s, log);
            diag::log_tagged_fmt("mcp_burp", "headless_view_install fetch_browser failed err=%s", msg.c_str());
            return tool_result_t::error(msg);
        }
        json out = install_status_to_json(s);
        out["action"] = "fetch_browser";
        diag::log_tagged_fmt("mcp_burp", "headless_view_install fetch_browser ok");
        return tool_result_t::ok(out);
    }
    diag::log_tagged_fmt("mcp_burp", "headless_view_install unsupported_action action=%s", action.c_str());
    return tool_result_t::error("unsupported_action");
}

}

void register_headless_view_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_headless_view_status";
        t.description = "Return the current Camoufox headless view state snapshot: bridge process status "
                        "(state/pid/uptime/last_error) and install status (python, module, browser). "
                        "Read-only and safe to call from agentic loops to gate downstream actions.";
        t.params = {
            {"refresh", "boolean", "Run a synchronous dependency probe instead of returning the cached install snapshot.", false},
        };
        t.read_only = true;
        t.handler = tool_status;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_headless_view_quick_navigate";
        t.description = "Open visible Camoufox if needed, navigate to the supplied URL, and optionally run a "
                        "JS expression immediately after load. Returns navigation status plus the eval result "
                        "if provided.";
        t.params = {
            {"url", "string", "Target URL to navigate to (must be a fully-qualified scheme://host[/path]).", true},
            {"eval_after_load", "string", "Optional JavaScript expression evaluated after the page reports 'load'.", false},
            {"wait_ms", "number", "Navigation timeout in milliseconds (default 30000, max 120000).", false},
        };
        t.read_only = false;
        t.handler = tool_quick_navigate;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_headless_view_install";
        t.description = "Trigger an install/setup action for the Camoufox headless dependency chain. "
                        "Action 'ensure' installs missing module/runtime/browser dependencies and returns ready only when setup is complete. "
                        "Action 'probe' only re-evaluates python/module/browser presence. "
                        "Action 'install_module' runs pip install. "
                        "Action 'fetch_browser' downloads the embedded Firefox build.";
        t.params = {
            {"action", "string", "One of: ensure, probe, install_module, fetch_browser. Default ensure.", false},
        };
        t.read_only = false;
        t.handler = tool_install;
        srv.register_tool(std::move(t));
    }
}

}
}
