#include "burp_browser_mcp.hpp"
#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"
#include "../mitm_proxy.hpp"

#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace browser {

namespace {

using mcp_standalone::tool_def_t;
using mcp_standalone::tool_result_t;
using nlohmann::json;

uint16_t default_proxy_port()
{
    uint16_t p = mitm_proxy::g_state.config.bind_port;
    return p == 0 ? static_cast<uint16_t>(8443) : p;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

const char* camoufox_bridge_state_label(camoufox::bridge_state_t s)
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

const char* camoufox_install_state_label(camoufox::install::install_state_t s)
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

json camoufox_status_json(const camoufox::bridge_status_t& s)
{
    const bool ready = s.state == camoufox::bridge_state_t::ready &&
        s.child_alive && s.browser_open && s.page_verified && !s.cleanup_pending;
    json j;
    j["browser"] = "camoufox";
    j["pid"] = s.child_pid;
    j["running"] = s.child_alive && s.browser_open;
    j["state"] = camoufox_bridge_state_label(s.state);
    j["ready"] = ready;
    j["browser_open"] = s.browser_open;
    j["child_alive"] = s.child_alive;
    j["child_pid"] = s.child_pid;
    j["page_verified"] = s.page_verified;
    j["cleanup_pending"] = s.cleanup_pending;
    j["active_page_url"] = s.active_page_url;
    j["active_page_title"] = s.active_page_title;
    j["launched_ms"] = s.launched_ms;
    j["last_error"] = s.last_error;
    j["generation"] = s.generation;
    return j;
}

bool camoufox_install_ready(const camoufox::install::status_t& s)
{
    return s.state == camoufox::install::install_state_t::ok &&
        !s.python_path.empty() &&
        !s.module_version.empty() &&
        !s.browser_path.empty();
}

std::string proxy_url(const std::string& host, uint16_t port)
{
    return "http://" + (host.empty() ? std::string("127.0.0.1") : host) + ":" +
        std::to_string(static_cast<unsigned>(port));
}

tool_result_t tool_launch(const json& params)
{
    std::string proxy_host = "127.0.0.1";
    uint16_t proxy_port = default_proxy_port();
    std::string initial_url;
    camoufox::launch_config_t cfg;
    cfg.headless = false;
    diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox entry policy=camoufox_only proxy_host=%s proxy_port=%d", proxy_host.c_str(), (int)proxy_port);

    if (params.is_object()) {
        if (params.contains("proxy_host") && params["proxy_host"].is_string())
            proxy_host = params["proxy_host"].get<std::string>();
        if (params.contains("proxy_port") && params["proxy_port"].is_number_unsigned()) {
            uint32_t p = params["proxy_port"].get<uint32_t>();
            if (p > 0 && p <= 65535) proxy_port = static_cast<uint16_t>(p);
        }
        if (params.contains("initial_url") && params["initial_url"].is_string())
            initial_url = params["initial_url"].get<std::string>();
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
        if (params.contains("geoip") && params["geoip"].is_boolean())
            cfg.geoip = params["geoip"].get<bool>();
        if (params.contains("block_images") && params["block_images"].is_boolean())
            cfg.block_images = params["block_images"].get<bool>();
        if (params.contains("block_webrtc") && params["block_webrtc"].is_boolean())
            cfg.block_webrtc = params["block_webrtc"].get<bool>();
        if (params.contains("enable_trace") && params["enable_trace"].is_boolean())
            cfg.enable_trace = params["enable_trace"].get<bool>();
        if (params.contains("python_executable") && params["python_executable"].is_string())
            cfg.python_executable = params["python_executable"].get<std::string>();
        if (params.contains("server_module") && params["server_module"].is_string())
            cfg.server_module = params["server_module"].get<std::string>();
        if (params.contains("launch_timeout_ms") && params["launch_timeout_ms"].is_number_integer())
            cfg.launch_timeout_ms = params["launch_timeout_ms"].get<int>();
        if (params.contains("window_width") && params["window_width"].is_number_integer())
            cfg.window_width = params["window_width"].get<int>();
        if (params.contains("window_height") && params["window_height"].is_number_integer())
            cfg.window_height = params["window_height"].get<int>();
    }
    if (cfg.proxy.empty())
        cfg.proxy = proxy_url(proxy_host, proxy_port);

    const uint64_t probe_start = now_ms();
    auto install = camoufox::install::probe();
    diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox dependency_probe elapsed_ms=%llu state=%s python=%s module=%s browser=%s message=%s",
        static_cast<unsigned long long>(now_ms() - probe_start),
        camoufox_install_state_label(install.state),
        install.python_path.empty() ? "<empty>" : install.python_path.c_str(),
        install.module_version.empty() ? "<empty>" : install.module_version.c_str(),
        install.browser_path.empty() ? "<empty>" : install.browser_path.c_str(),
        install.last_message.empty() ? "<empty>" : install.last_message.c_str());
    if (cfg.python_executable.empty() && !install.python_path.empty())
        cfg.python_executable = install.python_path;

    diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox resolved policy=camoufox_only browser=%s proxy=%s initial_url_len=%zu headless=%d module=%s python=%s timeout_ms=%d window=%dx%d extra_args=%zu fallback_allowed=0",
        install.browser_path.empty() ? "<empty>" : install.browser_path.c_str(), cfg.proxy.c_str(), initial_url.size(),
        static_cast<int>(cfg.headless),
        (cfg.server_module.empty() ? "camoufox_reverse_mcp" : cfg.server_module.c_str()),
        cfg.python_executable.c_str(), cfg.launch_timeout_ms, cfg.window_width, cfg.window_height,
        cfg.extra_args.size());

    if (!camoufox::start_bridge(cfg)) {
        auto st = camoufox::get_status();
        const std::string err = st.last_error.empty() ? camoufox::last_error() : st.last_error;
        diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox failed state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d browser=%s err=%s",
            camoufox_bridge_state_label(st.state), st.child_pid, st.child_alive ? 1 : 0,
            st.browser_open ? 1 : 0, st.page_verified ? 1 : 0, st.cleanup_pending ? 1 : 0,
            install.browser_path.empty() ? "<empty>" : install.browser_path.c_str(), err.c_str());
        return tool_result_t::error(err.empty() ? std::string("camoufox_launch_failed") : err);
    }

    if (!initial_url.empty()) {
        diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox navigate_begin child_pid=%u url_len=%zu",
            camoufox::get_status().child_pid, initial_url.size());
        if (!camoufox::navigate(initial_url, "load", 30000)) {
            const std::string err = camoufox::last_error();
            diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox navigate_failed err=%s", err.c_str());
            return tool_result_t::error(err.empty() ? std::string("camoufox_initial_navigation_failed") : err);
        }
    }

    auto st = camoufox::get_status();
    install = camoufox::install::get_status();
    const bool ready = st.state == camoufox::bridge_state_t::ready &&
        st.child_alive && st.browser_open && st.page_verified && !st.cleanup_pending;
    diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox ok child_pid=%u ready=%d browser_open=%d page_verified=%d cleanup_pending=%d proxy=%s browser=%s",
        st.child_pid,
        ready ? 1 : 0,
        st.browser_open ? 1 : 0,
        st.page_verified ? 1 : 0,
        st.cleanup_pending ? 1 : 0,
        cfg.proxy.c_str(), install.browser_path.empty() ? "<empty>" : install.browser_path.c_str());
    if (!ready) {
        const std::string err = st.last_error.empty() ? std::string("camoufox_bridge_not_ready_after_launch") : st.last_error;
        diag::log_tagged_fmt("mcp_burp", "browser_launch_camoufox fail_closed not_ready state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d browser=%s err=%s",
            camoufox_bridge_state_label(st.state),
            st.child_pid,
            st.child_alive ? 1 : 0,
            st.browser_open ? 1 : 0,
            st.page_verified ? 1 : 0,
            st.cleanup_pending ? 1 : 0,
            install.browser_path.empty() ? "<empty>" : install.browser_path.c_str(),
            err.c_str());
        return tool_result_t::error(err);
    }
    json j = camoufox_status_json(st);
    j["proxy"] = cfg.proxy;
    j["proxy_host"] = proxy_host;
    j["proxy_port"] = proxy_port;
    j["python_path"] = install.python_path;
    j["module_version"] = install.module_version;
    j["browser_path"] = install.browser_path;
    j["install_state"] = camoufox_install_state_label(install.state);
    j["camoufox_only"] = true;
    j["chromium_fallback_allowed"] = false;
    return tool_result_t::ok(j);
}

tool_result_t tool_kill(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "browser_kill_camoufox entry");
    uint32_t requested_pid = 0;
    if (params.is_object() && params.contains("pid") && params["pid"].is_number_unsigned())
        requested_pid = params["pid"].get<uint32_t>();
    auto before = camoufox::get_status();
    if (requested_pid != 0 && before.child_pid != 0 && requested_pid != before.child_pid) {
        diag::log_tagged_fmt("mcp_burp", "browser_kill_camoufox pid_mismatch requested=%u current=%u",
            requested_pid, before.child_pid);
        return tool_result_t::error("pid_does_not_match_camoufox_child");
    }
    bool ok = camoufox::close_browser();
    auto after = camoufox::get_status();
    diag::log_tagged_fmt("mcp_burp", "browser_kill_camoufox result=%d requested_pid=%u before_pid=%u after_pid=%u after_state=%s",
        ok ? 1 : 0, requested_pid, before.child_pid, after.child_pid, camoufox_bridge_state_label(after.state));
    if (!ok)
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("camoufox_close_failed") : camoufox::last_error());
    json j;
    j["pid"] = requested_pid == 0 ? before.child_pid : requested_pid;
    j["killed"] = true;
    j["browser"] = "camoufox";
    j["after"] = camoufox_status_json(after);
    return tool_result_t::ok(j);
}

tool_result_t tool_kill_all(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "browser_kill_all_camoufox entry");
    bool ok = camoufox::close_browser();
    auto after = camoufox::get_status();
    diag::log_tagged_fmt("mcp_burp", "browser_kill_all_camoufox result=%d after_pid=%u state=%s",
        ok ? 1 : 0, after.child_pid, camoufox_bridge_state_label(after.state));
    if (!ok)
        return tool_result_t::error(camoufox::last_error().empty() ? std::string("camoufox_close_failed") : camoufox::last_error());
    json j;
    j["ok"] = ok;
    j["browser"] = "camoufox";
    j["after"] = camoufox_status_json(after);
    return tool_result_t::ok(j);
}

tool_result_t tool_list(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "browser_list_camoufox entry");
    auto st = camoufox::get_status();
    json arr = json::array();
    const bool running = st.child_pid != 0 && st.child_alive && st.browser_open;
    if (running)
        arr.push_back(camoufox_status_json(st));
    diag::log_tagged_fmt("mcp_burp", "browser_list_camoufox ok count=%zu child_pid=%u child_alive=%d browser_open=%d page_verified=%d",
        arr.size(), st.child_pid, st.child_alive ? 1 : 0, st.browser_open ? 1 : 0, st.page_verified ? 1 : 0);
    json out;
    out["count"] = arr.size();
    out["items"] = arr;
    out["browser"] = "camoufox";
    out["camoufox_only"] = true;
    out["chromium_fallback_allowed"] = false;
    out["status"] = camoufox_status_json(st);
    return tool_result_t::ok(out);
}

tool_result_t tool_detect(const json& params)
{
    (void)params;
    diag::log_tagged_fmt("mcp_burp", "browser_detect_camoufox entry");
    auto install = camoufox::install::probe();
    auto st = camoufox::get_status();
    const bool ready = camoufox_install_ready(install);
    diag::log_tagged_fmt("mcp_burp", "browser_detect_camoufox install_state=%s ready=%d python=%s browser=%s module=%s message=%s bridge_state=%s child_pid=%u fallback_allowed=0",
        camoufox_install_state_label(install.state), ready ? 1 : 0,
        install.python_path.empty() ? "<empty>" : install.python_path.c_str(),
        install.browser_path.empty() ? "<empty>" : install.browser_path.c_str(),
        install.module_version.empty() ? "<empty>" : install.module_version.c_str(),
        install.last_message.empty() ? "<empty>" : install.last_message.c_str(),
        camoufox_bridge_state_label(st.state), st.child_pid);
    json j;
    j["browser"] = "camoufox";
    j["camoufox_only"] = true;
    j["chromium_fallback_allowed"] = false;
    j["edge_detected"] = false;
    j["edge_path"] = "";
    j["chrome_detected"] = false;
    j["chrome_path"] = "";
    j["ready"] = ready;
    j["install_state"] = camoufox_install_state_label(install.state);
    j["python_path"] = install.python_path;
    j["module_version"] = install.module_version;
    j["browser_path"] = install.browser_path;
    j["last_message"] = install.last_message;
    j["status"] = camoufox_status_json(st);
    return tool_result_t::ok(j);
}

}

void register_browser_tools(mcp_standalone::server_t& srv)
{
    {
        tool_def_t t;
        t.name = "burp_browser_launch";
        t.description = "Launch the bundled Camoufox anti-detection browser preconfigured to use AiDA's MITM proxy. "
                        "Returns the Camoufox bridge process id and readiness state. This tool never falls back to Edge, Chrome, or the system default browser.";
        t.params = {
            {"proxy_host", "string", "Proxy host (defaults to 127.0.0.1)", false},
            {"proxy_port", "number", "Proxy port (defaults to active MITM proxy port)", false},
            {"initial_url", "string", "URL to open initially. Defaults to about:blank.", false},
            {"headless", "boolean", "Launch Camoufox headless when true", false},
            {"proxy", "string", "Full proxy URL. Overrides proxy_host/proxy_port when set.", false},
            {"os", "string", "Camoufox OS fingerprint target", false},
            {"locale", "string", "Camoufox locale fingerprint target", false},
            {"humanize", "boolean", "Enable Camoufox humanization options", false},
            {"geoip", "boolean", "Enable Camoufox GeoIP behavior", false},
            {"block_images", "boolean", "Block images in the Camoufox session", false},
            {"block_webrtc", "boolean", "Block WebRTC leakage in the Camoufox session", false},
            {"enable_trace", "boolean", "Enable Camoufox trace capture", false},
            {"python_executable", "string", "Override Python interpreter path", false},
            {"server_module", "string", "Override Camoufox MCP server module", false},
            {"launch_timeout_ms", "number", "Launch timeout in milliseconds", false},
            {"window_width", "number", "Initial browser window width", false},
            {"window_height", "number", "Initial browser window height", false},
        };
        t.read_only = false;
        t.handler = tool_launch;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_kill";
        t.description = "Close the active Camoufox browser bridge. If a PID is supplied it must match the active Camoufox child process.";
        t.params = { {"pid", "number", "Camoufox bridge process ID", false} };
        t.read_only = false;
        t.handler = tool_kill;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_kill_all";
        t.description = "Close the active Camoufox browser bridge.";
        t.params = {};
        t.read_only = false;
        t.handler = tool_kill_all;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_list";
        t.description = "List the active Camoufox browser bridge with PID and readiness state.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_list;
        srv.register_tool(std::move(t));
    }
    {
        tool_def_t t;
        t.name = "burp_browser_detect";
        t.description = "Report Camoufox dependency readiness and current bridge state. Edge, Chrome, and default browsers are never selected.";
        t.params = {};
        t.read_only = true;
        t.handler = tool_detect;
        srv.register_tool(std::move(t));
    }
}

}
}
}
