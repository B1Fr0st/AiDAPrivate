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
    j["active_page_title"] = s.active_page_title;
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
    diag::log_tagged_fmt("mcp_burp", "headless_start config headless=%d has_proxy=%d proxy_len=%zu os=%s locale=%s humanize=%d geoip=%d block_images=%d block_webrtc=%d enable_trace=%d python=%s module=%s timeout_ms=%d window=%dx%d",
        (int)cfg.headless, (int)!cfg.proxy.empty(), cfg.proxy.size(), cfg.os.c_str(), cfg.locale.c_str(),
        (int)cfg.humanize, (int)cfg.geoip, (int)cfg.block_images, (int)cfg.block_webrtc, (int)cfg.enable_trace,
        cfg.python_executable.c_str(), cfg.server_module.c_str(), cfg.launch_timeout_ms, cfg.window_width, cfg.window_height);
    bool ok = camoufox::start_bridge(cfg);
    auto s = ok ? wait_for_ready_status(5000) : camoufox::get_status();
    json j = status_to_json(s);
    if (!ok)
    {
        std::string err = s.last_error.empty() ? camoufox::last_error() : s.last_error;
        diag::log_tagged_fmt("mcp_burp", "headless_start failed state=%s browser_open=%d calls=%llu errors=%llu err_len=%zu err=%s",
            state_label(s.state), (int)s.browser_open, static_cast<unsigned long long>(s.total_calls),
            static_cast<unsigned long long>(s.total_errors), err.size(), err.c_str());
        return tool_result_t::error(err.empty() ? std::string("camoufox start failed") : err);
    }
    if (!bridge_ready(s))
    {
        std::string err = s.last_error.empty() ? std::string("camoufox bridge did not become ready") : s.last_error;
        diag::log_tagged_fmt("mcp_burp", "headless_start not_ready state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d err=%s",
            state_label(s.state), s.child_pid, s.child_alive ? 1 : 0, s.browser_open ? 1 : 0,
            s.page_verified ? 1 : 0, s.cleanup_pending ? 1 : 0, err.c_str());
        tool_result_t out;
        out.success = false;
        out.text = err;
        out.data = j;
        return out;
    }
    diag::log_tagged_fmt("mcp_burp", "headless_start ok state=%s browser_open=%d calls=%llu errors=%llu response_shape=%s",
        state_label(s.state), (int)s.browser_open, static_cast<unsigned long long>(s.total_calls),
        static_cast<unsigned long long>(s.total_errors), json_shape(j).c_str());
    return tool_result_t::ok(j);
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

json camoufox_args(const json& params)
{
    json args = params.is_object() ? params : json::object();
    args.erase("binary_id");
    args.erase("call_timeout_ms");
    args.erase("launch_timeout_ms");
    args.erase("python_executable");
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
    auto before = camoufox::get_status();
    const auto start = std::chrono::steady_clock::now();
    diag::log_tagged_fmt("mcp_burp", "camoufox_click_direct entry selector=%s state=%s child_pid=%lu ready=%d",
        selector.c_str(),
        state_label(before.state),
        static_cast<unsigned long>(before.child_pid),
        bridge_ready(before) ? 1 : 0);
    json args;
    args["selector"] = selector;
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("click", args, 5000));
    auto after = camoufox::get_status();
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
    auto before = camoufox::get_status();
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
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("type_text", args, 5000));
    auto after = camoufox::get_status();
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
    auto before = camoufox::get_status();
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
    tool_result_t out = bridge_result_to_tool_result(camoufox::call_tool("wait_for", args, timeout_ms + 5000));
    auto after = camoufox::get_status();
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
    cfg.headless = json_bool_param(params, "headless", cfg.headless);
    cfg.proxy = json_string_param(params, "proxy", cfg.proxy);
    cfg.os = json_string_param(params, "os_type", json_string_param(params, "os", cfg.os));
    cfg.locale = json_string_param(params, "locale", cfg.locale);
    cfg.humanize = json_bool_param(params, "humanize", cfg.humanize);
    cfg.geoip = json_bool_param(params, "geoip", cfg.geoip);
    cfg.block_images = json_bool_param(params, "block_images", cfg.block_images);
    cfg.block_webrtc = json_bool_param(params, "block_webrtc", cfg.block_webrtc);
    cfg.enable_trace = json_bool_param(params, "enable_trace", cfg.enable_trace);
    cfg.python_executable = json_string_param(params, "python_executable", cfg.python_executable);
    cfg.server_module = json_string_param(params, "server_module", cfg.server_module);
    cfg.launch_timeout_ms = json_int_param(params, "launch_timeout_ms", cfg.launch_timeout_ms);
    cfg.window_width = json_int_param(params, "window_width", json_int_param(params, "width", cfg.window_width));
    cfg.window_height = json_int_param(params, "window_height", json_int_param(params, "height", cfg.window_height));
    return cfg;
}

tool_result_t tool_launch_browser(const json& params)
{
    camoufox::launch_config_t cfg = launch_config_from_mcp_params(params);
    bool ok = camoufox::start_bridge(cfg);
    auto status = ok ? wait_for_ready_status(5000) : camoufox::get_status();
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

tool_result_t tool_close_browser(const json&)
{
    bool ok = camoufox::stop_bridge();
    json j = status_to_json(camoufox::get_status());
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
        std::string text = data["dependencies_ready"].get<bool>()
            ? std::string("Camoufox dependencies are ready.")
            : std::string("Camoufox dependencies are not ready: ") + install_status.last_message;
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
    auto before = camoufox::get_status();
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
    camoufox::call_result_t bridge_result = camoufox::call_tool(tool_name, args, timeout_ms);
    tool_result_t out = bridge_result_to_tool_result(bridge_result);
    auto after = camoufox::get_status();
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
        {"launch_browser", "Launch the bundled Camoufox anti-detection browser through AiDA's integrated bridge.",
            {{"headless", "boolean", "Run in headless mode; AiDA defaults to visible headed Camoufox", false},
             {"os_type", "string", "Spoofed OS: auto, windows, macos, or linux", false},
             {"locale", "string", "Browser locale such as en-US; auto uses the system locale", false},
             {"proxy", "string", "Proxy URL such as http://127.0.0.1:8443", false},
             {"humanize", "boolean", "Enable humanized mouse movement", false},
             {"geoip", "boolean", "Infer geolocation from proxy IP", false},
             {"block_images", "boolean", "Block image loading", false},
             {"block_webrtc", "boolean", "Block WebRTC to prevent IP leaks", false},
             {"enable_trace", "boolean", "Enable engine-level property access tracing", false},
             {"python_executable", "string", "Override Python interpreter path", false},
             {"server_module", "string", "Override Python module name", false},
             {"launch_timeout_ms", "number", "Requested launch timeout in milliseconds; AiDA bounds the readiness handshake internally", false},
             {"window_width", "number", "Initial outer browser window width in pixels", false},
             {"window_height", "number", "Initial outer browser window height in pixels", false}}, false, 60000},
        {"close_browser", "Close Camoufox and stop the hidden bundled Python bridge.", {}, false, 30000},
        {"navigate", "Navigate the active Camoufox page with optional hook pre-injection and redirect tracing.",
            {{"url", "string", "Target URL", true},
             {"wait_until", "string", "load, domcontentloaded, or networkidle", false},
             {"pre_inject_hooks", "array", "Hook preset names to register before navigation", false},
             {"collect_response_chain", "boolean", "Record response chain for final status resolution", false},
             {"clear_network_capture", "boolean", "Clear stale network capture before navigating", false},
             {"include_title", "boolean", "Return page title when available", false}}, false, 60000},
        {"reload", "Reload the current Camoufox page while preserving init scripts.",
            {{"wait_until", "string", "load, domcontentloaded, or networkidle", false}}, false, 45000},
        {"take_screenshot", "Capture a base64 PNG screenshot of the current page or selected element.",
            {{"full_page", "boolean", "Capture the full scrollable page", false},
             {"selector", "string", "CSS selector for an element screenshot", false}}, true, 60000},
        {"take_snapshot", "Return a token-efficient accessibility snapshot of the current page.", {}, true, 30000},
        {"click", "Click an element matching a CSS selector in the active Camoufox page.",
            {{"selector", "string", "CSS selector", true}}, false, 30000},
        {"type_text", "Type text into an element with realistic keystroke delay.",
            {{"selector", "string", "CSS selector", true},
             {"text", "string", "Text to type", true},
             {"delay", "number", "Delay between key presses in milliseconds", false}}, false, 30000},
        {"wait_for", "Wait for a selector or URL pattern in Camoufox.",
            {{"selector", "string", "CSS selector to wait for", false},
             {"url_pattern", "string", "URL pattern to wait for", false},
             {"timeout", "number", "Wait timeout in milliseconds", false}}, true, 45000},
        {"get_page_info", "Return current page URL, title, and viewport size.", {}, true, 30000},
        {"reset_browser_state", "Clear Camoufox residual state such as persistent hooks, capture buffers, routes, cookies, or storage.",
            {{"clear_persistent_hooks", "boolean", "Remove persistent init scripts", false},
             {"clear_network_capture", "boolean", "Clear network capture buffer and stop captures", false},
             {"clear_active_routes", "boolean", "Clear instrumentation routes", false},
             {"clear_cookies", "boolean", "Clear browser cookies", false},
             {"clear_storage", "boolean", "Clear localStorage and sessionStorage", false}}, false, 45000},
        {"evaluate_js", "Execute a JavaScript expression in the active page context.",
            {{"expression", "string", "JavaScript expression", true},
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
        {"get_console_logs", "Return console output collected from the active page.",
            {{"level", "string", "Filter by log, warn, error, or info", false},
             {"keyword", "string", "Filter logs containing this text", false},
             {"clear", "boolean", "Clear the log buffer after retrieval", false}}, true, 30000},
        {"network_capture", "Start, stop, clear, or report Camoufox network capture.",
            {{"action", "string", "start, stop, clear, or status", true},
             {"url_pattern", "string", "URL glob pattern", false},
             {"capture_body", "boolean", "Capture response bodies", false}}, false, 30000},
        {"list_network_requests", "List captured network requests with optional filters.",
            {{"url_filter", "string", "Substring filter for URLs", false},
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
            {{"request_id", "number", "Request id from list_network_requests", true}}, true, 30000},
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
        {"get_storage", "Return localStorage or sessionStorage from the active page.",
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
             {"max_entries", "number", "Maximum log entries", false}}, false, 45000},
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
    diag::log_tagged_fmt("mcp_burp", "headless_navigate page_info failed error_len=%zu err=%s", page.error.size(), page.error.c_str());
    return tool_result_t::error(page.error.empty() ? std::string("headless_navigate page verification failed") : page.error);
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
    diag::log_tagged_fmt("mcp_burp", "headless_reload page_info failed err=%s", page.error.c_str());
    return tool_result_t::error(page.error.empty() ? std::string("headless_reload page verification failed") : page.error);
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
    register_camoufox_reverse_tools(srv);

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
            {"geoip",             "boolean", "Infer geolocation from proxy IP", false},
            {"block_images",      "boolean", "Block image loading", false},
            {"block_webrtc",      "boolean", "Block WebRTC to prevent IP leaks", false},
            {"enable_trace",      "boolean", "Enable engine-level property access tracing", false},
            {"python_executable", "string",  "Override python interpreter path", false},
            {"server_module",     "string",  "MCP server module name (default camoufox_reverse_mcp)", false},
            {"launch_timeout_ms", "number",  "Requested launch timeout in ms; readiness is internally bounded before caller timeout", false},
            {"window_width",      "number",  "Initial outer browser window width in pixels", false},
            {"window_height",     "number",  "Initial outer browser window height in pixels", false},
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
