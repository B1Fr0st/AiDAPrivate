#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../infra/event_bus.hpp"

namespace aida {
namespace burp {
namespace camoufox {

struct launch_config_t
{
    bool                     headless           = false;
    std::string              proxy;
    std::string              os                 = "auto";
    std::string              locale             = "auto";
    bool                     humanize           = false;
    bool                     block_images       = false;
    bool                     block_webrtc       = false;
    std::string              python_executable;
    std::string              server_module      = "camoufox_reverse_mcp";
    std::vector<std::string> extra_args;
    int                      launch_timeout_ms  = 5000;
};

enum class bridge_state_t : int
{
    stopped  = 0,
    starting = 1,
    ready    = 2,
    error    = 3
};

struct bridge_status_t
{
    bridge_state_t state            = bridge_state_t::stopped;
    std::string    last_error;
    std::string    server_command;
    uint32_t       child_pid        = 0;
    uint64_t       launched_ms      = 0;
    uint64_t       last_call_ms     = 0;
    uint64_t       total_calls      = 0;
    uint64_t       total_errors     = 0;
    bool           browser_open     = false;
    std::string    active_page_url;
};

struct call_result_t
{
    bool           ok = false;
    std::string    error;
    nlohmann::json data;
    std::string    text;
};

struct bridge_state_changed_t
{
    bridge_state_t state     = bridge_state_t::stopped;
    std::string    last_error;
    uint32_t       child_pid = 0;
};

struct bridge_call_completed_t
{
    std::string tool_name;
    bool        ok          = false;
    uint64_t    duration_ms = 0;
};

inline constexpr aida::events::event_def_t<bridge_state_changed_t>  kBridgeStateChanged{"burp.camoufox.state_changed"};
inline constexpr aida::events::event_def_t<bridge_call_completed_t> kBridgeCallCompleted{"burp.camoufox.call_completed"};

bool             start_bridge(const launch_config_t& cfg);
bool             stop_bridge();
bool             is_ready();
bool             ensure_ready();
bridge_status_t  get_status();

call_result_t    call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms = 30000);

bool             launch_browser(const launch_config_t& cfg);
bool             close_browser();
bool             navigate(const std::string& url, const std::string& wait_until = "load", int timeout_ms = 30000);
bool             reload(const std::string& wait_until = "load");
call_result_t    evaluate_js(const std::string& expression, bool await_promise = true);
bool             add_init_script(const std::string& js);

call_result_t    get_console_logs(size_t max_records = 200);
call_result_t    list_network_requests(size_t max_records = 200);
call_result_t    get_page_info();
bool             take_screenshot(const std::string& output_path, bool full_page = true);
bool             take_snapshot(std::string& out_text);
bool             click(const std::string& selector);
bool             type_text(const std::string& selector, const std::string& text);
bool             wait_for(const std::string& selector, int timeout_ms = 5000);
bool             reset_browser_state();
bool             inject_hook_preset(const std::string& preset_name);
bool             hook_function(const std::string& target, const std::string& mode);
bool             remove_hooks();

std::string      last_error();

bool             ensure_python_available(std::string& out_python_path);

}
}
}
