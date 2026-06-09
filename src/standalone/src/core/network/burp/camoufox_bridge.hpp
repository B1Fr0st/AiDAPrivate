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
    std::string              session_id        = "default";
    bool                     headless           = false;
    std::string              proxy;
    std::string              os                 = "auto";
    std::string              locale             = "auto";
    bool                     humanize           = false;
    bool                     geoip              = false;
    bool                     block_images       = false;
    bool                     block_webrtc       = true;
    bool                     enable_trace       = false;
    std::string              python_executable;
    std::string              browser_executable;
    std::string              server_executable;
    std::string              server_module      = "camoufox_reverse_mcp";
    std::vector<std::string> extra_args;
    int                      launch_timeout_ms  = 35000;
    int                      window_width       = 1280;
    int                      window_height      = 900;
};

struct page_status_t
{
    std::string page_id;
    std::string context_id;
    std::string url;
    std::string title;
    std::string guid;
    bool        active       = false;
    bool        closed       = false;
    uint64_t    created_ms   = 0;
    uint64_t    last_used_ms = 0;
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
    std::string    session_id        = "default";
    std::string    active_session_id = "default";
    bridge_state_t state            = bridge_state_t::stopped;
    std::string    last_error;
    std::string    server_command;
    uint32_t       child_pid        = 0;
    uint64_t       launched_ms      = 0;
    uint64_t       last_call_ms     = 0;
    uint64_t       total_calls      = 0;
    uint64_t       total_errors     = 0;
    bool           browser_open     = false;
    std::string    active_page_id;
    std::string    active_page_url;
    std::string    active_page_title;
    uint32_t       page_count       = 0;
    uint32_t       session_count    = 1;
    std::vector<page_status_t> pages;
    std::string    active_profile_dir;
    bool           page_verified    = false;
    bool           child_alive      = false;
    bool           cleanup_pending  = false;
    uint64_t       generation       = 0;
    uint64_t       last_launch_ms   = 0;
    uint64_t       last_nav_ms      = 0;
    uint64_t       last_cleanup_ms  = 0;
    uint64_t       last_verified_ms = 0;
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
bool             start_bridge(const launch_config_t& cfg, const std::string& session_id);
uint64_t         begin_activity(const char* owner);
void             end_activity(uint64_t token, const char* owner);

bool             stop_bridge(const char* reason = nullptr);
bool             stop_bridge(const std::string& session_id, const char* reason = nullptr);
bool             force_cleanup(const char* reason = nullptr);
bool             force_cleanup(const std::string& session_id, const char* reason = nullptr);
bool             wait_until_idle(uint32_t timeout_ms, const char* reason = nullptr);
bool             is_ready();
bool             ensure_ready();
bool             prewarm_default_async(const char* reason = nullptr);
bridge_status_t  get_status();
bridge_status_t  get_status(const std::string& session_id);

call_result_t    call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms = 30000);
call_result_t    call_tool(const std::string& tool_name, const nlohmann::json& args, int timeout_ms, const std::string& session_id);

bool             launch_browser(const launch_config_t& cfg);
bool             close_browser(const char* reason = nullptr);
bool             navigate(const std::string& url, const std::string& wait_until = "domcontentloaded", int timeout_ms = 30000);
bool             navigate(const std::string& url, const std::string& wait_until, int timeout_ms, const std::string& session_id, const std::string& page_id = {});
bool             reload(const std::string& wait_until = "domcontentloaded");
bool             reload(const std::string& wait_until, const std::string& session_id, const std::string& page_id = {});
call_result_t    evaluate_js(const std::string& expression, bool await_promise = true);
call_result_t    evaluate_js(const std::string& expression, bool await_promise, const std::string& session_id, const std::string& page_id = {});
bool             add_init_script(const std::string& js);

call_result_t    get_console_logs(size_t max_records = 200);
call_result_t    get_console_logs(size_t max_records, const std::string& session_id, const std::string& page_id = {});
call_result_t    list_network_requests(size_t max_records = 200);
call_result_t    list_network_requests(size_t max_records, const std::string& session_id, const std::string& page_id = {});
call_result_t    get_page_info();
call_result_t    get_page_info(const std::string& session_id, const std::string& page_id = {});
call_result_t    list_pages(const std::string& session_id = {});
call_result_t    new_page(const std::string& session_id = {}, const std::string& page_id = {}, const std::string& url = {}, bool make_active = true);
call_result_t    select_page(const std::string& session_id, const std::string& page_id);
call_result_t    close_page(const std::string& session_id, const std::string& page_id);
bool             take_screenshot(const std::string& output_path, bool full_page = true);
bool             take_screenshot(const std::string& output_path, bool full_page, const std::string& session_id, const std::string& page_id = {});
bool             take_snapshot(std::string& out_text);
bool             take_snapshot(std::string& out_text, const std::string& session_id, const std::string& page_id = {});
bool             click(const std::string& selector);
bool             click(const std::string& selector, const std::string& session_id, const std::string& page_id = {});
bool             type_text(const std::string& selector, const std::string& text);
bool             type_text(const std::string& selector, const std::string& text, const std::string& session_id, const std::string& page_id = {});
bool             wait_for(const std::string& selector, int timeout_ms = 5000);
bool             wait_for(const std::string& selector, int timeout_ms, const std::string& session_id, const std::string& page_id = {});
bool             reset_browser_state();
bool             inject_hook_preset(const std::string& preset_name);
bool             hook_function(const std::string& target, const std::string& mode);
bool             remove_hooks();

std::string      last_error();

bool             ensure_python_available(std::string& out_python_path);

}
}
}
