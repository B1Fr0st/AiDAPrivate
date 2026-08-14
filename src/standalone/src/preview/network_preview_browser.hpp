#pragma once

#include "network_preview_adapter.hpp"

#include "../core/infra/event_bus.hpp"

#include <algorithm>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

namespace aida::burp::camoufox {

struct launch_config_t {
    std::string session_id = "default";
    bool headless = false;
    std::string proxy;
    std::string os = "windows";
    std::string locale = "auto";
    bool humanize = false;
    bool geoip = false;
    bool block_images = false;
    bool block_webrtc = true;
    std::string user_agent;
    std::string ua_policy = "camoufox_native";
    bool persistent_context = false;
    std::string profile_dir;
    std::string user_data_dir;
    bool enable_trace = false;
    std::string python_executable;
    std::string browser_executable;
    std::string server_module = "camoufox_reverse_mcp";
    std::vector<std::string> extra_args;
    int launch_timeout_ms = 120000;
    int window_width = 1280;
    int window_height = 900;
    bool testlab_fast_probe = false;
};

struct page_status_t {
    std::string page_id;
    std::string context_id;
    std::string url;
    std::string title;
    std::string guid;
    bool active = false;
    bool closed = false;
    uint64_t created_ms = 0;
    uint64_t last_used_ms = 0;
};

enum class bridge_state_t : int { stopped = 0, starting = 1, ready = 2, error = 3 };

struct bridge_status_t {
    std::string session_id = "default";
    std::string active_session_id = "default";
    bridge_state_t state = bridge_state_t::stopped;
    std::string last_error;
    std::string server_command;
    uint32_t child_pid = 0;
    std::string child_process_image_path;
    uint64_t child_process_creation_time_100ns = 0;
    uint32_t child_process_identity_gle = 0;
    bool child_process_identity_available = false;
    uint64_t launched_ms = 0;
    uint64_t attempt_started_ms = 0;
    uint64_t attempt_elapsed_ms = 0;
    uint64_t last_attempt_elapsed_ms = 0;
    uint64_t status_age_ms = 0;
    uint64_t last_call_ms = 0;
    uint64_t total_calls = 0;
    uint64_t total_errors = 0;
    std::string phase;
    std::string error_type;
    std::string error_kind;
    std::string readiness_phase;
    std::string last_debug_event;
    bool protocol_schema_viewport = false;
    bool browser_open = false;
    std::string active_page_id;
    std::string active_page_url;
    std::string active_page_title;
    uint32_t page_count = 0;
    uint32_t session_count = 1;
    uint32_t browser_instance_count = 0;
    uint32_t child_process_count = 0;
    uint32_t browser_process_count = 0;
    std::vector<page_status_t> pages;
    std::string active_profile_dir;
    bool active_profile_generated = false;
    std::string effective_ua_policy = "camoufox_native";
    std::string ua_override_string;
    bool ua_override = false;
    bool webrtc_blocked = false;
    bool privacy_verified = false;
    nlohmann::json privacy_diagnostics;
    nlohmann::json last_launch_diagnostics;
    bool page_verified = false;
    bool child_alive = false;
    bool cleanup_pending = false;
    uint64_t cleanup_generation = 0;
    uint64_t cleanup_started_ms = 0;
    uint32_t cleanup_child_pid = 0;
    std::string cleanup_reason;
    nlohmann::json cleanup_diagnostics;
    uint64_t generation = 0;
    uint64_t last_launch_ms = 0;
    uint64_t last_nav_ms = 0;
    uint64_t last_cleanup_ms = 0;
    uint64_t last_verified_ms = 0;
};

struct call_result_t {
    bool ok = false;
    std::string error;
    nlohmann::json data;
    std::string text;
};

struct bridge_state_changed_t {
    bridge_state_t state = bridge_state_t::stopped;
    std::string last_error;
    uint32_t child_pid = 0;
};

inline constexpr aida::events::event_def_t<bridge_state_changed_t> kBridgeStateChanged{"burp.camoufox.state_changed"};

inline bridge_status_t& status_storage() {
    static bridge_status_t status = [] {
        bridge_status_t value;
        value.state = bridge_state_t::ready;
        value.child_pid = 12064;
        value.child_process_image_path = "/aida-preview/camoufox/camoufox.exe";
        value.child_process_identity_available = true;
        value.launched_ms = aida::preview::network::monotonic_ms() - 184000;
        value.last_call_ms = aida::preview::network::monotonic_ms();
        value.total_calls = 28;
        value.phase = "ready";
        value.readiness_phase = "page_verified";
        value.browser_open = true;
        value.active_page_id = "page-main";
        value.active_page_url = "https://portal.aidapro.net/reverse-lab";
        value.active_page_title = "AiDA Reverse Lab";
        value.page_count = 2;
        value.browser_instance_count = 1;
        value.child_process_count = 1;
        value.browser_process_count = 1;
        value.active_profile_dir = "/aida-preview/profiles/BurpBrowser";
        value.active_profile_generated = true;
        value.webrtc_blocked = true;
        value.privacy_verified = true;
        value.page_verified = true;
        value.child_alive = true;
        value.generation = 7;
        value.last_launch_ms = value.launched_ms;
        value.last_verified_ms = aida::preview::network::monotonic_ms();
        value.pages = {
            { "page-main", "context-default", value.active_page_url, value.active_page_title, "guid-main", true, false, value.launched_ms, value.last_verified_ms },
            { "page-api", "context-default", "https://portal.aidapro.net/api-docs", "API Docs", "guid-api", false, false, value.launched_ms + 12000, value.last_verified_ms - 4100 }
        };
        value.privacy_diagnostics = {{"webrtc", "blocked"}, {"ua_policy", "camoufox_native"}};
        return value;
    }();
    return status;
}

inline bridge_status_t get_status() { return status_storage(); }

inline bool start_bridge(const launch_config_t& config) {
    auto& status = status_storage();
    status.state = bridge_state_t::ready;
    status.browser_open = true;
    status.child_alive = true;
    status.page_verified = true;
    status.privacy_verified = true;
    status.webrtc_blocked = config.block_webrtc;
    status.active_page_url = "about:blank";
    status.last_launch_ms = aida::preview::network::monotonic_ms();
    aida::preview::network::record_receipt("Camoufox bridge", config.headless ? "headless ready" : "ready");
    aida::events::publish(kBridgeStateChanged, bridge_state_changed_t{status.state, {}, status.child_pid});
    return true;
}

inline bool stop_bridge(const char* = nullptr) {
    auto& status = status_storage();
    status.state = bridge_state_t::stopped;
    status.browser_open = false;
    status.child_alive = false;
    status.page_verified = false;
    aida::preview::network::record_receipt("Camoufox bridge", "stopped");
    aida::events::publish(kBridgeStateChanged, bridge_state_changed_t{status.state, {}, status.child_pid});
    return true;
}

inline bool navigate(const std::string& url, const std::string& = "domcontentloaded", int = 30000) {
    auto& status = status_storage();
    status.active_page_url = url;
    status.active_page_title = url.find("api") != std::string::npos ? "API Surface" : "Reverse Engineering Target";
    status.last_nav_ms = aida::preview::network::monotonic_ms();
    status.page_verified = true;
    aida::preview::network::record_receipt("Camoufox navigate", url);
    return !url.empty();
}

inline bool reload(const std::string& = "domcontentloaded") {
    status_storage().last_nav_ms = aida::preview::network::monotonic_ms();
    aida::preview::network::record_receipt("Camoufox page", "reloaded");
    return true;
}

inline call_result_t evaluate_js(const std::string& expression, bool = true) {
    return { true, {}, {{"type", "string"}, {"value", "preview evaluation result"}, {"expression_length", expression.size()}}, "preview evaluation result" };
}

inline bool add_init_script(const std::string& script) {
    aida::preview::network::record_receipt("Camoufox init script", std::to_string(script.size()) + " bytes");
    return !script.empty();
}

inline call_result_t get_console_logs(size_t max_records = 200) {
    return { true, {}, {{"records", nlohmann::json::array({
        {{"level", "info"}, {"text", "AiDA instrumentation ready"}, {"source", "page"}},
        {{"level", "debug"}, {"text", "WebSocket endpoint discovered"}, {"source", "network"}},
        {{"level", "warning"}, {"text", "Source map is not published"}, {"source", "console"}}
    })}, {"limit", max_records}}, "3 console records" };
}

inline call_result_t list_network_requests(size_t max_records = 200) {
    return { true, {}, {{"requests", nlohmann::json::array({
        {{"method", "GET"}, {"url", "https://portal.aidapro.net/api/v2/session"}, {"status", 200}, {"type", "fetch"}},
        {{"method", "POST"}, {"url", "https://sandbox.aidapro.net/v1/analyze"}, {"status", 202}, {"type", "xhr"}},
        {{"method", "GET"}, {"url", "wss://portal.aidapro.net/events"}, {"status", 101}, {"type", "websocket"}}
    })}, {"limit", max_records}}, "3 network records" };
}

inline call_result_t get_page_info() {
    const auto status = get_status();
    return { true, {}, {{"url", status.active_page_url}, {"title", status.active_page_title}, {"page_id", status.active_page_id}}, status.active_page_title };
}

inline bool take_screenshot(const std::string& output_path, bool = true) {
    aida::preview::network::record_receipt("Camoufox screenshot", output_path);
    return !output_path.empty();
}

inline bool reset_browser_state() {
    status_storage().total_calls = 0;
    aida::preview::network::record_receipt("Camoufox browser state", "reset");
    return true;
}

inline bool inject_hook_preset(const std::string& preset_name) {
    aida::preview::network::record_receipt("Camoufox hook preset", preset_name);
    return !preset_name.empty();
}

inline bool remove_hooks() {
    aida::preview::network::record_receipt("Camoufox hooks", "removed");
    return true;
}

inline std::string last_error() { return status_storage().last_error; }

namespace install {

enum class install_state_t : int {
    unknown = 0,
    checking,
    available,
    missing_python,
    missing_module,
    missing_browser,
    installing,
    install_failed,
    ok
};

struct status_t {
    install_state_t state = install_state_t::ok;
    std::string python_path = "/aida-preview/runtime/python";
    std::string module_version = "0.4.11";
    std::string browser_path = "/aida-preview/camoufox/camoufox.exe";
    std::string last_message = "Preview runtime ready";
};

inline status_t probe() { return {}; }
inline bool pip_install_module(std::string& out_log) { out_log = "Preview Camoufox module is already available"; return true; }
inline bool fetch_browser(std::string& out_log) { out_log = "Preview Camoufox browser is already available"; return true; }
inline std::string last_error() { return {}; }

}

}

namespace aida::burp::browser {

enum class certificate_strategy_t : uint8_t {
    trust_store_only = 0,
    camoufox_spki_allowlist = 1,
    unsafe_ignore_all_for_debug_builds_only = 2
};

struct browser_launch_config_t {
    std::string proxy_host = "127.0.0.1";
    uint16_t proxy_port = 8443;
    std::string profile_subdir = "BurpBrowser";
    std::string initial_url;
    certificate_strategy_t certificate_strategy = certificate_strategy_t::camoufox_spki_allowlist;
    std::string spki_allowlist;
    bool clear_profile_first = false;
};

struct browser_status_t {
    bool running = false;
    uint32_t pid = 0;
    std::string browser_path;
    std::string profile_path;
    uint16_t proxy_port = 0;
    uint64_t launched_ms = 0;
    certificate_strategy_t certificate_strategy = certificate_strategy_t::camoufox_spki_allowlist;
    std::string spki_hash_prefix;
};

inline std::vector<browser_status_t>& browser_storage() {
    static std::vector<browser_status_t> browsers = {
        { true, 12064, "/aida-preview/camoufox/camoufox.exe", "/aida-preview/profiles/BurpBrowser", 8443,
          aida::preview::network::monotonic_ms() - 184000, certificate_strategy_t::camoufox_spki_allowlist, "n3LzqMY7lB8L" }
    };
    return browsers;
}

inline bool launch(const browser_launch_config_t& config, uint32_t& out_pid) {
    out_pid = 12064;
    auto& browsers = browser_storage();
    browsers.clear();
    browsers.push_back({ true, out_pid, "/aida-preview/camoufox/camoufox.exe",
        "/aida-preview/profiles/" + config.profile_subdir, config.proxy_port,
        aida::preview::network::monotonic_ms(), config.certificate_strategy, "n3LzqMY7lB8L" });
    camoufox::launch_config_t bridge_config;
    bridge_config.proxy = config.proxy_host + ":" + std::to_string(config.proxy_port);
    camoufox::start_bridge(bridge_config);
    if (!config.initial_url.empty()) camoufox::navigate(config.initial_url);
    return true;
}

inline bool kill(uint32_t pid) {
    auto& browsers = browser_storage();
    for (auto& browser : browsers) if (browser.pid == pid) browser.running = false;
    aida::preview::network::record_receipt("Camoufox process stopped", std::to_string(pid));
    return true;
}

inline bool kill_all() {
    for (auto& browser : browser_storage()) browser.running = false;
    camoufox::stop_bridge("preview stop");
    return true;
}

inline std::vector<browser_status_t> list_running() { return browser_storage(); }
inline bool certificate_strategy_debug_only_available() { return false; }

inline const char* certificate_strategy_name(certificate_strategy_t strategy) {
    switch (strategy) {
    case certificate_strategy_t::trust_store_only: return "trust_store_only";
    case certificate_strategy_t::camoufox_spki_allowlist: return "camoufox_spki_allowlist";
    case certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only: return "unsafe_ignore_all_for_debug_builds_only";
    }
    return "camoufox_spki_allowlist";
}

inline std::string spki_hash_prefix(const std::string& allowlist) {
    return allowlist.substr(0, std::min<size_t>(12, allowlist.size()));
}

inline std::string last_error() { return {}; }

}
