#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

#ifdef small
#undef small
#endif

#include "headless_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_browser.hpp"
#else
#include "camoufox_bridge.hpp"
#include "camoufox_install.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/components.hpp"
#include "../../infra/event_bus.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
#include <utility>

namespace aida {
namespace burp {
namespace headless_view {

namespace {

constexpr size_t kInstallLogCapacity   = 256;
constexpr size_t kConsoleCacheCapacity = 200;
constexpr size_t kNetworkCacheCapacity = 50;
constexpr size_t kEvalOutputRenderCap  = 8 * 1024;
constexpr uint64_t kPollIntervalMs     = 750;

struct state_t
{
    char        url_input[2048] = {};
    char        eval_input[8192] = {};
    std::string eval_output;
    std::string last_screenshot_path;

    bool        cfg_headless        = false;
    bool        cfg_humanize        = false;
    bool        cfg_block_images    = false;
    bool        cfg_block_webrtc    = true;

    bool        show_install_panel  = false;
    bool        install_panel_user_toggled = false;

    std::vector<std::string>     install_log;
    std::vector<nlohmann::json>  console_cache;
    std::vector<nlohmann::json>  network_cache;
    int                          console_cache_signature = 0;
    int                          network_cache_signature = 0;

    uint64_t    last_poll_ms = 0;
    int         selected_hook_preset = 0;
    int         selected_os = 0;
    int         selected_locale = 0;

    aida::burp::camoufox::install::status_t install_status;
    aida::burp::camoufox::bridge_status_t   bridge_status;

    float       anim_time    = 0.f;
    float       split_ratio  = 0.6f;
    bool        console_autoscroll = true;
    bool        network_autoscroll = true;

    aida::events::subscription_handle_t sub_state;

    std::mutex  log_mtx;
    std::mutex  status_mtx;
    std::mutex  err_mtx;
    std::string last_err;

    std::atomic<bool> initialized{false};
    std::atomic<bool> poll_in_flight{false};
    std::atomic<bool> install_poll_in_flight{false};
    std::atomic<bool> install_log_dirty{false};
};

inline state_t g_state;

const char* kHookPresets[] = {
    "xss_sentinel",
    "alert_capture",
    "eval_capture",
    "function_capture",
    "setTimeout_capture",
    "location_capture",
};
constexpr int kHookPresetCount = static_cast<int>(sizeof(kHookPresets) / sizeof(kHookPresets[0]));

const char* kOsPresets[] = { "windows" };
constexpr int kOsPresetCount = static_cast<int>(sizeof(kOsPresets) / sizeof(kOsPresets[0]));

const char* kLocalePresets[] = { "auto", "en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "ja-JP", "zh-CN" };
constexpr int kLocalePresetCount = static_cast<int>(sizeof(kLocalePresets) / sizeof(kLocalePresets[0]));

void set_err(const std::string& msg)
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    g_state.last_err = msg;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string format_elapsed(uint64_t launched_ms)
{
    if (launched_ms == 0) return std::string("-");
    const uint64_t now = now_ms();
    if (now < launched_ms) return std::string("0s");
    const uint64_t diff = (now - launched_ms) / 1000ULL;
    char buf[64];
    if (diff < 60) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llus", static_cast<unsigned long long>(diff));
    } else if (diff < 3600) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llum %llus",
                    static_cast<unsigned long long>(diff / 60),
                    static_cast<unsigned long long>(diff % 60));
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%lluh %llum",
                    static_cast<unsigned long long>(diff / 3600),
                    static_cast<unsigned long long>((diff % 3600) / 60));
    }
    return std::string(buf);
}

const char* state_label(aida::burp::camoufox::bridge_state_t s)
{
    switch (s) {
        case aida::burp::camoufox::bridge_state_t::stopped:  return "Stopped";
        case aida::burp::camoufox::bridge_state_t::starting: return "Starting";
        case aida::burp::camoufox::bridge_state_t::ready:    return "Ready";
        case aida::burp::camoufox::bridge_state_t::error:    return "Error";
    }
    return "Unknown";
}

ImU32 state_color(const aida::ui::theme_t& th, aida::burp::camoufox::bridge_state_t s)
{
    switch (s) {
        case aida::burp::camoufox::bridge_state_t::stopped:  return th.text_dim;
        case aida::burp::camoufox::bridge_state_t::starting: return th.warning;
        case aida::burp::camoufox::bridge_state_t::ready:    return th.success;
        case aida::burp::camoufox::bridge_state_t::error:    return th.error;
    }
    return th.text_dim;
}

void append_install_log_line(std::string line)
{
    if (line.empty()) return;
    std::lock_guard<std::mutex> lk(g_state.log_mtx);
    if (g_state.install_log.size() >= kInstallLogCapacity) {
        const size_t drop = (kInstallLogCapacity / 4) + 1;
        const auto drop_count = static_cast<std::vector<std::string>::difference_type>(drop);
        g_state.install_log.erase(g_state.install_log.begin(), g_state.install_log.begin() + drop_count);
    }
    g_state.install_log.push_back(std::move(line));
    g_state.install_log_dirty.store(true, std::memory_order_release);
}

void on_bridge_state_changed(const aida::burp::camoufox::bridge_state_changed_t& ev)
{
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        g_state.bridge_status.state     = ev.state;
        g_state.bridge_status.last_error = ev.last_error;
        g_state.bridge_status.child_pid = ev.child_pid;
    }
    ::diag::log_tagged_fmt("headless_v", "bridge_state_changed state=%s pid=%u",
        state_label(ev.state), static_cast<unsigned>(ev.child_pid));
}

bool need_install_panel(const aida::burp::camoufox::install::status_t& s)
{
    using namespace aida::burp::camoufox::install;
    return s.state != install_state_t::ok;
}

bool string_eq_lower(const std::string& a, const char* b)
{
    if (!b) return false;
    size_t blen = std::strlen(b);
    if (a.size() != blen) return false;
    for (size_t i = 0; i < blen; ++i) {
        char ca = a[i]; if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca + 32);
        char cb = b[i]; if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

void schedule_status_poll()
{
    bool expected = false;
    if (!g_state.poll_in_flight.compare_exchange_strong(expected, true)) return;
    const bool posted = [&]() {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.status_poll";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        aida::burp::camoufox::bridge_status_t s = aida::burp::camoufox::get_status();
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            g_state.bridge_status = s;
        }

        if (s.state == aida::burp::camoufox::bridge_state_t::ready) {
            auto cl = aida::burp::camoufox::get_console_logs(kConsoleCacheCapacity);
            if (cl.ok) {
                std::vector<nlohmann::json> rows;
                try {
                    if (cl.data.is_array()) {
                        for (const auto& it : cl.data) rows.push_back(it);
                    } else if (cl.data.is_object() && cl.data.contains("logs") && cl.data["logs"].is_array()) {
                        for (const auto& it : cl.data["logs"]) rows.push_back(it);
                    } else if (cl.data.is_object() && cl.data.contains("entries") && cl.data["entries"].is_array()) {
                        for (const auto& it : cl.data["entries"]) rows.push_back(it);
                    }
                } catch (...) {}
                std::lock_guard<std::mutex> lk(g_state.log_mtx);
                g_state.console_cache = std::move(rows);
                g_state.console_cache_signature++;
            }

            auto nr = aida::burp::camoufox::list_network_requests(kNetworkCacheCapacity);
            if (nr.ok) {
                std::vector<nlohmann::json> rows;
                try {
                    if (nr.data.is_array()) {
                        for (const auto& it : nr.data) rows.push_back(it);
                    } else if (nr.data.is_object() && nr.data.contains("requests") && nr.data["requests"].is_array()) {
                        for (const auto& it : nr.data["requests"]) rows.push_back(it);
                    } else if (nr.data.is_object() && nr.data.contains("entries") && nr.data["entries"].is_array()) {
                        for (const auto& it : nr.data["entries"]) rows.push_back(it);
                    }
                } catch (...) {}
                std::lock_guard<std::mutex> lk(g_state.log_mtx);
                g_state.network_cache = std::move(rows);
                g_state.network_cache_signature++;
            }

            auto pi = aida::burp::camoufox::get_page_info();
            if (pi.ok) {
                try {
                    if (pi.data.is_object() && pi.data.contains("url") && pi.data["url"].is_string()) {
                        std::lock_guard<std::mutex> lk(g_state.status_mtx);
                        g_state.bridge_status.active_page_url = pi.data["url"].get<std::string>();
                    }
                } catch (...) {}
            }
        }

        g_state.poll_in_flight.store(false, std::memory_order_release);
    };
        return ::aida::infra::executor::submit(std::move(sub)).submitted;
    }();
    if (!posted)
        g_state.poll_in_flight.store(false, std::memory_order_release);
}

void schedule_install_probe(bool also_log)
{
    bool expected = false;
    if (!g_state.install_poll_in_flight.compare_exchange_strong(expected, true)) return;
    const bool posted = [&]() {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.install_probe";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [also_log]() {
        aida::burp::camoufox::install::status_t s = aida::burp::camoufox::install::probe();
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            g_state.install_status = s;
        }
        if (also_log && !s.last_message.empty()) {
            append_install_log_line(s.last_message);
        }
        if (!g_state.install_panel_user_toggled) {
            g_state.show_install_panel = need_install_panel(s);
        }
        g_state.install_poll_in_flight.store(false, std::memory_order_release);
    };
        return ::aida::infra::executor::submit(std::move(sub)).submitted;
    }();
    if (!posted)
        g_state.install_poll_in_flight.store(false, std::memory_order_release);
}

void run_async_install_module()
{
    ::diag::log_tagged("headless_v", "install_module_start");
    append_install_log_line(std::string("[install_module] starting pip install"));
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.install_module";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        std::string log;
        bool ok = false;
        try { ok = aida::burp::camoufox::install::pip_install_module(log); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "install_module_result ok=%d", ok ? 1 : 0);
        std::string detail;
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            detail = g_state.install_status.last_message;
        }
        if (!ok) {
            if (detail.empty()) detail = aida::burp::camoufox::install::last_error();
            if (detail.empty()) detail = "pip install returned false";
            append_install_log_line(std::string("[install_module] ") + detail);
        } else {
            append_install_log_line(std::string("[install_module] completed"));
        }
        schedule_install_probe(true);
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_async_fetch_browser()
{
    ::diag::log_tagged("headless_v", "fetch_browser_start");
    append_install_log_line(std::string("[fetch_browser] starting download"));
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.fetch_browser";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        std::string log;
        bool ok = false;
        try { ok = aida::burp::camoufox::install::fetch_browser(log); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "fetch_browser_result ok=%d", ok ? 1 : 0);
        std::string detail;
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            detail = g_state.install_status.last_message;
        }
        if (!ok) {
            if (detail.empty()) detail = aida::burp::camoufox::install::last_error();
            if (detail.empty()) detail = "browser fetch returned false";
            append_install_log_line(std::string("[fetch_browser] ") + detail);
        } else {
            append_install_log_line(std::string("[fetch_browser] completed"));
        }
        schedule_install_probe(true);
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

aida::burp::camoufox::launch_config_t build_launch_config()
{
    aida::burp::camoufox::launch_config_t cfg;
    cfg.headless     = g_state.cfg_headless;
    cfg.humanize     = g_state.cfg_humanize;
    cfg.block_images = g_state.cfg_block_images;
    cfg.block_webrtc = true;
    if (g_state.selected_os >= 0 && g_state.selected_os < kOsPresetCount) cfg.os = kOsPresets[g_state.selected_os];
    if (g_state.selected_locale >= 0 && g_state.selected_locale < kLocalePresetCount) cfg.locale = kLocalePresets[g_state.selected_locale];
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        if (!g_state.install_status.python_path.empty()) cfg.python_executable = g_state.install_status.python_path;
    }
    return cfg;
}

void run_start_bridge()
{
    aida::burp::camoufox::launch_config_t cfg = build_launch_config();
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.start_bridge";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [cfg]() {
        bool ok = false;
        try { ok = aida::burp::camoufox::start_bridge(cfg); } catch (...) { ok = false; }
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "start_bridge returned false";
            set_err(msg);
            ::diag::log_tagged_fmt("headless_v", "start_bridge_failed msg='%s'", msg.c_str());
        } else {
            ::diag::log_tagged("headless_v", "start_bridge_completed");
        }
        schedule_status_poll();
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_stop_bridge()
{
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.stop_bridge";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        bool ok = false;
        try { ok = aida::burp::camoufox::stop_bridge("headless_view.stop"); } catch (...) { ok = false; }
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "stop_bridge returned false";
            set_err(msg);
            ::diag::log_tagged_fmt("headless_v", "stop_bridge_failed msg='%s'", msg.c_str());
        } else {
            ::diag::log_tagged("headless_v", "stop_bridge_completed");
        }
        schedule_status_poll();
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_navigate(const std::string& url)
{
    if (url.empty()) { set_err("navigate: empty url"); return; }
    std::string copy = url;
    ::diag::log_tagged_fmt("headless_v", "navigate url='%s'", copy.c_str());
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.navigate";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [copy]() {
        bool ok = false;
        try { ok = aida::burp::camoufox::navigate(copy, std::string("load"), 30000); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "navigate_result ok=%d url='%s'", ok ? 1 : 0, copy.c_str());
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "navigate returned false";
            set_err(msg);
        }
        schedule_status_poll();
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_reload()
{
    ::diag::log_tagged("headless_v", "reload");
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.reload";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        bool ok = false;
        try { ok = aida::burp::camoufox::reload(std::string("load")); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "reload_result ok=%d", ok ? 1 : 0);
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "reload returned false";
            set_err(msg);
        }
        schedule_status_poll();
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

std::string compute_screenshot_path()
{
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    std::string base = "/aida-preview/screenshots/";
#else
    char buf[MAX_PATH];
    const DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    std::string base;
    if (len == 0 || len >= MAX_PATH) base = "C:\\";
    else                              base = std::string(buf);
    if (!base.empty() && base.back() != '\\') base.push_back('\\');
    base += "Downloads\\";
    CreateDirectoryA(base.c_str(), nullptr);
#endif

    const uint64_t ts = now_ms() / 1000ULL;
    char fn[128];
    snprintf(fn, sizeof(fn), "camoufox_%llu.png", static_cast<unsigned long long>(ts));
    return base + fn;
}

void run_screenshot()
{
    std::string out = compute_screenshot_path();
    ::diag::log_tagged_fmt("headless_v", "screenshot path='%s'", out.c_str());
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.screenshot";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [out]() {
        bool ok = false;
        try { ok = aida::burp::camoufox::take_screenshot(out, true); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "screenshot_result ok=%d path='%s'", ok ? 1 : 0, out.c_str());
        if (ok) {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            g_state.last_screenshot_path = out;
        } else {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "take_screenshot returned false";
            set_err(msg);
        }
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_reset_state()
{
    ::diag::log_tagged("headless_v", "reset_state");
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.reset_state";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        bool ok = false;
        try { ok = aida::burp::camoufox::reset_browser_state(); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "reset_state_result ok=%d", ok ? 1 : 0);
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "reset_browser_state returned false";
            set_err(msg);
        }
        schedule_status_poll();
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_inject_preset(int idx)
{
    if (idx < 0 || idx >= kHookPresetCount) return;
    std::string name = kHookPresets[idx];
    ::diag::log_tagged_fmt("headless_v", "inject_hook preset='%s'", name.c_str());
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.inject_preset";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [name]() {
        bool ok = false;
        try { ok = aida::burp::camoufox::inject_hook_preset(name); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "inject_hook_result ok=%d preset='%s'", ok ? 1 : 0, name.c_str());
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "inject_hook_preset returned false";
            set_err(msg);
        }
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_remove_hooks()
{
    ::diag::log_tagged("headless_v", "remove_hooks");
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.remove_hooks";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = []() {
        bool ok = false;
        try { ok = aida::burp::camoufox::remove_hooks(); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "remove_hooks_result ok=%d", ok ? 1 : 0);
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "remove_hooks returned false";
            set_err(msg);
        }
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_evaluate_js(const std::string& expr)
{
    if (expr.empty()) {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        g_state.eval_output = "[error] expression is empty";
        return;
    }
    ::diag::log_tagged_fmt("headless_v", "evaluate_js expr_len=%zu", expr.size());
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.evaluate_js";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [expr]() {
        aida::burp::camoufox::call_result_t r;
        try { r = aida::burp::camoufox::evaluate_js(expr, true); } catch (...) { r.ok = false; r.error = "evaluate_js threw"; }
        ::diag::log_tagged_fmt("headless_v", "evaluate_js_result ok=%d error='%s'",
            r.ok ? 1 : 0, r.ok ? "" : r.error.c_str());
        std::string txt;
        if (!r.ok) {
            txt = std::string("[error] ");
            txt += r.error.empty() ? std::string("evaluate_js failed") : r.error;
        } else {
            try {
                if (!r.text.empty()) txt = r.text;
                else if (!r.data.is_null()) txt = r.data.dump(2);
                else                        txt = std::string("(no result)");
            } catch (...) {
                txt = "[error] response not serialisable";
            }
        }
        if (txt.size() > kEvalOutputRenderCap) {
            txt.resize(kEvalOutputRenderCap);
            txt.append("\n[truncated]");
        }
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        g_state.eval_output = std::move(txt);
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void run_add_init_script(const std::string& js)
{
    if (js.empty()) { set_err("add_init_script: empty"); return; }
    ::diag::log_tagged_fmt("headless_v", "add_init_script js_len=%zu", js.size());
    {
        ::aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "burp.headless_view";
        sub.label = "headless.add_init_script";
        sub.thread_class = "bounded_task";
        sub.domain = aida::infra::executor::domain_t::external_tool;
        sub.priority = 3;
        sub.body = [js]() {
        bool ok = false;
        try { ok = aida::burp::camoufox::add_init_script(js); } catch (...) { ok = false; }
        ::diag::log_tagged_fmt("headless_v", "add_init_script_result ok=%d", ok ? 1 : 0);
        if (!ok) {
            std::string msg = aida::burp::camoufox::last_error();
            if (msg.empty()) msg = "add_init_script returned false";
            set_err(msg);
        }
    };
        (void)::aida::infra::executor::submit(std::move(sub));
    }
}

void open_in_explorer(const std::string& path)
{
    if (path.empty()) return;
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
    set_err("Preview receipt: " + path);
#else
    std::wstring wpath;
    int needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (needed > 0) {
        wpath.resize(static_cast<size_t>(needed));
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), needed);
        if (!wpath.empty() && wpath.back() == L'\0') wpath.pop_back();
    } else {
        return;
    }
    std::wstring args = L"/select,\"" + wpath + L"\"";
    ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
#endif
}

void draw_status_dot(ImDrawList* dl, ImVec2 center, float radius, ImU32 color, float alpha)
{
    dl->AddCircleFilled(center, radius, aida::ui::with_alpha(color, alpha), 24);
    dl->AddCircle(center, radius + 1.5f, aida::ui::with_alpha(color, alpha * 0.40f), 24, 1.2f);
}

void draw_panel_header(ImDrawList* dl, ImVec2 org, float width, const aida::ui::theme_t& th,
                       const char* label, float alpha)
{
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 26.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddLine(ImVec2(org.x, org.y + 26.f), ImVec2(org.x + width, org.y + 26.f),
                aida::ui::with_alpha(th.border_subtle, alpha));
    dl->AddText(ImVec2(org.x + 10.f, org.y + 5.f),
                aida::ui::with_alpha(th.text_primary, alpha), label);
}

bool same_line_if_fits(float next_w, float spacing = 8.f)
{
    if (ImGui::GetContentRegionAvail().x >= next_w + spacing) {
        ImGui::SameLine(0.f, spacing);
        return true;
    }
    return false;
}

float pill_width(const char* label)
{
    return ImGui::CalcTextSize(label ? label : "").x + 28.f;
}

void status_pill(const char* label, bool ok, bool neutral_when_false = false)
{
    aida::ui::pill_kind_t kind = ok ? aida::ui::pill_kind_t::success :
        (neutral_when_false ? aida::ui::pill_kind_t::neutral : aida::ui::pill_kind_t::warning);
    aida::ui::pill_kind(label, kind, aida::ui::size_t_::sm, false);
}

const char* install_state_label(const aida::burp::camoufox::install::status_t& s)
{
    if (s.state == aida::burp::camoufox::install::install_state_t::ok) return "Ready";
    if (s.python_path.empty())     return "Python missing";
    if (s.module_version.empty())  return "Module missing";
    if (s.browser_path.empty())    return "Browser missing";
    return "Not ready";
}

ImU32 install_state_color(const aida::ui::theme_t& th, const aida::burp::camoufox::install::status_t& s)
{
    if (s.state == aida::burp::camoufox::install::install_state_t::ok) return th.success;
    if (s.python_path.empty() || s.module_version.empty() || s.browser_path.empty()) return th.error;
    return th.warning;
}

void render_install_row(ImDrawList* dl, ImVec2 pos, float width, const aida::ui::theme_t& th,
                        const char* label, bool ok, const std::string& detail, float alpha)
{
    ImU32 dot_col = aida::ui::with_alpha(ok ? th.success : th.error, alpha);
    dl->AddCircleFilled(ImVec2(pos.x + 10.f, pos.y + 10.f), 5.f, dot_col, 16);

    dl->AddText(ImVec2(pos.x + 26.f, pos.y + 3.f),
                aida::ui::with_alpha(th.text_primary, alpha), label);
    if (!detail.empty()) {
        std::string trimmed = detail;
        if (trimmed.size() > 80) { trimmed.resize(77); trimmed.append("..."); }
        dl->AddText(ImVec2(pos.x + 26.f, pos.y + 18.f),
                    aida::ui::with_alpha(th.text_dim, alpha), trimmed.c_str());
    }
    (void)width;
}

void render_install_panel(float pos_x, float pos_y, float width, float& consumed_h,
                          const aida::ui::theme_t& th, float alpha)
{
    aida::burp::camoufox::install::status_t s;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        s = g_state.install_status;
    }

    const float panel_h = 220.f;
    consumed_h = panel_h;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 win_org = ImGui::GetWindowPos();
    ImVec2 org(win_org.x + pos_x, win_org.y + pos_y);

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + panel_h),
                      aida::ui::with_alpha(th.panel_bg, alpha));
    dl->AddRect(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + panel_h),
                aida::ui::with_alpha(th.border_subtle, alpha), 0.f, 0, 1.f);

    char header[160];
    _snprintf_s(header, sizeof(header), _TRUNCATE, "Install / Setup    state=%s",
                install_state_label(s));
    draw_panel_header(dl, org, width, th, header, alpha);

    const bool python_ok  = !s.python_path.empty();
    const bool module_ok  = !s.module_version.empty();
    const bool browser_ok = !s.browser_path.empty();

    render_install_row(dl, ImVec2(org.x + 10.f, org.y + 32.f),  width - 20.f, th,
                       "Python", python_ok,
                       python_ok ? s.python_path : std::string("not found"), alpha);
    render_install_row(dl, ImVec2(org.x + 10.f, org.y + 60.f),  width - 20.f, th,
                       "Camoufox module", module_ok,
                       module_ok ? (std::string("v") + s.module_version) : std::string("not installed"), alpha);
    render_install_row(dl, ImVec2(org.x + 10.f, org.y + 88.f),  width - 20.f, th,
                       "Browser binary", browser_ok,
                       browser_ok ? s.browser_path : std::string("not fetched"), alpha);

    ImGui::SetCursorPos(ImVec2(pos_x + 10.f, pos_y + 120.f));
    ImGui::PushID("headless_install_buttons");
    const bool busy_install = false;
    if (busy_install) ImGui::BeginDisabled();
    if (ImGui::Button("Install Module", ImVec2(140.f, 26.f))) { run_async_install_module(); }
    ImGui::SameLine();
    if (ImGui::Button("Fetch Browser", ImVec2(140.f, 26.f))) { run_async_fetch_browser(); }
    ImGui::SameLine();
    if (ImGui::Button("Re-probe", ImVec2(110.f, 26.f))) {
        append_install_log_line(std::string("[re-probe] requested"));
        schedule_install_probe(true);
    }
    if (busy_install) ImGui::EndDisabled();
    ImGui::PopID();

    const float log_top = pos_y + 152.f;
    const float log_h   = (pos_y + panel_h) - log_top - 8.f;
    ImGui::SetCursorPos(ImVec2(pos_x + 10.f, log_top));
    ImGui::BeginChild("##headless_install_log", ImVec2(width - 20.f, log_h),
                      false, ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoBackground);

    std::vector<std::string> snap;
    {
        std::lock_guard<std::mutex> lk(g_state.log_mtx);
        snap = g_state.install_log;
    }
    int idx = 0;
    for (const auto& line : snap) {
        float ra = ui_anim::render_row_entrance(idx, g_state.anim_time, 0.012f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_secondary, alpha * ra)));
        ImGui::TextUnformatted(line.c_str());
        ImGui::PopStyleColor();
        ++idx;
    }
    if (snap.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_dim, alpha)));
        ImGui::TextUnformatted("No install output yet.");
        ImGui::PopStyleColor();
    }
    if (g_state.install_log_dirty.exchange(false, std::memory_order_acq_rel)) {
        ImGui::SetScrollHereY(1.f);
    }
    ImGui::EndChild();
}

void render_status_header(float pos_x, float pos_y, float width, float height,
                          const aida::ui::theme_t& th, float alpha)
{
    aida::burp::camoufox::bridge_status_t s;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        s = g_state.bridge_status;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 win_org = ImGui::GetWindowPos();
    ImVec2 org(win_org.x + pos_x, win_org.y + pos_y);

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + height),
                      aida::ui::with_alpha(th.panel_header, alpha));

    draw_status_dot(dl, ImVec2(org.x + 14.f, org.y + height * 0.5f), 6.f,
                    state_color(th, s.state), alpha);

    dl->AddText(ImVec2(org.x + 28.f, org.y + 4.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Camoufox Headless Browser");

    char sub[128];
    _snprintf_s(sub, sizeof(sub), _TRUNCATE, "state=%s    elapsed=%s",
                state_label(s.state), format_elapsed(s.launched_ms).c_str());
    dl->AddText(ImVec2(org.x + 28.f, org.y + 20.f),
                aida::ui::with_alpha(th.text_secondary, alpha), sub);

    char right[256];
    if (s.state == aida::burp::camoufox::bridge_state_t::ready ||
        s.state == aida::burp::camoufox::bridge_state_t::starting) {
        _snprintf_s(right, sizeof(right), _TRUNCATE, "PID: %u", static_cast<unsigned>(s.child_pid));
    } else {
        _snprintf_s(right, sizeof(right), _TRUNCATE, "Not running");
    }
    ImVec2 rsz = ImGui::CalcTextSize(right);
    dl->AddText(ImVec2(org.x + width - rsz.x - 12.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha), right);

    if (s.state == aida::burp::camoufox::bridge_state_t::ready && !s.active_page_url.empty()) {
        std::string url_line = std::string("Open URL: ") + s.active_page_url;
        if (url_line.size() > 80) { url_line.resize(77); url_line.append("..."); }
        ImVec2 usz = ImGui::CalcTextSize(url_line.c_str());
        dl->AddText(ImVec2(org.x + width - usz.x - 12.f, org.y + 22.f),
                    aida::ui::with_alpha(th.text_dim, alpha), url_line.c_str());
    } else if (!s.last_error.empty()) {
        std::string err_line = std::string("err: ") + s.last_error;
        if (err_line.size() > 80) { err_line.resize(77); err_line.append("..."); }
        ImVec2 esz = ImGui::CalcTextSize(err_line.c_str());
        dl->AddText(ImVec2(org.x + width - esz.x - 12.f, org.y + 22.f),
                    aida::ui::with_alpha(th.error, alpha), err_line.c_str());
    }

    const bool native_ua = !s.ua_override &&
        (s.effective_ua_policy.empty() || s.effective_ua_policy == "camoufox_native");
    ImGui::SetCursorPos(ImVec2(pos_x + 28.f, pos_y + 39.f));
    status_pill("Camoufox only", true);
    if (same_line_if_fits(pill_width("WebRTC blocked")))
        status_pill("WebRTC blocked", s.webrtc_blocked || s.state == aida::burp::camoufox::bridge_state_t::stopped, true);
    if (same_line_if_fits(pill_width("Native UA")))
        status_pill("Native UA", native_ua, true);
    if (same_line_if_fits(pill_width("Page verified")))
        status_pill("Page verified", s.page_verified, true);
    if (same_line_if_fits(pill_width("Privacy verified")))
        status_pill("Privacy verified", s.privacy_verified, true);
}

void render_bridge_controls(float pos_x, float pos_y, float width, float height,
                            const aida::ui::theme_t& th, float alpha)
{
    aida::burp::camoufox::bridge_state_t st;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        st = g_state.bridge_status.state;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 win_org = ImGui::GetWindowPos();
    ImVec2 org(win_org.x + pos_x, win_org.y + pos_y);
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + height),
                      aida::ui::with_alpha(th.panel_bg, alpha));
    dl->AddRect(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + height),
                aida::ui::with_alpha(th.border_subtle, alpha), 0.f, 0, 1.f);

    ImGui::SetCursorPos(ImVec2(pos_x + 8.f, pos_y + 7.f));
    ImGui::PushID("headless_bridge_controls");

    const bool starting = st == aida::burp::camoufox::bridge_state_t::starting;
    const bool ready    = st == aida::burp::camoufox::bridge_state_t::ready;
    const bool stopped  = st == aida::burp::camoufox::bridge_state_t::stopped
                       || st == aida::burp::camoufox::bridge_state_t::error;

    if (ready || starting) ImGui::BeginDisabled();
    if (ImGui::Button("Start", ImVec2(80.f, 26.f))) { run_start_bridge(); }
    if (ready || starting) ImGui::EndDisabled();
    same_line_if_fits(80.f);

    if (stopped || starting) ImGui::BeginDisabled();
    if (ImGui::Button("Stop", ImVec2(80.f, 26.f))) { run_stop_bridge(); }
    if (stopped || starting) ImGui::EndDisabled();
    same_line_if_fits(110.f);

    if (!ready) ImGui::BeginDisabled();
    if (ImGui::Button("Reset State", ImVec2(110.f, 26.f))) { run_reset_state(); }
    if (!ready) ImGui::EndDisabled();
    same_line_if_fits(86.f);

    ImGui::Checkbox("Headless", &g_state.cfg_headless);
    same_line_if_fits(88.f);
    ImGui::Checkbox("Humanize", &g_state.cfg_humanize);
    same_line_if_fits(108.f);
    ImGui::Checkbox("Block Images", &g_state.cfg_block_images);
    same_line_if_fits(pill_width("WebRTC blocked"));
    status_pill("WebRTC blocked", true);

    ImGui::PopID();
}

void render_url_bar(float pos_x, float pos_y, float width, float height,
                    const aida::ui::theme_t& th, float alpha)
{
    aida::burp::camoufox::bridge_state_t st;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        st = g_state.bridge_status.state;
    }
    const bool ready = st == aida::burp::camoufox::bridge_state_t::ready;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 win_org = ImGui::GetWindowPos();
    ImVec2 org(win_org.x + pos_x, win_org.y + pos_y);
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + height),
                      aida::ui::with_alpha(th.panel_bg, alpha));
    dl->AddRect(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + height),
                aida::ui::with_alpha(th.border_subtle, alpha), 0.f, 0, 1.f);

    ImGui::SetCursorPos(ImVec2(pos_x + 8.f, pos_y + 7.f));
    ImGui::PushID("headless_url_bar");

    const float btns_w = 90.f + 90.f + 110.f + 24.f;
    const float input_w = std::max(160.f, width - btns_w - 16.f);
    ImGui::SetNextItemWidth(input_w);
    ImGui::InputTextWithHint("##headless_url", "https://example.com",
                             g_state.url_input, sizeof(g_state.url_input));
    same_line_if_fits(90.f);
    if (!ready) ImGui::BeginDisabled();
    if (ImGui::Button("Navigate", ImVec2(90.f, 26.f))) {
        run_navigate(std::string(g_state.url_input));
    }
    same_line_if_fits(90.f);
    if (ImGui::Button("Reload", ImVec2(90.f, 26.f))) { run_reload(); }
    same_line_if_fits(110.f);
    if (ImGui::Button("Screenshot", ImVec2(110.f, 26.f))) { run_screenshot(); }
    if (!ready) ImGui::EndDisabled();

    ImGui::PopID();
}

void render_page_info_section(const aida::ui::theme_t& th, float alpha)
{
    std::string url, last_err;
    bool browser_open = false;
    uint64_t calls = 0, errs = 0;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        url          = g_state.bridge_status.active_page_url;
        last_err     = g_state.bridge_status.last_error;
        browser_open = g_state.bridge_status.browser_open;
        calls        = g_state.bridge_status.total_calls;
        errs         = g_state.bridge_status.total_errors;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Current page info");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_primary, alpha)));
    ImGui::Text("URL:       %s", url.empty() ? "-" : url.c_str());
    ImGui::Text("Browser:   %s", browser_open ? "open" : "closed");
    ImGui::Text("Calls:     %llu  errors=%llu",
                static_cast<unsigned long long>(calls),
                static_cast<unsigned long long>(errs));
    if (!last_err.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.error, alpha)),
                           "Err: %s", last_err.c_str());
    }
    ImGui::PopStyleColor();
}

std::string console_row_summary(const nlohmann::json& j)
{
    std::string level;
    std::string text;
    std::string ts;
    try {
        if (j.is_object()) {
            if (j.contains("level") && j["level"].is_string()) level = j["level"].get<std::string>();
            else if (j.contains("type") && j["type"].is_string()) level = j["type"].get<std::string>();
            if (j.contains("text") && j["text"].is_string()) text = j["text"].get<std::string>();
            else if (j.contains("message") && j["message"].is_string()) text = j["message"].get<std::string>();
            else if (j.contains("args")) text = j["args"].dump();
            if (j.contains("timestamp")) {
                if (j["timestamp"].is_number_unsigned()) {
                    char b[32];
                    _snprintf_s(b, sizeof(b), _TRUNCATE, "%llu",
                                static_cast<unsigned long long>(j["timestamp"].get<uint64_t>()));
                    ts = b;
                } else if (j["timestamp"].is_string()) {
                    ts = j["timestamp"].get<std::string>();
                }
            }
        } else if (j.is_string()) {
            text = j.get<std::string>();
        } else {
            text = j.dump();
        }
    } catch (...) {}
    if (level.empty()) level = "log";
    std::string out;
    out.reserve(level.size() + text.size() + ts.size() + 8);
    if (!ts.empty()) { out.append("["); out.append(ts); out.append("] "); }
    out.append("["); out.append(level); out.append("] ");
    out.append(text);
    return out;
}

ImU32 console_level_color(const aida::ui::theme_t& th, const nlohmann::json& j)
{
    std::string level;
    try {
        if (j.is_object()) {
            if (j.contains("level") && j["level"].is_string()) level = j["level"].get<std::string>();
            else if (j.contains("type") && j["type"].is_string()) level = j["type"].get<std::string>();
        }
    } catch (...) {}
    if (string_eq_lower(level, "error") || string_eq_lower(level, "exception")) return th.error;
    if (string_eq_lower(level, "warn") || string_eq_lower(level, "warning"))    return th.warning;
    if (string_eq_lower(level, "info"))                                          return th.info;
    if (string_eq_lower(level, "debug") || string_eq_lower(level, "trace"))     return th.text_dim;
    return th.text_primary;
}

void render_console_section(const aida::ui::theme_t& th, float alpha, float region_height)
{
    std::vector<nlohmann::json> snap;
    int sig = 0;
    {
        std::lock_guard<std::mutex> lk(g_state.log_mtx);
        snap = g_state.console_cache;
        sig  = g_state.console_cache_signature;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Console logs");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::Checkbox("auto-scroll##headless_console", &g_state.console_autoscroll);
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear##headless_console")) {
        ::diag::log_tagged("headless_v", "clear_console_cache");
        std::lock_guard<std::mutex> lk(g_state.log_mtx);
        g_state.console_cache.clear();
        g_state.console_cache_signature++;
    }

    ImGui::BeginChild("##headless_console_inner",
                      ImVec2(0.f, std::max(60.f, region_height - 28.f)),
                      false, ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoBackground);

    int idx = 0;
    for (const auto& row : snap) {
        float ra = ui_anim::render_row_entrance(idx, g_state.anim_time, 0.010f);
        ImU32 col = aida::ui::with_alpha(console_level_color(th, row), alpha * ra);
        std::string line = console_row_summary(row);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(col));
        ImGui::TextUnformatted(line.c_str());
        ImGui::PopStyleColor();
        ++idx;
    }
    if (snap.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_dim, alpha)));
        ImGui::TextUnformatted("(no console messages)");
        ImGui::PopStyleColor();
    }

    static int s_last_sig = 0;
    static float s_last_max = 0.f;
    if (g_state.console_autoscroll) {
        float maxs = ImGui::GetScrollMaxY();
        float cur  = ImGui::GetScrollY();
        bool at_bot = (maxs <= 0.f) || (cur >= maxs - 8.f);
        if (sig != s_last_sig && at_bot) ImGui::SetScrollHereY(1.f);
        s_last_sig = sig;
        s_last_max = maxs;
    }
    (void)s_last_max;

    ImGui::EndChild();
}

std::string network_row_summary(const nlohmann::json& j, std::string& out_status,
                                std::string& out_method, uint64_t& out_len, uint64_t& out_time_ms)
{
    out_status.clear(); out_method.clear(); out_len = 0; out_time_ms = 0;
    std::string url;
    try {
        if (j.is_object()) {
            if (j.contains("url") && j["url"].is_string()) url = j["url"].get<std::string>();
            if (j.contains("method") && j["method"].is_string()) out_method = j["method"].get<std::string>();
            if (j.contains("status")) {
                if (j["status"].is_number_unsigned()) {
                    char b[16];
                    _snprintf_s(b, sizeof(b), _TRUNCATE, "%u", j["status"].get<unsigned>());
                    out_status = b;
                } else if (j["status"].is_string()) {
                    out_status = j["status"].get<std::string>();
                }
            }
            if (j.contains("response_size") && j["response_size"].is_number_unsigned()) out_len = j["response_size"].get<uint64_t>();
            else if (j.contains("length") && j["length"].is_number_unsigned())          out_len = j["length"].get<uint64_t>();
            else if (j.contains("size") && j["size"].is_number_unsigned())              out_len = j["size"].get<uint64_t>();
            if (j.contains("duration_ms") && j["duration_ms"].is_number_unsigned())     out_time_ms = j["duration_ms"].get<uint64_t>();
            else if (j.contains("time_ms") && j["time_ms"].is_number_unsigned())        out_time_ms = j["time_ms"].get<uint64_t>();
        }
    } catch (...) {}
    return url;
}

void render_network_section(const aida::ui::theme_t& th, float alpha, float region_height)
{
    std::vector<nlohmann::json> snap;
    int sig = 0;
    {
        std::lock_guard<std::mutex> lk(g_state.log_mtx);
        snap = g_state.network_cache;
        sig  = g_state.network_cache_signature;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Network requests");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::Checkbox("auto-scroll##headless_net", &g_state.network_autoscroll);
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear##headless_net")) {
        ::diag::log_tagged("headless_v", "clear_network_cache");
        std::lock_guard<std::mutex> lk(g_state.log_mtx);
        g_state.network_cache.clear();
        g_state.network_cache_signature++;
    }

    ImGui::BeginChild("##headless_net_inner",
                      ImVec2(0.f, std::max(60.f, region_height - 28.f)),
                      false, ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoBackground);

    int idx = 0;
    for (const auto& row : snap) {
        float ra = ui_anim::render_row_entrance(idx, g_state.anim_time, 0.010f);
        std::string status, method;
        uint64_t len = 0, t_ms = 0;
        std::string url = network_row_summary(row, status, method, len, t_ms);
        char prefix[64];
        _snprintf_s(prefix, sizeof(prefix), _TRUNCATE,
                    "%-4s %-3s %6llu %5llums  ",
                    method.empty() ? "-" : method.c_str(),
                    status.empty() ? "-" : status.c_str(),
                    static_cast<unsigned long long>(len),
                    static_cast<unsigned long long>(t_ms));
        ImU32 col = aida::ui::with_alpha(th.text_primary, alpha * ra);
        if (!status.empty()) {
            int code = std::atoi(status.c_str());
            if (code >= 500)      col = aida::ui::with_alpha(th.error, alpha * ra);
            else if (code >= 400) col = aida::ui::with_alpha(th.warning, alpha * ra);
            else if (code >= 300) col = aida::ui::with_alpha(th.info, alpha * ra);
            else if (code >= 200) col = aida::ui::with_alpha(th.success, alpha * ra);
        }
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(col));
        ImGui::Text("%s%s", prefix, url.c_str());
        ImGui::PopStyleColor();
        ++idx;
    }
    if (snap.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_dim, alpha)));
        ImGui::TextUnformatted("(no requests)");
        ImGui::PopStyleColor();
    }
    static int s_last_sig_n = 0;
    if (g_state.network_autoscroll) {
        float maxs = ImGui::GetScrollMaxY();
        float cur  = ImGui::GetScrollY();
        bool at_bot = (maxs <= 0.f) || (cur >= maxs - 8.f);
        if (sig != s_last_sig_n && at_bot) ImGui::SetScrollHereY(1.f);
        s_last_sig_n = sig;
    }
    ImGui::EndChild();
}

void render_eval_repl(const aida::ui::theme_t& th, float alpha, float width_avail)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Evaluate JS");
    ImGui::PopStyleColor();

    const float input_h = ImGui::GetFrameHeight() * 8.f;
    ImGui::InputTextMultiline("##headless_eval_input",
                              g_state.eval_input, sizeof(g_state.eval_input),
                              ImVec2(-1.f, input_h),
                              ImGuiInputTextFlags_AllowTabInput);

    aida::burp::camoufox::bridge_state_t st;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        st = g_state.bridge_status.state;
    }
    const bool ready = st == aida::burp::camoufox::bridge_state_t::ready;

    if (!ready) ImGui::BeginDisabled();
    if (ImGui::Button("Run", ImVec2(70.f, 26.f))) {
        run_evaluate_js(std::string(g_state.eval_input));
    }
    if (!ready) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Add as init script", ImVec2(150.f, 26.f))) {
        run_add_init_script(std::string(g_state.eval_input));
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##headless_eval", ImVec2(70.f, 26.f))) {
        ::diag::log_tagged("headless_v", "eval_clear");
        g_state.eval_input[0] = '\0';
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        g_state.eval_output.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy", ImVec2(60.f, 26.f))) {
        std::string out;
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            out = g_state.eval_output;
        }
        if (!out.empty()) {
            ::diag::log_tagged_fmt("headless_v", "eval_copy_output len=%zu", out.size());
            ImGui::SetClipboardText(out.c_str());
        }
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_dim, alpha)));
    ImGui::TextUnformatted("Output:");
    ImGui::PopStyleColor();

    std::string out;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        out = g_state.eval_output;
    }
    ImGui::BeginChild("##headless_eval_out",
                      ImVec2(-1.f, std::max(80.f, ImGui::GetContentRegionAvail().y * 0.35f)),
                      true, ImGuiWindowFlags_HorizontalScrollbar);
    ImU32 out_col = aida::ui::with_alpha(th.text_primary, alpha);
    if (!out.empty() && out.size() >= 8 && out.compare(0, 7, "[error]") == 0) {
        out_col = aida::ui::with_alpha(th.error, alpha);
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(out_col));
    ImGui::TextUnformatted(out.empty() ? "(no output yet)" : out.c_str());
    ImGui::PopStyleColor();
    ImGui::EndChild();

    (void)width_avail;
}

void render_hooks_section(const aida::ui::theme_t& th, float alpha)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Hooks");
    ImGui::PopStyleColor();

    ImGui::SetNextItemWidth(220.f);
    const char* current = (g_state.selected_hook_preset >= 0 && g_state.selected_hook_preset < kHookPresetCount)
                              ? kHookPresets[g_state.selected_hook_preset] : "xss_sentinel";
    if (ImGui::BeginCombo("##headless_hook_preset", current)) {
        for (int i = 0; i < kHookPresetCount; ++i) {
            bool selected = (i == g_state.selected_hook_preset);
            if (ImGui::Selectable(kHookPresets[i], selected)) g_state.selected_hook_preset = i;
            if (selected) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    aida::burp::camoufox::bridge_state_t st;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        st = g_state.bridge_status.state;
    }
    const bool ready = st == aida::burp::camoufox::bridge_state_t::ready;
    if (!ready) ImGui::BeginDisabled();
    if (ImGui::Button("Inject Hook", ImVec2(110.f, 26.f))) {
        run_inject_preset(g_state.selected_hook_preset);
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove All Hooks", ImVec2(150.f, 26.f))) {
        run_remove_hooks();
    }
    if (!ready) ImGui::EndDisabled();
}

void render_screenshot_section(const aida::ui::theme_t& th, float alpha)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Latest screenshot");
    ImGui::PopStyleColor();

    std::string path;
    {
        std::lock_guard<std::mutex> lk(g_state.status_mtx);
        path = g_state.last_screenshot_path;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(path.empty() ? th.text_dim : th.text_primary, alpha)));
    ImGui::TextWrapped("%s", path.empty() ? "(none yet)" : path.c_str());
    ImGui::PopStyleColor();

    if (path.empty()) ImGui::BeginDisabled();
    if (ImGui::Button("Open in Explorer", ImVec2(160.f, 26.f))) {
        ::diag::log_tagged_fmt("headless_v", "screenshot_open_explorer path='%s'", path.c_str());
        open_in_explorer(path);
    }
    if (path.empty()) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Copy Path", ImVec2(110.f, 26.f))) {
        if (!path.empty()) {
            ::diag::log_tagged_fmt("headless_v", "screenshot_copy_path path='%s'", path.c_str());
            ImGui::SetClipboardText(path.c_str());
        }
    }
}

void render_advanced_section(const aida::ui::theme_t& th, float alpha)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted("Launch profile");
    ImGui::PopStyleColor();

    ImGui::SetNextItemWidth(140.f);
    const char* os_cur = (g_state.selected_os >= 0 && g_state.selected_os < kOsPresetCount)
                            ? kOsPresets[g_state.selected_os] : "windows";
    if (ImGui::BeginCombo("##headless_os", os_cur)) {
        for (int i = 0; i < kOsPresetCount; ++i) {
            bool sel = (i == g_state.selected_os);
            if (ImGui::Selectable(kOsPresets[i], sel)) g_state.selected_os = i;
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    const char* loc_cur = (g_state.selected_locale >= 0 && g_state.selected_locale < kLocalePresetCount)
                             ? kLocalePresets[g_state.selected_locale] : "auto";
    if (ImGui::BeginCombo("##headless_locale", loc_cur)) {
        for (int i = 0; i < kLocalePresetCount; ++i) {
            bool sel = (i == g_state.selected_locale);
            if (ImGui::Selectable(kLocalePresets[i], sel)) g_state.selected_locale = i;
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
}

}

bool initialize()
{
    bool expected = false;
    if (!g_state.initialized.compare_exchange_strong(expected, true)) return true;
    std::strcpy(g_state.url_input, "https://example.com");
    g_state.sub_state = aida::events::subscribe(
        aida::burp::camoufox::kBridgeStateChanged,
        [](const aida::burp::camoufox::bridge_state_changed_t& ev) { on_bridge_state_changed(ev); });
    schedule_status_poll();
    ::diag::log_tagged("headless_v", "headless_view_initialized");
    return true;
}

void shutdown()
{
    if (!g_state.initialized.exchange(false)) return;
    if (g_state.sub_state.valid()) aida::events::unsubscribe(g_state.sub_state);
    ::diag::log_tagged("headless_v", "headless_view_shutdown");
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(g_state.err_mtx);
    return g_state.last_err;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;

    const auto& th = aida::ui::resolved();
    g_state.anim_time += ImGui::GetIO().DeltaTime;

    const uint64_t now = now_ms();
    if (now - g_state.last_poll_ms >= kPollIntervalMs) {
        g_state.last_poll_ms = now;
        schedule_status_poll();
        if (g_state.show_install_panel || !g_state.install_panel_user_toggled) {
            schedule_install_probe(false);
        }
    }

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##headless_view_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    const float pad_x = 8.f;
    const float content_w = width - pad_x * 2.f;
    float cursor_y = 0.f;

    render_status_header(pad_x, cursor_y, content_w, 66.f, th, alpha);
    cursor_y += 70.f;

    {
        const char* lbl = g_state.show_install_panel ? "Hide install panel" : "Show install panel";
        ImGui::SetCursorPos(ImVec2(pad_x, cursor_y));
        ImGui::PushID("headless_install_toggle");
        if (ImGui::SmallButton(lbl)) {
            g_state.show_install_panel = !g_state.show_install_panel;
            g_state.install_panel_user_toggled = true;
        }
        ImGui::SameLine();
        aida::burp::camoufox::install::status_t s;
        {
            std::lock_guard<std::mutex> lk(g_state.status_mtx);
            s = g_state.install_status;
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(install_state_color(th, s), alpha)),
            "install=%s", install_state_label(s));
        ImGui::PopID();
    }
    cursor_y += 26.f;

    if (g_state.show_install_panel) {
        float consumed = 0.f;
        render_install_panel(pad_x, cursor_y, content_w, consumed, th, alpha);
        cursor_y += consumed + 6.f;
    }

    const float controls_h = content_w < 760.f ? 72.f : 40.f;
    render_bridge_controls(pad_x, cursor_y, content_w, controls_h, th, alpha);
    cursor_y += controls_h + 4.f;

    const float url_h = content_w < 640.f ? 72.f : 40.f;
    render_url_bar(pad_x, cursor_y, content_w, url_h, th, alpha);
    cursor_y += url_h + 4.f;

    const float split_y0 = cursor_y;
    const float split_h  = std::max(120.f, height - split_y0 - 8.f);
    const float left_w   = std::max(180.f, content_w * g_state.split_ratio - 6.f);
    const float right_w  = std::max(180.f, content_w - left_w - 12.f);

    ImGui::SetCursorPos(ImVec2(pad_x, split_y0));
    ImGui::BeginChild("##headless_left", ImVec2(left_w, split_h), false,
                      ImGuiWindowFlags_NoBackground);
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 lo = ImGui::GetWindowPos();
        dl->AddRectFilled(lo, ImVec2(lo.x + left_w, lo.y + split_h),
                          aida::ui::with_alpha(th.panel_bg, alpha));
        dl->AddRect(lo, ImVec2(lo.x + left_w, lo.y + split_h),
                    aida::ui::with_alpha(th.border_subtle, alpha), 0.f, 0, 1.f);
        ImGui::PushID("headless_left_inner");
        const float pad = 8.f;

        ImGui::SetCursorPos(ImVec2(pad, pad));
        ImGui::BeginGroup();
        render_page_info_section(th, alpha);
        ImGui::EndGroup();

        const float info_h = 100.f;
        ImGui::SetCursorPos(ImVec2(pad, pad + info_h));
        ImGui::BeginChild("##headless_left_console",
                          ImVec2(left_w - pad * 2.f, (split_h - info_h - 12.f) * 0.55f),
                          false, ImGuiWindowFlags_NoBackground);
        render_console_section(th, alpha, ImGui::GetContentRegionAvail().y);
        ImGui::EndChild();

        ImGui::SetCursorPos(ImVec2(pad, pad + info_h + (split_h - info_h - 12.f) * 0.55f + 4.f));
        ImGui::BeginChild("##headless_left_net",
                          ImVec2(left_w - pad * 2.f, (split_h - info_h - 12.f) * 0.45f),
                          false, ImGuiWindowFlags_NoBackground);
        render_network_section(th, alpha, ImGui::GetContentRegionAvail().y);
        ImGui::EndChild();

        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pad_x + left_w + 6.f, split_y0));
    ImGui::BeginChild("##headless_right", ImVec2(right_w, split_h), false,
                      ImGuiWindowFlags_NoBackground);
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 ro = ImGui::GetWindowPos();
        dl->AddRectFilled(ro, ImVec2(ro.x + right_w, ro.y + split_h),
                          aida::ui::with_alpha(th.panel_bg, alpha));
        dl->AddRect(ro, ImVec2(ro.x + right_w, ro.y + split_h),
                    aida::ui::with_alpha(th.border_subtle, alpha), 0.f, 0, 1.f);
        ImGui::PushID("headless_right_inner");
        const float pad = 8.f;

        ImGui::SetCursorPos(ImVec2(pad, pad));
        ImGui::BeginGroup();
        render_eval_repl(th, alpha, right_w - pad * 2.f);
        ImGui::EndGroup();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::BeginGroup();
        render_hooks_section(th, alpha);
        ImGui::EndGroup();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::BeginGroup();
        render_screenshot_section(th, alpha);
        ImGui::EndGroup();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::BeginGroup();
        render_advanced_section(th, alpha);
        ImGui::EndGroup();

        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
