#include "network_view.hpp"
#include "../infra/executor.hpp"
#include "../infra/taskflow_runtime.hpp"
#include "executor_status.hpp"
#include "standalone_driver.hpp"
#include "../runtime/standalone_license.hpp"
#include "protocol_parser.hpp"
#include "mitm_proxy.hpp"
#include "cert_pin_bypass.hpp"
#include "cert_generator.hpp"
#include "ssl_keylog.hpp"
#include "script_engine.hpp"
#include "decoder_pipeline.hpp"
#include "toast_notification.hpp"
#include "ui_anim.hpp"
#include "../ui/theme.hpp"
#include "../ui/clock.hpp"
#include "../ui/motion.hpp"
#include "../ui/transition.hpp"
#include "../ui/components.hpp"
#include "../ui/empty_state.hpp"
#include "../ui/no_target_overlay.hpp"
#include "../ui/responsive.hpp"
#include "../ui/skeleton.hpp"
#include "../ui/blur_layer.hpp"
#include "../ui/fonts.hpp"
#include "../helpers/helpers.h"
#include "../helpers/diag_log.hpp"
#include "../helpers/win32_dialog.hpp"
#include "../session/analysis_session.hpp"
#include "../anti-tamper/webhook.hpp"

#include "burp/burp_module.hpp"
#include "burp/site_map.hpp"
#include "burp/scope.hpp"
#include "burp/cookie_jar.hpp"
#include "burp/scanner_view.hpp"
#include "burp/recon_view.hpp"
#include "burp/intruder_view.hpp"
#include "burp/collaborator_view.hpp"
#include "burp/sequencer_view.hpp"
#include "burp/comparer_view.hpp"
#include "burp/jwt_lab_view.hpp"
#include "burp/match_replace_view.hpp"
#include "burp/session_handler_view.hpp"
#include "burp/api_view.hpp"
#include "burp/ws_editor_view.hpp"
#include "burp/h2_editor_view.hpp"
#include "burp/burp_logger_view.hpp"
#include "burp/csp_view.hpp"
#include "burp/upstream_view.hpp"
#include "burp/browser_view.hpp"
#include "burp/browser_launch.hpp"
#include "burp/report_view.hpp"
#include "burp/headless_view.hpp"
#include "burp/offensive/api_security_engine.hpp"
#include "burp/offensive/auth_attack_engine.hpp"
#include "burp/offensive/business_logic_engine.hpp"
#include "burp/offensive/client_attack_engine.hpp"
#include "burp/offensive/fuzzing_engine.hpp"
#include "burp/offensive/js_analysis_engine.hpp"
#include "burp/offensive/recon_engine.hpp"
#include "burp/offensive/server_attack_engine.hpp"
#include "burp/offensive/sqli_engine.hpp"
#include "burp/offensive/xss_engine.hpp"
#include "intercept/cert_profile_manager.hpp"
#include "intercept/diagnostics.hpp"
#include "intercept/instrumentation_provider.hpp"
#include "intercept/script_handoff.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace network_view {

using json = nlohmann::json;

static aida::ui::pill_kind_t tcp_state_to_pill(uint8_t st) {
    switch (st) {
        case 4:  return aida::ui::pill_kind_t::success;
        case 1:  return aida::ui::pill_kind_t::info;
        case 2:  return aida::ui::pill_kind_t::accent;
        case 3:  return aida::ui::pill_kind_t::accent;
        case 5:  return aida::ui::pill_kind_t::warning;
        case 6:  return aida::ui::pill_kind_t::warning;
        case 7:  return aida::ui::pill_kind_t::warning;
        case 8:  return aida::ui::pill_kind_t::warning;
        case 9:  return aida::ui::pill_kind_t::warning;
        case 10: return aida::ui::pill_kind_t::info;
        case 0:  return aida::ui::pill_kind_t::error;
        case 11: return aida::ui::pill_kind_t::error;
        default: return aida::ui::pill_kind_t::neutral;
    }
}

static ImU32 protocol_stripe_color(const std::string& label) {
    const auto& t = aida::ui::resolved();
    if (label == "HTTP") return t.info;
    if (label == "TLS")  return t.success;
    if (label == "DNS")  return t.warning;
    if (label == "QUIC") return t.accent_u32;
    if (label == "TCP")  return t.text_dim;
    if (label == "UDP")  return t.info_soft;
    return t.text_dim;
}

struct capture_row_snapshot_t {
    int packet_index = -1;
    uint64_t timestamp = 0;
    std::string src;
    std::string dst;
    std::string protocol_label;
    std::string summary;
};

struct capture_table_snapshot_t {
    size_t total_count = 0;
    int selected_index = -1;
    std::vector<capture_row_snapshot_t> rows;
};

static ImU32 status_code_color(int code) {
    const auto& t = aida::ui::resolved();
    if (code >= 200 && code < 300) return t.success;
    if (code >= 300 && code < 400) return t.info;
    if (code >= 400 && code < 500) return t.warning;
    if (code >= 500)               return t.error;
    return t.text_dim;
}

static aida::ui::pill_kind_t status_code_pill(int code) {
    if (code >= 200 && code < 300) return aida::ui::pill_kind_t::success;
    if (code >= 300 && code < 400) return aida::ui::pill_kind_t::info;
    if (code >= 400 && code < 500) return aida::ui::pill_kind_t::warning;
    if (code >= 500)               return aida::ui::pill_kind_t::error;
    return aida::ui::pill_kind_t::neutral;
}


struct row_entrance_state_t {
    std::vector<float> spawn_time;
};
static row_entrance_state_t s_conn_rows;
static row_entrance_state_t s_cap_rows;
static row_entrance_state_t s_dns_rows;
static row_entrance_state_t s_proxy_rows;
static row_entrance_state_t s_kl_rows;

static void compute_row_entrance(row_entrance_state_t& rs, size_t total, float& alpha_out, float& off_out, int row_index) {
    if (rs.spawn_time.size() < total) {
        float now = aida::ui::clock::seconds();
        float stagger = 0.012f;
        size_t base = rs.spawn_time.size();
        for (size_t i = base; i < total; ++i)
            rs.spawn_time.push_back(now + (float)(i - base) * stagger);
    } else if (rs.spawn_time.size() > total) {
        rs.spawn_time.resize(total);
    }
    if (row_index < 0 || (size_t)row_index >= rs.spawn_time.size()) {
        alpha_out = 1.f; off_out = 0.f; return;
    }
    float age = aida::ui::clock::seconds() - rs.spawn_time[row_index];
    float dur = 0.180f;
    if (age >= dur) { alpha_out = 1.f; off_out = 0.f; return; }
    if (age < 0.f) { alpha_out = 0.f; off_out = 8.f; return; }
    float t01 = age / dur;
    float eased = aida::motion::ease::out_cubic(t01);
    alpha_out = eased;
    off_out = (1.f - eased) * 8.f;
}


struct intercept_ui_state_t {
    int     prev_held_count = 0;
    aida::ui::flash_t border_flash;
    aida::ui::flash_t label_flash;
};
static intercept_ui_state_t s_intercept_ui;


struct proxy_history_chart_t {
    static constexpr int N = 32;
    float values[N] = {};
    int   head = 0;
    uint64_t last_total = 0;
    float    last_sample_time = 0.f;
};
static proxy_history_chart_t s_proxy_chart;

static void proxy_chart_tick(uint64_t total_requests) {
    float now = aida::ui::clock::seconds();
    if (s_proxy_chart.last_sample_time == 0.f) {
        s_proxy_chart.last_total = total_requests;
        s_proxy_chart.last_sample_time = now;
        return;
    }
    float dt = now - s_proxy_chart.last_sample_time;
    if (dt < 0.5f) return;
    uint64_t diff = total_requests - s_proxy_chart.last_total;
    float rate = (dt > 0.f) ? (float)diff / dt : 0.f;
    s_proxy_chart.values[s_proxy_chart.head] = rate;
    s_proxy_chart.head = (s_proxy_chart.head + 1) % proxy_history_chart_t::N;
    s_proxy_chart.last_total = total_requests;
    s_proxy_chart.last_sample_time = now;
}


struct capture_rate_smooth_t {
    float displayed = 0.f;
    float velocity  = 0.f;
    float ema       = 0.f;
    float last_sample_time = 0.f;
    size_t last_count = 0;
};
static capture_rate_smooth_t s_cap_rate;
static std::mutex s_capture_control_mutex;
static std::string s_capture_control_status;

static void set_capture_control_status(const char* text) {
    std::lock_guard<std::mutex> lock(s_capture_control_mutex);
    s_capture_control_status = text ? text : "";
}

static std::string capture_control_status() {
    std::lock_guard<std::mutex> lock(s_capture_control_mutex);
    return s_capture_control_status;
}

template <typename Fn>
static bool post_network_task(const char* name,
                              aida::infra::executor::domain_t domain,
                              const char* thread_class,
                              Fn&& fn) {
    try {
        std::string task_name = name ? name : "?";
        std::function<void()> task(std::forward<Fn>(fn));
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "network.view";
        sub.label = name ? name : "network.task";
        sub.thread_class = thread_class ? thread_class : "bounded_task";
        sub.domain = domain;
        sub.priority = 3;
        sub.body = [task_name, task = std::move(task), domain]() mutable {
            const bool tls_ready = aida::manual_map_tls::ensure_current_thread();
            diag::log_tagged_fmt("network",
                "executor_task_enter name=%s domain=%s tid=%lu tls_ready=%d",
                task_name.c_str(),
                aida::infra::executor::domain_name(domain),
                static_cast<unsigned long>(GetCurrentThreadId()),
                tls_ready ? 1 : 0);
            task();
            diag::log_tagged_fmt("network",
                "executor_task_exit name=%s domain=%s tid=%lu",
                task_name.c_str(),
                aida::infra::executor::domain_name(domain),
                static_cast<unsigned long>(GetCurrentThreadId()));
        };
        auto submit_result = aida::infra::executor::submit(std::move(sub));
        bool ok = submit_result.submitted;
        diag::log_tagged_fmt("network", "executor_post name=%s domain=%s ok=%d reject=%s",
            name ? name : "?",
            aida::infra::executor::domain_name(domain),
            ok ? 1 : 0,
            submit_result.reject_reason.empty() ? "<none>" : submit_result.reject_reason.c_str());
        return ok;
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "executor_post_cpp_exception name=%s what=%s",
            name ? name : "?", e.what());
        return false;
    } catch (...) {
        diag::log_tagged_fmt("network", "executor_post_unknown_exception name=%s",
            name ? name : "?");
        return false;
    }
}

static bool initialize_executor_for_network() {
    try {
        const auto snap = aida::infra::taskflow_runtime::active_snapshot(0);
        const auto work = aida::network::executor_status::work_stats();
        const auto service = aida::network::executor_status::service_stats();
        const auto critical = aida::network::executor_status::critical_stats();
        const bool accepting = snap.accepting && !snap.shutting_down;
        diag::log_tagged_fmt("network",
            "executor_runtime_status accepting=%d shutting_down=%d total_active=%u executor_work_pending=%llu executor_service_pending=%llu executor_critical_pending=%llu",
            snap.accepting ? 1 : 0,
            snap.shutting_down ? 1 : 0,
            static_cast<unsigned>(snap.total_active),
            static_cast<unsigned long long>(work.pending),
            static_cast<unsigned long long>(service.pending),
            static_cast<unsigned long long>(critical.pending));
        return accepting;
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "executor_runtime_status_cpp_exception what=%s", e.what());
        return false;
    } catch (...) {
        diag::log_tagged("network", "executor_runtime_status_unknown_exception");
        return false;
    }
}

static float capture_rate_tick(size_t total_packets) {
    float now = aida::ui::clock::seconds();
    if (s_cap_rate.last_sample_time == 0.f) {
        s_cap_rate.last_sample_time = now;
        s_cap_rate.last_count = total_packets;
        return 0.f;
    }
    float dt = now - s_cap_rate.last_sample_time;
    if (dt >= 0.25f) {
        size_t diff = total_packets >= s_cap_rate.last_count ? total_packets - s_cap_rate.last_count : 0;
        float rate = (dt > 0.f) ? (float)diff / dt : 0.f;
        float a = 0.35f;
        s_cap_rate.ema = s_cap_rate.ema * (1.f - a) + rate * a;
        s_cap_rate.last_count = total_packets;
        s_cap_rate.last_sample_time = now;
    }
    s_cap_rate.displayed = aida::motion::critically_damped_step(
        s_cap_rate.displayed, s_cap_rate.ema, s_cap_rate.velocity, 0.18f, aida::ui::clock::dt());
    if (s_cap_rate.displayed < 0.f) s_cap_rate.displayed = 0.f;
    return s_cap_rate.displayed;
}


static aida::ui::transition_t s_tab_content_in;
static int s_last_active_tab = -1;

struct cert_diagnostics_ui_t {
    int target_pid = 0;
    bool has_report = false;
    cert_intercept::process_diagnostics_t report;
    std::vector<cert_intercept::provider_status_t> providers;
    std::string status;
    std::string handoff_status;
};
static cert_diagnostics_ui_t s_cert_diag_ui;

static std::string cert_diag_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static bool cert_diag_has_any(const std::string& value, std::initializer_list<const char*> needles) {
    const std::string lowered = cert_diag_lower(value);
    for (const char* needle : needles) {
        if (lowered.find(needle) != std::string::npos) return true;
    }
    return false;
}

static void cert_diag_apply_proxy_observations(cert_intercept::diagnostic_context_t& context) {
    auto observations = mitm_proxy::get_tls_observations(64);
    for (const auto& obs : observations) {
        std::string evidence = std::string(mitm_proxy::to_string(obs.kind)) + " host=" + obs.target_host;
        if (!obs.sni.empty()) evidence += " sni=" + obs.sni;
        if (!obs.alpn.empty()) evidence += " alpn=" + obs.alpn;
        if (!obs.detail.empty()) evidence += " detail=" + obs.detail;
        switch (obs.kind) {
        case mitm_proxy::tls_observation_kind_t::http_tls:
            context.interception_observed = true;
            break;
        case mitm_proxy::tls_observation_kind_t::sni_authority_mismatch:
            context.hostname_san_mismatch_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        case mitm_proxy::tls_observation_kind_t::client_handshake_failed:
            if (cert_diag_has_any(obs.detail, {"certificate", "unknown ca", "bad certificate", "required", "alert"})) {
                context.browser_trust_policy_or_ct_block = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::upstream_handshake_failed:
            if (cert_diag_has_any(obs.detail, {"certificate required", "bad certificate", "handshake failure", "alert certificate"})) {
                context.mutual_tls_requested = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::non_http_tls:
            context.non_http_tls_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        default:
            break;
        }
    }
}

static std::string format_ip(const uint8_t* addr, uint8_t af) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (af == 2) {
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else if (af == 23) {
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    }
    return buf;
}

static const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "???";
    }
}

static const char* tcp_state_name(uint8_t state) {
    static const char* names[] = {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    };
    if (state < 12) return names[state];
    return "UNKNOWN";
}

static std::string format_bytes(uint64_t bytes) {
    char buf[64];
    if (bytes < 1024)
        snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    else if (bytes < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

static std::string format_rate(float bytes_per_sec) {
    if (bytes_per_sec < 1024.f) return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
    return format_bytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

static std::string format_timestamp(uint64_t ts) {
    uint64_t sec = ts / 1000;
    uint64_t ms = ts % 1000;
    uint64_t h = (sec / 3600) % 24;
    uint64_t m = (sec / 60) % 60;
    uint64_t s = sec % 60;
    char buf[32];
    snprintf(buf, sizeof(buf), "%02llu:%02llu:%02llu.%03llu",
        static_cast<unsigned long long>(h), static_cast<unsigned long long>(m),
        static_cast<unsigned long long>(s), static_cast<unsigned long long>(ms));
    return buf;
}

static bool filter_text_match(const char* filter, const std::string& text) {
    if (!filter || !filter[0]) return true;

    std::string lower_filter(filter);
    std::string lower_text = text;
    for (auto& c : lower_filter) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_text) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lower_text.find(lower_filter) != std::string::npos;
}

static void clamp_capture_selection_to_buffer_locked(state_t& state) {
    int count = static_cast<int>(state.captured_packets.size());
    if (count <= 0) {
        state.cap_selected = -1;
        return;
    }
    if (state.cap_selected < -1)
        state.cap_selected = -1;
    if (state.cap_selected >= count)
        state.cap_selected = count - 1;
}

static void shift_capture_selection_after_front_pop_locked(state_t& state) {
    if (state.cap_selected > 0)
        --state.cap_selected;
    else if (state.cap_selected == 0)
        state.cap_selected = -1;
}

static std::string capture_row_info_text(const std::string& summary) {
    if (summary.size() <= 200)
        return summary;
    return summary.substr(0, 197) + "...";
}

static capture_table_snapshot_t snapshot_capture_table(state_t& state, const char* filter_text) {
    capture_table_snapshot_t snapshot;
    std::string filter = filter_text ? filter_text : "";
    std::lock_guard<std::mutex> lock(state.cap_mutex);
    clamp_capture_selection_to_buffer_locked(state);
    snapshot.total_count = state.captured_packets.size();
    snapshot.selected_index = state.cap_selected;
    snapshot.rows.reserve(state.captured_packets.size());

    bool selected_visible = snapshot.selected_index < 0;
    for (size_t i = 0; i < state.captured_packets.size(); ++i) {
        const packet_entry_t& p = state.captured_packets[i];
        std::string src = format_ip(p.src_addr, 2) + ":" + std::to_string(p.src_port);
        std::string dst = format_ip(p.dst_addr, 2) + ":" + std::to_string(p.dst_port);

        if (!filter.empty()) {
            std::string all = src + " " + dst + " " + p.protocol_label + " " + p.summary;
            if (!filter_text_match(filter.c_str(), all))
                continue;
        }

        capture_row_snapshot_t row;
        row.packet_index = static_cast<int>(i);
        row.timestamp = p.timestamp;
        row.src = std::move(src);
        row.dst = std::move(dst);
        row.protocol_label = p.protocol_label;
        row.summary = capture_row_info_text(p.summary);
        if (row.packet_index == snapshot.selected_index)
            selected_visible = true;
        snapshot.rows.push_back(std::move(row));
    }

    if (!selected_visible) {
        if (snapshot.rows.empty()) {
            state.cap_selected = -1;
        } else {
            auto it = std::lower_bound(snapshot.rows.begin(), snapshot.rows.end(), snapshot.selected_index,
                [](const capture_row_snapshot_t& row, int selected) {
                    return row.packet_index < selected;
                });
            if (it == snapshot.rows.end()) {
                it = snapshot.rows.end();
                --it;
            }
            state.cap_selected = it->packet_index;
        }
        snapshot.selected_index = state.cap_selected;
    }

    return snapshot;
}

static bool driver_feature_ready(const char* feature, int iter = -1) {
    bool drv_ok = driver_bridge::using_kernel_driver();
    bool auth_ok = drv_ok && standalone_license::is_valid();
    if (!auth_ok && (iter < 0 || iter <= 3 || (iter % 60) == 0)) {
        diag::log_tagged_fmt("network", "%s_driver_gate drv_ok=%d auth_ok=%d iter=%d",
            feature ? feature : "network",
            drv_ok ? 1 : 0,
            auth_ok ? 1 : 0,
            iter);
    }
    if (!auth_ok)
        return false;

    static std::atomic<uint64_t> s_bridge_cooldown_until_ms{0};
    uint64_t now = static_cast<uint64_t>(GetTickCount64());
    uint64_t cooldown_until = s_bridge_cooldown_until_ms.load(std::memory_order_acquire);
    if (cooldown_until != 0 && now < cooldown_until) {
        if (iter < 0 || iter <= 3 || (iter % 10) == 0) {
            diag::log_tagged_fmt("network",
                "%s_driver_gate bridge_cooldown iter=%d remaining_ms=%llu",
                feature ? feature : "network",
                iter,
                static_cast<unsigned long long>(cooldown_until - now));
        }
        return false;
    }

    ::SetLastError(ERROR_SUCCESS);
    bool bridge_ok = driver_bridge::refresh_heartbeat();
    DWORD bridge_err = bridge_ok ? ERROR_SUCCESS : ::GetLastError();
    if (!bridge_ok) {
        constexpr uint64_t kBridgeFailureCooldownMs = 5000;
        s_bridge_cooldown_until_ms.store(now + kBridgeFailureCooldownMs, std::memory_order_release);
        diag::log_tagged_fmt("network",
            "%s_driver_gate bridge_heartbeat_failed iter=%d err=%lu cooldown_ms=%llu",
            feature ? feature : "network",
            iter,
            static_cast<unsigned long>(bridge_err),
            static_cast<unsigned long long>(kBridgeFailureCooldownMs));
        return false;
    }

    if (cooldown_until != 0) {
        s_bridge_cooldown_until_ms.store(0, std::memory_order_release);
        diag::log_tagged_fmt("network",
            "%s_driver_gate bridge_heartbeat_recovered iter=%d",
            feature ? feature : "network",
            iter);
    }
    return true;
}


static void connection_poll_thread(state_t& state) {
    diag::log_tagged_fmt("network", "connection_poll_thread_started auto_refresh=%d filter_pid=%u filter_proto=%u",
        state.conn_auto_refresh_enabled.load(std::memory_order_acquire) ? 1 : 0, state.conn_filter_pid, state.conn_filter_protocol);
    int poll_iter = 0;
    while (state.conn_polling.load()) {
        bool drv_ok = driver_feature_ready("connection_poll", poll_iter);
        ++poll_iter;
        const uint64_t now_ms = static_cast<uint64_t>(GetTickCount64());
        const uint64_t last_render_ms = state.last_render_tick_ms.load(std::memory_order_acquire);
        const bool rendered_recently = last_render_ms != 0 && now_ms >= last_render_ms && (now_ms - last_render_ms) <= 2500ULL;
        const bool auto_refresh = state.conn_auto_refresh_enabled.load(std::memory_order_acquire);
        if (drv_ok && auto_refresh && rendered_recently) {
            auto raw_conns = driver_bridge::enumerate_connections(
                state.conn_filter_pid, state.conn_filter_protocol);

            std::vector<connection_entry_t> entries;
            entries.reserve(raw_conns.size());
            for (auto& c : raw_conns) {
                connection_entry_t e;
                e.pid = c.pid;
                e.protocol = c.protocol;
                e.state = c.state;
                e.local_port = c.local_port;
                e.remote_port = c.remote_port;
                e.address_family = c.address_family;
                memcpy(e.local_addr, c.local_addr, 16);
                memcpy(e.remote_addr, c.remote_addr, 16);
                entries.push_back(std::move(e));
            }

            size_t count = entries.size();
            {
                std::lock_guard<std::mutex> lock(state.conn_mutex);
                state.connections = std::move(entries);
            }
            if (poll_iter <= 3 || (poll_iter % 60) == 0) {
                diag::log_tagged_fmt("network", "connection_poll iter=%d drv_ok=1 count=%zu", poll_iter, count);
            }
        } else if (poll_iter <= 3 || (poll_iter % 60) == 0) {
            diag::log_tagged_fmt("network", "connection_poll iter=%d drv_ok=%d auto_refresh=%d rendered_recently=%d skipped",
                poll_iter, drv_ok ? 1 : 0, auto_refresh ? 1 : 0, rendered_recently ? 1 : 0);
        }

        std::unique_lock<std::mutex> lk(state.conn_cv_mutex);
        state.conn_cv.wait_for(lk, std::chrono::milliseconds(1000), [&state]() {
            return !state.conn_polling.load();
        });
    }
    diag::log_tagged("network", "connection_poll_thread_exited");
}

static void capture_poll_thread(state_t& state) {
    diag::log_tagged("network", "capture_poll_thread_started");
    state.cap_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.cap_cv_mutex);
            state.cap_cv.wait(lk, [&state]() {
                return state.cap_polling.load() || !state.cap_thread_alive.load();
            });
        }
        if (!state.cap_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "capture_poll_loop_armed");
        while (state.cap_polling.load()) {
            bool drv_ok = driver_feature_ready("capture_poll", poll_iter);
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                diag::log_tagged_fmt("network", "capture_poll iter=%d drv_ok=%d", poll_iter, drv_ok ? 1 : 0);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_packets = driver_bridge::get_captured_packets(64);

                if (!raw_packets.empty()) {
                    size_t batch_n = raw_packets.size();
                    std::lock_guard<std::mutex> lock(state.cap_mutex);
                    for (auto& p : raw_packets) {
                        packet_entry_t entry;
                        entry.timestamp = p.timestamp;
                        entry.pid = p.pid;
                        entry.protocol = static_cast<uint8_t>(p.protocol);
                        entry.direction = static_cast<uint8_t>(p.direction);
                        entry.src_port = static_cast<uint16_t>(p.local_port);
                        entry.dst_port = static_cast<uint16_t>(p.remote_port);
                        memcpy(entry.src_addr, p.local_addr, 16);
                        memcpy(entry.dst_addr, p.remote_addr, 16);
                        entry.payload_size = p.payload_size;
                        entry.payload = p.payload;

                        auto det = protocol_parser::detect_protocol(
                            p.payload.data(), p.payload.size(),
                            static_cast<uint16_t>(p.local_port), static_cast<uint16_t>(p.remote_port),
                            p.protocol);
                        entry.protocol_label = det.label;
                        entry.summary = det.summary;

                        state.captured_packets.push_back(std::move(entry));
                        while (state.captured_packets.size() > state.cap_max_packets) {
                            shift_capture_selection_after_front_pop_locked(state);
                            state.captured_packets.pop_front();
                        }
                    }
                    if (poll_iter <= 5 || (poll_iter % 50) == 0) {
                        diag::log_tagged_fmt("network", "capture_poll_batch packets=%zu total_buffered=%zu",
                            batch_n, state.captured_packets.size());
                    }
                }
            }

            for (int i = 0; i < 10 && state.cap_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "capture_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "capture_poll_thread_exited");
}

static void dns_poll_thread(state_t& state) {
    diag::log_tagged("network", "dns_poll_thread_started");
    state.dns_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.dns_cv_mutex);
            state.dns_cv.wait(lk, [&state]() {
                return state.dns_polling.load() || !state.dns_thread_alive.load();
            });
        }
        if (!state.dns_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "dns_poll_loop_armed");
        while (state.dns_polling.load()) {
            bool drv_ok = driver_feature_ready("dns_poll", poll_iter);
            if (poll_iter < 5 || (poll_iter % 100) == 0) {
                diag::log_tagged_fmt("network", "dns_poll iter=%d drv_ok=%d filter_pid=%u",
                    poll_iter, drv_ok ? 1 : 0, state.dns_filter_pid);
            }
            ++poll_iter;
            if (drv_ok) {
                auto raw_dns = driver_bridge::get_dns_queries(state.dns_filter_pid);

                if (!raw_dns.empty()) {
                    size_t added = 0;
                    std::lock_guard<std::mutex> lock(state.dns_mutex);
                    for (auto& d : raw_dns) {
                        bool duplicate = false;
                        for (auto it = state.dns_entries.rbegin();
                             it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + (std::min)(static_cast<size_t>(256), state.dns_entries.size());
                             ++it) {
                            if (it->timestamp == d.timestamp && it->domain == d.domain && it->pid == d.pid) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            dns_entry_t e;
                            e.timestamp = d.timestamp;
                            e.pid = d.pid;
                            e.query_type = static_cast<uint16_t>(d.query_type);
                            e.domain = d.domain;
                            e.resolved_addr = format_ip(d.resolved_addr, 2);
                            e.response_code = d.response_code;
                            e.ttl = d.ttl;
                            state.dns_entries.push_back(std::move(e));
                            ++added;
                        }
                    }
                    while (state.dns_entries.size() > state.dns_max_entries)
                        state.dns_entries.pop_front();
                    if (added > 0) {
                        diag::log_tagged_fmt("network", "dns_poll_batch raw=%zu added=%zu total=%zu",
                            raw_dns.size(), added, state.dns_entries.size());
                    }
                }
            }

            for (int i = 0; i < 50 && state.dns_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "dns_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "dns_poll_thread_exited");
}

static void bandwidth_poll_thread(state_t& state) {
    diag::log_tagged("network", "bandwidth_poll_thread_started");
    state.bw_thread_alive.store(true);
    int poll_iter = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk(state.bw_cv_mutex);
            state.bw_cv.wait(lk, [&state]() {
                return state.bw_polling.load() || !state.bw_thread_alive.load();
            });
        }
        if (!state.bw_thread_alive.load())
            break;
        poll_iter = 0;
        diag::log_tagged("network", "bandwidth_poll_loop_armed");
        while (state.bw_polling.load()) {
            ++poll_iter;
            if (driver_bridge::using_kernel_driver()) {
                auto raw_bw = driver_bridge::get_bw_per_process();
                if (poll_iter <= 3 || (poll_iter % 60) == 0) {
                    diag::log_tagged_fmt("network", "bandwidth_poll iter=%d processes=%zu", poll_iter, raw_bw.size());
                }

            std::vector<bw_entry_t> old_entries;
            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                old_entries = state.bw_entries;
            }

            std::vector<bw_entry_t> entries;
            entries.reserve(raw_bw.size());
            for (auto& b : raw_bw) {
                bw_entry_t e;
                e.pid = b.pid;
                e.bytes_in = b.bytes_recv;
                e.bytes_out = b.bytes_sent;
                e.rate_in = 0.f;
                e.rate_out = 0.f;

                for (auto& old : old_entries) {
                    if (old.pid == b.pid) {
                        if (old.bytes_in > 0 || old.bytes_out > 0) {
                            float dt = 0.5f;
                            e.rate_in = static_cast<float>(b.bytes_recv > old.bytes_in ? b.bytes_recv - old.bytes_in : 0) / dt;
                            e.rate_out = static_cast<float>(b.bytes_sent > old.bytes_out ? b.bytes_sent - old.bytes_out : 0) / dt;
                        }
                        memcpy(e.rate_history, old.rate_history, sizeof(e.rate_history));
                        e.history_index = old.history_index;
                        break;
                    }
                }

                e.rate_history[e.history_index % 64] = e.rate_in + e.rate_out;
                e.history_index++;

                entries.push_back(std::move(e));
            }

            {
                std::lock_guard<std::mutex> lock(state.bw_mutex);
                state.bw_entries = std::move(entries);
            }
            }


            for (int i = 0; i < 50 && state.bw_polling.load(); i++)
                Sleep(10);
        }
        diag::log_tagged_fmt("network", "bandwidth_poll_loop_idle iter=%d", poll_iter);
    }
    diag::log_tagged("network", "bandwidth_poll_thread_exited");
}


static void run_fuzzer_thread(state_t& state);

static bool start_connection_worker(state_t& state) {
    if (!state.conn_thread_done.load(std::memory_order_acquire))
        return true;
    state.conn_polling.store(true);
    state.conn_thread_done.store(false, std::memory_order_release);
    if (post_network_task("connection_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                connection_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "connection_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "connection_poll_unknown_exception");
            }
            g_state.conn_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.conn_polling.store(false);
    state.conn_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "connection_worker_post_failed");
    return false;
}

static bool start_capture_worker(state_t& state) {
    if (!state.cap_thread_done.load(std::memory_order_acquire) &&
        state.cap_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.cap_thread_alive.store(true, std::memory_order_release);
    state.cap_thread_done.store(false, std::memory_order_release);
    if (post_network_task("capture_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                capture_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "capture_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "capture_poll_unknown_exception");
            }
            g_state.cap_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.cap_thread_alive.store(false, std::memory_order_release);
    state.cap_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "capture_worker_post_failed");
    return false;
}

static bool start_dns_worker(state_t& state) {
    if (!state.dns_thread_done.load(std::memory_order_acquire) &&
        state.dns_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.dns_thread_alive.store(true, std::memory_order_release);
    state.dns_thread_done.store(false, std::memory_order_release);
    if (post_network_task("dns_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                dns_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "dns_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "dns_poll_unknown_exception");
            }
            g_state.dns_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.dns_thread_alive.store(false, std::memory_order_release);
    state.dns_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "dns_worker_post_failed");
    return false;
}

static bool start_bandwidth_worker(state_t& state) {
    if (!state.bw_thread_done.load(std::memory_order_acquire) &&
        state.bw_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.bw_thread_alive.store(true, std::memory_order_release);
    state.bw_thread_done.store(false, std::memory_order_release);
    if (post_network_task("bandwidth_poll", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            try {
                bandwidth_poll_thread(g_state);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "bandwidth_poll_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "bandwidth_poll_unknown_exception");
            }
            g_state.bw_thread_done.store(true, std::memory_order_release);
        })) {
        return true;
    }
    state.bw_thread_alive.store(false, std::memory_order_release);
    state.bw_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "bandwidth_worker_post_failed");
    return false;
}

static bool start_fuzzer_worker(state_t& state) {
    if (!state.fuzz_thread_done.load(std::memory_order_acquire) &&
        state.fuzz_thread_alive.load(std::memory_order_acquire)) {
        return true;
    }
    state.fuzz_thread_alive.store(true, std::memory_order_release);
    state.fuzz_thread_done.store(false, std::memory_order_release);
    if (post_network_task("fuzzer", aida::infra::executor::domain_t::long_running, "long_running", []() {
            try {
                diag::log_tagged("network", "fuzzer_thread_started");
                while (true) {
                    {
                        std::unique_lock<std::mutex> lk(g_state.fuzz_cv_mutex);
                        g_state.fuzz_cv.wait(lk, []() {
                            return g_state.fuzz_running.load() || !g_state.fuzz_thread_alive.load();
                        });
                    }
                    if (!g_state.fuzz_thread_alive.load())
                        break;
                    run_fuzzer_thread(g_state);
                }
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "fuzzer_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "fuzzer_unknown_exception");
            }
            g_state.fuzz_thread_done.store(true, std::memory_order_release);
            diag::log_tagged("network", "fuzzer_thread_exited");
        })) {
        return true;
    }
    state.fuzz_thread_alive.store(false, std::memory_order_release);
    state.fuzz_thread_done.store(true, std::memory_order_release);
    diag::log_tagged("network", "fuzzer_thread_post_failed");
    return false;
}

void initialize() {
    g_state.active = true;
    diag::log_tagged("network", "initialize_begin");
    anti_tamper::webhook::write_log("net_audit", "[net_audit] network_view initialize begin");

    bool executor_ready = initialize_executor_for_network();

    mitm_proxy::set_ws_frame_callback([](const mitm_proxy::ws_frame_observed_t& frame) {
        state_t::ws_frame_entry_t entry;
        entry.timestamp = frame.timestamp;
        entry.exchange_id = frame.exchange_id;
        entry.host = frame.host;
        entry.port = frame.port;
        entry.is_outbound = frame.is_outbound;
        entry.is_text = frame.is_text;
        entry.opcode = frame.opcode;
        entry.payload = frame.payload;
        if (frame.is_text && !frame.payload.empty()) {
            size_t preview_len = frame.payload.size() < 96 ? frame.payload.size() : 96;
            entry.preview.assign(frame.payload.begin(), frame.payload.begin() + static_cast<ptrdiff_t>(preview_len));
            for (auto& ch : entry.preview) {
                unsigned char uc = static_cast<unsigned char>(ch);
                if (uc < 32 || uc == 127) ch = '.';
            }
        } else if (!frame.payload.empty()) {
            char buf[16];
            entry.preview.clear();
            size_t cap = frame.payload.size() < 16 ? frame.payload.size() : 16;
            for (size_t bi = 0; bi < cap; ++bi) {
                snprintf(buf, sizeof(buf), bi == 0 ? "%02X" : " %02X", frame.payload[bi]);
                entry.preview += buf;
            }
            if (frame.payload.size() > cap) entry.preview += " ...";
        }
        {
            std::lock_guard<std::mutex> lock(g_state.ws_mutex);
            g_state.ws_frames.push_back(std::move(entry));
            while (g_state.ws_frames.size() > g_state.ws_max_frames)
                g_state.ws_frames.pop_front();
        }
    });
    anti_tamper::webhook::write_log("net_audit", "[net_audit] websocket ws_frame_callback installed");

    if (executor_ready) {
        start_connection_worker(g_state);
        start_capture_worker(g_state);
        start_dns_worker(g_state);
        start_bandwidth_worker(g_state);
        start_fuzzer_worker(g_state);
    } else {
        g_state.conn_polling.store(false);
        g_state.conn_thread_done.store(true, std::memory_order_release);
        g_state.cap_thread_alive.store(false, std::memory_order_release);
        g_state.cap_thread_done.store(true, std::memory_order_release);
        g_state.dns_thread_alive.store(false, std::memory_order_release);
        g_state.dns_thread_done.store(true, std::memory_order_release);
        g_state.bw_thread_alive.store(false, std::memory_order_release);
        g_state.bw_thread_done.store(true, std::memory_order_release);
        g_state.fuzz_thread_alive.store(false, std::memory_order_release);
        g_state.fuzz_thread_done.store(true, std::memory_order_release);
        diag::log_tagged("network", "initialize_continuing_without_poll_workers");
    }

    try {
        diag::log_tagged("network", "burp_initialize_begin");
        bool burp_ok = aida::burp::initialize();
        diag::log_tagged_fmt("network", "burp_initialize_result ok=%d", burp_ok ? 1 : 0);
    } catch (const std::exception& e) {
        diag::log_tagged_fmt("network", "burp_initialize_cpp_exception what=%s", e.what());
    } catch (...) {
        diag::log_tagged("network", "burp_initialize_unknown_exception");
    }

    diag::log_tagged("network", "initialize_complete");
}

void shutdown() {
    diag::log_tagged("network", "shutdown_begin");
    anti_tamper::webhook::write_log("net_audit", "[net_audit] network_view shutdown begin");
    mitm_proxy::set_ws_frame_callback(nullptr);
    g_state.conn_polling.store(false);
    g_state.conn_cv.notify_all();
    g_state.bw_polling.store(false);
    g_state.bw_thread_alive.store(false);
    g_state.bw_cv.notify_all();

    g_state.cap_polling.store(false);
    g_state.cap_running.store(false, std::memory_order_release);
    g_state.cap_start_pending.store(false, std::memory_order_release);
    g_state.cap_stop_pending.store(false, std::memory_order_release);
    g_state.cap_thread_alive.store(false);
    g_state.cap_cv.notify_all();

    g_state.dns_polling.store(false);
    g_state.dns_thread_alive.store(false);
    g_state.dns_cv.notify_all();

    g_state.fuzz_running.store(false);
    g_state.fuzz_thread_alive.store(false);
    g_state.fuzz_cv.notify_all();

    auto wait_done = [](const char* name, const std::atomic<bool>& done_flag) {
        const uint64_t begin = static_cast<uint64_t>(GetTickCount64());
        while (!done_flag.load(std::memory_order_acquire)) {
            const uint64_t elapsed = static_cast<uint64_t>(GetTickCount64()) - begin;
            if (elapsed >= 2500) {
                diag::log_tagged_fmt("network", "shutdown_wait_timeout worker=%s elapsed_ms=%llu",
                    name ? name : "<unnamed>",
                    static_cast<unsigned long long>(elapsed));
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        diag::log_tagged_fmt("network", "shutdown_wait_done worker=%s elapsed_ms=%llu",
            name ? name : "<unnamed>",
            static_cast<unsigned long long>(static_cast<uint64_t>(GetTickCount64()) - begin));
    };
    wait_done("conn", g_state.conn_thread_done);
    wait_done("capture", g_state.cap_thread_done);
    wait_done("dns", g_state.dns_thread_done);
    wait_done("bandwidth", g_state.bw_thread_done);
    wait_done("fuzzer", g_state.fuzz_thread_done);

    aida::burp::shutdown();

    mitm_proxy::stop();
    ssl_keylog::stop_watching();
    g_state.active = false;
    diag::log_tagged("network", "shutdown_complete");
}


static const char* tab_names[] = {
    "Connections", "Capture", "Intercept", "Proxy",
    "DNS", "Filters", "Bandwidth", "Repeater", "KeyLog",
    "PCAP", "Fuzzer", "Offensive", "WebSocket", "Scripting", "Decoder",
    "Site Map", "Scope", "Cookies", "Scanner", "Recon",
    "Intruder", "Collaborator", "Sequencer", "Comparer",
    "JWT Lab", "Match/Replace", "Session", "API",
    "WS Editor", "H/2 Editor", "Logger", "CSP",
    "Upstream", "Browser", "Reports", "Headless"
};

static const char* tab_short_names[] = {
    "Conn", "Cap", "Int", "Prx",
    "DNS", "Filt", "BW", "Rep", "KL",
    "PCAP", "Fuz", "Off", "WS", "Scr", "Dec",
    "Site", "Scope", "Cook", "Scan", "Recon",
    "Intr", "Collab", "Seq", "Cmp",
    "JWT", "M/R", "Sess", "API",
    "WSe", "H2e", "Log", "CSP",
    "Up", "Brw", "Rpt", "HL"
};

static const sub_tab_t k_monitor_tabs[] = {
    sub_tab_t::connections,
    sub_tab_t::capture,
    sub_tab_t::dns,
    sub_tab_t::filters,
    sub_tab_t::bandwidth,
    sub_tab_t::keylog,
    sub_tab_t::pcap_export
};

static const sub_tab_t k_proxy_tabs[] = {
    sub_tab_t::proxy,
    sub_tab_t::intercept,
    sub_tab_t::repeater,
    sub_tab_t::logger,
    sub_tab_t::scope,
    sub_tab_t::cookies,
    sub_tab_t::upstream
};

static const sub_tab_t k_web_tabs[] = {
    sub_tab_t::browser,
    sub_tab_t::headless,
    sub_tab_t::sitemap,
    sub_tab_t::recon,
    sub_tab_t::scanner,
    sub_tab_t::reports,
    sub_tab_t::csp
};

static const sub_tab_t k_api_tabs[] = {
    sub_tab_t::api
};

static const sub_tab_t k_attack_tabs[] = {
    sub_tab_t::intruder,
    sub_tab_t::fuzzer,
    sub_tab_t::offensive,
    sub_tab_t::jwt,
    sub_tab_t::mr,
    sub_tab_t::session,
    sub_tab_t::collab,
    sub_tab_t::sequencer,
    sub_tab_t::comparer
};

static const sub_tab_t k_protocol_tabs[] = {
    sub_tab_t::websocket,
    sub_tab_t::ws_edit,
    sub_tab_t::h2_edit,
    sub_tab_t::decoder
};

static const sub_tab_t k_automation_tabs[] = {
    sub_tab_t::scripting
};

struct nav_group_t {
    const char* label;
    const char* short_label;
    const char* status;
    const sub_tab_t* tabs;
    int tab_count;
};

static const nav_group_t k_nav_groups[] = {
    { "Monitor", "Mon", "Driver capture and packet evidence", k_monitor_tabs, static_cast<int>(sizeof(k_monitor_tabs) / sizeof(k_monitor_tabs[0])) },
    { "Proxy", "Proxy", "MITM, intercept, replay, logs, and scope", k_proxy_tabs, static_cast<int>(sizeof(k_proxy_tabs) / sizeof(k_proxy_tabs[0])) },
    { "Web", "Web", "Camoufox-only browser automation and web scans", k_web_tabs, static_cast<int>(sizeof(k_web_tabs) / sizeof(k_web_tabs[0])) },
    { "API", "API", "API request workbench", k_api_tabs, static_cast<int>(sizeof(k_api_tabs) / sizeof(k_api_tabs[0])) },
    { "Attack", "Attack", "Fuzzing, sessions, tokens, and comparison tools", k_attack_tabs, static_cast<int>(sizeof(k_attack_tabs) / sizeof(k_attack_tabs[0])) },
    { "Protocol", "Proto", "WebSocket, HTTP/2, and decoding tools", k_protocol_tabs, static_cast<int>(sizeof(k_protocol_tabs) / sizeof(k_protocol_tabs[0])) },
    { "Automation", "Auto", "Network scripting and workflow automation", k_automation_tabs, static_cast<int>(sizeof(k_automation_tabs) / sizeof(k_automation_tabs[0])) }
};

static int nav_group_count() {
    return static_cast<int>(sizeof(k_nav_groups) / sizeof(k_nav_groups[0]));
}

static int nav_group_for_tab(sub_tab_t tab) {
    for (int g = 0; g < nav_group_count(); ++g) {
        const nav_group_t& group = k_nav_groups[g];
        for (int i = 0; i < group.tab_count; ++i) {
            if (group.tabs[i] == tab) return g;
        }
    }
    return 0;
}

static int tab_index_in_group(const nav_group_t& group, sub_tab_t tab) {
    for (int i = 0; i < group.tab_count; ++i) {
        if (group.tabs[i] == tab) return i;
    }
    return 0;
}

static bool tab_requires_target(sub_tab_t tab) {
    switch (tab) {
        case sub_tab_t::connections:
        case sub_tab_t::capture:
        case sub_tab_t::dns:
        case sub_tab_t::filters:
        case sub_tab_t::bandwidth:
        case sub_tab_t::keylog:
        case sub_tab_t::pcap_export:
            return true;
        default:
            return false;
    }
}

static float estimate_chip_w(const char* label, float pad) {
    return ImGui::CalcTextSize(label ? label : "").x + pad;
}

static bool same_line_if_fits(float next_w, float spacing = 8.f) {
    if (ImGui::GetContentRegionAvail().x >= next_w + spacing) {
        ImGui::SameLine(0.f, spacing);
        return true;
    }
    return false;
}

static void clipped_text(const char* text, ImU32 color, float max_w = 0.f) {
    const char* safe = text ? text : "";
    bool clipped = max_w > 0.f && ImGui::CalcTextSize(safe).x > max_w;
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(color));
    ImGui::TextUnformatted(safe);
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered() && clipped) {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted(safe);
        ImGui::EndTooltip();
    }
}

static void table_text(const std::string& text, ImU32 color) {
    clipped_text(text.c_str(), color, ImGui::GetContentRegionAvail().x);
}

static void table_text(const char* text, ImU32 color) {
    clipped_text(text ? text : "", color, ImGui::GetContentRegionAvail().x);
}

static std::string payload_display_text(const std::vector<uint8_t>& bytes, size_t cap = 262144) {
    std::string out;
    size_t n = std::min(bytes.size(), cap);
    out.reserve(n + 64);
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = bytes[i];
        if (b == '\r' || b == '\n' || b == '\t' || (b >= 32 && b < 127))
            out.push_back(static_cast<char>(b));
        else
            out.push_back('.');
    }
    if (bytes.size() > n) {
        out += "\n[truncated ";
        out += std::to_string(bytes.size() - n);
        out += " bytes]";
    }
    return out;
}

static void render_payload_box(const char* id, const char* title, const std::string& meta,
                               const std::string& text, ImVec2 size,
                               const aida::ui::theme_t& th, float alpha) {
    ImGui::BeginChild(id, size, true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)));
    ImGui::TextUnformatted(title ? title : "");
    ImGui::PopStyleColor();
    if (!meta.empty()) {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)));
        ImGui::TextUnformatted(meta.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy")) {
        ImGui::SetClipboardText(text.c_str());
    }
    ImGui::Separator();
    ImFont* code_font = aida::ui::fonts::code();
    bool pushed = false;
    if (code_font) {
        ImGui::PushFont(code_font);
        pushed = true;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)));
    ImGui::TextUnformatted(text.empty() ? "(empty)" : text.c_str());
    ImGui::PopStyleColor();
    if (pushed)
        ImGui::PopFont();
    ImGui::EndChild();
}

static float render_no_target_banner(float x, float y, float w, float alpha) {
    const auto& th = aida::ui::resolved();
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 a(wp.x + x, wp.y + y);
    ImVec2 b(wp.x + x + w, wp.y + y + 34.f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(a, b, aida::ui::with_alpha(th.warning_soft, alpha * 2.4f), 6.f);
    dl->AddRect(a, b, aida::ui::with_alpha(th.warning, alpha * 0.55f), 6.f, 0, 1.f);
    dl->PushClipRect(a, b, true);
    dl->AddText(ImVec2(a.x + 10.f, a.y + 8.f), aida::ui::with_alpha(th.warning, alpha), "No target attached");
    const char* msg = w < 620.f
        ? "Driver capture disabled; web, proxy, API, protocol, and Camoufox prep remain available."
        : "Driver capture and native process diagnostics are disabled; web, proxy, API, protocol, and Camoufox prep tools remain available.";
    dl->AddText(ImVec2(a.x + 140.f, a.y + 8.f), aida::ui::with_alpha(th.text_secondary, alpha), msg);
    dl->PopClipRect();
    return 40.f;
}

static float render_tab_bar(state_t& state, float x, float y, float w, float alpha,
                            float ar, float ag, float ab, float dt) {
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();

    const float primary_h = 32.f;
    const float secondary_h = 30.f;
    const float gap_h = 4.f;
    const float nav_h = primary_h + secondary_h + gap_h;
    const int group_count = nav_group_count();
    const int active_group_idx = nav_group_for_tab(state.active_tab);
    const nav_group_t& active_group = k_nav_groups[active_group_idx];

    float nav_x0 = origin.x + x;
    float nav_x1 = origin.x + x + w;
    float nav_y0 = origin.y + y;
    float nav_y1 = origin.y + y + primary_h;
    float second_y0 = nav_y1 + gap_h;
    float second_y1 = second_y0 + secondary_h;

    ui_anim::render_gradient_header(dl, nav_x0, nav_y0, w, primary_h, ar, ag, ab, alpha * 0.65f);
    dl->AddRectFilled(ImVec2(nav_x0, nav_y0), ImVec2(nav_x1, nav_y1),
                      aida::ui::with_alpha(th.panel_header, alpha * 0.55f));

    float primary_total = 0.f;
    float primary_full[16] = {};
    float primary_short[16] = {};
    for (int i = 0; i < group_count; ++i) {
        primary_full[i] = std::max(64.f, ImGui::CalcTextSize(k_nav_groups[i].label).x + 26.f);
        primary_short[i] = std::max(44.f, ImGui::CalcTextSize(k_nav_groups[i].short_label).x + 20.f);
        primary_total += primary_full[i];
    }
    const bool primary_equal = primary_total > w;
    const bool primary_short_labels = primary_equal || w < 720.f;
    float gx = nav_x0;
    static aida::ui::hover_state_t s_group_hover[16];
    static aida::ui::press_state_t s_group_press[16];
    for (int i = 0; i < group_count; ++i) {
        float gw = primary_equal ? w / static_cast<float>(group_count)
                                 : primary_full[i];
        if (i == group_count - 1)
            gw = nav_x1 - gx;
        bool active = i == active_group_idx;
        ImVec2 a(gx, nav_y0 + 3.f);
        ImVec2 b(gx + gw - 2.f, nav_y1 - 3.f);
        ImGui::SetCursorScreenPos(a);
        ImGui::PushID(0x4E475250 + i);
        ImGui::InvisibleButton("##network_group", ImVec2(std::max(1.f, b.x - a.x), std::max(1.f, b.y - a.y)));
        bool hovered = ImGui::IsItemHovered();
        bool pressed = hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            sub_tab_t next_tab = k_nav_groups[i].tabs[0];
            if (state.active_tab != next_tab) {
                state.prev_tab = state.active_tab;
                state.content_fade = 0.f;
            }
            state.active_tab = next_tab;
        }
        ImGui::PopID();

        float hv = s_group_hover[i].tick(hovered, dt, aida::motion::spring::balanced);
        float pv = s_group_press[i].tick(pressed, dt);
        if (active) {
            dl->AddRectFilled(a, b, aida::ui::with_alpha(th.selection, alpha), 7.f);
            dl->AddRect(a, b, aida::ui::with_alpha(th.accent_u32, alpha * 0.55f), 7.f, 0, 1.f);
        } else if (hv > 0.001f) {
            dl->AddRectFilled(a, b, aida::ui::with_alpha(th.hover_wash, alpha * hv), 7.f);
        }
        const char* label = primary_short_labels ? k_nav_groups[i].short_label : k_nav_groups[i].label;
        ImVec2 ts = ImGui::CalcTextSize(label);
        ImU32 text_col = active
            ? aida::ui::with_alpha(th.text_primary, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha * (0.70f + 0.25f * hv));
        ImVec2 ta(a.x + std::max(8.f, (gw - ts.x) * 0.5f), a.y + (b.y - a.y - ts.y) * 0.5f - pv * 0.5f);
        dl->PushClipRect(a, b, true);
        dl->AddText(ta, text_col, label);
        dl->PopClipRect();
        if (hovered) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(k_nav_groups[i].label);
            ImGui::TextUnformatted(k_nav_groups[i].status);
            ImGui::EndTooltip();
        }
        gx += gw;
    }

    if (w >= 760.f) {
        const char* status = active_group.status;
        ImVec2 ss = ImGui::CalcTextSize(status);
        float sx = nav_x1 - ss.x - 12.f;
        if (sx > nav_x0 + primary_total + 16.f) {
            dl->AddText(ImVec2(sx, nav_y0 + (primary_h - ss.y) * 0.5f),
                        aida::ui::with_alpha(th.text_dim, alpha), status);
        }
    }
    dl->AddLine(ImVec2(nav_x0, nav_y1), ImVec2(nav_x1, nav_y1),
                aida::ui::with_alpha(th.border_subtle, alpha));

    dl->AddRectFilled(ImVec2(nav_x0, second_y0), ImVec2(nav_x1, second_y1),
                      aida::ui::with_alpha(th.panel_bg, alpha * 0.55f));

    const int count = active_group.tab_count;
    float total_w = 0.f;
    float tab_widths[static_cast<int>(sub_tab_t::COUNT)];
    float tab_offsets[static_cast<int>(sub_tab_t::COUNT)];
    for (int i = 0; i < count; i++) {
        int tab_idx = static_cast<int>(active_group.tabs[i]);
        const char* full = tab_names[tab_idx];
        const char* short_name = tab_short_names[tab_idx];
        bool use_short_preview = (w < 520.f);
        const char* lbl = use_short_preview ? short_name : full;
        tab_widths[i] = ImGui::CalcTextSize(lbl).x + (use_short_preview ? 18.f : 22.f);
        tab_offsets[i] = total_w;
        total_w += tab_widths[i] + 2.f;
    }

    float view_x0 = nav_x0;
    float view_x1 = nav_x1;
    if (total_w > w) {
        view_x0 += 28.f;
        view_x1 -= 28.f;
    }
    float view_w = std::max(1.f, view_x1 - view_x0);

    static int s_last_group_idx = -1;
    if (s_last_group_idx != active_group_idx) {
        state.tab_scroll_x = 0.f;
        state.tab_target_scroll_x = 0.f;
        state.tab_last_ensured = -1;
        s_last_group_idx = active_group_idx;
    }

    if (ImGui::IsMouseHoveringRect(ImVec2(view_x0, second_y0), ImVec2(view_x1, second_y1), false)) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            state.tab_target_scroll_x -= wheel * 60.f;
    }

    float max_scroll = std::max(0.f, total_w - view_w);
    state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
    state.tab_scroll_x = ui_anim::smooth_lerp(state.tab_scroll_x, state.tab_target_scroll_x, 14.f, dt);

    int active_idx = tab_index_in_group(active_group, state.active_tab);
    int active_tab_int = static_cast<int>(state.active_tab);
    if (state.tab_last_ensured != active_tab_int) {
        float active_left = tab_offsets[active_idx] - state.tab_scroll_x;
        float active_right = active_left + tab_widths[active_idx];
        if (active_left < 0.f)
            state.tab_target_scroll_x = tab_offsets[active_idx];
        else if (active_right > view_w)
            state.tab_target_scroll_x = tab_offsets[active_idx] + tab_widths[active_idx] - view_w;
        state.tab_target_scroll_x = std::clamp(state.tab_target_scroll_x, 0.f, max_scroll);
        state.tab_last_ensured = active_tab_int;
    }

    float target_ux = view_x0 + tab_offsets[active_idx] - state.tab_scroll_x + 6.f;
    float target_uw = tab_widths[active_idx] - 12.f;
    if (state.underline_w < 0.1f) {
        state.underline_x = target_ux;
        state.underline_w = target_uw;
    }
    state.underline_x = ui_anim::spring_interp(state.underline_x, target_ux, state.underline_vel, 280.f, 22.f, dt);
    state.underline_w = ui_anim::smooth_lerp(state.underline_w, target_uw, 16.f, dt);

    ImGui::PushClipRect(ImVec2(view_x0, second_y0), ImVec2(view_x1, second_y1), true);

    static aida::ui::hover_state_t s_tab_hover[static_cast<int>(sub_tab_t::COUNT)];
    static aida::ui::press_state_t s_tab_press[static_cast<int>(sub_tab_t::COUNT)];

    for (int i = 0; i < count; i++) {
        int tab_idx = static_cast<int>(active_group.tabs[i]);
        float bx0 = view_x0 + tab_offsets[i] - state.tab_scroll_x;
        float bx1 = bx0 + tab_widths[i];
        float by0 = second_y0;
        float by1 = second_y1;
        bool is_active = active_group.tabs[i] == state.active_tab;

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= bx0 && mouse.x < bx1 && mouse.y >= by0 && mouse.y < by1);
        bool pressed = hovered && ImGui::IsMouseDown(ImGuiMouseButton_Left);
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            if (state.active_tab != active_group.tabs[i]) {
                state.prev_tab = state.active_tab;
                state.content_fade = 0.f;
            }
            state.active_tab = active_group.tabs[i];
        }

        float hov_v = s_tab_hover[tab_idx].tick(hovered, dt, aida::motion::spring::balanced);
        float prs_v = s_tab_press[tab_idx].tick(pressed, dt);
        float scale = 1.f - (1.f - 0.96f) * prs_v;
        float pad_x = (1.f - scale) * tab_widths[i] * 0.5f;
        float pad_y = (1.f - scale) * secondary_h * 0.5f;

        if (is_active) {
            ImU32 fill_top = aida::ui::with_alpha(th.accent_grad_top, 0.22f * alpha);
            ImU32 fill_bot = aida::ui::with_alpha(th.accent_grad_bot, 0.16f * alpha);
            dl->AddRectFilledMultiColor(
                ImVec2(bx0 + pad_x + 4.f, by0 + pad_y + 4.f),
                ImVec2(bx1 - pad_x - 4.f, by1 - pad_y - 4.f),
                fill_top, fill_top, fill_bot, fill_bot);
        } else if (hov_v > 0.001f) {
            dl->AddRectFilled(
                ImVec2(bx0 + pad_x + 4.f, by0 + pad_y + 4.f),
                ImVec2(bx1 - pad_x - 4.f, by1 - pad_y - 4.f),
                aida::ui::with_alpha(th.hover_wash, hov_v * alpha), 8.f);
        }

        bool use_short = (w < 520.f);
        const char* draw_label = use_short ? tab_short_names[tab_idx] : tab_names[tab_idx];
        ImVec2 ts = ImGui::CalcTextSize(draw_label);
        ImU32 text_col = is_active
            ? aida::ui::with_alpha(th.text_primary, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha * (0.65f + 0.30f * hov_v));
        dl->AddText(ImVec2(bx0 + (tab_widths[i] - ts.x) * 0.5f, by0 + (secondary_h - ts.y) * 0.5f - prs_v * 0.5f),
            text_col, draw_label);

        if (use_short && hovered) {
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f, 6.f));
            ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(th.bg_overlay));
            if (ImGui::BeginTooltip()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
                ImGui::TextUnformatted(tab_names[tab_idx]);
                ImGui::PopStyleColor();
                ImGui::EndTooltip();
            }
            ImGui::PopStyleColor();
            ImGui::PopStyleVar();
        }
    }

    ui_anim::render_tab_underline_glow(dl, state.underline_x, state.underline_w,
        second_y1 - 3.f, alpha);

    ImGui::PopClipRect();

    if (state.tab_scroll_x > 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(view_x0, second_y0), ImVec2(view_x0 + 30.f, second_y1),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f));
    }
    if (state.tab_scroll_x < max_scroll - 1.f) {
        dl->AddRectFilledMultiColor(
            ImVec2(view_x1 - 30.f, second_y0), ImVec2(view_x1, second_y1),
            aida::ui::with_alpha(th.bg_base, 0.f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, alpha * 0.94f),
            aida::ui::with_alpha(th.bg_base, 0.f));
    }

    if (max_scroll > 1.f) {
        ImGui::SetCursorScreenPos(ImVec2(nav_x0 + 2.f, second_y0 + 2.f));
        ImGui::PushID("net_tabs_left");
        ImGui::BeginDisabled(state.tab_target_scroll_x <= 1.f);
        if (ImGui::InvisibleButton("##left", ImVec2(22.f, secondary_h - 4.f)))
            state.tab_target_scroll_x = std::max(0.f, state.tab_target_scroll_x - view_w * 0.6f);
        ImGui::EndDisabled();
        ImGui::PopID();
        dl->AddText(ImVec2(nav_x0 + 10.f, second_y0 + 7.f),
                    aida::ui::with_alpha(state.tab_target_scroll_x <= 1.f ? th.text_dim : th.text_secondary, alpha), "<");

        ImGui::SetCursorScreenPos(ImVec2(nav_x1 - 24.f, second_y0 + 2.f));
        ImGui::PushID("net_tabs_right");
        ImGui::BeginDisabled(state.tab_target_scroll_x >= max_scroll - 1.f);
        if (ImGui::InvisibleButton("##right", ImVec2(22.f, secondary_h - 4.f)))
            state.tab_target_scroll_x = std::min(max_scroll, state.tab_target_scroll_x + view_w * 0.6f);
        ImGui::EndDisabled();
        ImGui::PopID();
        dl->AddText(ImVec2(nav_x1 - 16.f, second_y0 + 7.f),
                    aida::ui::with_alpha(state.tab_target_scroll_x >= max_scroll - 1.f ? th.text_dim : th.text_secondary, alpha), ">");
    }

    dl->AddLine(
        ImVec2(origin.x + x, second_y1),
        ImVec2(origin.x + x + w, second_y1),
        aida::ui::with_alpha(th.border_subtle, alpha));

    return nav_h;
}


static void render_connections(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_conn", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();

    float conn_toolbar_avail = ImGui::GetContentRegionAvail().x;
    bool conn_toolbar_narrow = (conn_toolbar_avail < 560.f);
    float search_w = conn_toolbar_narrow
        ? (std::max)(conn_toolbar_avail - 240.f, 140.f)
        : 280.f;
    aida::ui::input_text("##conn_search", state.conn_filter_text, sizeof(state.conn_filter_text),
                          "Filter by PID, host, port...", false, ImVec2(search_w, 32.f));
    if (conn_toolbar_narrow && conn_toolbar_avail < 360.f) {
        static bool s_logged_conn_narrow = false;
        if (!s_logged_conn_narrow) {
            s_logged_conn_narrow = true;
            ::diag::log_tagged_fmt("responsive",
                "network_view connections toolbar avail=%.0f wrap=1", conn_toolbar_avail);
        }
    }
    ImGui::SameLine();
    if (!driver_ok) ImGui::BeginDisabled();
    bool prev_auto = state.conn_auto_refresh;
    aida::ui::toggle_switch("Auto refresh##conn_auto", &state.conn_auto_refresh);
    state.conn_auto_refresh_enabled.store(state.conn_auto_refresh, std::memory_order_release);
    if (prev_auto != state.conn_auto_refresh) {
        diag::log_tagged_fmt("network", "connections_auto_refresh_toggled enabled=%d",
            state.conn_auto_refresh ? 1 : 0);
        state.conn_cv.notify_all();
    }
    ImGui::SameLine();
    if (aida::ui::button("Refresh##conn_refresh", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        diag::log_tagged_fmt("network", "connections_refresh_clicked drv_ok=%d filter_pid=%u filter_proto=%u",
            driver_ok ? 1 : 0, state.conn_filter_pid, state.conn_filter_protocol);
        if (driver_ok) {
            auto raw = driver_bridge::enumerate_connections(state.conn_filter_pid, state.conn_filter_protocol);
            size_t n = raw.size();
            std::lock_guard<std::mutex> lock(state.conn_mutex);
            state.connections.clear();
            for (auto& c : raw) {
                connection_entry_t e;
                e.pid = c.pid;
                e.protocol = c.protocol;
                e.state = c.state;
                e.local_port = c.local_port;
                e.remote_port = c.remote_port;
                e.address_family = c.address_family;
                memcpy(e.local_addr, c.local_addr, 16);
                memcpy(e.remote_addr, c.remote_addr, 16);
                state.connections.push_back(std::move(e));
            }
            diag::log_tagged_fmt("network", "connections_refresh_done count=%zu", n);
        }
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    size_t conn_count = 0;
    {
        std::lock_guard<std::mutex> lock(state.conn_mutex);
        conn_count = state.connections.size();
    }
    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%zu connections", conn_count);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "%s", count_buf);

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;


    float col_pid = 64.f, col_proto = 50.f, col_state = 110.f;
    float remain_w = w - col_pid - col_proto - col_state - 24.f;
    if (remain_w < 120.f) {
        if (w < 280.f) {
            col_proto = 40.f;
            col_state = 70.f;
        }
        remain_w = w - col_pid - col_proto - col_state - 24.f;
        if (remain_w < 80.f) remain_w = 80.f;
    }
    float col_local = remain_w * 0.5f;
    float col_remote = col_local;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");    cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Proto");  cx += col_proto;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "State");  cx += col_state;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Local");  cx += col_local;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Remote");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);


    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##conn_list", ImVec2(w - 4.f, list_h), false,
                      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_AlwaysVerticalScrollbar);

    std::lock_guard<std::mutex> lock(state.conn_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);
    int conn_visible_row = 0;

    if (state.connections.empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        ImGui::SetCursorPos(ImVec2(x, ImGui::GetCursorPos().y - list_h));
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No active connections";
        cfg.body  = driver_ok
            ? "Connections will appear once the kernel driver enumerates them."
            : "Kernel driver not attached. Some features are unavailable.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    for (int i = 0; i < static_cast<int>(state.connections.size()); i++) {
        auto& c = state.connections[static_cast<size_t>(i)];

        if (c.pid == 0 && c.protocol == 0 && c.local_port == 0 && c.remote_port == 0)
            continue;

        std::string local_str = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        std::string remote_str = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);


        if (state.conn_filter_text[0]) {
            std::string all = std::to_string(c.pid) + " " + protocol_name(c.protocol) + " " +
                tcp_state_name(c.state) + " " + local_str + " " + remote_str;
            if (!filter_text_match(state.conn_filter_text, all)) continue;
        }

        float row_alpha = 1.f;
        float row_xoff = 0.f;
        compute_row_entrance(s_conn_rows, state.connections.size(), row_alpha, row_xoff, i);
        float r_alpha = alpha * row_alpha;

        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;

        if (conn_visible_row & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.35f));

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.conn_selected == i);

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, r_alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 2.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_dim, r_alpha));
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.conn_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);

        cx = list_org.x + 8.f + row_xoff;
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%u", c.pid);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, pid_buf);                            cx += col_pid;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, protocol_name(c.protocol));          cx += col_proto;


        aida::ui::pill_kind_t state_kind = tcp_state_to_pill(c.state);
        ImU32 pill_col;
        switch (state_kind) {
            case aida::ui::pill_kind_t::success: pill_col = th.success; break;
            case aida::ui::pill_kind_t::warning: pill_col = th.warning; break;
            case aida::ui::pill_kind_t::error:   pill_col = th.error;   break;
            case aida::ui::pill_kind_t::info:    pill_col = th.info;    break;
            case aida::ui::pill_kind_t::accent:  pill_col = th.accent_u32; break;
            default:                              pill_col = th.text_secondary; break;
        }
        const char* sname = tcp_state_name(c.state);
        ImFont* pill_font = ImGui::GetFont();
        float pill_fs = ImGui::GetFontSize() - 2.f;
        ImVec2 ts = pill_font->CalcTextSizeA(pill_fs, FLT_MAX, 0.f, sname);
        float pill_pad = 7.f;
        float pill_h = pill_fs + 4.f;
        float pill_w = ts.x + pill_pad * 2.f;
        float pill_x = cx;
        float pill_y = abs_ry + (row_h - pill_h) * 0.5f;
        dl->AddRectFilled(ImVec2(pill_x, pill_y), ImVec2(pill_x + pill_w, pill_y + pill_h),
                          aida::ui::with_alpha(pill_col, 0.20f * r_alpha), pill_h * 0.5f);
        dl->AddRect(ImVec2(pill_x, pill_y), ImVec2(pill_x + pill_w, pill_y + pill_h),
                     aida::ui::with_alpha(pill_col, 0.55f * r_alpha), pill_h * 0.5f, 0, 1.f);
        dl->AddText(pill_font, pill_fs, ImVec2(pill_x + pill_pad, pill_y + (pill_h - pill_fs) * 0.5f),
                     aida::ui::with_alpha(pill_col, r_alpha), sname);
        cx += col_state;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, local_str.c_str());                  cx += col_local;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, remote_str.c_str());

        conn_visible_row++;
        ImGui::SetCursorPosY(ry + row_h);
    }

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void request_capture_start(state_t& state) {
    bool expected = false;
    if (!state.cap_start_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged("network", "start_capture_ignored_already_pending");
        return;
    }
    set_capture_control_status("Starting capture...");
    uint32_t filter_pid = state.cap_filter_pid;
    uint32_t filter_port = static_cast<uint32_t>(state.cap_filter_port);
    uint32_t filter_protocol = state.cap_filter_protocol;
    bool driver_ok = driver_feature_ready("start_capture");
    if (!driver_ok) {
        set_capture_control_status("Capture unavailable until AiDA is authorized");
        state.cap_start_pending.store(false, std::memory_order_release);
        return;
    }
    bool poll_ready = start_capture_worker(state);
    diag::log_tagged_fmt("network",
        "start_capture_requested filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d poll_ready=%d cap_thread_done=%d cap_thread_alive=%d",
        filter_pid, filter_port, filter_protocol,
        driver_ok ? 1 : 0,
        poll_ready ? 1 : 0,
        state.cap_thread_done.load(std::memory_order_acquire) ? 1 : 0,
        state.cap_thread_alive.load(std::memory_order_acquire) ? 1 : 0);
    if (!poll_ready) {
        set_capture_control_status("Capture worker unavailable");
        state.cap_start_pending.store(false, std::memory_order_release);
        return;
    }

    if (!post_network_task("capture_start_control", aida::infra::executor::domain_t::feature_worker, "bounded_task", [filter_pid, filter_port, filter_protocol]() {
            ULONGLONG t0 = GetTickCount64();
            bool ok = false;
            try {
                ok = driver_feature_ready("start_capture_async") &&
                     driver_bridge::start_capture(filter_pid, filter_port, filter_protocol, nullptr);
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "start_capture_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "start_capture_unknown_exception");
            }
            ULONGLONG elapsed = GetTickCount64() - t0;
            if (ok) {
                g_state.cap_running.store(true, std::memory_order_release);
                g_state.cap_polling.store(true, std::memory_order_release);
                g_state.cap_cv.notify_all();
                set_capture_control_status("Capture running");
                diag::log_tagged_fmt("network", "start_capture_ok async elapsed_ms=%llu poll_thread_signaled=%d",
                    static_cast<unsigned long long>(elapsed),
                    g_state.cap_thread_alive.load(std::memory_order_acquire) ? 1 : 0);
                anti_tamper::webhook::write_log("net_audit",
                    "[net_audit] capture started ok");
            } else {
                set_capture_control_status("Capture start failed");
                diag::log_tagged_fmt("network", "start_capture_failed async elapsed_ms=%llu kernel_mode=%d",
                    static_cast<unsigned long long>(elapsed),
                    driver_bridge::using_kernel_driver() ? 1 : 0);
                anti_tamper::webhook::write_log("net_audit",
                    "[net_audit] capture start FAILED driver call returned false");
            }
            g_state.cap_start_pending.store(false, std::memory_order_release);
        })) {
        set_capture_control_status("Capture start queue failed");
        state.cap_start_pending.store(false, std::memory_order_release);
    }
}

static void request_capture_stop(state_t& state) {
    bool expected = false;
    if (!state.cap_stop_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        diag::log_tagged("network", "stop_capture_ignored_already_pending");
        return;
    }
    set_capture_control_status("Stopping capture...");
    diag::log_tagged("network", "stop_capture_requested");
    if (!post_network_task("capture_stop_control", aida::infra::executor::domain_t::feature_worker, "bounded_task", []() {
            ULONGLONG t0 = GetTickCount64();
            bool ok = false;
            try {
                ok = driver_bridge::stop_capture();
            } catch (const std::exception& e) {
                diag::log_tagged_fmt("network", "stop_capture_cpp_exception what=%s", e.what());
            } catch (...) {
                diag::log_tagged("network", "stop_capture_unknown_exception");
            }
            ULONGLONG elapsed = GetTickCount64() - t0;
            g_state.cap_running.store(false, std::memory_order_release);
            g_state.cap_polling.store(false, std::memory_order_release);
            set_capture_control_status(ok ? "Capture stopped" : "Capture stop failed");
            diag::log_tagged_fmt("network", "stop_capture_complete ok=%d elapsed_ms=%llu",
                ok ? 1 : 0,
                static_cast<unsigned long long>(elapsed));
            anti_tamper::webhook::write_log("net_audit",
                ok ? "[net_audit] capture stopped by user" : "[net_audit] capture stop FAILED driver call returned false");
            g_state.cap_stop_pending.store(false, std::memory_order_release);
        })) {
        set_capture_control_status("Capture stop queue failed");
        state.cap_stop_pending.store(false, std::memory_order_release);
    }
}


static void render_capture(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_cap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_feature_ready("bandwidth");
    bool cap_running = state.cap_running.load(std::memory_order_acquire);
    bool cap_start_pending = state.cap_start_pending.load(std::memory_order_acquire);
    bool cap_stop_pending = state.cap_stop_pending.load(std::memory_order_acquire);

    size_t pkt_count = 0;
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        pkt_count = state.captured_packets.size();
    }
    float live_rate = capture_rate_tick(pkt_count);


    {
        ImDrawList* hdr_dl = ImGui::GetWindowDrawList();
        ImVec2 dpos = ImGui::GetCursorScreenPos();
        float bx = dpos.x;
        float by = dpos.y + 4.f;
        float bh = 24.f;

        char live_buf[64];
        if (cap_running) {
            snprintf(live_buf, sizeof(live_buf), "LIVE  -  %.1f pkt/s", live_rate);
        } else if (cap_start_pending || cap_stop_pending) {
            snprintf(live_buf, sizeof(live_buf), "%s", cap_start_pending ? "STARTING" : "STOPPING");
        } else {
            snprintf(live_buf, sizeof(live_buf), "PAUSED");
        }
        float text_w = ImGui::CalcTextSize(live_buf).x;
        float dot_d = 18.f;
        float pad_x = 10.f;
        float bw = dot_d + text_w + pad_x * 2.f + 4.f;

        ImU32 fill_col = cap_running
            ? aida::ui::with_alpha(th.error, 0.18f * alpha)
            : aida::ui::with_alpha(th.text_dim, 0.18f * alpha);
        ImU32 border_col = cap_running
            ? aida::ui::with_alpha(th.error, 0.55f * alpha)
            : aida::ui::with_alpha(th.text_dim, 0.55f * alpha);
        hdr_dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh), fill_col, bh * 0.5f);
        hdr_dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh), border_col, bh * 0.5f, 0, 1.f);

        if (cap_running) {
            float pulse = aida::ui::clock::pulse(0.8f, 0.45f, 1.0f);
            ImU32 dot_col = aida::ui::with_alpha(th.error, alpha);
            ImU32 halo_col = aida::ui::with_alpha(th.error, alpha * 0.35f * pulse);
            hdr_dl->AddCircleFilled(ImVec2(bx + pad_x + 5.f, by + bh * 0.5f), 6.f, halo_col, 18);
            hdr_dl->AddCircleFilled(ImVec2(bx + pad_x + 5.f, by + bh * 0.5f), 4.f, dot_col, 16);
        } else {
            ImU32 dot_col = aida::ui::with_alpha(th.text_dim, alpha);
            hdr_dl->AddCircleFilled(ImVec2(bx + pad_x + 5.f, by + bh * 0.5f), 4.f, dot_col, 16);
        }
        ImU32 text_col = cap_running
            ? aida::ui::with_alpha(th.error, alpha)
            : aida::ui::with_alpha(th.text_secondary, alpha);
        hdr_dl->AddText(ImVec2(bx + pad_x + dot_d, by + (bh - ImGui::GetTextLineHeight()) * 0.5f),
                        text_col, live_buf);

        ImGui::Dummy(ImVec2(bw + 8.f, bh + 4.f));
        ImGui::SameLine();
    }

    if (!driver_ok) ImGui::BeginDisabled();

    if (cap_start_pending || cap_stop_pending)
        ImGui::BeginDisabled();

    if (!cap_running) {
        if (aida::ui::button("Start Capture", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "start_capture_clicked filter_pid=%u filter_port=%u filter_proto=%u drv_ok=%d",
                state.cap_filter_pid, state.cap_filter_port, state.cap_filter_protocol,
                driver_bridge::using_kernel_driver() ? 1 : 0);
            request_capture_start(state);
        }
    } else {
        if (aida::ui::button("Stop Capture", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged("network", "stop_capture_clicked");
            request_capture_stop(state);
        }
    }

    if (cap_start_pending || cap_stop_pending)
        ImGui::EndDisabled();

    if (!driver_ok) ImGui::EndDisabled();

    std::string capture_status = capture_control_status();
    if (!capture_status.empty()) {
        ImGui::SameLine(0.f, 12.f);
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "%s", capture_status.c_str());
    }

    ImGui::SameLine(0.f, 12.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "PID:");
    ImGui::SameLine();
    {
        int pid_v = static_cast<int>(state.cap_filter_pid);
        ImGui::SetNextItemWidth(80.f);
        if (ImGui::InputInt("##cap_filter_pid", &pid_v, 0, 0, ImGuiInputTextFlags_CharsDecimal)) {
            if (pid_v < 0) pid_v = 0;
            state.cap_filter_pid = static_cast<uint32_t>(pid_v);
        }
    }
    ImGui::SameLine(0.f, 8.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Port:");
    ImGui::SameLine();
    {
        int port_v = static_cast<int>(state.cap_filter_port);
        ImGui::SetNextItemWidth(70.f);
        if (ImGui::InputInt("##cap_filter_port", &port_v, 0, 0, ImGuiInputTextFlags_CharsDecimal)) {
            if (port_v < 0) port_v = 0;
            if (port_v > 65535) port_v = 65535;
            state.cap_filter_port = static_cast<uint16_t>(port_v);
        }
    }
    ImGui::SameLine(0.f, 8.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Proto:");
    ImGui::SameLine();
    {
        const char* cap_proto_items[] = { "All", "TCP", "UDP" };
        int cap_proto_idx = state.cap_filter_protocol == 6 ? 1 :
                             state.cap_filter_protocol == 17 ? 2 : 0;
        ImGui::SetNextItemWidth(80.f);
        if (ImGui::Combo("##cap_filter_proto", &cap_proto_idx, cap_proto_items, 3)) {
            state.cap_filter_protocol = cap_proto_idx == 1 ? 6 :
                                         cap_proto_idx == 2 ? 17 : 0;
        }
    }

    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        size_t prev = state.captured_packets.size();
        state.captured_packets.clear();
        state.cap_selected = -1;
        diag::log_tagged_fmt("network", "capture_cleared prev_packet_count=%zu", prev);
    }

    {
        char count_buf[32];
        snprintf(count_buf, sizeof(count_buf), "%zu packets", pkt_count);
        float count_w = ImGui::CalcTextSize(count_buf).x;
        float row_avail = ImGui::GetContentRegionAvail().x;
        float right_pad = 12.f;
        float gap = 14.f;
        float reserved_right = count_w + right_pad + gap;
        float input_min = 200.f;
        float input_max = 640.f;
        float input_w = row_avail - reserved_right;
        if (input_w < input_min) input_w = input_min;
        if (input_w > input_max) input_w = input_max;

        ImGui::SameLine(0.f, gap);
        aida::ui::input_text("##cap_filter", state.cap_filter_text, sizeof(state.cap_filter_text),
                              "Filter packets...", false, ImVec2(input_w, 28.f));

        if (row_avail > input_w + reserved_right) {
            ImGui::SameLine();
            float row_x = ImGui::GetCursorPosX();
            ImGui::SetCursorPosX(row_x + (row_avail - input_w - count_w - right_pad - gap));
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", count_buf);
        }
    }

    ImGui::Spacing();


    float split_y = h * state.detail_ratio;
    float list_top = ImGui::GetCursorPosY();
    float list_h = split_y - list_top;
    if (list_h < 80.f) list_h = 80.f;
    float detail_h = h - split_y - 30.f;


    capture_table_snapshot_t cap_snapshot = snapshot_capture_table(state, state.cap_filter_text);

    ImGui::BeginChild("##cap_list", ImVec2(w - 4.f, list_h), false,
                      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

    if (cap_snapshot.total_count == 0) {
        ImVec2 list_org = ImGui::GetWindowPos();
        ImVec2 list_sz  = ImGui::GetWindowSize();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = cap_running ? "Waiting for packets..." : "Capture not running";
        cfg.body  = cap_running
            ? "Packets will stream in here as they are observed by the kernel driver."
            : "Press Start Capture above to begin recording network traffic.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, list_h));
        ImGui::EndChild();
        ImGui::EndChild();
        return;
    }

    if (cap_snapshot.rows.empty()) {
        ImVec2 list_org = ImGui::GetWindowPos();
        ImVec2 list_sz  = ImGui::GetWindowSize();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No packets match filter";
        cfg.body  = "Captured packets remain buffered; clear the text filter to show them again.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, list_h));
    } else {

        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8.f, 7.f));
        ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, aida::ui::with_alpha(th.panel_header, alpha));
        ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, aida::ui::with_alpha(th.hover_wash, alpha * 0.35f));
        ImGui::PushStyleColor(ImGuiCol_TableBorderLight, aida::ui::with_alpha(th.border_subtle, alpha));

        ImGuiTableFlags table_flags =
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Reorderable |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV |
            ImGuiTableFlags_NoSavedSettings |
            ImGuiTableFlags_SizingStretchProp |
            ImGuiTableFlags_PadOuterX |
            ImGuiTableFlags_ScrollY;

        bool table_open = ImGui::BeginTable("##cap_table", 6, table_flags, ImVec2(0.f, 0.f));
        int pending_selection = -1;
        if (table_open) {
            ImGui::TableSetupColumn("#",     ImGuiTableColumnFlags_WidthFixed,   48.f);
            ImGui::TableSetupColumn("Time",  ImGuiTableColumnFlags_WidthFixed,   110.f);
            ImGui::TableSetupColumn("Src",   ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Dst",   ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed,   64.f);
            ImGui::TableSetupColumn("Info",  ImGuiTableColumnFlags_WidthStretch, 0.60f);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            ImDrawList* table_dl = ImGui::GetWindowDrawList();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(cap_snapshot.rows.size()));
            while (clipper.Step()) {
                for (int visible_i = clipper.DisplayStart; visible_i < clipper.DisplayEnd; ++visible_i) {
                    const capture_row_snapshot_t& row = cap_snapshot.rows[static_cast<size_t>(visible_i)];

                    float row_alpha = 1.f;
                    float row_yoff = 0.f;
                    compute_row_entrance(s_cap_rows, cap_snapshot.total_count, row_alpha, row_yoff, row.packet_index);
                    (void)row_yoff;
                    float r_alpha = alpha * row_alpha;

                    ImGui::TableNextRow();

                    bool selected = (cap_snapshot.selected_index == row.packet_index);
                    ImU32 proto_col = protocol_stripe_color(row.protocol_label);
                    if (selected) {
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.selection, r_alpha * 0.55f));
                    }

                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(row.packet_index);
                    ImGuiSelectableFlags sel_flags =
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowItemOverlap;
                    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, r_alpha);
                    ImVec4 transparent(0.f, 0.f, 0.f, 0.f);
                    ImGui::PushStyleColor(ImGuiCol_Header, transparent);
                    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, transparent);
                    ImGui::PushStyleColor(ImGuiCol_HeaderActive, transparent);
                    float row_h = ImGui::GetTextLineHeight() + ImGui::GetStyle().CellPadding.y * 2.f;
                    if (ImGui::Selectable("##row_select", selected, sel_flags, ImVec2(0.f, row_h))) {
                        pending_selection = row.packet_index;
                        cap_snapshot.selected_index = row.packet_index;
                        selected = true;
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.selection, r_alpha * 0.55f));
                    }
                    bool hovered = ImGui::IsItemHovered();
                    ImGui::PopStyleColor(3);

                    if (hovered && !selected) {
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                                               aida::ui::with_alpha(th.hover_wash, r_alpha * 0.45f));
                    }

                    ImVec2 row_min = ImGui::GetItemRectMin();
                    ImVec2 row_max = ImGui::GetItemRectMax();
                    ImVec2 stripe_min(row_min.x, row_min.y);
                    ImVec2 stripe_max(row_min.x + 3.f, row_max.y);
                    table_dl->PushClipRect(stripe_min, ImVec2(stripe_max.x, stripe_max.y), true);
                    table_dl->AddRectFilled(stripe_min, stripe_max,
                                            aida::ui::with_alpha(proto_col, r_alpha));
                    table_dl->PopClipRect();

                    ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
                    ImGui::SetCursorScreenPos(ImVec2(row_min.x + 8.f, row_min.y + ImGui::GetStyle().CellPadding.y));
                    ImGui::PushStyleColor(ImGuiCol_Text, dim_col);
                    ImGui::Text("%d", row.packet_index + 1);
                    ImGui::PopStyleColor();

                    ImGui::TableSetColumnIndex(1);
                    table_text(format_timestamp(row.timestamp), dim_col);

                    ImGui::TableSetColumnIndex(2);
                    table_text(row.src, txt_col);

                    ImGui::TableSetColumnIndex(3);
                    table_text(row.dst, txt_col);

                    ImGui::TableSetColumnIndex(4);
                    table_text(row.protocol_label, aida::ui::with_alpha(proto_col, r_alpha));

                    ImGui::TableSetColumnIndex(5);
                    ImU32 info_col = aida::ui::with_alpha(th.text_secondary, r_alpha);
                    if (!row.summary.empty()) {
                        const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "};
                        for (auto* m : methods) {
                            if (row.summary.compare(0, strlen(m), m) == 0) {
                                info_col = ui_anim::http_method_color(m, r_alpha);
                                break;
                            }
                        }
                    }
                    table_text(row.summary, info_col);

                    ImGui::PopID();
                }
            }

            if (state.cap_auto_scroll && !cap_snapshot.rows.empty()) {
                float scroll_max_y = ImGui::GetScrollMaxY();
                float scroll_y = ImGui::GetScrollY();
                bool at_bottom = (scroll_max_y <= 0.f) || ((scroll_max_y - scroll_y) <= 4.f);
                bool user_scrolling = (ImGui::GetIO().MouseWheel != 0.f) ||
                                      ImGui::IsMouseDragging(ImGuiMouseButton_Left, 1.f);
                if (at_bottom && !user_scrolling)
                    ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndTable();
        }

        if (pending_selection >= 0) {
            std::lock_guard<std::mutex> lock(state.cap_mutex);
            if (pending_selection < static_cast<int>(state.captured_packets.size()))
                state.cap_selected = pending_selection;
            else
                clamp_capture_selection_to_buffer_locked(state);
        }

        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar();
    }

    ImGui::EndChild();


    ImGui::Spacing();
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 wp = ImGui::GetWindowPos();
        dl->AddLine(ImVec2(wp.x + 2.f, wp.y + ImGui::GetCursorPosY()),
                    ImVec2(wp.x + w - 2.f, wp.y + ImGui::GetCursorPosY()),
                    aida::ui::with_alpha(th.border_subtle, alpha));
    }
    ImGui::Spacing();

    if (detail_h > 30.f) {
        ImGui::BeginChild("##cap_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        std::lock_guard<std::mutex> lock2(state.cap_mutex);
        clamp_capture_selection_to_buffer_locked(state);
        if (state.cap_selected >= 0 && state.cap_selected < static_cast<int>(state.captured_packets.size())) {
            auto& p = state.captured_packets[static_cast<size_t>(state.cap_selected)];

            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Packet #%d  -  %s", state.cap_selected + 1, p.protocol_label.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                "%s:%u -> %s:%u  -  PID: %u  -  %u bytes  -  %s",
                format_ip(p.src_addr, 2).c_str(), p.src_port,
                format_ip(p.dst_addr, 2).c_str(), p.dst_port,
                p.pid, p.payload_size,
                p.direction == 0 ? "Inbound" : "Outbound");

            if (!p.summary.empty())
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                                    "%s", p.summary.c_str());

            ImGui::Spacing();


            if (!p.payload.empty()) {
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                    "Payload (%u bytes):", p.payload_size);
                ImGui::BeginChild("##cap_hex", ImVec2(0, 0), false, ImGuiWindowFlags_NoBackground);

                ImFont* mono_font = aida::ui::fonts::code();
                bool pushed_font = false;
                if (mono_font) { ImGui::PushFont(mono_font); pushed_font = true; }

                size_t display_size = std::min(p.payload.size(), static_cast<size_t>(4096));
                for (size_t off = 0; off < display_size; off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04X  ", static_cast<unsigned>(off));

                    size_t end = std::min(off + 16, display_size);
                    for (size_t j = off; j < off + 16; j++) {
                        if (j < end)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02X ", p.payload[j]);
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                        if (j == off + 7)
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
                    }
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " |");
                    for (size_t j = off; j < end; j++) {
                        char c = static_cast<char>(p.payload[j]);
                        line[pos++] = (c >= 32 && c < 127) ? c : '.';
                    }
                    line[pos++] = '|';
                    line[pos] = '\0';

                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                        "%s", line);
                }

                if (display_size < p.payload.size()) {
                    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                        "... %zu more bytes", p.payload.size() - display_size);
                }

                if (pushed_font) ImGui::PopFont();

                ImGui::EndChild();
            }
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                "Select a packet to view details");
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_dns(state_t& state, float x, float y, float w, float h,
                        float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_dns", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();

    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.dns_polling.load()) {
        if (aida::ui::button("Start DNS Monitor", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "dns_monitor_start_clicked filter_pid=%u drv_ok=%d",
                state.dns_filter_pid, driver_ok ? 1 : 0);
            state.dns_polling.store(true);
            state.dns_cv.notify_all();
        }
    } else {
        if (aida::ui::button("Stop DNS Monitor", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged("network", "dns_monitor_stop_clicked");
            state.dns_polling.store(false);
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Refresh", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        diag::log_tagged_fmt("network", "dns_refresh_clicked drv_ok=%d filter_pid=%u",
            driver_ok ? 1 : 0, state.dns_filter_pid);
        if (driver_ok) {
            auto raw = driver_bridge::get_dns_queries(state.dns_filter_pid);
            size_t added = 0;
            std::lock_guard<std::mutex> lock(state.dns_mutex);
            for (auto& d : raw) {
                bool duplicate = false;
                for (auto it = state.dns_entries.rbegin();
                     it != state.dns_entries.rend() && it != state.dns_entries.rbegin() + (std::min)(static_cast<size_t>(256), state.dns_entries.size());
                     ++it) {
                    if (it->timestamp == d.timestamp && it->domain == d.domain && it->pid == d.pid) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    dns_entry_t e;
                    e.timestamp = d.timestamp;
                    e.pid = d.pid;
                    e.query_type = static_cast<uint16_t>(d.query_type);
                    e.domain = d.domain;
                    e.resolved_addr = format_ip(d.resolved_addr, 2);
                    e.response_code = d.response_code;
                    e.ttl = d.ttl;
                    state.dns_entries.push_back(std::move(e));
                    ++added;
                }
            }
            while (state.dns_entries.size() > state.dns_max_entries)
                state.dns_entries.pop_front();
            diag::log_tagged_fmt("network", "dns_refresh_done raw=%zu added=%zu total=%zu",
                raw.size(), added, state.dns_entries.size());
        }
    }

    if (!driver_ok) ImGui::EndDisabled();

    ImGui::SameLine();
    aida::ui::input_text("##dns_filter", state.dns_filter_text, sizeof(state.dns_filter_text),
                          "Filter by domain or address...", false, ImVec2(280.f, 28.f));

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 64.f, col_type = 60.f, col_rcode = 64.f, col_ttl = 56.f;
    float remaining = w - col_pid - col_type - col_rcode - col_ttl - 24.f;
    float col_domain = remaining * 0.55f;
    float col_addr = remaining * 0.45f;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");     cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Type");    cx += col_type;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Domain");  cx += col_domain;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Address"); cx += col_addr;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "RCode");   cx += col_rcode;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "TTL");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##dns_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.dns_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 dns_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + dns_list_sz.x, list_org.y + dns_list_sz.y), true);

    if (state.dns_entries.empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = state.dns_polling.load() ? "Listening for DNS queries" : "DNS monitor idle";
        cfg.body  = state.dns_polling.load()
            ? "Resolved queries will appear here as the kernel observes DNS traffic."
            : "Click Start DNS Monitor to begin tracking queries.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(dns_list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    int total_visible_rows = 0;
    for (int i = 0; i < static_cast<int>(state.dns_entries.size()); i++) {
        auto& d = state.dns_entries[static_cast<size_t>(i)];
        if (state.dns_filter_text[0]) {
            std::string all = d.domain + " " + d.resolved_addr + " " + std::to_string(d.pid);
            if (!filter_text_match(state.dns_filter_text, all)) continue;
        }
        total_visible_rows++;
    }

    float scroll_y = ImGui::GetScrollY();
    float viewport_top = scroll_y;
    float viewport_bot = scroll_y + dns_list_sz.y;

    int dns_visible_row = 0;
    for (int i = 0; i < static_cast<int>(state.dns_entries.size()); i++) {
        auto& d = state.dns_entries[static_cast<size_t>(i)];

        if (state.dns_filter_text[0]) {
            std::string all = d.domain + " " + d.resolved_addr + " " + std::to_string(d.pid);
            if (!filter_text_match(state.dns_filter_text, all)) continue;
        }

        float ry = static_cast<float>(dns_visible_row) * row_h;

        if (ry + row_h < viewport_top || ry > viewport_bot) {
            dns_visible_row++;
            continue;
        }

        float row_alpha = 1.f;
        float row_yoff = 0.f;
        compute_row_entrance(s_dns_rows, state.dns_entries.size(), row_alpha, row_yoff, i);
        float r_alpha = alpha * row_alpha;

        float abs_ry = list_org.y + ry - scroll_y;
        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.dns_selected == i);

        if (dns_visible_row & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, r_alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.dns_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
        cx = list_org.x + 8.f;
        char buf[16];

        snprintf(buf, sizeof(buf), "%u", d.pid);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += col_pid;

        const char* qtype = d.query_type == 1 ? "A" : d.query_type == 28 ? "AAAA" : d.query_type == 5 ? "CNAME" : "?";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.info, r_alpha), qtype);
        cx += col_type;


        std::string domain = d.domain;
        if (domain.size() > 40) domain = domain.substr(0, 37) + "...";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.accent_u32, r_alpha),
                     domain.c_str()); cx += col_domain;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, d.resolved_addr.c_str()); cx += col_addr;

        snprintf(buf, sizeof(buf), "%u", d.response_code);
        ImU32 rcode_col = d.response_code == 0
            ? aida::ui::with_alpha(th.success, r_alpha)
            : aida::ui::with_alpha(th.error, r_alpha);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), rcode_col, buf); cx += col_rcode;

        snprintf(buf, sizeof(buf), "%u", d.ttl);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_dim, r_alpha), buf);

        dns_visible_row++;
    }

    dl->PopClipRect();
    ImGui::Dummy(ImVec2(1.f, static_cast<float>(total_visible_rows) * row_h));
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_proxy(state_t& state, float x, float y, float w, float h,
                          float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_proxy", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool running = mitm_proxy::is_running();

    ImGui::PushID("proxy_toolbar");
    if (!running) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Bind:");
        same_line_if_fits(140.f);
        aida::ui::input_text("##proxy_addr", state.proxy_bind_addr, sizeof(state.proxy_bind_addr),
                              "127.0.0.1", false, ImVec2(std::min(180.f, std::max(128.f, w * 0.22f)), 28.f));
        same_line_if_fits(56.f);
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Port:");
        same_line_if_fits(82.f);
        aida::ui::input_int("##proxy_port", &state.proxy_port, ImVec2(80.f, 28.f));
        same_line_if_fits(96.f);
        aida::ui::toggle_switch("##proxy_tls", &state.proxy_decode_tls);
        same_line_if_fits(72.f);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "TLS MITM");
        same_line_if_fits(110.f);

        if (aida::ui::button("Start Proxy", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            mitm_proxy::proxy_config cfg;
            cfg.bind_addr = state.proxy_bind_addr;
            cfg.bind_port = static_cast<uint16_t>(state.proxy_port);
            cfg.decode_tls = state.proxy_decode_tls;
            diag::log_tagged_fmt("network", "proxy_start_clicked bind=%s:%u decode_tls=%d",
                state.proxy_bind_addr, state.proxy_port, state.proxy_decode_tls ? 1 : 0);
            bool ok = mitm_proxy::start(cfg);
            diag::log_tagged_fmt("network", "proxy_start_result ok=%d running=%d",
                ok ? 1 : 0, mitm_proxy::is_running() ? 1 : 0);
            char buf[160];
            snprintf(buf, sizeof(buf),
                "[net_audit] proxy start clicked bind=%s:%u tls=%d ok=%d running=%d",
                state.proxy_bind_addr, state.proxy_port, state.proxy_decode_tls ? 1 : 0,
                ok ? 1 : 0, mitm_proxy::is_running() ? 1 : 0);
            anti_tamper::webhook::write_log("net_audit", buf);
            if (!ok) {
                toast_notification::push("Failed to start proxy. See aida_debug.log.",
                    toast_notification::toast_type_t::error);
            }
        }
    } else {
        auto stats = mitm_proxy::get_stats();
        proxy_chart_tick(stats.total_requests);

        char run_buf[64];
        snprintf(run_buf, sizeof(run_buf), "Proxy running  %s:%d", state.proxy_bind_addr, state.proxy_port);
        aida::ui::pill_kind(run_buf, aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, true);

        same_line_if_fits(112.f);
        ImDrawList* dl_top = ImGui::GetWindowDrawList();
        ImVec2 sp_pos = ImGui::GetCursorScreenPos();
        float sp_w = 96.f, sp_h = 22.f;
        float ordered[proxy_history_chart_t::N];
        for (int i = 0; i < proxy_history_chart_t::N; i++) {
            int idx = (s_proxy_chart.head + i) % proxy_history_chart_t::N;
            ordered[i] = s_proxy_chart.values[idx];
        }
        ImU32 spark_line = aida::ui::with_alpha(th.accent_u32, alpha);
        ImU32 spark_fill = aida::ui::with_alpha(th.accent_glow, alpha * 0.6f);
        ui_anim::render_sparkline(dl_top, sp_pos.x, sp_pos.y + 4.f, sp_w, sp_h,
                                   ordered, proxy_history_chart_t::N, spark_line, spark_fill);
        ImGui::Dummy(ImVec2(sp_w + 8.f, sp_h + 6.f));

        char stats_buf[192];
        snprintf(stats_buf, sizeof(stats_buf), "%llu req  %u active  In %s  Out %s",
            static_cast<unsigned long long>(stats.total_requests),
            stats.active_connections,
            format_bytes(stats.total_bytes_in).c_str(),
            format_bytes(stats.total_bytes_out).c_str());
        same_line_if_fits(estimate_chip_w(stats_buf, 10.f));
        clipped_text(stats_buf, aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);

        same_line_if_fits(64.f);
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged("network", "proxy_stop_clicked");
            mitm_proxy::stop();
        }
        same_line_if_fits(112.f);
        if (aida::ui::button("Clear History", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            size_t prev = mitm_proxy::history_count();
            mitm_proxy::clear_history();
            diag::log_tagged_fmt("network", "proxy_history_cleared prev_count=%zu", prev);
        }
    }

    same_line_if_fits(230.f);
    aida::ui::input_text("##proxy_filter", state.proxy_filter_text, sizeof(state.proxy_filter_text),
                          "Filter requests...", false, ImVec2(220.f, 28.f));
    ImGui::PopID();


    ImGui::Spacing();
    bool ca_ready = cert_generator::is_ready();
    bool ca_installed = false;
    std::string spki_prefix;
    if (ca_ready) {
        const auto& ca = cert_generator::get_root_ca();
        ca_installed = cert_generator::is_root_ca_installed(ca);
        spki_prefix = aida::burp::browser::spki_hash_prefix(cert_generator::spki_sha256_base64(ca));
    }
    auto controlled_browsers = aida::burp::browser::list_running();
    bool controlled_browser_running = false;
    for (const auto& browser : controlled_browsers) {
        if (browser.running) {
            controlled_browser_running = true;
            break;
        }
    }

    bool first_pill = true;
    auto readiness_pill = [&](const char* label, aida::ui::pill_kind_t kind) {
        if (!first_pill)
            same_line_if_fits(estimate_chip_w(label, 24.f));
        aida::ui::pill_kind(label, kind, aida::ui::size_t_::sm, false);
        first_pill = false;
    };
    readiness_pill("Interception readiness", aida::ui::pill_kind_t::info);
    aida::ui::pill_kind(mitm_proxy::is_running() ? "Proxy running" : "Proxy stopped",
        mitm_proxy::is_running() ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::warning,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w(ca_installed ? "AiDA CA trusted" : "AiDA CA not trusted", 24.f));
    aida::ui::pill_kind(ca_installed ? "AiDA CA trusted" : "AiDA CA not trusted",
        ca_installed ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::warning,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w(controlled_browser_running ? "Controlled active" : "Controlled ready", 24.f));
    aida::ui::pill_kind(controlled_browser_running ? "Controlled active" : "Controlled ready",
        controlled_browser_running ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::neutral,
        aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("Camoufox only", 24.f));
    aida::ui::pill_kind("Camoufox only", aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("WebRTC blocked", 24.f));
    aida::ui::pill_kind("WebRTC blocked", aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    same_line_if_fits(estimate_chip_w("QUIC disabled", 24.f));
    aida::ui::pill_kind("QUIC disabled", aida::ui::pill_kind_t::info, aida::ui::size_t_::sm, false);
    if (!spki_prefix.empty()) {
        char spki_buf[64];
        snprintf(spki_buf, sizeof(spki_buf), "SPKI %s", spki_prefix.c_str());
        same_line_if_fits(estimate_chip_w(spki_buf, 24.f));
        aida::ui::pill_kind(spki_buf, aida::ui::pill_kind_t::neutral, aida::ui::size_t_::sm, false);
    }
    ImGui::Spacing();
    if (aida::ui::button("Prepare controlled browser", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        state.prev_tab = state.active_tab;
        state.active_tab = sub_tab_t::browser;
    }
    same_line_if_fits(92.f);
    if (aida::ui::button("Repair trust", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        bool ok = cert_generator::initialize();
        if (ok && cert_generator::is_ready()) {
            ok = cert_generator::install_root_ca(cert_generator::get_root_ca());
        }
        toast_notification::push(ok ? "AiDA CA trust repaired." : "AiDA CA trust repair failed.",
            ok ? toast_notification::toast_type_t::success : toast_notification::toast_type_t::error);
    }
    same_line_if_fits(154.f);
    if (aida::ui::button("Open Camoufox controls", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        state.prev_tab = state.active_tab;
        state.active_tab = sub_tab_t::browser;
        toast_notification::push("Camoufox is the only supported browser.", toast_notification::toast_type_t::info);
    }
    if (cert_pin_bypass::is_bypass_active()) {
        auto active_bypasses = cert_pin_bypass::get_active_bypasses();
        char legacy_buf[96];
        snprintf(legacy_buf, sizeof(legacy_buf), "Legacy cleanup  -  %zu patches", active_bypasses.size());
        same_line_if_fits(estimate_chip_w(legacy_buf, 24.f));
        aida::ui::pill_kind(legacy_buf, aida::ui::pill_kind_t::warning, aida::ui::size_t_::sm, false);
        same_line_if_fits(142.f);
        if (aida::ui::button("Revert legacy patches", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "cert_pin_revert_clicked patches=%zu",
                active_bypasses.size());
            cert_pin_bypass::revert_all_bypasses();
        }
    }

    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
        "Target PID:");
    same_line_if_fits(112.f);
    ImGui::SetNextItemWidth(110.f);
    ImGui::InputInt("##cert_diag_pid", &s_cert_diag_ui.target_pid, 1, 100, ImGuiInputTextFlags_CharsDecimal);
    if (s_cert_diag_ui.target_pid < 0) s_cert_diag_ui.target_pid = 0;
    same_line_if_fits(118.f);
    if (aida::ui::button("Diagnose target", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        cert_intercept::diagnostic_context_t context;
        context.proxy_running = mitm_proxy::is_running();
        context.ca_trusted = ca_installed;
        context.controlled_browser = controlled_browser_running;
        context.proxy_endpoint = std::string(state.proxy_bind_addr) + ":" + std::to_string(state.proxy_port);
        cert_diag_apply_proxy_observations(context);
        if (s_cert_diag_ui.target_pid > 0) {
            s_cert_diag_ui.report = cert_intercept::diagnose_process(static_cast<uint32_t>(s_cert_diag_ui.target_pid), context);
            s_cert_diag_ui.providers = cert_intercept::provider_registry_t::instance().evaluate(
                static_cast<uint32_t>(s_cert_diag_ui.target_pid), s_cert_diag_ui.report);
            s_cert_diag_ui.has_report = true;
            s_cert_diag_ui.status = cert_intercept::to_string(s_cert_diag_ui.report.primary) + " - " + s_cert_diag_ui.report.summary;
            s_cert_diag_ui.handoff_status.clear();
        } else {
            s_cert_diag_ui.has_report = false;
            s_cert_diag_ui.status = "Select a live PID before diagnostics";
        }
    }
    if (!s_cert_diag_ui.status.empty()) {
        same_line_if_fits(std::min(360.f, ImGui::CalcTextSize(s_cert_diag_ui.status.c_str()).x + 8.f));
        clipped_text(s_cert_diag_ui.status.c_str(), aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);
    }
    if (s_cert_diag_ui.has_report) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "Recommended tier: %s", s_cert_diag_ui.report.recommended_tier.c_str());
        int shown = 0;
        for (const auto& finding : s_cert_diag_ui.report.findings) {
            if (shown++ >= 3) break;
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "%s: %s", cert_intercept::to_string(finding.severity).c_str(), finding.title.c_str());
            clipped_text(finding.next_action.c_str(), aida::ui::with_alpha(th.text_dim, alpha * th.disabled_alpha), ImGui::GetContentRegionAvail().x);
        }
        if (!s_cert_diag_ui.providers.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                "Providers:");
            bool first_provider = true;
            for (const auto& provider : s_cert_diag_ui.providers) {
                char provider_buf[160];
                snprintf(provider_buf, sizeof(provider_buf), "%s:%s",
                    provider.descriptor.provider_id.c_str(),
                    cert_intercept::to_string(provider.state).c_str());
                if (!first_provider)
                    same_line_if_fits(estimate_chip_w(provider_buf, 24.f));
                aida::ui::pill_kind(provider_buf,
                    provider.state == cert_intercept::provider_state_t::available ? aida::ui::pill_kind_t::success : aida::ui::pill_kind_t::neutral,
                    aida::ui::size_t_::sm, false);
                first_provider = false;
            }
        }
        bool can_handoff = s_cert_diag_ui.report.primary == cert_intercept::classification_t::true_pinning ||
            s_cert_diag_ui.report.primary == cert_intercept::classification_t::app_specific_tls_stack;
        if (can_handoff) {
            if (aida::ui::button("Generate handoff", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
                bool ok = cert_generator::initialize();
                cert_intercept::profiles::public_ca_export_t exported;
                if (ok && cert_generator::is_ready()) {
                    exported = cert_intercept::profiles::export_public_ca_files(cert_generator::get_root_ca());
                    ok = exported.ok;
                }
                if (ok) {
                    cert_intercept::handoff_request_t request;
                    request.diagnostics = s_cert_diag_ui.report;
                    request.provider_statuses = s_cert_diag_ui.providers;
                    request.target_label = s_cert_diag_ui.report.process_name.empty() ? "target" : s_cert_diag_ui.report.process_name;
                    request.proxy_endpoint = std::string(state.proxy_bind_addr) + ":" + std::to_string(state.proxy_port);
                    request.ca_cert_pem_path = exported.pem_path.u8string();
                    request.ca_cert_der_path = exported.der_path.u8string();
                    auto handoff = cert_intercept::generate_handoff(request);
                    ok = handoff.ok;
                    s_cert_diag_ui.handoff_status = ok ? handoff.metadata_path.u8string() : handoff.error;
                } else {
                    s_cert_diag_ui.handoff_status = exported.error.empty() ? "ca_export_failed" : exported.error;
                }
            }
            if (!s_cert_diag_ui.handoff_status.empty()) {
                same_line_if_fits(std::min(360.f, ImGui::CalcTextSize(s_cert_diag_ui.handoff_status.c_str()).x + 8.f));
                clipped_text(s_cert_diag_ui.handoff_status.c_str(), aida::ui::with_alpha(th.text_dim, alpha), ImGui::GetContentRegionAvail().x);
            }
        }
    }
    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    float cursor_y = ImGui::GetCursorPosY();
    float list_h = std::max(120.f, (h - cursor_y - 16.f) * 0.58f);
    auto history = mitm_proxy::get_history();

    if (history.empty()) {
        ImVec2 list_org = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = running ? "Awaiting requests" : "Proxy idle";
        cfg.body  = running
            ? "Configure a client to use this proxy. Captured exchanges will appear here."
            : "Start the proxy to intercept and inspect HTTP/S traffic.";
        aida::ui::empty_state::render(list_org, ImVec2(w - 4.f, list_h), cfg);
        ImGui::Dummy(ImVec2(0.f, list_h));
        ImGui::EndChild();
        return;
    }

    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerH |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable |
        ImGuiTableFlags_SizingStretchProp;

    int visible_rows = 0;
    if (ImGui::BeginTable("##proxy_history_table", 8, table_flags, ImVec2(w - 4.f, list_h))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 54.f);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 72.f);
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.75f);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch, 1.35f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 76.f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 76.f);
        ImGui::TableSetupColumn("TLS", ImGuiTableColumnFlags_WidthFixed, 48.f);
        ImGui::TableHeadersRow();

        for (int i = 0; i < static_cast<int>(history.size()); i++) {
            auto& ex = history[static_cast<size_t>(i)];

            if (state.proxy_filter_text[0]) {
                std::string all = ex.target_host + " " + ex.request.method + " " + ex.request.uri;
                if (!filter_text_match(state.proxy_filter_text, all)) continue;
            }

            float row_alpha = 1.f;
            float row_yoff = 0.f;
            compute_row_entrance(s_proxy_rows, history.size(), row_alpha, row_yoff, i);
            (void)row_yoff;
            float r_alpha = alpha * row_alpha;
            bool selected = (state.proxy_selected == i);
            ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, r_alpha);
            ImU32 dim_col = aida::ui::with_alpha(th.text_dim, r_alpha);

            ImGui::TableNextRow(ImGuiTableRowFlags_None, 24.f);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(i);
            char buf[64];
            snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(ex.id));
            if (ImGui::Selectable(buf, selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                  ImVec2(0.f, 22.f))) {
                state.proxy_selected = i;
            }
            ImGui::PopID();

            ImGui::TableSetColumnIndex(1);
            table_text(ex.request.method, ui_anim::http_method_color(ex.request.method.c_str(), r_alpha));

            ImGui::TableSetColumnIndex(2);
            table_text(ex.target_host, txt_col);

            ImGui::TableSetColumnIndex(3);
            table_text(ex.request.uri, txt_col);

            ImGui::TableSetColumnIndex(4);
            if (ex.response.status_code > 0) {
                snprintf(buf, sizeof(buf), "%d", ex.response.status_code);
                table_text(buf, aida::ui::with_alpha(status_code_color(ex.response.status_code), r_alpha));
            } else {
                const char* st = "...";
                ImU32 st_col = dim_col;
                if (ex.state == mitm_proxy::http_exchange::state_t::dropped) {
                    st = "DROP";
                    st_col = aida::ui::with_alpha(th.error, r_alpha);
                } else if (ex.state == mitm_proxy::http_exchange::state_t::error) {
                    st = "ERR";
                    st_col = aida::ui::with_alpha(th.error, r_alpha);
                }
                table_text(st, st_col);
            }

            ImGui::TableSetColumnIndex(5);
            snprintf(buf, sizeof(buf), "%llums", static_cast<unsigned long long>(ex.latency_ms));
            table_text(buf, txt_col);

            ImGui::TableSetColumnIndex(6);
            table_text(format_bytes(ex.response_size), txt_col);

            ImGui::TableSetColumnIndex(7);
            table_text(ex.is_tls ? "TLS" : "-", ex.is_tls ? aida::ui::with_alpha(th.success, r_alpha)
                                                          : dim_col);
            ++visible_rows;
        }
        ImGui::EndTable();
    }

    if (visible_rows == 0) {
        ImVec2 empty_pos = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No matching requests";
        cfg.body = "Clear or adjust the proxy filter to show captured exchanges.";
        aida::ui::empty_state::render(empty_pos, ImVec2(w - 4.f, 80.f), cfg);
        ImGui::Dummy(ImVec2(0.f, 80.f));
    }


    float detail_h = h - ImGui::GetCursorPosY() - 8.f;
    if (detail_h > 30.f && state.proxy_selected >= 0 && state.proxy_selected < static_cast<int>(history.size())) {
        dl->AddLine(ImVec2(org.x + 2.f, org.y + ImGui::GetCursorPosY()),
                    ImVec2(org.x + w - 2.f, org.y + ImGui::GetCursorPosY()),
                    aida::ui::with_alpha(th.border_subtle, alpha));
        ImGui::Spacing();
        ImGui::BeginChild("##proxy_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        auto& ex = history[static_cast<size_t>(state.proxy_selected)];
        ImU32 method_col = ui_anim::http_method_color(ex.request.method.c_str(), alpha);

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(method_col), "%s", ex.request.method.c_str());
        same_line_if_fits(std::min(520.f, ImGui::CalcTextSize(ex.request.uri.c_str()).x + 8.f));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                            "%s", ex.request.uri.c_str());

        char meta_buf[256];
        snprintf(meta_buf, sizeof(meta_buf), "%s:%u  %s  %llums  req=%s  resp=%s",
            ex.target_host.c_str(), ex.target_port,
            ex.is_tls ? "TLS" : "Plain",
            static_cast<unsigned long long>(ex.latency_ms),
            format_bytes(ex.raw_request.size()).c_str(),
            format_bytes(ex.response_size).c_str());
        clipped_text(meta_buf, aida::ui::with_alpha(th.text_secondary, alpha), ImGui::GetContentRegionAvail().x);

        if (aida::ui::button("Send to Repeater", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            auto rep = std::make_shared<repeater_entry_t>();
            rep->host = ex.target_host;
            rep->port = ex.target_port;
            rep->use_tls = ex.is_tls;
            rep->raw_request = std::string(ex.raw_request.begin(), ex.raw_request.end());
            diag::log_tagged_fmt("network", "proxy_send_to_repeater id=%llu host=%s:%u tls=%d size=%zu",
                static_cast<unsigned long long>(ex.id), ex.target_host.c_str(), ex.target_port,
                ex.is_tls ? 1 : 0, rep->raw_request.size());
            state.repeater_entries.push_back(std::move(rep));
            state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
        }
        same_line_if_fits(96.f);
        if (aida::ui::button("Copy URL", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            std::string url = std::string(ex.is_tls ? "https://" : "http://") + ex.target_host + ex.request.uri;
            ImGui::SetClipboardText(url.c_str());
        }

        ImGui::Spacing();
        std::string request_text = payload_display_text(ex.raw_request);
        std::string response_text = payload_display_text(ex.raw_response);
        char req_meta[96];
        snprintf(req_meta, sizeof(req_meta), "%zu headers  %s",
            ex.request.headers.size(), format_bytes(ex.raw_request.size()).c_str());
        char resp_meta[128];
        if (ex.response.status_code > 0) {
            snprintf(resp_meta, sizeof(resp_meta), "%d %s  %zu headers  %s",
                ex.response.status_code,
                ex.response.reason.c_str(),
                ex.response.headers.size(),
                format_bytes(ex.raw_response.size()).c_str());
        } else {
            snprintf(resp_meta, sizeof(resp_meta), "pending  %s", format_bytes(ex.raw_response.size()).c_str());
        }
        float pane_h = std::max(80.f, detail_h - ImGui::GetCursorPosY() - 6.f);
        if (w >= 900.f) {
            float pane_w = (w - 16.f) * 0.5f;
            render_payload_box("##proxy_request_payload", "Request", req_meta, request_text,
                               ImVec2(pane_w, pane_h), th, alpha);
            ImGui::SameLine();
            render_payload_box("##proxy_response_payload", "Response", resp_meta, response_text,
                               ImVec2(pane_w, pane_h), th, alpha);
        } else {
            float each_h = std::max(72.f, (pane_h - 6.f) * 0.5f);
            render_payload_box("##proxy_request_payload", "Request", req_meta, request_text,
                               ImVec2(w - 8.f, each_h), th, alpha);
            render_payload_box("##proxy_response_payload", "Response", resp_meta, response_text,
                               ImVec2(w - 8.f, each_h), th, alpha);
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_filters(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab; (void)w; (void)h;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_filters", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Add Filter Rule");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Action:");
    ImGui::SameLine();
    aida::ui::radio_button("Block", &state.nf_action, 0); ImGui::SameLine();
    aida::ui::radio_button("Allow", &state.nf_action, 1);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Direction:");
    ImGui::SameLine();
    aida::ui::radio_button("In", &state.nf_direction, 0); ImGui::SameLine();
    aida::ui::radio_button("Out", &state.nf_direction, 1); ImGui::SameLine();
    aida::ui::radio_button("Both", &state.nf_direction, 2);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Protocol:");
    ImGui::SameLine();
    aida::ui::radio_button("Any", &state.nf_protocol, 0); ImGui::SameLine();
    aida::ui::radio_button("TCP##f", &state.nf_protocol, 6); ImGui::SameLine();
    aida::ui::radio_button("UDP##f", &state.nf_protocol, 17);

    aida::ui::input_text("##nf_pid_in", state.nf_pid, sizeof(state.nf_pid), "PID",
                          false, ImVec2(110.f, 28.f));
    ImGui::SameLine();
    aida::ui::input_text("##nf_port_in", state.nf_port, sizeof(state.nf_port), "Port",
                          false, ImVec2(110.f, 28.f));
    ImGui::SameLine();
    aida::ui::input_text("##nf_ip_in", state.nf_ip, sizeof(state.nf_ip), "IP Address",
                          false, ImVec2(180.f, 28.f));
    ImGui::SameLine();

    if (!driver_ok) ImGui::BeginDisabled();
    if (aida::ui::button("Add Rule", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        uint32_t pid = state.nf_pid[0] ? static_cast<uint32_t>(atoi(state.nf_pid)) : 0;
        uint16_t port = state.nf_port[0] ? static_cast<uint16_t>(atoi(state.nf_port)) : 0;

        uint8_t ip_bytes[16] = {};
        if (state.nf_ip[0]) {
            inet_pton(AF_INET, state.nf_ip, ip_bytes);
        }

        uint32_t out_rule_id = 0;
        bool added = driver_bridge::add_filter_rule(
            static_cast<uint32_t>(state.nf_action),
            static_cast<uint32_t>(state.nf_direction),
            static_cast<uint32_t>(state.nf_protocol),
            pid, port, ip_bytes, nullptr, &out_rule_id);
        diag::log_tagged_fmt("network", "filter_add_rule action=%d dir=%d proto=%d pid=%u port=%u ip='%s' added=%d rule_id=%u",
            state.nf_action, state.nf_direction, state.nf_protocol, pid, port,
            state.nf_ip, added ? 1 : 0, out_rule_id);
        if (added) {
            filter_entry_t fe;
            fe.rule_id = out_rule_id;
            fe.action = static_cast<uint8_t>(state.nf_action);
            fe.direction = static_cast<uint8_t>(state.nf_direction);
            fe.protocol = static_cast<uint8_t>(state.nf_protocol);
            fe.pid = pid;
            fe.port = port;
            fe.ip_addr = state.nf_ip;
            fe.active = true;
            state.filters.push_back(std::move(fe));
            toast_notification::push("Filter rule added", toast_notification::toast_type_t::info);
        } else {
            toast_notification::push("Failed to add filter rule",
                toast_notification::toast_type_t::error);
        }
    }

    ImGui::SameLine();
    if (aida::ui::button("Clear All", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        size_t prev_n = state.filters.size();
        bool cleared = driver_bridge::clear_filter_rules();
        state.filters.clear();
        diag::log_tagged_fmt("network", "filter_clear_all prev_count=%zu driver_cleared=%d",
            prev_n, cleared ? 1 : 0);
    }
    if (!driver_ok) ImGui::EndDisabled();

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Active Rules:");
    ImGui::Spacing();

    if (state.filters.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "No active filter rules.");
    }

    int remove_idx = -1;
    for (int i = 0; i < static_cast<int>(state.filters.size()); i++) {
        auto& f = state.filters[static_cast<size_t>(i)];
        char rule_buf[192];
        snprintf(rule_buf, sizeof(rule_buf), "#%u  %s  %s %s  PID:%u  Port:%u  %s",
                 f.rule_id,
                 f.action == 0 ? "BLOCK" : "ALLOW",
                 f.direction == 0 ? "IN" : f.direction == 1 ? "OUT" : "BOTH",
                 f.protocol == 6 ? "TCP" : f.protocol == 17 ? "UDP" : "ANY",
                 f.pid, f.port, f.ip_addr.c_str());
        aida::ui::pill_kind_t kind = (f.action == 0)
            ? aida::ui::pill_kind_t::error
            : aida::ui::pill_kind_t::success;
        aida::ui::pill_kind(rule_buf, kind, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        ImGui::PushID(i);
        if (aida::ui::button("Remove", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm))
            remove_idx = i;
        ImGui::PopID();
    }
    if (remove_idx >= 0 && remove_idx < static_cast<int>(state.filters.size())) {
        auto& f = state.filters[static_cast<size_t>(remove_idx)];
        bool drv_removed = driver_bridge::remove_filter_rule(f.rule_id);
        diag::log_tagged_fmt("network", "filter_remove_rule rule_id=%u drv_removed=%d", f.rule_id,
            drv_removed ? 1 : 0);
        state.filters.erase(state.filters.begin() + remove_idx);
    }

    ImGui::EndChild();
}


static void render_bandwidth(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_bw", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool driver_ok = driver_bridge::using_kernel_driver();

    if (!driver_ok) ImGui::BeginDisabled();

    if (!state.bw_polling.load()) {
        if (aida::ui::button("Start Monitoring", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            bool drv_started = driver_bridge::bw_monitor_op(0);
            diag::log_tagged_fmt("network", "bandwidth_monitor_start_clicked drv_ok=%d drv_started=%d",
                driver_ok ? 1 : 0, drv_started ? 1 : 0);
            state.bw_monitoring = true;
            state.bw_polling.store(true);
            state.bw_cv.notify_one();
        }
    } else {
        if (aida::ui::button("Stop Monitoring", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            bool drv_stopped = driver_bridge::bw_monitor_op(1);
            diag::log_tagged_fmt("network", "bandwidth_monitor_stop_clicked drv_stopped=%d",
                drv_stopped ? 1 : 0);
            state.bw_monitoring = false;
            state.bw_polling.store(false);
        }
    }

    if (!driver_ok) ImGui::EndDisabled();
    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 26.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_y = org.y + cursor.y;

    float col_pid = 64.f, col_name = 160.f, col_spark = 130.f;
    float col_in = (w - col_pid - col_name - col_spark - 24.f) * 0.25f;
    float col_out = col_in, col_rin = col_in, col_rout = col_in;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, row_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "PID");       cx += col_pid;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Process");   cx += col_name;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "In");        cx += col_in;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Out");       cx += col_out;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "In Rate");   cx += col_rin;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Out Rate");  cx += col_rout;
    dl->AddText(ImVec2(cx, hdr_y + text_oy), hdr_col, "Trend");

    ImGui::SetCursorPosY(cursor.y + row_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + row_h - 1.f), ImVec2(org.x + w, hdr_y + row_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + row_h + 12.f);
    ImGui::BeginChild("##bw_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    std::lock_guard<std::mutex> lock(state.bw_mutex);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 bw_list_sz = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + bw_list_sz.x, list_org.y + bw_list_sz.y), true);

    if (state.bw_entries.empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = state.bw_polling.load() ? "Collecting metrics" : "Bandwidth monitor idle";
        cfg.body  = state.bw_polling.load()
            ? "Per-process bandwidth statistics will appear shortly."
            : "Click Start Monitoring above to track per-process bandwidth.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(bw_list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    for (int i = 0; i < static_cast<int>(state.bw_entries.size()); i++) {
        auto& b = state.bw_entries[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;

        ImVec2 mouse = ImGui::GetMousePos();
        bool hovered = (mouse.x >= list_org.x && mouse.x < list_org.x + w &&
                        mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        bool selected = (state.bw_selected == i);

        if (i & 1)
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha * 0.30f));

        if (selected) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }

        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            state.bw_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(selected ? th.text_primary : th.text_secondary, alpha);
        cx = list_org.x + 8.f;

        char buf[32];
        snprintf(buf, sizeof(buf), "%u", b.pid);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += col_pid;

        std::string name = b.process_name.empty() ? "-" : b.process_name;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, name.c_str()); cx += col_name;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.info, alpha),
            format_bytes(b.bytes_in).c_str()); cx += col_in;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.warning, alpha),
            format_bytes(b.bytes_out).c_str()); cx += col_out;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, format_rate(b.rate_in).c_str()); cx += col_rin;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, format_rate(b.rate_out).c_str()); cx += col_rout;

        int hist_count = std::min(b.history_index, 64);
        if (hist_count > 1) {
            float ordered[64];
            float max_v = 0.0001f;
            int peak_idx = 0;
            for (int hi = 0; hi < hist_count; hi++) {
                int idx = (b.history_index - hist_count + hi) % 64;
                if (idx < 0) idx += 64;
                ordered[hi] = b.rate_history[idx];
                if (ordered[hi] > max_v) { max_v = ordered[hi]; peak_idx = hi; }
            }
            float spark_x = cx;
            float spark_y = abs_ry + 4.f;
            float spark_w = col_spark - 8.f;
            float spark_h = row_h - 8.f;
            ImU32 spark_line = aida::ui::with_alpha(th.accent_u32, alpha);
            ImU32 spark_fill = aida::ui::with_alpha(th.accent_glow, alpha * 0.55f);
            ui_anim::render_sparkline(dl, spark_x, spark_y, spark_w, spark_h,
                                      ordered, hist_count, spark_line, spark_fill);

            float step = spark_w / static_cast<float>(hist_count - 1);
            float peak_x = spark_x + step * static_cast<float>(peak_idx);
            float peak_y = spark_y + spark_h - (ordered[peak_idx] / max_v) * spark_h;
            dl->AddCircleFilled(ImVec2(peak_x, peak_y), 2.5f,
                                 aida::ui::with_alpha(th.warning, alpha), 12);
            dl->AddCircle(ImVec2(peak_x, peak_y), 4.5f,
                           aida::ui::with_alpha(th.warning, alpha * 0.55f), 14, 1.f);

            ImVec2 mp = ImGui::GetMousePos();
            if (mp.x >= spark_x && mp.x <= spark_x + spark_w &&
                mp.y >= spark_y && mp.y <= spark_y + spark_h) {
                int hi = static_cast<int>((mp.x - spark_x) / step + 0.5f);
                if (hi < 0) hi = 0;
                if (hi >= hist_count) hi = hist_count - 1;
                float vx = spark_x + step * static_cast<float>(hi);
                float vy = spark_y + spark_h - (ordered[hi] / max_v) * spark_h;
                dl->AddLine(ImVec2(vx, spark_y), ImVec2(vx, spark_y + spark_h),
                             aida::ui::with_alpha(th.accent_u32, alpha * 0.6f), 1.f);
                dl->AddCircleFilled(ImVec2(vx, vy), 3.f,
                                     aida::ui::with_alpha(th.accent_u32, alpha), 12);
                ImGui::SetCursorScreenPos(ImVec2(mp.x + 12.f, mp.y - 6.f));
                char tip[64];
                snprintf(tip, sizeof(tip), "%s", format_rate(ordered[hi]).c_str());
                ImGui::PushStyleColor(ImGuiCol_PopupBg,
                                       ImGui::ColorConvertU32ToFloat4(th.bg_overlay));
                ImGui::SetTooltip("%s", tip);
                ImGui::PopStyleColor();
            }
        }

        ImGui::SetCursorPosY(ry + row_h);
    }

    dl->PopClipRect();
    ImGui::EndChild();
    ImGui::EndChild();
}


static void render_repeater(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_rep", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Host:");
    ImGui::SameLine();
    aida::ui::input_text("##rep_host", state.rep_host, sizeof(state.rep_host),
                          "example.com", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Port:");
    ImGui::SameLine();
    aida::ui::input_int("##rep_port", &state.rep_port, ImVec2(80.f, 28.f));
    ImGui::SameLine();
    aida::ui::toggle_switch("##rep_tls", &state.rep_use_tls);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "TLS");
    ImGui::SameLine();

    if (aida::ui::button("New", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        auto rep = std::make_shared<repeater_entry_t>();
        rep->host = state.rep_host;
        rep->port = static_cast<uint16_t>(state.rep_port);
        rep->use_tls = state.rep_use_tls;
        rep->raw_request = "GET / HTTP/1.1\r\nHost: " + std::string(state.rep_host) + "\r\n\r\n";
        diag::log_tagged_fmt("network", "repeater_new_entry host=%s:%d tls=%d",
            state.rep_host, state.rep_port, state.rep_use_tls ? 1 : 0);
        state.repeater_entries.push_back(std::move(rep));
        state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
    }


    if (!state.repeater_entries.empty()) {
        ImGui::Spacing();
        for (int i = 0; i < static_cast<int>(state.repeater_entries.size()); i++) {
            if (i > 0) ImGui::SameLine();
            bool is_sel = (state.repeater_selected == i);
            char label[32];
            snprintf(label, sizeof(label), "#%d##rep_tab", i + 1);
            aida::ui::button_kind_t kk = is_sel
                ? aida::ui::button_kind_t::primary
                : aida::ui::button_kind_t::secondary;
            if (aida::ui::button(label, kk, aida::ui::size_t_::sm)) {
                if (state.repeater_selected != i)
                    diag::log_tagged_fmt("network", "repeater_tab_switched from=%d to=%d",
                        state.repeater_selected, i);
                state.repeater_selected = i;
            }
        }

        ImGui::SameLine();
        if (state.repeater_selected >= 0 &&
            state.repeater_selected < static_cast<int>(state.repeater_entries.size())) {
            if (aida::ui::button("Close##rep_close", aida::ui::button_kind_t::ghost,
                                  aida::ui::size_t_::sm)) {
                int idx = state.repeater_selected;
                diag::log_tagged_fmt("network", "repeater_entry_closed idx=%d", idx);
                state.repeater_entries.erase(
                    state.repeater_entries.begin() + static_cast<ptrdiff_t>(idx));
                if (state.repeater_selected >= static_cast<int>(state.repeater_entries.size()))
                    state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
            }
        }

        ImGui::Spacing();

        if (state.repeater_selected >= 0 && state.repeater_selected < static_cast<int>(state.repeater_entries.size())) {
            auto rep_ptr = state.repeater_entries[static_cast<size_t>(state.repeater_selected)];
            auto& rep = *rep_ptr;

            const bool stack_editors = w < 760.f;
            float half_w = (w - 8.f) * 0.5f;
            float panel_h = h - ImGui::GetCursorPosY() - 40.f;
            if (panel_h < 160.f) panel_h = 160.f;
            float req_w = stack_editors ? std::max(120.f, w - 4.f) : half_w;
            float resp_w = req_w;
            float req_h = panel_h;
            float resp_h = panel_h;
            if (stack_editors) {
                req_h = std::max(124.f, (panel_h - 8.f) * 0.5f);
                resp_h = std::max(124.f, panel_h - req_h - 8.f);
            }


            ImGui::BeginChild("##rep_req", ImVec2(req_w, req_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Request");

            static char req_buf[65536] = {};
            static const repeater_entry_t* req_buf_owner = nullptr;
            static bool req_buf_dirty = false;
            if (req_buf_owner != &rep) {
                size_t copy_n = rep.raw_request.size() < (sizeof(req_buf) - 1)
                    ? rep.raw_request.size()
                    : (sizeof(req_buf) - 1);
                memcpy(req_buf, rep.raw_request.data(), copy_n);
                req_buf[copy_n] = '\0';
                req_buf_owner = &rep;
                req_buf_dirty = false;
            }
            if (ImGui::InputTextMultiline("##rep_req_edit", req_buf, sizeof(req_buf),
                ImVec2(req_w - 4.f, std::max(72.f, req_h - 78.f)))) {
                rep.raw_request = req_buf;
                req_buf_dirty = true;
            }

            if (!rep.in_progress.load()) {
                if (aida::ui::button("Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
                    if (req_buf_dirty) {
                        rep.raw_request = req_buf;
                        req_buf_dirty = false;
                    }
                    rep.in_progress.store(true);
                    std::shared_ptr<repeater_entry_t> entry = rep_ptr;
                    diag::log_tagged_fmt("network", "repeater_send_clicked host=%s:%u tls=%d req_size=%zu",
                        entry->host.c_str(), entry->port, entry->use_tls ? 1 : 0,
                        entry->raw_request.size());
                    anti_tamper::webhook::write_log("net_audit",
                        (std::string("[net_audit] repeater send host=") + entry->host + ":" +
                         std::to_string(entry->port) + " tls=" + (entry->use_tls ? "1" : "0")).c_str());
                    const bool posted = post_network_task("repeater_send", aida::infra::executor::domain_t::external_tool, "bounded_task", [entry]() {
                        std::vector<uint8_t> raw(entry->raw_request.begin(), entry->raw_request.end());
                        auto t0 = GetTickCount64();
                        auto result = mitm_proxy::repeat_request(
                            entry->host, entry->port, entry->use_tls, raw);
                        uint64_t elapsed = GetTickCount64() - t0;
                        if (result.success) {
                            entry->raw_response = std::string(result.exchange.raw_response.begin(),
                                result.exchange.raw_response.end());
                            entry->status_code = result.exchange.response.status_code;
                            entry->latency_ms = result.exchange.latency_ms;
                            diag::log_tagged_fmt("network", "repeater_send_ok host=%s:%u status=%d size=%zu latency_ms=%llu wall_ms=%llu",
                                entry->host.c_str(), entry->port, entry->status_code,
                                entry->raw_response.size(),
                                static_cast<unsigned long long>(entry->latency_ms),
                                static_cast<unsigned long long>(elapsed));
                        } else {
                            entry->raw_response = "Error: " + result.error;
                            entry->status_code = 0;
                            diag::log_tagged_fmt("network", "repeater_send_failed host=%s:%u err='%s' wall_ms=%llu",
                                entry->host.c_str(), entry->port, result.error.c_str(),
                                static_cast<unsigned long long>(elapsed));
                            anti_tamper::webhook::write_log("net_audit",
                                (std::string("[net_audit] repeater send FAILED err='") + result.error + "'").c_str());
                        }
                        entry->in_progress.store(false);
                    });
                    if (!posted) {
                        entry->raw_response = "Error: executor rejected repeater_send";
                        entry->status_code = 0;
                        entry->in_progress.store(false);
                    }
                }
            } else {
                aida::ui::pill_kind("Sending...", aida::ui::pill_kind_t::accent,
                                     aida::ui::size_t_::sm, true);
            }

            ImGui::EndChild();

            if (stack_editors) {
                ImGui::Dummy(ImVec2(0.f, 8.f));
            } else {
                ImGui::SameLine();
            }


            ImGui::BeginChild("##rep_resp", ImVec2(resp_w, resp_h), false, ImGuiWindowFlags_NoBackground);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                               "Response");

            if (rep.status_code > 0) {
                ImGui::SameLine();
                ImU32 sc_col = aida::ui::with_alpha(status_code_color(rep.status_code), alpha);
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(sc_col), " %d", rep.status_code);
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                    " %llums", static_cast<unsigned long long>(rep.latency_ms));
            }

            ImGui::InputTextMultiline("##rep_resp_view", rep.raw_response.data(),
                rep.raw_response.size() + 1,
                ImVec2(resp_w - 4.f, std::max(72.f, resp_h - 78.f)),
                ImGuiInputTextFlags_ReadOnly);

            ImGui::EndChild();
        }
    } else {
        ImVec2 region_pos = ImGui::GetCursorScreenPos();
        ImVec2 region_size = ImVec2(w, h - ImGui::GetCursorPosY() - 8.f);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No repeater entries";
        cfg.body  = "Use New to create one, or Send to Repeater from proxy history.";
        aida::ui::empty_state::render(region_pos, region_size, cfg);
    }

    ImGui::EndChild();
}


static void render_intercept(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_intercept", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    bool running = mitm_proxy::is_running();
    if (!running) {
        ImVec2 region = ImVec2(w, h);
        ImVec2 region_pos = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::shield;
        cfg.title = "Proxy not running";
        cfg.body  = "Start the MITM proxy first to use intercept mode.";
        aida::ui::empty_state::render(region_pos, region, cfg);
        ImGui::EndChild();
        return;
    }

    bool intercept_changed = aida::ui::toggle_switch("##intercept_en", &state.intercept_enabled);
    if (intercept_changed) {
        diag::log_tagged_fmt("network", "intercept_enabled_toggled new=%d",
            state.intercept_enabled ? 1 : 0);
        mitm_proxy::set_intercept_enabled(state.intercept_enabled);
    }
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                       "Intercept Enabled");
    ImGui::SameLine();

    if (aida::ui::button("Forward All", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        diag::log_tagged("network", "intercept_forward_all_clicked");
        mitm_proxy::forward_all();
    }
    ImGui::SameLine();
    aida::ui::kbd_chip("Shift+F");
    ImGui::SameLine();
    if (aida::ui::button("Drop All", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        diag::log_tagged("network", "intercept_drop_all_clicked");
        mitm_proxy::drop_all();
    }
    ImGui::SameLine();
    aida::ui::kbd_chip("Shift+D");

    if (state.intercept_enabled) {
        ImGui::SameLine();
        aida::ui::pill_kind("INTERCEPTING", aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
    }

    ImGui::Spacing();


    auto held = mitm_proxy::get_held_exchanges();
    int held_count = static_cast<int>(held.size());
    if (held_count > s_intercept_ui.prev_held_count) {
        s_intercept_ui.border_flash.trigger();
        s_intercept_ui.label_flash.trigger();
    }
    s_intercept_ui.prev_held_count = held_count;

    float lbl_pulse = s_intercept_ui.label_flash.tick(aida::ui::clock::dt(), 1.6f);
    ImU32 lbl_col = aida::ui::mix(aida::ui::with_alpha(th.text_secondary, alpha),
                                   aida::ui::with_alpha(th.accent_u32, alpha),
                                   lbl_pulse);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(lbl_col),
                       "Held: %d", held_count);

    bool can_use_shortcuts = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                              !ImGui::IsAnyItemActive() && !ImGui::GetIO().WantTextInput;
    if (can_use_shortcuts) {
        bool shift = ImGui::GetIO().KeyShift;
        if (shift && ImGui::IsKeyPressed(ImGuiKey_F)) {
            diag::log_tagged("network", "intercept_forward_all_shortcut");
            anti_tamper::webhook::write_log("net_audit", "[net_audit] intercept Shift+F forward_all shortcut fired");
            mitm_proxy::forward_all();
        }
        if (shift && ImGui::IsKeyPressed(ImGuiKey_D)) {
            diag::log_tagged("network", "intercept_drop_all_shortcut");
            anti_tamper::webhook::write_log("net_audit", "[net_audit] intercept Shift+D drop_all shortcut fired");
            mitm_proxy::drop_all();
        }


        if (state.intercept_selected >= 0 && state.intercept_selected < static_cast<int>(held.size())) {
            auto& sel = held[static_cast<size_t>(state.intercept_selected)];
            if (!shift && ImGui::IsKeyPressed(ImGuiKey_F)) {
                diag::log_tagged_fmt("network", "intercept_forward_shortcut id=%llu",
                    static_cast<unsigned long long>(sel.id));
                mitm_proxy::forward_exchange(sel.id);
            }
            if (!shift && ImGui::IsKeyPressed(ImGuiKey_D)) {
                diag::log_tagged_fmt("network", "intercept_drop_shortcut id=%llu",
                    static_cast<unsigned long long>(sel.id));
                mitm_proxy::drop_exchange(sel.id);
            }
        }
    }

    ImGui::Spacing();


    float split_y = h * 0.45f;
    ImDrawList* dl_outer = ImGui::GetWindowDrawList();
    ImVec2 outer_pos = ImGui::GetCursorScreenPos();

    float border_v = s_intercept_ui.border_flash.tick(aida::ui::clock::dt(), 0.5f);

    ImGui::BeginChild("##held_list", ImVec2(w - 4.f, split_y), false, ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;

    dl->AddRectFilled(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                      aida::ui::with_alpha(th.panel_bg, alpha * 0.75f), 8.f);
    dl->AddRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                 aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);
    if (border_v > 0.001f) {
        ImU32 glow = aida::ui::with_alpha(th.accent_u32, border_v * alpha);
        dl->AddRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y),
                     glow, 8.f, 0, 2.f);
        for (int gi = 1; gi <= 3; ++gi) {
            float ga = (0.18f - (float)gi * 0.05f) * border_v * alpha;
            dl->AddRect(ImVec2(list_org.x - (float)gi, list_org.y - (float)gi),
                         ImVec2(list_org.x + list_sz.x + (float)gi, list_org.y + list_sz.y + (float)gi),
                         aida::ui::with_alpha(th.accent_glow, ga), 8.f + (float)gi, 0, 1.f);
        }
    }


    float cx = list_org.x + 8.f;
    float cy = list_org.y + ImGui::GetCursorPosY() + 4.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    float col_id = 50.f, col_method = 64.f, col_host = 200.f, col_path = 260.f, col_size = 80.f;

    dl->AddText(ImVec2(cx, cy), hdr_col, "ID"); cx += col_id;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Method"); cx += col_method;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Host"); cx += col_host;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Path"); cx += col_path;
    dl->AddText(ImVec2(cx, cy), hdr_col, "Size");
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);

    if (held.empty()) {
        ImGui::Dummy(ImVec2(list_sz.x - 16.f, split_y - 60.f));
        ImU32 dim = aida::ui::with_alpha(th.text_dim, alpha);
        const char* msg = "No exchanges held. Toggle Intercept Enabled to start capturing.";
        ImVec2 ts = ImGui::CalcTextSize(msg);
        dl->AddText(ImVec2(list_org.x + (list_sz.x - ts.x) * 0.5f,
                           list_org.y + split_y * 0.5f), dim, msg);
    }

    for (int i = 0; i < static_cast<int>(held.size()); i++) {
        auto& ex = held[static_cast<size_t>(i)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool is_sel = (state.intercept_selected == i);

        if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x + 2.f, abs_ry), ImVec2(list_org.x + list_sz.x - 2.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(list_org.x + 2.f, abs_ry), ImVec2(list_org.x + 4.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= list_org.x && mouse.x < list_org.x + list_sz.x - 4.f &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.intercept_selected = i;

        ImU32 txt_col = aida::ui::with_alpha(is_sel ? th.text_primary : th.text_secondary, alpha);
        cx = list_org.x + 8.f;

        char id_buf[16];
        snprintf(id_buf, sizeof(id_buf), "%llu", static_cast<unsigned long long>(ex.id));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, id_buf); cx += col_id;

        ImU32 method_col = ui_anim::http_method_color(ex.request.method.c_str(), alpha);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), method_col, ex.request.method.c_str()); cx += col_method;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, ex.target_host.c_str()); cx += col_host;

        std::string path_display = ex.request.uri.size() > 50 ? ex.request.uri.substr(0, 47) + "..." : ex.request.uri;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, path_display.c_str()); cx += col_path;

        char size_buf[32];
        snprintf(size_buf, sizeof(size_buf), "%zu B", ex.raw_request.size());
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_dim, alpha), size_buf);

        ImGui::SetCursorPosY(ry + row_h);
    }
    ImGui::EndChild();
    (void)dl_outer; (void)outer_pos;


    if (state.intercept_selected >= 0 && state.intercept_selected < static_cast<int>(held.size())) {
        auto& sel = held[static_cast<size_t>(state.intercept_selected)];
        static char mod_buf[65536] = {};
        static uint64_t mod_buf_loaded_id = 0;
        if (mod_buf_loaded_id != sel.id) {
            size_t copy_len = sel.raw_request.size() < (sizeof(mod_buf) - 1)
                ? sel.raw_request.size()
                : (sizeof(mod_buf) - 1);
            memcpy(mod_buf, sel.raw_request.data(), copy_len);
            mod_buf[copy_len] = '\0';
            mod_buf_loaded_id = sel.id;
        }

        ImGui::Spacing();
        if (aida::ui::button("Forward", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "intercept_forward_clicked id=%llu",
                static_cast<unsigned long long>(sel.id));
            mitm_proxy::forward_exchange(sel.id);
        }
        ImGui::SameLine();
        aida::ui::kbd_chip("F");
        ImGui::SameLine();
        if (aida::ui::button("Drop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "intercept_drop_clicked id=%llu",
                static_cast<unsigned long long>(sel.id));
            mitm_proxy::drop_exchange(sel.id);
        }
        ImGui::SameLine();
        aida::ui::kbd_chip("D");
        ImGui::SameLine();
        if (aida::ui::button("Forward Modified", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            size_t len = strlen(mod_buf);
            if (len > 0) {
                std::vector<uint8_t> mod_data(mod_buf, mod_buf + len);
                diag::log_tagged_fmt("network", "intercept_forward_modified id=%llu new_size=%zu",
                    static_cast<unsigned long long>(sel.id), len);
                mitm_proxy::forward_modified(sel.id, mod_data);
            } else {
                diag::log_tagged_fmt("network", "intercept_forward_modified id=%llu empty_buf_fallback_forward",
                    static_cast<unsigned long long>(sel.id));
                mitm_proxy::forward_exchange(sel.id);
            }
        }
        ImGui::SameLine();
        aida::ui::kbd_chip("M");
        ImGui::SameLine();
        if (aida::ui::button("Send to Repeater", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            auto rep = std::make_shared<repeater_entry_t>();
            rep->host = sel.target_host;
            rep->port = sel.target_port;
            rep->use_tls = sel.is_tls;
            rep->raw_request = std::string(sel.raw_request.begin(), sel.raw_request.end());
            diag::log_tagged_fmt("network", "intercept_send_to_repeater id=%llu host=%s:%u size=%zu",
                static_cast<unsigned long long>(sel.id), sel.target_host.c_str(), sel.target_port,
                rep->raw_request.size());
            state.repeater_entries.push_back(std::move(rep));
            state.repeater_selected = static_cast<int>(state.repeater_entries.size()) - 1;
        }
        ImGui::SameLine();
        if (aida::ui::button("Send to Fuzzer", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            state.fuzz_config.host = sel.target_host;
            state.fuzz_config.port = sel.target_port;
            state.fuzz_config.use_tls = sel.is_tls;
            state.fuzz_config.base_request = std::string(sel.raw_request.begin(), sel.raw_request.end());
            diag::log_tagged_fmt("network", "intercept_send_to_fuzzer id=%llu host=%s:%u size=%zu",
                static_cast<unsigned long long>(sel.id), sel.target_host.c_str(), sel.target_port,
                state.fuzz_config.base_request.size());
            state.active_tab = sub_tab_t::fuzzer;
        }

        ImGui::Spacing();


        const bool stack_editors = w < 760.f;
        float detail_h = h - ImGui::GetCursorPosY() + y - 8.f;
        if (detail_h < 170.f) detail_h = 170.f;
        ImGui::BeginChild("##intercept_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);

        float half_w = (w - 12.f) * 0.5f;
        float pane_w = stack_editors ? std::max(120.f, w - 8.f) : half_w;
        float pane_h = stack_editors ? std::max(128.f, (detail_h - 12.f) * 0.5f) : detail_h - 4.f;
        float edit_pane_h = stack_editors ? std::max(128.f, detail_h - pane_h - 12.f) : detail_h - 4.f;

        ImGui::BeginChild("##int_req_pane", ImVec2(pane_w, pane_h), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Original Request");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "%zu bytes", sel.raw_request.size());

        static char int_orig_buf[65536] = {};
        if (sel.raw_request.size() < sizeof(int_orig_buf)) {
            memcpy(int_orig_buf, sel.raw_request.data(), sel.raw_request.size());
            int_orig_buf[sel.raw_request.size()] = '\0';
        }
        ImGui::InputTextMultiline("##int_req_orig", int_orig_buf, sizeof(int_orig_buf),
            ImVec2(pane_w - 4.f, std::max(72.f, pane_h - 50.f)), ImGuiInputTextFlags_ReadOnly);
        ImGui::EndChild();

        if (stack_editors) {
            ImGui::Dummy(ImVec2(0.f, 8.f));
        } else {
            ImGui::SameLine();
        }

        ImGui::BeginChild("##int_req_edit_pane", ImVec2(pane_w, edit_pane_h), false, ImGuiWindowFlags_NoBackground);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Modified Request");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Editable buffer");
        ImGui::InputTextMultiline("##mod_buf", mod_buf, sizeof(mod_buf),
            ImVec2(pane_w - 4.f, std::max(72.f, edit_pane_h - 50.f)));
        ImGui::EndChild();

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_keylog(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_keylog", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "SSL Key Logger");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Executable:");
    ImGui::SameLine();
    aida::ui::input_text("##kl_exe", state.kl_exe_path, sizeof(state.kl_exe_path),
                          "C:\\path\\to\\target.exe", false, ImVec2(360.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Browse...##kl_browse", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        char path_buf[MAX_PATH] = {};
        static const char k_exe_open_filter[] =
            "Executable (*.exe)\0*.exe\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_open_file_dialog(g_hwnd,
                "Select Target Executable",
                k_exe_open_filter,
                path_buf, sizeof(path_buf),
                "network_view::keylog_exe")) {
            snprintf(state.kl_exe_path, sizeof(state.kl_exe_path), "%s", path_buf);
            diag::log_tagged_fmt("network", "keylog_exe_picked path='%s'", path_buf);
            anti_tamper::webhook::write_log("net_audit",
                (std::string("[net_audit] keylog exe picked path='") + path_buf + "'").c_str());
        }
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Arguments:");
    ImGui::SameLine();
    aida::ui::input_text("##kl_args", state.kl_args, sizeof(state.kl_args),
                          "Arguments to pass...", false, ImVec2(360.f, 28.f));

    ImGui::Spacing();

    if (!ssl_keylog::g_state.watching.load()) {
        if (aida::ui::button("Launch & Watch", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "keylog_launch_clicked exe='%s' args='%s'",
                state.kl_exe_path, state.kl_args);
            auto result = ssl_keylog::launch_with_keylog(state.kl_exe_path, state.kl_args);
            if (result.success) {
                diag::log_tagged_fmt("network", "keylog_launch_ok pid=%u keylog='%s'",
                    result.pid, result.keylog_path.c_str());
                ssl_keylog::start_watching(result.keylog_path);
                toast_notification::push("SSL keylog: process launched, watching key file",
                    toast_notification::toast_type_t::info);
            } else {
                diag::log_tagged_fmt("network", "keylog_launch_failed err='%s'", result.error.c_str());
                toast_notification::push(std::string("Failed to launch: ") + result.error,
                    toast_notification::toast_type_t::error);
            }
        }
        ImGui::SameLine();
        if (aida::ui::button("Watch File...", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            char path_buf[MAX_PATH] = {};
            static const char k_keylog_open_filter[] =
                "SSL Keylog (*.log;*.keylog;*.txt)\0*.log;*.keylog;*.txt\0"
                "All files (*.*)\0*.*\0\0";
            if (win32_dialog::show_open_file_dialog(g_hwnd,
                    "Watch SSLKEYLOGFILE",
                    k_keylog_open_filter,
                    path_buf, sizeof(path_buf),
                    "network_view::keylog_watch")) {
                snprintf(state.kl_watch_path, sizeof(state.kl_watch_path), "%s", path_buf);
                diag::log_tagged_fmt("network", "keylog_watch_dialog_pick path='%s'", path_buf);
                anti_tamper::webhook::write_log("net_audit",
                    (std::string("[net_audit] keylog watch dialog path='") + path_buf + "'").c_str());
                ssl_keylog::start_watching(path_buf);
            } else {
                diag::log_tagged("network", "keylog_watch_dialog_cancelled");
            }
        }
        ImGui::SameLine();
        aida::ui::input_text("##kl_watch_path", state.kl_watch_path, sizeof(state.kl_watch_path),
                              "or paste a keylog path...", false, ImVec2(260.f, 28.f));
        ImGui::SameLine();
        bool can_use_typed = state.kl_watch_path[0] != '\0';
        if (aida::ui::button("Watch", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), !can_use_typed) && can_use_typed) {
            diag::log_tagged_fmt("network", "keylog_watch_typed path='%s'", state.kl_watch_path);
            anti_tamper::webhook::write_log("net_audit",
                (std::string("[net_audit] keylog watch typed path='") + state.kl_watch_path + "'").c_str());
            ssl_keylog::start_watching(state.kl_watch_path);
        }
    } else {
        char watch_buf[640];
        snprintf(watch_buf, sizeof(watch_buf), "Watching: %s", ssl_keylog::g_state.keylog_path.c_str());
        aida::ui::pill_kind(watch_buf, aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        if (aida::ui::button("Stop Watching", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "keylog_stop_watching path='%s' entries=%zu",
                ssl_keylog::g_state.keylog_path.c_str(), ssl_keylog::entry_count());
            ssl_keylog::stop_watching();
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            size_t prev = ssl_keylog::entry_count();
            ssl_keylog::clear_entries();
            diag::log_tagged_fmt("network", "keylog_cleared prev_entry_count=%zu", prev);
        }
    }

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Captured Keys: %zu", ssl_keylog::entry_count());

    ImGui::Spacing();


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    ImVec2 cursor = ImGui::GetCursorPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float hdr_h = std::max(28.f, ImGui::GetFontSize() + 9.f);
    float hdr_y = org.y + cursor.y;

    float col_time = 100.f, col_label = 220.f, col_cr = 220.f, col_sec_min = 220.f;
    (void)col_sec_min;

    dl->AddRectFilled(ImVec2(org.x, hdr_y), ImVec2(org.x + w, hdr_y + hdr_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, org.x, hdr_y, w, hdr_h, ar, ag, ab, alpha * 0.30f);

    float cx = org.x + 8.f;
    float hdr_text_y = hdr_y + (hdr_h - ImGui::GetFontSize()) * 0.5f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Time");          cx += col_time;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Label");         cx += col_label;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Client Random"); cx += col_cr;
    dl->AddText(ImVec2(cx, hdr_text_y), hdr_col, "Secret");

    ImGui::SetCursorPosY(cursor.y + hdr_h + 4.f);
    dl->AddLine(ImVec2(org.x, hdr_y + hdr_h - 1.f), ImVec2(org.x + w, hdr_y + hdr_h - 1.f),
                aida::ui::with_alpha(th.border_subtle, alpha));

    float list_h = h - (cursor.y + hdr_h + 12.f);
    ImGui::BeginChild("##kl_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);

    auto entries = ssl_keylog::get_entries(500);
    ImVec2 list_org = ImGui::GetWindowPos();
    ImVec2 list_sz  = ImGui::GetWindowSize();
    dl->PushClipRect(list_org, ImVec2(list_org.x + list_sz.x, list_org.y + list_sz.y), true);

    if (entries.empty()) {
        dl->PopClipRect();
        ImGui::EndChild();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::key;
        cfg.title = "No keys captured";
        cfg.body  = "Launch a target executable or watch a SSLKEYLOGFILE to start collecting TLS secrets.";
        aida::ui::empty_state::render(ImVec2(list_org.x, list_org.y), ImVec2(list_sz.x, list_h), cfg);
        ImGui::EndChild();
        return;
    }

    for (int i = static_cast<int>(entries.size()) - 1; i >= 0; i--) {
        auto& e = entries[static_cast<size_t>(i)];

        float row_alpha = 1.f;
        float row_yoff = 0.f;
        compute_row_entrance(s_kl_rows, entries.size(), row_alpha, row_yoff,
                              static_cast<int>(entries.size()) - 1 - i);
        float r_alpha = alpha * row_alpha;

        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool is_sel = (state.kl_selected == i);

        if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + list_sz.x, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        ImVec2 mouse = ImGui::GetMousePos();
        bool hov = (mouse.x >= list_org.x && mouse.x < list_org.x + list_sz.x &&
                    mouse.y >= abs_ry && mouse.y < abs_ry + row_h);
        if (hov && !is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + list_sz.x, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha), 4.f);
        }
        if (hov && ImGui::IsMouseClicked(0))
            state.kl_selected = i;


        std::string cr_short = e.client_random_hex.substr(0, 24) + "...";
        std::string sec_short = e.secret_hex.size() > 24 ? e.secret_hex.substr(0, 24) + "..." : e.secret_hex;

        ImU32 label_col;
        if (e.label == "CLIENT_RANDOM")
            label_col = aida::ui::with_alpha(th.info, r_alpha);
        else if (e.label.find("HANDSHAKE") != std::string::npos)
            label_col = aida::ui::with_alpha(th.warning, r_alpha);
        else
            label_col = aida::ui::with_alpha(th.success, r_alpha);

        cx = list_org.x + 8.f;
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_dim, r_alpha),
                     format_timestamp(e.timestamp).c_str());
        cx += col_time;

        dl->AddText(ImVec2(cx, abs_ry + text_oy), label_col, e.label.c_str());
        cx += col_label;

        ImFont* mono_font = aida::ui::fonts::code();
        bool pushed = false;
        if (mono_font) {
            ImGui::PushFont(mono_font);
            pushed = true;
        }
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_secondary, r_alpha), cr_short.c_str());
        cx += col_cr;
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
                     aida::ui::with_alpha(th.text_secondary, r_alpha), sec_short.c_str());
        if (pushed) ImGui::PopFont();

        ImGui::SetCursorPosY(ry + row_h);
    }
    dl->PopClipRect();

    if (state.kl_auto_scroll && !entries.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    if (state.kl_selected >= 0 && state.kl_selected < static_cast<int>(entries.size())) {
        auto& e = entries[static_cast<size_t>(state.kl_selected)];
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                            "Selected: %s  -  %s", e.label.c_str(), format_timestamp(e.timestamp).c_str());
        if (aida::ui::button("Copy Client Random", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            ImGui::SetClipboardText(e.client_random_hex.c_str());
        }
        ImGui::SameLine();
        if (aida::ui::button("Copy Secret", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            ImGui::SetClipboardText(e.secret_hex.c_str());
        }
        ImGui::SameLine();
        if (aida::ui::button("Copy Line", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            std::string line = e.label + " " + e.client_random_hex + " " + e.secret_hex;
            ImGui::SetClipboardText(line.c_str());
        }
    }

    ImGui::EndChild();
}


static void write_pcap_header(std::ofstream& f) {

    uint32_t magic = 0xa1b2c3d4;
    uint16_t ver_major = 2, ver_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 1;
    f.write(reinterpret_cast<const char*>(&magic), 4);
    f.write(reinterpret_cast<const char*>(&ver_major), 2);
    f.write(reinterpret_cast<const char*>(&ver_minor), 2);
    f.write(reinterpret_cast<const char*>(&thiszone), 4);
    f.write(reinterpret_cast<const char*>(&sigfigs), 4);
    f.write(reinterpret_cast<const char*>(&snaplen), 4);
    f.write(reinterpret_cast<const char*>(&network), 4);
}

static void write_pcap_packet(std::ofstream& f, const packet_entry_t& pkt) {

    uint32_t ts_sec = static_cast<uint32_t>(pkt.timestamp / 1000);
    uint32_t ts_usec = static_cast<uint32_t>((pkt.timestamp % 1000) * 1000);


    uint32_t transport_hdr_len = (pkt.protocol == 6) ? 20 : 8;
    uint32_t ip_total_len = 20 + transport_hdr_len + pkt.payload_size;
    uint32_t frame_len = 14 + ip_total_len;

    std::vector<uint8_t> frame(frame_len, 0);


    frame[12] = 0x08; frame[13] = 0x00;


    uint8_t* ip = frame.data() + 14;
    ip[0] = 0x45;
    ip[2] = static_cast<uint8_t>((ip_total_len >> 8) & 0xff);
    ip[3] = static_cast<uint8_t>(ip_total_len & 0xff);
    ip[8] = 64;
    ip[9] = pkt.protocol;


    if (pkt.direction == 1) {
        memcpy(ip + 12, pkt.src_addr, 4);
        memcpy(ip + 16, pkt.dst_addr, 4);
    } else {
        memcpy(ip + 12, pkt.dst_addr, 4);
        memcpy(ip + 16, pkt.src_addr, 4);
    }


    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += (static_cast<uint32_t>(ip[i]) << 8) | ip[i + 1];
    while (cksum >> 16) cksum = (cksum & 0xffff) + (cksum >> 16);
    uint16_t ip_cksum = static_cast<uint16_t>(~cksum);
    ip[10] = static_cast<uint8_t>(ip_cksum >> 8);
    ip[11] = static_cast<uint8_t>(ip_cksum & 0xff);


    uint8_t* th = ip + 20;
    uint16_t sp = pkt.direction == 1 ? pkt.src_port : pkt.dst_port;
    uint16_t dp = pkt.direction == 1 ? pkt.dst_port : pkt.src_port;
    th[0] = static_cast<uint8_t>(sp >> 8); th[1] = static_cast<uint8_t>(sp & 0xff);
    th[2] = static_cast<uint8_t>(dp >> 8); th[3] = static_cast<uint8_t>(dp & 0xff);
    if (pkt.protocol == 6) {
        th[12] = 0x50;
        th[13] = 0x18;
    } else {
        uint16_t udp_len = static_cast<uint16_t>(8 + pkt.payload_size);
        th[4] = static_cast<uint8_t>(udp_len >> 8);
        th[5] = static_cast<uint8_t>(udp_len & 0xff);
    }


    if (pkt.payload_size > 0 && !pkt.payload.empty()) {
        memcpy(th + transport_hdr_len, pkt.payload.data(),
            std::min<size_t>(pkt.payload_size, pkt.payload.size()));
    }


    f.write(reinterpret_cast<const char*>(&ts_sec), 4);
    f.write(reinterpret_cast<const char*>(&ts_usec), 4);
    f.write(reinterpret_cast<const char*>(&frame_len), 4);
    f.write(reinterpret_cast<const char*>(&frame_len), 4);
    f.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame_len));
}

static void render_pcap_export(state_t& state, float x, float y, float w, float h,
                                float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab; (void)w; (void)h;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_pcap", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "PCAP Export");
    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Output File:");
    ImGui::SameLine();
    aida::ui::input_text("##pcap_path", state.pcap_path, sizeof(state.pcap_path),
                          "C:\\path\\to\\capture.pcap", false, ImVec2(420.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Browse...##pcap_browse", aida::ui::button_kind_t::secondary,
                          aida::ui::size_t_::sm)) {
        char path_buf[MAX_PATH] = {};
        if (state.pcap_path[0])
            snprintf(path_buf, sizeof(path_buf), "%s", state.pcap_path);
        static const char k_pcap_save_filter[] =
            "Packet Capture (*.pcap)\0*.pcap\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_save_file_dialog(g_hwnd,
                "Save PCAP",
                k_pcap_save_filter,
                "pcap",
                path_buf, sizeof(path_buf),
                "network_view::pcap_save")) {
            snprintf(state.pcap_path, sizeof(state.pcap_path), "%s", path_buf);
            diag::log_tagged_fmt("network", "pcap_path_picked path='%s'", path_buf);
            anti_tamper::webhook::write_log("net_audit",
                (std::string("[net_audit] pcap path picked path='") + path_buf + "'").c_str());
        }
    }

    if (state.pcap_path[0] == '\0') {
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        snprintf(state.pcap_path, sizeof(state.pcap_path), "%saida_capture.pcap", temp);
    }

    ImGui::Spacing();

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Filter PID:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.f);
    int fpid = static_cast<int>(state.pcap_filter_pid);
    if (ImGui::InputInt("##pcap_fpid", &fpid, 0, 0))
        state.pcap_filter_pid = static_cast<uint32_t>(std::max(0, fpid));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "(0 = all)");

    ImGui::SameLine(0, 20.f);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Protocol:");
    ImGui::SameLine();
    const char* proto_names[] = { "All", "TCP", "UDP" };
    int proto_idx = state.pcap_filter_protocol == 6 ? 1 : (state.pcap_filter_protocol == 17 ? 2 : 0);
    ImGui::SetNextItemWidth(100.f);
    if (ImGui::Combo("##pcap_proto", &proto_idx, proto_names, 3)) {
        state.pcap_filter_protocol = proto_idx == 1 ? 6 : (proto_idx == 2 ? 17 : 0);
    }

    ImGui::Spacing();

    size_t cap_count = 0;
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        cap_count = state.captured_packets.size();
    }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Captured packets available: %zu", cap_count);

    ImGui::Spacing();

    if (!state.pcap_writing.load()) {
        bool can_export = state.pcap_path[0] != '\0' && cap_count > 0;
        if (aida::ui::button("Export to PCAP", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), !can_export)) {
            state.pcap_writing.store(true);
            state.pcap_written_count.store(0);
            {
                std::lock_guard<std::mutex> elock(state.pcap_error_mutex);
                state.pcap_last_error.clear();
            }


            std::deque<packet_entry_t> packets_copy;
            {
                std::lock_guard<std::mutex> lock(state.cap_mutex);
                packets_copy = state.captured_packets;
            }

            auto path = std::string(state.pcap_path);
            auto filter_pid = state.pcap_filter_pid;
            auto filter_proto = state.pcap_filter_protocol;

            diag::log_tagged_fmt("network", "pcap_export_clicked path='%s' filter_pid=%u filter_proto=%u source_packets=%zu",
                path.c_str(), filter_pid, filter_proto, packets_copy.size());
            anti_tamper::webhook::write_log("net_audit",
                ("[net_audit] pcap export start path='" + path + "'").c_str());

            const bool posted = post_network_task("pcap_export", aida::infra::executor::domain_t::diagnostics, "bounded_task", [packets_copy = std::move(packets_copy), path, filter_pid, filter_proto,
                         st = &state]() {
                std::ofstream f(path, std::ios::binary);
                if (!f.is_open()) {
                    diag::log_tagged_fmt("network", "pcap_export_failed_open path='%s'", path.c_str());
                    anti_tamper::webhook::write_log("net_audit",
                        ("[net_audit] pcap export FAILED open path='" + path + "'").c_str());
                    {
                        std::lock_guard<std::mutex> elock(st->pcap_error_mutex);
                        st->pcap_last_error = "Cannot open '" + path + "' for writing";
                    }
                    st->pcap_writing.store(false);
                    return;
                }
                write_pcap_header(f);

                uint32_t count = 0;
                for (auto& pkt : packets_copy) {
                    if (filter_pid != 0 && pkt.pid != filter_pid) continue;
                    if (filter_proto != 0 && pkt.protocol != filter_proto) continue;
                    write_pcap_packet(f, pkt);
                    count++;
                }
                st->pcap_written_count.store(count);
                f.close();
                st->pcap_writing.store(false);
                diag::log_tagged_fmt("network", "pcap_export_done path='%s' written=%u",
                    path.c_str(), count);
                anti_tamper::webhook::write_log("net_audit",
                    ("[net_audit] pcap export ok path='" + path + "' written=" + std::to_string(count)).c_str());
            });
            if (!posted) {
                std::lock_guard<std::mutex> elock(state.pcap_error_mutex);
                state.pcap_last_error = "Executor rejected PCAP export";
                state.pcap_writing.store(false);
            }
        }
        if (!can_export) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Capture some packets first or set a valid output path.");
        }
    } else {
        aida::ui::pill_kind("Writing PCAP file...", aida::ui::pill_kind_t::accent,
                             aida::ui::size_t_::sm, true);
    }

    {
        std::string err_copy;
        {
            std::lock_guard<std::mutex> elock(state.pcap_error_mutex);
            err_copy = state.pcap_last_error;
        }
        if (!err_copy.empty()) {
            ImGui::Spacing();
            aida::ui::pill_kind(err_copy.c_str(), aida::ui::pill_kind_t::error,
                                 aida::ui::size_t_::sm, true);
        }
    }

    uint32_t exported_count = state.pcap_written_count.load();
    if (exported_count > 0 && !state.pcap_writing.load()) {
        ImGui::Spacing();
        char done_buf[640];
        snprintf(done_buf, sizeof(done_buf), "Exported %u packets to %s",
                 exported_count, state.pcap_path);
        aida::ui::pill_kind(done_buf, aida::ui::pill_kind_t::success, aida::ui::size_t_::sm, false);
    }


    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Export Proxy History");
    ImGui::Spacing();

    size_t proxy_count = mitm_proxy::history_count();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Proxy exchanges available: %zu", proxy_count);

    if (aida::ui::button("Export Proxy as HAR", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        char har_buf[MAX_PATH] = {};
        char temp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, temp);
        snprintf(har_buf, sizeof(har_buf), "%saida_proxy_export.har", temp);
        static const char k_har_save_filter[] =
            "HTTP Archive (*.har)\0*.har\0"
            "JSON (*.json)\0*.json\0"
            "All files (*.*)\0*.*\0\0";
        if (!win32_dialog::show_save_file_dialog(g_hwnd,
                "Export HAR",
                k_har_save_filter,
                "har",
                har_buf, sizeof(har_buf),
                "network_view::har_save")) {
            diag::log_tagged("network", "har_export_dialog_cancelled");
            anti_tamper::webhook::write_log("net_audit",
                "[net_audit] HAR export dialog cancelled");
        } else {
        std::string har_path(har_buf);

        auto history = mitm_proxy::get_history(0);
        diag::log_tagged_fmt("network", "har_export_clicked path='%s' history_count=%zu",
            har_path.c_str(), history.size());
        anti_tamper::webhook::write_log("net_audit",
            (std::string("[net_audit] HAR export path='") + har_path + "' count=" +
             std::to_string(history.size())).c_str());
        (void)post_network_task("har_export", aida::infra::executor::domain_t::diagnostics, "bounded_task", [history = std::move(history), har_path]() {

            std::ofstream f(har_path);
            if (!f.is_open()) {
                diag::log_tagged_fmt("network", "har_export_failed_open path='%s'", har_path.c_str());
                return;
            }

            f << "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"entries\": [\n";
            for (size_t i = 0; i < history.size(); i++) {
                auto& ex = history[i];
                if (i > 0) f << ",\n";
                f << "      {\n";
                f << "        \"request\": {\n";
                f << "          \"method\": \"" << ex.request.method << "\",\n";
                f << "          \"url\": \"" << (ex.is_tls ? "https://" : "http://")
                  << ex.target_host << ex.request.uri << "\",\n";
                f << "          \"httpVersion\": \"" << ex.request.version << "\",\n";
                f << "          \"bodySize\": " << ex.request_size << "\n";
                f << "        },\n";
                f << "        \"response\": {\n";
                f << "          \"status\": " << ex.response.status_code << ",\n";
                f << "          \"statusText\": \"" << ex.response.reason << "\",\n";
                f << "          \"bodySize\": " << ex.response_size << "\n";
                f << "        },\n";
                f << "        \"time\": " << ex.latency_ms << "\n";
                f << "      }";
            }
            f << "\n    ]\n  }\n}\n";
            f.close();
            diag::log_tagged_fmt("network", "har_export_done path='%s' entries=%zu",
                har_path.c_str(), history.size());
        });
        }
    }

    ImGui::EndChild();
}


static void run_fuzzer_thread(state_t& state) {
    auto& cfg = state.fuzz_config;


    auto load_set = [](const payload_set_t& ps) -> std::vector<std::string> {
        std::vector<std::string> lines;
        auto push_line = [&](std::istream& is) {
            std::string line;
            while (std::getline(is, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty()) lines.push_back(std::move(line));
            }
        };
        if (ps.type == 0) {
            std::ifstream f(ps.source);
            if (f.is_open()) push_line(f);
        } else {
            std::istringstream ss(ps.source);
            push_line(ss);
        }
        return lines;
    };


    auto load_legacy_set = [&]() -> std::vector<std::string> {
        payload_set_t tmp;
        tmp.type   = cfg.payload_type;
        tmp.source = cfg.payload_source;
        if (cfg.payload_type == 1) {
            std::vector<std::string> nums;
            int start_n = 0, end_n = 100;
            if (sscanf(cfg.payload_source.c_str(), "%d-%d", &start_n, &end_n) >= 1)
                for (int n = start_n; n <= end_n; n++)
                    nums.push_back(std::to_string(n));
            return nums;
        } else if (cfg.payload_type == 2) {
            std::string charset = cfg.payload_source.empty()
                ? "abcdefghijklmnopqrstuvwxyz0123456789" : cfg.payload_source;
            std::vector<std::string> v;
            for (char c : charset) v.push_back(std::string(1, c));
            for (char a : charset)
                for (char b : charset)
                    v.push_back(std::string(1, a) + b);
            return v;
        }
        return load_set(tmp);
    };


    auto make_request_multi = [](const std::string& tmpl,
                                  const std::vector<std::string>& payloads) -> std::string {
        const std::string marker = "\xc2\xa7";
        std::string result;
        result.reserve(tmpl.size() + 512);
        size_t pos = 0;
        size_t pi  = 0;
        while (pos < tmpl.size()) {
            size_t s = tmpl.find(marker, pos);
            if (s == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
            size_t e = tmpl.find(marker, s + marker.size());
            if (e == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
            result.append(tmpl, pos, s - pos);
            if (pi < payloads.size()) result.append(payloads[pi]);
            pi++;
            pos = e + marker.size();
        }

        if (!payloads.empty()) {
            size_t fp = 0;
            const std::string fuzz_tok = "FUZZ";
            while ((fp = result.find(fuzz_tok, fp)) != std::string::npos) {
                result.replace(fp, fuzz_tok.size(), payloads[0]);
                fp += payloads[0].size();
            }
        }
        return result;
    };


    auto do_grep_extract = [](const std::string& body,
                               const char* re_str,
                               const char* grp_str) -> std::string {
        if (!re_str || re_str[0] == '\0') return {};
        try {
            std::regex re(re_str);
            std::smatch m;
            if (std::regex_search(body, m, re)) {
                int grp = 1;
                if (grp_str && grp_str[0] != '\0') {
                    char* end = nullptr;
                    errno = 0;
                    long v = strtol(grp_str, &end, 10);
                    if (errno == 0 && end != grp_str && v >= 0 && v <= INT_MAX) {
                        grp = static_cast<int>(v);
                    }
                }
                if (grp >= 0 && grp < static_cast<int>(m.size()))
                    return m[static_cast<size_t>(grp)].str();
            }
        } catch (...) {}
        return {};
    };


    auto check_match = [&](int sc, const std::string& body, size_t len) -> bool {
        if (cfg.match_status > 0 && sc != cfg.match_status) return false;
        if (!cfg.match_body.empty() && body.find(cfg.match_body) == std::string::npos) return false;
        if (cfg.match_size_op == 1 && static_cast<int>(len) != cfg.match_size) return false;
        if (cfg.match_size_op == 2 && static_cast<int>(len) <= cfg.match_size) return false;
        if (cfg.match_size_op == 3 && static_cast<int>(len) >= cfg.match_size) return false;
        return true;
    };


    using combo_t = std::vector<std::string>;
    std::vector<combo_t> combos;

    switch (cfg.attack_mode) {

        case fuzzer_attack_mode_t::sniper: {
            std::vector<std::string> payloads = cfg.payload_sets.empty()
                ? load_legacy_set()
                : load_set(cfg.payload_sets[0]);
            combos.reserve(payloads.size());
            for (auto& p : payloads) combos.push_back({ p });
            break;
        }

        case fuzzer_attack_mode_t::pitchfork: {
            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
            std::vector<std::vector<std::string>> sets;
            sets.reserve(cfg.payload_sets.size());
            for (auto& ps : cfg.payload_sets) {
                sets.push_back(load_set(ps));
                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
            }
            size_t min_len = sets[0].size();
            for (auto& s : sets) min_len = std::min(min_len, s.size());
            combos.reserve(min_len);
            for (size_t i = 0; i < min_len; i++) {
                combo_t c;
                c.reserve(sets.size());
                for (auto& s : sets) c.push_back(s[i]);
                combos.push_back(std::move(c));
            }
            break;
        }

        case fuzzer_attack_mode_t::clusterbomb: {
            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
            std::vector<std::vector<std::string>> sets;
            sets.reserve(cfg.payload_sets.size());
            for (auto& ps : cfg.payload_sets) {
                sets.push_back(load_set(ps));
                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
            }

            combos.push_back(combo_t{});
            for (auto& s : sets) {
                std::vector<combo_t> next;
                next.reserve(combos.size() * s.size());
                for (auto& base : combos)
                    for (auto& val : s) {
                        combo_t nc = base;
                        nc.push_back(val);
                        next.push_back(std::move(nc));
                    }
                combos = std::move(next);
            }
            break;
        }
    }

    if (combos.empty()) {
        diag::log_tagged_fmt("network", "fuzzer_no_combos attack_mode=%d sets=%zu",
            static_cast<int>(cfg.attack_mode), cfg.payload_sets.size());
        state.fuzz_running.store(false);
        return;
    }

    state.fuzz_total.store(static_cast<int>(combos.size()));
    state.fuzz_progress.store(0);

    std::atomic<int> next_index{0};
    int total   = static_cast<int>(combos.size());
    int threads = std::min(std::max(cfg.thread_count, 1), 32);
    diag::log_tagged_fmt("network", "fuzzer_run_start host=%s:%u tls=%d mode=%d combos=%d threads=%d",
        cfg.host.c_str(), cfg.port, cfg.use_tls ? 1 : 0,
        static_cast<int>(cfg.attack_mode), total, threads);

    auto worker = [&]() {
        while (state.fuzz_running.load()) {
            int idx = next_index.fetch_add(1);
            if (idx >= total) break;

            auto& combo       = combos[static_cast<size_t>(idx)];
            std::string req_s = make_request_multi(cfg.base_request, combo);
            std::vector<uint8_t> raw_req(req_s.begin(), req_s.end());

            auto t0 = GetTickCount64();
            auto res = mitm_proxy::repeat_request(cfg.host, cfg.port, cfg.use_tls, raw_req);
            auto elapsed = GetTickCount64() - t0;

            state_t::fuzzer_result_t fr;
            fr.index     = idx;
            fr.payloads  = combo;
            fr.payload   = combo.empty() ? std::string() : combo[0];
            fr.latency_ms = elapsed;

            if (res.success) {
                fr.status_code  = res.exchange.response.status_code;
                fr.response_len = res.exchange.raw_response.size();
                std::string body(res.exchange.raw_response.begin(),
                                 res.exchange.raw_response.end());
                fr.response_preview = body.substr(0, std::min<size_t>(200, body.size()));
                fr.match = check_match(fr.status_code, body, fr.response_len);


                if (!cfg.payload_sets.empty()) {
                    fr.extracted_value = do_grep_extract(body,
                        cfg.payload_sets[0].grep_regex,
                        cfg.payload_sets[0].grep_group);
                }
            }

            {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                state.fuzz_results.push_back(std::move(fr));
            }
            state.fuzz_progress.fetch_add(1);

            if (cfg.stop_on_match && fr.match) {
                state.fuzz_running.store(false);
                break;
            }
            if (cfg.delay_ms > 0) Sleep(static_cast<DWORD>(cfg.delay_ms));
        }
    };

    std::atomic<int> remaining{threads};
    std::mutex done_mtx;
    std::condition_variable done_cv;

    for (int t = 0; t < threads; t++) {
        const bool posted = post_network_task("fuzzer_worker", aida::infra::executor::domain_t::long_running, "long_running", [&worker, &remaining, &done_cv]() {
            worker();
            if (--remaining == 0)
                done_cv.notify_all();
        });
        if (!posted && --remaining == 0)
            done_cv.notify_all();
    }
    {
        std::unique_lock<std::mutex> lk(done_mtx);
        done_cv.wait(lk, [&remaining]() { return remaining.load() == 0; });
    }

    int final_progress = state.fuzz_progress.load();
    size_t result_count = 0;
    int match_count = 0;
    {
        std::lock_guard<std::mutex> lk(state.fuzz_mutex);
        result_count = state.fuzz_results.size();
        for (auto& fr : state.fuzz_results) if (fr.match) match_count++;
    }
    diag::log_tagged_fmt("network", "fuzzer_run_complete combos=%d processed=%d results=%zu matches=%d",
        total, final_progress, result_count, match_count);

    state.fuzz_running.store(false);
}

static void render_fuzzer(state_t& state, float x, float y, float w, float h,
                           float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_fuzzer", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Fuzzer / Intruder");
    ImGui::Spacing();

    auto& cfg = state.fuzz_config;


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Host:");
    ImGui::SameLine();
    static char fuzz_host[256] = {};
    if (cfg.host.size() < sizeof(fuzz_host)) { memcpy(fuzz_host, cfg.host.c_str(), cfg.host.size() + 1); }
    if (aida::ui::input_text("##fuzz_host", fuzz_host, sizeof(fuzz_host),
                              "target.example.com", false, ImVec2(220.f, 28.f)))
        cfg.host = fuzz_host;
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Port:");
    ImGui::SameLine();
    int fp = cfg.port;
    if (aida::ui::input_int("##fuzz_port", &fp, ImVec2(80.f, 28.f)))
        cfg.port = static_cast<uint16_t>(std::max(1, std::min(65535, fp)));
    ImGui::SameLine();
    aida::ui::toggle_switch("##fuzz_tls", &cfg.use_tls);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "TLS");

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Attack Mode:");
    ImGui::SameLine();
    int am = static_cast<int>(cfg.attack_mode);
    if (aida::ui::radio_button("Sniper##fuzz",      &am, 0)) cfg.attack_mode = fuzzer_attack_mode_t::sniper;
    ImGui::SameLine();
    if (aida::ui::radio_button("Pitchfork##fuzz",   &am, 1)) cfg.attack_mode = fuzzer_attack_mode_t::pitchfork;
    ImGui::SameLine();
    if (aida::ui::radio_button("Clusterbomb##fuzz", &am, 2)) cfg.attack_mode = fuzzer_attack_mode_t::clusterbomb;

    ImGui::Spacing();


    if (cfg.attack_mode == fuzzer_attack_mode_t::sniper) {

        const char* payload_types[] = { "Wordlist File", "Sequential Numbers", "Charset Brute" };
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Payload Type:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180.f);
        ImGui::Combo("##fuzz_pt", &cfg.payload_type, payload_types, 3);

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Payload Source:");
        ImGui::SameLine();
        static char pl_src[512] = {};
        if (cfg.payload_source.size() < sizeof(pl_src)) {
            memcpy(pl_src, cfg.payload_source.c_str(), cfg.payload_source.size() + 1);
        }
        if (aida::ui::input_text("##fuzz_src", pl_src, sizeof(pl_src), "Source...", false, ImVec2(320.f, 28.f)))
            cfg.payload_source = pl_src;
        ImGui::SameLine();
        const char* hint = cfg.payload_type == 0 ? "(path to wordlist)"
                            : cfg.payload_type == 1 ? "(start-end)" : "(charset)";
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "%s", hint);


        if (cfg.payload_sets.empty()) cfg.payload_sets.emplace_back();
        auto& ps0 = cfg.payload_sets[0];
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Grep Extract:");
        ImGui::SameLine();
        aida::ui::input_text("##fuzz_grep0", ps0.grep_regex, sizeof(ps0.grep_regex),
                              "regex (leave empty to skip)", false, ImVec2(280.f, 28.f));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Group:");
        ImGui::SameLine();
        aida::ui::input_text("##fuzz_grp0", ps0.grep_group, sizeof(ps0.grep_group),
                              "1", false, ImVec2(60.f, 28.f));

    } else {

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Payload Sets");
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "(one set per injection position S...S)");
        ImGui::SameLine();
        if (aida::ui::button("+", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
            cfg.payload_sets.emplace_back();
        ImGui::SameLine();
        if (aida::ui::button("-", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)
            && !cfg.payload_sets.empty())
            cfg.payload_sets.pop_back();

        float sets_h = std::min(h * 0.35f, 200.f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(th.panel_bg, 0.6f * alpha));
        ImGui::BeginChild("##fuzz_sets_panel", ImVec2(w - 8.f, sets_h), true,
                          ImGuiWindowFlags_NoBackground);

        static int  set_sel = 0;
        const char* set_type_items[] = { "Wordlist File", "Inline List" };

        for (int si = 0; si < static_cast<int>(cfg.payload_sets.size()); si++) {
            auto& ps = cfg.payload_sets[static_cast<size_t>(si)];
            ImGui::PushID(si);


            char set_label[32];
            snprintf(set_label, sizeof(set_label), "Set %d", si + 1);
            if (ImGui::CollapsingHeader(set_label)) {
                ImGui::Indent(12.f);

                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Name:");
                ImGui::SameLine();
                char name_buf[128] = {};
                if (ps.name.size() < sizeof(name_buf))
                    memcpy(name_buf, ps.name.c_str(), ps.name.size() + 1);
                if (aida::ui::input_text("##ps_name", name_buf, sizeof(name_buf), "Set name", false, ImVec2(180.f, 28.f)))
                    ps.name = name_buf;

                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Type:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(140.f);
                ImGui::Combo("##ps_type", &ps.type, set_type_items, 2);

                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Source:");
                ImGui::SameLine();
                char src_buf[512] = {};
                if (ps.source.size() < sizeof(src_buf))
                    memcpy(src_buf, ps.source.c_str(), ps.source.size() + 1);
                if (ps.type == 0) {
                    if (aida::ui::input_text("##ps_src", src_buf, sizeof(src_buf), "Path to file", false, ImVec2(w - 180.f, 28.f)))
                        ps.source = src_buf;
                } else {
                    ImGui::SetNextItemWidth(w - 180.f);
                    if (ImGui::InputTextMultiline("##ps_src_ml", src_buf, sizeof(src_buf),
                                                  ImVec2(w - 180.f, 60.f)))
                        ps.source = src_buf;
                }


                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Grep Extract:");
                ImGui::SameLine();
                aida::ui::input_text("##ps_grep", ps.grep_regex, sizeof(ps.grep_regex),
                                      "regex (leave empty to skip)", false, ImVec2(260.f, 28.f));
                ImGui::SameLine();
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                                   "Group:");
                ImGui::SameLine();
                aida::ui::input_text("##ps_grp", ps.grep_group, sizeof(ps.grep_group), "1", false, ImVec2(60.f, 28.f));

                ImGui::Unindent(12.f);
            }

            ImGui::PopID();
        }

        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Threads:");
    ImGui::SameLine();
    {
        int v = cfg.thread_count;
        if (aida::ui::input_int("##fuzz_threads", &v, ImVec2(120.f, 32.f))) cfg.thread_count = v;
    }
    cfg.thread_count = std::max(1, std::min(32, cfg.thread_count));
    ImGui::SameLine(0.f, 18.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Delay (ms):");
    ImGui::SameLine();
    {
        int v = cfg.delay_ms;
        if (aida::ui::input_int("##fuzz_delay", &v, ImVec2(120.f, 32.f))) cfg.delay_ms = v;
    }
    cfg.delay_ms = std::max(0, cfg.delay_ms);


    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Match Status:");
    ImGui::SameLine();
    {
        int v = cfg.match_status;
        if (aida::ui::input_int("##fuzz_ms", &v, ImVec2(120.f, 32.f))) cfg.match_status = v;
    }
    ImGui::SameLine(0.f, 10.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "(0=any)");
    ImGui::SameLine(0.f, 18.f);
    aida::ui::toggle_switch("##fuzz_stop_match", &cfg.stop_on_match);
    ImGui::SameLine(0.f, 10.f);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Stop on match");

    ImGui::Spacing();


    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Request Template");
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Mark injection points with $value$  (FUZZ also accepted)");
    ImGui::Spacing();

    static char tmpl_buf[65536] = {};
    if (cfg.base_request.size() < sizeof(tmpl_buf) && !state.fuzz_running.load()) {
        memcpy(tmpl_buf, cfg.base_request.c_str(), cfg.base_request.size());
        tmpl_buf[cfg.base_request.size()] = '\0';
    }

    float tmpl_h = std::min(h * 0.22f, 180.f);
    if (ImGui::InputTextMultiline("##fuzz_tmpl", tmpl_buf, sizeof(tmpl_buf),
                                   ImVec2(w - 8.f, tmpl_h)))
        cfg.base_request = tmpl_buf;

    ImGui::Spacing();


    if (!state.fuzz_running.load()) {
        bool fuzz_can_start = !cfg.host.empty() && cfg.port > 0 && !cfg.base_request.empty();
        if (aida::ui::button("Start Fuzzer", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm,
                              ImVec2(0.f, 0.f), !fuzz_can_start)) {
            {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                state.fuzz_results.clear();
            }
            state.fuzz_progress.store(0);
            state.fuzz_total.store(0);
            diag::log_tagged_fmt("network", "fuzzer_start_clicked host=%s:%u tls=%d mode=%d threads=%d delay_ms=%d match_status=%d stop_on_match=%d sets=%zu",
                cfg.host.c_str(), cfg.port, cfg.use_tls ? 1 : 0,
                static_cast<int>(cfg.attack_mode), cfg.thread_count, cfg.delay_ms,
                cfg.match_status, cfg.stop_on_match ? 1 : 0, cfg.payload_sets.size());
            {
                char buf[256];
                snprintf(buf, sizeof(buf),
                    "[net_audit] fuzzer start host=%s:%u tls=%d mode=%d threads=%d sets=%zu",
                    cfg.host.c_str(), cfg.port, cfg.use_tls ? 1 : 0,
                    static_cast<int>(cfg.attack_mode), cfg.thread_count, cfg.payload_sets.size());
                anti_tamper::webhook::write_log("net_audit", buf);
            }
            state.fuzz_running.store(true);
            state.fuzz_cv.notify_one();
        }
        if (!fuzz_can_start) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Set host, port and request template before running.");
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear Results", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            std::lock_guard<std::mutex> lk(state.fuzz_mutex);
            size_t prev = state.fuzz_results.size();
            state.fuzz_results.clear();
            diag::log_tagged_fmt("network", "fuzzer_results_cleared prev=%zu", prev);
        }
    } else {
        int prog = state.fuzz_progress.load();
        int tot  = state.fuzz_total.load();
        {
            static float fuzz_spin_time = 0.f;
            fuzz_spin_time += ImGui::GetIO().DeltaTime;
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 spos = ImGui::GetCursorScreenPos();
            ui_anim::render_spinner(sdl, spos.x + 8.f, spos.y + 8.f, 6.f, 2.f,
                                    aida::ui::with_alpha(th.accent_u32, alpha), fuzz_spin_time);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 22.f);
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                           "Running: %d / %d", prog, tot);
        float frac = tot > 0 ? static_cast<float>(prog) / static_cast<float>(tot) : 0.f;
        ImVec2 pb_pos = ImGui::GetCursorScreenPos();
        aida::ui::render_progress_bar(pb_pos, 320.f, 8.f, frac, false, true);
        ImGui::Dummy(ImVec2(320.f, 12.f));
        ImGui::SameLine();
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            diag::log_tagged_fmt("network", "fuzzer_stop_clicked progress=%d total=%d", prog, tot);
            state.fuzz_running.store(false);
        }
    }

    ImGui::Spacing();


    std::vector<state_t::fuzzer_result_t> results_copy;
    {
        std::lock_guard<std::mutex> lk(state.fuzz_mutex);
        results_copy = state.fuzz_results;
    }


    size_t max_cols = 1;
    for (auto& fr : results_copy)
        max_cols = std::max(max_cols, fr.payloads.size());
    bool show_extract = false;
    for (auto& fr : results_copy)
        if (!fr.extracted_value.empty()) { show_extract = true; break; }

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Results: %zu", results_copy.size());

    float results_h = h - ImGui::GetCursorPosY() + y - 8.f;
    ImGui::BeginChild("##fuzz_results", ImVec2(w - 4.f, results_h), false,
                      ImGuiWindowFlags_NoBackground);

    ImDrawList* dl   = ImGui::GetWindowDrawList();
    ImVec2 list_org  = ImGui::GetWindowPos();
    float row_h      = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;


    float c_idx     = 50.f;
    float c_payload = std::min(180.f, (w - 50.f - 60.f - 80.f - 80.f - 50.f
                                       - (show_extract ? 120.f : 0.f))
                                      / static_cast<float>(std::max<size_t>(1, max_cols)));
    float c_status  = 60.f;
    float c_len     = 80.f;
    float c_time    = 80.f;
    float c_match   = 50.f;
    float c_extract = show_extract ? 120.f : 0.f;

    float cy  = list_org.y + ImGui::GetCursorPosY();
    float cx0 = list_org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);

    dl->AddRectFilled(ImVec2(list_org.x, cy - 4.f),
                      ImVec2(list_org.x + ImGui::GetWindowSize().x, cy + row_h - 4.f),
                      aida::ui::with_alpha(th.panel_header, alpha));

    {
        float cx = cx0;
        char hbuf[32];
        float hdr_ty = cy - 4.f + (row_h - ImGui::GetTextLineHeight()) * 0.5f;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "#"); cx += c_idx;
        for (size_t pi = 0; pi < max_cols; pi++) {
            snprintf(hbuf, sizeof(hbuf), "Payload %zu", pi + 1);
            dl->AddText(ImVec2(cx, hdr_ty), hdr_col, hbuf); cx += c_payload;
        }
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Status");  cx += c_status;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Length");  cx += c_len;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Time");    cx += c_time;
        dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Match");   cx += c_match;
        if (show_extract) dl->AddText(ImVec2(cx, hdr_ty), hdr_col, "Extracted");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);
    }

    for (auto& fr : results_copy) {
        float ry     = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool  is_sel = (state.fuzz_selected == fr.index);

        if (fr.match) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry),
                              ImVec2(list_org.x + w - 4.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.success_soft, alpha * 4.f));
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry), ImVec2(list_org.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.success, alpha));
        } else if (is_sel) {
            dl->AddRectFilled(ImVec2(list_org.x, abs_ry),
                              ImVec2(list_org.x + w - 4.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= list_org.x && mouse.x < list_org.x + w - 4.f &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.fuzz_selected = fr.index;

        ImU32 txt_col = aida::ui::with_alpha(is_sel ? th.text_primary : th.text_secondary, alpha);
        float cx = cx0;
        char buf[64];

        snprintf(buf, sizeof(buf), "%d", fr.index);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_idx;


        for (size_t pi = 0; pi < max_cols; pi++) {
            std::string pl;
            if (pi < fr.payloads.size()) {
                pl = fr.payloads[pi].size() > 28
                    ? fr.payloads[pi].substr(0, 28) + ".." : fr.payloads[pi];
            }
            dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, pl.c_str()); cx += c_payload;
        }


        ImU32 sc_col = aida::ui::with_alpha(status_code_color(fr.status_code), alpha);
        snprintf(buf, sizeof(buf), "%d", fr.status_code);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), sc_col, buf); cx += c_status;

        snprintf(buf, sizeof(buf), "%zu", fr.response_len);
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_len;

        snprintf(buf, sizeof(buf), "%llums",
                 static_cast<unsigned long long>(fr.latency_ms));
        dl->AddText(ImVec2(cx, abs_ry + text_oy), txt_col, buf); cx += c_time;

        if (fr.match)
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                         aida::ui::with_alpha(th.success, alpha), "YES");
        cx += c_match;

        if (show_extract && !fr.extracted_value.empty()) {
            std::string ev = fr.extracted_value.size() > 20
                ? fr.extracted_value.substr(0, 20) + ".." : fr.extracted_value;
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                         aida::ui::with_alpha(th.warning, alpha), ev.c_str());
        }

        ImGui::SetCursorPosY(ry + row_h);
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

enum class offensive_workflow_kind_t : int {
    sqli_detect,
    sqli_fingerprint,
    xss_detect,
    xss_dom,
    auth_bruteforce,
    auth_idor,
    server_ssrf,
    server_ssti,
    server_cmdi,
    server_traversal,
    server_xxe,
    server_smuggle,
    api_param_fuzz,
    api_authz_matrix,
    client_cors,
    client_csrf,
    client_postmessage,
    business_race,
    fuzz_start,
    fuzz_mutate,
    js_secrets,
    js_endpoints,
    recon_fingerprint,
    recon_waf
};

struct offensive_workflow_t {
    const char* label;
    offensive_workflow_kind_t kind;
};

static const offensive_workflow_t k_offensive_workflows[] = {
    { "SQLi Detect", offensive_workflow_kind_t::sqli_detect },
    { "SQLi Fingerprint", offensive_workflow_kind_t::sqli_fingerprint },
    { "XSS Detect", offensive_workflow_kind_t::xss_detect },
    { "XSS DOM", offensive_workflow_kind_t::xss_dom },
    { "Auth Brute Force", offensive_workflow_kind_t::auth_bruteforce },
    { "Auth IDOR", offensive_workflow_kind_t::auth_idor },
    { "SSRF", offensive_workflow_kind_t::server_ssrf },
    { "SSTI", offensive_workflow_kind_t::server_ssti },
    { "CMDi", offensive_workflow_kind_t::server_cmdi },
    { "Path Traversal", offensive_workflow_kind_t::server_traversal },
    { "XXE", offensive_workflow_kind_t::server_xxe },
    { "Request Smuggling", offensive_workflow_kind_t::server_smuggle },
    { "API Param Fuzz", offensive_workflow_kind_t::api_param_fuzz },
    { "API Auth Matrix", offensive_workflow_kind_t::api_authz_matrix },
    { "Client CORS", offensive_workflow_kind_t::client_cors },
    { "Client CSRF", offensive_workflow_kind_t::client_csrf },
    { "Client PostMessage", offensive_workflow_kind_t::client_postmessage },
    { "Business Race", offensive_workflow_kind_t::business_race },
    { "Fuzz Start", offensive_workflow_kind_t::fuzz_start },
    { "Fuzz Mutate", offensive_workflow_kind_t::fuzz_mutate },
    { "JS Secrets", offensive_workflow_kind_t::js_secrets },
    { "JS Endpoints", offensive_workflow_kind_t::js_endpoints },
    { "Recon Fingerprint", offensive_workflow_kind_t::recon_fingerprint },
    { "Recon WAF", offensive_workflow_kind_t::recon_waf }
};

struct offensive_run_result_t {
    bool success = false;
    std::string message;
    std::string code;
    json data = json::object();
};

static int offensive_workflow_count() {
    return static_cast<int>(sizeof(k_offensive_workflows) / sizeof(k_offensive_workflows[0]));
}

static int clamp_offensive_workflow_index(int idx) {
    return std::max(0, std::min(idx, offensive_workflow_count() - 1));
}

static const offensive_workflow_t& offensive_workflow_at(int idx) {
    return k_offensive_workflows[clamp_offensive_workflow_index(idx)];
}

static std::string lower_ascii_copy(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static bool offensive_sensitive_key(const std::string& key) {
    const std::string k = lower_ascii_copy(key);
    return k.find("password") != std::string::npos ||
           k.find("passwd") != std::string::npos ||
           k.find("pwd") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("secret") != std::string::npos ||
           k.find("cookie") != std::string::npos ||
           k.find("authorization") != std::string::npos ||
           k.find("api_key") != std::string::npos ||
           k.find("apikey") != std::string::npos ||
           k.find("private_key") != std::string::npos ||
           k.find("session") != std::string::npos ||
           k.find("credential") != std::string::npos ||
           k.find("bearer") != std::string::npos ||
           k == "jwt";
}

static json offensive_redact_json(const json& src) {
    if (src.is_object()) {
        json out = json::object();
        std::string named_value_key;
        if (src.contains("name") && src["name"].is_string())
            named_value_key = src["name"].get<std::string>();
        for (auto it = src.begin(); it != src.end(); ++it) {
            if (offensive_sensitive_key(it.key()) || (it.key() == "value" && offensive_sensitive_key(named_value_key)))
                out[it.key()] = "[redacted]";
            else
                out[it.key()] = offensive_redact_json(it.value());
        }
        return out;
    }
    if (src.is_array()) {
        json out = json::array();
        for (const auto& item : src)
            out.push_back(offensive_redact_json(item));
        return out;
    }
    return src;
}

static bool offensive_parse_json_object(const char* text, json& out, std::string& err) {
    std::string raw = text ? std::string(text) : std::string();
    if (raw.empty()) {
        out = json::object();
        return true;
    }
    bool all_space = true;
    for (char c : raw) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            all_space = false;
            break;
        }
    }
    if (all_space) {
        out = json::object();
        return true;
    }
    json parsed = json::parse(raw, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        err = "Payload JSON must be an object";
        return false;
    }
    out = std::move(parsed);
    return true;
}

static void offensive_apply_base_payload(state_t& state, json& payload) {
    const int timeout_ms = std::max(1000, std::min(state.off_timeout_ms, 120000));
    const int max_payloads = std::max(1, std::min(state.off_max_payloads, 256));
    const int max_requests = std::max(1, std::min(state.off_max_requests, 1000));
    state.off_timeout_ms = timeout_ms;
    state.off_max_payloads = max_payloads;
    state.off_max_requests = max_requests;
    if (state.off_target_url[0] != '\0') {
        payload["url"] = state.off_target_url;
        if (!payload.contains("base_url"))
            payload["base_url"] = state.off_target_url;
    }
    if (state.off_target_param[0] != '\0') {
        payload["param"] = state.off_target_param;
        payload["param_target"] = state.off_target_param;
        payload["param_name"] = state.off_target_param;
    }
    if (state.off_raw_request[0] != '\0' && !payload.contains("raw_request"))
        payload["raw_request"] = state.off_raw_request;
    payload["scope_only"] = state.off_scope_only;
    payload["enforce_scope"] = state.off_scope_only;
    payload["timeout_ms"] = timeout_ms;
    payload["max_payloads"] = max_payloads;
    payload["max_requests"] = max_requests;
    if (!payload.contains("max_attempts"))
        payload["max_attempts"] = max_requests;
    if (!payload.contains("request_count"))
        payload["request_count"] = max_requests;
    if (!payload.contains("max_params"))
        payload["max_params"] = max_payloads;
    if (!payload.contains("max_variants"))
        payload["max_variants"] = max_payloads;
    if (!payload.contains("max_payloads_per_set"))
        payload["max_payloads_per_set"] = max_payloads;
}

static bool offensive_json_bool(const json& obj, const char* primary, const char* secondary, bool fallback) {
    if (obj.is_object() && obj.contains(primary) && obj[primary].is_boolean())
        return obj[primary].get<bool>();
    if (obj.is_object() && obj.contains(secondary) && obj[secondary].is_boolean())
        return obj[secondary].get<bool>();
    return fallback;
}

static offensive_run_result_t offensive_from_tool_result(const mcp_standalone::tool_result_t& tr) {
    offensive_run_result_t out;
    out.success = tr.success;
    out.message = tr.text;
    out.code = tr.error_code;
    if (!tr.data.is_null() && !(tr.data.is_object() && tr.data.empty()))
        out.data = tr.data;
    else if (!tr.error_details.is_null() && !(tr.error_details.is_object() && tr.error_details.empty()))
        out.data = tr.error_details;
    else
        out.data = json{{"text", tr.text}};
    return out;
}

static offensive_run_result_t offensive_from_json_result(const json& result, const std::string& fallback_message) {
    offensive_run_result_t out;
    out.data = result;
    out.success = offensive_json_bool(result, "ok", "success", true);
    out.message = result.is_object() && result.contains("message") && result["message"].is_string()
        ? result["message"].get<std::string>() : fallback_message;
    out.code = result.is_object() && result.contains("error_code") && result["error_code"].is_string()
        ? result["error_code"].get<std::string>() : std::string();
    if (out.code.empty() && result.is_object() && result.contains("code") && result["code"].is_string())
        out.code = result["code"].get<std::string>();
    return out;
}

static offensive_run_result_t offensive_from_auth_result(const aida::burp::offensive::auth_attack::result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.error_code, r.data};
}

static offensive_run_result_t offensive_from_business_result(const aida::burp::offensive::business_logic::result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.error_code, r.data};
}

static offensive_run_result_t offensive_from_server_result(const aida::burp::offensive::server_attack::action_result_t& r) {
    return offensive_run_result_t{r.success, r.message, r.code, r.data};
}

static offensive_run_result_t offensive_from_sqli_result(const aida::burp::offensive::sqli::engine_result_t& r) {
    return offensive_run_result_t{r.ok, r.message, r.code, r.data};
}

static offensive_run_result_t offensive_from_xss_result(const aida::burp::offensive::xss::engine_result_t& r) {
    return offensive_run_result_t{r.ok, r.message, r.code, r.data};
}

static offensive_run_result_t offensive_dispatch(const offensive_workflow_t& workflow, json payload) {
    using namespace aida::burp::offensive;
    switch (workflow.kind) {
        case offensive_workflow_kind_t::sqli_detect:
            return offensive_from_sqli_result(sqli::detect(payload));
        case offensive_workflow_kind_t::sqli_fingerprint:
            return offensive_from_sqli_result(sqli::fingerprint_db(payload));
        case offensive_workflow_kind_t::xss_detect:
            return offensive_from_xss_result(xss::detect(payload));
        case offensive_workflow_kind_t::xss_dom:
            return offensive_from_xss_result(xss::dom_analyze(payload));
        case offensive_workflow_kind_t::auth_bruteforce:
            return offensive_from_auth_result(auth_attack::handle_action("brute_force", payload));
        case offensive_workflow_kind_t::auth_idor:
            return offensive_from_auth_result(auth_attack::handle_action("idor_test", payload));
        case offensive_workflow_kind_t::server_ssrf:
            return offensive_from_server_result(server_attack::handle_action("ssrf_exploit", payload));
        case offensive_workflow_kind_t::server_ssti:
            return offensive_from_server_result(server_attack::handle_action("ssti_exploit", payload));
        case offensive_workflow_kind_t::server_cmdi:
            return offensive_from_server_result(server_attack::handle_action("cmdi_exploit", payload));
        case offensive_workflow_kind_t::server_traversal:
            return offensive_from_server_result(server_attack::handle_action("path_traversal_exploit", payload));
        case offensive_workflow_kind_t::server_xxe:
            return offensive_from_server_result(server_attack::handle_action("xxe_exploit", payload));
        case offensive_workflow_kind_t::server_smuggle:
            return offensive_from_server_result(server_attack::handle_action("smuggle_exploit", payload));
        case offensive_workflow_kind_t::api_param_fuzz:
            return offensive_from_tool_result(api_security::param_fuzz(payload));
        case offensive_workflow_kind_t::api_authz_matrix:
            return offensive_from_tool_result(api_security::authz_matrix(payload));
        case offensive_workflow_kind_t::client_cors:
            return offensive_from_tool_result(client_attack::cors_exploit(payload));
        case offensive_workflow_kind_t::client_csrf:
            return offensive_from_tool_result(client_attack::csrf_test(payload));
        case offensive_workflow_kind_t::client_postmessage:
            return offensive_from_tool_result(client_attack::postmessage_scan(payload));
        case offensive_workflow_kind_t::business_race:
            return offensive_from_business_result(business_logic::handle_action("race_test", payload));
        case offensive_workflow_kind_t::fuzz_start:
            return offensive_from_tool_result(fuzzing::start(payload));
        case offensive_workflow_kind_t::fuzz_mutate:
            return offensive_from_tool_result(fuzzing::mutate(payload));
        case offensive_workflow_kind_t::js_secrets:
            return offensive_from_json_result(js_analysis::extract_secrets(payload), "JavaScript secret extraction completed");
        case offensive_workflow_kind_t::js_endpoints:
            return offensive_from_json_result(js_analysis::extract_endpoints(payload), "JavaScript endpoint extraction completed");
        case offensive_workflow_kind_t::recon_fingerprint:
            return offensive_from_json_result(recon::fingerprint(payload), "Recon fingerprint completed");
        case offensive_workflow_kind_t::recon_waf:
            return offensive_from_json_result(recon::waf_detect(payload), "Recon WAF detection completed");
    }
    return offensive_run_result_t{false, "Unsupported offensive workflow", "unsupported_workflow", json::object()};
}

static void collect_offensive_issue_ids(const json& node, std::vector<uint64_t>& ids) {
    if (node.is_object()) {
        for (auto it = node.begin(); it != node.end(); ++it) {
            const std::string key = lower_ascii_copy(it.key());
            if ((key == "issue_id" || key == "issue" || key == "id") && it.value().is_number_unsigned()) {
                const uint64_t id = it.value().get<uint64_t>();
                if (id != 0 && std::find(ids.begin(), ids.end(), id) == ids.end())
                    ids.push_back(id);
            }
            collect_offensive_issue_ids(it.value(), ids);
        }
    } else if (node.is_array()) {
        for (const auto& item : node)
            collect_offensive_issue_ids(item, ids);
    }
}

static void render_offensive_issue_links(state_t& state, const std::string& result, float alpha) {
    json parsed = json::parse(result, nullptr, false);
    if (parsed.is_discarded())
        return;
    std::vector<uint64_t> ids;
    collect_offensive_issue_ids(parsed, ids);
    if (ids.empty())
        return;
    const auto& th = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Issues:");
    ImGui::SameLine();
    for (size_t i = 0; i < ids.size() && i < 8; ++i) {
        if (i > 0) ImGui::SameLine();
        char label[48];
        snprintf(label, sizeof(label), "#%llu##off_issue_%zu", static_cast<unsigned long long>(ids[i]), i);
        if (aida::ui::button(label, aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
            state.active_tab = sub_tab_t::scanner;
    }
}

static bool start_offensive_workflow(state_t& state, const offensive_workflow_t& workflow) {
    json payload;
    std::string err;
    if (!offensive_parse_json_object(state.off_payload_json, payload, err)) {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = err;
        state.off_result = json{{"success", false}, {"error", err}}.dump(2);
        return false;
    }
    offensive_apply_base_payload(state, payload);
    const uint64_t run_id = state.off_run_id.fetch_add(1, std::memory_order_acq_rel) + 1;
    state.off_cancel_requested.store(false, std::memory_order_release);
    state.off_running.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = std::string("Running ") + workflow.label;
        state.off_result.clear();
    }
    const int workflow_index = clamp_offensive_workflow_index(state.off_workflow);
    const bool posted = post_network_task("offensive_workflow", aida::infra::executor::domain_t::long_running, "long_running", [payload = std::move(payload), workflow_index, run_id]() mutable {
        const offensive_workflow_t workflow_copy = offensive_workflow_at(workflow_index);
        offensive_run_result_t result;
        const uint64_t begin = static_cast<uint64_t>(GetTickCount64());
        if (g_state.off_cancel_requested.load(std::memory_order_acquire)) {
            result.success = false;
            result.message = "Cancelled before dispatch";
            result.code = "cancelled";
            result.data = json::object();
        } else {
            try {
                result = offensive_dispatch(workflow_copy, std::move(payload));
            } catch (const std::exception& e) {
                result.success = false;
                result.message = "Offensive workflow failed";
                result.code = "exception";
                result.data = json{{"exception_len", std::string(e.what()).size()}};
            } catch (...) {
                result.success = false;
                result.message = "Offensive workflow failed";
                result.code = "unknown_exception";
                result.data = json::object();
            }
        }
        const uint64_t elapsed_ms = static_cast<uint64_t>(GetTickCount64()) - begin;
        if (g_state.off_cancel_requested.load(std::memory_order_acquire) && result.success) {
            result.success = false;
            result.message = "Cancelled";
            result.code = "cancelled";
        }
        json out;
        out["run_id"] = run_id;
        out["workflow"] = workflow_copy.label;
        out["success"] = result.success;
        out["message"] = result.message;
        out["code"] = result.code;
        out["elapsed_ms"] = elapsed_ms;
        out["data"] = offensive_redact_json(result.data);
        if (workflow_copy.kind == offensive_workflow_kind_t::fuzz_start && result.success && result.data.is_object()) {
            uint64_t job_id = 0;
            if (result.data.contains("job_id") && result.data["job_id"].is_number_unsigned())
                job_id = result.data["job_id"].get<uint64_t>();
            if (job_id != 0)
                g_state.off_active_fuzz_job_id.store(job_id, std::memory_order_release);
        }
        {
            std::lock_guard<std::mutex> lk(g_state.off_mutex);
            g_state.off_status = result.message.empty() ? (result.success ? "Completed" : "Failed") : result.message;
            g_state.off_result = out.dump(2);
        }
        g_state.off_running.store(false, std::memory_order_release);
        g_state.off_cancel_requested.store(false, std::memory_order_release);
    });
    if (!posted) {
        state.off_running.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Network work queue unavailable";
        state.off_result = json{{"success", false}, {"error", "network_executor_unavailable"}}.dump(2);
        return false;
    }
    return true;
}

static void stop_offensive_fuzz_job(state_t& state) {
    const uint64_t job_id = state.off_active_fuzz_job_id.exchange(0, std::memory_order_acq_rel);
    if (job_id == 0)
        return;
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Stopping fuzz job";
    }
    const bool posted = post_network_task("offensive_fuzz_stop", aida::infra::executor::domain_t::feature_worker, "bounded_task", [job_id]() {
        auto result = aida::burp::offensive::fuzzing::stop(json{{"job_id", job_id}});
        json out;
        out["workflow"] = "Fuzz Stop";
        out["success"] = result.success;
        out["message"] = result.text;
        out["data"] = offensive_redact_json(result.data);
        std::lock_guard<std::mutex> lk(g_state.off_mutex);
        g_state.off_status = result.success ? "Fuzz job stopped" : result.text;
        g_state.off_result = out.dump(2);
    });
    if (!posted) {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        state.off_status = "Network work queue unavailable";
    }
}

static void render_offensive(state_t& state, float x, float y, float w, float h,
                             float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##net_offensive", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    const offensive_workflow_t& wf = offensive_workflow_at(state.off_workflow);
    const bool compact_controls = w < 1120.f;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Workflow:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::min(260.f, std::max(160.f, w * 0.28f)));
    if (ImGui::BeginCombo("##off_workflow", wf.label)) {
        for (int i = 0; i < offensive_workflow_count(); ++i) {
            const bool selected = state.off_workflow == i;
            if (ImGui::Selectable(k_offensive_workflows[i].label, selected))
                state.off_workflow = i;
            if (selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    aida::ui::toggle_switch("##off_scope", &state.off_scope_only);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Scope");
    if (compact_controls)
        ImGui::Spacing();
    else
        ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Timeout:");
    ImGui::SameLine();
    aida::ui::input_int("##off_timeout", &state.off_timeout_ms, ImVec2(100.f, 28.f));
    state.off_timeout_ms = std::max(1000, std::min(state.off_timeout_ms, 120000));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Payloads:");
    ImGui::SameLine();
    aida::ui::input_int("##off_payloads", &state.off_max_payloads, ImVec2(86.f, 28.f));
    state.off_max_payloads = std::max(1, std::min(state.off_max_payloads, 256));
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Requests:");
    ImGui::SameLine();
    aida::ui::input_int("##off_requests", &state.off_max_requests, ImVec2(86.f, 28.f));
    state.off_max_requests = std::max(1, std::min(state.off_max_requests, 1000));

    ImGui::Spacing();
    const bool compact_target = w < 760.f;
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Target:");
    ImGui::SameLine();
    const float target_w = compact_target ? std::max(180.f, w - 92.f) : std::max(180.f, std::min(520.f, w - 260.f));
    aida::ui::input_text("##off_url", state.off_target_url, sizeof(state.off_target_url),
                         "https://target.example/path?name=value", false, ImVec2(target_w, 28.f));
    if (compact_target)
        ImGui::Spacing();
    else
        ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Param:");
    ImGui::SameLine();
    aida::ui::input_text("##off_param", state.off_target_param, sizeof(state.off_target_param),
                         "name", false, ImVec2(150.f, 28.f));

    ImGui::Spacing();
    const float split_gap = 10.f;
    const bool stacked = w < 940.f;
    const float pane_w = stacked ? std::max(220.f, w - 6.f) : std::max(220.f, (w - split_gap - 6.f) * 0.5f);
    const float editor_h = std::max(110.f, std::min(220.f, h * 0.26f));
    ImGui::BeginChild("##off_payload_pane", ImVec2(pane_w, editor_h + 26.f), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Payload JSON");
    ImGui::InputTextMultiline("##off_payload_json", state.off_payload_json, sizeof(state.off_payload_json),
                              ImVec2(pane_w - 4.f, editor_h), ImGuiInputTextFlags_AllowTabInput);
    ImGui::EndChild();
    if (stacked)
        ImGui::Dummy(ImVec2(0.f, 8.f));
    else
        ImGui::SameLine(0.f, split_gap);
    ImGui::BeginChild("##off_raw_pane", ImVec2(pane_w, editor_h + 26.f), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Raw Request");
    ImGui::InputTextMultiline("##off_raw", state.off_raw_request, sizeof(state.off_raw_request),
                              ImVec2(pane_w - 4.f, editor_h), ImGuiInputTextFlags_AllowTabInput);
    ImGui::EndChild();

    ImGui::Spacing();
    const bool running = state.off_running.load(std::memory_order_acquire);
    const uint64_t fuzz_job = state.off_active_fuzz_job_id.load(std::memory_order_acquire);
    if (!running) {
        if (aida::ui::button("Run", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            const offensive_workflow_t& run_wf = offensive_workflow_at(state.off_workflow);
            diag::log_tagged_fmt("network", "offensive_run_clicked workflow=%s scope_only=%d timeout_ms=%d max_payloads=%d max_requests=%d url_len=%zu raw_len=%zu",
                run_wf.label, state.off_scope_only ? 1 : 0, state.off_timeout_ms, state.off_max_payloads, state.off_max_requests,
                strlen(state.off_target_url), strlen(state.off_raw_request));
            start_offensive_workflow(state, run_wf);
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            std::lock_guard<std::mutex> lk(state.off_mutex);
            state.off_status = "Idle";
            state.off_result.clear();
        }
        if (fuzz_job != 0) {
            ImGui::SameLine();
            if (aida::ui::button("Stop Job", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm))
                stop_offensive_fuzz_job(state);
        }
    } else {
        aida::ui::pill_kind("Running", aida::ui::pill_kind_t::accent, aida::ui::size_t_::sm, true);
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            state.off_cancel_requested.store(true, std::memory_order_release);
            if (fuzz_job != 0)
                stop_offensive_fuzz_job(state);
            std::lock_guard<std::mutex> lk(state.off_mutex);
            state.off_status = "Cancellation requested";
        }
    }

    std::string status;
    std::string result;
    {
        std::lock_guard<std::mutex> lk(state.off_mutex);
        status = state.off_status;
        result = state.off_result;
    }
    ImGui::SameLine();
    aida::ui::pill_kind(status.c_str(), running ? aida::ui::pill_kind_t::accent : aida::ui::pill_kind_t::neutral,
                        aida::ui::size_t_::sm, true);

    ImGui::Spacing();
    if (!result.empty())
        render_offensive_issue_links(state, result, alpha);
    const float result_h = std::max(120.f, h - ImGui::GetCursorPosY() + y - 10.f);
    static char empty_result[1] = {};
    char* result_buf = result.empty() ? empty_result : result.data();
    ImGui::InputTextMultiline("##off_result", result_buf,
                              result.empty() ? 1 : result.size() + 1,
                              ImVec2(w - 6.f, result_h), ImGuiInputTextFlags_ReadOnly);
    ImGui::EndChild();
}

static void render_websocket(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##ws_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = aida::ui::with_alpha(th.text_primary, alpha);
    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, alpha);


    float ty = 4.f;
    ImGui::SetCursorPos(ImVec2(8.f, ty));
    aida::ui::input_text("##ws_filter", state.ws_filter_text, sizeof(state.ws_filter_text),
                          "Filter...", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                         ImVec2(0.f, 28.f))) {
        std::lock_guard<std::mutex> lock(state.ws_mutex);
        size_t prev = state.ws_frames.size();
        state.ws_frames.clear();
        state.ws_selected = -1;
        diag::log_tagged_fmt("network", "ws_frames_cleared prev=%zu", prev);
    }
    ImGui::SameLine();
    aida::ui::toggle_switch("##ws_auto", &state.ws_auto_scroll);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Auto-scroll");

    float header_y = ty + 38.f;

    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    dl->AddRectFilled(ImVec2(origin.x, origin.y + header_y - 4.f),
                      ImVec2(origin.x + w, origin.y + header_y + row_h - 4.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    ui_anim::render_gradient_header(dl, origin.x, origin.y + header_y - 4.f, w, row_h, ar, ag, ab, alpha * 0.30f);

    float c_dir = 36.f, c_host = 220.f, c_opcode = 70.f, c_size = 80.f;
    float cx = 8.f;
    float ws_hdr_ty = origin.y + header_y - 4.f + text_oy;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Dir"); cx += c_dir;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Host"); cx += c_host;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Opcode"); cx += c_opcode;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Size"); cx += c_size;
    dl->AddText(ImVec2(origin.x + cx, ws_hdr_ty), dim_col, "Preview");

    float list_y = header_y + row_h;
    float list_h = h * 0.55f;
    ImGui::SetCursorPos(ImVec2(0.f, list_y));
    ImGui::BeginChild("##ws_list", ImVec2(w, list_h), false);
    dl = ImGui::GetWindowDrawList();

    std::lock_guard<std::mutex> lock(state.ws_mutex);
    std::string filter(state.ws_filter_text);
    int visible_idx = 0;

    if (state.ws_frames.empty()) {
        ImGui::EndChild();
        ImGui::SetCursorPos(ImVec2(0.f, list_y));
        ImGui::BeginChild("##ws_empty", ImVec2(w, list_h), false);
        ImVec2 ep = ImGui::GetCursorScreenPos();
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No WebSocket frames";
        cfg.body  = "Frames captured by the proxy will appear here.";
        aida::ui::empty_state::render(ep, ImVec2(w, list_h), cfg);
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::EndChild();
        return;
    }

    for (size_t i = 0; i < state.ws_frames.size(); i++) {
        const auto& fr = state.ws_frames[i];
        if (!filter.empty() && fr.host.find(filter) == std::string::npos &&
            fr.preview.find(filter) == std::string::npos)
            continue;

        float ry = static_cast<float>(visible_idx) * row_h;
        float abs_ry = ImGui::GetWindowPos().y + ry - ImGui::GetScrollY();

        bool is_selected = (state.ws_selected == static_cast<int>(i));
        if (is_selected) {
            dl->AddRectFilled(ImVec2(ImGui::GetWindowPos().x, abs_ry),
                ImVec2(ImGui::GetWindowPos().x + w, abs_ry + row_h),
                aida::ui::with_alpha(th.selection, alpha));
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= ImGui::GetWindowPos().x && mouse.x < ImGui::GetWindowPos().x + w &&
            mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0))
            state.ws_selected = static_cast<int>(i);

        cx = 8.f;
        ImU32 dir_col = fr.is_outbound
            ? aida::ui::with_alpha(th.warning, alpha)
            : aida::ui::with_alpha(th.info, alpha);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dir_col,
            fr.is_outbound ? "\xe2\x86\x91" : "\xe2\x86\x93"); cx += c_dir;

        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%u", fr.host.c_str(), fr.port);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), txt_col, buf); cx += c_host;

        snprintf(buf, sizeof(buf), "0x%02X", fr.opcode);
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dim_col, buf); cx += c_opcode;

        snprintf(buf, sizeof(buf), "%zu", fr.payload.size());
        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), txt_col, buf); cx += c_size;

        dl->AddText(ImVec2(ImGui::GetWindowPos().x + cx, abs_ry + text_oy), dim_col,
            fr.preview.empty() ? "(empty)" : fr.preview.c_str());

        ImGui::SetCursorPosY(ry + row_h);
        visible_idx++;
    }

    if (state.ws_auto_scroll && !state.ws_frames.empty())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();


    float detail_y = list_y + list_h + 4.f;
    float detail_h = h - detail_y;
    ImGui::SetCursorPos(ImVec2(0.f, detail_y));
    ImGui::BeginChild("##ws_detail", ImVec2(w, detail_h), false);

    if (state.ws_selected >= 0 && state.ws_selected < static_cast<int>(state.ws_frames.size())) {
        const auto& fr = state.ws_frames[static_cast<size_t>(state.ws_selected)];
        dl = ImGui::GetWindowDrawList();
        ImVec2 dp = ImGui::GetWindowPos();

        ImFont* mono_font = aida::ui::fonts::code();
        bool pushed = false;
        if (mono_font) { ImGui::PushFont(mono_font); pushed = true; }

        float dy = 4.f;
        for (size_t off = 0; off < fr.payload.size() && dy < detail_h - 14.f; off += 16) {
            char line[128];
            int pos = snprintf(line, sizeof(line), "%04zx  ", off);
            for (size_t j = 0; j < 16; j++) {
                if (off + j < fr.payload.size())
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02x ", fr.payload[off + j]);
                else
                    pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
            }
            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
            for (size_t j = 0; j < 16 && off + j < fr.payload.size(); j++) {
                uint8_t c = fr.payload[off + j];
                line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
            }
            line[pos] = '\0';
            dl->AddText(ImVec2(dp.x + 8.f, dp.y + dy), aida::ui::with_alpha(th.text_secondary, alpha), line);
            dy += 14.f;
        }

        if (pushed) ImGui::PopFont();
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
}


namespace scripting_detail {

    struct panel_frame_t {
        ImVec2 origin;
        ImVec2 body_min;
        ImVec2 body_max;
        float  header_h;
    };

    static panel_frame_t panel_begin(ImVec2 pos, ImVec2 size,
                                     float alpha, const char* title,
                                     aida::ui::empty_state::glyph_t glyph,
                                     bool use_glyph) {
        const auto& th = aida::ui::resolved();

        ImDrawList* pdl = ImGui::GetWindowDrawList();
        ImVec2 win = ImGui::GetWindowPos();
        ImVec2 a = ImVec2(win.x + pos.x, win.y + pos.y);
        ImVec2 b = ImVec2(a.x + size.x, a.y + size.y);
        float radius = 10.f;
        float header_h = std::max(34.f, ImGui::GetFontSize() + 16.f);

        pdl->AddRectFilled(a, b, aida::ui::with_alpha(th.panel_bg, alpha * 0.92f), radius);
        pdl->AddRectFilledMultiColor(
            ImVec2(a.x, a.y), ImVec2(b.x, a.y + header_h),
            aida::ui::with_alpha(th.panel_header, alpha * 0.95f),
            aida::ui::with_alpha(th.panel_header, alpha * 0.95f),
            aida::ui::with_alpha(th.panel_bg, alpha * 0.55f),
            aida::ui::with_alpha(th.panel_bg, alpha * 0.55f));
        pdl->AddLine(ImVec2(a.x + 1.f, a.y + header_h),
                     ImVec2(b.x - 1.f, a.y + header_h),
                     aida::ui::with_alpha(th.border_subtle, alpha), 1.f);
        pdl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), radius, 0, 1.f);

        float gx = a.x + 14.f;
        float text_cy = a.y + (header_h - ImGui::GetFontSize()) * 0.5f;
        if (use_glyph) {
            float gs = ImGui::GetFontSize() * 1.4f;
            ImVec2 gc = ImVec2(a.x + 14.f + gs * 0.5f, a.y + header_h * 0.5f);
            aida::ui::empty_state::render_glyph(glyph, pdl, gc, gs,
                aida::ui::with_alpha(th.accent_u32, alpha), 1.f);
            gx = a.x + 14.f + gs + 8.f;
        }

        ImFont* hf = aida::ui::fonts::body_strong();
        if (hf)
            pdl->AddText(hf, ImGui::GetFontSize(), ImVec2(gx, text_cy),
                         aida::ui::with_alpha(th.text_primary, alpha), title);
        else
            pdl->AddText(ImVec2(gx, text_cy),
                         aida::ui::with_alpha(th.text_primary, alpha), title);

        panel_frame_t pf;
        pf.origin   = a;
        pf.body_min = ImVec2(a.x, a.y + header_h);
        pf.body_max = b;
        pf.header_h = header_h;
        return pf;
    }

    static void panel_header_meta(const panel_frame_t& pf, float alpha,
                                  const char* meta, ImU32 col) {
        ImDrawList* pdl = ImGui::GetWindowDrawList();
        ImFont* mf = aida::ui::fonts::caption();
        float fs = mf ? mf->FontSize : ImGui::GetFontSize();
        float tw = mf ? mf->CalcTextSizeA(fs, FLT_MAX, 0.f, meta).x
                      : ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, meta).x;
        float tx = pf.body_max.x - 14.f - tw;
        float ty = pf.origin.y + (pf.header_h - fs) * 0.5f;
        if (mf)
            pdl->AddText(mf, fs, ImVec2(tx, ty), aida::ui::with_alpha(col, alpha), meta);
        else
            pdl->AddText(ImVec2(tx, ty), aida::ui::with_alpha(col, alpha), meta);
    }

    static ImU32 log_level_color(script_engine::log_level lv, float alpha) {
        const auto& th = aida::ui::resolved();
        switch (lv) {
            case script_engine::log_level::error:
                return aida::ui::with_alpha(th.error, alpha);
            case script_engine::log_level::warn:
                return aida::ui::with_alpha(th.warning, alpha);
            case script_engine::log_level::output:
                return aida::ui::with_alpha(th.success, alpha);
            case script_engine::log_level::command:
                return aida::ui::with_alpha(th.accent_u32, alpha);
            case script_engine::log_level::debug:
                return aida::ui::with_alpha(th.text_dim, alpha);
            case script_engine::log_level::info:
            default:
                return aida::ui::with_alpha(th.text_secondary, alpha);
        }
    }

    static const char* log_level_tag(script_engine::log_level lv) {
        switch (lv) {
            case script_engine::log_level::error:   return "ERR ";
            case script_engine::log_level::warn:    return "WARN";
            case script_engine::log_level::output:  return "OUT ";
            case script_engine::log_level::command: return "CMD ";
            case script_engine::log_level::debug:   return "DBG ";
            case script_engine::log_level::info:
            default:                                return "INFO";
        }
    }

    static void format_log_timestamp(uint64_t wall_seconds, char* out, size_t out_size) {
        if (out_size == 0) return;
        time_t t = static_cast<time_t>(wall_seconds);
        std::tm tm_buf{};
        bool ok = localtime_s(&tm_buf, &t) == 0;
        if (!ok) {
            snprintf(out, out_size, "--:--:--");
            return;
        }
        snprintf(out, out_size, "%02d:%02d:%02d",
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    }

}

static void render_scripting(state_t& state, float x, float y, float w, float h,
                              float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    using namespace scripting_detail;
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::BeginChild("##script_tab", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();

    auto load_script_from_dialog = [&state]() {
        char path_buf[MAX_PATH] = {};
        static const char k_lua_open_filter[] =
            "Lua Scripts (*.lua)\0*.lua\0"
            "All files (*.*)\0*.*\0\0";
        if (!win32_dialog::show_open_file_dialog(g_hwnd,
                "Load Lua Script",
                k_lua_open_filter,
                path_buf, sizeof(path_buf),
                "network_view::load_script")) {
            return;
        }

        std::string path_str(path_buf);
        diag::log_tagged_fmt("network", "script_load_dialog_pick path='%s'", path_str.c_str());
        if (script_engine::load_script(path_str)) {
            std::filesystem::path fp(path_str);
            std::string stem = fp.stem().string();

            bool updated = false;
            for (auto& entry : state.scripts) {
                if (entry.name == stem) {
                    entry.path = path_str;
                    entry.loaded = true;
                    entry.enabled = true;
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                state_t::script_entry_t ne;
                ne.name = stem;
                ne.path = path_str;
                ne.enabled = true;
                ne.loaded = true;
                state.scripts.push_back(std::move(ne));
                state.script_selected = static_cast<int>(state.scripts.size()) - 1;
            }
            diag::log_tagged_fmt("network", "script_load_ok name='%s' path='%s' total_loaded=%zu",
                stem.c_str(), path_str.c_str(), state.scripts.size());
            toast_notification::push(std::string("Loaded script: ") + stem,
                                     toast_notification::toast_type_t::info);
        }
        else {
            diag::log_tagged_fmt("network", "script_load_failed path='%s'", path_str.c_str());
            toast_notification::push(std::string("Failed to load script: ") + path_str,
                                     toast_notification::toast_type_t::error);
        }
    };

    bool engine_up = script_engine::is_initialized();
    size_t hook_count = script_engine::registered_hook_count();

    float pad = 2.f;
    float content_y = 0.f;
    float content_h = h;
    float rail_w = std::min(264.f, std::max(220.f, w * 0.24f));

    {
        panel_frame_t lib = panel_begin(ImVec2(0.f, content_y),
            ImVec2(rail_w, content_h), alpha, "Script Library",
            aida::ui::empty_state::glyph_t::layers, true);

        {
            ImFont* mf = aida::ui::fonts::caption();
            float mfs = mf ? mf->FontSize : ImGui::GetFontSize();
            char lib_meta[40];
            snprintf(lib_meta, sizeof(lib_meta), "%zu hooks", hook_count);
            float meta_w = mf ? mf->CalcTextSizeA(mfs, FLT_MAX, 0.f, lib_meta).x
                              : ImGui::GetFont()->CalcTextSizeA(mfs, FLT_MAX, 0.f, lib_meta).x;
            float meta_x = lib.body_max.x - 14.f - meta_w;
            float meta_y = lib.origin.y + (lib.header_h - mfs) * 0.5f;
            if (mf)
                dl->AddText(mf, mfs, ImVec2(meta_x, meta_y),
                            aida::ui::with_alpha(th.text_dim, alpha), lib_meta);
            else
                dl->AddText(ImVec2(meta_x, meta_y),
                            aida::ui::with_alpha(th.text_dim, alpha), lib_meta);

            ImVec2 dot_c = ImVec2(meta_x - 12.f, lib.origin.y + lib.header_h * 0.5f);
            aida::ui::status_dot(dot_c, 3.f,
                aida::ui::with_alpha(engine_up ? th.success : th.error, alpha),
                engine_up, 1.1f);
        }

        float footer_h = 116.f;
        float list_top = lib.header_h + 6.f;
        float list_h = std::max(48.f, content_h - list_top - footer_h);

        ImGui::SetCursorPos(ImVec2(0.f, content_y + list_top));
        ImGui::BeginChild("##script_lib_list", ImVec2(rail_w, list_h), false,
                          ImGuiWindowFlags_NoBackground);
        ImDrawList* ldl = ImGui::GetWindowDrawList();
        ImVec2 lwin = ImGui::GetWindowPos();
        ImVec2 lsz = ImGui::GetWindowSize();

        if (state.scripts.empty()) {
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::binary_file;
            cfg.title = "No scripts loaded";
            cfg.body  = "Load a .lua file to register request, response and packet hooks.";
            cfg.max_width = rail_w - 32.f;
            aida::ui::empty_state::render(lwin, lsz, cfg);
        } else {
            float row_h = std::max(46.f, ImGui::GetFontSize() * 2.6f);
            float gap = 6.f;
            ldl->PushClipRect(lwin, ImVec2(lwin.x + lsz.x, lwin.y + lsz.y), true);

            for (size_t i = 0; i < state.scripts.size(); i++) {
                auto& s = state.scripts[i];
                float ry = static_cast<float>(i) * (row_h + gap);
                float abs_ry = lwin.y + ry - ImGui::GetScrollY();
                bool sel = (state.script_selected == static_cast<int>(i));

                ImVec2 ra = ImVec2(lwin.x + 6.f, abs_ry);
                ImVec2 rb = ImVec2(lwin.x + lsz.x - 6.f, abs_ry + row_h);

                ImVec2 mouse = ImGui::GetMousePos();
                bool hovered = (mouse.x >= ra.x && mouse.x < rb.x &&
                                mouse.y >= ra.y && mouse.y < rb.y);

                ImU32 card_fill = sel
                    ? aida::ui::with_alpha(th.selection, alpha)
                    : (hovered ? aida::ui::with_alpha(th.hover_wash, alpha)
                               : aida::ui::with_alpha(th.bg_elevated, alpha * 0.55f));
                ldl->AddRectFilled(ra, rb, card_fill, 8.f);
                ImU32 card_border = sel
                    ? aida::ui::with_alpha(th.accent_dim, alpha)
                    : aida::ui::with_alpha(th.border_subtle, alpha);
                ldl->AddRect(ra, rb, card_border, 8.f, 0, 1.f);

                if (sel) {
                    ldl->AddRectFilled(ra, ImVec2(ra.x + 3.f, rb.y),
                        aida::ui::with_alpha(th.accent_u32, alpha), 8.f,
                        ImDrawFlags_RoundCornersLeft);
                }

                if (hovered && ImGui::IsMouseClicked(0))
                    state.script_selected = static_cast<int>(i);

                ImU32 dot_col = !s.loaded
                    ? aida::ui::with_alpha(th.text_dim, alpha)
                    : (s.enabled ? aida::ui::with_alpha(th.success, alpha)
                                 : aida::ui::with_alpha(th.warning, alpha));
                ImVec2 dot_c = ImVec2(ra.x + 16.f, ra.y + row_h * 0.5f - ImGui::GetFontSize() * 0.32f);
                ldl->AddCircleFilled(dot_c, 4.f, dot_col, 16);
                ldl->AddCircle(dot_c, 6.f, aida::ui::with_alpha(dot_col, alpha * 0.4f), 16, 1.f);

                ImFont* nf = aida::ui::fonts::body_em();
                float nfs = nf ? nf->FontSize : ImGui::GetFontSize();
                ImU32 name_col = s.enabled
                    ? aida::ui::with_alpha(th.text_primary, alpha)
                    : aida::ui::with_alpha(th.text_secondary, alpha);
                if (nf)
                    ldl->AddText(nf, nfs, ImVec2(ra.x + 30.f, ra.y + 7.f), name_col, s.name.c_str());
                else
                    ldl->AddText(ImVec2(ra.x + 30.f, ra.y + 7.f), name_col, s.name.c_str());

                const char* state_label = !s.loaded ? "UNLOADED"
                                          : (s.enabled ? "ENABLED" : "PAUSED");
                ImU32 badge_col = !s.loaded ? th.text_dim
                                  : (s.enabled ? th.success : th.warning);
                ImFont* cf = aida::ui::fonts::caption();
                float cfs = cf ? cf->FontSize * 0.92f : ImGui::GetFontSize() * 0.82f;
                float bw = (cf ? cf->CalcTextSizeA(cfs, FLT_MAX, 0.f, state_label).x
                               : ImGui::GetFont()->CalcTextSizeA(cfs, FLT_MAX, 0.f, state_label).x)
                           + 14.f;
                ImVec2 ba = ImVec2(ra.x + 30.f, ra.y + 7.f + nfs + 4.f);
                ImVec2 bb = ImVec2(ba.x + bw, ba.y + cfs + 6.f);
                ldl->AddRectFilled(ba, bb, aida::ui::with_alpha(badge_col, alpha * 0.18f),
                                   (cfs + 6.f) * 0.5f);
                ldl->AddRect(ba, bb, aida::ui::with_alpha(badge_col, alpha * 0.5f),
                             (cfs + 6.f) * 0.5f, 0, 1.f);
                if (cf)
                    ldl->AddText(cf, cfs, ImVec2(ba.x + 7.f, ba.y + 3.f),
                                 aida::ui::with_alpha(badge_col, alpha), state_label);
                else
                    ldl->AddText(ImVec2(ba.x + 7.f, ba.y + 3.f),
                                 aida::ui::with_alpha(badge_col, alpha), state_label);

                if (!s.path.empty()) {
                    std::filesystem::path fp(s.path);
                    std::string fname = fp.filename().string();
                    float fnx = bb.x + 8.f;
                    if (cf && fnx < rb.x - 8.f) {
                        ldl->PushClipRect(ImVec2(fnx, ba.y), ImVec2(rb.x - 8.f, bb.y), true);
                        ldl->AddText(cf, cfs, ImVec2(fnx, ba.y + 3.f),
                                     aida::ui::with_alpha(th.text_dim, alpha), fname.c_str());
                        ldl->PopClipRect();
                    }
                }
            }

            ldl->PopClipRect();
            ImGui::Dummy(ImVec2(rail_w - 12.f,
                static_cast<float>(state.scripts.size()) * (row_h + gap)));
        }
        ImGui::EndChild();

        bool has_sel = state.script_selected >= 0 &&
                       state.script_selected < static_cast<int>(state.scripts.size());

        float footer_y = content_y + list_top + list_h + 6.f;
        ImVec2 fa = ImVec2(lib.origin.x + 8.f, lib.origin.y + list_top + list_h + 2.f);
        ImVec2 fb = ImVec2(lib.body_max.x - 8.f, lib.body_max.y - 8.f);
        dl->AddLine(ImVec2(fa.x, fa.y - 4.f), ImVec2(fb.x, fa.y - 4.f),
                    aida::ui::with_alpha(th.border_subtle, alpha), 1.f);

        ImGui::SetCursorPos(ImVec2(8.f, footer_y));
        if (aida::ui::button("Load Script", aida::ui::button_kind_t::primary,
                             aida::ui::size_t_::sm, ImVec2(rail_w - 16.f, 30.f)))
            load_script_from_dialog();

        float fbtn_w = (rail_w - 16.f - 8.f) * 0.5f;
        ImGui::SetCursorPos(ImVec2(8.f, footer_y + 36.f));
        bool can_unload = has_sel && state.scripts[static_cast<size_t>(state.script_selected)].loaded;
        if (aida::ui::button(can_unload ? "Unload" : "Unloaded",
                             aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm,
                             ImVec2(fbtn_w, 30.f), !can_unload) && can_unload) {
            auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            diag::log_tagged_fmt("network", "script_unload_clicked name='%s'", s.name.c_str());
            script_engine::unload_script(s.name);
            s.loaded = false;
        }
        ImGui::SameLine(0.f, 8.f);
        bool sel_enabled = has_sel && state.scripts[static_cast<size_t>(state.script_selected)].enabled;
        if (aida::ui::button(sel_enabled ? "Pause" : "Enable",
                             aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm,
                             ImVec2(fbtn_w, 30.f), !has_sel) && has_sel) {
            auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            s.enabled = !s.enabled;
            diag::log_tagged_fmt("network", "script_toggle_enabled name='%s' enabled=%d",
                s.name.c_str(), s.enabled ? 1 : 0);
            script_engine::set_script_enabled(s.name, s.enabled);
        }

        ImGui::SetCursorPos(ImVec2(8.f, footer_y + 72.f));
        bool can_edit = has_sel && !state.scripts[static_cast<size_t>(state.script_selected)].path.empty();
        if (aida::ui::button("Open in Editor", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(rail_w - 16.f, 30.f),
                             !can_edit) && can_edit) {
            const auto& s = state.scripts[static_cast<size_t>(state.script_selected)];
            std::ifstream ifs(s.path, std::ios::binary);
            if (ifs) {
                std::stringstream ss;
                ss << ifs.rdbuf();
                std::string contents = ss.str();
                size_t copy_n = std::min(contents.size(), sizeof(state.script_editor_buf) - 1);
                memcpy(state.script_editor_buf, contents.data(), copy_n);
                state.script_editor_buf[copy_n] = '\0';
            }
        }
    }

    float right_x = rail_w + pad * 2.f;
    float right_w = w - right_x;

    float console_field_h = std::max(30.f, ImGui::GetFontSize() + 14.f);
    float console_inner_pad = 8.f;
    float console_header_h = std::max(34.f, ImGui::GetFontSize() + 16.f);
    float console_h = console_header_h + console_field_h + console_inner_pad * 2.f;
    float editor_h = std::max(180.f, (content_h - console_h - pad * 4.f) * 0.52f);
    float log_h = std::max(150.f, content_h - editor_h - console_h - pad * 4.f);

    {
        panel_frame_t ed = panel_begin(
            ImVec2(right_x, content_y), ImVec2(right_w, editor_h), alpha,
            "Editor", aida::ui::empty_state::glyph_t::message, true);

        size_t char_count = strnlen(state.script_editor_buf, sizeof(state.script_editor_buf));
        int line_count = 1;
        for (size_t i = 0; i < char_count; i++)
            if (state.script_editor_buf[i] == '\n') line_count++;
        char ed_meta[64];
        snprintf(ed_meta, sizeof(ed_meta), "%d lines  -  %zu chars", line_count, char_count);
        panel_header_meta(ed, alpha, ed_meta, th.text_dim);

        float action_h = 38.f;
        float inner_pad = 8.f;
        float field_top = content_y + ed.header_h + inner_pad;
        float field_h = editor_h - ed.header_h - inner_pad * 2.f - action_h;

        ImVec2 fa = ImVec2(ed.origin.x + inner_pad, ed.body_min.y + inner_pad);
        ImVec2 fb = ImVec2(ed.body_max.x - inner_pad, fa.y + field_h);
        dl->AddRectFilled(fa, fb, aida::ui::with_alpha(th.bg_base, alpha * 0.85f), 8.f);

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.syn_identifier, alpha)));
        ImFont* code_font = aida::ui::fonts::code();
        bool code_pushed = false;
        if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad + 6.f, field_top + 5.f));
        ImGui::InputTextMultiline("##script_edit", state.script_editor_buf,
            sizeof(state.script_editor_buf),
            ImVec2(right_w - inner_pad * 2.f - 12.f, field_h - 10.f),
            ImGuiInputTextFlags_AllowTabInput);
        bool editor_active = ImGui::IsItemActive();

        if (code_pushed) ImGui::PopFont();
        ImGui::PopStyleColor(2);

        dl->AddRect(fa, fb, aida::ui::with_alpha(
            editor_active ? th.border_focus : th.border_subtle, alpha), 8.f, 0,
            editor_active ? 1.6f : 1.f);

        if (char_count == 0 && !editor_active) {
            ImFont* hint_font = aida::ui::fonts::code();
            float hfs = hint_font ? hint_font->FontSize : ImGui::GetFontSize();
            const char* hint = "-- write a Lua hook, e.g. function on_request(req) ... end";
            if (hint_font)
                dl->AddText(hint_font, hfs, ImVec2(fa.x + 12.f, fa.y + 8.f),
                            aida::ui::with_alpha(th.text_dim, alpha), hint);
            else
                dl->AddText(ImVec2(fa.x + 12.f, fa.y + 8.f),
                            aida::ui::with_alpha(th.text_dim, alpha), hint);
        }

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad,
            field_top + field_h + inner_pad - 4.f));
        bool has_src = char_count > 0;
        if (aida::ui::button("Run Script", aida::ui::button_kind_t::primary,
                             aida::ui::size_t_::sm, ImVec2(112.f, 30.f), !has_src) && has_src) {
            std::string src(state.script_editor_buf);
            diag::log_tagged_fmt("network", "script_editor_run size=%zu", src.size());
            (void)post_network_task("script_editor_run", aida::infra::executor::domain_t::diagnostics, "bounded_task", [src]() {
                bool ok = script_engine::load_script_source("_editor_", src);
                diag::log_tagged_fmt("network", "script_editor_run_result ok=%d size=%zu",
                    ok ? 1 : 0, src.size());
            });
        }
        ImGui::SameLine(0.f, 8.f);
        if (aida::ui::button("Clear", aida::ui::button_kind_t::secondary,
                             aida::ui::size_t_::sm, ImVec2(82.f, 30.f), !has_src) && has_src)
            memset(state.script_editor_buf, 0, sizeof(state.script_editor_buf));
        ImGui::SameLine(0.f, 8.f);
        if (aida::ui::button("Copy", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(72.f, 30.f), !has_src) && has_src)
            ImGui::SetClipboardText(state.script_editor_buf);
    }

    float console_y = content_y + editor_h + pad * 2.f;
    {
        panel_frame_t cs = panel_begin(
            ImVec2(right_x, console_y), ImVec2(right_w, console_h), alpha,
            "Console", aida::ui::empty_state::glyph_t::dots, true);

        panel_header_meta(cs, alpha, "Lua REPL", th.text_dim);

        float btn_w = 88.f;
        float field_h = console_field_h;

        ImVec2 fa = ImVec2(cs.origin.x + console_inner_pad, cs.body_min.y + console_inner_pad);
        ImVec2 fb = ImVec2(cs.body_max.x - console_inner_pad - btn_w - 8.f, fa.y + field_h);
        dl->AddRectFilled(fa, fb, aida::ui::with_alpha(th.bg_base, alpha * 0.85f), 8.f);

        ImFont* code_font = aida::ui::fonts::code();
        float prompt_fs = code_font ? code_font->FontSize : ImGui::GetFontSize();
        if (code_font)
            dl->AddText(code_font, prompt_fs, ImVec2(fa.x + 10.f, fa.y + (field_h - prompt_fs) * 0.5f),
                        aida::ui::with_alpha(th.accent_u32, alpha), ">");
        else
            dl->AddText(ImVec2(fa.x + 10.f, fa.y + (field_h - prompt_fs) * 0.5f),
                        aida::ui::with_alpha(th.accent_u32, alpha), ">");

        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_primary, alpha)));
        bool code_pushed = false;
        if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }

        ImGui::SetCursorScreenPos(ImVec2(fa.x + 26.f,
            fa.y + (field_h - ImGui::GetFontSize()) * 0.5f));
        ImGui::SetNextItemWidth(fb.x - fa.x - 36.f);
        bool enter = ImGui::InputTextWithHint("##scr_input", "print(2 + 2)",
            state.script_console_buf, sizeof(state.script_console_buf),
            ImGuiInputTextFlags_EnterReturnsTrue);
        bool console_active = ImGui::IsItemActive();

        if (code_pushed) ImGui::PopFont();
        ImGui::PopStyleColor(2);

        dl->AddRect(fa, fb, aida::ui::with_alpha(
            console_active ? th.border_focus : th.border_subtle, alpha), 8.f, 0,
            console_active ? 1.6f : 1.f);

        ImGui::SetCursorScreenPos(ImVec2(fb.x + 8.f, fa.y + (field_h - 30.f) * 0.5f));
        bool exec = aida::ui::button("Exec", aida::ui::button_kind_t::primary,
                                     aida::ui::size_t_::sm, ImVec2(btn_w, 30.f));
        if (exec || enter) {
            std::string cmd(state.script_console_buf);
            if (!cmd.empty()) {
                diag::log_tagged_fmt("network", "script_console_exec size=%zu", cmd.size());
                (void)post_network_task("script_console_exec", aida::infra::executor::domain_t::diagnostics, "bounded_task", [cmd]() {
                    std::string out = script_engine::execute(cmd);
                    diag::log_tagged_fmt("network", "script_console_exec_done out_size=%zu",
                        out.size());
                });
                memset(state.script_console_buf, 0, sizeof(state.script_console_buf));
            }
        }
    }

    float log_y = console_y + console_h + pad * 2.f;
    {
        panel_frame_t lg = panel_begin(
            ImVec2(right_x, log_y), ImVec2(right_w, log_h), alpha,
            "Engine Log", aida::ui::empty_state::glyph_t::memory, true);

        std::vector<script_engine::log_entry> entries = script_engine::get_log();
        size_t log_size = entries.size();

        float ctrl_w = 200.f;
        ImGui::SetCursorScreenPos(ImVec2(lg.body_max.x - ctrl_w - 12.f,
            lg.origin.y + (lg.header_h - 22.f) * 0.5f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            aida::ui::with_alpha(th.text_secondary, alpha)));
        aida::ui::toggle_switch("Auto-scroll##scriptlog", &state.script_log_auto_scroll);
        ImGui::PopStyleColor();
        ImGui::SameLine(0.f, 10.f);
        if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost,
                             aida::ui::size_t_::sm, ImVec2(64.f, 24.f),
                             log_size == 0) && log_size > 0) {
            script_engine::clear_log();
        }

        float inner_pad = 8.f;
        float scroll_top = log_y + lg.header_h + inner_pad;
        float scroll_h = log_h - lg.header_h - inner_pad * 2.f;
        if (scroll_h < 24.f) scroll_h = 24.f;

        ImVec2 sa = ImVec2(lg.origin.x + inner_pad, lg.body_min.y + inner_pad);
        ImVec2 sb = ImVec2(lg.body_max.x - inner_pad, lg.body_max.y - inner_pad);
        dl->AddRectFilled(sa, sb, aida::ui::with_alpha(th.bg_base, alpha * 0.7f), 8.f);
        dl->AddRect(sa, sb, aida::ui::with_alpha(th.border_subtle, alpha), 8.f, 0, 1.f);

        ImGui::SetCursorPos(ImVec2(right_x + inner_pad + 4.f, scroll_top + 4.f));
        ImGui::BeginChild("##script_log_scroll",
            ImVec2(right_w - inner_pad * 2.f - 8.f, scroll_h - 8.f), false,
            ImGuiWindowFlags_NoBackground);

        if (log_size == 0) {
            ImVec2 ewin = ImGui::GetWindowPos();
            ImVec2 esz = ImGui::GetWindowSize();
            aida::ui::empty_state::config_t cfg;
            cfg.glyph = aida::ui::empty_state::glyph_t::memory;
            cfg.title = "Log is empty";
            cfg.body  = "Output from print(), hook events and the REPL appears here.";
            cfg.max_width = std::min(360.f, esz.x - 32.f);
            aida::ui::empty_state::render(ewin, esz, cfg);
        } else {
            ImFont* code_font = aida::ui::fonts::code();
            bool code_pushed = false;
            if (code_font) { ImGui::PushFont(code_font); code_pushed = true; }
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 swin = ImGui::GetWindowPos();
            float fs = ImGui::GetFontSize();
            float line_h = ImGui::GetTextLineHeightWithSpacing();
            float avail_w = right_w - inner_pad * 2.f - 16.f;
            float ty = 0.f;

            float ts_w = ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, "00:00:00").x + 8.f;
            float tag_w = ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f, "WARN").x + 8.f;

            for (const auto& e : entries) {
                float row_y = swin.y + ty - ImGui::GetScrollY();
                ImU32 lvl_col = log_level_color(e.level, alpha);

                char ts_buf[16];
                format_log_timestamp(e.wall_seconds, ts_buf, sizeof(ts_buf));
                sdl->AddText(ImVec2(swin.x + 4.f, row_y),
                             aida::ui::with_alpha(th.text_dim, alpha), ts_buf);

                sdl->AddText(ImVec2(swin.x + 4.f + ts_w, row_y),
                             lvl_col, log_level_tag(e.level));

                float text_x = swin.x + 4.f + ts_w + tag_w;
                float text_right = swin.x + avail_w;

                std::string body;
                if (!e.script_name.empty() && e.script_name != "console" &&
                    e.script_name != "engine")
                    body = "[" + e.script_name + "] ";
                body += e.message;

                std::string repeat_badge;
                if (e.repeat_count > 1) {
                    char rb[24];
                    snprintf(rb, sizeof(rb), "  x%u", e.repeat_count);
                    repeat_badge = rb;
                }

                float badge_w = repeat_badge.empty()
                    ? 0.f
                    : ImGui::GetFont()->CalcTextSizeA(fs, FLT_MAX, 0.f,
                          repeat_badge.c_str()).x;

                sdl->PushClipRect(ImVec2(text_x, row_y),
                                  ImVec2(text_right - badge_w, row_y + line_h), true);
                sdl->AddText(ImVec2(text_x, row_y), lvl_col, body.c_str());
                sdl->PopClipRect();

                if (!repeat_badge.empty()) {
                    sdl->AddText(ImVec2(text_right - badge_w, row_y),
                                 aida::ui::with_alpha(th.text_dim, alpha),
                                 repeat_badge.c_str());
                }

                ty += line_h;
            }
            ImGui::Dummy(ImVec2(avail_w, ty));

            if (code_pushed) ImGui::PopFont();

            if (state.script_log_auto_scroll)
                ImGui::SetScrollHereY(1.0f);
        }

        ImGui::EndChild();
    }

    ImGui::EndChild();
}


static void render_decoder(state_t& state, float x, float y, float w, float h,
                            float alpha, float ar, float ag, float ab) {
    (void)ar; (void)ag; (void)ab;
    const auto& th = aida::ui::resolved();
    ImGui::SetCursorPos(ImVec2(x, y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##decoder_tab", ImVec2(w, h), false);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetWindowPos();
    ImU32 txt_col = aida::ui::with_alpha(th.text_primary, alpha);
    ImU32 dim_col = aida::ui::with_alpha(th.text_dim, alpha);
    (void)origin; (void)dim_col;


    float pipe_w = w * 0.3f;
    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##dec_pipeline", ImVec2(pipe_w, h), false);

    dl = ImGui::GetWindowDrawList();
    ImVec2 pp = ImGui::GetWindowPos();
    dl->AddText(ImVec2(pp.x + 8.f, pp.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Pipeline");


    ImGui::SetCursorPos(ImVec2(4.f, 24.f));
    auto& reg = decoder_pipeline::registry::instance();
    auto transforms = reg.all();


    static std::string combo_str;
    static size_t combo_str_count = 0;
    if (combo_str.empty() || combo_str_count != transforms.size()) {
        combo_str.clear();
        for (const auto& t : transforms) {
            combo_str += t->name;
            combo_str += '\0';
        }
        combo_str += '\0';
        combo_str_count = transforms.size();
    }

    ImGui::PushItemWidth(pipe_w - 90.f);
    ImGui::Combo("##dec_add", &state.decoder_add_transform, combo_str.c_str());
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (aida::ui::button("Add", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        if (state.decoder_add_transform >= 0 &&
            state.decoder_add_transform < static_cast<int>(transforms.size())) {
            state_t::decoder_step_t step;
            step.transform_name = transforms[static_cast<size_t>(state.decoder_add_transform)]->id;
            diag::log_tagged_fmt("network", "decoder_step_added name='%s' pipeline_size=%zu",
                step.transform_name.c_str(), state.decoder_pipeline.size() + 1);
            state.decoder_pipeline.push_back(std::move(step));
        }
    }


    float py = 50.f;
    for (size_t i = 0; i < state.decoder_pipeline.size(); i++) {
        auto& step = state.decoder_pipeline[i];
        float abs_py = pp.y + py;
        bool sel = (state.decoder_selected_step == static_cast<int>(i));

        if (sel) {
            dl->AddRectFilled(ImVec2(pp.x + 4.f, abs_py), ImVec2(pp.x + pipe_w - 4.f, abs_py + 22.f),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
        }

        ImVec2 mouse = ImGui::GetMousePos();
        if (mouse.x >= pp.x && mouse.x < pp.x + pipe_w &&
            mouse.y >= abs_py && mouse.y < abs_py + 22.f && ImGui::IsMouseClicked(0))
            state.decoder_selected_step = static_cast<int>(i);

        char label[256];
        snprintf(label, sizeof(label), "%zu. %s", i + 1, step.transform_name.c_str());
        dl->AddText(ImVec2(pp.x + 12.f, abs_py + 4.f), txt_col, label);


        ImGui::SetCursorPos(ImVec2(pipe_w - 28.f, py + 2.f));
        ImGui::PushID(static_cast<int>(i));
        if (aida::ui::button("X", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            state.decoder_pipeline.erase(state.decoder_pipeline.begin() + static_cast<ptrdiff_t>(i));
            if (state.decoder_selected_step >= static_cast<int>(i))
                state.decoder_selected_step--;
            ImGui::PopID();
            break;
        }
        ImGui::PopID();

        if (i + 1 < state.decoder_pipeline.size()) {
            float arrow_base_y = pp.y + py + 22.f;
            float arrow_cx = pp.x + pipe_w * 0.5f;
            ImU32 arrow_col = aida::ui::with_alpha(th.accent_u32, alpha * 0.6f);
            dl->AddLine(ImVec2(arrow_cx, arrow_base_y + 2.f), ImVec2(arrow_cx, arrow_base_y + 12.f), arrow_col, 1.5f);
            dl->AddTriangleFilled(
                ImVec2(arrow_cx - 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx + 4.f, arrow_base_y + 10.f),
                ImVec2(arrow_cx, arrow_base_y + 16.f),
                arrow_col);
            py += 40.f;
        } else {
            py += 24.f;
        }
    }

    ImGui::SetCursorPos(ImVec2(4.f, py + 8.f));
    if (aida::ui::button("Clear Pipeline", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        diag::log_tagged_fmt("network", "decoder_pipeline_cleared prev_size=%zu",
            state.decoder_pipeline.size());
        state.decoder_pipeline.clear();
        state.decoder_selected_step = -1;
    }
    ImGui::SameLine();
    if (aida::ui::button("Execute", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {

        std::string input(state.decoder_input);
        std::vector<uint8_t> data(input.begin(), input.end());
        diag::log_tagged_fmt("network", "decoder_execute steps=%zu input_size=%zu",
            state.decoder_pipeline.size(), data.size());

        bool failed = false;
        for (const auto& step : state.decoder_pipeline) {

            std::map<std::string, std::string> params;
            for (const auto& p : step.params)
                params[p.first] = p.second;
            auto result = decoder_pipeline::apply_single(step.transform_name, data, params);
            if (result.success)
                data = std::move(result.data);
            else {
                state.decoder_output = "Error at '" + step.transform_name + "': " + result.error;
                diag::log_tagged_fmt("network", "decoder_execute_step_failed step='%s' err='%s'",
                    step.transform_name.c_str(), result.error.c_str());
                data.clear();
                failed = true;
                break;
            }
        }
        if (!failed) {
            diag::log_tagged_fmt("network", "decoder_execute_done out_size=%zu", data.size());
        }

        if (!data.empty()) {

            bool printable = true;
            for (uint8_t b : data) {
                if (b != '\n' && b != '\r' && b != '\t' && (b < 32 || b > 126)) {
                    printable = false;
                    break;
                }
            }
            if (printable) {
                state.decoder_output.assign(data.begin(), data.end());
            } else {

                state.decoder_output.clear();
                for (size_t off = 0; off < data.size(); off += 16) {
                    char line[128];
                    int pos = snprintf(line, sizeof(line), "%04zx  ", off);
                    for (size_t j = 0; j < 16; j++) {
                        if (off + j < data.size())
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos),
                                "%02x ", data[off + j]);
                        else
                            pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
                    }
                    for (size_t j = 0; j < 16 && off + j < data.size(); j++) {
                        uint8_t c = data[off + j];
                        line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
                    }
                    line[pos] = '\0';
                    state.decoder_output += line;
                    state.decoder_output += '\n';
                }
            }
        }
    }

    ImGui::EndChild();


    float right_x = pipe_w + 2.f;
    float right_w = w - right_x;
    float input_h = h * 0.45f;
    float output_h = h - input_h;


    float dec_label_h = ImGui::GetFontSize() + 12.f;

    ImGui::SetCursorPos(ImVec2(right_x, 0.f));
    ImGui::BeginChild("##dec_input", ImVec2(right_w, input_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 ip = ImGui::GetWindowPos();
    dl->AddText(ImVec2(ip.x + 8.f, ip.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Input");

    ImGui::SetCursorPos(ImVec2(4.f, dec_label_h));
    ImGui::InputTextMultiline("##dec_in", state.decoder_input, sizeof(state.decoder_input),
        ImVec2(right_w - 8.f, input_h - dec_label_h - 6.f), ImGuiInputTextFlags_AllowTabInput);
    {
        ImVec2 bmin = ImGui::GetItemRectMin();
        ImVec2 bmax = ImGui::GetItemRectMax();
        if (ImGui::IsItemActive())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha), 6.f, 0, 1.8f);
        else if (ImGui::IsItemHovered())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha * 0.55f), 6.f, 0, 1.f);
    }
    ImGui::EndChild();


    ImGui::SetCursorPos(ImVec2(right_x, input_h));
    ImGui::BeginChild("##dec_output", ImVec2(right_w, output_h), false);
    dl = ImGui::GetWindowDrawList();
    ImVec2 op = ImGui::GetWindowPos();
    dl->AddText(ImVec2(op.x + 8.f, op.y + 4.f),
                 aida::ui::with_alpha(th.accent_u32, alpha), "Output");

    ImGui::SetCursorPos(ImVec2(4.f, dec_label_h));
    ImGui::InputTextMultiline("##dec_out",
        state.decoder_output.data(),
        state.decoder_output.size() + 1,
        ImVec2(right_w - 8.f, output_h - dec_label_h - 6.f),
        ImGuiInputTextFlags_ReadOnly);
    {
        ImVec2 bmin = ImGui::GetItemRectMin();
        ImVec2 bmax = ImGui::GetItemRectMax();
        if (ImGui::IsItemActive())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha), 6.f, 0, 1.8f);
        else if (ImGui::IsItemHovered())
            dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_focus, alpha * 0.55f), 6.f, 0, 1.f);
    }
    ImGui::EndChild();

    ImGui::PopStyleColor();
    ImGui::EndChild();
}


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    float dt = ImGui::GetIO().DeltaTime;
    const auto& th = aida::ui::resolved();
    const bool has_target = analysis_session::has_active_target();
    g_state.last_render_tick_ms.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);

    const float kNetMinWidth = 320.f;
    if (width < kNetMinWidth) {
        static bool s_logged_net_clamp = false;
        if (!s_logged_net_clamp) {
            s_logged_net_clamp = true;
            ::diag::log_tagged_fmt("responsive",
                "network_view clamp_overlay width=%.0f min=%.0f",
                width, kNetMinWidth);
        }
        ImVec2 wp = ImGui::GetWindowPos();
        aida::ui::responsive::draw_clamp_overlay(
            ImVec2(wp.x + pos_x, wp.y + pos_y),
            ImVec2(width, height),
            "Widen the panel to view network tools");
        return;
    }


    float tab_h = render_tab_bar(g_state, pos_x, pos_y, width, alpha, accent_r, accent_g, accent_b, dt);

    g_state.content_fade = ui_anim::smooth_lerp(g_state.content_fade, 1.f, 14.f, dt);
    float ca = alpha * std::max(g_state.content_fade, 0.3f);

    float content_y = pos_y + tab_h + 6.f;
    float content_h = height - tab_h - 6.f;
    if (!has_target && tab_requires_target(g_state.active_tab)) {
        ImVec2 wp = ImGui::GetWindowPos();
        aida::ui::no_target_overlay::render(
            ImVec2(wp.x + pos_x, wp.y + content_y),
            ImVec2(width, content_h),
            "No target attached",
            "This Network tool needs an attached process for driver-backed capture, PID filtering, TLS key capture, or PCAP export. Attach or launch a target to enable it.",
            alpha, aida::ui::empty_state::glyph_t::network);
        return;
    }
    if (!has_target) {
        float banner_h = render_no_target_banner(pos_x, content_y, width, ca);
        content_y += banner_h;
        content_h = std::max(0.f, content_h - banner_h);
    }

    int active_now = static_cast<int>(g_state.active_tab);
    if (active_now != s_last_active_tab) {
        diag::log_tagged_fmt("network", "tab_switch from=%d to=%d", s_last_active_tab, active_now);
        s_tab_content_in.start(0.220f, aida::motion::ease::out_cubic);
        s_last_active_tab = active_now;
    }
    s_tab_content_in.tick(dt);

    ImGui::PushStyleColor(ImGuiCol_FrameBg,         aida::ui::with_alpha(th.panel_header, alpha));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,  aida::ui::with_alpha(th.hover_wash, alpha));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,   aida::ui::with_alpha(th.selection, alpha));
    ImGui::PushStyleColor(ImGuiCol_Border,          aida::ui::with_alpha(th.border_subtle, alpha));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarBg,     IM_COL32(0,0,0,0));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrab,   aida::ui::with_alpha(th.accent_dim, alpha));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabHovered, aida::ui::with_alpha(th.accent_hover, alpha));
    ImGui::PushStyleColor(ImGuiCol_ScrollbarGrabActive,  aida::ui::with_alpha(th.accent_u32, alpha));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);

    switch (g_state.active_tab) {
        case sub_tab_t::connections:
            render_connections(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::capture:
            render_capture(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intercept:
            render_intercept(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::proxy:
            render_proxy(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::dns:
            render_dns(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::filters:
            render_filters(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::bandwidth:
            render_bandwidth(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::repeater:
            render_repeater(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::keylog:
            render_keylog(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::pcap_export:
            render_pcap_export(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::fuzzer:
            render_fuzzer(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::offensive:
            render_offensive(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::websocket:
            render_websocket(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scripting:
            render_scripting(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::decoder:
            render_decoder(g_state, pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::sitemap:
            aida::burp::sitemap::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scope:
            aida::burp::scope::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::cookies:
            aida::burp::cookie_jar::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::scanner:
            aida::burp::scanner_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::recon:
            aida::burp::recon_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::intruder:
            aida::burp::intruder_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::collab:
            aida::burp::collaborator_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::sequencer:
            aida::burp::sequencer_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::comparer:
            aida::burp::comparer_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::jwt:
            aida::burp::jwt_lab_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::mr:
            aida::burp::match_replace_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::session:
            aida::burp::session_handler_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::api:
            aida::burp::api_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::ws_edit:
            aida::burp::ws_editor_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::h2_edit:
            aida::burp::h2_editor_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::logger:
            aida::burp::logger_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::csp:
            aida::burp::csp::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::upstream:
            aida::burp::upstream::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::browser:
            aida::burp::browser::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::reports:
            aida::burp::report_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        case sub_tab_t::headless:
            aida::burp::headless_view::render(pos_x, content_y, width, content_h, ca, accent_r, accent_g, accent_b);
            break;
        default:
            break;
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(8);
}

}
