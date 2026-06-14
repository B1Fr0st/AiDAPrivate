#include "browser_view.hpp"
#include "browser_launch.hpp"
#include "camoufox_bridge.hpp"
#include "../mitm_proxy.hpp"
#include "../cert_generator.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace browser {

namespace {

struct view_state_t
{
    char        initial_url[512] = "about:blank";
    char        profile_subdir[128] = "BurpBrowser";
    int         certificate_strategy = static_cast<int>(certificate_strategy_t::camoufox_spki_allowlist);
    bool        clear_profile_first = false;
    int         proxy_port_override = 0;
    bool        use_proxy_override = false;
    std::string last_launch_status;
    std::atomic<bool> launching{false};
    std::mutex  status_mtx;
    float       anim_time = 0.f;
    uint64_t    cert_status_checked_ms = 0;
    bool        ca_ready = false;
    bool        ca_installed = false;
    std::string spki_prefix;
};

view_state_t& vs()
{
    static view_state_t st;
    return st;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string format_elapsed(uint64_t launched_ms)
{
    if (launched_ms == 0) return "-";
    uint64_t now = now_ms();
    if (now < launched_ms) return "0s";
    uint64_t diff = (now - launched_ms) / 1000ULL;
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

certificate_strategy_t selected_certificate_strategy(view_state_t& st)
{
    certificate_strategy_t strategy = static_cast<certificate_strategy_t>(st.certificate_strategy);
    if (strategy == certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only &&
        !certificate_strategy_debug_only_available()) {
        strategy = certificate_strategy_t::camoufox_spki_allowlist;
        st.certificate_strategy = static_cast<int>(strategy);
    }
    return strategy;
}

void refresh_cert_status(view_state_t& st)
{
    uint64_t now = now_ms();
    if (st.cert_status_checked_ms != 0 && now - st.cert_status_checked_ms < 1500)
        return;
    st.cert_status_checked_ms = now;
    st.ca_ready = ::cert_generator::is_ready();
    st.ca_installed = false;
    st.spki_prefix.clear();
    if (st.ca_ready) {
        const auto& ca = ::cert_generator::get_root_ca();
        st.ca_installed = ::cert_generator::is_root_ca_installed(ca);
        st.spki_prefix = spki_hash_prefix(::cert_generator::spki_sha256_base64(ca));
    }
}

const char* bridge_state_label(aida::burp::camoufox::bridge_state_t state)
{
    switch (state) {
    case aida::burp::camoufox::bridge_state_t::stopped: return "stopped";
    case aida::burp::camoufox::bridge_state_t::starting: return "starting";
    case aida::burp::camoufox::bridge_state_t::ready: return "ready";
    case aida::burp::camoufox::bridge_state_t::error: return "error";
    default: return "unknown";
    }
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = vs();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_browser_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Camoufox browser launcher");

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 40.f));
    ImGui::PushID("burp_browser_form");

    auto bridge_status = aida::burp::camoufox::get_status();
    const bool bridge_ready = bridge_status.state == aida::burp::camoufox::bridge_state_t::ready &&
        bridge_status.child_alive && bridge_status.browser_open && bridge_status.page_verified && !bridge_status.cleanup_pending;
    refresh_cert_status(st);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Camoufox %s   PID %u   open %s   verified %s   cleanup %s",
                       bridge_ready ? "ready" : bridge_state_label(bridge_status.state),
                       static_cast<unsigned>(bridge_status.child_pid),
                       bridge_status.browser_open ? "yes" : "no",
                       bridge_status.page_verified ? "yes" : "no",
                       bridge_status.cleanup_pending ? "yes" : "no");
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "CA ready %s   Installed %s   SPKI %s",
                       st.ca_ready ? "yes" : "no",
                       st.ca_installed ? "yes" : "no",
                       st.spki_prefix.empty() ? "-" : st.spki_prefix.c_str());

    ImGui::Spacing();

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "URL:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(420.f);
    ImGui::InputTextWithHint("##bb_url", "about:blank", st.initial_url, sizeof(st.initial_url));

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Profile subdir:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.f);
    ImGui::InputTextWithHint("##bb_profile", "BurpBrowser", st.profile_subdir, sizeof(st.profile_subdir));

    const char* strategy_names[] = {
        "trust_store_only",
        "camoufox_spki_allowlist",
        "unsafe_ignore_all_for_debug_builds_only"
    };
    int strategy_values[] = {
        static_cast<int>(certificate_strategy_t::trust_store_only),
        static_cast<int>(certificate_strategy_t::camoufox_spki_allowlist),
        static_cast<int>(certificate_strategy_t::unsafe_ignore_all_for_debug_builds_only)
    };
    int strategy_count = certificate_strategy_debug_only_available() ? 3 : 2;
    int strategy_index = 1;
    for (int i = 0; i < strategy_count; ++i) {
        if (strategy_values[i] == st.certificate_strategy) {
            strategy_index = i;
            break;
        }
    }
    ImGui::SetNextItemWidth(250.f);
    if (ImGui::Combo("Certificate strategy", &strategy_index, strategy_names, strategy_count)) {
        st.certificate_strategy = strategy_values[strategy_index];
    }
    ImGui::SameLine();
    ImGui::Checkbox("Clear profile first", &st.clear_profile_first);

    ImGui::Checkbox("Override proxy port", &st.use_proxy_override);
    if (st.use_proxy_override) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(100.f);
        ImGui::InputInt("##bb_port", &st.proxy_port_override);
        if (st.proxy_port_override < 1) st.proxy_port_override = 1;
        if (st.proxy_port_override > 65535) st.proxy_port_override = 65535;
    }

    ImGui::Spacing();

    bool busy = st.launching.load();
    if (busy) ImGui::BeginDisabled();
    if (ImGui::Button("Open Camoufox", ImVec2(180.f, 28.f))) {
        browser_launch_config_t cfg;
        cfg.initial_url = std::string(st.initial_url);
        cfg.profile_subdir = std::string(st.profile_subdir);
        cfg.certificate_strategy = selected_certificate_strategy(st);
        cfg.clear_profile_first = st.clear_profile_first;
        cfg.proxy_host = "127.0.0.1";
        if (st.use_proxy_override && st.proxy_port_override > 0) {
            cfg.proxy_port = static_cast<uint16_t>(st.proxy_port_override);
        } else {
            cfg.proxy_port = mitm_proxy::g_state.config.bind_port;
            if (cfg.proxy_port == 0) cfg.proxy_port = 8443;
        }
        uint32_t pid = 0;
        st.launching.store(true);
        bool ok = launch(cfg, pid);
        st.launching.store(false);
        char buf[256];
        if (ok) {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Launched Camoufox bridge pid=%u proxy=127.0.0.1:%u strategy=%s",
                        pid, static_cast<unsigned>(cfg.proxy_port),
                        certificate_strategy_name(cfg.certificate_strategy));
        } else {
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Launch failed: %s", last_error().c_str());
        }
        std::lock_guard<std::mutex> lk(st.status_mtx);
        st.last_launch_status = buf;
    }
    if (busy) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Stop Camoufox", ImVec2(160.f, 28.f))) {
        kill_all();
        std::lock_guard<std::mutex> lk(st.status_mtx);
        st.last_launch_status = "camoufox_stopped";
    }

    {
        std::lock_guard<std::mutex> lk(st.status_mtx);
        if (!st.last_launch_status.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", st.last_launch_status.c_str());
        }
    }

    ImGui::PopID();

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 240.f));
    ImGui::BeginChild("##burp_browser_table", ImVec2(width - 12.f, height - 250.f),
                      false, ImGuiWindowFlags_NoBackground);

    st.anim_time += ImGui::GetIO().DeltaTime;
    auto rows = list_running();

    ImVec2 table_org = ImGui::GetWindowPos();
    const float row_h = 24.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    const float col_pid = 72.f;
    const float col_port = 80.f;
    const float col_elapsed = 90.f;
    const float col_strategy = 172.f;
    const float col_spki = 88.f;
    const float col_actions = 96.f;
    const float remain = (width - 12.f) - col_pid - col_port - col_elapsed - col_strategy - col_spki - col_actions - 24.f;
    const float col_profile = std::max(160.f, remain * 0.5f);
    const float col_browser = std::max(160.f, remain - col_profile);

    dl->AddRectFilled(ImVec2(table_org.x, table_org.y), ImVec2(table_org.x + width - 12.f, table_org.y + row_h),
                      aida::ui::with_alpha(th.panel_header, alpha));
    float cx = table_org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "PID");       cx += col_pid;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Proxy");     cx += col_port;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Uptime");    cx += col_elapsed;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Strategy");  cx += col_strategy;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "SPKI");      cx += col_spki;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Browser");   cx += col_browser;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Profile");   cx += col_profile;
    dl->AddText(ImVec2(cx, table_org.y + text_oy), hdr_col, "Actions");

    ImGui::SetCursorPosY(row_h + 4.f);

    int visible = 0;
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& r = rows[i];
        float ra = ui_anim::render_row_entrance(visible, st.anim_time, 0.012f);
        float r_alpha = alpha * ra;
        float abs_ry = ImGui::GetCursorScreenPos().y;
        if (visible & 1) {
            dl->AddRectFilled(ImVec2(table_org.x, abs_ry),
                              ImVec2(table_org.x + width - 12.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }

        ImGui::PushID(static_cast<int>(r.pid));
        ImGui::InvisibleButton("##bb_row", ImVec2(width - 12.f, row_h));

        ImU32 txt = aida::ui::with_alpha(r.running ? th.text_primary : th.text_dim, r_alpha);
        ImU32 status_col = aida::ui::with_alpha(r.running ? th.success : th.error, r_alpha);
        float ty = abs_ry + text_oy;
        float lx = table_org.x + 8.f;

        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%u", static_cast<unsigned>(r.pid));
        dl->AddText(ImVec2(lx, ty), txt, buf); lx += col_pid;

        _snprintf_s(buf, sizeof(buf), _TRUNCATE, ":%u", static_cast<unsigned>(r.proxy_port));
        dl->AddText(ImVec2(lx, ty), txt, buf); lx += col_port;

        std::string elapsed = format_elapsed(r.launched_ms);
        dl->AddText(ImVec2(lx, ty), status_col, elapsed.c_str()); lx += col_elapsed;

        dl->AddText(ImVec2(lx, ty), txt, certificate_strategy_name(r.certificate_strategy)); lx += col_strategy;

        const char* spki = r.spki_hash_prefix.empty() ? "-" : r.spki_hash_prefix.c_str();
        dl->AddText(ImVec2(lx, ty), txt, spki); lx += col_spki;

        const char* bp = r.browser_path.c_str();
        dl->AddText(ImVec2(lx, ty), txt, bp); lx += col_browser;

        const char* pp = r.profile_path.c_str();
        dl->AddText(ImVec2(lx, ty), txt, pp); lx += col_profile;

        ImGui::SetCursorScreenPos(ImVec2(lx, abs_ry + (row_h - ImGui::GetFrameHeight()) * 0.5f));
        if (ImGui::SmallButton("Kill")) {
            kill(r.pid);
        }
        ImGui::PopID();
        ++visible;
    }

    if (rows.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "No tracked browser processes.");
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
