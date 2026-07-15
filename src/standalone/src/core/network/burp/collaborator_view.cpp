#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "collaborator_view.hpp"
#include "collaborator.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "helpers/diag_log.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/components.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace collaborator_view {

namespace {

struct state_t
{
    char    bind_ip[64]      = "0.0.0.0";
    int     http_port        = 8444;
    int     dns_port         = 5353;
    int     smtp_port        = 2525;
    bool    enable_http      = true;
    bool    enable_dns       = true;
    bool    enable_smtp      = true;
    char    public_host[256] = "aidacollab.local";
    char    public_ip[64]    = "127.0.0.1";
    char    canned_body[1024] = {};
    char    canned_ct[128]   = "text/plain";

    std::string                                          filter_kind = "all";
    char                                                 filter_token[64] = {};
    char                                                 filter_ip[64]    = {};
    int                                                  selected_id     = -1;

    std::vector<aida::burp::collaborator::interaction_t> cached;
    uint64_t                                             cache_last_ms = 0;
    uint64_t                                             cache_max_id  = 0;

    std::string                                          last_generated_token;
    std::string                                          last_generated_domain;
};

static state_t g_view_state;

static void refresh_cache()
{
    auto snap = aida::burp::collaborator::snapshot_all(4096);
    g_view_state.cached = std::move(snap);
}

static bool interaction_matches(const aida::burp::collaborator::interaction_t& it)
{
    if (g_view_state.filter_kind != "all" && it.kind != g_view_state.filter_kind) return false;
    if (g_view_state.filter_token[0] != 0) {
        std::string filt = g_view_state.filter_token;
        if (it.payload_token.find(filt) == std::string::npos) return false;
    }
    if (g_view_state.filter_ip[0] != 0) {
        std::string filt = g_view_state.filter_ip;
        if (it.client_ip.find(filt) == std::string::npos) return false;
    }
    return true;
}

}

void initialize()
{
    ::diag::log_tagged("collaborator_v", "initialize");
}

void shutdown()
{
    ::diag::log_tagged("collaborator_v", "shutdown");
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##collab_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    auto status = aida::burp::collaborator::status();
    static bool s_last_running = false;
    if (status.running != s_last_running) {
        s_last_running = status.running;
        ::diag::log_tagged_fmt("collaborator_v", "render_state_change running=%d interactions=%zu tokens=%zu",
            status.running ? 1 : 0,
            status.interaction_count,
            status.token_count);
    }

    float bar_h = 64.f;
    ImGui::BeginChild("##collab_bar", ImVec2(width, bar_h), false, ImGuiWindowFlags_NoBackground);
    {
        ImVec2 p = ImGui::GetWindowPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(p, ImVec2(p.x + width, p.y + bar_h),
            aida::ui::with_alpha(th.panel_header, alpha * 0.7f), 8.f);
        dl->AddRect(p, ImVec2(p.x + width, p.y + bar_h),
            aida::ui::with_alpha(th.border_subtle, alpha), 8.f);
    }

    ImGui::SetCursorPos(ImVec2(12.f, 8.f));
    ImU32 ind_col = status.running
        ? aida::ui::with_alpha(th.success, alpha)
        : aida::ui::with_alpha(th.text_dim, alpha);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ind_col),
        status.running ? "RUNNING" : "STOPPED");

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "  HTTP %s:%d %s   DNS %s:%d %s   SMTP %s:%d %s",
        status.bind_ip.c_str(), static_cast<int>(status.http_port), status.http_alive ? "OK" : "--",
        status.bind_ip.c_str(), static_cast<int>(status.dns_port),  status.dns_alive  ? "OK" : "--",
        status.bind_ip.c_str(), static_cast<int>(status.smtp_port), status.smtp_alive ? "OK" : "--");

    ImGui::SetCursorPos(ImVec2(12.f, 30.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Public: %s -> %s   Interactions=%zu Tokens=%zu",
        status.public_host.c_str(), status.public_ip.c_str(),
        status.interaction_count, status.token_count);

    float btn_x = width - 480.f;
    if (btn_x < 320.f) btn_x = 320.f;
    ImGui::SetCursorPos(ImVec2(btn_x, 16.f));

    if (!status.running) {
        if (aida::ui::button("Start", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            aida::burp::collaborator::collaborator_config_t cfg;
            cfg.bind_ip = g_view_state.bind_ip;
            cfg.http_port = static_cast<uint16_t>(g_view_state.http_port);
            cfg.dns_port  = static_cast<uint16_t>(g_view_state.dns_port);
            cfg.smtp_port = static_cast<uint16_t>(g_view_state.smtp_port);
            cfg.enable_http = g_view_state.enable_http;
            cfg.enable_dns  = g_view_state.enable_dns;
            cfg.enable_smtp = g_view_state.enable_smtp;
            cfg.public_host = g_view_state.public_host;
            cfg.public_ip   = g_view_state.public_ip;
            cfg.canned_body = g_view_state.canned_body;
            cfg.canned_content_type = g_view_state.canned_ct[0] ? g_view_state.canned_ct : "text/plain";
            bool ok = aida::burp::collaborator::start(cfg);
            ::diag::log_tagged_fmt("collaborator", "ui_start ok=%d", ok ? 1 : 0);
        }
    } else {
        if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            aida::burp::collaborator::stop();
            ::diag::log_tagged("collaborator", "ui_stop");
        }
    }

    ImGui::SameLine();
    if (aida::ui::button("Generate Token", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        std::string tok = aida::burp::collaborator::generate_token();
        auto cfg = aida::burp::collaborator::current_config();
        g_view_state.last_generated_token = tok;
        g_view_state.last_generated_domain = tok + "." + cfg.public_host;
        ::diag::log_tagged_fmt("collaborator_v", "generate_token token=%s domain=%s",
            tok.c_str(), g_view_state.last_generated_domain.c_str());
    }
    ImGui::SameLine();
    if (aida::ui::button("Copy Domain", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        if (!g_view_state.last_generated_domain.empty()) {
            ImGui::SetClipboardText(g_view_state.last_generated_domain.c_str());
            ::diag::log_tagged_fmt("collaborator_v", "copy_domain domain=%s", g_view_state.last_generated_domain.c_str());
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        aida::burp::collaborator::clear();
        g_view_state.selected_id = -1;
        ::diag::log_tagged("collaborator_v", "clear_interactions");
    }

    ImGui::EndChild();

    float cfg_y = bar_h + 6.f;
    float cfg_h = status.running ? 36.f : 110.f;
    ImGui::SetCursorPos(ImVec2(0.f, cfg_y));
    ImGui::BeginChild("##collab_cfg", ImVec2(width, cfg_h), false, ImGuiWindowFlags_NoBackground);

    if (!status.running) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Bind IP");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_bind", g_view_state.bind_ip, sizeof(g_view_state.bind_ip));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Public host");
        ImGui::SameLine();
        ImGui::PushItemWidth(220.f);
        ImGui::InputText("##c_phost", g_view_state.public_host, sizeof(g_view_state.public_host));
        ImGui::PopItemWidth();

        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Public IP");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_pip", g_view_state.public_ip, sizeof(g_view_state.public_ip));
        ImGui::PopItemWidth();

        ImGui::Checkbox("HTTP", &g_view_state.enable_http);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_hport", &g_view_state.http_port);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::Checkbox("DNS", &g_view_state.enable_dns);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_dport", &g_view_state.dns_port);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::Checkbox("SMTP", &g_view_state.enable_smtp);
        ImGui::SameLine();
        ImGui::PushItemWidth(80.f);
        ImGui::InputInt("##c_sport", &g_view_state.smtp_port);
        ImGui::PopItemWidth();

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Canned body");
        ImGui::SameLine();
        ImGui::PushItemWidth(width - 320.f);
        ImGui::InputText("##c_body", g_view_state.canned_body, sizeof(g_view_state.canned_body));
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "CT");
        ImGui::SameLine();
        ImGui::PushItemWidth(140.f);
        ImGui::InputText("##c_ct", g_view_state.canned_ct, sizeof(g_view_state.canned_ct));
        ImGui::PopItemWidth();
    } else {
        if (!g_view_state.last_generated_domain.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                "Last token domain: %s", g_view_state.last_generated_domain.c_str());
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Click Generate Token to issue a callback domain.");
        }
    }

    ImGui::EndChild();

    float filt_y = cfg_y + cfg_h + 6.f;
    float filt_h = 36.f;
    ImGui::SetCursorPos(ImVec2(0.f, filt_y));
    ImGui::BeginChild("##collab_filter", ImVec2(width, filt_h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Filter:");
    ImGui::SameLine();
    const char* kinds[] = { "all", "http", "dns", "smtp" };
    int cur = 0;
    for (int i = 0; i < 4; ++i) if (g_view_state.filter_kind == kinds[i]) { cur = i; break; }
    ImGui::PushItemWidth(80.f);
    if (ImGui::Combo("##c_kind", &cur, kinds, 4)) {
        g_view_state.filter_kind = kinds[cur];
        ::diag::log_tagged_fmt("collaborator_v", "filter_kind_changed kind=%s", g_view_state.filter_kind.c_str());
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Token");
    ImGui::SameLine();
    ImGui::PushItemWidth(160.f);
    ImGui::InputText("##c_ftok", g_view_state.filter_token, sizeof(g_view_state.filter_token));
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
        "Client IP");
    ImGui::SameLine();
    ImGui::PushItemWidth(120.f);
    ImGui::InputText("##c_fip", g_view_state.filter_ip, sizeof(g_view_state.filter_ip));
    ImGui::PopItemWidth();

    ImGui::EndChild();

    float list_y = filt_y + filt_h + 6.f;
    float list_h = height - list_y - 8.f;
    float left_w = width * 0.50f;
    float right_w = width - left_w - 8.f;

    refresh_cache();

    ImGui::SetCursorPos(ImVec2(0.f, list_y));
    ImGui::BeginChild("##collab_list", ImVec2(left_w, list_h), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Interactions");

    if (ImGui::BeginTable("##c_intable", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("ID",     ImGuiTableColumnFlags_WidthFixed, 60.f);
        ImGui::TableSetupColumn("Time",   ImGuiTableColumnFlags_WidthFixed, 100.f);
        ImGui::TableSetupColumn("Kind",   ImGuiTableColumnFlags_WidthFixed, 60.f);
        ImGui::TableSetupColumn("Client", ImGuiTableColumnFlags_WidthFixed, 120.f);
        ImGui::TableSetupColumn("Token",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (size_t i = g_view_state.cached.size(); i > 0; --i) {
            const auto& it = g_view_state.cached[i - 1];
            if (!interaction_matches(it)) continue;
            ImGui::TableNextRow();
            bool sel = (static_cast<int>(it.id) == g_view_state.selected_id);

            ImGui::TableSetColumnIndex(0);
            char idbuf[32];
            snprintf(idbuf, sizeof(idbuf), "%llu", static_cast<unsigned long long>(it.id));
            if (ImGui::Selectable(idbuf, sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_view_state.selected_id = static_cast<int>(it.id);
                ::diag::log_tagged_fmt("collaborator_v", "interaction_selected id=%llu kind=%s client=%s",
                    static_cast<unsigned long long>(it.id), it.kind.c_str(), it.client_ip.c_str());
            }

            uint64_t age = (status.started_ms == 0) ? 0 : (it.timestamp_ms > status.started_ms ? it.timestamp_ms - status.started_ms : 0);
            uint64_t s = age / 1000;
            uint64_t ms = age % 1000;
            char tbuf[32];
            snprintf(tbuf, sizeof(tbuf), "+%llu.%03llus",
                static_cast<unsigned long long>(s),
                static_cast<unsigned long long>(ms));
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(tbuf);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(it.kind.c_str());
            ImGui::TableSetColumnIndex(3);
            char ipbuf[80];
            snprintf(ipbuf, sizeof(ipbuf), "%s:%u", it.client_ip.c_str(), static_cast<unsigned>(it.client_port));
            ImGui::TextUnformatted(ipbuf);
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(it.payload_token.empty() ? "-" : it.payload_token.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, list_y));
    ImGui::BeginChild("##collab_detail", ImVec2(right_w, list_h), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
        "Detail");

    aida::burp::collaborator::interaction_t* sel_it = nullptr;
    if (g_view_state.selected_id >= 0) {
        for (auto& it : g_view_state.cached) {
            if (static_cast<int>(it.id) == g_view_state.selected_id) { sel_it = &it; break; }
        }
    }

    if (sel_it) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "id=%llu kind=%s client=%s:%u subdomain=%s token=%s",
            static_cast<unsigned long long>(sel_it->id),
            sel_it->kind.c_str(),
            sel_it->client_ip.c_str(),
            static_cast<unsigned>(sel_it->client_port),
            sel_it->subdomain.c_str(),
            sel_it->payload_token.empty() ? "-" : sel_it->payload_token.c_str());

        if (ImGui::BeginTable("##c_det_tbl", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 120.f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            for (const auto& kv : sel_it->details) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(kv.first.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextWrapped("%s", kv.second.c_str());
            }
            ImGui::EndTable();
        }

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
            "Raw");
        static std::string s_raw_view;
        s_raw_view = sel_it->raw;
        ImGui::InputTextMultiline("##c_raw", s_raw_view.data(), s_raw_view.size() + 1,
            ImVec2(right_w - 8.f, list_h - 200.f),
            ImGuiInputTextFlags_ReadOnly);
    } else {
        ImVec2 rp = ImGui::GetCursorScreenPos();
        ImVec2 rs = ImVec2(right_w, list_h - 32.f);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No interaction selected";
        cfg.body  = "Click an entry on the left to view the raw payload, headers, and decoded details.";
        aida::ui::empty_state::render(rp, rs, cfg);
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
