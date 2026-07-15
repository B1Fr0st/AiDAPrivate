#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#else
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#ifdef small
#undef small
#endif

#include "ws_editor_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "ws_editor.hpp"
#endif
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/fonts.hpp"
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

#include "imgui/imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <utility>

namespace aida {
namespace burp {
namespace ws_editor_view {

namespace {

state_t s_state;

const char* g_scheme_items[] = { "ws", "wss" };
const char* g_compose_modes[] = { "Text", "Binary hex", "Raw frame" };

std::vector<std::pair<std::string, std::string>> parse_headers(const char* buf)
{
    std::vector<std::pair<std::string, std::string>> out;
    std::string s(buf);
    size_t p = 0;
    while (p < s.size()) {
        size_t eol = s.find('\n', p);
        if (eol == std::string::npos) eol = s.size();
        std::string line = s.substr(p, eol - p);
        p = eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t cp = line.find(':');
        if (cp == std::string::npos) continue;
        std::string k = line.substr(0, cp);
        std::string v = line.substr(cp + 1);
        size_t kb = k.find_first_not_of(" \t");
        size_t ke = k.find_last_not_of(" \t");
        size_t vb = v.find_first_not_of(" \t");
        size_t ve = v.find_last_not_of(" \t");
        if (kb == std::string::npos || vb == std::string::npos) continue;
        out.emplace_back(k.substr(kb, ke - kb + 1), v.substr(vb, ve - vb + 1));
    }
    return out;
}

bool parse_hex_payload(const std::string& src, std::vector<uint8_t>& out)
{
    out.clear();
    std::string digits;
    for (char c : src) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) digits.push_back(c);
    }
    if (digits.size() % 2 != 0) return false;
    for (size_t i = 0; i + 1 < digits.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        char h = digits[i], l = digits[i + 1];
        hi = static_cast<uint8_t>(h <= '9' ? h - '0' : (std::tolower(static_cast<unsigned char>(h)) - 'a' + 10));
        lo = static_cast<uint8_t>(l <= '9' ? l - '0' : (std::tolower(static_cast<unsigned char>(l)) - 'a' + 10));
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

const char* opcode_name(uint8_t op)
{
    switch (op) {
        case 0x0: return "continuation";
        case 0x1: return "text";
        case 0x2: return "binary";
        case 0x8: return "close";
        case 0x9: return "ping";
        case 0xA: return "pong";
    }
    return "?";
}

}

state_t& get_state() { return s_state; }

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    s_state.active = true;

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(0, 0, 0, 0));
    ImGui::BeginChild("##wse_root", ImVec2(width, height), false);

    ImGui::SetCursorPos(ImVec2(8.f, 6.f));
    ImGui::SetNextItemWidth(80.f);
    ImGui::Combo("##wse_scheme", &s_state.scheme_idx, g_scheme_items, IM_ARRAYSIZE(g_scheme_items));
    ImGui::SameLine();
    aida::ui::input_text("##wse_host", s_state.host_buf, sizeof(s_state.host_buf),
                         "host.example.com", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("##wse_port", &s_state.port, 0, 0);
    if (s_state.port < 1) s_state.port = 1;
    if (s_state.port > 65535) s_state.port = 65535;
    ImGui::SameLine();
    aida::ui::input_text("##wse_path", s_state.path_buf, sizeof(s_state.path_buf),
                         "/socket", false, ImVec2(220.f, 28.f));
    ImGui::SameLine();
    ImGui::Checkbox("Verify TLS", &s_state.verify_tls);
    ImGui::SameLine();
    if (aida::ui::button("Connect", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm, ImVec2(0.f, 28.f))) {
        ws_editor::ws_connection_config_t cfg;
        cfg.scheme       = g_scheme_items[s_state.scheme_idx];
        cfg.host         = s_state.host_buf;
        cfg.port         = static_cast<uint16_t>(s_state.port);
        cfg.path         = s_state.path_buf;
        cfg.origin       = s_state.origin_buf;
        cfg.subprotocol  = s_state.subprotocol_buf;
        cfg.verify_tls   = s_state.verify_tls;
        cfg.headers      = parse_headers(s_state.headers_buf);
        ::diag::log_tagged_fmt("ws_v", "connect scheme=%s host=%s port=%d path=%s",
            cfg.scheme.c_str(), cfg.host.c_str(), cfg.port, cfg.path.c_str());
        {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.ws_view";
            sub.label = "ws.connect";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::external_tool;
            sub.priority = 3;
            sub.body = [cfg]() {
            uint64_t id = ws_editor::connect(cfg);
            std::lock_guard<std::mutex> lk(s_state.lock);
            if (id != 0) {
                ::diag::log_tagged_fmt("ws_v", "connected id=%llu", static_cast<unsigned long long>(id));
                s_state.last_action_kind = "ok";
                s_state.last_action = std::string("Connected id=") + std::to_string(id);
            } else {
                ::diag::log_tagged_fmt("ws_v", "connect_failed err='%s'", ws_editor::last_error().c_str());
                s_state.last_action_kind = "error";
                s_state.last_action = ws_editor::last_error();
            }
        };
            (void)::aida::infra::executor::submit(std::move(sub));
        }
    }

    ImGui::SetCursorPos(ImVec2(8.f, 40.f));
    aida::ui::input_text("##wse_origin", s_state.origin_buf, sizeof(s_state.origin_buf),
                         "Origin (optional)", false, ImVec2(280.f, 26.f));
    ImGui::SameLine();
    aida::ui::input_text("##wse_subp", s_state.subprotocol_buf, sizeof(s_state.subprotocol_buf),
                         "Sub-protocol", false, ImVec2(200.f, 26.f));

    ImGui::SetCursorPos(ImVec2(8.f, 72.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Headers (Name: value, one per line)");
    ImGui::SetCursorPos(ImVec2(8.f, 90.f));
    ImGui::InputTextMultiline("##wse_hdr", s_state.headers_buf, sizeof(s_state.headers_buf),
                              ImVec2(width - 16.f, 60.f));

    {
        std::lock_guard<std::mutex> lk(s_state.lock);
        if (!s_state.last_action.empty()) {
            ImGui::SetCursorPos(ImVec2(8.f, 152.f));
            ImU32 c = (s_state.last_action_kind == "error")
                ? aida::ui::with_alpha(th.error, alpha)
                : aida::ui::with_alpha(th.success, alpha);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(c), "%s", s_state.last_action.c_str());
        }
    }

    auto conns = ws_editor::list_connections();
    float content_y = 178.f;
    float content_h = height - content_y - 8.f;
    float left_w = 360.f;
    float right_w = width - left_w - 16.f;

    ImGui::SetCursorPos(ImVec2(0.f, content_y));
    ImGui::BeginChild("##wse_left", ImVec2(left_w, content_h), false);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Connections (%zu)", conns.size());
    ImGui::Separator();
    for (size_t i = 0; i < conns.size(); ++i) {
        const auto& c = conns[i];
        char buf[1024];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%llu] %s%s",
            static_cast<unsigned long long>(c.id), c.url.c_str(),
            c.connected ? "" : " (disconnected)");
        bool sel = (s_state.selected_conn_index == static_cast<int>(i));
        if (ImGui::Selectable(buf, sel)) {
            ::diag::log_tagged_fmt("ws_v", "connection_selected idx=%zu id=%llu url=%s",
                i, static_cast<unsigned long long>(c.id), c.url.c_str());
            s_state.selected_conn_index = static_cast<int>(i);
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "    sent=%zu recv=%zu err=%s",
                           c.frames_sent, c.frames_received,
                           c.last_error.empty() ? "(none)" : c.last_error.c_str());
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, content_y));
    ImGui::BeginChild("##wse_right", ImVec2(right_w, content_h), false);

    const size_t selected_conn_index = static_cast<size_t>(s_state.selected_conn_index);
    if (s_state.selected_conn_index >= 0 && selected_conn_index < conns.size()) {
        const auto& c = conns[selected_conn_index];
        uint64_t cid = c.id;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                           "%s [id=%llu]", c.url.c_str(), static_cast<unsigned long long>(cid));
        ImGui::SameLine();
        if (aida::ui::button("Disconnect", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("ws_v", "disconnect id=%llu", static_cast<unsigned long long>(cid));
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.ws_view";
                sub.label = "ws.disconnect";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [cid]() { ws_editor::disconnect(cid); };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear log", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("ws_v", "clear_frames id=%llu", static_cast<unsigned long long>(cid));
            ws_editor::clear_frames(cid);
        }
        ImGui::SameLine();
        if (aida::ui::button("Ping", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("ws_v", "send_ping id=%llu", static_cast<unsigned long long>(cid));
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.ws_view";
                sub.label = "ws.send_ping";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [cid]() { ws_editor::send_ping(cid, {}); };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
        ImGui::SameLine();
        if (aida::ui::button("Close", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("ws_v", "send_close id=%llu", static_cast<unsigned long long>(cid));
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.ws_view";
                sub.label = "ws.send_close";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [cid]() { ws_editor::send_close(cid, 1000, "user_close"); };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }

        float log_h = content_h * 0.55f;
        ImGui::BeginChild("##wse_log", ImVec2(right_w - 8.f, log_h), false);
        auto fr = ws_editor::frames(cid, 0, 0);
        ImFont* mono = aida::ui::fonts::code();
        if (mono) ImGui::PushFont(mono);
        for (const auto& f : fr) {
            ImU32 col = f.outbound
                ? aida::ui::with_alpha(th.warning, alpha)
                : aida::ui::with_alpha(th.info, alpha);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col), "%s op=%s len=%zu | %s",
                f.outbound ? "OUT" : "IN ",
                opcode_name(f.opcode),
                f.payload.size(),
                f.preview.c_str());
        }
        if (mono) ImGui::PopFont();
        ImGui::EndChild();

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Compose:");
        ImGui::SetNextItemWidth(140.f);
        ImGui::Combo("##wse_cm", &s_state.compose_mode_idx, g_compose_modes, IM_ARRAYSIZE(g_compose_modes));
        ImGui::SameLine();
        if (s_state.compose_mode_idx == 2) {
            ImGui::SetNextItemWidth(80.f);
            ImGui::InputInt("Op", &s_state.compose_opcode, 0, 0);
            ImGui::SameLine();
            ImGui::Checkbox("FIN", &s_state.compose_fin);
            ImGui::SameLine();
            ImGui::Checkbox("MASK", &s_state.compose_masked);
        }
        if (s_state.compose_mode_idx == 0) {
            ImGui::InputTextMultiline("##wse_text", s_state.compose_text_buf, sizeof(s_state.compose_text_buf),
                                      ImVec2(right_w - 16.f, content_h - log_h - 120.f));
        } else {
            ImGui::InputTextMultiline("##wse_hex", s_state.compose_hex_buf, sizeof(s_state.compose_hex_buf),
                                      ImVec2(right_w - 16.f, content_h - log_h - 120.f));
        }

        if (aida::ui::button("Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            int mode = s_state.compose_mode_idx;
            std::string text(s_state.compose_text_buf);
            std::string hex(s_state.compose_hex_buf);
            int opcode = s_state.compose_opcode & 0xF;
            bool fin = s_state.compose_fin;
            bool masked = s_state.compose_masked;
            ::diag::log_tagged_fmt("ws_v", "send_frame id=%llu mode=%d payload_len=%zu",
                static_cast<unsigned long long>(cid),
                mode,
                mode == 0 ? text.size() : hex.size());
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.ws_view";
                sub.label = "ws.send_frame";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [cid, mode, text, hex, opcode, fin, masked]() {
                if (mode == 0) {
                    ws_editor::send_text(cid, text);
                } else if (mode == 1) {
                    std::vector<uint8_t> bin;
                    if (parse_hex_payload(hex, bin)) ws_editor::send_binary(cid, bin);
                } else {
                    std::vector<uint8_t> bin;
                    parse_hex_payload(hex, bin);
                    ws_editor::send_raw_frame(cid, static_cast<uint8_t>(opcode), fin, masked, bin);
                }
            };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
    } else {
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No connection selected";
        cfg.body  = "Open a connection above, or select one from the list.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImVec2(right_w, content_h), cfg);
    }

    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

}
}
}
