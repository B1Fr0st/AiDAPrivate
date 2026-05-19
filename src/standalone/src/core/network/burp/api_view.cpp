#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "api_view.hpp"
#include "api_definition.hpp"
#include "audit_http.hpp"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/fonts.hpp"
#include "../../infra/work_queue.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>

namespace aida {
namespace burp {
namespace api_view {

namespace {

state_t s_state;

std::map<std::string, std::string> parse_kv_lines(const char* buf)
{
    std::map<std::string, std::string> out;
    std::string s(buf);
    size_t p = 0;
    while (p < s.size()) {
        size_t eol = s.find('\n', p);
        if (eol == std::string::npos) eol = s.size();
        std::string line = s.substr(p, eol - p);
        p = eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) eq = line.find(':');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        size_t kb = k.find_first_not_of(" \t");
        size_t ke = k.find_last_not_of(" \t");
        size_t vb = v.find_first_not_of(" \t");
        size_t ve = v.find_last_not_of(" \t");
        if (kb == std::string::npos || vb == std::string::npos) continue;
        out[k.substr(kb, ke - kb + 1)] = v.substr(vb, ve - vb + 1);
    }
    return out;
}

const char* g_format_items[] = { "auto", "openapi_json", "openapi_yaml", "swagger_v2", "postman_v2_1", "har", "graphql_sdl" };

api_definition::api_format_t fmt_from_idx(int i)
{
    switch (i) {
        case 0: return api_definition::api_format_t::auto_detect;
        case 1: return api_definition::api_format_t::openapi_json;
        case 2: return api_definition::api_format_t::openapi_yaml;
        case 3: return api_definition::api_format_t::swagger_v2;
        case 4: return api_definition::api_format_t::postman_v2_1;
        case 5: return api_definition::api_format_t::har;
        case 6: return api_definition::api_format_t::graphql_sdl;
    }
    return api_definition::api_format_t::auto_detect;
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
    ImGui::BeginChild("##api_root", ImVec2(width, height), false);

    float toolbar_h = 64.f;

    ImGui::SetCursorPos(ImVec2(8.f, 6.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Import path/url:");
    ImGui::SameLine();
    aida::ui::input_text("##api_imp", s_state.import_path_buf, sizeof(s_state.import_path_buf),
                         "Local path or http(s):// URL", false, ImVec2(420.f, 28.f));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.f);
    ImGui::Combo("##api_fmt", &s_state.import_format_idx, g_format_items, IM_ARRAYSIZE(g_format_items));
    ImGui::SameLine();
    bool importing = s_state.importing.load();
    if (importing) ImGui::BeginDisabled();
    if (aida::ui::button("Import", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm, ImVec2(0.f, 28.f))) {
        std::string what(s_state.import_path_buf);
        api_definition::api_format_t fmt = fmt_from_idx(s_state.import_format_idx);
        s_state.importing.store(true);
        work_queue::post([what, fmt]() {
            uint64_t id = 0;
            if (what.rfind("http://", 0) == 0 || what.rfind("https://", 0) == 0)
                id = api_definition::import_from_url(what);
            else
                id = api_definition::import_from_file(what, fmt);
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                if (id != 0) {
                    s_state.last_action_kind    = "ok";
                    s_state.last_action_message = std::string("Imported collection id=") + std::to_string(id);
                } else {
                    s_state.last_action_kind    = "error";
                    s_state.last_action_message = api_definition::last_error();
                }
            }
            s_state.importing.store(false);
        });
    }
    if (importing) ImGui::EndDisabled();

    ImGui::SetCursorPos(ImVec2(8.f, 36.f));
    {
        std::lock_guard<std::mutex> lk(s_state.lock);
        if (!s_state.last_action_message.empty()) {
            ImU32 c = (s_state.last_action_kind == "error")
                        ? aida::ui::with_alpha(th.error, alpha)
                        : aida::ui::with_alpha(th.success, alpha);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(c), "%s", s_state.last_action_message.c_str());
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "Drop OpenAPI / Postman / HAR / GraphQL files here, or paste a URL.");
        }
    }

    auto collections = api_definition::list_collections();

    float content_y = toolbar_h + 4.f;
    float content_h = height - content_y;
    float left_w = 320.f;
    float center_w = 360.f;
    float right_w = width - left_w - center_w - 24.f;
    if (right_w < 280.f) right_w = 280.f;

    ImGui::SetCursorPos(ImVec2(0.f, content_y));
    ImGui::BeginChild("##api_left", ImVec2(left_w, content_h), false);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Collections (%zu)", collections.size());
    ImGui::Separator();
    for (size_t i = 0; i < collections.size(); ++i) {
        const auto& c = collections[i];
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s [%s] (%zu reqs)",
            c.name.c_str(), api_definition::format_label(c.format), c.requests.size());
        bool sel = (s_state.selected_collection_index == static_cast<int>(i));
        if (ImGui::Selectable(buf, sel)) {
            s_state.selected_collection_index = static_cast<int>(i);
            s_state.selected_request_index    = -1;
        }
        if (ImGui::BeginPopupContextItem(buf)) {
            if (ImGui::MenuItem("Remove")) {
                api_definition::remove_collection(c.id);
                s_state.selected_collection_index = -1;
                s_state.selected_request_index    = -1;
            }
            ImGui::EndPopup();
        }
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, content_y));
    ImGui::BeginChild("##api_center", ImVec2(center_w, content_h), false);
    if (s_state.selected_collection_index >= 0 && s_state.selected_collection_index < static_cast<int>(collections.size())) {
        const auto& c = collections[s_state.selected_collection_index];
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Requests in %s", c.name.c_str());
        ImGui::Separator();
        for (size_t i = 0; i < c.requests.size(); ++i) {
            const auto& r = c.requests[i];
            char buf[512];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s %s", r.method.c_str(),
                r.path.empty() ? r.id.c_str() : r.path.c_str());
            bool sel = (s_state.selected_request_index == static_cast<int>(i));
            if (ImGui::Selectable(buf, sel)) {
                s_state.selected_request_index = static_cast<int>(i);
                s_state.send_path_value_buf[0]   = '\0';
                s_state.send_query_value_buf[0]  = '\0';
                s_state.send_header_value_buf[0] = '\0';
            }
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Audit all requests:");
        aida::ui::input_text("##api_audit_auth", s_state.audit_auth_buf, sizeof(s_state.audit_auth_buf),
                             "auth values: bearer=<jwt>, api_key=<key>, ...",
                             false, ImVec2(center_w - 16.f, 28.f));
        bool auditing = s_state.auditing.load();
        if (auditing) ImGui::BeginDisabled();
        if (aida::ui::button("Audit Collection", aida::ui::button_kind_t::accent_gradient, aida::ui::size_t_::sm)) {
            uint64_t cid = c.id;
            std::map<std::string, std::string> auth = parse_kv_lines(s_state.audit_auth_buf);
            s_state.auditing.store(true);
            work_queue::post([cid, auth]() {
                api_definition::audit_result_t res;
                bool ok = api_definition::audit_entire_collection(cid, auth, res);
                {
                    std::lock_guard<std::mutex> lk(s_state.lock);
                    char msg[256];
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                        "Audit %s: sent=%zu failed=%zu issues=%zu",
                        ok ? "completed" : "failed",
                        res.requests_sent, res.requests_failed, res.issues_raised);
                    s_state.last_action_kind    = ok ? "ok" : "error";
                    s_state.last_action_message = msg;
                }
                s_state.auditing.store(false);
            });
        }
        if (auditing) ImGui::EndDisabled();
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + center_w + 16.f, content_y));
    ImGui::BeginChild("##api_right", ImVec2(right_w, content_h), false);

    if (s_state.selected_collection_index >= 0 && s_state.selected_collection_index < static_cast<int>(collections.size())
        && s_state.selected_request_index >= 0
        && s_state.selected_request_index < static_cast<int>(collections[s_state.selected_collection_index].requests.size())) {
        const auto& c = collections[s_state.selected_collection_index];
        const auto& r = c.requests[s_state.selected_request_index];
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                           "%s %s", r.method.c_str(), r.path.c_str());
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "base: %s   auth: %s",
                           r.base_url.empty() ? "(none)" : r.base_url.c_str(),
                           r.auth_kind.empty() ? "(none)" : r.auth_kind.c_str());
        ImGui::Spacing();

        if (!r.path_params.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                               "Path params (one per line, name=value):");
            ImGui::InputTextMultiline("##api_path_kv", s_state.send_path_value_buf,
                                      sizeof(s_state.send_path_value_buf), ImVec2(right_w - 16.f, 60.f));
        }
        if (!r.query_params.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                               "Query params (one per line, name=value):");
            ImGui::InputTextMultiline("##api_query_kv", s_state.send_query_value_buf,
                                      sizeof(s_state.send_query_value_buf), ImVec2(right_w - 16.f, 60.f));
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Header overrides (one per line, name=value):");
        ImGui::InputTextMultiline("##api_hdr_kv", s_state.send_header_value_buf,
                                  sizeof(s_state.send_header_value_buf), ImVec2(right_w - 16.f, 60.f));

        bool sending = s_state.sending.load();
        if (sending) ImGui::BeginDisabled();
        if (aida::ui::button("Send", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            auto pv = parse_kv_lines(s_state.send_path_value_buf);
            auto qv = parse_kv_lines(s_state.send_query_value_buf);
            auto hv = parse_kv_lines(s_state.send_header_value_buf);
            api_definition::api_request_template_t tpl_copy = r;
            s_state.sending.store(true);
            work_queue::post([tpl_copy, pv, qv, hv]() {
                std::string scheme, host, path; uint16_t port = 0;
                std::vector<uint8_t> raw = api_definition::render_to_raw_request(tpl_copy, pv, qv, hv, std::string());
                bool tls = false;
                if (!tpl_copy.base_url.empty()) {
                    audit_http::parse_url(tpl_copy.base_url, scheme, host, port, path);
                    tls = (scheme == "https");
                }
                audit_http::send_options_t opts;
                opts.timeout_ms = 20000;
                opts.enforce_scope = false;
                auto resp = audit_http::send(raw, host, port, tls, opts);
                std::lock_guard<std::mutex> lk(s_state.lock);
                if (resp.has_value()) {
                    s_state.response_status     = resp->status_code;
                    s_state.response_latency_ms = resp->latency_ms;
                    std::string out;
                    out += "HTTP/1.1 " + std::to_string(resp->status_code) + " " + resp->reason_phrase + "\r\n";
                    for (const auto& h : resp->resp_headers) out += h.first + ": " + h.second + "\r\n";
                    out += "\r\n";
                    out.append(reinterpret_cast<const char*>(resp->resp_body.data()), resp->resp_body.size());
                    s_state.response_raw    = std::move(out);
                    s_state.last_action_kind = "ok";
                    s_state.last_action_message = std::string("Sent: HTTP ") + std::to_string(resp->status_code);
                } else {
                    s_state.response_status = 0;
                    s_state.response_raw    = audit_http::last_error();
                    s_state.last_action_kind = "error";
                    s_state.last_action_message = audit_http::last_error();
                }
                s_state.sending.store(false);
            });
        }
        if (sending) ImGui::EndDisabled();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Response (status %d, %llu ms)",
                           s_state.response_status, static_cast<unsigned long long>(s_state.response_latency_ms));
        {
            std::lock_guard<std::mutex> lk(s_state.lock);
            ImFont* mono = aida::ui::fonts::code();
            if (mono) ImGui::PushFont(mono);
            ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(th.panel_header, alpha));
            ImGui::InputTextMultiline("##api_resp_text", s_state.response_raw.data(),
                                       s_state.response_raw.size() + 1,
                                       ImVec2(right_w - 16.f, content_h - 280.f),
                                       ImGuiInputTextFlags_ReadOnly);
            ImGui::PopStyleColor();
            if (mono) ImGui::PopFont();
        }
    } else {
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "Select a request";
        cfg.body  = "Pick a collection on the left, then a request to view and send it.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImVec2(right_w, content_h), cfg);
    }

    ImGui::EndChild();

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

}
}
}
