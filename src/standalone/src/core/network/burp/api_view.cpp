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

#include "api_view.hpp"
#include "../network_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "api_definition.hpp"
#include "audit_http.hpp"
#endif
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/fonts.hpp"
#include "../../ui/application_ui_runtime.hpp"
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
#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace api_view {

namespace {

state_t s_state;
uint64_t s_pending_remove_collection = 0;
std::string s_pending_remove_collection_name;
bool s_remove_collection_dialog_requested = false;

uint64_t artifact_hash(const std::vector<uint8_t>& bytes)
{
    uint64_t hash = 14695981039346656037ULL;
    for (uint8_t value : bytes) { hash ^= value; hash *= 1099511628211ULL; }
    hash ^= static_cast<uint64_t>(bytes.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

network_view::artifact_identity_t artifact_identity(const retained_exchange_t& exchange, bool response)
{
    network_view::artifact_identity_t identity;
    const uint64_t hash = response ? exchange.response_hash : exchange.request_hash;
    const size_t size = response ? exchange.response_size : exchange.request_size;
    if (hash == 0) return identity;
    identity.kind = response ? network_view::artifact_kind_t::api_response
                             : network_view::artifact_kind_t::api_request;
    identity.id = "network.api." + std::to_string(exchange.id) +
        (response ? ".response" : ".request");
    identity.parent_id = "network.api." + std::to_string(exchange.id);
    identity.source_view_id = "view.network.api";
    identity.source_id = exchange.id;
    identity.timestamp = exchange.generation;
    identity.revision = exchange.generation;
    identity.content_size = size;
    identity.content_hash = hash;
    identity.label = exchange.label + (response ? " response" : " request");
    identity.target_host = exchange.host;
    identity.target_port = exchange.port;
    identity.use_tls = exchange.use_tls;
    return identity;
}

retained_exchange_t retained_metadata(const retained_exchange_t& source)
{
    retained_exchange_t copy;
    copy.id = source.id;
    copy.generation = source.generation;
    copy.collection_id = source.collection_id;
    copy.request_template_id = source.request_template_id;
    copy.label = source.label;
    copy.host = source.host;
    copy.port = source.port;
    copy.use_tls = source.use_tls;
    copy.response_status = source.response_status;
    copy.response_latency_ms = source.response_latency_ms;
    copy.request_hash = source.request_hash;
    copy.response_hash = source.response_hash;
    copy.request_size = source.request_size;
    copy.response_size = source.response_size;
    return copy;
}

void trim_retained_history_locked()
{
    constexpr size_t byte_budget = 64U * 1024U * 1024U;
    size_t retained_bytes = 0;
    for (const auto& exchange : s_state.retained_exchanges)
        retained_bytes += exchange.request.size() + exchange.response.size();
    while (s_state.retained_exchanges.size() > 1 &&
           (s_state.retained_exchanges.size() > 64 || retained_bytes > byte_budget)) {
        retained_bytes -= s_state.retained_exchanges.front().request.size();
        retained_bytes -= s_state.retained_exchanges.front().response.size();
        s_state.retained_exchanges.pop_front();
    }
}

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

bool resolve_retained_artifact(uint64_t exchange_id, uint64_t generation, bool response,
                               std::vector<uint8_t>& bytes, std::string& unavailable_reason)
{
    std::lock_guard<std::mutex> lk(s_state.lock);
    const auto found = std::find_if(s_state.retained_exchanges.begin(), s_state.retained_exchanges.end(),
        [exchange_id, generation](const retained_exchange_t& exchange) {
            return exchange.id == exchange_id && exchange.generation == generation;
        });
    if (found == s_state.retained_exchanges.end()) {
        unavailable_reason = "The API exchange rolled out of the bounded retained history.";
        return false;
    }
    bytes = response ? found->response : found->request;
    if (bytes.empty()) {
        unavailable_reason = response ? "The API exchange has no retained response."
                                      : "The API exchange has no retained request.";
        return false;
    }
    unavailable_reason.clear();
    return true;
}

bool resolve_retained_endpoint(uint64_t exchange_id, uint64_t generation,
                               std::string& host, uint16_t& port, bool& use_tls,
                               std::string& unavailable_reason)
{
    std::lock_guard<std::mutex> lk(s_state.lock);
    const auto found = std::find_if(s_state.retained_exchanges.begin(),
        s_state.retained_exchanges.end(), [exchange_id, generation](
            const retained_exchange_t& exchange) {
            return exchange.id == exchange_id && exchange.generation == generation;
        });
    if (found == s_state.retained_exchanges.end()) {
        unavailable_reason = "The API exchange rolled out of the bounded retained history.";
        return false;
    }
    host = found->host;
    port = found->port;
    use_tls = found->use_tls;
    if (host.empty() || port == 0) {
        unavailable_reason = "The retained API exchange has no canonical endpoint.";
        return false;
    }
    unavailable_reason.clear();
    return true;
}

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
        ::diag::log_tagged_fmt("api_v", "import what='%s' format_idx=%d", what.c_str(), s_state.import_format_idx);
        s_state.importing.store(true);
        {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.api_view";
            sub.label = "api_view.import";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::external_tool;
            sub.priority = 3;
            sub.body = [what, fmt]() {
            uint64_t id = 0;
            if (what.rfind("http://", 0) == 0 || what.rfind("https://", 0) == 0)
                id = api_definition::import_from_url(what);
            else
                id = api_definition::import_from_file(what, fmt);
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                if (id != 0) {
                    ::diag::log_tagged_fmt("api_v", "import_ok id=%llu", static_cast<unsigned long long>(id));
                    s_state.last_action_kind    = "ok";
                    s_state.last_action_message = std::string("Imported collection id=") + std::to_string(id);
                } else {
                    ::diag::log_tagged_fmt("api_v", "import_failed err='%s'", api_definition::last_error().c_str());
                    s_state.last_action_kind    = "error";
                    s_state.last_action_message = api_definition::last_error();
                }
            }
            s_state.importing.store(false);
        };
            (void)::aida::infra::executor::submit(std::move(sub));
        }
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
        const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
        const bool menu_key_context = sel &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            ImGui::IsKeyPressed(ImGuiKey_Menu, false);
        const bool shift_f10_context = !menu_key_context && sel &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
        const bool keyboard_context = menu_key_context || shift_f10_context;
        if (pointer_context || keyboard_context) {
            aida::ui::application_ui::retained_entity_context_t context;
            context.owner_id = "network.api.collection";
            context.entity_id = std::to_string(c.id);
            context.entity_generation = c.requests.size();
            context.active_view = aida::ui::stable_view_id_t("view.network.api");
            const auto retained_id = c.id;
            const auto retained_name = c.name;
            context.validate_identity = [retained_id, retained_name] {
                const auto live = api_definition::list_collections();
                const auto found = std::find_if(live.begin(), live.end(),
                    [retained_id, &retained_name](const auto& item) {
                        return item.id == retained_id && item.name == retained_name;
                    });
                return found != live.end()
                    ? aida::ui::capability_state_t::available()
                    : aida::ui::capability_state_t::unavailable(
                        "The API collection was removed or replaced; select it again");
            };
            aida::ui::application_ui::retained_entity_action_t action;
            action.action_id = "network.api.collection.remove_review";
            action.capability = aida::ui::capability_state_t::available();
            action.invoke = [retained_id, retained_name] {
                s_pending_remove_collection = retained_id;
                s_pending_remove_collection_name = retained_name;
                s_remove_collection_dialog_requested = true;
                return aida::ui::action_handler_result_t::completed();
            };
            context.actions.push_back(std::move(action));
            aida::ui::application_ui::open_retained_entity_context_menu(
                std::move(context), pointer_context
                    ? aida::ui::context_menu_open_origin_t::pointer
                    : menu_key_context
                    ? aida::ui::context_menu_open_origin_t::menu_key
                    : aida::ui::context_menu_open_origin_t::shift_f10);
        }
        aida::ui::application_ui::render_retained_entity_context_menu(
            "network.api.collection");
    }
    ImGui::EndChild();

    if (s_remove_collection_dialog_requested) {
        ImGui::OpenPopup("Remove API Collection");
        s_remove_collection_dialog_requested = false;
    }
    if (ImGui::BeginPopupModal("Remove API Collection", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        const auto live = api_definition::list_collections();
        const auto retained = std::find_if(live.begin(), live.end(), [](const auto& item) {
            return item.id == s_pending_remove_collection &&
                item.name == s_pending_remove_collection_name;
        });
        const bool current = retained != live.end();
        ImGui::TextWrapped("Remove '%s' and every request template in this collection?",
            s_pending_remove_collection_name.c_str());
        ImGui::TextDisabled("Scope: API definition catalog only. Captured traffic and proxy history are unchanged.");
        ImGui::TextDisabled("This operation cannot be undone after confirmation.");
        ImGui::BeginDisabled(!current);
        if (ImGui::Button("Remove Collection")) {
            const auto id = s_pending_remove_collection;
            const auto name = s_pending_remove_collection_name;
            ::diag::log_tagged_fmt("api_v", "collection_remove_queued id=%llu name='%s'",
                static_cast<unsigned long long>(id), name.c_str());
            ::aida::infra::executor::submission_t submission;
            submission.owner_subsystem = "burp.api_view";
            submission.label = "api_view.remove_collection";
            submission.thread_class = "bounded_task";
            submission.domain = aida::infra::executor::domain_t::external_tool;
            submission.priority = 3;
            submission.body = [id]() { api_definition::remove_collection(id); };
            static_cast<void>(::aida::infra::executor::submit(std::move(submission)));
            s_state.selected_collection_index = -1;
            s_state.selected_request_index = -1;
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                s_state.last_action_kind = "success";
                s_state.last_action_message = "API collection removal queued.";
            }
            s_pending_remove_collection = 0;
            s_pending_remove_collection_name.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
        if (!current) ImGui::TextWrapped("The collection changed after review. Close this dialog and select it again.");
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            s_pending_remove_collection = 0;
            s_pending_remove_collection_name.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    const size_t selected_collection_index = static_cast<size_t>(s_state.selected_collection_index);
    const size_t selected_request_index = static_cast<size_t>(s_state.selected_request_index);

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, content_y));
    ImGui::BeginChild("##api_center", ImVec2(center_w, content_h), false);
    if (s_state.selected_collection_index >= 0 && selected_collection_index < collections.size()) {
        const auto& c = collections[selected_collection_index];
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
            ::diag::log_tagged_fmt("api_v", "audit_collection id=%llu name='%s'",
                static_cast<unsigned long long>(cid), c.name.c_str());
            s_state.auditing.store(true);
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.api_view";
                sub.label = "api_view.audit_collection";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [cid, auth]() {
                api_definition::audit_result_t res;
                bool ok = api_definition::audit_entire_collection(cid, auth, res);
                {
                    std::lock_guard<std::mutex> lk(s_state.lock);
                    char msg[256];
                    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                        "Audit %s: sent=%zu failed=%zu issues=%zu",
                        ok ? "completed" : "failed",
                        res.requests_sent, res.requests_failed, res.issues_raised);
                    ::diag::log_tagged_fmt("api_v", "audit_result id=%llu ok=%d sent=%zu failed=%zu issues=%zu",
                        static_cast<unsigned long long>(cid), ok ? 1 : 0,
                        res.requests_sent, res.requests_failed, res.issues_raised);
                    s_state.last_action_kind    = ok ? "ok" : "error";
                    s_state.last_action_message = msg;
                }
                s_state.auditing.store(false);
            };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
        if (auditing) ImGui::EndDisabled();
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + center_w + 16.f, content_y));
    ImGui::BeginChild("##api_right", ImVec2(right_w, content_h), false);

    if (s_state.selected_collection_index >= 0 && selected_collection_index < collections.size()
        && s_state.selected_request_index >= 0
        && selected_request_index < collections[selected_collection_index].requests.size()) {
        const auto& c = collections[selected_collection_index];
        const auto& r = c.requests[selected_request_index];
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
            std::string scheme, host, parsed_path;
            uint16_t port = 0;
            if (!tpl_copy.base_url.empty())
                audit_http::parse_url(tpl_copy.base_url, scheme, host, port, parsed_path);
            const bool tls = scheme == "https";
            std::vector<uint8_t> raw = api_definition::render_to_raw_request(
                tpl_copy, pv, qv, hv, std::string());
            uint64_t exchange_id = 0;
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                retained_exchange_t exchange;
                exchange.id = s_state.next_exchange_id++;
                exchange.generation = exchange.id;
                exchange.collection_id = c.id;
                exchange.request_template_id = r.id;
                exchange.label = r.method + " " + (r.path.empty() ? r.id : r.path);
                exchange.host = host;
                exchange.port = port;
                exchange.use_tls = tls;
                exchange.request = raw;
                exchange.request_size = raw.size();
                exchange.request_hash = artifact_hash(raw);
                exchange_id = exchange.id;
                s_state.retained_exchanges.push_back(std::move(exchange));
                trim_retained_history_locked();
            }
            ::diag::log_tagged_fmt("api_v", "send_request method='%s' path='%s' base='%s'",
                r.method.c_str(), r.path.c_str(), r.base_url.c_str());
            s_state.sending.store(true);
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.api_view";
                sub.label = "api_view.send_request";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [raw, host, port, tls, exchange_id]() {
                audit_http::send_options_t opts;
                opts.timeout_ms = 20000;
                opts.enforce_scope = false;
                auto resp = audit_http::send(raw, host, port, tls, opts);
                std::lock_guard<std::mutex> lk(s_state.lock);
                if (resp.has_value()) {
                    ::diag::log_tagged_fmt("api_v", "send_response status=%d latency=%llums",
                        resp->status_code, static_cast<unsigned long long>(resp->latency_ms));
                    std::string out;
                    out += "HTTP/1.1 " + std::to_string(resp->status_code) + " " + resp->reason_phrase + "\r\n";
                    for (const auto& h : resp->resp_headers) out += h.first + ": " + h.second + "\r\n";
                    out += "\r\n";
                    out.append(reinterpret_cast<const char*>(resp->resp_body.data()), resp->resp_body.size());
                    const auto retained = std::find_if(s_state.retained_exchanges.begin(),
                        s_state.retained_exchanges.end(), [exchange_id](const retained_exchange_t& exchange) {
                            return exchange.id == exchange_id;
                        });
                    if (retained != s_state.retained_exchanges.end()) {
                        retained->response.assign(out.begin(), out.end());
                        retained->response_size = retained->response.size();
                        retained->response_hash = artifact_hash(retained->response);
                        retained->response_status = resp->status_code;
                        retained->response_latency_ms = resp->latency_ms;
                        trim_retained_history_locked();
                    }
                    s_state.last_action_kind = "ok";
                    s_state.last_action_message = std::string("Sent: HTTP ") + std::to_string(resp->status_code);
                } else {
                    ::diag::log_tagged_fmt("api_v", "send_failed err='%s'", audit_http::last_error().c_str());
                    s_state.last_action_kind = "error";
                    s_state.last_action_message = audit_http::last_error();
                }
                s_state.sending.store(false);
            };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }
        if (sending) ImGui::EndDisabled();

        retained_exchange_t retained;
        bool has_retained = false;
        {
            std::lock_guard<std::mutex> lk(s_state.lock);
            const auto found = std::find_if(s_state.retained_exchanges.rbegin(),
                s_state.retained_exchanges.rend(), [&](const retained_exchange_t& exchange) {
                    return exchange.collection_id == c.id && exchange.request_template_id == r.id;
                });
            if (found != s_state.retained_exchanges.rend()) {
                retained = retained_metadata(*found);
                constexpr size_t preview_limit = 256U * 1024U;
                const size_t preview_size = (std::min)(found->response.size(), preview_limit);
                retained.response.assign(found->response.begin(),
                    found->response.begin() + static_cast<ptrdiff_t>(preview_size));
                has_retained = true;
            }
        }
        if (has_retained) {
            const auto request_identity = artifact_identity(retained, false);
            const auto response_identity = artifact_identity(retained, true);
            if (aida::ui::button("Actions", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm))
                network_view::open_exchange_context(request_identity, response_identity,
                    network_view::exchange_context_origin_t::pointer);
        }

        ImGui::Spacing();
        ImGui::Separator();
        const int retained_status = has_retained ? retained.response_status : 0;
        const uint64_t retained_latency = has_retained ? retained.response_latency_ms : 0;
        std::string retained_response = has_retained
            ? std::string(retained.response.begin(), retained.response.end()) : std::string();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Response (status %d, %llu ms)", retained_status,
                           static_cast<unsigned long long>(retained_latency));
        if (has_retained && retained.response_size > retained.response.size()) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.warning, alpha)),
                "Preview limited to 256 KiB; actions use all %zu bytes", retained.response_size);
        }
        {
            ImFont* mono = aida::ui::fonts::code();
            if (mono) ImGui::PushFont(mono);
            ImGui::PushStyleColor(ImGuiCol_FrameBg, aida::ui::with_alpha(th.panel_header, alpha));
            ImGui::InputTextMultiline("##api_resp_text", retained_response.data(),
                                       retained_response.size() + 1,
                                       ImVec2(right_w - 16.f, content_h - 280.f),
                                       ImGuiInputTextFlags_ReadOnly);
            const bool response_pointer_context = has_retained &&
                ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const bool response_menu_key = has_retained && ImGui::IsItemFocused() &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool response_shift_f10 = !response_menu_key && has_retained &&
                ImGui::IsItemFocused() && ImGui::GetIO().KeyShift &&
                ImGui::IsKeyPressed(ImGuiKey_F10, false);
            if (response_pointer_context || response_menu_key || response_shift_f10) {
                const auto request_identity = artifact_identity(retained, false);
                const auto response_identity = artifact_identity(retained, true);
                network_view::open_exchange_context(response_identity.valid() ? response_identity : request_identity,
                    response_identity.valid() ? request_identity : network_view::artifact_identity_t{},
                    response_pointer_context
                        ? network_view::exchange_context_origin_t::pointer
                        : response_menu_key
                        ? network_view::exchange_context_origin_t::menu_key
                        : network_view::exchange_context_origin_t::shift_f10);
            }
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
