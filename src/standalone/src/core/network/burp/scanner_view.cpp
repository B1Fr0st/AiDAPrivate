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

#include "scanner_view.hpp"
#include "../network_view.hpp"
#include "burp_ui_operation.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "issue.hpp"
#include "passive_scanner.hpp"
#include "scanner_module.hpp"
#endif

#include "../../ui/components.hpp"
#include "../../scanner/scanner_async_io.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "../../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner_view {

namespace {

struct view_state_t
{
    char            new_url[1024] = {};
    char            new_raw[65536] = {};
    bool            new_open = false;
    bool            scope_only = true;
    bool            follow_redirects = false;
    int             timeout_ms = 15000;
    int             max_concurrent = 16;
    int             throttle_ms = 0;
    int             per_module_cap = 64;
    std::set<std::string> module_disabled;
    uint64_t        selected_audit_id = 0;
    uint64_t        selected_issue_id = 0;
    int             filter_sev = 0;
    int             filter_conf = 0;
    char            filter_host[128] = {};
    char            filter_type[128] = {};
    char            status_msg[256] = {};
    std::atomic<bool> initialized{false};
    std::atomic<bool> initialization_requested{false};
    bool            initialization_attempted = false;
    std::shared_ptr<const std::vector<issue_t>> issues =
        std::make_shared<const std::vector<issue_t>>();
    std::atomic<bool> issues_refresh_pending{false};
    std::uint64_t issues_refresh_ms = 0;
    std::string issues_filter_signature;
    aida::burp::ui_operation::state_t operation;
    std::uint64_t observed_operation_generation = 0;
    std::atomic<std::uint64_t> started_audit_id{0};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> reviewed_issue_identity;
};

view_state_t& vs()
{
    static view_state_t s;
    return s;
}

void submit_initialization()
{
    auto& state = vs();
    bool expected = false;
    if (!state.initialization_requested.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return;
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.initialize";
    request.label = "Load Scanner state";
    request.target = "Scanner issue and module catalogs";
    request.affected_entity = "Scanner state";
    request.execute = []() {
        aida::burp::ui_operation::result_t result;
        result.success = initialize();
        result.message = result.success ? "Scanner state loaded." : "Scanner initialization failed.";
        return result;
    };
    if (!state.operation.submit(std::move(request)))
        state.initialization_requested.store(false, std::memory_order_release);
}

void request_issue_snapshot(issue_filter_t filter, std::string signature)
{
    auto& state = vs();
    bool expected = false;
    if (!state.issues_refresh_pending.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
        return;
    filter.limit = 10000;
    state.issues_filter_signature = signature;
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.scanner";
    submission.label = "scanner.refresh_issues";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 4;
    submission.body = [filter = std::move(filter)]() mutable {
        auto finish_pending = std::unique_ptr<void, void(*)(void*)>(
            reinterpret_cast<void*>(1), [](void*) {
                vs().issues_refresh_pending.store(false, std::memory_order_release);
            });
        auto rows = issue_store::list(filter);
        std::shared_ptr<const std::vector<issue_t>> publication =
            std::make_shared<const std::vector<issue_t>>(std::move(rows));
        std::atomic_store_explicit(&vs().issues, std::move(publication),
            std::memory_order_release);
    };
    if (!aida::infra::executor::submit(std::move(submission)).submitted) {
        state.issues_filter_signature.clear();
        state.issues_refresh_pending.store(false, std::memory_order_release);
    }
}

void submit_issue_export()
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.export_issues";
    request.label = "Export Scanner issues";
    request.target = "Scanner issue export";
    request.affected_entity = "Scanner issues";
    request.execute = []() {
        aida::burp::ui_operation::result_t result;
        issue_filter_t filter;
        const auto document = issue_store::export_json(filter);
        const std::string path = issue_store::storage_path() + ".export.json";
        const std::string payload = document.dump(2);
        if (payload.size() > scanner_async_io::max_serialized_bytes) {
            result.message = "Scanner issue export exceeds the 64 MiB bound.";
            return result;
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        result.success = true;
        result.message = "Scanner issue export prepared for Studio preview.";
#else
        const auto written = scanner_async_io::atomic_replace(path, payload, true, {}, []() {
            return true;
        });
        result.success = written.success;
        result.message = written.success ? "Scanner issues exported to " + path : written.error;
#endif
        return result;
    };
    static_cast<void>(vs().operation.submit(std::move(request)));
}

void submit_reviewed_issue_clear(std::vector<std::pair<std::uint64_t, std::uint64_t>> reviewed)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.clear_issues";
    request.label = "Clear Scanner issues";
    request.target = std::to_string(reviewed.size()) + " issues";
    request.affected_entity = request.target;
    request.execute = [reviewed = std::move(reviewed)]() {
        aida::burp::ui_operation::result_t result;
        issue_filter_t filter;
        filter.limit = 10000;
        const auto current = issue_store::list(filter);
        if (current.size() != reviewed.size()) {
            result.message = "The issue catalog changed after review; no issues were cleared.";
            return result;
        }
        for (std::size_t index = 0; index < current.size(); ++index) {
            if (current[index].id != reviewed[index].first ||
                current[index].seen_ms != reviewed[index].second) {
                result.message = "The issue catalog changed after review; no issues were cleared.";
                return result;
            }
        }
        issue_store::clear();
        result.success = issue_store::count() == 0;
        result.message = result.success ? "Scanner issues cleared."
                                        : "Scanner issue clearing could not be verified.";
        return result;
    };
    static_cast<void>(vs().operation.submit(std::move(request)));
}

void submit_audit(std::vector<std::uint8_t> raw, std::string url,
    active_scanner::audit_config_t config)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.start_audit";
    request.label = "Start Scanner audit";
    request.target = url;
    request.affected_entity = url;
    request.execute = [raw = std::move(raw), url = std::move(url),
                       config = std::move(config)]() mutable {
        aida::burp::ui_operation::result_t result;
        const std::uint64_t id = active_scanner::enqueue_target(raw, url, config);
        result.success = id != 0;
        result.message = result.success ? "Scanner audit started."
                                        : active_scanner::last_error();
        if (id != 0)
            vs().started_audit_id.store(id, std::memory_order_release);
        return result;
    };
    static_cast<void>(vs().operation.submit(std::move(request)));
}

void submit_passive_toggle(bool reviewed, bool desired)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.passive_toggle";
    request.label = desired ? "Enable passive scanning" : "Disable passive scanning";
    request.target = "Passive Scanner";
    request.affected_entity = request.target;
    request.execute = [reviewed, desired]() {
        aida::burp::ui_operation::result_t result;
        if (passive_scanner::is_enabled() != reviewed) {
            result.message = "Passive Scanner state changed before the toggle was applied.";
            return result;
        }
        passive_scanner::set_enabled(desired);
        result.success = passive_scanner::is_enabled() == desired;
        result.message = result.success
            ? desired ? "Passive scanning enabled." : "Passive scanning disabled."
            : "Passive Scanner did not reach the requested state.";
        return result;
    };
    static_cast<void>(vs().operation.submit(std::move(request)));
}

ImU32 sev_color(severity_t s, float a)
{
    switch (s) {
        case severity_t::info:     return aida::ui::with_alpha(IM_COL32(120, 160, 200, 255), a);
        case severity_t::low:      return aida::ui::with_alpha(IM_COL32(120, 200, 140, 255), a);
        case severity_t::medium:   return aida::ui::with_alpha(IM_COL32(230, 200, 80, 255),  a);
        case severity_t::high:     return aida::ui::with_alpha(IM_COL32(240, 140, 80, 255),  a);
        case severity_t::critical: return aida::ui::with_alpha(IM_COL32(240, 80, 100, 255),  a);
    }
    return aida::ui::with_alpha(IM_COL32(180, 180, 180, 255), a);
}

ImU32 conf_color(confidence_t c, float a)
{
    switch (c) {
        case confidence_t::tentative: return aida::ui::with_alpha(IM_COL32(170, 170, 170, 255), a);
        case confidence_t::firm:      return aida::ui::with_alpha(IM_COL32(180, 210, 240, 255), a);
        case confidence_t::certain:   return aida::ui::with_alpha(IM_COL32(140, 230, 180, 255), a);
    }
    return aida::ui::with_alpha(IM_COL32(180, 180, 180, 255), a);
}

::network_view::artifact_identity_t evidence_identity(const issue_t& issue,
    std::size_t evidence_index, bool response)
{
    const auto& text = response ? issue.evidence[evidence_index].response_raw
                                : issue.evidence[evidence_index].request_raw;
    const std::vector<std::uint8_t> bytes(text.begin(), text.end());
    ::network_view::artifact_identity_t identity;
    identity.id = "scanner." + std::to_string(issue.id) + ".evidence." +
        std::to_string(evidence_index) + (response ? ".response" : ".request");
    identity.parent_id = "scanner." + std::to_string(issue.id) + ".evidence." +
        std::to_string(evidence_index);
    identity.source_view_id = "view.network.scanner";
    identity.session_id = issue.session_id;
    identity.kind = response ? ::network_view::artifact_kind_t::scanner_response
                             : ::network_view::artifact_kind_t::scanner_request;
    identity.source_id = issue.id;
    identity.timestamp = issue.seen_ms;
    identity.revision = evidence_index;
    identity.content_size = bytes.size();
    identity.content_hash = ::network_view::artifact_content_hash(bytes);
    identity.label = std::string("Scanner evidence ") + (response ? "response" : "request") +
        " #" + std::to_string(evidence_index + 1);
    identity.target_host = issue.host;
    identity.target_port = issue.port;
    identity.use_tls = issue.scheme == "https";
    return identity;
}

void render_evidence_artifact(const issue_t& issue, std::size_t evidence_index,
    bool response, float alpha)
{
    const auto& evidence = issue.evidence[evidence_index];
    const auto& text = response ? evidence.response_raw : evidence.request_raw;
    if (text.empty()) return;
    ImGui::PushID(response ? "evidence_response" : "evidence_request");
    ImGui::PushID(static_cast<int>(evidence_index));
    ImGui::TextDisabled("%s:", response ? "Response" : "Request");
    ImGui::BeginChild("##artifact", ImVec2(0.f, 112.f), true,
        ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
    const bool pointer = ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Right);
    const bool menu = ImGui::IsWindowFocused() && ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool shift_f10 = ImGui::IsWindowFocused() && ImGui::GetIO().KeyShift &&
        ImGui::IsKeyPressed(ImGuiKey_F10, false);
    if (pointer || menu || shift_f10) {
        const auto primary = evidence_identity(issue, evidence_index, response);
        ::network_view::artifact_identity_t related;
        const auto& related_text = response ? evidence.request_raw : evidence.response_raw;
        if (!related_text.empty())
            related = evidence_identity(issue, evidence_index, !response);
        const auto origin = pointer ? ::network_view::exchange_context_origin_t::pointer
            : shift_f10 ? ::network_view::exchange_context_origin_t::shift_f10
                        : ::network_view::exchange_context_origin_t::menu_key;
        ::network_view::open_exchange_context(primary, related, origin);
    }
    ImGui::EndChild();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Right-click, Menu, or Shift+F10 for request/response actions");
    ImGui::PopID();
    ImGui::PopID();
    (void)alpha;
}

void render_audits_pane(float w, float h, float alpha)
{
    auto& s = vs();
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::BeginChild("##burp_audits", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Audits");
    ImGui::Spacing();

    auto audits = active_scanner::list_audits();
    float row_h = 60.f;
    float list_h = h - 48.f;
    ImGui::BeginChild("##burp_audit_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);
    ImVec2 lo = ImGui::GetWindowPos();
    for (size_t i = 0; i < audits.size(); ++i) {
        const auto& a = audits[i];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool hovered = ImGui::IsMouseHoveringRect(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h), false);
        bool selected = (s.selected_audit_id == a.id);
        if (selected) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) s.selected_audit_id = a.id;

        char buf[512];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "#%llu  %s:%u  %s",
            static_cast<unsigned long long>(a.id), a.host.c_str(), a.port,
            a.tls ? "https" : "http");
        dl->AddText(ImVec2(lo.x + 12.f, abs_ry + 4.f),
                    aida::ui::with_alpha(th.text_primary, alpha), buf);

        std::string url_clip = a.url;
        if (url_clip.size() > 80) url_clip = url_clip.substr(0, 77) + "...";
        dl->AddText(ImVec2(lo.x + 12.f, abs_ry + 22.f),
                    aida::ui::with_alpha(th.text_secondary, alpha), url_clip.c_str());

        float frac = (a.total_probes > 0)
            ? static_cast<float>(a.completed_probes) / static_cast<float>(a.total_probes) : 0.f;
        ImVec2 pb_pos(lo.x + 12.f, abs_ry + 42.f);
        aida::ui::render_progress_bar(pb_pos, w - 130.f, 6.f, frac, false, a.running);

        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "%zu/%zu  %zu issues  %s",
            a.completed_probes, a.total_probes, a.issues_found,
            a.running ? "Running" : (a.cancelled ? "Cancelled" : "Done"));
        dl->AddText(ImVec2(lo.x + w - 110.f, abs_ry + 40.f),
                    aida::ui::with_alpha(a.running ? th.warning : th.text_dim, alpha), buf);

        ImGui::SetCursorPosY(ry + row_h + 4.f);

        if (selected) {
            float bx = lo.x + w - 80.f;
            float by = abs_ry + 4.f;
            ImGui::SetCursorScreenPos(ImVec2(bx, by));
            if (a.running) {
                if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
                    active_scanner::cancel_audit(a.id);
                    diag::log_tagged_fmt("burp", "scanner_view cancel id=%llu",
                                          static_cast<unsigned long long>(a.id));
                }
            }
        }
    }
    if (audits.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "No audits yet. Click 'New Audit' to start.");
    }
    ImGui::EndChild();
    ImGui::EndChild();
}

void render_issues_pane(float w, float h, float alpha)
{
    auto& s = vs();
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::BeginChild("##burp_issues", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Issues");
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 20.f);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Sev:");
    ImGui::SameLine();
    const char* sev_items[] = { "Any", "Info", "Low", "Medium", "High", "Critical" };
    ImGui::SetNextItemWidth(110.f);
    ImGui::Combo("##bs_sev", &s.filter_sev, sev_items, 6);
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Conf:");
    ImGui::SameLine();
    const char* conf_items[] = { "Any", "Tentative", "Firm", "Certain" };
    ImGui::SetNextItemWidth(110.f);
    ImGui::Combo("##bs_conf", &s.filter_conf, conf_items, 4);
    ImGui::SameLine();
    aida::ui::input_text("##bs_host", s.filter_host, sizeof(s.filter_host),
                          "Host filter", false, ImVec2(160.f, 28.f));
    ImGui::SameLine();
    aida::ui::input_text("##bs_type", s.filter_type, sizeof(s.filter_type),
                          "Type filter (e.g. sqli)", false, ImVec2(180.f, 28.f));

    ImGui::Spacing();

    issue_filter_t f;
    if (s.filter_sev > 0) { f.has_severity_min = true; f.severity_min = static_cast<severity_t>(s.filter_sev - 1); }
    if (s.filter_conf > 0) { f.has_confidence_min = true; f.confidence_min = static_cast<confidence_t>(s.filter_conf - 1); }
    if (s.filter_host[0]) f.host_substring = s.filter_host;
    if (s.filter_type[0]) f.type_key_substring = s.filter_type;
    if (s.selected_audit_id != 0) { f.has_audit_id = true; f.audit_id = s.selected_audit_id; }
    std::string filter_signature = std::to_string(s.filter_sev) + "\n" +
        std::to_string(s.filter_conf) + "\n" + s.filter_host + "\n" +
        s.filter_type + "\n" + std::to_string(s.selected_audit_id);
    const std::uint64_t now = aida::infra::executor::now_ms();
    if (!s.issues_refresh_pending.load(std::memory_order_acquire) &&
        (s.issues_filter_signature != filter_signature || now - s.issues_refresh_ms >= 200)) {
        s.issues_refresh_ms = now;
        request_issue_snapshot(f, std::move(filter_signature));
    }
    const auto issues = std::atomic_load_explicit(&s.issues, std::memory_order_acquire);

    float top_used = 70.f;
    float list_h = (h - top_used) * 0.55f;

    ImGui::BeginChild("##burp_issue_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);
    ImVec2 lo = ImGui::GetWindowPos();
    float row_h = 22.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    float col_sev = 80.f, col_conf = 70.f, col_host = 220.f, col_param = 140.f;
    float col_type = (w - 8.f - col_sev - col_conf - col_host - col_param - 16.f);
    if (col_type < 120.f) col_type = 120.f;

    {
        float hy = ImGui::GetCursorScreenPos().y;
        dl->AddRectFilled(ImVec2(lo.x, hy), ImVec2(lo.x + w, hy + row_h),
                          aida::ui::with_alpha(th.panel_header, alpha));
        float cx = lo.x + 8.f;
        ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
        dl->AddText(ImVec2(cx, hy + text_oy), hc, "Severity"); cx += col_sev;
        dl->AddText(ImVec2(cx, hy + text_oy), hc, "Conf.");    cx += col_conf;
        dl->AddText(ImVec2(cx, hy + text_oy), hc, "Host");     cx += col_host;
        dl->AddText(ImVec2(cx, hy + text_oy), hc, "Param");    cx += col_param;
        dl->AddText(ImVec2(cx, hy + text_oy), hc, "Type");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);
    }

    ImGuiListClipper issue_clipper;
    issue_clipper.Begin(static_cast<int>(issues->size()), row_h);
    while (issue_clipper.Step()) {
    for (int row = issue_clipper.DisplayStart; row < issue_clipper.DisplayEnd; ++row) {
        const auto& it = (*issues)[static_cast<std::size_t>(row)];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        bool hovered = ImGui::IsMouseHoveringRect(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h), false);
        bool selected = (s.selected_issue_id == it.id);
        if (selected) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + 3.f, abs_ry + row_h),
                              sev_color(it.severity, alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) s.selected_issue_id = it.id;

        float cx = lo.x + 8.f;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), sev_color(it.severity, alpha), severity_label(it.severity)); cx += col_sev;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), conf_color(it.confidence, alpha), confidence_label(it.confidence)); cx += col_conf;
        std::string host = it.host;
        if (host.size() > 32) host = host.substr(0, 29) + "...";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_primary, alpha), host.c_str()); cx += col_host;
        std::string param = it.parameter;
        if (param.size() > 18) param = param.substr(0, 15) + "...";
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_secondary, alpha), param.c_str()); cx += col_param;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), aida::ui::with_alpha(th.text_primary, alpha), it.type_key.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }
    }
    ImGui::Dummy(ImVec2(0.f, 0.f));
    ImGui::EndChild();

    ImGui::Spacing();

    float detail_h = h - top_used - list_h - 16.f;
    if (detail_h < 60.f) detail_h = 60.f;
    ImGui::BeginChild("##burp_issue_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);
    const auto selected_it = std::find_if(issues->begin(), issues->end(),
        [&](const auto& issue) { return issue.id == s.selected_issue_id; });
    if (s.selected_issue_id != 0 && selected_it != issues->end()) {
        const auto& selected = *selected_it;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(sev_color(selected.severity, alpha)),
                           "%s", severity_label(selected.severity));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                           "%s", selected.name.c_str());
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "%s://%s:%u%s   param=%s   ip=%s",
                           selected.scheme.c_str(), selected.host.c_str(), selected.port,
                           selected.path.c_str(), selected.parameter.c_str(),
                           selected.insertion_point.c_str());
        if (!selected.cwe.empty()) {
            std::string cwe;
            for (size_t i = 0; i < selected.cwe.size(); ++i) {
                if (i) cwe += ", ";
                cwe += selected.cwe[i];
            }
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "CWE: %s", cwe.c_str());
        }
        ImGui::Spacing();
        if (ImGui::CollapsingHeader("Description", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::TextWrapped("%s", selected.description.c_str());
        }
        if (ImGui::CollapsingHeader("Remediation", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::TextWrapped("%s", selected.remediation.c_str());
        }
        if (!selected.evidence.empty() && ImGui::CollapsingHeader("Evidence", ImGuiTreeNodeFlags_DefaultOpen)) {
            for (size_t i = 0; i < selected.evidence.size(); ++i) {
                const auto& ev = selected.evidence[i];
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                                   "Evidence #%zu  marker=%s", i + 1, ev.marker.c_str());
                render_evidence_artifact(selected, i, false, alpha);
                render_evidence_artifact(selected, i, true, alpha);
                ImGui::Spacing();
            }
        }
    } else {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Select an issue to view details.");
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

void render_new_audit_dialog(float alpha)
{
    auto& s = vs();
    const auto& th = aida::ui::resolved();
    if (!s.new_open) return;

    ImGui::SetNextWindowSize(ImVec2(620.f, 540.f), ImGuiCond_Once);
    if (ImGui::Begin("New Audit##burp_new", &s.new_open,
                     ImGuiWindowFlags_NoCollapse)) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Target URL");
        aida::ui::input_text("##na_url", s.new_url, sizeof(s.new_url),
                              "https://example.com/path?id=1", false, ImVec2(580.f, 28.f));
        ImGui::Spacing();

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Raw Request (HTTP/1.1 textual)");
        ImGui::InputTextMultiline("##na_raw", s.new_raw, sizeof(s.new_raw),
                                  ImVec2(580.f, 220.f));

        ImGui::Spacing();
        aida::ui::toggle_switch("##na_scope", &s.scope_only);
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Scope only");
        ImGui::SameLine();
        aida::ui::toggle_switch("##na_redir", &s.follow_redirects);
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Follow redirects");
        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Timeout(ms):");
        ImGui::SameLine();
        aida::ui::input_int("##na_to", &s.timeout_ms, ImVec2(120.f, 28.f));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Max parallel:");
        ImGui::SameLine();
        aida::ui::input_int("##na_par", &s.max_concurrent, ImVec2(80.f, 28.f));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Throttle:");
        ImGui::SameLine();
        aida::ui::input_int("##na_th", &s.throttle_ms, ImVec2(80.f, 28.f));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Per-module cap:");
        ImGui::SameLine();
        aida::ui::input_int("##na_cap", &s.per_module_cap, ImVec2(80.f, 28.f));

        ImGui::Spacing();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Enabled modules:");
        auto modules = scanner::all_modules();
        ImGui::BeginChild("##na_mods", ImVec2(580.f, 100.f), true, ImGuiWindowFlags_NoBackground);
        for (auto& m : modules) {
            bool en = s.module_disabled.find(m.id) == s.module_disabled.end();
            ImGui::PushID(m.id.c_str());
            if (ImGui::Checkbox(m.name.c_str(), &en)) {
                if (en) s.module_disabled.erase(m.id);
                else    s.module_disabled.insert(m.id);
            }
            ImGui::PopID();
            ImGui::SameLine(220.f);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "[%s] %s", m.category.c_str(), m.id.c_str());
        }
        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::BeginDisabled(s.operation.pending());
        if (aida::ui::button("Start Audit", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            std::string url = s.new_url;
            std::string raw = s.new_raw;
            if (url.empty() || raw.empty()) {
                _snprintf_s(s.status_msg, sizeof(s.status_msg), _TRUNCATE,
                            "Provide URL and raw request.");
            } else {
                std::vector<uint8_t> raw_bytes(raw.begin(), raw.end());
                if (raw_bytes.size() < 4 ||
                    !(raw_bytes[raw_bytes.size() - 4] == '\r' && raw_bytes[raw_bytes.size() - 3] == '\n' &&
                      raw_bytes[raw_bytes.size() - 2] == '\r' && raw_bytes[raw_bytes.size() - 1] == '\n')) {
                    raw_bytes.push_back('\r'); raw_bytes.push_back('\n');
                    raw_bytes.push_back('\r'); raw_bytes.push_back('\n');
                }
                active_scanner::audit_config_t cfg;
                cfg.scope_only = s.scope_only;
                cfg.follow_redirects = s.follow_redirects;
                cfg.timeout_ms = s.timeout_ms;
                cfg.max_concurrent_requests = static_cast<size_t>(std::max(1, s.max_concurrent));
                cfg.request_throttle_ms = static_cast<size_t>(std::max(0, s.throttle_ms));
                cfg.per_module_request_cap = static_cast<size_t>(std::max(1, s.per_module_cap));
                for (auto& m : modules) {
                    if (s.module_disabled.find(m.id) == s.module_disabled.end())
                        cfg.enabled_modules.push_back(m.id);
                }
                submit_audit(std::move(raw_bytes), std::move(url), std::move(cfg));
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            s.new_open = false;
        }
        if (s.status_msg[0]) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "%s", s.status_msg);
        }
    }
    ImGui::End();
}

}

bool initialize()
{
    auto& s = vs();
    bool expected = false;
    if (!s.initialized.compare_exchange_strong(expected, true)) return true;
    const bool issues_ready = issue_store::initialize();
    const bool passive_ready = passive_scanner::initialize();
    const bool active_ready = active_scanner::initialize();
    const bool ready = issues_ready && passive_ready && active_ready;
    if (!ready)
        s.initialized.store(false, std::memory_order_release);
    return ready;
}

void shutdown()
{
    auto& s = vs();
    if (!s.initialized.load()) return;
    active_scanner::shutdown();
    passive_scanner::shutdown();
    issue_store::shutdown();
    s.initialized.store(false);
}

bool open_new_audit_with(const std::string& url, const std::string& raw_request)
{
    auto& s = vs();
    _snprintf_s(s.new_url, sizeof(s.new_url), _TRUNCATE, "%s", url.c_str());
    size_t copy_len = std::min(raw_request.size(), sizeof(s.new_raw) - 1);
    std::memcpy(s.new_raw, raw_request.data(), copy_len);
    s.new_raw[copy_len] = '\0';
    s.new_open = true;
    return true;
}

bool resolve_retained_artifact(std::uint64_t issue_id, std::uint64_t seen_ms,
                               std::uint64_t evidence_index, bool response,
                               std::vector<std::uint8_t>& bytes, std::string& reason)
{
    issue_t issue;
    if (!issue_store::get(issue_id, issue) || issue.seen_ms != seen_ms) {
        reason = "The Scanner issue changed or is no longer retained.";
        return false;
    }
    if (evidence_index >= static_cast<std::uint64_t>(issue.evidence.size())) {
        reason = "The reviewed Scanner evidence is no longer retained.";
        return false;
    }
    const auto retained_index = static_cast<std::size_t>(evidence_index);
    const auto& text = response ? issue.evidence[retained_index].response_raw
                                : issue.evidence[retained_index].request_raw;
    bytes.assign(text.begin(), text.end());
    reason.clear();
    return true;
}

bool resolve_retained_endpoint(std::uint64_t issue_id, std::uint64_t seen_ms,
                               std::string& host, std::uint16_t& port, bool& use_tls,
                               std::string& reason)
{
    issue_t issue;
    if (!issue_store::get(issue_id, issue) || issue.seen_ms != seen_ms) {
        reason = "The Scanner issue changed or is no longer retained.";
        return false;
    }
    host = issue.host;
    port = issue.port;
    use_tls = issue.scheme == "https";
    if (host.empty() || port == 0) {
        reason = "The retained Scanner evidence has no canonical endpoint.";
        return false;
    }
    reason.clear();
    return true;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    if (!vs().initialized.load(std::memory_order_acquire) &&
        !vs().initialization_attempted) {
        vs().initialization_attempted = true;
        submit_initialization();
    }
    const auto operation_completion = vs().operation.completion();
    if (operation_completion &&
        operation_completion->generation != vs().observed_operation_generation) {
        vs().observed_operation_generation = operation_completion->generation;
        if (vs().initialization_requested.exchange(false, std::memory_order_acq_rel))
            vs().initialized.store(operation_completion->result.success,
                std::memory_order_release);
        if (operation_completion->result.success) {
            const std::uint64_t audit_id = vs().started_audit_id.exchange(0,
                std::memory_order_acq_rel);
            if (audit_id != 0) {
                vs().selected_audit_id = audit_id;
                vs().new_open = false;
            }
            vs().issues_filter_signature.clear();
            if (operation_completion->result.message.find("cleared") != std::string::npos)
                vs().selected_issue_id = 0;
        }
        _snprintf_s(vs().status_msg, sizeof(vs().status_msg), _TRUNCATE,
            "%s", operation_completion->result.message.c_str());
    }
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_scanner_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Scanner");
    if (!vs().initialized.load(std::memory_order_acquire) && operation_completion &&
        !operation_completion->result.success && !vs().operation.pending()) {
        ImGui::SameLine();
        if (aida::ui::button("Retry initialization", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm))
            submit_initialization();
    }
    ImGui::SameLine();
    if (aida::ui::button("New Audit", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        vs().new_open = true;
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(vs().operation.pending() ||
        !vs().initialized.load(std::memory_order_acquire));
    if (aida::ui::button("Export Issues", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        const std::string path = issue_store::storage_path() + ".export.json";
        aida::preview::network::record_receipt("Scanner issue export", path);
#endif
        submit_issue_export();
    }
    ImGui::SameLine();
    if (aida::ui::button("Clear Issues", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        const auto issues = std::atomic_load_explicit(&vs().issues, std::memory_order_acquire);
        vs().reviewed_issue_identity.clear();
        vs().reviewed_issue_identity.reserve(issues->size());
        for (const auto& issue : *issues)
            vs().reviewed_issue_identity.emplace_back(issue.id, issue.seen_ms);
        ImGui::OpenPopup("Review Scanner issue clearing");
    }
    ImGui::EndDisabled();
    if (ImGui::BeginPopupModal("Review Scanner issue clearing", nullptr,
        ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Permanently clear all Scanner issues?");
        ImGui::Text("Affected issues: %zu", vs().reviewed_issue_identity.size());
        ImGui::TextWrapped("The exact reviewed issue identities and timestamps will be revalidated before persistence.");
        if (aida::ui::button("Clear issues", aida::ui::button_kind_t::destructive,
            aida::ui::size_t_::sm)) {
            submit_reviewed_issue_clear(vs().reviewed_issue_identity);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm)) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::SameLine();
    const bool passive_before = passive_scanner::is_enabled();
    bool passive = passive_before;
    ImGui::BeginDisabled(vs().operation.pending());
    aida::ui::toggle_switch("##bs_passive_en", &passive);
    if (passive != passive_before) submit_passive_toggle(passive_before, passive);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Passive");

    auto pstats = passive_scanner::get_stats();
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "  scanned=%llu  issues=%zu  modules=%zu",
                       static_cast<unsigned long long>(pstats.exchanges_scanned),
                       issue_store::count(),
                       scanner::count());

    ImGui::Spacing();

    float split = 0.36f;
    float left_w = width * split - 8.f;
    float right_w = width - left_w - 16.f;
    float panes_h = height - 60.f;

    ImGui::SetCursorPos(ImVec2(0.f, 50.f));
    ImGui::BeginChild("##burp_left", ImVec2(left_w, panes_h), false, ImGuiWindowFlags_NoBackground);
    render_audits_pane(left_w, panes_h, alpha);
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, 50.f));
    ImGui::BeginChild("##burp_right", ImVec2(right_w, panes_h), false, ImGuiWindowFlags_NoBackground);
    render_issues_pane(right_w, panes_h, alpha);
    ImGui::EndChild();

    render_new_audit_dialog(alpha);

    ImGui::EndChild();
}

}
}
}
