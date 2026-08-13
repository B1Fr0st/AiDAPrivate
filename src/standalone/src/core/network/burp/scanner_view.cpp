#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_platform.hpp"
#include "../../../preview/studio_semantics.hpp"
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
#include "../human_request_editor.hpp"
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
#include "../../ui/design_system.hpp"
#include "../../ui/responsive.hpp"
#include "../../ui/task_center.hpp"
#include "../../ui/application_view_registry.hpp"
#include "../../scanner/scanner_async_io.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "../../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
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
    bool            new_dialog_requested = false;
    bool            new_close_requested = false;
    std::uint64_t   new_dialog_generation = 0;
    std::uint64_t   new_close_dialog_generation = 0;
    bool            audit_submission_pending = false;
    bool            restore_scanner_focus = false;
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
    aida::ui::design::form_state_t new_audit_form;
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
    std::atomic<std::uint64_t> started_audit_dialog_generation{0};
    std::vector<std::pair<std::uint64_t, std::uint64_t>> reviewed_issue_identity;
    std::unordered_set<std::uint64_t> task_center_audits;
    std::unordered_set<std::uint64_t> terminal_audits;
};

constexpr std::size_t max_new_audit_url_bytes = 1023;
constexpr std::size_t max_new_audit_request_bytes = 65535;

bool valid_audit_url(std::string_view url)
{
    const std::size_t scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos)
        return false;
    std::string scheme(url.substr(0, scheme_end));
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    if (scheme != "http" && scheme != "https")
        return false;
    const std::size_t host_begin = scheme_end + 3;
    if (host_begin >= url.size())
        return false;
    const std::size_t host_end = url.find_first_of("/:?#", host_begin);
    return (host_end == std::string_view::npos ? url.size() : host_end) > host_begin;
}

void validate_new_audit(view_state_t& state, std::size_t enabled_module_count)
{
    state.new_audit_form.clear();
    const std::string_view url(state.new_url);
    const std::string_view raw(state.new_raw);
    if (url.empty())
        state.new_audit_form.reject("scanner-new-url", "Enter the exact HTTP or HTTPS target URL.");
    else if (!valid_audit_url(url))
        state.new_audit_form.reject("scanner-new-url", "Use an absolute HTTP or HTTPS URL with a host.");
    if (raw.empty())
        state.new_audit_form.reject("scanner-new-request", "Enter the HTTP/1.1 request to audit.");
    else {
        const std::size_t line_end = raw.find_first_of("\r\n");
        const std::string_view request_line = raw.substr(0, line_end);
        const std::size_t first_space = request_line.find(' ');
        const std::size_t second_space = first_space == std::string_view::npos
            ? std::string_view::npos : request_line.find(' ', first_space + 1);
        if (first_space == 0 || first_space == std::string_view::npos ||
            second_space == std::string_view::npos || second_space == first_space + 1 ||
            second_space + 1 >= request_line.size())
            state.new_audit_form.reject("scanner-new-request",
                "The first line must contain method, request target, and HTTP version.");
        else if (raw.find("\r\n\r\n") == std::string_view::npos)
            state.new_audit_form.reject("scanner-new-request",
                "Terminate the HTTP header block with an empty CRLF line.");
    }
    if (state.timeout_ms < 100 || state.timeout_ms > 300000)
        state.new_audit_form.reject("scanner-new-timeout", "Use a timeout from 100 to 300000 ms.");
    if (state.max_concurrent < 1 || state.max_concurrent > 64)
        state.new_audit_form.reject("scanner-new-concurrency", "Use 1 to 64 parallel requests.");
    if (state.throttle_ms < 0 || state.throttle_ms > 60000)
        state.new_audit_form.reject("scanner-new-throttle", "Use a throttle from 0 to 60000 ms.");
    if (state.per_module_cap < 1 || state.per_module_cap > 100000)
        state.new_audit_form.reject("scanner-new-module-cap", "Use a per-module cap from 1 to 100000.");
    if (enabled_module_count == 0)
        state.new_audit_form.reject("scanner-new-modules", "Enable at least one Scanner module.");
}

view_state_t& vs()
{
    static view_state_t s;
    return s;
}

float toolbar_button_width(const char* label)
{
    const auto size = aida::ui::size_t_::sm;
    const ImVec2 padding = aida::ui::components::control_padding(size);
    return aida::ui::components::display_text_width(
        ImGui::GetFont(), aida::ui::components::control_font_size(size), label) +
        padding.x * 2.f + 4.f;
}

bool continue_toolbar_line(float next_width, float spacing = 6.f)
{
    const float content_right = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
    if (ImGui::GetItemRectMax().x + spacing + next_width > content_right)
        return false;
    ImGui::SameLine(0.f, spacing);
    return true;
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

bool submit_audit(std::vector<std::uint8_t> raw, std::string url,
    active_scanner::audit_config_t config, std::uint64_t dialog_generation)
{
    aida::burp::ui_operation::request_t request;
    request.owner = "burp.scanner";
    request.owner_view = "view.network.scanner";
    request.owner_action = "network.scanner.start_audit";
    request.label = "Start Scanner audit";
    request.target = url;
    request.affected_entity = url;
    request.execute = [raw = std::move(raw), url = std::move(url),
                       config = std::move(config), dialog_generation]() mutable {
        aida::burp::ui_operation::result_t result;
        const std::uint64_t id = active_scanner::enqueue_target(raw, url, config);
        result.success = id != 0;
        result.message = result.success ? "Scanner audit started."
                                        : active_scanner::last_error();
        if (id != 0) {
            vs().started_audit_dialog_generation.store(dialog_generation,
                std::memory_order_release);
            vs().started_audit_id.store(id, std::memory_order_release);
        }
        return result;
    };
    return vs().operation.submit(std::move(request));
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

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
std::string semantic_identity_id(
    std::string_view kind, const ::network_view::artifact_identity_t& identity)
{
    const std::string retained = identity.id + ":" +
        std::to_string(identity.timestamp) + ":" +
        std::to_string(identity.revision) + ":" +
        std::to_string(identity.content_hash) + ":" +
        std::to_string(identity.content_size);
    return aida::preview::semantics::stable_id(
        "aida.network", std::string(kind) + "-" +
            aida::preview::semantics::entity_token(retained));
}

std::string semantic_finding_id(const issue_t& issue)
{
    const std::string retained = std::to_string(issue.id) + ":" +
        std::to_string(issue.seen_ms) + ":" + issue.type_key + ":" +
        issue.host + ":" + issue.path + ":" + issue.name;
    return aida::preview::semantics::stable_id(
        "aida.network", "scanner-finding-" +
            aida::preview::semantics::entity_token(retained));
}
#endif

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
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto identity = evidence_identity(issue, evidence_index, response);
    const std::string finding_id = semantic_finding_id(issue);
    if (ImGui::IsItemVisible())
        aida::preview::semantics::register_last_item(
            semantic_identity_id(response ? "response" : "request", identity),
            response ? "network-response-editor" : "network-request-editor",
            false, false, finding_id);
#endif
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
    ImGui::BeginChild("##burp_audits", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Audits");
    ImGui::Spacing();

    auto audits = active_scanner::list_audits();
    std::unordered_set<std::uint64_t> visible_audits;
    visible_audits.reserve(audits.size());
    for (const auto& audit : audits) {
        visible_audits.insert(audit.id);
        const std::string task_id = "network.scanner.audit." + std::to_string(audit.id);
        const float audit_progress = audit.total_probes == 0
            ? -1.0f : (std::min)(1.0f, static_cast<float>(audit.completed_probes) /
                static_cast<float>(audit.total_probes));
        if (audit.running && s.task_center_audits.insert(audit.id).second) {
            aida::ui::task_center::task_registration_t registration;
            registration.id = task_id;
            registration.owner = "network.scanner";
            registration.owner_view = "view.network.scanner";
            registration.owner_action = "network.scanner.cancel_audit";
            registration.label = "Scanner audit: " + audit.host;
            registration.stage = "Running active audit";
            registration.cancellation_is_safe = true;
            registration.callbacks.cancel = [id = audit.id] {
                return active_scanner::cancel_audit(id);
            };
            registration.callbacks.focus = [] {
                (void)aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("view.network.scanner"));
            };
            if (!aida::ui::task_center::register_task(std::move(registration)))
                s.task_center_audits.erase(audit.id);
            else
                static_cast<void>(aida::ui::task_center::update_task(task_id,
                    aida::ui::task_center::task_state_t::running, audit_progress,
                    "Running active audit"));
        } else if (audit.running && s.task_center_audits.count(audit.id) != 0U) {
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                aida::ui::task_center::task_state_t::running, audit_progress,
                "Running active audit"));
        } else if (!audit.running && s.task_center_audits.count(audit.id) != 0U &&
                   s.terminal_audits.insert(audit.id).second) {
            const bool transport_failed = !audit.cancelled &&
                audit.responses_received == 0 && audit.transport_failures != 0;
            static_cast<void>(aida::ui::task_center::update_task(task_id,
                audit.cancelled ? aida::ui::task_center::task_state_t::cancelled
                                : transport_failed
                                ? aida::ui::task_center::task_state_t::failed
                                : aida::ui::task_center::task_state_t::completed,
                1.0f, audit.cancelled ? "Cancelled" : transport_failed
                    ? "Transport failed" : "Completed",
                transport_failed ? audit.last_transport_error : std::string{}));
            s.task_center_audits.erase(audit.id);
        }
    }
    for (auto it = s.task_center_audits.begin(); it != s.task_center_audits.end();) {
        if (visible_audits.count(*it) != 0U) {
            ++it;
            continue;
        }
        const std::string task_id = "network.scanner.audit." + std::to_string(*it);
        static_cast<void>(aida::ui::task_center::update_task(task_id,
            aida::ui::task_center::task_state_t::interrupted, 1.0f,
            "Audit no longer exists in the scanner registry"));
        it = s.task_center_audits.erase(it);
    }
    constexpr std::size_t maximum_terminal_audits = 4096U;
    while (s.terminal_audits.size() > maximum_terminal_audits)
        s.terminal_audits.erase(s.terminal_audits.begin());
    const bool compact_rows = w < 400.f;
    const float line_h = ImGui::GetTextLineHeight();
    const float primary_y = 4.f;
    const float url_y = primary_y + line_h + 2.f;
    const float progress_y = url_y + line_h + 5.f;
    const float status_y = progress_y + 10.f;
    const float row_h = compact_rows
        ? std::max(76.f, status_y + line_h + 4.f)
        : std::max(60.f, progress_y + line_h + 2.f);
    const float list_h = std::max(1.f, h - 48.f);
    ImGui::BeginChild("##burp_audit_list", ImVec2(std::max(1.f, w - 4.f), list_h),
        false, ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 lo = ImGui::GetWindowPos();
    ImGuiListClipper audit_clipper;
    audit_clipper.Begin(static_cast<int>(audits.size()), row_h + 4.f);
    while (audit_clipper.Step()) {
    for (int row = audit_clipper.DisplayStart; row < audit_clipper.DisplayEnd; ++row) {
        const size_t i = static_cast<size_t>(row);
        const auto& a = audits[i];
        float ry = ImGui::GetCursorPosY();
        float abs_ry = ImGui::GetCursorScreenPos().y;
        const float row_content_w = std::max(1.f, ImGui::GetContentRegionAvail().x);
        bool hovered = ImGui::IsMouseHoveringRect(
            ImVec2(lo.x, abs_ry), ImVec2(lo.x + row_content_w, abs_ry + row_h), false);
        bool selected = (s.selected_audit_id == a.id);
        if (selected) {
            dl->AddRectFilled(
                ImVec2(lo.x, abs_ry), ImVec2(lo.x + row_content_w, abs_ry + row_h),
                              aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + 3.f, abs_ry + row_h),
                              aida::ui::with_alpha(th.accent_u32, alpha));
        } else if (hovered) {
            dl->AddRectFilled(
                ImVec2(lo.x, abs_ry), ImVec2(lo.x + row_content_w, abs_ry + row_h),
                              aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) s.selected_audit_id = a.id;

        const bool show_cancel = selected && a.running;
        const float primary_w = std::max(1.f,
            row_content_w - 24.f - (show_cancel ? 84.f : 0.f));
        char buf[512];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "#%llu  %s:%u  %s",
            static_cast<unsigned long long>(a.id), a.host.c_str(), a.port,
            a.tls ? "https" : "http");
        const std::string primary = aida::ui::responsive::ellipsize_end(
            buf, ImGui::GetFont(), ImGui::GetFontSize(), primary_w);
        dl->AddText(ImVec2(lo.x + 12.f, abs_ry + primary_y),
                    aida::ui::with_alpha(th.text_primary, alpha), primary.c_str());

        const std::string url_clip = aida::ui::responsive::ellipsize_middle(
            a.url, ImGui::GetFont(), ImGui::GetFontSize(),
            primary_w);
        dl->AddText(ImVec2(lo.x + 12.f, abs_ry + url_y),
                    aida::ui::with_alpha(th.text_secondary, alpha), url_clip.c_str());
        if (hovered && (primary != buf || url_clip != a.url))
            ImGui::SetTooltip("%s\n%s", buf, a.url.c_str());

        float frac = (a.total_probes > 0)
            ? static_cast<float>(a.completed_probes) / static_cast<float>(a.total_probes) : 0.f;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "%zu/%zu  %zu issues  %s",
            a.completed_probes, a.total_probes, a.issues_found,
            a.running ? "Running" : (a.cancelled ? "Cancelled" : "Done"));
        if (compact_rows) {
            aida::ui::render_progress_bar(ImVec2(lo.x + 12.f, abs_ry + progress_y),
                std::max(1.f, row_content_w - 24.f), 6.f, frac, false, a.running);
            const std::string status = aida::ui::responsive::ellipsize_end(
                buf, ImGui::GetFont(), ImGui::GetFontSize(),
                std::max(1.f, row_content_w - 24.f));
            dl->AddText(ImVec2(lo.x + 12.f, abs_ry + status_y),
                aida::ui::with_alpha(a.running ? th.warning : th.text_dim, alpha),
                status.c_str());
        } else {
            aida::ui::render_progress_bar(ImVec2(lo.x + 12.f, abs_ry + progress_y),
                std::max(1.f, row_content_w - 130.f), 6.f, frac, false, a.running);
            const std::string status = aida::ui::responsive::ellipsize_end(
                buf, ImGui::GetFont(), ImGui::GetFontSize(), 106.f);
            dl->AddText(ImVec2(lo.x + row_content_w - 110.f, abs_ry + progress_y - 2.f),
                aida::ui::with_alpha(a.running ? th.warning : th.text_dim, alpha),
                status.c_str());
        }

        if (selected) {
            float bx = std::max(lo.x + 8.f, lo.x + row_content_w - 80.f);
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
        ImGui::SetCursorPosY(ry + row_h + 4.f);
    }
    }
    ImGui::Dummy(ImVec2(0.f, 0.f));
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
    ImGui::BeginChild("##burp_issues", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Issues");
    const float filter_width = std::max(1.f, ImGui::GetContentRegionAvail().x);
    const float filter_gap = 6.f;
    const float density_scale = std::max(1.f, ImGui::GetFontSize() / 16.f);
    const float sev_label_w = ImGui::CalcTextSize("Sev:").x;
    const float sev_combo_preferred = std::max(110.f,
        ImGui::CalcTextSize("Critical").x + ImGui::GetStyle().FramePadding.x * 2.f);
    const float sev_combo_w = std::min(sev_combo_preferred,
        std::max(1.f, filter_width - sev_label_w - filter_gap));
    continue_toolbar_line(sev_label_w + filter_gap + sev_combo_w, filter_gap);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Sev:");
    ImGui::SameLine(0.f, filter_gap);
    const char* sev_items[] = { "Any", "Info", "Low", "Medium", "High", "Critical" };
    ImGui::SetNextItemWidth(sev_combo_w);
    ImGui::Combo("##bs_sev", &s.filter_sev, sev_items, 6);
    const float conf_label_w = ImGui::CalcTextSize("Conf:").x;
    const float conf_combo_preferred = std::max(110.f,
        ImGui::CalcTextSize("Tentative").x + ImGui::GetStyle().FramePadding.x * 2.f);
    const float conf_combo_w = std::min(conf_combo_preferred,
        std::max(1.f, filter_width - conf_label_w - filter_gap));
    continue_toolbar_line(conf_label_w + filter_gap + conf_combo_w, filter_gap);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Conf:");
    ImGui::SameLine(0.f, filter_gap);
    const char* conf_items[] = { "Any", "Tentative", "Firm", "Certain" };
    ImGui::SetNextItemWidth(conf_combo_w);
    ImGui::Combo("##bs_conf", &s.filter_conf, conf_items, 4);
    const float host_filter_w = std::min(160.f * density_scale, filter_width);
    continue_toolbar_line(host_filter_w, filter_gap);
    aida::ui::input_text("##bs_host", s.filter_host, sizeof(s.filter_host),
                          "Host filter", false, ImVec2(host_filter_w, 28.f));
    const float type_filter_w = std::min(180.f * density_scale, filter_width);
    continue_toolbar_line(type_filter_w, filter_gap);
    aida::ui::input_text("##bs_type", s.filter_type, sizeof(s.filter_type),
                          "Type filter (e.g. sqli)", false, ImVec2(type_filter_w, 28.f));

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

    const float content_top = ImGui::GetCursorPosY();
    const float remaining_h = std::max(1.f, h - content_top);
    const float split_gap = std::min(8.f, std::max(0.f, remaining_h - 2.f));
    const float usable_h = std::max(2.f, remaining_h - split_gap);
    const float list_h = std::max(1.f, usable_h * 0.55f);

    ImGui::BeginChild("##burp_issue_list", ImVec2(std::max(1.f, w - 4.f), list_h),
        false, ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 lo = ImGui::GetWindowPos();
    const float row_h = std::max(22.f, ImGui::GetTextLineHeight() + 8.f);
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    const float table_w = std::max(1.f, ImGui::GetContentRegionAvail().x);
    const float usable_w = std::max(1.f, table_w - 12.f);
    const bool show_host = usable_w >= 260.f * density_scale;
    const bool show_conf = usable_w >= 440.f * density_scale;
    const bool show_param = usable_w >= 600.f * density_scale;
    const float severity_header_w = ImGui::CalcTextSize("Severity").x + 8.f;
    const float col_sev = usable_w < 110.f * density_scale
        ? std::max(1.f, usable_w * 0.44f)
        : std::min(usable_w * 0.45f,
            std::max(severity_header_w, usable_w * 0.18f));
    const float col_conf = show_conf
        ? std::max(70.f * density_scale, ImGui::CalcTextSize("Certain").x + 8.f) : 0.f;
    const float col_host = show_host
        ? std::min(220.f * density_scale,
            std::max(96.f * density_scale, usable_w * 0.28f)) : 0.f;
    const float col_param = show_param
        ? std::min(140.f * density_scale,
            std::max(92.f * density_scale, usable_w * 0.18f)) : 0.f;
    const float col_type = std::max(1.f,
        usable_w - col_sev - col_conf - col_host - col_param);

    {
        float hy = ImGui::GetCursorScreenPos().y;
        dl->AddRectFilled(ImVec2(lo.x, hy), ImVec2(lo.x + table_w, hy + row_h),
                          aida::ui::with_alpha(th.panel_header, alpha));
        float cx = lo.x + 8.f;
        ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
        dl->AddText(ImVec2(cx, hy + text_oy), hc,
            usable_w < 110.f * density_scale ? "Sev" : "Severity");
        cx += col_sev;
        if (show_conf) {
            dl->AddText(ImVec2(cx, hy + text_oy), hc, "Conf.");
            cx += col_conf;
        }
        if (show_host) {
            dl->AddText(ImVec2(cx, hy + text_oy), hc, "Host");
            cx += col_host;
        }
        if (show_param) {
            dl->AddText(ImVec2(cx, hy + text_oy), hc, "Param");
            cx += col_param;
        }
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
        bool hovered = ImGui::IsMouseHoveringRect(
            ImVec2(lo.x, abs_ry), ImVec2(lo.x + table_w, abs_ry + row_h), false);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        ImGui::PushID(row);
        const ImGuiID finding_row_id = ImGui::GetID("##scanner_finding_row");
        ImGui::PopID();
        aida::preview::semantics::register_region(
            semantic_finding_id(it), "network-scanner-finding", finding_row_id,
            ImVec2(lo.x, abs_ry), ImVec2(lo.x + table_w, abs_ry + row_h), false, false,
            "aida.dock-window.view.network.scanner");
#endif
        bool selected = (s.selected_issue_id == it.id);
        if (selected) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + table_w, abs_ry + row_h),
                               aida::ui::with_alpha(th.selection, alpha), 4.f);
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + 3.f, abs_ry + row_h),
                              sev_color(it.severity, alpha));
        } else if (hovered) {
            dl->AddRectFilled(ImVec2(lo.x, abs_ry), ImVec2(lo.x + table_w, abs_ry + row_h),
                               aida::ui::with_alpha(th.hover_wash, alpha), 4.f);
        }
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) s.selected_issue_id = it.id;

        float cx = lo.x + 8.f;
        dl->AddText(ImVec2(cx, abs_ry + text_oy), sev_color(it.severity, alpha), severity_label(it.severity)); cx += col_sev;
        if (show_conf) {
            dl->AddText(ImVec2(cx, abs_ry + text_oy), conf_color(it.confidence, alpha),
                confidence_label(it.confidence));
            cx += col_conf;
        }
        if (show_host) {
            const std::string host = aida::ui::responsive::ellipsize_middle(
                it.host, ImGui::GetFont(), ImGui::GetFontSize(),
                std::max(1.f, col_host - 6.f));
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                aida::ui::with_alpha(th.text_primary, alpha), host.c_str());
            cx += col_host;
        }
        if (show_param) {
            const std::string param = aida::ui::responsive::ellipsize_end(
                it.parameter, ImGui::GetFont(), ImGui::GetFontSize(),
                std::max(1.f, col_param - 6.f));
            dl->AddText(ImVec2(cx, abs_ry + text_oy),
                aida::ui::with_alpha(th.text_secondary, alpha), param.c_str());
            cx += col_param;
        }
        const std::string type = aida::ui::responsive::ellipsize_end(
            it.type_key, ImGui::GetFont(), ImGui::GetFontSize(),
            std::max(1.f, col_type - 4.f));
        dl->AddText(ImVec2(cx, abs_ry + text_oy),
            aida::ui::with_alpha(th.text_primary, alpha), type.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }
    }
    ImGui::Dummy(ImVec2(0.f, 0.f));
    ImGui::EndChild();

    if (split_gap > 0.f)
        ImGui::Dummy(ImVec2(0.f, split_gap));

    const float detail_h = std::max(1.f, usable_h - list_h);
    ImGui::BeginChild("##burp_issue_detail", ImVec2(std::max(1.f, w - 4.f), detail_h),
        false, ImGuiWindowFlags_NoBackground);
    const auto selected_it = std::find_if(issues->begin(), issues->end(),
        [&](const auto& issue) { return issue.id == s.selected_issue_id; });
    if (s.selected_issue_id != 0 && selected_it != issues->end()) {
        const auto& selected = *selected_it;
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(sev_color(selected.severity, alpha)),
                           "%s", severity_label(selected.severity));
        if (ImGui::GetContentRegionAvail().x >= 400.f)
            ImGui::SameLine();
        ImGui::TextWrapped("%s", selected.name.c_str());
        ImGui::TextWrapped("%s://%s:%u%s   param=%s   ip=%s",
            selected.scheme.c_str(), selected.host.c_str(), selected.port,
            selected.path.c_str(), selected.parameter.c_str(),
            selected.insertion_point.c_str());
        ImGui::TextWrapped(
            "Confidence: %s   Type: %s", confidence_label(selected.confidence),
            selected.type_key.c_str());
        if (!selected.cwe.empty()) {
            std::string cwe;
            for (size_t i = 0; i < selected.cwe.size(); ++i) {
                if (i) cwe += ", ";
                cwe += selected.cwe[i];
            }
            ImGui::TextWrapped("CWE: %s", cwe.c_str());
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
                ImGui::TextWrapped("Evidence #%zu  marker=%s", i + 1, ev.marker.c_str());
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
    if (s.new_dialog_requested) {
        aida::ui::design::open_dialog("dialog.network_scanner_new", "New Scanner Audit");
        s.new_dialog_requested = false;
    }
    if (!s.new_open)
        return;

    auto modules = scanner::all_modules();
    const std::size_t enabled_module_count = static_cast<std::size_t>(std::count_if(
        modules.begin(), modules.end(), [&s](const auto& module) {
            return s.module_disabled.find(module.id) == s.module_disabled.end();
        }));
    validate_new_audit(s, enabled_module_count);
    if (aida::ui::design::begin_dialog("dialog.network_scanner_new",
        "New Scanner Audit", ImVec2(680.f, 720.f), ImVec2(420.f, 360.f))) {
        static network_view::human_request_editor::fixed_state_t request_editor;
        network_view::human_request_editor::render_result_t request_editor_result;
        const bool pending = s.audit_submission_pending;
        const float footer = aida::ui::design::dialog_footer_reserve_height("Start Audit");
        if (aida::ui::design::begin_dialog_body("network-scanner-new-body", footer)) {
            ImGui::BeginDisabled(pending);
            aida::ui::design::form_input_text("scanner-new-url", "Target URL", s.new_url,
                sizeof(s.new_url), s.new_audit_form, "https://example.com/path?id=1");
            aida::ui::design::text(aida::ui::design::text_role_t::secondary,
                "Raw Request (HTTP/1.1 textual)");
            if (s.new_audit_form.consume_focus_request("scanner-new-request"))
                ImGui::SetKeyboardFocusHere();
            network_view::human_request_editor::render_config_t request_config;
            request_config.stable_id = "scanner-new-request";
            request_config.size = ImVec2(-FLT_MIN,
                (std::max)(140.f, ImGui::GetContentRegionAvail().y * 0.34f));
            request_config.max_bytes = sizeof(s.new_raw) - 1;
            request_config.editable = !pending;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            std::string request_editor_parent =
                aida::preview::semantics::stable_id(
                    "aida.dialog", "dialog.network_scanner_new");
            const auto& active_parent =
                aida::preview::semantics::active_parent_storage();
            if (!active_parent.empty()) {
                request_editor_parent.push_back('.');
                request_editor_parent.append(
                    aida::preview::semantics::entity_token(active_parent));
            }
            request_config.semantic_parent_id = request_editor_parent.c_str();
#endif
            request_editor_result = network_view::human_request_editor::render_fixed(
                request_editor,
                "scanner.new-request." + std::to_string(s.new_dialog_generation),
                s.new_raw, request_config);
            aida::ui::design::inline_validation("scanner-new-request", s.new_audit_form);

            ImGui::Spacing();
            ImGui::PushID("scanner-new-options");
            aida::ui::toggle_switch("##scope", &s.scope_only);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.form-field.scanner-new-scope", "form-field"));
#endif
            ImGui::SameLine();
            ImGui::TextUnformatted("Scope only");
            ImGui::SameLine(0.f, aida::ui::design::metrics().spacing_lg);
            aida::ui::toggle_switch("##redirects", &s.follow_redirects);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            static_cast<void>(aida::preview::semantics::register_last_item(
                "aida.form-field.scanner-new-redirects", "form-field"));
#endif
            ImGui::SameLine();
            ImGui::TextUnformatted("Follow redirects");
            ImGui::PopID();

            if (ImGui::BeginTable("##scanner-new-limits", 2,
                ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings)) {
                ImGui::TableNextColumn();
                aida::ui::design::form_input_int("scanner-new-timeout", "Timeout (ms)",
                    s.timeout_ms, s.new_audit_form, 1000);
                ImGui::TableNextColumn();
                aida::ui::design::form_input_int("scanner-new-concurrency", "Max parallel",
                    s.max_concurrent, s.new_audit_form);
                ImGui::TableNextColumn();
                aida::ui::design::form_input_int("scanner-new-throttle", "Throttle (ms)",
                    s.throttle_ms, s.new_audit_form, 10);
                ImGui::TableNextColumn();
                aida::ui::design::form_input_int("scanner-new-module-cap", "Per-module cap",
                    s.per_module_cap, s.new_audit_form);
                ImGui::EndTable();
            }

            aida::ui::design::text(aida::ui::design::text_role_t::secondary,
                "Enabled modules");
            if (ImGui::BeginChild("##scanner-new-modules", ImVec2(0.f, 132.f),
                ImGuiChildFlags_Borders, ImGuiWindowFlags_NoSavedSettings)) {
                const float row_height = ImGui::GetTextLineHeightWithSpacing();
                aida::ui::design::render_clipped_rows(modules.size(), row_height,
                    [&s, &modules, alpha, &th](std::size_t index) {
                        const auto& module = modules[index];
                        bool enabled = s.module_disabled.find(module.id) == s.module_disabled.end();
                        ImGui::PushID(module.id.c_str());
                        if (ImGui::Checkbox(module.name.c_str(), &enabled)) {
                            if (enabled)
                                s.module_disabled.erase(module.id);
                            else
                                s.module_disabled.insert(module.id);
                        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                        static_cast<void>(aida::preview::semantics::register_last_item(
                            aida::preview::semantics::stable_id(
                                "aida.form-field.scanner-new-module", module.id), "form-field"));
#endif
                        ImGui::SameLine((std::min)(220.f, ImGui::GetContentRegionAvail().x * 0.48f));
                        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
                            aida::ui::with_alpha(th.text_dim, alpha)), "[%s] %s",
                            module.category.c_str(), module.id.c_str());
                        ImGui::PopID();
                    });
            }
            ImGui::EndChild();
            aida::ui::design::inline_validation("scanner-new-modules", s.new_audit_form);
            ImGui::EndDisabled();

            aida::ui::design::form_summary("scanner-new-summary", s.new_audit_form);
            if (pending)
                aida::ui::components::inline_notice("scanner-new-pending", "Starting audit",
                    "The reviewed target and request are queued in Task Center.",
                    aida::ui::components::status_kind_t::accent);
            else if (!s.initialized.load(std::memory_order_acquire))
                aida::ui::components::inline_notice("scanner-new-unavailable",
                    s.operation.pending() ? "Scanner is loading" : "Scanner unavailable",
                    s.operation.pending() ? "Initialization is running in Task Center."
                                          : "Retry Scanner initialization before starting an audit.",
                    s.operation.pending() ? aida::ui::components::status_kind_t::accent
                                          : aida::ui::components::status_kind_t::error);
            else if (s.status_msg[0])
                aida::ui::components::inline_notice("scanner-new-status", "Scanner",
                    s.status_msg, aida::ui::components::status_kind_t::warning);
        }
        aida::ui::design::end_dialog_body();

        if (s.new_close_requested &&
            s.new_close_dialog_generation == s.new_dialog_generation) {
            s.new_close_requested = false;
            s.new_close_dialog_generation = 0;
            s.new_open = false;
            s.restore_scanner_focus = true;
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::SetWindowFocus();
            s.restore_scanner_focus = false;
            return;
        }
        if (s.new_close_requested) {
            s.new_close_requested = false;
            s.new_close_dialog_generation = 0;
        }

        const std::size_t current_enabled_module_count = static_cast<std::size_t>(
            std::count_if(modules.begin(), modules.end(), [&s](const auto& module) {
                return s.module_disabled.find(module.id) == s.module_disabled.end();
            }));
        validate_new_audit(s, current_enabled_module_count);
        const bool can_submit = s.new_audit_form.valid() && !pending &&
            !s.operation.pending() && s.initialized.load(std::memory_order_acquire) &&
            request_editor_result.valid && !request_editor_result.has_unapplied_pretty;
        const auto result = aida::ui::design::dialog_footer("network-scanner-new-footer",
            "Start Audit", can_submit, false, "Cancel", !pending, can_submit);
        if (!s.new_audit_form.valid() && !pending && !ImGui::GetIO().WantTextInput &&
            (ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
             ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)))
            s.new_audit_form.request_first_invalid_focus();
        if (result.confirmed) {
            std::string url(s.new_url);
            std::string raw(s.new_raw);
            std::vector<std::uint8_t> raw_bytes(raw.begin(), raw.end());
            active_scanner::audit_config_t config;
            config.scope_only = s.scope_only;
            config.follow_redirects = s.follow_redirects;
            config.timeout_ms = s.timeout_ms;
            config.max_concurrent_requests = static_cast<std::size_t>(s.max_concurrent);
            config.request_throttle_ms = static_cast<std::size_t>(s.throttle_ms);
            config.per_module_request_cap = static_cast<std::size_t>(s.per_module_cap);
            config.max_concurrent_explicit = true;
            config.request_throttle_explicit = true;
            for (const auto& module : modules) {
                if (s.module_disabled.find(module.id) == s.module_disabled.end())
                    config.enabled_modules.push_back(module.id);
            }
            s.status_msg[0] = '\0';
            s.audit_submission_pending = submit_audit(
                std::move(raw_bytes), std::move(url), std::move(config),
                s.new_dialog_generation);
            if (!s.audit_submission_pending) {
                _snprintf_s(s.status_msg, sizeof(s.status_msg), _TRUNCATE,
                    "Task Center rejected the audit request; review the active operation and retry.");
            }
        }
        if (result.cancelled && !s.audit_submission_pending) {
            s.new_open = false;
            s.restore_scanner_focus = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    if (s.restore_scanner_focus) {
        ImGui::SetWindowFocus();
        s.restore_scanner_focus = false;
    }
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
    if (s.new_open || url.size() > max_new_audit_url_bytes ||
        raw_request.size() > max_new_audit_request_bytes ||
        network_view::human_request_editor::contains_binary_bytes(url) ||
        network_view::human_request_editor::contains_binary_bytes(raw_request))
        return false;
    std::memcpy(s.new_url, url.data(), url.size());
    s.new_url[url.size()] = '\0';
    std::memcpy(s.new_raw, raw_request.data(), raw_request.size());
    s.new_raw[raw_request.size()] = '\0';
    s.status_msg[0] = '\0';
    ++s.new_dialog_generation;
    if (s.new_dialog_generation == 0)
        ++s.new_dialog_generation;
    s.new_close_requested = false;
    s.new_close_dialog_generation = 0;
    s.new_open = true;
    s.new_dialog_requested = true;
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
            const std::uint64_t dialog_generation =
                vs().started_audit_dialog_generation.exchange(0,
                    std::memory_order_acq_rel);
            if (audit_id != 0) {
                vs().selected_audit_id = audit_id;
                if (vs().new_open && dialog_generation == vs().new_dialog_generation) {
                    vs().new_close_requested = true;
                    vs().new_close_dialog_generation = dialog_generation;
                }
            }
            vs().issues_filter_signature.clear();
            if (operation_completion->result.message.find("cleared") != std::string::npos)
                vs().selected_issue_id = 0;
        }
        if (vs().audit_submission_pending)
            vs().audit_submission_pending = false;
        _snprintf_s(vs().status_msg, sizeof(vs().status_msg), _TRUNCATE,
            "%s", operation_completion->result.message.c_str());
    }
    const auto& th = aida::ui::resolved();
    const float density_scale = std::max(1.f, ImGui::GetFontSize() / 16.f);
    const bool compact_toolbar = width < 760.f * density_scale;

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_scanner_root", ImVec2(width, height), false,
        ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::SetScrollY(0.f);

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Scanner");
    continue_toolbar_line(toolbar_button_width("New Audit"));
    if (aida::ui::button("New Audit", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        ++vs().new_dialog_generation;
        if (vs().new_dialog_generation == 0)
            ++vs().new_dialog_generation;
        vs().new_close_requested = false;
        vs().new_close_dialog_generation = 0;
        vs().new_open = true;
        vs().new_dialog_requested = true;
        vs().status_msg[0] = '\0';
    }
    if (!vs().initialized.load(std::memory_order_acquire) && operation_completion &&
        !operation_completion->result.success && !vs().operation.pending()) {
        continue_toolbar_line(toolbar_button_width("Retry initialization"));
        if (aida::ui::button("Retry initialization", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm))
            submit_initialization();
    }
    if (!compact_toolbar)
        continue_toolbar_line(toolbar_button_width("Export Issues"));
    ImGui::BeginDisabled(vs().operation.pending() ||
        !vs().initialized.load(std::memory_order_acquire));
    if (aida::ui::button("Export Issues", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
        const std::string path = issue_store::storage_path() + ".export.json";
        aida::preview::network::record_receipt("Scanner issue export", path);
#endif
        submit_issue_export();
    }
    continue_toolbar_line(toolbar_button_width("Clear Issues"));
    if (aida::ui::button("Clear Issues", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        const auto issues = std::atomic_load_explicit(&vs().issues, std::memory_order_acquire);
        vs().reviewed_issue_identity.clear();
        vs().reviewed_issue_identity.reserve(issues->size());
        for (const auto& issue : *issues)
            vs().reviewed_issue_identity.emplace_back(issue.id, issue.seen_ms);
        ImGui::OpenPopup("Review Scanner issue clearing");
    }
    ImGui::EndDisabled();
    const float passive_width = 42.f + 6.f + ImGui::CalcTextSize("Passive").x;
    if (!compact_toolbar)
        continue_toolbar_line(passive_width);
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
    char scanned[64]{};
    char issues[64]{};
    char modules[64]{};
    std::snprintf(scanned, sizeof(scanned), "Scanned %llu",
        static_cast<unsigned long long>(pstats.exchanges_scanned));
    std::snprintf(issues, sizeof(issues), "Issues %zu", issue_store::count());
    std::snprintf(modules, sizeof(modules), "Modules %zu", scanner::count());
    const ImVec4 stats_color = ImGui::ColorConvertU32ToFloat4(
        aida::ui::with_alpha(th.text_dim, alpha));
    continue_toolbar_line(ImGui::CalcTextSize(scanned).x);
    ImGui::TextColored(stats_color, "%s", scanned);
    continue_toolbar_line(ImGui::CalcTextSize(issues).x);
    ImGui::TextColored(stats_color, "%s", issues);
    continue_toolbar_line(ImGui::CalcTextSize(modules).x);
    ImGui::TextColored(stats_color, "%s", modules);

    const float panes_y = ImGui::GetCursorPosY() + 6.f;
    const float panes_h = std::max(1.f, height - panes_y);
    const float pane_gap = std::max(8.f, ImGui::GetStyle().ItemSpacing.x);
    const bool stack_panes = width < 760.f * density_scale;
    const float pane_w = std::max(1.f, width);
    ImGui::SetCursorPos(ImVec2(0.f, panes_y));
    if (stack_panes) {
        ImGui::BeginChild("##burp_compact_panes", ImVec2(pane_w, panes_h), false,
            ImGuiWindowFlags_NoBackground);
        if (ImGui::BeginTabBar("##burp_scanner_compact_tabs")) {
            if (ImGui::BeginTabItem("Audits")) {
                const ImVec2 avail = ImGui::GetContentRegionAvail();
                render_audits_pane(std::max(1.f, avail.x), std::max(1.f, avail.y), alpha);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Issues")) {
                const ImVec2 avail = ImGui::GetContentRegionAvail();
                render_issues_pane(std::max(1.f, avail.x), std::max(1.f, avail.y), alpha);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::EndChild();
    } else {
        const float left_w = std::max(1.f, width * 0.36f - pane_gap);
        const float right_w = std::max(1.f, width - left_w - pane_gap * 2.f);
        ImGui::BeginChild("##burp_left", ImVec2(left_w, panes_h), false,
            ImGuiWindowFlags_NoBackground);
        render_audits_pane(left_w, panes_h, alpha);
        ImGui::EndChild();

        ImGui::SetCursorPos(ImVec2(left_w + pane_gap, panes_y));
        ImGui::BeginChild("##burp_right", ImVec2(right_w, panes_h), false,
            ImGuiWindowFlags_NoBackground);
        render_issues_pane(right_w, panes_h, alpha);
        ImGui::EndChild();
    }

    if (aida::ui::design::begin_dialog_exact("Review Scanner issue clearing",
        ImVec2(540.f, 300.f), ImVec2(420.f, 240.f))) {
        const float footer = aida::ui::design::dialog_footer_reserve_height("Clear issues");
        if (aida::ui::design::begin_dialog_body("scanner_issue_clear_review_body", footer)) {
            ImGui::TextUnformatted("Permanently clear all Scanner issues?");
            ImGui::Text("Affected issues: %zu", vs().reviewed_issue_identity.size());
            ImGui::TextWrapped("The exact reviewed issue identities and timestamps will be revalidated before persistence.");
        }
        aida::ui::design::end_dialog_body();
        const auto result = aida::ui::design::dialog_footer(
            "scanner_issue_clear_review_footer", "Clear issues",
            !vs().reviewed_issue_identity.empty() && !vs().operation.pending(), true);
        if (result.confirmed) {
            submit_reviewed_issue_clear(vs().reviewed_issue_identity);
            ImGui::CloseCurrentPopup();
        }
        if (result.cancelled) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    render_new_audit_dialog(alpha);

    ImGui::EndChild();
}

}
}
}
