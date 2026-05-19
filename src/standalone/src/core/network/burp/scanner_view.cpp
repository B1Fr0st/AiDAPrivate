#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "scanner_view.hpp"
#include "active_scanner.hpp"
#include "audit_http.hpp"
#include "issue.hpp"
#include "passive_scanner.hpp"
#include "scanner_module.hpp"

#include "../../ui/components.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
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
};

view_state_t& vs()
{
    static view_state_t s;
    return s;
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

void render_audits_pane(float w, float h, float alpha)
{
    auto& s = vs();
    const auto& th = aida::ui::resolved();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::BeginChild("##burp_audits", ImVec2(w, h), false, ImGuiWindowFlags_NoBackground);
    ImVec2 org = ImGui::GetWindowPos();

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
    ImVec2 org = ImGui::GetWindowPos();

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
    auto issues = issue_store::list(f);

    float top_used = 70.f;
    float list_h = (h - top_used) * 0.55f;

    ImGui::BeginChild("##burp_issue_list", ImVec2(w - 4.f, list_h), false, ImGuiWindowFlags_NoBackground);
    ImVec2 lo = ImGui::GetWindowPos();
    float row_h = 22.f;
    float col_sev = 80.f, col_conf = 70.f, col_host = 220.f, col_param = 140.f;
    float col_type = (w - 8.f - col_sev - col_conf - col_host - col_param - 16.f);
    if (col_type < 120.f) col_type = 120.f;

    {
        float hy = ImGui::GetCursorScreenPos().y;
        dl->AddRectFilled(ImVec2(lo.x, hy), ImVec2(lo.x + w, hy + row_h),
                          aida::ui::with_alpha(th.panel_header, alpha));
        float cx = lo.x + 8.f;
        ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
        dl->AddText(ImVec2(cx, hy + 4.f), hc, "Severity"); cx += col_sev;
        dl->AddText(ImVec2(cx, hy + 4.f), hc, "Conf.");    cx += col_conf;
        dl->AddText(ImVec2(cx, hy + 4.f), hc, "Host");     cx += col_host;
        dl->AddText(ImVec2(cx, hy + 4.f), hc, "Param");    cx += col_param;
        dl->AddText(ImVec2(cx, hy + 4.f), hc, "Type");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);
    }

    for (size_t i = 0; i < issues.size(); ++i) {
        const auto& it = issues[i];
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
        dl->AddText(ImVec2(cx, abs_ry + 3.f), sev_color(it.severity, alpha), severity_label(it.severity)); cx += col_sev;
        dl->AddText(ImVec2(cx, abs_ry + 3.f), conf_color(it.confidence, alpha), confidence_label(it.confidence)); cx += col_conf;
        std::string host = it.host;
        if (host.size() > 32) host = host.substr(0, 29) + "...";
        dl->AddText(ImVec2(cx, abs_ry + 3.f), aida::ui::with_alpha(th.text_primary, alpha), host.c_str()); cx += col_host;
        std::string param = it.parameter;
        if (param.size() > 18) param = param.substr(0, 15) + "...";
        dl->AddText(ImVec2(cx, abs_ry + 3.f), aida::ui::with_alpha(th.text_secondary, alpha), param.c_str()); cx += col_param;
        dl->AddText(ImVec2(cx, abs_ry + 3.f), aida::ui::with_alpha(th.text_primary, alpha), it.type_key.c_str());

        ImGui::SetCursorPosY(ry + row_h);
    }
    ImGui::EndChild();

    ImGui::Spacing();

    float detail_h = h - top_used - list_h - 16.f;
    if (detail_h < 60.f) detail_h = 60.f;
    ImGui::BeginChild("##burp_issue_detail", ImVec2(w - 4.f, detail_h), false, ImGuiWindowFlags_NoBackground);
    issue_t selected;
    if (s.selected_issue_id != 0 && issue_store::get(s.selected_issue_id, selected)) {
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
                if (!ev.request_raw.empty()) {
                    ImGui::TextDisabled("Request:");
                    ImGui::TextWrapped("%s", ev.request_raw.c_str());
                }
                if (!ev.response_raw.empty()) {
                    ImGui::TextDisabled("Response:");
                    ImGui::TextWrapped("%s", ev.response_raw.c_str());
                }
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
                uint64_t id = active_scanner::enqueue_target(raw_bytes, url, cfg);
                if (id == 0) {
                    _snprintf_s(s.status_msg, sizeof(s.status_msg), _TRUNCATE,
                                "Failed: %s", active_scanner::last_error().c_str());
                } else {
                    s.selected_audit_id = id;
                    s.new_open = false;
                    _snprintf_s(s.status_msg, sizeof(s.status_msg), _TRUNCATE,
                                "Audit #%llu started.", static_cast<unsigned long long>(id));
                }
            }
        }
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
    issue_store::initialize();
    passive_scanner::initialize();
    active_scanner::initialize();
    return true;
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

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    if (!vs().initialized.load()) initialize();
    const auto& th = aida::ui::resolved();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_scanner_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Scanner");
    ImGui::SameLine();
    if (aida::ui::button("New Audit", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        vs().new_open = true;
    }
    ImGui::SameLine();
    if (aida::ui::button("Export Issues", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        issue_filter_t f;
        auto doc = issue_store::export_json(f);
        std::string path = issue_store::storage_path();
        path += ".export.json";
        FILE* fp = nullptr;
        if (fopen_s(&fp, path.c_str(), "wb") == 0 && fp) {
            std::string dump = doc.dump(2);
            fwrite(dump.data(), 1, dump.size(), fp);
            fclose(fp);
            _snprintf_s(vs().status_msg, sizeof(vs().status_msg), _TRUNCATE,
                        "Exported %zu issues to %s",
                        doc.contains("count") ? doc["count"].get<size_t>() : 0, path.c_str());
        }
    }
    ImGui::SameLine();
    if (aida::ui::button("Clear Issues", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        issue_store::clear();
        vs().selected_issue_id = 0;
    }
    ImGui::SameLine();
    bool passive = passive_scanner::is_enabled();
    aida::ui::toggle_switch("##bs_passive_en", &passive);
    if (passive != passive_scanner::is_enabled()) passive_scanner::set_enabled(passive);
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
