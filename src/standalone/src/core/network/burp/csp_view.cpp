#include "csp_view.hpp"
#include "csp_analyzer.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace csp {

namespace {

struct view_state_t
{
    char         input_buf[8192] = {};
    bool         report_only = false;
    csp_result_t result;
    bool         have_result = false;
    float        anim_time = 0.f;
    std::mutex   mtx;
};

view_state_t& vs()
{
    static view_state_t st;
    return st;
}

ImU32 sev_color(const std::string& sev, ImU32 fallback)
{
    const auto& th = aida::ui::resolved();
    if (sev == "high")   return th.error;
    if (sev == "medium") return th.warning;
    if (sev == "low")    return th.info;
    if (sev == "info")   return th.text_secondary;
    return fallback;
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = vs();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_csp_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();

    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "CSP Analyzer");

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + 36.f));
    ImGui::PushID("burp_csp_form");

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Paste Content-Security-Policy header value:");
    ImGui::SetNextItemWidth(width - 16.f);
    ImGui::InputTextMultiline("##csp_input", st.input_buf, sizeof(st.input_buf),
                              ImVec2(width - 16.f, 96.f), ImGuiInputTextFlags_AllowTabInput);

    ImGui::Checkbox("Report-only", &st.report_only);
    ImGui::SameLine();
    if (ImGui::Button("Analyze", ImVec2(120.f, 24.f))) {
        std::string src(st.input_buf);
        ::diag::log_tagged_fmt("csp_v", "analyze report_only=%d input_len=%zu",
            st.report_only ? 1 : 0, src.size());
        auto r = analyze(src, st.report_only);
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            st.result = std::move(r);
            st.have_result = true;
        }
        ::diag::log_tagged_fmt("csp_v", "analyze_result score=%d has_csp=%d directives=%zu findings=%zu",
            st.result.score, st.result.has_csp ? 1 : 0,
            st.result.directives.size(), st.result.findings.size());
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(80.f, 24.f))) {
        ::diag::log_tagged("csp_v", "clear");
        st.input_buf[0] = '\0';
        std::lock_guard<std::mutex> lk(st.mtx);
        st.result = csp_result_t{};
        st.have_result = false;
    }

    ImGui::PopID();

    if (!st.have_result) {
        ImGui::EndChild();
        return;
    }

    st.anim_time += ImGui::GetIO().DeltaTime;

    csp_result_t snapshot;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        snapshot = st.result;
    }

    char score_buf[64];
    _snprintf_s(score_buf, sizeof(score_buf), _TRUNCATE, "Score: %d / 100", snapshot.score);
    ImU32 score_col = th.success;
    if (snapshot.score < 70 && snapshot.score >= 40) score_col = th.warning;
    if (snapshot.score < 40) score_col = th.error;
    if (!snapshot.has_csp) score_col = th.error;

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(score_col, alpha)), "%s", score_buf);
    if (snapshot.is_report_only) {
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.warning, alpha)),
                           "  [report-only]");
    }

    ImGui::Spacing();
    ImGui::Separator();

    float left_w = (width - 24.f) * 0.45f;
    float right_w = (width - 24.f) - left_w;

    ImGui::BeginChild("##csp_directives", ImVec2(left_w, height - 220.f), true,
                      ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                       "Directives (%zu)", snapshot.directives.size());
    ImGui::Spacing();
    int row_i = 0;
    for (const auto& d : snapshot.directives) {
        float ra = ui_anim::render_row_entrance(row_i, st.anim_time, 0.012f);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha * ra)),
                           "%s", d.name.c_str());
        for (const auto& v : d.values) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha * ra)),
                               " %s", v.c_str());
        }
        if (d.values.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha * ra)),
                               " (empty)");
        }
        ++row_i;
    }
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##csp_findings", ImVec2(right_w, height - 220.f), true,
                      ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                       "Findings (%zu)", snapshot.findings.size());
    ImGui::Spacing();
    int fi = 0;
    for (const auto& f : snapshot.findings) {
        float ra = ui_anim::render_row_entrance(fi, st.anim_time, 0.012f);
        ImU32 col = aida::ui::with_alpha(sev_color(f.severity, th.text_primary), alpha * ra);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(col), "[%s] %s",
                           f.severity.c_str(), f.title.c_str());
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha * ra)),
                           "  %s", f.description.c_str());
        if (!f.evidence.empty()) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha * ra)),
                               "  evidence: %s", f.evidence.c_str());
        }
        ImGui::Spacing();
        ++fi;
    }
    if (snapshot.findings.empty()) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.success, alpha)),
                           "No findings. Looks tight.");
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
