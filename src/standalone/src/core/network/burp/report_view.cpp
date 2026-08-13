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

#include "report_view.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_routed.hpp"
#else
#include "report_generator.hpp"
#include "issue.hpp"
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
#include <cstdio>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace report_view {

namespace {

state_t s_state;

const char* g_format_items[] = { "html", "markdown", "json", "sarif_2_1_0", "csv" };

report::report_format_t fmt_from_idx(int i)
{
    switch (i) {
        case 0: return report::report_format_t::html;
        case 1: return report::report_format_t::markdown;
        case 2: return report::report_format_t::json;
        case 3: return report::report_format_t::sarif_2_1;
        case 4: return report::report_format_t::csv;
    }
    return report::report_format_t::html;
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
    ImGui::BeginChild("##rv_root", ImVec2(width, height), false);

    float left_w = width * 0.45f;
    float right_w = width - left_w - 16.f;

    ImGui::SetCursorPos(ImVec2(0.f, 0.f));
    ImGui::BeginChild("##rv_left", ImVec2(left_w, height), false);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Report configuration:");
    ImGui::Separator();
    ImGui::Text("Title");
    aida::ui::input_text("##rv_title", s_state.title_buf, sizeof(s_state.title_buf),
                         "Engagement title", false, ImVec2(left_w - 16.f, 28.f));
    ImGui::Text("Client");
    aida::ui::input_text("##rv_client", s_state.client_buf, sizeof(s_state.client_buf),
                         "Client name", false, ImVec2(left_w - 16.f, 28.f));
    ImGui::Text("Scope summary");
    ImGui::InputTextMultiline("##rv_scope", s_state.scope_buf, sizeof(s_state.scope_buf),
                              ImVec2(left_w - 16.f, 80.f));
    ImGui::Text("Output path");
    aida::ui::input_text("##rv_path", s_state.output_path_buf, sizeof(s_state.output_path_buf),
                         "C:\\reports\\engagement.html", false, ImVec2(left_w - 16.f, 28.f));
    ImGui::Text("Format");
    ImGui::SetNextItemWidth(220.f);
    ImGui::Combo("##rv_fmt", &s_state.format_idx, g_format_items, IM_ARRAYSIZE(g_format_items));
    ImGui::Checkbox("Include evidence", &s_state.include_evidence);
    ImGui::SameLine();
    ImGui::Checkbox("Include remediation", &s_state.include_remediation);

    size_t cnt = issue_store::count();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Issues available: %zu", cnt);

    bool gen = s_state.generating.load();
    if (gen) ImGui::BeginDisabled();
    if (aida::ui::button("Generate report", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        report::report_config_t cfg;
        cfg.title               = s_state.title_buf;
        cfg.client              = s_state.client_buf;
        cfg.scope_summary       = s_state.scope_buf;
        cfg.output_path         = s_state.output_path_buf;
        cfg.format              = fmt_from_idx(s_state.format_idx);
        cfg.include_evidence    = s_state.include_evidence;
        cfg.include_remediation = s_state.include_remediation;
        ::diag::log_tagged_fmt("report_v", "generate_report title='%s' format=%d path='%s' issues=%zu",
            cfg.title.c_str(), s_state.format_idx, cfg.output_path.c_str(), cnt);
        s_state.generating.store(true);
        {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.report_view";
            sub.label = "report.generate";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::diagnostics;
            sub.priority = 3;
            sub.body = [cfg]() {
            std::string out;
            bool ok = report::generate(cfg, out);
            {
                std::lock_guard<std::mutex> lk(s_state.lock);
                s_state.last_action_kind = ok ? "ok" : "error";
                s_state.last_action      = ok ? std::string("Generated: ") + out : out;
            }
            ::diag::log_tagged_fmt("report_v", "generate_result ok=%d path='%s'", ok ? 1 : 0, out.c_str());
            s_state.generating.store(false);
        };
            (void)::aida::infra::executor::submit(std::move(sub));
        }
    }
    if (gen) ImGui::EndDisabled();
    {
        std::lock_guard<std::mutex> lk(s_state.lock);
        if (!s_state.last_action.empty()) {
            ImU32 c = (s_state.last_action_kind == "error")
                ? aida::ui::with_alpha(th.error, alpha)
                : aida::ui::with_alpha(th.success, alpha);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(c), "%s", s_state.last_action.c_str());
        }
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(left_w + 8.f, 0.f));
    ImGui::BeginChild("##rv_right", ImVec2(right_w, height), false);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Generated reports:");
    ImGui::SameLine();
    if (aida::ui::button("Clear history", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("report_v", "clear_history");
        ::aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.report_view";
        submission.label = "report.clear_history";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::diagnostics;
        submission.priority = 3;
        submission.body = []() { report::clear_history(); };
        static_cast<void>(::aida::infra::executor::submit(std::move(submission)));
    }
    ImGui::Separator();
    auto reports = report::list_reports();
    if (reports.empty()) {
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::layers;
        cfg.title = "No reports yet";
        cfg.body  = "Use the left panel to configure and generate a report.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImVec2(right_w, height - 60.f), cfg);
    } else {
        for (size_t i = 0; i < reports.size(); ++i) {
            const auto& r = reports[i];
            char buf[1024];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%llu] %s (%s) - %zu issues - %s",
                static_cast<unsigned long long>(r.id),
                r.title.empty() ? "(untitled)" : r.title.c_str(),
                report::format_label(r.format),
                r.issue_count,
                r.output_path.c_str());
            bool sel = (s_state.selected_history == static_cast<int>(i));
            if (ImGui::Selectable(buf, sel)) {
                ::diag::log_tagged_fmt("report_v", "history_selected id=%llu path='%s'",
                    static_cast<unsigned long long>(r.id), r.output_path.c_str());
                s_state.selected_history = static_cast<int>(i);
            }
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();
}

}
}
}
