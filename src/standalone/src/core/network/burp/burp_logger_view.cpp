#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_logger_view.hpp"
#include "burp_logger.hpp"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/empty_state.hpp"
#include "../../ui/fonts.hpp"
#include "../../infra/executor.hpp"
#include "helpers/diag_log.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace logger_view {

namespace {

state_t s_state;

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
    ImGui::BeginChild("##bl_root", ImVec2(width, height), false);

    ImGui::SetCursorPos(ImVec2(8.f, 6.f));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Filters:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70.f);
    aida::ui::input_text("##bl_meth", s_state.method_filter_buf, sizeof(s_state.method_filter_buf), "method", false, ImVec2(80.f, 26.f));
    ImGui::SameLine();
    aida::ui::input_text("##bl_host", s_state.host_regex_buf, sizeof(s_state.host_regex_buf), "host regex", false, ImVec2(220.f, 26.f));
    ImGui::SameLine();
    aida::ui::input_text("##bl_url", s_state.url_regex_buf, sizeof(s_state.url_regex_buf), "url regex", false, ImVec2(300.f, 26.f));

    ImGui::SetCursorPos(ImVec2(8.f, 38.f));
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("##bl_smin", &s_state.status_min, 0, 0);
    ImGui::SameLine(); ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)), "<= status <=");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.f);
    ImGui::InputInt("##bl_smax", &s_state.status_max, 0, 0);
    ImGui::SameLine();
    aida::ui::input_text("##bl_src", s_state.source_buf, sizeof(s_state.source_buf), "source", false, ImVec2(120.f, 26.f));
    ImGui::SameLine();
    aida::ui::input_text("##bl_mime", s_state.mime_buf, sizeof(s_state.mime_buf), "mime", false, ImVec2(160.f, 26.f));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90.f);
    ImGui::InputInt("##bl_lim", &s_state.row_limit, 0, 0);
    if (s_state.row_limit < 1) s_state.row_limit = 1;
    if (s_state.row_limit > 100000) s_state.row_limit = 100000;
    ImGui::SameLine();
    if (aida::ui::button("Clear", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        ::diag::log_tagged("logger_v", "clear_log");
        logger::clear();
    }

    ImGui::SetCursorPos(ImVec2(8.f, 70.f));
    aida::ui::input_text("##bl_path", s_state.export_path_buf, sizeof(s_state.export_path_buf),
                         "Export CSV path...", false, ImVec2(420.f, 26.f));
    ImGui::SameLine();
    if (aida::ui::button("Export CSV", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
        std::string path(s_state.export_path_buf);
        logger::log_filter_t f;
        f.method     = s_state.method_filter_buf;
        f.host_regex = s_state.host_regex_buf;
        f.url_regex  = s_state.url_regex_buf;
        f.source     = s_state.source_buf;
        f.mime_type  = s_state.mime_buf;
        f.status_min = s_state.status_min;
        f.status_max = s_state.status_max;
        ::diag::log_tagged_fmt("logger_v", "export_csv path='%s' method='%s' host='%s' url='%s' status=%d-%d",
            path.c_str(), f.method.c_str(), f.host_regex.c_str(), f.url_regex.c_str(),
            f.status_min, f.status_max);
        {
            ::aida::infra::executor::submission_t sub;
            sub.owner_subsystem = "burp.logger_view";
            sub.label = "logger.export_csv";
            sub.thread_class = "bounded_task";
            sub.domain = aida::infra::executor::domain_t::diagnostics;
            sub.priority = 3;
            sub.body = [path, f]() {
            bool ok = logger::export_csv(path, f);
            ::diag::log_tagged_fmt("logger_v", "export_csv_result ok=%d path='%s'", ok ? 1 : 0, path.c_str());
            std::lock_guard<std::mutex> lk(s_state.lock);
            s_state.last_action_kind = ok ? "ok" : "error";
            s_state.last_action      = ok ? std::string("Exported ") + path : logger::last_error();
        };
            (void)::aida::infra::executor::submit(std::move(sub));
        }
    }
    ImGui::SameLine(0.f, 12.f);
    {
        std::lock_guard<std::mutex> lk(s_state.lock);
        if (!s_state.last_action.empty()) {
            ImU32 c = (s_state.last_action_kind == "error")
                ? aida::ui::with_alpha(th.error, alpha)
                : aida::ui::with_alpha(th.success, alpha);
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(c), "%s", s_state.last_action.c_str());
        } else {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "Total: %zu rows (cap %zu)",
                               logger::total_rows(), logger::capacity());
        }
    }

    float content_y = 104.f;
    float content_h = height - content_y - 8.f;

    logger::log_filter_t f;
    f.method     = s_state.method_filter_buf;
    f.host_regex = s_state.host_regex_buf;
    f.url_regex  = s_state.url_regex_buf;
    f.source     = s_state.source_buf;
    f.mime_type  = s_state.mime_buf;
    f.status_min = s_state.status_min;
    f.status_max = s_state.status_max;
    std::vector<logger::log_row_t> rows = logger::query(f, static_cast<size_t>(s_state.row_limit));

    ImGui::SetCursorPos(ImVec2(0.f, content_y));
    ImGui::BeginChild("##bl_table", ImVec2(width, content_h), false);
    if (rows.empty()) {
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::network;
        cfg.title = "No log rows";
        cfg.body  = "Traffic captured by the proxy or sent by repeater/scanner/API will appear here.";
        aida::ui::empty_state::render(ImGui::GetCursorScreenPos(), ImVec2(width, content_h), cfg);
    } else {
        ImFont* mono = aida::ui::fonts::code();
        if (mono) ImGui::PushFont(mono);
        if (ImGui::BeginTable("##bl_t", 8, ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 60.f);
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 140.f);
            ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 70.f);
            ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch, 0.f);
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 60.f);
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 90.f);
            ImGui::TableSetupColumn("Latency", ImGuiTableColumnFlags_WidthFixed, 90.f);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 90.f);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < rows.size(); ++i) {
                const auto& r = rows[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%llu", static_cast<unsigned long long>(r.id));
                ImGui::TableSetColumnIndex(1); ImGui::Text("%llu", static_cast<unsigned long long>(r.ts_ms));
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(r.method.c_str());
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(r.url.c_str());
                ImGui::TableSetColumnIndex(4); ImGui::Text("%d", r.status);
                ImGui::TableSetColumnIndex(5); ImGui::Text("%zu", r.response_length);
                ImGui::TableSetColumnIndex(6); ImGui::Text("%llu", static_cast<unsigned long long>(r.latency_ms));
                ImGui::TableSetColumnIndex(7); ImGui::TextUnformatted(logger::source_label(r.source));
            }
            ImGui::EndTable();
        }
        if (mono) ImGui::PopFont();
    }
    ImGui::EndChild();

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

}
}
}
