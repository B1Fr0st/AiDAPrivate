#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#ifdef small
#undef small
#endif

#include "intruder_view.hpp"
#include "intruder_engine.hpp"
#include "payload_library.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/components.hpp"
#include "../../ui/ui_anim.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace intruder_view {

namespace {

struct ui_state_t
{
    std::mutex                              mtx;
    uint64_t                                selected_job_id = 0;
    int                                     selected_result_index = -1;
    bool                                    show_new_attack = false;

    char                                    new_host[256] = "example.com";
    int                                     new_port = 443;
    bool                                    new_tls = true;
    int                                     new_attack_mode = 0;
    int                                     new_engine_mode = 2;
    int                                     new_concurrency = 32;
    int                                     new_rps_cap = 0;
    int                                     new_total_cap = 0;
    int                                     new_timeout_ms = 15000;
    int                                     new_race_gate = 30;
    int                                     new_race_warmup = 0;
    char                                    new_request[65536]
        = "GET / HTTP/1.1\r\n"
          "Host: example.com\r\n"
          "User-Agent: AiDA-Intruder/1.0\r\n"
          "Accept: */*\r\n"
          "Connection: close\r\n"
          "\r\n";
    char                                    new_payload_set[8192] = "test1\ntest2\ntest3\n";
    std::vector<std::pair<size_t, size_t>>  new_positions;
};

ui_state_t& ui() { static ui_state_t s; return s; }

static std::vector<std::string> split_lines(const std::string& v)
{
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= v.size(); ++i) {
        if (i == v.size() || v[i] == '\n') {
            if (i > start) {
                std::string line = v.substr(start, i - start);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty()) out.push_back(line);
            }
            start = i + 1;
        }
    }
    return out;
}

static void detect_positions_from_markers(const std::string& tmpl, std::vector<std::pair<size_t, size_t>>& positions, std::string& clean_out)
{
    positions.clear();
    clean_out.clear();
    clean_out.reserve(tmpl.size());
    size_t i = 0;
    while (i < tmpl.size()) {
        if (tmpl[i] == '$') {
            size_t end = tmpl.find('$', i + 1);
            if (end != std::string::npos) {
                size_t pos_in_clean = clean_out.size();
                positions.push_back({ pos_in_clean, 0 });
                i = end + 1;
                continue;
            }
        }
        clean_out.push_back(tmpl[i]);
        ++i;
    }
}

static ImU32 status_code_color(int code)
{
    const auto& t = aida::ui::resolved();
    if (code >= 200 && code < 300) return t.success;
    if (code >= 300 && code < 400) return t.info;
    if (code >= 400 && code < 500) return t.warning;
    if (code >= 500)               return t.error;
    return t.text_dim;
}

}

void initialize()
{
}

void shutdown()
{
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = ui();

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_intruder_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)),
                       "Intruder / Turbo");
    ImGui::SameLine();
    if (aida::ui::button("New Attack", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        std::lock_guard<std::mutex> lk(st.mtx);
        st.show_new_attack = true;
    }
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                       "Mark positions in the request with $value$");

    ImGui::Spacing();

    float left_w = width * 0.32f;
    if (left_w < 260.f) left_w = 260.f;
    if (left_w > 460.f) left_w = 460.f;
    float gap = 8.f;
    float right_w = width - left_w - gap;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(th.panel_bg, 0.6f * alpha));
    ImGui::BeginChild("##burp_intruder_jobs", ImVec2(left_w, height - 36.f), true, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                       "Jobs");
    ImGui::Separator();

    auto jobs = intruder::list_jobs();
    uint64_t selected;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        selected = st.selected_job_id;
    }

    for (auto& j : jobs) {
        ImGui::PushID(static_cast<int>(j.job_id));
        char buf[256];
        snprintf(buf, sizeof(buf), "Job %llu  %s%zu/%zu  %.0f rps%s",
                 static_cast<unsigned long long>(j.job_id),
                 j.running ? "[RUN] " : "[DONE] ",
                 j.sent, j.total, j.current_rps,
                 j.errors > 0 ? "  [ERR]" : "");
        bool is_sel = (j.job_id == selected);
        if (is_sel) {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 cp = ImGui::GetCursorScreenPos();
            dl->AddRectFilled(cp,
                              ImVec2(cp.x + left_w - 24.f, cp.y + 22.f),
                              aida::ui::with_alpha(th.selection, alpha));
        }
        if (ImGui::Selectable(buf, is_sel)) {
            std::lock_guard<std::mutex> lk(st.mtx);
            st.selected_job_id = j.job_id;
            st.selected_result_index = -1;
        }
        ImGui::SameLine();
        if (j.running) {
            if (aida::ui::button("Stop", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
                intruder::stop(j.job_id);
            }
        } else {
            if (aida::ui::button("Clear", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
                intruder::clear(j.job_id);
                {
                    std::lock_guard<std::mutex> lk(st.mtx);
                    if (st.selected_job_id == j.job_id) st.selected_job_id = 0;
                }
            }
        }
        ImGui::PopID();
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0.f, gap);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, aida::ui::with_alpha(th.panel_bg, 0.45f * alpha));
    ImGui::BeginChild("##burp_intruder_results", ImVec2(right_w, height - 36.f), true, ImGuiWindowFlags_NoBackground);

    if (selected == 0) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Select a job, or start a New Attack");
    } else {
        intruder::status_t s_info = intruder::status(selected);
        char hdr[512];
        snprintf(hdr, sizeof(hdr),
                 "Job %llu  sent=%zu/%zu  errors=%zu  rps=%.1f  %s",
                 static_cast<unsigned long long>(s_info.job_id),
                 s_info.sent, s_info.total, s_info.errors, s_info.current_rps,
                 s_info.running ? "RUNNING" : "FINISHED");
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                           "%s", hdr);
        ImGui::Separator();

        auto rows = intruder::results(selected, 0, 1024);

        ImGui::BeginChild("##burp_intruder_grid", ImVec2(right_w - 18.f, (height - 100.f) * 0.6f), false, ImGuiWindowFlags_HorizontalScrollbar);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 org = ImGui::GetWindowPos();
        float row_h = 22.f;
        const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
        float cx0 = org.x + 6.f;
        float c_idx = 50.f;
        float c_pay = 220.f;
        float c_st = 60.f;
        float c_len = 80.f;
        float c_lat = 80.f;
        float c_err = 220.f;
        float head_y = org.y + ImGui::GetCursorPosY();
        dl->AddRectFilled(ImVec2(org.x, head_y - 2.f),
                          ImVec2(org.x + ImGui::GetWindowWidth(), head_y + row_h - 2.f),
                          aida::ui::with_alpha(th.panel_header, alpha));
        ImU32 hcol = aida::ui::with_alpha(th.text_secondary, alpha);
        float hdr_ty = head_y - 2.f + text_oy;
        dl->AddText(ImVec2(cx0,                              hdr_ty), hcol, "#");
        dl->AddText(ImVec2(cx0 + c_idx,                      hdr_ty), hcol, "Payload");
        dl->AddText(ImVec2(cx0 + c_idx + c_pay,              hdr_ty), hcol, "Status");
        dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st,       hdr_ty), hcol, "Length");
        dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st + c_len, hdr_ty), hcol, "Latency");
        dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st + c_len + c_lat, hdr_ty), hcol, "Error");
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + row_h + 4.f);

        int sel_row;
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            sel_row = st.selected_result_index;
        }

        for (auto& r : rows) {
            float ry = ImGui::GetCursorPosY();
            float abs_ry = ImGui::GetCursorScreenPos().y;
            bool is_sel = (static_cast<int>(r.index) == sel_row);
            if (r.error) {
                dl->AddRectFilled(ImVec2(org.x, abs_ry),
                                  ImVec2(org.x + ImGui::GetWindowWidth(), abs_ry + row_h),
                                  aida::ui::with_alpha(th.error_soft, alpha * 0.8f));
            } else if (is_sel) {
                dl->AddRectFilled(ImVec2(org.x, abs_ry),
                                  ImVec2(org.x + ImGui::GetWindowWidth(), abs_ry + row_h),
                                  aida::ui::with_alpha(th.selection, alpha));
            }
            ImVec2 mouse = ImGui::GetMousePos();
            if (mouse.x >= org.x && mouse.x < org.x + ImGui::GetWindowWidth()
                && mouse.y >= abs_ry && mouse.y < abs_ry + row_h && ImGui::IsMouseClicked(0)) {
                std::lock_guard<std::mutex> lk(st.mtx);
                st.selected_result_index = static_cast<int>(r.index);
            }
            ImU32 txt = aida::ui::with_alpha(is_sel ? th.text_primary : th.text_secondary, alpha);
            char buf[64];
            snprintf(buf, sizeof(buf), "%zu", r.index);
            dl->AddText(ImVec2(cx0, abs_ry + text_oy), txt, buf);

            std::string pay;
            for (size_t i = 0; i < r.payloads.size(); ++i) {
                if (i > 0) pay += ",";
                if (r.payloads[i].size() > 32) pay += r.payloads[i].substr(0, 30) + "..";
                else                            pay += r.payloads[i];
            }
            dl->AddText(ImVec2(cx0 + c_idx, abs_ry + text_oy), txt, pay.c_str());

            snprintf(buf, sizeof(buf), "%d", r.status_code);
            dl->AddText(ImVec2(cx0 + c_idx + c_pay, abs_ry + text_oy),
                         aida::ui::with_alpha(status_code_color(r.status_code), alpha), buf);

            snprintf(buf, sizeof(buf), "%zu", r.response_size);
            dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st, abs_ry + text_oy), txt, buf);

            snprintf(buf, sizeof(buf), "%llums", static_cast<unsigned long long>(r.latency_ms));
            dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st + c_len, abs_ry + text_oy), txt, buf);

            if (r.error && !r.error_msg.empty()) {
                dl->AddText(ImVec2(cx0 + c_idx + c_pay + c_st + c_len + c_lat, abs_ry + text_oy),
                             aida::ui::with_alpha(th.error, alpha), r.error_msg.c_str());
            }
            ImGui::SetCursorPosY(ry + row_h);
        }
        ImGui::EndChild();

        ImGui::Separator();

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Detail");

        int detail_idx;
        {
            std::lock_guard<std::mutex> lk(st.mtx);
            detail_idx = st.selected_result_index;
        }
        const intruder::result_t* detail = nullptr;
        for (auto& r : rows) if (static_cast<int>(r.index) == detail_idx) { detail = &r; break; }
        if (!detail) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                               "(select a row to view the response)");
        } else {
            char info[512];
            std::string pay_join;
            for (auto& p : detail->payloads) { if (!pay_join.empty()) pay_join += ","; pay_join += p; }
            snprintf(info, sizeof(info), "idx=%zu status=%d len=%zu lat=%llums payload=%s%s",
                     detail->index, detail->status_code, detail->response_size,
                     static_cast<unsigned long long>(detail->latency_ms),
                     pay_join.c_str(),
                     detail->error ? "  [ERR]" : "");
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)),
                               "%s", info);
            ImGui::TextWrapped("%.*s",
                static_cast<int>(detail->response_preview.size()),
                detail->response_preview.c_str());
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();

    bool need_open = false;
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        need_open = st.show_new_attack;
    }
    if (need_open) {
        ImGui::OpenPopup("Intruder - New Attack");
        std::lock_guard<std::mutex> lk(st.mtx);
        st.show_new_attack = false;
    }
    ImVec2 center = ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(800.f, 620.f), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Intruder - New Attack", nullptr, ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Host:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(280.f);
        ImGui::InputText("##na_host", st.new_host, sizeof(st.new_host));
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
                           "Port:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80.f);
        ImGui::InputInt("##na_port", &st.new_port);
        ImGui::SameLine();
        ImGui::Checkbox("TLS##na_tls", &st.new_tls);

        const char* attack_modes[] = { "sniper", "battering_ram", "pitchfork", "clusterbomb", "turbo", "race" };
        const char* engine_modes[] = { "http1_serial", "http1_pipelined", "http1_pooled", "http2_multiplexed", "http2_single_packet" };
        ImGui::Combo("Attack mode##na_am", &st.new_attack_mode, attack_modes, 6);
        ImGui::Combo("Engine mode##na_em", &st.new_engine_mode, engine_modes, 5);
        ImGui::InputInt("Concurrency##na_c", &st.new_concurrency);
        ImGui::InputInt("Throttle RPS (0=unbounded)##na_r", &st.new_rps_cap);
        ImGui::InputInt("Total cap (0=all)##na_t", &st.new_total_cap);
        ImGui::InputInt("Timeout ms##na_to", &st.new_timeout_ms);
        if (st.new_attack_mode == 5) {
            ImGui::InputInt("Race gate size##na_rg", &st.new_race_gate);
            ImGui::InputInt("Race warmup##na_rw", &st.new_race_warmup);
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Request template (mark positions with $...$):");
        ImGui::InputTextMultiline("##na_req", st.new_request, sizeof(st.new_request),
                                  ImVec2(770.f, 180.f));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                           "Payload set (one per line):");
        ImGui::InputTextMultiline("##na_ps", st.new_payload_set, sizeof(st.new_payload_set),
                                  ImVec2(770.f, 140.f));

        if (aida::ui::button("Launch", aida::ui::button_kind_t::primary, aida::ui::size_t_::md)) {
            intruder::config_t cfg;
            cfg.host = st.new_host;
            cfg.port = static_cast<uint16_t>(st.new_port);
            cfg.scheme = st.new_tls ? "https" : "http";
            cfg.attack_mode = static_cast<intruder::attack_mode_t>(st.new_attack_mode);
            cfg.engine_mode = static_cast<intruder::engine_mode_t>(st.new_engine_mode);
            cfg.concurrency = static_cast<size_t>(std::max(1, st.new_concurrency));
            cfg.requests_per_second_cap = static_cast<size_t>(std::max(0, st.new_rps_cap));
            cfg.total_requests_cap = static_cast<size_t>(std::max(0, st.new_total_cap));
            cfg.timeout_ms = std::max(500, st.new_timeout_ms);
            cfg.race_gate_size = static_cast<size_t>(std::max(1, st.new_race_gate));
            cfg.race_warmup_count = std::max(0, st.new_race_warmup);

            std::string tmpl(st.new_request);
            std::string clean;
            std::vector<std::pair<size_t, size_t>> positions;
            detect_positions_from_markers(tmpl, positions, clean);
            cfg.base_request.assign(clean.begin(), clean.end());
            cfg.positions = std::move(positions);
            if (cfg.positions.empty()) cfg.positions.push_back({ cfg.base_request.size(), 0 });

            std::string payload_text(st.new_payload_set);
            std::vector<std::string> payloads = split_lines(payload_text);
            cfg.payload_sets.push_back(std::move(payloads));

            uint64_t id = intruder::start(std::move(cfg));
            if (id != 0) {
                std::lock_guard<std::mutex> lk(st.mtx);
                st.selected_job_id = id;
                st.selected_result_index = -1;
                diag::log_tagged_fmt("burp", "intruder_start_job id=%llu host=%s port=%d tls=%d",
                                     static_cast<unsigned long long>(id),
                                     cfg.host.c_str(), cfg.port, st.new_tls ? 1 : 0);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (aida::ui::button("Cancel", aida::ui::button_kind_t::ghost, aida::ui::size_t_::md)) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::EndChild();
}

}
}
}
