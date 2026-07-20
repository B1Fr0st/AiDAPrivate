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

#include "session_handler_view.hpp"
#include "session_handler.hpp"
#include "../human_request_editor.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/components.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_executor.hpp"
#else
#include "../../infra/executor.hpp"
#endif
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "../../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace aida {
namespace burp {
namespace session_handler_view {

namespace {

struct view_state_t
{
    std::atomic<bool> initialized{false};
    std::atomic<bool> initialization_requested{false};
    std::atomic<std::uint64_t> created_macro_id{0};
    std::atomic<std::uint64_t> created_rule_id{0};

    char         new_macro_name[128] = {};
    char         new_step_label[128] = {};
    char         new_step_host[256] = {};
    char         new_step_scheme[16] = "https";
    int          new_step_port = 443;
    char         new_step_request[8192] = {};
    int          new_step_timeout_ms = 15000;
    char         new_extract_name[64] = {};
    char         new_extract_regex[512] = {};
    int          new_extract_from = 0;
    int          new_extract_group = 1;

    uint64_t     selected_macro_id = 0;
    char         edit_macro_name[128] = {};
    int          edit_step_index = -1;

    uint64_t     selected_rule_id = 0;
    char         new_rule_name[128] = {};
    int          new_rule_match = 0;
    char         new_rule_pattern[512] = {};
    int          new_rule_status = 200;
    uint64_t     new_rule_macro_id = 0;
    bool         new_rule_repl_url = true;
    bool         new_rule_repl_headers = true;
    bool         new_rule_repl_body = true;

    std::mutex                          run_mtx;
    std::map<std::string, std::string>  last_run_values;
    bool                                last_run_ok = false;
    uint64_t                            last_run_macro_id = 0;
};

view_state_t& s()
{
    static view_state_t st;
    return st;
}

const char* extract_from_combo[] = { "resp_body", "resp_headers", "resp_url" };
const char* match_combo[]        = { "url_regex", "response_status", "response_regex" };

void queue_macro_update(session_handler::macro_t macro)
{
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "burp.session_handler_view";
    submission.label = "session_handler.update_macro";
    submission.thread_class = "bounded_task";
    submission.domain = aida::infra::executor::domain_t::external_tool;
    submission.priority = 3;
    submission.body = [macro = std::move(macro)]() mutable {
        session_handler::update_macro(std::move(macro));
    };
    static_cast<void>(aida::infra::executor::submit(std::move(submission)));
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    if (!st.initialized.load(std::memory_order_acquire) &&
        !st.initialization_requested.exchange(true, std::memory_order_acq_rel)) {
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.session_handler_view";
        submission.label = "session_handler.initialize";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 3;
        submission.body = []() {
            session_handler::initialize();
            s().initialized.store(true, std::memory_order_release);
            s().initialization_requested.store(false, std::memory_order_release);
        };
        if (!aida::infra::executor::submit(std::move(submission)).submitted)
            st.initialization_requested.store(false, std::memory_order_release);
    }
    const std::uint64_t created_macro = st.created_macro_id.exchange(0, std::memory_order_acq_rel);
    if (created_macro != 0) st.selected_macro_id = created_macro;
    const std::uint64_t created_rule = st.created_rule_id.exchange(0, std::memory_order_acq_rel);
    if (created_rule != 0) st.selected_rule_id = created_rule;

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_sh_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Session handler / Macros");

    const float top_y = 36.f;
    const float left_w = width * 0.42f;
    const float right_x = left_w + 8.f;
    const float right_w = width - right_x - 8.f;

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y));
    ImGui::BeginChild("##sh_left", ImVec2(left_w, height - top_y - 8.f), false, ImGuiWindowFlags_NoBackground);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Macros");

    auto macros = session_handler::list_macros();
    for (const auto& m : macros) {
        ImGui::PushID(static_cast<int>(m.id & 0x7FFFFFFF));
        const bool selected = (st.selected_macro_id == m.id);
        ImU32 bg = selected ? aida::ui::with_alpha(th.selection, alpha) : aida::ui::with_alpha(th.panel_header, alpha * 0.5f);
        const ImVec2 cur = ImGui::GetCursorScreenPos();
        const float row_w = left_w - 4.f;
        const float row_h = 30.f;
        dl->AddRectFilled(cur, ImVec2(cur.x + row_w, cur.y + row_h), bg, 4.f);
        ImGui::InvisibleButton("##sh_macro_row", ImVec2(row_w, row_h));
        if (ImGui::IsItemClicked()) {
            ::diag::log_tagged_fmt("session_v", "macro_selected id=%llu name='%s' steps=%zu",
                static_cast<unsigned long long>(m.id), m.name.c_str(), m.steps.size());
            st.selected_macro_id = m.id;
            std::strncpy(st.edit_macro_name, m.name.c_str(), sizeof(st.edit_macro_name) - 1);
            st.edit_macro_name[sizeof(st.edit_macro_name) - 1] = '\0';
            st.edit_step_index = -1;
        }
        char hdr[256];
        std::snprintf(hdr, sizeof(hdr), "%s  (id=%llu, %zu steps)", m.name.empty() ? "(unnamed)" : m.name.c_str(),
            static_cast<unsigned long long>(m.id), m.steps.size());
        dl->AddText(ImVec2(cur.x + 8.f, cur.y + 4.f),
                    aida::ui::with_alpha(th.text_primary, alpha), hdr);
        char tail[256];
        std::snprintf(tail, sizeof(tail), "last_run_ms=%llu  last_ok=%s",
            static_cast<unsigned long long>(m.last_run_ms), m.ok_last_run ? "yes" : "no");
        dl->AddText(ImVec2(cur.x + 8.f, cur.y + 16.f),
                    aida::ui::with_alpha(th.text_dim, alpha), tail);
        ImGui::PopID();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "New macro");
    ImGui::InputText("Name##sh_new_macro_name", st.new_macro_name, sizeof(st.new_macro_name));
    if (aida::ui::button("Create macro", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        session_handler::macro_t m;
        m.name = st.new_macro_name;
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.session_handler_view";
        submission.label = "session_handler.add_macro";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 3;
        submission.body = [m = std::move(m)]() mutable {
            const std::uint64_t id = session_handler::add_macro(std::move(m));
            if (id != 0) s().created_macro_id.store(id, std::memory_order_release);
        };
        static_cast<void>(aida::infra::executor::submit(std::move(submission)));
        st.new_macro_name[0] = '\0';
        std::strncpy(st.edit_macro_name, "", sizeof(st.edit_macro_name) - 1);
    }
    ImGui::SameLine();
    if (st.selected_macro_id != 0 &&
        aida::ui::button("Delete macro", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        ::diag::log_tagged_fmt("session_v", "macro_deleted id=%llu", static_cast<unsigned long long>(st.selected_macro_id));
        const std::uint64_t id = st.selected_macro_id;
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.session_handler_view";
        submission.label = "session_handler.remove_macro";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 3;
        submission.body = [id]() { session_handler::remove_macro(id); };
        static_cast<void>(aida::infra::executor::submit(std::move(submission)));
        st.selected_macro_id = 0;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Session rules");
    auto rules = session_handler::list_rules();
    for (const auto& r : rules) {
        ImGui::PushID(static_cast<int>(r.id & 0x7FFFFFFF));
        const bool selected = (st.selected_rule_id == r.id);
        const ImVec2 cur = ImGui::GetCursorScreenPos();
        const float row_w = left_w - 4.f;
        const float row_h = 26.f;
        ImU32 bg = selected ? aida::ui::with_alpha(th.selection, alpha) : aida::ui::with_alpha(th.panel_header, alpha * 0.4f);
        dl->AddRectFilled(cur, ImVec2(cur.x + row_w, cur.y + row_h), bg, 4.f);
        ImGui::InvisibleButton("##sh_rule_row", ImVec2(row_w, row_h));
        if (ImGui::IsItemClicked()) st.selected_rule_id = r.id;
        char buf[256];
        std::snprintf(buf, sizeof(buf), "%s  [%s]  -> macro #%llu  %s",
            r.name.c_str(),
            session_handler::match_label(r.match),
            static_cast<unsigned long long>(r.macro_id),
            r.active ? "on" : "off");
        dl->AddText(ImVec2(cur.x + 8.f, cur.y + 6.f),
                    aida::ui::with_alpha(th.text_primary, alpha), buf);
        ImGui::PopID();
    }

    ImGui::Spacing();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "New rule");
    ImGui::InputText("Name##sh_new_rule_name", st.new_rule_name, sizeof(st.new_rule_name));
    ImGui::Combo("Match##sh_new_rule_match", &st.new_rule_match, match_combo, 3);
    ImGui::InputText("Pattern##sh_new_rule_pattern", st.new_rule_pattern, sizeof(st.new_rule_pattern));
    if (st.new_rule_match == 1) ImGui::InputInt("HTTP status##sh_new_rule_status", &st.new_rule_status);
    ImGui::InputScalar("Macro id##sh_new_rule_macro_id", ImGuiDataType_U64, &st.new_rule_macro_id);
    ImGui::Checkbox("URL##sh_new_rule_repl_url", &st.new_rule_repl_url);
    ImGui::SameLine();
    ImGui::Checkbox("Headers##sh_new_rule_repl_headers", &st.new_rule_repl_headers);
    ImGui::SameLine();
    ImGui::Checkbox("Body##sh_new_rule_repl_body", &st.new_rule_repl_body);
    if (aida::ui::button("Add rule", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        session_handler::session_rule_t r;
        r.name = st.new_rule_name;
        r.match = static_cast<session_handler::sh_match_t>(st.new_rule_match);
        r.match_pattern = st.new_rule_pattern;
        r.match_status = st.new_rule_status;
        r.macro_id = st.new_rule_macro_id;
        r.replace_in_url = st.new_rule_repl_url;
        r.replace_in_headers = st.new_rule_repl_headers;
        r.replace_in_body = st.new_rule_repl_body;
        r.active = true;
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.session_handler_view";
        submission.label = "session_handler.add_rule";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 3;
        submission.body = [r = std::move(r)]() mutable {
            const std::uint64_t id = session_handler::add_rule(std::move(r));
            if (id != 0) s().created_rule_id.store(id, std::memory_order_release);
        };
        static_cast<void>(aida::infra::executor::submit(std::move(submission)));
        ::diag::log_tagged_fmt("session_v", "rule_added name='%s' match=%d macro_id=%llu",
            r.name.c_str(), st.new_rule_match, static_cast<unsigned long long>(r.macro_id));
        st.new_rule_name[0] = '\0';
        st.new_rule_pattern[0] = '\0';
    }
    ImGui::SameLine();
    if (st.selected_rule_id != 0 &&
        aida::ui::button("Delete rule", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
        ::diag::log_tagged_fmt("session_v", "rule_deleted id=%llu", static_cast<unsigned long long>(st.selected_rule_id));
        const std::uint64_t id = st.selected_rule_id;
        aida::infra::executor::submission_t submission;
        submission.owner_subsystem = "burp.session_handler_view";
        submission.label = "session_handler.remove_rule";
        submission.thread_class = "bounded_task";
        submission.domain = aida::infra::executor::domain_t::external_tool;
        submission.priority = 3;
        submission.body = [id]() { session_handler::remove_rule(id); };
        static_cast<void>(aida::infra::executor::submit(std::move(submission)));
        st.selected_rule_id = 0;
    }

    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + right_x, pos_y + top_y));
    ImGui::BeginChild("##sh_right", ImVec2(right_w, height - top_y - 8.f), false, ImGuiWindowFlags_NoBackground);

    if (st.selected_macro_id == 0) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Select a macro on the left to edit, or create a new one.");
    } else {
        session_handler::macro_t cur;
        if (!session_handler::get_macro(st.selected_macro_id, cur)) {
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
                "Macro not found.");
            ImGui::EndChild();
            ImGui::EndChild();
            return;
        }
        ImGui::InputText("Macro name##sh_edit_name", st.edit_macro_name, sizeof(st.edit_macro_name));
        if (aida::ui::button("Rename", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            ::diag::log_tagged_fmt("session_v", "macro_rename id=%llu new_name='%s'",
                static_cast<unsigned long long>(cur.id), st.edit_macro_name);
            cur.name = st.edit_macro_name;
            queue_macro_update(cur);
        }
        ImGui::SameLine();
        if (aida::ui::button("Run macro now", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            const uint64_t mid = cur.id;
            ::diag::log_tagged_fmt("session_v", "macro_run id=%llu name='%s'",
                static_cast<unsigned long long>(mid), cur.name.c_str());
            {
                ::aida::infra::executor::submission_t sub;
                sub.owner_subsystem = "burp.session_view";
                sub.label = "session.macro_run";
                sub.thread_class = "bounded_task";
                sub.domain = aida::infra::executor::domain_t::external_tool;
                sub.priority = 3;
                sub.body = [mid]() {
                std::map<std::string, std::string> values;
                const bool ok = session_handler::run_macro(mid, values);
                ::diag::log_tagged_fmt("session_v", "macro_run_result id=%llu ok=%d extracted=%zu",
                    static_cast<unsigned long long>(mid), ok ? 1 : 0, values.size());
                auto& vs = s();
                std::lock_guard<std::mutex> lk(vs.run_mtx);
                vs.last_run_values = std::move(values);
                vs.last_run_ok = ok;
                vs.last_run_macro_id = mid;
            };
                (void)::aida::infra::executor::submit(std::move(sub));
            }
        }

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Steps");
        for (size_t i = 0; i < cur.steps.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            const ImVec2 cv = ImGui::GetCursorScreenPos();
            const float row_w = right_w - 4.f;
            const float row_h = 28.f;
            const bool sel = (st.edit_step_index == static_cast<int>(i));
            dl->AddRectFilled(cv, ImVec2(cv.x + row_w, cv.y + row_h),
                              sel ? aida::ui::with_alpha(th.selection, alpha)
                                  : aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 4.f);
            ImGui::InvisibleButton("##sh_step", ImVec2(row_w, row_h));
            if (ImGui::IsItemClicked()) st.edit_step_index = static_cast<int>(i);
            char b[300];
            std::snprintf(b, sizeof(b), "%zu. %s  %s://%s:%u  (%zu extracts)", i + 1,
                cur.steps[i].label.empty() ? "(unlabeled)" : cur.steps[i].label.c_str(),
                cur.steps[i].scheme.c_str(), cur.steps[i].host.c_str(),
                static_cast<unsigned>(cur.steps[i].port), cur.steps[i].extracts.size());
            dl->AddText(ImVec2(cv.x + 8.f, cv.y + 4.f),
                        aida::ui::with_alpha(th.text_primary, alpha), b);
            ImGui::PopID();
        }

        if (st.edit_step_index >= 0 && st.edit_step_index < static_cast<int>(cur.steps.size())) {
            const int idx = st.edit_step_index;
            ImGui::SameLine();
            if (aida::ui::button("Delete step", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
                ::diag::log_tagged_fmt("session_v", "step_deleted macro_id=%llu step_idx=%d",
                    static_cast<unsigned long long>(cur.id), idx);
                const auto step_offset = static_cast<decltype(cur.steps)::difference_type>(idx);
                cur.steps.erase(cur.steps.begin() + step_offset);
                queue_macro_update(cur);
                st.edit_step_index = -1;
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Add step");
        ImGui::InputText("Label##sh_new_step_label", st.new_step_label, sizeof(st.new_step_label));
        ImGui::InputText("Host##sh_new_step_host", st.new_step_host, sizeof(st.new_step_host));
        ImGui::InputText("Scheme##sh_new_step_scheme", st.new_step_scheme, sizeof(st.new_step_scheme));
        ImGui::SameLine();
        ImGui::InputInt("Port##sh_new_step_port", &st.new_step_port);
        ImGui::InputInt("Timeout(ms)##sh_new_step_timeout", &st.new_step_timeout_ms);
        static network_view::human_request_editor::fixed_state_t request_editor;
        network_view::human_request_editor::render_config_t request_config;
        request_config.stable_id = "session-handler-new-step";
        request_config.size = ImVec2(right_w - 4.f, 112.f);
        request_config.max_bytes = sizeof(st.new_step_request) - 1;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        request_config.semantic_parent_id = "aida.dock-window.view.network.session";
#endif
        const auto request_editor_result = network_view::human_request_editor::render_fixed(
            request_editor,
            "session-handler.new-step." + std::to_string(cur.id),
            st.new_step_request, request_config);

        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)), "Extractor (optional)");
        ImGui::InputText("Name##sh_new_ext_name", st.new_extract_name, sizeof(st.new_extract_name));
        ImGui::Combo("From##sh_new_ext_from", &st.new_extract_from, extract_from_combo, 3);
        ImGui::InputText("Regex##sh_new_ext_regex", st.new_extract_regex, sizeof(st.new_extract_regex));
        ImGui::InputInt("Group##sh_new_ext_group", &st.new_extract_group);

        const bool add_step_disabled = !request_editor_result.valid ||
            request_editor_result.has_unapplied_pretty;
        if (aida::ui::button("Add step", aida::ui::button_kind_t::primary,
                aida::ui::size_t_::sm, ImVec2(0.f, 0.f), add_step_disabled)) {
            session_handler::macro_step_t step;
            step.label = st.new_step_label;
            step.host = st.new_step_host;
            step.scheme = st.new_step_scheme;
            step.port = static_cast<uint16_t>(st.new_step_port);
            const std::string r(st.new_step_request);
            step.raw_request.assign(r.begin(), r.end());
            step.timeout_ms = st.new_step_timeout_ms;
            ::diag::log_tagged_fmt("session_v", "step_adding macro_id=%llu label='%s' host='%s' port=%d",
                static_cast<unsigned long long>(cur.id), step.label.c_str(), step.host.c_str(), step.port);
            if (st.new_extract_name[0] != '\0' && st.new_extract_regex[0] != '\0') {
                session_handler::extract_t e;
                e.name = st.new_extract_name;
                e.regex = st.new_extract_regex;
                e.from = extract_from_combo[st.new_extract_from];
                e.group = st.new_extract_group;
                step.extracts.push_back(e);
            }
            cur.steps.push_back(step);
            queue_macro_update(cur);
            st.new_step_label[0] = '\0';
            st.new_step_host[0] = '\0';
            st.new_step_request[0] = '\0';
            st.new_extract_name[0] = '\0';
            st.new_extract_regex[0] = '\0';
        }

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, alpha)), "Last extracted values");
        std::map<std::string, std::string> values;
        bool ok = false;
        {
            std::lock_guard<std::mutex> lk(st.run_mtx);
            if (st.last_run_macro_id == cur.id) {
                values = st.last_run_values;
                ok = st.last_run_ok;
            }
        }
        if (values.empty()) {
            const auto persisted = cur.last_extracted_values;
            values = persisted;
            ok = cur.ok_last_run;
        }
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            ok ? "ok=yes" : "ok=no");
        for (const auto& kv : values) {
            char line[1024];
            std::snprintf(line, sizeof(line), "%s = %s", kv.first.c_str(),
                kv.second.size() > 200 ? (kv.second.substr(0, 200) + "...").c_str() : kv.second.c_str());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_primary, alpha)), "%s", line);
        }
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
