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

#include "match_replace_view.hpp"
#include "match_replace.hpp"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "../../ui/theme.hpp"
#include "../../ui/ui_anim.hpp"
#include "../../ui/components.hpp"
#ifdef AIDA_IMGUI_STUDIO_PREVIEW
#include "../../../preview/network_preview_services.hpp"
#else
#include "../../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <cstring>
#include <string>

namespace aida {
namespace burp {
namespace match_replace_view {

namespace {

struct view_state_t
{
    char        new_label[128] = {};
    char        new_match[2048] = {};
    char        new_replace[2048] = {};
    char        new_host_filter[256] = {};
    int         new_target = 0;
    int         new_scheme = 0;
    bool        new_regex = true;
    bool        new_ci = false;
    bool        new_active = true;
    uint64_t    selected_id = 0;
    char        edit_label[128] = {};
    char        edit_match[2048] = {};
    char        edit_replace[2048] = {};
    char        edit_host_filter[256] = {};
    int         edit_target = 0;
    int         edit_scheme = 0;
    bool        edit_regex = true;
    bool        edit_ci = false;
    bool        edit_active = true;
    bool        edit_dirty = false;
    bool        show_edit_popup = false;
    char        test_sample[4096] = {};
    std::string test_result;
    bool        initialized = false;
};

view_state_t& s()
{
    static view_state_t st;
    return st;
}

const char* target_combo[] = {
    "request_url",
    "request_headers",
    "request_body",
    "response_headers",
    "response_body",
    "all"
};

const char* scheme_combo[] = { "(any)", "http", "https" };

void load_into_edit(view_state_t& st, const match_replace::rule_t& r)
{
    st.selected_id = r.id;
    std::strncpy(st.edit_label, r.label.c_str(), sizeof(st.edit_label) - 1);
    st.edit_label[sizeof(st.edit_label) - 1] = '\0';
    std::strncpy(st.edit_match, r.match_regex.c_str(), sizeof(st.edit_match) - 1);
    st.edit_match[sizeof(st.edit_match) - 1] = '\0';
    std::strncpy(st.edit_replace, r.replacement.c_str(), sizeof(st.edit_replace) - 1);
    st.edit_replace[sizeof(st.edit_replace) - 1] = '\0';
    std::strncpy(st.edit_host_filter, r.host_filter.c_str(), sizeof(st.edit_host_filter) - 1);
    st.edit_host_filter[sizeof(st.edit_host_filter) - 1] = '\0';
    st.edit_target = static_cast<int>(r.target);
    st.edit_scheme = (r.scheme_filter == "http") ? 1 : (r.scheme_filter == "https") ? 2 : 0;
    st.edit_regex = r.regex;
    st.edit_ci = r.case_insensitive;
    st.edit_active = r.active;
    st.edit_dirty = false;
}

}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    const auto& th = aida::ui::resolved();
    auto& st = s();

    if (!st.initialized) {
        match_replace::initialize();
        st.initialized = true;
    }

    ImGui::SetCursorPos(ImVec2(pos_x, pos_y));
    ImGui::BeginChild("##burp_mr_root", ImVec2(width, height), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetWindowPos();
    dl->AddRectFilled(ImVec2(org.x, org.y), ImVec2(org.x + width, org.y + 28.f),
                      aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddText(ImVec2(org.x + 8.f, org.y + 6.f),
                aida::ui::with_alpha(th.text_primary, alpha),
                "Match and Replace");

    const float top_y = 36.f;
    const float toolbar_h = 36.f;
    const float left_w = width * 0.55f;
    const float right_x = left_w + 8.f;
    const float right_w = width - right_x - 8.f;

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y));
    ImGui::PushID("mr_toolbar");
    ImGui::SetNextItemWidth(180.f);
    ImGui::Combo("Target##mr_new_target", &st.new_target, target_combo, 6);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.f);
    ImGui::Combo("Scheme##mr_new_scheme", &st.new_scheme, scheme_combo, 3);
    ImGui::SameLine();
    ImGui::Checkbox("regex##mr_new_regex", &st.new_regex);
    ImGui::SameLine();
    ImGui::Checkbox("ci##mr_new_ci", &st.new_ci);
    ImGui::SameLine();
    ImGui::Checkbox("active##mr_new_active", &st.new_active);
    ImGui::SameLine();
    if (aida::ui::button("Add rule", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
        match_replace::rule_t r;
        r.label = st.new_label;
        r.target = static_cast<match_replace::match_kind_t>(st.new_target);
        r.match_regex = st.new_match;
        r.replacement = st.new_replace;
        r.regex = st.new_regex;
        r.case_insensitive = st.new_ci;
        r.active = st.new_active;
        r.host_filter = st.new_host_filter;
        if (st.new_scheme == 1) r.scheme_filter = "http";
        else if (st.new_scheme == 2) r.scheme_filter = "https";
        match_replace::add(r);
        st.new_label[0] = '\0';
        st.new_match[0] = '\0';
        st.new_replace[0] = '\0';
        st.new_host_filter[0] = '\0';
    }

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y + toolbar_h));
    ImGui::SetNextItemWidth(width - 16.f);
    ImGui::InputTextWithHint("Label##mr_new_label", "Optional label", st.new_label, sizeof(st.new_label));
    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y + toolbar_h + 28.f));
    ImGui::SetNextItemWidth((width - 24.f) * 0.5f);
    ImGui::InputTextWithHint("Match##mr_new_match", "regex or literal", st.new_match, sizeof(st.new_match));
    ImGui::SameLine();
    ImGui::SetNextItemWidth((width - 24.f) * 0.5f);
    ImGui::InputTextWithHint("Replace##mr_new_replace", "replacement", st.new_replace, sizeof(st.new_replace));
    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + top_y + toolbar_h + 56.f));
    ImGui::SetNextItemWidth(width - 16.f);
    ImGui::InputTextWithHint("Host filter##mr_new_host_filter", "(optional regex)", st.new_host_filter, sizeof(st.new_host_filter));
    ImGui::PopID();

    const float table_top = top_y + toolbar_h + 92.f;

    ImGui::SetCursorPos(ImVec2(pos_x + 6.f, pos_y + table_top));
    ImGui::BeginChild("##mr_rules_table", ImVec2(left_w, height - table_top - 8.f), false, ImGuiWindowFlags_NoBackground);

    ImDrawList* tdl = ImGui::GetWindowDrawList();
    const ImVec2 t_org = ImGui::GetWindowPos();
    const float row_h = 24.f;
    const float text_oy = (row_h - ImGui::GetTextLineHeight()) * 0.5f;
    const float col_label = 180.f;
    const float col_target = 130.f;
    const float col_match  = 220.f;
    const float col_hits   = 60.f;

    tdl->AddRectFilled(ImVec2(t_org.x, t_org.y), ImVec2(t_org.x + left_w, t_org.y + row_h),
                       aida::ui::with_alpha(th.panel_header, alpha));
    float hx = t_org.x + 8.f;
    ImU32 hdr_col = aida::ui::with_alpha(th.text_secondary, alpha);
    tdl->AddText(ImVec2(hx, t_org.y + text_oy), hdr_col, "Label"); hx += col_label;
    tdl->AddText(ImVec2(hx, t_org.y + text_oy), hdr_col, "Target"); hx += col_target;
    tdl->AddText(ImVec2(hx, t_org.y + text_oy), hdr_col, "Match"); hx += col_match;
    tdl->AddText(ImVec2(hx, t_org.y + text_oy), hdr_col, "Hits"); hx += col_hits;
    tdl->AddText(ImVec2(hx, t_org.y + text_oy), hdr_col, "Active");

    ImGui::SetCursorPosY(row_h + 4.f);

    static float s_anim_time = 0.f;
    s_anim_time += ImGui::GetIO().DeltaTime;

    const auto rules = match_replace::list();
    int visible = 0;
    for (const auto& r : rules) {
        ImGui::PushID(static_cast<int>(r.id & 0x7FFFFFFF));
        const float row_alpha_anim = ui_anim::render_row_entrance(visible, s_anim_time, 0.010f);
        const float r_alpha = alpha * row_alpha_anim;
        const float abs_ry = ImGui::GetCursorScreenPos().y;

        const bool selected = (st.selected_id == r.id);
        if (visible & 1) {
            tdl->AddRectFilled(ImVec2(t_org.x, abs_ry), ImVec2(t_org.x + left_w, abs_ry + row_h),
                               aida::ui::with_alpha(th.hover_wash, r_alpha * 0.30f));
        }
        if (selected) {
            tdl->AddRectFilled(ImVec2(t_org.x, abs_ry), ImVec2(t_org.x + left_w, abs_ry + row_h),
                               aida::ui::with_alpha(th.selection, r_alpha), 4.f);
        }

        ImGui::InvisibleButton("##mr_row", ImVec2(left_w, row_h));
        if (ImGui::IsItemClicked()) {
            load_into_edit(st, r);
        }
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
            load_into_edit(st, r);
            st.show_edit_popup = true;
        }

        ImU32 txt = aida::ui::with_alpha(th.text_primary, r_alpha);
        float lx = t_org.x + 8.f;
        const float ty = abs_ry + text_oy;
        std::string lbl = r.label;
        if (lbl.empty()) lbl = std::string("(rule #") + std::to_string(r.id) + ")";
        if (lbl.size() > 30) lbl = lbl.substr(0, 30) + "...";
        tdl->AddText(ImVec2(lx, ty), txt, lbl.c_str()); lx += col_label;
        tdl->AddText(ImVec2(lx, ty), txt, match_replace::target_label(r.target)); lx += col_target;
        std::string m_prev = r.match_regex;
        if (m_prev.size() > 32) m_prev = m_prev.substr(0, 32) + "...";
        tdl->AddText(ImVec2(lx, ty), aida::ui::with_alpha(th.text_secondary, r_alpha), m_prev.c_str()); lx += col_match;
        char hits_buf[24]; std::snprintf(hits_buf, sizeof(hits_buf), "%llu", static_cast<unsigned long long>(r.hit_count));
        tdl->AddText(ImVec2(lx, ty), aida::ui::with_alpha(th.text_dim, r_alpha), hits_buf); lx += col_hits;
        tdl->AddText(ImVec2(lx, ty),
            r.active ? aida::ui::with_alpha(th.success, r_alpha) : aida::ui::with_alpha(th.text_dim, r_alpha),
            r.active ? "yes" : "no");
        ImGui::PopID();
        ++visible;
    }

    if (visible == 0) {
        const ImVec2 c_sz = ImGui::GetWindowSize();
        const char* msg = "No match-replace rules yet.";
        const ImVec2 sz = ImGui::CalcTextSize(msg);
        tdl->AddText(ImVec2(t_org.x + (c_sz.x - sz.x) * 0.5f, t_org.y + (c_sz.y - sz.y) * 0.5f),
                     aida::ui::with_alpha(th.text_dim, alpha * 0.85f), msg);
    }

    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(pos_x + right_x, pos_y + table_top));
    ImGui::BeginChild("##mr_detail", ImVec2(right_w, height - table_top - 8.f), false, ImGuiWindowFlags_NoBackground);

    if (st.selected_id == 0) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_dim, alpha)),
            "Select a rule to edit or test.");
    } else {
        ImGui::InputText("Label##mr_e_label", st.edit_label, sizeof(st.edit_label));
        ImGui::SetNextItemWidth(220.f);
        ImGui::Combo("Target##mr_e_target", &st.edit_target, target_combo, 6);
        ImGui::SetNextItemWidth(160.f);
        ImGui::Combo("Scheme##mr_e_scheme", &st.edit_scheme, scheme_combo, 3);
        ImGui::Checkbox("regex##mr_e_regex", &st.edit_regex);
        ImGui::SameLine();
        ImGui::Checkbox("ci##mr_e_ci", &st.edit_ci);
        ImGui::SameLine();
        ImGui::Checkbox("active##mr_e_active", &st.edit_active);
        ImGui::InputTextMultiline("Match##mr_e_match", st.edit_match, sizeof(st.edit_match),
            ImVec2(right_w - 4.f, 64.f));
        ImGui::InputTextMultiline("Replace##mr_e_replace", st.edit_replace, sizeof(st.edit_replace),
            ImVec2(right_w - 4.f, 64.f));
        ImGui::InputText("Host filter##mr_e_host_filter", st.edit_host_filter, sizeof(st.edit_host_filter));

        if (aida::ui::button("Save", aida::ui::button_kind_t::primary, aida::ui::size_t_::sm)) {
            match_replace::rule_t r;
            r.id = st.selected_id;
            r.label = st.edit_label;
            r.target = static_cast<match_replace::match_kind_t>(st.edit_target);
            r.match_regex = st.edit_match;
            r.replacement = st.edit_replace;
            r.regex = st.edit_regex;
            r.case_insensitive = st.edit_ci;
            r.active = st.edit_active;
            r.host_filter = st.edit_host_filter;
            if (st.edit_scheme == 1) r.scheme_filter = "http";
            else if (st.edit_scheme == 2) r.scheme_filter = "https";
            else r.scheme_filter.clear();
            for (const auto& cur : match_replace::list()) {
                if (cur.id == st.selected_id) { r.hit_count = cur.hit_count; break; }
            }
            match_replace::update(r);
        }
        ImGui::SameLine();
        if (aida::ui::button("Delete", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            match_replace::remove(st.selected_id);
            st.selected_id = 0;
        }
        ImGui::SameLine();
        if (aida::ui::button("Up", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            match_replace::move(st.selected_id, -1);
        }
        ImGui::SameLine();
        if (aida::ui::button("Down", aida::ui::button_kind_t::ghost, aida::ui::size_t_::sm)) {
            match_replace::move(st.selected_id, 1);
        }
        ImGui::SameLine();
        if (aida::ui::button("Clear all", aida::ui::button_kind_t::destructive, aida::ui::size_t_::sm)) {
            match_replace::clear();
            st.selected_id = 0;
        }

        ImGui::Separator();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.text_secondary, alpha)),
            "Test against sample");
        ImGui::InputTextMultiline("##mr_test_sample", st.test_sample, sizeof(st.test_sample),
            ImVec2(right_w - 4.f, 96.f));
        if (aida::ui::button("Run test", aida::ui::button_kind_t::secondary, aida::ui::size_t_::sm)) {
            match_replace::rule_t r;
            r.id = st.selected_id;
            r.label = st.edit_label;
            r.target = static_cast<match_replace::match_kind_t>(st.edit_target);
            r.match_regex = st.edit_match;
            r.replacement = st.edit_replace;
            r.regex = st.edit_regex;
            r.case_insensitive = st.edit_ci;
            r.active = true;
            const bool ok = match_replace::test_rule(r, std::string(st.test_sample), st.test_result);
            if (!ok) st.test_result = std::string("(error: ") + match_replace::last_error() + ")";
        }
        ImGui::InputTextMultiline("Result##mr_test_result",
            const_cast<char*>(st.test_result.c_str()),
            st.test_result.size() + 1,
            ImVec2(right_w - 4.f, 96.f), ImGuiInputTextFlags_ReadOnly);
    }

    ImGui::EndChild();

    ImGui::EndChild();
}

}
}
}
