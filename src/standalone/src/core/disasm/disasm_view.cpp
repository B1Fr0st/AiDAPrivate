#include "disasm_view.hpp"
#include "zydis_disasm.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <thread>
#include "ui_anim.hpp"
#include "decompiler_engine.hpp"
#include "aob_generator.hpp"
#include "scan_hub_view.hpp"
#include "standalone_settings.hpp"
#include "symbol_store.hpp"
#include "xref_engine.hpp"
#include "cfg_view.hpp"
#include "source_reconstruct_view.hpp"

namespace disasm_view {

static cfg_view::cfg_state_t s_inline_cfg;
static float s_xref_anim_t = 0.f;


static int find_instr_at(uint64_t addr, const DisasmFile& file) {
    if (file.instrs.empty()) return -1;

    int lo = 0, hi = (int)file.instrs.size() - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (file.instrs[mid].addr == addr) return mid;
        if (file.instrs[mid].addr < addr) lo = mid + 1;
        else hi = mid - 1;
    }
    return (lo < (int)file.instrs.size()) ? lo : (int)file.instrs.size() - 1;
}

void goto_address(uint64_t addr, DisasmState& disasm) {
    auto& st = g_state;
    int idx = find_instr_at(addr, disasm.file);
    if (idx < 0) return;


    if (st.selected_row >= 0) {

        if (st.nav_pos + 1 < (int)st.nav_history.size())
            st.nav_history.resize(st.nav_pos + 1);
        st.nav_history.push_back(st.selected_row);
        st.nav_pos = (int)st.nav_history.size() - 1;
    }

    st.selected_row = idx;
    st.target_scroll_y = idx * 18.f;
}

void navigate_back() {
    auto& st = g_state;
    if (st.nav_pos <= 0 || st.nav_history.empty()) return;
    st.nav_pos--;
    st.selected_row = st.nav_history[st.nav_pos];
    st.target_scroll_y = st.selected_row * 18.f;
}

void navigate_forward() {
    auto& st = g_state;
    if (st.nav_pos + 1 >= (int)st.nav_history.size()) return;
    st.nav_pos++;
    st.selected_row = st.nav_history[st.nav_pos];
    st.target_scroll_y = st.selected_row * 18.f;
}

static void launch_xref_scan(uint64_t addr)
{
    auto& st = g_state;
    st.xref_scanning.store(true);
    st.xref_popup_selected = -1;
    st.xref_popup_scroll = 0.f;
    st.xref_popup_target_scroll = 0.f;

    try {
    std::thread([addr]() {
        auto modules = driver_bridge::enumerate_modules();

        uint64_t search_base = 0;
        uint64_t search_size = 0;
        std::string mod_name;

        bool use_static = false;

        for (auto& m : modules) {
            if (addr >= m.base && addr < m.base + m.size) {
                search_base = m.base;
                search_size = m.size;
                mod_name = m.name;
                break;
            }
        }

        if (search_size == 0 && !modules.empty()) {
            search_base = modules[0].base;
            search_size = modules[0].size;
            mod_name = modules[0].name;
        }

        if (search_size == 0 && g_disasm.file.loaded && !g_disasm.file.sections.empty()) {
            use_static = true;
            search_base = g_disasm.file.image_base;
            search_size = static_analysis::total_image_size(g_disasm.file);
            mod_name = g_disasm.file.filename;
        }

        if (search_size == 0) {
            g_state.xref_scanning.store(false);
            return;
        }

        const size_t page_size = 4096;
        std::vector<xref_popup_entry_t> found;

        for (uint64_t offset = 0; offset < search_size; offset += page_size) {
            size_t chunk = page_size;
            if (offset + chunk > search_size)
                chunk = static_cast<size_t>(search_size - offset);

            std::vector<uint8_t> page_data;
            bool got_page = false;

            if (!use_static)
                got_page = driver_bridge::read_memory(search_base + offset, chunk, page_data);

            if (!got_page)
                got_page = static_analysis::read_bytes_from_pe(g_disasm.file, search_base + offset, chunk, page_data);

            if (!got_page || page_data.empty())
                continue;

            const uint8_t* data = page_data.data();
            int sz = static_cast<int>(page_data.size());
            int pos = 0;

            while (pos < sz) {
                int avail = sz - pos;
                if (avail > 15) avail = 15;

                uint64_t ins_addr = search_base + offset + pos;
                AsmInstr ins = zydis_decode_one(data + pos, avail, ins_addr);

                uint64_t resolved = 0;
                if (xref_engine::detail::extract_target(data + pos, ins.len, ins_addr, ins, resolved)) {
                    if (resolved == addr) {
                        xref_popup_entry_t e;
                        e.addr = ins_addr;
                        e.type = static_cast<int>(xref_engine::detail::classify_instruction(ins));
                        char buf[256];
                        snprintf(buf, sizeof(buf), "%s %s", ins.mnem, ins.ops);
                        e.disasm_text = buf;
                        e.module_name = mod_name;
                        found.push_back(std::move(e));
                    }
                }
                pos += ins.len;
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_state.xref_mutex);
            g_state.xref_results = std::move(found);
        }
        g_state.xref_scanning.store(false);
    }).detach();
    } catch (...) {
        g_state.xref_scanning.store(false);
        driver_bridge::debug_log("[disasm] xref scan thread creation failed\n");
    }
}

static float s_close_btn_anim = 0.f;
static float s_copy_addr_anim = 0.f;
static float s_copy_all_anim = 0.f;

static void render_xref_popup(float pos_x, float pos_y, float width, float height,
                               float alpha, float accent_r, float accent_g, float accent_b,
                               DisasmState& disasm, float dt)
{
    auto& st = g_state;

    float target_fade = st.xref_popup_open ? 1.f : 0.f;
    st.xref_popup_fade = ui_anim::smooth_lerp(st.xref_popup_fade, target_fade, 14.f, dt);

    if (st.xref_popup_fade < 0.01f && !st.xref_popup_open)
        return;

    float fa = alpha * st.xref_popup_fade;
    const auto& _t = themes::resolved;
    const auto _ta = [fa](ImU32 c) -> ImU32 { return ui_anim::theme_alpha(c, fa); };
    ImDrawList* fdl = ImGui::GetForegroundDrawList();

    float popup_w = std::min(760.f, width * 0.88f);
    float popup_h = std::min(460.f, height * 0.8f);
    float cx = pos_x + width * 0.5f;
    float cy = pos_y + height * 0.5f;

    ui_anim::render_popup_frame(fdl, cx, cy, popup_w, popup_h, st.xref_popup_fade,
                                accent_r, accent_g, accent_b, alpha,
                                pos_x, pos_y, width, height);

    float t_back = ui_anim::ease_out_back(std::clamp(st.xref_popup_fade * 1.2f, 0.f, 1.f));
    float scale = 0.92f + 0.08f * t_back;
    float pw = popup_w * scale;
    float ph = popup_h * scale;
    float px = cx - pw * 0.5f;
    float py = cy - ph * 0.5f + (1.f - t_back) * 12.f;

    char title_buf[64];
    snprintf(title_buf, sizeof(title_buf), "Cross References to 0x%llX",
             static_cast<unsigned long long>(st.xref_popup_addr));

    std::vector<xref_popup_entry_t> results_copy;
    {
        std::lock_guard<std::mutex> lk(st.xref_mutex);
        results_copy = st.xref_results;
    }

    float header_h = 38.f;
    ui_anim::render_popup_header(fdl, px, py, pw, header_h,
                                  title_buf, accent_r, accent_g, accent_b, fa);

    if (ui_anim::render_popup_close_button(fdl, px, py, pw, header_h, fa, s_close_btn_anim, dt))
        st.xref_popup_open = false;

    float toolbar_y = py + header_h;
    float toolbar_h = 30.f;
    fdl->AddRectFilled(ImVec2(px, toolbar_y), ImVec2(px + pw, toolbar_y + toolbar_h),
        _ta(_t.panel_bg));
    fdl->AddLine(ImVec2(px, toolbar_y + toolbar_h - 1.f), ImVec2(px + pw, toolbar_y + toolbar_h - 1.f),
        _ta(ui_anim::lighten(_t.panel_bg, 12)));

    float btn_x = px + 10.f;
    float btn_y = toolbar_y + 4.f;
    if (ui_anim::render_toolbar_button(fdl, "Copy Address", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_addr_anim, dt,
                                        false, results_copy.empty())) {
        if (st.xref_popup_selected >= 0 && st.xref_popup_selected < static_cast<int>(results_copy.size())) {
            char addr_buf_copy[20];
            snprintf(addr_buf_copy, sizeof(addr_buf_copy), "%llX",
                     static_cast<unsigned long long>(results_copy[static_cast<size_t>(st.xref_popup_selected)].addr));
            ImGui::SetClipboardText(addr_buf_copy);
        }
    }
    btn_x += ui_anim::toolbar_button_width("Copy Address") + 4.f;
    if (ui_anim::render_toolbar_button(fdl, "Copy All", btn_x, btn_y,
                                        accent_r, accent_g, accent_b, fa, s_copy_all_anim, dt,
                                        false, results_copy.empty())) {
        std::string all_text;
        for (auto& e : results_copy) {
            char line_buf[256];
            snprintf(line_buf, sizeof(line_buf), "%016llX  %s\n",
                     static_cast<unsigned long long>(e.addr), e.disasm_text.c_str());
            all_text += line_buf;
        }
        if (!all_text.empty())
            ImGui::SetClipboardText(all_text.c_str());
    }

    bool scanning = st.xref_scanning.load();

    if (scanning) {
        s_xref_anim_t += dt * 5.f;
        float spinner_x = px + pw - 28.f;
        float spinner_y = py + header_h * 0.5f;
        ImU32 spin_col = IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                                   static_cast<int>(accent_b * 255), static_cast<int>(255 * fa));
        ui_anim::render_spinner(fdl, spinner_x, spinner_y, 6.f, 2.f, spin_col, s_xref_anim_t);
    }

    char count_buf[32];
    snprintf(count_buf, sizeof(count_buf), "%zu result%s",
             results_copy.size(), results_copy.size() == 1 ? "" : "s");
    ImVec2 cs = ImGui::CalcTextSize(count_buf);
    fdl->AddText(ImVec2(px + pw - cs.x - (scanning ? 42.f : 14.f), py + 11.f),
        _ta(_t.text_secondary), count_buf);

    float toolbar_end = toolbar_y + toolbar_h;
    const float footer_h = 26.f;
    float table_y = toolbar_end + 2.f;
    float table_h = ph - header_h - toolbar_h - 4.f - footer_h;
    const float row_h = 24.f;

    float col_type_w = 54.f;
    float col_addr_w = 145.f;
    float col_mod_w = 120.f;
    float col_disasm_w = pw - col_type_w - col_addr_w - col_mod_w - 30.f;
    if (col_disasm_w < 100.f) col_disasm_w = 100.f;

    ui_anim::table_col_t xref_cols[] = {
        { "Type", col_type_w }, { "Address", col_addr_w },
        { "Module", col_mod_w }, { "Disassembly", col_disasm_w }
    };
    ui_anim::render_table_header(fdl, px, table_y, pw, row_h, xref_cols, 4,
                                  accent_r, accent_g, accent_b, fa);

    float list_y = table_y + row_h;
    float list_h = table_h - row_h;
    if (list_h < 1.f) list_h = 1.f;

    float content_h = static_cast<float>(results_copy.size()) * row_h;
    int n_results = static_cast<int>(results_copy.size());

    bool popup_hovered = ImGui::IsMouseHoveringRect(ImVec2(px, list_y), ImVec2(px + pw, list_y + list_h));
    if (popup_hovered) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            st.xref_popup_target_scroll -= wheel * row_h * 3.f;
    }

    if (st.xref_popup_open) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
            st.xref_popup_selected = std::min(st.xref_popup_selected + 1, n_results - 1);
            if (st.xref_popup_selected < 0) st.xref_popup_selected = 0;
            float sel_y = static_cast<float>(st.xref_popup_selected) * row_h;
            if (sel_y < st.xref_popup_target_scroll)
                st.xref_popup_target_scroll = sel_y;
            if (sel_y + row_h > st.xref_popup_target_scroll + list_h)
                st.xref_popup_target_scroll = sel_y + row_h - list_h;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
            st.xref_popup_selected = std::max(st.xref_popup_selected - 1, 0);
            float sel_y = static_cast<float>(st.xref_popup_selected) * row_h;
            if (sel_y < st.xref_popup_target_scroll)
                st.xref_popup_target_scroll = sel_y;
            if (sel_y + row_h > st.xref_popup_target_scroll + list_h)
                st.xref_popup_target_scroll = sel_y + row_h - list_h;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Enter, false) && st.xref_popup_selected >= 0 &&
            st.xref_popup_selected < n_results) {
            goto_address(results_copy[static_cast<size_t>(st.xref_popup_selected)].addr, disasm);
            st.xref_popup_open = false;
        }
    }

    float max_scroll = std::max(0.f, content_h - list_h);
    st.xref_popup_target_scroll = std::max(0.f, std::min(st.xref_popup_target_scroll, max_scroll));
    ui_anim::smooth_scroll(st.xref_popup_scroll, st.xref_popup_target_scroll, 16.f, dt);

    fdl->PushClipRect(ImVec2(px + 1.f, list_y), ImVec2(px + pw - 12.f, list_y + list_h), true);

    int first_vis = static_cast<int>(st.xref_popup_scroll / row_h);
    int last_vis = first_vis + static_cast<int>(list_h / row_h) + 2;
    if (first_vis < 0) first_vis = 0;
    if (last_vis > n_results) last_vis = n_results;

    for (int i = first_vis; i < last_vis; ++i) {
        float ry = list_y + static_cast<float>(i) * row_h - st.xref_popup_scroll;
        if (ry + row_h < list_y || ry > list_y + list_h) continue;

        auto& e = results_copy[static_cast<size_t>(i)];

        ImVec2 rmin(px + 4.f, ry);
        ImVec2 rmax(px + pw - 14.f, ry + row_h);

        bool row_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
        bool row_sel = (st.xref_popup_selected == i);

        if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            st.xref_popup_selected = i;

        if (row_hov && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            goto_address(e.addr, disasm);
            st.xref_popup_open = false;
        }

        float row_entrance = 1.f;
        if (st.xref_popup_fade < 0.95f) {
            float delay = static_cast<float>(i - first_vis) * 0.03f;
            float t = (st.xref_popup_fade - delay) / (1.f - delay);
            if (t < 0.f) t = 0.f;
            if (t > 1.f) t = 1.f;
            row_entrance = t;
        }
        float row_alpha = fa * row_entrance;

        if (row_sel) {
            fdl->AddRectFilled(rmin, rmax,
                IM_COL32(static_cast<int>(accent_r * 180), static_cast<int>(accent_g * 180),
                         static_cast<int>(accent_b * 180), static_cast<int>(35 * row_alpha)));
            fdl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
                IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                         static_cast<int>(accent_b * 255), static_cast<int>(200 * row_alpha)));
        } else if (row_hov) {
            fdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, static_cast<int>(12 * row_alpha)));
        } else if (i & 1) {
            fdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, static_cast<int>(3 * row_alpha)));
        }

        float rx = px + 10.f;

        ImU32 type_col;
        const char* type_str;
        switch (e.type) {
        case 0:  type_str = "CALL"; type_col = IM_COL32(100, 160, 255, static_cast<int>(240 * row_alpha)); break;
        case 1:  type_str = "JMP";  type_col = IM_COL32(255, 160, 80, static_cast<int>(240 * row_alpha)); break;
        case 2:  type_str = "Jcc";  type_col = IM_COL32(220, 200, 80, static_cast<int>(240 * row_alpha)); break;
        case 3:  type_str = "LEA";  type_col = IM_COL32(80, 200, 160, static_cast<int>(240 * row_alpha)); break;
        default: type_str = "DATA"; type_col = IM_COL32(160, 140, 200, static_cast<int>(220 * row_alpha)); break;
        }

        ImVec2 tsz = ImGui::CalcTextSize(type_str);
        float badge_w = tsz.x + 10.f;
        fdl->AddRectFilled(ImVec2(rx, ry + 3.f), ImVec2(rx + badge_w, ry + row_h - 3.f),
            IM_COL32((type_col >> 0) & 0xFF, (type_col >> 8) & 0xFF, (type_col >> 16) & 0xFF,
                     static_cast<int>(35 * row_alpha)), 3.f);
        fdl->AddText(ImVec2(rx + 5.f, ry + 4.f), type_col, type_str);
        rx += col_type_w;

        char addr_buf[20];
        snprintf(addr_buf, sizeof(addr_buf), "%016llX", static_cast<unsigned long long>(e.addr));
        fdl->AddText(ImVec2(rx, ry + 4.f),
            IM_COL32(229, 192, 123, static_cast<int>(220 * row_alpha)), addr_buf);
        rx += col_addr_w;

        if (!e.module_name.empty()) {
            const char* mod = e.module_name.c_str();
            size_t max_mod = 16;
            std::string mod_short = e.module_name.size() > max_mod
                ? e.module_name.substr(0, max_mod - 2) + ".." : e.module_name;
            fdl->AddText(ImVec2(rx, ry + 4.f),
                ui_anim::theme_alpha(_t.text_secondary, row_alpha), mod_short.c_str());
        }
        rx += col_mod_w;

        const char* disasm_end = e.disasm_text.c_str() + std::min(e.disasm_text.size(), static_cast<size_t>(60));
        fdl->AddText(ImVec2(rx, ry + 4.f),
            ui_anim::theme_alpha(_t.text_primary, row_alpha),
            e.disasm_text.c_str(), disasm_end);

    }

    fdl->PopClipRect();

    if (content_h > list_h && list_h > 0.f) {
        float sb_x = px + pw - 10.f;
        float sb_track_h = list_h;
        float ratio = list_h / content_h;
        float thumb_h = std::max(20.f, sb_track_h * ratio);
        float scroll_range = content_h - list_h;
        float thumb_y = list_y + (scroll_range > 0.f
            ? (st.xref_popup_scroll / scroll_range) * (sb_track_h - thumb_h) : 0.f);

        bool sb_hov = ImGui::IsMouseHoveringRect(
            ImVec2(sb_x - 4.f, list_y), ImVec2(sb_x + 8.f, list_y + sb_track_h));

        if (sb_hov || st.xref_popup_sb_dragging) {
            fdl->AddRectFilled(ImVec2(sb_x, list_y), ImVec2(sb_x + 6.f, list_y + sb_track_h),
                IM_COL32(255, 255, 255, static_cast<int>(8 * fa)), 3.f);
            fdl->AddRectFilled(ImVec2(sb_x, thumb_y), ImVec2(sb_x + 6.f, thumb_y + thumb_h),
                IM_COL32(200, 200, 220, static_cast<int>((st.xref_popup_sb_dragging ? 120 : 60) * fa)), 3.f);
        }

        if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            st.xref_popup_sb_dragging = true;
            st.xref_popup_sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
        }
        if (st.xref_popup_sb_dragging) {
            if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                float my = ImGui::GetIO().MousePos.y - st.xref_popup_sb_drag_offset;
                float drag_ratio = (my - list_y) / (sb_track_h - thumb_h);
                drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                st.xref_popup_target_scroll = drag_ratio * scroll_range;
                st.xref_popup_scroll = st.xref_popup_target_scroll;
            } else {
                st.xref_popup_sb_dragging = false;
            }
        }
    }

    if (results_copy.empty() && !scanning) {
        float cw = std::min(pw - 32.f, 420.f);
        if (cw < 140.f) cw = std::max(140.f, pw - 20.f);
        float ccx = px + (pw - cw) * 0.5f;
        float ccy = list_y + list_h * 0.5f - 26.f;
        ui_anim::render_inline_callout(fdl, ccx, ccy, cw, 52.f,
            "No cross references found. This address is not referenced by call/jmp/lea/data.",
            ui_anim::callout_kind_t::info, accent_r, accent_g, accent_b, fa);
    }

    {
        float fx = px + 12.f;
        float fy = py + ph - footer_h + 4.f;
        float cw;
        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "\xe2\x86\x91", fa);
        fx += cw + 4.f;
        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "\xe2\x86\x93", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(_t.text_dim), "navigate");
        fx += ImGui::CalcTextSize("navigate").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Enter", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(_t.text_dim), "jump");
        fx += ImGui::CalcTextSize("jump").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Esc", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(_t.text_dim), "close");
        fx += ImGui::CalcTextSize("close").x + 14.f;

        cw = ui_anim::render_kbd_chip(fdl, fx, fy, "Dbl-click", fa);
        fx += cw + 6.f;
        fdl->AddText(ImVec2(fx, fy + 2.f), _ta(_t.text_dim), "goto");
    }

    if (!st.xref_popup_open && !popup_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        st.xref_popup_fade = 0.f;
    }
}

static void render_inline_graph(float pos_x, float pos_y, float width, float height,
                                 float alpha, float accent_r, float accent_g, float accent_b,
                                 DisasmState& disasm, float dt)
{
    auto& st = g_state;

    if (st.cfg_needs_build && !s_inline_cfg.building.load()) {
        st.cfg_needs_build = false;

        s_inline_cfg.building.store(true);
        uint64_t entry = st.cfg_entry_addr;

        try {
        std::thread([entry]() {
            const size_t max_bytes = 0x10000;
            const size_t max_insns = 4096;

            std::vector<uint8_t> mem;
            bool have_data = false;

            if (driver_bridge::attached_pid() != 0) {
                have_data = driver_bridge::read_memory(entry, max_bytes, mem);
            }

            if (!have_data || mem.empty()) {
                have_data = static_analysis::read_bytes_from_pe(g_disasm.file, entry, max_bytes, mem);
            }

            if (mem.empty()) {
                s_inline_cfg.building.store(false);
                return;
            }

            struct decoded_t {
                AsmInstr ins;
                uint64_t branch_target = 0;
                bool     has_target = false;
            };

            std::vector<decoded_t> all_insns;
            all_insns.reserve(max_insns);

            const uint8_t* data = mem.data();
            int sz = static_cast<int>(mem.size());
            int pos = 0;

            while (pos < sz && all_insns.size() < max_insns) {
                int avail = sz - pos;
                if (avail > 15) avail = 15;
                uint64_t va = entry + pos;
                AsmInstr ins = zydis_decode_one(data + pos, avail, va);

                decoded_t d;
                d.ins = ins;

                if (ins.is_call || ins.is_branch) {
                    if (ins.len == 5 && (data[pos] == 0xE8 || data[pos] == 0xE9)) {
                        int32_t rel = 0;
                        std::memcpy(&rel, data + pos + 1, 4);
                        d.branch_target = va + ins.len + rel;
                        d.has_target = true;
                    } else if (ins.len == 2 && (data[pos] >= 0x70 && data[pos] <= 0x7F)) {
                        int8_t rel = static_cast<int8_t>(data[pos + 1]);
                        d.branch_target = va + ins.len + rel;
                        d.has_target = true;
                    } else if (ins.len == 6 && data[pos] == 0x0F && (data[pos+1] >= 0x80 && data[pos+1] <= 0x8F)) {
                        int32_t rel = 0;
                        std::memcpy(&rel, data + pos + 2, 4);
                        d.branch_target = va + ins.len + rel;
                        d.has_target = true;
                    } else if (ins.len == 2 && data[pos] == 0xEB) {
                        int8_t rel = static_cast<int8_t>(data[pos + 1]);
                        d.branch_target = va + ins.len + rel;
                        d.has_target = true;
                    }
                }

                all_insns.push_back(d);
                if (ins.is_ret) break;
                pos += ins.len;
            }

            if (all_insns.empty()) {
                s_inline_cfg.building.store(false);
                return;
            }

            std::map<uint64_t, bool> leaders;
            leaders[entry] = true;

            for (auto& d : all_insns) {
                if (d.has_target && !d.ins.is_call) {
                    leaders[d.branch_target] = true;
                    leaders[d.ins.addr + d.ins.len] = true;
                }
                if (d.ins.is_ret)
                    leaders[d.ins.addr + d.ins.len] = true;
            }

            std::vector<cfg_view::basic_block_t> blocks;
            std::map<uint64_t, int> addr_to_block;

            int cur_block = -1;
            for (auto& d : all_insns) {
                if (leaders.count(d.ins.addr)) {
                    cur_block = cfg_view::detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);
                    if (d.ins.addr == entry)
                        blocks[cur_block].is_entry = true;
                }
                if (cur_block < 0)
                    cur_block = cfg_view::detail::find_or_create_block(addr_to_block, blocks, d.ins.addr);

                cfg_view::instruction_line_t line;
                line.addr = d.ins.addr;
                char buf[192];
                snprintf(buf, sizeof(buf), "%s %s", d.ins.mnem, d.ins.ops);
                line.text = buf;
                blocks[cur_block].instructions.push_back(std::move(line));
                blocks[cur_block].end_addr = d.ins.addr + d.ins.len;

                if (d.ins.is_ret) continue;

                if (d.has_target && !d.ins.is_call) {
                    int tidx = cfg_view::detail::find_or_create_block(addr_to_block, blocks, d.branch_target);
                    blocks[cur_block].successors.push_back(tidx);

                    bool is_uncond = (std::strcmp(d.ins.mnem, "jmp") == 0 || std::strcmp(d.ins.mnem, "JMP") == 0);
                    if (!is_uncond) {
                        int fidx = cfg_view::detail::find_or_create_block(addr_to_block, blocks, d.ins.addr + d.ins.len);
                        blocks[cur_block].successors.push_back(fidx);
                    }

                    if (leaders.count(d.ins.addr + d.ins.len))
                        cur_block = -1;
                }
            }

            float line_h = 14.f;
            float padding = 8.f;

            cfg_layout::graph_t graph;
            graph.nodes.reserve(blocks.size());
            for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
                cfg_layout::node_t n;
                n.id = i;
                n.width = 260.f;
                n.height = padding * 2.f + static_cast<float>(blocks[i].instructions.size()) * line_h;
                if (n.height < 30.f) n.height = 30.f;
                graph.nodes.push_back(n);
            }

            for (int i = 0; i < static_cast<int>(blocks.size()); ++i) {
                for (int j = 0; j < static_cast<int>(blocks[i].successors.size()); ++j) {
                    cfg_layout::edge_t e;
                    e.from = i;
                    e.to = blocks[i].successors[j];
                    e.is_true_branch = (j == 0 && blocks[i].successors.size() > 1);
                    graph.edges.push_back(e);
                }
            }

            cfg_layout::layout(graph, 60.f, 40.f);

            {
                std::lock_guard<std::mutex> lk(s_inline_cfg.mutex);
                s_inline_cfg.blocks = std::move(blocks);
                s_inline_cfg.graph = std::move(graph);
                s_inline_cfg.entry_addr = entry;
                s_inline_cfg.built = true;
                s_inline_cfg.selected_block = -1;
                s_inline_cfg.pan_x = 0.f;
                s_inline_cfg.pan_y = 0.f;
                s_inline_cfg.zoom = 1.f;
            }

            s_inline_cfg.building.store(false);
        }).detach();
        } catch (...) {
            s_inline_cfg.building.store(false);
            driver_bridge::debug_log("[disasm] CFG build thread creation failed\n");
        }
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    float ox = wp.x + pos_x;
    float oy = wp.y + pos_y;

    dl->PushClipRect(ImVec2(ox, oy), ImVec2(ox + width, oy + height), true);
    const auto& _t = themes::resolved;
    const auto _ta = [alpha](ImU32 c) -> ImU32 { return ui_anim::theme_alpha(c, alpha); };
    dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
        _ta(_t.bg_base));

    float mode_badge_x = ox + width - 110.f;
    float mode_badge_y = oy + 6.f;
    dl->AddRectFilled(ImVec2(mode_badge_x, mode_badge_y),
                      ImVec2(mode_badge_x + 100.f, mode_badge_y + 22.f),
                      IM_COL32(static_cast<int>(accent_r * 120), static_cast<int>(accent_g * 120),
                               static_cast<int>(accent_b * 120), static_cast<int>(60 * alpha)), 11.f);
    ImVec2 badge_ts = ImGui::CalcTextSize("GRAPH VIEW");
    dl->AddText(ImVec2(mode_badge_x + (100.f - badge_ts.x) * 0.5f, mode_badge_y + 3.f),
        IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                 static_cast<int>(accent_b * 255), static_cast<int>(220 * alpha)),
        "GRAPH VIEW");

    const char* hint = "Press SPACE to return to linear view";
    ImVec2 hs = ImGui::CalcTextSize(hint);
    dl->AddText(ImVec2(ox + 10.f, oy + 8.f),
        _ta(_t.text_dim), hint);

    if (s_inline_cfg.building.load()) {
        float cx = ox + width * 0.5f;
        float cy = oy + height * 0.5f;
        static float spin_t = 0.f;
        spin_t += dt * 4.f;
        ui_anim::render_spinner(dl, cx, cy - 10.f, 10.f, 2.5f,
            IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                     static_cast<int>(accent_b * 255), static_cast<int>(220 * alpha)), spin_t);
        const char* bld = "Building CFG...";
        ImVec2 bs = ImGui::CalcTextSize(bld);
        dl->AddText(ImVec2(cx - bs.x * 0.5f, cy + 8.f),
            _ta(_t.text_secondary), bld);
        dl->PopClipRect();
        return;
    }

    std::lock_guard<std::mutex> lk(s_inline_cfg.mutex);

    if (!s_inline_cfg.built || s_inline_cfg.blocks.empty()) {
        float cx = ox + width * 0.5f;
        float cy = oy + height * 0.5f;
        const char* msg = "No CFG available";
        ImVec2 ms = ImGui::CalcTextSize(msg);
        dl->AddText(ImVec2(cx - ms.x * 0.5f, cy),
            _ta(_t.text_dim), msg);
        dl->PopClipRect();
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    bool hov = ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + width, oy + height), false);

    if (hov && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.f)) {
        s_inline_cfg.pan_x += io.MouseDelta.x / s_inline_cfg.zoom;
        s_inline_cfg.pan_y += io.MouseDelta.y / s_inline_cfg.zoom;
    }

    if (hov && !ImGui::GetIO().KeyCtrl) {
        if (io.MouseWheel != 0.f)
            s_inline_cfg.pan_y += io.MouseWheel * 40.f / s_inline_cfg.zoom;
    }
    if (hov && ImGui::GetIO().KeyCtrl && io.MouseWheel != 0.f) {
        float old_zoom = s_inline_cfg.zoom;
        s_inline_cfg.zoom *= (io.MouseWheel > 0) ? 1.1f : 0.9f;
        s_inline_cfg.zoom = std::max(0.1f, std::min(5.f, s_inline_cfg.zoom));

        float mx = io.MousePos.x - ox - width * 0.5f;
        float my = io.MousePos.y - oy - height * 0.5f;
        float sc = s_inline_cfg.zoom / old_zoom;
        s_inline_cfg.pan_x -= mx * (1.f - 1.f / sc) / s_inline_cfg.zoom;
        s_inline_cfg.pan_y -= my * (1.f - 1.f / sc) / s_inline_cfg.zoom;
    }

    float center_x = ox + width * 0.5f;
    float center_y = oy + height * 0.5f;
    float z = s_inline_cfg.zoom;

    auto world_to_screen = [&](float wx, float wy) -> ImVec2 {
        return ImVec2(center_x + (wx + s_inline_cfg.pan_x) * z,
                      center_y + (wy + s_inline_cfg.pan_y) * z);
    };

    auto& nodes = s_inline_cfg.graph.nodes;
    auto& edges = s_inline_cfg.graph.edges;
    auto& blocks = s_inline_cfg.blocks;

    int ar = static_cast<int>(accent_r * 255);
    int ag = static_cast<int>(accent_g * 255);
    int ab = static_cast<int>(accent_b * 255);

    for (auto& e : edges) {
        int from_idx = -1, to_idx = -1;
        for (int i = 0; i < static_cast<int>(nodes.size()); ++i) {
            if (nodes[i].id == e.from) from_idx = i;
            if (nodes[i].id == e.to) to_idx = i;
        }
        if (from_idx < 0 || to_idx < 0) continue;

        auto& fn = nodes[from_idx];
        auto& tn = nodes[to_idx];

        ImVec2 p1 = world_to_screen(fn.x, fn.y + fn.height);
        ImVec2 p4 = world_to_screen(tn.x, tn.y);
        float mid_y = (p1.y + p4.y) * 0.5f;
        ImVec2 p2(p1.x, mid_y);
        ImVec2 p3(p4.x, mid_y);

        ImU32 edge_col;
        if (e.from < static_cast<int>(blocks.size()) && blocks[e.from].successors.size() > 1) {
            edge_col = e.is_true_branch
                ? IM_COL32(80, 200, 80, static_cast<int>(180 * alpha))
                : IM_COL32(200, 80, 80, static_cast<int>(180 * alpha));
        } else {
            edge_col = IM_COL32(140, 140, 160, static_cast<int>(120 * alpha));
        }

        for (int g = 2; g >= 0; --g) {
            float gw = (1.5f + static_cast<float>(g) * 1.5f) * z;
            int ga = static_cast<int>(alpha * (g == 0 ? 180 : (g == 1 ? 40 : 15)));
            ImU32 gc = IM_COL32((edge_col >> 0) & 0xFF, (edge_col >> 8) & 0xFF,
                                 (edge_col >> 16) & 0xFF, ga);
            dl->AddBezierCubic(p1, p2, p3, p4, gc, gw);
        }

        float arrow_sz = 6.f * z;
        ImVec2 dir(p4.x - p3.x, p4.y - p3.y);
        float dir_len = std::sqrt(dir.x * dir.x + dir.y * dir.y);
        if (dir_len > 0.001f) {
            dir.x /= dir_len; dir.y /= dir_len;
            ImVec2 perp(-dir.y, dir.x);
            ImVec2 a1(p4.x - dir.x * arrow_sz + perp.x * arrow_sz * 0.5f,
                       p4.y - dir.y * arrow_sz + perp.y * arrow_sz * 0.5f);
            ImVec2 a2(p4.x - dir.x * arrow_sz - perp.x * arrow_sz * 0.5f,
                       p4.y - dir.y * arrow_sz - perp.y * arrow_sz * 0.5f);
            dl->AddTriangleFilled(p4, a1, a2, edge_col);
        }
    }

    float line_h = 14.f * z;
    float pad = 8.f * z;

    for (int ni = 0; ni < static_cast<int>(nodes.size()); ++ni) {
        auto& n = nodes[ni];
        if (n.id < 0 || n.id >= static_cast<int>(blocks.size())) continue;

        auto& blk = blocks[n.id];

        float nw = n.width * z;
        float nh = n.height * z;
        ImVec2 tl = world_to_screen(n.x - n.width * 0.5f, n.y);
        ImVec2 br(tl.x + nw, tl.y + nh);

        if (br.x < ox || tl.x > ox + width || br.y < oy || tl.y > oy + height) continue;

        ImU32 bg_col = _ta(_t.panel_bg);
        dl->AddRectFilled(tl, br, bg_col, 4.f * z);

        bool is_sel = (n.id == s_inline_cfg.selected_block);
        bool is_entry = blk.is_entry;

        if (is_entry) {
            dl->AddRectFilled(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(30 * alpha)), 4.f * z);
            dl->AddRect(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(180 * alpha)), 4.f * z, 0, 2.f * z);
        } else if (is_sel) {
            dl->AddRect(tl, br, IM_COL32(ar, ag, ab, static_cast<int>(160 * alpha)), 4.f * z, 0, 1.5f * z);
        } else {
            dl->AddRect(tl, br, _ta(ui_anim::lighten(_t.panel_bg, 12)), 4.f * z, 0, 1.f * z);
        }

        if (blk.has_breakpoint) {
            dl->AddRectFilled(tl, ImVec2(tl.x + 3.f * z, br.y),
                IM_COL32(200, 50, 50, static_cast<int>(200 * alpha)), 2.f * z);
        }

        float text_y = tl.y + pad;
        for (auto& line : blk.instructions) {
            if (text_y + line_h > oy + height) break;
            if (text_y + line_h < oy) { text_y += line_h; continue; }

            char addr_buf[24];
            snprintf(addr_buf, sizeof(addr_buf), "%llX", static_cast<unsigned long long>(line.addr));

            ImU32 addr_col = _ta(_t.text_dim);
            ImU32 text_col = _ta(_t.text_primary);

            if (st.selected_row >= 0 && st.selected_row < static_cast<int>(disasm.file.instrs.size())
                && disasm.file.instrs[st.selected_row].addr == line.addr) {
                dl->AddRectFilled(ImVec2(tl.x + 2.f * z, text_y),
                    ImVec2(br.x - 2.f * z, text_y + line_h),
                    IM_COL32(ar, ag, ab, static_cast<int>(35 * alpha)));
                text_col = IM_COL32(255, 255, 255, static_cast<int>(255 * alpha));
            }

            dl->AddText(ImVec2(tl.x + pad, text_y), addr_col, addr_buf);
            dl->AddText(ImVec2(tl.x + pad + 90.f * z, text_y), text_col, line.text.c_str());

            text_y += line_h;
        }

        if (hov && ImGui::IsMouseHoveringRect(tl, br, false)) {
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                s_inline_cfg.selected_block = n.id;
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                goto_address(blk.start_addr, disasm);
        }
    }

    dl->PopClipRect();
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt) {

    auto& st    = g_state;


    if (disasm.live_mode && disasm.live_pending_ready.load(std::memory_order_acquire)) {

        driver_bridge::debug_log("disasm_view: live_pending_ready=TRUE, moving %llu instrs to display\n",
            (unsigned long long)disasm.live_pending_instrs.size());

        uint64_t scroll_addr = 0;
        if (st.selected_row >= 0 && st.selected_row < static_cast<int>(disasm.file.instrs.size()))
            scroll_addr = disasm.file.instrs[st.selected_row].addr;

        disasm.file.instrs = std::move(disasm.live_pending_instrs);
        disasm.file.image_base = disasm.live_pending_va;
        disasm.file.text_va    = disasm.live_pending_va;
        disasm.live_pending_ready.store(false, std::memory_order_release);


        if (scroll_addr != 0 && !disasm.file.instrs.empty()) {
            int lo = 0, hi = static_cast<int>(disasm.file.instrs.size()) - 1;
            int best = 0;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (disasm.file.instrs[mid].addr == scroll_addr) { best = mid; break; }
                if (disasm.file.instrs[mid].addr < scroll_addr) { best = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            st.selected_row = best;
        }
    }


    if (disasm.live_mode && !disasm.live_paused) {
        disasm.live_refresh_timer += dt;
        if (disasm.live_refresh_timer >= disasm.live_refresh_interval || disasm.live_needs_refresh) {
            disasm.live_refresh_timer = 0.f;
            disasm.live_needs_refresh = false;

            if (driver_bridge::attached_pid() != disasm.live_pid) {
                driver_bridge::debug_log("disasm_view: pid mismatch (attached=%u live=%u), stopping live\n",
                    driver_bridge::attached_pid(), disasm.live_pid);
                disasm::stop_live(disasm);
            } else if (disasm.live_fail_count < 5) {
                static int s_req_log = 0;
                if (s_req_log++ < 20)
                    driver_bridge::debug_log("disasm_view: triggering request_live_decode (fail_count=%d, decoding=%d)\n",
                        disasm.live_fail_count, disasm.live_decoding ? 1 : 0);
                disasm::request_live_decode(disasm);
            }
        }
    }

    auto& file  = disasm.file;
    auto& instrs = file.instrs;
    const float a = alpha;
    const auto& _t = themes::resolved;
    const auto _ta = [a](ImU32 c) -> ImU32 { return ui_anim::theme_alpha(c, a); };
    const int n = (int)instrs.size();

    if (n == 0) {


        if (disasm.live_mode || disasm.file.decoding) {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 wpos = ImGui::GetWindowPos();
            float ox = wpos.x + pos_x;
            float oy = wpos.y + pos_y;
            float cx = ox + width * 0.5f;
            float cy = oy + height * 0.5f;

            bool failed = disasm.live_mode && disasm.live_decode_failed && disasm.live_fail_count >= 3;

            {
                static int s_spinner_log = 0;
                if (s_spinner_log++ < 10)
                    driver_bridge::debug_log("disasm_view SPINNER: n=%d live_mode=%d decoding=%d failed=%d fail_count=%d pending_ready=%d paused=%d\n",
                        n, disasm.live_mode ? 1 : 0, disasm.live_decoding ? 1 : 0,
                        disasm.live_decode_failed ? 1 : 0, disasm.live_fail_count,
                        disasm.live_pending_ready.load() ? 1 : 0, disasm.live_paused ? 1 : 0);
            }

            if (failed) {
                const char* err_msg = "Failed to read process memory";
                ImVec2 es = ImGui::CalcTextSize(err_msg);
                dl->AddText(ImVec2(cx - es.x * 0.5f, cy - 20.f),
                    IM_COL32(230, 80, 80, static_cast<int>(200 * a)), err_msg);

                const char* hint = "Verify driver connection and process attachment";
                ImVec2 hs = ImGui::CalcTextSize(hint);
                dl->AddText(ImVec2(cx - hs.x * 0.5f, cy + 4.f),
                    _ta(_t.text_secondary), hint);

                const char* retry_label = "Retry";
                ImVec2 rs = ImGui::CalcTextSize(retry_label);
                float bw = rs.x + 24.f;
                float bh = 24.f;
                float bx = cx - bw * 0.5f;
                float by = cy + 30.f;
                bool btn_hov = ImGui::IsMouseHoveringRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh), false);
                dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
                    btn_hov ? IM_COL32(static_cast<int>(accent_r*255), static_cast<int>(accent_g*255),
                                       static_cast<int>(accent_b*255), static_cast<int>(60*a))
                            : _ta(_t.panel_bg), 4.f);
                dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
                    _ta(ui_anim::lighten(_t.panel_bg, 12)), 4.f);
                dl->AddText(ImVec2(bx + (bw - rs.x) * 0.5f, by + (bh - rs.y) * 0.5f),
                    btn_hov ? IM_COL32(static_cast<int>(accent_r*255), static_cast<int>(accent_g*255),
                                       static_cast<int>(accent_b*255), static_cast<int>(220*a))
                            : _ta(_t.text_primary), retry_label);
                if (btn_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    disasm.live_fail_count = 0;
                    disasm.live_decode_failed = false;
                    disasm.live_needs_refresh = true;
                }
            } else {
                static float spin = 0.f;
                spin += dt * 4.f;
                if (spin > 6.283185f) spin -= 6.283185f;

                for (int i = 0; i < 3; i++) {
                    float phase = spin + i * (6.283185f / 3.f);
                    float dot_a = (sinf(phase) * 0.5f + 0.5f) * 0.7f + 0.3f;
                    float bounce = sinf(phase) * 6.f;
                    dl->AddCircleFilled(
                        ImVec2(cx + (i - 1) * 18.f, cy - 14.f + bounce), 4.f,
                        IM_COL32(static_cast<int>(accent_r*200), static_cast<int>(accent_g*200),
                                 static_cast<int>(accent_b*200), static_cast<int>(255 * dot_a * a)));
                }

                const char* msg = disasm.live_mode
                    ? "Loading live disassembly..."
                    : "Decoding instructions...";
                ImVec2 ts = ImGui::CalcTextSize(msg);
                dl->AddText(ImVec2(cx - ts.x * 0.5f, cy + 6.f),
                    _ta(_t.text_secondary), msg);

                if (disasm.live_mode && disasm.live_fail_count > 0) {
                    char attempt_buf[48];
                    snprintf(attempt_buf, sizeof(attempt_buf), "Retry %d/5...", disasm.live_fail_count);
                    ImVec2 as = ImGui::CalcTextSize(attempt_buf);
                    dl->AddText(ImVec2(cx - as.x * 0.5f, cy + 6.f + ts.y + 8.f),
                        IM_COL32(200, 160, 80, static_cast<int>(160 * a)), attempt_buf);
                }

                const std::string& label = disasm.live_mode
                    ? disasm.live_module : disasm.file.filename;
                if (!label.empty()) {
                    float label_y = cy + 6.f + ImGui::CalcTextSize("A").y + 6.f;
                    if (disasm.live_mode && disasm.live_fail_count > 0)
                        label_y += ImGui::CalcTextSize("A").y + 2.f;
                    ImVec2 ms = ImGui::CalcTextSize(label.c_str());
                    dl->AddText(ImVec2(cx - ms.x * 0.5f, label_y),
                        _ta(_t.text_dim), label.c_str());
                }
            }
        }
        return;
    }

    st.graph_crossfade = ui_anim::smooth_lerp(st.graph_crossfade, st.graph_mode ? 1.f : 0.f, 10.f, dt);

    if (st.graph_mode || st.graph_crossfade > 0.01f) {
        float gf = st.graph_crossfade;
        float ga = alpha * gf;
        render_inline_graph(pos_x, pos_y, width, height, ga, accent_r, accent_g, accent_b, disasm, dt);

        ImDrawList* gdl = ImGui::GetWindowDrawList();
        ImVec2 gwp = ImGui::GetWindowPos();
        float badge_x = gwp.x + pos_x + width - 120.f;
        float badge_y = gwp.y + pos_y + 8.f;
        ui_anim::render_status_pill(gdl, badge_x, badge_y, "Graph View",
            IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                     static_cast<int>(accent_b * 255), 255), ga);

        if (gf >= 0.99f) {
            bool hovered_g = ImGui::IsMouseHoveringRect(
                ImVec2(ImGui::GetWindowPos().x + pos_x, ImGui::GetWindowPos().y + pos_y),
                ImVec2(ImGui::GetWindowPos().x + pos_x + width, ImGui::GetWindowPos().y + pos_y + height));

            if (hovered_g || st.goto_visible) {
                ImGuiIO& graph_hk_io = ImGui::GetIO();
                bool graph_hk_text_lock = graph_hk_io.WantTextInput
                    || graph_hk_io.WantCaptureKeyboard
                    || ImGui::IsAnyItemActive();
                if (graph_hk_io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false) && !graph_hk_text_lock)
                    st.goto_visible = !st.goto_visible;
                if (graph_hk_io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false) && !graph_hk_text_lock)
                    navigate_back();
                if (graph_hk_io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false) && !graph_hk_text_lock)
                    navigate_forward();

                if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
                    st.graph_mode = false;
                if (ImGui::IsKeyPressed(ImGuiKey_Space, false) && !graph_hk_text_lock)
                    st.graph_mode = false;
            }
        }

        render_xref_popup(ImGui::GetWindowPos().x + pos_x, ImGui::GetWindowPos().y + pos_y,
                          width, height, alpha, accent_r, accent_g, accent_b, disasm, dt);
        if (st.graph_mode)
            return;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;

    const float nav_band_h = 6.f;
    const float line_h = 18.f;

    {
        float bx0 = ox;
        float by0 = oy;
        float bx1 = ox + width;
        float by1 = oy + nav_band_h;

        dl->AddRectFilled(ImVec2(bx0, by0), ImVec2(bx1, by1),
            _ta(_t.bg_base));

        if (n > 0) {
            uint64_t range_start = instrs[0].addr;
            uint64_t range_end   = instrs[n - 1].addr + instrs[n - 1].len;
            uint64_t range       = range_end > range_start ? range_end - range_start : 1;

            float band_w = bx1 - bx0 - 2.f;
            float band_x = bx0 + 1.f;

            for (int i = 0; i < n; i += std::max(1, n / static_cast<int>(band_w))) {
                auto& ins = instrs[i];
                float t = static_cast<float>(ins.addr - range_start) / static_cast<float>(range);
                float px = band_x + t * band_w;

                ImU32 c;
                if (ins.is_call)
                    c = IM_COL32(static_cast<int>(accent_r * 200), static_cast<int>(accent_g * 200),
                                 static_cast<int>(accent_b * 200), static_cast<int>(200 * a));
                else if (ins.is_branch)
                    c = IM_COL32(120, 170, 100, static_cast<int>(180 * a));
                else if (ins.is_ret)
                    c = IM_COL32(200, 90, 90, static_cast<int>(200 * a));
                else if (ins.is_nop)
                    c = IM_COL32(50, 50, 55, static_cast<int>(100 * a));
                else
                    c = IM_COL32(80, 85, 120, static_cast<int>(160 * a));

                dl->AddRectFilled(ImVec2(px, by0 + 1.f), ImVec2(px + std::max(1.f, band_w / static_cast<float>(n) * 2.f), by1 - 1.f), c);
            }

            if (st.selected_row >= 0 && st.selected_row < n) {
                float sel_t = static_cast<float>(instrs[st.selected_row].addr - range_start) / static_cast<float>(range);
                float sel_x = band_x + sel_t * band_w;
                float cursor_w = std::max(3.f, band_w / static_cast<float>(n) * 8.f);
                dl->AddRectFilled(ImVec2(sel_x - cursor_w * 0.5f, by0),
                                  ImVec2(sel_x + cursor_w * 0.5f, by1),
                                  IM_COL32(255, 255, 255, static_cast<int>(200 * a)));
                dl->AddRectFilled(ImVec2(sel_x - 1.f, by0), ImVec2(sel_x + 1.f, by1),
                                  IM_COL32(static_cast<int>(accent_r * 255), static_cast<int>(accent_g * 255),
                                           static_cast<int>(accent_b * 255), static_cast<int>(255 * a)));
            }

            if (ImGui::IsMouseHoveringRect(ImVec2(bx0, by0), ImVec2(bx1, by1), false) &&
                ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float mx = ImGui::GetIO().MousePos.x - band_x;
                float click_t = mx / band_w;
                click_t = std::max(0.f, std::min(1.f, click_t));
                uint64_t target_addr = range_start + static_cast<uint64_t>(click_t * static_cast<float>(range));
                goto_address(target_addr, disasm);
            }
        }

        dl->AddLine(ImVec2(bx0, by1), ImVec2(bx1, by1),
            IM_COL32(255, 255, 255, static_cast<int>(8 * a)));
    }

    float oy_content = oy + nav_band_h;
    float content_height = height - nav_band_h;


    ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, dt);
    float max_scroll = std::max(0.f, n * line_h - content_height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));


    bool hovered = ImGui::IsMouseHoveringRect(ImVec2(ox, oy_content), ImVec2(ox + width, oy_content + content_height));
    if (hovered) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            st.target_scroll_y -= wheel * line_h * 3.f;
    }


    static float addr_col_w = 0.f;
    if (addr_col_w == 0.f)
        addr_col_w = ImGui::CalcTextSize("0000000140001000").x + 6.f;

    const float gutter_w = 20.f;
    const float x_addr = ox + gutter_w + 4.f;
    const float x_vsep = x_addr + addr_col_w;
    float x_bytes = x_vsep + 10.f;
    float bytes_col_w = st.show_bytes ? ImGui::CalcTextSize("00 00 00 00 00 00 00").x + 10.f : 0.f;
    const float x_mnem = x_bytes + bytes_col_w;
    const float x_ops  = x_mnem + 72.f;


    ImU32 ac_full = IM_COL32((int)(accent_r*255), (int)(accent_g*255),
                              (int)(accent_b*255), (int)(200*a));
    ImU32 ac_dim  = IM_COL32((int)(accent_r*255), (int)(accent_g*255),
                              (int)(accent_b*255), (int)(15*a));


    dl->AddLine(ImVec2(x_vsep, oy_content), ImVec2(x_vsep, oy_content + content_height),
                IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);
    if (st.show_bytes && bytes_col_w > 0.f) {
        dl->AddLine(ImVec2(x_mnem - 6.f, oy_content), ImVec2(x_mnem - 6.f, oy_content + content_height),
                    IM_COL32(255, 255, 255, (int)(6 * a)), 1.f);
    }

    int first_row = std::max(0, (int)(st.scroll_y / line_h) - 1);
    int last_row  = std::min(n - 1, (int)((st.scroll_y + content_height) / line_h) + 1);


    if (disasm.live_mode && n > 0) {
        int mid_row = (first_row + last_row) / 2;
        if (mid_row >= 0 && mid_row < n)
            disasm.live_view_addr = instrs[mid_row].addr;
    }

    for (int i = first_row; i <= last_row; i++) {
        float y = oy_content + i * line_h - st.scroll_y;
        const AsmInstr& ins = instrs[i];


        if (i & 1)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              IM_COL32(255, 255, 255, (int)(3.f * a)));


        bool row_hovered = ImGui::IsMouseHoveringRect(
            ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f), false);

        ImGuiID rhid = ImGui::GetID((void*)(intptr_t)(0xD000 + i));
        float rh = ImGui::GetStateStorage()->GetFloat(rhid, 0.f);
        rh += ((row_hovered ? 1.f : 0.f) - rh) * std::min(12.f * dt, 1.f);
        ImGui::GetStateStorage()->SetFloat(rhid, rh);

        if (rh > 0.002f)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              IM_COL32(255, 255, 255, (int)(rh * 12.f * a)));


        if (i == st.selected_row) {
            float pulse = (std::sin(static_cast<float>(ImGui::GetTime()) * 3.f) + 1.f) * 0.5f;
            float sel_a = 25.f + pulse * 15.f;
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              IM_COL32((int)(accent_r*180), (int)(accent_g*180),
                                       (int)(accent_b*180), (int)(sel_a * a)));
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + 3.f, y + line_h - 1.f),
                              IM_COL32((int)(accent_r*255), (int)(accent_g*255),
                                       (int)(accent_b*255), (int)((140.f + pulse * 60.f) * a)));
        }


        if (ins.is_branch || ins.is_call)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f), ac_dim);


        for (auto& bm : st.bookmarks) {
            if (bm.addr == ins.addr) {
                dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + 3.f, y + line_h),
                                  IM_COL32(220, 180, 100, (int)(200 * a)));
                break;
            }
        }


        char addr_buf[20];
        uint64_t display_addr = ins.addr;
        if (st.addr_format == addr_format_t::rva)
            display_addr = ins.addr - file.image_base;
        else if (st.addr_format == addr_format_t::file_offset)
            display_addr = ins.addr - file.text_va;
        snprintf(addr_buf, sizeof(addr_buf), "%016llX", (unsigned long long)display_addr);
        dl->AddText(ImVec2(x_addr, y + 1.f), IM_COL32(75, 95, 155, (int)(170 * a)), addr_buf);


        if (st.show_bytes) {
            char bytes_buf[64] = {};
            int boff = 0;
            for (int b = 0; b < ins.len && b < 7 && boff + 3 < 64; b++)
                boff += snprintf(bytes_buf + boff, 64 - boff, b ? " %02X" : "%02X", ins.raw[b]);
            if (ins.len > 7)
                snprintf(bytes_buf + boff, 64 - boff, "..");
            dl->AddText(ImVec2(x_bytes, y + 1.f),
                        _ta(_t.text_dim), bytes_buf);
        }


        ImU32 mc;
        if (ins.is_call)
            mc = ac_full;
        else if (ins.is_branch)
            mc = IM_COL32(152, 195, 121, (int)(230 * a));
        else if (ins.is_ret)
            mc = IM_COL32(224, 108, 117, (int)(230 * a));
        else if (ins.is_nop)
            mc = IM_COL32(100, 100, 110, (int)(140 * a));
        else if (ins.is_priv)
            mc = IM_COL32(220, 180, 100, (int)(230 * a));
        else
            mc = IM_COL32(200, 200, 240, (int)(235 * a));

        dl->AddText(ImVec2(x_mnem, y + 1.f), mc, ins.mnem);


        if (ins.ops[0]) {
            ImU32 oc;
            if (ins.is_branch || ins.is_call)
                oc = IM_COL32(210, 215, 255, (int)(160 * a));
            else if (ins.is_nop)
                oc = IM_COL32(80, 80, 90, (int)(120 * a));
            else if (ins.is_priv)
                oc = IM_COL32(200, 170, 95, (int)(180 * a));
            else
                oc = IM_COL32(165, 170, 190, (int)(210 * a));

            dl->AddText(ImVec2(x_ops, y + 1.f), oc, ins.ops);
        }


        if (ins.is_branch || ins.is_call) {

            uint64_t target = 0;
            const char* hex_p = strstr(ins.ops, "0x");
            if (!hex_p) hex_p = ins.ops;
            if (sscanf_s(hex_p, "%llx", &target) == 1 || sscanf_s(hex_p, "0x%llx", &target) == 1) {

                std::string sym_name = symbol_store::resolve_symbol(target);
                if (!sym_name.empty()) {
                    float ops_w = ImGui::CalcTextSize(ins.ops).x;
                    std::string label = "; " + sym_name;
                    dl->AddText(ImVec2(x_ops + ops_w + 12.f, y + 1.f),
                        IM_COL32(120, 180, 140, static_cast<int>(180 * a)), label.c_str());
                }

                if (!instrs.empty() && target >= instrs.front().addr && target <= instrs.back().addr) {
                    float arrow_x = ox + width - 16.f;
                    dl->AddTriangleFilled(
                        ImVec2(arrow_x, y + 4.f),
                        ImVec2(arrow_x + 8.f, y + line_h * 0.5f),
                        ImVec2(arrow_x, y + line_h - 4.f),
                        IM_COL32(100, 160, 100, (int)(120 * a)));
                }
            }
        }


        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            st.selected_row = i;
        }


        if (row_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            if (ins.is_branch || ins.is_call) {
                uint64_t target = 0;
                const char* hex_p = strstr(ins.ops, "0x");
                if (!hex_p) hex_p = ins.ops;
                if (sscanf_s(hex_p, "%llx", &target) == 1 || sscanf_s(hex_p, "0x%llx", &target) == 1) {
                    goto_address(target, disasm);
                }
            }
        }


        if (row_hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            st.ctx_row = i;
            ImGui::OpenPopup("##disasm_view_ctx");
        }
    }

    {
        struct branch_vis_t { float from_y; float to_y; ImU32 color; };
        std::vector<branch_vis_t> bv;
        for (int bi = first_row; bi <= last_row; ++bi) {
            const AsmInstr& bins = instrs[bi];
            if (!bins.is_branch && !bins.is_call) continue;
            uint64_t btarget = 0;
            const char* bhex = strstr(bins.ops, "0x");
            if (!bhex) bhex = bins.ops;
            if (sscanf_s(bhex, "%llx", &btarget) != 1)
                if (sscanf_s(bhex, "0x%llx", &btarget) != 1)
                    continue;
            int tidx = find_instr_at(btarget, file);
            if (tidx < first_row || tidx > last_row) continue;
            float fy = oy_content + static_cast<float>(bi) * line_h - st.scroll_y + line_h * 0.5f;
            float ty = oy_content + static_cast<float>(tidx) * line_h - st.scroll_y + line_h * 0.5f;
            ImU32 bcol;
            if (bins.is_call)
                bcol = IM_COL32(200, 120, 100, 180);
            else if (strcmp(bins.mnem, "jmp") == 0)
                bcol = ui_anim::accent_col_u8(accent_r, accent_g, accent_b, 180);
            else
                bcol = IM_COL32(100, 200, 120, 180);
            bv.push_back({fy, ty, bcol});
        }
        float gx = ox + 2.f;
        for (auto& ba : bv)
            ui_anim::render_branch_arrow(dl, gx, ba.from_y, ba.to_y, gutter_w, ba.color, 1.f);
    }


    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 6.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.10f, 0.11f, 0.15f, 0.97f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.22f, 0.24f, 0.30f, 0.5f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(accent_r * 0.3f, accent_g * 0.3f, accent_b * 0.3f, 0.25f));

    if (ImGui::BeginPopup("##disasm_view_ctx")) {
        if (st.ctx_row >= 0 && st.ctx_row < n) {
            const AsmInstr& ci = instrs[st.ctx_row];


            if (ImGui::MenuItem("Copy Address")) {
                char buf[20];
                snprintf(buf, sizeof(buf), "%016llX", (unsigned long long)ci.addr);
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }


            if (ImGui::MenuItem("Copy Bytes")) {
                char buf[64] = {};
                int boff2 = 0;
                for (int b = 0; b < ci.len && boff2 + 3 < 64; b++)
                    boff2 += snprintf(buf + boff2, 64 - boff2, b ? " %02X" : "%02X", ci.raw[b]);
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }


            if (ImGui::MenuItem("Copy Instruction")) {
                char buf[256];
                if (ci.ops[0])
                    snprintf(buf, sizeof(buf), "%016llX  %-8s %s",
                             (unsigned long long)ci.addr, ci.mnem, ci.ops);
                else
                    snprintf(buf, sizeof(buf), "%016llX  %s",
                             (unsigned long long)ci.addr, ci.mnem);
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(buf) + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), buf, strlen(buf) + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }

            ImGui::Separator();


            bool has_bm = false;
            int bm_idx = -1;
            for (int bi = 0; bi < (int)st.bookmarks.size(); bi++) {
                if (st.bookmarks[bi].addr == ci.addr) { has_bm = true; bm_idx = bi; break; }
            }
            if (has_bm) {
                if (ImGui::MenuItem("Remove Bookmark")) {
                    st.bookmarks.erase(st.bookmarks.begin() + bm_idx);
                }
            } else {
                if (ImGui::MenuItem("Add Bookmark")) {
                    bookmark_t bm;
                    bm.addr = ci.addr;
                    char lbl[32];
                    snprintf(lbl, sizeof(lbl), "0x%llX", (unsigned long long)ci.addr);
                    bm.label = lbl;
                    st.bookmarks.push_back(bm);
                }
            }


            if (ci.is_branch || ci.is_call) {
                if (ImGui::MenuItem("Follow Target")) {
                    uint64_t target = 0;
                    const char* hex_p = strstr(ci.ops, "0x");
                    if (!hex_p) hex_p = ci.ops;
                    if (sscanf_s(hex_p, "%llx", &target) == 1 || sscanf_s(hex_p, "0x%llx", &target) == 1)
                        goto_address(target, disasm);
                }
            }

            ImGui::Separator();


            if (ImGui::MenuItem("VA Format", nullptr, st.addr_format == addr_format_t::va))
                st.addr_format = addr_format_t::va;
            if (ImGui::MenuItem("RVA Format", nullptr, st.addr_format == addr_format_t::rva))
                st.addr_format = addr_format_t::rva;

            if (ImGui::MenuItem("Show Bytes", nullptr, st.show_bytes))
                st.show_bytes = !st.show_bytes;

            ImGui::Separator();

            if (ImGui::MenuItem("Decompile Function")) {
                globals::ui::decompile_popup_addr = ci.addr;
                if (globals::ui::decompile_default_mode == 0) {
                    decompiler_engine::decompile_function(ci.addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else if (globals::ui::decompile_default_mode == 1) {
                    decompiler_engine::decompile_function_native(ci.addr);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else if (globals::ui::decompile_default_mode == 2) {
                    decompiler_engine::decompile_function_hybrid(ci.addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                } else {
                    globals::ui::show_decompile_popup = true;
                }
            }
            if (ImGui::MenuItem("Reconstruct Source")) {
                source_reconstruct_view::open();
            }
            if (ImGui::MenuItem("Generate AOB Signature")) {
                char addr_buf[32];
                snprintf(addr_buf, sizeof(addr_buf), "%llX", (unsigned long long)ci.addr);
                strncpy(aob_generator::g_state.address_input, addr_buf, sizeof(aob_generator::g_state.address_input) - 1);
                aob_generator::generate_from_address(ci.addr, aob_generator::g_state.instruction_count, aob_generator::g_state.auto_wildcard);
                scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
                globals::ui::active_center_view = center_view_t::scan_hub;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(3);


    if (hovered || st.goto_visible) {
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false))
            st.goto_visible = !st.goto_visible;


        if (ImGui::GetIO().KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false))
            navigate_back();
        if (ImGui::GetIO().KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false))
            navigate_forward();

        if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
            uint64_t f5_addr = 0;
            if (st.ctx_row >= 0 && st.ctx_row < n)
                f5_addr = instrs[st.ctx_row].addr;
            if (f5_addr == 0 && !instrs.empty())
                f5_addr = instrs[0].addr;
            if (f5_addr != 0)
                globals::ui::decompile_popup_addr = f5_addr;
            if (globals::ui::decompile_default_mode == 0) {
                if (f5_addr)
                    decompiler_engine::decompile_function(f5_addr, g_sa_settings);
                globals::ui::active_center_view = center_view_t::decompiler;
            } else if (globals::ui::decompile_default_mode == 1) {
                if (f5_addr)
                    decompiler_engine::decompile_function_native(f5_addr);
                globals::ui::active_center_view = center_view_t::decompiler;
            } else if (globals::ui::decompile_default_mode == 2) {
                if (f5_addr)
                    decompiler_engine::decompile_function_hybrid(f5_addr, g_sa_settings);
                globals::ui::active_center_view = center_view_t::decompiler;
            } else {
                globals::ui::show_decompile_popup = true;
            }
        }

        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            if (st.xref_popup_open) {
                st.xref_popup_open = false;
            } else if (st.graph_mode) {
                st.graph_mode = false;
            } else {
                st.goto_visible = false;
            }
        }

        ImGuiIO& disasm_hk_io = ImGui::GetIO();
        bool disasm_hk_text_lock = disasm_hk_io.WantTextInput
            || disasm_hk_io.WantCaptureKeyboard
            || ImGui::IsAnyItemActive();
        if (!st.xref_popup_open && !st.goto_visible && !disasm_hk_io.KeyCtrl && !disasm_hk_io.KeyAlt
            && !disasm_hk_text_lock) {
            if (ImGui::IsKeyPressed(ImGuiKey_X, false)) {
                int row = st.selected_row;
                if (row >= 0 && row < n) {
                    uint64_t addr = instrs[row].addr;
                    st.xref_popup_addr = addr;
                    st.xref_popup_open = true;
                    st.xref_popup_fade = 0.f;
                    st.xref_popup_scroll = 0.f;
                    st.xref_popup_target_scroll = 0.f;
                    st.xref_popup_selected = -1;
                    {
                        std::lock_guard<std::mutex> lk(st.xref_mutex);
                        st.xref_results.clear();
                    }
                    launch_xref_scan(addr);
                }
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
                st.graph_mode = !st.graph_mode;
                if (st.graph_mode) {
                    uint64_t entry = 0;
                    if (st.selected_row >= 0 && st.selected_row < n)
                        entry = instrs[st.selected_row].addr;
                    else if (n > 0)
                        entry = instrs[0].addr;
                    if (entry != 0) {
                        st.cfg_entry_addr = entry;
                        st.cfg_needs_build = true;
                    }
                }
            }

            if (ImGui::IsKeyPressed(ImGuiKey_G, false) && !ImGui::GetIO().KeyCtrl) {
                st.goto_visible = !st.goto_visible;
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
                uint64_t tab_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < n)
                    tab_addr = instrs[st.selected_row].addr;
                else if (n > 0)
                    tab_addr = instrs[0].addr;
                if (tab_addr != 0) {
                    globals::ui::decompile_popup_addr = tab_addr;
                    if (globals::ui::decompile_default_mode == 0)
                        decompiler_engine::decompile_function(tab_addr, g_sa_settings);
                    else if (globals::ui::decompile_default_mode == 1)
                        decompiler_engine::decompile_function_native(tab_addr);
                    else
                        decompiler_engine::decompile_function_hybrid(tab_addr, g_sa_settings);
                    globals::ui::active_center_view = center_view_t::decompiler;
                }
            }

            if (ImGui::IsKeyPressed(ImGuiKey_N, false)) {
                int row = st.selected_row;
                if (row >= 0 && row < n) {
                    uint64_t addr = instrs[row].addr;
                    char label_buf[32];
                    snprintf(label_buf, sizeof(label_buf), "0x%llX", static_cast<unsigned long long>(addr));
                    bool already = false;
                    for (auto& bm : st.bookmarks) {
                        if (bm.addr == addr) { already = true; break; }
                    }
                    if (!already) {
                        bookmark_t bm;
                        bm.addr = addr;
                        bm.label = label_buf;
                        st.bookmarks.push_back(bm);
                    }
                }
            }
        }
    }


    if (st.goto_visible) {
        float gy = oy_content + 4.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(ox + 10.f, gy), ImVec2(ox + 260.f, gy + 30.f),
            _ta(_t.panel_bg), 6.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 8.f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.14f, 0.9f));
        ImGui::PushItemWidth(150.f);
        bool go = ImGui::InputText("##disasm_goto", st.goto_buf, sizeof(st.goto_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::PopItemWidth();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        ImGui::SameLine();
        if (ImGui::SmallButton("Go##disasm") || go) {
            uint64_t addr = 0;
            sscanf_s(st.goto_buf, "%llx", &addr);
            goto_address(addr, disasm);
            st.goto_visible = false;
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("<##back"))  navigate_back();
        ImGui::SameLine();
        if (ImGui::SmallButton(">##fwd"))   navigate_forward();
    }


    if (!st.bookmarks.empty()) {
        float bm_y = oy_content + content_height - 22.f;
        dl->AddRectFilled(ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + 20.f),
                          _ta(_t.bg_base));


        float total_bm_w = 6.f;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            total_bm_w += ts.x + 12.f + 4.f;
        }
        float max_scroll = std::max(0.f, total_bm_w - width + 6.f);


        bool bm_bar_hov = ImGui::IsMouseHoveringRect(
            ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + 20.f));
        if (bm_bar_hov && max_scroll > 0.f) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f)
                st.bm_scroll_x = std::max(0.f, std::min(max_scroll, st.bm_scroll_x - wheel * 40.f));
        }
        if (st.bm_scroll_x > max_scroll) st.bm_scroll_x = max_scroll;

        float bm_x = ox + 6.f - st.bm_scroll_x;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            float btn_w = ts.x + 12.f;

            if (bm_x + btn_w >= ox && bm_x <= ox + width) {
                bool bm_hv = ImGui::IsMouseHoveringRect(
                    ImVec2(std::max(bm_x, ox), bm_y + 1.f),
                    ImVec2(std::min(bm_x + btn_w, ox + width), bm_y + 19.f));
                if (bm_hv)
                    dl->AddRectFilled(ImVec2(bm_x, bm_y + 1.f), ImVec2(bm_x + btn_w, bm_y + 19.f),
                                      IM_COL32(255, 255, 255, (int)(15 * a)), 3.f);
                dl->AddText(ImVec2(bm_x + 6.f, bm_y + 3.f),
                            IM_COL32(220, 180, 100, (int)(200 * a)), bm.label.c_str());
                if (bm_hv && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    goto_address(bm.addr, disasm);
            }
            bm_x += btn_w + 4.f;
        }


        if (st.bm_scroll_x > 0.f) {
            for (int gi = 0; gi < 20; gi++) {
                float ga = (1.f - gi / 20.f) * a;
                dl->AddLine(ImVec2(ox + static_cast<float>(gi), bm_y),
                            ImVec2(ox + static_cast<float>(gi), bm_y + 20.f),
                            ui_anim::theme_alpha(_t.bg_base, ga));
            }
        }
        if (st.bm_scroll_x < max_scroll) {
            for (int gi = 0; gi < 20; gi++) {
                float ga = (1.f - gi / 20.f) * a;
                dl->AddLine(ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y),
                            ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y + 20.f),
                            ui_anim::theme_alpha(_t.bg_base, ga));
            }
        }
    }


    if (disasm.live_mode) {
        float ind_w = 280.f, ind_h = 26.f;
        float ix = ox + width - ind_w - 14.f;
        float iy = oy_content + 6.f;


        dl->AddRectFilled(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            _ta(_t.bg_base), 13.f);
        dl->AddRect(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            _ta(ui_anim::lighten(_t.panel_bg, 12)), 13.f);


        float dot_x = ix + 14.f, dot_y = iy + ind_h * 0.5f;
        ImU32 dot_col = disasm.live_paused
            ? IM_COL32(200, 180, 60, static_cast<int>(200 * a))
            : IM_COL32(60, 220, 80, static_cast<int>(255 * a));
        ui_anim::render_status_dot(dl, dot_x, dot_y, 4.f, dot_col,
            static_cast<float>(ImGui::GetTime()), !disasm.live_paused);


        const char* status_txt = disasm.live_paused ? "PAUSED" : "LIVE";
        dl->AddText(ImVec2(dot_x + 10.f, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            disasm.live_paused
                ? IM_COL32(200, 180, 60, (int)(200 * a))
                : IM_COL32(60, 220, 80, (int)(220 * a)),
            status_txt);


        float label_x = dot_x + 10.f + ImGui::CalcTextSize(status_txt).x + 8.f;
        std::string mod_short = disasm.live_module;
        if (mod_short.size() > 18) mod_short = mod_short.substr(0, 15) + "...";
        dl->AddText(ImVec2(label_x, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            _ta(_t.text_secondary), mod_short.c_str());


        float btn_x = ix + ind_w - 56.f;
        float btn_y = iy + 3.f;
        float btn_w2 = 48.f, btn_h2 = ind_h - 6.f;
        bool btn_hov = ImGui::IsMouseHoveringRect(
            ImVec2(btn_x, btn_y), ImVec2(btn_x + btn_w2, btn_y + btn_h2));
        dl->AddRectFilled(ImVec2(btn_x, btn_y), ImVec2(btn_x + btn_w2, btn_y + btn_h2),
            btn_hov ? IM_COL32(255, 255, 255, (int)(25 * a))
                    : IM_COL32(255, 255, 255, (int)(10 * a)), 6.f);
        const char* btn_lbl = disasm.live_paused ? "Play" : "Pause";
        ImVec2 bts = ImGui::CalcTextSize(btn_lbl);
        dl->AddText(ImVec2(btn_x + (btn_w2 - bts.x) * 0.5f, btn_y + (btn_h2 - bts.y) * 0.5f),
            _ta(_t.text_primary), btn_lbl);
        if (btn_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            disasm.live_paused = !disasm.live_paused;
            if (!disasm.live_paused)
                disasm.live_needs_refresh = true;
        }
    }


    {
        float total_content = n * line_h;
        if (total_content > content_height) {
            const float sb_w = 10.f;
            const float sb_pad = 2.f;
            float track_x = ox + width - sb_w - sb_pad;
            float track_y0 = oy_content + sb_pad;
            float track_h  = content_height - sb_pad * 2.f;

            float ratio = content_height / total_content;
            float thumb_h = std::max(20.f, track_h * ratio);
            float scroll_range = total_content - content_height;
            float thumb_y = track_y0 + (scroll_range > 0.f ? (st.scroll_y / scroll_range) * (track_h - thumb_h) : 0.f);

            bool sb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(track_x - 4.f, track_y0), ImVec2(track_x + sb_w + 4.f, track_y0 + track_h));

            ImGuiID sb_hov_id = ImGui::GetID("##disasm_sb_hov");
            float sb_a = ImGui::GetStateStorage()->GetFloat(sb_hov_id, 0.f);
            sb_a += ((sb_hov || st.sb_dragging ? 1.f : 0.f) - sb_a) * std::min(14.f * dt, 1.f);
            ImGui::GetStateStorage()->SetFloat(sb_hov_id, sb_a);

            if (sb_a > 0.01f) {
                dl->AddRectFilled(ImVec2(track_x, track_y0), ImVec2(track_x + sb_w, track_y0 + track_h),
                    IM_COL32(255, 255, 255, (int)(8.f * sb_a * a)), 3.f);

                bool thumb_hov = ImGui::IsMouseHoveringRect(
                    ImVec2(track_x - 2.f, thumb_y), ImVec2(track_x + sb_w + 2.f, thumb_y + thumb_h));
                int thumb_alpha = thumb_hov || st.sb_dragging ? (int)(120.f * sb_a * a) : (int)(60.f * sb_a * a);
                dl->AddRectFilled(ImVec2(track_x, thumb_y), ImVec2(track_x + sb_w, thumb_y + thumb_h),
                    IM_COL32(200, 200, 220, thumb_alpha), 3.f);
            }

            if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float my = ImGui::GetIO().MousePos.y;
                if (my < thumb_y || my > thumb_y + thumb_h) {
                    float click_ratio = (my - track_y0 - thumb_h * 0.5f) / (track_h - thumb_h);
                    click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                    st.target_scroll_y = click_ratio * scroll_range;
                }
                st.sb_dragging = true;
                st.sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
            }

            if (st.sb_dragging) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    float my = ImGui::GetIO().MousePos.y - st.sb_drag_offset;
                    float drag_ratio = (my - track_y0) / (track_h - thumb_h);
                    drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                    st.target_scroll_y = drag_ratio * scroll_range;
                    st.scroll_y = st.target_scroll_y;
                } else {
                    st.sb_dragging = false;
                }
            }
        }
    }

    render_xref_popup(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b, disasm, dt);
}

}
