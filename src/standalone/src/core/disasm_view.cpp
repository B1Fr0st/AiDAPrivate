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
#include "ui_anim.hpp"
#include "decompiler_engine.hpp"
#include "aob_generator.hpp"
#include "scan_hub_view.hpp"
#include "standalone_settings.hpp"
#include "symbol_store.hpp"

namespace disasm_view {


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

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt) {

    auto& st    = g_state;


    if (disasm.live_mode && disasm.live_pending_ready.load(std::memory_order_acquire)) {

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
                disasm::stop_live(disasm);
            } else if (disasm.live_fail_count < 5) {
                disasm::request_live_decode(disasm);
            }
        }
    }

    auto& file  = disasm.file;
    auto& instrs = file.instrs;
    const float a = alpha;
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

            if (failed) {
                const char* err_msg = "Failed to read process memory";
                ImVec2 es = ImGui::CalcTextSize(err_msg);
                dl->AddText(ImVec2(cx - es.x * 0.5f, cy - 20.f),
                    IM_COL32(230, 80, 80, static_cast<int>(200 * a)), err_msg);

                const char* hint = "Verify driver connection and process attachment";
                ImVec2 hs = ImGui::CalcTextSize(hint);
                dl->AddText(ImVec2(cx - hs.x * 0.5f, cy + 4.f),
                    IM_COL32(140, 140, 160, static_cast<int>(150 * a)), hint);

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
                            : IM_COL32(40, 42, 55, static_cast<int>(180*a)), 4.f);
                dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh),
                    IM_COL32(80, 85, 100, static_cast<int>(140*a)), 4.f);
                dl->AddText(ImVec2(bx + (bw - rs.x) * 0.5f, by + (bh - rs.y) * 0.5f),
                    btn_hov ? IM_COL32(static_cast<int>(accent_r*255), static_cast<int>(accent_g*255),
                                       static_cast<int>(accent_b*255), static_cast<int>(220*a))
                            : IM_COL32(200, 200, 210, static_cast<int>(180*a)), retry_label);
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
                    IM_COL32(160, 160, 180, static_cast<int>(180 * a)), msg);

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
                        IM_COL32(120, 120, 140, static_cast<int>(140 * a)), label.c_str());
                }
            }
        }
        return;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;

    const float line_h = 18.f;


    ui_anim::smooth_scroll(st.scroll_y, st.target_scroll_y, 20.f, dt);
    float max_scroll = std::max(0.f, n * line_h - height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));


    bool hovered = ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + width, oy + height));
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


    dl->AddLine(ImVec2(x_vsep, oy), ImVec2(x_vsep, oy + height),
                IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);
    if (st.show_bytes && bytes_col_w > 0.f) {
        dl->AddLine(ImVec2(x_mnem - 6.f, oy), ImVec2(x_mnem - 6.f, oy + height),
                    IM_COL32(255, 255, 255, (int)(6 * a)), 1.f);
    }

    int first_row = std::max(0, (int)(st.scroll_y / line_h) - 1);
    int last_row  = std::min(n - 1, (int)((st.scroll_y + height) / line_h) + 1);


    if (disasm.live_mode && n > 0) {
        int mid_row = (first_row + last_row) / 2;
        if (mid_row >= 0 && mid_row < n)
            disasm.live_view_addr = instrs[mid_row].addr;
    }

    for (int i = first_row; i <= last_row; i++) {
        float y = oy + i * line_h - st.scroll_y;
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


        if (i == st.selected_row)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              IM_COL32((int)(accent_r*180), (int)(accent_g*180),
                                       (int)(accent_b*180), (int)(30 * a)));


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
                        IM_COL32(100, 100, 120, (int)(120 * a)), bytes_buf);
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
            float fy = oy + static_cast<float>(bi) * line_h - st.scroll_y + line_h * 0.5f;
            float ty = oy + static_cast<float>(tidx) * line_h - st.scroll_y + line_h * 0.5f;
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


    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 7.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 6.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.11f, 0.11f, 0.15f, 1.f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.f, 1.f, 1.f, 0.08f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1.f, 1.f, 1.f, 0.07f));

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

        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
            st.goto_visible = false;
    }


    if (st.goto_visible) {
        float gy = oy + 4.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(ox + 10.f, gy), ImVec2(ox + 260.f, gy + 30.f),
            IM_COL32(30, 30, 40, (int)(240 * a)), 6.f);

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
        float bm_y = oy + height - 22.f;
        dl->AddRectFilled(ImVec2(ox, bm_y), ImVec2(ox + width, bm_y + 20.f),
                          IM_COL32(20, 20, 30, (int)(200 * a)));


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
                            IM_COL32(20, 20, 30, (int)(200 * ga)));
            }
        }
        if (st.bm_scroll_x < max_scroll) {
            for (int gi = 0; gi < 20; gi++) {
                float ga = (1.f - gi / 20.f) * a;
                dl->AddLine(ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y),
                            ImVec2(ox + width - 1.f - static_cast<float>(gi), bm_y + 20.f),
                            IM_COL32(20, 20, 30, (int)(200 * ga)));
            }
        }
    }


    if (disasm.live_mode) {
        float ind_w = 280.f, ind_h = 26.f;
        float ix = ox + width - ind_w - 14.f;
        float iy = oy + 6.f;


        dl->AddRectFilled(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            IM_COL32(15, 15, 22, (int)(220 * a)), 13.f);
        dl->AddRect(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            IM_COL32(80, 80, 120, (int)(40 * a)), 13.f);


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
            IM_COL32(160, 160, 180, (int)(180 * a)), mod_short.c_str());


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
            IM_COL32(200, 200, 220, (int)(200 * a)), btn_lbl);
        if (btn_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            disasm.live_paused = !disasm.live_paused;
            if (!disasm.live_paused)
                disasm.live_needs_refresh = true;
        }
    }


    {
        float total_content = n * line_h;
        if (total_content > height) {
            const float sb_w = 10.f;
            const float sb_pad = 2.f;
            float track_x = ox + width - sb_w - sb_pad;
            float track_y0 = oy + sb_pad;
            float track_h  = height - sb_pad * 2.f;

            float ratio = height / total_content;
            float thumb_h = std::max(20.f, track_h * ratio);
            float scroll_range = total_content - height;
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
}

}
