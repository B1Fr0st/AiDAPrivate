#include "disasm_view.hpp"
#include "zydis_disasm.hpp"
#include "../helpers/globals.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

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
    auto& file  = disasm.file;
    auto& instrs = file.instrs;
    const float a = alpha;
    const int n = (int)instrs.size();

    if (n == 0) return;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;

    const float line_h = 18.f;


    st.scroll_y += (st.target_scroll_y - st.scroll_y) * std::min(20.f * dt, 1.f);
    if (std::abs(st.target_scroll_y - st.scroll_y) < 0.5f)
        st.scroll_y = st.target_scroll_y;
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

    const float x_addr = ox + 4.f;
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


    ImGui::SetCursorPos(ImVec2(pos_x, pos_y + n * line_h));
    ImGui::Dummy(ImVec2(1.f, 1.f));


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
        float bm_x = ox + 6.f;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            float btn_w = ts.x + 12.f;
            bool bm_hv = ImGui::IsMouseHoveringRect(
                ImVec2(bm_x, bm_y + 1.f), ImVec2(bm_x + btn_w, bm_y + 19.f));
            if (bm_hv)
                dl->AddRectFilled(ImVec2(bm_x, bm_y + 1.f), ImVec2(bm_x + btn_w, bm_y + 19.f),
                                  IM_COL32(255, 255, 255, (int)(15 * a)), 3.f);
            dl->AddText(ImVec2(bm_x + 6.f, bm_y + 3.f),
                        IM_COL32(220, 180, 100, (int)(200 * a)), bm.label.c_str());
            if (bm_hv && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                goto_address(bm.addr, disasm);
            bm_x += btn_w + 4.f;
        }
    }
}

}
