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

    // Live disassembly: periodic refresh
    if (disasm.live_mode && !disasm.live_paused) {
        disasm.live_refresh_timer += dt;
        if (disasm.live_refresh_timer >= disasm.live_refresh_interval || disasm.live_needs_refresh) {
            disasm.live_refresh_timer = 0.f;
            disasm.live_needs_refresh = false;

            // Check if process is still attached
            if (driver_bridge::attached_pid() != disasm.live_pid) {
                disasm::stop_live(disasm);
            } else {
                // Preserve scroll position across refresh
                uint64_t scroll_addr = 0;
                if (st.selected_row >= 0 && st.selected_row < static_cast<int>(disasm.file.instrs.size()))
                    scroll_addr = disasm.file.instrs[st.selected_row].addr;

                disasm::decode_live(disasm);

                // Restore selected row to same address via binary search
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
        }
    }

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

        // Calculate total bookmark width
        float total_bm_w = 6.f;
        for (auto& bm : st.bookmarks) {
            ImVec2 ts = ImGui::CalcTextSize(bm.label.c_str());
            total_bm_w += ts.x + 12.f + 4.f;
        }
        float max_scroll = std::max(0.f, total_bm_w - width + 6.f);

        // Scroll on mouse wheel when hovering bookmark bar
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
            // Skip rendering if fully outside visible area
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

        // Fade gradients at edges when scrolled
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


    // Live disassembly indicator and controls
    if (disasm.live_mode) {
        float ind_w = 280.f, ind_h = 26.f;
        float ix = ox + width - ind_w - 14.f;
        float iy = oy + 6.f;

        // Background pill
        dl->AddRectFilled(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            IM_COL32(15, 15, 22, (int)(220 * a)), 13.f);
        dl->AddRect(ImVec2(ix, iy), ImVec2(ix + ind_w, iy + ind_h),
            IM_COL32(80, 80, 120, (int)(40 * a)), 13.f);

        // Pulsing live dot
        static float pulse = 0.f;
        pulse += dt * 3.f;
        if (pulse > 6.283f) pulse -= 6.283f;
        float pulse_a = 0.6f + 0.4f * sinf(pulse);
        if (disasm.live_paused) pulse_a = 0.3f;

        ImU32 dot_col = disasm.live_paused
            ? IM_COL32(200, 180, 60, (int)(180 * pulse_a * a))
            : IM_COL32(60, 220, 80, (int)(255 * pulse_a * a));
        float dot_x = ix + 14.f, dot_y = iy + ind_h * 0.5f;
        dl->AddCircleFilled(ImVec2(dot_x, dot_y), 4.f, dot_col);

        // Label
        const char* status_txt = disasm.live_paused ? "PAUSED" : "LIVE";
        dl->AddText(ImVec2(dot_x + 10.f, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            disasm.live_paused
                ? IM_COL32(200, 180, 60, (int)(200 * a))
                : IM_COL32(60, 220, 80, (int)(220 * a)),
            status_txt);

        // Module name
        float label_x = dot_x + 10.f + ImGui::CalcTextSize(status_txt).x + 8.f;
        std::string mod_short = disasm.live_module;
        if (mod_short.size() > 18) mod_short = mod_short.substr(0, 15) + "...";
        dl->AddText(ImVec2(label_x, iy + (ind_h - ImGui::GetFontSize()) * 0.5f),
            IM_COL32(160, 160, 180, (int)(180 * a)), mod_short.c_str());

        // Pause/Resume button
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
