#include "hex_view.hpp"
#include "../helpers/globals.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace hex_view {

void set_data(const std::vector<uint8_t>& bytes, uint64_t base_addr,
              const std::string& name) {
    g_state.data       = bytes;
    g_state.base_addr  = base_addr;
    g_state.source_name = name;
    g_state.active     = true;
    g_state.sel_start  = -1;
    g_state.sel_end    = -1;
    g_state.scroll_y   = 0.f;
    g_state.target_scroll_y = 0.f;
}

void load_from_file(const std::string& path, size_t offset, size_t size) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return;
    size_t fsize = (size_t)f.tellg();
    if (offset >= fsize) return;
    f.seekg((std::streamoff)offset);
    size_t read_sz = (size > 0 && offset + size <= fsize) ? size : (fsize - offset);
    std::vector<uint8_t> buf(read_sz);
    f.read((char*)buf.data(), (std::streamsize)read_sz);
    auto pos = path.find_last_of("/\\");
    std::string name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
    set_data(buf, (uint64_t)offset, name);
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    if (!g_state.active || g_state.data.empty()) return;

    auto& st = g_state;
    const float a   = alpha;
    const float dt  = ImGui::GetIO().DeltaTime;
    const float line_h = 18.f;
    const float char_w = ImGui::CalcTextSize("0").x;
    const int   bytes_per_row = 16;
    const int   total_rows = ((int)st.data.size() + bytes_per_row - 1) / bytes_per_row;


    const float addr_w = char_w * 17.f;
    const float hex_w  = char_w * 50.f;
    const float asc_x  = addr_w + hex_w + char_w * 2.f;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;


    st.scroll_y += (st.target_scroll_y - st.scroll_y) * std::min(20.f * dt, 1.f);
    if (std::abs(st.target_scroll_y - st.scroll_y) < 0.5f)
        st.scroll_y = st.target_scroll_y;
    float max_scroll = std::max(0.f, total_rows * line_h - height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));


    bool hovered = ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + width, oy + height));
    if (hovered) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            st.target_scroll_y -= wheel * line_h * 3.f;
    }


    int first_row = std::max(0, (int)(st.scroll_y / line_h) - 1);
    int last_row  = std::min(total_rows - 1, (int)((st.scroll_y + height) / line_h) + 1);


    dl->AddLine(ImVec2(ox + addr_w - char_w, oy),
                ImVec2(ox + addr_w - char_w, oy + height),
                IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);
    dl->AddLine(ImVec2(ox + addr_w + hex_w, oy),
                ImVec2(ox + addr_w + hex_w, oy + height),
                IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);


    int sel_lo = -1, sel_hi = -1;
    if (st.sel_start >= 0 && st.sel_end >= 0) {
        sel_lo = std::min(st.sel_start, st.sel_end);
        sel_hi = std::max(st.sel_start, st.sel_end);
    }
    ImU32 sel_col = IM_COL32((int)(accent_r * 180), (int)(accent_g * 180),
                              (int)(accent_b * 180), (int)(50 * a));

    for (int row = first_row; row <= last_row; row++) {
        float y = oy + row * line_h - st.scroll_y;
        int row_off = row * bytes_per_row;


        if (row & 1)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              IM_COL32(255, 255, 255, (int)(3.f * a)));


        char addr_buf[20];
        snprintf(addr_buf, sizeof(addr_buf), "%016llX",
                 (unsigned long long)(st.base_addr + row_off));
        dl->AddText(ImVec2(ox + 4.f, y + 1.f),
                    IM_COL32(75, 95, 155, (int)(170 * a)), addr_buf);


        for (int col = 0; col < bytes_per_row; col++) {
            int byte_idx = row_off + col;
            if (byte_idx >= (int)st.data.size()) break;

            uint8_t b = st.data[byte_idx];
            float bx = ox + addr_w + col * char_w * 3.f;
            if (col >= 8) bx += char_w;


            if (sel_lo >= 0 && byte_idx >= sel_lo && byte_idx <= sel_hi) {
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h), sel_col);
            }


            ImU32 bc;
            if (b == 0)
                bc = IM_COL32(60, 60, 80, (int)(100 * a));
            else
                bc = IM_COL32(200, 200, 230, (int)(220 * a));


            if (st.search_match >= 0 && byte_idx == st.search_match) {
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                  IM_COL32((int)(accent_r * 255), (int)(accent_g * 255),
                                           (int)(accent_b * 255), (int)(60 * a)));
            }

            char hex[4];
            snprintf(hex, sizeof(hex), "%02X", b);
            dl->AddText(ImVec2(bx, y + 1.f), bc, hex);


            if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                ImVec2 mp = ImGui::GetIO().MousePos;
                if (mp.x >= bx - 1.f && mp.x <= bx + char_w * 2.f + 1.f &&
                    mp.y >= y && mp.y <= y + line_h) {
                    if (ImGui::GetIO().KeyShift && st.sel_start >= 0)
                        st.sel_end = byte_idx;
                    else {
                        st.sel_start = byte_idx;
                        st.sel_end   = byte_idx;
                    }
                    st.selecting = true;
                }
            }
            if (st.selecting && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                ImVec2 mp = ImGui::GetIO().MousePos;
                if (mp.x >= bx - 1.f && mp.x <= bx + char_w * 2.f + 1.f &&
                    mp.y >= y && mp.y <= y + line_h)
                    st.sel_end = byte_idx;
            }
        }
        if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
            st.selecting = false;


        float ax = ox + asc_x;
        for (int col = 0; col < bytes_per_row; col++) {
            int byte_idx = row_off + col;
            if (byte_idx >= (int)st.data.size()) break;

            uint8_t b = st.data[byte_idx];
            char ch[2] = { '.', 0 };
            ImU32 ac;

            if (b >= 0x20 && b <= 0x7E) {
                ch[0] = (char)b;
                ac = IM_COL32(180, 180, 200, (int)(200 * a));
            } else if (b == 0) {
                ch[0] = '.';
                ac = IM_COL32(60, 60, 80, (int)(80 * a));
            } else {
                ch[0] = '.';
                ac = IM_COL32(209, 154, 102, (int)(160 * a));
            }


            if (sel_lo >= 0 && byte_idx >= sel_lo && byte_idx <= sel_hi)
                dl->AddRectFilled(ImVec2(ax, y), ImVec2(ax + char_w, y + line_h), sel_col);

            dl->AddText(ImVec2(ax, y + 1.f), ac, ch);
            ax += char_w;
        }
    }


    ImGui::SetCursorPos(ImVec2(pos_x, pos_y + total_rows * line_h));
    ImGui::Dummy(ImVec2(1.f, 1.f));


    if (sel_lo >= 0 && sel_lo < (int)st.data.size()) {
        float insp_w = 200.f;
        float insp_h = 200.f;
        float insp_x = ox + width - insp_w - 8.f;
        float insp_y = oy + 8.f;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(insp_x, insp_y),
                           ImVec2(insp_x + insp_w, insp_y + insp_h),
                           IM_COL32(20, 20, 30, (int)(230 * a)), 6.f);
        fdl->AddRect(ImVec2(insp_x, insp_y),
                     ImVec2(insp_x + insp_w, insp_y + insp_h),
                     IM_COL32(80, 80, 120, (int)(80 * a)), 6.f);

        fdl->AddText(ImVec2(insp_x + 6.f, insp_y + 4.f),
                     IM_COL32((int)(accent_r*255), (int)(accent_g*255),
                              (int)(accent_b*255), (int)(220*a)),
                     "Data Inspector");

        float iy = insp_y + 22.f;
        float label_x = insp_x + 8.f;
        float val_x   = insp_x + 80.f;
        ImU32 label_c = IM_COL32(120, 120, 150, (int)(180 * a));
        ImU32 val_c   = IM_COL32(200, 200, 230, (int)(230 * a));
        int remaining = (int)st.data.size() - sel_lo;
        const uint8_t* p = st.data.data() + sel_lo;
        char vbuf[64];

        auto add_row = [&](const char* label, const char* val) {
            fdl->AddText(ImVec2(label_x, iy), label_c, label);
            fdl->AddText(ImVec2(val_x, iy), val_c, val);
            iy += 18.f;
        };


        if (remaining >= 1) {
            snprintf(vbuf, sizeof(vbuf), "%d (0x%02X)", (int8_t)p[0], p[0]);
            add_row("int8", vbuf);
        }

        if (remaining >= 2) {
            int16_t v; memcpy(&v, p, 2);
            snprintf(vbuf, sizeof(vbuf), "%d (0x%04X)", v, (uint16_t)v);
            add_row("int16", vbuf);
        }

        if (remaining >= 4) {
            int32_t v; memcpy(&v, p, 4);
            snprintf(vbuf, sizeof(vbuf), "%d (0x%08X)", v, (uint32_t)v);
            add_row("int32", vbuf);
        }

        if (remaining >= 8) {
            int64_t v; memcpy(&v, p, 8);
            snprintf(vbuf, sizeof(vbuf), "%lld", (long long)v);
            add_row("int64", vbuf);
        }

        if (remaining >= 4) {
            float v; memcpy(&v, p, 4);
            snprintf(vbuf, sizeof(vbuf), "%.6g", v);
            add_row("float", vbuf);
        }

        if (remaining >= 8) {
            double v; memcpy(&v, p, 8);
            snprintf(vbuf, sizeof(vbuf), "%.10g", v);
            add_row("double", vbuf);
        }

        if (remaining >= 8) {
            uint64_t v; memcpy(&v, p, 8);
            snprintf(vbuf, sizeof(vbuf), "0x%016llX", (unsigned long long)v);
            add_row("ptr64", vbuf);
        }

        {
            std::string s;
            for (int i = 0; i < std::min(remaining, 20); i++) {
                if (p[i] >= 0x20 && p[i] <= 0x7E) s += (char)p[i];
                else break;
            }
            if (!s.empty()) add_row("ASCII", s.c_str());
        }
    }


    if (hovered || st.goto_visible || st.search_visible) {
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false))
            st.goto_visible = !st.goto_visible;
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false))
            st.search_visible = !st.search_visible;
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            st.goto_visible = false;
            st.search_visible = false;
        }


        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false) &&
            sel_lo >= 0 && sel_hi >= sel_lo) {
            std::string hex_str;
            for (int i = sel_lo; i <= sel_hi && i < (int)st.data.size(); i++) {
                char h[4];
                snprintf(h, sizeof(h), "%02X ", st.data[i]);
                hex_str += h;
            }
            if (!hex_str.empty()) {
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, hex_str.size() + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), hex_str.c_str(), hex_str.size() + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }
        }
    }


    if (st.goto_visible) {
        float gy = oy + 4.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(ox + 10.f, gy), ImVec2(ox + 230.f, gy + 30.f),
            IM_COL32(30, 30, 40, (int)(240 * a)), 6.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 8.f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.14f, 0.9f));
        ImGui::PushItemWidth(130.f);
        bool go = ImGui::InputText("##hex_goto", st.goto_buf, sizeof(st.goto_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::PopItemWidth();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        ImGui::SameLine();
        if (ImGui::SmallButton("Go##hex") || go) {
            uint64_t addr = 0;
            sscanf_s(st.goto_buf, "%llx", &addr);
            if (addr >= st.base_addr) {
                int off = (int)(addr - st.base_addr);
                if (off >= 0 && off < (int)st.data.size()) {
                    int row = off / bytes_per_row;
                    st.target_scroll_y = row * line_h;
                    st.sel_start = st.sel_end = off;
                    st.goto_visible = false;
                }
            }
        }
    }
}

}
