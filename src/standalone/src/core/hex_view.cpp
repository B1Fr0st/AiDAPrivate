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


    if (sel_lo >= 0 && sel_lo < (int)st.data.size()) {
        float insp_w = 260.f;
        float insp_h = 0.f;
        float insp_x = ox + width - insp_w - 8.f;
        float insp_y = oy + 8.f;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        int remaining = (int)st.data.size() - sel_lo;
        const uint8_t* p = st.data.data() + sel_lo;
        char vbuf[64];


        struct InspRow { const char* label; std::string value; };
        std::vector<InspRow> rows;

        if (remaining >= 1) {
            snprintf(vbuf, sizeof(vbuf), "%d", (int8_t)p[0]);
            rows.push_back({"int8", vbuf});
            snprintf(vbuf, sizeof(vbuf), "%u (0x%02X)", p[0], p[0]);
            rows.push_back({"uint8", vbuf});
        }
        if (remaining >= 2) {
            int16_t v; memcpy(&v, p, 2);
            uint16_t uv; memcpy(&uv, p, 2);
            snprintf(vbuf, sizeof(vbuf), "%d", v);
            rows.push_back({"int16", vbuf});
            snprintf(vbuf, sizeof(vbuf), "%u (0x%04X)", uv, uv);
            rows.push_back({"uint16", vbuf});
        }
        if (remaining >= 4) {
            int32_t v; memcpy(&v, p, 4);
            uint32_t uv; memcpy(&uv, p, 4);
            snprintf(vbuf, sizeof(vbuf), "%d (0x%08X)", v, uv);
            rows.push_back({"int32", vbuf});
            snprintf(vbuf, sizeof(vbuf), "%u", uv);
            rows.push_back({"uint32", vbuf});
        }
        if (remaining >= 8) {
            int64_t v; memcpy(&v, p, 8);
            uint64_t uv; memcpy(&uv, p, 8);
            snprintf(vbuf, sizeof(vbuf), "%lld", (long long)v);
            rows.push_back({"int64", vbuf});
            snprintf(vbuf, sizeof(vbuf), "%llu", (unsigned long long)uv);
            rows.push_back({"uint64", vbuf});
        }
        if (remaining >= 4) {
            float v; memcpy(&v, p, 4);
            snprintf(vbuf, sizeof(vbuf), "%.6g", v);
            rows.push_back({"float", vbuf});
        }
        if (remaining >= 8) {
            double v; memcpy(&v, p, 8);
            snprintf(vbuf, sizeof(vbuf), "%.10g", v);
            rows.push_back({"double", vbuf});
        }
        if (remaining >= 8) {
            uint64_t v; memcpy(&v, p, 8);
            snprintf(vbuf, sizeof(vbuf), "0x%016llX", (unsigned long long)v);
            rows.push_back({"ptr64", vbuf});
        }
        {
            std::string s;
            for (int i = 0; i < std::min(remaining, 32); i++) {
                if (p[i] >= 0x20 && p[i] <= 0x7E) s += (char)p[i];
                else break;
            }
            if (!s.empty()) rows.push_back({"ASCII", std::move(s)});
        }

        const float row_h = 18.f;
        const float header_h = 28.f;
        const float pad = 8.f;
        insp_h = header_h + static_cast<float>(rows.size()) * row_h + pad;


        fdl->AddRectFilled(ImVec2(insp_x + 3.f, insp_y + 3.f),
                           ImVec2(insp_x + insp_w + 3.f, insp_y + insp_h + 3.f),
                           IM_COL32(0, 0, 0, (int)(80 * a)), 8.f);

        fdl->AddRectFilled(ImVec2(insp_x, insp_y),
                           ImVec2(insp_x + insp_w, insp_y + insp_h),
                           IM_COL32(18, 18, 28, (int)(240 * a)), 8.f);

        fdl->AddRect(ImVec2(insp_x, insp_y),
                     ImVec2(insp_x + insp_w, insp_y + insp_h),
                     IM_COL32(80, 80, 130, (int)(60 * a)), 8.f);


        fdl->AddRectFilled(ImVec2(insp_x, insp_y),
                           ImVec2(insp_x + insp_w, insp_y + header_h),
                           IM_COL32(30, 28, 45, (int)(255 * a)), 8.f, ImDrawFlags_RoundCornersTop);

        fdl->AddLine(ImVec2(insp_x, insp_y + header_h),
                     ImVec2(insp_x + insp_w, insp_y + header_h),
                     IM_COL32((int)(accent_r*255), (int)(accent_g*255),
                              (int)(accent_b*255), (int)(80*a)));

        fdl->AddText(ImVec2(insp_x + pad, insp_y + (header_h - ImGui::GetFontSize()) * 0.5f),
                     IM_COL32((int)(accent_r*200), (int)(accent_g*200),
                              (int)(accent_b*200), (int)(240*a)),
                     "Data Inspector");

        snprintf(vbuf, sizeof(vbuf), "@ 0x%X", sel_lo);
        ImVec2 offs_ts = ImGui::CalcTextSize(vbuf);
        fdl->AddRectFilled(
            ImVec2(insp_x + insp_w - offs_ts.x - 16.f, insp_y + 4.f),
            ImVec2(insp_x + insp_w - 6.f, insp_y + header_h - 4.f),
            IM_COL32(50, 48, 70, (int)(200 * a)), 4.f);
        fdl->AddText(
            ImVec2(insp_x + insp_w - offs_ts.x - 11.f, insp_y + (header_h - ImGui::GetFontSize()) * 0.5f),
            IM_COL32(160, 158, 190, (int)(200 * a)), vbuf);


        float iy = insp_y + header_h + 2.f;
        float label_x = insp_x + pad;
        float val_x   = insp_x + 80.f;
        ImU32 label_c = IM_COL32(100, 100, 135, (int)(180 * a));
        ImU32 val_c   = IM_COL32(210, 210, 240, (int)(240 * a));

        for (int ri = 0; ri < (int)rows.size(); ri++) {
            ImVec2 rmin(insp_x + 2.f, iy);
            ImVec2 rmax(insp_x + insp_w - 2.f, iy + row_h);
            bool row_hov = ImGui::IsMouseHoveringRect(rmin, rmax);
            if (row_hov) {
                fdl->AddRectFilled(rmin, rmax, IM_COL32(255, 255, 255, (int)(12 * a)), 3.f);
            }
            fdl->AddText(ImVec2(label_x, iy + 1.f), label_c, rows[ri].label);
            fdl->AddText(ImVec2(val_x, iy + 1.f), val_c, rows[ri].value.c_str());


            if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                if (OpenClipboard(nullptr)) {
                    EmptyClipboard();
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, rows[ri].value.size() + 1);
                    if (hg) {
                        memcpy(GlobalLock(hg), rows[ri].value.c_str(), rows[ri].value.size() + 1);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                }
            }

            iy += row_h;
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


    {
        float total_content = total_rows * line_h;
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

            ImGuiID sb_hov_id = ImGui::GetID("##hex_sb_hov");
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
