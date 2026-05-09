#include "hex_view.hpp"
#include "../helpers/globals.h"
#include "standalone_driver.hpp"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include "ui_anim.hpp"
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "empty_state.hpp"
#include "fonts.hpp"

namespace hex_view {

namespace {

std::string s_last_error;

bool parse_hex_pattern(const char* in, std::vector<uint8_t>& out) {
    out.clear();
    int nibble = -1;
    for (const char* p = in; *p; ++p) {
        char c = *p;
        if (c == ' ' || c == '\t' || c == ',' || c == '-' || c == '_') {
            if (nibble >= 0) return false;
            continue;
        }
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return false;
        if (nibble < 0) {
            nibble = v;
        } else {
            out.push_back(static_cast<uint8_t>((nibble << 4) | v));
            nibble = -1;
        }
    }
    return nibble < 0 && !out.empty();
}

void recompute_search_matches(state_t& st) {
    st.search_matches.clear();
    st.search_match     = -1;
    st.search_match_idx = -1;
    st.search_match_len = 0;
    st.search_last_query.assign(st.search_buf);
    st.search_last_hex = st.search_hex;

    if (st.data.empty() || st.search_buf[0] == '\0') return;

    std::vector<uint8_t> pat;
    if (st.search_hex) {
        if (!parse_hex_pattern(st.search_buf, pat)) return;
    } else {
        size_t len = std::strlen(st.search_buf);
        pat.assign(reinterpret_cast<const uint8_t*>(st.search_buf),
                   reinterpret_cast<const uint8_t*>(st.search_buf) + len);
    }
    if (pat.empty() || pat.size() > st.data.size()) return;

    const size_t n = st.data.size();
    const size_t m = pat.size();
    const uint8_t  first = pat[0];
    const uint8_t* dp    = st.data.data();
    for (size_t i = 0; i + m <= n; ++i) {
        if (dp[i] != first) continue;
        if (std::memcmp(dp + i, pat.data(), m) == 0) {
            st.search_matches.push_back(static_cast<int>(i));
            if (st.search_matches.size() >= 65536u) break;
        }
    }
    st.search_match_len = static_cast<int>(m);
    if (!st.search_matches.empty()) {
        st.search_match_idx = 0;
        st.search_match     = st.search_matches[0];
    }
}

void goto_search_match(state_t& st, int idx, float line_h, int bytes_per_row, float view_h) {
    if (idx < 0 || idx >= static_cast<int>(st.search_matches.size())) return;
    st.search_match_idx = idx;
    st.search_match     = st.search_matches[idx];
    int len = st.search_match_len > 0 ? st.search_match_len : 1;
    st.sel_start = st.search_match;
    st.sel_end   = st.search_match + len - 1;
    int row = st.search_match / bytes_per_row;
    float row_y = row * line_h;
    float center = row_y - (view_h * 0.5f) + (line_h * 0.5f);
    if (center < 0.f) center = 0.f;
    st.target_scroll_y = center;
}

void step_search(state_t& st, int dir, float line_h, int bytes_per_row, float view_h) {
    if (st.search_matches.empty()) return;
    int n = static_cast<int>(st.search_matches.size());
    int idx = st.search_match_idx + dir;
    if (idx < 0) idx = n - 1;
    if (idx >= n) idx = 0;
    goto_search_match(st, idx, line_h, bytes_per_row, view_h);
}

bool match_range_contains(const std::vector<int>& matches, int len, int byte_idx, int& which) {
    if (matches.empty() || len <= 0) return false;
    auto it = std::upper_bound(matches.begin(), matches.end(), byte_idx);
    if (it == matches.begin()) return false;
    --it;
    int start = *it;
    if (byte_idx >= start && byte_idx < start + len) {
        which = static_cast<int>(it - matches.begin());
        return true;
    }
    return false;
}

void clipboard_copy_string(const std::string& text) {
    if (text.empty() || !OpenClipboard(nullptr)) return;
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hg) {
        void* p = GlobalLock(hg);
        if (p) {
            memcpy(p, text.c_str(), text.size() + 1);
            GlobalUnlock(hg);
            SetClipboardData(CF_TEXT, hg);
        }
    }
    CloseClipboard();
}

}

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
    g_state.search_match     = -1;
    g_state.search_match_len = 0;
    g_state.search_match_idx = -1;
    g_state.search_matches.clear();
    g_state.search_last_query.clear();
}

void load_from_file(const std::string& path, size_t offset, size_t size) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        s_last_error = "hex_view::load_from_file: failed to open " + path;
        return;
    }
    size_t fsize = (size_t)f.tellg();
    if (offset >= fsize) {
        s_last_error = "hex_view::load_from_file: offset past end of " + path;
        return;
    }
    f.seekg((std::streamoff)offset);
    size_t read_sz = (size > 0 && offset + size <= fsize) ? size : (fsize - offset);
    std::vector<uint8_t> buf(read_sz);
    f.read((char*)buf.data(), (std::streamsize)read_sz);
    auto pos = path.find_last_of("/\\");
    std::string name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
    set_data(buf, (uint64_t)offset, name);
    s_last_error.clear();
}

std::string last_error() {
    return s_last_error;
}

bool read_from_process(uint64_t address, size_t size) {
    if (!driver_bridge::is_loaded() || !driver_bridge::can_read_memory())
        return false;
    if (driver_bridge::attached_pid() == 0)
        return false;
    if (size == 0 || size > 1 * 1024 * 1024)
        return false;

    std::vector<uint8_t> buf;
    if (!driver_bridge::read_memory(address, size, buf))
        return false;
    if (buf.empty())
        return false;

    char label[64];
    snprintf(label, sizeof(label), "PID %u @ %016llX",
             driver_bridge::attached_pid(),
             static_cast<unsigned long long>(address));
    set_data(buf, address, label);
    return true;
}

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b) {
    (void)accent_r; (void)accent_g; (void)accent_b;

    auto& st = g_state;
    const float a   = alpha;
    const float dt  = aida::ui::clock::dt();

    const auto& t = aida::ui::resolved();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + pos_y;

    dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
        aida::ui::with_alpha(t.bg_base, a));

    static aida::ui::transition_t s_empty_intro;
    static bool                   s_empty_intro_armed = false;
    static aida::ui::transition_t s_inspector_anim;
    static bool                   s_inspector_was_visible = false;
    static float                  s_insp_x_smooth = 0.f;
    static aida::ui::transition_t s_heat_xfade;
    static bool                   s_heat_mode = false;
    static aida::ui::flash_t      s_copy_flash;
    static double                 s_copy_flash_until = 0.0;
    static std::string            s_copy_toast_text;
    static aida::ui::transition_t s_overlay_intro;
    static aida::ui::hover_state_t s_heat_btn_hover;
    static float                  s_zoom_scale = 1.f;
    static float                  s_zoom_target = 1.f;

    if (!st.active || st.data.empty()) {
        if (!s_empty_intro_armed) { s_empty_intro.start(aida::motion::dur::lg, aida::motion::ease::out_quint); s_empty_intro_armed = true; }
        s_empty_intro.tick(dt);
        float ev = s_empty_intro.eased();
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * ev);
        aida::ui::empty_state::config_t cfg;
        cfg.glyph = aida::ui::empty_state::glyph_t::memory;
        cfg.title = "No buffer attached";
        cfg.body  = "Open a file or attach a process to inspect bytes.";
        cfg.hints = { {"Ctrl+O"}, {"Ctrl+P"} };
        cfg.max_width = 360.f;
        aida::ui::empty_state::render(ImVec2(ox, oy), ImVec2(width, height), cfg);
        ImGui::PopStyleVar();
        return;
    } else {
        s_empty_intro.reset();
        s_empty_intro_armed = false;
    }

    static float s_overlay_armed_for = -1.f;
    bool overlay_visible = st.goto_visible || st.search_visible;
    if (overlay_visible && s_overlay_armed_for < 0.f) {
        s_overlay_intro.start(aida::motion::dur::md, aida::motion::ease::out_quint);
        s_overlay_armed_for = 1.f;
    } else if (!overlay_visible) {
        s_overlay_armed_for = -1.f;
    }
    s_overlay_intro.tick(dt);

    bool ctrl_held = ImGui::GetIO().KeyCtrl;
    bool wheel_zoom_consumed = false;
    if (ctrl_held) {
        float w_in = ImGui::GetIO().MouseWheel;
        if (w_in != 0.f) {
            ImVec2 mp_z = ImGui::GetIO().MousePos;
            if (mp_z.x >= ox && mp_z.x <= ox + width && mp_z.y >= oy && mp_z.y <= oy + height) {
                s_zoom_target += w_in * 0.06f;
                if (s_zoom_target < 0.78f) s_zoom_target = 0.78f;
                if (s_zoom_target > 1.30f) s_zoom_target = 1.30f;
                wheel_zoom_consumed = true;
            }
        }
    }
    s_zoom_scale = aida::motion::smooth_lerp(s_zoom_scale, s_zoom_target, 14.f, dt);

    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
    const float font_base = ImGui::GetFontSize();
    const float font_size = font_base * s_zoom_scale;
    const float line_h = font_size + 4.f;
    const float char_w = code_font->CalcTextSizeA(font_size, FLT_MAX, 0.f, "0").x;
    const int   bytes_per_row = 16;
    const int   total_rows = ((int)st.data.size() + bytes_per_row - 1) / bytes_per_row;

    const float addr_w = char_w * 17.f;
    const float hex_w  = char_w * 50.f;
    const float asc_x  = addr_w + hex_w + char_w * 2.f;

    static std::vector<uint8_t> prev_bytes;
    static std::vector<float> byte_flash;
    static std::vector<aida::ui::transition_t> byte_heat_anim;
    if (prev_bytes.size() != st.data.size()) {
        prev_bytes = st.data;
        byte_flash.assign(st.data.size(), 0.f);
        byte_heat_anim.clear();
        byte_heat_anim.resize(st.data.size());
    }

    const float strip_h = 46.f;
    {
        char bytes_buf[32];
        char sel_buf[32];
        char base_buf[24];
        char src_buf[48];

        std::snprintf(bytes_buf, sizeof(bytes_buf), "%zu", st.data.size());
        int sel_count = 0;
        if (st.sel_start >= 0 && st.sel_end >= 0)
            sel_count = std::abs(st.sel_end - st.sel_start) + 1;
        if (sel_count > 0)
            std::snprintf(sel_buf, sizeof(sel_buf), "%d", sel_count);
        else
            std::snprintf(sel_buf, sizeof(sel_buf), "none");
        std::snprintf(base_buf, sizeof(base_buf), "0x%016llX",
            static_cast<unsigned long long>(st.base_addr));
        if (st.source_name.empty())
            std::snprintf(src_buf, sizeof(src_buf), "in-memory");
        else
            std::snprintf(src_buf, sizeof(src_buf), "%.44s", st.source_name.c_str());

        ui_anim::stat_strip_item_t items[4];
        items[0] = { "Bytes",    bytes_buf, nullptr, 0, nullptr, 0, t.text_primary };
        items[1] = { "Selected", sel_buf,   nullptr, 0, nullptr, 0, sel_count > 0 ? t.accent_u32 : t.text_dim };
        items[2] = { "Base",     base_buf,  nullptr, 0, nullptr, 0, t.text_address };
        items[3] = { "Source",   src_buf,   nullptr, 0, nullptr, 0, t.text_secondary };
        ui_anim::render_stat_strip(dl, ox + 6.f, oy + 6.f, width - 12.f, strip_h - 10.f,
            items, 4,
            ((float)((t.accent_u32 >> IM_COL32_R_SHIFT) & 0xFF)) / 255.f,
            ((float)((t.accent_u32 >> IM_COL32_G_SHIFT) & 0xFF)) / 255.f,
            ((float)((t.accent_u32 >> IM_COL32_B_SHIFT) & 0xFF)) / 255.f, a);
    }
    oy += strip_h;
    height -= strip_h;

    float col_hdr_h = line_h + 4.f;
    {
        dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + col_hdr_h),
            aida::ui::with_alpha(t.panel_header, a));
        dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + col_hdr_h),
            aida::ui::with_alpha(t.accent_glow, a * 0.7f),
            aida::ui::with_alpha(t.accent_glow, 0),
            aida::ui::with_alpha(t.accent_glow, 0),
            aida::ui::with_alpha(t.accent_glow, a * 0.7f));
        float hx = ox + addr_w;
        for (int c = 0; c < bytes_per_row; ++c) {
            float bx = hx + c * char_w * 3.f;
            if (c >= 8) bx += char_w;
            char hdr[4];
            snprintf(hdr, sizeof(hdr), "%02X", c);
            dl->AddText(code_font, font_size, ImVec2(bx, oy + 3.f),
                aida::ui::with_alpha(t.text_dim, a), hdr);
        }
        dl->AddText(aida::ui::fonts::caption(), 13.f,
            ImVec2(ox + asc_x, oy + (col_hdr_h - 11.f) * 0.5f),
            aida::ui::with_alpha(t.text_dim, a), "DECODED TEXT");
        dl->AddLine(ImVec2(ox, oy + col_hdr_h - 1.f),
                    ImVec2(ox + width, oy + col_hdr_h - 1.f),
                    aida::ui::with_alpha(t.border_subtle, a), 1.f);
    }
    oy += col_hdr_h;
    height -= col_hdr_h;

    st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 20.f, dt);
    if (std::abs(st.target_scroll_y - st.scroll_y) < 0.5f)
        st.scroll_y = st.target_scroll_y;
    float max_scroll = std::max(0.f, total_rows * line_h - height + line_h);
    st.target_scroll_y = std::max(0.f, std::min(st.target_scroll_y, max_scroll));
    st.scroll_y = std::max(0.f, std::min(st.scroll_y, max_scroll));

    bool hovered = ImGui::IsMouseHoveringRect(ImVec2(ox, oy), ImVec2(ox + width, oy + height));
    if (hovered && !wheel_zoom_consumed) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f && !ctrl_held)
            st.target_scroll_y -= wheel * line_h * 3.f;
    }

    int first_row = std::max(0, (int)(st.scroll_y / line_h) - 1);
    int last_row  = std::min(total_rows - 1, (int)((st.scroll_y + height) / line_h) + 1);

    dl->AddLine(ImVec2(ox + addr_w - char_w, oy),
                ImVec2(ox + addr_w - char_w, oy + height),
                aida::ui::with_alpha(t.border_subtle, a * 1.2f), 1.f);
    dl->AddLine(ImVec2(ox + addr_w + hex_w, oy),
                ImVec2(ox + addr_w + hex_w, oy + height),
                aida::ui::with_alpha(t.border_subtle, a * 1.2f), 1.f);

    {
        ImVec2 ht_min = ImVec2(ox + width - 110.f, oy + 4.f);
        ImVec2 ht_max = ImVec2(ox + width - 10.f, oy + 4.f + 22.f);
        bool ht_hov = ImGui::IsMouseHoveringRect(ht_min, ht_max);
        float hov_v = s_heat_btn_hover.tick(ht_hov, dt, aida::motion::spring::balanced);

        if (ht_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            s_heat_mode = !s_heat_mode;
            s_heat_xfade.start(aida::motion::dur::md, aida::motion::ease::out_quint);
        }
        s_heat_xfade.tick(dt);

        ImU32 fill_off = aida::ui::with_alpha(t.panel_header, (0.55f + hov_v * 0.25f) * a);
        ImU32 fill_on  = aida::ui::with_alpha(t.accent_dim, (0.6f + hov_v * 0.30f) * a);
        ImU32 fill = s_heat_mode ? fill_on : fill_off;
        dl->AddRectFilled(ht_min, ht_max, fill, 11.f);
        ImU32 border_col = aida::ui::with_alpha(s_heat_mode ? t.accent_u32 : t.border_subtle, a);
        dl->AddRect(ht_min, ht_max, border_col, 11.f, 0, 1.f);

        const char* lbl = s_heat_mode ? "Heat: ON" : "Heat";
        ImVec2 ts = ImGui::CalcTextSize(lbl);
        ImU32 txt_col = s_heat_mode ? aida::ui::with_alpha(t.accent_u32, a)
                                    : aida::ui::with_alpha(t.text_secondary, (0.85f + hov_v * 0.15f) * a);
        dl->AddText(ImVec2(ht_min.x + (ht_max.x - ht_min.x - ts.x) * 0.5f,
                           ht_min.y + ((ht_max.y - ht_min.y) - ts.y) * 0.5f),
                    txt_col, lbl);
    }

    int sel_lo = -1, sel_hi = -1;
    if (st.sel_start >= 0 && st.sel_end >= 0) {
        sel_lo = std::min(st.sel_start, st.sel_end);
        sel_hi = std::max(st.sel_start, st.sel_end);
    }

    static float s_sel_lo_anim = -1.f;
    static float s_sel_hi_anim = -1.f;
    static float s_sel_lo_vel = 0.f;
    static float s_sel_hi_vel = 0.f;
    if (sel_lo < 0) {
        s_sel_lo_anim = -1.f;
        s_sel_hi_anim = -1.f;
        s_sel_lo_vel = 0.f;
        s_sel_hi_vel = 0.f;
    } else {
        if (s_sel_lo_anim < 0.f) {
            s_sel_lo_anim = (float)sel_lo;
            s_sel_hi_anim = (float)sel_hi;
        } else {
            s_sel_lo_anim = aida::motion::spring_step(s_sel_lo_anim, (float)sel_lo, s_sel_lo_vel, aida::motion::spring::snappy, dt);
            s_sel_hi_anim = aida::motion::spring_step(s_sel_hi_anim, (float)sel_hi, s_sel_hi_vel, aida::motion::spring::snappy, dt);
        }
    }

    ImU32 sel_col_fill = aida::ui::with_alpha(t.selection, a);
    ImU32 sel_glow     = aida::ui::with_alpha(t.accent_glow, a);

    for (int row = first_row; row <= last_row; row++) {
        float y = oy + row * line_h - st.scroll_y;
        int row_off = row * bytes_per_row;

        if (row & 1) {
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + width, y + line_h - 1.f),
                              aida::ui::with_alpha(t.text_primary, 0.012f * a));
        }

        char addr_buf[20];
        snprintf(addr_buf, sizeof(addr_buf), "%016llX",
                 (unsigned long long)(st.base_addr + row_off));
        dl->AddText(code_font, font_size, ImVec2(ox + 4.f, y + 1.f),
                    aida::ui::with_alpha(t.text_address, 0.85f * a), addr_buf);

        for (int col = 0; col < bytes_per_row; col++) {
            int byte_idx = row_off + col;
            if (byte_idx >= (int)st.data.size()) break;

            uint8_t byte_val = st.data[byte_idx];
            float bx = ox + addr_w + col * char_w * 3.f;
            if (col >= 8) bx += char_w;

            float heat_alpha = 0.f;
            if (byte_idx < (int)byte_heat_anim.size()) {
                auto& xa = byte_heat_anim[byte_idx];
                if (s_heat_mode && !xa.active && xa.progress < 0.999f) {
                    xa.start(aida::motion::dur::md, aida::motion::ease::out_quint);
                } else if (!s_heat_mode && !xa.active && xa.progress > 0.001f) {
                    xa.start_reverse(aida::motion::dur::md, aida::motion::ease::out_quint);
                }
                xa.tick(dt);
                heat_alpha = xa.eased();
            }
            if (heat_alpha > 0.001f) {
                ImU32 hc = ui_anim::byte_heat_color(byte_val, a * 0.32f * heat_alpha);
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                  hc);
            } else if (byte_val == 0) {
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                  IM_COL32(0, 0, 0, static_cast<int>(30 * a)));
            }

            bool sel_animated_in = false;
            if (s_sel_lo_anim >= 0.f) {
                float lo_a = s_sel_lo_anim;
                float hi_a = s_sel_hi_anim;
                if (lo_a > hi_a) { float tmp = lo_a; lo_a = hi_a; hi_a = tmp; }
                if (byte_idx >= (int)floorf(lo_a) && byte_idx <= (int)ceilf(hi_a)) {
                    float intensity = 1.f;
                    if (byte_idx < (int)floorf(lo_a) + 1) {
                        intensity = 1.f - (lo_a - floorf(lo_a));
                    }
                    if (byte_idx > (int)ceilf(hi_a) - 1) {
                        intensity = std::min(intensity, 1.f - (ceilf(hi_a) - hi_a));
                    }
                    if (intensity < 0.f) intensity = 0.f;
                    dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                      ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                      aida::ui::with_alpha(sel_col_fill, intensity));
                    sel_animated_in = true;
                }
            }

            if (sel_animated_in && sel_lo >= 0 && byte_idx >= sel_lo && byte_idx <= sel_hi) {
                if (byte_idx == sel_lo || byte_idx == sel_hi) {
                    dl->AddRect(ImVec2(bx - 1.f, y),
                                ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                aida::ui::with_alpha(t.accent_u32, 0.55f * a),
                                0.f, 0, 1.f);
                }
            }

            if (byte_idx < static_cast<int>(prev_bytes.size()) &&
                st.data[byte_idx] != prev_bytes[byte_idx]) {
                byte_flash[byte_idx] = 1.f;
                prev_bytes[byte_idx] = st.data[byte_idx];
            }

            if (byte_idx < static_cast<int>(byte_flash.size()) && byte_flash[byte_idx] > 0.f) {
                ui_anim::decay_flash(byte_flash[byte_idx], 3.f, dt);
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                  aida::ui::with_alpha(t.error, byte_flash[byte_idx] * 0.46f * a));
            }

            ImU32 bc = (byte_val == 0)
                        ? aida::ui::with_alpha(t.text_dim, a)
                        : aida::ui::with_alpha(t.text_primary, a);

            int match_which = -1;
            if (match_range_contains(st.search_matches, st.search_match_len, byte_idx, match_which)) {
                bool is_current = (match_which == st.search_match_idx);
                float pulse = aida::ui::clock::pulse(1.5f, 0.55f, 1.f);
                float intensity = is_current ? pulse : 0.34f;
                ImU32 match_fill = aida::ui::with_alpha(t.accent_u32, 0.42f * intensity * a);
                dl->AddRectFilled(ImVec2(bx - 1.f, y),
                                  ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                  match_fill);
                if (is_current) {
                    dl->AddRect(ImVec2(bx - 1.f, y),
                                ImVec2(bx + char_w * 2.f + 1.f, y + line_h),
                                aida::ui::with_alpha(t.accent_u32, 0.85f * pulse * a),
                                0.f, 0, 1.2f);
                    aida::ui::blur::render_inner_glow(dl,
                        ImVec2(bx - 2.f, y - 1.f),
                        ImVec2(bx + char_w * 2.f + 2.f, y + line_h + 1.f),
                        2.f, sel_glow, 2);
                }
            }

            char hex[4];
            snprintf(hex, sizeof(hex), "%02X", byte_val);
            dl->AddText(code_font, font_size, ImVec2(bx, y + 1.f), bc, hex);

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

            uint8_t byte_val = st.data[byte_idx];
            char ch[2] = { '.', 0 };
            ImU32 ac;

            if (byte_val >= 0x20 && byte_val <= 0x7E) {
                ch[0] = (char)byte_val;
                ac = aida::ui::with_alpha(t.text_secondary, a);
            } else if (byte_val == 0) {
                ch[0] = '.';
                ac = aida::ui::with_alpha(t.text_dim, 0.55f * a);
            } else {
                ch[0] = '.';
                ac = aida::ui::with_alpha(t.warning, 0.62f * a);
            }

            if (sel_lo >= 0 && byte_idx >= sel_lo && byte_idx <= sel_hi)
                dl->AddRectFilled(ImVec2(ax, y), ImVec2(ax + char_w, y + line_h), sel_col_fill);

            int ascii_match_which = -1;
            if (match_range_contains(st.search_matches, st.search_match_len, byte_idx, ascii_match_which)) {
                bool is_current = (ascii_match_which == st.search_match_idx);
                float pulse = aida::ui::clock::pulse(1.5f, 0.55f, 1.f);
                float intensity = is_current ? pulse : 0.30f;
                dl->AddRectFilled(ImVec2(ax, y), ImVec2(ax + char_w, y + line_h),
                    aida::ui::with_alpha(t.accent_u32, 0.36f * intensity * a));
            }

            dl->AddText(code_font, font_size, ImVec2(ax, y + 1.f), ac, ch);
            ax += char_w;
        }
    }

    if (sel_lo >= 0 && sel_lo < (int)st.data.size()) {
        float insp_w = 280.f;
        float insp_h = 0.f;
        float insp_target_x = ox + width - insp_w - 8.f;
        float insp_y = oy + 8.f;

        if (!s_inspector_was_visible) {
            s_inspector_anim.start(aida::motion::dur::lg, aida::motion::ease::out_back);
            s_inspector_was_visible = true;
            s_insp_x_smooth = ox + width;
        }
        s_inspector_anim.tick(dt);
        float intro = s_inspector_anim.eased();
        float anim_x = aida::motion::remap(intro, 0.f, 1.f, ox + width, insp_target_x);
        s_insp_x_smooth = aida::motion::smooth_lerp(s_insp_x_smooth, anim_x, 16.f, dt);
        float insp_x = s_insp_x_smooth;

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

        const float row_h = 22.f;
        const float header_h = 36.f;
        const float pad = 12.f;
        insp_h = header_h + static_cast<float>(rows.size()) * row_h + pad + 8.f;

        ImVec2 imin(insp_x, insp_y);
        ImVec2 imax(insp_x + insp_w, insp_y + insp_h);

        aida::ui::blur::render_drop_shadow(fdl, imin, imax, 14.f, 5, 0.42f, ImVec2(0.f, 6.f));
        aida::ui::blur::render_glass_fill(fdl, imin, imax, 14.f, a);
        aida::ui::blur::render_glass_border(fdl, imin, imax, 14.f, a, 1.f);

        fdl->AddRectFilledMultiColor(
            ImVec2(imin.x, imin.y),
            ImVec2(imax.x, imin.y + 4.f),
            aida::ui::with_alpha(t.accent_grad_top, a),
            aida::ui::with_alpha(t.accent_grad_top, a),
            aida::ui::with_alpha(t.accent_grad_bot, a),
            aida::ui::with_alpha(t.accent_grad_bot, a));

        fdl->AddRectFilledMultiColor(
            ImVec2(imin.x + 1.f, imin.y + 4.f),
            ImVec2(imax.x - 1.f, imin.y + header_h),
            aida::ui::with_alpha(t.accent_glow, a * 0.45f),
            aida::ui::with_alpha(t.accent_glow, a * 0.10f),
            aida::ui::with_alpha(t.accent_glow, 0),
            aida::ui::with_alpha(t.accent_glow, a * 0.20f));

        fdl->AddText(aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont(),
                     14.f, ImVec2(imin.x + pad, imin.y + (header_h - 14.f) * 0.5f + 2.f),
                     aida::ui::with_alpha(t.text_primary, a), "Data Inspector");

        snprintf(vbuf, sizeof(vbuf), "@ 0x%X", sel_lo);
        ImVec2 offs_ts = ImGui::CalcTextSize(vbuf);
        ImVec2 chip_min(imax.x - offs_ts.x - 18.f, imin.y + (header_h - 18.f) * 0.5f + 2.f);
        ImVec2 chip_max(imax.x - 8.f, chip_min.y + 18.f);
        fdl->AddRectFilled(chip_min, chip_max,
            aida::ui::with_alpha(t.panel_header, 0.85f * a), 9.f);
        fdl->AddRect(chip_min, chip_max,
            aida::ui::with_alpha(t.border_subtle, a), 9.f, 0, 1.f);
        fdl->AddText(aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont(),
                     11.f, ImVec2(chip_min.x + 8.f, chip_min.y + 3.f),
                     aida::ui::with_alpha(t.text_secondary, a), vbuf);

        float iy = insp_y + header_h + 4.f;
        float label_x = insp_x + pad;
        float val_x   = insp_x + 86.f;
        ImU32 label_c = aida::ui::with_alpha(t.text_dim, a);
        ImU32 val_c   = aida::ui::with_alpha(t.text_primary, a);

        for (int ri = 0; ri < (int)rows.size(); ri++) {
            ImVec2 rmin(insp_x + 4.f, iy);
            ImVec2 rmax(insp_x + insp_w - 4.f, iy + row_h);
            bool row_hov = ImGui::IsMouseHoveringRect(rmin, rmax);

            float row_lift = 0.f;
            ImGuiID row_id = ImGui::GetID(rows[ri].label);
            ImGuiStorage* store = ImGui::GetStateStorage();
            float prev_hov = store->GetFloat(row_id, 0.f);
            float new_hov = aida::motion::smooth_lerp(prev_hov, row_hov ? 1.f : 0.f, 16.f, dt);
            store->SetFloat(row_id, new_hov);
            row_lift = new_hov;

            if (row_lift > 0.001f) {
                fdl->AddRectFilled(rmin, rmax,
                    aida::ui::with_alpha(t.hover_wash, row_lift * 0.9f * a), 6.f);
                fdl->AddLine(ImVec2(rmin.x + 2.f, rmin.y),
                             ImVec2(rmin.x + 2.f, rmax.y),
                             aida::ui::with_alpha(t.accent_u32, row_lift * 0.55f * a), 1.5f);
            }

            ImFont* code_f = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
            fdl->AddText(aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont(),
                         11.f, ImVec2(label_x, iy + 4.f),
                         label_c, rows[ri].label);
            fdl->AddText(code_f, 13.f, ImVec2(val_x, iy + 3.f),
                         val_c, rows[ri].value.c_str());

            if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                clipboard_copy_string(rows[ri].value);
                s_copy_flash.trigger();
                s_copy_toast_text = "Copied " + rows[ri].value;
                s_copy_flash_until = ImGui::GetTime() + 1.4;
            }

            if (s_copy_flash.v > 0.f && row_hov) {
                fdl->AddRect(rmin, rmax,
                    aida::ui::with_alpha(t.success, s_copy_flash.v * a), 6.f, 0, 1.5f);
                float check_x = rmax.x - 16.f;
                float check_y = rmin.y + (rmax.y - rmin.y) * 0.5f;
                ImU32 check_col = aida::ui::with_alpha(t.success, s_copy_flash.v * a);
                fdl->AddLine(ImVec2(check_x - 4.f, check_y),
                             ImVec2(check_x - 1.f, check_y + 3.f),
                             check_col, 1.5f);
                fdl->AddLine(ImVec2(check_x - 1.f, check_y + 3.f),
                             ImVec2(check_x + 4.f, check_y - 3.f),
                             check_col, 1.5f);
            }

            iy += row_h;
        }

        s_copy_flash.tick(dt, 2.0f);

        if (ImGui::GetTime() < s_copy_flash_until && !s_copy_toast_text.empty()) {
            float toast_w = ImGui::CalcTextSize(s_copy_toast_text.c_str()).x + 28.f;
            float toast_x = insp_x + (insp_w - toast_w) * 0.5f;
            float toast_y = insp_y + insp_h + 8.f;
            ImVec2 tmin(toast_x, toast_y);
            ImVec2 tmax(toast_x + toast_w, toast_y + 26.f);
            float remaining = (float)(s_copy_flash_until - ImGui::GetTime());
            float fade = std::min(1.f, remaining * 2.f);
            aida::ui::blur::render_drop_shadow(fdl, tmin, tmax, 13.f, 3, 0.30f, ImVec2(0.f, 4.f));
            fdl->AddRectFilled(tmin, tmax, aida::ui::with_alpha(t.bg_overlay, fade * 0.95f), 13.f);
            fdl->AddRect(tmin, tmax, aida::ui::with_alpha(t.success, fade * 0.7f), 13.f, 0, 1.f);
            float check_cx = tmin.x + 12.f;
            float check_cy = tmin.y + 13.f;
            fdl->AddLine(ImVec2(check_cx - 3.f, check_cy),
                         ImVec2(check_cx - 0.5f, check_cy + 2.5f),
                         aida::ui::with_alpha(t.success, fade), 1.6f);
            fdl->AddLine(ImVec2(check_cx - 0.5f, check_cy + 2.5f),
                         ImVec2(check_cx + 3.5f, check_cy - 2.5f),
                         aida::ui::with_alpha(t.success, fade), 1.6f);
            fdl->AddText(ImVec2(tmin.x + 22.f, tmin.y + 6.f),
                         aida::ui::with_alpha(t.text_primary, fade),
                         s_copy_toast_text.c_str());
        }
    } else if (s_inspector_was_visible && s_inspector_anim.progress > 0.001f) {
        if (s_inspector_anim.is_finished()) {
            s_inspector_anim.start_reverse(aida::motion::dur::md, aida::motion::ease::in_quint);
        }
        s_inspector_anim.tick(dt);
        float intro = s_inspector_anim.eased();
        float insp_w = 280.f;
        float insp_target_x = ox + width - insp_w - 8.f;
        float anim_x = aida::motion::remap(intro, 0.f, 1.f, ox + width, insp_target_x);
        s_insp_x_smooth = aida::motion::smooth_lerp(s_insp_x_smooth, anim_x, 16.f, dt);
        float insp_x = s_insp_x_smooth;
        float insp_y = oy + 8.f;
        float insp_h = 60.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 imin(insp_x, insp_y);
        ImVec2 imax(insp_x + insp_w, insp_y + insp_h);
        aida::ui::blur::render_drop_shadow(fdl, imin, imax, 14.f, 5, 0.42f * intro, ImVec2(0.f, 6.f));
        aida::ui::blur::render_glass_fill(fdl, imin, imax, 14.f, intro);
        if (s_inspector_anim.progress < 0.001f && !s_inspector_anim.active) {
            s_inspector_was_visible = false;
            s_insp_x_smooth = ox + width;
        }
    } else {
        s_inspector_anim.tick(dt);
    }

    if (hovered || st.goto_visible || st.search_visible) {
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G, false)) {
            st.goto_visible = !st.goto_visible;
            if (st.goto_visible) st.search_visible = false;
        }
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
            st.search_visible = !st.search_visible;
            if (st.search_visible) st.goto_visible = false;
        }
        if (st.search_visible && ImGui::IsKeyPressed(ImGuiKey_F3, false)) {
            int dir = ImGui::GetIO().KeyShift ? -1 : 1;
            step_search(st, dir, line_h, bytes_per_row, height);
        }
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
            if (!hex_str.empty()) clipboard_copy_string(hex_str);
        }
    }

    auto render_overlay_panel = [&](float panel_x, float panel_y, float panel_w, float panel_h) {
        float intro = s_overlay_intro.eased();
        float ease_y = aida::motion::remap(intro, 0.f, 1.f, panel_y - 12.f, panel_y);
        float ease_a = intro;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 a_min(panel_x, ease_y);
        ImVec2 a_max(panel_x + panel_w, ease_y + panel_h);
        aida::ui::blur::render_drop_shadow(fdl, a_min, a_max, 12.f, 4, 0.35f * ease_a, ImVec2(0.f, 4.f));
        aida::ui::blur::render_glass_fill(fdl, a_min, a_max, 12.f, ease_a);
        aida::ui::blur::render_glass_border(fdl, a_min, a_max, 12.f, ease_a, 1.f);
        return ease_y;
    };

    if (st.goto_visible) {
        float panel_w = 270.f;
        float panel_h = 40.f;
        float panel_x = ox + 12.f;
        float panel_y = oy + 6.f;
        float ey = render_overlay_panel(panel_x, panel_y, panel_w, panel_h);

        ImGui::SetCursorScreenPos(ImVec2(panel_x + 12.f, ey + (panel_h - 26.f) * 0.5f));
        ImGui::PushID("hex_goto_overlay");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(t.bg_base, 0.65f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
        ImGui::SetNextItemWidth(160.f);
        bool go = ImGui::InputTextWithHint("##hex_goto_input", "0x...", st.goto_buf, sizeof(st.goto_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);
        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2.f);
        bool clicked_go = aida::ui::components::button("Go", aida::ui::components::button_kind_t::primary,
            aida::ui::components::size_t_::sm);
        ImGui::PopID();

        if (clicked_go || go) {
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

    if (st.search_visible) {
        float panel_w = 540.f;
        float panel_h = 40.f;
        float panel_x = ox + 12.f;
        float panel_y = oy + 6.f;
        float ey = render_overlay_panel(panel_x, panel_y, panel_w, panel_h);

        ImGui::SetCursorScreenPos(ImVec2(panel_x + 12.f, ey + (panel_h - 26.f) * 0.5f));
        ImGui::PushID("hex_search_overlay");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(t.bg_base, 0.65f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(t.text_primary));
        ImGui::SetNextItemWidth(220.f);
        const char* hint = st.search_hex ? "DE AD BE EF..." : "text";
        bool submit = ImGui::InputTextWithHint("##hex_search_input", hint, st.search_buf, sizeof(st.search_buf),
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        bool query_changed = (st.search_last_query != st.search_buf) ||
                             (st.search_last_hex != st.search_hex);
        if (query_changed) {
            recompute_search_matches(st);
            if (!st.search_matches.empty()) {
                goto_search_match(st, 0, line_h, bytes_per_row, height);
            }
        }

        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2.f);
        const char* mode_label = st.search_hex ? "Hex" : "Txt";
        if (aida::ui::components::button(mode_label, aida::ui::components::button_kind_t::secondary,
                                          aida::ui::components::size_t_::sm)) {
            st.search_hex = !st.search_hex;
        }

        ImGui::SameLine();
        if (aida::ui::components::button("<", aida::ui::components::button_kind_t::ghost,
                                          aida::ui::components::size_t_::sm)) {
            step_search(st, -1, line_h, bytes_per_row, height);
        }
        ImGui::SameLine();
        if (aida::ui::components::button(">", aida::ui::components::button_kind_t::ghost,
                                          aida::ui::components::size_t_::sm)) {
            step_search(st, +1, line_h, bytes_per_row, height);
        }

        ImGui::SameLine();
        char count_buf[32];
        if (st.search_buf[0] == '\0') {
            std::snprintf(count_buf, sizeof(count_buf), " ");
        } else if (st.search_matches.empty()) {
            std::snprintf(count_buf, sizeof(count_buf), "0 matches");
        } else {
            std::snprintf(count_buf, sizeof(count_buf), "%d/%d",
                st.search_match_idx + 1, static_cast<int>(st.search_matches.size()));
        }
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
            st.search_matches.empty() && st.search_buf[0] != '\0' ? t.error : t.text_secondary));
        ImGui::TextUnformatted(count_buf);
        ImGui::PopStyleColor();

        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4.f);
        if (aida::ui::components::button("Close", aida::ui::components::button_kind_t::ghost,
                                          aida::ui::components::size_t_::sm)) {
            st.search_visible = false;
        }

        if (submit) {
            int dir = ImGui::GetIO().KeyShift ? -1 : 1;
            step_search(st, dir, line_h, bytes_per_row, height);
        }
        ImGui::PopID();
    }

    {
        float total_content = total_rows * line_h;
        if (total_content > height) {
            const float sb_w = 10.f;
            const float sb_pad = 2.f;
            float track_x = ox + width - sb_w - sb_pad;
            float track_y0 = oy + sb_pad;
            float track_h  = height - sb_pad * 2.f;

            ui_anim::render_custom_scrollbar(dl, track_x, track_y0, sb_w, track_h,
                st.scroll_y, total_content, height, a,
                st.sb_dragging, st.sb_drag_offset);
        }
    }

}

}
