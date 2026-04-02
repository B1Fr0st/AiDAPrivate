#include "code_editor.hpp"
#include "syntax_highlight.hpp"
#include "standalone_ai_client.hpp"
#include "standalone_settings.hpp"
#include "standalone_license.hpp"
#include "../helpers/globals.h"

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


namespace {


struct line_cache_t {
    std::vector<std::string>          lines;
    std::vector<std::vector<syntax::token_t>> tokens;
    bool dirty = true;
};

line_cache_t                  s_cache;
code_editor_widget::selection_t s_sel;
code_editor_widget::find_state_t s_find;
code_editor_widget::goto_state_t s_goto;


static constexpr int UNDO_MAX = 100;
std::vector<code_editor_widget::undo_entry_t> s_undo;
std::vector<code_editor_widget::undo_entry_t> s_redo;
bool s_undo_group_open = false;


float s_scroll_y    = 0.f;
float s_scroll_x    = 0.f;
float s_target_scroll_y = 0.f;


float s_blink_timer = 0.f;
bool  s_blink_on    = true;


bool  s_mouse_selecting = false;
float s_last_click_time = 0.f;
int   s_click_count     = 0;


syntax::language_def_t s_lang;
bool s_lang_set = false;


bool s_has_focus = false;
ImGuiID s_widget_id = 0;


std::string    s_ghost_text;
std::mutex     s_ghost_mtx;
std::string    s_ghost_pending;
bool           s_ghost_has_pending = false;
float          s_ghost_debounce = 0.f;
int            s_ghost_trigger_line = -1;
int            s_ghost_trigger_col  = -1;
bool           s_ghost_requesting = false;
std::thread    s_ghost_worker;

bool s_request_undo = false;
bool s_request_redo = false;
bool s_request_find = false;
bool s_request_replace = false;


void rebuild_lines() {
    s_cache.lines.clear();
    if (code_editor::buffer.empty()) {
        s_cache.lines.push_back("");
        s_cache.tokens.clear();
        s_cache.tokens.push_back({});
        s_cache.dirty = false;
        return;
    }

    const char* txt = code_editor::buffer.data();
    const char* p = txt;
    const char* line_start = txt;
    while (*p) {
        if (*p == '\n') {
            s_cache.lines.emplace_back(line_start, p);
            line_start = p + 1;
        }
        p++;
    }
    s_cache.lines.emplace_back(line_start, p);


    s_cache.tokens.resize(s_cache.lines.size());
    for (size_t i = 0; i < s_cache.lines.size(); i++) {
        syntax::tokenize(s_cache.lines[i], s_lang, s_cache.tokens[i]);
    }
    s_cache.dirty = false;
}

void rebuild_buffer_from_lines() {
    std::string result;
    for (size_t i = 0; i < s_cache.lines.size(); i++) {
        if (i > 0) result += '\n';
        result += s_cache.lines[i];
    }
    size_t needed = result.size() + 1024 * 64;
    if (code_editor::buffer.size() < needed)
        code_editor::buffer.resize(needed);
    memcpy(code_editor::buffer.data(), result.c_str(), result.size());
    code_editor::buffer[result.size()] = '\0';
    code_editor::dirty = true;


    s_cache.tokens.resize(s_cache.lines.size());
    for (size_t i = 0; i < s_cache.lines.size(); i++) {
        syntax::tokenize(s_cache.lines[i], s_lang, s_cache.tokens[i]);
    }
}

int line_count() { return (int)s_cache.lines.size(); }

const std::string& line_at(int idx) {
    static const std::string empty;
    if (idx < 0 || idx >= (int)s_cache.lines.size()) return empty;
    return s_cache.lines[idx];
}

int line_length(int idx) { return (int)line_at(idx).size(); }

int clamp_col(int line, int col) {
    return std::max(0, std::min(col, line_length(line)));
}

int clamp_line(int line) {
    return std::max(0, std::min(line, line_count() - 1));
}


int byte_offset(int line, int col) {
    int off = 0;
    for (int i = 0; i < line && i < line_count(); i++)
        off += line_length(i) + 1;
    off += std::min(col, line_length(line));
    return off;
}


void selection_ordered(int& l0, int& c0, int& l1, int& c1) {
    if (s_sel.anchor_line < s_sel.caret_line ||
        (s_sel.anchor_line == s_sel.caret_line && s_sel.anchor_col <= s_sel.caret_col)) {
        l0 = s_sel.anchor_line; c0 = s_sel.anchor_col;
        l1 = s_sel.caret_line;  c1 = s_sel.caret_col;
    } else {
        l0 = s_sel.caret_line;  c0 = s_sel.caret_col;
        l1 = s_sel.anchor_line; c1 = s_sel.anchor_col;
    }
}

std::string get_selected_text() {
    if (!s_sel.has_selection()) return {};
    int l0, c0, l1, c1;
    selection_ordered(l0, c0, l1, c1);
    if (l0 == l1) {
        auto& ln = line_at(l0);
        c0 = std::min(c0, (int)ln.size());
        c1 = std::min(c1, (int)ln.size());
        return ln.substr(c0, c1 - c0);
    }
    std::string result;
    result += line_at(l0).substr(std::min(c0, line_length(l0)));
    result += '\n';
    for (int i = l0 + 1; i < l1; i++) {
        result += line_at(i);
        result += '\n';
    }
    result += line_at(l1).substr(0, std::min(c1, line_length(l1)));
    return result;
}

void push_undo() {
    code_editor_widget::undo_entry_t e;
    e.text = code_editor::buffer.data();
    e.caret_line = s_sel.caret_line;
    e.caret_col  = s_sel.caret_col;
    s_undo.push_back(std::move(e));
    if ((int)s_undo.size() > UNDO_MAX) s_undo.erase(s_undo.begin());
    s_redo.clear();
}

void delete_selection() {
    if (!s_sel.has_selection()) return;
    push_undo();
    int l0, c0, l1, c1;
    selection_ordered(l0, c0, l1, c1);
    c0 = std::min(c0, line_length(l0));
    c1 = std::min(c1, line_length(l1));

    if (l0 == l1) {
        s_cache.lines[l0].erase(c0, c1 - c0);
    } else {
        std::string merged = s_cache.lines[l0].substr(0, c0) +
                             s_cache.lines[l1].substr(c1);
        s_cache.lines[l0] = merged;
        s_cache.lines.erase(s_cache.lines.begin() + l0 + 1,
                            s_cache.lines.begin() + l1 + 1);
        s_cache.tokens.erase(s_cache.tokens.begin() + l0 + 1,
                             s_cache.tokens.begin() + l1 + 1);
    }
    s_sel.caret_line = s_sel.anchor_line = l0;
    s_sel.caret_col  = s_sel.anchor_col  = c0;
    s_sel.active = false;
    rebuild_buffer_from_lines();
}

void insert_text_at_caret(const std::string& text) {
    if (s_sel.has_selection()) delete_selection();
    else push_undo();

    int line = s_sel.caret_line;
    int col  = clamp_col(line, s_sel.caret_col);


    std::vector<std::string> ins_lines;
    {
        const char* p = text.c_str();
        const char* s = p;
        while (*p) {
            if (*p == '\n') {
                ins_lines.emplace_back(s, p);
                s = p + 1;
            }
            p++;
        }
        ins_lines.emplace_back(s, p);
    }

    if (ins_lines.size() == 1) {
        s_cache.lines[line].insert(col, ins_lines[0]);
        s_sel.caret_col = s_sel.anchor_col = col + (int)ins_lines[0].size();
    } else {
        std::string tail = s_cache.lines[line].substr(col);
        s_cache.lines[line] = s_cache.lines[line].substr(0, col) + ins_lines[0];

        for (size_t i = 1; i < ins_lines.size() - 1; i++) {
            s_cache.lines.insert(s_cache.lines.begin() + line + (int)i, ins_lines[i]);
            s_cache.tokens.insert(s_cache.tokens.begin() + line + (int)i, {});
        }

        int last_idx = line + (int)ins_lines.size() - 1;
        std::string last_line = ins_lines.back() + tail;
        s_cache.lines.insert(s_cache.lines.begin() + last_idx, last_line);
        s_cache.tokens.insert(s_cache.tokens.begin() + last_idx, {});

        s_sel.caret_line = s_sel.anchor_line = last_idx;
        s_sel.caret_col  = s_sel.anchor_col  = (int)ins_lines.back().size();
    }
    s_sel.active = false;
    rebuild_buffer_from_lines();
}


void clipboard_copy(const std::string& text) {
    if (text.empty()) return;
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hg) {
        memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
        GlobalUnlock(hg);
        SetClipboardData(CF_TEXT, hg);
    }
    CloseClipboard();
}

std::string clipboard_paste() {
    if (!OpenClipboard(nullptr)) return {};
    HANDLE hd = GetClipboardData(CF_TEXT);
    if (!hd) { CloseClipboard(); return {}; }
    const char* p = (const char*)GlobalLock(hd);
    std::string result;
    if (p) {
        result = p;

        std::string normalized;
        for (size_t i = 0; i < result.size(); i++) {
            if (result[i] == '\r') continue;
            normalized += result[i];
        }
        result = normalized;
    }
    GlobalUnlock(hd);
    CloseClipboard();
    return result;
}

void do_undo() {
    if (s_undo.empty()) return;
    auto& e = s_undo.back();

    code_editor_widget::undo_entry_t redo_e;
    redo_e.text = code_editor::buffer.data();
    redo_e.caret_line = s_sel.caret_line;
    redo_e.caret_col  = s_sel.caret_col;
    s_redo.push_back(std::move(redo_e));


    size_t needed = e.text.size() + 1024 * 64;
    if (code_editor::buffer.size() < needed)
        code_editor::buffer.resize(needed);
    memcpy(code_editor::buffer.data(), e.text.c_str(), e.text.size());
    code_editor::buffer[e.text.size()] = '\0';
    s_sel.caret_line = s_sel.anchor_line = e.caret_line;
    s_sel.caret_col  = s_sel.anchor_col  = e.caret_col;
    s_sel.active = false;
    s_undo.pop_back();
    s_cache.dirty = true;
}

void do_redo() {
    if (s_redo.empty()) return;
    auto& e = s_redo.back();
    code_editor_widget::undo_entry_t undo_e;
    undo_e.text = code_editor::buffer.data();
    undo_e.caret_line = s_sel.caret_line;
    undo_e.caret_col  = s_sel.caret_col;
    s_undo.push_back(std::move(undo_e));

    size_t needed = e.text.size() + 1024 * 64;
    if (code_editor::buffer.size() < needed)
        code_editor::buffer.resize(needed);
    memcpy(code_editor::buffer.data(), e.text.c_str(), e.text.size());
    code_editor::buffer[e.text.size()] = '\0';
    s_sel.caret_line = s_sel.anchor_line = e.caret_line;
    s_sel.caret_col  = s_sel.anchor_col  = e.caret_col;
    s_sel.active = false;
    s_redo.pop_back();
    s_cache.dirty = true;
}

void ensure_caret_visible(float vis_h, float line_h) {
    float caret_y = s_sel.caret_line * line_h;
    if (caret_y < s_scroll_y)
        s_target_scroll_y = caret_y;
    else if (caret_y + line_h > s_scroll_y + vis_h)
        s_target_scroll_y = caret_y - vis_h + line_h * 2.f;
}


void screen_to_linecol(float sx, float sy, float origin_x, float origin_y,
                        float gutter_w, float line_h, float char_w,
                        int& out_line, int& out_col) {
    float rel_y = sy - origin_y + s_scroll_y;
    float rel_x = sx - origin_x - gutter_w - 4.f + s_scroll_x;
    out_line = clamp_line((int)(rel_y / line_h));
    out_col  = std::max(0, (int)((rel_x + char_w * 0.5f) / char_w));
    out_col  = clamp_col(out_line, out_col);
}

bool is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}


void word_bounds(int line, int col, int& start, int& end) {
    auto& ln = line_at(line);
    start = col;
    end   = col;
    while (start > 0 && is_word_char(ln[start - 1])) start--;
    while (end < (int)ln.size() && is_word_char(ln[end])) end++;
}


void find_all_matches() {
    s_find.match_positions.clear();
    s_find.total_matches = 0;
    s_find.current_match = -1;
    if (s_find.find_buf[0] == '\0') return;

    std::string needle = s_find.find_buf;
    if (!s_find.case_sensitive) {
        for (auto& c : needle) c = (char)tolower((unsigned char)c);
    }
    int needle_len = (int)needle.size();
    if (needle_len == 0) return;

    for (int i = 0; i < (int)s_cache.lines.size(); i++) {
        std::string haystack = s_cache.lines[i];
        if (!s_find.case_sensitive) {
            for (auto& c : haystack) c = (char)tolower((unsigned char)c);
        }
        size_t pos = 0;
        while ((pos = haystack.find(needle, pos)) != std::string::npos) {
            s_find.match_positions.push_back({ i, (int)pos });
            pos += needle_len;
        }
    }
    s_find.total_matches = (int)s_find.match_positions.size();
}

void find_next() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match + 1) % (int)s_find.match_positions.size();
    auto [line, col] = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = line;
    s_sel.caret_col  = col + (int)strlen(s_find.find_buf);
    s_sel.anchor_col = col;
    s_sel.active = true;
}

void find_prev() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match - 1 + (int)s_find.match_positions.size())
                            % (int)s_find.match_positions.size();
    auto [line, col] = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = line;
    s_sel.caret_col  = col + (int)strlen(s_find.find_buf);
    s_sel.anchor_col = col;
    s_sel.active = true;
}

void replace_current() {
    if (s_find.current_match < 0 || s_find.current_match >= (int)s_find.match_positions.size())
        return;
    auto [line, col] = s_find.match_positions[s_find.current_match];
    int find_len = (int)strlen(s_find.find_buf);
    push_undo();
    s_cache.lines[line].erase(col, find_len);
    s_cache.lines[line].insert(col, s_find.replace_buf);
    rebuild_buffer_from_lines();
    find_all_matches();
}

void replace_all() {
    if (s_find.match_positions.empty()) return;
    push_undo();
    int find_len = (int)strlen(s_find.find_buf);
    int repl_len = (int)strlen(s_find.replace_buf);

    for (int i = (int)s_find.match_positions.size() - 1; i >= 0; i--) {
        auto [line, col] = s_find.match_positions[i];
        s_cache.lines[line].erase(col, find_len);
        s_cache.lines[line].insert(col, s_find.replace_buf);
    }
    rebuild_buffer_from_lines();
    find_all_matches();
}

}


void code_editor_widget::init() {
    s_cache.dirty = true;
    s_sel = {};
    s_find = {};
    s_goto = {};
    s_undo.clear();
    s_redo.clear();
    s_scroll_y = s_scroll_x = s_target_scroll_y = 0.f;
    s_lang_set = false;
}

void code_editor_widget::on_text_changed() {
    s_cache.dirty = true;
    s_sel = {};
    s_undo.clear();
    s_redo.clear();
    s_scroll_y = s_scroll_x = s_target_scroll_y = 0.f;
    s_blink_timer = 0.f;
    s_blink_on = true;


    if (!code_editor::filename.empty()) {
        s_lang = syntax::detect_language(code_editor::filename);
        s_lang_set = true;
    }
}

void code_editor_widget::get_caret(int& line, int& col) {
    line = s_sel.caret_line;
    col  = s_sel.caret_col;
}

void code_editor_widget::trigger_undo()   { s_request_undo = true; }
void code_editor_widget::trigger_redo()   { s_request_redo = true; }
void code_editor_widget::open_find()      { s_request_find = true; }
void code_editor_widget::open_replace()   { s_request_replace = true; }


void code_editor_widget::render(float pos_x, float pos_y, float width, float height,
                                 float alpha, float accent_r, float accent_g, float accent_b)
{
    if (!code_editor::active || code_editor::buffer.empty())
        return;

    if (s_request_undo)   { do_undo();   s_request_undo = false; }
    if (s_request_redo)   { do_redo();   s_request_redo = false; }
    if (s_request_find)   { s_find.visible = true; s_find.replace_mode = false; s_request_find = false; }
    if (s_request_replace){ s_find.visible = true; s_find.replace_mode = true;  s_request_replace = false; }

    if (!s_lang_set && !code_editor::filename.empty()) {
        s_lang = syntax::detect_language(code_editor::filename);
        s_lang_set = true;
    }

    if (s_cache.dirty)
        rebuild_lines();

    const float a   = alpha;
    const float dt  = ImGui::GetIO().DeltaTime;
    const float line_h = ImGui::GetFontSize() + 2.f;
    const float char_w = ImGui::CalcTextSize("X").x;
    const bool  show_ln = editor_config::show_line_numbers;
    const int   n_lines = line_count();
    const float gutter_w = show_ln ? (ImGui::CalcTextSize("00000").x + 12.f) : 0.f;
    const float text_x0 = gutter_w + 4.f;
    const float text_w  = width - text_x0 - 4.f;


    ImU32 tok_colors[(int)syntax::token_type::COUNT];
    syntax::get_token_colors(tok_colors, accent_r * 255.f, accent_g * 255.f, accent_b * 255.f, a);


    const float find_bar_h = s_find.visible ? (s_find.replace_mode ? 60.f : 32.f) : 0.f;
    const float goto_bar_h = s_goto.visible ? 32.f : 0.f;
    const float overlay_h = find_bar_h + goto_bar_h;
    const float editor_y0 = pos_y + overlay_h;
    const float editor_h  = height - overlay_h;


    s_scroll_y += (s_target_scroll_y - s_scroll_y) * std::min(20.f * dt, 1.f);
    if (std::abs(s_target_scroll_y - s_scroll_y) < 0.5f)
        s_scroll_y = s_target_scroll_y;
    float max_scroll = std::max(0.f, n_lines * line_h - editor_h + line_h);
    s_target_scroll_y = std::max(0.f, std::min(s_target_scroll_y, max_scroll));
    s_scroll_y = std::max(0.f, std::min(s_scroll_y, max_scroll));


    s_blink_timer += dt;
    if (s_blink_timer > 0.53f) { s_blink_on = !s_blink_on; s_blink_timer = 0.f; }


    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos   = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + editor_y0;


    ImGuiID id = ImGui::GetID("##code_editor_widget");
    s_widget_id = id;
    ImRect bb(ImVec2(ox, oy), ImVec2(ox + width, oy + editor_h));
    ImGui::ItemSize(ImVec2(width, height));
    if (!ImGui::ItemAdd(bb, id)) return;


    bool hovered = ImGui::IsMouseHoveringRect(bb.Min, bb.Max);
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        ImGui::SetActiveID(id, ImGui::GetCurrentWindow());
        ImGui::SetFocusID(id, ImGui::GetCurrentWindow());
        s_has_focus = true;
    }
    if (ImGui::GetActiveID() != id && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        s_has_focus = false;


    if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_TextInput);
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            s_target_scroll_y -= wheel * line_h * 3.f;
    }


    int first_row = std::max(0, (int)(s_scroll_y / line_h) - 1);
    int last_row  = std::min(n_lines - 1, (int)((s_scroll_y + editor_h) / line_h) + 1);


    if (show_ln) {
        dl->AddLine(ImVec2(ox + gutter_w, oy),
                    ImVec2(ox + gutter_w, oy + editor_h),
                    IM_COL32(255, 255, 255, (int)(10 * a)), 1.f);
    }


    if (editor_config::highlight_current_line && s_has_focus) {
        float cy = oy + s_sel.caret_line * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + width, cy + line_h),
                              IM_COL32(255, 255, 255, (int)(8 * a)));
        }
    }


    if (s_sel.has_selection()) {
        int l0, c0, l1, c1;
        selection_ordered(l0, c0, l1, c1);
        ImU32 sel_col = IM_COL32((int)(accent_r * 180), (int)(accent_g * 180),
                                  (int)(accent_b * 180), (int)(60 * a));
        for (int i = std::max(first_row, l0); i <= std::min(last_row, l1); i++) {
            float ly = oy + i * line_h - s_scroll_y;
            float sx0, sx1;
            if (i == l0 && i == l1) {
                sx0 = ox + text_x0 + c0 * char_w - s_scroll_x;
                sx1 = ox + text_x0 + c1 * char_w - s_scroll_x;
            } else if (i == l0) {
                sx0 = ox + text_x0 + c0 * char_w - s_scroll_x;
                sx1 = ox + text_x0 + line_length(i) * char_w - s_scroll_x + char_w;
            } else if (i == l1) {
                sx0 = ox + text_x0 - s_scroll_x;
                sx1 = ox + text_x0 + c1 * char_w - s_scroll_x;
            } else {
                sx0 = ox + text_x0 - s_scroll_x;
                sx1 = ox + text_x0 + line_length(i) * char_w - s_scroll_x + char_w;
            }
            sx0 = std::max(sx0, ox + text_x0);
            dl->AddRectFilled(ImVec2(sx0, ly), ImVec2(sx1, ly + line_h), sel_col);
        }
    }


    if (s_find.visible && !s_find.match_positions.empty()) {
        int find_len = (int)strlen(s_find.find_buf);
        ImU32 match_col  = IM_COL32((int)(accent_r * 220), (int)(accent_g * 220),
                                     (int)(accent_b * 220), (int)(35 * a));
        ImU32 active_col = IM_COL32((int)(accent_r * 255), (int)(accent_g * 255),
                                     (int)(accent_b * 255), (int)(70 * a));
        for (int mi = 0; mi < (int)s_find.match_positions.size(); mi++) {
            auto [ml, mc] = s_find.match_positions[mi];
            if (ml < first_row || ml > last_row) continue;
            float my = oy + ml * line_h - s_scroll_y;
            float mx0 = ox + text_x0 + mc * char_w - s_scroll_x;
            float mx1 = mx0 + find_len * char_w;
            dl->AddRectFilled(ImVec2(mx0, my), ImVec2(mx1, my + line_h),
                              (mi == s_find.current_match) ? active_col : match_col);
        }
    }


    for (int i = first_row; i <= last_row; i++) {
        float y = oy + i * line_h - s_scroll_y;


        if (i & 1)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + gutter_w, y + line_h - 1.f),
                              IM_COL32(255, 255, 255, (int)(3.f * a)));


        if (show_ln) {
            char ln_buf[8];
            snprintf(ln_buf, sizeof(ln_buf), "%5d", i + 1);
            ImU32 ln_col = (i == s_sel.caret_line)
                ? IM_COL32(200, 200, 220, (int)(200 * a))
                : IM_COL32(75, 85, 120, (int)(140 * a));
            dl->AddText(ImVec2(ox + 4.f, y + 1.f), ln_col, ln_buf);
        }


        if (i < (int)s_cache.tokens.size()) {
            auto& toks = s_cache.tokens[i];
            auto& ln = s_cache.lines[i];
            float tx = ox + text_x0 - s_scroll_x;

            for (auto& tok : toks) {
                if (tok.type == syntax::token_type::whitespace) {

                    for (uint32_t k = 0; k < tok.length; k++) {
                        char c = ln[tok.start + k];
                        if (c == '\t')
                            tx += char_w * editor_config::tab_size;
                        else
                            tx += char_w;
                    }
                    continue;
                }

                if (tok.start + tok.length > (uint32_t)ln.size()) continue;

                ImU32 col = tok_colors[(int)tok.type];
                const char* ts = ln.c_str() + tok.start;
                const char* te = ts + tok.length;


                float tok_w = tok.length * char_w;
                if (tx + tok_w < ox + text_x0 || tx > ox + width) {
                    tx += tok_w;
                    continue;
                }

                dl->AddText(ImVec2(tx, y + 1.f), col, ts, te);
                tx += tok_w;
            }
        }
    }


    if (s_has_focus && s_blink_on) {
        float cx = ox + text_x0 + s_sel.caret_col * char_w - s_scroll_x;
        float cy = oy + s_sel.caret_line * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddLine(ImVec2(cx, cy), ImVec2(cx, cy + line_h),
                        IM_COL32(230, 230, 255, (int)(220 * a)), 1.5f);
        }
    }


    if (g_sa_settings.ghost_text_enabled && s_has_focus) {

        {
            std::lock_guard<std::mutex> lk(s_ghost_mtx);
            if (s_ghost_has_pending) {
                s_ghost_text = std::move(s_ghost_pending);
                s_ghost_pending.clear();
                s_ghost_has_pending = false;
                s_ghost_requesting = false;
            }
        }


        if (s_sel.caret_line != s_ghost_trigger_line || s_sel.caret_col != s_ghost_trigger_col) {
            s_ghost_debounce = 0.f;
            s_ghost_trigger_line = s_sel.caret_line;
            s_ghost_trigger_col  = s_sel.caret_col;
            s_ghost_text.clear();
        }


        if (s_ghost_text.empty() && !s_ghost_requesting && s_ghost_debounce < 0.5f) {
            s_ghost_debounce += dt;
            if (s_ghost_debounce >= 0.5f && n_lines > 0) {

                int ctx_start = (std::max)(0, s_sel.caret_line - 20);
                std::string context;
                context.reserve(2048);
                for (int i = ctx_start; i < n_lines && i <= s_sel.caret_line; i++) {
                    const std::string& ln = line_at(i);
                    if (i == s_sel.caret_line) {
                        int col = (std::min)(s_sel.caret_col, (int)ln.size());
                        context.append(ln, 0, col);
                    } else {
                        context += ln;
                        context += '\n';
                    }
                }

                if (!context.empty() && g_sa_ai_client) {

                    uint64_t gt = standalone_license::inline_gate_check(
                        standalone_license::gate_editor_ghost);
                    if (standalone_license::verify_gate_token(
                            standalone_license::gate_editor_ghost, gt) < 0.5) {
                        s_ghost_debounce = 0.f;
                    } else {
                    s_ghost_requesting = true;
                    if (s_ghost_worker.joinable()) s_ghost_worker.join();
                    s_ghost_worker = std::thread([context]() {
                        std::string prompt = "Complete the following code. Output ONLY the completion text (the part that comes after the cursor), nothing else. No explanation, no markdown. If there's nothing meaningful to suggest, output nothing.\n\n```\n" + context + "```";
                        std::vector<std::pair<std::string, std::string>> empty_history;
                        std::string result = g_sa_ai_client->chat_blocking(prompt, empty_history);

                        if (result.size() > 6 && result.substr(0, 3) == "```") {
                            auto nl = result.find('\n');
                            if (nl != std::string::npos) result = result.substr(nl + 1);
                            if (result.size() >= 3 && result.substr(result.size()-3) == "```")
                                result.resize(result.size()-3);
                        }

                        auto nl = result.find('\n');
                        if (nl != std::string::npos) result.resize(nl);

                        while (!result.empty() && (result.back() == ' ' || result.back() == '\t' || result.back() == '\r'))
                            result.pop_back();

                        std::lock_guard<std::mutex> lk(s_ghost_mtx);
                        s_ghost_pending = std::move(result);
                        s_ghost_has_pending = true;
                    });
                    }
                }
            }
        }


        if (!s_ghost_text.empty()) {
            float gx = ox + text_x0 + s_sel.caret_col * char_w - s_scroll_x;
            float gy = oy + s_sel.caret_line * line_h - s_scroll_y;
            if (gy >= oy - line_h && gy <= oy + editor_h) {
                dl->AddText(ImVec2(gx, gy + 1.f),
                    IM_COL32(150, 160, 200, (int)(90 * a)),
                    s_ghost_text.c_str());
            }


            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
                insert_text_at_caret(s_ghost_text);
                s_ghost_text.clear();
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                s_ghost_text.clear();
            }
        }
    }


    if (s_has_focus || hovered) {
        ImVec2 mp = ImGui::GetIO().MousePos;
        bool in_text = mp.x >= ox + text_x0 && mp.y >= oy && mp.y <= oy + editor_h;

        if (in_text && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);


            float now = (float)ImGui::GetTime();
            if (now - s_last_click_time < 0.3f) s_click_count++;
            else s_click_count = 1;
            s_last_click_time = now;

            if (s_click_count == 2) {
                int ws, we;
                word_bounds(ml, mc, ws, we);
                s_sel.anchor_line = s_sel.caret_line = ml;
                s_sel.anchor_col = ws;
                s_sel.caret_col  = we;
                s_sel.active = true;
            } else if (s_click_count >= 3) {

                s_sel.anchor_line = s_sel.caret_line = ml;
                s_sel.anchor_col = 0;
                s_sel.caret_col  = line_length(ml);
                s_sel.active = true;
            } else {
                bool shift = ImGui::GetIO().KeyShift;
                if (!shift) {
                    s_sel.anchor_line = ml;
                    s_sel.anchor_col  = mc;
                }
                s_sel.caret_line = ml;
                s_sel.caret_col  = mc;
                s_sel.active = shift;
                s_mouse_selecting = true;
            }
            s_blink_timer = 0.f; s_blink_on = true;
        }

        if (s_mouse_selecting && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);
            s_sel.caret_line = ml;
            s_sel.caret_col  = mc;
            s_sel.active = true;
        }

        if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
            s_mouse_selecting = false;
    }


    if (s_has_focus) {
        auto& io = ImGui::GetIO();
        bool ctrl  = io.KeyCtrl;
        bool shift = io.KeyShift;


        ImGui::SetKeyOwner(ImGuiKey_Enter, id);
        ImGui::SetKeyOwner(ImGuiKey_KeypadEnter, id);
        ImGui::SetKeyOwner(ImGuiKey_Tab, id);
        ImGui::SetKeyOwner(ImGuiKey_Escape, id);


        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_A, false)) {

            s_sel.anchor_line = 0; s_sel.anchor_col = 0;
            s_sel.caret_line = line_count() - 1;
            s_sel.caret_col  = line_length(s_sel.caret_line);
            s_sel.active = true;
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
            std::string txt = get_selected_text();
            if (!txt.empty()) clipboard_copy(txt);
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_X, false)) {
            std::string txt = get_selected_text();
            if (!txt.empty()) { clipboard_copy(txt); delete_selection(); }
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_V, false)) {
            std::string txt = clipboard_paste();
            if (!txt.empty()) insert_text_at_caret(txt);
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Z, false)) {
            do_undo();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Y, false)) {
            do_redo();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
            s_find.visible = true;
            s_find.replace_mode = false;

            if (s_sel.has_selection()) {
                std::string sel = get_selected_text();
                if (sel.find('\n') == std::string::npos)
                    strncpy_s(s_find.find_buf, sel.c_str(), _TRUNCATE);
            }
            find_all_matches();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_H, false)) {
            s_find.visible = true;
            s_find.replace_mode = true;
            if (s_sel.has_selection()) {
                std::string sel = get_selected_text();
                if (sel.find('\n') == std::string::npos)
                    strncpy_s(s_find.find_buf, sel.c_str(), _TRUNCATE);
            }
            find_all_matches();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_G, false)) {
            s_goto.visible = !s_goto.visible;
            s_goto.line_buf[0] = '\0';
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_S, false)) {
            code_editor::save();
        }


        auto move_caret = [&](int new_line, int new_col) {
            if (shift) s_sel.active = true;
            else { s_sel.active = false; s_sel.anchor_line = new_line; s_sel.anchor_col = new_col; }
            s_sel.caret_line = new_line;
            s_sel.caret_col  = new_col;
            s_blink_timer = 0.f; s_blink_on = true;
            ensure_caret_visible(editor_h, line_h);
        };

        if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (ctrl) {

            } else if (nc > 0) {
                nc--;
            } else if (nl > 0) {
                nl--; nc = line_length(nl);
            }
            move_caret(nl, nc);
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_RightArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (nc < line_length(nl)) {
                nc++;
            } else if (nl < line_count() - 1) {
                nl++; nc = 0;
            }
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
            int nl = std::max(0, s_sel.caret_line - 1);
            int nc = clamp_col(nl, s_sel.caret_col);
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
            int nl = std::min(line_count() - 1, s_sel.caret_line + 1);
            int nc = clamp_col(nl, s_sel.caret_col);
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_Home, true)) {
            if (ctrl) move_caret(0, 0);
            else move_caret(s_sel.caret_line, 0);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_End, true)) {
            if (ctrl) move_caret(line_count() - 1, line_length(line_count() - 1));
            else move_caret(s_sel.caret_line, line_length(s_sel.caret_line));
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_PageUp, false)) {
            int page = std::max(1, (int)(editor_h / line_h) - 2);
            int nl = std::max(0, s_sel.caret_line - page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) {
            int page = std::max(1, (int)(editor_h / line_h) - 2);
            int nl = std::min(line_count() - 1, s_sel.caret_line + page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }


        if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Enter, true)) {

            std::string indent;
            if (s_sel.caret_line < (int)s_cache.lines.size()) {
                auto& ln = s_cache.lines[s_sel.caret_line];
                for (char c : ln) {
                    if (c == ' ' || c == '\t') indent += c;
                    else break;
                }
            }
            insert_text_at_caret("\n" + indent);
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Backspace, true)) {
            if (s_sel.has_selection()) {
                delete_selection();
            } else if (s_sel.caret_col > 0) {
                push_undo();
                auto& ln = s_cache.lines[s_sel.caret_line];
                ln.erase(s_sel.caret_col - 1, 1);
                s_sel.caret_col--; s_sel.anchor_col = s_sel.caret_col;
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line > 0) {
                push_undo();
                int prev = s_sel.caret_line - 1;
                int prev_len = (int)s_cache.lines[prev].size();
                s_cache.lines[prev] += s_cache.lines[s_sel.caret_line];
                s_cache.lines.erase(s_cache.lines.begin() + s_sel.caret_line);
                s_cache.tokens.erase(s_cache.tokens.begin() + s_sel.caret_line);
                s_sel.caret_line = s_sel.anchor_line = prev;
                s_sel.caret_col  = s_sel.anchor_col  = prev_len;
                rebuild_buffer_from_lines();
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Delete, true)) {
            if (s_sel.has_selection()) {
                delete_selection();
            } else if (s_sel.caret_col < line_length(s_sel.caret_line)) {
                push_undo();
                s_cache.lines[s_sel.caret_line].erase(s_sel.caret_col, 1);
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line < line_count() - 1) {
                push_undo();
                s_cache.lines[s_sel.caret_line] += s_cache.lines[s_sel.caret_line + 1];
                s_cache.lines.erase(s_cache.lines.begin() + s_sel.caret_line + 1);
                s_cache.tokens.erase(s_cache.tokens.begin() + s_sel.caret_line + 1);
                rebuild_buffer_from_lines();
            }
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Tab, true)) {

            std::string spaces(editor_config::tab_size, ' ');
            insert_text_at_caret(spaces);
        }
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            if (s_find.visible) s_find.visible = false;
            else if (s_goto.visible) s_goto.visible = false;
            else if (autocomplete::popup_visible) {
                autocomplete::popup_visible = false;
                autocomplete::matches.clear();
            }
        }


        if (!ctrl) {
            for (int k = 0; k < io.InputQueueCharacters.Size; k++) {
                ImWchar ch = io.InputQueueCharacters[k];
                if (ch < 32 || ch > 126) continue;
                char c = (char)ch;
                insert_text_at_caret(std::string(1, c));
                ensure_caret_visible(editor_h, line_h);


                if (editor_config::auto_complete && autocomplete::enabled) {
                    int cursor = s_sel.caret_col;
                    int ws = cursor;
                    auto& ln = s_cache.lines[s_sel.caret_line];
                    while (ws > 0 && (isalnum((unsigned char)ln[ws-1]) || ln[ws-1] == '_'))
                        ws--;
                    if (cursor > ws) {
                        autocomplete::partial = ln.substr(ws, cursor - ws);
                        autocomplete::find_matches(autocomplete::partial);
                        autocomplete::popup_visible = !autocomplete::matches.empty();
                        autocomplete::cursor_line = s_sel.caret_line;
                        autocomplete::cursor_col  = s_sel.caret_col;
                    } else {
                        autocomplete::popup_visible = false;
                        autocomplete::matches.clear();
                    }
                }
            }
        }


        if (autocomplete::popup_visible && !autocomplete::matches.empty()) {
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
                autocomplete::selected = (autocomplete::selected - 1 + (int)autocomplete::matches.size())
                    % (int)autocomplete::matches.size();
            }
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
                autocomplete::selected = (autocomplete::selected + 1) % (int)autocomplete::matches.size();
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false) || ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
                if (autocomplete::selected < (int)autocomplete::matches.size()) {

                    int cursor = s_sel.caret_col;
                    int ws = cursor;
                    auto& ln = s_cache.lines[s_sel.caret_line];
                    while (ws > 0 && (isalnum((unsigned char)ln[ws - 1]) || ln[ws - 1] == '_'))
                        ws--;
                    push_undo();
                    ln.erase(ws, cursor - ws);
                    ln.insert(ws, autocomplete::matches[autocomplete::selected]);
                    s_sel.caret_col = s_sel.anchor_col = ws + (int)autocomplete::matches[autocomplete::selected].size();
                    rebuild_buffer_from_lines();
                }
                autocomplete::popup_visible = false;
                autocomplete::matches.clear();
            }
        }
    }


    {
        char buf[128];
        if (code_editor::filename.empty())
            snprintf(buf, sizeof(buf), "Untitled  Ln %d, Col %d",
                     s_sel.caret_line + 1, s_sel.caret_col + 1);
        else
            snprintf(buf, sizeof(buf), "%s%s  Ln %d, Col %d",
                     code_editor::filename.c_str(),
                     code_editor::dirty ? " *" : "",
                     s_sel.caret_line + 1, s_sel.caret_col + 1);
        globals::ui::status_file_info = buf;
    }


    if (autocomplete::popup_visible && !autocomplete::matches.empty() && s_has_focus) {
        float popup_w = 220.f;
        float ac_item_h = 22.f;
        float popup_h = std::min((float)autocomplete::matches.size(), 8.f) * ac_item_h + 8.f;
        float sx = ox + text_x0 + autocomplete::cursor_col * char_w - s_scroll_x;
        float sy = oy + (autocomplete::cursor_line + 1) * line_h - s_scroll_y + 4.f;

        if (sx + popup_w > ox + width) sx = ox + width - popup_w - 4.f;
        if (sy + popup_h > oy + editor_h) sy = oy + autocomplete::cursor_line * line_h - s_scroll_y - popup_h;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(sx, sy), ImVec2(sx + popup_w, sy + popup_h),
            IM_COL32(20, 20, 30, 240), 6.f);
        fdl->AddRect(ImVec2(sx, sy), ImVec2(sx + popup_w, sy + popup_h),
            IM_COL32(80, 80, 130, 100), 6.f);

        for (int mi = 0; mi < (int)autocomplete::matches.size() && mi < 8; mi++) {
            float iy = sy + 4.f + mi * ac_item_h;
            float text_y = iy + (ac_item_h - ImGui::GetFontSize()) * 0.5f;
            if (mi == autocomplete::selected)
                fdl->AddRectFilled(ImVec2(sx + 2.f, iy), ImVec2(sx + popup_w - 2.f, iy + ac_item_h),
                    IM_COL32((int)(accent_r*255), (int)(accent_g*255), (int)(accent_b*255), 50), 4.f);

            auto& match = autocomplete::matches[mi];
            size_t plen = autocomplete::partial.size();
            if (plen > 0 && plen <= match.size()) {
                fdl->AddText(ImVec2(sx + 10.f, text_y),
                    IM_COL32((int)(accent_r*255), (int)(accent_g*255), (int)(accent_b*255), 255),
                    match.c_str(), match.c_str() + plen);
                float prefix_w = ImGui::CalcTextSize(match.c_str(), match.c_str() + plen).x;
                fdl->AddText(ImVec2(sx + 10.f + prefix_w, text_y),
                    IM_COL32(200, 200, 220, 220), match.c_str() + plen);
            } else {
                fdl->AddText(ImVec2(sx + 10.f, text_y),
                    IM_COL32(200, 200, 220, 220), match.c_str());
            }
        }
    }


    if (s_find.visible) {
        float fy = wpos.y + pos_y;
        float fw = width - 20.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(ox + 10.f, fy), ImVec2(ox + 10.f + fw, fy + find_bar_h),
            IM_COL32(30, 30, 40, (int)(240 * a)), 6.f);
        fdl->AddRect(ImVec2(ox + 10.f, fy), ImVec2(ox + 10.f + fw, fy + find_bar_h),
            IM_COL32(80, 80, 120, (int)(80 * a)), 6.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 4.f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.14f, 0.9f));
        ImGui::PushItemWidth(fw * 0.45f);
        bool find_changed = ImGui::InputText("##find_input", s_find.find_buf,
            sizeof(s_find.find_buf), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();

        if (find_changed || ImGui::IsItemDeactivatedAfterEdit())
            find_all_matches();

        ImGui::SameLine();
        if (ImGui::SmallButton("Prev")) find_prev();
        ImGui::SameLine();
        if (ImGui::SmallButton("Next")) find_next();
        ImGui::SameLine();
        if (ImGui::Checkbox("Case", &s_find.case_sensitive)) find_all_matches();
        ImGui::SameLine();
        char match_buf[32];
        snprintf(match_buf, sizeof(match_buf), "%d/%d",
                 s_find.current_match + 1, s_find.total_matches);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, a), "%s", match_buf);
        ImGui::SameLine();
        if (ImGui::SmallButton("X##close_find")) s_find.visible = false;

        if (s_find.replace_mode) {
            ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 30.f));
            ImGui::PushItemWidth(fw * 0.45f);
            ImGui::InputText("##replace_input", s_find.replace_buf, sizeof(s_find.replace_buf));
            ImGui::PopItemWidth();
            ImGui::SameLine();
            if (ImGui::SmallButton("Replace")) replace_current();
            ImGui::SameLine();
            if (ImGui::SmallButton("All")) replace_all();
        }

        ImGui::PopStyleColor();
        ImGui::PopStyleVar();


        if (find_changed) find_next();
    }


    if (s_goto.visible) {
        float gy = wpos.y + pos_y + find_bar_h;
        float gw = 200.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilled(ImVec2(ox + 10.f, gy), ImVec2(ox + 10.f + gw, gy + 30.f),
            IM_COL32(30, 30, 40, (int)(240 * a)), 6.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + find_bar_h + 4.f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.f);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.1f, 0.1f, 0.14f, 0.9f));
        ImGui::PushItemWidth(120.f);
        bool go = ImGui::InputText("##goto_line", s_goto.line_buf, sizeof(s_goto.line_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal);
        ImGui::PopItemWidth();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        ImGui::SameLine();
        if (ImGui::SmallButton("Go") || go) {
            int n = atoi(s_goto.line_buf);
            if (n >= 1 && n <= line_count()) {
                s_sel.caret_line = s_sel.anchor_line = n - 1;
                s_sel.caret_col  = s_sel.anchor_col  = 0;
                s_sel.active = false;
                ensure_caret_visible(editor_h, line_h);
                s_goto.visible = false;
            }
        }
    }
}
