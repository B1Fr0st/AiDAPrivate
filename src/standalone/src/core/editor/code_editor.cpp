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
#include <cmath>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <vector>
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "fonts.hpp"
#include "ui_anim.hpp"


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

bool  s_focus_find_input = false;
bool  s_find_has_focus   = false;
char  s_find_last_buf[256] = {};


bool  s_mouse_selecting = false;
float s_last_click_time = 0.f;
int   s_click_count     = 0;

bool  s_sb_dragging     = false;
float s_sb_drag_offset  = 0.f;


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

std::string s_last_error;


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
            const char* line_end = (p > line_start && *(p - 1) == '\r') ? p - 1 : p;
            s_cache.lines.emplace_back(line_start, line_end);
            line_start = p + 1;
        }
        p++;
    }
    const char* line_end = (p > line_start && *(p - 1) == '\r') ? p - 1 : p;
    s_cache.lines.emplace_back(line_start, line_end);


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

int line_count() { return static_cast<int>(s_cache.lines.size()); }

const std::string& line_at(int idx) {
    static const std::string empty;
    if (idx < 0 || idx >= static_cast<int>(s_cache.lines.size())) return empty;
    return s_cache.lines[idx];
}

int line_length(int idx) { return static_cast<int>(line_at(idx).size()); }

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
        c0 = std::min(c0, static_cast<int>(ln.size()));
        c1 = std::min(c1, static_cast<int>(ln.size()));
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
    if (static_cast<int>(s_undo.size()) > UNDO_MAX) s_undo.erase(s_undo.begin());
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
        s_sel.caret_col = s_sel.anchor_col = col + static_cast<int>(ins_lines[0].size());
    } else {
        std::string tail = s_cache.lines[line].substr(col);
        s_cache.lines[line] = s_cache.lines[line].substr(0, col) + ins_lines[0];

        for (size_t i = 1; i < ins_lines.size() - 1; i++) {
            s_cache.lines.insert(s_cache.lines.begin() + line + static_cast<int>(i), ins_lines[i]);
            s_cache.tokens.insert(s_cache.tokens.begin() + line + static_cast<int>(i), {});
        }

        int last_idx = line + static_cast<int>(ins_lines.size()) - 1;
        std::string last_line = ins_lines.back() + tail;
        s_cache.lines.insert(s_cache.lines.begin() + last_idx, last_line);
        s_cache.tokens.insert(s_cache.tokens.begin() + last_idx, {});

        s_sel.caret_line = s_sel.anchor_line = last_idx;
        s_sel.caret_col  = s_sel.anchor_col  = static_cast<int>(ins_lines.back().size());
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
    const char* p = static_cast<const char*>(GlobalLock(hd));
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
    out_line = clamp_line(static_cast<int>(rel_y / line_h));
    out_col  = std::max(0, static_cast<int>((rel_x + char_w * 0.5f) / char_w));
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
    while (end < static_cast<int>(ln.size()) && is_word_char(ln[end])) end++;
}


void find_all_matches() {
    s_find.match_positions.clear();
    s_find.total_matches = 0;
    s_find.current_match = -1;
    if (s_find.find_buf[0] == '\0') return;

    std::string needle = s_find.find_buf;
    if (needle.empty()) return;

    if (s_find.use_regex) {
        try {
            auto flags = std::regex_constants::ECMAScript;
            if (!s_find.case_sensitive)
                flags |= std::regex_constants::icase;
            std::regex re(needle, flags);
            for (int i = 0; i < static_cast<int>(s_cache.lines.size()); i++) {
                const std::string& line = s_cache.lines[i];
                auto it  = std::sregex_iterator(line.begin(), line.end(), re);
                auto end = std::sregex_iterator();
                for (; it != end; ++it) {
                    if (it->length() == 0) break;
                    s_find.match_positions.push_back({ i, static_cast<int>(it->position()) });
                }
            }
        } catch (const std::regex_error& e) {
            s_last_error = std::string("code_editor: invalid regex in live highlight: ") + e.what();
            s_find.match_positions.clear();
        } catch (...) {
            s_last_error = "code_editor: invalid regex in live highlight";
            s_find.match_positions.clear();
        }
    } else {
        if (!s_find.case_sensitive) {
            for (auto& c : needle) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        }
        int needle_len = static_cast<int>(needle.size());

        for (int i = 0; i < static_cast<int>(s_cache.lines.size()); i++) {
            std::string haystack = s_cache.lines[i];
            if (!s_find.case_sensitive) {
                for (auto& c : haystack) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            }
            size_t pos = 0;
            while ((pos = haystack.find(needle, pos)) != std::string::npos) {
                if (s_find.whole_word) {
                    bool left_ok  = (pos == 0) || (!isalnum(static_cast<unsigned char>(haystack[pos - 1])) && haystack[pos - 1] != '_');
                    bool right_ok = (pos + needle_len >= haystack.size()) || (!isalnum(static_cast<unsigned char>(haystack[pos + needle_len])) && haystack[pos + needle_len] != '_');
                    if (!left_ok || !right_ok) { pos += 1; continue; }
                }
                s_find.match_positions.push_back({ i, static_cast<int>(pos) });
                pos += needle_len;
            }
        }
    }
    s_find.total_matches = static_cast<int>(s_find.match_positions.size());
}

void find_next() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match + 1) % static_cast<int>(s_find.match_positions.size());
    auto [line, col] = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = line;
    s_sel.caret_col  = col + static_cast<int>(strlen(s_find.find_buf));
    s_sel.anchor_col = col;
    s_sel.active = true;
}

void find_prev() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match - 1 + static_cast<int>(s_find.match_positions.size()))
                            % static_cast<int>(s_find.match_positions.size());
    auto [line, col] = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = line;
    s_sel.caret_col  = col + static_cast<int>(strlen(s_find.find_buf));
    s_sel.anchor_col = col;
    s_sel.active = true;
}

void replace_current() {
    if (s_find.current_match < 0 || s_find.current_match >= static_cast<int>(s_find.match_positions.size()))
        return;
    auto [line, col] = s_find.match_positions[s_find.current_match];
    int find_len = static_cast<int>(strlen(s_find.find_buf));
    push_undo();
    s_cache.lines[line].erase(col, find_len);
    s_cache.lines[line].insert(col, s_find.replace_buf);
    rebuild_buffer_from_lines();
    find_all_matches();
}

void replace_all() {
    if (s_find.match_positions.empty()) return;
    push_undo();
    int find_len = static_cast<int>(strlen(s_find.find_buf));
    int repl_len = static_cast<int>(strlen(s_find.replace_buf));

    for (int i = static_cast<int>(s_find.match_positions.size()) - 1; i >= 0; i--) {
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

std::string code_editor_widget::last_error() {
    return s_last_error;
}


void code_editor_widget::render(float pos_x, float pos_y, float width, float height,
                                 float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    if (!code_editor::active || code_editor::buffer.empty())
        return;

    if (g_code_font) ImGui::PushFont(g_code_font);

    if (s_request_undo)   { do_undo();   s_request_undo = false; }
    if (s_request_redo)   { do_redo();   s_request_redo = false; }
    if (s_request_find)   { s_find.visible = true; s_find.replace_mode = false; s_request_find = false; s_focus_find_input = true; }
    if (s_request_replace){ s_find.visible = true; s_find.replace_mode = true;  s_request_replace = false; s_focus_find_input = true; }

    if (!s_lang_set && !code_editor::filename.empty()) {
        s_lang = syntax::detect_language(code_editor::filename);
        s_lang_set = true;
    }

    if (s_cache.dirty)
        rebuild_lines();

    const auto& th = aida::ui::resolved();
    const float a   = alpha;
    const float dt  = aida::ui::clock::dt();
    const float line_h = ImGui::GetFontSize() + 2.f;
    const float char_w = ImGui::CalcTextSize("X").x;
    const bool  show_ln = editor_config::show_line_numbers;
    const int   n_lines = line_count();
    const float gutter_w = show_ln ? (ImGui::CalcTextSize("00000").x + 12.f) : 0.f;

    static aida::ui::transition_t s_caret_move_anim;
    static int   s_prev_caret_line = 0;
    static int   s_prev_caret_col  = 0;
    static aida::ui::transition_t s_focus_anim;
    static aida::ui::transition_t s_ghost_in;
    static int   s_ghost_visible_for_line = -1;
    static int   s_ghost_visible_for_col  = -1;
    static aida::ui::transition_t s_ghost_absorb;
    static aida::ui::flash_t      s_breadcrumb_flash;
    static aida::ui::transition_t s_match_pulse;
    static int   s_active_match_for = -1;
    static aida::ui::transition_t s_minimap_hover;

    ImU32 tok_colors[static_cast<int>(syntax::token_type::COUNT)];
    syntax::get_token_colors(tok_colors,
        ((float)((th.accent_u32 >> IM_COL32_R_SHIFT) & 0xFF)),
        ((float)((th.accent_u32 >> IM_COL32_G_SHIFT) & 0xFF)),
        ((float)((th.accent_u32 >> IM_COL32_B_SHIFT) & 0xFF)), a);

    const float goto_bar_h = s_goto.visible ? 36.f : 0.f;
    const float breadcrumb_h = 28.f;
    const float minimap_w = (width > 600.f) ? 64.f : 0.f;
    const float overlay_h = goto_bar_h + breadcrumb_h;
    const float editor_y0 = pos_y + overlay_h;
    const float editor_h  = height - overlay_h;
    const float code_w = width - minimap_w;
    const float text_x0 = gutter_w + 4.f;

    s_scroll_y = aida::motion::smooth_lerp(s_scroll_y, s_target_scroll_y, 20.f, dt);
    if (std::abs(s_target_scroll_y - s_scroll_y) < 0.5f)
        s_scroll_y = s_target_scroll_y;
    float max_scroll = std::max(0.f, n_lines * line_h - editor_h + line_h);
    s_target_scroll_y = std::max(0.f, std::min(s_target_scroll_y, max_scroll));
    s_scroll_y = std::max(0.f, std::min(s_scroll_y, max_scroll));

    s_blink_timer += dt;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wpos   = ImGui::GetWindowPos();
    float ox = wpos.x + pos_x;
    float oy = wpos.y + editor_y0;
    float bcb_x = wpos.x + pos_x;
    float bcb_y = wpos.y + pos_y + goto_bar_h;
    {
        ImDrawList* bc_dl = ImGui::GetWindowDrawList();
        ImVec2 bc_min(bcb_x, bcb_y);
        ImVec2 bc_max(bcb_x + width, bcb_y + breadcrumb_h);
        bc_dl->AddRectFilled(bc_min, bc_max, aida::ui::with_alpha(th.panel_header, a * 0.85f));
        bc_dl->AddLine(ImVec2(bc_min.x, bc_max.y - 1.f),
                       ImVec2(bc_max.x, bc_max.y - 1.f),
                       aida::ui::with_alpha(th.border_subtle, a), 1.f);

        std::string crumb_path = code_editor::filename.empty() ? std::string("Untitled")
                                                                : code_editor::filename;
        std::string crumb_func;
        std::string crumb_class;
        for (int i = std::min(s_sel.caret_line, line_count() - 1); i >= 0 && (crumb_func.empty() || crumb_class.empty()); --i) {
            const std::string& ln = line_at(i);
            if (crumb_func.empty()) {
                size_t paren = ln.find('(');
                if (paren != std::string::npos && paren > 0) {
                    size_t end = paren;
                    while (end > 0 && (ln[end - 1] == ' ' || ln[end - 1] == '\t')) end--;
                    if (end > 0) {
                        size_t start = end;
                        while (start > 0 && (isalnum((unsigned char)ln[start - 1]) || ln[start - 1] == '_' || ln[start - 1] == ':')) start--;
                        if (end > start && (isalpha((unsigned char)ln[start]) || ln[start] == '_')) {
                            std::string token = ln.substr(start, end - start);
                            if (token != "if" && token != "for" && token != "while" && token != "switch"
                                && token != "return" && token != "catch" && token != "sizeof") {
                                crumb_func = token;
                            }
                        }
                    }
                }
            }
            if (crumb_class.empty()) {
                static const char* prefixes[] = { "class ", "struct ", "namespace " };
                for (auto* pref : prefixes) {
                    size_t pos = ln.find(pref);
                    if (pos != std::string::npos) {
                        size_t s = pos + std::strlen(pref);
                        size_t e = s;
                        while (e < ln.size() && (isalnum((unsigned char)ln[e]) || ln[e] == '_' || ln[e] == ':')) e++;
                        if (e > s) crumb_class = ln.substr(s, e - s);
                        break;
                    }
                }
            }
        }

        struct seg_t { std::string text; bool is_path; bool is_active; };
        std::vector<seg_t> segs;
        size_t lastsep = crumb_path.find_last_of("/\\");
        std::string parent_path = (lastsep != std::string::npos) ? crumb_path.substr(0, lastsep) : "";
        std::string name_only   = (lastsep != std::string::npos) ? crumb_path.substr(lastsep + 1) : crumb_path;
        if (!parent_path.empty()) {
            size_t prev_sep = parent_path.find_last_of("/\\");
            std::string parent_seg = (prev_sep != std::string::npos)
                ? parent_path.substr(prev_sep + 1) : parent_path;
            if (!parent_seg.empty()) segs.push_back({ parent_seg, true, false });
        }
        segs.push_back({ name_only, true, false });
        if (!crumb_class.empty()) segs.push_back({ crumb_class, false, false });
        if (!crumb_func.empty())  segs.push_back({ crumb_func,  false, true  });

        ImFont* bc_font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
        float crumb_x = bc_min.x + 12.f;
        float crumb_y = bc_min.y + (breadcrumb_h - 13.f) * 0.5f;
        float chev_w = 10.f;
        for (size_t i = 0; i < segs.size(); ++i) {
            const auto& sg = segs[i];
            float tw = bc_font->CalcTextSizeA(13.f, FLT_MAX, 0.f, sg.text.c_str()).x;
            ImVec2 chip_min(crumb_x - 4.f, crumb_y - 3.f);
            ImVec2 chip_max(crumb_x + tw + 4.f, crumb_y + 16.f);
            bool seg_hov = ImGui::IsMouseHoveringRect(chip_min, chip_max);
            ImU32 seg_col = sg.is_path ? th.text_secondary
                                       : (sg.is_active ? th.accent_u32 : th.text_primary);
            if (seg_hov) {
                bc_dl->AddRectFilled(chip_min, chip_max, aida::ui::with_alpha(th.hover_wash, a * 1.4f), 5.f);
                seg_col = th.accent_u32;
            }
            bc_dl->AddText(bc_font, 13.f, ImVec2(crumb_x, crumb_y),
                aida::ui::with_alpha(seg_col, a), sg.text.c_str());
            crumb_x += tw;
            if (i + 1 < segs.size()) {
                ImU32 chev_col = aida::ui::with_alpha(th.text_dim, a);
                float cx = crumb_x + 4.f;
                float cy = crumb_y + 6.f;
                bc_dl->AddLine(ImVec2(cx, cy - 3.f), ImVec2(cx + 3.f, cy), chev_col, 1.5f);
                bc_dl->AddLine(ImVec2(cx + 3.f, cy), ImVec2(cx, cy + 3.f), chev_col, 1.5f);
                crumb_x += chev_w + 4.f;
            }
        }
    }
    s_breadcrumb_flash.tick(dt, 2.f);

    ImGuiID id = ImGui::GetID("##code_editor_widget");
    s_widget_id = id;
    ImRect bb(ImVec2(ox, oy), ImVec2(ox + width, oy + editor_h));
    ImGui::ItemSize(ImVec2(width, height));
    if (!ImGui::ItemAdd(bb, id)) { if (g_code_font) ImGui::PopFont(); return; }

    bool mouse_over_find_bar = false;
    if (s_find.visible) {
        const float fb_w = 340.f;
        const float fb_h = s_find.replace_mode ? (28.f * 2 + 5.f * 3) : (28.f + 5.f * 2);
        const float fb_x = ox + width - fb_w - 20.f;
        const float fb_y = wpos.y + pos_y + 2.f;
        ImVec2 mp = ImGui::GetIO().MousePos;
        mouse_over_find_bar = (mp.x >= fb_x && mp.x <= fb_x + fb_w && mp.y >= fb_y && mp.y <= fb_y + fb_h);
    }

    bool hovered = ImGui::IsMouseHoveringRect(bb.Min, bb.Max);
    if (mouse_over_find_bar) hovered = false;

    bool input_blocked = (file_tabs::pending_close_idx >= 0)
        || globals::ui::process_attach_open
        || globals::ui::driver_status_open
        || globals::ui::shortcuts_dialog_open
        || globals::ui::about_dialog_open
        || globals::ui::mcp_servers_dialog_open
        || globals::ui::command_palette_open;
    if (input_blocked) hovered = false;

    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        ImGui::SetActiveID(id, ImGui::GetCurrentWindow());
        ImGui::SetFocusID(id, ImGui::GetCurrentWindow());
        s_has_focus = true;
    }
    if (s_has_focus && !hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        s_has_focus = false;
        if (ImGui::GetActiveID() == id)
            ImGui::ClearActiveID();
    }

    if (s_has_focus && s_focus_anim.is_finished() && s_focus_anim.progress < 1.f)
        s_focus_anim.start(0.10f, aida::motion::ease::out_quint);
    if (!s_has_focus && s_focus_anim.is_finished() && s_focus_anim.progress > 0.f)
        s_focus_anim.start_reverse(0.18f, aida::motion::ease::in_quint);
    s_focus_anim.tick(dt);
    float focus_blend = s_focus_anim.eased();

    if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_TextInput);
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.f)
            s_target_scroll_y -= wheel * line_h * 3.f;
    }

    int first_row = std::max(0, static_cast<int>(s_scroll_y / line_h) - 1);
    int last_row  = std::min(n_lines - 1, static_cast<int>((s_scroll_y + editor_h) / line_h) + 1);

    if (show_ln) {
        dl->AddLine(ImVec2(ox + gutter_w, oy),
                    ImVec2(ox + gutter_w, oy + editor_h),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);
    }

    if (editor_config::highlight_current_line && focus_blend > 0.001f) {
        float cy = oy + s_sel.caret_line * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + code_w, cy + line_h),
                              aida::ui::with_alpha(th.hover_wash, focus_blend * 0.85f * a));
            dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + 2.f, cy + line_h),
                              aida::ui::with_alpha(th.accent_u32, focus_blend * 0.55f * a));
        }
    }

    if (s_sel.caret_line != s_prev_caret_line || s_sel.caret_col != s_prev_caret_col) {
        if (s_caret_move_anim.is_finished())
            s_caret_move_anim.start(0.120f, aida::motion::ease::out_quint);
        else
            s_caret_move_anim.progress = 0.f;
    }
    s_caret_move_anim.tick(dt);
    if (s_caret_move_anim.active) {
        float pe = s_caret_move_anim.eased();
        float prev_x = ox + text_x0 + s_prev_caret_col * char_w - s_scroll_x;
        float prev_y = oy + s_prev_caret_line * line_h - s_scroll_y;
        float cur_x  = ox + text_x0 + s_sel.caret_col * char_w - s_scroll_x;
        float cur_y  = oy + s_sel.caret_line * line_h - s_scroll_y;
        float gx = prev_x + (cur_x - prev_x) * pe;
        float gy = prev_y + (cur_y - prev_y) * pe;
        if (gy >= oy - line_h && gy <= oy + editor_h) {
            dl->AddRectFilled(ImVec2(gx - 2.f, gy), ImVec2(gx + 6.f, gy + line_h),
                aida::ui::with_alpha(th.accent_glow, (1.f - pe) * a));
        }
    }
    if (s_caret_move_anim.is_finished() && s_caret_move_anim.progress >= 0.999f) {
        s_prev_caret_line = s_sel.caret_line;
        s_prev_caret_col  = s_sel.caret_col;
    }

    {
        const int max_indent_render = 16;
        int tab = std::max(1, editor_config::tab_size);
        for (int i = first_row; i <= last_row; i++) {
            const std::string& ln = line_at(i);
            int leading = 0;
            for (char c : ln) {
                if (c == ' ') leading++;
                else if (c == '\t') leading += tab;
                else break;
            }
            if (leading <= 0) continue;
            int levels = std::min(max_indent_render, leading / tab);
            float ly = oy + i * line_h - s_scroll_y;
            for (int lv = 1; lv <= levels; ++lv) {
                float gx = ox + text_x0 + lv * tab * char_w - s_scroll_x - char_w * 0.5f;
                bool active = (s_sel.caret_line == i) && (lv * tab <= leading);
                ImU32 col = active ? aida::ui::with_alpha(th.accent_dim, 0.45f * a)
                                   : aida::ui::with_alpha(th.border_subtle, 0.6f * a);
                dl->AddLine(ImVec2(gx, ly), ImVec2(gx, ly + line_h), col, 1.f);
            }
        }
    }


    if (s_sel.has_selection()) {
        int l0, c0, l1, c1;
        selection_ordered(l0, c0, l1, c1);
        ImU32 sel_col = aida::ui::with_alpha(th.selection, a);
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
            sx1 = std::min(sx1, ox + code_w - 4.f);
            if (sx1 > sx0) {
                dl->AddRectFilled(ImVec2(sx0, ly), ImVec2(sx1, ly + line_h), sel_col);
            }
        }
    }


    if (s_find.visible && !s_find.match_positions.empty()) {
        if (s_active_match_for != s_find.current_match) {
            s_active_match_for = s_find.current_match;
            s_match_pulse.start(aida::motion::dur::md, aida::motion::ease::out_quint);
        }
        s_match_pulse.tick(dt);
        int find_len = static_cast<int>(strlen(s_find.find_buf));
        ImU32 match_col  = aida::ui::with_alpha(th.accent_dim, 0.32f * a);
        float pulse = aida::ui::clock::pulse(1.5f, 0.55f, 1.f);
        ImU32 active_col = aida::ui::with_alpha(th.accent_u32, 0.55f * pulse * a);
        for (int mi = 0; mi < static_cast<int>(s_find.match_positions.size()); mi++) {
            auto [ml, mc] = s_find.match_positions[mi];
            if (ml < first_row || ml > last_row) continue;
            float my = oy + ml * line_h - s_scroll_y;
            float mx0 = ox + text_x0 + mc * char_w - s_scroll_x;
            float mx1 = mx0 + find_len * char_w;
            mx1 = std::min(mx1, ox + code_w - 4.f);
            if (mx1 <= mx0) continue;
            bool is_active = (mi == s_find.current_match);
            dl->AddRectFilled(ImVec2(mx0, my), ImVec2(mx1, my + line_h),
                              is_active ? active_col : match_col);
            if (is_active) {
                dl->AddRect(ImVec2(mx0 - 1.f, my),
                            ImVec2(mx1 + 1.f, my + line_h),
                            aida::ui::with_alpha(th.accent_u32, 0.85f * pulse * a),
                            2.f, 0, 1.2f);
                aida::ui::blur::render_inner_glow(dl,
                    ImVec2(mx0 - 2.f, my - 1.f),
                    ImVec2(mx1 + 2.f, my + line_h + 1.f),
                    2.f, aida::ui::with_alpha(th.accent_glow, a), 2);
            }
        }
    }


    for (int i = first_row; i <= last_row; i++) {
        float y = oy + i * line_h - s_scroll_y;


        if (i & 1)
            dl->AddRectFilled(ImVec2(ox, y), ImVec2(ox + gutter_w, y + line_h - 1.f),
                              aida::ui::with_alpha(th.text_primary, 0.012f * a));


        if (show_ln) {
            char ln_buf[8];
            snprintf(ln_buf, sizeof(ln_buf), "%5d", i + 1);
            ImU32 ln_col = (i == s_sel.caret_line)
                ? aida::ui::with_alpha(th.accent_u32, 0.85f * a)
                : aida::ui::with_alpha(th.text_lineno, a);
            dl->AddText(ImVec2(ox + 4.f, y + 1.f), ln_col, ln_buf);
        }


        if (i < static_cast<int>(s_cache.tokens.size())) {
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

                if (tok.start + tok.length > static_cast<uint32_t>(ln.size())) continue;

                ImU32 col = tok_colors[static_cast<int>(tok.type)];
                const char* ts = ln.c_str() + tok.start;
                const char* te = ts + tok.length;


                float tok_w = tok.length * char_w;
                if (tx + tok_w < ox + text_x0 || tx > ox + code_w) {
                    tx += tok_w;
                    continue;
                }

                dl->AddText(ImVec2(tx, y + 1.f), col, ts, te);
                tx += tok_w;
            }
        }
    }


    if (s_has_focus) {
        float caret_alpha_pulse = aida::ui::clock::pulse(2.0f, 0.30f, 1.0f);
        float cx = ox + text_x0 + s_sel.caret_col * char_w - s_scroll_x;
        float cy = oy + s_sel.caret_line * line_h - s_scroll_y;
        if (cy >= oy - line_h && cy <= oy + editor_h) {
            dl->AddLine(ImVec2(cx, cy), ImVec2(cx, cy + line_h),
                        aida::ui::with_alpha(th.accent_hover, caret_alpha_pulse * a), 1.5f);
            dl->AddLine(ImVec2(cx, cy + line_h - 1.f),
                        ImVec2(cx, cy + line_h),
                        aida::ui::with_alpha(th.accent_u32, caret_alpha_pulse * a * 0.85f), 2.f);
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
                        int col = (std::min)(s_sel.caret_col, static_cast<int>(ln.size()));
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

                        if (result.find("Error:") == 0 || result.find("error") == 0 ||
                            result.find("{\"error\"") != std::string::npos ||
                            result.find("API returned status") != std::string::npos) {
                            result.clear();
                        }

                        std::lock_guard<std::mutex> lk(s_ghost_mtx);
                        s_ghost_pending = std::move(result);
                        s_ghost_has_pending = true;
                    });
                    }
                }
            }
        }


        if (!s_ghost_text.empty()) {
            if (s_ghost_visible_for_line != s_sel.caret_line || s_ghost_visible_for_col != s_sel.caret_col) {
                s_ghost_visible_for_line = s_sel.caret_line;
                s_ghost_visible_for_col  = s_sel.caret_col;
                s_ghost_in.start(0.150f, aida::motion::ease::out_quint);
            }
            s_ghost_in.tick(dt);
            s_ghost_absorb.tick(dt);
            float gv = s_ghost_in.eased();
            float absorb = s_ghost_absorb.is_finished() ? 0.f : (1.f - s_ghost_absorb.eased());
            float vis_alpha = (gv * 0.45f + 0.05f) * a * (1.f - s_ghost_absorb.eased() * 0.6f);
            float gx = ox + text_x0 + s_sel.caret_col * char_w - s_scroll_x;
            float gy = oy + s_sel.caret_line * line_h - s_scroll_y;
            if (gy >= oy - line_h && gy <= oy + editor_h) {
                ImU32 ghost_col = aida::ui::with_alpha(th.text_dim, vis_alpha);
                dl->AddText(ImVec2(gx, gy + 1.f), ghost_col, s_ghost_text.c_str());
            }
            (void)absorb;

            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false)) {
                s_ghost_absorb.start(0.18f, aida::motion::ease::out_quint);
                insert_text_at_caret(s_ghost_text);
                s_ghost_text.clear();
                s_ghost_visible_for_line = -1;
                s_ghost_visible_for_col  = -1;
            }

            if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                s_ghost_text.clear();
                s_ghost_in.reset();
                s_ghost_visible_for_line = -1;
                s_ghost_visible_for_col  = -1;
            }
        } else {
            s_ghost_visible_for_line = -1;
            s_ghost_visible_for_col  = -1;
        }
    }


    if ((s_has_focus || hovered) && !input_blocked) {
        ImVec2 mp = ImGui::GetIO().MousePos;
        bool in_text = mp.x >= ox + text_x0 && mp.x < ox + code_w - 14.f && mp.y >= oy && mp.y <= oy + editor_h;
        if (mouse_over_find_bar) in_text = false;

        if (in_text && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);


            float now = static_cast<float>(ImGui::GetTime());
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

        if (s_mouse_selecting && !s_sb_dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            int ml, mc;
            screen_to_linecol(mp.x, mp.y, ox, oy, gutter_w, line_h, char_w, ml, mc);
            s_sel.caret_line = ml;
            s_sel.caret_col  = mc;
            s_sel.active = true;
        }

        if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
            s_mouse_selecting = false;
    }


    if (s_has_focus && !input_blocked && !s_find_has_focus) {
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
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Z, true)) {
            do_undo();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Y, true)) {
            do_redo();
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
            s_find.visible = true;
            s_find.replace_mode = false;
            s_focus_find_input = true;

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
            s_focus_find_input = true;
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

        if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (ctrl) {
                if (nc == 0 && nl > 0) {
                    nl--;
                    nc = line_length(nl);
                } else if (nc > 0) {
                    const std::string& ln = line_at(nl);
                    while (nc > 0 && !is_word_char(ln[nc - 1])) nc--;
                    while (nc > 0 && is_word_char(ln[nc - 1])) nc--;
                }
            } else if (nc > 0) {
                nc--;
            } else if (nl > 0) {
                nl--; nc = line_length(nl);
            }
            move_caret(nl, nc);
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, true)) {
            int nl = s_sel.caret_line, nc = s_sel.caret_col;
            if (ctrl) {
                if (nc >= line_length(nl) && nl < line_count() - 1) {
                    nl++;
                    nc = 0;
                } else {
                    const std::string& ln = line_at(nl);
                    int len = static_cast<int>(ln.size());
                    while (nc < len && is_word_char(ln[nc])) nc++;
                    while (nc < len && !is_word_char(ln[nc])) nc++;
                }
            } else if (nc < line_length(nl)) {
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
            int page = std::max(1, static_cast<int>(editor_h / line_h) - 2);
            int nl = std::max(0, s_sel.caret_line - page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown, false)) {
            int page = std::max(1, static_cast<int>(editor_h / line_h) - 2);
            int nl = std::min(line_count() - 1, s_sel.caret_line + page);
            move_caret(nl, clamp_col(nl, s_sel.caret_col));
        }


        if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Enter, true)) {

            std::string indent;
            if (s_sel.caret_line < static_cast<int>(s_cache.lines.size())) {
                auto& ln = s_cache.lines[s_sel.caret_line];
                for (char c : ln) {
                    if (c == ' ' || c == '\t') indent += c;
                    else break;
                }
            }
            insert_text_at_caret("\n" + indent);
            ensure_caret_visible(editor_h, line_h);
        }
        else if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Backspace, true)) {
            if (s_sel.has_selection()) {
                delete_selection();
            } else if (s_sel.caret_col > 0) {
                push_undo();
                auto& ln = s_cache.lines[s_sel.caret_line];
                int col = s_sel.caret_col;
                int start = col;

                while (start > 0 && (ln[start - 1] == ' ' || ln[start - 1] == '\t'))
                    start--;

                if (start > 0) {

                    while (start > 0 && (isalnum(static_cast<unsigned char>(ln[start - 1])) || ln[start - 1] == '_'))
                        start--;
                }

                if (start == col)
                    start = col - 1;
                ln.erase(start, col - start);
                s_sel.caret_col = s_sel.anchor_col = start;
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line > 0) {
                push_undo();
                int prev = s_sel.caret_line - 1;
                int prev_len = static_cast<int>(s_cache.lines[prev].size());
                s_cache.lines[prev] += s_cache.lines[s_sel.caret_line];
                s_cache.lines.erase(s_cache.lines.begin() + s_sel.caret_line);
                s_cache.tokens.erase(s_cache.tokens.begin() + s_sel.caret_line);
                s_sel.caret_line = s_sel.anchor_line = prev;
                s_sel.caret_col  = s_sel.anchor_col  = prev_len;
                rebuild_buffer_from_lines();
            }
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
                int prev_len = static_cast<int>(s_cache.lines[prev].size());
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
                char c = static_cast<char>(ch);
                insert_text_at_caret(std::string(1, c));
                ensure_caret_visible(editor_h, line_h);


                if (editor_config::auto_complete && autocomplete::enabled) {
                    int cursor = s_sel.caret_col;
                    int ws = cursor;
                    auto& ln = s_cache.lines[s_sel.caret_line];
                    while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[ws-1])) || ln[ws-1] == '_'))
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
                autocomplete::selected = (autocomplete::selected - 1 + static_cast<int>(autocomplete::matches.size()))
                    % static_cast<int>(autocomplete::matches.size());
            }
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
                autocomplete::selected = (autocomplete::selected + 1) % static_cast<int>(autocomplete::matches.size());
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Tab, false) || ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
                if (autocomplete::selected < static_cast<int>(autocomplete::matches.size())) {

                    int cursor = s_sel.caret_col;
                    int ws = cursor;
                    auto& ln = s_cache.lines[s_sel.caret_line];
                    while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[ws - 1])) || ln[ws - 1] == '_'))
                        ws--;
                    push_undo();
                    ln.erase(ws, cursor - ws);
                    ln.insert(ws, autocomplete::matches[autocomplete::selected]);
                    s_sel.caret_col = s_sel.anchor_col = ws + static_cast<int>(autocomplete::matches[autocomplete::selected].size());
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
        float popup_w = 240.f;
        float ac_item_h = 24.f;
        float popup_h = std::min(static_cast<float>(autocomplete::matches.size()), 8.f) * ac_item_h + 10.f;
        float sx = ox + text_x0 + autocomplete::cursor_col * char_w - s_scroll_x;
        float sy = oy + (autocomplete::cursor_line + 1) * line_h - s_scroll_y + 4.f;

        if (sx + popup_w > ox + code_w) sx = ox + code_w - popup_w - 4.f;
        if (sy + popup_h > oy + editor_h) sy = oy + autocomplete::cursor_line * line_h - s_scroll_y - popup_h;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 pmin(sx, sy);
        ImVec2 pmax(sx + popup_w, sy + popup_h);
        aida::ui::blur::render_drop_shadow(fdl, pmin, pmax, 10.f, 4, 0.40f, ImVec2(0.f, 4.f));
        aida::ui::blur::render_glass_fill(fdl, pmin, pmax, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, pmin, pmax, 10.f, a, 1.f);

        for (int mi = 0; mi < static_cast<int>(autocomplete::matches.size()) && mi < 8; mi++) {
            float iy = sy + 5.f + mi * ac_item_h;
            float text_y = iy + (ac_item_h - ImGui::GetFontSize()) * 0.5f;
            if (mi == autocomplete::selected) {
                fdl->AddRectFilled(ImVec2(sx + 3.f, iy), ImVec2(sx + popup_w - 3.f, iy + ac_item_h),
                    aida::ui::with_alpha(th.accent_dim, 0.55f * a), 6.f);
                fdl->AddRectFilled(ImVec2(sx + 3.f, iy), ImVec2(sx + 5.f, iy + ac_item_h),
                    aida::ui::with_alpha(th.accent_u32, a), 1.f);
            }

            auto& match = autocomplete::matches[mi];
            size_t plen = autocomplete::partial.size();
            if (plen > 0 && plen <= match.size()) {
                fdl->AddText(ImVec2(sx + 12.f, text_y),
                    aida::ui::with_alpha(th.accent_u32, a),
                    match.c_str(), match.c_str() + plen);
                float prefix_w = ImGui::CalcTextSize(match.c_str(), match.c_str() + plen).x;
                fdl->AddText(ImVec2(sx + 12.f + prefix_w, text_y),
                    aida::ui::with_alpha(th.text_primary, 0.90f * a),
                    match.c_str() + plen);
            } else {
                fdl->AddText(ImVec2(sx + 12.f, text_y),
                    aida::ui::with_alpha(th.text_primary, 0.90f * a),
                    match.c_str());
            }
        }
    }


    if (s_find.visible) {

        ImVec4 accent_col = th.accent;
        ImVec4 bg     = ImGui::ColorConvertU32ToFloat4(th.panel_header);
        ImVec4 bg_inp = ImGui::ColorConvertU32ToFloat4(th.bg_base);
        ImVec4 txt1   = ImGui::ColorConvertU32ToFloat4(th.text_primary);
        ImVec4 txt2   = ImGui::ColorConvertU32ToFloat4(th.text_secondary);
        ImVec4 txt_d  = ImGui::ColorConvertU32ToFloat4(th.text_dim);

        const float row_h       = 28.f;
        const float bar_pad_x   = 8.f;
        const float bar_pad_y   = 5.f;
        const float input_w     = 200.f;
        const float btn_sz      = 26.f;
        const float bar_w       = 340.f;
        const float total_bar_h = s_find.replace_mode ? (row_h * 2 + bar_pad_y * 3) : (row_h + bar_pad_y * 2);
        const float bar_x       = ox + width - bar_w - 20.f;
        const float bar_y       = wpos.y + pos_y + 2.f;

        ImGui::SetNextWindowPos(ImVec2(bar_x, bar_y), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(bar_w, total_bar_h), ImGuiCond_Always);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(bar_pad_x, bar_pad_y));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(3.f, 3.f));
        ImGui::PushStyleColor(ImGuiCol_WindowBg, bg);
        ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.accent_u32, 0.35f)));

        ImGuiWindowFlags find_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings |
            ImGuiWindowFlags_AlwaysAutoResize;

        bool find_open = true;
        ImGui::Begin("##find_bar", &find_open, find_flags);
        s_find_has_focus = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);


        auto toggle_button = [&](const char* label, bool& state, const char* id_suffix, const char* tooltip) -> bool {
            ImGui::PushID(id_suffix);
            ImVec2 sz(btn_sz, row_h);
            bool was = state;
            if (state) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(accent_col.x, accent_col.y, accent_col.z, 0.25f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(accent_col.x, accent_col.y, accent_col.z, 0.35f));
                ImGui::PushStyleColor(ImGuiCol_Text, accent_col);
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.f, 0.f, 0.f, 0.f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(txt2.x, txt2.y, txt2.z, 0.4f));
                ImGui::PushStyleColor(ImGuiCol_Text, txt2);
            }
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            if (ImGui::Button(label, sz)) state = !state;
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
            if (tooltip) ImGui::SetItemTooltip("%s", tooltip);
            ImGui::PopID();
            return state != was;
        };


        auto icon_button = [&](const char* label, const char* id_suffix, const char* tooltip, float w = 26.f) -> bool {
            ImGui::PushID(id_suffix);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.f, 0.f, 0.f, 0.f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(txt_d.x, txt_d.y, txt_d.z, 0.3f));
            ImGui::PushStyleColor(ImGuiCol_Text, txt2);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            bool clicked = ImGui::Button(label, ImVec2(w, row_h));
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
            if (tooltip) ImGui::SetItemTooltip("%s", tooltip);
            ImGui::PopID();
            return clicked;
        };


        {
            const char* chev = s_find.replace_mode ? "v" : ">";
            if (icon_button(chev, "chevron", "Toggle Replace", 20.f))
                s_find.replace_mode = !s_find.replace_mode;
            ImGui::SameLine();
        }


        {
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, (row_h - ImGui::GetFontSize()) * 0.5f - 1.f));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, bg_inp);
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(bg_inp.x + 0.03f, bg_inp.y + 0.03f, bg_inp.z + 0.03f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(bg_inp.x + 0.05f, bg_inp.y + 0.05f, bg_inp.z + 0.05f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_Text, txt1);
            ImGui::PushItemWidth(input_w);
            if (s_focus_find_input) {
                ImGui::SetKeyboardFocusHere();
                s_focus_find_input = false;
            }
            bool enter_pressed = ImGui::InputText("##find_input", s_find.find_buf,
                sizeof(s_find.find_buf), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
            bool edited = ImGui::IsItemEdited();
            ImGui::PopItemWidth();
            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar(2);


            if (edited && strcmp(s_find.find_buf, s_find_last_buf) != 0) {
                memcpy(s_find_last_buf, s_find.find_buf, sizeof(s_find.find_buf));
                find_all_matches();
                if (!s_find.match_positions.empty()) {
                    s_find.current_match = -1;
                    find_next();
                    ensure_caret_visible(editor_h, line_h);
                }
            }


            if (enter_pressed) {
                if (ImGui::GetIO().KeyShift)
                    find_prev();
                else
                    find_next();
                ensure_caret_visible(editor_h, line_h);
                s_focus_find_input = true;
            }
            ImGui::SameLine();
        }


        if (toggle_button("Aa", s_find.case_sensitive, "case", "Match Case")) {
            find_all_matches();
            if (!s_find.match_positions.empty()) {
                s_find.current_match = -1;
                find_next();
                ensure_caret_visible(editor_h, line_h);
            }
        }
        ImGui::SameLine();


        {
            char match_buf[32];
            if (s_find.find_buf[0] == '\0') {
                match_buf[0] = '\0';
            } else if (s_find.total_matches == 0) {
                snprintf(match_buf, sizeof(match_buf), "No results");
            } else {
                snprintf(match_buf, sizeof(match_buf), "%d of %d",
                         s_find.current_match >= 0 ? s_find.current_match + 1 : 0, s_find.total_matches);
            }
            if (match_buf[0]) {
                bool no_match = (s_find.total_matches == 0 && s_find.find_buf[0] != '\0');
                ImVec4 mc = no_match ? ImGui::ColorConvertU32ToFloat4(th.error) : txt2;
                ImGui::PushStyleColor(ImGuiCol_Text, mc);
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (row_h - ImGui::GetFontSize()) * 0.5f);
                ImGui::TextUnformatted(match_buf);
                ImGui::PopStyleColor();
                ImGui::SameLine();
            }
        }


        if (icon_button("\xc3\x97", "close", "Close (Esc)")) {
            s_find.visible = false;
            s_find_has_focus = false;
            s_has_focus = true;
        }


        if (s_find.replace_mode) {
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 22.f);

            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.f, (row_h - ImGui::GetFontSize()) * 0.5f - 1.f));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, bg_inp);
            ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(bg_inp.x + 0.03f, bg_inp.y + 0.03f, bg_inp.z + 0.03f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(bg_inp.x + 0.05f, bg_inp.y + 0.05f, bg_inp.z + 0.05f, bg_inp.w));
            ImGui::PushStyleColor(ImGuiCol_Text, txt1);
            ImGui::PushItemWidth(input_w);
            ImGui::InputText("##replace_input", s_find.replace_buf, sizeof(s_find.replace_buf));
            ImGui::PopItemWidth();
            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar(2);
            ImGui::SameLine();

            if (icon_button("R1", "repl_one", "Replace"))    replace_current();
            ImGui::SameLine();
            if (icon_button("R*", "repl_all", "Replace All")) replace_all();
        }


        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
            s_find.visible = false;
            s_find_has_focus = false;
            s_has_focus = true;
        }

        ImGui::End();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(4);


        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        fdl->AddRectFilledMultiColor(
            ImVec2(bar_x + 4.f, bar_y + total_bar_h),
            ImVec2(bar_x + bar_w - 4.f, bar_y + total_bar_h + 6.f),
            IM_COL32(0, 0, 0, static_cast<int>(40 * a)), IM_COL32(0, 0, 0, static_cast<int>(40 * a)),
            IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0));
    } else {
        s_find_has_focus = false;
    }


    if (s_goto.visible) {
        float gy = wpos.y + pos_y;
        float gw = 240.f;
        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 gmin(ox + 10.f, gy + 2.f);
        ImVec2 gmax(ox + 10.f + gw, gy + goto_bar_h - 2.f);
        aida::ui::blur::render_drop_shadow(fdl, gmin, gmax, 10.f, 3, 0.30f, ImVec2(0.f, 3.f));
        aida::ui::blur::render_glass_fill(fdl, gmin, gmax, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, gmin, gmax, 10.f, a, 1.f);

        ImGui::SetCursorPos(ImVec2(pos_x + 18.f, pos_y + 6.f));
        ImGui::PushID("##editor_goto_overlay");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.f, 4.f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(aida::ui::with_alpha(th.bg_base, 0.65f)));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(th.text_primary));
        ImGui::SetNextItemWidth(140.f);
        bool go = ImGui::InputTextWithHint("##goto_line", "line", s_goto.line_buf, sizeof(s_goto.line_buf),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);

        ImGui::SameLine();
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2.f);
        bool clicked_go = aida::ui::components::button("Go",
            aida::ui::components::button_kind_t::primary,
            aida::ui::components::size_t_::sm);
        ImGui::PopID();

        if (clicked_go || go) {
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


    {
        float total_content = n_lines * line_h;
        if (total_content > editor_h) {
            const float sb_w   = 10.f;
            const float sb_pad = 2.f;
            float track_x  = ox + code_w - sb_w - sb_pad;
            float track_y0 = oy + sb_pad;
            float track_h  = editor_h - sb_pad * 2.f;

            float ratio       = editor_h / total_content;
            float thumb_h     = std::max(20.f, track_h * ratio);
            float scroll_range = total_content - editor_h;
            float thumb_y     = track_y0 + (scroll_range > 0.f
                ? (s_scroll_y / scroll_range) * (track_h - thumb_h) : 0.f);

            bool sb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(track_x - 4.f, track_y0),
                ImVec2(track_x + sb_w + 4.f, track_y0 + track_h));

            ImGuiID sb_hov_id = ImGui::GetID("##code_sb_hov");
            float sb_a = ImGui::GetStateStorage()->GetFloat(sb_hov_id, 0.f);
            sb_a = aida::motion::smooth_lerp(sb_a, (sb_hov || s_sb_dragging) ? 1.f : 0.f, 14.f, dt);
            ImGui::GetStateStorage()->SetFloat(sb_hov_id, sb_a);

            if (sb_a > 0.01f) {

                dl->AddRectFilled(ImVec2(track_x, track_y0),
                    ImVec2(track_x + sb_w, track_y0 + track_h),
                    aida::ui::with_alpha(th.text_primary, 0.04f * sb_a * a), 3.f);


                bool thumb_hov = ImGui::IsMouseHoveringRect(
                    ImVec2(track_x - 2.f, thumb_y),
                    ImVec2(track_x + sb_w + 2.f, thumb_y + thumb_h));
                ImU32 thumb_col = aida::ui::with_alpha(
                    (thumb_hov || s_sb_dragging) ? th.accent_u32 : th.text_secondary,
                    (thumb_hov || s_sb_dragging ? 0.55f : 0.30f) * sb_a * a);
                dl->AddRectFilled(ImVec2(track_x, thumb_y),
                    ImVec2(track_x + sb_w, thumb_y + thumb_h),
                    thumb_col, 3.f);
            }

            if (sb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                float my = ImGui::GetIO().MousePos.y;
                if (my < thumb_y || my > thumb_y + thumb_h) {
                    float click_ratio = (my - track_y0 - thumb_h * 0.5f) / (track_h - thumb_h);
                    click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                    s_target_scroll_y = click_ratio * scroll_range;
                }
                s_sb_dragging = true;
                s_sb_drag_offset = ImGui::GetIO().MousePos.y - thumb_y;
            }

            if (s_sb_dragging) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    float my = ImGui::GetIO().MousePos.y - s_sb_drag_offset;
                    float drag_ratio = (my - track_y0) / (track_h - thumb_h);
                    drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                    s_target_scroll_y = drag_ratio * scroll_range;
                    s_scroll_y = s_target_scroll_y;
                } else {
                    s_sb_dragging = false;
                }
            }
        }
    }

    if (minimap_w > 0.f && n_lines > 1) {
        float mm_x = ox + code_w;
        float mm_y = oy;
        float mm_h = editor_h;
        ImVec2 mm_min(mm_x, mm_y);
        ImVec2 mm_max(mm_x + minimap_w, mm_y + mm_h);

        bool mm_hov = ImGui::IsMouseHoveringRect(mm_min, mm_max);
        float mm_hov_v = s_minimap_hover.eased();
        if (mm_hov && s_minimap_hover.is_finished() && s_minimap_hover.progress < 1.f)
            s_minimap_hover.start(0.18f, aida::motion::ease::out_quint);
        if (!mm_hov && s_minimap_hover.is_finished() && s_minimap_hover.progress > 0.f)
            s_minimap_hover.start_reverse(0.18f, aida::motion::ease::in_quint);
        s_minimap_hover.tick(dt);

        aida::ui::blur::render_glass_fill(dl, mm_min, mm_max, 0.f, a);
        dl->AddLine(ImVec2(mm_x, mm_y), ImVec2(mm_x, mm_y + mm_h),
            aida::ui::with_alpha(th.border_subtle, a), 1.f);

        float mm_line_h = (n_lines > 0) ? (mm_h / (float)n_lines) : 1.f;
        if (mm_line_h > 4.f) mm_line_h = 4.f;
        if (mm_line_h < 1.f) mm_line_h = 1.f;
        float mm_char_step = (minimap_w - 8.f) / 80.f;
        if (mm_char_step < 0.6f) mm_char_step = 0.6f;

        int mm_first = 0;
        int mm_last  = std::min(n_lines - 1, 4000);

        for (int i = mm_first; i <= mm_last; i++) {
            if (i >= (int)s_cache.tokens.size()) break;
            float ly = mm_y + (float)i * mm_line_h;
            if (ly + mm_line_h < mm_y || ly > mm_y + mm_h) continue;

            const auto& toks = s_cache.tokens[i];
            const auto& ln_text = s_cache.lines[i];
            float lx = mm_x + 4.f;
            for (const auto& tok : toks) {
                if (tok.type == syntax::token_type::whitespace) {
                    for (uint32_t k = 0; k < tok.length; k++) {
                        char c = ln_text[tok.start + k];
                        if (c == '\t') lx += mm_char_step * (float)editor_config::tab_size;
                        else lx += mm_char_step;
                    }
                    continue;
                }
                if (tok.start + tok.length > (uint32_t)ln_text.size()) continue;
                ImU32 tc = tok_colors[(int)tok.type];
                tc = aida::ui::with_alpha(tc, 0.55f * a);
                float seg_w = (float)tok.length * mm_char_step;
                if (lx + seg_w > mm_max.x - 4.f) seg_w = (mm_max.x - 4.f) - lx;
                if (seg_w < 0.5f) { lx += seg_w; continue; }
                dl->AddRectFilled(ImVec2(lx, ly + 0.5f),
                                  ImVec2(lx + seg_w, ly + mm_line_h - 0.5f), tc);
                lx += (float)tok.length * mm_char_step;
                if (lx > mm_max.x - 4.f) break;
            }
        }

        if (n_lines > 0) {
            float view_y0 = mm_y + (s_scroll_y / std::max(1.f, n_lines * line_h)) * mm_h;
            float view_h  = (editor_h / std::max(1.f, n_lines * line_h)) * mm_h;
            if (view_h < 12.f) view_h = 12.f;
            if (view_y0 + view_h > mm_y + mm_h) view_y0 = mm_y + mm_h - view_h;
            ImVec2 vmin(mm_x + 1.f, view_y0);
            ImVec2 vmax(mm_max.x - 1.f, view_y0 + view_h);
            dl->AddRectFilled(vmin, vmax,
                aida::ui::with_alpha(th.accent_glow, (0.55f + mm_hov_v * 0.35f) * a), 4.f);
            dl->AddRect(vmin, vmax,
                aida::ui::with_alpha(th.accent_u32, (0.45f + mm_hov_v * 0.35f) * a),
                4.f, 0, 1.f);
        }

        float caret_mm_y = mm_y + ((float)s_sel.caret_line / std::max(1.f, (float)n_lines)) * mm_h;
        dl->AddLine(ImVec2(mm_x + 2.f, caret_mm_y),
                    ImVec2(mm_max.x - 2.f, caret_mm_y),
                    aida::ui::with_alpha(th.accent_u32, 0.65f * a), 1.f);

        if (mm_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            float local = (ImGui::GetIO().MousePos.y - mm_y) / mm_h;
            if (local < 0.f) local = 0.f;
            if (local > 1.f) local = 1.f;
            s_target_scroll_y = local * std::max(0.f, n_lines * line_h - editor_h * 0.5f);
        }
        if (mm_hov && ImGui::IsMouseDown(ImGuiMouseButton_Left) && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.f)) {
            float local = (ImGui::GetIO().MousePos.y - mm_y) / mm_h;
            if (local < 0.f) local = 0.f;
            if (local > 1.f) local = 1.f;
            s_target_scroll_y = local * std::max(0.f, n_lines * line_h - editor_h * 0.5f);
        }
    }

    if (g_code_font) ImGui::PopFont();
}
