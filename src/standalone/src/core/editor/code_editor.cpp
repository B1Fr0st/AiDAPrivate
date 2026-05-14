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
#include <cstdlib>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include "theme.hpp"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "components.hpp"
#include "blur_layer.hpp"
#include "fonts.hpp"
#include "ui_anim.hpp"
#include "work_queue.hpp"


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

bool s_request_undo = false;
bool s_request_redo = false;
bool s_request_find = false;
bool s_request_replace = false;

std::string s_last_error;


std::mutex                          s_diff_mtx;
code_editor_widget::pending_diff_t   s_diff;
int                                 s_diff_hover_hunk = -1;
float                               s_diff_scroll_target = -1.f;


double s_last_edit_time   = 0.0;
int    s_last_edit_line   = -1;
int    s_last_edit_col    = -1;
int    s_undo_kind        = 0;


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
    int clamped = std::max(0, std::min(col, line_length(line)));
    const std::string& ln = line_at(line);
    while (clamped > 0 && clamped < static_cast<int>(ln.size()) &&
           (static_cast<unsigned char>(ln[clamped]) & 0xC0) == 0x80)
        clamped--;
    return clamped;
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

void push_undo(int coalesce_kind = 0) {
    if (coalesce_kind != 0 && coalesce_kind == s_undo_kind && !s_undo.empty()) {
        double now = ImGui::GetTime();
        bool adjacent = (s_last_edit_line == s_sel.caret_line) &&
                        (std::abs(s_sel.caret_col - s_last_edit_col) <= 1);
        if (adjacent && (now - s_last_edit_time) < 1.2) {
            s_last_edit_time = now;
            s_last_edit_line = s_sel.caret_line;
            s_last_edit_col  = s_sel.caret_col;
            s_redo.clear();
            return;
        }
    }
    code_editor_widget::undo_entry_t e;
    e.text = code_editor::buffer.data();
    e.caret_line = s_sel.caret_line;
    e.caret_col  = s_sel.caret_col;
    s_undo.push_back(std::move(e));
    if (static_cast<int>(s_undo.size()) > UNDO_MAX) s_undo.erase(s_undo.begin());
    s_redo.clear();
    s_undo_kind      = coalesce_kind;
    s_last_edit_time = ImGui::GetTime();
    s_last_edit_line = s_sel.caret_line;
    s_last_edit_col  = s_sel.caret_col;
}

void break_undo_coalescing() {
    s_undo_kind      = 0;
    s_last_edit_line = -1;
    s_last_edit_col  = -1;
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

void insert_text_at_caret(const std::string& text, int coalesce_kind = 0) {
    if (s_sel.has_selection()) { delete_selection(); break_undo_coalescing(); }
    else push_undo(coalesce_kind);

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
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (wlen <= 0) { CloseClipboard(); return; }
    size_t bytes = (static_cast<size_t>(wlen) + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) { CloseClipboard(); return; }
    wchar_t* dst = static_cast<wchar_t*>(GlobalLock(hg));
    if (!dst) { GlobalFree(hg); CloseClipboard(); return; }
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), dst, wlen);
    dst[wlen] = L'\0';
    GlobalUnlock(hg);
    if (!SetClipboardData(CF_UNICODETEXT, hg)) {
        GlobalFree(hg);
    }
    CloseClipboard();
}

std::string clipboard_paste() {
    if (!OpenClipboard(nullptr)) return {};
    std::string result;
    HANDLE hd = GetClipboardData(CF_UNICODETEXT);
    if (hd) {
        const wchar_t* wp = static_cast<const wchar_t*>(GlobalLock(hd));
        if (wp) {
            int wlen = static_cast<int>(wcslen(wp));
            int u8 = WideCharToMultiByte(CP_UTF8, 0, wp, wlen, nullptr, 0, nullptr, nullptr);
            if (u8 > 0) {
                result.resize(static_cast<size_t>(u8));
                WideCharToMultiByte(CP_UTF8, 0, wp, wlen, result.data(), u8, nullptr, nullptr);
            }
            GlobalUnlock(hd);
        }
    } else {
        HANDLE ht = GetClipboardData(CF_TEXT);
        if (ht) {
            const char* p = static_cast<const char*>(GlobalLock(ht));
            if (p) result = p;
            GlobalUnlock(ht);
        }
    }
    CloseClipboard();
    if (!result.empty()) {
        std::string normalized;
        normalized.reserve(result.size());
        for (size_t i = 0; i < result.size(); i++) {
            if (result[i] == '\r') continue;
            normalized += result[i];
        }
        result = std::move(normalized);
    }
    return result;
}

void do_undo() {
    if (s_undo.empty()) return;
    break_undo_coalescing();
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
    break_undo_coalescing();
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

float s_view_char_w   = 8.f;
float s_view_text_w   = 0.f;
float s_max_scroll_x  = 0.f;

void ensure_caret_visible(float vis_h, float line_h) {
    float caret_y = s_sel.caret_line * line_h;
    if (caret_y < s_scroll_y)
        s_target_scroll_y = caret_y;
    else if (caret_y + line_h > s_scroll_y + vis_h)
        s_target_scroll_y = caret_y - vis_h + line_h * 2.f;

    if (editor_config::word_wrap) {
        s_scroll_x = 0.f;
        return;
    }
    if (s_view_text_w <= 0.f) return;
    float caret_x = s_sel.caret_col * s_view_char_w;
    float pad = s_view_char_w * 4.f;
    if (caret_x - pad < s_scroll_x)
        s_scroll_x = std::max(0.f, caret_x - pad);
    else if (caret_x + pad > s_scroll_x + s_view_text_w)
        s_scroll_x = caret_x + pad - s_view_text_w;
    if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
    if (s_scroll_x < 0.f) s_scroll_x = 0.f;
}


void screen_to_linecol(float sx, float sy, float origin_x, float origin_y,
                        float gutter_w, float line_h, float char_w,
                        int& out_line, int& out_col) {
    float rel_y = sy - origin_y + s_scroll_y;
    float rel_x = sx - origin_x - gutter_w - 4.f + s_scroll_x;
    out_line = clamp_line(static_cast<int>(rel_y / line_h));
    out_col  = std::max(0, static_cast<int>((rel_x + char_w * 0.5f) / char_w));
    out_col  = clamp_col(out_line, out_col);
    const std::string& ln = line_at(out_line);
    while (out_col > 0 && out_col < static_cast<int>(ln.size()) &&
           (static_cast<unsigned char>(ln[out_col]) & 0xC0) == 0x80)
        out_col--;
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
                    int match_len = static_cast<int>(it->length());
                    if (match_len <= 0) continue;
                    int match_pos = static_cast<int>(it->position());
                    if (s_find.whole_word) {
                        bool left_ok  = (match_pos == 0) || (!isalnum(static_cast<unsigned char>(line[match_pos - 1])) && line[match_pos - 1] != '_');
                        bool right_ok = (match_pos + match_len >= static_cast<int>(line.size())) || (!isalnum(static_cast<unsigned char>(line[match_pos + match_len])) && line[match_pos + match_len] != '_');
                        if (!left_ok || !right_ok) continue;
                    }
                    code_editor_widget::find_match_t m;
                    m.line = i;
                    m.col = match_pos;
                    m.length = match_len;
                    s_find.match_positions.push_back(m);
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
                code_editor_widget::find_match_t m;
                m.line = i;
                m.col = static_cast<int>(pos);
                m.length = needle_len;
                s_find.match_positions.push_back(m);
                pos += needle_len;
            }
        }
    }
    s_find.total_matches = static_cast<int>(s_find.match_positions.size());
}

void find_next() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match + 1) % static_cast<int>(s_find.match_positions.size());
    const auto& m = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = m.col;
    s_sel.caret_col  = m.col + m.length;
    s_sel.active = true;
}

void find_prev() {
    if (s_find.match_positions.empty()) return;
    s_find.current_match = (s_find.current_match - 1 + static_cast<int>(s_find.match_positions.size()))
                            % static_cast<int>(s_find.match_positions.size());
    const auto& m = s_find.match_positions[s_find.current_match];
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = m.col;
    s_sel.caret_col  = m.col + m.length;
    s_sel.active = true;
}

std::string compute_replacement(const std::string& line_text, const code_editor_widget::find_match_t& m) {
    std::string replacement = s_find.replace_buf;
    if (!s_find.use_regex) return replacement;
    try {
        auto flags = std::regex_constants::ECMAScript;
        if (!s_find.case_sensitive)
            flags |= std::regex_constants::icase;
        std::regex re(s_find.find_buf, flags);
        std::string slice = line_text.substr(m.col, m.length);
        return std::regex_replace(slice, re, replacement,
            std::regex_constants::format_first_only);
    } catch (...) {
        return replacement;
    }
}

void replace_current() {
    if (s_find.current_match < 0 || s_find.current_match >= static_cast<int>(s_find.match_positions.size()))
        return;
    const auto& m = s_find.match_positions[s_find.current_match];
    if (m.line < 0 || m.line >= static_cast<int>(s_cache.lines.size())) return;
    push_undo();
    std::string& ln = s_cache.lines[m.line];
    int col_clamped = std::min(m.col, static_cast<int>(ln.size()));
    int len_clamped = std::min(m.length, static_cast<int>(ln.size()) - col_clamped);
    std::string replacement = compute_replacement(ln, m);
    ln.erase(col_clamped, len_clamped);
    ln.insert(col_clamped, replacement);
    s_sel.caret_line = s_sel.anchor_line = m.line;
    s_sel.anchor_col = col_clamped;
    s_sel.caret_col  = col_clamped + static_cast<int>(replacement.size());
    s_sel.active = true;
    rebuild_buffer_from_lines();
    find_all_matches();
}

void replace_all() {
    if (s_find.match_positions.empty()) return;
    push_undo();
    for (int i = static_cast<int>(s_find.match_positions.size()) - 1; i >= 0; i--) {
        const auto& m = s_find.match_positions[i];
        if (m.line < 0 || m.line >= static_cast<int>(s_cache.lines.size())) continue;
        std::string& ln = s_cache.lines[m.line];
        int col_clamped = std::min(m.col, static_cast<int>(ln.size()));
        int len_clamped = std::min(m.length, static_cast<int>(ln.size()) - col_clamped);
        std::string replacement = compute_replacement(ln, m);
        ln.erase(col_clamped, len_clamped);
        ln.insert(col_clamped, replacement);
    }
    rebuild_buffer_from_lines();
    find_all_matches();
}


char matching_close_bracket(char open) {
    switch (open) {
        case '(': return ')';
        case '[': return ']';
        case '{': return '}';
        case '"': return '"';
        case '\'': return '\'';
        default:  return 0;
    }
}

bool is_open_bracket(char c) {
    return c == '(' || c == '[' || c == '{';
}

bool is_close_bracket(char c) {
    return c == ')' || c == ']' || c == '}';
}

bool find_matching_bracket(int line, int col, int& out_line, int& out_col, char& out_ch) {
    const std::string& cur = line_at(line);
    char here = (col >= 0 && col < static_cast<int>(cur.size())) ? cur[col] : 0;
    char before = (col > 0 && col - 1 < static_cast<int>(cur.size())) ? cur[col - 1] : 0;

    int probe_line = line;
    int probe_col  = col;
    char open_ch   = 0;
    bool forward   = true;

    if (is_open_bracket(here) || is_close_bracket(here)) {
        open_ch  = here;
        forward  = is_open_bracket(here);
    } else if (is_open_bracket(before) || is_close_bracket(before)) {
        open_ch  = before;
        probe_col = col - 1;
        forward  = is_open_bracket(before);
    } else {
        return false;
    }

    char want_open  = forward ? open_ch : 0;
    char want_close = 0;
    if (forward) {
        want_close = matching_close_bracket(open_ch);
    } else {
        if (open_ch == ')') { want_open = '('; want_close = ')'; }
        else if (open_ch == ']') { want_open = '['; want_close = ']'; }
        else if (open_ch == '}') { want_open = '{'; want_close = '}'; }
    }
    if (want_open == 0 || want_close == 0) return false;

    int depth = 0;
    if (forward) {
        for (int li = probe_line; li < line_count(); ++li) {
            const std::string& ln = line_at(li);
            int start = (li == probe_line) ? probe_col : 0;
            for (int ci = start; ci < static_cast<int>(ln.size()); ++ci) {
                char c = ln[ci];
                if (c == want_open) depth++;
                else if (c == want_close) {
                    depth--;
                    if (depth == 0) {
                        out_line = li; out_col = ci; out_ch = c;
                        return true;
                    }
                }
            }
        }
    } else {
        for (int li = probe_line; li >= 0; --li) {
            const std::string& ln = line_at(li);
            int start = (li == probe_line) ? probe_col : static_cast<int>(ln.size()) - 1;
            for (int ci = start; ci >= 0; --ci) {
                char c = ln[ci];
                if (c == want_close) depth++;
                else if (c == want_open) {
                    depth--;
                    if (depth == 0) {
                        out_line = li; out_col = ci; out_ch = c;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}


void collect_buffer_identifiers(std::vector<std::string>& out, int around_line) {
    out.clear();
    std::unordered_set<std::string> seen;
    int total = line_count();
    int lo = std::max(0, around_line - 1500);
    int hi = std::min(total, around_line + 1500);
    for (int i = lo; i < hi; ++i) {
        const std::string& ln = s_cache.lines[i];
        size_t j = 0;
        while (j < ln.size()) {
            unsigned char c = static_cast<unsigned char>(ln[j]);
            bool starts = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
            if (!starts) { j++; continue; }
            size_t s = j;
            while (j < ln.size()) {
                unsigned char d = static_cast<unsigned char>(ln[j]);
                bool cont = (d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') ||
                            (d >= '0' && d <= '9') || d == '_';
                if (!cont) break;
                j++;
            }
            if (j - s >= 3 && j - s <= 80) {
                std::string word = ln.substr(s, j - s);
                if (seen.insert(word).second)
                    out.push_back(std::move(word));
            }
        }
    }
}

bool fuzzy_subsequence_score(const std::string& lower_pat, const std::string& lower_cand, int& score) {
    if (lower_pat.empty()) { score = 0; return true; }
    size_t pi = 0;
    int s = 0;
    int prev_match = -2;
    int consecutive = 0;
    for (size_t ci = 0; ci < lower_cand.size() && pi < lower_pat.size(); ++ci) {
        if (lower_cand[ci] == lower_pat[pi]) {
            if (static_cast<int>(ci) == prev_match + 1) {
                consecutive++;
                s += 6 + consecutive * 2;
            } else {
                consecutive = 0;
                s += 2;
            }
            if (ci == 0) s += 12;
            else {
                char p = lower_cand[ci - 1];
                if (p == '_' || p == ':' || p == '.') s += 8;
            }
            prev_match = static_cast<int>(ci);
            pi++;
        }
    }
    if (pi != lower_pat.size()) return false;
    if (lower_cand.size() == lower_pat.size()) s += 4;
    s -= static_cast<int>(lower_cand.size()) / 4;
    score = s;
    return true;
}

void rebuild_autocomplete(const std::string& partial, int caret_line) {
    autocomplete::matches.clear();
    autocomplete::selected = 0;
    if (partial.size() < 2) {
        autocomplete::popup_visible = false;
        return;
    }

    std::string lower_pat = partial;
    for (auto& c : lower_pat) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    struct cand_t { std::string text; int score; };
    std::vector<cand_t> cands;
    std::unordered_set<std::string> seen;
    seen.insert(partial);

    for (const auto& kw : autocomplete::keywords()) {
        if (kw == partial) continue;
        std::string lk = kw;
        for (auto& c : lk) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        int sc = 0;
        if (fuzzy_subsequence_score(lower_pat, lk, sc)) {
            if (seen.insert(kw).second)
                cands.push_back({ kw, sc + 6 });
        }
    }

    std::vector<std::string> idents;
    collect_buffer_identifiers(idents, caret_line);
    for (const auto& id : idents) {
        if (id == partial) continue;
        std::string li = id;
        for (auto& c : li) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        int sc = 0;
        if (fuzzy_subsequence_score(lower_pat, li, sc)) {
            if (seen.insert(id).second)
                cands.push_back({ id, sc });
        }
    }

    std::stable_sort(cands.begin(), cands.end(),
        [](const cand_t& a, const cand_t& b) { return a.score > b.score; });

    int cap = static_cast<int>(cands.size());
    if (cap > 12) cap = 12;
    for (int i = 0; i < cap; ++i)
        autocomplete::matches.push_back(cands[i].text);

    autocomplete::partial      = partial;
    autocomplete::popup_visible = !autocomplete::matches.empty();
    autocomplete::cursor_line  = caret_line;
}


std::vector<std::string> split_to_lines(std::string_view text) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') {
            size_t end = i;
            if (end > start && text[end - 1] == '\r') end--;
            out.emplace_back(text.substr(start, end - start));
            start = i + 1;
        }
    }
    size_t end = text.size();
    if (end > start && text[end - 1] == '\r') end--;
    out.emplace_back(text.substr(start, end - start));
    return out;
}


void compute_lcs_diff(const std::vector<std::string>& a,
                      const std::vector<std::string>& b,
                      code_editor_widget::pending_diff_t& diff)
{
    const int n = static_cast<int>(a.size());
    const int m = static_cast<int>(b.size());

    int pre = 0;
    while (pre < n && pre < m && a[pre] == b[pre]) pre++;
    int suf = 0;
    while (suf < (n - pre) && suf < (m - pre) &&
           a[n - 1 - suf] == b[m - 1 - suf]) suf++;

    const int an = n - pre - suf;
    const int bm = m - pre - suf;

    struct op_t { int kind; std::string text; int old_line; int new_line; };
    std::vector<op_t> ops;

    for (int i = 0; i < pre; ++i)
        ops.push_back({ 0, a[i], i, i });

    const long long dp_cells =
        static_cast<long long>(an + 1) * static_cast<long long>(bm + 1);
    const long long dp_cap = 6000000;

    if (dp_cells > dp_cap) {
        for (int i = 0; i < an; ++i)
            ops.push_back({ 2, a[pre + i], pre + i, -1 });
        for (int j = 0; j < bm; ++j)
            ops.push_back({ 1, b[pre + j], -1, pre + j });
    } else {
        std::vector<std::vector<int>> dp(an + 1, std::vector<int>(bm + 1, 0));
        for (int i = an - 1; i >= 0; --i) {
            for (int j = bm - 1; j >= 0; --j) {
                if (a[pre + i] == b[pre + j])
                    dp[i][j] = dp[i + 1][j + 1] + 1;
                else
                    dp[i][j] = std::max(dp[i + 1][j], dp[i][j + 1]);
            }
        }

        int i = 0, j = 0;
        while (i < an && j < bm) {
            if (a[pre + i] == b[pre + j]) {
                ops.push_back({ 0, a[pre + i], pre + i, pre + j });
                i++; j++;
            } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                ops.push_back({ 2, a[pre + i], pre + i, -1 });
                i++;
            } else {
                ops.push_back({ 1, b[pre + j], -1, pre + j });
                j++;
            }
        }
        while (i < an) { ops.push_back({ 2, a[pre + i], pre + i, -1 }); i++; }
        while (j < bm) { ops.push_back({ 1, b[pre + j], -1, pre + j }); j++; }
    }

    for (int i = 0; i < suf; ++i)
        ops.push_back({ 0, a[n - suf + i], n - suf + i, m - suf + i });

    diff.hunks.clear();
    diff.total_added   = 0;
    diff.total_removed = 0;

    size_t idx = 0;
    while (idx < ops.size()) {
        if (ops[idx].kind == 0) { idx++; continue; }

        code_editor_widget::diff_hunk_t hunk;
        hunk.state = code_editor_widget::diff_hunk_state_t::pending;
        size_t hs = idx;
        int ctx_run = 0;
        size_t he = idx;
        while (he < ops.size()) {
            if (ops[he].kind == 0) {
                ctx_run++;
                if (ctx_run > 2) break;
            } else {
                ctx_run = 0;
            }
            he++;
        }
        while (he > hs && ops[he - 1].kind == 0) he--;

        int first_old = -1, first_new = -1, last_old = -1, last_new = -1;
        for (size_t k = hs; k < he; ++k) {
            const op_t& o = ops[k];
            code_editor_widget::diff_line_t dl;
            dl.text     = o.text;
            dl.old_line = o.old_line;
            dl.new_line = o.new_line;
            if (o.kind == 0)      dl.kind = code_editor_widget::diff_line_kind_t::context;
            else if (o.kind == 1) { dl.kind = code_editor_widget::diff_line_kind_t::added;   hunk.added++; }
            else                  { dl.kind = code_editor_widget::diff_line_kind_t::removed; hunk.removed++; }

            if (o.old_line >= 0) {
                if (first_old < 0) first_old = o.old_line;
                last_old = o.old_line;
            }
            if (o.new_line >= 0) {
                if (first_new < 0) first_new = o.new_line;
                last_new = o.new_line;
            }
            hunk.lines.push_back(std::move(dl));
        }

        hunk.old_start = first_old < 0 ? 0 : first_old;
        hunk.new_start = first_new < 0 ? 0 : first_new;
        hunk.old_count = (first_old < 0) ? 0 : (last_old - first_old + 1);
        hunk.new_count = (first_new < 0) ? 0 : (last_new - first_new + 1);

        diff.total_added   += hunk.added;
        diff.total_removed += hunk.removed;
        diff.hunks.push_back(std::move(hunk));
        idx = he;
    }
}


void rebuild_buffer_from_external(const std::string& text) {
    s_cache.lines = split_to_lines(text);
    if (s_cache.lines.empty()) s_cache.lines.push_back("");
    s_cache.tokens.assign(s_cache.lines.size(), {});
    for (size_t i = 0; i < s_cache.lines.size(); ++i)
        syntax::tokenize(s_cache.lines[i], s_lang, s_cache.tokens[i]);

    size_t needed = text.size() + 1024 * 64;
    if (code_editor::buffer.size() < needed)
        code_editor::buffer.resize(needed);
    memcpy(code_editor::buffer.data(), text.c_str(), text.size());
    code_editor::buffer[text.size()] = '\0';
    code_editor::dirty = true;
    s_cache.dirty = false;
}


void rebuild_pending_from_proposal(const std::string& origin,
                                   const std::vector<std::string>& old_lines,
                                   const std::vector<std::string>& new_lines)
{
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff.active        = true;
    s_diff.origin        = origin;
    s_diff.old_lines     = old_lines;
    s_diff.new_lines     = new_lines;
    compute_lcs_diff(old_lines, new_lines, s_diff);
    s_diff_hover_hunk    = -1;
}


std::string compose_resolved_text() {
    std::vector<std::string> result;
    result.reserve(s_diff.new_lines.size() + s_diff.old_lines.size());

    size_t old_idx = 0;
    size_t hi = 0;

    auto emit_context_until = [&](int old_target) {
        while (static_cast<int>(old_idx) < old_target &&
               old_idx < s_diff.old_lines.size()) {
            result.push_back(s_diff.old_lines[old_idx]);
            old_idx++;
        }
    };

    while (hi < s_diff.hunks.size()) {
        const code_editor_widget::diff_hunk_t& h = s_diff.hunks[hi];

        int hunk_old_begin = h.old_count > 0 ? h.old_start : static_cast<int>(old_idx);
        if (h.old_count == 0) {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::context &&
                    dl.old_line >= 0) {
                    hunk_old_begin = dl.old_line;
                    break;
                }
            }
        }
        emit_context_until(hunk_old_begin);

        if (h.state == code_editor_widget::diff_hunk_state_t::accepted) {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::added ||
                    dl.kind == code_editor_widget::diff_line_kind_t::context)
                    result.push_back(dl.text);
            }
        } else {
            for (const auto& dl : h.lines) {
                if (dl.kind == code_editor_widget::diff_line_kind_t::removed ||
                    dl.kind == code_editor_widget::diff_line_kind_t::context)
                    result.push_back(dl.text);
            }
        }

        int consumed_old = 0;
        for (const auto& dl : h.lines)
            if (dl.old_line >= 0) consumed_old++;
        old_idx = static_cast<size_t>(hunk_old_begin) + consumed_old;
        hi++;
    }

    emit_context_until(static_cast<int>(s_diff.old_lines.size()));

    std::string joined;
    for (size_t i = 0; i < result.size(); ++i) {
        if (i > 0) joined += '\n';
        joined += result[i];
    }
    return joined;
}


void apply_resolved_diff_to_buffer() {
    std::string text = compose_resolved_text();
    int caret_l = std::min(s_sel.caret_line, std::max(0, static_cast<int>(split_to_lines(text).size()) - 1));
    rebuild_buffer_from_external(text);
    s_sel.caret_line = s_sel.anchor_line = clamp_line(caret_l);
    s_sel.caret_col  = s_sel.anchor_col  = clamp_col(s_sel.caret_line, s_sel.caret_col);
    s_sel.active = false;
}


void finalize_diff_if_resolved_locked() {
    if (!s_diff.active) return;
    if (!s_diff.fully_resolved()) return;
    apply_resolved_diff_to_buffer();
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = false;
    s_diff_hover_hunk = -1;
    s_diff_scroll_target = -1.f;
    s_scroll_y = s_scroll_x = s_target_scroll_y = 0.f;
    s_undo.clear();
    s_redo.clear();
    break_undo_coalescing();
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
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        s_diff = code_editor_widget::pending_diff_t{};
        s_diff_hover_hunk = -1;
        s_diff_scroll_target = -1.f;
    }
    break_undo_coalescing();
}

void code_editor_widget::on_text_changed() {
    s_cache.dirty = true;
    s_sel = {};
    s_undo.clear();
    s_redo.clear();
    s_scroll_y = s_scroll_x = s_target_scroll_y = 0.f;
    s_blink_timer = 0.f;
    s_blink_on = true;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        s_diff = code_editor_widget::pending_diff_t{};
        s_diff_hover_hunk = -1;
        s_diff_scroll_target = -1.f;
    }
    break_undo_coalescing();


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


bool code_editor_widget::begin_agent_edit(std::string_view origin) {
    if (!code_editor::active) {
        s_last_error = "code_editor: begin_agent_edit called with no active document";
        return false;
    }
    std::vector<std::string> base = split_to_lines(code_editor::get_content());
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = true;
    s_diff.origin = std::string(origin);
    s_diff.old_lines = base;
    s_diff.new_lines = base;
    s_diff_hover_hunk = -1;
    return true;
}

bool code_editor_widget::propose_full_content(std::string_view new_content) {
    if (!code_editor::active) {
        s_last_error = "code_editor: propose_full_content called with no active document";
        return false;
    }
    std::vector<std::string> old_lines = split_to_lines(code_editor::get_content());
    std::vector<std::string> new_lines = split_to_lines(new_content);
    std::string origin;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        origin = s_diff.active ? s_diff.origin : std::string("agent");
    }
    rebuild_pending_from_proposal(origin, old_lines, new_lines);
    return true;
}

bool code_editor_widget::propose_replace_range(int start_line, int end_line,
                                               std::string_view replacement) {
    if (!code_editor::active) {
        s_last_error = "code_editor: propose_replace_range called with no active document";
        return false;
    }

    std::vector<std::string> old_lines = split_to_lines(code_editor::get_content());
    int n = static_cast<int>(old_lines.size());
    if (start_line < 0) start_line = 0;
    if (end_line < start_line) end_line = start_line;
    if (start_line > n) start_line = n;
    if (end_line > n) end_line = n;

    std::vector<std::string> repl = split_to_lines(replacement);
    if (replacement.empty()) repl.clear();

    std::vector<std::string> new_lines;
    new_lines.reserve(old_lines.size());
    for (int i = 0; i < start_line && i < n; ++i)
        new_lines.push_back(old_lines[i]);
    for (auto& r : repl)
        new_lines.push_back(std::move(r));
    for (int i = end_line; i < n; ++i)
        new_lines.push_back(old_lines[i]);
    if (new_lines.empty()) new_lines.push_back("");

    std::string origin;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        origin = s_diff.active ? s_diff.origin : std::string("agent");
    }
    rebuild_pending_from_proposal(origin, old_lines, new_lines);
    return true;
}

bool code_editor_widget::has_pending_diff() {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    return s_diff.active && !s_diff.hunks.empty();
}

const code_editor_widget::pending_diff_t& code_editor_widget::pending_diff() {
    return s_diff;
}

int code_editor_widget::pending_hunk_count() {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    return static_cast<int>(s_diff.hunks.size());
}

bool code_editor_widget::accept_hunk(int index) {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active || index < 0 || index >= static_cast<int>(s_diff.hunks.size()))
        return false;
    s_diff.hunks[index].state = code_editor_widget::diff_hunk_state_t::accepted;
    return true;
}

bool code_editor_widget::reject_hunk(int index) {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active || index < 0 || index >= static_cast<int>(s_diff.hunks.size()))
        return false;
    s_diff.hunks[index].state = code_editor_widget::diff_hunk_state_t::rejected;
    return true;
}

void code_editor_widget::accept_all() {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active) return;
    for (auto& h : s_diff.hunks)
        h.state = code_editor_widget::diff_hunk_state_t::accepted;
}

void code_editor_widget::reject_all() {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    if (!s_diff.active) return;
    for (auto& h : s_diff.hunks)
        h.state = code_editor_widget::diff_hunk_state_t::rejected;
}

void code_editor_widget::cancel_agent_edit() {
    std::lock_guard<std::mutex> lk(s_diff_mtx);
    s_diff = code_editor_widget::pending_diff_t{};
    s_diff.active = false;
    s_diff_hover_hunk = -1;
}


void code_editor_widget::render(float pos_x, float pos_y, float width, float height,
                                 float alpha, float accent_r, float accent_g, float accent_b)
{
    (void)accent_r; (void)accent_g; (void)accent_b;
    if (!code_editor::active || code_editor::buffer.empty())
        return;

    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : g_code_font;
    if (code_font) ImGui::PushFont(code_font);

    ImGuiWindow* editor_win = ImGui::GetCurrentWindow();
    float prev_font_scale = editor_win ? editor_win->FontWindowScale : 1.f;
    {
        float want = editor_config::font_size;
        if (want < 8.f)  want = 8.f;
        if (want > 48.f) want = 48.f;
        float scale = want / 14.f;
        if (scale < 0.5f) scale = 0.5f;
        if (scale > 3.f)  scale = 3.f;
        ImGui::SetWindowFontScale(scale);
    }

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

    bool ghost_consumed_tab = false;

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
    const float minimap_w = (editor_config::minimap && width > 360.f) ? 64.f : 0.f;
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

    int longest_line_chars = 0;
    {
        int probe_lo = std::max(0, static_cast<int>(s_scroll_y / line_h) - 4);
        int probe_hi = std::min(n_lines - 1,
                                static_cast<int>((s_scroll_y + editor_h) / line_h) + 4);
        for (int i = probe_lo; i <= probe_hi; ++i)
            longest_line_chars = std::max(longest_line_chars, line_length(i));
    }
    const float h_scrollbar_h = 9.f;
    const bool  word_wrap_on  = editor_config::word_wrap;
    s_view_char_w = char_w;
    s_view_text_w = (code_w - text_x0 - 14.f);
    if (s_view_text_w < char_w) s_view_text_w = char_w;
    {
        float content_w = longest_line_chars * char_w + char_w * 2.f;
        s_max_scroll_x = word_wrap_on ? 0.f
                                      : std::max(0.f, content_w - s_view_text_w);
    }
    if (word_wrap_on) s_scroll_x = 0.f;
    if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
    if (s_scroll_x < 0.f) s_scroll_x = 0.f;

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
    if (!ImGui::ItemAdd(bb, id)) {
        ImGui::SetWindowFontScale(prev_font_scale);
        if (code_font) ImGui::PopFont();
        return;
    }

    bool diff_active = false;
    {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        diff_active = s_diff.active && !s_diff.hunks.empty();
    }

    if (diff_active) {
        std::lock_guard<std::mutex> lk(s_diff_mtx);
        s_scroll_x = 0.f;

        const float hdr_h = 40.f;
        ImVec2 hdr_min(ox, oy);
        ImVec2 hdr_max(ox + width, oy + hdr_h);
        dl->AddRectFilled(hdr_min, hdr_max, aida::ui::with_alpha(th.panel_header, a));
        dl->AddLine(ImVec2(hdr_min.x, hdr_max.y - 1.f), ImVec2(hdr_max.x, hdr_max.y - 1.f),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);

        ImFont* hdr_font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
        {
            std::string title = "AI Edit";
            if (!s_diff.origin.empty()) title += "  -  " + s_diff.origin;
            dl->AddText(hdr_font, 14.f, ImVec2(hdr_min.x + 14.f, hdr_min.y + 6.f),
                        aida::ui::with_alpha(th.text_primary, a), title.c_str());

            char stats[96];
            int pend = 0;
            for (const auto& h : s_diff.hunks)
                if (h.state == code_editor_widget::diff_hunk_state_t::pending) pend++;
            snprintf(stats, sizeof(stats), "+%d  -%d   %d hunk%s   %d pending",
                     s_diff.total_added, s_diff.total_removed,
                     static_cast<int>(s_diff.hunks.size()),
                     s_diff.hunks.size() == 1 ? "" : "s", pend);
            dl->AddText(hdr_font, 12.f, ImVec2(hdr_min.x + 14.f, hdr_min.y + 22.f),
                        aida::ui::with_alpha(th.text_secondary, a), stats);
        }

        bool want_accept_all = false;
        bool want_reject_all = false;
        {
            ImGui::PushID("##diff_hdr_actions");
            const float bw = 88.f;
            const float bh = 24.f;
            float by = hdr_min.y + (hdr_h - bh) * 0.5f;
            float bx_reject = hdr_max.x - 14.f - bw;
            float bx_accept = bx_reject - 8.f - bw;

            ImVec2 mp = ImGui::GetIO().MousePos;
            auto hdr_button = [&](const char* label, float bx, ImU32 base, bool& out) {
                ImVec2 mn(bx, by), mx(bx + bw, by + bh);
                bool hov = (mp.x >= mn.x && mp.x <= mx.x && mp.y >= mn.y && mp.y <= mx.y);
                dl->AddRectFilled(mn, mx, aida::ui::with_alpha(base, (hov ? 0.32f : 0.20f) * a), 6.f);
                dl->AddRect(mn, mx, aida::ui::with_alpha(base, (hov ? 0.95f : 0.55f) * a), 6.f, 0, 1.f);
                float tw = hdr_font->CalcTextSizeA(12.f, FLT_MAX, 0.f, label).x;
                dl->AddText(hdr_font, 12.f,
                            ImVec2(mn.x + (bw - tw) * 0.5f, mn.y + (bh - 12.f) * 0.5f),
                            aida::ui::with_alpha(base, a), label);
                if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) out = true;
            };
            hdr_button("Accept All", bx_accept, th.success, want_accept_all);
            hdr_button("Reject All", bx_reject, th.error, want_reject_all);
            ImGui::PopID();
        }

        struct vis_row_t {
            int hunk = -1;
            int line_in_hunk = -1;
            bool is_hunk_head = false;
            code_editor_widget::diff_line_kind_t kind = code_editor_widget::diff_line_kind_t::context;
            const std::string* text = nullptr;
            int old_no = -1;
            int new_no = -1;
        };
        std::vector<vis_row_t> rows;
        rows.reserve(s_diff.old_lines.size() + s_diff.total_added + s_diff.hunks.size());

        {
            int old_idx = 0;
            int gap_ctx = 3;
            for (int hi = 0; hi < static_cast<int>(s_diff.hunks.size()); ++hi) {
                const code_editor_widget::diff_hunk_t& h = s_diff.hunks[hi];

                int hunk_old_begin = h.old_count > 0 ? h.old_start : old_idx;
                if (h.old_count == 0) {
                    for (const auto& dl2 : h.lines)
                        if (dl2.kind == code_editor_widget::diff_line_kind_t::context && dl2.old_line >= 0) {
                            hunk_old_begin = dl2.old_line; break;
                        }
                }

                int ctx_from = std::max(old_idx, hunk_old_begin - gap_ctx);
                if (hi == 0) ctx_from = std::max(0, hunk_old_begin - gap_ctx);
                if (ctx_from > old_idx && old_idx > 0) {
                    vis_row_t sep;
                    sep.kind = code_editor_widget::diff_line_kind_t::context;
                    rows.push_back(sep);
                }
                for (int li = ctx_from; li < hunk_old_begin &&
                                          li < static_cast<int>(s_diff.old_lines.size()); ++li) {
                    vis_row_t r;
                    r.kind = code_editor_widget::diff_line_kind_t::context;
                    r.text = &s_diff.old_lines[li];
                    r.old_no = li + 1;
                    r.new_no = -1;
                    rows.push_back(r);
                }

                vis_row_t head;
                head.hunk = hi;
                head.is_hunk_head = true;
                rows.push_back(head);

                for (int k = 0; k < static_cast<int>(h.lines.size()); ++k) {
                    const code_editor_widget::diff_line_t& dl2 = h.lines[k];
                    vis_row_t r;
                    r.hunk = hi;
                    r.line_in_hunk = k;
                    r.kind = dl2.kind;
                    r.text = &dl2.text;
                    r.old_no = dl2.old_line >= 0 ? dl2.old_line + 1 : -1;
                    r.new_no = dl2.new_line >= 0 ? dl2.new_line + 1 : -1;
                    rows.push_back(r);
                }

                int consumed = 0;
                for (const auto& dl2 : h.lines)
                    if (dl2.old_line >= 0) consumed++;
                old_idx = hunk_old_begin + consumed;
            }

            int tail_to = std::min(static_cast<int>(s_diff.old_lines.size()), old_idx + gap_ctx);
            if (old_idx < static_cast<int>(s_diff.old_lines.size())) {
                for (int li = old_idx; li < tail_to; ++li) {
                    vis_row_t r;
                    r.kind = code_editor_widget::diff_line_kind_t::context;
                    r.text = &s_diff.old_lines[li];
                    r.old_no = li + 1;
                    rows.push_back(r);
                }
            }
        }

        const float body_y0 = oy + hdr_h;
        const float body_h  = editor_h - hdr_h;
        const float diff_gutter_w = char_w * 11.f + 16.f;
        const float sign_x = ox + diff_gutter_w + 4.f;
        const float diff_text_x = sign_x + char_w * 1.6f;

        float content_h = rows.size() * line_h;
        float diff_max_scroll = std::max(0.f, content_h - body_h + line_h);
        if (s_diff_scroll_target < 0.f) s_diff_scroll_target = 0.f;

        bool body_hovered = ImGui::IsMouseHoveringRect(
            ImVec2(ox, body_y0), ImVec2(ox + width, body_y0 + body_h));
        if (body_hovered) {
            float wheel = ImGui::GetIO().MouseWheel;
            if (wheel != 0.f) s_diff_scroll_target -= wheel * line_h * 3.f;
        }
        s_diff_scroll_target = std::max(0.f, std::min(s_diff_scroll_target, diff_max_scroll));
        s_scroll_y = aida::motion::smooth_lerp(s_scroll_y, s_diff_scroll_target, 20.f, dt);
        if (std::abs(s_diff_scroll_target - s_scroll_y) < 0.5f) s_scroll_y = s_diff_scroll_target;
        s_scroll_y = std::max(0.f, std::min(s_scroll_y, diff_max_scroll));

        dl->PushClipRect(ImVec2(ox, body_y0), ImVec2(ox + width, body_y0 + body_h), true);

        int diff_first = std::max(0, static_cast<int>(s_scroll_y / line_h) - 1);
        int diff_last  = std::min(static_cast<int>(rows.size()) - 1,
                                  static_cast<int>((s_scroll_y + body_h) / line_h) + 1);

        ImVec2 mp = ImGui::GetIO().MousePos;
        int new_hover_hunk = -1;
        std::vector<int> accept_clicked;
        std::vector<int> reject_clicked;

        for (int ri = diff_first; ri <= diff_last; ++ri) {
            const vis_row_t& r = rows[ri];
            float ry = body_y0 + ri * line_h - s_scroll_y;

            if (r.is_hunk_head) {
                const code_editor_widget::diff_hunk_t& h = s_diff.hunks[r.hunk];
                dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + code_w, ry + line_h),
                                  aida::ui::with_alpha(th.accent_glow, 0.6f * a));
                char hb[64];
                snprintf(hb, sizeof(hb), "@@ -%d,%d +%d,%d @@",
                         h.old_start + 1, h.old_count, h.new_start + 1, h.new_count);
                dl->AddText(ImVec2(ox + 10.f, ry + 1.f),
                            aida::ui::with_alpha(th.accent_u32, a), hb);

                const char* state_label =
                    h.state == code_editor_widget::diff_hunk_state_t::accepted ? "ACCEPTED" :
                    h.state == code_editor_widget::diff_hunk_state_t::rejected ? "REJECTED" : nullptr;

                const float hbw = char_w * 7.f + 10.f;
                const float hbh = line_h - 4.f;
                float hby = ry + 2.f;
                float hbx_rej = ox + code_w - 12.f - hbw;
                float hbx_acc = hbx_rej - 6.f - hbw;

                if (state_label) {
                    ImU32 sc = h.state == code_editor_widget::diff_hunk_state_t::accepted
                                   ? th.success : th.error;
                    float tw = ImGui::CalcTextSize(state_label).x;
                    dl->AddText(ImVec2(ox + code_w - 12.f - tw, ry + 1.f),
                                aida::ui::with_alpha(sc, a), state_label);
                    if (mp.x >= ox && mp.x <= ox + code_w && mp.y >= ry && mp.y < ry + line_h)
                        new_hover_hunk = r.hunk;
                } else {
                    auto mini_btn = [&](const char* lbl, float bx, ImU32 base) -> bool {
                        ImVec2 mn(bx, hby), mx(bx + hbw, hby + hbh);
                        bool hov = (mp.x >= mn.x && mp.x <= mx.x && mp.y >= mn.y && mp.y <= mx.y);
                        dl->AddRectFilled(mn, mx, aida::ui::with_alpha(base, (hov ? 0.35f : 0.18f) * a), 4.f);
                        dl->AddRect(mn, mx, aida::ui::with_alpha(base, (hov ? 1.f : 0.5f) * a), 4.f, 0, 1.f);
                        float tw = ImGui::CalcTextSize(lbl).x;
                        dl->AddText(ImVec2(mn.x + (hbw - tw) * 0.5f, mn.y + (hbh - ImGui::GetFontSize()) * 0.5f),
                                    aida::ui::with_alpha(base, a), lbl);
                        return hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left);
                    };
                    if (mini_btn("Accept", hbx_acc, th.success)) accept_clicked.push_back(r.hunk);
                    if (mini_btn("Reject", hbx_rej, th.error))   reject_clicked.push_back(r.hunk);
                    if (mp.x >= ox && mp.x <= ox + code_w && mp.y >= ry && mp.y < ry + line_h)
                        new_hover_hunk = r.hunk;
                }
                continue;
            }

            if (!r.text) {
                float midy = ry + line_h * 0.5f;
                for (float dx = ox + 12.f; dx < ox + code_w - 12.f; dx += 8.f)
                    dl->AddLine(ImVec2(dx, midy), ImVec2(dx + 3.f, midy),
                                aida::ui::with_alpha(th.border_subtle, a), 1.f);
                continue;
            }

            bool is_add = r.kind == code_editor_widget::diff_line_kind_t::added;
            bool is_rem = r.kind == code_editor_widget::diff_line_kind_t::removed;

            bool hunk_resolved = false;
            ImU32 wash = 0;
            ImU32 bar  = 0;
            if (is_add) {
                wash = aida::ui::with_alpha(th.success, 0.14f * a);
                bar  = aida::ui::with_alpha(th.success, 0.9f * a);
            } else if (is_rem) {
                wash = aida::ui::with_alpha(th.error, 0.14f * a);
                bar  = aida::ui::with_alpha(th.error, 0.9f * a);
            }
            if (r.hunk >= 0) {
                const code_editor_widget::diff_hunk_t& h = s_diff.hunks[r.hunk];
                hunk_resolved = h.state != code_editor_widget::diff_hunk_state_t::pending;
                if (h.state == code_editor_widget::diff_hunk_state_t::rejected && is_add) {
                    wash = aida::ui::with_alpha(th.text_dim, 0.06f * a);
                    bar  = aida::ui::with_alpha(th.text_dim, 0.4f * a);
                } else if (h.state == code_editor_widget::diff_hunk_state_t::accepted && is_rem) {
                    wash = aida::ui::with_alpha(th.text_dim, 0.06f * a);
                    bar  = aida::ui::with_alpha(th.text_dim, 0.4f * a);
                }
            }

            if (wash) dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + code_w, ry + line_h), wash);
            if (bar)  dl->AddRectFilled(ImVec2(ox, ry), ImVec2(ox + 3.f, ry + line_h), bar);

            if (r.hunk >= 0 && r.hunk == s_diff_hover_hunk && !hunk_resolved)
                dl->AddRectFilled(ImVec2(ox + 3.f, ry), ImVec2(ox + code_w, ry + line_h),
                                  aida::ui::with_alpha(th.accent_u32, 0.05f * a));

            char numbuf[24];
            if (r.old_no > 0)
                snprintf(numbuf, sizeof(numbuf), "%5d", r.old_no);
            else
                snprintf(numbuf, sizeof(numbuf), "     ");
            dl->AddText(ImVec2(ox + 6.f, ry + 1.f),
                        aida::ui::with_alpha(th.text_lineno, a), numbuf);
            if (r.new_no > 0)
                snprintf(numbuf, sizeof(numbuf), "%5d", r.new_no);
            else
                snprintf(numbuf, sizeof(numbuf), "     ");
            dl->AddText(ImVec2(ox + 6.f + char_w * 5.5f, ry + 1.f),
                        aida::ui::with_alpha(th.text_lineno, a), numbuf);

            const char* sign = is_add ? "+" : (is_rem ? "-" : " ");
            ImU32 sign_col = is_add ? aida::ui::with_alpha(th.success, a)
                          : is_rem ? aida::ui::with_alpha(th.error, a)
                          : aida::ui::with_alpha(th.text_dim, a);
            dl->AddText(ImVec2(sign_x, ry + 1.f), sign_col, sign);

            std::vector<syntax::token_t> toks;
            syntax::tokenize(*r.text, s_lang, toks);
            float tx = diff_text_x - s_scroll_x;
            float dim = (is_rem ? 0.92f : 1.f) * (hunk_resolved ? 0.55f : 1.f);
            for (const auto& tk : toks) {
                if (tk.type == syntax::token_type::whitespace) {
                    for (uint32_t kk = 0; kk < tk.length; ++kk) {
                        char c = (*r.text)[tk.start + kk];
                        tx += (c == '\t') ? char_w * editor_config::tab_size : char_w;
                    }
                    continue;
                }
                if (tk.start + tk.length > static_cast<uint32_t>(r.text->size())) continue;
                ImU32 col = tok_colors[static_cast<int>(tk.type)];
                col = aida::ui::with_alpha(col, dim);
                const char* ts = r.text->c_str() + tk.start;
                dl->AddText(ImVec2(tx, ry + 1.f), col, ts, ts + tk.length);
                if (is_rem)
                    dl->AddLine(ImVec2(tx, ry + line_h * 0.5f + 1.f),
                                ImVec2(tx + tk.length * char_w, ry + line_h * 0.5f + 1.f),
                                aida::ui::with_alpha(th.error, 0.5f * a), 1.f);
                tx += tk.length * char_w;
            }
        }

        dl->AddLine(ImVec2(ox + diff_gutter_w, body_y0),
                    ImVec2(ox + diff_gutter_w, body_y0 + body_h),
                    aida::ui::with_alpha(th.border_subtle, a), 1.f);

        dl->PopClipRect();

        if (content_h > body_h) {
            const float sb_w = 10.f;
            float track_x = ox + code_w - sb_w - 2.f;
            float track_y0 = body_y0 + 2.f;
            float track_h = body_h - 4.f;
            float ratio = body_h / content_h;
            float thumb_h = std::max(24.f, track_h * ratio);
            float range = content_h - body_h;
            float thumb_y = track_y0 + (range > 0.f ? (s_scroll_y / range) * (track_h - thumb_h) : 0.f);
            dl->AddRectFilled(ImVec2(track_x, thumb_y), ImVec2(track_x + sb_w, thumb_y + thumb_h),
                              aida::ui::with_alpha(th.text_secondary, 0.35f * a), 3.f);
        }

        s_diff_hover_hunk = new_hover_hunk;

        for (int hi : accept_clicked)
            if (hi >= 0 && hi < static_cast<int>(s_diff.hunks.size()))
                s_diff.hunks[hi].state = code_editor_widget::diff_hunk_state_t::accepted;
        for (int hi : reject_clicked)
            if (hi >= 0 && hi < static_cast<int>(s_diff.hunks.size()))
                s_diff.hunks[hi].state = code_editor_widget::diff_hunk_state_t::rejected;
        if (want_accept_all)
            for (auto& h : s_diff.hunks) h.state = code_editor_widget::diff_hunk_state_t::accepted;
        if (want_reject_all)
            for (auto& h : s_diff.hunks) h.state = code_editor_widget::diff_hunk_state_t::rejected;

        {
            char buf[160];
            snprintf(buf, sizeof(buf), "%s%s  -  AI Edit (+%d -%d)",
                     code_editor::filename.empty() ? "Untitled" : code_editor::filename.c_str(),
                     code_editor::dirty ? " *" : "",
                     s_diff.total_added, s_diff.total_removed);
            globals::ui::status_file_info = buf;
        }

        finalize_diff_if_resolved_locked();

        ImGui::SetWindowFontScale(prev_font_scale);
        if (code_font) ImGui::PopFont();
        return;
    }

    s_diff_scroll_target = -1.f;

    bool mouse_over_find_bar = false;
    if (s_find.visible) {
        const float fb_w = 420.f;
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
        float wheel  = ImGui::GetIO().MouseWheel;
        float wheelh = ImGui::GetIO().MouseWheelH;
        bool  h_intent = ImGui::GetIO().KeyShift;
        if (h_intent && wheel != 0.f && !word_wrap_on) {
            s_scroll_x -= wheel * char_w * 6.f;
        } else if (wheel != 0.f) {
            s_target_scroll_y -= wheel * line_h * 3.f;
        }
        if (wheelh != 0.f && !word_wrap_on)
            s_scroll_x -= wheelh * char_w * 6.f;
        if (s_scroll_x > s_max_scroll_x) s_scroll_x = s_max_scroll_x;
        if (s_scroll_x < 0.f) s_scroll_x = 0.f;
    }

    int first_row = std::max(0, static_cast<int>(s_scroll_y / line_h) - 1);
    int last_row  = std::min(n_lines - 1, static_cast<int>((s_scroll_y + editor_h) / line_h) + 1);

    dl->PushClipRect(ImVec2(ox, oy), ImVec2(ox + code_w, oy + editor_h), true);

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
        ImU32 match_col  = aida::ui::with_alpha(th.accent_dim, 0.32f * a);
        float pulse = aida::ui::clock::pulse(1.5f, 0.55f, 1.f);
        ImU32 active_col = aida::ui::with_alpha(th.accent_u32, 0.55f * pulse * a);
        for (int mi = 0; mi < static_cast<int>(s_find.match_positions.size()); mi++) {
            const auto& m = s_find.match_positions[mi];
            int ml = m.line;
            int mc = m.col;
            int mlen = m.length;
            if (ml < first_row || ml > last_row) continue;
            float my = oy + ml * line_h - s_scroll_y;
            float mx0 = ox + text_x0 + mc * char_w - s_scroll_x;
            float mx1 = mx0 + mlen * char_w;
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


    if (editor_config::bracket_match && s_has_focus && !s_sel.has_selection()) {
        int br_open_line = -1, br_open_col = -1;
        const std::string& cl = line_at(s_sel.caret_line);
        char here   = (s_sel.caret_col >= 0 && s_sel.caret_col < static_cast<int>(cl.size()))
                          ? cl[s_sel.caret_col] : 0;
        char before = (s_sel.caret_col > 0 && s_sel.caret_col - 1 < static_cast<int>(cl.size()))
                          ? cl[s_sel.caret_col - 1] : 0;
        if (is_open_bracket(here) || is_close_bracket(here)) {
            br_open_line = s_sel.caret_line; br_open_col = s_sel.caret_col;
        } else if (is_open_bracket(before) || is_close_bracket(before)) {
            br_open_line = s_sel.caret_line; br_open_col = s_sel.caret_col - 1;
        }
        if (br_open_line >= 0) {
            int mline = -1, mcol = -1;
            char mch = 0;
            bool found = find_matching_bracket(br_open_line, br_open_col, mline, mcol, mch);
            ImU32 box_col = found ? aida::ui::with_alpha(th.accent_u32, 0.55f * a)
                                  : aida::ui::with_alpha(th.error, 0.55f * a);
            ImU32 fill_col = found ? aida::ui::with_alpha(th.accent_glow, a)
                                   : aida::ui::with_alpha(th.error, 0.18f * a);
            auto draw_box = [&](int bl, int bc) {
                float bx = ox + text_x0 + bc * char_w - s_scroll_x;
                float by = oy + bl * line_h - s_scroll_y;
                if (by < oy - line_h || by > oy + editor_h) return;
                dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + char_w, by + line_h), fill_col, 2.f);
                dl->AddRect(ImVec2(bx, by), ImVec2(bx + char_w, by + line_h), box_col, 2.f, 0, 1.f);
            };
            draw_box(br_open_line, br_open_col);
            if (found) draw_box(mline, mcol);
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
                    work_queue::post([context]() {
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
                ghost_consumed_tab = true;
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
            break_undo_coalescing();
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
            break_undo_coalescing();
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
                const std::string& ln = line_at(nl);
                nc--;
                while (nc > 0 &&
                       (static_cast<unsigned char>(ln[nc]) & 0xC0) == 0x80)
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
                const std::string& ln = line_at(nl);
                int len = static_cast<int>(ln.size());
                nc++;
                while (nc < len &&
                       (static_cast<unsigned char>(ln[nc]) & 0xC0) == 0x80)
                    nc++;
            } else if (nl < line_count() - 1) {
                nl++; nc = 0;
            }
            move_caret(nl, nc);
        }
        else if (!(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_UpArrow, true)) {
            int nl = std::max(0, s_sel.caret_line - 1);
            int nc = clamp_col(nl, s_sel.caret_col);
            move_caret(nl, nc);
        }
        else if (!(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) {
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


        if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Enter, true) &&
            !(autocomplete::popup_visible && !autocomplete::matches.empty())) {

            std::string indent;
            char prev_ch = 0;
            char next_ch = 0;
            if (s_sel.caret_line < static_cast<int>(s_cache.lines.size())) {
                auto& ln = s_cache.lines[s_sel.caret_line];
                for (char c : ln) {
                    if (c == ' ' || c == '\t') indent += c;
                    else break;
                }
                int cc = clamp_col(s_sel.caret_line, s_sel.caret_col);
                if (cc > 0 && cc - 1 < static_cast<int>(ln.size())) prev_ch = ln[cc - 1];
                if (cc < static_cast<int>(ln.size())) next_ch = ln[cc];
            }
            bool between_pair = (prev_ch == '{' && next_ch == '}') ||
                                (prev_ch == '(' && next_ch == ')') ||
                                (prev_ch == '[' && next_ch == ']');
            break_undo_coalescing();
            if (between_pair) {
                std::string extra(std::max(1, editor_config::tab_size), ' ');
                insert_text_at_caret("\n" + indent + extra + "\n" + indent);
                int target_line = s_sel.caret_line - 1;
                s_sel.caret_line = s_sel.anchor_line = clamp_line(target_line);
                s_sel.caret_col  = s_sel.anchor_col  =
                    static_cast<int>(indent.size()) + static_cast<int>(extra.size());
                s_sel.active = false;
            } else {
                if (prev_ch == '{' || prev_ch == '(' || prev_ch == '[' ||
                    prev_ch == ':')
                    indent += std::string(std::max(1, editor_config::tab_size), ' ');
                insert_text_at_caret("\n" + indent);
            }
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
                break_undo_coalescing();
            } else if (s_sel.caret_col > 0) {
                push_undo();
                break_undo_coalescing();
                auto& ln = s_cache.lines[s_sel.caret_line];
                int del_start = s_sel.caret_col - 1;
                while (del_start > 0 &&
                       (static_cast<unsigned char>(ln[del_start]) & 0xC0) == 0x80)
                    del_start--;
                int del_len = s_sel.caret_col - del_start;
                char prev_c = ln[del_start];
                char next_c = (s_sel.caret_col < static_cast<int>(ln.size()))
                                  ? ln[s_sel.caret_col] : 0;
                bool pair = editor_config::bracket_match &&
                            ((prev_c == '(' && next_c == ')') ||
                             (prev_c == '[' && next_c == ']') ||
                             (prev_c == '{' && next_c == '}') ||
                             (prev_c == '"' && next_c == '"') ||
                             (prev_c == '\'' && next_c == '\''));
                if (pair) ln.erase(del_start, del_len + 1);
                else      ln.erase(del_start, del_len);
                s_sel.caret_col = s_sel.anchor_col = del_start;
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
                auto& ln = s_cache.lines[s_sel.caret_line];
                int del_end = s_sel.caret_col + 1;
                int line_size = static_cast<int>(ln.size());
                while (del_end < line_size &&
                       (static_cast<unsigned char>(ln[del_end]) & 0xC0) == 0x80)
                    del_end++;
                ln.erase(s_sel.caret_col, del_end - s_sel.caret_col);
                rebuild_buffer_from_lines();
            } else if (s_sel.caret_line < line_count() - 1) {
                push_undo();
                s_cache.lines[s_sel.caret_line] += s_cache.lines[s_sel.caret_line + 1];
                s_cache.lines.erase(s_cache.lines.begin() + s_sel.caret_line + 1);
                s_cache.tokens.erase(s_cache.tokens.begin() + s_sel.caret_line + 1);
                rebuild_buffer_from_lines();
            }
        }
        else if (!ctrl && shift && !ghost_consumed_tab &&
                 !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_Tab, true)) {

            int tab = std::max(1, editor_config::tab_size);
            if (s_sel.has_selection()) {
                int l0, c0, l1, c1;
                selection_ordered(l0, c0, l1, c1);
                (void)c0;
                int end_line = (c1 == 0 && l1 > l0) ? l1 - 1 : l1;
                push_undo();
                break_undo_coalescing();
                for (int li = l0; li <= end_line && li < line_count(); ++li) {
                    std::string& ln = s_cache.lines[li];
                    int removed = 0;
                    if (!ln.empty() && ln[0] == '\t') { ln.erase(0, 1); removed = 1; }
                    else {
                        while (removed < tab && !ln.empty() && ln[0] == ' ') {
                            ln.erase(0, 1);
                            removed++;
                        }
                    }
                    if (li == s_sel.anchor_line)
                        s_sel.anchor_col = std::max(0, s_sel.anchor_col - removed);
                    if (li == s_sel.caret_line)
                        s_sel.caret_col = std::max(0, s_sel.caret_col - removed);
                }
                rebuild_buffer_from_lines();
            } else {
                std::string& ln = s_cache.lines[s_sel.caret_line];
                int removed = 0;
                if (!ln.empty() && ln[0] == '\t') { ln.erase(0, 1); removed = 1; }
                else {
                    while (removed < tab && !ln.empty() && ln[0] == ' ') {
                        ln.erase(0, 1);
                        removed++;
                    }
                }
                if (removed > 0) {
                    push_undo();
                    break_undo_coalescing();
                    s_sel.caret_col = s_sel.anchor_col = std::max(0, s_sel.caret_col - removed);
                    rebuild_buffer_from_lines();
                }
            }
            ensure_caret_visible(editor_h, line_h);
        }
        else if (!ctrl && !ghost_consumed_tab &&
                 !(autocomplete::popup_visible && !autocomplete::matches.empty()) &&
                 ImGui::IsKeyPressed(ImGuiKey_Tab, true)) {

            int tab = std::max(1, editor_config::tab_size);
            if (s_sel.has_selection() &&
                s_sel.anchor_line != s_sel.caret_line) {
                int l0, c0, l1, c1;
                selection_ordered(l0, c0, l1, c1);
                (void)c0;
                int end_line = (c1 == 0 && l1 > l0) ? l1 - 1 : l1;
                push_undo();
                break_undo_coalescing();
                std::string pad(tab, ' ');
                for (int li = l0; li <= end_line && li < line_count(); ++li) {
                    if (s_cache.lines[li].empty()) continue;
                    s_cache.lines[li].insert(0, pad);
                    if (li == s_sel.anchor_line) s_sel.anchor_col += tab;
                    if (li == s_sel.caret_line)  s_sel.caret_col  += tab;
                }
                rebuild_buffer_from_lines();
            } else {
                int col = clamp_col(s_sel.caret_line, s_sel.caret_col);
                int to_next = tab - (col % tab);
                if (to_next <= 0) to_next = tab;
                std::string spaces(to_next, ' ');
                insert_text_at_caret(spaces);
                break_undo_coalescing();
            }
            ensure_caret_visible(editor_h, line_h);
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
                if (ch < 32) continue;
                std::string utf8;
                uint32_t cp = static_cast<uint32_t>(ch);
                if (cp < 0x80) {
                    utf8.push_back(static_cast<char>(cp));
                } else if (cp < 0x800) {
                    utf8.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    utf8.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x110000) {
                    utf8.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    continue;
                }

                char ascii = (cp < 0x80) ? static_cast<char>(cp) : 0;
                bool handled_bracket = false;

                if (editor_config::bracket_match && ascii != 0) {
                    const std::string& cl = line_at(s_sel.caret_line);
                    char next_ch = (s_sel.caret_col < static_cast<int>(cl.size()))
                                       ? cl[s_sel.caret_col] : 0;

                    if (is_close_bracket(ascii) && next_ch == ascii && !s_sel.has_selection()) {
                        s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col + 1;
                        s_sel.active = false;
                        handled_bracket = true;
                        break_undo_coalescing();
                    } else if (ascii == '"' && next_ch == '"' && !s_sel.has_selection()) {
                        s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col + 1;
                        s_sel.active = false;
                        handled_bracket = true;
                        break_undo_coalescing();
                    } else if (is_open_bracket(ascii) ||
                               (ascii == '"' &&
                                (next_ch == 0 || next_ch == ')' || next_ch == ']' ||
                                 next_ch == '}' || next_ch == ' ' || next_ch == '\t' ||
                                 next_ch == ','))) {
                        if (s_sel.has_selection()) {
                            std::string sel = get_selected_text();
                            char close = (ascii == '"') ? '"' : matching_close_bracket(ascii);
                            insert_text_at_caret(std::string(1, ascii) + sel + std::string(1, close));
                            break_undo_coalescing();
                        } else {
                            char close = (ascii == '"') ? '"' : matching_close_bracket(ascii);
                            insert_text_at_caret(std::string(1, ascii) + std::string(1, close));
                            s_sel.caret_col = s_sel.anchor_col = s_sel.caret_col - 1;
                            break_undo_coalescing();
                        }
                        handled_bracket = true;
                    }
                }

                if (!handled_bracket) {
                    int kind = 0;
                    if (ascii != 0) {
                        bool word = (ascii >= 'a' && ascii <= 'z') ||
                                    (ascii >= 'A' && ascii <= 'Z') ||
                                    (ascii >= '0' && ascii <= '9') || ascii == '_';
                        kind = word ? 1 : 2;
                    }
                    insert_text_at_caret(utf8, kind);
                    if (kind == 2) break_undo_coalescing();
                }
                ensure_caret_visible(editor_h, line_h);


                if (editor_config::auto_complete && autocomplete::enabled && ascii != 0) {
                    bool word_ch = (ascii >= 'a' && ascii <= 'z') ||
                                   (ascii >= 'A' && ascii <= 'Z') ||
                                   (ascii >= '0' && ascii <= '9') || ascii == '_';
                    if (word_ch) {
                        int cursor = s_sel.caret_col;
                        int ws = cursor;
                        auto& ln = s_cache.lines[s_sel.caret_line];
                        while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[ws-1])) || ln[ws-1] == '_'))
                            ws--;
                        if (cursor > ws) {
                            rebuild_autocomplete(ln.substr(ws, cursor - ws), s_sel.caret_line);
                            autocomplete::cursor_col = s_sel.caret_col;
                        } else {
                            autocomplete::popup_visible = false;
                            autocomplete::matches.clear();
                        }
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
                    break_undo_coalescing();
                    const std::string& chosen = autocomplete::matches[autocomplete::selected];
                    ln.erase(ws, cursor - ws);
                    ln.insert(ws, chosen);
                    s_sel.caret_col = s_sel.anchor_col = ws + static_cast<int>(chosen.size());
                    rebuild_buffer_from_lines();
                }
                autocomplete::popup_visible = false;
                autocomplete::matches.clear();
            }
        }
    }


    dl->PopClipRect();


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
        const int   total = static_cast<int>(autocomplete::matches.size());
        const int   max_visible = 8;
        const float popup_w = 280.f;
        const float ac_item_h = 24.f;
        const int   visible = std::min(total, max_visible);
        const float popup_h = visible * ac_item_h + 10.f;

        int sel = autocomplete::selected;
        if (sel < 0) sel = 0;
        if (sel >= total) sel = total - 1;
        autocomplete::selected = sel;
        int top = 0;
        if (sel >= max_visible) top = sel - max_visible + 1;
        if (top > total - visible) top = std::max(0, total - visible);

        float sx = ox + text_x0 + autocomplete::cursor_col * char_w - s_scroll_x;
        float sy = oy + (autocomplete::cursor_line + 1) * line_h - s_scroll_y + 4.f;
        if (sx + popup_w > ox + code_w) sx = ox + code_w - popup_w - 4.f;
        if (sx < ox + text_x0) sx = ox + text_x0;
        if (sy + popup_h > oy + editor_h)
            sy = oy + autocomplete::cursor_line * line_h - s_scroll_y - popup_h;

        ImDrawList* fdl = ImGui::GetForegroundDrawList();
        ImVec2 pmin(sx, sy);
        ImVec2 pmax(sx + popup_w, sy + popup_h);
        aida::ui::blur::render_drop_shadow(fdl, pmin, pmax, 10.f, 4, 0.40f, ImVec2(0.f, 4.f));
        aida::ui::blur::render_glass_fill(fdl, pmin, pmax, 10.f, a);
        aida::ui::blur::render_glass_border(fdl, pmin, pmax, 10.f, a, 1.f);

        std::string lower_pat = autocomplete::partial;
        for (auto& c : lower_pat) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

        const auto& kws = autocomplete::keywords();
        std::unordered_set<std::string> kw_set(kws.begin(), kws.end());

        int accepted_idx = -1;
        ImVec2 mp = ImGui::GetIO().MousePos;

        for (int row = 0; row < visible; ++row) {
            int mi = top + row;
            float iy = sy + 5.f + row * ac_item_h;
            float text_y = iy + (ac_item_h - ImGui::GetFontSize()) * 0.5f;
            const std::string& match = autocomplete::matches[mi];

            ImVec2 row_min(sx + 3.f, iy);
            ImVec2 row_max(sx + popup_w - 3.f, iy + ac_item_h);
            bool row_hov = (mp.x >= row_min.x && mp.x <= row_max.x &&
                            mp.y >= row_min.y && mp.y <= row_max.y);
            if (row_hov) autocomplete::selected = mi;

            if (mi == autocomplete::selected) {
                fdl->AddRectFilled(row_min, row_max,
                    aida::ui::with_alpha(th.accent_dim, 0.55f * a), 6.f);
                fdl->AddRectFilled(ImVec2(sx + 3.f, iy), ImVec2(sx + 5.f, iy + ac_item_h),
                    aida::ui::with_alpha(th.accent_u32, a), 1.f);
            } else if (row_hov) {
                fdl->AddRectFilled(row_min, row_max,
                    aida::ui::with_alpha(th.hover_wash, 1.4f * a), 6.f);
            }

            float tx = sx + 14.f;
            size_t pi = 0;
            for (size_t ci = 0; ci < match.size(); ++ci) {
                char glyph[2] = { match[ci], 0 };
                char lc = static_cast<char>(tolower(static_cast<unsigned char>(match[ci])));
                bool hit = (pi < lower_pat.size() && lc == lower_pat[pi]);
                ImU32 col = hit ? aida::ui::with_alpha(th.accent_u32, a)
                                : aida::ui::with_alpha(th.text_primary, 0.90f * a);
                if (hit) pi++;
                fdl->AddText(ImVec2(tx, text_y), col, glyph);
                tx += ImGui::CalcTextSize(glyph).x;
            }

            const char* kind = kw_set.count(match) ? "kw" : "id";
            ImU32 kind_col = kw_set.count(match)
                ? aida::ui::with_alpha(th.syn_keyword, 0.85f * a)
                : aida::ui::with_alpha(th.text_dim, 0.85f * a);
            float kw_w = ImGui::CalcTextSize(kind).x;
            fdl->AddText(ImVec2(sx + popup_w - 12.f - kw_w, text_y), kind_col, kind);

            if (row_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                accepted_idx = mi;
        }

        if (total > visible) {
            float track_x = sx + popup_w - 6.f;
            float track_y0 = sy + 5.f;
            float track_h = visible * ac_item_h;
            float thumb_h = std::max(16.f, track_h * static_cast<float>(visible) / total);
            float thumb_y = track_y0 +
                (track_h - thumb_h) * static_cast<float>(top) /
                std::max(1, total - visible);
            fdl->AddRectFilled(ImVec2(track_x, thumb_y),
                ImVec2(track_x + 3.f, thumb_y + thumb_h),
                aida::ui::with_alpha(th.text_secondary, 0.4f * a), 2.f);
        }

        if (accepted_idx >= 0 && accepted_idx < total) {
            int cursor = s_sel.caret_col;
            int ws = cursor;
            auto& ln = s_cache.lines[s_sel.caret_line];
            while (ws > 0 && (isalnum(static_cast<unsigned char>(ln[ws - 1])) || ln[ws - 1] == '_'))
                ws--;
            push_undo();
            break_undo_coalescing();
            const std::string& chosen = autocomplete::matches[accepted_idx];
            ln.erase(ws, cursor - ws);
            ln.insert(ws, chosen);
            s_sel.caret_col = s_sel.anchor_col = ws + static_cast<int>(chosen.size());
            rebuild_buffer_from_lines();
            autocomplete::popup_visible = false;
            autocomplete::matches.clear();
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
        const float bar_w       = 420.f;
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

        if (toggle_button("W", s_find.whole_word, "ww", "Whole Word")) {
            find_all_matches();
            if (!s_find.match_positions.empty()) {
                s_find.current_match = -1;
                find_next();
                ensure_caret_visible(editor_h, line_h);
            }
        }
        ImGui::SameLine();

        if (toggle_button(".*", s_find.use_regex, "rx", "Regular Expression")) {
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

    if (!word_wrap_on && s_max_scroll_x > 0.5f) {
        static bool  s_hsb_dragging = false;
        static float s_hsb_drag_offset = 0.f;

        const float sb_h   = h_scrollbar_h;
        const float sb_pad = 2.f;
        float track_x0 = ox + text_x0;
        float track_y  = oy + editor_h - sb_h - sb_pad;
        float track_w  = code_w - text_x0 - 14.f;
        if (track_w < 30.f) track_w = 30.f;

        float total_w   = s_max_scroll_x + track_w;
        float ratio     = track_w / total_w;
        float thumb_w   = std::max(28.f, track_w * ratio);
        float thumb_x   = track_x0 + (s_max_scroll_x > 0.f
            ? (s_scroll_x / s_max_scroll_x) * (track_w - thumb_w) : 0.f);

        bool hsb_hov = ImGui::IsMouseHoveringRect(
            ImVec2(track_x0, track_y - 3.f),
            ImVec2(track_x0 + track_w, track_y + sb_h + 3.f));

        ImGuiID hsb_id = ImGui::GetID("##code_hsb_hov");
        float hsb_a = ImGui::GetStateStorage()->GetFloat(hsb_id, 0.f);
        hsb_a = aida::motion::smooth_lerp(hsb_a, (hsb_hov || s_hsb_dragging) ? 1.f : 0.f, 14.f, dt);
        ImGui::GetStateStorage()->SetFloat(hsb_id, hsb_a);

        if (hsb_a > 0.01f) {
            dl->AddRectFilled(ImVec2(track_x0, track_y),
                ImVec2(track_x0 + track_w, track_y + sb_h),
                aida::ui::with_alpha(th.text_primary, 0.04f * hsb_a * a), 3.f);
            bool thumb_hov = ImGui::IsMouseHoveringRect(
                ImVec2(thumb_x, track_y - 2.f),
                ImVec2(thumb_x + thumb_w, track_y + sb_h + 2.f));
            ImU32 thumb_col = aida::ui::with_alpha(
                (thumb_hov || s_hsb_dragging) ? th.accent_u32 : th.text_secondary,
                (thumb_hov || s_hsb_dragging ? 0.55f : 0.30f) * hsb_a * a);
            dl->AddRectFilled(ImVec2(thumb_x, track_y),
                ImVec2(thumb_x + thumb_w, track_y + sb_h), thumb_col, 3.f);
        }

        if (hsb_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            float mx = ImGui::GetIO().MousePos.x;
            if (mx < thumb_x || mx > thumb_x + thumb_w) {
                float click_ratio = (mx - track_x0 - thumb_w * 0.5f) / (track_w - thumb_w);
                click_ratio = std::max(0.f, std::min(1.f, click_ratio));
                s_scroll_x = click_ratio * s_max_scroll_x;
            }
            s_hsb_dragging = true;
            s_hsb_drag_offset = ImGui::GetIO().MousePos.x - thumb_x;
        }
        if (s_hsb_dragging) {
            if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                float mx = ImGui::GetIO().MousePos.x - s_hsb_drag_offset;
                float drag_ratio = (track_w - thumb_w) > 0.f
                    ? (mx - track_x0) / (track_w - thumb_w) : 0.f;
                drag_ratio = std::max(0.f, std::min(1.f, drag_ratio));
                s_scroll_x = drag_ratio * s_max_scroll_x;
            } else {
                s_hsb_dragging = false;
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

    ImGui::SetWindowFontScale(prev_font_scale);
    if (code_font) ImGui::PopFont();
}
