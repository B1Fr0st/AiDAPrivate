#include "chat_render.hpp"
#include "ide_icons.h"
#include "motion.hpp"
#include "clock.hpp"
#include "transition.hpp"
#include "theme.hpp"
#include "blur_layer.hpp"
#include "brand.hpp"
#include "components.hpp"
#include "fonts.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdio>


namespace {

inline bool is_space_or_tab(char c) { return c == ' ' || c == '\t'; }
inline bool is_digit_ch(char c)     { return c >= '0' && c <= '9'; }

inline std::string strip_lr(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && is_space_or_tab(s[a])) ++a;
    while (b > a && is_space_or_tab(s[b - 1])) --b;
    return s.substr(a, b - a);
}

inline size_t leading_spaces(const std::string& line) {
    size_t i = 0;
    while (i < line.size() && line[i] == ' ') ++i;
    return i;
}

inline std::vector<std::string> split_pipe_row(const std::string& line) {
    std::vector<std::string> cells;
    std::string body = strip_lr(line);
    if (!body.empty() && body.front() == '|') body.erase(body.begin());
    if (!body.empty() && body.back() == '|') body.pop_back();
    std::string cur;
    bool escape = false;
    for (size_t i = 0; i < body.size(); ++i) {
        char c = body[i];
        if (escape) { cur += c; escape = false; continue; }
        if (c == '\\') { escape = true; continue; }
        if (c == '|') { cells.push_back(strip_lr(cur)); cur.clear(); continue; }
        cur += c;
    }
    cells.push_back(strip_lr(cur));
    return cells;
}

inline bool looks_like_table_separator(const std::string& line) {
    std::string t = strip_lr(line);
    if (t.empty() || t.find('|') == std::string::npos) return false;
    for (char c : t) {
        if (c != '|' && c != '-' && c != ':' && c != ' ' && c != '\t') return false;
    }
    return t.find('-') != std::string::npos;
}

inline bool is_hrule(const std::string& line) {
    std::string t = strip_lr(line);
    if (t.size() < 3) return false;
    char first = t.front();
    if (first != '-' && first != '*' && first != '_') return false;
    int count = 0;
    for (char c : t) {
        if (c == first) ++count;
        else if (c != ' ' && c != '\t') return false;
    }
    return count >= 3;
}


struct inline_emit_t {
    chat_render::span_type type;
    std::string text;
    std::string url;
};

void parse_inline(const std::string& src, std::vector<inline_emit_t>& out) {
    size_t i = 0;
    size_t n = src.size();
    std::string accum;

    auto flush = [&]() {
        if (!accum.empty()) {
            inline_emit_t e;
            e.type = chat_render::span_type::text;
            e.text = accum;
            out.push_back(std::move(e));
            accum.clear();
        }
    };

    while (i < n) {
        if (i + 2 < n && src[i] == '`') {
            size_t end = src.find('`', i + 1);
            if (end != std::string::npos && end > i + 1) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::inline_code;
                e.text = src.substr(i + 1, end - i - 1);
                out.push_back(std::move(e));
                i = end + 1;
                continue;
            }
        }

        if (i + 1 < n && src[i] == '`') {
            size_t end = src.find('`', i + 1);
            if (end != std::string::npos) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::inline_code;
                e.text = src.substr(i + 1, end - i - 1);
                out.push_back(std::move(e));
                i = end + 1;
                continue;
            }
        }

        if (i + 4 < n && src[i] == '*' && src[i + 1] == '*' && src[i + 2] == '*') {
            size_t end = src.find("***", i + 3);
            if (end != std::string::npos) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::bold_italic;
                e.text = src.substr(i + 3, end - i - 3);
                out.push_back(std::move(e));
                i = end + 3;
                continue;
            }
        }

        if (i + 3 < n && src[i] == '*' && src[i + 1] == '*') {
            size_t end = src.find("**", i + 2);
            if (end != std::string::npos && end > i + 2) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::bold;
                e.text = src.substr(i + 2, end - i - 2);
                out.push_back(std::move(e));
                i = end + 2;
                continue;
            }
        }

        if (i + 1 < n && src[i] == '*' && src[i + 1] != '*') {
            size_t end = src.find('*', i + 1);
            if (end != std::string::npos && end > i + 1 &&
                (end + 1 >= n || src[end + 1] != '*')) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::italic;
                e.text = src.substr(i + 1, end - i - 1);
                out.push_back(std::move(e));
                i = end + 1;
                continue;
            }
        }

        if (i + 3 < n && src[i] == '~' && src[i + 1] == '~') {
            size_t end = src.find("~~", i + 2);
            if (end != std::string::npos && end > i + 2) {
                flush();
                inline_emit_t e;
                e.type = chat_render::span_type::strikethrough;
                e.text = src.substr(i + 2, end - i - 2);
                out.push_back(std::move(e));
                i = end + 2;
                continue;
            }
        }

        if (src[i] == '[') {
            size_t close_label = src.find(']', i + 1);
            if (close_label != std::string::npos &&
                close_label + 1 < n && src[close_label + 1] == '(') {
                size_t close_url = src.find(')', close_label + 2);
                if (close_url != std::string::npos) {
                    flush();
                    inline_emit_t e;
                    e.type = chat_render::span_type::link;
                    e.text = src.substr(i + 1, close_label - i - 1);
                    e.url  = src.substr(close_label + 2, close_url - close_label - 2);
                    out.push_back(std::move(e));
                    i = close_url + 1;
                    continue;
                }
            }
        }

        accum += src[i++];
    }

    flush();
}

}


std::vector<chat_render::span_t> chat_render::parse_markdown(const std::string& text)
{
    std::vector<span_t> spans;
    if (text.empty()) return spans;

    auto push_inline_run = [&](const std::string& src) {
        std::vector<inline_emit_t> parts;
        parse_inline(src, parts);
        for (auto& p : parts) {
            span_t s;
            s.type = p.type;
            s.text = std::move(p.text);
            s.url  = std::move(p.url);
            spans.push_back(std::move(s));
        }
    };

    size_t i = 0;
    size_t n = text.size();

    while (i < n) {
        if (i + 2 < n && text[i] == '`' && text[i + 1] == '`' && text[i + 2] == '`') {
            i += 3;
            std::string lang;
            while (i < n && text[i] != '\n' && text[i] != '\r') lang += text[i++];
            if (i < n && text[i] == '\r') ++i;
            if (i < n && text[i] == '\n') ++i;
            std::string code;
            while (i < n) {
                if (i + 2 < n && text[i] == '`' && text[i + 1] == '`' && text[i + 2] == '`') {
                    i += 3;
                    if (i < n && text[i] == '\r') ++i;
                    if (i < n && text[i] == '\n') ++i;
                    break;
                }
                code += text[i++];
            }
            while (!code.empty() && (code.back() == '\n' || code.back() == '\r')) code.pop_back();
            std::string trimmed_lang = strip_lr(lang);
            span_t s;
            s.type = span_type::code_block;
            s.text = std::move(code);
            s.language = std::move(trimmed_lang);
            spans.push_back(std::move(s));
            continue;
        }

        if (i + 10 < n && text.compare(i, 11, "<tool_call>") == 0) {
            i += 11;
            size_t end = text.find("</tool_call>", i);
            std::string content;
            if (end != std::string::npos) { content = text.substr(i, end - i); i = end + 12; }
            else { content = text.substr(i); i = n; }
            span_t s; s.type = span_type::tool_call; s.text = std::move(content);
            spans.push_back(std::move(s));
            continue;
        }

        if (i + 12 < n && text.compare(i, 13, "<tool_result>") == 0) {
            i += 13;
            size_t end = text.find("</tool_result>", i);
            std::string content;
            if (end != std::string::npos) { content = text.substr(i, end - i); i = end + 14; }
            else { content = text.substr(i); i = n; }
            span_t s; s.type = span_type::tool_result; s.text = std::move(content);
            spans.push_back(std::move(s));
            continue;
        }

        size_t line_start = i;
        size_t line_end = line_start;
        while (line_end < n && text[line_end] != '\n' && text[line_end] != '\r') ++line_end;
        std::string line = text.substr(line_start, line_end - line_start);
        size_t consumed_to = line_end;
        if (consumed_to < n && text[consumed_to] == '\r') ++consumed_to;
        if (consumed_to < n && text[consumed_to] == '\n') ++consumed_to;

        std::string trimmed = strip_lr(line);

        if (trimmed.empty()) {
            span_t s; s.type = span_type::paragraph_break; s.text = "";
            if (spans.empty() || spans.back().type != span_type::paragraph_break)
                spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }

        if (is_hrule(line)) {
            span_t s; s.type = span_type::hrule; s.text = "";
            spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }

        if (!trimmed.empty() && trimmed.front() == '#') {
            size_t h = 0;
            while (h < trimmed.size() && trimmed[h] == '#' && h < 6) ++h;
            if (h >= 1 && h <= 3 && h < trimmed.size() && trimmed[h] == ' ') {
                std::string body = strip_lr(trimmed.substr(h + 1));
                span_t s;
                if (h == 1)      s.type = span_type::heading1;
                else if (h == 2) s.type = span_type::heading2;
                else             s.type = span_type::heading3;
                s.depth = (int)h;
                s.text = body;
                spans.push_back(std::move(s));
                i = consumed_to;
                continue;
            }
        }

        if (!trimmed.empty() && trimmed.front() == '>') {
            std::string body = trimmed.size() > 1 ? trimmed.substr(1) : std::string();
            if (!body.empty() && body.front() == ' ') body.erase(body.begin());
            span_t s; s.type = span_type::blockquote; s.text = body;
            spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }

        if (trimmed.size() >= 6 &&
            (trimmed.compare(0, 6, "- [ ] ") == 0 || trimmed.compare(0, 6, "* [ ] ") == 0)) {
            span_t s; s.type = span_type::task_unchecked;
            s.text = trimmed.substr(6);
            s.list_indent = (int)(leading_spaces(line) / 2);
            spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }
        if (trimmed.size() >= 6 &&
            (trimmed.compare(0, 6, "- [x] ") == 0 || trimmed.compare(0, 6, "- [X] ") == 0 ||
             trimmed.compare(0, 6, "* [x] ") == 0 || trimmed.compare(0, 6, "* [X] ") == 0)) {
            span_t s; s.type = span_type::task_checked;
            s.text = trimmed.substr(6);
            s.list_indent = (int)(leading_spaces(line) / 2);
            spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }

        if (trimmed.size() >= 2 &&
            (trimmed[0] == '-' || trimmed[0] == '*' || trimmed[0] == '+') &&
            trimmed[1] == ' ') {
            span_t s; s.type = span_type::list_bullet;
            s.text = trimmed.substr(2);
            s.list_indent = (int)(leading_spaces(line) / 2);
            spans.push_back(std::move(s));
            i = consumed_to;
            continue;
        }

        {
            size_t p = 0;
            while (p < trimmed.size() && is_digit_ch(trimmed[p])) ++p;
            if (p > 0 && p < trimmed.size() && (trimmed[p] == '.' || trimmed[p] == ')') &&
                p + 1 < trimmed.size() && trimmed[p + 1] == ' ') {
                int idx = 0;
                for (size_t k = 0; k < p; ++k) idx = idx * 10 + (trimmed[k] - '0');
                span_t s; s.type = span_type::list_numbered;
                s.list_index = idx;
                s.text = trimmed.substr(p + 2);
                s.list_indent = (int)(leading_spaces(line) / 2);
                spans.push_back(std::move(s));
                i = consumed_to;
                continue;
            }
        }

        if (trimmed.find('|') != std::string::npos) {
            size_t scan = consumed_to;
            size_t scan_end = scan;
            while (scan_end < n && text[scan_end] != '\n' && text[scan_end] != '\r') ++scan_end;
            std::string maybe_sep = text.substr(scan, scan_end - scan);
            if (looks_like_table_separator(maybe_sep)) {
                span_t s; s.type = span_type::table;
                s.table_data.push_back(split_pipe_row(line));
                size_t nxt = scan_end;
                if (nxt < n && text[nxt] == '\r') ++nxt;
                if (nxt < n && text[nxt] == '\n') ++nxt;
                while (nxt < n) {
                    size_t row_end = nxt;
                    while (row_end < n && text[row_end] != '\n' && text[row_end] != '\r') ++row_end;
                    std::string row_line = text.substr(nxt, row_end - nxt);
                    std::string row_trim = strip_lr(row_line);
                    if (row_trim.empty() || row_trim.find('|') == std::string::npos) break;
                    s.table_data.push_back(split_pipe_row(row_line));
                    nxt = row_end;
                    if (nxt < n && text[nxt] == '\r') ++nxt;
                    if (nxt < n && text[nxt] == '\n') ++nxt;
                }
                spans.push_back(std::move(s));
                i = nxt;
                continue;
            }
        }

        push_inline_run(line);
        if (consumed_to < n) {
            span_t br; br.type = span_type::text; br.text = "\n";
            spans.push_back(std::move(br));
        }
        i = consumed_to;
    }

    return spans;
}


static syntax::language_def_t get_lang_def(const std::string& lang)
{
    if (lang.empty() || lang == "cpp" || lang == "c++" || lang == "c" || lang == "h" || lang == "hpp")
        return syntax::lang_cpp();
    if (lang == "asm" || lang == "assembly" || lang == "x86" || lang == "nasm" || lang == "masm")
        return syntax::lang_asm();
    if (lang == "python" || lang == "py")
        return syntax::lang_python();
    if (lang == "json")
        return syntax::lang_json();
    if (lang == "lua")
        return syntax::lang_lua();
    return syntax::lang_cpp();
}


struct code_token_pal_t {
    ImU32 keyword;
    ImU32 type_name;
    ImU32 string_lit;
    ImU32 number;
    ImU32 comment;
    ImU32 preproc;
    ImU32 op_sym;
    ImU32 func_call;
    ImU32 ident;
    ImU32 punct;
    ImU32 decorator;
    ImU32 boolean_lit;
    ImU32 reg_name;
    ImU32 directive;
};

static code_token_pal_t make_themed_token_palette(float alpha)
{
    const auto& th = aida::ui::resolved();
    code_token_pal_t p;
    p.keyword     = aida::ui::with_alpha(th.syn_keyword,      alpha);
    p.type_name   = aida::ui::with_alpha(th.syn_type,         alpha);
    p.string_lit  = aida::ui::with_alpha(th.syn_string,       alpha);
    p.number      = aida::ui::with_alpha(th.syn_number,       alpha);
    p.comment     = aida::ui::with_alpha(th.syn_comment,      alpha);
    p.preproc     = aida::ui::with_alpha(th.syn_preprocessor, alpha);
    p.op_sym      = aida::ui::with_alpha(th.syn_operator,     alpha);
    p.func_call   = aida::ui::with_alpha(th.syn_function,     alpha);
    p.ident       = aida::ui::with_alpha(th.syn_identifier,   alpha);
    p.punct       = aida::ui::with_alpha(th.syn_operator,     alpha * 0.85f);
    p.decorator   = aida::ui::with_alpha(th.syn_keyword,      alpha);
    p.boolean_lit = aida::ui::with_alpha(th.syn_number,       alpha);
    p.reg_name    = aida::ui::with_alpha(th.syn_register,     alpha);
    p.directive   = aida::ui::with_alpha(th.syn_keyword,      alpha);
    return p;
}

static ImU32 token_color_for(syntax::token_type tt, const code_token_pal_t& p)
{
    switch (tt) {
    case syntax::token_type::keyword:        return p.keyword;
    case syntax::token_type::type_name:      return p.type_name;
    case syntax::token_type::string_lit:     return p.string_lit;
    case syntax::token_type::number:         return p.number;
    case syntax::token_type::comment_line:   return p.comment;
    case syntax::token_type::comment_block:  return p.comment;
    case syntax::token_type::preprocessor:   return p.preproc;
    case syntax::token_type::operator_sym:   return p.op_sym;
    case syntax::token_type::function_call:  return p.func_call;
    case syntax::token_type::identifier:     return p.ident;
    case syntax::token_type::punctuation:    return p.punct;
    case syntax::token_type::decorator:      return p.decorator;
    case syntax::token_type::boolean_lit:    return p.boolean_lit;
    case syntax::token_type::register_name:  return p.reg_name;
    case syntax::token_type::directive:      return p.directive;
    default:                                  return p.ident;
    }
}


float chat_render::render_code_block(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::string& code,
    const std::string& language,
    float       alpha,
    float       accent_r,
    float       accent_g,
    float       accent_b)
{
    if (code.empty()) return 0.f;

    const auto& th = aida::ui::resolved();
    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
    float code_fs = code_font->FontSize;
    if (code_fs <= 0.f) code_fs = ImGui::GetFontSize();

    float pad      = 12.f;
    float header_h = 32.f;
    float line_h   = code_fs + 4.f;

    int line_count = 1;
    for (char ch : code) if (ch == '\n') ++line_count;

    float code_h  = (float)line_count * line_h + pad;
    float total_h = header_h + code_h + pad * 0.5f;
    float block_w = max_w;

    ImVec2 bmin = origin;
    ImVec2 bmax(origin.x + block_w, origin.y + total_h);

    aida::ui::blur::render_drop_shadow(dl, bmin, bmax, 10.f, 3, 0.22f, ImVec2(0.f, 3.f));
    ImU32 fill = aida::ui::with_alpha(aida::ui::darken(th.bg_elevated, th.is_dark ? 6 : 0), alpha * 0.95f);
    dl->AddRectFilled(bmin, bmax, fill, 10.f);
    dl->AddRect(bmin, bmax, aida::ui::with_alpha(th.border_subtle, alpha), 10.f, 0, 1.f);

    ImVec2 hmin = bmin;
    ImVec2 hmax(bmin.x + block_w, bmin.y + header_h);

    ImU32 head_top = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_top, 0.10f), alpha * 0.95f);
    ImU32 head_bot = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_bot, 0.04f), alpha * 0.95f);
    dl->AddRectFilledMultiColor(hmin, hmax, head_top, head_top, head_bot, head_bot);
    dl->AddLine(ImVec2(hmin.x, hmax.y), ImVec2(hmax.x, hmax.y),
                aida::ui::with_alpha(th.border_subtle, alpha), 1.f);

    std::string lang_label = language.empty() ? "code" : language;
    for (char& c : lang_label) c = (char)tolower((unsigned char)c);

    ImFont* ui_font = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
    float lang_fs = 11.f;

    ImVec2 lts = ui_font->CalcTextSizeA(lang_fs, FLT_MAX, 0.f, lang_label.c_str());
    float lang_pill_w = lts.x + 16.f;
    float lang_pill_h = 18.f;
    ImVec2 lpmin(hmin.x + 10.f, hmin.y + (header_h - lang_pill_h) * 0.5f);
    ImVec2 lpmax(lpmin.x + lang_pill_w, lpmin.y + lang_pill_h);

    ImU32 lang_pill_fill = aida::ui::with_alpha(th.accent_grad_top, alpha * 0.20f);
    ImU32 lang_pill_brd  = aida::ui::with_alpha(th.accent_dim, alpha * 0.85f);
    dl->AddRectFilled(lpmin, lpmax, lang_pill_fill, lang_pill_h * 0.5f);
    dl->AddRect(lpmin, lpmax, lang_pill_brd, lang_pill_h * 0.5f, 0, 1.f);
    dl->AddText(ui_font, lang_fs,
                ImVec2(lpmin.x + 8.f, lpmin.y + (lang_pill_h - lang_fs) * 0.5f),
                aida::ui::with_alpha(th.accent_u32, alpha), lang_label.c_str());

    const char* copy_label = ICON_COPY;
    ImFont* icon_font = ImGui::GetFont();
    float icon_fs = 14.f;
    ImVec2 cts = icon_font->CalcTextSizeA(icon_fs, FLT_MAX, 0.f, copy_label);
    float copy_btn_w = cts.x + 16.f;
    float copy_btn_h = 22.f;
    ImVec2 cmin(hmax.x - copy_btn_w - 10.f, hmin.y + (header_h - copy_btn_h) * 0.5f);
    ImVec2 cmax(cmin.x + copy_btn_w, cmin.y + copy_btn_h);

    ImGui::PushID((int)((intptr_t)code.data() & 0x7FFFFFFF));
    ImGuiID copy_id = ImGui::GetID("##cb_copy");
    ImGui::SetCursorScreenPos(cmin);
    ImGui::InvisibleButton("##cb_copy_btn", ImVec2(copy_btn_w, copy_btn_h));
    bool copy_hov = ImGui::IsItemHovered();
    bool copy_clk = ImGui::IsItemClicked();

    auto& cb_st = aida::ui::components::detail::bstate(copy_id);
    float chov  = cb_st.hover.tick(copy_hov, aida::ui::clock::dt());
    float cflash = cb_st.flash.tick(aida::ui::clock::dt(), 2.5f);
    if (copy_clk) { cb_st.flash.trigger(); ImGui::SetClipboardText(code.c_str()); }
    ImGui::PopID();

    ImU32 copy_fill = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_top, chov * 0.45f), alpha);
    ImU32 copy_brd  = aida::ui::with_alpha(aida::ui::mix(th.border_subtle, th.accent_hover, chov), alpha);
    dl->AddRectFilled(cmin, cmax, copy_fill, copy_btn_h * 0.5f);
    dl->AddRect(cmin, cmax, copy_brd, copy_btn_h * 0.5f, 0, 1.f);
    if (cflash > 0.001f) {
        dl->AddRectFilled(cmin, cmax,
            aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), cflash * 0.18f * alpha),
            copy_btn_h * 0.5f);
    }

    ImU32 copy_text_col = aida::ui::with_alpha(
        aida::ui::mix(th.text_secondary, th.accent_u32, chov), alpha);
    dl->AddText(icon_font, icon_fs,
                ImVec2(cmin.x + (copy_btn_w - cts.x) * 0.5f, cmin.y + (copy_btn_h - icon_fs) * 0.5f),
                copy_text_col, copy_label);

    if (cflash > 0.001f) {
        aida::ui::brand::render_check_drawn(dl,
            ImVec2(cmin.x + copy_btn_w * 0.5f, cmin.y + copy_btn_h * 0.5f),
            10.f, 1.f - cflash,
            aida::ui::with_alpha(th.success, alpha), 1.8f);
    }

    auto lang_def = get_lang_def(language);
    std::vector<syntax::token_t> tokens;
    syntax::tokenize(code, lang_def, tokens);
    code_token_pal_t pal = make_themed_token_palette(alpha);

    char gutter_max[12];
    snprintf(gutter_max, sizeof(gutter_max), "%d", line_count);
    ImVec2 gmsz = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, gutter_max);
    float gutter_w = gmsz.x + 18.f;

    ImU32 gutter_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.55f);
    dl->AddRectFilled(
        ImVec2(bmin.x, hmax.y),
        ImVec2(bmin.x + gutter_w, bmax.y),
        gutter_bg, 0.f);
    dl->AddLine(
        ImVec2(bmin.x + gutter_w, hmax.y + 1.f),
        ImVec2(bmin.x + gutter_w, bmax.y - 1.f),
        aida::ui::with_alpha(th.border_subtle, alpha), 1.f);

    float code_origin_x = bmin.x + gutter_w + 8.f;
    float code_origin_y = hmax.y + pad * 0.5f;
    float cy = code_origin_y;

    auto draw_gutter_for_line = [&](int line_num) {
        char buf[12];
        snprintf(buf, sizeof(buf), "%d", line_num);
        ImVec2 sz = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, buf);
        ImU32 col = aida::ui::with_alpha(th.text_lineno, alpha);
        dl->AddText(code_font, code_fs,
            ImVec2(bmin.x + gutter_w - sz.x - 8.f, cy),
            col, buf);
    };

    int line_num = 1;
    draw_gutter_for_line(line_num);

    float text_x = code_origin_x;
    for (size_t ti = 0; ti < tokens.size(); ++ti) {
        const auto& tok = tokens[ti];
        ImU32 col = token_color_for(tok.type, pal);
        const char* span_start = code.data() + tok.start;
        size_t span_len = tok.length;

        size_t k = 0;
        while (k < span_len) {
            char ch = span_start[k];
            if (ch == '\n') {
                cy += line_h;
                text_x = code_origin_x;
                ++line_num;
                draw_gutter_for_line(line_num);
                ++k;
                continue;
            }
            if (ch == '\t') {
                ImVec2 tab_sz = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, "    ");
                text_x += tab_sz.x;
                ++k;
                continue;
            }
            size_t run_end = k;
            while (run_end < span_len && span_start[run_end] != '\n' && span_start[run_end] != '\t')
                ++run_end;
            ImVec2 run_sz = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f,
                span_start + k, span_start + run_end);
            dl->AddText(code_font, code_fs, ImVec2(text_x, cy), col,
                span_start + k, span_start + run_end);
            text_x += run_sz.x;
            k = run_end;
        }
    }

    (void)accent_r; (void)accent_g; (void)accent_b;
    return total_h;
}


static float draw_inline_words(
    ImDrawList* dl,
    ImFont*     font,
    float       font_size,
    const std::string& txt,
    ImU32       color,
    float&      cursor_x,
    float&      cursor_y,
    float       base_x,
    float       wrap_w,
    float       line_h,
    bool        underline = false,
    bool        strike    = false,
    ImU32       deco_color = 0)
{
    const char* p   = txt.c_str();
    const char* end = p + txt.size();
    ImVec2 space_ts = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, " ");
    float space_w = space_ts.x;

    while (p < end) {
        if (*p == '\n') {
            cursor_y += line_h;
            cursor_x = base_x;
            ++p;
            continue;
        }
        if (*p == '\r') { ++p; continue; }
        if (*p == ' ') {
            if (cursor_x > base_x) cursor_x += space_w;
            ++p;
            continue;
        }

        const char* word_start = p;
        while (p < end && *p != ' ' && *p != '\n' && *p != '\r') ++p;

        ImVec2 ws = font->CalcTextSizeA(font_size, FLT_MAX, 0.f, word_start, p);
        float remaining = (base_x + wrap_w) - cursor_x;
        if (ws.x > remaining && cursor_x > base_x) {
            cursor_y += line_h;
            cursor_x = base_x;
        }

        dl->AddText(font, font_size, ImVec2(cursor_x, cursor_y), color, word_start, p);

        if (underline) {
            float uy = cursor_y + font_size + 1.f;
            ImU32 uc = deco_color ? deco_color : color;
            dl->AddLine(ImVec2(cursor_x, uy), ImVec2(cursor_x + ws.x, uy), uc, 1.f);
        }
        if (strike) {
            float sy = cursor_y + font_size * 0.55f;
            ImU32 sc = deco_color ? deco_color : color;
            dl->AddLine(ImVec2(cursor_x, sy), ImVec2(cursor_x + ws.x, sy), sc, 1.2f);
        }

        cursor_x += ws.x;
    }
    return cursor_y;
}


static float render_table_block(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::vector<std::vector<std::string>>& rows,
    float       alpha)
{
    if (rows.empty()) return 0.f;

    const auto& th = aida::ui::resolved();
    ImFont* font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
    ImFont* head_font = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : font;
    float fs = font->FontSize;
    if (fs <= 0.f) fs = ImGui::GetFontSize();

    size_t col_count = 0;
    for (auto& r : rows) col_count = std::max(col_count, r.size());
    if (col_count == 0) return 0.f;

    std::vector<float> col_w(col_count, 0.f);
    for (auto& r : rows) {
        for (size_t c = 0; c < r.size(); ++c) {
            ImVec2 ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, r[c].c_str());
            if (ts.x > col_w[c]) col_w[c] = ts.x;
        }
    }

    float total_natural = 0.f;
    for (float w : col_w) total_natural += w;
    float pad_x = 14.f;
    float total_padded = total_natural + (float)col_count * pad_x * 2.f;
    float scale = total_padded > max_w ? (max_w - (float)col_count * pad_x * 2.f) / total_natural : 1.f;
    if (scale < 0.4f) scale = 0.4f;
    for (size_t c = 0; c < col_count; ++c) col_w[c] *= scale;

    float row_h = fs + 14.f;
    float total_h = row_h * (float)rows.size() + 2.f;

    ImVec2 bmin = origin;
    ImVec2 bmax(origin.x + max_w, origin.y + total_h);

    ImU32 head_fill = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_top, 0.06f), alpha);
    ImU32 row_fill_a = aida::ui::with_alpha(th.panel_bg, alpha * 0.55f);
    ImU32 row_fill_b = aida::ui::with_alpha(aida::ui::lighten(th.panel_bg, th.is_dark ? 6 : -4), alpha * 0.55f);
    ImU32 brd = aida::ui::with_alpha(th.border_subtle, alpha);

    dl->AddRectFilled(bmin, bmax, row_fill_a, 8.f);
    dl->AddRect(bmin, bmax, brd, 8.f, 0, 1.f);

    ImVec2 hd_a = bmin;
    ImVec2 hd_b(bmax.x, bmin.y + row_h);
    dl->AddRectFilledMultiColor(hd_a, hd_b, head_fill, head_fill,
        aida::ui::with_alpha(th.panel_header, alpha), aida::ui::with_alpha(th.panel_header, alpha));
    dl->AddLine(ImVec2(hd_a.x, hd_b.y), ImVec2(hd_b.x, hd_b.y), brd, 1.f);

    for (size_t ri = 0; ri < rows.size(); ++ri) {
        float y = bmin.y + (float)ri * row_h;
        if (ri > 0 && (ri & 1)) {
            dl->AddRectFilled(ImVec2(bmin.x + 1.f, y),
                              ImVec2(bmax.x - 1.f, y + row_h),
                              row_fill_b, 0.f);
        }

        float x = bmin.x + pad_x;
        const auto& row = rows[ri];
        for (size_t c = 0; c < col_count; ++c) {
            std::string cell = c < row.size() ? row[c] : std::string();
            ImFont* cf = ri == 0 ? head_font : font;
            ImU32 col = ri == 0
                ? aida::ui::with_alpha(th.text_primary, alpha)
                : aida::ui::with_alpha(th.text_secondary, alpha);
            dl->AddText(cf, fs, ImVec2(x, y + (row_h - fs) * 0.5f), col, cell.c_str());
            x += col_w[c] + pad_x * 2.f;
            if (c + 1 < col_count) {
                dl->AddLine(ImVec2(x - pad_x, y + 4.f), ImVec2(x - pad_x, y + row_h - 4.f),
                    aida::ui::with_alpha(th.border_subtle, alpha * 0.6f), 1.f);
            }
        }

        if (ri + 1 < rows.size()) {
            dl->AddLine(ImVec2(bmin.x + 8.f, y + row_h),
                        ImVec2(bmax.x - 8.f, y + row_h),
                        aida::ui::with_alpha(th.border_subtle, alpha * 0.5f), 1.f);
        }
    }

    return total_h;
}


static void try_extract_tool_name(const std::string& payload, std::string& out_name)
{
    out_name.clear();
    size_t name_pos = payload.find("\"name\"");
    if (name_pos == std::string::npos) return;
    size_t q1 = payload.find('"', name_pos + 6);
    if (q1 == std::string::npos) return;
    ++q1;
    size_t q2 = payload.find('"', q1);
    if (q2 == std::string::npos) return;
    out_name = payload.substr(q1, q2 - q1);
}


static float render_tool_call_card(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::string& payload,
    float       alpha,
    int         msg_idx,
    int         span_idx,
    float       dt)
{
    const auto& th = aida::ui::resolved();
    ImFont* ui_font = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
    float fs = 12.f;

    std::string tool_name;
    try_extract_tool_name(payload, tool_name);
    if (tool_name.empty()) tool_name = "tool";

    char id_buf[64];
    snprintf(id_buf, sizeof(id_buf), "tcc_%d_%d", msg_idx, span_idx);
    ImGuiID col_id = ImGui::GetID(id_buf);
    ImGuiStorage* storage = ImGui::GetStateStorage();
    bool collapsed = storage->GetBool(col_id, true);

    char ah_buf[64]; snprintf(ah_buf, sizeof(ah_buf), "tcc_h_%d_%d", msg_idx, span_idx);
    ImGuiID anim_id = ImGui::GetID(ah_buf);
    char av_buf[64]; snprintf(av_buf, sizeof(av_buf), "tcc_v_%d_%d", msg_idx, span_idx);
    ImGuiID vel_id = ImGui::GetID(av_buf);

    float header_h = 30.f;
    float body_pad = 12.f;

    auto json_def = syntax::lang_json();
    std::vector<syntax::token_t> jt;
    syntax::tokenize(payload, json_def, jt);

    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
    float code_fs = code_font->FontSize > 0.f ? code_font->FontSize : ImGui::GetFontSize();
    int line_count = 1;
    for (char c : payload) if (c == '\n') ++line_count;
    float code_line_h = code_fs + 4.f;
    float full_body_h = (float)line_count * code_line_h + body_pad * 2.f;
    if (full_body_h > 360.f) full_body_h = 360.f;

    float target_h = collapsed ? header_h : (header_h + full_body_h);
    float current_h = storage->GetFloat(anim_id, target_h);
    float current_v = storage->GetFloat(vel_id, 0.f);
    current_h = aida::motion::spring_step(current_h, target_h, current_v,
                                           aida::motion::spring::balanced, dt);
    storage->SetFloat(anim_id, current_h);
    storage->SetFloat(vel_id, current_v);

    ImVec2 a = origin;
    ImVec2 b(origin.x + max_w, origin.y + current_h);

    aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 3, 0.18f, ImVec2(0.f, 2.f));
    ImU32 fill = aida::ui::with_alpha(th.panel_bg, alpha * 0.94f);
    dl->AddRectFilled(a, b, fill, 12.f);
    dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 12.f, 0, 1.f);

    dl->AddRectFilled(a, ImVec2(a.x + 2.f, b.y),
        aida::ui::with_alpha(th.warning, alpha * 0.85f), 1.f);

    ImVec2 ha = a;
    ImVec2 hb(b.x, a.y + header_h);

    ImVec2 status_center(ha.x + 18.f, ha.y + header_h * 0.5f);
    aida::ui::components::status_dot(status_center, 4.5f,
        aida::ui::with_alpha(th.warning, alpha), true, 1.4f);

    char chev_buf[8];
    if (collapsed) std::strcpy(chev_buf, "\xe2\x96\xb6");
    else           std::strcpy(chev_buf, "\xe2\x96\xbc");
    ImFont* chev_font = ImGui::GetFont();
    ImVec2 chsz = chev_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, chev_buf);
    dl->AddText(chev_font, 11.f,
        ImVec2(ha.x + 32.f, ha.y + (header_h - chsz.y) * 0.5f),
        aida::ui::with_alpha(th.text_secondary, alpha), chev_buf);

    std::string label = std::string("\xe2\x9a\x99 ") + tool_name;
    dl->AddText(ui_font, fs,
        ImVec2(ha.x + 50.f, ha.y + (header_h - fs) * 0.5f),
        aida::ui::with_alpha(th.text_primary, alpha), label.c_str());

    {
        const char* args_label = "args";
        ImFont* tag_font = aida::ui::fonts::caption() ? aida::ui::fonts::caption() : ImGui::GetFont();
        float tag_fs = 10.f;
        ImVec2 ts = tag_font->CalcTextSizeA(tag_fs, FLT_MAX, 0.f, args_label);
        float pill_w = ts.x + 14.f;
        float pill_h = 16.f;
        ImVec2 pa(hb.x - pill_w - 12.f, ha.y + (header_h - pill_h) * 0.5f);
        ImVec2 pb(pa.x + pill_w, pa.y + pill_h);
        dl->AddRectFilled(pa, pb, aida::ui::with_alpha(th.accent_grad_top, alpha * 0.18f), pill_h * 0.5f);
        dl->AddRect(pa, pb, aida::ui::with_alpha(th.accent_dim, alpha * 0.7f), pill_h * 0.5f, 0, 1.f);
        dl->AddText(tag_font, tag_fs,
            ImVec2(pa.x + 7.f, pa.y + (pill_h - tag_fs) * 0.5f),
            aida::ui::with_alpha(th.accent_u32, alpha), args_label);
    }

    bool hov_header = ImGui::IsMouseHoveringRect(ha, hb);
    if (hov_header) {
        dl->AddRectFilled(ha, hb,
            aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), alpha * 0.04f),
            12.f, ImDrawFlags_RoundCornersTop);
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            storage->SetBool(col_id, !collapsed);
        }
    }

    if (current_h > header_h + 4.f) {
        ImVec2 body_clip_a(a.x + 1.f, hb.y);
        ImVec2 body_clip_b(b.x - 1.f, b.y - 1.f);
        dl->PushClipRect(body_clip_a, body_clip_b, true);

        code_token_pal_t pal = make_themed_token_palette(alpha);
        float text_x = a.x + body_pad;
        float text_y = hb.y + body_pad;

        for (size_t ti = 0; ti < jt.size(); ++ti) {
            const auto& tok = jt[ti];
            ImU32 col = token_color_for(tok.type, pal);
            const char* sp = payload.data() + tok.start;
            size_t sl = tok.length;
            size_t k = 0;
            while (k < sl) {
                char ch = sp[k];
                if (ch == '\n') {
                    text_y += code_line_h;
                    text_x = a.x + body_pad;
                    ++k; continue;
                }
                if (ch == '\t') {
                    ImVec2 tabsz = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, "  ");
                    text_x += tabsz.x; ++k; continue;
                }
                size_t re = k;
                while (re < sl && sp[re] != '\n' && sp[re] != '\t') ++re;
                ImVec2 rs = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, sp + k, sp + re);
                dl->AddText(code_font, code_fs, ImVec2(text_x, text_y), col, sp + k, sp + re);
                text_x += rs.x;
                k = re;
            }
        }
        dl->PopClipRect();
    }

    return current_h;
}


static float render_tool_result_card(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::string& payload,
    float       alpha,
    int         msg_idx,
    int         span_idx,
    float       dt)
{
    const auto& th = aida::ui::resolved();
    ImFont* ui_font = aida::ui::fonts::body_strong() ? aida::ui::fonts::body_strong() : ImGui::GetFont();
    ImFont* code_font = aida::ui::fonts::code() ? aida::ui::fonts::code() : ImGui::GetFont();
    float code_fs = code_font->FontSize > 0.f ? code_font->FontSize : ImGui::GetFontSize();
    float fs = 12.f;

    std::string display = payload;
    bool truncated = display.size() > 500;
    if (truncated) display = display.substr(0, 500) + "\n... (truncated)";

    char ck_buf[64]; snprintf(ck_buf, sizeof(ck_buf), "trc_%d_%d", msg_idx, span_idx);
    ImGuiID col_id = ImGui::GetID(ck_buf);
    ImGuiStorage* storage = ImGui::GetStateStorage();
    bool collapsed = storage->GetBool(col_id, true);

    char ch_buf[64]; snprintf(ch_buf, sizeof(ch_buf), "trc_h_%d_%d", msg_idx, span_idx);
    ImGuiID anim_id = ImGui::GetID(ch_buf);
    char cv_buf[64]; snprintf(cv_buf, sizeof(cv_buf), "trc_v_%d_%d", msg_idx, span_idx);
    ImGuiID vel_id = ImGui::GetID(cv_buf);

    float header_h = 32.f;
    float body_pad = 12.f;
    ImVec2 wrap_sz = code_font->CalcTextSizeA(code_fs, max_w - body_pad * 2.f, max_w - body_pad * 2.f, display.c_str());
    float full_body_h = wrap_sz.y + body_pad * 2.f;
    if (full_body_h > 380.f) full_body_h = 380.f;

    float target_h = collapsed ? header_h : (header_h + full_body_h);
    float current_h = storage->GetFloat(anim_id, target_h);
    float current_v = storage->GetFloat(vel_id, 0.f);
    current_h = aida::motion::spring_step(current_h, target_h, current_v,
                                           aida::motion::spring::balanced, dt);
    storage->SetFloat(anim_id, current_h);
    storage->SetFloat(vel_id, current_v);

    ImVec2 a = origin;
    ImVec2 b(origin.x + max_w, origin.y + current_h);

    aida::ui::blur::render_drop_shadow(dl, a, b, 12.f, 3, 0.20f, ImVec2(0.f, 3.f));
    ImU32 fill = aida::ui::with_alpha(th.panel_bg, alpha * 0.94f);
    dl->AddRectFilled(a, b, fill, 12.f);
    dl->AddRect(a, b, aida::ui::with_alpha(th.border_subtle, alpha), 12.f, 0, 1.f);

    ImVec2 ha = a;
    ImVec2 hb(b.x, a.y + header_h);
    ImU32 grad_top = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.success, 0.18f), alpha * 0.95f);
    ImU32 grad_bot = aida::ui::with_alpha(th.panel_header, alpha * 0.95f);
    dl->AddRectFilledMultiColor(ha, hb, grad_top, grad_top, grad_bot, grad_bot);
    dl->AddLine(ImVec2(ha.x, hb.y), ImVec2(hb.x, hb.y),
        aida::ui::with_alpha(th.border_subtle, alpha), 1.f);

    ImVec2 status_c(ha.x + 16.f, ha.y + header_h * 0.5f);
    aida::ui::components::status_dot(status_c, 4.5f,
        aida::ui::with_alpha(th.success, alpha), true, 1.2f);

    char chev_buf[8];
    if (collapsed) std::strcpy(chev_buf, "\xe2\x96\xb6");
    else           std::strcpy(chev_buf, "\xe2\x96\xbc");
    ImFont* chev_font = ImGui::GetFont();
    ImVec2 chsz = chev_font->CalcTextSizeA(11.f, FLT_MAX, 0.f, chev_buf);
    dl->AddText(chev_font, 11.f,
        ImVec2(ha.x + 28.f, ha.y + (header_h - chsz.y) * 0.5f),
        aida::ui::with_alpha(th.text_secondary, alpha), chev_buf);

    char hdr_buf[96];
    snprintf(hdr_buf, sizeof(hdr_buf), "result \xc2\xb7 %zu chars%s",
        payload.size(), truncated ? " (truncated)" : "");
    dl->AddText(ui_font, fs,
        ImVec2(ha.x + 46.f, ha.y + (header_h - fs) * 0.5f),
        aida::ui::with_alpha(th.text_primary, alpha), hdr_buf);

    float cb_w = 24.f;
    float cb_h = 22.f;
    ImVec2 cba(hb.x - cb_w - 10.f, ha.y + (header_h - cb_h) * 0.5f);
    ImVec2 cbb(cba.x + cb_w, cba.y + cb_h);

    char cid[64]; snprintf(cid, sizeof(cid), "trc_cp_%d_%d", msg_idx, span_idx);
    ImGui::PushID(cid);
    ImGuiID copy_id = ImGui::GetID("##cp");
    ImGui::SetCursorScreenPos(cba);
    ImGui::InvisibleButton("##cpbtn", ImVec2(cb_w, cb_h));
    bool cp_hov = ImGui::IsItemHovered();
    bool cp_clk = ImGui::IsItemClicked();
    auto& cp_st = aida::ui::components::detail::bstate(copy_id);
    float chov = cp_st.hover.tick(cp_hov, aida::ui::clock::dt());
    float cflash = cp_st.flash.tick(aida::ui::clock::dt(), 2.5f);
    if (cp_clk) { cp_st.flash.trigger(); ImGui::SetClipboardText(payload.c_str()); }
    ImGui::PopID();

    ImU32 cb_fill = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_top, chov * 0.45f), alpha);
    ImU32 cb_brd  = aida::ui::with_alpha(aida::ui::mix(th.border_subtle, th.accent_hover, chov), alpha);
    dl->AddRectFilled(cba, cbb, cb_fill, cb_h * 0.5f);
    dl->AddRect(cba, cbb, cb_brd, cb_h * 0.5f, 0, 1.f);
    if (cflash > 0.001f) {
        dl->AddRectFilled(cba, cbb,
            aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), cflash * 0.18f * alpha),
            cb_h * 0.5f);
    }
    ImFont* icf = ImGui::GetFont();
    ImVec2 ics = icf->CalcTextSizeA(13.f, FLT_MAX, 0.f, ICON_COPY);
    dl->AddText(icf, 13.f,
        ImVec2(cba.x + (cb_w - ics.x) * 0.5f, cba.y + (cb_h - 13.f) * 0.5f),
        aida::ui::with_alpha(aida::ui::mix(th.text_secondary, th.accent_u32, chov), alpha),
        ICON_COPY);

    bool hov_header = ImGui::IsMouseHoveringRect(ha, ImVec2(cba.x - 4.f, hb.y));
    if (hov_header) {
        dl->AddRectFilled(ha, hb,
            aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), alpha * 0.04f),
            12.f, ImDrawFlags_RoundCornersTop);
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            storage->SetBool(col_id, !collapsed);
        }
    }

    if (current_h > header_h + 4.f) {
        ImVec2 body_clip_a(a.x + 1.f, hb.y);
        ImVec2 body_clip_b(b.x - 1.f, b.y - 1.f);
        dl->PushClipRect(body_clip_a, body_clip_b, true);
        dl->AddText(code_font, code_fs,
            ImVec2(a.x + body_pad, hb.y + body_pad),
            aida::ui::with_alpha(th.text_secondary, alpha),
            display.c_str(), nullptr, max_w - body_pad * 2.f);
        dl->PopClipRect();
    }

    return current_h;
}


float chat_render::render_thinking_indicator(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    int         msg_idx,
    float       alpha,
    float       dt)
{
    (void)dt;
    const auto& th = aida::ui::resolved();
    ImFont* font = aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont();
    float fs = 12.f;
    float pill_h = 28.f;

    static const char* phases[] = { "Reasoning", "Reading code", "Planning", "Drafting" };
    int phase_count = 4;

    float t = aida::ui::clock::seconds();
    float phase_period = 1.6f;
    float total = phase_period * (float)phase_count;
    float p = fmodf(t, total) / phase_period;
    int idx_a = (int)p;
    if (idx_a < 0) idx_a = 0;
    if (idx_a >= phase_count) idx_a = phase_count - 1;
    int idx_b = (idx_a + 1) % phase_count;
    float frac = p - (float)idx_a;
    float blend = 0.f;
    if (frac > 0.85f) blend = (frac - 0.85f) / 0.15f;

    const char* label_a = phases[idx_a];
    const char* label_b = phases[idx_b];
    ImVec2 lts_a = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label_a);
    ImVec2 lts_b = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label_b);
    float label_w = std::max(lts_a.x, lts_b.x);

    float orbit_r = 11.f;
    float pad_l = orbit_r + 12.f;
    float pad_r = 14.f;
    float pill_w = label_w + pad_l + pad_r + 14.f;
    if (pill_w > max_w) pill_w = max_w;

    ImVec2 a = origin;
    ImVec2 b(origin.x + pill_w, origin.y + pill_h);

    aida::ui::blur::render_drop_shadow(dl, a, b, pill_h * 0.5f, 3, 0.18f, ImVec2(0.f, 1.f));
    aida::ui::blur::render_glass_fill(dl, a, b, pill_h * 0.5f, alpha);
    aida::ui::blur::render_glass_border(dl, a, b, pill_h * 0.5f, alpha, 1.f);

    ImVec2 orbit_c(a.x + 6.f + orbit_r, a.y + pill_h * 0.5f);
    aida::ui::brand::render_orbit_ring(dl, orbit_c, orbit_r * 0.6f,
        3, 4.5f, aida::ui::with_alpha(th.accent_u32, alpha), alpha);

    float text_x = orbit_c.x + orbit_r + 4.f;
    float text_y = a.y + (pill_h - fs) * 0.5f;
    ImU32 col_a = aida::ui::with_alpha(th.text_secondary, alpha * (1.f - blend));
    ImU32 col_b = aida::ui::with_alpha(th.text_secondary, alpha * blend);
    dl->AddText(font, fs, ImVec2(text_x, text_y), col_a, label_a);
    if (blend > 0.001f) {
        dl->AddText(font, fs, ImVec2(text_x, text_y), col_b, label_b);
    }

    (void)msg_idx;
    return pill_h;
}


struct streaming_track_t {
    int last_visible = 0;
    float since_last_grow = 0.f;
};

static streaming_track_t load_stream_track(int msg_idx, int total_len)
{
    streaming_track_t tr{};
    ImGuiStorage* st = ImGui::GetStateStorage();
    char vis_buf[48]; snprintf(vis_buf, sizeof(vis_buf), "stream_v_%d", msg_idx);
    char tmr_buf[48]; snprintf(tmr_buf, sizeof(tmr_buf), "stream_t_%d", msg_idx);
    ImGuiID vid = ImGui::GetID(vis_buf);
    ImGuiID tid = ImGui::GetID(tmr_buf);
    tr.last_visible    = st->GetInt(vid, 0);
    tr.since_last_grow = st->GetFloat(tid, 0.f);
    if (tr.last_visible > total_len) tr.last_visible = total_len;
    if (tr.last_visible < 0) tr.last_visible = 0;
    return tr;
}

static void store_stream_track(int msg_idx, const streaming_track_t& tr)
{
    ImGuiStorage* st = ImGui::GetStateStorage();
    char vis_buf[48]; snprintf(vis_buf, sizeof(vis_buf), "stream_v_%d", msg_idx);
    char tmr_buf[48]; snprintf(tmr_buf, sizeof(tmr_buf), "stream_t_%d", msg_idx);
    ImGuiID vid = ImGui::GetID(vis_buf);
    ImGuiID tid = ImGui::GetID(tmr_buf);
    st->SetInt(vid, tr.last_visible);
    st->SetFloat(tid, tr.since_last_grow);
}


chat_render::render_result_t chat_render::render_rich_message(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::string& text,
    float       alpha,
    float       accent_r,
    float       accent_g,
    float       accent_b,
    int         msg_idx,
    float       dt,
    bool        show_actions)
{
    render_result_t result{};
    result.action = action_t::none;
    result.action_msg_index = msg_idx;

    if (text.empty() && show_actions) {
        result.height = 0.f;
        return result;
    }

    const auto& th = aida::ui::resolved();
    ImFont* body_font   = aida::ui::fonts::body()         ? aida::ui::fonts::body()         : ImGui::GetFont();
    ImFont* em_font     = aida::ui::fonts::body_em()      ? aida::ui::fonts::body_em()      : body_font;
    ImFont* strong_font = aida::ui::fonts::body_strong()  ? aida::ui::fonts::body_strong()  : body_font;
    ImFont* h1_font     = aida::ui::fonts::h1()           ? aida::ui::fonts::h1()           : strong_font;
    ImFont* h2_font     = aida::ui::fonts::h2()           ? aida::ui::fonts::h2()           : strong_font;
    ImFont* code_font   = aida::ui::fonts::code()         ? aida::ui::fonts::code()         : body_font;

    float body_fs   = body_font->FontSize > 0.f ? body_font->FontSize : ImGui::GetFontSize();
    float h1_fs     = body_fs * 1.55f;
    float h2_fs     = body_fs * 1.30f;
    float h3_fs     = body_fs * 1.12f;
    float code_fs   = code_font->FontSize > 0.f ? code_font->FontSize : body_fs;

    float card_pad_x = 14.f;
    float card_pad_y = 12.f;
    float wrap_w     = max_w - card_pad_x * 2.f;
    if (wrap_w < 40.f) wrap_w = 40.f;
    float line_h = body_fs + 5.f;

    bool is_streaming = !show_actions;

    int target_visible = (int)text.size();
    int visible_chars = target_visible;
    if (is_streaming) {
        streaming_track_t tr = load_stream_track(msg_idx, target_visible);
        if (tr.last_visible < target_visible) {
            tr.since_last_grow += dt;
            int delta = target_visible - tr.last_visible;
            int step = delta / 4;
            if (step < 1) step = 1;
            tr.last_visible += step;
            if (tr.last_visible > target_visible) tr.last_visible = target_visible;
            tr.since_last_grow = 0.f;
        }
        visible_chars = tr.last_visible;
        store_stream_track(msg_idx, tr);
    }

    std::string visible_text = visible_chars >= (int)text.size()
        ? text
        : text.substr(0, visible_chars);

    auto spans = parse_markdown(visible_text);

    float content_x0 = origin.x + card_pad_x;
    float content_y0 = origin.y + card_pad_y;

    ImGuiStorage* st = ImGui::GetStateStorage();
    float card_w = max_w;
    if (card_w < 40.f) card_w = 40.f;

    char lift_buf[48]; snprintf(lift_buf, sizeof(lift_buf), "rmlift_%d", msg_idx);
    char lift_t_buf[48]; snprintf(lift_t_buf, sizeof(lift_t_buf), "rmliftt_%d", msg_idx);
    char lift_seen_buf[48]; snprintf(lift_seen_buf, sizeof(lift_seen_buf), "rmliftseen_%d", msg_idx);
    ImGuiID lift_id  = ImGui::GetID(lift_buf);
    ImGuiID lift_t   = ImGui::GetID(lift_t_buf);
    ImGuiID lift_seen= ImGui::GetID(lift_seen_buf);
    bool seen_complete = st->GetBool(lift_seen, false);
    float lift_amt = st->GetFloat(lift_id, 0.f);
    float lift_age = st->GetFloat(lift_t, 0.f);
    if (!is_streaming && !seen_complete) {
        st->SetBool(lift_seen, true);
        st->SetFloat(lift_t, 0.f);
        seen_complete = true;
        lift_age = 0.f;
    }
    if (seen_complete) {
        lift_age += dt;
        float dur = 0.6f;
        float t01 = lift_age / dur;
        if (t01 > 1.f) t01 = 1.f;
        if (t01 < 0.f) t01 = 0.f;
        float curve = 1.f - aida::motion::ease::out_cubic(t01);
        lift_amt = curve;
        st->SetFloat(lift_t, lift_age);
    }
    st->SetFloat(lift_id, lift_amt);

    float cursor_x = content_x0;
    float cursor_y = content_y0;
    float base_x   = content_x0;

    auto break_paragraph = [&](float gap = 6.f) {
        if (cursor_x > base_x) {
            cursor_y += line_h;
            cursor_x = base_x;
        }
        cursor_y += gap;
    };

    auto run_inline_in_box = [&](const std::string& s, ImU32 col, ImFont* font, float fs,
                                  bool underline = false, bool strike = false, ImU32 deco = 0) {
        draw_inline_words(dl, font, fs, s, col, cursor_x, cursor_y, base_x, wrap_w,
            fs + 5.f, underline, strike, deco);
    };

    ImU32 text_col       = aida::ui::with_alpha(th.text_primary,  alpha);
    ImU32 italic_col     = aida::ui::with_alpha(th.text_secondary, alpha);
    ImU32 inline_bg      = aida::ui::with_alpha(aida::ui::mix(th.panel_header, th.accent_grad_top, 0.10f), alpha * 0.95f);
    ImU32 inline_fg      = aida::ui::with_alpha(th.accent_u32, alpha);
    ImU32 link_col       = aida::ui::with_alpha(th.accent_u32, alpha);
    ImU32 quote_bar_col  = aida::ui::with_alpha(th.accent_dim, alpha);
    ImU32 quote_bg       = aida::ui::with_alpha(aida::ui::mix(th.panel_bg, th.accent_grad_top, 0.06f), alpha * 0.65f);
    ImU32 hrule_col      = aida::ui::with_alpha(th.border_subtle, alpha);
    ImU32 strike_deco    = aida::ui::with_alpha(th.text_secondary, alpha * 0.95f);

    int span_idx = 0;
    int total_spans = (int)spans.size();
    int last_visible_span = total_spans - 1;

    for (const auto& span : spans) {
        bool is_last_visible = (span_idx == last_visible_span);
        float span_alpha_mul = 1.f;
        if (is_streaming && is_last_visible) {
            float ramp = 0.f;
            char ra_buf[48]; snprintf(ra_buf, sizeof(ra_buf), "rmra_%d_%d", msg_idx, span_idx);
            ImGuiID ra_id = ImGui::GetID(ra_buf);
            ramp = st->GetFloat(ra_id, 0.f);
            ramp += dt / 0.080f;
            if (ramp > 1.f) ramp = 1.f;
            st->SetFloat(ra_id, ramp);
            span_alpha_mul = ramp;
        }

        float effective_alpha = alpha * span_alpha_mul;

        switch (span.type) {
        case span_type::heading1: {
            break_paragraph(8.f);
            ImU32 col = aida::ui::with_alpha(th.text_primary, effective_alpha);
            run_inline_in_box(span.text, col, h1_font, h1_fs);
            cursor_y += h1_fs + 6.f;
            cursor_x = base_x;
            float ly = cursor_y - 4.f;
            ImU32 lc = aida::ui::with_alpha(th.accent_grad_top, effective_alpha * 0.85f);
            ImU32 lc2 = aida::ui::with_alpha(th.accent_grad_bot, effective_alpha * 0.0f);
            dl->AddRectFilledMultiColor(
                ImVec2(base_x, ly - 1.f),
                ImVec2(base_x + wrap_w * 0.45f, ly + 1.f),
                lc, lc2, lc2, lc);
            cursor_y += 6.f;
            break;
        }
        case span_type::heading2: {
            break_paragraph(6.f);
            ImU32 col = aida::ui::with_alpha(th.text_primary, effective_alpha);
            run_inline_in_box(span.text, col, h2_font, h2_fs);
            cursor_y += h2_fs + 6.f;
            cursor_x = base_x;
            break;
        }
        case span_type::heading3: {
            break_paragraph(4.f);
            ImU32 col = aida::ui::with_alpha(th.text_primary, effective_alpha);
            run_inline_in_box(span.text, col, strong_font, h3_fs);
            cursor_y += h3_fs + 4.f;
            cursor_x = base_x;
            break;
        }

        case span_type::text: {
            run_inline_in_box(span.text, aida::ui::with_alpha(text_col, span_alpha_mul), body_font, body_fs);
            break;
        }
        case span_type::bold: {
            ImU32 c = aida::ui::with_alpha(th.text_primary, effective_alpha);
            run_inline_in_box(span.text, c, strong_font, body_fs);
            break;
        }
        case span_type::italic: {
            ImU32 c = aida::ui::with_alpha(italic_col, span_alpha_mul);
            run_inline_in_box(span.text, c, em_font, body_fs);
            break;
        }
        case span_type::bold_italic: {
            ImU32 c = aida::ui::with_alpha(th.text_primary, effective_alpha);
            run_inline_in_box(span.text, c, strong_font, body_fs);
            break;
        }

        case span_type::link: {
            ImU32 c = aida::ui::with_alpha(link_col, span_alpha_mul);
            ImVec2 measure = body_font->CalcTextSizeA(body_fs, FLT_MAX, 0.f, span.text.c_str());
            ImVec2 hit_a(cursor_x, cursor_y);
            ImVec2 hit_b(cursor_x + measure.x, cursor_y + body_fs + 2.f);
            bool hov = ImGui::IsMouseHoveringRect(hit_a, hit_b);
            run_inline_in_box(span.text, c, body_font, body_fs, hov, false, c);
            if (hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !span.url.empty()) {
                ImGui::SetClipboardText(span.url.c_str());
            }
            break;
        }

        case span_type::strikethrough: {
            ImU32 c = aida::ui::with_alpha(th.text_secondary, effective_alpha);
            run_inline_in_box(span.text, c, body_font, body_fs, false, true, strike_deco);
            break;
        }

        case span_type::inline_code: {
            ImVec2 ts = code_font->CalcTextSizeA(code_fs, FLT_MAX, 0.f, span.text.c_str());
            float pill_w = ts.x + 10.f;
            float pill_h = body_fs + 5.f;

            float remaining = (base_x + wrap_w) - cursor_x;
            if (pill_w > remaining && cursor_x > base_x) {
                cursor_y += line_h;
                cursor_x = base_x;
            }
            ImU32 bg = aida::ui::with_alpha(inline_bg, span_alpha_mul);
            ImU32 fg = aida::ui::with_alpha(inline_fg, span_alpha_mul);
            ImU32 brd = aida::ui::with_alpha(th.accent_dim, alpha * 0.55f * span_alpha_mul);

            dl->AddRectFilled(
                ImVec2(cursor_x - 1.f, cursor_y - 1.f),
                ImVec2(cursor_x + pill_w, cursor_y + pill_h - 1.f),
                bg, 4.f);
            dl->AddRect(
                ImVec2(cursor_x - 1.f, cursor_y - 1.f),
                ImVec2(cursor_x + pill_w, cursor_y + pill_h - 1.f),
                brd, 4.f, 0, 0.8f);
            dl->AddText(code_font, code_fs,
                ImVec2(cursor_x + 5.f, cursor_y + (pill_h - code_fs) * 0.5f - 1.f),
                fg, span.text.c_str());

            cursor_x += pill_w + 4.f;
            break;
        }

        case span_type::code_block: {
            break_paragraph(6.f);
            float block_h = render_code_block(
                dl, ImVec2(base_x, cursor_y), wrap_w,
                span.text, span.language, effective_alpha,
                accent_r, accent_g, accent_b);
            cursor_y += block_h + 8.f;
            cursor_x = base_x;
            break;
        }

        case span_type::tool_call: {
            break_paragraph(6.f);
            float h = render_tool_call_card(dl, ImVec2(base_x, cursor_y), wrap_w,
                span.text, effective_alpha, msg_idx, span_idx, dt);
            cursor_y += h + 8.f;
            cursor_x = base_x;
            break;
        }

        case span_type::tool_result: {
            break_paragraph(6.f);
            float h = render_tool_result_card(dl, ImVec2(base_x, cursor_y), wrap_w,
                span.text, effective_alpha, msg_idx, span_idx, dt);
            cursor_y += h + 8.f;
            cursor_x = base_x;
            break;
        }

        case span_type::list_bullet: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            float indent = (float)span.list_indent * 14.f;
            float bx = base_x + indent;
            float by = cursor_y + body_fs * 0.55f;
            dl->AddCircleFilled(ImVec2(bx + 4.f, by), 2.5f,
                aida::ui::with_alpha(th.accent_u32, effective_alpha), 12);
            float saved_base = base_x;
            base_x = bx + 14.f;
            cursor_x = base_x;
            ImU32 c = aida::ui::with_alpha(text_col, span_alpha_mul);
            run_inline_in_box(span.text, c, body_font, body_fs);
            base_x = saved_base;
            cursor_y += line_h;
            cursor_x = base_x;
            break;
        }
        case span_type::list_numbered: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            float indent = (float)span.list_indent * 14.f;
            float bx = base_x + indent;
            char num_buf[16]; snprintf(num_buf, sizeof(num_buf), "%d.", span.list_index);
            ImVec2 ns = strong_font->CalcTextSizeA(body_fs, FLT_MAX, 0.f, num_buf);
            ImU32 nc = aida::ui::with_alpha(th.accent_u32, effective_alpha);
            dl->AddText(strong_font, body_fs, ImVec2(bx, cursor_y), nc, num_buf);
            float saved_base = base_x;
            base_x = bx + ns.x + 8.f;
            cursor_x = base_x;
            ImU32 c = aida::ui::with_alpha(text_col, span_alpha_mul);
            run_inline_in_box(span.text, c, body_font, body_fs);
            base_x = saved_base;
            cursor_y += line_h;
            cursor_x = base_x;
            break;
        }

        case span_type::task_unchecked:
        case span_type::task_checked: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            float indent = (float)span.list_indent * 14.f;
            float bx = base_x + indent;
            float by = cursor_y + 1.f;
            float sz = body_fs - 1.f;
            ImVec2 cmin(bx, by);
            ImVec2 cmax(bx + sz, by + sz);
            bool checked = span.type == span_type::task_checked;
            ImU32 brd = aida::ui::with_alpha(checked ? th.accent_u32 : th.border_strong, effective_alpha);
            ImU32 fl  = checked
                ? aida::ui::with_alpha(th.accent_grad_top, effective_alpha * 0.85f)
                : aida::ui::with_alpha(th.panel_header, effective_alpha * 0.4f);
            dl->AddRectFilled(cmin, cmax, fl, 4.f);
            dl->AddRect(cmin, cmax, brd, 4.f, 0, 1.f);
            if (checked) {
                aida::ui::brand::render_check_drawn(dl,
                    ImVec2((cmin.x + cmax.x) * 0.5f, (cmin.y + cmax.y) * 0.5f),
                    sz - 2.f, 1.f,
                    IM_COL32(255, 255, 255, (int)(245.f * effective_alpha)),
                    1.6f);
            }
            float saved_base = base_x;
            base_x = bx + sz + 8.f;
            cursor_x = base_x;
            ImU32 c = checked
                ? aida::ui::with_alpha(th.text_secondary, effective_alpha)
                : aida::ui::with_alpha(text_col, span_alpha_mul);
            run_inline_in_box(span.text, c, body_font, body_fs, false, checked, strike_deco);
            base_x = saved_base;
            cursor_y += line_h;
            cursor_x = base_x;
            break;
        }

        case span_type::blockquote: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            ImVec2 wrap_sz = em_font->CalcTextSizeA(body_fs, wrap_w - 16.f, wrap_w - 16.f, span.text.c_str());
            float box_h = wrap_sz.y + 8.f;
            ImVec2 ba(base_x, cursor_y - 2.f);
            ImVec2 bb(base_x + wrap_w, cursor_y + box_h);
            dl->AddRectFilled(ba, bb, quote_bg, 6.f);
            dl->AddRectFilled(ba, ImVec2(ba.x + 3.f, bb.y), quote_bar_col, 1.5f);
            dl->AddText(em_font, body_fs,
                ImVec2(ba.x + 12.f, ba.y + 4.f),
                aida::ui::with_alpha(th.text_secondary, effective_alpha),
                span.text.c_str(), nullptr, wrap_w - 18.f);
            cursor_y = bb.y + 4.f;
            cursor_x = base_x;
            break;
        }

        case span_type::hrule: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            cursor_y += 6.f;
            float midy = cursor_y;
            ImU32 a = aida::ui::with_alpha(hrule_col, 0.f);
            ImU32 b = aida::ui::with_alpha(hrule_col, effective_alpha);
            dl->AddRectFilledMultiColor(
                ImVec2(base_x, midy - 1.f),
                ImVec2(base_x + wrap_w * 0.5f, midy + 1.f),
                a, b, b, a);
            dl->AddRectFilledMultiColor(
                ImVec2(base_x + wrap_w * 0.5f, midy - 1.f),
                ImVec2(base_x + wrap_w, midy + 1.f),
                b, a, a, b);
            cursor_y += 10.f;
            cursor_x = base_x;
            break;
        }

        case span_type::table: {
            if (cursor_x > base_x) { cursor_y += line_h; cursor_x = base_x; }
            cursor_y += 4.f;
            float h = render_table_block(dl, ImVec2(base_x, cursor_y), wrap_w,
                span.table_data, effective_alpha);
            cursor_y += h + 8.f;
            cursor_x = base_x;
            break;
        }

        case span_type::paragraph_break: {
            break_paragraph(6.f);
            break;
        }
        }

        ++span_idx;
    }

    if (cursor_x > base_x) {
        cursor_y += line_h * 0.6f;
        cursor_x = base_x;
    }

    float final_cursor_y = cursor_y;
    float content_h = (final_cursor_y - origin.y) + card_pad_y;
    if (content_h < body_fs + card_pad_y * 2.f) content_h = body_fs + card_pad_y * 2.f;

    float card_y_off = -lift_amt * 1.f;
    ImVec2 card_a(origin.x, origin.y + card_y_off);
    ImVec2 card_b(origin.x + card_w, origin.y + content_h + card_y_off);

    float shadow_strength = 0.18f + lift_amt * 0.10f;
    aida::ui::blur::render_drop_shadow(dl, card_a, card_b, 14.f, 4, shadow_strength,
        ImVec2(0.f, 3.f + lift_amt * 1.5f));
    aida::ui::blur::render_glass_fill(dl, card_a, card_b, 14.f, alpha);
    aida::ui::blur::render_glass_border(dl, card_a, card_b, 14.f, alpha, 1.f);

    ImU32 left_bar = aida::ui::with_alpha(th.accent_dim, alpha);
    dl->AddRectFilled(
        ImVec2(card_a.x + 0.5f, card_a.y + 1.f),
        ImVec2(card_a.x + 2.5f, card_b.y - 1.f),
        left_bar, 1.5f);

    if (is_streaming) {
        float blink_a = aida::ui::clock::pulse(2.0f, 0.30f, 1.0f);
        float cursor_baseline_x = cursor_x + 1.f;
        float cursor_baseline_y = cursor_y - line_h;
        if (cursor_baseline_y < content_y0) cursor_baseline_y = content_y0;
        ImU32 cur_col = aida::ui::with_alpha(th.accent_u32, alpha * blink_a);
        dl->AddRectFilled(
            ImVec2(cursor_baseline_x, cursor_baseline_y + 2.f + card_y_off),
            ImVec2(cursor_baseline_x + 2.f, cursor_baseline_y + body_fs + 2.f + card_y_off),
            cur_col);
    }

    result.height = content_h;

    if (show_actions) {
        float btn_h = 22.f;
        float btn_y = card_b.y + 8.f;
        float btn_gap = 8.f;

        struct btn_def_t { const char* glyph; action_t action; };
        btn_def_t buttons[2] = {
            { ICON_COPY, action_t::copy },
            { ICON_HISTORY, action_t::retry }
        };

        float total_btn_w = 0.f;
        float btn_widths[2];
        ImFont* icon_font = ImGui::GetFont();
        for (int bi = 0; bi < 2; ++bi) {
            ImVec2 ts = icon_font->CalcTextSizeA(13.f, FLT_MAX, 0.f, buttons[bi].glyph);
            btn_widths[bi] = ts.x + 16.f;
            total_btn_w += btn_widths[bi];
        }
        total_btn_w += btn_gap;

        float bx = card_b.x - total_btn_w;

        for (int bi = 0; bi < 2; ++bi) {
            float bw = btn_widths[bi];
            ImVec2 bmin(bx, btn_y);
            ImVec2 bmax_pt(bx + bw, btn_y + btn_h);

            char id_buf[48]; snprintf(id_buf, sizeof(id_buf), "rmact_%d_%d", msg_idx, bi);
            ImGui::PushID(id_buf);
            ImGuiID id = ImGui::GetID("##act");
            ImGui::SetCursorScreenPos(bmin);
            ImGui::InvisibleButton("##actb", ImVec2(bw, btn_h));
            bool hov = ImGui::IsItemHovered();
            bool clk = ImGui::IsItemClicked();
            auto& bs = aida::ui::components::detail::bstate(id);
            float h_v = bs.hover.tick(hov, aida::ui::clock::dt());
            float fl  = bs.flash.tick(aida::ui::clock::dt(), 2.5f);
            if (clk) bs.flash.trigger();
            ImGui::PopID();

            ImU32 fill = aida::ui::with_alpha(
                aida::ui::mix(th.panel_header, th.accent_grad_top, h_v * 0.40f), alpha);
            ImU32 brd = aida::ui::with_alpha(
                aida::ui::mix(th.border_subtle, th.accent_hover, h_v), alpha);
            dl->AddRectFilled(bmin, bmax_pt, fill, btn_h * 0.5f);
            dl->AddRect(bmin, bmax_pt, brd, btn_h * 0.5f, 0, 1.f);
            if (fl > 0.001f) {
                dl->AddRectFilled(bmin, bmax_pt,
                    aida::ui::with_alpha(IM_COL32(255, 255, 255, 255), fl * 0.20f * alpha),
                    btn_h * 0.5f);
            }
            ImU32 ic_col = aida::ui::with_alpha(
                aida::ui::mix(th.text_secondary, th.accent_u32, h_v), alpha);
            ImVec2 ts = icon_font->CalcTextSizeA(13.f, FLT_MAX, 0.f, buttons[bi].glyph);
            dl->AddText(icon_font, 13.f,
                ImVec2(bmin.x + (bw - ts.x) * 0.5f, bmin.y + (btn_h - 13.f) * 0.5f),
                ic_col, buttons[bi].glyph);

            if (clk) {
                result.action = buttons[bi].action;
                if (result.action == action_t::copy)
                    ImGui::SetClipboardText(text.c_str());
            }

            bx += bw + btn_gap;
        }

        result.height += btn_h + 12.f;

        if (ImGui::IsMouseHoveringRect(card_a, card_b) &&
            ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            char popid[48]; snprintf(popid, sizeof(popid), "##rmctx_%d", msg_idx);
            ImGui::OpenPopup(popid);
        }
        char popid[48]; snprintf(popid, sizeof(popid), "##rmctx_%d", msg_idx);
        if (ImGui::BeginPopup(popid)) {
            if (ImGui::MenuItem("Copy Message")) {
                ImGui::SetClipboardText(text.c_str());
            }
            if (ImGui::MenuItem("Edit Message")) {
                result.action = action_t::edit_msg;
            }
            if (ImGui::MenuItem("Delete Message")) {
                result.action = action_t::delete_msg;
            }
            if (ImGui::MenuItem("Retry From Here")) {
                result.action = action_t::retry;
            }
            ImGui::EndPopup();
        }
    }

    return result;
}
