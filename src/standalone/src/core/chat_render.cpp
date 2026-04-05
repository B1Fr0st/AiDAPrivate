#include "chat_render.hpp"
#include "../ide_icons.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>


std::vector<chat_render::span_t> chat_render::parse_markdown(const std::string& text)
{
    std::vector<span_t> spans;
    if (text.empty()) return spans;

    size_t i = 0;
    size_t n = text.size();
    std::string accum;

    auto flush_text = [&]() {
        if (!accum.empty()) {
            spans.push_back({ span_type::text, accum, {} });
            accum.clear();
        }
    };

    while (i < n) {

        if (i + 2 < n && text[i] == '`' && text[i+1] == '`' && text[i+2] == '`') {
            flush_text();
            i += 3;

            std::string lang;
            while (i < n && text[i] != '\n' && text[i] != '\r') {
                lang += text[i++];
            }
            if (i < n && text[i] == '\r') i++;
            if (i < n && text[i] == '\n') i++;


            std::string code;
            while (i < n) {
                if (i + 2 < n && text[i] == '`' && text[i+1] == '`' && text[i+2] == '`') {
                    i += 3;

                    if (i < n && text[i] == '\r') i++;
                    if (i < n && text[i] == '\n') i++;
                    break;
                }
                code += text[i++];
            }

            while (!code.empty() && (code.back() == '\n' || code.back() == '\r'))
                code.pop_back();


            while (!lang.empty() && (lang.front() == ' ' || lang.front() == '\t'))
                lang.erase(lang.begin());
            while (!lang.empty() && (lang.back() == ' ' || lang.back() == '\t'))
                lang.pop_back();

            spans.push_back({ span_type::code_block, code, lang });
            continue;
        }


        if (i + 10 < n && text.substr(i, 11) == "<tool_call>") {
            flush_text();
            i += 11;
            size_t end = text.find("</tool_call>", i);
            std::string content;
            if (end != std::string::npos) {
                content = text.substr(i, end - i);
                i = end + 12;
            } else {
                content = text.substr(i);
                i = n;
            }
            spans.push_back({ span_type::tool_call, content, {} });
            continue;
        }


        if (i + 12 < n && text.substr(i, 13) == "<tool_result>") {
            flush_text();
            i += 13;
            size_t end = text.find("</tool_result>", i);
            std::string content;
            if (end != std::string::npos) {
                content = text.substr(i, end - i);
                i = end + 14;
            } else {
                content = text.substr(i);
                i = n;
            }
            spans.push_back({ span_type::tool_result, content, {} });
            continue;
        }


        if (text[i] == '`') {
            size_t end = text.find('`', i + 1);
            if (end != std::string::npos && end - i > 1) {
                flush_text();
                spans.push_back({ span_type::inline_code, text.substr(i + 1, end - i - 1), {} });
                i = end + 1;
                continue;
            }
        }


        if (i + 2 < n && text[i] == '*' && text[i+1] == '*') {
            if (i + 4 < n && text[i+2] == '*') {

                size_t end = text.find("***", i + 3);
                if (end != std::string::npos) {
                    flush_text();
                    spans.push_back({ span_type::bold_italic, text.substr(i + 3, end - i - 3), {} });
                    i = end + 3;
                    continue;
                }
            }

            size_t end = text.find("**", i + 2);
            if (end != std::string::npos && end > i + 2) {
                flush_text();
                spans.push_back({ span_type::bold, text.substr(i + 2, end - i - 2), {} });
                i = end + 2;
                continue;
            }
        }


        if (text[i] == '*' && (i + 1 >= n || text[i+1] != '*')) {
            size_t end = text.find('*', i + 1);
            if (end != std::string::npos && end > i + 1) {

                if (end + 1 >= n || text[end + 1] != '*') {
                    flush_text();
                    spans.push_back({ span_type::italic, text.substr(i + 1, end - i - 1), {} });
                    i = end + 1;
                    continue;
                }
            }
        }

        accum += text[i++];
    }

    flush_text();
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
    return syntax::lang_cpp();
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

    float pad       = 10.f;
    float header_h  = 20.f;
    float font_size = ImGui::GetFontSize();
    float line_h    = font_size + 2.f;


    int line_count = 1;
    for (char ch : code)
        if (ch == '\n') line_count++;

    float code_h   = line_count * line_h + pad;
    float total_h  = header_h + code_h + pad;
    float block_w  = max_w;


    ImVec2 bmin = origin;
    ImVec2 bmax(origin.x + block_w, origin.y + total_h);
    dl->AddRectFilled(bmin, bmax, IM_COL32(22, 20, 38, (int)(230 * alpha)), 6.f);
    dl->AddRect(bmin, bmax, IM_COL32(255, 255, 255, (int)(12 * alpha)), 6.f, 0, 0.5f);


    ImVec2 hmin = bmin;
    ImVec2 hmax(bmin.x + block_w, bmin.y + header_h);
    dl->AddRectFilled(hmin, hmax, IM_COL32(255, 255, 255, (int)(6 * alpha)), 6.f, ImDrawFlags_RoundCornersTop);


    std::string lang_label = language.empty() ? "code" : language;
    dl->AddText(ImVec2(hmin.x + 8.f, hmin.y + 2.f),
        IM_COL32(140, 140, 170, (int)(180 * alpha)), lang_label.c_str());


    const char* copy_label = ICON_COPY;
    ImVec2 cts = ImGui::CalcTextSize(copy_label);
    ImVec2 cmin(hmax.x - cts.x - 16.f, hmin.y + 1.f);
    ImVec2 cmax(hmax.x - 4.f, hmin.y + header_h - 1.f);
    bool copy_hov = ImGui::IsMouseHoveringRect(cmin, cmax);

    if (copy_hov)
        dl->AddRectFilled(cmin, cmax, IM_COL32(255, 255, 255, (int)(16 * alpha)), 3.f);

    dl->AddText(ImVec2(cmin.x + 4.f, cmin.y + 2.f),
        IM_COL32(160, 160, 190, (int)((copy_hov ? 240 : 160) * alpha)), copy_label);

    if (copy_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        ImGui::SetClipboardText(code.c_str());


    auto lang_def = get_lang_def(language);
    std::vector<syntax::token_t> tokens;
    syntax::tokenize(code, lang_def, tokens);
    ImU32 colors[(int)syntax::token_type::COUNT];
    syntax::get_token_colors(colors, accent_r, accent_g, accent_b, alpha);

    float cx = origin.x + pad;
    float cy = origin.y + header_h + pad * 0.5f;


    size_t line_num = 1;
    size_t tok_idx = 0;
    size_t char_pos = 0;


    char gutter_buf[8];
    snprintf(gutter_buf, sizeof(gutter_buf), "%d", line_count);
    float gutter_w = ImGui::CalcTextSize(gutter_buf).x + 12.f;


    snprintf(gutter_buf, sizeof(gutter_buf), "%d", (int)line_num);
    ImVec2 gts = ImGui::CalcTextSize(gutter_buf);
    dl->AddText(ImVec2(cx + gutter_w - gts.x - 6.f, cy),
        IM_COL32(80, 80, 100, (int)(120 * alpha)), gutter_buf);

    float text_x = cx + gutter_w;
    float text_start_x = text_x;

    for (size_t ti = 0; ti < tokens.size(); ti++) {
        const auto& tok = tokens[ti];
        std::string_view sv(code.data() + tok.start, tok.length);

        ImU32 col = colors[(int)tok.type];


        for (size_t ci = 0; ci < sv.size(); ci++) {
            if (sv[ci] == '\n') {
                cy += line_h;
                text_x = text_start_x;
                line_num++;
                snprintf(gutter_buf, sizeof(gutter_buf), "%d", (int)line_num);
                gts = ImGui::CalcTextSize(gutter_buf);
                dl->AddText(ImVec2(cx + gutter_w - gts.x - 6.f, cy),
                    IM_COL32(80, 80, 100, (int)(120 * alpha)), gutter_buf);
            } else if (sv[ci] == '\t') {
                text_x += ImGui::CalcTextSize("    ").x;
            } else {
                char ch_buf[2] = { sv[ci], 0 };
                dl->AddText(ImVec2(text_x, cy), col, ch_buf);
                text_x += ImGui::CalcTextSize(ch_buf).x;
            }
        }
    }

    return total_h;
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

    auto spans = parse_markdown(text);
    if (spans.empty()) {
        result.height = 0.f;
        return result;
    }

    float cx = origin.x;
    float cy = origin.y;
    float wrap_w = max_w - 16.f;
    float font_size = ImGui::GetFontSize();
    float line_h = font_size + 2.f;

    ImU32 text_col   = IM_COL32(220, 218, 240, (int)(230 * alpha));
    ImU32 bold_col   = IM_COL32(240, 238, 255, (int)(250 * alpha));
    ImU32 italic_col = IM_COL32(185, 180, 220, (int)(220 * alpha));
    ImU32 inline_bg  = IM_COL32(40, 38, 60, (int)(200 * alpha));
    ImU32 inline_fg  = IM_COL32(220, 190, 255, (int)(240 * alpha));
    ImU32 tool_bg    = IM_COL32(30, 28, 50, (int)(200 * alpha));

    float cursor_x = cx + 8.f;
    float cursor_y = cy + 5.f;
    float base_x   = cx + 8.f;

    // WHY: Word-by-word inline renderer. All inline spans (text, bold, italic,
    // inline_code) share cursor_x/cursor_y so they flow together on the same line.
    // The old code rendered each text span as a full-width paragraph which broke
    // around inline code pills (e.g. "variable `has_kernel` is false" would put
    // "has_kernel" on its own line instead of flowing inline).
    auto render_inline_words = [&](const std::string& txt, ImU32 color) {
        const char* p   = txt.c_str();
        const char* end = p + txt.size();
        float space_w   = ImGui::CalcTextSize(" ").x;

        while (p < end) {
            if (*p == '\n') {
                cursor_y += line_h;
                cursor_x = base_x;
                p++;
                continue;
            }
            if (*p == '\r') { p++; continue; }

            if (*p == ' ') {
                // Only add space if we've already rendered something on this line
                if (cursor_x > base_x)
                    cursor_x += space_w;
                p++;
                continue;
            }

            const char* word_start = p;
            while (p < end && *p != ' ' && *p != '\n' && *p != '\r')
                p++;

            ImVec2 ws = ImGui::CalcTextSize(word_start, p);
            float remaining = (base_x + wrap_w) - cursor_x;
            if (ws.x > remaining && cursor_x > base_x) {
                cursor_y += line_h;
                cursor_x = base_x;
            }

            dl->AddText(ImVec2(cursor_x, cursor_y), color, word_start, p);
            cursor_x += ws.x;
        }
    };

    for (const auto& span : spans) {
        switch (span.type) {
        case span_type::text: {
            render_inline_words(span.text, text_col);
            break;
        }

        case span_type::bold: {
            render_inline_words(span.text, bold_col);
            break;
        }

        case span_type::italic: {
            render_inline_words(span.text, italic_col);
            break;
        }

        case span_type::bold_italic: {
            render_inline_words(span.text, bold_col);
            break;
        }

        case span_type::inline_code: {

            ImVec2 ts = ImGui::CalcTextSize(span.text.c_str());
            float pill_w = ts.x + 8.f;
            float pill_h = ts.y + 4.f;

            float remaining = (base_x + wrap_w) - cursor_x;
            if (pill_w > remaining && cursor_x > base_x) {
                cursor_y += line_h;
                cursor_x = base_x;
            }

            dl->AddRectFilled(
                ImVec2(cursor_x, cursor_y - 1.f),
                ImVec2(cursor_x + pill_w, cursor_y + pill_h - 1.f),
                inline_bg, 3.f);
            dl->AddText(
                ImVec2(cursor_x + 4.f, cursor_y + 1.f),
                inline_fg, span.text.c_str());

            cursor_x += pill_w + 4.f;

            break;
        }

        case span_type::code_block: {

            if (cursor_x > base_x) {
                cursor_y += font_size + 4.f;
                cursor_x = base_x;
            }
            cursor_y += 4.f;

            float block_h = render_code_block(
                dl, ImVec2(cx + 4.f, cursor_y), max_w - 8.f,
                span.text, span.language, alpha,
                accent_r, accent_g, accent_b);

            cursor_y += block_h + 6.f;
            cursor_x = base_x;
            break;
        }

        case span_type::tool_call: {

            if (cursor_x > base_x) {
                cursor_y += font_size + 4.f;
                cursor_x = base_x;
            }
            cursor_y += 2.f;

            float sec_w = max_w - 8.f;
            float sec_h = 22.f;


            ImVec2 smin(cx + 4.f, cursor_y);
            ImVec2 smax(smin.x + sec_w, smin.y + sec_h);
            dl->AddRectFilled(smin, smax, tool_bg, 4.f);
            dl->AddRect(smin, smax, IM_COL32(255, 255, 255, (int)(10 * alpha)), 4.f, 0, 0.5f);


            std::string tool_label = "Tool Call";
            size_t name_pos = span.text.find("\"name\"");
            if (name_pos != std::string::npos) {
                size_t q1 = span.text.find('\"', name_pos + 6);
                if (q1 != std::string::npos) {
                    size_t q2 = span.text.find('\"', q1 + 1);
                    if (q2 != std::string::npos) {
                        q1++;
                        size_t q3 = span.text.find('\"', q1);
                        if (q3 != std::string::npos)
                            tool_label = "\xf0\x9f\x94\xa7 " + span.text.substr(q1, q3 - q1);
                    }
                }
            }

            dl->AddText(ImVec2(smin.x + 8.f, smin.y + 3.f),
                IM_COL32((int)accent_r, (int)accent_g, (int)accent_b, (int)(200 * alpha)),
                tool_label.c_str());

            cursor_y += sec_h + 4.f;
            cursor_x = base_x;
            break;
        }

        case span_type::tool_result: {

            if (cursor_x > base_x) {
                cursor_y += font_size + 4.f;
                cursor_x = base_x;
            }
            cursor_y += 2.f;

            float sec_w = max_w - 8.f;
            std::string truncated = span.text;
            if (truncated.size() > 500) {
                truncated = truncated.substr(0, 500) + "\n... (truncated)";
            }

            ImVec2 tts = ImGui::CalcTextSize(truncated.c_str(), nullptr, false, sec_w - 16.f);
            float sec_h = tts.y + 12.f;

            ImVec2 smin(cx + 4.f, cursor_y);
            ImVec2 smax(smin.x + sec_w, smin.y + sec_h);
            dl->AddRectFilled(smin, smax,
                IM_COL32(18, 16, 32, (int)(200 * alpha)), 4.f);
            dl->AddRect(smin, smax,
                IM_COL32(255, 255, 255, (int)(8 * alpha)), 4.f, 0, 0.5f);

            dl->PushClipRect(smin, smax, true);
            dl->AddText(ImGui::GetFont(), font_size,
                ImVec2(smin.x + 8.f, smin.y + 6.f),
                IM_COL32(150, 148, 175, (int)(180 * alpha)),
                truncated.c_str(), nullptr, sec_w - 16.f);
            dl->PopClipRect();

            cursor_y += sec_h + 4.f;
            cursor_x = base_x;
            break;
        }
        }
    }


    float msg_h = cursor_y - origin.y + 5.f;
    result.height = msg_h;


    if (show_actions) {
        ImVec2 msg_min = origin;
        ImVec2 msg_max(origin.x + max_w, origin.y + msg_h);

        float btn_h = 20.f;
        float btn_y = msg_max.y + 12.f;

        // Always show Copy and Retry buttons at the bottom-right
        const char* labels[] = { ICON_COPY, ICON_SPINNER };
        action_t actions[] = { action_t::copy, action_t::retry };

        // Calculate total width of buttons first for right-alignment
        float btn_gap = 12.f;
        float total_btn_w = 0.f;
        float btn_widths[2];
        for (int bi = 0; bi < 2; bi++) {
            ImVec2 lts = ImGui::CalcTextSize(labels[bi]);
            btn_widths[bi] = lts.x + 10.f;
            total_btn_w += btn_widths[bi];
        }
        total_btn_w += btn_gap; // gap between buttons

        float bx = msg_max.x - total_btn_w - 8.f;

        for (int bi = 0; bi < 2; bi++) {
            float bw = btn_widths[bi];
            ImVec2 bmin(bx, btn_y);
            ImVec2 bmax(bx + bw, btn_y + btn_h);
            bool bhov = ImGui::IsMouseHoveringRect(bmin, bmax);

            ImGuiID btn_id = ImGui::GetID(("msg_btn_" + std::to_string(msg_idx) + "_" + std::to_string(bi)).c_str());
            float btn_anim = ImGui::GetStateStorage()->GetFloat(btn_id, 0.f);
            btn_anim += ((bhov ? 1.f : 0.f) - btn_anim) * std::min(12.f * dt, 1.f);
            ImGui::GetStateStorage()->SetFloat(btn_id, btn_anim);

            float bg_alpha = (100.f + btn_anim * 80.f) * alpha;
            dl->AddRectFilled(bmin, bmax,
                IM_COL32(40, 38, 60, (int)bg_alpha), 4.f);

            float text_alpha = (140.f + btn_anim * 80.f) * alpha;
            dl->AddText(ImVec2(bmin.x + 5.f, bmin.y + 2.f),
                IM_COL32(160, 158, 190, (int)text_alpha),
                labels[bi]);

            if (bhov && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                result.action = actions[bi];
                if (result.action == action_t::copy)
                    ImGui::SetClipboardText(text.c_str());
            }

            bx += bw + btn_gap;
        }

        result.height += btn_h + 14.f;


        if (ImGui::IsMouseHoveringRect(msg_min, msg_max) &&
            ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
            ImGui::OpenPopup(("##msg_ctx_" + std::to_string(msg_idx)).c_str());
        }
        if (ImGui::BeginPopup(("##msg_ctx_" + std::to_string(msg_idx)).c_str())) {
            if (ImGui::MenuItem("Copy Message"))
                ImGui::SetClipboardText(text.c_str());
            ImGui::EndPopup();
        }
    }

    return result;
}
