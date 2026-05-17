#pragma once


#include <cstdint>
#include <string>
#include <vector>

#include "imgui/imgui.h"
#include "syntax_highlight.hpp"

struct ID3D11ShaderResourceView;

namespace chat_render {


enum class span_type : int {
    text = 0,
    bold,
    italic,
    bold_italic,
    inline_code,
    code_block,
    tool_call,
    tool_result,
    heading1,
    heading2,
    heading3,
    list_bullet,
    list_numbered,
    blockquote,
    link,
    strikethrough,
    task_unchecked,
    task_checked,
    hrule,
    table,
    paragraph_break
};


struct span_t {
    span_type   type;
    std::string text;
    std::string language;
    std::string url;
    int         depth        = 0;
    int         list_index   = 0;
    int         list_indent  = 0;
    std::vector<std::vector<std::string>> table_data;
};


std::vector<span_t> parse_markdown(const std::string& text);


enum class action_t : int {
    none = 0,
    copy,
    retry,
    edit_msg,
    delete_msg,
    select_text,
};

struct render_result_t {
    float    height;
    action_t action;
    int      action_msg_index;
};


render_result_t render_rich_message(
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
    bool        show_actions = true);


float render_code_block(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    const std::string& code,
    const std::string& language,
    float       alpha,
    float       accent_r,
    float       accent_g,
    float       accent_b);


float render_thinking_indicator(
    ImDrawList* dl,
    ImVec2      origin,
    float       max_w,
    int         msg_idx,
    float       alpha,
    float       dt);

}
