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
};

struct span_t {
    span_type   type;
    std::string text;
    std::string language;
};


std::vector<span_t> parse_markdown(const std::string& text);


enum class action_t : int {
    none = 0,
    copy,
    retry,
    edit_msg,
    delete_msg,
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

}
