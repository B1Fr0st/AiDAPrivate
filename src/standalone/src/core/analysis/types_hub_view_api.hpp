#pragma once

#include <string>

namespace aida::analysis {
struct address_t;
}

namespace disasm_view {
struct workspace_context_t;
}

namespace types_hub_view {

enum class sub_tab_t : int {
    structs = 0,
    unions = 1,
    enums = 2,
    typedefs = 3,
    functions = 4,
    inferred = 5,
    dissector = 6,
    COUNT = 7
};

void set_sub_tab(sub_tab_t tab);

bool stage_type_application(const disasm_view::workspace_context_t& context,
    const aida::analysis::address_t& address, std::string* error = nullptr);

void render_subview(sub_tab_t tab, float pos_x, float pos_y,
    float width, float height, float alpha,
    float accent_r, float accent_g, float accent_b);

}
