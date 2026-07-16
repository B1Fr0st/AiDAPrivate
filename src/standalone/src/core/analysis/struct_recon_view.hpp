#pragma once

#include <string>

namespace struct_recon_view {

struct command_result_t {
    bool completed = false;
    std::string detail;
};

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

command_result_t copy_current_declaration();
command_result_t declare_and_apply_current();
bool has_current_structure();

}
