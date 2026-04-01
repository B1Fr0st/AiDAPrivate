#pragma once


#include <cstdint>
#include <string>
#include <vector>


struct DisasmFile;
struct DisasmState;

namespace disasm_view {

enum class addr_format_t : int {
    va = 0,
    rva,
    file_offset
};

struct bookmark_t {
    uint64_t addr;
    std::string label;
};

struct state_t {

    std::vector<int> nav_history;
    int              nav_pos = -1;


    bool  goto_visible  = false;
    char  goto_buf[20]  = {};


    addr_format_t addr_format = addr_format_t::va;
    int  active_section = 0;
    bool show_bytes     = true;


    std::vector<bookmark_t> bookmarks;


    float scroll_y = 0.f;
    float target_scroll_y = 0.f;


    int selected_row = -1;


    int ctx_row = -1;
};

inline state_t g_state;

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt);

void goto_address(uint64_t addr, DisasmState& disasm);
void navigate_back();
void navigate_forward();

}
