#pragma once


#include <cstdint>
#include <string>
#include <vector>

namespace hex_view {

struct state_t {
    std::vector<uint8_t> data;
    uint64_t             base_addr    = 0;
    std::string          source_name;
    bool                 active       = false;


    int  sel_start    = -1;
    int  sel_end      = -1;
    bool selecting    = false;


    float scroll_y    = 0.f;
    float target_scroll_y = 0.f;

    bool  sb_dragging = false;
    float sb_drag_offset = 0.f;


    bool  goto_visible = false;
    char  goto_buf[20] = {};


    bool  search_visible = false;
    char  search_buf[64] = {};
    bool  search_hex     = true;
    int   search_match   = -1;
};

inline state_t g_state;

void set_data(const std::vector<uint8_t>& bytes, uint64_t base_addr,
              const std::string& name = "");
void load_from_file(const std::string& path, size_t offset = 0, size_t size = 0);
bool read_from_process(uint64_t address, size_t size);
void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

}
