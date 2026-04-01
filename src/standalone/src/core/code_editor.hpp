#pragma once


#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace code_editor_widget {


struct selection_t {
    int  anchor_line = 0;
    int  anchor_col  = 0;
    int  caret_line  = 0;
    int  caret_col   = 0;
    bool active      = false;

    bool has_selection() const {
        return active && (anchor_line != caret_line || anchor_col != caret_col);
    }
    void clear() { active = false; anchor_line = caret_line; anchor_col = caret_col; }
};


struct undo_entry_t {
    std::string text;
    int         caret_line = 0;
    int         caret_col  = 0;
};


struct find_state_t {
    bool visible          = false;
    bool replace_mode     = false;
    char find_buf[256]    = {};
    char replace_buf[256] = {};
    bool case_sensitive   = false;
    bool whole_word       = false;
    int  current_match    = -1;
    int  total_matches    = 0;
    std::vector<std::pair<int,int>> match_positions;
};


struct goto_state_t {
    bool visible      = false;
    char line_buf[16] = {};
};


void init();


void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);


void on_text_changed();


void get_caret(int& line, int& col);


void trigger_undo();
void trigger_redo();
void open_find();
void open_replace();

}
