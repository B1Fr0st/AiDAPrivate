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


struct find_match_t {
    int line = 0;
    int col  = 0;
    int length = 0;
};

struct find_state_t {
    bool visible          = false;
    bool replace_mode     = false;
    char find_buf[256]    = {};
    char replace_buf[256] = {};
    bool case_sensitive   = false;
    bool whole_word       = false;
    bool use_regex        = false;
    int  current_match    = -1;
    int  total_matches    = 0;
    std::vector<find_match_t> match_positions;
};


struct goto_state_t {
    bool visible      = false;
    char line_buf[16] = {};
};


enum class diff_line_kind_t : int {
    context = 0,
    added,
    removed
};


struct diff_line_t {
    diff_line_kind_t kind = diff_line_kind_t::context;
    std::string      text;
    int              old_line = -1;
    int              new_line = -1;
};


enum class diff_hunk_state_t : int {
    pending = 0,
    accepted,
    rejected
};


struct diff_hunk_t {
    int               old_start   = 0;
    int               old_count   = 0;
    int               new_start   = 0;
    int               new_count   = 0;
    int               added       = 0;
    int               removed     = 0;
    diff_hunk_state_t state       = diff_hunk_state_t::pending;
    std::vector<diff_line_t> lines;
};


struct pending_diff_t {
    bool                     active   = false;
    std::string              origin;
    std::vector<std::string> old_lines;
    std::vector<std::string> new_lines;
    std::vector<diff_hunk_t> hunks;
    int                      total_added   = 0;
    int                      total_removed = 0;

    bool fully_resolved() const {
        for (const auto& h : hunks)
            if (h.state == diff_hunk_state_t::pending) return false;
        return true;
    }
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

std::string last_error();


bool begin_agent_edit(std::string_view origin);

bool propose_full_content(std::string_view new_content);

bool propose_replace_range(int start_line, int end_line, std::string_view replacement);

bool has_pending_diff();

const pending_diff_t& pending_diff();

int  pending_hunk_count();

bool accept_hunk(int index);

bool reject_hunk(int index);

void accept_all();

void reject_all();

void cancel_agent_edit();

}
