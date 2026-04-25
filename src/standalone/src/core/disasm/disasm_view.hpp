#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct DisasmFile;
struct DisasmState;

namespace xref_engine {
enum class xref_type_t : int;
struct xref_t;
}

namespace cfg_view {
struct cfg_state_t;
}

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

struct xref_popup_entry_t {
    uint64_t    addr = 0;
    int         type = 0;
    std::string disasm_text;
    std::string module_name;
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

    bool  sb_dragging = false;
    float sb_drag_offset = 0.f;
    float bm_scroll_x = 0.f;

    int selected_row = -1;

    int ctx_row = -1;

    bool  graph_mode = false;
    float graph_crossfade = 0.f;
    bool  cfg_needs_build = false;
    uint64_t cfg_entry_addr = 0;

    bool  xref_popup_open = false;
    uint64_t xref_popup_addr = 0;
    float xref_popup_fade = 0.f;
    float xref_popup_scroll = 0.f;
    float xref_popup_target_scroll = 0.f;
    int   xref_popup_selected = -1;
    bool  xref_popup_sb_dragging = false;
    float xref_popup_sb_drag_offset = 0.f;
    char  xref_popup_filter[96] = {};
    std::vector<xref_popup_entry_t> xref_results;
    std::atomic<bool> xref_scanning{false};
    std::mutex xref_mutex;
};

inline state_t g_state;

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b,
            DisasmState& disasm, float dt);

void goto_address(uint64_t addr, DisasmState& disasm);
void navigate_back();
void navigate_forward();

}
