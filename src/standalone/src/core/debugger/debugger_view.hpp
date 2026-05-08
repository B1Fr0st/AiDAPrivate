#pragma once

#include <cstdint>
#include "transition.hpp"

namespace debugger_view {

enum class sub_tab_t : int {
	cpu = 0,
	breakpoints,
	memory_map,
	call_stack,
	threads,
	watches,
	handles,
	trace_log,
	strings,
	bookmarks,
	modules,
	patches,
	seh_chain,
	cfg,
	COUNT
};

struct list_panel_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	int   selected = -1;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
};

struct toolbar_state_t {
	aida::ui::hover_state_t hover[6];
	aida::ui::press_state_t press[6];
};

struct tab_animator_t {
	float    direction = 0.f;
	aida::ui::transition_t slide;
};

struct register_cell_t {
	float   change_anim = 0.f;
	float   edge_intensity = 0.f;
	uint64_t shown_value = 0;
	uint64_t target_value = 0;
};

struct ui_state_t {
	sub_tab_t active_tab = sub_tab_t::cpu;
	sub_tab_t prev_tab   = sub_tab_t::cpu;

	float tab_anim[static_cast<int>(sub_tab_t::COUNT)] = {};

	float tab_scroll_x        = 0.f;
	float tab_target_scroll_x = 0.f;
	float underline_x         = 0.f;
	float underline_w         = 0.f;
	float underline_vel       = 0.f;
	float content_fade        = 1.f;

	tab_animator_t tab_animator;

	float disasm_scroll_y = 0.f;
	float disasm_target_scroll_y = 0.f;
	int   disasm_selected = -1;

	float reg_scroll_y = 0.f;
	float dump_scroll_y = 0.f;
	float stack_scroll_y = 0.f;

	uint64_t dump_address = 0;
	char     dump_goto_buf[20] = {};

	list_panel_state_t bp_panel;
	list_panel_state_t callstack_panel;
	list_panel_state_t threads_panel;
	list_panel_state_t watch_panel;
	list_panel_state_t handle_panel;
	list_panel_state_t trace_panel;
	list_panel_state_t strings_panel;
	list_panel_state_t bookmark_panel;
	list_panel_state_t patches_panel;

	float memmap_scroll_y        = 0.f;
	float memmap_target_scroll_y = 0.f;
	int   memmap_selected        = -1;

	float trace_scroll_y        = 0.f;
	float trace_target_scroll_y = 0.f;
	int   trace_selected        = -1;

	float strings_scroll_y        = 0.f;
	float strings_target_scroll_y = 0.f;
	int   strings_selected        = -1;

	int   list_selected = -1;

	char  string_filter[128] = {};
	int   string_min_len = 4;

	uint64_t prev_regs[18] = {};
	float    reg_flash[18] = {};
	register_cell_t reg_cells[18] = {};

	uint64_t prev_rip = 0;
	float    rip_flash = 0.f;

	float panel_sep_phase = 0.f;
	float empty_phase = 0.f;

	float bp_scroll_y = 0.f;
	float callstack_scroll_y = 0.f;
	float watch_scroll_y = 0.f;
	float bookmark_scroll_y = 0.f;
	float handle_scroll_y = 0.f;

	float row_hover_anim[64] = {};

	toolbar_state_t toolbar;

	uint32_t prev_thread_state[256] = {};
	float    thread_state_flash[256] = {};

	float    record_pulse = 0.f;
};

inline ui_state_t g_ui;

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);

}
