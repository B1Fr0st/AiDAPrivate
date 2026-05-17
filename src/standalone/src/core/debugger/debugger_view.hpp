#pragma once

#include <cstdint>
#include <string>
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
	aida::ui::hover_state_t hover[8];
	aida::ui::press_state_t press[8];
};

struct tab_animator_t {
	float    direction = 0.f;
	aida::ui::transition_t slide;
};

struct ui_state_t {
	sub_tab_t active_tab = sub_tab_t::cpu;
	sub_tab_t prev_tab   = sub_tab_t::cpu;

	float tab_anim[static_cast<int>(sub_tab_t::COUNT)] = {};

	float tab_scroll_x        = 0.f;
	float tab_target_scroll_x = 0.f;
	int   tab_last_ensured    = -1;
	float underline_x         = 0.f;
	float underline_w         = 0.f;
	float underline_vel       = 0.f;
	float content_fade        = 1.f;

	tab_animator_t tab_animator;

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

	char     add_bp_addr_buf[24] = {};
	char     add_watch_buf[96] = {};
	char     add_bookmark_buf[24] = {};
	char     add_bookmark_label_buf[64] = {};
	char     trace_filter_buf[96] = {};

	list_panel_state_t cpu_panel;
	float    cpu_scroll_y = 0.f;
	int      cpu_edit_reg_idx = -1;
	char     cpu_edit_value_buf[24] = {};
	bool     cpu_edit_popup_open = false;

	uint64_t cpu_prev_reg_values[32] = {};
	float    cpu_reg_flash[32] = {};
	bool     cpu_prev_reg_initialized = false;
	float    cpu_reg_scroll_y = 0.f;
	float    cpu_stack_scroll_y = 0.f;
	int      cpu_stack_selected = -1;
	int      cpu_disasm_selected = -1;
	uint64_t cpu_disasm_anchor_rip = 0;
	int      cpu_context_reg_idx = -1;
	bool     cpu_context_open = false;
	int      cpu_stack_context_idx = -1;
	bool     cpu_stack_context_open = false;
	int      cpu_disasm_context_idx = -1;
	bool     cpu_disasm_context_open = false;
	uint64_t cpu_disasm_context_target = 0;
	uint64_t cpu_disasm_context_addr = 0;

	int      bp_edit_idx = -1;
	char     bp_edit_condition_buf[160] = {};
	char     bp_edit_log_buf[160] = {};
	bool     bp_edit_auto_continue = false;
	bool     bp_edit_popup_open = false;

	int      handle_close_idx = -1;
	uint64_t handle_close_value = 0;
	std::string handle_close_type;
	std::string handle_close_name;
	bool     handle_close_popup_open = false;

	int      thread_kill_idx = -1;
	uint32_t thread_kill_tid = 0;
	bool     thread_kill_popup_open = false;

	uint64_t cfg_last_built_addr = 0;

	bool     seh_break_request_active = false;
};

inline ui_state_t g_ui;

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);

}
