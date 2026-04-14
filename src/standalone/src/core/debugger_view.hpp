#pragma once

#include <cstdint>

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

	float disasm_scroll_y = 0.f;
	float disasm_target_scroll_y = 0.f;
	int   disasm_selected = -1;

	float reg_scroll_y = 0.f;
	float dump_scroll_y = 0.f;
	float stack_scroll_y = 0.f;

	uint64_t dump_address = 0;
	char     dump_goto_buf[20] = {};

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
	uint64_t prev_rip = 0;
	float    rip_flash = 0.f;

	float panel_sep_phase = 0.f;
	float empty_phase = 0.f;

	float row_hover_anim[64] = {};
};

inline ui_state_t g_ui;

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);

}
