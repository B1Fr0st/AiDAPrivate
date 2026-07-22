#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "transition.hpp"
#include "debugger_interaction_context.hpp"

namespace debugger_view {

enum class execution_command_t : std::uint8_t {
	launch,
	run_continue,
	pause,
	step_over,
	step_into,
	step_out,
	stop,
	restart,
	detach,
	toggle_breakpoint_at_instruction_pointer
};

enum class patch_panel_command_t : std::uint8_t {
	stage,
	find_code_caves,
	revert_all,
	save_patchset
};

enum class breakpoint_definition_mode_t : std::uint8_t {
	software,
	hardware_execute
};

struct execution_capability_t {
	bool enabled = false;
	const char* disabled_reason = nullptr;
};

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
	source,
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
	bool     add_bp_staged = false;
	breakpoint_definition_mode_t add_bp_staged_mode =
		breakpoint_definition_mode_t::software;
	debugger_interaction::context_t add_bp_staged_context;
	char     add_watch_buf[96] = {};
	char     add_bookmark_buf[24] = {};
	char     add_bookmark_label_buf[64] = {};
	char     trace_filter_buf[96] = {};
	bool     trace_freeze_display = false;

	list_panel_state_t cpu_panel;
	float    cpu_scroll_y = 0.f;
	int      cpu_edit_reg_idx = -1;
	char     cpu_edit_value_buf[24] = {};
	bool     cpu_edit_popup_open = false;
	debugger_interaction::context_t cpu_edit_context;

	uint64_t cpu_prev_reg_values[32] = {};
	float    cpu_reg_flash[32] = {};
	bool     cpu_prev_reg_initialized = false;
	float    cpu_reg_scroll_y = 0.f;
	float    cpu_stack_scroll_y = 0.f;
	int      cpu_stack_selected = -1;
	int      cpu_disasm_selected = -1;
	uint64_t cpu_disasm_anchor_rip = 0;
	int      source_definition_selected = -1;
	int      bp_edit_idx = -1;
	char     bp_edit_condition_buf[160] = {};
	char     bp_edit_log_buf[160] = {};
	bool     bp_edit_auto_continue = false;
	bool     bp_edit_popup_open = false;
	bool     bp_edit_identity_retained = false;
	debugger_interaction::context_t bp_edit_context;
	std::uint64_t bp_edit_breakpoints_generation = 0;
	std::uint64_t bp_edit_fingerprint = 0;
	std::uint64_t bp_edit_address = 0;
	std::uint64_t bp_edit_size = 0;
	int      bp_edit_type = 0;
	std::string bp_edit_name;
	std::string bp_edit_original_condition;
	std::string bp_edit_original_log;
	bool     bp_edit_original_auto_continue = false;

	int      handle_close_idx = -1;
	uint64_t handle_close_value = 0;
	std::string handle_close_type;
	std::string handle_close_name;
	bool     handle_close_popup_open = false;
	debugger_interaction::context_t handle_close_context;

	int      thread_kill_idx = -1;
	uint32_t thread_kill_tid = 0;
	bool     thread_kill_popup_open = false;
	debugger_interaction::context_t thread_kill_context;

	uint64_t cfg_last_built_addr = 0;

	bool     seh_break_request_active = false;
	bool     patch_stage_open = false;
	std::uint64_t patch_stage_address = 0;
	std::uint64_t patch_stage_extent = 0;
	char     patch_stage_bytes_buf[12288] = {};
	char     patch_stage_description_buf[256] = {};
	std::vector<std::uint8_t> patch_stage_parsed_bytes;
	bool     patch_stage_parse_valid = false;
	bool     patch_stage_exact = false;
	debugger_interaction::context_t patch_stage_context;
	std::vector<std::uint8_t> patch_stage_expected_before;
};

inline ui_state_t g_ui;

bool is_visible_sub_tab(sub_tab_t tab);
int visible_sub_tab_count();

void render(float pos_x, float pos_y, float width, float height,
			float alpha, float accent_r, float accent_g, float accent_b);

void render_pane(sub_tab_t pane, float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b,
	bool show_execution_controls = false, bool show_status = false);
void render_execution_controls(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_global_target_dialog();
void render_global_dialogs();
execution_capability_t execution_capability(execution_command_t command);
bool execute_command(execution_command_t command, std::string* error = nullptr);
execution_capability_t patch_panel_capability(patch_panel_command_t command);
bool execute_patch_panel_command(patch_panel_command_t command, std::string* error = nullptr);
bool stage_patch_review(std::uint64_t address, std::uint64_t extent,
	const std::string& description, std::string* error = nullptr);
bool stage_patch_review(const debugger_interaction::context_t& expected_context,
	std::uint64_t extent, const std::string& description,
	std::string* error = nullptr);
bool stage_exact_patch_review(std::uint64_t address,
	const std::vector<std::uint8_t>& expected_before,
	const std::vector<std::uint8_t>& reviewed_after,
	std::uint32_t expected_pid,
	const std::string& description, std::string* error = nullptr);
bool stage_nop_review(std::uint64_t address, std::uint64_t extent,
	std::string* error = nullptr);
bool stage_nop_review(const debugger_interaction::context_t& expected_context,
	std::uint64_t extent, std::string* error = nullptr);
bool stage_breakpoint_definition(
	const debugger_interaction::context_t& expected_context,
	breakpoint_definition_mode_t mode, std::string* error = nullptr);
execution_capability_t address_mutation_capability(std::uint64_t address,
	bool toggle_breakpoint, std::uint32_t expected_pid = 0);
execution_capability_t address_mutation_capability(
	const debugger_interaction::context_t& expected_context,
	bool toggle_breakpoint);
bool queue_run_to_address(std::uint64_t address, std::uint32_t expected_pid,
	std::string* error = nullptr);
bool queue_run_to_address(const debugger_interaction::context_t& expected_context,
	std::string* error = nullptr);
bool queue_toggle_breakpoint(std::uint64_t address, std::uint32_t expected_pid,
	std::string* error = nullptr);
bool queue_toggle_breakpoint(const debugger_interaction::context_t& expected_context,
	std::string* error = nullptr);

void render_cpu_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_registers_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_stack_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_breakpoints_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_memory_map_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_call_stack_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_threads_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_watches_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_handles_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_trace_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_strings_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_bookmarks_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_modules_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_patches_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_seh_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_cfg_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);
void render_source_pane(float pos_x, float pos_y, float width, float height,
	float alpha, float accent_r, float accent_g, float accent_b);

}
