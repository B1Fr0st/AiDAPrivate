#pragma once

#include <cstdint>
#include <string>

namespace debugger_interaction {

enum class kind_t : std::uint8_t {
	none = 0,
	instruction,
	register_value,
	stack_slot,
	breakpoint,
	memory_region,
	stack_frame,
	thread,
	module,
	trace_record,
	handle,
	patch
};

enum class capability_t : std::uint8_t {
	copy,
	follow_disassembly,
	follow_memory,
	edit_register,
	set_instruction_pointer,
	run_to_address,
	toggle_breakpoint,
	edit_breakpoint,
	remove_breakpoint,
	change_memory_protection,
	dump_memory,
	suspend_thread,
	resume_thread,
	terminate_thread,
	switch_thread,
	close_handle,
	apply_patch,
	revert_patch,
	remove_patch,
	unload_module
};

struct context_t {
	kind_t kind = kind_t::none;
	std::uint32_t target_pid = 0;
	std::uint64_t stop_generation = 0;
	std::uint64_t address = 0;
	std::uint64_t value = 0;
	std::uint64_t extent = 0;
	std::uint32_t thread_id = 0;
	int index = -1;
	std::string primary_text;
	std::string secondary_text;
};

struct capability_result_t {
	bool enabled = false;
	const char* disabled_reason = nullptr;
};

void synchronize_target(std::uint32_t target_pid, bool stopped);
std::uint64_t current_stop_generation();
void advance_stop_generation();
context_t capture(kind_t kind, std::uint64_t address = 0,
	std::uint64_t value = 0, int index = -1, std::uint32_t thread_id = 0,
	std::uint64_t extent = 0, std::string primary_text = {},
	std::string secondary_text = {});
void select(context_t context);
const context_t& selected();
void clear();
bool is_current(const context_t& context);
capability_result_t evaluate(capability_t capability, const context_t& context);
bool context_key_pressed();

}
