#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/debugger_preview_runtime.hpp"
#else
#include "../runtime/standalone_driver.hpp"
#endif

#include "debugger_interaction_context.hpp"
#include "debugger_engine.hpp"

#include "imgui.h"

#include <atomic>
#include <utility>

namespace debugger_interaction {
namespace {

std::atomic<std::uint64_t> g_stop_generation{1};
std::uint32_t g_target_pid = 0;
bool g_stopped = true;
std::uint64_t g_stop_address = 0;
std::uint32_t g_stop_thread = 0;
context_t g_selected;

capability_result_t allowed() {
	return {true, nullptr};
}

capability_result_t denied(const char* reason) {
	return {false, reason};
}

bool is_mutation(capability_t capability) {
	switch (capability) {
		case capability_t::edit_register:
		case capability_t::set_instruction_pointer:
		case capability_t::run_to_address:
		case capability_t::toggle_breakpoint:
		case capability_t::edit_breakpoint:
		case capability_t::remove_breakpoint:
		case capability_t::change_memory_protection:
		case capability_t::suspend_thread:
		case capability_t::resume_thread:
		case capability_t::terminate_thread:
		case capability_t::switch_thread:
		case capability_t::close_handle:
		case capability_t::apply_patch:
		case capability_t::revert_patch:
		case capability_t::remove_patch:
		case capability_t::unload_module:
			return true;
		default:
			return false;
	}
}

bool needs_paused_target(capability_t capability) {
	switch (capability) {
		case capability_t::edit_register:
		case capability_t::set_instruction_pointer:
		case capability_t::run_to_address:
		case capability_t::toggle_breakpoint:
		case capability_t::change_memory_protection:
		case capability_t::apply_patch:
		case capability_t::revert_patch:
		case capability_t::remove_patch:
			return true;
		default:
			return false;
	}
}

bool needs_kernel_session(capability_t capability) {
	switch (capability) {
		case capability_t::change_memory_protection:
		case capability_t::suspend_thread:
		case capability_t::resume_thread:
		case capability_t::terminate_thread:
		case capability_t::close_handle:
			return true;
		default:
			return false;
	}
}

}

void synchronize_target(std::uint32_t target_pid, bool stopped) {
	std::uint64_t stop_address = 0;
	std::uint32_t stop_thread = 0;
	if (target_pid != 0 && stopped) {
		stop_address = debugger_engine::cached_registers().rip;
		stop_thread = debugger_engine::g_state.active_tid;
	}
	if (target_pid != g_target_pid || (!g_stopped && stopped) ||
		(stopped && g_stopped && target_pid != 0 &&
			(stop_address != g_stop_address || stop_thread != g_stop_thread))) {
		g_stop_generation.fetch_add(1, std::memory_order_acq_rel);
		g_selected = {};
	}
	g_target_pid = target_pid;
	g_stopped = stopped;
	g_stop_address = stop_address;
	g_stop_thread = stop_thread;
}

std::uint64_t current_stop_generation() {
	return g_stop_generation.load(std::memory_order_acquire);
}

void advance_stop_generation() {
	g_stop_generation.fetch_add(1, std::memory_order_acq_rel);
	g_selected = {};
}

context_t capture(kind_t kind, std::uint64_t address, std::uint64_t value,
	int index, std::uint32_t thread_id, std::uint64_t extent,
	std::string primary_text, std::string secondary_text) {
	context_t context;
	context.kind = kind;
	context.target_pid = driver_bridge::attached_pid();
	context.stop_generation = current_stop_generation();
	context.address = address;
	context.value = value;
	context.extent = extent;
	context.thread_id = thread_id;
	context.index = index;
	context.primary_text = std::move(primary_text);
	context.secondary_text = std::move(secondary_text);
	return context;
}

void select(context_t context) {
	g_selected = std::move(context);
}

const context_t& selected() {
	return g_selected;
}

void clear() {
	g_selected = {};
}

bool is_current(const context_t& context) {
	return context.kind != kind_t::none && context.target_pid != 0 &&
		context.target_pid == driver_bridge::attached_pid() &&
		context.stop_generation == current_stop_generation();
}

capability_result_t evaluate(capability_t capability, const context_t& context) {
	if (capability == capability_t::copy)
		return context.kind == kind_t::none ? denied("Select an item first.") : allowed();
	if (capability == capability_t::unload_module)
		return denied("The debugger engine does not expose a safe module-unload operation.");
	if (context.kind == kind_t::none)
		return denied("Select an item first.");
	if (capability == capability_t::follow_disassembly &&
		context.address == 0 && context.value == 0)
		return denied("The selected item has no instruction address.");
	if (capability == capability_t::follow_memory && context.address == 0 && context.value == 0)
		return denied("The selected item has no memory address.");
	if (capability == capability_t::edit_register && context.kind != kind_t::register_value)
		return denied("Select an editable register.");
	if ((capability == capability_t::set_instruction_pointer ||
		capability == capability_t::run_to_address) && context.address == 0)
		return denied("The selected item has no executable address.");
	if ((capability == capability_t::change_memory_protection ||
		capability == capability_t::dump_memory) &&
		(context.kind != kind_t::memory_region || context.address == 0 || context.extent == 0))
		return denied("Select a current memory-map region.");
	if ((capability == capability_t::toggle_breakpoint ||
		capability == capability_t::edit_breakpoint ||
		capability == capability_t::remove_breakpoint) &&
		context.kind != kind_t::breakpoint && context.kind != kind_t::instruction)
		return denied("Select an instruction or breakpoint.");
	if ((capability == capability_t::suspend_thread ||
		capability == capability_t::resume_thread ||
		capability == capability_t::terminate_thread ||
		capability == capability_t::switch_thread) && context.thread_id == 0)
		return denied("The selected item has no live thread identity.");
	if (capability == capability_t::close_handle &&
		(context.kind != kind_t::handle || context.value == 0))
		return denied("Select a live target handle.");
	if ((capability == capability_t::apply_patch ||
		capability == capability_t::remove_patch) &&
		(context.kind != kind_t::patch || context.index < 0))
		return denied("Select a patch definition.");
	if (capability == capability_t::revert_patch &&
		context.kind != kind_t::patch)
		return denied("Select a patch definition.");
	if (context.target_pid == 0 || driver_bridge::attached_pid() == 0)
		return denied("No target process is attached.");
	if (!is_current(context))
		return denied("The debugger stopped or changed targets; select the item again.");
	if (!is_mutation(capability))
		return allowed();
	if (!driver_bridge::is_loaded())
		return denied("The driver bridge is unavailable.");
	if (needs_paused_target(capability)) {
		const debugger_engine::dbg_status_t status =
			debugger_engine::g_state.status.load(std::memory_order_acquire);
		if (status != debugger_engine::dbg_status_t::paused &&
			status != debugger_engine::dbg_status_t::stepping)
			return denied("Pause the target before changing execution or memory state.");
	}
	if (needs_kernel_session(capability)) {
		std::string reason;
		if (!driver_bridge::using_kernel_driver() ||
			!driver_bridge::kernel_session_available(&reason) ||
			!driver_bridge::dynamic_ioctls_ready())
			return denied("A verified kernel session with dynamic IOCTLs is required.");
	}
	return allowed();
}

bool context_key_pressed() {
	const ImGuiIO& io = ImGui::GetIO();
	return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		(io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

}
