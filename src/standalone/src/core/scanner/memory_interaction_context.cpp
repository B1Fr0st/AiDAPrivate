#include "memory_interaction_context.hpp"

#include "imgui/imgui.h"

#include <utility>
#include <mutex>

namespace memory_interaction {
namespace {

std::mutex g_selection_mutex;
context_t g_selected;
std::uint64_t g_selection_generation = 0;

capability_result_t allowed() {
	return {true, nullptr};
}

}

context_t capture_pointer_chain(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string module_offset) {
	context_t context;
	context.kind = kind_t::pointer_chain;
	context.source = runtime.live_attached ? source_t::live_process : source_t::none;
	context.target_pid = runtime.target_pid;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.module_offset = std::move(module_offset);
	return context;
}

context_t capture_memory_range(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string module_offset) {
	context_t context;
	context.kind = kind_t::memory_range;
	context.source = runtime.live_attached ? source_t::live_process :
		(runtime.static_loaded ? source_t::static_binary : source_t::none);
	context.target_pid = runtime.target_pid;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.module_offset = std::move(module_offset);
	return context;
}

context_t capture_patch(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string value) {
	context_t context;
	context.kind = kind_t::patch_record;
	context.source = runtime.live_attached ? source_t::live_process : source_t::none;
	context.target_pid = runtime.target_pid;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.value = std::move(value);
	return context;
}

void select(context_t context) {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	g_selected = std::move(context);
	++g_selection_generation;
}

context_t selected() {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	return g_selected;
}

void clear_selection() {
	select({});
}

std::uint64_t selection_generation() {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	return g_selection_generation;
}

namespace {

capability_result_t denied(const char* reason) {
	return {false, reason};
}

bool live_mutation(capability_t capability) {
	switch (capability) {
		case capability_t::add_to_address_list:
		case capability_t::change_value:
		case capability_t::freeze:
		case capability_t::unfreeze:
		case capability_t::stage_patch:
		case capability_t::revert_patch:
			return true;
		default:
			return false;
	}
}

}

context_t capture_result(const runtime_t& runtime, std::uint64_t address,
	int index, std::string value, std::string previous_value,
	std::string module_offset) {
	context_t context;
	context.kind = kind_t::scan_result;
	context.source = runtime.live_attached ? source_t::live_process :
		(runtime.static_loaded ? source_t::static_binary : source_t::none);
	context.target_pid = runtime.target_pid;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.index = index;
	context.value = std::move(value);
	context.previous_value = std::move(previous_value);
	context.module_offset = std::move(module_offset);
	return context;
}

context_t capture_address(const runtime_t& runtime, std::uint64_t address,
	int index, bool frozen, std::string value) {
	context_t context;
	context.kind = kind_t::address_entry;
	context.source = runtime.live_attached ? source_t::live_process : source_t::none;
	context.target_pid = runtime.target_pid;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.index = index;
	context.frozen = frozen;
	context.value = std::move(value);
	return context;
}

bool is_current(const context_t& context, const runtime_t& runtime) {
	if (context.kind == kind_t::none || context.address == 0)
		return false;
	if (context.source == source_t::live_process)
		return runtime.live_attached && context.target_pid != 0 &&
			context.target_pid == runtime.target_pid &&
			(context.kind != kind_t::scan_result ||
				context.scan_revision == runtime.scan_revision);
	if (context.source == source_t::static_binary)
		return runtime.static_loaded && context.scan_revision == runtime.scan_revision;
	return false;
}

capability_result_t evaluate(capability_t capability,
	const context_t& context, const runtime_t& runtime) {
	if (context.kind == kind_t::none)
		return denied("Select a scan result or address-list entry first.");
	if (context.address == 0)
		return denied("The selected item has no usable address.");
	if (capability == capability_t::copy_value && context.value.empty())
		return denied("The selected item has no current value.");
	if (capability == capability_t::copy_previous_value &&
		context.previous_value.empty())
		return denied("The selected result has no previous value.");
	if (capability == capability_t::copy_module_offset &&
		context.module_offset.empty())
		return denied("The selected result has no module-relative identity.");
	if (capability == capability_t::add_to_address_list &&
		context.kind != kind_t::scan_result)
		return denied("Select a scan result to add it to the address list.");
	if ((capability == capability_t::edit_description ||
		capability == capability_t::change_type ||
		capability == capability_t::change_value ||
		capability == capability_t::freeze ||
		capability == capability_t::unfreeze ||
		capability == capability_t::remove) &&
		context.kind != kind_t::address_entry)
		return denied("Select an address-list entry for this action.");
	if (capability == capability_t::copy_address ||
		capability == capability_t::edit_description ||
		capability == capability_t::change_type ||
		capability == capability_t::remove)
		return allowed();
	if (!is_current(context, runtime))
		return denied("The target or scan changed; select the item again.");
	if (capability == capability_t::freeze && context.frozen)
		return denied("The selected address is already frozen.");
	if (capability == capability_t::freeze && context.value.empty())
		return denied("Refresh the address successfully before freezing its value.");
	if (capability == capability_t::unfreeze && !context.frozen)
		return denied("The selected address is not frozen.");
	if (capability == capability_t::stage_patch ||
		capability == capability_t::revert_patch) {
		if (capability == capability_t::revert_patch)
			return denied("Use the Patches view for staged patch review and reversal.");
	}
	if (live_mutation(capability)) {
		if (!runtime.live_attached || runtime.target_pid == 0)
			return denied("Attach a live process before changing memory.");
		if (!runtime.driver_loaded)
			return denied("The verified driver bridge is unavailable.");
	}
	if ((capability == capability_t::open_hex ||
		capability == capability_t::open_disassembly) &&
		context.source == source_t::none)
		return denied("No live or static memory source is available.");
	if (capability == capability_t::open_hex &&
		context.source == source_t::static_binary)
		return denied("This scanner selection has no static Hex reader; open the binary Hex document instead.");
	return allowed();
}

bool context_key_pressed() {
	const ImGuiIO& io = ImGui::GetIO();
	return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
		(io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

}
