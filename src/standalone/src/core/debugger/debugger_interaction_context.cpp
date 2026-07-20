#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/debugger_preview_runtime.hpp"
#else
#include "../runtime/standalone_driver.hpp"
#include "../runtime/standalone_driver_identity.hpp"
#endif

#include "debugger_interaction_context.hpp"
#include "debugger_engine.hpp"
#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"

#include "imgui.h"

#include <atomic>
#include <algorithm>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace debugger_interaction {
namespace {

std::atomic<std::uint64_t> g_stop_generation{1};
std::uint32_t g_target_pid = 0;
std::uint64_t g_target_process_creation_time_100ns = 0;
bool g_stopped = true;
std::uint64_t g_stop_address = 0;
std::uint32_t g_stop_thread = 0;
context_t g_selected;
std::vector<context_t> g_selected_set;
std::weak_ptr<aida::analysis::analysis_workspace_t> g_published_workspace;
std::string g_published_entity_key;
std::uint64_t g_published_document_id = 0;

constexpr std::size_t k_maximum_selected_contexts = 4096;

void mix_hash(std::uint64_t& hash, std::uint64_t value) noexcept {
	for (unsigned shift = 0; shift < 64; shift += 8) {
		hash ^= static_cast<std::uint8_t>(value >> shift);
		hash *= 1099511628211ULL;
	}
}

void mix_hash(std::uint64_t& hash, std::string_view value) noexcept {
	for (const unsigned char byte : value) {
		hash ^= byte;
		hash *= 1099511628211ULL;
	}
}

std::uint64_t context_hash(const context_t& context) noexcept {
	std::uint64_t hash = 1469598103934665603ULL;
	mix_hash(hash, static_cast<std::uint64_t>(context.kind));
	mix_hash(hash, context.target_pid);
	mix_hash(hash, context.process_creation_time_100ns);
	mix_hash(hash, context.stop_generation);
	mix_hash(hash, context.address);
	mix_hash(hash, context.value);
	mix_hash(hash, context.extent);
	mix_hash(hash, context.thread_id);
	mix_hash(hash, static_cast<std::uint64_t>(static_cast<std::int64_t>(context.index)));
	mix_hash(hash, context.primary_text);
	mix_hash(hash, context.secondary_text);
	return hash;
}

bool same_identity(const context_t& left, const context_t& right) noexcept {
	return left.kind == right.kind && left.target_pid == right.target_pid &&
		left.process_creation_time_100ns == right.process_creation_time_100ns &&
		left.stop_generation == right.stop_generation && left.address == right.address &&
		left.value == right.value && left.extent == right.extent &&
		left.thread_id == right.thread_id && left.index == right.index &&
		left.primary_text == right.primary_text && left.secondary_text == right.secondary_text;
}

const aida::workbench::selection_context_t* focused_selection(
	const aida::workbench::workbench_shell_workspace_context_t& context,
	std::uint64_t* document_id = nullptr) noexcept {
	const auto focused_view = std::find_if(context.persistence.views.begin(),
		context.persistence.views.end(), [](const auto& view) { return view.focused; });
	if (focused_view == context.persistence.views.end()) return nullptr;
	const auto found = std::find_if(context.persistence.documents.begin(),
		context.persistence.documents.end(), [&](const auto& document) {
			return document.id == focused_view->document;
		});
	if (found == context.persistence.documents.end()) return nullptr;
	if (document_id) *document_id = found->id.value;
	return &found->local_state.selection;
}

void clear_published_selection_if_owned() {
	auto workspace = g_published_workspace.lock();
	if (!workspace || g_published_entity_key.empty() || g_published_document_id == 0) {
		g_published_workspace.reset();
		g_published_entity_key.clear();
		g_published_document_id = 0;
		return;
	}
	aida::workbench::workbench_shell_workspace_context_t current;
	auto& runtime = aida::workbench::workbench_shell_runtime_t::instance();
	if (runtime.workspace_context(workspace, current).ok()) {
		std::uint64_t document_id = 0;
		const auto* selection = focused_selection(current, &document_id);
		if (selection && selection->kind == aida::workbench::selection_kind_t::entity &&
			document_id == g_published_document_id &&
			selection->entity_key == g_published_entity_key) {
			aida::workbench::workbench_shell_workspace_context_t ignored;
			static_cast<void>(runtime.publish_selection(workspace, {}, {},
				aida::workbench::navigation_origin_t::user, ignored));
		}
	}
	g_published_workspace.reset();
	g_published_entity_key.clear();
	g_published_document_id = 0;
}

std::uint64_t current_process_creation_time(std::uint32_t pid) {
	if (pid == 0) return 0;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	return 1;
#else
	static int cached_frame = -1;
	static std::uint32_t cached_pid = 0;
	static std::uint64_t cached_creation = 0;
	const int frame = ImGui::GetFrameCount();
	if (cached_frame == frame && cached_pid == pid) return cached_creation;
	driver_bridge::identity::live_target_identity_t identity;
	std::string error;
	cached_creation = driver_bridge::identity::capture_live_target_identity(
		pid, 0, identity, &error) ? identity.process.creation_time_100ns : 0;
	cached_pid = pid;
	cached_frame = frame;
	return cached_creation;
#endif
}

void publish_selection(const context_t& focused,
	const std::vector<context_t>& contexts) {
	if (focused.kind == kind_t::none || contexts.empty()) {
		clear_published_selection_if_owned();
		return;
	}
	const auto workspace_context = disasm_view::capture_selected_workspace();
	if (!workspace_context.workspace || workspace_context.workspace->closing() ||
		workspace_context.workspace->closed()) {
		clear_published_selection_if_owned();
		return;
	}
	const auto process = workspace_context.workspace->identity().process();
	if (!process || process->pid != focused.target_pid ||
		process->creation_time_100ns != focused.process_creation_time_100ns) {
		clear_published_selection_if_owned();
		return;
	}
	const auto previous_workspace = g_published_workspace.lock();
	if (previous_workspace && previous_workspace != workspace_context.workspace)
		clear_published_selection_if_owned();
	std::uint64_t set_hash = 1469598103934665603ULL;
	for (const auto& context : contexts)
		mix_hash(set_hash, context_hash(context));
	aida::workbench::selection_context_t selection;
	selection.kind = aida::workbench::selection_kind_t::entity;
	selection.entity_key = "debugger.pid." + std::to_string(focused.target_pid) +
		".stop." + std::to_string(focused.stop_generation) + ".kind." +
		std::to_string(static_cast<unsigned>(focused.kind)) + ".focus." +
		std::to_string(context_hash(focused)) + ".set." + std::to_string(set_hash);
	aida::workbench::document_local_cursor_t cursor;
	const std::uint64_t position = focused.address != 0 ? focused.address : focused.value;
	if (position != 0) {
		cursor.has_position = true;
		cursor.position = position;
	}
	aida::workbench::workbench_shell_workspace_context_t output;
	if (aida::workbench::workbench_shell_runtime_t::instance().publish_selection(
			workspace_context.workspace, selection, cursor,
			aida::workbench::navigation_origin_t::user, output).ok()) {
		g_published_workspace = workspace_context.workspace;
		g_published_entity_key = std::move(selection.entity_key);
		std::uint64_t document_id = 0;
		static_cast<void>(focused_selection(output, &document_id));
		g_published_document_id = document_id;
	} else {
		clear_published_selection_if_owned();
	}
}

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
	synchronize_target_snapshot(target_pid, stopped, stop_address, stop_thread);
}

void synchronize_target_snapshot(std::uint32_t target_pid, bool stopped,
	std::uint64_t stop_address, std::uint32_t stop_thread) {
	if (!stopped || target_pid == 0) {
		stop_address = 0;
		stop_thread = 0;
	}
	const std::uint64_t process_creation_time_100ns =
		current_process_creation_time(target_pid);
	if (target_pid != g_target_pid ||
		process_creation_time_100ns != g_target_process_creation_time_100ns ||
		stopped != g_stopped ||
		(stopped && g_stopped && target_pid != 0 &&
			(stop_address != g_stop_address || stop_thread != g_stop_thread))) {
		g_stop_generation.fetch_add(1, std::memory_order_acq_rel);
		g_selected = {};
		g_selected_set.clear();
		clear_published_selection_if_owned();
	}
	g_target_pid = target_pid;
	g_target_process_creation_time_100ns = process_creation_time_100ns;
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
	g_selected_set.clear();
	clear_published_selection_if_owned();
}

context_t capture(kind_t kind, std::uint64_t address, std::uint64_t value,
	int index, std::uint32_t thread_id, std::uint64_t extent,
	std::string primary_text, std::string secondary_text) {
	context_t context;
	context.kind = kind;
	context.target_pid = driver_bridge::attached_pid();
	context.process_creation_time_100ns = g_target_process_creation_time_100ns;
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
	if (context.kind == kind_t::none) {
		clear();
		return;
	}
	g_selected = std::move(context);
	g_selected_set.assign(1, g_selected);
	publish_selection(g_selected, g_selected_set);
}

void select_set(std::vector<context_t> contexts, context_t focused) {
	if (focused.kind == kind_t::none || contexts.empty()) {
		clear();
		return;
	}
	contexts.erase(std::remove_if(contexts.begin(), contexts.end(), [&](const context_t& item) {
		return item.kind != focused.kind || item.target_pid != focused.target_pid ||
			item.process_creation_time_100ns != focused.process_creation_time_100ns ||
			item.stop_generation != focused.stop_generation;
	}), contexts.end());
	std::sort(contexts.begin(), contexts.end(), [](const context_t& left, const context_t& right) {
		if (left.index != right.index) return left.index < right.index;
		return context_hash(left) < context_hash(right);
	});
	contexts.erase(std::unique(contexts.begin(), contexts.end(), same_identity), contexts.end());
	if (contexts.size() > k_maximum_selected_contexts)
		contexts.resize(k_maximum_selected_contexts);
	if (std::none_of(contexts.begin(), contexts.end(), [&](const context_t& item) {
		return same_identity(item, focused);
	})) {
		if (contexts.size() == k_maximum_selected_contexts)
			contexts.pop_back();
		contexts.push_back(focused);
	}
	g_selected = std::move(focused);
	g_selected_set = std::move(contexts);
	publish_selection(g_selected, g_selected_set);
}

const context_t& selected() {
	return g_selected;
}

const std::vector<context_t>& selected_set() {
	return g_selected_set;
}

bool selected_in_set(const context_t& context) {
	return std::any_of(g_selected_set.begin(), g_selected_set.end(),
		[&](const context_t& item) { return same_identity(item, context); });
}

void clear() {
	g_selected = {};
	g_selected_set.clear();
	clear_published_selection_if_owned();
}

bool is_current(const context_t& context) {
	return context.kind != kind_t::none && context.target_pid != 0 &&
		context.target_pid == driver_bridge::attached_pid() &&
		context.process_creation_time_100ns != 0 &&
		context.process_creation_time_100ns == g_target_process_creation_time_100ns &&
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
