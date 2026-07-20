#include "memory_interaction_context.hpp"
#include "memory_scanner.hpp"
#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"

#include "imgui/imgui.h"

#include <utility>
#include <algorithm>
#include <memory>
#include <mutex>
#include <string_view>

namespace memory_interaction {
namespace {

std::mutex g_selection_mutex;
context_t g_selected;
std::vector<context_t> g_selected_set;
std::uint64_t g_selection_generation = 0;
std::weak_ptr<aida::analysis::analysis_workspace_t> g_published_workspace;
std::string g_published_entity_key;
std::uint64_t g_published_document_id = 0;

constexpr std::size_t k_maximum_selected_contexts = 4096;

bool same_identity(const context_t& left, const context_t& right) noexcept {
	return left.kind == right.kind && left.source == right.source &&
		left.target_pid == right.target_pid && left.target_epoch == right.target_epoch &&
		left.process_creation_time_100ns == right.process_creation_time_100ns &&
		left.scan_revision == right.scan_revision && left.workspace_id == right.workspace_id &&
		left.workspace_generation == right.workspace_generation &&
		left.owner_workspace_id == right.owner_workspace_id &&
		left.owner_workspace_generation == right.owner_workspace_generation &&
		left.document_id == right.document_id &&
		left.address == right.address && left.extent == right.extent &&
		left.index == right.index;
}

void mix_hash(std::uint64_t& hash, std::uint64_t value) noexcept {
	for (unsigned shift = 0; shift < 64; shift += 8) {
		hash ^= static_cast<std::uint8_t>(value >> shift);
		hash *= 1099511628211ULL;
	}
}

void mix_hash(std::uint64_t& hash, std::string_view value) noexcept {
	for (const char character : value) {
		const auto byte = static_cast<unsigned char>(character);
		hash ^= byte;
		hash *= 1099511628211ULL;
	}
}

std::uint64_t context_hash(const context_t& context) noexcept {
	std::uint64_t hash = 14695981039346656037ULL;
	mix_hash(hash, static_cast<std::uint64_t>(context.kind));
	mix_hash(hash, static_cast<std::uint64_t>(context.source));
	mix_hash(hash, context.target_pid);
	mix_hash(hash, context.target_epoch);
	mix_hash(hash, context.process_creation_time_100ns);
	mix_hash(hash, context.scan_revision);
	mix_hash(hash, context.workspace_id);
	mix_hash(hash, context.workspace_generation);
	mix_hash(hash, context.owner_workspace_id);
	mix_hash(hash, context.owner_workspace_generation);
	mix_hash(hash, context.document_id);
	mix_hash(hash, context.address);
	mix_hash(hash, context.extent);
	mix_hash(hash, static_cast<std::uint64_t>(static_cast<std::int64_t>(context.index)));
	return hash;
}

const aida::workbench::selection_context_t* document_selection(
	const aida::workbench::workbench_shell_workspace_context_t& context,
	std::uint64_t document_id) noexcept {
	const auto found = std::find_if(context.persistence.documents.begin(),
		context.persistence.documents.end(), [document_id](const auto& document) {
			return document.id.value == document_id;
		});
	if (found == context.persistence.documents.end()) return nullptr;
	return &found->local_state.selection;
}

std::uint64_t focused_document_id(
	const aida::workbench::workbench_shell_workspace_context_t& context) noexcept {
	const auto focused = std::find_if(context.persistence.views.begin(),
		context.persistence.views.end(), [](const auto& view) { return view.focused; });
	return focused == context.persistence.views.end() ? 0 : focused->document.value;
}

std::uint64_t focused_document_id(
	const disasm_view::workspace_context_t& context) noexcept {
	if (!context.workspace) return 0;
	aida::workbench::workbench_shell_workspace_context_t workbench_context;
	if (!aida::workbench::workbench_shell_runtime_t::instance().workspace_context(
			context.workspace, workbench_context).ok())
		return 0;
	return focused_document_id(workbench_context);
}

void capture_owner(context_t& context) {
	const auto owner = disasm_view::capture_selected_workspace();
	if (!owner.workspace || owner.workspace->closing() || owner.workspace->closed())
		return;
	context.owner_workspace_id = owner.workspace->identity().binary_id().to_hex();
	context.owner_workspace_generation = owner.workspace->generation();
	context.document_id = focused_document_id(owner);
}

void clear_published_selection_if_owned() {
	auto workspace = g_published_workspace.lock();
	if (!workspace || g_published_entity_key.empty() || g_published_document_id == 0) {
		g_published_workspace.reset();
		g_published_entity_key.clear();
		g_published_document_id = 0;
		return;
	}
	auto& shell = aida::workbench::workbench_shell_runtime_t::instance();
	aida::workbench::workbench_shell_workspace_context_t current;
	if (!shell.workspace_context(workspace, current).ok()) return;
	const auto* selection = document_selection(current, g_published_document_id);
	if (!selection || selection->kind != aida::workbench::selection_kind_t::entity ||
		selection->entity_key != g_published_entity_key) {
		g_published_workspace.reset();
		g_published_entity_key.clear();
		g_published_document_id = 0;
		return;
	}
	aida::workbench::workbench_shell_workspace_context_t cleared;
	if (!shell.publish_document_selection(workspace,
			aida::workbench::document_id_t{g_published_document_id}, {}, {},
			aida::workbench::navigation_origin_t::user, cleared).ok()) return;
	const auto* cleared_selection = document_selection(cleared, g_published_document_id);
	if (cleared_selection && cleared_selection->kind ==
			aida::workbench::selection_kind_t::entity &&
		cleared_selection->entity_key == g_published_entity_key)
		return;
	g_published_workspace.reset();
	g_published_entity_key.clear();
	g_published_document_id = 0;
}

void publish_selection(const context_t& context,
	const std::vector<context_t>& contexts) {
	if (context.kind == kind_t::none || context.address == 0 || contexts.empty()) {
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
	const bool workspace_matches = context.source == source_t::live_process
		? process && process->pid == context.target_pid &&
			process->creation_time_100ns == context.process_creation_time_100ns
		: context.source == source_t::static_binary &&
			workspace_context.workspace->identity().binary_id().to_hex() == context.workspace_id &&
			workspace_context.workspace->generation() == context.workspace_generation;
	if (!workspace_matches) {
		clear_published_selection_if_owned();
		return;
	}
	const auto previous_workspace = g_published_workspace.lock();
	if (previous_workspace && (previous_workspace != workspace_context.workspace ||
		focused_document_id(workspace_context) != g_published_document_id)) {
		clear_published_selection_if_owned();
		if (g_published_document_id != 0) return;
	}
	aida::workbench::selection_context_t selection;
	selection.kind = aida::workbench::selection_kind_t::entity;
	std::uint64_t set_hash = 14695981039346656037ULL;
	for (const auto& selected : contexts) mix_hash(set_hash, context_hash(selected));
	selection.entity_key = "memory.source." + std::to_string(static_cast<unsigned>(context.source)) +
		".pid." + std::to_string(context.target_pid) + ".scan." +
		std::to_string(context.scan_revision) + ".kind." +
		std::to_string(static_cast<unsigned>(context.kind)) + ".address." +
		std::to_string(context.address) + ".index." + std::to_string(context.index) +
		".count." + std::to_string(contexts.size()) + ".set." + std::to_string(set_hash);
	aida::workbench::document_local_cursor_t cursor;
	cursor.has_position = true;
	cursor.position = context.address;
	aida::workbench::workbench_shell_workspace_context_t output;
	if (aida::workbench::workbench_shell_runtime_t::instance().publish_selection(
			workspace_context.workspace, selection, cursor,
			aida::workbench::navigation_origin_t::user, output).ok()) {
		g_published_workspace = workspace_context.workspace;
		g_published_entity_key = std::move(selection.entity_key);
		g_published_document_id = focused_document_id(output);
		const auto* published = document_selection(output, g_published_document_id);
		if (g_published_document_id == 0 || !published ||
			published->kind != aida::workbench::selection_kind_t::entity ||
			published->entity_key != g_published_entity_key)
			clear_published_selection_if_owned();
	} else {
		clear_published_selection_if_owned();
	}
}

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
	context.target_epoch = runtime.target_epoch;
	context.process_creation_time_100ns = runtime.process_creation_time_100ns;
	context.scan_revision = runtime.scan_revision;
	context.workspace_id = context.source == source_t::static_binary
		? runtime.scan_workspace_id : std::string{};
	context.workspace_generation = context.source == source_t::static_binary
		? runtime.scan_workspace_generation : 0;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.module_offset = std::move(module_offset);
	capture_owner(context);
	return context;
}

context_t capture_memory_range(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string module_offset) {
	context_t context;
	context.kind = kind_t::memory_range;
	context.source = runtime.live_attached ? source_t::live_process :
		(runtime.static_loaded ? source_t::static_binary : source_t::none);
	context.target_pid = runtime.target_pid;
	context.target_epoch = runtime.target_epoch;
	context.process_creation_time_100ns = runtime.process_creation_time_100ns;
	context.scan_revision = runtime.scan_revision;
	context.workspace_id = context.source == source_t::static_binary
		? runtime.scan_workspace_id : std::string{};
	context.workspace_generation = context.source == source_t::static_binary
		? runtime.scan_workspace_generation : 0;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.module_offset = std::move(module_offset);
	capture_owner(context);
	return context;
}

context_t capture_patch(const runtime_t& runtime, std::uint64_t address,
	std::uint64_t extent, int index, std::string value) {
	context_t context;
	context.kind = kind_t::patch_record;
	context.source = runtime.live_attached ? source_t::live_process : source_t::none;
	context.target_pid = runtime.target_pid;
	context.target_epoch = runtime.target_epoch;
	context.process_creation_time_100ns = runtime.process_creation_time_100ns;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.extent = extent;
	context.index = index;
	context.value = std::move(value);
	capture_owner(context);
	return context;
}

void select(context_t context) {
	if (context.kind == kind_t::none) {
		clear_selection();
		return;
	}
	select_set({context}, context);
}

void select_set(std::vector<context_t> contexts, context_t focused) {
	if (focused.kind == kind_t::none || contexts.empty()) {
		clear_selection();
		return;
	}
	contexts.erase(std::remove_if(contexts.begin(), contexts.end(), [&](const context_t& item) {
		return item.kind != focused.kind || item.source != focused.source ||
			item.target_pid != focused.target_pid || item.target_epoch != focused.target_epoch ||
			item.process_creation_time_100ns != focused.process_creation_time_100ns ||
			item.scan_revision != focused.scan_revision ||
			item.workspace_id != focused.workspace_id ||
			item.workspace_generation != focused.workspace_generation ||
			item.owner_workspace_id != focused.owner_workspace_id ||
			item.owner_workspace_generation != focused.owner_workspace_generation ||
			item.document_id != focused.document_id;
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
		if (contexts.size() == k_maximum_selected_contexts) contexts.pop_back();
		contexts.push_back(focused);
	}
	context_t published;
	std::vector<context_t> published_set;
	{
		std::lock_guard<std::mutex> lock(g_selection_mutex);
		g_selected = std::move(focused);
		g_selected_set = std::move(contexts);
		published = g_selected;
		published_set = g_selected_set;
		++g_selection_generation;
	}
	publish_selection(published, published_set);
}

context_t selected() {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	return g_selected;
}

std::vector<context_t> selected_set() {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	return g_selected_set;
}

bool selected_in_set(const context_t& context) {
	std::lock_guard<std::mutex> lock(g_selection_mutex);
	return std::any_of(g_selected_set.begin(), g_selected_set.end(),
		[&](const context_t& item) { return same_identity(item, context); });
}

void clear_selection() {
	{
		std::lock_guard<std::mutex> lock(g_selection_mutex);
		g_selected = {};
		g_selected_set.clear();
		++g_selection_generation;
	}
	clear_published_selection_if_owned();
}

void synchronize_selection(const runtime_t& runtime) {
	context_t current;
	{
		std::lock_guard<std::mutex> lock(g_selection_mutex);
		current = g_selected;
	}
	if (current.kind != kind_t::none && !is_current(current, runtime))
		clear_selection();
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
	context.source = runtime.scan_static_binary ? source_t::static_binary :
		(runtime.scan_target_pid != 0 ? source_t::live_process : source_t::none);
	context.target_pid = runtime.scan_static_binary ? 0 : runtime.scan_target_pid;
	context.target_epoch = runtime.scan_static_binary ? 0 : runtime.scan_target_epoch;
	context.process_creation_time_100ns = runtime.scan_static_binary ? 0 :
		runtime.scan_process_creation_time_100ns;
	context.scan_revision = runtime.scan_revision;
	context.workspace_id = runtime.scan_static_binary ? runtime.scan_workspace_id : std::string{};
	context.workspace_generation = runtime.scan_static_binary
		? runtime.scan_workspace_generation : 0;
	context.address = address;
	context.index = index;
	context.value = std::move(value);
	context.previous_value = std::move(previous_value);
	context.module_offset = std::move(module_offset);
	capture_owner(context);
	return context;
}

context_t capture_address(const runtime_t& runtime, std::uint64_t address,
	int index, bool frozen, std::string value, std::uint32_t target_pid,
	std::uint64_t target_epoch, std::uint64_t process_creation_time_100ns) {
	context_t context;
	context.kind = kind_t::address_entry;
	context.source = runtime.live_attached ? source_t::live_process : source_t::none;
	context.target_pid = target_pid != 0 ? target_pid : runtime.target_pid;
	context.target_epoch = target_epoch != 0 ? target_epoch : runtime.target_epoch;
	context.process_creation_time_100ns = process_creation_time_100ns != 0
		? process_creation_time_100ns : runtime.process_creation_time_100ns;
	context.scan_revision = runtime.scan_revision;
	context.address = address;
	context.index = index;
	context.frozen = frozen;
	context.value = std::move(value);
	capture_owner(context);
	return context;
}

bool is_current(const context_t& context, const runtime_t& runtime) {
	if (context.kind == kind_t::none || context.address == 0)
		return false;
	const auto owner = disasm_view::capture_selected_workspace();
	if (context.owner_workspace_id.empty() || context.owner_workspace_generation == 0 ||
		context.document_id == 0 || !owner.workspace || owner.workspace->closing() ||
		owner.workspace->closed() ||
		owner.workspace->identity().binary_id().to_hex() != context.owner_workspace_id ||
		owner.workspace->generation() != context.owner_workspace_generation ||
		focused_document_id(owner) != context.document_id)
		return false;
	if (context.source == source_t::live_process)
		return runtime.live_attached && context.target_pid != 0 &&
			context.target_pid == runtime.target_pid &&
			context.target_epoch != 0 && context.target_epoch == runtime.target_epoch &&
			context.process_creation_time_100ns != 0 &&
			context.process_creation_time_100ns == runtime.process_creation_time_100ns &&
			memory_scanner::validate_target_binding(context.target_pid,
				context.target_epoch, context.process_creation_time_100ns) &&
			(context.kind != kind_t::scan_result || (!runtime.scan_static_binary &&
				context.target_pid == runtime.scan_target_pid &&
				context.target_epoch == runtime.scan_target_epoch &&
				context.process_creation_time_100ns ==
					runtime.scan_process_creation_time_100ns &&
				context.scan_revision == runtime.scan_revision));
	if (context.source == source_t::static_binary)
		return runtime.static_loaded && runtime.scan_static_binary &&
			context.scan_revision == runtime.scan_revision &&
			context.workspace_id == runtime.scan_workspace_id &&
			context.workspace_generation == runtime.scan_workspace_generation;
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
	if ((capability == capability_t::compare_selected ||
		capability == capability_t::export_selected) &&
		context.kind != kind_t::scan_result)
		return denied("Select current memory scan results for this action.");
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
