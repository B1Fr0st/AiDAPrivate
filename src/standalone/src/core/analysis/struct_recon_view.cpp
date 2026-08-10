#include "struct_recon_view.hpp"
#include "struct_dissector_view.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#include "../disasm/disasm_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/struct_recon_preview_runtime.hpp"
#include "../../preview/studio_semantics.hpp"
#include "../../preview/ui_task_executor.hpp"
#else
#include "struct_recon_engine.hpp"
#include "struct_monitor.hpp"
#include "standalone_driver.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../disasm/function_index.hpp"
#include "../infra/executor.hpp"
#include "../../helpers/globals.h"
#include "../../helpers/win32_dialog.hpp"
#endif
#include "ui/theme.hpp"
#include "ui/clock.hpp"
#include "ui/motion.hpp"
#include "ui/transition.hpp"
#include "ui/components.hpp"
#include "ui/design_system.hpp"
#include "ui/blur_layer.hpp"
#include "ui/empty_state.hpp"
#include "ui/responsive.hpp"
#include "ui/skeleton.hpp"
#include "ui/fonts.hpp"
#include "ui/ui_anim.hpp"
#include "imgui.h"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/task_center.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace struct_recon_view {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
static std::string studio_recon_field_id(
	const struct_recon::reconstructed_struct_t& structure,
	const struct_recon::struct_field_t& field) {
	const auto workspace = disasm_view::capture_selected_workspace();
	const std::string workspace_id = workspace.workspace
		? workspace.workspace->identity().binary_id().to_hex() : std::string("none");
	const std::string identity = workspace_id + ":" +
		std::to_string(structure.base_address) + ":" + std::to_string(field.offset);
	return aida::preview::semantics::stable_id("aida.types",
		"recon-field-" + aida::preview::semantics::entity_token(identity));
}
#endif

struct field_anim_t {
	float heat_v = 0.f;
	aida::ui::flash_t change_flash;
	aida::ui::flash_t write_success;
	aida::ui::transition_t expand_anim;
	bool  expanded = false;
	uint64_t last_value = 0;
	bool  has_last = false;
};

struct local_state_t {
	float scroll_y = 0.f;
	float target_scroll_y = 0.f;
	bool  scrollbar_dragging = false;
	float scrollbar_drag_offset = 0.f;
	int   selected_field = -1;
	int   editing_field = -1;
	char  edit_value_buf[128] = {};
	std::unordered_map<int, field_anim_t> field_anims;
	aida::ui::transition_t vtable_expand;
	bool  vtable_expanded = true;
	int context_field = -1;
	uint64_t context_base = 0;
	uint64_t context_offset = 0;
	int context_size = 0;
	std::string context_name;
	std::string context_struct_name;
	std::string operation_status;
	bool operation_error = false;
	bool operation_pending = false;
	uint64_t operation_generation = 0;
	uint64_t operation_overlay_revision = 0;
	bool overlay_review_requested = false;
	std::string overlay_review_workspace_id;
	std::string overlay_review_structure_name;
	std::string overlay_review_declaration;
	uint64_t overlay_review_base = 0;
	uint64_t overlay_review_generation = 0;
	uint64_t overlay_review_analysis_revision = 0;
	uint64_t overlay_review_overlay_revision = 0;
	std::shared_ptr<const struct_recon::reconstructed_struct_t> overlay_review_snapshot;
	std::weak_ptr<aida::analysis::analysis_workspace_t> overlay_review_workspace;
	std::shared_ptr<const aida::analysis::analysis_publication_t> overlay_review_publication;
	bool declaration_preview_requested = false;
	std::string declaration_preview_name;
	std::string declaration_preview_text;
	std::shared_ptr<const struct_recon::reconstructed_struct_t> declaration_preview_snapshot;
	enum class retained_edit_kind_t : std::uint8_t { none, rename, retype, live_value };
	retained_edit_kind_t retained_edit_kind = retained_edit_kind_t::none;
	bool retained_edit_requested = false;
	std::shared_ptr<const struct_recon::reconstructed_struct_t> retained_edit_snapshot;
	std::weak_ptr<aida::analysis::analysis_workspace_t> retained_edit_workspace;
	std::shared_ptr<const aida::analysis::analysis_publication_t> retained_edit_publication;
	std::string retained_edit_workspace_id;
	std::uint64_t retained_edit_workspace_generation = 0;
	std::uint64_t retained_edit_analysis_revision = 0;
	std::uint32_t retained_edit_target_pid = 0;
	std::uint64_t retained_edit_field_hash = 0;
	std::uint64_t retained_edit_structure_id = 0;
	std::uint64_t retained_edit_structure_revision = 0;
	std::uint64_t retained_edit_field_id = 0;
	std::uint64_t retained_edit_schema_revision = 0;
	std::uint64_t retained_edit_base = 0;
	std::uint64_t retained_edit_refresh_sequence = 0;
	int retained_edit_field_index = -1;
	char retained_edit_text[256] = {};
	int retained_edit_type = 0;
};

static local_state_t s_state;

static bool checked_field_address(uint64_t base, uint64_t offset, uint64_t& result)
{
	if (offset > (std::numeric_limits<uint64_t>::max)() - base)
		return false;
	result = base + offset;
	return true;
}

static bool context_is_current(const struct_recon::reconstructed_struct_t& structure,
	const local_state_t& state)
{
	if (state.context_field < 0 ||
		state.context_field >= static_cast<int>(structure.fields.size()) ||
		structure.base_address != state.context_base ||
		structure.name != state.context_struct_name)
		return false;
	const auto& field = structure.fields[static_cast<size_t>(state.context_field)];
	return field.offset == state.context_offset && field.size == state.context_size &&
		field.name == state.context_name;
}

static void publish_field_selection(const struct_recon::reconstructed_struct_t& structure,
	const struct_recon::struct_field_t& field)
{
	auto context = disasm_view::capture_selected_workspace();
	if (!context.workspace)
		return;
	uint64_t address = 0;
	if (checked_field_address(structure.base_address, field.offset, address) &&
		disasm_view::typed_address(context, address)) {
		disasm_view::select_address(address, context);
		return;
	}
	aida::workbench::selection_context_t selection;
	selection.kind = aida::workbench::selection_kind_t::entity;
	selection.entity_key = "structure.reconstruction." + structure.name + ".field." +
		std::to_string(field.offset);
	aida::workbench::document_local_cursor_t cursor;
	aida::workbench::workbench_shell_workspace_context_t workbench;
	static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
		.publish_selection(context.workspace, selection, cursor,
			aida::workbench::navigation_origin_t::inspector, workbench));
}

bool has_current_structure()
{
	const auto structure = struct_recon::capture_current_snapshot();
	return structure && !structure->fields.empty();
}

command_result_t copy_current_declaration()
{
	const auto structure = struct_recon::capture_current_snapshot();
	if (!structure || structure->fields.empty())
		return {false, "Reconstruct or load a structure first"};
	const std::string declaration = struct_recon::export_as_cpp(*structure);
	if (declaration.empty() || declaration.size() > 64U * 1024U)
		return {false, "The reconstruction declaration is empty or exceeds 64 KiB"};
	ImGui::SetClipboardText(declaration.c_str());
	return {true, "Generated C++ declaration copied"};
}

command_result_t declare_and_apply_current()
{
	const auto structure = struct_recon::capture_current_snapshot();
	if (!structure || structure->fields.empty())
		return {false, "Reconstruct or load a structure first"};
	auto context = disasm_view::capture_selected_workspace();
	if (!context.workspace || !context.publication)
		return {false, "Open and analyze the static or live target that owns this structure first"};
	if (context.workspace->closing() || context.workspace->closed())
		return {false, "The selected analysis workspace is closing"};
	const auto address = disasm_view::typed_address(context, structure->base_address);
	if (!address)
		return {false, "The reconstructed base address is outside the selected workspace mapping"};
	const std::string declaration = struct_recon::export_as_cpp(*structure);
	if (declaration.empty() || declaration.size() > 64U * 1024U || structure->name.empty())
		return {false, "The reconstruction has no valid generated declaration or type name"};
	s_state.overlay_review_workspace_id = context.workspace->identity().binary_id().to_hex();
	s_state.overlay_review_structure_name = structure->name;
	s_state.overlay_review_declaration = declaration;
	s_state.overlay_review_base = structure->base_address;
	s_state.overlay_review_generation = context.workspace->generation();
	s_state.overlay_review_analysis_revision = context.publication->analysis_revision;
	s_state.overlay_review_overlay_revision = context.workspace->overlay_revision();
	s_state.overlay_review_snapshot = structure;
	s_state.overlay_review_workspace = context.workspace;
	s_state.overlay_review_publication = context.publication;
	s_state.overlay_review_requested = true;
	const auto opened = aida::ui::application_views::open_or_focus(
		aida::ui::stable_view_id_t("view.types.struct_recon"));
	if (!opened.ok()) {
		s_state.overlay_review_requested = false;
		return {false, opened.detail};
	}
	return {true, "Review the atomic declaration and application before committing it to the overlay"};
}

static aida::ui::action_handler_result_t stage_declare_apply_review()
{
	const auto result = declare_and_apply_current();
	return result.completed
		? aida::ui::action_handler_result_t::completed(result.detail)
		: aida::ui::action_handler_result_t::failed(result.detail);
}

static std::uint64_t field_identity_hash(const struct_recon::struct_field_t& field)
{
	std::uint64_t hash = 1469598103934665603ull;
	const auto mix = [&hash](std::uint64_t value) {
		hash ^= value;
		hash *= 1099511628211ull;
	};
	const auto mix_string = [&mix](const std::string& value) {
		mix(value.size());
		for (const char character : value)
			mix(static_cast<std::uint64_t>(static_cast<unsigned char>(character)));
	};
	const auto mix_bytes = [&mix](const std::vector<std::uint8_t>& value) {
		mix(value.size());
		for (const auto byte : value) mix(byte);
	};
	mix_string(field.name);
	mix(static_cast<std::uint64_t>(field.type));
	mix(field.offset);
	mix(static_cast<std::uint64_t>(field.size));
	mix_string(field.comment);
	std::uint32_t confidence_bits = 0;
	static_assert(sizeof(confidence_bits) == sizeof(field.type_confidence));
	std::memcpy(&confidence_bits, &field.type_confidence, sizeof(confidence_bits));
	mix(confidence_bits);
	mix(static_cast<std::uint64_t>(field.array_count));
	mix(static_cast<std::uint64_t>(field.value_history.count));
	mix(static_cast<std::uint64_t>(field.value_history.write_idx));
	for (const auto value : field.value_history.values) mix(value);
	mix(field.vtable_entries.size());
	for (const auto& entry : field.vtable_entries) {
		mix(entry.func_addr);
		mix(static_cast<std::uint64_t>(entry.index));
		mix_string(entry.name);
	}
	mix(field.accesses.size());
	for (const auto& access : field.accesses) {
		mix(access.instruction_addr);
		mix(access.access_offset);
		mix(static_cast<std::uint64_t>(access.access_size));
		mix(access.is_write ? 1U : 0U);
		mix_string(access.disasm_text);
		mix(static_cast<std::uint64_t>(access.hit_count));
		mix_string(access.source);
		mix(access.thread_id);
		mix(access.sample_index);
		mix(access.capture_session_id);
		mix(access.initial_value_captured ? 1U : 0U);
		mix(access.initial_value);
		mix_bytes(access.initial_bytes);
		mix(access.value_captured ? 1U : 0U);
		mix(access.value_after_access ? 1U : 0U);
		mix(access.observed_value);
		mix_bytes(access.observed_bytes);
	}
	return hash == 0 ? 1 : hash;
}

struct editable_field_binding_t {
	int structure_index = -1;
	int field_index = -1;
	std::uint64_t structure_id = 0;
	std::uint64_t structure_revision = 0;
	std::uint64_t field_id = 0;
	std::uint64_t schema_revision = 0;
	std::uint64_t base_address = 0;
	std::uint64_t refresh_sequence = 0;
	bool live_snapshot_current = false;
	struct_dissector::field_def_t field;
	struct_dissector::live_value_t value;
};

static std::optional<editable_field_binding_t> find_editable_field_binding(
	const struct_recon::reconstructed_struct_t& reconstruction,
	const struct_recon::struct_field_t& reconstructed_field)
{
	auto& state = struct_dissector::g_state;
	std::lock_guard<std::mutex> lock(state.mtx);
	for (std::size_t structure_index = 0; structure_index < state.structs.size(); ++structure_index) {
		const auto& structure = state.structs[structure_index];
		if (structure.name != reconstruction.name || structure.stable_id == 0 ||
			structure.layout_revision == 0)
			continue;
		for (std::size_t field_index = 0; field_index < structure.fields.size(); ++field_index) {
			const auto& field = structure.fields[field_index];
			if (field.stable_id == 0 || field.name != reconstructed_field.name ||
				field.offset != reconstructed_field.offset ||
				field.size != static_cast<std::uint32_t>(reconstructed_field.size))
				continue;
			if (!struct_dissector::index_fits_int(structure_index) ||
				!struct_dissector::index_fits_int(field_index))
				return std::nullopt;
			editable_field_binding_t result;
			result.structure_index = static_cast<int>(structure_index);
			result.field_index = static_cast<int>(field_index);
			result.structure_id = structure.stable_id;
			result.structure_revision = structure.layout_revision;
			result.field_id = field.stable_id;
			result.schema_revision = state.schema_revision;
			result.base_address = state.base_address;
			result.refresh_sequence = state.last_completed_seq.load(std::memory_order_acquire);
			result.field = field;
			if (field_index < state.cached_values.size())
				result.value = state.cached_values[field_index];
			result.live_snapshot_current = state.active_struct == static_cast<int>(structure_index) &&
				state.base_address == reconstruction.base_address && state.base_address != 0 &&
				result.refresh_sequence != 0 && !result.value.raw_bytes.empty();
			return result;
		}
	}
	return std::nullopt;
}

static std::optional<std::pair<int, int>> resolve_retained_edit_binding(
	const local_state_t& state)
{
	auto& catalog = struct_dissector::g_state;
	std::lock_guard<std::mutex> lock(catalog.mtx);
	if (catalog.schema_revision != state.retained_edit_schema_revision)
		return std::nullopt;
	const int structure_index = struct_dissector::structure_index_by_id_locked(
		state.retained_edit_structure_id);
	if (!struct_dissector::valid_index(structure_index, catalog.structs.size()))
		return std::nullopt;
	const auto& structure = catalog.structs[static_cast<std::size_t>(structure_index)];
	if (structure.layout_revision != state.retained_edit_structure_revision)
		return std::nullopt;
	const auto found = std::find_if(structure.fields.begin(), structure.fields.end(),
		[&state](const auto& field) { return field.stable_id == state.retained_edit_field_id; });
	if (found == structure.fields.end())
		return std::nullopt;
	const auto field_index = static_cast<std::size_t>(
		std::distance(structure.fields.begin(), found));
	if (!struct_dissector::index_fits_int(field_index))
		return std::nullopt;
	return std::pair<int, int>{structure_index, static_cast<int>(field_index)};
}

static bool retained_reconstruction_is_current(const local_state_t& state,
	std::string& reason)
{
	const auto workspace = disasm_view::capture_selected_workspace();
	const auto retained_workspace = state.retained_edit_workspace.lock();
	const auto reconstruction = struct_recon::capture_current_snapshot();
	if (!workspace.workspace || !workspace.publication || !retained_workspace ||
		workspace.workspace != retained_workspace ||
		workspace.publication != state.retained_edit_publication ||
		workspace.workspace->closing() || workspace.workspace->closed() ||
		workspace.workspace->identity().binary_id().to_hex() != state.retained_edit_workspace_id ||
		workspace.workspace->generation() != state.retained_edit_workspace_generation ||
		workspace.publication->analysis_revision != state.retained_edit_analysis_revision) {
		reason = "The selected workspace or analysis revision changed; select the field again.";
		return false;
	}
	if (!reconstruction || reconstruction != state.retained_edit_snapshot ||
		state.retained_edit_field_index < 0 ||
		state.retained_edit_field_index >= static_cast<int>(reconstruction->fields.size())) {
		reason = "The reconstruction generation changed; select the field again.";
		return false;
	}
	const auto& field = reconstruction->fields[
		static_cast<std::size_t>(state.retained_edit_field_index)];
	if (field_identity_hash(field) != state.retained_edit_field_hash ||
		reconstruction->base_address != state.retained_edit_base) {
		reason = "The retained reconstructed field identity changed; select it again.";
		return false;
	}
	if (!resolve_retained_edit_binding(state)) {
		reason = "The editable Structure Dissector catalog changed; select the field again.";
		return false;
	}
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
	const auto process = workspace.workspace->identity().process();
	if (state.retained_edit_kind == local_state_t::retained_edit_kind_t::live_value &&
		(!process || process->pid != state.retained_edit_target_pid ||
		 !driver_bridge::is_loaded() || driver_bridge::attached_pid() != process->pid)) {
		reason = "The original attached process identity changed; select the field again.";
		return false;
	}
#endif
	reason.clear();
	return true;
}

static aida::ui::action_handler_result_t stage_retained_field_edit(
	local_state_t::retained_edit_kind_t kind,
	std::shared_ptr<const struct_recon::reconstructed_struct_t> reconstruction,
	int field_index, const editable_field_binding_t& binding,
	const disasm_view::workspace_context_t& workspace)
{
	if (!reconstruction || !workspace.workspace || !workspace.publication ||
		field_index < 0 || field_index >= static_cast<int>(reconstruction->fields.size()))
		return aida::ui::action_handler_result_t::failed("The retained reconstruction field is stale");
	const auto& field = reconstruction->fields[static_cast<std::size_t>(field_index)];
	auto& state = s_state;
	state.retained_edit_kind = kind;
	state.retained_edit_snapshot = std::move(reconstruction);
	state.retained_edit_workspace = workspace.workspace;
	state.retained_edit_publication = workspace.publication;
	state.retained_edit_workspace_id = workspace.workspace->identity().binary_id().to_hex();
	state.retained_edit_workspace_generation = workspace.workspace->generation();
	state.retained_edit_analysis_revision = workspace.publication->analysis_revision;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	state.retained_edit_target_pid = workspace.workspace->identity().process()
		? workspace.workspace->identity().process()->pid : 4242;
#else
	state.retained_edit_target_pid = workspace.workspace->identity().process()
		? workspace.workspace->identity().process()->pid : 0;
#endif
	state.retained_edit_field_hash = field_identity_hash(field);
	state.retained_edit_structure_id = binding.structure_id;
	state.retained_edit_structure_revision = binding.structure_revision;
	state.retained_edit_field_id = binding.field_id;
	state.retained_edit_schema_revision = binding.schema_revision;
	state.retained_edit_base = state.retained_edit_snapshot->base_address;
	state.retained_edit_refresh_sequence = binding.refresh_sequence;
	state.retained_edit_field_index = field_index;
	state.retained_edit_type = static_cast<int>(binding.field.type);
	const std::string seed = kind == local_state_t::retained_edit_kind_t::rename
		? binding.field.name : kind == local_state_t::retained_edit_kind_t::live_value
		? binding.value.display_text : std::string{};
	std::snprintf(state.retained_edit_text, sizeof(state.retained_edit_text), "%s", seed.c_str());
	state.retained_edit_requested = true;
	return aida::ui::action_handler_result_t::completed(
		"Review the revision-bound Structure Dissector transaction before committing it");
}

static void clear_retained_field_edit()
{
	s_state.retained_edit_kind = local_state_t::retained_edit_kind_t::none;
	s_state.retained_edit_snapshot.reset();
	s_state.retained_edit_workspace.reset();
	s_state.retained_edit_publication.reset();
	s_state.retained_edit_text[0] = '\0';
}

static void render_retained_field_edit_review()
{
	if (s_state.retained_edit_requested) {
		s_state.retained_edit_requested = false;
		aida::ui::design::open_dialog("types.reconstruction.field.edit-review",
			"Review Reconstructed Field Edit");
	}
	if (!aida::ui::design::begin_dialog("types.reconstruction.field.edit-review",
			"Review Reconstructed Field Edit", ImVec2(620.0f, 420.0f),
			ImVec2(440.0f, 320.0f)))
		return;
	std::string stale_reason;
	const bool current = retained_reconstruction_is_current(s_state, stale_reason);
	const auto reconstruction = s_state.retained_edit_snapshot;
	const auto* field = reconstruction && s_state.retained_edit_field_index >= 0 &&
		s_state.retained_edit_field_index < static_cast<int>(reconstruction->fields.size())
		? &reconstruction->fields[static_cast<std::size_t>(s_state.retained_edit_field_index)]
		: nullptr;
	const char* operation = s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::rename
		? "Rename editable field" : s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::retype
		? "Retype editable field" : "Edit live field value";
	const char* confirm_label = s_state.retained_edit_kind ==
		local_state_t::retained_edit_kind_t::live_value
		? "Stage verified write" : "Commit catalog edit";
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		confirm_label, "Cancel");
	aida::ui::design::begin_dialog_body("types.reconstruction.field.edit-review.body",
		footer_height);
	ImGui::TextUnformatted(operation);
	if (field && reconstruction)
		ImGui::Text("%s.%s  +0x%llX  %u bytes", reconstruction->name.c_str(),
			field->name.c_str(), static_cast<unsigned long long>(field->offset),
			static_cast<unsigned int>((std::max)(field->size, 0)));
	ImGui::TextDisabled("Workspace generation %llu  analysis revision %llu  catalog revision %llu",
		static_cast<unsigned long long>(s_state.retained_edit_workspace_generation),
		static_cast<unsigned long long>(s_state.retained_edit_analysis_revision),
		static_cast<unsigned long long>(s_state.retained_edit_schema_revision));
	ImGui::Separator();
	ImGui::BeginDisabled(!current);
	if (s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::rename) {
		ImGui::InputText("Field name", s_state.retained_edit_text,
			sizeof(s_state.retained_edit_text));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item("aida.types.reconstruction-edit-name",
			"field-edit-input", false, !current);
#endif
	} else if (s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::retype) {
		const char* preview = struct_dissector::field_type_name(
			static_cast<struct_dissector::field_type_t>(s_state.retained_edit_type));
		if (ImGui::BeginCombo("Field type", preview)) {
			for (int index = 0; index < static_cast<int>(struct_dissector::field_type_t::COUNT); ++index) {
				const bool selected = index == s_state.retained_edit_type;
				if (ImGui::Selectable(struct_dissector::field_type_name(
						static_cast<struct_dissector::field_type_t>(index)), selected))
					s_state.retained_edit_type = index;
				if (selected) ImGui::SetItemDefaultFocus();
			}
			ImGui::EndCombo();
		}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item("aida.types.reconstruction-edit-type",
			"field-type-selector", false, !current);
#endif
	} else {
		ImGui::Text("Target PID %u  address 0x%016llX", s_state.retained_edit_target_pid,
			static_cast<unsigned long long>(s_state.retained_edit_base +
				(field ? field->offset : 0)));
		ImGui::InputText("New value", s_state.retained_edit_text,
			sizeof(s_state.retained_edit_text));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item("aida.types.reconstruction-edit-live-value",
			"live-value-input", false, !current);
#endif
		ImGui::TextWrapped("The Structure Dissector will revalidate the exact target, old bytes, field identity, and address before writing, then require an exact readback match.");
	}
	ImGui::EndDisabled();
	if (!current)
		ImGui::TextWrapped("%s", stale_reason.c_str());
	aida::ui::design::end_dialog_body();
	const bool has_non_whitespace_input = std::any_of(std::begin(s_state.retained_edit_text),
		std::end(s_state.retained_edit_text), [](char character) {
			return character != '\0' && !std::isspace(static_cast<unsigned char>(character));
		});
	const bool has_input = s_state.retained_edit_kind ==
		local_state_t::retained_edit_kind_t::retype || has_non_whitespace_input;
	const auto footer = aida::ui::design::dialog_footer(
		"types.reconstruction.field.edit-review.footer", confirm_label,
		current && has_input, false, "Cancel");
	if (footer.confirmed) {
		const auto resolved = resolve_retained_edit_binding(s_state);
		bool applied = false;
		std::string error;
		if (!resolved) {
			error = "The editable field revision changed before confirmation.";
		} else if (s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::live_value) {
			struct_dissector::field_def_t editable_field;
			struct_dissector::live_value_t value;
			std::uint64_t base = 0;
			{
				auto& catalog = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(catalog.mtx);
				if (catalog.schema_revision == s_state.retained_edit_schema_revision &&
					catalog.active_struct == resolved->first &&
					catalog.base_address == s_state.retained_edit_base &&
					catalog.last_completed_seq.load(std::memory_order_acquire) ==
						s_state.retained_edit_refresh_sequence &&
					struct_dissector::valid_index(resolved->second,
						catalog.structs[static_cast<std::size_t>(resolved->first)].fields.size()) &&
					static_cast<std::size_t>(resolved->second) < catalog.cached_values.size()) {
					editable_field = catalog.structs[static_cast<std::size_t>(resolved->first)]
						.fields[static_cast<std::size_t>(resolved->second)];
					value = catalog.cached_values[static_cast<std::size_t>(resolved->second)];
					base = catalog.base_address;
				}
			}
			if (base == 0 || value.raw_bytes.empty()) {
				error = "The live value snapshot changed; refresh and select the field again.";
			} else {
				const auto workspace = disasm_view::capture_selected_workspace();
				applied = struct_dissector_view::stage_write_review(workspace,
					resolved->first, resolved->second, editable_field, value, base,
					s_state.retained_edit_text, error);
			}
		} else {
			const auto kind = s_state.retained_edit_kind;
			const std::string text = s_state.retained_edit_text;
			const int type = s_state.retained_edit_type;
			applied = struct_dissector::perform_user_catalog_edit(
				kind == local_state_t::retained_edit_kind_t::rename
					? "Rename reconstructed field" : "Retype reconstructed field",
				[resolved, kind, text, type] {
					return kind == local_state_t::retained_edit_kind_t::rename
						? struct_dissector::rename_field(resolved->first, resolved->second, text)
						: struct_dissector::retype_field(resolved->first, resolved->second,
							static_cast<struct_dissector::field_type_t>(type));
				}, error);
		}
		s_state.operation_error = !applied;
		s_state.operation_status = applied
			? s_state.retained_edit_kind == local_state_t::retained_edit_kind_t::live_value
				? "Live mutation staged for explicit confirmation and exact readback verification."
				: "Editable structure catalog updated and durable persistence queued."
			: error.empty() ? "The revision-bound edit was rejected; no change was claimed." : error;
		if (applied) {
			{
				auto& catalog = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(catalog.mtx);
				const int structure_index = struct_dissector::structure_index_by_id_locked(
					s_state.retained_edit_structure_id);
				if (struct_dissector::valid_index(structure_index, catalog.structs.size())) {
					catalog.active_struct = structure_index;
					const auto& structure = catalog.structs[static_cast<std::size_t>(structure_index)];
					const auto found = std::find_if(structure.fields.begin(), structure.fields.end(),
						[](const auto& candidate) {
							return candidate.stable_id == s_state.retained_edit_field_id;
						});
					if (found != structure.fields.end()) {
						const auto index = static_cast<std::size_t>(
							std::distance(structure.fields.begin(), found));
						if (struct_dissector::index_fits_int(index))
							struct_dissector_view::g_ui.selected_field = static_cast<int>(index);
					}
				}
			}
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.types.dissector"));
			if (!opened.ok()) {
				s_state.operation_error = true;
				s_state.operation_status = opened.detail;
			}
			clear_retained_field_edit();
			ImGui::CloseCurrentPopup();
		}
	}
	if (footer.cancelled) {
		clear_retained_field_edit();
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

static void render_declaration_preview()
{
	if (s_state.declaration_preview_requested) {
		s_state.declaration_preview_requested = false;
		aida::ui::design::open_dialog("types.reconstruction.declaration-preview",
			"Generated Reconstruction Declaration");
	}
	if (!aida::ui::design::begin_dialog("types.reconstruction.declaration-preview",
			"Generated Reconstruction Declaration", ImVec2(760.0f, 600.0f),
			ImVec2(440.0f, 320.0f)))
		return;
	const auto current_snapshot = struct_recon::capture_current_snapshot();
	const bool current = current_snapshot &&
		current_snapshot == s_state.declaration_preview_snapshot &&
		!s_state.declaration_preview_text.empty() &&
		s_state.declaration_preview_text.size() <= 64U * 1024U;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Copy Declaration", "Close");
	aida::ui::design::begin_dialog_body("types.reconstruction.declaration-preview.body",
		footer_height);
	ImGui::Text("Generated declaration: %s", s_state.declaration_preview_name.c_str());
	ImGui::TextDisabled("%zu bytes  bounded maximum 64 KiB",
		s_state.declaration_preview_text.size());
	ImGui::Separator();
	ImGui::BeginChild("##recon_declaration_text", ImVec2(0.0f, -42.0f), true,
		ImGuiWindowFlags_HorizontalScrollbar);
	ImGui::TextUnformatted(s_state.declaration_preview_text.c_str());
	ImGui::EndChild();
	ImGui::BeginDisabled(!current);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	ImGui::BeginDisabled();
	ImGui::Button("Export File...");
	aida::preview::semantics::register_last_item("aida.types.reconstruction-declaration-export",
		"declaration-export", false, true);
	ImGui::EndDisabled();
	if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
		ImGui::SetTooltip("Native file selection is available in the Win32/DX11 authority");
#else
	if (ImGui::Button("Export File...")) {
		char destination[32768]{};
		std::string initial = s_state.declaration_preview_name.empty()
			? "reconstructed_type.hpp" : s_state.declaration_preview_name + ".hpp";
		std::snprintf(destination, sizeof(destination), "%s", initial.c_str());
		static const char filter[] =
			"C/C++ Header (*.h;*.hpp)\0*.h;*.hpp\0C/C++ Source (*.c;*.cpp)\0*.c;*.cpp\0All Files (*.*)\0*.*\0\0";
		if (win32_dialog::show_save_file_dialog(g_hwnd,
				"Export Generated Structure Declaration", filter, "hpp", destination,
				sizeof(destination), "struct_recon_view::export_declaration")) {
			const auto result = file_tabs::atomic_write_file(destination,
				s_state.declaration_preview_text);
			s_state.operation_error = !result.succeeded;
			s_state.operation_status = result.succeeded
				? "Generated declaration exported through an exact atomic file replacement."
				: result.detail;
		}
	}
#endif
	ImGui::EndDisabled();
	if (!current)
		ImGui::TextDisabled("The reconstruction changed. Close and generate a fresh declaration preview.");
	aida::ui::design::end_dialog_body();
	const auto footer = aida::ui::design::dialog_footer(
		"types.reconstruction.declaration-preview.footer", "Copy Declaration",
		current, false, "Close");
	if (footer.confirmed) {
		ImGui::SetClipboardText(s_state.declaration_preview_text.c_str());
		s_state.operation_error = false;
		s_state.operation_status = "Generated C++ declaration copied.";
	}
	if (footer.cancelled) {
		s_state.declaration_preview_snapshot.reset();
		s_state.declaration_preview_text.clear();
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

static void render_declare_apply_review()
{
	if (s_state.overlay_review_requested) {
		s_state.overlay_review_requested = false;
		aida::ui::design::open_dialog("types.reconstruction.overlay-review",
			"Review Reconstructed Type Application");
	}
	if (!aida::ui::design::begin_dialog("types.reconstruction.overlay-review",
			"Review Reconstructed Type Application", ImVec2(720.0f, 560.0f),
			ImVec2(440.0f, 320.0f)))
		return;
	auto context = disasm_view::capture_selected_workspace();
	const auto structure = struct_recon::capture_current_snapshot();
	const auto review_workspace = s_state.overlay_review_workspace.lock();
	const bool current = context.workspace && context.publication && structure &&
		!context.workspace->closing() && !context.workspace->closed() &&
		context.workspace->identity().binary_id().to_hex() == s_state.overlay_review_workspace_id &&
		context.workspace == review_workspace &&
		context.publication == s_state.overlay_review_publication &&
		context.workspace->generation() == s_state.overlay_review_generation &&
		context.publication->analysis_revision == s_state.overlay_review_analysis_revision &&
		context.workspace->overlay_revision() == s_state.overlay_review_overlay_revision &&
		structure == s_state.overlay_review_snapshot;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Commit Declaration and Application", "Cancel");
	aida::ui::design::begin_dialog_body("types.reconstruction.overlay-review.body",
		footer_height);
	ImGui::Text("Declare %s and apply at 0x%016llX",
		s_state.overlay_review_structure_name.c_str(),
		static_cast<unsigned long long>(s_state.overlay_review_base));
	ImGui::TextDisabled("Workspace generation %llu  analysis revision %llu  overlay revision %llu",
		static_cast<unsigned long long>(s_state.overlay_review_generation),
		static_cast<unsigned long long>(s_state.overlay_review_analysis_revision),
		static_cast<unsigned long long>(s_state.overlay_review_overlay_revision));
	ImGui::Separator();
	ImGui::BeginChild("##reconstructed_type_review", ImVec2(0.0f, -24.0f), true,
		ImGuiWindowFlags_HorizontalScrollbar);
	ImGui::TextUnformatted(s_state.overlay_review_declaration.c_str());
	ImGui::EndChild();
	if (!current)
		ImGui::TextDisabled("The workspace, reconstruction, or overlay revision changed. Cancel and select the field again.");
	aida::ui::design::end_dialog_body();
	const auto footer = aida::ui::design::dialog_footer(
		"types.reconstruction.overlay-review.footer",
		"Commit Declaration and Application", current, false, "Cancel");
	if (footer.confirmed) {
		const auto address = disasm_view::typed_address(context, s_state.overlay_review_base);
		const bool queued = address && disasm_view::queue_type_declaration_and_application(
			context, *address, s_state.overlay_review_declaration,
			s_state.overlay_review_structure_name);
		s_state.operation_error = !queued;
		s_state.operation_status = queued
			? "Atomic declaration and application queued through the reversible overlay authority"
			: "The overlay authority rejected the transaction; no change was claimed";
		if (queued) {
			s_state.operation_pending = true;
			s_state.operation_generation = s_state.overlay_review_generation;
			s_state.operation_overlay_revision = s_state.overlay_review_overlay_revision;
			s_state.overlay_review_snapshot.reset();
			s_state.overlay_review_publication.reset();
			s_state.overlay_review_workspace.reset();
			ImGui::CloseCurrentPopup();
		}
	}
	if (footer.cancelled) {
		s_state.overlay_review_declaration.clear();
		s_state.overlay_review_snapshot.reset();
		s_state.overlay_review_publication.reset();
		s_state.overlay_review_workspace.reset();
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

static ImU32 type_color_token(struct_recon::field_type_t tp, float alpha)
{
	const auto& th = aida::ui::resolved();
	ImU32 base;
	switch (tp) {
		case struct_recon::field_type_t::int8:
		case struct_recon::field_type_t::int16:
		case struct_recon::field_type_t::int32:
		case struct_recon::field_type_t::int64:
		case struct_recon::field_type_t::uint8:
		case struct_recon::field_type_t::uint16:
		case struct_recon::field_type_t::uint32:
		case struct_recon::field_type_t::uint64:        base = th.syn_number; break;
		case struct_recon::field_type_t::float32:
		case struct_recon::field_type_t::float64:       base = th.syn_number; break;
		case struct_recon::field_type_t::pointer:       base = th.syn_function; break;
		case struct_recon::field_type_t::vtable_ptr:    base = th.error;       break;
		case struct_recon::field_type_t::c_string:
		case struct_recon::field_type_t::wide_string:
		case struct_recon::field_type_t::utf8_string:
		case struct_recon::field_type_t::utf16_string:  base = th.syn_string;  break;
		case struct_recon::field_type_t::padding:       base = th.text_dim;    break;
		case struct_recon::field_type_t::nested_struct: base = th.syn_keyword; break;
		case struct_recon::field_type_t::vec2:
		case struct_recon::field_type_t::vec3:
		case struct_recon::field_type_t::vec4:
		case struct_recon::field_type_t::mat4x4:        base = th.warning;     break;
		case struct_recon::field_type_t::color_rgba:    base = th.accent_grad_top; break;
		case struct_recon::field_type_t::bitfield:      base = th.syn_keyword; break;
		case struct_recon::field_type_t::bool8:         base = th.syn_keyword; break;
		default:                                        base = th.text_secondary; break;
	}
	return aida::ui::with_alpha(base, alpha);
}

static void render_type_glyph(ImDrawList* dl, ImVec2 center, struct_recon::field_type_t tp,
                              ImU32 color, float size = 10.f)
{
	switch (tp) {
		case struct_recon::field_type_t::pointer:
		case struct_recon::field_type_t::vtable_ptr: {
			dl->AddCircle(center, size * 0.5f, color, 12, 1.2f);
			ImVec2 tip = ImVec2(center.x + size * 0.7f, center.y);
			dl->AddLine(center, tip, color, 1.2f);
			dl->AddTriangleFilled(
				ImVec2(tip.x - 3.f, center.y - 3.f),
				ImVec2(tip.x + 1.f, center.y),
				ImVec2(tip.x - 3.f, center.y + 3.f), color);
			break;
		}
		case struct_recon::field_type_t::c_string:
		case struct_recon::field_type_t::wide_string:
		case struct_recon::field_type_t::utf8_string:
		case struct_recon::field_type_t::utf16_string: {
			ImVec2 a = ImVec2(center.x - size * 0.5f, center.y - 1.f);
			ImVec2 b = ImVec2(center.x + size * 0.5f, center.y + 1.f);
			dl->AddRectFilled(a, b, color, 1.f);
			dl->AddRectFilled(ImVec2(a.x, a.y + 4.f), ImVec2(b.x - 2.f, b.y + 4.f), color, 1.f);
			dl->AddRectFilled(ImVec2(a.x, a.y + 8.f), ImVec2(b.x + 2.f, b.y + 8.f), color, 1.f);
			break;
		}
		case struct_recon::field_type_t::float32:
		case struct_recon::field_type_t::float64: {
			dl->AddText(ImGui::GetFont(), aida::ui::components::detail::ui_fs() * 0.85f,
				ImVec2(center.x - 5.f, center.y - 7.f), color, "f");
			break;
		}
		case struct_recon::field_type_t::nested_struct: {
			ImVec2 a = ImVec2(center.x - size * 0.5f, center.y - size * 0.5f);
			ImVec2 b = ImVec2(center.x + size * 0.5f, center.y + size * 0.5f);
			dl->AddRect(a, b, color, 1.5f, 0, 1.f);
			dl->AddLine(ImVec2(a.x + 2.f, center.y), ImVec2(b.x - 2.f, center.y), color, 1.f);
			break;
		}
		default: {
			dl->AddCircleFilled(center, size * 0.25f, color, 12);
			break;
		}
	}
}

static field_anim_t& fanim(int idx) { return s_state.field_anims[idx]; }

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b)
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
	struct_recon::ensure_preview_fixture();
#endif
	{
		static bool s_sr_render_logged = false;
		if (!s_sr_render_logged) {
			s_sr_render_logged = true;
			diag::log_tagged_fmt("struct_recon", "render first_frame width=%.0f height=%.0f", width, height);
		}
	}
	{
		static bool s_types_font_logged_recon = false;
		if (!s_types_font_logged_recon) {
			s_types_font_logged_recon = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			diag::log_tagged("types_font", "[types_font] scaled struct_recon_view");
#endif
		}
	}

	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowPos().x + pos_x,
	                                 ImGui::GetWindowPos().y + pos_y));

	ImGui::BeginChild("##struct_recon_view", ImVec2(width, height), false,
	    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);

	auto* dl = ImGui::GetWindowDrawList();
	auto& st = s_state;
	render_declare_apply_review();
	render_retained_field_edit_review();
	render_declaration_preview();
	auto& sr = struct_recon::g_state;
	const auto frame_structure = struct_recon::capture_current_snapshot();
	const bool has_frame_structure = frame_structure && !frame_structure->fields.empty();
	ImVec2 wp = ImGui::GetWindowPos();
	float ox = wp.x;
	float oy = wp.y;

	const float kReconMinW = 460.f;
	if (width < kReconMinW) {
		static bool s_logged_recon_narrow = false;
		if (!s_logged_recon_narrow) {
			s_logged_recon_narrow = true;
			::diag::log_tagged_fmt("responsive",
				"struct_recon_view clamp_overlay width=%.0f min=%.0f",
				width, kReconMinW);
		}
		aida::ui::responsive::draw_clamp_overlay(
			ImVec2(ox, oy), ImVec2(width, height),
			"Widen the panel to reconstruct structs");
		ImGui::EndChild();
		return;
	}

	const auto& th = aida::ui::resolved();
	const float dt = aida::ui::clock::dt();

	dl->AddRectFilled(ImVec2(ox, oy), ImVec2(ox + width, oy + height),
		aida::ui::with_alpha(th.bg_base, alpha));

	const float toolbar_h = 64.f;

	ImU32 bar_top = aida::ui::with_alpha(th.panel_header, alpha * 0.85f);
	ImU32 bar_bot = aida::ui::with_alpha(th.panel_bg, alpha * 0.85f);
	dl->AddRectFilledMultiColor(ImVec2(ox, oy), ImVec2(ox + width, oy + toolbar_h),
		bar_top, bar_top, bar_bot, bar_bot);
	dl->AddLine(ImVec2(ox, oy + toolbar_h - 1.f), ImVec2(ox + width, oy + toolbar_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	float cx = ox + 12.f;
	float cy = oy + 8.f;

	ImGui::SetCursorScreenPos(ImVec2(cx, cy));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.f);
	ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.panel_header, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.border_subtle, alpha)));
	ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(
		aida::ui::with_alpha(th.text_primary, alpha)));

	ImGui::PushItemWidth(160.f);
	ImGui::InputTextWithHint("##sr_addr", "Base address (hex)", sr.address_input, sizeof(sr.address_input));
	ImGui::PopItemWidth();
	ImGui::SameLine(0.f, 6.f);
	ImGui::PushItemWidth(140.f);
	ImGui::InputTextWithHint("##sr_name", "Struct name", sr.name_input, sizeof(sr.name_input));
	ImGui::PopItemWidth();
	ImGui::SameLine(0.f, 6.f);
	ImGui::PushItemWidth(70.f);
	ImGui::InputTextWithHint("##sr_size", "Size", sr.size_input, sizeof(sr.size_input));
	ImGui::PopItemWidth();

	ImGui::PopStyleColor(3);
	ImGui::PopStyleVar(2);

	cy += 32.f;
	ImGui::SetCursorScreenPos(ImVec2(cx, cy));

	bool monitoring = sr.monitoring.load();

	if (!monitoring) {
		if (aida::ui::button("Snapshot", aida::ui::button_kind_t::primary,
			aida::ui::size_t_::sm, ImVec2(86.f, 28.f))) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) {
				diag::log_tagged_fmt("struct_recon",
					"snapshot_clicked addr=0x%llX size=%d name='%s'",
					static_cast<unsigned long long>(addr), sz, sr.name_input);
				struct_recon::reconstruct_from_snapshot(addr, sz, sr.name_input);
			} else {
				diag::log_tagged_fmt("struct_recon",
					"snapshot_skipped reason='addr_zero' input='%s'", sr.address_input);
			}
		}
		ImGui::SameLine(0.f, 6.f);
		if (aida::ui::button("HW Monitor", aida::ui::button_kind_t::secondary,
			aida::ui::size_t_::sm, ImVec2(98.f, 28.f))) {
			uint64_t addr = 0;
			int sz = 256;
			if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
			if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
			if (sz <= 0) sz = 256;
			if (sz > 4096) sz = 4096;
			if (addr != 0) {
				diag::log_tagged_fmt("struct_recon",
					"hwmon_clicked addr=0x%llX size=%d name='%s'",
					static_cast<unsigned long long>(addr), sz, sr.name_input);
				struct_recon::monitor_with_hwbp(addr, sz, sr.name_input);
			} else {
				diag::log_tagged_fmt("struct_recon",
					"hwmon_skipped reason='addr_zero' input='%s'", sr.address_input);
			}
		}
		ImGui::SameLine(0.f, 6.f);
		bool live_active = struct_monitor::g_state.active.load();
		if (!live_active) {
			if (aida::ui::button("Live Monitor", aida::ui::button_kind_t::secondary,
				aida::ui::size_t_::sm, ImVec2(108.f, 28.f))) {
				uint64_t addr = 0;
				int sz = 256;
				if (sr.address_input[0]) addr = std::strtoull(sr.address_input, nullptr, 16);
				if (sr.size_input[0]) sz = static_cast<int>(std::strtol(sr.size_input, nullptr, 0));
				if (sz <= 0) sz = 256;
				if (sz > 4096) sz = 4096;
				if (addr != 0) {
					diag::log_tagged_fmt("struct_recon",
						"live_monitor_start_clicked addr=0x%llX size=%d name='%s'",
						static_cast<unsigned long long>(addr), sz, sr.name_input);
					std::string nm = sr.name_input;
					aida::infra::executor::submission_t sub;
					sub.owner_subsystem = "analysis";
					sub.label = "analysis.struct_recon.live_monitor_start";
					sub.thread_class = "long_running";
					sub.domain = aida::infra::executor::domain_t::long_running;
					sub.priority = 2;
					sub.body = [addr, sz, nm]() {
						struct_monitor::start(addr, sz, nm);
					};
					if (!aida::infra::executor::submit(std::move(sub)).submitted) {
						diag::log_tagged_fmt("struct_recon",
							"live_monitor_start_post_failed addr=0x%llX size=%d name='%s'",
							static_cast<unsigned long long>(addr), sz, nm.c_str());
					}
				} else {
					diag::log_tagged_fmt("struct_recon",
						"live_monitor_skipped reason='addr_zero' input='%s'", sr.address_input);
				}
			}
		} else {
			if (aida::ui::button("Stop Live", aida::ui::button_kind_t::destructive,
				aida::ui::size_t_::sm, ImVec2(94.f, 28.f))) {
				diag::log_tagged_fmt("struct_recon", "live_monitor_stop_clicked");
				struct_monitor::stop();
			}
			ImGui::SameLine();
			uint64_t cps = struct_monitor::g_state.captures_per_second.load();
			uint64_t total = struct_monitor::g_state.total_captures.load();
			char live_buf[64];
			std::snprintf(live_buf, sizeof(live_buf), "%llu cap/s   %llu total",
				static_cast<unsigned long long>(cps),
				static_cast<unsigned long long>(total));
			ImGui::SameLine();
			ImVec2 cp = ImGui::GetCursorScreenPos();
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				aida::ui::components::detail::ui_fs() * 0.92f, ImVec2(cp.x, cp.y + 4.f),
				aida::ui::with_alpha(th.success, alpha), live_buf);
		}
	} else {
		if (aida::ui::button("Cancel", aida::ui::button_kind_t::destructive,
			aida::ui::size_t_::sm, ImVec2(80.f, 28.f))) {
			diag::log_tagged_fmt("struct_recon", "cancel_clicked");
			struct_recon::cancel();
		}
		ImGui::SameLine();
		float prog = sr.progress.load();
		ImVec2 cp = ImGui::GetCursorScreenPos();
		aida::ui::components::render_progress_bar(ImVec2(cp.x, cp.y + 6.f),
			120.f, 10.f, prog, false, true);
		ImGui::Dummy(ImVec2(124.f, 22.f));
	}

	ImGui::SameLine(0.f, 10.f);
	if (aida::ui::button("Export C++", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(94.f, 28.f), !has_frame_structure)) {
		const std::string cpp = frame_structure
			? struct_recon::export_as_cpp(*frame_structure) : std::string{};
		const std::string name = frame_structure ? frame_structure->name : std::string{};
		const size_t field_count = frame_structure ? frame_structure->fields.size() : 0;
		if (!cpp.empty() && cpp.size() <= 64U * 1024U) {
			st.declaration_preview_name = name;
			st.declaration_preview_text = cpp;
			st.declaration_preview_snapshot = frame_structure;
			st.declaration_preview_requested = true;
		}
		diag::log_tagged_fmt("struct_recon",
			"export_cpp_review name='%s' fields=%zu bytes=%zu",
			name.c_str(), field_count, cpp.size());
	}
	if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !has_frame_structure)
		ImGui::SetTooltip("Reconstruct or load a structure before exporting its declaration");
	ImGui::SameLine(0.f, 6.f);
	if (aida::ui::button("Apply Type", aida::ui::button_kind_t::secondary,
		aida::ui::size_t_::sm, ImVec2(92.f, 28.f), !has_frame_structure)) {
		const auto result = declare_and_apply_current();
		st.operation_status = result.detail;
		st.operation_error = !result.completed;
	}
	if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
		ImGui::SetTooltip(has_frame_structure
			? "Review the generated declaration and base-address application before one reversible overlay transaction"
			: "Reconstruct or load a structure before applying its type");
	ImGui::SameLine(0.f, 6.f);
	{
		bool ai_naming = sr.ai_naming.load();
		bool clicked = aida::ui::button(ai_naming ? "Naming" : "AI Name",
			aida::ui::button_kind_t::ghost,
			aida::ui::size_t_::sm,
			ImVec2(88.f, 28.f), ai_naming || !has_frame_structure, nullptr, ai_naming);
		if (clicked && !ai_naming) {
			diag::log_tagged_fmt("struct_recon", "ai_name_clicked");
			struct_recon::ai_name_fields();
		}
		if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
			!ai_naming && !has_frame_structure)
			ImGui::SetTooltip("Reconstruct or load a structure before requesting field names");
	}
	ImGui::SameLine(0.f, 6.f);
	if (aida::ui::button("Save", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(64.f, 28.f), !has_frame_structure)) {
		const struct_recon::reconstructed_struct_t snap = frame_structure
			? *frame_structure : struct_recon::reconstructed_struct_t{};
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "analysis";
		sub.label = "analysis.struct_recon.save_struct";
		sub.thread_class = "bounded_task";
		sub.domain = aida::infra::executor::domain_t::diagnostics;
		sub.priority = 4;
		sub.body = [snap]() {
			std::string error;
			if (!struct_recon::save_struct_to_disk(snap, error))
				throw std::runtime_error(error.empty()
					? "The structure could not be saved" : error);
			diag::log_tagged_fmt("struct_recon",
				"save_disk_done name='%s' fields=%zu",
				snap.name.c_str(), snap.fields.size());
		};
		const auto save_submission = aida::infra::executor::submit(std::move(sub));
		if (!save_submission.submitted) {
			diag::log_tagged_fmt("struct_recon",
				"save_disk_post_failed name='%s' fields=%zu",
				snap.name.c_str(), snap.fields.size());
			st.operation_error = true;
			st.operation_status = save_submission.reject_reason.empty()
				? "The structure persistence queue rejected Save."
				: save_submission.reject_reason;
		} else {
			st.operation_error = false;
			st.operation_status = "Save queued; the persisted structure remains available after restart.";
			aida::ui::task_center::task_registration_t registration;
			registration.owner = "analysis";
			registration.owner_view = "view.types.struct_recon";
			registration.owner_action = "types.structure.save";
			registration.label = "Save reconstructed structure";
			registration.stage = "Queued";
			registration.target = snap.name;
			static_cast<void>(aida::ui::task_center::register_executor_job(
				save_submission.task_id, std::move(registration)));
		}
		diag::log_tagged_fmt("struct_recon",
			"save_clicked name='%s' fields=%zu",
			snap.name.c_str(), snap.fields.size());
	}
	if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !has_frame_structure)
		ImGui::SetTooltip("Reconstruct or load a structure before saving it");
	ImGui::SameLine(0.f, 6.f);
	if (aida::ui::button("Load All", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(82.f, 28.f))) {
		aida::infra::executor::submission_t sub;
		sub.owner_subsystem = "analysis";
		sub.label = "analysis.struct_recon.load_all";
		sub.thread_class = "bounded_task";
		sub.domain = aida::infra::executor::domain_t::diagnostics;
		sub.priority = 4;
		sub.body = []() {
			std::string error;
			if (!struct_recon::load_structs_from_disk(error))
				throw std::runtime_error(error.empty()
					? "The structure catalog could not be loaded" : error);
			size_t loaded = 0;
			{
				std::lock_guard<std::mutex> lk(struct_recon::g_state.mutex);
				loaded = struct_recon::g_state.saved_structs.size();
			}
			diag::log_tagged_fmt("struct_recon",
				"load_all_done count=%zu", loaded);
		};
		const auto load_submission = aida::infra::executor::submit(std::move(sub));
		if (!load_submission.submitted) {
			diag::log_tagged_fmt("struct_recon", "load_all_post_failed");
			st.operation_error = true;
			st.operation_status = load_submission.reject_reason.empty()
				? "The structure persistence queue rejected Load All."
				: load_submission.reject_reason;
		} else {
			st.operation_error = false;
			st.operation_status = "Load All queued; saved structures will appear when disk loading completes.";
			aida::ui::task_center::task_registration_t registration;
			registration.owner = "analysis";
			registration.owner_view = "view.types.struct_recon";
			registration.owner_action = "types.structure.load_all";
			registration.label = "Load reconstructed structures";
			registration.stage = "Queued";
			static_cast<void>(aida::ui::task_center::register_executor_job(
				load_submission.task_id, std::move(registration)));
		}
		diag::log_tagged_fmt("struct_recon", "load_all_clicked");
	}
	ImGui::SameLine(0.f, 6.f);
	const bool refresh_available = has_frame_structure && frame_structure->base_address != 0;
	if (aida::ui::button("Refresh", aida::ui::button_kind_t::ghost,
		aida::ui::size_t_::sm, ImVec2(76.f, 28.f), !refresh_available)) {
		const uint64_t base = frame_structure ? frame_structure->base_address : 0;
		const bool active = frame_structure && !frame_structure->fields.empty();
		const bool any_fields = active;
		if (active && base != 0 && any_fields) {
			aida::infra::executor::submission_t sub;
			sub.owner_subsystem = "analysis";
			sub.label = "analysis.struct_recon.refresh_values";
			sub.thread_class = "bounded_task";
			sub.domain = aida::infra::executor::domain_t::diagnostics;
			sub.priority = 4;
			sub.body = []() {
				std::string error;
				if (!struct_recon::refresh_value_history(error))
					throw std::runtime_error(error.empty()
						? "The reconstructed live values could not be refreshed" : error);
				diag::log_tagged_fmt("struct_recon",
					"refresh_value_history_done");
			};
			const auto refresh_submission = aida::infra::executor::submit(std::move(sub));
			if (!refresh_submission.submitted) {
				diag::log_tagged_fmt("struct_recon", "refresh_value_history_post_failed");
				st.operation_error = true;
				st.operation_status = refresh_submission.reject_reason.empty()
					? "The value refresh queue rejected the request."
					: refresh_submission.reject_reason;
			} else {
				st.operation_error = false;
				st.operation_status = "Value refresh queued; displayed values remain the last completed snapshot.";
				aida::ui::task_center::task_registration_t registration;
				registration.owner = "analysis";
				registration.owner_view = "view.types.struct_recon";
				registration.owner_action = "types.structure.refresh_values";
				registration.label = "Refresh reconstructed live values";
				registration.stage = "Queued";
				registration.target = "Address " + std::to_string(base);
				static_cast<void>(aida::ui::task_center::register_executor_job(
					refresh_submission.task_id, std::move(registration)));
			}
			diag::log_tagged_fmt("struct_recon",
				"refresh_clicked base=0x%llX",
				static_cast<unsigned long long>(base));
		} else {
			st.operation_error = true;
			st.operation_status = "Refresh requires an active reconstructed structure with a nonzero base address.";
			diag::log_tagged_fmt("struct_recon",
				"refresh_skipped active=%d base=0x%llX has_fields=%d",
				active ? 1 : 0,
				static_cast<unsigned long long>(base),
				any_fields ? 1 : 0);
		}
	}

	cy = oy + toolbar_h + 8.f;
	if (st.operation_pending) {
		auto workspace = disasm_view::capture_selected_workspace();
		const auto mutation = disasm_view::mutation_state(workspace);
		if (!workspace.workspace ||
			workspace.workspace->generation() != st.operation_generation) {
			st.operation_pending = false;
			st.operation_error = true;
			st.operation_status = "Analysis generation changed before the structure application committed.";
		} else if (mutation.overlay_revision > st.operation_overlay_revision) {
			st.operation_pending = false;
			st.operation_error = false;
			st.operation_status = "Structure declaration and base application committed to the reversible overlay.";
		} else if (mutation.pending == 0 && !mutation.error.empty()) {
			st.operation_pending = false;
			st.operation_error = true;
			st.operation_status = mutation.error;
		}
	}
	if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !refresh_available)
		ImGui::SetTooltip("Refresh requires a reconstructed structure with a nonzero live base address");
	if (!st.operation_status.empty()) {
		dl->AddText(ImVec2(ox + 12.f, cy), aida::ui::with_alpha(
			st.operation_error ? th.error : (st.operation_pending ? th.warning : th.success), alpha),
			st.operation_status.c_str());
		cy += 22.f;
	}

	bool driver_loaded = driver_bridge::is_loaded();
	bool sr_static_pe = function_index::detail::static_pe_active();
	if (!driver_loaded && !sr_static_pe) {
		static bool s_no_driver_logged = false;
		if (!s_no_driver_logged) {
			s_no_driver_logged = true;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
			diag::log_tagged("types_audit",
				"[types_audit] inferred_view_no_driver BROKEN reason='driver_not_loaded'");
#endif
		}
		float callout_h = 40.f;
		ui_anim::render_inline_callout(dl, ox + 8.f, cy, width - 16.f, callout_h,
			"Inferred reconstruction needs an attached process. Attach via the debugger or scanner views first.",
			ui_anim::callout_kind_t::warn,
			accent_r, accent_g, accent_b, alpha);
		cy += callout_h + 8.f;
	}

	const struct_recon::reconstructed_struct_t empty_frame_structure;
	const auto& current_copy = frame_structure ? *frame_structure : empty_frame_structure;

	if (current_copy.fields.empty() && !monitoring) {
		ImVec2 sz = ImVec2(width, oy + height - cy - 8.f);
		aida::ui::empty_state::config_t cfg;
		cfg.glyph = aida::ui::empty_state::glyph_t::memory;
		cfg.title = driver_loaded ? "No struct reconstructed" : "Attach a process first";
		cfg.body  = driver_loaded
			? "Enter a base address and click Snapshot to reconstruct struct layout."
			: "Inferred-struct reconstruction reads live memory and needs an attached target. Open the debugger or scanner view to attach.";
		cfg.max_width = 380.f;
		aida::ui::empty_state::render(ImVec2(ox, cy), sz, cfg);
		ImGui::EndChild();
		return;
	}

	{
		char info_buf[160];
		std::snprintf(info_buf, sizeof(info_buf), "%s   0x%llX   %d bytes   %zu fields",
			current_copy.name.c_str(),
			static_cast<unsigned long long>(current_copy.base_address),
			current_copy.total_size,
			current_copy.fields.size());
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();
		dl->AddText(code_font, aida::ui::components::detail::ui_fs() * 1.10f, ImVec2(cx, cy),
			aida::ui::with_alpha(th.accent_u32, alpha), info_buf);
		cy += 28.f;
	}

	bool show_right_panel = width > 640.f;
	float main_w = show_right_panel ? width * 0.62f : width - 24.f;
	float right_x = ox + main_w + 12.f;

	const float row_h = 38.f;
	const float table_top = cy;
	const float table_h = oy + height - cy - 8.f;
	float content_h = static_cast<float>(current_copy.fields.size()) * row_h;
	float visible_h = table_h;

	const float col_offset_w = main_w * 0.10f;
	const float col_glyph_w  = 24.f;
	const float col_type_w   = main_w * 0.13f;
	const float col_name_w   = main_w * 0.22f;
	const float col_size_w   = main_w * 0.07f;
	const float col_conf_w   = main_w * 0.08f;
	const float col_heat_w   = main_w * 0.10f;

	ImU32 hdr_bg = aida::ui::with_alpha(th.panel_header, alpha * 0.9f);
	dl->AddRectFilled(ImVec2(ox, cy), ImVec2(ox + main_w, cy + row_h), hdr_bg, 6.f);
	dl->AddLine(ImVec2(ox, cy + row_h - 1.f), ImVec2(ox + main_w, cy + row_h - 1.f),
		aida::ui::with_alpha(th.border_subtle, alpha));

	ImFont* head_em = aida::ui::fonts::body_em();
	if (!head_em) head_em = ImGui::GetFont();
	const float fs_sr_base = aida::ui::components::detail::ui_fs();
	const float fs_sr_hdr  = fs_sr_base * 0.95f;
	{
		float hx = cx;
		ImU32 hc = aida::ui::with_alpha(th.text_secondary, alpha);
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Offset");
		hx += col_offset_w + col_glyph_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Type");
		hx += col_type_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Name");
		hx += col_name_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Size");
		hx += col_size_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Conf");
		hx += col_conf_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Heat");
		hx += col_heat_w;
		dl->AddText(head_em, fs_sr_hdr, ImVec2(hx, cy + 10.f), hc, "Comment");
	}
	cy += row_h + 2.f;
	visible_h -= row_h + 2.f;

	float wheel = 0.f;
	if (ImGui::IsMouseHoveringRect(ImVec2(ox, cy), ImVec2(ox + main_w, oy + height))) {
		wheel = ImGui::GetIO().MouseWheel;
	}
	if (wheel != 0.f) st.target_scroll_y -= wheel * row_h * 3.f;
	if (st.target_scroll_y < 0.f) st.target_scroll_y = 0.f;
	float max_scroll = std::max(0.f, content_h - visible_h);
	if (st.target_scroll_y > max_scroll) st.target_scroll_y = max_scroll;
	st.scroll_y = aida::motion::smooth_lerp(st.scroll_y, st.target_scroll_y, 14.f, dt);

	ImGui::PushClipRect(ImVec2(ox, cy), ImVec2(ox + main_w, oy + height - 8.f), true);

	int first_vis = static_cast<int>(st.scroll_y / row_h);
	int last_vis = first_vis + static_cast<int>(visible_h / row_h) + 2;
	if (first_vis < 0) first_vis = 0;
	if (last_vis > static_cast<int>(current_copy.fields.size()))
		last_vis = static_cast<int>(current_copy.fields.size());

	int context_request = -1;
	bool pointer_context_request = false;
	for (int i = first_vis; i < last_vis; ++i) {
		float ry = cy + static_cast<float>(i) * row_h - st.scroll_y;
		if (ry + row_h < cy || ry > oy + height) continue;

		const auto& field = current_copy.fields[static_cast<size_t>(i)];
		auto& fa = fanim(i);

		const float entrance = 1.f;

		ImVec2 rmin(ox, ry);
		ImVec2 rmax(ox + main_w, ry + row_h);

		ImGui::SetCursorScreenPos(rmin);
		ImGui::PushID(i);
		ImGui::InvisibleButton("##struct_recon_field", ImVec2(main_w, row_h));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		aida::preview::semantics::register_last_item(
			studio_recon_field_id(current_copy, field),
			"reconstruction-field-row", false, false,
			"aida.dock-window.view.types.struct-recon");
#endif
		const bool hovered = ImGui::IsItemHovered();
		const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
		const bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
		const bool focused = ImGui::IsItemFocused();
		ImGui::PopID();
		bool selected = (st.selected_field == i);

		ImU32 row_fill;
		if (selected) row_fill = aida::ui::with_alpha(th.selection, alpha);
		else if (hovered) row_fill = aida::ui::with_alpha(th.hover_wash, alpha);
		else row_fill = (i & 1)
			? aida::ui::with_alpha(th.panel_bg, alpha * 0.55f * entrance)
			: aida::ui::with_alpha(IM_COL32(0,0,0,0), alpha);

		dl->AddRectFilled(rmin, rmax, row_fill, 4.f);
		if (selected) {
			dl->AddRectFilled(ImVec2(rmin.x, rmin.y), ImVec2(rmin.x + 3.f, rmax.y),
				aida::ui::with_alpha(th.accent_u32, alpha), 1.5f);
		}

		float change_v = fa.change_flash.tick(dt, 1.7f);
		if (change_v > 0.001f) {
			ImU32 pulse = aida::ui::with_alpha(th.error, alpha * change_v * 0.45f);
			dl->AddRectFilled(rmin, rmax, pulse, 4.f);
		}
		float write_v = fa.write_success.tick(dt, 2.0f);
		if (write_v > 0.001f) {
			ImU32 pulse = aida::ui::with_alpha(th.success_soft, alpha * write_v * 1.4f);
			dl->AddRectFilled(rmin, rmax, pulse, 4.f);
		}

		uint64_t cur_val = 0;
		if (!field.value_history.values.empty() && field.value_history.count > 0) {
			int last_idx = (field.value_history.write_idx - 1 + struct_recon::value_history_t::MAX_ENTRIES)
				% struct_recon::value_history_t::MAX_ENTRIES;
			cur_val = field.value_history.values[static_cast<size_t>(last_idx)];
		}
		if (fa.has_last && fa.last_value != cur_val) {
			fa.change_flash.trigger();
		}
		fa.last_value = cur_val;
		fa.has_last = true;

		if (clicked) {
			diag::log_tagged_fmt("struct_recon",
				"field_row_click idx=%d offset=0x%llX type=%s name='%s' size=%d",
				i,
				static_cast<unsigned long long>(field.offset),
				struct_recon::field_type_name(field.type),
				field.name.c_str(),
				field.size);
			st.selected_field = i;
			publish_field_selection(current_copy, field);
		}
		if (right_clicked) {
			st.selected_field = i;
			context_request = i;
			pointer_context_request = true;
			publish_field_selection(current_copy, field);
		}
		const ImGuiIO& field_io = ImGui::GetIO();
		if (selected && focused && (ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
			(field_io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false))))
			context_request = i;

		float rx = cx;
		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		const float fs_sr_row  = fs_sr_base * 0.95f;
		const float fs_sr_body = fs_sr_base * 1.00f;
		char buf[160];
		std::snprintf(buf, sizeof(buf), "0x%04llX",
			static_cast<unsigned long long>(field.offset));
		dl->AddText(code_font, fs_sr_row, ImVec2(rx + 6.f, ry + 10.f),
			aida::ui::with_alpha(th.text_address, alpha * entrance), buf);
		rx += col_offset_w;

		ImU32 type_col = type_color_token(field.type, alpha * entrance);
		render_type_glyph(dl, ImVec2(rx + col_glyph_w * 0.5f, ry + row_h * 0.5f),
			field.type, type_col, 16.f);
		rx += col_glyph_w;

		if (field.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "%s[%d]",
				struct_recon::field_type_name(field.type), field.array_count);
		} else {
			std::snprintf(buf, sizeof(buf), "%s", struct_recon::field_type_name(field.type));
		}
		dl->AddText(code_font, fs_sr_row, ImVec2(rx + 4.f, ry + 10.f), type_col, buf);
		rx += col_type_w;

		ImU32 name_col = aida::ui::with_alpha(th.text_primary, alpha * entrance);
		dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
			fs_sr_body, ImVec2(rx + 4.f, ry + 10.f), name_col, field.name.c_str());
		rx += col_name_w;

		std::snprintf(buf, sizeof(buf), "%d", field.size);
		dl->AddText(code_font, fs_sr_row, ImVec2(rx + 4.f, ry + 10.f),
			aida::ui::with_alpha(th.text_dim, alpha * entrance), buf);
		rx += col_size_w;

		{
			const char* conf_str = "-";
			ImU32 conf_col = aida::ui::with_alpha(th.text_dim, alpha * entrance);
			if (field.type_confidence >= 75.f) {
				conf_str = "Strong"; conf_col = aida::ui::with_alpha(th.success, alpha * entrance);
			} else if (field.type_confidence >= 50.f) {
				conf_str = "Med"; conf_col = aida::ui::with_alpha(th.warning, alpha * entrance);
			} else if (field.type_confidence >= 25.f) {
				conf_str = "Weak"; conf_col = aida::ui::with_alpha(th.error, alpha * entrance);
			}
			dl->AddText(code_font, fs_sr_row, ImVec2(rx + 4.f, ry + 10.f), conf_col, conf_str);
		}
		rx += col_conf_w;

		{
			int heat = field.value_history.heat_level();
			float target = static_cast<float>(heat) / 10.f;
			fa.heat_v = aida::motion::smooth_lerp(fa.heat_v, target, 8.f, dt);
			float visible_v = fa.heat_v;
			float bar_w = (col_heat_w - 12.f) * visible_v;
			ImU32 heat_col;
			if (heat <= 3)      heat_col = aida::ui::with_alpha(th.success, alpha * 0.85f);
			else if (heat <= 6) heat_col = aida::ui::with_alpha(th.warning, alpha * 0.85f);
			else                heat_col = aida::ui::with_alpha(th.error,   alpha * 0.85f);
			float bar_y = ry + (row_h - 6.f) * 0.5f;
			dl->AddRectFilled(ImVec2(rx + 6.f, bar_y),
				ImVec2(rx + 6.f + col_heat_w - 12.f, bar_y + 6.f),
				aida::ui::with_alpha(th.panel_header, alpha * 0.6f), 2.f);
			if (bar_w > 0.5f) {
				dl->AddRectFilled(ImVec2(rx + 6.f, bar_y),
					ImVec2(rx + 6.f + bar_w, bar_y + 6.f),
					heat_col, 2.f);
			}
		}
		rx += col_heat_w;

		if (!field.comment.empty()) {
			dl->AddText(aida::ui::fonts::body() ? aida::ui::fonts::body() : ImGui::GetFont(),
				fs_sr_row, ImVec2(rx + 4.f, ry + 10.f),
				aida::ui::with_alpha(th.text_dim, alpha * entrance),
				field.comment.c_str());
		} else if (!field.accesses.empty()) {
			std::snprintf(buf, sizeof(buf), "%zu accesses", field.accesses.size());
			dl->AddText(code_font, fs_sr_row, ImVec2(rx + 4.f, ry + 10.f),
				aida::ui::with_alpha(th.text_dim, alpha * entrance), buf);
		}
	}
	if (context_request < 0 && st.selected_field >= 0 &&
		ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
		const ImGuiIO& field_io = ImGui::GetIO();
		if (ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
			(field_io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false)))
			context_request = st.selected_field;
	}
	if (context_request >= 0 &&
		context_request < static_cast<int>(current_copy.fields.size())) {
		const auto& field = current_copy.fields[static_cast<size_t>(context_request)];
		st.context_field = context_request;
		st.context_base = current_copy.base_address;
		st.context_offset = field.offset;
		st.context_size = field.size;
		st.context_name = field.name;
		st.context_struct_name = current_copy.name;
	}

	ImGui::PopClipRect();

	if (context_request >= 0) {
		const auto live_snapshot = struct_recon::capture_current_snapshot();
		const struct_recon::reconstructed_struct_t empty_live_structure;
		const auto& live = live_snapshot ? *live_snapshot : empty_live_structure;
		const bool current = context_is_current(live, st);
		const bool valid_field = current && st.context_field >= 0 &&
			st.context_field < static_cast<int>(live.fields.size());
		const auto field = valid_field
			? live.fields[static_cast<size_t>(st.context_field)]
			: struct_recon::struct_field_t{};
		uint64_t absolute = 0;
		const bool address_valid = valid_field &&
			checked_field_address(live.base_address, field.offset, absolute);
		auto workspace = disasm_view::capture_selected_workspace();
		const bool mapped = address_valid && workspace &&
			disasm_view::typed_address(workspace, absolute).has_value();
		aida::ui::application_ui::retained_entity_context_t retained;
		retained.owner_id = "types.reconstruction.field";
		retained.entity_id = st.context_struct_name + ":" + st.context_name + ":" +
			std::to_string(st.context_offset);
		retained.entity_generation = workspace.publication
			? workspace.publication->generation : 0;
		retained.active_view = aida::ui::stable_view_id_t("view.types.struct_recon");
		const int retained_field = st.context_field;
		const std::uint64_t retained_base = st.context_base;
		const std::uint64_t retained_offset = st.context_offset;
		const int retained_size = st.context_size;
		const std::string retained_name = st.context_name;
		const std::string retained_struct_name = st.context_struct_name;
		const std::uint64_t retained_field_hash = field_identity_hash(field);
		const std::uint64_t retained_workspace_generation = workspace.workspace
			? workspace.workspace->generation() : 0;
		const std::uint64_t retained_analysis_revision = workspace.publication
			? workspace.publication->analysis_revision : 0;
		const std::string retained_workspace_id = workspace.workspace
			? workspace.workspace->identity().binary_id().to_hex() : std::string{};
		retained.validate_identity = [retained_field, retained_base, retained_offset,
			retained_size, retained_name, retained_struct_name, workspace,
			retained_workspace_generation, retained_analysis_revision,
			retained_workspace_id, retained_field_hash] {
			const auto selected = disasm_view::capture_selected_workspace();
			if (!workspace.workspace || !workspace.publication ||
				workspace.workspace->closing() || workspace.workspace->closed() ||
				workspace.workspace->generation() != retained_workspace_generation ||
				workspace.publication->analysis_revision != retained_analysis_revision ||
				!selected.workspace || !selected.publication ||
				selected.workspace != workspace.workspace ||
				selected.publication != workspace.publication ||
				selected.workspace->identity().binary_id().to_hex() != retained_workspace_id ||
				selected.workspace->generation() != retained_workspace_generation ||
				selected.publication->analysis_revision != retained_analysis_revision)
				return aida::ui::capability_state_t::unavailable(
					"The type workspace changed; select the field again");
			const auto snapshot = struct_recon::capture_current_snapshot();
			if (!snapshot || retained_field < 0 ||
				retained_field >= static_cast<int>(snapshot->fields.size()) ||
				snapshot->base_address != retained_base || snapshot->name != retained_struct_name)
				return aida::ui::capability_state_t::unavailable(
					"The reconstruction snapshot changed; select the field again");
			const auto& candidate = snapshot->fields[static_cast<std::size_t>(retained_field)];
			return candidate.offset == retained_offset && candidate.size == retained_size &&
				candidate.name == retained_name &&
				field_identity_hash(candidate) == retained_field_hash
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"The retained field identity no longer matches the live reconstruction");
		};
		auto add_action = [&retained](std::string id, bool enabled,
			const char* reason, auto invoke) {
			aida::ui::application_ui::retained_entity_action_t action;
			action.action_id = std::move(id);
			action.capability = enabled ? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(reason);
			action.invoke = std::move(invoke);
			retained.actions.push_back(std::move(action));
		};
		add_action("types.reconstruction.field.follow_disassembly", current && mapped,
			"The field address is not mapped by the selected analysis workspace",
			[absolute, workspace] {
				disasm_view::goto_address(absolute, workspace);
				aida::ui::application_views::open_or_focus(
					aida::ui::stable_view_id_t("document.disassembly"));
				return aida::ui::action_handler_result_t::completed();
			});
		const size_t shown = (std::min)(field.accesses.size(), static_cast<size_t>(64));
		for (size_t index = 0; index < shown; ++index) {
			const auto access = field.accesses[index];
			add_action("types.reconstruction.field.follow_access." + std::to_string(index + 1),
				static_cast<bool>(workspace), "No analysis workspace is selected",
				[access, workspace] {
					disasm_view::goto_address(access.instruction_addr, workspace);
					aida::ui::application_views::open_or_focus(
						aida::ui::stable_view_id_t("document.disassembly"));
					return aida::ui::action_handler_result_t::completed();
				});
		}
		const std::string field_name = field.name;
		const std::string field_type = valid_field ? struct_recon::field_type_name(field.type) : "";
		add_action("types.reconstruction.field.copy_name", valid_field,
			"The retained field is stale", [field_name] {
				ImGui::SetClipboardText(field_name.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
		add_action("types.reconstruction.field.copy_type", valid_field,
			"The retained field is stale", [field_type] {
				ImGui::SetClipboardText(field_type.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
		add_action("types.reconstruction.field.copy_offset", valid_field,
			"The retained field is stale", [field] {
			char text[32]{};
			std::snprintf(text, sizeof(text), "0x%llX",
				static_cast<unsigned long long>(field.offset));
			ImGui::SetClipboardText(text);
			return aida::ui::action_handler_result_t::completed();
		});
		add_action("types.reconstruction.field.copy_absolute_address", address_valid,
			"The field address overflowed the target address range", [absolute] {
			char text[32]{};
			std::snprintf(text, sizeof(text), "0x%llX",
				static_cast<unsigned long long>(absolute));
			ImGui::SetClipboardText(text);
			return aida::ui::action_handler_result_t::completed();
		});
		add_action("types.reconstruction.field.copy_access_evidence",
			valid_field && !field.accesses.empty() && field.accesses.size() <= 4096,
			field.accesses.size() > 4096
				? "The access evidence exceeds the bounded 4,096-entry export limit"
				: "No monitored instruction access references were captured for this field", [field] {
			if (field.accesses.size() > 4096)
				return aida::ui::action_handler_result_t::failed(
					"The access evidence exceeds the bounded 4,096-entry export limit");
			std::string evidence;
			evidence.reserve(64U * 1024U);
			for (const auto& access : field.accesses) {
				char prefix[96]{};
				std::snprintf(prefix, sizeof(prefix), "0x%llX %s ",
					static_cast<unsigned long long>(access.instruction_addr),
					access.is_write ? "write" : "read");
				const std::size_t required = std::strlen(prefix) + access.disasm_text.size() + 1;
				if (required > 64U * 1024U - evidence.size())
					return aida::ui::action_handler_result_t::failed(
						"The access evidence exceeds the bounded 64 KiB export limit");
				evidence += prefix;
				evidence += access.disasm_text;
				evidence.push_back('\n');
			}
			ImGui::SetClipboardText(evidence.c_str());
			return aida::ui::action_handler_result_t::completed();
		});
		add_action("types.reconstruction.field.declare_apply", valid_field,
			"The retained field is stale", [&st] {
			const auto result = stage_declare_apply_review();
			st.operation_status = result.message;
			st.operation_error = !result.success;
			return result;
		});
		const auto editable_binding = valid_field
			? find_editable_field_binding(live, field)
			: std::optional<editable_field_binding_t>{};
		const bool workspace_available = workspace.workspace && workspace.publication &&
			!workspace.workspace->closing() && !workspace.workspace->closed();
		const bool editable_available = current && workspace_available &&
			editable_binding.has_value() &&
			struct_dissector::catalog_mutation_available();
		const char* editable_reason = !workspace_available
			? "Select the analysis workspace that owns this reconstruction first"
			: !editable_binding
			? "Create or select the exact editable structure and field in Structure Dissector first"
			: !struct_dissector::catalog_mutation_available()
			? "Another Structure Dissector persistence transaction is running"
			: "The retained reconstructed field is stale";
		add_action("types.reconstruction.field.rename", editable_available,
			editable_reason, [live_snapshot, retained_field, editable_binding, workspace] {
				if (!editable_binding)
					return aida::ui::action_handler_result_t::failed(
						"The editable Structure Dissector field is unavailable");
				return stage_retained_field_edit(local_state_t::retained_edit_kind_t::rename,
					live_snapshot, retained_field, *editable_binding, workspace);
			});
		add_action("types.reconstruction.field.set_type", editable_available,
			editable_reason, [live_snapshot, retained_field, editable_binding, workspace] {
				if (!editable_binding)
					return aida::ui::action_handler_result_t::failed(
						"The editable Structure Dissector field is unavailable");
				return stage_retained_field_edit(local_state_t::retained_edit_kind_t::retype,
					live_snapshot, retained_field, *editable_binding, workspace);
			});
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
		const bool process_current = static_cast<bool>(workspace.workspace);
#else
		const auto process = workspace.workspace ? workspace.workspace->identity().process()
			: std::optional<aida::analysis::process_identity_t>{};
		const bool process_current = process && driver_bridge::is_loaded() &&
			driver_bridge::attached_pid() != 0 && driver_bridge::attached_pid() == process->pid;
#endif
		const bool live_edit_available = editable_available && process_current &&
			editable_binding->live_snapshot_current;
		const char* live_edit_reason = !editable_binding
			? "Create or select the exact editable structure and field in Structure Dissector first"
			: !process_current
			? "Attach the original process workspace before editing live memory"
			: !editable_binding->live_snapshot_current
			? "Refresh the exact Structure Dissector field at this reconstruction base first"
			: editable_reason;
		add_action("types.reconstruction.field.edit_live", live_edit_available,
			live_edit_reason, [live_snapshot, retained_field, editable_binding, workspace] {
				if (!editable_binding)
					return aida::ui::action_handler_result_t::failed(
						"The editable Structure Dissector field is unavailable");
				return stage_retained_field_edit(local_state_t::retained_edit_kind_t::live_value,
					live_snapshot, retained_field, *editable_binding, workspace);
			});
		aida::automation_ui::entity_evidence::snapshot_t evidence;
		evidence.workspace_id = workspace.workspace
			? workspace.workspace->identity().binary_id().to_hex() : std::string{};
		evidence.source_view_id = "view.types.struct_recon";
		evidence.source_kind = "reconstructed_field";
		evidence.entity_id = retained.entity_id;
		evidence.display_label = retained_struct_name + "." + field_name;
		constexpr std::size_t maximum_evidence_bytes = 64U * 1024U;
		const auto append_evidence = [&](const std::string& value) {
			if (value.size() > maximum_evidence_bytes - evidence.excerpt.size())
				return false;
			evidence.excerpt.append(value);
			return true;
		};
		if (!append_evidence("Structure: ") || !append_evidence(retained_struct_name) ||
			!append_evidence("\nField: ") || !append_evidence(field_name) ||
			!append_evidence("\nType: ") || !append_evidence(field_type) ||
			!append_evidence("\nOffset: ") ||
			!append_evidence(std::to_string(retained_offset)) ||
			!append_evidence("\nSize: ") ||
			!append_evidence(std::to_string(retained_size)) ||
			!append_evidence("\nCaptured accesses: ") ||
			!append_evidence(std::to_string(field.accesses.size())))
			evidence.excerpt.clear();
		const std::size_t evidence_accesses = (std::min)(field.accesses.size(),
			static_cast<std::size_t>(32));
		for (std::size_t index = 0; index < evidence_accesses &&
			!evidence.excerpt.empty(); ++index) {
			const auto& access = field.accesses[index];
			if (!append_evidence("\n") ||
				!append_evidence(std::to_string(access.instruction_addr)) ||
				!append_evidence(access.is_write ? " write " : " read ") ||
				!append_evidence(access.disasm_text)) {
				evidence.excerpt.clear();
				break;
			}
		}
		evidence.address = address_valid ? absolute : 0;
		evidence.revision = retained_analysis_revision;
		evidence.generation = retained_workspace_generation;
		evidence.sensitive = true;
		evidence.return_to_source = [workspace, retained_field, retained_base,
			retained_offset, retained_size, retained_name, retained_struct_name,
			retained_workspace_generation, retained_analysis_revision,
			retained_workspace_id, retained_field_hash](std::string& reason) {
			const auto selected = disasm_view::capture_selected_workspace();
			if (!workspace.workspace || !workspace.publication ||
				workspace.workspace->generation() != retained_workspace_generation ||
				workspace.publication->analysis_revision != retained_analysis_revision ||
				!selected.workspace || !selected.publication ||
				selected.workspace != workspace.workspace ||
				selected.publication != workspace.publication ||
				selected.workspace->identity().binary_id().to_hex() != retained_workspace_id ||
				selected.workspace->generation() != retained_workspace_generation ||
				selected.publication->analysis_revision != retained_analysis_revision) {
				reason = "The reconstruction workspace changed; capture the field again.";
				return false;
			}
			const auto snapshot = struct_recon::capture_current_snapshot();
			if (!snapshot || retained_field < 0 ||
				retained_field >= static_cast<int>(snapshot->fields.size()) ||
				snapshot->base_address != retained_base || snapshot->name != retained_struct_name) {
				reason = "The reconstruction snapshot changed; capture the field again.";
				return false;
			}
			const auto& candidate = snapshot->fields[static_cast<std::size_t>(retained_field)];
			if (candidate.offset != retained_offset || candidate.size != retained_size ||
				candidate.name != retained_name ||
				field_identity_hash(candidate) != retained_field_hash) {
				reason = "The reconstructed field identity changed; capture it again.";
				return false;
			}
			const auto opened = aida::ui::application_views::open_or_focus(
				aida::ui::stable_view_id_t("view.types.struct_recon"));
			reason = opened.ok() ? std::string{} : opened.detail;
			return opened.ok();
		};
		const bool evidence_available = valid_field && static_cast<bool>(workspace) &&
			!evidence.excerpt.empty();
		aida::automation_ui::entity_evidence::append_actions(retained,
			std::move(evidence), evidence_available
				? aida::ui::capability_state_t::available()
				: aida::ui::capability_state_t::unavailable(
					"The retained reconstruction field or workspace is stale"));
		aida::ui::application_ui::open_retained_entity_context_menu(
			std::move(retained), pointer_context_request
				? aida::ui::context_menu_open_origin_t::pointer
				: ImGui::IsKeyPressed(ImGuiKey_Menu, false)
				? aida::ui::context_menu_open_origin_t::menu_key
				: aida::ui::context_menu_open_origin_t::shift_f10);
	}
	aida::ui::application_ui::render_retained_entity_context_menu(
		"types.reconstruction.field");

	if (content_h > visible_h && visible_h > 0.f) {
		float bar_x = ox + main_w - 12.f;
		float bar_y = table_top + row_h + 2.f;
		float bar_h = visible_h;
		float ratio = visible_h / content_h;
		float thumb_h = std::max(bar_h * ratio, 24.f);
		float track = bar_h - thumb_h;
		float scroll_ratio = (content_h - visible_h > 0.f) ? st.scroll_y / (content_h - visible_h) : 0.f;
		float thumb_y = bar_y + track * scroll_ratio;
		dl->AddRectFilled(ImVec2(bar_x, bar_y), ImVec2(bar_x + 6.f, bar_y + bar_h),
			aida::ui::with_alpha(th.panel_header, alpha * 0.4f), 3.f);
		dl->AddRectFilled(ImVec2(bar_x, thumb_y), ImVec2(bar_x + 6.f, thumb_y + thumb_h),
			aida::ui::with_alpha(th.accent_dim, alpha), 3.f);
	}

	if (show_right_panel && st.selected_field >= 0 &&
		st.selected_field < static_cast<int>(current_copy.fields.size())) {

		const auto& sel = current_copy.fields[static_cast<size_t>(st.selected_field)];

		float rp_w = (ox + width - 8.f) - (right_x - 4.f);
		float rp_h = oy + height - table_top - 8.f;
		ImVec2 r_a = ImVec2(right_x - 4.f, table_top);
		ImVec2 r_b = ImVec2(r_a.x + rp_w, r_a.y + rp_h);

		aida::ui::blur::layer_request_t req;
		req.pos = r_a; req.size = ImVec2(rp_w, rp_h);
		req.radius = 10.f; req.alpha = alpha; req.strength = 0.5f;
		aida::ui::blur::schedule(req);
		aida::ui::blur::render_glass_fill(dl, r_a, r_b, 10.f, alpha);
		aida::ui::blur::render_glass_border(dl, r_a, r_b, 10.f, alpha, 1.f);

		float ry = r_a.y + 12.f;
		float rxx = r_a.x + 12.f;

		ImFont* head = aida::ui::fonts::body_strong();
		if (!head) head = ImGui::GetFont();
		const float fs_det_title = fs_sr_base * 1.05f;
		const float fs_det_row   = fs_sr_base * 0.95f;
		const float fs_det_body  = fs_sr_base * 1.00f;
		dl->AddText(head, fs_det_title, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_primary, alpha), "Field Details");
		ry += 30.f;

		ImFont* code_font = aida::ui::fonts::code();
		if (!code_font) code_font = ImGui::GetFont();

		char buf[160];
		std::snprintf(buf, sizeof(buf), "Offset   0x%04llX",
			static_cast<unsigned long long>(sel.offset));
		dl->AddText(code_font, fs_det_row, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_secondary, alpha), buf);
		ry += 22.f;

		std::snprintf(buf, sizeof(buf), "Size     %d bytes", sel.size);
		dl->AddText(code_font, fs_det_row, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_secondary, alpha), buf);
		ry += 22.f;

		ImU32 type_c = type_color_token(sel.type, alpha);
		render_type_glyph(dl, ImVec2(rxx + 6.f, ry + 9.f), sel.type, type_c, 16.f);
		std::snprintf(buf, sizeof(buf), "Type     %s",
			struct_recon::field_type_name(sel.type));
		dl->AddText(code_font, fs_det_row, ImVec2(rxx + 22.f, ry), type_c, buf);
		ry += 24.f;

		if (sel.array_count > 1) {
			std::snprintf(buf, sizeof(buf), "Array    [%d]", sel.array_count);
			dl->AddText(code_font, fs_det_row, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.accent_u32, alpha), buf);
			ry += 22.f;
		}

		{
			const char* conf_name = "Unknown";
			aida::ui::pill_kind_t pk = aida::ui::pill_kind_t::neutral;
			if (sel.type_confidence >= 75.f) { conf_name = "Strong"; pk = aida::ui::pill_kind_t::success; }
			else if (sel.type_confidence >= 50.f) { conf_name = "Moderate"; pk = aida::ui::pill_kind_t::warning; }
			else if (sel.type_confidence >= 25.f) { conf_name = "Weak"; pk = aida::ui::pill_kind_t::error; }
			ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
			aida::ui::pill_kind(conf_name, pk, aida::ui::size_t_::sm, true);
			ry += 24.f;
		}

		{
			int heat = sel.value_history.heat_level();
			std::snprintf(buf, sizeof(buf), "Heat     %d/10  (%d unique)",
				heat, static_cast<int>(sel.value_history.unique_count()));
			dl->AddText(code_font, fs_det_row, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.text_secondary, alpha), buf);
			ry += 24.f;
		}

		ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
		dl->AddText(code_font, fs_det_row, ImVec2(rxx, ry),
			aida::ui::with_alpha(th.text_dim, alpha), "Name");
		dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
			fs_det_body, ImVec2(rxx + 78.f, ry),
			aida::ui::with_alpha(th.text_primary, alpha), sel.name.c_str());
		ry += 28.f;

		if (sel.type == struct_recon::field_type_t::vtable_ptr && !sel.vtable_entries.empty()) {
			float arrow_x = rxx;
			ImU32 arr_col = aida::ui::with_alpha(th.accent_u32, alpha);
			ImGui::SetCursorScreenPos(ImVec2(rxx, ry));
			ImGui::InvisibleButton("##sr_vtable_hdr", ImVec2(rp_w - 24.f, 22.f));
			if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
				st.vtable_expanded = !st.vtable_expanded;
				diag::log_tagged_fmt("struct_recon",
					"vtable_toggle expanded=%d field_idx=%d entry_count=%zu",
					st.vtable_expanded ? 1 : 0,
					st.selected_field,
					sel.vtable_entries.size());
				if (st.vtable_expanded) st.vtable_expand.start(0.18f);
				else                    st.vtable_expand.start_reverse(0.18f);
			}
			st.vtable_expand.tick(dt);
			if (st.vtable_expanded && st.vtable_expand.at_origin()) {
				st.vtable_expand.start(0.18f);
			}
			float arrow_p = st.vtable_expanded ? 1.f : 0.f;
			float arrow_off = st.vtable_expand.eased();
			float ax = arrow_x + 2.f;
			float ay = ry + 11.f;
			ImVec2 a1, a2, a3;
			if (arrow_off > 0.5f) {
				a1 = ImVec2(ax - 1.f, ay - 3.f);
				a2 = ImVec2(ax + 7.f, ay - 3.f);
				a3 = ImVec2(ax + 3.f, ay + 4.f);
			} else {
				a1 = ImVec2(ax, ay - 4.f);
				a2 = ImVec2(ax + 6.f, ay);
				a3 = ImVec2(ax, ay + 4.f);
			}
			(void)arrow_p;
			dl->AddTriangleFilled(a1, a2, a3, arr_col);
			dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
				fs_det_body, ImVec2(rxx + 16.f, ry + 5.f),
				aida::ui::with_alpha(th.error, alpha), "VTable Entries");
			char vbuf[24];
			std::snprintf(vbuf, sizeof(vbuf), "(%zu)", sel.vtable_entries.size());
			dl->AddText(code_font, fs_det_row,
				ImVec2(rxx + 160.f, ry + 6.f),
				aida::ui::with_alpha(th.text_dim, alpha), vbuf);
			ry += 30.f;

			float content_alpha = alpha * arrow_off;
			if (content_alpha > 0.01f) {
				for (size_t vi = 0; vi < sel.vtable_entries.size() && vi < 32; ++vi) {
					auto& ve = sel.vtable_entries[vi];
					bool has_symbol = ve.name.find('!') != std::string::npos ||
									   ve.name.find('+') != std::string::npos;
					ImU32 name_col = has_symbol
						? aida::ui::with_alpha(th.accent_u32, content_alpha)
						: aida::ui::with_alpha(th.text_dim, content_alpha);

					char idx_buf[16];
					std::snprintf(idx_buf, sizeof(idx_buf), "[%2d]", ve.index);
					dl->AddText(code_font, fs_det_row, ImVec2(rxx + 8.f, ry),
						aida::ui::with_alpha(th.text_dim, content_alpha), idx_buf);

					char addr_buf[24];
					std::snprintf(addr_buf, sizeof(addr_buf), "0x%llX",
						static_cast<unsigned long long>(ve.func_addr));
					dl->AddText(code_font, fs_det_row, ImVec2(rxx + 58.f, ry),
						aida::ui::with_alpha(th.text_address, content_alpha), addr_buf);

					float name_x = rxx + 220.f;
					if (name_x + 10.f < r_b.x - 12.f) {
						dl->AddText(code_font, fs_det_row, ImVec2(name_x, ry), name_col, ve.name.c_str());
					}
					ry += 22.f * arrow_off;
					if (ry > r_b.y - 60.f) break;
				}
			}
			ry += 6.f;
		}

		if (!sel.accesses.empty() && ry < r_b.y - 60.f) {
			dl->AddText(aida::ui::fonts::body_em() ? aida::ui::fonts::body_em() : ImGui::GetFont(),
				fs_det_body, ImVec2(rxx, ry),
				aida::ui::with_alpha(th.accent_u32, alpha), "Access Log");
			ry += 24.f;
			for (size_t ai = 0; ai < sel.accesses.size() && ai < 20; ++ai) {
				if (ry > r_b.y - 20.f) break;
				auto& acc = sel.accesses[static_cast<size_t>(ai)];
				char buf2[160];
				std::snprintf(buf2, sizeof(buf2), "%s 0x%llX  +0x%llX  %dB  x%d",
					acc.is_write ? "W" : "R",
					static_cast<unsigned long long>(acc.instruction_addr),
					static_cast<unsigned long long>(acc.access_offset),
					acc.access_size, acc.hit_count);
				dl->AddText(code_font, fs_det_row, ImVec2(rxx + 4.f, ry),
					aida::ui::with_alpha(th.text_dim, alpha), buf2);
				ry += 20.f;
			}
		}
	}

	ImGui::EndChild();
}

}
