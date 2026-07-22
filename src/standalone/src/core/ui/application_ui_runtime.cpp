#include "application_ui_runtime.hpp"

#include "context_menu_renderer.hpp"
#include "application_view_registry.hpp"
#include "design_system.hpp"
#include "explorer_views.hpp"
#include "output_views.hpp"
#include "programming_tasks.hpp"
#include "programming_language_views.hpp"
#include "task_center.hpp"
#include "toast_notification.hpp"
#include "ui_thread_dispatcher.hpp"
#include "workspace_layout.hpp"
#include "../../helpers/globals.h"
#include "../editor/code_editor.hpp"
#include "../editor/programming_language_service.hpp"
#include "../debugger/source_debug_service.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../debugger/debugger_interaction_context.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/debugger_preview_runtime.hpp"
#else
#include "../runtime/standalone_driver.hpp"
#endif
#include "../infra/executor.hpp"
#include "../session/analysis_session.hpp"
#include "../settings/standalone_settings.hpp"
#include "../settings/settings_persistence_service.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/comment_dialog.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/rename_dialog.hpp"
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/struct_recon_view.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../analysis/analysis_relationship_views.hpp"
#include "../ai/standalone_chat.hpp"
#include "../debugger/debugger_view.hpp"
#include "../network/network_view.hpp"
#include "../scanner/memory_scanner_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::ui::application_ui {

namespace {

std::filesystem::path path_from_utf8(std::string_view value) {
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value.begin(), value.end());
#endif
}

std::string path_to_utf8(const std::filesystem::path& value) {
    const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
    return encoded;
#endif
}

constexpr const char* k_editor_context_type = "context.editor.text";
constexpr const char* k_tab_context_type = "context.editor.tab";
constexpr const char* k_explorer_entry_context_type = "context.explorer.entry";
constexpr const char* k_explorer_empty_context_type = "context.explorer.empty";
constexpr const char* k_workspace_search_context_type = "context.workspace_search.result";
constexpr const char* k_programming_result_context_type = "context.programming.language.result";
constexpr const char* k_recent_context_type = "context.recent.item";
constexpr const char* k_output_context_type = "context.output.view";
constexpr const char* k_view_surface_context_type = "context.view.surface";
constexpr const char* k_retained_entity_context_type = "context.retained.entity";
constexpr const char* k_editor_scope = "scope.editor.text";
constexpr const char* k_editor_review_scope = "scope.editor.review";
constexpr const char* k_analysis_scope = "scope.analysis";
constexpr const char* k_debugger_scope = "scope.debugger";
constexpr const char* k_disassembly_scope = "scope.document.disassembly";
constexpr const char* k_output_scope = "scope.output";
constexpr const char* k_terminal_scope = "scope.terminal";
constexpr const char* k_network_intercept_scope = "scope.view.network.intercept";
constexpr const char* k_memory_scan_scope = "scope.view.memory.value_scan";
constexpr std::size_t k_maximum_keybinding_overrides = 512;
constexpr std::size_t k_maximum_keybinding_payload_bytes = 64U * 1024U;

struct editor_context_t {
    bool focused = false;
};

struct tab_context_t {
    int index = -1;
    std::string path;
    std::string name;
};

struct explorer_context_t {
    int index = -1;
    std::string path;
    std::string name;
    bool directory = false;
    std::vector<explorer_views::file_operation_target_t> targets;
    std::vector<std::uint64_t> entry_ids;
    std::vector<std::uint64_t> entry_generations;
    std::uint64_t index_generation = 0;
    std::array<explorer_views::file_operation_capability_t,
        static_cast<std::size_t>(explorer_views::file_operation_t::terminal_here) + 1>
        operation_capabilities{};
};

struct workspace_search_context_t {
    int index = -1;
    std::string path;
    std::string line_text;
    int line = 0;
    int column = 0;
};

struct programming_result_context_t {
    aida::editor::language_service::location_t location;
    std::string label;
    std::string provenance;
    aida::editor::language_service::capability_kind_t kind =
        aida::editor::language_service::capability_kind_t::references;
    std::uint64_t request_id = 0;
    std::uint64_t request_generation = 0;
    std::uint64_t provider_generation = 0;
    std::uint64_t index_generation = 0;
};

struct recent_context_t {
    std::string path;
    bool open_session = false;
};

struct output_context_t {
    int tab = static_cast<int>(bottom_tab_t::output);
};

struct view_surface_context_t {
    view_instance_id_t instance;
    std::string window_name;
};

struct retained_entity_runtime_context_t {
    retained_entity_context_t retained;
    const retained_entity_context_t* external = nullptr;

    const retained_entity_context_t& context() const noexcept {
        return external ? *external : retained;
    }
};

struct pending_action_confirmation_t {
    bool active = false;
    bool open_requested = false;
    std::string action;
    std::string label;
    std::string description;
    std::string consequence;
    action_invocation_source_t source = action_invocation_source_t::command_palette;
    interaction_context_t context;
    retained_entity_runtime_context_t retained_context;
};

struct runtime_t {
    application_action_registry_t actions;
    shortcut_resolver_t shortcuts;
    context_menu_catalog_t menus;
    shell_callbacks_t shell;
    editor_context_t editor;
    tab_context_t tab;
    explorer_context_t explorer;
    workspace_search_context_t workspace_search;
    programming_result_context_t programming_result;
    recent_context_t recent;
    output_context_t output;
    view_surface_context_t view_surface;
    retained_entity_runtime_context_t retained_entity;
    interaction_context_t current;
    interaction_context_t editor_popup_context;
    interaction_context_t tab_popup_context;
    interaction_context_t explorer_popup_context;
    interaction_context_t workspace_search_popup_context;
    interaction_context_t programming_result_popup_context;
    interaction_context_t recent_popup_context;
    interaction_context_t output_popup_context;
    interaction_context_t view_surface_popup_context;
    interaction_context_t retained_entity_popup_context;
    context_menu_open_request_t editor_popup_request;
    context_menu_open_request_t tab_popup_request;
    context_menu_open_request_t explorer_popup_request;
    context_menu_open_request_t workspace_search_popup_request;
    context_menu_open_request_t programming_result_popup_request;
    context_menu_open_request_t recent_popup_request;
    context_menu_open_request_t output_popup_request;
    context_menu_open_request_t view_surface_popup_request;
    context_menu_open_request_t retained_entity_popup_request;
    std::uint64_t generation = 1;
    std::uint64_t invocation = 1;
    std::vector<ImGuiKeyChord> consumed_strokes_this_frame;
    std::map<stable_action_binding_id_t, shortcut_binding_t> default_shortcuts;
    bool initialized = false;
    bool editor_focused = false;
    bool editor_text_input = false;
	bool previous_editor_focused = false;
	bool previous_editor_text_input = false;
	bool editor_focus_observed_this_frame = false;
    bool editor_review_mode = false;
    code_editor_widget::review_hunk_identity_t editor_hunk_target;
    bool editor_hunk_target_explicit = false;
    bool shortcut_capture_active = false;
    std::string retained_entity_executed_owner;
    std::string retained_entity_executed_id;
    std::string retained_entity_executed_action;
    pending_action_confirmation_t pending_confirmation;
};

runtime_t& runtime() {
    static runtime_t value;
    return value;
}

stable_action_id_t action_id(const char* value) {
    return stable_action_id_t(value ? value : "");
}

stable_context_type_id_t context_type(const char* value) {
    return stable_context_type_id_t(value ? value : "");
}

capability_state_t editor_active() {
    return code_editor_widget::document_state().active
        ? capability_state_t::available()
        : capability_state_t::unavailable("Open or create a text document first");
}

capability_state_t editor_selection() {
    if (!code_editor_widget::document_state().active)
        return capability_state_t::unavailable("Open or create a text document first");
    return code_editor_widget::has_selection()
        ? capability_state_t::available()
        : capability_state_t::unavailable("Select text first");
}

capability_state_t editor_savable() {
    const auto editor = code_editor_widget::document_state();
    if (!editor.active) {
        return capability_state_t::unavailable("Open or create a text document first");
    }
	const auto gate = file_tabs::verify_tab_save_gate(file_tabs::active_tab, true);
	return gate.succeeded ? capability_state_t::available()
		: capability_state_t::unavailable(gate.detail);
}

enum class focused_edit_operation_t : std::uint8_t {
	undo,
	redo,
	cut,
	copy,
	paste,
	delete_selection,
	select_all,
	find,
	replace,
	go_to
};

bool focused_code_editor(const interaction_context_t& context) {
	return context.active_view == stable_view_id_t("document.code") ||
		runtime().editor_focused;
}

bool effective_editor_focus() {
	const auto& rt = runtime();
	return rt.editor_focus_observed_this_frame
		? rt.editor_focused : rt.previous_editor_focused;
}

bool effective_editor_text_input() {
	const auto& rt = runtime();
	return rt.editor_focus_observed_this_frame
		? rt.editor_text_input : rt.previous_editor_text_input;
}

std::string focused_provider_action(focused_edit_operation_t operation,
	const interaction_context_t& context) {
	const std::string& view = context.active_view.value();
	if (view == "view.terminal") {
		if (operation == focused_edit_operation_t::paste) return "terminal.paste";
		if (operation == focused_edit_operation_t::find) return "terminal.search";
		return {};
	}
	const auto* descriptor = application_views::registry().find_descriptor(
		context.active_view);
	if (descriptor && descriptor->category == view_category_t::output) {
		if (operation == focused_edit_operation_t::copy) return "output.copy_all";
		if (operation == focused_edit_operation_t::select_all) return "output.select_all";
		if (operation == focused_edit_operation_t::find) return "output.filter";
		return {};
	}
	if (descriptor && (descriptor->category == view_category_t::analysis ||
		descriptor->category == view_category_t::document)) {
		if (operation == focused_edit_operation_t::undo) return "analysis.overlay.undo";
		if (operation == focused_edit_operation_t::redo) return "analysis.overlay.redo";
		if (operation == focused_edit_operation_t::go_to) return "analysis.navigate.goto";
	}
	return {};
}

capability_state_t focused_edit_capability(focused_edit_operation_t operation,
	const interaction_context_t& context) {
	const bool exact_editor_canvas_focus = effective_editor_focus() &&
		!effective_editor_text_input() &&
		context.active_view == stable_view_id_t("document.code");
	if ((effective_editor_text_input() ||
		(ImGui::GetCurrentContext() && ImGui::GetIO().WantTextInput)) &&
		!exact_editor_canvas_focus)
		return capability_state_t::unavailable(
			"The focused text input owns this edit command");
	if (focused_code_editor(context)) {
		switch (operation) {
			case focused_edit_operation_t::undo:
				return code_editor_widget::can_undo() ? capability_state_t::available()
					: capability_state_t::unavailable("Nothing to undo in the focused code editor");
			case focused_edit_operation_t::redo:
				return code_editor_widget::can_redo() ? capability_state_t::available()
					: capability_state_t::unavailable("Nothing to redo in the focused code editor");
			case focused_edit_operation_t::cut:
			case focused_edit_operation_t::copy:
				return editor_selection();
			case focused_edit_operation_t::paste:
				return code_editor_widget::can_paste() ? capability_state_t::available()
					: capability_state_t::unavailable("The clipboard does not contain text");
			default:
				return editor_active();
		}
	}
	const std::string provider_action = focused_provider_action(operation, context);
	if (provider_action.empty())
		return capability_state_t::unavailable(
			"The focused view does not provide this edit command");
	return runtime().actions.evaluate(action_id(provider_action.c_str()), context).capability;
}

action_handler_result_t execute_focused_edit(focused_edit_operation_t operation,
	const action_invocation_t& invocation) {
	const bool exact_editor_canvas_focus = effective_editor_focus() &&
		!effective_editor_text_input() &&
		invocation.context.active_view == stable_view_id_t("document.code");
	if ((effective_editor_text_input() ||
		(ImGui::GetCurrentContext() && ImGui::GetIO().WantTextInput)) &&
		!exact_editor_canvas_focus)
		return action_handler_result_t::failed(
			"The focused text input owns this edit command");
	if (focused_code_editor(invocation.context)) {
		switch (operation) {
			case focused_edit_operation_t::undo: code_editor_widget::trigger_undo(); break;
			case focused_edit_operation_t::redo: code_editor_widget::trigger_redo(); break;
			case focused_edit_operation_t::cut: code_editor_widget::trigger_cut(); break;
			case focused_edit_operation_t::copy: code_editor_widget::trigger_copy(); break;
			case focused_edit_operation_t::paste: code_editor_widget::trigger_paste(); break;
			case focused_edit_operation_t::delete_selection: code_editor_widget::trigger_delete(); break;
			case focused_edit_operation_t::select_all: code_editor_widget::trigger_select_all(); break;
			case focused_edit_operation_t::find: code_editor_widget::open_find(); break;
			case focused_edit_operation_t::replace: code_editor_widget::open_replace(); break;
			case focused_edit_operation_t::go_to: code_editor_widget::open_goto_line(); break;
		}
		return action_handler_result_t::completed();
	}
	const std::string provider_action = focused_provider_action(operation,
		invocation.context);
	if (provider_action.empty())
		return action_handler_result_t::failed(
			"The focused view does not provide this edit command");
	action_invocation_t routed{invocation.context};
	routed.source = invocation.source;
	routed.invocation_id = invocation.invocation_id;
	routed.review_completed = invocation.review_completed;
	routed.confirmation_granted = invocation.confirmation_granted;
	const auto result = runtime().actions.execute(
		action_id(provider_action.c_str()), routed);
	return result.executed() ? action_handler_result_t::completed()
		: action_handler_result_t::failed(result.message.empty()
			? "The focused provider rejected the edit command" : result.message);
}

capability_state_t language_capability(
    aida::editor::language_service::capability_kind_t kind,
    bool requires_identifier = false) {
    const auto document = aida::editor::language_service::active_document_context();
    if (document.document_id == 0 &&
        kind != aida::editor::language_service::capability_kind_t::workspace_symbols)
        return capability_state_t::unavailable("Open or create a text document first");
    if (requires_identifier &&
        aida::editor::language_service::active_query_text().empty())
        return capability_state_t::unavailable(
            "Select or place the caret on an identifier first");
    auto provider_document = document;
    if (kind == aida::editor::language_service::capability_kind_t::workspace_symbols)
        provider_document.file_path.clear();
    const auto available = aida::editor::language_service::capability(kind,
        provider_document);
    return available.available ? capability_state_t::available()
        : capability_state_t::unavailable(available.reason);
}

action_handler_result_t request_language_query(
    aida::editor::language_service::capability_kind_t kind,
    bool use_identifier, const char* result_view) {
    aida::editor::language_service::query_t query;
    query.kind = kind;
    query.document = aida::editor::language_service::active_document_context();
    if (kind == aida::editor::language_service::capability_kind_t::workspace_symbols)
        query.document.file_path.clear();
    query.text = use_identifier
        ? aida::editor::language_service::active_query_text() : std::string{};
    if (kind == aida::editor::language_service::capability_kind_t::range_formatting) {
        query.has_selection = code_editor_widget::selected_range(
            query.selection.start.line, query.selection.start.column,
            query.selection.end.line, query.selection.end.column);
        if (!query.has_selection)
            return action_handler_result_t::failed("Select a source range to format");
    }
    query.maximum_results = 4096;
    const auto requested = aida::editor::language_service::request(std::move(query));
    if (!requested.accepted)
        return action_handler_result_t::failed(requested.reason);
    if (result_view && result_view[0]) {
        const auto opened = application_views::open_or_focus(stable_view_id_t(result_view));
        if (!opened.ok())
            return action_handler_result_t::failed(opened.detail);
    }
    return action_handler_result_t::completed();
}

bool same_programming_location(
    const aida::editor::language_service::location_t& left,
    const aida::editor::language_service::location_t& right) {
    return left.root_path == right.root_path && left.file_path == right.file_path &&
        left.line == right.line &&
        left.column == right.column && left.match_length == right.match_length;
}

capability_state_t programming_result_capability(
    const programming_result_context_t& retained) {
    const auto snapshot = aida::editor::language_service::result(retained.kind);
    if (!snapshot || snapshot->request_id != retained.request_id ||
        snapshot->request_generation != retained.request_generation ||
        snapshot->provider_generation != retained.provider_generation ||
        snapshot->index_generation != retained.index_generation)
        return capability_state_t::unavailable(
            "The provider result was replaced, cancelled, or invalidated by a newer index generation");
    for (const auto& location : snapshot->locations)
        if (same_programming_location(location, retained.location))
            return capability_state_t::available();
    for (const auto& symbol : snapshot->symbols)
        if (same_programming_location(symbol.location, retained.location))
            return capability_state_t::available();
    for (const auto& diagnostic : snapshot->diagnostics)
        if (same_programming_location(diagnostic.location, retained.location))
            return capability_state_t::available();
    for (const auto& edit : snapshot->proposed_edits) {
        aida::editor::language_service::location_t location;
        location.root_path = snapshot->root_path;
        location.file_path = edit.file_path;
        location.line = edit.range.start.line;
        location.column = edit.range.start.column;
        location.match_length = (std::max)(0,
            edit.range.end.column - edit.range.start.column);
        location.preview = edit.expected_text;
        if (same_programming_location(location, retained.location))
            return capability_state_t::available();
    }
    return capability_state_t::unavailable(
        "The provider result was replaced, cancelled, or invalidated by a newer index generation");
}

void register_action(runtime_t& rt,
                     const char* id,
                     const char* label,
                     const char* description,
                     action_surface_t surfaces,
                     action_handler_fn_t invoke,
                     action_capability_fn_t capability = {},
                     bool undoable = false,
                     action_check_fn_t checked = {},
                     const char* category_id = "category.application",
                     const char* category_label = "Application") {
    application_action_descriptor_t descriptor;
    descriptor.id = action_id(id);
    descriptor.label = label;
    descriptor.description = description;
    descriptor.category = {category_id, category_label};
    descriptor.surfaces = surfaces;
    descriptor.invoke = std::move(invoke);
    descriptor.capability = std::move(capability);
    descriptor.checked = std::move(checked);
    descriptor.undoable = undoable;
    const auto registered = rt.actions.register_action(std::move(descriptor));
    if (!registered.ok())
        throw std::logic_error(std::string("Action registration failed for '") +
            id + "': " + registered.detail);
}

void register_action_with_consequence(runtime_t& rt,
                     const char* id,
                     const char* label,
                     const char* description,
                     action_surface_t surfaces,
                     action_handler_fn_t invoke,
                     action_capability_fn_t capability,
                     action_check_fn_t checked,
                     action_effect_t effects,
                     confirmation_requirement_t confirmation,
                     const char* consequence_summary,
                     std::function<std::string(const interaction_context_t&)> target_summary,
                     action_confirmation_prepare_fn_t prepare_confirmation = {},
                     action_confirmation_cancel_fn_t cancel_confirmation = {}) {
    application_action_descriptor_t descriptor;
    descriptor.id = action_id(id);
    descriptor.label = label;
    descriptor.description = description;
    descriptor.category = {"category.network", "Network"};
    descriptor.surfaces = surfaces;
    descriptor.invoke = std::move(invoke);
    descriptor.capability = std::move(capability);
    descriptor.checked = std::move(checked);
    descriptor.consequence.effects = effects;
    descriptor.consequence.confirmation = confirmation;
    descriptor.consequence.summary = consequence_summary ? consequence_summary : "";
    descriptor.consequence.target_summary = std::move(target_summary);
    descriptor.prepare_confirmation = std::move(prepare_confirmation);
    descriptor.cancel_confirmation = std::move(cancel_confirmation);
    const auto registered = rt.actions.register_action(std::move(descriptor));
    if (!registered.ok())
        throw std::logic_error(std::string("Action registration failed for '") +
            id + "': " + registered.detail);
}

const retained_entity_action_t* retained_entity_action(
    const interaction_context_t& context, const std::string& id) {
    const auto* retained = context.payload.get<retained_entity_runtime_context_t>();
    if (!retained)
        return nullptr;
    const auto& retained_context = retained->context();
    const auto found = std::find_if(retained_context.actions.begin(),
        retained_context.actions.end(), [&](const retained_entity_action_t& item) {
            return item.action_id == id;
        });
    return found == retained_context.actions.end() ? nullptr : &*found;
}

capability_state_t retained_entity_action_capability(
    const interaction_context_t& context, const std::string& id) {
    const auto* retained = context.payload.get<retained_entity_runtime_context_t>();
    if (!retained)
        return capability_state_t::unavailable(
            "The retained entity context is unavailable", false);
    const auto* action = retained_entity_action(context, id);
    if (!action) {
        const bool analysis_context = retained->context().owner_id == "analysis.context";
        return capability_state_t::unavailable(
            analysis_context
                ? "This analysis provider does not support this action"
                : "This action does not apply to the retained entity",
            analysis_context);
    }
    if (!action->invoke)
        return capability_state_t::unavailable(
            "This action has no active provider");
    if (retained->context().validate_identity) {
        const auto valid = retained->context().validate_identity();
        if (!valid.enabled)
            return valid;
    }
    if (!action->capability.enabled && action->capability.disabled_reason.empty())
        return capability_state_t::unavailable(
            "This action is unavailable for the retained entity");
    return action->capability;
}

action_check_state_t retained_entity_action_check_state(
    const interaction_context_t& context, const std::string& id) {
    const auto* action = retained_entity_action(context, id);
    return action ? action->check_state : action_check_state_t::not_checkable;
}

action_handler_result_t invoke_retained_entity_action(
    const action_invocation_t& invocation, const std::string& id);

bool is_retained_entity_context(const interaction_context_t& context) {
    return context.payload.type_id() == context_type(k_retained_entity_context_type) &&
        context.payload.get<retained_entity_runtime_context_t>() != nullptr;
}

action_handler_fn_t retained_or_handler(const char* id,
                                        action_handler_fn_t fallback) {
    const std::string retained_id = id;
    return [retained_id, fallback = std::move(fallback)](
               const action_invocation_t& invocation) {
        return is_retained_entity_context(invocation.context)
            ? invoke_retained_entity_action(invocation, retained_id)
            : fallback(invocation);
    };
}

action_capability_fn_t retained_or_capability(const char* id,
                                              action_capability_fn_t fallback) {
    const std::string retained_id = id;
    return [retained_id, fallback = std::move(fallback)](
               const interaction_context_t& context) {
        return is_retained_entity_context(context)
            ? retained_entity_action_capability(context, retained_id)
            : fallback(context);
    };
}

action_check_fn_t retained_check_state(const char* id) {
    const std::string retained_id = id;
    return [retained_id](const interaction_context_t& context) {
        return is_retained_entity_context(context)
            ? retained_entity_action_check_state(context, retained_id)
            : action_check_state_t::not_checkable;
    };
}

action_handler_result_t invoke_retained_entity_action(
    const action_invocation_t& invocation, const std::string& id) {
    const auto available = retained_entity_action_capability(invocation.context, id);
    if (!available.enabled)
        return action_handler_result_t::failed(available.disabled_reason);
    const auto* action = retained_entity_action(invocation.context, id);
    if (!action || !action->invoke)
        return action_handler_result_t::failed(
            "The retained entity did not provide this operation");
    auto result = action->invoke();
    if (result.success) {
        auto& rt = runtime();
        const auto* retained = invocation.context.payload.get<
            retained_entity_runtime_context_t>();
        if (retained) {
            rt.retained_entity_executed_owner = retained->context().owner_id;
            rt.retained_entity_executed_id = retained->context().entity_id;
            rt.retained_entity_executed_action = id;
        }
    }
    return result;
}

const char* view_category_id(view_category_t category) noexcept {
    switch (category) {
        case view_category_t::shell: return "category.view.shell";
        case view_category_t::explorer: return "category.view.explorer";
        case view_category_t::document: return "category.view.document";
        case view_category_t::analysis: return "category.view.analysis";
        case view_category_t::debugger: return "category.view.debugger";
        case view_category_t::memory: return "category.view.memory";
        case view_category_t::types: return "category.view.types";
        case view_category_t::network: return "category.view.network";
        case view_category_t::automation: return "category.view.automation";
        case view_category_t::programming: return "category.view.programming";
        case view_category_t::output: return "category.view.output";
        case view_category_t::settings: return "category.view.settings";
    }
    return "category.view";
}

std::string compose_view_action_id(const stable_view_id_t& view) {
    return std::string("view.manage.") + view.value();
}

action_handler_result_t workspace_result(workspace_layout::workspace_request_result_t result,
                                         const char* failure) {
    using result_t = workspace_layout::workspace_request_result_t;
    if (result == result_t::completed || result == result_t::queued ||
        result == result_t::unchanged)
        return action_handler_result_t::completed();
    if (result == result_t::busy)
        return action_handler_result_t::failed("Another workspace layout transaction is already in progress");
    if (result == result_t::invalid_name)
        return action_handler_result_t::failed("Workspace names must be 1-64 ASCII letters, numbers, spaces, hyphens or underscores, without leading, trailing or repeated spaces");
    if (result == result_t::already_exists)
        return action_handler_result_t::failed("A saved workspace with this exact name already exists");
    if (result == result_t::not_found)
        return action_handler_result_t::failed("The selected saved workspace no longer exists");
    if (result == result_t::unavailable)
        return action_handler_result_t::failed("The workspace operation is unavailable until the DockSpace is ready");
    return action_handler_result_t::failed(failure);
}

const view_surface_context_t* view_surface(const interaction_context_t& context) {
    return context.payload.get<view_surface_context_t>();
}

capability_state_t live_surface_capability(const interaction_context_t& context) {
    const auto* surface = view_surface(context);
    if (!surface)
        return capability_state_t::unavailable("Open this action from a dock tab or panel title");
    const auto* descriptor = application_views::registry().find_descriptor(surface->instance.view);
    if (!descriptor || !application_views::registry().is_open(surface->instance))
        return capability_state_t::unavailable("The target view is no longer open");
    return capability_state_t::available();
}

capability_state_t surface_close_capability(const interaction_context_t& context) {
    const auto live = live_surface_capability(context);
    if (!live.enabled)
        return live;
    const auto* surface = view_surface(context);
    const auto* descriptor = application_views::registry().find_descriptor(surface->instance.view);
    if (!descriptor->closeable)
        return capability_state_t::unavailable("This required shell surface cannot be closed");
    if (application_views::is_pinned(surface->instance))
        return capability_state_t::unavailable("Unpin this view before closing it");
    return capability_state_t::available();
}

capability_state_t surface_close_others_capability(const interaction_context_t& context) {
    const auto live = live_surface_capability(context);
    if (!live.enabled)
        return live;
    const auto* surface = view_surface(context);
    bool available = false;
    application_views::registry().for_each_instance([&](const view_descriptor_t& descriptor,
            const view_instance_state_t& instance) {
        if (!(instance.id == surface->instance) && instance.open && descriptor.closeable &&
            !application_views::is_pinned(instance.id))
            available = true;
    }, true);
    return available ? capability_state_t::available() :
        capability_state_t::unavailable("No other closeable unpinned view is open");
}

capability_state_t surface_placement_capability(const interaction_context_t& context,
    std::optional<workspace_layout::dock_role_t> target) {
    const auto live = live_surface_capability(context);
    if (!live.enabled)
        return live;
    if (workspace_layout::operation_pending()) {
        const std::string status = workspace_layout::operation_status();
        return capability_state_t::unavailable(status.empty()
            ? "A workspace layout transaction is already in progress" : status);
    }
    if (workspace_layout::layout_locked())
        return capability_state_t::unavailable("Unlock the workspace layout before moving views");
    const auto* surface = view_surface(context);
    const auto placement = workspace_layout::inspect_window_placement(surface->window_name);
    if (!placement.realized)
        return capability_state_t::unavailable("The target window has not been realized yet");
    if (!target)
        return placement.docked ? capability_state_t::available() :
            capability_state_t::unavailable("This view is already floating");
    const ImGuiID target_node = workspace_layout::node_id(*target);
    if (target_node == 0)
        return capability_state_t::unavailable("The requested dock region is unavailable in this layout");
    if (placement.dock_node == target_node)
        return capability_state_t::unavailable("This view is already in that dock region");
    return capability_state_t::available();
}

action_handler_result_t surface_operation(const view_operation_result_t& result) {
    return result.ok() ? action_handler_result_t::completed(result.detail) :
        action_handler_result_t::failed(result.detail);
}

bool valid_edit_stroke(ImGuiKeyChord stroke) noexcept {
    const ImGuiKey key = static_cast<ImGuiKey>(stroke & ~ImGuiMod_Mask_);
    return key >= ImGuiKey_Tab && key < ImGuiKey_GamepadStart &&
           key != ImGuiKey_LeftCtrl && key != ImGuiKey_RightCtrl &&
           key != ImGuiKey_LeftShift && key != ImGuiKey_RightShift &&
           key != ImGuiKey_LeftAlt && key != ImGuiKey_RightAlt &&
           key != ImGuiKey_LeftSuper && key != ImGuiKey_RightSuper;
}

std::string format_strokes(const std::vector<ImGuiKeyChord>& strokes) {
    if (strokes.empty() || strokes.size() > 4)
        return {};
    std::string result;
    for (std::size_t index = 0; index < strokes.size(); ++index) {
        const ImGuiKeyChord stroke = strokes[index];
        if (!valid_edit_stroke(stroke))
            return {};
        const ImGuiKey key = static_cast<ImGuiKey>(stroke & ~ImGuiMod_Mask_);
        const char* key_name = ImGui::GetKeyName(key);
        if (!key_name || !*key_name)
            return {};
        if (index != 0)
            result.append(", ");
        if ((stroke & ImGuiMod_Ctrl) != 0) result.append("Ctrl+");
        if ((stroke & ImGuiMod_Shift) != 0) result.append("Shift+");
        if ((stroke & ImGuiMod_Alt) != 0) result.append("Alt+");
        if ((stroke & ImGuiMod_Super) != 0) result.append("Super+");
        result.append(key_name);
    }
    return result;
}

void capture_default_shortcuts(runtime_t& rt) {
    rt.default_shortcuts.clear();
    rt.shortcuts.for_each([&](const shortcut_binding_t& binding) {
        rt.default_shortcuts.emplace(binding.id, binding);
    });
}

void apply_persisted_shortcut_overrides(runtime_t& rt) {
    const std::string& payload = g_sa_settings.keybinding_overrides_json;
    if (payload.empty() || payload.size() > k_maximum_keybinding_payload_bytes)
        return;
    try {
        const nlohmann::json root = nlohmann::json::parse(payload);
        if (!root.is_object() || !root.contains("version") ||
            !root["version"].is_number_unsigned() || root["version"].get<unsigned>() != 1 ||
            !root.contains("bindings") || !root["bindings"].is_object() ||
            root["bindings"].size() > k_maximum_keybinding_overrides)
            return;
        for (auto iterator = root["bindings"].begin();
             iterator != root["bindings"].end(); ++iterator) {
            const stable_action_binding_id_t id(iterator.key());
            const auto found = rt.default_shortcuts.find(id);
            if (found == rt.default_shortcuts.end() || !iterator.value().is_object())
                continue;
            const auto& value = iterator.value();
            if (!value.contains("enabled") || !value["enabled"].is_boolean() ||
                !value.contains("strokes") || !value["strokes"].is_array() ||
                value["strokes"].empty() || value["strokes"].size() > 4 ||
                !value.contains("action") || !value["action"].is_string() ||
                value["action"].get<std::string>() != found->second.action.value() ||
                !value.contains("scope") || !value["scope"].is_string() ||
                value["scope"].get<std::string>() != found->second.scope.value() ||
                !value.contains("scope_kind") || !value["scope_kind"].is_number_unsigned() ||
                value["scope_kind"].get<unsigned>() !=
                    static_cast<unsigned>(found->second.scope_kind))
                continue;
            std::vector<ImGuiKeyChord> strokes;
            strokes.reserve(value["strokes"].size());
            bool valid = true;
            for (const auto& encoded : value["strokes"]) {
                if (!encoded.is_number_unsigned() ||
                    encoded.get<std::uint64_t>() >
                        static_cast<std::uint64_t>((std::numeric_limits<int>::max)())) {
                    valid = false;
                    break;
                }
                const auto stroke = static_cast<ImGuiKeyChord>(encoded.get<unsigned>());
                if (!valid_edit_stroke(stroke)) {
                    valid = false;
                    break;
                }
                strokes.push_back(stroke);
            }
            const std::string display = valid ? format_strokes(strokes) : std::string{};
            if (display.empty())
                continue;
            shortcut_binding_t binding = found->second;
            binding.sequence = {std::move(strokes), display};
            binding.enabled = value["enabled"].get<bool>();
            binding.source = shortcut_binding_source_t::user_override;
            static_cast<void>(rt.shortcuts.replace_binding(std::move(binding), rt.actions));
        }
    } catch (...) {
    }
}

std::optional<std::string> serialize_shortcut_overrides(const runtime_t& rt) {
    nlohmann::json bindings = nlohmann::json::object();
    rt.shortcuts.for_each([&](const shortcut_binding_t& binding) {
        const auto found = rt.default_shortcuts.find(binding.id);
        if (found == rt.default_shortcuts.end() ||
            (binding.enabled == found->second.enabled &&
             binding.sequence.strokes == found->second.sequence.strokes))
            return;
        nlohmann::json strokes = nlohmann::json::array();
        for (const ImGuiKeyChord stroke : binding.sequence.strokes)
            strokes.push_back(static_cast<unsigned>(stroke));
        bindings[binding.id.value()] = {
            {"action", binding.action.value()},
            {"scope", binding.scope.value()},
            {"scope_kind", static_cast<unsigned>(binding.scope_kind)},
            {"enabled", binding.enabled},
            {"strokes", std::move(strokes)}};
    });
    if (bindings.size() > k_maximum_keybinding_overrides)
        return std::nullopt;
    nlohmann::json root = {{"version", 1}, {"bindings", std::move(bindings)}};
    std::string payload = root.dump();
    if (payload.size() > k_maximum_keybinding_payload_bytes)
        return std::nullopt;
    return payload;
}

bool persist_shortcut_overrides(runtime_t& rt, const shortcut_resolver_t& rollback,
    const std::string& previous_payload) {
    const auto payload = serialize_shortcut_overrides(rt);
    if (!payload) {
        rt.shortcuts = rollback;
        return false;
    }
    g_sa_settings.keybinding_overrides_json = *payload;
    const auto saved = aida::settings_persistence::request_save(g_sa_settings);
    if (!aida::settings_persistence::accepted(saved)) {
        g_sa_settings.keybinding_overrides_json = previous_payload;
        rt.shortcuts = rollback;
        return false;
    }
    return true;
}

void register_binding(runtime_t& rt, shortcut_binding_t binding) {
    const std::string id = binding.id.value();
    const auto registered = rt.shortcuts.register_binding(
        std::move(binding), rt.actions);
    if (!registered.ok())
        throw std::logic_error(std::string("Shortcut registration failed for '") +
            id + "': " + registered.detail);
}

void register_shortcut(runtime_t& rt,
                       const char* binding_id,
                       const char* action,
                       ImGuiKeyChord chord,
                       const char* display,
                       bool repeat = false) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope = stable_scope_id_t(k_editor_scope);
    binding.scope_kind = focus_scope_kind_t::text_editor;
    binding.text_input_policy = shortcut_text_input_policy_t::allow;
    binding.allow_repeat = repeat;
    register_binding(rt, std::move(binding));
}

void register_review_shortcut(runtime_t& rt,
                              const char* binding_id,
                              const char* action,
                              ImGuiKeyChord chord,
                              const char* display) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope = stable_scope_id_t(k_editor_review_scope);
    binding.scope_kind = focus_scope_kind_t::text_editor;
    binding.text_input_policy = shortcut_text_input_policy_t::allow;
    register_binding(rt, std::move(binding));
}

void register_global_shortcut(runtime_t& rt,
                              const char* binding_id,
                              const char* action,
                              ImGuiKeyChord chord,
                              const char* display) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope_kind = focus_scope_kind_t::global;
    binding.text_input_policy = shortcut_text_input_policy_t::suppress;
    register_binding(rt, std::move(binding));
}

void register_global_chord(runtime_t& rt,
                           const char* binding_id,
                           const char* action,
                           ImGuiKeyChord first,
                           ImGuiKeyChord second,
                           const char* display) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{first, second}, display};
    binding.scope_kind = focus_scope_kind_t::global;
    binding.text_input_policy = shortcut_text_input_policy_t::suppress;
    register_binding(rt, std::move(binding));
}

void register_domain_shortcut(runtime_t& rt,
                              const char* binding_id,
                              const char* action,
                              ImGuiKeyChord chord,
                              const char* display,
                              const char* scope,
                              int priority = 0) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope = stable_scope_id_t(scope);
    binding.scope_kind = focus_scope_kind_t::domain;
    binding.text_input_policy = shortcut_text_input_policy_t::suppress;
    binding.priority = priority;
    register_binding(rt, std::move(binding));
}

void register_document_shortcut(runtime_t& rt,
                                const char* binding_id,
                                const char* action,
                                ImGuiKeyChord chord,
                                const char* display,
                                const char* scope,
                                int priority = 0) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope = stable_scope_id_t(scope);
    binding.scope_kind = focus_scope_kind_t::document;
    binding.text_input_policy = shortcut_text_input_policy_t::suppress;
    binding.priority = priority;
    register_binding(rt, std::move(binding));
}

void register_widget_shortcut(runtime_t& rt,
                              const char* binding_id,
                              const char* action,
                              ImGuiKeyChord chord,
                              const char* display,
                              const char* scope,
                              int priority = 0) {
    shortcut_binding_t binding;
    binding.id = stable_action_binding_id_t(binding_id);
    binding.action = action_id(action);
    binding.sequence = {{chord}, display};
    binding.scope = stable_scope_id_t(scope);
    binding.scope_kind = focus_scope_kind_t::widget;
    binding.text_input_policy = shortcut_text_input_policy_t::suppress;
    binding.priority = priority;
    register_binding(rt, std::move(binding));
}

void register_menu(runtime_t& rt,
                   const char* id,
                   const char* accepted_context,
                   std::vector<context_menu_section_t> sections) {
    context_menu_descriptor_t descriptor;
    descriptor.id = stable_menu_id_t(id);
    descriptor.accepted_contexts.push_back(context_type(accepted_context));
    descriptor.sections = std::move(sections);
    const auto registered = rt.menus.register_menu(std::move(descriptor), rt.actions);
    if (!registered.ok())
        throw std::logic_error(std::string("Context-menu registration failed for '") +
            id + "': " + registered.detail);
}

context_menu_action_t menu_action(const char* id, int order) {
    context_menu_action_t result;
    result.action = action_id(id);
    result.order = order;
    return result;
}

context_menu_action_t retained_menu_action(const char* id, int order) {
    auto result = menu_action(id, order);
	const std::string_view action(id);
	if (action == "debugger.entity.copy_address" || action == "memory.entity.copy_address" ||
		action == "hex.copy_byte")
		result.shortcut_override = "Ctrl+C";
	else if (action == "debugger.instruction.toggle_breakpoint")
		result.shortcut_action = action_id("debugger.toggle_breakpoint_at_rip");
	else if (action == "debugger.breakpoint.delete" || action == "debugger.source.remove" ||
		action == "memory.address.remove")
		result.shortcut_override = "Delete";
	else if (action == "debugger.source.open" || action == "memory.result.add_address" ||
		action == "memory.address.change_value")
		result.shortcut_override = "Enter";
    return result;
}

context_menu_action_t analysis_context_menu_action(
    const char* id, int order, const char* shortcut = nullptr,
    const char* label = nullptr, const char* description = nullptr,
    const char* shortcut_action = nullptr) {
    auto result = retained_menu_action(id, order);
    if (shortcut)
        result.shortcut_override = shortcut;
    if (label)
        result.label_override = label;
    if (description)
        result.description_override = description;
    if (shortcut_action)
        result.shortcut_action = action_id(shortcut_action);
    return result;
}

context_menu_section_t menu_section(const char* id,
                                    context_menu_group_t group,
                                    int order,
                                    std::vector<context_menu_action_t> actions) {
    context_menu_section_t result;
    result.id = stable_menu_section_id_t(id);
    result.group = group;
    result.order = order;
    result.actions = std::move(actions);
    return result;
}

context_menu_section_t analysis_context_menu_section(
    const char* id, const char* label, context_menu_group_t group, int order,
    std::vector<context_menu_action_t> actions) {
    auto result = menu_section(id, group, order, std::move(actions));
    result.label = label;
    return result;
}

void close_tab_with_confirmation(int index) {
    if (!file_tabs::is_valid_tab_index(index))
        return;
    if (file_tabs::tabs[file_tabs::tab_index(index)].pinned)
        return;
    if (file_tabs::tabs[file_tabs::tab_index(index)].dirty) {
        file_tabs::pending_close_idx = index;
        file_tabs::show_close_confirm = true;
    } else {
        file_tabs::close_tab(index);
    }
}

bool find_open_session(const std::string& path, std::size_t& index) {
    auto key = [](const std::string& value) {
        std::string normalized = path_to_utf8(path_from_utf8(value).lexically_normal());
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return normalized;
    };
    const std::string expected = key(path);
    const std::size_t count = analysis_session::session_count();
    for (std::size_t candidate = 0; candidate < count; ++candidate) {
        const auto session = analysis_session::session_handle_at(candidate);
        if (session && key(session->path) == expected) {
            index = candidate;
            return true;
        }
    }
    return false;
}

std::optional<std::string> workspace_relative_path(const std::string& path) {
    if (path.empty())
        return std::nullopt;
    std::string candidate = path_to_utf8(path_from_utf8(path).lexically_normal());
    std::string candidate_key = candidate;
    std::transform(candidate_key.begin(), candidate_key.end(), candidate_key.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    for (const auto& root_value : file_browser::roots) {
        std::string root = path_to_utf8(path_from_utf8(root_value).lexically_normal());
        while (root.size() > 1 && root.back() == '/')
            root.pop_back();
        std::string root_key = root;
        std::transform(root_key.begin(), root_key.end(), root_key.begin(),
            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
        if (candidate_key == root_key) {
            const std::string name = path_to_utf8(path_from_utf8(candidate).filename());
            return name.empty() ? std::optional<std::string>(".") :
                std::optional<std::string>(name);
        }
        if (candidate_key.size() > root_key.size() &&
            candidate_key.compare(0, root_key.size(), root_key) == 0 &&
            candidate_key[root_key.size()] == '/')
            return candidate.substr(root.size() + 1);
    }
    return std::nullopt;
}

std::string normalized_programming_path_key(const std::string& path) {
    try {
        std::string value = path_to_utf8(path_from_utf8(path).lexically_normal());
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return value;
    } catch (...) {
        return {};
    }
}

capability_state_t live_explorer_selection(const explorer_context_t& retained,
    std::vector<explorer_views::file_operation_target_t>* targets = nullptr) {
    if (retained.targets.empty())
        return capability_state_t::unavailable("Select a file or folder first");
    if (retained.targets.size() != retained.entry_ids.size() ||
        retained.targets.size() != retained.entry_generations.size())
        return capability_state_t::unavailable("The retained Explorer selection identity is incomplete");
    if (retained.index_generation != file_browser::index_generation)
        return capability_state_t::unavailable(
            "The Project Explorer selection changed during indexing; reopen the context menu");
    if (targets) *targets = retained.targets;
    return capability_state_t::available();
}

capability_state_t single_explorer_selection(const explorer_context_t& retained) {
    const auto live = live_explorer_selection(retained);
    if (!live.enabled) return live;
    if (retained.targets.size() != 1)
        return capability_state_t::unavailable(
            "This action requires exactly one selected Project Explorer item");
    if (retained.index < 0 || static_cast<std::size_t>(retained.index) >=
            file_browser::entries.size())
        return capability_state_t::unavailable(
            "The Project Explorer row moved during indexing; reopen the context menu");
    const auto& indexed = file_browser::entries[static_cast<std::size_t>(retained.index)];
    if (normalized_programming_path_key(indexed.full_path) !=
            normalized_programming_path_key(retained.path) ||
        indexed.entry_id != retained.entry_ids.front() ||
        indexed.generation != retained.entry_generations.front())
        return capability_state_t::unavailable(
            "The Project Explorer row moved during indexing; reopen the context menu");
    return capability_state_t::available();
}

std::string bounded_context_value(std::string value) {
    for (char& character : value)
        if (character == '\r' || character == '\n' || character == '\t')
            character = ' ';
    constexpr std::size_t maximum_bytes = 3072;
    if (value.size() > maximum_bytes)
        value.resize(maximum_bytes);
    return value;
}

action_handler_result_t send_programming_path_to_ai(const std::string& path,
    const std::string& label, const char* source) {
    if (path.empty())
        return action_handler_result_t::failed("The selected programming item has no file path");
    const auto opened = application_views::open_or_focus(stable_view_id_t("view.ai_chat"));
    if (!opened.ok())
        return action_handler_result_t::failed(opened.detail);
    std::string payload = "Programming context from ";
    payload.append(source && *source ? source : "IDE").append("\nName: ")
        .append(bounded_context_value(label)).append("\nPath: ")
        .append(bounded_context_value(path));
    if (const auto relative = workspace_relative_path(path))
        payload.append("\nWorkspace-relative path: ")
            .append(bounded_context_value(*relative));
    chat_inject::post(payload);
    return action_handler_result_t::completed();
}

action_handler_result_t send_editor_selection_to_ai(const char* instruction) {
    const auto editor = code_editor_widget::document_state();
    const std::string selection = code_editor_widget::selected_text(16U * 1024U);
    if (!editor.active || selection.empty())
        return action_handler_result_t::failed("Select source text first");
    const auto opened = application_views::open_or_focus(stable_view_id_t("view.ai_chat"));
    if (!opened.ok())
        return action_handler_result_t::failed(opened.detail);
    std::string payload = instruction && *instruction ? instruction : "Review this source selection";
    payload.append("\n\nSource: ").append(bounded_context_value(editor.filepath.empty()
        ? editor.filename : editor.filepath));
    payload.append("\nCaret: ").append(std::to_string(editor.caret_line + 1))
        .append(":").append(std::to_string(editor.caret_column + 1));
    payload.append("\n\n```\n").append(selection).append("\n```");
    chat_inject::post(payload);
    return action_handler_result_t::completed();
}

std::atomic<std::uint64_t>& debugger_expression_generation() {
    static std::atomic<std::uint64_t> generation{0};
    return generation;
}

struct debugger_task_registration_gate_t {
    enum class state_t : std::uint8_t {
        pending,
        registered,
        rejected,
        timed_out
    };

    bool await_registration() {
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, std::chrono::seconds(5), [this] {
                return state != state_t::pending;
            })) {
            state = state_t::timed_out;
            return false;
        }
        return state == state_t::registered;
    }

    bool release(bool accepted) {
        std::lock_guard<std::mutex> lock(mutex);
        const bool worker_timed_out = state == state_t::timed_out;
        if (state == state_t::pending)
            state = accepted ? state_t::registered : state_t::rejected;
        ready.notify_all();
        return worker_timed_out;
    }

    std::mutex mutex;
    std::condition_variable ready;
    state_t state = state_t::pending;
};

bool expression_fence_matches(const source_debug_service::snapshot_ptr& snapshot,
        std::uint32_t pid, std::uint64_t publication_generation,
        std::uint64_t stop_generation, const std::string& target_key) {
    return snapshot && snapshot->target_pid == pid && snapshot->target_key == target_key &&
        snapshot->generation == publication_generation &&
        snapshot->stop_generation == stop_generation &&
        driver_bridge::attached_pid() == pid &&
        debugger_engine::g_state.target_pid == pid &&
        debugger_interaction::current_stop_generation() == stop_generation &&
        debugger_engine::g_state.status.load(std::memory_order_acquire) ==
            debugger_engine::dbg_status_t::paused;
}

action_handler_result_t schedule_debugger_expression_evaluation(
        std::string expression, int persistent_watch_index,
        const char* owner_action, const char* label) {
    if (expression.empty() || expression.size() > 96 ||
        expression.find('\n') != std::string::npos ||
        expression.find('\r') != std::string::npos)
        return action_handler_result_t::failed(
            "Select one single-line debugger expression no longer than 96 bytes");
    const auto retained = source_debug_service::snapshot();
    if (!retained || retained->target_pid == 0 || retained->target_key.empty())
        return action_handler_result_t::failed(
            "The source-debug target context is unavailable; wait for debugger context publication");
    if (debugger_engine::g_state.status.load(std::memory_order_acquire) !=
            debugger_engine::dbg_status_t::paused)
        return action_handler_result_t::failed(
            "Pause the debugger before evaluating a source expression");
    const std::uint64_t request_generation =
        debugger_expression_generation().fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint32_t pid = retained->target_pid;
    const std::uint64_t publication_generation = retained->generation;
    const std::uint64_t stop_generation = retained->stop_generation;
    const std::uint64_t watches_generation = persistent_watch_index >= 0
        ? debugger_engine::g_state.watches_generation.load(std::memory_order_acquire)
        : 0;
    const std::string target_key = retained->target_key;
    const std::string task_id = "source.debug.expression." +
        std::to_string(request_generation);
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    auto registration_gate =
        std::make_shared<debugger_task_registration_gate_t>();
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "source_debug";
    submission.label = persistent_watch_index >= 0
        ? "source_debug.evaluate_watch" : "source_debug.evaluate_selection";
    submission.thread_class = "target_read";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.target_pid = pid;
    submission.generation = request_generation;
    submission.cancel_hook = [cancelled] {
        cancelled->store(true, std::memory_order_release);
    };
    submission.body = [expression, persistent_watch_index, pid,
        publication_generation, stop_generation, watches_generation,
        target_key, task_id, cancelled, registration_gate]() mutable {
        if (!registration_gate->await_registration())
            return;
        debugger_engine::expression_evaluation_t evaluation;
        std::string fence_error;
        try {
            const auto before = source_debug_service::snapshot();
            if (!expression_fence_matches(before, pid, publication_generation,
                    stop_generation, target_key))
                fence_error = "Debugger target or stop generation changed before evaluation began";
            else if (cancelled->load(std::memory_order_acquire))
                fence_error = "Debugger expression evaluation was cancelled";
            else
                evaluation = debugger_engine::evaluate_expression(expression);
        } catch (const std::exception& exception) {
            evaluation.error = std::string("Debugger expression evaluation raised an exception: ") +
                exception.what();
        } catch (...) {
            evaluation.error = "Debugger expression evaluation raised an unknown exception";
        }
        const auto after = source_debug_service::snapshot();
        if (fence_error.empty() && !expression_fence_matches(after, pid,
                publication_generation, stop_generation, target_key))
            fence_error = "Debugger target or stop generation changed during evaluation; the stale result was discarded";
        if (fence_error.empty() && cancelled->load(std::memory_order_acquire))
            fence_error = "Debugger expression evaluation was cancelled; the result was discarded";
        if (fence_error.empty() && !evaluation.succeeded && evaluation.error.empty())
            evaluation.error = "The debugger expression evaluator returned no result";
        bool posted = false;
        std::string dispatch_error =
            "The debugger expression result could not return to the UI owner";
        try {
            posted = aida::ui_thread::post(
            [expression, persistent_watch_index, pid,
             publication_generation, stop_generation, watches_generation,
             target_key,
             task_id, evaluation = std::move(evaluation),
             fence_error = std::move(fence_error)]() mutable {
                const auto current = source_debug_service::snapshot();
                if (fence_error.empty() && !expression_fence_matches(current, pid,
                        publication_generation, stop_generation, target_key))
                    fence_error = "Debugger target or stop generation changed before result publication; the stale result was discarded";
                if (!fence_error.empty()) {
                    bool watch_updated = true;
                    if (persistent_watch_index >= 0) {
                        debugger_engine::expression_evaluation_t failure;
                        failure.error = fence_error;
                        watch_updated = debugger_engine::publish_watch_evaluation(
                            persistent_watch_index, expression, watches_generation,
                            failure);
                    }
                    static_cast<void>(task_center::update_task(task_id,
                        watch_updated ? task_center::task_state_t::cancelled
                                      : task_center::task_state_t::partial,
                        1.0f, watch_updated
                            ? "Result discarded by debugger generation fence"
                            : "Watch changed while the result was discarded",
                        watch_updated ? fence_error
                            : "No stale result or error was applied to another watch"));
                    return;
                }
                if (persistent_watch_index >= 0 &&
                    !debugger_engine::publish_watch_evaluation(
                        persistent_watch_index, expression, watches_generation,
                        evaluation)) {
                    static_cast<void>(task_center::update_task(task_id,
                        task_center::task_state_t::partial, 1.0f,
                        "Watch changed before result publication",
                        "The persistent watch remains authoritative; no stale result was applied"));
                    return;
                }
                const std::string result = evaluation.succeeded
                    ? expression + " = " + evaluation.rendered_value
                    : expression + ": " + evaluation.error;
                const std::string diagnostic_id = evaluation.succeeded ? std::string{}
                    : "diagnostic.source_debug.expression." + task_id;
                static_cast<void>(task_center::update_task(task_id,
                    evaluation.succeeded ? task_center::task_state_t::completed
                                         : task_center::task_state_t::failed,
                    1.0f, result, result, diagnostic_id));
                if (!evaluation.succeeded) {
                    task_center::diagnostic_registration_t diagnostic;
                    diagnostic.id = diagnostic_id;
                    diagnostic.task_id = task_id;
                    diagnostic.owner = "Source Debugger";
                    diagnostic.target = expression;
                    diagnostic.summary = "Debugger expression evaluation failed";
                    diagnostic.details = evaluation.error;
                    diagnostic.severity = task_center::diagnostic_severity_t::error;
                    diagnostic.callbacks.focus = [] {
                        static_cast<void>(application_views::open_or_focus(
                            stable_view_id_t("view.programming.source_debug_console")));
                    };
                    static_cast<void>(task_center::raise_diagnostic(
                        std::move(diagnostic)));
                }
            }, "source_debug", "expression_evaluation_result", "worker_result");
        } catch (const std::exception& exception) {
            dispatch_error = std::string("Result publication raised an exception: ") +
                exception.what();
        } catch (...) {
            dispatch_error = "Result publication raised an unknown exception";
        }
        if (!posted) {
            if (persistent_watch_index >= 0) {
                debugger_engine::expression_evaluation_t failure;
                failure.error = dispatch_error;
                static_cast<void>(debugger_engine::publish_watch_evaluation(
                    persistent_watch_index, expression, watches_generation,
                    failure));
            }
            static_cast<void>(task_center::update_task(task_id,
                task_center::task_state_t::failed, 1.0f,
                "Result publication failed", dispatch_error));
            task_center::diagnostic_registration_t diagnostic;
            diagnostic.id = "diagnostic.source_debug.expression.dispatch." + task_id;
            diagnostic.task_id = task_id;
            diagnostic.owner = "Source Debugger";
            diagnostic.target = "PID " + std::to_string(pid);
            diagnostic.summary = "Debugger expression result publication failed";
            diagnostic.details = dispatch_error;
            diagnostic.severity = task_center::diagnostic_severity_t::error;
            diagnostic.callbacks.focus = [] {
                static_cast<void>(application_views::open_or_focus(
                    stable_view_id_t("view.programming.source_debug_console")));
            };
            static_cast<void>(task_center::raise_diagnostic(std::move(diagnostic)));
        }
    };
    aida::infra::executor::submit_result_t submitted;
    try {
        submitted = aida::infra::executor::submit(std::move(submission));
    } catch (const std::exception& exception) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            std::string("Debugger expression scheduling raised an exception: ") +
            exception.what());
    } catch (...) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            "Debugger expression scheduling raised an unknown exception");
    }
    if (!submitted.submitted) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            "Debugger expression evaluation scheduling failed: " +
            submitted.reject_reason);
    }
    bool registered = false;
    std::string registration_error =
        "Task Center rejected debugger expression evaluation ownership";
    try {
        task_center::task_registration_t registration;
        registration.id = task_id;
        registration.owner = "source_debug";
        registration.owner_view = persistent_watch_index >= 0
            ? "view.debug.watches" : "view.programming.source_debug_console";
        registration.owner_action = owner_action ? owner_action : "debug.selection.evaluate";
        registration.target = "PID " + std::to_string(pid);
        registration.label = label ? label : "Evaluate debugger expression";
        registration.stage = "Queued against stop generation " +
            std::to_string(stop_generation);
        registration.affected_entity = expression;
        registration.cancellation_is_safe = true;
        registration.callbacks.cancel = [cancelled, task = submitted.task_id] {
            cancelled->store(true, std::memory_order_release);
            return aida::infra::executor::cancel(task);
        };
        registration.callbacks.focus = [persistent = persistent_watch_index >= 0] {
            static_cast<void>(application_views::open_or_focus(stable_view_id_t(
                persistent ? "view.debug.watches"
                           : "view.programming.source_debug_console")));
        };
        registered = task_center::try_register_executor_job(
            submitted.task_id, std::move(registration));
    } catch (const std::exception& exception) {
        registration_error = std::string(
            "Task Center registration raised an exception: ") + exception.what();
    } catch (...) {
        registration_error = "Task Center registration raised an unknown exception";
    }
    const bool registration_timed_out = registration_gate->release(registered);
    if (!registered) {
        cancelled->store(true, std::memory_order_release);
        static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
        return action_handler_result_t::failed(registration_error);
    }
    if (registration_timed_out) {
        cancelled->store(true, std::memory_order_release);
        static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
        static_cast<void>(task_center::update_task(task_id,
            task_center::task_state_t::failed, 1.0f,
            "Registration handshake timed out",
            "The bounded worker ownership gate expired before Task Center registration completed"));
        return action_handler_result_t::failed(
            "Debugger expression ownership registration exceeded the bounded worker gate");
    }
    return action_handler_result_t::completed(
        persistent_watch_index >= 0
            ? "Watch persisted; authoritative evaluation queued"
            : "One-shot debugger evaluation queued");
}

std::atomic<std::uint64_t>& debugger_watch_refresh_generation() {
    static std::atomic<std::uint64_t> generation{0};
    return generation;
}

bool debugger_watch_refresh_task_active() {
    const auto current = task_center::snapshot();
    if (!current)
        return false;
    return std::any_of(current->tasks.begin(), current->tasks.end(), [](const auto& task) {
        if (task.owner_action != "debugger.watch.refresh_all")
            return false;
        return task.state == task_center::task_state_t::queued ||
            task.state == task_center::task_state_t::running ||
            task.state == task_center::task_state_t::cancellation_requested;
    });
}

capability_state_t debugger_watch_refresh_capability() {
    if (debugger_watch_refresh_task_active())
        return capability_state_t::unavailable(
            "A debugger watch refresh is already running");
    if (debugger_engine::g_state.target_pid == 0)
        return capability_state_t::unavailable(
            "Attach the debugger to a process first");
    if (debugger_engine::g_state.status.load(std::memory_order_acquire) !=
            debugger_engine::dbg_status_t::paused)
        return capability_state_t::unavailable(
            "Pause the debugger before refreshing watches");
    const auto source = source_debug_service::snapshot();
    if (!source || source->target_pid != debugger_engine::g_state.target_pid ||
        source->target_key.empty() ||
        source->stop_generation != debugger_interaction::current_stop_generation())
        return capability_state_t::unavailable(
            "Wait for the debugger target and stop context to finish publishing");
    std::unique_lock<std::mutex> lock(debugger_engine::g_state.watch_mutex,
        std::try_to_lock);
    if (!lock.owns_lock())
        return capability_state_t::unavailable(
            "Watch definitions are being updated");
    if (debugger_engine::g_state.watches.empty())
        return capability_state_t::unavailable(
            "Add at least one watch expression first");
    return capability_state_t::available();
}

const char* watch_refresh_publish_detail(
        debugger_engine::watch_refresh_publish_result_t result) {
    using result_t = debugger_engine::watch_refresh_publish_result_t;
    switch (result) {
    case result_t::published:
        return "The exact watch generation was refreshed";
    case result_t::stale_generation:
        return "Watch definitions changed before publication; no stale result was applied";
    case result_t::cardinality_mismatch:
        return "The watch count changed before publication; no stale result was applied";
    case result_t::identity_mismatch:
        return "A watch definition changed before publication; no stale result was applied";
    case result_t::invalid_batch:
        return "The immutable watch refresh capture was invalid";
    case result_t::result_mismatch:
        return "The watch refresh evaluator returned an incomplete result set";
    }
    return "The watch refresh publication returned an unknown result";
}

action_handler_result_t schedule_debugger_watch_refresh() {
    const auto capability = debugger_watch_refresh_capability();
    if (!capability.enabled)
        return action_handler_result_t::failed(capability.disabled_reason);
    const auto source = source_debug_service::snapshot();
    if (!source)
        return action_handler_result_t::failed(
            "The debugger stop context is unavailable");
    debugger_engine::watch_refresh_batch_ptr captured;
    try {
        captured = debugger_engine::capture_watch_refresh_batch();
    } catch (const std::exception& exception) {
        return action_handler_result_t::failed(
            std::string("Watch capture raised an exception: ") + exception.what());
    } catch (...) {
        return action_handler_result_t::failed(
            "Watch capture raised an unknown exception");
    }
    if (!captured || !captured->valid())
        return action_handler_result_t::failed(captured && !captured->error.empty()
            ? captured->error : "The immutable watch capture is invalid");
    if (captured->targets.empty())
        return action_handler_result_t::failed(
            "Add at least one watch expression first");

    const std::uint64_t request_generation =
        debugger_watch_refresh_generation().fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint32_t pid = source->target_pid;
    const std::uint64_t publication_generation = source->generation;
    const std::uint64_t stop_generation = source->stop_generation;
    const std::string target_key = source->target_key;
    const std::string task_id = "debugger.watch.refresh." +
        std::to_string(request_generation);
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    auto registration_gate = std::make_shared<debugger_task_registration_gate_t>();

    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "debugger";
    submission.label = "debugger.watch.refresh_all";
    submission.thread_class = "target_read";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.target_pid = pid;
    submission.generation = request_generation;
    submission.cancel_hook = [cancelled] {
        cancelled->store(true, std::memory_order_release);
    };
    submission.body = [captured, pid, publication_generation, stop_generation,
        target_key, task_id, cancelled, registration_gate]() mutable {
        if (!registration_gate->await_registration())
            return;
        static_cast<void>(task_center::update_task(task_id,
            task_center::task_state_t::running, 0.1f,
            "Evaluating immutable watch generation " +
                std::to_string(captured->generation)));

        debugger_engine::watch_refresh_evaluation_batch_t evaluated;
        std::string fence_error;
        try {
            const auto before = source_debug_service::snapshot();
            if (!expression_fence_matches(before, pid, publication_generation,
                    stop_generation, target_key))
                fence_error = "Debugger target or stop generation changed before watch evaluation began";
            else if (cancelled->load(std::memory_order_acquire))
                fence_error = "Debugger watch refresh was cancelled before evaluation began";
            else
                evaluated = debugger_engine::evaluate_watch_refresh_batch(captured,
                    [cancelled] {
                        return cancelled->load(std::memory_order_acquire);
                    });
        } catch (const std::exception& exception) {
            evaluated.source = captured;
            evaluated.error = std::string("Watch evaluation raised an exception: ") +
                exception.what();
        } catch (...) {
            evaluated.source = captured;
            evaluated.error = "Watch evaluation raised an unknown exception";
        }

        const auto after = source_debug_service::snapshot();
        if (fence_error.empty() && !expression_fence_matches(after, pid,
                publication_generation, stop_generation, target_key))
            fence_error = "Debugger target or stop generation changed during watch evaluation";
        if (fence_error.empty() && cancelled->load(std::memory_order_acquire))
            fence_error = "Debugger watch refresh was cancelled after evaluation";

        bool posted = false;
        std::string dispatch_error =
            "The watch refresh result could not return to the UI owner";
        try {
            posted = aida::ui_thread::post(
                [pid, publication_generation, stop_generation, target_key,
                 task_id, cancelled, evaluated = std::move(evaluated),
                 fence_error = std::move(fence_error)]() mutable {
                    const auto current = source_debug_service::snapshot();
                    if (fence_error.empty() && !expression_fence_matches(current, pid,
                            publication_generation, stop_generation, target_key))
                        fence_error = "Debugger target or stop generation changed before watch publication";
                    if (fence_error.empty() && cancelled->load(std::memory_order_acquire))
                        fence_error = "Debugger watch refresh was cancelled before publication";
                    if (!fence_error.empty()) {
                        static_cast<void>(task_center::update_task(task_id,
                            task_center::task_state_t::cancelled, 1.0f,
                            "Watch refresh discarded by the debugger generation fence",
                            fence_error));
                        return;
                    }
                    if (!evaluated.valid()) {
                        const std::string detail = evaluated.error.empty()
                            ? "The watch evaluator returned an invalid result batch"
                            : evaluated.error;
                        const std::string diagnostic_id =
                            "diagnostic.debugger.watch.refresh." + task_id;
                        static_cast<void>(task_center::update_task(task_id,
                            task_center::task_state_t::failed, 1.0f,
                            "Watch evaluation failed", detail, diagnostic_id));
                        task_center::diagnostic_registration_t diagnostic;
                        diagnostic.id = diagnostic_id;
                        diagnostic.task_id = task_id;
                        diagnostic.owner = "Debugger Watches";
                        diagnostic.target = "PID " + std::to_string(pid);
                        diagnostic.summary = "Debugger watch refresh failed";
                        diagnostic.details = detail;
                        diagnostic.severity = task_center::diagnostic_severity_t::error;
                        diagnostic.callbacks.focus = [] {
                            static_cast<void>(application_views::open_or_focus(
                                stable_view_id_t("view.debug.watches")));
                        };
                        static_cast<void>(task_center::raise_diagnostic(
                            std::move(diagnostic)));
                        return;
                    }

                    auto published =
                        debugger_engine::watch_refresh_publish_result_t::invalid_batch;
                    std::string publication_exception;
                    try {
                        published = debugger_engine::publish_watch_refresh_batch(evaluated);
                    } catch (const std::exception& exception) {
                        publication_exception =
                            std::string("Watch publication raised an exception: ") +
                            exception.what();
                    } catch (...) {
                        publication_exception =
                            "Watch publication raised an unknown exception";
                    }
                    if (!publication_exception.empty()) {
                        const std::string diagnostic_id =
                            "diagnostic.debugger.watch.publish." + task_id;
                        static_cast<void>(task_center::update_task(task_id,
                            task_center::task_state_t::failed, 1.0f,
                            "Watch publication failed", publication_exception,
                            diagnostic_id));
                        task_center::diagnostic_registration_t diagnostic;
                        diagnostic.id = diagnostic_id;
                        diagnostic.task_id = task_id;
                        diagnostic.owner = "Debugger Watches";
                        diagnostic.target = "PID " + std::to_string(pid);
                        diagnostic.summary = "Debugger watch publication failed";
                        diagnostic.details = publication_exception;
                        diagnostic.severity = task_center::diagnostic_severity_t::error;
                        diagnostic.callbacks.focus = [] {
                            static_cast<void>(application_views::open_or_focus(
                                stable_view_id_t("view.debug.watches")));
                        };
                        static_cast<void>(task_center::raise_diagnostic(
                            std::move(diagnostic)));
                        return;
                    }
                    const char* detail = watch_refresh_publish_detail(published);
                    if (published == debugger_engine::watch_refresh_publish_result_t::published) {
                        static_cast<void>(task_center::update_task(task_id,
                            task_center::task_state_t::completed, 1.0f,
                            "Refreshed " + std::to_string(evaluated.results.size()) +
                                " watch expression(s)", detail));
                        return;
                    }
                    const bool stale =
                        published == debugger_engine::watch_refresh_publish_result_t::stale_generation ||
                        published == debugger_engine::watch_refresh_publish_result_t::cardinality_mismatch ||
                        published == debugger_engine::watch_refresh_publish_result_t::identity_mismatch;
                    if (stale) {
                        static_cast<void>(task_center::update_task(task_id,
                            task_center::task_state_t::partial, 1.0f,
                            "Watch definitions changed during refresh", detail));
                        return;
                    }
                    const std::string diagnostic_id =
                        "diagnostic.debugger.watch.publish." + task_id;
                    static_cast<void>(task_center::update_task(task_id,
                        task_center::task_state_t::failed, 1.0f,
                        "Watch publication failed", detail, diagnostic_id));
                    task_center::diagnostic_registration_t diagnostic;
                    diagnostic.id = diagnostic_id;
                    diagnostic.task_id = task_id;
                    diagnostic.owner = "Debugger Watches";
                    diagnostic.target = "PID " + std::to_string(pid);
                    diagnostic.summary = "Debugger watch publication failed";
                    diagnostic.details = detail;
                    diagnostic.severity = task_center::diagnostic_severity_t::error;
                    diagnostic.callbacks.focus = [] {
                        static_cast<void>(application_views::open_or_focus(
                            stable_view_id_t("view.debug.watches")));
                    };
                    static_cast<void>(task_center::raise_diagnostic(
                        std::move(diagnostic)));
                }, "debugger", "watch_refresh_result", "worker_result");
        } catch (const std::exception& exception) {
            dispatch_error = std::string("Watch result publication raised an exception: ") +
                exception.what();
        } catch (...) {
            dispatch_error = "Watch result publication raised an unknown exception";
        }
        if (!posted) {
            const std::string diagnostic_id =
                "diagnostic.debugger.watch.dispatch." + task_id;
            static_cast<void>(task_center::update_task(task_id,
                task_center::task_state_t::failed, 1.0f,
                "Watch result dispatch failed", dispatch_error, diagnostic_id));
            task_center::diagnostic_registration_t diagnostic;
            diagnostic.id = diagnostic_id;
            diagnostic.task_id = task_id;
            diagnostic.owner = "Debugger Watches";
            diagnostic.target = "PID " + std::to_string(pid);
            diagnostic.summary = "Debugger watch result dispatch failed";
            diagnostic.details = dispatch_error;
            diagnostic.severity = task_center::diagnostic_severity_t::error;
            diagnostic.callbacks.focus = [] {
                static_cast<void>(application_views::open_or_focus(
                    stable_view_id_t("view.debug.watches")));
            };
            static_cast<void>(task_center::raise_diagnostic(std::move(diagnostic)));
        }
    };

    aida::infra::executor::submit_result_t submitted;
    try {
        submitted = aida::infra::executor::submit(std::move(submission));
    } catch (const std::exception& exception) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            std::string("Watch refresh scheduling raised an exception: ") +
            exception.what());
    } catch (...) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            "Watch refresh scheduling raised an unknown exception");
    }
    if (!submitted.submitted) {
        static_cast<void>(registration_gate->release(false));
        return action_handler_result_t::failed(
            "Watch refresh scheduling failed: " + submitted.reject_reason);
    }

    bool registered = false;
    std::string registration_error =
        "Task Center rejected debugger watch refresh ownership";
    try {
        task_center::task_registration_t registration;
        registration.id = task_id;
        registration.owner = "debugger";
        registration.owner_view = "view.debug.watches";
        registration.owner_action = "debugger.watch.refresh_all";
        registration.target = "PID " + std::to_string(pid);
        registration.label = "Refresh debugger watches";
        registration.stage = "Queued against stop generation " +
            std::to_string(stop_generation);
        registration.affected_entity = std::to_string(captured->cardinality) +
            " watch expression(s)";
        registration.cancellation_is_safe = true;
        registration.callbacks.cancel = [cancelled, task = submitted.task_id] {
            cancelled->store(true, std::memory_order_release);
            return aida::infra::executor::cancel(task);
        };
        registration.callbacks.focus = [] {
            static_cast<void>(application_views::open_or_focus(
                stable_view_id_t("view.debug.watches")));
        };
        registered = task_center::try_register_executor_job(
            submitted.task_id, std::move(registration));
    } catch (const std::exception& exception) {
        registration_error = std::string(
            "Watch Task Center registration raised an exception: ") +
            exception.what();
    } catch (...) {
        registration_error =
            "Watch Task Center registration raised an unknown exception";
    }
    const bool registration_timed_out = registration_gate->release(registered);
    if (!registered) {
        cancelled->store(true, std::memory_order_release);
        static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
        return action_handler_result_t::failed(registration_error);
    }
    if (registration_timed_out) {
        cancelled->store(true, std::memory_order_release);
        static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
        static_cast<void>(task_center::update_task(task_id,
            task_center::task_state_t::failed, 1.0f,
            "Registration handshake timed out",
            "The bounded worker ownership gate expired before Task Center registration completed"));
        return action_handler_result_t::failed(
            "Debugger watch ownership registration exceeded the bounded worker gate");
    }
    return action_handler_result_t::completed(
        "Authoritative debugger watch refresh queued");
}

std::optional<view_instance_id_t> code_group_instance(int tab_index) {
    if (!file_tabs::is_valid_tab_index(tab_index))
        return std::nullopt;
    return view_instance_id_t{stable_view_id_t("document.code"),
        stable_view_instance_key_t(file_tabs::group_instance_key(
            file_tabs::tabs[file_tabs::tab_index(tab_index)].group_id))};
}

bool open_workspace_search_result(const workspace_search_context_t& result) {
    const std::string name = path_to_utf8(path_from_utf8(result.path).filename());
    if (!file_tabs::request_document_open(result.path, name,
            (std::max)(0, result.line - 1), (std::max)(0, result.column)))
        return false;
    application_views::open_or_focus(stable_view_id_t("document.code"));
    return true;
}

disasm_view::workspace_context_t selected_analysis_context() {
    return disasm_view::capture_selected_workspace();
}

std::optional<aida::analysis::address_t> selected_analysis_address(
    const disasm_view::workspace_context_t& context) {
    return context.workspace ? context.workspace->view_state().selection : std::nullopt;
}

capability_state_t analysis_workspace_capability() {
    const auto context = selected_analysis_context();
    if (!context.workspace)
        return capability_state_t::unavailable("Open and analyze a binary first");
    if (context.workspace->closing() || context.workspace->closed())
        return capability_state_t::unavailable("The selected analysis workspace is closing");
    if (!context.publication || !context.publication->snapshot)
        return capability_state_t::unavailable("Analysis has not published a usable snapshot yet");
    return capability_state_t::available();
}

capability_state_t analysis_selection_capability() {
    const auto workspace = analysis_workspace_capability();
    if (!workspace.enabled)
        return workspace;
    const auto context = selected_analysis_context();
    return selected_analysis_address(context)
        ? capability_state_t::available()
        : capability_state_t::unavailable("Select an instruction, function, graph node, pseudocode line, reference, or typed address first");
}

capability_state_t analysis_graph_capability() {
    const auto selection = analysis_selection_capability();
    if (!selection.enabled)
        return selection;
    const auto context = selected_analysis_context();
    const auto address = selected_analysis_address(context);
    if (!address)
        return capability_state_t::unavailable(
            "The analysis selection no longer has an address");
    const auto runtime = disasm_view::runtime_address(context, *address)
        .value_or(address->value);
    return disasm_view::enclosing_function_start(runtime, context) != 0
        ? capability_state_t::available()
        : capability_state_t::unavailable(
            "No recovered function contains the selected address");
}

capability_state_t analysis_history_capability(bool forward) {
    const auto workspace = analysis_workspace_capability();
    if (!workspace.enabled)
        return workspace;
    const auto context = selected_analysis_context();
    workbench::workbench_shell_workspace_context_t workspace_context;
    const auto loaded = workbench::workbench_shell_runtime_t::instance()
        .workspace_context(context.workspace, workspace_context);
    if (!loaded)
        return capability_state_t::unavailable("The persistent analysis history is unavailable for this workspace");
    const auto& history = workspace_context.persistence.history;
    if (forward ? history.forward.empty() : history.back.empty())
        return capability_state_t::unavailable(forward
            ? "There is no forward analysis location"
            : "There is no previous analysis location");
    return capability_state_t::available();
}

capability_state_t analysis_overlay_history_capability(bool redo) {
    const auto workspace = analysis_workspace_capability();
    if (!workspace.enabled)
        return workspace;
    const auto context = selected_analysis_context();
    if (!context.view || !context.workspace->overlay())
        return capability_state_t::unavailable(
            "The selected analysis workspace has no reversible overlay journal");
    const auto mutation = disasm_view::mutation_state(context);
    if (mutation.pending != 0)
        return capability_state_t::unavailable(
            "Wait for the current analysis overlay mutation to finish");
    const auto history = context.workspace->overlay()->history_snapshot();
    if (history.revision != context.workspace->overlay_revision())
        return capability_state_t::unavailable(
            "The overlay history publication changed; retry after the current frame");
    if (redo ? !history.can_redo() : !history.can_undo())
        return capability_state_t::unavailable(redo
            ? "There is no reversible analysis overlay transaction to redo"
            : "There is no reversible analysis overlay transaction to undo");
    return capability_state_t::available();
}

capability_state_t analysis_rebase_capability() {
    const auto workspace = analysis_workspace_capability();
    if (!workspace.enabled)
        return workspace;
    const auto context = selected_analysis_context();
    if (!context.image || context.workspace->target_kind() !=
            aida::analysis::target_kind_t::static_file)
        return capability_state_t::unavailable(
            "Rebase is available only for static file-backed analysis workspaces");
    return capability_state_t::available();
}

capability_state_t analysis_listing_export_capability() {
    const auto workspace = analysis_workspace_capability();
    if (!workspace.enabled)
        return workspace;
    const auto context = selected_analysis_context();
    if (!context.image)
        return capability_state_t::unavailable(
            "A file-backed analysis listing is required for export");
    if (context.view && context.view->export_pending.load(std::memory_order_acquire))
        return capability_state_t::unavailable(
            "A disassembly listing export is already running");
    return capability_state_t::available();
}

std::optional<std::uint64_t> selected_analysis_direct_target(
    const disasm_view::workspace_context_t& context) {
    const auto selected = selected_analysis_address(context);
    if (!selected || !context.publication || !context.publication->snapshot)
        return std::nullopt;
    const auto& snapshot = *context.publication->snapshot;
    const auto instruction = std::lower_bound(snapshot.instructions.begin(),
        snapshot.instructions.end(), *selected,
        [](const aida::analysis::instruction_record_t& record,
           const aida::analysis::address_t& address) {
            return record.address < address;
        });
    if (instruction == snapshot.instructions.end() || instruction->address != *selected)
        return std::nullopt;
    const std::size_t begin = instruction->target_fact_begin;
    const std::size_t end = (std::min)(snapshot.target_facts.size(),
        begin + static_cast<std::size_t>(instruction->target_fact_count));
    for (std::size_t index = begin; index < end; ++index) {
        if (snapshot.target_facts[index].direct)
            return disasm_view::runtime_address(context,
                snapshot.target_facts[index].target).value_or(
                    snapshot.target_facts[index].target.value);
    }
    return std::nullopt;
}

struct analysis_debug_location_t {
    debugger_interaction::context_t debugger_context;
};

std::optional<analysis_debug_location_t> selected_analysis_debug_location() {
    const auto context = selected_analysis_context();
    const auto selected = selected_analysis_address(context);
    const auto process = context.workspace ? context.workspace->identity().process()
                                           : std::nullopt;
    if (!selected || !process)
        return std::nullopt;
    const auto runtime = disasm_view::runtime_address(context, *selected);
    if (!runtime)
        return std::nullopt;
    const auto debugger_context = debugger_interaction::capture(
        debugger_interaction::kind_t::instruction, *runtime);
    if (process->creation_time_100ns == 0 ||
        debugger_context.target_pid != process->pid ||
        debugger_context.process_creation_time_100ns != process->creation_time_100ns ||
        !debugger_interaction::is_current(debugger_context))
        return std::nullopt;
    return analysis_debug_location_t{debugger_context};
}

capability_state_t analysis_debug_mutation_capability(bool toggle_breakpoint) {
    const auto selection = analysis_selection_capability();
    if (!selection.enabled)
        return selection;
    const auto location = selected_analysis_debug_location();
    if (!location)
        return capability_state_t::unavailable(
            "Select an address in a live process-backed analysis workspace");
    const auto capability = debugger_view::address_mutation_capability(
        location->debugger_context, toggle_breakpoint);
    return capability.enabled
        ? capability_state_t::available()
        : capability_state_t::unavailable(capability.disabled_reason
            ? capability.disabled_reason : "The debugger mutation is unavailable");
}

action_handler_result_t open_analysis_view(const char* id) {
    const auto result = application_views::open_or_focus(stable_view_id_t(id));
    return result.ok() ? action_handler_result_t::completed()
                       : action_handler_result_t::failed(result.detail);
}

capability_state_t document_or_session_cycle_capability() {
    if (file_tabs::tabs.size() > 1 || analysis_session::session_count() > 1)
        return capability_state_t::available();
    return capability_state_t::unavailable(
        "Open at least two code documents or analysis sessions first");
}

action_handler_result_t cycle_document_or_session(bool reverse) {
    const auto focused = application_views::registry().focused_instance();
    const bool code_focused = focused && focused->view == stable_view_id_t("document.code");
    if (code_focused && file_tabs::tabs.size() > 1) {
        const int count = static_cast<int>(file_tabs::tabs.size());
        const int current = file_tabs::is_valid_tab_index(file_tabs::active_tab)
            ? file_tabs::active_tab : 0;
        const int target = reverse ? (current + count - 1) % count : (current + 1) % count;
        file_tabs::switch_to(target);
        const auto result = application_views::open_or_focus(stable_view_id_t("document.code"));
        return result.ok() ? action_handler_result_t::completed()
                           : action_handler_result_t::failed(result.detail);
    }
    const std::size_t count = analysis_session::session_count();
    if (count > 1) {
        const std::size_t current = analysis_session::active_session_idx();
        const std::size_t target = current == static_cast<std::size_t>(-1)
            ? 0
            : (reverse ? (current + count - 1) % count : (current + 1) % count);
        return analysis_session::switch_session(target)
            ? action_handler_result_t::completed()
            : action_handler_result_t::failed("The target analysis session could not be activated");
    }
    if (file_tabs::tabs.size() > 1) {
        const int count_tabs = static_cast<int>(file_tabs::tabs.size());
        const int current = file_tabs::is_valid_tab_index(file_tabs::active_tab)
            ? file_tabs::active_tab : 0;
        file_tabs::switch_to(reverse
            ? (current + count_tabs - 1) % count_tabs
            : (current + 1) % count_tabs);
        const auto result = application_views::open_or_focus(stable_view_id_t("document.code"));
        return result.ok() ? action_handler_result_t::completed()
                           : action_handler_result_t::failed(result.detail);
    }
    return action_handler_result_t::failed(
        "There is no other code document or analysis session");
}

void initialize(runtime_t& rt) {
    if (rt.initialized)
        return;
    rt.initialized = true;
    const auto all_surfaces = action_surface_t::application_menu |
        action_surface_t::command_palette | action_surface_t::context_menu |
        action_surface_t::shortcut | action_surface_t::accessibility;
    const auto menu_surfaces = action_surface_t::application_menu |
        action_surface_t::command_palette | action_surface_t::shortcut |
        action_surface_t::accessibility;
    const auto context_surfaces = action_surface_t::context_menu |
        action_surface_t::command_palette | action_surface_t::accessibility;

    register_action(rt, "file.new", "New File", "Create an untitled code document",
        menu_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            file_tabs::open_or_focus("", "untitled", "");
            application_views::open_or_focus(stable_view_id_t("document.code"));
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.open", "Open File...", "Open a file",
        menu_surfaces | action_surface_t::toolbar,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_file)
                return action_handler_result_t::failed("Open-file provider is unavailable");
            rt.shell.open_file();
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.open_folder", "Open Folder...", "Open a folder in Explorer",
        menu_surfaces | action_surface_t::toolbar | action_surface_t::context_menu,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_folder)
                return action_handler_result_t::failed("Open-folder provider is unavailable");
            rt.shell.open_folder();
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.quick_open", "Quick Open...",
        "Incrementally search indexed workspace files and symbols, IDE views, and registered commands",
        menu_surfaces | action_surface_t::context_menu,
        [](const action_invocation_t&) {
            globals::ui::command_palette_open = false;
            globals::ui::quick_open_buf[0] = '\0';
            globals::ui::quick_open_open = true;
            return action_handler_result_t::completed();
        }, {}, false, {}, "category.file", "File");
    register_action(rt, "file.restore_previous_session", "Restore Previous Session",
        "Open the most recent closed binary or analysis session",
        menu_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            return explorer_views::request_restore_previous_session()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("No closed recent analysis session is available");
        }, [](const interaction_context_t&) {
            return explorer_views::can_restore_previous_session()
                ? capability_state_t::available()
                : capability_state_t::unavailable("No closed recent analysis session is available");
        });
    register_action(rt, "file.reopen_closed_document", "Reopen Closed Code Document",
        "Reopen the most recently closed path-backed code document and restore its group and caret",
        menu_surfaces | action_surface_t::context_menu,
        [](const action_invocation_t&) {
            if (!file_tabs::reopen_closed_document())
                return action_handler_result_t::failed(
                    "No path-backed closed code document is available");
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("document.code"));
            return opened.ok() ? action_handler_result_t::completed()
                : action_handler_result_t::failed(opened.detail);
        }, [](const interaction_context_t&) {
            return file_tabs::can_reopen_closed_document()
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "No path-backed closed code document is available");
        });
    register_action(rt, "file.save", "Save", "Save the active code document", all_surfaces,
        [](const action_invocation_t&) {
            const auto result = file_tabs::save_tab_to_disk_result(file_tabs::active_tab);
            return result.succeeded ? action_handler_result_t::completed()
                                    : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) { return editor_savable(); });
    register_action(rt, "file.save_as", "Save As...", "Save the active code document to a new path", all_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.save_as)
                return action_handler_result_t::failed("Save As provider is unavailable");
			file_tabs::shell_save_as_result.reset();
            rt.shell.save_as();
			if (!file_tabs::shell_save_as_result)
				return action_handler_result_t::failed(
					"Save As provider did not return an operation result");
			const auto result = std::move(*file_tabs::shell_save_as_result);
			file_tabs::shell_save_as_result.reset();
			return result.succeeded ? action_handler_result_t::completed()
				: action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
			const auto active = editor_active();
			if (!active.enabled) return active;
			const auto gate = file_tabs::verify_tab_save_gate(file_tabs::active_tab, false);
			return gate.succeeded ? capability_state_t::available()
				: capability_state_t::unavailable(gate.detail);
		});
    register_action(rt, "file.save_all", "Save All", "Save every modified code document", all_surfaces,
        [](const action_invocation_t&) {
			const auto result = file_tabs::save_all_tabs_result();
			return result.succeeded ? action_handler_result_t::completed()
				: action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
			const auto preflight = file_tabs::preflight_save_all();
			if (!preflight.result.succeeded)
				return capability_state_t::unavailable(preflight.result.detail);
			return !preflight.documents.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("No modified documents need saving");
        });
    register_action(rt, "file.close", "Close", "Close the active code document", all_surfaces,
        [](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
			if (!file_tabs::is_valid_tab_index(file_tabs::active_tab))
				return action_handler_result_t::failed("No code document is open");
			const auto& tab = file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)];
			if (file_tabs::close_operation_pending(tab))
				return action_handler_result_t::failed(file_tabs::close_operation_detail(tab));
            close_tab_with_confirmation(file_tabs::active_tab);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            if (!file_tabs::is_valid_tab_index(file_tabs::active_tab))
                return capability_state_t::unavailable("No code document is open");
			const auto& tab = file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)];
			if (file_tabs::close_operation_pending(tab))
				return capability_state_t::unavailable(file_tabs::close_operation_detail(tab));
            return tab.pinned
                ? capability_state_t::unavailable("Unpin the active document before closing it")
                : capability_state_t::available();
        });
    register_action(rt, "file.close_all", "Close All", "Close every unpinned code document, reviewing each unsaved document in turn", all_surfaces,
        [](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
            for (const auto& tab : file_tabs::tabs) {
				if (!tab.pinned && file_tabs::close_operation_pending(tab))
					return action_handler_result_t::failed(
						tab.filename + ": " + file_tabs::close_operation_detail(tab));
            }
            const std::size_t requested = file_tabs::request_close_all();
            return requested != 0
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("No unpinned code documents are open");
        }, [](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            bool has_unpinned = false;
            for (const auto& tab : file_tabs::tabs) {
                if (tab.pinned)
                    continue;
                has_unpinned = true;
				if (file_tabs::close_operation_pending(tab))
					return capability_state_t::unavailable(
						tab.filename + ": " + file_tabs::close_operation_detail(tab));
            }
            return has_unpinned
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "No unpinned code documents are open");
        });
    register_action(rt, "file.exit", "Exit", "Close AiDA", menu_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.exit_application)
                return action_handler_result_t::failed("Application shutdown provider is unavailable");
			const auto requested = file_tabs::request_exit_review();
			return requested.succeeded ? action_handler_result_t::completed()
				: action_handler_result_t::failed(requested.detail);
        }, [&rt](const interaction_context_t&) {
			if (!rt.shell.exit_application)
				return capability_state_t::unavailable(
					"Application shutdown provider is unavailable");
			if (file_tabs::exit_review_requested)
				return capability_state_t::available();
			return file_tabs::close_review_in_progress()
				? capability_state_t::unavailable(
					"Finish the current document-close review first")
				: capability_state_t::available();
		});

    register_action(rt, "navigate.next_document_or_session", "Next Document or Session",
        "Activate the next code document in the focused editor, otherwise the next analysis session",
        menu_surfaces,
        [](const action_invocation_t&) { return cycle_document_or_session(false); },
        [](const interaction_context_t&) { return document_or_session_cycle_capability(); },
        false, {}, "category.navigate", "Navigate");
    register_action(rt, "navigate.previous_document_or_session", "Previous Document or Session",
        "Activate the previous code document in the focused editor, otherwise the previous analysis session",
        menu_surfaces,
        [](const action_invocation_t&) { return cycle_document_or_session(true); },
        [](const interaction_context_t&) { return document_or_session_cycle_capability(); },
        false, {}, "category.navigate", "Navigate");
    register_action(rt, "programming.show_problems", "Problems and Diagnostics",
        "Open the canonical diagnostics surface for editor, task, analysis, and runtime failures",
        all_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            const auto result = application_views::open_or_focus(
                stable_view_id_t("view.diagnostics"));
            return result.ok() ? action_handler_result_t::completed()
                               : action_handler_result_t::failed(result.detail);
        }, {}, false, {}, "category.programming", "Programming");
    const auto programming_result = [](const programming_tasks::operation_result_t& result) {
        return result.succeeded ? action_handler_result_t::completed()
            : action_handler_result_t::failed(result.detail);
    };
    register_action(rt, "programming.task.run", "Run Programming Task...",
        "Review and run the selected explicit programming task or launch configuration; this is separate from RE Run Target",
        all_surfaces,
        [programming_result](const action_invocation_t&) {
            return programming_result(programming_tasks::request_run_selected());
        }, [](const interaction_context_t&) {
            const std::string reason = programming_tasks::run_unavailable_reason();
            return reason.empty() ? capability_state_t::available() : capability_state_t::unavailable(reason);
        }, false, {}, "category.programming", "Programming / Tasks");
    register_action(rt, "programming.task.cancel", "Cancel Programming Task",
        "Request cancellation and terminate the selected programming process tree",
        all_surfaces,
        [programming_result](const action_invocation_t&) {
            return programming_result(programming_tasks::request_cancel_active());
        }, [](const interaction_context_t&) {
            const std::string reason = programming_tasks::cancel_unavailable_reason();
            return reason.empty() ? capability_state_t::available() : capability_state_t::unavailable(reason);
        }, false, {}, "category.programming", "Programming / Tasks");
    register_action(rt, "programming.task.retry", "Retry Last Programming Task...",
        "Review the current resolved configuration before retrying the last completed programming run",
        all_surfaces,
        [programming_result](const action_invocation_t&) {
            return programming_result(programming_tasks::request_retry_last());
        }, [](const interaction_context_t&) {
            const std::string reason = programming_tasks::retry_unavailable_reason();
            return reason.empty() ? capability_state_t::available() : capability_state_t::unavailable(reason);
        }, false, {}, "category.programming", "Programming / Tasks");
    register_action(rt, "programming.task.configure", "Configure Programming Tasks...",
        "Manage explicit user task and launch configurations and inspect project .aida/tasks.json entries",
        all_surfaces,
        [programming_result](const action_invocation_t&) {
            return programming_result(programming_tasks::open_configurations());
        }, {}, false, {}, "category.programming", "Programming / Tasks");
    register_action(rt, "programming.task.reload", "Reload Programming Configurations",
        "Reload saved user configurations and the open folder's .aida/tasks.json",
        all_surfaces,
        [programming_result](const action_invocation_t&) {
            return programming_result(programming_tasks::reload_configurations());
        }, {}, false, {}, "category.programming", "Programming / Tasks");

    const auto language_surfaces = action_surface_t::application_menu |
        action_surface_t::command_palette | action_surface_t::context_menu |
        action_surface_t::shortcut | action_surface_t::accessibility;
    register_action(rt, "programming.index.rebuild", "Rebuild Workspace Text Index",
        "Cancel the previous generation and build one bounded immutable workspace text and C/C++ symbol index",
        language_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            const auto result = aida::editor::language_service::rebuild_workspace_index();
            return result.accepted ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.reason);
        }, [](const interaction_context_t&) {
            return g_sa_settings.workspace.root_path.empty() && file_browser::current_dir.empty()
                ? capability_state_t::unavailable("Open a workspace before rebuilding Workspace Text Index")
                : capability_state_t::available();
        }, false, {}, "category.programming.language", "Programming / Language Services");
    register_action(rt, "programming.index.cancel", "Cancel Workspace Index",
        "Request cancellation of the active Workspace Text Index generation while preserving the previous immutable publication",
        language_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            return aida::editor::language_service::cancel_workspace_index()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("No workspace index generation accepted cancellation");
        }, [](const interaction_context_t&) {
            return aida::editor::language_service::workspace_index_task_id() != 0
                ? capability_state_t::available()
                : capability_state_t::unavailable("No Workspace Text Index generation is running");
        }, false, {}, "category.programming.language", "Programming / Language Services");

    const auto register_language_query = [&](const char* id, const char* label,
        const char* description,
        aida::editor::language_service::capability_kind_t kind,
        bool identifier, const char* view) {
        register_action(rt, id, label, description, language_surfaces,
            [kind, identifier, view](const action_invocation_t&) {
                return request_language_query(kind, identifier, view);
            }, [kind, identifier](const interaction_context_t&) {
                return language_capability(kind, identifier);
            }, false, {}, "category.programming.language", "Programming / Language Services");
    };
    register_language_query("programming.language.completion", "Trigger Completion",
        "Request completion from the selected programming-language provider; AI ghost completion remains a separate AI feature",
        aida::editor::language_service::capability_kind_t::completion, false,
        "view.programming.references");
    register_language_query("programming.language.hover", "Show Hover",
        "Request semantic hover information from the selected programming-language provider",
        aida::editor::language_service::capability_kind_t::hover, true,
        "view.programming.references");
    register_language_query("programming.language.signature_help", "Signature Help",
        "Request call signature help from the selected programming-language provider",
        aida::editor::language_service::capability_kind_t::signature_help, false,
        "view.programming.references");
    register_language_query("programming.language.document_symbols", "Document Symbols",
        "Refresh the provider-backed Programming Outline for the active document",
        aida::editor::language_service::capability_kind_t::document_symbols, false,
        "view.programming.outline");
    register_language_query("programming.language.workspace_symbols", "Workspace Symbols",
        "Query bounded provider-backed symbols across the active workspace",
        aida::editor::language_service::capability_kind_t::workspace_symbols, false,
        "view.programming.outline");
    register_language_query("programming.language.diagnostics", "Language Diagnostics",
        "Request generated language diagnostics from the selected provider",
        aida::editor::language_service::capability_kind_t::diagnostics, false,
        "view.programming.references");
    register_language_query("programming.language.definition", "Go to Definition",
        "Resolve the identifier under the caret through the selected provider",
        aida::editor::language_service::capability_kind_t::definition, true,
        "view.programming.references");
    register_language_query("programming.language.declaration", "Go to Declaration",
        "Resolve the declaration of the identifier under the caret through a semantic provider",
        aida::editor::language_service::capability_kind_t::declaration, true,
        "view.programming.references");
    register_language_query("programming.language.implementation", "Go to Implementation",
        "Resolve concrete implementations of the identifier under the caret through a semantic provider",
        aida::editor::language_service::capability_kind_t::implementation, true,
        "view.programming.references");
    register_language_query("programming.language.type_definition", "Go to Type Definition",
        "Resolve the semantic type definition of the identifier under the caret",
        aida::editor::language_service::capability_kind_t::type_definition, true,
        "view.programming.references");
    register_language_query("programming.language.references", "Find Programming References",
        "Find bounded lexical or semantic references through the selected provider",
        aida::editor::language_service::capability_kind_t::references, true,
        "view.programming.references");
    register_action(rt, "programming.language.rename", "Rename Symbol",
        "Request revision-bound semantic rename edits from the selected provider for explicit review",
        language_surfaces,
        [](const action_invocation_t&) {
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.programming.references"));
            if (!opened.ok())
                return action_handler_result_t::failed(opened.detail);
            programming_language_views::open_rename_dialog();
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            return language_capability(
                aida::editor::language_service::capability_kind_t::semantic_rename, true);
        }, false, {}, "category.programming.language", "Programming / Language Services");
    register_language_query("programming.language.format", "Format Document",
        "Request document formatting from the selected provider",
        aida::editor::language_service::capability_kind_t::formatting, false,
        "view.programming.references");
    register_action(rt, "programming.language.format_selection", "Format Selection",
        "Request revision-bound formatting for the selected source range from the selected provider",
        language_surfaces,
        [](const action_invocation_t&) {
            return request_language_query(
                aida::editor::language_service::capability_kind_t::range_formatting,
                false, "view.programming.references");
        }, [](const interaction_context_t&) {
            const auto selected = editor_selection();
            if (!selected.enabled) return selected;
            return language_capability(
                aida::editor::language_service::capability_kind_t::range_formatting, false);
        }, false, {}, "category.programming.language", "Programming / Language Services");
    register_language_query("programming.language.code_actions", "Code Actions",
        "Request reviewed code actions from the selected provider",
        aida::editor::language_service::capability_kind_t::code_actions, false,
        "view.programming.references");
    register_action(rt, "programming.language.cancel_query", "Cancel Language Query",
        "Cancel the active provider query without discarding its previous immutable result",
        language_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            bool cancelled = false;
            for (std::size_t index = 0; index <= static_cast<std::size_t>(
                    aida::editor::language_service::capability_kind_t::code_actions); ++index)
                cancelled = aida::editor::language_service::cancel_request(
                    static_cast<aida::editor::language_service::capability_kind_t>(index)) || cancelled;
            return cancelled ? action_handler_result_t::completed()
                : action_handler_result_t::failed("No language query accepted cancellation");
        }, [](const interaction_context_t&) {
            for (std::size_t index = 0; index <= static_cast<std::size_t>(
                    aida::editor::language_service::capability_kind_t::code_actions); ++index) {
                const auto snapshot = aida::editor::language_service::result(
                    static_cast<aida::editor::language_service::capability_kind_t>(index));
                if (snapshot && snapshot->state ==
                    aida::editor::language_service::result_state_t::loading)
                    return capability_state_t::available();
            }
            return capability_state_t::unavailable("No language query is running");
        }, false, {}, "category.programming.language", "Programming / Language Services");

    const auto register_file_target = [&](const char* id, const char* label,
            const char* description, int kind) {
        register_action(rt, id, label, description, language_surfaces,
            [kind](const action_invocation_t&) {
                const auto document = code_editor_widget::document_state();
                const auto result = kind == 2
                    ? programming_tasks::request_test_selected_for_file(document.filepath)
                    : programming_tasks::request_run_selected_for_file(
                        document.filepath, kind == 1);
                return result.succeeded ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.detail);
            }, [kind](const interaction_context_t&) {
                const auto document = code_editor_widget::document_state();
                if (!document.active || document.filepath.empty())
                    return capability_state_t::unavailable(
                        "Open a path-backed source document first");
                const std::string reason = kind == 2
                    ? programming_tasks::test_for_file_unavailable_reason(document.filepath)
                    : programming_tasks::run_for_file_unavailable_reason(
                        document.filepath, kind == 1);
                return reason.empty() ? capability_state_t::available()
                    : capability_state_t::unavailable(reason);
            }, false, {}, "category.programming.tasks", "Programming / Run and Debug");
    };
    register_file_target("programming.run.file", "Run Current File...",
        "Review and run the selected Task configuration bound to this exact file", 0);
    register_file_target("programming.debug.file", "Debug Current File...",
        "Review and run the selected Launch configuration bound to this exact file", 1);
    register_file_target("programming.test.file", "Test Current File...",
        "Review and run the selected Test configuration bound to this exact file", 2);
    const auto selection_runner_capability = [](const interaction_context_t&) {
        const auto selected = editor_selection();
        if (!selected.enabled) return selected;
        return capability_state_t::unavailable(
            "Programming commands do not interpolate source text into a shell command; configure a file-bound Task, Launch, or Test target instead");
    };
    for (const auto& action : std::array<std::array<const char*, 3>, 3>{{
            {{"programming.run.selection", "Run Selection", "Run the selected source through a registered non-shell selection provider"}},
            {{"programming.debug.selection", "Debug Selection", "Debug the selected source through a registered non-shell selection provider"}},
            {{"programming.test.selection", "Test Selection", "Test the selected source through a registered non-shell selection provider"}}}}) {
        register_action(rt, action[0], action[1], action[2], language_surfaces,
            [](const action_invocation_t&) {
                return action_handler_result_t::failed(
                    "No bounded non-shell programming selection provider is registered");
            }, selection_runner_capability, false, {}, "category.programming.tasks",
            "Programming / Run and Debug");
    }
    const auto watch_capability = [](const interaction_context_t&) {
        const auto selected = editor_selection();
        if (!selected.enabled) return selected;
        const std::string expression = code_editor_widget::selected_text(97);
        if (expression.empty() || expression.size() > 96)
            return capability_state_t::unavailable(
                "Select one debugger expression no longer than 96 bytes");
        if (expression.find('\n') != std::string::npos || expression.find('\r') != std::string::npos)
            return capability_state_t::unavailable(
                "Select one single-line debugger expression");
        if (debugger_engine::g_state.target_pid == 0)
            return capability_state_t::unavailable("Attach the debugger to a process first");
        if (debugger_engine::g_state.status.load(std::memory_order_acquire) !=
                debugger_engine::dbg_status_t::paused)
            return capability_state_t::unavailable(
                "Pause the debugger before evaluating a source expression");
        const auto source = source_debug_service::snapshot();
        if (!source || source->target_pid != debugger_engine::g_state.target_pid ||
            source->target_key.empty())
            return capability_state_t::unavailable(
                "Wait for the source-debug target context to match the attached process");
        return capability_state_t::available();
    };
    register_action(rt, "debug.selection.watch", "Add Selection to Watch",
        "Persist the bounded selected expression, queue authoritative evaluation, and open Watches",
        language_surfaces,
        [](const action_invocation_t&) {
            const std::string expression = code_editor_widget::selected_text(97);
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.debug.watches"));
            if (!opened.ok())
                return action_handler_result_t::failed(opened.detail);
            const int index = debugger_engine::add_watch(expression);
            if (index < 0)
                return action_handler_result_t::failed(
                    "The debugger rejected the selected watch expression");
            const auto scheduled = schedule_debugger_expression_evaluation(
                expression, index, "debug.selection.watch", "Evaluate persistent watch");
            if (!scheduled.success) {
                static_cast<void>(debugger_engine::remove_watch(index));
                return scheduled;
            }
            return scheduled;
        }, watch_capability, true, {}, "category.programming.debug",
        "Programming / Source Debugging");
    register_action(rt, "debug.selection.evaluate", "Evaluate Selection",
        "Queue an ephemeral one-shot debugger evaluation without creating a persistent watch",
        language_surfaces,
        [](const action_invocation_t&) {
            const std::string expression = code_editor_widget::selected_text(97);
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.programming.source_debug_console"));
            if (!opened.ok())
                return action_handler_result_t::failed(opened.detail);
            const auto scheduled = schedule_debugger_expression_evaluation(
                expression, -1, "debug.selection.evaluate", "Evaluate source selection");
            return scheduled;
        }, watch_capability, false, {}, "category.programming.debug",
        "Programming / Source Debugging");

    const auto register_ai_selection = [&](const char* id, const char* label,
            const char* instruction) {
        register_action(rt, id, label, instruction, language_surfaces,
            [instruction](const action_invocation_t&) {
                return send_editor_selection_to_ai(instruction);
            }, [](const interaction_context_t&) { return editor_selection(); },
            false, {}, "category.programming.ai", "Programming / AI");
    };
    register_ai_selection("editor.ai.explain", "AI: Explain Selection",
        "Explain this source selection, including behavior, assumptions, edge cases, and security implications.");
    register_ai_selection("editor.ai.refactor", "AI: Refactor Selection",
        "Propose a production-grade refactor for this source selection. Return changes for reviewed editor hunks; do not apply them directly.");
    register_ai_selection("editor.ai.fix", "AI: Fix Selection",
        "Find concrete defects in this source selection and propose a minimal production-grade fix for reviewed editor hunks.");
    register_ai_selection("editor.ai.generate_tests", "AI: Generate Tests for Selection",
        "Generate comprehensive tests for this source selection, covering success, boundary, failure, cancellation, and concurrency behavior where applicable.");

    const auto pending_review_capability = [](const interaction_context_t&) {
        if (!code_editor_widget::has_pending_review_hunks())
            return capability_state_t::unavailable("No reviewed AI diff is active");
        return capability_state_t::available();
    };
    const auto retained_hunk_identity = [&rt] {
        return rt.editor_hunk_target_explicit
            ? rt.editor_hunk_target
            : code_editor_widget::selected_review_hunk_identity();
    };
    const auto pending_hunk_capability = [retained_hunk_identity](
            const interaction_context_t&) {
        const auto identity = retained_hunk_identity();
        if (!identity.valid())
            return capability_state_t::unavailable(
                "Select a pending AI review hunk first");
        if (identity.document_id != code_editor_widget::active_document_id())
            return capability_state_t::unavailable(
                "The retained AI hunk belongs to another editor document");
        return code_editor_widget::resolve_review_hunk(identity, true) >= 0
            ? capability_state_t::available()
            : capability_state_t::unavailable(
                "The retained AI hunk changed or was already resolved");
    };
    const auto register_hunk_action = [&](const char* id, const char* label, bool accept) {
        register_action(rt, id, label,
            accept ? "Accept the retained revision-bound AI hunk"
                   : "Reject the retained revision-bound AI hunk",
            language_surfaces,
            [retained_hunk_identity, accept](const action_invocation_t&) {
                const auto identity = retained_hunk_identity();
                const int index = code_editor_widget::resolve_review_hunk(identity, true);
                const bool changed = accept ? code_editor_widget::accept_hunk(index)
                                            : code_editor_widget::reject_hunk(index);
                return changed ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(
                        "The retained AI hunk changed before the review action executed");
            }, pending_hunk_capability, true, {}, "category.programming.ai",
            "Programming / AI Review");
    };
    register_hunk_action("editor.ai.accept_hunk", "Accept AI Hunk", true);
    register_hunk_action("editor.ai.reject_hunk", "Reject AI Hunk", false);
    register_action(rt, "editor.ai.previous_pending_hunk", "Previous Pending AI Hunk",
        "Select, focus, and reveal the previous pending hunk in the exact active AI proposal, wrapping once at the beginning",
        language_surfaces,
        [](const action_invocation_t&) {
            return code_editor_widget::select_previous_pending_hunk()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "No pending AI review hunk could be selected");
        }, pending_review_capability, false, {}, "category.programming.ai",
        "Programming / AI Review");
    register_action(rt, "editor.ai.next_pending_hunk", "Next Pending AI Hunk",
        "Select, focus, and reveal the next pending hunk in the exact active AI proposal, wrapping once at the end",
        language_surfaces,
        [](const action_invocation_t&) {
            return code_editor_widget::select_next_pending_hunk()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "No pending AI review hunk could be selected");
        }, pending_review_capability, false, {}, "category.programming.ai",
        "Programming / AI Review");
    const auto register_current_hunk_action = [&](const char* id,
            const char* label, const char* description, const char* retained_action) {
        register_action(rt, id, label, description,
            language_surfaces,
            [retained_action](const action_invocation_t& invocation) {
                const auto identity = code_editor_widget::selected_review_hunk_identity();
                const int index = code_editor_widget::resolve_review_hunk(identity, true);
                if (index < 0)
                    return action_handler_result_t::failed(
                        "The selected AI hunk changed before the decision executed");
                const auto result = execute_editor_hunk_action(
                    index, retained_action, invocation.source);
                return result.executed()
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.message.empty()
                        ? "The selected AI hunk decision was not executed"
                        : result.message);
            }, pending_hunk_capability, true, {}, "category.programming.ai",
            "Programming / AI Review");
    };
    register_current_hunk_action("editor.ai.accept_current_hunk",
        "Accept Current AI Hunk",
        "Accept the keyboard-selected hunk in the exact active AI proposal",
        "editor.ai.accept_hunk");
    register_current_hunk_action("editor.ai.reject_current_hunk",
        "Reject Current AI Hunk",
        "Reject the keyboard-selected hunk in the exact active AI proposal",
        "editor.ai.reject_hunk");
    register_action(rt, "editor.ai.accept_all", "Accept All AI Hunks",
        "Accept every pending hunk in the active revision-bound AI proposal",
        language_surfaces,
        [](const action_invocation_t&) {
            code_editor_widget::accept_all();
            return action_handler_result_t::completed();
        }, [pending_review_capability](const interaction_context_t& context) {
            return pending_review_capability(context);
        }, true, {}, "category.programming.ai", "Programming / AI Review");
    register_action(rt, "editor.ai.reject_all", "Reject All AI Hunks",
        "Reject every pending hunk in the active revision-bound AI proposal",
        language_surfaces,
        [](const action_invocation_t&) {
            code_editor_widget::reject_all();
            return action_handler_result_t::completed();
        }, [pending_review_capability](const interaction_context_t& context) {
            return pending_review_capability(context);
        }, true, {}, "category.programming.ai", "Programming / AI Review");

    auto source_breakpoint_capability = [](const interaction_context_t&) {
		const auto document = code_editor_widget::document_state();
		if (!document.active || document.filepath.empty())
			return capability_state_t::unavailable(
				"Open a path-backed source document first");
		const auto source = source_debug_service::snapshot();
		if (!source || source->target_key.empty())
			return capability_state_t::unavailable(
				"Open an analysis workspace or attach a target first");
		if (source->operation_pending)
			return capability_state_t::unavailable(
				"A source-debug operation is already running in Task Center");
		return capability_state_t::available();
	};
    register_action(rt, "debug.source.toggle_breakpoint", "Toggle Source Breakpoint",
		"Persist or remove the exact file:line breakpoint definition and bind it through PDB source records",
		all_surfaces,
		[](const action_invocation_t&) {
			const auto document = code_editor_widget::document_state();
			std::string error;
			return source_debug_service::request_toggle(document.filepath,
				static_cast<std::uint32_t>((std::max)(0, document.caret_line) + 1), &error)
				? action_handler_result_t::completed()
				: action_handler_result_t::failed(std::move(error));
		}, source_breakpoint_capability, false, {},
		"category.programming.debug", "Programming / Source Debugging");
    register_action(rt, "debug.source.open_mixed", "Open Mixed Source / Assembly",
		"Open the dockable source breakpoint, exact source excerpt and live assembly surface",
		menu_surfaces | action_surface_t::toolbar | action_surface_t::context_menu,
		[](const action_invocation_t&) {
			const auto opened = application_views::open_or_focus(
				stable_view_id_t("view.debug.source"));
			return opened.ok() ? action_handler_result_t::completed()
				: action_handler_result_t::failed(opened.detail);
		}, {}, false, {}, "category.programming.debug",
		"Programming / Source Debugging");
    register_action(rt, "debug.source.rebind", "Rebind Source Breakpoints",
		"Re-enumerate loaded modules and bind every persistent file:line definition against immutable PDB source records",
		menu_surfaces | action_surface_t::toolbar | action_surface_t::context_menu,
		[](const action_invocation_t&) {
			std::string error;
			return source_debug_service::request_rebind(&error)
				? action_handler_result_t::completed()
				: action_handler_result_t::failed(std::move(error));
		}, [](const interaction_context_t&) {
			const auto source = source_debug_service::snapshot();
			if (!source || source->target_key.empty())
				return capability_state_t::unavailable(
					"Open an analysis workspace or attach a target first");
			return source->operation_pending
				? capability_state_t::unavailable(
					"A source-debug operation is already running in Task Center")
				: capability_state_t::available();
		}, false, {}, "category.programming.debug",
		"Programming / Source Debugging");

    register_action(rt, "programming.result.open", "Open Source Location",
        "Open the retained provider result at its exact line and column",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return action_handler_result_t::failed(current.disabled_reason);
            return aida::editor::language_service::open_location(
                rt.programming_result.location)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The retained source location could not be opened");
        }, [&rt](const interaction_context_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return current;
            return rt.programming_result.location.file_path.empty()
                ? capability_state_t::unavailable("The retained result has no source location")
                : capability_state_t::available();
        }, false, {}, "category.programming.language.result", "Programming / Provider Result");
    register_action(rt, "programming.result.copy_location", "Copy Location",
        "Copy the exact provider-backed file, line, and column",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return action_handler_result_t::failed(current.disabled_reason);
            const auto& location = rt.programming_result.location;
            const std::string text = location.file_path + ":" +
                std::to_string(location.line) + ":" + std::to_string(location.column);
            ImGui::SetClipboardText(text.c_str());
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return current;
            return rt.programming_result.location.file_path.empty()
                ? capability_state_t::unavailable("The retained result has no source location")
                : capability_state_t::available();
        }, false, {}, "category.programming.language.result", "Programming / Provider Result");
    register_action(rt, "programming.result.copy_path", "Copy File Path",
        "Copy the provider-backed source path",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return action_handler_result_t::failed(current.disabled_reason);
            ImGui::SetClipboardText(rt.programming_result.location.file_path.c_str());
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return current;
            return rt.programming_result.location.file_path.empty()
                ? capability_state_t::unavailable("The retained result has no source path")
                : capability_state_t::available();
        }, false, {}, "category.programming.language.result", "Programming / Provider Result");
    register_action(rt, "programming.result.copy_preview", "Copy Preview",
        "Copy the bounded source preview published by the provider",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return action_handler_result_t::failed(current.disabled_reason);
            ImGui::SetClipboardText(rt.programming_result.location.preview.c_str());
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return current;
            return rt.programming_result.location.preview.empty()
                ? capability_state_t::unavailable("The provider published no source preview")
                : capability_state_t::available();
        }, false, {}, "category.programming.language.result", "Programming / Provider Result");
    register_action(rt, "programming.result.send_to_ai", "Send to AI Chat",
        "Send the bounded provider-backed location and preview to AI Chat with provenance",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return action_handler_result_t::failed(current.disabled_reason);
            return aida::editor::language_service::send_location_to_ai(
                rt.programming_result.location, rt.programming_result.provenance)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The retained result could not be sent to AI Chat");
        }, [&rt](const interaction_context_t&) {
            const auto current = programming_result_capability(rt.programming_result);
            if (!current.enabled)
                return current;
            return rt.programming_result.location.file_path.empty()
                ? capability_state_t::unavailable("The retained result has no source evidence")
                : capability_state_t::available();
        }, false, {}, "category.programming.language.result", "Programming / Provider Result");

    register_action(rt, "analysis.navigate.back", "Analysis Back",
        "Restore the previous global analysis document and exact selection",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.navigate.back", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            disasm_view::navigate_back(context);
            return action_handler_result_t::completed();
        }), retained_or_capability("analysis.navigate.back",
            [](const interaction_context_t&) { return analysis_history_capability(false); }),
        false, retained_check_state("analysis.navigate.back"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.forward", "Analysis Forward",
        "Restore the next global analysis document and exact selection",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.navigate.forward", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            disasm_view::navigate_forward(context);
            return action_handler_result_t::completed();
        }), retained_or_capability("analysis.navigate.forward",
            [](const interaction_context_t&) { return analysis_history_capability(true); }),
        false, retained_check_state("analysis.navigate.forward"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.goto", "Go to Address...",
        "Open the canonical Disassembly address or symbol navigation field",
        menu_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto opened = open_analysis_view("document.disassembly");
            if (!opened.success)
                return opened;
            return disasm_view::request_goto(context)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The selected analysis workspace has no Disassembly view state");
        }, [](const interaction_context_t&) { return analysis_workspace_capability(); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.modify.rebase", "Rebase Analysis Image...",
        "Set the presentation image base for the selected static analysis workspace",
        all_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            std::string error;
            return disasm_view::request_rebase(selected_analysis_context(), &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }, [](const interaction_context_t&) { return analysis_rebase_capability(); },
        false, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.export.listing", "Export Disassembly Listing...",
        "Export the current bounded disassembly listing through the background task runtime",
        all_surfaces,
        retained_or_handler("analysis.export.listing", [](const action_invocation_t&) {
            std::string error;
            return disasm_view::request_listing_export(selected_analysis_context(), &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }), retained_or_capability("analysis.export.listing",
            [](const interaction_context_t&) {
                return analysis_listing_export_capability();
            }), false, retained_check_state("analysis.export.listing"),
        "category.analysis.export", "Analysis / Export");
    register_action(rt, "analysis.navigate.follow", "Follow Target / Open Selection",
        "Follow a selected direct target, or open the selected analysis address in Disassembly",
        all_surfaces,
        retained_or_handler("analysis.navigate.follow", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed(
                    "The analysis selection no longer has an address");
            const auto target = selected_analysis_direct_target(context);
            disasm_view::goto_address(target.value_or(
                disasm_view::runtime_address(context, *address).value_or(address->value)), context);
            return open_analysis_view("document.disassembly");
        }), retained_or_capability("analysis.navigate.follow",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        false, retained_check_state("analysis.navigate.follow"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.proximity.drill", "Drill into Selected Proximity Node",
        "Make the selected Proximity node the new graph root",
        all_surfaces,
        [](const action_invocation_t&) {
            return analysis_relationship_views::proximity::drill_selected()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The selected Proximity node could not become the graph root");
        }, [](const interaction_context_t&) {
            return analysis_relationship_views::proximity::selected_drill_capability();
        }, false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.disassembly", "Open Selection in Disassembly",
        "Open and focus the selected analysis address in Disassembly",
        all_surfaces,
        retained_or_handler("analysis.navigate.disassembly", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            disasm_view::goto_address(runtime, context);
            return open_analysis_view("document.disassembly");
        }), retained_or_capability("analysis.navigate.disassembly",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        false, retained_check_state("analysis.navigate.disassembly"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.graph", "Open Selection in Graph",
        "Build and focus the control-flow graph for the selected function",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.navigate.graph", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            const auto function = disasm_view::enclosing_function_start(runtime, context);
            if (function == 0)
                return action_handler_result_t::failed("No recovered function contains the selected address");
            cfg_view::build_cfg(context, function);
            return open_analysis_view("document.graph");
        }), retained_or_capability("analysis.navigate.graph",
            [](const interaction_context_t&) { return analysis_graph_capability(); }),
        false, retained_check_state("analysis.navigate.graph"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.toggle_graph_text", "Toggle Graph / Text View",
        "Switch the selected function between graph and disassembly representations",
        menu_surfaces,
        [](const action_invocation_t& invocation) {
            const auto context = selected_analysis_context();
            if (invocation.context.active_view.value() == "document.graph") {
                const auto address = selected_analysis_address(context);
                if (address) {
                    const auto runtime = disasm_view::runtime_address(
                        context, *address).value_or(address->value);
                    disasm_view::goto_address(runtime, context);
                }
                return open_analysis_view("document.disassembly");
            }
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed(
                    "The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(
                context, *address).value_or(address->value);
            const auto function = disasm_view::enclosing_function_start(runtime, context);
            if (function == 0)
                return action_handler_result_t::failed(
                    "No recovered function contains the selected address");
            cfg_view::build_cfg(context, function);
            return open_analysis_view("document.graph");
        }, [](const interaction_context_t& context) {
            return context.active_view.value() == "document.graph"
                ? capability_state_t::available()
                : analysis_selection_capability();
        }, false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.pseudocode", "Open Selection in Pseudocode",
        "Decompile and focus the function containing the selected address",
        all_surfaces,
        retained_or_handler("analysis.navigate.pseudocode", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            const auto function = disasm_view::enclosing_function_start(runtime, context);
            if (function == 0)
                return action_handler_result_t::failed("No recovered function contains the selected address");
            pseudocode_view::request_decompile(context, function, false);
            return open_analysis_view("document.pseudocode");
        }), retained_or_capability("analysis.navigate.pseudocode",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        false, retained_check_state("analysis.navigate.pseudocode"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.xrefs", "Cross References to Selection",
        "Open references for the selected analysis address",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.navigate.xrefs", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            disasm_view::open_xrefs(runtime, context);
            const auto view = open_analysis_view("document.disassembly");
            if (!view.success)
                return view;
            return open_analysis_view("view.analysis.references");
        }), retained_or_capability("analysis.navigate.xrefs",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        false, retained_check_state("analysis.navigate.xrefs"),
        "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.modify.rename", "Rename Analysis Symbol...",
        "Rename the selected address through the reversible analysis overlay",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.modify.rename", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            rename_dialog::open(context, *address);
            return open_analysis_view("document.disassembly");
        }), retained_or_capability("analysis.modify.rename",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.rename"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.comment", "Edit Analysis Comment...",
        "Add or edit the selected address comment through the reversible overlay",
        all_surfaces,
        retained_or_handler("analysis.modify.comment", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            comment_dialog::open(context, *address);
            return open_analysis_view("document.disassembly");
        }), retained_or_capability("analysis.modify.comment",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.comment"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.bookmark", "Bookmark Analysis Selection",
        "Persist a bookmark for the selected address in the reversible overlay",
        all_surfaces,
        retained_or_handler("analysis.modify.bookmark", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            char label[48]{};
            std::snprintf(label, sizeof(label), "Bookmark 0x%llX",
                static_cast<unsigned long long>(runtime));
            return disasm_view::queue_bookmark(context, *address, label)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The reversible overlay rejected the bookmark request");
        }), retained_or_capability("analysis.modify.bookmark",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.bookmark"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.debug.breakpoint", "Toggle Breakpoint at Selection",
        "Toggle a software breakpoint at the selected live-process analysis address",
        all_surfaces,
        retained_or_handler("analysis.debug.breakpoint", [](const action_invocation_t&) {
            const auto location = selected_analysis_debug_location();
            if (!location)
                return action_handler_result_t::failed(
                    "The analysis selection is not owned by a live process workspace");
            std::string error;
            return debugger_view::queue_toggle_breakpoint(
                location->debugger_context, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }), retained_or_capability("analysis.debug.breakpoint",
            [](const interaction_context_t&) {
                return analysis_debug_mutation_capability(true);
            }), true, retained_check_state("analysis.debug.breakpoint"),
        "category.analysis.debug", "Analysis / Debug");
    register_action(rt, "analysis.debug.run_to_cursor", "Run to Cursor",
        "Continue the paused debugger until the selected live-process analysis address",
        all_surfaces,
        [](const action_invocation_t&) {
            const auto location = selected_analysis_debug_location();
            if (!location)
                return action_handler_result_t::failed(
                    "The analysis selection is not owned by a live process workspace");
            std::string error;
            return debugger_view::queue_run_to_address(
                location->debugger_context, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }, [](const interaction_context_t&) {
            return analysis_debug_mutation_capability(false);
        }, false, {}, "category.analysis.debug", "Analysis / Debug");
    register_action(rt, "analysis.modify.retype", "Set Analysis Type...",
        "Apply a canonical type through the reversible overlay",
        all_surfaces,
        retained_or_handler("analysis.modify.retype", [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed(
                    "The analysis selection no longer has an address");
            std::string error;
            if (!types_hub_view::stage_type_application(context, *address, &error))
                return action_handler_result_t::failed(error);
            return open_analysis_view("view.types.structures");
        }), retained_or_capability("analysis.modify.retype",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.retype"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.overlay.undo", "Undo Analysis Overlay",
        "Undo the latest rename, comment, type, bookmark, or static patch transaction",
        all_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            return disasm_view::queue_overlay_undo(context)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The reversible analysis overlay rejected the undo request");
        }, [](const interaction_context_t&) {
            return analysis_overlay_history_capability(false);
        }, true, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.overlay.redo", "Redo Analysis Overlay",
        "Redo the next rename, comment, type, bookmark, or static patch transaction",
        all_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            return disasm_view::queue_overlay_redo(context)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The reversible analysis overlay rejected the redo request");
        }, [](const interaction_context_t&) {
            return analysis_overlay_history_capability(true);
        }, true, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.patch", "Patch Bytes or Instruction...",
        "Open the reviewed runtime or reversible static-overlay patch workflow at the selected instruction",
        all_surfaces | action_surface_t::toolbar,
        retained_or_handler("analysis.modify.patch", [](const action_invocation_t&) {
            std::string error;
            return disasm_view::open_selected_patch_review(
                disasm_view::static_patch_mode_t::bytes, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }), retained_or_capability("analysis.modify.patch",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.patch"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.nop", "Stage NOP Fill...",
        "Review a runtime or reversible static-overlay NOP replacement at the selected instruction",
        all_surfaces,
        retained_or_handler("analysis.modify.nop", [](const action_invocation_t&) {
            std::string error;
            return disasm_view::open_selected_patch_review(
                disasm_view::static_patch_mode_t::nop_fill, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }), retained_or_capability("analysis.modify.nop",
            [](const interaction_context_t&) { return analysis_selection_capability(); }),
        true, retained_check_state("analysis.modify.nop"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.assemble", "Assemble Instruction...",
        "Assemble and review an instruction only when a validated reusable assembler provider is registered",
        all_surfaces,
        retained_or_handler("analysis.modify.assemble", [](const action_invocation_t&) {
            return action_handler_result_t::failed(
                "No reusable standalone assembler provider is registered; Zydis encoding is enabled as a dependency, but the UI has no validated assembly parser/provider. Use reviewed Patch Bytes or NOP Fill.");
        }), retained_or_capability("analysis.modify.assemble", [](const interaction_context_t&) {
            const auto selection = analysis_selection_capability();
            return selection.enabled
                ? capability_state_t::unavailable(
                    "No reusable standalone assembler provider is registered; use reviewed Patch Bytes or NOP Fill.")
                : selection;
        }), true, retained_check_state("analysis.modify.assemble"),
        "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "types.reconstruction.copy_declaration",
        "Copy Reconstructed C++ Declaration",
        "Generate and copy the current Structure Reconstruction declaration",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto result = struct_recon_view::copy_current_declaration();
            return result.completed ? action_handler_result_t::completed()
                                    : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
            return struct_recon_view::has_current_structure()
                ? capability_state_t::available()
                : capability_state_t::unavailable("Reconstruct or load a structure first");
        }, false, {}, "category.types.reconstruction", "Types / Reconstruction");
    register_action(rt, "types.reconstruction.declare_apply",
        "Declare and Apply Reconstructed Structure",
		"Review the generated declaration and base application before one reversible overlay transaction",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto result = struct_recon_view::declare_and_apply_current();
            return result.completed ? action_handler_result_t::completed()
                                    : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
            if (!struct_recon_view::has_current_structure())
                return capability_state_t::unavailable("Reconstruct or load a structure first");
            return analysis_workspace_capability();
        }, true, {}, "category.types.reconstruction", "Types / Reconstruction");

    register_action(rt, "edit.undo", "Undo", "Undo the last editor change", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::undo, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::undo, context); }, true);
    register_action(rt, "edit.redo", "Redo", "Redo the last undone editor change", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::redo, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::redo, context); }, true);
    register_action(rt, "edit.cut", "Cut", "Cut the selected text", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::cut, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::cut, context); }, true);
    register_action(rt, "edit.copy", "Copy", "Copy the selected text", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::copy, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::copy, context); });
    register_action(rt, "edit.paste", "Paste", "Paste text at the caret", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::paste, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::paste, context); }, true);
    register_action(rt, "edit.delete", "Delete", "Delete the selection or the character at the caret", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::delete_selection, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::delete_selection, context); }, true);
    register_action(rt, "edit.select_all", "Select All", "Select the entire document", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::select_all, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::select_all, context); });
    register_action(rt, "edit.find", "Find", "Find text in the active document", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::find, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::find, context); });
    register_action(rt, "edit.replace", "Replace", "Find and replace text in the active document", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::replace, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::replace, context); });
    register_action(rt, "edit.goto_line", "Go to Line...", "Navigate to a line in the active document", all_surfaces,
		[](const action_invocation_t& invocation) { return execute_focused_edit(
			focused_edit_operation_t::go_to, invocation); },
		[](const interaction_context_t& context) { return focused_edit_capability(
			focused_edit_operation_t::go_to, context); });
    const auto document_action = [](code_editor_widget::document_action_t action) {
        return [action](const action_invocation_t&) {
            return code_editor_widget::request_document_action(action)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(code_editor_widget::last_error());
        };
    };
    register_action(rt, "edit.select_word", "Select Word", "Select the word at the caret",
        context_surfaces, document_action(code_editor_widget::document_action_t::select_word),
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.select_line", "Select Line", "Select the current source line",
        context_surfaces, document_action(code_editor_widget::document_action_t::select_line),
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.copy_line", "Copy Line", "Copy the current source line",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::copy_line),
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.copy_path", "Copy File Path", "Copy the active source file path",
        context_surfaces, document_action(code_editor_widget::document_action_t::copy_path),
        [](const interaction_context_t&) {
            const auto editor = code_editor_widget::document_state();
            return editor.active && !editor.filepath.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("The active document has no file path");
        });
    register_action(rt, "edit.copy_relative_path", "Copy Workspace-Relative Path",
        "Copy the active source file path relative to its Project Explorer root",
        context_surfaces,
        [](const action_invocation_t&) {
            const auto editor = code_editor_widget::document_state();
            const auto relative = workspace_relative_path(editor.filepath);
            if (!relative)
                return action_handler_result_t::failed(
                    "The active file is not inside an open Project Explorer root");
            ImGui::SetClipboardText(relative->c_str());
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            const auto editor = code_editor_widget::document_state();
            if (!editor.active || editor.filepath.empty())
                return capability_state_t::unavailable("The active document has no file path");
            return workspace_relative_path(editor.filepath)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "The active file is not inside an open Project Explorer root");
        });
    register_action(rt, "editor.add_to_chat", "Add File Context to AI Chat",
        "Send bounded source identity and workspace-relative path to AI Chat without copying file contents",
        context_surfaces,
        [](const action_invocation_t&) {
            const auto editor = code_editor_widget::document_state();
            return send_programming_path_to_ai(editor.filepath, editor.filename,
                "Code Editor");
        }, [](const interaction_context_t&) {
            const auto editor = code_editor_widget::document_state();
            return editor.active && !editor.filepath.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "Save this document to a file before sending its identity to AI Chat");
        });
    register_action(rt, "editor.reveal_in_explorer", "Reveal in Project Explorer",
        "Expand the active file's workspace path and select it in Project Explorer",
        context_surfaces,
        [](const action_invocation_t&) {
            const auto editor = code_editor_widget::document_state();
            if (!file_browser::reveal_path(editor.filepath))
                return action_handler_result_t::failed(
                    "The active file is not inside an open Project Explorer root");
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.project_explorer"));
            return opened.ok() ? action_handler_result_t::completed()
                : action_handler_result_t::failed(opened.detail);
        }, [](const interaction_context_t&) {
            const auto editor = code_editor_widget::document_state();
            if (!editor.active || editor.filepath.empty())
                return capability_state_t::unavailable("The active document has no file path");
            return workspace_relative_path(editor.filepath)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "The active file is not inside an open Project Explorer root");
        });
    register_action(rt, "edit.duplicate_line", "Duplicate Line", "Duplicate the current source line",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::duplicate_line),
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.delete_line", "Delete Line", "Delete the current source line",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::delete_line),
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.move_line_up", "Move Line Up", "Move the current source line upward",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::move_line_up),
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.move_line_down", "Move Line Down", "Move the current source line downward",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::move_line_down),
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.toggle_line_comment", "Toggle Line Comment",
        "Add or remove the active language's line comment marker",
        context_surfaces | action_surface_t::shortcut,
        document_action(code_editor_widget::document_action_t::toggle_line_comment),
        [](const interaction_context_t&) {
            if (!code_editor_widget::document_state().active)
                return capability_state_t::unavailable("Open or create a text document first");
            return code_editor_widget::document_capabilities().line_comment
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "The active language has no supported line-comment syntax");
        }, true);
    register_action(rt, "edit.trim_trailing_whitespace", "Trim Trailing Whitespace",
        "Remove trailing spaces and tabs from every source line", context_surfaces,
        document_action(code_editor_widget::document_action_t::trim_trailing_whitespace),
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.preferences", "Preferences", "Open AiDA settings", menu_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_settings)
                return action_handler_result_t::failed("Settings are unavailable");
            rt.shell.open_settings();
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            return rt.shell.open_settings
                ? capability_state_t::available()
                : capability_state_t::unavailable("Settings are unavailable");
        });
    register_action(rt, "shell.toggle_maximize", "Toggle Window Maximize",
        "Maximize or restore the native AiDA IDE window", menu_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.toggle_maximize)
                return action_handler_result_t::failed("Native window controls are unavailable");
            rt.shell.toggle_maximize();
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            return rt.shell.toggle_maximize
                ? capability_state_t::available()
                : capability_state_t::unavailable("Native window controls are unavailable");
        }, false, {}, "category.view", "View");
    register_action(rt, "analysis.decompile_or_focus_pseudocode", "Decompile / Focus Pseudocode",
        "Decompile the active analysis selection or focus its existing Pseudocode document",
        menu_surfaces | action_surface_t::toolbar,
        [&rt](const action_invocation_t&) {
            return rt.shell.decompile_or_focus_pseudocode
                ? rt.shell.decompile_or_focus_pseudocode()
                : action_handler_result_t::failed("No analysis decompiler context is available");
        }, [&rt](const interaction_context_t&) {
            return rt.shell.decompile_or_focus_pseudocode_capability
                ? rt.shell.decompile_or_focus_pseudocode_capability()
                : capability_state_t::unavailable("No analysis decompiler context is available");
        }, false, {}, "category.analysis.navigate", "Analysis / Navigate");

    application_views::initialize();
    const auto canonical_view_capability = [](const stable_view_id_t& target,
                                              const interaction_context_t& context) {
        const auto* descriptor = application_views::registry().find_descriptor(target);
        if (!descriptor)
            return capability_state_t::unavailable("The view is no longer registered");
        if (application_views::is_open(target) && !descriptor->closeable)
            return capability_state_t::unavailable("This required view cannot be closed");
        return application_views::registry().evaluate(target, context);
    };
    const auto canonical_view_check = [](const stable_view_id_t& target) {
        return application_views::is_open(target)
            ? action_check_state_t::checked : action_check_state_t::unchecked;
    };
    const auto toggle_canonical_view = [&rt](const stable_view_id_t& target,
                                             const char* compatibility_action) {
        const auto result = application_views::is_open(target)
            ? application_views::close(target)
            : application_views::open_or_focus(target);
        if (!result.ok())
            return action_handler_result_t::failed(result.detail);
        if (rt.shell.persist_workspace)
            rt.shell.persist_workspace();
        if (compatibility_action && rt.shell.action_executed)
            rt.shell.action_executed(compatibility_action);
        return action_handler_result_t::completed();
    };
    auto register_view = [&](const char* id, const char* label, const char* target_view,
                             action_surface_t surfaces = action_surface_t::shortcut) {
        register_action(rt, id, label, "Compatibility launcher for the canonical dockable IDE view",
            surfaces,
            [toggle_canonical_view, id,
             target = stable_view_id_t(target_view)](const action_invocation_t&) {
                return toggle_canonical_view(target, id);
            }, [canonical_view_capability,
                target = stable_view_id_t(target_view)](const interaction_context_t& context) {
                return canonical_view_capability(target, context);
            }, false, [canonical_view_check,
                       target = stable_view_id_t(target_view)](const interaction_context_t&) {
                return canonical_view_check(target);
            });
    };
    register_view("view.explorer", "Toggle Explorer", "view.project_explorer", menu_surfaces);
    register_view("view.chat", "Toggle Chat", "view.ai_chat", menu_surfaces);
    register_view("view.output", "Toggle Output", "view.output", menu_surfaces);
    register_view("view.editor", "Editor", "document.code");
    register_view("view.disassembly", "Disassembly", "document.disassembly");
    register_view("view.hex", "Hex", "document.hex");
    register_view("view.pseudocode", "Pseudocode", "document.pseudocode");
    register_view("view.graph", "Graph", "document.graph");
    register_view("view.binary_map", "Binary Map", "view.analysis.binary_map");
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    register_view("view.test_lab", "Test Lab", "view.test_lab", menu_surfaces);
#endif

    application_views::registry().for_each_descriptor([&](const view_descriptor_t& view) {
        const std::string stable_id = compose_view_action_id(view.id);
        const std::string label = std::string("Toggle ") + view.display_name;
        const std::string category = std::string("View / ") + application_views::category_label(view.category);
        register_action(rt, stable_id.c_str(), label.c_str(), "Open, focus, or close this dockable IDE view",
            action_surface_t::application_menu | action_surface_t::command_palette |
                action_surface_t::accessibility,
            [id = view.id, toggle_canonical_view](const action_invocation_t&) {
                return toggle_canonical_view(id, nullptr);
            },
            [id = view.id, canonical_view_capability](const interaction_context_t& context) {
                return canonical_view_capability(id, context);
            }, false,
            [id = view.id, canonical_view_check](const interaction_context_t&) {
                return canonical_view_check(id);
            }, view_category_id(view.category), category.c_str());

        std::string focus_id = "view.focus.";
        focus_id.append(view.id.value());
        const std::string focus_label = std::string("Focus ") + view.display_name;
        action_surface_t focus_surfaces = action_surface_t::application_menu |
            action_surface_t::command_palette | action_surface_t::accessibility;
        if (view.id.value() == "view.recent" ||
            view.id.value() == "view.background_tasks" ||
            view.id.value() == "view.diagnostics" ||
            view.id.value() == "view.output")
            focus_surfaces = focus_surfaces | action_surface_t::toolbar;
        if (view.id.value() == "view.programming.source_debug_console" ||
            view.id.value() == "view.analysis.references" ||
            view.id.value() == "view.analysis.deobfuscation")
            focus_surfaces = focus_surfaces | action_surface_t::shortcut;
        register_action(rt, focus_id.c_str(), focus_label.c_str(),
            "Open this IDE view if needed, then move keyboard focus to it",
            focus_surfaces,
            [id = view.id](const action_invocation_t&) {
                const auto result = application_views::open_or_focus(id);
                return result.ok()
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.detail);
            },
            [id = view.id](const interaction_context_t& context) {
                return application_views::registry().evaluate(id, context);
            }, false, {}, view_category_id(view.category), category.c_str());
    });

    register_action(rt, "view.reopen_last_closed", "Reopen Last Closed View",
        "Reopen and focus the most recently closed IDE view",
        menu_surfaces | action_surface_t::context_menu,
        [](const action_invocation_t&) {
            const auto result = application_views::reopen_last_closed();
            return result.ok()
                ? action_handler_result_t::completed(result.detail)
                : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
            return application_views::can_reopen_last_closed()
                ? capability_state_t::available()
                : capability_state_t::unavailable("No recently closed view is available");
        }, false, {}, "category.view", "View");
    register_action(rt, "view.open_default_missing", "Open Missing Default Views",
        "Reopen any closed views that belong to the default IDE shell",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto result = application_views::open_default_missing();
            return result.ok()
                ? action_handler_result_t::completed(result.detail)
                : action_handler_result_t::failed(result.detail);
        }, {}, false, {}, "category.view", "View");
    register_action(rt, "view.close_focused", "Close Focused View",
        "Close the focused dockable view without stopping its backend activity",
        action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            const auto focused = application_views::registry().focused_instance();
            if (!focused)
                return action_handler_result_t::failed("No dockable view has focus");
            const auto result = application_views::close_instance(*focused);
            return result.ok()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
            const auto focused = application_views::registry().focused_instance();
            if (!focused)
                return capability_state_t::unavailable("No dockable view has focus");
            const auto* descriptor = application_views::registry().find_descriptor(focused->view);
            if (!descriptor || !descriptor->closeable)
                return capability_state_t::unavailable("The focused view cannot be closed");
            return application_views::is_pinned(*focused)
                ? capability_state_t::unavailable("Unpin the focused view before closing it")
                : capability_state_t::available();
        }, false, {}, "category.view", "View");

    register_action(rt, "surface.close", "Close", "Close this dockable view without stopping backend activity",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? surface_operation(application_views::close_instance(surface->instance)) :
                action_handler_result_t::failed("The target view context is unavailable");
        }, surface_close_capability, false, {}, "category.view.surface", "View / Surface");
    register_action(rt, "surface.close_others", "Close Others", "Close every other closeable unpinned IDE view",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? surface_operation(application_views::close_other_instances(surface->instance)) :
                action_handler_result_t::failed("The target view context is unavailable");
        }, surface_close_others_capability, false, {}, "category.view.surface", "View / Surface");
    register_action(rt, "surface.float", "Float", "Undock this view without forcing a new position or size",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? workspace_result(workspace_layout::float_window(surface->window_name),
                "The view could not be floated") : action_handler_result_t::failed("The target view context is unavailable");
        }, [](const interaction_context_t& context) { return surface_placement_capability(context, std::nullopt); },
        false, {}, "category.view.surface", "View / Surface");
    const auto register_surface_dock = [&rt](const char* id, const char* label,
            const char* description, workspace_layout::dock_role_t role) {
        register_action(rt, id, label, description, context_surfaces,
            [role](const action_invocation_t& invocation) {
                const auto* surface = view_surface(invocation.context);
                return surface ? workspace_result(workspace_layout::dock_window(surface->window_name, role),
                    "The view could not be moved to that dock region") :
                    action_handler_result_t::failed("The target view context is unavailable");
            }, [role](const interaction_context_t& context) {
                return surface_placement_capability(context, role);
            }, false, {}, "category.view.surface", "View / Surface");
    };
    register_surface_dock("surface.move_left", "Move Left", "Dock this view in the left navigator region", workspace_layout::dock_role_t::navigator);
    register_surface_dock("surface.move_right", "Move Right", "Dock this view in the right inspector region", workspace_layout::dock_role_t::inspector);
    register_surface_dock("surface.move_bottom", "Move Bottom", "Dock this view in the bottom output region", workspace_layout::dock_role_t::bottom);
    register_surface_dock("surface.move_center", "Move Center", "Dock this view in the central document region", workspace_layout::dock_role_t::documents);
    register_action(rt, "surface.pin", "Pin View", "Keep this view out of close and close-others operations",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? surface_operation(application_views::toggle_pin(surface->instance)) :
                action_handler_result_t::failed("The target view context is unavailable");
        }, live_surface_capability, false,
        [](const interaction_context_t& context) {
            const auto* surface = view_surface(context);
            return surface && application_views::is_pinned(surface->instance)
                ? action_check_state_t::checked : action_check_state_t::unchecked;
        }, "category.view.surface", "View / Surface");
    register_action(rt, "surface.duplicate", "Duplicate", "Create an independent second instance only when its renderer declares that safe",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? surface_operation(application_views::duplicate_instance(surface->instance)) :
                action_handler_result_t::failed("The target view context is unavailable");
        }, [](const interaction_context_t& context) {
            const auto live = live_surface_capability(context);
            if (!live.enabled) return live;
            const auto* surface = view_surface(context);
            return application_views::can_duplicate(surface->instance) ? capability_state_t::available() :
                capability_state_t::unavailable("This renderer does not declare independent duplicate state");
        }, false, {}, "category.view.surface", "View / Surface");
    register_action(rt, "surface.reset_state", "Reset View State", "Reset local scroll and ImGui open-state without changing backend data or layout",
        context_surfaces,
        [](const action_invocation_t& invocation) {
            const auto* surface = view_surface(invocation.context);
            return surface ? surface_operation(application_views::request_reset_state(surface->instance)) :
                action_handler_result_t::failed("The target view context is unavailable");
        }, [](const interaction_context_t& context) {
            const auto live = live_surface_capability(context);
            if (!live.enabled) return live;
            const auto* surface = view_surface(context);
            return application_views::can_reset_state(surface->instance) ? capability_state_t::available() :
                capability_state_t::unavailable("This view has no resettable local UI state");
        }, false, {}, "category.view.surface", "View / Surface");

    std::size_t preset_count = 0;
    const auto* presets = workspace_layout::presets(preset_count);
    const auto workspace_action_capability = [](const interaction_context_t&) {
        if (workspace_layout::node_id(workspace_layout::dock_role_t::root) == 0)
            return capability_state_t::unavailable("The DockSpace is not ready yet");
        if (workspace_layout::operation_pending()) {
            const std::string status = workspace_layout::operation_status();
            return capability_state_t::unavailable(status.empty()
                ? "A workspace layout transaction is already in progress" : status);
        }
        return capability_state_t::available();
    };
    const auto activate_workspace = [](workspace_layout::workspace_preset_t preset) {
        const auto switched = workspace_layout::switch_to(preset);
        const auto result = workspace_result(switched, "Workspace switching failed");
        if (switched != workspace_layout::workspace_request_result_t::completed &&
            switched != workspace_layout::workspace_request_result_t::unchanged)
            return result;
        const char* primary_document = preset == workspace_layout::workspace_preset_t::analysis
            ? "document.disassembly"
            : preset == workspace_layout::workspace_preset_t::programming
                ? "document.code" : nullptr;
        if (!primary_document)
            return result;
        const auto opened = application_views::open_or_focus(
            stable_view_id_t(primary_document));
        return opened.ok() ? result : action_handler_result_t::failed(opened.detail);
    };
    const auto workspace_check = [](workspace_layout::workspace_preset_t preset) {
        const auto identity = workspace_layout::active_identity();
        return identity.kind == workspace_layout::workspace_identity_kind_t::built_in &&
            identity.preset == preset
            ? action_check_state_t::checked : action_check_state_t::unchecked;
    };
    for (std::size_t index = 0; index < preset_count; ++index) {
        const auto preset = presets[index];
        if (preset.id == workspace_layout::workspace_preset_t::safe)
            continue;
        std::string id = "workspace.switch.";
        id.append(preset.stable_id);
        std::string label = "Switch to ";
        label.append(preset.display_name);
        const std::string description(preset.description);
        register_action(rt, id.c_str(), label.c_str(), description.c_str(),
            action_surface_t::application_menu | action_surface_t::command_palette |
                action_surface_t::toolbar | action_surface_t::accessibility,
            [preset, activate_workspace](const action_invocation_t&) {
                return activate_workspace(preset.id);
            }, workspace_action_capability, false,
            [preset, workspace_check](const interaction_context_t&) {
                return workspace_check(preset.id);
            }, "category.workspace", "Workspace");
    }
    const auto register_workspace_alias = [&](const char* id, const char* label,
                                               workspace_layout::workspace_preset_t preset) {
        register_action(rt, id, label,
            "Compatibility launcher for the canonical named IDE workspace",
            action_surface_t::shortcut,
            [&rt, id, preset, activate_workspace](const action_invocation_t&) {
                const auto result = activate_workspace(preset);
                if (result.success && rt.shell.action_executed)
                    rt.shell.action_executed(id);
                return result;
            }, workspace_action_capability, false,
            [preset, workspace_check](const interaction_context_t&) {
                return workspace_check(preset);
            }, "category.workspace", "Workspace");
    };
    register_workspace_alias("view.analysis", "Analysis",
        workspace_layout::workspace_preset_t::analysis);
    register_workspace_alias("view.workbench", "Workbench",
        workspace_layout::workspace_preset_t::analysis);
    register_workspace_alias("view.debugger", "Debugger",
        workspace_layout::workspace_preset_t::debugging);
    register_workspace_alias("view.network", "Network",
        workspace_layout::workspace_preset_t::network);
    register_workspace_alias("view.scan", "Scan",
        workspace_layout::workspace_preset_t::memory);
    register_workspace_alias("view.types", "Types",
        workspace_layout::workspace_preset_t::types_structures);

    register_action(rt, "workspace.lock", "Lock / Unlock Layout", "Toggle dock placement editing while preserving close and reopen",
        action_surface_t::application_menu | action_surface_t::command_palette |
            action_surface_t::context_menu | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(
                workspace_layout::set_layout_locked(!workspace_layout::layout_locked()),
                "Changing the workspace lock failed");
        }, workspace_action_capability, false,
        [](const interaction_context_t&) {
            return workspace_layout::layout_locked()
                ? action_check_state_t::checked
                : action_check_state_t::unchecked;
        }, "category.workspace", "Workspace");
    register_action(rt, "workspace.save_active", "Save Active Workspace", "Replace the active named workspace with the current dock layout and view visibility",
        action_surface_t::application_menu | action_surface_t::command_palette |
            action_surface_t::context_menu | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::save_active_user_layout(),
                "Saving the active workspace failed");
        }, [workspace_action_capability](const interaction_context_t& context) {
            const auto base = workspace_action_capability(context);
            if (!base.enabled)
                return base;
            return workspace_layout::active_identity().kind ==
                workspace_layout::workspace_identity_kind_t::user
                ? capability_state_t::available()
                : capability_state_t::unavailable("Use Save Workspace As to create a named workspace first");
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.save_as", "Save Workspace As...", "Create a named workspace derivative from the current dock layout and view visibility",
        action_surface_t::application_menu | action_surface_t::command_palette |
            action_surface_t::context_menu | action_surface_t::accessibility,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_workspace_save_as)
                return action_handler_result_t::failed("The Save Workspace As dialog is unavailable");
            rt.shell.open_workspace_save_as();
            return action_handler_result_t::completed();
        }, [&rt, workspace_action_capability](const interaction_context_t& context) {
            const auto base = workspace_action_capability(context);
            if (!base.enabled)
                return base;
            if (!workspace_layout::user_layout_catalog_ready())
                return capability_state_t::unavailable("The saved workspace catalog is still loading");
            return rt.shell.open_workspace_save_as ? capability_state_t::available() :
                capability_state_t::unavailable("The Save Workspace As dialog is unavailable");
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.save", "Save Workspace", "Save the active named workspace, or open Save Workspace As when a built-in workspace is active",
        action_surface_t::application_menu | action_surface_t::command_palette |
            action_surface_t::context_menu | action_surface_t::accessibility,
        [&rt](const action_invocation_t&) {
            if (workspace_layout::active_identity().kind ==
                workspace_layout::workspace_identity_kind_t::user)
                return workspace_result(workspace_layout::save_active_user_layout(),
                    "Saving the active workspace failed");
            if (!rt.shell.open_workspace_save_as)
                return action_handler_result_t::failed("The Save Workspace As dialog is unavailable");
            rt.shell.open_workspace_save_as();
            return action_handler_result_t::completed();
        }, [&rt, workspace_action_capability](const interaction_context_t& context) {
            const auto base = workspace_action_capability(context);
            if (!base.enabled)
                return base;
            if (workspace_layout::active_identity().kind ==
                workspace_layout::workspace_identity_kind_t::user)
                return capability_state_t::available();
            if (!workspace_layout::user_layout_catalog_ready())
                return capability_state_t::unavailable("The saved workspace catalog is still loading");
            return rt.shell.open_workspace_save_as ? capability_state_t::available() :
                capability_state_t::unavailable("The Save Workspace As dialog is unavailable");
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.load_saved", "Saved Workspaces...", "Open the named workspace catalog to load or manage a saved derivative",
        action_surface_t::application_menu | action_surface_t::command_palette |
            action_surface_t::context_menu | action_surface_t::accessibility,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_workspace_manager)
                return action_handler_result_t::failed("The Saved Workspaces manager is unavailable");
            rt.shell.open_workspace_manager();
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            return rt.shell.open_workspace_manager ? capability_state_t::available() :
                capability_state_t::unavailable("The Saved Workspaces manager is unavailable");
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.restore_builtin", "Restore Built-in Workspace", "Restore the active preset's factory layout",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::restore_builtin(workspace_layout::active_preset()),
                "Restoring the built-in workspace failed");
        }, workspace_action_capability, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.reset_current", "Reset Current Layout", "Restore the current preset's built-in layout without deleting named workspace derivatives",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::reset_current(), "Resetting the layout failed");
        }, workspace_action_capability, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.reset_all", "Reset All Layouts", "Discard every saved preset and named user layout, then activate the factory Analysis workspace",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_workspace_reset_all)
                return action_handler_result_t::failed("The Reset All Layouts review is unavailable");
            rt.shell.open_workspace_reset_all();
            return action_handler_result_t::completed();
        }, [&rt, workspace_action_capability](const interaction_context_t& context) {
            const auto base = workspace_action_capability(context);
            if (!base.enabled)
                return base;
            return rt.shell.open_workspace_reset_all ? capability_state_t::available() :
                capability_state_t::unavailable("The Reset All Layouts review is unavailable");
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.open_missing", "Open Missing Workspace Views", "Reopen views required by the active workspace",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::open_missing_views(), "Opening missing views failed");
        }, [workspace_action_capability](const interaction_context_t& context) {
            const auto base = workspace_action_capability(context);
            if (!base.enabled)
                return base;
            return workspace_layout::layout_locked()
                ? capability_state_t::unavailable("Unlock the layout before placing missing views")
                : capability_state_t::available();
        }, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.safe", "Activate Safe Layout", "Recover to the minimal known-good IDE layout",
        action_surface_t::application_menu | action_surface_t::toolbar |
            action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::activate_safe_layout(), "Safe Layout recovery failed");
        }, workspace_action_capability, false, {}, "category.workspace", "Workspace");

    const auto shell_capability = [](const std::function<void()>& callback, const char* reason) {
        return callback ? capability_state_t::available() : capability_state_t::unavailable(reason);
    };
    register_action(rt, "tools.load_binary", "Load Binary...", "Open a binary and create an analysis session",
        menu_surfaces | action_surface_t::toolbar, [&rt](const action_invocation_t&) {
            if (!rt.shell.load_binary)
                return action_handler_result_t::failed("Binary loader is unavailable");
            rt.shell.load_binary();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.load_binary, "Binary loader is unavailable");
        }, false, {}, "category.tools", "Tools");
    register_action(rt, "tools.attach_process", "Attach to Process...", "Select and attach to a running process",
        menu_surfaces | action_surface_t::toolbar, [&rt](const action_invocation_t&) {
            if (!rt.shell.attach_process)
                return action_handler_result_t::failed("Process attachment is unavailable");
            rt.shell.attach_process();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.attach_process, "Process attachment is unavailable");
        }, false, {}, "category.tools", "Tools");

    const auto network_surfaces = action_surface_t::application_menu |
        action_surface_t::toolbar | action_surface_t::command_palette |
        action_surface_t::accessibility;
    const auto register_network_operation = [&rt](
        const char* id, const char* label, const char* description,
        network_view::operational_command_t command, action_effect_t effects,
        confirmation_requirement_t confirmation, const char* consequence) {
        action_confirmation_prepare_fn_t prepare;
        action_confirmation_cancel_fn_t cancel;
        if (confirmation != confirmation_requirement_t::none) {
            prepare = [command](const action_invocation_t&) {
                std::string error;
                return network_view::prepare_operational_command_confirmation(command, &error)
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(error.empty()
                        ? "The Network confirmation target could not be retained" : error);
            };
            cancel = [command] { network_view::cancel_operational_command_confirmation(command); };
        }
        register_action_with_consequence(rt, id, label, description, network_surfaces,
            [command](const action_invocation_t&) {
                std::string error;
                return network_view::execute_operational_command(command, &error)
                    ? action_handler_result_t::completed("Network operation queued")
                    : action_handler_result_t::failed(error.empty()
                        ? "The Network operation was rejected" : error);
            }, [command](const interaction_context_t&) {
                const auto state = network_view::operational_command_capability(command);
                return state.enabled ? capability_state_t::available()
                    : capability_state_t::unavailable(state.disabled_reason.empty()
                        ? "The Network operation is unavailable" : state.disabled_reason);
            }, [command](const interaction_context_t&) {
                if (command != network_view::operational_command_t::intercept_toggle)
                    return action_check_state_t::not_checkable;
                return network_view::operational_command_capability(command).checked
                    ? action_check_state_t::checked : action_check_state_t::unchecked;
            }, effects, confirmation, consequence,
            [command](const interaction_context_t&) {
                return network_view::operational_command_capability(command).target_summary;
            }, std::move(prepare), std::move(cancel));
    };
    register_network_operation("network.capture.start", "Start Packet Capture",
        "Start driver-backed packet capture with the current PID, port, and protocol filters",
        network_view::operational_command_t::capture_start,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Starts driver-backed traffic collection");
    register_network_operation("network.capture.stop", "Stop Packet Capture",
        "Stop driver-backed packet capture without clearing retained packets",
        network_view::operational_command_t::capture_stop,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Stops traffic collection and preserves retained packets");
    register_network_operation("network.proxy.start", "Start Interception Proxy",
        "Start the configured local interception Proxy listener",
        network_view::operational_command_t::proxy_start,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Starts a local interception listener");
    register_network_operation("network.proxy.stop", "Stop Interception Proxy",
        "Stop the active local interception Proxy listener",
        network_view::operational_command_t::proxy_stop,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Stops the local interception listener");
    register_network_operation("network.proxy.history.clear", "Clear Proxy History...",
        "Review permanently clearing the complete retained Proxy exchange history",
        network_view::operational_command_t::proxy_history_clear,
        action_effect_t::application_state | action_effect_t::destructive,
        confirmation_requirement_t::explicit_confirmation,
        "Permanently removes retained requests, responses, annotations, and evidence");
    register_network_operation("network.proxy.ca_trust_repair", "Repair AiDA CA Trust...",
        "Review repairing the AiDA interception CA in the current-user trust store",
        network_view::operational_command_t::proxy_ca_trust_repair,
        action_effect_t::file_system | action_effect_t::security_sensitive,
        confirmation_requirement_t::explicit_confirmation,
        "Installs the AiDA interception root CA for controlled Camoufox traffic");
    register_network_operation("network.filters.add", "Add Network Filter Rule...",
        "Review applying the current filter draft to live driver-backed traffic policy",
        network_view::operational_command_t::filter_add,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::explicit_confirmation, "Applies a live kernel traffic policy rule");
    register_network_operation("network.filters.remove_selected", "Remove Selected Filter Rule...",
        "Review removing the exact retained network filter rule",
        network_view::operational_command_t::filter_remove_selected,
        action_effect_t::network_activity | action_effect_t::security_sensitive |
            action_effect_t::destructive,
        confirmation_requirement_t::explicit_confirmation,
        "Removes the retained live kernel traffic policy rule");
    register_network_operation("network.filters.clear", "Clear All Filter Rules...",
        "Review removing the exact retained set of network filter rules",
        network_view::operational_command_t::filter_clear,
        action_effect_t::network_activity | action_effect_t::security_sensitive |
            action_effect_t::destructive,
        confirmation_requirement_t::explicit_confirmation,
        "Removes every retained live kernel traffic policy rule");
    register_network_operation("network.intercept.toggle_enabled", "Enable / Disable Intercept",
        "Toggle interception of new Proxy exchanges while preserving held exchanges",
        network_view::operational_command_t::intercept_toggle,
        action_effect_t::network_activity | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Changes interception for newly observed Proxy exchanges");
    register_network_operation("network.keylog.launch", "Launch Target with TLS Key Logging",
        "Launch the configured executable and watch its bounded SSLKEYLOGFILE output",
        network_view::operational_command_t::keylog_launch,
        action_effect_t::live_process | action_effect_t::file_system |
            action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Launches the configured target with SSLKEYLOGFILE enabled");
    register_network_operation("network.keylog.watch", "Watch TLS Keylog File",
        "Watch the configured SSLKEYLOGFILE without launching a process",
        network_view::operational_command_t::keylog_watch,
        action_effect_t::file_system | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Reads appended TLS secrets from the configured file");
    register_network_operation("network.keylog.stop", "Stop TLS Keylog Watcher",
        "Stop the active SSLKEYLOGFILE watcher without clearing retained secrets",
        network_view::operational_command_t::keylog_stop,
        action_effect_t::application_state | action_effect_t::security_sensitive,
        confirmation_requirement_t::none, "Stops watching and preserves retained TLS secrets");
    register_network_operation("network.keylog.clear", "Clear Captured TLS Secrets...",
        "Review permanently clearing the exact retained TLS secret set",
        network_view::operational_command_t::keylog_clear,
        action_effect_t::application_state | action_effect_t::security_sensitive |
            action_effect_t::destructive,
        confirmation_requirement_t::explicit_confirmation,
        "Permanently removes retained TLS secrets used for later traffic decryption");

	const auto register_memory_scan_action = [&rt](const char* id, const char* label,
		const char* description, memory_scanner_view::scan_command_t command) {
		register_action(rt, id, label, description,
			action_surface_t::application_menu | action_surface_t::toolbar |
			action_surface_t::command_palette | action_surface_t::shortcut |
			action_surface_t::accessibility,
			[command](const action_invocation_t&) {
				const auto result = memory_scanner_view::execute_scan_command(command);
				return result.succeeded
					? action_handler_result_t::completed(result.detail)
					: action_handler_result_t::failed(result.detail);
			}, [command](const interaction_context_t&) {
				const auto state = memory_scanner_view::scan_command_capability(command);
				return state.enabled ? capability_state_t::available()
					: capability_state_t::unavailable(state.disabled_reason);
			}, false, {}, "category.memory", "Memory");
	};
	register_memory_scan_action("memory.first_scan", "First Scan",
		"Start an initial value scan using the current type, mode, value, range, and live target",
		memory_scanner_view::scan_command_t::first_scan);
	register_memory_scan_action("memory.next_scan", "Next Scan",
		"Refine the current value-scan result generation using the configured comparison",
		memory_scanner_view::scan_command_t::next_scan);
	register_memory_scan_action("memory.stop_scan", "Stop Scan",
		"Request safe cancellation of the active value-scan task without discarding completed state",
		memory_scanner_view::scan_command_t::stop_scan);
	register_memory_scan_action("memory.undo_scan", "Undo Scan",
		"Restore the previous completed value-scan result generation",
		memory_scanner_view::scan_command_t::undo_scan);
	register_memory_scan_action("memory.new_scan", "New Scan",
		"Clear scan results and history while preserving the address list and current scan configuration",
		memory_scanner_view::scan_command_t::new_scan);

	const auto register_debugger_action = [&rt](const char* id, const char* label,
		const char* description, debugger_view::execution_command_t command) {
		register_action(rt, id, label, description,
			action_surface_t::application_menu | action_surface_t::toolbar |
				action_surface_t::command_palette |
				action_surface_t::shortcut | action_surface_t::accessibility,
			[command](const action_invocation_t&) {
				std::string error;
				return debugger_view::execute_command(command, &error)
					? action_handler_result_t::completed()
					: action_handler_result_t::failed(error);
			}, [command](const interaction_context_t&) {
				const auto state = debugger_view::execution_capability(command);
				return state.enabled ? capability_state_t::available()
					: capability_state_t::unavailable(state.disabled_reason
						? state.disabled_reason : "Debugger command is unavailable");
			}, false, {}, "category.debugger", "Debugger");
	};
	register_debugger_action("debugger.launch", "Launch Target...",
		"Configure and launch a target under the debugger", debugger_view::execution_command_t::launch);
	register_debugger_action("debugger.run_continue", "Run / Continue",
		"Launch a target or continue the paused target", debugger_view::execution_command_t::run_continue);
	register_debugger_action("debugger.pause", "Pause",
		"Pause the running target", debugger_view::execution_command_t::pause);
	register_debugger_action("debugger.step_over", "Step Over",
		"Execute the current instruction without entering a call", debugger_view::execution_command_t::step_over);
	register_debugger_action("debugger.step_into", "Step Into",
		"Execute the current instruction and enter a call", debugger_view::execution_command_t::step_into);
	register_debugger_action("debugger.step_out", "Step Out",
		"Continue until the current frame returns", debugger_view::execution_command_t::step_out);
	register_debugger_action("debugger.stop", "Stop Target",
		"Terminate the attached target after an explicit debugger command", debugger_view::execution_command_t::stop);
	register_debugger_action("debugger.restart", "Restart Target...",
		"Terminate the current target and reopen the reviewed launch configuration", debugger_view::execution_command_t::restart);
	register_debugger_action("debugger.detach", "Detach",
		"Detach without terminating the target", debugger_view::execution_command_t::detach);
	register_debugger_action("debugger.toggle_breakpoint_at_rip", "Toggle Breakpoint at RIP",
		"Add or remove a software breakpoint at the paused instruction pointer",
		debugger_view::execution_command_t::toggle_breakpoint_at_instruction_pointer);
	register_action(rt, "debugger.watch.refresh_all", "Refresh Watches",
		"Evaluate the exact immutable watch generation off the UI thread and publish all results atomically",
		action_surface_t::application_menu | action_surface_t::toolbar |
			action_surface_t::command_palette | action_surface_t::shortcut |
			action_surface_t::accessibility,
		[](const action_invocation_t&) {
			return schedule_debugger_watch_refresh();
		}, [](const interaction_context_t&) {
			return debugger_watch_refresh_capability();
		}, false, {}, "category.debugger", "Debugger");
	const auto register_patch_panel_action = [&rt](const char* id, const char* label,
		const char* description, debugger_view::patch_panel_command_t command) {
		register_action(rt, id, label, description,
			action_surface_t::toolbar | action_surface_t::command_palette |
				action_surface_t::accessibility,
			[command](const action_invocation_t&) {
				std::string error;
				return debugger_view::execute_patch_panel_command(command, &error)
					? action_handler_result_t::completed()
					: action_handler_result_t::failed(error);
			}, [command](const interaction_context_t&) {
				const auto state = debugger_view::patch_panel_capability(command);
				return state.enabled ? capability_state_t::available()
					: capability_state_t::unavailable(state.disabled_reason
						? state.disabled_reason : "Patches panel action is unavailable");
			}, false, {}, "category.debugger", "Debugger");
	};
	register_patch_panel_action("debugger.patch.stage", "Stage Patch...",
		"Review a new runtime byte patch", debugger_view::patch_panel_command_t::stage);
	register_patch_panel_action("debugger.patch.find_caves", "Find Code Caves...",
		"Find bounded code caves in the attached module",
		debugger_view::patch_panel_command_t::find_code_caves);
	register_patch_panel_action("debugger.patch.revert_all", "Revert All Patches...",
		"Review restoring every active runtime patch",
		debugger_view::patch_panel_command_t::revert_all);
	register_patch_panel_action("debugger.patch.save_set", "Save Patchset...",
		"Export the bounded runtime patch definition set",
		debugger_view::patch_panel_command_t::save_patchset);
	const auto register_intercept_action = [&rt](const char* id, const char* label,
		const char* description, network_view::intercept_command_t command) {
		register_action(rt, id, label, description,
			action_surface_t::application_menu | action_surface_t::toolbar |
			action_surface_t::command_palette | action_surface_t::shortcut |
			action_surface_t::context_menu | action_surface_t::accessibility,
			retained_or_handler(id, [command](const action_invocation_t&) {
				std::string error;
				return network_view::execute_intercept_command(command, &error)
					? action_handler_result_t::completed()
					: action_handler_result_t::failed(error);
			}), retained_or_capability(id, [command](const interaction_context_t&) {
				const auto state = network_view::intercept_command_capability(command);
				return state.enabled ? capability_state_t::available()
					: capability_state_t::unavailable(state.disabled_reason.empty()
						? "Intercept command is unavailable" : state.disabled_reason);
			}), false, {}, "category.network", "Network");
	};
	register_intercept_action("network.intercept.forward_selected", "Forward Selected",
		"Forward the exact selected held exchange",
		network_view::intercept_command_t::forward_selected);
	register_intercept_action("network.intercept.drop_selected", "Drop Selected...",
		"Review dropping the exact selected held exchange",
		network_view::intercept_command_t::drop_selected);
	register_intercept_action("network.intercept.forward_modified", "Forward Modified",
		"Forward the exact selected held exchange with its reviewed bounded text draft",
		network_view::intercept_command_t::forward_modified);
	register_intercept_action("network.intercept.forward_all", "Forward All Held",
		"Forward every exchange in the current immutable Intercept publication",
		network_view::intercept_command_t::forward_all);
	register_intercept_action("network.intercept.drop_all", "Drop All Held...",
		"Review dropping every exchange in the current immutable Intercept publication",
		network_view::intercept_command_t::drop_all);
    register_action(rt, "tools.settings", "Settings", "Open AiDA settings",
        menu_surfaces | action_surface_t::toolbar, [&rt](const action_invocation_t&) {
            if (!rt.shell.open_settings)
                return action_handler_result_t::failed("Settings are unavailable");
            rt.shell.open_settings();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.open_settings, "Settings are unavailable");
        }, false, {}, "category.tools", "Tools");
    register_action(rt, "tools.driver_status", "Driver Status", "Inspect driver connection and integrity status",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.open_driver_status)
                return action_handler_result_t::failed("Driver status is unavailable");
            rt.shell.open_driver_status();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.open_driver_status, "Driver status is unavailable");
        }, false, {}, "category.tools", "Tools");
    register_action(rt, "ai.new_chat", "New Chat", "Start a new AI conversation",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.new_chat)
                return action_handler_result_t::failed("Chat is unavailable");
            rt.shell.new_chat();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.new_chat, "Chat is unavailable");
        }, false, {}, "category.ai", "AI");
    register_action(rt, "ai.model_settings", "Model Settings", "Open model and provider settings",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.open_settings)
                return action_handler_result_t::failed("Model settings are unavailable");
            rt.shell.open_settings();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.open_settings, "Model settings are unavailable");
        }, false, {}, "category.ai", "AI");
    register_action(rt, "ai.agent_picker.toggle", "Choose Active Agent...",
        "Open or close the active-agent picker",
        menu_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            std::string error;
            return chat_toggle_agent_picker(error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }, {}, false, {}, "category.ai", "AI");
    register_action(rt, "ai.agent_mode.toggle_plan_build", "Toggle Plan / Build Agent",
        "Switch the active AI agent between plan and build modes", menu_surfaces,
        [](const action_invocation_t&) {
            std::string error;
            return chat_toggle_plan_build_agent(error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }, {}, false, {}, "category.ai", "AI");
    register_action(rt, "help.shortcuts", "Keyboard Shortcuts", "Show effective shortcuts and conflicts",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.open_shortcuts)
                return action_handler_result_t::failed("Shortcut help is unavailable");
            rt.shell.open_shortcuts();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.open_shortcuts, "Shortcut help is unavailable");
        }, false, {}, "category.help", "Help");
    register_action(rt, "view.command_palette", "Command Palette", "Search and run every registered human action",
        action_surface_t::application_menu | action_surface_t::shortcut | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            globals::ui::command_palette_open = !globals::ui::command_palette_open;
            return action_handler_result_t::completed();
        }, {}, false, {}, "category.view", "View");
    register_action(rt, "view.global_search", "Search Workspace", "Search text across the open source workspace",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto result = application_views::open_or_focus(
                stable_view_id_t("view.workspace_search"));
            return result.ok()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, {}, false, {}, "category.view", "View");

    register_action(rt, "explorer.open", "Open", "Open the selected Explorer item", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto live = single_explorer_selection(rt.explorer);
            if (!live.enabled) return action_handler_result_t::failed(live.disabled_reason);
            if (rt.explorer.directory)
                file_browser::toggle_dir(rt.explorer.index);
            else
                file_browser::open_file(rt.explorer.index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) { return single_explorer_selection(rt.explorer); });
    register_action(rt, "explorer.copy_path", "Copy Path", "Copy the full path", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.explorer.path.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return single_explorer_selection(rt.explorer); });
    register_action(rt, "explorer.copy_name", "Copy Name", "Copy the item name", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.explorer.name.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return single_explorer_selection(rt.explorer); });
    register_action(rt, "explorer.copy_relative_path", "Copy Workspace-Relative Path",
        "Copy the selected item path relative to its Project Explorer root", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto relative = workspace_relative_path(rt.explorer.path);
            if (!relative)
                return action_handler_result_t::failed(
                    "The selected item is not inside an open Project Explorer root");
            ImGui::SetClipboardText(relative->c_str());
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            const auto single = single_explorer_selection(rt.explorer);
            if (!single.enabled) return single;
            return workspace_relative_path(rt.explorer.path)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "The selected item is not inside an open Project Explorer root");
        });
    register_action(rt, "explorer.add_to_chat", "Add to AI Chat",
        "Send bounded file or folder identity to AI Chat without reading its contents",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            return send_programming_path_to_ai(rt.explorer.path, rt.explorer.name,
                rt.explorer.directory ? "Project Explorer folder" : "Project Explorer file");
        }, [&rt](const interaction_context_t&) {
            return single_explorer_selection(rt.explorer);
        });
    register_action(rt, "explorer.search", "Search Workspace", "Open workspace search",
        context_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            const auto result = application_views::open_or_focus(stable_view_id_t("view.workspace_search"));
            return result.ok() ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        });
    register_action(rt, "explorer.search_here", "Search Here",
        "Scope Workspace Search to the retained Project Explorer folder or selected file's containing folder",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = explorer_views::request_search_scope(
                rt.explorer.path, rt.explorer.directory);
            return result.accepted ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [&rt](const interaction_context_t&) {
            return single_explorer_selection(rt.explorer);
        });
    register_action(rt, "explorer.refresh", "Refresh", "Refresh Explorer",
        context_surfaces | action_surface_t::toolbar,
        [](const action_invocation_t&) {
            file_browser::needs_refresh = true;
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            return file_browser::roots.empty()
                ? capability_state_t::unavailable("Open a workspace folder before refreshing Explorer")
                : capability_state_t::available();
        });
    const auto register_explorer_file_operation = [&rt](const char* id, const char* label,
            const char* description, explorer_views::file_operation_t operation,
            bool mutation) {
        register_action(rt, id, label, description, context_surfaces,
            [&rt, operation](const action_invocation_t&) {
                std::vector<explorer_views::file_operation_target_t> targets;
                const auto live = live_explorer_selection(rt.explorer, &targets);
                if (!live.enabled && !rt.explorer.path.empty())
                    return action_handler_result_t::failed(live.disabled_reason);
                if (targets.empty() && !file_browser::roots.empty())
                    targets.push_back({file_browser::roots.front(), true});
                const auto result = explorer_views::request_file_operation(operation, targets);
                return result.accepted ? action_handler_result_t::completed(result.detail)
                    : action_handler_result_t::failed(result.detail);
            }, [&rt, operation](const interaction_context_t&) {
                std::vector<explorer_views::file_operation_target_t> targets;
                const auto live = live_explorer_selection(rt.explorer, &targets);
                if (!live.enabled && !rt.explorer.path.empty()) return live;
                if (targets.empty() && !file_browser::roots.empty())
                    targets.push_back({file_browser::roots.front(), true});
                const std::size_t operation_index = static_cast<std::size_t>(operation);
                const auto capability = !rt.explorer.targets.empty() &&
                    operation_index < rt.explorer.operation_capabilities.size()
                    ? rt.explorer.operation_capabilities[operation_index]
                    : explorer_views::file_operation_capability(operation, targets);
                return capability.enabled ? capability_state_t::available()
                    : capability_state_t::unavailable(capability.reason);
            }, mutation, {}, "category.programming.explorer", "Programming / Explorer");
    };
    register_explorer_file_operation("explorer.new_file", "New File...",
        "Create an empty file inside the selected folder through the bounded filesystem worker",
        explorer_views::file_operation_t::new_file, true);
    register_explorer_file_operation("explorer.new_folder", "New Folder...",
        "Create a folder inside the selected folder through the bounded filesystem worker",
        explorer_views::file_operation_t::new_folder, true);
    register_explorer_file_operation("explorer.rename", "Rename...",
        "Rename the selected item after validating its workspace-root identity",
        explorer_views::file_operation_t::rename, true);
    register_explorer_file_operation("explorer.cut", "Cut",
        "Stage the selected item for a same-volume reviewed move",
        explorer_views::file_operation_t::cut, true);
    register_explorer_file_operation("explorer.copy_item", "Copy Item",
        "Stage the selected item for a bounded workspace copy",
        explorer_views::file_operation_t::copy, false);
    register_explorer_file_operation("explorer.paste", "Paste",
        "Copy or move the staged item into the selected folder",
        explorer_views::file_operation_t::paste, true);
    register_explorer_file_operation("explorer.duplicate", "Duplicate...",
        "Create a bounded duplicate beside the selected file or folder",
        explorer_views::file_operation_t::duplicate, true);
    register_explorer_file_operation("explorer.delete", "Delete...",
        "Permanently delete the selected workspace item after exact-scope review",
        explorer_views::file_operation_t::remove, true);
    register_explorer_file_operation("explorer.open_with", "Open With...",
        "Open the native Windows application chooser for the selected file",
        explorer_views::file_operation_t::open_with, false);
    register_explorer_file_operation("explorer.terminal_here", "Open Terminal Here",
        "Open AiDA's configured integrated terminal profile in the selected folder",
        explorer_views::file_operation_t::terminal_here, false);
    register_action(rt, "explorer.set_workspace_root", "Set as Workspace Root",
        "Replace the open Project Explorer roots through the canonical File / Open Folder root transaction",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto live = single_explorer_selection(rt.explorer);
            if (!live.enabled) return action_handler_result_t::failed(live.disabled_reason);
            if (!rt.explorer.directory)
                return action_handler_result_t::failed("Set Workspace Root requires one selected folder");
            std::string error;
            return file_browser::set_workspace_root(rt.explorer.path, &error)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(error);
        }, [&rt](const interaction_context_t&) {
            const auto live = single_explorer_selection(rt.explorer);
            if (!live.enabled) return live;
            if (!rt.explorer.directory)
                return capability_state_t::unavailable(
                    "Set Workspace Root requires one selected folder");
            if (file_browser::roots.size() == 1 &&
                normalized_programming_path_key(file_browser::roots.front()) ==
                    normalized_programming_path_key(rt.explorer.path))
                return capability_state_t::unavailable(
                    "The selected folder is already the only Project Explorer workspace root");
            return capability_state_t::available();
        }, true, {}, "category.programming.explorer", "Programming / Explorer");
    register_action(rt, "explorer.analyze_binary", "Analyze Binary",
        "Open the exact selected binary through AiDA's canonical reviewed analysis transaction",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto live = single_explorer_selection(rt.explorer);
            if (!live.enabled) return action_handler_result_t::failed(live.disabled_reason);
            if (rt.explorer.directory || !file_browser::binary_analysis_candidate(rt.explorer.path))
                return action_handler_result_t::failed(
                    "Analyze Binary requires one selected supported binary or archive file");
            file_browser::request_open_confirmation(rt.explorer.path);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            const auto live = single_explorer_selection(rt.explorer);
            if (!live.enabled) return live;
            return !rt.explorer.directory && file_browser::binary_analysis_candidate(rt.explorer.path)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "Analyze Binary requires one selected supported binary or archive file");
        }, false, {}, "category.analysis", "Analysis");
    const auto register_configured_file_action = [&rt](const char* id,
            const char* label, const char* description, bool launch) {
        register_action(rt, id, label, description, context_surfaces,
            [&rt, launch](const action_invocation_t&) {
                const auto live = single_explorer_selection(rt.explorer);
                if (!live.enabled) return action_handler_result_t::failed(live.disabled_reason);
                if (rt.explorer.directory)
                    return action_handler_result_t::failed(
                        "Configured targets require one selected file, not a folder");
                const auto result = programming_tasks::request_run_selected_for_file(
                    rt.explorer.path, launch);
                return result.succeeded ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.detail);
            }, [&rt, launch](const interaction_context_t&) {
                const auto live = single_explorer_selection(rt.explorer);
                if (!live.enabled) return live;
                if (rt.explorer.directory)
                    return capability_state_t::unavailable(
                        "Configured targets require one selected file, not a folder");
                const std::string reason = programming_tasks::run_for_file_unavailable_reason(
                    rt.explorer.path, launch);
                return reason.empty() ? capability_state_t::available()
                    : capability_state_t::unavailable(reason);
            }, false, {}, "category.programming.tasks", "Programming / Tasks");
    };
    register_configured_file_action("explorer.run_configured_target", "Run Configured Target...",
        "Review and run the selected Task configuration only when its command binds this exact file with ${file}",
        false);
    register_configured_file_action("explorer.debug_configured_target", "Debug Configured Target...",
        "Review and run the selected Launch configuration only when its command binds this exact file with ${file}",
        true);

    register_action(rt, "workspace_search.open", "Open Result", "Open this search result in the code editor", context_surfaces,
        [&rt](const action_invocation_t&) {
            return open_workspace_search_result(rt.workspace_search)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The result file could not be opened");
        }, [&rt](const interaction_context_t&) {
            return rt.workspace_search.path.empty()
                ? capability_state_t::unavailable("Select a search result first")
                : capability_state_t::available();
        });
    register_action(rt, "workspace_search.copy_path", "Copy Path", "Copy the result file path", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.workspace_search.path.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.workspace_search.path.empty() ? capability_state_t::unavailable("The result has no path") : capability_state_t::available(); });
    register_action(rt, "workspace_search.copy_line", "Copy Matching Line", "Copy the matching source line", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.workspace_search.line_text.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.workspace_search.line_text.empty() ? capability_state_t::unavailable("The matching line is empty") : capability_state_t::available(); });
    register_action(rt, "workspace_search.add_to_chat", "Add Result to AI Chat",
        "Send the bounded matching source location to AI Chat with workspace identity",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            std::string label = path_to_utf8(path_from_utf8(rt.workspace_search.path).filename());
            if (rt.workspace_search.line > 0)
                label.append(":").append(std::to_string(rt.workspace_search.line));
            return send_programming_path_to_ai(rt.workspace_search.path, label,
                "Workspace Search result");
        }, [&rt](const interaction_context_t&) {
            return rt.workspace_search.path.empty()
                ? capability_state_t::unavailable("Select a search result first")
                : capability_state_t::available();
        });

    register_action(rt, "recent.open", "Open", "Open or activate this recent binary", context_surfaces,
        [&rt](const action_invocation_t&) {
            std::size_t index = 0;
            if (find_open_session(rt.recent.path, index))
                return analysis_session::switch_session(index)
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed("The open session could not be activated");
            const std::string name = path_to_utf8(path_from_utf8(rt.recent.path).filename());
            file_browser::pending_open_path = rt.recent.path;
            file_browser::pending_open_filename = name;
            file_browser::pending_open_should_open = true;
            file_browser::pending_open_modal_visible = true;
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) { return rt.recent.path.empty() ? capability_state_t::unavailable("Select a recent item first") : capability_state_t::available(); });
    register_action(rt, "recent.close", "Close Session", "Close this open analysis session", context_surfaces,
        [&rt](const action_invocation_t&) {
            std::size_t index = 0;
            if (!find_open_session(rt.recent.path, index))
                return action_handler_result_t::failed("The session is no longer open");
            return analysis_session::close_session(index)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The session could not be closed");
        }, [&rt](const interaction_context_t&) {
            std::size_t index = 0;
            return rt.recent.open_session && find_open_session(rt.recent.path, index)
                ? capability_state_t::available()
                : capability_state_t::unavailable("This recent item is not an open session");
        });
    register_action(rt, "recent.copy_path", "Copy Path", "Copy the binary path", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.recent.path.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.recent.path.empty() ? capability_state_t::unavailable("The item has no path") : capability_state_t::available(); });

    const auto output_tab = [&rt]() { return static_cast<bottom_tab_t>(rt.output.tab); };
    const auto output_capability = [&rt](const interaction_context_t&) {
        return output_views::has_content(static_cast<bottom_tab_t>(rt.output.tab))
            ? capability_state_t::available()
            : capability_state_t::unavailable("This output view has no text");
    };
    const auto output_surfaces = context_surfaces | action_surface_t::toolbar |
        action_surface_t::shortcut;
    register_action(rt, "output.copy_all", "Copy All", "Copy the complete bounded output buffer", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::copy_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.clear", "Clear", "Clear this view without affecting its underlying service", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::clear(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.select_all", "Select All", "Select all text in this output view", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::select_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.follow", "Follow Tail", "Toggle automatic following of new output", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::toggle_follow(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, [output_tab](const interaction_context_t&) {
            return output_views::source_available(output_tab())
                ? capability_state_t::available()
                : capability_state_t::unavailable("The terminal session is not running");
        }, false, [output_tab](const interaction_context_t&) {
            return output_views::follows_tail(output_tab())
                ? action_check_state_t::checked : action_check_state_t::unchecked;
        });
    register_action(rt, "output.filter", "Focus Filter", "Focus the output filter", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::focus_filter(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, [output_tab](const interaction_context_t&) {
            return output_views::supports_filter(output_tab())
                ? capability_state_t::available()
                : capability_state_t::unavailable("Interactive terminal output cannot be filtered safely");
        });
    register_action(rt, "output.export", "Export...", "Export the complete bounded output buffer to a chosen file", output_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::export_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    const auto terminal_context_active = [&rt](const interaction_context_t& context) {
        return context.active_view.value() == "view.terminal" ||
            rt.output.tab == static_cast<int>(bottom_tab_t::terminal);
    };
    const auto terminal_capability = [terminal_context_active](const interaction_context_t& context) {
        return terminal_context_active(context)
            ? capability_state_t::available()
            : capability_state_t::unavailable("This action is available in the Terminal view");
    };
    const auto terminal_session_capability = [terminal_context_active](const interaction_context_t& context) {
        if (!terminal_context_active(context))
            return capability_state_t::unavailable("This action is available in the Terminal view");
        return output_views::terminal_session_count() != 0
            ? capability_state_t::available()
            : capability_state_t::unavailable("There are no terminal sessions");
    };
    const auto register_terminal_operation = [&](const char* id, const char* name,
            const char* description, auto operation, auto capability) {
        register_action(rt, id, name, description, output_surfaces,
            [operation](const action_invocation_t&) {
                const auto result = operation();
                return result.succeeded ? action_handler_result_t::completed()
                    : action_handler_result_t::failed(result.detail);
            }, capability);
    };
    register_terminal_operation("terminal.new", "New Terminal", "Start another terminal session from the selected profile",
        output_views::terminal_new, terminal_capability);
    register_terminal_operation("terminal.close", "Close Terminal", "Stop the active terminal process tree and close its tab",
        output_views::terminal_close, terminal_session_capability);
    register_terminal_operation("terminal.restart", "Restart Terminal", "Stop and recreate the active terminal process tree with the same profile and working directory",
        output_views::terminal_restart, terminal_session_capability);
    register_terminal_operation("terminal.next", "Next Terminal", "Activate the next terminal session",
        output_views::terminal_next, terminal_session_capability);
    register_terminal_operation("terminal.previous", "Previous Terminal", "Activate the previous terminal session",
        output_views::terminal_previous, terminal_session_capability);
    register_terminal_operation("terminal.split_vertical", "Split Terminal Right", "Show a second terminal session beside the active session",
        output_views::terminal_split_vertical, terminal_session_capability);
    register_terminal_operation("terminal.split_horizontal", "Split Terminal Down", "Show a second terminal session below the active session",
        output_views::terminal_split_horizontal, terminal_session_capability);
    register_terminal_operation("terminal.unsplit", "Unsplit Terminal", "Return the terminal view to a single pane",
        output_views::terminal_unsplit, [terminal_context_active](const interaction_context_t& context) {
            if (!terminal_context_active(context))
                return capability_state_t::unavailable("This action is available in the Terminal view");
            return output_views::terminal_is_split() ? capability_state_t::available()
                : capability_state_t::unavailable("The terminal is not split");
        });
    register_terminal_operation("terminal.search", "Find in Terminal", "Search the active terminal scrollback",
        output_views::terminal_focus_search, terminal_session_capability);
    register_terminal_operation("terminal.paste", "Paste into Terminal", "Send clipboard text to the focused terminal session",
        output_views::terminal_paste, terminal_session_capability);

    register_action(rt, "tab.save", "Save", "Save this editor tab", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = file_tabs::save_tab_to_disk_result(rt.tab.index);
            return result.succeeded ? action_handler_result_t::completed()
                                    : action_handler_result_t::failed(result.detail);
        },
        [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index) || rt.tab.path.empty())
                return capability_state_t::unavailable("This tab has no writable path");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            return tab.external_conflict && !tab.external_overwrite_approved
                ? capability_state_t::unavailable(
                    "The file changed on disk; resolve the editor conflict before saving")
                : capability_state_t::available();
        });
    const auto tab_toolbar_surfaces = context_surfaces | action_surface_t::toolbar;
    register_action(rt, "tab.compare_disk", "Compare with Disk",
        "Load the bounded current disk version asynchronously and open a revision-bound reviewed comparison",
        tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = file_tabs::compare_with_disk(rt.tab.index);
            return result.succeeded ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            if (tab.filepath.empty() || !tab.buffer_loaded)
                return capability_state_t::unavailable(
                    "Open a path-backed text document before comparing with disk");
            return tab.recovery_operation_pending
                ? capability_state_t::unavailable(
                    "Another document comparison or recovery operation is still running")
                : capability_state_t::available();
        });
    register_action(rt, "tab.load.cancel", "Cancel Load",
        "Cancel the asynchronous bounded read for this editor document", tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return action_handler_result_t::failed("The tab is no longer open");
            file_tabs::cancel_document_load(
                file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].document_id);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            return file_tabs::is_valid_tab_index(rt.tab.index) &&
                file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].load_in_progress
                ? capability_state_t::available()
                : capability_state_t::unavailable("This document is not loading");
        });
    register_action(rt, "tab.load.retry", "Retry Load",
        "Retry the asynchronous bounded read for this editor document", tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return action_handler_result_t::failed("The tab is no longer open");
            file_tabs::load_tab_into_editor(rt.tab.index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            return !tab.buffer_loaded && !tab.load_in_progress
                ? capability_state_t::available()
                : capability_state_t::unavailable("This document does not have a failed load to retry");
        });
    register_action(rt, "tab.recovery.retry_probe", "Retry Recovery Check",
        "Retry the asynchronous verified recovery-journal probe", tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return action_handler_result_t::failed("The tab is no longer open");
            auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            tab.recovery_error.clear();
            tab.recovery_probe_completed = false;
            file_tabs::request_recovery_probe(rt.tab.index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            return !tab.recovery_operation_pending && tab.recovery_probe_completed &&
                !tab.recovery_error.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("No failed recovery check is available to retry");
        });
    register_action(rt, "tab.external.reload", "Reload from Disk",
        "Replace the unmodified editor buffer with the newer retained disk version", tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            return file_tabs::reload_external(rt.tab.index)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The retained disk-conflict state changed before reload executed");
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            if (!tab.external_conflict)
                return capability_state_t::unavailable("The file has no unresolved disk conflict");
            return tab.dirty ? capability_state_t::unavailable(
                "Save the editor changes elsewhere or keep the editor version first")
                : capability_state_t::available();
        });
    register_action(rt, "tab.external.keep_editor", "Keep Editor Version",
        "Approve the retained editor version for the next explicit save over the newer disk version",
        tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            return file_tabs::keep_editor_version(rt.tab.index)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(
                    "The retained disk-conflict state changed before approval executed");
        }, [&rt](const interaction_context_t&) {
            return file_tabs::is_valid_tab_index(rt.tab.index) &&
                file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].external_conflict
                ? capability_state_t::available()
                : capability_state_t::unavailable("The file has no unresolved disk conflict");
        });
    const auto recovery_capability = [&rt](bool allow_dirty) {
        if (!file_tabs::is_valid_tab_index(rt.tab.index))
            return capability_state_t::unavailable("The tab is no longer open");
        const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
        if (tab.recovery_operation_pending)
            return capability_state_t::unavailable(tab.recovery_operation_label.empty()
                ? "Another recovery operation is still running"
                : tab.recovery_operation_label);
        if (!tab.recovery.available)
            return capability_state_t::unavailable(tab.recovery_error.empty()
                ? "No verified unsaved recovery journal is available"
                : tab.recovery_error);
        if (!allow_dirty && tab.dirty)
            return capability_state_t::unavailable(
                "Compare first or save the current changes; recovery will not overwrite newer unsaved work");
        return capability_state_t::available();
    };
    register_action(rt, "tab.recovery.recover", "Recover Unsaved Content",
        "Open the verified journal content as unsaved work without consuming the retained recovery point",
        tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = file_tabs::recover_from_journal(rt.tab.index);
            return result.succeeded ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [recovery_capability](const interaction_context_t&) {
            return recovery_capability(false);
        });
    register_action(rt, "tab.recovery.compare", "Compare with Recovery",
        "Open a revision-bound comparison between the current document and the verified journal",
        tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = file_tabs::compare_with_journal(rt.tab.index);
            return result.succeeded ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [recovery_capability](const interaction_context_t&) {
            return recovery_capability(true);
        });
    register_action(rt, "tab.recovery.discard", "Discard Recovery",
        "Permanently discard the current and last-good journals for this document after explicit acknowledgement",
        tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            const auto result = file_tabs::request_recovery_discard(rt.tab.index);
            return result.succeeded ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [recovery_capability](const interaction_context_t&) {
            return recovery_capability(true);
        });
    register_action(rt, "tab.close", "Close", "Close this editor tab", tab_toolbar_surfaces,
        [&rt](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
            close_tab_with_confirmation(rt.tab.index);
            return action_handler_result_t::completed();
        },
        [&rt](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            return file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].pinned
                ? capability_state_t::unavailable("Unpin this document before closing it")
                : capability_state_t::available();
        });
    register_action(rt, "tab.close_others", "Close Other Tabs", "Close all other saved editor tabs", context_surfaces,
        [&rt](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1; index >= 0; --index)
                if (index != rt.tab.index &&
                    file_tabs::tabs[file_tabs::tab_index(index)].group_id == group &&
                    !file_tabs::tabs[file_tabs::tab_index(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            const auto eligible = [&](std::size_t index) {
                return static_cast<int>(index) != rt.tab.index &&
                    file_tabs::tabs[index].group_id == group && !file_tabs::tabs[index].pinned;
            };
            if (std::none_of(file_tabs::tabs.begin(), file_tabs::tabs.end(),
                    [&](const OpenTab& tab) {
                        const std::size_t index = static_cast<std::size_t>(&tab - file_tabs::tabs.data());
                        return eligible(index);
                    }))
                return capability_state_t::unavailable("There are no other tabs");
            for (std::size_t index = 0; index < file_tabs::tabs.size(); ++index)
                if (eligible(index) && file_tabs::tabs[index].dirty)
                    return capability_state_t::unavailable("Save or close modified tabs first");
            return capability_state_t::available();
        });
    register_action(rt, "tab.close_right", "Close Tabs to the Right",
        "Close every unmodified editor tab to the right of this tab", context_surfaces,
        [&rt](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1;
                 index > rt.tab.index; --index)
                if (file_tabs::tabs[file_tabs::tab_index(index)].group_id == group &&
                    !file_tabs::tabs[file_tabs::tab_index(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            bool found = false;
            for (std::size_t index = static_cast<std::size_t>(rt.tab.index + 1);
                 index < file_tabs::tabs.size(); ++index)
                found = found || (file_tabs::tabs[index].group_id == group &&
                    !file_tabs::tabs[index].pinned);
            if (!found)
                return capability_state_t::unavailable("There are no tabs to the right");
            for (std::size_t index = static_cast<std::size_t>(rt.tab.index + 1);
                 index < file_tabs::tabs.size(); ++index)
                if (file_tabs::tabs[index].group_id == group && !file_tabs::tabs[index].pinned &&
                    file_tabs::tabs[index].dirty)
                    return capability_state_t::unavailable(
                        "Save or close modified tabs to the right first");
            return capability_state_t::available();
        });
    register_action(rt, "tab.close_saved", "Close Saved Tabs",
        "Close every unmodified editor tab while preserving modified work", context_surfaces,
        [](const action_invocation_t&) {
            if (file_tabs::close_review_in_progress())
                return action_handler_result_t::failed(
                    "Finish the current document-close review first");
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1;
                 index >= 0; --index)
                if (!file_tabs::tabs[static_cast<std::size_t>(index)].dirty &&
                    !file_tabs::tabs[static_cast<std::size_t>(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            if (file_tabs::close_review_in_progress())
                return capability_state_t::unavailable(
                    "Finish the current document-close review first");
            return std::any_of(file_tabs::tabs.begin(), file_tabs::tabs.end(),
                [](const OpenTab& tab) { return !tab.dirty && !tab.pinned; })
                ? capability_state_t::available()
                : capability_state_t::unavailable("No saved tabs are open");
        });
    register_action(rt, "tab.toggle_pin", "Pin Tab", "Keep this document open in its group", context_surfaces,
        [&rt](const action_invocation_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return action_handler_result_t::failed("The tab is no longer open");
            auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            tab.pinned = !tab.pinned;
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            return file_tabs::is_valid_tab_index(rt.tab.index)
                ? capability_state_t::available()
                : capability_state_t::unavailable("The tab is no longer open");
        }, false, [&rt](const interaction_context_t&) {
            return file_tabs::is_valid_tab_index(rt.tab.index) &&
                file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].pinned
                ? action_check_state_t::checked : action_check_state_t::unchecked;
        });
    register_action(rt, "tab.move_new_group", "Move into New Group",
        "Create a dockable editor group and move this document into it", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto group = file_tabs::create_group_for_tab(rt.tab.index);
            if (group == 0)
                return action_handler_result_t::failed("The tab is no longer open");
            file_tabs::switch_to(rt.tab.index);
            const auto result = application_views::open_or_focus(stable_view_id_t("document.code"));
            return result.ok() ? action_handler_result_t::completed()
                               : action_handler_result_t::failed(result.detail);
        }, [&rt](const interaction_context_t&) {
            return file_tabs::is_valid_tab_index(rt.tab.index)
                ? capability_state_t::available()
                : capability_state_t::unavailable("The tab is no longer open");
        });
    struct editor_split_action_t {
        const char* id;
        const char* label;
        workspace_layout::dock_split_direction_t direction;
    };
    for (const auto& split : std::array<editor_split_action_t, 4>{{
            {"tab.split_left", "Split Editor Left", workspace_layout::dock_split_direction_t::left},
            {"tab.split_right", "Split Editor Right", workspace_layout::dock_split_direction_t::right},
            {"tab.split_up", "Split Editor Up", workspace_layout::dock_split_direction_t::up},
            {"tab.split_down", "Split Editor Down", workspace_layout::dock_split_direction_t::down}}}) {
        register_action(rt, split.id, split.label,
            "Move this document into a new dockable editor group in the explicit direction",
            context_surfaces,
            [&rt, direction = split.direction](const action_invocation_t&) {
                if (!file_tabs::is_valid_tab_index(rt.tab.index))
                    return action_handler_result_t::failed("The tab is no longer open");
                const auto anchor_instance = code_group_instance(rt.tab.index);
                if (!anchor_instance)
                    return action_handler_result_t::failed("The editor group is no longer available");
                const std::string anchor_window =
                    application_views::registry().window_name(*anchor_instance);
                const std::uint32_t original_group = file_tabs::tabs[
                    file_tabs::tab_index(rt.tab.index)].group_id;
                if (file_tabs::create_group_for_tab(rt.tab.index) == 0)
                    return action_handler_result_t::failed("The tab is no longer open");
                file_tabs::switch_to(rt.tab.index);
                const auto opened = application_views::open_or_focus(
                    stable_view_id_t("document.code"));
                const auto split_instance = code_group_instance(rt.tab.index);
                if (!opened.ok() || !split_instance) {
                    file_tabs::move_to_group(rt.tab.index, original_group);
                    return action_handler_result_t::failed(opened.ok()
                        ? "The new editor group was not registered" : opened.detail);
                }
                const std::string split_window_name =
                    application_views::registry().window_name(*split_instance);
                const auto result = workspace_layout::split_window(
                    split_window_name, anchor_window, direction);
                if (result != workspace_layout::workspace_request_result_t::completed &&
                    result != workspace_layout::workspace_request_result_t::queued &&
                    result != workspace_layout::workspace_request_result_t::unchanged) {
                    file_tabs::move_to_group(rt.tab.index, original_group);
                    return action_handler_result_t::failed(
                        "The workspace could not create the requested directional editor split");
                }
                return action_handler_result_t::completed();
            }, [&rt](const interaction_context_t&) {
                if (!file_tabs::is_valid_tab_index(rt.tab.index))
                    return capability_state_t::unavailable("The tab is no longer open");
                if (workspace_layout::operation_pending())
                    return capability_state_t::unavailable(
                        "A workspace layout transaction is already in progress");
                if (workspace_layout::layout_locked())
                    return capability_state_t::unavailable(
                        "Unlock the workspace layout before splitting editor groups");
                const auto instance = code_group_instance(rt.tab.index);
                if (!instance)
                    return capability_state_t::unavailable(
                        "The editor group is no longer available");
                const auto placement = workspace_layout::inspect_window_placement(
                    application_views::registry().window_name(*instance));
                return placement.docked ? capability_state_t::available()
                    : capability_state_t::unavailable(
                        "Dock this editor group before creating a directional split");
            });
    }
    register_action(rt, "tab.move_primary_group", "Move into Primary Group",
        "Move this document back into the primary editor group", context_surfaces,
        [&rt](const action_invocation_t&) {
            return file_tabs::move_to_group(rt.tab.index, 0)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The tab is no longer open");
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            return file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id == 0
                ? capability_state_t::unavailable("This document is already in the primary group")
                : capability_state_t::available();
        });
    register_action(rt, "tab.history_back", "Previous Document in Group",
        "Restore the previous document selection in this editor group", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            return file_tabs::navigate_group_history(group, false)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("This editor group has no previous document");
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            const auto found = file_tabs::navigation_by_group.find(group);
            return found != file_tabs::navigation_by_group.end() && !found->second.back.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("This editor group has no previous document");
        });
    register_action(rt, "tab.history_forward", "Next Document in Group",
        "Restore the next document selection in this editor group", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            return file_tabs::navigate_group_history(group, true)
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("This editor group has no next document");
        }, [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            const auto found = file_tabs::navigation_by_group.find(group);
            return found != file_tabs::navigation_by_group.end() && !found->second.forward.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("This editor group has no next document");
        });
    register_action(rt, "tab.copy_path", "Copy Path", "Copy the tab path", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.tab.path.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.tab.path.empty() ? capability_state_t::unavailable("This untitled tab has no path") : capability_state_t::available(); });
    register_action(rt, "tab.copy_name", "Copy Name", "Copy the tab name", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.tab.name.c_str()); return action_handler_result_t::completed(); });
    register_action(rt, "tab.copy_relative_path", "Copy Workspace-Relative Path",
        "Copy this document path relative to its Project Explorer root", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto relative = workspace_relative_path(rt.tab.path);
            if (!relative)
                return action_handler_result_t::failed(
                    "This document is not inside an open Project Explorer root");
            ImGui::SetClipboardText(relative->c_str());
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
            if (rt.tab.path.empty())
                return capability_state_t::unavailable("This untitled tab has no path");
            return workspace_relative_path(rt.tab.path)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "This document is not inside an open Project Explorer root");
        });
    register_action(rt, "tab.add_to_chat", "Add File Context to AI Chat",
        "Send bounded document identity and workspace-relative path to AI Chat without copying file contents",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            return send_programming_path_to_ai(rt.tab.path, rt.tab.name,
                "Code document tab");
        }, [&rt](const interaction_context_t&) {
            return rt.tab.path.empty()
                ? capability_state_t::unavailable(
                    "Save this document to a file before sending its identity to AI Chat")
                : capability_state_t::available();
        });
    register_action(rt, "tab.reveal_in_explorer", "Reveal in Project Explorer",
        "Expand this document's workspace path and select it in Project Explorer",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            if (!file_browser::reveal_path(rt.tab.path))
                return action_handler_result_t::failed(
                    "This document is not inside an open Project Explorer root");
            const auto opened = application_views::open_or_focus(
                stable_view_id_t("view.project_explorer"));
            return opened.ok() ? action_handler_result_t::completed()
                : action_handler_result_t::failed(opened.detail);
        }, [&rt](const interaction_context_t&) {
            if (rt.tab.path.empty())
                return capability_state_t::unavailable("This untitled tab has no path");
            return workspace_relative_path(rt.tab.path)
                ? capability_state_t::available()
                : capability_state_t::unavailable(
                    "This document is not inside an open Project Explorer root");
        });
    register_action(rt, "tab.float_group", "Float Editor Group",
        "Undock the editor group containing this document without changing its size",
        context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto instance = code_group_instance(rt.tab.index);
            if (!instance)
                return action_handler_result_t::failed("The editor tab is no longer open");
            const std::string& window = application_views::registry().window_name(*instance);
            if (window.empty())
                return action_handler_result_t::failed(
                    "The editor group window has not been realized yet");
            return workspace_result(workspace_layout::float_window(window),
                "The editor group could not be floated");
        }, [&rt](const interaction_context_t&) {
            const auto instance = code_group_instance(rt.tab.index);
            if (!instance)
                return capability_state_t::unavailable("The editor tab is no longer open");
            if (workspace_layout::operation_pending())
                return capability_state_t::unavailable(
                    "A workspace layout transaction is already in progress");
            if (workspace_layout::layout_locked())
                return capability_state_t::unavailable(
                    "Unlock the workspace layout before floating editor groups");
            const std::string& window = application_views::registry().window_name(*instance);
            const auto placement = workspace_layout::inspect_window_placement(window);
            if (!placement.realized)
                return capability_state_t::unavailable(
                    "The editor group window has not been realized yet");
            return placement.docked ? capability_state_t::available()
                : capability_state_t::unavailable("This editor group is already floating");
        });

    register_shortcut(rt, "binding.editor.save", "file.save", ImGuiMod_Ctrl | ImGuiKey_S, "Ctrl+S");
    register_shortcut(rt, "binding.editor.undo", "edit.undo", ImGuiMod_Ctrl | ImGuiKey_Z, "Ctrl+Z", true);
    register_shortcut(rt, "binding.editor.redo", "edit.redo", ImGuiMod_Ctrl | ImGuiKey_Y, "Ctrl+Y", true);
    register_shortcut(rt, "binding.editor.redo_alternate", "edit.redo",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Z, "Ctrl+Shift+Z", true);
    register_shortcut(rt, "binding.editor.cut", "edit.cut", ImGuiMod_Ctrl | ImGuiKey_X, "Ctrl+X");
    register_shortcut(rt, "binding.editor.copy", "edit.copy", ImGuiMod_Ctrl | ImGuiKey_C, "Ctrl+C");
    register_shortcut(rt, "binding.editor.paste", "edit.paste", ImGuiMod_Ctrl | ImGuiKey_V, "Ctrl+V");
    register_shortcut(rt, "binding.editor.delete", "edit.delete", ImGuiKey_Delete, "Delete", true);
    register_shortcut(rt, "binding.editor.select_all", "edit.select_all", ImGuiMod_Ctrl | ImGuiKey_A, "Ctrl+A");
    register_shortcut(rt, "binding.editor.find", "edit.find", ImGuiMod_Ctrl | ImGuiKey_F, "Ctrl+F");
    register_shortcut(rt, "binding.editor.replace", "edit.replace", ImGuiMod_Ctrl | ImGuiKey_H, "Ctrl+H");
    register_shortcut(rt, "binding.editor.goto", "edit.goto_line", ImGuiMod_Ctrl | ImGuiKey_G, "Ctrl+G");
    register_shortcut(rt, "binding.editor.quick_open", "file.quick_open", ImGuiMod_Ctrl | ImGuiKey_P, "Ctrl+P");
    register_shortcut(rt, "binding.editor.close", "file.close", ImGuiMod_Ctrl | ImGuiKey_W, "Ctrl+W");
    register_shortcut(rt, "binding.editor.save_all", "file.save_all",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_S, "Ctrl+Alt+S");
    register_shortcut(rt, "binding.editor.copy_line", "edit.copy_line",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_C, "Ctrl+Shift+C");
    register_shortcut(rt, "binding.editor.next_document_or_session",
        "navigate.next_document_or_session", ImGuiMod_Ctrl | ImGuiKey_Tab, "Ctrl+Tab");
    register_shortcut(rt, "binding.editor.previous_document_or_session",
        "navigate.previous_document_or_session",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Tab, "Ctrl+Shift+Tab");
    register_shortcut(rt, "binding.editor.duplicate_line", "edit.duplicate_line",
        ImGuiMod_Ctrl | ImGuiKey_D, "Ctrl+D");
    register_shortcut(rt, "binding.editor.delete_line", "edit.delete_line",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_K, "Ctrl+Shift+K");
    register_shortcut(rt, "binding.editor.move_line_up", "edit.move_line_up",
        ImGuiMod_Alt | ImGuiKey_UpArrow, "Alt+Up");
    register_shortcut(rt, "binding.editor.move_line_down", "edit.move_line_down",
        ImGuiMod_Alt | ImGuiKey_DownArrow, "Alt+Down");
    register_shortcut(rt, "binding.editor.toggle_line_comment", "edit.toggle_line_comment",
        ImGuiMod_Ctrl | ImGuiKey_Slash, "Ctrl+/");
    register_shortcut(rt, "binding.editor.language.completion",
        "programming.language.completion", ImGuiMod_Ctrl | ImGuiKey_Space,
        "Ctrl+Space");
    register_shortcut(rt, "binding.editor.language.definition",
        "programming.language.definition", ImGuiKey_F12, "F12");
    register_shortcut(rt, "binding.editor.language.references",
        "programming.language.references", ImGuiMod_Shift | ImGuiKey_F12,
        "Shift+F12");
    register_shortcut(rt, "binding.editor.language.outline",
        "programming.language.document_symbols",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_O, "Ctrl+Shift+O");
    register_review_shortcut(rt, "binding.editor.ai.previous_pending_hunk",
        "editor.ai.previous_pending_hunk", ImGuiMod_Alt | ImGuiKey_LeftBracket,
        "Alt+[");
    register_review_shortcut(rt, "binding.editor.ai.next_pending_hunk",
        "editor.ai.next_pending_hunk", ImGuiMod_Alt | ImGuiKey_RightBracket,
        "Alt+]");
    register_review_shortcut(rt, "binding.editor.ai.accept_current_hunk",
        "editor.ai.accept_current_hunk",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_Enter, "Ctrl+Alt+Enter");
    register_review_shortcut(rt, "binding.editor.ai.reject_current_hunk",
        "editor.ai.reject_current_hunk",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_Backspace, "Ctrl+Alt+Backspace");
    register_global_shortcut(rt, "binding.global.new", "file.new", ImGuiMod_Ctrl | ImGuiKey_N, "Ctrl+N");
    register_global_shortcut(rt, "binding.global.open", "file.open", ImGuiMod_Ctrl | ImGuiKey_O, "Ctrl+O");
    register_global_shortcut(rt, "binding.global.open_folder", "file.open_folder", ImGuiMod_Ctrl | ImGuiKey_K, "Ctrl+K");
    register_global_shortcut(rt, "binding.global.quick_open", "file.quick_open", ImGuiMod_Ctrl | ImGuiKey_P, "Ctrl+P");
    register_global_shortcut(rt, "binding.global.save_as", "file.save_as", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S, "Ctrl+Shift+S");
    register_global_shortcut(rt, "binding.global.explorer", "view.explorer", ImGuiMod_Ctrl | ImGuiKey_B, "Ctrl+B");
    register_global_shortcut(rt, "binding.global.chat", "view.chat", ImGuiMod_Ctrl | ImGuiKey_J, "Ctrl+J");
    register_global_shortcut(rt, "binding.global.output", "view.output", ImGuiMod_Ctrl | ImGuiKey_GraveAccent, "Ctrl+`");
    register_global_shortcut(rt, "binding.global.network", "view.network", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_N, "Ctrl+Shift+N");
    register_global_shortcut(rt, "binding.global.debugger", "view.debugger", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_D, "Ctrl+Shift+D");
    register_global_shortcut(rt, "binding.global.source_debug_console",
        "view.focus.view.programming.source_debug_console",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_D, "Ctrl+Alt+D");
    register_global_shortcut(rt, "binding.global.scan", "view.scan", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_M, "Ctrl+Shift+M");
	register_widget_shortcut(rt, "binding.memory.first_scan", "memory.first_scan",
		ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_F, "Ctrl+Alt+F", k_memory_scan_scope, 50);
	register_widget_shortcut(rt, "binding.memory.next_scan", "memory.next_scan",
		ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_N, "Ctrl+Alt+N", k_memory_scan_scope, 50);
	register_widget_shortcut(rt, "binding.memory.stop_scan", "memory.stop_scan",
		ImGuiMod_Shift | ImGuiKey_Escape, "Shift+Escape", k_memory_scan_scope, 50);
	register_widget_shortcut(rt, "binding.memory.undo_scan", "memory.undo_scan",
		ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_Z, "Ctrl+Alt+Z", k_memory_scan_scope, 50);
	register_widget_shortcut(rt, "binding.memory.new_scan", "memory.new_scan",
		ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_R, "Ctrl+Alt+R", k_memory_scan_scope, 50);
    register_global_shortcut(rt, "binding.global.binary_map", "view.binary_map", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_B, "Ctrl+Shift+B");
    register_global_shortcut(rt, "binding.global.command_palette", "view.command_palette", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_P, "Ctrl+Shift+P");
    register_global_shortcut(rt, "binding.global.new_chat", "ai.new_chat", ImGuiMod_Ctrl | ImGuiKey_L, "Ctrl+L");
    register_global_shortcut(rt, "binding.global.workspace_search", "view.global_search", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_F, "Ctrl+Shift+F");
    register_global_shortcut(rt, "binding.global.preferences", "edit.preferences", ImGuiMod_Ctrl | ImGuiKey_Comma, "Ctrl+,");
    register_widget_shortcut(rt, "binding.ai.agent_picker", "ai.agent_picker.toggle",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_A, "Ctrl+Shift+A",
        "scope.view.ai_chat", 50);
    register_widget_shortcut(rt, "binding.ai.agent_mode", "ai.agent_mode.toggle_plan_build",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_M, "Ctrl+Alt+M",
        "scope.view.ai_chat", 50);
    register_global_chord(rt, "binding.global.keyboard_shortcuts", "help.shortcuts",
        ImGuiMod_Ctrl | ImGuiKey_K, ImGuiMod_Ctrl | ImGuiKey_S,
        "Ctrl+K, Ctrl+S");
    register_global_shortcut(rt, "binding.global.xrefs", "view.focus.view.analysis.references", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_X, "Ctrl+Shift+X");
    register_global_shortcut(rt, "binding.global.deobfuscation", "view.focus.view.analysis.deobfuscation", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_O, "Ctrl+Shift+O");
    register_global_shortcut(rt, "binding.global.next_document_or_session",
        "navigate.next_document_or_session", ImGuiMod_Ctrl | ImGuiKey_Tab, "Ctrl+Tab");
    register_global_shortcut(rt, "binding.global.previous_document_or_session",
        "navigate.previous_document_or_session",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Tab, "Ctrl+Shift+Tab");
    register_global_shortcut(rt, "binding.global.programming_task_run", "programming.task.run",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_R, "Ctrl+Alt+R");
    register_global_shortcut(rt, "binding.global.programming_task_cancel", "programming.task.cancel",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_C, "Ctrl+Alt+C");
    register_global_shortcut(rt, "binding.global.programming_task_configure", "programming.task.configure",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_T, "Ctrl+Alt+T");
    register_domain_shortcut(rt, "binding.output.copy_all", "output.copy_all",
        ImGuiMod_Ctrl | ImGuiKey_C, "Ctrl+C", k_output_scope, 40);
    register_domain_shortcut(rt, "binding.output.select_all", "output.select_all",
        ImGuiMod_Ctrl | ImGuiKey_A, "Ctrl+A", k_output_scope, 40);
    register_domain_shortcut(rt, "binding.output.filter", "output.filter",
        ImGuiMod_Ctrl | ImGuiKey_F, "Ctrl+F", k_output_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.new", "terminal.new",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_GraveAccent, "Ctrl+Shift+`", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.close", "terminal.close",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_W, "Ctrl+Shift+W", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.restart", "terminal.restart",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_R, "Ctrl+Shift+R", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.next", "terminal.next",
        ImGuiMod_Ctrl | ImGuiKey_PageDown, "Ctrl+PageDown", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.previous", "terminal.previous",
        ImGuiMod_Ctrl | ImGuiKey_PageUp, "Ctrl+PageUp", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.search", "terminal.search",
        ImGuiMod_Ctrl | ImGuiKey_F, "Ctrl+F", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.paste", "terminal.paste",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_V, "Ctrl+Shift+V", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.split_vertical", "terminal.split_vertical",
        ImGuiMod_Alt | ImGuiMod_Shift | ImGuiKey_V, "Alt+Shift+V", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.split_horizontal", "terminal.split_horizontal",
        ImGuiMod_Alt | ImGuiMod_Shift | ImGuiKey_H, "Alt+Shift+H", k_terminal_scope, 40);
    register_domain_shortcut(rt, "binding.terminal.unsplit", "terminal.unsplit",
        ImGuiMod_Alt | ImGuiMod_Shift | ImGuiKey_U, "Alt+Shift+U", k_terminal_scope, 40);
	register_global_shortcut(rt, "binding.global.shell.maximize", "shell.toggle_maximize", ImGuiKey_F11, "F11");
	register_domain_shortcut(rt, "binding.analysis.decompile", "analysis.decompile_or_focus_pseudocode",
		ImGuiKey_F5, "F5", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.toggle_graph_text", "analysis.toggle_graph_text",
		ImGuiKey_Space, "Space", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.back", "analysis.navigate.back",
        ImGuiMod_Alt | ImGuiKey_LeftArrow, "Alt+Left", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.forward", "analysis.navigate.forward",
        ImGuiMod_Alt | ImGuiKey_RightArrow, "Alt+Right", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.follow", "analysis.navigate.follow",
        ImGuiKey_Enter, "Enter", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.follow_keypad", "analysis.navigate.follow",
        ImGuiKey_KeypadEnter, "Keypad Enter", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.goto", "analysis.navigate.goto",
		ImGuiKey_G, "G", k_analysis_scope, 20);
    register_document_shortcut(rt, "binding.analysis.goto_ctrl", "analysis.navigate.goto",
        ImGuiMod_Ctrl | ImGuiKey_G, "Ctrl+G", k_disassembly_scope, 30);
    register_document_shortcut(rt, "binding.analysis.rebase", "analysis.modify.rebase",
        ImGuiMod_Ctrl | ImGuiKey_R, "Ctrl+R", k_disassembly_scope, 30);
    register_document_shortcut(rt, "binding.analysis.export_listing",
        "analysis.export.listing", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_D,
        "Ctrl+Shift+D", k_disassembly_scope, 30);
    register_domain_shortcut(rt, "binding.analysis.rename", "analysis.modify.rename",
        ImGuiKey_N, "N", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.retype", "analysis.modify.retype",
        ImGuiKey_Y, "Y", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.xrefs", "analysis.navigate.xrefs",
        ImGuiKey_X, "X", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.comment", "analysis.modify.comment",
        ImGuiKey_Semicolon, ";", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.bookmark", "analysis.modify.bookmark",
        ImGuiKey_B, "B", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.overlay_undo", "analysis.overlay.undo",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_Z, "Ctrl+Alt+Z", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.overlay_redo", "analysis.overlay.redo",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_Y, "Ctrl+Alt+Y", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.run_to_cursor",
        "analysis.debug.run_to_cursor", ImGuiKey_F4, "F4", k_analysis_scope, 20);
    register_domain_shortcut(rt, "binding.analysis.toggle_breakpoint",
        "analysis.debug.breakpoint", ImGuiKey_F9, "F9", k_analysis_scope, 20);
    register_document_shortcut(rt, "binding.analysis.pseudocode_tab",
        "analysis.decompile_or_focus_pseudocode", ImGuiKey_Tab, "Tab",
        k_disassembly_scope, 30);
    register_widget_shortcut(rt, "binding.analysis.proximity.drill",
        "analysis.proximity.drill", ImGuiKey_Enter, "Enter",
        "scope.view.analysis.proximity", 40);
    register_widget_shortcut(rt, "binding.analysis.proximity.drill_keypad",
        "analysis.proximity.drill", ImGuiKey_KeypadEnter, "Keypad Enter",
        "scope.view.analysis.proximity", 40);
	register_domain_shortcut(rt, "binding.debugger.run", "debugger.run_continue", ImGuiKey_F9, "F9", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_over", "debugger.step_over", ImGuiKey_F8, "F8", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_into", "debugger.step_into", ImGuiKey_F7, "F7", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_out", "debugger.step_out", ImGuiMod_Shift | ImGuiKey_F11, "Shift+F11", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.stop", "debugger.stop", ImGuiMod_Shift | ImGuiKey_F5, "Shift+F5", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.restart", "debugger.restart", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_F5, "Ctrl+Shift+F5", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.detach", "debugger.detach", ImGuiMod_Ctrl | ImGuiKey_F2, "Ctrl+F2", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.toggle_breakpoint", "debugger.toggle_breakpoint_at_rip", ImGuiKey_F2, "F2", k_debugger_scope, 30);
	register_widget_shortcut(rt, "binding.debugger.watch.refresh_all",
		"debugger.watch.refresh_all", ImGuiMod_Ctrl | ImGuiKey_R,
		"Ctrl+R", "scope.view.debug.watches", 50);
	register_shortcut(rt, "binding.editor.source_breakpoint",
		"debug.source.toggle_breakpoint", ImGuiKey_F9, "F9");
	register_widget_shortcut(rt, "binding.network.intercept.forward_selected",
		"network.intercept.forward_selected", ImGuiKey_F, "F", k_network_intercept_scope, 50);
	register_widget_shortcut(rt, "binding.network.intercept.drop_selected",
		"network.intercept.drop_selected", ImGuiKey_D, "D", k_network_intercept_scope, 50);
	register_widget_shortcut(rt, "binding.network.intercept.forward_modified",
		"network.intercept.forward_modified", ImGuiKey_M, "M", k_network_intercept_scope, 50);
	register_widget_shortcut(rt, "binding.network.intercept.forward_all",
		"network.intercept.forward_all", ImGuiMod_Shift | ImGuiKey_F,
		"Shift+F", k_network_intercept_scope, 50);
	register_widget_shortcut(rt, "binding.network.intercept.drop_all",
		"network.intercept.drop_all", ImGuiMod_Shift | ImGuiKey_D,
		"Shift+D", k_network_intercept_scope, 50);
    struct retained_action_definition_t {
        const char* id;
        const char* label;
        const char* description;
        const char* category;
        bool undoable = false;
    };
    static constexpr retained_action_definition_t retained_actions[] = {
        {"workspace.load_named", "Load Saved Workspace", "Load the exact retained saved workspace generation", "Workspace"},
        {"task.focus_owner", "Focus Owner", "Focus the retained task owner", "Tasks"},
        {"task.open_log", "Open Log", "Open the retained task log", "Tasks"},
        {"task.retry", "Retry", "Retry the retained terminal task", "Tasks"},
        {"task.request_cancel", "Request Cancellation", "Request safe cancellation from the retained task owner", "Tasks"},
        {"task.view_diagnostic", "View Diagnostic", "Open Diagnostics for the retained task", "Tasks"},
        {"task.copy_id", "Copy Task ID", "Copy the retained task identifier", "Tasks"},
        {"task.copy_summary", "Copy Task Summary", "Copy the retained task summary and result", "Tasks"},
        {"programming.configuration.run_review", "Run with Review...", "Resolve and review the exact retained task configuration before execution", "Programming / Tasks"},
        {"programming.configuration.open_edit", "Open or Edit Configuration...", "Open the retained project configuration source or user configuration editor", "Programming / Tasks"},
        {"programming.configuration.duplicate", "Duplicate as User Configuration...", "Create a reviewed user-owned draft from the retained configuration", "Programming / Tasks"},
        {"programming.configuration.delete_review", "Delete Configuration...", "Review deleting the exact retained user configuration", "Programming / Tasks"},
        {"programming.run.cancel", "Cancel Run", "Request cancellation of the exact retained programming run", "Programming / Tasks"},
        {"programming.run.retry_review", "Retry with Review...", "Open the canonical retry review for the exact retained terminal run", "Programming / Tasks"},
        {"programming.run.focus", "Focus Run Output", "Focus the exact retained programming run output owner", "Programming / Tasks"},
        {"programming.run.open_log", "Open Run Log", "Open the exact retained programming run log", "Programming / Tasks"},
        {"diagnostic.focus_owner", "Focus Owner", "Focus the retained diagnostic owner", "Diagnostics"},
        {"diagnostic.open_log", "Open Log", "Open the retained diagnostic log", "Diagnostics"},
        {"diagnostic.retry", "Retry Operation", "Retry the operation that raised the retained diagnostic", "Diagnostics"},
        {"diagnostic.acknowledge", "Acknowledge", "Acknowledge the retained diagnostic", "Diagnostics"},
        {"diagnostic.copy", "Copy Diagnostic", "Copy the retained diagnostic details", "Diagnostics"},
        {"diagnostic.copy_id", "Copy Diagnostic ID", "Copy the retained diagnostic identifier", "Diagnostics"},
        {"evidence.handoff.add_chat", "Add to AI Chat", "Register bounded retained evidence and add it to AI Chat", "Evidence"},
        {"evidence.handoff.add_review", "Add to Evidence Review", "Register bounded retained evidence for review", "Evidence"},
        {"evidence.handoff.assign_agent", "Assign to Agent", "Register bounded retained evidence and assign it to an agent", "Evidence"},
        {"workbench.inspector.copy_va", "Copy VA", "Copy the retained virtual address", "Inspector"},
        {"workbench.inspector.copy_rva", "Copy RVA", "Copy the retained relative virtual address", "Inspector"},
        {"workbench.inspector.copy_file_offset", "Copy File Offset", "Copy the retained file offset", "Inspector"},
        {"workbench.inspector.follow_disassembly", "Follow in Disassembly", "Open the retained address in Disassembly", "Inspector"},
        {"workbench.inspector.follow_hex", "Follow in Hex", "Open the retained address in Hex", "Inspector"},
        {"workbench.inspector.show_xrefs", "Show Xrefs", "Show cross-references for the retained address", "Inspector"},
        {"workbench.inspector.send_chat", "Send to AI Chat", "Attach the retained Inspector evidence to AI Chat", "Inspector"},
        {"workbench.inspector.add_evidence", "Add to Evidence Review", "Add the retained Inspector evidence to Evidence Review", "Inspector"},
        {"workbench.navigator.follow_disassembly", "Follow in Disassembly", "Open the retained Navigator entity in Disassembly", "Navigator"},
        {"workbench.navigator.copy_address", "Copy Address", "Copy the retained Navigator address", "Navigator"},
        {"workbench.navigator.copy_name", "Copy Name", "Copy the retained Navigator name", "Navigator"},
        {"workbench.diff.follow", "Follow Change", "Open the retained diff change", "Diff"},
        {"workbench.diff.copy_address", "Copy Address", "Copy the retained diff address", "Diff"},
        {"workbench.diff.copy_before", "Copy Before", "Copy the retained value before the change", "Diff"},
        {"workbench.diff.copy_after", "Copy After", "Copy the retained value after the change", "Diff"},
        {"chat.link.copy", "Copy Link", "Copy the retained chat link", "AI Chat"},
        {"chat.message.copy", "Copy Message", "Copy the retained chat message", "AI Chat"},
        {"chat.message.edit", "Edit Message", "Edit the retained chat message", "AI Chat"},
        {"chat.message.delete", "Delete Message", "Delete the retained chat message", "AI Chat"},
        {"chat.message.retry", "Retry From Here", "Retry AI Chat from the retained message", "AI Chat"},
        {"debugger.entity.copy_address", "Copy Address", "Copy the retained debugger address", "Debugger"},
        {"debugger.entity.copy_primary", "Copy Label / Expression", "Copy the retained debugger label, expression, or string", "Debugger"},
        {"debugger.entity.copy_secondary", "Copy Current Value / Module", "Copy the retained debugger value or module", "Debugger"},
        {"debugger.entity.open_disassembly", "Open in Disassembly", "Navigate to the retained debugger address in Disassembly", "Debugger"},
        {"debugger.entity.open_hex", "Open in Hex View", "Navigate to the retained debugger address in Hex", "Debugger"},
        {"debugger.instruction.run_to", "Run to Here", "Continue execution to the retained instruction", "Debugger"},
        {"debugger.instruction.toggle_breakpoint", "Toggle Breakpoint", "Toggle a breakpoint at the retained instruction", "Debugger"},
        {"debugger.instruction.set_rip", "Set RIP to Here...", "Review setting the instruction pointer to the retained instruction", "Debugger"},
        {"debugger.instruction.follow_branch", "Follow Branch Target", "Navigate to the retained branch target", "Debugger"},
        {"debugger.register.copy_decimal", "Copy Decimal", "Copy the retained register value as decimal", "Debugger"},
        {"debugger.register.edit", "Edit Register...", "Edit the retained register through the reviewed register editor", "Debugger"},
        {"debugger.register.zero", "Set to Zero...", "Set the retained register to zero through the reviewed register editor", "Debugger"},
		{"debugger.register.add_watch", "Add Watch", "Stage the retained register expression in Watches", "Debugger"},
        {"debugger.stack.copy_qword", "Copy Qword Value", "Copy the retained stack qword", "Debugger"},
		{"debugger.stack.add_watch", "Add Watch", "Stage the retained stack slot as a memory watch expression", "Debugger"},
		{"debugger.entity.pointer_workflow", "Find Pointer Paths...", "Stage the retained live address in Pointer Scanner", "Debugger"},
		{"debugger.entity.interpret_structure", "Interpret as Structure...", "Stage the retained live address in Structures", "Debugger"},
        {"debugger.breakpoint.toggle_enabled", "Enable / Disable", "Toggle the retained breakpoint state", "Debugger"},
        {"debugger.breakpoint.edit", "Edit Breakpoint...", "Open the retained breakpoint editor", "Debugger"},
		{"debugger.breakpoint.condition", "Edit Condition...", "Open the retained breakpoint condition in the reviewed editor", "Debugger"},
		{"debugger.breakpoint.log_message", "Edit Log Message...", "Open the retained breakpoint log message in the reviewed editor", "Debugger"},
		{"debugger.breakpoint.auto_continue", "Configure Auto-continue...", "Open the retained breakpoint auto-continue setting in the reviewed editor", "Debugger"},
        {"debugger.breakpoint.delete", "Delete Breakpoint", "Delete the retained breakpoint", "Debugger"},
        {"debugger.memory.change_protection", "Change Protection...", "Review a protection change for the retained memory region", "Debugger"},
        {"debugger.memory.dump", "Dump Region...", "Export the retained memory region with exact read verification", "Debugger"},
        {"debugger.module.unload", "Unload Module", "Unload the retained module when a safe debugger operation is available", "Debugger"},
        {"debugger.thread.suspend", "Suspend Thread", "Suspend the retained target thread", "Debugger"},
        {"debugger.thread.resume", "Resume Thread", "Resume the retained target thread", "Debugger"},
        {"debugger.thread.terminate", "Terminate Thread...", "Review termination of the retained target thread", "Debugger"},
        {"debugger.thread.switch", "Switch To", "Make the retained thread active", "Debugger"},
        {"debugger.thread.follow_rip", "Go to RIP in Disassembly", "Navigate to the retained thread instruction pointer", "Debugger"},
        {"debugger.handle.close", "Close Handle...", "Review closing the retained target handle", "Debugger"},
        {"debugger.patch.apply", "Apply Patch...", "Review applying the retained patch", "Debugger"},
        {"debugger.patch.revert", "Revert Patch...", "Review reverting the retained patch", "Debugger"},
        {"debugger.patch.remove", "Remove Patch...", "Review removing the retained patch definition", "Debugger"},
        {"debugger.watch.remove", "Remove Watch...", "Review removing the retained watch", "Debugger"},
        {"debugger.bookmark.remove", "Remove Bookmark...", "Review removing the retained bookmark", "Debugger"},
        {"debugger.seh.follow_handler", "Go to Handler", "Navigate to the retained exception handler", "Debugger"},
        {"debugger.source.open", "Open Source", "Open the retained source breakpoint location", "Debugger"},
        {"debugger.source.open_disassembly", "Open First Location in Disassembly", "Navigate to the retained source breakpoint address", "Debugger"},
        {"debugger.source.copy_location", "Copy File:Line", "Copy the retained source breakpoint location", "Debugger"},
        {"debugger.source.copy_address", "Copy First Address", "Copy the retained source breakpoint address", "Debugger"},
        {"debugger.source.rebind_all", "Rebind All Source Breakpoints", "Queue exact PDB source breakpoint rebinding", "Debugger"},
        {"debugger.source.remove", "Remove Source Breakpoint", "Remove the retained source breakpoint", "Debugger"},
        {"memory.entity.open_disassembly", "Open in Disassembly", "Navigate to the retained memory entity in Disassembly", "Memory"},
        {"memory.entity.open_hex", "Open in Hex View", "Navigate to the retained memory entity in Hex", "Memory"},
        {"memory.entity.copy_address", "Copy Address", "Copy the retained memory address", "Memory"},
        {"memory.entity.copy_value", "Copy Current Value", "Copy the retained memory value", "Memory"},
        {"memory.entity.copy_previous", "Copy Previous Value", "Copy the retained previous memory value", "Memory"},
        {"memory.entity.copy_module_offset", "Copy Module + Offset", "Copy the retained module-relative address", "Memory"},
        {"memory.result.add_address", "Add to Address List", "Add the retained scan result to the address list", "Memory"},
        {"memory.result.compare_selected", "Compare Selected Results", "Open the exact retained memory result pair in Comparer", "Memory"},
        {"memory.result.export_selected", "Export Selected Results...", "Export the exact retained memory result set as bounded JSON", "Memory"},
		{"memory.result.freeze", "Freeze", "Freeze the exact matching retained Address List entry", "Memory"},
		{"memory.result.unfreeze", "Unfreeze", "Unfreeze the exact matching retained Address List entry", "Memory"},
		{"memory.entity.pointer_workflow", "Find Pointer Paths...", "Stage the retained live address in Pointer Scanner", "Memory"},
		{"memory.entity.interpret_structure", "Interpret / Apply Structure...", "Stage the retained address in Structures for explicit review", "Memory"},
        {"memory.entity.stage_patch", "Stage Patch in Patches View...", "Stage the retained address in the reviewed Patches workflow", "Memory"},
        {"memory.address.edit_description", "Edit Description", "Edit the retained address-list description", "Memory"},
        {"memory.address.change_type", "Change Type", "Change the retained address-list value type", "Memory"},
        {"memory.address.change_value", "Change Value...", "Review and write a new value at the retained address", "Memory"},
        {"memory.address.freeze", "Freeze", "Freeze the retained address-list value", "Memory"},
        {"memory.address.unfreeze", "Unfreeze", "Unfreeze the retained address-list value", "Memory"},
        {"memory.address.remove", "Remove from Address List", "Remove the retained address-list entry", "Memory"},
        {"memory.aob.copy_pattern", "Copy Pattern", "Copy the retained AOB pattern", "Memory"},
        {"memory.aob.copy_ida_pattern", "Copy IDA Pattern", "Copy the retained IDA-style AOB pattern", "Memory"},
        {"memory.crypto.copy_algorithm", "Copy Algorithm", "Copy the retained crypto algorithm", "Memory"},
        {"memory.crypto.show_references", "Show References...", "Open the complete retained crypto-reference chooser", "Memory"},
        {"memory.pointer.copy_chain", "Copy Chain", "Copy the retained pointer chain", "Memory"},
        {"memory.pointer.copy_cpp", "Copy C++ Resolver", "Copy a C++ resolver for the retained pointer chain", "Memory"},
        {"memory.pointer.copy_base", "Copy Base Address", "Copy the retained pointer-chain base", "Memory"},
        {"memory.pointer.copy_resolved", "Copy Resolved Address", "Copy the retained pointer-chain result", "Memory"},
        {"memory.pointer.open_base_disassembly", "Open Base in Disassembly", "Navigate to the retained pointer base", "Memory"},
        {"memory.pointer.open_resolved_hex", "Open Resolved Address in Hex", "Navigate to the retained pointer result in Hex", "Memory"},
        {"memory.pointer.add_address", "Add Resolved Address to Address List", "Add the retained pointer result to the address list", "Memory"},
        {"memory.pointer.stage_patch", "Stage Patch at Resolved Address...", "Stage the retained pointer result in Patches", "Memory"},
        {"memory.pointer.validate", "Validate This Chain", "Validate the retained pointer chain against current memory", "Memory"},
        {"hex.copy_byte", "Copy Byte", "Copy the retained byte", "Hex"},
        {"hex.copy_selection", "Copy Selected Bytes", "Copy the retained byte selection", "Hex"},
        {"hex.copy_address", "Copy Address", "Copy the retained Hex address", "Hex"},
        {"hex.open_disassembly", "Open in Disassembly", "Navigate from the retained byte to Disassembly", "Hex"},
        {"hex.stage_zero_overlay", "Stage 00-byte Overlay...", "Stage a reversible zero-byte workspace overlay", "Hex"},
        {"hex.stage_patch_overlay", "Patch Selected Bytes...", "Review arbitrary replacement bytes in the reversible workspace overlay", "Hex"},
        {"hex.stage_nop_overlay", "NOP Selected Bytes...", "Review a NOP fill in the reversible workspace overlay", "Hex"},
        {"network.capture.copy_summary", "Copy Summary", "Copy the retained packet summary", "Network Capture"},
        {"network.capture.copy_source", "Copy Source Endpoint", "Copy the retained packet source endpoint", "Network Capture"},
        {"network.capture.copy_destination", "Copy Destination Endpoint", "Copy the retained packet destination endpoint", "Network Capture"},
        {"network.capture.copy_payload", "Copy Payload", "Copy the bounded retained packet payload", "Network Capture"},
        {"network.capture.send_comparer", "Send Payload to Comparer", "Send the retained packet payload to Comparer", "Network Capture"},
        {"network.capture.send_chat", "Add Payload to AI Chat", "Attach bounded packet evidence to AI Chat", "Network Capture"},
        {"network.capture.assign_agent", "Assign Payload to Agent", "Assign bounded packet evidence to an agent", "Network Capture"},
        {"network.capture.filter_pid", "Filter by PID", "Filter capture rows by the retained packet process", "Network Capture"},
        {"network.capture.filter_protocol", "Filter by Protocol", "Filter capture rows by the retained packet protocol", "Network Capture"},
        {"network.capture.toggle_follow", "Toggle Follow Tail", "Toggle capture follow-tail behavior", "Network Capture"},
        {"network.capture.send_repeater", "Send to Repeater", "Send a retained HTTP request to Repeater", "Network Capture"},
        {"network.capture.replay", "Replay Packet", "Replay a reviewed retained packet", "Network Capture"},
        {"network.exchange.repeater", "Open Request in Repeater", "Stage the retained request in Repeater", "Network Exchange"},
        {"network.exchange.fuzzer", "Open Request in Fuzzer", "Stage the exact retained request in Fuzzer", "Network Exchange"},
        {"network.exchange.intruder", "Open Request in Intruder", "Stage the retained request in Intruder", "Network Exchange"},
        {"network.exchange.scanner", "Open Request in Scanner", "Stage the retained request in Scanner", "Network Exchange"},
        {"network.exchange.comparer", "Send Artifact to Comparer", "Send the retained exchange artifact to Comparer", "Network Exchange"},
        {"network.exchange.compare_request_response", "Compare Request vs Response", "Open the matching retained HTTP/1 request and response in Comparer", "Network Exchange"},
        {"network.exchange.session_handling", "Open in Session Handling", "Stage the retained request as reviewed Session Handling context", "Network Exchange"},
        {"network.exchange.cookies", "Inspect Target Cookies", "Open Cookie Jar with the retained request target as reviewed filter context", "Network Exchange"},
        {"network.exchange.match_replace", "Draft Match and Replace Rule", "Stage the retained HTTP/1 artifact scope as a disabled rule draft", "Network Exchange"},
        {"network.exchange.decoder", "Open Artifact in Decoder", "Open the retained exchange artifact in Decoder", "Network Exchange"},
        {"network.exchange.sequencer", "Open Request in Sequencer", "Stage the retained request in Sequencer", "Network Exchange"},
        {"network.exchange.camoufox", "Open URL in Camoufox...", "Stage the retained request URL in Camoufox", "Network Exchange"},
        {"network.exchange.copy_url", "Copy URL", "Copy the retained request URL", "Network Exchange"},
        {"network.exchange.copy_method", "Copy Method", "Copy the retained request method", "Network Exchange"},
        {"network.exchange.copy_status", "Copy Status", "Copy the retained response status", "Network Exchange"},
        {"network.exchange.copy_request", "Copy Request", "Copy the retained request", "Network Exchange"},
        {"network.exchange.copy_response", "Copy Response", "Copy the retained response", "Network Exchange"},
        {"network.exchange.copy_headers", "Copy Headers", "Copy headers from the retained artifact", "Network Exchange"},
        {"network.exchange.copy_body", "Copy Body", "Copy the body from the retained artifact", "Network Exchange"},
        {"network.exchange.copy_artifact", "Copy Selected Artifact", "Copy the bounded retained artifact", "Network Exchange"},
        {"network.exchange.copy_curl", "Copy as cURL", "Copy the retained HTTP request as a cURL command", "Network Exchange"},
        {"network.exchange.related_comparer", "Send Related Artifact to Comparer", "Send the retained related exchange artifact to Comparer", "Network Exchange"},
        {"network.exchange.related_chat", "Send Related Evidence to Chat", "Attach the bounded related exchange artifact to AI Chat", "Network Exchange"},
        {"network.exchange.related_agent", "Assign Related Evidence to Agent", "Assign the bounded related exchange artifact to an agent", "Network Exchange"},
        {"network.exchange.scope_include", "Stage Include in Scope...", "Stage a reviewed scope inclusion rule", "Network Exchange"},
        {"network.exchange.scope_exclude", "Stage Exclude from Scope...", "Stage a reviewed scope exclusion rule", "Network Exchange"},
        {"network.exchange.save_export", "Save / Export Artifact...", "Export the retained artifact through a reviewed destination", "Network Exchange"},
        {"network.exchange.create_issue", "Create Issue from Artifact...", "Create a reviewed issue from the retained artifact", "Network Exchange"},
        {"network.exchange.chat", "Send Bounded Evidence to Chat", "Attach bounded exchange evidence to AI Chat", "Network Exchange"},
        {"network.exchange.agent", "Assign Bounded Evidence to Agent", "Assign bounded exchange evidence to an agent", "Network Exchange"},
        {"network.exchange.replay", "Replay / Send Now", "Replay the retained request after review", "Network Exchange"},
        {"network.exchange.remove", "Remove from History", "Remove the retained exchange after review", "Network Exchange"},
        {"network.proxy.filter_host", "Filter by Host", "Filter Proxy history by the retained request host", "Network Proxy"},
        {"network.proxy.filter_method", "Filter by Method", "Filter Proxy history by the retained request method", "Network Proxy"},
        {"network.proxy.clear_filter", "Clear Filter", "Clear the current Proxy history filter", "Network Proxy"},
        {"network.repeater.duplicate", "Duplicate Repeater Tab", "Duplicate the retained Repeater request into a new tab", "Network Repeater"},
        {"network.repeater.clear_response", "Clear Response Display", "Clear the retained Repeater response display", "Network Repeater"},
        {"network.websocket.copy_host", "Copy Host", "Copy the retained WebSocket frame host", "Network WebSocket"},
        {"network.websocket.filter_host", "Filter by Host", "Filter captured WebSocket frames by the retained host", "Network WebSocket"},
        {"network.websocket.toggle_follow", "Toggle Follow Tail", "Toggle captured WebSocket frame follow-tail behavior", "Network WebSocket"},
        {"network.websocket.open_editor", "Send to WebSocket Editor", "Stage the retained frame in WebSocket Editor when its backend supports import", "Network WebSocket"},
        {"network.comparer.copy_slot", "Copy Slot", "Copy the retained Comparer slot", "Network Comparer"},
        {"network.comparer.use_a", "Use as A", "Use the retained slot as Comparer input A", "Network Comparer"},
        {"network.comparer.use_b", "Use as B", "Use the retained slot as Comparer input B", "Network Comparer"},
        {"network.comparer.swap", "Swap A and B", "Swap the current Comparer inputs", "Network Comparer"},
        {"network.comparer.remove_review", "Remove Slot Permanently...", "Review permanent removal of the retained Comparer slot", "Network Comparer"},
        {"network.site_map.path.include", "Add Path to Scope", "Include the retained site-map path in scope", "Network Site Map"},
        {"network.site_map.path.exclude", "Exclude Path from Scope", "Exclude the retained site-map path from scope", "Network Site Map"},
        {"network.site_map.copy_url", "Copy URL", "Copy the retained site-map URL", "Network Site Map"},
        {"network.site_map.host.include", "Add Host to Scope", "Include the retained site-map host in scope", "Network Site Map"},
        {"network.site_map.host.exclude", "Exclude Host from Scope", "Exclude the retained site-map host from scope", "Network Site Map"},
        {"network.api.collection.remove_review", "Remove Collection...", "Review removal of the retained API collection", "Network API"},
        {"ai.provider.open_details", "Show Provider Details", "Open details for the retained AI provider", "AI Providers"},
        {"ai.provider.set_default_model", "Set Current Model as Default", "Persist the retained provider model as default", "AI Providers"},
        {"ai.provider.test_model", "Test Current Model", "Run a bounded connection test for the retained model", "AI Providers"},
        {"ai.provider.copy_provider_id", "Copy Provider ID", "Copy the retained provider identifier", "AI Providers"},
        {"ai.provider.copy_model_id", "Copy Model ID", "Copy the retained model identifier", "AI Providers"},
        {"ai.agent.set_active", "Set as Active Agent", "Set the retained agent as active", "AI Agents"},
        {"ai.agent.copy_name", "Copy Agent Name", "Copy the retained agent name", "AI Agents"},
        {"ai.agent.copy_description", "Copy Description", "Copy the retained agent description", "AI Agents"},
        {"ai.agent.duplicate", "Duplicate as Custom", "Duplicate the retained agent with generation-safe catalog ownership", "AI Agents"},
        {"ai.agent.delete_review", "Delete...", "Review deletion of the retained custom agent", "AI Agents"},
        {"ai.skill.copy_name", "Copy Skill Name", "Copy the retained skill name", "AI Skills"},
        {"ai.skill.copy_path", "Copy Skill Path", "Copy the retained skill source path", "AI Skills"},
        {"ai.skill.open_file", "Open File", "Open the retained skill source file", "AI Skills"},
        {"ai.skill.reload", "Reload", "Reload the retained skill catalog", "AI Skills"},
        {"ai.skill.toggle_enabled", "Enable / Disable", "Toggle the retained skill state", "AI Skills"},
        {"ai.skill.uninstall_review", "Uninstall...", "Review uninstalling the retained remote skill", "AI Skills"},
        {"mcp.marketplace.open_details", "Open Details", "Open details for the retained MCP package", "MCP Marketplace"},
        {"mcp.marketplace.review_install", "Review Install", "Review provenance and installation scope for the retained MCP package", "MCP Marketplace"},
        {"mcp.marketplace.copy_name", "Copy Package Name", "Copy the retained MCP package name", "MCP Marketplace"},
        {"mcp.marketplace.copy_version", "Copy Version", "Copy the retained MCP package version", "MCP Marketplace"},
        {"mcp.marketplace.copy_registry", "Copy Registry", "Copy the retained MCP registry", "MCP Marketplace"},
        {"mcp.marketplace.copy_source", "Copy Source", "Copy the retained MCP source", "MCP Marketplace"},
        {"mcp.marketplace.copy_launch_preview", "Copy Launch Preview", "Copy the reviewed launch preview for the retained MCP package", "MCP Marketplace"},
        {"ai.chat.conversation.open", "Open Conversation", "Open the retained conversation", "AI Chat"},
        {"ai.chat.conversation.fork", "Fork Conversation", "Fork the retained conversation", "AI Chat"},
        {"ai.chat.conversation.toggle_pin", "Pin / Unpin Conversation", "Toggle the retained conversation pin state", "AI Chat"},
        {"ai.chat.conversation.export", "Export Conversation as Markdown...", "Export the retained conversation", "AI Chat"},
        {"ai.chat.conversation.copy_id", "Copy Conversation ID", "Copy the retained conversation identifier", "AI Chat"},
        {"ai.chat.conversation.delete_review", "Delete Conversation...", "Review deleting the retained conversation", "AI Chat"},
        {"ai.chat.message.copy", "Copy Message", "Copy the retained AI message", "AI Chat"},
        {"ai.chat.message.copy_reasoning", "Copy Reasoning", "Copy reasoning from the retained AI message", "AI Chat"},
        {"ai.chat.message.copy_tool", "Copy Tool Name", "Copy the tool name from the retained AI message", "AI Chat"},
        {"ai.chat.message.edit", "Edit Message", "Edit the retained AI message", "AI Chat"},
        {"ai.chat.message.retry", "Retry From Here", "Retry AI Chat from the retained message", "AI Chat"},
        {"ai.chat.message.delete_review", "Delete Message...", "Review deleting the retained AI message", "AI Chat"},
        {"ai.chat.message.add_input", "Add to Chat Input", "Add the retained AI message to the chat input", "AI Chat"},
        {"ai.chat.message.create_evidence", "Add as Evidence", "Create bounded evidence from the retained AI message", "AI Chat"},
        {"ai.chat.message.inspect_tool", "Inspect Tool Activity", "Inspect tool activity for the retained AI message", "AI Chat"},
        {"ai.chat.message.review_change", "Review Staged Change", "Review the staged code change linked to the retained AI message", "AI Chat"},
        {"ai.chat.message.apply_review", "Apply Staged Change...", "Review applying the staged code change linked to the retained AI message", "AI Chat"},
        {"ai.chat.message.reject_change", "Reject Staged Change", "Reject the staged code change linked to the retained AI message", "AI Chat"},
        {"ai.chat.message.cancel_operation", "Cancel Active Operation", "Request cancellation of the retained AI operation", "AI Chat"},
        {"ai.evidence.return_source", "Return to Source", "Return to the retained evidence source", "AI Evidence"},
        {"ai.evidence.add_chat", "Add to Chat", "Add the retained evidence to AI Chat", "AI Evidence"},
        {"ai.evidence.assign_agent", "Assign to Agent", "Assign the retained evidence to an agent", "AI Evidence"},
        {"ai.evidence.copy_id", "Copy Evidence ID", "Copy the retained evidence identifier", "AI Evidence"}
    };
    static constexpr retained_action_definition_t analysis_context_retained_actions[] = {
        {"analysis.navigate.disassembly_side", "Open Disassembly to the Side", "Open the selected entity in a second disassembly document", "Analysis"},
        {"analysis.navigate.hex", "Open in Hex", "Navigate the selected address in the hex document", "Analysis"},
        {"analysis.navigate.functions", "Open in Functions", "Open the function list at the selected analysis context", "Analysis"},
        {"analysis.navigate.structures", "Open in Structures", "Open the type and structure workspace at the selected analysis context", "Analysis"},
        {"analysis.navigate.types", "Open in Type Views", "Open the type workspace at the selected analysis context", "Analysis"},
        {"analysis.navigate.xrefs_from", "Cross References From", "Show references originating from the selected entity", "Analysis"},
        {"analysis.navigate.callers", "Show Callers", "Show functions that call the selected function", "Analysis"},
        {"analysis.navigate.callees", "Show Callees", "Show functions called by the selected function", "Analysis"},
        {"analysis.copy.line", "Copy Line", "Copy address and rendered text", "Analysis"},
        {"analysis.copy.text", "Copy Text", "Copy rendered analysis text", "Analysis"},
        {"analysis.copy.address", "Copy Displayed Address", "Copy the address exactly as displayed in the listing", "Analysis"},
        {"analysis.copy.address_va", "Copy Virtual Address", "Copy the selected virtual address in canonical hexadecimal form", "Analysis"},
        {"analysis.copy.address_rva", "Copy RVA", "Copy the selected image-relative address", "Analysis"},
        {"analysis.copy.address_file", "Copy File Offset", "Copy the selected file offset", "Analysis"},
        {"analysis.copy.address_module", "Copy Module + Offset", "Copy the selected module-relative address", "Analysis"},
        {"analysis.copy.bytes", "Copy Bytes", "Copy rendered instruction bytes", "Analysis"},
        {"analysis.copy.instruction", "Copy Instruction", "Copy instruction text without the address", "Analysis"},
        {"analysis.copy.name", "Copy Name", "Copy the selected function or symbol name", "Analysis"},
        {"analysis.copy.block", "Copy Block", "Copy all rendered instructions in the selected graph block", "Analysis"},
        {"analysis.copy.block_addressed", "Copy Block with Addresses", "Copy graph block instructions with addresses", "Analysis"},
        {"analysis.copy.metadata", "Copy Metadata", "Copy the complete retained file metadata banner", "Analysis"},
        {"analysis.copy.metadata_line", "Copy Line Text", "Copy the retained metadata identity line", "Analysis"},
        {"analysis.copy.metadata_current_line", "Copy Current Line", "Copy the retained displayed metadata row", "Analysis"},
        {"analysis.copy.metadata_address", "Copy Address", "Copy the retained image base address", "Analysis"},
        {"analysis.select.metadata_all", "Select All Banner", "Select the complete file metadata banner", "Analysis"},
        {"analysis.modify.remove_bookmark", "Remove Bookmark", "Remove the selected address bookmark", "Analysis", true},
        {"analysis.debug.hardware_breakpoint", "Define Hardware Breakpoint...", "Use the debugger's explicit hardware-breakpoint definition controls at the selected address", "Analysis", true},
        {"analysis.function.decompile", "Decompile Function", "Decompile the enclosing function", "Analysis"},
        {"analysis.function.source", "Reconstruct Source", "Reconstruct source for the selected function", "Analysis"},
        {"analysis.function.aob", "Generate AOB Signature", "Generate a signature from the selected instruction", "Analysis"},
        {"analysis.export.line", "Export Selected Line", "Copy the complete selected listing row for export", "Analysis"},
        {"analysis.graph.fit", "Fit Graph", "Fit all graph blocks in the canvas", "Analysis"},
        {"analysis.graph.zoom_in", "Zoom In", "Increase graph canvas zoom", "Analysis"},
        {"analysis.graph.zoom_out", "Zoom Out", "Decrease graph canvas zoom", "Analysis"},
        {"analysis.graph.reset", "Reset View", "Reset graph pan and zoom", "Analysis"},
        {"analysis.graph.select_block", "Select Entire Block", "Select all instructions in the graph block", "Analysis"},
        {"analysis.graph.clear_selection", "Clear Selection", "Clear the graph text selection", "Analysis"},
		{"analysis.graph.navigate_source", "Go to Visible Source Block", "Navigate to an incoming source block present on the visible graph page", "Analysis"},
		{"analysis.graph.navigate_target", "Go to Visible Target", "Navigate to the selected instruction's direct target when present on the visible graph page", "Analysis"},
		{"analysis.graph.collapse_reachable", "Collapse Reachable on Visible Page", "Hide blocks reachable within the complete visible-page edge set", "Analysis"},
		{"analysis.graph.expand_reachable", "Expand Reachable on Visible Page", "Restore blocks hidden within the complete visible-page edge set", "Analysis"},
		{"analysis.graph.pin_node", "Pin Node Position", "Retain the selected node position across graph rebuilds", "Analysis"},
		{"analysis.graph.unpin_node", "Unpin Node Position", "Return the selected node to automatic graph layout", "Analysis"},
		{"analysis.graph.pin_layout", "Pin Layout", "Retain all current node positions across graph rebuilds", "Analysis"},
		{"analysis.graph.unpin_layout", "Unpin Layout", "Return the graph to automatic layout", "Analysis"},
        {"analysis.view.va", "Virtual Address Format", "Display virtual addresses", "Analysis"},
        {"analysis.view.rva", "Relative Address Format", "Display image-relative addresses", "Analysis"},
        {"analysis.view.file_offset", "File Offset Format", "Display file offsets where available", "Analysis"},
        {"analysis.view.bytes", "Show Bytes", "Show or hide instruction bytes", "Analysis"},
        {"analysis.view.full_line", "Full-Line Selection", "Select the complete disassembly row", "Analysis"},
        {"analysis.evidence.chat", "Send to AI Chat", "Attach the selected analysis evidence to AI chat", "Analysis"},
        {"analysis.evidence.agent", "Send to Agent", "Attach the selected analysis evidence to an agent workflow", "Analysis"}
    };
    static constexpr retained_action_definition_t analysis_type_retained_actions[] = {
        {"analysis.fuzzer.crash.ai_analyze", "AI Analyze Crash", "Analyze the retained crash with AI", "Analysis"},
        {"analysis.fuzzer.crash.minimize", "Minimize Crash", "Minimize the retained crash reproducer", "Analysis"},
        {"analysis.fuzzer.crash.copy_instruction_address", "Copy Instruction Address", "Copy the retained crash instruction address", "Analysis"},
        {"analysis.fuzzer.crash.copy_hash", "Copy Crash Hash", "Copy the retained crash hash", "Analysis"},
        {"analysis.fuzzer.crash.copy_description", "Copy Description", "Copy the retained crash description", "Analysis"},
        {"analysis.fuzzer.crash.copy_input_hex", "Copy Input Hex (first 64 KiB)", "Copy a bounded retained crash input", "Analysis"},
        {"analysis.protection.finding.follow_disassembly", "Follow in Disassembly", "Open the retained protection finding address", "Protection"},
        {"analysis.protection.finding.copy_address", "Copy Address", "Copy the retained protection finding address", "Protection"},
        {"analysis.protection.finding.copy_title", "Copy Finding", "Copy the retained finding title", "Protection"},
        {"analysis.protection.finding.copy_details", "Copy Details", "Copy the retained finding details", "Protection"},
        {"analysis.protection.finding.copy_module", "Copy Module", "Copy the retained finding module", "Protection"},
        {"memory.integrity.reader.neutralize", "Neutralize...", "Neutralize the retained integrity reader", "Integrity Hunter"},
        {"memory.integrity.reader.restore", "Restore Original...", "Restore the retained integrity reader", "Integrity Hunter"},
        {"memory.integrity.reader.follow_disassembly", "Go to Disassembly", "Open the retained integrity reader", "Integrity Hunter"},
        {"memory.integrity.reader.decompile", "Decompile Reader", "Decompile the retained integrity reader", "Integrity Hunter"},
        {"analysis.binary_map.function.follow_disassembly", "Jump to Disassembly", "Open the retained function in Disassembly", "Binary Map"},
        {"analysis.binary_map.function.open_hex", "Open in Hex View", "Open the retained function in Hex", "Binary Map"},
        {"analysis.binary_map.function.send_chat", "Copy Summary to Chat", "Attach the retained function summary to AI Chat", "Binary Map"},
        {"analysis.binary_map.function.pin", "Pin", "Pin the retained function", "Binary Map"},
        {"analysis.binary_map.function.unpin", "Unpin", "Unpin the retained function", "Binary Map"},
        {"analysis.binary_map.function.copy_va", "Copy VA", "Copy the retained function address", "Binary Map"},
        {"analysis.binary_map.function.copy_name", "Copy Name", "Copy the retained function name", "Binary Map"},
        {"analysis.binary_map.region.follow_disassembly", "Jump to Disassembly", "Open the retained region in Disassembly", "Binary Map"},
        {"analysis.binary_map.region.open_hex", "Open in Hex View", "Open the retained region in Hex", "Binary Map"},
        {"analysis.binary_map.region.dump", "Dump Region...", "Export the retained region", "Binary Map"},
        {"analysis.binary_map.region.change_protection", "Change Protection...", "Review a protection change for the retained region", "Binary Map"},
        {"analysis.binary_map.region.copy_va", "Copy VA", "Copy the retained region address", "Binary Map"},
        {"analysis.binary_map.region.copy_json", "Copy as JSON", "Copy the retained region as JSON", "Binary Map"},
        {"analysis.binary_map.region.send_chat", "Copy Summary to Chat", "Attach the retained region summary to AI Chat", "Binary Map"},
        {"analysis.binary_map.module.follow_disassembly", "Jump to Disassembly", "Open the retained module in Disassembly", "Binary Map"},
        {"analysis.binary_map.module.open_hex", "Open in Hex View", "Open the retained module in Hex", "Binary Map"},
        {"analysis.binary_map.module.copy_name", "Copy Module Name", "Copy the retained module name", "Binary Map"},
        {"analysis.binary_map.module.copy_path", "Copy Module Path", "Copy the retained module path", "Binary Map"},
        {"analysis.binary_map.section.follow_disassembly", "Jump to Disassembly", "Open the retained section in Disassembly", "Binary Map"},
        {"analysis.binary_map.section.open_hex", "Open in Hex View", "Open the retained section in Hex", "Binary Map"},
        {"analysis.binary_map.section.dump", "Dump Section...", "Export the retained section", "Binary Map"},
        {"analysis.binary_map.section.copy_name", "Copy Section Name", "Copy the retained section name", "Binary Map"},
        {"analysis.binary_map.section.copy_va", "Copy Section VA", "Copy the retained section address", "Binary Map"},
        {"analysis.binary_map.global.send_chat", "Copy Summary to Chat", "Attach the retained global summary to AI Chat", "Binary Map"},
        {"analysis.binary_map.global.open_hex", "Open in Hex View", "Open the retained global in Hex", "Binary Map"},
        {"analysis.binary_map.global.follow_disassembly", "Jump to Disassembly", "Open the retained global in Disassembly", "Binary Map"},
        {"analysis.binary_map.global.copy_va", "Copy VA", "Copy the retained global address", "Binary Map"},
        {"analysis.binary_map.global.copy_name", "Copy Name", "Copy the retained global name", "Binary Map"},
        {"analysis.binary_map.import.copy_dll_name", "Copy DLL Name", "Copy the retained import DLL name", "Binary Map"},
        {"analysis.binary_map.import.copy_function_list", "Copy Function List", "Copy retained imported functions", "Binary Map"},
        {"analysis.binary_map.import.copy_qualified_name", "Copy DLL!fn", "Copy the retained qualified import", "Binary Map"},
        {"analysis.binary_map.import.copy_function_name", "Copy Function Name", "Copy the retained imported function name", "Binary Map"},
        {"analysis.binary_map.export.follow_disassembly", "Jump to Disassembly", "Open the retained export in Disassembly", "Binary Map"},
        {"analysis.binary_map.export.copy_name", "Copy Export Name", "Copy the retained export name", "Binary Map"},
        {"types.catalog.copy_name", "Copy Name", "Copy the retained catalog name", "Types"},
        {"types.catalog.copy_ida_declaration", "Copy IDA-style Declaration", "Copy the retained IDA-style declaration", "Types"},
		{"types.catalog.export_declaration", "Export Declaration", "Export the retained bounded type declaration", "Types"},
		{"types.catalog.duplicate_to_editor", "Duplicate as Editable Copy", "Create and persist a validated editable copy", "Types"},
        {"types.catalog.open_structure_editor", "Open in Structure Editor", "Open the retained type in Structure Editor", "Types"},
        {"types.catalog.rename", "Rename Type...", "Rename the retained type", "Types"},
        {"types.catalog.delete", "Delete Type...", "Delete the retained type", "Types"},
        {"types.catalog.edit_enum", "Edit Enum...", "Edit the retained enum", "Types"},
        {"types.catalog.function.follow_disassembly", "Jump to Disassembly", "Open the retained typed function", "Types"},
        {"types.catalog.function.open_pseudocode", "Open Pseudocode", "Decompile the retained typed function", "Types"},
        {"types.catalog.function.copy_signature", "Copy Signature", "Copy the retained function signature", "Types"},
        {"types.catalog.function.copy_address", "Copy Address", "Copy the retained function address", "Types"},
        {"types.catalog.function.retype", "Retype Function...", "Retype the retained function", "Types"},
        {"types.catalog.copy_canonical_type", "Copy Canonical Type", "Copy the retained canonical type", "Types"},
        {"types.catalog.evidence.follow_disassembly", "Jump to Evidence Address", "Open retained type evidence", "Types"},
        {"types.catalog.promote_global", "Review Global Promotion...", "Review the retained type before global overlay promotion", "Types"},
        {"types.reconstruction.field.follow_disassembly", "Open Field in Disassembly", "Open the retained reconstructed field", "Types"},
        {"types.reconstruction.field.copy_name", "Copy Field Name", "Copy the retained reconstructed field name", "Types"},
        {"types.reconstruction.field.copy_type", "Copy Field Type", "Copy the retained reconstructed field type", "Types"},
        {"types.reconstruction.field.copy_offset", "Copy Offset", "Copy the retained reconstructed field offset", "Types"},
        {"types.reconstruction.field.copy_absolute_address", "Copy Absolute Address", "Copy the retained reconstructed field address", "Types"},
        {"types.reconstruction.field.copy_access_evidence", "Copy Access Evidence", "Copy retained field access evidence", "Types"},
        {"types.reconstruction.field.declare_apply", "Review Declaration and Application...", "Review the retained reconstruction before one atomic overlay transaction", "Types"},
        {"types.reconstruction.field.rename", "Rename Field...", "Rename the retained reconstructed field", "Types"},
        {"types.reconstruction.field.set_type", "Set Field Type...", "Retype the retained reconstructed field", "Types"},
        {"types.reconstruction.field.edit_live", "Edit Live Value...", "Edit the retained reconstructed field value", "Types"},
		{"types.dissector.structure.copy_name", "Copy Structure Name", "Copy the retained structure name", "Types"},
		{"types.dissector.structure.copy_declaration", "Copy C/C++ Declaration", "Copy the retained structure declaration", "Types"},
		{"types.dissector.structure.export_declaration", "Export Declaration", "Export the retained bounded structure declaration", "Types"},
		{"types.dissector.structure.duplicate", "Duplicate Structure", "Duplicate and persist the retained structure", "Types"},
		{"types.dissector.structure.review_global_overlay", "Review Global Declaration...", "Review the retained declaration before global overlay propagation", "Types"},
		{"types.dissector.structure.configure_layout", "Configure Layout...", "Configure retained structure kind, packing, and alignment", "Types"},
		{"types.dissector.structure.toggle_union", "Convert Struct / Union", "Toggle the retained structure layout kind", "Types"},
		{"types.dissector.structure.save_catalog", "Save Structure Catalog", "Atomically save the retained structure catalog", "Types"},
		{"types.dissector.structure.load_catalog", "Load Structure Catalog", "Load and validate the durable structure catalog", "Types"},
		{"types.dissector.enum.export_declaration", "Export Enum Declaration", "Export the retained bounded enum declaration", "Types"},
		{"types.dissector.enum.duplicate", "Duplicate Enum", "Duplicate and persist the retained enum", "Types"},
		{"types.dissector.enum.review_global_overlay", "Review Enum Globally...", "Review the enum before global overlay propagation", "Types"},
		{"types.dissector.field.copy_name", "Copy Field Name", "Copy the retained dissector field name", "Types"},
		{"types.dissector.field.export_declaration", "Export Field Declaration", "Export the retained bounded field declaration", "Types"},
		{"types.dissector.field.duplicate", "Duplicate Field", "Duplicate and persist the retained top-level field", "Types"},
		{"types.dissector.field.review_containing_type_global", "Review Containing Type Globally...", "Review the containing declaration before global overlay propagation", "Types"},
        {"types.dissector.field.copy_offset", "Copy Offset", "Copy the retained dissector field offset", "Types"},
        {"types.dissector.field.copy_absolute_address", "Copy Absolute Address", "Copy the retained dissector field address", "Types"},
        {"types.dissector.field.copy_current_value", "Copy Current Value", "Copy the retained live field value", "Types"},
        {"types.dissector.field.edit_live_value", "Edit Live Value...", "Review editing the retained live field", "Types"},
        {"types.dissector.field.refresh_live_value", "Refresh Live Value", "Refresh the retained live field", "Types"},
        {"types.dissector.field.rename", "Rename Field...", "Rename the retained dissector field", "Types"},
        {"types.dissector.field.set_size", "Set Size...", "Set the retained dissector field size", "Types"},
        {"types.dissector.field.set_comment", "Set Comment...", "Set the retained dissector field comment", "Types"},
        {"types.dissector.field.set_array_count", "Set Array Count...", "Set the retained field array count", "Types"},
        {"types.dissector.field.choose_nested", "Choose Nested Structure...", "Choose a nested type for the retained field", "Types"},
		{"types.dissector.field.choose_pointer_target", "Choose Pointer Target...", "Choose a pointee structure for the retained field", "Types"},
		{"types.dissector.field.choose_enum", "Choose Enum...", "Apply an enum definition to the retained field", "Types"},
        {"types.dissector.field.configure_bitfield", "Configure Bitfield...", "Configure the retained field bit layout", "Types"},
        {"types.dissector.field.set_alignment", "Set Alignment...", "Set alignment for the retained field", "Types"},
		{"types.dissector.field.insert_before", "Insert Field Before...", "Insert a field before the retained field", "Types"},
		{"types.dissector.field.insert_after", "Insert Field After...", "Insert a field after the retained field", "Types"},
		{"types.dissector.field.move_up", "Move Field Up", "Move the retained field up", "Types"},
		{"types.dissector.field.move_down", "Move Field Down", "Move the retained field down", "Types"},
        {"types.dissector.field.remove", "Remove Field...", "Review removing the retained field", "Types"}
    };
    const auto retained_surfaces = action_surface_t::context_menu |
        action_surface_t::accessibility;
    for (const auto& definition : retained_actions) {
        const std::string retained_id = definition.id;
        const bool toolbar_retained = retained_id == "workspace.load_named" ||
            retained_id == "debugger.patch.apply" ||
            retained_id == "debugger.patch.remove" ||
            retained_id == "network.exchange.repeater" ||
            retained_id == "network.exchange.copy_url" ||
            retained_id == "network.exchange.fuzzer";
        const bool shortcut_retained = retained_id == "memory.address.remove" ||
            retained_id == "debugger.source.remove";
        auto definition_surfaces = retained_surfaces;
        if (toolbar_retained)
            definition_surfaces = definition_surfaces | action_surface_t::toolbar;
        if (retained_id == "workspace.load_named")
            definition_surfaces = definition_surfaces |
                action_surface_t::application_menu;
        if (shortcut_retained)
            definition_surfaces = definition_surfaces |
                action_surface_t::shortcut;
        register_action(rt, definition.id, definition.label, definition.description,
            definition_surfaces,
            [retained_id](const action_invocation_t& invocation) {
                return invoke_retained_entity_action(invocation, retained_id);
            },
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_capability(context, retained_id);
            }, definition.undoable,
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_check_state(context, retained_id);
            }, "category.retained_entity", definition.category);
    }
    for (const auto& definition : analysis_context_retained_actions) {
        const std::string retained_id = definition.id;
        register_action(rt, definition.id, definition.label, definition.description,
            retained_surfaces,
            [retained_id](const action_invocation_t& invocation) {
                return invoke_retained_entity_action(invocation, retained_id);
            },
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_capability(context, retained_id);
            }, definition.undoable,
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_check_state(context, retained_id);
            }, "category.retained_entity", definition.category);
    }
    register_document_shortcut(rt, "binding.analysis.patch_bytes", "analysis.modify.patch",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_P, "Ctrl+Alt+P", k_disassembly_scope, 30);
    register_document_shortcut(rt, "binding.analysis.patch_nop", "analysis.modify.nop",
        ImGuiMod_Ctrl | ImGuiMod_Alt | ImGuiKey_N, "Ctrl+Alt+N", k_disassembly_scope, 30);
    for (const auto& definition : analysis_type_retained_actions) {
        const std::string retained_id = definition.id;
        register_action(rt, definition.id, definition.label, definition.description,
            retained_surfaces,
            [retained_id](const action_invocation_t& invocation) {
                return invoke_retained_entity_action(invocation, retained_id);
            },
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_capability(context, retained_id);
            }, definition.undoable,
            [retained_id](const interaction_context_t& context) {
                return retained_entity_action_check_state(context, retained_id);
            }, "category.retained_entity", definition.category);
    }
    for (int index = 0; index < 64; ++index) {
        const std::string id = "types.reconstruction.field.follow_access." +
            std::to_string(index + 1);
        const std::string label = "Follow Access Reference " + std::to_string(index + 1);
        register_action(rt, id.c_str(), label.c_str(),
            "Open the retained field access reference in Disassembly", retained_surfaces,
            [id](const action_invocation_t& invocation) {
                return invoke_retained_entity_action(invocation, id);
            }, [id](const interaction_context_t& context) {
                return retained_entity_action_capability(context, id);
            }, false, {}, "category.retained_entity", "Types");
    }
    static constexpr const char* dissector_type_labels[] = {
        "Change Type to Int8", "Change Type to UInt8", "Change Type to Int16",
        "Change Type to UInt16", "Change Type to Int32", "Change Type to UInt32",
        "Change Type to Int64", "Change Type to UInt64", "Change Type to Float",
        "Change Type to Double", "Change Type to Pointer", "Change Type to ASCII String",
        "Change Type to UTF-16 String", "Change Type to Byte Array",
        "Change Type to Padding", "Change Type to Struct"};
    for (std::size_t index = 0; index < std::size(dissector_type_labels); ++index) {
        const std::string id = "types.dissector.field.change_type." + std::to_string(index);
        register_action(rt, id.c_str(), dissector_type_labels[index],
            "Retype the retained dissector field", retained_surfaces,
            [id](const action_invocation_t& invocation) {
                return invoke_retained_entity_action(invocation, id);
            }, [id](const interaction_context_t& context) {
                return retained_entity_action_capability(context, id);
            }, false, {}, "category.retained_entity", "Types");
    }

    const auto analysis_navigation = analysis_context_menu_section(
        "section.analysis.navigate", "Navigate", context_menu_group_t::open_navigate, 0, {
            analysis_context_menu_action("analysis.navigate.back", 0, nullptr, "Back",
                "Return to the previous analysis location"),
            analysis_context_menu_action("analysis.navigate.forward", 1, nullptr, "Forward",
                "Advance to the next analysis location"),
            analysis_context_menu_action("analysis.navigate.disassembly", 2, nullptr,
                "Open in Disassembly", "Navigate the selected entity in the disassembly document"),
            analysis_context_menu_action("analysis.navigate.disassembly_side", 3),
            analysis_context_menu_action("analysis.navigate.hex", 4),
            analysis_context_menu_action("analysis.navigate.follow", 5),
            analysis_context_menu_action("analysis.navigate.graph", 6, nullptr, "Open in Graph",
                "Open the selected function in graph representation",
                "analysis.toggle_graph_text"),
            analysis_context_menu_action("analysis.navigate.pseudocode", 7, nullptr,
                "Open in Pseudocode", "Open or decompile the selected function as pseudocode",
                "analysis.decompile_or_focus_pseudocode"),
            analysis_context_menu_action("analysis.navigate.functions", 8),
            analysis_context_menu_action("analysis.navigate.structures", 9),
            analysis_context_menu_action("analysis.navigate.types", 10)});
    const auto analysis_inspect = analysis_context_menu_section(
        "section.analysis.inspect", "References", context_menu_group_t::inspect_relate, 1, {
            analysis_context_menu_action("analysis.navigate.xrefs", 0, nullptr, "Cross References To",
                "Show references that target the selected entity"),
            analysis_context_menu_action("analysis.navigate.xrefs_from", 1),
            analysis_context_menu_action("analysis.navigate.callers", 2),
            analysis_context_menu_action("analysis.navigate.callees", 3)});
    const auto analysis_copy = analysis_context_menu_section(
        "section.analysis.copy", "Copy", context_menu_group_t::copy_export, 2, {
            analysis_context_menu_action("analysis.copy.line", 0),
            analysis_context_menu_action("analysis.copy.text", 1, "Ctrl+C"),
            analysis_context_menu_action("analysis.copy.address", 2),
            analysis_context_menu_action("analysis.copy.bytes", 3),
            analysis_context_menu_action("analysis.copy.instruction", 4),
            analysis_context_menu_action("analysis.copy.name", 5),
            analysis_context_menu_action("analysis.copy.address_va", 6),
            analysis_context_menu_action("analysis.copy.address_rva", 7),
            analysis_context_menu_action("analysis.copy.address_file", 8),
            analysis_context_menu_action("analysis.copy.address_module", 9),
            analysis_context_menu_action("analysis.export.line", 10),
            analysis_context_menu_action("analysis.export.listing", 11)});
    const auto analysis_modify = analysis_context_menu_section(
        "section.analysis.modify", "Modify", context_menu_group_t::modify_run, 3, {
            analysis_context_menu_action("analysis.modify.rename", 0, nullptr, "Rename",
                "Rename the selected symbol"),
            analysis_context_menu_action("analysis.modify.retype", 1, nullptr, "Set Type",
                "Apply a type to the selected analysis entity"),
            analysis_context_menu_action("analysis.modify.comment", 2, nullptr, "Edit Comment",
                "Add or edit the selected entity comment"),
            analysis_context_menu_action("analysis.modify.bookmark", 3, nullptr, "Add Bookmark",
                "Bookmark the selected address"),
            analysis_context_menu_action("analysis.modify.remove_bookmark", 4),
            analysis_context_menu_action("analysis.modify.patch", 5),
            analysis_context_menu_action("analysis.modify.assemble", 6),
            analysis_context_menu_action("analysis.modify.nop", 7),
            analysis_context_menu_action("analysis.debug.breakpoint", 8),
            analysis_context_menu_action("analysis.debug.run_to_cursor", 9),
            analysis_context_menu_action("analysis.debug.hardware_breakpoint", 10)});
    const auto analysis_transform = analysis_context_menu_section(
        "section.analysis.transform", "Represent and Transform",
        context_menu_group_t::modify_run, 4, {
            analysis_context_menu_action("analysis.function.decompile", 0),
            analysis_context_menu_action("analysis.function.source", 1),
            analysis_context_menu_action("analysis.function.aob", 2)});
    const auto analysis_ai = analysis_context_menu_section(
        "section.analysis.ai", "AI and Evidence", context_menu_group_t::ai_evidence, 5, {
            analysis_context_menu_action("analysis.evidence.chat", 0),
            analysis_context_menu_action("analysis.evidence.agent", 1)});
    const auto analysis_display = analysis_context_menu_section(
        "section.analysis.display", "Display", context_menu_group_t::open_navigate, 4, {
            analysis_context_menu_action("analysis.view.va", 0),
            analysis_context_menu_action("analysis.view.rva", 1),
            analysis_context_menu_action("analysis.view.file_offset", 2),
            analysis_context_menu_action("analysis.view.bytes", 3),
            analysis_context_menu_action("analysis.view.full_line", 4)});
    register_menu(rt, "menu.analysis.instruction", k_retained_entity_context_type,
        {analysis_navigation, analysis_inspect, analysis_copy, analysis_modify,
         analysis_display, analysis_transform, analysis_ai});
    register_menu(rt, "menu.analysis.pseudocode", k_retained_entity_context_type,
        {analysis_navigation, analysis_inspect, analysis_copy, analysis_modify, analysis_ai});
    register_menu(rt, "menu.analysis.function", k_retained_entity_context_type,
        {analysis_navigation, analysis_inspect, analysis_copy, analysis_modify,
         analysis_transform, analysis_ai});
    register_menu(rt, "menu.analysis.xref", k_retained_entity_context_type,
        {analysis_navigation, analysis_copy, analysis_inspect, analysis_ai});
    register_menu(rt, "menu.analysis.metadata", k_retained_entity_context_type, {
        analysis_context_menu_section("section.analysis.metadata.copy", "Copy",
            context_menu_group_t::copy_export, 0, {
                analysis_context_menu_action("analysis.copy.metadata", 0, "Ctrl+C"),
                analysis_context_menu_action("analysis.copy.metadata_line", 1),
                analysis_context_menu_action("analysis.copy.metadata_current_line", 2),
                analysis_context_menu_action("analysis.copy.metadata_address", 3)}),
        analysis_context_menu_section("section.analysis.metadata.select", "Select",
            context_menu_group_t::inspect_relate, 1, {
                analysis_context_menu_action("analysis.select.metadata_all", 0)})});
    register_menu(rt, "menu.analysis.graph", k_retained_entity_context_type, {
        analysis_navigation,
		analysis_context_menu_section("section.graph.navigate", "Graph Navigation",
			context_menu_group_t::open_navigate, 1, {
				analysis_context_menu_action("analysis.graph.navigate_source", 0),
				analysis_context_menu_action("analysis.graph.navigate_target", 1, "Enter")}),
        analysis_context_menu_section("section.graph.canvas", "Graph",
			context_menu_group_t::open_navigate, 2, {
                analysis_context_menu_action("analysis.graph.fit", 0),
                analysis_context_menu_action("analysis.graph.zoom_in", 1),
                analysis_context_menu_action("analysis.graph.zoom_out", 2),
                analysis_context_menu_action("analysis.graph.reset", 3),
                analysis_context_menu_action("analysis.graph.select_block", 4),
				analysis_context_menu_action("analysis.graph.clear_selection", 5),
				analysis_context_menu_action("analysis.graph.collapse_reachable", 6),
				analysis_context_menu_action("analysis.graph.expand_reachable", 7),
				analysis_context_menu_action("analysis.graph.pin_node", 8),
				analysis_context_menu_action("analysis.graph.unpin_node", 9),
				analysis_context_menu_action("analysis.graph.pin_layout", 10),
				analysis_context_menu_action("analysis.graph.unpin_layout", 11)}),
        analysis_context_menu_section("section.graph.copy", "Copy",
			context_menu_group_t::copy_export, 3, {
                analysis_context_menu_action("analysis.copy.block", 0),
                analysis_context_menu_action("analysis.copy.block_addressed", 1),
                analysis_context_menu_action("analysis.copy.address", 2)}),
        analysis_modify, analysis_inspect, analysis_transform, analysis_ai});

    capture_default_shortcuts(rt);
    apply_persisted_shortcut_overrides(rt);

    register_menu(rt, "menu.editor.text", k_editor_context_type, {
        menu_section("section.editor.history", context_menu_group_t::modify_run, 0, {menu_action("edit.undo", 0), menu_action("edit.redo", 1)}),
        menu_section("section.editor.clipboard", context_menu_group_t::copy_export, 1,
            {menu_action("edit.cut", 0), menu_action("edit.copy", 1), menu_action("edit.paste", 2),
             menu_action("edit.delete", 3), menu_action("edit.select_all", 4),
             menu_action("edit.select_word", 5), menu_action("edit.select_line", 6),
             menu_action("edit.copy_line", 7), menu_action("edit.copy_path", 8),
             menu_action("edit.copy_relative_path", 9),
             menu_action("editor.reveal_in_explorer", 10)}),
        menu_section("section.editor.lines", context_menu_group_t::modify_run, 2,
            {menu_action("edit.duplicate_line", 0), menu_action("edit.delete_line", 1),
             menu_action("edit.move_line_up", 2), menu_action("edit.move_line_down", 3),
             menu_action("edit.toggle_line_comment", 4),
             menu_action("edit.trim_trailing_whitespace", 5)}),
        menu_section("section.editor.navigate", context_menu_group_t::open_navigate, 3,
            {menu_action("edit.find", 0), menu_action("edit.replace", 1),
             menu_action("edit.goto_line", 2)}),
        menu_section("section.editor.language", context_menu_group_t::inspect_relate, 4,
            {menu_action("programming.language.definition", 0),
             menu_action("programming.language.declaration", 1),
             menu_action("programming.language.implementation", 2),
             menu_action("programming.language.type_definition", 3),
             menu_action("programming.language.references", 4),
             menu_action("programming.language.completion", 5),
             menu_action("programming.language.hover", 6),
             menu_action("programming.language.signature_help", 7),
             menu_action("programming.language.rename", 8),
             menu_action("programming.language.format_selection", 9),
             menu_action("programming.language.format", 10),
             menu_action("programming.language.code_actions", 11),
             menu_action("programming.language.document_symbols", 12)}),
        menu_section("section.editor.diagnostics", context_menu_group_t::inspect_relate, 5,
            {menu_action("programming.task.run", 0), menu_action("programming.task.cancel", 1),
             menu_action("programming.show_problems", 2), menu_action("programming.task.configure", 3),
             menu_action("programming.language.diagnostics", 4)}),
		menu_section("section.editor.source_debug", context_menu_group_t::modify_run, 6,
			{menu_action("debug.source.toggle_breakpoint", 0),
			 menu_action("debug.source.open_mixed", 1),
			 menu_action("debug.source.rebind", 2),
             menu_action("programming.run.selection", 3),
             menu_action("programming.debug.selection", 4),
             menu_action("programming.test.selection", 5),
             menu_action("programming.run.file", 6),
             menu_action("programming.debug.file", 7),
             menu_action("programming.test.file", 8),
             menu_action("debug.selection.watch", 9),
             menu_action("debug.selection.evaluate", 10)}),
        menu_section("section.editor.ai", context_menu_group_t::ai_evidence, 7,
            {menu_action("editor.ai.explain", 0),
             menu_action("editor.ai.refactor", 1),
             menu_action("editor.ai.fix", 2),
             menu_action("editor.ai.generate_tests", 3),
             menu_action("editor.add_to_chat", 4),
             menu_action("editor.ai.previous_pending_hunk", 5),
             menu_action("editor.ai.next_pending_hunk", 6),
             menu_action("editor.ai.accept_current_hunk", 7),
             menu_action("editor.ai.reject_current_hunk", 8),
             menu_action("editor.ai.accept_hunk", 9),
             menu_action("editor.ai.reject_hunk", 10),
             menu_action("editor.ai.accept_all", 11),
             menu_action("editor.ai.reject_all", 12)}),
        menu_section("section.editor.file", context_menu_group_t::modify_run, 8,
            {menu_action("file.quick_open", 0), menu_action("file.save", 1),
             menu_action("file.save_as", 2), menu_action("file.save_all", 3),
             menu_action("file.close", 4), menu_action("file.close_all", 5)})
    });
    register_menu(rt, "menu.editor.review", k_editor_context_type, {
        menu_section("section.editor.review.navigate", context_menu_group_t::open_navigate, 0,
            {menu_action("editor.ai.previous_pending_hunk", 0),
             menu_action("editor.ai.next_pending_hunk", 1)}),
        menu_section("section.editor.review.current", context_menu_group_t::modify_run, 1,
            {menu_action("editor.ai.accept_current_hunk", 0),
             menu_action("editor.ai.reject_current_hunk", 1),
             menu_action("editor.ai.accept_hunk", 2),
             menu_action("editor.ai.reject_hunk", 3)}),
        menu_section("section.editor.review.all", context_menu_group_t::modify_run, 2,
            {menu_action("editor.ai.accept_all", 0),
             menu_action("editor.ai.reject_all", 1)})
    });
    register_menu(rt, "menu.editor.tab", k_tab_context_type, {
        menu_section("section.tab.reopen", context_menu_group_t::open_navigate, 0,
            {menu_action("file.reopen_closed_document", 0)}),
        menu_section("section.tab.file", context_menu_group_t::modify_run, 0,
            {menu_action("tab.save", 0), menu_action("file.save_all", 1),
             menu_action("tab.compare_disk", 2), menu_action("tab.close", 3),
             menu_action("tab.close_others", 4), menu_action("tab.close_right", 5),
             menu_action("tab.close_saved", 6)}),
        menu_section("section.tab.group", context_menu_group_t::open_navigate, 1,
            {menu_action("tab.toggle_pin", 0), menu_action("tab.move_new_group", 1),
             menu_action("tab.split_left", 2), menu_action("tab.split_right", 3),
             menu_action("tab.split_up", 4), menu_action("tab.split_down", 5),
             menu_action("tab.move_primary_group", 6), menu_action("tab.float_group", 7),
             menu_action("tab.history_back", 8), menu_action("tab.history_forward", 9),
             menu_action("tab.reveal_in_explorer", 10)}),
        menu_section("section.tab.copy", context_menu_group_t::copy_export, 2,
            {menu_action("tab.copy_path", 0), menu_action("tab.copy_relative_path", 1),
             menu_action("tab.copy_name", 2)}),
        menu_section("section.tab.recovery", context_menu_group_t::inspect_relate, 3,
            {menu_action("tab.recovery.recover", 0),
             menu_action("tab.recovery.compare", 1),
             menu_action("tab.recovery.discard", 2)}),
        menu_section("section.tab.tasks", context_menu_group_t::inspect_relate, 4,
            {menu_action("programming.task.run", 0), menu_action("programming.show_problems", 1),
             menu_action("programming.task.configure", 2)}),
        menu_section("section.tab.ai", context_menu_group_t::ai_evidence, 5,
            {menu_action("tab.add_to_chat", 0)})
    });
    register_menu(rt, "menu.explorer.entry", k_explorer_entry_context_type, {
        menu_section("section.explorer.open", context_menu_group_t::open_navigate, 0,
            {menu_action("explorer.open", 0), menu_action("explorer.open_with", 1),
             menu_action("explorer.analyze_binary", 2), menu_action("explorer.terminal_here", 3),
             menu_action("explorer.set_workspace_root", 4), menu_action("explorer.search_here", 5)}),
        menu_section("section.explorer.modify", context_menu_group_t::modify_run, 1,
            {menu_action("explorer.new_file", 0), menu_action("explorer.new_folder", 1),
             menu_action("explorer.rename", 2), menu_action("explorer.cut", 3),
             menu_action("explorer.copy_item", 4), menu_action("explorer.paste", 5),
             menu_action("explorer.duplicate", 6)}),
        menu_section("section.explorer.copy", context_menu_group_t::copy_export, 2,
            {menu_action("explorer.copy_path", 0), menu_action("explorer.copy_relative_path", 1),
             menu_action("explorer.copy_name", 2)}),
        menu_section("section.explorer.refresh", context_menu_group_t::inspect_relate, 3, {menu_action("explorer.refresh", 0)}),
        menu_section("section.explorer.tasks", context_menu_group_t::modify_run, 4,
            {menu_action("explorer.run_configured_target", 0),
             menu_action("explorer.debug_configured_target", 1),
             menu_action("programming.task.configure", 2)}),
        menu_section("section.explorer.ai", context_menu_group_t::ai_evidence, 5,
            {menu_action("explorer.add_to_chat", 0)}),
        menu_section("section.explorer.delete", context_menu_group_t::destructive, 6,
            {menu_action("explorer.delete", 0)})
    });
    register_menu(rt, "menu.explorer.empty", k_explorer_empty_context_type, {
        menu_section("section.explorer.workspace", context_menu_group_t::open_navigate, 0,
            {menu_action("file.quick_open", 0), menu_action("file.open_folder", 1),
             menu_action("explorer.search", 2), menu_action("explorer.refresh", 3)}),
        menu_section("section.explorer.create", context_menu_group_t::modify_run, 1,
            {menu_action("explorer.new_file", 0), menu_action("explorer.new_folder", 1),
             menu_action("explorer.paste", 2), menu_action("explorer.terminal_here", 3)}),
        menu_section("section.explorer.tasks", context_menu_group_t::modify_run, 2,
            {menu_action("programming.task.run", 0), menu_action("programming.task.configure", 1),
             menu_action("programming.task.reload", 2)})
    });
    register_menu(rt, "menu.workspace_search.result", k_workspace_search_context_type, {
        menu_section("section.workspace_search.open", context_menu_group_t::open_navigate, 0, {menu_action("workspace_search.open", 0)}),
        menu_section("section.workspace_search.copy", context_menu_group_t::copy_export, 1, {menu_action("workspace_search.copy_path", 0), menu_action("workspace_search.copy_line", 1)}),
        menu_section("section.workspace_search.ai", context_menu_group_t::ai_evidence, 2,
            {menu_action("workspace_search.add_to_chat", 0)})
    });
    register_menu(rt, "menu.programming.language.result",
        k_programming_result_context_type, {
        menu_section("section.programming.result.open",
            context_menu_group_t::open_navigate, 0,
            {menu_action("programming.result.open", 0)}),
        menu_section("section.programming.result.copy",
            context_menu_group_t::copy_export, 1,
            {menu_action("programming.result.copy_location", 0),
             menu_action("programming.result.copy_path", 1),
             menu_action("programming.result.copy_preview", 2)}),
        menu_section("section.programming.result.ai",
            context_menu_group_t::ai_evidence, 2,
            {menu_action("programming.result.send_to_ai", 0)})
    });
    register_menu(rt, "menu.recent.item", k_recent_context_type, {
        menu_section("section.recent.open", context_menu_group_t::open_navigate, 0, {menu_action("recent.open", 0)}),
        menu_section("section.recent.copy", context_menu_group_t::copy_export, 1, {menu_action("recent.copy_path", 0)}),
        menu_section("section.recent.close", context_menu_group_t::destructive, 2, {menu_action("recent.close", 0)})
    });
    register_menu(rt, "menu.output.view", k_output_context_type, {
        menu_section("section.programming.tasks", context_menu_group_t::modify_run, 0,
            {menu_action("programming.task.run", 0), menu_action("programming.task.cancel", 1),
             menu_action("programming.task.retry", 2), menu_action("programming.task.configure", 3),
             menu_action("programming.task.reload", 4), menu_action("programming.show_problems", 5)}),
        menu_section("section.terminal.sessions", context_menu_group_t::open_navigate, 1,
            {menu_action("terminal.new", 0), menu_action("terminal.next", 1),
             menu_action("terminal.previous", 2), menu_action("terminal.restart", 3)}),
        menu_section("section.terminal.layout", context_menu_group_t::modify_run, 2,
            {menu_action("terminal.split_vertical", 0), menu_action("terminal.split_horizontal", 1),
             menu_action("terminal.unsplit", 2), menu_action("terminal.search", 3)}),
        menu_section("section.output.copy", context_menu_group_t::copy_export, 3, {menu_action("output.copy_all", 0), menu_action("output.select_all", 1), menu_action("terminal.paste", 2), menu_action("output.export", 3)}),
        menu_section("section.output.view", context_menu_group_t::inspect_relate, 4, {menu_action("output.follow", 0), menu_action("output.filter", 1)}),
        menu_section("section.output.clear", context_menu_group_t::destructive, 5,
            {menu_action("output.clear", 0), menu_action("terminal.close", 1)})
    });
    register_menu(rt, "menu.view.surface", k_view_surface_context_type, {
        menu_section("section.surface.lifecycle", context_menu_group_t::modify_run, 0,
            {menu_action("surface.close", 0), menu_action("surface.close_others", 1),
             menu_action("surface.duplicate", 2), menu_action("view.reopen_last_closed", 3)}),
        menu_section("section.surface.placement", context_menu_group_t::open_navigate, 1,
            {menu_action("surface.float", 0), menu_action("surface.move_left", 1),
             menu_action("surface.move_right", 2), menu_action("surface.move_bottom", 3),
             menu_action("surface.move_center", 4)}),
        menu_section("section.surface.state", context_menu_group_t::inspect_relate, 2,
            {menu_action("surface.pin", 0), menu_action("surface.reset_state", 1)}),
        menu_section("section.surface.workspace", context_menu_group_t::copy_export, 3,
            {menu_action("workspace.save", 0), menu_action("workspace.lock", 1)})
    });
    std::vector<context_menu_action_t> analysis_types_open = {
        retained_menu_action("analysis.protection.finding.follow_disassembly", 0),
        retained_menu_action("memory.integrity.reader.follow_disassembly", 1),
        retained_menu_action("memory.integrity.reader.decompile", 2),
        retained_menu_action("analysis.binary_map.function.follow_disassembly", 3),
        retained_menu_action("analysis.binary_map.function.open_hex", 4),
        retained_menu_action("analysis.binary_map.region.follow_disassembly", 5),
        retained_menu_action("analysis.binary_map.region.open_hex", 6),
        retained_menu_action("analysis.binary_map.module.follow_disassembly", 7),
        retained_menu_action("analysis.binary_map.module.open_hex", 8),
        retained_menu_action("analysis.binary_map.section.follow_disassembly", 9),
        retained_menu_action("analysis.binary_map.section.open_hex", 10),
        retained_menu_action("analysis.binary_map.global.follow_disassembly", 11),
        retained_menu_action("analysis.binary_map.global.open_hex", 12),
        retained_menu_action("analysis.binary_map.export.follow_disassembly", 13),
        retained_menu_action("types.catalog.open_structure_editor", 14),
        retained_menu_action("types.catalog.function.follow_disassembly", 15),
        retained_menu_action("types.catalog.function.open_pseudocode", 16),
        retained_menu_action("types.catalog.evidence.follow_disassembly", 17),
        retained_menu_action("types.reconstruction.field.follow_disassembly", 18)};
    for (int index = 0; index < 64; ++index)
        analysis_types_open.push_back(retained_menu_action(
            ("types.reconstruction.field.follow_access." + std::to_string(index + 1)).c_str(),
            19 + index));
    std::vector<context_menu_action_t> analysis_types_modify = {
        retained_menu_action("analysis.fuzzer.crash.ai_analyze", 0),
        retained_menu_action("analysis.fuzzer.crash.minimize", 1),
        retained_menu_action("analysis.binary_map.function.pin", 2),
        retained_menu_action("analysis.binary_map.function.unpin", 3),
        retained_menu_action("types.catalog.rename", 5),
        retained_menu_action("types.catalog.edit_enum", 6),
        retained_menu_action("types.catalog.function.retype", 7),
        retained_menu_action("types.catalog.promote_global", 8),
        retained_menu_action("types.reconstruction.field.declare_apply", 9),
        retained_menu_action("types.reconstruction.field.rename", 10),
        retained_menu_action("types.reconstruction.field.set_type", 11),
        retained_menu_action("types.reconstruction.field.edit_live", 12),
        retained_menu_action("types.dissector.field.edit_live_value", 13),
        retained_menu_action("types.dissector.field.refresh_live_value", 14),
        retained_menu_action("types.dissector.field.rename", 15),
        retained_menu_action("types.dissector.field.set_size", 16),
        retained_menu_action("types.dissector.field.set_comment", 17)};
    for (int index = 0; index < 16; ++index)
        analysis_types_modify.push_back(retained_menu_action(
            ("types.dissector.field.change_type." + std::to_string(index)).c_str(),
            18 + index));
    analysis_types_modify.push_back(retained_menu_action(
        "types.dissector.field.set_array_count", 34));
    analysis_types_modify.push_back(retained_menu_action(
        "types.dissector.field.choose_nested", 35));
    analysis_types_modify.push_back(retained_menu_action(
        "types.dissector.field.configure_bitfield", 36));
    analysis_types_modify.push_back(retained_menu_action(
        "types.dissector.field.set_alignment", 37));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.choose_pointer_target", 38));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.choose_enum", 39));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.configure_layout", 40));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.toggle_union", 41));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.save_catalog", 42));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.load_catalog", 43));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.insert_before", 44));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.insert_after", 45));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.move_up", 46));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.move_down", 47));
	analysis_types_modify.push_back(retained_menu_action(
		"types.catalog.duplicate_to_editor", 48));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.duplicate", 49));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.duplicate", 50));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.structure.review_global_overlay", 51));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.field.review_containing_type_global", 52));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.enum.duplicate", 53));
	analysis_types_modify.push_back(retained_menu_action(
		"types.dissector.enum.review_global_overlay", 54));
    std::vector<context_menu_action_t> analysis_types_copy = {
		retained_menu_action("types.dissector.structure.copy_name", 0),
		retained_menu_action("types.dissector.structure.copy_declaration", 1),
        retained_menu_action("analysis.fuzzer.crash.copy_instruction_address", 0),
        retained_menu_action("analysis.fuzzer.crash.copy_hash", 1),
        retained_menu_action("analysis.fuzzer.crash.copy_description", 2),
        retained_menu_action("analysis.fuzzer.crash.copy_input_hex", 3),
        retained_menu_action("analysis.protection.finding.copy_address", 4),
        retained_menu_action("analysis.protection.finding.copy_title", 5),
        retained_menu_action("analysis.protection.finding.copy_details", 6),
        retained_menu_action("analysis.protection.finding.copy_module", 7),
        retained_menu_action("analysis.binary_map.function.copy_va", 8),
        retained_menu_action("analysis.binary_map.function.copy_name", 9),
        retained_menu_action("analysis.binary_map.region.copy_va", 10),
        retained_menu_action("analysis.binary_map.region.copy_json", 11),
        retained_menu_action("analysis.binary_map.module.copy_name", 12),
        retained_menu_action("analysis.binary_map.module.copy_path", 13),
        retained_menu_action("analysis.binary_map.section.copy_name", 14),
        retained_menu_action("analysis.binary_map.section.copy_va", 15),
        retained_menu_action("analysis.binary_map.global.copy_va", 16),
        retained_menu_action("analysis.binary_map.global.copy_name", 17),
        retained_menu_action("analysis.binary_map.import.copy_dll_name", 18),
        retained_menu_action("analysis.binary_map.import.copy_function_list", 19),
        retained_menu_action("analysis.binary_map.import.copy_qualified_name", 20),
        retained_menu_action("analysis.binary_map.import.copy_function_name", 21),
        retained_menu_action("analysis.binary_map.export.copy_name", 22),
        retained_menu_action("types.catalog.copy_name", 23),
        retained_menu_action("types.catalog.copy_ida_declaration", 25),
        retained_menu_action("types.catalog.function.copy_signature", 26),
        retained_menu_action("types.catalog.function.copy_address", 27),
        retained_menu_action("types.catalog.copy_canonical_type", 28),
        retained_menu_action("types.reconstruction.field.copy_name", 29),
        retained_menu_action("types.reconstruction.field.copy_type", 30),
        retained_menu_action("types.reconstruction.field.copy_offset", 31),
        retained_menu_action("types.reconstruction.field.copy_absolute_address", 32),
        retained_menu_action("types.reconstruction.field.copy_access_evidence", 33),
        retained_menu_action("types.dissector.field.copy_name", 34),
        retained_menu_action("types.dissector.field.copy_offset", 35),
        retained_menu_action("types.dissector.field.copy_absolute_address", 36),
        retained_menu_action("types.dissector.field.copy_current_value", 37)};
	analysis_types_copy.push_back(retained_menu_action(
		"types.catalog.export_declaration", 38));
	analysis_types_copy.push_back(retained_menu_action(
		"types.dissector.structure.export_declaration", 39));
	analysis_types_copy.push_back(retained_menu_action(
		"types.dissector.field.export_declaration", 40));
	analysis_types_copy.push_back(retained_menu_action(
		"types.dissector.enum.export_declaration", 41));
    std::vector<context_menu_action_t> analysis_types_ai = {
        retained_menu_action("analysis.binary_map.function.send_chat", 0),
        retained_menu_action("analysis.binary_map.region.send_chat", 1),
		retained_menu_action("analysis.binary_map.global.send_chat", 2)};
    std::vector<context_menu_action_t> analysis_types_destructive = {
        retained_menu_action("memory.integrity.reader.neutralize", 0),
        retained_menu_action("memory.integrity.reader.restore", 1),
        retained_menu_action("analysis.binary_map.region.dump", 2),
        retained_menu_action("analysis.binary_map.region.change_protection", 3),
        retained_menu_action("analysis.binary_map.section.dump", 4),
        retained_menu_action("types.catalog.delete", 5),
        retained_menu_action("types.dissector.field.remove", 6)};
    register_menu(rt, "menu.retained.entity", k_retained_entity_context_type, {
        menu_section("section.retained.open", context_menu_group_t::open_navigate, 0,
            {retained_menu_action("task.focus_owner", 0),
             retained_menu_action("task.open_log", 1),
             retained_menu_action("task.view_diagnostic", 2),
             retained_menu_action("programming.configuration.open_edit", 3),
             retained_menu_action("programming.run.focus", 4),
             retained_menu_action("programming.run.open_log", 5),
             retained_menu_action("diagnostic.focus_owner", 6),
             retained_menu_action("diagnostic.open_log", 7),
             retained_menu_action("workbench.inspector.follow_disassembly", 8),
             retained_menu_action("workbench.inspector.follow_hex", 6),
             retained_menu_action("workbench.inspector.show_xrefs", 7),
             retained_menu_action("workbench.navigator.follow_disassembly", 8),
             retained_menu_action("workbench.diff.follow", 9),
             retained_menu_action("debugger.entity.open_disassembly", 10),
             retained_menu_action("debugger.entity.open_hex", 11),
             retained_menu_action("debugger.instruction.follow_branch", 12),
             retained_menu_action("debugger.thread.follow_rip", 13),
             retained_menu_action("debugger.seh.follow_handler", 14),
             retained_menu_action("debugger.source.open", 15),
             retained_menu_action("debugger.source.open_disassembly", 16),
             retained_menu_action("memory.entity.open_disassembly", 17),
             retained_menu_action("memory.entity.open_hex", 18),
             retained_menu_action("memory.result.compare_selected", 19),
             retained_menu_action("memory.crypto.show_references", 20),
             retained_menu_action("memory.pointer.open_base_disassembly", 21),
             retained_menu_action("memory.pointer.open_resolved_hex", 22),
             retained_menu_action("hex.open_disassembly", 23)}),
        menu_section("section.retained.modify", context_menu_group_t::modify_run, 1,
            {retained_menu_action("task.retry", 0),
             retained_menu_action("task.request_cancel", 1),
             retained_menu_action("programming.configuration.run_review", 2),
             retained_menu_action("programming.configuration.duplicate", 3),
             retained_menu_action("programming.run.cancel", 4),
             retained_menu_action("programming.run.retry_review", 5),
             retained_menu_action("diagnostic.retry", 6),
             retained_menu_action("diagnostic.acknowledge", 7),
             retained_menu_action("chat.message.edit", 4),
             retained_menu_action("chat.message.retry", 5),
             retained_menu_action("debugger.instruction.run_to", 6),
             retained_menu_action("debugger.instruction.toggle_breakpoint", 7),
             retained_menu_action("debugger.instruction.set_rip", 8),
             retained_menu_action("debugger.register.edit", 9),
             retained_menu_action("debugger.register.zero", 10),
			 retained_menu_action("debugger.register.add_watch", 11),
			 retained_menu_action("debugger.stack.add_watch", 12),
			 retained_menu_action("debugger.entity.pointer_workflow", 13),
			 retained_menu_action("debugger.entity.interpret_structure", 14),
             retained_menu_action("debugger.breakpoint.toggle_enabled", 11),
             retained_menu_action("debugger.breakpoint.edit", 12),
			 retained_menu_action("debugger.breakpoint.condition", 13),
			 retained_menu_action("debugger.breakpoint.log_message", 14),
			 retained_menu_action("debugger.breakpoint.auto_continue", 15),
             retained_menu_action("debugger.memory.change_protection", 13),
             retained_menu_action("debugger.memory.dump", 14),
             retained_menu_action("debugger.module.unload", 32),
             retained_menu_action("debugger.thread.suspend", 15),
             retained_menu_action("debugger.thread.resume", 16),
             retained_menu_action("debugger.thread.switch", 17),
             retained_menu_action("debugger.patch.apply", 18),
             retained_menu_action("debugger.patch.revert", 19),
             retained_menu_action("debugger.source.rebind_all", 20),
             retained_menu_action("memory.result.add_address", 21),
             retained_menu_action("memory.entity.stage_patch", 22),
			 retained_menu_action("memory.entity.pointer_workflow", 23),
			 retained_menu_action("memory.entity.interpret_structure", 24),
			 retained_menu_action("memory.result.freeze", 25),
			 retained_menu_action("memory.result.unfreeze", 26),
             retained_menu_action("memory.address.edit_description", 23),
             retained_menu_action("memory.address.change_type", 24),
             retained_menu_action("memory.address.change_value", 25),
             retained_menu_action("memory.address.freeze", 26),
             retained_menu_action("memory.address.unfreeze", 27),
             retained_menu_action("memory.pointer.add_address", 28),
             retained_menu_action("memory.pointer.stage_patch", 29),
             retained_menu_action("memory.pointer.validate", 30),
             retained_menu_action("hex.stage_zero_overlay", 31),
             retained_menu_action("hex.stage_patch_overlay", 32),
             retained_menu_action("hex.stage_nop_overlay", 33)}),
        menu_section("section.retained.copy", context_menu_group_t::copy_export, 2,
            {retained_menu_action("task.copy_id", 0),
             retained_menu_action("task.copy_summary", 1),
             retained_menu_action("diagnostic.copy", 2),
             retained_menu_action("diagnostic.copy_id", 3),
             retained_menu_action("workbench.inspector.copy_va", 4),
             retained_menu_action("workbench.inspector.copy_rva", 5),
             retained_menu_action("workbench.inspector.copy_file_offset", 6),
             retained_menu_action("workbench.navigator.copy_address", 7),
             retained_menu_action("workbench.navigator.copy_name", 8),
             retained_menu_action("workbench.diff.copy_address", 9),
             retained_menu_action("workbench.diff.copy_before", 10),
             retained_menu_action("workbench.diff.copy_after", 11),
             retained_menu_action("chat.link.copy", 12),
             retained_menu_action("chat.message.copy", 13),
             retained_menu_action("debugger.entity.copy_address", 14),
             retained_menu_action("debugger.entity.copy_primary", 15),
             retained_menu_action("debugger.entity.copy_secondary", 16),
             retained_menu_action("debugger.register.copy_decimal", 17),
             retained_menu_action("debugger.stack.copy_qword", 18),
             retained_menu_action("debugger.source.copy_location", 19),
             retained_menu_action("debugger.source.copy_address", 20),
             retained_menu_action("memory.entity.copy_address", 21),
             retained_menu_action("memory.entity.copy_value", 22),
             retained_menu_action("memory.entity.copy_previous", 23),
             retained_menu_action("memory.entity.copy_module_offset", 24),
             retained_menu_action("memory.result.export_selected", 25),
             retained_menu_action("memory.aob.copy_pattern", 26),
             retained_menu_action("memory.aob.copy_ida_pattern", 27),
             retained_menu_action("memory.crypto.copy_algorithm", 28),
             retained_menu_action("memory.pointer.copy_chain", 29),
             retained_menu_action("memory.pointer.copy_cpp", 30),
             retained_menu_action("memory.pointer.copy_base", 31),
             retained_menu_action("memory.pointer.copy_resolved", 32),
             retained_menu_action("hex.copy_byte", 33),
             retained_menu_action("hex.copy_selection", 34),
             retained_menu_action("hex.copy_address", 35)}),
        menu_section("section.retained.ai", context_menu_group_t::ai_evidence, 3,
            {retained_menu_action("workbench.inspector.send_chat", 0),
             retained_menu_action("workbench.inspector.add_evidence", 1),
             retained_menu_action("evidence.handoff.add_chat", 2),
             retained_menu_action("evidence.handoff.add_review", 3),
             retained_menu_action("evidence.handoff.assign_agent", 4)}),
        menu_section("section.retained.destructive", context_menu_group_t::destructive, 4,
            {retained_menu_action("programming.configuration.delete_review", 0),
             retained_menu_action("chat.message.delete", 1),
             retained_menu_action("debugger.breakpoint.delete", 1),
             retained_menu_action("debugger.thread.terminate", 2),
             retained_menu_action("debugger.handle.close", 3),
             retained_menu_action("debugger.patch.remove", 4),
             retained_menu_action("debugger.watch.remove", 5),
             retained_menu_action("debugger.bookmark.remove", 6),
             retained_menu_action("debugger.source.remove", 7),
             retained_menu_action("memory.address.remove", 8)}),
        menu_section("section.retained.network_ai.open", context_menu_group_t::open_navigate, 5,
            {retained_menu_action("network.capture.send_comparer", 0),
             retained_menu_action("network.capture.send_repeater", 1),
             retained_menu_action("network.exchange.repeater", 2),
             retained_menu_action("network.exchange.fuzzer", 3),
             retained_menu_action("network.exchange.intruder", 4),
             retained_menu_action("network.exchange.scanner", 5),
             retained_menu_action("network.exchange.comparer", 6),
             retained_menu_action("network.exchange.compare_request_response", 7),
             retained_menu_action("network.exchange.session_handling", 8),
             retained_menu_action("network.exchange.cookies", 9),
             retained_menu_action("network.exchange.match_replace", 10),
             retained_menu_action("network.exchange.decoder", 11),
             retained_menu_action("network.exchange.sequencer", 12),
             retained_menu_action("network.exchange.camoufox", 13),
             retained_menu_action("ai.provider.open_details", 10),
             retained_menu_action("ai.provider.test_model", 11),
             retained_menu_action("ai.skill.open_file", 12),
             retained_menu_action("mcp.marketplace.open_details", 13),
             retained_menu_action("ai.chat.conversation.open", 14),
             retained_menu_action("ai.chat.message.inspect_tool", 15),
             retained_menu_action("ai.chat.message.review_change", 16),
             retained_menu_action("ai.evidence.return_source", 17),
             retained_menu_action("network.exchange.related_comparer", 18),
             retained_menu_action("network.websocket.open_editor", 19)}),
        menu_section("section.retained.network_ai.modify", context_menu_group_t::modify_run, 6,
            {retained_menu_action("network.capture.filter_pid", 0),
             retained_menu_action("network.capture.filter_protocol", 1),
             retained_menu_action("network.capture.toggle_follow", 2),
             retained_menu_action("network.exchange.scope_include", 3),
             retained_menu_action("network.exchange.scope_exclude", 4),
             retained_menu_action("network.exchange.save_export", 5),
             retained_menu_action("network.exchange.create_issue", 6),
             retained_menu_action("network.comparer.use_a", 7),
             retained_menu_action("network.comparer.use_b", 8),
             retained_menu_action("network.comparer.swap", 9),
             retained_menu_action("network.site_map.path.include", 10),
             retained_menu_action("network.site_map.path.exclude", 11),
             retained_menu_action("network.site_map.host.include", 12),
             retained_menu_action("network.site_map.host.exclude", 13),
             retained_menu_action("ai.provider.set_default_model", 14),
             retained_menu_action("ai.agent.set_active", 15),
             retained_menu_action("ai.agent.duplicate", 16),
             retained_menu_action("ai.skill.reload", 17),
             retained_menu_action("ai.skill.toggle_enabled", 18),
             retained_menu_action("mcp.marketplace.review_install", 19),
             retained_menu_action("ai.chat.conversation.fork", 20),
             retained_menu_action("ai.chat.conversation.toggle_pin", 21),
             retained_menu_action("ai.chat.conversation.export", 22),
             retained_menu_action("ai.chat.message.edit", 23),
             retained_menu_action("ai.chat.message.retry", 24),
             retained_menu_action("ai.chat.message.add_input", 25),
             retained_menu_action("ai.chat.message.reject_change", 26),
             retained_menu_action("ai.chat.message.cancel_operation", 27),
             retained_menu_action("network.proxy.filter_host", 28),
             retained_menu_action("network.proxy.filter_method", 29),
             retained_menu_action("network.proxy.clear_filter", 30),
             retained_menu_action("network.repeater.duplicate", 31),
             retained_menu_action("network.websocket.filter_host", 32),
             retained_menu_action("network.websocket.toggle_follow", 33),
             retained_menu_action("network.intercept.forward_selected", 34),
             retained_menu_action("network.intercept.drop_selected", 35),
             retained_menu_action("network.intercept.forward_modified", 36)}),
        menu_section("section.retained.network_ai.copy", context_menu_group_t::copy_export, 7,
            {retained_menu_action("network.capture.copy_summary", 0),
             retained_menu_action("network.capture.copy_source", 1),
             retained_menu_action("network.capture.copy_destination", 2),
             retained_menu_action("network.capture.copy_payload", 3),
             retained_menu_action("network.exchange.copy_url", 4),
             retained_menu_action("network.exchange.copy_method", 5),
             retained_menu_action("network.exchange.copy_status", 6),
             retained_menu_action("network.exchange.copy_request", 7),
             retained_menu_action("network.exchange.copy_response", 8),
             retained_menu_action("network.exchange.copy_headers", 9),
             retained_menu_action("network.exchange.copy_body", 10),
             retained_menu_action("network.exchange.copy_artifact", 11),
             retained_menu_action("network.comparer.copy_slot", 12),
             retained_menu_action("network.site_map.copy_url", 13),
             retained_menu_action("ai.provider.copy_provider_id", 14),
             retained_menu_action("ai.provider.copy_model_id", 15),
             retained_menu_action("ai.agent.copy_name", 16),
             retained_menu_action("ai.agent.copy_description", 17),
             retained_menu_action("ai.skill.copy_name", 18),
             retained_menu_action("ai.skill.copy_path", 19),
             retained_menu_action("mcp.marketplace.copy_name", 20),
             retained_menu_action("mcp.marketplace.copy_version", 21),
             retained_menu_action("mcp.marketplace.copy_registry", 22),
             retained_menu_action("mcp.marketplace.copy_source", 23),
             retained_menu_action("mcp.marketplace.copy_launch_preview", 24),
             retained_menu_action("ai.chat.conversation.copy_id", 25),
             retained_menu_action("ai.chat.message.copy", 26),
             retained_menu_action("ai.chat.message.copy_reasoning", 27),
             retained_menu_action("ai.chat.message.copy_tool", 28),
             retained_menu_action("ai.evidence.copy_id", 29),
             retained_menu_action("network.exchange.copy_curl", 30),
             retained_menu_action("network.websocket.copy_host", 31)}),
        menu_section("section.retained.network_ai.evidence", context_menu_group_t::ai_evidence, 8,
            {retained_menu_action("network.capture.send_chat", 0),
             retained_menu_action("network.capture.assign_agent", 1),
             retained_menu_action("network.exchange.chat", 2),
             retained_menu_action("network.exchange.agent", 3),
             retained_menu_action("ai.chat.message.create_evidence", 4),
             retained_menu_action("ai.evidence.add_chat", 5),
             retained_menu_action("ai.evidence.assign_agent", 6),
             retained_menu_action("network.exchange.related_chat", 7),
             retained_menu_action("network.exchange.related_agent", 8)}),
        menu_section("section.retained.network_ai.destructive", context_menu_group_t::destructive, 9,
            {retained_menu_action("network.capture.replay", 0),
             retained_menu_action("network.exchange.replay", 1),
             retained_menu_action("network.exchange.remove", 2),
             retained_menu_action("network.comparer.remove_review", 3),
             retained_menu_action("network.api.collection.remove_review", 4),
             retained_menu_action("ai.agent.delete_review", 5),
             retained_menu_action("ai.skill.uninstall_review", 6),
             retained_menu_action("ai.chat.conversation.delete_review", 7),
             retained_menu_action("ai.chat.message.delete_review", 8),
             retained_menu_action("ai.chat.message.apply_review", 9),
             retained_menu_action("network.repeater.clear_response", 10)}),
        menu_section("section.retained.analysis_types.open", context_menu_group_t::open_navigate, 10,
            std::move(analysis_types_open)),
        menu_section("section.retained.analysis_types.modify", context_menu_group_t::modify_run, 11,
            std::move(analysis_types_modify)),
        menu_section("section.retained.analysis_types.copy", context_menu_group_t::copy_export, 12,
            std::move(analysis_types_copy)),
        menu_section("section.retained.analysis_types.ai", context_menu_group_t::ai_evidence, 13,
            std::move(analysis_types_ai)),
        menu_section("section.retained.analysis_types.destructive", context_menu_group_t::destructive, 14,
            std::move(analysis_types_destructive))
    });
}

interaction_context_t editor_context(runtime_t& rt) {
    interaction_context_t context;
    context.active_view = stable_view_id_t("document.code");
    if (rt.editor_focused)
        context.focus_path.push_back({stable_scope_id_t(rt.editor_review_mode
            ? k_editor_review_scope : k_editor_scope), focus_scope_kind_t::text_editor});
    context.payload = typed_context_ref_t::from(context_type(k_editor_context_type), rt.editor);
    context.generation = rt.generation;
    context.text_input_active = rt.editor_text_input;
    return context;
}

interaction_context_t active_context(runtime_t& rt) {
    auto context = editor_context(rt);
    if (rt.editor_focused)
        return context;
    context.focus_path.clear();
    context.active_view = {};
    context.active_view_instance = {};
    context.payload = {};
    context.text_input_active = false;
    const auto focused = application_views::registry().focused_instance();
    if (focused) {
        context.active_view = focused->view;
        context.active_view_instance = focused->instance;
        const auto* descriptor = application_views::registry().find_descriptor(focused->view);
        if (descriptor && descriptor->category == view_category_t::document)
            context.focus_path.push_back({stable_scope_id_t(
                std::string("scope.") + focused->view.value()), focus_scope_kind_t::document});
        else
            context.focus_path.push_back({stable_scope_id_t(
                std::string("scope.") + focused->view.value()), focus_scope_kind_t::widget});
        if (descriptor && descriptor->category == view_category_t::debugger)
            context.focus_path.push_back({stable_scope_id_t(k_debugger_scope), focus_scope_kind_t::domain});
        else if (focused->view.value() == "view.terminal")
            context.focus_path.push_back({stable_scope_id_t(k_terminal_scope), focus_scope_kind_t::domain});
        else if (descriptor && descriptor->category == view_category_t::output)
            context.focus_path.push_back({stable_scope_id_t(k_output_scope), focus_scope_kind_t::domain});
        else if (descriptor && (descriptor->category == view_category_t::analysis ||
                 descriptor->category == view_category_t::document))
            context.focus_path.push_back({stable_scope_id_t(k_analysis_scope), focus_scope_kind_t::domain});
    }
    return context;
}

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void cancel_action_confirmation(runtime_t& rt);

bool queue_action_confirmation(runtime_t& rt, const char* id,
                               action_invocation_source_t source,
                               const action_execution_result_t& result,
                               const interaction_context_t& context) {
    if (result.status != action_execution_status_t::confirmation_required &&
        result.status != action_execution_status_t::review_required)
        return false;
    if (rt.pending_confirmation.active)
        cancel_action_confirmation(rt);
    const auto* descriptor = rt.actions.find(action_id(id));
    if (!descriptor)
        return false;
    rt.pending_confirmation = {};
    rt.pending_confirmation.active = true;
    rt.pending_confirmation.open_requested = true;
    rt.pending_confirmation.action = id;
    rt.pending_confirmation.label = descriptor->label;
    rt.pending_confirmation.description = descriptor->description;
    rt.pending_confirmation.consequence = result.consequence_summary;
    rt.pending_confirmation.source = source;
    rt.pending_confirmation.context = context;
    if (const auto* retained =
            context.payload.get<retained_entity_runtime_context_t>()) {
        rt.pending_confirmation.retained_context.retained = retained->context();
        rt.pending_confirmation.context.payload = typed_context_ref_t::from(
            context_type(k_retained_entity_context_type),
            rt.pending_confirmation.retained_context);
    }
    return true;
}

void cancel_action_confirmation(runtime_t& rt) {
    if (!rt.pending_confirmation.active)
        return;
    const std::string pending_id = rt.pending_confirmation.action;
    const auto* descriptor = rt.actions.find(
        action_id(pending_id.c_str()));
    const auto cleanup = descriptor ? descriptor->cancel_confirmation
                                    : action_confirmation_cancel_fn_t{};
    rt.pending_confirmation = {};
    try {
        if (cleanup)
            cleanup();
    } catch (const std::exception& exception) {
        design::notification_t diagnostic;
        diagnostic.stable_id = "diagnostic.ui.confirmation.cleanup";
        diagnostic.owner = "application.ui";
        diagnostic.target = pending_id.c_str();
        diagnostic.summary = "Action confirmation cleanup failed";
        diagnostic.details = exception.what();
        diagnostic.semantic = design::semantic_t::error;
        diagnostic.attention_required = true;
        static_cast<void>(design::publish_notification(std::move(diagnostic)));
    } catch (...) {
        design::notification_t diagnostic;
        diagnostic.stable_id = "diagnostic.ui.confirmation.cleanup";
        diagnostic.owner = "application.ui";
        diagnostic.target = pending_id.c_str();
        diagnostic.summary = "Action confirmation cleanup failed";
        diagnostic.details = "The cleanup callback raised an unknown exception";
        diagnostic.semantic = design::semantic_t::error;
        diagnostic.attention_required = true;
        static_cast<void>(design::publish_notification(std::move(diagnostic)));
    }
}

bool execute_resolution(runtime_t& rt, const shortcut_resolution_t& resolution) {
    if (!resolution.resolved())
        return resolution.status != shortcut_resolution_status_t::none;
    action_invocation_t invocation{rt.current};
    invocation.source = action_invocation_source_t::shortcut;
    invocation.invocation_id = rt.invocation++;
    const auto result = rt.actions.execute(resolution.action, invocation);
    finalize_action_execution(resolution.action.c_str(), result,
        action_invocation_source_t::shortcut, invocation.context);
    return true;
}

}

void configure_shell_callbacks(shell_callbacks_t callbacks) {
    auto& rt = runtime();
    initialize(rt);
    rt.shell = std::move(callbacks);
}

void begin_frame() {
    auto& rt = runtime();
    initialize(rt);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::infra::executor::drain_preview_frame();
#endif
    aida::editor::language_service::begin_frame();
	source_debug_service::begin_frame();
	if (rt.shell.exit_application && file_tabs::consume_exit_review_ready())
		rt.shell.exit_application();
    rt.consumed_strokes_this_frame.clear();
	rt.previous_editor_focused = rt.editor_focused;
	rt.previous_editor_text_input = rt.editor_text_input;
	rt.editor_focused = false;
	rt.editor_text_input = false;
	rt.editor_focus_observed_this_frame = false;
    rt.editor.focused = rt.editor_focused;
    rt.current = active_context(rt);
}

void render_action_confirmation() {
    auto& rt = runtime();
    initialize(rt);
    if (!rt.pending_confirmation.active)
        return;
    constexpr const char* popup_label =
        "Confirm Action###aida_global_action_confirmation";
    if (rt.pending_confirmation.open_requested) {
        design::open_dialog("aida_global_action_confirmation", "Confirm Action");
        rt.pending_confirmation.open_requested = false;
    }
    bool keep_open = true;
    if (design::begin_dialog_exact(popup_label, ImVec2(560.0f, 350.0f),
            ImVec2(420.0f, 280.0f), &keep_open)) {
        const std::string pending_id = rt.pending_confirmation.action;
        const auto pending_source = rt.pending_confirmation.source;
        const interaction_context_t pending_context = rt.pending_confirmation.context;
        const auto state = rt.actions.evaluate(
            action_id(pending_id.c_str()), pending_context);
        const auto* descriptor = rt.actions.find(action_id(pending_id.c_str()));
        const action_effect_t high_consequence_effects =
            action_effect_t::destructive | action_effect_t::security_sensitive |
            action_effect_t::live_process | action_effect_t::file_system |
            action_effect_t::network_activity | action_effect_t::memory_mutation |
            action_effect_t::debugger_execution;
        const bool high_consequence = descriptor &&
            any(descriptor->consequence.effects & high_consequence_effects);
        const float footer_height = design::dialog_footer_reserve_height(
            "Confirm", "Cancel");
        design::begin_dialog_body("aida_global_action_confirmation_body",
            footer_height);
        design::text(design::text_role_t::title,
            rt.pending_confirmation.label.c_str());
        if (!rt.pending_confirmation.description.empty())
            ImGui::TextWrapped("%s", rt.pending_confirmation.description.c_str());
        if (!rt.pending_confirmation.consequence.empty()) {
            ImGui::Spacing();
            ImGui::TextWrapped("Consequence: %s", rt.pending_confirmation.consequence.c_str());
        }
        if (!state.capability.enabled && !state.capability.disabled_reason.empty())
            ImGui::TextWrapped("Unavailable: %s", state.capability.disabled_reason.c_str());
        design::end_dialog_body();
        const auto dialog_result = design::dialog_footer(
            "aida_global_action_confirmation_footer", "Confirm",
            state.capability.enabled, high_consequence);
        if (!descriptor || !state.capability.enabled) {
            action_execution_result_t unavailable;
            unavailable.status = action_execution_status_t::unavailable;
            unavailable.action = action_id(pending_id.c_str());
            unavailable.message = !descriptor ? "The retained action is no longer registered"
                : state.capability.disabled_reason.empty()
                    ? "The retained action became unavailable before confirmation"
                    : state.capability.disabled_reason;
            cancel_action_confirmation(rt);
            ImGui::CloseCurrentPopup();
            publish_action_execution_failure(pending_id.c_str(), unavailable,
                pending_source);
        } else if (dialog_result.confirmed) {
            action_invocation_t invocation{pending_context};
            invocation.source = pending_source;
            invocation.invocation_id = rt.invocation++;
            invocation.review_completed = true;
            invocation.confirmation_granted = true;
            const auto result = rt.actions.execute(
                action_id(pending_id.c_str()), invocation);
            if (result.executed())
                rt.pending_confirmation = {};
            else
                cancel_action_confirmation(rt);
            ImGui::CloseCurrentPopup();
            publish_action_execution_failure(pending_id.c_str(), result,
                pending_source);
        } else if (dialog_result.cancelled) {
            cancel_action_confirmation(rt);
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    if (!keep_open)
        cancel_action_confirmation(rt);
    else if (rt.pending_confirmation.active &&
             !ImGui::IsPopupOpen(popup_label))
        cancel_action_confirmation(rt);
}

void process_global_shortcuts() {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    if (rt.shortcut_capture_active) {
        rt.shortcuts.cancel_pending();
        return;
    }
    if (globals::ui::command_palette_open) {
        rt.shortcuts.cancel_pending();
        return;
    }
    if (ImGui::IsPopupOpen(nullptr,
            ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
        rt.shortcuts.cancel_pending();
        return;
    }
    if (ImGui::GetIO().WantTextInput)
        return;
    const auto& io = ImGui::GetIO();
    for (int value = ImGuiKey_Tab; value < ImGuiKey_GamepadStart; ++value) {
        const auto key = static_cast<ImGuiKey>(value);
        if (!ImGui::IsKeyPressed(key, false))
            continue;
        ImGuiKeyChord stroke = key;
        if (io.KeyCtrl) stroke |= ImGuiMod_Ctrl;
        if (io.KeyShift) stroke |= ImGuiMod_Shift;
        if (io.KeyAlt) stroke |= ImGuiMod_Alt;
        if (io.KeySuper) stroke |= ImGuiMod_Super;
        if (std::find(rt.consumed_strokes_this_frame.begin(),
                      rt.consumed_strokes_this_frame.end(), stroke) !=
            rt.consumed_strokes_this_frame.end())
            continue;
        const auto resolution = rt.shortcuts.feed(
            stroke, false, now_ms(), rt.current, rt.actions);
        if (execute_resolution(rt, resolution))
            rt.consumed_strokes_this_frame.push_back(stroke);
    }
    execute_resolution(rt, rt.shortcuts.poll(now_ms(), rt.current, rt.actions));
}

void set_editor_focus(bool focused, bool text_input_active, bool review_mode) {
    auto& rt = runtime();
    initialize(rt);
    const bool effective_review_mode = focused && review_mode;
    if (rt.editor_focused != focused || rt.editor_text_input != text_input_active ||
        rt.editor_review_mode != effective_review_mode)
        ++rt.generation;
    rt.editor_focused = focused;
    rt.editor_text_input = text_input_active;
	rt.editor_focus_observed_this_frame = true;
    rt.editor_review_mode = effective_review_mode;
    rt.editor.focused = focused;
    rt.current = editor_context(rt);
}

void process_editor_shortcuts() {
    auto& rt = runtime();
    initialize(rt);
    rt.current = editor_context(rt);
    if (rt.shortcut_capture_active) {
        rt.shortcuts.cancel_pending();
        return;
    }
    const auto& io = ImGui::GetIO();
    for (int value = ImGuiKey_Tab; value < ImGuiKey_GamepadStart; ++value) {
        const auto key = static_cast<ImGuiKey>(value);
        const bool pressed = ImGui::IsKeyPressed(key, true);
        if (!pressed)
            continue;
        ImGuiKeyChord stroke = key;
        if (io.KeyCtrl) stroke |= ImGuiMod_Ctrl;
        if (io.KeyShift) stroke |= ImGuiMod_Shift;
        if (io.KeyAlt) stroke |= ImGuiMod_Alt;
        if (io.KeySuper) stroke |= ImGuiMod_Super;
        if (std::find(rt.consumed_strokes_this_frame.begin(),
                      rt.consumed_strokes_this_frame.end(), stroke) !=
            rt.consumed_strokes_this_frame.end())
            continue;
        const auto resolution = rt.shortcuts.feed(stroke,
            pressed && !ImGui::IsKeyPressed(key, false), now_ms(), rt.current, rt.actions);
        if (execute_resolution(rt, resolution))
            rt.consumed_strokes_this_frame.push_back(stroke);
    }
    execute_resolution(rt, rt.shortcuts.poll(now_ms(), rt.current, rt.actions));
}

void set_shortcut_capture_active(bool active) noexcept {
    auto& rt = runtime();
    initialize(rt);
    rt.shortcut_capture_active = active;
    if (active)
        rt.shortcuts.cancel_pending();
}

action_presentation_t present_action(const char* id) {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    action_presentation_t result;
    const auto* descriptor = rt.actions.find(action_id(id));
    if (!descriptor)
        return result;
    const auto state = rt.actions.evaluate(descriptor->id, rt.current);
    result.id = descriptor->id.value();
    result.label = descriptor->label;
    result.description = descriptor->description;
    result.category = descriptor->category.display_name;
    result.shortcut = rt.shortcuts.effective_hint(descriptor->id, rt.current);
    result.disabled_reason = state.capability.disabled_reason;
    result.visible = state.capability.visible;
    result.enabled = state.capability.enabled;
    return result;
}

action_presentation_t present_editor_review_action(const char* id) {
    auto& rt = runtime();
    initialize(rt);
    auto context = editor_context(rt);
    context.focus_path.clear();
    context.focus_path.push_back({stable_scope_id_t(k_editor_review_scope),
        focus_scope_kind_t::text_editor});
    context.text_input_active = false;
    action_presentation_t result;
    const auto* descriptor = rt.actions.find(action_id(id));
    if (!descriptor)
        return result;
    const auto state = rt.actions.evaluate(descriptor->id, context);
    result.id = descriptor->id.value();
    result.label = descriptor->label;
    result.description = descriptor->description;
    result.category = descriptor->category.display_name;
    result.shortcut = rt.shortcuts.effective_hint(descriptor->id, context);
    result.disabled_reason = state.capability.disabled_reason;
    result.visible = state.capability.visible;
    result.enabled = state.capability.enabled;
    return result;
}

action_presentation_t present_retained_entity_action(
    const char* id, const retained_entity_context_t& context) {
    auto& rt = runtime();
    initialize(rt);
    retained_entity_runtime_context_t retained;
    retained.external = &context;
    interaction_context_t interaction;
    interaction.active_view = context.active_view;
    interaction.payload = typed_context_ref_t::from(
        context_type(k_retained_entity_context_type), retained);
    interaction.generation = context.entity_generation;
    action_presentation_t result;
    const auto* descriptor = rt.actions.find(action_id(id));
    if (!descriptor)
        return result;
    const auto state = rt.actions.evaluate(descriptor->id, interaction);
    result.id = descriptor->id.value();
    result.label = descriptor->label;
    result.description = descriptor->description;
    result.category = descriptor->category.display_name;
    result.shortcut = rt.shortcuts.effective_hint(descriptor->id, interaction);
    result.disabled_reason = state.capability.disabled_reason;
    result.visible = state.capability.visible;
    result.enabled = state.capability.enabled;
    return result;
}

capability_state_t action_capability(const char* id) {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    const auto* descriptor = rt.actions.find(action_id(id));
    if (!descriptor)
        return capability_state_t::unavailable("The action is not registered", false);
    return rt.actions.evaluate(descriptor->id, rt.current).capability;
}

std::vector<action_presentation_t> list_actions(action_surface_t surface) {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    std::vector<action_presentation_t> result;
    result.reserve(rt.actions.size());
    rt.actions.for_each([&](const application_action_descriptor_t& descriptor) {
        if (!any(descriptor.surfaces & surface))
            return;
        const auto state = rt.actions.evaluate(descriptor.id, rt.current);
        action_presentation_t item;
        item.id = descriptor.id.value();
        item.label = descriptor.label;
        item.description = descriptor.description;
        item.category = descriptor.category.display_name;
        item.shortcut = rt.shortcuts.effective_hint(descriptor.id, rt.current);
        item.disabled_reason = state.capability.disabled_reason;
        item.visible = state.capability.visible;
        item.enabled = state.capability.enabled;
        result.push_back(std::move(item));
    });
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.category != rhs.category)
            return lhs.category < rhs.category;
        if (lhs.label != rhs.label)
            return lhs.label < rhs.label;
        return lhs.id < rhs.id;
    });
    return result;
}

std::vector<shortcut_presentation_t> list_shortcuts() {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    const auto conflicts = rt.shortcuts.conflicts();
    auto has_conflict = [&](const stable_action_binding_id_t& id) {
        return std::any_of(conflicts.begin(), conflicts.end(), [&](const shortcut_conflict_t& conflict) {
            return conflict.first == id || conflict.second == id;
        });
    };
    std::vector<shortcut_presentation_t> result;
    result.reserve(rt.shortcuts.size());
    rt.shortcuts.for_each([&](const shortcut_binding_t& binding) {
        const auto* action = rt.actions.find(binding.action);
        if (!action)
            return;
        const auto state = rt.actions.evaluate(binding.action, rt.current);
        shortcut_presentation_t item;
        item.binding_id = binding.id.value();
        item.action_id = binding.action.value();
        item.label = action->label;
        item.category = action->category.display_name;
        item.shortcut = binding.sequence.display_text;
        const auto default_binding = rt.default_shortcuts.find(binding.id);
        if (default_binding != rt.default_shortcuts.end())
            item.default_shortcut = default_binding->second.sequence.display_text;
        switch (binding.scope_kind) {
            case focus_scope_kind_t::global: item.scope = "Global"; break;
            case focus_scope_kind_t::domain: item.scope = "Domain"; break;
            case focus_scope_kind_t::document: item.scope = "Document"; break;
            case focus_scope_kind_t::widget: item.scope = "Widget"; break;
            case focus_scope_kind_t::text_editor: item.scope = "Text Editor"; break;
            case focus_scope_kind_t::table: item.scope = "Table"; break;
            case focus_scope_kind_t::tree: item.scope = "Tree"; break;
            case focus_scope_kind_t::canvas: item.scope = "Canvas"; break;
            case focus_scope_kind_t::modal: item.scope = "Modal"; break;
        }
        item.disabled_reason = binding.enabled
            ? state.capability.disabled_reason
            : "This shortcut binding is disabled";
        item.enabled = binding.enabled && state.capability.enabled;
        item.binding_enabled = binding.enabled;
        item.conflict = has_conflict(binding.id);
        item.customized = default_binding != rt.default_shortcuts.end() &&
            (binding.enabled != default_binding->second.enabled ||
             binding.sequence.strokes != default_binding->second.sequence.strokes);
        item.editable = default_binding != rt.default_shortcuts.end();
        result.push_back(std::move(item));
    });
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.category != rhs.category)
            return lhs.category < rhs.category;
        if (lhs.label != rhs.label)
            return lhs.label < rhs.label;
        return lhs.shortcut < rhs.shortcut;
    });
    return result;
}

std::string format_shortcut_sequence(const std::vector<ImGuiKeyChord>& strokes) {
    return format_strokes(strokes);
}

shortcut_edit_result_t update_shortcut_override(const char* binding_id,
    const std::vector<ImGuiKeyChord>& strokes, bool replace_conflicts) {
    auto& rt = runtime();
    initialize(rt);
    const stable_action_binding_id_t id(binding_id ? binding_id : "");
    const auto default_binding = rt.default_shortcuts.find(id);
    if (default_binding == rt.default_shortcuts.end())
        return {shortcut_edit_status_t::unavailable,
            "This shortcut is not registered as an editable canonical binding", {}};
    const std::string display = format_strokes(strokes);
    if (display.empty())
        return {shortcut_edit_status_t::invalid,
            "Use one to four keyboard strokes; modifier-only, mouse and gamepad inputs are not supported", {}};

    shortcut_binding_t candidate = default_binding->second;
    candidate.sequence = {strokes, display};
    candidate.source = shortcut_binding_source_t::user_override;
    candidate.enabled = true;
    shortcut_resolver_t updated = rt.shortcuts;
    const auto replaced = updated.replace_binding(candidate, rt.actions);
    if (!replaced.ok())
        return {shortcut_edit_status_t::invalid, replaced.detail, {}};

    std::set<stable_action_binding_id_t> collisions;
    for (const auto& conflict : updated.conflicts()) {
        if (conflict.first == id)
            collisions.insert(conflict.second);
        else if (conflict.second == id)
            collisions.insert(conflict.first);
    }
    if (!collisions.empty() && !replace_conflicts) {
        shortcut_edit_result_t result;
        result.status = shortcut_edit_status_t::conflict;
        result.detail = "The shortcut is already assigned in the same focus scope";
        for (const auto& collision : collisions)
            result.conflicts.push_back(collision.value());
        return result;
    }
    if (replace_conflicts) {
        for (const auto& collision : collisions) {
            const auto* existing = updated.find(collision);
            if (!existing)
                continue;
            shortcut_binding_t disabled = *existing;
            disabled.enabled = false;
            disabled.source = shortcut_binding_source_t::user_override;
            const auto disabled_result = updated.replace_binding(
                std::move(disabled), rt.actions);
            if (!disabled_result.ok())
                return {shortcut_edit_status_t::invalid, disabled_result.detail, {}};
        }
    }

    const shortcut_resolver_t rollback = rt.shortcuts;
    const std::string previous_payload = g_sa_settings.keybinding_overrides_json;
    rt.shortcuts = std::move(updated);
    if (!persist_shortcut_overrides(rt, rollback, previous_payload))
        return {shortcut_edit_status_t::persistence_rejected,
            "The settings service rejected the keybinding update; the previous bindings were restored", {}};
    shortcut_edit_result_t result;
    result.detail = collisions.empty()
        ? "Shortcut updated"
        : "Shortcut updated and conflicting bindings disabled";
    for (const auto& collision : collisions)
        result.conflicts.push_back(collision.value());
    return result;
}

shortcut_edit_result_t reset_shortcut_override(const char* binding_id) {
    auto& rt = runtime();
    initialize(rt);
    const stable_action_binding_id_t id(binding_id ? binding_id : "");
    const auto found = rt.default_shortcuts.find(id);
    if (found == rt.default_shortcuts.end())
        return {shortcut_edit_status_t::unavailable,
            "This shortcut has no registered default binding", {}};
    const shortcut_resolver_t rollback = rt.shortcuts;
    const std::string previous_payload = g_sa_settings.keybinding_overrides_json;
    const auto replaced = rt.shortcuts.replace_binding(found->second, rt.actions);
    if (!replaced.ok())
        return {shortcut_edit_status_t::invalid, replaced.detail, {}};
    if (!persist_shortcut_overrides(rt, rollback, previous_payload))
        return {shortcut_edit_status_t::persistence_rejected,
            "The settings service rejected the reset; the customized binding was restored", {}};
    return {shortcut_edit_status_t::completed, "Shortcut reset to default", {}};
}

shortcut_edit_result_t disable_shortcut_override(const char* binding_id) {
    auto& rt = runtime();
    initialize(rt);
    const stable_action_binding_id_t id(binding_id ? binding_id : "");
    const auto* current = rt.shortcuts.find(id);
    if (!current || rt.default_shortcuts.find(id) == rt.default_shortcuts.end())
        return {shortcut_edit_status_t::unavailable,
            "This shortcut is not an editable canonical binding", {}};
    if (!current->enabled)
        return {shortcut_edit_status_t::completed, "Shortcut is already disabled", {}};
    const shortcut_resolver_t rollback = rt.shortcuts;
    const std::string previous_payload = g_sa_settings.keybinding_overrides_json;
    shortcut_binding_t disabled = *current;
    disabled.enabled = false;
    disabled.source = shortcut_binding_source_t::user_override;
    const auto replaced = rt.shortcuts.replace_binding(std::move(disabled), rt.actions);
    if (!replaced.ok())
        return {shortcut_edit_status_t::invalid, replaced.detail, {}};
    if (!persist_shortcut_overrides(rt, rollback, previous_payload))
        return {shortcut_edit_status_t::persistence_rejected,
            "The settings service rejected the change; the shortcut remains enabled", {}};
    return {shortcut_edit_status_t::completed, "Shortcut disabled; Reset restores its default", {}};
}

shortcut_edit_result_t reset_all_shortcut_overrides() {
    auto& rt = runtime();
    initialize(rt);
    shortcut_resolver_t defaults;
    for (const auto& entry : rt.default_shortcuts) {
        const auto registered = defaults.register_binding(entry.second, rt.actions);
        if (!registered.ok())
            return {shortcut_edit_status_t::invalid, registered.detail, {}};
    }
    const shortcut_resolver_t rollback = rt.shortcuts;
    const std::string previous_payload = g_sa_settings.keybinding_overrides_json;
    rt.shortcuts = std::move(defaults);
    if (!persist_shortcut_overrides(rt, rollback, previous_payload))
        return {shortcut_edit_status_t::persistence_rejected,
            "The settings service rejected the reset; all customized bindings were restored", {}};
    return {shortcut_edit_status_t::completed,
        "All shortcuts reset to their registered defaults", {}};
}

std::string view_action_id(const stable_view_id_t& view) {
    return compose_view_action_id(view);
}

void publish_action_execution_failure(const char* id,
    const action_execution_result_t& result,
    action_invocation_source_t source) noexcept {
    if (result.executed())
        return;
    const char* source_name = source == action_invocation_source_t::application_menu
        ? "application-menu" : source == action_invocation_source_t::activity_bar
        ? "activity-bar" : source == action_invocation_source_t::toolbar
        ? "toolbar" : source == action_invocation_source_t::command_palette
        ? "command-palette" : source == action_invocation_source_t::context_menu
        ? "context-menu" : source == action_invocation_source_t::shortcut
        ? "shortcut" : "accessibility";
    std::string safe_action = id && *id ? id : "unknown";
    for (char& character : safe_action) {
        const bool valid = (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') || character == '.' ||
            character == '_' || character == '-';
        if (!valid)
            character = '_';
    }
    std::string diagnostic_id = "diagnostic.ui.action.";
    diagnostic_id.append(source_name).append(".").append(safe_action);
    std::string message = result.message.empty()
        ? "The action did not complete" : result.message;
    std::string details = "Action '";
    details.append(id && *id ? id : "<unknown>")
        .append("' from ").append(source_name).append(" did not execute: ")
        .append(message);
    design::notification_t diagnostic;
    diagnostic.stable_id = diagnostic_id.c_str();
    diagnostic.owner = "application.ui";
    diagnostic.target = id && *id ? id : "unknown";
    diagnostic.summary = message.c_str();
    diagnostic.details = details.c_str();
    diagnostic.semantic = design::semantic_t::error;
    diagnostic.attention_required = true;
    static_cast<void>(design::publish_notification(std::move(diagnostic)));
    toast_notification::push(message, toast_notification::toast_type_t::error, 5.0f);
}

void finalize_action_execution(const char* id,
    const action_execution_result_t& result,
    action_invocation_source_t source,
    const interaction_context_t& context) {
    auto& rt = runtime();
    initialize(rt);
    if (!queue_action_confirmation(rt, id, source, result, context))
        publish_action_execution_failure(id, result, source);
}

action_execution_result_t execute_action(const char* id, action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    auto result = rt.actions.execute(action_id(id), invocation);
    finalize_action_execution(id, result, source, invocation.context);
    return result;
}

action_execution_result_t execute_editor_hunk_action(int hunk_index,
        const char* id, action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    rt.editor_hunk_target = code_editor_widget::review_hunk_identity(hunk_index);
    rt.editor_hunk_target_explicit = true;
    rt.current = editor_context(rt);
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    auto result = rt.actions.execute(action_id(id), invocation);
    rt.editor_hunk_target = {};
    rt.editor_hunk_target_explicit = false;
    finalize_action_execution(id, result, source, invocation.context);
    return result;
}

action_presentation_t present_editor_tab_action(int tab_index, const char* id) {
    action_presentation_t result;
    auto& rt = runtime();
    initialize(rt);
    if (!file_tabs::is_valid_tab_index(tab_index))
        return result;
    const auto previous_tab = rt.tab;
    const auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
    rt.tab = {tab_index, tab.filepath, tab.filename};
    interaction_context_t context;
    context.active_view = stable_view_id_t("document.code");
    context.payload = typed_context_ref_t::from(context_type(k_tab_context_type), rt.tab);
    context.generation = rt.generation;
    const auto* descriptor = rt.actions.find(action_id(id));
    if (descriptor) {
        const auto state = rt.actions.evaluate(descriptor->id, context);
        result.id = descriptor->id.value();
        result.label = descriptor->label;
        result.description = descriptor->description;
        result.category = descriptor->category.display_name;
        result.shortcut = rt.shortcuts.effective_hint(descriptor->id, context);
        result.disabled_reason = state.capability.disabled_reason;
        result.visible = state.capability.visible;
        result.enabled = state.capability.enabled;
    }
    rt.tab = previous_tab;
    return result;
}

action_execution_result_t execute_editor_tab_action(int tab_index,
        const char* id, action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    if (!file_tabs::is_valid_tab_index(tab_index)) {
        action_execution_result_t result;
        result.status = action_execution_status_t::unavailable;
        result.action = action_id(id);
        result.message = "The editor tab is no longer open";
        publish_action_execution_failure(id, result, source);
        return result;
    }
    const auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
    rt.tab = {tab_index, tab.filepath, tab.filename};
    rt.current = {};
    rt.current.active_view = stable_view_id_t("document.code");
    rt.current.payload = typed_context_ref_t::from(context_type(k_tab_context_type), rt.tab);
    rt.current.generation = ++rt.generation;
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    auto result = rt.actions.execute(action_id(id), invocation);
    finalize_action_execution(id, result, source, invocation.context);
    return result;
}

action_execution_result_t execute_retained_entity_action(
    const char* id, action_invocation_source_t source,
    const retained_entity_context_t& context) {
    auto& rt = runtime();
    initialize(rt);
    retained_entity_runtime_context_t retained;
    retained.external = &context;
    interaction_context_t interaction;
    interaction.active_view = context.active_view;
    interaction.payload = typed_context_ref_t::from(
        context_type(k_retained_entity_context_type), retained);
    interaction.generation = context.entity_generation;
    action_invocation_t invocation{interaction};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    auto result = rt.actions.execute(action_id(id), invocation);
    finalize_action_execution(id, result, source, invocation.context);
    return result;
}

void open_editor_context_menu(context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    ++rt.generation;
    rt.editor_popup_context = editor_context(rt);
    rt.editor_popup_request = {stable_menu_id_t(rt.editor_review_mode
        ? "menu.editor.review" : "menu.editor.text"), origin,
        rt.editor_popup_context.generation};
    ImGui::OpenPopup("##aida_editor_context");
}

void render_editor_context_menu() {
    auto& rt = runtime();
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_editor_context", presenter, rt.editor_popup_request, rt.editor_popup_context);
}

void open_editor_tab_context_menu(int tab_index, context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (!file_tabs::is_valid_tab_index(tab_index))
        return;
    ++rt.generation;
    const auto& tab = file_tabs::tabs[file_tabs::tab_index(tab_index)];
    rt.tab = {tab_index, tab.filepath, tab.filename};
    rt.tab_popup_context = {};
    rt.tab_popup_context.active_view = stable_view_id_t("document.code");
    rt.tab_popup_context.payload = typed_context_ref_t::from(context_type(k_tab_context_type), rt.tab);
    rt.tab_popup_context.generation = rt.generation;
    rt.tab_popup_request = {stable_menu_id_t("menu.editor.tab"), origin, rt.generation};
    ImGui::OpenPopup("##aida_editor_tab_context");
}

void render_editor_tab_context_menu() {
    auto& rt = runtime();
    if (ImGui::IsPopupOpen("##aida_editor_tab_context") &&
        (!file_tabs::is_valid_tab_index(rt.tab.index) ||
         file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].filepath != rt.tab.path ||
         file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].filename != rt.tab.name))
        rt.tab_popup_context.generation = ++rt.generation;
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_editor_tab_context", presenter, rt.tab_popup_request, rt.tab_popup_context);
}

void open_explorer_context_menu(int entry_index, context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (entry_index < 0 || static_cast<std::size_t>(entry_index) >= file_browser::entries.size())
        return;
    ++rt.generation;
    const auto& entry = file_browser::entries[static_cast<std::size_t>(entry_index)];
    rt.explorer = {};
    rt.explorer.index = entry_index;
    rt.explorer.path = entry.full_path;
    rt.explorer.name = entry.name;
    rt.explorer.directory = entry.is_dir;
    rt.explorer.index_generation = file_browser::index_generation;
    const auto append_entry = [&rt](const FileBrowserEntry& selected) {
        rt.explorer.targets.push_back({selected.full_path, selected.is_dir});
        rt.explorer.entry_ids.push_back(selected.entry_id);
        rt.explorer.entry_generations.push_back(selected.generation);
    };
    append_entry(entry);
    if (file_browser::selected_paths.size() > 1) {
        const std::string clicked = normalized_programming_path_key(entry.full_path);
        for (const auto& selected : file_browser::entries) {
            const std::string key = normalized_programming_path_key(selected.full_path);
            if (key == clicked || file_browser::selected_paths.find(key) ==
                    file_browser::selected_paths.end())
                continue;
            append_entry(selected);
            if (rt.explorer.targets.size() == 100000)
                break;
        }
    }
    for (std::size_t operation = 0;
         operation < rt.explorer.operation_capabilities.size(); ++operation)
        rt.explorer.operation_capabilities[operation] =
            explorer_views::file_operation_capability(
                static_cast<explorer_views::file_operation_t>(operation),
                rt.explorer.targets);
    rt.explorer_popup_context = {};
    rt.explorer_popup_context.active_view = stable_view_id_t("view.project_explorer");
    rt.explorer_popup_context.payload = typed_context_ref_t::from(context_type(k_explorer_entry_context_type), rt.explorer);
    rt.explorer_popup_context.generation = rt.generation;
    rt.explorer_popup_request = {stable_menu_id_t("menu.explorer.entry"), origin, rt.generation};
    ImGui::OpenPopup("##aida_explorer_context");
}

void open_explorer_empty_context_menu(context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    ++rt.generation;
    rt.explorer = {};
    rt.explorer_popup_context = {};
    rt.explorer_popup_context.active_view = stable_view_id_t("view.project_explorer");
    rt.explorer_popup_context.payload = typed_context_ref_t::from(context_type(k_explorer_empty_context_type), rt.explorer);
    rt.explorer_popup_context.generation = rt.generation;
    rt.explorer_popup_request = {stable_menu_id_t("menu.explorer.empty"), origin, rt.generation};
    ImGui::OpenPopup("##aida_explorer_context");
}

void render_explorer_context_menu() {
    auto& rt = runtime();
    if (ImGui::IsPopupOpen("##aida_explorer_context") && rt.explorer.index >= 0 &&
        (static_cast<std::size_t>(rt.explorer.index) >= file_browser::entries.size() ||
         file_browser::entries[static_cast<std::size_t>(rt.explorer.index)].full_path != rt.explorer.path))
        rt.explorer_popup_context.generation = ++rt.generation;
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_explorer_context", presenter, rt.explorer_popup_request, rt.explorer_popup_context);
}

void open_workspace_search_context_menu(int result_index, context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    std::lock_guard<std::mutex> lock(workspace_search::g_search.results_mtx);
    if (result_index < 0 || static_cast<std::size_t>(result_index) >= workspace_search::g_search.results.size())
        return;
    ++rt.generation;
    const auto& result = workspace_search::g_search.results[static_cast<std::size_t>(result_index)];
    rt.workspace_search = {result_index, result.filepath, result.line_text, result.line_number, result.col_start};
    rt.workspace_search_popup_context = {};
    rt.workspace_search_popup_context.active_view = stable_view_id_t("view.workspace_search");
    rt.workspace_search_popup_context.payload = typed_context_ref_t::from(context_type(k_workspace_search_context_type), rt.workspace_search);
    rt.workspace_search_popup_context.generation = rt.generation;
    rt.workspace_search_popup_request = {stable_menu_id_t("menu.workspace_search.result"), origin, rt.generation};
    ImGui::OpenPopup("##aida_workspace_search_context");
}

void render_workspace_search_context_menu() {
    auto& rt = runtime();
    if (ImGui::IsPopupOpen("##aida_workspace_search_context")) {
        std::lock_guard<std::mutex> lock(workspace_search::g_search.results_mtx);
        const bool valid = rt.workspace_search.index >= 0 &&
            static_cast<std::size_t>(rt.workspace_search.index) < workspace_search::g_search.results.size();
        if (!valid || workspace_search::g_search.results[static_cast<std::size_t>(rt.workspace_search.index)].filepath != rt.workspace_search.path ||
            workspace_search::g_search.results[static_cast<std::size_t>(rt.workspace_search.index)].line_number != rt.workspace_search.line)
            rt.workspace_search_popup_context.generation = ++rt.generation;
    }
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_workspace_search_context", presenter,
        rt.workspace_search_popup_request, rt.workspace_search_popup_context);
}

void open_programming_result_context_menu(
    aida::editor::language_service::location_t location,
    std::string label, std::string provenance,
    aida::editor::language_service::capability_kind_t kind,
    std::uint64_t request_id, std::uint64_t request_generation,
    std::uint64_t provider_generation, std::uint64_t index_generation,
    context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (location.file_path.empty())
        return;
    ++rt.generation;
    rt.programming_result = {std::move(location), std::move(label),
        std::move(provenance), kind, request_id, request_generation,
        provider_generation, index_generation};
    rt.programming_result_popup_context = {};
    rt.programming_result_popup_context.active_view = stable_view_id_t(
        kind == aida::editor::language_service::capability_kind_t::document_symbols ||
        kind == aida::editor::language_service::capability_kind_t::workspace_symbols
            ? "view.programming.outline" : "view.programming.references");
    rt.programming_result_popup_context.payload = typed_context_ref_t::from(
        context_type(k_programming_result_context_type), rt.programming_result);
    rt.programming_result_popup_context.generation = rt.generation;
    rt.programming_result_popup_request = {
        stable_menu_id_t("menu.programming.language.result"), origin, rt.generation};
    ImGui::OpenPopup("##aida_programming_language_result_context");
}

void render_programming_result_context_menu() {
    auto& rt = runtime();
    if (ImGui::IsPopupOpen("##aida_programming_language_result_context") &&
        !programming_result_capability(rt.programming_result).enabled)
        rt.programming_result_popup_context.generation = ++rt.generation;
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_programming_language_result_context",
        presenter, rt.programming_result_popup_request,
        rt.programming_result_popup_context);
}

void open_recent_context_menu(const std::string& path, bool open_session,
                              context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (path.empty())
        return;
    ++rt.generation;
    rt.recent = {path, open_session};
    rt.recent_popup_context = {};
    rt.recent_popup_context.active_view = stable_view_id_t("view.recent");
    rt.recent_popup_context.payload = typed_context_ref_t::from(context_type(k_recent_context_type), rt.recent);
    rt.recent_popup_context.generation = rt.generation;
    rt.recent_popup_request = {stable_menu_id_t("menu.recent.item"), origin, rt.generation};
    ImGui::OpenPopup("##aida_recent_context");
}

void render_recent_context_menu() {
    auto& rt = runtime();
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_recent_context", presenter,
        rt.recent_popup_request, rt.recent_popup_context);
}

void open_view_surface_context_menu(const view_instance_id_t& instance,
                                    context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    const auto* descriptor = application_views::registry().find_descriptor(instance.view);
    if (!descriptor || !application_views::registry().is_open(instance) ||
        descriptor->render_ownership != view_render_ownership_t::registry_window)
        return;
    ++rt.generation;
    rt.view_surface = {instance, application_views::registry().window_name(instance)};
    rt.view_surface_popup_context = {};
    rt.view_surface_popup_context.active_view = instance.view;
    rt.view_surface_popup_context.active_view_instance = instance.instance;
    rt.view_surface_popup_context.payload = typed_context_ref_t::from(
        context_type(k_view_surface_context_type), rt.view_surface);
    rt.view_surface_popup_context.generation = rt.generation;
    rt.view_surface_popup_request = {
        stable_menu_id_t("menu.view.surface"), origin, rt.generation};
    ImGui::OpenPopup("##aida_view_surface_context");
}

void render_view_surface_context_menu(const view_instance_id_t& instance) {
    auto& rt = runtime();
    if (!(rt.view_surface.instance == instance))
        return;
    if (ImGui::IsPopupOpen("##aida_view_surface_context")) {
        if (!application_views::registry().is_open(instance) ||
            application_views::registry().window_name(instance) != rt.view_surface.window_name)
            rt.view_surface_popup_context.generation = ++rt.generation;
    }
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_view_surface_context", presenter,
        rt.view_surface_popup_request, rt.view_surface_popup_context);
}

action_presentation_t present_output_action(int tab, const char* action) {
    action_presentation_t result;
    auto& rt = runtime();
    initialize(rt);
    if (tab < 0 || tab >= static_cast<int>(bottom_tab_t::COUNT))
        return result;
    const int previous_tab = rt.output.tab;
    rt.output.tab = tab;
    interaction_context_t context;
    context.active_view = stable_view_id_t(tab == static_cast<int>(bottom_tab_t::terminal)
        ? "view.terminal" : tab == static_cast<int>(bottom_tab_t::mcp_log)
        ? "view.mcp_log" : tab == static_cast<int>(bottom_tab_t::driver_log)
        ? "view.driver_log" : tab == static_cast<int>(bottom_tab_t::sandbox_log)
        ? "view.sandbox_log" : "view.output");
    context.focus_path.push_back({stable_scope_id_t(
        tab == static_cast<int>(bottom_tab_t::terminal)
            ? k_terminal_scope : k_output_scope), focus_scope_kind_t::domain});
    context.payload = typed_context_ref_t::from(context_type(k_output_context_type), rt.output);
    context.generation = rt.generation;
    const auto* descriptor = rt.actions.find(action_id(action));
    if (descriptor) {
        const auto state = rt.actions.evaluate(descriptor->id, context);
        result.id = descriptor->id.value();
        result.label = descriptor->label;
        result.description = descriptor->description;
        result.category = descriptor->category.display_name;
        result.shortcut = rt.shortcuts.effective_hint(descriptor->id, context);
        result.disabled_reason = state.capability.disabled_reason;
        result.visible = state.capability.visible;
        result.enabled = state.capability.enabled;
    }
    rt.output.tab = previous_tab;
    return result;
}

action_execution_result_t execute_output_action(int tab, const char* action,
                                                action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    if (tab < 0 || tab >= static_cast<int>(bottom_tab_t::COUNT)) {
        action_execution_result_t result;
        result.status = action_execution_status_t::unavailable;
        result.action = action_id(action);
        result.message = "The requested output surface is no longer available";
        publish_action_execution_failure(action, result, source);
        return result;
    }
    rt.output.tab = tab;
    rt.current = {};
    rt.current.active_view = stable_view_id_t(tab == static_cast<int>(bottom_tab_t::terminal)
        ? "view.terminal" : tab == static_cast<int>(bottom_tab_t::mcp_log)
        ? "view.mcp_log" : tab == static_cast<int>(bottom_tab_t::driver_log)
        ? "view.driver_log" : tab == static_cast<int>(bottom_tab_t::sandbox_log)
        ? "view.sandbox_log" : "view.output");
    rt.current.focus_path.push_back({stable_scope_id_t(
        tab == static_cast<int>(bottom_tab_t::terminal)
            ? k_terminal_scope : k_output_scope), focus_scope_kind_t::domain});
    rt.current.payload = typed_context_ref_t::from(context_type(k_output_context_type), rt.output);
    rt.current.generation = ++rt.generation;
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    auto result = rt.actions.execute(action_id(action), invocation);
    finalize_action_execution(action, result, source, invocation.context);
    return result;
}

void open_output_context_menu(int tab, context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (tab < 0 || tab >= static_cast<int>(bottom_tab_t::COUNT))
        return;
    rt.output.tab = tab;
    rt.output_popup_context = {};
    rt.output_popup_context.active_view = stable_view_id_t(tab == static_cast<int>(bottom_tab_t::terminal)
        ? "view.terminal" : tab == static_cast<int>(bottom_tab_t::mcp_log)
        ? "view.mcp_log" : tab == static_cast<int>(bottom_tab_t::driver_log)
        ? "view.driver_log" : tab == static_cast<int>(bottom_tab_t::sandbox_log)
        ? "view.sandbox_log" : "view.output");
    rt.output_popup_context.payload = typed_context_ref_t::from(context_type(k_output_context_type), rt.output);
    rt.output_popup_context.generation = ++rt.generation;
    rt.output_popup_request = {stable_menu_id_t("menu.output.view"), origin, rt.generation};
    ImGui::OpenPopup("##aida_output_context");
}

void render_output_context_menu() {
    auto& rt = runtime();
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_output_context", presenter,
        rt.output_popup_request, rt.output_popup_context);
}

void open_retained_entity_context_menu(retained_entity_context_t context,
                                       context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    if (context.owner_id.empty() || context.entity_id.empty() ||
        context.actions.empty())
        return;
    rt.retained_entity.retained = std::move(context);
    rt.retained_entity_popup_context = {};
    rt.retained_entity_popup_context.active_view =
        rt.retained_entity.retained.active_view;
    if (!rt.retained_entity_popup_context.active_view.empty()) {
        const auto* descriptor = application_views::registry().find_descriptor(
            rt.retained_entity_popup_context.active_view);
        if (descriptor && descriptor->category == view_category_t::document)
            rt.retained_entity_popup_context.focus_path.push_back({stable_scope_id_t(
                std::string("scope.") + rt.retained_entity_popup_context.active_view.value()),
                focus_scope_kind_t::document});
        else
            rt.retained_entity_popup_context.focus_path.push_back({stable_scope_id_t(
                std::string("scope.") + rt.retained_entity_popup_context.active_view.value()),
                focus_scope_kind_t::widget});
        if (descriptor && descriptor->category == view_category_t::debugger)
            rt.retained_entity_popup_context.focus_path.push_back({
                stable_scope_id_t(k_debugger_scope), focus_scope_kind_t::domain});
        else if (descriptor && (descriptor->category == view_category_t::analysis ||
                 descriptor->category == view_category_t::document))
            rt.retained_entity_popup_context.focus_path.push_back({
                stable_scope_id_t(k_analysis_scope), focus_scope_kind_t::domain});
    }
    rt.retained_entity_popup_context.payload = typed_context_ref_t::from(
        context_type(k_retained_entity_context_type), rt.retained_entity);
    rt.retained_entity_popup_context.generation = ++rt.generation;
    rt.retained_entity_popup_request = {
        rt.retained_entity.retained.menu.empty()
            ? stable_menu_id_t("menu.retained.entity")
            : rt.retained_entity.retained.menu,
        origin, rt.generation};
    ImGui::OpenPopup("##aida_retained_entity_context");
}

void render_retained_entity_context_menu(const char* owner_id) {
    auto& rt = runtime();
    if (!owner_id || rt.retained_entity.retained.owner_id != owner_id)
        return;
    context_menu_presenter_t presenter(rt.menus, rt.actions, &rt.shortcuts);
    render_context_menu_popup("##aida_retained_entity_context", presenter,
        rt.retained_entity_popup_request, rt.retained_entity_popup_context);
}

std::string consume_retained_entity_action(const char* owner_id,
                                           const char* entity_id) {
    auto& rt = runtime();
    if (!owner_id || !entity_id ||
        rt.retained_entity_executed_owner != owner_id ||
        rt.retained_entity_executed_id != entity_id)
        return {};
    std::string action = std::move(rt.retained_entity_executed_action);
    rt.retained_entity_executed_owner.clear();
    rt.retained_entity_executed_id.clear();
    rt.retained_entity_executed_action.clear();
    return action;
}

}
