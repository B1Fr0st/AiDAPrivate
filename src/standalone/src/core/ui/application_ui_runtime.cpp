#include "application_ui_runtime.hpp"

#include "context_menu_renderer.hpp"
#include "application_view_registry.hpp"
#include "output_views.hpp"
#include "workspace_layout.hpp"
#include "../../helpers/globals.h"
#include "../editor/code_editor.hpp"
#include "../session/analysis_session.hpp"
#include "../disasm/cfg_view.hpp"
#include "../disasm/comment_dialog.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../disasm/rename_dialog.hpp"
#include "../analysis/struct_recon_view.hpp"
#include "../debugger/debugger_view.hpp"
#include "../workbench/workbench_shell_integration.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <optional>
#include <utility>
#include <vector>

namespace aida::ui::application_ui {

namespace {

constexpr const char* k_editor_context_type = "context.editor.text";
constexpr const char* k_tab_context_type = "context.editor.tab";
constexpr const char* k_explorer_entry_context_type = "context.explorer.entry";
constexpr const char* k_explorer_empty_context_type = "context.explorer.empty";
constexpr const char* k_workspace_search_context_type = "context.workspace_search.result";
constexpr const char* k_recent_context_type = "context.recent.item";
constexpr const char* k_output_context_type = "context.output.view";
constexpr const char* k_editor_scope = "scope.editor.text";
constexpr const char* k_analysis_scope = "scope.analysis";
constexpr const char* k_debugger_scope = "scope.debugger";

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
};

struct workspace_search_context_t {
    int index = -1;
    std::string path;
    std::string line_text;
    int line = 0;
    int column = 0;
};

struct recent_context_t {
    std::string path;
    bool open_session = false;
};

struct output_context_t {
    int tab = static_cast<int>(bottom_tab_t::output);
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
    recent_context_t recent;
    output_context_t output;
    interaction_context_t current;
    interaction_context_t editor_popup_context;
    interaction_context_t tab_popup_context;
    interaction_context_t explorer_popup_context;
    interaction_context_t workspace_search_popup_context;
    interaction_context_t recent_popup_context;
    interaction_context_t output_popup_context;
    context_menu_open_request_t editor_popup_request;
    context_menu_open_request_t tab_popup_request;
    context_menu_open_request_t explorer_popup_request;
    context_menu_open_request_t workspace_search_popup_request;
    context_menu_open_request_t recent_popup_request;
    context_menu_open_request_t output_popup_request;
    std::uint64_t generation = 1;
    std::uint64_t invocation = 1;
    bool initialized = false;
    bool editor_focused = false;
    bool editor_text_input = false;
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
    return code_editor::active
        ? capability_state_t::available()
        : capability_state_t::unavailable("Open or create a text document first");
}

capability_state_t editor_selection() {
    if (!code_editor::active)
        return capability_state_t::unavailable("Open or create a text document first");
    return code_editor_widget::has_selection()
        ? capability_state_t::available()
        : capability_state_t::unavailable("Select text first");
}

capability_state_t editor_savable() {
    if (!code_editor::active)
        return capability_state_t::unavailable("Open or create a text document first");
    if (file_tabs::is_valid_tab_index(file_tabs::active_tab)) {
        const auto& tab = file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)];
        if (tab.external_conflict && !tab.external_overwrite_approved)
            return capability_state_t::unavailable(
                "The file changed on disk; resolve the editor conflict before saving");
    }
    return code_editor::filepath.empty()
        ? capability_state_t::unavailable("Use Save As to choose a path first")
        : capability_state_t::available();
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
    rt.actions.register_action(std::move(descriptor));
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
    if (result == result_t::completed || result == result_t::unchanged)
        return action_handler_result_t::completed();
    if (result == result_t::invalid_name)
        return action_handler_result_t::failed("The workspace name is invalid");
    if (result == result_t::unavailable)
        return action_handler_result_t::failed("The workspace operation is unavailable until the DockSpace is ready");
    return action_handler_result_t::failed(failure);
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
    rt.shortcuts.register_binding(std::move(binding), rt.actions);
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
    rt.shortcuts.register_binding(std::move(binding), rt.actions);
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
    rt.shortcuts.register_binding(std::move(binding), rt.actions);
}

void register_menu(runtime_t& rt,
                   const char* id,
                   const char* accepted_context,
                   std::vector<context_menu_section_t> sections) {
    context_menu_descriptor_t descriptor;
    descriptor.id = stable_menu_id_t(id);
    descriptor.accepted_contexts.push_back(context_type(accepted_context));
    descriptor.sections = std::move(sections);
    rt.menus.register_menu(std::move(descriptor), rt.actions);
}

context_menu_action_t menu_action(const char* id, int order) {
    context_menu_action_t result;
    result.action = action_id(id);
    result.order = order;
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
        std::string normalized = std::filesystem::path(value).lexically_normal().generic_string();
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

bool open_workspace_search_result(const workspace_search_context_t& result) {
    std::ifstream input(result.path, std::ios::binary);
    if (!input.is_open())
        return false;
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const std::string name = std::filesystem::path(result.path).filename().string();
    file_tabs::open_or_focus(result.path, name, content);
    autocomplete::cursor_line = (std::max)(0, result.line - 1);
    autocomplete::cursor_col = (std::max)(0, result.column);
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

    register_action(rt, "file.new", "New File", "Create an untitled code document", menu_surfaces,
        [](const action_invocation_t&) {
            file_tabs::open_or_focus("", "untitled", "");
            application_views::open_or_focus(stable_view_id_t("document.code"));
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.open", "Open File...", "Open a file", menu_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_file)
                return action_handler_result_t::failed("Open-file provider is unavailable");
            rt.shell.open_file();
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.open_folder", "Open Folder...", "Open a folder in Explorer", menu_surfaces | action_surface_t::context_menu,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.open_folder)
                return action_handler_result_t::failed("Open-folder provider is unavailable");
            rt.shell.open_folder();
            return action_handler_result_t::completed();
        });
    register_action(rt, "file.save", "Save", "Save the active code document", all_surfaces,
        [](const action_invocation_t&) {
            return code_editor::save()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The active document has no writable path");
        }, [](const interaction_context_t&) { return editor_savable(); });
    register_action(rt, "file.save_as", "Save As...", "Save the active code document to a new path", all_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.save_as)
                return action_handler_result_t::failed("Save As provider is unavailable");
            rt.shell.save_as();
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "file.save_all", "Save All", "Save every modified code document", all_surfaces,
        [](const action_invocation_t&) {
            file_tabs::snapshot_active_to_tab();
            for (std::size_t index = 0; index < file_tabs::tabs.size(); ++index) {
                if (!file_tabs::tabs[index].dirty)
                    continue;
                if (!file_tabs::save_tab_to_disk(static_cast<int>(index)))
                    return action_handler_result_t::failed(
                        "A modified document could not be saved");
            }
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            bool modified = false;
            for (const auto& tab : file_tabs::tabs) {
                if (!tab.dirty)
                    continue;
                modified = true;
                if (tab.filepath.empty())
                    return capability_state_t::unavailable(
                        "Use Save As for untitled modified documents first");
                if (tab.external_conflict && !tab.external_overwrite_approved)
                    return capability_state_t::unavailable(
                        "Resolve externally changed documents before Save All");
            }
            return modified
                ? capability_state_t::available()
                : capability_state_t::unavailable("No modified documents need saving");
        });
    register_action(rt, "file.close", "Close", "Close the active code document", all_surfaces,
        [](const action_invocation_t&) {
            close_tab_with_confirmation(file_tabs::active_tab);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(file_tabs::active_tab))
                return capability_state_t::unavailable("No code document is open");
            return file_tabs::tabs[file_tabs::tab_index(file_tabs::active_tab)].pinned
                ? capability_state_t::unavailable("Unpin the active document before closing it")
                : capability_state_t::available();
        });
    register_action(rt, "file.exit", "Exit", "Close AiDA", menu_surfaces,
        [&rt](const action_invocation_t&) {
            if (!rt.shell.exit_application)
                return action_handler_result_t::failed("Application shutdown provider is unavailable");
            rt.shell.exit_application();
            return action_handler_result_t::completed();
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
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto result = application_views::open_or_focus(
                stable_view_id_t("view.diagnostics"));
            return result.ok() ? action_handler_result_t::completed()
                               : action_handler_result_t::failed(result.detail);
        }, {}, false, {}, "category.programming", "Programming");

    register_action(rt, "analysis.navigate.back", "Analysis Back",
        "Restore the previous global analysis document and exact selection",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            disasm_view::navigate_back(context);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) { return analysis_history_capability(false); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.forward", "Analysis Forward",
        "Restore the next global analysis document and exact selection",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            disasm_view::navigate_forward(context);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) { return analysis_history_capability(true); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.disassembly", "Open Selection in Disassembly",
        "Open and focus the selected analysis address in Disassembly",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            const auto runtime = disasm_view::runtime_address(context, *address).value_or(address->value);
            disasm_view::goto_address(runtime, context);
            return open_analysis_view("document.disassembly");
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.graph", "Open Selection in Graph",
        "Build and focus the control-flow graph for the selected function",
        menu_surfaces,
        [](const action_invocation_t&) {
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
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.pseudocode", "Open Selection in Pseudocode",
        "Decompile and focus the function containing the selected address",
        menu_surfaces,
        [](const action_invocation_t&) {
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
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.navigate.xrefs", "Cross References to Selection",
        "Open references for the selected analysis address",
        menu_surfaces,
        [](const action_invocation_t&) {
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
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        false, {}, "category.analysis.navigate", "Analysis / Navigate");
    register_action(rt, "analysis.modify.rename", "Rename Analysis Symbol...",
        "Rename the selected address through the reversible analysis overlay",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            rename_dialog::open(context, *address);
            return open_analysis_view("document.disassembly");
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        true, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.comment", "Edit Analysis Comment...",
        "Add or edit the selected address comment through the reversible overlay",
        menu_surfaces,
        [](const action_invocation_t&) {
            const auto context = selected_analysis_context();
            const auto address = selected_analysis_address(context);
            if (!address)
                return action_handler_result_t::failed("The analysis selection no longer has an address");
            comment_dialog::open(context, *address);
            return open_analysis_view("document.disassembly");
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        true, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.bookmark", "Bookmark Analysis Selection",
        "Persist a bookmark for the selected address in the reversible overlay",
        menu_surfaces,
        [](const action_invocation_t&) {
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
        }, [](const interaction_context_t&) { return analysis_selection_capability(); },
        true, {}, "category.analysis.modify", "Analysis / Modify");
    register_action(rt, "analysis.modify.retype", "Set Analysis Type...",
        "Apply a canonical type through the reversible overlay",
        menu_surfaces,
        [](const action_invocation_t&) {
            return action_handler_result_t::failed(
                "Use Types > Apply Type; no global canonical-type entry dialog owns validation yet");
        }, [](const interaction_context_t&) {
            const auto selection = analysis_selection_capability();
            return selection.enabled
                ? capability_state_t::unavailable(
                    "Use Types > Apply Type; no global canonical-type entry dialog owns validation yet")
                : selection;
        }, true, {}, "category.analysis.modify", "Analysis / Modify");
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
        "Queue the generated declaration and base application as one reversible overlay transaction",
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
        [](const action_invocation_t&) { code_editor_widget::trigger_undo(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return code_editor::active && code_editor_widget::can_undo() ? capability_state_t::available() : capability_state_t::unavailable(code_editor::active ? "Nothing to undo" : "Open or create a text document first"); }, true);
    register_action(rt, "edit.redo", "Redo", "Redo the last undone editor change", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_redo(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return code_editor::active && code_editor_widget::can_redo() ? capability_state_t::available() : capability_state_t::unavailable(code_editor::active ? "Nothing to redo" : "Open or create a text document first"); }, true);
    register_action(rt, "edit.cut", "Cut", "Cut the selected text", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_cut(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_selection(); }, true);
    register_action(rt, "edit.copy", "Copy", "Copy the selected text", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_copy(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_selection(); });
    register_action(rt, "edit.paste", "Paste", "Paste text at the caret", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_paste(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) {
            if (!code_editor::active)
                return capability_state_t::unavailable("Open or create a text document first");
            return code_editor_widget::can_paste()
                ? capability_state_t::available()
                : capability_state_t::unavailable("The clipboard does not contain text");
        }, true);
    register_action(rt, "edit.delete", "Delete", "Delete the selection or the character at the caret", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_delete(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_active(); }, true);
    register_action(rt, "edit.select_all", "Select All", "Select the entire document", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::trigger_select_all(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.find", "Find", "Find text in the active document", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::open_find(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.replace", "Replace", "Find and replace text in the active document", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::open_replace(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.goto_line", "Go to Line...", "Navigate to a line in the active document", all_surfaces,
        [](const action_invocation_t&) { code_editor_widget::open_goto_line(); return action_handler_result_t::completed(); },
        [](const interaction_context_t&) { return editor_active(); });
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
        context_surfaces, document_action(code_editor_widget::document_action_t::copy_line),
        [](const interaction_context_t&) { return editor_active(); });
    register_action(rt, "edit.copy_path", "Copy File Path", "Copy the active source file path",
        context_surfaces, document_action(code_editor_widget::document_action_t::copy_path),
        [](const interaction_context_t&) {
            return code_editor::active && !code_editor::filepath.empty()
                ? capability_state_t::available()
                : capability_state_t::unavailable("The active document has no file path");
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
            if (!code_editor::active)
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
        menu_surfaces,
        [&rt](const action_invocation_t&) {
            return rt.shell.decompile_or_focus_pseudocode
                ? rt.shell.decompile_or_focus_pseudocode()
                : action_handler_result_t::failed("No analysis decompiler context is available");
        }, [&rt](const interaction_context_t&) {
            return rt.shell.decompile_or_focus_pseudocode_capability
                ? rt.shell.decompile_or_focus_pseudocode_capability()
                : capability_state_t::unavailable("No analysis decompiler context is available");
        }, false, {}, "category.analysis.navigate", "Analysis / Navigate");

    auto register_view = [&](const char* id, const char* label, const char* target_view) {
        register_action(rt, id, label, "Show this IDE view", menu_surfaces,
            [&rt, id, target = stable_view_id_t(target_view)](const action_invocation_t&) {
                const auto result = application_views::open_or_focus(target);
                if (!result.ok())
                    return action_handler_result_t::failed(result.detail);
                if (rt.shell.action_executed)
                    rt.shell.action_executed(id);
                return action_handler_result_t::completed();
            }, [target = stable_view_id_t(target_view)](const interaction_context_t& context) {
                return application_views::registry().evaluate(target, context);
            });
    };
    register_action(rt, "view.explorer", "Toggle Explorer", "Show or hide Project Explorer", menu_surfaces,
        [&rt](const action_invocation_t&) {
            const stable_view_id_t id("view.project_explorer");
            const auto result = application_views::is_open(id)
                ? application_views::close(id)
                : application_views::open_or_focus(id);
            if (!result.ok())
                return action_handler_result_t::failed(result.detail);
            if (rt.shell.persist_workspace) rt.shell.persist_workspace();
            if (rt.shell.action_executed) rt.shell.action_executed("view.explorer");
            return action_handler_result_t::completed();
        });
    register_action(rt, "view.chat", "Toggle Chat", "Show or hide Chat", menu_surfaces,
        [&rt](const action_invocation_t&) {
            const stable_view_id_t id("view.ai_chat");
            const auto result = application_views::is_open(id)
                ? application_views::close(id)
                : application_views::open_or_focus(id);
            if (!result.ok())
                return action_handler_result_t::failed(result.detail);
            if (rt.shell.persist_workspace)
                rt.shell.persist_workspace();
            if (rt.shell.action_executed)
                rt.shell.action_executed("view.chat");
            return action_handler_result_t::completed();
        });
    register_action(rt, "view.output", "Toggle Output", "Show or hide Output", menu_surfaces,
        [&rt](const action_invocation_t&) {
            const stable_view_id_t id("view.output");
            const auto result = application_views::is_open(id)
                ? application_views::close(id)
                : application_views::open_or_focus(id);
            if (!result.ok())
                return action_handler_result_t::failed(result.detail);
            if (rt.shell.persist_workspace) rt.shell.persist_workspace();
            if (rt.shell.action_executed) rt.shell.action_executed("view.output");
            return action_handler_result_t::completed();
        });
    register_view("view.editor", "Editor", "document.code");
    register_view("view.workbench", "Workbench", "document.disassembly");
    register_view("view.disassembly", "Disassembly", "document.disassembly");
    register_view("view.hex", "Hex", "document.hex");
    register_view("view.pseudocode", "Pseudocode", "document.pseudocode");
    register_view("view.graph", "Graph", "document.graph");
    register_view("view.network", "Network", "view.network.connections");
    register_view("view.debugger", "Debugger", "view.debug.cpu");
    register_view("view.scan", "Scan", "view.memory.value_scan");
    register_view("view.types", "Types", "view.types.structures");
    register_view("view.analysis", "Analysis", "view.analysis.symbolic");
    register_view("view.binary_map", "Binary Map", "view.analysis.binary_map");

    application_views::initialize();
    application_views::registry().for_each_descriptor([&](const view_descriptor_t& view) {
        const std::string stable_id = compose_view_action_id(view.id);
        const std::string label = std::string("Toggle ") + view.display_name;
        const std::string category = std::string("View / ") + application_views::category_label(view.category);
        register_action(rt, stable_id.c_str(), label.c_str(), "Open, focus, or close this dockable IDE view",
            action_surface_t::application_menu | action_surface_t::command_palette |
                action_surface_t::accessibility,
            [id = view.id, &rt](const action_invocation_t&) {
                const auto result = application_views::is_open(id)
                    ? application_views::close(id)
                    : application_views::open_or_focus(id);
                if (!result.ok())
                    return action_handler_result_t::failed(result.detail);
                if (rt.shell.persist_workspace)
                    rt.shell.persist_workspace();
                return action_handler_result_t::completed();
            },
            [id = view.id](const interaction_context_t& context) {
                const auto* descriptor = application_views::registry().find_descriptor(id);
                if (!descriptor)
                    return capability_state_t::unavailable("The view is no longer registered");
                if (application_views::is_open(id) && !descriptor->closeable)
                    return capability_state_t::unavailable("This required view cannot be closed");
                return application_views::registry().evaluate(id, context);
            }, false,
            [id = view.id](const interaction_context_t&) {
                return application_views::is_open(id)
                    ? action_check_state_t::checked
                    : action_check_state_t::unchecked;
            }, view_category_id(view.category), category.c_str());

        std::string focus_id = "view.focus.";
        focus_id.append(view.id.value());
        const std::string focus_label = std::string("Focus ") + view.display_name;
        register_action(rt, focus_id.c_str(), focus_label.c_str(),
            "Open this IDE view if needed, then move keyboard focus to it",
            action_surface_t::application_menu | action_surface_t::command_palette |
                action_surface_t::accessibility,
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
        menu_surfaces,
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
            const auto result = application_views::registry().close(*focused);
            return result.ok()
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed(result.detail);
        }, [](const interaction_context_t&) {
            const auto focused = application_views::registry().focused_instance();
            if (!focused)
                return capability_state_t::unavailable("No dockable view has focus");
            const auto* descriptor = application_views::registry().find_descriptor(focused->view);
            return descriptor && descriptor->closeable
                ? capability_state_t::available()
                : capability_state_t::unavailable("The focused view cannot be closed");
        }, false, {}, "category.view", "View");

    std::size_t preset_count = 0;
    const auto* presets = workspace_layout::presets(preset_count);
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
                action_surface_t::accessibility,
            [preset](const action_invocation_t&) {
                return workspace_result(workspace_layout::switch_to(preset.id),
                    "Workspace switching failed");
            }, {}, false,
            [preset](const interaction_context_t&) {
                return workspace_layout::active_preset() == preset.id
                    ? action_check_state_t::checked
                    : action_check_state_t::unchecked;
            }, "category.workspace", "Workspace");
    }

    register_action(rt, "workspace.lock", "Lock Layout", "Prevent dock placement changes while preserving close and reopen",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            workspace_layout::set_layout_locked(!workspace_layout::layout_locked());
            return action_handler_result_t::completed();
        }, {}, false,
        [](const interaction_context_t&) {
            return workspace_layout::layout_locked()
                ? action_check_state_t::checked
                : action_check_state_t::unchecked;
        }, "category.workspace", "Workspace");
    register_action(rt, "workspace.save", "Save Current Workspace", "Save the current user-modified dock layout",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::save_user_layout(workspace_layout::active_preset_name()),
                "Saving the workspace failed");
        }, {}, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.restore_builtin", "Restore Built-in Workspace", "Restore the active preset's factory layout",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::restore_builtin(workspace_layout::active_preset()),
                "Restoring the built-in workspace failed");
        }, {}, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.reset_current", "Reset Current Layout", "Discard the active preset's saved user layout",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::reset_current(), "Resetting the layout failed");
        }, {}, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.open_missing", "Open Missing Workspace Views", "Reopen views required by the active workspace",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::open_missing_views(), "Opening missing views failed");
        }, {}, false, {}, "category.workspace", "Workspace");
    register_action(rt, "workspace.safe", "Activate Safe Layout", "Recover to the minimal known-good IDE layout",
        action_surface_t::application_menu | action_surface_t::command_palette | action_surface_t::accessibility,
        [](const action_invocation_t&) {
            return workspace_result(workspace_layout::activate_safe_layout(), "Safe Layout recovery failed");
        }, {}, false, {}, "category.workspace", "Workspace");

    const auto shell_capability = [](const std::function<void()>& callback, const char* reason) {
        return callback ? capability_state_t::available() : capability_state_t::unavailable(reason);
    };
    register_action(rt, "tools.load_binary", "Load Binary...", "Open a binary and create an analysis session",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.load_binary)
                return action_handler_result_t::failed("Binary loader is unavailable");
            rt.shell.load_binary();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.load_binary, "Binary loader is unavailable");
        }, false, {}, "category.tools", "Tools");
    register_action(rt, "tools.attach_process", "Attach to Process...", "Select and attach to a running process",
        menu_surfaces, [&rt](const action_invocation_t&) {
            if (!rt.shell.attach_process)
                return action_handler_result_t::failed("Process attachment is unavailable");
            rt.shell.attach_process();
            return action_handler_result_t::completed();
        }, [&rt, shell_capability](const interaction_context_t&) {
            return shell_capability(rt.shell.attach_process, "Process attachment is unavailable");
        }, false, {}, "category.tools", "Tools");

	const auto register_debugger_action = [&rt](const char* id, const char* label,
		const char* description, debugger_view::execution_command_t command) {
		register_action(rt, id, label, description,
			action_surface_t::application_menu | action_surface_t::command_palette |
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
    register_action(rt, "tools.settings", "Settings", "Open AiDA settings",
        menu_surfaces, [&rt](const action_invocation_t&) {
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
            if (rt.explorer.index < 0 || static_cast<std::size_t>(rt.explorer.index) >= file_browser::entries.size())
                return action_handler_result_t::failed("Explorer selection is stale");
            if (rt.explorer.directory)
                file_browser::toggle_dir(rt.explorer.index);
            else
                file_browser::open_file(rt.explorer.index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) { return rt.explorer.index >= 0 && static_cast<std::size_t>(rt.explorer.index) < file_browser::entries.size() ? capability_state_t::available() : capability_state_t::unavailable("Select a file or folder first"); });
    register_action(rt, "explorer.copy_path", "Copy Path", "Copy the full path", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.explorer.path.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.explorer.path.empty() ? capability_state_t::unavailable("The selected item has no path") : capability_state_t::available(); });
    register_action(rt, "explorer.copy_name", "Copy Name", "Copy the item name", context_surfaces,
        [&rt](const action_invocation_t&) { ImGui::SetClipboardText(rt.explorer.name.c_str()); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) { return rt.explorer.name.empty() ? capability_state_t::unavailable("The selected item has no name") : capability_state_t::available(); });
    register_action(rt, "explorer.search", "Search Workspace", "Open workspace search", context_surfaces,
        [](const action_invocation_t&) {
            const auto result = application_views::open_or_focus(stable_view_id_t("view.workspace_search"));
            return result.ok() ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        });
    register_action(rt, "explorer.refresh", "Refresh", "Refresh Explorer", context_surfaces,
        [](const action_invocation_t&) { file_browser::needs_refresh = true; return action_handler_result_t::completed(); });

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

    register_action(rt, "recent.open", "Open", "Open or activate this recent binary", context_surfaces,
        [&rt](const action_invocation_t&) {
            std::size_t index = 0;
            if (find_open_session(rt.recent.path, index))
                return analysis_session::switch_session(index)
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed("The open session could not be activated");
            const std::string name = std::filesystem::path(rt.recent.path).filename().string();
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
    register_action(rt, "output.copy_all", "Copy All", "Copy the complete bounded output buffer", context_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::copy_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.clear", "Clear", "Clear this view without affecting its underlying service", context_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::clear(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.select_all", "Select All", "Select all text in this output view", context_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::select_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);
    register_action(rt, "output.follow", "Follow Tail", "Toggle automatic following of new output", context_surfaces,
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
    register_action(rt, "output.filter", "Focus Filter", "Focus the output filter", context_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::focus_filter(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, [output_tab](const interaction_context_t&) {
            return output_views::supports_filter(output_tab())
                ? capability_state_t::available()
                : capability_state_t::unavailable("Interactive terminal output cannot be filtered safely");
        });
    register_action(rt, "output.export", "Export...", "Export the complete bounded output buffer to a chosen file", context_surfaces,
        [output_tab](const action_invocation_t&) {
            const auto result = output_views::export_all(output_tab());
            return result.succeeded ? action_handler_result_t::completed() : action_handler_result_t::failed(result.detail);
        }, output_capability);

    register_action(rt, "tab.save", "Save", "Save this editor tab", context_surfaces,
        [&rt](const action_invocation_t&) { return file_tabs::save_tab_to_disk(rt.tab.index) ? action_handler_result_t::completed() : action_handler_result_t::failed("This tab has no writable path"); },
        [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index) || rt.tab.path.empty())
                return capability_state_t::unavailable("This tab has no writable path");
            const auto& tab = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)];
            return tab.external_conflict && !tab.external_overwrite_approved
                ? capability_state_t::unavailable(
                    "The file changed on disk; resolve the editor conflict before saving")
                : capability_state_t::available();
        });
    register_action(rt, "tab.close", "Close", "Close this editor tab", context_surfaces,
        [&rt](const action_invocation_t&) { close_tab_with_confirmation(rt.tab.index); return action_handler_result_t::completed(); },
        [&rt](const interaction_context_t&) {
            if (!file_tabs::is_valid_tab_index(rt.tab.index))
                return capability_state_t::unavailable("The tab is no longer open");
            return file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].pinned
                ? capability_state_t::unavailable("Unpin this document before closing it")
                : capability_state_t::available();
        });
    register_action(rt, "tab.close_others", "Close Other Tabs", "Close all other saved editor tabs", context_surfaces,
        [&rt](const action_invocation_t&) {
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1; index >= 0; --index)
                if (index != rt.tab.index &&
                    file_tabs::tabs[file_tabs::tab_index(index)].group_id == group &&
                    !file_tabs::tabs[file_tabs::tab_index(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
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
            const auto group = file_tabs::tabs[file_tabs::tab_index(rt.tab.index)].group_id;
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1;
                 index > rt.tab.index; --index)
                if (file_tabs::tabs[file_tabs::tab_index(index)].group_id == group &&
                    !file_tabs::tabs[file_tabs::tab_index(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [&rt](const interaction_context_t&) {
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
            for (int index = static_cast<int>(file_tabs::tabs.size()) - 1;
                 index >= 0; --index)
                if (!file_tabs::tabs[static_cast<std::size_t>(index)].dirty &&
                    !file_tabs::tabs[static_cast<std::size_t>(index)].pinned)
                    file_tabs::close_tab(index);
            return action_handler_result_t::completed();
        }, [](const interaction_context_t&) {
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

    register_shortcut(rt, "binding.editor.save", "file.save", ImGuiMod_Ctrl | ImGuiKey_S, "Ctrl+S");
    register_shortcut(rt, "binding.editor.undo", "edit.undo", ImGuiMod_Ctrl | ImGuiKey_Z, "Ctrl+Z", true);
    register_shortcut(rt, "binding.editor.redo", "edit.redo", ImGuiMod_Ctrl | ImGuiKey_Y, "Ctrl+Y", true);
    register_shortcut(rt, "binding.editor.cut", "edit.cut", ImGuiMod_Ctrl | ImGuiKey_X, "Ctrl+X");
    register_shortcut(rt, "binding.editor.copy", "edit.copy", ImGuiMod_Ctrl | ImGuiKey_C, "Ctrl+C");
    register_shortcut(rt, "binding.editor.paste", "edit.paste", ImGuiMod_Ctrl | ImGuiKey_V, "Ctrl+V");
    register_shortcut(rt, "binding.editor.delete", "edit.delete", ImGuiKey_Delete, "Delete", true);
    register_shortcut(rt, "binding.editor.select_all", "edit.select_all", ImGuiMod_Ctrl | ImGuiKey_A, "Ctrl+A");
    register_shortcut(rt, "binding.editor.find", "edit.find", ImGuiMod_Ctrl | ImGuiKey_F, "Ctrl+F");
    register_shortcut(rt, "binding.editor.replace", "edit.replace", ImGuiMod_Ctrl | ImGuiKey_H, "Ctrl+H");
    register_shortcut(rt, "binding.editor.goto", "edit.goto_line", ImGuiMod_Ctrl | ImGuiKey_G, "Ctrl+G");
    register_shortcut(rt, "binding.editor.close", "file.close", ImGuiMod_Ctrl | ImGuiKey_W, "Ctrl+W");
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
    register_global_shortcut(rt, "binding.global.new", "file.new", ImGuiMod_Ctrl | ImGuiKey_N, "Ctrl+N");
    register_global_shortcut(rt, "binding.global.open", "file.open", ImGuiMod_Ctrl | ImGuiKey_O, "Ctrl+O");
    register_global_shortcut(rt, "binding.global.open_folder", "file.open_folder", ImGuiMod_Ctrl | ImGuiKey_K, "Ctrl+K");
    register_global_shortcut(rt, "binding.global.save_as", "file.save_as", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S, "Ctrl+Shift+S");
    register_global_shortcut(rt, "binding.global.explorer", "view.explorer", ImGuiMod_Ctrl | ImGuiKey_B, "Ctrl+B");
    register_global_shortcut(rt, "binding.global.chat", "view.chat", ImGuiMod_Ctrl | ImGuiKey_J, "Ctrl+J");
    register_global_shortcut(rt, "binding.global.output", "view.output", ImGuiMod_Ctrl | ImGuiKey_GraveAccent, "Ctrl+`");
    register_global_shortcut(rt, "binding.global.network", "view.network", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_N, "Ctrl+Shift+N");
    register_global_shortcut(rt, "binding.global.debugger", "view.debugger", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_D, "Ctrl+Shift+D");
    register_global_shortcut(rt, "binding.global.scan", "view.scan", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_M, "Ctrl+Shift+M");
    register_global_shortcut(rt, "binding.global.binary_map", "view.binary_map", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_B, "Ctrl+Shift+B");
    register_global_shortcut(rt, "binding.global.command_palette", "view.command_palette", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_P, "Ctrl+Shift+P");
    register_global_shortcut(rt, "binding.global.new_chat", "ai.new_chat", ImGuiMod_Ctrl | ImGuiKey_L, "Ctrl+L");
    register_global_shortcut(rt, "binding.global.workspace_search", "view.global_search", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_F, "Ctrl+Shift+F");
    register_global_shortcut(rt, "binding.global.preferences", "edit.preferences", ImGuiMod_Ctrl | ImGuiKey_Comma, "Ctrl+,");
    register_global_shortcut(rt, "binding.global.xrefs", "view.focus.view.analysis.references", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_X, "Ctrl+Shift+X");
    register_global_shortcut(rt, "binding.global.deobfuscation", "view.focus.view.analysis.deobfuscation", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_O, "Ctrl+Shift+O");
    register_global_shortcut(rt, "binding.global.next_document_or_session",
        "navigate.next_document_or_session", ImGuiMod_Ctrl | ImGuiKey_Tab, "Ctrl+Tab");
    register_global_shortcut(rt, "binding.global.previous_document_or_session",
        "navigate.previous_document_or_session",
        ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_Tab, "Ctrl+Shift+Tab");
	register_global_shortcut(rt, "binding.global.shell.maximize", "shell.toggle_maximize", ImGuiKey_F11, "F11");
	register_domain_shortcut(rt, "binding.analysis.decompile", "analysis.decompile_or_focus_pseudocode",
		ImGuiKey_F5, "F5", k_analysis_scope, 20);
	register_domain_shortcut(rt, "binding.debugger.run", "debugger.run_continue", ImGuiKey_F5, "F5", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.pause", "debugger.pause", ImGuiKey_F6, "F6", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_over", "debugger.step_over", ImGuiKey_F10, "F10", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_into", "debugger.step_into", ImGuiKey_F11, "F11", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.step_out", "debugger.step_out", ImGuiMod_Shift | ImGuiKey_F11, "Shift+F11", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.stop", "debugger.stop", ImGuiMod_Shift | ImGuiKey_F5, "Shift+F5", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.restart", "debugger.restart", ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_F5, "Ctrl+Shift+F5", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.detach", "debugger.detach", ImGuiMod_Ctrl | ImGuiKey_F2, "Ctrl+F2", k_debugger_scope, 30);
	register_domain_shortcut(rt, "binding.debugger.toggle_breakpoint", "debugger.toggle_breakpoint_at_rip", ImGuiKey_F9, "F9", k_debugger_scope, 30);

    register_menu(rt, "menu.editor.text", k_editor_context_type, {
        menu_section("section.editor.history", context_menu_group_t::modify_run, 0, {menu_action("edit.undo", 0), menu_action("edit.redo", 1)}),
        menu_section("section.editor.clipboard", context_menu_group_t::copy_export, 1,
            {menu_action("edit.cut", 0), menu_action("edit.copy", 1), menu_action("edit.paste", 2),
             menu_action("edit.delete", 3), menu_action("edit.select_all", 4),
             menu_action("edit.select_word", 5), menu_action("edit.select_line", 6),
             menu_action("edit.copy_line", 7), menu_action("edit.copy_path", 8)}),
        menu_section("section.editor.lines", context_menu_group_t::modify_run, 2,
            {menu_action("edit.duplicate_line", 0), menu_action("edit.delete_line", 1),
             menu_action("edit.move_line_up", 2), menu_action("edit.move_line_down", 3),
             menu_action("edit.toggle_line_comment", 4),
             menu_action("edit.trim_trailing_whitespace", 5)}),
        menu_section("section.editor.navigate", context_menu_group_t::open_navigate, 3,
            {menu_action("edit.find", 0), menu_action("edit.replace", 1),
             menu_action("edit.goto_line", 2)}),
        menu_section("section.editor.diagnostics", context_menu_group_t::inspect_relate, 4,
            {menu_action("programming.show_problems", 0)}),
        menu_section("section.editor.file", context_menu_group_t::modify_run, 5,
            {menu_action("file.save", 0), menu_action("file.save_as", 1),
             menu_action("file.save_all", 2), menu_action("file.close", 3)})
    });
    register_menu(rt, "menu.editor.tab", k_tab_context_type, {
        menu_section("section.tab.file", context_menu_group_t::modify_run, 0,
            {menu_action("tab.save", 0), menu_action("tab.close", 1),
             menu_action("tab.close_others", 2), menu_action("tab.close_right", 3),
             menu_action("tab.close_saved", 4)}),
        menu_section("section.tab.group", context_menu_group_t::open_navigate, 1,
            {menu_action("tab.toggle_pin", 0), menu_action("tab.move_new_group", 1),
             menu_action("tab.move_primary_group", 2), menu_action("tab.history_back", 3),
             menu_action("tab.history_forward", 4)}),
        menu_section("section.tab.copy", context_menu_group_t::copy_export, 2,
            {menu_action("tab.copy_path", 0), menu_action("tab.copy_name", 1)})
    });
    register_menu(rt, "menu.explorer.entry", k_explorer_entry_context_type, {
        menu_section("section.explorer.open", context_menu_group_t::open_navigate, 0, {menu_action("explorer.open", 0), menu_action("explorer.search", 1)}),
        menu_section("section.explorer.copy", context_menu_group_t::copy_export, 1, {menu_action("explorer.copy_path", 0), menu_action("explorer.copy_name", 1)}),
        menu_section("section.explorer.refresh", context_menu_group_t::inspect_relate, 2, {menu_action("explorer.refresh", 0)})
    });
    register_menu(rt, "menu.explorer.empty", k_explorer_empty_context_type, {
        menu_section("section.explorer.workspace", context_menu_group_t::open_navigate, 0, {menu_action("file.open_folder", 0), menu_action("explorer.search", 1), menu_action("explorer.refresh", 2)})
    });
    register_menu(rt, "menu.workspace_search.result", k_workspace_search_context_type, {
        menu_section("section.workspace_search.open", context_menu_group_t::open_navigate, 0, {menu_action("workspace_search.open", 0)}),
        menu_section("section.workspace_search.copy", context_menu_group_t::copy_export, 1, {menu_action("workspace_search.copy_path", 0), menu_action("workspace_search.copy_line", 1)})
    });
    register_menu(rt, "menu.recent.item", k_recent_context_type, {
        menu_section("section.recent.open", context_menu_group_t::open_navigate, 0, {menu_action("recent.open", 0)}),
        menu_section("section.recent.copy", context_menu_group_t::copy_export, 1, {menu_action("recent.copy_path", 0)}),
        menu_section("section.recent.close", context_menu_group_t::destructive, 2, {menu_action("recent.close", 0)})
    });
    register_menu(rt, "menu.output.view", k_output_context_type, {
        menu_section("section.output.copy", context_menu_group_t::copy_export, 0, {menu_action("output.copy_all", 0), menu_action("output.select_all", 1), menu_action("output.export", 2)}),
        menu_section("section.output.view", context_menu_group_t::inspect_relate, 1, {menu_action("output.follow", 0), menu_action("output.filter", 1)}),
        menu_section("section.output.clear", context_menu_group_t::destructive, 2, {menu_action("output.clear", 0)})
    });
}

interaction_context_t editor_context(runtime_t& rt) {
    interaction_context_t context;
    context.active_view = stable_view_id_t("document.code");
    if (rt.editor_focused)
        context.focus_path.push_back({stable_scope_id_t(k_editor_scope), focus_scope_kind_t::text_editor});
    context.payload = typed_context_ref_t::from(context_type(k_editor_context_type), rt.editor);
    context.generation = rt.generation;
    context.text_input_active = rt.editor_text_input;
    return context;
}

bool analysis_center_focused() noexcept {
    switch (globals::ui::active_center_view) {
    case center_view_t::disassembly:
    case center_view_t::hex_view:
    case center_view_t::pseudocode:
    case center_view_t::graph_view:
    case center_view_t::binary_map:
    case center_view_t::functions_panel:
    case center_view_t::xref_database:
    case center_view_t::analysis_hub:
    case center_view_t::workbench:
        return true;
    default:
        return false;
    }
}

interaction_context_t active_context(runtime_t& rt) {
    auto context = editor_context(rt);
    if (rt.editor_focused)
        return context;
    context.focus_path.clear();
    context.text_input_active = false;
    const auto focused = application_views::registry().focused_instance();
    if (focused) {
        context.active_view = focused->view;
        context.active_view_instance = focused->instance;
        const auto* descriptor = application_views::registry().find_descriptor(focused->view);
        if (descriptor && descriptor->category == view_category_t::debugger)
            context.focus_path.push_back({stable_scope_id_t(k_debugger_scope), focus_scope_kind_t::domain});
        else if (descriptor && (descriptor->category == view_category_t::analysis ||
                 descriptor->category == view_category_t::document))
            context.focus_path.push_back({stable_scope_id_t(k_analysis_scope), focus_scope_kind_t::domain});
    } else if (globals::ui::active_center_view == center_view_t::debugger_view) {
        context.active_view = stable_view_id_t("view.debug.cpu");
        context.focus_path.push_back({stable_scope_id_t(k_debugger_scope), focus_scope_kind_t::domain});
    } else if (analysis_center_focused()) {
        context.active_view = stable_view_id_t("document.disassembly");
        context.focus_path.push_back({stable_scope_id_t(k_analysis_scope), focus_scope_kind_t::domain});
    }
    return context;
}

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void execute_resolution(runtime_t& rt, const shortcut_resolution_t& resolution) {
    if (!resolution.resolved())
        return;
    action_invocation_t invocation{rt.current};
    invocation.source = action_invocation_source_t::shortcut;
    invocation.invocation_id = rt.invocation++;
    rt.actions.execute(resolution.action, invocation);
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
    rt.editor.focused = rt.editor_focused;
    rt.current = active_context(rt);
}

void process_global_shortcuts() {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    if (ImGui::GetIO().WantTextInput)
        return;
    const ImGuiKey keys[] = {ImGuiKey_N, ImGuiKey_O, ImGuiKey_K, ImGuiKey_S, ImGuiKey_B,
        ImGuiKey_J, ImGuiKey_L, ImGuiKey_P, ImGuiKey_GraveAccent, ImGuiKey_D, ImGuiKey_M,
        ImGuiKey_F, ImGuiKey_Comma, ImGuiKey_X, ImGuiKey_F2, ImGuiKey_F5, ImGuiKey_F6,
		ImGuiKey_F9, ImGuiKey_F10, ImGuiKey_F11};
    const auto& io = ImGui::GetIO();
    for (const auto key : keys) {
        if (!ImGui::IsKeyPressed(key, false))
            continue;
        ImGuiKeyChord stroke = key;
        if (io.KeyCtrl) stroke |= ImGuiMod_Ctrl;
        if (io.KeyShift) stroke |= ImGuiMod_Shift;
        if (io.KeyAlt) stroke |= ImGuiMod_Alt;
        if (io.KeySuper) stroke |= ImGuiMod_Super;
        execute_resolution(rt, rt.shortcuts.feed(stroke, false, now_ms(), rt.current, rt.actions));
    }
    execute_resolution(rt, rt.shortcuts.poll(now_ms(), rt.current, rt.actions));
}

void set_editor_focus(bool focused, bool text_input_active) {
    auto& rt = runtime();
    initialize(rt);
    if (rt.editor_focused != focused || rt.editor_text_input != text_input_active)
        ++rt.generation;
    rt.editor_focused = focused;
    rt.editor_text_input = text_input_active;
    rt.editor.focused = focused;
    rt.current = editor_context(rt);
}

void process_editor_shortcuts() {
    auto& rt = runtime();
    initialize(rt);
    rt.current = editor_context(rt);
    const auto& io = ImGui::GetIO();
    const ImGuiKey keys[] = {ImGuiKey_S, ImGuiKey_Z, ImGuiKey_Y, ImGuiKey_X, ImGuiKey_C,
        ImGuiKey_V, ImGuiKey_Delete, ImGuiKey_A, ImGuiKey_F, ImGuiKey_H, ImGuiKey_G,
        ImGuiKey_W};
    for (const auto key : keys) {
        if (!ImGui::IsKeyPressed(key, true))
            continue;
        ImGuiKeyChord stroke = key;
        if (io.KeyCtrl) stroke |= ImGuiMod_Ctrl;
        if (io.KeyShift) stroke |= ImGuiMod_Shift;
        if (io.KeyAlt) stroke |= ImGuiMod_Alt;
        if (io.KeySuper) stroke |= ImGuiMod_Super;
        execute_resolution(rt, rt.shortcuts.feed(stroke, ImGui::IsKeyPressed(key, true) && !ImGui::IsKeyPressed(key, false), now_ms(), rt.current, rt.actions));
    }
    execute_resolution(rt, rt.shortcuts.poll(now_ms(), rt.current, rt.actions));
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
        item.conflict = has_conflict(binding.id);
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

std::string view_action_id(const stable_view_id_t& view) {
    return compose_view_action_id(view);
}

action_execution_result_t execute_action(const char* id, action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    rt.current = active_context(rt);
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    return rt.actions.execute(action_id(id), invocation);
}

void open_editor_context_menu(context_menu_open_origin_t origin) {
    auto& rt = runtime();
    initialize(rt);
    ++rt.generation;
    rt.editor_popup_context = editor_context(rt);
    rt.editor_popup_request = {stable_menu_id_t("menu.editor.text"), origin, rt.editor_popup_context.generation};
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
    rt.explorer = {entry_index, entry.full_path, entry.name, entry.is_dir};
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

action_execution_result_t execute_output_action(int tab, const char* action,
                                                action_invocation_source_t source) {
    auto& rt = runtime();
    initialize(rt);
    if (tab < 0 || tab >= static_cast<int>(bottom_tab_t::COUNT))
        return {};
    rt.output.tab = tab;
    rt.current = {};
    rt.current.active_view = stable_view_id_t(tab == static_cast<int>(bottom_tab_t::terminal)
        ? "view.terminal" : tab == static_cast<int>(bottom_tab_t::mcp_log)
        ? "view.mcp_log" : tab == static_cast<int>(bottom_tab_t::driver_log)
        ? "view.driver_log" : tab == static_cast<int>(bottom_tab_t::sandbox_log)
        ? "view.sandbox_log" : "view.output");
    rt.current.payload = typed_context_ref_t::from(context_type(k_output_context_type), rt.output);
    rt.current.generation = ++rt.generation;
    action_invocation_t invocation{rt.current};
    invocation.source = source;
    invocation.invocation_id = rt.invocation++;
    return rt.actions.execute(action_id(action), invocation);
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

}
