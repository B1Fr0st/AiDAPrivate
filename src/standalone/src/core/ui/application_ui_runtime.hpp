#pragma once

#include "application_action_registry.hpp"
#include "context_menu_contract.hpp"
#include "shortcut_resolver.hpp"
#include "view_registry.hpp"
#include "../editor/programming_language_service.hpp"

#include <functional>
#include <string>
#include <vector>

namespace aida::ui::application_ui {

struct shell_callbacks_t {
    std::function<void()> open_file;
    std::function<void()> open_folder;
    std::function<void()> save_as;
    std::function<void()> exit_application;
    std::function<void()> load_binary;
    std::function<void()> attach_process;
    std::function<void()> open_settings;
    std::function<void()> open_driver_status;
    std::function<void()> new_chat;
    std::function<void()> open_shortcuts;
    std::function<void()> open_workspace_save_as;
    std::function<void()> open_workspace_manager;
    std::function<void()> open_workspace_reset_all;
    std::function<void()> persist_workspace;
    std::function<void()> toggle_maximize;
    std::function<action_handler_result_t()> decompile_or_focus_pseudocode;
    std::function<capability_state_t()> decompile_or_focus_pseudocode_capability;
    std::function<void(const char*)> action_executed;
};

struct action_presentation_t {
    std::string id;
    std::string label;
    std::string description;
    std::string category;
    std::string shortcut;
    std::string disabled_reason;
    bool visible = false;
    bool enabled = false;
};

struct shortcut_presentation_t {
    std::string binding_id;
    std::string action_id;
    std::string label;
    std::string category;
    std::string shortcut;
    std::string default_shortcut;
    std::string scope;
    std::string disabled_reason;
    bool enabled = false;
    bool binding_enabled = false;
    bool conflict = false;
    bool customized = false;
    bool editable = false;
};

enum class shortcut_edit_status_t : std::uint8_t {
    completed,
    conflict,
    invalid,
    unavailable,
    persistence_rejected
};

struct shortcut_edit_result_t {
    shortcut_edit_status_t status = shortcut_edit_status_t::completed;
    std::string detail;
    std::vector<std::string> conflicts;

    bool completed() const noexcept {
        return status == shortcut_edit_status_t::completed;
    }
};

struct retained_entity_action_t {
    std::string action_id;
    capability_state_t capability;
    std::function<action_handler_result_t()> invoke;
    action_check_state_t check_state = action_check_state_t::not_checkable;
};

struct retained_entity_context_t {
    std::string owner_id;
    std::string entity_id;
    std::uint64_t entity_generation = 0;
    stable_view_id_t active_view;
    stable_menu_id_t menu;
    std::function<capability_state_t()> validate_identity;
    std::vector<retained_entity_action_t> actions;
};

void configure_shell_callbacks(shell_callbacks_t callbacks);
void begin_frame();
void process_global_shortcuts();
void set_editor_focus(bool focused, bool text_input_active);
void process_editor_shortcuts();
void set_shortcut_capture_active(bool active) noexcept;

action_presentation_t present_action(const char* action_id);
action_presentation_t present_retained_entity_action(
    const char* action_id, const retained_entity_context_t& context);
capability_state_t action_capability(const char* action_id);
std::vector<action_presentation_t> list_actions(action_surface_t surface);
std::vector<shortcut_presentation_t> list_shortcuts();
std::string format_shortcut_sequence(const std::vector<ImGuiKeyChord>& strokes);
shortcut_edit_result_t update_shortcut_override(
    const char* binding_id, const std::vector<ImGuiKeyChord>& strokes,
    bool replace_conflicts);
shortcut_edit_result_t reset_shortcut_override(const char* binding_id);
shortcut_edit_result_t disable_shortcut_override(const char* binding_id);
shortcut_edit_result_t reset_all_shortcut_overrides();
std::string view_action_id(const stable_view_id_t& view);
action_execution_result_t execute_action(const char* action_id,
                                         action_invocation_source_t source);
action_execution_result_t execute_retained_entity_action(
    const char* action_id, action_invocation_source_t source,
    const retained_entity_context_t& context);
void publish_action_execution_failure(const char* action_id,
    const action_execution_result_t& result,
    action_invocation_source_t source) noexcept;

void open_editor_context_menu(context_menu_open_origin_t origin);
void render_editor_context_menu();

void open_editor_tab_context_menu(int tab_index, context_menu_open_origin_t origin);
void render_editor_tab_context_menu();

void open_explorer_context_menu(int entry_index, context_menu_open_origin_t origin);
void open_explorer_empty_context_menu(context_menu_open_origin_t origin);
void render_explorer_context_menu();

void open_workspace_search_context_menu(int result_index, context_menu_open_origin_t origin);
void render_workspace_search_context_menu();

void open_programming_result_context_menu(
    aida::editor::language_service::location_t location,
    std::string label, std::string provenance,
    aida::editor::language_service::capability_kind_t kind,
    std::uint64_t request_id, std::uint64_t request_generation,
    std::uint64_t provider_generation, std::uint64_t index_generation,
    context_menu_open_origin_t origin);
void render_programming_result_context_menu();

void open_recent_context_menu(const std::string& path, bool open_session,
                              context_menu_open_origin_t origin);
void render_recent_context_menu();

void open_view_surface_context_menu(const view_instance_id_t& instance,
                                    context_menu_open_origin_t origin);
void render_view_surface_context_menu(const view_instance_id_t& instance);

action_execution_result_t execute_output_action(int tab, const char* action_id,
                                                action_invocation_source_t source);
void open_output_context_menu(int tab, context_menu_open_origin_t origin);
void render_output_context_menu();

void open_retained_entity_context_menu(retained_entity_context_t context,
                                       context_menu_open_origin_t origin);
void render_retained_entity_context_menu(const char* owner_id);
std::string consume_retained_entity_action(const char* owner_id,
                                           const char* entity_id);

}
