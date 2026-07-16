#pragma once

#include "application_action_registry.hpp"
#include "context_menu_contract.hpp"
#include "shortcut_resolver.hpp"

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
    std::string scope;
    std::string disabled_reason;
    bool enabled = false;
    bool conflict = false;
};

void configure_shell_callbacks(shell_callbacks_t callbacks);
void begin_frame();
void process_global_shortcuts();
void set_editor_focus(bool focused, bool text_input_active);
void process_editor_shortcuts();

action_presentation_t present_action(const char* action_id);
std::vector<action_presentation_t> list_actions(action_surface_t surface);
std::vector<shortcut_presentation_t> list_shortcuts();
std::string view_action_id(const stable_view_id_t& view);
action_execution_result_t execute_action(const char* action_id,
                                         action_invocation_source_t source);

void open_editor_context_menu(context_menu_open_origin_t origin);
void render_editor_context_menu();

void open_editor_tab_context_menu(int tab_index, context_menu_open_origin_t origin);
void render_editor_tab_context_menu();

void open_explorer_context_menu(int entry_index, context_menu_open_origin_t origin);
void open_explorer_empty_context_menu(context_menu_open_origin_t origin);
void render_explorer_context_menu();

void open_workspace_search_context_menu(int result_index, context_menu_open_origin_t origin);
void render_workspace_search_context_menu();

void open_recent_context_menu(const std::string& path, bool open_session,
                              context_menu_open_origin_t origin);
void render_recent_context_menu();

action_execution_result_t execute_output_action(int tab, const char* action_id,
                                                action_invocation_source_t source);
void open_output_context_menu(int tab, context_menu_open_origin_t origin);
void render_output_context_menu();

}
