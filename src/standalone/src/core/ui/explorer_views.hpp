#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida::ui::explorer_views {

enum class file_operation_t : std::uint8_t {
    new_file,
    new_folder,
    rename,
    cut,
    copy,
    paste,
    duplicate,
    remove,
    open_with,
    terminal_here
};

struct file_operation_capability_t {
    bool enabled = false;
    std::string reason;
};

struct file_operation_result_t {
    bool accepted = false;
    std::string detail;
};

struct file_operation_target_t {
    std::string path;
    bool directory = false;
};

void render_start_center();
void render_project_explorer();
void render_workspace_search();
void render_sessions();
void render_recent();
bool can_restore_previous_session();
bool request_restore_previous_session();
file_operation_capability_t file_operation_capability(file_operation_t operation,
    const std::string& path, bool directory);
file_operation_result_t request_file_operation(file_operation_t operation,
    const std::string& path, bool directory);
file_operation_capability_t file_operation_capability(file_operation_t operation,
    const std::vector<file_operation_target_t>& targets);
file_operation_result_t request_file_operation(file_operation_t operation,
    const std::vector<file_operation_target_t>& targets);
void render_global_file_operation_dialogs();

}
