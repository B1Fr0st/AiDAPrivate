#pragma once

#include "imgui/imgui.h"

#include <cstddef>
#include <string_view>

namespace aida::ui::workspace_layout {

enum class dock_role_t {
    root,
    navigator,
    documents,
    inspector,
    bottom
};

struct dock_nodes_t {
    ImGuiID root = 0;
    ImGuiID navigator = 0;
    ImGuiID documents = 0;
    ImGuiID inspector = 0;
    ImGuiID bottom = 0;
};

enum class workspace_preset_t {
    analysis,
    debugging,
    memory,
    types_structures,
    network,
    automation_ai,
    programming,
    safe
};

struct workspace_preset_descriptor_t {
    workspace_preset_t id;
    std::string_view stable_id;
    std::string_view display_name;
    std::string_view description;
};

enum class workspace_request_result_t {
    completed,
    unchanged,
    invalid_name,
    unavailable,
    failed
};

bool initialize(ImGuiID root_dockspace_id) noexcept;
void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept;
ImGuiID node_id(dock_role_t role) noexcept;
void persist_if_requested() noexcept;
void shutdown() noexcept;
const workspace_preset_descriptor_t* presets(std::size_t& count) noexcept;
workspace_preset_t active_preset() noexcept;
std::string_view active_preset_name() noexcept;
bool layout_locked() noexcept;
void set_layout_locked(bool locked) noexcept;
workspace_request_result_t switch_to(workspace_preset_t preset) noexcept;
workspace_request_result_t save_user_layout(std::string_view name) noexcept;
workspace_request_result_t load_user_layout(std::string_view name) noexcept;
workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept;
workspace_request_result_t reset_current() noexcept;
workspace_request_result_t reset_all() noexcept;
workspace_request_result_t activate_safe_layout() noexcept;
workspace_request_result_t open_missing_views() noexcept;

}
