#pragma once

#include "imgui/imgui.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aida::ui::workspace_layout {

enum class dock_role_t {
    root,
    navigator,
    documents,
    inspector,
    bottom
};

enum class dock_split_direction_t {
    left,
    right,
    up,
    down
};

struct dock_nodes_t {
    ImGuiID root = 0;
    ImGuiID navigator = 0;
    ImGuiID documents = 0;
    ImGuiID inspector = 0;
    ImGuiID bottom = 0;
};

struct window_placement_state_t {
    bool realized = false;
    bool docked = false;
    ImGuiID dock_node = 0;
    dock_role_t role = dock_role_t::root;
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
    std::uint32_t revision = 1;
};

enum class workspace_identity_kind_t {
    built_in,
    user
};

struct workspace_identity_t {
    workspace_identity_kind_t kind = workspace_identity_kind_t::built_in;
    workspace_preset_t preset = workspace_preset_t::analysis;
    std::string user_name;
};

struct user_workspace_descriptor_t {
    std::string name;
    workspace_preset_t base_preset = workspace_preset_t::analysis;
    std::uint64_t generation = 0;
    bool active = false;
};

enum class workspace_request_result_t {
    completed,
    queued,
    unchanged,
    busy,
    invalid_name,
    already_exists,
    not_found,
    unavailable,
    failed
};

bool initialize(ImGuiID root_dockspace_id) noexcept;
void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept;
bool surfaces_ready() noexcept;
void render_transition_surface() noexcept;
void render_global_dock_navigator() noexcept;
void settle_default_selection() noexcept;
ImGuiID node_id(dock_role_t role) noexcept;
window_placement_state_t inspect_window_placement(std::string_view window_name) noexcept;
workspace_request_result_t float_window(std::string_view window_name) noexcept;
workspace_request_result_t dock_window(std::string_view window_name, dock_role_t role) noexcept;
workspace_request_result_t split_window(std::string_view window_name,
    std::string_view anchor_window_name, dock_split_direction_t direction) noexcept;
void persist_if_requested() noexcept;
void settle_pending_operation_for_shutdown() noexcept;
void shutdown() noexcept;
const workspace_preset_descriptor_t* presets(std::size_t& count) noexcept;
std::uint32_t preset_revision(workspace_preset_t preset) noexcept;
workspace_preset_t active_preset() noexcept;
std::string_view active_preset_name() noexcept;
workspace_identity_t active_identity() noexcept;
std::string active_identity_key() noexcept;
std::shared_ptr<const std::vector<user_workspace_descriptor_t>> user_layout_catalog() noexcept;
bool user_layout_catalog_ready() noexcept;
bool preset_default_opens_view(workspace_preset_t preset,
                               std::string_view stable_view_id) noexcept;
bool layout_locked() noexcept;
workspace_request_result_t set_layout_locked(bool locked) noexcept;
bool operation_pending() noexcept;
std::string operation_status() noexcept;
workspace_request_result_t switch_to(workspace_preset_t preset) noexcept;
workspace_request_result_t save_user_layout(std::string_view name, bool overwrite = false) noexcept;
workspace_request_result_t save_active_user_layout() noexcept;
workspace_request_result_t load_user_layout(std::string_view name) noexcept;
workspace_request_result_t load_user_layout_exact(std::string_view name,
                                                  std::uint64_t expected_generation) noexcept;
workspace_request_result_t rename_user_layout(std::string_view current_name,
                                              std::string_view new_name) noexcept;
workspace_request_result_t delete_user_layout(std::string_view name) noexcept;
workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept;
workspace_request_result_t reset_current() noexcept;
workspace_request_result_t reset_all() noexcept;
workspace_request_result_t activate_safe_layout() noexcept;
workspace_request_result_t open_missing_views() noexcept;

}
