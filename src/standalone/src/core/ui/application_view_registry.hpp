#pragma once

#include "view_registry.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace aida::ui::workspace_layout {
enum class workspace_preset_t;
}

namespace aida::ui::application_views {

struct menu_entry_t {
    stable_view_id_t id;
    std::string label;
    view_category_t category = view_category_t::document;
    bool open = false;
    bool enabled = true;
    std::string disabled_reason;
};

void initialize();
view_registry_t& registry();
std::string ensure_window_name(const stable_view_id_t& id);
std::optional<stable_view_id_t> stable_subview_id(view_category_t category, int subview);
void begin_frame() noexcept;
bool synchronize_workspace_visibility(
    workspace_layout::workspace_preset_t preset) noexcept;
void reset_persisted_workspace_visibility(
    workspace_layout::workspace_preset_t preset, bool all_presets) noexcept;
void clone_persisted_workspace_visibility(std::string_view source_identity,
                                          std::string_view target_identity) noexcept;
void rename_persisted_workspace_visibility(std::string_view source_identity,
                                           std::string_view target_identity) noexcept;
void remove_persisted_workspace_visibility(std::string_view identity) noexcept;
std::string persistence_fingerprint() noexcept;
void migrate_persisted_window_settings() noexcept;
void dismiss_start_center_when_work_available() noexcept;
view_operation_result_t open_or_focus(const stable_view_id_t& id);
view_operation_result_t open_for_layout(const stable_view_id_t& id);
view_operation_result_t close(const stable_view_id_t& id);
view_operation_result_t close_instance(const view_instance_id_t& id);
view_operation_result_t close_other_instances(const view_instance_id_t& keep);
view_operation_result_t toggle_pin(const view_instance_id_t& id);
view_operation_result_t request_reset_state(const view_instance_id_t& id);
view_operation_result_t duplicate_instance(const view_instance_id_t& id);
view_operation_result_t reopen_last_closed();
view_operation_result_t open_default_missing();
bool is_open(const stable_view_id_t& id) noexcept;
bool is_pinned(const view_instance_id_t& id) noexcept;
bool can_duplicate(const view_instance_id_t& id) noexcept;
bool can_reset_state(const view_instance_id_t& id) noexcept;
bool can_reopen_last_closed() noexcept;
std::string focused_disassembly_presentation_key() noexcept;
void render_registry_owned_windows() noexcept;
void for_each_menu_entry(const std::function<void(const menu_entry_t&)>& visitor);
const char* category_label(view_category_t category) noexcept;

}
