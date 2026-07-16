#pragma once

#include "view_registry.hpp"

#include <functional>
#include <string>

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
void begin_frame() noexcept;
view_operation_result_t open_or_focus(const stable_view_id_t& id);
view_operation_result_t close(const stable_view_id_t& id);
view_operation_result_t reopen_last_closed();
view_operation_result_t open_default_missing();
bool is_open(const stable_view_id_t& id) noexcept;
bool can_reopen_last_closed() noexcept;
void synchronize_legacy_state();
void render_registry_owned_windows() noexcept;
void for_each_menu_entry(const std::function<void(const menu_entry_t&)>& visitor);
const char* category_label(view_category_t category) noexcept;

}
