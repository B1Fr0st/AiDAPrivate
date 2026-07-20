#pragma once

#include "components.hpp"
#include "imgui/imgui.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <unordered_set>
#include <vector>

namespace aida::ui::design {

enum class density_t : std::uint8_t {
    compact = 0,
    comfortable = 1
};

enum class semantic_t : std::uint8_t {
    neutral,
    brand,
    success,
    warning,
    error,
    info,
    live,
    stale,
    breakpoint,
    changed,
    disabled
};

enum class text_role_t : std::uint8_t {
    title,
    body,
    secondary,
    code,
    caption
};

enum class view_state_t : std::uint8_t {
    empty,
    loading,
    error,
    disconnected,
    tiny
};

enum class view_preference_kind_t : std::uint8_t {
    table,
    filter
};

enum class field_commit_t : std::uint8_t {
    unchanged,
    staged,
    pending,
    committed,
    conflict,
    readback_error
};

enum class view_size_class_t : std::uint8_t {
    narrow_utility,
    navigator,
    inspector,
    bottom_panel,
    document,
    graph,
    debugger_cpu,
    request_editor,
    structure_editor
};

struct preferences_t {
    density_t density = density_t::compact;
    bool reduced_motion = false;
};

struct scaled_metrics_t {
    float scale = 1.f;
    float spacing_xs = 4.f;
    float spacing_sm = 8.f;
    float spacing_md = 12.f;
    float spacing_lg = 16.f;
    float control_height = 28.f;
    float toolbar_height = 36.f;
    float row_height = 24.f;
    float table_row_height = 24.f;
    float panel_padding = 8.f;
    float property_label_width = 132.f;
    float focus_ring = 2.f;
    float dialog_footer_height = 52.f;
};

struct action_t {
    const char* id = nullptr;
    const char* label = nullptr;
    const char* compact_label = nullptr;
    const char* tooltip = nullptr;
    const char* shortcut = nullptr;
    const char* consequence = nullptr;
    components::button_kind_t kind = components::button_kind_t::secondary;
    bool enabled = true;
    bool primary = false;
    bool visible = true;
};

struct action_result_t {
    const char* id = nullptr;
    bool invoked = false;
};

struct header_t {
    const char* stable_id = nullptr;
    const char* title = nullptr;
    const char* breadcrumb = nullptr;
    const char* status_label = nullptr;
    const char* shortcut = nullptr;
    semantic_t status = semantic_t::neutral;
    const action_t* actions = nullptr;
    std::size_t action_count = 0;
    bool document_header = false;
};

struct search_state_t {
    char* query = nullptr;
    std::size_t query_capacity = 0;
    std::uint64_t match_count = 0;
    std::uint64_t active_match = 0;
    const char* syntax_error = nullptr;
    bool case_sensitive = false;
    bool whole_word = false;
    bool regex = false;
    bool supports_case = true;
    bool supports_whole_word = true;
    bool supports_regex = false;
    bool running = false;
    bool cancellable = false;
    bool request_focus = false;
};

struct search_result_t {
    bool query_changed = false;
    bool options_changed = false;
    bool previous_requested = false;
    bool next_requested = false;
    bool cancel_requested = false;
    bool cleared = false;
};

struct filter_chip_t {
    const char* id = nullptr;
    const char* label = nullptr;
    const char* value = nullptr;
    semantic_t semantic = semantic_t::brand;
    bool removable = true;
};

struct filter_result_t {
    const char* removed_id = nullptr;
    bool reset_all = false;
};

class selection_model_t {
public:
    void clear();
    bool contains(std::uint64_t stable_id) const;
    std::size_t size() const;
    std::uint64_t focused() const;
    void select(std::uint64_t stable_id, std::size_t row_index, bool additive, bool range,
        const std::function<std::uint64_t(std::size_t)>& id_at, std::size_t row_count);
    bool handle_keyboard(std::size_t row_count,
        const std::function<std::uint64_t(std::size_t)>& id_at, bool page_navigation = true);

private:
    std::unordered_set<std::uint64_t> selected_;
    std::size_t anchor_index_ = static_cast<std::size_t>(-1);
    std::size_t focused_index_ = static_cast<std::size_t>(-1);
    std::uint64_t focused_id_ = 0;
};

struct state_presentation_t {
    const char* stable_id = nullptr;
    view_state_t state = view_state_t::empty;
    const char* title = nullptr;
    const char* message = nullptr;
    const char* target = nullptr;
    const char* stage = nullptr;
    const char* diagnostic_id = nullptr;
    const char* stale_notice = nullptr;
    const char* hint = nullptr;
    float progress = -1.f;
    double elapsed_seconds = 0.0;
    bool preserves_stale_data = false;
    const action_t* actions = nullptr;
    std::size_t action_count = 0;
};

struct validation_error_t {
    std::string field_id;
    std::string message;
};

class form_state_t {
public:
    void clear();
    void reject(std::string field_id, std::string message);
    bool valid() const;
    const char* error_for(const char* field_id) const;
    const std::vector<validation_error_t>& errors() const;
    void request_first_invalid_focus();
    bool consume_focus_request(const char* field_id);

private:
    std::vector<validation_error_t> errors_;
    std::string focus_field_;
};

struct confirmation_t {
    const char* verb = nullptr;
    const char* target = nullptr;
    const char* scope = nullptr;
    const char* effect = nullptr;
    const char* reversibility = nullptr;
    const char* prerequisite = nullptr;
    const char* confirm_label = nullptr;
    bool destructive = false;
    bool confirm_enabled = true;
};

struct dialog_result_t {
    bool confirmed = false;
    bool cancelled = false;
};

struct inspector_control_result_t {
    bool follow_changed = false;
    bool pin_changed = false;
};

struct notification_t {
    const char* stable_id = nullptr;
    const char* owner = nullptr;
    const char* target = nullptr;
    const char* summary = nullptr;
    const char* details = nullptr;
    const char* action_label = nullptr;
    semantic_t semantic = semantic_t::info;
    bool attention_required = false;
    std::function<void()> action;
};

void set_preferences(preferences_t preferences);
preferences_t preferences();
bool reduced_motion();
scaled_metrics_t metrics();
float text_scale(text_role_t role);
void text(text_role_t role, const char* value);
ImU32 semantic_color(semantic_t semantic);
ImU32 semantic_soft_color(semantic_t semantic);
const char* semantic_label(semantic_t semantic);
components::status_kind_t component_status(semantic_t semantic);
void apply_style_preferences();
void tooltip_for_last_item(const char* description, const char* shortcut = nullptr,
    const char* consequence = nullptr);
void draw_focus_ring_for_last_item();
action_result_t render_toolbar(const char* stable_id, const action_t* actions,
    std::size_t action_count, float available_width = 0.f);
action_result_t render_view_header(const header_t& header);
search_result_t render_search(const char* stable_id, search_state_t& state, float width = 0.f);
filter_result_t render_filter_chips(const char* stable_id, const filter_chip_t* filters,
    std::size_t filter_count, bool allow_reset = true);
bool begin_expert_table(const char* stable_id, int columns, ImGuiTableFlags flags = 0,
    ImVec2 size = ImVec2(0.f, 0.f));
void end_expert_table();
bool tree_node(const char* stable_id, const char* label, bool selected = false,
    ImGuiTreeNodeFlags flags = 0);
void tree_pop();
action_result_t render_state(const state_presentation_t& state, ImVec2 size = ImVec2(0.f, 0.f));
bool begin_property_grid(const char* stable_id, float label_width = 0.f);
void property_value(const char* stable_id, const char* label, const char* value,
    semantic_t semantic = semantic_t::neutral, const char* provenance = nullptr);
inspector_control_result_t inspector_controls(const char* stable_id, bool& follow_selection,
    bool& pinned, const char* source = nullptr, const char* revision = nullptr);
void field_commit_badge(field_commit_t state);
void end_property_grid();
void inline_validation(const char* field_id, const form_state_t& form);
void form_summary(const char* stable_id, const form_state_t& form);
bool form_input_text(const char* field_id, const char* label, char* buffer,
    std::size_t buffer_size, form_state_t& form, const char* hint = nullptr);
bool form_input_int(const char* field_id, const char* label, int& value,
    form_state_t& form, int step = 1);
bool begin_dialog(const char* popup_id, const char* title, ImVec2 desired_size,
    ImVec2 minimum_size = ImVec2(360.f, 220.f));
bool begin_dialog_exact(const char* popup_label, ImVec2 desired_size,
    ImVec2 minimum_size = ImVec2(360.f, 220.f), bool* open = nullptr,
    ImGuiWindowFlags flags = ImGuiWindowFlags_None);
void open_dialog(const char* popup_id, const char* title);
float dialog_footer_reserve_height(const char* confirm_label,
    const char* cancel_label = "Cancel");
bool begin_dialog_body(const char* stable_id, float footer_reserve_height);
void end_dialog_body();
dialog_result_t dialog_footer(const char* stable_id, const char* confirm_label,
    bool confirm_enabled, bool destructive, const char* cancel_label = "Cancel",
    bool cancel_enabled = true, bool confirm_on_enter = true);
void render_confirmation_content(const confirmation_t& confirmation);
dialog_result_t confirmation_dialog(const char* stable_id, const confirmation_t& confirmation);
bool tiny_view_required(ImVec2 available, ImVec2 logical_minimum);
ImVec2 minimum_logical_size(view_size_class_t size_class);
bool read_view_preference(view_preference_kind_t kind, const char* stable_view_id,
    std::string& payload);
bool write_view_preference(view_preference_kind_t kind, const char* stable_view_id,
    const std::string& payload);
bool erase_view_preference(view_preference_kind_t kind, const char* stable_view_id);
bool publish_notification(notification_t notification);
bool selection_activate_requested();
bool selection_context_requested();

template <typename RowRenderer>
void render_clipped_rows(std::size_t row_count, float row_height, RowRenderer&& renderer) {
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>((std::min)(row_count,
        static_cast<std::size_t>((std::numeric_limits<int>::max)()))), row_height);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
            renderer(static_cast<std::size_t>(row));
    }
}

}
