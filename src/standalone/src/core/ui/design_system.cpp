#include "design_system.hpp"

#include "metrics.hpp"
#include "fonts.hpp"
#include "task_center.hpp"
#include "theme.hpp"
#include "toast_notification.hpp"
#include "../settings/standalone_settings.hpp"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <atomic>
#include <cfloat>
#include <cstdio>
#include <utility>

#include <nlohmann/json.hpp>

namespace aida::ui::design {

namespace {

std::atomic<int> g_density{static_cast<int>(density_t::compact)};
std::atomic<bool> g_reduced_motion{false};

const char* safe(const char* value) {
    return value ? value : "";
}

float action_width(const action_t& action, bool compact) {
    const char* label = compact && action.compact_label && *action.compact_label
        ? action.compact_label : safe(action.label);
    return ImGui::CalcTextSize(label, nullptr, true).x + metrics().spacing_lg * 2.f;
}

bool action_button(const char* toolbar_id, const action_t& action, bool compact, float width) {
    const char* label = compact && action.compact_label && *action.compact_label
        ? action.compact_label : safe(action.label);
    ImGui::PushID(safe(action.id));
    const bool clicked = components::button(label, action.kind, components::size_t_::sm,
        ImVec2(width, metrics().control_height), !action.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::string toolbar_semantic_id = aida::preview::semantics::stable_id(
        "aida.toolbar", safe(toolbar_id));
    aida::preview::semantics::register_last_item(
        aida::preview::semantics::stable_id(toolbar_semantic_id, safe(action.id)),
        "toolbar-action");
#endif
    tooltip_for_last_item(action.tooltip, action.shortcut, action.consequence);
    draw_focus_ring_for_last_item();
    ImGui::PopID();
    return clicked;
}

const char* state_label(view_state_t state) {
    switch (state) {
    case view_state_t::empty: return "Empty";
    case view_state_t::loading: return "Loading";
    case view_state_t::error: return "Error";
    case view_state_t::disconnected: return "Disconnected";
    case view_state_t::tiny: return "View too small";
    }
    return "State";
}

semantic_t state_semantic(view_state_t state) {
    switch (state) {
    case view_state_t::loading: return semantic_t::info;
    case view_state_t::error: return semantic_t::error;
    case view_state_t::disconnected: return semantic_t::stale;
    case view_state_t::tiny: return semantic_t::warning;
    case view_state_t::empty: return semantic_t::neutral;
    }
    return semantic_t::neutral;
}

std::string& preference_blob(view_preference_kind_t kind) {
    return kind == view_preference_kind_t::table
        ? g_sa_settings.ui_table_preferences_json
        : g_sa_settings.ui_filter_preferences_json;
}

nlohmann::json parse_preferences(const std::string& blob) {
    if (blob.empty() || blob.size() > 1024u * 1024u)
        return nlohmann::json{{"version", 1}, {"views", nlohmann::json::object()}};
    nlohmann::json parsed = nlohmann::json::parse(blob, nullptr, false);
    if (!parsed.is_object() || parsed.value("version", 0) != 1 ||
        !parsed.contains("views") || !parsed["views"].is_object())
        return nlohmann::json{{"version", 1}, {"views", nlohmann::json::object()}};
    return parsed;
}

}

void set_preferences(preferences_t value) {
    const int density = value.density == density_t::comfortable
        ? static_cast<int>(density_t::comfortable) : static_cast<int>(density_t::compact);
    g_density.store(density, std::memory_order_release);
    g_reduced_motion.store(value.reduced_motion, std::memory_order_release);
    aida::ui::set_design_preferences(value.density == density_t::comfortable, value.reduced_motion);
    apply_style_preferences();
}

preferences_t preferences() {
    preferences_t value;
    value.density = g_density.load(std::memory_order_acquire) == static_cast<int>(density_t::comfortable)
        ? density_t::comfortable : density_t::compact;
    value.reduced_motion = g_reduced_motion.load(std::memory_order_acquire);
    return value;
}

bool reduced_motion() {
    return g_reduced_motion.load(std::memory_order_acquire);
}

scaled_metrics_t metrics() {
    scaled_metrics_t value;
    value.scale = aida::ui::dpi_scale();
    const bool comfortable = preferences().density == density_t::comfortable;
    const float density = comfortable ? 1.15f : 1.f;
    const auto scaled = [&](float logical) { return aida::ui::scale_px(logical * density, value.scale); };
    value.spacing_xs = scaled(4.f);
    value.spacing_sm = scaled(8.f);
    value.spacing_md = scaled(12.f);
    value.spacing_lg = scaled(16.f);
    value.control_height = scaled(comfortable ? 32.f : 28.f);
    value.toolbar_height = scaled(comfortable ? 42.f : 36.f);
    value.row_height = scaled(comfortable ? 30.f : 24.f);
    value.table_row_height = value.row_height;
    value.panel_padding = scaled(comfortable ? 12.f : 8.f);
    value.property_label_width = scaled(comfortable ? 148.f : 132.f);
    value.focus_ring = (std::max)(1.f, scaled(2.f));
    value.dialog_footer_height = scaled(comfortable ? 60.f : 52.f);
    return value;
}

float text_scale(text_role_t role) {
    switch (role) {
    case text_role_t::title: return 1.18f;
    case text_role_t::body: return 1.f;
    case text_role_t::secondary: return 0.94f;
    case text_role_t::code: return 1.f;
    case text_role_t::caption: return 0.86f;
    }
    return 1.f;
}

void text(text_role_t role, const char* value) {
    ImFont* font = nullptr;
    ImU32 color = aida::ui::resolved().text_primary;
    switch (role) {
    case text_role_t::title: font = aida::ui::fonts::h2(); break;
    case text_role_t::body: font = aida::ui::fonts::body(); break;
    case text_role_t::secondary:
        font = aida::ui::fonts::body();
        color = aida::ui::resolved().text_secondary;
        break;
    case text_role_t::code: font = aida::ui::fonts::code(); break;
    case text_role_t::caption:
        font = aida::ui::fonts::caption();
        color = aida::ui::resolved().text_secondary;
        break;
    }
    if (font) ImGui::PushFont(font);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(color), "%s", safe(value));
    if (font) ImGui::PopFont();
}

ImU32 semantic_color(semantic_t semantic) {
    const auto& theme = aida::ui::resolved();
    switch (semantic) {
    case semantic_t::brand: return theme.accent_u32;
    case semantic_t::success: return theme.success;
    case semantic_t::warning: return theme.warning;
    case semantic_t::error: return theme.error;
    case semantic_t::info: return theme.info;
    case semantic_t::live: return theme.live;
    case semantic_t::stale: return theme.stale;
    case semantic_t::breakpoint: return theme.breakpoint;
    case semantic_t::changed: return theme.changed;
    case semantic_t::disabled: return theme.disabled;
    case semantic_t::neutral: return theme.text_secondary;
    }
    return theme.text_secondary;
}

ImU32 semantic_soft_color(semantic_t semantic) {
    const auto& theme = aida::ui::resolved();
    switch (semantic) {
    case semantic_t::success:
    case semantic_t::live: return theme.success_soft;
    case semantic_t::warning:
    case semantic_t::stale: return theme.warning_soft;
    case semantic_t::error:
    case semantic_t::breakpoint: return theme.error_soft;
    case semantic_t::info:
    case semantic_t::changed: return theme.info_soft;
    case semantic_t::brand: return aida::ui::with_alpha(theme.accent_u32, 0.18f);
    case semantic_t::disabled: return aida::ui::with_alpha(theme.text_dim, 0.10f);
    case semantic_t::neutral: return aida::ui::with_alpha(theme.text_secondary, 0.10f);
    }
    return aida::ui::with_alpha(theme.text_secondary, 0.10f);
}

const char* semantic_label(semantic_t semantic) {
    switch (semantic) {
    case semantic_t::neutral: return "Neutral";
    case semantic_t::brand: return "Selected";
    case semantic_t::success: return "Success";
    case semantic_t::warning: return "Warning";
    case semantic_t::error: return "Error";
    case semantic_t::info: return "Information";
    case semantic_t::live: return "Live";
    case semantic_t::stale: return "Stale";
    case semantic_t::breakpoint: return "Breakpoint";
    case semantic_t::changed: return "Changed";
    case semantic_t::disabled: return "Disabled";
    }
    return "Status";
}

components::status_kind_t component_status(semantic_t semantic) {
    switch (semantic) {
    case semantic_t::success:
    case semantic_t::live: return components::status_kind_t::success;
    case semantic_t::warning:
    case semantic_t::stale: return components::status_kind_t::warning;
    case semantic_t::error:
    case semantic_t::breakpoint: return components::status_kind_t::error;
    case semantic_t::info:
    case semantic_t::changed: return components::status_kind_t::info;
    case semantic_t::brand: return components::status_kind_t::accent;
    case semantic_t::disabled:
    case semantic_t::neutral: return components::status_kind_t::neutral;
    }
    return components::status_kind_t::neutral;
}

void apply_style_preferences() {
    if (!ImGui::GetCurrentContext()) return;
    const auto m = metrics();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ItemSpacing = ImVec2(m.spacing_sm, m.spacing_sm);
    style.ItemInnerSpacing = ImVec2(m.spacing_sm, m.spacing_xs);
    style.CellPadding = ImVec2(m.spacing_sm, (m.table_row_height - ImGui::GetFontSize()) * 0.5f);
    style.FramePadding = ImVec2(m.spacing_sm, (m.control_height - ImGui::GetFontSize()) * 0.5f);
}

void tooltip_for_last_item(const char* description, const char* shortcut, const char* consequence) {
    if ((!description || !*description) && (!shortcut || !*shortcut) && (!consequence || !*consequence)) return;
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal |
        ImGuiHoveredFlags_NoSharedDelay | ImGuiHoveredFlags_AllowWhenDisabled)) return;
    ImGui::BeginTooltip();
    if (description && *description) ImGui::TextUnformatted(description);
    if (shortcut && *shortcut) {
        ImGui::Separator();
        ImGui::TextDisabled("Shortcut");
        ImGui::SameLine();
        components::kbd_chip(shortcut);
    }
    if (consequence && *consequence) {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 30.f);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(semantic_color(semantic_t::warning)), "%s", consequence);
        ImGui::PopTextWrapPos();
    }
    ImGui::EndTooltip();
}

void draw_focus_ring_for_last_item() {
    if (!ImGui::IsItemFocused()) return;
    const auto m = metrics();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 pad(m.focus_ring, m.focus_ring);
    const ImVec2 minimum = ImGui::GetItemRectMin();
    const ImVec2 maximum = ImGui::GetItemRectMax();
    draw->AddRect(ImVec2(minimum.x - pad.x, minimum.y - pad.y),
        ImVec2(maximum.x + pad.x, maximum.y + pad.y),
        aida::ui::resolved().border_focus, aida::ui::scale_px(4.f, m.scale), 0, m.focus_ring);
}

action_result_t render_toolbar(const char* stable_id, const action_t* actions,
    std::size_t action_count, float available_width) {
    action_result_t result;
    if (!actions || action_count == 0) return result;
    const auto m = metrics();
    ImGui::PushID(safe(stable_id));
    const float width = (std::max)(1.f,
        available_width > 0.f ? available_width : ImGui::GetContentRegionAvail().x);
    const float overflow_width = ImGui::CalcTextSize("More").x + m.spacing_lg * 2.f;
    float required = 0.f;
    std::size_t visible_count = 0;
    for (std::size_t i = 0; i < action_count; ++i) {
        if (!actions[i].visible) continue;
        required += action_width(actions[i], false) + (visible_count ? m.spacing_xs : 0.f);
        ++visible_count;
    }
    bool compact = required > width;
    if (compact) {
        required = 0.f;
        visible_count = 0;
        for (std::size_t i = 0; i < action_count; ++i) {
            if (!actions[i].visible) continue;
            required += action_width(actions[i], true) + (visible_count ? m.spacing_xs : 0.f);
            ++visible_count;
        }
    }
    const bool popup_only = required > width && width < overflow_width + m.control_height;
    float used = 0.f;
    bool has_overflow = false;
    for (std::size_t i = 0; i < action_count; ++i) {
        const auto& action = actions[i];
        if (!action.visible) continue;
        const float button_width = action_width(action, compact);
        const float reserve = i + 1 < action_count ? overflow_width + m.spacing_xs : 0.f;
        if (popup_only || used + button_width + reserve > width) {
            has_overflow = true;
            continue;
        }
        if (used > 0.f) ImGui::SameLine(0.f, m.spacing_xs);
        if (action_button(stable_id, action, compact, button_width)) {
            result.id = action.id;
            result.invoked = true;
        }
        used += button_width + (used > 0.f ? m.spacing_xs : 0.f);
    }
    if (has_overflow) {
        if (used > 0.f) ImGui::SameLine(0.f, m.spacing_xs);
        const bool open_overflow = components::button("More", components::button_kind_t::ghost,
            components::size_t_::sm,
            ImVec2((std::min)(overflow_width, width), m.control_height));
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        const std::string toolbar_semantic_id = aida::preview::semantics::stable_id(
            "aida.toolbar", safe(stable_id));
        aida::preview::semantics::register_last_item(
            aida::preview::semantics::stable_id(toolbar_semantic_id, "more"),
            "toolbar-overflow-action");
#endif
        if (open_overflow)
            ImGui::OpenPopup("##overflow");
        tooltip_for_last_item("Show actions that do not fit in this view", nullptr, nullptr);
        draw_focus_ring_for_last_item();
        if (ImGui::BeginPopup("##overflow")) {
            float replay_used = 0.f;
            for (std::size_t index = 0; index < action_count; ++index) {
                const auto& action = actions[index];
                if (!action.visible) continue;
                const float button_width = action_width(action, compact);
                const float reserve = index + 1 < action_count ? overflow_width + m.spacing_xs : 0.f;
                const bool overflowed = popup_only || replay_used + button_width + reserve > width;
                if (!overflowed) {
                    replay_used += button_width + (replay_used > 0.f ? m.spacing_xs : 0.f);
                    continue;
                }
                const char* label = safe(action.label);
                if (!action.enabled) ImGui::BeginDisabled();
                const bool invoked = ImGui::MenuItem(label, action.shortcut);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                const std::string toolbar_semantic_id = aida::preview::semantics::stable_id(
                    "aida.toolbar", safe(stable_id));
                aida::preview::semantics::register_last_item(
                    aida::preview::semantics::stable_id(toolbar_semantic_id, safe(action.id)),
                    "toolbar-overflow-action");
#endif
                if (invoked) {
                    result.id = action.id;
                    result.invoked = true;
                }
                if (!action.enabled) ImGui::EndDisabled();
                tooltip_for_last_item(action.tooltip, action.shortcut, action.consequence);
            }
            ImGui::EndPopup();
        }
    }
    ImGui::PopID();
    return result;
}

action_result_t render_view_header(const header_t& header) {
    action_result_t result;
    if (header.document_header) return result;
    const auto m = metrics();
    const auto& theme = aida::ui::resolved();
    const float height = header.breadcrumb && *header.breadcrumb
        ? aida::ui::scale_px(56.f, m.scale) : aida::ui::scale_px(42.f, m.scale);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = (std::max)(1.f, ImGui::GetContentRegionAvail().x);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height), theme.bg_elevated,
        aida::ui::scale_px(6.f, m.scale));
    draw->AddRect(origin, ImVec2(origin.x + width, origin.y + height), theme.border_subtle,
        aida::ui::scale_px(6.f, m.scale));
    draw->AddRectFilled(origin, ImVec2(origin.x + aida::ui::scale_px(3.f, m.scale), origin.y + height),
        semantic_color(header.status), aida::ui::scale_px(2.f, m.scale));
    ImGui::SetCursorScreenPos(ImVec2(origin.x + m.spacing_lg, origin.y + m.spacing_sm));
    ImGui::TextUnformatted(safe(header.title));
    if (header.shortcut && *header.shortcut) {
        ImGui::SameLine(0.f, m.spacing_sm);
        components::kbd_chip(header.shortcut);
    }
    if (header.breadcrumb && *header.breadcrumb) {
        ImGui::SetCursorScreenPos(ImVec2(origin.x + m.spacing_lg,
            origin.y + m.spacing_sm + ImGui::GetFontSize() + m.spacing_xs));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_secondary), "%s", header.breadcrumb);
    }
    float status_width = 0.f;
    if (header.status_label && *header.status_label)
        status_width = ImGui::CalcTextSize(header.status_label).x + m.spacing_lg * 2.f;
    const float action_width_available = (std::max)(m.control_height,
        width * (width < aida::ui::scale_px(620.f, m.scale) ? 0.42f : 0.56f) - status_width);
    ImGui::SetCursorScreenPos(ImVec2(origin.x + width - action_width_available - status_width - m.spacing_sm,
        origin.y + (height - m.control_height) * 0.5f));
    result = render_toolbar(header.stable_id && *header.stable_id ? header.stable_id : "header-actions",
        header.actions, header.action_count, action_width_available);
    if (status_width > 0.f) {
        ImGui::SameLine(0.f, m.spacing_sm);
        components::status_badge(header.status_label, component_status(header.status));
        tooltip_for_last_item(semantic_label(header.status), nullptr, nullptr);
    }
    ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + height + m.spacing_sm));
    ImGui::Dummy(ImVec2(0.f, 0.f));
    return result;
}

search_result_t render_search(const char* stable_id, search_state_t& state, float width) {
    search_result_t result;
    if (!state.query || state.query_capacity == 0) return result;
    const auto m = metrics();
    ImGui::PushID(safe(stable_id));
    const bool local_find = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::GetIO().KeyCtrl && !ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F);
    if (state.request_focus || local_find) {
        ImGui::SetKeyboardFocusHere();
        state.request_focus = false;
    }
    const float total_width = width > 0.f ? width : ImGui::GetContentRegionAvail().x;
    const float controls_width = aida::ui::scale_px(178.f, m.scale);
    const bool compact = total_width < controls_width + aida::ui::scale_px(160.f, m.scale);
    const float field_width = compact ? (std::max)(aida::ui::scale_px(72.f, m.scale), total_width) :
        (std::max)(aida::ui::scale_px(120.f, m.scale), total_width - controls_width);
    bool query_focused = false;
    result.query_changed = components::search_field("query", state.query, state.query_capacity,
        "Filter this view", field_width, &result.cleared, &query_focused);
    if (query_focused && ImGui::IsKeyPressed(ImGuiKey_Enter)) {
        if (ImGui::GetIO().KeyShift) result.previous_requested = state.match_count != 0;
        else result.next_requested = state.match_count != 0;
    }
    if (query_focused && state.running && state.cancellable && ImGui::IsKeyPressed(ImGuiKey_Escape))
        result.cancel_requested = true;
    draw_focus_ring_for_last_item();
    if (compact) ImGui::Dummy(ImVec2(0.f, m.spacing_xs));
    else ImGui::SameLine(0.f, m.spacing_xs);
    if (components::icon_button("previous", "<", m.control_height,
        components::button_kind_t::ghost, state.match_count == 0)) result.previous_requested = true;
    tooltip_for_last_item("Previous match", "Shift+Enter", nullptr);
    ImGui::SameLine(0.f, m.spacing_xs);
    if (components::icon_button("next", ">", m.control_height,
        components::button_kind_t::ghost, state.match_count == 0)) result.next_requested = true;
    tooltip_for_last_item("Next match", "Enter", nullptr);
    ImGui::SameLine(0.f, m.spacing_xs);
    char count[64]{};
    if (state.running) std::snprintf(count, sizeof(count), "Searching");
    else if (state.match_count == 0) std::snprintf(count, sizeof(count), "No matches");
    else std::snprintf(count, sizeof(count), "%llu / %llu",
        static_cast<unsigned long long>((std::min)(state.active_match + 1, state.match_count)),
        static_cast<unsigned long long>(state.match_count));
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::resolved().text_secondary), "%s", count);
    ImGui::SameLine(0.f, m.spacing_xs);
    if (components::icon_button("options", "...", m.control_height,
        components::button_kind_t::ghost)) ImGui::OpenPopup("##options");
    tooltip_for_last_item("Search options", nullptr, nullptr);
    if (ImGui::BeginPopup("##options")) {
        if (state.supports_case) result.options_changed |= ImGui::Checkbox("Match case", &state.case_sensitive);
        if (state.supports_whole_word) result.options_changed |= ImGui::Checkbox("Whole word", &state.whole_word);
        if (state.supports_regex) result.options_changed |= ImGui::Checkbox("Regular expression", &state.regex);
        ImGui::EndPopup();
    }
    if (state.running && state.cancellable) {
        ImGui::SameLine(0.f, m.spacing_xs);
        if (components::button("Cancel", components::button_kind_t::destructive, components::size_t_::sm,
            ImVec2(0.f, m.control_height))) result.cancel_requested = true;
        tooltip_for_last_item("Cancel this search without discarding its last immutable results", "Esc", nullptr);
    }
    if (state.syntax_error && *state.syntax_error)
        components::inline_notice("search_error", "Search expression is invalid", state.syntax_error,
            components::status_kind_t::error);
    ImGui::PopID();
    return result;
}

filter_result_t render_filter_chips(const char* stable_id, const filter_chip_t* filters,
    std::size_t filter_count, bool allow_reset) {
    filter_result_t result;
    if (!filters || filter_count == 0) return result;
    const auto m = metrics();
    ImGui::PushID(safe(stable_id));
    for (std::size_t i = 0; i < filter_count; ++i) {
        if (i) ImGui::SameLine(0.f, m.spacing_xs);
        const auto& filter = filters[i];
        ImGui::PushID(safe(filter.id));
        char label[256]{};
        if (filter.value && *filter.value)
            std::snprintf(label, sizeof(label), "%s: %s", safe(filter.label), filter.value);
        else
            std::snprintf(label, sizeof(label), "%s", safe(filter.label));
        bool removed = false;
        components::chip(label, semantic_color(filter.semantic), filter.removable, &removed);
        if (removed) result.removed_id = filter.id;
        ImGui::PopID();
    }
    if (allow_reset) {
        ImGui::SameLine(0.f, m.spacing_sm);
        result.reset_all = ImGui::SmallButton("Reset filters");
        tooltip_for_last_item("Remove every active filter in this view", nullptr, nullptr);
    }
    ImGui::PopID();
    return result;
}

void selection_model_t::clear() {
    selected_.clear();
    anchor_index_ = static_cast<std::size_t>(-1);
    focused_index_ = static_cast<std::size_t>(-1);
    focused_id_ = 0;
}

bool selection_model_t::contains(std::uint64_t stable_id) const { return selected_.count(stable_id) != 0; }
std::size_t selection_model_t::size() const { return selected_.size(); }
std::uint64_t selection_model_t::focused() const { return focused_id_; }

void selection_model_t::select(std::uint64_t stable_id, std::size_t row_index, bool additive, bool range,
    const std::function<std::uint64_t(std::size_t)>& id_at, std::size_t row_count) {
    if (row_index >= row_count || !stable_id) return;
    if (range && anchor_index_ != static_cast<std::size_t>(-1) && id_at) {
        if (!additive) selected_.clear();
        const std::size_t first = (std::min)(anchor_index_, row_index);
        const std::size_t last = (std::max)(anchor_index_, row_index);
        for (std::size_t i = first; i <= last && i < row_count; ++i) selected_.insert(id_at(i));
    } else if (additive) {
        if (selected_.count(stable_id)) selected_.erase(stable_id);
        else selected_.insert(stable_id);
        anchor_index_ = row_index;
    } else {
        selected_.clear();
        selected_.insert(stable_id);
        anchor_index_ = row_index;
    }
    focused_index_ = row_index;
    focused_id_ = stable_id;
}

bool selection_model_t::handle_keyboard(std::size_t row_count,
    const std::function<std::uint64_t(std::size_t)>& id_at, bool page_navigation) {
    if (row_count == 0 || !id_at ||
        !ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) return false;
    std::size_t next = focused_index_ == static_cast<std::size_t>(-1) ? 0 : focused_index_;
    bool moved = false;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && next + 1 < row_count) { ++next; moved = true; }
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && next > 0) { --next; moved = true; }
    if (ImGui::IsKeyPressed(ImGuiKey_Home)) { next = 0; moved = true; }
    if (ImGui::IsKeyPressed(ImGuiKey_End)) { next = row_count - 1; moved = true; }
    if (page_navigation && ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
        next = (std::min)(row_count - 1, next + 10); moved = true;
    }
    if (page_navigation && ImGui::IsKeyPressed(ImGuiKey_PageUp)) {
        next = next > 10 ? next - 10 : 0; moved = true;
    }
    if (!moved) return false;
    const ImGuiIO& io = ImGui::GetIO();
    select(id_at(next), next, io.KeyCtrl, io.KeyShift, id_at, row_count);
    return true;
}

bool begin_expert_table(const char* stable_id, int columns, ImGuiTableFlags flags, ImVec2 size) {
    const ImGuiTableFlags defaults = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding,
        ImVec2(metrics().spacing_sm, (metrics().table_row_height - ImGui::GetFontSize()) * 0.5f));
    const bool open = ImGui::BeginTable(safe(stable_id), columns, defaults | flags, size);
    if (!open) ImGui::PopStyleVar();
    return open;
}

void end_expert_table() {
    ImGui::EndTable();
    ImGui::PopStyleVar();
}

bool tree_node(const char* stable_id, const char* label, bool selected, ImGuiTreeNodeFlags flags) {
    ImGui::PushID(safe(stable_id));
    if (selected) flags |= ImGuiTreeNodeFlags_Selected;
    const bool open = ImGui::TreeNodeEx("##node", flags | ImGuiTreeNodeFlags_SpanAvailWidth, "%s", safe(label));
    draw_focus_ring_for_last_item();
    if (!open) ImGui::PopID();
    return open;
}

void tree_pop() {
    ImGui::TreePop();
    ImGui::PopID();
}

action_result_t render_state(const state_presentation_t& state, ImVec2 size) {
    action_result_t result;
    const auto m = metrics();
    const auto& theme = aida::ui::resolved();
    const float width = size.x > 0.f ? size.x : ImGui::GetContentRegionAvail().x;
    const float height = size.y > 0.f ? size.y : (std::max)(aida::ui::scale_px(170.f, m.scale), ImGui::GetContentRegionAvail().y);
    ImGui::PushID(safe(state.stable_id));
    ImGui::BeginChild("##state", ImVec2((std::max)(1.f, width), (std::max)(1.f, height)), true,
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysUseWindowPadding);
    const float content_width = (std::min)(ImGui::GetContentRegionAvail().x, aida::ui::scale_px(620.f, m.scale));
    const float left = ImGui::GetCursorPosX() + (ImGui::GetContentRegionAvail().x - content_width) * 0.5f;
    ImGui::SetCursorPosX(left);
    components::status_badge(state_label(state.state), component_status(state_semantic(state.state)));
    ImGui::Dummy(ImVec2(0.f, m.spacing_sm));
    ImGui::SetCursorPosX(left);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_primary), "%s", safe(state.title));
    if (state.message && *state.message) {
        ImGui::SetCursorPosX(left);
        ImGui::PushTextWrapPos(left + content_width);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_secondary), "%s", state.message);
        ImGui::PopTextWrapPos();
    }
    if (state.target && *state.target) {
        ImGui::SetCursorPosX(left);
        components::property_row("target", "Target", state.target);
    }
    if (state.stage && *state.stage) {
        ImGui::SetCursorPosX(left);
        components::property_row("stage", "Stage", state.stage, false, false, components::status_kind_t::info);
    }
    if (state.progress >= 0.f) {
        ImGui::SetCursorPosX(left);
        components::render_progress_bar(ImGui::GetCursorScreenPos(), content_width,
            aida::ui::scale_px(5.f, m.scale), (std::max)(0.f, (std::min)(1.f, state.progress)),
            false, !reduced_motion());
        ImGui::Dummy(ImVec2(content_width, aida::ui::scale_px(10.f, m.scale)));
    } else if (state.state == view_state_t::loading) {
        ImGui::SetCursorPosX(left);
        if (reduced_motion()) ImGui::TextUnformatted("Working...");
        else components::render_progress_bar(ImGui::GetCursorScreenPos(), content_width,
            aida::ui::scale_px(5.f, m.scale), 0.f, true);
        ImGui::Dummy(ImVec2(content_width, aida::ui::scale_px(10.f, m.scale)));
    }
    if (state.elapsed_seconds > 0.0) {
        ImGui::SetCursorPosX(left);
        ImGui::TextDisabled("Elapsed %.1f s", state.elapsed_seconds);
    }
    if (state.diagnostic_id && *state.diagnostic_id) {
        ImGui::SetCursorPosX(left);
        components::property_row("diagnostic", "Diagnostic", state.diagnostic_id);
        tooltip_for_last_item("Stable diagnostic identifier", nullptr, nullptr);
        ImGui::SameLine(0.f, m.spacing_sm);
        if (ImGui::SmallButton("Copy diagnostic"))
            ImGui::SetClipboardText(state.diagnostic_id);
        tooltip_for_last_item("Copy the stable diagnostic identifier", "Ctrl+C", nullptr);
    }
    if (state.preserves_stale_data && state.stale_notice && *state.stale_notice) {
        ImGui::SetCursorPosX(left);
        components::inline_notice("stale", "Showing stale read-only data", state.stale_notice,
            components::status_kind_t::warning);
    }
    if (state.hint && *state.hint) {
        ImGui::SetCursorPosX(left);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme.text_secondary), "Tip: %s", state.hint);
    }
    if (state.actions && state.action_count) {
        ImGui::Dummy(ImVec2(0.f, m.spacing_md));
        ImGui::SetCursorPosX(left);
        result = render_toolbar(state.stable_id && *state.stable_id ? state.stable_id : "state-actions",
            state.actions, state.action_count, content_width);
    }
    ImGui::EndChild();
    ImGui::PopID();
    return result;
}

bool begin_property_grid(const char* stable_id, float label_width) {
    const float width = label_width > 0.f ? label_width : metrics().property_label_width;
    if (!ImGui::BeginTable(safe(stable_id), 2,
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg)) return false;
    ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, width);
    ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
    return true;
}

void property_value(const char* stable_id, const char* label, const char* value,
    semantic_t semantic, const char* provenance) {
    ImGui::PushID(safe(stable_id));
    ImGui::TableNextRow(0, metrics().row_height);
    ImGui::TableSetColumnIndex(0);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(aida::ui::resolved().text_secondary), "%s", safe(label));
    ImGui::TableSetColumnIndex(1);
    ImGui::Selectable(safe(value), false, ImGuiSelectableFlags_AllowDoubleClick);
    if (ImGui::IsItemFocused() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C))
        ImGui::SetClipboardText(safe(value));
    if (ImGui::BeginPopupContextItem("##value_context")) {
        if (ImGui::MenuItem("Copy Value", "Ctrl+C")) ImGui::SetClipboardText(safe(value));
        ImGui::EndPopup();
    }
    if (semantic != semantic_t::neutral) {
        ImGui::SameLine(0.f, metrics().spacing_sm);
        components::status_badge(semantic_label(semantic), component_status(semantic));
    }
    tooltip_for_last_item(provenance, nullptr, nullptr);
    ImGui::PopID();
}

void end_property_grid() { ImGui::EndTable(); }

inspector_control_result_t inspector_controls(const char* stable_id, bool& follow_selection,
    bool& pinned, const char* source, const char* revision) {
    inspector_control_result_t result;
    ImGui::PushID(safe(stable_id));
    result.follow_changed = ImGui::Checkbox("Follow Selection", &follow_selection);
    tooltip_for_last_item("Update this inspector when the global selection changes", nullptr, nullptr);
    ImGui::SameLine(0.f, metrics().spacing_md);
    result.pin_changed = ImGui::Checkbox("Pin", &pinned);
    tooltip_for_last_item("Keep inspecting the current entity while global selection changes", nullptr, nullptr);
    if (pinned && follow_selection) {
        follow_selection = false;
        result.follow_changed = true;
    }
    if (source && *source) {
        ImGui::SameLine(0.f, metrics().spacing_lg);
        ImGui::TextDisabled("Source: %s", source);
    }
    if (revision && *revision) {
        ImGui::SameLine(0.f, metrics().spacing_sm);
        ImGui::TextDisabled("Revision: %s", revision);
    }
    ImGui::PopID();
    return result;
}

void field_commit_badge(field_commit_t state) {
    switch (state) {
    case field_commit_t::staged:
        components::status_badge("Staged", components::status_kind_t::warning);
        break;
    case field_commit_t::pending:
        components::status_badge("Applying", components::status_kind_t::info);
        break;
    case field_commit_t::committed:
        components::status_badge("Committed", components::status_kind_t::success);
        break;
    case field_commit_t::conflict:
        components::status_badge("Conflict", components::status_kind_t::error);
        break;
    case field_commit_t::readback_error:
        components::status_badge("Readback failed", components::status_kind_t::error);
        break;
    case field_commit_t::unchanged:
        components::status_badge("Unchanged", components::status_kind_t::neutral);
        break;
    }
}

void form_state_t::clear() { errors_.clear(); focus_field_.clear(); }

void form_state_t::reject(std::string field_id, std::string message) {
    if (field_id.empty() || message.empty()) return;
    const auto found = std::find_if(errors_.begin(), errors_.end(), [&](const auto& error) {
        return error.field_id == field_id;
    });
    if (found == errors_.end()) errors_.push_back({std::move(field_id), std::move(message)});
    else found->message = std::move(message);
}

bool form_state_t::valid() const { return errors_.empty(); }

const char* form_state_t::error_for(const char* field_id) const {
    if (!field_id) return nullptr;
    const auto found = std::find_if(errors_.begin(), errors_.end(), [&](const auto& error) {
        return error.field_id == field_id;
    });
    return found == errors_.end() ? nullptr : found->message.c_str();
}

const std::vector<validation_error_t>& form_state_t::errors() const { return errors_; }

void form_state_t::request_first_invalid_focus() {
    focus_field_ = errors_.empty() ? std::string() : errors_.front().field_id;
}

bool form_state_t::consume_focus_request(const char* field_id) {
    if (!field_id || focus_field_ != field_id) return false;
    focus_field_.clear();
    return true;
}

void inline_validation(const char* field_id, const form_state_t& form) {
    const char* error = form.error_for(field_id);
    if (!error) return;
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(semantic_color(semantic_t::error)), "Error: %s", error);
}

void form_summary(const char* stable_id, const form_state_t& form) {
    if (form.valid()) return;
    ImGui::PushID(safe(stable_id));
    std::string summary = std::to_string(form.errors().size());
    summary += form.errors().size() == 1 ? " field needs attention" : " fields need attention";
    components::inline_notice("summary", "Cannot apply these changes", summary.c_str(),
        components::status_kind_t::error);
    ImGui::PopID();
}

bool form_input_text(const char* field_id, const char* label, char* buffer,
    std::size_t buffer_size, form_state_t& form, const char* hint) {
    if (!buffer || buffer_size == 0) return false;
    ImGui::PushID(safe(field_id));
    text(text_role_t::secondary, label);
    if (form.consume_focus_request(field_id)) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool changed = hint && *hint
        ? ImGui::InputTextWithHint("##value", hint, buffer, buffer_size)
        : ImGui::InputText("##value", buffer, buffer_size);
    draw_focus_ring_for_last_item();
    inline_validation(field_id, form);
    ImGui::PopID();
    return changed;
}

bool form_input_int(const char* field_id, const char* label, int& value,
    form_state_t& form, int step) {
    ImGui::PushID(safe(field_id));
    text(text_role_t::secondary, label);
    if (form.consume_focus_request(field_id)) ImGui::SetKeyboardFocusHere();
    ImGui::SetNextItemWidth(-FLT_MIN);
    const bool changed = ImGui::InputInt("##value", &value, step, step * 10);
    draw_focus_ring_for_last_item();
    inline_validation(field_id, form);
    ImGui::PopID();
    return changed;
}

bool begin_dialog(const char* popup_id, const char* title, ImVec2 desired_size, ImVec2 minimum_size) {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImVec2 work = viewport ? viewport->WorkSize : ImGui::GetIO().DisplaySize;
    const ImVec2 position = viewport ? viewport->GetWorkCenter() : ImVec2(work.x * 0.5f, work.y * 0.5f);
    const float scale = metrics().scale;
    const float margin = aida::ui::scale_px(32.f, scale);
    const ImVec2 available((std::max)(1.f, work.x - margin * 2.f),
        (std::max)(1.f, work.y - margin * 2.f));
    const ImVec2 scaled_minimum(
        aida::ui::scale_px(minimum_size.x, scale),
        aida::ui::scale_px(minimum_size.y, scale));
    const ImVec2 effective_minimum((std::min)(scaled_minimum.x, available.x),
        (std::min)(scaled_minimum.y, available.y));
    const ImVec2 scaled_desired(
        aida::ui::scale_px(desired_size.x, scale),
        aida::ui::scale_px(desired_size.y, scale));
    desired_size.x = (std::clamp)(scaled_desired.x, effective_minimum.x, available.x);
    desired_size.y = (std::clamp)(scaled_desired.y, effective_minimum.y, available.y);
    ImGui::SetNextWindowPos(position, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(desired_size, ImGuiCond_Appearing);
    ImGui::SetNextWindowSizeConstraints(effective_minimum, available);
    std::string popup = safe(title);
    popup += "###";
    popup += safe(popup_id);
    return ImGui::BeginPopupModal(popup.c_str(), nullptr,
        ImGuiWindowFlags_NoSavedSettings);
}

void open_dialog(const char* popup_id, const char* title) {
    std::string popup = safe(title);
    popup += "###";
    popup += safe(popup_id);
    ImGui::OpenPopup(popup.c_str());
}

dialog_result_t dialog_footer(const char* stable_id, const char* confirm_label,
    bool confirm_enabled, bool destructive, const char* cancel_label) {
    dialog_result_t result;
    const auto m = metrics();
    ImGui::PushID(safe(stable_id));
    ImGui::Separator();
    ImGui::Dummy(ImVec2(0.f, m.spacing_xs));
    const float available_width = (std::max)(1.f, ImGui::GetContentRegionAvail().x);
    const float desired_cancel_width = ImGui::CalcTextSize(safe(cancel_label)).x + m.spacing_lg * 2.f;
    const float desired_confirm_width = ImGui::CalcTextSize(safe(confirm_label)).x + m.spacing_lg * 2.f;
    const bool stacked = desired_cancel_width + desired_confirm_width + m.spacing_sm > available_width;
    const float cancel_width = stacked ? available_width : desired_cancel_width;
    const float confirm_width = stacked ? available_width : desired_confirm_width;
    if (!stacked)
        ImGui::SetCursorPosX((std::max)(ImGui::GetCursorPosX(), ImGui::GetCursorPosX() +
            available_width - cancel_width - confirm_width - m.spacing_sm));
    if (components::button(safe(cancel_label), components::button_kind_t::secondary,
        components::size_t_::sm, ImVec2(cancel_width, m.control_height))) result.cancelled = true;
    draw_focus_ring_for_last_item();
    if (!stacked)
        ImGui::SameLine(0.f, m.spacing_sm);
    const auto kind = destructive ? components::button_kind_t::destructive : components::button_kind_t::primary;
    if (components::button(safe(confirm_label), kind, components::size_t_::sm,
        ImVec2(confirm_width, m.control_height), !confirm_enabled)) result.confirmed = true;
    draw_focus_ring_for_last_item();
    if (!destructive && confirm_enabled && ImGui::IsKeyPressed(ImGuiKey_Enter) &&
        !ImGui::GetIO().WantTextInput) result.confirmed = true;
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) result.cancelled = true;
    ImGui::PopID();
    return result;
}

dialog_result_t confirmation_dialog(const char* stable_id, const confirmation_t& confirmation) {
    dialog_result_t result;
    const auto& theme = aida::ui::resolved();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(
        confirmation.destructive ? theme.error : theme.text_primary), "%s %s?",
        safe(confirmation.verb), safe(confirmation.target));
    if (confirmation.scope && *confirmation.scope)
        components::property_row("scope", "Scope", confirmation.scope);
    if (confirmation.effect && *confirmation.effect)
        components::property_row("effect", "Effect", confirmation.effect,
            false, false, confirmation.destructive ? components::status_kind_t::error : components::status_kind_t::info);
    if (confirmation.reversibility && *confirmation.reversibility)
        components::property_row("reversible", "Recovery", confirmation.reversibility);
    if (confirmation.prerequisite && *confirmation.prerequisite)
        components::inline_notice("prerequisite", "Required before continuing", confirmation.prerequisite,
            components::status_kind_t::warning);
    result = dialog_footer(stable_id,
        confirmation.confirm_label && *confirmation.confirm_label ? confirmation.confirm_label : confirmation.verb,
        confirmation.confirm_enabled, confirmation.destructive);
    return result;
}

bool tiny_view_required(ImVec2 available, ImVec2 logical_minimum) {
    const float scale = metrics().scale;
    return available.x < aida::ui::scale_px(logical_minimum.x, scale) ||
        available.y < aida::ui::scale_px(logical_minimum.y, scale);
}

ImVec2 minimum_logical_size(view_size_class_t size_class) {
    switch (size_class) {
    case view_size_class_t::narrow_utility: return ImVec2(240.f, 160.f);
    case view_size_class_t::navigator: return ImVec2(260.f, 220.f);
    case view_size_class_t::inspector: return ImVec2(300.f, 220.f);
    case view_size_class_t::bottom_panel: return ImVec2(360.f, 160.f);
    case view_size_class_t::document: return ImVec2(480.f, 300.f);
    case view_size_class_t::graph: return ImVec2(520.f, 340.f);
    case view_size_class_t::debugger_cpu: return ImVec2(620.f, 380.f);
    case view_size_class_t::request_editor: return ImVec2(520.f, 320.f);
    case view_size_class_t::structure_editor: return ImVec2(560.f, 360.f);
    }
    return ImVec2(240.f, 160.f);
}

bool read_view_preference(view_preference_kind_t kind, const char* stable_view_id,
    std::string& payload) {
    payload.clear();
    const std::string id = safe(stable_view_id);
    if (id.empty() || id.size() > 160u) return false;
    const nlohmann::json root = parse_preferences(preference_blob(kind));
    const auto& views = root["views"];
    const auto found = views.find(id);
    if (found == views.end() || !found->is_string()) return false;
    payload = found->get<std::string>();
    if (payload.size() > 64u * 1024u) {
        payload.clear();
        return false;
    }
    return true;
}

bool write_view_preference(view_preference_kind_t kind, const char* stable_view_id,
    const std::string& payload) {
    const std::string id = safe(stable_view_id);
    if (id.empty() || id.size() > 160u || payload.size() > 64u * 1024u) return false;
    nlohmann::json root = parse_preferences(preference_blob(kind));
    root["views"][id] = payload;
    std::string serialized = root.dump();
    if (serialized.size() > 1024u * 1024u) return false;
    preference_blob(kind) = std::move(serialized);
    return g_sa_settings.save();
}

bool erase_view_preference(view_preference_kind_t kind, const char* stable_view_id) {
    const std::string id = safe(stable_view_id);
    if (id.empty() || id.size() > 160u) return false;
    nlohmann::json root = parse_preferences(preference_blob(kind));
    auto& views = root["views"];
    const std::size_t erased = views.erase(id);
    if (!erased) return true;
    preference_blob(kind) = root.dump();
    return g_sa_settings.save();
}

bool publish_notification(notification_t notification) {
    if (!notification.summary || !*notification.summary) return false;
    const bool persistent = notification.attention_required ||
        notification.semantic == semantic_t::error ||
        notification.semantic == semantic_t::stale ||
        notification.semantic == semantic_t::disabled;
    if (persistent) {
        if (!notification.stable_id || !*notification.stable_id) return false;
        task_center::diagnostic_registration_t diagnostic;
        diagnostic.id = notification.stable_id;
        diagnostic.owner = safe(notification.owner);
        diagnostic.target = safe(notification.target);
        diagnostic.summary = notification.summary;
        diagnostic.details = safe(notification.details);
        if (notification.semantic == semantic_t::warning || notification.semantic == semantic_t::stale)
            diagnostic.severity = task_center::diagnostic_severity_t::warning;
        else if (notification.semantic == semantic_t::info)
            diagnostic.severity = task_center::diagnostic_severity_t::information;
        else
            diagnostic.severity = task_center::diagnostic_severity_t::error;
        diagnostic.callbacks.focus = std::move(notification.action);
        return task_center::raise_diagnostic(std::move(diagnostic));
    }
    toast_notification::toast_type_t type = toast_notification::toast_type_t::info;
    if (notification.semantic == semantic_t::success || notification.semantic == semantic_t::live)
        type = toast_notification::toast_type_t::success;
    else if (notification.semantic == semantic_t::warning)
        type = toast_notification::toast_type_t::warning;
    if (notification.action && notification.action_label && *notification.action_label) {
        toast_notification::action_t action;
        action.label = notification.action_label;
        action.on_click = std::move(notification.action);
        toast_notification::push_with_action(notification.summary, type, std::move(action));
    } else {
        toast_notification::push(notification.summary, type);
    }
    return true;
}

bool selection_activate_requested() {
    return ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Enter) && !ImGui::GetIO().WantTextInput;
}

bool selection_context_requested() {
    if (!ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) ||
        ImGui::GetIO().WantTextInput) return false;
    return ImGui::IsKeyPressed(ImGuiKey_Menu) ||
        (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10));
}

}
