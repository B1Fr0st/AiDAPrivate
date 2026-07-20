#include "context_menu_renderer.hpp"
#include "application_ui_runtime.hpp"

#include "imgui/imgui.h"
#include "../../preview/studio_semantics.hpp"

#include <algorithm>
#include <cfloat>

namespace aida::ui {

context_menu_render_result_t render_context_menu_popup(
    const char* popup_id,
    const context_menu_presenter_t& presenter,
    const context_menu_open_request_t& request,
    const interaction_context_t& context) {
    context_menu_render_result_t result;
    if (!popup_id || !*popup_id)
        return result;
    const ImGuiViewport* viewport = ImGui::GetWindowViewport();
    const float dpi = viewport ? (std::max)(1.0f, viewport->DpiScale) : 1.0f;
    const float available_height = viewport
        ? (std::max)(1.0f, viewport->WorkSize.y - 16.0f * dpi)
        : 720.0f * dpi;
    const float maximum_height = (std::min)(720.0f * dpi, available_height);
    ImGui::SetNextWindowSizeConstraints(
        ImVec2(0.0f, 0.0f), ImVec2(FLT_MAX, maximum_height));
    if (!ImGui::BeginPopup(popup_id))
        return result;

    result.open = true;
    const auto presentation = presenter.compose(request, context);
    if (!presentation.ready()) {
        ImGui::BeginDisabled();
        ImGui::MenuItem(presentation.detail.empty() ? "Context unavailable" : presentation.detail.c_str());
        ImGui::EndDisabled();
        ImGui::EndPopup();
        return result;
    }
    if (presentation.sections.empty()) {
        ImGui::BeginDisabled();
        ImGui::MenuItem("No actions available for this selection");
        ImGui::EndDisabled();
        ImGui::EndPopup();
        return result;
    }

    bool first_section = true;
    for (const auto& section : presentation.sections) {
        if (!first_section)
            ImGui::Separator();
        first_section = false;
        if (!section.label.empty())
            ImGui::TextDisabled("%s", section.label.c_str());
        for (const auto& action : section.actions) {
            const bool checked = action.check_state == action_check_state_t::checked;
            const bool checkable = action.check_state != action_check_state_t::not_checkable;
            if (!action.enabled)
                ImGui::BeginDisabled();
            const bool selected = ImGui::MenuItem(
                action.label.c_str(),
                action.shortcut_hint.empty() ? nullptr : action.shortcut_hint.c_str(),
                checkable ? checked : false,
                action.enabled);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            if (ImGui::IsItemVisible()) {
                const std::string semantic_id = aida::preview::semantics::stable_id(
                    "aida.context", request.menu.value() + "." + action.action.value());
                aida::preview::semantics::register_last_item(
                    semantic_id, "context-menu-action", true, !action.enabled);
            }
#endif
            if (!action.enabled) {
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) &&
                    !action.disabled_reason.empty())
                    ImGui::SetTooltip("%s", action.disabled_reason.c_str());
                ImGui::EndDisabled();
            } else if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal) &&
                       !action.description.empty()) {
                ImGui::SetTooltip("%s", action.description.c_str());
            }
            if (!selected)
                continue;

            action_invocation_t invocation{context};
            invocation.source = action_invocation_source_t::context_menu;
            result.execution = presenter.execute(request, action.action, invocation);
            result.action = action.action;
            result.executed = result.execution.executed();
            application_ui::finalize_action_execution(action.action.c_str(),
                result.execution, action_invocation_source_t::context_menu, context);
        }
    }

    ImGui::EndPopup();
    return result;
}

}
