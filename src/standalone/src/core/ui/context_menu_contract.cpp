#include "context_menu_contract.hpp"

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>

namespace aida::ui {

namespace {

bool accepts_context(const context_menu_descriptor_t& descriptor,
                     const interaction_context_t& context) noexcept {
    if (descriptor.accepted_contexts.empty())
        return true;
    if (!context.payload.has_value())
        return false;
    return std::find(descriptor.accepted_contexts.begin(),
                     descriptor.accepted_contexts.end(),
                     context.payload.type_id()) != descriptor.accepted_contexts.end();
}

}

context_menu_registration_result_t context_menu_catalog_t::validate(
    const context_menu_descriptor_t& descriptor,
    const application_action_registry_t& actions) {
    if (!is_valid_stable_id(descriptor.id.value()))
        return {context_menu_status_t::invalid_descriptor, "Context menu ID is not stable"};
    if (descriptor.sections.empty())
        return {context_menu_status_t::invalid_descriptor, "Context menu has no sections"};
    std::set<stable_context_type_id_t> context_ids;
    for (const auto& context : descriptor.accepted_contexts) {
        if (!is_valid_stable_id(context.value()))
            return {context_menu_status_t::invalid_descriptor,
                    "Context menu type is invalid"};
        if (!context_ids.insert(context).second)
            return {context_menu_status_t::invalid_descriptor,
                    "Context menu type is duplicated"};
    }

    std::set<stable_menu_section_id_t> section_ids;
    std::set<stable_action_id_t> action_ids;
    for (const auto& section : descriptor.sections) {
        if (!is_valid_stable_id(section.id.value()) ||
            (!section.label.empty() && !is_valid_display_label(section.label)))
            return {context_menu_status_t::invalid_descriptor,
                    "Context menu section is invalid"};
        if (!section_ids.insert(section.id).second)
            return {context_menu_status_t::invalid_descriptor,
                    "Context menu section ID is duplicated"};
        if (section.actions.empty())
            return {context_menu_status_t::invalid_descriptor,
                    "Context menu section has no actions"};
        for (const auto& item : section.actions) {
            const auto* action = actions.find(item.action);
            if (!action || !any(action->surfaces & action_surface_t::context_menu))
                return {context_menu_status_t::invalid_descriptor,
                        "Context menu action is not registered for context menus"};
            if (!item.label_override.empty() && !is_valid_display_label(item.label_override))
                return {context_menu_status_t::invalid_descriptor,
                        "Context menu action label is invalid"};
            if (!item.description_override.empty() &&
                !is_valid_display_label(item.description_override))
                return {context_menu_status_t::invalid_descriptor,
                        "Context menu action description is invalid"};
            if (!action_ids.insert(item.action).second)
                return {context_menu_status_t::invalid_descriptor,
                        "Context menu action is duplicated"};
        }
    }
    return {};
}

context_menu_registration_result_t context_menu_catalog_t::register_menu(
    context_menu_descriptor_t descriptor,
    const application_action_registry_t& actions) {
    auto validation = validate(descriptor, actions);
    if (!validation.ok())
        return validation;
    if (menus_.find(descriptor.id) != menus_.end())
        return {context_menu_status_t::duplicate_id, "Context menu ID is already registered"};
    menus_.emplace(descriptor.id, std::move(descriptor));
    ++revision_;
    return {};
}

const context_menu_descriptor_t* context_menu_catalog_t::find(
    const stable_menu_id_t& id) const noexcept {
    const auto found = menus_.find(id);
    return found == menus_.end() ? nullptr : &found->second;
}

void context_menu_catalog_t::for_each(
    const std::function<void(const context_menu_descriptor_t&)>& visitor) const {
    if (!visitor)
        return;
    for (const auto& entry : menus_)
        visitor(entry.second);
}

context_menu_presenter_t::context_menu_presenter_t(
    const context_menu_catalog_t& catalog,
    const application_action_registry_t& actions,
    const shortcut_resolver_t* shortcuts) noexcept
    : catalog_(catalog), actions_(actions), shortcuts_(shortcuts) {}

context_menu_presentation_t context_menu_presenter_t::compose(
    const context_menu_open_request_t& request,
    const interaction_context_t& context) const {
    context_menu_presentation_t result;
    result.menu = request.menu;
    result.origin = request.origin;
    const auto* descriptor = catalog_.find(request.menu);
    if (!descriptor) {
        result.status = context_menu_status_t::not_registered;
        result.detail = "Context menu is not registered";
        return result;
    }
    if (request.context_generation != context.generation) {
        result.status = context_menu_status_t::context_mismatch;
        result.detail = "Context menu selection is stale";
        return result;
    }
    if (!accepts_context(*descriptor, context)) {
        result.status = context_menu_status_t::context_mismatch;
        result.detail = "Context menu does not support the current selection";
        return result;
    }

    for (const auto& section : descriptor->sections) {
        context_menu_presented_section_t presented_section;
        presented_section.id = section.id;
        presented_section.label = section.label;
        presented_section.group = section.group;
        presented_section.order = section.order;
        for (const auto& item : section.actions) {
            const auto* action = actions_.find(item.action);
            if (!action)
                continue;
            const auto state = actions_.evaluate(item.action, context);
            if (!state.capability.visible ||
                (!state.capability.enabled &&
                 item.visibility == context_menu_visibility_t::hide_when_unavailable))
                continue;

            context_menu_presented_action_t presented;
            presented.action = item.action;
            presented.label = item.label_override.empty() ? action->label : item.label_override;
            presented.description = item.description_override.empty()
                ? action->description
                : item.description_override;
            presented.icon_semantic = item.icon_override.empty()
                ? action->icon_semantic
                : item.icon_override;
            presented.shortcut_hint = !item.shortcut_override.empty()
                ? item.shortcut_override
                : shortcuts_ ? shortcuts_->effective_hint(item.action, context)
                             : std::string{};
            presented.disabled_reason = state.capability.disabled_reason;
            presented.consequence_summary = state.consequence_summary;
            presented.check_state = state.check_state;
            presented.group = section.group;
            presented.order = item.order;
            presented.enabled = state.capability.enabled;
            presented.undoable = action->undoable;
            presented.reviewable = action->reviewable;
            presented.close_menu_on_execute = item.close_menu_on_execute;
            presented_section.actions.push_back(std::move(presented));
        }
        std::sort(presented_section.actions.begin(), presented_section.actions.end(),
            [](const context_menu_presented_action_t& lhs,
               const context_menu_presented_action_t& rhs) {
                return std::tie(lhs.group, lhs.order, lhs.label, lhs.action) <
                       std::tie(rhs.group, rhs.order, rhs.label, rhs.action);
            });
        if (!presented_section.actions.empty())
            result.sections.push_back(std::move(presented_section));
    }
    std::sort(result.sections.begin(), result.sections.end(),
        [](const context_menu_presented_section_t& lhs,
           const context_menu_presented_section_t& rhs) {
            return std::tie(lhs.group, lhs.order, lhs.label, lhs.id) <
                   std::tie(rhs.group, rhs.order, rhs.label, rhs.id);
        });
    return result;
}

action_execution_result_t context_menu_presenter_t::execute(
    const context_menu_open_request_t& request,
    const stable_action_id_t& action,
    const action_invocation_t& invocation) const {
    const auto* descriptor = catalog_.find(request.menu);
    if (!descriptor) {
        action_execution_result_t result;
        result.status = action_execution_status_t::not_found;
        result.action = action;
        result.message = "Context menu is not registered";
        return result;
    }
    if (request.context_generation != invocation.context.generation) {
        action_execution_result_t result;
        result.status = action_execution_status_t::rejected;
        result.action = action;
        result.message = "Context menu selection is stale";
        return result;
    }
    if (!accepts_context(*descriptor, invocation.context)) {
        action_execution_result_t result;
        result.status = action_execution_status_t::rejected;
        result.action = action;
        result.message = "Context menu does not support the current selection";
        return result;
    }
    if (invocation.source != action_invocation_source_t::context_menu) {
        action_execution_result_t result;
        result.status = action_execution_status_t::rejected;
        result.action = action;
        result.message = "Context menu action has an invalid invocation source";
        return result;
    }

    bool present = false;
    for (const auto& section : descriptor->sections) {
        for (const auto& item : section.actions) {
            if (item.action == action) {
                present = true;
                break;
            }
        }
        if (present)
            break;
    }
    if (!present) {
        action_execution_result_t result;
        result.status = action_execution_status_t::rejected;
        result.action = action;
        result.message = "Action is not part of this context menu";
        return result;
    }
    return actions_.execute(action, invocation);
}

}
