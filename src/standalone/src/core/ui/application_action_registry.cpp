#include "application_action_registry.hpp"

#include <algorithm>
#include <exception>
#include <set>
#include <utility>

namespace aida::ui {

namespace {

constexpr action_surface_t k_all_surfaces =
    action_surface_t::application_menu |
    action_surface_t::toolbar |
    action_surface_t::command_palette |
    action_surface_t::context_menu |
    action_surface_t::shortcut |
    action_surface_t::accessibility;

bool valid_category_id(const std::string& value) noexcept {
    return is_valid_stable_id(value);
}

std::string resolved_consequence_summary(const application_action_descriptor_t& descriptor,
                                         const interaction_context_t& context) {
    std::string result = descriptor.consequence.summary;
    if (descriptor.consequence.target_summary) {
        std::string target = descriptor.consequence.target_summary(context);
        if (!target.empty()) {
            if (!result.empty())
                result.append(": ");
            result.append(target);
        }
    }
    return result;
}

action_surface_t surface_for_source(action_invocation_source_t source) noexcept {
    switch (source) {
        case action_invocation_source_t::application_menu:
            return action_surface_t::application_menu;
        case action_invocation_source_t::activity_bar:
            return action_surface_t::accessibility;
        case action_invocation_source_t::toolbar:
            return action_surface_t::toolbar;
        case action_invocation_source_t::command_palette:
            return action_surface_t::command_palette;
        case action_invocation_source_t::context_menu:
            return action_surface_t::context_menu;
        case action_invocation_source_t::shortcut:
            return action_surface_t::shortcut;
        case action_invocation_source_t::accessibility:
            return action_surface_t::accessibility;
    }
    return action_surface_t::none;
}

action_handler_result_t prepare_confirmation_safely(
    const application_action_descriptor_t& descriptor,
    const action_invocation_t& invocation) {
    if (!descriptor.prepare_confirmation)
        return action_handler_result_t::completed();
    try {
        return descriptor.prepare_confirmation(invocation);
    } catch (const std::exception& exception) {
        return action_handler_result_t::failed(exception.what());
    } catch (...) {
        return action_handler_result_t::failed(
            "The action confirmation could not be prepared");
    }
}

std::string cancel_failed_confirmation_safely(
    const application_action_descriptor_t& descriptor) {
    if (!descriptor.cancel_confirmation)
        return {};
    try {
        descriptor.cancel_confirmation();
        return {};
    } catch (const std::exception& exception) {
        return exception.what();
    } catch (...) {
        return "The failed confirmation cleanup raised an unknown error";
    }
}

}

action_handler_result_t action_handler_result_t::completed(std::string message_value) {
    return {true, std::move(message_value)};
}

action_handler_result_t action_handler_result_t::failed(std::string message_value) {
    if (message_value.empty())
        message_value = "The action failed";
    return {false, std::move(message_value)};
}

action_registration_result_t application_action_registry_t::validate(
    const application_action_descriptor_t& descriptor) {
    if (!is_valid_stable_id(descriptor.id.value()))
        return {action_registration_error_t::invalid_id, "Action ID is not stable"};
    if (!is_valid_display_label(descriptor.label))
        return {action_registration_error_t::invalid_label, "Action label is invalid"};
    if (!descriptor.description.empty() && !is_valid_display_label(descriptor.description))
        return {action_registration_error_t::invalid_label, "Action description is invalid"};
    if (!valid_category_id(descriptor.category.id) ||
        !is_valid_display_label(descriptor.category.display_name))
        return {action_registration_error_t::invalid_category, "Action category is invalid"};
    if (!descriptor.icon_semantic.empty() && !is_valid_stable_id(descriptor.icon_semantic))
        return {action_registration_error_t::invalid_label, "Action icon semantic is invalid"};
    if (!any(descriptor.surfaces & k_all_surfaces))
        return {action_registration_error_t::missing_surface, "Action has no discoverable surface"};
    if (static_cast<std::uint32_t>(descriptor.surfaces) &
        ~static_cast<std::uint32_t>(k_all_surfaces))
        return {action_registration_error_t::missing_surface, "Action has an unknown surface"};
    if (!descriptor.invoke)
        return {action_registration_error_t::missing_handler, "Action has no handler"};
    std::set<stable_context_type_id_t> contexts;
    for (const auto& context : descriptor.accepted_contexts) {
        if (!is_valid_stable_id(context.value()))
            return {action_registration_error_t::invalid_context_type,
                    "Action context type is invalid"};
        if (!contexts.insert(context).second)
            return {action_registration_error_t::invalid_context_type,
                    "Action context type is duplicated"};
    }
    if (descriptor.consequence.confirmation != confirmation_requirement_t::none &&
        !any(descriptor.consequence.effects))
        return {action_registration_error_t::invalid_consequence,
                "Confirmation requires a declared consequence"};
    if (descriptor.consequence.confirmation == confirmation_requirement_t::review &&
        !descriptor.reviewable)
        return {action_registration_error_t::invalid_consequence,
                "Review confirmation requires reviewable behavior"};
    if (descriptor.consequence.confirmation != confirmation_requirement_t::none &&
        descriptor.consequence.summary.empty() && !descriptor.consequence.target_summary)
        return {action_registration_error_t::invalid_consequence,
                "Confirmed action requires a consequence summary"};
    if (any(descriptor.consequence.effects & action_effect_t::destructive) &&
        descriptor.consequence.confirmation == confirmation_requirement_t::none)
        return {action_registration_error_t::invalid_consequence,
                "Destructive action requires confirmation or review"};
    return {};
}

action_registration_result_t application_action_registry_t::register_action(
    application_action_descriptor_t descriptor) {
    auto validation = validate(descriptor);
    if (!validation.ok())
        return validation;
    if (actions_.find(descriptor.id) != actions_.end())
        return {action_registration_error_t::duplicate_id, "Action ID is already registered"};

    actions_.emplace(descriptor.id, std::move(descriptor));
    ++revision_;
    return {};
}

const application_action_descriptor_t* application_action_registry_t::find(
    const stable_action_id_t& id) const noexcept {
    const auto found = actions_.find(id);
    return found == actions_.end() ? nullptr : &found->second;
}

bool application_action_registry_t::accepts_context(
    const application_action_descriptor_t& descriptor,
    const interaction_context_t& context) noexcept {
    if (descriptor.accepted_contexts.empty())
        return true;
    if (!context.payload.has_value())
        return false;
    return std::find(descriptor.accepted_contexts.begin(),
                     descriptor.accepted_contexts.end(),
                     context.payload.type_id()) != descriptor.accepted_contexts.end();
}

action_state_t application_action_registry_t::evaluate(
    const stable_action_id_t& id,
    const interaction_context_t& context) const {
    action_state_t state;
    const auto* descriptor = find(id);
    if (!descriptor) {
        state.capability = capability_state_t::unavailable("Action is not registered", false);
        return state;
    }
    if (!accepts_context(*descriptor, context)) {
        state.capability = capability_state_t::unavailable(
            "Action does not support the current selection");
        return state;
    }

    try {
        state.capability = descriptor->capability
            ? descriptor->capability(context)
            : capability_state_t::available();
        if ((!state.capability.visible || !state.capability.enabled) &&
            state.capability.disabled_reason.empty())
            state.capability.disabled_reason = "Unavailable in the current context";
        if (descriptor->checked)
            state.check_state = descriptor->checked(context);
        state.consequence_summary = resolved_consequence_summary(*descriptor, context);
    } catch (const std::exception& exception) {
        state.capability = capability_state_t::unavailable(exception.what());
    } catch (...) {
        state.capability = capability_state_t::unavailable(
            "Action capability evaluation failed");
    }
    return state;
}

action_execution_result_t application_action_registry_t::execute(
    const stable_action_id_t& id,
    const action_invocation_t& invocation) const {
    action_execution_result_t result;
    result.action = id;
    const auto* descriptor = find(id);
    if (!descriptor) {
        result.status = action_execution_status_t::not_found;
        result.message = "Action is not registered";
        return result;
    }
    if (!any(descriptor->surfaces & surface_for_source(invocation.source))) {
        result.status = action_execution_status_t::rejected;
        result.message = "Action is not available from this command surface";
        return result;
    }

    const auto state = evaluate(id, invocation.context);
    result.consequence_summary = state.consequence_summary;
    if (!state.capability.visible || !state.capability.enabled) {
        result.status = action_execution_status_t::unavailable;
        result.message = state.capability.disabled_reason;
        return result;
    }

    if (descriptor->consequence.confirmation == confirmation_requirement_t::review &&
        !invocation.review_completed) {
        const auto prepared = prepare_confirmation_safely(*descriptor, invocation);
        if (!prepared.success) {
            result.status = action_execution_status_t::failed;
            result.message = prepared.message.empty()
                ? "The action review could not be prepared" : prepared.message;
            const std::string cleanup_failure =
                cancel_failed_confirmation_safely(*descriptor);
            if (!cleanup_failure.empty())
                result.message.append("; cleanup failed: ").append(cleanup_failure);
            return result;
        }
        result.status = action_execution_status_t::review_required;
        result.message = "Review is required before this action can run";
        return result;
    }
    if (descriptor->consequence.confirmation == confirmation_requirement_t::explicit_confirmation &&
        !invocation.confirmation_granted) {
        const auto prepared = prepare_confirmation_safely(*descriptor, invocation);
        if (!prepared.success) {
            result.status = action_execution_status_t::failed;
            result.message = prepared.message.empty()
                ? "The action confirmation could not be prepared" : prepared.message;
            const std::string cleanup_failure =
                cancel_failed_confirmation_safely(*descriptor);
            if (!cleanup_failure.empty())
                result.message.append("; cleanup failed: ").append(cleanup_failure);
            return result;
        }
        result.status = action_execution_status_t::confirmation_required;
        result.message = "Explicit confirmation is required before this action can run";
        return result;
    }

    try {
        const auto handler_result = descriptor->invoke(invocation);
        result.status = handler_result.success
            ? action_execution_status_t::executed
            : action_execution_status_t::failed;
        result.message = !handler_result.success && handler_result.message.empty()
            ? "The action failed" : handler_result.message;
    } catch (const std::exception& exception) {
        result.status = action_execution_status_t::failed;
        result.message = exception.what();
    } catch (...) {
        result.status = action_execution_status_t::failed;
        result.message = "The action failed with an unknown error";
    }
    return result;
}

void application_action_registry_t::for_each(
    const std::function<void(const application_action_descriptor_t&)>& visitor) const {
    if (!visitor)
        return;
    for (const auto& entry : actions_)
        visitor(entry.second);
}

}
