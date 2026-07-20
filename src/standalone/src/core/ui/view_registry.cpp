#include "view_registry.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <exception>
#include <set>
#include <utility>

namespace aida::ui {

namespace {

constexpr float k_maximum_minimum_dimension = 16384.0f;

bool valid_minimum_size(const view_minimum_size_t& size) noexcept {
    return std::isfinite(size.width) && std::isfinite(size.height) &&
           size.width >= 1.0f && size.height >= 1.0f &&
           size.width <= k_maximum_minimum_dimension &&
           size.height <= k_maximum_minimum_dimension;
}

}

view_operation_result_t view_registry_t::validate_descriptor(
    const view_descriptor_t& descriptor) {
    if (!is_valid_stable_id(descriptor.id.value()))
        return {view_operation_status_t::invalid_descriptor, "View ID is not stable"};
    if (!is_valid_display_label(descriptor.display_name))
        return {view_operation_status_t::invalid_descriptor, "View display name is invalid"};
    if (!is_valid_stable_id(descriptor.internal_name))
        return {view_operation_status_t::invalid_descriptor, "View internal name is invalid"};
    if (!valid_minimum_size(descriptor.minimum_size))
        return {view_operation_status_t::invalid_descriptor, "View minimum size is invalid"};
    if (descriptor.persistence_version == 0 || descriptor.preset_introduced_revision == 0)
        return {view_operation_status_t::invalid_descriptor, "View persistence metadata is invalid"};
    if (descriptor.render_ownership == view_render_ownership_t::registry_window &&
        !descriptor.render)
        return {view_operation_status_t::invalid_descriptor, "View has no renderer"};
    if (descriptor.render_ownership == view_render_ownership_t::legacy_adapter &&
        !descriptor.activate)
        return {view_operation_status_t::invalid_descriptor, "Legacy view has no activation adapter"};
    if (descriptor.default_open &&
        descriptor.identity_policy == view_identity_policy_t::multi_instance)
        return {view_operation_status_t::invalid_descriptor,
                "Multi-instance view cannot open without an instance key"};
    std::set<stable_action_id_t> actions;
    for (const auto& action : descriptor.action_bindings) {
        if (!is_valid_stable_id(action.value()))
            return {view_operation_status_t::invalid_descriptor, "View action binding is invalid"};
        if (!actions.insert(action).second)
            return {view_operation_status_t::invalid_descriptor,
                    "View action binding is duplicated"};
    }
    std::set<stable_view_id_t> aliases;
    for (const auto& alias : descriptor.persistence_aliases) {
        if (!is_valid_stable_id(alias.value()) || alias == descriptor.id)
            return {view_operation_status_t::invalid_descriptor, "View persistence alias is invalid"};
        if (!aliases.insert(alias).second)
            return {view_operation_status_t::invalid_descriptor, "View persistence alias is duplicated"};
    }
    return {};
}

view_operation_result_t view_registry_t::register_view(view_descriptor_t descriptor) {
    auto validation = validate_descriptor(descriptor);
    if (!validation.ok())
        return validation;
    if (descriptors_.find(descriptor.id) != descriptors_.end())
        return {view_operation_status_t::already_registered, "View ID is already registered"};
    for (const auto& entry : descriptors_) {
        if (entry.second.internal_name == descriptor.internal_name)
            return {view_operation_status_t::already_registered,
                    "View internal name is already registered"};
        if (std::find(entry.second.persistence_aliases.begin(),
                      entry.second.persistence_aliases.end(), descriptor.id) !=
                entry.second.persistence_aliases.end() ||
            std::find(descriptor.persistence_aliases.begin(), descriptor.persistence_aliases.end(),
                      entry.first) != descriptor.persistence_aliases.end())
            return {view_operation_status_t::already_registered,
                    "View ID conflicts with a persistence alias"};
        for (const auto& alias : descriptor.persistence_aliases)
            if (std::find(entry.second.persistence_aliases.begin(),
                          entry.second.persistence_aliases.end(), alias) !=
                    entry.second.persistence_aliases.end())
                return {view_operation_status_t::already_registered,
                        "View persistence alias is already registered"};
    }

    const auto id = descriptor.id;
    const bool default_open = descriptor.default_open;
    const auto inserted = descriptors_.emplace(id, std::move(descriptor));
    try {
        if (default_open) {
            const view_instance_id_t instance{id, {}};
            auto& state = ensure_instance(inserted.first->second, instance, {});
            state.open = true;
        }
    } catch (...) {
        descriptors_.erase(inserted.first);
        throw;
    }
    ++revision_;
    ++visibility_revision_;
    return {};
}

const view_descriptor_t* view_registry_t::find_descriptor(const stable_view_id_t& id) const noexcept {
    const auto found = descriptors_.find(id);
    return found == descriptors_.end() ? nullptr : &found->second;
}

const view_instance_state_t* view_registry_t::find_instance(
    const view_instance_id_t& id) const noexcept {
    const auto found = instances_.find(id);
    return found == instances_.end() ? nullptr : &found->second;
}

view_instance_state_t* view_registry_t::find_instance(const view_instance_id_t& id) noexcept {
    const auto found = instances_.find(id);
    return found == instances_.end() ? nullptr : &found->second;
}

capability_state_t view_registry_t::evaluate(const stable_view_id_t& id,
                                             const interaction_context_t& context) const {
    const auto* descriptor = find_descriptor(id);
    if (!descriptor)
        return capability_state_t::unavailable("View is not registered", false);
    try {
        auto result = descriptor->capability
            ? descriptor->capability(context)
            : capability_state_t::available();
        if ((!result.visible || !result.enabled) && result.disabled_reason.empty())
            result.disabled_reason = "View is unavailable in the current context";
        return result;
    } catch (const std::exception& exception) {
        return capability_state_t::unavailable(exception.what());
    } catch (...) {
        return capability_state_t::unavailable("View capability evaluation failed");
    }
}

view_operation_result_t view_registry_t::validate_instance(
    const view_descriptor_t& descriptor,
    const view_instance_id_t& id) const {
    if (descriptor.id != id.view)
        return {view_operation_status_t::invalid_instance, "Instance belongs to another view"};
    if (descriptor.identity_policy == view_identity_policy_t::singleton && !id.instance.empty())
        return {view_operation_status_t::invalid_instance,
                "Singleton view cannot have an instance key"};
    if (descriptor.identity_policy == view_identity_policy_t::multi_instance &&
        !is_valid_stable_instance_key(id.instance.value()))
        return {view_operation_status_t::invalid_instance,
                "Multi-instance view requires a stable instance key"};
    return {};
}

view_instance_state_t& view_registry_t::ensure_instance(
    const view_descriptor_t& descriptor,
    const view_instance_id_t& id,
    std::string display_name) {
    auto found = instances_.find(id);
    if (found != instances_.end()) {
        if (!display_name.empty() && display_name != found->second.display_name) {
            std::string window_name = compose_window_name(descriptor, id, display_name);
            found->second.display_name = std::move(display_name);
            found->second.window_name = std::move(window_name);
        }
        return found->second;
    }

    view_instance_state_t state;
    state.id = id;
    state.display_name = display_name.empty() ? descriptor.display_name : std::move(display_name);
    state.window_name = compose_window_name(descriptor, id, state.display_name);
    return instances_.emplace(id, std::move(state)).first->second;
}

std::string view_registry_t::compose_window_name(const view_descriptor_t& descriptor,
                                                 const view_instance_id_t& id,
                                                 const std::string& display_name) {
    std::string result = display_name;
    result.append("###");
    result.append(descriptor.internal_name);
    if (descriptor.identity_policy == view_identity_policy_t::multi_instance) {
        result.push_back('.');
        result.append(id.instance.value());
    }
    return result;
}

view_operation_result_t view_registry_t::open(const view_instance_id_t& id,
                                              const interaction_context_t& context,
                                              std::string display_name) {
    const auto* descriptor = find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "View is not registered"};
    auto instance_validation = validate_instance(*descriptor, id);
    if (!instance_validation.ok())
        return instance_validation;
    if (!display_name.empty() && !is_valid_display_label(display_name))
        return {view_operation_status_t::invalid_instance, "Instance display name is invalid"};
    const auto capability = evaluate(id.view, context);
    if (!capability.visible || !capability.enabled)
        return {view_operation_status_t::unavailable, capability.disabled_reason};

    try {
        if (descriptor->activate)
            descriptor->activate(id);
    } catch (const std::exception& exception) {
        return {view_operation_status_t::unavailable, exception.what()};
    } catch (...) {
        return {view_operation_status_t::unavailable,
            "View activation failed with an unknown error"};
    }

    const auto* existing = find_instance(id);
    const bool visibility_changed = !existing || !existing->open;
    const bool changed = visibility_changed ||
        (!display_name.empty() && display_name != existing->display_name);
    auto& state = ensure_instance(*descriptor, id, std::move(display_name));
    state.open = true;
    closed_history_.erase(
        std::remove(closed_history_.begin(), closed_history_.end(), id),
        closed_history_.end());
    if (changed)
        ++revision_;
    if (visibility_changed)
        ++visibility_revision_;
    return {};
}

view_operation_result_t view_registry_t::ensure_identity(const view_instance_id_t& id,
                                                          std::string display_name) {
    const auto* descriptor = find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "View is not registered"};
    auto instance_validation = validate_instance(*descriptor, id);
    if (!instance_validation.ok())
        return instance_validation;
    if (!display_name.empty() && !is_valid_display_label(display_name))
        return {view_operation_status_t::invalid_instance, "Instance display name is invalid"};
    const auto* existing = find_instance(id);
    const bool changed = !existing ||
        (!display_name.empty() && display_name != existing->display_name);
    ensure_instance(*descriptor, id, std::move(display_name));
    if (changed)
        ++revision_;
    return {};
}

view_operation_result_t view_registry_t::focus(const view_instance_id_t& id) {
    auto* state = find_instance(id);
    if (!state || !state->open)
        return {view_operation_status_t::not_open, "View is not open"};
    state->focus_request_generation = ++focus_sequence_;
    state->last_focus_sequence = focus_sequence_;
    ++revision_;
    return {};
}

view_operation_result_t view_registry_t::open_or_focus(const view_instance_id_t& id,
                                                       const interaction_context_t& context,
                                                       std::string display_name) {
    auto opened = open(id, context, std::move(display_name));
    if (!opened.ok())
        return opened;
    return focus(id);
}

view_operation_result_t view_registry_t::close(const view_instance_id_t& id) {
    const auto* descriptor = find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "View is not registered"};
    auto* state = find_instance(id);
    if (!state || !state->open)
        return {view_operation_status_t::not_open, "View is not open"};
    if (!descriptor->closeable)
        return {view_operation_status_t::not_closeable, "View cannot be closed"};

    std::vector<view_instance_id_t> next_closed_history;
    try {
        next_closed_history = closed_history_;
        next_closed_history.erase(
            std::remove(next_closed_history.begin(), next_closed_history.end(), id),
            next_closed_history.end());
        next_closed_history.push_back(id);
        constexpr std::size_t k_closed_history_capacity = 64;
        if (next_closed_history.size() > k_closed_history_capacity)
            next_closed_history.erase(next_closed_history.begin(),
                next_closed_history.begin() +
                    static_cast<std::ptrdiff_t>(next_closed_history.size() -
                        k_closed_history_capacity));
        if (descriptor->deactivate)
            descriptor->deactivate(id);
    } catch (const std::exception& exception) {
        return {view_operation_status_t::unavailable, exception.what()};
    } catch (...) {
        return {view_operation_status_t::unavailable,
            "View deactivation failed with an unknown error"};
    }

    state->open = false;
    state->focused = false;
    state->focus_request_generation = state->consumed_focus_generation;
    if (focused_instance_ && *focused_instance_ == id)
        focused_instance_.reset();
    closed_history_.swap(next_closed_history);
    ++revision_;
    ++visibility_revision_;
    return {};
}

view_operation_result_t view_registry_t::reopen_last_closed(
    const interaction_context_t& context) {
    if (closed_history_.empty())
        return {view_operation_status_t::not_open, "No recently closed view is available"};
    const view_instance_id_t id = closed_history_.back();
    return open_or_focus(id, context);
}

view_operation_result_t view_registry_t::open_default_missing(
    const interaction_context_t& context) {
    bool opened = false;
    for (const auto& entry : descriptors_) {
        const auto& descriptor = entry.second;
        if (!descriptor.default_open)
            continue;
        const view_instance_id_t id{descriptor.id, {}};
        if (is_open(id))
            continue;
        const auto result = open(id, context);
        if (!result.ok())
            return result;
        opened = true;
    }
    return opened
        ? view_operation_result_t{}
        : view_operation_result_t{view_operation_status_t::completed,
            "All default views are already open"};
}

view_operation_result_t view_registry_t::erase_closed_instance(const view_instance_id_t& id) {
    const auto* descriptor = find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "View is not registered"};
    if (descriptor->identity_policy != view_identity_policy_t::multi_instance)
        return {view_operation_status_t::invalid_instance,
                "Singleton view instances are retained"};
    const auto found = instances_.find(id);
    if (found == instances_.end())
        return {view_operation_status_t::invalid_instance, "View instance does not exist"};
    if (found->second.open)
        return {view_operation_status_t::invalid_instance,
                "Open view instance cannot be erased"};
    closed_history_.erase(
        std::remove(closed_history_.begin(), closed_history_.end(), id),
        closed_history_.end());
    instances_.erase(found);
    ++revision_;
    return {};
}

view_operation_result_t view_registry_t::render(const view_instance_id_t& id,
                                                const interaction_context_t& context) const {
    const auto* descriptor = find_descriptor(id.view);
    if (!descriptor)
        return {view_operation_status_t::not_registered, "View is not registered"};
    const auto* state = find_instance(id);
    if (!state || !state->open)
        return {view_operation_status_t::not_open, "View is not open"};
    const auto capability = evaluate(id.view, context);
    if (!capability.visible || !capability.enabled)
        return {view_operation_status_t::unavailable, capability.disabled_reason};

    if (descriptor->render_ownership == view_render_ownership_t::legacy_adapter)
        return {};

    try {
        descriptor->render({id, context});
    } catch (const std::exception& exception) {
        return {view_operation_status_t::render_failed, exception.what()};
    } catch (...) {
        return {view_operation_status_t::render_failed,
                "View renderer failed with an unknown error"};
    }
    return {};
}

bool view_registry_t::consume_focus_request(const view_instance_id_t& id) noexcept {
    auto* state = find_instance(id);
    if (!state || !state->open ||
        state->focus_request_generation <= state->consumed_focus_generation)
        return false;
    state->consumed_focus_generation = state->focus_request_generation;
    return true;
}

void view_registry_t::update_focus(const std::optional<view_instance_id_t>& focused) {
    if (focused_instance_ == focused)
        return;
    if (focused_instance_) {
        if (auto* previous = find_instance(*focused_instance_))
            previous->focused = false;
    }
    focused_instance_.reset();
    if (focused) {
        if (auto* current = find_instance(*focused); current && current->open) {
            current->focused = true;
            current->last_focus_sequence = ++focus_sequence_;
            focused_instance_ = *focused;
        }
    }
    ++revision_;
}

bool view_registry_t::is_open(const view_instance_id_t& id) const noexcept {
    const auto* state = find_instance(id);
    return state && state->open;
}

std::optional<view_instance_id_t> view_registry_t::focused_instance() const {
    return focused_instance_;
}

const std::string& view_registry_t::window_name(const view_instance_id_t& id) const noexcept {
    static const std::string empty;
    const auto* state = find_instance(id);
    return state ? state->window_name : empty;
}

void view_registry_t::for_each_descriptor(
    const std::function<void(const view_descriptor_t&)>& visitor) const {
    if (!visitor)
        return;
    for (const auto& entry : descriptors_)
        visitor(entry.second);
}

void view_registry_t::for_each_instance(
    const std::function<void(const view_descriptor_t&, const view_instance_state_t&)>& visitor,
    bool open_only) const {
    if (!visitor)
        return;
    for (const auto& entry : instances_) {
        if (open_only && !entry.second.open)
            continue;
        const auto* descriptor = find_descriptor(entry.first.view);
        if (descriptor)
            visitor(*descriptor, entry.second);
    }
}

}
