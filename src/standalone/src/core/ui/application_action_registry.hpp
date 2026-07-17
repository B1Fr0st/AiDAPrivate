#pragma once

#include "interaction_context.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace aida::ui {

enum class action_surface_t : std::uint32_t {
    none = 0,
    application_menu = 1u << 0u,
    toolbar = 1u << 1u,
    command_palette = 1u << 2u,
    context_menu = 1u << 3u,
    shortcut = 1u << 4u,
    accessibility = 1u << 5u
};

constexpr action_surface_t operator|(action_surface_t lhs, action_surface_t rhs) noexcept {
    return static_cast<action_surface_t>(static_cast<std::uint32_t>(lhs) |
                                         static_cast<std::uint32_t>(rhs));
}

constexpr action_surface_t operator&(action_surface_t lhs, action_surface_t rhs) noexcept {
    return static_cast<action_surface_t>(static_cast<std::uint32_t>(lhs) &
                                         static_cast<std::uint32_t>(rhs));
}

constexpr bool any(action_surface_t value) noexcept {
    return static_cast<std::uint32_t>(value) != 0;
}

enum class action_effect_t : std::uint32_t {
    none = 0,
    application_state = 1u << 0u,
    project_state = 1u << 1u,
    file_system = 1u << 2u,
    live_process = 1u << 3u,
    debugger_execution = 1u << 4u,
    memory_mutation = 1u << 5u,
    network_activity = 1u << 6u,
    agent_activity = 1u << 7u,
    security_sensitive = 1u << 8u,
    destructive = 1u << 9u
};

constexpr action_effect_t operator|(action_effect_t lhs, action_effect_t rhs) noexcept {
    return static_cast<action_effect_t>(static_cast<std::uint32_t>(lhs) |
                                        static_cast<std::uint32_t>(rhs));
}

constexpr action_effect_t operator&(action_effect_t lhs, action_effect_t rhs) noexcept {
    return static_cast<action_effect_t>(static_cast<std::uint32_t>(lhs) &
                                        static_cast<std::uint32_t>(rhs));
}

constexpr bool any(action_effect_t value) noexcept {
    return static_cast<std::uint32_t>(value) != 0;
}

enum class confirmation_requirement_t : std::uint8_t {
    none,
    review,
    explicit_confirmation
};

enum class action_check_state_t : std::uint8_t {
    not_checkable,
    unchecked,
    checked,
    mixed
};

enum class action_invocation_source_t : std::uint8_t {
    application_menu,
    activity_bar,
    toolbar,
    command_palette,
    context_menu,
    shortcut,
    accessibility
};

enum class action_execution_status_t : std::uint8_t {
    executed,
    unavailable,
    review_required,
    confirmation_required,
    rejected,
    failed,
    not_found
};

struct action_category_t {
    std::string id;
    std::string display_name;
};

struct action_consequence_t {
    action_effect_t effects = action_effect_t::none;
    confirmation_requirement_t confirmation = confirmation_requirement_t::none;
    std::string summary;
    std::function<std::string(const interaction_context_t&)> target_summary;
};

struct action_state_t {
    capability_state_t capability;
    action_check_state_t check_state = action_check_state_t::not_checkable;
    std::string consequence_summary;
};

struct action_invocation_t {
    const interaction_context_t& context;
    action_invocation_source_t source = action_invocation_source_t::command_palette;
    std::uint64_t invocation_id = 0;
    bool review_completed = false;
    bool confirmation_granted = false;
};

struct action_handler_result_t {
    bool success = true;
    std::string message;

    static action_handler_result_t completed(std::string message = {});
    static action_handler_result_t failed(std::string message);
};

struct action_execution_result_t {
    action_execution_status_t status = action_execution_status_t::not_found;
    stable_action_id_t action;
    std::string message;
    std::string consequence_summary;

    bool executed() const noexcept { return status == action_execution_status_t::executed; }
};

using action_capability_fn_t = std::function<capability_state_t(const interaction_context_t&)>;
using action_check_fn_t = std::function<action_check_state_t(const interaction_context_t&)>;
using action_handler_fn_t = std::function<action_handler_result_t(const action_invocation_t&)>;

struct application_action_descriptor_t {
    stable_action_id_t id;
    std::string label;
    std::string description;
    action_category_t category;
    std::string icon_semantic;
    action_surface_t surfaces = action_surface_t::command_palette;
    std::vector<stable_context_type_id_t> accepted_contexts;
    action_consequence_t consequence;
    action_capability_fn_t capability;
    action_check_fn_t checked;
    action_handler_fn_t invoke;
    bool undoable = false;
    bool reviewable = false;
};

enum class action_registration_error_t : std::uint8_t {
    none,
    invalid_id,
    invalid_label,
    invalid_category,
    missing_surface,
    missing_handler,
    invalid_context_type,
    invalid_consequence,
    duplicate_id
};

struct action_registration_result_t {
    action_registration_error_t error = action_registration_error_t::none;
    std::string detail;

    bool ok() const noexcept { return error == action_registration_error_t::none; }
};

class application_action_registry_t {
public:
    action_registration_result_t register_action(application_action_descriptor_t descriptor);

    const application_action_descriptor_t* find(const stable_action_id_t& id) const noexcept;
    action_state_t evaluate(const stable_action_id_t& id,
                            const interaction_context_t& context) const;
    action_execution_result_t execute(const stable_action_id_t& id,
                                      const action_invocation_t& invocation) const;

    void for_each(const std::function<void(const application_action_descriptor_t&)>& visitor) const;
    std::size_t size() const noexcept { return actions_.size(); }
    std::uint64_t revision() const noexcept { return revision_; }

private:
    static action_registration_result_t validate(const application_action_descriptor_t& descriptor);
    static bool accepts_context(const application_action_descriptor_t& descriptor,
                                const interaction_context_t& context) noexcept;

    std::map<stable_action_id_t, application_action_descriptor_t> actions_;
    std::uint64_t revision_ = 0;
};

}
