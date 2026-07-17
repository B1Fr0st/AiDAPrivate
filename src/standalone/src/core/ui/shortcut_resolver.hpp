#pragma once

#include "application_action_registry.hpp"
#include "imgui/imgui.h"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace aida::ui {

enum class shortcut_binding_source_t : std::uint8_t {
    default_binding,
    user_override
};

enum class shortcut_text_input_policy_t : std::uint8_t {
    suppress,
    allow,
    text_input_only
};

enum class shortcut_modal_policy_t : std::uint8_t {
    suppress_when_modal,
    allow_when_modal,
    modal_only
};

struct shortcut_sequence_t {
    std::vector<ImGuiKeyChord> strokes;
    std::string display_text;

    bool operator==(const shortcut_sequence_t& other) const noexcept {
        return strokes == other.strokes;
    }
};

struct shortcut_binding_t {
    stable_action_binding_id_t id;
    stable_action_id_t action;
    shortcut_sequence_t sequence;
    stable_scope_id_t scope;
    focus_scope_kind_t scope_kind = focus_scope_kind_t::global;
    shortcut_binding_source_t source = shortcut_binding_source_t::default_binding;
    shortcut_text_input_policy_t text_input_policy = shortcut_text_input_policy_t::suppress;
    shortcut_modal_policy_t modal_policy = shortcut_modal_policy_t::suppress_when_modal;
    int priority = 0;
    std::uint32_t chord_timeout_ms = 1000;
    bool allow_repeat = false;
    bool enabled = true;
};

enum class shortcut_registration_error_t : std::uint8_t {
    none,
    invalid_binding_id,
    invalid_action,
    invalid_sequence,
    invalid_scope,
    invalid_timeout,
    duplicate_binding
};

struct shortcut_registration_result_t {
    shortcut_registration_error_t error = shortcut_registration_error_t::none;
    std::string detail;

    bool ok() const noexcept { return error == shortcut_registration_error_t::none; }
};

struct shortcut_conflict_t {
    stable_action_binding_id_t first;
    stable_action_binding_id_t second;
    shortcut_sequence_t sequence;
};

enum class shortcut_resolution_status_t : std::uint8_t {
    none,
    pending_chord,
    resolved,
    unavailable,
    conflict
};

struct shortcut_resolution_t {
    shortcut_resolution_status_t status = shortcut_resolution_status_t::none;
    stable_action_id_t action;
    stable_action_binding_id_t binding;
    std::vector<stable_action_binding_id_t> conflicts;
    std::string detail;

    bool resolved() const noexcept { return status == shortcut_resolution_status_t::resolved; }
};

class shortcut_resolver_t {
public:
    shortcut_registration_result_t register_binding(
        shortcut_binding_t binding,
        const application_action_registry_t& actions);
    shortcut_registration_result_t replace_binding(
        shortcut_binding_t binding,
        const application_action_registry_t& actions);

    shortcut_resolution_t feed(ImGuiKeyChord stroke,
                               bool repeated,
                               std::uint64_t timestamp_ms,
                               const interaction_context_t& context,
                               const application_action_registry_t& actions);
    shortcut_resolution_t poll(std::uint64_t timestamp_ms,
                               const interaction_context_t& context,
                               const application_action_registry_t& actions);
    void cancel_pending() noexcept;

    const shortcut_binding_t* find(const stable_action_binding_id_t& id) const noexcept;
    std::vector<shortcut_conflict_t> conflicts() const;
    std::string effective_hint(const stable_action_id_t& action,
                               const interaction_context_t& context) const;
    void for_each(const std::function<void(const shortcut_binding_t&)>& visitor) const;

    std::size_t size() const noexcept { return bindings_.size(); }
    std::uint64_t revision() const noexcept { return revision_; }

private:
    struct pending_state_t {
        std::vector<stable_action_binding_id_t> candidates;
        std::vector<stable_action_binding_id_t> exact;
        std::size_t matched_strokes = 0;
        std::uint64_t deadline_ms = 0;
        std::uint64_t context_generation = 0;
    };

    static shortcut_registration_result_t validate(
        const shortcut_binding_t& binding,
        const application_action_registry_t& actions);
    bool applies(const shortcut_binding_t& binding,
                 const interaction_context_t& context) const noexcept;
    int specificity(const shortcut_binding_t& binding,
                    const interaction_context_t& context) const noexcept;
    shortcut_resolution_t resolve_exact(
        const std::vector<stable_action_binding_id_t>& candidates,
        const interaction_context_t& context,
        const application_action_registry_t& actions) const;
    shortcut_resolution_t begin_sequence(ImGuiKeyChord stroke,
                                         bool repeated,
                                         std::uint64_t timestamp_ms,
                                         const interaction_context_t& context,
                                         const application_action_registry_t& actions);

    std::map<stable_action_binding_id_t, shortcut_binding_t> bindings_;
    std::optional<pending_state_t> pending_;
    std::uint64_t revision_ = 0;
};

}
