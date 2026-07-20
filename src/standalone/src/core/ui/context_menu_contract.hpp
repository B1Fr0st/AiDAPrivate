#pragma once

#include "application_action_registry.hpp"
#include "shortcut_resolver.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace aida::ui {

enum class context_menu_group_t : std::uint8_t {
    open_navigate,
    modify_run,
    inspect_relate,
    copy_export,
    ai_evidence,
    destructive
};

enum class context_menu_open_origin_t : std::uint8_t {
    pointer,
    menu_key,
    shift_f10,
    accessibility
};

struct context_menu_action_t {
    stable_action_id_t action;
    std::string label_override;
    std::string description_override;
    std::string icon_override;
    std::string shortcut_override;
    stable_action_id_t shortcut_action;
    int order = 0;
};

struct context_menu_section_t {
    stable_menu_section_id_t id;
    std::string label;
    context_menu_group_t group = context_menu_group_t::inspect_relate;
    int order = 0;
    std::vector<context_menu_action_t> actions;
};

struct context_menu_descriptor_t {
    stable_menu_id_t id;
    std::vector<stable_context_type_id_t> accepted_contexts;
    std::vector<context_menu_section_t> sections;
};

struct context_menu_open_request_t {
    stable_menu_id_t menu;
    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    std::uint64_t context_generation = 0;
};

struct context_menu_presented_action_t {
    stable_action_id_t action;
    std::string label;
    std::string description;
    std::string icon_semantic;
    std::string shortcut_hint;
    std::string disabled_reason;
    std::string consequence_summary;
    action_check_state_t check_state = action_check_state_t::not_checkable;
    context_menu_group_t group = context_menu_group_t::inspect_relate;
    int order = 0;
    bool enabled = false;
    bool undoable = false;
    bool reviewable = false;
};

struct context_menu_presented_section_t {
    stable_menu_section_id_t id;
    std::string label;
    context_menu_group_t group = context_menu_group_t::inspect_relate;
    int order = 0;
    std::vector<context_menu_presented_action_t> actions;
};

enum class context_menu_status_t : std::uint8_t {
    ready,
    not_registered,
    invalid_descriptor,
    duplicate_id,
    context_mismatch
};

struct context_menu_presentation_t {
    context_menu_status_t status = context_menu_status_t::ready;
    stable_menu_id_t menu;
    context_menu_open_origin_t origin = context_menu_open_origin_t::pointer;
    std::vector<context_menu_presented_section_t> sections;
    std::string detail;

    bool ready() const noexcept { return status == context_menu_status_t::ready; }
};

struct context_menu_registration_result_t {
    context_menu_status_t status = context_menu_status_t::ready;
    std::string detail;

    bool ok() const noexcept { return status == context_menu_status_t::ready; }
};

class context_menu_catalog_t {
public:
    context_menu_registration_result_t register_menu(context_menu_descriptor_t descriptor,
                                                     const application_action_registry_t& actions);
    const context_menu_descriptor_t* find(const stable_menu_id_t& id) const noexcept;
    void for_each(const std::function<void(const context_menu_descriptor_t&)>& visitor) const;

    std::size_t size() const noexcept { return menus_.size(); }
    std::uint64_t revision() const noexcept { return revision_; }

private:
    static context_menu_registration_result_t validate(
        const context_menu_descriptor_t& descriptor,
        const application_action_registry_t& actions);

    std::map<stable_menu_id_t, context_menu_descriptor_t> menus_;
    std::uint64_t revision_ = 0;
};

class context_menu_presenter_t {
public:
    context_menu_presenter_t(const context_menu_catalog_t& catalog,
                             const application_action_registry_t& actions,
                             const shortcut_resolver_t* shortcuts = nullptr) noexcept;

    context_menu_presentation_t compose(const context_menu_open_request_t& request,
                                        const interaction_context_t& context) const;
    action_execution_result_t execute(const context_menu_open_request_t& request,
                                      const stable_action_id_t& action,
                                      const action_invocation_t& invocation) const;

private:
    const context_menu_catalog_t& catalog_;
    const application_action_registry_t& actions_;
    const shortcut_resolver_t* shortcuts_ = nullptr;
};

}
