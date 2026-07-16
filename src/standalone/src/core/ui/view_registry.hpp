#pragma once

#include "interaction_context.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace aida::ui {

enum class view_category_t : std::uint8_t {
    shell,
    explorer,
    document,
    analysis,
    debugger,
    memory,
    types,
    network,
    automation,
    programming,
    output,
    settings
};

enum class view_identity_policy_t : std::uint8_t {
    singleton,
    multi_instance
};

enum class view_presentation_role_t : std::uint8_t {
    tool_window,
    document,
    inspector,
    bottom_panel,
    shell_surface
};

enum class view_render_ownership_t : std::uint8_t {
    registry_window,
    legacy_adapter
};

struct view_minimum_size_t {
    float width = 240.0f;
    float height = 160.0f;
};

struct view_instance_id_t {
    stable_view_id_t view;
    stable_view_instance_key_t instance;

    friend bool operator==(const view_instance_id_t& lhs,
                           const view_instance_id_t& rhs) noexcept {
        return lhs.view == rhs.view && lhs.instance == rhs.instance;
    }

    friend bool operator<(const view_instance_id_t& lhs,
                          const view_instance_id_t& rhs) noexcept {
        if (lhs.view != rhs.view)
            return lhs.view < rhs.view;
        return lhs.instance < rhs.instance;
    }
};

struct view_render_context_t {
    const view_instance_id_t& instance;
    const interaction_context_t& interaction;
};

using view_capability_fn_t = std::function<capability_state_t(const interaction_context_t&)>;
using view_render_fn_t = std::function<void(const view_render_context_t&)>;
using view_lifecycle_fn_t = std::function<void(const view_instance_id_t&)>;

struct view_descriptor_t {
    stable_view_id_t id;
    std::string display_name;
    std::string internal_name;
    view_category_t category = view_category_t::document;
    view_identity_policy_t identity_policy = view_identity_policy_t::singleton;
    view_presentation_role_t role = view_presentation_role_t::tool_window;
    view_render_ownership_t render_ownership = view_render_ownership_t::registry_window;
    view_minimum_size_t minimum_size;
    std::vector<stable_action_id_t> action_bindings;
    view_capability_fn_t capability;
    view_render_fn_t render;
    view_lifecycle_fn_t activate;
    view_lifecycle_fn_t deactivate;
    bool default_open = false;
    bool closeable = true;
};

struct view_instance_state_t {
    view_instance_id_t id;
    std::string display_name;
    std::string window_name;
    bool open = false;
    bool focused = false;
    std::uint64_t focus_request_generation = 0;
    std::uint64_t consumed_focus_generation = 0;
    std::uint64_t last_focus_sequence = 0;
};

enum class view_operation_status_t : std::uint8_t {
    completed,
    not_registered,
    invalid_instance,
    unavailable,
    not_open,
    not_closeable,
    already_registered,
    invalid_descriptor,
    render_failed
};

struct view_operation_result_t {
    view_operation_status_t status = view_operation_status_t::completed;
    std::string detail;

    bool ok() const noexcept { return status == view_operation_status_t::completed; }
};

class view_registry_t {
public:
    view_operation_result_t register_view(view_descriptor_t descriptor);

    const view_descriptor_t* find_descriptor(const stable_view_id_t& id) const noexcept;
    const view_instance_state_t* find_instance(const view_instance_id_t& id) const noexcept;

    capability_state_t evaluate(const stable_view_id_t& id,
                                const interaction_context_t& context) const;
    view_operation_result_t open(const view_instance_id_t& id,
                                 const interaction_context_t& context,
                                 std::string display_name = {});
    view_operation_result_t ensure_identity(const view_instance_id_t& id,
                                            std::string display_name = {});
    view_operation_result_t focus(const view_instance_id_t& id);
    view_operation_result_t open_or_focus(const view_instance_id_t& id,
                                          const interaction_context_t& context,
                                          std::string display_name = {});
    view_operation_result_t close(const view_instance_id_t& id);
    view_operation_result_t reopen_last_closed(const interaction_context_t& context);
    view_operation_result_t open_default_missing(const interaction_context_t& context);
    view_operation_result_t erase_closed_instance(const view_instance_id_t& id);
    view_operation_result_t render(const view_instance_id_t& id,
                                   const interaction_context_t& context) const;

    bool consume_focus_request(const view_instance_id_t& id) noexcept;
    void update_focus(const std::optional<view_instance_id_t>& focused);
    bool is_open(const view_instance_id_t& id) const noexcept;
    bool can_reopen_last_closed() const noexcept { return !closed_history_.empty(); }
    std::optional<view_instance_id_t> focused_instance() const;

    const std::string& window_name(const view_instance_id_t& id) const noexcept;
    void for_each_descriptor(const std::function<void(const view_descriptor_t&)>& visitor) const;
    void for_each_instance(const std::function<void(const view_descriptor_t&,
                                                    const view_instance_state_t&)>& visitor,
                           bool open_only = false) const;

    std::size_t descriptor_count() const noexcept { return descriptors_.size(); }
    std::size_t instance_count() const noexcept { return instances_.size(); }
    std::uint64_t revision() const noexcept { return revision_; }

private:
    static view_operation_result_t validate_descriptor(const view_descriptor_t& descriptor);
    view_operation_result_t validate_instance(const view_descriptor_t& descriptor,
                                              const view_instance_id_t& id) const;
    view_instance_state_t& ensure_instance(const view_descriptor_t& descriptor,
                                           const view_instance_id_t& id,
                                           std::string display_name);
    view_instance_state_t* find_instance(const view_instance_id_t& id) noexcept;
    static std::string compose_window_name(const view_descriptor_t& descriptor,
                                           const view_instance_id_t& id,
                                           const std::string& display_name);

    std::map<stable_view_id_t, view_descriptor_t> descriptors_;
    std::map<view_instance_id_t, view_instance_state_t> instances_;
    std::vector<view_instance_id_t> closed_history_;
    std::optional<view_instance_id_t> focused_instance_;
    std::uint64_t focus_sequence_ = 0;
    std::uint64_t revision_ = 0;
};

}
