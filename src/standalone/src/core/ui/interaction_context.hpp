#pragma once

#include <cstdint>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <utility>
#include <vector>

namespace aida::ui {

template <typename Tag>
class stable_id_t {
public:
    stable_id_t() = default;
    explicit stable_id_t(std::string value) : value_(std::move(value)) {}

    const std::string& value() const noexcept { return value_; }
    const char* c_str() const noexcept { return value_.c_str(); }
    bool empty() const noexcept { return value_.empty(); }

    friend bool operator==(const stable_id_t& lhs, const stable_id_t& rhs) noexcept {
        return lhs.value_ == rhs.value_;
    }

    friend bool operator!=(const stable_id_t& lhs, const stable_id_t& rhs) noexcept {
        return !(lhs == rhs);
    }

    friend bool operator<(const stable_id_t& lhs, const stable_id_t& rhs) noexcept {
        return lhs.value_ < rhs.value_;
    }

private:
    std::string value_;
};

struct view_id_tag_t;
struct view_instance_key_tag_t;
struct action_id_tag_t;
struct action_binding_id_tag_t;
struct scope_id_tag_t;
struct context_type_id_tag_t;
struct menu_id_tag_t;
struct menu_section_id_tag_t;

using stable_view_id_t = stable_id_t<view_id_tag_t>;
using stable_view_instance_key_t = stable_id_t<view_instance_key_tag_t>;
using stable_action_id_t = stable_id_t<action_id_tag_t>;
using stable_action_binding_id_t = stable_id_t<action_binding_id_tag_t>;
using stable_scope_id_t = stable_id_t<scope_id_tag_t>;
using stable_context_type_id_t = stable_id_t<context_type_id_tag_t>;
using stable_menu_id_t = stable_id_t<menu_id_tag_t>;
using stable_menu_section_id_t = stable_id_t<menu_section_id_tag_t>;

bool is_valid_stable_id(const std::string& value) noexcept;
bool is_valid_stable_instance_key(const std::string& value) noexcept;
bool is_valid_display_label(const std::string& value) noexcept;

enum class focus_scope_kind_t : std::uint8_t {
    global,
    domain,
    document,
    widget,
    table,
    tree,
    canvas,
    text_editor,
    modal
};

struct focus_scope_t {
    stable_scope_id_t id;
    focus_scope_kind_t kind = focus_scope_kind_t::global;
};

class typed_context_ref_t {
public:
    typed_context_ref_t() noexcept;

    template <typename T>
    static typed_context_ref_t from(stable_context_type_id_t type_id, const T& value) noexcept {
        return typed_context_ref_t(std::move(type_id), std::type_index(typeid(T)), &value);
    }

    bool has_value() const noexcept { return value_ != nullptr; }
    const stable_context_type_id_t& type_id() const noexcept { return type_id_; }
    std::type_index runtime_type() const noexcept { return runtime_type_; }

    template <typename T>
    const T* get() const noexcept {
        if (!value_ || runtime_type_ != std::type_index(typeid(T)))
            return nullptr;
        return static_cast<const T*>(value_);
    }

private:
    typed_context_ref_t(stable_context_type_id_t type_id,
                        std::type_index runtime_type,
                        const void* value) noexcept;

    stable_context_type_id_t type_id_;
    std::type_index runtime_type_;
    const void* value_ = nullptr;
};

struct interaction_context_t {
    std::vector<focus_scope_t> focus_path;
    stable_view_id_t active_view;
    stable_view_instance_key_t active_view_instance;
    typed_context_ref_t payload;
    std::uint64_t generation = 0;
    bool modal_active = false;
    bool text_input_active = false;

    const focus_scope_t* most_specific_scope() const noexcept;
    const focus_scope_t* find_scope(const stable_scope_id_t& id) const noexcept;
    bool contains_scope_kind(focus_scope_kind_t kind) const noexcept;
};

struct capability_state_t {
    bool visible = true;
    bool enabled = true;
    std::string disabled_reason;

    static capability_state_t available();
    static capability_state_t unavailable(std::string reason, bool visible = true);
};

}
