#include "interaction_context.hpp"

namespace aida::ui {

namespace {

bool ascii_alpha(char value) noexcept {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
}

bool ascii_digit(char value) noexcept {
    return value >= '0' && value <= '9';
}

bool ascii_alnum(char value) noexcept {
    return ascii_alpha(value) || ascii_digit(value);
}

bool valid_identifier_body(const std::string& value) noexcept {
    if (value.empty() || value.size() > 192)
        return false;

    bool previous_separator = false;
    for (const char ch : value) {
        const bool separator = ch == '.' || ch == '-' || ch == '_' || ch == '/';
        if (!ascii_alnum(ch) && !separator)
            return false;
        if (separator && previous_separator)
            return false;
        previous_separator = separator;
    }
    return !previous_separator;
}

}

bool is_valid_stable_id(const std::string& value) noexcept {
    return valid_identifier_body(value) && ascii_alpha(value.front());
}

bool is_valid_stable_instance_key(const std::string& value) noexcept {
    return valid_identifier_body(value) && ascii_alnum(value.front());
}

bool is_valid_display_label(const std::string& value) noexcept {
    if (value.empty() || value.size() > 512 || value.find("###") != std::string::npos)
        return false;
    for (const char ch : value) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 && ch != '\t')
            return false;
    }
    return true;
}

typed_context_ref_t::typed_context_ref_t() noexcept
    : runtime_type_(typeid(void)) {}

typed_context_ref_t::typed_context_ref_t(stable_context_type_id_t type_id,
                                         std::type_index runtime_type,
                                         const void* value) noexcept
    : type_id_(std::move(type_id)), runtime_type_(runtime_type), value_(value) {}

const focus_scope_t* interaction_context_t::most_specific_scope() const noexcept {
    return focus_path.empty() ? nullptr : &focus_path.front();
}

const focus_scope_t* interaction_context_t::find_scope(const stable_scope_id_t& id) const noexcept {
    for (const auto& scope : focus_path) {
        if (scope.id == id)
            return &scope;
    }
    return nullptr;
}

bool interaction_context_t::contains_scope_kind(focus_scope_kind_t kind) const noexcept {
    for (const auto& scope : focus_path) {
        if (scope.kind == kind)
            return true;
    }
    return false;
}

capability_state_t capability_state_t::available() {
    return {};
}

capability_state_t capability_state_t::unavailable(std::string reason, bool visible_value) {
    capability_state_t result;
    result.visible = visible_value;
    result.enabled = false;
    result.disabled_reason = std::move(reason);
    if (result.disabled_reason.empty())
        result.disabled_reason = "Unavailable in the current context";
    return result;
}

}
