#include "shortcut_resolver.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <tuple>
#include <utility>

namespace aida::ui {

namespace {

constexpr std::size_t k_maximum_chord_strokes = 4;
constexpr std::uint32_t k_minimum_chord_timeout_ms = 200;
constexpr std::uint32_t k_maximum_chord_timeout_ms = 5000;

bool valid_stroke(ImGuiKeyChord stroke) noexcept {
    const auto key = stroke & ~ImGuiMod_Mask_;
    return key >= ImGuiKey_Tab && key < ImGuiKey_GamepadStart &&
           key != ImGuiKey_LeftCtrl && key != ImGuiKey_RightCtrl &&
           key != ImGuiKey_LeftShift && key != ImGuiKey_RightShift &&
           key != ImGuiKey_LeftAlt && key != ImGuiKey_RightAlt &&
           key != ImGuiKey_LeftSuper && key != ImGuiKey_RightSuper;
}

bool scopes_can_overlap(const shortcut_binding_t& lhs,
                        const shortcut_binding_t& rhs) noexcept {
    return lhs.scope_kind == rhs.scope_kind && lhs.scope == rhs.scope;
}

bool policies_can_overlap(const shortcut_binding_t& lhs,
                          const shortcut_binding_t& rhs) noexcept {
    if ((lhs.modal_policy == shortcut_modal_policy_t::modal_only &&
         rhs.modal_policy == shortcut_modal_policy_t::suppress_when_modal) ||
        (rhs.modal_policy == shortcut_modal_policy_t::modal_only &&
         lhs.modal_policy == shortcut_modal_policy_t::suppress_when_modal))
        return false;
    if ((lhs.text_input_policy == shortcut_text_input_policy_t::text_input_only &&
         rhs.text_input_policy == shortcut_text_input_policy_t::suppress) ||
        (rhs.text_input_policy == shortcut_text_input_policy_t::text_input_only &&
         lhs.text_input_policy == shortcut_text_input_policy_t::suppress))
        return false;
    return true;
}

std::uint64_t deadline_from(std::uint64_t timestamp_ms, std::uint32_t timeout_ms) noexcept {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    if (timestamp_ms > maximum - timeout_ms)
        return maximum;
    return timestamp_ms + timeout_ms;
}

}

shortcut_registration_result_t shortcut_resolver_t::validate(
    const shortcut_binding_t& binding,
    const application_action_registry_t& actions) {
    if (!is_valid_stable_id(binding.id.value()))
        return {shortcut_registration_error_t::invalid_binding_id,
                "Shortcut binding ID is not stable"};
    const auto* action = actions.find(binding.action);
    if (!action || !any(action->surfaces & action_surface_t::shortcut))
        return {shortcut_registration_error_t::invalid_action,
                "Shortcut action is not registered for the shortcut surface"};
    if (binding.sequence.strokes.empty() ||
        binding.sequence.strokes.size() > k_maximum_chord_strokes ||
        !is_valid_display_label(binding.sequence.display_text))
        return {shortcut_registration_error_t::invalid_sequence,
                "Shortcut sequence is invalid"};
    for (const auto stroke : binding.sequence.strokes) {
        if (!valid_stroke(stroke))
            return {shortcut_registration_error_t::invalid_sequence,
                    "Shortcut sequence contains an invalid stroke"};
    }
    if (binding.scope_kind != focus_scope_kind_t::global &&
        !is_valid_stable_id(binding.scope.value()))
        return {shortcut_registration_error_t::invalid_scope,
                "Scoped shortcut requires a stable scope ID"};
    if (binding.scope_kind == focus_scope_kind_t::global && !binding.scope.empty())
        return {shortcut_registration_error_t::invalid_scope,
                "Global shortcut cannot carry a scoped ID"};
    if (binding.chord_timeout_ms < k_minimum_chord_timeout_ms ||
        binding.chord_timeout_ms > k_maximum_chord_timeout_ms)
        return {shortcut_registration_error_t::invalid_timeout,
                "Shortcut chord timeout is outside the supported range"};
    return {};
}

shortcut_registration_result_t shortcut_resolver_t::register_binding(
    shortcut_binding_t binding,
    const application_action_registry_t& actions) {
    auto validation = validate(binding, actions);
    if (!validation.ok())
        return validation;
    if (bindings_.find(binding.id) != bindings_.end())
        return {shortcut_registration_error_t::duplicate_binding,
                "Shortcut binding ID is already registered"};
    bindings_.emplace(binding.id, std::move(binding));
    ++revision_;
    return {};
}

shortcut_registration_result_t shortcut_resolver_t::replace_binding(
    shortcut_binding_t binding,
    const application_action_registry_t& actions) {
    auto validation = validate(binding, actions);
    if (!validation.ok())
        return validation;
    const auto found = bindings_.find(binding.id);
    if (found == bindings_.end())
        return {shortcut_registration_error_t::invalid_binding_id,
            "Shortcut binding is not registered"};
    found->second = std::move(binding);
    pending_.reset();
    ++revision_;
    return {};
}

const shortcut_binding_t* shortcut_resolver_t::find(
    const stable_action_binding_id_t& id) const noexcept {
    const auto found = bindings_.find(id);
    return found == bindings_.end() ? nullptr : &found->second;
}

bool shortcut_resolver_t::applies(const shortcut_binding_t& binding,
                                  const interaction_context_t& context) const noexcept {
    if (!binding.enabled)
        return false;
    if (context.modal_active) {
        if (binding.modal_policy == shortcut_modal_policy_t::suppress_when_modal)
            return false;
    } else if (binding.modal_policy == shortcut_modal_policy_t::modal_only) {
        return false;
    }
    if (context.text_input_active) {
        if (binding.text_input_policy == shortcut_text_input_policy_t::suppress)
            return false;
    } else if (binding.text_input_policy == shortcut_text_input_policy_t::text_input_only) {
        return false;
    }
    if (binding.scope_kind == focus_scope_kind_t::global)
        return true;
    const auto* scope = context.find_scope(binding.scope);
    return scope && scope->kind == binding.scope_kind;
}

int shortcut_resolver_t::specificity(const shortcut_binding_t& binding,
                                     const interaction_context_t& context) const noexcept {
    if (binding.scope_kind == focus_scope_kind_t::global)
        return 0;
    for (std::size_t index = 0; index < context.focus_path.size(); ++index) {
        const auto& scope = context.focus_path[index];
        if (scope.id == binding.scope && scope.kind == binding.scope_kind) {
            const auto bounded = static_cast<int>((std::min)(index,
                static_cast<std::size_t>(std::numeric_limits<int>::max() / 2)));
            return std::numeric_limits<int>::max() / 2 - bounded;
        }
    }
    return -1;
}

shortcut_resolution_t shortcut_resolver_t::resolve_exact(
    const std::vector<stable_action_binding_id_t>& candidates,
    const interaction_context_t& context,
    const application_action_registry_t& actions) const {
    struct ranked_t {
        const shortcut_binding_t* binding = nullptr;
        int specificity = -1;
        int priority = 0;
        int source = 0;
        action_state_t state;
    };

    std::vector<ranked_t> ranked;
    ranked.reserve(candidates.size());
    for (const auto& id : candidates) {
        const auto* binding = find(id);
        if (!binding || !applies(*binding, context))
            continue;
        auto state = actions.evaluate(binding->action, context);
        if (!state.capability.visible)
            continue;
        ranked.push_back({binding,
                          specificity(*binding, context),
                          binding->priority,
                          binding->source == shortcut_binding_source_t::user_override ? 1 : 0,
                          std::move(state)});
    }
    if (ranked.empty())
        return {};

    const auto compare = [](const ranked_t& lhs, const ranked_t& rhs) {
        const bool lhs_available = lhs.state.capability.enabled;
        const bool rhs_available = rhs.state.capability.enabled;
        return std::tie(lhs_available, lhs.specificity, lhs.source, lhs.priority) >
               std::tie(rhs_available, rhs.specificity, rhs.source, rhs.priority);
    };
    std::sort(ranked.begin(), ranked.end(), compare);

    const auto& best = ranked.front();
    const bool best_available = best.state.capability.enabled;
    if (!best_available) {
        shortcut_resolution_t result;
        result.status = shortcut_resolution_status_t::unavailable;
        result.action = best.binding->action;
        result.binding = best.binding->id;
        result.detail = best.state.capability.disabled_reason;
        return result;
    }

    std::vector<stable_action_binding_id_t> tied;
    for (const auto& candidate : ranked) {
        const bool available = candidate.state.capability.enabled;
        if (!available || candidate.specificity != best.specificity ||
            candidate.priority != best.priority || candidate.source != best.source)
            break;
        tied.push_back(candidate.binding->id);
    }
    if (tied.size() > 1) {
        shortcut_resolution_t result;
        result.status = shortcut_resolution_status_t::conflict;
        result.conflicts = std::move(tied);
        result.detail = "Shortcut has multiple equally ranked actions";
        return result;
    }

    shortcut_resolution_t result;
    result.status = shortcut_resolution_status_t::resolved;
    result.action = best.binding->action;
    result.binding = best.binding->id;
    return result;
}

shortcut_resolution_t shortcut_resolver_t::begin_sequence(
    ImGuiKeyChord stroke,
    bool repeated,
    std::uint64_t timestamp_ms,
    const interaction_context_t& context,
    const application_action_registry_t& actions) {
    std::vector<stable_action_binding_id_t> candidates;
    std::vector<stable_action_binding_id_t> exact;
    std::uint32_t timeout = k_maximum_chord_timeout_ms;
    bool has_longer = false;

    for (const auto& entry : bindings_) {
        const auto& binding = entry.second;
        if (!applies(binding, context) ||
            (repeated && !binding.allow_repeat) ||
            binding.sequence.strokes.front() != stroke)
            continue;
        candidates.push_back(binding.id);
        timeout = (std::min)(timeout, binding.chord_timeout_ms);
        if (binding.sequence.strokes.size() == 1)
            exact.push_back(binding.id);
        else
            has_longer = true;
    }
    if (candidates.empty())
        return {};
    if (!has_longer)
        return resolve_exact(exact, context, actions);

    pending_state_t state;
    state.candidates = std::move(candidates);
    state.exact = std::move(exact);
    state.matched_strokes = 1;
    state.deadline_ms = deadline_from(timestamp_ms, timeout);
    state.context_generation = context.generation;
    pending_ = std::move(state);
    shortcut_resolution_t result;
    result.status = shortcut_resolution_status_t::pending_chord;
    return result;
}

shortcut_resolution_t shortcut_resolver_t::feed(
    ImGuiKeyChord stroke,
    bool repeated,
    std::uint64_t timestamp_ms,
    const interaction_context_t& context,
    const application_action_registry_t& actions) {
    if (!valid_stroke(stroke))
        return {};
    if (pending_ && (pending_->context_generation != context.generation ||
                     timestamp_ms > pending_->deadline_ms))
        pending_.reset();
    if (!pending_)
        return begin_sequence(stroke, repeated, timestamp_ms, context, actions);

    std::vector<stable_action_binding_id_t> next;
    std::vector<stable_action_binding_id_t> exact;
    std::uint32_t timeout = k_maximum_chord_timeout_ms;
    bool has_longer = false;
    for (const auto& id : pending_->candidates) {
        const auto* binding = find(id);
        if (!binding || !applies(*binding, context) ||
            (repeated && !binding->allow_repeat) ||
            binding->sequence.strokes.size() <= pending_->matched_strokes ||
            binding->sequence.strokes[pending_->matched_strokes] != stroke)
            continue;
        next.push_back(id);
        timeout = (std::min)(timeout, binding->chord_timeout_ms);
        if (binding->sequence.strokes.size() == pending_->matched_strokes + 1)
            exact.push_back(id);
        else
            has_longer = true;
    }
    if (next.empty()) {
        pending_.reset();
        return begin_sequence(stroke, repeated, timestamp_ms, context, actions);
    }
    if (!has_longer) {
        pending_.reset();
        return resolve_exact(exact, context, actions);
    }

    pending_->candidates = std::move(next);
    pending_->exact = std::move(exact);
    ++pending_->matched_strokes;
    pending_->deadline_ms = deadline_from(timestamp_ms, timeout);
    shortcut_resolution_t result;
    result.status = shortcut_resolution_status_t::pending_chord;
    return result;
}

shortcut_resolution_t shortcut_resolver_t::poll(
    std::uint64_t timestamp_ms,
    const interaction_context_t& context,
    const application_action_registry_t& actions) {
    if (!pending_)
        return {};
    if (pending_->context_generation != context.generation) {
        pending_.reset();
        return {};
    }
    if (timestamp_ms <= pending_->deadline_ms) {
        shortcut_resolution_t result;
        result.status = shortcut_resolution_status_t::pending_chord;
        return result;
    }
    auto exact = std::move(pending_->exact);
    pending_.reset();
    return resolve_exact(exact, context, actions);
}

void shortcut_resolver_t::cancel_pending() noexcept {
    pending_.reset();
}

std::vector<shortcut_conflict_t> shortcut_resolver_t::conflicts() const {
    std::vector<shortcut_conflict_t> result;
    for (auto left = bindings_.begin(); left != bindings_.end(); ++left) {
        if (!left->second.enabled)
            continue;
        for (auto right = std::next(left); right != bindings_.end(); ++right) {
            if (!right->second.enabled ||
                !(left->second.sequence == right->second.sequence) ||
                left->second.action == right->second.action ||
                !scopes_can_overlap(left->second, right->second) ||
                !policies_can_overlap(left->second, right->second))
                continue;
            result.push_back({left->first, right->first, left->second.sequence});
        }
    }
    return result;
}

std::string shortcut_resolver_t::effective_hint(
    const stable_action_id_t& action,
    const interaction_context_t& context) const {
    const shortcut_binding_t* best = nullptr;
    int best_specificity = -1;
    for (const auto& entry : bindings_) {
        const auto& binding = entry.second;
        if (binding.action != action || !applies(binding, context))
            continue;
        const int candidate_specificity = specificity(binding, context);
        if (!best || candidate_specificity > best_specificity ||
            (candidate_specificity == best_specificity &&
             binding.source == shortcut_binding_source_t::user_override &&
             best->source != shortcut_binding_source_t::user_override) ||
            (candidate_specificity == best_specificity && binding.source == best->source &&
             binding.priority > best->priority)) {
            best = &binding;
            best_specificity = candidate_specificity;
        }
    }
    return best ? best->sequence.display_text : std::string{};
}

void shortcut_resolver_t::for_each(
    const std::function<void(const shortcut_binding_t&)>& visitor) const {
    if (!visitor)
        return;
    for (const auto& entry : bindings_)
        visitor(entry.second);
}

}
