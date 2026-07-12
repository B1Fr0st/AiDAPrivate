#include "effect_policy.hpp"

#include <utility>

namespace aida::standalone::mcp::compat {

struct effect_lock_slot_t final {
    std::shared_timed_mutex workspace_mutex;
};

namespace {

std::string_view stable_code_for(effect_policy_error_code_t code) noexcept {
    switch (code) {
    case effect_policy_error_code_t::none:
        return "ok";
    case effect_policy_error_code_t::descriptor_invalid:
        return "effect_descriptor_invalid";
    case effect_policy_error_code_t::policy_mismatch:
        return "effect_policy_mismatch";
    case effect_policy_error_code_t::target_required:
        return "effect_target_required";
    case effect_policy_error_code_t::lock_busy:
        return "effect_lock_busy";
    }
    return "effect_policy_unknown";
}

bool lock_before_deadline(std::shared_timed_mutex& mutex,
                          std::optional<std::chrono::steady_clock::time_point> deadline,
                          std::shared_lock<std::shared_timed_mutex>& lock) {
    if (!deadline || *deadline > std::chrono::steady_clock::now()) {
        lock = deadline ? std::shared_lock<std::shared_timed_mutex>(mutex, std::defer_lock)
                        : std::shared_lock<std::shared_timed_mutex>(mutex);
        if (!deadline) {
            return true;
        }
        return lock.try_lock_until(*deadline);
    }
    lock = std::shared_lock<std::shared_timed_mutex>(mutex, std::defer_lock);
    return lock.try_lock();
}

bool lock_before_deadline(std::shared_timed_mutex& mutex,
                          std::optional<std::chrono::steady_clock::time_point> deadline,
                          std::unique_lock<std::shared_timed_mutex>& lock) {
    if (!deadline || *deadline > std::chrono::steady_clock::now()) {
        lock = deadline ? std::unique_lock<std::shared_timed_mutex>(mutex, std::defer_lock)
                        : std::unique_lock<std::shared_timed_mutex>(mutex);
        if (!deadline) {
            return true;
        }
        return lock.try_lock_until(*deadline);
    }
    lock = std::unique_lock<std::shared_timed_mutex>(mutex, std::defer_lock);
    return lock.try_lock();
}

bool lock_before_deadline(std::timed_mutex& mutex,
                          std::optional<std::chrono::steady_clock::time_point> deadline,
                          std::unique_lock<std::timed_mutex>& lock) {
    if (!deadline || *deadline > std::chrono::steady_clock::now()) {
        lock = deadline ? std::unique_lock<std::timed_mutex>(mutex, std::defer_lock)
                        : std::unique_lock<std::timed_mutex>(mutex);
        if (!deadline) {
            return true;
        }
        return lock.try_lock_until(*deadline);
    }
    lock = std::unique_lock<std::timed_mutex>(mutex, std::defer_lock);
    return lock.try_lock();
}

}

bool effect_policy_resolution_t::has_value() const noexcept {
    return policy.has_value();
}

effect_policy_resolution_t::operator bool() const noexcept {
    return has_value();
}

const effect_lock_policy_t& effect_policy_resolution_t::value() const noexcept {
    return *policy;
}

effect_policy_resolution_t effect_policy_for(const contract_descriptor_t& descriptor) noexcept {
    if (descriptor.name.empty()) {
        return {{}, {effect_policy_error_code_t::descriptor_invalid,
                     stable_code_for(effect_policy_error_code_t::descriptor_invalid)}};
    }

    effect_lock_policy_t policy;
    policy.effect = descriptor.effect;
    policy.contract_lock = descriptor.lock;
    policy.target_required = descriptor.target_dependent;
    switch (descriptor.effect) {
    case contract_effect_t::workspace_read:
        policy.mode = effect_lock_mode_t::shared;
        policy.contract_lock = contract_lock_t::workspace_shared;
        break;
    case contract_effect_t::workspace_checkpoint:
        policy.mode = effect_lock_mode_t::unique;
        policy.contract_lock = contract_lock_t::workspace_checkpoint;
        policy.mutates_workspace = true;
        break;
    case contract_effect_t::workspace_overlay_mutation:
        policy.mode = effect_lock_mode_t::unique;
        policy.contract_lock = contract_lock_t::workspace_overlay_transaction;
        policy.mutates_workspace = true;
        break;
    case contract_effect_t::debugger_read:
    case contract_effect_t::debugger_control:
    case contract_effect_t::debugger_write:
        policy.mode = effect_lock_mode_t::effect;
        policy.contract_lock = contract_lock_t::debugger_lane;
        break;
    case contract_effect_t::isolated_python:
        policy.mode = effect_lock_mode_t::effect;
        policy.contract_lock = contract_lock_t::python_worker;
        break;
    case contract_effect_t::registry_read:
        policy.mode = effect_lock_mode_t::shared;
        policy.contract_lock = contract_lock_t::registry_read;
        policy.target_required = false;
        break;
    }
    if (descriptor.lock != policy.contract_lock) {
        return {{}, {effect_policy_error_code_t::policy_mismatch,
                     stable_code_for(effect_policy_error_code_t::policy_mismatch)}};
    }
    if (descriptor.target_dependent != policy.target_required) {
        return {{}, {effect_policy_error_code_t::policy_mismatch,
                     stable_code_for(effect_policy_error_code_t::policy_mismatch)}};
    }
    return {policy, {}};
}

bool effect_lock_lease_t::owns_lock() const noexcept {
    return registry_lock_.owns_lock() || workspace_shared_lock_.owns_lock() ||
        workspace_unique_lock_.owns_lock() || effect_lock_.owns_lock();
}

const effect_lock_policy_t& effect_lock_lease_t::policy() const noexcept {
    return policy_;
}

std::uint64_t effect_lock_lease_t::target_id() const noexcept {
    return target_id_;
}

bool effect_lock_acquire_result_t::has_value() const noexcept {
    return lease.owns_lock();
}

effect_lock_acquire_result_t::operator bool() const noexcept {
    return has_value();
}

effect_policy_error_t effect_lock_manager_t::make_error(effect_policy_error_code_t code) noexcept {
    return {code, stable_code_for(code)};
}

bool effect_lock_manager_t::valid_policy(const effect_lock_policy_t& policy) noexcept {
    switch (policy.effect) {
    case contract_effect_t::workspace_read:
        return policy.mode == effect_lock_mode_t::shared &&
            policy.contract_lock == contract_lock_t::workspace_shared &&
            !policy.mutates_workspace;
    case contract_effect_t::workspace_checkpoint:
        return policy.mode == effect_lock_mode_t::unique && policy.target_required &&
            policy.contract_lock == contract_lock_t::workspace_checkpoint && policy.mutates_workspace;
    case contract_effect_t::workspace_overlay_mutation:
        return policy.mode == effect_lock_mode_t::unique && policy.target_required &&
            policy.contract_lock == contract_lock_t::workspace_overlay_transaction &&
            policy.mutates_workspace;
    case contract_effect_t::debugger_read:
    case contract_effect_t::debugger_control:
    case contract_effect_t::debugger_write:
        return policy.mode == effect_lock_mode_t::effect && policy.target_required &&
            policy.contract_lock == contract_lock_t::debugger_lane && !policy.mutates_workspace;
    case contract_effect_t::isolated_python:
        return policy.mode == effect_lock_mode_t::effect && policy.target_required &&
            policy.contract_lock == contract_lock_t::python_worker && !policy.mutates_workspace;
    case contract_effect_t::registry_read:
        return policy.mode == effect_lock_mode_t::shared && !policy.target_required &&
            policy.contract_lock == contract_lock_t::registry_read && !policy.mutates_workspace;
    }
    return false;
}

std::shared_ptr<effect_lock_slot_t> effect_lock_manager_t::slot_for(std::uint64_t target_id) {
    std::lock_guard lock(slots_mutex_);
    auto [iterator, inserted] = slots_.try_emplace(target_id, std::make_shared<effect_lock_slot_t>());
    return iterator->second;
}

effect_lock_acquire_result_t effect_lock_manager_t::acquire(
    const effect_lock_policy_t& policy, std::uint64_t target_id,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!valid_policy(policy)) {
        return {{}, make_error(effect_policy_error_code_t::policy_mismatch)};
    }
    if (policy.target_required && target_id == 0) {
        return {{}, make_error(effect_policy_error_code_t::target_required)};
    }

    effect_lock_lease_t lease;
    lease.policy_ = policy;
    lease.target_id_ = target_id;
    bool locked = false;
    if (!policy.target_required) {
        locked = lock_before_deadline(registry_mutex_, deadline, lease.registry_lock_);
    } else {
        switch (policy.mode) {
        case effect_lock_mode_t::shared:
            lease.slot_ = slot_for(target_id);
            locked = lock_before_deadline(lease.slot_->workspace_mutex, deadline,
                                          lease.workspace_shared_lock_);
            break;
        case effect_lock_mode_t::unique:
            lease.slot_ = slot_for(target_id);
            locked = lock_before_deadline(lease.slot_->workspace_mutex, deadline,
                                          lease.workspace_unique_lock_);
            break;
        case effect_lock_mode_t::effect:
            if (policy.contract_lock == contract_lock_t::debugger_lane) {
                locked = lock_before_deadline(debugger_lane_mutex_, deadline, lease.effect_lock_);
            } else if (policy.contract_lock == contract_lock_t::python_worker) {
                locked = lock_before_deadline(python_worker_mutex_, deadline, lease.effect_lock_);
            }
            break;
        }
    }
    if (!locked) {
        return {{}, make_error(effect_policy_error_code_t::lock_busy)};
    }
    return {std::move(lease), {}};
}

void effect_lock_manager_t::forget_target(std::uint64_t target_id) {
    if (target_id == 0) {
        return;
    }
    std::lock_guard lock(slots_mutex_);
    const auto iterator = slots_.find(target_id);
    if (iterator != slots_.end() && iterator->second.use_count() == 1) {
        slots_.erase(iterator);
    }
}

}
