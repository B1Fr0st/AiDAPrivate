#pragma once

#include "ida_contracts_generated.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>

namespace aida::standalone::mcp::compat {

enum class effect_lock_mode_t : std::uint8_t {
    shared = 0,
    unique,
    effect
};

enum class effect_policy_error_code_t : std::uint8_t {
    none = 0,
    descriptor_invalid,
    policy_mismatch,
    target_required,
    lock_busy
};

struct effect_policy_error_t final {
    effect_policy_error_code_t code = effect_policy_error_code_t::none;
    std::string_view stable_code;

    constexpr explicit operator bool() const noexcept {
        return code != effect_policy_error_code_t::none;
    }
};

struct effect_lock_policy_t final {
    contract_effect_t effect = contract_effect_t::workspace_read;
    contract_lock_t contract_lock = contract_lock_t::workspace_shared;
    effect_lock_mode_t mode = effect_lock_mode_t::shared;
    bool target_required = true;
    bool mutates_workspace = false;
};

struct effect_policy_resolution_t final {
    std::optional<effect_lock_policy_t> policy;
    effect_policy_error_t error{};

    bool has_value() const noexcept;
    explicit operator bool() const noexcept;
    const effect_lock_policy_t& value() const noexcept;
};

effect_policy_resolution_t effect_policy_for(const contract_descriptor_t& descriptor) noexcept;

struct effect_lock_slot_t;

class effect_lock_lease_t final {
public:
    effect_lock_lease_t() = default;
    effect_lock_lease_t(const effect_lock_lease_t&) = delete;
    effect_lock_lease_t& operator=(const effect_lock_lease_t&) = delete;
    effect_lock_lease_t(effect_lock_lease_t&&) noexcept = default;
    effect_lock_lease_t& operator=(effect_lock_lease_t&&) noexcept = default;

    bool owns_lock() const noexcept;
    const effect_lock_policy_t& policy() const noexcept;
    std::uint64_t target_id() const noexcept;

private:
    friend class effect_lock_manager_t;

    std::shared_ptr<effect_lock_slot_t> slot_;
    std::shared_lock<std::shared_timed_mutex> registry_lock_;
    std::shared_lock<std::shared_timed_mutex> workspace_shared_lock_;
    std::unique_lock<std::shared_timed_mutex> workspace_unique_lock_;
    std::unique_lock<std::timed_mutex> effect_lock_;
    effect_lock_policy_t policy_{};
    std::uint64_t target_id_ = 0;
};

struct effect_lock_acquire_result_t final {
    effect_lock_lease_t lease;
    effect_policy_error_t error{};

    bool has_value() const noexcept;
    explicit operator bool() const noexcept;
};

class effect_lock_manager_t final {
public:
    effect_lock_manager_t() = default;
    effect_lock_manager_t(const effect_lock_manager_t&) = delete;
    effect_lock_manager_t& operator=(const effect_lock_manager_t&) = delete;

    effect_lock_acquire_result_t acquire(
        const effect_lock_policy_t& policy, std::uint64_t target_id,
        std::optional<std::chrono::steady_clock::time_point> deadline = {});
    void forget_target(std::uint64_t target_id);

private:
    static effect_policy_error_t make_error(effect_policy_error_code_t code) noexcept;
    static bool valid_policy(const effect_lock_policy_t& policy) noexcept;
    std::shared_ptr<effect_lock_slot_t> slot_for(std::uint64_t target_id);

    mutable std::mutex slots_mutex_;
    std::unordered_map<std::uint64_t, std::shared_ptr<effect_lock_slot_t>> slots_;
    std::shared_timed_mutex registry_mutex_;
    std::timed_mutex debugger_lane_mutex_;
    std::timed_mutex python_worker_mutex_;
};

}
