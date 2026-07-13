#pragma once

#include "debugger_lane.hpp"
#include "workspace_adapter.hpp"
#include "target_resolver.hpp"
#include "effect_policy.hpp"
#include "../protocol/mcp_tool_contract.hpp"
#include "../../analysis/live_request_budget.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida::standalone::mcp::compat {

enum class live_routing_error_code_t : std::uint8_t {
    none = 0,
    target_not_resolved,
    process_identity_mismatch,
    module_identity_mismatch,
    attach_generation_stale,
    snapshot_budget_exceeded,
    snapshot_cancelled,
    snapshot_deadline_exceeded,
    debugger_lane_busy,
    debugger_lane_serialization_violation,
    static_mutation_blocked_live_write,
    unsupported_live_effect,
    routing_contract_not_found,
    internal_error
};

struct live_routing_error_t final {
    live_routing_error_code_t code = live_routing_error_code_t::none;
    std::string_view stable_code;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr explicit operator bool() const noexcept {
        return code != live_routing_error_code_t::none;
    }
};

template <typename value_t>
class live_routing_result_t final {
public:
    static live_routing_result_t success(value_t value) {
        return live_routing_result_t(std::move(value));
    }

    static live_routing_result_t failure(live_routing_error_t error) noexcept {
        return live_routing_result_t(error);
    }

    bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return has_value(); }
    const value_t& value() const & { return value_.value(); }
    value_t take_value() && { return std::move(value_).value(); }
    const live_routing_error_t& error() const noexcept { return error_; }

private:
    explicit live_routing_result_t(value_t value) : value_(std::move(value)) {}
    explicit live_routing_result_t(live_routing_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    live_routing_error_t error_{};
};

struct live_routing_identity_binding_t final {
    std::uint32_t pid = 0;
    std::uint64_t process_creation_identity = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::uint64_t attach_generation = 0;
    std::uint64_t workspace_generation = 0;
};

struct live_routing_snapshot_request_t final {
    target_selector_t target;
    std::optional<std::uint64_t> expected_generation;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct live_routing_snapshot_result_t final {
    std::vector<std::uint8_t> bytes;
    live_routing_identity_binding_t binding;
    bool truncated = false;
};

struct live_routing_limits_t final {
    std::uint64_t maximum_snapshot_bytes = 1024ULL * 1024ULL;
    std::uint32_t maximum_snapshots_per_request = 64;
    std::chrono::milliseconds maximum_lane_wait{5000};
    std::chrono::milliseconds maximum_snapshot_elapsed{15000};
};

struct live_routing_invocation_context_t final {
    std::string_view contract_name;
    contract_effect_t effect = contract_effect_t::workspace_read;
    protocol::cancellation_token_t cancellation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::optional<std::uint64_t> expected_generation;
};

struct live_routing_dispatch_result_t final {
    protocol::json structured = protocol::json::object();
    bool truncated = false;
    live_routing_identity_binding_t identity;
};

class live_routing_integration_t final {
public:
    live_routing_integration_t(
        target_resolver_t& resolver,
        effect_lock_manager_t& lock_manager,
        debugger_lane_t& debugger_lane,
        live_routing_limits_t limits = {});

    live_routing_integration_t(const live_routing_integration_t&) = delete;
    live_routing_integration_t& operator=(const live_routing_integration_t&) = delete;
    live_routing_integration_t(live_routing_integration_t&&) = delete;
    live_routing_integration_t& operator=(live_routing_integration_t&&) = delete;

    live_routing_result_t<live_routing_identity_binding_t>
        bind_identity(const target_selector_t& selector,
                      std::optional<std::uint64_t> expected_generation = {},
                      const protocol::cancellation_token_t& cancellation = {}) const;

    live_routing_result_t<live_routing_snapshot_result_t>
        capture_bounded_snapshot(const live_routing_snapshot_request_t& request) const;

    live_routing_result_t<live_routing_dispatch_result_t>
        dispatch_debugger(const live_routing_invocation_context_t& context,
                          const protocol::json& arguments) const;

    live_routing_result_t<void>
        verify_static_mutation_safety(std::string_view contract_name,
                                      contract_effect_t effect) const;

    bool is_live_target(const target_selector_t& selector) const;
    std::uint64_t completed_snapshot_requests() const noexcept;
    std::uint64_t completed_debugger_requests() const noexcept;
    std::uint64_t blocked_static_mutations() const noexcept;
    const live_routing_limits_t& limits() const noexcept;

private:
    static live_routing_error_t make_error(live_routing_error_code_t code,
                                           std::uint64_t expected = 0,
                                           std::uint64_t actual = 0) noexcept;
    static bool effect_is_live_write(contract_effect_t effect) noexcept;
    static bool effect_is_static_mutation(contract_effect_t effect) noexcept;
    static bool effect_permits_debugger_lane(contract_effect_t effect) noexcept;
    static live_routing_identity_binding_t
        binding_from_target(const target_record_t& target) noexcept;
    static live_routing_identity_binding_t
        binding_from_debugger(const debugger_target_identity_t& identity) noexcept;
    static bool binding_matches(const live_routing_identity_binding_t& a,
                                const live_routing_identity_binding_t& b) noexcept;

    live_routing_result_t<live_routing_identity_binding_t>
        resolve_and_bind(const target_selector_t& selector,
                         std::optional<std::uint64_t> expected_generation,
                         const protocol::cancellation_token_t& cancellation) const;

    target_resolver_t& resolver_;
    effect_lock_manager_t& lock_manager_;
    debugger_lane_t& debugger_lane_;
    live_routing_limits_t limits_;

    mutable std::atomic_uint64_t completed_snapshots_{0};
    mutable std::atomic_uint64_t completed_debugger_{0};
    mutable std::atomic_uint64_t blocked_mutations_{0};
};

}
