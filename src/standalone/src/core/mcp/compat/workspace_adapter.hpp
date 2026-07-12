#pragma once

#include "effect_policy.hpp"
#include "target_resolver.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat {

enum class adapter_error_code_t : std::uint8_t {
    none = 0,
    invalid_request,
    contract_not_found,
    operation_not_permitted,
    target_resolution_failed,
    effect_policy_failed,
    effect_lock_busy,
    backend_unavailable,
    backend_rejected,
    live_snapshot_denied,
    live_snapshot_bounds,
    live_snapshot_invalid
};

struct adapter_error_t final {
    adapter_error_code_t code = adapter_error_code_t::none;
    std::string_view stable_code;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr explicit operator bool() const noexcept {
        return code != adapter_error_code_t::none;
    }
};

template <typename value_t>
class adapter_result_t final {
public:
    static adapter_result_t success(value_t value) {
        return adapter_result_t(std::move(value));
    }

    static adapter_result_t failure(adapter_error_t error) noexcept {
        return adapter_result_t(error);
    }

    bool has_value() const noexcept {
        return value_.has_value();
    }

    explicit operator bool() const noexcept {
        return has_value();
    }

    const value_t& value() const & {
        return value_.value();
    }

    value_t take_value() && {
        return std::move(value_).value();
    }

    const adapter_error_t& error() const noexcept {
        return error_;
    }

private:
    explicit adapter_result_t(value_t value) : value_(std::move(value)) {}
    explicit adapter_result_t(adapter_error_t error) noexcept : error_(error) {}

    std::optional<value_t> value_;
    adapter_error_t error_{};
};

enum class adapter_operation_t : std::uint8_t {
    query = 0,
    overlay,
    analysis,
    decompilation,
    checkpoint,
    debugger,
    isolated_python
};

struct adapter_request_t final {
    target_selector_t target;
    std::optional<std::uint64_t> expected_generation;
    std::string payload;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct adapter_response_t final {
    std::string payload;
    bool truncated = false;
};

struct adapter_call_context_t final {
    const contract_descriptor_t* contract = nullptr;
    std::optional<target_resolution_t> target;
    effect_lock_policy_t effect;
};

struct bounded_live_snapshot_request_t final {
    target_selector_t target;
    std::optional<std::uint64_t> expected_generation;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct bounded_live_snapshot_t final {
    std::vector<std::uint8_t> bytes;
    std::uint64_t process_creation_identity = 0;
    std::uint64_t attach_generation = 0;
    std::uint64_t generation = 0;
};

struct live_snapshot_limits_t final {
    std::uint64_t maximum_bytes = 1024ULL * 1024ULL;
};

using adapter_handler_t = std::function<adapter_result_t<adapter_response_t>(
    const adapter_call_context_t&, const adapter_request_t&)>;
using live_snapshot_handler_t = std::function<adapter_result_t<bounded_live_snapshot_t>(
    const adapter_call_context_t&, const bounded_live_snapshot_request_t&)>;

struct workspace_adapter_handlers_t final {
    adapter_handler_t query;
    adapter_handler_t overlay;
    adapter_handler_t analysis;
    adapter_handler_t decompilation;
    adapter_handler_t checkpoint;
    adapter_handler_t debugger;
    adapter_handler_t isolated_python;
    live_snapshot_handler_t live_snapshot;
};

class workspace_adapter_t final {
public:
    workspace_adapter_t(target_resolver_t& resolver, effect_lock_manager_t& lock_manager,
                        workspace_adapter_handlers_t handlers,
                        live_snapshot_limits_t live_snapshot_limits = {});

    adapter_result_t<adapter_response_t> execute(
        std::string_view contract_name, adapter_operation_t operation,
        const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> query(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> overlay(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> analyze(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> decompile(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> checkpoint(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> debug(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<adapter_response_t> execute_isolated_python(
        std::string_view contract_name, const adapter_request_t& request) const;
    adapter_result_t<bounded_live_snapshot_t> capture_live_snapshot(
        const bounded_live_snapshot_request_t& request) const;
    std::vector<target_record_t> list_targets() const;

private:
    static adapter_error_t make_error(adapter_error_code_t code, std::uint64_t expected = 0,
                                      std::uint64_t actual = 0) noexcept;
    static adapter_error_t from_target_error(const target_resolution_error_t& error) noexcept;
    static adapter_error_t from_effect_error(const effect_policy_error_t& error) noexcept;
    static bool operation_accepts(adapter_operation_t operation,
                                  contract_effect_t effect) noexcept;
    static bool request_has_target_selector(const adapter_request_t& request) noexcept;
    static bool live_range_contains(const target_record_t& target, std::uint64_t address,
                                    std::uint64_t size) noexcept;
    const adapter_handler_t* handler_for(adapter_operation_t operation) const noexcept;

    target_resolver_t& resolver_;
    effect_lock_manager_t& lock_manager_;
    workspace_adapter_handlers_t handlers_;
    live_snapshot_limits_t live_snapshot_limits_;
};

}
