#pragma once

#include "workspace_adapter.hpp"
#include "../protocol/mcp_tool_contract.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace aida::standalone::mcp::compat {

enum class debugger_adapter_error_code_t : std::uint8_t {
    none,
    unavailable,
    attach_lost,
    pid_reused,
    module_changed,
    attach_generation_stale,
    breakpoint_conflict,
    partial_read,
    partial_write,
    cancelled,
    deadline_exceeded,
    request_rejected,
    invalid_response,
    internal_error,
};

struct debugger_adapter_error_t final {
    debugger_adapter_error_code_t code = debugger_adapter_error_code_t::none;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;

    constexpr explicit operator bool() const noexcept {
        return code != debugger_adapter_error_code_t::none;
    }
};

template <typename value_t>
class debugger_adapter_result_t final {
public:
    static debugger_adapter_result_t success(value_t value) {
        return debugger_adapter_result_t(std::move(value));
    }

    static debugger_adapter_result_t failure(
        debugger_adapter_error_code_t code,
        std::uint64_t expected = 0,
        std::uint64_t actual = 0) noexcept {
        return debugger_adapter_result_t(debugger_adapter_error_t{code, expected, actual});
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

    const debugger_adapter_error_t& error() const noexcept {
        return error_;
    }

private:
    explicit debugger_adapter_result_t(value_t value) : value_(std::move(value)) {}
    explicit debugger_adapter_result_t(debugger_adapter_error_t error) noexcept
        : error_(error) {}

    std::optional<value_t> value_;
    debugger_adapter_error_t error_{};
};

struct debugger_target_identity_t final {
    std::uint32_t pid = 0;
    std::uint64_t process_creation_identity = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::uint64_t attach_generation = 0;
    bool attached = false;
};

struct debugger_adapter_request_t final {
    std::string tool_name;
    protocol::json arguments = protocol::json::object();
    debugger_target_identity_t expected_identity;
    contract_effect_t effect = contract_effect_t::debugger_read;
    protocol::cancellation_token_t cancellation;
    std::chrono::steady_clock::time_point deadline;
};

struct debugger_adapter_response_t final {
    protocol::json structured = protocol::json::object();
    bool truncated = false;
};

class debugger_adapter_t {
public:
    virtual ~debugger_adapter_t() = default;

    virtual debugger_adapter_result_t<debugger_target_identity_t> identity(
        const protocol::cancellation_token_t& cancellation,
        std::chrono::steady_clock::time_point deadline) = 0;
    virtual debugger_adapter_result_t<debugger_adapter_response_t> execute(
        const debugger_adapter_request_t& request) = 0;
};

struct debugger_lane_limits_t final {
    std::chrono::milliseconds maximum_lock_wait{5000};
    std::chrono::milliseconds lock_poll_interval{5};
};

class debugger_lane_t final {
public:
    class invocation_scope_t final {
    public:
        ~invocation_scope_t() noexcept;

        invocation_scope_t(const invocation_scope_t&) = delete;
        invocation_scope_t& operator=(const invocation_scope_t&) = delete;
        invocation_scope_t(invocation_scope_t&&) = delete;
        invocation_scope_t& operator=(invocation_scope_t&&) = delete;

    private:
        friend class debugger_lane_t;

        invocation_scope_t(const debugger_lane_t& owner,
                           const protocol::cancellation_token_t& cancellation);

        const debugger_lane_t* owner_ = nullptr;
        protocol::cancellation_token_t cancellation_;
        const invocation_scope_t* previous_ = nullptr;
        std::thread::id thread_id_;
    };

    explicit debugger_lane_t(debugger_adapter_t& adapter,
                             debugger_lane_limits_t limits = {});

    debugger_lane_t(const debugger_lane_t&) = delete;
    debugger_lane_t& operator=(const debugger_lane_t&) = delete;
    debugger_lane_t(debugger_lane_t&&) = delete;
    debugger_lane_t& operator=(debugger_lane_t&&) = delete;

    invocation_scope_t bind(
        const protocol::cancellation_token_t& cancellation) const;
    adapter_handler_t workspace_handler();

    std::uint64_t completed_requests() const noexcept;
    std::uint64_t peak_concurrency() const noexcept;

private:
    adapter_result_t<adapter_response_t> handle(
        const adapter_call_context_t& context,
        const adapter_request_t& request);
    static adapter_error_t workspace_error(
        debugger_adapter_error_code_t code,
        std::uint64_t expected = 0,
        std::uint64_t actual = 0) noexcept;
    static std::string_view stable_error_code(
        debugger_adapter_error_code_t code) noexcept;
    static bool valid_identity(const debugger_target_identity_t& identity) noexcept;
    static debugger_adapter_error_t compare_identity(
        const debugger_target_identity_t& expected,
        const debugger_target_identity_t& actual) noexcept;
    static bool permits_detach_after(
        std::string_view tool_name,
        const protocol::json& response) noexcept;

    debugger_adapter_t& adapter_;
    debugger_lane_limits_t limits_;
    std::atomic_uint64_t active_requests_{0};
    std::atomic_uint64_t completed_requests_{0};
    std::atomic_uint64_t peak_concurrency_{0};

    static std::timed_mutex global_lane_mutex_;
    static thread_local const invocation_scope_t* active_scope_;
};

}
