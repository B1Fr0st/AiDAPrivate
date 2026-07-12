#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

struct memory_handler_limits_t final {
    std::size_t maximum_batch_items = 4096;
    std::uint64_t maximum_read_bytes_per_item = 1ULL << 20;
    std::uint64_t maximum_read_bytes_per_call = 16ULL << 20;
    std::uint64_t maximum_string_bytes = 1ULL << 20;
    std::size_t maximum_backend_payload_bytes = 64ULL << 20;

    bool valid() const noexcept;
};

struct memory_invocation_t final {
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

class memory_handlers_t final {
public:
    memory_handlers_t(workspace_adapter_t& adapter,
                      protocol::schema_runtime_t& schemas,
                      memory_handler_limits_t limits = {});
    ~memory_handlers_t();

    memory_handlers_t(const memory_handlers_t&) = delete;
    memory_handlers_t& operator=(const memory_handlers_t&) = delete;
    memory_handlers_t(memory_handlers_t&&) noexcept;
    memory_handlers_t& operator=(memory_handlers_t&&) noexcept;

    protocol::mcp_result_t invoke(
        std::string_view tool_name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;

    protocol::mcp_result_t get_bytes(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;
    protocol::mcp_result_t get_int(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;
    protocol::mcp_result_t get_string(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;
    protocol::mcp_result_t get_global_value(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;
    protocol::mcp_result_t patch(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;
    protocol::mcp_result_t put_int(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const memory_invocation_t& invocation = {}) const;

private:
    class impl_t;
    std::unique_ptr<impl_t> impl_;
};

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t get_bytes(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});
protocol::mcp_result_t get_int(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});
protocol::mcp_result_t get_string(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});
protocol::mcp_result_t get_global_value(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});
protocol::mcp_result_t patch(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});
protocol::mcp_result_t put_int(
    handlers::memory_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::memory_invocation_t& invocation = {});

}
