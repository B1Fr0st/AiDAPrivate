#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_memory_tool_count = 6;

struct memory_handler_limits_t final {
    std::size_t maximum_batch_items = 4096;
    std::uint64_t maximum_read_bytes_per_item = 1ULL << 20;
    std::uint64_t maximum_read_bytes_per_call = 16ULL << 20;
    std::uint64_t maximum_string_bytes = 1ULL << 20;
    std::size_t maximum_backend_payload_bytes = 64ULL << 20;
    std::size_t maximum_selector_bytes = 1024U;
    std::size_t maximum_address_bytes = 4096U;
    std::size_t maximum_type_bytes = 64U;
    std::size_t maximum_request_bytes = 1024U * 1024U;
    std::size_t maximum_response_bytes = 16U * 1024U * 1024U;
    std::chrono::milliseconds maximum_execution_time{120000};

    bool valid() const noexcept;
};

const std::array<std::string_view, k_memory_tool_count>& memory_tool_names() noexcept;

struct live_memory_identity_t final {
    std::uint64_t target_id = 0;
    std::uint32_t pid = 0;
    std::uint64_t process_creation_identity = 0;
    std::uint64_t module_base = 0;
    std::uint64_t module_size = 0;
    std::uint64_t attach_generation = 0;
};

struct memory_invocation_t final {
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::optional<live_memory_identity_t> expected_live_identity;
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

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const memory_handler_limits_t& limits() const noexcept;

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
