#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_core_tool_count = 12;

struct core_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_query_text_bytes = 16384U;
    std::size_t max_batch_queries = 256U;
    std::size_t max_lookup_queries = 1000U;
    std::size_t max_projection_fields = 256U;
    std::size_t max_integer_bytes = 4096U;
    std::uint64_t max_offset = 10000000ULL;
    std::uint64_t max_page_items = 10000ULL;
    std::uint64_t max_regex_matches = 500ULL;
    std::uint64_t max_text_hits = 500ULL;
    std::chrono::milliseconds max_execution_time{120000};
};

struct core_invocation_options_t final {
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

const std::array<std::string_view, k_core_tool_count>& core_tool_names() noexcept;

class core_handlers_t final {
public:
    core_handlers_t(workspace_adapter_t& workspace,
                    protocol::schema_runtime_t& schemas,
                    core_handler_limits_t limits = {});

    core_handlers_t(const core_handlers_t&) = delete;
    core_handlers_t& operator=(const core_handlers_t&) = delete;
    core_handlers_t(core_handlers_t&&) = delete;
    core_handlers_t& operator=(core_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const core_handler_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const core_invocation_options_t& options = {},
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const core_invocation_options_t& options) const;

    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    core_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_core_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using core_adapter_t = protocol::mcp_result_t (*)(
    const handlers::core_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const handlers::core_invocation_options_t&,
    const protocol::json&);

protocol::mcp_result_t server_health(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t lookup_funcs(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t int_convert(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t list_funcs(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t func_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t list_globals(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t entity_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t imports(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t imports_query(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t idb_save(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t find_regex(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t search_text(
    const handlers::core_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::core_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

}
