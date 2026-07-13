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

inline constexpr std::size_t k_modify_tool_count = 11;

struct modify_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_address_bytes = 4096U;
    std::size_t max_batch_items = 4096U;
    std::size_t max_comment_bytes = 4096U;
    std::size_t max_data_bytes = 1024U * 1024U;
    std::size_t max_type_bytes = 4096U;
    std::size_t max_asm_bytes = 4096U;
    std::size_t max_rename_batch_items = 4096U;
    std::size_t max_name_bytes = 4096U;
    std::size_t max_op_kind_bytes = 64U;
    std::chrono::milliseconds max_execution_time{60000};
};

struct modify_invocation_options_t final {
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

const std::array<std::string_view, k_modify_tool_count>& modify_tool_names() noexcept;

class modify_handlers_t final {
public:
    modify_handlers_t(workspace_adapter_t& workspace,
                      protocol::schema_runtime_t& schemas,
                      modify_handler_limits_t limits = {});

    modify_handlers_t(const modify_handlers_t&) = delete;
    modify_handlers_t& operator=(const modify_handlers_t&) = delete;
    modify_handlers_t(modify_handlers_t&&) = delete;
    modify_handlers_t& operator=(modify_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const modify_handler_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const modify_invocation_options_t& options = {},
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const modify_invocation_options_t& options) const;

    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    modify_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_modify_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using modify_adapter_t = protocol::mcp_result_t (*)(
    const handlers::modify_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const handlers::modify_invocation_options_t&,
    const protocol::json&);

protocol::mcp_result_t add_bookmark(
    const handlers::modify_handlers_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::modify_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t set_comments(const handlers::modify_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const handlers::modify_invocation_options_t& options = {},
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t append_comments(const handlers::modify_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const handlers::modify_invocation_options_t& options = {},
                                       const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t rename(const handlers::modify_handlers_t& handlers,
                              const protocol::json& arguments,
                              const protocol::cancellation_token_t& cancellation,
                              const handlers::modify_invocation_options_t& options = {},
                              const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t define_code(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::modify_invocation_options_t& options = {},
                                   const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t define_func(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::modify_invocation_options_t& options = {},
                                   const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t undefine(const handlers::modify_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const handlers::modify_invocation_options_t& options = {},
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t make_data(const handlers::modify_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::modify_invocation_options_t& options = {},
                                 const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t patch_asm(const handlers::modify_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::modify_invocation_options_t& options = {},
                                 const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t force_recompile(const handlers::modify_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const handlers::modify_invocation_options_t& options = {},
                                       const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t set_op_type(const handlers::modify_handlers_t& handlers,
                                   const protocol::json& arguments,
                                   const protocol::cancellation_token_t& cancellation,
                                   const handlers::modify_invocation_options_t& options = {},
                                   const protocol::json& aida_metadata = protocol::json::object());

}
