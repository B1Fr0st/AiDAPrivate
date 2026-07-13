#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_survey_tool_count = 1;

struct survey_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_detail_level_bytes = 32U;
    std::chrono::milliseconds max_execution_time{120000};
};

const std::array<std::string_view, k_survey_tool_count>& survey_tool_names() noexcept;

class survey_handlers_t final {
public:
    survey_handlers_t(workspace_adapter_t& workspace,
                      protocol::schema_runtime_t& schemas,
                      survey_handler_limits_t limits = {});

    survey_handlers_t(const survey_handlers_t&) = delete;
    survey_handlers_t& operator=(const survey_handlers_t&) = delete;
    survey_handlers_t(survey_handlers_t&&) = delete;
    survey_handlers_t& operator=(survey_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const survey_handler_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    survey_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_survey_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using survey_adapter_t = protocol::mcp_result_t (*)(
    const handlers::survey_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const protocol::json&);

protocol::mcp_result_t survey_binary(const handlers::survey_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const protocol::json& aida_metadata = protocol::json::object());

}
