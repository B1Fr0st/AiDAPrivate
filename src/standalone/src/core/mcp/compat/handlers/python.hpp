#pragma once

#include "../python_worker_host.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_python_tool_count = 1;

struct python_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_script_path_bytes = 4096U;
    std::size_t max_workspace_metadata_bytes = 64U * 1024U;
    std::size_t max_result_bytes = 256U * 1024U;
    std::chrono::milliseconds max_execution_time{30000};
};

using python_worker_execute_t = std::function<python_worker_execution_result_t(
    const python_worker_execution_request_t&)>;

const std::array<std::string_view, k_python_tool_count>& python_tool_names() noexcept;

class python_handlers_t final {
public:
    python_handlers_t(python_worker_execute_t executor,
                      protocol::schema_runtime_t& schemas,
                      python_handler_limits_t limits = {});

    python_handlers_t(const python_handlers_t&) = delete;
    python_handlers_t& operator=(const python_handlers_t&) = delete;
    python_handlers_t(python_handlers_t&&) = delete;
    python_handlers_t& operator=(python_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const python_handler_limits_t& limits() const noexcept;

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

    python_worker_execute_t executor_;
    protocol::schema_runtime_t& schemas_;
    python_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_python_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using python_adapter_t = protocol::mcp_result_t (*)(
    const handlers::python_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const protocol::json&);

protocol::mcp_result_t py_exec_file(const handlers::python_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());

}
