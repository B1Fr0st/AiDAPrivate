#pragma once

#include "../debugger_lane.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_debugger_tool_count = 22;

struct debugger_handler_limits_t final {
    std::size_t max_request_bytes = 256U * 1024U;
    std::size_t max_response_bytes = 4U * 1024U * 1024U;
    std::size_t max_selector_bytes = 512;
    std::size_t max_address_bytes = 32;
    std::size_t max_register_name_bytes = 64;
    std::size_t max_register_value_bytes = 512;
    std::size_t max_condition_bytes = 4096;
    std::size_t max_language_bytes = 64;
    std::size_t max_symbol_bytes = 4096;
    std::size_t max_breakpoints = 256;
    std::size_t max_threads = 64;
    std::size_t max_registers_per_thread = 256;
    std::size_t max_stack_frames = 512;
    std::size_t max_read_regions = 64;
    std::size_t max_read_bytes_per_region = 64U * 1024U;
    std::size_t max_read_bytes_total = 1024U * 1024U;
    std::size_t max_write_regions = 32;
    std::size_t max_write_bytes_per_region = 4U * 1024U;
    std::size_t max_write_bytes_total = 64U * 1024U;
    std::size_t max_approval_source_bytes = 128;
    std::chrono::milliseconds max_execution_time{15000};
};

struct debugger_effect_approval_t final {
    bool granted = false;
    std::uint64_t approval_id = 0;
    std::string source;
};

const std::array<std::string_view, k_debugger_tool_count>& debugger_tool_names() noexcept;

class debugger_handlers_t final {
public:
    debugger_handlers_t(workspace_adapter_t& workspace,
                        debugger_lane_t& lane,
                        protocol::schema_runtime_t& schemas,
                        debugger_handler_limits_t limits = {});

    debugger_handlers_t(const debugger_handlers_t&) = delete;
    debugger_handlers_t& operator=(const debugger_handlers_t&) = delete;
    debugger_handlers_t(debugger_handlers_t&&) = delete;
    debugger_handlers_t& operator=(debugger_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const debugger_handler_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const debugger_effect_approval_t& approval,
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    workspace_adapter_t& workspace_;
    debugger_lane_t& lane_;
    protocol::schema_runtime_t& schemas_;
    debugger_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_debugger_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using debugger_adapter_handler_t = protocol::mcp_result_t (*)(
    const handlers::debugger_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const handlers::debugger_effect_approval_t&,
    const protocol::json&);

protocol::mcp_result_t dbg_add_bp(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_bps(const handlers::debugger_handlers_t& handlers,
                               const protocol::json& arguments,
                               const protocol::cancellation_token_t& cancellation,
                               const handlers::debugger_effect_approval_t& approval,
                               const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_continue(const handlers::debugger_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const handlers::debugger_effect_approval_t& approval,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_delete_bp(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_exit(const handlers::debugger_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const handlers::debugger_effect_approval_t& approval,
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_gpregs(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_gpregs_remote(const handlers::debugger_handlers_t& handlers,
                                         const protocol::json& arguments,
                                         const protocol::cancellation_token_t& cancellation,
                                         const handlers::debugger_effect_approval_t& approval,
                                         const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_read(const handlers::debugger_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const handlers::debugger_effect_approval_t& approval,
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_regs(const handlers::debugger_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const handlers::debugger_effect_approval_t& approval,
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_regs_all(const handlers::debugger_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const handlers::debugger_effect_approval_t& approval,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_regs_named(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_regs_named_remote(const handlers::debugger_handlers_t& handlers,
                                             const protocol::json& arguments,
                                             const protocol::cancellation_token_t& cancellation,
                                             const handlers::debugger_effect_approval_t& approval,
                                             const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_regs_remote(const handlers::debugger_handlers_t& handlers,
                                       const protocol::json& arguments,
                                       const protocol::cancellation_token_t& cancellation,
                                       const handlers::debugger_effect_approval_t& approval,
                                       const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_run_to(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_set_bp_condition(const handlers::debugger_handlers_t& handlers,
                                            const protocol::json& arguments,
                                            const protocol::cancellation_token_t& cancellation,
                                            const handlers::debugger_effect_approval_t& approval,
                                            const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_stacktrace(const handlers::debugger_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const handlers::debugger_effect_approval_t& approval,
                                      const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_start(const handlers::debugger_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::debugger_effect_approval_t& approval,
                                 const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_status(const handlers::debugger_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const handlers::debugger_effect_approval_t& approval,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_step_into(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_step_over(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_toggle_bp(const handlers::debugger_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const handlers::debugger_effect_approval_t& approval,
                                     const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t dbg_write(const handlers::debugger_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const handlers::debugger_effect_approval_t& approval,
                                 const protocol::json& aida_metadata = protocol::json::object());

}
