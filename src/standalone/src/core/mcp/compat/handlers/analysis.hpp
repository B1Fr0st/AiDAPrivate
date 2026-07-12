#pragma once

#include "../workspace_adapter.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_analysis_tool_count = 14;

struct analysis_handler_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_address_bytes = 4096U;
    std::size_t max_pattern_bytes = 16384U;
    std::size_t max_filter_bytes = 4096U;
    std::size_t max_target_count = 256U;
    std::size_t max_query_count = 256U;
    std::size_t max_batch_query_count = 128U;
    std::uint64_t max_offset = 10000000ULL;
    std::uint64_t max_disasm_instructions = 50000ULL;
    std::uint64_t max_profile_results = 5000ULL;
    std::uint64_t max_profile_list_items = 5000ULL;
    std::uint64_t max_batch_blocks = 10000ULL;
    std::uint64_t max_batch_relations = 5000ULL;
    std::uint64_t max_batch_constants = 5000ULL;
    std::uint64_t max_batch_disasm_instructions = 50000ULL;
    std::uint64_t max_batch_strings = 5000ULL;
    std::uint64_t max_xrefs_per_target = 1000ULL;
    std::uint64_t max_xref_query_results = 5000ULL;
    std::uint64_t max_callees_per_function = 500ULL;
    std::uint64_t max_find_matches = 10000ULL;
    std::uint64_t max_basic_blocks = 10000ULL;
    std::uint64_t max_instruction_query_results = 5000ULL;
    std::uint64_t max_instruction_scan = 5000000ULL;
    std::uint64_t max_callgraph_depth = 64ULL;
    std::uint64_t max_callgraph_nodes = 100000ULL;
    std::uint64_t max_callgraph_edges = 200000ULL;
    std::uint64_t max_callgraph_edges_per_function = 5000ULL;
    std::chrono::milliseconds max_execution_time{120000};
};

const std::array<std::string_view, k_analysis_tool_count>& analysis_tool_names() noexcept;

class analysis_handlers_t final {
public:
    analysis_handlers_t(workspace_adapter_t& workspace,
                        protocol::schema_runtime_t& schemas,
                        analysis_handler_limits_t limits = {});

    analysis_handlers_t(const analysis_handlers_t&) = delete;
    analysis_handlers_t& operator=(const analysis_handlers_t&) = delete;
    analysis_handlers_t(analysis_handlers_t&&) = delete;
    analysis_handlers_t& operator=(analysis_handlers_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const analysis_handler_limits_t& limits() const noexcept;

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
    analysis_handler_limits_t limits_;
    std::array<protocol::tool_contract_t, k_analysis_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

using analysis_adapter_t = protocol::mcp_result_t (*)(
    const handlers::analysis_handlers_t&,
    const protocol::json&,
    const protocol::cancellation_token_t&,
    const protocol::json&);

protocol::mcp_result_t decompile(const handlers::analysis_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t disasm(const handlers::analysis_handlers_t& handlers,
                              const protocol::json& arguments,
                              const protocol::cancellation_token_t& cancellation,
                              const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t func_profile(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t analyze_batch(const handlers::analysis_handlers_t& handlers,
                                     const protocol::json& arguments,
                                     const protocol::cancellation_token_t& cancellation,
                                     const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t xrefs_to(const handlers::analysis_handlers_t& handlers,
                                const protocol::json& arguments,
                                const protocol::cancellation_token_t& cancellation,
                                const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t xref_query(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t xrefs_to_field(const handlers::analysis_handlers_t& handlers,
                                      const protocol::json& arguments,
                                      const protocol::cancellation_token_t& cancellation,
                                      const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t callees(const handlers::analysis_handlers_t& handlers,
                               const protocol::json& arguments,
                               const protocol::cancellation_token_t& cancellation,
                               const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t find_bytes(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t basic_blocks(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t find(const handlers::analysis_handlers_t& handlers,
                            const protocol::json& arguments,
                            const protocol::cancellation_token_t& cancellation,
                            const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t insn_query(const handlers::analysis_handlers_t& handlers,
                                  const protocol::json& arguments,
                                  const protocol::cancellation_token_t& cancellation,
                                  const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t export_funcs(const handlers::analysis_handlers_t& handlers,
                                    const protocol::json& arguments,
                                    const protocol::cancellation_token_t& cancellation,
                                    const protocol::json& aida_metadata = protocol::json::object());
protocol::mcp_result_t callgraph(const handlers::analysis_handlers_t& handlers,
                                 const protocol::json& arguments,
                                 const protocol::cancellation_token_t& cancellation,
                                 const protocol::json& aida_metadata = protocol::json::object());

}
