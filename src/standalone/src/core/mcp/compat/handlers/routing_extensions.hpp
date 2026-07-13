#pragma once

#include "../target_resolver.hpp"
#include "../workspace_adapter.hpp"
#include "../ida_contracts_generated.hpp"
#include "../../protocol/mcp_tool_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::standalone::mcp::compat::handlers {

inline constexpr std::size_t k_routing_extension_tool_count = 5;

inline constexpr std::string_view k_extension_tool_list_instances = "list_instances";
inline constexpr std::string_view k_extension_tool_analyze_funcs = "analyze_funcs";
inline constexpr std::string_view k_extension_tool_find_insns = "find_insns";
inline constexpr std::string_view k_extension_tool_calculator = "calculator";
inline constexpr std::string_view k_extension_tool_calculate = "calculate";

inline constexpr std::array<std::string_view, k_routing_extension_tool_count>
    k_routing_extension_names = {{
        k_extension_tool_list_instances,
        k_extension_tool_analyze_funcs,
        k_extension_tool_find_insns,
        k_extension_tool_calculator,
        k_extension_tool_calculate,
    }};

enum class extension_lane_t : std::uint8_t {
    registry_read = 0,
    workspace_analysis,
    workspace_instruction_scan,
    local_calculator,
};

struct routing_extension_limits_t final {
    std::size_t max_request_bytes = 1024U * 1024U;
    std::size_t max_response_bytes = 16U * 1024U * 1024U;
    std::size_t max_selector_bytes = 1024U;
    std::size_t max_expression_bytes = 16384U;
    std::size_t max_function_addresses = 256U;
    std::size_t max_instruction_results = 5000U;
    std::size_t max_address_bytes = 4096U;
    std::size_t max_mnemonic_bytes = 64U;
    std::size_t max_operand_pattern_bytes = 256U;
    std::uint64_t max_offset = 10000000ULL;
    std::uint64_t max_calculator_value = (std::numeric_limits<std::uint64_t>::max)();
    std::chrono::milliseconds max_execution_time{120000};
};

struct routing_extension_invocation_options_t final {
    std::optional<std::uint64_t> expected_generation;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct routing_metadata_t final {
    std::string name;
    protocol::target_requirement_t target_requirement =
        protocol::target_requirement_t::independent;
    bool accepts_pid = false;
    bool accepts_bin_name = false;
    protocol::tool_effect_t effect = protocol::tool_effect_t::unspecified;
    protocol::effect_lock_t lock = protocol::effect_lock_t::unspecified;
    bool read_only = true;
    bool unsafe = false;
    bool archive_backed = false;
    bool is_extension = false;
    extension_lane_t lane = extension_lane_t::registry_read;
};

const std::array<std::string_view, k_routing_extension_tool_count>&
routing_extension_tool_names() noexcept;

const std::vector<routing_metadata_t>& routing_metadata_inventory();

const routing_metadata_t* find_routing_metadata(std::string_view name) noexcept;

std::size_t routing_metadata_count() noexcept;

class routing_extensions_t final {
public:
    routing_extensions_t(target_resolver_t& resolver,
                         workspace_adapter_t& workspace,
                         protocol::schema_runtime_t& schemas,
                         routing_extension_limits_t limits = {});

    routing_extensions_t(const routing_extensions_t&) = delete;
    routing_extensions_t& operator=(const routing_extensions_t&) = delete;
    routing_extensions_t(routing_extensions_t&&) = delete;
    routing_extensions_t& operator=(routing_extensions_t&&) = delete;

    std::size_t size() const noexcept;
    const protocol::tool_contract_t& contract_at(std::size_t index) const;
    const protocol::tool_contract_t* find(std::string_view name) const noexcept;
    const routing_extension_limits_t& limits() const noexcept;

    protocol::mcp_result_t invoke(
        std::string_view name,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const routing_extension_invocation_options_t& options = {},
        const protocol::json& aida_metadata = protocol::json::object()) const;

private:
    protocol::mcp_result_t dispatch(
        std::size_t index,
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const routing_extension_invocation_options_t& options) const;

    protocol::mcp_result_t handle_list_instances(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    protocol::mcp_result_t handle_analyze_funcs(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const routing_extension_invocation_options_t& options) const;

    protocol::mcp_result_t handle_find_insns(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation,
        const routing_extension_invocation_options_t& options) const;

    protocol::mcp_result_t handle_calculator(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    protocol::mcp_result_t handle_calculate(
        const protocol::json& arguments,
        const protocol::cancellation_token_t& cancellation) const;

    target_resolver_t& resolver_;
    workspace_adapter_t& workspace_;
    protocol::schema_runtime_t& schemas_;
    routing_extension_limits_t limits_;
    std::array<protocol::tool_contract_t, k_routing_extension_tool_count> contracts_;
};

}

namespace aida::standalone::mcp::compat::adapters {

protocol::mcp_result_t list_instances(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t analyze_funcs(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::routing_extension_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t find_insns(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const handlers::routing_extension_invocation_options_t& options = {},
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t calculator(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata = protocol::json::object());

protocol::mcp_result_t calculate(
    const handlers::routing_extensions_t& handlers,
    const protocol::json& arguments,
    const protocol::cancellation_token_t& cancellation,
    const protocol::json& aida_metadata = protocol::json::object());

}
