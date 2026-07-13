#pragma once

#include "routing_extensions.hpp"
#include "../workspace_adapter.hpp"
#include "../target_resolver.hpp"
#include "../effect_policy.hpp"
#include "../ida_contracts_generated.hpp"
#include "../../protocol/mcp_tool_contract.hpp"
#include "../../protocol/mcp_result.hpp"
#include "../../protocol/schema_runtime.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::handlers::test {

struct routing_test_result_t {
    std::string test_name;
    bool passed = false;
    std::string message;
    std::uint64_t elapsed_ms = 0;
};

struct routing_test_summary_t {
    std::size_t total = 0;
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::vector<routing_test_result_t> results;
};

class routing_test_harness_t {
public:
    void register_test(const std::string& name, std::function<routing_test_result_t()> test);
    routing_test_summary_t run_all();
    routing_test_summary_t run_by_name(const std::string& name);
    std::size_t test_count() const noexcept;
private:
    std::vector<std::pair<std::string, std::function<routing_test_result_t()>>> tests_;
};

struct stub_handler_state_t {
    std::uint64_t call_count = 0;
    std::string last_contract_name;
    std::string last_payload;
    std::string canned_response;
    bool canned_success = true;
};

class routing_test_fixture_t final {
public:
    routing_test_fixture_t();
    ~routing_test_fixture_t();

    routing_test_fixture_t(const routing_test_fixture_t&) = delete;
    routing_test_fixture_t& operator=(const routing_test_fixture_t&) = delete;
    routing_test_fixture_t(routing_test_fixture_t&&) = delete;
    routing_test_fixture_t& operator=(routing_test_fixture_t&&) = delete;

    target_resolver_t& resolver() noexcept;
    effect_lock_manager_t& lock_manager() noexcept;
    workspace_adapter_t& workspace() noexcept;
    protocol::schema_runtime_t& schemas() noexcept;
    routing_extensions_t& routing() noexcept;

    stub_handler_state_t& analysis_state() noexcept;
    stub_handler_state_t& query_state() noexcept;

    void publish_target(std::uint32_t pid, const std::string& bin_name, bool live = false);
    void set_analysis_response(const std::string& json_payload);
    void set_query_response(const std::string& json_payload);

    protocol::cancellation_token_t make_cancellation(bool cancelled = false);

private:
    static adapter_result_t<adapter_response_t> stub_analysis_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_query_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_overlay_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_checkpoint_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_debugger_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_python_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<adapter_response_t> stub_decompilation_handler(
        const adapter_call_context_t& context, const adapter_request_t& request);
    static adapter_result_t<bounded_live_snapshot_t> stub_snapshot_handler(
        const adapter_call_context_t& context, const bounded_live_snapshot_request_t& request);

    target_resolver_t resolver_;
    effect_lock_manager_t lock_manager_;
    protocol::schema_runtime_t schemas_;
    stub_handler_state_t analysis_state_;
    stub_handler_state_t query_state_;
    workspace_adapter_handlers_t handlers_;
    std::unique_ptr<workspace_adapter_t> workspace_;
    std::unique_ptr<routing_extensions_t> routing_;
};

void register_all_routing_extension_tests(routing_test_harness_t& harness);
routing_test_summary_t run_all_routing_extension_tests();

routing_test_result_t test_metadata_inventory_count();
routing_test_result_t test_metadata_find_all_extensions();
routing_test_result_t test_metadata_find_archive_tool();
routing_test_result_t test_metadata_find_missing_returns_null();
routing_test_result_t test_metadata_effect_fields_for_extensions();
routing_test_result_t test_metadata_lane_for_extensions();
routing_test_result_t test_metadata_archive_backed_flag();
routing_test_result_t test_metadata_is_extension_flag();
routing_test_result_t test_metadata_target_requirement_for_extensions();
routing_test_result_t test_metadata_count_function();
routing_test_result_t test_extension_tool_count();
routing_test_result_t test_extension_tool_names_match_constants();
routing_test_result_t test_union_tool_count_is_92();
routing_test_result_t test_archive_tool_count_is_88();
routing_test_result_t test_extension_count_is_4();
routing_test_result_t test_list_instances_empty_resolver();
routing_test_result_t test_list_instances_with_published_target();
routing_test_result_t test_list_instances_with_filter();
routing_test_result_t test_list_instances_multiple_targets();
routing_test_result_t test_list_instances_include_retired_flag();
routing_test_result_t test_calculator_addition();
routing_test_result_t test_calculator_subtraction();
routing_test_result_t test_calculator_multiplication();
routing_test_result_t test_calculator_division();
routing_test_result_t test_calculator_modulo();
routing_test_result_t test_calculator_hex_literal();
routing_test_result_t test_calculator_binary_literal();
routing_test_result_t test_calculator_bitwise_and();
routing_test_result_t test_calculator_bitwise_or();
routing_test_result_t test_calculator_bitwise_xor();
routing_test_result_t test_calculator_bitwise_not();
routing_test_result_t test_calculator_shift_left();
routing_test_result_t test_calculator_shift_right();
routing_test_result_t test_calculator_parentheses();
routing_test_result_t test_calculator_division_by_zero();
routing_test_result_t test_calculator_empty_expression();
routing_test_result_t test_calculator_trailing_tokens();
routing_test_result_t test_calculator_complex_expression();
routing_test_result_t test_calculate_alias_matches_calculator();
routing_test_result_t test_calculate_hex_output();
routing_test_result_t test_analyze_funcs_missing_addrs();
routing_test_result_t test_find_insns_missing_mnemonic();
routing_test_result_t test_routing_extension_size();
routing_test_result_t test_routing_extension_find_existing();
routing_test_result_t test_routing_extension_find_missing();
routing_test_result_t test_routing_extension_limits_defaults();
routing_test_result_t test_list_instances_metadata_fields();

}
