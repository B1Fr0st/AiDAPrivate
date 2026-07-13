#pragma once

#include "types.hpp"
#include "../workspace_adapter.hpp"
#include "../target_resolver.hpp"
#include "../effect_policy.hpp"
#include "../ida_contracts_generated.hpp"
#include "../../protocol/mcp_tool_contract.hpp"
#include "../../protocol/mcp_result.hpp"
#include "../../protocol/schema_runtime.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::standalone::mcp::compat::handlers::test {

struct type_test_result_t {
    std::string test_name;
    bool passed = false;
    std::string message;
    std::uint64_t elapsed_ms = 0;
};

struct type_test_summary_t {
    std::size_t total = 0;
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::vector<type_test_result_t> results;
};

class type_test_harness_t {
public:
    void register_test(const std::string& name, std::function<type_test_result_t()> test);
    type_test_summary_t run_all();
    type_test_summary_t run_by_name(const std::string& name);
    std::size_t test_count() const noexcept;
private:
    std::vector<std::pair<std::string, std::function<type_test_result_t()>>> tests_;
};

class types_test_fixture_t final {
public:
    types_test_fixture_t();
    ~types_test_fixture_t();

    types_test_fixture_t(const types_test_fixture_t&) = delete;
    types_test_fixture_t& operator=(const types_test_fixture_t&) = delete;
    types_test_fixture_t(types_test_fixture_t&&) = delete;
    types_test_fixture_t& operator=(types_test_fixture_t&&) = delete;

    types_overlay_store_t& overlay_store() noexcept;
    target_resolver_t& resolver() noexcept;
    effect_lock_manager_t& lock_manager() noexcept;
    protocol::schema_runtime_t& schemas() noexcept;

    adapter_request_t make_request(const protocol::json& args);

    adapter_result_t<adapter_response_t> call_query(
        std::string_view tool_name, const protocol::json& args);
    adapter_result_t<adapter_response_t> call_overlay(
        std::string_view tool_name, const protocol::json& args);
    adapter_result_t<adapter_response_t> call_query_for(
        std::uint32_t pid, std::string_view tool_name, const protocol::json& args);
    adapter_result_t<adapter_response_t> call_overlay_for(
        std::uint32_t pid, std::string_view tool_name, const protocol::json& args);

    protocol::json call_query_json(
        std::string_view tool_name, const protocol::json& args);
    protocol::json call_overlay_json(
        std::string_view tool_name, const protocol::json& args);
    protocol::json call_query_json_for(
        std::uint32_t pid, std::string_view tool_name, const protocol::json& args);
    protocol::json call_overlay_json_for(
        std::uint32_t pid, std::string_view tool_name, const protocol::json& args);

    void publish_test_target(std::uint32_t pid, const std::string& bin_name);
    void reset();

private:
    target_resolver_t resolver_;
    effect_lock_manager_t lock_manager_;
    types_overlay_store_t overlay_store_;
    protocol::schema_runtime_t schemas_;
    target_record_t default_target_;
    std::shared_ptr<types_overlay_store_t> default_scope_;
    std::unique_ptr<workspace_adapter_t> workspace_;
};

void register_all_type_handler_tests(type_test_harness_t& harness);
type_test_summary_t run_all_type_handler_tests();

type_test_result_t test_declare_struct_basic();
type_test_result_t test_declare_union_basic();
type_test_result_t test_declare_enum_basic();
type_test_result_t test_declare_typedef_basic();
type_test_result_t test_declare_multiple_types();
type_test_result_t test_declare_invalid_declaration();
type_test_result_t test_enum_upsert_create_new();
type_test_result_t test_enum_upsert_add_members();
type_test_result_t test_enum_upsert_conflict_value();
type_test_result_t test_enum_upsert_skip_existing();
type_test_result_t test_enum_upsert_bitfield_flag();
type_test_result_t test_read_struct_with_explicit_type();
type_test_result_t test_read_struct_via_application();
type_test_result_t test_read_struct_missing_address();
type_test_result_t test_read_struct_undeclared_type();
type_test_result_t test_read_struct_non_udt_type();
type_test_result_t test_search_structs_with_filter();
type_test_result_t test_search_structs_empty_filter();
type_test_result_t test_search_structs_no_matches();
type_test_result_t test_type_query_by_kind_struct();
type_test_result_t test_type_query_by_kind_enum();
type_test_result_t test_type_query_pagination();
type_test_result_t test_type_query_include_members();
type_test_result_t test_type_query_include_relationships();
type_test_result_t test_type_query_sort_by_size();
type_test_result_t test_type_query_sort_by_name_descending();
type_test_result_t test_type_query_next_offset();
type_test_result_t test_type_query_include_declaration();
type_test_result_t test_type_inspect_existing_struct();
type_test_result_t test_type_inspect_missing_type();
type_test_result_t test_type_inspect_enum_type();
type_test_result_t test_type_inspect_typedef();
type_test_result_t test_type_inspect_empty_name();
type_test_result_t test_set_type_data_kind();
type_test_result_t test_set_type_function_kind();
type_test_result_t test_set_type_overwrite_existing();
type_test_result_t test_set_type_missing_address();
type_test_result_t test_set_type_no_type_info();
type_test_result_t test_type_apply_batch_all_success();
type_test_result_t test_type_apply_batch_partial_failure();
type_test_result_t test_type_apply_batch_rollback_on_error();
type_test_result_t test_type_apply_batch_empty_edits();
type_test_result_t test_infer_types_existing_application();
type_test_result_t test_infer_types_no_data();
type_test_result_t test_infer_types_multiple_addresses();
type_test_result_t test_undo_declare_type();
type_test_result_t test_undo_set_type();
type_test_result_t test_undo_empty_stack();
type_test_result_t test_overlay_revision_tracking();
type_test_result_t test_overlay_store_clear();
type_test_result_t test_overlay_store_type_count();
type_test_result_t test_overlay_store_application_count();
type_test_result_t test_overlay_store_all_type_names_sorted();
type_test_result_t test_overlay_store_has_type();
type_test_result_t test_overlay_store_has_application();
type_test_result_t test_overlay_store_find_type();
type_test_result_t test_overlay_store_find_application();
type_test_result_t test_struct_member_offset_alignment();
type_test_result_t test_builtin_type_size_lookup();
type_test_result_t test_struct_with_array_member();
type_test_result_t test_struct_with_pointer_member();
type_test_result_t test_enum_auto_increment_values();
type_test_result_t test_enum_hex_values();
type_test_result_t test_type_query_filter_substring();
type_test_result_t test_type_inspect_max_members_limit();
type_test_result_t test_type_query_max_members_limit();
type_test_result_t test_type_apply_batch_multiple_kinds();
type_test_result_t test_target_scoped_overlay_isolation();

}
