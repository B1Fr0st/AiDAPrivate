#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::c03_test {

enum class testlab_category_t : std::uint8_t {
    contract = 0,
    fixture = 1,
    scorer = 2,
    sla = 3,
    multitarget = 4,
    persistence = 5,
    workbench = 6,
    fake_debugger = 7,
    python = 8,
    surface_reconciliation = 9,
    build_packaging = 10,
    live_routing = 11
};

enum class testlab_execution_t : std::uint8_t {
    in_process = 0,
    external_ctest = 1
};

struct testlab_entry_t {
    std::string_view name;
    std::string_view harness_file;
    std::string_view ctest_target;
    testlab_category_t category = testlab_category_t::contract;
    testlab_execution_t execution = testlab_execution_t::external_ctest;
    bool bounded = true;
    std::uint32_t max_wall_ms = 30000;
    std::uint64_t max_private_bytes = 536870912ULL;
    std::uint32_t expected_assertions = 0;
    bool requires_driver = false;
    bool requires_network = false;
};

struct testlab_run_result_t {
    std::string name;
    bool passed = false;
    std::string error;
    std::uint64_t elapsed_ms = 0;
    std::uint32_t assertions_checked = 0;
};

struct testlab_summary_t {
    std::uint32_t registered = 0;
    std::uint32_t external_registered = 0;
    std::uint32_t total = 0;
    std::uint32_t passed = 0;
    std::uint32_t failed = 0;
    std::uint64_t total_elapsed_ms = 0;
    std::vector<testlab_run_result_t> results;
};

inline constexpr std::size_t k_expected_mcp_tool_count = 92;
inline constexpr std::size_t k_expected_archive_tool_count = 88;
inline constexpr std::size_t k_expected_extension_count = 4;
inline constexpr std::size_t k_expected_debugger_tool_count = 22;
inline constexpr std::size_t k_expected_routing_extension_count = 5;
inline constexpr std::size_t k_expected_testlab_entry_count = 26;
inline constexpr std::size_t k_expected_testlab_in_process_count = 12;
inline constexpr std::size_t k_expected_testlab_external_count = 14;

inline constexpr std::string_view k_mcp_tool_ownership_categories[] = {
    "analysis", "core", "debugger", "memory", "modify", "python",
    "signatures", "stack", "survey", "types", "composite", "routing_extensions"
};

inline constexpr std::size_t k_mcp_tool_ownership_count =
    sizeof(k_mcp_tool_ownership_categories) / sizeof(k_mcp_tool_ownership_categories[0]);

const std::vector<testlab_entry_t>& testlab_entries();
const testlab_entry_t* find_testlab_entry(std::string_view name);
std::size_t testlab_entry_count() noexcept;

testlab_summary_t run_testlab_integration();
bool verify_testlab_registry(std::string& failure);
bool verify_mcp_tool_count();
bool verify_tool_ownership_coverage();

}
