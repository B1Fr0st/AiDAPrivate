#include "harness_testlab_integration.hpp"

#include "../../src/core/mcp/compat/handlers/analysis.hpp"
#include "../../src/core/mcp/compat/handlers/composite.hpp"
#include "../../src/core/mcp/compat/handlers/core.hpp"
#include "../../src/core/mcp/compat/handlers/debugger.hpp"
#include "../../src/core/mcp/compat/handlers/memory.h"
#include "../../src/core/mcp/compat/handlers/modify.hpp"
#include "../../src/core/mcp/compat/handlers/python.hpp"
#include "../../src/core/mcp/compat/handlers/routing_extensions.hpp"
#include "../../src/core/mcp/compat/handlers/signatures.h"
#include "../../src/core/mcp/compat/handlers/stack.hpp"
#include "../../src/core/mcp/compat/handlers/survey.hpp"
#include "../../src/core/mcp/compat/handlers/types.hpp"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../mcp_compat/analysis_handlers_harness.hpp"
#include "../mcp_compat/composite_handlers_harness.hpp"
#include "../mcp_compat/core_handlers_harness.hpp"
#include "../mcp_compat/debugger_handlers_harness.hpp"
#include "../mcp_compat/memory_handlers_harness.hpp"
#include "../mcp_compat/modify_handlers_harness.hpp"
#include "../mcp_compat/python_handler_harness.hpp"
#include "../mcp_compat/routing_extensions_harness.hpp"
#include "../mcp_compat/signature_handlers_harness.h"
#include "../mcp_compat/stack_handlers_harness.hpp"
#include "../mcp_compat/survey_handler_harness.hpp"
#include "../mcp_compat/type_handlers_harness.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using namespace aida::standalone::mcp::compat;
namespace handler_tests = aida::standalone::tests::mcp_compat;

using harness_runner_t = bool (*)(std::string& failure);

struct harness_runner_binding_t final {
    std::string_view name;
    harness_runner_t runner = nullptr;
};

constexpr std::array<harness_runner_binding_t, 12> k_harness_runners{{
    {"analysis_handlers", handler_tests::run_analysis_handlers_harness},
    {"composite_handlers", handler_tests::run_composite_handlers_harness},
    {"core_handlers", handler_tests::run_core_handlers_harness},
    {"debugger_handlers", handler_tests::run_debugger_handlers_harness},
    {"memory_handlers", handler_tests::run_memory_handlers_harness},
    {"modify_handlers", handler_tests::run_modify_handlers_harness},
    {"python_handler", handler_tests::run_python_handler_harness},
    {"signature_handlers", handler_tests::run_signature_handlers_harness},
    {"stack_handlers", handler_tests::run_stack_handlers_harness},
    {"survey_handler", handler_tests::run_survey_handler_harness},
    {"type_handlers", handler_tests::run_type_handlers_harness},
    {"routing_extensions", handler_tests::run_routing_extensions_harness},
}};

constexpr std::string_view k_mcp_handler_ctest_target =
    "aida_c03_c19_mcp_handler_testlab_harness";

constexpr testlab_entry_t external_entry(
    std::string_view name,
    std::string_view harness_file,
    std::string_view ctest_target,
    testlab_category_t category) noexcept {
    return {name, harness_file, ctest_target, category,
            testlab_execution_t::external_ctest, true, 60000, 536870912ULL,
            0, false, false};
}

constexpr testlab_entry_t in_process_entry(
    std::string_view name,
    std::string_view harness_file,
    testlab_category_t category,
    std::uint32_t expected_assertions) noexcept {
    return {name, harness_file, k_mcp_handler_ctest_target, category,
            testlab_execution_t::in_process, true, 60000, 536870912ULL,
            expected_assertions, false, false};
}

constexpr std::array<std::string_view, handlers::k_composite_tool_count>
    k_composite_names{{
        "analyze_function",
        "analyze_component",
        "diff_before_after",
        "trace_data_flow",
    }};

constexpr std::array<std::string_view, 4> k_signature_names{{
    "make_signature",
    "make_signature_for_function",
    "make_signature_for_range",
    "find_xref_signatures",
}};

template <typename Range>
bool contains_name(const Range& names, std::string_view name) {
    return std::find(names.begin(), names.end(), name) != names.end();
}

harness_runner_t find_harness_runner(std::string_view name) noexcept {
    const auto found = std::find_if(
        k_harness_runners.begin(), k_harness_runners.end(),
        [name](const harness_runner_binding_t& binding) {
            return binding.name == name;
        });
    return found == k_harness_runners.end() ? nullptr : found->runner;
}

std::size_t archive_owner_count(std::string_view name) {
    std::size_t count = 0;
    count += contains_name(handlers::analysis_tool_names(), name) ? 1U : 0U;
    count += contains_name(k_composite_names, name) ? 1U : 0U;
    count += contains_name(handlers::core_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::debugger_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::memory_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::modify_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::python_tool_names(), name) ? 1U : 0U;
    count += handlers::is_signature_tool_name(name) ? 1U : 0U;
    count += contains_name(handlers::stack_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::survey_tool_names(), name) ? 1U : 0U;
    count += contains_name(handlers::types_tool_names(), name) ? 1U : 0U;
    count += name == "list_instances" ? 1U : 0U;
    return count;
}

}

const std::vector<testlab_entry_t>& testlab_entries() {
    static const std::vector<testlab_entry_t> entries = {
        external_entry("tile_decode_orchestrator", "tile_decode_orchestrator_harness.cpp", "aida_c03_c01_tile_decode_orchestrator_harness", testlab_category_t::contract),
        external_entry("function_cfg_callgraph", "function_cfg_callgraph_harness.cpp", "aida_c03_c02_function_cfg_callgraph_harness", testlab_category_t::contract),
        external_entry("xref_discovery", "xref_discovery_harness.cpp", "aida_c03_c03_xref_discovery_harness", testlab_category_t::contract),
        external_entry("search_query", "search_query_harness.cpp", "aida_c03_c04_search_query_harness", testlab_category_t::contract),
        external_entry("schema_v9", "schema_v9_harness.cpp", "aida_c03_c05_schema_v9_harness", testlab_category_t::persistence),
        external_entry("decompiler_service", "decompiler_service_harness.cpp", "aida_c03_c06_decompiler_service_harness", testlab_category_t::contract),
        external_entry("decompiler_readability", "decompiler_readability_harness.cpp", "aida_c03_c07_decompiler_readability_harness", testlab_category_t::scorer),
        external_entry("python_worker", "python_worker_harness.cpp", "aida_c03_b24_python_worker_harness", testlab_category_t::python),
        external_entry("workbench_documents", "workbench_documents_harness.cpp", "aida_c03_c20_c22_workbench_documents_harness", testlab_category_t::workbench),
        external_entry("graph_diff_documents", "workbench_documents_harness.cpp", "aida_c03_c20_c22_workbench_documents_harness", testlab_category_t::workbench),
        external_entry("workbench_persistence", "workbench_persistence_harness.cpp", "aida_c03_c23_workbench_persistence_harness", testlab_category_t::persistence),
        external_entry("overlay_projection", "overlay_projection_harness.cpp", "aida_c03_c24_overlay_projection_harness", testlab_category_t::contract),
        in_process_entry("analysis_handlers", "analysis_handlers_harness.cpp", testlab_category_t::contract, 14),
        in_process_entry("composite_handlers", "composite_handlers_harness.cpp", testlab_category_t::contract, 4),
        in_process_entry("core_handlers", "core_handlers_harness.cpp", testlab_category_t::contract, 12),
        in_process_entry("debugger_handlers", "debugger_handlers_harness.cpp", testlab_category_t::fake_debugger, 22),
        in_process_entry("memory_handlers", "memory_handlers_harness.cpp", testlab_category_t::contract, 6),
        in_process_entry("modify_handlers", "modify_handlers_harness.cpp", testlab_category_t::contract, 11),
        in_process_entry("python_handler", "python_handler_harness.cpp", testlab_category_t::python, 1),
        in_process_entry("signature_handlers", "signature_handlers_harness.cpp", testlab_category_t::contract, 4),
        in_process_entry("stack_handlers", "stack_handlers_harness.cpp", testlab_category_t::contract, 3),
        in_process_entry("survey_handler", "survey_handler_harness.cpp", testlab_category_t::contract, 1),
        in_process_entry("type_handlers", "type_handlers_harness.cpp", testlab_category_t::contract, 9),
        in_process_entry("routing_extensions", "routing_extensions_harness.cpp", testlab_category_t::multitarget, 5),
    };
    return entries;
}

const testlab_entry_t* find_testlab_entry(std::string_view name) {
    const auto& entries = testlab_entries();
    const auto found = std::find_if(
        entries.begin(), entries.end(),
        [name](const testlab_entry_t& entry) {
            return entry.name == name;
        });
    return found == entries.end() ? nullptr : &*found;
}

std::size_t testlab_entry_count() noexcept {
    return testlab_entries().size();
}

bool verify_testlab_registry(std::string& failure) {
    const auto& entries = testlab_entries();
    if (entries.size() != k_expected_testlab_entry_count) {
        failure = "Test Lab registry cardinality is invalid";
        return false;
    }

    std::unordered_set<std::string> names;
    names.reserve(entries.size());
    std::size_t in_process_count = 0;
    std::size_t external_count = 0;
    for (const auto& entry : entries) {
        if (entry.name.empty() || entry.harness_file.empty() || entry.ctest_target.empty() ||
            !entry.bounded || entry.max_wall_ms == 0 || entry.max_private_bytes == 0 ||
            entry.requires_driver || entry.requires_network ||
            !names.emplace(entry.name.data(), entry.name.size()).second) {
            failure = "Test Lab registry contains an invalid, unsafe, or duplicate entry";
            return false;
        }

        const auto runner = find_harness_runner(entry.name);
        if (entry.execution == testlab_execution_t::in_process) {
            if (!runner || entry.ctest_target != k_mcp_handler_ctest_target) {
                failure = "Test Lab in-process entry has no matching handler runner";
                return false;
            }
            ++in_process_count;
        } else if (entry.execution == testlab_execution_t::external_ctest) {
            if (runner || entry.expected_assertions != 0) {
                failure = "Test Lab external entry overlaps an in-process handler runner";
                return false;
            }
            ++external_count;
        } else {
            failure = "Test Lab registry contains an unknown execution mode";
            return false;
        }
    }

    if (in_process_count != k_expected_testlab_in_process_count ||
        external_count != k_expected_testlab_external_count) {
        failure = "Test Lab execution-mode cardinality is invalid";
        return false;
    }
    failure.clear();
    return true;
}

bool verify_mcp_tool_count() {
    const std::size_t owned_archive_count =
        handlers::analysis_tool_names().size() +
        handlers::k_composite_tool_count +
        handlers::core_tool_names().size() +
        handlers::debugger_tool_names().size() +
        handlers::memory_tool_names().size() +
        handlers::modify_tool_names().size() +
        handlers::python_tool_names().size() +
        k_signature_names.size() +
        handlers::stack_tool_names().size() +
        handlers::survey_tool_names().size() +
        handlers::types_tool_names().size() + 1U;
    const auto& routing_names = handlers::routing_extension_tool_names();
    const std::size_t extension_count =
        sizeof(k_aida_extension_names) / sizeof(k_aida_extension_names[0]);

    return contract_count() == k_expected_archive_tool_count &&
        owned_archive_count == k_expected_archive_tool_count &&
        handlers::debugger_tool_names().size() == k_expected_debugger_tool_count &&
        routing_names.size() == k_expected_routing_extension_count &&
        extension_count == k_expected_extension_count &&
        k_union_tool_count == k_expected_mcp_tool_count &&
        contract_count() + extension_count == k_expected_mcp_tool_count &&
        k_harness_runners.size() == k_mcp_tool_ownership_count;
}

bool verify_tool_ownership_coverage() {
    if (!verify_mcp_tool_count())
        return false;

    const auto* generated = contracts();
    if (!generated)
        return false;

    std::unordered_set<std::string> seen_names;
    seen_names.reserve(k_expected_mcp_tool_count);
    for (std::size_t index = 0; index < contract_count(); ++index) {
        const auto name = generated[index].name;
        if (name.empty() || name == "py_eval" || archive_owner_count(name) != 1U ||
            !seen_names.emplace(name).second) {
            return false;
        }
    }

    const auto& routing_names = handlers::routing_extension_tool_names();
    if (!contains_name(routing_names, "list_instances") ||
        seen_names.find("list_instances") == seen_names.end()) {
        return false;
    }

    for (const auto extension_name : k_aida_extension_names) {
        if (!contains_name(routing_names, extension_name) ||
            !seen_names.emplace(extension_name).second) {
            return false;
        }
    }

    return seen_names.size() == k_expected_mcp_tool_count &&
        seen_names.find("py_eval") == seen_names.end();
}

testlab_summary_t run_testlab_integration() {
    testlab_summary_t summary;
    const auto& entries = testlab_entries();
    std::string registry_failure;
    if (!verify_testlab_registry(registry_failure))
        throw std::runtime_error(registry_failure);

    summary.registered = static_cast<std::uint32_t>(entries.size());
    summary.results.reserve(k_expected_testlab_in_process_count);

    for (const auto& entry : entries) {
        if (entry.execution == testlab_execution_t::external_ctest) {
            ++summary.external_registered;
            continue;
        }

        ++summary.total;
        testlab_run_result_t result;
        result.name.assign(entry.name.data(), entry.name.size());
        const auto start = std::chrono::steady_clock::now();

        const auto runner = find_harness_runner(entry.name);
        if (!entry.bounded || entry.max_wall_ms == 0 || entry.requires_driver ||
            entry.requires_network) {
            result.error = "unsafe or unbounded Test Lab entry";
        } else if (!runner) {
            result.error = "Test Lab runner is not registered";
        } else {
            try {
                result.passed = runner(result.error);
                if (result.passed && !result.error.empty()) {
                    result.passed = false;
                    result.error = "runner reported success with a non-empty failure message";
                } else if (!result.passed && result.error.empty()) {
                    result.error = "runner reported failure without diagnostics";
                }
            } catch (const std::exception& error) {
                result.error = error.what();
            } catch (...) {
                result.error = "runner raised a non-standard exception";
            }
        }

        const auto end = std::chrono::steady_clock::now();
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        if (result.elapsed_ms > entry.max_wall_ms) {
            result.passed = false;
            result.error = "runner exceeded the " + std::to_string(entry.max_wall_ms) +
                " ms Test Lab limit";
        }
        result.assertions_checked = result.passed ? entry.expected_assertions : 0;

        if (result.passed)
            ++summary.passed;
        else
            ++summary.failed;
        summary.total_elapsed_ms += result.elapsed_ms;
        summary.results.push_back(std::move(result));
    }

    return summary;
}

}

int main() {
    try {
        std::string registry_failure;
        if (!aida::analysis::c03_test::verify_testlab_registry(registry_failure)) {
            std::cerr << registry_failure << '\n';
            return 1;
        }
        if (!aida::analysis::c03_test::verify_mcp_tool_count()) {
            std::cerr << "MCP tool count verification failed\n";
            return 1;
        }
        if (!aida::analysis::c03_test::verify_tool_ownership_coverage()) {
            std::cerr << "MCP tool ownership coverage verification failed\n";
            return 1;
        }

        std::cout << "MCP inventory verified: archive="
                  << aida::analysis::c03_test::k_expected_archive_tool_count
                  << " union=" << aida::analysis::c03_test::k_expected_mcp_tool_count << '\n';

        const auto summary = aida::analysis::c03_test::run_testlab_integration();
        std::cout << "testlab_integration: registered=" << summary.registered
                  << " external=" << summary.external_registered
                  << " executed=" << summary.total << " passed=" << summary.passed
                  << " failed=" << summary.failed << '\n';
        if (summary.failed == 0)
            return 0;

        for (const auto& result : summary.results) {
            if (!result.passed)
                std::cerr << "FAILED: " << result.name << " - " << result.error << '\n';
        }
        return 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
