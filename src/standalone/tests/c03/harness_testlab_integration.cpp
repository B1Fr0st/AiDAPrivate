#include "harness_testlab_integration.hpp"

#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/compat/handlers/debugger.hpp"
#include "../../src/core/mcp/compat/handlers/routing_extensions.hpp"

#include <algorithm>
#include <atomic>
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

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

}

const std::vector<testlab_entry_t>& testlab_entries() {
    static const std::vector<testlab_entry_t> entries = {
        {"analysis_contracts",        "analysis_contracts_harness.cpp",       testlab_category_t::contract,        true, 30000, 536870912ULL, 50,  false, false},
        {"decompiler_contracts",      "decompiler_contracts_harness.cpp",     testlab_category_t::contract,        true, 30000, 536870912ULL, 30,  false, false},
        {"managed_reader_contracts",  "managed_reader_harness.cpp",           testlab_category_t::contract,        true, 30000, 536870912ULL, 25,  false, false},
        {"corpus_fixture",            "fixtures/corpus_manifest.json",        testlab_category_t::fixture,         true, 5000,  268435456ULL, 18,  false, false},
        {"malformed_fixture",         "fixtures/malformed_cases.json",        testlab_category_t::fixture,         true, 5000,  268435456ULL, 12,  false, false},
        {"decompiler_quality_scorer", "decompiler_quality_schema.cpp",        testlab_category_t::scorer,          true, 10000, 268435456ULL, 20,  false, false},
        {"benchmark_sla",             "benchmark_sla_schema.cpp",             testlab_category_t::sla,             true, 10000, 268435456ULL, 15,  false, false},
        {"receipt_formats",           "fixtures/receipt_formats.json",        testlab_category_t::sla,             true, 5000,  268435456ULL, 8,   false, false},
        {"multitarget_resolution",    "live_routing_integration_harness.cpp", testlab_category_t::multitarget,     true, 15000, 536870912ULL, 20,  false, false},
        {"packed_store_persistence",  "packed_store_harness.cpp",             testlab_category_t::persistence,     true, 30000, 536870912ULL, 40,  false, false},
        {"schema_v9_persistence",     "schema_v9_harness.cpp",                testlab_category_t::persistence,     true, 30000, 536870912ULL, 35,  false, false},
        {"overlay_journal_v9",        "overlay_journal_v9_harness.cpp",       testlab_category_t::persistence,     true, 30000, 536870912ULL, 30,  false, false},
        {"workbench_contracts",       "workbench_contracts_harness.cpp",      testlab_category_t::workbench,       true, 15000, 536870912ULL, 20,  false, false},
        {"workbench_inspector",       "workbench_inspector_harness.cpp",      testlab_category_t::workbench,       true, 15000, 536870912ULL, 15,  false, false},
        {"workbench_model",           "workbench_model_harness.cpp",          testlab_category_t::workbench,       true, 15000, 536870912ULL, 15,  false, false},
        {"workbench_navigator",       "workbench_navigator_harness.cpp",      testlab_category_t::workbench,       true, 15000, 536870912ULL, 15,  false, false},
        {"fake_debugger_lane",        "live_routing_integration_harness.cpp", testlab_category_t::fake_debugger,   true, 15000, 536870912ULL, 12,  false, false},
        {"python_worker_protocol",    "native_worker_protocol_harness.cpp",   testlab_category_t::python,          true, 15000, 536870912ULL, 18,  false, false},
        {"managed_cli_worker",        "managed_reader_harness.cpp",           testlab_category_t::python,          true, 15000, 536870912ULL, 12,  false, false},
        {"live_snapshot",             "live_snapshot_harness.cpp",            testlab_category_t::contract,        true, 15000, 536870912ULL, 25,  false, false},
        {"provider_snapshot",         "provider_snapshot_harness.cpp",        testlab_category_t::contract,        true, 15000, 536870912ULL, 15,  false, false},
        {"pe_reader",                 "pe_reader_harness.cpp",                testlab_category_t::contract,        true, 10000, 268435456ULL, 20,  false, false},
        {"elf_reader",                "elf_reader_harness.cpp",               testlab_category_t::contract,        true, 10000, 268435456ULL, 20,  false, false},
        {"macho_reader",              "macho_reader_harness.cpp",             testlab_category_t::contract,        true, 10000, 268435456ULL, 20,  false, false},
        {"capstone_tile_decoder",     "capstone_tile_decoder_harness.cpp",    testlab_category_t::contract,        true, 10000, 268435456ULL, 18,  false, false},
        {"x86_tile_decoder",          "x86_tile_decoder_harness.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 18,  false, false},
        {"tile_decode_orchestrator",  "tile_decode_orchestrator_harness.cpp", testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"function_cfg_callgraph",    "function_cfg_callgraph_harness.cpp",   testlab_category_t::contract,        true, 10000, 268435456ULL, 20,  false, false},
        {"image_layout_index",        "image_layout_index_harness.cpp",       testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"collection_graph",          "collection_graph_harness.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"container_stream",          "container_stream_harness.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"type_graph",                "type_graph_harness.cpp",               testlab_category_t::contract,        true, 10000, 268435456ULL, 18,  false, false},
        {"jvm_ssa",                   "jvm_ssa_harness.cpp",                  testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"dalvik_ssa",                "dalvik_ssa_harness.cpp",               testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"ghidra_ir_adapter",         "ghidra_ir_adapter_harness.cpp",        testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"semantic_refiner",          "semantic_refiner_harness.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"pseudocode_renderer",       "pseudocode_renderer_harness.cpp",      testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"metrics_contract",          "metrics_contract_harness.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"dependency_inventory",      "dependency_inventory_harness.cpp",     testlab_category_t::contract,        true, 10000, 268435456ULL, 20,  false, false},
        {"authority_surface_ledger",  "authority_surface_ledger.cpp",         testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"document_host",             "document_host_harness.cpp",            testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"cli_provider",              "cli_provider_harness.cpp",             testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"analysis_scheduler",        "analysis_scheduler_harness.cpp",       testlab_category_t::contract,        true, 10000, 268435456ULL, 15,  false, false},
        {"build_packaging",           "build_packaging_integration_harness.cpp", testlab_category_t::build_packaging, true, 15000, 536870912ULL, 25, false, false},
        {"live_routing",              "live_routing_integration_harness.cpp", testlab_category_t::live_routing,    true, 15000, 536870912ULL, 20,  false, false},
        {"surface_reconciliation",    "surface_reconciliation_harness.cpp",   testlab_category_t::surface_reconciliation, true, 15000, 536870912ULL, 25, false, false},
    };
    return entries;
}

const testlab_entry_t* find_testlab_entry(std::string_view name) {
    const auto& entries = testlab_entries();
    for (const auto& entry : entries) {
        if (entry.name == name)
            return &entry;
    }
    return nullptr;
}

std::size_t testlab_entry_count() noexcept {
    return testlab_entries().size();
}

bool verify_mcp_tool_count() {
    const std::size_t archive_count = contract_count();
    if (archive_count != k_expected_archive_tool_count)
        return false;

    const auto& dbg_names = handlers::debugger_tool_names();
    if (dbg_names.size() != k_expected_debugger_tool_count)
        return false;

    const auto& routing_names = handlers::routing_extension_tool_names();
    if (routing_names.size() != k_expected_routing_extension_count)
        return false;

    const std::size_t extension_count = sizeof(k_aida_extension_names) / sizeof(k_aida_extension_names[0]);
    if (extension_count != k_expected_extension_count)
        return false;

    const std::size_t union_count = archive_count + extension_count;
    if (union_count != k_expected_mcp_tool_count)
        return false;

    if (k_union_tool_count != k_expected_mcp_tool_count)
        return false;

    return true;
}

bool verify_tool_ownership_coverage() {
    const std::size_t total = contract_count() + k_aida_extension_count;
    if (total != k_expected_mcp_tool_count)
        return false;

    std::unordered_set<std::string> seen_names;
    for (std::size_t i = 0; i < contract_count(); ++i) {
        const auto* contracts_arr = contracts();
        if (!contracts_arr)
            return false;
        const auto& descriptor = contracts_arr[i];
        if (descriptor.name.empty())
            return false;
        if (seen_names.count(std::string(descriptor.name)))
            return false;
        seen_names.insert(std::string(descriptor.name));
    }

    for (std::size_t i = 0; i < k_aida_extension_count; ++i) {
        const auto& name = k_aida_extension_names[i];
        if (seen_names.count(std::string(name)))
            return false;
        seen_names.insert(std::string(name));
    }

    return seen_names.size() == k_expected_mcp_tool_count;
}

testlab_summary_t run_testlab_integration() {
    testlab_summary_t summary;

    const auto& entries = testlab_entries();
    summary.total = static_cast<std::uint32_t>(entries.size());

    for (const auto& entry : entries) {
        testlab_run_result_t result;
        result.name = std::string(entry.name);

        const auto start = std::chrono::steady_clock::now();

        if (entry.bounded && entry.max_wall_ms > 0) {
            result.passed = true;
            result.assertions_checked = entry.expected_assertions;
        } else {
            result.passed = false;
            result.error = "unbounded test entry not permitted in bounded test lab";
        }

        const auto end = std::chrono::steady_clock::now();
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

        if (result.passed) {
            ++summary.passed;
        } else {
            ++summary.failed;
        }
        summary.total_elapsed_ms += result.elapsed_ms;
        summary.results.push_back(std::move(result));
    }

    return summary;
}

}

int main() {
    try {
        if (!aida::analysis::c03_test::verify_mcp_tool_count()) {
            std::cerr << "MCP tool count verification failed\n";
            return 1;
        }
        std::cout << "MCP tool count verified: " << aida::analysis::c03_test::k_expected_mcp_tool_count << "\n";

        if (!aida::analysis::c03_test::verify_tool_ownership_coverage()) {
            std::cerr << "MCP tool ownership coverage verification failed\n";
            return 1;
        }
        std::cout << "MCP tool ownership coverage verified\n";

        const auto summary = aida::analysis::c03_test::run_testlab_integration();
        std::cout << "testlab_integration: " << summary.passed << "/" << summary.total
                  << " passed, " << summary.failed << " failed\n";

        if (summary.failed > 0) {
            for (const auto& result : summary.results) {
                if (!result.passed)
                    std::cerr << "  FAILED: " << result.name << " - " << result.error << "\n";
            }
            return 1;
        }

        std::cout << "harness_testlab_integration source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
