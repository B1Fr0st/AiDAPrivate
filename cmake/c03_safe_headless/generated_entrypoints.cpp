#include "managed_reader_harness.hpp"
#include "packed_store_harness.hpp"
#include "pe_reader_harness.hpp"
#include "provider_snapshot_harness.hpp"
#include "schema_v9_harness.hpp"
#include "search_query_harness.hpp"
#include "mcp_client_auth_harness.hpp"
#include "analysis_handlers_harness.hpp"
#include "composite_handlers_harness.hpp"
#include "contract_generation_harness.hpp"
#include "core_handlers_harness.hpp"
#include "debugger_handlers_harness.hpp"
#include "memory_handlers_harness.hpp"
#include "modify_handlers_harness.hpp"
#include "protocol_core_harness.hpp"
#include "python_handler_harness.hpp"
#include "routing_extensions_harness.hpp"
#include "signature_handlers_harness.h"
#include "stack_handlers_harness.hpp"
#include "survey_handler_harness.hpp"
#include "type_handlers_harness.hpp"
#include "workspace_adapter_harness.hpp"

#include <Windows.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>

namespace {

std::filesystem::path scratch_root(const char* identity)
{
    return std::filesystem::temp_directory_path() /
        (std::string("aida-c03-") + identity + "-" + std::to_string(GetCurrentProcessId()));
}

bool report(bool passed, const std::string& failure)
{
    if (!passed)
        std::cerr << failure << '\n';
    return passed;
}

}

int main()
{
#if defined(AIDA_C03_ENTRY_PROVIDER_SNAPSHOT)
    const auto root = scratch_root("provider-snapshot");
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    try {
        aida::analysis::c03::test::run_provider_snapshot_harness(root);
        std::filesystem::remove_all(root, ignored);
        return 0;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root, ignored);
        std::cerr << error.what() << '\n';
        return 1;
    }
#elif defined(AIDA_C03_ENTRY_PACKED_STORE)
    try {
        aida::analysis::c03_test::run_packed_store_harness();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
#elif defined(AIDA_C03_ENTRY_PE_READER)
    const auto root = scratch_root("pe-reader");
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    try {
        aida::analysis::c03_test::run_pe_reader_harness(root);
        std::filesystem::remove_all(root, ignored);
        return 0;
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root, ignored);
        std::cerr << error.what() << '\n';
        return 1;
    }
#elif defined(AIDA_C03_ENTRY_MANAGED_READER)
    try {
        aida::analysis::c03_test::run_managed_reader_harness();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
#elif defined(AIDA_C03_ENTRY_PROTOCOL_CORE)
    std::string failure;
    return report(aida::standalone::tests::mcp_compat::run_protocol_core_harness(failure), failure) ? 0 : 1;
#elif defined(AIDA_C03_ENTRY_WORKSPACE_ADAPTER)
    std::string failure;
    return report(aida::standalone::tests::mcp_compat::run_workspace_adapter_harness(failure), failure) ? 0 : 1;
#elif defined(AIDA_C03_ENTRY_SEARCH_QUERY)
    std::string failure;
    return report(aida::analysis::c03::run_search_query_harness(failure), failure) ? 0 : 1;
#elif defined(AIDA_C03_ENTRY_SCHEMA_V9)
    const auto summary = aida::analysis::run_all_schema_v9_fixtures();
    for (const auto& result : summary.results) {
        if (!result.passed)
            std::cerr << result.name << ": " << result.message << '\n';
    }
    return summary.failed == 0 ? 0 : 1;
#elif defined(AIDA_C03_ENTRY_MCP_COMPATIBILITY)
    using namespace aida::standalone::tests::mcp_compat;
    bool passed = true;
    const auto run = [&](const char* name, const auto& harness) {
        std::string failure;
        if (!harness(failure)) {
            std::cerr << name << ": " << failure << '\n';
            passed = false;
        }
    };
    run("contract_generation", run_contract_generation_harness);
    run("analysis_handlers", run_analysis_handlers_harness);
    run("composite_handlers", run_composite_handlers_harness);
    run("core_handlers", run_core_handlers_harness);
    run("debugger_handlers", run_debugger_handlers_harness);
    run("memory_handlers", run_memory_handlers_harness);
    run("modify_handlers", run_modify_handlers_harness);
    run("python_handler", run_python_handler_harness);
    run("signature_handlers", run_signature_handlers_harness);
    run("stack_handlers", run_stack_handlers_harness);
    run("survey_handler", run_survey_handler_harness);
    run("type_handlers", run_type_handlers_harness);
    run("routing_extensions", run_routing_extensions_harness);
    return passed ? 0 : 1;
#elif defined(AIDA_C03_ENTRY_MCP_CLIENT_AUTH)
    std::string failure;
    return report(aida::standalone::tests::c03::security::run_mcp_client_auth_harness(failure), failure) ? 0 : 1;
#else
#error An AiDA C03 generated entrypoint identity is required
#endif
}
