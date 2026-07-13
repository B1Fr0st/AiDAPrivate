include_guard(GLOBAL)

if(NOT DEFINED STANDALONE_ROOT)
    message(FATAL_ERROR "AiDA C03 safe-headless manifest requires STANDALONE_ROOT")
endif()

set(AIDA_C03_B01_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/../tests/c03/driver_bridge_stub.cpp"
)

set(AIDA_C03_B05_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decode/x86_tile_decoder.cpp"
)

set(AIDA_C03_B07_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/container/streaming_member_provider.cpp"
)

set(AIDA_C03_B13_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
)

set(AIDA_C03_DECOMPILER_CONTRACT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
)

set(AIDA_C03_B14_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
)

set(AIDA_C03_B20_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
)

set(AIDA_C03_B21_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
)

set(AIDA_C03_B22_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_result.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/schema_runtime.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_tool_contract.cpp"
)

set(AIDA_C03_B23_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
)

set(AIDA_C03_B29_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
)

set(AIDA_C03_B30_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
)

set(AIDA_C03_WAVE_B_STANDALONE_SOURCES
    ${AIDA_C03_B01_STANDALONE_SOURCES}
    ${AIDA_C03_B05_STANDALONE_SOURCES}
    ${AIDA_C03_B07_STANDALONE_SOURCES}
    ${AIDA_C03_B13_STANDALONE_SOURCES}
    ${AIDA_C03_DECOMPILER_CONTRACT_SOURCES}
    ${AIDA_C03_B14_STANDALONE_SOURCES}
    ${AIDA_C03_B20_STANDALONE_SOURCES}
    ${AIDA_C03_B21_STANDALONE_SOURCES}
    ${AIDA_C03_B22_STANDALONE_SOURCES}
    ${AIDA_C03_B23_STANDALONE_SOURCES}
    ${AIDA_C03_B29_STANDALONE_SOURCES}
    ${AIDA_C03_B30_STANDALONE_SOURCES}
)
list(REMOVE_DUPLICATES AIDA_C03_WAVE_B_STANDALONE_SOURCES)

set(AIDA_C03_WORKBENCH_FOUNDATION_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
    "${STANDALONE_ROOT}/core/workbench/split_tree.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/navigator/workbench_navigator.cpp"
    "${STANDALONE_ROOT}/core/workbench/inspector/workbench_inspector_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host.cpp"
)

set(AIDA_C03_WAVE_C_MCP_HANDLER_SOURCES
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/analysis.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/composite.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/core.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/debugger.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/memory.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/modify.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/python.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signatures.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/stack.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/survey.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/types.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/routing_extensions.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
)

set(AIDA_C03_WAVE_C_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
    "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
    ${AIDA_C03_WAVE_C_MCP_HANDLER_SOURCES}
    ${AIDA_C03_WORKBENCH_FOUNDATION_STANDALONE_SOURCES}
    "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
    "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
)
list(REMOVE_DUPLICATES AIDA_C03_WAVE_C_STANDALONE_SOURCES)

set(AIDA_C03_WAVE_D_SHARED_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/mcp/compat/mcp_server_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
)
list(REMOVE_DUPLICATES AIDA_C03_WAVE_D_SHARED_STANDALONE_SOURCES)

function(aida_c03_require_sources descriptor)
    if(NOT ARGN)
        message(FATAL_ERROR "AiDA C03 source list is empty: ${descriptor}")
    endif()
    foreach(_aida_c03_source IN LISTS ARGN)
        if(NOT IS_ABSOLUTE "${_aida_c03_source}")
            message(FATAL_ERROR "AiDA C03 source path is not absolute: ${descriptor} -> ${_aida_c03_source}")
        endif()
        if(NOT EXISTS "${_aida_c03_source}")
            message(FATAL_ERROR "AiDA C03 source is missing: ${descriptor} -> ${_aida_c03_source}")
        endif()
    endforeach()
endfunction()

aida_c03_require_sources("Wave B standalone registration" ${AIDA_C03_WAVE_B_STANDALONE_SOURCES})
aida_c03_require_sources("Wave C standalone registration" ${AIDA_C03_WAVE_C_STANDALONE_SOURCES})
aida_c03_require_sources("Wave D shared standalone registration" ${AIDA_C03_WAVE_D_SHARED_STANDALONE_SOURCES})

set(AIDA_C03_GENERATED_HARNESS_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/c03")
file(MAKE_DIRECTORY "${AIDA_C03_GENERATED_HARNESS_DIRECTORY}")
set(AIDA_C03_B01_PROVIDER_SNAPSHOT_HARNESS_MAIN
    "${AIDA_C03_GENERATED_HARNESS_DIRECTORY}/provider_snapshot_harness_main.cpp")
set(AIDA_C03_B22_PROTOCOL_CORE_HARNESS_MAIN
    "${AIDA_C03_GENERATED_HARNESS_DIRECTORY}/protocol_core_harness_main.cpp")
set(AIDA_C03_C04_SEARCH_QUERY_HARNESS_MAIN
    "${AIDA_C03_GENERATED_HARNESS_DIRECTORY}/search_query_harness_main.cpp")
set(AIDA_C03_C05_SCHEMA_V9_HARNESS_MAIN
    "${AIDA_C03_GENERATED_HARNESS_DIRECTORY}/schema_v9_harness_main.cpp")
configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/c03_provider_snapshot_harness_main.cpp.in"
    "${AIDA_C03_B01_PROVIDER_SNAPSHOT_HARNESS_MAIN}"
    @ONLY)
configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/c03_protocol_core_harness_main.cpp.in"
    "${AIDA_C03_B22_PROTOCOL_CORE_HARNESS_MAIN}"
    @ONLY)
file(WRITE "${AIDA_C03_C04_SEARCH_QUERY_HARNESS_MAIN}" [=[
#include "search_query_harness.hpp"

#include <iostream>
#include <string>

int main()
{
    std::string failure;
    if (!aida::analysis::c03::run_search_query_harness(failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
]=])
file(WRITE "${AIDA_C03_C05_SCHEMA_V9_HARNESS_MAIN}" [=[
#include "schema_v9_harness.hpp"

#include <iostream>

int main()
{
    const auto summary = aida::analysis::run_all_schema_v9_fixtures();
    if (summary.failed == 0)
        return 0;
    for (const auto& result : summary.results) {
        if (!result.passed)
            std::cerr << result.name << ": " << result.message << '\n';
    }
    return 1;
}
]=])
aida_c03_require_sources("C03 generated harness entrypoints"
    "${AIDA_C03_B01_PROVIDER_SNAPSHOT_HARNESS_MAIN}"
    "${AIDA_C03_B22_PROTOCOL_CORE_HARNESS_MAIN}"
    "${AIDA_C03_C04_SEARCH_QUERY_HARNESS_MAIN}"
    "${AIDA_C03_C05_SCHEMA_V9_HARNESS_MAIN}")

function(aida_c03_require_z3 descriptor)
    if(NOT Z3_FOUND OR NOT Z3_INCLUDE_DIRS OR NOT Z3_LIBRARIES)
        message(FATAL_ERROR "AiDA C03 Z3 dependency is not configured: ${descriptor}")
    endif()
    foreach(_aida_c03_z3_include IN LISTS Z3_INCLUDE_DIRS)
        if(NOT IS_DIRECTORY "${_aida_c03_z3_include}" OR
           NOT EXISTS "${_aida_c03_z3_include}/z3.h")
            message(FATAL_ERROR "AiDA C03 Z3 include dependency is missing: ${descriptor} -> ${_aida_c03_z3_include}")
        endif()
    endforeach()
    foreach(_aida_c03_z3_library IN LISTS Z3_LIBRARIES)
        if(NOT EXISTS "${_aida_c03_z3_library}")
            message(FATAL_ERROR "AiDA C03 Z3 library dependency is missing: ${descriptor} -> ${_aida_c03_z3_library}")
        endif()
    endforeach()
endfunction()

function(aida_c03_configure_safe_headless_target target package mode)
    string(SUBSTRING "${package}" 0 1 _aida_c03_wave_prefix)
    if(_aida_c03_wave_prefix STREQUAL "B")
        set(_aida_c03_wave_label "wave-b")
    elseif(_aida_c03_wave_prefix STREQUAL "C")
        set(_aida_c03_wave_label "wave-c")
    else()
        message(FATAL_ERROR "AiDA C03 safe-headless wave label is invalid: ${package}")
    endif()
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
        "${STANDALONE_ROOT}"
        "${STANDALONE_ROOT}/core"
        "${STANDALONE_ROOT}/core/analysis"
        "${STANDALONE_ROOT}/core/analysis/workspace"
        "${STANDALONE_ROOT}/core/analysis/decompiler"
        "${STANDALONE_ROOT}/core/mcp"
        "${STANDALONE_ROOT}/core/mcp/compat"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs"
    )
    target_compile_definitions(${target} PRIVATE
        __NT__
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
        AIDA_STANDALONE
    )
    target_compile_options(${target} PRIVATE
        /W3
        /EHsc
        /Zc:__cplusplus
        /permissive-
        /Zp8
        /bigobj
    )
    if(TARGET aida_hardening)
        target_link_libraries(${target} PRIVATE aida_hardening)
    endif()
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c03/$<CONFIG>"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c03/$<CONFIG>"
        PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/c03/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_PACKAGE "${package}"
        AIDA_C03_HARNESS_MODE "${mode}"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;safe-headless;${_aida_c03_wave_label};${package}"
    )
endfunction()

function(aida_c03_register_safe_headless_target)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "TARGET;PACKAGE;MODE;OUTPUT_NAME" "SOURCES;INCLUDE_DIRECTORIES;LINK_LIBRARIES;ARGUMENTS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest entry is malformed: ${_aida_c03_UNPARSED_ARGUMENTS};${_aida_c03_KEYWORDS_MISSING_VALUES}")
    endif()
    if(NOT _aida_c03_TARGET OR NOT _aida_c03_PACKAGE OR NOT _aida_c03_MODE)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest entry is incomplete")
    endif()
    if(NOT _aida_c03_TARGET MATCHES "^aida_c03_[a-z0-9_]+$")
        message(FATAL_ERROR "AiDA C03 safe-headless target name is invalid: ${_aida_c03_TARGET}")
    endif()
    if(NOT _aida_c03_PACKAGE MATCHES "^[BC][0-9][0-9]$")
        message(FATAL_ERROR "AiDA C03 package label is invalid: ${_aida_c03_PACKAGE}")
    endif()
    if(TARGET ${_aida_c03_TARGET})
        message(FATAL_ERROR "AiDA C03 safe-headless target already exists: ${_aida_c03_TARGET}")
    endif()
    aida_c03_require_sources("${_aida_c03_PACKAGE}/${_aida_c03_TARGET}" ${_aida_c03_SOURCES})
    if(_aida_c03_MODE STREQUAL "RUNNABLE" OR _aida_c03_MODE STREQUAL "BUILD_ONLY")
        add_executable(${_aida_c03_TARGET} ${_aida_c03_SOURCES})
    elseif(_aida_c03_MODE STREQUAL "COMPILE_ONLY")
        if(_aida_c03_ARGUMENTS)
            message(FATAL_ERROR "AiDA C03 compile-only target cannot declare runtime arguments: ${_aida_c03_TARGET}")
        endif()
        add_library(${_aida_c03_TARGET} STATIC ${_aida_c03_SOURCES})
    else()
        message(FATAL_ERROR "AiDA C03 safe-headless mode is invalid: ${_aida_c03_TARGET} -> ${_aida_c03_MODE}")
    endif()
    aida_c03_configure_safe_headless_target(${_aida_c03_TARGET} ${_aida_c03_PACKAGE} ${_aida_c03_MODE})
    if(_aida_c03_INCLUDE_DIRECTORIES)
        target_include_directories(${_aida_c03_TARGET} PRIVATE ${_aida_c03_INCLUDE_DIRECTORIES})
    endif()
    if(_aida_c03_LINK_LIBRARIES)
        target_link_libraries(${_aida_c03_TARGET} PRIVATE ${_aida_c03_LINK_LIBRARIES})
    endif()
    if(_aida_c03_OUTPUT_NAME)
        set_target_properties(${_aida_c03_TARGET} PROPERTIES OUTPUT_NAME "${_aida_c03_OUTPUT_NAME}")
    endif()
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_SAFE_HEADLESS_TARGETS ${_aida_c03_TARGET})
    if(_aida_c03_MODE STREQUAL "RUNNABLE")
        string(SUBSTRING "${_aida_c03_PACKAGE}" 0 1 _aida_c03_test_wave_prefix)
        if(_aida_c03_test_wave_prefix STREQUAL "B")
            set(_aida_c03_test_wave_label "wave-b")
        else()
            set(_aida_c03_test_wave_label "wave-c")
        endif()
        add_test(NAME ${_aida_c03_TARGET}
            COMMAND $<TARGET_FILE:${_aida_c03_TARGET}> ${_aida_c03_ARGUMENTS})
        set_tests_properties(${_aida_c03_TARGET} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            TIMEOUT 60
            LABELS "c03;safe-headless;${_aida_c03_test_wave_label};${_aida_c03_PACKAGE}"
        )
        set_property(GLOBAL APPEND PROPERTY AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS ${_aida_c03_TARGET})
    endif()
endfunction()

function(aida_c03_register_native_decompiler_worker_package application_target)
    if(NOT TARGET ${application_target})
        message(FATAL_ERROR "AiDA C03 native worker package requires an application target: ${application_target}")
    endif()
    if(TARGET aida_c03_b14_native_decompiler_worker OR
       TARGET aida_c03_b14_native_worker_package_manifest)
        message(FATAL_ERROR "AiDA C03 native worker package was registered more than once")
    endif()
    if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)
        message(FATAL_ERROR "AiDA C03 native worker package requires a local Python3 interpreter")
    endif()

    set(_aida_c03_native_worker_source
        "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp")
    set(_aida_c03_native_worker_contract_source
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp")
    set(_aida_c03_native_worker_identity_source
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp")
    set(_aida_c03_native_worker_manifest_tool
        "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_native_worker_manifest.py")
    set(_aida_c03_native_worker_manifest_contract
        "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_native_worker_manifest.json")
    aida_c03_require_sources("B14 native decompiler worker"
        "${_aida_c03_native_worker_source}"
        "${_aida_c03_native_worker_contract_source}"
        "${_aida_c03_native_worker_identity_source}"
        "${_aida_c03_native_worker_manifest_tool}"
        "${_aida_c03_native_worker_manifest_contract}")

    add_executable(aida_c03_b14_native_decompiler_worker
        "${_aida_c03_native_worker_source}"
        "${_aida_c03_native_worker_contract_source}"
        "${_aida_c03_native_worker_identity_source}")
    aida_c03_configure_safe_headless_target(aida_c03_b14_native_decompiler_worker B14 BUILD_ONLY)
    target_link_libraries(aida_c03_b14_native_decompiler_worker PRIVATE bcrypt)
    set_target_properties(aida_c03_b14_native_decompiler_worker PROPERTIES
        OUTPUT_NAME "AiDA_NativeDecompilerWorker"
        FOLDER "Packaging/C03"
        AIDA_C03_SAFE_HEADLESS FALSE
        AIDA_C03_PACKAGE_ROLE "native-decompiler-worker"
        LABELS "c03;packaging;wave-b;B14")
    aida_c03_reject_forbidden_target_links(aida_c03_b14_native_decompiler_worker)

    add_custom_target(aida_c03_b14_native_worker_package_manifest
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${application_target}>/deps"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:aida_c03_b14_native_decompiler_worker>"
            "$<TARGET_FILE_DIR:${application_target}>/deps/AiDA_NativeDecompilerWorker.exe"
        COMMAND "${Python3_EXECUTABLE}" "${_aida_c03_native_worker_manifest_tool}"
            --contract "${_aida_c03_native_worker_manifest_contract}"
            --package-root "$<TARGET_FILE_DIR:${application_target}>"
            --worker "$<TARGET_FILE_DIR:${application_target}>/deps/AiDA_NativeDecompilerWorker.exe"
        DEPENDS
            aida_c03_b14_native_decompiler_worker
            "${_aida_c03_native_worker_manifest_tool}"
            "${_aida_c03_native_worker_manifest_contract}"
        COMMENT "Staging the native decompiler worker and its locked manifest beside ${application_target}..."
        VERBATIM)
    set_target_properties(aida_c03_b14_native_worker_package_manifest PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "native-decompiler-worker-manifest"
        AIDA_C03_PACKAGE_OUTPUTS "deps/AiDA_NativeDecompilerWorker.exe;deps/AiDA_NativeDecompilerWorker.manifest.bin;deps/AiDA_NativeDecompilerWorker.manifest.sha256"
        LABELS "c03;packaging;wave-b;B14")
    add_dependencies(${application_target} aida_c03_b14_native_worker_package_manifest)
endfunction()

function(aida_c03_register_analysis_python_worker_package application_target)
    if(NOT TARGET ${application_target})
        message(FATAL_ERROR "AiDA C03 analysis Python worker package requires an application target: ${application_target}")
    endif()
    if(TARGET aida_c03_b24_analysis_python_worker_source_contract OR
       TARGET aida_c03_b24_analysis_python_worker_package_manifest)
        message(FATAL_ERROR "AiDA C03 analysis Python worker package was registered more than once")
    endif()
    file(READ "${AIDA_C03_WORKER_MANIFEST_LOCK}" _aida_c03_worker_lock_json)
    string(JSON _aida_c03_worker_lock_no_fetch GET "${_aida_c03_worker_lock_json}" no_network_fetch)
    string(JSON _aida_c03_worker_id GET "${_aida_c03_worker_lock_json}" analysis_python_worker id)
    string(JSON _aida_c03_worker_no_fetch GET "${_aida_c03_worker_lock_json}" analysis_python_worker network_fetch_forbidden)
    string(JSON _aida_c03_worker_pinned_freezer GET "${_aida_c03_worker_lock_json}" analysis_python_worker pinned_freezer_required)
    string(JSON _aida_c03_worker_source_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker source path)
    string(JSON _aida_c03_worker_source_sha256 GET "${_aida_c03_worker_lock_json}" analysis_python_worker source sha256)
    string(JSON _aida_c03_worker_build_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker build_script path)
    string(JSON _aida_c03_worker_build_sha256 GET "${_aida_c03_worker_lock_json}" analysis_python_worker build_script sha256)
    string(JSON _aida_c03_worker_materializer_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker manifest_materializer path)
    string(JSON _aida_c03_worker_materializer_sha256 GET "${_aida_c03_worker_lock_json}" analysis_python_worker manifest_materializer sha256)
    string(JSON _aida_c03_worker_artifact_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker prebuilt_artifact source_path)
    string(JSON _aida_c03_worker_package_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker prebuilt_artifact package_relative_path)
    string(JSON _aida_c03_worker_manifest_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker prebuilt_artifact manifest_relative_path)
    string(JSON _aida_c03_worker_digest_relative GET "${_aida_c03_worker_lock_json}" analysis_python_worker prebuilt_artifact manifest_digest_relative_path)
    string(JSON _aida_c03_worker_artifact_required GET "${_aida_c03_worker_lock_json}" analysis_python_worker prebuilt_artifact required_for_staging)

    if(NOT _aida_c03_worker_lock_no_fetch OR
       NOT _aida_c03_worker_id STREQUAL "analysis_python" OR
       NOT _aida_c03_worker_no_fetch OR NOT _aida_c03_worker_pinned_freezer OR
       NOT _aida_c03_worker_artifact_required OR
       NOT _aida_c03_worker_source_relative STREQUAL "src/standalone/workers/analysis_python/analysis_python_worker.py" OR
       NOT _aida_c03_worker_build_relative STREQUAL "src/standalone/workers/analysis_python/build_frozen_worker.ps1" OR
       NOT _aida_c03_worker_materializer_relative STREQUAL "src/standalone/workers/analysis_python/materialize_python_worker_manifest.py" OR
       NOT _aida_c03_worker_artifact_relative STREQUAL ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.exe" OR
       NOT _aida_c03_worker_package_relative STREQUAL "deps/AiDA_AnalysisPythonWorker.exe" OR
       NOT _aida_c03_worker_manifest_relative STREQUAL "deps/AiDA_AnalysisPythonWorker.manifest.bin" OR
       NOT _aida_c03_worker_digest_relative STREQUAL "deps/AiDA_AnalysisPythonWorker.manifest.sha256")
        message(FATAL_ERROR "AiDA C03 analysis Python worker source manifest violates the locked package contract")
    endif()

    set(_aida_c03_worker_source "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_worker_source_relative}")
    set(_aida_c03_worker_build "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_worker_build_relative}")
    set(_aida_c03_worker_materializer "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_worker_materializer_relative}")
    set(_aida_c03_worker_artifact "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_worker_artifact_relative}")
    aida_c03_require_path_sha256("${_aida_c03_worker_source}" "${_aida_c03_worker_source_sha256}" "B24 analysis Python worker source")
    aida_c03_require_path_sha256("${_aida_c03_worker_build}" "${_aida_c03_worker_build_sha256}" "B24 analysis Python worker frozen-build policy")
    aida_c03_require_path_sha256("${_aida_c03_worker_materializer}" "${_aida_c03_worker_materializer_sha256}" "B24 analysis Python worker manifest materializer")

    add_custom_target(aida_c03_b24_analysis_python_worker_source_contract SOURCES
        "${_aida_c03_worker_source}"
        "${_aida_c03_worker_build}"
        "${_aida_c03_worker_materializer}"
        "${AIDA_C03_WORKER_MANIFEST_SCHEMA}"
        "${AIDA_C03_WORKER_MANIFEST_LOCK}")
    set_target_properties(aida_c03_b24_analysis_python_worker_source_contract PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_SAFE_HEADLESS FALSE
        AIDA_C03_PACKAGE_ROLE "analysis-python-worker-source-contract"
        LABELS "c03;packaging;wave-b;B24")
    add_dependencies(${application_target} aida_c03_b24_analysis_python_worker_source_contract)

    if(NOT EXISTS "${_aida_c03_worker_artifact}")
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER
            "missing locked prebuilt artifact: ${_aida_c03_worker_artifact}"
            CACHE INTERNAL "" FORCE)
        set_property(TARGET ${application_target} PROPERTY
            AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER
            "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
        message(STATUS "AiDA C03 B24 analysis Python worker staging blocked: ${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
        return()
    endif()
    if(IS_DIRECTORY "${_aida_c03_worker_artifact}")
        message(FATAL_ERROR "AiDA C03 analysis Python worker artifact is not a file: ${_aida_c03_worker_artifact}")
    endif()
    if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)
        message(FATAL_ERROR "AiDA C03 analysis Python worker package requires a local Python3 interpreter")
    endif()

    unset(AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER CACHE)
    add_custom_target(aida_c03_b24_analysis_python_worker_package_manifest
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${application_target}>/deps"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_aida_c03_worker_artifact}"
            "$<TARGET_FILE_DIR:${application_target}>/${_aida_c03_worker_package_relative}"
        COMMAND "${Python3_EXECUTABLE}" "${_aida_c03_worker_materializer}"
            --package-root "$<TARGET_FILE_DIR:${application_target}>"
            --worker "$<TARGET_FILE_DIR:${application_target}>/${_aida_c03_worker_package_relative}"
            --manifest "$<TARGET_FILE_DIR:${application_target}>/${_aida_c03_worker_manifest_relative}"
            --digest "$<TARGET_FILE_DIR:${application_target}>/${_aida_c03_worker_digest_relative}"
        DEPENDS
            aida_c03_b24_analysis_python_worker_source_contract
            "${_aida_c03_worker_artifact}"
            "${_aida_c03_worker_materializer}"
        COMMENT "Staging the analysis Python worker and its locked manifest beside ${application_target}..."
        VERBATIM)
    set_target_properties(aida_c03_b24_analysis_python_worker_package_manifest PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_SAFE_HEADLESS FALSE
        AIDA_C03_PACKAGE_ROLE "analysis-python-worker-manifest"
        AIDA_C03_PACKAGE_OUTPUTS "${_aida_c03_worker_package_relative};${_aida_c03_worker_manifest_relative};${_aida_c03_worker_digest_relative}"
        LABELS "c03;packaging;wave-b;B24")
    add_dependencies(${application_target} aida_c03_b24_analysis_python_worker_package_manifest)
endfunction()

function(aida_c03_register_safe_headless_targets)
    if(NOT WIN32 OR NOT MSVC)
        message(FATAL_ERROR "AiDA C03 safe-headless targets require Windows and MSVC")
    endif()
    if(TARGET aida_c03_safe_headless_harnesses)
        message(FATAL_ERROR "AiDA C03 safe-headless targets were registered more than once")
    endif()
    if(NOT COMMAND aida_c03_reject_forbidden_target_links)
        message(FATAL_ERROR "AiDA C03 dependency policy was not loaded before safe-headless registration")
    endif()
    set_property(GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_TARGETS "")
    set_property(GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS "")

    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b01_provider_snapshot_harness
        PACKAGE B01
        MODE RUNNABLE
        SOURCES
            "${AIDA_C03_B01_PROVIDER_SNAPSHOT_HARNESS_MAIN}"
            "${STANDALONE_ROOT}/../tests/c03/provider_snapshot_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
            "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
            "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
            "${STANDALONE_ROOT}/../tests/c03/driver_bridge_stub.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_require_components(zydis Zydis)
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b05_x86_tile_decoder_harness
        PACKAGE B05
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/x86_tile_decoder_harness.cpp"
            ${AIDA_C03_B05_STANDALONE_SOURCES}
            ${AIDA_C03_B01_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
        LINK_LIBRARIES Zydis bcrypt
    )
    aida_c03_require_components(zydis Zydis)
    aida_c03_require_components(zstd zstd_static)
    aida_c03_require_components(liblzma_minimal liblzma)
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b07_container_stream_harness
        PACKAGE B07
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/container_stream_harness.cpp"
            ${AIDA_C03_B07_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
            "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
            "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
            "${STANDALONE_ROOT}/../tests/c03/driver_bridge_stub.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${zlib_SOURCE_DIR}"
            "${zlib_BINARY_DIR}"
            "${zstd_SOURCE_DIR}/../lib"
            "${xz_SOURCE_DIR}/src/liblzma/api"
        LINK_LIBRARIES zlibstatic libzstd_static liblzma bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b13_metrics_contract_harness
        PACKAGE B13
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/metrics_contract_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b14_native_worker_protocol_harness
        PACKAGE B14
        MODE COMPILE_ONLY
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/native_worker_protocol_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        LINK_LIBRARIES bcrypt advapi32 userenv
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b14_fake_native_decompiler_worker
        PACKAGE B14
        MODE BUILD_ONLY
        OUTPUT_NAME fake_native_decompiler_worker
        SOURCES
            "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        LINK_LIBRARIES bcrypt advapi32 ws2_32
    )
    aida_c03_require_z3("B20 semantic refiner harness")
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b20_semantic_refiner_harness
        PACKAGE B20
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/semantic_refiner_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${Z3_INCLUDE_DIRS}"
        LINK_LIBRARIES "${Z3_LIBRARIES}"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b21_pseudocode_renderer_harness
        PACKAGE B21
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/pseudocode_renderer_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b22_protocol_core_harness
        PACKAGE B22
        MODE RUNNABLE
        SOURCES
            "${AIDA_C03_B22_PROTOCOL_CORE_HARNESS_MAIN}"
            "${STANDALONE_ROOT}/../tests/mcp_compat/protocol_core_harness.cpp"
            ${AIDA_C03_B22_STANDALONE_SOURCES}
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/mcp_compat"
            "${json_schema_validator_SOURCE_DIR}/src"
        LINK_LIBRARIES nlohmann_json_schema_validator
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b23_workspace_adapter_harness
        PACKAGE B23
        MODE COMPILE_ONLY
        SOURCES
            "${STANDALONE_ROOT}/../tests/mcp_compat/workspace_adapter_harness.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b29_overlay_journal_v9_harness
        PACKAGE B29
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/overlay_journal_v9_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b30_live_snapshot_harness
        PACKAGE B30
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/live_snapshot_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
            "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c01_tile_decode_orchestrator_harness
        PACKAGE C01
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/tile_decode_orchestrator_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
            "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
            "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
            "${STANDALONE_ROOT}/core/analysis/packed_analysis_store.cpp"
            ${AIDA_C03_B01_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c02_function_cfg_callgraph_harness
        PACKAGE C02
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/function_cfg_callgraph_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
            "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c03_xref_discovery_harness
        PACKAGE C03
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/xref_discovery_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
            "${STANDALONE_ROOT}/core/analysis/readers/macho_reader.cpp"
            ${AIDA_C03_B01_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_require_components(pcre2_8bit_no_jit pcre2_8)
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c04_search_query_harness
        PACKAGE C04
        MODE RUNNABLE
        SOURCES
            "${AIDA_C03_C04_SEARCH_QUERY_HARNESS_MAIN}"
            "${STANDALONE_ROOT}/../tests/c03/search_query_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
            ${AIDA_C03_B01_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES pcre2-8 bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c05_schema_v9_harness
        PACKAGE C05
        MODE RUNNABLE
        SOURCES
            "${AIDA_C03_C05_SCHEMA_V9_HARNESS_MAIN}"
            "${STANDALONE_ROOT}/../tests/c03/schema_v9_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
            "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${DEPS_DIR}/sqlite-amalgamation-3530300"
            "${DEPS_DIR}/taskflow"
        LINK_LIBRARIES bcrypt shell32 ole32
    )
    aida_c03_require_z3("C06 decompiler service harness")
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c06_decompiler_service_harness
        PACKAGE C06
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/decompiler_service_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache_v9.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            ${AIDA_C03_B01_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${GHIDRA_DECOMP_DIR}"
            "${Z3_INCLUDE_DIRS}"
        LINK_LIBRARIES libdecomp_aida "${Z3_LIBRARIES}" bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c07_decompiler_readability_harness
        PACKAGE C07
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/decompiler_readability_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b24_fake_analysis_python_worker
        PACKAGE B24
        MODE BUILD_ONLY
        OUTPUT_NAME fake_analysis_python_worker
        SOURCES
            "${STANDALONE_ROOT}/../workers/analysis_python/fake_analysis_python_worker.cpp"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt advapi32 ws2_32
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b24_python_worker_harness
        PACKAGE B24
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/mcp_compat/python_worker_harness_main.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/python_worker_harness.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/mcp_compat"
            "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt advapi32 userenv ws2_32
        ARGUMENTS "$<TARGET_FILE:aida_c03_b24_fake_analysis_python_worker>"
    )
    add_dependencies(aida_c03_b24_python_worker_harness
        aida_c03_b24_fake_analysis_python_worker)
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c22_workbench_shell_integration
        PACKAGE C22
        MODE COMPILE_ONLY
        SOURCES
            "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c20_c22_workbench_documents_harness
        PACKAGE C22
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/workbench_documents_harness.cpp"
            ${AIDA_C03_WORKBENCH_FOUNDATION_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
            "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
            "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
            "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
            "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
            "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
        LINK_LIBRARIES bcrypt
    )
    add_dependencies(aida_c03_c20_c22_workbench_documents_harness
        aida_c03_c22_workbench_shell_integration)
    set_target_properties(aida_c03_c20_c22_workbench_documents_harness PROPERTIES
        AIDA_C03_PACKAGES "C20;C21;C22"
        LABELS "c03;safe-headless;wave-c;C20;C21;C22")
    set_tests_properties(aida_c03_c20_c22_workbench_documents_harness PROPERTIES
        LABELS "c03;safe-headless;wave-c;C20;C21;C22")
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c23_workbench_persistence_harness
        PACKAGE C23
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/workbench_persistence_harness.cpp"
            "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp"
            "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
            "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
            "${STANDALONE_ROOT}/core/workbench/split_tree.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
            "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${DEPS_DIR}/sqlite-amalgamation-3530300"
            "${DEPS_DIR}/taskflow"
        LINK_LIBRARIES bcrypt shell32 ole32
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c24_overlay_projection_harness
        PACKAGE C24
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/overlay_projection_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
            "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
            "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../tests/c03"
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c19_live_routing_integration_harness
        PACKAGE C19
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/live_routing_integration_harness.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
            "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
            ${AIDA_C03_B22_STANDALONE_SOURCES}
            ${AIDA_C03_B23_STANDALONE_SOURCES}
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${json_schema_validator_SOURCE_DIR}/src"
        LINK_LIBRARIES nlohmann_json_schema_validator
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_c19_mcp_handler_testlab_harness
        PACKAGE C19
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/harness_testlab_integration.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/analysis_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/composite_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/core_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/debugger_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/memory_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/modify_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/python_handler_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/signature_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/stack_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/survey_handler_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/type_handlers_harness.cpp"
            "${STANDALONE_ROOT}/../tests/mcp_compat/routing_extensions_harness.cpp"
            ${AIDA_C03_WAVE_C_MCP_HANDLER_SOURCES}
            ${AIDA_C03_B22_STANDALONE_SOURCES}
            ${AIDA_C03_B23_STANDALONE_SOURCES}
            "${STANDALONE_ROOT}/core/mcp/calculator_tool.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
        INCLUDE_DIRECTORIES
            "${STANDALONE_ROOT}/../tests/c03"
            "${STANDALONE_ROOT}/../tests/mcp_compat"
            "${json_schema_validator_SOURCE_DIR}/src"
        LINK_LIBRARIES nlohmann_json_schema_validator
    )
    set_target_properties(aida_c03_c19_mcp_handler_testlab_harness PROPERTIES
        AIDA_C03_PACKAGES "C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19"
        LABELS "c03;safe-headless;wave-c;C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19")
    set_tests_properties(aida_c03_c19_mcp_handler_testlab_harness PROPERTIES
        LABELS "c03;safe-headless;wave-c;C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19")

    get_property(_aida_c03_targets GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_TARGETS)
    get_property(_aida_c03_runnable_targets GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS)
    list(LENGTH _aida_c03_targets _aida_c03_target_count)
    list(LENGTH _aida_c03_runnable_targets _aida_c03_runnable_count)
    if(NOT _aida_c03_target_count EQUAL 27 OR NOT _aida_c03_runnable_count EQUAL 22)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest cardinality is invalid: targets=${_aida_c03_target_count} runnable=${_aida_c03_runnable_count}")
    endif()
    aida_c03_reject_forbidden_target_links(${_aida_c03_targets})
    add_custom_target(aida_c03_safe_headless_harnesses DEPENDS ${_aida_c03_targets})
    set_target_properties(aida_c03_safe_headless_harnesses PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;safe-headless;wave-b;wave-c"
    )
    set(AIDA_C03_SAFE_HEADLESS_TARGETS "${_aida_c03_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS "${_aida_c03_runnable_targets}" PARENT_SCOPE)
endfunction()
