include_guard(GLOBAL)

if(NOT DEFINED STANDALONE_ROOT)
    message(FATAL_ERROR "AiDA C03 safe-headless manifest requires STANDALONE_ROOT")
endif()

set(AIDA_C03_B01_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
)

set(AIDA_C03_B13_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
)

set(AIDA_C03_DECOMPILER_CONTRACT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
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
    ${AIDA_C03_B13_STANDALONE_SOURCES}
    ${AIDA_C03_DECOMPILER_CONTRACT_SOURCES}
    ${AIDA_C03_B14_STANDALONE_SOURCES}
    ${AIDA_C03_B20_STANDALONE_SOURCES}
    ${AIDA_C03_B21_STANDALONE_SOURCES}
    ${AIDA_C03_B23_STANDALONE_SOURCES}
    ${AIDA_C03_B29_STANDALONE_SOURCES}
    ${AIDA_C03_B30_STANDALONE_SOURCES}
)
list(REMOVE_DUPLICATES AIDA_C03_WAVE_B_STANDALONE_SOURCES)

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

function(aida_c03_configure_safe_headless_target target package mode)
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
        LABELS "c03;safe-headless;wave-b;${package}"
    )
endfunction()

function(aida_c03_register_safe_headless_target)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "TARGET;PACKAGE;MODE;OUTPUT_NAME" "SOURCES;LINK_LIBRARIES;ARGUMENTS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest entry is malformed: ${_aida_c03_UNPARSED_ARGUMENTS};${_aida_c03_KEYWORDS_MISSING_VALUES}")
    endif()
    if(NOT _aida_c03_TARGET OR NOT _aida_c03_PACKAGE OR NOT _aida_c03_MODE)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest entry is incomplete")
    endif()
    if(NOT _aida_c03_TARGET MATCHES "^aida_c03_[a-z0-9_]+$")
        message(FATAL_ERROR "AiDA C03 safe-headless target name is invalid: ${_aida_c03_TARGET}")
    endif()
    if(NOT _aida_c03_PACKAGE MATCHES "^B[0-9][0-9]$")
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
    if(_aida_c03_LINK_LIBRARIES)
        target_link_libraries(${_aida_c03_TARGET} PRIVATE ${_aida_c03_LINK_LIBRARIES})
    endif()
    if(_aida_c03_OUTPUT_NAME)
        set_target_properties(${_aida_c03_TARGET} PROPERTIES OUTPUT_NAME "${_aida_c03_OUTPUT_NAME}")
    endif()
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_SAFE_HEADLESS_TARGETS ${_aida_c03_TARGET})
    if(_aida_c03_MODE STREQUAL "RUNNABLE")
        add_test(NAME ${_aida_c03_TARGET}
            COMMAND $<TARGET_FILE:${_aida_c03_TARGET}> ${_aida_c03_ARGUMENTS})
        set_tests_properties(${_aida_c03_TARGET} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            TIMEOUT 60
            LABELS "c03;safe-headless;wave-b;${_aida_c03_PACKAGE}"
        )
        set_property(GLOBAL APPEND PROPERTY AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS ${_aida_c03_TARGET})
    endif()
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
        MODE COMPILE_ONLY
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/provider_snapshot_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
            "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
            "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
            "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        LINK_LIBRARIES bcrypt
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
        LINK_LIBRARIES bcrypt advapi32 userenv
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b14_native_decompiler_worker
        PACKAGE B14
        MODE BUILD_ONLY
        OUTPUT_NAME AiDA_NativeDecompilerWorker
        SOURCES
            "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        LINK_LIBRARIES bcrypt
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b14_fake_native_decompiler_worker
        PACKAGE B14
        MODE BUILD_ONLY
        OUTPUT_NAME fake_native_decompiler_worker
        SOURCES
            "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        LINK_LIBRARIES bcrypt advapi32 ws2_32
    )
    aida_c03_register_safe_headless_target(
        TARGET aida_c03_b20_semantic_refiner_harness
        PACKAGE B20
        MODE RUNNABLE
        SOURCES
            "${STANDALONE_ROOT}/../tests/c03/semantic_refiner_harness.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
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

    get_property(_aida_c03_targets GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_TARGETS)
    get_property(_aida_c03_runnable_targets GLOBAL PROPERTY AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS)
    list(LENGTH _aida_c03_targets _aida_c03_target_count)
    list(LENGTH _aida_c03_runnable_targets _aida_c03_runnable_count)
    if(NOT _aida_c03_target_count EQUAL 10 OR NOT _aida_c03_runnable_count EQUAL 5)
        message(FATAL_ERROR "AiDA C03 safe-headless manifest cardinality is invalid: targets=${_aida_c03_target_count} runnable=${_aida_c03_runnable_count}")
    endif()
    aida_c03_reject_forbidden_target_links(${_aida_c03_targets})
    add_custom_target(aida_c03_safe_headless_harnesses DEPENDS ${_aida_c03_targets})
    set_target_properties(aida_c03_safe_headless_harnesses PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;safe-headless;wave-b"
    )
    set(AIDA_C03_SAFE_HEADLESS_TARGETS "${_aida_c03_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_RUNNABLE_TARGETS "${_aida_c03_runnable_targets}" PARENT_SCOPE)
endfunction()
