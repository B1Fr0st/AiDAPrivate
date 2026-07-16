include_guard(GLOBAL)

set(AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT "${CMAKE_CURRENT_LIST_DIR}")
set(AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE "${CMAKE_CURRENT_LIST_FILE}")
set(AIDA_C03_PATH_POLICY_MODULE "${CMAKE_CURRENT_LIST_DIR}/c03_safe_headless/package_policy_fixture/aida_c03_path_policy.cmake")
set(AIDA_C03_PATH_IDENTITY_POLICY "${CMAKE_CURRENT_LIST_DIR}/c03_safe_headless/package_policy_fixture/aida_c03_path_identity.ps1")
include("${AIDA_C03_PATH_POLICY_MODULE}")

if(NOT DEFINED STANDALONE_ROOT OR NOT IS_DIRECTORY "${STANDALONE_ROOT}")
    message(FATAL_ERROR "AiDA C03 integration requires STANDALONE_ROOT")
endif()
if(NOT COMMAND aida_c03_require_components OR
   NOT COMMAND aida_c03_reject_forbidden_target_links)
    message(FATAL_ERROR "AiDA C03 dependency policy must be loaded before integration")
endif()
aida_c03_require_components(zydis Zydis)
aida_c03_require_components(zycore Zycore)
aida_c03_require_components(capstone ARM ARM64 MIPS PPC RISCV X86 detail)
aida_c03_require_components(taskflow taskflow)
aida_c03_require_components(ghidra_worker decompiler sleigh processor_specs compiler_specs)
aida_c03_require_components(triton_thorough_only triton z3_interface)
aida_c03_require_components(z3_thorough_only libz3)
aida_c03_require_components(sqlite sqlite3)
aida_c03_require_components(imgui imgui imgui_freetype imgui_impl_dx11 imgui_impl_win32)
aida_c03_require_components(zlib zlib)
aida_c03_require_components(zstd zstd_static)
aida_c03_require_components(liblzma_minimal liblzma)
aida_c03_require_components(minizip_ng_read_only mz_zip_reader)
aida_c03_require_components(pcre2_8bit_no_jit pcre2_8)
aida_c03_require_components(nlohmann_json nlohmann_json)
aida_c03_require_components(json_schema_validator nlohmann_json_schema_validator)
aida_c03_require_components(llvm_demangle_support Demangle Support)
aida_c03_require_components(managed_worker_packages ICSharpCode.Decompiler System.Collections.Immutable System.Reflection.Metadata)

set(AIDA_C03_TEST_ROOT "${STANDALONE_ROOT}/../tests/c03")
set(AIDA_C03_MCP_TEST_ROOT "${STANDALONE_ROOT}/../tests/mcp_compat")
set(AIDA_C03_WORKSPACE_TEST_ROOT "${STANDALONE_ROOT}/../tests/analysis_workspace")
set(AIDA_C03_PACKAGE_VERIFIER_SOURCE
    "${STANDALONE_ROOT}/../tools/c03_package_verifier/main.cpp")
if(NOT DEFINED ENV{LOCALAPPDATA} OR NOT IS_ABSOLUTE "$ENV{LOCALAPPDATA}")
    message(FATAL_ERROR "AiDA C03 requires the canonical per-user local application-data root")
endif()
file(TO_CMAKE_PATH "$ENV{LOCALAPPDATA}" _aida_c03_local_app_data)
file(REAL_PATH "${_aida_c03_local_app_data}" _aida_c03_local_app_data)
file(TO_CMAKE_PATH "${_aida_c03_local_app_data}" _aida_c03_local_app_data)
string(SHA256 AIDA_C03_STAGE_AUTHORITY_ID
    "aida-c03-stage-v1|${CMAKE_SOURCE_DIR}|${CMAKE_BINARY_DIR}|ninja-msvc-release")
string(SUBSTRING "${AIDA_C03_STAGE_AUTHORITY_ID}" 0 24 AIDA_C03_STAGE_AUTHORITY_ID)
set(AIDA_C03_STAGE_OWNER_ROOT
    "${_aida_c03_local_app_data}/AiDA/C03/${AIDA_C03_STAGE_AUTHORITY_ID}")
set(AIDA_C03_APPLICATION_BUILD_ROOT "${AIDA_C03_STAGE_OWNER_ROOT}/application")
set(AIDA_C03_DEVELOPER_ROOT "${AIDA_C03_STAGE_OWNER_ROOT}/developer")
set(AIDA_C03_CUSTOMER_STAGE_ANCHOR "${AIDA_C03_STAGE_OWNER_ROOT}/customer")
set(AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT "${AIDA_C03_STAGE_OWNER_ROOT}/evidence")
file(MAKE_DIRECTORY
    "${AIDA_C03_STAGE_OWNER_ROOT}"
    "${AIDA_C03_APPLICATION_BUILD_ROOT}"
    "${AIDA_C03_DEVELOPER_ROOT}"
    "${AIDA_C03_CUSTOMER_STAGE_ANCHOR}"
    "${AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT}")
set(_aida_c03_stage_owner_record
    "{\"schema\":\"aida.c03.stage-owner.v1\",\"authority_id\":\"${AIDA_C03_STAGE_AUTHORITY_ID}\",\"repository\":\"${CMAKE_SOURCE_DIR}\",\"binary\":\"${CMAKE_BINARY_DIR}\"}\n")
set(_aida_c03_stage_owner_record_path
    "${AIDA_C03_STAGE_OWNER_ROOT}/.aida-c03-stage-owner.json")
if(EXISTS "${_aida_c03_stage_owner_record_path}")
    file(READ "${_aida_c03_stage_owner_record_path}" _aida_c03_existing_stage_owner
        LIMIT 4096)
    if(NOT _aida_c03_existing_stage_owner STREQUAL _aida_c03_stage_owner_record)
        message(FATAL_ERROR "AiDA C03 external stage root is owned by a different source/binary authority")
    endif()
else()
    file(WRITE "${_aida_c03_stage_owner_record_path}" "${_aida_c03_stage_owner_record}")
endif()
aida_c03_require_detached_roots(
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_BINARY_DIR}"
    "${CMAKE_BINARY_DIR}"
    "${AIDA_C03_APPLICATION_BUILD_ROOT}"
    "${AIDA_C03_DEVELOPER_ROOT}"
    "${AIDA_C03_CUSTOMER_STAGE_ANCHOR}"
    "${AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT}"
    "${AIDA_C03_STAGE_OWNER_ROOT}")
set(AIDA_C03_SAFE_HEADLESS_STAGE_ROOT "${AIDA_C03_DEVELOPER_ROOT}/suite/$<CONFIG>")
set(AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT "${AIDA_C03_DEVELOPER_ROOT}/generated")
set(AIDA_C03_CUSTOMER_PACKAGE_ROOT "${AIDA_C03_CUSTOMER_STAGE_ANCHOR}/$<CONFIG>")
set(AIDA_C03_SAFE_HEADLESS_INVENTORY "${AIDA_C03_TEST_ROOT}/testlab_runtime/safe_headless_inventory.json")
set(AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY "${AIDA_C03_TEST_ROOT}/testlab_runtime/assertion_site_inventory.json")
set(AIDA_C03_SAFE_HEADLESS_MATERIALIZER "${AIDA_C03_TEST_ROOT}/testlab_runtime/materialize_safe_headless_manifest.py")
set(AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/target_resource_policy_cases.json")
set(AIDA_C03_SAFE_HEADLESS_RECORDS "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}/target-records-$<CONFIG>.json")
set(AIDA_C03_SAFE_HEADLESS_MANIFEST "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/manifest.json")
set(AIDA_C03_SAFE_HEADLESS_DIGEST "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/manifest.sha256")
set(AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}/manifest_digest.hpp")
file(MAKE_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}")

set(AIDA_C03_PRODUCTION_STANDALONE_SOURCES
    "${STANDALONE_ROOT}/core/analysis/analysis_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
    "${STANDALONE_ROOT}/core/analysis/build_worker_packaging_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/artifact_collection.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/member_graph.cpp"
    "${STANDALONE_ROOT}/core/analysis/container/streaming_member_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/capstone_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/x86_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/managed_entity_binding.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/metadata_provenance.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/type_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
    "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_analysis_store.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_string_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/macho_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/classfile_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/cli_metadata_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/dex_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/managed_reader_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_engine_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/c03_analysis_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_result.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_tool_contract.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/schema_runtime.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/tool_registry.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/c03_compatibility_registration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/mcp_server_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/analysis.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/composite.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/core.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/debugger.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/memory.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/modify.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/python.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/routing_extensions.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signature_operand_mask.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signatures.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/stack.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/survey.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/types.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_interaction_context.cpp"
    "${STANDALONE_ROOT}/core/ui/application_action_registry.cpp"
    "${STANDALONE_ROOT}/core/ui/application_ui_runtime.cpp"
    "${STANDALONE_ROOT}/core/ui/analysis_context_menu.cpp"
    "${STANDALONE_ROOT}/core/ui/imgui_capability_guard.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/inspector/workbench_inspector_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/navigator/workbench_navigator.cpp"
    "${STANDALONE_ROOT}/core/workbench/split_tree.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
)
list(REMOVE_DUPLICATES AIDA_C03_PRODUCTION_STANDALONE_SOURCES)

set(AIDA_C03_COMPILER_MATRIX_CM_01
    "${STANDALONE_ROOT}/core/analysis/provider_snapshot.cpp"
    "${STANDALONE_ROOT}/core/analysis/mapped_window_cache.cpp"
    "${STANDALONE_ROOT}/core/analysis/subrange_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/spill_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/image_layout_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/c03_analysis_contracts.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_02
    "${STANDALONE_ROOT}/core/analysis/packed_analysis_store.cpp"
    "${STANDALONE_ROOT}/core/analysis/packed_string_pool.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_workspace.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_registry.cpp"
    "${STANDALONE_ROOT}/core/session/analysis_session.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_03
    "${STANDALONE_ROOT}/core/analysis/analysis_scheduler.cpp"
    "${STANDALONE_ROOT}/core/analysis/analysis_resource_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/x86_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode/capstone_tile_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decode_frontier.cpp"
    "${STANDALONE_ROOT}/core/analysis/tile_decode_orchestrator.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/x86_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arch_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arm_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/aarch64_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/mips_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ppc_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/riscv_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/call_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_engine_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_pipeline.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/data_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/string_discovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/symbol_type_candidates.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/query_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/regex_query.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_apply_engine.cpp"
    "${STANDALONE_ROOT}/core/analysis/overlay_projection.cpp"
    "${STANDALONE_ROOT}/core/analysis/incremental_reanalysis.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/patched_export.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_baseline_analyzer.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_04
    "${STANDALONE_ROOT}/core/analysis/readers/pe_coff_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/elf_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/macho_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/classfile_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/cli_metadata_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/dex_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/managed/managed_reader_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/container/streaming_member_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/artifact_collection.cpp"
    "${STANDALONE_ROOT}/core/analysis/collection/member_graph.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/coff_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/elf_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/macho_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/classfile_parser.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/dex_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/apk_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ipa_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/jar_container.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_05
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_schema_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/packed_page_codec.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/overlay_journal.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_persistence.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_06
    "${STANDALONE_ROOT}/core/analysis/decompiler/native_worker_host.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
    "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp"
    "${STANDALONE_ROOT}/../workers/native_decompiler/ghidra_native_provider.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
    "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_07
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/cli_provider.cpp"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/ManagedDecompilerWorker.csproj"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/packages.lock.json"
    "${STANDALONE_ROOT}/../workers/managed_decompiler/NuGet.Config"
    "${AIDA_C03_TEST_ROOT}/managed_cli/ManagedCliFixtures.csproj"
    "${AIDA_C03_TEST_ROOT}/managed_cli/packages.lock.json"
    "${AIDA_C03_TEST_ROOT}/managed_cli/NuGet.Config")
set(AIDA_C03_COMPILER_MATRIX_CM_08
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/type_graph_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/semantic_refiner.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/triton_z3_adapter.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/managed_entity_binding.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/metadata_provenance.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_feedback.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/semantic_fusion.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/type_recovery.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_09
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_cache_v9.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_provider_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/decompiler/legacy_document_adapter.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/pseudocode_document.cpp"
    "${STANDALONE_ROOT}/core/disasm/pseudocode_view.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pseudocode_readability.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_10
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_result.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/schema_runtime.cpp"
    "${STANDALONE_ROOT}/core/mcp/protocol/mcp_tool_contract.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/ida_contracts_generated.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/effect_policy.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/target_resolver.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/workspace_adapter.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/tool_registry.cpp"
    "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_11
    "${STANDALONE_ROOT}/core/mcp/compat/c03_compatibility_registration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/mcp_server_integration.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/analysis.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/composite.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/core.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/debugger.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/memory.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/modify.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/python.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/routing_extensions.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signature_operand_mask.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/signatures.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/stack.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/survey.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/handlers/types.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_read.cpp"
    "${STANDALONE_ROOT}/core/mcp/ida_compat_mut.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone.cpp"
    "${STANDALONE_ROOT}/core/mcp/mcp_standalone_tools.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_12
    "${STANDALONE_ROOT}/core/mcp/compat/debugger_lane.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/python_worker_host.cpp"
    "${STANDALONE_ROOT}/core/mcp/compat/live_routing_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_request_budget.cpp"
    "${STANDALONE_ROOT}/core/analysis/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_engine.cpp"
    "${STANDALONE_ROOT}/core/runtime/standalone_driver.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_13
    "${STANDALONE_ROOT}/main.cpp"
    "${STANDALONE_ROOT}/helpers/helpers.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_registry.cpp"
    "${STANDALONE_ROOT}/core/ai/agent_task.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_ai_client.cpp"
    "${STANDALONE_ROOT}/core/ai/standalone_chat.cpp"
    "${STANDALONE_ROOT}/core/debugger/thread_intel.cpp"
    "${STANDALONE_ROOT}/core/debugger/debugger_interaction_context.cpp"
    "${STANDALONE_ROOT}/core/ui/application_action_registry.cpp"
    "${STANDALONE_ROOT}/core/ui/application_ui_runtime.cpp"
    "${STANDALONE_ROOT}/core/ui/analysis_context_menu.cpp"
    "${STANDALONE_ROOT}/core/ui/imgui_capability_guard.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/diff_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/disasm_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/document_adapter_base.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/graph_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/adapters/hex_document.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_host/document_host_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/document_registry.cpp"
    "${STANDALONE_ROOT}/core/workbench/inspector/workbench_inspector_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/navigator/workbench_navigator.cpp"
    "${STANDALONE_ROOT}/core/workbench/split_tree.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_contracts.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_model.cpp"
    "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp")
set(AIDA_C03_COMPILER_MATRIX_CM_14
    "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_view.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_disasm.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_ui.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_features.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_all_mcp.cpp"
    "${AIDA_C03_TEST_ROOT}/harness_testlab_integration.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
    "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}"
    "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
    "${CMAKE_SOURCE_DIR}/driver/syscall.asm"
    "${STANDALONE_ROOT}/resources/aida_embedded.rc.in")
set(AIDA_C03_COMPILER_MATRIX_CM_15
    "${AIDA_C03_PACKAGE_VERIFIER_SOURCE}"
    "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
    "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
    "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp"
    "${STANDALONE_ROOT}/core/analysis/build_worker_packaging_integration.hpp"
    "${STANDALONE_ROOT}/core/analysis/build_worker_packaging_integration.cpp"
    "${STANDALONE_ROOT}/core/analysis/surface_reconciliation.cpp"
    "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/managed_decompiler_consumers_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/managed_publication_persistence/managed_publication_persistence_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/security/mcp_client_auth/mcp_client_auth_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/anti_tamper_integrity_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/build_packaging_integration_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/surface_reconciliation_harness.cpp"
    "${AIDA_C03_TEST_ROOT}/testlab_runtime/source_policy_scanner.cpp"
    "${CMAKE_SOURCE_DIR}/src/emulation_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/auth_attack_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/business_logic_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/js_analysis_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_auth_attack.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/offensive_business_logic.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/recon_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/sqli_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/offensive/xss_engine.cpp"
    "${STANDALONE_ROOT}/core/network/burp/tls_analyzer.cpp"
    "${STANDALONE_ROOT}/core/network/http_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/network/net_proto_analysis.cpp"
    "${STANDALONE_ROOT}/core/network/network_tool_aliases_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/coding_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/session_tools_standalone.cpp"
    "${STANDALONE_ROOT}/core/tools/workflow_tools_standalone.cpp"
    "${CMAKE_SOURCE_DIR}/CMakeLists.txt"
    "${CMAKE_SOURCE_DIR}/cmake/aida_c03_dependencies.cmake"
    "${CMAKE_SOURCE_DIR}/cmake/aida_c03_package_integration.cmake"
    "${AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE}"
    "${AIDA_C03_PATH_POLICY_MODULE}"
    "${AIDA_C03_PATH_IDENTITY_POLICY}"
    "${CMAKE_SOURCE_DIR}/packaging/c03_distribution_manifest.ps1"
    "${CMAKE_SOURCE_DIR}/packaging/c03_distribution_manifest_spec.json"
    "${CMAKE_SOURCE_DIR}/packaging/c03_distribution_fixture/path_byte_policy.json"
    "${AIDA_C03_TEST_ROOT}/package_distribution_policy/policy_stage_spec.json"
    "${AIDA_C03_TEST_ROOT}/package_distribution_policy/package_distribution_policy_harness.ps1"
    "${CMAKE_SOURCE_DIR}/packaging/c03_worker_runtime/managed_runtime_source_spec.json"
    "${CMAKE_SOURCE_DIR}/packaging/c03_worker_runtime/ghidra_spec_source_spec.json"
    "${CMAKE_SOURCE_DIR}/deploy_to_server.ps1"
    "${CMAKE_SOURCE_DIR}/tools/protector/main.cpp")
set(AIDA_C03_COMPILER_MATRIX_UNION)
foreach(_aida_matrix_suffix IN ITEMS 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15)
    list(APPEND AIDA_C03_COMPILER_MATRIX_UNION ${AIDA_C03_COMPILER_MATRIX_CM_${_aida_matrix_suffix}})
endforeach()
list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_UNION)

set(AIDA_C03_HARNESS_SUPPORT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/surface_reconciliation.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/elf_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/readers/pe_coff_reader.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/advanced_cfg.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/byte_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/calling_convention.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/function_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/live_snapshot_provider.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/overlay_journal.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/persistence_queue.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/search_index.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_database.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/xref_builder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/zip_container.cpp"
    "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
    "${DEPS_DIR}/sqlite-amalgamation-3530300/sqlite3.c"
)
set(AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES
    "${STANDALONE_ROOT}/core/analysis/workspace/aarch64_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_metrics.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/analysis_workspace.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/apk_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arch_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/arm_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/baseline_pipeline.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/classfile_parser.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/coff_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_feedback.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/decompiler_service.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/dex_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/elf_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ipa_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/jar_container.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/macho_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/mips_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/patched_export.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_baseline_analyzer.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pe_image.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/ppc_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/pseudocode_readability.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/riscv_decoder.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/semantic_fusion.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/type_recovery.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/workspace_registry.cpp"
    "${STANDALONE_ROOT}/core/analysis/workspace/x86_decoder.cpp"
)

function(aida_c03_require_sources descriptor)
    if(NOT ARGN)
        message(FATAL_ERROR "AiDA C03 source list is empty: ${descriptor}")
    endif()
    foreach(_aida_source IN LISTS ARGN)
        if(NOT IS_ABSOLUTE "${_aida_source}" OR NOT EXISTS "${_aida_source}" OR IS_DIRECTORY "${_aida_source}")
            message(FATAL_ERROR "AiDA C03 source is absent or invalid: ${descriptor} -> ${_aida_source}")
        endif()
    endforeach()
endfunction()

aida_c03_require_sources("production registration" ${AIDA_C03_PRODUCTION_STANDALONE_SOURCES})
aida_c03_require_sources("safe-headless support" ${AIDA_C03_HARNESS_SUPPORT_SOURCES})
aida_c03_require_sources("workspace safe-headless support" ${AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES})
aida_c03_require_sources("safe-headless assertion inventory" "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}")
aida_c03_require_sources("safe-headless target resource policy cases" "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}")

function(aida_c03_configure_native_target target)
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
        "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}"
        "${STANDALONE_ROOT}"
        "${STANDALONE_ROOT}/core"
        "${STANDALONE_ROOT}/core/analysis"
        "${STANDALONE_ROOT}/core/analysis/workspace"
        "${STANDALONE_ROOT}/core/analysis/decompiler"
        "${STANDALONE_ROOT}/core/mcp"
        "${STANDALONE_ROOT}/core/mcp/compat"
        "${STANDALONE_ROOT}/core/workbench"
        "${AIDA_C03_TEST_ROOT}"
        "${AIDA_C03_TEST_ROOT}/security/mcp_client_auth"
        "${AIDA_C03_MCP_TEST_ROOT}"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs"
        "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
        "${DEPS_DIR}/sqlite-amalgamation-3530300"
        "${zlib_SOURCE_DIR}"
        "${zlib_BINARY_DIR}"
        "${zstd_SOURCE_DIR}/../lib"
        "${xz_SOURCE_DIR}/src/liblzma/api"
        "${zydis_SOURCE_DIR}/include"
        "${zydis_SOURCE_DIR}/dependencies/zycore/include"
        "${zydis_BINARY_DIR}"
        "${zydis_BINARY_DIR}/zycore"
        "${capstone_SOURCE_DIR}/include"
        "${json_schema_validator_SOURCE_DIR}/src"
        "${GHIDRA_DECOMP_DIR}"
        "${Z3_INCLUDE_DIRS}"
    )
    target_include_directories(${target} SYSTEM PRIVATE "${DEPS_DIR}/taskflow")
    target_compile_definitions(${target} PRIVATE
        __NT__ _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE AIDA_STANDALONE
        GHIDRA_SPECS_DIR=${GHIDRA_SPECS_OUTPUT_DIR}
    )
    target_compile_options(${target} PRIVATE
        /W3 /Zp8 /bigobj
        "$<$<COMPILE_LANGUAGE:CXX>:/EHsc>"
        "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>"
        "$<$<COMPILE_LANGUAGE:CXX>:/permissive->")
    if(TARGET aida_hardening)
        target_link_libraries(${target} PRIVATE aida_hardening)
    endif()
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endfunction()

function(aida_c03_json_quote output value)
    string(REPLACE "\\" "\\\\" _aida_value "${value}")
    string(REPLACE "\"" "\\\"" _aida_value "${_aida_value}")
    string(REPLACE "\n" "\\n" _aida_value "${_aida_value}")
    string(REPLACE "\r" "\\r" _aida_value "${_aida_value}")
    set(${output} "\"${_aida_value}\"" PARENT_SCOPE)
endfunction()

function(aida_c03_json_array output)
    set(_aida_items)
    foreach(_aida_item IN LISTS ARGN)
        aida_c03_json_quote(_aida_quoted "${_aida_item}")
        list(APPEND _aida_items "${_aida_quoted}")
    endforeach()
    string(JOIN "," _aida_joined ${_aida_items})
    set(${output} "[${_aida_joined}]" PARENT_SCOPE)
endfunction()

function(aida_c03_repository_relative output source)
    cmake_path(ABSOLUTE_PATH source NORMALIZE OUTPUT_VARIABLE _aida_absolute)
    cmake_path(IS_PREFIX CMAKE_SOURCE_DIR "${_aida_absolute}" NORMALIZE _aida_inside)
    if(_aida_inside)
        file(RELATIVE_PATH _aida_relative "${CMAKE_SOURCE_DIR}" "${_aida_absolute}")
        string(REPLACE "\\" "/" _aida_relative "${_aida_relative}")
    else()
        message(FATAL_ERROR "AiDA C03 manifest source escapes the repository: ${_aida_absolute}")
    endif()
    set(${output} "${_aida_relative}" PARENT_SCOPE)
endfunction()

function(aida_c03_stage_runtime_file source relative)
    if(NOT IS_ABSOLUTE "${source}" OR NOT EXISTS "${source}" OR IS_DIRECTORY "${source}")
        message(FATAL_ERROR "AiDA C03 runtime source is invalid: ${source}")
    endif()
    if(relative MATCHES "(^|/)\\.\\.(/|$)" OR IS_ABSOLUTE "${relative}")
        message(FATAL_ERROR "AiDA C03 runtime destination is invalid: ${relative}")
    endif()
    string(REPLACE "\\" "/" _aida_relative "${relative}")
    get_property(_aida_registered GLOBAL PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS)
    string(SHA256 _aida_runtime_key "${_aida_relative}")
    if(_aida_relative IN_LIST _aida_registered)
        get_property(_aida_prior_source GLOBAL PROPERTY "AIDA_C03_RUNTIME_SOURCE_${_aida_runtime_key}")
        if(NOT _aida_prior_source STREQUAL "${source}")
            message(FATAL_ERROR "AiDA C03 runtime destination collision: ${_aida_relative}")
        endif()
        return()
    endif()
    set(_aida_output "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/${_aida_relative}")
    cmake_path(GET _aida_output PARENT_PATH _aida_parent)
    add_custom_command(OUTPUT "${_aida_output}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_aida_parent}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${source}" "${_aida_output}"
        DEPENDS "${source}"
        VERBATIM)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS "${_aida_relative}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_RUNTIME_OUTPUTS "${_aida_output}")
    set_property(GLOBAL PROPERTY "AIDA_C03_RUNTIME_SOURCE_${_aida_runtime_key}" "${source}")
endfunction()

function(aida_c03_stage_runtime_tree source_root relative_root output)
    file(GLOB_RECURSE _aida_files CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE "${source_root}/*")
    set(_aida_relatives)
    foreach(_aida_file IN LISTS _aida_files)
        file(RELATIVE_PATH _aida_leaf "${source_root}" "${_aida_file}")
        string(REPLACE "\\" "/" _aida_leaf "${_aida_leaf}")
        set(_aida_relative "${relative_root}/${_aida_leaf}")
        aida_c03_stage_runtime_file("${_aida_file}" "${_aida_relative}")
        list(APPEND _aida_relatives "${_aida_relative}")
    endforeach()
    set(${output} "${_aida_relatives}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_manifest_entry)
    cmake_parse_arguments(PARSE_ARGV 0 _aida "ARGS_ENTRY" "TARGET;PACKAGE;ENTRY_DEFINITION;OUTPUT_NAME;MAX_ACTIVE_PROCESSES;MAX_WALL_MS" "SOURCES;ARGUMENTS;RUNTIME_FILES;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;SOURCE_RECORDS")
    if(_aida_UNPARSED_ARGUMENTS OR _aida_KEYWORDS_MISSING_VALUES OR
       NOT _aida_TARGET OR NOT _aida_PACKAGE OR NOT _aida_SOURCES)
        message(FATAL_ERROR "AiDA C03 adapted manifest entry is malformed: ${_aida_TARGET}")
    endif()
    if(NOT _aida_TARGET MATCHES "^aida_c03_[a-z0-9_]+$" OR TARGET "${_aida_TARGET}")
        message(FATAL_ERROR "AiDA C03 adapted manifest target is invalid or duplicated: ${_aida_TARGET}")
    endif()
    if("${_aida_MAX_ACTIVE_PROCESSES}" STREQUAL "")
        set(_aida_MAX_ACTIVE_PROCESSES 1)
    endif()
    if("${_aida_MAX_WALL_MS}" STREQUAL "")
        set(_aida_MAX_WALL_MS 120000)
    endif()
    if(NOT "${_aida_MAX_ACTIVE_PROCESSES}" MATCHES "^[1-4]$")
        message(FATAL_ERROR "AiDA C03 adapted manifest active-process limit is invalid: ${_aida_TARGET}")
    endif()
    if(NOT "${_aida_MAX_WALL_MS}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR "AiDA C03 adapted manifest wall limit is invalid: ${_aida_TARGET}")
    endif()
    if(_aida_TARGET STREQUAL "aida_c03_a06_decompiler_quality_scorer_harness")
        if(NOT _aida_MAX_ACTIVE_PROCESSES EQUAL 4)
            message(FATAL_ERROR "AiDA C03 quality provider matrix requires the exact four-process containment bound")
        endif()
        if(NOT _aida_MAX_WALL_MS EQUAL 1800000)
            message(FATAL_ERROR "AiDA C03 quality provider matrix requires the exact thirty-minute wall bound")
        endif()
    elseif(NOT _aida_MAX_ACTIVE_PROCESSES EQUAL 1)
        message(FATAL_ERROR "AiDA C03 ordinary safe-headless entries require single-process containment: ${_aida_TARGET}")
    elseif(NOT _aida_MAX_WALL_MS EQUAL 120000)
        message(FATAL_ERROR "AiDA C03 ordinary safe-headless entries require the exact two-minute wall bound: ${_aida_TARGET}")
    endif()
    aida_c03_require_sources("${_aida_PACKAGE}/${_aida_TARGET}" ${_aida_SOURCES})
    set(_aida_payload "${_aida_TARGET}_payload")
    add_library(${_aida_payload} OBJECT ${_aida_SOURCES})
    aida_c03_configure_native_target(${_aida_payload})
    target_compile_definitions(${_aida_payload} PRIVATE main=aida_c03_harness_entry)
    if(_aida_ENTRY_DEFINITION)
        target_compile_definitions(${_aida_payload} PRIVATE "${_aida_ENTRY_DEFINITION}")
    endif()
    if(_aida_COMPILE_DEFINITIONS)
        target_compile_definitions(${_aida_payload} PRIVATE ${_aida_COMPILE_DEFINITIONS})
    endif()
    if(_aida_INCLUDE_DIRECTORIES)
        target_include_directories(${_aida_payload} PRIVATE ${_aida_INCLUDE_DIRECTORIES})
    endif()
    if(_aida_ARGS_ENTRY)
        set(_aida_adapter "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_args.cpp")
    else()
        set(_aida_adapter "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_noargs.cpp")
    endif()
    add_executable(${_aida_TARGET}
        "${_aida_adapter}"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
        $<TARGET_OBJECTS:${_aida_payload}>)
    aida_c03_configure_native_target(${_aida_TARGET})
    target_link_libraries(${_aida_TARGET} PRIVATE aida_c03_safe_headless_runtime ${_aida_LINK_LIBRARIES})
    if(_aida_OUTPUT_NAME)
        set(_aida_output_name "${_aida_OUTPUT_NAME}")
    else()
        set(_aida_output_name "${_aida_TARGET}")
    endif()
    set_target_properties(${_aida_TARGET} PROPERTIES
        OUTPUT_NAME "${_aida_output_name}"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/bin"
        PDB_OUTPUT_DIRECTORY "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/symbols"
        FOLDER "Tests/C03/SafeHeadless/Manifest"
        AIDA_C03_PACKAGE "${_aida_PACKAGE}"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;${_aida_PACKAGE}"
    )
    if(_aida_SOURCE_RECORDS)
        set(_aida_source_records ${_aida_SOURCE_RECORDS})
    else()
        set(_aida_source_records)
        foreach(_aida_source IN LISTS _aida_SOURCES)
            aida_c03_repository_relative(_aida_relative "${_aida_source}")
            list(APPEND _aida_source_records "${_aida_relative}")
        endforeach()
    endif()
    list(REMOVE_DUPLICATES _aida_source_records)
    list(REMOVE_DUPLICATES _aida_RUNTIME_FILES)
    aida_c03_json_quote(_aida_target_json "${_aida_TARGET}")
    aida_c03_json_quote(_aida_executable_json "bin/${_aida_output_name}.exe")
    aida_c03_json_array(_aida_arguments_json ${_aida_ARGUMENTS})
    aida_c03_json_array(_aida_sources_json ${_aida_source_records})
    aida_c03_json_array(_aida_runtime_json ${_aida_RUNTIME_FILES})
    set(_aida_record "{\"source_target\":${_aida_target_json},\"executable_relative_path\":${_aida_executable_json},\"working_directory_relative_path\":\".\",\"arguments\":${_aida_arguments_json},\"source_files\":${_aida_sources_json},\"runtime_files\":${_aida_runtime_json},\"max_active_processes\":${_aida_MAX_ACTIVE_PROCESSES},\"max_wall_ms\":${_aida_MAX_WALL_MS}}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS "${_aida_record}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_MANIFEST_TARGETS "${_aida_TARGET}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS
        ${_aida_SOURCES} "${_aida_adapter}" "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp")
endfunction()

function(aida_c03_register_direct_test)
    cmake_parse_arguments(PARSE_ARGV 0 _aida "NO_SHARED_RUNTIME" "TARGET;PACKAGE;TIMEOUT" "SOURCES;ARGUMENTS;LINK_LIBRARIES;INCLUDE_DIRECTORIES;COMPILE_DEFINITIONS;DEPENDS")
    if(_aida_UNPARSED_ARGUMENTS OR _aida_KEYWORDS_MISSING_VALUES OR
       NOT _aida_TARGET OR NOT _aida_PACKAGE OR NOT _aida_SOURCES)
        message(FATAL_ERROR "AiDA C03 direct safe-headless test is malformed: ${_aida_TARGET}")
    endif()
    if(TARGET "${_aida_TARGET}")
        message(FATAL_ERROR "AiDA C03 direct safe-headless target is duplicated: ${_aida_TARGET}")
    endif()
    aida_c03_require_sources("${_aida_PACKAGE}/${_aida_TARGET}" ${_aida_SOURCES})
    add_executable(${_aida_TARGET} ${_aida_SOURCES})
    aida_c03_configure_native_target(${_aida_TARGET})
    if(_aida_NO_SHARED_RUNTIME)
        if(NOT _aida_LINK_LIBRARIES)
            message(FATAL_ERROR "AiDA C03 isolated direct target requires an explicit implementation graph: ${_aida_TARGET}")
        endif()
        target_link_libraries(${_aida_TARGET} PRIVATE ${_aida_LINK_LIBRARIES})
    else()
        target_link_libraries(${_aida_TARGET} PRIVATE aida_c03_safe_headless_runtime ${_aida_LINK_LIBRARIES})
    endif()
    if(_aida_INCLUDE_DIRECTORIES)
        target_include_directories(${_aida_TARGET} PRIVATE ${_aida_INCLUDE_DIRECTORIES})
    endif()
    if(_aida_COMPILE_DEFINITIONS)
        target_compile_definitions(${_aida_TARGET} PRIVATE ${_aida_COMPILE_DEFINITIONS})
    endif()
    if(_aida_DEPENDS)
        add_dependencies(${_aida_TARGET} ${_aida_DEPENDS})
    endif()
    set_target_properties(${_aida_TARGET} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Direct"
        AIDA_C03_PACKAGE "${_aida_PACKAGE}"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;direct;${_aida_PACKAGE}")
    if(NOT _aida_TIMEOUT)
        set(_aida_TIMEOUT 120)
    endif()
    add_test(NAME ${_aida_TARGET} COMMAND $<TARGET_FILE:${_aida_TARGET}> ${_aida_ARGUMENTS})
    set_tests_properties(${_aida_TARGET} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT "${_aida_TIMEOUT}"
        LABELS "c03;c03_safe_headless;safe-headless;direct;${_aida_PACKAGE}"
        RESOURCE_LOCK "aida_c03_safe_headless_direct")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_DIRECT_TARGETS "${_aida_TARGET}")
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS ${_aida_SOURCES})
endfunction()

function(aida_c03_register_worker_targets application_target)
    if(NOT TARGET "${application_target}")
        message(FATAL_ERROR "AiDA C03 worker registration requires the standalone target")
    endif()
    if(TARGET aida_c03_b14_native_decompiler_worker OR TARGET aida_c03_b16_managed_decompiler_worker)
        message(FATAL_ERROR "AiDA C03 worker targets were registered more than once")
    endif()
    if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE OR
       NOT DEFINED ENV{SystemDrive} OR NOT "$ENV{SystemDrive}" MATCHES "^[A-Z]:$" OR
       NOT DEFINED ENV{SystemRoot} OR
       NOT "$ENV{SystemRoot}" STREQUAL "$ENV{SystemDrive}\\Windows")
        message(FATAL_ERROR "AiDA C03 worker registration requires canonical local interpreters")
    endif()
    aida_c03_validate_canonical_regular_file(
        AIDA_C03_VALIDATED_PYTHON_EXECUTABLE
        _aida_c03_worker_python_sha256
        "${Python3_EXECUTABLE}"
        "worker Python interpreter")
    set(_aida_c03_worker_system_root "$ENV{SystemDrive}/Windows")
    aida_c03_validate_canonical_directory(
        _aida_c03_worker_system_root
        "${_aida_c03_worker_system_root}"
        "worker Windows system root")
    aida_c03_validate_canonical_regular_file(
        AIDA_C03_VALIDATED_POWERSHELL_EXECUTABLE
        _aida_c03_worker_powershell_sha256
        "${_aida_c03_worker_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe"
        "worker system PowerShell")
    aida_c03_validate_canonical_regular_file(
        _aida_c03_worker_path_identity_policy
        _aida_c03_worker_path_identity_policy_sha256
        "${AIDA_C03_PATH_IDENTITY_POLICY}"
        "worker path-identity policy")
    foreach(_aida_c03_worker_authority_path IN ITEMS
            "${AIDA_C03_VALIDATED_PYTHON_EXECUTABLE}"
            "${AIDA_C03_VALIDATED_POWERSHELL_EXECUTABLE}"
            "${_aida_c03_worker_path_identity_policy}")
        aida_c03_validate_no_reparse_chain(
            "${AIDA_C03_VALIDATED_POWERSHELL_EXECUTABLE}"
            "${_aida_c03_worker_path_identity_policy}"
            "${_aida_c03_worker_authority_path}"
            "worker execution authority")
    endforeach()
    set(_aida_native_sources
        "${STANDALONE_ROOT}/../workers/native_decompiler/native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/../workers/native_decompiler/ghidra_native_provider.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/dalvik_ssa.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/ghidra_ir_adapter.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/providers/jvm_ssa.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/pseudocode_renderer_v2.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/typed_ast_v2.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
        "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp")
    aida_c03_require_sources("B14 native decompiler worker" ${_aida_native_sources})
    add_executable(aida_c03_b14_native_decompiler_worker ${_aida_native_sources})
    aida_c03_configure_native_target(aida_c03_b14_native_decompiler_worker)
    target_link_libraries(aida_c03_b14_native_decompiler_worker PRIVATE libdecomp_aida bcrypt advapi32 userenv ws2_32)
    set_target_properties(aida_c03_b14_native_decompiler_worker PROPERTIES
        OUTPUT_NAME "AiDA_NativeDecompilerWorker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/workers/$<CONFIG>"
        FOLDER "Workers/C03"
        AIDA_C03_PACKAGE "B14"
        AIDA_C03_SAFE_HEADLESS FALSE)

    aida_c03_require_sources("D06 production package verifier"
        "${AIDA_C03_PACKAGE_VERIFIER_SOURCE}"
        "${STANDALONE_ROOT}/core/analysis/build_worker_packaging_integration.cpp")
    add_executable(aida_c03_package_verifier
        "${AIDA_C03_PACKAGE_VERIFIER_SOURCE}"
        "${STANDALONE_ROOT}/core/analysis/build_worker_packaging_integration.cpp")
    aida_c03_configure_native_target(aida_c03_package_verifier)
    target_include_directories(aida_c03_package_verifier PRIVATE "${CMAKE_SOURCE_DIR}")
    target_link_libraries(aida_c03_package_verifier PRIVATE bcrypt crypt32 wintrust)
    set_target_properties(aida_c03_package_verifier PROPERTIES
        OUTPUT_NAME "AiDA_C03PackageVerifier"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/package-verifier/$<CONFIG>"
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE "D06"
        AIDA_C03_PRODUCTION_VERIFIER TRUE
        AIDA_C03_SAFE_HEADLESS FALSE)

    file(GLOB _aida_managed_inputs CONFIGURE_DEPENDS
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.cs"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.json"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/*.csproj"
        "${AIDA_C03_MANAGED_WORKER_ROOT}/NuGet.Config")
    aida_c03_require_sources("B16 managed decompiler worker" ${_aida_managed_inputs})
    set(AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/publish")
    set(AIDA_C03_MANAGED_WORKER_EXECUTABLE "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/AiDA_ManagedDecompilerWorker.exe")
    set(AIDA_C03_MANAGED_WORKER_PROVIDER "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/ICSharpCode.Decompiler.dll")
    set(AIDA_C03_MANAGED_WORKER_RUNTIME_FILES
        "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/AiDA_ManagedDecompilerWorker.dll"
        "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/AiDA_ManagedDecompilerWorker.deps.json"
        "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/AiDA_ManagedDecompilerWorker.runtimeconfig.json"
        "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/System.Collections.Immutable.dll"
        "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}/System.Reflection.Metadata.dll")
    get_filename_component(_aida_c03_dotnet_root "${AIDA_C03_DOTNET_EXECUTABLE}" DIRECTORY)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_NATIVE_WORKER_INPUTS
        ${_aida_native_sources})
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS
        ${_aida_managed_inputs})
    add_custom_target(aida_c03_b16_managed_decompiler_worker
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home"
            "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home"
            "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" restore "${AIDA_C03_MANAGED_WORKER_PROJECT}"
            --configfile "${AIDA_C03_MANAGED_WORKER_NUGET_CONFIG}"
            --packages "${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages"
            --locked-mode --no-cache --disable-parallel
            --runtime win-x64
            -p:AssemblyName=AiDA_ManagedDecompilerWorker
            -p:RuntimeFrameworkVersion=10.0.9
            -p:TargetLatestRuntimePatch=false
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-worker/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" publish "${AIDA_C03_MANAGED_WORKER_PROJECT}"
            --configuration Release --framework net10.0 --runtime win-x64 --self-contained false --no-restore
            --output "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}"
            -p:AssemblyName=AiDA_ManagedDecompilerWorker
            -p:RuntimeFrameworkVersion=10.0.9
            -p:TargetLatestRuntimePatch=false
            -p:ContinuousIntegrationBuild=true -p:Deterministic=true -p:TreatWarningsAsErrors=true
        DEPENDS ${_aida_managed_inputs} "${AIDA_C03_DOTNET_EXECUTABLE}"
        COMMENT "Publishing the locked offline C03 managed decompiler worker"
        VERBATIM)
    set_target_properties(aida_c03_b16_managed_decompiler_worker PROPERTIES
        FOLDER "Workers/C03"
        AIDA_C03_PACKAGE "B16"
        AIDA_C03_SAFE_HEADLESS FALSE)

    set(AIDA_C03_MANAGED_FIXTURE_ROOT "${AIDA_C03_TEST_ROOT}/managed_cli")
    set(AIDA_C03_MANAGED_FIXTURE_PROJECT "${AIDA_C03_MANAGED_FIXTURE_ROOT}/ManagedCliFixtures.csproj")
    set(AIDA_C03_MANAGED_FIXTURE_LOCK "${AIDA_C03_MANAGED_FIXTURE_ROOT}/packages.lock.json")
    set(AIDA_C03_MANAGED_FIXTURE_NUGET_CONFIG "${AIDA_C03_MANAGED_FIXTURE_ROOT}/NuGet.Config")
    file(SHA256 "${AIDA_C03_MANAGED_FIXTURE_PROJECT}" _aida_c03_managed_fixture_project_sha256)
    file(SHA256 "${AIDA_C03_MANAGED_FIXTURE_LOCK}" _aida_c03_managed_fixture_lock_sha256)
    string(TOUPPER "${_aida_c03_managed_fixture_project_sha256}" _aida_c03_managed_fixture_project_sha256)
    string(TOUPPER "${_aida_c03_managed_fixture_lock_sha256}" _aida_c03_managed_fixture_lock_sha256)
    if(NOT _aida_c03_managed_fixture_project_sha256 STREQUAL "16DF21A9585B1D7DB1E080876DF2F70B1B38A7D50389A0C06BBBC9E43D771B34" OR
       NOT _aida_c03_managed_fixture_lock_sha256 STREQUAL "98540F8C8005E000CC83CFFB4598281F61900A13426B470F1D1114C62B54A63D")
        message(FATAL_ERROR "AiDA C03 managed CLI fixture project or lock identity changed")
    endif()
    file(GLOB _aida_c03_managed_fixture_inputs CONFIGURE_DEPENDS
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.cs"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.json"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/*.csproj"
        "${AIDA_C03_MANAGED_FIXTURE_ROOT}/NuGet.Config")
    aida_c03_require_sources("A06 managed CLI fixture" ${_aida_c03_managed_fixture_inputs})
    set(AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/publish")
    set(AIDA_C03_MANAGED_FIXTURE_DLL "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}/ManagedCliFixtures.dll")
    add_custom_target(aida_c03_a06_managed_cli_fixture
        COMMAND ${CMAKE_COMMAND} -E rm -rf
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home"
            "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home"
            "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" restore "${AIDA_C03_MANAGED_FIXTURE_PROJECT}"
            --configfile "${AIDA_C03_MANAGED_FIXTURE_NUGET_CONFIG}"
            --packages "${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages"
            --locked-mode --no-cache --disable-parallel
        COMMAND ${CMAKE_COMMAND} -E env
            DOTNET_CLI_HOME=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/cli-home
            DOTNET_CLI_TELEMETRY_OPTOUT=1
            DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1
            DOTNET_NOLOGO=1
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            DOTNET_MULTILEVEL_LOOKUP=0
            DOTNET_ROOT=${_aida_c03_dotnet_root}
            DOTNET_ROLL_FORWARD=Disable
            NUGET_CERT_REVOCATION_MODE=offline
            NUGET_PACKAGES=${AIDA_C03_DEVELOPER_ROOT}/managed-fixture/packages
            "${AIDA_C03_DOTNET_EXECUTABLE}" build "${AIDA_C03_MANAGED_FIXTURE_PROJECT}"
            --configuration Release --framework net10.0 --no-restore
            --output "${AIDA_C03_MANAGED_FIXTURE_PUBLISH_ROOT}"
            -p:ContinuousIntegrationBuild=true -p:Deterministic=true -p:TreatWarningsAsErrors=true
        BYPRODUCTS "${AIDA_C03_MANAGED_FIXTURE_DLL}"
        DEPENDS ${_aida_c03_managed_fixture_inputs} "${AIDA_C03_DOTNET_EXECUTABLE}"
        VERBATIM)
    set_target_properties(aida_c03_a06_managed_cli_fixture PROPERTIES
        FOLDER "Tests/C03/SafeHeadless/Fixtures"
        AIDA_C03_PACKAGE "A06"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_TARGET_FRAMEWORK "net10.0"
        AIDA_C03_PINNED_SDK_VERSION "10.0.301"
        AIDA_C03_MACHINE_RUNTIME_FALLBACK FALSE)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS
        ${_aida_c03_managed_fixture_inputs})

    aida_c03_register_ghidra_spec_package(
        APPLICATION_TARGET ${application_target}
        SPEC_TARGET ghidra_specs
        GENERATOR_TARGET ghidra_sleigh_compiler
        APPROVED_INPUT_ROOT "${GHIDRA_SPECS_OUTPUT_DIR}"
        SPEC_FILES ${GHIDRA_STAGED_SPEC_OUTPUTS})
    aida_c03_register_native_worker_package(
        APPLICATION_TARGET ${application_target}
        WORKER_TARGET aida_c03_b14_native_decompiler_worker)
    aida_c03_register_managed_worker_package(
        APPLICATION_TARGET ${application_target}
        BUILD_TARGET aida_c03_b16_managed_decompiler_worker
        WORKER_EXECUTABLE "${AIDA_C03_MANAGED_WORKER_EXECUTABLE}"
        PROVIDER_BINARY "${AIDA_C03_MANAGED_WORKER_PROVIDER}"
        RUNTIME_FILES ${AIDA_C03_MANAGED_WORKER_RUNTIME_FILES})
    aida_c03_register_analysis_python_worker_package(APPLICATION_TARGET ${application_target})
    aida_c03_register_customer_notice_package(APPLICATION_TARGET ${application_target})
    aida_c03_register_auxiliary_notice_package(
        TARGET aida_c03_auxiliary_notice_package
        OUTPUT_ROOT "${AIDA_C03_DEVELOPER_ROOT}/auxiliary-notices")
    set(_aida_c03_distribution_dependencies
        ${application_target}
        ${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}
        ${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}
        ${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET}
        ${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET})
    if(TARGET ${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET})
        list(APPEND _aida_c03_distribution_dependencies
            ${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET})
    endif()
    if(NOT DEFINED ENV{SystemDrive} OR NOT "$ENV{SystemDrive}" MATCHES "^[A-Z]:$" OR
       NOT DEFINED ENV{SystemRoot} OR
       NOT "$ENV{SystemRoot}" STREQUAL "$ENV{SystemDrive}\\Windows")
        message(FATAL_ERROR "AiDA C03 distribution requires the canonical Windows system root")
    endif()
    set(_aida_c03_distribution_system_root "$ENV{SystemDrive}/Windows")
    aida_c03_validate_canonical_directory(
        _aida_c03_distribution_system_root
        "${_aida_c03_distribution_system_root}"
        "distribution Windows system root")
    aida_c03_validate_canonical_regular_file(
        _aida_c03_distribution_powershell
        _aida_c03_distribution_powershell_sha256
        "${_aida_c03_distribution_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe"
        "distribution system PowerShell")
    aida_c03_validate_no_reparse_chain(
        "${_aida_c03_distribution_powershell}"
        "${AIDA_C03_PATH_IDENTITY_POLICY}"
        "${_aida_c03_distribution_powershell}"
        "distribution system PowerShell")
    set(_aida_c03_distribution_output_root
        "${AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT}/distribution")
    file(MAKE_DIRECTORY "${_aida_c03_distribution_output_root}")
    foreach(_aida_c03_distribution_path IN ITEMS
            "${AIDA_C03_APPLICATION_BUILD_ROOT}"
            "${AIDA_C03_DEVELOPER_ROOT}"
            "${AIDA_C03_CUSTOMER_STAGE_ANCHOR}"
            "${_aida_c03_distribution_output_root}")
        aida_c03_validate_no_reparse_chain(
            "${_aida_c03_distribution_powershell}"
            "${AIDA_C03_PATH_IDENTITY_POLICY}"
            "${_aida_c03_distribution_path}"
            "distribution detached root")
    endforeach()
    aida_c03_register_distribution_manifest(
        REQUIRE_ANALYSIS_PYTHON
        TARGET aida_c03_distribution_manifest
        APPLICATION_TARGET ${application_target}
        APPLICATION_ROOT "${AIDA_C03_APPLICATION_BUILD_ROOT}"
        REPOSITORY_ROOT "${CMAKE_SOURCE_DIR}"
        BINARY_ROOT "${CMAKE_BINARY_DIR}"
        SOURCE_ROOT "$<TARGET_FILE_DIR:${application_target}>"
        DEVELOPER_ROOT "${AIDA_C03_DEVELOPER_ROOT}"
        CUSTOMER_STAGE_ANCHOR "${AIDA_C03_CUSTOMER_STAGE_ANCHOR}"
        EVIDENCE_ROOT "${AIDA_C03_DISTRIBUTION_EVIDENCE_ROOT}"
        STAGE_OWNER_ROOT "${AIDA_C03_STAGE_OWNER_ROOT}"
        PACKAGE_ROOT "${AIDA_C03_CUSTOMER_PACKAGE_ROOT}"
        SPEC "${AIDA_C03_DISTRIBUTION_MANIFEST_SPEC}"
        OUTPUT_MANIFEST "${_aida_c03_distribution_output_root}/AiDA_C03.distribution.json"
        OUTPUT_DIGEST "${_aida_c03_distribution_output_root}/AiDA_C03.distribution.sha256"
        POWERSHELL_EXECUTABLE "${_aida_c03_distribution_powershell}"
        PACKAGE_VERIFIER_TARGET aida_c03_package_verifier
        DEPENDS ${_aida_c03_distribution_dependencies})
    set(AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT "${AIDA_C03_MANAGED_WORKER_PUBLISH_ROOT}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_WORKER_EXECUTABLE "${AIDA_C03_MANAGED_WORKER_EXECUTABLE}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_WORKER_PROVIDER "${AIDA_C03_MANAGED_WORKER_PROVIDER}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_WORKER_RUNTIME_FILES "${AIDA_C03_MANAGED_WORKER_RUNTIME_FILES}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_FIXTURE_DLL "${AIDA_C03_MANAGED_FIXTURE_DLL}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_safe_headless_targets application_target)
    if(NOT WIN32 OR NOT MSVC OR NOT TARGET "${application_target}")
        message(FATAL_ERROR "AiDA C03 safe-headless registration requires the Windows MSVC standalone target")
    endif()
    if(TARGET aida_c03_safe_headless_harnesses)
        message(FATAL_ERROR "AiDA C03 safe-headless integration was registered more than once")
    endif()
    if(NOT Python3_Interpreter_FOUND OR NOT Python3_EXECUTABLE)
        message(FATAL_ERROR "AiDA C03 safe-headless materialization requires the pinned local Python interpreter")
    endif()
    aida_c03_validate_canonical_regular_file(
        _aida_python_executable
        _aida_python_sha256
        "${Python3_EXECUTABLE}"
        "Python interpreter")
    if(NOT DEFINED ENV{SystemDrive} OR NOT "$ENV{SystemDrive}" MATCHES "^[A-Z]:$" OR
       NOT DEFINED ENV{SystemRoot} OR
       NOT "$ENV{SystemRoot}" STREQUAL "$ENV{SystemDrive}\\Windows")
        message(FATAL_ERROR "AiDA C03 authority reproduction requires the canonical Windows system root")
    endif()
    set(_aida_system_root_input "$ENV{SystemDrive}/Windows")
    aida_c03_validate_canonical_directory(
        _aida_system_root
        "${_aida_system_root_input}"
        "Windows system root")
    aida_c03_validate_canonical_regular_file(
        _aida_system_powershell
        _aida_system_powershell_sha256
        "${_aida_system_root}/System32/WindowsPowerShell/v1.0/powershell.exe"
        "Windows system PowerShell interpreter")
    set(_aida_authority_archive "C:/Users/ruar1337/ida-pro-mcp.zip")
    aida_c03_validate_canonical_regular_file(
        _aida_authority_archive
        _aida_authority_archive_sha256
        "${_aida_authority_archive}"
        "pinned ida-pro-mcp archive")
    if(NOT _aida_authority_archive_sha256 STREQUAL "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7")
        message(FATAL_ERROR "AiDA C03 pinned ida-pro-mcp archive SHA-256 is invalid")
    endif()
    set(_aida_authority_repository_files
        "${AIDA_C03_PATH_POLICY_MODULE}"
        "${AIDA_C03_PATH_IDENTITY_POLICY}"
        "${CMAKE_SOURCE_DIR}/tools/c03_authority/verify_authority_surface_ledger.py"
        "${CMAKE_SOURCE_DIR}/tools/c03_authority/authority_surface_ledger.json"
        "${CMAKE_SOURCE_DIR}/tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_baseline.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_final.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp"
        "${CMAKE_SOURCE_DIR}/src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp")
    aida_c03_require_sources("authority and surface reproduction" ${_aida_authority_repository_files})
    foreach(_aida_authority_path IN ITEMS
            "${_aida_system_root}"
            "${_aida_system_powershell}"
            "${_aida_python_executable}"
            "${_aida_authority_archive}"
            ${_aida_authority_repository_files})
        aida_c03_validate_no_reparse_chain(
            "${_aida_system_powershell}"
            "${AIDA_C03_PATH_IDENTITY_POLICY}"
            "${_aida_authority_path}"
            "authority path")
    endforeach()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        ${_aida_authority_repository_files}
        "${_aida_python_executable}"
        "${_aida_system_powershell}"
        "${_aida_authority_archive}")
    set(_aida_authority_identity_material "aida-c03-authority-surface-reproduction-v1")
    foreach(_aida_authority_file IN LISTS _aida_authority_repository_files)
        file(SHA256 "${_aida_authority_file}" _aida_authority_file_sha256)
        string(TOUPPER "${_aida_authority_file_sha256}" _aida_authority_file_sha256)
        file(RELATIVE_PATH _aida_authority_relative "${CMAKE_SOURCE_DIR}" "${_aida_authority_file}")
        string(REPLACE "\\" "/" _aida_authority_relative "${_aida_authority_relative}")
        string(APPEND _aida_authority_identity_material
            "|${_aida_authority_relative}=${_aida_authority_file_sha256}")
    endforeach()
    string(APPEND _aida_authority_identity_material
        "|python=${_aida_python_executable}:${_aida_python_sha256}"
        "|powershell=${_aida_system_powershell}:${_aida_system_powershell_sha256}"
        "|archive=${_aida_authority_archive}:${_aida_authority_archive_sha256}")
    string(SHA256 _aida_authority_identity "${_aida_authority_identity_material}")
    string(TOUPPER "${_aida_authority_identity}" _aida_authority_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/tools/c03_authority/verify_authority_surface_ledger.py" _aida_authority_verifier_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/tools/c03_authority/authority_surface_ledger.json" _aida_authority_ledger_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py" _aida_contract_generator_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1" _aida_surface_generator_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_baseline.json" _aida_surface_baseline_sha256)
    file(SHA256 "${CMAKE_SOURCE_DIR}/src/standalone/tests/analysis_workspace/standalone_surface_final.json" _aida_surface_final_sha256)
    foreach(_aida_hash_variable IN ITEMS
            _aida_authority_verifier_sha256
            _aida_authority_ledger_sha256
            _aida_contract_generator_sha256
            _aida_surface_generator_sha256
            _aida_surface_baseline_sha256
            _aida_surface_final_sha256)
        string(TOUPPER "${${_aida_hash_variable}}" ${_aida_hash_variable})
    endforeach()
    set_property(GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGETS "")
    set_property(GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS "")
    set_property(GLOBAL PROPERTY AIDA_C03_DIRECT_TARGETS "")
    set_property(GLOBAL PROPERTY AIDA_C03_RUNTIME_RELATIVE_PATHS "")
    set_property(GLOBAL PROPERTY AIDA_C03_RUNTIME_OUTPUTS "")
    set_property(GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS "")

    set(_aida_runtime_sources
        ${AIDA_C03_PRODUCTION_STANDALONE_SOURCES}
        ${AIDA_C03_HARNESS_SUPPORT_SOURCES}
        ${AIDA_C03_WORKSPACE_HARNESS_SUPPORT_SOURCES})
    set(_aida_auth_implementation_sources
        "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
        "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
        "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp")
    aida_c03_require_sources("D08 normal and preview auth implementation graph"
        ${_aida_auth_implementation_sources})
    list(REMOVE_ITEM _aida_runtime_sources
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
        "${STANDALONE_ROOT}/core/mcp/registry/application_debugger_capability.cpp")
    list(REMOVE_DUPLICATES _aida_runtime_sources)
    add_library(aida_c03_safe_headless_runtime STATIC ${_aida_runtime_sources})
    aida_c03_configure_native_target(aida_c03_safe_headless_runtime)
    target_link_libraries(aida_c03_safe_headless_runtime PUBLIC
        Zydis capstone::capstone triton "${Z3_LIBRARIES}"
        nlohmann_json_schema_validator::validator libdecomp_aida
        zlibstatic libzstd_static liblzma pcre2-8
        bcrypt crypt32 advapi32 userenv ws2_32 shell32 ole32 Shlwapi)
    set_target_properties(aida_c03_safe_headless_runtime PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;runtime")
    add_library(aida_c03_auth_preview_implementation STATIC
        ${_aida_auth_implementation_sources})
    aida_c03_configure_native_target(aida_c03_auth_preview_implementation)
    target_compile_definitions(aida_c03_auth_preview_implementation PRIVATE
        AIDA_IMGUI_STUDIO_PREVIEW=1)
    target_link_libraries(aida_c03_auth_preview_implementation PUBLIC
        bcrypt crypt32 advapi32 userenv ws2_32 shell32 ole32 Shlwapi)
    set_target_properties(aida_c03_auth_preview_implementation PROPERTIES
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_IMPLEMENTATION_VARIANT "preview"
        AIDA_C03_IMPLEMENTATION_SOURCES "${_aida_auth_implementation_sources}")
    set_target_properties(aida_c03_safe_headless_runtime PROPERTIES
        AIDA_C03_AUTH_IMPLEMENTATION_VARIANT "normal"
        AIDA_C03_AUTH_IMPLEMENTATION_SOURCES "${_aida_auth_implementation_sources}")

    set(_aida_entries "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/generated_entrypoints.cpp")
    set(_aida_result_sources
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/result_adapter.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_args.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/adapter_main_noargs.cpp")
    aida_c03_require_sources("safe-headless adapters" ${_aida_result_sources} "${_aida_entries}")

    aida_c03_stage_runtime_tree("${AIDA_C03_TEST_ROOT}/fixtures" "src/standalone/tests/c03/fixtures" _aida_fixture_runtime)
    aida_c03_stage_runtime_file(
        "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
        "src/standalone/tests/c03/fixture_materializer.cpp")
    list(APPEND _aida_fixture_runtime "src/standalone/tests/c03/fixture_materializer.cpp")
    aida_c03_stage_runtime_file("${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/benchmark_search_receipt.json" "fixtures/benchmark_search_receipt.json")
    aida_c03_stage_runtime_file("${AIDA_C03_TEST_ROOT}/fixtures/external_sla_qualification_policy.json" "fixtures/external_sla_qualification_policy.json")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_a00_authority_surface_harness PACKAGE A00
        ENTRY_DEFINITION AIDA_C03_ENTRY_AUTHORITY
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/authority_surface_ledger.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a01_analysis_contracts_harness PACKAGE A01
        SOURCES "${AIDA_C03_TEST_ROOT}/analysis_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a02_decompiler_contracts_harness PACKAGE A02
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a04_workbench_contracts_harness PACKAGE A04
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_contracts_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_fixture_materializer_harness PACKAGE A06 ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "." "scratch/fixture-materializer"
        RUNTIME_FILES ${_aida_fixture_runtime})

    aida_c03_register_manifest_entry(
        TARGET aida_c03_b01_provider_snapshot_harness PACKAGE B01
        ENTRY_DEFINITION AIDA_C03_ENTRY_PROVIDER_SNAPSHOT
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/provider_snapshot_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b02_image_layout_index_harness PACKAGE B02
        SOURCES "${AIDA_C03_TEST_ROOT}/image_layout_index_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b03_packed_store_harness PACKAGE B03
        ENTRY_DEFINITION AIDA_C03_ENTRY_PACKED_STORE
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/packed_store_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b04_analysis_scheduler_harness PACKAGE B04
        SOURCES "${AIDA_C03_TEST_ROOT}/analysis_scheduler_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b05_x86_tile_decoder_harness PACKAGE B05
        SOURCES "${AIDA_C03_TEST_ROOT}/x86_tile_decoder_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b06_capstone_tile_decoder_harness PACKAGE B06
        SOURCES "${AIDA_C03_TEST_ROOT}/capstone_tile_decoder_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b07_container_stream_harness PACKAGE B07
        SOURCES "${AIDA_C03_TEST_ROOT}/container_stream_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b08_pe_reader_harness PACKAGE B08
        ENTRY_DEFINITION AIDA_C03_ENTRY_PE_READER
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/pe_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b09_elf_reader_harness PACKAGE B09
        SOURCES "${AIDA_C03_TEST_ROOT}/elf_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b10_macho_reader_harness PACKAGE B10
        SOURCES "${AIDA_C03_TEST_ROOT}/macho_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b11_managed_reader_harness PACKAGE B11
        ENTRY_DEFINITION AIDA_C03_ENTRY_MANAGED_READER
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/managed_reader_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b12_collection_graph_harness PACKAGE B12
        SOURCES "${AIDA_C03_TEST_ROOT}/collection_graph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b13_metrics_contract_harness PACKAGE B13
        SOURCES "${AIDA_C03_TEST_ROOT}/metrics_contract_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b14_native_worker_protocol_harness PACKAGE B14 ARGS_ENTRY
        SOURCES "${AIDA_C03_TEST_ROOT}/native_worker_protocol_harness.cpp"
        ARGUMENTS "--protocol-only")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b15_ghidra_ir_adapter_harness PACKAGE B15
        SOURCES "${AIDA_C03_TEST_ROOT}/ghidra_ir_adapter_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b16_cli_provider_harness PACKAGE B16
        SOURCES "${AIDA_C03_TEST_ROOT}/cli_provider_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b17_jvm_ssa_harness PACKAGE B17
        SOURCES "${AIDA_C03_TEST_ROOT}/jvm_ssa_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b18_dalvik_ssa_harness PACKAGE B18
        SOURCES "${AIDA_C03_TEST_ROOT}/dalvik_ssa_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b19_type_graph_harness PACKAGE B19
        SOURCES "${AIDA_C03_TEST_ROOT}/type_graph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b20_semantic_refiner_harness PACKAGE B20
        SOURCES "${AIDA_C03_TEST_ROOT}/semantic_refiner_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b21_pseudocode_renderer_harness PACKAGE B21
        SOURCES "${AIDA_C03_TEST_ROOT}/pseudocode_renderer_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b22_protocol_core_harness PACKAGE B22
        ENTRY_DEFINITION AIDA_C03_ENTRY_PROTOCOL_CORE
        SOURCES "${_aida_entries}" "${AIDA_C03_MCP_TEST_ROOT}/protocol_core_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b23_workspace_adapter_harness PACKAGE B23
        ENTRY_DEFINITION AIDA_C03_ENTRY_WORKSPACE_ADAPTER
        SOURCES "${_aida_entries}" "${AIDA_C03_MCP_TEST_ROOT}/workspace_adapter_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b24_python_worker_harness PACKAGE B24
        SOURCES "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/python_protocol_harness.cpp"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b25_workbench_model_harness PACKAGE B25
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_model_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b26_workbench_navigator_harness PACKAGE B26
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_navigator_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b27_workbench_inspector_harness PACKAGE B27
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_inspector_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b28_document_host_harness PACKAGE B28
        SOURCES "${AIDA_C03_TEST_ROOT}/document_host_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b29_overlay_journal_v9_harness PACKAGE B29
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_journal_v9_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_b30_live_snapshot_harness PACKAGE B30
        SOURCES "${AIDA_C03_TEST_ROOT}/live_snapshot_harness.cpp")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_c01_tile_decode_orchestrator_harness PACKAGE C01
        SOURCES "${AIDA_C03_TEST_ROOT}/tile_decode_orchestrator_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c02_function_cfg_callgraph_harness PACKAGE C02
        SOURCES "${AIDA_C03_TEST_ROOT}/function_cfg_callgraph_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c03_xref_discovery_harness PACKAGE C03
        SOURCES "${AIDA_C03_TEST_ROOT}/xref_discovery_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c04_search_query_harness PACKAGE C04
        ENTRY_DEFINITION AIDA_C03_ENTRY_SEARCH_QUERY
        SOURCES "${_aida_entries}" "${AIDA_C03_TEST_ROOT}/search_query_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c05_schema_v9_harness PACKAGE C05
        ENTRY_DEFINITION AIDA_C03_ENTRY_SCHEMA_V9
        SOURCES
            "${_aida_entries}"
            "${AIDA_C03_TEST_ROOT}/schema_v9_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_publication_persistence/managed_publication_persistence_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c06_decompiler_service_harness PACKAGE C06
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_service_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c07_decompiler_readability_harness PACKAGE C07
        SOURCES "${AIDA_C03_TEST_ROOT}/decompiler_readability_harness.cpp")

    set(_aida_mcp_harness_sources
        "${AIDA_C03_MCP_TEST_ROOT}/contract_generation_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/analysis_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/composite_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/core_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/debugger_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/memory_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/modify_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/python_handler_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/signature_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/stack_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/survey_handler_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/type_handlers_harness.cpp"
        "${AIDA_C03_MCP_TEST_ROOT}/routing_extensions_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c08_c19_mcp_compatibility_harness PACKAGE C08
        ENTRY_DEFINITION AIDA_C03_ENTRY_MCP_COMPATIBILITY
        SOURCES "${_aida_entries}" ${_aida_mcp_harness_sources})
    set_target_properties(aida_c03_c08_c19_mcp_compatibility_harness PROPERTIES
        AIDA_C03_PACKAGES "C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19"
        LABELS "c03;c03_safe_headless;safe-headless;C08;C09;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_security_mcp_client_auth_harness PACKAGE SECURITY
        ENTRY_DEFINITION AIDA_C03_ENTRY_MCP_CLIENT_AUTH
        SOURCES
            "${_aida_entries}"
            "${AIDA_C03_TEST_ROOT}/security/mcp_client_auth/mcp_client_auth_harness.cpp"
        INCLUDE_DIRECTORIES "${AIDA_C03_TEST_ROOT}/security/mcp_client_auth")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_c20_c22_workbench_documents_harness PACKAGE C20
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_documents_harness.cpp")
    set_target_properties(aida_c03_c20_c22_workbench_documents_harness PROPERTIES
        AIDA_C03_PACKAGES "C20;C21;C22"
        LABELS "c03;c03_safe_headless;safe-headless;C20;C21;C22")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c22_workbench_shell_lifecycle_harness PACKAGE C22
        SOURCES
            "${AIDA_C03_TEST_ROOT}/workbench_shell_lifecycle_harness.cpp"
            "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c23_workbench_persistence_harness PACKAGE C23
        SOURCES "${AIDA_C03_TEST_ROOT}/workbench_persistence_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c24_overlay_projection_harness PACKAGE C24
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_projection_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_c19_live_routing_integration_harness PACKAGE C19
        SOURCES "${AIDA_C03_TEST_ROOT}/live_routing_integration_harness.cpp")
    aida_c03_register_manifest_entry(
        TARGET aida_c03_managed_cli_snapshot_protocol_harness PACKAGE B16
        SOURCES
            "${AIDA_C03_TEST_ROOT}/managed_cli_snapshot_protocol/main.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_cli_snapshot_protocol/managed_cli_snapshot_protocol_harness.cpp")

    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_decompiler_quality_scorer_harness PACKAGE A06 ARGS_ENTRY
        MAX_ACTIVE_PROCESSES 4
        MAX_WALL_MS 1800000
        SOURCES
            "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/decompiler_quality_pipeline_main.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_provider_matrix/provider_matrix.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_provider_matrix/provider_matrix.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer_harness.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_scorer.hpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.hpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.hpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.hpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.hpp"
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_fixture_builder.hpp"
            "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
        ARGUMENTS
            "."
            "scratch/quality/evidence"
            "$<TARGET_FILE_DIR:${application_target}>"
            "scratch/quality/materialized"
            "scratch/quality/results"
            "120000"
        RUNTIME_FILES ${_aida_fixture_runtime})
    add_dependencies(aida_c03_a06_decompiler_quality_scorer_harness
        ${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}
        ${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}
        ${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET})
    aida_c03_register_manifest_entry(
        TARGET aida_c03_a06_benchmark_sla_receipt_harness PACKAGE A06 ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_receipt.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS "not-run" "scratch/benchmark" "fixtures/benchmark_search_receipt.json"
        RUNTIME_FILES
            "fixtures/benchmark_search_receipt.json"
            "fixtures/external_sla_qualification_policy.json"
            "src/standalone/tests/c03/fixtures/external_sla_qualification_policy.json")

    set(_aida_dependency_runtime)
    foreach(_aida_input IN LISTS
            AIDA_C03_REQUIRED_PRODUCTION_INPUTS
            AIDA_C03_REQUIRED_BUILD_INPUTS
            AIDA_C03_REQUIRED_EVIDENCE_INPUTS)
        file(RELATIVE_PATH _aida_relative "${CMAKE_SOURCE_DIR}" "${_aida_input}")
        string(REPLACE "\\" "/" _aida_relative "${_aida_relative}")
        aida_c03_stage_runtime_file("${_aida_input}" "${_aida_relative}")
        list(APPEND _aida_dependency_runtime "${_aida_relative}")
    endforeach()
    set(_aida_dependency_explicit
        ".gitignore"
        "cmake/aida_c03_dependencies.cmake"
        "cmake/aida_c03_package_integration.cmake"
        "cmake/aida_c03_safe_headless_manifest.cmake"
        "deploy_to_server.ps1"
        "licenses/c03/THIRD_PARTY_NOTICES.md")
    foreach(_aida_relative IN LISTS _aida_dependency_explicit)
        aida_c03_stage_runtime_file("${CMAKE_SOURCE_DIR}/${_aida_relative}" "${_aida_relative}")
        list(APPEND _aida_dependency_runtime "${_aida_relative}")
    endforeach()
    list(REMOVE_DUPLICATES _aida_dependency_runtime)
    aida_c03_register_manifest_entry(
        TARGET aida_c03_dependency_inventory_harness PACKAGE A05 ARGS_ENTRY
        SOURCES "${AIDA_C03_TEST_ROOT}/dependency_inventory_harness.cpp"
        ARGUMENTS "."
        RUNTIME_FILES ${_aida_dependency_runtime})

    set(_aida_managed_runtime_source_root
        "${CMAKE_SOURCE_DIR}/.deps/dotnet-sdk-10.0.301-win-x64")
    set(_aida_managed_runtime_sources
        "${_aida_managed_runtime_source_root}/dotnet.exe"
        "${_aida_managed_runtime_source_root}/LICENSE.txt"
        "${_aida_managed_runtime_source_root}/ThirdPartyNotices.txt"
        "${_aida_managed_runtime_source_root}/host/fxr/10.0.9/hostfxr.dll")
    file(GLOB _aida_managed_framework_sources CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE
        "${_aida_managed_runtime_source_root}/shared/Microsoft.NETCore.App/10.0.9/*")
    list(LENGTH _aida_managed_framework_sources _aida_managed_framework_source_count)
    if(NOT _aida_managed_framework_source_count EQUAL 189)
        message(FATAL_ERROR "AiDA C03 managed safe-headless runtime requires the exact 189-file .NET 10.0.9 framework inventory")
    endif()
    list(APPEND _aida_managed_runtime_sources ${_aida_managed_framework_sources})
    list(LENGTH _aida_managed_runtime_sources _aida_managed_runtime_source_count)
    if(NOT _aida_managed_runtime_source_count EQUAL 193)
        message(FATAL_ERROR "AiDA C03 managed safe-headless runtime requires the exact 193-file host/framework inventory")
    endif()
    set(_aida_build_packaging_runtime
        "packaging/c03_worker_runtime/managed_runtime_source_spec.json")
    aida_c03_stage_runtime_file(
        "${CMAKE_SOURCE_DIR}/packaging/c03_worker_runtime/managed_runtime_source_spec.json"
        "packaging/c03_worker_runtime/managed_runtime_source_spec.json")
    foreach(_aida_managed_runtime_source IN LISTS _aida_managed_runtime_sources)
        file(RELATIVE_PATH _aida_managed_runtime_relative
            "${CMAKE_SOURCE_DIR}" "${_aida_managed_runtime_source}")
        string(REPLACE "\\" "/" _aida_managed_runtime_relative
            "${_aida_managed_runtime_relative}")
        aida_c03_stage_runtime_file(
            "${_aida_managed_runtime_source}" "${_aida_managed_runtime_relative}")
        list(APPEND _aida_build_packaging_runtime "${_aida_managed_runtime_relative}")
    endforeach()
    aida_c03_register_manifest_entry(
        TARGET aida_c03_build_packaging_integration_harness PACKAGE D06
        SOURCES "${AIDA_C03_TEST_ROOT}/build_packaging_integration_harness.cpp"
        COMPILE_DEFINITIONS AIDA_C03_PACKAGE_FIXTURE_ADAPTERS=1
        RUNTIME_FILES ${_aida_build_packaging_runtime})
    aida_c03_register_manifest_entry(
        TARGET aida_c03_surface_reconciliation_harness PACKAGE D08
        SOURCES "${AIDA_C03_TEST_ROOT}/surface_reconciliation_harness.cpp")

    set(_aida_policy_runtime
        "CMakeLists.txt"
        "src/standalone/src/main.cpp"
        "deploy_to_server.ps1"
        "src/standalone/src/core/auth/auth_browser_launch.hpp"
        "packaging/c03_distribution_manifest.ps1"
        "packaging/c03_distribution_fixture/path_byte_policy.json"
        "src/standalone/tools/c03_package_verifier/main.cpp"
        "src/standalone/src/core/analysis/build_worker_packaging_integration.cpp"
        "src/standalone/tests/c03/build_packaging_integration_harness.cpp"
        "src/standalone/tests/c03/auth_browser_dispatch/auth_browser_dispatch_harness.hpp"
        "src/standalone/tests/c03/auth_browser_dispatch/auth_browser_dispatch_harness.cpp"
        "src/standalone/tests/c03/package_distribution_policy/package_distribution_policy_harness.ps1"
        "src/standalone/tests/c03/package_distribution_policy/policy_stage_spec.json"
        "src/standalone/src/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "src/standalone/tests/c03/testlab_runtime/materialize_safe_headless_manifest.py"
        "cmake/aida_c03_safe_headless_manifest.cmake"
        "cmake/aida_c03_package_integration.cmake"
        "cmake/aida_c03_dependencies.cmake"
        "cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_policy.cmake"
        "cmake/c03_safe_headless/package_policy_fixture/aida_c03_path_identity.ps1"
        "cmake/c03_safe_headless/target_resource_policy_cases.json"
        "cmake/c03_safe_headless/decompiler_quality_pipeline_main.cpp"
        "tools/c03_authority/verify_authority_surface_ledger.py"
        "tools/c03_authority/authority_surface_ledger.json"
        "tools/generate_ida_mcp_contracts/generate_ida_mcp_contracts.py"
        "src/standalone/tests/analysis_workspace/generate_surface_manifest.ps1"
        "src/standalone/tests/analysis_workspace/standalone_surface_baseline.json"
        "src/standalone/tests/analysis_workspace/standalone_surface_final.json"
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/contracts.json"
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/effect_ledger.json"
        "src/standalone/src/resources/mcp/ida_pro_mcp_2_0_0/archive_manifest.json"
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.hpp"
        "src/standalone/src/core/mcp/compat/ida_contracts_generated.cpp")
    foreach(_aida_relative IN LISTS _aida_policy_runtime)
        aida_c03_stage_runtime_file("${CMAKE_SOURCE_DIR}/${_aida_relative}" "${_aida_relative}")
    endforeach()
    aida_c03_register_manifest_entry(
        TARGET aida_c03_source_policy_scanner PACKAGE D08 ARGS_ENTRY
        SOURCES "${AIDA_C03_TEST_ROOT}/testlab_runtime/source_policy_scanner.cpp"
        ARGUMENTS "."
        RUNTIME_FILES ${_aida_policy_runtime})

    set(_aida_anti_tamper_runtime
        "src/standalone/src/core/anti-tamper/anti_hook.hpp"
        "src/standalone/src/core/anti-tamper/re_detection_engine.hpp"
        "src/standalone/src/core/anti-tamper/orchestrator.hpp"
        "src/standalone/src/core/anti-tamper/anti_dump.hpp")
    foreach(_aida_relative IN LISTS _aida_anti_tamper_runtime)
        aida_c03_stage_runtime_file("${CMAKE_SOURCE_DIR}/${_aida_relative}" "${_aida_relative}")
    endforeach()
    aida_c03_register_manifest_entry(
        TARGET aida_c03_anti_tamper_integrity_harness PACKAGE SECURITY ARGS_ENTRY
        SOURCES
            "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/anti_tamper_integrity_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/self_guard_policy_cases.cpp"
            "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/prologue_policy_cases.cpp"
            "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/dma_policy_cases.cpp"
            "${AIDA_C03_TEST_ROOT}/security/anti_tamper_integrity/passive_probe_policy_cases.cpp"
        ARGUMENTS "."
        RUNTIME_FILES ${_aida_anti_tamper_runtime})

    get_property(_aida_manifest_targets GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGETS)
    get_property(_aida_manifest_records GLOBAL PROPERTY AIDA_C03_MANIFEST_TARGET_RECORDS)
    list(LENGTH _aida_manifest_targets _aida_manifest_target_count)
    list(LENGTH _aida_manifest_records _aida_manifest_record_count)
    if(NOT _aida_manifest_target_count EQUAL 57 OR NOT _aida_manifest_record_count EQUAL 57)
        message(FATAL_ERROR "AiDA C03 canonical manifest cardinality is invalid: targets=${_aida_manifest_target_count}, records=${_aida_manifest_record_count}")
    endif()
    file(READ "${AIDA_C03_SAFE_HEADLESS_INVENTORY}" _aida_inventory_json)
    string(JSON _aida_inventory_schema GET "${_aida_inventory_json}" schema)
    string(JSON _aida_inventory_count LENGTH "${_aida_inventory_json}" entries)
    if(NOT _aida_inventory_schema STREQUAL "aida.c03.safe-headless.inventory.v1" OR
       NOT _aida_inventory_count EQUAL 57)
        message(FATAL_ERROR "AiDA C03 safe-headless inventory identity or cardinality is invalid")
    endif()
    math(EXPR _aida_inventory_last "${_aida_inventory_count} - 1")
    set(_aida_inventory_targets)
    foreach(_aida_index RANGE 0 ${_aida_inventory_last})
        string(JSON _aida_inventory_target GET "${_aida_inventory_json}" entries ${_aida_index} source_target)
        if(_aida_inventory_target IN_LIST _aida_inventory_targets OR
           NOT _aida_inventory_target IN_LIST _aida_manifest_targets)
            message(FATAL_ERROR "AiDA C03 inventory target is duplicated or unregistered: ${_aida_inventory_target}")
        endif()
        list(APPEND _aida_inventory_targets "${_aida_inventory_target}")
    endforeach()
    foreach(_aida_target IN LISTS _aida_manifest_targets)
        if(NOT _aida_target IN_LIST _aida_inventory_targets)
            message(FATAL_ERROR "AiDA C03 manifest target is absent from the canonical inventory: ${_aida_target}")
        endif()
    endforeach()
    file(READ "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}" _aida_assertion_inventory_json)
    string(JSON _aida_assertion_inventory_schema GET "${_aida_assertion_inventory_json}" schema)
    string(JSON _aida_assertion_inventory_version GET "${_aida_assertion_inventory_json}" version)
    string(JSON _aida_assertion_entry_count GET "${_aida_assertion_inventory_json}" entry_count)
    string(JSON _aida_assertion_source_count GET "${_aida_assertion_inventory_json}" all_inventory_source_files_with_static_record_calls)
    string(JSON _aida_assertion_site_count GET "${_aida_assertion_inventory_json}" all_inventory_static_record_call_count)
    string(JSON _aida_assertion_pending_count GET "${_aida_assertion_inventory_json}" pending_handoff_entry_count)
    string(JSON _aida_assertion_entries_length LENGTH "${_aida_assertion_inventory_json}" entries)
    if(NOT _aida_assertion_inventory_schema STREQUAL "aida.c03.safe-headless.assertion-sites.v1" OR
       NOT _aida_assertion_inventory_version EQUAL 1 OR
       NOT _aida_assertion_entry_count EQUAL 57 OR
       NOT _aida_assertion_entries_length EQUAL 57 OR
       NOT _aida_assertion_source_count EQUAL 71 OR
       NOT _aida_assertion_site_count EQUAL 187 OR
       NOT _aida_assertion_pending_count EQUAL 0)
        message(FATAL_ERROR "AiDA C03 assertion telemetry inventory identity, cardinality, or handoff state is invalid")
    endif()
    set(_aida_assertion_targets)
    foreach(_aida_index RANGE 0 56)
        string(JSON _aida_assertion_target GET "${_aida_assertion_inventory_json}" entries ${_aida_index} target)
        if(_aida_assertion_target IN_LIST _aida_assertion_targets OR
           NOT _aida_assertion_target IN_LIST _aida_manifest_targets)
            message(FATAL_ERROR "AiDA C03 assertion telemetry target is duplicated or unregistered: ${_aida_assertion_target}")
        endif()
        list(APPEND _aida_assertion_targets "${_aida_assertion_target}")
    endforeach()

    string(JOIN "," _aida_records_joined ${_aida_manifest_records})
    file(GENERATE OUTPUT "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
        CONTENT "{\"schema\":\"aida.c03.safe-headless.target-records.v2\",\"version\":2,\"targets\":[${_aida_records_joined}]}\n")
    get_property(_aida_runtime_outputs GLOBAL PROPERTY AIDA_C03_RUNTIME_OUTPUTS)
    add_custom_target(aida_c03_safe_headless_runtime_files DEPENDS ${_aida_runtime_outputs})
    set_target_properties(aida_c03_safe_headless_runtime_files PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_AUTHORITY_LEDGER_SHA256 "${_aida_authority_ledger_sha256}"
        AIDA_C03_AUTHORITY_VERIFIER_SHA256 "${_aida_authority_verifier_sha256}"
        AIDA_C03_SURFACE_GENERATOR_SHA256 "${_aida_surface_generator_sha256}"
        AIDA_C03_SURFACE_BASELINE_SHA256 "${_aida_surface_baseline_sha256}"
        AIDA_C03_SURFACE_FINAL_SHA256 "${_aida_surface_final_sha256}"
        LABELS "c03;c03_safe_headless;safe-headless;fixtures")

    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_INVENTORY}" _aida_contract_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}" _aida_assertion_inventory_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}" _aida_materializer_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}" _aida_resource_policy_cases_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/CMakeLists.txt" _aida_root_cmake_identity)
    file(SHA256 "${AIDA_C03_SAFE_HEADLESS_CMAKE_MODULE}" _aida_manifest_cmake_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/cmake/aida_c03_dependencies.cmake" _aida_dependency_cmake_identity)
    file(SHA256 "${CMAKE_SOURCE_DIR}/cmake/aida_c03_package_integration.cmake" _aida_package_cmake_identity)
    string(TOLOWER "${_aida_contract_identity}" _aida_contract_identity)
    string(TOLOWER "${_aida_assertion_inventory_identity}" _aida_assertion_inventory_identity)
    string(SHA256 _aida_build_identity
        "aida-c03-safe-headless|${_aida_contract_identity}|${_aida_assertion_inventory_identity}|${_aida_materializer_identity}|${_aida_resource_policy_cases_identity}|${_aida_root_cmake_identity}|${_aida_manifest_cmake_identity}|${_aida_dependency_cmake_identity}|${_aida_package_cmake_identity}|${_aida_authority_identity}")
    string(TOLOWER "${_aida_build_identity}" _aida_build_identity)
    add_custom_command(OUTPUT "${AIDA_C03_SAFE_HEADLESS_MANIFEST}" "${AIDA_C03_SAFE_HEADLESS_DIGEST}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}/scratch"
        COMMAND "${_aida_python_executable}" "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}"
            --inventory "${AIDA_C03_SAFE_HEADLESS_INVENTORY}"
            --target-records "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
            --policy-cases "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
            --approved-root "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}"
            --output "${AIDA_C03_SAFE_HEADLESS_MANIFEST}"
            --digest "${AIDA_C03_SAFE_HEADLESS_DIGEST}"
            --build-identity "${_aida_build_identity}"
            --contract-identity "${_aida_contract_identity}"
        DEPENDS
            ${_aida_manifest_targets}
            aida_c03_safe_headless_runtime_files
            "${AIDA_C03_SAFE_HEADLESS_RECORDS}"
            "${AIDA_C03_SAFE_HEADLESS_INVENTORY}"
            "${AIDA_C03_SAFE_HEADLESS_ASSERTION_INVENTORY}"
            "${AIDA_C03_SAFE_HEADLESS_MATERIALIZER}"
            "${AIDA_C03_SAFE_HEADLESS_RESOURCE_POLICY_CASES}"
        VERBATIM)
    add_custom_command(OUTPUT "${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}"
        COMMAND ${CMAKE_COMMAND}
            -DAIDA_C03_DIGEST_FILE="${AIDA_C03_SAFE_HEADLESS_DIGEST}"
            -DAIDA_C03_HEADER_FILE="${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}"
            -P "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/write_digest_header.cmake"
        DEPENDS
            "${AIDA_C03_SAFE_HEADLESS_MANIFEST}"
            "${AIDA_C03_SAFE_HEADLESS_DIGEST}"
            "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/write_digest_header.cmake"
        VERBATIM)
    add_custom_target(aida_c03_safe_headless_manifest
        DEPENDS
            "${AIDA_C03_SAFE_HEADLESS_MANIFEST}"
            "${AIDA_C03_SAFE_HEADLESS_DIGEST}"
            "${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}")
    set_target_properties(aida_c03_safe_headless_manifest PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_DEVELOPER_ONLY TRUE
        AIDA_C03_DEVELOPER_SUITE_OUTPUTS "suite/$<CONFIG>/manifest.json;suite/$<CONFIG>/manifest.sha256"
        AIDA_C03_ASSERTION_INVENTORY_SHA256 "${_aida_assertion_inventory_identity}"
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_AUTHORITY_LEDGER_SHA256 "${_aida_authority_ledger_sha256}"
        AIDA_C03_AUTHORITY_VERIFIER_SHA256 "${_aida_authority_verifier_sha256}"
        AIDA_C03_CONTRACT_GENERATOR_SHA256 "${_aida_contract_generator_sha256}"
        AIDA_C03_SURFACE_GENERATOR_SHA256 "${_aida_surface_generator_sha256}"
        AIDA_C03_SURFACE_BASELINE_SHA256 "${_aida_surface_baseline_sha256}"
        AIDA_C03_SURFACE_FINAL_SHA256 "${_aida_surface_final_sha256}"
        AIDA_C03_PYTHON_EXECUTABLE "${_aida_python_executable}"
        AIDA_C03_PYTHON_SHA256 "${_aida_python_sha256}"
        AIDA_C03_POWERSHELL_EXECUTABLE "${_aida_system_powershell}"
        AIDA_C03_POWERSHELL_SHA256 "${_aida_system_powershell_sha256}"
        AIDA_C03_MCP_ARCHIVE "${_aida_authority_archive}"
        AIDA_C03_MCP_ARCHIVE_SHA256 "${_aida_authority_archive_sha256}"
        LABELS "c03;c03_safe_headless;safe-headless;manifest")

    add_custom_target(aida_c03_safe_headless_application_package
        DEPENDS aida_c03_safe_headless_manifest
        COMMENT "Binding the detached C03 safe-headless manifest identity to ${application_target}"
        VERBATIM)
    set_target_properties(aida_c03_safe_headless_application_package PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_SAFE_HEADLESS TRUE
        AIDA_C03_AUTHORITY_SURFACE_IDENTITY "${_aida_authority_identity}"
        AIDA_C03_PYTHON_SHA256 "${_aida_python_sha256}"
        AIDA_C03_POWERSHELL_SHA256 "${_aida_system_powershell_sha256}"
        AIDA_C03_MCP_ARCHIVE_SHA256 "${_aida_authority_archive_sha256}"
        AIDA_C03_CUSTOMER_PAYLOAD_FORBIDDEN TRUE
        LABELS "c03;c03_safe_headless;safe-headless;package")
    add_dependencies(${application_target} aida_c03_safe_headless_application_package)
    target_include_directories(${application_target} PRIVATE "${AIDA_C03_SAFE_HEADLESS_GENERATED_ROOT}")
    target_compile_options(${application_target} PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:/FI${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}>")

    add_executable(aida_c03_safe_headless_manifest_suite
        "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/manifest_suite_main.cpp"
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${imgui_SOURCE_DIR}/imgui.cpp"
        "${imgui_SOURCE_DIR}/imgui_draw.cpp"
        "${imgui_SOURCE_DIR}/imgui_tables.cpp"
        "${imgui_SOURCE_DIR}/imgui_widgets.cpp")
    aida_c03_configure_native_target(aida_c03_safe_headless_manifest_suite)
    target_include_directories(aida_c03_safe_headless_manifest_suite PRIVATE "${imgui_SOURCE_DIR}")
    target_compile_options(aida_c03_safe_headless_manifest_suite PRIVATE "/FI${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}")
    target_link_libraries(aida_c03_safe_headless_manifest_suite PRIVATE
        aida_c03_safe_headless_runtime bcrypt advapi32 userenv)
    add_dependencies(aida_c03_safe_headless_manifest_suite aida_c03_safe_headless_manifest)
    set_target_properties(aida_c03_safe_headless_manifest_suite PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Direct"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless;manifest-suite")
    add_test(NAME aida_c03_safe_headless_manifest_suite
        COMMAND $<TARGET_FILE:aida_c03_safe_headless_manifest_suite> "${AIDA_C03_SAFE_HEADLESS_STAGE_ROOT}")
    set_tests_properties(aida_c03_safe_headless_manifest_suite PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 14400
        LABELS "c03;c03_safe_headless;safe-headless;manifest-suite"
        RESOURCE_LOCK "aida_c03_safe_headless_manifest")

    add_executable(aida_c03_testlab_fake_safe_headless_adapter
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/fake_safe_headless_adapter.cpp")
    aida_c03_configure_native_target(aida_c03_testlab_fake_safe_headless_adapter)
    set_target_properties(aida_c03_testlab_fake_safe_headless_adapter PROPERTIES
        OUTPUT_NAME "aida_c03_testlab_fake_safe_headless_adapter"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE)
    add_executable(aida_c03_b14_fake_native_decompiler_worker
        "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp")
    aida_c03_configure_native_target(aida_c03_b14_fake_native_decompiler_worker)
    target_link_libraries(aida_c03_b14_fake_native_decompiler_worker PRIVATE bcrypt advapi32 ws2_32)
    set_target_properties(aida_c03_b14_fake_native_decompiler_worker PROPERTIES
        OUTPUT_NAME "fake_native_decompiler_worker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE)
    add_executable(aida_c03_b24_fake_analysis_python_worker
        "${STANDALONE_ROOT}/../workers/analysis_python/fake_analysis_python_worker.cpp")
    aida_c03_configure_native_target(aida_c03_b24_fake_analysis_python_worker)
    target_include_directories(aida_c03_b24_fake_analysis_python_worker PRIVATE
        "${STANDALONE_ROOT}/../workers/analysis_python")
    target_link_libraries(aida_c03_b24_fake_analysis_python_worker PRIVATE bcrypt advapi32 ws2_32)
    set_target_properties(aida_c03_b24_fake_analysis_python_worker PROPERTIES
        OUTPUT_NAME "fake_analysis_python_worker"
        RUNTIME_OUTPUT_DIRECTORY "${AIDA_C03_DEVELOPER_ROOT}/direct/$<CONFIG>"
        FOLDER "Tests/C03/SafeHeadless/Support"
        AIDA_C03_SAFE_HEADLESS TRUE)
    set_property(GLOBAL APPEND PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS
        "${AIDA_C03_SAFE_HEADLESS_CMAKE_ROOT}/c03_safe_headless/manifest_suite_main.cpp"
        "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
        "${AIDA_C03_TEST_ROOT}/testlab_runtime/fake_safe_headless_adapter.cpp"
        "${STANDALONE_ROOT}/../workers/native_decompiler/fake_native_decompiler_worker.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_contracts.cpp"
        "${STANDALONE_ROOT}/core/analysis/workspace/workspace_identity.cpp"
        "${STANDALONE_ROOT}/../workers/analysis_python/fake_analysis_python_worker.cpp")

    aida_c03_register_direct_test(
        TARGET aida_c03_testlab_runtime_integration_harness PACKAGE D07 TIMEOUT 180
        SOURCES
            "${AIDA_C03_TEST_ROOT}/harness_testlab_integration.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_c03_safe_headless.cpp"
            "${imgui_SOURCE_DIR}/imgui.cpp"
            "${imgui_SOURCE_DIR}/imgui_draw.cpp"
            "${imgui_SOURCE_DIR}/imgui_tables.cpp"
            "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
        ARGUMENTS
            "$<TARGET_FILE:aida_c03_testlab_fake_safe_headless_adapter>"
            "${AIDA_C03_DEVELOPER_ROOT}/scratch/testlab"
        INCLUDE_DIRECTORIES "${imgui_SOURCE_DIR}"
        COMPILE_DEFINITIONS AIDA_C03_SAFE_HEADLESS_MANIFEST_SHA256=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"
        LINK_LIBRARIES bcrypt advapi32 userenv
        DEPENDS aida_c03_testlab_fake_safe_headless_adapter)
    aida_c03_register_direct_test(
        TARGET aida_c03_b14_native_worker_containment_harness PACKAGE B14 TIMEOUT 180
        SOURCES "${AIDA_C03_TEST_ROOT}/native_worker_protocol_harness.cpp"
        ARGUMENTS
            "$<TARGET_FILE:aida_c03_b14_fake_native_decompiler_worker>"
            "${AIDA_C03_DEVELOPER_ROOT}/scratch/native-worker"
        LINK_LIBRARIES bcrypt advapi32 userenv ws2_32
        DEPENDS aida_c03_b14_fake_native_decompiler_worker)
    aida_c03_register_direct_test(
        TARGET aida_c03_b24_python_worker_containment_harness PACKAGE B24 TIMEOUT 180
        SOURCES
            "${AIDA_C03_MCP_TEST_ROOT}/python_worker_harness_main.cpp"
            "${AIDA_C03_MCP_TEST_ROOT}/python_worker_harness.cpp"
        ARGUMENTS "$<TARGET_FILE:aida_c03_b24_fake_analysis_python_worker>"
        INCLUDE_DIRECTORIES "${STANDALONE_ROOT}/../workers/analysis_python"
        LINK_LIBRARIES bcrypt advapi32 userenv ws2_32
        DEPENDS aida_c03_b24_fake_analysis_python_worker)
    aida_c03_register_direct_test(
        TARGET aida_c03_mcp_production_core_harness PACKAGE D03 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/mcp_production_core/main.cpp"
            "${AIDA_C03_TEST_ROOT}/mcp_production_core/mcp_production_core_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_compact_dex_harness PACKAGE B11
        SOURCES "${AIDA_C03_TEST_ROOT}/compact_dex/compact_dex_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_overlay_lifecycle_harness PACKAGE C24
        SOURCES "${AIDA_C03_TEST_ROOT}/overlay_lifecycle_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_managed_overlay_identity_harness PACKAGE C24 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/managed_overlay_identity/main.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_overlay_identity/managed_overlay_identity_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_auth_browser_dispatch_harness PACKAGE D08 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp")
    aida_c03_register_direct_test(
        NO_SHARED_RUNTIME
        TARGET aida_c03_auth_browser_dispatch_preview_harness PACKAGE D08 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/auth_browser_dispatch/auth_browser_dispatch_harness.cpp"
        COMPILE_DEFINITIONS AIDA_IMGUI_STUDIO_PREVIEW=1
        LINK_LIBRARIES aida_c03_auth_preview_implementation)

    aida_c03_register_direct_test(
        TARGET aida_c03_fixture_materializer_direct PACKAGE A06 TIMEOUT 300
        SOURCES
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness_main.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/fixture_materializer.cpp"
            "${AIDA_C03_TEST_ROOT}/managed_fixture_fidelity/managed_fixture_fidelity.cpp"
            "${AIDA_C03_TEST_ROOT}/decompiler_quality_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS
            "${CMAKE_SOURCE_DIR}"
            "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized")
    set_tests_properties(aida_c03_fixture_materializer_direct PROPERTIES
        FIXTURES_SETUP aida_c03_materialized_corpus)

    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_core_harness PACKAGE D01 TIMEOUT 600
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_core_harness.cpp"
            "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
        LINK_LIBRARIES bcrypt)
    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_persistence_harness PACKAGE D01 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_persistence_harness.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_workspace_multitarget_harness PACKAGE D01 TIMEOUT 600
        SOURCES "${AIDA_C03_WORKSPACE_TEST_ROOT}/workspace_multitarget_harness.cpp")

    aida_c03_register_direct_test(
        TARGET aida_c03_analysis_benchmark_harness PACKAGE A06 TIMEOUT 1200
        SOURCES
            "${AIDA_C03_WORKSPACE_TEST_ROOT}/analysis_benchmark_harness.cpp"
            "${AIDA_C03_TEST_ROOT}/benchmark_sla_schema.cpp"
            "${AIDA_C03_TEST_ROOT}/evidence_hash.cpp"
        ARGUMENTS
            "deterministic_component"
            "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/pe32plus-x64.exe"
        LINK_LIBRARIES bcrypt)
    set_tests_properties(aida_c03_analysis_benchmark_harness PROPERTIES
        FIXTURES_REQUIRED aida_c03_materialized_corpus)

    set(_aida_managed_consumer_sources
        "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/main.cpp"
        "${AIDA_C03_TEST_ROOT}/managed_decompiler_consumers/managed_decompiler_consumers_harness.cpp"
        "${STANDALONE_ROOT}/core/analysis/decompiler/decompiler_ui_integration.cpp"
        "${STANDALONE_ROOT}/core/workbench/workbench_shell_integration.cpp")
    aida_c03_register_direct_test(
        TARGET aida_c03_managed_decompiler_consumers_harness PACKAGE D02 TIMEOUT 1200
        SOURCES ${_aida_managed_consumer_sources}
        ARGUMENTS
            "--cli-fixture" "${AIDA_C03_MANAGED_FIXTURE_DLL}"
            "--class-fixture" "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/classfile-jvm.class"
            "--dex-fixture" "${AIDA_C03_DEVELOPER_ROOT}/fixtures/materialized/first/dex-dalvik.dex"
        LINK_LIBRARIES
            bcrypt
        DEPENDS aida_c03_a06_managed_cli_fixture)
    set_tests_properties(aida_c03_managed_decompiler_consumers_harness PROPERTIES
        FIXTURES_REQUIRED aida_c03_materialized_corpus)
    if(TARGET ${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET})
        add_dependencies(aida_c03_managed_decompiler_consumers_harness
            ${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET})
    endif()

    add_test(NAME aida_c03_authority_surface_reproduction
        COMMAND "${_aida_python_executable}"
            "${CMAKE_SOURCE_DIR}/tools/c03_authority/verify_authority_surface_ledger.py"
            --repository-root "${CMAKE_SOURCE_DIR}"
            --ledger "${CMAKE_SOURCE_DIR}/tools/c03_authority/authority_surface_ledger.json"
            --archive "${_aida_authority_archive}"
            --powershell "${_aida_system_powershell}")
    set_tests_properties(aida_c03_authority_surface_reproduction PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 600
        LABELS "c03;c03_safe_headless;safe-headless;authority;surface;contract-reproduction"
        RESOURCE_LOCK "aida_c03_authority_surface_reproduction")

    add_test(NAME aida_c03_package_distribution_policy
        COMMAND "${_aida_system_powershell}" -NoLogo -NoProfile -NonInteractive
            -ExecutionPolicy Bypass
            -File "${AIDA_C03_TEST_ROOT}/package_distribution_policy/package_distribution_policy_harness.ps1"
            -PowerShellExecutable "${_aida_system_powershell}"
            -Producer "${CMAKE_SOURCE_DIR}/packaging/c03_distribution_manifest.ps1"
            -ContractVerifier "$<TARGET_FILE:aida_c03_build_packaging_integration_harness>"
            -ProductionVerifier "$<TARGET_FILE:aida_c03_package_verifier>"
            -StageSpec "${AIDA_C03_TEST_ROOT}/package_distribution_policy/policy_stage_spec.json"
            -PathBytePolicy "${CMAKE_SOURCE_DIR}/packaging/c03_distribution_fixture/path_byte_policy.json"
            -AuthorityLock "${AIDA_C03_WORKER_MANIFEST_LOCK}"
            -ProtectorTool "$<TARGET_FILE:AiDAProtector>"
            -ProtectorVerifier "$<TARGET_FILE:AiDAProtectorVerify>"
            -ScratchRoot "${AIDA_C03_DEVELOPER_ROOT}/scratch/package-policy/$<CONFIG>")
    set_tests_properties(aida_c03_package_distribution_policy PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT 1200
        LABELS "c03;c03_safe_headless;safe-headless;package;distribution;policy"
        RESOURCE_LOCK "aida_c03_package_distribution_policy")

    get_property(_aida_compiler_harness_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_HARNESS_INPUTS)
    get_property(_aida_compiler_native_worker_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_NATIVE_WORKER_INPUTS)
    get_property(_aida_compiler_managed_worker_inputs GLOBAL PROPERTY AIDA_C03_COMPILER_MATRIX_MANAGED_WORKER_INPUTS)
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_06 ${_aida_compiler_native_worker_inputs})
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_07 ${_aida_compiler_managed_worker_inputs})
    list(APPEND AIDA_C03_COMPILER_MATRIX_CM_14 ${_aida_compiler_harness_inputs})
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_06)
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_07)
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_CM_14)
    set(AIDA_C03_COMPILER_MATRIX_UNION)
    foreach(_aida_matrix_suffix IN ITEMS 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15)
        list(APPEND AIDA_C03_COMPILER_MATRIX_UNION ${AIDA_C03_COMPILER_MATRIX_CM_${_aida_matrix_suffix}})
    endforeach()
    list(REMOVE_DUPLICATES AIDA_C03_COMPILER_MATRIX_UNION)
    foreach(_aida_production_source IN LISTS AIDA_C03_PRODUCTION_STANDALONE_SOURCES)
        if(NOT _aida_production_source IN_LIST AIDA_C03_COMPILER_MATRIX_UNION)
            message(FATAL_ERROR "AiDA C03 production source is absent from CM-01..CM-15: ${_aida_production_source}")
        endif()
    endforeach()
    foreach(_aida_runtime_source IN LISTS _aida_runtime_sources)
        if(NOT _aida_runtime_source IN_LIST AIDA_C03_COMPILER_MATRIX_UNION)
            message(FATAL_ERROR "AiDA C03 safe-headless runtime source is absent from CM-01..CM-15: ${_aida_runtime_source}")
        endif()
    endforeach()
    aida_c03_require_sources("CM-01..CM-15 compiler matrix" ${AIDA_C03_COMPILER_MATRIX_UNION})

    get_property(_aida_direct_targets GLOBAL PROPERTY AIDA_C03_DIRECT_TARGETS)
    add_custom_target(aida_c03_safe_headless_harnesses ALL
        DEPENDS
            aida_c03_safe_headless_manifest
            aida_c03_safe_headless_manifest_suite
            ${_aida_direct_targets}
        SOURCES ${AIDA_C03_COMPILER_MATRIX_UNION})
    set_target_properties(aida_c03_safe_headless_harnesses PROPERTIES
        FOLDER "Tests/C03/SafeHeadless"
        AIDA_C03_SAFE_HEADLESS TRUE
        LABELS "c03;c03_safe_headless;safe-headless")
    set_property(TARGET aida_c03_safe_headless_harnesses PROPERTY
        AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}")
    set_property(TARGET ${application_target} PROPERTY
        AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}")

    set(AIDA_C03_SAFE_HEADLESS_TARGETS "${_aida_manifest_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_DIRECT_TARGETS "${_aida_direct_targets}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_MANIFEST "${AIDA_C03_SAFE_HEADLESS_MANIFEST}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_DIGEST "${AIDA_C03_SAFE_HEADLESS_DIGEST}" PARENT_SCOPE)
    set(AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER "${AIDA_C03_SAFE_HEADLESS_DIGEST_HEADER}" PARENT_SCOPE)
    set(AIDA_C03_COMPILER_MATRIX_CM_15 "${AIDA_C03_COMPILER_MATRIX_CM_15}" PARENT_SCOPE)
    set(AIDA_C03_COMPILER_MATRIX_UNION "${AIDA_C03_COMPILER_MATRIX_UNION}" PARENT_SCOPE)
endfunction()
