include_guard(GLOBAL)

if(NOT WIN32)
    message(FATAL_ERROR "AiDA C03 dependencies are Windows-only")
endif()

set(AIDA_C03_DEPENDENCY_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
cmake_path(NORMAL_PATH AIDA_C03_DEPENDENCY_ROOT)
set(AIDA_C03_NOTICE_LEDGER "${AIDA_C03_DEPENDENCY_ROOT}/licenses/c03/THIRD_PARTY_NOTICES.md")
set(AIDA_C03_WORKER_MANIFEST_SCHEMA "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_worker_manifest.schema.json")
set(AIDA_C03_WORKER_MANIFEST_SCHEMA_SHA256 "8c9bd6e9a2f5003af5bf55fd2e75fb7b60fbf8294e7f1613beca6242924e7f6a")
set(AIDA_C03_WORKER_MANIFEST_LOCK "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_worker_manifest.lock.json")
set(AIDA_C03_WORKER_MANIFEST_LOCK_SHA256 "7d7995b62bbaa3b6e5a24942cadd8c44e97a91fa1d9d3067a0e3a2856b3cac05")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_SCHEMA "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_native_worker_manifest.schema.json")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_SCHEMA_SHA256 "32ed5de9fde31039518946d6c28f7681675398466959daa2eb100e5d16746655")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_native_worker_manifest.json")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT_SHA256 "93365a40798b3ac0a52b0098f011509d6eb319cf7a9936046c70ae1db5ab1544")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_MATERIALIZER "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_native_worker_manifest.py")
set(AIDA_C03_NATIVE_WORKER_MANIFEST_MATERIALIZER_SHA256 "ce731ce2459c61e8a88b32f9dacec1313d6e9ea8f60690ed37452ec606b0f58c")
set(AIDA_C03_MANAGED_WORKER_ROOT "${AIDA_C03_DEPENDENCY_ROOT}/src/standalone/workers/managed_decompiler")
set(AIDA_C03_MANAGED_WORKER_PROJECT "${AIDA_C03_MANAGED_WORKER_ROOT}/ManagedDecompilerWorker.csproj")
set(AIDA_C03_MANAGED_WORKER_PROJECT_SHA256 "6cd5f5aac485fd4df184fefefd991c34b6260b05686f2b0ac68c9cfd01bbd58f")
set(AIDA_C03_MANAGED_WORKER_PACKAGES_LOCK "${AIDA_C03_MANAGED_WORKER_ROOT}/packages.lock.json")
set(AIDA_C03_MANAGED_WORKER_PACKAGES_LOCK_SHA256 "1d9aa159e4abd4135519f5f4f3b62d71883aedd57426a66def82cde9f6d42a2b")
set(AIDA_C03_MANAGED_WORKER_NUGET_CONFIG "${AIDA_C03_MANAGED_WORKER_ROOT}/NuGet.Config")
set(AIDA_C03_MANAGED_WORKER_NUGET_CONFIG_SHA256 "7ed721d172b6e0b6993d1000ae81c09fce12741614fa8b001cd2b99b79c0053c")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_SCHEMA "${AIDA_C03_MANAGED_WORKER_ROOT}/worker_manifest.schema.json")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_SCHEMA_SHA256 "fbc0fbac75c5af1219963aee9f624b600175dd1fb621353eeb3be3df9ccd994f")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT "${AIDA_C03_MANAGED_WORKER_ROOT}/worker_manifest.json")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT_SHA256 "3a1d2d5643b0204871f636d93a5c869dfe71667f03dc75f32f6fd83f646a193d")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_MATERIALIZER "${AIDA_C03_MANAGED_WORKER_ROOT}/materialize_manifest.py")
set(AIDA_C03_MANAGED_WORKER_MANIFEST_MATERIALIZER_SHA256 "81f9c0c82da5d945f2f5cbca834211c85fc11985901ec3f2152a326aa78b9991")
set(AIDA_C03_WORKER_RUNTIME_ROOT "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_worker_runtime")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC "${AIDA_C03_WORKER_RUNTIME_ROOT}/managed_runtime_source_spec.json")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC_SHA256 "2ee04cc5ed3c0fdbe1dac2f59ff2ac0e0fd5b4595c042aadb9abfbbd8153c4de")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/managed_runtime_source_spec.schema.json")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_SCHEMA_SHA256 "d66d6182c59356274183c669328bf370d3fc52d5ae396084990722503ef17aa0")
set(AIDA_C03_MANAGED_RUNTIME_MANIFEST_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/managed_runtime_manifest.schema.json")
set(AIDA_C03_MANAGED_RUNTIME_MANIFEST_SCHEMA_SHA256 "6edabaa290de6f5717a2dd01bad787c49577f4103cb029f4ef88a49804759ac6")
set(AIDA_C03_MANAGED_RUNTIME_MATERIALIZER "${AIDA_C03_WORKER_RUNTIME_ROOT}/materialize_managed_runtime.py")
set(AIDA_C03_MANAGED_RUNTIME_MATERIALIZER_SHA256 "b7294b49d3a3f1d43936b57a91b540c37ec98ffc778dcca980c469c5cd5ee25d")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT "${AIDA_C03_DEPENDENCY_ROOT}/.deps/dotnet-sdk-10.0.301-win-x64")
set(AIDA_C03_MANAGED_RUNTIME_VERSION "10.0.9")
set(AIDA_C03_MANAGED_RUNTIME_TFM "net10.0")
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_FILE_COUNT 193)
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_SIZE 80344570)
set(AIDA_C03_MANAGED_RUNTIME_SOURCE_INVENTORY_SHA256 "20687edbe0abc5020387ed0f6bdaef85d4ed91529bc356a99510150032af2fe5")
set(AIDA_C03_MANAGED_RUNTIME_PACKAGE_INVENTORY_SHA256 "8582bda52b66ad61651a2c9bc2c705cf10b038e374f87662045397c7966b02c9")
set(AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC "${AIDA_C03_WORKER_RUNTIME_ROOT}/ghidra_spec_source_spec.json")
set(AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC_SHA256 "880c588da681d62451d3dd5f901abc7cb86491a128a7793c8738f9bd7917f0b7")
set(AIDA_C03_GHIDRA_SPEC_SOURCE_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/ghidra_spec_source_spec.schema.json")
set(AIDA_C03_GHIDRA_SPEC_SOURCE_SCHEMA_SHA256 "10e75b9598526600a04d76df410ff1f3ec5fe914ff0395a2ecf4a740b9520ead")
set(AIDA_C03_GHIDRA_SPEC_MANIFEST_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/ghidra_spec_manifest.schema.json")
set(AIDA_C03_GHIDRA_SPEC_MANIFEST_SCHEMA_SHA256 "227602cbd5cde9b54519bea71ab5c16c2648a0f5c2eb3464353f06a3fc8f2132")
set(AIDA_C03_GHIDRA_SPEC_MATERIALIZER "${AIDA_C03_WORKER_RUNTIME_ROOT}/materialize_ghidra_specs.py")
set(AIDA_C03_GHIDRA_SPEC_MATERIALIZER_SHA256 "eac39783c10269ce48f97d1f0174b2ed1590bc65b28f350ea188207ee52ddebe")
set(AIDA_C03_GHIDRA_SPEC_FILE_COUNT 51)
set(AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER "${AIDA_C03_WORKER_RUNTIME_ROOT}/apply_worker_runtime_acl.ps1")
set(AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER_SHA256 "241edea4b518ad455f6cacf6862c1bc67884803b948ad5e239932dfbf101f48f")
set(AIDA_C03_WORKER_RUNTIME_ACL_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/worker_runtime_acl_receipt.schema.json")
set(AIDA_C03_WORKER_RUNTIME_ACL_SCHEMA_SHA256 "e766379539f18fa3ce2ce43e9e4c7353fe9af768dd6d0efe65a059151d602131")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SPEC "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_distribution_manifest_spec.json")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SHA256 "864227d0c0249d1b64434840ef6a8563b3772c8c950fb22a041f1b94031cde77")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SCHEMA "${AIDA_C03_WORKER_RUNTIME_ROOT}/distribution_manifest_spec.schema.json")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SCHEMA_SHA256 "9f2649e41ef59d4a74c4c06dfa840aa846e6cf6ca461f05f05c23576b951cf7a")
set(AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT "${AIDA_C03_WORKER_RUNTIME_ROOT}/fail_distribution.cmake")
set(AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT_SHA256 "41bdc9628b17ea27f38d37d3196a2611a5a20dc9d6ef602b781c625abd797fda")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_ROOT "${AIDA_C03_DEPENDENCY_ROOT}/src/standalone/workers/analysis_python")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ROOT}/analysis_python_worker.py")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_SHA256 "493d52e9401adaa060a4f5d1435ea38dfd3ee9f0519325ea04ce651a73c83024")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_STAGER "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ROOT}/build_frozen_worker.ps1")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_STAGER_SHA256 "39d608ea74f5a9352828fd8d4a6078f558006019991b9b77d19838d152f16232")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT "${AIDA_C03_DEPENDENCY_ROOT}/.deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.exe")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SCHEMA "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_distribution_manifest.schema.json")
set(AIDA_C03_DISTRIBUTION_MANIFEST_SCHEMA_SHA256 "0140f8582f8a2292a0364bfe60e3a2c6ef05f876a617e19fd026f3e9f4f7b2ab")
set(AIDA_C03_DISTRIBUTION_MANIFEST_MATERIALIZER "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_distribution_manifest.ps1")
set(AIDA_C03_DISTRIBUTION_MANIFEST_MATERIALIZER_SHA256 "0ce5b8176f47ff3764cf230dd8a11d73c467e7d234898122aa7d6ff1d67fdde4")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_BUILD_LOCK "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_camoufox_reverse_mcp_build.lock.json")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_BUILD_LOCK_SHA256 "ae513d4afe67806293a7fde3c9fee1b1ecaa9eda4865e9fb08193bd2150f30b5")
set(AIDA_C03_DOTNET_EXECUTABLE "${AIDA_C03_DEPENDENCY_ROOT}/.deps/dotnet-sdk-10.0.301-win-x64/dotnet.exe")
set(AIDA_C03_DOTNET_EXECUTABLE_SHA256 "a5ccdc3a41d5e5c6014ff64509aed176db39f4f14caffff3dd1997f8907e94d7")
set(AIDA_C03_OFFLINE_NUGET_ROOT "${AIDA_C03_DEPENDENCY_ROOT}/.deps/nuget-offline")
set(AIDA_C03_CAMOUFOX_EXECUTABLE "${AIDA_C03_DEPENDENCY_ROOT}/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe")
set(AIDA_C03_CAMOUFOX_EXECUTABLE_SHA256 "768937fa6a6df581d0cdc88ecffe1cf651ffebe1ad1d5667a5f75100e96acfe0")
set(AIDA_C03_CAMOUFOX_EXECUTABLE_SOURCE_RELATIVE_PATH "camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe")
set(AIDA_C03_CAMOUFOX_EXECUTABLE_PACKAGE_RELATIVE_PATH "deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_EXECUTABLE "${AIDA_C03_DEPENDENCY_ROOT}/.deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_EXECUTABLE_SHA256 "2443649a43c92b048b7f013434d169889b41f494f391359d9cc72111c6e0ee4c")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_SOURCE_RELATIVE_PATH ".deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe")
set(AIDA_C03_CAMOUFOX_REVERSE_MCP_PACKAGE_RELATIVE_PATH "deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe")
set(AIDA_C03_LOCKED_PRODUCTION_LINK_DENYLIST lmdb unicorn remill)
set(AIDA_C03_PRODUCTION_LINK_DENY_TOKENS lief lmdb unicorn remill)
set(AIDA_C03_ZYDIS_COMPONENT_ALLOWLIST Zydis Zycore)
set(AIDA_C03_ZYCORE_COMPONENT_ALLOWLIST Zycore)
set(AIDA_C03_CAPSTONE_COMPONENT_ALLOWLIST ARM ARM64 MIPS PPC RISCV X86 detail)
set(AIDA_C03_TASKFLOW_COMPONENT_ALLOWLIST taskflow)
set(AIDA_C03_GHIDRA_WORKER_COMPONENT_ALLOWLIST decompiler sleigh processor_specs compiler_specs)
set(AIDA_C03_TRITON_THOROUGH_ONLY_COMPONENT_ALLOWLIST triton z3_interface)
set(AIDA_C03_Z3_THOROUGH_ONLY_COMPONENT_ALLOWLIST libz3)
set(AIDA_C03_SQLITE_COMPONENT_ALLOWLIST sqlite3)
set(AIDA_C03_IMGUI_COMPONENT_ALLOWLIST imgui imgui_freetype imgui_impl_dx11 imgui_impl_win32)
set(AIDA_C03_ZLIB_COMPONENT_ALLOWLIST zlib)
set(AIDA_C03_ZSTD_COMPONENT_ALLOWLIST zstd_static)
set(AIDA_C03_LIBLZMA_MINIMAL_COMPONENT_ALLOWLIST liblzma)
set(AIDA_C03_MINIZIP_NG_READ_ONLY_COMPONENT_ALLOWLIST mz_zip_reader)
set(AIDA_C03_PCRE2_8BIT_NO_JIT_COMPONENT_ALLOWLIST pcre2_8)
set(AIDA_C03_NLOHMANN_JSON_COMPONENT_ALLOWLIST nlohmann_json)
set(AIDA_C03_JSON_SCHEMA_VALIDATOR_COMPONENT_ALLOWLIST nlohmann_json_schema_validator)
set(AIDA_C03_LLVM_COMPONENT_ALLOWLIST Demangle Support)
set(AIDA_C03_LLVM_DEMANGLE_SUPPORT_COMPONENT_ALLOWLIST Demangle Support)
set(AIDA_C03_MANAGED_WORKER_PACKAGES_COMPONENT_ALLOWLIST ICSharpCode.Decompiler System.Collections.Immutable System.Reflection.Metadata)
set(AIDA_C03_DEPENDENCY_DECISION_PRODUCTION zydis zycore capstone taskflow ghidra_worker triton_thorough_only z3_thorough_only sqlite imgui zlib zstd liblzma_minimal minizip_ng_read_only pcre2_8bit_no_jit nlohmann_json json_schema_validator llvm_demangle_support dotnet_runtime managed_worker_packages analysis_python_worker)
set(AIDA_C03_DEPENDENCY_DECISION_BUILD_ONLY dotnet_sdk pyinstaller)
set(AIDA_C03_DEPENDENCY_DECISION_EVIDENCE_ONLY lief remill)
set(AIDA_C03_DEPENDENCY_DECISION_NON_USE lmdb unicorn)
set(AIDA_C03_NO_NETWORK_FETCH ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_FULLY_DISCONNECTED ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)
set(AIDA_C03_DEPENDENCY_INITIALIZATION_ORDER "include;aida_c03_verify_dependency_inventory;aida_c03_register_pcre2_8bit_no_jit;register-targets;aida_c03_reject_forbidden_target_links")

function(aida_c03_require_sha256_value value descriptor)
    string(LENGTH "${value}" _aida_c03_sha256_length)
    if(NOT _aida_c03_sha256_length EQUAL 64 OR NOT value MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "AiDA C03 SHA-256 value is invalid: ${descriptor}")
    endif()
endfunction()

function(aida_c03_require_path_sha256 path expected_sha256 descriptor)
    aida_c03_require_sha256_value("${expected_sha256}" "${descriptor}")
    if(NOT EXISTS "${path}" OR IS_DIRECTORY "${path}")
        message(FATAL_ERROR "AiDA C03 dependency is missing or is not a file: ${descriptor}")
    endif()
    file(SHA256 "${path}" _aida_c03_actual_sha256)
    string(TOLOWER "${_aida_c03_actual_sha256}" _aida_c03_actual_sha256)
    if(NOT _aida_c03_actual_sha256 STREQUAL expected_sha256)
        message(FATAL_ERROR "AiDA C03 dependency hash mismatch: ${descriptor}")
    endif()
endfunction()

function(aida_c03_require_path_identity path expected_size expected_sha256 descriptor)
    if(NOT expected_size MATCHES "^[0-9]+$")
        message(FATAL_ERROR "AiDA C03 expected size is invalid: ${descriptor}")
    endif()
    aida_c03_require_path_sha256("${path}" "${expected_sha256}" "${descriptor}")
    file(SIZE "${path}" _aida_c03_actual_size)
    if(NOT _aida_c03_actual_size EQUAL expected_size)
        message(FATAL_ERROR "AiDA C03 dependency size mismatch: ${descriptor}")
    endif()
endfunction()

function(aida_c03_require_file_sha256 relative_path expected_sha256)
    aida_c03_require_path_sha256("${AIDA_C03_DEPENDENCY_ROOT}/${relative_path}" "${expected_sha256}" "${relative_path}")
endfunction()

function(aida_c03_require_file_identity relative_path expected_size expected_sha256)
    aida_c03_require_path_identity("${AIDA_C03_DEPENDENCY_ROOT}/${relative_path}" "${expected_size}" "${expected_sha256}" "${relative_path}")
endfunction()

function(aida_c03_require_json_contract path expected_sha256 descriptor output_variable)
    aida_c03_require_path_sha256("${path}" "${expected_sha256}" "${descriptor}")
    file(READ "${path}" _aida_c03_json)
    string(JSON _aida_c03_json_type ERROR_VARIABLE _aida_c03_json_error TYPE "${_aida_c03_json}")
    if(NOT _aida_c03_json_error STREQUAL "NOTFOUND" OR NOT _aida_c03_json_type STREQUAL "OBJECT")
        message(FATAL_ERROR "AiDA C03 JSON contract is malformed: ${descriptor}")
    endif()
    string(TOLOWER "${_aida_c03_json}" _aida_c03_json_lower)
    if(_aida_c03_json_lower MATCHES "(https?|ftp|git|ssh|file|ws|wss)://")
        message(FATAL_ERROR "AiDA C03 JSON contract contains a remote reference: ${descriptor}")
    endif()
    string(REGEX MATCHALL "\"\\$ref\"[ \t\r\n]*:[ \t\r\n]*\"[^\"]+\"" _aida_c03_refs "${_aida_c03_json}")
    foreach(_aida_c03_ref IN LISTS _aida_c03_refs)
        string(REGEX REPLACE "^.*:[ \t\r\n]*\"([^\"]+)\"$" "\\1" _aida_c03_ref_value "${_aida_c03_ref}")
        if(NOT _aida_c03_ref_value MATCHES "^#/")
            message(FATAL_ERROR "AiDA C03 JSON contract contains a non-local schema reference: ${descriptor}")
        endif()
    endforeach()
    set(${output_variable} "${_aida_c03_json}" PARENT_SCOPE)
endfunction()

function(aida_c03_require_json_array_exact json expected_variable descriptor)
    set(_aida_c03_path ${ARGN})
    string(JSON _aida_c03_actual_length LENGTH "${json}" ${_aida_c03_path})
    list(LENGTH ${expected_variable} _aida_c03_expected_length)
    if(NOT _aida_c03_actual_length EQUAL _aida_c03_expected_length)
        message(FATAL_ERROR "AiDA C03 JSON array cardinality is invalid: ${descriptor}")
    endif()
    if(_aida_c03_actual_length EQUAL 0)
        return()
    endif()
    math(EXPR _aida_c03_actual_last "${_aida_c03_actual_length} - 1")
    foreach(_aida_c03_index RANGE 0 ${_aida_c03_actual_last})
        string(JSON _aida_c03_actual GET "${json}" ${_aida_c03_path} ${_aida_c03_index})
        list(GET ${expected_variable} ${_aida_c03_index} _aida_c03_expected)
        if(NOT _aida_c03_actual STREQUAL _aida_c03_expected)
            message(FATAL_ERROR "AiDA C03 JSON array value is invalid: ${descriptor}")
        endif()
    endforeach()
endfunction()

function(aida_c03_require_locked_source_tree)
    set(_aida_c03_inputs
        "src/standalone/workers/native_decompiler/fake_native_decompiler_worker.cpp|15972|4323a48219411fb872594dc96e6b884039c8e8cf20c2954424a765818d6c2dc4"
        "src/standalone/workers/native_decompiler/ghidra_native_provider.cpp|13893|3b1cc79f48466147e8264ed64e1ecdf00e831cae715177fc311c4c034f4d3df7"
        "src/standalone/workers/native_decompiler/ghidra_native_provider.hpp|487|524fb2f51e2e208610fa28768b6fa6b7a4b2ebd8824070ac518dff1d06b6ce55"
        "src/standalone/workers/native_decompiler/native_decompiler_worker.cpp|2825|0a39212f62ce22df7caa28e62dbaadb2adaaf6b6394690ea4e2129ab3242de1f"
        "src/standalone/workers/native_decompiler/native_worker_protocol.hpp|18353|2ebc3f2326285c4db0c4fd0d93b3314902fcc9336aba78837e544e24dc343f43"
        "src/standalone/workers/native_decompiler/native_worker_runtime.hpp|17312|110cd165d8ad644c2ce164f66a0142dee6acf3e9de9cf862412b1594c88076cf"
        "src/standalone/tests/c03/decompiler_provider_matrix/provider_matrix.cpp|126322|63a40daf0d19e61daf7398b477cf730952f3be951eb8f98186cea1ce5c2a024d"
        "src/standalone/tests/c03/decompiler_provider_matrix/provider_matrix.hpp|749|d215b44be571a9577ab4fca2860ff34aa1cd864163407c76f4de0872fcbbaf79"
        "src/standalone/tests/c03/decompiler_quality_schema.cpp|115001|8dcc6359d1f7dd9bad36be742614c6b6b508c0055338be22af4700737c8e7e27"
        "src/standalone/tests/c03/decompiler_quality_schema.hpp|1266|97bc268ab39854317d24321bddce743c3c5b16340a9b9257b4422342db7b874c"
        "src/standalone/tests/c03/fixtures/decompiler_provider_results.schema.json|10352|2639cf30efba36143c8b7778264b714e7d3f50c09b3f68ae00d5786433c8427d"
        "src/standalone/tests/c03/decompiler_quality_scorer.cpp|59613|b974931254c1263157061137f20243f84ed1a3f7ade1c09f038e0c12d56861a8"
        "src/standalone/tests/c03/decompiler_quality_scorer.hpp|1480|9db0b310ca88f0a43c886819f3b4542834f621dcee6af7e498a8f50252fea28c"
        "src/standalone/tests/c03/decompiler_quality_scorer_harness.cpp|24838|3e97c751aa6db0e434263d2f74f37e8237206b42ddcc19a4f3f904d14da2147b"
        "src/standalone/tests/c03/decompiler_quality_scorer_harness.hpp|644|f116aa31bbe209d973c4d045f46f68f1a127ec424ec81279bc3d527153dbdf65"
        "cmake/c03_safe_headless/decompiler_quality_pipeline_main.cpp|5501|2cd9b2aa17aa25cabb0c2f9bb4d1705957174826613aa69e9d05f3072bb41b66"
        "src/standalone/workers/managed_decompiler/AssemblyInfo.cs|98|69ebe8ec7e9a518093d43e9e6909724562fa55ae8083a71701e55411f1a4ef76"
        "src/standalone/workers/managed_decompiler/AuthenticatedTransport.cs|15277|f7fffeab2540b2458326efcb68096313701f2b95087e2978c1bf80a3971b8437"
        "src/standalone/workers/managed_decompiler/ManagedDecompilerWorker.csproj|1281|6cd5f5aac485fd4df184fefefd991c34b6260b05686f2b0ac68c9cfd01bbd58f"
        "src/standalone/workers/managed_decompiler/materialize_manifest.py|23779|81f9c0c82da5d945f2f5cbca834211c85fc11985901ec3f2152a326aa78b9991"
        "src/standalone/workers/managed_decompiler/MetadataAnalysis.cs|44876|e080c2505290a867c6c9416581e4fe4bb53e4449ed690617bafcdb41e6ae9817"
        "src/standalone/workers/managed_decompiler/NuGet.Config|297|7ed721d172b6e0b6993d1000ae81c09fce12741614fa8b001cd2b99b79c0053c"
        "src/standalone/workers/managed_decompiler/packages.lock.json|1043|1d9aa159e4abd4135519f5f4f3b62d71883aedd57426a66def82cde9f6d42a2b"
        "src/standalone/workers/managed_decompiler/Program.cs|9701|cd1eadecd5a5436e57ffefa2dd1592b7cfbdc2d66b002dfbb74042b28d37446c"
        "src/standalone/workers/managed_decompiler/Protocol.cs|6319|e2907928f3c218c21c774a3753f98072a7dc8176a13044fc7a0568f643d711d6"
        "src/standalone/workers/managed_decompiler/ResourceBudgetGuard.cs|5609|b9b715c3a524f0c830ef94599ba7de7597bf2aa6bad8928581ec6de5f4ba35bd"
        "src/standalone/workers/managed_decompiler/RuntimeIdentity.cs|14815|386f2129ab3321b7f2d5f32fbb63b765c98914cc91fd2cd496cf293e51b865fe"
        "src/standalone/workers/managed_decompiler/worker_manifest.json|2429|3a1d2d5643b0204871f636d93a5c869dfe71667f03dc75f32f6fd83f646a193d"
        "src/standalone/workers/managed_decompiler/worker_manifest.schema.json|5361|fbc0fbac75c5af1219963aee9f624b600175dd1fb621353eeb3be3df9ccd994f"
        "src/standalone/workers/analysis_python/analysis_python_worker.py|9572|493d52e9401adaa060a4f5d1435ea38dfd3ee9f0519325ea04ce651a73c83024"
        "src/standalone/workers/analysis_python/build_frozen_worker.ps1|25982|39d608ea74f5a9352828fd8d4a6078f558006019991b9b77d19838d152f16232"
        "src/standalone/workers/analysis_python/fake_analysis_python_worker.cpp|9858|309fa6f7f38949ba60e0c5e9ae7953eb544cac4f95b664802761e4289a48079f"
        "src/standalone/workers/analysis_python/python_worker_protocol.hpp|17993|97216bc6b188075324cda563a50bd64bc020208eb305f4a638889249763f5c0c")
    foreach(_aida_c03_input IN LISTS _aida_c03_inputs)
        string(REPLACE "|" ";" _aida_c03_fields "${_aida_c03_input}")
        list(GET _aida_c03_fields 0 _aida_c03_path)
        list(GET _aida_c03_fields 1 _aida_c03_size)
        list(GET _aida_c03_fields 2 _aida_c03_sha256)
        aida_c03_require_file_identity("${_aida_c03_path}" "${_aida_c03_size}" "${_aida_c03_sha256}")
    endforeach()
endfunction()

function(aida_c03_verify_camoufox_build_lock)
    aida_c03_require_json_contract("${AIDA_C03_CAMOUFOX_REVERSE_MCP_BUILD_LOCK}" "${AIDA_C03_CAMOUFOX_REVERSE_MCP_BUILD_LOCK_SHA256}" "Camoufox reverse-MCP offline build lock" _aida_c03_lock)
    string(JSON _aida_c03_schema GET "${_aida_c03_lock}" schema)
    string(JSON _aida_c03_version GET "${_aida_c03_lock}" schema_version)
    string(JSON _aida_c03_no_fetch GET "${_aida_c03_lock}" network_fetch_forbidden)
    string(JSON _aida_c03_onefile GET "${_aida_c03_lock}" output onefile_required)
    string(JSON _aida_c03_no_source GET "${_aida_c03_lock}" output source_files_forbidden)
    string(JSON _aida_c03_no_stock GET "${_aida_c03_lock}" output stock_browser_fallback_forbidden)
    string(JSON _aida_c03_verify_records GET "${_aida_c03_lock}" runtime_graph verify_every_record_entry)
    string(JSON _aida_c03_reject_unexpected GET "${_aida_c03_lock}" runtime_graph unexpected_distributions_forbidden)
    if(NOT _aida_c03_schema STREQUAL "aida.c03.camoufox-reverse-mcp-offline-build-lock" OR
       NOT _aida_c03_version EQUAL 2 OR NOT _aida_c03_no_fetch OR NOT _aida_c03_onefile OR
       NOT _aida_c03_no_source OR NOT _aida_c03_no_stock OR NOT _aida_c03_verify_records OR
       NOT _aida_c03_reject_unexpected)
        message(FATAL_ERROR "AiDA C03 Camoufox reverse-MCP offline build policy is malformed or weakened")
    endif()
    foreach(_aida_c03_group_path IN ITEMS
            "interpreter|relative_path|interpreter|sha256"
            "freezer|metadata_relative_path|freezer|metadata_sha256"
            "freezer|record_relative_path|freezer|record_sha256"
            "freezer|license_relative_path|freezer|license_sha256"
            "source|project_relative_path|source|project_sha256"
            "source|package_marker_relative_path|source|package_marker_sha256"
            "source|environment_binding_relative_path|source|environment_binding_sha256"
            "patched_camoufox|fingerprints_relative_path|patched_camoufox|fingerprints_sha256")
        string(REPLACE "|" ";" _aida_c03_group_path_fields "${_aida_c03_group_path}")
        list(GET _aida_c03_group_path_fields 0 _aida_c03_path_group)
        list(GET _aida_c03_group_path_fields 1 _aida_c03_path_key)
        list(GET _aida_c03_group_path_fields 2 _aida_c03_hash_group)
        list(GET _aida_c03_group_path_fields 3 _aida_c03_hash_key)
        string(JSON _aida_c03_relative GET "${_aida_c03_lock}" "${_aida_c03_path_group}" "${_aida_c03_path_key}")
        string(JSON _aida_c03_sha256 GET "${_aida_c03_lock}" "${_aida_c03_hash_group}" "${_aida_c03_hash_key}")
        aida_c03_require_file_sha256("${_aida_c03_relative}" "${_aida_c03_sha256}")
    endforeach()
    string(JSON _aida_c03_interpreter_path GET "${_aida_c03_lock}" interpreter relative_path)
    string(JSON _aida_c03_interpreter_size GET "${_aida_c03_lock}" interpreter size_bytes)
    string(JSON _aida_c03_interpreter_hash GET "${_aida_c03_lock}" interpreter sha256)
    aida_c03_require_file_identity("${_aida_c03_interpreter_path}" "${_aida_c03_interpreter_size}" "${_aida_c03_interpreter_hash}")
endfunction()

function(aida_c03_verify_dependency_inventory)
    aida_c03_require_json_contract("${AIDA_C03_WORKER_MANIFEST_SCHEMA}" "${AIDA_C03_WORKER_MANIFEST_SCHEMA_SHA256}" "C03 worker authority schema" _aida_c03_authority_schema)
    aida_c03_require_json_contract("${AIDA_C03_WORKER_MANIFEST_LOCK}" "${AIDA_C03_WORKER_MANIFEST_LOCK_SHA256}" "C03 worker authority lock" _aida_c03_authority)
    aida_c03_require_json_contract("${AIDA_C03_NATIVE_WORKER_MANIFEST_SCHEMA}" "${AIDA_C03_NATIVE_WORKER_MANIFEST_SCHEMA_SHA256}" "C03 native worker manifest schema" _aida_c03_native_schema)
    aida_c03_require_json_contract("${AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT}" "${AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT_SHA256}" "C03 native worker manifest source" _aida_c03_native)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_WORKER_MANIFEST_SCHEMA}" "${AIDA_C03_MANAGED_WORKER_MANIFEST_SCHEMA_SHA256}" "C03 managed worker manifest schema" _aida_c03_managed_schema)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT}" "${AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT_SHA256}" "C03 managed worker manifest source" _aida_c03_managed)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_WORKER_PACKAGES_LOCK}" "${AIDA_C03_MANAGED_WORKER_PACKAGES_LOCK_SHA256}" "C03 managed worker package lock" _aida_c03_managed_packages)
    aida_c03_require_json_contract("${AIDA_C03_DISTRIBUTION_MANIFEST_SCHEMA}" "${AIDA_C03_DISTRIBUTION_MANIFEST_SCHEMA_SHA256}" "C03 distribution manifest schema" _aida_c03_distribution_schema)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC}" "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC_SHA256}" "C03 managed runtime source contract" _aida_c03_managed_runtime_source)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_RUNTIME_SOURCE_SCHEMA}" "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SCHEMA_SHA256}" "C03 managed runtime source schema" _aida_c03_managed_runtime_source_schema)
    aida_c03_require_json_contract("${AIDA_C03_MANAGED_RUNTIME_MANIFEST_SCHEMA}" "${AIDA_C03_MANAGED_RUNTIME_MANIFEST_SCHEMA_SHA256}" "C03 managed runtime manifest schema" _aida_c03_managed_runtime_manifest_schema)
    aida_c03_require_path_sha256("${AIDA_C03_MANAGED_RUNTIME_MATERIALIZER}" "${AIDA_C03_MANAGED_RUNTIME_MATERIALIZER_SHA256}" "C03 managed runtime materializer")
    aida_c03_require_json_contract("${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC}" "${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC_SHA256}" "C03 Ghidra specification source contract" _aida_c03_ghidra_spec_source)
    aida_c03_require_json_contract("${AIDA_C03_GHIDRA_SPEC_SOURCE_SCHEMA}" "${AIDA_C03_GHIDRA_SPEC_SOURCE_SCHEMA_SHA256}" "C03 Ghidra specification source schema" _aida_c03_ghidra_spec_source_schema)
    aida_c03_require_json_contract("${AIDA_C03_GHIDRA_SPEC_MANIFEST_SCHEMA}" "${AIDA_C03_GHIDRA_SPEC_MANIFEST_SCHEMA_SHA256}" "C03 Ghidra specification manifest schema" _aida_c03_ghidra_spec_manifest_schema)
    aida_c03_require_path_sha256("${AIDA_C03_GHIDRA_SPEC_MATERIALIZER}" "${AIDA_C03_GHIDRA_SPEC_MATERIALIZER_SHA256}" "C03 Ghidra specification materializer")
    aida_c03_require_path_sha256("${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}" "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER_SHA256}" "C03 worker runtime ACL materializer")
    aida_c03_require_json_contract("${AIDA_C03_WORKER_RUNTIME_ACL_SCHEMA}" "${AIDA_C03_WORKER_RUNTIME_ACL_SCHEMA_SHA256}" "C03 worker runtime ACL schema" _aida_c03_worker_acl_schema)
    aida_c03_require_json_contract("${AIDA_C03_DISTRIBUTION_MANIFEST_SPEC}" "${AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SHA256}" "C03 distribution source specification" _aida_c03_distribution_spec)
    aida_c03_require_json_contract("${AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SCHEMA}" "${AIDA_C03_DISTRIBUTION_MANIFEST_SPEC_SCHEMA_SHA256}" "C03 distribution source specification schema" _aida_c03_distribution_spec_schema)
    aida_c03_require_path_sha256("${AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT}" "${AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT_SHA256}" "C03 distribution fail-closed gate")
    string(JSON _aida_c03_runtime_tfm GET "${_aida_c03_managed_runtime_source}" application target_framework)
    string(JSON _aida_c03_runtime_version GET "${_aida_c03_managed_runtime_source}" source runtime_version)
    string(JSON _aida_c03_runtime_count GET "${_aida_c03_managed_runtime_source}" selection file_count)
    string(JSON _aida_c03_runtime_size GET "${_aida_c03_managed_runtime_source}" selection total_size_bytes)
    string(JSON _aida_c03_runtime_inventory GET "${_aida_c03_managed_runtime_source}" selection canonical_inventory_sha256)
    string(JSON _aida_c03_ghidra_spec_count LENGTH "${_aida_c03_ghidra_spec_source}" specifications)
    if(NOT _aida_c03_runtime_tfm STREQUAL AIDA_C03_MANAGED_RUNTIME_TFM OR
       NOT _aida_c03_runtime_version STREQUAL AIDA_C03_MANAGED_RUNTIME_VERSION OR
       NOT _aida_c03_runtime_count EQUAL AIDA_C03_MANAGED_RUNTIME_SOURCE_FILE_COUNT OR
       NOT _aida_c03_runtime_size EQUAL AIDA_C03_MANAGED_RUNTIME_SOURCE_SIZE OR
       NOT _aida_c03_runtime_inventory STREQUAL AIDA_C03_MANAGED_RUNTIME_SOURCE_INVENTORY_SHA256 OR
       NOT _aida_c03_ghidra_spec_count EQUAL AIDA_C03_GHIDRA_SPEC_FILE_COUNT)
        message(FATAL_ERROR "AiDA C03 managed runtime or Ghidra specification authority is invalid")
    endif()
    string(JSON _aida_c03_distribution_spec_version GET "${_aida_c03_distribution_spec}" schema_version)
    string(JSON _aida_c03_distribution_worker_count LENGTH "${_aida_c03_distribution_spec}" workers)
    string(JSON _aida_c03_distribution_source_count LENGTH "${_aida_c03_distribution_spec}" inventory_sources)
    if(NOT _aida_c03_distribution_spec_version EQUAL 2 OR
       NOT _aida_c03_distribution_worker_count EQUAL 3 OR
       _aida_c03_distribution_source_count LESS 5)
        message(FATAL_ERROR "AiDA C03 distribution source specification is incomplete or downgraded")
    endif()
    string(JSON _aida_c03_schema GET "${_aida_c03_authority}" schema)
    string(JSON _aida_c03_schema_version GET "${_aida_c03_authority}" schema_version)
    string(JSON _aida_c03_no_fetch GET "${_aida_c03_authority}" no_network_fetch)
    if(NOT _aida_c03_schema STREQUAL "aida.c03.worker-manifest-lock" OR
       NOT _aida_c03_schema_version EQUAL 2 OR NOT _aida_c03_no_fetch)
        message(FATAL_ERROR "AiDA C03 worker authority is malformed or downgraded")
    endif()
    string(JSON _aida_c03_inventory_length LENGTH "${_aida_c03_authority}" source_inventory)
    if(NOT _aida_c03_inventory_length EQUAL 58)
        message(FATAL_ERROR "AiDA C03 worker authority inventory cardinality is invalid")
    endif()
    math(EXPR _aida_c03_inventory_last "${_aida_c03_inventory_length} - 1")
    set(_aida_c03_seen_paths)
    set(_aida_c03_required_production_inputs)
    set(_aida_c03_required_build_inputs)
    set(_aida_c03_required_evidence_inputs)
    foreach(_aida_c03_index RANGE 0 ${_aida_c03_inventory_last})
        string(JSON _aida_c03_relative GET "${_aida_c03_authority}" source_inventory ${_aida_c03_index} path)
        string(JSON _aida_c03_size GET "${_aida_c03_authority}" source_inventory ${_aida_c03_index} size_bytes)
        string(JSON _aida_c03_sha256 GET "${_aida_c03_authority}" source_inventory ${_aida_c03_index} sha256)
        string(JSON _aida_c03_usage GET "${_aida_c03_authority}" source_inventory ${_aida_c03_index} usage)
        if(_aida_c03_relative IN_LIST _aida_c03_seen_paths)
            message(FATAL_ERROR "AiDA C03 worker authority contains a duplicate source path: ${_aida_c03_relative}")
        endif()
        list(APPEND _aida_c03_seen_paths "${_aida_c03_relative}")
        aida_c03_require_file_identity("${_aida_c03_relative}" "${_aida_c03_size}" "${_aida_c03_sha256}")
        if(_aida_c03_usage STREQUAL "production")
            list(APPEND _aida_c03_required_production_inputs "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_relative}")
        elseif(_aida_c03_usage STREQUAL "build_only")
            list(APPEND _aida_c03_required_build_inputs "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_relative}")
        elseif(_aida_c03_usage STREQUAL "evidence_only")
            list(APPEND _aida_c03_required_evidence_inputs "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_relative}")
        else()
            message(FATAL_ERROR "AiDA C03 worker authority source usage is invalid: ${_aida_c03_relative}")
        endif()
    endforeach()
    string(JSON _aida_c03_deny_length LENGTH "${_aida_c03_authority}" production_link_denylist)
    if(NOT _aida_c03_deny_length EQUAL 3)
        message(FATAL_ERROR "AiDA C03 locked production deny-link list cardinality is invalid")
    endif()
    foreach(_aida_c03_index RANGE 0 2)
        string(JSON _aida_c03_deny GET "${_aida_c03_authority}" production_link_denylist ${_aida_c03_index})
        list(GET AIDA_C03_LOCKED_PRODUCTION_LINK_DENYLIST ${_aida_c03_index} _aida_c03_expected_deny)
        if(NOT _aida_c03_deny STREQUAL _aida_c03_expected_deny)
            message(FATAL_ERROR "AiDA C03 locked production deny-link list is invalid")
        endif()
    endforeach()
    foreach(_aida_c03_decision_group IN ITEMS
            "production|AIDA_C03_DEPENDENCY_DECISION_PRODUCTION"
            "build_only|AIDA_C03_DEPENDENCY_DECISION_BUILD_ONLY"
            "evidence_only|AIDA_C03_DEPENDENCY_DECISION_EVIDENCE_ONLY"
            "non_use|AIDA_C03_DEPENDENCY_DECISION_NON_USE")
        string(REPLACE "|" ";" _aida_c03_decision_fields "${_aida_c03_decision_group}")
        list(GET _aida_c03_decision_fields 0 _aida_c03_decision_key)
        list(GET _aida_c03_decision_fields 1 _aida_c03_decision_expected)
        aida_c03_require_json_array_exact("${_aida_c03_authority}" "${_aida_c03_decision_expected}"
            "dependency decision ${_aida_c03_decision_key}" dependency_decisions "${_aida_c03_decision_key}")
    endforeach()
    aida_c03_require_json_array_exact("${_aida_c03_authority}" AIDA_C03_LLVM_COMPONENT_ALLOWLIST
        "LLVM component allowlist" dependency_decisions llvm_component_allowlist)
    aida_c03_require_json_array_exact("${_aida_c03_authority}" AIDA_C03_LOCKED_PRODUCTION_LINK_DENYLIST
        "locked production deny-link list" dependency_decisions production_link_denylist)
    string(JSON _aida_c03_dependency_length LENGTH "${_aida_c03_authority}" dependencies)
    if(NOT _aida_c03_dependency_length EQUAL 30)
        message(FATAL_ERROR "AiDA C03 dependency decision inventory cardinality is invalid")
    endif()
    math(EXPR _aida_c03_dependency_last "${_aida_c03_dependency_length} - 1")
    set(_aida_c03_dependency_ids)
    set(_aida_c03_usage_production 0)
    set(_aida_c03_usage_build_only 0)
    set(_aida_c03_usage_evidence_only 0)
    set(_aida_c03_usage_non_use 0)
    foreach(_aida_c03_index RANGE 0 ${_aida_c03_dependency_last})
        string(JSON _aida_c03_dependency_id GET "${_aida_c03_authority}" dependencies ${_aida_c03_index} id)
        string(JSON _aida_c03_dependency_usage GET "${_aida_c03_authority}" dependencies ${_aida_c03_index} usage)
        string(JSON _aida_c03_dependency_license GET "${_aida_c03_authority}" dependencies ${_aida_c03_index} license)
        string(JSON _aida_c03_dependency_ships GET "${_aida_c03_authority}" dependencies ${_aida_c03_index} ships_to_customer)
        string(JSON _aida_c03_dependency_component_count LENGTH "${_aida_c03_authority}" dependencies ${_aida_c03_index} components)
        string(JSON _aida_c03_dependency_source_count LENGTH "${_aida_c03_authority}" dependencies ${_aida_c03_index} source_paths)
        string(LENGTH "${_aida_c03_dependency_id}" _aida_c03_dependency_id_length)
        if(NOT _aida_c03_dependency_id MATCHES "^[a-z0-9][a-z0-9-]*$" OR
           _aida_c03_dependency_id_length GREATER 128 OR
           _aida_c03_dependency_id IN_LIST _aida_c03_dependency_ids OR NOT _aida_c03_dependency_license)
            message(FATAL_ERROR "AiDA C03 dependency decision identity is invalid")
        endif()
        list(APPEND _aida_c03_dependency_ids "${_aida_c03_dependency_id}")
        if(_aida_c03_dependency_usage STREQUAL "production")
            math(EXPR _aida_c03_usage_production "${_aida_c03_usage_production} + 1")
            if(NOT _aida_c03_dependency_ships OR _aida_c03_dependency_component_count LESS 1 OR
               _aida_c03_dependency_source_count LESS 1)
                message(FATAL_ERROR "AiDA C03 production dependency is incomplete: ${_aida_c03_dependency_id}")
            endif()
        elseif(_aida_c03_dependency_usage STREQUAL "build_only")
            math(EXPR _aida_c03_usage_build_only "${_aida_c03_usage_build_only} + 1")
            if(_aida_c03_dependency_ships OR _aida_c03_dependency_component_count LESS 1 OR
               _aida_c03_dependency_source_count LESS 1)
                message(FATAL_ERROR "AiDA C03 build-only dependency is incomplete: ${_aida_c03_dependency_id}")
            endif()
        elseif(_aida_c03_dependency_usage STREQUAL "evidence_only")
            math(EXPR _aida_c03_usage_evidence_only "${_aida_c03_usage_evidence_only} + 1")
            if(_aida_c03_dependency_ships OR _aida_c03_dependency_component_count LESS 1 OR
               _aida_c03_dependency_source_count LESS 1)
                message(FATAL_ERROR "AiDA C03 evidence-only dependency is incomplete: ${_aida_c03_dependency_id}")
            endif()
        elseif(_aida_c03_dependency_usage STREQUAL "non_use")
            math(EXPR _aida_c03_usage_non_use "${_aida_c03_usage_non_use} + 1")
            if(_aida_c03_dependency_ships OR NOT _aida_c03_dependency_component_count EQUAL 0 OR
               NOT _aida_c03_dependency_source_count EQUAL 0)
                message(FATAL_ERROR "AiDA C03 non-use dependency is not empty: ${_aida_c03_dependency_id}")
            endif()
        else()
            message(FATAL_ERROR "AiDA C03 dependency usage is invalid: ${_aida_c03_dependency_id}")
        endif()
        if(_aida_c03_dependency_source_count GREATER 0)
            math(EXPR _aida_c03_source_last "${_aida_c03_dependency_source_count} - 1")
            foreach(_aida_c03_source_index RANGE 0 ${_aida_c03_source_last})
                string(JSON _aida_c03_dependency_source GET "${_aida_c03_authority}" dependencies ${_aida_c03_index} source_paths ${_aida_c03_source_index})
                if(NOT _aida_c03_dependency_source IN_LIST _aida_c03_seen_paths)
                    message(FATAL_ERROR "AiDA C03 dependency source is not identity-bound: ${_aida_c03_dependency_source}")
                endif()
            endforeach()
        endif()
    endforeach()
    if(NOT _aida_c03_usage_production EQUAL 24 OR NOT _aida_c03_usage_build_only EQUAL 2 OR
       NOT _aida_c03_usage_evidence_only EQUAL 2 OR NOT _aida_c03_usage_non_use EQUAL 2)
        message(FATAL_ERROR "AiDA C03 dependency usage partition is invalid")
    endif()
    string(JSON _aida_c03_managed_locked GET "${_aida_c03_authority}" offline_managed_restore locked_mode_required)
    string(JSON _aida_c03_managed_offline GET "${_aida_c03_authority}" offline_managed_restore network_sources_forbidden)
    string(JSON _aida_c03_managed_source GET "${_aida_c03_authority}" offline_managed_restore local_source)
    string(JSON _aida_c03_managed_count LENGTH "${_aida_c03_authority}" offline_managed_restore packages)
    if(NOT _aida_c03_managed_locked OR NOT _aida_c03_managed_offline OR
       NOT _aida_c03_managed_source STREQUAL ".deps/nuget-offline" OR
       NOT _aida_c03_managed_count EQUAL 3)
        message(FATAL_ERROR "AiDA C03 offline managed package graph is invalid")
    endif()
    set(_aida_c03_managed_expected
        "ICSharpCode.Decompiler|10.1.0.8386|.deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg|a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af"
        "System.Collections.Immutable|9.0.0|.deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg|fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7"
        "System.Reflection.Metadata|9.0.0|.deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg|6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634")
    set(_aida_c03_managed_archives)
    foreach(_aida_c03_index RANGE 0 2)
        list(GET _aida_c03_managed_expected ${_aida_c03_index} _aida_c03_expected_record)
        string(REPLACE "|" ";" _aida_c03_expected_fields "${_aida_c03_expected_record}")
        string(JSON _aida_c03_package_id GET "${_aida_c03_authority}" offline_managed_restore packages ${_aida_c03_index} id)
        string(JSON _aida_c03_package_version GET "${_aida_c03_authority}" offline_managed_restore packages ${_aida_c03_index} version)
        string(JSON _aida_c03_package_path GET "${_aida_c03_authority}" offline_managed_restore packages ${_aida_c03_index} path)
        string(JSON _aida_c03_package_sha256 GET "${_aida_c03_authority}" offline_managed_restore packages ${_aida_c03_index} sha256)
        list(GET _aida_c03_expected_fields 0 _aida_c03_expected_id)
        list(GET _aida_c03_expected_fields 1 _aida_c03_expected_version)
        list(GET _aida_c03_expected_fields 2 _aida_c03_expected_path)
        list(GET _aida_c03_expected_fields 3 _aida_c03_expected_sha256)
        if(NOT _aida_c03_package_id STREQUAL _aida_c03_expected_id OR
           NOT _aida_c03_package_version STREQUAL _aida_c03_expected_version OR
           NOT _aida_c03_package_path STREQUAL _aida_c03_expected_path OR
           NOT _aida_c03_package_sha256 STREQUAL _aida_c03_expected_sha256)
            message(FATAL_ERROR "AiDA C03 offline managed package identity is invalid")
        endif()
        list(APPEND _aida_c03_managed_archives "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_package_path}")
    endforeach()
    file(READ "${AIDA_C03_MANAGED_WORKER_NUGET_CONFIG}" _aida_c03_nuget_config)
    string(TOLOWER "${_aida_c03_nuget_config}" _aida_c03_nuget_config_lower)
    if(NOT _aida_c03_nuget_config_lower MATCHES "<clear[ ]*/>" OR
       NOT _aida_c03_nuget_config_lower MATCHES "\\.deps\\\\nuget-offline" OR
       _aida_c03_nuget_config_lower MATCHES "(https?|ftp|git|ssh|file)://")
        message(FATAL_ERROR "AiDA C03 managed worker NuGet configuration is not strictly offline")
    endif()
    string(JSON _aida_c03_native_schema_version GET "${_aida_c03_native}" schema_version)
    string(JSON _aida_c03_native_manifest_version GET "${_aida_c03_native}" artifact schema_version)
    string(JSON _aida_c03_native_protocol_version GET "${_aida_c03_native}" worker protocol version)
    string(JSON _aida_c03_native_protocol_material GET "${_aida_c03_native}" worker protocol hash_material)
    string(JSON _aida_c03_native_provider_version GET "${_aida_c03_native}" worker provider version)
    string(JSON _aida_c03_native_build_id GET "${_aida_c03_native}" worker provider worker_build_id)
    string(JSON _aida_c03_native_build_material GET "${_aida_c03_native}" worker provider worker_build_hash_material)
    if(NOT _aida_c03_native_schema_version EQUAL 2 OR NOT _aida_c03_native_manifest_version EQUAL 2 OR
       NOT _aida_c03_native_protocol_version EQUAL 3 OR
       NOT _aida_c03_native_protocol_material STREQUAL "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m" OR
       NOT _aida_c03_native_provider_version STREQUAL "2" OR
       NOT _aida_c03_native_build_id STREQUAL "aida-native-decompiler-worker-v3" OR
       NOT _aida_c03_native_build_material STREQUAL "aida-native-decompiler-worker-build-v3|bounded-printc-evidence")
        message(FATAL_ERROR "AiDA C03 native worker manifest identity is stale")
    endif()
    string(JSON _aida_c03_managed_schema_version GET "${_aida_c03_managed}" schema_version)
    string(JSON _aida_c03_managed_manifest_version GET "${_aida_c03_managed}" artifact schema_version)
    string(JSON _aida_c03_managed_protocol_version GET "${_aida_c03_managed}" worker protocol version)
    string(JSON _aida_c03_managed_protocol_material GET "${_aida_c03_managed}" worker protocol hash_material)
    string(JSON _aida_c03_managed_build_id GET "${_aida_c03_managed}" worker provider worker_build_id)
    if(NOT _aida_c03_managed_schema_version EQUAL 3 OR NOT _aida_c03_managed_manifest_version EQUAL 3 OR
       NOT _aida_c03_managed_protocol_version EQUAL 3 OR
       NOT _aida_c03_managed_protocol_material STREQUAL "aida.isolated-decompiler.worker.frame.v3|bootstrap.v1|hmac-sha256|strict-sequence|readonly-provider-input|attested-provider-artifacts|bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m" OR
       NOT _aida_c03_managed_build_id STREQUAL "aida-managed-decompiler-worker-v3")
        message(FATAL_ERROR "AiDA C03 managed worker manifest identity is stale")
    endif()
    string(JSON _aida_c03_notice_ledger GET "${_aida_c03_authority}" notice_artifacts ledger_source_path)
    string(JSON _aida_c03_notice_ledger_output GET "${_aida_c03_authority}" notice_artifacts customer_ledger_relative_path)
    string(JSON _aida_c03_managed_notice_count LENGTH "${_aida_c03_authority}" notice_artifacts managed_package_notices)
    if(NOT _aida_c03_notice_ledger STREQUAL "licenses/c03/THIRD_PARTY_NOTICES.md" OR
       NOT _aida_c03_notice_ledger_output STREQUAL "notices/THIRD_PARTY_NOTICES.md" OR
       NOT _aida_c03_managed_notice_count EQUAL 2)
        message(FATAL_ERROR "AiDA C03 notice artifact authority is malformed")
    endif()
    set(_aida_c03_managed_notice_records)
    foreach(_aida_c03_index RANGE 0 1)
        string(JSON _aida_c03_notice_id GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} id)
        string(JSON _aida_c03_notice_archive GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} archive)
        string(JSON _aida_c03_license_entry GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} license_entry)
        string(JSON _aida_c03_license_output GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} license_relative_path)
        string(JSON _aida_c03_license_sha256 GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} license_sha256)
        string(JSON _aida_c03_third_party_entry GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} third_party_notices_entry)
        string(JSON _aida_c03_third_party_output GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} third_party_notices_relative_path)
        string(JSON _aida_c03_third_party_sha256 GET "${_aida_c03_authority}" notice_artifacts managed_package_notices ${_aida_c03_index} third_party_notices_sha256)
        aida_c03_require_sha256_value("${_aida_c03_license_sha256}" "managed package license notice")
        aida_c03_require_sha256_value("${_aida_c03_third_party_sha256}" "managed package third-party notice")
        if(NOT _aida_c03_notice_archive IN_LIST _aida_c03_seen_paths OR
           NOT _aida_c03_license_entry STREQUAL "LICENSE.TXT" OR
           NOT _aida_c03_third_party_entry STREQUAL "THIRD-PARTY-NOTICES.TXT" OR
           NOT _aida_c03_license_output MATCHES "^notices/managed/[A-Za-z0-9_.-]+/LICENSE\\.TXT$" OR
           NOT _aida_c03_third_party_output MATCHES "^notices/managed/[A-Za-z0-9_.-]+/THIRD-PARTY-NOTICES\\.TXT$")
            message(FATAL_ERROR "AiDA C03 managed package notice authority is malformed: ${_aida_c03_notice_id}")
        endif()
        list(APPEND _aida_c03_managed_notice_records
            "${_aida_c03_notice_archive}|${_aida_c03_license_entry}|${_aida_c03_license_output}|${_aida_c03_license_sha256}|${_aida_c03_third_party_entry}|${_aida_c03_third_party_output}|${_aida_c03_third_party_sha256}")
    endforeach()
    string(JSON _aida_c03_build_notice_count LENGTH "${_aida_c03_authority}" notice_artifacts build_only_notices)
    string(JSON _aida_c03_evidence_notice_count LENGTH "${_aida_c03_authority}" notice_artifacts evidence_only_notices)
    if(NOT _aida_c03_build_notice_count EQUAL 1 OR NOT _aida_c03_evidence_notice_count EQUAL 2)
        message(FATAL_ERROR "AiDA C03 auxiliary notice authority cardinality is invalid")
    endif()
    foreach(_aida_c03_notice_group IN ITEMS build_only_notices evidence_only_notices)
        string(JSON _aida_c03_notice_count LENGTH "${_aida_c03_authority}" notice_artifacts ${_aida_c03_notice_group})
        math(EXPR _aida_c03_notice_last "${_aida_c03_notice_count} - 1")
        foreach(_aida_c03_index RANGE 0 ${_aida_c03_notice_last})
            string(JSON _aida_c03_notice_source GET "${_aida_c03_authority}" notice_artifacts ${_aida_c03_notice_group} ${_aida_c03_index} license_source)
            string(JSON _aida_c03_notice_sha256 GET "${_aida_c03_authority}" notice_artifacts ${_aida_c03_notice_group} ${_aida_c03_index} license_sha256)
            if(NOT _aida_c03_notice_source IN_LIST _aida_c03_seen_paths)
                message(FATAL_ERROR "AiDA C03 auxiliary notice is not identity-bound: ${_aida_c03_notice_source}")
            endif()
            aida_c03_require_file_sha256("${_aida_c03_notice_source}" "${_aida_c03_notice_sha256}")
        endforeach()
    endforeach()
    string(JSON _aida_c03_distribution_policy GET "${_aida_c03_authority}" customer_sidecars distribution)
    string(JSON _aida_c03_raw_forbidden GET "${_aida_c03_authority}" customer_sidecars raw_standalone_download_forbidden)
    string(JSON _aida_c03_fileless_forbidden GET "${_aida_c03_authority}" customer_sidecars fileless_launch_forbidden)
    string(JSON _aida_c03_only_browser GET "${_aida_c03_authority}" customer_sidecars camoufox only_supported_browser)
    string(JSON _aida_c03_browser_source GET "${_aida_c03_authority}" customer_sidecars camoufox browser_source_path)
    string(JSON _aida_c03_browser_output GET "${_aida_c03_authority}" customer_sidecars camoufox browser_relative_path)
    string(JSON _aida_c03_browser_sha256 GET "${_aida_c03_authority}" customer_sidecars camoufox browser_sha256)
    string(JSON _aida_c03_reverse_source GET "${_aida_c03_authority}" customer_sidecars camoufox reverse_mcp_source_path)
    string(JSON _aida_c03_reverse_output GET "${_aida_c03_authority}" customer_sidecars camoufox reverse_mcp_relative_path)
    string(JSON _aida_c03_reverse_sha256 GET "${_aida_c03_authority}" customer_sidecars camoufox reverse_mcp_sha256)
    string(JSON _aida_c03_sidecar_lock GET "${_aida_c03_authority}" customer_sidecars camoufox offline_build_lock)
    string(JSON _aida_c03_developer_source GET "${_aida_c03_authority}" customer_sidecars camoufox developer_source_shipped)
    string(JSON _aida_c03_loose_python GET "${_aida_c03_authority}" customer_sidecars camoufox loose_python_shipped)
    string(JSON _aida_c03_stock_browser GET "${_aida_c03_authority}" customer_sidecars camoufox stock_browser_fallback)
    string(JSON _aida_c03_env_browser GET "${_aida_c03_authority}" customer_sidecars camoufox environment AIDA_CAMOUFOX_EXECUTABLE)
    string(JSON _aida_c03_env_mcp GET "${_aida_c03_authority}" customer_sidecars camoufox environment AIDA_CAMOUFOX_MCP_EXECUTABLE)
    string(JSON _aida_c03_env_python GET "${_aida_c03_authority}" customer_sidecars camoufox environment AIDA_CAMOUFOX_PYTHON)
    if(NOT _aida_c03_distribution_policy STREQUAL "protected-disk-backed" OR
       NOT _aida_c03_raw_forbidden OR NOT _aida_c03_fileless_forbidden OR
       NOT _aida_c03_only_browser STREQUAL "camoufox" OR
       NOT _aida_c03_browser_source STREQUAL AIDA_C03_CAMOUFOX_EXECUTABLE_SOURCE_RELATIVE_PATH OR
       NOT _aida_c03_browser_output STREQUAL AIDA_C03_CAMOUFOX_EXECUTABLE_PACKAGE_RELATIVE_PATH OR
       NOT _aida_c03_browser_sha256 STREQUAL AIDA_C03_CAMOUFOX_EXECUTABLE_SHA256 OR
       NOT _aida_c03_reverse_source STREQUAL AIDA_C03_CAMOUFOX_REVERSE_MCP_SOURCE_RELATIVE_PATH OR
       NOT _aida_c03_reverse_output STREQUAL AIDA_C03_CAMOUFOX_REVERSE_MCP_PACKAGE_RELATIVE_PATH OR
       NOT _aida_c03_reverse_sha256 STREQUAL AIDA_C03_CAMOUFOX_REVERSE_MCP_EXECUTABLE_SHA256 OR
       NOT _aida_c03_sidecar_lock STREQUAL "packaging/c03_camoufox_reverse_mcp_build.lock.json" OR
       _aida_c03_developer_source OR _aida_c03_loose_python OR _aida_c03_stock_browser OR
       NOT _aida_c03_env_browser STREQUAL "verified-browser" OR
       NOT _aida_c03_env_mcp STREQUAL "verified-frozen-sidecar" OR
       NOT _aida_c03_env_python STREQUAL "unset-unless-verified-sidecar-runtime")
        message(FATAL_ERROR "AiDA C03 customer sidecar policy is malformed or weakened")
    endif()
    string(JSON _aida_c03_python_id GET "${_aida_c03_authority}" analysis_python_worker id)
    string(JSON _aida_c03_python_no_fetch GET "${_aida_c03_authority}" analysis_python_worker network_fetch_forbidden)
    string(JSON _aida_c03_python_camoufox_forbidden GET "${_aida_c03_authority}" analysis_python_worker runtime_coupling camoufox_forbidden)
    string(JSON _aida_c03_python_required GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact required_for_staging)
    string(JSON _aida_c03_python_state GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact identity_state)
    string(JSON _aida_c03_python_relative GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact source_path)
    string(JSON _aida_c03_python_expected_sha256 GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact expected_sha256)
    string(JSON _aida_c03_python_expected_size GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact expected_size_bytes)
    if(NOT _aida_c03_python_id STREQUAL "analysis_python" OR NOT _aida_c03_python_no_fetch OR
       NOT _aida_c03_python_camoufox_forbidden OR NOT _aida_c03_python_required OR
       NOT _aida_c03_python_relative STREQUAL ".deps/AiDA_AnalysisPythonWorker/AiDA_AnalysisPythonWorker.exe")
        message(FATAL_ERROR "AiDA C03 analysis Python worker contract is malformed or weakened")
    endif()
    if(_aida_c03_python_state STREQUAL "external_fixture_required")
        if(EXISTS "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_python_relative}" OR
           NOT _aida_c03_python_expected_sha256 STREQUAL "" OR NOT _aida_c03_python_expected_size EQUAL 0)
            message(FATAL_ERROR "AiDA C03 analysis Python external artifact state does not match its unlocked authority")
        endif()
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE OFF PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_SHIPPED OFF PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER "missing locked prebuilt artifact: ${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT}" PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_RECEIPTS "" PARENT_SCOPE)
    elseif(_aida_c03_python_state STREQUAL "locked")
        aida_c03_require_sha256_value("${_aida_c03_python_expected_sha256}" "analysis Python locked artifact")
        if(_aida_c03_python_expected_size LESS 1)
            message(FATAL_ERROR "AiDA C03 analysis Python locked artifact identity is incomplete")
        endif()
        aida_c03_require_file_identity("${_aida_c03_python_relative}" "${_aida_c03_python_expected_size}" "${_aida_c03_python_expected_sha256}")
        set(_aida_c03_python_receipts)
        foreach(_aida_c03_receipt_key IN ITEMS frozen_contents_path build_receipt_path protector_receipt_path signature_receipt_path)
            string(JSON _aida_c03_receipt_relative GET "${_aida_c03_authority}" analysis_python_worker prebuilt_artifact ${_aida_c03_receipt_key})
            if(NOT EXISTS "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_receipt_relative}" OR IS_DIRECTORY "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_receipt_relative}")
                message(FATAL_ERROR "AiDA C03 analysis Python locked artifact receipt is missing: ${_aida_c03_receipt_relative}")
            endif()
            list(APPEND _aida_c03_python_receipts "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_receipt_relative}")
        endforeach()
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE ON PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_SHIPPED ON PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER "" PARENT_SCOPE)
        set(AIDA_C03_ANALYSIS_PYTHON_WORKER_RECEIPTS "${_aida_c03_python_receipts}" PARENT_SCOPE)
    else()
        message(FATAL_ERROR "AiDA C03 analysis Python worker identity state is invalid")
    endif()
    aida_c03_require_locked_source_tree()
    aida_c03_verify_camoufox_build_lock()
    set(AIDA_C03_REQUIRED_PRODUCTION_INPUTS "${_aida_c03_required_production_inputs}" PARENT_SCOPE)
    set(AIDA_C03_REQUIRED_BUILD_INPUTS "${_aida_c03_required_build_inputs}" PARENT_SCOPE)
    set(AIDA_C03_REQUIRED_EVIDENCE_INPUTS "${_aida_c03_required_evidence_inputs}" PARENT_SCOPE)
    set(AIDA_C03_OPTIONAL_EXTERNAL_INPUTS "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT}" PARENT_SCOPE)
    set(AIDA_C03_DEPENDENCY_IDS "${_aida_c03_dependency_ids}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_PACKAGE_ARCHIVES "${_aida_c03_managed_archives}" PARENT_SCOPE)
    set(AIDA_C03_MANAGED_PACKAGE_NOTICE_RECORDS "${_aida_c03_managed_notice_records}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_pcre2_8bit_no_jit)
    if(TARGET pcre2-8)
        if(NOT TARGET pcre2-8-static)
            message(FATAL_ERROR "AiDA C03 PCRE2 dependency is not the approved static 8-bit target")
        endif()
        return()
    endif()
    set(_aida_c03_pcre2_source "${AIDA_C03_DEPENDENCY_ROOT}/.deps/pcre2-10.47")
    set(_aida_c03_pcre2_binary "${CMAKE_BINARY_DIR}/.deps/pcre2-c03")
    aida_c03_require_path_sha256("${_aida_c03_pcre2_source}/CMakeLists.txt" "74f65935e2b1120e7d7aeb4be81755e0f7a875732467ae64a9cc6ee7174fa5ba" "PCRE2 10.47 CMake contract")
    aida_c03_require_path_sha256("${_aida_c03_pcre2_source}/src/pcre2.h.generic" "058462dc030e845ee627e19ac36347f561f5cc44d89eaf1c0010f2b363ab68d5" "PCRE2 10.47 public header")
    aida_c03_require_path_sha256("${_aida_c03_pcre2_source}/LICENCE.md" "197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811" "PCRE2 10.47 license")
    set(_aida_c03_saved_build_shared_libs "${BUILD_SHARED_LIBS}")
    set(_aida_c03_saved_build_static_libs "${BUILD_STATIC_LIBS}")
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_STATIC_LIBS ON)
    set(PCRE2_BUILD_PCRE2_8 ON CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_16 OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_32 OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2GREP OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_JIT OFF CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_JIT_SEALLOC OFF CACHE BOOL "" FORCE)
    add_subdirectory("${_aida_c03_pcre2_source}" "${_aida_c03_pcre2_binary}" EXCLUDE_FROM_ALL)
    set(BUILD_SHARED_LIBS "${_aida_c03_saved_build_shared_libs}")
    set(BUILD_STATIC_LIBS "${_aida_c03_saved_build_static_libs}")
    if(NOT TARGET pcre2-8 OR NOT TARGET pcre2-8-static)
        message(FATAL_ERROR "AiDA C03 PCRE2 static 8-bit target registration failed")
    endif()
    set_target_properties(pcre2-8-static PROPERTIES FOLDER "Dependencies/C03")
endfunction()

function(aida_c03_require_components dependency)
    set(_aida_c03_requested_components ${ARGN})
    if(NOT _aida_c03_requested_components)
        message(FATAL_ERROR "AiDA C03 component request is empty: ${dependency}")
    endif()
    string(TOUPPER "${dependency}" _aida_c03_dependency_key)
    string(REPLACE "-" "_" _aida_c03_dependency_key "${_aida_c03_dependency_key}")
    set(_aida_c03_allowlist_name "AIDA_C03_${_aida_c03_dependency_key}_COMPONENT_ALLOWLIST")
    if(NOT DEFINED ${_aida_c03_allowlist_name})
        message(FATAL_ERROR "AiDA C03 dependency has no component allowlist: ${dependency}")
    endif()
    foreach(_aida_c03_component IN LISTS _aida_c03_requested_components)
        if(NOT _aida_c03_component IN_LIST ${_aida_c03_allowlist_name})
            message(FATAL_ERROR "AiDA C03 component is not approved: ${dependency} -> ${_aida_c03_component}")
        endif()
        string(TOLOWER "${_aida_c03_component}" _aida_c03_component_lower)
        foreach(_aida_c03_forbidden IN LISTS AIDA_C03_PRODUCTION_LINK_DENY_TOKENS)
            if(_aida_c03_component_lower MATCHES "(^|[^a-z0-9])${_aida_c03_forbidden}([^a-z0-9]|$)")
                message(FATAL_ERROR "AiDA C03 forbidden component requested: ${_aida_c03_component}")
            endif()
        endforeach()
    endforeach()
endfunction()

function(aida_c03_reject_forbidden_target_links)
    if(NOT ARGN)
        message(FATAL_ERROR "AiDA C03 deny-link audit requires at least one target")
    endif()
    set(_aida_c03_queue ${ARGN})
    set(_aida_c03_visited)
    while(_aida_c03_queue)
        list(POP_FRONT _aida_c03_queue _aida_c03_target)
        if(NOT TARGET "${_aida_c03_target}")
            message(FATAL_ERROR "AiDA C03 target is not defined: ${_aida_c03_target}")
        endif()
        get_target_property(_aida_c03_aliased_target "${_aida_c03_target}" ALIASED_TARGET)
        if(_aida_c03_aliased_target)
            set(_aida_c03_target "${_aida_c03_aliased_target}")
        endif()
        if(_aida_c03_target IN_LIST _aida_c03_visited)
            continue()
        endif()
        list(APPEND _aida_c03_visited "${_aida_c03_target}")
        foreach(_aida_c03_property IN ITEMS
                LINK_LIBRARIES
                LINK_INTERFACE_LIBRARIES
                INTERFACE_LINK_LIBRARIES
                INTERFACE_LINK_LIBRARIES_DIRECT
                IMPORTED_LINK_INTERFACE_LIBRARIES
                IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG
                IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE
                IMPORTED_LINK_INTERFACE_LIBRARIES_RELWITHDEBINFO
                IMPORTED_LINK_INTERFACE_LIBRARIES_MINSIZEREL
                IMPORTED_LINK_DEPENDENT_LIBRARIES
                IMPORTED_LINK_DEPENDENT_LIBRARIES_DEBUG
                IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE
                IMPORTED_LINK_DEPENDENT_LIBRARIES_RELWITHDEBINFO
                IMPORTED_LINK_DEPENDENT_LIBRARIES_MINSIZEREL)
            get_target_property(_aida_c03_links "${_aida_c03_target}" "${_aida_c03_property}")
            if(NOT _aida_c03_links OR _aida_c03_links MATCHES "-NOTFOUND$")
                continue()
            endif()
            foreach(_aida_c03_link IN LISTS _aida_c03_links)
                string(TOLOWER "${_aida_c03_link}" _aida_c03_normalized_link)
                foreach(_aida_c03_forbidden IN LISTS AIDA_C03_PRODUCTION_LINK_DENY_TOKENS)
                    if(_aida_c03_normalized_link MATCHES "(^|[^a-z0-9])${_aida_c03_forbidden}([^a-z0-9]|$)")
                        message(FATAL_ERROR "AiDA C03 target links a forbidden dependency: ${_aida_c03_target} -> ${_aida_c03_link}")
                    endif()
                endforeach()
                if(TARGET "${_aida_c03_link}")
                    list(APPEND _aida_c03_queue "${_aida_c03_link}")
                else()
                    string(REGEX MATCHALL "[A-Za-z0-9_.:+-]+" _aida_c03_link_tokens "${_aida_c03_link}")
                    foreach(_aida_c03_link_token IN LISTS _aida_c03_link_tokens)
                        if(TARGET "${_aida_c03_link_token}")
                            list(APPEND _aida_c03_queue "${_aida_c03_link_token}")
                        endif()
                    endforeach()
                endif()
            endforeach()
        endforeach()
    endwhile()
endfunction()

set(AIDA_C03_CUSTOMER_NOTICE_SOURCE_PATHS
    "licenses/c03/THIRD_PARTY_NOTICES.md"
    "licenses/c03/MIT.txt"
    "licenses/c03/SQLite-Public-Domain.txt"
    ".deps/zydis-4.1.1/LICENSE"
    ".deps/zydis-4.1.1/dependencies/zycore/LICENSE"
    ".deps/capstone/capstone-5.0.9/LICENSE.TXT"
    ".deps/taskflow/LICENSE"
    "src/standalone/third_party_notices/Ghidra-LICENSE.txt"
    "src/standalone/third_party_notices/Ghidra-NOTICE.txt"
    "sources/Triton/LICENSE.txt"
    ".deps/z3/z3-4.13.4-x64-win/LICENSE.txt"
    ".deps/imgui-src/LICENSE.txt"
    ".deps/zlib-1.3.2/LICENSE"
    ".deps/zstd-1.5.7/LICENSE"
    ".deps/xz-5.8.3/COPYING.0BSD"
    ".deps/minizip-ng-4.2.2/LICENSE"
    ".deps/pcre2-10.47/LICENCE.md"
    ".deps/licenses/nlohmann-json-3.12.0-LICENSE.MIT"
    ".deps/json-schema-validator-2.4.0/LICENSE"
    ".deps/llvm-project-llvmorg-22.1.8/LICENSE.TXT")
list(APPEND AIDA_C03_CUSTOMER_NOTICE_SOURCE_PATHS
    ".deps/dotnet-sdk-10.0.301-win-x64/LICENSE.txt"
    ".deps/dotnet-sdk-10.0.301-win-x64/ThirdPartyNotices.txt")
set(AIDA_C03_BUILD_ONLY_NOTICE_SOURCE_PATHS
    ".deps/.camoufox-reverse-mcp-build-venv/Lib/site-packages/pyinstaller-6.21.0.dist-info/licenses/COPYING.txt")
set(AIDA_C03_EVIDENCE_ONLY_NOTICE_SOURCE_PATHS
    ".deps/LIEF-0.17.6/LICENSE"
    ".deps/remill-6.0.1/remill-6.0.1/LICENSE")

aida_c03_verify_dependency_inventory()
aida_c03_register_pcre2_8bit_no_jit()
