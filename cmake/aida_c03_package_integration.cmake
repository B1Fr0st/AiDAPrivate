include_guard(GLOBAL)

if(NOT WIN32)
    message(FATAL_ERROR "AiDA C03 package integration is Windows-only")
endif()
if(NOT COMMAND aida_c03_require_path_sha256 OR
   NOT COMMAND aida_c03_reject_forbidden_target_links)
    message(FATAL_ERROR "AiDA C03 package integration requires aida_c03_dependencies.cmake")
endif()

set(AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET "aida_c03_b14_native_worker_package_manifest")
set(AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET "aida_c03_b15_ghidra_spec_package_manifest")
set(AIDA_C03_GHIDRA_SPEC_PACKAGE_OUTPUTS
    "ghidra_specs"
    "deps/ghidra_specs"
    "deps/AiDA_GhidraSpecs.manifest.json"
    "deps/AiDA_GhidraSpecs.manifest.sha256")
set(AIDA_C03_NATIVE_WORKER_PACKAGE_OUTPUTS
    "deps/AiDA_NativeDecompilerWorker.exe"
    "deps/AiDA_NativeDecompilerWorker.manifest.bin"
    "deps/AiDA_NativeDecompilerWorker.manifest.sha256"
    "deps/evidence/native.acl.json")
set(AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET "aida_c03_b16_managed_worker_package_manifest")
set(AIDA_C03_MANAGED_WORKER_PACKAGE_OUTPUTS
    "deps/AiDA_ManagedDecompilerWorker.exe"
    "deps/AiDA_ManagedDecompilerWorker.dll"
    "deps/AiDA_ManagedDecompilerWorker.deps.json"
    "deps/AiDA_ManagedDecompilerWorker.runtimeconfig.json"
    "deps/ICSharpCode.Decompiler.dll"
    "deps/System.Collections.Immutable.dll"
    "deps/System.Reflection.Metadata.dll"
    "deps/dotnet"
    "deps/AiDA_ManagedRuntime.manifest.json"
    "deps/AiDA_ManagedRuntime.manifest.sha256"
    "deps/AiDA_ManagedDecompilerWorker.manifest.bin"
    "deps/AiDA_ManagedDecompilerWorker.manifest.sha256"
    "deps/evidence/managed.acl.json")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET "aida_c03_b24_analysis_python_worker_source_contract")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET "aida_c03_b24_analysis_python_worker_package_manifest")
set(AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_OUTPUTS
    "deps/AiDA_AnalysisPythonWorker.exe"
    "deps/AiDA_AnalysisPythonWorker.manifest.bin"
    "deps/AiDA_AnalysisPythonWorker.manifest.sha256"
    "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.acl.json"
    "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.frozen_contents.json"
    "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.build_receipt.json"
    "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.protector_receipt.json"
    "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.signature_receipt.json")
set(AIDA_C03_NATIVE_WORKER_REQUIRED_RECEIPT_OUTPUTS
    "deps/evidence/native.protector.json"
    "deps/evidence/native.signature.json")
set(AIDA_C03_MANAGED_WORKER_REQUIRED_RECEIPT_OUTPUTS
    "deps/evidence/managed.protector.json"
    "deps/evidence/managed.signature.json")
set(AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET "aida_c03_customer_notice_package")
set(AIDA_C03_CUSTOMER_SIDECAR_ARTIFACTS
    "${AIDA_C03_CAMOUFOX_EXECUTABLE}"
    "${AIDA_C03_CAMOUFOX_REVERSE_MCP_EXECUTABLE}")
set(AIDA_C03_CUSTOMER_SIDECAR_PACKAGE_RELATIVE_PATHS
    "${AIDA_C03_CAMOUFOX_EXECUTABLE_PACKAGE_RELATIVE_PATH}"
    "${AIDA_C03_CAMOUFOX_REVERSE_MCP_PACKAGE_RELATIVE_PATH}")
set(AIDA_C03_CUSTOMER_SIDECAR_ENVIRONMENT
    "AIDA_CAMOUFOX_EXECUTABLE=verified-browser"
    "AIDA_CAMOUFOX_MCP_EXECUTABLE=verified-frozen-sidecar"
    "AIDA_CAMOUFOX_PYTHON=unset-unless-verified-sidecar-runtime")

function(_aida_c03_package_require_target target descriptor)
    if(NOT target OR NOT TARGET "${target}")
        message(FATAL_ERROR "AiDA C03 ${descriptor} target is missing: ${target}")
    endif()
endfunction()

function(_aida_c03_package_require_dependency_targets descriptor)
    foreach(_aida_c03_dependency IN LISTS ARGN)
        _aida_c03_package_require_target("${_aida_c03_dependency}" "${descriptor} dependency")
    endforeach()
endfunction()

function(_aida_c03_package_require_python)
    if(NOT Python3_EXECUTABLE OR NOT EXISTS "${Python3_EXECUTABLE}" OR IS_DIRECTORY "${Python3_EXECUTABLE}")
        message(FATAL_ERROR "AiDA C03 worker manifest materialization requires the configured local Python3 interpreter")
    endif()
endfunction()

function(_aida_c03_package_find_powershell output_variable)
    if(AIDA_POWERSHELL_EXECUTABLE AND EXISTS "${AIDA_POWERSHELL_EXECUTABLE}" AND
       NOT IS_DIRECTORY "${AIDA_POWERSHELL_EXECUTABLE}")
        set(${output_variable} "${AIDA_POWERSHELL_EXECUTABLE}" PARENT_SCOPE)
        return()
    endif()
    find_program(_aida_c03_powershell NAMES powershell.exe pwsh.exe powershell pwsh)
    if(NOT _aida_c03_powershell)
        message(FATAL_ERROR "AiDA C03 package materialization requires a local PowerShell executable")
    endif()
    set(${output_variable} "${_aida_c03_powershell}" PARENT_SCOPE)
endfunction()

function(_aida_c03_package_require_filename path expected descriptor)
    get_filename_component(_aida_c03_name "${path}" NAME)
    if(NOT _aida_c03_name STREQUAL expected)
        message(FATAL_ERROR "AiDA C03 ${descriptor} filename is invalid: ${_aida_c03_name}")
    endif()
endfunction()

function(_aida_c03_package_require_runtime_file path output_name)
    if(NOT path OR path MATCHES ";")
        message(FATAL_ERROR "AiDA C03 managed runtime file path is invalid")
    endif()
    get_filename_component(_aida_c03_name "${path}" NAME)
    string(TOLOWER "${_aida_c03_name}" _aida_c03_name_lower)
    if(NOT _aida_c03_name OR
       _aida_c03_name_lower MATCHES "\\.(cs|csproj|fs|fsproj|vb|vbproj|pdb|ilk|lib|obj|exp|map|a|nupkg|snupkg|nuspec|targets|props)$")
        message(FATAL_ERROR "AiDA C03 managed runtime file is a source, package, symbol, or build artifact: ${path}")
    endif()
    set(${output_name} "${_aida_c03_name}" PARENT_SCOPE)
endfunction()

function(_aida_c03_package_require_distinct_paths left right descriptor)
    string(TOLOWER "${left}" _aida_c03_left)
    string(TOLOWER "${right}" _aida_c03_right)
    if(_aida_c03_left STREQUAL _aida_c03_right)
        message(FATAL_ERROR "AiDA C03 ${descriptor} paths overlap")
    endif()
endfunction()

function(aida_c03_register_ghidra_spec_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "APPLICATION_TARGET;SPEC_TARGET;GENERATOR_TARGET;APPROVED_INPUT_ROOT" "SPEC_FILES;DEPENDS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_APPLICATION_TARGET OR NOT _aida_c03_SPEC_TARGET OR
       NOT _aida_c03_GENERATOR_TARGET OR NOT _aida_c03_APPROVED_INPUT_ROOT OR
       NOT _aida_c03_SPEC_FILES)
        message(FATAL_ERROR "AiDA C03 Ghidra specification package arguments are incomplete or malformed")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "Ghidra specification application")
    _aida_c03_package_require_target("${_aida_c03_SPEC_TARGET}" "Ghidra specification producer")
    _aida_c03_package_require_target("${_aida_c03_GENERATOR_TARGET}" "Ghidra SLEIGH generator")
    _aida_c03_package_require_dependency_targets("Ghidra specification package" ${_aida_c03_DEPENDS})
    if(TARGET "${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 Ghidra specification package was registered more than once")
    endif()
    list(LENGTH _aida_c03_SPEC_FILES _aida_c03_spec_count)
    if(NOT _aida_c03_spec_count EQUAL AIDA_C03_GHIDRA_SPEC_FILE_COUNT)
        message(FATAL_ERROR "AiDA C03 Ghidra specification package must receive the exact 51-file inventory")
    endif()
    file(READ "${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC}" _aida_c03_ghidra_source_json)
    set(_aida_c03_seen_names)
    set(_aida_c03_input_arguments)
    math(EXPR _aida_c03_spec_last "${_aida_c03_spec_count} - 1")
    foreach(_aida_c03_index RANGE 0 ${_aida_c03_spec_last})
        list(GET _aida_c03_SPEC_FILES ${_aida_c03_index} _aida_c03_spec_file)
        get_filename_component(_aida_c03_spec_name "${_aida_c03_spec_file}" NAME)
        string(JSON _aida_c03_expected_name GET "${_aida_c03_ghidra_source_json}" specifications ${_aida_c03_index} name)
        if(NOT _aida_c03_spec_name STREQUAL _aida_c03_expected_name OR
           _aida_c03_spec_name IN_LIST _aida_c03_seen_names)
            message(FATAL_ERROR "AiDA C03 Ghidra specification input is missing, reordered, or duplicated: ${_aida_c03_spec_name}")
        endif()
        list(APPEND _aida_c03_seen_names "${_aida_c03_spec_name}")
        list(APPEND _aida_c03_input_arguments --input "${_aida_c03_spec_file}")
    endforeach()
    _aida_c03_package_require_python()
    add_custom_target(${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_GHIDRA_SPEC_MATERIALIZER}"
            --repository-root "${AIDA_C03_DEPENDENCY_ROOT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --contract "${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC}"
            --approved-input-root "${_aida_c03_APPROVED_INPUT_ROOT}"
            --approved-generator-root "$<TARGET_FILE_DIR:${_aida_c03_GENERATOR_TARGET}>"
            --generator "$<TARGET_FILE:${_aida_c03_GENERATOR_TARGET}>"
            ${_aida_c03_input_arguments}
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_GHIDRA_SPEC_MATERIALIZER}"
            --repository-root "${AIDA_C03_DEPENDENCY_ROOT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --contract "${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC}"
            --approved-input-root "${_aida_c03_APPROVED_INPUT_ROOT}"
            --approved-generator-root "$<TARGET_FILE_DIR:${_aida_c03_GENERATOR_TARGET}>"
            --generator "$<TARGET_FILE:${_aida_c03_GENERATOR_TARGET}>"
            ${_aida_c03_input_arguments}
            --verify-only
        DEPENDS
            "${_aida_c03_SPEC_TARGET}"
            "${_aida_c03_GENERATOR_TARGET}"
            ${_aida_c03_SPEC_FILES}
            ${_aida_c03_DEPENDS}
            "${AIDA_C03_GHIDRA_SPEC_SOURCE_SPEC}"
            "${AIDA_C03_GHIDRA_SPEC_SOURCE_SCHEMA}"
            "${AIDA_C03_GHIDRA_SPEC_MANIFEST_SCHEMA}"
            "${AIDA_C03_GHIDRA_SPEC_MATERIALIZER}"
        COMMAND_EXPAND_LISTS
        VERBATIM)
    set_target_properties(${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "ghidra-exact-spec-generation-manifest-v1"
        AIDA_C03_PACKAGE_OUTPUTS "${AIDA_C03_GHIDRA_SPEC_PACKAGE_OUTPUTS}"
        AIDA_C03_SPEC_FILE_COUNT "51"
        AIDA_C03_EXACT_INVENTORY "TRUE"
        AIDA_C03_FINAL_BYTE_ORDERING "sleigh-generation;approved-root-verification;mirror-copy;manifest;verify")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET "${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}")
endfunction()

function(aida_c03_register_native_worker_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "APPLICATION_TARGET;WORKER_TARGET" "DEPENDS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_APPLICATION_TARGET OR NOT _aida_c03_WORKER_TARGET)
        message(FATAL_ERROR "AiDA C03 native worker package arguments are incomplete or malformed")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "native worker application")
    _aida_c03_package_require_target("${_aida_c03_WORKER_TARGET}" "native worker executable")
    _aida_c03_package_require_dependency_targets("native worker package" ${_aida_c03_DEPENDS})
    if(TARGET "${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 native worker package was registered more than once")
    endif()
    if(NOT TARGET "${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 native worker package requires the verified Ghidra specification package")
    endif()
    if(_aida_c03_APPLICATION_TARGET STREQUAL _aida_c03_WORKER_TARGET)
        message(FATAL_ERROR "AiDA C03 native worker must remain a distinct disk-backed sidecar")
    endif()
    _aida_c03_package_require_python()
    _aida_c03_package_find_powershell(_aida_c03_powershell)
    add_custom_target(${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:${_aida_c03_WORKER_TARGET}>"
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_NativeDecompilerWorker.exe"
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_NATIVE_WORKER_MANIFEST_MATERIALIZER}"
            --contract "${AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --worker "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_NativeDecompilerWorker.exe"
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_NATIVE_WORKER_MANIFEST_MATERIALIZER}"
            --contract "${AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --worker "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_NativeDecompilerWorker.exe"
            --verify-only
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy native
            -WorkerManifestDigest "deps/AiDA_NativeDecompilerWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/native.acl.json"
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy native
            -WorkerManifestDigest "deps/AiDA_NativeDecompilerWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/native.acl.json"
            -VerifyOnly
        DEPENDS
            "${_aida_c03_WORKER_TARGET}"
            "${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}"
            ${_aida_c03_DEPENDS}
            "${AIDA_C03_NATIVE_WORKER_MANIFEST_MATERIALIZER}"
            "${AIDA_C03_NATIVE_WORKER_MANIFEST_CONTRACT}"
            "${AIDA_C03_NATIVE_WORKER_MANIFEST_SCHEMA}"
            "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
        VERBATIM)
    set_target_properties(${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "native-decompiler-worker-manifest-v2"
        AIDA_C03_PACKAGE_OUTPUTS "${AIDA_C03_NATIVE_WORKER_PACKAGE_OUTPUTS}"
        AIDA_C03_GHIDRA_SPEC_AUTHORITY "deps/AiDA_GhidraSpecs.manifest.json;deps/AiDA_GhidraSpecs.manifest.sha256;exact-51-file-mirrors"
        AIDA_C03_FINAL_BYTE_ORDERING "verified-ghidra-specs;worker-target;finalizers;copy;manifest;verify;appcontainer-acl;acl-receipt;verify-acl")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET "${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}")
endfunction()

function(aida_c03_register_managed_worker_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "APPLICATION_TARGET;BUILD_TARGET;WORKER_EXECUTABLE;PROVIDER_BINARY" "RUNTIME_FILES;DEPENDS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_APPLICATION_TARGET OR NOT _aida_c03_BUILD_TARGET OR
       NOT _aida_c03_WORKER_EXECUTABLE OR NOT _aida_c03_PROVIDER_BINARY)
        message(FATAL_ERROR "AiDA C03 managed worker package arguments are incomplete or malformed")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "managed worker application")
    _aida_c03_package_require_target("${_aida_c03_BUILD_TARGET}" "managed worker offline finalizer")
    _aida_c03_package_require_dependency_targets("managed worker package" ${_aida_c03_DEPENDS})
    if(TARGET "${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 managed worker package was registered more than once")
    endif()
    _aida_c03_package_require_filename("${_aida_c03_WORKER_EXECUTABLE}" "AiDA_ManagedDecompilerWorker.exe" "managed worker")
    _aida_c03_package_require_filename("${_aida_c03_PROVIDER_BINARY}" "ICSharpCode.Decompiler.dll" "managed provider")
    _aida_c03_package_require_distinct_paths("${_aida_c03_WORKER_EXECUTABLE}" "${_aida_c03_PROVIDER_BINARY}" "managed worker/provider")
    _aida_c03_package_require_python()
    _aida_c03_package_find_powershell(_aida_c03_powershell)
    set(_aida_c03_expected_runtime_names
        "AiDA_ManagedDecompilerWorker.dll"
        "AiDA_ManagedDecompilerWorker.deps.json"
        "AiDA_ManagedDecompilerWorker.runtimeconfig.json"
        "System.Collections.Immutable.dll"
        "System.Reflection.Metadata.dll")
    list(LENGTH _aida_c03_RUNTIME_FILES _aida_c03_application_file_count)
    if(NOT _aida_c03_application_file_count EQUAL 5)
        message(FATAL_ERROR "AiDA C03 managed application publication must contain the exact five non-apphost runtime files")
    endif()
    set(_aida_c03_runtime_commands)
    set(_aida_c03_runtime_outputs)
    set(_aida_c03_runtime_names
        "AiDA_ManagedDecompilerWorker.exe"
        "ICSharpCode.Decompiler.dll"
        "AiDA_ManagedDecompilerWorker.manifest.bin"
        "AiDA_ManagedDecompilerWorker.manifest.sha256")
    set(_aida_c03_application_index 0)
    foreach(_aida_c03_runtime_file IN LISTS _aida_c03_RUNTIME_FILES)
        _aida_c03_package_require_runtime_file("${_aida_c03_runtime_file}" _aida_c03_runtime_name)
        list(GET _aida_c03_expected_runtime_names ${_aida_c03_application_index} _aida_c03_expected_runtime_name)
        if(NOT _aida_c03_runtime_name STREQUAL _aida_c03_expected_runtime_name)
            message(FATAL_ERROR "AiDA C03 managed application publication is incomplete or reordered: ${_aida_c03_runtime_name}")
        endif()
        string(TOLOWER "${_aida_c03_runtime_name}" _aida_c03_runtime_name_lower)
        set(_aida_c03_runtime_names_lower)
        foreach(_aida_c03_existing_name IN LISTS _aida_c03_runtime_names)
            string(TOLOWER "${_aida_c03_existing_name}" _aida_c03_existing_name_lower)
            list(APPEND _aida_c03_runtime_names_lower "${_aida_c03_existing_name_lower}")
        endforeach()
        if(_aida_c03_runtime_name_lower IN_LIST _aida_c03_runtime_names_lower)
            message(FATAL_ERROR "AiDA C03 managed runtime destination is duplicated: ${_aida_c03_runtime_name}")
        endif()
        list(APPEND _aida_c03_runtime_names "${_aida_c03_runtime_name}")
        list(APPEND _aida_c03_runtime_outputs "deps/${_aida_c03_runtime_name}")
        list(APPEND _aida_c03_runtime_commands
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${_aida_c03_runtime_file}"
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/${_aida_c03_runtime_name}")
        math(EXPR _aida_c03_application_index "${_aida_c03_application_index} + 1")
    endforeach()
    file(GLOB _aida_c03_framework_runtime_files CONFIGURE_DEPENDS LIST_DIRECTORIES false
        "${AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT}/shared/Microsoft.NETCore.App/${AIDA_C03_MANAGED_RUNTIME_VERSION}/*")
    list(LENGTH _aida_c03_framework_runtime_files _aida_c03_framework_runtime_count)
    if(NOT _aida_c03_framework_runtime_count EQUAL 189)
        message(FATAL_ERROR "AiDA C03 app-local Microsoft.NETCore.App 10.0.9 inventory is incomplete")
    endif()
    set(_aida_c03_managed_runtime_sources
        "${AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT}/dotnet.exe"
        "${AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT}/LICENSE.txt"
        "${AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT}/ThirdPartyNotices.txt"
        "${AIDA_C03_MANAGED_RUNTIME_SOURCE_ROOT}/host/fxr/${AIDA_C03_MANAGED_RUNTIME_VERSION}/hostfxr.dll"
        ${_aida_c03_framework_runtime_files})
    add_custom_target(${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET}
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${_aida_c03_WORKER_EXECUTABLE}"
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedDecompilerWorker.exe"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${_aida_c03_PROVIDER_BINARY}"
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/ICSharpCode.Decompiler.dll"
        ${_aida_c03_runtime_commands}
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_MANAGED_RUNTIME_MATERIALIZER}"
            --repository-root "${AIDA_C03_DEPENDENCY_ROOT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --contract "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC}"
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_MANAGED_RUNTIME_MATERIALIZER}"
            --repository-root "${AIDA_C03_DEPENDENCY_ROOT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --contract "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC}"
            --verify-only
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_MANAGED_WORKER_MANIFEST_MATERIALIZER}"
            --contract "${AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --worker "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedDecompilerWorker.exe"
            --provider "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/ICSharpCode.Decompiler.dll"
            --runtime-manifest "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedRuntime.manifest.json"
            --runtime-manifest-digest "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedRuntime.manifest.sha256"
        COMMAND "${Python3_EXECUTABLE}" "${AIDA_C03_MANAGED_WORKER_MANIFEST_MATERIALIZER}"
            --contract "${AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT}"
            --package-root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            --worker "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedDecompilerWorker.exe"
            --provider "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/ICSharpCode.Decompiler.dll"
            --runtime-manifest "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedRuntime.manifest.json"
            --runtime-manifest-digest "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/deps/AiDA_ManagedRuntime.manifest.sha256"
            --verify-only
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy managed
            -WorkerManifestDigest "deps/AiDA_ManagedDecompilerWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/managed.acl.json"
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy managed
            -WorkerManifestDigest "deps/AiDA_ManagedDecompilerWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/managed.acl.json"
            -VerifyOnly
        DEPENDS
            "${_aida_c03_BUILD_TARGET}"
            ${_aida_c03_DEPENDS}
            "${AIDA_C03_MANAGED_WORKER_MANIFEST_MATERIALIZER}"
            "${AIDA_C03_MANAGED_WORKER_MANIFEST_CONTRACT}"
            "${AIDA_C03_MANAGED_WORKER_MANIFEST_SCHEMA}"
            "${AIDA_C03_MANAGED_WORKER_PACKAGES_LOCK}"
            "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SPEC}"
            "${AIDA_C03_MANAGED_RUNTIME_SOURCE_SCHEMA}"
            "${AIDA_C03_MANAGED_RUNTIME_MANIFEST_SCHEMA}"
            "${AIDA_C03_MANAGED_RUNTIME_MATERIALIZER}"
            "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            ${_aida_c03_managed_runtime_sources}
        VERBATIM)
    set(_aida_c03_outputs ${AIDA_C03_MANAGED_WORKER_PACKAGE_OUTPUTS} ${_aida_c03_runtime_outputs})
    set_target_properties(${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "managed-cli-decompiler-worker-manifest-v3"
        AIDA_C03_PACKAGE_OUTPUTS "${_aida_c03_outputs}"
        AIDA_C03_OFFLINE_RESTORE "locked-mode;local-source-only;no-machine-install"
        AIDA_C03_APP_LOCAL_RUNTIME "Microsoft.NETCore.App-${AIDA_C03_MANAGED_RUNTIME_VERSION};${AIDA_C03_MANAGED_RUNTIME_TFM};win-x64;exact-193-file-inventory"
        AIDA_C03_CUSTOMER_SDK_SHIPMENT "forbidden"
        AIDA_C03_FINAL_BYTE_ORDERING "offline-build;finalizers;copy-application;materialize-app-local-runtime;verify-runtime;manifest-v3;verify;appcontainer-acl;acl-receipt;verify-acl")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET "${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET}")
    set(AIDA_C03_MANAGED_WORKER_PACKAGE_OUTPUTS "${_aida_c03_outputs}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_analysis_python_worker_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "REQUIRE_STAGING" "APPLICATION_TARGET" "")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_APPLICATION_TARGET)
        message(FATAL_ERROR "AiDA C03 analysis Python worker package arguments are incomplete or malformed")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "analysis Python application")
    if(TARGET "${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET}" OR
       TARGET "${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 analysis Python worker package was registered more than once")
    endif()
    add_custom_target(${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET} SOURCES
        "${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE}"
        "${AIDA_C03_ANALYSIS_PYTHON_WORKER_STAGER}"
        "${AIDA_C03_WORKER_MANIFEST_LOCK}"
        "${AIDA_C03_WORKER_MANIFEST_SCHEMA}")
    set_target_properties(${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "analysis-python-worker-source-contract-v2"
        AIDA_C03_NETWORK_FETCH "forbidden"
        AIDA_C03_CAMOUFOX_RUNTIME_COUPLING "forbidden")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE "${AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE}")
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_ANALYSIS_PYTHON_WORKER_SHIPPED "${AIDA_C03_ANALYSIS_PYTHON_WORKER_SHIPPED}")
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_ANALYSIS_PYTHON_WORKER_BLOCKER "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
    if(NOT AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE)
        if(_aida_c03_REQUIRE_STAGING)
            message(FATAL_ERROR "AiDA C03 analysis Python worker staging is unavailable: ${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
        endif()
        message(STATUS "AiDA C03 analysis Python worker is unavailable and will not be shipped: ${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
        return()
    endif()
    _aida_c03_package_find_powershell(_aida_c03_powershell)
    add_custom_target(${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET}
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_ANALYSIS_PYTHON_WORKER_STAGER}"
            -RepositoryRoot "${AIDA_C03_DEPENDENCY_ROOT}"
            -OutputDirectory "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Force
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy analysis_python
            -WorkerManifestDigest "deps/AiDA_AnalysisPythonWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.acl.json"
        COMMAND "${_aida_c03_powershell}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
            -PackageRoot "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>"
            -Policy analysis_python
            -WorkerManifestDigest "deps/AiDA_AnalysisPythonWorker.manifest.sha256"
            -OutputReceipt "deps/evidence/analysis-python/AiDA_AnalysisPythonWorker.acl.json"
            -VerifyOnly
        DEPENDS
            ${AIDA_C03_ANALYSIS_PYTHON_WORKER_SOURCE_TARGET}
            "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT}"
            ${AIDA_C03_ANALYSIS_PYTHON_WORKER_RECEIPTS}
            "${AIDA_C03_ANALYSIS_PYTHON_WORKER_STAGER}"
            "${AIDA_C03_WORKER_MANIFEST_LOCK}"
            "${AIDA_C03_WORKER_RUNTIME_ACL_MATERIALIZER}"
        VERBATIM)
    set_target_properties(${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "analysis-python-worker-manifest-v1"
        AIDA_C03_PACKAGE_OUTPUTS "${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_OUTPUTS}"
        AIDA_C03_FINAL_BYTE_ORDERING "locked-prebuilt;signature;protector-receipts;copy;manifest;verify;appcontainer-acl;acl-receipt;verify-acl")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET "${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET}")
endfunction()

function(aida_c03_register_customer_notice_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "APPLICATION_TARGET" "")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_APPLICATION_TARGET)
        message(FATAL_ERROR "AiDA C03 customer notice package arguments are incomplete or malformed")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "customer notice application")
    if(TARGET "${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET}")
        message(FATAL_ERROR "AiDA C03 customer notice package was registered more than once")
    endif()
    set(_aida_c03_notice_commands)
    set(_aida_c03_notice_outputs)
    set(_aida_c03_notice_index 0)
    foreach(_aida_c03_notice_relative IN LISTS AIDA_C03_CUSTOMER_NOTICE_SOURCE_PATHS)
        set(_aida_c03_notice_source "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_notice_relative}")
        if(NOT EXISTS "${_aida_c03_notice_source}" OR IS_DIRECTORY "${_aida_c03_notice_source}")
            message(FATAL_ERROR "AiDA C03 customer notice source is missing: ${_aida_c03_notice_relative}")
        endif()
        get_filename_component(_aida_c03_notice_name "${_aida_c03_notice_relative}" NAME)
        string(REGEX REPLACE "[^A-Za-z0-9_.-]" "_" _aida_c03_notice_name "${_aida_c03_notice_name}")
        if(_aida_c03_notice_relative STREQUAL "licenses/c03/THIRD_PARTY_NOTICES.md")
            set(_aida_c03_notice_output "notices/THIRD_PARTY_NOTICES.md")
        else()
            set(_aida_c03_notice_output "notices/components/${_aida_c03_notice_index}-${_aida_c03_notice_name}")
        endif()
        list(APPEND _aida_c03_notice_commands
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${_aida_c03_notice_source}"
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/${_aida_c03_notice_output}")
        list(APPEND _aida_c03_notice_outputs "${_aida_c03_notice_output}")
        math(EXPR _aida_c03_notice_index "${_aida_c03_notice_index} + 1")
    endforeach()
    set(_aida_c03_managed_notice_index 0)
    foreach(_aida_c03_managed_notice IN LISTS AIDA_C03_MANAGED_PACKAGE_NOTICE_RECORDS)
        string(REPLACE "|" ";" _aida_c03_managed_notice_fields "${_aida_c03_managed_notice}")
        list(LENGTH _aida_c03_managed_notice_fields _aida_c03_managed_notice_field_count)
        if(NOT _aida_c03_managed_notice_field_count EQUAL 7)
            message(FATAL_ERROR "AiDA C03 managed package notice record is malformed")
        endif()
        list(GET _aida_c03_managed_notice_fields 0 _aida_c03_managed_archive)
        list(GET _aida_c03_managed_notice_fields 1 _aida_c03_managed_license_entry)
        list(GET _aida_c03_managed_notice_fields 2 _aida_c03_managed_license_output)
        list(GET _aida_c03_managed_notice_fields 3 _aida_c03_managed_license_sha256)
        list(GET _aida_c03_managed_notice_fields 4 _aida_c03_managed_third_party_entry)
        list(GET _aida_c03_managed_notice_fields 5 _aida_c03_managed_third_party_output)
        list(GET _aida_c03_managed_notice_fields 6 _aida_c03_managed_third_party_sha256)
        set(_aida_c03_managed_notice_root
            "${CMAKE_CURRENT_BINARY_DIR}/c03-managed-notices/${_aida_c03_managed_notice_index}")
        file(MAKE_DIRECTORY "${_aida_c03_managed_notice_root}")
        file(ARCHIVE_EXTRACT
            INPUT "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_managed_archive}"
            DESTINATION "${_aida_c03_managed_notice_root}"
            PATTERNS "${_aida_c03_managed_license_entry}" "${_aida_c03_managed_third_party_entry}")
        set(_aida_c03_managed_license_source
            "${_aida_c03_managed_notice_root}/${_aida_c03_managed_license_entry}")
        set(_aida_c03_managed_third_party_source
            "${_aida_c03_managed_notice_root}/${_aida_c03_managed_third_party_entry}")
        aida_c03_require_path_sha256("${_aida_c03_managed_license_source}"
            "${_aida_c03_managed_license_sha256}" "managed package license notice")
        aida_c03_require_path_sha256("${_aida_c03_managed_third_party_source}"
            "${_aida_c03_managed_third_party_sha256}" "managed package third-party notice")
        get_filename_component(_aida_c03_managed_license_directory
            "${_aida_c03_managed_license_output}" DIRECTORY)
        get_filename_component(_aida_c03_managed_third_party_directory
            "${_aida_c03_managed_third_party_output}" DIRECTORY)
        list(APPEND _aida_c03_notice_commands
            COMMAND "${CMAKE_COMMAND}" -E make_directory
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/${_aida_c03_managed_license_directory}"
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/${_aida_c03_managed_third_party_directory}"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${_aida_c03_managed_license_source}"
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/${_aida_c03_managed_license_output}"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${_aida_c03_managed_third_party_source}"
                "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/${_aida_c03_managed_third_party_output}")
        list(APPEND _aida_c03_notice_outputs
            "${_aida_c03_managed_license_output}"
            "${_aida_c03_managed_third_party_output}")
        math(EXPR _aida_c03_managed_notice_index "${_aida_c03_managed_notice_index} + 1")
    endforeach()
    if(_aida_c03_notice_index LESS 20)
        message(FATAL_ERROR "AiDA C03 customer notice inventory is incomplete")
    endif()
    if(NOT _aida_c03_managed_notice_index EQUAL 2)
        message(FATAL_ERROR "AiDA C03 managed customer notice inventory is incomplete")
    endif()
    add_custom_target(${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET}
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/notices"
            "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>/notices/components"
        ${_aida_c03_notice_commands}
        DEPENDS ${AIDA_C03_REQUIRED_PRODUCTION_INPUTS}
        VERBATIM)
    set_target_properties(${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET} PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "customer-production-license-notices"
        AIDA_C03_PACKAGE_OUTPUTS "${_aida_c03_notice_outputs}"
        AIDA_C03_EXCLUDES_BUILD_AND_EVIDENCE_ONLY_NOTICES "TRUE")
    add_dependencies("${_aida_c03_APPLICATION_TARGET}" ${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET})
    set_property(TARGET "${_aida_c03_APPLICATION_TARGET}" PROPERTY
        AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET "${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET}")
    set(AIDA_C03_CUSTOMER_NOTICE_PACKAGE_OUTPUTS "${_aida_c03_notice_outputs}" PARENT_SCOPE)
endfunction()

function(aida_c03_register_auxiliary_notice_package)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "" "TARGET;OUTPUT_ROOT" "")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_TARGET OR NOT _aida_c03_OUTPUT_ROOT OR TARGET "${_aida_c03_TARGET}")
        message(FATAL_ERROR "AiDA C03 auxiliary notice package arguments are incomplete, malformed, or duplicated")
    endif()
    set(_aida_c03_commands)
    set(_aida_c03_outputs)
    set(_aida_c03_index 0)
    foreach(_aida_c03_scope IN ITEMS build-only evidence-only)
        if(_aida_c03_scope STREQUAL "build-only")
            set(_aida_c03_sources ${AIDA_C03_BUILD_ONLY_NOTICE_SOURCE_PATHS})
        else()
            set(_aida_c03_sources ${AIDA_C03_EVIDENCE_ONLY_NOTICE_SOURCE_PATHS})
        endif()
        foreach(_aida_c03_relative IN LISTS _aida_c03_sources)
            set(_aida_c03_source "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_relative}")
            if(NOT EXISTS "${_aida_c03_source}" OR IS_DIRECTORY "${_aida_c03_source}")
                message(FATAL_ERROR "AiDA C03 auxiliary notice source is missing: ${_aida_c03_relative}")
            endif()
            get_filename_component(_aida_c03_name "${_aida_c03_relative}" NAME)
            string(REGEX REPLACE "[^A-Za-z0-9_.-]" "_" _aida_c03_name "${_aida_c03_name}")
            set(_aida_c03_output "${_aida_c03_scope}/${_aida_c03_index}-${_aida_c03_name}")
            list(APPEND _aida_c03_commands
                COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                    "${_aida_c03_source}" "${_aida_c03_OUTPUT_ROOT}/${_aida_c03_output}")
            list(APPEND _aida_c03_outputs "${_aida_c03_output}")
            math(EXPR _aida_c03_index "${_aida_c03_index} + 1")
        endforeach()
    endforeach()
    add_custom_target("${_aida_c03_TARGET}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${_aida_c03_OUTPUT_ROOT}/build-only"
            "${_aida_c03_OUTPUT_ROOT}/evidence-only"
        ${_aida_c03_commands}
        DEPENDS ${AIDA_C03_REQUIRED_BUILD_INPUTS} ${AIDA_C03_REQUIRED_EVIDENCE_INPUTS}
        VERBATIM)
    set_target_properties("${_aida_c03_TARGET}" PROPERTIES
        FOLDER "Evidence/C03"
        AIDA_C03_PACKAGE_ROLE "non-customer-build-and-evidence-notices"
        AIDA_C03_PACKAGE_OUTPUTS "${_aida_c03_outputs}"
        AIDA_C03_CUSTOMER_SHIPMENT "forbidden")
endfunction()

function(aida_c03_register_distribution_manifest)
    cmake_parse_arguments(PARSE_ARGV 0 _aida_c03 "REQUIRE_ANALYSIS_PYTHON" "TARGET;APPLICATION_TARGET;APPLICATION_ROOT;SOURCE_ROOT;DEVELOPER_ROOT;CUSTOMER_STAGE_ANCHOR;PACKAGE_ROOT;SPEC;OUTPUT_MANIFEST;OUTPUT_DIGEST;POWERSHELL_EXECUTABLE" "DEPENDS")
    if(_aida_c03_UNPARSED_ARGUMENTS OR _aida_c03_KEYWORDS_MISSING_VALUES OR
       NOT _aida_c03_TARGET OR NOT _aida_c03_APPLICATION_TARGET OR
       NOT _aida_c03_APPLICATION_ROOT OR NOT _aida_c03_SOURCE_ROOT OR
       NOT _aida_c03_DEVELOPER_ROOT OR NOT _aida_c03_CUSTOMER_STAGE_ANCHOR OR
       NOT _aida_c03_PACKAGE_ROOT OR NOT _aida_c03_SPEC OR
       NOT _aida_c03_OUTPUT_MANIFEST OR NOT _aida_c03_OUTPUT_DIGEST OR NOT _aida_c03_DEPENDS OR
       NOT _aida_c03_POWERSHELL_EXECUTABLE OR
       TARGET "${_aida_c03_TARGET}")
        message(FATAL_ERROR "AiDA C03 distribution manifest arguments are incomplete, malformed, or duplicated")
    endif()
    if(NOT _aida_c03_REQUIRE_ANALYSIS_PYTHON)
        message(FATAL_ERROR "AiDA C03 distribution requires the complete three-worker inventory")
    endif()
    _aida_c03_package_require_target("${_aida_c03_APPLICATION_TARGET}" "distribution application")
    _aida_c03_package_require_dependency_targets("distribution manifest" ${_aida_c03_DEPENDS})
    if(NOT EXISTS "${_aida_c03_SPEC}" OR IS_DIRECTORY "${_aida_c03_SPEC}")
        message(FATAL_ERROR "AiDA C03 distribution specification is missing: ${_aida_c03_SPEC}")
    endif()
    file(READ "${_aida_c03_SPEC}" _aida_c03_spec_json LIMIT 16777216)
    string(JSON _aida_c03_spec_type ERROR_VARIABLE _aida_c03_spec_error TYPE "${_aida_c03_spec_json}")
    string(JSON _aida_c03_spec_schema ERROR_VARIABLE _aida_c03_spec_schema_error GET "${_aida_c03_spec_json}" schema)
    string(JSON _aida_c03_spec_version ERROR_VARIABLE _aida_c03_spec_version_error GET "${_aida_c03_spec_json}" schema_version)
    string(TOLOWER "${_aida_c03_spec_json}" _aida_c03_spec_lower)
    if(NOT _aida_c03_spec_error STREQUAL "NOTFOUND" OR NOT _aida_c03_spec_type STREQUAL "OBJECT" OR
       NOT _aida_c03_spec_schema_error STREQUAL "NOTFOUND" OR
       NOT _aida_c03_spec_version_error STREQUAL "NOTFOUND" OR
       NOT _aida_c03_spec_schema STREQUAL "aida.c03.distribution-manifest-spec" OR
       NOT _aida_c03_spec_version EQUAL 2 OR
       _aida_c03_spec_lower MATCHES "(https?|ftp|git|ssh|file|ws|wss)://")
        message(FATAL_ERROR "AiDA C03 distribution specification is malformed, remote, or downgraded")
    endif()
    _aida_c03_package_require_distinct_paths("${_aida_c03_OUTPUT_MANIFEST}" "${_aida_c03_OUTPUT_DIGEST}" "distribution manifest/digest")
    set(_aida_c03_expected_source_root "$<TARGET_FILE_DIR:${_aida_c03_APPLICATION_TARGET}>")
    set(_aida_c03_expected_package_root "${_aida_c03_CUSTOMER_STAGE_ANCHOR}/$<CONFIG>")
    if(NOT _aida_c03_SOURCE_ROOT STREQUAL _aida_c03_expected_source_root OR
       NOT _aida_c03_PACKAGE_ROOT STREQUAL _aida_c03_expected_package_root)
        message(FATAL_ERROR "AiDA C03 distribution must stage from the exact application target into the exact detached customer root")
    endif()
    foreach(_aida_c03_literal_root IN ITEMS
            "${_aida_c03_APPLICATION_ROOT}"
            "${_aida_c03_DEVELOPER_ROOT}"
            "${_aida_c03_CUSTOMER_STAGE_ANCHOR}")
        string(FIND "${_aida_c03_literal_root}" "$<" _aida_c03_literal_generator_expression)
        if(NOT _aida_c03_literal_generator_expression EQUAL -1 OR
           NOT IS_ABSOLUTE "${_aida_c03_literal_root}" OR
           NOT IS_DIRECTORY "${_aida_c03_literal_root}" OR
           IS_SYMLINK "${_aida_c03_literal_root}")
            message(FATAL_ERROR "AiDA C03 application, developer, and customer roots must be existing literal absolute non-reparse directories")
        endif()
    endforeach()
    foreach(_aida_c03_pair IN ITEMS
            "${_aida_c03_APPLICATION_ROOT}|${_aida_c03_DEVELOPER_ROOT}"
            "${_aida_c03_APPLICATION_ROOT}|${_aida_c03_CUSTOMER_STAGE_ANCHOR}"
            "${_aida_c03_DEVELOPER_ROOT}|${_aida_c03_CUSTOMER_STAGE_ANCHOR}")
        string(REPLACE "|" ";" _aida_c03_pair_fields "${_aida_c03_pair}")
        list(GET _aida_c03_pair_fields 0 _aida_c03_left)
        list(GET _aida_c03_pair_fields 1 _aida_c03_right)
        cmake_path(IS_PREFIX _aida_c03_left "${_aida_c03_right}" NORMALIZE _aida_c03_left_contains_right)
        cmake_path(IS_PREFIX _aida_c03_right "${_aida_c03_left}" NORMALIZE _aida_c03_right_contains_left)
        if(_aida_c03_left_contains_right OR _aida_c03_right_contains_left)
            message(FATAL_ERROR "AiDA C03 application, developer, and customer roots must not equal, contain, or descend from one another")
        endif()
    endforeach()
    if(NOT EXISTS "${_aida_c03_POWERSHELL_EXECUTABLE}" OR
       IS_DIRECTORY "${_aida_c03_POWERSHELL_EXECUTABLE}" OR
       IS_SYMLINK "${_aida_c03_POWERSHELL_EXECUTABLE}")
        message(FATAL_ERROR "AiDA C03 distribution requires the validated system PowerShell executable")
    endif()
    foreach(_aida_c03_output IN ITEMS "${_aida_c03_OUTPUT_MANIFEST}" "${_aida_c03_OUTPUT_DIGEST}")
        string(FIND "${_aida_c03_output}" "$<" _aida_c03_output_generator_expression)
        if(NOT _aida_c03_output_generator_expression EQUAL -1 OR
           NOT IS_ABSOLUTE "${_aida_c03_output}")
            message(FATAL_ERROR "AiDA C03 distribution manifest and digest outputs must be literal absolute paths")
        endif()
    endforeach()
    foreach(_aida_c03_detached IN ITEMS "${_aida_c03_OUTPUT_MANIFEST}" "${_aida_c03_OUTPUT_DIGEST}")
        get_filename_component(_aida_c03_detached_absolute "${_aida_c03_detached}" ABSOLUTE)
        foreach(_aida_c03_root IN ITEMS
                "${_aida_c03_APPLICATION_ROOT}"
                "${_aida_c03_DEVELOPER_ROOT}"
                "${_aida_c03_CUSTOMER_STAGE_ANCHOR}")
            cmake_path(IS_PREFIX _aida_c03_root "${_aida_c03_detached_absolute}"
                NORMALIZE _aida_c03_detached_inside_root)
            if(_aida_c03_detached_inside_root)
                message(FATAL_ERROR "AiDA C03 distribution evidence must remain outside application, developer, and customer inventory roots")
            endif()
        endforeach()
    endforeach()
    if(NOT AIDA_C03_ANALYSIS_PYTHON_WORKER_AVAILABLE OR
       NOT TARGET "${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET}")
        add_custom_target("${_aida_c03_TARGET}"
            COMMAND "${CMAKE_COMMAND}"
                "-DAIDA_C03_DISTRIBUTION_BLOCKER=${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}"
                -P "${AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT}"
            DEPENDS
                ${_aida_c03_DEPENDS}
                "${_aida_c03_SPEC}"
                "${AIDA_C03_DISTRIBUTION_BLOCKER_SCRIPT}"
            VERBATIM)
        set_target_properties("${_aida_c03_TARGET}" PROPERTIES
            FOLDER "Packaging/C03"
            AIDA_C03_PACKAGE_ROLE "mandatory-three-worker-distribution-blocked"
            AIDA_C03_DISTRIBUTION_AVAILABLE "FALSE"
            AIDA_C03_DISTRIBUTION_BLOCKER "${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}"
            AIDA_C03_WORKER_CARDINALITY "3"
            AIDA_C03_EXPLICIT_INVOCATION_REQUIRED "TRUE")
        set(AIDA_C03_DISTRIBUTION_MANIFEST_TARGET "${_aida_c03_TARGET}" PARENT_SCOPE)
        set(AIDA_C03_DISTRIBUTION_MANIFEST_OUTPUT "${_aida_c03_OUTPUT_MANIFEST}" PARENT_SCOPE)
        set(AIDA_C03_DISTRIBUTION_MANIFEST_DIGEST_OUTPUT "${_aida_c03_OUTPUT_DIGEST}" PARENT_SCOPE)
        message(STATUS "AiDA C03 explicit distribution target is fail-closed: ${AIDA_C03_ANALYSIS_PYTHON_WORKER_ARTIFACT_BLOCKER}")
        return()
    endif()
    foreach(_aida_c03_required_target IN ITEMS
            "${AIDA_C03_GHIDRA_SPEC_PACKAGE_TARGET}"
            "${AIDA_C03_NATIVE_WORKER_PACKAGE_TARGET}"
            "${AIDA_C03_MANAGED_WORKER_PACKAGE_TARGET}"
            "${AIDA_C03_ANALYSIS_PYTHON_WORKER_PACKAGE_TARGET}"
            "${AIDA_C03_CUSTOMER_NOTICE_PACKAGE_TARGET}")
        _aida_c03_package_require_target("${_aida_c03_required_target}" "complete distribution input")
    endforeach()
    get_filename_component(_aida_c03_manifest_directory "${_aida_c03_OUTPUT_MANIFEST}" DIRECTORY)
    get_filename_component(_aida_c03_digest_directory "${_aida_c03_OUTPUT_DIGEST}" DIRECTORY)
    add_custom_target("${_aida_c03_TARGET}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${_aida_c03_CUSTOMER_STAGE_ANCHOR}"
            "${_aida_c03_manifest_directory}"
            "${_aida_c03_digest_directory}"
        COMMAND "${_aida_c03_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${AIDA_C03_DISTRIBUTION_MANIFEST_MATERIALIZER}"
            -PackageRoot "${_aida_c03_PACKAGE_ROOT}"
            -SourceRoot "${_aida_c03_SOURCE_ROOT}"
            -CustomerStageAnchor "${_aida_c03_CUSTOMER_STAGE_ANCHOR}"
            -StageCustomerPackage
            -Spec "${_aida_c03_SPEC}"
            -AuthorityLock "${AIDA_C03_WORKER_MANIFEST_LOCK}"
            -OutputManifest "${_aida_c03_OUTPUT_MANIFEST}"
            -OutputDigest "${_aida_c03_OUTPUT_DIGEST}"
            -Force
        DEPENDS
            ${_aida_c03_DEPENDS}
            "${_aida_c03_SPEC}"
            "${AIDA_C03_DISTRIBUTION_MANIFEST_MATERIALIZER}"
            "${AIDA_C03_DISTRIBUTION_MANIFEST_SCHEMA}"
            "${AIDA_C03_WORKER_MANIFEST_LOCK}"
        VERBATIM)
    set_target_properties("${_aida_c03_TARGET}" PROPERTIES
        FOLDER "Packaging/C03"
        AIDA_C03_PACKAGE_ROLE "detached-exact-distribution-manifest-v2"
        AIDA_C03_PACKAGE_ROOT "${_aida_c03_PACKAGE_ROOT}"
        AIDA_C03_PACKAGE_SOURCE_ROOT "${_aida_c03_SOURCE_ROOT}"
        AIDA_C03_APPLICATION_ROOT "${_aida_c03_APPLICATION_ROOT}"
        AIDA_C03_DEVELOPER_ROOT "${_aida_c03_DEVELOPER_ROOT}"
        AIDA_C03_CUSTOMER_STAGE_ANCHOR "${_aida_c03_CUSTOMER_STAGE_ANCHOR}"
        AIDA_C03_SANITIZED_CUSTOMER_STAGE "TRUE"
        AIDA_C03_PACKAGE_OUTPUTS "${_aida_c03_OUTPUT_MANIFEST};${_aida_c03_OUTPUT_DIGEST}"
        AIDA_C03_WORKER_CARDINALITY "3"
        AIDA_C03_DISTRIBUTION_AVAILABLE "TRUE"
        AIDA_C03_EXPLICIT_INVOCATION_REQUIRED "TRUE"
        AIDA_C03_EXACT_INVENTORY "TRUE"
        AIDA_C03_FILELESS_LAUNCH "forbidden"
        AIDA_C03_RAW_STANDALONE_DOWNLOAD "forbidden"
        AIDA_C03_ONLY_SUPPORTED_BROWSER "camoufox")
    set(AIDA_C03_DISTRIBUTION_MANIFEST_TARGET "${_aida_c03_TARGET}" PARENT_SCOPE)
    set(AIDA_C03_DISTRIBUTION_MANIFEST_OUTPUT "${_aida_c03_OUTPUT_MANIFEST}" PARENT_SCOPE)
    set(AIDA_C03_DISTRIBUTION_MANIFEST_DIGEST_OUTPUT "${_aida_c03_OUTPUT_DIGEST}" PARENT_SCOPE)
endfunction()
