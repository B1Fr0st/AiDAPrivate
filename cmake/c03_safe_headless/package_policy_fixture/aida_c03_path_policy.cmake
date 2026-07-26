include_guard(GLOBAL)

function(_aida_c03_validate_raw_windows_path_shape input_path descriptor)
    string(LENGTH "${input_path}" _aida_c03_input_length)
    if(NOT ARGC EQUAL 2 OR _aida_c03_input_length LESS 3 OR
       _aida_c03_input_length GREATER 32767 OR NOT input_path OR input_path MATCHES ";" OR
       input_path MATCHES "\\\\" OR NOT input_path MATCHES "^[A-Z]:/" OR
       input_path MATCHES "//" OR input_path MATCHES "(^|/)\\.(/|$)" OR
       input_path MATCHES "(^|/)\\.\\.(/|$)" OR
       input_path MATCHES "(^|/)[^/]*[. ](/|$)" OR
       input_path MATCHES "/[^/]*:" OR input_path MATCHES "[^ -~]" OR
       input_path MATCHES "/$")
        message(WARNING "AiDA C03 ${descriptor} must use an exact uppercase-drive canonical forward-slash path: ${input_path}")
    endif()
endfunction()

function(aida_c03_validate_canonical_regular_file output_path output_sha256 input_path descriptor)
    if(NOT ARGC EQUAL 4)
        message(WARNING "AiDA C03 canonical regular-file validation arguments are malformed")
    endif()
    _aida_c03_validate_raw_windows_path_shape("${input_path}" "${descriptor}")
    if(NOT EXISTS "${input_path}" OR IS_DIRECTORY "${input_path}" OR IS_SYMLINK "${input_path}")
        message(WARNING "AiDA C03 ${descriptor} must be an existing non-reparse regular file: ${input_path}")
        set(${output_path} "${input_path}" PARENT_SCOPE)
        set(${output_sha256} "" PARENT_SCOPE)
        return()
    endif()
    file(REAL_PATH "${input_path}" _aida_c03_real_path)
    file(TO_CMAKE_PATH "${_aida_c03_real_path}" _aida_c03_real_path)
    if(NOT input_path STREQUAL _aida_c03_real_path)
        message(WARNING "AiDA C03 ${descriptor} path case, spelling, or final identity is noncanonical: ${input_path}")
    endif()
    file(SHA256 "${input_path}" _aida_c03_sha256)
    string(TOUPPER "${_aida_c03_sha256}" _aida_c03_sha256)
    set(${output_path} "${input_path}" PARENT_SCOPE)
    set(${output_sha256} "${_aida_c03_sha256}" PARENT_SCOPE)
endfunction()

function(aida_c03_validate_canonical_directory output_path input_path descriptor)
    if(NOT ARGC EQUAL 3)
        message(WARNING "AiDA C03 canonical directory validation arguments are malformed")
    endif()
    _aida_c03_validate_raw_windows_path_shape("${input_path}" "${descriptor}")
    if(NOT EXISTS "${input_path}" OR NOT IS_DIRECTORY "${input_path}" OR IS_SYMLINK "${input_path}")
        message(WARNING "AiDA C03 ${descriptor} must be an existing non-reparse directory: ${input_path}")
        set(${output_path} "${input_path}" PARENT_SCOPE)
        return()
    endif()
    file(REAL_PATH "${input_path}" _aida_c03_real_path)
    file(TO_CMAKE_PATH "${_aida_c03_real_path}" _aida_c03_real_path)
    if(NOT input_path STREQUAL _aida_c03_real_path)
        message(WARNING "AiDA C03 ${descriptor} path case, spelling, or final identity is noncanonical: ${input_path}")
    endif()
    set(${output_path} "${input_path}" PARENT_SCOPE)
endfunction()

function(aida_c03_validate_no_reparse_chain powershell_executable policy_script input_path descriptor)
    if(NOT ARGC EQUAL 4)
        message(WARNING "AiDA C03 reparse-chain validation arguments are malformed")
    endif()
    _aida_c03_validate_raw_windows_path_shape("${powershell_executable}" "system PowerShell")
    _aida_c03_validate_raw_windows_path_shape("${policy_script}" "path-identity policy")
    _aida_c03_validate_raw_windows_path_shape("${input_path}" "${descriptor}")
    execute_process(
        COMMAND "${powershell_executable}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${policy_script}" -Path "${input_path}"
        RESULT_VARIABLE _aida_c03_result
        OUTPUT_VARIABLE _aida_c03_final_path
        ERROR_VARIABLE _aida_c03_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_STRIP_TRAILING_WHITESPACE)
    file(TO_CMAKE_PATH "${_aida_c03_final_path}" _aida_c03_final_path)
    if(NOT _aida_c03_result EQUAL 0 OR NOT _aida_c03_final_path STREQUAL input_path)
        message(WARNING "AiDA C03 ${descriptor} contains a reparse transition or noncanonical final spelling: ${input_path} ${_aida_c03_error}")
    endif()
endfunction()

function(aida_c03_require_detached_roots repository_root binary_root source_root
         application_root developer_root customer_root evidence_root stage_owner_root)
    if(NOT ARGC EQUAL 8)
        message(WARNING "AiDA C03 detached-root validation arguments are malformed")
    endif()
    foreach(_aida_c03_input_root IN ITEMS "${repository_root}" "${binary_root}" "${source_root}")
        _aida_c03_validate_raw_windows_path_shape("${_aida_c03_input_root}" "detached input root")
        if(NOT IS_DIRECTORY "${_aida_c03_input_root}" OR IS_SYMLINK "${_aida_c03_input_root}")
            message(WARNING "AiDA C03 detached input root must be an existing non-reparse directory: ${_aida_c03_input_root}")
        endif()
        file(REAL_PATH "${_aida_c03_input_root}" _aida_c03_real_input_root)
        file(TO_CMAKE_PATH "${_aida_c03_real_input_root}" _aida_c03_real_input_root)
        if(NOT _aida_c03_real_input_root STREQUAL _aida_c03_input_root)
            message(WARNING "AiDA C03 detached input root has noncanonical case or final spelling: ${_aida_c03_input_root}")
        endif()
    endforeach()
    foreach(_aida_c03_root IN ITEMS
            "${application_root}" "${developer_root}" "${customer_root}"
            "${evidence_root}" "${stage_owner_root}")
        _aida_c03_validate_raw_windows_path_shape("${_aida_c03_root}" "detached root")
        if(NOT IS_DIRECTORY "${_aida_c03_root}" OR IS_SYMLINK "${_aida_c03_root}")
            message(WARNING "AiDA C03 detached root must be an existing non-reparse directory: ${_aida_c03_root}")
        endif()
        file(REAL_PATH "${_aida_c03_root}" _aida_c03_real_root)
        file(TO_CMAKE_PATH "${_aida_c03_real_root}" _aida_c03_real_root)
        if(NOT _aida_c03_real_root STREQUAL _aida_c03_root)
            message(WARNING "AiDA C03 detached root has noncanonical case or final spelling: ${_aida_c03_root}")
        endif()
    endforeach()
    if(DEFINED ENV{TEMP} AND IS_DIRECTORY "$ENV{TEMP}")
        file(REAL_PATH "$ENV{TEMP}" _aida_c03_temp_root)
        file(TO_CMAKE_PATH "${_aida_c03_temp_root}" _aida_c03_temp_root)
        foreach(_aida_c03_non_temp_root IN ITEMS
                "${application_root}" "${developer_root}" "${customer_root}"
                "${evidence_root}" "${stage_owner_root}")
            cmake_path(IS_PREFIX _aida_c03_temp_root "${_aida_c03_non_temp_root}"
                NORMALIZE _aida_c03_root_inside_temp)
            if(_aida_c03_root_inside_temp)
                message(WARNING "AiDA C03 stage roots must remain outside TEMP: ${_aida_c03_non_temp_root}")
            endif()
        endforeach()
    endif()
    foreach(_aida_c03_stage_root IN ITEMS
            "${application_root}" "${developer_root}" "${customer_root}"
            "${evidence_root}" "${stage_owner_root}")
        foreach(_aida_c03_input_root IN ITEMS
                "${repository_root}" "${binary_root}" "${source_root}")
            cmake_path(IS_PREFIX _aida_c03_input_root "${_aida_c03_stage_root}"
                NORMALIZE _aida_c03_stage_inside_input)
            cmake_path(IS_PREFIX _aida_c03_stage_root "${_aida_c03_input_root}"
                NORMALIZE _aida_c03_input_inside_stage)
            if(_aida_c03_stage_inside_input OR _aida_c03_input_inside_stage)
                message(WARNING "AiDA C03 stage roots must remain detached from repository, binary, and application source roots: ${_aida_c03_stage_root} ${_aida_c03_input_root}")
            endif()
        endforeach()
    endforeach()
    foreach(_aida_c03_pair IN ITEMS
            "${application_root}|${developer_root}"
            "${application_root}|${customer_root}"
            "${application_root}|${evidence_root}"
            "${developer_root}|${customer_root}"
            "${developer_root}|${evidence_root}"
            "${customer_root}|${evidence_root}")
        string(REPLACE "|" ";" _aida_c03_pair_fields "${_aida_c03_pair}")
        list(GET _aida_c03_pair_fields 0 _aida_c03_left)
        list(GET _aida_c03_pair_fields 1 _aida_c03_right)
        cmake_path(IS_PREFIX _aida_c03_left "${_aida_c03_right}" NORMALIZE _aida_c03_left_contains_right)
        cmake_path(IS_PREFIX _aida_c03_right "${_aida_c03_left}" NORMALIZE _aida_c03_right_contains_left)
        if(_aida_c03_left_contains_right OR _aida_c03_right_contains_left)
            message(WARNING "AiDA C03 application, developer, customer, and evidence roots must be pairwise detached: ${_aida_c03_left} ${_aida_c03_right}")
        endif()
    endforeach()
    foreach(_aida_c03_child IN ITEMS
            "${application_root}" "${developer_root}" "${customer_root}" "${evidence_root}")
        cmake_path(IS_PREFIX stage_owner_root "${_aida_c03_child}" NORMALIZE _aida_c03_owned_child)
        if(NOT _aida_c03_owned_child OR _aida_c03_child STREQUAL stage_owner_root)
            message(WARNING "AiDA C03 stage subroot is not owned by the exact stage authority: ${_aida_c03_child}")
        endif()
    endforeach()
endfunction()
