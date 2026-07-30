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

