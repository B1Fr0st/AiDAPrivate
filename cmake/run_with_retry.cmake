cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED RETRY_CMD)
    message(FATAL_ERROR "run_with_retry: RETRY_CMD not set")
endif()
if(NOT DEFINED RETRY_LABEL)
    set(RETRY_LABEL "command")
endif()

set(_aida_retry_backoffs "0.4;0.8;1.5;2.5;4.0")
list(LENGTH _aida_retry_backoffs _aida_retry_count)
math(EXPR _aida_max_attempts "${_aida_retry_count} + 1")

set(_aida_attempt 1)
while(TRUE)
    execute_process(
        COMMAND ${RETRY_CMD}
        RESULT_VARIABLE _aida_result
    )
    if(_aida_result EQUAL 0)
        if(_aida_attempt GREATER 1)
            message(STATUS "run_with_retry: ${RETRY_LABEL} succeeded on attempt ${_aida_attempt}")
        endif()
        return()
    endif()
    if(_aida_attempt GREATER_EQUAL _aida_max_attempts)
        message(FATAL_ERROR "run_with_retry: ${RETRY_LABEL} failed after ${_aida_attempt} attempts (last exit ${_aida_result})")
    endif()
    math(EXPR _aida_idx "${_aida_attempt} - 1")
    list(GET _aida_retry_backoffs ${_aida_idx} _aida_delay)
    message(STATUS "run_with_retry: ${RETRY_LABEL} attempt ${_aida_attempt} failed (exit ${_aida_result}); waiting ${_aida_delay}s before retry (transient file lock — Defender/indexer/AV)")
    execute_process(COMMAND ${CMAKE_COMMAND} -E sleep ${_aida_delay})
    math(EXPR _aida_attempt "${_aida_attempt} + 1")
endwhile()
