cmake_minimum_required(VERSION 3.20)

if(NOT WIN32)
    return()
endif()

option(BUILD_OVERLAP_TEST "Build the Phase 4 overlap (jump-in-the-middle) regression test" ON)

if(NOT BUILD_OVERLAP_TEST)
    return()
endif()

if(NOT TARGET asmjit)
    message(STATUS "OVERLAP_TEST: asmjit target unavailable, skipping")
    return()
endif()

if(NOT TARGET Zydis)
    message(STATUS "OVERLAP_TEST: Zydis target unavailable, skipping")
    return()
endif()

if(NOT EXISTS "${CMAKE_BINARY_DIR}/generated/payload_blob.hpp")
    message(STATUS "OVERLAP_TEST: payload_blob.hpp not yet generated, target will require AiDAPayloadBlob")
endif()

add_executable(OVERLAP_TEST
    "${CMAKE_CURRENT_SOURCE_DIR}/overlap_test.cpp"
)

target_include_directories(OVERLAP_TEST PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/tools/protector"
    "${CMAKE_BINARY_DIR}/generated"
    "${CMAKE_SOURCE_DIR}/libs/asmjit"
    "${CMAKE_SOURCE_DIR}/.deps/zydis/include"
    "${CMAKE_SOURCE_DIR}/.deps/zydis/dependencies/zycore/include"
)

target_compile_definitions(OVERLAP_TEST PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(OVERLAP_TEST PRIVATE
        /W3 /EHsc /permissive- /Zc:__cplusplus /Zp8 /MD /bigobj
    )
endif()

set_target_properties(OVERLAP_TEST PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    OUTPUT_NAME "OVERLAP_TEST"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
)

target_link_libraries(OVERLAP_TEST PRIVATE
    asmjit
    Zydis
    kernel32
)

if(TARGET AiDAPayloadBlob AND NOT EXISTS "${CMAKE_BINARY_DIR}/generated/payload_blob.hpp")
    add_dependencies(OVERLAP_TEST AiDAPayloadBlob)
endif()
