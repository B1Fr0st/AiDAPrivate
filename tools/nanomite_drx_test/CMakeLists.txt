cmake_minimum_required(VERSION 3.20)

if(NOT WIN32)
    return()
endif()

option(BUILD_NANOMITE_DRX_TEST "Build the DR0-DR3 nanomite hardware-breakpoint regression test" ON)

if(NOT BUILD_NANOMITE_DRX_TEST)
    return()
endif()

add_executable(NANOMITE_DRX_TEST
    "${CMAKE_CURRENT_SOURCE_DIR}/nanomite_drx_test.cpp"
)

target_include_directories(NANOMITE_DRX_TEST PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/src/standalone/src/core/anti-tamper"
)

target_compile_definitions(NANOMITE_DRX_TEST PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(NANOMITE_DRX_TEST PRIVATE
        /W3 /EHsc /permissive- /Zc:__cplusplus /Zp8 /MD
    )
endif()

set_target_properties(NANOMITE_DRX_TEST PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    OUTPUT_NAME "NANOMITE_DRX_TEST"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
)

target_link_libraries(NANOMITE_DRX_TEST PRIVATE
    kernel32
)
