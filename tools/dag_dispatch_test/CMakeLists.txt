cmake_minimum_required(VERSION 3.20)

if(NOT WIN32)
    return()
endif()

option(BUILD_DAG_DISPATCH_TEST "Build the DAG-based VM dispatcher regression test" ON)

if(NOT BUILD_DAG_DISPATCH_TEST)
    return()
endif()

add_executable(DAG_DISPATCH_TEST
    "${CMAKE_CURRENT_SOURCE_DIR}/dag_dispatch_test.cpp"
    "${CMAKE_SOURCE_DIR}/src/shared/hardware_id/hardware_id_v2.cpp"
)

target_include_directories(DAG_DISPATCH_TEST PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/src/standalone/src/core/anti-tamper"
    "${CMAKE_SOURCE_DIR}/src/standalone/src/core"
    "${CMAKE_SOURCE_DIR}/src/standalone/src/core/arc"
    "${CMAKE_SOURCE_DIR}/src/standalone/src/helpers"
    "${CMAKE_SOURCE_DIR}/src/standalone/src"
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/src/shared"
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_BINARY_DIR}/generated"
)

target_compile_definitions(DAG_DISPATCH_TEST PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    AIDA_DAG_DISPATCH_TEST
    ATP_JIT_DISABLED
)

if(MSVC)
    target_compile_options(DAG_DISPATCH_TEST PRIVATE
        /W3 /EHsc /permissive- /Zc:__cplusplus /Zp8 /MD /bigobj
    )
endif()

set_target_properties(DAG_DISPATCH_TEST PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    OUTPUT_NAME "DAG_DISPATCH_TEST"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
)

if(TARGET aida_openssl_ssl)
    target_link_libraries(DAG_DISPATCH_TEST PRIVATE aida_openssl_ssl aida_openssl_crypto)
endif()

if(TARGET Zydis)
    target_link_libraries(DAG_DISPATCH_TEST PRIVATE Zydis)
endif()

target_link_libraries(DAG_DISPATCH_TEST PRIVATE
    kernel32
    bcrypt
    advapi32
    user32
    ws2_32
    crypt32
    gdi32
)
