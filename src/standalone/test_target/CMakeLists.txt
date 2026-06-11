cmake_minimum_required(VERSION 3.20)

if(NOT WIN32)
    return()
endif()

option(BUILD_AIDA_TEST_TARGET "Build the AiDA test target CLI application" ON)

if(NOT BUILD_AIDA_TEST_TARGET)
    return()
endif()

add_executable(AiDA_TestTarget
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_log.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/memory_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/thread_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/struct_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/exception_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/debug_surface_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/file_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/module_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/http_server_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/traffic_generator.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/resident_state.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/re_domain_fixtures.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/protocol_re_tests.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/protected_re_fixtures.cpp"
)

target_include_directories(AiDA_TestTarget PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_definitions(AiDA_TestTarget PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(AiDA_TestTarget PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:/W3>
        $<$<COMPILE_LANGUAGE:C,CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:C,CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zp8>
        $<$<COMPILE_LANGUAGE:C,CXX>:/MD>
    )
endif()

set_target_properties(AiDA_TestTarget PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    OUTPUT_NAME "AiDA_TestTarget"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
)

target_link_libraries(AiDA_TestTarget PRIVATE
    kernel32
    ws2_32
    user32
    ntdll
)

set(AIDA_TARGET_PROTOCOL_FIXTURE_DIR "${CMAKE_BINARY_DIR}/test_binaries/target_protocol")

add_executable(AiDA_TargetProtocolFixture
    "${CMAKE_CURRENT_SOURCE_DIR}/target_protocol_fixture.cpp"
)

target_compile_definitions(AiDA_TargetProtocolFixture PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

if(MSVC)
    target_compile_options(AiDA_TargetProtocolFixture PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:/W4>
        $<$<COMPILE_LANGUAGE:C,CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:C,CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zp8>
        $<$<COMPILE_LANGUAGE:C,CXX>:/MD>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Zi>
    )

    target_link_options(AiDA_TargetProtocolFixture PRIVATE
        /DEBUG:FULL
        /PDBALTPATH:none
        /INCREMENTAL:NO
    )
endif()

set_target_properties(AiDA_TargetProtocolFixture PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    OUTPUT_NAME "target_protocol"
    RUNTIME_OUTPUT_DIRECTORY "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    PDB_NAME "target_protocol"
    PDB_NAME_RELEASE "target_protocol"
    PDB_NAME_DEBUG "target_protocol"
    PDB_NAME_RELWITHDEBINFO "target_protocol"
    PDB_OUTPUT_DIRECTORY "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    PDB_OUTPUT_DIRECTORY_RELEASE "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    PDB_OUTPUT_DIRECTORY_DEBUG "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    COMPILE_PDB_NAME "target_protocol_compile"
    COMPILE_PDB_NAME_RELEASE "target_protocol_compile"
    COMPILE_PDB_NAME_DEBUG "target_protocol_compile"
    COMPILE_PDB_NAME_RELWITHDEBINFO "target_protocol_compile"
    COMPILE_PDB_OUTPUT_DIRECTORY "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    COMPILE_PDB_OUTPUT_DIRECTORY_RELEASE "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    COMPILE_PDB_OUTPUT_DIRECTORY_DEBUG "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
    COMPILE_PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${AIDA_TARGET_PROTOCOL_FIXTURE_DIR}"
)
