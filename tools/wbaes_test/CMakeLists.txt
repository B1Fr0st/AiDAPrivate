add_executable(WBAES_TEST
    wbaes_test.cpp
    wbaes_payload_c.c
)

target_include_directories(WBAES_TEST PRIVATE
    "${CMAKE_BINARY_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/standalone/src/core/anti-tamper"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src/standalone/src/core"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/protector"
)

target_compile_definitions(WBAES_TEST PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_compile_options(WBAES_TEST PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:/W3>
    $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    $<$<COMPILE_LANGUAGE:CXX>:/MD>
    $<$<COMPILE_LANGUAGE:CXX>:/std:c++17>
    $<$<COMPILE_LANGUAGE:C>:/W3>
    $<$<COMPILE_LANGUAGE:C>:/MD>
)

target_link_libraries(WBAES_TEST PRIVATE bcrypt)

set_target_properties(WBAES_TEST PROPERTIES
    OUTPUT_NAME "WBAES_TEST"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
)
