if(NOT WIN32 OR NOT MSVC)
    return()
endif()

add_executable(aida_share_fingerprint_baker main.cpp)

target_compile_options(aida_share_fingerprint_baker PRIVATE
    /std:c++17
    /W3
    /EHsc
    /O2
    /MD
    /Zc:__cplusplus
    /permissive-
)

target_compile_definitions(aida_share_fingerprint_baker PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

target_link_libraries(aida_share_fingerprint_baker PRIVATE
    imagehlp
    bcrypt
)

set_target_properties(aida_share_fingerprint_baker PROPERTIES
    OUTPUT_NAME "aida_share_fingerprint_baker"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
)
