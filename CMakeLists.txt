cmake_minimum_required(VERSION 3.21)

project(AiDA
    VERSION   1.2.8
    LANGUAGES CXX ASM_MASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- Zydis disassembler engine (static) ---
include(FetchContent)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(zydis)

# Zycore adds /wd4201 as PUBLIC which leaks into MASM targets causing A4018 warnings.
# Change it to a CXX-only generator expression so it doesn't affect ASM_MASM sources.
if(MSVC AND TARGET Zycore)
    get_target_property(_zycore_opts Zycore INTERFACE_COMPILE_OPTIONS)
    if(_zycore_opts)
        list(REMOVE_ITEM _zycore_opts "/wd4201")
        list(APPEND _zycore_opts "$<$<COMPILE_LANGUAGE:C,CXX>:/wd4201>")
        set_target_properties(Zycore PROPERTIES INTERFACE_COMPILE_OPTIONS "${_zycore_opts}")
    endif()
endif()
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(UNICORN_ARCH "x86" CACHE STRING "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS_SAVED "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)

option(BUILD_AIDA_PLUGIN "Build the AiDA IDA plugin" ON)

FetchContent_Declare(
    unicorn
    GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
    GIT_TAG        2.1.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(unicorn)
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED}")

# Suppress third-party unicorn warnings (C4319: zero-extending in seg_helper.c/translate.c)
if(MSVC AND TARGET x86_64-softmmu)
    target_compile_options(x86_64-softmmu PRIVATE /wd4319)
endif()
if(MSVC AND TARGET unicorn-common)
    target_compile_options(unicorn-common PRIVATE /wd4319)
endif()

if(BUILD_AIDA_PLUGIN)
    if(NOT DEFINED IDASDK_DIR)
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ida-sdk/src/include/ida.hpp")
            set(IDASDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ida-sdk/src")
        elseif(DEFINED ENV{IDASDK})
            set(IDASDK_DIR "$ENV{IDASDK}")
        else()
            message(FATAL_ERROR
                "IDA SDK not found. Set -DIDASDK_DIR=<path> or the IDASDK environment variable.\n"
                "The path must point to the SDK 'src' directory that contains 'include/' and 'lib/'.")
        endif()
    endif()
endif()


if(WIN32)

    # --- Dear ImGui (for standalone app) ---
    FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.8-docking
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(imgui)

    option(BUILD_BEDAISY_DUMPER "Build standalone BEDaisy kernel module dumper tool" ON)

    if(BUILD_BEDAISY_DUMPER)
        add_executable(BEDaisyDumper
            tools/bedaisy_dumper/bedaisydumper.cpp
            driver/comm.cpp
        )

        target_include_directories(BEDaisyDumper PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
            "${unicorn_SOURCE_DIR}/include"
        )

        target_compile_definitions(BEDaisyDumper PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(BEDaisyDumper PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
            /wd4201
        )

        target_link_libraries(BEDaisyDumper PRIVATE
            Zydis
            unicorn
            ws2_32
            dnsapi
            winhttp
            iphlpapi
            ntdll
        )

        set_target_properties(BEDaisyDumper PROPERTIES
            OUTPUT_NAME "BEDaisyDumper"
        )
    endif()

    # =========================================================================
    # WhosWho Driver Test Application
    # =========================================================================
    option(BUILD_DRIVER_TEST "Build WhosWho driver test application" ON)

    if(BUILD_DRIVER_TEST)
        add_executable(DriverTest
            driver/test_driver.cpp
            driver/comm.cpp
            driver/syscall.asm
        )

        target_include_directories(DriverTest PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
            "${unicorn_SOURCE_DIR}/include"
        )

        target_compile_definitions(DriverTest PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(DriverTest PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/W3>
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
            $<$<COMPILE_LANGUAGE:CXX>:/MD>
            $<$<COMPILE_LANGUAGE:CXX>:/wd4201>
        )

        target_link_libraries(DriverTest PRIVATE
            Zydis
            unicorn
            ws2_32
            dnsapi
            winhttp
            iphlpapi
            ntdll
        )

        set_target_properties(DriverTest PROPERTIES
            OUTPUT_NAME "test_driver"
        )

        # ── Test Target (purpose-built networking target process) ──
        add_executable(TestTarget
            driver/test_target.cpp
        )

        target_compile_definitions(TestTarget PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(TestTarget PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /MD
            /wd4201
        )

        target_link_libraries(TestTarget PRIVATE
            ws2_32
        )

        set_target_properties(TestTarget PROPERTIES
            OUTPUT_NAME "test_target"
        )
    endif()

    # =========================================================================
    # AiDA Standalone App  (ImGui + DX11 + MCP + driver + emulation)
    # =========================================================================
    option(BUILD_AIDA_STANDALONE "Build AiDA standalone application" ON)

    if(BUILD_AIDA_STANDALONE)
        set(STANDALONE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src")
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        set(OPENSSL_MSVC_STATIC_RT OFF)
        find_package(OpenSSL REQUIRED)

        # -- Create imgui/ directory layout expected by standalone sources ---------
        # The standalone code does #include "imgui/imgui.h", "imgui/imgui_impl_dx11.h",
        # "imgui/imgui_internal.h", "imgui/freetype/freetype.h" etc.
        # We create a mirror directory under the build tree that maps to the FetchContent sources.
        set(IMGUI_WRAPPER_DIR "${CMAKE_BINARY_DIR}/_imgui_wrapper/imgui")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}/freetype")

        # Create thin redirect headers so #pragma once in the real imgui headers
        # de-duplicates correctly (copies would be seen as separate files by MSVC).
        file(GLOB _imgui_core_headers "${imgui_SOURCE_DIR}/*.h")
        foreach(_h ${_imgui_core_headers})
            get_filename_component(_name "${_h}" NAME)
            file(WRITE "${IMGUI_WRAPPER_DIR}/${_name}" "#pragma once\n#include \"${_h}\"\n")
        endforeach()

        file(GLOB _imgui_backend_headers "${imgui_SOURCE_DIR}/backends/*.h")
        foreach(_h ${_imgui_backend_headers})
            get_filename_component(_name "${_h}" NAME)
            file(WRITE "${IMGUI_WRAPPER_DIR}/${_name}" "#pragma once\n#include \"${_h}\"\n")
        endforeach()

        if(EXISTS "${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.h")
            file(WRITE "${IMGUI_WRAPPER_DIR}/freetype/freetype.h"
                 "#pragma once\n#include \"${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.h\"\n")
        endif()

        # -- Create stub IDA headers so driver_loader.cpp compiles standalone -----
        set(IDA_STUBS_DIR "${CMAKE_BINARY_DIR}/_ida_stubs")
        file(MAKE_DIRECTORY "${IDA_STUBS_DIR}")
        file(WRITE "${IDA_STUBS_DIR}/pro.h"
             "#ifndef _PRO_H\n#define _PRO_H\n/* stub for standalone build */\n#endif\n")
        file(WRITE "${IDA_STUBS_DIR}/kernwin.hpp"
             "#ifndef __KERNWIN_HPP\n#define __KERNWIN_HPP\n/* stub for standalone build */\n#endif\n")

        # -- Standalone sources ---------------------------------------------------
        set(STANDALONE_SOURCES
            "${STANDALONE_ROOT}/main.cpp"
            "${STANDALONE_ROOT}/helpers/helpers.cpp"
            "${STANDALONE_ROOT}/helpers/blur.cpp"
            "${STANDALONE_ROOT}/helpers/icon_loodr.cpp"
            "${STANDALONE_ROOT}/helpers/file_browser.cpp"
            "${STANDALONE_ROOT}/helpers/embedded_assets.cpp"
            "${STANDALONE_ROOT}/core/mcp_standalone.cpp"
            "${STANDALONE_ROOT}/core/mcp_standalone_tools.cpp"
            "${STANDALONE_ROOT}/core/standalone_driver.cpp"
            "${STANDALONE_ROOT}/core/standalone_ai_client.cpp"
            "${STANDALONE_ROOT}/core/standalone_chat.cpp"
            "${STANDALONE_ROOT}/core/standalone_license.cpp"
            driver/comm.cpp
            src/net_security.cpp
            src/emulation_engine.cpp
        )

        # -- ImGui sources from FetchContent --------------------------------------
        set(IMGUI_SOURCES
            "${imgui_SOURCE_DIR}/imgui.cpp"
            "${imgui_SOURCE_DIR}/imgui_demo.cpp"
            "${imgui_SOURCE_DIR}/imgui_draw.cpp"
            "${imgui_SOURCE_DIR}/imgui_tables.cpp"
            "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
            "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
            "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
            "${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.cpp"
        )

        # -- Syscall ASM stub -----------------------------------------------------
        set(STANDALONE_ASM driver/syscall.asm)
        set_source_files_properties(${STANDALONE_ASM} PROPERTIES LANGUAGE ASM_MASM)
        add_library(AiDAStandalone_asm OBJECT ${STANDALONE_ASM})

        add_executable(AiDAStandalone WIN32
            ${STANDALONE_SOURCES}
            ${IMGUI_SOURCES}
            $<TARGET_OBJECTS:AiDAStandalone_asm>
        )

        # -- Include directories --------------------------------------------------
        target_include_directories(AiDAStandalone PRIVATE
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${CMAKE_BINARY_DIR}/_imgui_wrapper"
            "${imgui_SOURCE_DIR}"
            "${imgui_SOURCE_DIR}/backends"
            "${STANDALONE_ROOT}/freetype/include"
            "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
            "${CMAKE_CURRENT_SOURCE_DIR}/libs"
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${zydis_SOURCE_DIR}/include"
            "${zydis_SOURCE_DIR}/dependencies/zycore/include"
            "${zydis_BINARY_DIR}"
            "${zydis_BINARY_DIR}/zycore"
            "${unicorn_SOURCE_DIR}/include"
            "${IDA_STUBS_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/mapper/src"
        )

        # -- Compile definitions --------------------------------------------------
        target_compile_definitions(AiDAStandalone PRIVATE
            __NT__
            _CRT_SECURE_NO_WARNINGS
            CPPHTTPLIB_OPENSSL_SUPPORT
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            IMGUI_ENABLE_FREETYPE
            UNICODE
            _UNICODE
        )

        # -- Compiler flags -------------------------------------------------------
        target_compile_options(AiDAStandalone PRIVATE
            /W3
            /wd4005
            /EHsc
            /Zi
            /FS
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
        )

        # -- Link libraries -------------------------------------------------------
        target_link_directories(AiDAStandalone PRIVATE
            "${STANDALONE_ROOT}/freetype/lib/x64"
        )

        target_link_libraries(AiDAStandalone PRIVATE
            Zydis
            unicorn
            freetype
            OpenSSL::SSL
            OpenSSL::Crypto
            d3d11
            d3dcompiler
            dxgi
            dwmapi
            ws2_32
            dnsapi
            winhttp
            iphlpapi
            ntdll
            crypt32
            Shlwapi
        )

        # -- Link flags (PDB) ----------------------------------------------------
        target_link_options(AiDAStandalone PRIVATE
            /DEBUG:FULL
            /ENTRY:mainCRTStartup
            /NODEFAULTLIB:LIBCMT
            /IGNORE:4099
        )

        # -- Output properties + PDB ---------------------------------------------
        set_target_properties(AiDAStandalone PROPERTIES
            OUTPUT_NAME "AiDAStandalone"
            PDB_NAME_DEBUG "AiDAStandalone"
            PDB_NAME_RELEASE "AiDAStandalone"
            PDB_NAME_RELWITHDEBINFO "AiDAStandalone"
            COMPILE_PDB_NAME_DEBUG "AiDAStandalone"
            COMPILE_PDB_NAME_RELEASE "AiDAStandalone"
            COMPILE_PDB_NAME_RELWITHDEBINFO "AiDAStandalone"
            PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
            COMPILE_PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
            COMPILE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
            COMPILE_PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        )

    endif()

endif()

if(BUILD_AIDA_PLUGIN)

if(NOT EXISTS "${IDASDK_DIR}/include/ida.hpp")
    if(EXISTS "${IDASDK_DIR}/src/include/ida.hpp")
        set(IDASDK_DIR "${IDASDK_DIR}/src")
    else()
        message(FATAL_ERROR
            "IDASDK_DIR (${IDASDK_DIR}) does not contain include/ida.hpp.\n"
            "Point it to the SDK's 'src' directory.")
    endif()
endif()

message(STATUS "IDA SDK: ${IDASDK_DIR}")

if(WIN32)
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_win_64")
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/ida.lib")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(IDA_LIB_DIR "${IDASDK_DIR}/lib/arm64_mac_clang_64")
    else()
        set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_mac_clang_64")
    endif()
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/libida.dylib")
elseif(UNIX)
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_linux_gcc_64")
    set(IDA_LINK_LIB "${IDA_LIB_DIR}/libida.so")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

if(NOT EXISTS "${IDA_LINK_LIB}")
    message(FATAL_ERROR "IDA link library not found: ${IDA_LINK_LIB}")
endif()

set(AIDA_SOURCES
    src/actions.cpp
    src/agent_tools.cpp
    src/agentic.cpp
    src/aida.cpp
    src/ai_client.cpp
    src/chat_widget.cpp
    src/chat_widget_ui.cpp
    src/context_manager.cpp
    src/graphrag.cpp
    src/ida_utils.cpp
    src/license.cpp
    src/mcp_server.cpp
    src/settings.cpp
    src/ui.cpp
    src/workbench.cpp
    src/driver_loader.cpp
    src/net_security.cpp
    src/emulation_engine.cpp
    driver/comm.cpp
)

# --- x64 indirect syscall stub (MASM) ---
if(WIN32)
    set(AIDA_ASM_SOURCES driver/syscall.asm)
    set_source_files_properties(${AIDA_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)
endif()

set(AIDA_HEADERS
    src/actions.hpp
    src/agent_tools.hpp
    src/agentic.hpp
    src/aida.hpp
    src/aida_pro.hpp
    src/ai_client.hpp
    src/analysis_db.hpp
    src/anti_re.hpp
    src/chat_widget.hpp
    src/chat_widget_ui.hpp
    src/context_manager.hpp
    src/graphrag.hpp
    src/ida_utils.hpp
    src/license.hpp
    src/mcp_server.hpp
    src/obfuscation.hpp
    src/prompts.hpp
    src/rlhf.hpp
    src/settings.hpp
    src/driver_loader.hpp
    src/net_security.hpp
    src/emulation_engine.hpp
    src/ui.hpp
    src/workbench.hpp
)

add_library(AiDA SHARED ${AIDA_SOURCES} ${AIDA_HEADERS} ${AIDA_ASM_SOURCES})

# --- Export control: only export the PLUGIN symbol required by IDA ---
# Reference: IDA SDK loader.hpp line 643:
#   idaman ida_module_data plugin_t PLUGIN;
# IDA's plugin loader searches for "PLUGIN" by name. All other exports are hidden.
if(WIN32)
    target_sources(AiDA PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/AiDA.def")
endif()

set_target_properties(AiDA PROPERTIES
    OUTPUT_NAME "AiDA"
    PREFIX      ""
    SUFFIX      ".dll"
)

if(WIN32)
    set_target_properties(AiDA PROPERTIES
        PDB_NAME_DEBUG "AiDA"
        PDB_NAME_RELEASE "AiDA"
        PDB_NAME_RELWITHDEBINFO "AiDA"
        COMPILE_PDB_NAME_DEBUG "AiDA"
        COMPILE_PDB_NAME_RELEASE "AiDA"
        COMPILE_PDB_NAME_RELWITHDEBINFO "AiDA"
        PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
        PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
        PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
        COMPILE_PDB_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
        COMPILE_PDB_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
        COMPILE_PDB_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/RelWithDebInfo"
    )
endif()

if(UNIX AND NOT APPLE)
    set_target_properties(AiDA PROPERTIES SUFFIX ".so")
elseif(APPLE)
    set_target_properties(AiDA PROPERTIES SUFFIX ".dylib")
endif()

target_include_directories(AiDA PRIVATE
    "${IDASDK_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/cpp-httplib"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/VMProtect3.9.4/Include/C"
    "${CMAKE_CURRENT_SOURCE_DIR}/driver"
    "${CMAKE_CURRENT_SOURCE_DIR}/mapper/src"
)

target_compile_definitions(AiDA PRIVATE
    __EA64__
    __X64__
    _CRT_SECURE_NO_WARNINGS
    CPPHTTPLIB_OPENSSL_SUPPORT
    NOMINMAX
)

target_compile_definitions(AiDA PRIVATE
    QT_NAMESPACE=QT
    QT_NO_EMIT
    QT_CORE_LIB
    QT_GUI_LIB
    QT_WIDGETS_LIB
)

if(WIN32)
    target_compile_definitions(AiDA PRIVATE
        __NT__
        __IDP__
        WIN32_LEAN_AND_MEAN
        OPENSSL_NO_DYNAMIC_ENGINE
        QT_DLL
        QT_THREAD_SUPPORT
    )
elseif(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        target_compile_definitions(AiDA PRIVATE __ARM__)
    endif()
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__)
endif()

target_link_libraries(AiDA PRIVATE "${IDA_LINK_LIB}")

# --- Zydis + Unicorn emulation engine ---
target_link_libraries(AiDA PRIVATE Zydis unicorn)
target_include_directories(AiDA PRIVATE
    "${zydis_SOURCE_DIR}/include"
    "${zydis_SOURCE_DIR}/dependencies/zycore/include"
    "${zydis_BINARY_DIR}"
    "${zydis_BINARY_DIR}/zycore"
    "${unicorn_SOURCE_DIR}/include"
)

if(WIN32)
    target_compile_options(AiDA PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/Zi>
        $<$<COMPILE_LANGUAGE:CXX>:/FS>
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
        $<$<COMPILE_LANGUAGE:CXX>:/EHa>
        $<$<COMPILE_LANGUAGE:CXX>:/MD>
        $<$<COMPILE_LANGUAGE:CXX>:/GR>
        $<$<COMPILE_LANGUAGE:CXX>:/GS>
        $<$<COMPILE_LANGUAGE:CXX>:/GF>
        $<$<COMPILE_LANGUAGE:CXX>:/Gy>
        $<$<COMPILE_LANGUAGE:CXX>:/Gw>
        $<$<COMPILE_LANGUAGE:CXX>:/Oi>
        $<$<COMPILE_LANGUAGE:CXX>:/Ob2>
        $<$<COMPILE_LANGUAGE:CXX>:/GL>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4946>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4826>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4628>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4718>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5219>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5240>
    )

    # --- Anti-RE linker hardening ---
    # /OPT:REF,ICF removes unreferenced code and folds identical COMDATs.
    # /PDBALTPATH strips the real PDB path from the binary.
    # /RELEASE sets the checksum in the PE header.
    # /LTCG enables link-time code generation for whole-program optimization,
    #   which merges and inlines across translation units, reducing visible functions.
    #
    # NOTE: /MERGE:.pdata=.text is NOT used because .pdata contains x64 SEH
    # unwind data. The Windows loader resolves the Exception Directory
    # (IMAGE_DIRECTORY_ENTRY_EXCEPTION, data directory index 3) to locate
    # .pdata for stack unwinding. Merging it into .text changes the section
    # characteristics from IMAGE_SCN_MEM_READ to IMAGE_SCN_MEM_EXECUTE|READ,
    # which corrupts unwind resolution and crashes during LoadLibrary.
    #
    # NOTE: /MERGE:.rdata=.text is NOT used because merging read-only data
    # into an executable section changes memory protection attributes.
    # The loader sets .text pages to PAGE_EXECUTE_READ but .rdata expects
    # PAGE_READONLY. This can trigger DEP violations or corrupt relocations
    # during DLL initialization, causing crashes at LoadLibrary time.
    target_link_options(AiDA PRIVATE
        /DEBUG:FULL
        /OPT:REF,ICF
        /RELEASE
        /LTCG
        /PDBALTPATH:none
        /EMITTOOLVERSIONINFO:NO
    )

    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT OFF)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ws2_32
        crypt32
        Shlwapi
        setupapi
        Psapi
        wintrust
        cfgmgr32
    )

    if(DEFINED ENV{QTDIR})
        set(QT_PREFIX_HINT "$ENV{QTDIR}")
    elseif(DEFINED QTDIR)
        set(QT_PREFIX_HINT "${QTDIR}")
    endif()

    if(DEFINED QT_PREFIX_HINT AND EXISTS "${QT_PREFIX_HINT}")
        list(PREPEND CMAKE_PREFIX_PATH "${QT_PREFIX_HINT}")
    endif()

    set(_qt_inc_found FALSE)
    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET CONFIG)
    if(Qt6_FOUND)
        foreach(_comp Core Gui Widgets)
            get_target_property(_incs Qt6::${_comp} INTERFACE_INCLUDE_DIRECTORIES)
            if(_incs)
                foreach(_d IN LISTS _incs)
                    if(IS_DIRECTORY "${_d}")
                        target_include_directories(AiDA PRIVATE "${_d}")
                    endif()
                endforeach()
            endif()
        endforeach()
        set(_qt_inc_found TRUE)
    endif()

    if(NOT _qt_inc_found)
        set(QT_INC "")
        if(DEFINED QT_PREFIX_HINT AND EXISTS "${QT_PREFIX_HINT}/include")
            set(QT_INC "${QT_PREFIX_HINT}/include")
        elseif(DEFINED ENV{QTDIR} AND EXISTS "$ENV{QTDIR}/include")
            set(QT_INC "$ENV{QTDIR}/include")
        endif()

        if(QT_INC)
            target_include_directories(AiDA PRIVATE
                "${QT_INC}"
                "${QT_INC}/QtCore"
                "${QT_INC}/QtGui"
                "${QT_INC}/QtWidgets"
            )
        else()
            message(WARNING
                "Qt6 headers not found. Set QTDIR or CMAKE_PREFIX_PATH to your Qt6 installation.")
        endif()
    endif()

    set(_qt_import_libs_dir "${CMAKE_CURRENT_SOURCE_DIR}/libs/qt")
    foreach(_qtmod Core Gui Widgets)
        set(_def_file "${_qt_import_libs_dir}/Qt6${_qtmod}.def")
        set(_lib_file "${_qt_import_libs_dir}/Qt6${_qtmod}.lib")
        if(EXISTS "${_def_file}" AND NOT EXISTS "${_lib_file}")
            find_program(_msvc_lib_tool lib REQUIRED)
            message(STATUS "Generating Qt6${_qtmod}.lib from Qt6${_qtmod}.def ...")
            execute_process(
                COMMAND "${_msvc_lib_tool}" /DEF:${_def_file} /OUT:${_lib_file} /MACHINE:X64 /NOLOGO
                WORKING_DIRECTORY "${_qt_import_libs_dir}"
                RESULT_VARIABLE _lib_gen_result
                OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT _lib_gen_result EQUAL 0)
                message(WARNING "Failed to generate Qt6${_qtmod}.lib from .def file")
            endif()
            file(REMOVE "${_qt_import_libs_dir}/Qt6${_qtmod}.exp")
        endif()
    endforeach()

    target_link_directories(AiDA PRIVATE "${_qt_import_libs_dir}")
    target_link_libraries(AiDA PRIVATE Qt6Core Qt6Gui Qt6Widgets)
elseif(APPLE)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -Wno-nullability-completeness -fPIC)
    target_link_options(AiDA PRIVATE -undefined dynamic_lookup)

    set(_qt_apple_found FALSE)
    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET CONFIG)
    if(Qt6_FOUND)
        foreach(_comp Core Gui Widgets)
            get_target_property(_incs Qt6::${_comp} INTERFACE_INCLUDE_DIRECTORIES)
            if(_incs)
                foreach(_d IN LISTS _incs)
                    if(IS_DIRECTORY "${_d}")
                        target_include_directories(AiDA PRIVATE "${_d}")
                    endif()
                endforeach()
            endif()
        endforeach()
        set(_qt_apple_found TRUE)
    endif()

    if(NOT _qt_apple_found)
        set(_qt_apple_inc "")
        if(DEFINED ENV{QTDIR} AND IS_DIRECTORY "$ENV{QTDIR}/include")
            set(_qt_apple_inc "$ENV{QTDIR}/include")
        elseif(IS_DIRECTORY "/opt/homebrew/opt/qt@6/include")
            set(_qt_apple_inc "/opt/homebrew/opt/qt@6/include")
        elseif(IS_DIRECTORY "/usr/local/opt/qt@6/include")
            set(_qt_apple_inc "/usr/local/opt/qt@6/include")
        endif()
        if(_qt_apple_inc)
            target_include_directories(AiDA PRIVATE
                "${_qt_apple_inc}"
                "${_qt_apple_inc}/QtCore"
                "${_qt_apple_inc}/QtGui"
                "${_qt_apple_inc}/QtWidgets"
            )
        else()
            message(WARNING "Qt6 headers not found on macOS. Set QTDIR or install Qt6.")
        endif()
    endif()
elseif(UNIX)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -fPIC)

    set(_qt_linux_found FALSE)
    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET CONFIG)
    if(Qt6_FOUND)
        foreach(_comp Core Gui Widgets)
            get_target_property(_incs Qt6::${_comp} INTERFACE_INCLUDE_DIRECTORIES)
            if(_incs)
                foreach(_d IN LISTS _incs)
                    if(IS_DIRECTORY "${_d}")
                        target_include_directories(AiDA PRIVATE "${_d}")
                    endif()
                endforeach()
            endif()
        endforeach()
        set(_qt_linux_found TRUE)
    endif()

    if(NOT _qt_linux_found)
        set(_qt_linux_inc "")
        if(DEFINED ENV{QTDIR} AND IS_DIRECTORY "$ENV{QTDIR}/include")
            set(_qt_linux_inc "$ENV{QTDIR}/include")
        elseif(IS_DIRECTORY "/usr/include/x86_64-linux-gnu/qt6")
            set(_qt_linux_inc "/usr/include/x86_64-linux-gnu/qt6")
        elseif(IS_DIRECTORY "/usr/include/qt6")
            set(_qt_linux_inc "/usr/include/qt6")
        endif()
        if(_qt_linux_inc)
            target_include_directories(AiDA PRIVATE
                "${_qt_linux_inc}"
                "${_qt_linux_inc}/QtCore"
                "${_qt_linux_inc}/QtGui"
                "${_qt_linux_inc}/QtWidgets"
            )
        else()
            message(WARNING "Qt6 headers not found on Linux. Set QTDIR or install qt6-base-dev.")
        endif()
    endif()
    
endif()

endif()


