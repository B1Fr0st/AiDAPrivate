cmake_minimum_required(VERSION 3.21)

project(AiDA
    VERSION   1.2.8
    LANGUAGES CXX ASM_MASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_win_vc_64")
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
    src/ida_utils.cpp
    src/license.cpp
    src/mcp_server.cpp
    src/settings.cpp
    src/ui.cpp
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
    src/anti_re.hpp
    src/chat_widget.hpp
    src/chat_widget_ui.hpp
    src/ida_utils.hpp
    src/license.hpp
    src/mcp_server.hpp
    src/obfuscation.hpp
    src/prompts.hpp
    src/settings.hpp
    src/ui.hpp
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
        AIDA_USE_VMP
    )

    target_link_directories(AiDA PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/VMProtect3.9.4/Lib/Windows"
    )

    # Delay-load VMProtectSDK64.dll so AiDA.dll loads even when the DLL is only
    # in the plugins folder. DllMain resolves it by full path before first VMP call.
    target_link_options(AiDA PRIVATE /DELAYLOAD:VMProtectSDK64.dll)
    target_link_libraries(AiDA PRIVATE delayimp)
elseif(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        target_compile_definitions(AiDA PRIVATE __ARM__)
    endif()
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__)
endif()

target_link_libraries(AiDA PRIVATE "${IDA_LINK_LIB}")

if(WIN32)
    target_compile_options(AiDA PRIVATE
        /W3
        /Zc:__cplusplus
        /permissive-
        /Zp8
        /EHsc
        /MD
        /GR
        /GS
        /GF
        /Gy
        /Gw
        /Oi
        /Ob2
        /GL
        /wd4946
        /wd4826
        /wd4628
        /wd4718
        /wd5219
        /wd5240
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

# --- Post-build PE protection step ---
# Runs pe_protect.py to strip debug info, randomize section names,
# wipe non-essential exports, and add junk overlay data.
# This makes static analysis in IDA/Ghidra/BinaryNinja extremely difficult.
# Must be outside the platform if/elseif block so it actually runs on WIN32.
if(WIN32)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_FOUND)
        add_custom_command(TARGET AiDA POST_BUILD
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/pe_protect.py"
                    "$<TARGET_FILE:AiDA>"
            COMMENT "Applying PE protection transformations to AiDA.dll..."
            VERBATIM
        )
    else()
        message(WARNING "Python3 not found. Post-build PE protection will be skipped.")
    endif()
endif()
