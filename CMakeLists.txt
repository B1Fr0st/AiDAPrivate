cmake_minimum_required(VERSION 3.21)

project(AiDA
    VERSION   1.2.8
    LANGUAGES CXX ASM_MASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/.deps")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER ON CACHE BOOL "" FORCE)

set(zydis_SOURCE_DIR "${DEPS_DIR}/zydis")
set(zydis_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/zydis")
add_subdirectory("${zydis_SOURCE_DIR}" "${zydis_BINARY_DIR}")

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

set(unicorn_SOURCE_DIR "${DEPS_DIR}/unicorn")
add_subdirectory("${unicorn_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/unicorn")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED}")

set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
set(zlib_SOURCE_DIR "${DEPS_DIR}/zlib")
set(zlib_BINARY_DIR "${CMAKE_BINARY_DIR}/.deps/zlib")
add_subdirectory("${zlib_SOURCE_DIR}" "${zlib_BINARY_DIR}")

# zlib manages its own include dirs; expose them for our consumers via a convenience variable
# but do NOT set PUBLIC includes on zlibstatic (causes CMP0070 errors with newer CMake)

set(BROTLI_DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(BROTLI_BUNDLED_MODE ON CACHE BOOL "" FORCE)
set(brotli_SOURCE_DIR "${DEPS_DIR}/brotli")
add_subdirectory("${brotli_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/brotli")

if(TARGET brotlidec)
    target_include_directories(brotlidec PUBLIC
        "${brotli_SOURCE_DIR}/c/include"
    )
endif()

set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(LLHTTP_BUILD_STATIC_LIBS ON CACHE INTERNAL "")
# The llhttp git repo uses "_RELEASE_" as a version placeholder (substituted by npm during release).
# Patch it to a real semver string so CMake's project() call doesn't reject it.
file(READ "${DEPS_DIR}/llhttp/CMakeLists.txt" _llhttp_cmake)
if("${_llhttp_cmake}" MATCHES "VERSION _RELEASE_")
    string(REPLACE "VERSION _RELEASE_" "VERSION 9.3.0" _llhttp_cmake "${_llhttp_cmake}")
    file(WRITE "${DEPS_DIR}/llhttp/CMakeLists.txt" "${_llhttp_cmake}")
endif()
add_subdirectory("${DEPS_DIR}/llhttp" "${CMAKE_BINARY_DIR}/.deps/llhttp")

set(BUILD_SHARED_LIBS_SAVED_NH2 "${BUILD_SHARED_LIBS}")
set(BUILD_STATIC_LIBS   ON)
set(BUILD_SHARED_LIBS  OFF)
set(ENABLE_LIB_ONLY     ON)
set(ENABLE_DOC          OFF)
set(ENABLE_APP          OFF)
set(ENABLE_EXAMPLES     OFF)
set(ENABLE_FAILMALLOC  OFF)
set(ENABLE_HPACK_TOOLS OFF)
set(WITH_LIBXML2       OFF)
set(WITH_JEMALLOC      OFF)
set(WITH_SPDYLAY       OFF)
add_subdirectory("${DEPS_DIR}/nghttp2" "${CMAKE_BINARY_DIR}/.deps/nghttp2")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED_NH2}")
unset(BUILD_STATIC_LIBS)

if(TARGET nghttp2_static)
    if(MSVC)
        target_compile_options(nghttp2_static PRIVATE /wd4100 /wd4244 /wd4267)
    endif()
endif()

set(lua_src_SOURCE_DIR "${DEPS_DIR}/lua-lua-a5522f0")

file(GLOB LUA_CORE_SOURCES "${lua_src_SOURCE_DIR}/*.c")
list(REMOVE_ITEM LUA_CORE_SOURCES
    "${lua_src_SOURCE_DIR}/lua.c"           # standalone interpreter
    "${lua_src_SOURCE_DIR}/luac.c"          # standalone compiler
    "${lua_src_SOURCE_DIR}/onelua.c"        # single-file build; all sources already included individually
)
add_library(lua54_static STATIC ${LUA_CORE_SOURCES})
target_include_directories(lua54_static PUBLIC "${lua_src_SOURCE_DIR}")
set_target_properties(lua54_static PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)
if(MSVC)
    target_compile_options(lua54_static PRIVATE /W3 /wd4244 /wd4702 /wd4334)
    target_compile_definitions(lua54_static PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set(sol2_SOURCE_DIR "${DEPS_DIR}/sol2")
add_subdirectory("${sol2_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/sol2")

if(MSVC AND TARGET x86_64-softmmu)
    target_compile_options(x86_64-softmmu PRIVATE /wd4319)
endif()
if(MSVC AND TARGET unicorn-common)
    target_compile_options(unicorn-common PRIVATE /wd4319)
endif()

# --- Z3 (pre-built static library) ---
# Use pre-existing Z3 library at .deps/z3/z3-4.13.4-x64-win
set(Z3_VERSION "4.13.4")
set(Z3_INSTALL_DIR "${DEPS_DIR}/z3/z3-${Z3_VERSION}-x64-win")

if(NOT EXISTS "${Z3_INSTALL_DIR}/include/z3.h")
    message(FATAL_ERROR "Z3 library not found at ${Z3_INSTALL_DIR}")
endif()

set(Z3_INCLUDE_DIRS "${Z3_INSTALL_DIR}/include" CACHE PATH "Z3 include directory" FORCE)
set(Z3_LIBRARIES "${Z3_INSTALL_DIR}/bin/libz3.lib" CACHE FILEPATH "Z3 library" FORCE)
set(Z3_FOUND TRUE CACHE BOOL "" FORCE)

# --- Capstone (required by Triton) ---
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${DEPS_DIR}/capstone/capstone-5.0.7" "${CMAKE_BINARY_DIR}/.deps/capstone")

# Suppress warnings from Capstone on MSVC
if(MSVC AND TARGET capstone)
    target_compile_options(capstone PRIVATE /W0)
endif()

# capstone 5.x creates capstone::capstone alias automatically, but guard just in case
if(NOT TARGET capstone::capstone)
    if(TARGET capstone_static)
        add_library(capstone::capstone ALIAS capstone_static)
    elseif(TARGET capstone)
        add_library(capstone::capstone ALIAS capstone)
    endif()
endif()

# Pre-populate CAPSTONE variables so Triton's FindCAPSTONE.cmake does not call
# find_path/find_library (which would fail at configure time before the build).
set(CAPSTONE_FOUND TRUE CACHE BOOL "" FORCE)
set(CAPSTONE_INCLUDE_DIRS "${DEPS_DIR}/capstone/capstone-5.0.7/include" CACHE PATH "" FORCE)
set(CAPSTONE_LIBRARIES "capstone" CACHE STRING "" FORCE)

# --- Triton (symbolic execution engine) ---
set(BUILD_SHARED_LIBS_SAVED_TRITON "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(Z3_INTERFACE ON CACHE BOOL "" FORCE)
set(BITWUZLA_INTERFACE OFF CACHE BOOL "" FORCE)
set(LLVM_INTERFACE OFF CACHE BOOL "" FORCE)
set(BOOST_INTERFACE OFF CACHE BOOL "" FORCE)
set(PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(MSVC_STATIC OFF CACHE BOOL "" FORCE)

set(TRITON_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sources/Triton")
set(TRITON_INSTALL_RULES OFF CACHE BOOL "" FORCE)
add_subdirectory("${TRITON_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/triton")
set(BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS_SAVED_TRITON}")

if(MSVC AND TARGET triton)
    target_compile_options(triton PRIVATE /W0 /wd4005 /wd4244 /wd4267 /wd4146 /wd4996)
endif()

# --- Ghidra Native Decompiler (embedded as static library) ---
set(GHIDRA_DECOMP_DIR "${CMAKE_SOURCE_DIR}/sources/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp")
set(GHIDRA_SPECS_SRC_DIR "${CMAKE_SOURCE_DIR}/sources/ghidra/Ghidra/Processors/x86/data/languages")
set(GHIDRA_SPECS_OUTPUT_DIR "${CMAKE_BINARY_DIR}/ghidra_specs")

file(GLOB GHIDRA_ALL_CC "${GHIDRA_DECOMP_DIR}/*.cc")

set(GHIDRA_LIBDECOMP_EXCLUDE
    "${GHIDRA_DECOMP_DIR}/ghidra_arch.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_context.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_process.cc"
    "${GHIDRA_DECOMP_DIR}/ghidra_translate.cc"
    "${GHIDRA_DECOMP_DIR}/inject_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/typegrp_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/database_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/cpool_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/comment_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/string_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/signature_ghidra.cc"
    "${GHIDRA_DECOMP_DIR}/slgh_compile.cc"
    "${GHIDRA_DECOMP_DIR}/slghparse.cc"
    "${GHIDRA_DECOMP_DIR}/slghscan.cc"
    "${GHIDRA_DECOMP_DIR}/consolemain.cc"
    "${GHIDRA_DECOMP_DIR}/sleighexample.cc"
    "${GHIDRA_DECOMP_DIR}/test.cc"
    "${GHIDRA_DECOMP_DIR}/bfd_arch.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_bfd.cc"
    "${GHIDRA_DECOMP_DIR}/raw_arch.cc"
    "${GHIDRA_DECOMP_DIR}/xml_arch.cc"
    "${GHIDRA_DECOMP_DIR}/loadimage_xml.cc"
    "${GHIDRA_DECOMP_DIR}/analyzesigs.cc"
    "${GHIDRA_DECOMP_DIR}/codedata.cc"
)

set(GHIDRA_LIBDECOMP_SOURCES ${GHIDRA_ALL_CC})
list(REMOVE_ITEM GHIDRA_LIBDECOMP_SOURCES ${GHIDRA_LIBDECOMP_EXCLUDE})

add_library(libdecomp_aida STATIC ${GHIDRA_LIBDECOMP_SOURCES})
target_include_directories(libdecomp_aida PRIVATE
    "${GHIDRA_DECOMP_DIR}"
    "${zlib_SOURCE_DIR}"
    "${zlib_BINARY_DIR}"
)
target_compile_definitions(libdecomp_aida PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    AIDA_STANDALONE
)
if(MSVC)
    target_compile_options(libdecomp_aida PRIVATE /W0 /EHsc /MD)
endif()
target_link_libraries(libdecomp_aida PRIVATE zlibstatic)

add_executable(ghidra_sleigh_compiler
    "${GHIDRA_DECOMP_DIR}/xml.cc"
    "${GHIDRA_DECOMP_DIR}/marshal.cc"
    "${GHIDRA_DECOMP_DIR}/space.cc"
    "${GHIDRA_DECOMP_DIR}/float.cc"
    "${GHIDRA_DECOMP_DIR}/address.cc"
    "${GHIDRA_DECOMP_DIR}/pcoderaw.cc"
    "${GHIDRA_DECOMP_DIR}/translate.cc"
    "${GHIDRA_DECOMP_DIR}/opcodes.cc"
    "${GHIDRA_DECOMP_DIR}/globalcontext.cc"
    "${GHIDRA_DECOMP_DIR}/sleigh.cc"
    "${GHIDRA_DECOMP_DIR}/pcodeparse.cc"
    "${GHIDRA_DECOMP_DIR}/pcodecompile.cc"
    "${GHIDRA_DECOMP_DIR}/sleighbase.cc"
    "${GHIDRA_DECOMP_DIR}/slghsymbol.cc"
    "${GHIDRA_DECOMP_DIR}/slghpatexpress.cc"
    "${GHIDRA_DECOMP_DIR}/slghpattern.cc"
    "${GHIDRA_DECOMP_DIR}/semantics.cc"
    "${GHIDRA_DECOMP_DIR}/context.cc"
    "${GHIDRA_DECOMP_DIR}/slaformat.cc"
    "${GHIDRA_DECOMP_DIR}/compression.cc"
    "${GHIDRA_DECOMP_DIR}/filemanage.cc"
    "${GHIDRA_DECOMP_DIR}/slgh_compile.cc"
    "${GHIDRA_DECOMP_DIR}/slghparse.cc"
    "${GHIDRA_DECOMP_DIR}/slghscan.cc"
)
target_include_directories(ghidra_sleigh_compiler PRIVATE
    "${GHIDRA_DECOMP_DIR}"
    "${zlib_SOURCE_DIR}"
    "${zlib_BINARY_DIR}"
)
target_compile_definitions(ghidra_sleigh_compiler PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)
if(MSVC)
    target_compile_options(ghidra_sleigh_compiler PRIVATE /W0 /EHsc /MD /O2)
endif()
target_link_libraries(ghidra_sleigh_compiler PRIVATE zlibstatic)

file(MAKE_DIRECTORY "${GHIDRA_SPECS_OUTPUT_DIR}")

add_custom_command(
    OUTPUT "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
    COMMAND ghidra_sleigh_compiler "${GHIDRA_SPECS_SRC_DIR}/x86-64.slaspec" "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
    DEPENDS ghidra_sleigh_compiler "${GHIDRA_SPECS_SRC_DIR}/x86-64.slaspec"
    WORKING_DIRECTORY "${GHIDRA_SPECS_SRC_DIR}"
    COMMENT "Compiling SLEIGH: x86-64.slaspec -> x86-64.sla"
    VERBATIM
)

add_custom_command(
    OUTPUT "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.pspec"
           "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64-win.cspec"
           "${GHIDRA_SPECS_OUTPUT_DIR}/x86.ldefs"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${GHIDRA_SPECS_SRC_DIR}/x86-64.pspec" "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.pspec"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${GHIDRA_SPECS_SRC_DIR}/x86-64-win.cspec" "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64-win.cspec"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${GHIDRA_SPECS_SRC_DIR}/x86.ldefs" "${GHIDRA_SPECS_OUTPUT_DIR}/x86.ldefs"
    DEPENDS
        "${GHIDRA_SPECS_SRC_DIR}/x86-64.pspec"
        "${GHIDRA_SPECS_SRC_DIR}/x86-64-win.cspec"
        "${GHIDRA_SPECS_SRC_DIR}/x86.ldefs"
    COMMENT "Copying Ghidra spec files"
    VERBATIM
)

add_custom_target(ghidra_specs ALL DEPENDS
    "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
    "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.pspec"
    "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64-win.cspec"
    "${GHIDRA_SPECS_OUTPUT_DIR}/x86.ldefs"
)

# --- Auto-encrypt embedded driver/mapper byte arrays ---
# When WhosWho.c, Sentinel.c, or WindMapper.c change, the corresponding
# encrypted headers are regenerated so driver_loader.cpp picks up the new bytes.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    # WhosWho.c  ->  src/whoswho_encrypted.h
    add_custom_command(
        OUTPUT "${CMAKE_BINARY_DIR}/whoswho_encrypted.stamp"
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_whoswho.py"
        COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_BINARY_DIR}/whoswho_encrypted.stamp"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/WhosWho.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_whoswho.py"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Encrypting WhosWho.c -> whoswho_encrypted.h"
        VERBATIM
    )

    # Sentinel.c  ->  src/sentinel_encrypted.h
    add_custom_command(
        OUTPUT "${CMAKE_BINARY_DIR}/sentinel_encrypted.stamp"
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_sentinel.py"
        COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_BINARY_DIR}/sentinel_encrypted.stamp"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/Sentinel.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_sentinel.py"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Encrypting Sentinel.c -> sentinel_encrypted.h"
        VERBATIM
    )

    add_custom_target(encrypt_drivers DEPENDS
        "${CMAKE_BINARY_DIR}/whoswho_encrypted.stamp"
        "${CMAKE_BINARY_DIR}/sentinel_encrypted.stamp"
    )
else()
    message(WARNING "Python3 not found -- encrypt_drivers target disabled. "
                    "Re-run encrypt scripts manually after updating WhosWho.c / Sentinel.c.")
endif()

# Track the generated encrypted headers so MSVC recompiles driver_loader.cpp
# when they change (even outside the encrypt_drivers flow).
set(ENCRYPTED_DRIVER_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/whoswho_encrypted.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sentinel_encrypted.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/windmapper_embedded.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/windmapper_data.inc"
)
set_source_files_properties(
    src/driver_loader.cpp
    PROPERTIES OBJECT_DEPENDS "${ENCRYPTED_DRIVER_HEADERS}"
)

# Track #include'd asset .c files so embedded_assets.cpp rebuilds when they change.
set(EMBEDDED_ASSET_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/aidalogo.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/background.c"
)
set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/helpers/embedded_assets.cpp"
    PROPERTIES OBJECT_DEPENDS "${EMBEDDED_ASSET_FILES}"
)

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

    set(imgui_SOURCE_DIR "${DEPS_DIR}/imgui-src")

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

    option(BUILD_AIDA_STANDALONE "Build AiDA standalone application" ON)

    if(BUILD_AIDA_STANDALONE)
        set(STANDALONE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src")
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        set(OPENSSL_MSVC_STATIC_RT OFF)
        find_package(OpenSSL REQUIRED)

        # Force static OpenSSL libs — CMake's FindOpenSSL picks the import libs
        # (libssl.lib/libcrypto.lib) even with OPENSSL_USE_STATIC_LIBS=TRUE on MSVC.
        # Override to the _static variants so users don't need DLLs at runtime.
        if(MSVC AND OPENSSL_FOUND)
            get_filename_component(_ossl_lib_dir "${OPENSSL_SSL_LIBRARY}" DIRECTORY)
            if(EXISTS "${_ossl_lib_dir}/libssl_static.lib")
                set_target_properties(OpenSSL::SSL PROPERTIES
                    IMPORTED_LOCATION "${_ossl_lib_dir}/libssl_static.lib"
                    IMPORTED_LOCATION_RELEASE "${_ossl_lib_dir}/libssl_static.lib"
                    IMPORTED_LOCATION_DEBUG "${_ossl_lib_dir}/../MDd/libssl_static.lib"
                )
                set_target_properties(OpenSSL::Crypto PROPERTIES
                    IMPORTED_LOCATION "${_ossl_lib_dir}/libcrypto_static.lib"
                    IMPORTED_LOCATION_RELEASE "${_ossl_lib_dir}/libcrypto_static.lib"
                    IMPORTED_LOCATION_DEBUG "${_ossl_lib_dir}/../MDd/libcrypto_static.lib"
                )
            endif()
        endif()

        set(IMGUI_WRAPPER_DIR "${CMAKE_BINARY_DIR}/_imgui_wrapper/imgui")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}")
        file(MAKE_DIRECTORY "${IMGUI_WRAPPER_DIR}/freetype")

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

        set(IDA_STUBS_DIR "${CMAKE_BINARY_DIR}/_ida_stubs")
        file(MAKE_DIRECTORY "${IDA_STUBS_DIR}")
        file(WRITE "${IDA_STUBS_DIR}/pro.h"
               "#ifndef _PRO_H\n"
               "#define _PRO_H\n"
               "#include <cstdarg>\n"
               "#include <cstdio>\n"
               "#include <windows.h>\n"
               "inline int qvsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {\n"
               "    return vsnprintf_s(buf, n, _TRUNCATE, fmt, ap);\n"
               "}\n"
               "inline void msg(const char* fmt, ...) {\n"
               "    char tmp[2048] = {};\n"
               "    va_list ap;\n"
               "    va_start(ap, fmt);\n"
               "    vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);\n"
               "    va_end(ap);\n"
               "    OutputDebugStringA(tmp);\n"
               "}\n"
               "#endif\n")
        file(WRITE "${IDA_STUBS_DIR}/kernwin.hpp"
               "#ifndef __KERNWIN_HPP\n"
               "#define __KERNWIN_HPP\n"
               "#include <cstdarg>\n"
               "#include <cstdio>\n"
               "#include <windows.h>\n"
               "#ifndef ASKBTN_NO\n"
               "#define ASKBTN_NO 0\n"
               "#endif\n"
               "#ifndef ASKBTN_YES\n"
               "#define ASKBTN_YES 1\n"
               "#endif\n"
               "inline int ask_yn(int deflt, const char* fmt, ...) {\n"
               "    char tmp[2048] = {};\n"
               "    va_list ap;\n"
               "    va_start(ap, fmt);\n"
               "    vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);\n"
               "    va_end(ap);\n"
               "    const int r = MessageBoxA(nullptr, tmp, \"AiDAStandalone\", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);\n"
               "    if (r == IDYES) return ASKBTN_YES;\n"
               "    if (r == IDNO) return ASKBTN_NO;\n"
               "    return deflt;\n"
               "}\n"
               "#endif\n")

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
            "${STANDALONE_ROOT}/core/driver_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/net_security_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/emulation_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/code_editor.cpp"
            "${STANDALONE_ROOT}/core/disasm_view.cpp"
            "${STANDALONE_ROOT}/core/hex_view.cpp"
            "${STANDALONE_ROOT}/core/chat_render.cpp"
            "${STANDALONE_ROOT}/core/mcp_client.cpp"
            "${STANDALONE_ROOT}/core/mcp_marketplace.cpp"
            "${STANDALONE_ROOT}/core/protocol_parser.cpp"
            "${STANDALONE_ROOT}/core/cert_generator.cpp"
            "${STANDALONE_ROOT}/core/mitm_proxy.cpp"
            "${STANDALONE_ROOT}/core/network_view.cpp"
            "${STANDALONE_ROOT}/core/coding_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/workflow_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/script_engine.cpp"
            "${STANDALONE_ROOT}/core/memory_scanner.cpp"
            "${STANDALONE_ROOT}/core/memory_scanner_view.cpp"
            "${STANDALONE_ROOT}/core/scanner_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger_engine.cpp"
            "${STANDALONE_ROOT}/core/debugger_view.cpp"
            "${STANDALONE_ROOT}/core/decompiler_view.cpp"
            "${STANDALONE_ROOT}/core/struct_recon_view.cpp"
            "${STANDALONE_ROOT}/core/fuzzer_view.cpp"
            "${STANDALONE_ROOT}/core/analysis_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/arc_loader.cpp"
            src/driver_loader.cpp
            driver/comm.cpp
            src/net_security.cpp
            src/emulation_engine.cpp
            "${STANDALONE_ROOT}/core/tls_exporter.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/hardware_id/hardware_id.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/telemetry/telemetry_client.cpp"
        )

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

        set(STANDALONE_ASM driver/syscall.asm)
        set_source_files_properties(${STANDALONE_ASM} PROPERTIES LANGUAGE ASM_MASM)
        add_library(AiDAStandalone_asm OBJECT ${STANDALONE_ASM})

        # --- Embedded resources (libz3.dll + ghidra specs) ---
        set(Z3_DLL_PATH "${Z3_INSTALL_DIR}/bin/libz3.dll")
        configure_file(
            "${STANDALONE_ROOT}/resources/aida_embedded.rc.in"
            "${CMAKE_BINARY_DIR}/aida_embedded.rc"
            @ONLY
        )

        add_executable(AiDAStandalone WIN32
            ${STANDALONE_SOURCES}
            ${IMGUI_SOURCES}
            $<TARGET_OBJECTS:AiDAStandalone_asm>
            "${CMAKE_BINARY_DIR}/aida_embedded.rc"
        )

        target_include_directories(AiDAStandalone PRIVATE
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/arc"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared"
            "${CMAKE_BINARY_DIR}/_imgui_wrapper"
            "${imgui_SOURCE_DIR}"
            "${imgui_SOURCE_DIR}/backends"
            "${lua_src_SOURCE_DIR}"
            "${sol2_SOURCE_DIR}/include"
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
            "${zlib_SOURCE_DIR}"
            "${zlib_BINARY_DIR}"
            "${IDA_STUBS_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/mapper/src"
            "${TRITON_SOURCE_DIR}/src/libtriton/includes"
            "${CMAKE_BINARY_DIR}/.deps/triton/src/libtriton/includes"
            "${Z3_INCLUDE_DIRS}"
            "${GHIDRA_DECOMP_DIR}"
        )

        target_compile_definitions(AiDAStandalone PRIVATE
            __NT__
            _CRT_SECURE_NO_WARNINGS
            CPPHTTPLIB_OPENSSL_SUPPORT
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            IMGUI_ENABLE_FREETYPE
            UNICODE
            _UNICODE
            SOL_ALL_SAFETIES_ON=1
            TRITON_Z3_INTERFACE
            GHIDRA_SPECS_DIR="${GHIDRA_SPECS_OUTPUT_DIR}"
        )

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

        target_link_directories(AiDAStandalone PRIVATE
            "${STANDALONE_ROOT}/freetype/lib/x64"
        )

        target_link_libraries(AiDAStandalone PRIVATE
            Zydis
            unicorn
            triton
            libdecomp_aida
            freetype
            zlibstatic
            brotlidec
            brotlienc
            brotlicommon
            llhttp_static
            nghttp2_static
            lua54_static
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
            bcrypt
            Shlwapi
            advapi32
            wintrust
            setupapi
            cfgmgr32
            Psapi
        )

        target_link_options(AiDAStandalone PRIVATE
            /DEBUG:FULL
            /ENTRY:mainCRTStartup
            /NODEFAULTLIB:LIBCMT
            /IGNORE:4099
            "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
            /DELAYLOAD:libz3.dll
        )

        target_link_libraries(AiDAStandalone PRIVATE delayimp)

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

        add_dependencies(AiDAStandalone ghidra_specs)
        if(TARGET encrypt_drivers)
            add_dependencies(AiDAStandalone encrypt_drivers)
        endif()

        # Post-build copies removed — libz3.dll and ghidra_specs are now
        # embedded as Win32 resources inside the .exe via aida_embedded.rc.

    endif()

    # ── ARC (AiDA Runtime Core) DLL ──────────────────────────────────────
    # Built separately, deployed on the license server, delivered after
    # successful license validation. NOT linked into AiDAStandalone.

    option(BUILD_ARC_DLL "Build the ARC (AiDA Runtime Core) DLL" ON)

    if(BUILD_ARC_DLL)
        set(ARC_SOURCES
            "${STANDALONE_ROOT}/core/arc/arc.cpp"
            driver/comm.cpp
        )

        set(ARC_ASM driver/syscall.asm)
        set_source_files_properties(${ARC_ASM} PROPERTIES LANGUAGE ASM_MASM)
        add_library(AiDA_ARC_asm OBJECT ${ARC_ASM})

        add_library(AiDA_ARC SHARED
            ${ARC_SOURCES}
            $<TARGET_OBJECTS:AiDA_ARC_asm>
        )

        target_include_directories(AiDA_ARC PRIVATE
            "${STANDALONE_ROOT}/core/arc"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}"
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )

        target_compile_definitions(AiDA_ARC PRIVATE
            ARC_EXPORTS
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )

        target_compile_options(AiDA_ARC PRIVATE
            /W3
            /EHsc
            /Zi
            /FS
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
            /O2
            /GL
        )

        target_link_libraries(AiDA_ARC PRIVATE
            ws2_32
            iphlpapi
            ntdll
            bcrypt
            advapi32
            winhttp
        )

        target_link_options(AiDA_ARC PRIVATE
            /DEBUG:FULL
            /LTCG
        )

        set_target_properties(AiDA_ARC PROPERTIES
            OUTPUT_NAME "aida_core"
            PDB_NAME_RELEASE "aida_core"
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
    src/aida.cpp
    src/graphrag.cpp
    src/ida_utils.cpp
    src/license.cpp
    src/mcp_server.cpp
    src/settings.cpp
    src/driver_loader.cpp
    src/net_security.cpp
    src/emulation_engine.cpp
    driver/comm.cpp
)

if(WIN32)
    set(AIDA_ASM_SOURCES driver/syscall.asm)
    set_source_files_properties(${AIDA_ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)
endif()

set(AIDA_HEADERS
    src/actions.hpp
    src/agent_tools.hpp
    src/aida.hpp
    src/aida_pro.hpp
    src/analysis_db.hpp
    src/anti_re.hpp
    src/graphrag.hpp
    src/ida_utils.hpp
    src/license.hpp
    src/mcp_server.hpp
    src/obfuscation.hpp
    src/settings.hpp
    src/driver_loader.hpp
    src/net_security.hpp
    src/emulation_engine.hpp
    src/whoswho_encrypted.h
    src/sentinel_encrypted.h
    src/windmapper_embedded.h
)

add_library(AiDA SHARED ${AIDA_SOURCES} ${AIDA_HEADERS} ${AIDA_ASM_SOURCES})

if(TARGET encrypt_drivers)
    add_dependencies(AiDA encrypt_drivers)
endif()

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



if(WIN32)
    target_compile_definitions(AiDA PRIVATE
        __NT__
        __IDP__
        WIN32_LEAN_AND_MEAN
        OPENSSL_NO_DYNAMIC_ENGINE
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
elseif(APPLE)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -Wno-nullability-completeness -fPIC)
    target_link_options(AiDA PRIVATE -undefined dynamic_lookup)
elseif(UNIX)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    target_compile_options(AiDA PRIVATE -Wall -Wextra -fPIC)
    
endif()

endif()



# -- AiDA PE Protector (build tool) ----------------------------------
option(BUILD_PROTECTOR "Build the AiDA PE Protector tool" ON)

if(BUILD_PROTECTOR)
    add_executable(AiDAProtector
        tools/protector/main.cpp
    )

    target_include_directories(AiDAProtector PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/protector
    )

    target_compile_definitions(AiDAProtector PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )

    target_compile_options(AiDAProtector PRIVATE
        /W4 /EHsc /O2 /Zc:__cplusplus /permissive- /MD
    )

    target_link_libraries(AiDAProtector PRIVATE bcrypt advapi32)

    set_target_properties(AiDAProtector PROPERTIES
        OUTPUT_NAME "aida_protector"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_executable(AiDAExtractPayload tools/protector/payload/extract_payload.cpp)
    target_compile_options(AiDAExtractPayload PRIVATE /W4 /WX /EHsc /O2 /Zc:__cplusplus /std:c++17)
    target_compile_definitions(AiDAExtractPayload PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)

    set(AIDA_PAYLOAD_OBJ "${CMAKE_BINARY_DIR}/aida_payload.obj")
    set(AIDA_PAYLOAD_HDR "${CMAKE_BINARY_DIR}/generated/payload_blob.hpp")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/generated")

    find_program(AIDA_MSVC_CL cl.exe REQUIRED)

    add_custom_command(
        OUTPUT "${AIDA_PAYLOAD_OBJ}"
        COMMAND "${AIDA_MSVC_CL}" /nologo /c /GS- /GR- /Od /Oi /Ob0 /Zl /EHs- /Gw /W3
                /D_NO_CRT_STDIO_INLINE /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX
                /Fo${AIDA_PAYLOAD_OBJ}
                ${CMAKE_SOURCE_DIR}/tools/protector/payload/payload.c
        DEPENDS "${CMAKE_SOURCE_DIR}/tools/protector/payload/payload.c"
        COMMENT "Compiling AiDA PIC payload..."
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${AIDA_PAYLOAD_HDR}"
        COMMAND "$<TARGET_FILE:AiDAExtractPayload>"
                "${AIDA_PAYLOAD_OBJ}"
                "${AIDA_PAYLOAD_HDR}"
                kAidaUnpackBlob
        DEPENDS "${AIDA_PAYLOAD_OBJ}" AiDAExtractPayload
        COMMENT "Extracting AiDA PIC payload blob..."
        VERBATIM
    )

    add_custom_target(AiDAPayloadBlob DEPENDS "${AIDA_PAYLOAD_HDR}")
    add_dependencies(AiDAProtector AiDAPayloadBlob)
    target_include_directories(AiDAProtector PRIVATE "${CMAKE_BINARY_DIR}/generated")

    add_executable(AiDAProtectorVerify tools/protector/verify.cpp)
    target_include_directories(AiDAProtectorVerify PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/protector
    )
    target_compile_definitions(AiDAProtectorVerify PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    target_compile_options(AiDAProtectorVerify PRIVATE
        /W4 /EHsc /O2 /Zc:__cplusplus /permissive- /MD
    )
    target_link_libraries(AiDAProtectorVerify PRIVATE bcrypt advapi32)
    set_target_properties(AiDAProtectorVerify PROPERTIES
        OUTPUT_NAME "aida_protector_verify"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_executable(AiDAProtectorTest tools/protector/test_runner.cpp)
    target_compile_definitions(AiDAProtectorTest PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    target_compile_options(AiDAProtectorTest PRIVATE
        /W4 /EHsc /O2 /Zc:__cplusplus /permissive- /MD
    )
    set_target_properties(AiDAProtectorTest PROPERTIES
        OUTPUT_NAME "aida_protector_test"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_executable(AiDATestPayload tools/protector/test_payload/test_payload.c)
    target_compile_options(AiDATestPayload PRIVATE /W3 /O2 /MD)
    set_target_properties(AiDATestPayload PROPERTIES
        OUTPUT_NAME "aida_test_payload"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )
endif()

if(BUILD_PROTECTOR)
    if(TARGET AiDAStandalone)
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND $<TARGET_FILE:AiDAProtector>
                --input "$<TARGET_FILE:AiDAStandalone>"
                --output "$<TARGET_FILE:AiDAStandalone>"
                --all --verbose
            COMMENT "Protecting AiDAStandalone.exe..."
            VERBATIM
        )
        add_dependencies(AiDAStandalone AiDAProtector)
    endif()

    if(TARGET AiDA_ARC)
        add_custom_command(TARGET AiDA_ARC POST_BUILD
            COMMAND $<TARGET_FILE:AiDAProtector>
                --input "$<TARGET_FILE:AiDA_ARC>"
                --output "$<TARGET_FILE:AiDA_ARC>"
                --all --verbose
            COMMENT "Protecting aida_core.dll..."
            VERBATIM
        )
        add_dependencies(AiDA_ARC AiDAProtector)
    endif()

    if(TARGET AiDA)
        add_custom_command(TARGET AiDA POST_BUILD
            COMMAND $<TARGET_FILE:AiDAProtector>
                --input "$<TARGET_FILE:AiDA>"
                --output "$<TARGET_FILE:AiDA>"
                --all --verbose
            COMMENT "Protecting AiDA.dll..."
            VERBATIM
        )
        add_dependencies(AiDA AiDAProtector)
    endif()
endif()
