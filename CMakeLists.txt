cmake_minimum_required(VERSION 3.25)

set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0141 NEW)

project(AiDA
    VERSION   1.2.8
    LANGUAGES C CXX ASM_MASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_program(AIDA_SCCACHE_PROGRAM sccache)
if(AIDA_SCCACHE_PROGRAM)
    message(STATUS "AiDA: sccache enabled for C++ at ${AIDA_SCCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   "" CACHE STRING "compiler launcher (disabled for C)" FORCE)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${AIDA_SCCACHE_PROGRAM}" CACHE STRING "compiler launcher (sccache)" FORCE)
endif()

if(MSVC)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo,Release>:Embedded>")

    if(CMAKE_GENERATOR MATCHES "Ninja")
        set(_aida_rule_launch_compile "\"${CMAKE_COMMAND}\" -E chdir \"${CMAKE_BINARY_DIR}\"")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${_aida_rule_launch_compile}")
        cmake_host_system_information(RESULT _aida_logical_cpus QUERY NUMBER_OF_LOGICAL_CORES)
        if(NOT _aida_logical_cpus OR _aida_logical_cpus LESS 4)
            set(_aida_logical_cpus 8)
        endif()
        math(EXPR _aida_heavy_pool "(${_aida_logical_cpus} + 1) / 2")
        if(_aida_heavy_pool LESS 2)
            set(_aida_heavy_pool 2)
        endif()
        set_property(GLOBAL PROPERTY JOB_POOLS
            aida_compile=${_aida_logical_cpus}
            aida_heavy_compile=${_aida_heavy_pool}
            aida_serial_compile=1)
        set(CMAKE_JOB_POOL_COMPILE aida_compile)
    endif()

    foreach(_aida_flagset
        CMAKE_C_FLAGS CMAKE_CXX_FLAGS
        CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_MINSIZEREL)
        if(DEFINED ${_aida_flagset})
            string(REGEX REPLACE "[ \t]*/Z[Ii7]([ \t]|$)" " " ${_aida_flagset} "${${_aida_flagset}}")
            string(REGEX REPLACE "[ \t]*/FS([ \t]|$)"     " " ${_aida_flagset} "${${_aida_flagset}}")
        endif()
    endforeach()

    if(NOT AIDA_SCCACHE_PROGRAM AND NOT CMAKE_GENERATOR MATCHES "Ninja")
        add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/MP>)
    endif()
endif()

option(AIDA_ENABLE_LTCG "Enable /GL + /LTCG on AiDA.dll and aida_core.dll (slower link, marginally faster runtime)" OFF)
option(AIDA_FAST_LINK   "Use /DEBUG (default) instead of /DEBUG:FULL for faster linking" ON)
option(AIDA_ARC_ENCRYPT_IMPORTS "Enable --encrypt-imports for ARC (requires api-set resolver in payload.c — W1c-payload)" OFF)
option(AIDA_HARDEN_RELEASE "Enable MSVC compiler/linker hardening (/GS /guard:cf /guard:ehcont /guard:xfg /Qspectre /sdl /CETCOMPAT /HIGHENTROPYVA /NXCOMPAT /DYNAMICBASE)" ON)
option(AIDA_HARDEN_XFG "Enable /guard:xfg (Extended Control Flow Guard, requires Win11 22H2+ runtime)" ON)

set(AIDA_BUILD_SEED_FILE "${CMAKE_BINARY_DIR}/build_seed.txt")
set(AIDA_BUILD_SEED "")
if(DEFINED ENV{AIDA_BUILD_SEED} AND NOT "$ENV{AIDA_BUILD_SEED}" STREQUAL "")
    set(AIDA_BUILD_SEED "$ENV{AIDA_BUILD_SEED}")
    string(STRIP "${AIDA_BUILD_SEED}" AIDA_BUILD_SEED)
    file(WRITE "${AIDA_BUILD_SEED_FILE}" "${AIDA_BUILD_SEED}")
    message(STATUS "AiDA: AIDA_BUILD_SEED supplied via environment")
elseif(EXISTS "${AIDA_BUILD_SEED_FILE}")
    file(READ "${AIDA_BUILD_SEED_FILE}" AIDA_BUILD_SEED)
    string(STRIP "${AIDA_BUILD_SEED}" AIDA_BUILD_SEED)
endif()

set(_aida_build_seed_needs_regen FALSE)
if("${AIDA_BUILD_SEED}" STREQUAL "")
    set(_aida_build_seed_needs_regen TRUE)
elseif(NOT "${AIDA_BUILD_SEED}" MATCHES "^[0-9a-fA-F]+$")
    set(_aida_build_seed_needs_regen TRUE)
else()
    string(LENGTH "${AIDA_BUILD_SEED}" _aida_build_seed_len_pre)
    if(NOT _aida_build_seed_len_pre EQUAL 64)
        set(_aida_build_seed_needs_regen TRUE)
    endif()
endif()
if(_aida_build_seed_needs_regen)
    if(WIN32)
        find_program(AIDA_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
        if(NOT AIDA_POWERSHELL_EXECUTABLE)
            message(FATAL_ERROR
                "AiDA build seed missing and PowerShell not found. Provide a 64-character "
                "lowercase hex AIDA_BUILD_SEED environment variable, or install PowerShell.")
        endif()
        execute_process(
            COMMAND "${AIDA_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive -Command
                "$bytes=New-Object byte[] 32; $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($bytes); $rng.Dispose(); -join ($bytes | ForEach-Object { $_.ToString('x2') })"
            OUTPUT_VARIABLE AIDA_BUILD_SEED_RAW
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE AIDA_BUILD_SEED_RC
        )
        if(NOT AIDA_BUILD_SEED_RC EQUAL 0)
            message(FATAL_ERROR
                "AiDA: failed to generate build seed via BCryptGenRandom-backed RNG (rc=${AIDA_BUILD_SEED_RC}).")
        endif()
        if(NOT AIDA_BUILD_SEED_RAW MATCHES "^[0-9a-fA-F]+$")
            message(FATAL_ERROR
                "AiDA: generated build seed contains invalid characters: ${AIDA_BUILD_SEED_RAW}")
        endif()
        string(LENGTH "${AIDA_BUILD_SEED_RAW}" AIDA_BUILD_SEED_LEN)
        if(NOT AIDA_BUILD_SEED_LEN EQUAL 64)
            message(FATAL_ERROR
                "AiDA: generated build seed has unexpected length ${AIDA_BUILD_SEED_LEN} (expected 64).")
        endif()
        set(AIDA_BUILD_SEED "${AIDA_BUILD_SEED_RAW}")
        file(WRITE "${AIDA_BUILD_SEED_FILE}" "${AIDA_BUILD_SEED}")
        message(STATUS "AiDA: generated 256-bit build seed via system RNG -> ${AIDA_BUILD_SEED_FILE}")
    else()
        message(FATAL_ERROR
            "AiDA: AIDA_BUILD_SEED missing or malformed; non-Windows configure must export "
            "a 64-character hex AIDA_BUILD_SEED environment variable.")
    endif()
endif()

string(LENGTH "${AIDA_BUILD_SEED}" _aida_build_seed_len_check)
if(NOT _aida_build_seed_len_check EQUAL 64)
    message(FATAL_ERROR
        "AiDA: build seed length is ${_aida_build_seed_len_check}; expected 64-character hex.")
endif()
if(NOT "${AIDA_BUILD_SEED}" MATCHES "^[0-9a-fA-F]+$")
    message(FATAL_ERROR
        "AiDA: build seed contains non-hex characters: ${AIDA_BUILD_SEED}")
endif()

string(TOLOWER "${AIDA_BUILD_SEED}" AIDA_BUILD_SEED)

set(AIDA_BUILD_SEED_BIN "${CMAKE_BINARY_DIR}/build_seed.bin")
set(_aida_build_seed_byte_index 0)
set(_aida_build_seed_byte_list "")
while(_aida_build_seed_byte_index LESS 32)
    math(EXPR _aida_build_seed_offset "${_aida_build_seed_byte_index} * 2")
    string(SUBSTRING "${AIDA_BUILD_SEED}" ${_aida_build_seed_offset} 2 _aida_build_seed_byte_hex)
    list(APPEND _aida_build_seed_byte_list "0x${_aida_build_seed_byte_hex}")
    math(EXPR _aida_build_seed_byte_index "${_aida_build_seed_byte_index} + 1")
endwhile()
string(REPLACE ";" ", " AIDA_ARC_BUILD_SEED_BYTES_INLINE "${_aida_build_seed_byte_list}")
set(AIDA_ARC_BUILD_SEED_BYTES "        ${AIDA_ARC_BUILD_SEED_BYTES_INLINE}")

if(WIN32)
    if(NOT DEFINED AIDA_POWERSHELL_EXECUTABLE OR NOT AIDA_POWERSHELL_EXECUTABLE)
        find_program(AIDA_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
    endif()
    if(NOT AIDA_POWERSHELL_EXECUTABLE)
        message(FATAL_ERROR "AiDA: PowerShell required to materialize build_seed.bin and compute commitment.")
    endif()
    execute_process(
        COMMAND "${AIDA_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive -Command
            "$hex='${AIDA_BUILD_SEED}'; $bytes=for ($i=0; $i -lt $hex.Length; $i+=2) { [Convert]::ToByte($hex.Substring($i,2),16) }; [System.IO.File]::WriteAllBytes('${AIDA_BUILD_SEED_BIN}', [byte[]]$bytes); $acl=Get-Acl '${AIDA_BUILD_SEED_BIN}'; $acl.SetAccessRuleProtection($true, $false); $rule=New-Object System.Security.AccessControl.FileSystemAccessRule([System.Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'Allow'); $acl.AddAccessRule($rule); Set-Acl '${AIDA_BUILD_SEED_BIN}' $acl"
        RESULT_VARIABLE _aida_seed_bin_rc
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT _aida_seed_bin_rc EQUAL 0)
        message(WARNING "AiDA: failed to materialize build_seed.bin (rc=${_aida_seed_bin_rc}); HKDF still operates from embedded constant.")
    endif()
    execute_process(
        COMMAND "${AIDA_POWERSHELL_EXECUTABLE}" -NoLogo -NoProfile -NonInteractive -Command
            "$hex='${AIDA_BUILD_SEED}'; $bytes=for ($i=0; $i -lt $hex.Length; $i+=2) { [Convert]::ToByte($hex.Substring($i,2),16) }; $sha=[System.Security.Cryptography.SHA256]::Create(); $h=$sha.ComputeHash([byte[]]$bytes); -join ($h | ForEach-Object { $_.ToString('x2') })"
        OUTPUT_VARIABLE AIDA_BUILD_COMMITMENT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _aida_commitment_rc
    )
    string(LENGTH "${AIDA_BUILD_COMMITMENT}" _aida_commitment_len)
    if(NOT _aida_commitment_rc EQUAL 0 OR NOT _aida_commitment_len EQUAL 64 OR NOT "${AIDA_BUILD_COMMITMENT}" MATCHES "^[0-9a-fA-F]+$")
        message(FATAL_ERROR "AiDA: failed to compute build seed SHA-256 commitment (rc=${_aida_commitment_rc} value='${AIDA_BUILD_COMMITMENT}').")
    endif()
    string(TOLOWER "${AIDA_BUILD_COMMITMENT}" AIDA_BUILD_COMMITMENT)
else()
    find_program(AIDA_OPENSSL_EXECUTABLE NAMES openssl)
    if(NOT AIDA_OPENSSL_EXECUTABLE)
        message(FATAL_ERROR "AiDA: openssl(1) not found; required to compute build seed commitment on non-Windows.")
    endif()
    file(WRITE "${AIDA_BUILD_SEED_BIN}.hex" "${AIDA_BUILD_SEED}")
    execute_process(
        COMMAND "${AIDA_OPENSSL_EXECUTABLE}" dgst -sha256 -hex
        INPUT_FILE "${AIDA_BUILD_SEED_BIN}.hex"
        OUTPUT_VARIABLE AIDA_BUILD_COMMITMENT_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _aida_commitment_rc
    )
    if(NOT _aida_commitment_rc EQUAL 0)
        message(FATAL_ERROR "AiDA: failed to compute build seed commitment via openssl (rc=${_aida_commitment_rc}).")
    endif()
    string(REGEX REPLACE ".*= " "" AIDA_BUILD_COMMITMENT "${AIDA_BUILD_COMMITMENT_RAW}")
    string(TOLOWER "${AIDA_BUILD_COMMITMENT}" AIDA_BUILD_COMMITMENT)
endif()

string(LENGTH "${AIDA_BUILD_COMMITMENT}" _aida_commitment_len_final)
if(NOT _aida_commitment_len_final EQUAL 64 OR NOT "${AIDA_BUILD_COMMITMENT}" MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "AiDA: build commitment is malformed: ${AIDA_BUILD_COMMITMENT}")
endif()

set(_aida_build_commitment_byte_index 0)
set(_aida_build_commitment_byte_list "")
while(_aida_build_commitment_byte_index LESS 32)
    math(EXPR _aida_build_commitment_offset "${_aida_build_commitment_byte_index} * 2")
    string(SUBSTRING "${AIDA_BUILD_COMMITMENT}" ${_aida_build_commitment_offset} 2 _aida_build_commitment_byte_hex)
    list(APPEND _aida_build_commitment_byte_list "0x${_aida_build_commitment_byte_hex}")
    math(EXPR _aida_build_commitment_byte_index "${_aida_build_commitment_byte_index} + 1")
endwhile()
string(REPLACE ";" ", " AIDA_ARC_BUILD_COMMITMENT_BYTES_INLINE "${_aida_build_commitment_byte_list}")
set(AIDA_ARC_BUILD_COMMITMENT_BYTES "        ${AIDA_ARC_BUILD_COMMITMENT_BYTES_INLINE}")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/core/arc/arc_build_seed.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/arc_build_seed.hpp"
    @ONLY
)
message(STATUS "AiDA: build_seed.bin materialized; commitment=${AIDA_BUILD_COMMITMENT}")

if(MSVC AND AIDA_HARDEN_RELEASE)
    add_library(aida_hardening INTERFACE)
    target_compile_options(aida_hardening INTERFACE
        $<$<COMPILE_LANGUAGE:C,CXX>:/GS>
        $<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf>
        $<$<COMPILE_LANGUAGE:C,CXX>:/guard:ehcont>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Qspectre>
        $<$<COMPILE_LANGUAGE:CXX>:/sdl>
        $<$<AND:$<BOOL:${AIDA_HARDEN_XFG}>,$<COMPILE_LANGUAGE:C,CXX>>:/guard:xfg>
    )
    target_link_options(aida_hardening INTERFACE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /CETCOMPAT
        /guard:cf
        /guard:ehcont
        /force:guardehcont
    )
endif()

if(WIN32 AND MSVC)
    add_executable(aida_build_seed_gen tools/build_seed/build_seed_gen.cpp)
    target_compile_options(aida_build_seed_gen PRIVATE /W4 /EHsc /O2 /MD /Zc:__cplusplus /permissive-)
    target_compile_definitions(aida_build_seed_gen PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(aida_build_seed_gen PRIVATE bcrypt)
    set_target_properties(aida_build_seed_gen PROPERTIES
        OUTPUT_NAME "aida_build_seed_gen"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_executable(aida_pdb_scrubber tools/pdb_scrubber/pdb_scrubber.cpp)
    target_compile_options(aida_pdb_scrubber PRIVATE /W4 /EHsc /O2 /MD /Zc:__cplusplus /permissive-)
    target_compile_definitions(aida_pdb_scrubber PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    set_target_properties(aida_pdb_scrubber PROPERTIES
        OUTPUT_NAME "aida_pdb_scrubber"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_subdirectory(tools/share_fingerprint_baker)
endif()

set(DEPS_DIR "${CMAKE_SOURCE_DIR}/.deps")

if(WIN32 AND MSVC)
    set(_aida_openssl_root "$ENV{OPENSSL_ROOT_DIR}")
    if(NOT _aida_openssl_root OR NOT EXISTS "${_aida_openssl_root}/include/openssl/ssl.h")
        foreach(_candidate
            "C:/Program Files/OpenSSL-Win64"
            "C:/Program Files/OpenSSL"
            "C:/OpenSSL-Win64"
        )
            if(EXISTS "${_candidate}/include/openssl/ssl.h")
                set(_aida_openssl_root "${_candidate}")
                break()
            endif()
        endforeach()
    endif()
    if(NOT _aida_openssl_root OR NOT EXISTS "${_aida_openssl_root}/include/openssl/ssl.h")
        message(FATAL_ERROR
            "OpenSSL headers not found. Set -DOPENSSL_ROOT_DIR=<path> or install "
            "OpenSSL (with static libs) under C:/Program Files/OpenSSL-Win64.")
    endif()
    set(_aida_openssl_lib_release "${_aida_openssl_root}/lib/VC/x64/MD")
    set(_aida_openssl_lib_debug   "${_aida_openssl_root}/lib/VC/x64/MDd")
    if(NOT EXISTS "${_aida_openssl_lib_release}/libssl_static.lib"
       OR NOT EXISTS "${_aida_openssl_lib_release}/libcrypto_static.lib")
        message(FATAL_ERROR
            "OpenSSL static libraries not present at ${_aida_openssl_lib_release}. "
            "Reinstall OpenSSL with the static-libs option enabled so AiDAStandalone "
            "can link without runtime DLL dependencies (libssl-3-x64.dll / libcrypto-3-x64.dll).")
    endif()

    add_library(aida_openssl_crypto STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_crypto PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release}/libcrypto_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug}/libcrypto_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "ws2_32;crypt32;advapi32;user32;gdi32"
    )

    add_library(aida_openssl_ssl STATIC IMPORTED GLOBAL)
    set_target_properties(aida_openssl_ssl PROPERTIES
        IMPORTED_LOCATION                "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_RELEASE        "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_MINSIZEREL     "${_aida_openssl_lib_release}/libssl_static.lib"
        IMPORTED_LOCATION_DEBUG          "${_aida_openssl_lib_debug}/libssl_static.lib"
        INTERFACE_INCLUDE_DIRECTORIES    "${_aida_openssl_root}/include"
        INTERFACE_LINK_LIBRARIES         "aida_openssl_crypto"
    )

    set(OPENSSL_FOUND TRUE CACHE BOOL "" FORCE)
    set(OPENSSL_INCLUDE_DIR "${_aida_openssl_root}/include" CACHE PATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY "${_aida_openssl_lib_release}/libssl_static.lib" CACHE FILEPATH "" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY "${_aida_openssl_lib_release}/libcrypto_static.lib" CACHE FILEPATH "" FORCE)
    set(OPENSSL_LIBRARIES "${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY}" CACHE STRING "" FORCE)
    set(OPENSSL_VERSION "3.0.0" CACHE STRING "" FORCE)

    message(STATUS "AiDA: OpenSSL static linking enabled (root=${_aida_openssl_root})")
endif()

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
        set(_zycore_opts_scoped)
        foreach(_opt IN LISTS _zycore_opts)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zycore_opts_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zycore_opts_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zycore PROPERTIES INTERFACE_COMPILE_OPTIONS "${_zycore_opts_scoped}")
    endif()
    get_target_property(_zycore_priv Zycore COMPILE_OPTIONS)
    if(_zycore_priv)
        set(_zycore_priv_scoped)
        foreach(_opt IN LISTS _zycore_priv)
            if(_opt STREQUAL "/wd4201" OR _opt MATCHES "^/wd[0-9]+$" OR _opt MATCHES "^/W[0-9]$" OR _opt STREQUAL "/WX")
                list(APPEND _zycore_priv_scoped "$<$<COMPILE_LANGUAGE:C,CXX>:${_opt}>")
            else()
                list(APPEND _zycore_priv_scoped "${_opt}")
            endif()
        endforeach()
        set_target_properties(Zycore PROPERTIES COMPILE_OPTIONS "${_zycore_priv_scoped}")
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
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET lua54_static PROPERTY JOB_POOL_COMPILE aida_serial_compile)
    endif()
    target_compile_options(lua54_static PRIVATE /W3 /wd4244 /wd4702 /wd4334)
    target_compile_definitions(lua54_static PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set(sol2_SOURCE_DIR "${DEPS_DIR}/sol2")
add_subdirectory("${sol2_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/.deps/sol2")

if(MSVC AND TARGET x86_64-softmmu)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET x86_64-softmmu PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
    target_compile_options(x86_64-softmmu PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/wd4319>)
endif()
if(MSVC AND TARGET unicorn-common)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET unicorn-common PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
    target_compile_options(unicorn-common PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:/wd4319>)
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
set(GHIDRA_PREBUILT_SLA "${GHIDRA_SPECS_SRC_DIR}/x86-64.sla")

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
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET libdecomp_aida PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
    endif()
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
if(EXISTS "${GHIDRA_PREBUILT_SLA}")
    set_property(TARGET ghidra_sleigh_compiler PROPERTY EXCLUDE_FROM_ALL TRUE)
endif()
if(MSVC)
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set_property(TARGET ghidra_sleigh_compiler PROPERTY JOB_POOL_COMPILE aida_serial_compile)
    endif()
    target_compile_options(ghidra_sleigh_compiler PRIVATE /W0 /EHsc /MD /O2)
endif()
target_link_libraries(ghidra_sleigh_compiler PRIVATE zlibstatic)

file(MAKE_DIRECTORY "${GHIDRA_SPECS_OUTPUT_DIR}")

if(EXISTS "${GHIDRA_PREBUILT_SLA}")
    add_custom_command(
        OUTPUT "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${GHIDRA_PREBUILT_SLA}" "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
        DEPENDS "${GHIDRA_PREBUILT_SLA}"
        COMMENT "Copying prebuilt SLEIGH: x86-64.sla"
        VERBATIM
    )
else()
    add_custom_command(
        OUTPUT "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
        COMMAND ghidra_sleigh_compiler "${GHIDRA_SPECS_SRC_DIR}/x86-64.slaspec" "${GHIDRA_SPECS_OUTPUT_DIR}/x86-64.sla"
        DEPENDS ghidra_sleigh_compiler "${GHIDRA_SPECS_SRC_DIR}/x86-64.slaspec"
        WORKING_DIRECTORY "${GHIDRA_SPECS_SRC_DIR}"
        COMMENT "Compiling SLEIGH: x86-64.slaspec -> x86-64.sla"
        VERBATIM
    )
endif()

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
# When the built drivers/mapper change (WhosWho.sys, Sentinel.sys,
# WindMapper.exe) -- or, as a fallback, when the legacy hex dumps
# WhosWho.c / Sentinel.c / WindMapper.c change -- the corresponding
# encrypted headers are regenerated so driver_loader.cpp picks up the
# new bytes. The encrypt_*.py scripts now accept --from-binary, which
# regenerates the legacy .c hex dump from the binary directly so the
# manual HxD round-trip is no longer required.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    # The driver/mapper .vcxproj files hardcode <OutDir> to
    # ${CMAKE_SOURCE_DIR}/build-ninja/Release/, so the built binaries
    # land at a fixed location independent of CMAKE_BINARY_DIR. Expose
    # as cache vars so users with custom .vcxproj OutDirs can override.
    set(AIDA_DRIVER_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/build-ninja/Release"
        CACHE PATH "Directory where WhosWho.sln / Sentinel.sln / WindMapper.sln deposit their build outputs")
    set(WHOSWHO_BINARY    "${AIDA_DRIVER_OUTPUT_DIR}/WhosWho.sys"
        CACHE FILEPATH "Path to the built WhosWho.sys")
    set(SENTINEL_BINARY   "${AIDA_DRIVER_OUTPUT_DIR}/Sentinel.sys"
        CACHE FILEPATH "Path to the built Sentinel.sys")
    set(WINDMAPPER_BINARY "${AIDA_DRIVER_OUTPUT_DIR}/WindMapper.exe"
        CACHE FILEPATH "Path to the built WindMapper.exe")
    set(SHADOWFS_BINARY   "${AIDA_DRIVER_OUTPUT_DIR}/AiDAShadowFS.sys"
        CACHE FILEPATH "Path to the built AiDAShadowFS.sys")

    set(WHOSWHO_HEX    "${CMAKE_CURRENT_SOURCE_DIR}/WhosWho.c")
    set(SENTINEL_HEX   "${CMAKE_CURRENT_SOURCE_DIR}/Sentinel.c")
    set(WINDMAPPER_HEX "${CMAKE_CURRENT_SOURCE_DIR}/WindMapper.c")
    set(SHADOWFS_HEX   "${CMAKE_CURRENT_SOURCE_DIR}/AiDAShadowFS.c")

    set(WHOSWHO_SCRIPT    "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_whoswho.py")
    set(SENTINEL_SCRIPT   "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_sentinel.py")
    set(WINDMAPPER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_windmapper.py")
    set(SHADOWFS_SCRIPT   "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_shadowfs.py")

    set(ENCRYPT_DRIVERS_STAMPS "")

    # Per-driver rule generator: prefer the built binary; fall back to
    # the legacy .c hex dump; if neither input exists, skip the rule
    # entirely so Ninja does not error on phantom deps and the existing
    # encrypted header in src/ stays authoritative.
    function(_aida_emit_encrypt_rule short_name binary_path hex_path script_path stamp_path comment_text)
        set(rule_deps "${script_path}")
        set(rule_command_args "")
        set(rule_input_label "")
        if(EXISTS "${binary_path}")
            list(APPEND rule_deps "${binary_path}")
            set(rule_command_args --from-binary "${binary_path}")
            set(rule_input_label "${binary_path}")
        elseif(EXISTS "${hex_path}")
            list(APPEND rule_deps "${hex_path}")
            set(rule_command_args "")
            set(rule_input_label "${hex_path}")
        else()
            message(STATUS "encrypt_drivers: ${short_name} -- neither ${binary_path} nor ${hex_path} found; "
                           "skipping rule (existing encrypted header will be used as-is). "
                           "Build the .sln (or restore the .c hex dump) and re-run cmake configure to enable.")
            return()
        endif()
        message(STATUS "encrypt_drivers: ${short_name} <- ${rule_input_label}")
        add_custom_command(
            OUTPUT "${stamp_path}"
            COMMAND ${Python3_EXECUTABLE} "${script_path}" ${rule_command_args}
            COMMAND ${CMAKE_COMMAND} -E touch "${stamp_path}"
            DEPENDS ${rule_deps}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMENT "${comment_text}"
            VERBATIM
        )
        set(ENCRYPT_DRIVERS_STAMPS "${ENCRYPT_DRIVERS_STAMPS};${stamp_path}" PARENT_SCOPE)
    endfunction()

    _aida_emit_encrypt_rule("WhosWho"
        "${WHOSWHO_BINARY}" "${WHOSWHO_HEX}" "${WHOSWHO_SCRIPT}"
        "${CMAKE_BINARY_DIR}/whoswho_encrypted.stamp"
        "Encrypting WhosWho -> whoswho_encrypted.h")
    _aida_emit_encrypt_rule("Sentinel"
        "${SENTINEL_BINARY}" "${SENTINEL_HEX}" "${SENTINEL_SCRIPT}"
        "${CMAKE_BINARY_DIR}/sentinel_encrypted.stamp"
        "Encrypting Sentinel -> sentinel_encrypted.h")
    _aida_emit_encrypt_rule("WindMapper"
        "${WINDMAPPER_BINARY}" "${WINDMAPPER_HEX}" "${WINDMAPPER_SCRIPT}"
        "${CMAKE_BINARY_DIR}/windmapper_encrypted.stamp"
        "Encrypting WindMapper -> windmapper_data.inc")
    _aida_emit_encrypt_rule("AiDAShadowFS"
        "${SHADOWFS_BINARY}" "${SHADOWFS_HEX}" "${SHADOWFS_SCRIPT}"
        "${CMAKE_BINARY_DIR}/shadowfs_encrypted.stamp"
        "Encrypting AiDAShadowFS -> shadowfs_encrypted.h")

    if(ENCRYPT_DRIVERS_STAMPS)
        add_custom_target(encrypt_drivers DEPENDS ${ENCRYPT_DRIVERS_STAMPS})
        add_custom_target(reencrypt_drivers
            COMMAND ${CMAKE_COMMAND} -E remove ${ENCRYPT_DRIVERS_STAMPS}
            COMMAND ${CMAKE_COMMAND} --build "${CMAKE_BINARY_DIR}" --target encrypt_drivers
            COMMENT "Force-regenerating encrypted driver/mapper headers from current binaries"
            VERBATIM
        )
    else()
        add_custom_target(encrypt_drivers
            COMMAND ${CMAKE_COMMAND} -E echo
                "encrypt_drivers: no inputs found (no .sys/.exe and no .c); using existing src/*_encrypted.h as-is."
        )
    endif()
else()
    message(WARNING "Python3 not found -- encrypt_drivers target disabled. "
                    "Re-run encrypt scripts manually after rebuilding WhosWho.sys / Sentinel.sys / WindMapper.exe.")
endif()

# Track the generated encrypted headers so MSVC recompiles driver_loader.cpp
# when they change (even outside the encrypt_drivers flow).
set(ENCRYPTED_DRIVER_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/whoswho_encrypted.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sentinel_encrypted.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/windmapper_embedded.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/windmapper_data.inc"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/shadowfs_encrypted.h"
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

    option(BUILD_BINPROTO_TEST "Build the binary protocol test executable" ON)

    if(BUILD_BINPROTO_TEST)
        add_executable(BINPROTO_TEST
            tools/binproto_test/binproto_test.cpp
        )

        target_include_directories(BINPROTO_TEST PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/core/anti-tamper"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src/core"
            "${CMAKE_CURRENT_SOURCE_DIR}"
        )

        target_compile_definitions(BINPROTO_TEST PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            BINPROTO_TEST_BUILD=1
        )

        target_compile_options(BINPROTO_TEST PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
            /bigobj
        )

        target_link_libraries(BINPROTO_TEST PRIVATE
            aida_openssl_ssl
            aida_openssl_crypto
            ws2_32
            crypt32
            bcrypt
            advapi32
            user32
            gdi32
        )

        set_target_properties(BINPROTO_TEST PROPERTIES
            OUTPUT_NAME "BINPROTO_TEST"
        )
    endif()

    option(BUILD_MALWARE_SAFE_TESTER "Build MalwareSafeTester console harness" ON)

    if(BUILD_MALWARE_SAFE_TESTER)
        add_executable(MalwareSafeTester
            tools/malware_safe_tester/src/main.cpp
        )

        target_compile_definitions(MalwareSafeTester PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            UNICODE
            _UNICODE
        )

        target_compile_options(MalwareSafeTester PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/W3>
            $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:CXX>:/MD>
            $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
        )

        target_link_libraries(MalwareSafeTester PRIVATE
            advapi32
            user32
            kernel32
            ws2_32
            psapi
            wininet
        )

        target_link_options(MalwareSafeTester PRIVATE
            /SUBSYSTEM:CONSOLE
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
        )

        set_target_properties(MalwareSafeTester PROPERTIES
            OUTPUT_NAME "MalwareSafeTester"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
            RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}"
        )
    endif()

    option(BUILD_AIDA_STANDALONE "Build AiDA standalone application" ON)

    if(BUILD_AIDA_STANDALONE)
        set(STANDALONE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src/standalone/src")

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
            "${STANDALONE_ROOT}/core/mcp/mcp_standalone.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_standalone_tools.cpp"
            "${STANDALONE_ROOT}/core/runtime/standalone_driver.cpp"
            "${STANDALONE_ROOT}/core/runtime/run_target.cpp"
            "${STANDALONE_ROOT}/core/runtime/shadow_fs_client.cpp"
            "${STANDALONE_ROOT}/core/ai/standalone_ai_client.cpp"
            "${STANDALONE_ROOT}/core/ai/standalone_chat.cpp"
            "${STANDALONE_ROOT}/core/runtime/standalone_license.cpp"
            "${STANDALONE_ROOT}/core/runtime/standalone_license_transport.cpp"
            "${STANDALONE_ROOT}/core/runtime/license_state.cpp"
            "${STANDALONE_ROOT}/core/runtime/gate_tokens.cpp"
            "${STANDALONE_ROOT}/core/crypto/keys_a.cpp"
            "${STANDALONE_ROOT}/core/crypto/keys_b.cpp"
            "${STANDALONE_ROOT}/core/crypto/keys_c.cpp"
            "${STANDALONE_ROOT}/core/crypto/keys_d.cpp"
            "${STANDALONE_ROOT}/core/crypto/wb_ed25519.cpp"
            "${STANDALONE_ROOT}/core/arc/plaintext_window.cpp"
            "${STANDALONE_ROOT}/core/tools/driver_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/network_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/network/net_security_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/emulation_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/editor/code_editor.cpp"
            "${STANDALONE_ROOT}/core/disasm/disasm_view.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pretty_xml_encode.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_function_db.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_arch_map.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_load_image.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_pcode_fixup.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_print_c.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_scope.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_architecture.cpp"
            "${STANDALONE_ROOT}/core/disasm/ghidra_adapters/aida_code_xml_parse.cpp"
            "${STANDALONE_ROOT}/core/editor/hex_view.cpp"
            "${STANDALONE_ROOT}/core/editor/image_view.cpp"
            "${STANDALONE_ROOT}/core/ui/chat_render.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_client.cpp"
            "${STANDALONE_ROOT}/core/mcp/mcp_marketplace.cpp"
            "${STANDALONE_ROOT}/core/network/protocol_parser.cpp"
            "${STANDALONE_ROOT}/core/network/cert_generator.cpp"
            "${STANDALONE_ROOT}/core/network/mitm_proxy.cpp"
            "${STANDALONE_ROOT}/core/network/network_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/active_scanner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/api_definition.cpp"
            "${STANDALONE_ROOT}/core/network/burp/api_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/audit_http.cpp"
            "${STANDALONE_ROOT}/core/network/burp/auth_lab.cpp"
            "${STANDALONE_ROOT}/core/network/burp/bambda.cpp"
            "${STANDALONE_ROOT}/core/network/burp/browser_launch.cpp"
            "${STANDALONE_ROOT}/core/network/burp/browser_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_api_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_auth_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_bambda_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_browser_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_collaborator_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_comparer_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_csp_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_intruder_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_jwt_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_logger.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_logger_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_module.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_mr_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_recon_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_scanner_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_sequencer_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_session_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_target_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_tech_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/burp_upstream_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/collaborator.cpp"
            "${STANDALONE_ROOT}/core/network/burp/collaborator_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/comparer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/comparer_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/content_discovery.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_bridge_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/camoufox_install.cpp"
            "${STANDALONE_ROOT}/core/network/burp/cookie_jar.cpp"
            "${STANDALONE_ROOT}/core/network/burp/crawler.cpp"
            "${STANDALONE_ROOT}/core/network/burp/csp_analyzer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/csp_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/dom_xss_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/dom_xss_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/graphql.cpp"
            "${STANDALONE_ROOT}/core/network/burp/headless_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/headless_view_mcp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/graphql_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/h2_editor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/h2_editor_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/insertion_points.cpp"
            "${STANDALONE_ROOT}/core/network/burp/intruder_engine.cpp"
            "${STANDALONE_ROOT}/core/network/burp/intruder_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/issue.cpp"
            "${STANDALONE_ROOT}/core/network/burp/jwt_lab.cpp"
            "${STANDALONE_ROOT}/core/network/burp/jwt_lab_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/match_replace.cpp"
            "${STANDALONE_ROOT}/core/network/burp/match_replace_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/param_miner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/passive_scanner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/payload_library.cpp"
            "${STANDALONE_ROOT}/core/network/burp/recon_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/report_generator.cpp"
            "${STANDALONE_ROOT}/core/network/burp/report_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_module.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scope.cpp"
            "${STANDALONE_ROOT}/core/network/burp/sequencer.cpp"
            "${STANDALONE_ROOT}/core/network/burp/sequencer_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/session_handler.cpp"
            "${STANDALONE_ROOT}/core/network/burp/session_handler_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/site_map.cpp"
            "${STANDALONE_ROOT}/core/network/burp/subdomain_enum.cpp"
            "${STANDALONE_ROOT}/core/network/burp/tech_fingerprint.cpp"
            "${STANDALONE_ROOT}/core/network/burp/upstream_chain.cpp"
            "${STANDALONE_ROOT}/core/network/burp/upstream_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/ws_editor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/ws_editor_view.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cmdi.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_cors.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_csp.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_csrf.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_deserial.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_dom_xss.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_host_header.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_idor.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_jwt_scan.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ldap.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_log4j.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_method_override.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_nosqli.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_open_redirect.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_param_miner.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_path_traversal.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_protopol.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_race_condition.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_smuggling.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_sqli.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ssrf.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_ssti.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xpath.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xss.cpp"
            "${STANDALONE_ROOT}/core/network/burp/scanner_modules/module_xxe.cpp"
            "${STANDALONE_ROOT}/core/tools/coding_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/workflow_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/tools/script_engine.cpp"
            "${STANDALONE_ROOT}/core/scanner/memory_scanner.cpp"
            "${STANDALONE_ROOT}/core/scanner/memory_scanner_view.cpp"
            "${STANDALONE_ROOT}/core/scanner/scanner_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_engine.cpp"
            "${STANDALONE_ROOT}/core/debugger/debugger_view.cpp"
            "${STANDALONE_ROOT}/core/disasm/pseudocode_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/struct_recon_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/fuzzer_view.cpp"
            "${STANDALONE_ROOT}/core/analysis/analysis_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/disasm/disasm_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/disasm/decompile_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/analysis/pdb_downloader.cpp"
            "${STANDALONE_ROOT}/core/runtime/arc_loader.cpp"
            src/driver_loader.cpp
            driver/comm.cpp
            src/net_security.cpp
            src/emulation_engine.cpp
            "${STANDALONE_ROOT}/core/network/tls_exporter.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_store.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_http.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_codex.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_copilot.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_claude_code.cpp"
            "${STANDALONE_ROOT}/core/auth/auth_view.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_catalog.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_transforms.cpp"
            "${STANDALONE_ROOT}/core/ai/provider_view.cpp"
            "${STANDALONE_ROOT}/core/infra/event_bus.cpp"
            "${STANDALONE_ROOT}/core/analysis/binary_map.cpp"
            "${STANDALONE_ROOT}/core/session/session_store.cpp"
            "${STANDALONE_ROOT}/core/ai/agent_registry.cpp"
            "${STANDALONE_ROOT}/core/ai/agent_task.cpp"
            "${STANDALONE_ROOT}/core/session/compaction.cpp"
            "${STANDALONE_ROOT}/core/session/cost_calculator.cpp"
            "${STANDALONE_ROOT}/core/session/analysis_session.cpp"
            "${STANDALONE_ROOT}/core/session/session_health.cpp"
            "${STANDALONE_ROOT}/core/tools/session_tools_standalone.cpp"
            "${STANDALONE_ROOT}/core/ai/command_registry.cpp"
            "${STANDALONE_ROOT}/core/ai/settings_overlay.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_registry.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_view.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_memory.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_thread.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_remote.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_anti_debug.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_module.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_network_query.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_network_action.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_dll.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_tamper.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_session.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_anti_dump.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_evidence.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_dma_canary.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_debug_attach.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_hv_detect.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_target_latch.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_sandbox.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_net_logging.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_shadowfs.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_verify.cpp"
            "${STANDALONE_ROOT}/core/testlab/test_lab_features_sentinel.cpp"
            "${DEPS_DIR}/sqlite-amalgamation-3530000/sqlite3.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/hardware_id/hardware_id.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/hardware_id/hardware_id_v2.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/shared/telemetry/telemetry_client.cpp"
        )

        set_source_files_properties(
            "${DEPS_DIR}/sqlite-amalgamation-3530000/sqlite3.c"
            PROPERTIES
                COMPILE_DEFINITIONS "SQLITE_THREADSAFE=1;SQLITE_DQS=0;SQLITE_OMIT_DEPRECATED;SQLITE_DEFAULT_MEMSTATUS=0;SQLITE_DEFAULT_WAL_SYNCHRONOUS=1;SQLITE_LIKE_DOESNT_MATCH_BLOBS;SQLITE_MAX_EXPR_DEPTH=0;SQLITE_OMIT_DECLTYPE;SQLITE_OMIT_PROGRESS_CALLBACK;SQLITE_OMIT_SHARED_CACHE;SQLITE_USE_ALLOCA"
                COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:C>:/wd4146>;$<$<COMPILE_LANGUAGE:C>:/wd4244>;$<$<COMPILE_LANGUAGE:C>:/wd4267>;$<$<COMPILE_LANGUAGE:C>:/wd4996>"
        )

        set(IMGUI_SOURCES
            "${imgui_SOURCE_DIR}/imgui.cpp"
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
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${STANDALONE_ROOT}"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/arc"
            "${STANDALONE_ROOT}/core/ai"
            "${STANDALONE_ROOT}/core/auth"
            "${STANDALONE_ROOT}/core/debugger"
            "${STANDALONE_ROOT}/core/disasm"
            "${STANDALONE_ROOT}/core/emulation"
            "${STANDALONE_ROOT}/core/network"
            "${STANDALONE_ROOT}/core/scanner"
            "${STANDALONE_ROOT}/core/analysis"
            "${STANDALONE_ROOT}/core/editor"
            "${STANDALONE_ROOT}/core/tools"
            "${STANDALONE_ROOT}/core/session"
            "${STANDALONE_ROOT}/core/mcp"
            "${STANDALONE_ROOT}/core/runtime"
            "${STANDALONE_ROOT}/core/ui"
            "${STANDALONE_ROOT}/core/infra"
            "${STANDALONE_ROOT}/core/settings"
            "${STANDALONE_ROOT}/core/testlab"
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
            "${DEPS_DIR}/sqlite-amalgamation-3530000"
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
            GHIDRA_SPECS_DIR=${GHIDRA_SPECS_OUTPUT_DIR}
            AIDA_DEEP_STEAL=1
            AIDA_TEST_VMWARE_BYPASS=1
        )

        target_compile_options(AiDAStandalone PRIVATE
            /W3
            /wd4005
            /wd4099
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
            /bigobj
        )

        target_precompile_headers(AiDAStandalone PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:<Windows.h$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<vector$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<string$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<string_view$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<unordered_map$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<unordered_set$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<map$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<set$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<deque$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<list$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<array$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<queue$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<stack$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<thread$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<mutex$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<atomic$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<future$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<condition_variable$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<chrono$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<filesystem$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<fstream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<sstream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<iostream$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<algorithm$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<numeric$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<memory$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<functional$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<optional$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<variant$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<tuple$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<utility$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<type_traits$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdint$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstring$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdio$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cassert$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cmath$<ANGLE-R>>"
            "$<$<COMPILE_LANGUAGE:CXX>:<cstdlib$<ANGLE-R>>"
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
            aida_openssl_ssl
            aida_openssl_crypto
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
            $<IF:$<BOOL:${AIDA_FAST_LINK}>,/DEBUG,/DEBUG:FULL>
            /ENTRY:mainCRTStartup
            /NODEFAULTLIB:LIBCMT
            /IGNORE:4099
            "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
            /DELAYLOAD:libz3.dll
            /PDBALTPATH:none
            /EMITTOOLVERSIONINFO:NO
        )

        target_link_libraries(AiDAStandalone PRIVATE delayimp)
        if(TARGET aida_hardening)
            target_link_libraries(AiDAStandalone PRIVATE aida_hardening)
        endif()

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
            "${CMAKE_CURRENT_BINARY_DIR}/generated"
            "${STANDALONE_ROOT}/core/arc"
            "${STANDALONE_ROOT}/core"
            "${STANDALONE_ROOT}/core/ai"
            "${STANDALONE_ROOT}/core/auth"
            "${STANDALONE_ROOT}/core/debugger"
            "${STANDALONE_ROOT}/core/disasm"
            "${STANDALONE_ROOT}/core/emulation"
            "${STANDALONE_ROOT}/core/network"
            "${STANDALONE_ROOT}/core/scanner"
            "${STANDALONE_ROOT}/core/analysis"
            "${STANDALONE_ROOT}/core/editor"
            "${STANDALONE_ROOT}/core/tools"
            "${STANDALONE_ROOT}/core/session"
            "${STANDALONE_ROOT}/core/mcp"
            "${STANDALONE_ROOT}/core/runtime"
            "${STANDALONE_ROOT}/core/ui"
            "${STANDALONE_ROOT}/core/infra"
            "${STANDALONE_ROOT}/core/settings"
            "${STANDALONE_ROOT}"
            "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )

        target_compile_definitions(AiDA_ARC PRIVATE
            ARC_EXPORTS
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            AIDA_DEEP_STEAL=1
        )

        target_compile_options(AiDA_ARC PRIVATE
            /W3
            /EHsc
            /Zc:__cplusplus
            /permissive-
            /Zp8
            /MD
            /O2
            /bigobj
            $<$<BOOL:${AIDA_ENABLE_LTCG}>:/GL>
        )

        target_link_libraries(AiDA_ARC PRIVATE
            aida_openssl_ssl
            aida_openssl_crypto
            ws2_32
            iphlpapi
            ntdll
            bcrypt
            advapi32
            winhttp
        )

        target_link_options(AiDA_ARC PRIVATE
            $<IF:$<BOOL:${AIDA_FAST_LINK}>,/DEBUG,/DEBUG:FULL>
            $<$<BOOL:${AIDA_ENABLE_LTCG}>:/LTCG>
            /PDBALTPATH:none
            /EMITTOOLVERSIONINFO:NO
        )

        if(TARGET aida_hardening)
            target_link_libraries(AiDA_ARC PRIVATE aida_hardening)
        endif()

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
    src/aida_ipc.cpp
    src/graphrag.cpp
    src/ida_utils.cpp
    src/instance_registry.cpp
    src/license.cpp
    src/mcp_server.cpp
    src/settings.cpp
    src/driver_loader.cpp
    src/vuln/cfg_engine.cpp
    src/vuln/kernel_engine.cpp
    src/vuln/microcode_engine.cpp
    src/vuln/surface_engine.cpp
    src/vuln/taint_engine.cpp
    src/vuln/vuln_callsites.cpp
    src/vuln/vuln_strings.cpp
    src/vuln/vuln_tools.cpp
    src/vuln/smt_solver.cpp
    src/vuln/symbolic_engine.cpp
    src/vuln/verification_engine.cpp
    src/vuln/verification_tools.cpp
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
    src/aida_ipc.hpp
    src/aida_manual_map_proof.hpp
    src/aida_pro.hpp
    src/analysis_db.hpp
    src/anti_re.hpp
    src/graphrag.hpp
    src/ida_utils.hpp
    src/instance_registry.hpp
    src/license.hpp
    src/mcp_server.hpp
    src/obfuscation.hpp
    src/settings.hpp
    src/driver_loader.hpp
    src/vuln/microcode_engine.hpp
    src/vuln/taint_engine.hpp
    src/vuln/vuln_common.hpp
    src/vuln/vuln_signatures.hpp
    src/vuln/vuln_tools.hpp
    src/vuln/smt_solver.hpp
    src/vuln/symbolic_engine.hpp
    src/vuln/verification_engine.hpp
    src/vuln/verification_tools.hpp
    src/vuln/embedded_libz3.hpp
    src/whoswho_encrypted.h
    src/sentinel_encrypted.h
    src/windmapper_embedded.h
    src/shadowfs_encrypted.h
)

if(WIN32)
    set(Z3_DLL_PATH_FORWARD "${Z3_INSTALL_DIR}/bin/libz3.dll")
    string(REPLACE "\\" "/" Z3_DLL_PATH_FORWARD "${Z3_DLL_PATH_FORWARD}")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/aida_plugin_embedded.rc.in"
        "${CMAKE_BINARY_DIR}/aida_plugin_embedded.rc"
        @ONLY
    )
    list(APPEND AIDA_SOURCES "${CMAKE_BINARY_DIR}/aida_plugin_embedded.rc")
endif()

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
    "${TRITON_SOURCE_DIR}/src/libtriton/includes"
    "${CMAKE_BINARY_DIR}/.deps/triton/src/libtriton/includes"
    "${Z3_INCLUDE_DIRS}"
)

target_compile_definitions(AiDA PRIVATE
    __EA64__
    __X64__
    _CRT_SECURE_NO_WARNINGS
    CPPHTTPLIB_OPENSSL_SUPPORT
    NOMINMAX
    ATP_JIT_DISABLED=1
    TRITON_Z3_INTERFACE
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

target_link_libraries(AiDA PRIVATE Zydis unicorn triton)
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
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/Zp8>
        $<$<COMPILE_LANGUAGE:CXX>:/EHa>
        $<$<COMPILE_LANGUAGE:CXX>:/MD>
        $<$<COMPILE_LANGUAGE:CXX>:/GR->
        $<$<COMPILE_LANGUAGE:CXX>:/GF>
        $<$<COMPILE_LANGUAGE:CXX>:/Gy>
        $<$<COMPILE_LANGUAGE:CXX>:/Gw>
        $<$<COMPILE_LANGUAGE:CXX>:/Oi>
        $<$<COMPILE_LANGUAGE:CXX>:/Ob2>
        $<$<COMPILE_LANGUAGE:CXX>:/bigobj>
        $<$<AND:$<BOOL:${AIDA_ENABLE_LTCG}>,$<COMPILE_LANGUAGE:CXX>>:/GL>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4946>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4826>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4628>
        $<$<COMPILE_LANGUAGE:CXX>:/wd4718>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5219>
        $<$<COMPILE_LANGUAGE:CXX>:/wd5240>
    )

    target_precompile_headers(AiDA PRIVATE
        <Windows.h>
        <vector>
        <string>
        <string_view>
        <unordered_map>
        <unordered_set>
        <map>
        <set>
        <deque>
        <thread>
        <mutex>
        <atomic>
        <chrono>
        <filesystem>
        <fstream>
        <sstream>
        <algorithm>
        <memory>
        <functional>
        <optional>
        <cstdint>
        <cstring>
        <cstdio>
    )

    target_link_options(AiDA PRIVATE
        $<IF:$<BOOL:${AIDA_FAST_LINK}>,/DEBUG,/DEBUG:FULL>
        /OPT:REF,ICF
        /RELEASE
        $<$<BOOL:${AIDA_ENABLE_LTCG}>:/LTCG>
        /PDBALTPATH:none
        /EMITTOOLVERSIONINFO:NO
        /DELAYLOAD:libz3.dll
    )

    target_link_libraries(AiDA PRIVATE delayimp)

    if(TARGET aida_hardening)
        target_link_libraries(AiDA PRIVATE aida_hardening)
    endif()

    target_link_libraries(AiDA PRIVATE
        aida_openssl_ssl
        aida_openssl_crypto
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
option(AIDA_PROTECTOR_LEGACY_STUB "Force legacy (pre-AsmJit) stub emitter for AiDAProtector" OFF)

if(BUILD_PROTECTOR)
    set(_aida_asmjit_src "${CMAKE_SOURCE_DIR}/libs/asmjit")
    if(NOT AIDA_PROTECTOR_LEGACY_STUB AND NOT EXISTS "${_aida_asmjit_src}/CMakeLists.txt")
        find_package(Git QUIET)
        if(GIT_FOUND)
            message(STATUS "AiDAProtector: fetching AsmJit into ${_aida_asmjit_src}")
            file(MAKE_DIRECTORY "${_aida_asmjit_src}")
            execute_process(
                COMMAND "${GIT_EXECUTABLE}" clone https://github.com/asmjit/asmjit.git "${_aida_asmjit_src}"
                RESULT_VARIABLE _aida_asmjit_clone_res
                OUTPUT_QUIET
                ERROR_QUIET
            )
            if(_aida_asmjit_clone_res EQUAL 0)
                execute_process(
                    COMMAND "${GIT_EXECUTABLE}" -C "${_aida_asmjit_src}" checkout a465fe71ab3e5e91b8dea8a5c34b22dcfbe99a15
                    RESULT_VARIABLE _aida_asmjit_co_res
                    OUTPUT_QUIET
                    ERROR_QUIET
                )
                if(NOT _aida_asmjit_co_res EQUAL 0)
                    message(STATUS "AiDAProtector: pinned AsmJit commit checkout failed; using default HEAD")
                endif()
            else()
                message(STATUS "AiDAProtector: AsmJit clone failed (network blocked?); LEGACY_STUB fallback will apply")
                file(REMOVE_RECURSE "${_aida_asmjit_src}")
            endif()
        else()
            message(STATUS "AiDAProtector: Git not found; cannot fetch AsmJit, LEGACY_STUB fallback will apply")
        endif()
    endif()

    if(NOT AIDA_PROTECTOR_LEGACY_STUB AND EXISTS "${_aida_asmjit_src}/CMakeLists.txt")
        set(ASMJIT_STATIC ON CACHE BOOL "Build asmjit as static library" FORCE)
        set(ASMJIT_NO_INSTALL ON CACHE BOOL "Disable asmjit install rules" FORCE)
        set(ASMJIT_NO_FOREIGN ON CACHE BOOL "Compile host backend only (drops AArch64 — AiDAProtector emits x86-64)" FORCE)
        if(NOT TARGET asmjit)
            add_subdirectory("${_aida_asmjit_src}" "${CMAKE_BINARY_DIR}/.deps/asmjit" EXCLUDE_FROM_ALL)
        endif()
        if(TARGET asmjit AND NOT TARGET asmjit::asmjit)
            add_library(asmjit::asmjit ALIAS asmjit)
        endif()
        if(MSVC AND TARGET asmjit AND CMAKE_GENERATOR MATCHES "Ninja")
            set_property(TARGET asmjit PROPERTY JOB_POOL_COMPILE aida_heavy_compile)
        endif()
    endif()

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

    if(TARGET asmjit AND NOT AIDA_PROTECTOR_LEGACY_STUB)
        target_link_libraries(AiDAProtector PRIVATE asmjit)
        target_include_directories(AiDAProtector PRIVATE "${_aida_asmjit_src}/src")
    else()
        target_compile_definitions(AiDAProtector PRIVATE AIDA_PROTECTOR_LEGACY_STUB=1)
        message(STATUS "AiDAProtector: building with legacy stub emitter (AsmJit unavailable or disabled)")
    endif()

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

    option(BUILD_MATRYOSHKA_TEST "Build the Matryoshka 3-layer pack-section test harness" ON)
    if(BUILD_MATRYOSHKA_TEST)
        add_executable(MATRYOSHKA_TEST tools/matryoshka_test/matryoshka_test.cpp)
        target_include_directories(MATRYOSHKA_TEST PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/protector
        )
        target_compile_definitions(MATRYOSHKA_TEST PRIVATE
            _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
        )
        target_compile_options(MATRYOSHKA_TEST PRIVATE
            /W4 /EHsc /O2 /Zc:__cplusplus /permissive- /MD /std:c++17
        )
        target_link_libraries(MATRYOSHKA_TEST PRIVATE bcrypt advapi32)
        set_target_properties(MATRYOSHKA_TEST PROPERTIES
            OUTPUT_NAME "matryoshka_test"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
        )
    endif()

    add_executable(AiDATestPayload tools/protector/test_payload/test_payload.c)
    target_compile_options(AiDATestPayload PRIVATE /W3 /O2 /MD)
    set_target_properties(AiDATestPayload PROPERTIES
        OUTPUT_NAME "aida_test_payload"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )

    add_executable(AiDAHelloLoop tools/protector/test_payload/hello_loop.cpp)
    target_compile_options(AiDAHelloLoop PRIVATE /W3 /O2 /MD /EHsc /std:c++17 /Zc:threadSafeInit)
    target_compile_definitions(AiDAHelloLoop PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    set_target_properties(AiDAHelloLoop PROPERTIES
        OUTPUT_NAME "aida_hello_loop"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )
    add_dependencies(AiDAHelloLoop AiDAProtector)

    add_custom_command(TARGET AiDAHelloLoop POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            "-DRETRY_LABEL=aida_hello_loop.exe-protect"
            "-DRETRY_CMD=$<TARGET_FILE:AiDAProtector>;--input;$<TARGET_FILE:AiDAHelloLoop>;--output;$<TARGET_FILE:AiDAHelloLoop>;--all;--bind-machine;--tamper-level;3;--jit;--verbose"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
        COMMENT "Protecting aida_hello_loop.exe (full --all pipeline, with AV/indexer retry)..."
        VERBATIM
    )

    add_library(AiDAHelloDll SHARED tools/protector/test_payload/hello_dll.cpp)
    target_compile_options(AiDAHelloDll PRIVATE /W3 /O2 /MD /EHsc /std:c++17 /Zc:threadSafeInit)
    target_compile_definitions(AiDAHelloDll PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    set_target_properties(AiDAHelloDll PROPERTIES
        OUTPUT_NAME "aida_hello_dll"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )
    add_dependencies(AiDAHelloDll AiDAProtector)

    add_executable(AiDADllLoader tools/protector/test_payload/dll_loader.cpp)
    target_compile_options(AiDADllLoader PRIVATE /W3 /O2 /MD /EHsc /std:c++17)
    target_compile_definitions(AiDADllLoader PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    set_target_properties(AiDADllLoader PROPERTIES
        OUTPUT_NAME "aida_dll_loader"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )
    add_dependencies(AiDADllLoader AiDAHelloDll)

    # Wave 5: structured logger/reporter wrapping protector + verifier
    add_executable(AiDAProtectorLogger tools/protector/protector_logger.cpp)
    target_include_directories(AiDAProtectorLogger PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/protector
    )
    target_compile_definitions(AiDAProtectorLogger PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN
    )
    target_compile_options(AiDAProtectorLogger PRIVATE
        /W4 /EHsc /O2 /Zc:__cplusplus /permissive- /MD
    )
    target_link_libraries(AiDAProtectorLogger PRIVATE bcrypt advapi32)
    set_target_properties(AiDAProtectorLogger PROPERTIES
        OUTPUT_NAME "aida_protector_logger"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
    )
    add_dependencies(AiDAProtectorLogger AiDAProtector AiDATestPayload)

    option(BUILD_PROTECTOR_TESTS "Register CTest for the AiDA protector full matrix" ON)
    if(BUILD_PROTECTOR_TESTS OR BUILD_TESTING)
        enable_testing()
        add_test(NAME protector_full_matrix
                 COMMAND $<TARGET_FILE:AiDAProtectorLogger>
                         --input  $<TARGET_FILE:AiDATestPayload>
                         --output ${CMAKE_BINARY_DIR}/Release/protector_report.json
                         --protector $<TARGET_FILE:AiDAProtector>)
        set_tests_properties(protector_full_matrix PROPERTIES
            PASS_REGULAR_EXPRESSION "\"probes_passed\": 27")
    endif()

    option(BUILD_WBAES_TEST "Build white-box AES-128 self-test executable" ON)
    if(BUILD_WBAES_TEST)
        add_subdirectory(tools/wbaes_test)
        if(BUILD_PROTECTOR_TESTS OR BUILD_TESTING)
            add_test(NAME wbaes_self_test COMMAND $<TARGET_FILE:WBAES_TEST>)
            set_tests_properties(wbaes_self_test PROPERTIES
                PASS_REGULAR_EXPRESSION "WBAES_TEST_PASSED")
        endif()
    endif()
endif()

if(BUILD_PROTECTOR)
    if(TARGET AiDAStandalone)
        if(TARGET aida_share_fingerprint_baker)
            add_custom_command(TARGET AiDAStandalone POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=AiDAStandalone.exe-bake-share-fingerprints"
                    "-DRETRY_CMD=$<TARGET_FILE:aida_share_fingerprint_baker>;--input;$<TARGET_FILE:AiDAStandalone>;--output;$<TARGET_FILE:AiDAStandalone>"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Baking per-share self-fingerprints into AiDAStandalone.exe (must run BEFORE protector: pack_sections zeroes .text)..."
                VERBATIM
            )
            add_dependencies(AiDAStandalone aida_share_fingerprint_baker)
        endif()
        add_custom_command(TARGET AiDAStandalone POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DRETRY_LABEL=AiDAStandalone.exe-protect"
                "-DRETRY_CMD=$<TARGET_FILE:AiDAProtector>;--input;$<TARGET_FILE:AiDAStandalone>;--output;$<TARGET_FILE:AiDAStandalone>;--all;--no-encrypt-imports;--bind-machine;--tamper-level;3;--jit;--no-llm-poison;--verbose"
                -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
            COMMENT "Protecting AiDAStandalone.exe (with AV/indexer retry)..."
            VERBATIM
        )
        if(TARGET aida_pdb_scrubber)
            add_custom_command(TARGET AiDAStandalone POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=AiDAStandalone.exe-scrub"
                    "-DRETRY_CMD=$<TARGET_FILE:aida_pdb_scrubber>;$<TARGET_FILE:AiDAStandalone>"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Scrubbing Rich header and PDB paths from AiDAStandalone.exe..."
                VERBATIM
            )
            add_dependencies(AiDAStandalone aida_pdb_scrubber)
        endif()
        add_dependencies(AiDAStandalone AiDAProtector)
    endif()

    if(TARGET AiDA_ARC)
        string(SUBSTRING "${AIDA_BUILD_SEED}" 0 32 AIDA_ARC_WATERMARK)
        string(TOLOWER "${AIDA_ARC_WATERMARK}" AIDA_ARC_WATERMARK)
        if(AIDA_ARC_ENCRYPT_IMPORTS)
            add_custom_command(TARGET AiDA_ARC POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=aida_core.dll-protect"
                    "-DRETRY_CMD=$<TARGET_FILE:AiDAProtector>;--input;$<TARGET_FILE:AiDA_ARC>;--output;$<TARGET_FILE:AiDA_ARC>;--all;--tamper-level;2;--deep-steal;--jit;--no-llm-poison;--target-arc;--watermark;${AIDA_ARC_WATERMARK};--embed-watermark;--verbose"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Protecting aida_core.dll (target-arc, encrypt-imports ON, with AV/indexer retry)..."
                VERBATIM
            )
        else()
            add_custom_command(TARGET AiDA_ARC POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=aida_core.dll-protect"
                    "-DRETRY_CMD=$<TARGET_FILE:AiDAProtector>;--input;$<TARGET_FILE:AiDA_ARC>;--output;$<TARGET_FILE:AiDA_ARC>;--all;--no-encrypt-imports;--tamper-level;2;--deep-steal;--jit;--no-llm-poison;--target-arc;--watermark;${AIDA_ARC_WATERMARK};--embed-watermark;--verbose"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Protecting aida_core.dll (target-arc, encrypt-imports OFF, with AV/indexer retry)..."
                VERBATIM
            )
        endif()
        if(TARGET aida_pdb_scrubber)
            add_custom_command(TARGET AiDA_ARC POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=aida_core.dll-scrub"
                    "-DRETRY_CMD=$<TARGET_FILE:aida_pdb_scrubber>;$<TARGET_FILE:AiDA_ARC>"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Scrubbing Rich header and PDB paths from aida_core.dll..."
                VERBATIM
            )
            add_dependencies(AiDA_ARC aida_pdb_scrubber)
        endif()
        add_dependencies(AiDA_ARC AiDAProtector)
    endif()

    if(TARGET AiDA)
        add_custom_command(TARGET AiDA POST_BUILD
            COMMAND ${CMAKE_COMMAND}
                "-DRETRY_LABEL=AiDA.dll-protect"
                "-DRETRY_CMD=$<TARGET_FILE:AiDAProtector>;--input;$<TARGET_FILE:AiDA>;--output;$<TARGET_FILE:AiDA>;--all;--no-encrypt-imports;--tamper-level;2;--no-jit;--no-llm-poison;--verbose"
                -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
            COMMENT "Protecting AiDA.dll (with AV/indexer retry)..."
            VERBATIM
        )
        if(TARGET aida_pdb_scrubber)
            add_custom_command(TARGET AiDA POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                    "-DRETRY_LABEL=AiDA.dll-scrub"
                    "-DRETRY_CMD=$<TARGET_FILE:aida_pdb_scrubber>;$<TARGET_FILE:AiDA>"
                    -P "${CMAKE_SOURCE_DIR}/cmake/run_with_retry.cmake"
                COMMENT "Scrubbing Rich header and PDB paths from AiDA.dll..."
                VERBATIM
            )
            add_dependencies(AiDA aida_pdb_scrubber)
        endif()
        add_dependencies(AiDA AiDAProtector)
    endif()
endif()

if(WIN32 AND TARGET AiDA AND TARGET AiDAStandalone AND Python3_FOUND)
    set(AIDA_PLUGIN_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/src/aida_plugin_encrypted.h")
    add_custom_command(
        OUTPUT "${AIDA_PLUGIN_HEADER}"
        COMMAND ${Python3_EXECUTABLE}
                "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_aida_plugin.py"
                --input  "$<TARGET_FILE:AiDA>"
                --output "${AIDA_PLUGIN_HEADER}"
        DEPENDS AiDA
                "${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_aida_plugin.py"
        COMMENT "Encrypting protected AiDA.dll -> aida_plugin_encrypted.h"
        VERBATIM
    )
    add_custom_target(encrypt_aida_plugin DEPENDS "${AIDA_PLUGIN_HEADER}")
    add_dependencies(encrypt_aida_plugin AiDA)
    add_dependencies(AiDAStandalone encrypt_aida_plugin)
    target_sources(AiDAStandalone PRIVATE
        "${STANDALONE_ROOT}/core/runtime/ida_injector.cpp"
    )
    set_source_files_properties(
        "${STANDALONE_ROOT}/core/runtime/ida_injector.cpp"
        PROPERTIES OBJECT_DEPENDS "${AIDA_PLUGIN_HEADER}"
    )
endif()

if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/nanomite_drx_test/CMakeLists.txt")
    add_subdirectory(tools/nanomite_drx_test)
endif()

if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/dag_dispatch_test/CMakeLists.txt")
    add_subdirectory(tools/dag_dispatch_test)
endif()

if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/overlap_test/CMakeLists.txt")
    add_subdirectory(tools/overlap_test)
endif()
