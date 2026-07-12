set(AIDA_C03_DEPENDENCY_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
set(AIDA_C03_NOTICE_LEDGER "${AIDA_C03_DEPENDENCY_ROOT}/licenses/c03/THIRD_PARTY_NOTICES.md")
set(AIDA_C03_WORKER_MANIFEST_SCHEMA "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_worker_manifest.schema.json")
set(AIDA_C03_WORKER_MANIFEST_LOCK "${AIDA_C03_DEPENDENCY_ROOT}/packaging/c03_worker_manifest.lock.json")
set(AIDA_C03_FORBIDDEN_LINK_TOKENS lmdb unicorn remill)
set(AIDA_C03_ZYDIS_COMPONENT_ALLOWLIST Zydis Zycore)
set(AIDA_C03_CAPSTONE_COMPONENT_ALLOWLIST ARM ARM64 MIPS PPC RISCV X86 detail)
set(AIDA_C03_TASKFLOW_COMPONENT_ALLOWLIST taskflow)
set(AIDA_C03_GHIDRA_WORKER_COMPONENT_ALLOWLIST decompiler sleigh processor_specs compiler_specs)
set(AIDA_C03_TRITON_THOROUGH_ONLY_COMPONENT_ALLOWLIST triton z3_interface)
set(AIDA_C03_Z3_THOROUGH_ONLY_COMPONENT_ALLOWLIST libz3)
set(AIDA_C03_SQLITE_COMPONENT_ALLOWLIST sqlite3)
set(AIDA_C03_IMGUI_COMPONENT_ALLOWLIST imgui imgui_freetype imgui_impl_dx11 imgui_impl_win32)
set(AIDA_C03_ZLIB_COMPONENT_ALLOWLIST zlib)
set(AIDA_C03_ZSTD_COMPONENT_ALLOWLIST zstd_static)
set(AIDA_C03_LIBLZMA_MINIMAL_COMPONENT_ALLOWLIST liblzma)
set(AIDA_C03_MINIZIP_NG_READ_ONLY_COMPONENT_ALLOWLIST mz_zip_reader)
set(AIDA_C03_PCRE2_8BIT_NO_JIT_COMPONENT_ALLOWLIST pcre2_8)
set(AIDA_C03_NLOHMANN_JSON_COMPONENT_ALLOWLIST nlohmann_json)
set(AIDA_C03_JSON_SCHEMA_VALIDATOR_COMPONENT_ALLOWLIST nlohmann_json_schema_validator)
set(AIDA_C03_LLVM_COMPONENT_ALLOWLIST Demangle Support)
set(AIDA_C03_MANAGED_WORKER_PACKAGES_COMPONENT_ALLOWLIST ICSharpCode.Decompiler System.Collections.Immutable System.Reflection.Metadata)
set(AIDA_C03_NO_NETWORK_FETCH ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_FULLY_DISCONNECTED ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)

function(aida_c03_require_path_sha256 path expected_sha256 descriptor)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "AiDA C03 dependency is missing: ${descriptor}")
    endif()
    file(SHA256 "${path}" _aida_c03_actual_sha256)
    if(NOT _aida_c03_actual_sha256 STREQUAL expected_sha256)
        message(FATAL_ERROR "AiDA C03 dependency hash mismatch: ${descriptor}")
    endif()
endfunction()

function(aida_c03_require_file_sha256 relative_path expected_sha256)
    aida_c03_require_path_sha256("${AIDA_C03_DEPENDENCY_ROOT}/${relative_path}" "${expected_sha256}" "${relative_path}")
endfunction()

function(aida_c03_verify_dependency_inventory)
    foreach(_aida_c03_metadata_file IN ITEMS
            "licenses/c03/THIRD_PARTY_NOTICES.md"
            "licenses/c03/MIT.txt"
            "licenses/c03/SQLite-Public-Domain.txt"
            "packaging/c03_worker_manifest.schema.json"
            "packaging/c03_worker_manifest.lock.json")
        if(NOT EXISTS "${AIDA_C03_DEPENDENCY_ROOT}/${_aida_c03_metadata_file}")
            message(FATAL_ERROR "AiDA C03 metadata is missing: ${_aida_c03_metadata_file}")
        endif()
    endforeach()
    aida_c03_require_file_sha256("licenses/c03/MIT.txt" "c0fc02a86ae2b179c4729694c523bbf42da674e5136ed8e12e3cb2f26556ea9f")
    aida_c03_require_file_sha256("licenses/c03/THIRD_PARTY_NOTICES.md" "ed491c0cf9a9f34bc745d6bfb033656672862e1b6e38320c10698c6228f48d5e")
    aida_c03_require_file_sha256("licenses/c03/SQLite-Public-Domain.txt" "003344876cc9d3b93313b297bc432ab109f41cf970c64c3c357cc8aa8dfc0c09")
    aida_c03_require_file_sha256("packaging/c03_worker_manifest.schema.json" "401d7d9b31f30687cb0430388bc0f4a2cac69fe65a5f0a5caa51039b9ca1f48c")
    aida_c03_require_file_sha256("packaging/c03_worker_manifest.lock.json" "18a207dca364967ae90dd1a68f4734a312a7b362ae2754fb77d3d06246681c31")
    aida_c03_require_file_sha256(".deps/zydis-4.1.1/CMakeLists.txt" "f577d285af7cf71f78830e45add8e0f4567f29b464414611be49ae2aef6e210f")
    aida_c03_require_file_sha256(".deps/zydis-4.1.1/LICENSE" "e5e99718209e94baaf3e9cbf6f64aa3329c9e73c63b1ab47e10f29d81974e6f3")
    aida_c03_require_file_sha256(".deps/zydis-4.1.1/dependencies/zycore/LICENSE" "7991ec4481a82c51d196f7440fda34c578aab51f8b9c7023935c6e03b57638bd")
    aida_c03_require_file_sha256(".deps/capstone/capstone-5.0.9/CMakeLists.txt" "2b5eb43abba6ad34b9fd4aabea18a0c6fe4b49e5aab34a8b6111e66c6f706f49")
    aida_c03_require_file_sha256(".deps/capstone/capstone-5.0.9/LICENSE.TXT" "65e9ed46a59976eda8f5bd1ea79a680dea38dd299c760bc9a8d87a764ef5029b")
    aida_c03_require_file_sha256(".deps/taskflow/taskflow/taskflow.hpp" "083716c4914d20d960cf6a4e73ff088d0c367652d4768f0a5fc4b7ed3a594146")
    aida_c03_require_file_sha256(".deps/taskflow/LICENSE" "aa797f3efb1fab9c55c3b2f6d905b6f447d23c17c53a56c19b1f885d55150a01")
    aida_c03_require_file_sha256("src/standalone/third_party_notices/Ghidra-LICENSE.txt" "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4")
    aida_c03_require_file_sha256("src/standalone/third_party_notices/Ghidra-NOTICE.txt" "ad4b2bb6e75e908251226180081b5afa01c7161d7710e08b603d0c340a08a23f")
    aida_c03_require_file_sha256("sources/Triton/CMakeLists.txt" "576eeeec6d38ab3d901a3425c0aee32ab2dbff7a49253c30cec730e194e83e97")
    aida_c03_require_file_sha256("sources/Triton/LICENSE.txt" "4dac13b8543ff39efdff4cb54e50ee26379d8b2d520d1942a362ad89f1bf6225")
    aida_c03_require_file_sha256(".deps/z3/z3-4.13.4-x64-win/include/z3.h" "f36cf06ae2259a444c938269a6d866922737c795d1886405006ce7c960228314")
    aida_c03_require_file_sha256(".deps/z3/z3-4.13.4-x64-win/LICENSE.txt" "26a0a08e51bfccaa3850e4418426a710ee3fa98e93f35637c4f06e8de041a470")
    aida_c03_require_file_sha256(".deps/sqlite-amalgamation-3530300/sqlite3.c" "87497ab605bedd0dbee27a209c1eeff8c89b229b13f921a7efdbb81a13f779fd")
    aida_c03_require_file_sha256(".deps/sqlite-amalgamation-3530300/sqlite3.h" "4ff81af4849acabc76fc8349abb926814395072617ca18e08800abf734ab7612")
    aida_c03_require_file_sha256(".deps/imgui-src/imgui.h" "5de7ae6fa7eac1632e827bcb65707d053315635ccea95bcec430c1872a8171e3")
    aida_c03_require_file_sha256(".deps/imgui-src/LICENSE.txt" "55e058cc5899e6077a819ad1005d6d1f4528f65ae100795c9692f9fa6525a8ce")
    aida_c03_require_file_sha256(".deps/zlib-1.3.2/zlib.h" "818667d6ab6a37fe7469cb06a7f0cb2c2cb2f2c948a03e5accf1a4a74bf3020a")
    aida_c03_require_file_sha256(".deps/zlib-1.3.2/LICENSE" "e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2")
    aida_c03_require_file_sha256(".deps/zstd-1.5.7/lib/zstd.h" "9b4bc8245565c98ccfc61c07749928b57e7c0f6fddb0530c4f6aa1971893d88b")
    aida_c03_require_file_sha256(".deps/zstd-1.5.7/LICENSE" "7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8")
    aida_c03_require_file_sha256(".deps/xz-5.8.3/src/liblzma/api/lzma.h" "6829350ef1ee35fae25481cc87a4f4b17c4b6c2a3df26f2b34dc1804df75c0d9")
    aida_c03_require_file_sha256(".deps/xz-5.8.3/COPYING.0BSD" "0b01625d853911cd0e2e088dcfb743261034a091bb379246cb25a14cc4c74bf1")
    aida_c03_require_file_sha256(".deps/minizip-ng-4.2.2/mz.h" "4a6eda89f5dc0533dc93b9c4f98278dc052c5f1e27c39dfeaf59672549f1c1a8")
    aida_c03_require_file_sha256(".deps/minizip-ng-4.2.2/LICENSE" "675181c03fc1302a1c8554c00f7be9bb420c5dbc9dcc2013433cec144413de03")
    aida_c03_require_file_sha256(".deps/pcre2-10.47/src/pcre2.h.generic" "058462dc030e845ee627e19ac36347f561f5cc44d89eaf1c0010f2b363ab68d5")
    aida_c03_require_file_sha256(".deps/pcre2-10.47/LICENCE.md" "197d8a73ffee0d6b09adba2f9c677b5f5aede24edf89258a68e48248d010d811")
    aida_c03_require_file_sha256("libs/nlohmann/json.hpp" "aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63")
    aida_c03_require_file_sha256(".deps/licenses/nlohmann-json-3.12.0-LICENSE.MIT" "46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603")
    aida_c03_require_file_sha256(".deps/json-schema-validator-2.4.0/src/nlohmann/json-schema.hpp" "2d9772aee4cb7ddb6d338eac207c965fe2cd283a045dc35dfa9c0aaec481247b")
    aida_c03_require_file_sha256(".deps/json-schema-validator-2.4.0/LICENSE" "4294d027a5205eea79a5241b2c1423d556efaa3139df8cea5ac313fb5ffb07bf")
    aida_c03_require_file_sha256(".deps/llvm-project-llvmorg-22.1.8/llvm/include/llvm/Demangle/Demangle.h" "21d4064997c95961f5c5d75a941562c2cc2b1dca95711a162116829388c84cfc")
    aida_c03_require_file_sha256(".deps/llvm-project-llvmorg-22.1.8/LICENSE.TXT" "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee")
    aida_c03_require_file_sha256(".deps/dotnet-sdk-10.0.301-win-x64/dotnet.exe" "a5ccdc3a41d5e5c6014ff64509aed176db39f4f14caffff3dd1997f8907e94d7")
    aida_c03_require_file_sha256(".deps/dotnet-sdk-10.0.301-win-x64/LICENSE.txt" "7f6839a61ce892b79c6549e2dc5a81fdbd240a0b260f8881216b45b7fda8b45d")
    aida_c03_require_file_sha256(".deps/nuget-offline/ICSharpCode.Decompiler.10.1.0.8386.nupkg" "a6fb2e9be86c1b73e54231e20640d4d566c52f21cba9ad99c3e9100d67e8f5af")
    aida_c03_require_file_sha256(".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg" "fbaab954c7a87396e6e1616ca15ea705703d755e696bf3b8c96fa039d8bcc9a7")
    aida_c03_require_file_sha256(".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg" "6af1166dc0a1ed7829b127ac9d1dff4a0c568bfe82e4ec6347cf497ff49f4634")
    aida_c03_require_file_sha256(".deps/LIEF-0.17.6/LICENSE" "94a5b753e8d799c7aa0c0c4899c5d5f9be1a940cba73f61c6396f32db790a0be")
    aida_c03_require_file_sha256(".deps/remill-6.0.1/remill-6.0.1/LICENSE" "59899c6091b540582ed617e8eeaac4919dc985ccfc35459ee9752b699be5205b")
    aida_c03_require_file_sha256("camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe" "768937fa6a6df581d0cdc88ecffe1cf651ffebe1ad1d5667a5f75100e96acfe0")
    aida_c03_require_file_sha256(".deps/AiDA_CamoufoxReverseMcp/AiDA_CamoufoxReverseMcp.exe" "2443649a43c92b048b7f013434d169889b41f494f391359d9cc72111c6e0ee4c")
    aida_c03_require_file_sha256("camoufox-reverse-mcp/pyproject.toml" "aa1eab416c99bb3c51e833372d0638540ecbac0ba1712172da8db81b81a86deb")
endfunction()

function(aida_c03_require_components dependency)
    set(_aida_c03_requested_components ${ARGN})
    if(NOT _aida_c03_requested_components)
        message(FATAL_ERROR "AiDA C03 component request is empty: ${dependency}")
    endif()
    string(TOUPPER "${dependency}" _aida_c03_dependency_key)
    string(REPLACE "-" "_" _aida_c03_dependency_key "${_aida_c03_dependency_key}")
    set(_aida_c03_allowlist_name "AIDA_C03_${_aida_c03_dependency_key}_COMPONENT_ALLOWLIST")
    if(NOT DEFINED ${_aida_c03_allowlist_name})
        message(FATAL_ERROR "AiDA C03 dependency has no component allowlist: ${dependency}")
    endif()
    foreach(_aida_c03_component IN LISTS _aida_c03_requested_components)
        if(NOT _aida_c03_component IN_LIST ${_aida_c03_allowlist_name})
            message(FATAL_ERROR "AiDA C03 component is not approved: ${dependency} -> ${_aida_c03_component}")
        endif()
        if(_aida_c03_component MATCHES "(^|[^A-Za-z0-9])(lmdb|unicorn|remill)([^A-Za-z0-9]|$)")
            message(FATAL_ERROR "AiDA C03 forbidden component requested: ${_aida_c03_component}")
        endif()
    endforeach()
endfunction()

function(aida_c03_reject_forbidden_target_links)
    foreach(_aida_c03_target IN LISTS ARGN)
        if(NOT TARGET "${_aida_c03_target}")
            message(FATAL_ERROR "AiDA C03 target is not defined: ${_aida_c03_target}")
        endif()
        foreach(_aida_c03_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(_aida_c03_links "${_aida_c03_target}" "${_aida_c03_property}")
            if(_aida_c03_links)
                foreach(_aida_c03_link IN LISTS _aida_c03_links)
                    string(TOLOWER "${_aida_c03_link}" _aida_c03_normalized_link)
                    foreach(_aida_c03_forbidden IN LISTS AIDA_C03_FORBIDDEN_LINK_TOKENS)
                        if(_aida_c03_normalized_link MATCHES "(^|[^a-z0-9])${_aida_c03_forbidden}([^a-z0-9]|$)")
                            message(FATAL_ERROR "AiDA C03 target links a forbidden dependency: ${_aida_c03_target} -> ${_aida_c03_link}")
                        endif()
                    endforeach()
                endforeach()
            endif()
        endforeach()
    endforeach()
endfunction()

function(aida_c03_copy_notice_as destination relative_path output_name)
    configure_file("${AIDA_C03_DEPENDENCY_ROOT}/${relative_path}" "${destination}/${output_name}" COPYONLY)
endfunction()

function(aida_c03_copy_notice destination relative_path)
    set(_aida_c03_notice_name "${relative_path}")
    string(REPLACE "/" "_" _aida_c03_notice_name "${_aida_c03_notice_name}")
    aida_c03_copy_notice_as("${destination}" "${relative_path}" "${_aida_c03_notice_name}")
endfunction()

function(aida_c03_stage_managed_package_notices destination archive_relative_path package_directory license_sha256 third_party_notices_sha256)
    set(_aida_c03_notice_destination "${destination}/managed/${package_directory}")
    file(MAKE_DIRECTORY "${_aida_c03_notice_destination}")
    file(ARCHIVE_EXTRACT
        INPUT "${AIDA_C03_DEPENDENCY_ROOT}/${archive_relative_path}"
        DESTINATION "${_aida_c03_notice_destination}"
        PATTERNS "LICENSE.TXT" "THIRD-PARTY-NOTICES.TXT")
    aida_c03_require_path_sha256("${_aida_c03_notice_destination}/LICENSE.TXT" "${license_sha256}" "${archive_relative_path}::LICENSE.TXT")
    aida_c03_require_path_sha256("${_aida_c03_notice_destination}/THIRD-PARTY-NOTICES.TXT" "${third_party_notices_sha256}" "${archive_relative_path}::THIRD-PARTY-NOTICES.TXT")
endfunction()

function(aida_c03_stage_notices destination)
    aida_c03_verify_dependency_inventory()
    file(MAKE_DIRECTORY "${destination}")
    aida_c03_copy_notice_as("${destination}" "licenses/c03/THIRD_PARTY_NOTICES.md" "THIRD_PARTY_NOTICES.md")
    foreach(_aida_c03_notice IN ITEMS
            "licenses/c03/MIT.txt"
            "licenses/c03/SQLite-Public-Domain.txt"
            ".deps/zydis-4.1.1/LICENSE"
            ".deps/zydis-4.1.1/dependencies/zycore/LICENSE"
            ".deps/capstone/capstone-5.0.9/LICENSE.TXT"
            ".deps/taskflow/LICENSE"
            "src/standalone/third_party_notices/Ghidra-LICENSE.txt"
            "src/standalone/third_party_notices/Ghidra-NOTICE.txt"
            "sources/Triton/LICENSE.txt"
            ".deps/z3/z3-4.13.4-x64-win/LICENSE.txt"
            ".deps/imgui-src/LICENSE.txt"
            ".deps/zlib-1.3.2/LICENSE"
            ".deps/zstd-1.5.7/LICENSE"
            ".deps/xz-5.8.3/COPYING.0BSD"
            ".deps/minizip-ng-4.2.2/LICENSE"
            ".deps/pcre2-10.47/LICENCE.md"
            ".deps/licenses/nlohmann-json-3.12.0-LICENSE.MIT"
            ".deps/json-schema-validator-2.4.0/LICENSE"
            ".deps/llvm-project-llvmorg-22.1.8/LICENSE.TXT"
            ".deps/dotnet-sdk-10.0.301-win-x64/LICENSE.txt")
        aida_c03_copy_notice("${destination}" "${_aida_c03_notice}")
    endforeach()
    aida_c03_stage_managed_package_notices("${destination}" ".deps/nuget-offline/System.Collections.Immutable.9.0.0.nupkg" "System.Collections.Immutable-9.0.0" "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b" "40686c6447a7d5b5d3693068e4571b5f483d7ed335aeee773ef662440de4c5d5")
    aida_c03_stage_managed_package_notices("${destination}" ".deps/nuget-offline/System.Reflection.Metadata.9.0.0.nupkg" "System.Reflection.Metadata-9.0.0" "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b" "40686c6447a7d5b5d3693068e4571b5f483d7ed335aeee773ef662440de4c5d5")
endfunction()

function(aida_c03_stage_evidence_notices destination)
    aida_c03_verify_dependency_inventory()
    file(MAKE_DIRECTORY "${destination}")
    foreach(_aida_c03_notice IN ITEMS
            ".deps/LIEF-0.17.6/LICENSE"
            ".deps/remill-6.0.1/remill-6.0.1/LICENSE")
        aida_c03_copy_notice("${destination}" "${_aida_c03_notice}")
    endforeach()
endfunction()
