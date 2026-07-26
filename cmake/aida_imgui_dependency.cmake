include_guard(GLOBAL)

set(AIDA_IMGUI_LOCK_FILE "${CMAKE_CURRENT_LIST_DIR}/aida_imgui_dependency.lock.json")
set(AIDA_IMGUI_EXPECTED_VERSION "1.92.1")
set(AIDA_IMGUI_EXPECTED_VERSION_NUM 19210)
set(AIDA_IMGUI_EXPECTED_COMMIT "44aa9a4b3a6f27d09a4eb5770d095cbd376dfc4b")
set(AIDA_IMGUI_EXPECTED_TREE "7b2a8d999b74caf2d517911dd2403abf35e86632")
set(AIDA_IMGUI_EXPECTED_SOURCE_SHA256 "ab58f5a545bf97ebf72807f2c7f41302ad3d2a3a2e4869ff624b92d5e473c4f7")

function(aida_configure_imgui_dependency source_dir)
    if(NOT EXISTS "${AIDA_IMGUI_LOCK_FILE}")
        message(WARNING "AiDA Dear ImGui dependency lock is missing")
    endif()
    file(READ "${AIDA_IMGUI_LOCK_FILE}" _aida_imgui_lock)
    file(SHA256 "${AIDA_IMGUI_LOCK_FILE}" _aida_imgui_lock_sha256)
    string(JSON _aida_imgui_schema GET "${_aida_imgui_lock}" schemaVersion)
    string(JSON _aida_imgui_name GET "${_aida_imgui_lock}" name)
    string(JSON _aida_imgui_version GET "${_aida_imgui_lock}" version)
    string(JSON _aida_imgui_version_num GET "${_aida_imgui_lock}" versionNum)
    string(JSON _aida_imgui_branch GET "${_aida_imgui_lock}" branch)
    string(JSON _aida_imgui_tag GET "${_aida_imgui_lock}" tag)
    string(JSON _aida_imgui_repository GET "${_aida_imgui_lock}" repository)
    string(JSON _aida_imgui_commit GET "${_aida_imgui_lock}" commit)
    string(JSON _aida_imgui_tree GET "${_aida_imgui_lock}" tree)
    string(JSON _aida_imgui_docking GET "${_aida_imgui_lock}" capabilities docking)
    string(JSON _aida_imgui_dockspace GET "${_aida_imgui_lock}" capabilities dockSpace)
    string(JSON _aida_imgui_viewport_dockspace GET "${_aida_imgui_lock}" capabilities dockSpaceOverViewport)
    string(JSON _aida_imgui_dock_builder GET "${_aida_imgui_lock}" capabilities dockBuilder)
    string(JSON _aida_imgui_multi_viewport GET "${_aida_imgui_lock}" capabilities multiViewportPolicy)
    if(NOT _aida_imgui_schema EQUAL 1 OR
       NOT _aida_imgui_name STREQUAL "dear-imgui" OR
       NOT _aida_imgui_version STREQUAL AIDA_IMGUI_EXPECTED_VERSION OR
       NOT _aida_imgui_version_num EQUAL AIDA_IMGUI_EXPECTED_VERSION_NUM OR
       NOT _aida_imgui_branch STREQUAL "docking" OR
       NOT _aida_imgui_tag STREQUAL "v1.92.1-docking" OR
       NOT _aida_imgui_repository STREQUAL "https://github.com/ocornut/imgui.git" OR
       NOT _aida_imgui_commit STREQUAL AIDA_IMGUI_EXPECTED_COMMIT OR
       NOT _aida_imgui_tree STREQUAL AIDA_IMGUI_EXPECTED_TREE OR
       NOT _aida_imgui_docking OR
       NOT _aida_imgui_dockspace OR
       NOT _aida_imgui_viewport_dockspace OR
       NOT _aida_imgui_dock_builder STREQUAL "reviewed-internal-v1" OR
       NOT _aida_imgui_multi_viewport STREQUAL "disabled")
        message(WARNING "AiDA Dear ImGui dependency lock does not match the approved docking authority")
    endif()
    string(JSON _aida_imgui_file_count LENGTH "${_aida_imgui_lock}" files)
    if(NOT _aida_imgui_file_count EQUAL 17)
        message(WARNING "AiDA Dear ImGui dependency inventory cardinality is invalid")
    endif()
    math(EXPR _aida_imgui_file_last "${_aida_imgui_file_count} - 1")
    set(_aida_imgui_seen_paths)
    set(_aida_imgui_source_sha256)
    foreach(_aida_imgui_index RANGE 0 ${_aida_imgui_file_last})
        string(JSON _aida_imgui_path GET "${_aida_imgui_lock}" files ${_aida_imgui_index} path)
        string(JSON _aida_imgui_size GET "${_aida_imgui_lock}" files ${_aida_imgui_index} sizeBytes)
        string(JSON _aida_imgui_sha256 GET "${_aida_imgui_lock}" files ${_aida_imgui_index} sha256)
        string(LENGTH "${_aida_imgui_sha256}" _aida_imgui_sha256_length)
        if(_aida_imgui_path MATCHES "(^|/)\\.\\.(/|$)" OR
           _aida_imgui_path MATCHES "^[\\\\/]" OR
           _aida_imgui_path IN_LIST _aida_imgui_seen_paths OR
           NOT _aida_imgui_sha256_length EQUAL 64 OR
           NOT _aida_imgui_sha256 MATCHES "^[0-9a-f]+$")
            message(WARNING "AiDA Dear ImGui dependency inventory contains an invalid path or identity")
        endif()
        list(APPEND _aida_imgui_seen_paths "${_aida_imgui_path}")
        set(_aida_imgui_absolute "${source_dir}/${_aida_imgui_path}")
        if(NOT EXISTS "${_aida_imgui_absolute}" OR IS_DIRECTORY "${_aida_imgui_absolute}")
            message(WARNING "AiDA Dear ImGui dependency file is missing: ${_aida_imgui_path}. Run tools/bootstrap_imgui_dependency.ps1")
        endif()
        file(SHA256 "${_aida_imgui_absolute}" _aida_imgui_actual_sha256)
        string(TOLOWER "${_aida_imgui_actual_sha256}" _aida_imgui_actual_sha256)
        if(_aida_imgui_path STREQUAL "imgui.cpp")
            set(_aida_imgui_source_sha256 "${_aida_imgui_actual_sha256}")
        endif()
    endforeach()
    file(READ "${source_dir}/imgui.h" _aida_imgui_public_header)
    file(READ "${source_dir}/imgui_internal.h" _aida_imgui_internal_header)
    if(NOT _aida_imgui_public_header MATCHES "#define[ \t]+IMGUI_VERSION_NUM[ \t]+19210" OR
       NOT _aida_imgui_public_header MATCHES "#define[ \t]+IMGUI_HAS_DOCK" OR
       NOT _aida_imgui_public_header MATCHES "DockSpaceOverViewport" OR
       NOT _aida_imgui_internal_header MATCHES "DockBuilderFinish")
        message(WARNING "AiDA Dear ImGui dependency lacks the approved docking capabilities")
    endif()
    set(AIDA_IMGUI_SOURCE_SHA256 "${_aida_imgui_source_sha256}" PARENT_SCOPE)
    set(AIDA_IMGUI_LOCK_SHA256 "${_aida_imgui_lock_sha256}" PARENT_SCOPE)
    set(AIDA_IMGUI_SOURCE_COMMIT "${_aida_imgui_commit}" PARENT_SCOPE)
    set(AIDA_IMGUI_SOURCE_TREE "${_aida_imgui_tree}" PARENT_SCOPE)
endfunction()
