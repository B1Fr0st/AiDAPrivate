if(NOT DEFINED AIDA_CAMOUFOX_STAGE_ROOT)
    message(FATAL_ERROR "AIDA_CAMOUFOX_STAGE_ROOT is required")
endif()

set(AIDA_CAMOUFOX_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/browser.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/browser.py"
)

foreach(AIDA_CAMOUFOX_PATCH_FILE IN LISTS AIDA_CAMOUFOX_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_PATCH_FILE}" AIDA_CAMOUFOX_CONTENT)
    set(AIDA_CAMOUFOX_ORIGINAL "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE")
        string(REPLACE
"        if cfg.get(\"block_webrtc\"):
            kwargs[\"block_webrtc\"] = True

        locale = cfg.get(\"locale\", \"auto\")"
"        if cfg.get(\"block_webrtc\"):
            kwargs[\"block_webrtc\"] = True

        executable_path = cfg.get(\"executable_path\") or __import__(\"os\").environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")
        if executable_path:
            kwargs[\"executable_path\"] = str(executable_path)

        ff_version = cfg.get(\"ff_version\")
        if ff_version is not None:
            try:
                kwargs[\"ff_version\"] = int(ff_version)
                kwargs[\"i_know_what_im_doing\"] = True
            except (TypeError, ValueError):
                pass

        locale = cfg.get(\"locale\", \"auto\")"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE
        "_os.environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")"
        "__import__(\"os\").environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE
"            import json as _json
            import os as _os
            from functools import partial"
"            import json as _json
            from functools import partial"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "bundled_visible_launch")
        string(REPLACE
"        os_type = cfg.get(\"os\", \"auto\")
        host_os = detect_host_os()
        if os_type == \"auto\":
            os_type = host_os
        kwargs[\"os\"] = os_type"
"        os_requested = cfg.get(\"os\", \"auto\")
        host_os = detect_host_os()
        os_type = host_os if os_requested == \"auto\" else os_requested"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"        locale = cfg.get(\"locale\", \"auto\")
        if locale == \"auto\":
            locale = detect_system_locale()
        kwargs[\"locale\"] = locale

        headless = cfg.get(\"headless\", False)
        kwargs[\"headless\"] = headless

        window_size, window_diag = _resolve_window_size(cfg)"
"        locale_requested = cfg.get(\"locale\", \"auto\")
        locale = detect_system_locale() if locale_requested == \"auto\" else locale_requested

        headless = cfg.get(\"headless\", False)
        kwargs[\"headless\"] = headless

        bundled_visible_launch = bool(executable_path) and not headless
        if not bundled_visible_launch or os_requested != \"auto\":
            kwargs[\"os\"] = os_type
        if not bundled_visible_launch or locale_requested != \"auto\":
            kwargs[\"locale\"] = locale

        window_size, window_diag = _resolve_window_size(cfg)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_build_camoufox_launch_options")
        string(REPLACE
"def detect_system_locale() -> str:
    \"\"\"Best-effort detection of the host's locale (e.g. 'zh-CN').\"\"\"
    for var in (\"LANG\", \"LC_ALL\", \"LC_MESSAGES\"):
        val = _os.environ.get(var, \"\")
        if val and val not in (\"C\", \"POSIX\"):
            return val.split(\".\")[0].replace(\"_\", \"-\")
    return \"en-US\""
"def detect_system_locale() -> str:
    \"\"\"Best-effort detection of the host's locale (e.g. 'zh-CN').\"\"\"
    for var in (\"LANG\", \"LC_ALL\", \"LC_MESSAGES\"):
        val = _os.environ.get(var, \"\")
        if val and val not in (\"C\", \"POSIX\"):
            return val.split(\".\")[0].replace(\"_\", \"-\")
    return \"en-US\"


def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\")
    })"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_bundled_options")
        string(REPLACE
"        enable_trace = cfg.get(\"enable_trace\", False)

        if enable_trace:"
"        enable_trace = cfg.get(\"enable_trace\", False)

        from_options = None
        if executable_path:
            from_options = _build_camoufox_launch_options(headless, kwargs)
            kwargs[\"from_options\"] = from_options
            _camoufox_debug(
                \"launch_bundled_options\",
                executable_path=str(executable_path),
                from_options_has_executable=bool(from_options.get(\"executable_path\")),
                from_options_args=len(from_options.get(\"args\") or []),
                from_options_has_env=bool(from_options.get(\"env\")),
            )

        if enable_trace:"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"            from camoufox.utils import launch_options as _cfx_launch_options"
""
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"            from_options = _cfx_launch_options(headless=headless, **{
                k: v for k, v in kwargs.items() if k != \"headless\"
            })"
"            if from_options is None:
                from_options = _build_camoufox_launch_options(headless, kwargs)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_CONTENT}" "_os.environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")" AIDA_CAMOUFOX_SHADOWED_ENV_POS)

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "bundled_visible_launch"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ff_version"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_bundled_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_build_camoufox_launch_options"
        OR AIDA_CAMOUFOX_SHADOWED_ENV_POS GREATER -1)
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT STREQUAL AIDA_CAMOUFOX_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_PATCH_FILE}" "${AIDA_CAMOUFOX_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_NAV_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/navigation.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/navigation.py"
)

foreach(AIDA_CAMOUFOX_NAV_PATCH_FILE IN LISTS AIDA_CAMOUFOX_NAV_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" AIDA_CAMOUFOX_NAV_CONTENT)
    set(AIDA_CAMOUFOX_NAV_ORIGINAL "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "executable_path: str | None" AIDA_CAMOUFOX_NAV_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "ff_version: int | None" AIDA_CAMOUFOX_NAV_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)

    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"    window_width: int = 1280,
    window_height: int = 900,
) -> dict:"
"    window_width: int = 1280,
    window_height: int = 900,
    executable_path: str | None = None,
    ff_version: int | None = None,
) -> dict:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    if(AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"            \"enable_trace\": enable_trace,
            \"window_width\": window_width,
            \"window_height\": window_height,
        }
        if proxy:"
"            \"enable_trace\": enable_trace,
            \"window_width\": window_width,
            \"window_height\": window_height,
        }
        if executable_path:
            config[\"executable_path\"] = executable_path
        if ff_version is not None:
            try:
                config[\"ff_version\"] = int(ff_version)
            except (TypeError, ValueError):
                pass
        if proxy:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "executable_path: str | None" AIDA_CAMOUFOX_NAV_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "ff_version: int | None" AIDA_CAMOUFOX_NAV_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)
    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_VERSION_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS EQUAL -1)
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_NAV_CONTENT STREQUAL AIDA_CAMOUFOX_NAV_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" "${AIDA_CAMOUFOX_NAV_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()
endforeach()
