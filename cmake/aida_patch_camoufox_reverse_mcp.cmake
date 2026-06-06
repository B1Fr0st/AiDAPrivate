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

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_DEBUG_LOG")
        string(REPLACE [=[def _camoufox_debug(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    try:
        print("AIDA_CAMOUFOX " + _json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)
    except Exception:
        pass]=]
[=[def _camoufox_debug(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    try:
        line = "AIDA_CAMOUFOX " + _json.dumps(payload, sort_keys=True, separators=(",", ":"))
        print(line, file=sys.stderr, flush=True)
        log_path = _os.environ.get("AIDA_CAMOUFOX_DEBUG_LOG", "")
        if log_path:
            with open(log_path, "a", encoding="utf-8") as fp:
                fp.write(line + "\n")
    except Exception:
        pass]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE
        "k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\")"
        "k: v for k, v in kwargs.items() if k not in (\"headless\", \"from_options\", \"persistent_context\")"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_new_profile_dir")
        string(REPLACE [=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    })]=]
[=[def _build_camoufox_launch_options(headless: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
    from camoufox.utils import launch_options as _cfx_launch_options
    return _cfx_launch_options(headless=headless, **{
        k: v for k, v in kwargs.items() if k not in ("headless", "from_options", "persistent_context")
    })


def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir")
        string(REPLACE
            "        self._route_handlers: dict[str, Any] = {}  # 已注册的 route handler 映射"
            "        self._route_handlers: dict[str, Any] = {}  # 已注册的 route handler 映射\n        self._profile_dir: str | None = None"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir")
        string(REPLACE [=[        self._persistent_scripts: list[dict] = []
        self._persistent_traces: dict[str, list] = {}]=]
[=[        self._persistent_scripts: list[dict] = []
        self._persistent_traces: dict[str, list] = {}
        self._profile_dir: str | None = None]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "kwargs\\[\"persistent_context\"\\]")
        string(REPLACE [=[        if not bundled_visible_launch or locale_requested != "auto":
            kwargs["locale"] = locale

        window_size, window_diag = _resolve_window_size(cfg)
        if not headless:
            kwargs["window"] = window_size]=]
[=[        if not bundled_visible_launch or locale_requested != "auto":
            kwargs["locale"] = locale

        profile_dir = None
        if bundled_visible_launch:
            profile_dir = str(cfg.get("profile_dir") or _new_profile_dir())
            kwargs["persistent_context"] = True
            kwargs["user_data_dir"] = profile_dir

        window_size, window_diag = _resolve_window_size(cfg)
        if not headless:
            kwargs["window"] = window_size
        launch_timeout_floor_ms = 32000 if bundled_visible_launch else 5000
        launch_timeout_ms = min(max(_int_config(cfg.get("launch_timeout_ms"), 30000), launch_timeout_floor_ms), 120000)]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "timeout_ms=launch_timeout_ms")
        string(REPLACE [=[            enable_trace=bool(cfg.get("enable_trace")),
            window=window_diag,
        )]=]
[=[            enable_trace=bool(cfg.get("enable_trace")),
            window=window_diag,
            persistent=bool(kwargs.get("persistent_context")),
            timeout_ms=launch_timeout_ms,
        )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "profile_dir=profile_dir")
        string(REPLACE [=[                from_options_has_executable=bool(from_options.get("executable_path")),
                from_options_args=len(from_options.get("args") or []),
                from_options_has_env=bool(from_options.get("env")),
            )]=]
[=[                from_options_has_executable=bool(from_options.get("executable_path")),
                from_options_args=len(from_options.get("args") or []),
                from_options_has_env=bool(from_options.get("env")),
                persistent=bool(kwargs.get("persistent_context")),
                profile_dir=profile_dir or "",
            )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_begin")
        string(REPLACE [=[        try:
            self._cm = AsyncCamoufox(**kwargs)
            self.browser = await self._cm.__aenter__()

            ctx = self.browser.contexts[0] if self.browser.contexts else await self.browser.new_context()]=]
[=[        try:
            self._profile_dir = profile_dir
            self._cm = AsyncCamoufox(**kwargs)
            _camoufox_debug(
                "launch_context_enter_begin",
                persistent=bool(kwargs.get("persistent_context")),
                timeout_ms=launch_timeout_ms,
            )
            self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)
            _camoufox_debug(
                "launch_context_enter_ok",
                elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                browser_type=type(self.browser).__name__,
                persistent=bool(kwargs.get("persistent_context")),
            )

            if isinstance(self.browser, BrowserContext):
                ctx = self.browser
            else:
                if self.browser.contexts:
                    ctx = self.browser.contexts[0]
                else:
                    _camoufox_debug("launch_new_context_begin")
                    ctx = await asyncio.wait_for(self.browser.new_context(), timeout=max(5.0, launch_timeout_ms / 3000))
                    _camoufox_debug("launch_new_context_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
            "            page = ctx.pages[0] if ctx.pages else await ctx.new_page()"
            "            if ctx.pages:\n                page = ctx.pages[0]\n            else:\n                _camoufox_debug(\"launch_new_page_begin\")\n                page = await asyncio.wait_for(ctx.new_page(), timeout=max(5.0, launch_timeout_ms / 3000))\n                _camoufox_debug(\"launch_new_page_ok\", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE [=[                error_len=len(str(exc)),
                window=window_diag,
            )
            raise]=]
[=[                error_len=len(str(exc)),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
            )
            if self._cm is not None:
                try:
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                except Exception:
                    pass
            self.browser = None
            self.contexts.clear()
            self.pages.clear()
            self.active_page_name = None
            self._cm = None
            self._profile_dir = None
            if profile_dir:
                try:
                    import shutil
                    shutil.rmtree(profile_dir, ignore_errors=True)
                except Exception:
                    pass
            raise]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "_shutil.rmtree\\(profile_dir"
        AND NOT AIDA_CAMOUFOX_CONTENT MATCHES "shutil.rmtree\\(profile_dir")
        string(REPLACE [=[    async def close(self) -> dict:
        """Close the browser and clean up all resources."""
        if self._cm is not None:]=]
[=[    async def close(self) -> dict:
        """Close the browser and clean up all resources."""
        profile_dir = self._profile_dir
        if self._cm is not None:]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE [=[        self._persistent_traces.clear()
        self._nav_responses.clear()
        self._route_handlers.clear()
        return {"status": "closed"}]=]
[=[        self._persistent_traces.clear()
        self._nav_responses.clear()
        self._route_handlers.clear()
        self._profile_dir = None
        if profile_dir:
            try:
                import shutil
                shutil.rmtree(profile_dir, ignore_errors=True)
            except Exception:
                pass
        return {"status": "closed"}]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_CONTENT}" "_os.environ.get(\"AIDA_CAMOUFOX_EXECUTABLE\")" AIDA_CAMOUFOX_SHADOWED_ENV_POS)

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "bundled_visible_launch"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "ff_version"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_bundled_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_build_camoufox_launch_options"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_DEBUG_LOG"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "persistent_context"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir"
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
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "launch_timeout_ms: int" AIDA_CAMOUFOX_NAV_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"launch_timeout_ms\": launch_timeout_ms" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)

    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"    window_width: int = 1280,
    window_height: int = 900,
) -> dict:"
"    window_width: int = 1280,
    window_height: int = 900,
    executable_path: str | None = None,
    ff_version: int | None = None,
    launch_timeout_ms: int = 30000,
) -> dict:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    if(AIDA_CAMOUFOX_NAV_TIMEOUT_POS EQUAL -1 AND NOT AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1)
        string(REPLACE
"    ff_version: int | None = None,
) -> dict:"
"    ff_version: int | None = None,
    launch_timeout_ms: int = 30000,
) -> dict:"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"launch_timeout_ms\": launch_timeout_ms" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)
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

    if(AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS EQUAL -1)
        string(REPLACE
"            \"window_width\": window_width,
            \"window_height\": window_height,
        }"
"            \"window_width\": window_width,
            \"window_height\": window_height,
            \"launch_timeout_ms\": launch_timeout_ms,
        }"
            AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    endif()

    string(REPLACE
"        await page.goto(current_url, wait_until=wait_until)
        return {\"url\": page.url, \"title\": await page.title()}"
"        await page.goto(current_url, wait_until=wait_until)
        title = \"\"
        title_error = None
        try:
            title = await page.title()
        except Exception as e:
            title_error = str(e)
        out = {\"url\": page.url, \"title\": title}
        if title_error:
            out[\"title_error\"] = title_error
        return out"
        AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(REPLACE
"        bounds = await browser_manager._page_bounds(page)
        return {
            \"url\": page.url, \"title\": await page.title(),
            \"viewport_width\": viewport.get(\"width\"),
            \"viewport_height\": viewport.get(\"height\"),
            \"window_bounds\": bounds,
        }"
"        bounds = await browser_manager._page_bounds(page)
        title = \"\"
        title_error = None
        try:
            title = await page.title()
        except Exception as e:
            title_error = str(e)
        out = {
            \"url\": page.url, \"title\": title,
            \"viewport_width\": viewport.get(\"width\"),
            \"viewport_height\": viewport.get(\"height\"),
            \"window_bounds\": bounds,
        }
        if title_error:
            out[\"title_error\"] = title_error
        return out"
        AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "executable_path: str | None" AIDA_CAMOUFOX_NAV_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "ff_version: int | None" AIDA_CAMOUFOX_NAV_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "launch_timeout_ms: int" AIDA_CAMOUFOX_NAV_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"executable_path\"] = executable_path" AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "config[\"ff_version\"] = int(ff_version)" AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "\"launch_timeout_ms\": launch_timeout_ms" AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "bounds = await browser_manager._page_bounds(page)
        title = \"\"" AIDA_CAMOUFOX_NAV_SAFE_PAGE_INFO_POS)
    string(FIND "${AIDA_CAMOUFOX_NAV_CONTENT}" "return {\"url\": page.url, \"title\": await page.title()}" AIDA_CAMOUFOX_NAV_UNSAFE_TITLE_POS)
    if(AIDA_CAMOUFOX_NAV_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_VERSION_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_TIMEOUT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_EXECUTABLE_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_VERSION_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_CONFIG_TIMEOUT_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_SAFE_PAGE_INFO_POS EQUAL -1
        OR AIDA_CAMOUFOX_NAV_UNSAFE_TITLE_POS GREATER -1)
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_NAV_CONTENT STREQUAL AIDA_CAMOUFOX_NAV_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_NAV_PATCH_FILE}" "${AIDA_CAMOUFOX_NAV_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_NAV_PATCH_FILE}")
    endif()
endforeach()
