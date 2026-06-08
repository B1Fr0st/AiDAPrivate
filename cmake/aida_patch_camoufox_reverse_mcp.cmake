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
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "import ctypes as _ctypes")
        string(REPLACE
            "import contextlib\n"
            "import contextlib\nimport ctypes as _ctypes\n"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "import traceback as _traceback")
        string(REPLACE
            "import time\n"
            "import time\nimport traceback as _traceback\n"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE
        "import subprocess as _subprocess\n"
        ""
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "AIDA_CAMOUFOX_EXECUTABLE")
        string(REPLACE
"        if cfg.get(\"block_webrtc\"):
            kwargs[\"block_webrtc\"] = True

        locale = cfg.get(\"locale\", \"auto\")"
"        kwargs[\"block_webrtc\"] = True
        cfg.pop(\"user_agent\", None)
        cfg.pop(\"userAgent\", None)

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

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "cfg\\.pop\\(\"userAgent\"")
        string(REPLACE
"        if cfg.get(\"block_webrtc\"):
            kwargs[\"block_webrtc\"] = True"
"        kwargs[\"block_webrtc\"] = True
        cfg.pop(\"user_agent\", None)
        cfg.pop(\"userAgent\", None)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
        string(REPLACE
"        kwargs[\"block_webrtc\"] = True

        locale ="
"        kwargs[\"block_webrtc\"] = True
        cfg.pop(\"user_agent\", None)
        cfg.pop(\"userAgent\", None)

        locale ="
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

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _write_private_profile_prefs")
        string(REPLACE [=[def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")]=]
[=[def _new_profile_dir() -> str:
    root = _os.environ.get("AIDA_CAMOUFOX_PROFILE_ROOT", "")
    if not root:
        base = _os.environ.get("LOCALAPPDATA") or _os.environ.get("TEMP") or _os.getcwd()
        root = _os.path.join(base, "AiDA", "camoufox-profiles")
    _os.makedirs(root, exist_ok=True)
    return _os.path.join(root, f"profile-{_os.getpid()}-{int(time.time() * 1000)}")


def _write_private_profile_prefs(profile_dir: str | None) -> dict[str, Any]:
    prefs = {
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.proxy_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.obfuscate_host_addresses": True,
    }
    out: dict[str, Any] = {"profile_dir": profile_dir or "", "prefs": sorted(prefs.keys()), "written": False}
    if not profile_dir:
        return out
    try:
        _os.makedirs(profile_dir, exist_ok=True)
        path = _os.path.join(profile_dir, "user.js")
        try:
            with open(path, "r", encoding="utf-8") as fp:
                existing = fp.read()
        except FileNotFoundError:
            existing = ""
        keys = tuple(prefs.keys())
        lines = [
            line for line in existing.splitlines()
            if not any(line.strip().startswith(f"user_pref(\"{key}\"") for key in keys)
        ]
        rendered = []
        for key, value in prefs.items():
            if isinstance(value, bool):
                value_text = "true" if value else "false"
            else:
                value_text = _json.dumps(value)
            rendered.append(f"user_pref(\"{key}\", {value_text});")
        with open(path, "w", encoding="utf-8", newline="\n") as fp:
            if lines:
                fp.write("\n".join(lines).rstrip() + "\n")
            fp.write("\n".join(rendered) + "\n")
        out["written"] = True
        out["path"] = path
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out


async def _verify_private_page(page: Page | None) -> dict[str, Any]:
    out: dict[str, Any] = {"webrtc_disabled": False, "ua_policy": "camoufox_native"}
    if page is None:
        out["error"] = "missing_page"
        return out
    try:
        state = await page.evaluate("""() => ({
            rtc: typeof RTCPeerConnection,
            mozRtc: typeof mozRTCPeerConnection,
            uaLength: String(navigator.userAgent || "").length
        })""")
        rtc_type = str((state or {}).get("rtc", ""))
        moz_rtc_type = str((state or {}).get("mozRtc", ""))
        out["rtc_type"] = rtc_type
        out["moz_rtc_type"] = moz_rtc_type
        out["ua_length"] = int((state or {}).get("uaLength", 0) or 0)
        out["webrtc_disabled"] = rtc_type == "undefined" and moz_rtc_type == "undefined"
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _write_private_profile_prefs")
        string(REPLACE [=[def _windows_descendant_pids(root_pid: int) -> list[int]:]=]
[=[def _write_private_profile_prefs(profile_dir: str | None) -> dict[str, Any]:
    prefs = {
        "media.peerconnection.enabled": False,
        "media.peerconnection.ice.proxy_only": True,
        "media.peerconnection.ice.no_host": True,
        "media.peerconnection.ice.default_address_only": True,
        "media.peerconnection.ice.obfuscate_host_addresses": True,
    }
    out: dict[str, Any] = {"profile_dir": profile_dir or "", "prefs": sorted(prefs.keys()), "written": False}
    if not profile_dir:
        return out
    try:
        _os.makedirs(profile_dir, exist_ok=True)
        path = _os.path.join(profile_dir, "user.js")
        try:
            with open(path, "r", encoding="utf-8") as fp:
                existing = fp.read()
        except FileNotFoundError:
            existing = ""
        keys = tuple(prefs.keys())
        lines = [
            line for line in existing.splitlines()
            if not any(line.strip().startswith(f"user_pref(\"{key}\"") for key in keys)
        ]
        rendered = []
        for key, value in prefs.items():
            if isinstance(value, bool):
                value_text = "true" if value else "false"
            else:
                value_text = _json.dumps(value)
            rendered.append(f"user_pref(\"{key}\", {value_text});")
        with open(path, "w", encoding="utf-8", newline="\n") as fp:
            if lines:
                fp.write("\n".join(lines).rstrip() + "\n")
            fp.write("\n".join(rendered) + "\n")
        out["written"] = True
        out["path"] = path
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out


async def _verify_private_page(page: Page | None) -> dict[str, Any]:
    out: dict[str, Any] = {"webrtc_disabled": False, "ua_policy": "camoufox_native"}
    if page is None:
        out["error"] = "missing_page"
        return out
    try:
        state = await page.evaluate("""() => ({
            rtc: typeof RTCPeerConnection,
            mozRtc: typeof mozRTCPeerConnection,
            uaLength: String(navigator.userAgent || "").length
        })""")
        rtc_type = str((state or {}).get("rtc", ""))
        moz_rtc_type = str((state or {}).get("mozRtc", ""))
        out["rtc_type"] = rtc_type
        out["moz_rtc_type"] = moz_rtc_type
        out["ua_length"] = int((state or {}).get("uaLength", 0) or 0)
        out["webrtc_disabled"] = rtc_type == "undefined" and moz_rtc_type == "undefined"
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 300)
    return out


def _windows_descendant_pids(root_pid: int) -> list[int]:]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "media\\.peerconnection\\.enabled")
        string(REPLACE
"        \"browser.sessionstore.resume_from_crash\": False,"
"        \"browser.sessionstore.resume_from_crash\": False,
        \"media.peerconnection.enabled\": False,
        \"media.peerconnection.ice.proxy_only\": True,
        \"media.peerconnection.ice.no_host\": True,
        \"media.peerconnection.ice.default_address_only\": True,
        \"media.peerconnection.ice.obfuscate_host_addresses\": True,"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "prefs\\[\"media\\.peerconnection\\.enabled\"\\] = False")
        string(REPLACE [=[            if isinstance(cfg.get("firefox_user_prefs"), dict):
                prefs.update(cfg["firefox_user_prefs"])
            kwargs["firefox_user_prefs"] = prefs]=]
[=[            if isinstance(cfg.get("firefox_user_prefs"), dict):
                prefs.update(cfg["firefox_user_prefs"])
            prefs["media.peerconnection.enabled"] = False
            prefs["media.peerconnection.ice.proxy_only"] = True
            prefs["media.peerconnection.ice.no_host"] = True
            prefs["media.peerconnection.ice.default_address_only"] = True
            prefs["media.peerconnection.ice.obfuscate_host_addresses"] = True
            kwargs["firefox_user_prefs"] = prefs]=]
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

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _profile_snapshot")
        string(REPLACE [=[def _prepare_profile_dir(profile_dir: str, generated: bool) -> tuple[str, dict[str, Any]]:
    resolved = _os.path.abspath(_os.path.expandvars(_os.path.expanduser(str(profile_dir))))
    existed = _os.path.exists(resolved)
    if generated and existed:
        _shutil.rmtree(resolved, ignore_errors=True)
        existed = False
    _os.makedirs(resolved, exist_ok=True)
    locks = _profile_lock_info(resolved)
    info = {
        "profile_dir": resolved,
        "generated": generated,
        "existed": existed,
        "locks": len(locks),
        "lock_names": [item.get("name", "") for item in locks],
    }
    return resolved, info]=]
[=[def _prepare_profile_dir(profile_dir: str, generated: bool) -> tuple[str, dict[str, Any]]:
    resolved = _os.path.abspath(_os.path.expandvars(_os.path.expanduser(str(profile_dir))))
    existed = _os.path.exists(resolved)
    if generated and existed:
        _shutil.rmtree(resolved, ignore_errors=True)
        existed = False
    _os.makedirs(resolved, exist_ok=True)
    locks = _profile_lock_info(resolved)
    info = {
        "profile_dir": resolved,
        "generated": generated,
        "existed": existed,
        "locks": len(locks),
        "lock_names": [item.get("name", "") for item in locks],
    }
    return resolved, info


def _profile_snapshot(profile_dir: str | None) -> dict[str, Any]:
    if not profile_dir:
        return {"present": False}
    out: dict[str, Any] = {"present": True, "profile_dir": str(profile_dir)}
    try:
        out["exists"] = _os.path.exists(profile_dir)
        out["locks"] = _profile_lock_info(profile_dir)
        names = ("parent.lock", ".parentlock", "lock", "compatibility.ini", "prefs.js", "sessionCheckpoints.json", "sessionstore.jsonlz4")
        files = []
        for name in names:
            path = _os.path.join(profile_dir, name)
            if _os.path.exists(path):
                item = _path_info(path)
                item["name"] = name
                files.append(item)
        out["files"] = files[:32]
        crash_dir = _os.path.join(profile_dir, "crashes")
        crashes = []
        if _os.path.isdir(crash_dir):
            for name in sorted(_os.listdir(crash_dir))[-24:]:
                crashes.append(_path_info(_os.path.join(crash_dir, name)))
        out["crashes"] = crashes
        out["descendants"] = _windows_descendant_pids(_os.getpid())[:32]
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 500)
    return out]=]
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
            profile_privacy = _write_private_profile_prefs(profile_dir)
            _camoufox_debug("launch_profile_privacy", **profile_privacy)
            if profile_dir and not profile_privacy.get("written"):
                raise RuntimeError("Camoufox privacy profile preferences were not written")
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
            "            if ctx.pages:\n                page = ctx.pages[0]\n            else:\n                _camoufox_debug(\"launch_new_page_begin\")\n                page = await asyncio.wait_for(ctx.new_page(), timeout=max(5.0, launch_timeout_ms / 3000))\n                _camoufox_debug(\"launch_new_page_ok\", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))\n            privacy_info = await _verify_private_page(page)\n            _camoufox_debug(\"launch_privacy_verified\", **privacy_info)\n            if not privacy_info.get(\"webrtc_disabled\"):\n                raise RuntimeError(\"Camoufox privacy verification failed: WebRTC is still exposed\")"
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

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_wait")
        string(REPLACE [=[            self._cm = AsyncCamoufox(**kwargs)
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
            )]=]
[=[            self._cm = AsyncCamoufox(**kwargs)
            _camoufox_debug(
                "launch_context_enter_begin",
                persistent=bool(kwargs.get("persistent_context")),
                timeout_ms=launch_timeout_ms,
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],
            )

            async def _aida_launch_watchdog() -> None:
                tick = 0
                while True:
                    await asyncio.sleep(5)
                    tick += 1
                    _camoufox_debug(
                        "launch_context_enter_wait",
                        tick=tick,
                        elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                        persistent=bool(kwargs.get("persistent_context")),
                        timeout_ms=launch_timeout_ms,
                        profile_snapshot=_profile_snapshot(profile_dir),
                        descendants=_windows_descendant_pids(_os.getpid())[:32],
                    )

            watchdog_task = asyncio.create_task(_aida_launch_watchdog())
            try:
                self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)
            finally:
                watchdog_task.cancel()
                with contextlib.suppress(BaseException):
                    await watchdog_task
            _camoufox_debug(
                "launch_context_enter_ok",
                elapsed_ms=int((time.perf_counter() - launch_started) * 1000),
                browser_type=type(self.browser).__name__,
                persistent=bool(kwargs.get("persistent_context")),
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],
            )]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_profile_privacy")
        string(REPLACE [=[        try:
            self._profile_dir = profile_dir]=]
[=[        try:
            profile_privacy = _write_private_profile_prefs(profile_dir)
            _camoufox_debug("launch_profile_privacy", **profile_privacy)
            if profile_dir and not profile_privacy.get("written"):
                raise RuntimeError("Camoufox privacy profile preferences were not written")
            self._profile_dir = profile_dir]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_privacy_verified")
        string(REPLACE [=[            if ctx.pages:
                page = ctx.pages[0]
            else:
                _camoufox_debug("launch_new_page_begin")
                page = await asyncio.wait_for(ctx.new_page(), timeout=max(5.0, launch_timeout_ms / 3000))
                _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))]=]
[=[            if ctx.pages:
                page = ctx.pages[0]
            else:
                _camoufox_debug("launch_new_page_begin")
                page = await asyncio.wait_for(ctx.new_page(), timeout=max(5.0, launch_timeout_ms / 3000))
                _camoufox_debug("launch_new_page_ok", elapsed_ms=int((time.perf_counter() - launch_started) * 1000))
            privacy_info = await _verify_private_page(page)
            _camoufox_debug("launch_privacy_verified", **privacy_info)
            if not privacy_info.get("webrtc_disabled"):
                raise RuntimeError("Camoufox privacy verification failed: WebRTC is still exposed")]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[    started = time.perf_counter()
    pids = _windows_descendant_pids(_os.getpid())
    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}]=]
[=[    started = time.perf_counter()
    _camoufox_debug("descendant_cleanup_scan_begin", reason=reason)
    pids = _windows_descendant_pids(_os.getpid())
    _camoufox_debug("descendant_cleanup_scan_end", reason=reason, count=len(pids), pids=pids[:24])
    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}
    for pid in reversed(pids):]=]
[=[    summary: dict[str, Any] = {"reason": reason, "count": len(pids), "pids": pids[:24], "results": []}
    _camoufox_debug("descendant_cleanup_begin", reason=reason, count=len(pids), pids=pids[:24])
    for pid in reversed(pids):]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    if pids:
        _camoufox_debug("descendant_cleanup", **summary)
    return summary]=]
[=[    summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    summary["after_pids"] = _windows_descendant_pids(_os.getpid())[:24]
    summary["after_count"] = len(summary["after_pids"])
    _camoufox_debug("descendant_cleanup", **summary)
    return summary]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[    for pid in reversed(pids):
        try:
            proc_started = time.perf_counter()
            result = _subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=6,
            )
            summary["results"].append({
                "pid": pid,
                "returncode": int(result.returncode),
                "elapsed_ms": int((time.perf_counter() - proc_started) * 1000),
                "stdout": _safe_text(result.stdout, 240),
                "stderr": _safe_text(result.stderr, 240),
            })
        except Exception as exc:
            summary["results"].append({
                "pid": pid,
                "error_type": type(exc).__name__,
                "error": _safe_text(exc, 240),
            })]=]
[=[    try:
        kernel32 = _ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [_ctypes.c_ulong, _ctypes.c_int, _ctypes.c_ulong]
        kernel32.OpenProcess.restype = _ctypes.c_void_p
        kernel32.TerminateProcess.argtypes = [_ctypes.c_void_p, _ctypes.c_uint]
        kernel32.TerminateProcess.restype = _ctypes.c_int
        kernel32.WaitForSingleObject.argtypes = [_ctypes.c_void_p, _ctypes.c_ulong]
        kernel32.WaitForSingleObject.restype = _ctypes.c_ulong
        kernel32.GetExitCodeProcess.argtypes = [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_ulong)]
        kernel32.GetExitCodeProcess.restype = _ctypes.c_int
        kernel32.CloseHandle.argtypes = [_ctypes.c_void_p]
        kernel32.CloseHandle.restype = _ctypes.c_int
    except Exception as exc:
        summary["setup_error_type"] = type(exc).__name__
        summary["setup_error"] = _safe_text(exc, 240)
        summary["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        summary["after_pids"] = _windows_descendant_pids(_os.getpid())[:24]
        summary["after_count"] = len(summary["after_pids"])
        _camoufox_debug("descendant_cleanup", **summary)
        return summary

    process_access = 0x0001 | 0x1000 | 0x00100000
    still_active = 259
    for pid in reversed(pids):
        proc_started = time.perf_counter()
        entry: dict[str, Any] = {"pid": int(pid)}
        handle = None
        try:
            _camoufox_debug("descendant_cleanup_process_begin", target_pid=int(pid), reason=reason)
            handle = kernel32.OpenProcess(process_access, 0, int(pid))
            _camoufox_debug("descendant_cleanup_process_open", target_pid=int(pid), open_ok=bool(handle), error=0 if handle else int(_ctypes.get_last_error()))
            if not handle:
                entry["open_ok"] = False
                entry["open_error"] = int(_ctypes.get_last_error())
            else:
                entry["open_ok"] = True
                exit_before = _ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry["exit_code_before"] = int(exit_before.value)
                    _camoufox_debug("descendant_cleanup_process_exit_before", target_pid=int(pid), exit_code=int(exit_before.value))
                else:
                    entry["exit_code_before_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_exit_before", target_pid=int(pid), error=int(entry["exit_code_before_error"]))
                if entry.get("exit_code_before", still_active) == still_active:
                    terminate_ok = bool(kernel32.TerminateProcess(handle, 1))
                    entry["terminate_ok"] = terminate_ok
                    if not terminate_ok:
                        entry["terminate_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_terminate", target_pid=int(pid), terminate_ok=terminate_ok, error=int(entry.get("terminate_error", 0)))
                    entry["wait_result"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))
                    _camoufox_debug("descendant_cleanup_process_wait", target_pid=int(pid), wait_result=int(entry["wait_result"]))
                else:
                    entry["terminate_ok"] = False
                    entry["already_exited"] = True
                    entry["wait_result"] = int(kernel32.WaitForSingleObject(handle, 0))
                    _camoufox_debug("descendant_cleanup_process_wait", target_pid=int(pid), wait_result=int(entry["wait_result"]), already_exited=True)
                exit_after = _ctypes.c_ulong(0)
                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry["exit_code_after"] = int(exit_after.value)
                    _camoufox_debug("descendant_cleanup_process_exit_after", target_pid=int(pid), exit_code=int(exit_after.value))
                else:
                    entry["exit_code_after_error"] = int(_ctypes.get_last_error())
                    _camoufox_debug("descendant_cleanup_process_exit_after", target_pid=int(pid), error=int(entry["exit_code_after_error"]))
        except Exception as exc:
            entry["error_type"] = type(exc).__name__
            entry["error"] = _safe_text(exc, 240)
            _camoufox_debug("descendant_cleanup_process_exception", target_pid=int(pid), error_type=type(exc).__name__, error=_safe_text(exc, 240))
        finally:
            if handle:
                close_ok = bool(kernel32.CloseHandle(handle))
                entry["close_ok"] = close_ok
                if not close_ok:
                    entry["close_error"] = int(_ctypes.get_last_error())
                _camoufox_debug("descendant_cleanup_process_close", target_pid=int(pid), close_ok=close_ok, error=int(entry.get("close_error", 0)))
            entry["elapsed_ms"] = int((time.perf_counter() - proc_started) * 1000)
            summary["results"].append(entry)
            _camoufox_debug("descendant_cleanup_process", target_pid=int(pid), cleanup_result=entry)]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_begin")
        string(REPLACE
"        try:
            handle = kernel32.OpenProcess(process_access, 0, int(pid))"
"        try:
            _camoufox_debug(\"descendant_cleanup_process_begin\", target_pid=int(pid), reason=reason)
            handle = kernel32.OpenProcess(process_access, 0, int(pid))
            _camoufox_debug(\"descendant_cleanup_process_open\", target_pid=int(pid), open_ok=bool(handle), error=0 if handle else int(_ctypes.get_last_error()))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry[\"exit_code_before\"] = int(exit_before.value)
                else:
                    entry[\"exit_code_before_error\"] = int(_ctypes.get_last_error())"
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_before)):
                    entry[\"exit_code_before\"] = int(exit_before.value)
                    _camoufox_debug(\"descendant_cleanup_process_exit_before\", target_pid=int(pid), exit_code=int(exit_before.value))
                else:
                    entry[\"exit_code_before_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_exit_before\", target_pid=int(pid), error=int(entry[\"exit_code_before_error\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                    if not terminate_ok:
                        entry[\"terminate_error\"] = int(_ctypes.get_last_error())
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))"
"                    if not terminate_ok:
                        entry[\"terminate_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_terminate\", target_pid=int(pid), terminate_ok=terminate_ok, error=int(entry.get(\"terminate_error\", 0)))
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 2000 if terminate_ok else 0))
                    _camoufox_debug(\"descendant_cleanup_process_wait\", target_pid=int(pid), wait_result=int(entry[\"wait_result\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                    entry[\"already_exited\"] = True
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 0))"
"                    entry[\"already_exited\"] = True
                    entry[\"wait_result\"] = int(kernel32.WaitForSingleObject(handle, 0))
                    _camoufox_debug(\"descendant_cleanup_process_wait\", target_pid=int(pid), wait_result=int(entry[\"wait_result\"]), already_exited=True)"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry[\"exit_code_after\"] = int(exit_after.value)
                else:
                    entry[\"exit_code_after_error\"] = int(_ctypes.get_last_error())"
"                if kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_after)):
                    entry[\"exit_code_after\"] = int(exit_after.value)
                    _camoufox_debug(\"descendant_cleanup_process_exit_after\", target_pid=int(pid), exit_code=int(exit_after.value))
                else:
                    entry[\"exit_code_after_error\"] = int(_ctypes.get_last_error())
                    _camoufox_debug(\"descendant_cleanup_process_exit_after\", target_pid=int(pid), error=int(entry[\"exit_code_after_error\"]))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"        except Exception as exc:
            entry[\"error_type\"] = type(exc).__name__
            entry[\"error\"] = _safe_text(exc, 240)"
"        except Exception as exc:
            entry[\"error_type\"] = type(exc).__name__
            entry[\"error\"] = _safe_text(exc, 240)
            _camoufox_debug(\"descendant_cleanup_process_exception\", target_pid=int(pid), error_type=type(exc).__name__, error=_safe_text(exc, 240))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

        string(REPLACE
"                if not close_ok:
                    entry[\"close_error\"] = int(_ctypes.get_last_error())"
"                if not close_ok:
                    entry[\"close_error\"] = int(_ctypes.get_last_error())
                _camoufox_debug(\"descendant_cleanup_process_close\", target_pid=int(pid), close_ok=close_ok, error=int(entry.get(\"close_error\", 0)))"
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[            if self._cm is not None:
                try:
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                except Exception:
                    pass]=]
[=[            if self._cm is not None:
                try:
                    cleanup_started = time.perf_counter()
                    _camoufox_debug("launch_error_context_exit_begin")
                    await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)
                    _camoufox_debug("launch_error_context_exit_ok", elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000))
                except Exception as cleanup_exc:
                    _camoufox_debug(
                        "launch_error_context_exit_failed",
                        elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000),
                        error_type=type(cleanup_exc).__name__,
                        error_len=len(str(cleanup_exc)),
                        error_summary=_safe_text(cleanup_exc),
                    )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    if(NOT AIDA_CAMOUFOX_CONTENT MATCHES "error_traceback")
        string(REPLACE [=[                error_len=len(str(exc)),
                error_summary=_safe_text(exc),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
                profile=profile_info,]=]
[=[                error_len=len(str(exc)),
                error_summary=_safe_text(exc),
                error_repr=_safe_text(repr(exc), 1000),
                error_args=[_safe_text(arg, 500) for arg in getattr(exc, "args", ())],
                error_dict={str(k): _safe_text(v, 500) for k, v in getattr(exc, "__dict__", {}).items()},
                error_traceback=_safe_text("".join(_traceback.format_exception(type(exc), exc, exc.__traceback__)), 4000),
                window=window_diag,
                persistent=bool(kwargs.get("persistent_context")),
                profile=profile_info,
                profile_snapshot=_profile_snapshot(profile_dir),
                descendants=_windows_descendant_pids(_os.getpid())[:32],]=]
            AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")
    endif()

    string(REPLACE [=[                except Exception:
                    _camoufox_debug("launch_error_context_exit_failed")]=]
[=[                except Exception as cleanup_exc:
                    _camoufox_debug(
                        "launch_error_context_exit_failed",
                        elapsed_ms=int((time.perf_counter() - cleanup_started) * 1000),
                        error_type=type(cleanup_exc).__name__,
                        error_len=len(str(cleanup_exc)),
                        error_summary=_safe_text(cleanup_exc),
                    )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE
        "                await self._cm.__aexit__(None, None, None)"
        "                await asyncio.wait_for(self._cm.__aexit__(None, None, None), timeout=10)"
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

    string(REPLACE [=[            except Exception:
                _camoufox_debug("close_context_exit_failed")]=]
[=[            except Exception as close_exc:
                _camoufox_debug(
                    "close_context_exit_failed",
                    elapsed_ms=int((time.perf_counter() - exit_started) * 1000),
                    error_type=type(close_exc).__name__,
                    error_len=len(str(close_exc)),
                    error_summary=_safe_text(close_exc),
                )]=]
        AIDA_CAMOUFOX_CONTENT "${AIDA_CAMOUFOX_CONTENT}")

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
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "import ctypes as _ctypes"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "import traceback as _traceback"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "cfg\\.pop\\(\"userAgent\""
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _write_private_profile_prefs"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _verify_private_page"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "media\\.peerconnection\\.enabled"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "prefs\\[\"media\\.peerconnection\\.enabled\"\\] = False"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_context_enter_wait"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_profile_privacy"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "launch_privacy_verified"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "error_traceback"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "def _profile_snapshot"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "persistent_context"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "_profile_dir"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_scan_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_scan_end"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_begin"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_open"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_wait"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process_close"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "descendant_cleanup_process"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "OpenProcess"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "TerminateProcess"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "WaitForSingleObject"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "GetExitCodeProcess"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "CloseHandle"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "cleanup_exc"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "close_exc"
        OR NOT AIDA_CAMOUFOX_CONTENT MATCHES "asyncio.wait_for\\(self\\._cm\\.__aexit__"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "taskkill\\.exe"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "_subprocess"
        OR AIDA_CAMOUFOX_CONTENT MATCHES "import subprocess as _subprocess"
        OR AIDA_CAMOUFOX_SHADOWED_ENV_POS GREATER -1)
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_CONTENT STREQUAL AIDA_CAMOUFOX_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_PATCH_FILE}" "${AIDA_CAMOUFOX_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_PATCH_FILE}")
    endif()
endforeach()


set(AIDA_CAMOUFOX_HOOKING_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/hooking.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/hooking.py"
)

foreach(AIDA_CAMOUFOX_HOOKING_PATCH_FILE IN LISTS AIDA_CAMOUFOX_HOOKING_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}" AIDA_CAMOUFOX_HOOKING_CONTENT)
    set(AIDA_CAMOUFOX_HOOKING_ORIGINAL "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")

    if(NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "context_init")
        string(REPLACE [=[        page = await browser_manager.get_active_page()
        await page.add_init_script(script=script)
        browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": False,
            "page_init": True,
            "applied_to_current_page": warning is None,
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out]=]
[=[        page = await browser_manager.get_active_page()
        ctx = page.context
        await ctx.add_init_script(script=script)
        replaced = False
        for script_info in browser_manager._persistent_scripts:
            if script_info.get("name") == script_name:
                script_info["content"] = script
                replaced = True
                break
        if not replaced:
            browser_manager._persistent_scripts.append({"name": script_name, "content": script})
        browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": True,
            "context_init": True,
            "page_init": False,
            "applied_to_current_page": warning is None,
            "contexts": len(browser_manager.contexts),
            "pages": len(browser_manager.pages),
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out]=]
            AIDA_CAMOUFOX_HOOKING_CONTENT "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
    endif()

    if(NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "context_init"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "ctx.add_init_script"
        OR NOT AIDA_CAMOUFOX_HOOKING_CONTENT MATCHES "_persistent_scripts")
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_HOOKING_CONTENT STREQUAL AIDA_CAMOUFOX_HOOKING_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}" "${AIDA_CAMOUFOX_HOOKING_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_HOOKING_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/hooks/jsvmp_hook.js"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/hooks/jsvmp_hook.js"
)

foreach(AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE IN LISTS AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT)
    set(AIDA_CAMOUFOX_JSVMP_HOOK_ORIGINAL "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")

    string(REPLACE
        "try { src = _FP_call.call(_FP_toString, v); } catch (e) {}"
        "try { src = _Reflect_apply(_FP_toString, v, []); } catch (e) {}"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(this, thisArg, argsArray);"
        "return _Reflect_apply(_FP_apply, this, [thisArg, argsArray]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "var argsArr = _Array.prototype.slice.call(arguments, 1);"
        "var argsArr = _Reflect_apply(_Array.prototype.slice, arguments, [1]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(this, thisArg, _Array.prototype.slice.call(arguments, 1));"
        "return _Reflect_apply(_FP_apply, this, [thisArg, _Reflect_apply(_Array.prototype.slice, arguments, [1])]);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "return _FP_apply.call(_FP_bind, this, arguments);"
        "return _Reflect_apply(_FP_bind, this, arguments);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
    string(REPLACE
        "var r = _FP_apply.call(origFn, this, arguments);"
        "var r = _Reflect_apply(origFn, this, arguments);"
        AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "_FP_apply.call" AIDA_CAMOUFOX_JSVMP_HOOK_APPLY_CALL_POS)
    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "_FP_call.call" AIDA_CAMOUFOX_JSVMP_HOOK_CALL_CALL_POS)
    string(FIND "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}" "slice.call(arguments" AIDA_CAMOUFOX_JSVMP_HOOK_SLICE_CALL_POS)
    if(AIDA_CAMOUFOX_JSVMP_HOOK_APPLY_CALL_POS GREATER -1
        OR AIDA_CAMOUFOX_JSVMP_HOOK_CALL_CALL_POS GREATER -1
        OR AIDA_CAMOUFOX_JSVMP_HOOK_SLICE_CALL_POS GREATER -1
        OR NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT MATCHES "_Reflect_apply\\(_FP_apply, this"
        OR NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT MATCHES "_Reflect_apply\\(origFn, this")
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT STREQUAL AIDA_CAMOUFOX_JSVMP_HOOK_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}" "${AIDA_CAMOUFOX_JSVMP_HOOK_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_JSVMP_HOOK_PATCH_FILE}")
    endif()
endforeach()

set(AIDA_CAMOUFOX_VERIFICATION_PATCH_FILES
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-reverse-mcp/src/camoufox_reverse_mcp/tools/verification.py"
    "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/Lib/site-packages/camoufox_reverse_mcp/tools/verification.py"
)

foreach(AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE IN LISTS AIDA_CAMOUFOX_VERIFICATION_PATCH_FILES)
    if(NOT EXISTS "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
        continue()
    endif()

    file(READ "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}" AIDA_CAMOUFOX_VERIFICATION_CONTENT)
    set(AIDA_CAMOUFOX_VERIFICATION_ORIGINAL "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")

    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "import json as _json")
        string(REPLACE
"from __future__ import annotations

from ..server import mcp, browser_manager"
"from __future__ import annotations

import json as _json

from ..server import mcp, browser_manager"
            AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
    endif()

    string(REPLACE [=[                computed = await page.evaluate(
                    "(sample) => window.__mcp_signer_fn(sample)", sample_input)]=]
[=[                sample_json = _json.dumps(sample_input)
                computed = await page.evaluate(
                    f"() => window.__mcp_signer_fn({sample_json})")]=]
        AIDA_CAMOUFOX_VERIFICATION_CONTENT "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")

    string(FIND "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}" "(sample) => window.__mcp_signer_fn(sample)" AIDA_CAMOUFOX_VERIFICATION_OLD_EVAL_POS)
    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "import json as _json"
        OR NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT MATCHES "sample_json = _json.dumps\\(sample_input\\)"
        OR AIDA_CAMOUFOX_VERIFICATION_OLD_EVAL_POS GREATER -1)
        message(FATAL_ERROR "Failed to patch ${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
    endif()

    if(NOT AIDA_CAMOUFOX_VERIFICATION_CONTENT STREQUAL AIDA_CAMOUFOX_VERIFICATION_ORIGINAL)
        file(WRITE "${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}" "${AIDA_CAMOUFOX_VERIFICATION_CONTENT}")
        message(STATUS "Patched ${AIDA_CAMOUFOX_VERIFICATION_PATCH_FILE}")
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
    string(REPLACE "\r\n" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")
    string(REPLACE "\r" "\n" AIDA_CAMOUFOX_NAV_CONTENT "${AIDA_CAMOUFOX_NAV_CONTENT}")

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

set(AIDA_CAMOUFOX_MULTIPAGE_PATCHER "${CMAKE_CURRENT_LIST_DIR}/aida_camoufox_reverse_mcp_multipage.py")
set(AIDA_CAMOUFOX_PATCH_PYTHON "${AIDA_CAMOUFOX_STAGE_ROOT}/deps/camoufox-runtime/python.exe")
if(NOT EXISTS "${AIDA_CAMOUFOX_PATCH_PYTHON}")
    find_program(AIDA_CAMOUFOX_PATCH_PYTHON_FALLBACK NAMES python3 python)
    if(AIDA_CAMOUFOX_PATCH_PYTHON_FALLBACK)
        set(AIDA_CAMOUFOX_PATCH_PYTHON "${AIDA_CAMOUFOX_PATCH_PYTHON_FALLBACK}")
    endif()
endif()
if(NOT EXISTS "${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}")
    message(FATAL_ERROR "Missing Camoufox multipage patcher: ${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}")
endif()
if(NOT AIDA_CAMOUFOX_PATCH_PYTHON)
    message(FATAL_ERROR "Python interpreter required for Camoufox multipage patcher")
endif()
execute_process(
    COMMAND "${AIDA_CAMOUFOX_PATCH_PYTHON}" "${AIDA_CAMOUFOX_MULTIPAGE_PATCHER}" "${AIDA_CAMOUFOX_STAGE_ROOT}"
    RESULT_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_RESULT
    OUTPUT_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT
    ERROR_VARIABLE AIDA_CAMOUFOX_MULTIPAGE_PATCH_ERR
)
if(NOT AIDA_CAMOUFOX_MULTIPAGE_PATCH_RESULT EQUAL 0)
    message(FATAL_ERROR "Camoufox multipage patch failed: ${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT} ${AIDA_CAMOUFOX_MULTIPAGE_PATCH_ERR}")
endif()
if(AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT)
    string(STRIP "${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT}" AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT_STRIPPED)
    message(STATUS "${AIDA_CAMOUFOX_MULTIPAGE_PATCH_OUT_STRIPPED}")
endif()
