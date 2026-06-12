param(
    [string]$Python = "",
    [string]$SourceRoot = "",
    [string]$OutputDir = "",
    [ValidateSet("auto", "pyinstaller", "nuitka")]
    [string]$Backend = "auto",
    [int]$Jobs = 0,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir "..")).Path
}

function Resolve-Python {
    param([string]$Requested)
    if ($Requested) {
        $resolved = Resolve-Path -LiteralPath $Requested -ErrorAction Stop
        return $resolved.Path
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        $candidate = (& $py.Source -3.12 -c "import sys; print(sys.executable)" 2>$null)
        if ($LASTEXITCODE -eq 0 -and $candidate) {
            return [string]$candidate
        }
    }
    $candidateRoots = @(
        "$env:LOCALAPPDATA\AiDA\runtimes\python\Python312-3.12.10-x64\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    foreach ($candidate in $candidateRoots) {
        if ($candidate -and [IO.File]::Exists($candidate)) {
            return $candidate
        }
    }
    throw "Python 3.12 or 3.13 is required to build the frozen Camoufox reverse MCP executable."
}

function Resolve-CamoufoxBrowser {
    param([string]$RepoRoot)
    $candidates = @(
        (Join-Path $RepoRoot "camoufox-135.0.1-beta.24-win.x86_64\camoufox.exe"),
        (Join-Path $RepoRoot "build-ninja\deps\camoufox-135.0.1-beta.24-win.x86_64\camoufox.exe"),
        (Join-Path $RepoRoot ".deps\camoufox-135.0.1-beta.24-win.x86_64\camoufox.exe")
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and [IO.File]::Exists($candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return ""
}

function Resolve-PatchedCamoufoxPackage {
    param([string]$RepoRoot)
    $candidates = @(
        (Join-Path $RepoRoot ".deps\camoufox-runtime\Lib\site-packages\camoufox"),
        (Join-Path $RepoRoot "build-ninja\deps\camoufox-runtime\Lib\site-packages\camoufox"),
        (Join-Path $RepoRoot "camoufox-runtime\Lib\site-packages\camoufox")
    )
    foreach ($candidate in $candidates) {
        $fingerprints = Join-Path $candidate "fingerprints.py"
        if ($candidate -and [IO.Directory]::Exists($candidate) -and [IO.File]::Exists($fingerprints)) {
            if (Select-String -LiteralPath $fingerprints -Pattern "def generate_context_fingerprint" -Quiet) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }
    throw "AiDA patched Camoufox package with generate_context_fingerprint was not found."
}

function Install-PatchedCamoufoxPackage {
    param(
        [string]$VenvPython,
        [string]$RepoRoot
    )
    $package = Resolve-PatchedCamoufoxPackage $RepoRoot
    $sitePackages = (& $VenvPython -c "import site; print(site.getsitepackages()[0])")
    if ($LASTEXITCODE -ne 0 -or -not $sitePackages) {
        throw "Failed to resolve venv site-packages."
    }
    $sitePackages = [string]$sitePackages
    if (-not [IO.Directory]::Exists($sitePackages)) {
        throw "Resolved venv site-packages directory does not exist: $sitePackages"
    }
    $dest = Join-Path $sitePackages "camoufox"
    if ([IO.Directory]::Exists($dest)) {
        Remove-Item -LiteralPath $dest -Recurse -Force
    }
    Copy-Item -LiteralPath $package -Destination $dest -Recurse -Force
    Write-Output "patched_camoufox_package=$package"
}

function Invoke-FrozenMcpSmoke {
    param(
        [string]$Executable,
        [string]$RepoRoot
    )
    $browser = Resolve-CamoufoxBrowser $RepoRoot
    if (-not $browser) {
        throw "Camoufox browser executable for frozen MCP smoke was not found."
    }
    $smokeLog = Join-Path $env:TEMP "aida_camoufox_frozen_mcp_smoke.log"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.WorkingDirectory = $RepoRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment["AIDA_CAMOUFOX_IMPORT_SMOKE"] = "1"
    $psi.Environment["AIDA_CAMOUFOX_EXECUTABLE"] = $browser
    $psi.Environment["AIDA_CAMOUFOX_DEBUG_LOG"] = $smokeLog
    $psi.Environment["AIDA_CAMOUFOX_DEBUG_STDERR"] = "0"
    $psi.Environment["PYTHONIOENCODING"] = "utf-8"
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    if (-not $proc.Start()) {
        throw "Frozen MCP smoke process failed to start."
    }
    if (-not $proc.WaitForExit(90000)) {
        try { $proc.Kill() } catch {}
        throw "Frozen MCP smoke timed out after 90000 ms."
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    if ($proc.ExitCode -ne 0 -or $stdout -notmatch "AIDA_CAMOUFOX_IMPORT_SMOKE_OK") {
        throw "Frozen MCP smoke failed with exit $($proc.ExitCode). stdout=[$stdout] stderr=[$stderr]"
    }
    Write-Output "frozen_mcp_smoke=ok"
    Write-Output "frozen_mcp_smoke_browser=$browser"
    Write-Output "frozen_mcp_smoke_log=$smokeLog"

    $livePsi = [System.Diagnostics.ProcessStartInfo]::new()
    $livePsi.FileName = $Executable
    $livePsi.WorkingDirectory = $RepoRoot
    $livePsi.UseShellExecute = $false
    $livePsi.CreateNoWindow = $true
    $livePsi.RedirectStandardOutput = $true
    $livePsi.RedirectStandardError = $true
    $livePsi.Environment["AIDA_CAMOUFOX_LIVE_SMOKE"] = "1"
    $livePsi.Environment["AIDA_CAMOUFOX_LIVE_SMOKE_TIMEOUT_MS"] = "70000"
    $livePsi.Environment["AIDA_CAMOUFOX_TESTLAB_FAST_PROBE"] = "1"
    $livePsi.Environment["AIDA_CAMOUFOX_EXECUTABLE"] = $browser
    $livePsi.Environment["AIDA_CAMOUFOX_DEBUG_LOG"] = $smokeLog
    $livePsi.Environment["AIDA_CAMOUFOX_DEBUG_STDERR"] = "0"
    $livePsi.Environment["PYTHONIOENCODING"] = "utf-8"
    $liveProc = [System.Diagnostics.Process]::new()
    $liveProc.StartInfo = $livePsi
    if (-not $liveProc.Start()) {
        throw "Frozen MCP live smoke process failed to start."
    }
    if (-not $liveProc.WaitForExit(180000)) {
        try { $liveProc.Kill() } catch {}
        throw "Frozen MCP live smoke timed out after 180000 ms."
    }
    $liveStdout = $liveProc.StandardOutput.ReadToEnd()
    $liveStderr = $liveProc.StandardError.ReadToEnd()
    if ($liveProc.ExitCode -ne 0 -or $liveStdout -notmatch "AIDA_CAMOUFOX_LIVE_SMOKE_OK") {
        throw "Frozen MCP live smoke failed with exit $($liveProc.ExitCode). stdout=[$liveStdout] stderr=[$liveStderr]"
    }
    Write-Output "frozen_mcp_live_smoke=ok"
}

$repoRoot = Resolve-RepoRoot
if (-not $SourceRoot) {
    $SourceRoot = Join-Path $repoRoot "camoufox-reverse-mcp"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $repoRoot ".deps"
}

$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
if (-not [IO.File]::Exists((Join-Path $SourceRoot "pyproject.toml"))) {
    throw "camoufox-reverse-mcp pyproject.toml was not found at $SourceRoot"
}

$Python = Resolve-Python $Python
$version = (& $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if ($LASTEXITCODE -ne 0 -or -not ($version -match '^3\.(12|13)$')) {
    throw "Nuitka build requires Python 3.12 or 3.13; got $version from $Python"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
if ($Jobs -lt 1) {
    $Jobs = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount - 1))
}
$target = Join-Path $OutputDir "AiDA_CamoufoxReverseMcp.exe"
if ([IO.File]::Exists($target) -and -not $Force) {
    Invoke-FrozenMcpSmoke -Executable $target -RepoRoot $repoRoot
    Write-Output "frozen_mcp_exists=$target"
    exit 0
}

$stamp = Get-Date -Format "yyyyMMddHHmmss"
$workRoot = Join-Path $OutputDir ".camoufox-reverse-mcp-build-$stamp"
$venv = Join-Path $workRoot "venv"
$buildOut = Join-Path $workRoot "nuitka-out"
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

try {
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    $venvPython = Join-Path $venv "Scripts\python.exe"
    & $venvPython -m pip install --upgrade pip wheel setuptools nuitka zstandard ordered-set pyinstaller rich rich-click
    if ($LASTEXITCODE -ne 0) { throw "build dependency install failed" }
    & $venvPython -m pip install $SourceRoot
    if ($LASTEXITCODE -ne 0) { throw "camoufox-reverse-mcp dependency install failed" }
    Install-PatchedCamoufoxPackage -VenvPython $venvPython -RepoRoot $repoRoot
    $entry = Join-Path $workRoot "aida_camoufox_reverse_mcp_launcher.py"
    @'
import asyncio
import contextlib
import os
import sys
import time

from camoufox_reverse_mcp.__main__ import main


def _env_truthy(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _int_env(name, fallback):
    value = os.environ.get(name, "")
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _run_import_smoke():
    started = time.perf_counter()
    debug = None
    try:
        from camoufox_reverse_mcp.browser import _camoufox_debug
        debug = _camoufox_debug
        debug(
            "import_smoke_begin",
            cwd=os.getcwd(),
            python=sys.executable,
            env_browser=bool(os.environ.get("AIDA_CAMOUFOX_EXECUTABLE")),
        )
        import_started = time.perf_counter()
        from camoufox.utils import launch_options
        debug(
            "import_smoke_launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - import_started) * 1000),
        )
        executable = os.environ.get("AIDA_CAMOUFOX_EXECUTABLE", "")
        if executable:
            executable = os.path.abspath(os.path.expandvars(os.path.expanduser(executable)))
            if not os.path.isfile(executable):
                raise FileNotFoundError(f"Camoufox executable is not available: {executable}")
        kwargs = {
            "headless": True,
            "ff_version": _int_env("AIDA_CAMOUFOX_FF_VERSION", 135),
            "i_know_what_im_doing": True,
            "block_webrtc": True,
        }
        if executable:
            kwargs["executable_path"] = executable
        options_started = time.perf_counter()
        options = launch_options(**kwargs)
        debug(
            "import_smoke_launch_options_ok",
            elapsed_ms=int((time.perf_counter() - options_started) * 1000),
            total_ms=int((time.perf_counter() - started) * 1000),
            has_executable=bool(options.get("executable_path")),
            args=len(options.get("args") or []),
            env_keys=len(options.get("env") or {}),
        )
        print("AIDA_CAMOUFOX_IMPORT_SMOKE_OK", flush=True)
        return 0
    except Exception as exc:
        if debug is not None:
            debug(
                "import_smoke_failed",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                error_type=type(exc).__name__,
                error_summary=str(exc)[:1000],
            )
        print(f"AIDA_CAMOUFOX_IMPORT_SMOKE_FAIL {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 70


async def _run_live_smoke_async():
    started = time.perf_counter()
    from camoufox_reverse_mcp.browser import _await_no_cancel_wait, _camoufox_debug
    from camoufox_reverse_mcp.server import browser_manager
    executable = os.environ.get("AIDA_CAMOUFOX_EXECUTABLE", "")
    if executable:
        executable = os.path.abspath(os.path.expandvars(os.path.expanduser(executable)))
    if not executable or not os.path.isfile(executable):
        raise FileNotFoundError(f"Camoufox executable is not available: {executable}")
    timeout_ms = _int_env("AIDA_CAMOUFOX_LIVE_SMOKE_TIMEOUT_MS", 45000)
    config = {
        "headless": False,
        "executable_path": executable,
        "ff_version": _int_env("AIDA_CAMOUFOX_FF_VERSION", 135),
        "launch_timeout_ms": timeout_ms,
        "aida_testlab_fast_probe": True,
        "block_webrtc": True,
        "window_width": 960,
        "window_height": 700,
    }
    if _env_truthy("AIDA_CAMOUFOX_LIVE_SMOKE_TRACE"):
        config["enable_trace"] = True
    _camoufox_debug(
        "live_smoke_begin",
        executable=executable,
        timeout_ms=timeout_ms,
        trace=bool(config.get("enable_trace")),
    )
    try:
        launch = await browser_manager.launch(config)
        if launch.get("status") not in ("launched", "already_running"):
            raise RuntimeError(f"launch_status={launch.get('status')} payload={launch}")
        page = await browser_manager.get_active_page()
        proof = await _await_no_cancel_wait(
            page.evaluate("() => ({title: document.title, href: location.href, webdriver: String(navigator.webdriver)})"),
            timeout=10,
        )
        if not isinstance(proof, dict) or "href" not in proof:
            raise RuntimeError(f"invalid proof payload: {proof}")
        await browser_manager.close()
        _camoufox_debug(
            "live_smoke_ok",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            status=launch.get("status"),
            proof_keys=sorted(proof.keys()),
        )
        print("AIDA_CAMOUFOX_LIVE_SMOKE_OK", flush=True)
        return 0
    except Exception as exc:
        _camoufox_debug(
            "live_smoke_failed",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            error_type=type(exc).__name__,
            error_summary=str(exc)[:1000],
        )
        with contextlib.suppress(Exception):
            await browser_manager.close()
        raise


def _run_live_smoke():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_live_smoke_async())
    except Exception as exc:
        print(f"AIDA_CAMOUFOX_LIVE_SMOKE_FAIL {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 71
    finally:
        try:
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.sleep(0))
        except Exception:
            pass
        asyncio.set_event_loop(None)
        loop.close()


def _preload_camoufox():
    started = time.perf_counter()
    debug = None
    try:
        from camoufox_reverse_mcp.browser import _camoufox_debug
        debug = _camoufox_debug
        import_started = time.perf_counter()
        from camoufox.utils import launch_options as _aida_preloaded_launch_options
        debug(
            "preload_launch_options_import_ok",
            elapsed_ms=int((time.perf_counter() - import_started) * 1000),
            total_ms=int((time.perf_counter() - started) * 1000),
            loaded=bool(_aida_preloaded_launch_options),
        )
    except Exception as exc:
        if debug is not None:
            debug(
                "preload_launch_options_import_failed",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                error_type=type(exc).__name__,
                error_summary=str(exc)[:1000],
            )
        raise


if __name__ == "__main__":
    if _env_truthy("AIDA_CAMOUFOX_IMPORT_SMOKE"):
        raise SystemExit(_run_import_smoke())
    if _env_truthy("AIDA_CAMOUFOX_LIVE_SMOKE"):
        raise SystemExit(_run_live_smoke())
    _preload_camoufox()
    raise SystemExit(main())
'@ | Set-Content -LiteralPath $entry -Encoding UTF8
    $selectedBackend = $Backend.ToLowerInvariant()
    if ($selectedBackend -eq "auto") { $selectedBackend = "pyinstaller" }
    if ($selectedBackend -eq "pyinstaller") {
        $pyiWork = Join-Path $workRoot "pyinstaller-work"
        $pyiSpec = Join-Path $workRoot "pyinstaller-spec"
        & $venvPython -m PyInstaller `
            --noconfirm `
            --clean `
            --onefile `
            --console `
            --noupx `
            --name AiDA_CamoufoxReverseMcp `
            --distpath $OutputDir `
            --workpath $pyiWork `
            --specpath $pyiSpec `
            --collect-all camoufox_reverse_mcp `
            --collect-all camoufox `
            --collect-all browserforge `
            --collect-all apify_fingerprint_datapoints `
            --collect-all language_tags `
            --collect-all ua_parser `
            --collect-all ua_parser_builtins `
            --collect-submodules playwright `
            --collect-data playwright `
            --collect-all esprima `
            --hidden-import mcp.server.fastmcp `
            --hidden-import mcp.server.stdio `
            --hidden-import mcp.shared.session `
            --hidden-import mcp.shared.message `
            --hidden-import mcp.types `
            --hidden-import browserforge.fingerprints `
            --hidden-import browserforge.headers `
            --hidden-import apify_fingerprint_datapoints `
            --hidden-import language_tags `
            --hidden-import ua_parser `
            --hidden-import ua_parser_builtins `
            $entry
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
    } elseif ($selectedBackend -eq "nuitka") {
        & $venvPython -m nuitka `
            --standalone `
            --onefile `
            --assume-yes-for-downloads `
            --remove-output `
            --disable-cache=ccache `
            --jobs=$Jobs `
            --output-dir=$buildOut `
            --output-filename=AiDA_CamoufoxReverseMcp.exe `
            --include-package=camoufox_reverse_mcp `
            --include-package-data=camoufox_reverse_mcp `
            --include-package=mcp `
            --include-package=camoufox `
            --include-package=browserforge `
            --include-package-data=browserforge `
            --include-package=apify_fingerprint_datapoints `
            --include-package-data=apify_fingerprint_datapoints `
            --include-package=language_tags `
            --include-package-data=language_tags `
            --include-package=ua_parser `
            --include-package-data=ua_parser `
            --include-package=ua_parser_builtins `
            --include-package-data=ua_parser_builtins `
            --include-package=playwright `
            --include-package=esprima `
            $entry
        if ($LASTEXITCODE -ne 0) { throw "Nuitka build failed" }
        $built = Join-Path $buildOut "AiDA_CamoufoxReverseMcp.exe"
        if (-not [IO.File]::Exists($built)) { throw "Nuitka output executable was not produced" }
        Copy-Item -LiteralPath $built -Destination $target -Force
    } else {
        throw "Unsupported backend: $Backend"
    }
    if (-not [IO.File]::Exists($target)) { throw "Frozen executable was not produced" }
    Invoke-FrozenMcpSmoke -Executable $target -RepoRoot $repoRoot
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $target).Length
    Write-Output "frozen_mcp_backend=$selectedBackend"
    Write-Output "frozen_mcp_built=$target"
    Write-Output "frozen_mcp_size=$size"
    Write-Output "frozen_mcp_sha256=$hash"
} finally {
    if ([IO.Directory]::Exists($workRoot)) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
