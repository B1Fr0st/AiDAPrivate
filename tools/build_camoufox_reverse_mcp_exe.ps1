param(
    [string]$Python = "",
    [string]$SourceRoot = "",
    [string]$OutputDir = "",
    [ValidateSet("auto", "pyinstaller", "nuitka")]
    [string]$Backend = "auto",
    [int]$Jobs = 0,
    [switch]$Force,
    [switch]$ContractCheckOnly,
    [string]$ExistingExecutable = "",
    [string]$BrowserExecutable = ""
)

$ErrorActionPreference = "Stop"

$AidaFrozenMcpBuildDependencySchema = "20260621-reuse-venv-v1"
$AidaFrozenMcpBuildRequirements = @(
    "pip",
    "wheel",
    "setuptools",
    "pyinstaller",
    "rich",
    "rich-click",
    "tzdata"
)

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
    $repoRoot = Resolve-RepoRoot
    $candidateRoots = @(
        (Join-Path $repoRoot ".deps\camoufox-runtime\python.exe"),
        (Join-Path $repoRoot "build-ninja\deps\camoufox-runtime\python.exe"),
        "$env:LOCALAPPDATA\AiDA\runtimes\python\Python312-3.12.10-x64\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    foreach ($candidate in $candidateRoots) {
        if ($candidate -and [IO.File]::Exists($candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        try {
            $candidate = (& $py.Source -3.12 -c "import sys; print(sys.executable)" 2>$null)
            if ($LASTEXITCODE -eq 0 -and $candidate -and [IO.File]::Exists([string]$candidate)) {
                return [string]$candidate
            }
        } catch {
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
    $fingerprints = Join-Path $package "fingerprints.py"
    $packageNewest = Get-TreeNewestWriteTimeUtc -Root $package -Include @("*.py", "*.json", "*.dat")
    $packageKey = "$package|$(Get-FileSha256OrEmpty $fingerprints)|$($packageNewest.ToString('o'))"
    $packageKeyFile = Join-Path $sitePackages ".aida-patched-camoufox-key"
    if ([IO.Directory]::Exists($dest) -and [IO.File]::Exists($packageKeyFile)) {
        $existingKey = (Get-Content -LiteralPath $packageKeyFile -Raw).Trim()
        if ($existingKey -eq $packageKey) {
            Write-Output "patched_camoufox_package=$package"
            Write-Output "patched_camoufox_package_copy=skipped"
            return
        }
    }
    if ([IO.Directory]::Exists($dest)) {
        Remove-Item -LiteralPath $dest -Recurse -Force
    }
    Copy-Item -LiteralPath $package -Destination $dest -Recurse -Force
    Set-Content -LiteralPath $packageKeyFile -Value $packageKey -Encoding ASCII
    Write-Output "patched_camoufox_package=$package"
    Write-Output "patched_camoufox_package_copy=ok"
}

function Get-RequiredFrozenMcpTools {
    return @(
        "launch_browser",
        "close_browser",
        "list_pages",
        "new_page",
        "select_page",
        "close_page",
        "evaluate_js",
        "navigate",
        "diagnose_navigation",
        "diagnose_bloxflip_matrix",
        "reload",
        "wait_for",
        "click",
        "type_text",
        "take_screenshot",
        "take_snapshot",
        "get_page_info",
        "cookies",
        "get_storage",
        "export_state",
        "import_state",
        "reset_browser_state",
        "network_capture",
        "list_network_requests",
        "get_network_request",
        "get_request_initiator",
        "intercept_request",
        "hook_function",
        "add_init_script",
        "inject_hook_preset",
        "remove_hooks",
        "instrumentation",
        "hook_jsvmp_interpreter",
        "trace_property_access",
        "list_trace_files",
        "query_trace_file",
        "get_console_logs",
        "scripts",
        "search_code",
        "compare_env",
        "check_environment",
        "verify_signer_offline",
        "analyze_cookie_sources"
    )
}

function ConvertTo-CompactLogText {
    param(
        [string]$Text,
        [int]$Limit = 1600
    )
    if (-not $Text) {
        return ""
    }
    $value = $Text.Trim() -replace "[`r`n`t]+", " "
    if ($value.Length -le $Limit) {
        return $value
    }
    return "..." + $value.Substring($value.Length - $Limit)
}

function Stop-ProcessTreeAndWait {
    param(
        [System.Diagnostics.Process]$Process,
        [int]$TimeoutMs = 15000
    )
    if ($null -eq $Process) {
        return
    }
    try {
        if (-not $Process.HasExited) {
            $processIdToKill = $Process.Id
            try {
                & taskkill.exe /PID $processIdToKill /T /F *> $null
            } catch {
            }
            try {
                [void]$Process.WaitForExit($TimeoutMs)
            } catch {
            }
            if (-not $Process.HasExited) {
                try {
                    $Process.Kill($true)
                } catch {
                    try { $Process.Kill() } catch {}
                }
                try {
                    [void]$Process.WaitForExit($TimeoutMs)
                } catch {
                }
            }
        }
    } finally {
        try { $Process.Dispose() } catch {}
    }
}

function Remove-FileWithRetry {
    param(
        [string]$Path,
        [int]$Attempts = 20,
        [int]$DelayMs = 500
    )
    $lastError = $null
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            return
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    if ($lastError) {
        throw $lastError
    }
}

function Remove-DirectoryInsideWithRetry {
    param(
        [string]$Path,
        [string]$AllowedRoot,
        [int]$Attempts = 20,
        [int]$DelayMs = 500
    )
    if (-not $Path -or -not [IO.Directory]::Exists($Path)) {
        return
    }
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $fullRoot = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if (-not $fullPath.StartsWith($fullRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove directory outside allowed root. path=$fullPath root=$fullRoot"
    }
    $lastError = $null
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
            return
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    if ($lastError) {
        throw $lastError
    }
}

function Get-FileSha256OrEmpty {
    param([string]$Path)
    if (-not $Path -or -not [IO.File]::Exists($Path)) {
        return ""
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-FrozenMcpDependencyKey {
    param(
        [string]$PythonExe,
        [string]$SourceRoot,
        [string]$RepoRoot
    )
    $pythonVersion = (& $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}|{sys.executable}')" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $pythonVersion) {
        throw "Failed to query Python dependency key from $PythonExe"
    }
    $dependencyInputs = @(
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "uv.lock",
        "pdm.lock"
    )
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("schema=$AidaFrozenMcpBuildDependencySchema")
    $lines.Add("python=$pythonVersion")
    $lines.Add("source=$SourceRoot")
    $lines.Add("requirements=$($AidaFrozenMcpBuildRequirements -join ',')")
    foreach ($relative in $dependencyInputs) {
        $path = Join-Path $SourceRoot $relative
        $lines.Add("$relative=$(Get-FileSha256OrEmpty $path)")
    }
    $patchedCamoufox = Resolve-PatchedCamoufoxPackage $RepoRoot
    $fingerprints = Join-Path $patchedCamoufox "fingerprints.py"
    $lines.Add("patched_camoufox=$patchedCamoufox")
    $lines.Add("patched_camoufox_fingerprints=$(Get-FileSha256OrEmpty $fingerprints)")
    $text = ($lines -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace "-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Install-EditableReverseMcpSource {
    param(
        [string]$VenvPython,
        [string]$SourceRoot,
        [string]$VenvDir
    )
    $marker = Join-Path $VenvDir ".aida-source-root.txt"
    $current = ""
    if ([IO.File]::Exists($marker)) {
        $current = (Get-Content -LiteralPath $marker -Raw).Trim()
    }
    $expectedPackageRoot = [IO.Path]::GetFullPath((Join-Path $SourceRoot "src\camoufox_reverse_mcp")).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $installedPackageFile = (& $VenvPython -c "import pathlib, camoufox_reverse_mcp; print(pathlib.Path(camoufox_reverse_mcp.__file__).resolve())" 2>$null)
    $installedOk = $false
    if ($LASTEXITCODE -eq 0 -and $installedPackageFile) {
        $installedPath = [IO.Path]::GetFullPath([string]$installedPackageFile)
        $installedOk = $installedPath.StartsWith($expectedPackageRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    }
    if ($current -eq $SourceRoot -and $installedOk) {
        Write-Output "source_mcp_editable_install_skipped=1"
        return
    }
    & $VenvPython -m pip install --disable-pip-version-check --no-deps -e $SourceRoot
    if ($LASTEXITCODE -ne 0) { throw "camoufox-reverse-mcp editable source install failed" }
    Set-Content -LiteralPath $marker -Value $SourceRoot -Encoding ASCII
    Write-Output "source_mcp_editable_install=ok"
}

function Ensure-FrozenMcpBuildVenv {
    param(
        [string]$PythonExe,
        [string]$SourceRoot,
        [string]$OutputDir,
        [string]$RepoRoot,
        [switch]$Force
    )
    $script:AidaFrozenMcpVenvPython = ""
    $venv = Join-Path $OutputDir ".camoufox-reverse-mcp-build-venv"
    $venvPython = Join-Path $venv "Scripts\python.exe"
    $key = Get-FrozenMcpDependencyKey -PythonExe $PythonExe -SourceRoot $SourceRoot -RepoRoot $RepoRoot
    $keyFile = Join-Path $venv ".aida-dependency-key"
    $existingKey = ""
    if ([IO.File]::Exists($keyFile)) {
        $existingKey = (Get-Content -LiteralPath $keyFile -Raw).Trim()
    }
    $needsInstall = $Force -or -not [IO.File]::Exists($venvPython) -or $existingKey -ne $key
    Write-Output "build_venv=$venv"
    Write-Output "build_venv_dependency_key=$key"
    if ($needsInstall) {
        Write-Output "build_dependency_install=required"
        Remove-DirectoryInsideWithRetry -Path $venv -AllowedRoot $OutputDir
        & $PythonExe -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
        $venvPython = Join-Path $venv "Scripts\python.exe"
        & $venvPython -m pip install --disable-pip-version-check --upgrade $AidaFrozenMcpBuildRequirements
        if ($LASTEXITCODE -ne 0) { throw "build dependency install failed" }
        & $venvPython -m pip install --disable-pip-version-check -e $SourceRoot
        if ($LASTEXITCODE -ne 0) { throw "camoufox-reverse-mcp dependency install failed" }
        Set-Content -LiteralPath $keyFile -Value $key -Encoding ASCII
        Set-Content -LiteralPath (Join-Path $venv ".aida-source-root.txt") -Value $SourceRoot -Encoding ASCII
        Write-Output "build_dependency_install=ok"
    } else {
        Write-Output "build_dependency_install=skipped"
        Install-EditableReverseMcpSource -VenvPython $venvPython -SourceRoot $SourceRoot -VenvDir $venv
    }
    Install-PatchedCamoufoxPackage -VenvPython $venvPython -RepoRoot $RepoRoot
    $script:AidaFrozenMcpVenvPython = $venvPython
}

function Get-TreeNewestWriteTimeUtc {
    param(
        [string]$Root,
        [string[]]$Include = @("*")
    )
    $newest = [DateTime]::MinValue
    if (-not $Root -or -not [IO.Directory]::Exists($Root)) {
        return $newest
    }
    foreach ($pattern in $Include) {
        Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $pattern -ErrorAction Stop | ForEach-Object {
            if ($_.LastWriteTimeUtc -gt $newest) {
                $newest = $_.LastWriteTimeUtc
            }
        }
    }
    return $newest
}

function Get-FrozenMcpInputNewestWriteTimeUtc {
    param(
        [string]$SourceRoot,
        [string]$BuildScript
    )
    $newest = [DateTime]::MinValue
    foreach ($path in @((Join-Path $SourceRoot "pyproject.toml"), $BuildScript)) {
        if ($path -and [IO.File]::Exists($path)) {
            $item = Get-Item -LiteralPath $path
            if ($item.LastWriteTimeUtc -gt $newest) {
                $newest = $item.LastWriteTimeUtc
            }
        }
    }
    foreach ($path in @((Join-Path $SourceRoot "src"), (Join-Path (Resolve-RepoRoot) "cmake"))) {
        $treeNewest = Get-TreeNewestWriteTimeUtc -Root $path -Include @("*.py", "*.js", "*.json", "*.toml", "*.cmake")
        if ($treeNewest -gt $newest) {
            $newest = $treeNewest
        }
    }
    return $newest
}

function Test-FrozenMcpTargetFresh {
    param(
        [string]$Target,
        [DateTime]$InputNewestUtc
    )
    if (-not [IO.File]::Exists($Target)) {
        Write-Host "frozen_mcp_fresh=0"
        Write-Host "frozen_mcp_fresh_reason=missing"
        return $false
    }
    $targetItem = Get-Item -LiteralPath $Target
    $targetUtc = $targetItem.LastWriteTimeUtc
    Write-Host "frozen_mcp_target_mtime_utc=$($targetUtc.ToString('o'))"
    Write-Host "frozen_mcp_input_newest_utc=$($InputNewestUtc.ToString('o'))"
    if ($InputNewestUtc -gt $targetUtc.AddSeconds(1)) {
        Write-Host "frozen_mcp_fresh=0"
        Write-Host "frozen_mcp_fresh_reason=stale"
        return $false
    }
    Write-Host "frozen_mcp_fresh=1"
    return $true
}

function Add-McpJsonMessage {
    param(
        [System.Collections.ArrayList]$Messages,
        [string]$JsonText
    )
    if (-not $JsonText) {
        return
    }
    $trimmed = $JsonText.Trim()
    if (-not $trimmed.StartsWith("{")) {
        return
    }
    try {
        [void]$Messages.Add(($trimmed | ConvertFrom-Json -ErrorAction Stop))
    } catch {
    }
}

function ConvertFrom-McpOutput {
    param([string]$Text)
    $messages = [System.Collections.ArrayList]::new()
    if (-not $Text) {
        return ,$messages
    }
    $offset = 0
    while ($offset -lt $Text.Length) {
        $header = $Text.IndexOf("Content-Length:", $offset, [System.StringComparison]::OrdinalIgnoreCase)
        if ($header -lt 0) {
            break
        }
        $separator = $Text.IndexOf("`r`n`r`n", $header, [System.StringComparison]::Ordinal)
        $separatorLength = 4
        if ($separator -lt 0) {
            $separator = $Text.IndexOf("`n`n", $header, [System.StringComparison]::Ordinal)
            $separatorLength = 2
        }
        if ($separator -lt 0) {
            break
        }
        $headerText = $Text.Substring($header, $separator - $header)
        if ($headerText -match "Content-Length:\s*(\d+)") {
            $length = [int]$matches[1]
            $bodyStart = $separator + $separatorLength
            if ($length -gt 0 -and $bodyStart + $length -le $Text.Length) {
                Add-McpJsonMessage -Messages $messages -JsonText $Text.Substring($bodyStart, $length)
                $offset = $bodyStart + $length
                continue
            }
        }
        $offset = $separator + $separatorLength
    }
    foreach ($line in [System.Text.RegularExpressions.Regex]::Split($Text, "`r`n|`n|`r")) {
        Add-McpJsonMessage -Messages $messages -JsonText $line
    }
    return ,$messages
}

function Test-McpErrorProperty {
    param($Message)
    $prop = $Message.PSObject.Properties["error"]
    return $null -ne $prop -and $null -ne $prop.Value
}

function Invoke-FrozenMcpContractCheck {
    param(
        [string]$Executable
    )
    if (-not [IO.File]::Exists($Executable)) {
        throw "Frozen MCP contract executable was not found: $Executable"
    }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.Arguments = "--aida-contract-check"
    $psi.WorkingDirectory = Split-Path -Parent $Executable
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment["PYTHONIOENCODING"] = "utf-8"
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $timeoutMs = 30000
    Write-Output "frozen_mcp_contract_check_command=$Executable --aida-contract-check"
    Write-Output "frozen_mcp_contract_check_timeout_ms=$timeoutMs"
    if (-not $proc.Start()) {
        throw "Frozen MCP contract check process failed to start."
    }
    Write-Output "frozen_mcp_contract_check_child_pid=$($proc.Id)"
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($timeoutMs)) {
        Stop-ProcessTreeAndWait -Process $proc -TimeoutMs 5000
        $timeoutStdout = $stdoutTask.GetAwaiter().GetResult()
        $timeoutStderr = $stderrTask.GetAwaiter().GetResult()
        Write-Output "frozen_mcp_contract_check_timeout=1"
        Write-Output "frozen_mcp_contract_check_stdout_tail=$(ConvertTo-CompactLogText $timeoutStdout)"
        Write-Output "frozen_mcp_contract_check_stderr_tail=$(ConvertTo-CompactLogText $timeoutStderr)"
        throw "Frozen MCP contract check timed out after $timeoutMs ms. stdout=[$(ConvertTo-CompactLogText $timeoutStdout)] stderr=[$(ConvertTo-CompactLogText $timeoutStderr)]"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Write-Output "frozen_mcp_contract_check_exit_code=$($proc.ExitCode)"
    Write-Output "frozen_mcp_contract_check_stdout_tail=$(ConvertTo-CompactLogText $stdout)"
    Write-Output "frozen_mcp_contract_check_stderr_tail=$(ConvertTo-CompactLogText $stderr)"
    $hasContract = $stdout -match "aida_initiator_contract_v2_page_marker"
    $hasRequestId = $stdout -match "request_id"
    $hasPageId = $stdout -match "page_id"
    $hasMarker = $stdout -match '"marker"' -or $stdout -match ",marker" -or $stdout -match "marker," -or $stdout -match "marker]"
    $launchBudgetOk = $stdout -match '"launch_budget_contract_ok":true'
    $pageCreateFloorOk = $stdout -match '"page_create_floor_present":true'
    $pageCreateCeilingOk = $stdout -match '"page_create_ceiling_present":true'
    $pageCreateRatioOk = $stdout -match '"page_create_ratio_present":true'
    $latePageWaitOk = $stdout -match '"late_page_wait_floor_present":true'
    $waitForLatePageSelfPagesOk = $stdout -match '"wait_for_late_page_self_pages_present":true'
    $primaryWaitUntilDowngradeAbsent = $stdout -match '"primary_wait_until_downgrade_absent":true'
    $addonPolicyOk = $stdout -match '"addon_policy_contract_ok":true'
    $addonContractMarkerOk = $stdout -match "aida_default_addon_policy_v1"
    $addonPolicyMarkerOk = $stdout -match '"addon_policy_marker_present":true'
    $addonExcludeOk = $stdout -match '"default_ubo_exclusion_present":true'
    $addonExcludeMarkerOk = $stdout -match '"exclude_addons_marker_present":true'
    $addonInvalidDiagOk = $stdout -match '"addon_invalid_diagnostic_present":true'
    $addonAllLaunchScopeOk = $stdout -match '"addon_all_launch_scope_present":true'
    $fastVisibleContractMarkerOk = $stdout -match "aida_fast_visible_policy_v1"
    $fastVisiblePolicyOk = $stdout -match '"fast_visible_policy_contract_ok":true'
    $fastVisibleMarkerOk = $stdout -match '"fast_visible_policy_marker_present":true'
    $fastVisibleDisabledOk = $stdout -match '"fast_visible_disabled_return_present":true'
    $fastVisibleIgnoredOk = $stdout -match '"fast_visible_fallback_ignored_present":true'
    $fastVisibleForbiddenReturnAbsentOk = $stdout -match '"fast_visible_forbidden_return_absent":true'
    $fastVisibleCompatAbsentOk = $stdout -match '"fast_visible_compat_path_absent":true'
    $fastVisibleAsyncOk = $stdout -match '"fast_visible_selected_async_present":true'
    if ($proc.ExitCode -ne 0 -or -not ($hasContract -and $hasRequestId -and $hasPageId -and $hasMarker -and $launchBudgetOk -and $pageCreateFloorOk -and $pageCreateCeilingOk -and $pageCreateRatioOk -and $latePageWaitOk -and $waitForLatePageSelfPagesOk -and $primaryWaitUntilDowngradeAbsent -and $addonPolicyOk -and $addonContractMarkerOk -and $addonPolicyMarkerOk -and $addonExcludeOk -and $addonExcludeMarkerOk -and $addonInvalidDiagOk -and $addonAllLaunchScopeOk -and $fastVisibleContractMarkerOk -and $fastVisiblePolicyOk -and $fastVisibleMarkerOk -and $fastVisibleDisabledOk -and $fastVisibleIgnoredOk -and $fastVisibleForbiddenReturnAbsentOk -and $fastVisibleCompatAbsentOk -and $fastVisibleAsyncOk)) {
        throw "Frozen MCP contract check failed exit=$($proc.ExitCode) contract=$([int]$hasContract) request_id=$([int]$hasRequestId) page_id=$([int]$hasPageId) marker=$([int]$hasMarker) launch_budget=$([int]$launchBudgetOk) page_create_floor=$([int]$pageCreateFloorOk) page_create_ceiling=$([int]$pageCreateCeilingOk) page_create_ratio=$([int]$pageCreateRatioOk) late_page_wait=$([int]$latePageWaitOk) wait_for_late_page_self_pages=$([int]$waitForLatePageSelfPagesOk) wait_until_downgrade_absent=$([int]$primaryWaitUntilDowngradeAbsent) addon_policy=$([int]$addonPolicyOk) addon_contract_marker=$([int]$addonContractMarkerOk) addon_marker=$([int]$addonPolicyMarkerOk) addon_exclude_ubo=$([int]$addonExcludeOk) addon_exclude_marker=$([int]$addonExcludeMarkerOk) addon_invalid_diag=$([int]$addonInvalidDiagOk) addon_all_launch_scope=$([int]$addonAllLaunchScopeOk) fast_visible_contract_marker=$([int]$fastVisibleContractMarkerOk) fast_visible_policy=$([int]$fastVisiblePolicyOk) fast_visible_marker=$([int]$fastVisibleMarkerOk) fast_visible_disabled=$([int]$fastVisibleDisabledOk) fast_visible_ignored=$([int]$fastVisibleIgnoredOk) fast_visible_forbidden_return_absent=$([int]$fastVisibleForbiddenReturnAbsentOk) fast_visible_compat_absent=$([int]$fastVisibleCompatAbsentOk) fast_visible_async=$([int]$fastVisibleAsyncOk) stdout=[$(ConvertTo-CompactLogText $stdout)] stderr=[$(ConvertTo-CompactLogText $stderr)]"
    }
    Write-Output "frozen_mcp_contract_check=ok"
}

function Test-FrozenMcpOneDirRuntime {
    param([string]$Executable)
    if (-not $Executable) { return $false }
    $dir = Split-Path -Parent $Executable
    if (-not $dir) { return $false }
    $internal = Join-Path $dir "_internal"
    return [IO.Directory]::Exists($internal)
}

function Assert-FrozenMcpCustomerSafeExecutable {
    param([string]$Executable)
    if (Test-FrozenMcpOneDirRuntime $Executable) {
        throw "Frozen MCP executable is a PyInstaller onedir bootloader with sibling _internal runtime. Build a self-contained onefile executable before customer deployment."
    }
}

function Assert-SourceAddonPolicyContract {
    param([string]$SourceRoot)
    $browserPath = Join-Path $SourceRoot "src\camoufox_reverse_mcp\browser.py"
    if (-not [IO.File]::Exists($browserPath)) {
        throw "Camoufox reverse MCP browser.py was not found for addon policy validation: $browserPath"
    }
    $text = Get-Content -Raw -LiteralPath $browserPath
    $required = @(
        "aida_default_addon_policy_v1",
        "DefaultAddons.UBO",
        "exclude_addons",
        "launch_options_addon_policy",
        "launch_options_addon_invalid",
        "default_exclusion_scope",
        "all_launches",
        "default_addons_excluded",
        "explicit_addon_count",
        "explicit_addons_validated",
        "aida_fast_visible_policy_v1",
        "aida_fast_visible_fallback_ignored",
        'selected_launch_path = "async_camoufox"'
    )
    $missing = @()
    foreach ($marker in $required) {
        if (-not $text.Contains($marker)) {
            $missing += $marker
        }
    }
    if ($missing.Count -gt 0) {
        throw "Camoufox reverse MCP source addon policy contract missing markers: $($missing -join ',') in $browserPath"
    }
    if ($text.Contains("if explicit_addon_count == 0:")) {
        throw "Camoufox reverse MCP source addon policy contract has stale no-explicit-addon UBO exclusion gate in $browserPath"
    }
    $forbidden = @(
        "fast_visible_firefox_compat",
        "launch_fast_visible_compat_selected",
        "return _flag_enabled(requested)",
        'return bool(cfg.get("aida_fast_visible_launch", True))'
    )
    foreach ($marker in $forbidden) {
        if ($text.Contains($marker)) {
            throw "Camoufox reverse MCP source launch policy contract has forbidden stale marker: $marker in $browserPath"
        }
    }
    Write-Output "source_addon_policy_contract=ok"
    Write-Output "source_addon_policy_contract_browser=$browserPath"
}

function Invoke-SourceMcpContractCheck {
    param(
        [string]$PythonExe
    )
    if (-not [IO.File]::Exists($PythonExe)) {
        throw "Source MCP contract Python executable was not found: $PythonExe"
    }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $PythonExe
    $psi.Arguments = "-B -m camoufox_reverse_mcp --aida-contract-check"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment["PYTHONIOENCODING"] = "utf-8"
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $timeoutMs = 7000
    Write-Output "source_mcp_contract_check_command=$PythonExe -B -m camoufox_reverse_mcp --aida-contract-check"
    Write-Output "source_mcp_contract_check_timeout_ms=$timeoutMs"
    if (-not $proc.Start()) {
        throw "Source MCP contract check process failed to start."
    }
    Write-Output "source_mcp_contract_check_child_pid=$($proc.Id)"
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($timeoutMs)) {
        Stop-ProcessTreeAndWait -Process $proc -TimeoutMs 5000
        $timeoutStdout = $stdoutTask.GetAwaiter().GetResult()
        $timeoutStderr = $stderrTask.GetAwaiter().GetResult()
        Write-Output "source_mcp_contract_check_timeout=1"
        Write-Output "source_mcp_contract_check_stdout_tail=$(ConvertTo-CompactLogText $timeoutStdout)"
        Write-Output "source_mcp_contract_check_stderr_tail=$(ConvertTo-CompactLogText $timeoutStderr)"
        throw "Source MCP contract check timed out after $timeoutMs ms. stdout=[$(ConvertTo-CompactLogText $timeoutStdout)] stderr=[$(ConvertTo-CompactLogText $timeoutStderr)]"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Write-Output "source_mcp_contract_check_exit_code=$($proc.ExitCode)"
    Write-Output "source_mcp_contract_check_stdout_tail=$(ConvertTo-CompactLogText $stdout)"
    Write-Output "source_mcp_contract_check_stderr_tail=$(ConvertTo-CompactLogText $stderr)"
    $hasContract = $stdout -match "aida_initiator_contract_v2_page_marker"
    $hasRequestId = $stdout -match "request_id"
    $hasPageId = $stdout -match "page_id"
    $hasMarker = $stdout -match '"marker"' -or $stdout -match ",marker" -or $stdout -match "marker," -or $stdout -match "marker]"
    $launchBudgetOk = $stdout -match '"launch_budget_contract_ok":true'
    $pageCreateFloorOk = $stdout -match '"page_create_floor_present":true'
    $pageCreateCeilingOk = $stdout -match '"page_create_ceiling_present":true'
    $pageCreateRatioOk = $stdout -match '"page_create_ratio_present":true'
    $latePageWaitOk = $stdout -match '"late_page_wait_floor_present":true'
    $waitForLatePageSelfPagesOk = $stdout -match '"wait_for_late_page_self_pages_present":true'
    $primaryWaitUntilDowngradeAbsent = $stdout -match '"primary_wait_until_downgrade_absent":true'
    $addonPolicyOk = $stdout -match '"addon_policy_contract_ok":true'
    $addonContractMarkerOk = $stdout -match "aida_default_addon_policy_v1"
    $addonPolicyMarkerOk = $stdout -match '"addon_policy_marker_present":true'
    $addonExcludeOk = $stdout -match '"default_ubo_exclusion_present":true'
    $addonExcludeMarkerOk = $stdout -match '"exclude_addons_marker_present":true'
    $addonInvalidDiagOk = $stdout -match '"addon_invalid_diagnostic_present":true'
    $addonAllLaunchScopeOk = $stdout -match '"addon_all_launch_scope_present":true'
    $fastVisibleContractMarkerOk = $stdout -match "aida_fast_visible_policy_v1"
    $fastVisiblePolicyOk = $stdout -match '"fast_visible_policy_contract_ok":true'
    $fastVisibleMarkerOk = $stdout -match '"fast_visible_policy_marker_present":true'
    $fastVisibleDisabledOk = $stdout -match '"fast_visible_disabled_return_present":true'
    $fastVisibleIgnoredOk = $stdout -match '"fast_visible_fallback_ignored_present":true'
    $fastVisibleForbiddenReturnAbsentOk = $stdout -match '"fast_visible_forbidden_return_absent":true'
    $fastVisibleCompatAbsentOk = $stdout -match '"fast_visible_compat_path_absent":true'
    $fastVisibleAsyncOk = $stdout -match '"fast_visible_selected_async_present":true'
    if ($proc.ExitCode -ne 0 -or -not ($hasContract -and $hasRequestId -and $hasPageId -and $hasMarker -and $launchBudgetOk -and $pageCreateFloorOk -and $pageCreateCeilingOk -and $pageCreateRatioOk -and $latePageWaitOk -and $waitForLatePageSelfPagesOk -and $primaryWaitUntilDowngradeAbsent -and $addonPolicyOk -and $addonContractMarkerOk -and $addonPolicyMarkerOk -and $addonExcludeOk -and $addonExcludeMarkerOk -and $addonInvalidDiagOk -and $addonAllLaunchScopeOk -and $fastVisibleContractMarkerOk -and $fastVisiblePolicyOk -and $fastVisibleMarkerOk -and $fastVisibleDisabledOk -and $fastVisibleIgnoredOk -and $fastVisibleForbiddenReturnAbsentOk -and $fastVisibleCompatAbsentOk -and $fastVisibleAsyncOk)) {
        throw "Source MCP contract check failed exit=$($proc.ExitCode) contract=$([int]$hasContract) request_id=$([int]$hasRequestId) page_id=$([int]$hasPageId) marker=$([int]$hasMarker) launch_budget=$([int]$launchBudgetOk) page_create_floor=$([int]$pageCreateFloorOk) page_create_ceiling=$([int]$pageCreateCeilingOk) page_create_ratio=$([int]$pageCreateRatioOk) late_page_wait=$([int]$latePageWaitOk) wait_for_late_page_self_pages=$([int]$waitForLatePageSelfPagesOk) wait_until_downgrade_absent=$([int]$primaryWaitUntilDowngradeAbsent) addon_policy=$([int]$addonPolicyOk) addon_contract_marker=$([int]$addonContractMarkerOk) addon_marker=$([int]$addonPolicyMarkerOk) addon_exclude_ubo=$([int]$addonExcludeOk) addon_exclude_marker=$([int]$addonExcludeMarkerOk) addon_invalid_diag=$([int]$addonInvalidDiagOk) addon_all_launch_scope=$([int]$addonAllLaunchScopeOk) fast_visible_contract_marker=$([int]$fastVisibleContractMarkerOk) fast_visible_policy=$([int]$fastVisiblePolicyOk) fast_visible_marker=$([int]$fastVisibleMarkerOk) fast_visible_disabled=$([int]$fastVisibleDisabledOk) fast_visible_ignored=$([int]$fastVisibleIgnoredOk) fast_visible_forbidden_return_absent=$([int]$fastVisibleForbiddenReturnAbsentOk) fast_visible_compat_absent=$([int]$fastVisibleCompatAbsentOk) fast_visible_async=$([int]$fastVisibleAsyncOk) stdout=[$(ConvertTo-CompactLogText $stdout)] stderr=[$(ConvertTo-CompactLogText $stderr)]"
    }
    Write-Output "source_mcp_contract_check=ok"
}

function Write-McpStdioFrame {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$JsonText
    )
    $Writer.WriteLine($JsonText)
    $Writer.Flush()
}

function Invoke-FrozenMcpToolContract {
    param(
        [string]$Executable,
        [string]$RepoRoot,
        [string]$BrowserExecutable = ""
    )
    $browser = ""
    if ($BrowserExecutable) {
        if (-not [IO.File]::Exists($BrowserExecutable)) {
            throw "Camoufox browser executable for frozen MCP stdio smoke was not found: $BrowserExecutable"
        }
        $browser = (Resolve-Path -LiteralPath $BrowserExecutable).Path
    } else {
        $browser = Resolve-CamoufoxBrowser $RepoRoot
    }
    if (-not $browser) {
        throw "Camoufox browser executable for frozen MCP stdio smoke was not found."
    }
    $smokeLog = Join-Path $env:TEMP "aida_camoufox_frozen_mcp_stdio_smoke.log"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.WorkingDirectory = $RepoRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment["AIDA_CAMOUFOX_EXECUTABLE"] = $browser
    $psi.Environment["AIDA_CAMOUFOX_DEBUG_LOG"] = $smokeLog
    $psi.Environment["AIDA_CAMOUFOX_DEBUG_STDERR"] = "0"
    $psi.Environment["PYTHONIOENCODING"] = "utf-8"
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $stdioTimeoutMs = 45000
    Write-Output "frozen_mcp_stdio_smoke_command=$Executable"
    Write-Output "frozen_mcp_stdio_smoke_cwd=$RepoRoot"
    Write-Output "frozen_mcp_stdio_smoke_timeout_ms=$stdioTimeoutMs"
    if (-not $proc.Start()) {
        throw "Frozen MCP stdio smoke process failed to start."
    }
    Write-Output "frozen_mcp_stdio_smoke_child_pid=$($proc.Id)"
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $init = @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2025-06-18"
            capabilities = @{}
            clientInfo = @{
                name = "aida-frozen-camoufox-smoke"
                version = "1.0.0"
            }
        }
    } | ConvertTo-Json -Compress -Depth 12
    $initialized = @{
        jsonrpc = "2.0"
        method = "notifications/initialized"
        params = @{}
    } | ConvertTo-Json -Compress -Depth 12
    $toolsList = @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/list"
    } | ConvertTo-Json -Compress -Depth 12
    Write-McpStdioFrame -Writer $proc.StandardInput -JsonText $init
    Write-McpStdioFrame -Writer $proc.StandardInput -JsonText $initialized
    Write-McpStdioFrame -Writer $proc.StandardInput -JsonText $toolsList
    $proc.StandardInput.Close()
    if (-not $proc.WaitForExit($stdioTimeoutMs)) {
        Stop-ProcessTreeAndWait -Process $proc -TimeoutMs 15000
        $stdoutTimeout = $stdoutTask.GetAwaiter().GetResult()
        $stderrTimeout = $stderrTask.GetAwaiter().GetResult()
        Write-Output "frozen_mcp_stdio_smoke_timeout=1"
        Write-Output "frozen_mcp_stdio_smoke_stdout_tail=$(ConvertTo-CompactLogText $stdoutTimeout)"
        Write-Output "frozen_mcp_stdio_smoke_stderr_tail=$(ConvertTo-CompactLogText $stderrTimeout)"
        throw "Frozen MCP stdio smoke timed out after $stdioTimeoutMs ms. stdout=[$(ConvertTo-CompactLogText $stdoutTimeout)] stderr=[$(ConvertTo-CompactLogText $stderrTimeout)]"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Write-Output "frozen_mcp_stdio_smoke_exit_code=$($proc.ExitCode)"
    Write-Output "frozen_mcp_stdio_smoke_stdout_tail=$(ConvertTo-CompactLogText $stdout)"
    Write-Output "frozen_mcp_stdio_smoke_stderr_tail=$(ConvertTo-CompactLogText $stderr)"
    if ($proc.ExitCode -ne 0) {
        throw "Frozen MCP stdio smoke exited with $($proc.ExitCode). stdout=[$(ConvertTo-CompactLogText $stdout)] stderr=[$(ConvertTo-CompactLogText $stderr)]"
    }
    $messages = ConvertFrom-McpOutput $stdout
    $initSeen = $false
    $toolsSeen = $false
    $toolNames = @()
    foreach ($message in $messages) {
        $idProp = $message.PSObject.Properties["id"]
        if ($null -eq $idProp) {
            continue
        }
        $id = [string]$idProp.Value
        if ($id -eq "1") {
            if (Test-McpErrorProperty $message) {
                throw "Frozen MCP initialize returned error: $($message.error | ConvertTo-Json -Compress -Depth 8)"
            }
            $resultProp = $message.PSObject.Properties["result"]
            if ($null -eq $resultProp -or $null -eq $resultProp.Value) {
                throw "Frozen MCP initialize response was missing result."
            }
            $initSeen = $true
        } elseif ($id -eq "2") {
            if (Test-McpErrorProperty $message) {
                throw "Frozen MCP tools/list returned error: $($message.error | ConvertTo-Json -Compress -Depth 8)"
            }
            $resultProp = $message.PSObject.Properties["result"]
            if ($null -eq $resultProp -or $null -eq $resultProp.Value) {
                throw "Frozen MCP tools/list response was missing result."
            }
            $toolsProp = $resultProp.Value.PSObject.Properties["tools"]
            if ($null -eq $toolsProp -or $null -eq $toolsProp.Value) {
                throw "Frozen MCP tools/list response was missing tools."
            }
            foreach ($tool in @($toolsProp.Value)) {
                $nameProp = $tool.PSObject.Properties["name"]
                if ($null -ne $nameProp -and $nameProp.Value) {
                    $toolNames += [string]$nameProp.Value
                }
            }
            $toolsSeen = $true
        }
    }
    if (-not $initSeen) {
        throw "Frozen MCP stdio smoke did not receive initialize response. stdout=[$(ConvertTo-CompactLogText $stdout)] stderr=[$(ConvertTo-CompactLogText $stderr)]"
    }
    if (-not $toolsSeen) {
        throw "Frozen MCP stdio smoke did not receive tools/list response. stdout=[$(ConvertTo-CompactLogText $stdout)] stderr=[$(ConvertTo-CompactLogText $stderr)]"
    }
    $toolSet = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::Ordinal)
    foreach ($name in $toolNames) {
        [void]$toolSet.Add($name)
    }
    $missing = @()
    foreach ($required in Get-RequiredFrozenMcpTools) {
        if (-not $toolSet.Contains($required)) {
            $missing += $required
        }
    }
    $inventory = @()
    foreach ($name in $toolSet) {
        $inventory += $name
    }
    $inventory = $inventory | Sort-Object
    Write-Output "frozen_mcp_stdio_tools_list_result=count:$($inventory.Count);missing:$($missing -join ',');tools:$($inventory -join ',')"
    if ($missing.Count -gt 0) {
        throw "Frozen MCP stdio tool contract missing required tools: missing=$($missing -join ',') inventory=$($inventory -join ',')"
    }
    Write-Output "frozen_mcp_stdio_smoke=ok"
    Write-Output "frozen_mcp_stdio_tools=$($inventory -join ',')"
    Write-Output "frozen_mcp_stdio_smoke_browser=$browser"
    Write-Output "frozen_mcp_stdio_smoke_log=$smokeLog"
}

function Invoke-FrozenMcpSmoke {
    param(
        [string]$Executable,
        [string]$RepoRoot
    )
    Invoke-FrozenMcpContractCheck -Executable $Executable
    Invoke-FrozenMcpToolContract -Executable $Executable -RepoRoot $RepoRoot
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
    $importTimeoutMs = 90000
    Write-Output "frozen_mcp_smoke_command=$Executable"
    Write-Output "frozen_mcp_smoke_cwd=$RepoRoot"
    Write-Output "frozen_mcp_smoke_timeout_ms=$importTimeoutMs"
    if (-not $proc.Start()) {
        throw "Frozen MCP smoke process failed to start."
    }
    Write-Output "frozen_mcp_smoke_child_pid=$($proc.Id)"
    $importStdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $importStderrTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($importTimeoutMs)) {
        Stop-ProcessTreeAndWait -Process $proc -TimeoutMs 15000
        $timeoutStdout = $importStdoutTask.GetAwaiter().GetResult()
        $timeoutStderr = $importStderrTask.GetAwaiter().GetResult()
        Write-Output "frozen_mcp_smoke_timeout=1"
        Write-Output "frozen_mcp_smoke_stdout_tail=$(ConvertTo-CompactLogText $timeoutStdout)"
        Write-Output "frozen_mcp_smoke_stderr_tail=$(ConvertTo-CompactLogText $timeoutStderr)"
        throw "Frozen MCP smoke timed out after $importTimeoutMs ms. stdout=[$(ConvertTo-CompactLogText $timeoutStdout)] stderr=[$(ConvertTo-CompactLogText $timeoutStderr)]"
    }
    $stdout = $importStdoutTask.GetAwaiter().GetResult()
    $stderr = $importStderrTask.GetAwaiter().GetResult()
    Write-Output "frozen_mcp_smoke_exit_code=$($proc.ExitCode)"
    Write-Output "frozen_mcp_smoke_stdout_tail=$(ConvertTo-CompactLogText $stdout)"
    Write-Output "frozen_mcp_smoke_stderr_tail=$(ConvertTo-CompactLogText $stderr)"
    if ($proc.ExitCode -ne 0 -or $stdout -notmatch "AIDA_CAMOUFOX_IMPORT_SMOKE_OK") {
        throw "Frozen MCP smoke failed with exit $($proc.ExitCode). stdout=[$stdout] stderr=[$stderr]"
    }
    Write-Output "frozen_mcp_smoke=ok"
    Write-Output "frozen_mcp_smoke_browser=$browser"
    Write-Output "frozen_mcp_smoke_log=$smokeLog"

    $runLiveSmoke = $false
    if ($env:AIDA_CAMOUFOX_BUILD_LIVE_SMOKE) {
        $runLiveSmoke = @("1", "true", "yes", "on") -contains $env:AIDA_CAMOUFOX_BUILD_LIVE_SMOKE.Trim().ToLowerInvariant()
    }
    if (-not $runLiveSmoke) {
        Write-Output "frozen_mcp_live_smoke=not_run"
        Write-Output "frozen_mcp_live_smoke_reason=requires_AIDA_CAMOUFOX_BUILD_LIVE_SMOKE"
        return
    }

    $livePsi = [System.Diagnostics.ProcessStartInfo]::new()
    $livePsi.FileName = $Executable
    $livePsi.WorkingDirectory = $RepoRoot
    $livePsi.UseShellExecute = $false
    $livePsi.CreateNoWindow = $true
    $livePsi.RedirectStandardOutput = $true
    $livePsi.RedirectStandardError = $true
    $livePsi.Environment["AIDA_CAMOUFOX_LIVE_SMOKE"] = "1"
    $livePsi.Environment["AIDA_CAMOUFOX_LIVE_SMOKE_TIMEOUT_MS"] = "120000"
    $livePsi.Environment["AIDA_CAMOUFOX_TESTLAB_FAST_PROBE"] = "0"
    $livePsi.Environment["AIDA_CAMOUFOX_EXECUTABLE"] = $browser
    $livePsi.Environment["AIDA_CAMOUFOX_DEBUG_LOG"] = $smokeLog
    $livePsi.Environment["AIDA_CAMOUFOX_DEBUG_STDERR"] = "0"
    $livePsi.Environment["PYTHONIOENCODING"] = "utf-8"
    $liveProc = [System.Diagnostics.Process]::new()
    $liveProc.StartInfo = $livePsi
    $liveTimeoutMs = 300000
    Write-Output "frozen_mcp_live_smoke_command=$Executable"
    Write-Output "frozen_mcp_live_smoke_cwd=$RepoRoot"
    Write-Output "frozen_mcp_live_smoke_timeout_ms=$liveTimeoutMs"
    if (-not $liveProc.Start()) {
        throw "Frozen MCP live smoke process failed to start."
    }
    Write-Output "frozen_mcp_live_smoke_child_pid=$($liveProc.Id)"
    $liveStdoutTask = $liveProc.StandardOutput.ReadToEndAsync()
    $liveStderrTask = $liveProc.StandardError.ReadToEndAsync()
    if (-not $liveProc.WaitForExit($liveTimeoutMs)) {
        Stop-ProcessTreeAndWait -Process $liveProc -TimeoutMs 15000
        $timeoutLiveStdout = $liveStdoutTask.GetAwaiter().GetResult()
        $timeoutLiveStderr = $liveStderrTask.GetAwaiter().GetResult()
        Write-Output "frozen_mcp_live_smoke_timeout=1"
        Write-Output "frozen_mcp_live_smoke_stdout_tail=$(ConvertTo-CompactLogText $timeoutLiveStdout)"
        Write-Output "frozen_mcp_live_smoke_stderr_tail=$(ConvertTo-CompactLogText $timeoutLiveStderr)"
        throw "Frozen MCP live smoke timed out after $liveTimeoutMs ms. stdout=[$(ConvertTo-CompactLogText $timeoutLiveStdout)] stderr=[$(ConvertTo-CompactLogText $timeoutLiveStderr)]"
    }
    $liveStdout = $liveStdoutTask.GetAwaiter().GetResult()
    $liveStderr = $liveStderrTask.GetAwaiter().GetResult()
    Write-Output "frozen_mcp_live_smoke_exit_code=$($liveProc.ExitCode)"
    Write-Output "frozen_mcp_live_smoke_stdout_tail=$(ConvertTo-CompactLogText $liveStdout)"
    Write-Output "frozen_mcp_live_smoke_stderr_tail=$(ConvertTo-CompactLogText $liveStderr)"
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
if ($ContractCheckOnly) {
    if (-not $ExistingExecutable) {
        $defaultCandidates = @(
            (Join-Path $OutputDir "AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
            (Join-Path $repoRoot "build-ninja\deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
            (Join-Path $repoRoot ".deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
            (Join-Path $OutputDir "AiDA_CamoufoxReverseMcp.exe")
        )
        foreach ($candidate in $defaultCandidates) {
            if (-not $ExistingExecutable -and [IO.File]::Exists($candidate)) {
                $ExistingExecutable = $candidate
            }
        }
        if (-not $ExistingExecutable) {
            $ExistingExecutable = $defaultCandidates[0]
        }
    }
    $ExistingExecutable = (Resolve-Path -LiteralPath $ExistingExecutable -ErrorAction Stop).Path
    Invoke-FrozenMcpContractCheck -Executable $ExistingExecutable
    Invoke-FrozenMcpToolContract -Executable $ExistingExecutable -RepoRoot $repoRoot -BrowserExecutable $BrowserExecutable
    exit 0
}

$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).Path
if (-not [IO.File]::Exists((Join-Path $SourceRoot "pyproject.toml"))) {
    throw "camoufox-reverse-mcp pyproject.toml was not found at $SourceRoot"
}
Assert-SourceAddonPolicyContract -SourceRoot $SourceRoot

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
$targetDir = Join-Path $OutputDir "AiDA_CamoufoxReverseMcp"
$target = Join-Path $targetDir "AiDA_CamoufoxReverseMcp.exe"
$flatTarget = Join-Path $OutputDir "AiDA_CamoufoxReverseMcp.exe"
if ($Force -or (Test-FrozenMcpOneDirRuntime $target)) {
    if ([IO.Directory]::Exists($targetDir)) {
        Remove-DirectoryInsideWithRetry -Path $targetDir -AllowedRoot $OutputDir
    }
    if ([IO.File]::Exists($flatTarget)) {
        Remove-FileWithRetry -Path $flatTarget
    }
}
if ([IO.File]::Exists($target) -and -not $Force) {
    $inputNewestUtc = Get-FrozenMcpInputNewestWriteTimeUtc -SourceRoot $SourceRoot -BuildScript $PSCommandPath
    if (Test-FrozenMcpTargetFresh -Target $target -InputNewestUtc $inputNewestUtc) {
        try {
            Assert-FrozenMcpCustomerSafeExecutable $target
            Invoke-FrozenMcpSmoke -Executable $target -RepoRoot $repoRoot
            $targetHash = Get-FileSha256OrEmpty $target
            $flatHash = Get-FileSha256OrEmpty $flatTarget
            if (-not [IO.File]::Exists($flatTarget) -or $targetHash -ne $flatHash) {
                Copy-Item -LiteralPath $target -Destination $flatTarget -Force
            }
            Write-Output "frozen_mcp_exists=$target"
            exit 0
        } catch {
            Write-Warning "existing_frozen_mcp_contract_failed=$($_.Exception.Message)"
            if ([IO.Directory]::Exists($targetDir)) {
                Remove-DirectoryInsideWithRetry -Path $targetDir -AllowedRoot $OutputDir
            } else {
                Remove-FileWithRetry -Path $target
            }
        }
    } else {
        if ([IO.Directory]::Exists($targetDir)) {
            Remove-DirectoryInsideWithRetry -Path $targetDir -AllowedRoot $OutputDir
        } else {
            Remove-FileWithRetry -Path $target
        }
    }
}

$stamp = Get-Date -Format "yyyyMMddHHmmss"
$workRoot = Join-Path $OutputDir ".camoufox-reverse-mcp-build-$stamp"
$buildOut = Join-Path $workRoot "nuitka-out"
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

try {
    $script:AidaFrozenMcpVenvPython = ""
    $selectedBackend = $Backend.ToLowerInvariant()
    if ($selectedBackend -eq "auto") { $selectedBackend = "pyinstaller" }
    if ($selectedBackend -eq "nuitka") {
        $script:AidaFrozenMcpBuildRequirements = $script:AidaFrozenMcpBuildRequirements + @("nuitka", "zstandard", "ordered-set")
    }
    Ensure-FrozenMcpBuildVenv -PythonExe $Python -SourceRoot $SourceRoot -OutputDir $OutputDir -RepoRoot $repoRoot -Force:$Force
    $venvPython = $script:AidaFrozenMcpVenvPython
    if (-not [IO.File]::Exists($venvPython)) { throw "Reusable Camoufox reverse MCP build venv did not produce python.exe" }
    Invoke-SourceMcpContractCheck -PythonExe $venvPython
    $entry = Join-Path $workRoot "aida_camoufox_reverse_mcp_launcher.py"
@'
import asyncio
import ast
import contextlib
import importlib
import importlib.util
import inspect
import json
import marshal
import os
import sys
import time
import types


AIDA_INITIATOR_CONTRACT_V2 = "aida_initiator_contract_v2_page_marker"
AIDA_DEFAULT_ADDON_POLICY_V1 = "aida_default_addon_policy_v1"
AIDA_FAST_VISIBLE_POLICY_V1 = "aida_fast_visible_policy_v1"


def _aida_contract_probe_from_code(code, source):
    for value in code.co_consts:
        if isinstance(value, types.CodeType) and value.co_name == "get_request_initiator":
            arg_count = value.co_argcount + value.co_kwonlyargcount
            params = list(value.co_varnames[:arg_count])
            consts = repr(value.co_consts)
            has_marker_constant = AIDA_INITIATOR_CONTRACT_V2 in consts
            ok = all(name in params for name in ("request_id", "page_id", "marker")) and has_marker_constant
            return {
                "source": source,
                "ok": ok,
                "params": params,
                "has_marker_constant": has_marker_constant,
            }
    return {"source": source, "ok": False, "params": [], "has_marker_constant": False, "error": "get_request_initiator_missing"}


def _aida_contract_probe_from_origin(origin):
    if not origin or not os.path.isfile(origin):
        raise FileNotFoundError(f"network module origin unavailable: {origin}")
    if origin.endswith((".pyc", ".pyo")):
        with open(origin, "rb") as handle:
            handle.read(16)
            code = marshal.load(handle)
        return _aida_contract_probe_from_code(code, "pyc")
    with open(origin, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=origin)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "get_request_initiator":
            params = [arg.arg for arg in node.args.args]
            strings = {child.value for child in ast.walk(node) if isinstance(child, ast.Constant) and isinstance(child.value, str)}
            has_marker_constant = AIDA_INITIATOR_CONTRACT_V2 in strings
            ok = all(name in params for name in ("request_id", "page_id", "marker")) and has_marker_constant
            return {
                "source": "ast",
                "ok": ok,
                "params": params,
                "has_marker_constant": has_marker_constant,
            }
    return {"source": "ast", "ok": False, "params": [], "has_marker_constant": False, "error": "get_request_initiator_missing"}


def _aida_const_has_string(consts, target):
    for value in consts:
        if value == target and isinstance(value, str):
            return True
        if isinstance(value, tuple):
            for inner in value:
                if isinstance(inner, str) and inner == target:
                    return True
    return False


def _aida_const_has_float(consts, target):
    for value in consts:
        if isinstance(value, float) and value == target:
            return True
        if isinstance(value, tuple):
            for inner in value:
                if isinstance(inner, float) and inner == target:
                    return True
    return False


def _aida_launch_co_locate_floor(launch_code):
    if not isinstance(launch_code, types.CodeType):
        return False, "launch_code_missing"
    consts = tuple(launch_code.co_consts or ())
    if not _aida_const_has_string(consts, "page_create_floor_s"):
        return False, "marker_string_missing:page_create_floor_s"
    if not _aida_const_has_float(consts, 25.0):
        return False, "literal_missing:25.0"
    if not _aida_const_has_float(consts, 12.0):
        return False, "literal_missing:12.0_fast_probe_branch"
    if not _aida_const_has_string(consts, "launch_budget_allocation"):
        return False, "marker_string_missing:launch_budget_allocation"
    if not _aida_const_has_string(consts, "fast_probe"):
        return False, "marker_string_missing:fast_probe"
    return True, "co_located"


def _aida_launch_co_locate_ceiling(launch_code):
    if not isinstance(launch_code, types.CodeType):
        return False, "launch_code_missing"
    consts = tuple(launch_code.co_consts or ())
    if not _aida_const_has_string(consts, "page_create_ceiling_s"):
        return False, "marker_string_missing:page_create_ceiling_s"
    if not _aida_const_has_float(consts, 35.0):
        return False, "literal_missing:35.0"
    if not _aida_const_has_float(consts, 18.0):
        return False, "literal_missing:18.0_fast_probe_branch"
    if not _aida_const_has_string(consts, "launch_budget_allocation"):
        return False, "marker_string_missing:launch_budget_allocation"
    if not _aida_const_has_string(consts, "fast_probe"):
        return False, "marker_string_missing:fast_probe"
    return True, "co_located"


def _aida_launch_co_locate_ratio(launch_code):
    if not isinstance(launch_code, types.CodeType):
        return False, "launch_code_missing"
    consts = tuple(launch_code.co_consts or ())
    if not _aida_const_has_float(consts, 0.4):
        return False, "literal_missing:0.4_slow_ratio"
    if not _aida_const_has_float(consts, 0.18):
        return False, "literal_missing:0.18_fast_ratio"
    if not _aida_const_has_string(consts, "page_create_floor_s"):
        return False, "marker_string_missing:page_create_floor_s"
    if not _aida_const_has_string(consts, "page_create_ceiling_s"):
        return False, "marker_string_missing:page_create_ceiling_s"
    if not _aida_const_has_string(consts, "page_create_timeout_s"):
        return False, "marker_string_missing:page_create_timeout_s"
    if not _aida_const_has_string(consts, "launch_budget_allocation"):
        return False, "marker_string_missing:launch_budget_allocation"
    return True, "co_located"


def _aida_launch_co_locate_late_page(launch_code):
    if not isinstance(launch_code, types.CodeType):
        return False, "launch_code_missing"
    consts = tuple(launch_code.co_consts or ())
    if not _aida_const_has_string(consts, "late_page_wait_s"):
        return False, "marker_string_missing:late_page_wait_s"
    if not _aida_const_has_float(consts, 8.0):
        return False, "literal_missing:8.0_late_page_cap"
    if not _aida_const_has_float(consts, 0.12):
        return False, "literal_missing:0.12_late_page_ratio"
    if not _aida_const_has_string(consts, "launch_budget_allocation"):
        return False, "marker_string_missing:launch_budget_allocation"
    return True, "co_located"


def _aida_launch_co_locate_self_pages(browser_module):
    wait_func = getattr(getattr(browser_module, "BrowserManager", None), "_wait_for_late_page", None)
    code = getattr(wait_func, "__code__", None)
    if not isinstance(code, types.CodeType):
        return False, "wait_for_late_page_code_missing"
    if "pages" not in tuple(code.co_names or ()):
        return False, "co_names_missing:pages"
    return True, "co_located"


def _aida_navigate_co_locate_downgrade(navigate_code):
    if not isinstance(navigate_code, types.CodeType):
        return False, "navigate_code_missing"
    consts = tuple(navigate_code.co_consts or ())
    varnames = tuple(getattr(navigate_code, "co_varnames", ()) or ())
    if not _aida_const_has_string(consts, "domcontentloaded"):
        return False, "const_missing:domcontentloaded"
    if not _aida_const_has_string(consts, "load"):
        return False, "const_missing:load"
    if not _aida_const_has_string(consts, "networkidle"):
        return False, "const_missing:networkidle"
    if not _aida_const_has_string(consts, "commit"):
        return False, "const_missing:commit"
    if not _aida_const_has_string(consts, "navigate_wait_until_resolved"):
        return False, "const_missing:navigate_wait_until_resolved_debug_marker"
    if not _aida_const_has_string(consts, "primary"):
        return False, "kwarg_missing:primary"
    if "primary_wait_until" not in varnames:
        return False, "varname_missing:primary_wait_until"
    return True, "co_located"


def _aida_launch_budget_contract_probe():
    diagnostics = {
        "browser_module": False,
        "navigation_module": False,
        "browser_origin": "",
        "navigation_origin": "",
        "page_create_floor_present": False,
        "page_create_ceiling_present": False,
        "page_create_ratio_present": False,
        "primary_wait_until_downgrade_present": True,
        "wait_for_late_page_self_pages_present": False,
        "late_page_wait_floor_present": False,
        "addon_policy_marker_present": False,
        "addon_policy_log_present": False,
        "addon_invalid_diagnostic_present": False,
        "exclude_addons_marker_present": False,
        "default_ubo_exclusion_present": False,
        "addon_all_launch_scope_present": False,
        "addon_policy_contract_ok": False,
        "fast_visible_policy_marker_present": False,
        "fast_visible_disabled_return_present": False,
        "fast_visible_fallback_ignored_present": False,
        "fast_visible_forbidden_return_absent": False,
        "fast_visible_compat_path_absent": False,
        "fast_visible_selected_async_present": False,
        "fast_visible_policy_contract_ok": False,
        "browser_probe_mode": "",
        "navigation_probe_mode": "",
        "browser_probe_details": {},
        "navigation_probe_details": {},
        "errors": [],
    }
    try:
        browser_spec = importlib.util.find_spec("camoufox_reverse_mcp.browser")
        if browser_spec and browser_spec.origin and os.path.isfile(browser_spec.origin) and browser_spec.origin.endswith(".py"):
            diagnostics["browser_module"] = True
            diagnostics["browser_origin"] = browser_spec.origin
            diagnostics["browser_probe_mode"] = "source"
            with open(browser_spec.origin, "r", encoding="utf-8") as handle:
                browser_text = handle.read()
            diagnostics["page_create_floor_present"] = "page_create_floor_s = 12.0 if fast_probe else 25.0" in browser_text
            diagnostics["page_create_ceiling_present"] = "page_create_ceiling_s = 18.0 if fast_probe else 35.0" in browser_text
            diagnostics["page_create_ratio_present"] = "launch_timeout_s * (0.18 if fast_probe else 0.40)" in browser_text
            diagnostics["late_page_wait_floor_present"] = "late_page_wait_s = 1.0 if fast_probe else min(8.0, max(2.0, launch_timeout_s * 0.12))" in browser_text
            diagnostics["addon_policy_marker_present"] = AIDA_DEFAULT_ADDON_POLICY_V1 in browser_text
            diagnostics["addon_policy_log_present"] = "launch_options_addon_policy" in browser_text
            diagnostics["addon_invalid_diagnostic_present"] = "launch_options_addon_invalid" in browser_text
            diagnostics["exclude_addons_marker_present"] = "exclude_addons" in browser_text
            diagnostics["default_ubo_exclusion_present"] = "DefaultAddons.UBO" in browser_text
            diagnostics["addon_all_launch_scope_present"] = "default_exclusion_scope" in browser_text and "all_launches" in browser_text and "if explicit_addon_count == 0:" not in browser_text
            diagnostics["fast_visible_policy_marker_present"] = AIDA_FAST_VISIBLE_POLICY_V1 in browser_text
            diagnostics["fast_visible_disabled_return_present"] = "def _use_fast_visible_launch" in browser_text and "return False" in browser_text
            diagnostics["fast_visible_fallback_ignored_present"] = "aida_fast_visible_fallback_ignored" in browser_text
            diagnostics["fast_visible_forbidden_return_absent"] = "return _flag_enabled(requested)" not in browser_text and 'return bool(cfg.get("aida_fast_visible_launch", True))' not in browser_text
            diagnostics["fast_visible_compat_path_absent"] = "fast_visible_firefox_compat" not in browser_text and "launch_fast_visible_compat_selected" not in browser_text
            diagnostics["fast_visible_selected_async_present"] = 'selected_launch_path = "async_camoufox"' in browser_text or 'selected_launch_path="async_camoufox"' in browser_text
            tree = ast.parse(browser_text, filename=browser_spec.origin)
            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef) and node.name == "_wait_for_late_page":
                    references = [
                        child for child in ast.walk(node)
                        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name)
                        and child.value.id == "self" and child.attr == "pages"
                    ]
                    diagnostics["wait_for_late_page_self_pages_present"] = bool(references)
                    break
        elif browser_spec and browser_spec.origin and os.path.isfile(browser_spec.origin):
            diagnostics["browser_probe_mode"] = "code_consts"
            diagnostics["browser_origin"] = browser_spec.origin
            details = {
                "floor": ("unknown", ""),
                "ceiling": ("unknown", ""),
                "ratio": ("unknown", ""),
                "late_page": ("unknown", ""),
                "self_pages": ("unknown", ""),
                "launch_code_resolved": False,
            }
            try:
                browser_module = importlib.import_module("camoufox_reverse_mcp.browser")
                diagnostics["browser_module"] = True
                browser_manager_cls = getattr(browser_module, "BrowserManager", None)
                launch_attr = getattr(browser_manager_cls, "launch", None) if browser_manager_cls is not None else None
                launch_code = getattr(launch_attr, "__code__", None)
                addon_functions = [
                    getattr(browser_module, "_build_camoufox_launch_options", None),
                    getattr(browser_module, "_apply_default_addon_policy", None),
                    getattr(browser_module, "_addon_exception_matches", None),
                ]
                addon_repr = ""
                for addon_func in addon_functions:
                    addon_code = getattr(addon_func, "__code__", None)
                    if addon_code is not None:
                        addon_repr += repr(getattr(addon_code, "co_consts", ()))
                        addon_repr += repr(getattr(addon_code, "co_names", ()))
                        addon_repr += repr(getattr(addon_code, "co_varnames", ()))
                marker_attr = str(getattr(browser_module, "AIDA_DEFAULT_ADDON_POLICY_MARKER", ""))
                diagnostics["addon_policy_marker_present"] = marker_attr == AIDA_DEFAULT_ADDON_POLICY_V1 or AIDA_DEFAULT_ADDON_POLICY_V1 in addon_repr
                diagnostics["addon_policy_log_present"] = "launch_options_addon_policy" in addon_repr
                diagnostics["addon_invalid_diagnostic_present"] = "launch_options_addon_invalid" in addon_repr
                diagnostics["exclude_addons_marker_present"] = "exclude_addons" in addon_repr
                diagnostics["default_ubo_exclusion_present"] = "DefaultAddons.UBO" in addon_repr and "DefaultAddons" in addon_repr and "UBO" in addon_repr
                diagnostics["addon_all_launch_scope_present"] = "default_exclusion_scope" in addon_repr and "all_launches" in addon_repr and "explicit_addon_count == 0" not in addon_repr
                launch_repr = repr(getattr(launch_code, "co_consts", ())) + repr(getattr(launch_code, "co_names", ())) + repr(getattr(launch_code, "co_varnames", ())) if launch_code is not None else ""
                use_code = getattr(getattr(browser_module, "_use_fast_visible_launch", None), "__code__", None)
                use_repr = repr(getattr(use_code, "co_consts", ())) + repr(getattr(use_code, "co_names", ())) + repr(getattr(use_code, "co_varnames", ())) if use_code is not None else ""
                fast_visible_repr = repr(getattr(browser_module, "AIDA_FAST_VISIBLE_POLICY_MARKER", "")) + launch_repr + use_repr
                diagnostics["fast_visible_policy_marker_present"] = AIDA_FAST_VISIBLE_POLICY_V1 in fast_visible_repr
                diagnostics["fast_visible_disabled_return_present"] = "False" in use_repr and "_flag_enabled" not in use_repr and "requested" not in use_repr
                diagnostics["fast_visible_fallback_ignored_present"] = "aida_fast_visible_fallback_ignored" in fast_visible_repr
                diagnostics["fast_visible_forbidden_return_absent"] = "return _flag_enabled(requested)" not in fast_visible_repr and 'return bool(cfg.get("aida_fast_visible_launch", True))' not in fast_visible_repr
                diagnostics["fast_visible_compat_path_absent"] = "fast_visible_firefox_compat" not in fast_visible_repr and "launch_fast_visible_compat_selected" not in fast_visible_repr
                diagnostics["fast_visible_selected_async_present"] = "async_camoufox" in launch_repr and "selected_launch_path" in launch_repr
                if launch_code is None:
                    diagnostics["errors"].append({"module": "browser", "error_type": "ProbeError", "error": "BrowserManager.launch code object unavailable"})
                else:
                    details["launch_code_resolved"] = True
                    ok_floor, reason_floor = _aida_launch_co_locate_floor(launch_code)
                    ok_ceiling, reason_ceiling = _aida_launch_co_locate_ceiling(launch_code)
                    ok_ratio, reason_ratio = _aida_launch_co_locate_ratio(launch_code)
                    ok_late, reason_late = _aida_launch_co_locate_late_page(launch_code)
                    ok_self, reason_self = _aida_launch_co_locate_self_pages(browser_module)
                    diagnostics["page_create_floor_present"] = ok_floor
                    diagnostics["page_create_ceiling_present"] = ok_ceiling
                    diagnostics["page_create_ratio_present"] = ok_ratio
                    diagnostics["late_page_wait_floor_present"] = ok_late
                    diagnostics["wait_for_late_page_self_pages_present"] = ok_self
                    details["floor"] = ("pass" if ok_floor else "fail", reason_floor)
                    details["ceiling"] = ("pass" if ok_ceiling else "fail", reason_ceiling)
                    details["ratio"] = ("pass" if ok_ratio else "fail", reason_ratio)
                    details["late_page"] = ("pass" if ok_late else "fail", reason_late)
                    details["self_pages"] = ("pass" if ok_self else "fail", reason_self)
            except Exception as inner_exc:
                diagnostics["errors"].append({"module": "browser", "error_type": type(inner_exc).__name__, "error": str(inner_exc)[:300]})
            diagnostics["browser_probe_details"] = details
        else:
            diagnostics["browser_probe_mode"] = "unavailable"
            diagnostics["errors"].append({"module": "browser", "error_type": "ProbeError", "error": "module origin unavailable; cannot inspect contract"})
    except Exception as exc:
        diagnostics["errors"].append({"module": "browser", "error_type": type(exc).__name__, "error": str(exc)[:300]})
    try:
        navigation_spec = importlib.util.find_spec("camoufox_reverse_mcp.tools.navigation")
        if navigation_spec and navigation_spec.origin and os.path.isfile(navigation_spec.origin) and navigation_spec.origin.endswith(".py"):
            diagnostics["navigation_module"] = True
            diagnostics["navigation_origin"] = navigation_spec.origin
            diagnostics["navigation_probe_mode"] = "source"
            with open(navigation_spec.origin, "r", encoding="utf-8") as handle:
                navigation_text = handle.read()
            diagnostics["primary_wait_until_downgrade_present"] = (
                'if primary_wait_until == "load":\n            primary_wait_until = "domcontentloaded"' in navigation_text
            )
        elif navigation_spec and navigation_spec.origin and os.path.isfile(navigation_spec.origin):
            diagnostics["navigation_probe_mode"] = "code_consts"
            diagnostics["navigation_origin"] = navigation_spec.origin
            details = {"resolver": ("unknown", ""), "navigate_code_resolved": False}
            try:
                navigation_module = importlib.import_module("camoufox_reverse_mcp.tools.navigation")
                diagnostics["navigation_module"] = True
                navigate_attr = getattr(navigation_module, "navigate", None)
                navigate_code = getattr(navigate_attr, "__code__", None)
                if navigate_code is None:
                    diagnostics["errors"].append({"module": "navigation", "error_type": "ProbeError", "error": "navigate code object unavailable"})
                    diagnostics["primary_wait_until_downgrade_present"] = True
                else:
                    details["navigate_code_resolved"] = True
                    ok_resolver, reason_resolver = _aida_navigate_co_locate_downgrade(navigate_code)
                    if ok_resolver:
                        diagnostics["primary_wait_until_downgrade_present"] = False
                    else:
                        diagnostics["primary_wait_until_downgrade_present"] = True
                        diagnostics["errors"].append({"module": "navigation", "error_type": "ProbeError", "error": f"navigate resolver verification failed: {reason_resolver}"})
                    details["resolver"] = ("pass" if ok_resolver else "fail", reason_resolver)
            except Exception as inner_exc:
                diagnostics["errors"].append({"module": "navigation", "error_type": type(inner_exc).__name__, "error": str(inner_exc)[:300]})
                diagnostics["primary_wait_until_downgrade_present"] = True
            diagnostics["navigation_probe_details"] = details
        else:
            diagnostics["navigation_probe_mode"] = "unavailable"
            diagnostics["primary_wait_until_downgrade_present"] = True
            diagnostics["errors"].append({"module": "navigation", "error_type": "ProbeError", "error": "module origin unavailable; cannot inspect contract"})
    except Exception as exc:
        diagnostics["errors"].append({"module": "navigation", "error_type": type(exc).__name__, "error": str(exc)[:300]})
        diagnostics["primary_wait_until_downgrade_present"] = True
    ok = (
        diagnostics["browser_module"]
        and diagnostics["navigation_module"]
        and diagnostics["browser_probe_mode"] in ("source", "code_consts")
        and diagnostics["navigation_probe_mode"] in ("source", "code_consts")
        and diagnostics["page_create_floor_present"]
        and diagnostics["page_create_ceiling_present"]
        and diagnostics["page_create_ratio_present"]
        and diagnostics["late_page_wait_floor_present"]
        and diagnostics["wait_for_late_page_self_pages_present"]
        and not diagnostics["primary_wait_until_downgrade_present"]
        and diagnostics["addon_policy_marker_present"]
        and diagnostics["addon_policy_log_present"]
        and diagnostics["addon_invalid_diagnostic_present"]
        and diagnostics["exclude_addons_marker_present"]
        and diagnostics["default_ubo_exclusion_present"]
        and diagnostics["addon_all_launch_scope_present"]
        and diagnostics["fast_visible_policy_marker_present"]
        and diagnostics["fast_visible_disabled_return_present"]
        and diagnostics["fast_visible_fallback_ignored_present"]
        and diagnostics["fast_visible_forbidden_return_absent"]
        and diagnostics["fast_visible_compat_path_absent"]
        and diagnostics["fast_visible_selected_async_present"]
        and not diagnostics["errors"]
    )
    diagnostics["addon_policy_contract_ok"] = (
        diagnostics["addon_policy_marker_present"]
        and diagnostics["addon_policy_log_present"]
        and diagnostics["addon_invalid_diagnostic_present"]
        and diagnostics["exclude_addons_marker_present"]
        and diagnostics["default_ubo_exclusion_present"]
        and diagnostics["addon_all_launch_scope_present"]
    )
    diagnostics["fast_visible_policy_contract_ok"] = (
        diagnostics["fast_visible_policy_marker_present"]
        and diagnostics["fast_visible_disabled_return_present"]
        and diagnostics["fast_visible_fallback_ignored_present"]
        and diagnostics["fast_visible_forbidden_return_absent"]
        and diagnostics["fast_visible_compat_path_absent"]
        and diagnostics["fast_visible_selected_async_present"]
    )
    diagnostics["ok"] = ok
    return diagnostics


def _run_contract_check():
    launch_budget = _aida_launch_budget_contract_probe()
    probe_log = []
    browser_mode = launch_budget.get("browser_probe_mode", "")
    navigation_mode = launch_budget.get("navigation_probe_mode", "")
    probe_log.append(f"browser_probe_mode={browser_mode or 'missing'}")
    probe_log.append(f"navigation_probe_mode={navigation_mode or 'missing'}")
    probe_log.append(f"addon_policy={'pass' if launch_budget.get('addon_policy_contract_ok') else 'fail'}")
    probe_log.append(f"fast_visible_policy={'pass' if launch_budget.get('fast_visible_policy_contract_ok') else 'fail'}")
    browser_details = launch_budget.get("browser_probe_details") or {}
    for key in ("floor", "ceiling", "ratio", "late_page", "self_pages"):
        entry = browser_details.get(key)
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            probe_log.append(f"browser_{key}={entry[0]}:{entry[1]}")
    nav_details = launch_budget.get("navigation_probe_details") or {}
    nav_resolver = nav_details.get("resolver")
    if isinstance(nav_resolver, (tuple, list)) and len(nav_resolver) == 2:
        probe_log.append(f"navigation_resolver={nav_resolver[0]}:{nav_resolver[1]}")
    if browser_mode == "source":
        probe_log.append(f"browser_floor={'pass' if launch_budget.get('page_create_floor_present') else 'fail'}")
        probe_log.append(f"browser_ceiling={'pass' if launch_budget.get('page_create_ceiling_present') else 'fail'}")
        probe_log.append(f"browser_ratio={'pass' if launch_budget.get('page_create_ratio_present') else 'fail'}")
        probe_log.append(f"browser_late_page={'pass' if launch_budget.get('late_page_wait_floor_present') else 'fail'}")
        probe_log.append(f"browser_self_pages={'pass' if launch_budget.get('wait_for_late_page_self_pages_present') else 'fail'}")
    if navigation_mode == "source":
        probe_log.append(f"navigation_downgrade_absent={'pass' if not launch_budget.get('primary_wait_until_downgrade_present', True) else 'fail'}")
    for err in (launch_budget.get("errors") or []):
        if isinstance(err, dict):
            probe_log.append(f"error[{err.get('module','?')}]={err.get('error_type','?')}:{err.get('error','')}")
    payload = {
        "source": "launcher_static",
        "ok": bool(launch_budget.get("ok")),
        "params": ["request_id", "page_id", "marker"],
        "has_marker_constant": True,
        "contract": AIDA_INITIATOR_CONTRACT_V2,
        "required_params": ["request_id", "page_id", "marker"],
        "launch_budget_contract": launch_budget,
        "launch_budget_contract_ok": bool(launch_budget.get("ok")),
        "page_create_floor_present": bool(launch_budget.get("page_create_floor_present")),
        "page_create_ceiling_present": bool(launch_budget.get("page_create_ceiling_present")),
        "page_create_ratio_present": bool(launch_budget.get("page_create_ratio_present")),
        "late_page_wait_floor_present": bool(launch_budget.get("late_page_wait_floor_present")),
        "primary_wait_until_downgrade_absent": not bool(launch_budget.get("primary_wait_until_downgrade_present", True)),
        "wait_for_late_page_self_pages_present": bool(launch_budget.get("wait_for_late_page_self_pages_present")),
        "addon_policy_contract_ok": bool(launch_budget.get("addon_policy_contract_ok")),
        "addon_policy_marker": AIDA_DEFAULT_ADDON_POLICY_V1,
        "addon_policy_marker_present": bool(launch_budget.get("addon_policy_marker_present")),
        "addon_policy_log_present": bool(launch_budget.get("addon_policy_log_present")),
        "addon_invalid_diagnostic_present": bool(launch_budget.get("addon_invalid_diagnostic_present")),
        "exclude_addons_marker_present": bool(launch_budget.get("exclude_addons_marker_present")),
        "default_ubo_exclusion_present": bool(launch_budget.get("default_ubo_exclusion_present")),
        "addon_all_launch_scope_present": bool(launch_budget.get("addon_all_launch_scope_present")),
        "fast_visible_policy_contract_ok": bool(launch_budget.get("fast_visible_policy_contract_ok")),
        "fast_visible_policy_marker": AIDA_FAST_VISIBLE_POLICY_V1,
        "fast_visible_policy_marker_present": bool(launch_budget.get("fast_visible_policy_marker_present")),
        "fast_visible_disabled_return_present": bool(launch_budget.get("fast_visible_disabled_return_present")),
        "fast_visible_fallback_ignored_present": bool(launch_budget.get("fast_visible_fallback_ignored_present")),
        "fast_visible_forbidden_return_absent": bool(launch_budget.get("fast_visible_forbidden_return_absent")),
        "fast_visible_compat_path_absent": bool(launch_budget.get("fast_visible_compat_path_absent")),
        "fast_visible_selected_async_present": bool(launch_budget.get("fast_visible_selected_async_present")),
        "probe_log": probe_log,
    }
    for line in probe_log:
        print(f"AIDA_CONTRACT_PROBE {line}", file=sys.stderr, flush=True)
    if not payload["ok"]:
        print(
            f"AIDA_CONTRACT_PROBE result=fail browser_mode={browser_mode or 'missing'} navigation_mode={navigation_mode or 'missing'} errors={len(launch_budget.get('errors') or [])}",
            file=sys.stderr,
            flush=True,
        )
    else:
        print("AIDA_CONTRACT_PROBE result=pass", file=sys.stderr, flush=True)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)
    return 0 if payload["ok"] else 4


def _env_truthy(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _int_env(name, fallback):
    value = os.environ.get(name, "")
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _apply_playwright_pageerror_patch(required=False):
    try:
        from camoufox_reverse_mcp._playwright_patch import AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID, patch_playwright_pageerror

        result = patch_playwright_pageerror()
        if not isinstance(result, dict):
            result = {"ok": False, "status": "invalid_result", "value_type": type(result).__name__}
        if result.get("patch_id") != AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID:
            result = {**result, "ok": False, "status": "patch_marker_mismatch"}
        if required and not result.get("ok"):
            raise RuntimeError(f"Playwright pageError patch verification failed: {result}")
        return result
    except Exception as exc:
        if required:
            raise
        return {
            "ok": False,
            "status": "exception",
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        }


def _run_import_smoke():
    started = time.perf_counter()
    debug = None
    try:
        playwright_patch = _apply_playwright_pageerror_patch(required=True)
        from camoufox_reverse_mcp.browser import _camoufox_debug
        debug = _camoufox_debug
        import camoufox_reverse_mcp.browser as browser_module
        import camoufox_reverse_mcp._playwright_patch as playwright_patch_module
        import camoufox_reverse_mcp.tools.navigation as navigation_module
        import camoufox_reverse_mcp.tools.network as network_module
        pageerror_patch_marker = getattr(playwright_patch_module, "AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID", "")
        patch_marker = getattr(browser_module, "AIDA_CAMOUFOX_BRIDGE_PATCH_ID", "")
        addon_policy_marker = getattr(browser_module, "AIDA_DEFAULT_ADDON_POLICY_MARKER", "")
        launch_code = getattr(browser_module.BrowserManager.launch, "__code__", None)
        launch_consts = repr(getattr(launch_code, "co_consts", ()))
        launch_names = repr(getattr(launch_code, "co_names", ()))
        launch_options_code = getattr(getattr(browser_module, "_build_camoufox_launch_options", None), "__code__", None)
        addon_policy_code = getattr(getattr(browser_module, "_apply_default_addon_policy", None), "__code__", None)
        addon_exception_code = getattr(getattr(browser_module, "_addon_exception_matches", None), "__code__", None)
        addon_policy_contract = (
            repr(addon_policy_marker) +
            repr(getattr(launch_options_code, "co_consts", ())) +
            repr(getattr(launch_options_code, "co_names", ())) +
            repr(getattr(launch_options_code, "co_varnames", ())) +
            repr(getattr(addon_policy_code, "co_consts", ())) +
            repr(getattr(addon_policy_code, "co_names", ())) +
            repr(getattr(addon_policy_code, "co_varnames", ())) +
            repr(getattr(addon_exception_code, "co_consts", ())) +
            repr(getattr(addon_exception_code, "co_names", ())) +
            repr(getattr(addon_exception_code, "co_varnames", ()))
        )
        privacy_verify_code = getattr(getattr(browser_module, "_verify_page_privacy", None), "__code__", None)
        privacy_verify_consts = repr(getattr(privacy_verify_code, "co_consts", ()))
        browser_recovery_consts = (
            repr(getattr(getattr(browser_module.BrowserManager.new_page, "__code__", None), "co_consts", ())) +
            repr(getattr(getattr(browser_module.BrowserManager.resolve_page, "__code__", None), "co_consts", ())) +
            repr(getattr(getattr(browser_module.BrowserManager._requested_page_id_blocker, "__code__", None), "co_consts", ())) +
            repr(getattr(getattr(browser_module.BrowserManager._attach_listeners, "__code__", None), "co_consts", ())) +
            repr(getattr(getattr(browser_module.BrowserManager._mark_page_terminal, "__code__", None), "co_consts", ()))
        )
        navigation_consts = repr(getattr(getattr(navigation_module.navigate, "__code__", None), "co_consts", ()))
        launch_browser_consts = (
            repr(getattr(getattr(navigation_module.launch_browser, "__code__", None), "co_consts", ())) +
            repr(getattr(getattr(navigation_module.launch_browser, "__code__", None), "co_names", ()))
        )
        network_consts = repr(getattr(getattr(network_module.list_network_requests, "__code__", None), "co_consts", ()))
        if pageerror_patch_marker != "aida_playwright_pageerror_location_patch_20260620_1":
            raise RuntimeError(f"frozen Playwright pageError patch marker mismatch: {pageerror_patch_marker!r}")
        if patch_marker != "aida_camoufox_bridge_20260620_crash_diag_1":
            raise RuntimeError(f"frozen browser patch marker mismatch: {patch_marker!r}")
        if addon_policy_marker != "aida_default_addon_policy_v1":
            raise RuntimeError(f"frozen addon policy marker mismatch: {addon_policy_marker!r}")
        if "aida_bridge_patch_active" not in launch_consts or "aida_launch_policy_resolved" not in launch_consts:
            raise RuntimeError("frozen browser launch diagnostics missing")
        if "AIDA_CAMOUFOX_BRIDGE_PATCH_ID" not in launch_names:
            raise RuntimeError("frozen browser launch patch marker missing")
        for marker in ("aida_default_addon_policy_v1", "DefaultAddons.UBO", "exclude_addons", "launch_options_addon_policy", "launch_options_addon_invalid", "default_exclusion_scope", "all_launches", "explicit_addons_validated"):
            if marker not in addon_policy_contract:
                raise RuntimeError(f"frozen addon policy contract marker missing: {marker}")
        for marker in ("launch_new_page_task_result",):
            if marker not in launch_consts:
                raise RuntimeError(f"frozen browser launch marker missing: {marker}")
        for marker in ("privacy_verify_begin", "privacy_verify_probe_begin", "privacy_verify_exception"):
            if marker not in privacy_verify_consts:
                raise RuntimeError(f"frozen browser privacy marker missing: {marker}")
        if not hasattr(browser_module.BrowserManager, "last_launch_failure_payload"):
            raise RuntimeError("frozen browser launch failure payload marker missing")
        for marker in ("browser_page_id_unavailable", "resolve_page_default_recovery_begin", "page_closed_during_launch", "requestfinished", "websocket"):
            if marker not in browser_recovery_consts:
                raise RuntimeError(f"frozen browser recovery marker missing: {marker}")
        for marker in ("launch_browser_tool_exception", "last_launch_failure_payload"):
            if marker not in launch_browser_consts:
                raise RuntimeError(f"frozen launch_browser diagnostic marker missing: {marker}")
        for marker in ("bloxflip_navigation_state", "diagnostic_navigation_goto_exception", "network_capture"):
            if marker not in navigation_consts:
                raise RuntimeError(f"frozen navigation diagnostic marker missing: {marker}")
        for marker in ("request_id", "network_request_id", "redirect_chain", "response_body_length", "request_body_length", "websocket", "timing", "initiator"):
            if marker not in network_consts:
                raise RuntimeError(f"frozen network capture marker missing: {marker}")
        debug(
            "import_smoke_begin",
            cwd=os.getcwd(),
            python=sys.executable,
            env_browser=bool(os.environ.get("AIDA_CAMOUFOX_EXECUTABLE")),
            patch_marker=patch_marker,
            pageerror_patch_marker=pageerror_patch_marker,
            pageerror_patch=playwright_patch,
        )
        import_started = time.perf_counter()
        from camoufox.addons import DefaultAddons
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
        direct_kwargs = dict(kwargs)
        direct_kwargs["exclude_addons"] = [DefaultAddons.UBO]
        options = launch_options(**direct_kwargs)
        builder_options = browser_module._build_camoufox_launch_options(True, dict(kwargs))
        addon_policy = dict(getattr(browser_module, "_LAST_ADDON_POLICY", {}) or {})
        if not addon_policy.get("default_addons_excluded") or not addon_policy.get("exclude_default_ubo"):
            raise RuntimeError(f"addon policy exclusion was not applied: {addon_policy}")
        if addon_policy.get("default_exclusion_scope") != "all_launches":
            raise RuntimeError(f"addon policy exclusion scope is stale: {addon_policy}")
        builder_addons = builder_options.get("addons") if isinstance(builder_options, dict) else []
        debug(
            "import_smoke_launch_options_ok",
            elapsed_ms=int((time.perf_counter() - options_started) * 1000),
            total_ms=int((time.perf_counter() - started) * 1000),
            has_executable=bool(options.get("executable_path")),
            args=len(options.get("args") or []),
            env_keys=len(options.get("env") or {}),
            direct_exclude_default_ubo=True,
            builder_args=len(builder_options.get("args") or []) if isinstance(builder_options, dict) else 0,
            builder_env_keys=len(builder_options.get("env") or {}) if isinstance(builder_options, dict) else 0,
            builder_addon_count=len(builder_addons) if isinstance(builder_addons, (list, tuple)) else (1 if builder_addons else 0),
            default_addons_excluded=bool(addon_policy.get("default_addons_excluded")),
            exclude_default_ubo=bool(addon_policy.get("exclude_default_ubo")),
            explicit_addon_count=int(addon_policy.get("explicit_addon_count") or 0),
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
    playwright_patch = _apply_playwright_pageerror_patch(required=True)
    from camoufox_reverse_mcp.browser import _await_no_cancel_wait, _camoufox_debug
    from camoufox_reverse_mcp.server import browser_manager
    executable = os.environ.get("AIDA_CAMOUFOX_EXECUTABLE", "")
    if executable:
        executable = os.path.abspath(os.path.expandvars(os.path.expanduser(executable)))
    if not executable or not os.path.isfile(executable):
        raise FileNotFoundError(f"Camoufox executable is not available: {executable}")
    timeout_ms = _int_env("AIDA_CAMOUFOX_LIVE_SMOKE_TIMEOUT_MS", 75000)
    config = {
        "headless": False,
        "executable_path": executable,
        "ff_version": _int_env("AIDA_CAMOUFOX_FF_VERSION", 135),
        "launch_timeout_ms": timeout_ms,
        "aida_testlab_fast_probe": False,
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
        pageerror_patch=playwright_patch,
    )
    try:
        launch = await browser_manager.launch(config)
        if launch.get("status") not in ("launched", "already_running"):
            raise RuntimeError(f"launch_status={launch.get('status')} payload={launch}")
        diagnostics = launch.get("diagnostics") if isinstance(launch, dict) else {}
        if not isinstance(diagnostics, dict):
            diagnostics = {}
        browser_ready_ms = int(diagnostics.get("browser_ready_ms") or launch.get("browser_ready_ms") or 0)
        camoufox_launch_ms = int(diagnostics.get("camoufox_launch_ms") or launch.get("camoufox_launch_ms") or browser_ready_ms)
        launch_elapsed_ms = int(diagnostics.get("elapsed_ms") or 0)
        privacy = diagnostics.get("privacy") if isinstance(diagnostics.get("privacy"), dict) else {}
        launch_budget_ms = max(45000, min(timeout_ms, 90000))
        if camoufox_launch_ms <= 0 or camoufox_launch_ms > launch_budget_ms:
            raise RuntimeError(f"camoufox_launch_ms={camoufox_launch_ms} exceeds {launch_budget_ms}")
        if launch_elapsed_ms <= 0 or launch_elapsed_ms > timeout_ms:
            raise RuntimeError(f"launch_elapsed_ms={launch_elapsed_ms} exceeds {timeout_ms}")
        if not privacy.get("webrtc_blocked") or not privacy.get("ice_probe_ok") or privacy.get("ice_candidate_leak_detected"):
            raise RuntimeError(f"webrtc privacy proof failed: {privacy}")
        if privacy.get("context_source") == "fast_visible_firefox":
            raise RuntimeError(f"unexpected fast visible launch path: {privacy}")
        if privacy.get("effective_ua_policy") not in (None, "", "camoufox_native"):
            raise RuntimeError(f"unexpected native launch ua policy: {privacy}")
        if privacy.get("ua_override"):
            raise RuntimeError(f"unexpected native launch ua override: {privacy}")
        if privacy.get("ua_override") and not (
            privacy.get("ua_ok") and privacy.get("app_version_ok") and privacy.get("platform_ok") and privacy.get("oscpu_ok")
        ):
            raise RuntimeError(f"ua privacy proof failed: {privacy}")
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
    playwright_patch = _apply_playwright_pageerror_patch(required=False)
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
            pageerror_patch=playwright_patch,
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
    if "--aida-contract-check" in sys.argv:
        raise SystemExit(_run_contract_check())
    if _env_truthy("AIDA_CAMOUFOX_IMPORT_SMOKE"):
        raise SystemExit(_run_import_smoke())
    if _env_truthy("AIDA_CAMOUFOX_LIVE_SMOKE"):
        raise SystemExit(_run_live_smoke())
    _preload_camoufox()
    from camoufox_reverse_mcp.__main__ import main
    raise SystemExit(main())
'@ | Set-Content -LiteralPath $entry -Encoding UTF8
    if ($selectedBackend -eq "pyinstaller") {
        $pyiWork = Join-Path $workRoot "pyinstaller-work"
        $pyiSpec = Join-Path $workRoot "pyinstaller-spec"
        $pyiHooks = Join-Path $workRoot "pyinstaller-hooks"
        New-Item -ItemType Directory -Force -Path $pyiHooks | Out-Null
        @'
from PyInstaller.utils.hooks import collect_all

def _filter(name):
    return name != "camoufox.gui" and not name.startswith("camoufox.gui.")

datas, binaries, hiddenimports = collect_all("camoufox", filter_submodules=_filter, on_error="ignore")
'@ | Set-Content -LiteralPath (Join-Path $pyiHooks "hook-camoufox.py") -Encoding UTF8
        @'
from PyInstaller.utils.hooks import collect_all

def _filter(name):
    blocked = "browserforge.injectors.undetected_playwright"
    return name != blocked and not name.startswith(blocked + ".")

datas, binaries, hiddenimports = collect_all("browserforge", filter_submodules=_filter, on_error="ignore")
'@ | Set-Content -LiteralPath (Join-Path $pyiHooks "hook-browserforge.py") -Encoding UTF8
        $pyiBuildLog = Join-Path $workRoot "pyinstaller-build.stdout.log"
        $pyiErrorLog = Join-Path $workRoot "pyinstaller-build.stderr.log"
        $pyiArgs = @(
            "-m", "PyInstaller",
            "--noconfirm",
            "--clean",
            "--log-level", "ERROR",
            "--console",
            "--noupx",
            "--onefile",
            "--name", "AiDA_CamoufoxReverseMcp",
            "--distpath", $OutputDir,
            "--workpath", $pyiWork,
            "--specpath", $pyiSpec,
            "--additional-hooks-dir", $pyiHooks,
            "--collect-all", "camoufox_reverse_mcp",
            "--collect-all", "apify_fingerprint_datapoints",
            "--collect-all", "language_tags",
            "--collect-all", "ua_parser",
            "--collect-all", "ua_parser_builtins",
            "--collect-submodules", "playwright",
            "--collect-data", "playwright",
            "--collect-all", "esprima",
            "--exclude-module", "camoufox.gui",
            "--exclude-module", "PySide6",
            "--exclude-module", "browserforge.injectors.undetected_playwright",
            "--exclude-module", "undetected_playwright",
            "--hidden-import", "mcp.server.fastmcp",
            "--hidden-import", "mcp.server.stdio",
            "--hidden-import", "mcp.shared.session",
            "--hidden-import", "mcp.shared.message",
            "--hidden-import", "mcp.types",
            "--hidden-import", "browserforge.fingerprints",
            "--hidden-import", "browserforge.headers",
            "--hidden-import", "apify_fingerprint_datapoints",
            "--hidden-import", "language_tags",
            "--hidden-import", "ua_parser",
            "--hidden-import", "ua_parser_builtins",
            $entry
        )
        $pyiProcess = Start-Process -FilePath $venvPython -ArgumentList $pyiArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $pyiBuildLog -RedirectStandardError $pyiErrorLog
        $pyiExitCode = $pyiProcess.ExitCode
        Write-Output "pyinstaller_exit_code=$pyiExitCode"
        Write-Output "pyinstaller_build_log=$pyiBuildLog"
        Write-Output "pyinstaller_stderr_log=$pyiErrorLog"
        if ($pyiExitCode -ne 0) {
            if (Test-Path -LiteralPath $pyiBuildLog) {
                Get-Content -LiteralPath $pyiBuildLog
            }
            if (Test-Path -LiteralPath $pyiErrorLog) {
                Get-Content -LiteralPath $pyiErrorLog
            }
            throw "PyInstaller build failed"
        }
        $built = Join-Path $OutputDir "AiDA_CamoufoxReverseMcp.exe"
        if (-not [IO.File]::Exists($built)) { throw "PyInstaller onefile output executable was not produced" }
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        Copy-Item -LiteralPath $built -Destination $target -Force
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
    if (-not [IO.File]::Exists($target)) { throw "Frozen executable was not produced at $target" }
    Assert-FrozenMcpCustomerSafeExecutable $target
    Copy-Item -LiteralPath $target -Destination $flatTarget -Force
    Invoke-FrozenMcpSmoke -Executable $target -RepoRoot $repoRoot
    Copy-Item -LiteralPath $target -Destination $flatTarget -Force
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $target).Length
    $flatHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $flatTarget).Hash.ToLowerInvariant()
    $flatSize = (Get-Item -LiteralPath $flatTarget).Length
    Write-Output "frozen_mcp_backend=$selectedBackend"
    Write-Output "frozen_mcp_built=$target"
    Write-Output "frozen_mcp_size=$size"
    Write-Output "frozen_mcp_sha256=$hash"
    Write-Output "frozen_mcp_flat=$flatTarget"
    Write-Output "frozen_mcp_flat_size=$flatSize"
    Write-Output "frozen_mcp_flat_sha256=$flatHash"
} finally {
    if ([IO.Directory]::Exists($workRoot)) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
