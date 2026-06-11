[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$BuildDir,
    [switch]$SkipArc,
    [switch]$SkipStandalone,
    [switch]$SkipCamoufoxSidecar,
    [switch]$Camoufox,
    [switch]$Force,
    [switch]$PlanOnly,
    [string]$PublicBaseUrl = "https://api.aidapro.net",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$publishCamoufoxMcpPatch = $Camoufox.IsPresent
foreach ($arg in @($ExtraArgs)) {
    if ([string]::Equals($arg, "--camoufox", [StringComparison]::OrdinalIgnoreCase)) {
        $publishCamoufoxMcpPatch = $true
    } elseif (-not [string]::IsNullOrWhiteSpace($arg)) {
        throw "Unknown argument: $arg"
    }
}
if ($publishCamoufoxMcpPatch -and $SkipCamoufoxSidecar.IsPresent) {
    throw "Use either --camoufox/-Camoufox or -SkipCamoufoxSidecar, not both."
}
if (-not $publishCamoufoxMcpPatch) {
    $SkipCamoufoxSidecar = [switch]::Present
}

$RepoRoot = $PSScriptRoot
$Server = "ruarr@23.88.62.199"
$SshKey = Join-Path $env:USERPROFILE ".ssh\aida_server"
$RemoteRoot = "/home/ruarr/aida-server"
$RemoteArcPath = "$RemoteRoot/arc/aida_core.bin"
$RemoteArcShaPath = "$RemoteRoot/arc/aida_core.sha256"
$RemoteArtifactDir = "$RemoteRoot/bootstrap_artifacts"
$SshOptions = @("-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no", "-i", $SshKey)

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Stop-Deploy([string]$Message) {
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
    exit 1
}

function ConvertTo-RemoteShellLiteral([string]$Value) {
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "'\''") + "'"
}

function Get-ReleaseDir {
    if ($BuildDir) {
        if (-not (Test-Path -LiteralPath $BuildDir -PathType Container)) {
            Stop-Deploy "BuildDir does not exist: $BuildDir"
        }
        return (Resolve-Path -LiteralPath $BuildDir).Path
    }
    $ninja = Join-Path $RepoRoot "build-ninja"
    if (Test-Path -LiteralPath $ninja -PathType Container) {
        return (Resolve-Path -LiteralPath $ninja).Path
    }
    $release = Join-Path $RepoRoot "build\Release"
    if (Test-Path -LiteralPath $release -PathType Container) {
        return (Resolve-Path -LiteralPath $release).Path
    }
    Stop-Deploy "No build output directory found. Run .\build-host.cmd first or pass -BuildDir."
}

function Invoke-CheckedNative([string]$FilePath, [string[]]$Arguments, [string]$FailureMessage) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Deploy $FailureMessage
    }
}

function Invoke-Remote([string]$Command) {
    $output = & ssh @SshOptions $Server $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        Stop-Deploy ("Remote command failed.`nCommand: {0}`n{1}" -f $Command, ($output -join "`n"))
    }
    return $output
}

function Invoke-RemoteSoft([string]$Command) {
    $output = & ssh @SshOptions $Server $Command 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Invoke-RemoteBash([string]$Script) {
    $normalized = ($Script -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not $normalized.EndsWith("`n", [StringComparison]::Ordinal)) {
        $normalized += "`n"
    }
    $id = [Guid]::NewGuid().ToString("N")
    $local = Join-Path ([IO.Path]::GetTempPath()) "aida_remote_$id.sh"
    $remote = "/tmp/aida_remote_$id.sh"
    try {
        [IO.File]::WriteAllText($local, $normalized, [Text.UTF8Encoding]::new($false))
        Copy-ToRemote $local $remote
        $remoteLit = ConvertTo-RemoteShellLiteral $remote
        $output = & ssh @SshOptions $Server "bash $remoteLit; rc=`$?; rm -f $remoteLit; exit `$rc" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Stop-Deploy ("Remote bash script failed.`n{0}" -f ($output -join "`n"))
        }
        return $output
    } finally {
        try { if (Test-Path -LiteralPath $local) { Remove-Item -LiteralPath $local -Force } } catch { }
    }
}

function Invoke-RemoteBashSoft([string]$Script) {
    $normalized = ($Script -replace "`r`n", "`n") -replace "`r", "`n"
    if (-not $normalized.EndsWith("`n", [StringComparison]::Ordinal)) {
        $normalized += "`n"
    }
    $id = [Guid]::NewGuid().ToString("N")
    $local = Join-Path ([IO.Path]::GetTempPath()) "aida_remote_$id.sh"
    $remote = "/tmp/aida_remote_$id.sh"
    try {
        [IO.File]::WriteAllText($local, $normalized, [Text.UTF8Encoding]::new($false))
        $args = @($SshOptions + @($local, "${Server}:$remote"))
        & scp @args | Out-Null
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = @("SCP upload failed for remote bash script") }
        }
        $remoteLit = ConvertTo-RemoteShellLiteral $remote
        $output = & ssh @SshOptions $Server "bash $remoteLit; rc=`$?; rm -f $remoteLit; exit `$rc" 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } finally {
        try { if (Test-Path -LiteralPath $local) { Remove-Item -LiteralPath $local -Force } } catch { }
    }
}

function Copy-ToRemote([string]$LocalPath, [string]$RemotePath) {
    $args = @($SshOptions + @($LocalPath, "${Server}:$RemotePath"))
    Invoke-CheckedNative "scp" $args "SCP upload failed: $LocalPath -> $RemotePath"
}

function Get-FileSha256Lower([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-RemoteEnvMap {
    $script = @'
set -e
cd /home/ruarr/aida-server
if [ -f .env ]; then
  awk -F= '/^AIDA_BOOTSTRAP_ARTIFACT_URL=|^AIDA_BOOTSTRAP_ARTIFACT_SHA256=|^AIDA_BOOTSTRAP_ARTIFACT_VERSION=|^AIDA_BOOTSTRAP_ARTIFACT_SIZE=|^AIDA_BOOTSTRAP_PACKAGE_SHA256=|^AIDA_BOOTSTRAP_PACKAGE_SIZE=|^AIDA_BOOTSTRAP_ARTIFACT_FORMAT=|^AIDA_CAMOUFOX_SIDECAR_URL=|^AIDA_CAMOUFOX_SIDECAR_SHA256=|^AIDA_CAMOUFOX_SIDECAR_VERSION=|^AIDA_CAMOUFOX_SIDECAR_SIZE=|^AIDA_CAMOUFOX_SIDECAR_EXE_REL=|^AIDA_CAMOUFOX_SIDECAR_PYTHON_REL=|^AIDA_CAMOUFOX_MCP_URL=|^AIDA_CAMOUFOX_MCP_SHA256=|^AIDA_CAMOUFOX_MCP_VERSION=|^AIDA_CAMOUFOX_MCP_SIZE=|^AIDA_CAMOUFOX_MCP_REL=/{print}' .env
fi
'@
    $lines = Invoke-RemoteBash $script
    $map = @{}
    foreach ($line in $lines) {
        $text = [string]$line
        $idx = $text.IndexOf("=")
        if ($idx -gt 0) {
            $map[$text.Substring(0, $idx)] = $text.Substring($idx + 1)
        }
    }
    return $map
}

function Get-RemoteArcSha {
    $cmd = "if [ -f " + (ConvertTo-RemoteShellLiteral $RemoteArcShaPath) + " ]; then cat " + (ConvertTo-RemoteShellLiteral $RemoteArcShaPath) + "; fi"
    $result = Invoke-RemoteSoft $cmd
    if ($result.ExitCode -ne 0 -or -not $result.Output) { return "" }
    return (([string]($result.Output | Select-Object -First 1)).Trim()).ToLowerInvariant()
}

function Find-FirstExistingPath([string[]]$Candidates, [switch]$Directory) {
    foreach ($candidate in $Candidates) {
        if (-not $candidate) { continue }
        if ($Directory) {
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        } else {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }
    return ""
}

function Sync-RemoteDeployScripts {
    Write-Step "Syncing remote deploy helpers"
    if ($PlanOnly) {
        Write-Ok "Plan only: would upload server/scripts/encrypt-arc.js and create_bootstrap_package.js"
        return
    }
    Invoke-Remote ("mkdir -p " + (ConvertTo-RemoteShellLiteral "$RemoteRoot/scripts") + " " + (ConvertTo-RemoteShellLiteral $RemoteArtifactDir) + " " + (ConvertTo-RemoteShellLiteral "$RemoteRoot/arc"))
    Copy-ToRemote (Join-Path $RepoRoot "server\scripts\encrypt-arc.js") "$RemoteRoot/scripts/encrypt-arc.js"
    Copy-ToRemote (Join-Path $RepoRoot "server\scripts\create_bootstrap_package.js") "$RemoteRoot/scripts/create_bootstrap_package.js"
    Write-Ok "Remote helper scripts synced"
}

function Publish-Arc([string]$ArcDllPath, [string]$DeployId) {
    if ($SkipArc) {
        Write-Warn "Skipping ARC publish because -SkipArc was specified"
        return $false
    }
    if (-not (Test-Path -LiteralPath $ArcDllPath -PathType Leaf)) {
        Stop-Deploy "aida_core.dll not found: $ArcDllPath"
    }
    $localSha = Get-FileSha256Lower $ArcDllPath
    $remoteSha = Get-RemoteArcSha
    if (-not $Force -and $remoteSha -eq $localSha) {
        Write-Ok "ARC unchanged: $localSha"
        return $false
    }

    Write-Step "Publishing ARC blob"
    if ($PlanOnly) {
        Write-Ok "Plan only: would encrypt and upload ARC for aida_core.dll sha256=$localSha"
        return $true
    }

    $remoteDll = "/tmp/aida_core_$DeployId.dll"
    $remoteBin = "/tmp/aida_core_$DeployId.bin"
    Copy-ToRemote $ArcDllPath $remoteDll
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
set -a
. ./.env
set +a
if [ -z "${ARC_MASTER_SECRET:-}" ]; then
  echo "ARC_MASTER_SECRET is not configured on the server" >&2
  rm -f '__REMOTE_DLL__' '__REMOTE_BIN__'
  exit 1
fi
node scripts/encrypt-arc.js '__REMOTE_DLL__' '__REMOTE_BIN__'
install -m 600 '__REMOTE_BIN__' '/home/ruarr/aida-server/arc/aida_core.bin'
sha256sum '__REMOTE_DLL__' | awk '{print $1}' > '/home/ruarr/aida-server/arc/aida_core.sha256'
chmod 600 '/home/ruarr/aida-server/arc/aida_core.sha256'
rm -f '__REMOTE_DLL__' '__REMOTE_BIN__'
stat -c 'arc_size=%s' '/home/ruarr/aida-server/arc/aida_core.bin'
'@
    $script = $script.Replace("__REMOTE_DLL__", $remoteDll).Replace("__REMOTE_BIN__", $remoteBin)
    $output = Invoke-RemoteBash $script
    $remoteShaAfter = Get-RemoteArcSha
    if ($remoteShaAfter -ne $localSha) {
        Stop-Deploy "ARC remote SHA marker mismatch after publish"
    }
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match "^arc_size=" -or $text -match "^Encrypted " -or $text -match "SHA-256 of plaintext") {
            Write-Host "  $text"
        }
    }
    Write-Ok "ARC published sha256=$localSha"
    return $true
}

function Publish-StandalonePackage([string]$StandalonePath, [string]$DeployId, [hashtable]$RemoteEnv) {
    if ($SkipStandalone) {
        Write-Warn "Skipping standalone package publish because -SkipStandalone was specified"
        return [pscustomobject]@{ Changed = $false; Url = ""; PackageName = ""; PlainSha = ""; PackageSha = ""; PlainSize = 0; PackageSize = 0; Version = "" }
    }
    if (-not (Test-Path -LiteralPath $StandalonePath -PathType Leaf)) {
        Stop-Deploy "AiDAStandalone.exe not found: $StandalonePath"
    }

    $plainSha = Get-FileSha256Lower $StandalonePath
    $plainSize = (Get-Item -LiteralPath $StandalonePath).Length
    $currentSha = if ($RemoteEnv.ContainsKey("AIDA_BOOTSTRAP_ARTIFACT_SHA256")) { ([string]$RemoteEnv["AIDA_BOOTSTRAP_ARTIFACT_SHA256"]).ToLowerInvariant() } else { "" }
    $currentSize = if ($RemoteEnv.ContainsKey("AIDA_BOOTSTRAP_ARTIFACT_SIZE")) { [string]$RemoteEnv["AIDA_BOOTSTRAP_ARTIFACT_SIZE"] } else { "" }
    if (-not $Force -and $currentSha -eq $plainSha -and $currentSize -eq [string]$plainSize) {
        $currentUrl = if ($RemoteEnv.ContainsKey("AIDA_BOOTSTRAP_ARTIFACT_URL")) { [string]$RemoteEnv["AIDA_BOOTSTRAP_ARTIFACT_URL"] } else { "" }
        $artifactLive = $false
        if ($currentUrl) {
            $urlLit = ConvertTo-RemoteShellLiteral $currentUrl
            $probe = Invoke-RemoteSoft "curl -s -r 0-0 -o /dev/null -w '%{http_code}' $urlLit || echo 000"
            $status = if ($probe.Output) { ([string]($probe.Output | Select-Object -First 1)).Trim() } else { "" }
            $artifactLive = $probe.ExitCode -eq 0 -and ($status -eq "200" -or $status -eq "206")
        }
        if ($artifactLive) {
            Write-Ok "Standalone package unchanged: $plainSha"
            return [pscustomobject]@{ Changed = $false; Url = $currentUrl; PackageName = [IO.Path]::GetFileName($currentUrl); PlainSha = $plainSha; PackageSha = ""; PlainSize = $plainSize; PackageSize = 0; Version = ""; }
        }
        Write-Warn "Standalone metadata matches local binary, but the package URL is not live; republishing"
    }

    Write-Step "Publishing fileless AiDAStandalone package"
    $version = (Get-Date -Format "yyyyMMddHHmmss")
    $packageName = "AiDAStandalone-$($version.Substring(0, 8))-$($version.Substring(8, 6)).pkg"
    $artifactUrl = ($PublicBaseUrl.TrimEnd("/")) + "/bootstrap-artifacts/" + $packageName

    if ($PlanOnly) {
        Write-Ok "Plan only: would create $packageName for AiDAStandalone.exe sha256=$plainSha size=$plainSize"
        return [pscustomobject]@{ Changed = $true; Url = $artifactUrl; PackageName = $packageName; PlainSha = $plainSha; PackageSha = ""; PlainSize = $plainSize; PackageSize = 0; Version = $version }
    }

    $remoteExe = "/tmp/AiDAStandalone_$DeployId.exe"
    $remotePkg = "$RemoteArtifactDir/$packageName"
    Copy-ToRemote $StandalonePath $remoteExe
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
set -a
. ./.env
set +a
if [ -z "${AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64:-}" ] || [ -z "${AIDA_BOOTSTRAP_PACKAGE_MAC_KEY_B64:-}" ]; then
  echo "Bootstrap package keys are not configured on the server" >&2
  rm -f '__REMOTE_EXE__'
  exit 1
fi
node scripts/create_bootstrap_package.js --input '__REMOTE_EXE__' --output '__REMOTE_PKG__'
rc=$?
rm -f '__REMOTE_EXE__'
exit $rc
'@
    $script = $script.Replace("__REMOTE_EXE__", $remoteExe).Replace("__REMOTE_PKG__", $remotePkg)
    $output = Invoke-RemoteBash $script
    $json = ($output | Where-Object { ([string]$_).TrimStart().StartsWith("{") } | Select-Object -Last 1)
    if (-not $json) {
        Stop-Deploy "Package generation did not return JSON metadata"
    }
    $metadata = $json | ConvertFrom-Json
    if ([string]$metadata.plaintext_sha256 -ne $plainSha -or [int64]$metadata.plaintext_size -ne [int64]$plainSize) {
        Stop-Deploy "Package metadata does not match local AiDAStandalone.exe"
    }
    Write-Ok ("Package created: {0} plaintext_sha256={1} package_sha256={2}" -f $packageName, $metadata.plaintext_sha256, $metadata.package_sha256)
    return [pscustomobject]@{
        Changed = $true
        Url = $artifactUrl
        PackageName = $packageName
        PlainSha = [string]$metadata.plaintext_sha256
        PackageSha = [string]$metadata.package_sha256
        PlainSize = [int64]$metadata.plaintext_size
        PackageSize = [int64]$metadata.package_size
        Version = $version
    }
}

function Get-CamoufoxSidecarInputs([string]$ReleaseDir) {
    $browserName = "camoufox-135.0.1-beta.24-win.x86_64"
    $browser = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "deps\$browserName"),
        (Join-Path $RepoRoot $browserName),
        (Join-Path $RepoRoot ".deps\$browserName")
    ) -Directory
    $mcp = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "deps\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $ReleaseDir "deps\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot ".deps\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot ".deps\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp\dist\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp\dist\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot "AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp.exe")
    )
    return [pscustomobject]@{
        BrowserName = $browserName
        BrowserDir = $browser
        BrowserExe = if ($browser) { Join-Path $browser "camoufox.exe" } else { "" }
        McpExe = $mcp
        ExeRel = "deps/$browserName/camoufox.exe"
        PythonRel = ""
    }
}

function Assert-CamoufoxMcpPatchInputs([pscustomobject]$Inputs) {
    if (-not $Inputs.McpExe -or -not (Test-Path -LiteralPath $Inputs.McpExe -PathType Leaf)) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable is missing. Build .deps\AiDA_CamoufoxReverseMcp.exe first."
    }
    $size = (Get-Item -LiteralPath $Inputs.McpExe).Length
    if ($size -le 0 -or $size -gt 268435456) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable size is invalid: $size bytes"
    }
}

function Assert-NoReverseMcpSourceLeak([string]$StageRoot) {
    $blocked = Get-ChildItem -LiteralPath $StageRoot -Recurse -Force -File -ErrorAction Stop | Where-Object {
        $rel = $_.FullName.Substring($StageRoot.Length).TrimStart("\", "/")
        ($rel -match '(^|[\\/])camoufox-reverse-mcp([\\/]|$)') -or
        ($rel -match '(^|[\\/])camoufox_reverse_mcp([\\/]|$)') -or
        ($rel -match '\.(py|pyc|pyo|pyd|whl)$' -and $rel -match 'camoufox[_-]reverse[_-]mcp')
    } | Select-Object -First 1
    if ($blocked) {
        Stop-Deploy "Refusing to package Camoufox sidecar because reverse-MCP source-like content was staged: $($blocked.FullName)"
    }
}

function Publish-CamoufoxMcpPatch([string]$ReleaseDir, [string]$DeployId, [hashtable]$RemoteEnv) {
    if ($SkipCamoufoxSidecar) {
        Write-Warn "Skipping Camoufox MCP patch publish; pass --camoufox or -Camoufox to publish only the frozen MCP executable"
        return [pscustomobject]@{ Changed = $false; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = ""; ExeRel = ""; PythonRel = ""; McpUrl = ""; McpPackageName = ""; McpSha = ""; McpSize = 0; McpRel = "" }
    }

    $inputs = Get-CamoufoxSidecarInputs $ReleaseDir
    Assert-CamoufoxMcpPatchInputs $inputs
    $mcpSha = Get-FileSha256Lower $inputs.McpExe
    $mcpSize = (Get-Item -LiteralPath $inputs.McpExe).Length
    $mcpRel = "deps/AiDA_CamoufoxReverseMcp.exe"
    $currentSha = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_SHA256")) { ([string]$RemoteEnv["AIDA_CAMOUFOX_MCP_SHA256"]).ToLowerInvariant() } else { "" }
    $currentSize = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_SIZE")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_SIZE"] } else { "" }
    $currentMcpRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_REL"] } else { "" }
    $currentExeRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_EXE_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_EXE_REL"] } else { "" }
    $currentPythonRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_PYTHON_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_PYTHON_REL"] } else { "" }
    $metadataCurrent = $currentMcpRel -eq $mcpRel -and $currentExeRel -eq $inputs.ExeRel -and $currentPythonRel -eq $inputs.PythonRel
    if (-not $Force -and $currentSha -eq $mcpSha -and $currentSize -eq [string]$mcpSize) {
        $currentUrl = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_URL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_URL"] } else { "" }
        $mcpLive = $false
        if ($currentUrl) {
            $urlLit = ConvertTo-RemoteShellLiteral $currentUrl
            $probe = Invoke-RemoteSoft "curl -s -r 0-0 -o /dev/null -w '%{http_code}' $urlLit || echo 000"
            $status = if ($probe.Output) { ([string]($probe.Output | Select-Object -First 1)).Trim() } else { "" }
            $mcpLive = $probe.ExitCode -eq 0 -and ($status -eq "200" -or $status -eq "206")
        }
        if ($mcpLive) {
            if (-not $metadataCurrent) {
                $currentVersion = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_VERSION")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_VERSION"] } else { (Get-Date -Format "yyyyMMddHHmmss") }
                Write-Warn "Camoufox MCP executable unchanged; repairing slash-safe bootstrap metadata"
                return [pscustomobject]@{ Changed = $true; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = $currentVersion; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $currentUrl; McpPackageName = [IO.Path]::GetFileName($currentUrl); McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
            }
            Write-Ok "Camoufox MCP patch unchanged: $mcpSha"
            return [pscustomobject]@{ Changed = $false; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = ""; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $currentUrl; McpPackageName = [IO.Path]::GetFileName($currentUrl); McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
        }
        Write-Warn "Camoufox MCP metadata matches local executable, but the patch URL is not live; republishing"
    }

    Write-Step "Publishing Camoufox MCP patch"
    $version = (Get-Date -Format "yyyyMMddHHmmss")
    $mcpName = "AiDA_CamoufoxReverseMcp-$($version.Substring(0, 8))-$($version.Substring(8, 6)).exe"
    $mcpUrl = ($PublicBaseUrl.TrimEnd("/")) + "/bootstrap-artifacts/" + $mcpName

    if ($PlanOnly) {
        Write-Ok "Plan only: would upload $mcpName from mcp=$($inputs.McpExe) sha256=$mcpSha size=$mcpSize"
        return [pscustomobject]@{ Changed = $true; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = $version; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $mcpUrl; McpPackageName = $mcpName; McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
    }

    Copy-ToRemote $inputs.McpExe "$RemoteArtifactDir/$mcpName"
    Write-Ok "Camoufox MCP patch uploaded: $mcpName sha256=$mcpSha size=$mcpSize"
    return [pscustomobject]@{ Changed = $true; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = $version; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $mcpUrl; McpPackageName = $mcpName; McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
}

function Update-BootstrapMetadata([pscustomobject]$Package) {
    if (-not $Package.Changed) { return $false }
    Write-Step "Updating bootstrap artifact metadata"
    if ($PlanOnly) {
        Write-Ok "Plan only: would update bootstrap metadata to $($Package.Url)"
        return $true
    }
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
cp .env ".env.bak.__VERSION__"
AIDA_NEW_ARTIFACT_URL='__URL__' AIDA_NEW_ARTIFACT_SHA256='__PLAIN_SHA__' AIDA_NEW_ARTIFACT_VERSION='__VERSION__' AIDA_NEW_ARTIFACT_SIZE='__PLAIN_SIZE__' AIDA_NEW_PACKAGE_SHA256='__PACKAGE_SHA__' AIDA_NEW_PACKAGE_SIZE='__PACKAGE_SIZE__' node <<'NODE'
const fs = require('fs');
const p = '.env';
let s = fs.readFileSync(p, 'utf8');
const updates = {
  AIDA_BOOTSTRAP_ARTIFACT_URL: process.env.AIDA_NEW_ARTIFACT_URL,
  AIDA_BOOTSTRAP_ARTIFACT_SHA256: process.env.AIDA_NEW_ARTIFACT_SHA256,
  AIDA_BOOTSTRAP_ARTIFACT_VERSION: process.env.AIDA_NEW_ARTIFACT_VERSION,
  AIDA_BOOTSTRAP_ARTIFACT_SIZE: process.env.AIDA_NEW_ARTIFACT_SIZE,
  AIDA_BOOTSTRAP_ARTIFACT_FORMAT: 'encrypted-cbc-hmac-v1',
  AIDA_BOOTSTRAP_ARTIFACT_NAME: 'AiDAStandalone.exe',
  AIDA_BOOTSTRAP_PACKAGE_SHA256: process.env.AIDA_NEW_PACKAGE_SHA256,
  AIDA_BOOTSTRAP_PACKAGE_SIZE: process.env.AIDA_NEW_PACKAGE_SIZE
};
for (const pair of Object.entries(updates)) {
  const key = pair[0];
  const value = pair[1];
  const line = key + '=' + value;
  const re = new RegExp('^' + key + '=.*$', 'm');
  s = re.test(s) ? s.replace(re, line) : s.replace(/\s*$/, '') + '\n' + line + '\n';
}
fs.writeFileSync(p, s, { mode: 0o600 });
NODE
awk -F= '/^AIDA_BOOTSTRAP_ARTIFACT_URL=|^AIDA_BOOTSTRAP_ARTIFACT_VERSION=|^AIDA_BOOTSTRAP_ARTIFACT_SIZE=|^AIDA_BOOTSTRAP_PACKAGE_SIZE=/{print}' .env
'@
    $script = $script.Replace("__VERSION__", [string]$Package.Version).
        Replace("__URL__", [string]$Package.Url).
        Replace("__PLAIN_SHA__", [string]$Package.PlainSha).
        Replace("__PLAIN_SIZE__", [string]$Package.PlainSize).
        Replace("__PACKAGE_SHA__", [string]$Package.PackageSha).
        Replace("__PACKAGE_SIZE__", [string]$Package.PackageSize)
    $output = Invoke-RemoteBash $script
    foreach ($line in $output) {
        Write-Host "  $line"
    }
    Write-Ok "Bootstrap metadata updated"
    return $true
}

function Update-CamoufoxMcpPatchMetadata([pscustomobject]$Sidecar) {
    if (-not $Sidecar.Changed) { return $false }
    Write-Step "Updating Camoufox MCP patch metadata"
    if ($PlanOnly) {
        Write-Ok "Plan only: would update Camoufox MCP patch metadata to $($Sidecar.McpUrl)"
        return $true
    }
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
cp .env ".env.bak.camoufox.__VERSION__"
AIDA_NEW_CAMOUFOX_MCP_URL='__MCP_URL__' AIDA_NEW_CAMOUFOX_MCP_SHA256='__MCP_SHA__' AIDA_NEW_CAMOUFOX_MCP_VERSION='__VERSION__' AIDA_NEW_CAMOUFOX_MCP_SIZE='__MCP_SIZE__' AIDA_NEW_CAMOUFOX_MCP_REL='__MCP_REL__' AIDA_NEW_CAMOUFOX_SIDECAR_EXE_REL='__EXE_REL__' AIDA_NEW_CAMOUFOX_SIDECAR_PYTHON_REL='__PYTHON_REL__' node <<'NODE'
const fs = require('fs');
const p = '.env';
let s = fs.readFileSync(p, 'utf8');
const updates = {
  AIDA_CAMOUFOX_SIDECAR_EXE_REL: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_EXE_REL,
  AIDA_CAMOUFOX_SIDECAR_PYTHON_REL: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_PYTHON_REL || '',
  AIDA_CAMOUFOX_MCP_URL: process.env.AIDA_NEW_CAMOUFOX_MCP_URL,
  AIDA_CAMOUFOX_MCP_SHA256: process.env.AIDA_NEW_CAMOUFOX_MCP_SHA256,
  AIDA_CAMOUFOX_MCP_VERSION: process.env.AIDA_NEW_CAMOUFOX_MCP_VERSION,
  AIDA_CAMOUFOX_MCP_SIZE: process.env.AIDA_NEW_CAMOUFOX_MCP_SIZE,
  AIDA_CAMOUFOX_MCP_REL: process.env.AIDA_NEW_CAMOUFOX_MCP_REL
};
for (const pair of Object.entries(updates)) {
  const key = pair[0];
  const value = pair[1] || '';
  const line = key + '=' + value;
  const re = new RegExp('^' + key + '=.*$', 'm');
  s = re.test(s) ? s.replace(re, line) : s.replace(/\s*$/, '') + '\n' + line + '\n';
}
fs.writeFileSync(p, s, { mode: 0o600 });
NODE
awk -F= '/^AIDA_CAMOUFOX_SIDECAR_EXE_REL=|^AIDA_CAMOUFOX_SIDECAR_PYTHON_REL=|^AIDA_CAMOUFOX_MCP_URL=|^AIDA_CAMOUFOX_MCP_VERSION=|^AIDA_CAMOUFOX_MCP_SIZE=|^AIDA_CAMOUFOX_MCP_REL=/{print}' .env
'@
    $script = $script.Replace("__VERSION__", [string]$Sidecar.Version).
        Replace("__MCP_URL__", [string]$Sidecar.McpUrl).
        Replace("__MCP_SHA__", [string]$Sidecar.McpSha).
        Replace("__MCP_SIZE__", [string]$Sidecar.McpSize).
        Replace("__MCP_REL__", [string]$Sidecar.McpRel).
        Replace("__EXE_REL__", [string]$Sidecar.ExeRel).
        Replace("__PYTHON_REL__", [string]$Sidecar.PythonRel)
    $output = Invoke-RemoteBash $script
    foreach ($line in $output) {
        Write-Host "  $line"
    }
    Write-Ok "Camoufox MCP patch metadata updated"
    return $true
}

function Restart-And-Verify([bool]$ShouldRestart, [pscustomobject]$Package, [pscustomobject]$Sidecar) {
    Write-Step "Verifying server"
    if ($PlanOnly) {
        Write-Ok "Plan only: would restart API if needed and verify health/package/sidecar/bootstrap"
        return
    }
    $restart = if ($ShouldRestart) { "1" } else { "0" }
    $packageUrl = if ($Package.Url) { [string]$Package.Url } else { "" }
    $sidecarUrl = if ($Sidecar.Url) { [string]$Sidecar.Url } else { "" }
    $mcpUrl = if ($Sidecar.McpUrl) { [string]$Sidecar.McpUrl } else { "" }
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
set -a
. ./.env
set +a
if [ "__RESTART__" = "1" ]; then
  pm2 restart aida-api --update-env >/dev/null
fi
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 2
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3001/health || echo 000)
  if [ "$code" = "200" ]; then break; fi
done
health=$(curl -s -o - -w ' http_code=%{http_code}' http://localhost:3001/health || true)
echo "health=$health"
if ! echo "$health" | grep -q '"status":"ok"'; then
  pm2 status aida-api || true
  pm2 logs aida-api --lines 80 --nostream || true
  exit 1
fi
pkg_url="__PACKAGE_URL__"
if [ -z "$pkg_url" ]; then
  pkg_url="${AIDA_BOOTSTRAP_ARTIFACT_URL:-}"
fi
if [ -n "$pkg_url" ]; then
  pkg_code=$(curl -s -r 0-0 -o /dev/null -w '%{http_code}' "$pkg_url" || echo 000)
  echo "package_http=$pkg_code url=$pkg_url"
  case "$pkg_code" in 200|206) ;; *) exit 1 ;; esac
fi
sidecar_url="__SIDECAR_URL__"
if [ -z "$sidecar_url" ]; then
  sidecar_url="${AIDA_CAMOUFOX_SIDECAR_URL:-}"
fi
if [ -n "$sidecar_url" ]; then
  sidecar_code=$(curl -s -r 0-0 -o /dev/null -w '%{http_code}' "$sidecar_url" || echo 000)
  echo "camoufox_sidecar_http=$sidecar_code url=$sidecar_url"
  case "$sidecar_code" in 200|206) ;; *) exit 1 ;; esac
fi
mcp_url="__MCP_URL__"
if [ -z "$mcp_url" ]; then
  mcp_url="${AIDA_CAMOUFOX_MCP_URL:-}"
fi
if [ -n "$mcp_url" ]; then
  mcp_code=$(curl -s -r 0-0 -o /dev/null -w '%{http_code}' "$mcp_url" || echo 000)
  echo "camoufox_mcp_http=$mcp_code url=$mcp_url"
  case "$mcp_code" in 200|206) ;; *) exit 1 ;; esac
fi
script_code=$(curl -s -H 'Accept: application/vnd.aida.bootstrap' -o /tmp/aida_bootstrap_verify_stage0.ps1 -w '%{http_code}' http://localhost:3001/ || echo 000)
echo "bootstrap_script_http=$script_code"
if [ "$script_code" != "200" ]; then exit 1; fi
verify_path=/tmp/aida_bootstrap_verify_stage0.ps1
if ! grep -q 'AIDA_FILELESS_LAUNCH' "$verify_path"; then
  stage_url=$(sed -n "s/^\$u = '\([^']*\)'.*/\1/p" "$verify_path" | head -1)
  stage_hash=$(sed -n "s/^\$h = '\([^']*\)'.*/\1/p" "$verify_path" | head -1)
  if [ -n "$stage_url" ]; then
    stage_code=$(curl -s -H 'Accept: application/vnd.aida.bootstrap' -o /tmp/aida_bootstrap_verify_stage1.ps1 -w '%{http_code}' "$stage_url" || echo 000)
    echo "bootstrap_stage_http=$stage_code url=$stage_url"
    if [ "$stage_code" != "200" ]; then exit 1; fi
    if [ -n "$stage_hash" ]; then
      actual_hash=$(sha256sum /tmp/aida_bootstrap_verify_stage1.ps1 | awk '{print $1}')
      echo "bootstrap_stage_sha256=$actual_hash"
      if [ "$actual_hash" != "$stage_hash" ]; then exit 1; fi
    fi
    verify_path=/tmp/aida_bootstrap_verify_stage1.ps1
  fi
fi
grep -q 'AIDA_FILELESS_LAUNCH' "$verify_path"
grep -q 'AIDA_CAMOUFOX_EXECUTABLE' "$verify_path"
grep -q 'AIDA_CAMOUFOX_MCP_EXECUTABLE' "$verify_path"
grep -q 'Install-AidaCamoufoxMcpPatch' "$verify_path"
grep -q 'camoufox_mcp_hash_required' "$verify_path"
rm -f /tmp/aida_bootstrap_verify_stage0.ps1 /tmp/aida_bootstrap_verify_stage1.ps1
'@
    $script = $script.Replace("__RESTART__", $restart).Replace("__PACKAGE_URL__", $packageUrl).Replace("__SIDECAR_URL__", $sidecarUrl).Replace("__MCP_URL__", $mcpUrl)
    $output = Invoke-RemoteBash $script
    foreach ($line in $output) {
        Write-Host "  $line"
    }
    Write-Ok "Server health, package, Camoufox artifacts, and bootstrap script verified"
}

if (-not (Test-Path -LiteralPath $SshKey -PathType Leaf)) {
    Stop-Deploy "SSH key not found: $SshKey"
}

$releaseDir = Get-ReleaseDir
$arcDll = Join-Path $releaseDir "aida_core.dll"
$standaloneExe = Join-Path $releaseDir "AiDAStandalone.exe"
$deployId = Get-Date -Format "yyyyMMddHHmmss"
$restartNeeded = $false

Write-Host ""
Write-Host "AiDA deployment" -ForegroundColor Cyan
Write-Host "  BuildDir:       $releaseDir"
Write-Host "  Server:         $Server"
Write-Host "  PublicBaseUrl:  $PublicBaseUrl"
Write-Host ("  Camoufox:       {0}" -f ($(if ($SkipCamoufoxSidecar) { "skip (use --camoufox to publish MCP patch only)" } else { "publish MCP patch only" })))
if ($PlanOnly) { Write-Host "  Mode:           PlanOnly" -ForegroundColor Yellow }

Sync-RemoteDeployScripts
$remoteEnv = Get-RemoteEnvMap
$arcChanged = Publish-Arc $arcDll $deployId
if ($arcChanged) { $restartNeeded = $true }
$package = Publish-StandalonePackage $standaloneExe $deployId $remoteEnv
$metadataChanged = Update-BootstrapMetadata $package
if ($metadataChanged) { $restartNeeded = $true }
$sidecar = Publish-CamoufoxMcpPatch $releaseDir $deployId $remoteEnv
$sidecarMetadataChanged = Update-CamoufoxMcpPatchMetadata $sidecar
if ($sidecarMetadataChanged) { $restartNeeded = $true }
Restart-And-Verify $restartNeeded $package $sidecar

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  DEPLOY COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ("  ARC:         {0}" -f ($(if ($SkipArc) { "skipped" } elseif ($arcChanged) { "published" } else { "unchanged" }))) -ForegroundColor White
Write-Host ("  Standalone:  {0}" -f ($(if ($SkipStandalone) { "skipped" } elseif ($package.Changed) { $package.Url } else { "unchanged" }))) -ForegroundColor White
Write-Host ("  Camoufox:    {0}" -f ($(if ($SkipCamoufoxSidecar) { "skipped" } elseif ($sidecar.Changed) { "MCP patch " + $sidecar.McpUrl } else { "unchanged" }))) -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
