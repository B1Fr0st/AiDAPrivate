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

$explicitCamoufox = $Camoufox.IsPresent
foreach ($arg in @($ExtraArgs)) {
    if ([string]::Equals($arg, "--camoufox", [StringComparison]::OrdinalIgnoreCase)) {
        $explicitCamoufox = $true
    } elseif (-not [string]::IsNullOrWhiteSpace($arg)) {
        throw "Unknown argument: $arg"
    }
}
if ($explicitCamoufox -and $SkipCamoufoxSidecar.IsPresent) {
    throw "Use either --camoufox/-Camoufox or -SkipCamoufoxSidecar, not both."
}
$SkipStandalone = [switch]::Present

$RepoRoot = $PSScriptRoot
$Server = "ruarr@23.88.62.199"
$SshKey = Join-Path $env:USERPROFILE ".ssh\aida_server"
$RemoteRoot = "/home/ruarr/aida-server"
$RemoteArcPath = "$RemoteRoot/arc/aida_core.bin"
$RemoteArcShaPath = "$RemoteRoot/arc/aida_core.sha256"
$RemoteArtifactDir = "$RemoteRoot/bootstrap_artifacts"
$RemotePrivateStandalonePath = "$RemoteRoot/private/AiDAStandalone.base.exe"
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

function Resolve-LocalPowerShellExe {
    $candidates = @(
        (Join-Path $PSHOME "pwsh.exe"),
        (Join-Path $PSHOME "powershell.exe")
    )
    foreach ($name in @("pwsh.exe", "powershell.exe")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command -and $command.Source) {
            $candidates += $command.Source
        }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    Stop-Deploy "Unable to locate a local PowerShell executable for Camoufox MCP contract validation."
}

function Invoke-CamoufoxFrozenMcpContractValidation([string]$McpExe, [string]$BrowserExe) {
    $contractScript = Join-Path $RepoRoot "tools\build_camoufox_reverse_mcp_exe.ps1"
    if (-not (Test-Path -LiteralPath $contractScript -PathType Leaf)) {
        Stop-Deploy "Frozen Camoufox reverse MCP contract script is missing: $contractScript"
    }
    $resolvedMcp = (Resolve-Path -LiteralPath $McpExe -ErrorAction Stop).Path
    $resolvedBrowser = (Resolve-Path -LiteralPath $BrowserExe -ErrorAction Stop).Path
    $mcpSize = (Get-Item -LiteralPath $resolvedMcp).Length
    $mcpSha = Get-FileSha256Lower $resolvedMcp
    Write-Step "Validating frozen Camoufox reverse MCP"
    Write-Host "  selected_mcp_path=$resolvedMcp"
    Write-Host "  selected_mcp_size=$mcpSize"
    Write-Host "  selected_mcp_sha256=$mcpSha"
    Write-Host "  selected_browser_path=$resolvedBrowser"
    $psExe = Resolve-LocalPowerShellExe
    $psArgs = @("-NoProfile")
    if ([string]::Equals([IO.Path]::GetFileName($psExe), "powershell.exe", [StringComparison]::OrdinalIgnoreCase)) {
        $psArgs += @("-ExecutionPolicy", "Bypass")
    }
    $psArgs += @("-File", $contractScript, "-ContractCheckOnly", "-ExistingExecutable", $resolvedMcp, "-BrowserExecutable", $resolvedBrowser)
    $output = & $psExe @psArgs 2>&1
    $exitCode = $LASTEXITCODE
    $outputLines = @()
    foreach ($line in @($output)) {
        $text = [string]$line
        $outputLines += $text
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }
        if ($text.Length -gt 4096) {
            $text = $text.Substring(0, 4096) + "..."
        }
        Write-Host "  contract_check: $text"
    }
    $outputText = $outputLines -join "`n"
    if ($exitCode -ne 0) {
        Stop-Deploy "Frozen Camoufox reverse MCP contract validation failed exit=$exitCode path=$resolvedMcp"
    }
    if ($outputText -notmatch "(?m)^frozen_mcp_contract_check=ok$" -or $outputText -notmatch "(?m)^frozen_mcp_stdio_smoke=ok$") {
        Stop-Deploy "Frozen Camoufox reverse MCP contract validation did not confirm both page-marker and tools/list contracts."
    }
    Write-Ok "Frozen Camoufox reverse MCP contract validation passed: sha256=$mcpSha size=$mcpSize"
    return [pscustomobject]@{ Path = $resolvedMcp; Sha = $mcpSha; Size = [int64]$mcpSize }
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
        Write-Warn "Skipping standalone package publish because bootstrap delivery is Camoufox-only"
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

function Publish-StandalonePrivateBase([string]$StandalonePath, [string]$DeployId, [hashtable]$RemoteEnv) {
    if ($SkipStandalone) {
        Write-Warn "Skipping private standalone base publish because -SkipStandalone was specified"
        return [pscustomobject]@{ Changed = $false; Sha = ""; Size = 0; Version = "" }
    }
    if (-not (Test-Path -LiteralPath $StandalonePath -PathType Leaf)) {
        Stop-Deploy "AiDAStandalone.exe not found: $StandalonePath"
    }
    $plainSha = Get-FileSha256Lower $StandalonePath
    $plainSize = (Get-Item -LiteralPath $StandalonePath).Length
    $currentSha = if ($RemoteEnv.ContainsKey("AIDA_STANDALONE_BASE_SHA256")) { ([string]$RemoteEnv["AIDA_STANDALONE_BASE_SHA256"]).ToLowerInvariant() } else { "" }
    $currentPath = if ($RemoteEnv.ContainsKey("AIDA_STANDALONE_BASE_EXE")) { [string]$RemoteEnv["AIDA_STANDALONE_BASE_EXE"] } else { "" }
    $remoteHash = ""
    if ($currentPath -eq $RemotePrivateStandalonePath) {
        $pathLit = ConvertTo-RemoteShellLiteral $RemotePrivateStandalonePath
        $probe = Invoke-RemoteSoft "if [ -f $pathLit ]; then sha256sum $pathLit | awk '{print `$1}'; else echo missing; fi"
        if ($probe.Output) { $remoteHash = ([string]($probe.Output | Select-Object -First 1)).Trim().ToLowerInvariant() }
    }
    if (-not $Force -and $currentSha -eq $plainSha -and $remoteHash -eq $plainSha) {
        Write-Ok "Private standalone base unchanged: $plainSha"
        return [pscustomobject]@{ Changed = $false; Sha = $plainSha; Size = $plainSize; Version = "" }
    }
    Write-Step "Publishing private standalone base"
    if ($PlanOnly) {
        Write-Ok "Plan only: would upload private base sha256=$plainSha size=$plainSize to $RemotePrivateStandalonePath"
        return [pscustomobject]@{ Changed = $true; Sha = $plainSha; Size = $plainSize; Version = $DeployId }
    }
    $remoteTmp = "/tmp/AiDAStandalone_private_base_$DeployId.exe"
    Copy-ToRemote $StandalonePath $remoteTmp
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
install -d -m 700 private
install -m 600 '__REMOTE_TMP__' '__REMOTE_BASE__'
rm -f '__REMOTE_TMP__'
actual=$(sha256sum '__REMOTE_BASE__' | awk '{print $1}')
if [ "$actual" != '__SHA__' ]; then
  echo "private standalone base sha mismatch: $actual" >&2
  exit 1
fi
cp .env ".env.bak.private-standalone.__VERSION__"
AIDA_STANDALONE_BASE_EXE_NEW='__REMOTE_BASE__' AIDA_STANDALONE_BASE_SHA256_NEW='__SHA__' AIDA_STANDALONE_BASE_SIZE_NEW='__SIZE__' AIDA_STANDALONE_BASE_VERSION_NEW='__VERSION__' node <<'NODE'
const fs = require('fs');
const p = '.env';
let s = fs.readFileSync(p, 'utf8');
const updates = {
  AIDA_STANDALONE_BASE_EXE: process.env.AIDA_STANDALONE_BASE_EXE_NEW,
  AIDA_STANDALONE_BASE_SHA256: process.env.AIDA_STANDALONE_BASE_SHA256_NEW,
  AIDA_STANDALONE_BASE_SIZE: process.env.AIDA_STANDALONE_BASE_SIZE_NEW,
  AIDA_STANDALONE_BASE_VERSION: process.env.AIDA_STANDALONE_BASE_VERSION_NEW
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
stat -c 'private_standalone_size=%s' '__REMOTE_BASE__'
'@
    $script = $script.Replace("__REMOTE_TMP__", $remoteTmp).
        Replace("__REMOTE_BASE__", $RemotePrivateStandalonePath).
        Replace("__SHA__", $plainSha).
        Replace("__SIZE__", [string]$plainSize).
        Replace("__VERSION__", $DeployId)
    $output = Invoke-RemoteBash $script
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match "^private_standalone_size=") {
            Write-Host "  $text"
        }
    }
    Write-Ok "Private standalone base published sha256=$plainSha"
    return [pscustomobject]@{ Changed = $true; Sha = $plainSha; Size = $plainSize; Version = $DeployId }
}

function Get-CamoufoxSidecarInputs([string]$ReleaseDir) {
    $browserName = "camoufox-135.0.1-beta.24-win.x86_64"
    $releaseOutput = Join-Path $ReleaseDir "Release"
    $browser = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "deps\$browserName"),
        (Join-Path $RepoRoot $browserName),
        (Join-Path $RepoRoot ".deps\$browserName")
    ) -Directory
    $mcp = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "deps\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot ".deps\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "build-ninja\deps\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $ReleaseDir "deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot ".deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "build-ninja\deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $ReleaseDir "deps\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp\dist\AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp\dist\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot ".deps\camoufox-reverse-mcp.exe"),
        (Join-Path $RepoRoot "AiDA_CamoufoxReverseMcp.exe"),
        (Join-Path $RepoRoot "camoufox-reverse-mcp.exe")
    )
    $ghidraSpecs = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "ghidra_specs"),
        (Join-Path $ReleaseDir "deps\ghidra_specs"),
        (Join-Path $releaseOutput "ghidra_specs"),
        (Join-Path $releaseOutput "deps\ghidra_specs"),
        (Join-Path $RepoRoot "build-ninja\ghidra_specs"),
        (Join-Path $RepoRoot "build-ninja\Release\ghidra_specs")
    ) -Directory
    $targetProtocol = Find-FirstExistingPath @(
        (Join-Path $ReleaseDir "test_binaries\target_protocol"),
        (Join-Path $ReleaseDir "deps\test_binaries\target_protocol"),
        (Join-Path $releaseOutput "test_binaries\target_protocol"),
        (Join-Path $releaseOutput "deps\test_binaries\target_protocol"),
        (Join-Path $RepoRoot "build-ninja\test_binaries\target_protocol"),
        (Join-Path $RepoRoot "build-ninja\Release\test_binaries\target_protocol"),
        (Join-Path $RepoRoot "build-ninja\Release\deps\test_binaries\target_protocol"),
        (Join-Path $RepoRoot "test_binaries\target_protocol")
    ) -Directory
    return [pscustomobject]@{
        BrowserName = $browserName
        BrowserDir = $browser
        BrowserExe = if ($browser) { Join-Path $browser "camoufox.exe" } else { "" }
        McpExe = $mcp
        GhidraSpecsDir = $ghidraSpecs
        TargetProtocolDir = $targetProtocol
        ExeRel = "deps/$browserName/camoufox.exe"
        PythonRel = ""
    }
}

function Assert-GhidraSpecsInput([string]$Dir) {
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) {
        Stop-Deploy "Ghidra specs directory is missing. Build AiDAStandalone so ghidra_specs is staged."
    }
    foreach ($name in @("x86-64.sla", "x86-64.pspec", "x86-64-win.cspec", "x86.ldefs")) {
        $path = Join-Path $Dir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Stop-Deploy "Ghidra specs directory is incomplete: $path is missing."
        }
    }
}

function Assert-TargetProtocolInput([string]$Dir) {
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) {
        Stop-Deploy "target_protocol fixture directory is missing. Build AiDAStandalone so test_binaries\target_protocol is staged."
    }
    foreach ($name in @("target_protocol.exe", "target_protocol.pdb")) {
        $path = Join-Path $Dir $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Stop-Deploy "target_protocol fixture directory is incomplete: $path is missing."
        }
    }
}

function Assert-CamoufoxSidecarInputs([pscustomobject]$Inputs) {
    if (-not $Inputs.BrowserDir -or -not (Test-Path -LiteralPath $Inputs.BrowserDir -PathType Container)) {
        Stop-Deploy "Camoufox browser bundle is missing. Expected camoufox-135.0.1-beta.24-win.x86_64 with camoufox.exe."
    }
    if (-not $Inputs.BrowserExe -or -not (Test-Path -LiteralPath $Inputs.BrowserExe -PathType Leaf)) {
        Stop-Deploy "Camoufox browser executable is missing: $($Inputs.BrowserExe)"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Inputs.BrowserDir "application.ini") -PathType Leaf)) {
        Stop-Deploy "Camoufox browser bundle is incomplete: application.ini is missing."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Inputs.BrowserDir "browser") -PathType Container)) {
        Stop-Deploy "Camoufox browser bundle is incomplete: browser directory is missing."
    }
    if (-not $Inputs.McpExe -or -not (Test-Path -LiteralPath $Inputs.McpExe -PathType Leaf)) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable is missing. Build .deps\AiDA_CamoufoxReverseMcp\AiDA_CamoufoxReverseMcp.exe first."
    }
    $mcpDir = Split-Path -Parent $Inputs.McpExe
    if ($mcpDir -and (Test-Path -LiteralPath (Join-Path $mcpDir "_internal") -PathType Container)) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable is a PyInstaller onedir bootloader with sibling _internal runtime. Build the self-contained onefile executable before customer deployment."
    }
    $size = (Get-Item -LiteralPath $Inputs.McpExe).Length
    if ($size -lt 33554432) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable is too small to be the customer self-contained bridge: $size bytes"
    }
    if ($size -le 0 -or $size -gt 268435456) {
        Stop-Deploy "Frozen Camoufox reverse MCP executable size is invalid: $size bytes"
    }
    Assert-GhidraSpecsInput $Inputs.GhidraSpecsDir
    Assert-TargetProtocolInput $Inputs.TargetProtocolDir
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

function New-CamoufoxSidecarPackage([pscustomobject]$Inputs, [string]$DeployId) {
    $id = [Guid]::NewGuid().ToString("N")
    $stageRoot = Join-Path ([IO.Path]::GetTempPath()) "aida-camoufox-sidecar-stage-$id"
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) "aida-camoufox-sidecar-$DeployId-$id.zip"
    try {
        $depsRoot = Join-Path $stageRoot "deps"
        New-Item -ItemType Directory -Force -Path $depsRoot | Out-Null
        Copy-Item -LiteralPath $Inputs.BrowserDir -Destination (Join-Path $depsRoot $Inputs.BrowserName) -Recurse -Force
        Copy-Item -LiteralPath $Inputs.McpExe -Destination (Join-Path $depsRoot "AiDA_CamoufoxReverseMcp.exe") -Force
        Copy-Item -LiteralPath $Inputs.GhidraSpecsDir -Destination (Join-Path $depsRoot "ghidra_specs") -Recurse -Force
        $targetProtocolDest = Join-Path $depsRoot "test_binaries\target_protocol"
        New-Item -ItemType Directory -Force -Path $targetProtocolDest | Out-Null
        Copy-Item -LiteralPath (Join-Path $Inputs.TargetProtocolDir "target_protocol.exe") -Destination (Join-Path $targetProtocolDest "target_protocol.exe") -Force
        Copy-Item -LiteralPath (Join-Path $Inputs.TargetProtocolDir "target_protocol.pdb") -Destination (Join-Path $targetProtocolDest "target_protocol.pdb") -Force
        Assert-NoReverseMcpSourceLeak $stageRoot
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($stageRoot, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
        $sha = Get-FileSha256Lower $zipPath
        $size = (Get-Item -LiteralPath $zipPath).Length
        return [pscustomobject]@{ ZipPath = $zipPath; Sha = $sha; Size = [int64]$size }
    } finally {
        try {
            $tempRoot = [IO.Path]::GetTempPath().TrimEnd('\')
            $resolvedStage = [IO.Path]::GetFullPath($stageRoot).TrimEnd('\')
            if ($resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and ([IO.Path]::GetFileName($resolvedStage) -like 'aida-camoufox-sidecar-stage-*') -and (Test-Path -LiteralPath $resolvedStage)) {
                Remove-Item -LiteralPath $resolvedStage -Recurse -Force
            }
        } catch { }
    }
}

function Test-RemoteHttpArtifactLive([string]$Url) {
    if (-not $Url) { return $false }
    $urlLit = ConvertTo-RemoteShellLiteral $Url
    $probe = Invoke-RemoteSoft "curl -s -r 0-0 -o /dev/null -w '%{http_code}' $urlLit || echo 000"
    $status = if ($probe.Output) { ([string]($probe.Output | Select-Object -First 1)).Trim() } else { "" }
    return $probe.ExitCode -eq 0 -and ($status -eq "200" -or $status -eq "206")
}

function Publish-CamoufoxSidecar([string]$ReleaseDir, [string]$DeployId, [hashtable]$RemoteEnv) {
    if ($SkipCamoufoxSidecar) {
        Write-Warn "Skipping Camoufox sidecar publish"
        return [pscustomobject]@{ Changed = $false; Url = ""; PackageName = ""; Sha = ""; Size = 0; Version = ""; ExeRel = ""; PythonRel = ""; McpUrl = ""; McpPackageName = ""; McpSha = ""; McpSize = 0; McpRel = "" }
    }

    $inputs = Get-CamoufoxSidecarInputs $ReleaseDir
    Assert-CamoufoxSidecarInputs $inputs
    $mcpContract = Invoke-CamoufoxFrozenMcpContractValidation $inputs.McpExe $inputs.BrowserExe
    $sidecarPackage = New-CamoufoxSidecarPackage $inputs $DeployId
    $mcpSha = $mcpContract.Sha
    $mcpSize = $mcpContract.Size
    $sidecarSha = $sidecarPackage.Sha
    $sidecarSize = $sidecarPackage.Size
    $version = (Get-Date -Format "yyyyMMddHHmmss")
    $sidecarName = "aida-camoufox-sidecar-$($version.Substring(0, 8))-$($version.Substring(8, 6)).zip"
    $sidecarUrl = ($PublicBaseUrl.TrimEnd("/")) + "/bootstrap-artifacts/" + $sidecarName
    $mcpName = "AiDA_CamoufoxReverseMcp-$($version.Substring(0, 8))-$($version.Substring(8, 6)).exe"
    $mcpUrl = ($PublicBaseUrl.TrimEnd("/")) + "/bootstrap-artifacts/" + $mcpName
    $mcpRel = "deps/AiDA_CamoufoxReverseMcp.exe"
    $currentSidecarUrl = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_URL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_URL"] } else { "" }
    $currentSidecarSha = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_SHA256")) { ([string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_SHA256"]).ToLowerInvariant() } else { "" }
    $currentSidecarVersion = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_VERSION")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_VERSION"] } else { "" }
    $currentSidecarSize = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_SIZE")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_SIZE"] } else { "" }
    $currentSha = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_SHA256")) { ([string]$RemoteEnv["AIDA_CAMOUFOX_MCP_SHA256"]).ToLowerInvariant() } else { "" }
    $currentSize = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_SIZE")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_SIZE"] } else { "" }
    $currentMcpRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_REL"] } else { "" }
    $currentExeRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_EXE_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_EXE_REL"] } else { "" }
    $currentPythonRel = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_SIDECAR_PYTHON_REL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_SIDECAR_PYTHON_REL"] } else { "" }
    $metadataCurrent = $currentMcpRel -eq $mcpRel -and $currentExeRel -eq $inputs.ExeRel -and $currentPythonRel -eq $inputs.PythonRel
    $currentMcpUrl = if ($RemoteEnv.ContainsKey("AIDA_CAMOUFOX_MCP_URL")) { [string]$RemoteEnv["AIDA_CAMOUFOX_MCP_URL"] } else { "" }
    try {
        $sidecarLive = Test-RemoteHttpArtifactLive $currentSidecarUrl
        $mcpLive = Test-RemoteHttpArtifactLive $currentMcpUrl
        $sidecarUnchanged = $currentSidecarSha -eq $sidecarSha -and $currentSidecarSize -eq [string]$sidecarSize
        $mcpUnchanged = $currentSha -eq $mcpSha -and $currentSize -eq [string]$mcpSize
        if (-not $Force -and $sidecarUnchanged -and $sidecarLive -and $mcpUnchanged -and $mcpLive) {
            if (-not $metadataCurrent) {
                $currentVersion = if ($currentSidecarVersion) { $currentSidecarVersion } else { $version }
                Write-Warn "Camoufox sidecar unchanged; repairing slash-safe bootstrap metadata"
                return [pscustomobject]@{ Changed = $true; Url = $currentSidecarUrl; PackageName = [IO.Path]::GetFileName($currentSidecarUrl); Sha = $sidecarSha; Size = [int64]$sidecarSize; Version = $currentVersion; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $currentMcpUrl; McpPackageName = [IO.Path]::GetFileName($currentMcpUrl); McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
            }
            Write-Ok "Camoufox sidecar unchanged: $sidecarSha"
            return [pscustomobject]@{ Changed = $false; Url = $currentSidecarUrl; PackageName = [IO.Path]::GetFileName($currentSidecarUrl); Sha = $sidecarSha; Size = [int64]$sidecarSize; Version = $currentSidecarVersion; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $currentMcpUrl; McpPackageName = [IO.Path]::GetFileName($currentMcpUrl); McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
        }
        Write-Step "Publishing Camoufox sidecar"
        if ($PlanOnly) {
            Write-Ok "Plan only: would upload $sidecarName from browser=$($inputs.BrowserDir) mcp=$($inputs.McpExe) sha256=$sidecarSha size=$sidecarSize"
            Write-Ok "Plan only: would upload $mcpName from mcp=$($inputs.McpExe) sha256=$mcpSha size=$mcpSize"
            return [pscustomobject]@{ Changed = $true; Url = $sidecarUrl; PackageName = $sidecarName; Sha = $sidecarSha; Size = [int64]$sidecarSize; Version = $version; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $mcpUrl; McpPackageName = $mcpName; McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
        }
        Copy-ToRemote $sidecarPackage.ZipPath "$RemoteArtifactDir/$sidecarName"
        Copy-ToRemote $inputs.McpExe "$RemoteArtifactDir/$mcpName"
        Write-Ok "Camoufox sidecar uploaded: $sidecarName sha256=$sidecarSha size=$sidecarSize"
        Write-Ok "Camoufox MCP patch uploaded: $mcpName sha256=$mcpSha size=$mcpSize"
        return [pscustomobject]@{ Changed = $true; Url = $sidecarUrl; PackageName = $sidecarName; Sha = $sidecarSha; Size = [int64]$sidecarSize; Version = $version; ExeRel = $inputs.ExeRel; PythonRel = $inputs.PythonRel; McpUrl = $mcpUrl; McpPackageName = $mcpName; McpSha = $mcpSha; McpSize = [int64]$mcpSize; McpRel = $mcpRel }
    } finally {
        try { if ($sidecarPackage -and $sidecarPackage.ZipPath -and (Test-Path -LiteralPath $sidecarPackage.ZipPath)) { Remove-Item -LiteralPath $sidecarPackage.ZipPath -Force } } catch { }
    }
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

function Update-CamoufoxSidecarMetadata([pscustomobject]$Sidecar) {
    if (-not $Sidecar.Changed) { return $false }
    Write-Step "Updating Camoufox sidecar metadata"
    if ($PlanOnly) {
        Write-Ok "Plan only: would update Camoufox sidecar metadata to $($Sidecar.Url)"
        return $true
    }
    $script = @'
set -euo pipefail
cd /home/ruarr/aida-server
cp .env ".env.bak.camoufox.__VERSION__"
AIDA_NEW_CAMOUFOX_SIDECAR_URL='__SIDECAR_URL__' AIDA_NEW_CAMOUFOX_SIDECAR_SHA256='__SIDECAR_SHA__' AIDA_NEW_CAMOUFOX_SIDECAR_VERSION='__VERSION__' AIDA_NEW_CAMOUFOX_SIDECAR_SIZE='__SIDECAR_SIZE__' AIDA_NEW_CAMOUFOX_MCP_URL='__MCP_URL__' AIDA_NEW_CAMOUFOX_MCP_SHA256='__MCP_SHA__' AIDA_NEW_CAMOUFOX_MCP_VERSION='__VERSION__' AIDA_NEW_CAMOUFOX_MCP_SIZE='__MCP_SIZE__' AIDA_NEW_CAMOUFOX_MCP_REL='__MCP_REL__' AIDA_NEW_CAMOUFOX_SIDECAR_EXE_REL='__EXE_REL__' AIDA_NEW_CAMOUFOX_SIDECAR_PYTHON_REL='__PYTHON_REL__' node <<'NODE'
const fs = require('fs');
const p = '.env';
let s = fs.readFileSync(p, 'utf8');
const updates = {
  AIDA_CAMOUFOX_SIDECAR_URL: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_URL,
  AIDA_CAMOUFOX_SIDECAR_SHA256: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_SHA256,
  AIDA_CAMOUFOX_SIDECAR_VERSION: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_VERSION,
  AIDA_CAMOUFOX_SIDECAR_SIZE: process.env.AIDA_NEW_CAMOUFOX_SIDECAR_SIZE,
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
awk -F= '/^AIDA_CAMOUFOX_SIDECAR_URL=|^AIDA_CAMOUFOX_SIDECAR_SHA256=|^AIDA_CAMOUFOX_SIDECAR_VERSION=|^AIDA_CAMOUFOX_SIDECAR_SIZE=|^AIDA_CAMOUFOX_SIDECAR_EXE_REL=|^AIDA_CAMOUFOX_SIDECAR_PYTHON_REL=|^AIDA_CAMOUFOX_MCP_URL=|^AIDA_CAMOUFOX_MCP_SHA256=|^AIDA_CAMOUFOX_MCP_VERSION=|^AIDA_CAMOUFOX_MCP_SIZE=|^AIDA_CAMOUFOX_MCP_REL=/{print}' .env
'@
    $script = $script.Replace("__VERSION__", [string]$Sidecar.Version).
        Replace("__SIDECAR_URL__", [string]$Sidecar.Url).
        Replace("__SIDECAR_SHA__", [string]$Sidecar.Sha).
        Replace("__SIDECAR_SIZE__", [string]$Sidecar.Size).
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
    Write-Ok "Camoufox sidecar metadata updated"
    return $true
}

function Restart-And-Verify([bool]$ShouldRestart, [pscustomobject]$Package, [pscustomobject]$Sidecar) {
    Write-Step "Verifying server"
    if ($PlanOnly) {
        Write-Ok "Plan only: would restart API if needed and verify health/Camoufox/bootstrap"
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
if ! grep -q 'Install-AidaCamoufoxSidecar' "$verify_path"; then
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
grep -q 'AIDA_CAMOUFOX_EXECUTABLE' "$verify_path"
grep -q 'AIDA_CAMOUFOX_MCP_EXECUTABLE' "$verify_path"
grep -q 'Install-AidaCamoufoxMcpPatch' "$verify_path"
grep -q 'camoufox_mcp_hash_required' "$verify_path"
grep -q 'camoufox_only_delivery_complete' "$verify_path"
if grep -qE 'AIDA_FILELESS_LAUNCH|Invoke-AidaPEInMemory|Get-AidaPackageBytesWithProgress|Decrypt-AidaPackageBytes|Downloading and verifying encrypted package|launch_inmemory_enter' "$verify_path"; then
  echo "bootstrap still contains standalone launch markers" >&2
  exit 1
fi
rm -f /tmp/aida_bootstrap_verify_stage0.ps1 /tmp/aida_bootstrap_verify_stage1.ps1
'@
    $script = $script.Replace("__RESTART__", $restart).Replace("__PACKAGE_URL__", $packageUrl).Replace("__SIDECAR_URL__", $sidecarUrl).Replace("__MCP_URL__", $mcpUrl)
    $output = Invoke-RemoteBash $script
    foreach ($line in $output) {
        Write-Host "  $line"
    }
    Write-Ok "Server health, Camoufox artifacts, and Camoufox-only bootstrap script verified"
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
Write-Host "  Standalone:     disabled (Discord/manual distribution)"
Write-Host ("  Camoufox:       {0}" -f ($(if ($SkipCamoufoxSidecar) { "skipped" } else { "publish full sidecar + MCP patch" })))
if ($PlanOnly) { Write-Host "  Mode:           PlanOnly" -ForegroundColor Yellow }

Sync-RemoteDeployScripts
$remoteEnv = Get-RemoteEnvMap
$arcChanged = Publish-Arc $arcDll $deployId
if ($arcChanged) { $restartNeeded = $true }
$package = Publish-StandalonePackage $standaloneExe $deployId $remoteEnv
$metadataChanged = Update-BootstrapMetadata $package
if ($metadataChanged) { $restartNeeded = $true }
$privateBase = Publish-StandalonePrivateBase $standaloneExe $deployId $remoteEnv
if ($privateBase.Changed) { $restartNeeded = $true }
$sidecar = Publish-CamoufoxSidecar $releaseDir $deployId $remoteEnv
$sidecarMetadataChanged = Update-CamoufoxSidecarMetadata $sidecar
if ($sidecarMetadataChanged) { $restartNeeded = $true }
Restart-And-Verify $restartNeeded $package $sidecar

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  DEPLOY COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ("  ARC:         {0}" -f ($(if ($SkipArc) { "skipped" } elseif ($arcChanged) { "published" } else { "unchanged" }))) -ForegroundColor White
Write-Host ("  Standalone:  {0}" -f ($(if ($SkipStandalone) { "skipped" } elseif ($package.Changed) { $package.Url } else { "unchanged" }))) -ForegroundColor White
Write-Host ("  PrivateBase: {0}" -f ($(if ($SkipStandalone) { "skipped" } elseif ($privateBase.Changed) { $privateBase.Sha } else { "unchanged" }))) -ForegroundColor White
Write-Host ("  Camoufox:    {0}" -f ($(if ($SkipCamoufoxSidecar) { "skipped" } elseif ($sidecar.Changed) { $sidecar.Url } else { "unchanged" }))) -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
