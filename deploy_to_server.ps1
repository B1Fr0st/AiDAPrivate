# ============================================================================
# AiDA Deploy Script — Build, Encrypt, Upload
# ============================================================================
# Builds AiDAStandalone + ARC DLL, encrypts ARC, uploads both to server,
# and restarts the API. Run from the repo root or anywhere — paths are absolute.
#
# Usage:
#   .\deploy_to_server.ps1              # Build all + upload
#   .\deploy_to_server.ps1 -SkipBuild   # Upload existing binaries only
#   .\deploy_to_server.ps1 -ArcOnly     # Build + upload ARC only
#   .\deploy_to_server.ps1 -ExeOnly     # Build + upload AiDAStandalone only
# ============================================================================

param(
    [switch]$SkipBuild,
    [switch]$ArcOnly,
    [switch]$ExeOnly
)

$ErrorActionPreference = "Stop"

# ── Configuration ────────────────────────────────────────────────────────────

$REPO_ROOT           = "C:\Users\ruar\AiDAPrivate"
$BUILD_DIR           = "$REPO_ROOT\build"
$RELEASE_DIR         = "$BUILD_DIR\Release"
$SSH_KEY             = "C:\Users\ruar\.ssh\aida_server"
$SERVER              = "ruarr@23.88.62.199"
$REMOTE_ARC_PATH     = "~/aida-server/arc/aida_core.bin"
$REMOTE_EXE_PATH     = "~/aida-server/bin/AiDA.exe"
$ARC_MASTER_SECRET   = "b3c4700abcf39f23d46527f2d2efd4b7d6e81dce0a674bd72d77a73067728453"
$MSBUILD             = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
$CMAKE               = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step($msg) {
    Write-Host ""
    Write-Host "=== $msg ===" -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    exit 1
}

function Invoke-SSH($cmd) {
    $output = ssh -i $SSH_KEY $SERVER $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "SSH command failed: $cmd`n$output"
    }
    return $output
}

# ── Ensure CMake is configured with ARC ──────────────────────────────────────

if (-not $SkipBuild) {
    # Check if ARC target exists in the build
    if (-not (Test-Path "$BUILD_DIR\AiDA_ARC.vcxproj")) {
        Write-Step "Configuring CMake with BUILD_ARC_DLL=ON"
        & $CMAKE -S $REPO_ROOT -B $BUILD_DIR -G "Visual Studio 17 2022" -A x64 -DBUILD_ARC_DLL=ON 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Fail "CMake configure failed" }
        Write-Ok "CMake configured"
    }
}

# ── Build ────────────────────────────────────────────────────────────────────

$buildTargets = @()

if (-not $SkipBuild) {
    if ($ArcOnly) {
        $buildTargets = @("AiDA_ARC")
    } elseif ($ExeOnly) {
        $buildTargets = @("AiDAStandalone")
    } else {
        $buildTargets = @("AiDAStandalone", "AiDA_ARC")
    }

    foreach ($target in $buildTargets) {
        Write-Step "Building $target (Release x64)"
        & $MSBUILD "$BUILD_DIR\$target.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /m 2>&1 | ForEach-Object {
            if ($_ -match "error") { Write-Host $_ -ForegroundColor Red }
            elseif ($_ -match "warning") { Write-Host $_ -ForegroundColor Yellow }
            elseif ($_ -match "\.vcxproj ->") { Write-Host $_ -ForegroundColor Green }
        }
        if ($LASTEXITCODE -ne 0) { Write-Fail "Build failed for $target" }
        Write-Ok "$target built"
    }
}

# ── Encrypt ARC ──────────────────────────────────────────────────────────────

$uploadArc = (-not $ExeOnly)
$uploadExe = (-not $ArcOnly)

if ($uploadArc) {
    $arcDll = "$RELEASE_DIR\aida_core.dll"
    $arcBin = "$RELEASE_DIR\aida_core.bin"

    if (-not (Test-Path $arcDll)) { Write-Fail "aida_core.dll not found at $arcDll" }

    Write-Step "Encrypting ARC DLL"
    $env:ARC_MASTER_SECRET = $ARC_MASTER_SECRET
    node "$REPO_ROOT\server\scripts\encrypt-arc.js" $arcDll $arcBin 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Fail "ARC encryption failed" }
    $arcSize = (Get-Item $arcBin).Length
    Write-Ok "Encrypted ARC: $arcSize bytes"
}

# ── Upload ───────────────────────────────────────────────────────────────────

if ($uploadArc) {
    Write-Step "Uploading ARC blob to server"
    scp -i $SSH_KEY $arcBin "${SERVER}:${REMOTE_ARC_PATH}" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Fail "ARC upload failed" }
    Write-Ok "ARC uploaded"
}

if ($uploadExe) {
    $exePath = "$RELEASE_DIR\AiDAStandalone.exe"
    if (-not (Test-Path $exePath)) { Write-Fail "AiDAStandalone.exe not found at $exePath" }

    $exeSize = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Step "Uploading AiDAStandalone.exe ($exeSize MB) to server"
    scp -i $SSH_KEY $exePath "${SERVER}:${REMOTE_EXE_PATH}" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Fail "EXE upload failed" }
    Write-Ok "AiDAStandalone.exe uploaded"
}

# ── Restart API ──────────────────────────────────────────────────────────────

Write-Step "Restarting server API"
$restart = Invoke-SSH "pm2 restart aida-api --update-env 2>&1 | tail -1"
Write-Ok "API restarted"

# ── Verify ───────────────────────────────────────────────────────────────────

Write-Step "Verifying server health"
$health = Invoke-SSH "curl -s http://localhost:3001/health"
if ($health -match '"ok"') {
    Write-Ok "Server healthy: $health"
} else {
    Write-Fail "Health check failed: $health"
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  DEPLOY COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

if ($uploadArc) {
    $remoteArc = Invoke-SSH "ls -lh ~/aida-server/arc/aida_core.bin | awk '{print `$5, `$6, `$7, `$8}'"
    Write-Host "  ARC:  $remoteArc" -ForegroundColor White
}
if ($uploadExe) {
    $remoteExe = Invoke-SSH "ls -lh ~/aida-server/bin/AiDA.exe | awk '{print `$5, `$6, `$7, `$8}'"
    Write-Host "  EXE:  $remoteExe" -ForegroundColor White
}

Write-Host "  URL:  https://aidapro.net" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
