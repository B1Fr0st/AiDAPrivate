# ============================================================================
# AiDA Deploy Script — Encrypt and Upload
# ============================================================================
# Encrypts ARC DLL and uploads the ARC blob to the server.
# Build via CMake/MSBuild before running this script.
#
# Usage:
#   .\deploy_to_server.ps1
#   .\deploy_to_server.ps1 -BuildDir "C:\Users\ruar\AiDAPrivate\build-ninja" # Specify custom build directory
# ============================================================================

param(
    [string]$BuildDir
)

$ErrorActionPreference = "Continue"

$REPO_ROOT           = "C:\Users\ruar\AiDAPrivate"
$SSH_KEY             = "C:\Users\ruar\.ssh\aida_server"
$SERVER              = "ruarr@23.88.62.199"
$REMOTE_ARC_PATH     = "~/aida-server/arc/aida_core.bin"
$ARC_MASTER_SECRET   = "b3c4700abcf39f23d46527f2d2efd4b7d6e81dce0a674bd72d77a73067728453"

if (-not $BuildDir) {
    if (Test-Path "$REPO_ROOT\build-ninja") {
        $RELEASE_DIR = "$REPO_ROOT\build-ninja"
    } else {
        $RELEASE_DIR = "$REPO_ROOT\build\Release"
    }
} else {
    $RELEASE_DIR = $BuildDir
}

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

# ── Encrypt ARC ──────────────────────────────────────────────────────────────

$arcDll = "$RELEASE_DIR\aida_core.dll"
$arcBin = "$RELEASE_DIR\aida_core.bin"

if (-not (Test-Path $arcDll)) { Write-Fail "aida_core.dll not found at $arcDll" }

Write-Step "Encrypting ARC DLL"
$env:ARC_MASTER_SECRET = $ARC_MASTER_SECRET
node "$REPO_ROOT\server\scripts\encrypt-arc.js" $arcDll $arcBin 2>&1
if ($LASTEXITCODE -ne 0) { Write-Fail "ARC encryption failed" }
$arcSize = (Get-Item $arcBin).Length
Write-Ok "Encrypted ARC: $arcSize bytes"

# ── Upload ───────────────────────────────────────────────────────────────────

Write-Step "Uploading ARC blob to server"
scp -i $SSH_KEY $arcBin "${SERVER}:${REMOTE_ARC_PATH}" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Fail "ARC upload failed" }
Write-Ok "ARC uploaded"

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

$remoteArc = Invoke-SSH "ls -lh ~/aida-server/arc/aida_core.bin | awk '{print `$5, `$6, `$7, `$8}'"
Write-Host "  ARC:  $remoteArc" -ForegroundColor White

Write-Host "  URL:  https://aidapro.net" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
