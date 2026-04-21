# AiDA Server Deploy Script
# Usage: .\deploy_server.ps1

$SSH_KEY = "C:\Users\ruar\.ssh\aida_server"
$REMOTE  = "ruarr@23.88.62.199"
$SRC     = "C:\Users\ruar\AiDAPrivate\server\"
$DST     = "/home/ruarr/aida-server/"
$ADMIN_KEY = "08497b90b9a76d7be929674519ce5d870a5d51185806ea2a6da732f3430f00b1"

Write-Host "`n=== Deploying server/ to $REMOTE ===" -ForegroundColor Cyan

# --- 1. Upload source files ---
Write-Host "`n[1/3] Uploading files..." -ForegroundColor Yellow
$files = @(
    "server.js",
    "routes\license.js",
    "routes\download.js",
    "routes\sentinel.js",
    "routes\telemetry.js",
    "crypto\signing.js",
    "crypto\arc-encrypt.js",
    "crypto\kw_wrap.js",
    "crypto\tls_exporter.js",
    "db\pool.js"
)
foreach ($f in $files) {
    $local = Join-Path $SRC $f
    $remotePath = $DST + ($f -replace '\\', '/')
    if (Test-Path $local) {
        & scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$local" "${REMOTE}:${remotePath}"
        if ($LASTEXITCODE -ne 0) { Write-Host "SCP failed for $f" -ForegroundColor Red; exit 1 }
    }
}
Write-Host "      Done." -ForegroundColor Green

# --- 2. Restart PM2 and smoke test via remote bash script ---
Write-Host "`n[2/3] Restarting PM2..." -ForegroundColor Yellow

# Build script with LF-only line endings (not CRLF) so bash can read it
$nl = "`n"
$script  = "#!/bin/bash$nl"
$script += "set -e$nl"
$script += "cd /home/ruarr/aida-server$nl"
$script += "pm2 restart aida-api 2>&1 | grep -E 'online|error|Done' || true$nl"
$script += "sleep 3$nl"
$script += "echo '[health]'$nl"
$script += "curl -s http://localhost:3001/health$nl"
$script += "echo$nl"
$script += "echo '[keygen]'$nl"
$script += "curl -s -X POST http://localhost:3001/api/license/create -H 'Content-Type: application/json' -d '{""admin_key"":""$ADMIN_KEY"",""plan"":""pro"",""note"":""deploy_test"",""expires"":""2099-01-01""}'$nl"
$script += "echo$nl"

$localScript = "$env:TEMP\aida_deploy.sh"
[System.IO.File]::WriteAllText($localScript, $script, [System.Text.UTF8Encoding]::new($false))

& scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$localScript" "${REMOTE}:/tmp/aida_deploy.sh"
$output = & ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no $REMOTE "bash /tmp/aida_deploy.sh"
Write-Host $output

if ($output -like '*"status":"ok"*') {
    Write-Host "`nDeploy complete." -ForegroundColor Green
} else {
    Write-Host "`nSomething looks off - check server logs above." -ForegroundColor Yellow
}
