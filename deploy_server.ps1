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
    "crypto\arc-license-bind.js",
    "crypto\kw_wrap.js",
    "crypto\tls_exporter.js",
    "db\pool.js",
    "db\schema.sql"
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

# --- 1b. Align signing keys with the repo so client signature verification works ---
# The client (standalone_license.cpp::get_arc_signing_public_key_der_hex) hard-codes the
# Ed25519 SPKI public key derived from server/keys/ed25519_private_b64.txt. If the server's
# .env was created by deploy.sh (which generates a fresh random key on first deploy), every
# signed page hits arc_paged_signature_invalid on the client. We push the repo's key here so
# the production server signs with the matching private key.
$privKeyPath = Join-Path $SRC "keys\ed25519_private_b64.txt"
$pubKeyPath  = Join-Path $SRC "keys\ed25519_public_b64.txt"
if ((Test-Path $privKeyPath) -and (Test-Path $pubKeyPath)) {
    $repoPriv = (Get-Content $privKeyPath -Raw).Trim()
    $repoPub  = (Get-Content $pubKeyPath  -Raw).Trim()
    if ($repoPriv -and $repoPub) {
        Write-Host "`n[1b] Aligning ED25519_PRIVATE_KEY_B64 in remote .env with repo key..." -ForegroundColor Yellow
        $alignScript = "#!/bin/bash`n"
        $alignScript += "set -e`n"
        $alignScript += "cd /home/ruarr/aida-server`n"
        $alignScript += "if [ ! -f .env ]; then`n"
        $alignScript += "  echo 'no_env_file_found'`n"
        $alignScript += "  exit 0`n"
        $alignScript += "fi`n"
        $alignScript += "DESIRED_PRIV='$repoPriv'`n"
        $alignScript += "DESIRED_PUB='$repoPub'`n"
        $alignScript += "if grep -q '^ED25519_PRIVATE_KEY_B64=' .env; then`n"
        $alignScript += "  sed -i.bak `"s|^ED25519_PRIVATE_KEY_B64=.*|ED25519_PRIVATE_KEY_B64=`$DESIRED_PRIV|`" .env`n"
        $alignScript += "  echo 'priv_replaced'`n"
        $alignScript += "else`n"
        $alignScript += "  echo `"ED25519_PRIVATE_KEY_B64=`$DESIRED_PRIV`" >> .env`n"
        $alignScript += "  echo 'priv_added'`n"
        $alignScript += "fi`n"
        $alignScript += "if grep -q '^ED25519_PUBLIC_KEY_B64=' .env; then`n"
        $alignScript += "  sed -i.bak `"s|^ED25519_PUBLIC_KEY_B64=.*|ED25519_PUBLIC_KEY_B64=`$DESIRED_PUB|`" .env`n"
        $alignScript += "  echo 'pub_replaced'`n"
        $alignScript += "else`n"
        $alignScript += "  echo `"ED25519_PUBLIC_KEY_B64=`$DESIRED_PUB`" >> .env`n"
        $alignScript += "  echo 'pub_added'`n"
        $alignScript += "fi`n"
        $alignScript += "if grep -q '^AIDA_SIGN_DEBUG=' .env; then`n"
        $alignScript += "  sed -i.bak 's|^AIDA_SIGN_DEBUG=.*|AIDA_SIGN_DEBUG=1|' .env`n"
        $alignScript += "else`n"
        $alignScript += "  echo 'AIDA_SIGN_DEBUG=1' >> .env`n"
        $alignScript += "fi`n"
        $alignScript += "rm -f .env.bak`n"
        $alignScript += "chmod 600 .env`n"
        $alignLocal = "$env:TEMP\aida_align_keys.sh"
        [System.IO.File]::WriteAllText($alignLocal, $alignScript, [System.Text.UTF8Encoding]::new($false))
        & scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$alignLocal" "${REMOTE}:/tmp/aida_align_keys.sh"
        $alignOut = & ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no $REMOTE "bash /tmp/aida_align_keys.sh"
        Write-Host "      $alignOut" -ForegroundColor Green
    } else {
        Write-Host "[1b] Skipped key alignment (key files empty)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[1b] Skipped key alignment (server/keys/ed25519_*_b64.txt not found)" -ForegroundColor Yellow
}

# --- 2. Restart PM2 and smoke test via remote bash script ---
Write-Host "`n[2/3] Restarting PM2..." -ForegroundColor Yellow

# Build script with LF-only line endings (not CRLF) so bash can read it
$nl = "`n"
$script  = "#!/bin/bash$nl"
$script += "set -e$nl"
$script += "cd /home/ruarr/aida-server$nl"
$script += "set -a$nl"
$script += ". ./.env$nl"
$script += "set +a$nl"
$script += "psql `"`$DATABASE_URL`" -f db/schema.sql$nl"
$script += "pm2 restart aida-api --update-env 2>&1 | grep -E 'online|error|Done' || true$nl"
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
