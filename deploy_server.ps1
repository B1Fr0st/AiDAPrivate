# AiDA Server Deploy Script
# Usage: .\deploy_server.ps1            # default; skips pg_hba.conf provisioning
#        .\deploy_server.ps1 -ProvisionPgHba   # also re-whitelists the operator's current IP for the bot (will prompt for ruarr's password once)

param(
    [switch]$ProvisionPgHba
)

$REMOTE  = "ruarr@23.88.62.199"
$SRC     = (Join-Path $PSScriptRoot "server") + "\"
$DST     = "/home/ruarr/aida-server/"
$AIDA_KEY = Join-Path $env:USERPROFILE ".ssh\aida_server"
$SSH_OPTS = @('-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no', '-i', $AIDA_KEY)

Write-Host "`n=== Deploying server/ to $REMOTE ===" -ForegroundColor Cyan

# --- 1. Upload source files ---
Write-Host "`n[1/3] Uploading files..." -ForegroundColor Yellow
$files = @(
    ".env.example",
    "server.js",
    "routes\license.js",
    "routes\download.js",
    "routes\sentinel.js",
    "routes\telemetry.js",
    "routes\functions.js",
    "routes\attestation.js",
    "routes\stolen_bytes.js",
    "routes\server_info.js",
    "routes\bootstrap.js",
    "nginx\aida-api.conf",
    "crypto\signing.js",
    "crypto\arc-encrypt.js",
    "crypto\arc-license-bind.js",
    "crypto\kw_wrap.js",
    "crypto\tls_exporter.js",
    "crypto\column_crypt.js",
    "crypto\local_hsm.js",
    "crypto\page_keys.js",
    "crypto\binary_protocol.js",
    "crypto\tpm_quote.js",
    "crypto\ek_roots.js",
    "crypto\session_aead.js",
    "crypto\canonical_response.js",
    "crypto\key_format.js",
    "crypto\peer_code_hash.js",
    "middleware\hmac_auth.js",
    "middleware\rate_limit.js",
    "middleware\audit_log.js",
    "middleware\license_rate_limit.js",
    "middleware\bot_auth.js",
    "middleware\replay_counter.js",
    "middleware\session_ratchet.js",
    "middleware\kill_switch.js",
    "anomaly\model.js",
    "anomaly\score.js",
    "db\pool.js",
    "db\migrate.js",
    "db\schema.sql",
    "db\migrations\0001_auth_redesign.sql",
    "db\migrations\0002_strict_replay_ratchet.sql",
    "db\migrations\0003_peer_attestation_ratchet.sql",
    "db\migrations\0004_oracle_audit_killswitch.sql",
    "db\migrations\0006_bootstrap_delivery.sql",
    "scripts\create_bootstrap_package.js"
)
$remoteDirs = @("routes", "crypto", "middleware", "anomaly", "db", "db/migrations", "nginx", "scripts", "bootstrap_artifacts") | ForEach-Object { "$DST$_" }
$mkdirCmd = "mkdir -p " + ($remoteDirs -join " ")
& ssh @SSH_OPTS $REMOTE $mkdirCmd | Out-Null
foreach ($f in $files) {
    $local = Join-Path $SRC $f
    $remotePath = $DST + ($f -replace '\\', '/')
    if (Test-Path $local) {
        & scp @SSH_OPTS "$local" "${REMOTE}:${remotePath}"
        if ($LASTEXITCODE -ne 0) { Write-Host "SCP failed for $f" -ForegroundColor Red; exit 1 }
    } else {
        Write-Host "  [WARN] missing local file: $local" -ForegroundColor Yellow
    }
}
$artifactDir = Join-Path $SRC "bootstrap_artifacts"
if (Test-Path $artifactDir) {
    $artifactFiles = Get-ChildItem -LiteralPath $artifactDir -Filter "*.pkg" -File -ErrorAction SilentlyContinue
    foreach ($artifact in $artifactFiles) {
        & scp @SSH_OPTS $artifact.FullName "${REMOTE}:${DST}bootstrap_artifacts/$($artifact.Name)"
        if ($LASTEXITCODE -ne 0) { Write-Host "SCP failed for bootstrap artifact $($artifact.Name)" -ForegroundColor Red; exit 1 }
    }
    if ($artifactFiles.Count -gt 0) {
        Write-Host "      Uploaded $($artifactFiles.Count) encrypted bootstrap artifact(s)." -ForegroundColor Green
    }
}
Write-Host "      Done." -ForegroundColor Green

Write-Host "`n[1b] Skipping signing-key alignment; production signing keys are managed on the server." -ForegroundColor DarkGray

# --- 1c. Provision pg_hba.conf for the operator's IP (so the Discord bot can connect) ---
# pg_hba.conf is owned by the postgres group (mode 0640); editing it requires sudo on
# the remote box. ruarr does not have passwordless sudo, so this step uses an interactive
# TTY (ssh -t) and you will be prompted for ruarr's password once during deploy.
# Default-skipped; pass -ProvisionPgHba when your IP changed or the bot can't reach Postgres.
if (-not $ProvisionPgHba) {
    Write-Host "`n[1c] Skipping pg_hba.conf provisioning (pass -ProvisionPgHba to enable)" -ForegroundColor DarkGray
} else {
Write-Host "`n[1c] Ensuring pg_hba.conf has a hostssl entry for the bot..." -ForegroundColor Yellow
$pgHbaScript = @'
#!/bin/bash
set -e
SRC_IP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
if [ -z "$SRC_IP" ]; then
    echo "[ERR] SSH_CLIENT not set; cannot derive operator IP"
    exit 1
fi
echo "[info] operator IP (from SSH_CLIENT): $SRC_IP"

HBA_FILE="/etc/postgresql/16/main/pg_hba.conf"
if ! sudo test -f "$HBA_FILE"; then
    HBA_FILE=$(sudo ls -1 /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -1 || true)
fi
if [ -z "$HBA_FILE" ] || ! sudo test -f "$HBA_FILE"; then
    echo "[ERR] could not locate pg_hba.conf"
    exit 1
fi
echo "[info] pg_hba.conf path: $HBA_FILE"

AUTH=$(sudo grep -E "^(host|hostssl|local)[[:space:]]+(aida_db|all)[[:space:]]+ruar\b" "$HBA_FILE" | head -1 | awk '{print $NF}')
if [ -z "$AUTH" ]; then
    AUTH="scram-sha-256"
fi

DESIRED_LINE="hostssl aida_db ruar ${SRC_IP}/32 $AUTH"

if sudo grep -qE "^hostssl[[:space:]]+aida_db[[:space:]]+ruar[[:space:]]+${SRC_IP//./\\.}/32[[:space:]]" "$HBA_FILE"; then
    echo "[ok] pg_hba entry already present for ${SRC_IP}/32"
    exit 0
fi

TS=$(date +%Y%m%d%H%M%S)
sudo cp "$HBA_FILE" "${HBA_FILE}.bak.${TS}"
echo "$DESIRED_LINE" | sudo tee -a "$HBA_FILE" >/dev/null
echo "[info] appended: $DESIRED_LINE"

if sudo systemctl reload postgresql 2>&1; then
    echo "[ok] postgresql reloaded; bot should now connect from ${SRC_IP}"
else
    echo "[ERR] reload failed; rolling back"
    sudo cp "${HBA_FILE}.bak.${TS}" "$HBA_FILE"
    sudo systemctl reload postgresql 2>&1 || true
    exit 1
fi
'@
$pgHbaLocal = "$env:TEMP\aida_pg_hba_provision.sh"
[System.IO.File]::WriteAllText($pgHbaLocal, $pgHbaScript, [System.Text.UTF8Encoding]::new($false))
& scp @SSH_OPTS "$pgHbaLocal" "${REMOTE}:/tmp/aida_pg_hba_provision.sh" | Out-Null
$pgHbaSshOpts = $SSH_OPTS + @('-t')
& ssh @pgHbaSshOpts $REMOTE "bash /tmp/aida_pg_hba_provision.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Host "      pg_hba provisioning step failed (continuing; bot may stay broken)" -ForegroundColor Red
} else {
    Write-Host "      Done." -ForegroundColor Green
}
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
$script += "for migration in db/migrations/*.sql; do$nl"
$script += "  if [ -f `"`$migration`" ]; then$nl"
$script += "    echo `"[migrate] applying `$migration`"$nl"
$script += "    psql `"`$DATABASE_URL`" -f `"`$migration`"$nl"
$script += "  fi$nl"
$script += "done$nl"
$script += "pm2 restart aida-api --update-env 2>&1 | tail -5$nl"
$script += "for i in 1 2 3 4 5 6 7 8; do$nl"
$script += "  sleep 2$nl"
$script += "  H=`$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3001/health || echo '000')$nl"
$script += "  if [ `"`$H`" = '200' ]; then break; fi$nl"
$script += "done$nl"
$script += "echo '[health]'$nl"
$script += "curl -s http://localhost:3001/health || echo 'curl_failed'$nl"
$script += "echo$nl"
$script += "if ! curl -s -f http://localhost:3001/health > /dev/null; then$nl"
$script += "  echo '[pm2 status]'$nl"
$script += "  pm2 status aida-api$nl"
$script += "  echo '[pm2 logs - last 60]'$nl"
$script += "  pm2 logs aida-api --lines 60 --nostream$nl"
$script += "  exit 0$nl"
$script += "fi$nl"
$script += "echo '[bootstrap]'$nl"
$script += "BOOT_PATH=`$(awk -F= '/^AIDA_BOOTSTRAP_SCRIPT_PATH=/{print `$2}' .env 2>/dev/null | tail -1)$nl"
$script += "if [ -n `"`$BOOT_PATH`" ]; then$nl"
$script += "  curl -s -o /dev/null -w 'bootstrap_script_http=%{http_code}\n' `"http://localhost:3001`${BOOT_PATH}`" || echo 'bootstrap_script_http=000'$nl"
$script += "else$nl"
$script += "  curl -s -H 'Accept: application/vnd.aida.bootstrap' -o /dev/null -w 'bootstrap_script_http=%{http_code}\n' http://localhost:3001/ || echo 'bootstrap_script_http=000'$nl"
$script += "fi$nl"
$script += "echo$nl"

$localScript = "$env:TEMP\aida_deploy.sh"
[System.IO.File]::WriteAllText($localScript, $script, [System.Text.UTF8Encoding]::new($false))

& scp @SSH_OPTS "$localScript" "${REMOTE}:/tmp/aida_deploy.sh"
$output = & ssh @SSH_OPTS $REMOTE "bash /tmp/aida_deploy.sh"
$licenseKeyRegex = [regex]::new('AIDA-[A-Z0-9][A-Z0-9-]*')
$safeOutput = $output | ForEach-Object { $licenseKeyRegex.Replace(('' + $_), 'AIDA-[REDACTED]') }
Write-Host $safeOutput

if ($output -like '*"status":"ok"*') {
    Write-Host "`nDeploy complete." -ForegroundColor Green
} else {
    Write-Host "`nSomething looks off - check server logs above." -ForegroundColor Yellow
}
