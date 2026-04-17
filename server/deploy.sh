#!/bin/bash
# ============================================================================
# AiDA License Server — Deployment Script
# ============================================================================
# Run this script on the Ubuntu server (23.88.62.199 / aidapro.net) as ruarr.
#
# Prerequisites (your friend must install these first):
#   - Node.js 20+, npm, PostgreSQL 16, Nginx, Certbot, PM2
#   - PostgreSQL database 'aida_prod' with user 'aida_api'
#   - DNS: aidapro.net → 23.88.62.199
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()  { echo -e "${CYAN}[deploy]${NC} $*"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $*"; }
fail() { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

# ─── Preflight Checks ───────────────────────────────────────────────────

log "Running preflight checks..."

command -v node   >/dev/null 2>&1 || fail "Node.js not found. Ask server admin to install: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - && sudo apt install -y nodejs"
command -v npm    >/dev/null 2>&1 || fail "npm not found."
command -v psql   >/dev/null 2>&1 || fail "psql not found. Ask server admin to install: sudo apt install -y postgresql-client"
command -v pm2    >/dev/null 2>&1 || fail "PM2 not found. Install with: sudo npm install -g pm2"
command -v nginx  >/dev/null 2>&1 || fail "Nginx not found. Ask server admin to install: sudo apt install -y nginx"

NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VER" -lt 18 ]; then
    fail "Node.js version must be 18+. Current: $(node -v)"
fi
ok "Node.js $(node -v)"
ok "npm $(npm -v)"
ok "PM2 $(pm2 -v 2>/dev/null || echo 'installed')"

# ─── Create Directory Structure ──────────────────────────────────────────

log "Creating directory structure..."

sudo mkdir -p /opt/aida/{api,arc,bin,keys,logs}
sudo chown -R $(whoami):$(whoami) /opt/aida
chmod 750 /opt/aida /opt/aida/api /opt/aida/arc /opt/aida/bin /opt/aida/logs
chmod 700 /opt/aida/keys

sudo mkdir -p /var/log/aida
sudo chown $(whoami):$(whoami) /var/log/aida

ok "Directory structure created at /opt/aida/"

# ─── Deploy API Server ───────────────────────────────────────────────────

log "Deploying API server to /opt/aida/api/..."

# Copy server files (assumes this script is in the server/ directory)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/server.js" ]; then
    cp "$SCRIPT_DIR/server.js"          /opt/aida/api/
    cp "$SCRIPT_DIR/package.json"       /opt/aida/api/
    cp "$SCRIPT_DIR/ecosystem.config.js" /opt/aida/api/
    cp -r "$SCRIPT_DIR/routes/"         /opt/aida/api/
    cp -r "$SCRIPT_DIR/crypto/"         /opt/aida/api/
    cp -r "$SCRIPT_DIR/db/"             /opt/aida/api/
    cp -r "$SCRIPT_DIR/scripts/"        /opt/aida/api/
    ok "Server files copied"
else
    warn "server.js not found in $SCRIPT_DIR — make sure to copy server files to /opt/aida/api/ manually"
fi

# ─── Install Dependencies ────────────────────────────────────────────────

log "Installing npm dependencies..."
cd /opt/aida/api
npm install --production
ok "Dependencies installed"

# ─── Generate Ed25519 Keys (if not already present) ──────────────────────

if [ ! -f /opt/aida/keys/ed25519_private.pem ]; then
    log "Generating Ed25519 signing key pair..."
    node /opt/aida/api/scripts/generate-keys.js /opt/aida/keys
    chmod 600 /opt/aida/keys/*
    ok "Ed25519 keys generated in /opt/aida/keys/"
    echo ""
    echo "=========================================="
    echo "  IMPORTANT: Save the private key B64 value above"
    echo "  and paste it into /opt/aida/api/.env as ED25519_PRIVATE_KEY_B64"
    echo "=========================================="
    echo ""
else
    ok "Ed25519 keys already exist in /opt/aida/keys/"
fi

# ─── Generate ARC Master Secret (if needed) ─────────────────────────────

if [ ! -f /opt/aida/api/.env ]; then
    log "Creating .env from template..."

    ARC_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    ED25519_B64=""
    if [ -f /opt/aida/keys/ed25519_private_b64.txt ]; then
        ED25519_B64=$(cat /opt/aida/keys/ed25519_private_b64.txt)
    fi

    cat > /opt/aida/api/.env << ENVEOF
# AiDA License Server — Production Environment
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

DATABASE_URL=postgresql://aida_api:CHANGEME@localhost:5432/aida_prod
ED25519_PRIVATE_KEY_B64=${ED25519_B64}
ARC_MASTER_SECRET=${ARC_SECRET}
DISCORD_WEBHOOK_URL=
ARC_BLOB_PATH=/opt/aida/arc/aida_core.bin
AIDA_BINARY_PATH=/opt/aida/bin/AiDA.exe
PORT=3001
NODE_ENV=production
ENVEOF

    chmod 600 /opt/aida/api/.env
    ok ".env created with auto-generated ARC_MASTER_SECRET"
    warn "EDIT /opt/aida/api/.env to set DATABASE_URL password and DISCORD_WEBHOOK_URL"
else
    ok ".env already exists"
fi

# ─── Database Migration ──────────────────────────────────────────────────

log "Running database schema migration..."
if [ -f /opt/aida/api/db/schema.sql ]; then
    # Source .env for DATABASE_URL
    set -a
    source /opt/aida/api/.env
    set +a

    psql "$DATABASE_URL" -f /opt/aida/api/db/schema.sql 2>&1 && ok "Database schema applied" || warn "Schema migration had warnings (tables may already exist)"
else
    warn "schema.sql not found — run manually: psql \$DATABASE_URL -f db/schema.sql"
fi

# ─── Self-Signed SSL (temporary, until Certbot) ─────────────────────────

if [ ! -f /etc/ssl/certs/aida-selfsigned.crt ]; then
    log "Generating self-signed SSL certificate (temporary)..."
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/aida-selfsigned.key \
        -out /etc/ssl/certs/aida-selfsigned.crt \
        -subj "/CN=aidapro.net/O=AiDA/C=US" 2>/dev/null
    ok "Self-signed certificate generated"
else
    ok "SSL certificate already exists"
fi

# ─── Nginx Configuration ────────────────────────────────────────────────

log "Setting up Nginx..."
if [ -f "$SCRIPT_DIR/nginx/aida-api.conf" ]; then
    sudo cp "$SCRIPT_DIR/nginx/aida-api.conf" /etc/nginx/sites-available/aida-api
elif [ -f /opt/aida/api/nginx/aida-api.conf ]; then
    # Try from deployed location
    true
fi

# If the config file exists in sites-available, link it
if [ -f /etc/nginx/sites-available/aida-api ]; then
    sudo ln -sf /etc/nginx/sites-available/aida-api /etc/nginx/sites-enabled/aida-api
    sudo rm -f /etc/nginx/sites-enabled/default

    sudo nginx -t 2>&1 && {
        sudo systemctl reload nginx
        ok "Nginx configured and reloaded"
    } || {
        warn "Nginx config test failed — check /etc/nginx/sites-available/aida-api"
    }
else
    warn "Nginx config not found — copy server/nginx/aida-api.conf to /etc/nginx/sites-available/aida-api"
fi

# ─── Start API with PM2 ─────────────────────────────────────────────────

log "Starting API server with PM2..."
cd /opt/aida/api

# Stop existing instance if running
pm2 delete aida-api 2>/dev/null || true

pm2 start ecosystem.config.js
pm2 save

ok "API server started via PM2"

# ─── Setup PM2 Startup (requires sudo) ──────────────────────────────────

log "Configuring PM2 auto-start on boot..."
pm2 startup 2>&1 | grep "sudo" | bash 2>/dev/null || warn "PM2 startup setup needs sudo — run the command PM2 suggested above"
pm2 save
ok "PM2 startup configured"

# ─── Final Status ────────────────────────────────────────────────────────

echo ""
echo "============================================================================"
echo "  AiDA License Server — Deployment Complete"
echo "============================================================================"
echo ""
echo "  Server:   https://aidapro.net (23.88.62.199)"
echo "  API Port: 3001 (proxied via Nginx on 443)"
echo "  PM2 Name: aida-api"
echo ""
echo "  Endpoints:"
echo "    POST /validateLicense     — License validation & heartbeat"
echo "    POST /api/download/arc    — ARC DLL delivery (session-encrypted)"
echo "    GET  /api/download/aida   — AiDA binary (watermarked per-user)"
echo "    GET  /health              — Health check"
echo ""
echo "  ── Remaining Manual Steps ──────────────────────────────────────"
echo ""
echo "  1. Edit /opt/aida/api/.env — set DATABASE_URL password, DISCORD_WEBHOOK_URL"
echo "  2. Upload ARC blob:  scp aida_core.bin ruarr@aidapro.net:/opt/aida/arc/"
echo "  3. Upload AiDA.exe:  scp AiDA.exe ruarr@aidapro.net:/opt/aida/bin/"
echo "  4. After DNS propagates: sudo certbot --nginx -d aidapro.net"
echo "  5. Test: curl -k https://aidapro.net/health"
echo "  6. Restart after .env changes: pm2 restart aida-api"
echo ""
echo "  ── Encrypt ARC DLL for at-rest storage ────────────────────────"
echo "  ARC_MASTER_SECRET=\$(grep ARC_MASTER_SECRET /opt/aida/api/.env | cut -d= -f2) \\"
echo "    node /opt/aida/api/scripts/encrypt-arc.js /path/to/aida_core.dll /opt/aida/arc/aida_core.bin"
echo ""
echo "============================================================================"
