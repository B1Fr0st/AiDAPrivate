#!/bin/bash
set -euo pipefail

ENV_FILE="$HOME/aida-server/.env"

# Add/update DISCORD_WEBHOOK_URL
if grep -q '^DISCORD_WEBHOOK_URL=' "$ENV_FILE"; then
    sed -i 's|^DISCORD_WEBHOOK_URL=.*|DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1487822472207138869/nXIS-mL2ExeO_mRKEHOGUGyw-N8gtLRsKrNSn2zxTtsFQysVVC0CekF238oDbx7WmRGA|' "$ENV_FILE"
    echo "Updated DISCORD_WEBHOOK_URL in .env"
else
    echo 'DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1487822472207138869/nXIS-mL2ExeO_mRKEHOGUGyw-N8gtLRsKrNSn2zxTtsFQysVVC0CekF238oDbx7WmRGA' >> "$ENV_FILE"
    echo "Added DISCORD_WEBHOOK_URL to .env"
fi

echo ""
echo "=== Current .env ==="
cat "$ENV_FILE"

echo ""
echo "=== Restarting PM2 ==="
cd ~/aida-server
pm2 restart aida-api
pm2 logs aida-api --lines 5 --nostream
