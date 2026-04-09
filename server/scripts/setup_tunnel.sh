#!/bin/bash
set -euo pipefail

TUNNEL_ID="daeed9f1-bbac-4f69-813d-de2fc48aa513"

mkdir -p ~/.cloudflared

cat > ~/.cloudflared/config.yml << EOF
tunnel: ${TUNNEL_ID}
credentials-file: /home/ruarr/.cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: aidapro.net
    service: http://localhost:3001
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

echo "=== Cloudflare tunnel config ==="
cat ~/.cloudflared/config.yml
echo ""
echo "=== Config created successfully ==="
