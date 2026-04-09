#!/bin/bash
set -euo pipefail
cd ~/aida-server

ED25519_B64=$(cat keys/ed25519_private_b64.txt | tr -d '\n')
ARC_SECRET=$(openssl rand -hex 32 | tr -d '\n')

cat > .env << ENVEOF
DATABASE_URL=postgresql://ruar:EhF3NbwCQ4ch2NxtkqP7@localhost:5432/aida_db
ED25519_PRIVATE_KEY_B64=${ED25519_B64}
ARC_MASTER_SECRET=${ARC_SECRET}
DISCORD_WEBHOOK_URL=
ARC_BLOB_PATH=/home/ruarr/aida-server/arc/aida_core.bin
AIDA_BINARY_PATH=/home/ruarr/aida-server/bin/AiDA.exe
PORT=3001
NODE_ENV=production
ENVEOF

chmod 600 .env
echo "=== .env created successfully ==="
cat .env
echo "=== DONE ==="
