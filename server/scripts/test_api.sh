#!/bin/bash
set -euo pipefail

API="http://localhost:3001"
NOW=$(date +%s)

echo "=== 1. Health Check ==="
curl -s "$API/health"
echo ""

echo ""
echo "=== 2. Validate (bad key — should return not_found) ==="
curl -s -X POST "$API/validateLicense" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"validate\",\"license_key\":\"FAKE-KEY-12345\",\"hwid\":\"0000000000000000\",\"client_nonce\":\"aabbccddeeff0011aabbccddeeff0011\",\"timestamp\":$NOW}"
echo ""

echo ""
echo "=== 3. Heartbeat (bad session — should return missing_fields) ==="
curl -s -X POST "$API/validateLicense" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"heartbeat\",\"license_key\":\"FAKE-KEY\",\"session_token\":\"deadbeef\",\"hwid\":\"0000\",\"heartbeat_nonce\":\"aabbccddeeff0011\",\"timestamp\":$NOW}"
echo ""

echo ""
echo "=== 4. ARC Download (bad session — should return 403) ==="
curl -s -X POST "$API/api/download/arc" \
  -H "Content-Type: application/json" \
  -d "{\"license_key\":\"FAKE\",\"session_token\":\"deadbeef\",\"hwid\":\"0000\"}"
echo ""

echo ""
echo "=== 5. 404 catch-all ==="
curl -s "$API/nonexistent"
echo ""

echo ""
echo "=== 6. DB Connection Test (count licenses) ==="
psql 'postgresql://ruar:EhF3NbwCQ4ch2NxtkqP7@localhost:5432/aida_db' -t -c 'SELECT COUNT(*) FROM licenses;'

echo ""
echo "=== ALL TESTS DONE ==="
