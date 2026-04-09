#!/bin/bash
set -euo pipefail

API="http://localhost:3001"
KEY="AIDA-0084-48CE-B239-47A8"
HWID="2084C5F0BB4D5A24"
TS=$(date +%s)

echo "=== Validate real license key ==="
RESULT=$(curl -s -X POST "$API/validateLicense" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"validate\",\"license_key\":\"$KEY\",\"hwid\":\"$HWID\",\"client_nonce\":\"aabbccddeeff00112233445566778899\",\"timestamp\":$TS}")

echo "$RESULT" | python3 -m json.tool

STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))")
echo ""
if [ "$STATUS" = "valid" ]; then
    echo "SUCCESS: License validated!"
    
    # Extract session token for heartbeat test
    TOKEN=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_token',''))")
    echo ""
    echo "=== Heartbeat with real session ==="
    HB_NONCE=$(openssl rand -hex 16)
    HB_TS=$(date +%s)
    HB_RESULT=$(curl -s -X POST "$API/validateLicense" \
      -H "Content-Type: application/json" \
      -d "{\"action\":\"heartbeat\",\"license_key\":\"$KEY\",\"session_token\":\"$TOKEN\",\"hwid\":\"$HWID\",\"heartbeat_nonce\":\"$HB_NONCE\",\"timestamp\":$HB_TS}")
    echo "$HB_RESULT" | python3 -m json.tool
    
    HB_STATUS=$(echo "$HB_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))")
    if [ "$HB_STATUS" = "valid" ]; then
        echo ""
        echo "SUCCESS: Heartbeat valid!"
    else
        echo ""
        echo "FAIL: Heartbeat returned status=$HB_STATUS"
    fi
else
    echo "FAIL: Validate returned status=$STATUS"
fi
