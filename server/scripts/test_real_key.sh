#!/bin/bash
set -euo pipefail

API="http://localhost:3001"
KEY="${AIDA_TEST_LICENSE_KEY:-}"
HWID="${AIDA_TEST_HWID:-}"
TS=$(date +%s)

if [ -z "$KEY" ] || [ -z "$HWID" ]; then
    echo "Set AIDA_TEST_LICENSE_KEY and AIDA_TEST_HWID before running this helper."
    exit 2
fi

redact_json() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); [data.__setitem__(k,"[REDACTED]") for k in ("license_key","session_token","server_nonce","heartbeat_nonce") if k in data and data[k]]; print(json.dumps(data, indent=2))'
}

echo "=== Validate configured license key ==="
RESULT=$(curl -s -X POST "$API/validateLicense" \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"validate\",\"license_key\":\"$KEY\",\"hwid\":\"$HWID\",\"client_nonce\":\"aabbccddeeff00112233445566778899\",\"timestamp\":$TS}")

echo "$RESULT" | redact_json

STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))")
echo ""
if [ "$STATUS" = "valid" ]; then
    echo "SUCCESS: License validated!"
    
    # Extract session token for heartbeat test
    TOKEN=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_token',''))")
    echo ""
    echo "=== Heartbeat with configured session ==="
    HB_NONCE=$(openssl rand -hex 16)
    HB_TS=$(date +%s)
    HB_RESULT=$(curl -s -X POST "$API/validateLicense" \
      -H "Content-Type: application/json" \
      -d "{\"action\":\"heartbeat\",\"license_key\":\"$KEY\",\"session_token\":\"$TOKEN\",\"hwid\":\"$HWID\",\"heartbeat_nonce\":\"$HB_NONCE\",\"timestamp\":$HB_TS}")
    echo "$HB_RESULT" | redact_json
    
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
