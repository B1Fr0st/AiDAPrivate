# AiDA Firebase Setup — Complete Guide

This walks you through deploying everything from zero.  
Your project ID is `aida-license-prod` and the region is `europe-west1`.

---

## Prerequisites

1. **Node.js 24+** — Download from https://nodejs.org  
2. **Firebase CLI** — Install it globally:
   ```
   npm install -g firebase-tools
   ```

---

## Step 1 — Log in to Firebase

```
firebase login
```

This opens a browser. Sign in with the Google account that owns the `aida-license-prod` project.

---

## Step 2 — Enable required APIs

Go to the Firebase Console (https://console.firebase.google.com) and make sure these are enabled for `aida-license-prod`:

1. **Realtime Database** — Already set up (your bot writes here)
2. **Authentication** → Sign-in method → Enable **Anonymous** sign-in
3. **Cloud Functions** — Requires the **Blaze (pay-as-you-go)** plan

### How to upgrade to Blaze:
- Firebase Console → Project Settings (gear icon) → Usage and billing → Modify plan → Select Blaze
- You will NOT be charged for small usage. Firebase has a generous free tier:
  - Cloud Functions: 2M invocations/month free
  - RTDB: 1GB stored, 10GB/month downloaded free
- You set a budget alert to avoid surprises

---

## Step 3 — Enable Anonymous Authentication

This is needed so the C++ plugin can get a proper ID token instead of using the database secret directly.

1. Firebase Console → Authentication → Sign-in method
2. Click **Add new provider**
3. Select **Anonymous**
4. Toggle it **ON**
5. Click **Save**

---

## Step 4 — Deploy the Security Rules

Navigate to the `firebase/` directory in your AiDA project:

```
cd C:\Users\diskt\AiDA\firebase
```

Deploy the database rules:

```
firebase deploy --only database
```

This replaces whatever rules you currently have. The new rules:
- `/licenses/{key}` — Read requires authentication, write is completely blocked (only your bot uses the database secret to bypass)
- `/sessions/` — No client reads or writes (only Cloud Functions with Admin SDK can access)
- Everything else — Blocked

> **Your Discord bot still works** because it uses the database secret (`?auth=secret`), which bypasses ALL security rules.

---

## Step 5 — Install Cloud Function dependencies

```
cd functions
npm install
cd ..
```

---

## Step 6 — Configure the Signing Secret

The license function now signs responses with an Ed25519 private key kept only in Firebase Secret Manager.
The matching local secret is stored in this ignored file:

```
C:\Users\diskt\AiDA\firebase\functions\.local-secrets\AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64.txt
```

Upload it to Firebase once:

```powershell
Get-Content C:\Users\diskt\AiDA\firebase\functions\.local-secrets\AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64.txt | firebase functions:secrets:set AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64
```

If you rotate this secret later, you must also update the embedded public key in `src/license.cpp`.

---

## Step 7 — Deploy the Cloud Function

```
firebase deploy --only functions
```

Expected output:
```
✔ functions: Finished running predeploy script.
✔ functions[validateLicense(europe-west1)] Successful create operation.

Function URL (validateLicense(europe-west1)):
  https://validatelicense-<deployment-id>-ew.a.run.app
```

Firebase 2nd-gen functions usually print a `run.app` URL now. The plugin uses the stable
`cloudfunctions.net` hostname and follows redirects, so either of these is valid:

- `https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense`
- The `run.app` URL shown by `firebase deploy`

You're done deploying.

---

## Step 8 — Test it

### Test with an invalid key in Windows PowerShell:
```
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body = @{
  action = "validate"
  license_key = "FAKE-KEY"
  hwid = "test123456"
  client_nonce = "aabbccdd11223344aabbccdd11223344"
  timestamp = $ts
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method POST `
  -Uri "https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense" `
  -ContentType "application/json" `
  -Body $body
```

Expected response:
```json
{"status":"invalid","reason":"not_found"}
```

### Test with a real key in Windows PowerShell (replace `AIDA-XXXX-...` with an actual key from your bot):
```
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body = @{
  action = "validate"
  license_key = "AIDA-XXXX-XXXX-XXXX-XXXX"
  hwid = "test123456"
  client_nonce = "aabbccdd11223344aabbccdd11223344"
  timestamp = $ts
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method POST `
  -Uri "https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense" `
  -ContentType "application/json" `
  -Body $body
```

Expected response:
```json
{
  "status": "valid",
  "license_key": "AIDA-XXXX-XXXX-XXXX-XXXX",
  "hwid": "test123456",
  "plan": "pro",
  "session_token": "a1b2c3d4...(64 hex chars)",
  "ttl": 3600,
  "issued_at": 1741392000,
  "server_nonce": "e5f6a7b8...(32 hex chars)",
  "client_nonce": "aabbccdd11223344aabbccdd11223344",
  "signature": "ed25519-signature-hex"
}
```

If you prefer `curl.exe` in PowerShell, pass the JSON body through a variable instead of using cmd.exe escaping:

```
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body = @{
  action = "validate"
  license_key = "FAKE-KEY"
  hwid = "test123456"
  client_nonce = "aabbccdd11223344aabbccdd11223344"
  timestamp = $ts
} | ConvertTo-Json -Compress

curl.exe -X POST "https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense" `
  -H "Content-Type: application/json" `
  --data-raw $body
```

The `timestamp` must be current. The server rejects requests with more than 5 minutes of clock drift.

---

## How It All Fits Together

```
┌─────────────────────┐
│   IDA Pro + AiDA    │  (the C++ plugin)
│                     │
│  1. POST /validate  │────────────────────┐
│  2. POST /heartbeat │───────────┐        │
└─────────────────────┘           │        │
                                  │        │
         ┌────────────────────────▼────────▼───────────┐
         │  Cloud Function: validateLicense             │
         │  (europe-west1-aida-license-prod)           │
         │                                              │
         │  • Reads /licenses/{key} from RTDB          │
         │  • Checks active, expires, hwid             │
         │  • Issues session_token                     │
         │  • Stores session in /sessions/{key}        │
         │  • Returns plan, TTL, nonces                │
         └──────────────┬──────────────────────────────┘
                        │
                        │ Firebase Admin SDK (full access)
                        │
         ┌──────────────▼──────────────────────────────┐
         │  Firebase Realtime Database                  │
         │                                              │
         │  /licenses/AIDA-XXXX-XXXX-XXXX-XXXX         │
         │    ├── active: true                         │
         │    ├── expires: "2026-12-31"                │
         │    ├── plan: "pro"                          │
         │    ├── hwid: "abc123..."                    │
         │    ├── note: "CustomerName"                 │
         │    └── created: "2026-03-01"                │
         │                                              │
         │  /sessions/AIDA-XXXX-XXXX-XXXX-XXXX         │
         │    ├── session_token: "a1b2c3..."           │
         │    ├── server_nonce: "e5f6..."              │
         │    ├── issued_at: 1741392000                │
         │    ├── ttl: 3600                            │
         │    ├── hwid: "abc123..."                    │
         │    ├── ip: "1.2.3.4"                        │
         │    └── last_heartbeat: 1741395600           │
         └─────────────────────────────────────────────┘

         ┌─────────────────────┐
         │  Discord Bot        │  (your existing bot.js)
         │                     │
         │  Uses DB secret to  │
         │  /generate, /revoke │──── Writes directly to /licenses/
         │  /reset_hwid, etc.  │     (bypasses security rules)
         └─────────────────────┘
```

---

## Firebase Console — Quick Navigation Guide

### Where things are in the console (https://console.firebase.google.com):

| What | Where to find it |
|------|-----------------|
| **Your project** | Click `aida-license-prod` on the home screen |
| **Realtime Database** | Left sidebar → Build → Realtime Database |
| **View license data** | Realtime Database → click `/licenses` → expand any key |
| **View sessions** | Realtime Database → click `/sessions` |
| **Security Rules** | Realtime Database → Rules tab |
| **Authentication** | Left sidebar → Build → Authentication |
| **Anonymous auth** | Authentication → Sign-in method → Anonymous |
| **Cloud Functions** | Left sidebar → Build → Functions |
| **Function logs** | Functions → click `validateLicense` → Logs tab |
| **Billing** | Left sidebar → gear icon → Usage and billing |
| **API keys** | Google Cloud Console → APIs & Services → Credentials |

### How to see function logs (for debugging):
1. Firebase Console → Functions
2. Click the `validateLicense` function name
3. Click the "Logs" tab
4. You'll see every request with timestamps and any `console.error` output

---

## Common Operations

### Redeploy after editing the function:
```
cd C:\Users\diskt\AiDA\firebase
firebase deploy --only functions
```

### View function logs from terminal:
```
firebase functions:log --only validateLicense
```

### Test locally before deploying:
```
cd C:\Users\diskt\AiDA\firebase
firebase emulators:start --only functions,database
```
This starts a local emulator at `http://127.0.0.1:5001/aida-license-prod/europe-west1/validateLicense`

### Update security rules only:
```
cd C:\Users\diskt\AiDA\firebase
firebase deploy --only database
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `firebase deploy` says "billing required" | Upgrade to Blaze plan in Firebase Console |
| `firebase deploy` says "permission denied" | Run `firebase login` again, make sure you're signed in as the project owner |
| Plugin gets `validate_with_cloud_function` returning false | Check function logs in Firebase Console. Most likely the license key doesn't exist in RTDB |
| Function returns `500 Internal Server Error` for every key | Confirm the function was deployed with an explicit `databaseURL`; otherwise the Admin SDK cannot open RTDB in some 2nd-gen environments |
| `ERR_CONNECTION_REFUSED` locally | The function URL is wrong, or function isn't deployed. Check `firebase deploy` output |
| Bot stops working after rule deploy | It won't — the database secret bypasses all rules. But verify `FIREBASE_SECRET` env var is set |
| HWID mismatch error | Use `/reset_hwid` in Discord to clear the binding, then re-activate from IDA |

---

## Security Notes

- The **database secret** (`bWLmMKBhD3TE7iYMnKizIjOrt4jXd9R1m0CVCj6P`) is used by your Discord bot to bypass security rules. This is expected and correct — it's an admin credential.
- The **Web API key** used by the C++ plugin is only for Firebase Anonymous Auth — it cannot read/write the database without first authenticating, and the security rules restrict what authenticated users can do.
- The **Cloud Function** uses the Firebase Admin SDK which automatically has full database access. No credentials needed in the function code — Firebase handles it.
- `/sessions/` is completely locked down in rules. Only the Cloud Function (Admin SDK) can read/write sessions. Clients cannot forge session tokens.
