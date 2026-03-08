// ============================================================================
// AiDA License Validation — Firebase Cloud Function
// ============================================================================
//
// Deployed at:
//   https://europe-west1-aida-license-prod.cloudfunctions.net/validateLicense
//
// Accepts POST JSON with "action" field:
//   - "validate"   — Full license validation (cold start / activation)
//   - "heartbeat"  — Session keepalive during runtime
//
// All license decisions happen HERE, never on the client.
// ============================================================================

const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");

// Initialize Firebase Admin — uses Application Default Credentials when deployed
initializeApp();
const db = getDatabase();

// ─── Configuration ──────────────────────────────────────────────────────────

const SESSION_TTL_SECONDS  = 3600;        // 1 hour default session TTL
const MAX_TTL_SECONDS      = 86400;       // 24 hour maximum TTL
const RATE_LIMIT_WINDOW_MS = 60 * 1000;   // 1 minute window
const RATE_LIMIT_MAX_CALLS = 30;          // max calls per window per IP

// In-memory rate limiter (per Cloud Function instance)
const rateLimitMap = new Map();

// ─── Helpers ────────────────────────────────────────────────────────────────

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

function generateServerNonce() {
    return crypto.randomBytes(16).toString("hex");
}

/**
 * Simple per-instance rate limiter.
 * Returns true if the request should be BLOCKED.
 */
function isRateLimited(ip) {
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
        rateLimitMap.set(ip, { windowStart: now, count: 1 });
        return false;
    }

    entry.count++;
    if (entry.count > RATE_LIMIT_MAX_CALLS) {
        return true;
    }
    return false;
}

/**
 * Validate a license key against the RTDB.
 * Returns { valid, data } where data is the license record if valid.
 */
async function lookupLicense(licenseKey) {
    // Sanitize: only allow alphanumeric + dashes (AIDA-XXXX-XXXX-XXXX-XXXX format)
    if (!licenseKey || typeof licenseKey !== "string") {
        return { valid: false, reason: "missing_key" };
    }

    if (!/^[A-Za-z0-9\-]{10,40}$/.test(licenseKey)) {
        return { valid: false, reason: "invalid_format" };
    }

    const snapshot = await db.ref(`licenses/${licenseKey}`).once("value");
    const data = snapshot.val();

    if (!data) {
        return { valid: false, reason: "not_found" };
    }

    // Check if active
    if (!data.active) {
        return { valid: false, reason: "revoked", data };
    }

    // Check expiry
    if (data.expires && data.expires < todayStr()) {
        return { valid: false, reason: "expired", data };
    }

    return { valid: true, data };
}

/**
 * Verify HWID binding. If no HWID is bound, bind it.
 * Returns { ok, reason }
 */
async function verifyOrBindHwid(licenseKey, hwid, existingHwid) {
    if (!hwid || typeof hwid !== "string" || hwid.length < 8 || hwid.length > 256) {
        return { ok: false, reason: "invalid_hwid" };
    }

    if (!existingHwid || existingHwid === "") {
        // First activation — bind HWID
        await db.ref(`licenses/${licenseKey}/hwid`).set(hwid);
        return { ok: true, reason: "bound" };
    }

    if (existingHwid !== hwid) {
        return { ok: false, reason: "hwid_mismatch" };
    }

    return { ok: true, reason: "match" };
}

/**
 * Store/update session in RTDB under /sessions/{license_key}
 */
async function storeSession(licenseKey, sessionData) {
    await db.ref(`sessions/${licenseKey}`).set(sessionData);
}

/**
 * Read session from RTDB under /sessions/{license_key}
 */
async function getSession(licenseKey) {
    const snapshot = await db.ref(`sessions/${licenseKey}`).once("value");
    return snapshot.val();
}

// ─── Action: validate ───────────────────────────────────────────────────────

async function handleValidate(body, clientIp) {
    const { license_key, hwid, client_nonce, plugin_version } = body;

    // 1. Validate input
    if (!license_key || !hwid || !client_nonce) {
        return {
            status: 400,
            body: { status: "error", reason: "missing_fields" },
        };
    }

    if (typeof client_nonce !== "string" || client_nonce.length < 16 || client_nonce.length > 128) {
        return {
            status: 400,
            body: { status: "error", reason: "invalid_nonce" },
        };
    }

    // 2. Look up license
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: "invalid", reason: lookup.reason },
        };
    }

    const licenseData = lookup.data;

    // 3. Verify/bind HWID
    const hwidResult = await verifyOrBindHwid(
        license_key,
        hwid,
        licenseData.hwid || ""
    );

    if (!hwidResult.ok) {
        return {
            status: 200,
            body: { status: "invalid", reason: hwidResult.reason },
        };
    }

    // 4. Generate server-side session credentials
    const sessionToken = generateSessionToken();
    const serverNonce  = generateServerNonce();
    const issuedAt     = Math.floor(Date.now() / 1000);
    const ttl          = SESSION_TTL_SECONDS;

    // 5. Store session on the server
    const sessionData = {
        session_token: sessionToken,
        server_nonce:  serverNonce,
        issued_at:     issuedAt,
        ttl:           ttl,
        hwid:          hwid,
        ip:            clientIp,
        plugin_version: plugin_version || "unknown",
        last_heartbeat: issuedAt,
    };
    await storeSession(license_key, sessionData);

    // 6. Return response — client_nonce is echoed for anti-replay
    return {
        status: 200,
        body: {
            status:        "valid",
            plan:          licenseData.plan || "standard",
            session_token: sessionToken,
            ttl:           ttl,
            issued_at:     issuedAt,
            server_nonce:  serverNonce,
            client_nonce:  client_nonce,   // Echo back for anti-replay
        },
    };
}

// ─── Action: heartbeat ──────────────────────────────────────────────────────

async function handleHeartbeat(body, clientIp) {
    const { license_key, session_token, hwid } = body;

    // 1. Validate input
    if (!license_key || !session_token) {
        return {
            status: 400,
            body: { status: "error", reason: "missing_fields" },
        };
    }

    // 2. Look up license — re-verify it's still active
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: lookup.reason === "revoked" ? "revoked" : "invalid", reason: lookup.reason },
        };
    }

    // 3. Verify session token matches what's stored server-side
    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return {
            status: 200,
            body: { status: "invalid", reason: "session_mismatch" },
        };
    }

    // 4. Check session hasn't expired server-side
    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + (session.ttl * 2); // Grace: 2x TTL
        if (now > expiresAt) {
            return {
                status: 200,
                body: { status: "invalid", reason: "session_expired" },
            };
        }
    }

    // 5. HWID consistency check
    if (hwid && session.hwid && hwid !== session.hwid) {
        return {
            status: 200,
            body: { status: "invalid", reason: "hwid_mismatch" },
        };
    }

    // 6. Update last heartbeat timestamp
    await db.ref(`sessions/${license_key}/last_heartbeat`).set(now);

    // 7. Return success with refreshed TTL
    return {
        status: 200,
        body: {
            status: "valid",
            plan:   lookup.data.plan || "standard",
            ttl:    SESSION_TTL_SECONDS,
        },
    };
}

// ─── Main Entry Point ───────────────────────────────────────────────────────

exports.validateLicense = onRequest(
    {
        region: "europe-west1",
        maxInstances: 10,
        timeoutSeconds: 30,
        memory: "256MiB",
        invoker: "public",
    },
    async (req, res) => {
        // CORS headers — the plugin doesn't need these but useful for testing
        res.set("Access-Control-Allow-Origin", "*");
        res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type");

        if (req.method === "OPTIONS") {
            return res.status(204).send("");
        }

        // Only accept POST
        if (req.method !== "POST") {
            return res.status(405).json({ status: "error", reason: "method_not_allowed" });
        }

        // Rate limiting
        const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
                      || req.ip
                      || "unknown";

        if (isRateLimited(clientIp)) {
            return res.status(429).json({ status: "error", reason: "rate_limited" });
        }

        // Parse body
        const body = req.body;
        if (!body || typeof body !== "object") {
            return res.status(400).json({ status: "error", reason: "invalid_body" });
        }

        const action = body.action;

        try {
            let result;

            switch (action) {
                case "validate":
                    result = await handleValidate(body, clientIp);
                    break;

                case "heartbeat":
                    result = await handleHeartbeat(body, clientIp);
                    break;

                default:
                    return res.status(400).json({ status: "error", reason: "unknown_action" });
            }

            return res.status(result.status).json(result.body);

        } catch (err) {
            console.error(`[validateLicense] Error processing ${action}:`, err);
            return res.status(500).json({ status: "error", reason: "internal_error" });
        }
    }
);
