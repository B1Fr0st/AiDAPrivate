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
const { defineSecret } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");

// Initialize Firebase Admin with an explicit RTDB URL.
// 2nd-gen runtimes do not always expose enough metadata for getDatabase()
// to infer the database URL automatically.
const FIREBASE_DB_URL =
    process.env.AIDA_FIREBASE_DB_URL ||
    "https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app";

initializeApp({ databaseURL: FIREBASE_DB_URL });
const db = getDatabase();

// ─── Configuration ──────────────────────────────────────────────────────────

const SESSION_TTL_SECONDS  = 3600;        // 1 hour default session TTL
const MAX_TTL_SECONDS      = 86400;       // 24 hour maximum TTL
const RATE_LIMIT_WINDOW_MS = 60 * 1000;   // 1 minute window
const RATE_LIMIT_MAX_CALLS = 30;          // max calls per window per IP

const LICENSE_SIGNING_PRIVATE_KEY_B64 = defineSecret("AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64");
let cachedSigningPrivateKey = null;

// Discord Webhook URL for violation/ban logging
const DISCORD_WEBHOOK_URL = process.env.AIDA_DISCORD_WEBHOOK || "https://discord.com/api/webhooks/1487822472207138869/nXIS-mL2ExeO_mRKEHOGUGyw-N8gtLRsKrNSn2zxTtsFQysVVC0CekF238oDbx7WmRGA";

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

function sortObjectKeys(payloadObj) {
    return Object.keys(payloadObj).sort().reduce((obj, key) => {
        obj[key] = payloadObj[key];
        return obj;
    }, {});
}

function getSigningPrivateKey() {
    if (cachedSigningPrivateKey) {
        return cachedSigningPrivateKey;
    }

    const secretValue =
        process.env.AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64 ||
        LICENSE_SIGNING_PRIVATE_KEY_B64.value();

    if (!secretValue || typeof secretValue !== "string") {
        throw new Error("Missing AIDA_LICENSE_SIGNING_PRIVATE_KEY_B64 secret");
    }

    cachedSigningPrivateKey = crypto.createPrivateKey({
        key: Buffer.from(secretValue, "base64"),
        format: "der",
        type: "pkcs8",
    });

    return cachedSigningPrivateKey;
}

function isHexNonce(value, minLength = 16, maxLength = 128) {
    return typeof value === "string"
        && value.length >= minLength
        && value.length <= maxLength
        && /^[a-fA-F0-9]+$/.test(value);
}

function sanitizeReason(reason) {
    return typeof reason === "string"
        ? reason.slice(0, 128).replace(/[^a-zA-Z0-9_ :\-]/g, "")
        : "unknown";
}

/**
 * Compute an Ed25519 signature over a canonical JSON payload string.
 * The client verifies this with the embedded public key.
 */
function signPayload(payloadObj) {
    const payloadStr = JSON.stringify(sortObjectKeys(payloadObj));
    return crypto.sign(null, Buffer.from(payloadStr, "utf8"), getSigningPrivateKey()).toString("hex");
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
 * Send a Discord webhook embed for violation/ban events.
 * Fire-and-forget — errors are silently ignored.
 */
async function sendDiscordWebhook(title, fields, color = 0xFF4444) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        const embed = {
            title,
            color,
            fields: fields.map(f => ({ name: f.name, value: String(f.value).slice(0, 1024), inline: f.inline !== false })),
            timestamp: new Date().toISOString(),
            footer: { text: "AiDA Anti-RE System" },
        };
        await fetch(DISCORD_WEBHOOK_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) { /* best-effort */ }
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

    const snapshot = await db.ref(`licenses/${licenseKey}`).get();
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
    const snapshot = await db.ref(`sessions/${licenseKey}`).get();
    return snapshot.val();
}

async function revokeLicenseAndSession(licenseKey, reason, version, hwid) {
    if (!licenseKey || typeof licenseKey !== "string") {
        return;
    }

    const now = Math.floor(Date.now() / 1000);
    const updates = {};
    updates[`licenses/${licenseKey}/active`] = false;
    updates[`licenses/${licenseKey}/revoked_at`] = now;
    updates[`licenses/${licenseKey}/revoked_at_iso`] = new Date().toISOString();
    updates[`licenses/${licenseKey}/revoked_reason`] = reason || "violation";
    updates[`licenses/${licenseKey}/revoked_version`] = version || "unknown";
    if (hwid) {
        updates[`licenses/${licenseKey}/revoked_hwid`] = hwid;
    }
    updates[`sessions/${licenseKey}`] = null;
    await db.ref().update(updates);
}

/**
 * Check if an HWID or IP is banned.
 * Returns { banned, reason } — banned=true means this client is permanently blocked.
 */
async function checkBans(hwid, clientIp) {
    if (hwid) {
        const hwidSnap = await db.ref(`bans/hwid/${hwid}`).get();
        if (hwidSnap.exists()) {
            return { banned: true, reason: "hwid_banned", data: hwidSnap.val() };
        }
    }
    if (clientIp && clientIp !== "unknown") {
        // Normalize IPv4-mapped IPv6 addresses
        const normalizedIp = clientIp.replace(/[.:]/g, "_");
        const ipSnap = await db.ref(`bans/ip/${normalizedIp}`).get();
        if (ipSnap.exists()) {
            return { banned: true, reason: "ip_banned", data: ipSnap.val() };
        }
    }
    return { banned: false };
}

/**
 * Record a ban for both HWID and IP.
 */
async function recordBan(hwid, clientIp, reason, version) {
    const now = Math.floor(Date.now() / 1000);
    const banRecord = {
        reason: reason || "violation",
        banned_at: now,
        banned_at_iso: new Date().toISOString(),
        plugin_version: version || "unknown",
    };

    const updates = {};

    if (hwid) {
        updates[`bans/hwid/${hwid}`] = {
            ...banRecord,
            ip: clientIp || "unknown",
        };
    }

    if (clientIp && clientIp !== "unknown") {
        const normalizedIp = clientIp.replace(/[.:]/g, "_");
        updates[`bans/ip/${normalizedIp}`] = {
            ...banRecord,
            hwid: hwid || "unknown",
            original_ip: clientIp,
        };
    }

    // Also log to a violations audit trail
    const violationId = `${hwid || "unknown"}_${now}`;
    updates[`violations/${violationId}`] = {
        hwid: hwid || "unknown",
        ip: clientIp || "unknown",
        reason: reason || "violation",
        timestamp: now,
        timestamp_iso: new Date().toISOString(),
        plugin_version: version || "unknown",
    };

    if (Object.keys(updates).length > 0) {
        await db.ref().update(updates);
    }

    // Delete any license bound to this HWID
    let deletedKeys = [];
    if (hwid) {
        const licensesSnap = await db.ref("licenses")
            .orderByChild("hwid")
            .equalTo(hwid)
            .get();
        if (licensesSnap.exists()) {
            const deleteUpdates = {};
            licensesSnap.forEach((child) => {
                deleteUpdates[`licenses/${child.key}`] = null;
                deleteUpdates[`sessions/${child.key}`] = null;
                deletedKeys.push(child.key);
            });
            await db.ref().update(deleteUpdates);
        }
    }

    // Discord webhook: log violation
    const fields = [
        { name: "\uD83D\uDEA8 Reason", value: reason || "violation" },
        { name: "\uD83D\uDDA5\uFE0F HWID", value: `\`${hwid || "unknown"}\`` },
        { name: "\uD83C\uDF10 IP", value: `\`${clientIp || "unknown"}\`` },
        { name: "\uD83D\uDCE6 Version", value: version || "unknown" },
    ];
    if (deletedKeys.length > 0) {
        fields.push({ name: "\uD83D\uDDD1\uFE0F Deleted Keys", value: deletedKeys.map(k => `\`${k}\``).join(", ") });
    }
    await sendDiscordWebhook("\uD83D\uDEA8 AiDA Violation Detected", fields, 0xFF0000);
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

    if (!isHexNonce(client_nonce)) {
        return {
            status: 400,
            body: { status: "error", reason: "invalid_nonce" },
        };
    }

    if (body.timestamp && typeof body.timestamp === "number") {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return {
                status: 200,
                body: { status: "invalid", reason: "clock_drift" },
            };
        }
    }

    // 1b. Check HWID and IP bans BEFORE any license lookup
    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return {
            status: 200,
            body: { status: "banned", reason: banCheck.reason },
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
    //    Signature covers the critical fields so the client can verify authenticity
    const sigPayload = {
        status:        "valid",
        license_key:   license_key,
        hwid:          hwid,
        plan:          licenseData.plan || "standard",
        session_token: sessionToken,
        ttl:           ttl,
        issued_at:     issuedAt,
        server_nonce:  serverNonce,
        client_nonce:  client_nonce,
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: {
            status:        "valid",
            license_key:   license_key,
            hwid:          hwid,
            plan:          licenseData.plan || "standard",
            session_token: sessionToken,
            ttl:           ttl,
            issued_at:     issuedAt,
            server_nonce:  serverNonce,
            client_nonce:  client_nonce,
            signature:     signature,
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

    // 1a. Check HWID and IP bans
    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return {
            status: 200,
            body: { status: "banned", reason: banCheck.reason },
        };
    }

    // 1b. Validate request timestamp — reject stale requests (> 5 min drift)
    if (body.timestamp && typeof body.timestamp === "number") {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return {
                status: 200,
                body: { status: "invalid", reason: "clock_drift" },
            };
        }
    }

    if (!isHexNonce(body.heartbeat_nonce || "", 16, 128)) {
        return {
            status: 200,
            body: { status: "invalid", reason: "invalid_heartbeat_nonce" },
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
        const expiresAt = session.issued_at + Math.floor(session.ttl * 1.5); // Grace: 1.5x TTL
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

    // 7. Generate per-heartbeat nonce and sign the response
    const heartbeatNonce = body.heartbeat_nonce || "";
    const serverNonce = generateServerNonce();

    const sigPayload = {
        status:          "valid",
        license_key:     license_key,
        hwid:            hwid || session.hwid || "",
        plan:            lookup.data.plan || "standard",
        ttl:             SESSION_TTL_SECONDS,
        heartbeat_nonce: heartbeatNonce,
        server_nonce:    serverNonce,
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: {
            status:          "valid",
            license_key:     license_key,
            hwid:            hwid || session.hwid || "",
            plan:            lookup.data.plan || "standard",
            ttl:             SESSION_TTL_SECONDS,
            heartbeat_nonce: heartbeatNonce,
            server_nonce:    serverNonce,
            signature:       signature,
        },
    };
}

// ─── Action: report_violation ────────────────────────────────────────────────

async function handleReportViolation(body, clientIp) {
    const { hwid, reason, version, license_key, session_token } = body;

    // Validate input and fail closed without revealing which field was wrong.
    if (!hwid || typeof hwid !== "string" || hwid.length < 8 || hwid.length > 64) {
        return {
            status: 200,
            body: { status: "ok" },   // Don't reveal validation logic to attackers
        };
    }

    if (!license_key || typeof license_key !== "string"
        || !session_token || typeof session_token !== "string") {
        return {
            status: 200,
            body: { status: "ok" },
        };
    }

    const sanitizedReason = sanitizeReason(reason);

    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: "ok" },
        };
    }

    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return {
            status: 200,
            body: { status: "ok" },
        };
    }

    if (session.hwid && session.hwid !== hwid) {
        return {
            status: 200,
            body: { status: "ok" },
        };
    }

    await revokeLicenseAndSession(license_key, sanitizedReason, version, hwid);

    // Record bans for HWID and IP only after a live session backs the report.
    await recordBan(hwid, clientIp, sanitizedReason, version);

    return {
        status: 200,
        body: { status: "ok" },
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
        secrets: [LICENSE_SIGNING_PRIVATE_KEY_B64],
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

                case "report_violation":
                    result = await handleReportViolation(body, clientIp);
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
