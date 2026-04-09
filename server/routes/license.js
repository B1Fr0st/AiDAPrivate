// ============================================================================
// AiDA License Server — License Validation Routes
// ============================================================================
// Direct port of firebase/functions/index.js to Express + PostgreSQL.
// Preserves IDENTICAL request/response format so the existing AiDA client
// works with only a base URL change.
//
// POST /api/license
//   body.action = "validate"          → Full license activation
//   body.action = "heartbeat"         → Session keepalive
//   body.action = "report_violation"  → Anti-RE violation reporting
// ============================================================================

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');

const router = express.Router();

// ─── Configuration ──────────────────────────────────────────────────────────

const SESSION_TTL_SECONDS = 3600;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

// ─── Helpers ────────────────────────────────────────────────────────────────

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateServerNonce() {
    return crypto.randomBytes(16).toString('hex');
}

function isHexNonce(value, minLength = 16, maxLength = 128) {
    return typeof value === 'string'
        && value.length >= minLength
        && value.length <= maxLength
        && /^[a-fA-F0-9]+$/.test(value);
}

function sanitizeReason(reason) {
    return typeof reason === 'string'
        ? reason.slice(0, 128).replace(/[^a-zA-Z0-9_ :\-]/g, '')
        : 'unknown';
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.ip
        || 'unknown';
}

function normalizeIp(ip) {
    return typeof ip === 'string' ? ip.replace(/[.:]/g, '_') : 'unknown';
}

/**
 * Send a Discord webhook embed (fire-and-forget).
 */
async function sendDiscordWebhook(title, fields, color = 0xFF4444) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        const embed = {
            title,
            color,
            fields: fields.map(f => ({
                name: f.name,
                value: String(f.value).slice(0, 1024),
                inline: f.inline !== false,
            })),
            timestamp: new Date().toISOString(),
            footer: { text: 'AiDA Anti-RE System' },
        };
        await fetch(DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) { /* best-effort */ }
}

// ─── Database Queries ───────────────────────────────────────────────────────

async function lookupLicense(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') {
        return { valid: false, reason: 'missing_key' };
    }
    if (!/^[A-Za-z0-9\-]{10,40}$/.test(licenseKey)) {
        return { valid: false, reason: 'invalid_format' };
    }

    const { rows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [licenseKey]
    );
    if (rows.length === 0) {
        return { valid: false, reason: 'not_found' };
    }

    const data = rows[0];

    if (!data.active) {
        return { valid: false, reason: 'revoked', data };
    }
    if (data.expires && data.expires !== '' && data.expires < todayStr()) {
        return { valid: false, reason: 'expired', data };
    }

    return { valid: true, data };
}

async function verifyOrBindHwid(licenseKey, hwid, existingHwid) {
    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 256) {
        return { ok: false, reason: 'invalid_hwid' };
    }

    if (!existingHwid || existingHwid === '') {
        // First activation — bind HWID atomically
        await pool.query(
            'UPDATE licenses SET hwid = $1 WHERE key = $2 AND hwid = $3',
            [hwid, licenseKey, '']
        );
        return { ok: true, reason: 'bound' };
    }

    if (existingHwid !== hwid) {
        return { ok: false, reason: 'hwid_mismatch' };
    }

    return { ok: true, reason: 'match' };
}

async function storeSession(licenseKey, sessionData) {
    await pool.query(`
        INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (license_key) DO UPDATE SET
            session_token   = EXCLUDED.session_token,
            server_nonce    = EXCLUDED.server_nonce,
            issued_at       = EXCLUDED.issued_at,
            ttl             = EXCLUDED.ttl,
            hwid            = EXCLUDED.hwid,
            ip              = EXCLUDED.ip,
            plugin_version  = EXCLUDED.plugin_version,
            last_heartbeat  = EXCLUDED.last_heartbeat
    `, [
        licenseKey,
        sessionData.session_token,
        sessionData.server_nonce,
        sessionData.issued_at,
        sessionData.ttl,
        sessionData.hwid,
        sessionData.ip,
        sessionData.plugin_version,
        sessionData.last_heartbeat,
    ]);
}

async function getSession(licenseKey) {
    const { rows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    return rows.length > 0 ? rows[0] : null;
}

async function checkBans(hwid, clientIp) {
    if (hwid) {
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND value = $2',
            ['hwid', hwid]
        );
        if (rows.length > 0) {
            return { banned: true, reason: 'hwid_banned', data: rows[0] };
        }
    }
    if (clientIp && clientIp !== 'unknown') {
        const normalized = normalizeIp(clientIp);
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND (value = $2 OR value = $3)',
            ['ip', clientIp, normalized]
        );
        if (rows.length > 0) {
            return { banned: true, reason: 'ip_banned', data: rows[0] };
        }
    }
    return { banned: false };
}

async function revokeLicenseAndSession(licenseKey, reason, version, hwid) {
    if (!licenseKey) return;
    const now = Math.floor(Date.now() / 1000);

    await pool.query(`
        UPDATE licenses SET
            active = false,
            revoked_at = $1,
            revoked_at_iso = $2,
            revoked_reason = $3,
            revoked_version = $4,
            revoked_hwid = $5
        WHERE key = $6
    `, [now, new Date().toISOString(), reason || 'violation', version || 'unknown', hwid || '', licenseKey]);

    await pool.query('DELETE FROM sessions WHERE license_key = $1', [licenseKey]);
}

async function recordBan(hwid, clientIp, reason, version) {
    const now = Math.floor(Date.now() / 1000);
    const isoNow = new Date().toISOString();
    const sanitized = reason || 'violation';

    // Ban HWID
    if (hwid) {
        await pool.query(`
            INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, ip)
            VALUES ('hwid', $1, $2, $3, $4, $5, $6)
            ON CONFLICT (ban_type, value) DO UPDATE SET
                reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                banned_at_iso = EXCLUDED.banned_at_iso, plugin_version = EXCLUDED.plugin_version
        `, [hwid, sanitized, now, isoNow, version || 'unknown', clientIp || 'unknown']);
    }

    // Ban IP
    if (clientIp && clientIp !== 'unknown') {
        const normalized = normalizeIp(clientIp);
        await pool.query(`
            INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, hwid, original_ip)
            VALUES ('ip', $1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (ban_type, value) DO UPDATE SET
                reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                banned_at_iso = EXCLUDED.banned_at_iso, plugin_version = EXCLUDED.plugin_version
        `, [normalized, sanitized, now, isoNow, version || 'unknown', hwid || 'unknown', clientIp]);
    }

    // Audit trail
    await pool.query(`
        INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, [hwid || 'unknown', clientIp || 'unknown', sanitized, now, isoNow, version || 'unknown']);

    // Cascade: delete all licenses bound to this HWID
    let deletedKeys = [];
    if (hwid) {
        const { rows } = await pool.query(
            'SELECT key FROM licenses WHERE hwid = $1',
            [hwid]
        );
        deletedKeys = rows.map(r => r.key);

        if (deletedKeys.length > 0) {
            await pool.query('DELETE FROM sessions WHERE license_key = ANY($1)', [deletedKeys]);
            await pool.query('DELETE FROM licenses WHERE key = ANY($1)', [deletedKeys]);
        }
    }

    // Discord webhook
    const fields = [
        { name: '\uD83D\uDEA8 Reason', value: sanitized },
        { name: '\uD83D\uDDA5\uFE0F HWID', value: `\`${hwid || 'unknown'}\`` },
        { name: '\uD83C\uDF10 IP', value: `\`${clientIp || 'unknown'}\`` },
        { name: '\uD83D\uDCE6 Version', value: version || 'unknown' },
    ];
    if (deletedKeys.length > 0) {
        fields.push({
            name: '\uD83D\uDDD1\uFE0F Deleted Keys',
            value: deletedKeys.map(k => `\`${k}\``).join(', '),
        });
    }
    await sendDiscordWebhook('\uD83D\uDEA8 AiDA Violation Detected', fields, 0xFF0000);
}

// ─── Action: validate ───────────────────────────────────────────────────────

async function handleValidate(body, clientIp) {
    const { license_key, hwid, client_nonce, plugin_version } = body;

    if (!license_key || !hwid || !client_nonce) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    if (!isHexNonce(client_nonce)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_nonce' } };
    }

    // Clock drift check
    if (body.timestamp && typeof body.timestamp === 'number') {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return { status: 200, body: { status: 'invalid', reason: 'clock_drift' } };
        }
    }

    // Ban check BEFORE any license lookup
    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return { status: 200, body: { status: 'banned', reason: banCheck.reason } };
    }

    // License lookup
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return { status: 200, body: { status: 'invalid', reason: lookup.reason } };
    }

    // Verify/bind HWID
    const hwidResult = await verifyOrBindHwid(license_key, hwid, lookup.data.hwid || '');
    if (!hwidResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: hwidResult.reason } };
    }

    // Generate session
    const sessionToken = generateSessionToken();
    const serverNonce = generateServerNonce();
    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = SESSION_TTL_SECONDS;

    await storeSession(license_key, {
        session_token: sessionToken,
        server_nonce: serverNonce,
        issued_at: issuedAt,
        ttl,
        hwid,
        ip: clientIp,
        plugin_version: plugin_version || 'unknown',
        last_heartbeat: issuedAt,
    });

    // Sign response
    const sigPayload = {
        status: 'valid',
        license_key,
        hwid,
        plan: lookup.data.plan || 'standard',
        session_token: sessionToken,
        ttl,
        issued_at: issuedAt,
        server_nonce: serverNonce,
        client_nonce,
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: { ...sigPayload, signature },
    };
}

// ─── Action: heartbeat ──────────────────────────────────────────────────────

async function handleHeartbeat(body, clientIp) {
    const { license_key, session_token, hwid } = body;

    if (!license_key || !session_token) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }

    // Ban check
    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return { status: 200, body: { status: 'banned', reason: banCheck.reason } };
    }

    // Clock drift
    if (body.timestamp && typeof body.timestamp === 'number') {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return { status: 200, body: { status: 'invalid', reason: 'clock_drift' } };
        }
    }

    if (!isHexNonce(body.heartbeat_nonce || '', 16, 128)) {
        return { status: 200, body: { status: 'invalid', reason: 'invalid_heartbeat_nonce' } };
    }

    // Re-verify license is still active
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: lookup.reason === 'revoked' ? 'revoked' : 'invalid', reason: lookup.reason },
        };
    }

    // Verify session token
    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return { status: 200, body: { status: 'invalid', reason: 'session_mismatch' } };
    }

    // Session TTL check with 1.5x grace
    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * 1.5);
        if (now > expiresAt) {
            return { status: 200, body: { status: 'invalid', reason: 'session_expired' } };
        }
    }

    // HWID consistency
    if (hwid && session.hwid && hwid !== session.hwid) {
        return { status: 200, body: { status: 'invalid', reason: 'hwid_mismatch' } };
    }

    // Update last heartbeat
    await pool.query(
        'UPDATE sessions SET last_heartbeat = $1 WHERE license_key = $2',
        [now, license_key]
    );

    // Sign and return response
    const heartbeatNonce = body.heartbeat_nonce || '';
    const serverNonce = generateServerNonce();

    const sigPayload = {
        status: 'valid',
        license_key,
        hwid: hwid || session.hwid || '',
        plan: lookup.data.plan || 'standard',
        ttl: SESSION_TTL_SECONDS,
        heartbeat_nonce: heartbeatNonce,
        server_nonce: serverNonce,
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: { ...sigPayload, signature },
    };
}

// ─── Action: report_violation ───────────────────────────────────────────────

async function handleReportViolation(body, clientIp) {
    const { hwid, reason, version, license_key, session_token } = body;

    // Fail closed — always return ok to prevent probing
    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 64) {
        return { status: 200, body: { status: 'ok' } };
    }
    if (!license_key || !session_token) {
        return { status: 200, body: { status: 'ok' } };
    }

    const sanitizedReason = sanitizeReason(reason);

    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return { status: 200, body: { status: 'ok' } };
    }

    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return { status: 200, body: { status: 'ok' } };
    }
    if (session.hwid && session.hwid !== hwid) {
        return { status: 200, body: { status: 'ok' } };
    }

    await revokeLicenseAndSession(license_key, sanitizedReason, version, hwid);
    await recordBan(hwid, clientIp, sanitizedReason, version);

    return { status: 200, body: { status: 'ok' } };
}

// ─── Route Handler ──────────────────────────────────────────────────────────

router.post('/', async (req, res) => {
    const body = req.body;
    if (!body || typeof body !== 'object') {
        return res.status(400).json({ status: 'error', reason: 'invalid_body' });
    }

    const clientIp = getClientIp(req);
    const action = body.action;

    try {
        let result;

        switch (action) {
            case 'validate':
                result = await handleValidate(body, clientIp);
                break;
            case 'heartbeat':
                result = await handleHeartbeat(body, clientIp);
                break;
            case 'report_violation':
                result = await handleReportViolation(body, clientIp);
                break;
            default:
                return res.status(400).json({ status: 'error', reason: 'unknown_action' });
        }

        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error(`[license] Error processing ${action}:`, err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
