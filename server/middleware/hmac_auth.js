'use strict';

const crypto = require('crypto');
const pool = require('../db/pool');

let columnCrypt = null;
try { columnCrypt = require('../crypto/column_crypt'); } catch (_) { columnCrypt = null; }

async function decryptSessionTokenForRow(sessionUuid) {
    if (!sessionUuid) return '';
    try {
        const { rows } = await pool.query(
            'SELECT session_token FROM sessions WHERE session_uuid = $1',
            [sessionUuid]
        );
        if (rows.length === 0) return '';
        const stored = rows[0].session_token;
        if (typeof stored === 'string' && columnCrypt && columnCrypt.isCiphertext && columnCrypt.isCiphertext(stored)) {
            return columnCrypt.decrypt(sessionUuid, 'sessions/session_token', stored);
        }
        return stored || '';
    } catch (_) {
        return '';
    }
}

const HMAC_HEADER = 'x-aida-auth';
const NONCE_HEADER = 'x-aida-nonce';
const TS_HEADER = 'x-aida-ts';
const SESSION_HEADER = 'x-aida-session';
const MAX_DRIFT_SECONDS = 60;
const NONCE_TTL_SECONDS = 120;
const HONEYPOT_FAIL_THRESHOLD = parseInt(process.env.HONEYPOT_REVOKE_THRESHOLD || '1', 10);

const inMemoryNonces = new Map();

function pruneInMemoryNonces() {
    const cutoff = Math.floor(Date.now() / 1000) - NONCE_TTL_SECONDS;
    for (const [k, v] of inMemoryNonces) {
        if (v < cutoff) inMemoryNonces.delete(k);
    }
}

setInterval(pruneInMemoryNonces, 30 * 1000).unref();

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function timingSafeHexEqual(aHex, bHex) {
    if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
    const a = Buffer.from(aHex, 'utf8');
    const b = Buffer.from(bHex, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function computeExpectedHmac(authKey, body, nonce, ts) {
    const bodyStr = (body && typeof body === 'object') ? JSON.stringify(body) : String(body || '');
    return crypto.createHmac('sha256', authKey)
        .update(`${nonce}|${ts}|${bodyStr}`, 'utf8')
        .digest('hex');
}

async function recordReplayNonce(nonceB64, licenseKey, now) {
    try {
        await pool.query(
            'INSERT INTO server_nonce_replay (nonce_b64, license_key, seen_at) VALUES ($1, $2, $3) ON CONFLICT (nonce_b64) DO NOTHING',
            [nonceB64, licenseKey || '', now]
        );
        await pool.query('DELETE FROM server_nonce_replay WHERE seen_at < $1', [now - NONCE_TTL_SECONDS]);
    } catch (err) {
        console.warn('[hmac_auth] replay_nonce persist failed:', err.message);
    }
}

async function flagHoneypotHit(licenseKey, route, ip) {
    if (!licenseKey) return;
    try {
        const { rows } = await pool.query(
            `UPDATE licenses SET honeypot_strike_count = honeypot_strike_count + 1
             WHERE key = $1 RETURNING honeypot_strike_count`,
            [licenseKey]
        );
        const strike = rows.length > 0 ? rows[0].honeypot_strike_count : 0;
        await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
            [licenseKey]
        );
        await pool.query(
            `INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version, license_key)
             VALUES ('unknown', $1, $2, $3, $4, 'honeypot', $5)`,
            [ip, `honeypot_unauth:${route}`, Math.floor(Date.now() / 1000), new Date().toISOString(), licenseKey]
        );
        if (strike >= HONEYPOT_FAIL_THRESHOLD) {
            await pool.query(
                `UPDATE licenses SET active = false, revoked_at = $1, revoked_at_iso = $2,
                                     revoked_reason = $3, revoked_version = 'honeypot'
                 WHERE key = $4`,
                [Math.floor(Date.now() / 1000), new Date().toISOString(), `honeypot_unauth:${route}`, licenseKey]
            );
        }
    } catch (err) {
        console.error('[hmac_auth] honeypot flag failed:', err.message);
    }
}

async function authenticate(req, res, next) {
    const route = req.baseUrl + (req.path || '');
    const headerSig = String(req.headers[HMAC_HEADER] || '').trim();
    const headerNonce = String(req.headers[NONCE_HEADER] || '').trim();
    const headerTs = String(req.headers[TS_HEADER] || '').trim();
    const sessionToken = String(req.headers[SESSION_HEADER] || '').trim();

    const bodyLicenseKey = (req.body && typeof req.body === 'object') ? String(req.body.license_key || '') : '';
    const ip = clientIp(req);

    if (!headerSig || !headerNonce || !headerTs || !sessionToken) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_missing' });
    }

    const ts = parseInt(headerTs, 10);
    if (!Number.isFinite(ts)) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_bad_ts' });
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > MAX_DRIFT_SECONDS) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_clock_drift' });
    }

    if (!/^[A-Za-z0-9+/=_-]{16,128}$/.test(headerNonce)) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_bad_nonce' });
    }

    if (inMemoryNonces.has(headerNonce)) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_nonce_replay' });
    }

    if (!bodyLicenseKey) {
        await flagHoneypotHit('', route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_no_license_key' });
    }

    let session;
    try {
        const { rows } = await pool.query(
            'SELECT session_uuid, license_key, hwid, kill_flag, auth_hmac_key FROM sessions WHERE license_key = $1',
            [bodyLicenseKey]
        );
        session = rows[0];
    } catch (err) {
        return res.status(503).json({ status: 'error', reason: 'auth_db_unavailable' });
    }

    if (!session || !session.auth_hmac_key) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_session_unknown' });
    }

    if (session.kill_flag) {
        return res.status(403).json({ status: 'error', reason: 'auth_session_killed' });
    }

    const decryptedSessionToken = await decryptSessionTokenForRow(session.session_uuid).catch(() => '');
    if (!decryptedSessionToken || sessionToken !== decryptedSessionToken) {
        await flagHoneypotHit(bodyLicenseKey, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_session_token_mismatch' });
    }

    const expected = computeExpectedHmac(session.auth_hmac_key, req.body || {}, headerNonce, headerTs);
    if (!timingSafeHexEqual(expected, headerSig)) {
        await flagHoneypotHit(session.license_key, route, ip);
        return res.status(403).json({ status: 'error', reason: 'auth_bad_signature' });
    }

    inMemoryNonces.set(headerNonce, now);
    await recordReplayNonce(headerNonce, session.license_key, now);

    req.aidaSession = {
        license_key: session.license_key,
        hwid: session.hwid,
        session_token: session.session_token,
    };
    next();
}

module.exports = {
    authenticate,
    computeExpectedHmac,
    HMAC_HEADER,
    NONCE_HEADER,
    TS_HEADER,
    SESSION_HEADER,
};
