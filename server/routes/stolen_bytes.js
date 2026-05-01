'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');

const router = express.Router();

const FETCH_TTL_SECONDS = 30;
const PROLOGUE_MIN_BYTES = 5;
const PROLOGUE_MAX_BYTES = 32;
const RAPID_REPEAT_WINDOW_MS = 5000;
const RAPID_REPEAT_THRESHOLD = 3;

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function isHexNonce(value, minLen, maxLen) {
    return typeof value === 'string'
        && value.length >= minLen
        && value.length <= maxLen
        && /^[a-fA-F0-9]+$/.test(value);
}

function isHexFunctionHash(value) {
    return typeof value === 'string'
        && value.length === 16
        && /^[a-fA-F0-9]{16}$/.test(value);
}

function safeBigIntFromHex(value) {
    if (typeof value !== 'string' || !/^[a-fA-F0-9]+$/.test(value)) return null;
    try {
        return BigInt('0x' + value);
    } catch (_) {
        return null;
    }
}

async function lookupSession(licenseKey, sessionToken) {
    if (!licenseKey || !sessionToken) return null;
    const { rows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1 AND session_token = $2',
        [licenseKey, sessionToken]
    );
    return rows.length > 0 ? rows[0] : null;
}

async function lookupLicenseRow(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') return null;
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [licenseKey]);
    return rows.length > 0 ? rows[0] : null;
}

async function ensureFetchTable() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS stolen_bytes_fetches (
            id              BIGSERIAL    PRIMARY KEY,
            license_key     TEXT         NOT NULL,
            session_token   TEXT         NOT NULL,
            function_hash   TEXT         NOT NULL,
            fetch_id        TEXT         NOT NULL,
            client_nonce    TEXT         NOT NULL DEFAULT '',
            issued_at       BIGINT       NOT NULL,
            valid_until     BIGINT       NOT NULL,
            consumed        BOOLEAN      NOT NULL DEFAULT false,
            consumed_at     BIGINT,
            client_ip       TEXT         NOT NULL DEFAULT '',
            UNIQUE (license_key, session_token, function_hash, fetch_id)
        );
    `);
    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_stolen_bytes_session ON stolen_bytes_fetches (license_key, session_token, function_hash);
    `);
    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_stolen_bytes_issued ON stolen_bytes_fetches (issued_at);
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS stolen_bytes_prologues (
            license_key     TEXT         NOT NULL,
            function_hash   TEXT         NOT NULL,
            prologue        BYTEA        NOT NULL,
            registered_at   BIGINT       NOT NULL,
            PRIMARY KEY (license_key, function_hash)
        );
    `);
    await pool.query(`
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS stolen_bytes_flag_count INTEGER NOT NULL DEFAULT 0;
    `);
    await pool.query(`
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS stolen_bytes_flag_at    BIGINT;
    `);
    await pool.query(`
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS stolen_bytes_status     TEXT NOT NULL DEFAULT 'clean';
    `);
}

let s_tablesEnsured = false;
async function ensureTablesOnce() {
    if (s_tablesEnsured) return;
    try {
        await ensureFetchTable();
        s_tablesEnsured = true;
    } catch (err) {
        console.error('[stolen_bytes] ensureFetchTable failed:', err && err.message ? err.message : err);
    }
}

async function purgeExpiredFetches() {
    try {
        const cutoff = Math.floor(Date.now() / 1000) - (FETCH_TTL_SECONDS * 10);
        await pool.query('DELETE FROM stolen_bytes_fetches WHERE issued_at < $1', [cutoff]);
    } catch (_) {}
}

setInterval(purgeExpiredFetches, 60 * 1000).unref();

async function recentFetchCount(licenseKey, sessionToken, functionHash, sinceMs) {
    const since = Math.floor((Date.now() - sinceMs) / 1000);
    const { rows } = await pool.query(
        `SELECT COUNT(*)::INT AS c
           FROM stolen_bytes_fetches
          WHERE license_key = $1
            AND session_token = $2
            AND function_hash = $3
            AND issued_at >= $4`,
        [licenseKey, sessionToken, functionHash, since]
    );
    return rows.length > 0 ? Number(rows[0].c) : 0;
}

async function isFetchAlreadyConsumed(licenseKey, sessionToken, functionHash, fetchId) {
    const { rows } = await pool.query(
        `SELECT consumed
           FROM stolen_bytes_fetches
          WHERE license_key = $1
            AND session_token = $2
            AND function_hash = $3
            AND fetch_id = $4`,
        [licenseKey, sessionToken, functionHash, fetchId]
    );
    if (rows.length === 0) return false;
    return rows[0].consumed === true;
}

async function recordFetch(licenseKey, sessionToken, functionHash, fetchId, clientNonce, issuedAt, validUntil, ip) {
    await pool.query(
        `INSERT INTO stolen_bytes_fetches
            (license_key, session_token, function_hash, fetch_id, client_nonce, issued_at, valid_until, consumed, client_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8)
         ON CONFLICT (license_key, session_token, function_hash, fetch_id) DO UPDATE SET
            consumed     = true,
            consumed_at  = EXCLUDED.issued_at,
            client_nonce = EXCLUDED.client_nonce,
            client_ip    = EXCLUDED.client_ip`,
        [licenseKey, sessionToken, functionHash, fetchId, clientNonce, issuedAt, validUntil, ip || '']
    );
}

async function flagLicenseForReview(licenseKey, reasonsCount) {
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `UPDATE licenses
            SET stolen_bytes_flag_count = stolen_bytes_flag_count + 1,
                stolen_bytes_flag_at    = $1,
                stolen_bytes_status     = 'flagged'
          WHERE key = $2`,
        [now, licenseKey]
    );
    await pool.query(
        `INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version, license_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        ['stolen_bytes', '', `stolen_bytes_rapid_repeat:${reasonsCount}`, now, new Date().toISOString(), 'stolen_bytes', licenseKey]
    );
}

async function lookupPrologue(licenseKey, functionHash) {
    const { rows } = await pool.query(
        `SELECT prologue
           FROM stolen_bytes_prologues
          WHERE license_key = $1
            AND function_hash = $2`,
        [licenseKey, functionHash]
    );
    if (rows.length === 0) return null;
    return Buffer.isBuffer(rows[0].prologue) ? rows[0].prologue : Buffer.from(rows[0].prologue);
}

async function registerPrologue(licenseKey, functionHash, plaintextBuffer) {
    if (!Buffer.isBuffer(plaintextBuffer)) return false;
    if (plaintextBuffer.length < PROLOGUE_MIN_BYTES || plaintextBuffer.length > PROLOGUE_MAX_BYTES) return false;
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `INSERT INTO stolen_bytes_prologues (license_key, function_hash, prologue, registered_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (license_key, function_hash) DO UPDATE SET
            prologue      = EXCLUDED.prologue,
            registered_at = EXCLUDED.registered_at`,
        [licenseKey, functionHash, plaintextBuffer, now]
    );
    return true;
}

function aesGcmEncrypt(plaintext, key, iv, aad) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext: ct, tag };
}

function deriveEphemeralKey(licenseKey, sessionToken, functionHash, fetchId) {
    const masterSecretRaw = process.env.STOLEN_BYTES_MASTER_SECRET
        || process.env.ARC_MASTER_SECRET
        || process.env.CHALLENGE_SIGNING_SECRET
        || '';
    if (!masterSecretRaw) {
        return null;
    }
    let masterSecret;
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(masterSecretRaw) && masterSecretRaw.length >= 24) {
        try {
            masterSecret = Buffer.from(masterSecretRaw, 'base64');
            if (masterSecret.length < 16) masterSecret = Buffer.from(masterSecretRaw, 'utf8');
        } catch (_) {
            masterSecret = Buffer.from(masterSecretRaw, 'utf8');
        }
    } else {
        masterSecret = Buffer.from(masterSecretRaw, 'utf8');
    }
    const info = Buffer.from(`stolen_bytes/v1|${licenseKey}|${sessionToken}|${functionHash}|${fetchId}`);
    const salt = Buffer.alloc(0);
    const prk = crypto.createHmac('sha256', salt.length === 0 ? Buffer.alloc(32) : salt)
        .update(masterSecret)
        .digest();
    const t1 = crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([0x01])])).digest();
    return t1.slice(0, 32);
}

async function handleFetch(body, ip) {
    await ensureTablesOnce();

    const { license_key, session_token, function_hash, nonce } = body || {};

    if (!license_key || !session_token || !function_hash || !nonce) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    if (!isHexFunctionHash(function_hash)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_function_hash' } };
    }
    if (!isHexNonce(nonce, 8, 64)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_nonce' } };
    }
    if (!/^AIDA-[A-Z0-9\-]{8,40}$/i.test(license_key) && !/^[A-Za-z0-9\-]{10,40}$/.test(license_key)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_license_format' } };
    }
    if (typeof session_token !== 'string' || session_token.length < 16 || session_token.length > 128) {
        return { status: 400, body: { status: 'error', reason: 'invalid_session_token' } };
    }

    const license = await lookupLicenseRow(license_key);
    if (!license) {
        return { status: 200, body: { status: 'invalid', reason: 'license_not_found' } };
    }
    if (!license.active) {
        return { status: 200, body: { status: 'invalid', reason: 'license_revoked' } };
    }

    const session = await lookupSession(license_key, session_token);
    if (!session) {
        return { status: 200, body: { status: 'invalid', reason: 'session_mismatch' } };
    }
    if (session.kill_flag) {
        return { status: 200, body: { status: 'killed', alive: false, reason: 'kill_flag_set' } };
    }

    const recentCount = await recentFetchCount(license_key, session_token, function_hash, RAPID_REPEAT_WINDOW_MS);
    if (recentCount >= RAPID_REPEAT_THRESHOLD) {
        await flagLicenseForReview(license_key, recentCount);
        return {
            status: 200,
            body: {
                status: 'flagged',
                reason: 'rapid_repeat_fetch',
                recent_fetches: recentCount,
                window_ms: RAPID_REPEAT_WINDOW_MS,
            },
        };
    }

    const plaintextPrologue = await lookupPrologue(license_key, function_hash);
    if (!plaintextPrologue) {
        return { status: 200, body: { status: 'invalid', reason: 'prologue_not_registered' } };
    }
    if (plaintextPrologue.length < PROLOGUE_MIN_BYTES || plaintextPrologue.length > PROLOGUE_MAX_BYTES) {
        return { status: 500, body: { status: 'error', reason: 'prologue_invalid_length' } };
    }

    const fetchId = crypto.randomBytes(12).toString('hex');

    const alreadyConsumed = await isFetchAlreadyConsumed(license_key, session_token, function_hash, fetchId);
    if (alreadyConsumed) {
        await flagLicenseForReview(license_key, recentCount + 1);
        return { status: 200, body: { status: 'flagged', reason: 'fetch_id_replay' } };
    }

    const ephemeralKey = deriveEphemeralKey(license_key, session_token, function_hash, fetchId);
    if (!ephemeralKey || ephemeralKey.length !== 32) {
        return { status: 500, body: { status: 'error', reason: 'key_derivation_failed' } };
    }
    const sessionIv = crypto.randomBytes(12);

    const fetchIdBuf = Buffer.from(fetchId, 'hex');
    const sessionEpochBuf = Buffer.alloc(8);
    sessionEpochBuf.writeBigUInt64LE(BigInt(session.issued_at || 0), 0);
    const fnHashBuf = Buffer.from(function_hash, 'hex');
    const aad = Buffer.concat([fnHashBuf, fetchIdBuf.length === 8 ? fetchIdBuf : Buffer.concat([fetchIdBuf, Buffer.alloc(8 - (fetchIdBuf.length % 8))]).slice(0, 8), sessionEpochBuf]);

    const { ciphertext, tag } = aesGcmEncrypt(plaintextPrologue, ephemeralKey, sessionIv, aad);

    const issuedAt = Math.floor(Date.now() / 1000);
    const validUntil = issuedAt + FETCH_TTL_SECONDS;
    const validUntilTickMs = Date.now() + (FETCH_TTL_SECONDS * 1000);

    await recordFetch(license_key, session_token, function_hash, fetchId, nonce, issuedAt, validUntil, ip);

    const sigPayload = {
        status: 'ok',
        license_key,
        session_token,
        function_hash,
        fetch_id: fetchId,
        prologue_len: plaintextPrologue.length,
        valid_until_tick: validUntilTickMs,
        valid_until_seconds: validUntil,
        issued_at: issuedAt,
    };
    let signature = '';
    try { signature = signPayload(sigPayload); } catch (_) { signature = ''; }

    return {
        status: 200,
        body: {
            ...sigPayload,
            ciphertext_b64: ciphertext.toString('base64'),
            tag_b64: tag.toString('base64'),
            iv_b64: sessionIv.toString('base64'),
            ephemeral_key_b64: ephemeralKey.toString('base64'),
            signature,
        },
    };
}

async function handleRegister(body, ip) {
    await ensureTablesOnce();

    const expectedAdminKey = process.env.ADMIN_API_KEY || '';
    const { admin_key, license_key, function_hash, prologue_b64 } = body || {};

    if (!expectedAdminKey || !admin_key || typeof admin_key !== 'string') {
        return { status: 403, body: { status: 'error', reason: 'unauthorized' } };
    }
    const aBuf = Buffer.from(admin_key);
    const eBuf = Buffer.from(expectedAdminKey);
    if (aBuf.length !== eBuf.length || !crypto.timingSafeEqual(aBuf, eBuf)) {
        return { status: 403, body: { status: 'error', reason: 'unauthorized' } };
    }

    if (!license_key || !function_hash || !prologue_b64) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    if (!isHexFunctionHash(function_hash)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_function_hash' } };
    }

    let prologueBuf;
    try {
        prologueBuf = Buffer.from(prologue_b64, 'base64');
    } catch (_) {
        return { status: 400, body: { status: 'error', reason: 'invalid_prologue_b64' } };
    }
    if (prologueBuf.length < PROLOGUE_MIN_BYTES || prologueBuf.length > PROLOGUE_MAX_BYTES) {
        return { status: 400, body: { status: 'error', reason: 'invalid_prologue_length' } };
    }

    const license = await lookupLicenseRow(license_key);
    if (!license) {
        return { status: 200, body: { status: 'invalid', reason: 'license_not_found' } };
    }

    const ok = await registerPrologue(license_key, function_hash, prologueBuf);
    if (!ok) {
        return { status: 500, body: { status: 'error', reason: 'register_failed' } };
    }
    return { status: 200, body: { status: 'ok', registered: true, ip: ip || '' } };
}

router.post('/fetch', async (req, res) => {
    try {
        const result = await handleFetch(req.body || {}, clientIp(req));
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[stolen_bytes] /fetch error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/register', async (req, res) => {
    try {
        const result = await handleRegister(req.body || {}, clientIp(req));
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[stolen_bytes] /register error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router._internal = {
    handleFetch,
    handleRegister,
    ensureFetchTable,
    deriveEphemeralKey,
    aesGcmEncrypt,
    PROLOGUE_MIN_BYTES,
    PROLOGUE_MAX_BYTES,
    FETCH_TTL_SECONDS,
    RAPID_REPEAT_WINDOW_MS,
    RAPID_REPEAT_THRESHOLD,
};

module.exports = router;
