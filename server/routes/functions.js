'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');
const pageKeys = require('../crypto/page_keys');

const router = express.Router();

const FUNCTION_TOKEN_TTL_SECONDS = pageKeys.FUNCTION_TOKEN_TTL_SECONDS;
const PROLOGUE_RAPID_FETCH_THRESHOLD_MS = pageKeys.PROLOGUE_RAPID_FETCH_THRESHOLD_MS;
const PROLOGUE_RAPID_FETCH_COUNT = pageKeys.PROLOGUE_RAPID_FETCH_COUNT;

const CRITICAL_FUNCTIONS_DEFAULT = [
    'arc_init',
    'arc_validate_tool_exec',
    'arc_heartbeat',
    'arc_heartbeat_ex',
    'arc_unseal_feature',
];

function loadCriticalFunctions() {
    const env = process.env.ARC_CRITICAL_FUNCTIONS || '';
    if (env.trim().length === 0) return CRITICAL_FUNCTIONS_DEFAULT.slice();
    const parts = env.split(',').map(s => s.trim()).filter(Boolean);
    return parts.length > 0 ? parts : CRITICAL_FUNCTIONS_DEFAULT.slice();
}

const criticalFunctionSet = new Set(loadCriticalFunctions());

function functionAllowed(name) {
    if (!name || typeof name !== 'string') return false;
    return criticalFunctionSet.has(name);
}

const PROLOGUE_BLOB_PATH = process.env.ARC_PROLOGUE_PATH
    || path.join(path.dirname(process.env.ARC_BLOB_PATH || '/opt/aida/arc/aida_core.bin'), 'aida_core_prologues.json');

let cachedPrologues = null;
let cachedPrologueMtimeMs = 0;

function loadPrologues() {
    try {
        const stat = fs.statSync(PROLOGUE_BLOB_PATH);
        if (cachedPrologues && stat.mtimeMs === cachedPrologueMtimeMs) {
            return cachedPrologues;
        }
        const raw = fs.readFileSync(PROLOGUE_BLOB_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || !parsed.functions || typeof parsed.functions !== 'object') {
            throw new Error('prologue_blob_invalid');
        }
        cachedPrologues = parsed.functions;
        cachedPrologueMtimeMs = stat.mtimeMs;
        return cachedPrologues;
    } catch (err) {
        if (err && err.code === 'ENOENT') {
            cachedPrologues = {};
            cachedPrologueMtimeMs = 0;
            return cachedPrologues;
        }
        throw err;
    }
}

function lookupPrologue(functionHash) {
    const prologues = loadPrologues();
    if (!prologues) return null;
    const entry = prologues[functionHash];
    if (!entry) return null;
    if (typeof entry.bytes !== 'string' || entry.bytes.length === 0) return null;
    const buf = Buffer.from(entry.bytes, 'hex');
    if (buf.length === 0) return null;
    return { bytes: buf, name: entry.name || '' };
}

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

async function validateFunctionSession(licenseKey, sessionToken, hwid) {
    if (!licenseKey || !sessionToken || !hwid) {
        return { valid: false, reason: 'missing_fields' };
    }
    const banResult = await pool.query(
        'SELECT 1 FROM bans WHERE ban_type = $1 AND value = $2 LIMIT 1',
        ['hwid', hwid]
    );
    if (banResult.rows.length > 0) {
        return { valid: false, reason: 'banned' };
    }
    const { rows: licRows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [licenseKey]
    );
    if (licRows.length === 0 || !licRows[0].active) {
        return { valid: false, reason: 'invalid_license' };
    }
    const license = licRows[0];
    const todayIso = new Date().toISOString().slice(0, 10);
    if (license.expires && license.expires !== '' && license.expires < todayIso) {
        return { valid: false, reason: 'expired' };
    }
    const { rows: sesRows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (sesRows.length === 0 || sesRows[0].session_token !== sessionToken) {
        return { valid: false, reason: 'session_mismatch' };
    }
    const session = sesRows[0];
    if (session.hwid && session.hwid !== hwid) {
        return { valid: false, reason: 'hwid_mismatch' };
    }
    if (session.kill_flag) {
        return { valid: false, reason: 'killed' };
    }
    return { valid: true, license, session };
}

router.post('/key', async (req, res) => {
    try {
        const { license_key, session_token, hwid, function_name, function_hash, nonce } = req.body || {};
        if (!functionAllowed(function_name)) {
            return res.status(403).json({ status: 'error', reason: 'function_not_critical' });
        }
        if (!function_hash || typeof function_hash !== 'string' || function_hash.length < 16 || function_hash.length > 256) {
            return res.status(400).json({ status: 'error', reason: 'invalid_function_hash' });
        }
        if (!nonce || typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 128) {
            return res.status(400).json({ status: 'error', reason: 'invalid_nonce' });
        }
        if (!/^[0-9a-fA-F]+$/.test(nonce)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_nonce' });
        }

        const validation = await validateFunctionSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const ip = clientIp(req);
        const nowSec = Math.floor(Date.now() / 1000);
        const expiresAt = nowSec + FUNCTION_TOKEN_TTL_SECONDS;

        const insertResult = await pool.query(
            `INSERT INTO arc_function_calls
                (license_key, hwid, function_hash, nonce, issued_at, expires_at, consumed, duplicate_count, flagged_replay)
             VALUES ($1,$2,$3,$4,$5,$6,false,0,false)
             ON CONFLICT (license_key, function_hash, nonce)
             DO UPDATE SET duplicate_count = arc_function_calls.duplicate_count + 1,
                           flagged_replay = true
             RETURNING id, duplicate_count, flagged_replay, consumed`,
            [license_key, hwid, function_hash, nonce, nowSec, expiresAt]
        );

        const row = insertResult.rows[0];
        if (row && (row.duplicate_count > 0 || row.flagged_replay || row.consumed)) {
            await pool.query(
                `INSERT INTO violations (hwid, ip, reason, timestamp, license_key)
                 VALUES ($1,$2,'arc_function_replay',$3,$4)`,
                [hwid, ip, nowSec, license_key]
            );
            return res.status(403).json({
                status: 'error',
                reason: 'replay_detected',
                duplicate_count: Number(row.duplicate_count || 0),
            });
        }

        const oneSecondAgo = nowSec - 1;
        const { rows: rapidRows } = await pool.query(
            `SELECT COUNT(*)::int AS c FROM arc_function_calls
              WHERE license_key = $1 AND function_hash = $2 AND issued_at >= $3`,
            [license_key, function_hash, oneSecondAgo]
        );
        if (rapidRows.length > 0 && Number(rapidRows[0].c) >= 6) {
            await pool.query(
                `UPDATE arc_function_calls SET flagged_replay = true WHERE id = $1`,
                [row.id]
            );
            await pool.query(
                `INSERT INTO violations (hwid, ip, reason, timestamp, license_key)
                 VALUES ($1,$2,'arc_function_burst',$3,$4)`,
                [hwid, ip, nowSec, license_key]
            );
            return res.status(429).json({ status: 'error', reason: 'function_call_burst' });
        }

        const issuedAtSec = Number(validation.session.issued_at || 0);
        const key = pageKeys.deriveFunctionKey(license_key, hwid, function_hash, nonce, issuedAtSec);
        const token = pageKeys.deriveFunctionToken(license_key, hwid, function_hash, nonce, nowSec, expiresAt);

        const responsePayload = {
            status: 'ok',
            function_name,
            function_hash,
            nonce,
            issued_at: nowSec,
            expires_at: expiresAt,
            ttl_seconds: FUNCTION_TOKEN_TTL_SECONDS,
            decryption_key: key.toString('base64'),
            access_token: token.toString('hex'),
        };
        responsePayload.signature = signPayload(responsePayload);

        key.fill(0);
        token.fill(0);

        return res.json(responsePayload);
    } catch (err) {
        console.error('[functions/key] error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/consume', async (req, res) => {
    try {
        const { license_key, session_token, hwid, function_name, function_hash, nonce } = req.body || {};
        if (!functionAllowed(function_name)) {
            return res.status(403).json({ status: 'error', reason: 'function_not_critical' });
        }
        if (!function_hash || !nonce) {
            return res.status(400).json({ status: 'error', reason: 'missing_fields' });
        }

        const validation = await validateFunctionSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const nowSec = Math.floor(Date.now() / 1000);
        const { rows } = await pool.query(
            `UPDATE arc_function_calls
                SET consumed = true, consumed_at = $1
              WHERE license_key = $2 AND function_hash = $3 AND nonce = $4
                AND consumed = false
                AND expires_at >= $1
             RETURNING id`,
            [nowSec, license_key, function_hash, nonce]
        );
        if (rows.length === 0) {
            return res.status(403).json({ status: 'error', reason: 'token_expired_or_consumed' });
        }
        return res.json({ status: 'ok', consumed_at: nowSec });
    } catch (err) {
        console.error('[functions/consume] error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/prologue', async (req, res) => {
    try {
        const { license_key, session_token, hwid, function_name, function_hash, nonce } = req.body || {};
        if (!functionAllowed(function_name)) {
            return res.status(403).json({ status: 'error', reason: 'function_not_critical' });
        }
        if (!function_hash || typeof function_hash !== 'string' || function_hash.length < 16) {
            return res.status(400).json({ status: 'error', reason: 'invalid_function_hash' });
        }
        if (!nonce || typeof nonce !== 'string' || nonce.length < 16) {
            return res.status(400).json({ status: 'error', reason: 'invalid_nonce' });
        }
        if (!/^[0-9a-fA-F]+$/.test(nonce)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_nonce' });
        }

        const validation = await validateFunctionSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const ip = clientIp(req);
        const nowMs = Date.now();
        const recentMs = nowMs - PROLOGUE_RAPID_FETCH_THRESHOLD_MS;

        const insertResult = await pool.query(
            `INSERT INTO arc_prologue_requests
                (license_key, hwid, function_hash, nonce, requested_at_ms, consumed, flagged, flagged_reason)
             VALUES ($1,$2,$3,$4,$5,false,false,'')
             ON CONFLICT (license_key, function_hash, nonce)
             DO UPDATE SET flagged = true, flagged_reason = 'duplicate_nonce'
             RETURNING id, consumed, flagged`,
            [license_key, hwid, function_hash, nonce, nowMs]
        );
        const row = insertResult.rows[0];
        if (!row) {
            return res.status(500).json({ status: 'error', reason: 'insert_failed' });
        }
        if (row.consumed || row.flagged) {
            await flagLicenseAnomaly(license_key, 'prologue_duplicate_nonce');
            return res.status(403).json({ status: 'error', reason: 'prologue_replay' });
        }

        const { rows: rapidRows } = await pool.query(
            `SELECT COUNT(*)::int AS c FROM arc_prologue_requests
              WHERE license_key = $1 AND function_hash = $2 AND requested_at_ms >= $3`,
            [license_key, function_hash, recentMs]
        );
        if (rapidRows.length > 0 && Number(rapidRows[0].c) >= PROLOGUE_RAPID_FETCH_COUNT) {
            await pool.query(
                `UPDATE arc_prologue_requests SET flagged = true, flagged_reason = 'rapid_refetch' WHERE id = $1`,
                [row.id]
            );
            await flagLicenseAnomaly(license_key, 'prologue_rapid_refetch');
            await pool.query(
                `INSERT INTO violations (hwid, ip, reason, timestamp, license_key)
                 VALUES ($1,$2,'prologue_rapid_refetch',$3,$4)`,
                [hwid, ip, Math.floor(nowMs / 1000), license_key]
            );
            return res.status(429).json({ status: 'error', reason: 'prologue_rapid_refetch' });
        }

        const { rows: lastRows } = await pool.query(
            `SELECT function_hash, requested_at_ms FROM arc_prologue_requests
              WHERE license_key = $1
              ORDER BY id DESC
              LIMIT 8`,
            [license_key]
        );
        if (lastRows.length >= 5) {
            const distinctHashes = new Set(lastRows.map(r => r.function_hash));
            if (distinctHashes.size === 1 && distinctHashes.has(function_hash)) {
                const span = Number(lastRows[0].requested_at_ms) - Number(lastRows[lastRows.length - 1].requested_at_ms);
                if (span >= 0 && span < PROLOGUE_RAPID_FETCH_THRESHOLD_MS * lastRows.length) {
                    await pool.query(
                        `UPDATE arc_prologue_requests SET flagged = true, flagged_reason = 'monotone_pattern' WHERE id = $1`,
                        [row.id]
                    );
                    await flagLicenseAnomaly(license_key, 'prologue_monotone_pattern');
                }
            }
        }

        const prologue = lookupPrologue(function_hash);
        if (!prologue) {
            return res.status(404).json({ status: 'error', reason: 'prologue_unknown' });
        }

        const enc = pageKeys.encryptPrologue(prologue.bytes, license_key, hwid, function_hash, nonce);

        await pool.query(
            `UPDATE arc_prologue_requests SET consumed = true, consumed_at_ms = $1 WHERE id = $2`,
            [Date.now(), row.id]
        );

        const responsePayload = {
            status: 'ok',
            function_name,
            function_hash,
            nonce,
            issued_at_ms: nowMs,
            ciphertext: enc.ciphertext.toString('base64'),
            iv: enc.iv.toString('hex'),
            auth_tag: enc.authTag.toString('hex'),
            prologue_size: prologue.bytes.length,
        };
        responsePayload.signature = signPayload(responsePayload);
        return res.json(responsePayload);
    } catch (err) {
        console.error('[functions/prologue] error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

async function flagLicenseAnomaly(licenseKey, reason) {
    const nowSec = Math.floor(Date.now() / 1000);
    try {
        await pool.query(
            `UPDATE licenses
                SET prologue_anomaly_count = prologue_anomaly_count + 1,
                    prologue_last_anomaly_at = $1,
                    prologue_last_anomaly_reason = $2
              WHERE key = $3`,
            [nowSec, String(reason || ''), licenseKey]
        );
    } catch (_) {}
}

async function purgeExpiredFunctionRecords() {
    const nowSec = Math.floor(Date.now() / 1000);
    try {
        await pool.query(`DELETE FROM arc_function_calls WHERE expires_at < $1 - 3600`, [nowSec]);
        await pool.query(`DELETE FROM arc_prologue_requests WHERE requested_at_ms < $1`, [Date.now() - 7 * 24 * 3600 * 1000]);
    } catch (_) {}
}
setInterval(purgeExpiredFunctionRecords, 5 * 60 * 1000).unref();

router.post('/list', async (req, res) => {
    try {
        const { license_key, session_token, hwid } = req.body || {};
        const validation = await validateFunctionSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }
        return res.json({
            status: 'ok',
            functions: Array.from(criticalFunctionSet),
            ttl_seconds: FUNCTION_TOKEN_TTL_SECONDS,
        });
    } catch (err) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router._internal = {
    functionAllowed,
    loadCriticalFunctions,
    lookupPrologue,
    purgeExpiredFunctionRecords,
};

module.exports = router;
