'use strict';

const crypto = require('crypto');
const pool = require('../db/pool');

const CACHE_TTL_MS = parseInt(process.env.KILL_SWITCH_CACHE_TTL_MS || '5000', 10) || 5000;
const HMAC_INFO = 'aida/kill-switch/v1';

let s_cache_loaded_at = 0;
let s_cache_global    = false;
let s_cache_keys      = new Set();
let s_cache_hwids     = new Set();
let s_cache_sessions  = new Set();
let s_loading         = null;
let s_hmac_key        = null;

function getHmacKey() {
    if (s_hmac_key) return s_hmac_key;
    const direct = process.env.KILL_SWITCH_HMAC_KEY_B64 || '';
    if (direct) {
        try {
            const buf = Buffer.from(direct, 'base64');
            if (buf.length >= 16) {
                s_hmac_key = buf;
                return s_hmac_key;
            }
        } catch (_) { }
    }
    const fallback = process.env.ARC_MASTER_SECRET
        || process.env.SERVER_MASTER_KEY_B64
        || 'aida-killswitch-fallback';
    s_hmac_key = crypto.createHmac('sha256', Buffer.from(String(fallback), 'utf8'))
        .update(HMAC_INFO, 'utf8')
        .digest();
    return s_hmac_key;
}

function hashLicenseKey(licenseKey) {
    if (!licenseKey) return '';
    return crypto.createHmac('sha256', getHmacKey())
        .update(String(licenseKey), 'utf8')
        .digest('hex');
}

function hashHwid(hwid) {
    if (!hwid) return '';
    return crypto.createHash('sha256')
        .update(String(hwid), 'utf8')
        .digest('hex');
}

function hashSessionId(sessionId) {
    if (!sessionId) return '';
    return crypto.createHash('sha256')
        .update(String(sessionId), 'utf8')
        .digest('hex');
}

async function reloadCache() {
    if (s_loading) return s_loading;
    s_loading = (async () => {
        try {
            const { rows } = await pool.query(
                `SELECT target_type, target_value
                   FROM kill_switch
                  WHERE expires_at IS NULL OR expires_at > NOW()`
            );
            const newKeys     = new Set();
            const newHwids    = new Set();
            const newSessions = new Set();
            let global = false;
            for (const r of rows) {
                const t = String(r.target_type || '');
                const v = String(r.target_value || '');
                if (t === 'global') { global = true; continue; }
                if (!v) continue;
                if (t === 'license_key') newKeys.add(v);
                else if (t === 'hwid_hash') newHwids.add(v);
                else if (t === 'session_id') newSessions.add(v);
            }
            s_cache_global = global;
            s_cache_keys = newKeys;
            s_cache_hwids = newHwids;
            s_cache_sessions = newSessions;
            s_cache_loaded_at = Date.now();
        } catch (err) {
            console.warn('[kill_switch] reload failed:', err && err.message ? err.message : err);
        } finally {
            s_loading = null;
        }
    })();
    return s_loading;
}

async function ensureFresh() {
    const now = Date.now();
    if (s_cache_loaded_at === 0 || (now - s_cache_loaded_at) > CACHE_TTL_MS) {
        await reloadCache();
    }
}

function bodyLicenseKey(req) {
    const body = req && req.body;
    if (!body || typeof body !== 'object') return '';
    const candidates = ['license_key', 'licenseKey', 'key', 'admin_target_key', 'target_key'];
    for (const k of candidates) {
        const v = body[k];
        if (typeof v === 'string' && v.length > 0) return v.trim();
    }
    return '';
}

function bodyHwid(req) {
    const body = req && req.body;
    if (!body || typeof body !== 'object') return '';
    const candidates = ['hwid', 'machine_hwid', 'hwid_v2'];
    for (const k of candidates) {
        const v = body[k];
        if (typeof v === 'string' && v.length > 0) return v.trim();
    }
    return '';
}

function bodySessionId(req) {
    const body = req && req.body;
    if (!body || typeof body !== 'object') return '';
    const candidates = ['session_id', 'sessionId', 'session_token', 'sessionToken'];
    for (const k of candidates) {
        const v = body[k];
        if (typeof v === 'string' && v.length > 0) return v.trim();
    }
    return '';
}

async function isDropped(req) {
    await ensureFresh();
    if (s_cache_global) {
        return { dropped: true, reason: 'global' };
    }
    const lk = bodyLicenseKey(req);
    if (lk && s_cache_keys.has(lk)) {
        return { dropped: true, reason: 'license_key' };
    }
    const hw = bodyHwid(req);
    if (hw) {
        const hh = hashHwid(hw);
        if (s_cache_hwids.has(hh) || s_cache_hwids.has(hw)) {
            return { dropped: true, reason: 'hwid_hash' };
        }
    }
    const sid = bodySessionId(req);
    if (sid) {
        const sh = hashSessionId(sid);
        if (s_cache_sessions.has(sh) || s_cache_sessions.has(sid)) {
            return { dropped: true, reason: 'session_id' };
        }
    }
    return { dropped: false };
}

function isAdminKillRequest(req) {
    const body = req && req.body;
    if (!body || typeof body !== 'object') return false;
    if (String(body.action || '') !== 'kill') return false;
    if (typeof req.headers === 'object' && typeof req.headers['x-bot-signature'] === 'string' && req.headers['x-bot-signature'].length > 0) {
        return true;
    }
    if (typeof body.admin_key === 'string' && body.admin_key.length > 0) {
        return true;
    }
    return false;
}

async function middleware(req, res, next) {
    try {
        if (isAdminKillRequest(req)) {
            return next();
        }
        const verdict = await isDropped(req);
        if (verdict.dropped) {
            res.setHeader('Content-Type', 'application/json');
            const body = JSON.stringify({ ok: false, error_code: 'EAUTH' });
            res.setHeader('Content-Length', Buffer.byteLength(body, 'utf8'));
            req._killSwitchDropped = verdict.reason;
            return res.status(401).send(body);
        }
        return next();
    } catch (err) {
        return next();
    }
}

async function addKill(targetType, targetValue, reason, createdBy, expiresAt) {
    const validTypes = ['license_key', 'hwid_hash', 'session_id', 'global'];
    if (!validTypes.includes(targetType)) {
        return { ok: false, reason: 'invalid_target_type' };
    }
    try {
        const expiresParam = expiresAt ? new Date(expiresAt * 1000).toISOString() : null;
        await pool.query(
            `INSERT INTO kill_switch (target_type, target_value, reason, created_by, expires_at)
             VALUES ($1, $2, $3, $4, $5::TIMESTAMPTZ)`,
            [targetType, targetValue || null, String(reason || ''), String(createdBy || ''), expiresParam]
        );
        s_cache_loaded_at = 0;
        return { ok: true };
    } catch (err) {
        return { ok: false, reason: 'insert_failed', error: err && err.message ? err.message : String(err) };
    }
}

async function removeKill(targetType, targetValue) {
    try {
        const { rowCount } = await pool.query(
            `DELETE FROM kill_switch
              WHERE target_type = $1
                AND COALESCE(target_value, '') = COALESCE($2, '')`,
            [targetType, targetValue || null]
        );
        s_cache_loaded_at = 0;
        return { ok: true, removed: rowCount || 0 };
    } catch (err) {
        return { ok: false, reason: 'delete_failed', error: err && err.message ? err.message : String(err) };
    }
}

async function listActive() {
    try {
        const { rows } = await pool.query(
            `SELECT id, target_type, target_value, reason, created_by, created_at, expires_at
               FROM kill_switch
              WHERE expires_at IS NULL OR expires_at > NOW()
              ORDER BY created_at DESC`
        );
        return { ok: true, rows };
    } catch (err) {
        return { ok: false, reason: 'select_failed', error: err && err.message ? err.message : String(err) };
    }
}

function invalidateCache() {
    s_cache_loaded_at = 0;
}

module.exports = {
    middleware,
    isDropped,
    addKill,
    removeKill,
    listActive,
    invalidateCache,
    hashLicenseKey,
    hashHwid,
    hashSessionId,
};
