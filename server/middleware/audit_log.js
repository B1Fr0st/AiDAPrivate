'use strict';

const crypto = require('crypto');
const pool = require('../db/pool');

let s_chainCache = null;
let s_hmacKey = null;

function getHmacKey() {
    if (s_hmacKey) return s_hmacKey;
    const direct = process.env.AUDIT_LOG_HMAC_KEY_B64 || '';
    if (direct) {
        try {
            const buf = Buffer.from(direct, 'base64');
            if (buf.length >= 16) {
                s_hmacKey = buf;
                return s_hmacKey;
            }
        } catch (_) { }
    }
    const fallback = process.env.ARC_MASTER_SECRET || process.env.SERVER_MASTER_KEY_B64 || 'aida-audit-fallback';
    s_hmacKey = crypto.createHmac('sha256', Buffer.from(String(fallback), 'utf8'))
        .update('aida/audit-log/v1', 'utf8')
        .digest();
    return s_hmacKey;
}

async function getLastChainHash() {
    if (s_chainCache) return s_chainCache;
    try {
        const { rows } = await pool.query('SELECT chain_hash FROM audit_log ORDER BY ts DESC, id DESC LIMIT 1');
        s_chainCache = rows.length > 0 ? String(rows[0].chain_hash || '') : '';
    } catch (_) {
        s_chainCache = '';
    }
    return s_chainCache;
}

function setLastChainHash(hash) {
    s_chainCache = typeof hash === 'string' ? hash : '';
}

async function appendAuditEntry(entry) {
    const ts = Math.floor(Date.now() / 1000);
    const id = (entry && entry.id) ? String(entry.id) : crypto.randomBytes(16).toString('hex');
    const actorId = String((entry && entry.actor_id) || '');
    const actorTag = String((entry && entry.actor_tag) || '');
    const action = String((entry && entry.action) || 'unknown');
    const target = String((entry && entry.target) || '');
    const details = entry && entry.details ? entry.details : {};
    const detailsJson = JSON.stringify(details);

    const prev = await getLastChainHash();
    const chainBase = `${prev}|${ts}|${actorId}|${actorTag}|${action}|${target}|${detailsJson}`;
    const chainHash = crypto.createHash('sha256').update(chainBase, 'utf8').digest('hex');
    const hmacHex = crypto.createHmac('sha256', getHmacKey()).update(chainHash, 'utf8').digest('hex');

    try {
        await pool.query(
            `INSERT INTO audit_log (id, ts, actor_id, actor_tag, action, target, details, prev_chain_hash, chain_hash, hmac)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)`,
            [id, ts, actorId, actorTag, action, target, detailsJson, prev, chainHash, hmacHex]
        );
        setLastChainHash(chainHash);
        return { ok: true, id, chain_hash: chainHash };
    } catch (err) {
        if (err && err.code === '23505') {
            const fresh = crypto.randomBytes(16).toString('hex');
            return appendAuditEntry(Object.assign({}, entry, { id: fresh }));
        }
        console.warn('[audit_log] append failed:', err && err.message ? err.message : err);
        return { ok: false, reason: 'append_failed' };
    }
}

async function logValidationFailure(reasonId, reason, licenseKey, hwid, clientIp, extra) {
    return appendAuditEntry({
        actor_id: '',
        actor_tag: '',
        action: 'license.validate_invalid',
        target: licenseKey || '',
        details: Object.assign({
            reason_id: Number.isFinite(reasonId) ? reasonId : 1,
            reason: String(reason || 'unknown'),
            hwid_prefix: typeof hwid === 'string' ? hwid.slice(0, 16) : '',
            client_ip: clientIp || '',
        }, extra || {}),
    });
}

async function logServerEvent(action, target, details) {
    return appendAuditEntry({
        action: String(action || 'server.event'),
        target: String(target || ''),
        details: details || {},
    });
}

function hashLicenseKeyHmac(licenseKey) {
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

function hashUserAgent(ua) {
    if (!ua) return '';
    return crypto.createHash('sha256')
        .update(String(ua), 'utf8')
        .digest('hex')
        .slice(0, 32);
}

function normalizeIpForInet(rawIp) {
    if (typeof rawIp !== 'string') return null;
    let ip = rawIp.trim();
    if (!ip) return null;
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (v4.test(ip)) return ip;
    if (/^[0-9a-fA-F:]+$/.test(ip)) return ip;
    return null;
}

async function logV2(record) {
    const action = String((record && record.action) || 'unknown');
    const licenseKey = (record && record.license_key) || '';
    const hwid = (record && record.hwid) || '';
    const sourceIp = (record && record.source_ip) || '';
    const userAgent = (record && record.user_agent) || '';
    const decision = String((record && record.decision) || 'unknown');
    const reasonCode = String((record && record.reason_code) || '');
    const extra = (record && record.extra) ? record.extra : {};

    const licenseHmac = hashLicenseKeyHmac(licenseKey);
    const hwidHash = hashHwid(hwid);
    const ipForInsert = normalizeIpForInet(sourceIp);
    const uaHash = hashUserAgent(userAgent);

    try {
        await pool.query(
            `INSERT INTO audit_log_v2 (action, license_key_hmac, hwid_hash, source_ip, user_agent_hash, decision, reason_code, extra)
             VALUES ($1, $2, $3, $4::INET, $5, $6, $7, $8::jsonb)`,
            [action, licenseHmac, hwidHash || null, ipForInsert, uaHash || null, decision, reasonCode, JSON.stringify(extra)]
        );
        return { ok: true };
    } catch (err) {
        console.warn('[audit_log_v2] insert failed:', err && err.message ? err.message : err);
        return { ok: false, reason: 'insert_failed' };
    }
}

function makeRequestLogger(action) {
    return async function loggerInstance(req, result) {
        try {
            const body = (req && req.body) || {};
            const headers = (req && req.headers) || {};
            const xff = typeof headers['x-forwarded-for'] === 'string' ? headers['x-forwarded-for'] : '';
            const ip = (xff.split(',')[0] || '').trim() || (req && req.ip) || '';
            const ua = typeof headers['user-agent'] === 'string' ? headers['user-agent'] : '';
            const decision = (result && result.decision) || 'unknown';
            const reasonCode = (result && result.reason_code) || '';
            const extra = (result && result.extra) || {};
            await logV2({
                action,
                license_key: body.license_key || body.licenseKey || body.key || '',
                hwid: body.hwid || '',
                source_ip: ip,
                user_agent: ua,
                decision,
                reason_code: reasonCode,
                extra,
            });
        } catch (_) { }
    };
}

module.exports = {
    appendAuditEntry,
    logValidationFailure,
    logServerEvent,
    logV2,
    makeRequestLogger,
    hashLicenseKeyHmac,
    hashHwid,
    hashUserAgent,
};
