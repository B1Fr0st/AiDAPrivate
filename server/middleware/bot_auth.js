'use strict';

const crypto = require('crypto');

let s_cachedPubKey = null;
let s_cachedPubKeyB64 = '';

const MAX_TIMESTAMP_DRIFT_SECONDS = 120;

function getBotPublicKey() {
    const b64 = (process.env.BOT_ED25519_PUBLIC_KEY_B64 || '').trim();
    if (!b64) return null;
    if (s_cachedPubKey && s_cachedPubKeyB64 === b64) return s_cachedPubKey;
    try {
        let der;
        const raw = Buffer.from(b64, 'base64');
        if (raw.length === 32) {
            const SPKI_PREFIX = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
            der = Buffer.concat([SPKI_PREFIX, raw]);
        } else {
            der = raw;
        }
        s_cachedPubKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        s_cachedPubKeyB64 = b64;
        return s_cachedPubKey;
    } catch (err) {
        console.warn('[bot_auth] BOT_ED25519_PUBLIC_KEY_B64 parse failed:', err && err.message ? err.message : err);
        s_cachedPubKey = null;
        s_cachedPubKeyB64 = '';
        return null;
    }
}

function canonicalize(payload) {
    const filtered = Object.keys(payload || {})
        .filter(k => !k.startsWith('__'))
        .sort();
    return JSON.stringify(filtered.reduce((acc, k) => {
        acc[k] = payload[k];
        return acc;
    }, {}));
}

function verifyBotRequest(req) {
    const pub = getBotPublicKey();
    if (!pub) {
        return { ok: false, reason: 'bot_public_key_unconfigured' };
    }
    const sigB64 = String(req.headers['x-bot-signature'] || '').trim();
    if (!sigB64) {
        return { ok: false, reason: 'bot_signature_missing' };
    }
    const body = req.body;
    if (!body || typeof body !== 'object') {
        return { ok: false, reason: 'bot_body_missing' };
    }
    const ts = Number(body.ts);
    if (!Number.isFinite(ts)) {
        return { ok: false, reason: 'bot_timestamp_missing' };
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > MAX_TIMESTAMP_DRIFT_SECONDS) {
        return { ok: false, reason: 'bot_timestamp_drift' };
    }
    const sigBuf = Buffer.from(sigB64, 'base64');
    if (sigBuf.length === 0) {
        return { ok: false, reason: 'bot_signature_format' };
    }
    const canonical = canonicalize(body);
    let ok = false;
    try {
        ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, sigBuf);
    } catch (err) {
        return { ok: false, reason: 'bot_signature_verify_threw' };
    }
    if (!ok) {
        return { ok: false, reason: 'bot_signature_invalid' };
    }
    return { ok: true, action: String(body.action || '') };
}

function authenticate(req, res, next) {
    const result = verifyBotRequest(req);
    if (!result.ok) {
        return res.status(403).json({ status: 'error', reason: result.reason || 'bot_unauthorized' });
    }
    req.botAuth = { action: result.action };
    return next();
}

let s_adminKey = null;

function getAdminKey() {
    if (s_adminKey) return s_adminKey;
    const direct = String(process.env.ADMIN_HMAC_SECRET_B64 || '').trim();
    if (direct) {
        const buf = Buffer.from(direct, 'base64');
        if (buf.length >= 32) {
            s_adminKey = buf;
            return s_adminKey;
        }
    }
    const master = String(process.env.SERVER_MASTER_KEY_B64 || '').trim();
    if (master) {
        const buf = Buffer.from(master, 'base64');
        if (buf.length !== 32) throw new Error('admin_hmac_master_key_invalid');
        s_adminKey = crypto.createHmac('sha256', buf).update('aida/admin-hmac/v1', 'utf8').digest();
        return s_adminKey;
    }
    throw new Error('admin_hmac_key_unavailable');
}

function canonicalizeAdmin(payload) {
    const filtered = Object.keys(payload || {})
        .filter(k => !k.startsWith('__') && k !== 'signature')
        .sort();
    return JSON.stringify(filtered.reduce((acc, k) => {
        acc[k] = payload[k];
        return acc;
    }, {}));
}

function verifyAdminRequest(req) {
    try {
        const sigHex = String(req.headers['x-admin-signature'] || '').trim().toLowerCase();
        if (!sigHex || !/^[0-9a-f]{64}$/.test(sigHex)) {
            return { ok: false, reason: 'admin_signature_missing' };
        }
        const body = req.body;
        if (!body || typeof body !== 'object') {
            return { ok: false, reason: 'admin_body_missing' };
        }
        const ts = Number(body.ts);
        if (!Number.isFinite(ts)) {
            return { ok: false, reason: 'admin_timestamp_missing' };
        }
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > MAX_TIMESTAMP_DRIFT_SECONDS) {
            return { ok: false, reason: 'admin_timestamp_drift' };
        }
        const nonce = String(body.nonce || '').trim().toLowerCase();
        if (!nonce || !/^[0-9a-f]{32,128}$/.test(nonce)) {
            return { ok: false, reason: 'admin_nonce_invalid' };
        }
        const canonical = canonicalizeAdmin(body);
        const expected = crypto.createHmac('sha256', getAdminKey()).update(canonical, 'utf8').digest();
        const providedBuf = Buffer.from(sigHex, 'hex');
        if (providedBuf.length !== expected.length) {
            return { ok: false, reason: 'admin_signature_invalid' };
        }
        if (!crypto.timingSafeEqual(expected, providedBuf)) {
            return { ok: false, reason: 'admin_signature_invalid' };
        }
        return { ok: true };
    } catch (err) {
        return { ok: false, reason: 'admin_key_error' };
    }
}

module.exports = {
    authenticate,
    verifyBotRequest,
    canonicalize,
    getBotPublicKey,
    verifyAdminRequest,
    getAdminKey,
    canonicalizeAdmin,
};
