'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const VERSION = 0x01;

let s_cachedKey = null;
let s_warned_derived = false;

function loadAeadKey() {
    if (s_cachedKey) return s_cachedKey;
    const direct = process.env.SESSION_AEAD_KEY || '';
    if (direct) {
        const trimmed = direct.trim();
        let key = null;
        if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length === KEY_LEN * 2) {
            key = Buffer.from(trimmed, 'hex');
        } else {
            try { key = Buffer.from(trimmed, 'base64'); } catch (_) { key = null; }
        }
        if (!key || key.length !== KEY_LEN) {
            throw new Error('SESSION_AEAD_KEY must decode to exactly 32 bytes (hex64 or base64)');
        }
        s_cachedKey = key;
        return s_cachedKey;
    }
    const arcSecret = process.env.ARC_MASTER_SECRET || '';
    const masterKey = process.env.SERVER_MASTER_KEY_B64 || '';
    let seed = null;
    if (masterKey) {
        try { seed = Buffer.from(masterKey, 'base64'); } catch (_) { seed = null; }
    }
    if ((!seed || seed.length === 0) && arcSecret) {
        seed = Buffer.from(arcSecret, 'utf8');
    }
    if (!seed || seed.length === 0) {
        throw new Error('SESSION_AEAD_KEY not set and no fallback secret (ARC_MASTER_SECRET / SERVER_MASTER_KEY_B64) available');
    }
    s_cachedKey = crypto.createHmac('sha256', seed)
        .update('aida/session-aead/v1', 'utf8')
        .digest();
    if (!s_warned_derived) {
        s_warned_derived = true;
        console.warn('[session_aead] SESSION_AEAD_KEY not set; deriving from fallback secret. Set SESSION_AEAD_KEY in .env (32-byte hex or base64) for production.');
    }
    return s_cachedKey;
}

function canonicalSessionPayload(licenseId, hwidHash, issuedAt, ttl, licenseTier) {
    return {
        license_id: String(licenseId || ''),
        hwid_hash: String(hwidHash || ''),
        issued_at: Number.isFinite(issuedAt) ? Math.floor(issuedAt) : 0,
        ttl: Number.isFinite(ttl) ? Math.floor(ttl) : 0,
        license_tier: String(licenseTier || 'standard'),
    };
}

function seal(licenseId, hwidHash, issuedAt, ttl, licenseTier) {
    const key = loadAeadKey();
    const payload = canonicalSessionPayload(licenseId, hwidHash, issuedAt, ttl, licenseTier);
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const versionByte = Buffer.from([VERSION]);
    return Buffer.concat([versionByte, iv, tag, encrypted]).toString('base64url');
}

function open(sessionToken) {
    if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
        return { ok: false, reason: 'empty_token' };
    }
    let raw;
    try {
        raw = Buffer.from(sessionToken, 'base64url');
    } catch (_) {
        return { ok: false, reason: 'b64_decode' };
    }
    if (raw.length < 1 + IV_LEN + TAG_LEN + 1) {
        return { ok: false, reason: 'short_token' };
    }
    if (raw[0] !== VERSION) {
        return { ok: false, reason: 'unknown_version' };
    }
    const iv = raw.subarray(1, 1 + IV_LEN);
    const tag = raw.subarray(1 + IV_LEN, 1 + IV_LEN + TAG_LEN);
    const ct = raw.subarray(1 + IV_LEN + TAG_LEN);
    try {
        const decipher = crypto.createDecipheriv(ALGO, loadAeadKey(), iv);
        decipher.setAuthTag(tag);
        const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
        const parsed = JSON.parse(pt.toString('utf8'));
        if (!parsed || typeof parsed !== 'object') {
            return { ok: false, reason: 'json_shape' };
        }
        return { ok: true, payload: parsed };
    } catch (err) {
        return { ok: false, reason: 'auth_fail' };
    }
}

function isSealedFormat(value) {
    if (typeof value !== 'string' || value.length < 32) return false;
    if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
    try {
        const raw = Buffer.from(value, 'base64url');
        return raw.length >= 1 + IV_LEN + TAG_LEN + 1 && raw[0] === VERSION;
    } catch (_) {
        return false;
    }
}

function deriveSessionKey(licenseSecret, sessionToken, hwid, issuedAt) {
    const secret = Buffer.isBuffer(licenseSecret) ? licenseSecret : Buffer.from(String(licenseSecret || ''), 'utf8');
    return crypto.createHmac('sha256', secret)
        .update('session|' + String(sessionToken || '') + '|' + String(hwid || '') + '|' + String(issuedAt || 0), 'utf8')
        .digest();
}

function deriveAuthHmacKey(sessionKey) {
    if (!Buffer.isBuffer(sessionKey)) sessionKey = Buffer.from(String(sessionKey || ''), 'utf8');
    return crypto.createHmac('sha256', sessionKey).update('auth', 'utf8').digest();
}

function deriveRatchet(sessionKey, counter) {
    if (!Buffer.isBuffer(sessionKey)) sessionKey = Buffer.from(String(sessionKey || ''), 'utf8');
    const c = Number.isFinite(counter) ? Math.max(0, Math.floor(counter)) : 0;
    return crypto.createHmac('sha256', sessionKey).update('ratchet|' + String(c), 'utf8').digest();
}

function clearKeyCacheForTests() {
    s_cachedKey = null;
}

module.exports = {
    seal,
    open,
    isSealedFormat,
    deriveSessionKey,
    deriveAuthHmacKey,
    deriveRatchet,
    canonicalSessionPayload,
    clearKeyCacheForTests,
    VERSION,
};
