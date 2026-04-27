'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

let s_warned_master_key_fallback = false;

function loadMasterKey() {
    const src = process.env.SERVER_MASTER_KEY_B64 || '';
    if (src) {
        const key = Buffer.from(src, 'base64');
        if (key.length !== KEY_LEN) {
            throw new Error(`SERVER_MASTER_KEY_B64 must decode to 32 bytes; got ${key.length}`);
        }
        return key;
    }
    const arcSecret = process.env.ARC_MASTER_SECRET || '';
    if (!arcSecret) {
        throw new Error('Neither SERVER_MASTER_KEY_B64 nor ARC_MASTER_SECRET is set; cannot derive master key');
    }
    const derived = crypto.createHmac('sha256', Buffer.from(arcSecret, 'utf8'))
                          .update('aida/server-master-key/v1')
                          .digest();
    if (derived.length !== KEY_LEN) {
        throw new Error(`derived master key length ${derived.length} != ${KEY_LEN}`);
    }
    if (!s_warned_master_key_fallback) {
        s_warned_master_key_fallback = true;
        console.warn('[kw_wrap] SERVER_MASTER_KEY_B64 not set; deriving master key from ARC_MASTER_SECRET (set SERVER_MASTER_KEY_B64 in .env for an independent key).');
    }
    return derived;
}

function deriveSubKey(label) {
    const master = loadMasterKey();
    return crypto.createHmac('sha256', master).update(String(label || '')).digest();
}

function wrap(plaintext, label) {
    if (!Buffer.isBuffer(plaintext)) plaintext = Buffer.from(plaintext);
    const key = deriveSubKey(label || 'kw_wrap/v1');
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, key, iv);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]);
}

function unwrap(blob, label) {
    if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);
    if (blob.length < IV_LEN + TAG_LEN) throw new Error('wrapped blob too short');
    const key = deriveSubKey(label || 'kw_wrap/v1');
    const iv = blob.subarray(0, IV_LEN);
    const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = blob.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function generateWitnessKey() {
    return crypto.randomBytes(32);
}

function generateInstallSecret() {
    return crypto.randomBytes(32);
}

function deriveKwSubkey(kw, label) {
    if (!Buffer.isBuffer(kw)) kw = Buffer.from(kw);
    return crypto.createHmac('sha256', kw).update(String(label || '')).digest();
}

module.exports = {
    wrap,
    unwrap,
    generateWitnessKey,
    generateInstallSecret,
    deriveKwSubkey,
};
