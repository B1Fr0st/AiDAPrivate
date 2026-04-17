'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

function loadMasterKey() {
    const src = process.env.SERVER_MASTER_KEY_B64 || '';
    if (!src) {
        throw new Error('SERVER_MASTER_KEY_B64 env var not set; cannot wrap Kw / install_secret');
    }
    const key = Buffer.from(src, 'base64');
    if (key.length !== KEY_LEN) {
        throw new Error(`SERVER_MASTER_KEY_B64 must decode to 32 bytes; got ${key.length}`);
    }
    return key;
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
