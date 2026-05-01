'use strict';

const crypto = require('crypto');
const localHsm = require('./local_hsm');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const VERSION = 'v1';
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEX_RE = /^[0-9a-fA-F]+$/;

let cachedRootKey = null;
let cachedRootKeyId = '';

function loadRootKey() {
    const kmsKeyId = (process.env.KMS_KEY_ID || '').trim();
    if (cachedRootKey && cachedRootKeyId === kmsKeyId) {
        return cachedRootKey;
    }
    if (kmsKeyId.startsWith('arn:aws:kms:')) {
        const synchronouslyDerivedSrc = process.env.KMS_DATA_KEY_B64 || '';
        if (!synchronouslyDerivedSrc) {
            throw new Error('column_crypt: KMS_KEY_ID points to AWS KMS but KMS_DATA_KEY_B64 (the cached envelope data key) is not set; run scripts/kms_unwrap.js at boot to populate it.');
        }
        const buf = Buffer.from(synchronouslyDerivedSrc, 'base64');
        if (buf.length !== KEY_LEN) {
            throw new Error(`column_crypt: KMS_DATA_KEY_B64 must decode to ${KEY_LEN} bytes; got ${buf.length}`);
        }
        cachedRootKey = buf;
        cachedRootKeyId = kmsKeyId;
        return cachedRootKey;
    }
    const local = localHsm.loadOrCreateColumnRootKey();
    cachedRootKey = local;
    cachedRootKeyId = kmsKeyId;
    return cachedRootKey;
}

function clearKeyCache() {
    cachedRootKey = null;
    cachedRootKeyId = '';
}

function deriveColumnKey(rowUuid, label) {
    if (typeof rowUuid !== 'string' || !UUID_RE.test(rowUuid)) {
        throw new Error('column_crypt: rowUuid must be a valid UUID string');
    }
    if (typeof label !== 'string' || label.length === 0 || label.length > 64) {
        throw new Error('column_crypt: label must be a non-empty string ≤64 chars');
    }
    const salt = Buffer.from(rowUuid.replace(/-/g, ''), 'hex');
    const info = Buffer.from(`aida/column/${label}/v1`, 'utf8');
    const root = loadRootKey();
    const okm = crypto.hkdfSync('sha512', root, salt, info, KEY_LEN);
    return Buffer.from(okm);
}

function encrypt(rowUuid, label, plaintext) {
    if (plaintext === null || plaintext === undefined) {
        return '';
    }
    if (typeof plaintext === 'string' && plaintext.length === 0) {
        return '';
    }
    if (Buffer.isBuffer(plaintext) && plaintext.length === 0) {
        return '';
    }
    const ptBuf = Buffer.isBuffer(plaintext)
        ? plaintext
        : Buffer.from(String(plaintext), 'utf8');
    const key = deriveColumnKey(rowUuid, label);
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, key, iv);
    const ct = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${VERSION}:${iv.toString('hex')}:${tag.toString('hex')}:${ct.toString('hex')}`;
}

function decrypt(rowUuid, label, blob) {
    if (blob === null || blob === undefined || blob === '') {
        return '';
    }
    if (typeof blob !== 'string') {
        throw new Error('column_crypt.decrypt: blob must be a string');
    }
    const parts = blob.split(':');
    if (parts.length !== 4 || parts[0] !== VERSION) {
        throw new Error('column_crypt.decrypt: invalid blob format');
    }
    const ivHex = parts[1];
    const tagHex = parts[2];
    const ctHex = parts[3];
    if (!HEX_RE.test(ivHex) || !HEX_RE.test(tagHex) || !HEX_RE.test(ctHex)) {
        throw new Error('column_crypt.decrypt: blob contains non-hex bytes');
    }
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const ct = Buffer.from(ctHex, 'hex');
    if (iv.length !== IV_LEN || tag.length !== TAG_LEN) {
        throw new Error('column_crypt.decrypt: iv or tag length mismatch');
    }
    const key = deriveColumnKey(rowUuid, label);
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
}

function isCiphertext(blob) {
    if (typeof blob !== 'string' || blob.length < (VERSION.length + 1 + IV_LEN * 2 + 1 + TAG_LEN * 2 + 1)) {
        return false;
    }
    const parts = blob.split(':');
    if (parts.length !== 4 || parts[0] !== VERSION) return false;
    return HEX_RE.test(parts[1]) && HEX_RE.test(parts[2]) && HEX_RE.test(parts[3])
        && parts[1].length === IV_LEN * 2
        && parts[2].length === TAG_LEN * 2;
}

function generateRowUuid() {
    return crypto.randomUUID();
}

function decryptIfCiphertext(rowUuid, label, value) {
    if (typeof value !== 'string' || value === '') return value || '';
    if (!isCiphertext(value)) return value;
    return decrypt(rowUuid, label, value);
}

module.exports = {
    encrypt,
    decrypt,
    decryptIfCiphertext,
    isCiphertext,
    generateRowUuid,
    deriveColumnKey,
    clearKeyCache,
    VERSION,
};
