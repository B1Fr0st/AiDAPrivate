'use strict';

const crypto = require('crypto');

const PAGE_SIZE_BYTES = 4096;
const EPOCH_INTERVAL_SECONDS = parseInt(process.env.PAGE_EPOCH_INTERVAL_SECONDS || '300', 10);
const FUNCTION_TOKEN_TTL_SECONDS = parseInt(process.env.FUNCTION_TOKEN_TTL_SECONDS || '10', 10);
const PROLOGUE_RAPID_FETCH_THRESHOLD_MS = parseInt(process.env.PROLOGUE_RAPID_FETCH_THRESHOLD_MS || '500', 10);
const PROLOGUE_RAPID_FETCH_COUNT = parseInt(process.env.PROLOGUE_RAPID_FETCH_COUNT || '3', 10);

function loadMasterSecret() {
    const arcSecret = process.env.ARC_MASTER_SECRET || '';
    if (!arcSecret || arcSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }
    return Buffer.from(arcSecret, 'utf8');
}

function currentEpoch(nowSec) {
    const now = typeof nowSec === 'number' ? nowSec : Math.floor(Date.now() / 1000);
    if (EPOCH_INTERVAL_SECONDS <= 0) return now;
    return Math.floor(now / EPOCH_INTERVAL_SECONDS) * EPOCH_INTERVAL_SECONDS;
}

function epochNonce(epochSec, sessionToken, hwid) {
    const master = loadMasterSecret();
    return crypto.createHmac('sha256', master)
        .update('aida/page-epoch/v1')
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(epochSec), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(sessionToken || ''), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(hwid || ''), 'utf8'))
        .digest();
}

function derivePageKey(licenseKey, sessionToken, hwid, pageIndex, epochNonceBuf) {
    if (!Buffer.isBuffer(epochNonceBuf) || epochNonceBuf.length !== 32) {
        throw new Error('epoch_nonce must be a 32-byte Buffer');
    }
    const ikm = Buffer.concat([
        Buffer.from(String(licenseKey || ''), 'utf8'),
        Buffer.from('|', 'utf8'),
        Buffer.from(String(sessionToken || ''), 'utf8'),
        Buffer.from('|', 'utf8'),
        Buffer.from(String(hwid || ''), 'utf8'),
    ]);
    const salt = Buffer.alloc(8);
    salt.writeUInt32LE(pageIndex >>> 0, 0);
    salt.writeUInt32LE(((pageIndex / 0x100000000) >>> 0), 4);
    const info = Buffer.concat([
        Buffer.from('aida/streaming-page/v1', 'utf8'),
        epochNonceBuf,
    ]);
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 32));
}

function encryptPage(plaintext, licenseKey, sessionToken, hwid, pageIndex, epochSec) {
    const epochBuf = epochNonce(epochSec, sessionToken, hwid);
    const key = derivePageKey(licenseKey, sessionToken, hwid, pageIndex, epochBuf);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const verify_hmac = crypto.createHmac('sha256', key)
        .update(iv)
        .update(authTag)
        .update(ciphertext)
        .update(Buffer.from(String(pageIndex), 'utf8'))
        .digest();
    key.fill(0);
    epochBuf.fill(0);
    return { ciphertext, iv, authTag, hmac: verify_hmac, epoch: epochSec };
}

function splitIntoPages(blob) {
    const out = [];
    for (let off = 0; off < blob.length; off += PAGE_SIZE_BYTES) {
        out.push(blob.subarray(off, Math.min(off + PAGE_SIZE_BYTES, blob.length)));
    }
    return out;
}

function getPageCount(blobSize) {
    return Math.ceil(blobSize / PAGE_SIZE_BYTES);
}

function pageBoundsForBlob(blobSize, pageIndex) {
    const start = pageIndex * PAGE_SIZE_BYTES;
    const end = Math.min(start + PAGE_SIZE_BYTES, blobSize);
    if (start >= blobSize) return null;
    return { start, end };
}

function deriveFunctionKey(licenseKey, hwid, functionHash, nonceHex, issuedAtSec) {
    const master = loadMasterSecret();
    const ikm = Buffer.concat([
        master,
        Buffer.from(String(licenseKey || ''), 'utf8'),
        Buffer.from('|', 'utf8'),
        Buffer.from(String(hwid || ''), 'utf8'),
    ]);
    const salt = Buffer.from(String(nonceHex || ''), 'hex');
    const info = Buffer.concat([
        Buffer.from('aida/function-key/v1|', 'utf8'),
        Buffer.from(String(functionHash || ''), 'utf8'),
        Buffer.from('|', 'utf8'),
        Buffer.from(String(issuedAtSec || 0), 'utf8'),
    ]);
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt.length === 0 ? Buffer.alloc(8, 0) : salt, info, 32));
}

function deriveFunctionToken(licenseKey, hwid, functionHash, nonceHex, issuedAtSec, expiresAtSec) {
    const master = loadMasterSecret();
    return crypto.createHmac('sha256', master)
        .update('aida/function-token/v1')
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(licenseKey || ''), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(hwid || ''), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(functionHash || ''), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(nonceHex || ''), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(issuedAtSec || 0), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(expiresAtSec || 0), 'utf8'))
        .digest();
}

function derivePrologueKey(licenseKey, hwid, functionHash, nonceHex) {
    const master = loadMasterSecret();
    const ikm = Buffer.concat([
        master,
        Buffer.from(String(licenseKey || ''), 'utf8'),
        Buffer.from('|', 'utf8'),
        Buffer.from(String(hwid || ''), 'utf8'),
    ]);
    const salt = Buffer.from(String(nonceHex || ''), 'hex');
    const info = Buffer.concat([
        Buffer.from('aida/prologue-key/v1|', 'utf8'),
        Buffer.from(String(functionHash || ''), 'utf8'),
    ]);
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt.length === 0 ? Buffer.alloc(8, 0) : salt, info, 32));
}

function encryptPrologue(plaintext, licenseKey, hwid, functionHash, nonceHex) {
    const key = derivePrologueKey(licenseKey, hwid, functionHash, nonceHex);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    key.fill(0);
    return { ciphertext, iv, authTag };
}

function constantTimeEqualHex(aHex, bHex) {
    if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
    if (aHex.length !== bHex.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(aHex, 'hex'), Buffer.from(bHex, 'hex'));
    } catch (_) {
        return false;
    }
}

module.exports = {
    PAGE_SIZE_BYTES,
    EPOCH_INTERVAL_SECONDS,
    FUNCTION_TOKEN_TTL_SECONDS,
    PROLOGUE_RAPID_FETCH_THRESHOLD_MS,
    PROLOGUE_RAPID_FETCH_COUNT,
    currentEpoch,
    epochNonce,
    derivePageKey,
    encryptPage,
    splitIntoPages,
    getPageCount,
    pageBoundsForBlob,
    deriveFunctionKey,
    deriveFunctionToken,
    derivePrologueKey,
    encryptPrologue,
    constantTimeEqualHex,
};
