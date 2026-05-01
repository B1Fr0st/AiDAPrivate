'use strict';

const crypto = require('crypto');

const REQUEST_MAGIC = 0x41494442;
const RESPONSE_MAGIC = 0x42494441;
const PROTOCOL_VERSION = 0x0001;

const OP_PAGE_FETCH = 1;
const OP_PAGE_COUNT = 2;
const OP_HEARTBEAT = 3;

const STATUS_OK = 0;
const STATUS_AUTH_FAIL = 1;
const STATUS_SERVER_ERROR = 2;
const STATUS_BAD_REQUEST = 3;
const STATUS_NOT_FOUND = 4;
const STATUS_RATE_LIMITED = 5;
const STATUS_PIN_FAIL = 6;

const REQUEST_HEADER_SIZE = 24;
const RESPONSE_HEADER_SIZE = 24;
const TAG_SIZE = 16;
const NONCE_SIZE = 12;

const CRC32C_POLY = 0x82F63B78;
const CRC32C_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? ((c >>> 1) ^ CRC32C_POLY) : (c >>> 1);
        }
        t[i] = c >>> 0;
    }
    return t;
})();

function crc32c(buf) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) {
        crc = ((crc >>> 8) ^ CRC32C_TABLE[(crc ^ buf[i]) & 0xFF]) >>> 0;
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function deriveProtocolKey(sessionToken, hwid) {
    const ikm = Buffer.concat([
        Buffer.from(String(sessionToken || ''), 'utf8'),
        Buffer.from(String(hwid || ''), 'utf8'),
    ]);
    const salt = Buffer.from('AIDB-SALT-v1-202', 'utf8');
    const info = Buffer.from('binary-proto-v1', 'utf8');
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    const out = Buffer.alloc(32);
    let prev = Buffer.alloc(0);
    let counter = 1;
    let produced = 0;
    while (produced < 32) {
        const h = crypto.createHmac('sha256', prk);
        if (counter > 1) h.update(prev);
        h.update(info);
        h.update(Buffer.from([counter]));
        prev = h.digest();
        const copy = Math.min(32, 32 - produced);
        prev.copy(out, produced, 0, copy);
        produced += copy;
        counter += 1;
    }
    return out;
}

function nonceToChachaIv(sessionNonce) {
    const iv = Buffer.alloc(NONCE_SIZE, 0);
    if (Buffer.isBuffer(sessionNonce) && sessionNonce.length >= 8) {
        sessionNonce.copy(iv, 0, 0, 8);
    } else if (typeof sessionNonce === 'bigint') {
        iv.writeBigUInt64LE(sessionNonce, 0);
    } else {
        const num = BigInt(sessionNonce);
        iv.writeBigUInt64LE(num, 0);
    }
    iv[8] = 0xA1;
    iv[9] = 0xDA;
    iv[10] = 0xC0;
    iv[11] = 0xDE;
    return iv;
}

function parseRequestHeader(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < REQUEST_HEADER_SIZE) {
        return { ok: false, reason: 'header_too_short' };
    }
    const magic = buf.readUInt32LE(0);
    const version = buf.readUInt16LE(4);
    const op = buf.readUInt16LE(6);
    const sessionNonce = buf.subarray(8, 16);
    const payloadLen = buf.readUInt32LE(16);
    const crcReceived = buf.readUInt32LE(20);

    if (magic !== REQUEST_MAGIC) return { ok: false, reason: 'bad_magic' };
    if (version !== PROTOCOL_VERSION) return { ok: false, reason: 'bad_version' };
    return {
        ok: true,
        magic,
        version,
        op,
        sessionNonce,
        payloadLen,
        crcReceived,
    };
}

function verifyRequestCrc(headerBuf, payloadBuf) {
    if (headerBuf.length < REQUEST_HEADER_SIZE) return false;
    const expected = headerBuf.readUInt32LE(20);
    const headerNoCrc = headerBuf.subarray(0, REQUEST_HEADER_SIZE - 4);
    const computed = crc32c(Buffer.concat([headerNoCrc, payloadBuf]));
    return expected === computed;
}

function parsePackedRequestBody(plaintext, op) {
    let off = 0;
    function readU32() {
        if (off + 4 > plaintext.length) throw new Error('truncated_u32');
        const v = plaintext.readUInt32LE(off);
        off += 4;
        return v;
    }
    function readU64() {
        if (off + 8 > plaintext.length) throw new Error('truncated_u64');
        const v = plaintext.readBigUInt64LE(off);
        off += 8;
        return v;
    }
    function readStr() {
        const len = readU32();
        if (len > 0x10000) throw new Error('field_too_long');
        if (off + len > plaintext.length) throw new Error('truncated_str');
        const s = plaintext.subarray(off, off + len).toString('utf8');
        off += len;
        return s;
    }

    const result = {
        license_key: readStr(),
        session_token: readStr(),
        hwid: readStr(),
        proof_token: readStr(),
    };
    if (op === OP_PAGE_FETCH) {
        result.page_index = readU32();
        result.issued_at = readU64();
    }
    return result;
}

function buildResponseHeader(sessionNonce, status, payloadLen, payloadBuf) {
    const hdr = Buffer.alloc(RESPONSE_HEADER_SIZE);
    hdr.writeUInt32LE(RESPONSE_MAGIC, 0);
    hdr.writeUInt16LE(PROTOCOL_VERSION, 4);
    hdr.writeUInt16LE(status, 6);
    if (Buffer.isBuffer(sessionNonce) && sessionNonce.length >= 8) {
        sessionNonce.copy(hdr, 8, 0, 8);
    } else {
        Buffer.alloc(8, 0).copy(hdr, 8);
    }
    hdr.writeUInt32LE(payloadLen >>> 0, 16);
    hdr.writeUInt32LE(0, 20);
    const crc = crc32c(Buffer.concat([hdr.subarray(0, RESPONSE_HEADER_SIZE - 4), payloadBuf]));
    hdr.writeUInt32LE(crc, 20);
    return hdr;
}

function decryptRequestBody(headerBuf, encryptedAndTag, sessionToken, hwid) {
    if (!Buffer.isBuffer(encryptedAndTag) || encryptedAndTag.length < TAG_SIZE) {
        throw new Error('encrypted_body_too_short');
    }
    const ct = encryptedAndTag.subarray(0, encryptedAndTag.length - TAG_SIZE);
    const tag = encryptedAndTag.subarray(encryptedAndTag.length - TAG_SIZE);

    const key = deriveProtocolKey(sessionToken, hwid);
    const sessionNonce = headerBuf.subarray(8, 16);
    const iv = nonceToChachaIv(sessionNonce);

    const aad = Buffer.alloc(REQUEST_HEADER_SIZE - 8);
    headerBuf.copy(aad, 0, 0, REQUEST_HEADER_SIZE - 8);

    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: TAG_SIZE });
    decipher.setAAD(aad, { plaintextLength: ct.length });
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    key.fill(0);
    return plain;
}

function encryptResponseBody(plainBuf, sessionNonce, status, sessionToken, hwid) {
    const key = deriveProtocolKey(sessionToken, hwid);
    const iv = nonceToChachaIv(sessionNonce);

    const aadHdr = Buffer.alloc(RESPONSE_HEADER_SIZE - 8);
    aadHdr.writeUInt32LE(RESPONSE_MAGIC, 0);
    aadHdr.writeUInt16LE(PROTOCOL_VERSION, 4);
    aadHdr.writeUInt16LE(status, 6);
    if (Buffer.isBuffer(sessionNonce) && sessionNonce.length >= 8) {
        sessionNonce.copy(aadHdr, 8, 0, 8);
    }

    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: TAG_SIZE });
    cipher.setAAD(aadHdr, { plaintextLength: plainBuf.length });
    const ct = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    key.fill(0);
    return Buffer.concat([ct, tag]);
}

function buildResponse(sessionNonce, status, plainPayload, sessionToken, hwid) {
    if (status !== STATUS_OK) {
        const emptyPayload = Buffer.alloc(0);
        return Buffer.concat([
            buildResponseHeader(sessionNonce, status, 0, emptyPayload),
            emptyPayload,
        ]);
    }
    const enc = encryptResponseBody(plainPayload, sessionNonce, status, sessionToken, hwid);
    return Buffer.concat([
        buildResponseHeader(sessionNonce, status, enc.length, enc),
        enc,
    ]);
}

function packU32LE(value) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(value >>> 0, 0);
    return b;
}

function packU64LE(value) {
    const b = Buffer.alloc(8);
    if (typeof value === 'bigint') {
        b.writeBigUInt64LE(value, 0);
    } else {
        b.writeBigUInt64LE(BigInt(value), 0);
    }
    return b;
}

module.exports = {
    REQUEST_MAGIC,
    RESPONSE_MAGIC,
    PROTOCOL_VERSION,
    OP_PAGE_FETCH,
    OP_PAGE_COUNT,
    OP_HEARTBEAT,
    STATUS_OK,
    STATUS_AUTH_FAIL,
    STATUS_SERVER_ERROR,
    STATUS_BAD_REQUEST,
    STATUS_NOT_FOUND,
    STATUS_RATE_LIMITED,
    STATUS_PIN_FAIL,
    REQUEST_HEADER_SIZE,
    RESPONSE_HEADER_SIZE,
    TAG_SIZE,
    NONCE_SIZE,
    crc32c,
    deriveProtocolKey,
    nonceToChachaIv,
    parseRequestHeader,
    verifyRequestCrc,
    parsePackedRequestBody,
    decryptRequestBody,
    encryptResponseBody,
    buildResponseHeader,
    buildResponse,
    packU32LE,
    packU64LE,
};
