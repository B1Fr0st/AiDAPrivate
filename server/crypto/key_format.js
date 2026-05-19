'use strict';

const crypto = require('crypto');

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CROCKFORD_DECODE = (() => {
    const map = new Map();
    for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
        map.set(CROCKFORD_ALPHABET[i], i);
    }
    map.set('I', map.get('1'));
    map.set('L', map.get('1'));
    map.set('O', map.get('0'));
    map.set('U', map.get('V'));
    return map;
})();

const SEGMENT_CHARS = 8;
const SEGMENT_COUNT = 4;
const RAW_BYTES = 20;

const FORMAT2_RAW_BYTES = 20;
const FORMAT2_BITS_WITH_CRC = 168;
const FORMAT2_CHAR_COUNT = 34;
const FORMAT2_SEGMENT_CHARS = 4;
const FORMAT2_DISPLAY_REGEX = /^([0-9A-HJKMNPQRSTVWXYZ]{4}-){8}[0-9A-HJKMNPQRSTVWXYZ]{2}$/;

const LEGACY_REGEX = /^AIDA-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/;
const MODERN_REGEX = /^AIDA-[0-9A-HJKMNPQRSTVWXYZ]{8}(-[0-9A-HJKMNPQRSTVWXYZ]{8}){3}$/;

const FORMAT_LEGACY = 1;
const FORMAT_MODERN = 2;
const FORMAT_FORMAT2 = 2;

const REQ_SEQ_INITIAL = 1;
const REQ_SEQ_SKIP_THRESHOLD = 1000;
const REQ_TIME_WINDOW_MS = 5000;
const REQ_TIME_WINDOW_LEGACY_MS = 25000;

function crc8Ccitt(buf) {
    let crc = 0;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i];
        for (let b = 0; b < 8; b++) {
            crc = (crc & 0x80) ? (((crc << 1) ^ 0x07) & 0xFF) : ((crc << 1) & 0xFF);
        }
    }
    return crc & 0xFF;
}

function encodeCrockford(bytes) {
    let bits = 0;
    let buffer = 0;
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        buffer = (buffer << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx = (buffer >> bits) & 0x1F;
            out += CROCKFORD_ALPHABET[idx];
        }
    }
    if (bits > 0) {
        const idx = (buffer << (5 - bits)) & 0x1F;
        out += CROCKFORD_ALPHABET[idx];
    }
    return out;
}

function format2Encode(buf20) {
    if (!Buffer.isBuffer(buf20) || buf20.length !== FORMAT2_RAW_BYTES) {
        throw new Error('format2_encode_requires_20_bytes');
    }
    const crc = crc8Ccitt(buf20);
    const composite = Buffer.alloc(FORMAT2_RAW_BYTES + 1);
    buf20.copy(composite, 0);
    composite[FORMAT2_RAW_BYTES] = crc;
    let raw = '';
    let bits = 0;
    let acc = 0;
    for (let i = 0; i < composite.length; i++) {
        acc = (acc << 8) | composite[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx = (acc >> bits) & 0x1F;
            raw += CROCKFORD_ALPHABET[idx];
        }
    }
    while (raw.length < FORMAT2_CHAR_COUNT) {
        raw += CROCKFORD_ALPHABET[0];
    }
    if (raw.length > FORMAT2_CHAR_COUNT) raw = raw.slice(0, FORMAT2_CHAR_COUNT);
    const segments = [];
    for (let i = 0; i < FORMAT2_CHAR_COUNT; i += FORMAT2_SEGMENT_CHARS) {
        segments.push(raw.slice(i, i + FORMAT2_SEGMENT_CHARS));
    }
    return segments.join('-');
}

function stripDisplayChars(value) {
    if (typeof value !== 'string') return '';
    return value.toUpperCase().replace(/[\s-]/g, '');
}

function format2Decode(value) {
    const stripped = stripDisplayChars(value);
    if (stripped.length !== FORMAT2_CHAR_COUNT) {
        return { ok: false, reason: 'format2_length' };
    }
    let bits = 0;
    let acc = 0;
    const composite = Buffer.alloc(FORMAT2_RAW_BYTES + 1);
    let outPos = 0;
    for (let i = 0; i < stripped.length; i++) {
        const ch = stripped[i];
        const v = CROCKFORD_DECODE.get(ch);
        if (v === undefined) {
            return { ok: false, reason: 'format2_alphabet' };
        }
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (outPos < composite.length) {
                composite[outPos++] = (acc >> bits) & 0xFF;
            }
        }
    }
    if (outPos !== composite.length) {
        return { ok: false, reason: 'format2_truncated' };
    }
    const payload = composite.subarray(0, FORMAT2_RAW_BYTES);
    const expectedCrc = composite[FORMAT2_RAW_BYTES];
    const actualCrc = crc8Ccitt(payload);
    if (expectedCrc !== actualCrc) {
        return { ok: false, reason: 'format2_crc' };
    }
    return { ok: true, payload, crc: actualCrc };
}

function format2IsCandidate(value) {
    if (typeof value !== 'string') return false;
    const stripped = stripDisplayChars(value);
    if (stripped.length !== FORMAT2_CHAR_COUNT) return false;
    for (let i = 0; i < stripped.length; i++) {
        if (!CROCKFORD_DECODE.has(stripped[i])) return false;
    }
    return true;
}

function format2CanonicalDisplay(buf20) {
    return format2Encode(buf20);
}

function generateFormat2Key() {
    const raw = crypto.randomBytes(FORMAT2_RAW_BYTES);
    return format2Encode(raw);
}

function generateModernKey() {
    const raw = crypto.randomBytes(RAW_BYTES);
    const encoded = encodeCrockford(raw).slice(0, SEGMENT_CHARS * SEGMENT_COUNT);
    const segments = [];
    for (let i = 0; i < SEGMENT_COUNT; i++) {
        segments.push(encoded.slice(i * SEGMENT_CHARS, (i + 1) * SEGMENT_CHARS));
    }
    return 'AIDA-' + segments.join('-');
}

function generateLegacyKey() {
    const segments = [];
    for (let i = 0; i < 4; i++) {
        segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    return 'AIDA-' + segments.join('-');
}

function isModernKey(value) {
    return typeof value === 'string' && MODERN_REGEX.test(value);
}

function isLegacyKey(value) {
    return typeof value === 'string' && LEGACY_REGEX.test(value.toUpperCase());
}

function isFormat2Key(value) {
    if (typeof value !== 'string') return false;
    if (!format2IsCandidate(value)) return false;
    const verdict = format2Decode(value);
    return verdict.ok === true;
}

function isAcceptedKey(value) {
    return isModernKey(value) || isLegacyKey(value) || isFormat2Key(value);
}

function detectKeyFormat(value) {
    if (isFormat2Key(value)) return FORMAT_FORMAT2;
    if (isModernKey(value)) return FORMAT_MODERN;
    if (isLegacyKey(value)) return FORMAT_LEGACY;
    return 0;
}

function canonicalizeFormat2(value) {
    const verdict = format2Decode(value);
    if (!verdict.ok) return '';
    return format2Encode(verdict.payload);
}

function normalizeForLookup(value) {
    if (typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (format2IsCandidate(trimmed)) {
        const canon = canonicalizeFormat2(trimmed);
        if (canon) return canon;
    }
    if (isModernKey(trimmed)) return trimmed;
    if (isLegacyKey(trimmed)) return trimmed.toUpperCase();
    return '';
}

module.exports = {
    generateModernKey,
    generateLegacyKey,
    generateFormat2Key,
    isModernKey,
    isLegacyKey,
    isFormat2Key,
    isAcceptedKey,
    detectKeyFormat,
    normalizeForLookup,
    canonicalizeFormat2,
    format2Encode,
    format2Decode,
    format2IsCandidate,
    format2CanonicalDisplay,
    crc8Ccitt,
    FORMAT_LEGACY,
    FORMAT_MODERN,
    FORMAT_FORMAT2,
    LEGACY_REGEX,
    MODERN_REGEX,
    FORMAT2_DISPLAY_REGEX,
    FORMAT2_CHAR_COUNT,
    FORMAT2_RAW_BYTES,
    FORMAT2_SEGMENT_CHARS,
    CROCKFORD_ALPHABET,
    REQ_SEQ_INITIAL,
    REQ_SEQ_SKIP_THRESHOLD,
    REQ_TIME_WINDOW_MS,
    REQ_TIME_WINDOW_LEGACY_MS,
};
