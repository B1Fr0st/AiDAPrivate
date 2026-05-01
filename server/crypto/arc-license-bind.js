'use strict';

const crypto = require('crypto');
const kwWrap = require('./kw_wrap');

const LICBIND_SECTION_NAME = '.licbind';
const LICBIND_SECTION_SIZE = 32;
const BIND_SECRET_INFO = Buffer.from('arc-bind-secret', 'utf8');
const PROOF_CODE_HASH_SENTINEL = '0000000000000000';

const FEAT_SECTION_NAME = '.feat';
const FEAT_SECTION_SIZE = 4096;
const FEAT_MAGIC = 0x46454154;
const FEAT_VERSION = 1;
const FEAT_HEADER_SIZE = 16;
const FEAT_ENTRY_SIZE = 44;
const FEAT_FEATURE_POLYMORPHISM_SEED = 1;
const FEAT_POLYMORPHISM_SEED_INFO = Buffer.from('polymorphism-seed', 'utf8');
const FEAT_NONCE_SIZE = 32;

const ED25519_SPKI_PREFIX = Buffer.from([
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
    0x70, 0x03, 0x21, 0x00,
]);
const ED25519_PUBLIC_KEY_SIZE = 32;
const WITNESS_KEY_UNWRAP_LABEL = 'witness_key/v1';

function bootNonceBuffer(licenseRow) {
    const buf = Buffer.alloc(8, 0);
    if (!licenseRow) return buf;
    const raw = licenseRow.boot_nonce_last;
    if (raw === null || raw === undefined || raw === '') return buf;
    if (Buffer.isBuffer(raw)) {
        const len = Math.min(raw.length, 8);
        raw.copy(buf, 8 - len, 0, len);
        return buf;
    }
    if (raw instanceof Uint8Array) {
        const src = Buffer.from(raw);
        const len = Math.min(src.length, 8);
        src.copy(buf, 8 - len, 0, len);
        return buf;
    }
    if (typeof raw === 'bigint') {
        try {
            buf.writeBigUInt64BE(raw & 0xFFFFFFFFFFFFFFFFn, 0);
        } catch (_) { return buf; }
        return buf;
    }
    if (typeof raw === 'number' && Number.isFinite(raw)) {
        try {
            buf.writeBigUInt64BE(BigInt(Math.max(0, Math.floor(raw))) & 0xFFFFFFFFFFFFFFFFn, 0);
        } catch (_) { return buf; }
        return buf;
    }
    if (typeof raw === 'string') {
        const trimmed = raw.trim();
        if (trimmed.length === 0) return buf;
        if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
            try {
                const v = BigInt(trimmed) & 0xFFFFFFFFFFFFFFFFn;
                buf.writeBigUInt64BE(v, 0);
            } catch (_) { }
            return buf;
        }
        if (/^[0-9]+$/.test(trimmed)) {
            try {
                const v = BigInt(trimmed) & 0xFFFFFFFFFFFFFFFFn;
                buf.writeBigUInt64BE(v, 0);
            } catch (_) { }
            return buf;
        }
        if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length <= 16) {
            const padded = trimmed.padStart(16, '0');
            const hexBuf = Buffer.from(padded, 'hex');
            hexBuf.copy(buf, 0, 0, 8);
            return buf;
        }
        const digest = crypto.createHash('sha256').update(trimmed, 'utf8').digest();
        digest.copy(buf, 0, 0, 8);
        return buf;
    }
    return buf;
}

function deriveBindSecret(licenseRow) {
    if (!licenseRow) {
        throw new Error('arc_license_missing_install_secret');
    }
    const wrapped = licenseRow.install_secret_wrapped;
    if (wrapped === null || wrapped === undefined) {
        throw new Error('arc_license_missing_install_secret');
    }
    const wrappedBuf = Buffer.isBuffer(wrapped) ? wrapped : Buffer.from(wrapped);
    if (wrappedBuf.length === 0) {
        throw new Error('arc_license_missing_install_secret');
    }
    let installSecret;
    try {
        installSecret = kwWrap.unwrap(wrappedBuf, 'install_secret/v1');
    } catch (err) {
        const wrapped2 = new Error('arc_license_install_secret_unwrap_failed');
        wrapped2.cause = err;
        throw wrapped2;
    }
    const salt = bootNonceBuffer(licenseRow);
    const derived = crypto.hkdfSync('sha256', installSecret, salt, BIND_SECRET_INFO, 32);
    return Buffer.from(derived);
}

function readUInt32LE(buf, offset) {
    return buf.readUInt32LE(offset);
}

function readUInt16LE(buf, offset) {
    return buf.readUInt16LE(offset);
}

function locateSection(blob, targetName, minSize) {
    if (!Buffer.isBuffer(blob) || blob.length < 0x40) {
        throw new Error('arc_blob_invalid_pe');
    }
    if (blob[0] !== 0x4D || blob[1] !== 0x5A) {
        throw new Error('arc_blob_missing_mz_header');
    }
    const eLfanew = readUInt32LE(blob, 0x3C);
    if (eLfanew <= 0 || eLfanew + 24 > blob.length) {
        throw new Error('arc_blob_invalid_e_lfanew');
    }
    if (blob[eLfanew] !== 0x50 || blob[eLfanew + 1] !== 0x45 || blob[eLfanew + 2] !== 0x00 || blob[eLfanew + 3] !== 0x00) {
        throw new Error('arc_blob_missing_pe_signature');
    }
    const numberOfSections = readUInt16LE(blob, eLfanew + 6);
    const sizeOfOptionalHeader = readUInt16LE(blob, eLfanew + 20);
    const sectionTableOffset = eLfanew + 24 + sizeOfOptionalHeader;
    const SECTION_HEADER_SIZE = 40;
    if (sectionTableOffset + numberOfSections * SECTION_HEADER_SIZE > blob.length) {
        throw new Error('arc_blob_section_table_truncated');
    }
    for (let i = 0; i < numberOfSections; i++) {
        const headerOffset = sectionTableOffset + i * SECTION_HEADER_SIZE;
        const nameBytes = blob.subarray(headerOffset, headerOffset + 8);
        let nameLen = 0;
        while (nameLen < 8 && nameBytes[nameLen] !== 0) nameLen++;
        const sectionName = nameBytes.toString('ascii', 0, nameLen);
        if (sectionName === targetName) {
            const sizeOfRawData = readUInt32LE(blob, headerOffset + 16);
            const pointerToRawData = readUInt32LE(blob, headerOffset + 20);
            if (sizeOfRawData < minSize) {
                return { found: true, error: `arc_blob_${targetName.replace(/^\./, '')}_section_too_small` };
            }
            if (pointerToRawData === 0 || pointerToRawData + minSize > blob.length) {
                return { found: true, error: `arc_blob_${targetName.replace(/^\./, '')}_section_out_of_bounds` };
            }
            return { found: true, pointerToRawData, sizeOfRawData };
        }
    }
    return { found: false };
}

function locateLicbindSection(blob) {
    const result = locateSection(blob, LICBIND_SECTION_NAME, LICBIND_SECTION_SIZE);
    if (!result.found) {
        throw new Error('arc_blob_missing_licbind_section');
    }
    if (result.error) {
        throw new Error(result.error);
    }
    return { pointerToRawData: result.pointerToRawData, sizeOfRawData: result.sizeOfRawData };
}

function sessionTokenToNonce(sessionRow) {
    const nonce = Buffer.alloc(FEAT_NONCE_SIZE, 0);
    if (!sessionRow) return nonce;
    const token = sessionRow.session_token;
    if (typeof token !== 'string' || token.length === 0) return nonce;
    const tokenBuf = Buffer.from(token, 'utf8');
    const copyLen = Math.min(tokenBuf.length, FEAT_NONCE_SIZE);
    tokenBuf.copy(nonce, 0, 0, copyLen);
    return nonce;
}

function derivePolymorphismSeedPlaintext(bindSecret, licenseRow) {
    const licenseKey = licenseRow && typeof licenseRow.key === 'string' ? licenseRow.key : '';
    const salt = Buffer.from(licenseKey, 'utf8');
    const derived = crypto.hkdfSync('sha256', bindSecret, salt, FEAT_POLYMORPHISM_SEED_INFO, 32);
    return Buffer.from(derived);
}

function deriveFeatureKey(bindSecret, nonce, featureId) {
    const info = Buffer.from(`feature:${featureId >>> 0}`, 'utf8');
    const derived = crypto.hkdfSync('sha256', bindSecret, nonce, info, 32);
    return Buffer.from(derived);
}

function assembleFeatureBlob(licenseRow, sessionRow) {
    const bindSecret = deriveBindSecret(licenseRow);
    const nonce = sessionTokenToNonce(sessionRow);

    const polymorphismPlaintext = derivePolymorphismSeedPlaintext(bindSecret, licenseRow);
    const polymorphismKey = deriveFeatureKey(bindSecret, nonce, FEAT_FEATURE_POLYMORPHISM_SEED);
    const polymorphismIv = crypto.randomBytes(12);
    const polymorphismCipher = crypto.createCipheriv('aes-256-gcm', polymorphismKey, polymorphismIv);
    const polymorphismCiphertext = Buffer.concat([
        polymorphismCipher.update(polymorphismPlaintext),
        polymorphismCipher.final(),
    ]);
    const polymorphismTag = polymorphismCipher.getAuthTag();

    const entries = [
        {
            featureId: FEAT_FEATURE_POLYMORPHISM_SEED,
            ciphertext: polymorphismCiphertext,
            iv: polymorphismIv,
            tag: polymorphismTag,
        },
    ];

    const entryCount = entries.length;
    const entryTableSize = entryCount * FEAT_ENTRY_SIZE;
    let ciphertextRunningOffset = FEAT_HEADER_SIZE + entryTableSize;
    const entryRecords = entries.map((entry) => {
        const record = {
            featureId: entry.featureId,
            ciphertextOffset: ciphertextRunningOffset,
            ciphertextLen: entry.ciphertext.length,
            iv: entry.iv,
            tag: entry.tag,
            ciphertext: entry.ciphertext,
        };
        ciphertextRunningOffset += entry.ciphertext.length;
        return record;
    });
    const totalSize = ciphertextRunningOffset;
    if (totalSize > FEAT_SECTION_SIZE) {
        throw new Error('arc_feat_blob_overflow');
    }

    const blob = Buffer.alloc(FEAT_SECTION_SIZE, 0);
    blob.writeUInt32LE(FEAT_MAGIC >>> 0, 0x000);
    blob.writeUInt32LE(FEAT_VERSION >>> 0, 0x004);
    blob.writeUInt32LE(entryCount >>> 0, 0x008);
    blob.writeUInt32LE(totalSize >>> 0, 0x00C);

    for (let i = 0; i < entryRecords.length; i++) {
        const record = entryRecords[i];
        const entryOffset = FEAT_HEADER_SIZE + i * FEAT_ENTRY_SIZE;
        blob.writeUInt32LE(record.featureId >>> 0, entryOffset + 0);
        blob.writeUInt32LE(record.ciphertextOffset >>> 0, entryOffset + 4);
        blob.writeUInt32LE(record.ciphertextLen >>> 0, entryOffset + 8);
        blob.writeUInt32LE(FEAT_ENTRY_SIZE >>> 0, entryOffset + 12);
        record.iv.copy(blob, entryOffset + 16, 0, 12);
        record.tag.copy(blob, entryOffset + 28, 0, 16);
        record.ciphertext.copy(blob, record.ciphertextOffset, 0, record.ciphertextLen);
    }

    return blob;
}

function applyLicenseTransform(blob, licenseRow, sessionRow) {
    if (!Buffer.isBuffer(blob)) {
        throw new Error('arc_blob_not_buffer');
    }
    const licbindSection = locateLicbindSection(blob);
    const bindSecret = deriveBindSecret(licenseRow);
    const out = Buffer.from(blob);
    bindSecret.copy(out, licbindSection.pointerToRawData, 0, LICBIND_SECTION_SIZE);

    const featResult = locateSection(out, FEAT_SECTION_NAME, FEAT_SECTION_SIZE);
    if (!featResult.found) {
        throw new Error('arc_feat_section_missing');
    }
    if (featResult.error) {
        throw new Error(`arc_feat_section_invalid:${featResult.error}`);
    }
    const featBlob = assembleFeatureBlob(licenseRow, sessionRow);
    featBlob.copy(out, featResult.pointerToRawData, 0, FEAT_SECTION_SIZE);
    return out;
}

function deriveBindProof(licenseRow, sessionToken, hwid, timestamp, codeHashUint64) {
    const bindSecret = deriveBindSecret(licenseRow);
    const sessionStr = String(sessionToken || '');
    const hwidStr = String(hwid || '');
    const tsStr = String(timestamp);
    void codeHashUint64;
    const message = `${sessionStr}|${hwidStr}|${tsStr}|${PROOF_CODE_HASH_SENTINEL}`;
    return crypto.createHmac('sha256', bindSecret).update(message, 'utf8').digest();
}

function deriveRotatingBindProof(licenseRow, sessionToken, hwid, epoch, heartbeatNonce, tpmDigestHex) {
    const bindSecret = deriveBindSecret(licenseRow);
    const sessionStr = String(sessionToken || '');
    const hwidStr = String(hwid || '');
    const epochStr = String(BigInt(epoch || 0));
    const nonceStr = String(heartbeatNonce || '');
    const tpmStr = typeof tpmDigestHex === 'string' && tpmDigestHex.length > 0
        ? tpmDigestHex.toLowerCase()
        : '0'.repeat(64);
    const message = `bind_proof_v2|${sessionStr}|${hwidStr}|${epochStr}|${nonceStr}|${tpmStr}`;
    return crypto.createHmac('sha256', bindSecret).update(message, 'utf8').digest();
}

function deriveCodePageSigningKey(licenseRow, sessionRow, hwid) {
    const sessionToken = sessionRow && typeof sessionRow.session_token === 'string'
        ? sessionRow.session_token : '';
    const issuedAt = sessionRow && Number.isFinite(Number(sessionRow.issued_at))
        ? Number(sessionRow.issued_at) : 0;
    const bindProof = deriveBindProof(licenseRow, sessionToken, hwid, issuedAt, 0n);
    const salt = Buffer.from(String(hwid || ''), 'utf8');
    const info = Buffer.from('code-page-binding/v1', 'utf8');
    const derived = crypto.hkdfSync('sha256', bindProof, salt, info, 32);
    return Buffer.from(derived);
}

function signCodePage(licenseRow, sessionRow, hwid, pageIndex, pageBytes) {
    if (!Buffer.isBuffer(pageBytes)) {
        throw new Error('arc_code_page_not_buffer');
    }
    const key = deriveCodePageSigningKey(licenseRow, sessionRow, hwid);
    const indexBuf = Buffer.alloc(4);
    indexBuf.writeUInt32LE(pageIndex >>> 0, 0);
    const digest = crypto.createHash('sha256').update(pageBytes).digest();
    const mac = crypto.createHmac('sha256', key)
        .update('aida-code-page', 'utf8')
        .update(indexBuf)
        .update(digest)
        .digest();
    return { digest, signature: mac };
}

function verifyCodePage(licenseRow, sessionRow, hwid, pageIndex, pageBytes, signatureHex) {
    if (typeof signatureHex !== 'string' || !/^[0-9a-fA-F]+$/.test(signatureHex)) return false;
    const expected = signCodePage(licenseRow, sessionRow, hwid, pageIndex, pageBytes).signature;
    let provided;
    try { provided = Buffer.from(signatureHex, 'hex'); } catch (_) { return false; }
    if (provided.length !== expected.length) return false;
    try { return crypto.timingSafeEqual(provided, expected); } catch (_) { return false; }
}

function deriveLicenseeId(licenseRow) {
    if (!licenseRow) return '';
    if (typeof licenseRow.licensee_id === 'string' && licenseRow.licensee_id.length > 0) {
        return licenseRow.licensee_id;
    }
    const key = typeof licenseRow.key === 'string' ? licenseRow.key : '';
    if (!key) return '';
    return crypto.createHash('sha256').update(`licensee/v1|${key}`, 'utf8').digest('hex');
}

function verifyArcProofToken(licenseRow, expectedData, clientProofFirst8) {
    if (!Buffer.isBuffer(clientProofFirst8) || clientProofFirst8.length !== 8) {
        return false;
    }
    let bindSecret;
    try {
        bindSecret = deriveBindSecret(licenseRow);
    } catch (_) {
        return false;
    }
    const dataBuf = Buffer.isBuffer(expectedData) ? expectedData : Buffer.from(String(expectedData), 'utf8');
    const fullMac = crypto.createHmac('sha256', bindSecret).update(dataBuf).digest();
    const expectedFirst8 = fullMac.subarray(0, 8);
    try {
        return crypto.timingSafeEqual(expectedFirst8, clientProofFirst8);
    } catch (_) {
        return false;
    }
}

function buildEd25519SpkiDer(rawPublicKey) {
    if (!Buffer.isBuffer(rawPublicKey) || rawPublicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
        return null;
    }
    return Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]);
}

function verifyDriverProof(licenseRow, message, signatureHex) {
    if (!licenseRow) return null;
    const wrapped = licenseRow.witness_key_wrapped;
    if (wrapped === null || wrapped === undefined) return null;
    const wrappedBuf = Buffer.isBuffer(wrapped) ? wrapped : Buffer.from(wrapped);
    if (wrappedBuf.length === 0) return null;

    let publicKeyRaw;
    try {
        publicKeyRaw = kwWrap.unwrap(wrappedBuf, WITNESS_KEY_UNWRAP_LABEL);
    } catch (_) {
        return null;
    }
    if (!Buffer.isBuffer(publicKeyRaw) || publicKeyRaw.length !== ED25519_PUBLIC_KEY_SIZE) {
        return null;
    }

    const spkiDer = buildEd25519SpkiDer(publicKeyRaw);
    if (!spkiDer) return null;

    let keyObject;
    try {
        keyObject = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    } catch (_) {
        return false;
    }

    let signatureBuf;
    if (typeof signatureHex !== 'string' || !/^[0-9a-fA-F]+$/.test(signatureHex)) {
        return false;
    }
    try {
        signatureBuf = Buffer.from(signatureHex, 'hex');
    } catch (_) {
        return false;
    }
    if (signatureBuf.length !== 64) {
        return false;
    }

    const messageBuf = Buffer.isBuffer(message) ? message : Buffer.from(String(message == null ? '' : message), 'utf8');

    try {
        return crypto.verify(null, messageBuf, keyObject, signatureBuf);
    } catch (_) {
        return false;
    }
}

module.exports = {
    applyLicenseTransform,
    assembleFeatureBlob,
    deriveBindProof,
    deriveRotatingBindProof,
    deriveCodePageSigningKey,
    deriveLicenseeId,
    signCodePage,
    verifyCodePage,
    verifyArcProofToken,
    verifyDriverProof,
    LICBIND_SECTION_NAME,
    LICBIND_SECTION_SIZE,
    FEAT_SECTION_NAME,
    FEAT_SECTION_SIZE,
    FEAT_FEATURE_POLYMORPHISM_SEED,
    PROOF_CODE_HASH_SENTINEL,
};
