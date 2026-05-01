'use strict';

const crypto = require('crypto');
const ekRoots = require('./ek_roots');

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_QUOTE = 0x8018;

const TPM_ALG_RSA = 0x0001;
const TPM_ALG_SHA1 = 0x0004;
const TPM_ALG_SHA256 = 0x000B;
const TPM_ALG_SHA384 = 0x000C;
const TPM_ALG_SHA512 = 0x000D;
const TPM_ALG_NULL = 0x0010;
const TPM_ALG_RSASSA = 0x0014;
const TPM_ALG_RSAPSS = 0x0016;
const TPM_ALG_ECDSA = 0x0018;
const TPM_ALG_ECC = 0x0023;

const TPM_ALG_TO_HASH = {
    [TPM_ALG_SHA1]: 'sha1',
    [TPM_ALG_SHA256]: 'sha256',
    [TPM_ALG_SHA384]: 'sha384',
    [TPM_ALG_SHA512]: 'sha512',
};

const HASH_OUTPUT_LEN = {
    [TPM_ALG_SHA1]: 20,
    [TPM_ALG_SHA256]: 32,
    [TPM_ALG_SHA384]: 48,
    [TPM_ALG_SHA512]: 64,
};

const REQUIRED_PCR_BANK = TPM_ALG_SHA256;
const REQUIRED_PCR_INDICES = [0, 1, 2, 3, 4, 5, 6, 7];
const QUOTE_FRESHNESS_SECONDS = 600;

class BufferReader {
    constructor(buf) {
        this.buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
        this.offset = 0;
    }
    remaining() { return this.buf.length - this.offset; }
    require(n) {
        if (this.remaining() < n) throw new Error(`tpm_quote_buffer_underflow:need=${n}:have=${this.remaining()}`);
    }
    u8() { this.require(1); const v = this.buf.readUInt8(this.offset); this.offset += 1; return v; }
    u16() { this.require(2); const v = this.buf.readUInt16BE(this.offset); this.offset += 2; return v; }
    u32() { this.require(4); const v = this.buf.readUInt32BE(this.offset); this.offset += 4; return v; }
    u64() { this.require(8); const hi = this.buf.readUInt32BE(this.offset); const lo = this.buf.readUInt32BE(this.offset + 4); this.offset += 8; return (BigInt(hi) << 32n) | BigInt(lo); }
    bytes(n) { this.require(n); const v = this.buf.subarray(this.offset, this.offset + n); this.offset += n; return v; }
    sized16() {
        const len = this.u16();
        return this.bytes(len);
    }
}

function decodeQuoteBuffer(input) {
    if (Buffer.isBuffer(input)) return input;
    if (typeof input !== 'string') throw new Error('tpm_quote_invalid_input');
    const trimmed = input.trim();
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
        return Buffer.from(trimmed, 'hex');
    }
    return Buffer.from(trimmed, 'base64');
}

function parseAttestStructure(buf) {
    const r = new BufferReader(buf);
    const magic = r.u32();
    if (magic !== TPM_GENERATED_VALUE) {
        throw new Error(`tpm_attest_bad_magic:0x${magic.toString(16)}`);
    }
    const type = r.u16();
    if (type !== TPM_ST_ATTEST_QUOTE) {
        throw new Error(`tpm_attest_not_quote:0x${type.toString(16)}`);
    }
    const qualifiedSigner = r.sized16();
    const extraData = r.sized16();
    const clockInfo = {
        clock: r.u64(),
        resetCount: r.u32(),
        restartCount: r.u32(),
        safe: r.u8(),
    };
    const firmwareVersion = r.u64();
    const pcrSelectCount = r.u32();
    const pcrSelections = [];
    for (let i = 0; i < pcrSelectCount; i++) {
        const hashAlg = r.u16();
        const sizeOfSelect = r.u8();
        const selectBitmap = r.bytes(sizeOfSelect);
        const indices = [];
        for (let byte = 0; byte < sizeOfSelect; byte++) {
            for (let bit = 0; bit < 8; bit++) {
                if ((selectBitmap[byte] & (1 << bit)) !== 0) {
                    indices.push(byte * 8 + bit);
                }
            }
        }
        pcrSelections.push({ hashAlg, indices, selectBitmap });
    }
    const pcrDigest = r.sized16();
    return {
        magic,
        type,
        qualifiedSigner,
        extraData,
        clockInfo,
        firmwareVersion,
        pcrSelections,
        pcrDigest,
        consumed: r.offset,
    };
}

function parseSignature(buf) {
    const r = new BufferReader(buf);
    const sigAlg = r.u16();
    if (sigAlg === TPM_ALG_RSASSA || sigAlg === TPM_ALG_RSAPSS) {
        const hashAlg = r.u16();
        const sigBytes = r.sized16();
        return { sigAlg, hashAlg, sigBytes };
    }
    if (sigAlg === TPM_ALG_ECDSA) {
        const hashAlg = r.u16();
        const rBytes = r.sized16();
        const sBytes = r.sized16();
        return { sigAlg, hashAlg, rBytes, sBytes };
    }
    throw new Error(`tpm_signature_unsupported_alg:0x${sigAlg.toString(16)}`);
}

function encodeEcdsaDer(r, s) {
    const trim = (b) => {
        let i = 0;
        while (i < b.length - 1 && b[i] === 0) i++;
        let buf = b.subarray(i);
        if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
        return buf;
    };
    const rBuf = trim(r);
    const sBuf = trim(s);
    const seq = (tag, bytes) => Buffer.concat([Buffer.from([tag, bytes.length]), bytes]);
    const inner = Buffer.concat([seq(0x02, rBuf), seq(0x02, sBuf)]);
    return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

function pcrDigestExpected(pcrValuesByIndex, indices, hashAlg) {
    const hashName = TPM_ALG_TO_HASH[hashAlg];
    if (!hashName) throw new Error(`tpm_pcr_unsupported_hash:0x${hashAlg.toString(16)}`);
    const expectLen = HASH_OUTPUT_LEN[hashAlg];
    const concatBuffers = [];
    for (const idx of indices) {
        const value = pcrValuesByIndex[idx];
        if (!Buffer.isBuffer(value) || value.length !== expectLen) {
            throw new Error(`tpm_pcr_missing_or_wrong_size:index=${idx}`);
        }
        concatBuffers.push(value);
    }
    const concat = Buffer.concat(concatBuffers);
    return crypto.createHash(hashName).update(concat).digest();
}

function verifyAttestSignature(ekPublicKey, ekKeyType, attestBytes, signatureInfo) {
    const hashName = TPM_ALG_TO_HASH[signatureInfo.hashAlg];
    if (!hashName) {
        return { ok: false, reason: `tpm_quote_unsupported_hash:0x${signatureInfo.hashAlg.toString(16)}` };
    }
    try {
        const verifier = crypto.createVerify(hashName);
        verifier.update(attestBytes);
        verifier.end();
        if (signatureInfo.sigAlg === TPM_ALG_RSASSA) {
            const ok = verifier.verify({ key: ekPublicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, signatureInfo.sigBytes);
            return ok ? { ok: true } : { ok: false, reason: 'tpm_quote_rsassa_verify_failed' };
        }
        if (signatureInfo.sigAlg === TPM_ALG_RSAPSS) {
            const ok = verifier.verify({ key: ekPublicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signatureInfo.sigBytes);
            return ok ? { ok: true } : { ok: false, reason: 'tpm_quote_rsapss_verify_failed' };
        }
        if (signatureInfo.sigAlg === TPM_ALG_ECDSA) {
            const der = encodeEcdsaDer(signatureInfo.rBytes, signatureInfo.sBytes);
            const ok = verifier.verify({ key: ekPublicKey, dsaEncoding: 'der' }, der);
            return ok ? { ok: true } : { ok: false, reason: 'tpm_quote_ecdsa_verify_failed' };
        }
    } catch (err) {
        return { ok: false, reason: `tpm_quote_verify_exception:${err.message || 'unknown'}` };
    }
    return { ok: false, reason: 'tpm_quote_unsupported_sig_alg' };
}

function buildPcrComposite(pcrValuesByIndex, indices) {
    const buffers = [];
    for (const idx of indices) {
        const v = pcrValuesByIndex[idx];
        if (!Buffer.isBuffer(v)) throw new Error(`tpm_pcr_missing:${idx}`);
        buffers.push(v);
    }
    return Buffer.concat(buffers);
}

function deriveTpmHwidComponent(ekPublicKey, pcrValuesByIndex, existingAnchorString) {
    if (!ekPublicKey) throw new Error('tpm_hwid_missing_ek');
    const ekDer = ekPublicKey.export({ type: 'spki', format: 'der' });
    const ekHash = crypto.createHash('sha256').update(ekDer).digest();
    const pcrComposite = buildPcrComposite(pcrValuesByIndex, REQUIRED_PCR_INDICES);
    const pcrHash = crypto.createHash('sha256').update(pcrComposite).digest();
    const anchors = Buffer.from(String(existingAnchorString || ''), 'utf8');
    return crypto.createHash('sha256')
        .update(ekHash)
        .update(pcrHash)
        .update(anchors)
        .digest('hex');
}

function pcrValuesToBufferMap(pcrInput) {
    if (!pcrInput || typeof pcrInput !== 'object') {
        throw new Error('tpm_pcr_values_missing');
    }
    const out = {};
    for (const idx of REQUIRED_PCR_INDICES) {
        const raw = pcrInput[String(idx)] !== undefined ? pcrInput[String(idx)] : pcrInput[idx];
        if (raw === undefined || raw === null) {
            throw new Error(`tpm_pcr_value_missing:${idx}`);
        }
        let buf;
        if (Buffer.isBuffer(raw)) buf = raw;
        else if (typeof raw === 'string') {
            const trimmed = raw.trim();
            if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length === 64) {
                buf = Buffer.from(trimmed, 'hex');
            } else {
                buf = Buffer.from(trimmed, 'base64');
            }
        } else {
            throw new Error(`tpm_pcr_value_invalid_type:${idx}`);
        }
        if (buf.length !== HASH_OUTPUT_LEN[REQUIRED_PCR_BANK]) {
            throw new Error(`tpm_pcr_value_bad_length:${idx}:${buf.length}`);
        }
        out[idx] = buf;
    }
    return out;
}

function verifyTpmQuote(bundle) {
    if (!bundle || typeof bundle !== 'object') {
        return { ok: false, reason: 'tpm_bundle_missing' };
    }

    const ekCertSrc = bundle.ekCertPem || bundle.ekCert || bundle.ek_cert;
    const ekResult = ekRoots.verifyEkCertificateAgainstRoots(ekCertSrc);
    if (!ekResult.ok) {
        return { ok: false, reason: ekResult.reason };
    }
    const ekPublicKey = ekResult.ekPublicKey;
    if (!ekPublicKey) {
        return { ok: false, reason: 'tpm_ek_pubkey_extract_failed' };
    }

    const ekKeyType = ekPublicKey.asymmetricKeyType || 'rsa';

    let pcrMap;
    try { pcrMap = pcrValuesToBufferMap(bundle.pcrValues || bundle.pcr_values || bundle.pcrs); }
    catch (err) { return { ok: false, reason: err.message }; }

    let attestBuf;
    let sigBuf;
    try {
        attestBuf = decodeQuoteBuffer(bundle.attest || bundle.quote || bundle.tpms_attest);
        sigBuf = decodeQuoteBuffer(bundle.signature || bundle.sig || bundle.tpmt_signature);
    } catch (err) {
        return { ok: false, reason: `tpm_buffer_decode_failed:${err.message}` };
    }
    if (!attestBuf || attestBuf.length < 32) return { ok: false, reason: 'tpm_attest_too_short' };
    if (!sigBuf || sigBuf.length < 4) return { ok: false, reason: 'tpm_sig_too_short' };

    let attest;
    try { attest = parseAttestStructure(attestBuf); }
    catch (err) { return { ok: false, reason: err.message }; }

    let signatureInfo;
    try { signatureInfo = parseSignature(sigBuf); }
    catch (err) { return { ok: false, reason: err.message }; }

    const sigVerify = verifyAttestSignature(ekPublicKey, ekKeyType, attestBuf, signatureInfo);
    if (!sigVerify.ok) {
        return { ok: false, reason: sigVerify.reason };
    }

    const pcrSel = attest.pcrSelections.find(s => s.hashAlg === REQUIRED_PCR_BANK);
    if (!pcrSel) {
        return { ok: false, reason: `tpm_required_pcr_bank_missing:0x${REQUIRED_PCR_BANK.toString(16)}` };
    }
    for (const idx of REQUIRED_PCR_INDICES) {
        if (!pcrSel.indices.includes(idx)) {
            return { ok: false, reason: `tpm_required_pcr_not_quoted:${idx}` };
        }
    }

    let expectedDigest;
    try { expectedDigest = pcrDigestExpected(pcrMap, REQUIRED_PCR_INDICES, REQUIRED_PCR_BANK); }
    catch (err) { return { ok: false, reason: err.message }; }
    if (expectedDigest.length !== attest.pcrDigest.length || !crypto.timingSafeEqual(expectedDigest, attest.pcrDigest)) {
        return { ok: false, reason: 'tpm_pcr_digest_mismatch' };
    }

    const expectedNonce = bundle.expectedNonce || bundle.expected_nonce || bundle.serverNonce || bundle.server_nonce;
    if (expectedNonce !== undefined && expectedNonce !== null && expectedNonce !== '') {
        let nonceBuf;
        try {
            const ns = String(expectedNonce);
            nonceBuf = /^[0-9a-fA-F]+$/.test(ns) && ns.length % 2 === 0
                ? Buffer.from(ns, 'hex')
                : Buffer.from(ns, 'utf8');
        } catch (_) { nonceBuf = Buffer.from(String(expectedNonce), 'utf8'); }
        if (nonceBuf.length !== attest.extraData.length || !crypto.timingSafeEqual(nonceBuf, attest.extraData)) {
            return { ok: false, reason: 'tpm_nonce_mismatch' };
        }
    }

    const issuedAtMs = bundle.issuedAtMs || bundle.issued_at_ms;
    if (typeof issuedAtMs === 'number' && Number.isFinite(issuedAtMs)) {
        const now = Date.now();
        if (Math.abs(now - issuedAtMs) > QUOTE_FRESHNESS_SECONDS * 1000) {
            return { ok: false, reason: 'tpm_quote_stale' };
        }
    }

    const hwidComponent = deriveTpmHwidComponent(ekPublicKey, pcrMap, bundle.existingAnchorString || bundle.anchor_string || '');

    return {
        ok: true,
        ekVendor: ekResult.root.vendor,
        ekProduct: ekResult.root.productName,
        ekRootFingerprint: ekResult.root.fingerprint,
        ekCertFingerprint: ekResult.ekCertFingerprint,
        attestExtraData: attest.extraData.toString('hex'),
        firmwareVersion: attest.firmwareVersion.toString(),
        pcrDigestHex: attest.pcrDigest.toString('hex'),
        pcrSelectionIndices: pcrSel.indices,
        sigAlg: signatureInfo.sigAlg,
        hashAlg: signatureInfo.hashAlg,
        hwidComponentHex: hwidComponent,
        ekPublicKey,
    };
}

function sealLicenseKeyForClient(licenseSecret, ekPublicKey, pcrValuesByIndex) {
    if (!Buffer.isBuffer(licenseSecret)) licenseSecret = Buffer.from(licenseSecret);
    if (!ekPublicKey) throw new Error('tpm_seal_missing_ek');
    const ekDer = ekPublicKey.export({ type: 'spki', format: 'der' });
    const pcrComposite = buildPcrComposite(pcrValuesByIndex, REQUIRED_PCR_INDICES);
    const policyDigest = crypto.createHash('sha256').update(ekDer).update(pcrComposite).digest();

    const ephemeralKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ephemeralKey, iv);
    cipher.setAAD(policyDigest);
    const ct = Buffer.concat([cipher.update(licenseSecret), cipher.final()]);
    const tag = cipher.getAuthTag();

    let wrappedEphemeral;
    try {
        wrappedEphemeral = crypto.publicEncrypt({
            key: ekPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        }, ephemeralKey);
    } catch (err) {
        throw new Error(`tpm_seal_publicEncrypt_failed:${err.message}`);
    }

    return {
        version: 1,
        policyDigest: policyDigest.toString('hex'),
        wrappedEphemeral: wrappedEphemeral.toString('base64'),
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        ciphertext: ct.toString('base64'),
        pcrIndices: REQUIRED_PCR_INDICES.slice(),
        pcrBank: REQUIRED_PCR_BANK,
    };
}

function buildSyntheticQuote(rsaPrivateKey, ekCertDer, pcrValuesByIndex, options) {
    const opts = options || {};
    const extraData = Buffer.isBuffer(opts.extraData) ? opts.extraData : Buffer.from(opts.extraData || crypto.randomBytes(16));
    const qualifiedSigner = Buffer.alloc(0);
    const indices = (opts.pcrIndices && opts.pcrIndices.length) ? opts.pcrIndices.slice() : REQUIRED_PCR_INDICES.slice();
    const hashAlg = opts.hashAlg || REQUIRED_PCR_BANK;
    const expectedDigest = pcrDigestExpected(pcrValuesByIndex, indices, hashAlg);

    const writers = [];
    const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; };
    const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n & 0xFFFF, 0); return b; };
    const u8 = (n) => Buffer.from([n & 0xFF]);
    const u64 = (n) => {
        const b = Buffer.alloc(8);
        b.writeUInt32BE(Number(BigInt(n) >> 32n) >>> 0, 0);
        b.writeUInt32BE(Number(BigInt(n) & 0xFFFFFFFFn) >>> 0, 4);
        return b;
    };
    const sized16 = (data) => Buffer.concat([u16(data.length), data]);

    const selectBitmap = Buffer.alloc(3, 0);
    for (const idx of indices) {
        if (idx < 0 || idx >= 24) throw new Error('synthetic_quote_pcr_index_out_of_range');
        selectBitmap[idx >> 3] |= (1 << (idx & 7));
    }
    const pcrSelectionEntry = Buffer.concat([u16(hashAlg), u8(selectBitmap.length), selectBitmap]);

    writers.push(u32(TPM_GENERATED_VALUE));
    writers.push(u16(TPM_ST_ATTEST_QUOTE));
    writers.push(sized16(qualifiedSigner));
    writers.push(sized16(extraData));
    writers.push(u64(opts.clock || 0));
    writers.push(u32(opts.resetCount || 0));
    writers.push(u32(opts.restartCount || 0));
    writers.push(u8(opts.safe === undefined ? 1 : opts.safe));
    writers.push(u64(opts.firmwareVersion || 0));
    writers.push(u32(1));
    writers.push(pcrSelectionEntry);
    writers.push(sized16(expectedDigest));
    const attestBuf = Buffer.concat(writers);

    const hashName = TPM_ALG_TO_HASH[hashAlg];
    const signer = crypto.createSign(hashName);
    signer.update(attestBuf);
    signer.end();
    const sigBytes = signer.sign({ key: rsaPrivateKey, padding: crypto.constants.RSA_PKCS1_PADDING });

    const tpmtSig = Buffer.concat([u16(TPM_ALG_RSASSA), u16(hashAlg), sized16(sigBytes)]);

    return {
        attest: attestBuf,
        signature: tpmtSig,
        ekCert: ekCertDer,
        pcrValues: Object.fromEntries(indices.map(i => [String(i), pcrValuesByIndex[i].toString('hex')])),
    };
}

module.exports = {
    verifyTpmQuote,
    sealLicenseKeyForClient,
    deriveTpmHwidComponent,
    pcrValuesToBufferMap,
    parseAttestStructure,
    parseSignature,
    pcrDigestExpected,
    buildPcrComposite,
    buildSyntheticQuote,
    decodeQuoteBuffer,
    encodeEcdsaDer,
    REQUIRED_PCR_BANK,
    REQUIRED_PCR_INDICES,
    QUOTE_FRESHNESS_SECONDS,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TPM_ALG_RSA,
    TPM_ALG_RSASSA,
    TPM_ALG_RSAPSS,
    TPM_ALG_ECDSA,
    TPM_ALG_SHA256,
};
