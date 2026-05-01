'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const TPM_EK_OID_KEY_USAGE = '2.5.29.15';
const TPM_EK_OID_EXT_KEY_USAGE = '2.5.29.37';

const DEFAULT_BUILT_IN_ROOTS_DIR = path.join(__dirname, '..', 'data', 'tpm_ek_roots');
const VENDOR_LABEL_FROM_FILENAME = [
    { regex: /infineon/i,        vendor: 'Infineon' },
    { regex: /intel/i,           vendor: 'Intel' },
    { regex: /(stm|stmicro)/i,   vendor: 'STMicroelectronics' },
    { regex: /nuvoton/i,         vendor: 'Nuvoton' },
    { regex: /amd/i,             vendor: 'AMD' },
    { regex: /(microsoft|pluton)/i, vendor: 'Microsoft' },
];

let s_compiledRoots = null;
let s_envRootsLoaded = false;

function vendorFromFilename(name) {
    for (const e of VENDOR_LABEL_FROM_FILENAME) {
        if (e.regex.test(name)) return e.vendor;
    }
    return 'unknown';
}

function loadDirectory(dirPath, list) {
    let entries;
    try { entries = fs.readdirSync(dirPath); }
    catch (_) { return; }
    for (const name of entries) {
        if (!/\.(pem|crt|cer)$/i.test(name)) continue;
        const fullPath = path.join(dirPath, name);
        try {
            const raw = fs.readFileSync(fullPath);
            const pem = raw.toString('utf8');
            let der;
            if (pem.includes('-----BEGIN')) {
                const b64 = extractDer(pem);
                der = Buffer.from(b64, 'base64');
            } else {
                der = raw;
            }
            const pubKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
            const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
            list.push({
                vendor: vendorFromFilename(name),
                productName: name,
                pem: pem.includes('-----BEGIN') ? pem : derToPem(der),
                der,
                publicKey: pubKey,
                fingerprint,
            });
        } catch (err) {
            try {
                const pem = fs.readFileSync(fullPath, 'utf8');
                const pubKey = crypto.createPublicKey({ key: pem, format: 'pem' });
                const der = Buffer.from(extractDer(pem), 'base64');
                const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
                list.push({
                    vendor: vendorFromFilename(name),
                    productName: name,
                    pem,
                    der,
                    publicKey: pubKey,
                    fingerprint,
                });
            } catch (err2) {
                console.warn(`[ek_roots] ${fullPath} parse failed: ${err2.message}`);
            }
        }
    }
}

function compileRoots() {
    if (s_compiledRoots) return s_compiledRoots;
    const list = [];
    if (!s_envRootsLoaded) {
        s_envRootsLoaded = true;
        if (fs.existsSync(DEFAULT_BUILT_IN_ROOTS_DIR)) {
            loadDirectory(DEFAULT_BUILT_IN_ROOTS_DIR, list);
        }
        const envDir = process.env.TPM_EK_ROOTS_DIR;
        if (envDir) {
            try {
                const stat = fs.statSync(envDir);
                if (stat.isDirectory()) loadDirectory(envDir, list);
            } catch (err) {
                console.warn(`[ek_roots] TPM_EK_ROOTS_DIR=${envDir} ignored: ${err.message}`);
            }
        }
    }
    s_compiledRoots = list;
    return s_compiledRoots;
}

function derToPem(der) {
    const b64 = der.toString('base64');
    const wrapped = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

function extractDer(pem) {
    const m = String(pem || '').match(/-----BEGIN [^-]+-----([\s\S]+?)-----END [^-]+-----/);
    if (!m) return '';
    return m[1].replace(/\s+/g, '');
}

function parseDerLengthAt(buf, pos) {
    if (pos >= buf.length) return null;
    const first = buf[pos];
    if ((first & 0x80) === 0) {
        return { length: first, headerLen: 1 };
    }
    const numLen = first & 0x7F;
    if (numLen === 0 || numLen > 4) return null;
    if (pos + 1 + numLen > buf.length) return null;
    let length = 0;
    for (let i = 0; i < numLen; i++) {
        length = (length << 8) | buf[pos + 1 + i];
    }
    return { length, headerLen: 1 + numLen };
}

function readDerSequence(buf, pos) {
    if (pos >= buf.length || buf[pos] !== 0x30) return null;
    const lenInfo = parseDerLengthAt(buf, pos + 1);
    if (!lenInfo) return null;
    const start = pos + 1 + lenInfo.headerLen;
    const end = start + lenInfo.length;
    if (end > buf.length) return null;
    return { start, end, total: end - pos };
}

function findCertSignatureSlice(certDer) {
    const outer = readDerSequence(certDer, 0);
    if (!outer) return null;
    const tbsStart = outer.start;
    const tbs = readDerSequence(certDer, tbsStart);
    if (!tbs) return null;
    const tbsEnd = tbs.end;
    const sigAlg = readDerSequence(certDer, tbsEnd);
    if (!sigAlg) return null;
    const sigBitStringPos = sigAlg.end;
    if (certDer[sigBitStringPos] !== 0x03) return null;
    const sigLen = parseDerLengthAt(certDer, sigBitStringPos + 1);
    if (!sigLen) return null;
    const sigContentStart = sigBitStringPos + 1 + sigLen.headerLen;
    const unusedBits = certDer[sigContentStart];
    if (unusedBits !== 0) return null;
    const signatureBytes = certDer.subarray(sigContentStart + 1, sigContentStart + sigLen.length);
    const tbsBytes = certDer.subarray(tbsStart, tbsEnd);
    const algBytes = certDer.subarray(tbsEnd, sigAlg.end);
    return { tbsBytes, sigAlgBytes: algBytes, signatureBytes };
}

function decodeAlgOid(algSeqBytes) {
    const seq = readDerSequence(algSeqBytes, 0);
    if (!seq) return '';
    const inner = algSeqBytes.subarray(seq.start, seq.end);
    if (inner.length < 2 || inner[0] !== 0x06) return '';
    const oidLen = parseDerLengthAt(inner, 1);
    if (!oidLen) return '';
    const oidBytes = inner.subarray(1 + oidLen.headerLen, 1 + oidLen.headerLen + oidLen.length);
    if (oidBytes.length === 0) return '';
    const result = [];
    const first = oidBytes[0];
    result.push(Math.floor(first / 40));
    result.push(first % 40);
    let acc = 0;
    for (let i = 1; i < oidBytes.length; i++) {
        const b = oidBytes[i];
        acc = (acc << 7) | (b & 0x7F);
        if ((b & 0x80) === 0) {
            result.push(acc);
            acc = 0;
        }
    }
    return result.join('.');
}

const SIG_ALG_OID_TO_HASH = {
    '1.2.840.113549.1.1.5': 'sha1',
    '1.2.840.113549.1.1.11': 'sha256',
    '1.2.840.113549.1.1.12': 'sha384',
    '1.2.840.113549.1.1.13': 'sha512',
    '1.2.840.10045.4.3.1': 'sha224',
    '1.2.840.10045.4.3.2': 'sha256',
    '1.2.840.10045.4.3.3': 'sha384',
    '1.2.840.10045.4.3.4': 'sha512',
};

function listRoots() {
    return compileRoots();
}

function getRootByFingerprint(fp) {
    if (!fp || typeof fp !== 'string') return null;
    const lower = fp.toLowerCase();
    for (const r of compileRoots()) {
        if (r.fingerprint === lower) return r;
    }
    return null;
}

function verifyEkCertificateAgainstRoots(ekCertPemOrDer) {
    let der;
    if (Buffer.isBuffer(ekCertPemOrDer)) {
        der = ekCertPemOrDer;
    } else if (typeof ekCertPemOrDer === 'string') {
        if (ekCertPemOrDer.includes('-----BEGIN')) {
            der = Buffer.from(extractDer(ekCertPemOrDer), 'base64');
        } else {
            try { der = Buffer.from(ekCertPemOrDer, 'base64'); }
            catch (_) { return { ok: false, reason: 'ek_cert_decode_failed' }; }
        }
    } else {
        return { ok: false, reason: 'ek_cert_invalid_type' };
    }

    if (!der || der.length < 64) {
        return { ok: false, reason: 'ek_cert_too_short' };
    }

    const slice = findCertSignatureSlice(der);
    if (!slice) {
        return { ok: false, reason: 'ek_cert_parse_failed' };
    }

    const oid = decodeAlgOid(slice.sigAlgBytes);
    const algName = SIG_ALG_OID_TO_HASH[oid];
    if (!algName) {
        return { ok: false, reason: `ek_cert_unsupported_sig_alg:${oid}` };
    }

    const isEcdsa = oid.startsWith('1.2.840.10045.4');
    const roots = compileRoots();
    if (roots.length === 0) {
        return { ok: false, reason: 'no_ek_roots_configured' };
    }
    for (const root of roots) {
        try {
            const verifier = crypto.createVerify(algName);
            verifier.update(slice.tbsBytes);
            verifier.end();
            const verifyOpts = isEcdsa
                ? { key: root.publicKey, dsaEncoding: 'der' }
                : root.publicKey;
            if (verifier.verify(verifyOpts, slice.signatureBytes)) {
                let ekPubKey = null;
                try {
                    ekPubKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
                } catch (_) {
                    ekPubKey = null;
                }
                if (!ekPubKey) {
                    try {
                        const pem = derToPem(der);
                        ekPubKey = crypto.createPublicKey({ key: pem, format: 'pem' });
                    } catch (_) { ekPubKey = null; }
                }
                return {
                    ok: true,
                    root: { vendor: root.vendor, productName: root.productName, fingerprint: root.fingerprint },
                    ekCertFingerprint: crypto.createHash('sha256').update(der).digest('hex'),
                    ekPublicKey: ekPubKey,
                    sigAlg: algName,
                };
            }
        } catch (_) {
        }
    }
    return { ok: false, reason: 'ek_cert_no_root_match' };
}

function syntheticTestRoot() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const issuer = 'AIDA-TEST-EK-ROOT';
    const root = {
        vendor: 'TestSynthetic',
        productName: issuer,
        publicKey,
        privateKey,
        fingerprint: 'synthetic-test',
    };
    return root;
}

function injectSyntheticRootForTests(root) {
    const list = compileRoots();
    list.push(root);
}

function clearForTests() {
    s_compiledRoots = null;
    s_envRootsLoaded = false;
}

module.exports = {
    listRoots,
    getRootByFingerprint,
    verifyEkCertificateAgainstRoots,
    syntheticTestRoot,
    injectSyntheticRootForTests,
    clearForTests,
    extractDer,
    derToPem,
    findCertSignatureSlice,
    decodeAlgOid,
    parseDerLengthAt,
    SIG_ALG_OID_TO_HASH,
    TPM_EK_OID_KEY_USAGE,
    TPM_EK_OID_EXT_KEY_USAGE,
    DEFAULT_BUILT_IN_ROOTS_DIR,
};
