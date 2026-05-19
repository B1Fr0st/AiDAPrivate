'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const tls = require('tls');
const { signPayload } = require('../crypto/signing');

const router = express.Router();

let s_cached_spki = null;
let s_cached_spki_loaded_at = 0;
const SPKI_CACHE_TTL_MS = 60 * 1000;

function computeSpkiSha256FromCertPem(pem) {
    if (!pem || typeof pem !== 'string') return '';
    try {
        const x509 = new crypto.X509Certificate(pem);
        const pub = x509.publicKey;
        const der = pub.export({ format: 'der', type: 'spki' });
        return crypto.createHash('sha256').update(der).digest('hex');
    } catch (err) {
        console.warn('[server_info] X509 parse failed:', err && err.message ? err.message : err);
        return '';
    }
}

function loadCurrentSpkiSha256() {
    const now = Date.now();
    if (s_cached_spki && (now - s_cached_spki_loaded_at) < SPKI_CACHE_TTL_MS) {
        return s_cached_spki;
    }
    const envHex = (process.env.SERVER_SPKI_SHA256 || '').trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(envHex)) {
        s_cached_spki = envHex;
        s_cached_spki_loaded_at = now;
        return s_cached_spki;
    }
    const certPath = (process.env.SERVER_TLS_CERT_PATH || '').trim();
    if (certPath && fs.existsSync(certPath)) {
        try {
            const pem = fs.readFileSync(certPath, 'utf8');
            const hash = computeSpkiSha256FromCertPem(pem);
            if (hash) {
                s_cached_spki = hash;
                s_cached_spki_loaded_at = now;
                return s_cached_spki;
            }
        } catch (err) {
            console.warn('[server_info] cert read failed:', err && err.message ? err.message : err);
        }
    }
    s_cached_spki = '';
    s_cached_spki_loaded_at = now;
    return s_cached_spki;
}

function loadNextSpkiSha256() {
    const envHex = (process.env.SERVER_NEXT_SPKI_SHA256 || '').trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(envHex)) return envHex;
    const nextPath = (process.env.SERVER_TLS_NEXT_CERT_PATH || '').trim();
    if (nextPath && fs.existsSync(nextPath)) {
        try {
            const pem = fs.readFileSync(nextPath, 'utf8');
            const hash = computeSpkiSha256FromCertPem(pem);
            if (hash) return hash;
        } catch (_) { }
    }
    return null;
}

function canonicalize(payload) {
    return JSON.stringify(Object.keys(payload).sort().reduce((acc, k) => {
        acc[k] = payload[k];
        return acc;
    }, {}));
}

router.get('/', (req, res) => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const currentSpki = loadCurrentSpkiSha256();
    const nextSpki = loadNextSpkiSha256();
    const kid = parseInt(process.env.ED25519_PRIMARY_KID || '1', 10) || 1;

    const corePayload = {
        current_spki_sha256: currentSpki || '',
        next_spki_sha256_pinned: nextSpki || null,
        issued_at: issuedAt,
        kid,
    };

    let signatureB64 = '';
    try {
        const canonical = canonicalize(corePayload);
        const sigHex = signPayload(JSON.parse(canonical));
        signatureB64 = Buffer.from(sigHex, 'hex').toString('base64');
    } catch (err) {
        console.error('[server_info] sign failed:', err && err.message ? err.message : err);
        res.setHeader('Content-Type', 'application/json');
        return res.status(503).send(JSON.stringify({ ok: false, error_code: 'EAUTH' }));
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(JSON.stringify(Object.assign({}, corePayload, { signature: signatureB64 })));
});

module.exports = router;
