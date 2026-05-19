'use strict';

const crypto = require('crypto');
const { getSigningPrivateKey, getNextSigningPrivateKey, sortObjectKeys } = require('./signing');

const PRIMARY_KID = parseInt(process.env.ED25519_PRIMARY_KID || '1', 10) || 1;
const NEXT_KID = parseInt(process.env.ED25519_NEXT_KID || '2', 10) || 2;
const PRIMARY_RETIRE_AT = parseInt(process.env.ED25519_PRIMARY_RETIRE_AT || '0', 10) || 0;

function activeKid() {
    const now = Math.floor(Date.now() / 1000);
    if (PRIMARY_RETIRE_AT > 0 && now >= PRIMARY_RETIRE_AT) {
        const next = getNextSigningPrivateKey();
        if (next) return NEXT_KID;
    }
    return PRIMARY_KID;
}

function getSigningKeyForKid(kid) {
    if (kid === NEXT_KID) {
        const k = getNextSigningPrivateKey();
        if (!k) throw new Error('next_signing_key_unavailable');
        return k;
    }
    return getSigningPrivateKey();
}

function canonicalizeForSig(payload) {
    return JSON.stringify(sortObjectKeys(payload));
}

function packPayload(payload) {
    const canonical = canonicalizeForSig(payload);
    return Buffer.from(canonical, 'utf8').toString('base64');
}

function unpackPayload(payloadB64) {
    if (typeof payloadB64 !== 'string') return null;
    try {
        const raw = Buffer.from(payloadB64, 'base64').toString('utf8');
        return JSON.parse(raw);
    } catch (_) {
        return null;
    }
}

function buildEnvelope(payload) {
    const kid = activeKid();
    const augmented = Object.assign({}, payload, { kid });
    const canonical = canonicalizeForSig(augmented);
    const buf = Buffer.from(canonical, 'utf8');
    const sig = crypto.sign(null, buf, getSigningKeyForKid(kid)).toString('base64');
    const payloadB64 = buf.toString('base64');

    const envelope = Object.assign({}, augmented, {
        payload: payloadB64,
        sig,
        kid,
    });

    const nextNotBefore = parseInt(process.env.ED25519_NEXT_NOT_BEFORE || '0', 10) || 0;
    const now = Math.floor(Date.now() / 1000);
    const OVERLAP_SECONDS = 86400;
    if (kid !== NEXT_KID && nextNotBefore > 0 && now >= (nextNotBefore - OVERLAP_SECONDS)) {
        const nextKey = getNextSigningPrivateKey();
        if (nextKey) {
            try {
                const nextAugmented = Object.assign({}, payload, { kid: NEXT_KID });
                const nextCanonical = canonicalizeForSig(nextAugmented);
                const nextSig = crypto.sign(null, Buffer.from(nextCanonical, 'utf8'), nextKey).toString('base64');
                envelope.next_sig = nextSig;
                envelope.next_kid = NEXT_KID;
            } catch (_) { }
        }
    }
    return envelope;
}

function wrapResponse(res, status, payload) {
    const envelope = buildEnvelope(payload || {});
    return res.status(status).json(envelope);
}

module.exports = {
    buildEnvelope,
    wrapResponse,
    activeKid,
    canonicalizeForSig,
    packPayload,
    unpackPayload,
};
