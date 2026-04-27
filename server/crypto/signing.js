

const crypto = require('crypto');

let cachedPrivateKey = null;
let cachedNextPrivateKey = null;
let s_loggedPubFp = false;


function getSigningPrivateKey() {
    if (cachedPrivateKey) {
        return cachedPrivateKey;
    }

    const b64 = process.env.ED25519_PRIVATE_KEY_B64;
    if (!b64 || typeof b64 !== 'string' || b64.length < 16) {
        throw new Error('Missing or invalid ED25519_PRIVATE_KEY_B64 environment variable');
    }

    cachedPrivateKey = crypto.createPrivateKey({
        key: Buffer.from(b64, 'base64'),
        format: 'der',
        type: 'pkcs8',
    });

    if (!s_loggedPubFp) {
        try {
            const pubSpkiHex = crypto.createPublicKey(cachedPrivateKey)
                .export({ format: 'der', type: 'spki' })
                .toString('hex');
            const fpShort = pubSpkiHex.slice(-16);
            console.log(`[signing] loaded ED25519 private key, derived public SPKI(hex)=${pubSpkiHex} fp_tail=${fpShort} src_b64_tail=${b64.slice(-12)} src_b64_len=${b64.length}`);
            s_loggedPubFp = true;
        } catch (err) {
            console.warn('[signing] failed to log pub fingerprint:', err && err.message ? err.message : err);
        }
    }

    return cachedPrivateKey;
}


function getNextSigningPrivateKey() {
    if (cachedNextPrivateKey !== null) {
        return cachedNextPrivateKey || null;
    }

    const b64 = process.env.ED25519_NEXT_PRIVATE_KEY_B64;
    if (!b64 || typeof b64 !== 'string' || b64.length < 16) {
        cachedNextPrivateKey = false;
        return null;
    }

    cachedNextPrivateKey = crypto.createPrivateKey({
        key: Buffer.from(b64, 'base64'),
        format: 'der',
        type: 'pkcs8',
    });

    return cachedNextPrivateKey;
}


function sortObjectKeys(obj) {
    return Object.keys(obj).sort().reduce((sorted, key) => {
        sorted[key] = obj[key];
        return sorted;
    }, {});
}


function signPayload(payloadObj) {
    const canonical = JSON.stringify(sortObjectKeys(payloadObj));
    const sigHex = crypto.sign(null, Buffer.from(canonical, 'utf8'), getSigningPrivateKey())
        .toString('hex');
    if (process.env.AIDA_SIGN_DEBUG === '1') {
        const canonHash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
        const keys = Object.keys(sortObjectKeys(payloadObj)).join(',');
        console.log(`[signing] signPayload keys=[${keys}] canonical_len=${canonical.length} canonical_sha256=${canonHash} sig_tail=${sigHex.slice(-16)}`);
    }
    return sigHex;
}


function dualSignPayload(payloadObj) {
    const canonical = JSON.stringify(sortObjectKeys(payloadObj));
    const buf = Buffer.from(canonical, 'utf8');

    const signature = crypto.sign(null, buf, getSigningPrivateKey()).toString('hex');

    const nextNotBefore = parseInt(process.env.ED25519_NEXT_NOT_BEFORE || '0', 10) || 0;
    const now = Math.floor(Date.now() / 1000);


    const OVERLAP_SECONDS = 86400;
    if (nextNotBefore > 0 && now >= (nextNotBefore - OVERLAP_SECONDS)) {
        const nextKey = getNextSigningPrivateKey();
        if (nextKey) {
            const nextSignature = crypto.sign(null, buf, nextKey).toString('hex');
            return { signature, next_signature: nextSignature };
        }
    }

    return { signature };
}


function clearKeyCache() {
    cachedPrivateKey = null;
    cachedNextPrivateKey = null;
}

module.exports = {
    signPayload,
    dualSignPayload,
    getSigningPrivateKey,
    getNextSigningPrivateKey,
    sortObjectKeys,
    clearKeyCache,
};
