

const crypto = require('crypto');

let cachedPrivateKey = null;
let cachedNextPrivateKey = null;
let cachedBootstrapP256 = null;
let s_loggedPubFp = false;

const PRIMARY_KID = parseInt(process.env.ED25519_PRIMARY_KID || '1', 10) || 1;
const NEXT_KID = parseInt(process.env.ED25519_NEXT_KID || '2', 10) || 2;
const PRIMARY_RETIRE_AT = parseInt(process.env.ED25519_PRIMARY_RETIRE_AT || '0', 10) || 0;


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
            const pubSpki = crypto.createPublicKey(cachedPrivateKey)
                .export({ format: 'der', type: 'spki' })
            const fpShort = crypto.createHash('sha256').update(pubSpki).digest('hex').slice(-16);
            console.log(`[signing] loaded ED25519 signing key public_spki_sha256_tail=${fpShort}`);
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

function base64Url(buf) {
    return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fixed32FromBigInt(value) {
    let hex = value.toString(16);
    if (hex.length > 64) hex = hex.slice(-64);
    while (hex.length < 64) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
}

function getBootstrapP256KeyInfo() {
    if (cachedBootstrapP256) return cachedBootstrapP256;
    const privateDer = Buffer.from(process.env.ED25519_PRIVATE_KEY_B64 || '', 'base64');
    if (privateDer.length < 32) {
        throw new Error('bootstrap p256 signing key unavailable');
    }
    const seed = crypto.createHmac('sha256', privateDer)
        .update('aida/bootstrap/manifest-p256/v1', 'utf8')
        .digest();
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    const scalar = (BigInt('0x' + seed.toString('hex')) % (n - 1n)) + 1n;
    const d = fixed32FromBigInt(scalar);
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(d);
    const pub = ecdh.getPublicKey(null, 'uncompressed');
    const x = pub.subarray(1, 33);
    const y = pub.subarray(33, 65);
    const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: base64Url(x),
        y: base64Url(y),
        d: base64Url(d),
    };
    cachedBootstrapP256 = {
        privateKey: crypto.createPrivateKey({ key: jwk, format: 'jwk' }),
        publicJwk: { kty: 'EC', crv: 'P-256', x: base64Url(x), y: base64Url(y) },
        x_hex: x.toString('hex'),
        y_hex: y.toString('hex'),
    };
    return cachedBootstrapP256;
}

function signBootstrapP256String(value) {
    return crypto.sign('sha256', Buffer.from(String(value || ''), 'utf8'), {
        key: getBootstrapP256KeyInfo().privateKey,
        dsaEncoding: 'ieee-p1363',
    }).toString('hex');
}

function getBootstrapP256PublicHex() {
    const key = getBootstrapP256KeyInfo();
    return { x: key.x_hex, y: key.y_hex };
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


function activeKidForCanonical() {
    const now = Math.floor(Date.now() / 1000);
    if (PRIMARY_RETIRE_AT > 0 && now >= PRIMARY_RETIRE_AT) {
        const nextKey = getNextSigningPrivateKey();
        if (nextKey) return NEXT_KID;
    }
    return PRIMARY_KID;
}

function signWithKid(payloadObj) {
    const kid = activeKidForCanonical();
    const augmented = { ...payloadObj, kid };
    const canonical = JSON.stringify(sortObjectKeys(augmented));
    const buf = Buffer.from(canonical, 'utf8');
    const key = (kid === NEXT_KID) ? getNextSigningPrivateKey() : getSigningPrivateKey();
    if (!key) {
        throw new Error('signWithKid: requested key id has no configured private key');
    }
    const signature = crypto.sign(null, buf, key).toString('hex');
    return { kid, signature, canonical };
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
            return { signature, next_signature: nextSignature, kid: PRIMARY_KID, next_kid: NEXT_KID };
        }
    }

    return { signature, kid: PRIMARY_KID };
}

function getActiveKidInfo() {
    return {
        primary_kid: PRIMARY_KID,
        next_kid: NEXT_KID,
        primary_retire_at: PRIMARY_RETIRE_AT,
        active_kid: activeKidForCanonical(),
    };
}


function clearKeyCache() {
    cachedPrivateKey = null;
    cachedNextPrivateKey = null;
    cachedBootstrapP256 = null;
}

module.exports = {
    signPayload,
    dualSignPayload,
    signWithKid,
    activeKidForCanonical,
    getActiveKidInfo,
    getSigningPrivateKey,
    getNextSigningPrivateKey,
    getBootstrapP256PublicHex,
    signBootstrapP256String,
    sortObjectKeys,
    clearKeyCache,
};
