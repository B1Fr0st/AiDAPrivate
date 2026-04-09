

const crypto = require('crypto');

let cachedPrivateKey = null;


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

    return cachedPrivateKey;
}


function sortObjectKeys(obj) {
    return Object.keys(obj).sort().reduce((sorted, key) => {
        sorted[key] = obj[key];
        return sorted;
    }, {});
}


function signPayload(payloadObj) {
    const canonical = JSON.stringify(sortObjectKeys(payloadObj));
    return crypto.sign(null, Buffer.from(canonical, 'utf8'), getSigningPrivateKey())
        .toString('hex');
}

module.exports = {
    signPayload,
    getSigningPrivateKey,
    sortObjectKeys,
};
