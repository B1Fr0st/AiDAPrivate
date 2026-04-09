// ============================================================================
// AiDA License Server — Ed25519 Signing Module
// ============================================================================
// Direct port from Firebase Cloud Function signing logic.
// Uses Node.js built-in crypto module for Ed25519 (available since Node 16).
// ============================================================================

const crypto = require('crypto');

let cachedPrivateKey = null;

/**
 * Load the Ed25519 private key from environment.
 * Caches the parsed key for subsequent calls.
 */
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

/**
 * Alphabetically sort object keys (recursively for deterministic JSON).
 * Mirrors the Firebase function's sortObjectKeys.
 */
function sortObjectKeys(obj) {
    return Object.keys(obj).sort().reduce((sorted, key) => {
        sorted[key] = obj[key];
        return sorted;
    }, {});
}

/**
 * Compute an Ed25519 signature over a canonical JSON payload string.
 * The client verifies this with the embedded public key.
 *
 * @param {Object} payloadObj - The payload to sign (keys will be sorted).
 * @returns {string} Hex-encoded Ed25519 signature.
 */
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
