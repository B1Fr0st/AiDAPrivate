// ============================================================================
// AiDA License Server — ARC Per-Session Encryption
// ============================================================================
// Encrypts the ARC DLL blob with a session-specific AES-256-GCM key.
// Each download gets a unique key derived from session credentials so
// captured blobs are useless for different sessions/users.
// ============================================================================

const crypto = require('crypto');

/**
 * Derive a per-session AES-256 encryption key using HMAC-SHA256.
 *
 * Key material: server master secret + session_token + hwid + issued_at
 * This ensures:
 *   - Different session → different key (session_token changes)
 *   - Different machine → different key (hwid changes)
 *   - Renewed session → different key (issued_at changes)
 *
 * @param {string} sessionToken - 64-char hex session token
 * @param {string} hwid         - Client hardware ID
 * @param {number} issuedAt     - Unix timestamp of session creation
 * @returns {Buffer} 32-byte AES-256 key
 */
function deriveSessionKey(sessionToken, hwid, issuedAt) {
    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }

    const data = `${sessionToken}|${hwid}|${issuedAt}`;
    return crypto.createHmac('sha256', masterSecret)
        .update(data)
        .digest();
}

/**
 * Encrypt a binary blob with AES-256-GCM using session-derived key.
 *
 * @param {Buffer} plaintext    - The raw ARC DLL bytes
 * @param {string} sessionToken - Session token for key derivation
 * @param {string} hwid         - Client HWID for key derivation
 * @param {number} issuedAt     - Session issued_at for key derivation
 * @returns {{ encrypted: Buffer, iv: Buffer, authTag: Buffer, hash: string }}
 */
function encryptArc(plaintext, sessionToken, hwid, issuedAt) {
    const key = deriveSessionKey(sessionToken, hwid, issuedAt);
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // SHA-256 of plaintext for client-side integrity verification after decryption
    const hash = crypto.createHash('sha256').update(plaintext).digest('hex');

    return { encrypted, iv, authTag, hash };
}

module.exports = {
    deriveSessionKey,
    encryptArc,
};
