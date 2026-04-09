

const crypto = require('crypto');


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


function encryptArc(plaintext, sessionToken, hwid, issuedAt) {
    const key = deriveSessionKey(sessionToken, hwid, issuedAt);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();


    const hash = crypto.createHash('sha256').update(plaintext).digest('hex');

    return { encrypted, iv, authTag, hash };
}

module.exports = {
    deriveSessionKey,
    encryptArc,
};
