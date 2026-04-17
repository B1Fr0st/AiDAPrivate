

const crypto = require('crypto');

function deriveKeySeed(sessionToken, hwid, issuedAt) {
    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }
    const data = `${sessionToken}|${hwid}|${issuedAt}`;
    return crypto.createHmac('sha256', masterSecret)
        .update(data)
        .digest();
}

function deriveSessionKey(sessionToken, hwid, issuedAt) {
    return deriveKeySeed(sessionToken, hwid, issuedAt);
}

function encryptArc(plaintext, sessionToken, hwid, issuedAt) {
    const key = deriveKeySeed(sessionToken, hwid, issuedAt);
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

const CODE_PAGE_SIZE = 4096;

function derivePageKey(keySeed, pageIndex, sessionToken, hwid, issuedAt, proofToken, chainTag) {
    const proof = proofToken || '';
    const chain = chainTag || '';
    const data = `page|${pageIndex}|${sessionToken}|${hwid}|${issuedAt}|${proof}|${chain}`;
    return crypto.createHmac('sha256', keySeed)
        .update(data)
        .digest();
}

function deriveChainTag(prevTag, authTag) {
    const prev = prevTag ? Buffer.from(prevTag, 'hex') : Buffer.alloc(32, 0);
    return crypto.createHmac('sha256', prev)
        .update(authTag)
        .update('chain')
        .digest();
}

function getPageCount(blobSize) {
    return Math.ceil(blobSize / CODE_PAGE_SIZE);
}

function encryptPage(plaintext, pageIndex, sessionToken, hwid, issuedAt, proofToken, chainTag) {
    const keySeed = deriveKeySeed(sessionToken, hwid, issuedAt);
    const key = derivePageKey(keySeed, pageIndex, sessionToken, hwid, issuedAt, proofToken, chainTag);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const hmac = crypto.createHmac('sha256', key)
        .update(Buffer.concat([iv, authTag, encrypted]))
        .digest();

    return { encrypted, iv, authTag, hmac };
}

function splitIntoPages(blob) {
    const pages = [];
    for (let offset = 0; offset < blob.length; offset += CODE_PAGE_SIZE) {
        const end = Math.min(offset + CODE_PAGE_SIZE, blob.length);
        pages.push(blob.subarray(offset, end));
    }
    return pages;
}

module.exports = {
    deriveKeySeed,
    deriveSessionKey,
    encryptArc,
    derivePageKey,
    deriveChainTag,
    getPageCount,
    encryptPage,
    splitIntoPages,
    CODE_PAGE_SIZE,
};
