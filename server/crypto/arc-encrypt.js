

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

function anchorToString(value) {
    if (value === null || value === undefined) return '';
    if (Buffer.isBuffer(value)) return value.toString('hex');
    if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'bigint') return String(value);
    if (typeof value === 'boolean') return value ? '1' : '0';
    return String(value);
}

function deriveKeySeedFull(licenseRow, sessionRow) {
    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }
    const lic = licenseRow || {};
    const ses = sessionRow || {};
    const parts = [
        anchorToString(ses.session_token),
        anchorToString(ses.hwid),
        anchorToString(ses.issued_at),
        anchorToString(lic.hardware_id_sha256),
        anchorToString(lic.smbios_uuid_hash),
        anchorToString(lic.baseboard_serial_hash),
        anchorToString(lic.disk_vpd_hash),
        anchorToString(lic.machine_guid_hash),
        anchorToString(lic.install_secret_wrapped),
        anchorToString(lic.witness_key_wrapped),
        anchorToString(lic.ioctl_seed_wrapped),
        anchorToString(lic.boot_nonce_last),
    ];
    const data = parts.join('|');
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

function encryptArcFull(plaintext, licenseRow, sessionRow) {
    const key = deriveKeySeedFull(licenseRow, sessionRow);
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

function derivePageKeyFull(keySeed, pageIndex, sessionRow, licenseRow, proofToken, chainTag) {
    const ses = sessionRow || {};
    const lic = licenseRow || {};
    const proof = proofToken || '';
    const chain = chainTag || '';
    const parts = [
        'page',
        String(pageIndex),
        anchorToString(ses.session_token),
        anchorToString(ses.hwid),
        anchorToString(ses.issued_at),
        proof,
        chain,
        anchorToString(lic.hardware_id_sha256),
        anchorToString(lic.smbios_uuid_hash),
        anchorToString(lic.baseboard_serial_hash),
        anchorToString(lic.disk_vpd_hash),
        anchorToString(lic.machine_guid_hash),
        anchorToString(lic.install_secret_wrapped),
        anchorToString(lic.witness_key_wrapped),
        anchorToString(lic.ioctl_seed_wrapped),
        anchorToString(lic.boot_nonce_last),
    ];
    const data = parts.join('|');
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

function encryptPageFull(plaintext, pageIndex, licenseRow, sessionRow, proofToken, chainTag) {
    const keySeed = deriveKeySeedFull(licenseRow, sessionRow);
    const key = derivePageKeyFull(keySeed, pageIndex, sessionRow, licenseRow, proofToken, chainTag);
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
    deriveKeySeedFull,
    deriveSessionKey,
    encryptArc,
    encryptArcFull,
    derivePageKey,
    derivePageKeyFull,
    deriveChainTag,
    getPageCount,
    encryptPage,
    encryptPageFull,
    splitIntoPages,
    CODE_PAGE_SIZE,
};
