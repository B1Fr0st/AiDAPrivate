

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { encryptArc, encryptPage, splitIntoPages, getPageCount } = require('../crypto/arc-encrypt');

const router = express.Router();


const ARC_BLOB_PATH = process.env.ARC_BLOB_PATH || '/opt/aida/arc/aida_core.bin';


let cachedArcBlob = null;


function loadArcBlob() {
    if (cachedArcBlob) return cachedArcBlob;

    if (!fs.existsSync(ARC_BLOB_PATH)) {
        throw new Error(`ARC blob not found at ${ARC_BLOB_PATH}`);
    }

    const raw = fs.readFileSync(ARC_BLOB_PATH);


    if (raw.length < 28) {
        throw new Error('ARC blob file is too small — corrupt or invalid');
    }

    const iv = raw.subarray(0, 12);
    const authTag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);

    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }


    const atRestKey = crypto.createHash('sha256')
        .update(`arc-at-rest|${masterSecret}`)
        .digest();

    const decipher = crypto.createDecipheriv('aes-256-gcm', atRestKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);


    if (decrypted.length < 2 || decrypted[0] !== 0x4D || decrypted[1] !== 0x5A) {
        throw new Error('Decrypted ARC blob does not have valid MZ header');
    }

    cachedArcBlob = decrypted;
    console.log(`[arc] Loaded ARC blob: ${decrypted.length} bytes`);
    return cachedArcBlob;
}


async function validateSession(licenseKey, sessionToken, hwid) {
    if (!licenseKey || !sessionToken || !hwid) {
        return { valid: false, reason: 'missing_fields' };
    }


    const banResult = await pool.query(
        'SELECT 1 FROM bans WHERE (ban_type = $1 AND value = $2) LIMIT 1',
        ['hwid', hwid]
    );
    if (banResult.rows.length > 0) {
        return { valid: false, reason: 'banned' };
    }


    const { rows: licRows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [licenseKey]
    );
    if (licRows.length === 0 || !licRows[0].active) {
        return { valid: false, reason: 'invalid_license' };
    }
    const license = licRows[0];
    if (license.expires && license.expires !== '' && license.expires < new Date().toISOString().slice(0, 10)) {
        return { valid: false, reason: 'expired' };
    }


    const { rows: sesRows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (sesRows.length === 0 || sesRows[0].session_token !== sessionToken) {
        return { valid: false, reason: 'session_mismatch' };
    }

    const session = sesRows[0];


    if (session.hwid && session.hwid !== hwid) {
        return { valid: false, reason: 'hwid_mismatch' };
    }


    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * 1.5);
        if (now > expiresAt) {
            return { valid: false, reason: 'session_expired' };
        }
    }

    return { valid: true, session };
}


router.post('/arc', async (req, res) => {
    try {
        const { license_key, session_token, hwid } = req.body || {};
        const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
            || req.ip || 'unknown';

        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;


        let arcBlob;
        try {
            arcBlob = loadArcBlob();
        } catch (err) {
            console.error('[arc] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }


        const { encrypted, iv, authTag, hash } = encryptArc(
            arcBlob,
            session.session_token,
            hwid,
            session.issued_at
        );


        await pool.query(`
            INSERT INTO downloads (hwid, ip, license_key, artifact, user_agent)
            VALUES ($1, $2, $3, 'arc', $4)
        `, [hwid, clientIp, license_key, req.headers['user-agent'] || '']);

        return res.json({
            status: 'ok',
            encrypted_blob: encrypted.toString('base64'),
            iv: iv.toString('hex'),
            auth_tag: authTag.toString('hex'),
            blob_hash: hash,
            blob_size: arcBlob.length,
        });
    } catch (err) {
        console.error('[arc] Download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


function watermarkBinary(peBuffer, licenseKey, hwid, clientIp) {
    const masterSecret = process.env.ARC_MASTER_SECRET || '';

    const now = Math.floor(Date.now() / 1000);
    const block = Buffer.alloc(256, 0);


    block.writeUInt32BE(0xA1DA0001, 0);
    block.writeUInt32BE(0x00000001, 4);


    block.writeBigUInt64LE(BigInt(now), 8);


    const identityHmac = crypto.createHmac('sha256', masterSecret)
        .update(`${licenseKey}|${hwid}|${now}`)
        .digest();
    identityHmac.copy(block, 16);


    const binaryHash = crypto.createHash('sha256').update(peBuffer).digest();
    binaryHash.copy(block, 48);


    const keyHash = crypto.createHash('sha512').update(licenseKey).digest();
    keyHash.copy(block, 80);


    const hwidHash = crypto.createHash('sha256').update(hwid).digest();
    hwidHash.copy(block, 144);


    const ipHash = crypto.createHash('md5').update(clientIp).digest();
    ipHash.copy(block, 176);


    const integrityHmac = crypto.createHmac('sha256', masterSecret)
        .update(block.subarray(0, 192))
        .digest();
    integrityHmac.copy(block, 192);


    crypto.randomBytes(32).copy(block, 224);


    const streamKey = crypto.createHash('sha256')
        .update(`watermark-stream|${masterSecret}`)
        .digest();
    for (let i = 0; i < 256; i++) {
        block[i] ^= streamKey[i % 32];
    }

    return Buffer.concat([peBuffer, block]);
}


router.get('/aida', async (req, res) => {
    try {
        const sessionToken = req.headers['authorization'] || '';
        if (!sessionToken || sessionToken.length < 32) {
            return res.status(401).json({ status: 'error', reason: 'unauthorized' });
        }


        const { rows } = await pool.query(
            'SELECT * FROM sessions WHERE session_token = $1',
            [sessionToken]
        );
        if (rows.length === 0) {
            return res.status(403).json({ status: 'error', reason: 'invalid_session' });
        }

        const session = rows[0];
        const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
            || req.ip || 'unknown';


        const aidaPath = process.env.AIDA_BINARY_PATH || '/opt/aida/bin/AiDA.exe';
        if (!fs.existsSync(aidaPath)) {
            return res.status(503).json({ status: 'error', reason: 'binary_unavailable' });
        }


        const rawBinary = fs.readFileSync(aidaPath);


        if (rawBinary.length < 2 || rawBinary[0] !== 0x4D || rawBinary[1] !== 0x5A) {
            console.error('[download] AiDA binary does not have valid MZ header');
            return res.status(503).json({ status: 'error', reason: 'binary_corrupt' });
        }


        const watermarked = watermarkBinary(
            rawBinary,
            session.license_key,
            session.hwid,
            clientIp
        );


        const now = Math.floor(Date.now() / 1000);
        await pool.query(`
            INSERT INTO downloads (hwid, ip, license_key, artifact, user_agent)
            VALUES ($1, $2, $3, 'aida', $4)
        `, [session.hwid, clientIp, session.license_key, req.headers['user-agent'] || '']);


        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="AiDA_${timestamp}.exe"`);
        res.setHeader('Content-Length', watermarked.length);
        res.setHeader('X-Download-Timestamp', String(now));
        res.end(watermarked);
    } catch (err) {
        console.error('[download] AiDA download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

// ── Paged ARC download ─────────────────────────────────────────────
router.post('/arc/page/:index', async (req, res) => {
    try {
        const pageIndex = parseInt(req.params.index, 10);
        if (isNaN(pageIndex) || pageIndex < 0) {
            return res.status(400).json({ status: 'error', reason: 'invalid_page_index' });
        }

        const { license_key, session_token, hwid } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;

        let arcBlob;
        try {
            arcBlob = loadArcBlob();
        } catch (err) {
            console.error('[arc-page] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const totalPages = getPageCount(arcBlob.length);
        if (pageIndex >= totalPages) {
            return res.status(404).json({ status: 'error', reason: 'page_out_of_range', total_pages: totalPages });
        }

        const pages = splitIntoPages(arcBlob);
        const { encrypted, iv, authTag, hmac } = encryptPage(
            pages[pageIndex],
            pageIndex,
            session.session_token,
            hwid,
            session.issued_at
        );

        return res.json({
            status: 'ok',
            page_index: pageIndex,
            total_pages: totalPages,
            blob_size: arcBlob.length,
            data: encrypted.toString('base64'),
            iv: iv.toString('hex'),
            auth_tag: authTag.toString('hex'),
            hmac: hmac,
        });
    } catch (err) {
        console.error('[arc-page] Page download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

// Page count metadata (lightweight, no blob data)
router.post('/arc/pages', async (req, res) => {
    try {
        const { license_key, session_token, hwid } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        let arcBlob;
        try {
            arcBlob = loadArcBlob();
        } catch (err) {
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        return res.json({
            status: 'ok',
            total_pages: getPageCount(arcBlob.length),
            page_size: 4096,
            blob_size: arcBlob.length,
        });
    } catch (err) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
