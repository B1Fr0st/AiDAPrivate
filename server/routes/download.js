

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { encryptArc, encryptArcFull, encryptPage, splitIntoPages, getPageCount, deriveChainTag } = require('../crypto/arc-encrypt');
const { signPayload } = require('../crypto/signing');
const arcLicenseBind = require('../crypto/arc-license-bind');

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


const TRANSFORMED_BLOB_TTL_MS = 30 * 60 * 1000;
const transformedArcBlobCache = new Map();

function getTransformedArcBlob(sessionRow, licenseRow) {
    if (!sessionRow || typeof sessionRow.session_token !== 'string' || sessionRow.session_token.length === 0) {
        throw new Error('arc_transform_missing_session_token');
    }
    const sessionToken = sessionRow.session_token;
    const now = Date.now();
    const cached = transformedArcBlobCache.get(sessionToken);
    if (cached && cached.blob && (now - cached.ts) < TRANSFORMED_BLOB_TTL_MS) {
        cached.ts = now;
        return cached.blob;
    }
    const baseBlob = loadArcBlob();
    const transformed = arcLicenseBind.applyLicenseTransform(baseBlob, licenseRow, sessionRow);
    transformedArcBlobCache.set(sessionToken, { blob: transformed, ts: now });
    return transformed;
}

function evictTransformedArcBlob(sessionToken) {
    if (!sessionToken || typeof sessionToken !== 'string') return;
    transformedArcBlobCache.delete(sessionToken);
}

function purgeExpiredTransformedBlobs() {
    const now = Date.now();
    for (const [token, entry] of transformedArcBlobCache) {
        if (!entry || !entry.blob || (now - entry.ts) >= TRANSFORMED_BLOB_TTL_MS) {
            transformedArcBlobCache.delete(token);
        }
    }
}

setInterval(purgeExpiredTransformedBlobs, 5 * 60 * 1000).unref();


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
    const graceFactor = parseFloat(process.env.SESSION_TTL_GRACE_FACTOR || '1.1') || 1.1;
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * graceFactor);
        if (now > expiresAt) {
            evictTransformedArcBlob(session.session_token);
            return { valid: false, reason: 'session_expired' };
        }
    }

    if (session.kill_flag) {
        evictTransformedArcBlob(session.session_token);
    }

    return { valid: true, session, license };
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
        const license = validation.license;


        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            console.error('[arc] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        arcBlob = watermarkBinary(arcBlob, license_key, hwid, clientIp);


        const { encrypted, iv, authTag, hash } = encryptArcFull(
            arcBlob,
            license,
            session
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


    const ipHash = crypto.createHash('sha256').update(clientIp).digest();
    ipHash.copy(block, 176, 0, 16);


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


router.post('/arc/page/:index', async (req, res) => {
    try {
        const pageIndex = parseInt(req.params.index, 10);
        if (isNaN(pageIndex) || pageIndex < 0) {
            return res.status(400).json({ status: 'error', reason: 'invalid_page_index' });
        }

        const { license_key, session_token, hwid, proof_token } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;
        const license = validation.license;

        if (session.kill_flag) {
            return res.status(403).json({ status: 'error', reason: 'killed' });
        }

        const lastProof = session.last_proof_token || '';
        const clientProof = proof_token || '';
        if (!clientProof || (lastProof && clientProof !== lastProof)) {
            return res.status(403).json({ status: 'error', reason: 'stale_proof_token' });
        }

        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            console.error('[arc-page] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const totalPages = getPageCount(arcBlob.length);
        if (pageIndex >= totalPages) {
            return res.status(404).json({ status: 'error', reason: 'page_out_of_range', total_pages: totalPages });
        }

        const pages = splitIntoPages(arcBlob);
        const prevChainTag = pageIndex === 0 ? '' : (session.last_chain_tag || '');
        if (pageIndex > 0 && !prevChainTag) {
            return res.status(403).json({ status: 'error', reason: 'out_of_order_page' });
        }
        const { encrypted, iv, authTag, hmac } = encryptPage(
            pages[pageIndex],
            pageIndex,
            session.session_token,
            hwid,
            session.issued_at,
            clientProof,
            prevChainTag
        );
        const nextChainTag = deriveChainTag(prevChainTag, authTag).toString('hex');
        await pool.query(
            'UPDATE sessions SET last_chain_tag = $1 WHERE license_key = $2',
            [nextChainTag, license_key]
        );

        const pageTrailer = buildPageWatermark(license_key, hwid, pageIndex, session.session_token);

        const pagePayload = {
            status: 'ok',
            page_index: pageIndex,
            total_pages: totalPages,
            blob_size: arcBlob.length,
            data: encrypted.toString('base64'),
            iv: iv.toString('hex'),
            auth_tag: authTag.toString('hex'),
            hmac: hmac.toString('hex'),
            page_trailer: pageTrailer.toString('hex'),
        };
        pagePayload.signature = signPayload(pagePayload);

        return res.json(pagePayload);
    } catch (err) {
        console.error('[arc-page] Page download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


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

router.post('/arc/pages/bulk', async (req, res) => {
    try {
        const { license_key, session_token, hwid, proof_token } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;
        const license = validation.license;

        if (session.kill_flag) {
            return res.status(403).json({ status: 'error', reason: 'killed' });
        }

        const lastProof = session.last_proof_token || '';
        const clientProof = proof_token || '';
        if (!clientProof || (lastProof && clientProof !== lastProof)) {
            return res.status(403).json({ status: 'error', reason: 'stale_proof_token' });
        }

        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            console.error('[arc-bulk] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const rawPages = splitIntoPages(arcBlob);
        const totalPages = rawPages.length;
        let prevChainTag = '';
        const pages = [];
        const digest = crypto.createHash('sha256');

        for (let pageIndex = 0; pageIndex < rawPages.length; pageIndex++) {
            const { encrypted, iv, authTag, hmac } = encryptPage(
                rawPages[pageIndex],
                pageIndex,
                session.session_token,
                hwid,
                session.issued_at,
                clientProof,
                prevChainTag
            );
            const nextChainTag = deriveChainTag(prevChainTag, authTag).toString('hex');
            const pagePayload = {
                status: 'ok',
                page_index: pageIndex,
                total_pages: totalPages,
                blob_size: arcBlob.length,
                data: encrypted.toString('base64'),
                iv: iv.toString('hex'),
                auth_tag: authTag.toString('hex'),
                hmac: hmac.toString('hex'),
                page_trailer: buildPageWatermark(license_key, hwid, pageIndex, session.session_token).toString('hex'),
            };
            digest.update(String(pagePayload.page_index));
            digest.update('|');
            digest.update(pagePayload.data);
            digest.update('|');
            digest.update(pagePayload.iv);
            digest.update('|');
            digest.update(pagePayload.auth_tag);
            digest.update('|');
            digest.update(pagePayload.hmac);
            digest.update('|');
            digest.update(pagePayload.page_trailer);
            digest.update('\n');
            pages.push(pagePayload);
            prevChainTag = nextChainTag;
        }

        await pool.query(
            'UPDATE sessions SET last_chain_tag = $1 WHERE license_key = $2',
            [prevChainTag, license_key]
        );

        const signedPayload = {
            status: 'ok',
            total_pages: totalPages,
            page_size: 4096,
            blob_size: arcBlob.length,
            pages_digest: digest.digest('hex'),
        };

        return res.json({
            ...signedPayload,
            pages,
            signature: signPayload(signedPayload),
        });
    } catch (err) {
        console.error('[arc-bulk] Bulk page download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

function buildPageWatermark(licenseKey, hwid, pageIndex, sessionToken) {
    const masterSecret = process.env.ARC_MASTER_SECRET || '';
    const trailer = Buffer.alloc(64, 0);
    trailer.writeUInt32BE(0xA1DA0002, 0);
    trailer.writeUInt32BE(pageIndex >>> 0, 4);
    const identity = crypto.createHmac('sha256', masterSecret)
        .update(`${licenseKey}|${hwid}|${pageIndex}|${sessionToken}`)
        .digest();
    identity.copy(trailer, 8, 0, 24);
    const integrity = crypto.createHmac('sha256', masterSecret)
        .update(trailer.subarray(0, 32))
        .digest();
    integrity.copy(trailer, 32, 0, 32);
    return trailer;
}

router.post('/pages/count', async (req, res) => {
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
            console.error('[pages] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const totalPages = getPageCount(arcBlob.length);

        return res.json({
            status: 'ok',
            total_pages: totalPages,
            page_size: 4096,
            blob_size: arcBlob.length,
        });
    } catch (err) {
        console.error('[pages] Count error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/pages/:index', async (req, res) => {
    try {
        const pageIndex = parseInt(req.params.index, 10);
        if (isNaN(pageIndex) || pageIndex < 0) {
            return res.status(400).json({ status: 'error', reason: 'invalid_page_index' });
        }

        const { license_key, session_token, hwid, proof_token } = req.body || {};

        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;
        const license = validation.license;
        if (session.kill_flag) {
            return res.status(403).json({ status: 'error', reason: 'killed' });
        }

        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            console.error('[pages] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const totalPages = getPageCount(arcBlob.length);
        if (pageIndex >= totalPages) {
            return res.status(400).json({ status: 'error', reason: 'page_out_of_range' });
        }

        const prevChainTag = pageIndex === 0 ? '' : (session.last_chain_tag || '');
        if (pageIndex > 0 && !prevChainTag) {
            return res.status(403).json({ status: 'error', reason: 'out_of_order_page' });
        }

        const pages = splitIntoPages(arcBlob);
        const pageData = pages[pageIndex];

        const { encrypted, iv, authTag, hmac } = encryptPage(
            pageData,
            pageIndex,
            session.session_token,
            hwid,
            session.issued_at,
            proof_token || '',
            prevChainTag
        );
        const nextChainTag = deriveChainTag(prevChainTag, authTag).toString('hex');
        await pool.query(
            'UPDATE sessions SET last_chain_tag = $1 WHERE license_key = $2',
            [nextChainTag, license_key]
        );

        const pageTrailer = buildPageWatermark(license_key, hwid, pageIndex, session.session_token);

        return res.json({
            status: 'ok',
            page_index: pageIndex,
            total_pages: totalPages,
            encrypted_page: encrypted.toString('base64'),
            iv: iv.toString('hex'),
            auth_tag: authTag.toString('hex'),
            hmac: hmac.toString('hex'),
            page_trailer: pageTrailer.toString('hex'),
            page_size: pageData.length,
        });
    } catch (err) {
        console.error('[pages] Page download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


const ROTATION_INTERVAL_SECONDS = parseInt(process.env.ROTATION_INTERVAL_SECONDS || '600', 10);
const ROTATION_EXPIRY_SECONDS = ROTATION_INTERVAL_SECONDS * 3;

async function getOrCreateRotationEpoch(sessionToken, hwid) {
    const now = Math.floor(Date.now() / 1000);
    const { rows } = await pool.query(
        `SELECT * FROM page_rotations WHERE session_token = $1 AND expires_at > $2
         ORDER BY epoch DESC LIMIT 1`,
        [sessionToken, now]
    );
    if (rows.length > 0) return rows[0];

    const epoch = now;
    const rotationNonce = crypto.randomBytes(16).toString('hex');
    const rotationKey = crypto.createHmac('sha256', process.env.ARC_MASTER_SECRET || '')
        .update(`${rotationNonce}|${sessionToken}|${hwid}`)
        .digest('hex');
    const expiresAt = now + ROTATION_EXPIRY_SECONDS;
    await pool.query(
        `INSERT INTO page_rotations (session_token, epoch, rotation_nonce, rotation_key, rotated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (session_token, epoch) DO NOTHING`,
        [sessionToken, epoch, rotationNonce, rotationKey, now, expiresAt]
    );
    return { session_token: sessionToken, epoch, rotation_nonce: rotationNonce, rotation_key: rotationKey, rotated_at: now, expires_at: expiresAt };
}

async function purgeExpiredRotations() {
    const now = Math.floor(Date.now() / 1000);
    try {
        await pool.query('DELETE FROM page_rotations WHERE expires_at < $1', [now]);
    } catch (_) { }
}
setInterval(purgeExpiredRotations, 5 * 60 * 1000).unref();

router.post('/pages/rotate', async (req, res) => {
    try {
        const { license_key, session_token, hwid, client_epoch } = req.body || {};

        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const session = validation.session;
        const rot = await getOrCreateRotationEpoch(session.session_token, hwid);
        const stale = !client_epoch || client_epoch < rot.epoch;

        await pool.query(
            `UPDATE sessions SET last_heartbeat = $1 WHERE license_key = $2`,
            [Math.floor(Date.now() / 1000), license_key]
        );

        let arcBlob;
        try {
            arcBlob = loadArcBlob();
        } catch (err) {
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        return res.json({
            status: 'ok',
            rotation_epoch: Number(rot.epoch),
            rotation_key: rot.rotation_key,
            rotation_nonce: rot.rotation_nonce,
            stale: stale,
            total_pages: getPageCount(arcBlob.length),
            page_size: 4096,
        });
    } catch (err) {
        console.error('[rotation] Error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


router.post('/pages/rotated/:index', async (req, res) => {
    try {
        const pageIndex = parseInt(req.params.index, 10);
        if (isNaN(pageIndex) || pageIndex < 0) {
            return res.status(400).json({ status: 'error', reason: 'invalid_page_index' });
        }

        const { license_key, session_token, hwid, rotation_epoch, rotation_key, proof_token } = req.body || {};

        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        if (!rotation_epoch || !rotation_key) {
            return res.status(403).json({ status: 'error', reason: 'missing_rotation' });
        }

        const now = Math.floor(Date.now() / 1000);
        const { rows: rotRows } = await pool.query(
            `SELECT * FROM page_rotations
             WHERE session_token = $1 AND epoch = $2 AND expires_at > $3`,
            [session_token, rotation_epoch, now]
        );
        if (rotRows.length === 0) {
            return res.status(403).json({ status: 'error', reason: 'stale_epoch' });
        }
        const rot = rotRows[0];
        const expectedBuf = Buffer.from(rot.rotation_key, 'utf8');
        const providedBuf = Buffer.from(String(rotation_key), 'utf8');
        if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
            return res.status(403).json({ status: 'error', reason: 'rotation_key_mismatch' });
        }

        const session = validation.session;
        const license = validation.license;

        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        const totalPages = getPageCount(arcBlob.length);
        if (pageIndex >= totalPages) {
            return res.status(400).json({ status: 'error', reason: 'page_out_of_range' });
        }

        const prevChainTag = pageIndex === 0 ? '' : (session.last_chain_tag || '');
        if (pageIndex > 0 && !prevChainTag) {
            return res.status(403).json({ status: 'error', reason: 'out_of_order_page' });
        }

        const pages = splitIntoPages(arcBlob);
        const pageData = pages[pageIndex];
        const rotatedIssuedAt = Number(rot.epoch);
        const rotatedSession = Object.assign({}, session, { issued_at: rotatedIssuedAt });

        const { encrypted, iv, authTag, hmac } = encryptPage(
            pageData,
            pageIndex,
            rotatedSession.session_token,
            hwid,
            rotatedSession.issued_at,
            proof_token || '',
            prevChainTag
        );
        const nextChainTag = deriveChainTag(prevChainTag, authTag).toString('hex');
        await pool.query(
            'UPDATE sessions SET last_chain_tag = $1 WHERE license_key = $2',
            [nextChainTag, license_key]
        );

        const pageTrailer = buildPageWatermark(license_key, hwid, pageIndex, session.session_token);

        return res.json({
            status: 'ok',
            page_index: pageIndex,
            total_pages: totalPages,
            rotation_epoch: rotatedIssuedAt,
            encrypted_page: encrypted.toString('base64'),
            iv: iv.toString('hex'),
            auth_tag: authTag.toString('hex'),
            hmac: hmac.toString('hex'),
            page_trailer: pageTrailer.toString('hex'),
            page_size: pageData.length,
        });
    } catch (err) {
        console.error('[rotation] Page download error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
