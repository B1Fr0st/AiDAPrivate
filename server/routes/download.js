// ============================================================================
// AiDA License Server — ARC Download Route
// ============================================================================
// Serves the AiDA Runtime Core (ARC) DLL encrypted per-session.
//
// POST /api/download/arc
//   - Validates session_token + license_key + hwid (same checks as heartbeat)
//   - Reads ARC blob from server filesystem (pre-encrypted at rest)
//   - Re-encrypts with session-specific AES-256-GCM key
//   - Returns { encrypted_blob, iv, auth_tag, blob_hash }
//   - Logs download to `downloads` table
//
// The ARC blob file should be placed on the server at:
//   /opt/aida/arc/aida_core.bin  (raw DLL bytes, encrypted at rest with ARC_MASTER_SECRET)
//
// To prepare the file on the server:
//   node scripts/encrypt-arc.js path/to/aida_core.dll /opt/aida/arc/aida_core.bin
// ============================================================================

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { encryptArc } = require('../crypto/arc-encrypt');

const router = express.Router();

// Path to the ARC blob on the server filesystem
const ARC_BLOB_PATH = process.env.ARC_BLOB_PATH || '/opt/aida/arc/aida_core.bin';

// Cache the decrypted ARC blob in memory to avoid repeated disk reads.
// It's small (~50-150KB) so memory impact is negligible.
let cachedArcBlob = null;

/**
 * Load and decrypt the ARC blob from disk.
 * The file on disk is AES-256-GCM encrypted with ARC_MASTER_SECRET.
 * Format: [12 bytes IV][16 bytes auth tag][encrypted data]
 */
function loadArcBlob() {
    if (cachedArcBlob) return cachedArcBlob;

    if (!fs.existsSync(ARC_BLOB_PATH)) {
        throw new Error(`ARC blob not found at ${ARC_BLOB_PATH}`);
    }

    const raw = fs.readFileSync(ARC_BLOB_PATH);

    // File format: IV (12) + AuthTag (16) + Ciphertext
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

    // Derive the at-rest encryption key from master secret
    const atRestKey = crypto.createHash('sha256')
        .update(`arc-at-rest|${masterSecret}`)
        .digest();

    const decipher = crypto.createDecipheriv('aes-256-gcm', atRestKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);

    // Validate PE signature (MZ header)
    if (decrypted.length < 2 || decrypted[0] !== 0x4D || decrypted[1] !== 0x5A) {
        throw new Error('Decrypted ARC blob does not have valid MZ header');
    }

    cachedArcBlob = decrypted;
    console.log(`[arc] Loaded ARC blob: ${decrypted.length} bytes`);
    return cachedArcBlob;
}

/**
 * Validate a session for ARC download (same checks as heartbeat).
 */
async function validateSession(licenseKey, sessionToken, hwid) {
    if (!licenseKey || !sessionToken || !hwid) {
        return { valid: false, reason: 'missing_fields' };
    }

    // Ban check
    const banResult = await pool.query(
        'SELECT 1 FROM bans WHERE (ban_type = $1 AND value = $2) LIMIT 1',
        ['hwid', hwid]
    );
    if (banResult.rows.length > 0) {
        return { valid: false, reason: 'banned' };
    }

    // License check
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

    // Session check
    const { rows: sesRows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (sesRows.length === 0 || sesRows[0].session_token !== sessionToken) {
        return { valid: false, reason: 'session_mismatch' };
    }

    const session = sesRows[0];

    // HWID consistency
    if (session.hwid && session.hwid !== hwid) {
        return { valid: false, reason: 'hwid_mismatch' };
    }

    // Session TTL with 1.5x grace
    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * 1.5);
        if (now > expiresAt) {
            return { valid: false, reason: 'session_expired' };
        }
    }

    return { valid: true, session };
}

// ─── POST /arc — Session-encrypted ARC delivery ────────────────────────────

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

        // Load ARC blob (cached in memory)
        let arcBlob;
        try {
            arcBlob = loadArcBlob();
        } catch (err) {
            console.error('[arc] Failed to load ARC blob:', err.message);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }

        // Encrypt with session-specific key
        const { encrypted, iv, authTag, hash } = encryptArc(
            arcBlob,
            session.session_token,
            hwid,
            session.issued_at
        );

        // Log download
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

// ─── PE Watermarking ────────────────────────────────────────────────────────
// Appends a unique, encrypted watermark to the PE overlay (after the last
// section's raw data). This region is ignored by the Windows PE loader so
// execution is unaffected, but every distributed binary carries a traceable
// fingerprint tied to the license holder and download timestamp.

/**
 * Build a 256-byte watermark block and append it to a PE buffer.
 *
 * Layout (256 bytes total):
 *   [0..3]    magic   0xA1DA0001 (big-endian)
 *   [4..7]    version 0x00000001
 *   [8..15]   timestamp (uint64 LE, unix epoch seconds)
 *   [16..47]  HMAC-SHA256 of (license_key | hwid | timestamp)
 *   [48..79]  SHA-256 of original binary (pre-watermark)
 *   [80..143] license_key hash (SHA-512 truncated to 64 bytes)
 *   [144..175] hwid hash (SHA-256)
 *   [176..191] client IP hash (MD5, for correlation only)
 *   [192..223] HMAC-SHA256 integrity tag over bytes [0..191]
 *   [224..255] random padding
 *
 * The entire 256-byte block is then XOR-encrypted with a key derived from
 * ARC_MASTER_SECRET so raw byte scanning cannot extract the fields.
 *
 * @param {Buffer} peBuffer   - Original PE binary
 * @param {string} licenseKey - License key string
 * @param {string} hwid       - Client hardware ID
 * @param {string} clientIp   - Client IP address
 * @returns {Buffer} PE binary with watermark appended
 */
function watermarkBinary(peBuffer, licenseKey, hwid, clientIp) {
    const masterSecret = process.env.ARC_MASTER_SECRET || '';

    const now = Math.floor(Date.now() / 1000);
    const block = Buffer.alloc(256, 0);

    // Magic + version
    block.writeUInt32BE(0xA1DA0001, 0);
    block.writeUInt32BE(0x00000001, 4);

    // Timestamp (LE uint64)
    block.writeBigUInt64LE(BigInt(now), 8);

    // HMAC-SHA256 of identity binding
    const identityHmac = crypto.createHmac('sha256', masterSecret)
        .update(`${licenseKey}|${hwid}|${now}`)
        .digest();
    identityHmac.copy(block, 16);

    // SHA-256 of original binary
    const binaryHash = crypto.createHash('sha256').update(peBuffer).digest();
    binaryHash.copy(block, 48);

    // License key hash (SHA-512 → 64 bytes)
    const keyHash = crypto.createHash('sha512').update(licenseKey).digest();
    keyHash.copy(block, 80);

    // HWID hash (SHA-256 → 32 bytes)
    const hwidHash = crypto.createHash('sha256').update(hwid).digest();
    hwidHash.copy(block, 144);

    // Client IP hash (MD5 → 16 bytes, correlation only)
    const ipHash = crypto.createHash('md5').update(clientIp).digest();
    ipHash.copy(block, 176);

    // Integrity HMAC over [0..191]
    const integrityHmac = crypto.createHmac('sha256', masterSecret)
        .update(block.subarray(0, 192))
        .digest();
    integrityHmac.copy(block, 192);

    // Random padding [224..255]
    crypto.randomBytes(32).copy(block, 224);

    // XOR-encrypt the entire block with a derived stream key
    const streamKey = crypto.createHash('sha256')
        .update(`watermark-stream|${masterSecret}`)
        .digest();
    for (let i = 0; i < 256; i++) {
        block[i] ^= streamKey[i % 32];
    }

    return Buffer.concat([peBuffer, block]);
}

// ─── GET /aida — Authenticated, watermarked AiDA binary download ───────────

router.get('/aida', async (req, res) => {
    try {
        const sessionToken = req.headers['authorization'] || '';
        if (!sessionToken || sessionToken.length < 32) {
            return res.status(401).json({ status: 'error', reason: 'unauthorized' });
        }

        // Find session by token
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

        // Check if binary exists
        const aidaPath = process.env.AIDA_BINARY_PATH || '/opt/aida/bin/AiDA.exe';
        if (!fs.existsSync(aidaPath)) {
            return res.status(503).json({ status: 'error', reason: 'binary_unavailable' });
        }

        // Read the full binary into memory for watermarking
        const rawBinary = fs.readFileSync(aidaPath);

        // Validate PE signature
        if (rawBinary.length < 2 || rawBinary[0] !== 0x4D || rawBinary[1] !== 0x5A) {
            console.error('[download] AiDA binary does not have valid MZ header');
            return res.status(503).json({ status: 'error', reason: 'binary_corrupt' });
        }

        // Apply per-user watermark (appended to PE overlay — does not affect execution)
        const watermarked = watermarkBinary(
            rawBinary,
            session.license_key,
            session.hwid,
            clientIp
        );

        // Log download
        const now = Math.floor(Date.now() / 1000);
        await pool.query(`
            INSERT INTO downloads (hwid, ip, license_key, artifact, user_agent)
            VALUES ($1, $2, $3, 'aida', $4)
        `, [session.hwid, clientIp, session.license_key, req.headers['user-agent'] || '']);

        // Send watermarked binary
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

module.exports = router;
