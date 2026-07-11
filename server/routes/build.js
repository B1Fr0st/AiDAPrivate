'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const botAuth = require('../middleware/bot_auth');
const killSwitch = require('../middleware/kill_switch');
const buildQueue = require('../workers/build_queue');
const customerDownload = require('./customer_download');

const router = express.Router();

const CUSTOMER_ROLE_ID = customerDownload._internal.CUSTOMER_ROLE_ID;
const EAUTH_BODY = { status: 'error', reason: 'EAUTH' };
const PACKED_MAGIC = 0x41504B44;
const TEMPLATE_GRACE_SECONDS = 30 * 24 * 60 * 60;
const MAX_QUEUE_DEPTH = 10;
const BUILD_RATE_LIMIT_PER_HOUR = parseInt(process.env.AIDA_BUILD_RATE_LIMIT_PER_HOUR || '3', 10);
const STRICT_TEMPLATE_VERSION = process.env.AIDA_STRICT_TEMPLATE_VERSION === '1';
const BUILD_TIMEOUT_SECONDS = parseInt(process.env.AIDA_BUILD_TIMEOUT_SECONDS || '60', 10);
const ADAPTIVE_EXTENSION_SECONDS = parseInt(process.env.AIDA_BUILD_ADAPTIVE_EXTENSION_SECONDS || '30', 10);

const TEMPLATE_DIR = process.env.AIDA_TEMPLATE_DIR || '/var/aida/templates';
const OUTPUT_DIR = process.env.AIDA_OUTPUT_DIR || '/var/aida/output';
const MIN_TEMPLATE_SIZE = 1024 * 1024;
const MAX_TEMPLATE_SIZE = 200 * 1024 * 1024;

let s_schemaPromise = null;

function nowSec() {
    return Math.floor(Date.now() / 1000);
}

function noStore(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
}

function getClientIp(req) {
    return (req && (req.ip || (req.socket && req.socket.remoteAddress))) || '';
}

function isHexNonce(value) {
    return typeof value === 'string' && /^[0-9a-f]{32,128}$/i.test(value.trim());
}

function parseDiscordId(value) {
    return customerDownload._internal.parseDiscordId(value);
}

function isValidBuildId(value) {
    return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim());
}

async function ensureSchema() {
    if (!s_schemaPromise) {
        s_schemaPromise = (async () => {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS build_templates (
                    id              SERIAL      PRIMARY KEY,
                    version         INTEGER     NOT NULL UNIQUE,
                    filename        TEXT        NOT NULL,
                    file_path       TEXT        NOT NULL,
                    file_sha256     TEXT        NOT NULL,
                    file_size       BIGINT      NOT NULL,
                    metadata_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,
                    uploaded_at     BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
                    uploaded_by     TEXT        NOT NULL DEFAULT '',
                    active          BOOLEAN     NOT NULL DEFAULT false,
                    activated_at    BIGINT,
                    archived_at     BIGINT,
                    CHECK (active = true OR archived_at IS NOT NULL)
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_build_templates_active ON build_templates (active) WHERE active = true');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_build_templates_uploaded ON build_templates (uploaded_at DESC)');
            await pool.query(`
                CREATE TABLE IF NOT EXISTS customer_watermarks (
                    watermark_id     TEXT        PRIMARY KEY,
                    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
                    discord_id       TEXT        NOT NULL DEFAULT '',
                    assigned_at      BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
                    template_version INTEGER     NOT NULL DEFAULT 0
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_customer_watermarks_license ON customer_watermarks (license_key)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_customer_watermarks_discord ON customer_watermarks (discord_id)');
            await pool.query(`
                CREATE TABLE IF NOT EXISTS build_requests (
                    build_id         TEXT        PRIMARY KEY,
                    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
                    discord_id       TEXT        NOT NULL DEFAULT '',
                    template_version INTEGER     NOT NULL,
                    watermark_id     TEXT        NOT NULL REFERENCES customer_watermarks(watermark_id) ON DELETE CASCADE,
                    status           TEXT        NOT NULL DEFAULT 'queued'
                                     CHECK (status IN ('queued', 'building', 'ready', 'failed', 'expired')),
                    output_filename  TEXT        NOT NULL DEFAULT '',
                    output_sha256    TEXT        NOT NULL DEFAULT '',
                    output_size      BIGINT      NOT NULL DEFAULT 0,
                    requested_at     BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
                    started_at       BIGINT,
                    completed_at     BIGINT,
                    error_message    TEXT        NOT NULL DEFAULT '',
                    downloaded_at    BIGINT,
                    download_count   INTEGER     NOT NULL DEFAULT 0,
                    progress_pct     INTEGER     NOT NULL DEFAULT 0
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_build_requests_license ON build_requests (license_key, requested_at DESC)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_build_requests_discord ON build_requests (discord_id, requested_at DESC)');
            await pool.query(`CREATE INDEX IF NOT EXISTS idx_build_requests_status ON build_requests (status) WHERE status IN ('queued', 'building')`);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_build_requests_requested ON build_requests (requested_at DESC)');
        })();
    }
    return s_schemaPromise;
}

async function storeBotNonce(body, action) {
    return customerDownload._internal.storeBotNonce(body, action);
}

async function lookupSingleLicense(discordId, at) {
    return customerDownload._internal.lookupSingleLicense(discordId, at);
}

function isUsableLicense(row, at) {
    return customerDownload._internal.isUsableLicense(row, at);
}

async function resolveTemplateVersion(requestedVersion) {
    if (requestedVersion && Number.isInteger(requestedVersion) && requestedVersion > 0) {
        const { rows } = await pool.query(
            `SELECT * FROM build_templates
              WHERE version = $1
                AND (archived_at IS NULL OR archived_at > (EXTRACT(EPOCH FROM now())::BIGINT - $2))`,
            [requestedVersion, TEMPLATE_GRACE_SECONDS]
        );
        if (rows.length === 0) return { ok: false, reason: 'version_not_available' };
        return { ok: true, template: rows[0] };
    }
    const { rows } = await pool.query(
        'SELECT * FROM build_templates WHERE active = true ORDER BY version DESC LIMIT 1'
    );
    if (rows.length === 0) return { ok: false, reason: 'no_active_template' };
    return { ok: true, template: rows[0] };
}

async function assignWatermark(licenseKey, discordId, templateVersion) {
    const { rows } = await pool.query(
        'SELECT watermark_id FROM customer_watermarks WHERE license_key = $1 OR discord_id = $2 LIMIT 1',
        [licenseKey, discordId]
    );
    if (rows.length > 0) {
        return { ok: true, watermarkId: rows[0].watermark_id, reused: true };
    }
    for (let attempt = 0; attempt < 3; attempt++) {
        const uuid = crypto.randomUUID();
        const { rows: collision } = await pool.query(
            'SELECT 1 FROM customer_watermarks WHERE watermark_id = $1',
            [uuid]
        );
        if (collision.length > 0) continue;
        await pool.query(
            `INSERT INTO customer_watermarks (watermark_id, license_key, discord_id, template_version)
             VALUES ($1, $2, $3, $4)`,
            [uuid, licenseKey, discordId, templateVersion]
        );
        return { ok: true, watermarkId: uuid, reused: false };
    }
    return { ok: false, reason: 'watermark_collision_unresolved' };
}

async function checkQueueDepth() {
    const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS depth FROM build_requests WHERE status IN ('queued', 'building')`
    );
    return rows.length > 0 ? rows[0].depth : 0;
}

async function checkUserRateLimit(discordId) {
    const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS cnt
           FROM build_requests
          WHERE discord_id = $1
            AND requested_at > (EXTRACT(EPOCH FROM now())::BIGINT - 3600)`,
        [discordId]
    );
    return rows.length > 0 ? rows[0].cnt : 0;
}

function parsePeSections(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 0x100) return [];
    if (buf.readUInt16LE(0) !== 0x5A4D) return [];
    const peOff = buf.readUInt32LE(0x3c);
    if (!Number.isInteger(peOff) || peOff <= 0 || peOff + 0x18 > buf.length) return [];
    if (buf.readUInt32LE(peOff) !== 0x00004550) return [];
    const sectionCount = buf.readUInt16LE(peOff + 6);
    const optionalSize = buf.readUInt16LE(peOff + 20);
    const sectionTable = peOff + 24 + optionalSize;
    if (sectionCount <= 0 || sectionCount > 96 || sectionTable <= 0 || sectionTable + sectionCount * 40 > buf.length) return [];
    const sections = [];
    for (let i = 0; i < sectionCount; ++i) {
        const off = sectionTable + i * 40;
        const rawSize = buf.readUInt32LE(off + 16);
        const rawPtr = buf.readUInt32LE(off + 20);
        if (rawPtr > 0 && rawSize > 0 && rawPtr < buf.length) {
            sections.push({
                raw_ptr: rawPtr,
                raw_size: Math.min(rawSize, buf.length - rawPtr),
            });
        }
    }
    return sections;
}

function checkPackedMagic(filePath) {
    try {
        const st = fs.statSync(filePath);
        const headerSize = Math.min(4096, st.size);
        const fd = fs.openSync(filePath, 'r');
        try {
            const buf = Buffer.alloc(headerSize);
            fs.readSync(fd, buf, 0, headerSize, 0);
            const sections = parsePeSections(buf);
            for (const section of sections) {
                if (section.raw_size >= 4 && section.raw_ptr + 4 <= buf.length) {
                    if (buf.readUInt32LE(section.raw_ptr) === PACKED_MAGIC) return true;
                }
            }
        } finally {
            fs.closeSync(fd);
        }
    } catch (_) {
    }
    return false;
}

function sha256File(filePath) {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(filePath, 'r');
    try {
        const buf = Buffer.alloc(1024 * 1024);
        let pos = 0;
        while (true) {
            const bytesRead = fs.readSync(fd, buf, 0, buf.length, pos);
            if (bytesRead === 0) break;
            hash.update(buf.subarray(0, bytesRead));
            pos += bytesRead;
        }
    } finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}

function computeTestVector() {
    const masterKeyB64 = String(process.env.AIDA_BUILD_MASTER_KEY_B64 || process.env.SERVER_MASTER_KEY_B64 || '').trim();
    if (!masterKeyB64) return null;
    const masterKey = Buffer.from(masterKeyB64, 'base64');
    if (masterKey.length !== 32) return null;
    const salt = Buffer.from('test_vector', 'utf8');
    const info = Buffer.alloc(0);
    const derived = crypto.hkdfSync('sha256', masterKey, salt, info, 32);
    return Buffer.from(derived).toString('hex');
}

async function buildRequest(req) {
    await ensureSchema();
    const verify = botAuth.verifyBotRequest(req);
    if (!verify.ok) return { status: 403, body: EAUTH_BODY };
    const body = req.body || {};
    if (String(body.action || '') !== 'build_request' || verify.action !== 'build_request') {
        return { status: 403, body: EAUTH_BODY };
    }
    if (String(body.customer_role_id || '') !== CUSTOMER_ROLE_ID) {
        return { status: 403, body: EAUTH_BODY };
    }
    if (!isHexNonce(body.nonce)) {
        return { status: 403, body: EAUTH_BODY };
    }
    const discordId = parseDiscordId(body.discord_id);
    if (!discordId) {
        return { status: 403, body: EAUTH_BODY };
    }
    try {
        await storeBotNonce(body, 'build_request');
    } catch (err) {
        if (err && err.code === '23505') {
            return { status: 403, body: EAUTH_BODY };
        }
        throw err;
    }
    const at = nowSec();
    const license = await lookupSingleLicense(discordId, at);
    if (!license.ok) {
        return { status: 403, body: EAUTH_BODY };
    }
    const userBuildCount = await checkUserRateLimit(discordId);
    if (userBuildCount >= BUILD_RATE_LIMIT_PER_HOUR) {
        return { status: 429, body: { status: 'error', reason: 'build_rate_limited' } };
    }
    const queueDepth = await checkQueueDepth();
    if (queueDepth >= MAX_QUEUE_DEPTH) {
        return { status: 503, body: { status: 'error', reason: 'queue_full' } };
    }
    const requestedVersion = (body.template_version === null || body.template_version === undefined)
        ? null
        : Number(body.template_version);
    const tmplResult = await resolveTemplateVersion(
        (requestedVersion && Number.isInteger(requestedVersion) && requestedVersion > 0) ? requestedVersion : null
    );
    if (!tmplResult.ok) {
        return { status: 400, body: { status: 'error', reason: tmplResult.reason } };
    }
    const templateVersion = tmplResult.template.version;
    const wmResult = await assignWatermark(license.row.key, discordId, templateVersion);
    if (!wmResult.ok) {
        return { status: 500, body: { status: 'error', reason: wmResult.reason } };
    }
    const buildId = crypto.randomUUID();
    await pool.query(
        `INSERT INTO build_requests
            (build_id, license_key, discord_id, template_version, watermark_id, status, requested_at)
         VALUES ($1, $2, $3, $4, $5, 'queued', $6)`,
        [buildId, license.row.key, discordId, templateVersion, wmResult.watermarkId, at]
    );
    buildQueue.enqueue(buildId);
    const estimatedSeconds = Math.max(3, (queueDepth + 1) * 3);
    return {
        status: 200,
        body: {
            status: 'ok',
            build_id: buildId,
            estimated_seconds: estimatedSeconds,
            template_version: templateVersion,
        },
    };
}

async function buildStatus(req) {
    await ensureSchema();
    const verify = botAuth.verifyBotRequest(req);
    if (!verify.ok) return { status: 403, body: EAUTH_BODY };
    const body = req.body || {};
    if (String(body.action || '') !== 'build_status' || verify.action !== 'build_status') {
        return { status: 403, body: EAUTH_BODY };
    }
    if (!isHexNonce(body.nonce)) {
        return { status: 403, body: EAUTH_BODY };
    }
    const discordId = parseDiscordId(body.discord_id);
    if (!discordId) {
        return { status: 403, body: EAUTH_BODY };
    }
    const buildId = String(body.build_id || '').trim();
    if (!isValidBuildId(buildId)) {
        return {
            status: 200,
            body: { status: 'queued', build_id: buildId, estimated_seconds: 999 },
        };
    }
    try {
        await storeBotNonce(body, 'build_status');
    } catch (err) {
        if (err && err.code === '23505') {
            return { status: 403, body: EAUTH_BODY };
        }
        throw err;
    }
    const { rows } = await pool.query(
        `SELECT status, output_filename, output_sha256, output_size, error_message,
                template_version, requested_at, completed_at, progress_pct, discord_id
           FROM build_requests
          WHERE build_id = $1`,
        [buildId]
    );
    if (rows.length === 0 || String(rows[0].discord_id || '') !== discordId) {
        return {
            status: 200,
            body: { status: 'queued', build_id: buildId, estimated_seconds: 999 },
        };
    }
    const row = rows[0];
    if (row.status === 'queued') {
        return {
            status: 200,
            body: {
                status: 'queued',
                build_id: buildId,
                requested_at: Number(row.requested_at || 0),
                estimated_seconds: Math.max(3, 3),
            },
        };
    }
    if (row.status === 'building') {
        return {
            status: 200,
            body: {
                status: 'building',
                build_id: buildId,
                estimated_seconds: 1,
                progress_pct: Number(row.progress_pct || 0),
            },
        };
    }
    if (row.status === 'ready') {
        return {
            status: 200,
            body: {
                status: 'ready',
                build_id: buildId,
                download_url: `/api/build/download/${buildId}`,
                output_sha256: String(row.output_sha256 || ''),
                output_size: Number(row.output_size || 0),
                template_version: Number(row.template_version || 0),
                completed_at: Number(row.completed_at || 0),
            },
        };
    }
    if (row.status === 'failed') {
        return {
            status: 200,
            body: {
                status: 'failed',
                build_id: buildId,
                error: String(row.error_message || 'unknown'),
                completed_at: Number(row.completed_at || 0),
            },
        };
    }
    return {
        status: 200,
        body: {
            status: 'expired',
            build_id: buildId,
            completed_at: Number(row.completed_at || 0),
        },
    };
}

async function buildDownload(req, res) {
    await ensureSchema();
    const verify = botAuth.verifyBotRequest(req);
    if (!verify.ok) {
        noStore(res);
        return res.status(403).json(EAUTH_BODY);
    }
    const body = req.body || {};
    if (String(body.action || '') !== 'build_download' || verify.action !== 'build_download') {
        noStore(res);
        return res.status(403).json(EAUTH_BODY);
    }
    if (!isHexNonce(body.nonce)) {
        noStore(res);
        return res.status(403).json(EAUTH_BODY);
    }
    const discordId = parseDiscordId(body.discord_id);
    if (!discordId) {
        noStore(res);
        return res.status(403).json(EAUTH_BODY);
    }
    const buildId = String(body.build_id || '').trim();
    if (!isValidBuildId(buildId)) {
        noStore(res);
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const { rows } = await pool.query(
        `SELECT build_id, discord_id, status, output_filename, output_sha256, output_size,
                template_version, download_count
           FROM build_requests
          WHERE build_id = $1 AND discord_id = $2 AND status = 'ready'`,
        [buildId, discordId]
    );
    if (rows.length === 0) {
        noStore(res);
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const row = rows[0];
    const filename = String(row.output_filename || '');
    if (!filename || filename.includes('..') || filename.includes('/')) {
        noStore(res);
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const filePath = path.resolve(OUTPUT_DIR, filename);
    const expectedPath = path.join(OUTPUT_DIR, filename);
    if (filePath !== expectedPath) {
        noStore(res);
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    try {
        const st = fs.statSync(filePath);
        if (!st.isFile() || st.size <= 0) {
            noStore(res);
            return res.status(404).json({ status: 'error', reason: 'not_found' });
        }
    } catch (_) {
        noStore(res);
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    await pool.query(
        `UPDATE build_requests
            SET download_count = download_count + 1,
                downloaded_at = CASE WHEN download_count = 0 THEN $1 ELSE downloaded_at END
          WHERE build_id = $2`,
        [nowSec(), buildId]
    );
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="AiDAStandalone.exe"');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-AIDA-Build-Id', buildId);
    res.setHeader('X-AIDA-Template-Version', String(row.template_version || 0));
    if (row.output_sha256) {
        res.setHeader('X-AIDA-Output-SHA256', String(row.output_sha256));
    }
    return res.sendFile(filePath);
}

async function activateTemplate(req) {
    await ensureSchema();
    const adminResult = botAuth.verifyAdminRequest(req);
    if (!adminResult.ok) {
        return { status: 403, body: { status: 'error', reason: adminResult.reason || 'EAUTH' } };
    }
    const body = req.body || {};
    const version = Number(body.version);
    if (!Number.isInteger(version) || version <= 0) {
        return { status: 400, body: { status: 'error', reason: 'invalid_version' } };
    }
    const filename = String(body.filename || '').trim();
    if (!filename || filename.includes('..') || filename.includes('/')) {
        return { status: 400, body: { status: 'error', reason: 'invalid_filename' } };
    }
    const declaredSha256 = String(body.file_sha256 || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(declaredSha256)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_sha256' } };
    }
    const declaredSize = Number(body.file_size || 0);
    if (!Number.isFinite(declaredSize) || declaredSize <= 0) {
        return { status: 400, body: { status: 'error', reason: 'invalid_size' } };
    }
    const testVector = String(body.test_vector || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(testVector)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_test_vector' } };
    }
    const expectedTestVector = computeTestVector();
    if (!expectedTestVector) {
        return { status: 500, body: { status: 'error', reason: 'master_key_unconfigured' } };
    }
    const expectedBuf = Buffer.from(expectedTestVector, 'hex');
    const providedBuf = Buffer.from(testVector, 'hex');
    if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
        return { status: 403, body: { status: 'error', reason: 'master_key_mismatch' } };
    }
    const metadata = body.metadata || {};
    const tmpPath = path.join(TEMPLATE_DIR, `.tmp_${filename}`);
    try {
        fs.accessSync(tmpPath, fs.constants.R_OK);
    } catch (_) {
        return { status: 400, body: { status: 'error', reason: 'template_file_not_found' } };
    }
    const st = fs.statSync(tmpPath);
    if (!st.isFile()) {
        return { status: 400, body: { status: 'error', reason: 'template_not_file' } };
    }
    if (st.size <= MIN_TEMPLATE_SIZE || st.size >= MAX_TEMPLATE_SIZE) {
        try { fs.unlinkSync(tmpPath); } catch (_) {}
        return { status: 400, body: { status: 'error', reason: 'size_out_of_bounds' } };
    }
    const fd = fs.openSync(tmpPath, 'r');
    try {
        const header = Buffer.alloc(2);
        fs.readSync(fd, header, 0, 2, 0);
        if (header[0] !== 0x5A || header[1] !== 0x4D) {
            try { fs.unlinkSync(tmpPath); } catch (_) {}
            return { status: 400, body: { status: 'error', reason: 'invalid_mz_header' } };
        }
    } finally {
        fs.closeSync(fd);
    }
    if (!checkPackedMagic(tmpPath)) {
        try { fs.unlinkSync(tmpPath); } catch (_) {}
        return { status: 400, body: { status: 'error', reason: 'not_protected' } };
    }
    const actualSha256 = sha256File(tmpPath);
    const actualBuf = Buffer.from(actualSha256, 'hex');
    const declaredBuf = Buffer.from(declaredSha256, 'hex');
    if (actualBuf.length !== declaredBuf.length || !crypto.timingSafeEqual(actualBuf, declaredBuf)) {
        try { fs.unlinkSync(tmpPath); } catch (_) {}
        return { status: 400, body: { status: 'error', reason: 'sha256_mismatch' } };
    }
    const finalFilename = `AiDAStandalone_template_v${version}.exe`;
    const finalPath = path.join(TEMPLATE_DIR, finalFilename);
    try {
        fs.renameSync(tmpPath, finalPath);
    } catch (err) {
        try { fs.unlinkSync(tmpPath); } catch (_) {}
        return { status: 500, body: { status: 'error', reason: 'rename_failed', detail: err && err.message ? err.message : '' } };
    }
    const activatedAt = nowSec();
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const prevResult = await client.query(
            `UPDATE build_templates
                SET active = false, archived_at = $1
              WHERE active = true
              RETURNING version`,
            [activatedAt]
        );
        const previousVersion = prevResult.rows.length > 0 ? prevResult.rows[0].version : null;
        await client.query(
            `INSERT INTO build_templates
                (version, filename, file_path, file_sha256, file_size, metadata_json, uploaded_by, active, activated_at)
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, true, $8)`,
            [version, finalFilename, finalPath, actualSha256, st.size, JSON.stringify(metadata), 'admin', activatedAt]
        );
        await client.query('COMMIT');
        return {
            status: 200,
            body: {
                status: 'ok',
                version: version,
                file_sha256: actualSha256,
                file_size: st.size,
                previous_version: previousVersion,
                activated_at: activatedAt,
            },
        };
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

async function listTemplates(req) {
    await ensureSchema();
    const adminResult = botAuth.verifyAdminRequest(req);
    if (!adminResult.ok) {
        return { status: 403, body: { status: 'error', reason: adminResult.reason || 'EAUTH' } };
    }
    const { rows } = await pool.query(
        `SELECT version, filename, file_sha256, file_size, active, uploaded_at, activated_at, archived_at
           FROM build_templates
          ORDER BY version DESC`
    );
    return {
        status: 200,
        body: {
            status: 'ok',
            templates: rows.map(row => ({
                version: row.version,
                filename: row.filename,
                file_sha256: row.file_sha256,
                file_size: row.file_size,
                active: row.active,
                uploaded_at: Number(row.uploaded_at || 0),
                activated_at: row.activated_at ? Number(row.activated_at) : null,
                archived_at: row.archived_at ? Number(row.archived_at) : null,
            })),
        },
    };
}

function deriveCustomerSeed(masterKey, watermarkId) {
    const uuidBytes = Buffer.from(String(watermarkId || '').replace(/-/g, ''), 'hex');
    if (uuidBytes.length !== 16) throw new Error('invalid_watermark_uuid');
    const seedInfo = Buffer.from('customer_seed_v1', 'ascii');
    return Buffer.from(crypto.hkdfSync('sha256', masterKey, uuidBytes, seedInfo, 32));
}

function deriveCustomerKey(customerSeed, templateVersion) {
    const keySalt = Buffer.alloc(4);
    keySalt.writeUInt32LE(templateVersion, 0);
    const keyInfo = Buffer.from('build_key_v1', 'ascii');
    return Buffer.from(crypto.hkdfSync('sha256', customerSeed, keySalt, keyInfo, 32));
}

function deriveKeyFromWatermark(watermarkId, templateVersion) {
    const masterKeyB64 = String(process.env.AIDA_BUILD_MASTER_KEY_B64 || process.env.SERVER_MASTER_KEY_B64 || '').trim();
    if (!masterKeyB64) throw new Error('master_key_unconfigured');
    const masterKey = Buffer.from(masterKeyB64, 'base64');
    if (masterKey.length !== 32) throw new Error('master_key_invalid_length');
    const seed = deriveCustomerSeed(masterKey, watermarkId);
    return deriveCustomerKey(seed, templateVersion);
}

function verifyHeartbeatHmac(watermarkId, templateVersion, heartbeatNonce, hwidHash, providedHmacHex) {
    const customerKey = deriveKeyFromWatermark(watermarkId, templateVersion);
    const sessionData = `${watermarkId}|${templateVersion}|${heartbeatNonce}|${hwidHash}`;
    const expectedHmac = crypto.createHmac('sha256', customerKey).update(sessionData, 'utf8').digest('hex');
    const expectedBuf = Buffer.from(expectedHmac, 'hex');
    const providedBuf = Buffer.from(String(providedHmacHex || ''), 'hex');
    if (providedBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

async function isTemplateVersionAllowed(templateVersion) {
    if (STRICT_TEMPLATE_VERSION) {
        const { rows } = await pool.query(
            'SELECT 1 FROM build_templates WHERE version = $1 AND active = true',
            [templateVersion]
        );
        return rows.length > 0;
    }
    const { rows } = await pool.query(
        `SELECT 1 FROM build_templates
          WHERE version = $1
            AND (archived_at IS NULL OR archived_at > (EXTRACT(EPOCH FROM now())::BIGINT - $2))`,
        [templateVersion, TEMPLATE_GRACE_SECONDS]
    );
    return rows.length > 0;
}

router.post('/request', async (req, res) => {
    try {
        const result = await buildRequest(req);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[build] request failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/status', async (req, res) => {
    try {
        const result = await buildStatus(req);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[build] status failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/download/:build_id', async (req, res) => {
    try {
        const urlBuildId = String(req.params.build_id || '').trim();
        const bodyBuildId = String((req.body && req.body.build_id) || '').trim();
        if (urlBuildId && bodyBuildId && urlBuildId !== bodyBuildId) {
            noStore(res);
            return res.status(404).json({ status: 'error', reason: 'not_found' });
        }
        if (bodyBuildId) {
            req.body.build_id = bodyBuildId;
        } else if (urlBuildId) {
            if (!req.body) req.body = {};
            req.body.build_id = urlBuildId;
        }
        return await buildDownload(req, res);
    } catch (err) {
        console.error('[build] download failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/activate-template', async (req, res) => {
    try {
        const result = await activateTemplate(req);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[build] activate-template failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/templates', async (req, res) => {
    try {
        const result = await listTemplates(req);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[build] templates list failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = {
    router,
    deriveCustomerSeed,
    deriveCustomerKey,
    deriveKeyFromWatermark,
    verifyHeartbeatHmac,
    isTemplateVersionAllowed,
    computeTestVector,
    resolveTemplateVersion,
    assignWatermark,
};
