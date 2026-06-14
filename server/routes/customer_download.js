'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const botAuth = require('../middleware/bot_auth');
const capsule = require('../crypto/customer_capsule');

const router = express.Router();

const CUSTOMER_ROLE_ID = '1515754127110438922';
const ACTION = 'discord_download_ticket';
const TOKEN_TTL_SECONDS = positiveIntEnv('AIDA_CUSTOMER_DOWNLOAD_TOKEN_TTL_SECONDS', 300);
const TOKEN_PREFIX = 'AIDADL.v1';
const EAUTH_BODY = { status: 'error', reason: 'EAUTH' };

let s_schemaPromise = null;
let s_tokenKey = null;

function positiveIntEnv(name, fallback) {
    const n = parseInt(process.env[name] || '', 10);
    if (Number.isFinite(n) && n > 0) return n;
    return fallback;
}

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

function normalizeIp(value) {
    let out = String(value || '').trim();
    if (out.startsWith('::ffff:')) out = out.slice(7);
    return out;
}

function userAgentHash(value) {
    return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex').slice(0, 32);
}

function publicOrigin() {
    return String(process.env.AIDA_PUBLIC_ORIGIN || process.env.PUBLIC_ORIGIN || 'https://aidapro.net').replace(/\/+$/, '');
}

function isHexNonce(value) {
    return typeof value === 'string' && /^[0-9a-f]{32,128}$/i.test(value.trim());
}

function parseDiscordId(value) {
    if (value === undefined || value === null) return '';
    let str;
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) return '';
        str = Math.trunc(value).toString();
    } else if (typeof value === 'bigint') {
        str = value.toString();
    } else if (typeof value === 'string') {
        str = value.trim();
    } else {
        return '';
    }
    return /^\d{15,22}$/.test(str) ? str : '';
}

function parseExpiryEpoch(row) {
    const epoch = Number(row && row.expires_epoch || 0);
    if (Number.isFinite(epoch) && epoch > 0) return Math.floor(epoch);
    const expires = String(row && row.expires || '').trim();
    if (!expires) return 0;
    if (/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
        const d = new Date(expires + 'T23:59:59Z');
        if (!Number.isNaN(d.getTime())) return Math.floor(d.getTime() / 1000);
    }
    const d = new Date(expires);
    if (!Number.isNaN(d.getTime())) return Math.floor(d.getTime() / 1000);
    return 0;
}

function isUsableLicense(row, at) {
    if (!row || row.active !== true) return false;
    if (row.revoked_at !== undefined && row.revoked_at !== null && Number(row.revoked_at || 0) > 0) return false;
    const exp = parseExpiryEpoch(row);
    return !(exp > 0 && (at || nowSec()) > exp);
}

function tokenKey() {
    if (s_tokenKey) return s_tokenKey;
    const direct = String(process.env.CUSTOMER_DOWNLOAD_TOKEN_SECRET_B64 || '').trim();
    if (direct) {
        const buf = Buffer.from(direct, 'base64');
        if (buf.length >= 32) {
            s_tokenKey = buf;
            return s_tokenKey;
        }
    }
    const master = String(process.env.SERVER_MASTER_KEY_B64 || '').trim();
    if (master) {
        const buf = Buffer.from(master, 'base64');
        if (buf.length !== 32) throw new Error('customer_download_token_master_invalid');
        s_tokenKey = crypto.createHmac('sha256', buf).update('aida/customer-download-token/v1', 'utf8').digest();
        return s_tokenKey;
    }
    const arc = String(process.env.ARC_MASTER_SECRET || '');
    if (!arc || arc.length < 32) throw new Error('customer_download_token_secret_unavailable');
    s_tokenKey = crypto.createHmac('sha256', Buffer.from(arc, 'utf8')).update('aida/customer-download-token/v1', 'utf8').digest();
    return s_tokenKey;
}

function hashTokenSecret(tokenId, secretHex) {
    return crypto.createHmac('sha256', tokenKey())
        .update('token|', 'utf8')
        .update(String(tokenId || ''), 'utf8')
        .update('|', 'utf8')
        .update(String(secretHex || ''), 'utf8')
        .digest('hex');
}

function timingSafeHexEqual(aHex, bHex) {
    const validA = /^[0-9a-f]{64}$/i.test(String(aHex || ''));
    const validB = /^[0-9a-f]{64}$/i.test(String(bHex || ''));
    const a = validA ? Buffer.from(String(aHex), 'hex') : Buffer.alloc(32);
    const b = validB ? Buffer.from(String(bHex), 'hex') : Buffer.alloc(32);
    return crypto.timingSafeEqual(a, b) && validA && validB;
}

function createToken() {
    const tokenId = crypto.randomBytes(16).toString('hex');
    const secret = crypto.randomBytes(32).toString('hex');
    return {
        token_id: tokenId,
        secret,
        token: `${TOKEN_PREFIX}.${tokenId}.${secret}`,
        token_hmac: hashTokenSecret(tokenId, secret),
    };
}

function parseToken(value) {
    if (typeof value !== 'string') return null;
    const m = /^AIDADL\.v1\.([0-9a-f]{32})\.([0-9a-f]{64})$/i.exec(value.trim());
    if (!m) return null;
    return { token_id: m[1].toLowerCase(), secret: m[2].toLowerCase() };
}

async function ensureSchema() {
    if (!s_schemaPromise) {
        s_schemaPromise = (async () => {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS customer_download_tokens (
                    token_id          TEXT PRIMARY KEY,
                    token_hmac        TEXT NOT NULL,
                    license_key       TEXT NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
                    discord_id        TEXT NOT NULL,
                    customer_role_id  TEXT NOT NULL,
                    issued_at         BIGINT NOT NULL,
                    expires_at        BIGINT NOT NULL,
                    consumed          BOOLEAN NOT NULL DEFAULT false,
                    consumed_at       BIGINT,
                    source_ip         TEXT NOT NULL DEFAULT '',
                    user_agent_hash   TEXT NOT NULL DEFAULT '',
                    capsule_id        TEXT NOT NULL DEFAULT ''
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_license ON customer_download_tokens (license_key, issued_at DESC)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_discord ON customer_download_tokens (discord_id, issued_at DESC)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_expiry ON customer_download_tokens (expires_at) WHERE consumed = false');
            await pool.query("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_capsule_required BOOLEAN NOT NULL DEFAULT false");
            await pool.query("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_capsule_id TEXT NOT NULL DEFAULT ''");
            await pool.query("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_base_sha256 TEXT NOT NULL DEFAULT ''");
            await pool.query(`
                CREATE TABLE IF NOT EXISTS standalone_customer_capsules (
                    capsule_id             TEXT PRIMARY KEY,
                    token_id               TEXT NOT NULL REFERENCES customer_download_tokens(token_id) ON DELETE CASCADE,
                    license_key            TEXT NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
                    discord_id             TEXT NOT NULL,
                    license_identity_hash  TEXT NOT NULL,
                    discord_identity_hash  TEXT NOT NULL,
                    hwid_hash              TEXT NOT NULL DEFAULT '',
                    base_sha256            TEXT NOT NULL,
                    base_size              BIGINT NOT NULL,
                    base_version           TEXT NOT NULL,
                    aux_patched            BOOLEAN NOT NULL DEFAULT false,
                    marker_hex             TEXT NOT NULL,
                    capsule_sha256         TEXT NOT NULL,
                    secret_wrapped         BYTEA NOT NULL,
                    issued_at              BIGINT NOT NULL,
                    expires_at             BIGINT NOT NULL
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_standalone_customer_capsules_license ON standalone_customer_capsules (license_key, issued_at DESC)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_standalone_customer_capsules_discord ON standalone_customer_capsules (discord_id, issued_at DESC)');
        })();
    }
    return s_schemaPromise;
}

async function storeBotNonce(body) {
    const nonce = String(body && body.nonce || '').trim().toLowerCase();
    await pool.query(
        `INSERT INTO bot_command_log (nonce_hex, action, discord_id, received_at, payload)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [nonce, ACTION, String(body.discord_id || ''), nowSec(), JSON.stringify(body || {})]
    );
}

async function lookupSingleLicense(discordId, at) {
    const { rows } = await pool.query(
        `SELECT key, active, hwid, expires, expires_epoch, revoked_at, plan, tier, discord_id
           FROM licenses
          WHERE discord_id = $1`,
        [discordId]
    );
    const usable = rows.filter(row => isUsableLicense(row, at));
    if (usable.length !== 1) return { ok: false };
    return { ok: true, row: usable[0] };
}

async function issueRequest(req, clientIp, userAgent) {
    await ensureSchema();
    const verify = botAuth.verifyBotRequest(req);
    if (!verify.ok) return { status: 403, body: EAUTH_BODY };
    const body = req.body || {};
    if (String(body.action || '') !== ACTION || verify.action !== ACTION) {
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
        await storeBotNonce(body);
    } catch (err) {
        if (err && err.code === '23505') {
            return { status: 403, body: EAUTH_BODY };
        }
        throw err;
    }
    const issuedAt = nowSec();
    const license = await lookupSingleLicense(discordId, issuedAt);
    if (!license.ok) {
        return { status: 403, body: EAUTH_BODY };
    }
    const token = createToken();
    const expiresAt = issuedAt + TOKEN_TTL_SECONDS;
    await pool.query(
        `INSERT INTO customer_download_tokens
            (token_id, token_hmac, license_key, discord_id, customer_role_id, issued_at, expires_at, consumed, source_ip, user_agent_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9)`,
        [
            token.token_id,
            token.token_hmac,
            license.row.key,
            discordId,
            CUSTOMER_ROLE_ID,
            issuedAt,
            expiresAt,
            normalizeIp(clientIp),
            userAgentHash(userAgent),
        ]
    );
    return {
        status: 200,
        body: {
            status: 'ok',
            url: `${publicOrigin()}/d/a/${token.token}`,
            expires_at: expiresAt,
            expires_in: TOKEN_TTL_SECONDS,
        },
    };
}

function landingHtml() {
    return [
        '<!doctype html>',
        '<html lang="en">',
        '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AiDA Download</title></head>',
        '<body><main><h1>AiDA Standalone</h1><p>Your signed customer download is ready.</p><button id="download" type="button">Download AiDAStandalone.exe</button></main><script>document.getElementById("download").addEventListener("click",async()=>{const token=location.pathname.split("/").pop();const r=await fetch("/api/customer-download/redeem",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token})});if(!r.ok)throw new Error("download failed");const b=await r.blob();const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download="AiDAStandalone.exe";document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(u);a.remove();},1000);});</script></body>',
        '</html>',
    ].join('');
}

async function landingRequest() {
    return {
        status: 200,
        body: landingHtml(),
    };
}

async function recordCapsule(tokenRow, licenseRow, personalized) {
    await pool.query(
        `INSERT INTO standalone_customer_capsules
            (capsule_id, token_id, license_key, discord_id, license_identity_hash, discord_identity_hash, hwid_hash, base_sha256, base_size, base_version, aux_patched, marker_hex, capsule_sha256, secret_wrapped, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [
            personalized.capsule.capsule_id,
            tokenRow.token_id,
            tokenRow.license_key,
            tokenRow.discord_id,
            personalized.capsule.license_identity_hash,
            personalized.capsule.discord_identity_hash,
            personalized.capsule.hwid_hash || '',
            personalized.capsule.base_sha256,
            personalized.capsule.base_size,
            personalized.capsule.base_version,
            personalized.aux_patched === true,
            personalized.marker_hex,
            personalized.capsule_sha256,
            personalized.secret_wrapped,
            personalized.capsule.issued_at,
            personalized.capsule.expires_at,
        ]
    );
    await pool.query(
        `UPDATE licenses
            SET standalone_capsule_required = true,
                standalone_capsule_id = $1,
                standalone_base_sha256 = $2
          WHERE key = $3`,
        [personalized.capsule.capsule_id, personalized.capsule.base_sha256, tokenRow.license_key]
    );
    await pool.query(
        `INSERT INTO downloads (hwid, ip, license_key, artifact, user_agent)
         VALUES ($1, $2, $3, $4, $5)`,
        [
            String(licenseRow && licenseRow.hwid || ''),
            normalizeIp(tokenRow.source_ip || ''),
            tokenRow.license_key,
            'aida',
            '',
        ]
    ).catch(() => {});
}

async function redeemRequest(body, clientIp, userAgent) {
    await ensureSchema();
    const parsed = parseToken(body && body.token);
    if (!parsed) return { status: 401, body: EAUTH_BODY };
    const expectedHmac = hashTokenSecret(parsed.token_id, parsed.secret);
    const { rows } = await pool.query('SELECT * FROM customer_download_tokens WHERE token_id = $1', [parsed.token_id]);
    if (rows.length !== 1) return { status: 401, body: EAUTH_BODY };
    const row = rows[0];
    const at = nowSec();
    if (!timingSafeHexEqual(expectedHmac, row.token_hmac)
        || row.consumed
        || Number(row.expires_at || 0) < at) {
        return { status: 401, body: EAUTH_BODY };
    }
    const license = await lookupSingleLicense(String(row.discord_id || ''), at);
    if (!license.ok || license.row.key !== row.license_key) {
        return { status: 401, body: EAUTH_BODY };
    }
    const update = await pool.query(
        `UPDATE customer_download_tokens
            SET consumed = true, consumed_at = $1
          WHERE token_id = $2 AND token_hmac = $3 AND consumed = false AND expires_at >= $1`,
        [at, parsed.token_id, expectedHmac]
    );
    if (!update || update.rowCount !== 1) {
        return { status: 401, body: EAUTH_BODY };
    }
    const personalized = capsule.createPersonalizedExe({
        license_key: row.license_key,
        discord_id: row.discord_id,
        hwid: license.row.hwid || '',
        issued_at: at,
        expires_at: Math.min(Number(row.expires_at || at), at + 120),
    });
    await recordCapsule(row, license.row, personalized);
    await pool.query(
        `UPDATE customer_download_tokens
            SET capsule_id = $1
          WHERE token_id = $2`,
        [personalized.capsule.capsule_id, parsed.token_id]
    );
    return {
        status: 200,
        body: personalized.output,
        filename: 'AiDAStandalone.exe',
        capsule_id: personalized.capsule.capsule_id,
    };
}

router.post('/issue', async (req, res) => {
    try {
        const result = await issueRequest(req, getClientIp(req), req.headers && req.headers['user-agent']);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[customer_download] issue failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/redeem', async (req, res) => {
    try {
        const result = await redeemRequest(req.body || {}, getClientIp(req), req.headers && req.headers['user-agent']);
        noStore(res);
        if (!Buffer.isBuffer(result.body)) {
            return res.status(result.status).json(result.body);
        }
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
        res.setHeader('Content-Length', String(result.body.length));
        res.setHeader('X-AiDA-Capsule-Id', result.capsule_id);
        return res.status(result.status).send(result.body);
    } catch (err) {
        console.error('[customer_download] redeem failed:', err && err.message ? err.message : err);
        noStore(res);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

async function landingHandler(_req, res) {
    const result = await landingRequest();
    noStore(res);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(result.status).send(result.body);
}

router._internal = {
    ACTION,
    CUSTOMER_ROLE_ID,
    TOKEN_PREFIX,
    createToken,
    parseToken,
    hashTokenSecret,
    timingSafeHexEqual,
    issueRequest,
    landingRequest,
    redeemRequest,
    isUsableLicense,
    _resetForTests: () => {
        s_schemaPromise = null;
        s_tokenKey = null;
    },
};

module.exports = {
    router,
    landingHandler,
    _internal: router._internal,
};
