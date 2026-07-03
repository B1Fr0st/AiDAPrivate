'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const keyFormat = require('../crypto/key_format');
const auditLog = require('../middleware/audit_log');
const licenseRateLimit = require('../middleware/license_rate_limit');
const killSwitch = require('../middleware/kill_switch');
const { dualSignPayload, getBootstrapP256PublicHex, signBootstrapP256String } = require('../crypto/signing');

const router = express.Router();

const EAUTH_BUDGET_MS = parseInt(process.env.BOOTSTRAP_EAUTH_BUDGET_MS || '250', 10) || 250;
const EAUTH_JITTER_MS = parseInt(process.env.BOOTSTRAP_EAUTH_JITTER_MS || '20', 10) || 20;
const TOKEN_TTL_SECONDS = parseInt(process.env.BOOTSTRAP_TOKEN_TTL_SECONDS || '180', 10) || 180;
const TIMESTAMP_WINDOW_MS = parseInt(process.env.BOOTSTRAP_TIMESTAMP_WINDOW_MS || '60000', 10) || 60000;
const IP_BIND_ENABLED = (process.env.BOOTSTRAP_TOKEN_BIND_IP || '1') !== '0';
const MAX_CAMOUFOX_SIDECAR_BYTES = positiveIntEnv('AIDA_CAMOUFOX_SIDECAR_MAX_BYTES', 1024 * 1024 * 1024);
const MAX_CAMOUFOX_MCP_BYTES = positiveIntEnv('AIDA_CAMOUFOX_MCP_MAX_BYTES', 256 * 1024 * 1024);
const EAUTH_BODY = JSON.stringify({ ok: false, error_code: 'EAUTH' });
const EAUTH_LENGTH = Buffer.byteLength(EAUTH_BODY, 'utf8');
const CAMOUFOX_BROWSER_DIR = 'camoufox-135.0.1-beta.24-win.x86_64';
const DEFAULT_CAMOUFOX_SIDECAR_EXE_REL = `deps\\${CAMOUFOX_BROWSER_DIR}\\camoufox.exe`;
const DEFAULT_CAMOUFOX_MCP_REL = 'deps\\AiDA_CamoufoxReverseMcp.exe';

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

function randomJitter() {
    if (EAUTH_JITTER_MS <= 0) return 0;
    return crypto.randomInt(0, EAUTH_JITTER_MS + 1);
}

async function applyEauthBudget(startedAt) {
    const target = EAUTH_BUDGET_MS + randomJitter();
    const remaining = target - (Date.now() - (startedAt || Date.now()));
    if (remaining > 0) await new Promise(resolve => setTimeout(resolve, remaining));
}

async function sendEauth(res, startedAt) {
    await applyEauthBudget(startedAt);
    noStore(res);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', String(EAUTH_LENGTH));
    return res.status(401).send(EAUTH_BODY);
}

function getClientIp(req) {
    return (req && (req.ip || (req.socket && req.socket.remoteAddress))) || '';
}

function normalizeIp(ip) {
    if (typeof ip !== 'string') return '';
    let out = ip.trim();
    if (out.startsWith('::ffff:')) out = out.slice(7);
    return out;
}

function userAgentHash(userAgent) {
    return crypto.createHash('sha256').update(String(userAgent || ''), 'utf8').digest('hex').slice(0, 32);
}

function tokenKey() {
    if (s_tokenKey) return s_tokenKey;
    const direct = process.env.BOOTSTRAP_TOKEN_SECRET_B64 || '';
    if (direct) {
        const buf = Buffer.from(direct, 'base64');
        if (buf.length >= 32) {
            s_tokenKey = buf;
            return s_tokenKey;
        }
    }
    const fallback = process.env.SERVER_MASTER_KEY_B64 || process.env.ARC_MASTER_SECRET || '';
    if (!fallback || fallback.length < 32) {
        throw new Error('bootstrap_token_secret_unavailable');
    }
    s_tokenKey = crypto.createHmac('sha256', Buffer.from(String(fallback), 'utf8'))
        .update('aida/bootstrap-token/v1', 'utf8')
        .digest();
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
    const a = /^[0-9a-f]{64}$/i.test(String(aHex || '')) ? Buffer.from(String(aHex), 'hex') : Buffer.alloc(32);
    const b = /^[0-9a-f]{64}$/i.test(String(bHex || '')) ? Buffer.from(String(bHex), 'hex') : Buffer.alloc(32);
    return crypto.timingSafeEqual(a, b) && /^[0-9a-f]{64}$/i.test(String(aHex || '')) && /^[0-9a-f]{64}$/i.test(String(bHex || ''));
}

function createToken() {
    const tokenId = crypto.randomBytes(16).toString('hex');
    const secret = crypto.randomBytes(32).toString('hex');
    return {
        token_id: tokenId,
        secret,
        token: `AIDABOOT.v1.${tokenId}.${secret}`,
        token_hmac: hashTokenSecret(tokenId, secret),
    };
}

function manifestMacInput(payload) {
    const artifact = payload && payload.artifact ? payload.artifact : {};
    const pkg = artifact.package || {};
    const auth = artifact.authenticode || {};
    const camoufox = payload && payload.camoufox ? payload.camoufox : {};
    const camoufoxMcp = camoufox.mcp || {};
    const policy = payload && payload.policy ? payload.policy : {};
    return [
        'AIDABOOTMANIFEST.v1',
        payload.token_id,
        payload.issued_at,
        payload.expires_at,
        artifact.name,
        artifact.version,
        artifact.url,
        artifact.sha256,
        artifact.size || '',
        pkg.format || '',
        pkg.sha256 || '',
        pkg.size || '',
        pkg.enc_key_b64 || '',
        pkg.mac_key_b64 || '',
        auth.required === true ? '1' : '0',
        auth.signer_thumbprint || '',
        auth.accept_pinned_private_ca === true ? '1' : '0',
        camoufox.configured === true ? '1' : '0',
        camoufox.version || '',
        camoufox.url || '',
        camoufox.sha256 || '',
        camoufox.size || '',
        camoufox.executable_rel || '',
        camoufox.python_rel || '',
        camoufoxMcp.configured === true ? '1' : '0',
        camoufoxMcp.version || '',
        camoufoxMcp.url || '',
        camoufoxMcp.sha256 || '',
        camoufoxMcp.size || '',
        camoufoxMcp.rel || '',
        policy.one_time_token === true ? '1' : '0',
        policy.token_bound_to_client_nonce === true ? '1' : '0',
        policy.token_bound_to_source_ip === true ? '1' : '0',
        policy.artifact_https_required === true ? '1' : '0',
        policy.no_public_binary_route === true ? '1' : '0',
        policy.encrypted_public_artifact === true ? '1' : '0',
        policy.camoufox_sidecar_hash_required === true ? '1' : '0',
        policy.camoufox_mcp_hash_required === true ? '1' : '0',
    ].map(v => String(v === undefined || v === null ? '' : v)).join('\n');
}

function createManifestMac(tokenSecretHex, payload) {
    return crypto.createHmac('sha256', Buffer.from(tokenSecretHex, 'hex'))
        .update(manifestMacInput(payload), 'utf8')
        .digest('hex');
}

function parseToken(token) {
    if (typeof token !== 'string') return null;
    const m = /^AIDABOOT\.v1\.([0-9a-f]{32})\.([0-9a-f]{64})$/i.exec(token.trim());
    if (!m) return null;
    return { token_id: m[1].toLowerCase(), secret: m[2].toLowerCase() };
}

function isHexNonce(value) {
    return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function normalizeBootstrapHwid(value) {
    const raw = typeof value === 'string' ? value.trim().toLowerCase() : '';
    return /^[0-9a-f]{64}$/.test(raw) ? raw : '';
}

function storedHwidMismatch(storedValue, presentedValue) {
    const stored = typeof storedValue === 'string' ? storedValue.trim().toLowerCase() : '';
    if (!stored) return false;
    return stored !== presentedValue;
}

function isTimestampFresh(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) return false;
    const ms = value > 1e12 ? Math.floor(value) : Math.floor(value * 1000);
    return Math.abs(Date.now() - ms) <= TIMESTAMP_WINDOW_MS;
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

function isLicenseExpired(row, now) {
    const epoch = parseExpiryEpoch(row);
    return epoch > 0 && (now || nowSec()) > epoch;
}

function isNonEnforcingBanReason(reason) {
    const r = String(reason || '').toLowerCase();
    return r === 'anomaly_auto_kill' || r === 'cross_session_anomaly_ban';
}

function psQuote(value) {
    return "'" + String(value || '').replace(/'/g, "''") + "'";
}

function publicOrigin() {
    return String(process.env.AIDA_PUBLIC_ORIGIN || process.env.PUBLIC_ORIGIN || 'https://aidapro.net').replace(/\/+$/, '');
}

function normalizeScriptPath(value) {
    const raw = String(value || '').trim();
    const lower = raw.toLowerCase();
    if (!raw || raw.length > 160 || raw.indexOf('?') >= 0 || raw.indexOf('#') >= 0) return '';
    if (!raw.startsWith('/')) return '';
    if (raw === '/' || lower.includes('/bootstrap.ps1') || raw === '/health' || raw === '/validateLicense' || raw === '/kill') return '';
    if (raw.includes('..') || raw.includes('//')) return '';
    if (/^\/api(?:\/|$)/i.test(raw) || /^\/bootstrap-artifacts(?:\/|$)/i.test(raw)) return '';
    if (!/^\/[A-Za-z0-9._~/-]+$/.test(raw)) return '';
    return raw;
}

function slugToScriptPath(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const name = raw.endsWith('.ps1') ? raw : raw + '.ps1';
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{15,95}\.ps1$/i.test(name)) return '';
    return '/b/' + name;
}

function getScriptRouteConfig() {
    const explicitPath = normalizeScriptPath(process.env.AIDA_BOOTSTRAP_SCRIPT_PATH || '');
    const slugPath = explicitPath ? '' : slugToScriptPath(process.env.AIDA_BOOTSTRAP_SCRIPT_SLUG || '');
    return {
        script_path: explicitPath || slugPath,
        root_content_negotiation: process.env.AIDA_BOOTSTRAP_ROOT_NEGOTIATION !== '0',
        legacy_route_enabled: process.env.AIDA_BOOTSTRAP_LEGACY_ROUTE_ENABLED === '1',
        legacy_path: '/bootstrap.ps1',
    };
}

function acceptsBootstrapScript(req) {
    const accept = String(req && req.headers && req.headers.accept || '');
    if (/(?:^|[,;\s])(?:application\/vnd\.aida\.bootstrap|application\/x-powershell|text\/x-powershell|text\/powershell)(?:$|[,;\s])/i.test(accept)) return true;
    const ua = String(req && req.headers && req.headers['user-agent'] || '');
    return /WindowsPowerShell|PowerShell\/\d/i.test(ua);
}

function validHexSha256(value) {
    return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function repairKnownMangledSidecarRelativePath(value) {
    const raw = String(value || '').trim();
    const compact = raw.replace(/[\\/]/g, '');
    if (compact === `deps${CAMOUFOX_BROWSER_DIR}camoufox.exe`) return DEFAULT_CAMOUFOX_SIDECAR_EXE_REL;
    if (compact === 'depsAiDA_CamoufoxReverseMcp.exe') return DEFAULT_CAMOUFOX_MCP_REL;
    if (compact === 'depscamoufox-reverse-mcp.exe') return 'deps\\camoufox-reverse-mcp.exe';
    if (compact === 'depscamoufox_reverse_mcp.exe') return 'deps\\camoufox_reverse_mcp.exe';
    return raw;
}

function safeSidecarRelativePath(value) {
    const raw = repairKnownMangledSidecarRelativePath(value).replace(/\//g, '\\');
    if (!raw || raw.length > 220 || raw.includes(':') || path.isAbsolute(raw)) {
        return '';
    }
    const parts = raw.split(/\\+/);
    if (parts.some(part => !part || part === '.' || part === '..')) {
        return '';
    }
    return parts.join('\\');
}

function getCamoufoxSidecarConfig() {
    const urlRaw = String(process.env.AIDA_CAMOUFOX_SIDECAR_URL || '').trim();
    if (!urlRaw) {
        return { ok: true, configured: false };
    }
    const sha256 = String(process.env.AIDA_CAMOUFOX_SIDECAR_SHA256 || '').trim().toLowerCase();
    const version = String(process.env.AIDA_CAMOUFOX_SIDECAR_VERSION || 'current').trim();
    const size = Number(process.env.AIDA_CAMOUFOX_SIDECAR_SIZE || 0);
    const executableRel = safeSidecarRelativePath(process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL || DEFAULT_CAMOUFOX_SIDECAR_EXE_REL);
    const pythonRelRaw = String(process.env.AIDA_CAMOUFOX_SIDECAR_PYTHON_REL || '').trim();
    const pythonRel = pythonRelRaw ? safeSidecarRelativePath(pythonRelRaw) : '';
    let parsed;
    try {
        parsed = new URL(urlRaw);
    } catch (_) {
        return { ok: false, reason: 'camoufox_sidecar_url_invalid' };
    }
    if (parsed.protocol !== 'https:' && !(process.env.AIDA_CAMOUFOX_SIDECAR_ALLOW_HTTP === '1' && parsed.hostname === 'localhost')) {
        return { ok: false, reason: 'camoufox_sidecar_url_not_https' };
    }
    if (/\/api\//i.test(parsed.pathname)) {
        return { ok: false, reason: 'camoufox_sidecar_api_route_disallowed' };
    }
    if (!/\.zip$/i.test(parsed.pathname)) {
        return { ok: false, reason: 'camoufox_sidecar_extension_invalid' };
    }
    if (!validHexSha256(sha256)) {
        return { ok: false, reason: 'camoufox_sidecar_sha256_invalid' };
    }
    if (!Number.isFinite(size) || size <= 0 || size > MAX_CAMOUFOX_SIDECAR_BYTES) {
        return { ok: false, reason: 'camoufox_sidecar_size_invalid' };
    }
    if (!version || !executableRel || (pythonRelRaw && !pythonRel)) {
        return { ok: false, reason: 'camoufox_sidecar_metadata_invalid' };
    }
    const mcpPatch = getCamoufoxMcpPatchConfig();
    if (!mcpPatch.ok) {
        return mcpPatch;
    }
    return {
        ok: true,
        configured: true,
        version,
        url: parsed.toString(),
        sha256,
        size: Math.floor(size),
        executable_rel: executableRel,
        python_rel: pythonRel,
        mcp: mcpPatch.configured ? {
            configured: true,
            version: mcpPatch.version,
            url: mcpPatch.url,
            sha256: mcpPatch.sha256,
            size: mcpPatch.size,
            rel: mcpPatch.rel,
        } : { configured: false },
    };
}

function getCamoufoxMcpPatchConfig() {
    const urlRaw = String(process.env.AIDA_CAMOUFOX_MCP_URL || '').trim();
    if (!urlRaw) {
        return { ok: true, configured: false };
    }
    const sha256 = String(process.env.AIDA_CAMOUFOX_MCP_SHA256 || '').trim().toLowerCase();
    const version = String(process.env.AIDA_CAMOUFOX_MCP_VERSION || 'current').trim();
    const size = Number(process.env.AIDA_CAMOUFOX_MCP_SIZE || 0);
    const rel = safeSidecarRelativePath(process.env.AIDA_CAMOUFOX_MCP_REL || DEFAULT_CAMOUFOX_MCP_REL);
    let parsed;
    try {
        parsed = new URL(urlRaw);
    } catch (_) {
        return { ok: false, reason: 'camoufox_mcp_url_invalid' };
    }
    if (parsed.protocol !== 'https:' && !(process.env.AIDA_CAMOUFOX_SIDECAR_ALLOW_HTTP === '1' && parsed.hostname === 'localhost')) {
        return { ok: false, reason: 'camoufox_mcp_url_not_https' };
    }
    if (/\/api\//i.test(parsed.pathname)) {
        return { ok: false, reason: 'camoufox_mcp_api_route_disallowed' };
    }
    if (forbiddenStandaloneExecutableName(path.basename(parsed.pathname))) {
        return { ok: false, reason: 'camoufox_mcp_standalone_executable_disallowed' };
    }
    if (!/\.exe$/i.test(parsed.pathname)) {
        return { ok: false, reason: 'camoufox_mcp_extension_invalid' };
    }
    if (!validHexSha256(sha256)) {
        return { ok: false, reason: 'camoufox_mcp_sha256_invalid' };
    }
    if (!Number.isFinite(size) || size <= 0 || size > MAX_CAMOUFOX_MCP_BYTES) {
        return { ok: false, reason: 'camoufox_mcp_size_invalid' };
    }
    if (!version || !rel) {
        return { ok: false, reason: 'camoufox_mcp_metadata_invalid' };
    }
    return {
        ok: true,
        configured: true,
        version,
        url: parsed.toString(),
        sha256,
        size: Math.floor(size),
        rel,
    };
}

function getReleaseConfig() {
    const certSha256 = String(process.env.AIDA_BOOTSTRAP_TLS_CERT_SHA256 || '').trim().toLowerCase();
    const spkiSha256 = String(process.env.LICENSE_SERVER_SPKI_PIN_HEX || process.env.AIDA_BOOTSTRAP_TLS_SPKI_SHA256 || '').trim().toLowerCase();
    const camoufox = getCamoufoxSidecarConfig();
    if (!camoufox.ok) {
        return { ok: false, reason: camoufox.reason };
    }
    if (!camoufox.configured) {
        return { ok: false, reason: 'camoufox_sidecar_config_missing' };
    }
    const z3 = {
        configured: false,
        version: '',
        url: '',
        sha256: '',
        size: '',
        dll_rel: '',
    };
    return {
        ok: true,
        url: '',
        sha256: camoufox.sha256,
        version: camoufox.version,
        file_name: '',
        size: null,
        package: null,
        require_authenticode: false,
        signer_thumbprint: '',
        accept_pinned_private_ca_signer: false,
        tls_spki_sha256: validHexSha256(spkiSha256) ? spkiSha256 : '',
        tls_cert_sha256: validHexSha256(certSha256) ? certSha256 : '',
        camoufox,
        z3,
    };
}

async function ensureSchema() {
    if (!s_schemaPromise) {
        s_schemaPromise = (async () => {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS bootstrap_delivery_tokens (
                    token_id        TEXT PRIMARY KEY,
                    token_hmac      TEXT NOT NULL,
                    license_key     TEXT NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
                    client_nonce    TEXT NOT NULL,
                    issued_at       BIGINT NOT NULL,
                    expires_at      BIGINT NOT NULL,
                    consumed        BOOLEAN NOT NULL DEFAULT false,
                    consumed_at     BIGINT,
                    source_ip       TEXT NOT NULL DEFAULT '',
                    user_agent_hash TEXT NOT NULL DEFAULT '',
                    manifest_version TEXT NOT NULL DEFAULT '',
                    artifact_sha256 TEXT NOT NULL DEFAULT ''
                )
            `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_license ON bootstrap_delivery_tokens (license_key, issued_at DESC)');
            await pool.query('CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expiry ON bootstrap_delivery_tokens (expires_at) WHERE consumed = false');
        })();
    }
    return s_schemaPromise;
}

async function isIpBanned(clientIp) {
    const normalized = normalizeIp(clientIp);
    const { rows } = await pool.query(
        'SELECT reason FROM bans WHERE ban_type = $1 AND (value = $2 OR value = $3)',
        ['ip', clientIp || '', normalized || '']
    );
    return rows.some(row => !isNonEnforcingBanReason(row.reason));
}

async function lookupActiveLicense(licenseKey) {
    const normalized = keyFormat.normalizeForLookup(licenseKey);
    if (!normalized) return { ok: false, reason: 'invalid_format' };
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [normalized]);
    if (rows.length === 0) return { ok: false, reason: 'not_found', normalized };
    const row = rows[0];
    if (!row.active) return { ok: false, reason: 'revoked', normalized, row };
    if (isLicenseExpired(row)) return { ok: false, reason: 'expired', normalized, row };
    return { ok: true, normalized, row };
}

async function audit(action, licenseKey, clientIp, userAgent, decision, reasonCode, extra) {
    return auditLog.logV2({
        action,
        license_key: licenseKey || '',
        hwid: '',
        source_ip: clientIp || '',
        user_agent: userAgent || '',
        decision,
        reason_code: reasonCode || '',
        extra: extra || {},
    }).catch(() => {});
}

async function authorizeRequest(body, clientIp, userAgent) {
    await ensureSchema();
    const release = getReleaseConfig();
    const licenseKeyRaw = body && typeof body.license_key === 'string' ? body.license_key.trim() : '';
    const normalizedLicenseKey = keyFormat.normalizeForLookup(licenseKeyRaw);
    const clientNonce = body && typeof body.client_nonce === 'string' ? body.client_nonce.trim().toLowerCase() : '';
    const presentedHwid = normalizeBootstrapHwid(body && body.hwid);
    if (!release.ok) {
        await audit('bootstrap.authorize', normalizedLicenseKey || '', clientIp, userAgent, 'deny', release.reason, {});
        return { eauth: true };
    }
    if (!normalizedLicenseKey || licenseKeyRaw.length > 128 || !isHexNonce(clientNonce) || !presentedHwid || !isTimestampFresh(body.timestamp)) {
        await audit('bootstrap.authorize', normalizedLicenseKey || '', clientIp, userAgent, 'deny', 'invalid_request', {});
        return { eauth: true };
    }
    const rl = await licenseRateLimit.check(normalizedLicenseKey, { fail_closed: true });
    if (!rl.ok) {
        await audit('bootstrap.authorize', normalizedLicenseKey, clientIp, userAgent, 'deny', (rl.soft_fail ? 'rate_limit_unavailable' : 'rate_limited:' + (rl.scope || '')), { retry_after: rl.retry_after || 0 });
        return { eauth: true };
    }
    if (await isIpBanned(clientIp)) {
        await audit('bootstrap.authorize', normalizedLicenseKey, clientIp, userAgent, 'deny', 'ip_banned', {});
        return { eauth: true };
    }
    const lookup = await lookupActiveLicense(normalizedLicenseKey);
    if (!lookup.ok) {
        await audit('bootstrap.authorize', normalizedLicenseKey, clientIp, userAgent, 'deny', 'license:' + (lookup.reason || 'invalid'), {});
        return { eauth: true };
    }
    if (storedHwidMismatch(lookup.row && lookup.row.hwid, presentedHwid)) {
        await audit('bootstrap.authorize', lookup.normalized, clientIp, userAgent, 'deny', 'hwid_mismatch', {
            bound_hwid_present: true,
            presented_hwid_valid: true,
        });
        return { eauth: true };
    }
    const issuedAt = nowSec();
    const expiresAt = issuedAt + TOKEN_TTL_SECONDS;
    const token = createToken();
    await pool.query(
        `INSERT INTO bootstrap_delivery_tokens
            (token_id, token_hmac, license_key, client_nonce, issued_at, expires_at, consumed, source_ip, user_agent_hash, manifest_version, artifact_sha256)
         VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9, $10)`,
        [token.token_id, token.token_hmac, lookup.normalized, clientNonce, issuedAt, expiresAt, normalizeIp(clientIp), userAgentHash(userAgent), release.version, release.sha256]
    );
    await audit('bootstrap.authorize', lookup.normalized, clientIp, userAgent, 'allow', 'token_issued', {
        token_id: token.token_id,
        expires_at: expiresAt,
        artifact_version: release.version,
        artifact_sha256: release.sha256,
    });
    return {
        status: 200,
        body: {
            ok: true,
            status: 'authorized',
            token: token.token,
            token_type: 'AIDABOOT.v1',
            expires_at: expiresAt,
            expires_in: TOKEN_TTL_SECONDS,
            manifest_url: '/api/bootstrap/manifest',
            client_nonce: clientNonce,
        },
    };
}

async function markDownloadIssued(licenseKey, clientIp, userAgent) {
    try {
        await pool.query(
            `INSERT INTO downloads (hwid, ip, license_key, artifact, user_agent)
             VALUES ($1, $2, $3, $4, $5)`,
            ['', normalizeIp(clientIp), licenseKey, 'aida', String(userAgent || '').slice(0, 512)]
        );
    } catch (err) {
        console.warn('[bootstrap] downloads insert failed:', err && err.message ? err.message : err);
    }
}

async function manifestRequest(body, clientIp, userAgent) {
    await ensureSchema();
    const release = getReleaseConfig();
    if (!release.ok) {
        await audit('bootstrap.manifest', '', clientIp, userAgent, 'deny', release.reason, {});
        return { eauth: true };
    }
    const parsed = parseToken(body && body.token);
    const clientNonce = body && typeof body.client_nonce === 'string' ? body.client_nonce.trim().toLowerCase() : '';
    if (!parsed || !isHexNonce(clientNonce) || !isTimestampFresh(body.timestamp)) {
        await audit('bootstrap.manifest', '', clientIp, userAgent, 'deny', 'invalid_request', {});
        return { eauth: true };
    }
    const expectedHmac = hashTokenSecret(parsed.token_id, parsed.secret);
    const { rows } = await pool.query('SELECT * FROM bootstrap_delivery_tokens WHERE token_id = $1', [parsed.token_id]);
    if (rows.length === 0) {
        await audit('bootstrap.manifest', '', clientIp, userAgent, 'deny', 'token_not_found', { token_id: parsed.token_id });
        return { eauth: true };
    }
    const row = rows[0];
    const sameIp = normalizeIp(clientIp) === normalizeIp(row.source_ip || '');
    if (!timingSafeHexEqual(expectedHmac, row.token_hmac)
        || row.consumed
        || Number(row.expires_at || 0) < nowSec()
        || String(row.client_nonce || '').toLowerCase() !== clientNonce
        || (IP_BIND_ENABLED && !sameIp)) {
        await audit('bootstrap.manifest', row.license_key || '', clientIp, userAgent, 'deny', 'token_invalid', { token_id: parsed.token_id });
        return { eauth: true };
    }
    const lookup = await lookupActiveLicense(row.license_key);
    if (!lookup.ok) {
        await audit('bootstrap.manifest', row.license_key || '', clientIp, userAgent, 'deny', 'license:' + (lookup.reason || 'invalid'), { token_id: parsed.token_id });
        return { eauth: true };
    }
    const killVerdict = await killSwitch.isLicenseKeyDropped(lookup.normalized);
    if (killVerdict && killVerdict.dropped) {
        await audit('bootstrap.manifest', lookup.normalized, clientIp, userAgent, 'deny', 'kill_switch:' + (killVerdict.reason || 'license_key'), { token_id: parsed.token_id });
        return { eauth: true };
    }
    const consumedAt = nowSec();
    const update = await pool.query(
        `UPDATE bootstrap_delivery_tokens
            SET consumed = true, consumed_at = $1
          WHERE token_id = $2 AND consumed = false AND expires_at >= $3`,
        [consumedAt, parsed.token_id, consumedAt]
    );
    if (!update || update.rowCount !== 1) {
        await audit('bootstrap.manifest', row.license_key || '', clientIp, userAgent, 'deny', 'token_replay', { token_id: parsed.token_id });
        return { eauth: true };
    }
    const issuedAt = consumedAt;
    const expiresAt = Math.min(Number(row.expires_at || consumedAt), issuedAt + 120);
    const payload = {
        ok: true,
        manifest_version: 1,
        issued_at: issuedAt,
        expires_at: expiresAt,
        token_id: parsed.token_id,
        artifact: {
            name: '',
            version: '',
            url: '',
            sha256: '',
            size: '',
            authenticode: {
                required: false,
                signer_thumbprint: '',
                accept_pinned_private_ca: false,
            },
        },
        camoufox: {
            configured: release.camoufox.configured === true,
            version: release.camoufox.version || '',
            url: release.camoufox.url || '',
            sha256: release.camoufox.sha256 || '',
            size: release.camoufox.size || '',
            executable_rel: release.camoufox.executable_rel || '',
            python_rel: release.camoufox.python_rel || '',
            mcp: release.camoufox.mcp && release.camoufox.mcp.configured ? {
                configured: true,
                version: release.camoufox.mcp.version || '',
                url: release.camoufox.mcp.url || '',
                sha256: release.camoufox.mcp.sha256 || '',
                size: release.camoufox.mcp.size || '',
                rel: release.camoufox.mcp.rel || '',
            } : { configured: false },
        },
        z3: {
            configured: release.z3.configured === true,
            version: release.z3.version || '',
            url: release.z3.url || '',
            sha256: release.z3.sha256 || '',
            size: release.z3.size || '',
            dll_rel: release.z3.dll_rel || '',
        },
        policy: {
            one_time_token: true,
            token_bound_to_client_nonce: true,
            token_bound_to_source_ip: IP_BIND_ENABLED,
            artifact_https_required: false,
            no_public_binary_route: true,
            encrypted_public_artifact: false,
            camoufox_sidecar_hash_required: release.camoufox.configured === true,
            camoufox_mcp_hash_required: !!(release.camoufox.mcp && release.camoufox.mcp.configured),
            z3_sidecar_hash_required: release.z3.configured === true,
        },
    };
    const sig = dualSignPayload(payload);
    const manifestMac = createManifestMac(parsed.secret, payload);
    const manifestSigP256 = signBootstrapP256String(manifestMacInput(payload));
    await markDownloadIssued(lookup.normalized, clientIp, userAgent);
    await audit('bootstrap.manifest', lookup.normalized, clientIp, userAgent, 'allow', 'manifest_issued', {
        token_id: parsed.token_id,
        artifact_version: release.version,
        artifact_sha256: release.sha256,
    });
    return { status: 200, body: Object.assign({}, payload, sig, { manifest_mac: manifestMac, manifest_sig_p256: manifestSigP256, manifest_sig_alg: 'ECDSA_P256_SHA256_P1363' }) };
}

function buildBootstrapScript() {
    const origin = publicOrigin();
    const tlsSpkiRaw = String(process.env.LICENSE_SERVER_SPKI_PIN_HEX || process.env.AIDA_BOOTSTRAP_TLS_SPKI_SHA256 || '').trim().toLowerCase();
    const tlsCertRaw = String(process.env.AIDA_BOOTSTRAP_TLS_CERT_SHA256 || '').trim().toLowerCase();
    const tlsSpki = validHexSha256(tlsSpkiRaw) ? tlsSpkiRaw : '';
    const tlsCert = validHexSha256(tlsCertRaw) ? tlsCertRaw : '';
    const requireTlsPin = (process.env.AIDA_BOOTSTRAP_REQUIRE_TLS_PIN || (process.env.NODE_ENV === 'production' ? '1' : '0')) !== '0';
    const release = getReleaseConfig();
    let p256 = { x: '', y: '' };
    try {
        p256 = getBootstrapP256PublicHex();
    } catch (_) { }
    const lines = [
        '$ErrorActionPreference = "Stop"',
        '$AidaBootstrapSelfUrl = ' + psQuote(origin),
        '$AidaBootstrapLogPath = Join-Path ([IO.Path]::GetTempPath()) "aida_bootstrap.log"',
        'function Write-AidaBootstrapLog([string]$Message) { try { $line = "[{0:O}] pid={1} tid={2} {3}{4}" -f [DateTimeOffset]::UtcNow, $PID, [System.Threading.Thread]::CurrentThread.ManagedThreadId, $Message, [Environment]::NewLine; [IO.File]::AppendAllText($script:AidaBootstrapLogPath, $line, [Text.Encoding]::UTF8) } catch { } }',
        'try { $logDir = [IO.Path]::GetDirectoryName($AidaBootstrapLogPath); if ($logDir -and -not [IO.Directory]::Exists($logDir)) { [IO.Directory]::CreateDirectory($logDir) | Out-Null }; [IO.File]::WriteAllText($AidaBootstrapLogPath, ("AiDA bootstrap log started {0:O} pid={1} powershell={2}{3}" -f [DateTimeOffset]::UtcNow, $PID, $PSVersionTable.PSVersion.ToString(), [Environment]::NewLine), [Text.Encoding]::UTF8) } catch { }',
        '$script:AidaBootstrapStartUtc = [DateTimeOffset]::UtcNow',
        'try { Write-AidaBootstrapLog ("script_entry exe=" + [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) } catch { Write-AidaBootstrapLog "script_entry" }',
        'Write-AidaBootstrapLog "direct_log_ready"',
        'if ($PSVersionTable.PSEdition -and $PSVersionTable.PSEdition -ne "Desktop") { Write-AidaBootstrapLog ("unsupported_powershell_edition=" + $PSVersionTable.PSEdition); throw "AiDA bootstrap requires Windows PowerShell 5.1. Run it from powershell.exe, not pwsh." }',
        'if ($PSVersionTable.PSVersion.Major -lt 5) { Write-AidaBootstrapLog ("unsupported_powershell_version=" + $PSVersionTable.PSVersion.ToString()); throw "AiDA bootstrap requires Windows PowerShell 5.1 or newer." }',
        '$ProgressPreference = "Continue"',
        '$AidaBootstrapServer = ' + psQuote(origin),
        '$AidaPinnedSpkiSha256 = ' + psQuote(tlsSpki),
        '$AidaPinnedCertSha256 = ' + psQuote(tlsCert),
        '$AidaRequireTlsPin = $' + (requireTlsPin ? 'true' : 'false'),
        '$AidaMaxSidecarBytes = ' + String(MAX_CAMOUFOX_SIDECAR_BYTES),
        '$AidaManifestP256X = ' + psQuote(p256.x),
        '$AidaManifestP256Y = ' + psQuote(p256.y),
        'function Write-AidaStatus([string]$Message) { Write-AidaBootstrapLog ("status " + $Message); Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) -ForegroundColor Cyan }',
        'function Set-AidaProcessEnvValue([string]$Name,$Value) { [Environment]::SetEnvironmentVariable($Name, $Value, "Process"); if ($null -eq $Value) { Remove-Item -Path ("Env:\\" + $Name) -ErrorAction SilentlyContinue } else { Set-Item -Path ("Env:\\" + $Name) -Value $Value } }',
        'function Get-AidaLocalAppDataDirectory { $d = [Environment]::GetFolderPath("LocalApplicationData"); if (-not $d) { $d = [Environment]::GetEnvironmentVariable("LOCALAPPDATA") }; if (-not $d) { throw "LOCALAPPDATA is unavailable for AiDA Camoufox setup." }; if (-not [IO.Directory]::Exists($d)) { [IO.Directory]::CreateDirectory($d) | Out-Null }; return $d }',
        'function ConvertTo-AidaHex([byte[]]$Bytes) { -join ($Bytes | ForEach-Object { $_.ToString("x2") }) }',
        'function ConvertFrom-AidaHex([string]$Hex) { if (-not $Hex -or ($Hex.Length % 2) -ne 0 -or $Hex -notmatch "^[0-9a-fA-F]+$") { throw "AiDA invalid hex value." }; $b = New-Object byte[] ($Hex.Length / 2); for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }; $b }',
        'function Test-AidaBytesEqual([byte[]]$A, [byte[]]$B) { if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }; $d = 0; for ($i = 0; $i -lt $A.Length; $i++) { $d = $d -bor ($A[$i] -bxor $B[$i]) }; return $d -eq 0 }',
        'function Test-AidaHexEqual([string]$A, [string]$B) { try { $ab = ConvertFrom-AidaHex $A; $bb = ConvertFrom-AidaHex $B; Test-AidaBytesEqual $ab $bb } catch { $false } }',
        'function New-AidaNonce { $b = New-Object byte[] 32; $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); try { $rng.GetBytes($b); ConvertTo-AidaHex $b } finally { $rng.Dispose() } }',
        'function Get-AidaUtf8Bytes([string]$Text) { if ($null -eq $Text) { $Text = "" }; [Text.Encoding]::UTF8.GetBytes($Text) }',
        'function Normalize-AidaWhitespace([string]$Text) { if ($null -eq $Text) { return "" }; return ($Text.Trim() -replace "\\s+", " ") }',
        'function Normalize-AidaUpperWhitespace([string]$Text) { $v = Normalize-AidaWhitespace $Text; if (-not $v) { return "" }; return $v.ToUpperInvariant() }',
        'function Normalize-AidaSerial([string]$Text) { if ($null -eq $Text) { return "" }; $v = $Text.Trim(); if (-not $v) { return "" }; return $v.ToUpperInvariant() }',
        'function Normalize-AidaMac([string]$Text) { if ($null -eq $Text) { return "" }; $v = (($Text.ToString()) -replace "[^0-9A-Fa-f]", "").ToUpperInvariant(); if ($v.Length -lt 12) { return "" }; $v = $v.Substring(0, 12); if ($v -match "^(0{12}|F{12})$") { return "" }; return $v }',
        'function Get-AidaRegistryString([string]$SubKey,[string]$Name) { $base = $null; $key = $null; try { $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64); $key = $base.OpenSubKey($SubKey); if (-not $key) { return "" }; $v = $key.GetValue($Name, ""); if ($null -eq $v) { return "" }; return [string]$v } catch { return "" } finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } } }',
        'function Get-AidaCimItems([string]$Class,[string]$Filter) { try { if ($Filter) { return @(Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop) }; return @(Get-CimInstance -ClassName $Class -ErrorAction Stop) } catch { try { if ($Filter) { return @(Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop) }; return @(Get-WmiObject -Class $Class -ErrorAction Stop) } catch { return @() } } }',
        'function Get-AidaFirstCimValue([string]$Class,[string]$Property,[string]$Filter) { foreach ($item in (Get-AidaCimItems $Class $Filter)) { try { $v = $item.$Property; if ($null -ne $v) { $s = [string]$v; if ($s.Trim()) { return $s } } } catch { } }; return "" }',
        'function Get-AidaSmbiosUuidFactor { $u = (Get-AidaFirstCimValue "Win32_ComputerSystemProduct" "UUID" "").Trim(); if ($u -notmatch "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$") { return "" }; $h = $u -replace "-", ""; if ($h -match "^(0{32}|F{32}|f{32})$") { return "" }; return $u.ToLowerInvariant() }',
        'function Get-AidaBaseboardSerialFactor { Normalize-AidaSerial (Get-AidaFirstCimValue "Win32_BaseBoard" "SerialNumber" "") }',
        'function Get-AidaChassisSerialFactor { $v = Get-AidaFirstCimValue "Win32_SystemEnclosure" "SerialNumber" ""; Normalize-AidaSerial $v }',
        'function Get-AidaDiskSerialFactor { $items = Get-AidaCimItems "Win32_DiskDrive" ""; $disk = $items | Where-Object { try { [int]$_.Index -eq 0 } catch { $false } } | Select-Object -First 1; if (-not $disk) { $disk = $items | Select-Object -First 1 }; if (-not $disk) { return "" }; Normalize-AidaSerial ([string]$disk.SerialNumber) }',
        'function Get-AidaMacFactor { $candidates = New-Object System.Collections.ArrayList; try { foreach ($a in @(Get-NetAdapter -ErrorAction Stop)) { $desc = [string]$a.InterfaceDescription; if ($desc -match "Loopback|Tunnel") { continue }; $p = Normalize-AidaMac ([string]$a.PermanentAddress); if ($p) { [void]$candidates.Add([pscustomobject]@{ value = $p; permanent = $true }) }; $m = Normalize-AidaMac ([string]$a.MacAddress); if ($m) { [void]$candidates.Add([pscustomobject]@{ value = $m; permanent = $false }) } } } catch { }; if ($candidates.Count -eq 0) { foreach ($a in (Get-AidaCimItems "Win32_NetworkAdapter" "MACAddress IS NOT NULL")) { $kind = [string]$a.AdapterType; if ($kind -match "Loopback|Tunnel") { continue }; $m = Normalize-AidaMac ([string]$a.MACAddress); if ($m) { [void]$candidates.Add([pscustomobject]@{ value = $m; permanent = $false }) } } }; if ($candidates.Count -eq 0) { return "" }; $selected = $candidates | Sort-Object -Property @{ Expression = { if ($_.permanent) { 0 } else { 1 } } }, value -Unique | Select-Object -First 1; return [string]$selected.value }',
        'function Get-AidaCpuBrandFactor { Normalize-AidaUpperWhitespace (Get-AidaFirstCimValue "Win32_Processor" "Name" "") }',
        'function Get-AidaMachineGuidFactor { $v = Normalize-AidaWhitespace (Get-AidaRegistryString "SOFTWARE\\Microsoft\\Cryptography" "MachineGuid"); if (-not $v) { return "" }; return $v.ToLowerInvariant() }',
        'function Get-AidaInstallationGuidFactor { $v = Get-AidaRegistryString "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" "InstallationGUID"; if (-not $v) { $v = Get-AidaRegistryString "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" "InstallationID" }; if (-not $v) { $v = Get-AidaRegistryString "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" "InstallationID" }; $v = Normalize-AidaWhitespace $v; if (-not $v) { return "" }; return $v.ToLowerInvariant() }',
        'function Add-AidaHwidBytes([System.Collections.Generic.List[byte]]$Buffer,[byte[]]$Bytes) { if ($null -eq $Bytes) { $Bytes = New-Object byte[] 0 }; $len = [Math]::Min([int]$Bytes.Length, 65535); $Buffer.Add([byte]($len -band 255)); $Buffer.Add([byte](($len -shr 8) -band 255)); for ($i = 0; $i -lt $len; $i++) { $Buffer.Add($Bytes[$i]) } }',
        'function Get-AidaBootstrapHwid { $factors = @((Get-AidaSmbiosUuidFactor), (Get-AidaBaseboardSerialFactor), (Get-AidaChassisSerialFactor), (Get-AidaDiskSerialFactor), (Get-AidaMacFactor), (Get-AidaCpuBrandFactor), (Get-AidaMachineGuidFactor), (Get-AidaInstallationGuidFactor), "no_tpm"); $collected = 0; foreach ($f in $factors) { if ($f) { $collected++ } }; if ($collected -lt 5) { throw "AiDA bootstrap HWID collection failed." }; $buf = New-Object "System.Collections.Generic.List[byte]"; $buf.AddRange([byte[]](2,0,0,0)); foreach ($f in $factors) { Add-AidaHwidBytes $buf (Get-AidaUtf8Bytes ([string]$f)) }; $sha = [Security.Cryptography.SHA256]::Create(); try { $bytes = $buf.ToArray(); $hwid = ConvertTo-AidaHex ($sha.ComputeHash($bytes)); if (-not $hwid -or $hwid -notmatch "^[0-9a-f]{64}$") { throw "AiDA bootstrap HWID hash is invalid." }; return $hwid } finally { if ($sha) { $sha.Dispose() }; if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) } } }',
        'function Get-AidaSecureText([string]$Prompt) { $s = Read-Host $Prompt -AsSecureString; $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { if ($p -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) } } }',
        'function Get-AidaTlsHashes([string]$Target) { $u = [Uri]$Target; $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($u.Host, $(if ($u.Port -gt 0) { $u.Port } else { 443 })); try { $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, { param($sender,$cert,$chain,$errors) return ($errors -eq [Net.Security.SslPolicyErrors]::None) }); $ssl.AuthenticateAsClient($u.Host); $cert2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate); $sha = [Security.Cryptography.SHA256]::Create(); try { $certHash = ConvertTo-AidaHex ($sha.ComputeHash($cert2.RawData)); $spkiHash = ""; try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert2); if ($rsa -and $rsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($rsa.ExportSubjectPublicKeyInfo())) } } catch { } try { if (-not $spkiHash) { $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert2); if ($ecdsa -and $ecdsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($ecdsa.ExportSubjectPublicKeyInfo())) } } } catch { } if(-not $spkiHash){try{$pk=$cert2.PublicKey;$od=$pk.Oid.Value;$ob=if($od-eq"1.2.840.10045.2.1"){[byte[]]@(6,7,42,134,72,206,61,2,1)}elseif($od-eq"1.2.840.113549.1.1.1"){[byte[]]@(6,9,42,134,72,134,247,13,1,1,1)}else{$null};if($ob){$dl={param($n)if($n-lt128){[byte[]]@($n)}elseif($n-le255){[byte[]]@(129,$n)}else{[byte[]]@(130,($n-shr8),($n-band255))}};$ap=[byte[]]$pk.EncodedParameters.RawData;$kb=[byte[]]$pk.EncodedKeyValue.RawData;$ai=$ob+$ap;$as=[byte[]]@(48)+(& $dl $ai.Length)+$ai;$bs=[byte[]]@(3)+(& $dl (1+$kb.Length))+[byte[]]@(0)+$kb;$si=[byte[]]($as+$bs);$sb=[byte[]]@(48)+(& $dl $si.Length)+$si;$spkiHash=ConvertTo-AidaHex($sha.ComputeHash($sb))}}catch{}} [pscustomobject]@{ cert_sha256 = $certHash; spki_sha256 = $spkiHash } } finally { $sha.Dispose(); $cert2.Dispose(); $ssl.Dispose() } } finally { $tcp.Dispose() } }',
        'function Assert-AidaTlsPin { if (-not $AidaPinnedSpkiSha256 -and -not $AidaPinnedCertSha256) { if ($AidaRequireTlsPin) { throw "AiDA bootstrap TLS pin is not configured." }; return }; $h = Get-AidaTlsHashes $AidaBootstrapServer; if ($AidaPinnedSpkiSha256 -and $h.spki_sha256 -and ($h.spki_sha256.ToLowerInvariant() -eq $AidaPinnedSpkiSha256.ToLowerInvariant())) { return }; if ($AidaPinnedCertSha256 -and ($h.cert_sha256.ToLowerInvariant() -eq $AidaPinnedCertSha256.ToLowerInvariant())) { return }; throw "AiDA bootstrap TLS pin verification failed." }',
        'function Enable-AidaPinnedTls { $script:AidaPinnedHost = ([Uri]$AidaBootstrapServer).Host; [Net.ServicePointManager]::ServerCertificateValidationCallback = { param($sender,$cert,$chain,$errors) try { if ($errors -ne [Net.Security.SslPolicyErrors]::None) { return $false }; $cert2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert); $sha = [Security.Cryptography.SHA256]::Create(); try { $certHash = ConvertTo-AidaHex ($sha.ComputeHash($cert2.RawData)); if ($AidaPinnedCertSha256 -and ($certHash.ToLowerInvariant() -eq $AidaPinnedCertSha256.ToLowerInvariant())) { return $true }; if ($AidaPinnedSpkiSha256) { $spkiHash = ""; try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert2); if ($rsa -and $rsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($rsa.ExportSubjectPublicKeyInfo())) } } catch { }; try { if (-not $spkiHash) { $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert2); if ($ecdsa -and $ecdsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($ecdsa.ExportSubjectPublicKeyInfo())) } } } catch { }; if(-not $spkiHash){try{$pk=$cert2.PublicKey;$od=$pk.Oid.Value;$ob=if($od-eq"1.2.840.10045.2.1"){[byte[]]@(6,7,42,134,72,206,61,2,1)}elseif($od-eq"1.2.840.113549.1.1.1"){[byte[]]@(6,9,42,134,72,134,247,13,1,1,1)}else{$null};if($ob){$dl={param($n)if($n-lt128){[byte[]]@($n)}elseif($n-le255){[byte[]]@(129,$n)}else{[byte[]]@(130,($n-shr8),($n-band255))}};$ap=[byte[]]$pk.EncodedParameters.RawData;$kb=[byte[]]$pk.EncodedKeyValue.RawData;$ai=$ob+$ap;$as=[byte[]]@(48)+(& $dl $ai.Length)+$ai;$bs=[byte[]]@(3)+(& $dl (1+$kb.Length))+[byte[]]@(0)+$kb;$si=[byte[]]($as+$bs);$sb=[byte[]]@(48)+(& $dl $si.Length)+$si;$spkiHash=ConvertTo-AidaHex($sha.ComputeHash($sb))}}catch{}}; if ($spkiHash -and ($spkiHash.ToLowerInvariant() -eq $AidaPinnedSpkiSha256.ToLowerInvariant())) { return $true } }; return (-not $AidaRequireTlsPin -and -not $AidaPinnedCertSha256 -and -not $AidaPinnedSpkiSha256) } finally { $sha.Dispose(); $cert2.Dispose() } } catch { return $false } } }',
        'function Invoke-AidaJson([string]$Path, [object]$Body) { $json = $null; $bytes = $null; $req = $null; $resp = $null; $rs = $null; try { Write-AidaBootstrapLog ("http_post path=" + $Path); $json = $Body | ConvertTo-Json -Depth 8 -Compress; $bytes = [Text.Encoding]::UTF8.GetBytes($json); $req = [Net.HttpWebRequest]::Create($AidaBootstrapServer + $Path); $req.Method = "POST"; $req.UserAgent = "AiDA Bootstrap"; $req.ContentType = "application/json"; $req.AllowAutoRedirect = $false; $req.Timeout = 60000; $req.ReadWriteTimeout = 60000; $req.ContentLength = $bytes.Length; $rs = $req.GetRequestStream(); try { $rs.Write($bytes, 0, $bytes.Length) } finally { if ($rs) { $rs.Dispose(); $rs = $null } }; try { $resp = $req.GetResponse() } catch [Net.WebException] { $status = 0; $wresp = $_.Exception.Response; try { if ($wresp) { $status = [int]$wresp.StatusCode } } finally { if ($wresp) { $wresp.Dispose() } }; Write-AidaBootstrapLog ("http_response_error path=" + $Path + " status=" + $status); if ($Path -eq "/api/bootstrap/authorize" -and ($status -eq 401 -or $status -eq 403)) { throw "AiDA bootstrap authorization failed. Verify the license key and machine binding." }; throw "AiDA bootstrap API request failed." }; Write-AidaBootstrapLog ("http_response path=" + $Path + " status=" + [int]$resp.StatusCode); if ([int]$resp.StatusCode -ne 200) { throw "AiDA bootstrap API request failed." }; $reader = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8); try { $text = $reader.ReadToEnd(); $text | ConvertFrom-Json } finally { $reader.Dispose(); $text = $null } } catch { Write-AidaBootstrapLog ("http_error path=" + $Path + " error=" + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); throw } finally { if ($resp) { $resp.Dispose() }; if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }; $json = $null } }',
        'function Get-AidaTokenId([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; $m.Groups[1].Value.ToLowerInvariant() }',
        'function Get-AidaTokenSecretBytes([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; ConvertFrom-AidaHex $m.Groups[2].Value }',
        'function Get-AidaTokenParts([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; [pscustomobject]@{ id = $m.Groups[1].Value.ToLowerInvariant(); secret = $m.Groups[2].Value.ToLowerInvariant() } }',
        'function Get-AidaManifestMacInput([object]$M) { @("AIDABOOTMANIFEST.v1", [string]$M.token_id, [string]$M.issued_at, [string]$M.expires_at, [string]$M.artifact.name, [string]$M.artifact.version, [string]$M.artifact.url, [string]$M.artifact.sha256, [string]$M.artifact.size, [string]$M.artifact.package.format, [string]$M.artifact.package.sha256, [string]$M.artifact.package.size, [string]$M.artifact.package.enc_key_b64, [string]$M.artifact.package.mac_key_b64, $(if ($M.artifact.authenticode.required) { "1" } else { "0" }), [string]$M.artifact.authenticode.signer_thumbprint, $(if ($M.artifact.authenticode.accept_pinned_private_ca) { "1" } else { "0" }), $(if ($M.camoufox.configured) { "1" } else { "0" }), [string]$M.camoufox.version, [string]$M.camoufox.url, [string]$M.camoufox.sha256, [string]$M.camoufox.size, [string]$M.camoufox.executable_rel, [string]$M.camoufox.python_rel, $(if ($M.camoufox.mcp.configured) { "1" } else { "0" }), [string]$M.camoufox.mcp.version, [string]$M.camoufox.mcp.url, [string]$M.camoufox.mcp.sha256, [string]$M.camoufox.mcp.size, [string]$M.camoufox.mcp.rel, $(if ($M.policy.one_time_token) { "1" } else { "0" }), $(if ($M.policy.token_bound_to_client_nonce) { "1" } else { "0" }), $(if ($M.policy.token_bound_to_source_ip) { "1" } else { "0" }), $(if ($M.policy.artifact_https_required) { "1" } else { "0" }), $(if ($M.policy.no_public_binary_route) { "1" } else { "0" }), $(if ($M.policy.encrypted_public_artifact) { "1" } else { "0" }), $(if ($M.policy.camoufox_sidecar_hash_required) { "1" } else { "0" }), $(if ($M.policy.camoufox_mcp_hash_required) { "1" } else { "0" })) -join "`n" }',
        'function Get-AidaHmacHex([string]$KeyHex, [string]$Data) { $key = ConvertFrom-AidaHex $KeyHex; $h = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$key); try { ConvertTo-AidaHex ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) } finally { $h.Dispose(); [Array]::Clear($key, 0, $key.Length) } }',
        'function Get-AidaHmacHexFromBytes([byte[]]$Key, [string]$Data) { $h = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$Key); try { ConvertTo-AidaHex ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) } finally { $h.Dispose() } }',
        'function Test-AidaP256Signature([string]$Data, [string]$SignatureHex) { if (-not $AidaManifestP256X -or -not $AidaManifestP256Y) { throw "AiDA manifest signature key is not configured." }; $x = ConvertFrom-AidaHex $AidaManifestP256X; $y = ConvertFrom-AidaHex $AidaManifestP256Y; $sig = ConvertFrom-AidaHex $SignatureHex; $blob = New-Object byte[] 72; try { if ($x.Length -ne 32 -or $y.Length -ne 32 -or $sig.Length -ne 64) { return $false }; $magic = [BitConverter]::GetBytes([uint32]0x31534345); $size = [BitConverter]::GetBytes([uint32]32); [Array]::Copy($magic, 0, $blob, 0, 4); [Array]::Copy($size, 0, $blob, 4, 4); [Array]::Copy($x, 0, $blob, 8, 32); [Array]::Copy($y, 0, $blob, 40, 32); $key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob); $ecdsa = New-Object Security.Cryptography.ECDsaCng($key); try { $ecdsa.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256; $ecdsa.VerifyData([Text.Encoding]::UTF8.GetBytes($Data), $sig) } finally { $ecdsa.Dispose(); $key.Dispose() } } catch { $false } finally { [Array]::Clear($x, 0, $x.Length); [Array]::Clear($y, 0, $y.Length); [Array]::Clear($sig, 0, $sig.Length); [Array]::Clear($blob, 0, $blob.Length) } }',
        'function Join-AidaSafeChildPath([string]$Root, [string]$Rel) {',
        '    if (-not $Root -or -not $Rel -or [IO.Path]::IsPathRooted($Rel) -or $Rel.Contains(":") -or $Rel.Contains("..")) { throw "AiDA sidecar relative path is invalid." }',
        '    $rootFull = [IO.Path]::GetFullPath($Root)',
        '    $candidate = [IO.Path]::GetFullPath((Join-Path $rootFull $Rel))',
        '    $rootNorm = $rootFull.TrimEnd([char][IO.Path]::DirectorySeparatorChar).TrimEnd([char][IO.Path]::AltDirectorySeparatorChar)',
        '    $prefix = $rootNorm + [IO.Path]::DirectorySeparatorChar',
        '    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "AiDA sidecar path escaped install root." }',
        '    return $candidate',
        '}',
        'function Save-AidaVerifiedSidecarFile([Uri]$Uri, [string]$Path, [long]$ExpectedSize, [string]$ExpectedSha256) {',
        '    Write-AidaBootstrapLog ("camoufox_sidecar_download_start host=" + $Uri.Host + " expected_size=" + $ExpectedSize)',
        '    if ($Uri.Scheme -ne "https") { throw "AiDA Camoufox sidecar URL must use HTTPS." }',
        '    if ($ExpectedSize -le 0 -or $ExpectedSize -gt $AidaMaxSidecarBytes) { throw "AiDA Camoufox sidecar size is not allowed." }',
        '    if (-not $ExpectedSha256 -or $ExpectedSha256 -notmatch "^[0-9a-fA-F]{64}$") { throw "AiDA Camoufox sidecar SHA-256 metadata is invalid." }',
        '    $req = $null; $resp = $null; $stream = $null; $fs = $null; $sha = $null; $readFs = $null; $buf = New-Object byte[] 1048576; $ok = $false; $done = [int64]0; $attempt = 0; $maxAttempts = 10; $progressNext = [int64]0; $sw = [Diagnostics.Stopwatch]::StartNew()',
        '    try {',
        '        if ([IO.File]::Exists($Path)) { [IO.File]::Delete($Path) }',
        '        while ($done -lt $ExpectedSize) {',
        '            $attempt++',
        '            $before = $done',
        '            try {',
        '                $req = [Net.HttpWebRequest]::Create($Uri.AbsoluteUri)',
        '                $req.Method = "GET"',
        '                $req.UserAgent = "AiDA Bootstrap"',
        '                $req.AllowAutoRedirect = $false',
        '                $req.Timeout = 900000',
        '                $req.ReadWriteTimeout = 900000',
        '                try { $req.AllowReadStreamBuffering = $false } catch { }',
        '                if ($done -gt 0) { try { $req.AddRange([int64]$done) } catch { $req.Headers["Range"] = ("bytes={0}-" -f $done) } }',
        '                Write-AidaBootstrapLog ("camoufox_sidecar_download_attempt attempt={0} offset={1}" -f $attempt,$done)',
        '                $resp = $req.GetResponse()',
        '                $status = [int]$resp.StatusCode',
        '                Write-AidaBootstrapLog ("camoufox_sidecar_download_response attempt={0} status={1} content_length={2} range={3}" -f $attempt,$status,$resp.ContentLength,$resp.Headers["Content-Range"])',
        '                if ($done -eq 0) { if ($status -ne 200 -and $status -ne 206) { throw "AiDA Camoufox sidecar download failed." }; if ($status -eq 200 -and $resp.ContentLength -ge 0 -and [int64]$resp.ContentLength -ne $ExpectedSize) { throw "AiDA Camoufox sidecar size mismatch." } }',
        '                else { if ($status -eq 200) { Write-AidaBootstrapLog ("camoufox_sidecar_range_unsupported_restart attempt={0} old_offset={1}" -f $attempt,$done); $done = 0; $before = 0; $progressNext = 0 } elseif ($status -ne 206) { throw "AiDA Camoufox sidecar resume failed." } }',
        '                $stream = $resp.GetResponseStream()',
        '                $fs = [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)',
        '                $fs.SetLength($done)',
        '                $null = $fs.Seek($done, [IO.SeekOrigin]::Begin)',
        '                while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {',
        '                    if ($done + $read -gt $ExpectedSize) { throw "AiDA Camoufox sidecar exceeded expected size." }',
        '                    $fs.Write($buf, 0, $read)',
        '                    $done += $read',
        '                    $pct = [Math]::Min(100, [Math]::Round(($done * 100.0) / $ExpectedSize, 1))',
        '                    if ($done -ge $progressNext -or $done -eq $ExpectedSize) { $elapsedMs = [Math]::Max(1, [int64]$sw.ElapsedMilliseconds); $rate = [int64](($done * 1000.0) / $elapsedMs); Write-AidaBootstrapLog ("camoufox_sidecar_download_progress bytes={0} expected={1} pct={2} elapsed_ms={3} rate_bps={4} attempt={5}" -f $done,$ExpectedSize,$pct,$elapsedMs,$rate,$attempt); $progressNext = $done + 5242880 }',
        '                    Write-Progress -Activity "Downloading Camoufox sidecar" -Status ("{0:N1} MB / {1:N1} MB" -f ($done / 1MB), ($ExpectedSize / 1MB)) -PercentComplete $pct',
        '                }',
        '                if ($fs) { $fs.Dispose(); $fs = $null }',
        '                if ($stream) { $stream.Dispose(); $stream = $null }',
        '                if ($resp) { $resp.Dispose(); $resp = $null }',
        '                if ($done -lt $ExpectedSize) { Write-AidaBootstrapLog ("camoufox_sidecar_download_attempt_incomplete attempt={0} before={1} after={2} expected={3}" -f $attempt,$before,$done,$ExpectedSize) }',
        '            } catch {',
        '                Write-AidaBootstrapLog ("camoufox_sidecar_download_attempt_error attempt={0} bytes={1} expected={2} elapsed_ms={3} error={4}: {5}" -f $attempt,$done,$ExpectedSize,[int64]$sw.ElapsedMilliseconds,$_.Exception.GetType().FullName,$_.Exception.Message)',
        '                if ($attempt -ge $maxAttempts) { throw }',
        '            } finally {',
        '                if ($fs) { $fs.Dispose(); $fs = $null }',
        '                if ($stream) { $stream.Dispose(); $stream = $null }',
        '                if ($resp) { $resp.Dispose(); $resp = $null }',
        '            }',
        '            if ($done -lt $ExpectedSize) { if ($attempt -ge $maxAttempts) { throw "AiDA Camoufox sidecar download size mismatch." }; Start-Sleep -Seconds ([Math]::Min(20, 2 * $attempt)) }',
        '        }',
        '        $item = Get-Item -LiteralPath $Path -ErrorAction Stop',
        '        if ([int64]$item.Length -ne [int64]$ExpectedSize) { Write-AidaBootstrapLog ("camoufox_sidecar_download_file_size_mismatch bytes={0} expected={1}" -f $item.Length,$ExpectedSize); throw "AiDA Camoufox sidecar download size mismatch." }',
        '        $sha = [Security.Cryptography.SHA256]::Create()',
        '        $readFs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)',
        '        $actualSha256 = ConvertTo-AidaHex ($sha.ComputeHash($readFs))',
        '        if (-not (Test-AidaHexEqual $actualSha256 $ExpectedSha256)) { throw "AiDA Camoufox sidecar SHA-256 verification failed." }',
        '        Write-AidaBootstrapLog ("camoufox_sidecar_download_complete bytes={0} elapsed_ms={1} sha256={2} attempts={3}" -f $done,[int64]$sw.ElapsedMilliseconds,$actualSha256,$attempt)',
        '        $ok = $true',
        '        return $Path',
        '    } catch { Write-AidaBootstrapLog ("camoufox_sidecar_download_error bytes={0} expected={1} elapsed_ms={2} attempts={3} error={4}: {5}" -f $done,$ExpectedSize,[int64]$sw.ElapsedMilliseconds,$attempt,$_.Exception.GetType().FullName,$_.Exception.Message); throw } finally {',
        '        if ($readFs) { $readFs.Dispose() }',
        '        if ($sha) { $sha.Dispose() }',
        '        if ($fs) { $fs.Dispose() }',
        '        if ($stream) { $stream.Dispose() }',
        '        if ($resp) { $resp.Dispose() }',
        '        if ($buf) { [Array]::Clear($buf, 0, $buf.Length) }',
        '        if (-not $ok) { try { if ([IO.File]::Exists($Path)) { [IO.File]::Delete($Path) } } catch { } }',
        '        Write-Progress -Activity "Downloading Camoufox sidecar" -Completed',
        '    }',
        '}',
        'function Get-AidaFileState([string]$Path) {',
        '    if (-not $Path -or -not [IO.File]::Exists($Path)) { return [pscustomobject]@{ path = $Path; exists = $false; size = [int64]-1; sha256 = "" } }',
        '    $fs = $null; $sha = $null; $actualSize = [int64]-1; $actualSha256 = ""',
        '    try {',
        '        $item = Get-Item -LiteralPath $Path -ErrorAction Stop',
        '        $actualSize = [int64]$item.Length',
        '        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)',
        '        $sha = [Security.Cryptography.SHA256]::Create()',
        '        $actualSha256 = ConvertTo-AidaHex ($sha.ComputeHash($fs))',
        '    } catch { Write-AidaBootstrapLog ("file_state_error path=" + $Path + " error=" + $_.Exception.GetType().FullName + ": " + $_.Exception.Message) } finally { if ($sha) { $sha.Dispose() }; if ($fs) { $fs.Dispose() } }',
        '    return [pscustomobject]@{ path = $Path; exists = $true; size = $actualSize; sha256 = $actualSha256 }',
        '}',
        'function Test-AidaVerifiedSidecarFile([string]$Path, [long]$ExpectedSize, [string]$ExpectedSha256, [string]$Label) {',
        '    if (-not $Label) { $Label = "camoufox_sidecar_file" }',
        '    if (-not $Path -or $ExpectedSize -le 0 -or -not $ExpectedSha256 -or $ExpectedSha256 -notmatch "^[0-9a-fA-F]{64}$") { Write-AidaBootstrapLog ($Label + "_expected_invalid path=" + $Path + " expected_size=" + $ExpectedSize + " expected_sha256=" + $ExpectedSha256); return $false }',
        '    $state = Get-AidaFileState $Path',
        '    if (-not $state.exists) { Write-AidaBootstrapLog ($Label + "_missing path=" + $Path + " expected_size=" + $ExpectedSize + " expected_sha256=" + $ExpectedSha256); return $false }',
        '    if ([int64]$state.size -ne [int64]$ExpectedSize) { Write-AidaBootstrapLog ($Label + "_size_mismatch path=" + $Path + " expected_size=" + $ExpectedSize + " actual_size=" + $state.size + " expected_sha256=" + $ExpectedSha256 + " actual_sha256=" + $state.sha256); return $false }',
        '    if (-not $state.sha256 -or -not (Test-AidaHexEqual $state.sha256 $ExpectedSha256)) { Write-AidaBootstrapLog ($Label + "_sha256_mismatch path=" + $Path + " expected_size=" + $ExpectedSize + " actual_size=" + $state.size + " expected_sha256=" + $ExpectedSha256 + " actual_sha256=" + $state.sha256); return $false }',
        '    Write-AidaBootstrapLog ($Label + "_verified path=" + $Path + " expected_size=" + $ExpectedSize + " actual_size=" + $state.size + " expected_sha256=" + $ExpectedSha256 + " actual_sha256=" + $state.sha256)',
        '    return $true',
        '}',
        'function Find-AidaCamoufoxMcpExecutable([string]$Root) {',
        '    $rels = @("deps\\AiDA_CamoufoxReverseMcp.exe","deps\\camoufox-reverse-mcp.exe","deps\\camoufox_reverse_mcp.exe","deps\\camoufox-reverse-mcp\\AiDA_CamoufoxReverseMcp.exe","deps\\camoufox-reverse-mcp\\camoufox-reverse-mcp.exe","AiDA_CamoufoxReverseMcp.exe","camoufox-reverse-mcp.exe","camoufox_reverse_mcp.exe")',
        '    foreach ($rel in $rels) { $p = Join-AidaSafeChildPath $Root $rel; if ([IO.File]::Exists($p)) { return $p } }',
        '    return ""',
        '}',
        'function Get-AidaCamoufoxMcpExpected([object]$Manifest, [string]$Root) {',
        '    if (-not $Manifest.camoufox -or -not $Manifest.camoufox.mcp -or -not $Manifest.camoufox.mcp.configured) { return [pscustomobject]@{ configured = $false; path = ""; rel = ""; version = ""; size = [int64]0; sha256 = "" } }',
        '    $m = $Manifest.camoufox.mcp',
        '    $rel = if ([string]$m.rel) { [string]$m.rel } else { "deps\\AiDA_CamoufoxReverseMcp.exe" }',
        '    return [pscustomobject]@{ configured = $true; path = (Join-AidaSafeChildPath $Root $rel); rel = $rel; version = [string]$m.version; size = [int64]$m.size; sha256 = [string]$m.sha256 }',
        '}',
        'function Get-AidaCamoufoxMcpLogSuffix([object]$Manifest, [string]$Root, [string]$McpPath) {',
        '    $expected = Get-AidaCamoufoxMcpExpected $Manifest $Root',
        '    $actualPath = if ($McpPath) { $McpPath } else { "" }',
        '    $state = Get-AidaFileState $actualPath',
        '    $actualSize = if ($state.exists) { [string]$state.size } else { "" }',
        '    return (" mcp_expected_path=" + $expected.path + " mcp_expected_size=" + $expected.size + " mcp_expected_sha256=" + $expected.sha256 + " mcp_expected_version=" + $expected.version + " mcp_actual_path=" + $actualPath + " mcp_actual_size=" + $actualSize + " mcp_actual_sha256=" + $state.sha256)',
        '}',
        'function Test-AidaCamoufoxMcpExecutable([string]$McpPath, [string]$ExePath, [string]$Root) {',
        '    if (-not $McpPath -or -not [IO.File]::Exists($McpPath)) { Write-AidaBootstrapLog "camoufox_mcp_static_missing"; return $false }',
        '    $fs = $null',
        '    try {',
        '        $item = Get-Item -LiteralPath $McpPath -ErrorAction Stop',
        '        if ($item.Length -le 4096) { Write-AidaBootstrapLog ("camoufox_mcp_static_too_small bytes=" + $item.Length); return $false }',
        '        $mcpDir = [IO.Path]::GetDirectoryName($McpPath)',
        '        if ($mcpDir -and [IO.Directory]::Exists((Join-Path $mcpDir "_internal"))) { Write-AidaBootstrapLog ("camoufox_mcp_static_onedir_runtime_disallowed dir=" + (Join-Path $mcpDir "_internal")); return $false }',
        '        if ($item.Length -lt 33554432) { Write-AidaBootstrapLog ("camoufox_mcp_static_self_contained_too_small bytes=" + $item.Length); return $false }',
        '        $fs = [IO.File]::Open($McpPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)',
        '        $hdr = New-Object byte[] 4096',
        '        $read = $fs.Read($hdr, 0, $hdr.Length)',
        '        if ($read -lt 0x40 -or $hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { Write-AidaBootstrapLog "camoufox_mcp_static_bad_mz"; return $false }',
        '        $lfanew = [BitConverter]::ToInt32($hdr, 0x3C)',
        '        if ($lfanew -lt 0x40 -or ($lfanew + 6) -ge $read) { Write-AidaBootstrapLog ("camoufox_mcp_static_bad_lfanew value=" + $lfanew); return $false }',
        '        if ($hdr[$lfanew] -ne 0x50 -or $hdr[$lfanew + 1] -ne 0x45 -or $hdr[$lfanew + 2] -ne 0 -or $hdr[$lfanew + 3] -ne 0) { Write-AidaBootstrapLog "camoufox_mcp_static_bad_pe"; return $false }',
        '        $machine = [BitConverter]::ToUInt16($hdr, $lfanew + 4)',
        '        if ($machine -ne 0x8664) { Write-AidaBootstrapLog ("camoufox_mcp_static_bad_machine machine=0x{0:X4}" -f $machine); return $false }',
        '        Write-AidaBootstrapLog ("camoufox_mcp_static_ok path=" + $McpPath + " bytes=" + $item.Length)',
        '        return $true',
        '    } catch { Write-AidaBootstrapLog ("camoufox_mcp_static_error " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); return $false } finally {',
        '        if ($fs) { $fs.Dispose() }',
        '    }',
        '}',
        'function Test-AidaCamoufoxMcpMatchesManifest([object]$Manifest, [string]$Root, [string]$ExePath, [string]$McpPath, [string]$Mode) {',
        '    $expected = Get-AidaCamoufoxMcpExpected $Manifest $Root',
        '    if (-not $expected.configured) { return $false }',
        '    if (-not $Manifest.policy.camoufox_mcp_hash_required) { Write-AidaBootstrapLog ("camoufox_mcp_manifest_policy_invalid mode=" + $Mode); return $false }',
        '    $actualPath = if ($McpPath) { $McpPath } else { "" }',
        '    Write-AidaBootstrapLog ("camoufox_mcp_manifest_check mode=" + $Mode + " expected_path=" + $expected.path + " expected_size=" + $expected.size + " expected_sha256=" + $expected.sha256 + " expected_version=" + $expected.version + " actual_path=" + $actualPath)',
        '    if (-not $actualPath) { Write-AidaBootstrapLog ("camoufox_mcp_manifest_missing mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $actualPath)); return $false }',
        '    try { $expectedFull = [IO.Path]::GetFullPath($expected.path); $actualFull = [IO.Path]::GetFullPath($actualPath) } catch { Write-AidaBootstrapLog ("camoufox_mcp_manifest_path_error mode=" + $Mode + " error=" + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); return $false }',
        '    if (-not [string]::Equals($expectedFull, $actualFull, [StringComparison]::OrdinalIgnoreCase)) { Write-AidaBootstrapLog ("camoufox_mcp_manifest_path_mismatch mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $actualPath)); return $false }',
        '    if (-not (Test-AidaVerifiedSidecarFile $expected.path $expected.size $expected.sha256 "camoufox_mcp_manifest")) { Write-AidaBootstrapLog ("camoufox_mcp_manifest_hash_failed mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $actualPath)); return $false }',
        '    if (-not (Test-AidaCamoufoxMcpExecutable $expected.path $ExePath $Root)) { Write-AidaBootstrapLog ("camoufox_mcp_manifest_static_failed mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $actualPath)); return $false }',
        '    Write-AidaBootstrapLog ("camoufox_mcp_manifest_ok mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $actualPath))',
        '    return $true',
        '}',
        'function Install-AidaCamoufoxMcpPatch([object]$Manifest, [string]$Root, [string]$ExePath) {',
        '    if (-not $Manifest.camoufox -or -not $Manifest.camoufox.mcp -or -not $Manifest.camoufox.mcp.configured) { return "" }',
        '    if (-not $Manifest.policy.camoufox_mcp_hash_required) { throw "AiDA Camoufox MCP patch policy is invalid." }',
        '    if (-not $Root -or -not [IO.Directory]::Exists($Root) -or -not [IO.File]::Exists($ExePath)) { return "" }',
        '    $m = $Manifest.camoufox.mcp',
        '    $mcpUri = [Uri]$m.url',
        '    $expected = Get-AidaCamoufoxMcpExpected $Manifest $Root',
        '    $target = $expected.path',
        '    Write-AidaBootstrapLog ("camoufox_mcp_patch_manifest target=" + $target + " expected_size=" + $expected.size + " expected_sha256=" + $expected.sha256 + " expected_version=" + $expected.version)',
        '    $state = Get-AidaFileState $target',
        '    if ($state.exists -and [int64]$state.size -eq [int64]$expected.size -and $state.sha256 -and (Test-AidaHexEqual $state.sha256 $expected.sha256) -and (Test-AidaCamoufoxMcpExecutable $target $ExePath $Root)) { Write-AidaBootstrapLog ("camoufox_mcp_patch_current_ok path=" + $target + " expected_size=" + $expected.size + " actual_size=" + $state.size + " expected_sha256=" + $expected.sha256 + " actual_sha256=" + $state.sha256 + " expected_version=" + $expected.version); return $target }',
        '    if ($state.exists) { Write-AidaBootstrapLog ("camoufox_mcp_patch_redownload reason=manifest_mismatch path=" + $target + " expected_size=" + $expected.size + " actual_size=" + $state.size + " expected_sha256=" + $expected.sha256 + " actual_sha256=" + $state.sha256 + " expected_version=" + $expected.version) } else { Write-AidaBootstrapLog ("camoufox_mcp_patch_redownload reason=missing path=" + $target + " expected_size=" + $expected.size + " expected_sha256=" + $expected.sha256 + " expected_version=" + $expected.version) }',
        '    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("aida-camoufox-mcp-" + [Guid]::NewGuid().ToString("N") + ".exe")',
        '    try {',
        '        Write-AidaStatus "Updating Camoufox bridge executable..."',
        '        [void](Save-AidaVerifiedSidecarFile $mcpUri $tmp $expected.size $expected.sha256)',
        '        $targetDir = [IO.Path]::GetDirectoryName($target)',
        '        if ($targetDir -and -not [IO.Directory]::Exists($targetDir)) { [IO.Directory]::CreateDirectory($targetDir) | Out-Null }',
        '        if ([IO.File]::Exists($target)) { try { [IO.File]::Delete($target) } catch { } }',
        '        Move-Item -LiteralPath $tmp -Destination $target -Force',
        '        if (-not (Test-AidaVerifiedSidecarFile $target $expected.size $expected.sha256 "camoufox_mcp_patch_target")) { throw "AiDA Camoufox MCP patch failed manifest check." }',
        '        if (-not (Test-AidaCamoufoxMcpExecutable $target $ExePath $Root)) { throw "AiDA Camoufox MCP patch failed health check." }',
        '        $installed = Get-AidaFileState $target',
        '        Write-AidaBootstrapLog ("camoufox_mcp_patch_installed path=" + $target + " expected_size=" + $expected.size + " actual_size=" + $installed.size + " expected_sha256=" + $expected.sha256 + " actual_sha256=" + $installed.sha256 + " expected_version=" + $expected.version)',
        '        return $target',
        '    } finally {',
        '        try { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } } catch { }',
        '    }',
        '}',
        'function Test-AidaCamoufoxSidecarInstalled([object]$Manifest, [string]$Root, [string]$ExePath, [string]$PythonPath, [string]$McpPath, [string]$Mode) {',
        '    if (-not $Mode) { $Mode = "unknown" }',
        '    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_root root=" + $Root); return $false }',
        '    if (-not [IO.File]::Exists($ExePath)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_exe exe=" + $ExePath); return $false }',
        '    $browserDir = [IO.Path]::GetDirectoryName($ExePath)',
        '    if (-not [IO.File]::Exists((Join-Path $browserDir "application.ini"))) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_application_ini dir=" + $browserDir); return $false }',
        '    if (-not [IO.Directory]::Exists((Join-Path $browserDir "browser"))) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_browser_dir dir=" + $browserDir); return $false }',
        '    if ($PythonPath -and -not [IO.File]::Exists($PythonPath)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_python python=" + $PythonPath); return $false }',
        '    if ($Manifest.camoufox.mcp.configured) { return (Test-AidaCamoufoxMcpMatchesManifest $Manifest $Root $ExePath $McpPath $Mode) }',
        '    if ($McpPath -and (Test-AidaCamoufoxMcpExecutable $McpPath $ExePath $Root)) { Write-AidaBootstrapLog ("camoufox_sidecar_static_mcp_accepted mode=" + $Mode + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $McpPath)); return $true }',
        '    if ($PythonPath -and [IO.File]::Exists($PythonPath)) { Write-AidaBootstrapLog ("camoufox_sidecar_python_bridge_accepted mode=" + $Mode + " python=" + $PythonPath); return $true }',
        '    Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_bridge mode=" + $Mode + " root=" + $Root + (Get-AidaCamoufoxMcpLogSuffix $Manifest $Root $McpPath))',
        '    return $false',
        '}',
        'function Set-AidaCamoufoxEnvironment([string]$ExePath, [string]$PythonPath, [string]$McpPath) {',
        '    if (-not [IO.File]::Exists($ExePath)) { throw "AiDA Camoufox executable is missing after setup." }',
        '    [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_EXECUTABLE", $ExePath, "Process"); $env:AIDA_CAMOUFOX_EXECUTABLE = $ExePath',
        '    if ($McpPath -and [IO.File]::Exists($McpPath)) { [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_MCP_EXECUTABLE", $McpPath, "Process"); $env:AIDA_CAMOUFOX_MCP_EXECUTABLE = $McpPath } else { [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_MCP_EXECUTABLE", $null, "Process"); Remove-Item Env:AIDA_CAMOUFOX_MCP_EXECUTABLE -ErrorAction SilentlyContinue }',
        '    if ($PythonPath -and [IO.File]::Exists($PythonPath)) { [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_PYTHON", $PythonPath, "Process"); $env:AIDA_CAMOUFOX_PYTHON = $PythonPath; [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON", "1", "Process"); $env:AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON = "1" } else { [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_PYTHON", $null, "Process"); Remove-Item Env:AIDA_CAMOUFOX_PYTHON -ErrorAction SilentlyContinue; [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON", $null, "Process"); Remove-Item Env:AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON -ErrorAction SilentlyContinue }',
        '    [Environment]::SetEnvironmentVariable("AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP", "1", "Process"); $env:AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP = "1"',
        '}',
        'function Install-AidaCamoufoxSidecar([object]$Manifest) {',
        '    if (-not $Manifest.camoufox -or -not $Manifest.camoufox.configured) { Write-AidaBootstrapLog "camoufox_sidecar_not_configured"; return }',
        '    if (-not $Manifest.policy.camoufox_sidecar_hash_required) { throw "AiDA Camoufox sidecar policy is invalid." }',
        '    $c = $Manifest.camoufox',
        '    $sidecarUri = [Uri]$c.url',
        '    $expectedSize = [int64]$c.size',
        '    $expectedSha256 = [string]$c.sha256',
        '    $exeRel = [string]$c.executable_rel',
        '    $pythonRel = [string]$c.python_rel',
        '    $localRoot = Join-Path (Get-AidaLocalAppDataDirectory) "AiDA\\Standalone"',
        '    $root = Join-Path $localRoot "camoufox"',
        '    $current = Join-Path $root "current"',
        '    $stampPath = Join-Path $current "aida-camoufox-sidecar.json"',
        '    $exePath = Join-AidaSafeChildPath $current $exeRel',
        '    $pythonPath = if ($pythonRel) { Join-AidaSafeChildPath $current $pythonRel } else { "" }',
        '    $mcpPath = if ([IO.Directory]::Exists($current)) { Find-AidaCamoufoxMcpExecutable $current } else { "" }',
        '    $cached = $false',
        '    $stamp = $null',
        '    if ([IO.File]::Exists($stampPath)) { try { $stamp = Get-Content -LiteralPath $stampPath -Raw | ConvertFrom-Json } catch { Write-AidaBootstrapLog ("camoufox_sidecar_cache_stamp_error " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); $stamp = $null } }',
        '    if ($stamp) { $sidecarStampOk = ([string]$stamp.sha256).ToLowerInvariant() -eq $expectedSha256.ToLowerInvariant() -and [string]$stamp.version -eq [string]$c.version -and [string]$stamp.executable_rel -eq $exeRel -and [string]$stamp.python_rel -eq $pythonRel; $mcpStampOk = $true; if ($c.mcp.configured) { $mcpStampOk = ([string]$stamp.mcp_sha256).ToLowerInvariant() -eq ([string]$c.mcp.sha256).ToLowerInvariant() -and [int64]$stamp.mcp_size -eq [int64]$c.mcp.size -and [string]$stamp.mcp_version -eq [string]$c.mcp.version -and [string]$stamp.mcp_rel -eq [string]$c.mcp.rel }; $cached = $sidecarStampOk -and $mcpStampOk; Write-AidaBootstrapLog ("camoufox_sidecar_cache_probe cached=" + $cached + " sidecar_ok=" + $sidecarStampOk + " mcp_ok=" + $mcpStampOk + " expected_sha256=" + $expectedSha256 + " expected_version=" + [string]$c.version + " expected_mcp_sha256=" + [string]$c.mcp.sha256 + " expected_mcp_size=" + [string]$c.mcp.size + " expected_mcp_version=" + [string]$c.mcp.version) }',
        '    if ([IO.File]::Exists($exePath)) { $patchedMcp = Install-AidaCamoufoxMcpPatch $Manifest $current $exePath; if ($patchedMcp) { $mcpPath = $patchedMcp } }',
        '    $currentSource = if ($cached) { "cached" } else { "existing" }',
        '    if (Test-AidaCamoufoxSidecarInstalled $Manifest $current $exePath $pythonPath $mcpPath $currentSource) { Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath; Write-AidaStatus "Camoufox sidecar ready."; $mcpLog = Get-AidaCamoufoxMcpLogSuffix $Manifest $current $mcpPath; Write-AidaBootstrapLog ("camoufox_sidecar_current_accept source=" + $currentSource + " exe=" + $exePath + " mcp=" + $mcpPath + $mcpLog); if ($cached) { Write-AidaBootstrapLog ("camoufox_sidecar_cached exe=" + $exePath + " mcp=" + $mcpPath + $mcpLog) } else { Write-AidaBootstrapLog ("camoufox_sidecar_existing_usable exe=" + $exePath + " mcp=" + $mcpPath + $mcpLog) }; return }',
        '    if ([IO.Directory]::Exists($current)) { Write-AidaBootstrapLog ("camoufox_sidecar_current_redownload source=" + $currentSource + " reason=validation_failed exe=" + $exePath + " mcp=" + $mcpPath + (Get-AidaCamoufoxMcpLogSuffix $Manifest $current $mcpPath)) } else { Write-AidaBootstrapLog ("camoufox_sidecar_current_redownload source=none reason=missing_current expected_size=" + $expectedSize + " expected_sha256=" + $expectedSha256 + " expected_version=" + [string]$c.version) }',
        '    Write-AidaStatus "Preparing verified Camoufox sidecar..."',
        '    if (-not [IO.Directory]::Exists($root)) { [IO.Directory]::CreateDirectory($root) | Out-Null }',
        '    $id = [Guid]::NewGuid().ToString("N")',
        '    $staging = Join-Path $root ("stage-" + $id)',
        '    $backup = Join-Path $root ("previous-" + $id)',
        '    $zipPath = Join-Path ([IO.Path]::GetTempPath()) ("aida-camoufox-" + $id + ".zip")',
        '    try {',
        '        [IO.Directory]::CreateDirectory($staging) | Out-Null',
        '        [void](Save-AidaVerifiedSidecarFile $sidecarUri $zipPath $expectedSize $expectedSha256)',
        '        Write-AidaStatus "Extracting Camoufox sidecar..."',
        '        Expand-Archive -LiteralPath $zipPath -DestinationPath $staging -Force',
        '        $stageExe = Join-AidaSafeChildPath $staging $exeRel',
        '        $stagePython = if ($pythonRel) { Join-AidaSafeChildPath $staging $pythonRel } else { "" }',
        '        $stageMcp = Install-AidaCamoufoxMcpPatch $Manifest $staging $stageExe',
        '        if (-not $stageMcp -and -not $Manifest.camoufox.mcp.configured) { $stageMcp = Find-AidaCamoufoxMcpExecutable $staging }',
        '        if (-not (Test-AidaCamoufoxSidecarInstalled $Manifest $staging $stageExe $stagePython $stageMcp "redownload")) { throw "AiDA Camoufox sidecar contents are incomplete." }',
        '        $mcpStampSha256 = ""; $mcpStampSize = [int64]0; $mcpStampVersion = ""; $mcpStampRel = ""',
        '        if ($c.mcp.configured) { $mcpStampSha256 = [string]$c.mcp.sha256; $mcpStampSize = [int64]$c.mcp.size; $mcpStampVersion = [string]$c.mcp.version; $mcpStampRel = [string]$c.mcp.rel }',
        '        $stamp = [pscustomobject]@{ sha256 = $expectedSha256; version = [string]$c.version; executable_rel = $exeRel; python_rel = $pythonRel; mcp_sha256 = $mcpStampSha256; mcp_size = $mcpStampSize; mcp_version = $mcpStampVersion; mcp_rel = $mcpStampRel; installed_at = [DateTimeOffset]::UtcNow.ToString("O") } | ConvertTo-Json -Depth 4 -Compress',
        '        [IO.File]::WriteAllText((Join-Path $staging "aida-camoufox-sidecar.json"), $stamp, [Text.Encoding]::UTF8)',
        '        if ([IO.Directory]::Exists($current)) { [IO.Directory]::Move($current, $backup) }',
        '        try { [IO.Directory]::Move($staging, $current) } catch { if ([IO.Directory]::Exists($backup) -and -not [IO.Directory]::Exists($current)) { [IO.Directory]::Move($backup, $current) }; throw }',
        '        try { if ([IO.Directory]::Exists($backup)) { [IO.Directory]::Delete($backup, $true) } } catch { Write-AidaBootstrapLog ("camoufox_sidecar_backup_cleanup_failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message) }',
        '        $exePath = Join-AidaSafeChildPath $current $exeRel',
        '        $pythonPath = if ($pythonRel) { Join-AidaSafeChildPath $current $pythonRel } else { "" }',
        '        $mcpPath = if ($Manifest.camoufox.mcp.configured) { (Get-AidaCamoufoxMcpExpected $Manifest $current).path } else { Find-AidaCamoufoxMcpExecutable $current }',
        '        if (-not (Test-AidaCamoufoxSidecarInstalled $Manifest $current $exePath $pythonPath $mcpPath "redownload-final")) { throw "AiDA Camoufox sidecar current contents are incomplete." }',
        '        Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath',
        '        Write-AidaStatus "Camoufox sidecar ready."',
        '        Write-AidaBootstrapLog ("camoufox_sidecar_installed source=redownload exe=" + $exePath + " mcp=" + $mcpPath + (Get-AidaCamoufoxMcpLogSuffix $Manifest $current $mcpPath))',
        '    } finally {',
        '        try { if ([IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) } } catch { }',
        '        try { if ([IO.Directory]::Exists($staging)) { [IO.Directory]::Delete($staging, $true) } } catch { }',
        '    }',
        '}',
        'try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }',
        'Write-AidaStatus "Checking secure connection..."',
        'Assert-AidaTlsPin',
        'Enable-AidaPinnedTls',
        'Write-AidaStatus "Secure connection verified."',
        'Write-AidaStatus "Preparing Camoufox delivery..."',
        'Write-AidaBootstrapLog "camoufox_delivery_preflight_done"',
        '$licenseKey = $null',
        '$currentHwid = $null',
        'try {',
        '$licenseKey = Get-AidaSecureText "AiDA license key"',
        'Write-AidaStatus "Collecting hardware identity..."',
        '$currentHwid = Get-AidaBootstrapHwid',
        'Write-AidaBootstrapLog ("hwid_v2_ready len=" + $currentHwid.Length)',
        '$clientNonce = New-AidaNonce',
        '$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
        'Write-AidaStatus "Authorizing license..."',
        '$auth = Invoke-AidaJson "/api/bootstrap/authorize" @{ license_key = $licenseKey; hwid = $currentHwid; hwid_version = 2; client_nonce = $clientNonce; timestamp = $timestamp; powershell = $PSVersionTable.PSVersion.ToString() }',
        '$licenseKey = $null',
        'if (-not $auth.ok -or -not $auth.token) { throw "AiDA bootstrap authorization failed." }',
        '$tokenParts = Get-AidaTokenParts $auth.token',
        'Write-AidaStatus "Fetching signed release manifest..."',
        '$manifest = Invoke-AidaJson "/api/bootstrap/manifest" @{ token = $auth.token; client_nonce = $clientNonce; timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }',
        '$auth.token = $null',
        'if (-not $manifest.ok -or -not $manifest.camoufox -or -not $manifest.camoufox.configured) { throw "AiDA Camoufox manifest failed." }',
        'if ([string]$manifest.token_id -ne $tokenParts.id) { throw "AiDA bootstrap manifest token mismatch." }',
        'if ([int64]$manifest.expires_at -lt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { throw "AiDA bootstrap manifest expired." }',
        '$expectedManifestMac = Get-AidaHmacHex $tokenParts.secret (Get-AidaManifestMacInput $manifest)',
        'if (-not (Test-AidaHexEqual $expectedManifestMac ([string]$manifest.manifest_mac))) { throw "AiDA bootstrap manifest authentication failed." }',
        'if ([string]$manifest.manifest_sig_alg -ne "ECDSA_P256_SHA256_P1363" -or -not $manifest.manifest_sig_p256) { throw "AiDA bootstrap manifest signature is missing." }',
        'if (-not (Test-AidaP256Signature (Get-AidaManifestMacInput $manifest) ([string]$manifest.manifest_sig_p256))) { throw "AiDA bootstrap manifest signature verification failed." }',
        '$tokenParts.secret = $null',
        'if (-not $manifest.policy.one_time_token -or -not $manifest.policy.token_bound_to_client_nonce -or -not $manifest.policy.token_bound_to_source_ip -or -not $manifest.policy.no_public_binary_route -or -not $manifest.policy.camoufox_sidecar_hash_required -or ($manifest.policy.encrypted_public_artifact) -or ($manifest.artifact -and ($manifest.artifact.url -or $manifest.artifact.package)) -or ($manifest.camoufox.mcp.configured -and -not $manifest.policy.camoufox_mcp_hash_required)) { throw "AiDA bootstrap manifest policy is invalid." }',
        'Write-AidaStatus "Preparing verified Camoufox package..."',
        'Install-AidaCamoufoxSidecar $manifest',
        'Write-AidaBootstrapLog "camoufox_only_delivery_complete"',
        'Write-AidaStatus "Camoufox package ready."',
        '} catch { Write-AidaBootstrapLog ("fatal_error " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); Write-Host ("AiDA bootstrap failed: " + $_.Exception.Message) -ForegroundColor Red; $global:LASTEXITCODE = 1; return } finally { Write-AidaBootstrapLog "cleanup_enter"; if ($licenseKey) { $licenseKey = $null }; if ($currentHwid) { $currentHwid = $null }; if ($auth -and $auth.token) { $auth.token = $null }; if ($tokenParts -and $tokenParts.secret) { $tokenParts.secret = $null }; Write-AidaBootstrapLog "cleanup_exit" }',
    ];
    return lines.join('\r\n') + '\r\n';
}

function sha256Hex(text) {
    return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function buildBootstrapStage0Script() {
    const cfg = getScriptRouteConfig();
    const fullScript = buildBootstrapScript();
    const pathOnly = cfg.script_path || (cfg.legacy_route_enabled ? cfg.legacy_path : '');
    if (!pathOnly) {
        return fullScript;
    }
    const fullHash = sha256Hex(fullScript);
    const origin = publicOrigin();
    const fullUrl = origin + pathOnly;
    const lines = [
        '$ErrorActionPreference = "Stop"',
        '$ProgressPreference = "SilentlyContinue"',
        'try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }',
        '$u = ' + psQuote(fullUrl),
        '$h = ' + psQuote(fullHash),
        'function ConvertTo-AidaHex([byte[]]$Bytes) { -join ($Bytes | ForEach-Object { $_.ToString("x2") }) }',
        '$req = [Net.HttpWebRequest]::Create($u)',
        '$req.Method = "GET"',
        '$req.UserAgent = "AiDA Bootstrap Stage0"',
        '$req.Accept = "application/vnd.aida.bootstrap"',
        '$req.AllowAutoRedirect = $false',
        '$req.Timeout = 60000',
        '$req.ReadWriteTimeout = 60000',
        '$resp = $null',
        '$reader = $null',
        '$s = $null',
        'try {',
        '    $resp = $req.GetResponse()',
        '    if ([int]$resp.StatusCode -ne 200) { throw "AiDA bootstrap stage fetch failed." }',
        '    $reader = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)',
        '    $s = $reader.ReadToEnd()',
        '} finally { if ($reader) { $reader.Dispose() }; if ($resp) { $resp.Dispose() } }',
        '$sha = [Security.Cryptography.SHA256]::Create()',
        'try { $actual = ConvertTo-AidaHex ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))) } finally { $sha.Dispose() }',
        'if ($actual -ne $h) { throw "AiDA bootstrap stage authentication failed." }',
        'Invoke-Expression $s',
    ];
    return lines.join('\r\n') + '\r\n';
}

async function scriptHandler(_req, res) {
    noStore(res);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(200).send(buildBootstrapScript());
}

async function rootScriptHandler(req, res, next) {
    if (!getScriptRouteConfig().root_content_negotiation || !acceptsBootstrapScript(req)) {
        return next();
    }
    noStore(res);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(200).send(buildBootstrapStage0Script());
}

function expectedCamoufoxSidecarFileName(release) {
    try {
        if (!release.camoufox || !release.camoufox.configured) return '';
        const url = new URL(release.camoufox.url);
        return path.basename(url.pathname);
    } catch (_) {
        return '';
    }
}

function expectedCamoufoxMcpFileName(release) {
    try {
        if (!release.camoufox || !release.camoufox.mcp || !release.camoufox.mcp.configured) return '';
        const url = new URL(release.camoufox.mcp.url);
        return path.basename(url.pathname);
    } catch (_) {
        return '';
    }
}

function forbiddenStandaloneExecutableName(name) {
    return /^(?:AiDAStandalone|AiDA)\.exe$/i.test(String(name || '').trim());
}

async function artifactHandler(req, res) {
    const release = getReleaseConfig();
    const requested = String(req.params && req.params.name || '');
    if (!release.ok || !/^[A-Za-z0-9._-]{1,160}\.(?:zip|exe)$/i.test(requested) || forbiddenStandaloneExecutableName(requested)) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const expectedSidecar = expectedCamoufoxSidecarFileName(release);
    const expectedMcp = expectedCamoufoxMcpFileName(release);
    let expectedSize = 0;
    if (requested === expectedSidecar) expectedSize = release.camoufox.size;
    else if (requested === expectedMcp) expectedSize = release.camoufox.mcp.size;
    if (!expectedSize) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const artifactDir = path.resolve(process.env.AIDA_BOOTSTRAP_ARTIFACT_DIR || path.join(__dirname, '..', 'bootstrap_artifacts'));
    const resolved = path.resolve(artifactDir, requested);
    if (resolved !== path.join(artifactDir, requested)) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    try {
        const st = await fs.promises.stat(resolved);
        if (!st.isFile() || st.size !== expectedSize) {
            return res.status(404).json({ status: 'error', reason: 'not_found' });
        }
    } catch (_) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    res.setHeader('Content-Type', /\.zip$/i.test(requested) ? 'application/zip' : 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Accept-Ranges', 'bytes');
    return res.sendFile(resolved);
}

router.post('/authorize', async (req, res) => {
    const startedAt = Date.now();
    const clientIp = getClientIp(req);
    const userAgent = (req.headers && req.headers['user-agent']) || '';
    try {
        const result = await authorizeRequest(req.body || {}, clientIp, userAgent);
        if (!result || result.eauth) return sendEauth(res, startedAt);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[bootstrap] authorize failed:', err && err.message ? err.message : err);
        return sendEauth(res, startedAt);
    }
});

router.post('/manifest', async (req, res) => {
    const startedAt = Date.now();
    const clientIp = getClientIp(req);
    const userAgent = (req.headers && req.headers['user-agent']) || '';
    try {
        const result = await manifestRequest(req.body || {}, clientIp, userAgent);
        if (!result || result.eauth) return sendEauth(res, startedAt);
        noStore(res);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[bootstrap] manifest failed:', err && err.message ? err.message : err);
        return sendEauth(res, startedAt);
    }
});

router._internal = {
    authorizeRequest,
    manifestRequest,
    buildBootstrapScript,
    buildBootstrapStage0Script,
    artifactHandler,
    rootScriptHandler,
    getScriptRouteConfig,
    acceptsBootstrapScript,
    getReleaseConfig,
    getCamoufoxSidecarConfig,
    getCamoufoxMcpPatchConfig,
    forbiddenStandaloneExecutableName,
    createToken,
    parseToken,
    hashTokenSecret,
    manifestMacInput,
    createManifestMac,
    isLicenseExpired,
    timingSafeHexEqual,
    _resetForTests: () => {
        s_schemaPromise = null;
        s_tokenKey = null;
    },
};

module.exports = {
    router,
    scriptHandler,
    rootScriptHandler,
    artifactHandler,
    getScriptRouteConfig,
    _internal: router._internal,
};
