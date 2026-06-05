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
        policy.one_time_token === true ? '1' : '0',
        policy.token_bound_to_client_nonce === true ? '1' : '0',
        policy.token_bound_to_source_ip === true ? '1' : '0',
        policy.artifact_https_required === true ? '1' : '0',
        policy.no_public_binary_route === true ? '1' : '0',
        policy.encrypted_public_artifact === true ? '1' : '0',
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
    return /(?:^|[,;\s])(?:application\/vnd\.aida\.bootstrap|application\/x-powershell|text\/x-powershell|text\/powershell)(?:$|[,;\s])/i.test(accept);
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

function getReleaseConfig() {
    const urlRaw = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_URL || '').trim();
    const sha256 = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_SHA256 || '').trim().toLowerCase();
    const version = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_VERSION || 'current').trim();
    const fileName = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_NAME || 'AiDAStandalone.exe').trim();
    const signerThumbprint = String(process.env.AIDA_BOOTSTRAP_SIGNER_THUMBPRINT || '').replace(/\s+/g, '').toUpperCase();
    const format = String(process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT || ENCRYPTED_PACKAGE_FORMAT).trim().toLowerCase();
    const certSha256 = String(process.env.AIDA_BOOTSTRAP_TLS_CERT_SHA256 || '').trim().toLowerCase();
    const spkiSha256 = String(process.env.LICENSE_SERVER_SPKI_PIN_HEX || process.env.AIDA_BOOTSTRAP_TLS_SPKI_SHA256 || '').trim().toLowerCase();
    const requireAuthenticode = (process.env.AIDA_BOOTSTRAP_REQUIRE_AUTHENTICODE || '1') !== '0';
    const acceptPinnedPrivateCa = process.env.AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER === '1';
    const allowSameHost = process.env.AIDA_BOOTSTRAP_ALLOW_SAME_HOST_ARTIFACT === '1';
    const allowHttp = process.env.AIDA_BOOTSTRAP_ALLOW_HTTP_ARTIFACT === '1';
    const origin = publicOrigin();
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
    if (!release.ok) {
        await audit('bootstrap.authorize', normalizedLicenseKey || '', clientIp, userAgent, 'deny', release.reason, {});
        return { eauth: true };
    }
    if (!normalizedLicenseKey || licenseKeyRaw.length > 128 || !isHexNonce(clientNonce) || !isTimestampFresh(body.timestamp)) {
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
        policy: {
            one_time_token: true,
            token_bound_to_client_nonce: true,
            token_bound_to_source_ip: IP_BIND_ENABLED,
            artifact_https_required: true,
            no_public_binary_route: true,
            encrypted_public_artifact: !!release.package,
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
        'if ($PSVersionTable.PSEdition -and $PSVersionTable.PSEdition -ne "Desktop") { throw "AiDA bootstrap requires Windows PowerShell 5.1. Run it from powershell.exe, not pwsh." }',
        'if ($PSVersionTable.PSVersion.Major -lt 5) { throw "AiDA bootstrap requires Windows PowerShell 5.1 or newer." }',
        '$ProgressPreference = "Continue"',
        '$AidaBootstrapServer = ' + psQuote(origin),
        '$AidaPinnedSpkiSha256 = ' + psQuote(tlsSpki),
        '$AidaPinnedCertSha256 = ' + psQuote(tlsCert),
        '$AidaRequireTlsPin = $' + (requireTlsPin ? 'true' : 'false'),
        '$AidaRequireAuthenticode = $true',
        '$AidaExpectedSignerThumbprint = ' + psQuote(signerThumbprint),
        '$AidaAcceptPinnedPrivateCaSigner = $' + (acceptPrivateCa ? 'true' : 'false'),
        '$AidaMaxPackageBytes = ' + String(MAX_PACKAGE_BYTES),
        '$AidaManifestP256X = ' + psQuote(p256.x),
        '$AidaManifestP256Y = ' + psQuote(p256.y),
        '$AidaInstallRoot = Join-Path $env:LOCALAPPDATA "AiDA"',
        '$AidaExePath = Join-Path $AidaInstallRoot "AiDAStandalone.exe"',
        'function Write-AidaStatus([string]$Message) { Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) -ForegroundColor Cyan }',
        'function ConvertTo-AidaHex([byte[]]$Bytes) { -join ($Bytes | ForEach-Object { $_.ToString("x2") }) }',
        'function ConvertFrom-AidaHex([string]$Hex) { if (-not $Hex -or ($Hex.Length % 2) -ne 0 -or $Hex -notmatch "^[0-9a-fA-F]+$") { throw "AiDA invalid hex value." }; $b = New-Object byte[] ($Hex.Length / 2); for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }; $b }',
        'function Test-AidaBytesEqual([byte[]]$A, [byte[]]$B) { if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }; $d = 0; for ($i = 0; $i -lt $A.Length; $i++) { $d = $d -bor ($A[$i] -bxor $B[$i]) }; return $d -eq 0 }',
        'function Test-AidaHexEqual([string]$A, [string]$B) { try { $ab = ConvertFrom-AidaHex $A; $bb = ConvertFrom-AidaHex $B; Test-AidaBytesEqual $ab $bb } catch { $false } }',
        'function New-AidaNonce { $b = New-Object byte[] 32; $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); try { $rng.GetBytes($b); ConvertTo-AidaHex $b } finally { $rng.Dispose() } }',
        'function Get-AidaSecureText([string]$Prompt) { $s = Read-Host $Prompt -AsSecureString; $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { if ($p -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) } } }',
        'function Get-AidaTlsHashes([string]$Target) { $u = [Uri]$Target; $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($u.Host, $(if ($u.Port -gt 0) { $u.Port } else { 443 })); try { $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, { param($sender,$cert,$chain,$errors) return ($errors -eq [Net.Security.SslPolicyErrors]::None) }); $ssl.AuthenticateAsClient($u.Host); $cert2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate); $sha = [Security.Cryptography.SHA256]::Create(); try { $certHash = ConvertTo-AidaHex ($sha.ComputeHash($cert2.RawData)); $spkiHash = ""; try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert2); if ($rsa -and $rsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($rsa.ExportSubjectPublicKeyInfo())) } } catch { } try { if (-not $spkiHash) { $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert2); if ($ecdsa -and $ecdsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($ecdsa.ExportSubjectPublicKeyInfo())) } } } catch { } [pscustomobject]@{ cert_sha256 = $certHash; spki_sha256 = $spkiHash } } finally { $sha.Dispose(); $cert2.Dispose(); $ssl.Dispose() } } finally { $tcp.Dispose() } }',
        'function Assert-AidaTlsPin { if (-not $AidaPinnedSpkiSha256 -and -not $AidaPinnedCertSha256) { if ($AidaRequireTlsPin) { throw "AiDA bootstrap TLS pin is not configured." }; return }; $h = Get-AidaTlsHashes $AidaBootstrapServer; if ($AidaPinnedSpkiSha256 -and $h.spki_sha256 -and ($h.spki_sha256.ToLowerInvariant() -eq $AidaPinnedSpkiSha256.ToLowerInvariant())) { return }; if ($AidaPinnedCertSha256 -and ($h.cert_sha256.ToLowerInvariant() -eq $AidaPinnedCertSha256.ToLowerInvariant())) { return }; throw "AiDA bootstrap TLS pin verification failed." }',
        'function Enable-AidaPinnedTls { $script:AidaPinnedHost = ([Uri]$AidaBootstrapServer).Host; [Net.ServicePointManager]::ServerCertificateValidationCallback = { param($sender,$cert,$chain,$errors) try { if ($errors -ne [Net.Security.SslPolicyErrors]::None) { return $false }; $cert2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert); $sha = [Security.Cryptography.SHA256]::Create(); try { $certHash = ConvertTo-AidaHex ($sha.ComputeHash($cert2.RawData)); if ($AidaPinnedCertSha256 -and ($certHash.ToLowerInvariant() -eq $AidaPinnedCertSha256.ToLowerInvariant())) { return $true }; if ($AidaPinnedSpkiSha256) { $spkiHash = ""; try { $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert2); if ($rsa -and $rsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($rsa.ExportSubjectPublicKeyInfo())) } } catch { }; try { if (-not $spkiHash) { $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert2); if ($ecdsa -and $ecdsa.GetType().GetMethod("ExportSubjectPublicKeyInfo")) { $spkiHash = ConvertTo-AidaHex ($sha.ComputeHash($ecdsa.ExportSubjectPublicKeyInfo())) } } } catch { }; if ($spkiHash -and ($spkiHash.ToLowerInvariant() -eq $AidaPinnedSpkiSha256.ToLowerInvariant())) { return $true } }; return (-not $AidaRequireTlsPin -and -not $AidaPinnedCertSha256 -and -not $AidaPinnedSpkiSha256) } finally { $sha.Dispose(); $cert2.Dispose() } } catch { return $false } } }',
        'function Invoke-AidaJson([string]$Path, [object]$Body) { $json = $null; $bytes = $null; $req = $null; $resp = $null; try { $json = $Body | ConvertTo-Json -Depth 8 -Compress; $bytes = [Text.Encoding]::UTF8.GetBytes($json); $req = [Net.HttpWebRequest]::Create($AidaBootstrapServer + $Path); $req.Method = "POST"; $req.UserAgent = "AiDA Bootstrap"; $req.ContentType = "application/json"; $req.AllowAutoRedirect = $false; $req.Timeout = 120000; $req.ReadWriteTimeout = 120000; $req.ContentLength = $bytes.Length; $rs = $req.GetRequestStream(); try { $rs.Write($bytes, 0, $bytes.Length) } finally { if ($rs) { $rs.Dispose() } }; $resp = $req.GetResponse(); if ([int]$resp.StatusCode -ne 200) { throw "AiDA bootstrap API request failed." }; $reader = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8); try { $text = $reader.ReadToEnd(); $text | ConvertFrom-Json } finally { $reader.Dispose(); $text = $null } } finally { if ($resp) { $resp.Dispose() }; if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }; $json = $null } }',
        'function Get-AidaTokenId([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; $m.Groups[1].Value.ToLowerInvariant() }',
        'function Get-AidaTokenSecretBytes([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; ConvertFrom-AidaHex $m.Groups[2].Value }',
        'function Get-AidaTokenParts([string]$Token) { $m = [regex]::Match($Token, "^AIDABOOT\\.v1\\.([0-9a-fA-F]{32})\\.([0-9a-fA-F]{64})$"); if (-not $m.Success) { throw "AiDA bootstrap token format is invalid." }; [pscustomobject]@{ id = $m.Groups[1].Value.ToLowerInvariant(); secret = $m.Groups[2].Value.ToLowerInvariant() } }',
        'function Get-AidaManifestMacInput([object]$M) { @("AIDABOOTMANIFEST.v1", [string]$M.token_id, [string]$M.issued_at, [string]$M.expires_at, [string]$M.artifact.name, [string]$M.artifact.version, [string]$M.artifact.url, [string]$M.artifact.sha256, [string]$M.artifact.size, [string]$M.artifact.package.format, [string]$M.artifact.package.sha256, [string]$M.artifact.package.size, [string]$M.artifact.package.enc_key_b64, [string]$M.artifact.package.mac_key_b64, $(if ($M.artifact.authenticode.required) { "1" } else { "0" }), [string]$M.artifact.authenticode.signer_thumbprint, $(if ($M.artifact.authenticode.accept_pinned_private_ca) { "1" } else { "0" }), $(if ($M.policy.one_time_token) { "1" } else { "0" }), $(if ($M.policy.token_bound_to_client_nonce) { "1" } else { "0" }), $(if ($M.policy.token_bound_to_source_ip) { "1" } else { "0" }), $(if ($M.policy.artifact_https_required) { "1" } else { "0" }), $(if ($M.policy.no_public_binary_route) { "1" } else { "0" }), $(if ($M.policy.encrypted_public_artifact) { "1" } else { "0" })) -join "`n" }',
        'function Get-AidaHmacHex([string]$KeyHex, [string]$Data) { $key = ConvertFrom-AidaHex $KeyHex; $h = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$key); try { ConvertTo-AidaHex ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) } finally { $h.Dispose(); [Array]::Clear($key, 0, $key.Length) } }',
        'function Get-AidaHmacHexFromBytes([byte[]]$Key, [string]$Data) { $h = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$Key); try { ConvertTo-AidaHex ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) } finally { $h.Dispose() } }',
        'function Test-AidaP256Signature([string]$Data, [string]$SignatureHex) { if (-not $AidaManifestP256X -or -not $AidaManifestP256Y) { throw "AiDA manifest signature key is not configured." }; $x = ConvertFrom-AidaHex $AidaManifestP256X; $y = ConvertFrom-AidaHex $AidaManifestP256Y; $sig = ConvertFrom-AidaHex $SignatureHex; $blob = New-Object byte[] 72; try { if ($x.Length -ne 32 -or $y.Length -ne 32 -or $sig.Length -ne 64) { return $false }; $magic = [BitConverter]::GetBytes([uint32]0x31534345); $size = [BitConverter]::GetBytes([uint32]32); [Array]::Copy($magic, 0, $blob, 0, 4); [Array]::Copy($size, 0, $blob, 4, 4); [Array]::Copy($x, 0, $blob, 8, 32); [Array]::Copy($y, 0, $blob, 40, 32); $key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob); $ecdsa = New-Object Security.Cryptography.ECDsaCng($key); try { $ecdsa.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256; $ecdsa.VerifyData([Text.Encoding]::UTF8.GetBytes($Data), $sig) } finally { $ecdsa.Dispose(); $key.Dispose() } } catch { $false } finally { [Array]::Clear($x, 0, $x.Length); [Array]::Clear($y, 0, $y.Length); [Array]::Clear($sig, 0, $sig.Length); [Array]::Clear($blob, 0, $blob.Length) } }',
        'function Get-AidaPackageBytesWithProgress([Uri]$Uri, [long]$ExpectedSize, [string]$ExpectedSha256) {',
        '    if ($ExpectedSize -le 0 -or $ExpectedSize -gt $AidaMaxPackageBytes) { throw "AiDA package size is not allowed." }',
        '    if (-not $ExpectedSha256 -or $ExpectedSha256 -notmatch "^[0-9a-fA-F]{64}$") { throw "AiDA encrypted package SHA-256 metadata is invalid." }',
        '    $req = $null; $resp = $null; $stream = $null; $ms = $null; $sha = $null; $buf = New-Object byte[] 1048576',
        '    try {',
        '        $req = [Net.HttpWebRequest]::Create($Uri.AbsoluteUri)',
        '        $req.Method = "GET"',
        '        $req.UserAgent = "AiDA Bootstrap"',
        '        $req.AllowAutoRedirect = $false',
        '        $req.Timeout = 300000',
        '        $req.ReadWriteTimeout = 300000',
        '        try { $req.AllowReadStreamBuffering = $false } catch { }',
        '        $resp = $req.GetResponse()',
        '        if ([int]$resp.StatusCode -ne 200) { throw "AiDA package download failed." }',
        '        if ($resp.ContentLength -ge 0 -and [int64]$resp.ContentLength -ne $ExpectedSize) { throw "AiDA package size mismatch." }',
        '        $stream = $resp.GetResponseStream()',
        '        $ms = New-Object IO.MemoryStream',
        '        $sha = [Security.Cryptography.SHA256]::Create()',
        '        $done = [int64]0',
        '        while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {',
        '            $done += $read',
        '            if ($done -gt $ExpectedSize) { throw "AiDA package exceeded expected size." }',
        '            $null = $sha.TransformBlock($buf, 0, $read, $buf, 0)',
        '            $ms.Write($buf, 0, $read)',
        '            $pct = [Math]::Min(100, [Math]::Round(($done * 100.0) / $ExpectedSize, 1))',
        '            Write-Progress -Activity "Downloading AiDA package" -Status ("{0:N1} MB / {1:N1} MB" -f ($done / 1MB), ($ExpectedSize / 1MB)) -PercentComplete $pct',
        '        }',
        '        if ($done -ne $ExpectedSize) { throw "AiDA package download size mismatch." }',
        '        $empty = New-Object byte[] 0',
        '        $null = $sha.TransformFinalBlock($empty, 0, 0)',
        '        $actualSha256 = ConvertTo-AidaHex $sha.Hash',
        '        if (-not (Test-AidaHexEqual $actualSha256 $ExpectedSha256)) { throw "AiDA encrypted package SHA-256 verification failed." }',
        '        return $ms.ToArray()',
        '    } finally {',
        '        if ($sha) { $sha.Dispose() }',
        '        if ($ms) { $ms.Dispose() }',
        '        if ($stream) { $stream.Dispose() }',
        '        if ($resp) { $resp.Dispose() }',
        '        if ($buf) { [Array]::Clear($buf, 0, $buf.Length) }',
        '        Write-Progress -Activity "Downloading AiDA package" -Completed',
        '    }',
        '}',
        'function Decrypt-AidaPackageBytes([byte[]]$PackageBytes, [string]$OutputPath, [object]$Package) {',
        '    if (-not $Package -or $Package.format -ne "encrypted-cbc-hmac-v1") { throw "AiDA encrypted package metadata is invalid." }',
        '    if ($null -eq $PackageBytes -or $PackageBytes.Length -le 0 -or $PackageBytes.Length -gt $AidaMaxPackageBytes) { throw "AiDA encrypted package bytes are invalid." }',
        '    $encKey = [Convert]::FromBase64String([string]$Package.enc_key_b64)',
        '    $macKey = [Convert]::FromBase64String([string]$Package.mac_key_b64)',
        '    if ($encKey.Length -ne 32 -or $macKey.Length -ne 32) { throw "AiDA encrypted package keys are invalid." }',
        '    $magic = [Text.Encoding]::ASCII.GetBytes("AIDABOOTPKG1`n")',
        '    $iv = New-Object byte[] 16',
        '    $expectedTag = New-Object byte[] 32',
        '    $buf = New-Object byte[] 1048576',
        '    $out = $null; $crypto = $null; $aes = $null; $dec = $null; $hmac = $null; $ok = $false',
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
        '        $aes = [Security.Cryptography.Aes]::Create()',
        '        $aes.Mode = [Security.Cryptography.CipherMode]::CBC',
        '        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7',
        '        $aes.KeySize = 256',
        '        $aes.BlockSize = 128',
        '        $aes.Key = $encKey',
        '        $aes.IV = $iv',
        '        $dec = $aes.CreateDecryptor()',
        '        $out = [IO.File]::Open($OutputPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)',
        '        $crypto = New-Object Security.Cryptography.CryptoStream -ArgumentList @($out, $dec, [Security.Cryptography.CryptoStreamMode]::Write)',
        '        $remaining = $cipherLength',
        '        $offset = $cipherOffset',
        '        while ($remaining -gt 0) {',
        '            $want = [Math]::Min($buf.Length, $remaining)',
        '            $crypto.Write($PackageBytes, [int]$offset, [int]$want)',
        '            $offset += $want',
        '            $remaining -= $want',
        '        }',
        '        $crypto.FlushFinalBlock()',
        '        $ok = $true',
        '    } finally {',
        '        if ($crypto) { $crypto.Dispose() }',
        '        if ($out) { $out.Dispose() }',
        '        if ($dec) { $dec.Dispose() }',
        '        if ($aes) { $aes.Dispose() }',
        '        if ($hmac) { $hmac.Dispose() }',
        '        [Array]::Clear($encKey, 0, $encKey.Length)',
        '        [Array]::Clear($macKey, 0, $macKey.Length)',
        '        [Array]::Clear($iv, 0, $iv.Length)',
        '        [Array]::Clear($expectedTag, 0, $expectedTag.Length)',
        '        [Array]::Clear($buf, 0, $buf.Length)',
        '        if (-not $ok) { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue }',
        '    }',
        '}',
        'function Assert-AidaAuthenticode([string]$Path) { if (-not $AidaRequireAuthenticode) { throw "AiDA Authenticode verification is required." }; $sig = Get-AuthenticodeSignature -FilePath $Path; if (-not $sig.SignerCertificate) { throw "AiDA artifact Authenticode signature is missing." }; $expectedThumb = ($AidaExpectedSignerThumbprint -replace "\\s+", "").ToUpperInvariant(); if (-not $expectedThumb) { throw "AiDA artifact signer thumbprint is not configured." }; $actualThumb = ($sig.SignerCertificate.Thumbprint -replace "\\s+", "").ToUpperInvariant(); if ($actualThumb -ne $expectedThumb) { throw "AiDA artifact signer thumbprint mismatch." }; if ($sig.Status -eq "Valid") { return }; $status = [string]$sig.Status; if ($AidaAcceptPinnedPrivateCaSigner -and ($status -eq "UnknownError" -or $status -eq "NotTrusted")) { return }; throw ("AiDA artifact Authenticode signature is not valid: " + $status) }',
        'try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }',
        'Write-AidaStatus "Checking secure connection..."',
        'Assert-AidaTlsPin',
        'Enable-AidaPinnedTls',
        'Write-AidaStatus "Secure connection verified."',
        '$tmp = $null',
        '$packageBytes = $null',
        '$installed = $false',
        '$licenseKey = $null',
        'try {',
        'New-Item -ItemType Directory -Path $AidaInstallRoot -Force | Out-Null',
        '$licenseKey = Get-AidaSecureText "AiDA license key"',
        '$clientNonce = New-AidaNonce',
        '$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
        'Write-AidaStatus "Authorizing license..."',
        '$auth = Invoke-AidaJson "/api/bootstrap/authorize" @{ license_key = $licenseKey; client_nonce = $clientNonce; timestamp = $timestamp; powershell = $PSVersionTable.PSVersion.ToString() }',
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
        'if (-not $manifest.policy.one_time_token -or -not $manifest.policy.token_bound_to_client_nonce -or -not $manifest.policy.token_bound_to_source_ip -or -not $manifest.policy.artifact_https_required -or -not $manifest.policy.no_public_binary_route -or -not $manifest.policy.encrypted_public_artifact) { throw "AiDA bootstrap manifest policy is invalid." }',
        'if (-not $manifest.artifact.authenticode.required) { throw "AiDA bootstrap manifest Authenticode policy is invalid." }',
        'if (([string]$manifest.artifact.authenticode.signer_thumbprint -replace "\\s+", "").ToUpperInvariant() -ne ($AidaExpectedSignerThumbprint -replace "\\s+", "").ToUpperInvariant()) { throw "AiDA bootstrap manifest signer policy mismatch." }',
        '$artifactUri = [Uri]$manifest.artifact.url',
        'if ($artifactUri.Scheme -ne "https") { throw "AiDA artifact URL must use HTTPS." }',
        '$tmp = Join-Path $AidaInstallRoot ("AiDAStandalone." + [Guid]::NewGuid().ToString("N") + ".exe.tmp")',
        'if (-not $manifest.artifact.package) { throw "AiDA encrypted package metadata is required." }',
        '$packageSize = [int64]0; try { $packageSize = [int64]$manifest.artifact.package.size } catch { $packageSize = 0 }',
        '$packageSizeText = if ($packageSize -gt 0) { "{0:N1} MB" -f ($packageSize / 1MB) } else { "unknown size" }',
        'Write-AidaStatus ("Downloading and verifying encrypted package ({0})..." -f $packageSizeText)',
        '$packageBytes = Get-AidaPackageBytesWithProgress $artifactUri $packageSize ([string]$manifest.artifact.package.sha256)',
        'Write-AidaStatus "Decrypting package..."',
        'Decrypt-AidaPackageBytes $packageBytes $tmp $manifest.artifact.package',
        '[Array]::Clear($packageBytes, 0, $packageBytes.Length); $packageBytes = $null',
        'Write-AidaStatus "Verifying AiDA executable hash..."',
        '$actualHash = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLowerInvariant()',
        'if ($actualHash -ne ([string]$manifest.artifact.sha256).ToLowerInvariant()) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; throw "AiDA artifact SHA-256 verification failed." }',
        'Write-AidaStatus "Checking Authenticode signature..."',
        'try { Assert-AidaAuthenticode $tmp } catch { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; throw }',
        'Write-AidaStatus "Installing AiDA..."',
        'Move-Item -LiteralPath $tmp -Destination $AidaExePath -Force',
        '$installed = $true',
        'Write-AidaStatus "Launching AiDA..."',
        'Start-Process -FilePath $AidaExePath',
        'Write-AidaStatus "Done."',
        '} finally { if ($licenseKey) { $licenseKey = $null }; if ($auth -and $auth.token) { $auth.token = $null }; if ($tokenParts -and $tokenParts.secret) { $tokenParts.secret = $null }; if ($null -ne $packageBytes) { [Array]::Clear($packageBytes, 0, $packageBytes.Length); $packageBytes = $null }; if ((-not $installed) -and $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }',
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
    return scriptHandler(req, res);
}

function expectedArtifactFileName(release) {
    try {
        const url = new URL(release.url);
        return path.basename(url.pathname);
    } catch (_) {
        return '';
    }
}

async function artifactHandler(req, res) {
    const release = getReleaseConfig();
    const requested = String(req.params && req.params.name || '');
    if (!release.ok || !release.package || !/^[A-Za-z0-9._-]{1,160}\.pkg$/i.test(requested)) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const expected = expectedArtifactFileName(release);
    if (requested !== expected) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    const artifactDir = path.resolve(process.env.AIDA_BOOTSTRAP_ARTIFACT_DIR || path.join(__dirname, '..', 'bootstrap_artifacts'));
    const resolved = path.resolve(artifactDir, requested);
    if (resolved !== path.join(artifactDir, requested)) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    try {
        const st = await fs.promises.stat(resolved);
        if (!st.isFile() || (release.package.size && st.size !== release.package.size)) {
            return res.status(404).json({ status: 'error', reason: 'not_found' });
        }
    } catch (_) {
        return res.status(404).json({ status: 'error', reason: 'not_found' });
    }
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store');
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
    artifactHandler,
    rootScriptHandler,
    getScriptRouteConfig,
    acceptsBootstrapScript,
    getReleaseConfig,
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
