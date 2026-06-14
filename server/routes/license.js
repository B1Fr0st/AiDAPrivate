

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload, dualSignPayload, signWithKid, getActiveKidInfo } = require('../crypto/signing');
const { deriveKeySeed } = require('../crypto/arc-encrypt');
const kwWrap = require('../crypto/kw_wrap');
const arcLicenseBind = require('../crypto/arc-license-bind');
const columnCrypt = require('../crypto/column_crypt');
const rateLimit = require('../middleware/rate_limit');
const tpmQuote = require('../crypto/tpm_quote');
const ekRoots = require('../crypto/ek_roots');
const anomalyScore = require('../anomaly/score');
const sessionAead = require('../crypto/session_aead');
const canonicalResponse = require('../crypto/canonical_response');
const keyFormat = require('../crypto/key_format');
const auditLog = require('../middleware/audit_log');
const licenseRateLimit = require('../middleware/license_rate_limit');
const botAuth = require('../middleware/bot_auth');
const replayCounter = require('../middleware/replay_counter');
const killSwitchModule = require('../middleware/kill_switch');
const peerCodeHash = require('../crypto/peer_code_hash');
const sessionRatchet = require('../middleware/session_ratchet');

const SESSION_RATCHET_AUTHENTICATED_ACTIONS = new Set([
    'heartbeat',
    'driver_proof',
    'tpm_attest',
    'report_violation',
]);

const SESSION_RATCHET_ENABLED = (process.env.SESSION_RATCHET_ENABLED || '1') !== '0';

const router = express.Router();

const REASON_INVALID = 1;
const REASON_BANNED = 2;
const REASON_RATE_LIMITED = 3;

const HANDLER_TIMING_BUDGET_MS = parseInt(process.env.LICENSE_TIMING_BUDGET_MS || '50', 10) || 50;
const EAUTH_BUDGET_MS = parseInt(process.env.LICENSE_EAUTH_BUDGET_MS || '250', 10) || 250;
const EAUTH_JITTER_MAX_MS = parseInt(process.env.LICENSE_EAUTH_JITTER_MS || '20', 10) || 20;
const REQ_TIME_WINDOW_MS = keyFormat.REQ_TIME_WINDOW_MS;
const REQ_TIME_WINDOW_LEGACY_MS = keyFormat.REQ_TIME_WINDOW_LEGACY_MS;
const HKDF_RATCHET_INFO_PREFIX = 'ratchet|';
const EAUTH_BODY_OBJECT = Object.freeze({ ok: false, error_code: 'EAUTH' });
const EAUTH_BODY_JSON   = JSON.stringify(EAUTH_BODY_OBJECT);
const EAUTH_BODY_LENGTH = Buffer.byteLength(EAUTH_BODY_JSON, 'utf8');

function jitterMs() {
    if (EAUTH_JITTER_MAX_MS <= 0) return 0;
    return crypto.randomInt(0, EAUTH_JITTER_MAX_MS + 1);
}

async function applyEauthBudget(startMs) {
    const elapsed = Date.now() - startMs;
    const target = EAUTH_BUDGET_MS + jitterMs();
    const remaining = target - elapsed;
    if (remaining > 0) {
        await new Promise(resolve => setTimeout(resolve, remaining));
    }
}

function buildEauthResult() {
    return {
        status: 401,
        body: EAUTH_BODY_OBJECT,
        eauth: true,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': String(EAUTH_BODY_LENGTH),
            'Cache-Control': 'no-store',
        },
    };
}

function padToFixedLengthBuf(value, length) {
    if (Buffer.isBuffer(value) && value.length === length) return value;
    const out = Buffer.alloc(length);
    if (typeof value === 'string') {
        Buffer.from(value, 'utf8').copy(out, 0, 0, Math.min(length, value.length));
    } else if (Buffer.isBuffer(value)) {
        value.copy(out, 0, 0, Math.min(length, value.length));
    }
    return out;
}

function fixedLengthTimingSafeEqual(a, b) {
    const padded_a = padToFixedLengthBuf(a, 32);
    const padded_b = padToFixedLengthBuf(b, 32);
    return crypto.timingSafeEqual(padded_a, padded_b);
}

const STANDALONE_CAPSULE_SECRET_LABEL = 'standalone_capsule_secret/v1';
const STANDALONE_CAPSULE_PROOF_PREFIX = 'aida-standalone-capsule-proof/v1';

function truthyDbFlag(value) {
    if (value === true) return true;
    if (value === false || value === null || value === undefined) return false;
    if (typeof value === 'number') return value !== 0;
    if (typeof value === 'bigint') return value !== 0n;
    if (typeof value === 'string') {
        const v = value.trim().toLowerCase();
        return v === '1' || v === 'true' || v === 't' || v === 'yes' || v === 'y' || v === 'on';
    }
    return false;
}

function normalizeCapsuleHex(value) {
    if (typeof value !== 'string') return '';
    const v = value.trim().toLowerCase();
    return /^[0-9a-f]{64}$/.test(v) ? v : '';
}

function normalizeCapsuleId(value) {
    if (typeof value !== 'string') return '';
    const v = value.trim();
    if (v.length < 8 || v.length > 128) return '';
    return /^[A-Za-z0-9_.:-]+$/.test(v) ? v : '';
}

function normalizeCapsuleNonce(value) {
    if (typeof value !== 'string') return '';
    const v = value.trim().toLowerCase();
    return /^[0-9a-f]{16,128}$/.test(v) ? v : '';
}

function normalizeCapsuleProofTs(value) {
    let n = 0;
    if (typeof value === 'number' && Number.isFinite(value)) n = Math.floor(value);
    else if (typeof value === 'bigint') n = Number(value);
    else if (typeof value === 'string' && value.trim() !== '') n = Math.floor(Number(value.trim()));
    return Number.isFinite(n) && n > 0 ? n : 0;
}

function parseCapsuleProof(value) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex');
    if (/^[A-Za-z0-9+/=_-]{43,88}$/.test(trimmed)) {
        try {
            const b64 = trimmed.replace(/-/g, '+').replace(/_/g, '/');
            const decoded = Buffer.from(b64, 'base64');
            return decoded.length === 32 ? decoded : null;
        } catch (_) {
            return null;
        }
    }
    return null;
}

function parseWrappedCapsuleSecret(value) {
    if (Buffer.isBuffer(value)) return value;
    if (value && value.type === 'Buffer' && Array.isArray(value.data)) return Buffer.from(value.data);
    if (typeof value !== 'string') return null;
    const v = value.trim();
    if (v.startsWith('\\x') && /^[\\]x[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
        return Buffer.from(v.slice(2), 'hex');
    }
    if (/^[0-9a-fA-F]{56,}$/.test(v) && v.length % 2 === 0) return Buffer.from(v, 'hex');
    try {
        const decoded = Buffer.from(v, 'base64');
        return decoded.length >= 28 ? decoded : null;
    } catch (_) {
        return null;
    }
}

function pickCapsuleSecretWrapped(row) {
    if (!row || typeof row !== 'object') return null;
    return row.secret_wrapped
        || row.capsule_secret_wrapped
        || row.proof_secret_wrapped
        || row.hmac_secret_wrapped
        || row.standalone_capsule_secret_wrapped
        || null;
}

function capsuleRowRevoked(row) {
    if (!row || typeof row !== 'object') return true;
    if (truthyDbFlag(row.revoked)) return true;
    if (truthyDbFlag(row.is_revoked)) return true;
    if (row.active !== undefined && !truthyDbFlag(row.active)) return true;
    if (row.status !== undefined) {
        const status = String(row.status || '').trim().toLowerCase();
        if (status && status !== 'active') return true;
    }
    return false;
}

function capsuleRowExpired(row, nowSeconds = Math.floor(Date.now() / 1000)) {
    if (!row || typeof row !== 'object') return true;
    const candidates = [
        row.expires_epoch,
        row.expires_at_epoch,
        row.expiry_epoch,
        row.not_after_epoch,
    ];
    for (const candidate of candidates) {
        const epoch = normalizeExpiryEpoch(candidate);
        if (epoch > 0) return nowSeconds > epoch;
    }
    for (const candidate of [row.expires_at, row.expiry, row.not_after]) {
        if (!candidate) continue;
        const parsed = Date.parse(candidate);
        if (Number.isFinite(parsed)) return Date.now() > parsed;
    }
    return false;
}

function capsuleRowActive(row) {
    return !!row && !capsuleRowRevoked(row) && !capsuleRowExpired(row);
}

function isMissingCapsuleSchemaError(err) {
    const code = err && err.code ? String(err.code) : '';
    if (code === '42P01' || code === '42703' || code === '42883') return true;
    const msg = err && err.message ? String(err.message).toLowerCase() : '';
    return msg.includes('standalone_customer_capsules')
        && (msg.includes('does not exist') || msg.includes('no such table') || msg.includes('unknown column') || msg.includes('no such column'));
}

async function fetchStandaloneCapsuleRows(licenseKey) {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM standalone_customer_capsules WHERE license_key = $1',
            [licenseKey]
        );
        return { ok: true, rows: rows || [] };
    } catch (err) {
        if (isMissingCapsuleSchemaError(err)) return { ok: false, missing_schema: true, rows: [] };
        throw err;
    }
}

function buildStandaloneCapsuleProofMessage(action, fields) {
    const parts = [
        STANDALONE_CAPSULE_PROOF_PREFIX,
        String(action || ''),
        String(fields.license_key || ''),
    ];
    if (action === 'validate') {
        parts.push(
            String(fields.hwid || ''),
            String(fields.client_nonce || '')
        );
    } else if (action === 'heartbeat') {
        parts.push(
            String(fields.session_token || ''),
            String(fields.hwid || ''),
            String(fields.heartbeat_nonce || ''),
            String(fields.heartbeat_count || ''),
            String(fields.req_seq || '')
        );
    } else {
        parts.push(String(fields.hwid || ''));
    }
    parts.push(
        String(fields.capsule_id || ''),
        String(fields.base_sha256 || ''),
        String(fields.capsule_sha256 || ''),
        String(fields.proof_nonce || ''),
        String(fields.proof_ts || '')
    );
    return parts.join('\n');
}

function verifyStandaloneCapsuleProof(secret, action, fields, proofBuf) {
    if (!Buffer.isBuffer(secret) || secret.length < 16 || !Buffer.isBuffer(proofBuf) || proofBuf.length !== 32) {
        if (Buffer.isBuffer(proofBuf) && proofBuf.length === 32) {
            crypto.timingSafeEqual(Buffer.alloc(32), proofBuf);
        }
        return false;
    }
    const expected = crypto.createHmac('sha256', secret)
        .update(buildStandaloneCapsuleProofMessage(action, fields), 'utf8')
        .digest();
    return crypto.timingSafeEqual(expected, proofBuf);
}

async function enforceStandaloneCapsuleProof(action, licenseRow, body, context = {}) {
    const normalizedLicenseKey = context.license_key || (licenseRow && licenseRow.key) || (body && body.license_key) || '';
    const licenseRequiresCapsule = truthyDbFlag(licenseRow && licenseRow.standalone_capsule_required);
    const fetched = await fetchStandaloneCapsuleRows(normalizedLicenseKey);
    if (!fetched.ok && fetched.missing_schema) {
        return licenseRequiresCapsule
            ? { ok: false, reason: 'capsule_schema_missing' }
            : { ok: true, enforced: false, reason: 'capsule_schema_absent' };
    }
    const rows = fetched.rows || [];
    const activeRows = rows.filter(capsuleRowActive);
    const proof = body && body.standalone_capsule && typeof body.standalone_capsule === 'object'
        ? body.standalone_capsule
        : null;
    const mustEnforce = licenseRequiresCapsule || activeRows.length > 0 || rows.length > 0;
    if (!mustEnforce) return { ok: true, enforced: false, reason: 'capsule_not_required' };
    if (!proof) return { ok: false, reason: 'capsule_missing' };

    const capsuleId = normalizeCapsuleId(proof.capsule_id);
    const baseSha = normalizeCapsuleHex(proof.base_sha256);
    const capsuleSha = normalizeCapsuleHex(proof.capsule_sha256);
    const proofNonce = normalizeCapsuleNonce(proof.proof_nonce);
    const proofTs = normalizeCapsuleProofTs(proof.proof_ts);
    const proofBuf = parseCapsuleProof(proof.proof);
    if (!capsuleId || !baseSha || !capsuleSha || !proofNonce || !proofTs || !proofBuf) {
        return { ok: false, reason: 'capsule_proof_format' };
    }
    const drift = Math.abs(Math.floor(Date.now() / 1000) - proofTs);
    if (drift > 300) return { ok: false, reason: 'capsule_proof_stale' };

    const row = rows.find(r => normalizeCapsuleId(r && r.capsule_id) === capsuleId);
    if (!row) return { ok: false, reason: 'capsule_id_mismatch' };
    if (capsuleRowRevoked(row)) return { ok: false, reason: 'capsule_revoked' };
    if (capsuleRowExpired(row)) return { ok: false, reason: 'capsule_expired' };
    if (normalizeCapsuleHex(row.base_sha256) !== baseSha) return { ok: false, reason: 'capsule_base_mismatch' };
    if (normalizeCapsuleHex(row.capsule_sha256) !== capsuleSha) return { ok: false, reason: 'capsule_hash_mismatch' };

    const wrapped = parseWrappedCapsuleSecret(pickCapsuleSecretWrapped(row));
    if (!wrapped) return { ok: false, reason: 'capsule_secret_missing' };
    let secret;
    try {
        secret = kwWrap.unwrap(wrapped, STANDALONE_CAPSULE_SECRET_LABEL);
    } catch (_) {
        return { ok: false, reason: 'capsule_secret_unwrap' };
    }

    const heartbeatCount = action === 'heartbeat'
        ? String(Math.max(0, Math.floor(Number(body.heartbeat_count || 0))))
        : '';
    const fields = {
        license_key: normalizedLicenseKey,
        hwid: context.hwid || body.hwid || '',
        client_nonce: body.client_nonce || '',
        session_token: body.session_token || '',
        heartbeat_nonce: body.heartbeat_nonce || '',
        heartbeat_count: heartbeatCount,
        req_seq: action === 'heartbeat' ? String(body.req_seq || '') : '',
        capsule_id: capsuleId,
        base_sha256: baseSha,
        capsule_sha256: capsuleSha,
        proof_nonce: proofNonce,
        proof_ts: String(proofTs),
    };
    const ok = verifyStandaloneCapsuleProof(secret, action, fields, proofBuf);
    secret.fill(0);
    if (!ok) return { ok: false, reason: 'capsule_proof_mismatch' };
    return { ok: true, enforced: true, capsule_id: capsuleId };
}

async function applyTimingBudget(startMs) {
    const elapsed = Date.now() - startMs;
    const remaining = HANDLER_TIMING_BUDGET_MS - elapsed;
    if (remaining > 0) {
        await new Promise(resolve => setTimeout(resolve, remaining));
    }
}

function timingBudgetWrap(handler) {
    return async function timingWrapped(...args) {
        const t0 = Date.now();
        let result;
        try {
            result = await handler.apply(this, args);
        } finally {
            await applyTimingBudget(t0);
        }
        return result;
    };
}

function deriveRatchetedSessionToken(prevSessionToken, hwid, toolCallCounter) {
    const prk = crypto.createHmac('sha256', Buffer.from(String(hwid || ''), 'utf8'))
        .update(Buffer.from(String(prevSessionToken || ''), 'utf8'))
        .digest();
    const info = Buffer.from(HKDF_RATCHET_INFO_PREFIX + String(toolCallCounter), 'utf8');
    const t1 = crypto.createHmac('sha256', prk)
        .update(info)
        .update(Buffer.from([0x01]))
        .digest();
    return t1.toString('hex');
}

async function persistRatchet(licenseKey, newSessionToken, prevSessionUuid, newCounter) {
    const uuid = prevSessionUuid || columnCrypt.generateRowUuid();
    const wrapped = encryptSessionToken(uuid, newSessionToken);
    try {
        await pool.query(
            `UPDATE sessions
                SET session_token = $1,
                    session_uuid = $2,
                    tool_call_counter = $3
              WHERE license_key = $4`,
            [wrapped, uuid, String(newCounter), licenseKey]
        );
        return { ok: true, session_token: newSessionToken, tool_call_counter: newCounter };
    } catch (err) {
        console.warn('[license] ratchet persist failed:', err && err.message ? err.message : err);
        return { ok: false, reason: 'ratchet_persist_failed' };
    }
}

async function performSessionRatchet(licenseKey, sessionRow) {
    if (!licenseKey || !sessionRow) return { ok: false, reason: 'no_session' };
    const prevToken = sessionRow.session_token || '';
    const hwid = sessionRow.hwid || '';
    const prevCounter = (() => {
        try { return BigInt(sessionRow.tool_call_counter || 0); }
        catch (_) { return 0n; }
    })();
    const nextCounter = prevCounter + 1n;
    const newToken = deriveRatchetedSessionToken(prevToken, hwid, nextCounter.toString());
    const persist = await persistRatchet(licenseKey, newToken, sessionRow.session_uuid, nextCounter.toString());
    if (!persist.ok) return persist;
    return { ok: true, prev_session_token: prevToken, new_session_token: newToken, tool_call_counter: nextCounter.toString() };
}

const HWID_GRACE_WINDOW_SECONDS = parseInt(process.env.HWID_GRACE_WINDOW_SECONDS || (30 * 86400), 10);

function envelopeResponse(status, payload) {
    return {
        status,
        body: canonicalResponse.buildEnvelope(payload),
    };
}

function collapseInvalid(rawReason, licenseKey, hwid, clientIp, extra) {
    console.warn('[validate-reject] kind=invalid reason=' + String(rawReason || 'unknown')
        + ' key_prefix=' + String(licenseKey || '').slice(0, 14)
        + ' hwid_prefix=' + String(hwid || '').slice(0, 12)
        + ' ip=' + String(clientIp || '')
        + ' extra=' + (extra ? JSON.stringify(extra).slice(0, 200) : ''));
    auditLog.logValidationFailure(REASON_INVALID, rawReason, licenseKey || '', hwid || '', clientIp || '', extra || null)
        .catch(() => {});
    auditLog.logV2({
        action: 'license.validate',
        license_key: licenseKey || '',
        hwid: hwid || '',
        source_ip: clientIp || '',
        decision: 'deny',
        reason_code: 'invalid:' + String(rawReason || 'unknown'),
        extra: extra || {},
    }).catch(() => {});
    const r = buildEauthResult();
    if (process.env.AIDA_DEBUG_EAUTH_HEADER !== '0') {
        r.headers = Object.assign({}, r.headers || {}, { 'X-Debug-Reason': 'invalid:' + String(rawReason || 'unknown') });
    }
    return r;
}

function collapseBanned(rawReason, licenseKey, hwid, clientIp, extra) {
    console.warn('[validate-reject] kind=banned reason=' + String(rawReason || 'unknown')
        + ' key_prefix=' + String(licenseKey || '').slice(0, 14)
        + ' hwid_prefix=' + String(hwid || '').slice(0, 12)
        + ' ip=' + String(clientIp || ''));
    auditLog.logValidationFailure(REASON_BANNED, rawReason, licenseKey || '', hwid || '', clientIp || '', extra || null)
        .catch(() => {});
    auditLog.logV2({
        action: 'license.validate',
        license_key: licenseKey || '',
        hwid: hwid || '',
        source_ip: clientIp || '',
        decision: 'deny',
        reason_code: 'banned:' + String(rawReason || 'unknown'),
        extra: extra || {},
    }).catch(() => {});
    const r = buildEauthResult();
    if (process.env.AIDA_DEBUG_EAUTH_HEADER !== '0') {
        r.headers = Object.assign({}, r.headers || {}, { 'X-Debug-Reason': 'banned:' + String(rawReason || 'unknown') });
    }
    return r;
}

function collapseRateLimited(scope, retryAfterSeconds, licenseKey, hwid, clientIp) {
    console.warn('[validate-reject] kind=rate_limited scope=' + String(scope || '')
        + ' retry_after=' + String(retryAfterSeconds || 0)
        + ' key_prefix=' + String(licenseKey || '').slice(0, 14)
        + ' hwid_prefix=' + String(hwid || '').slice(0, 12)
        + ' ip=' + String(clientIp || ''));
    auditLog.logValidationFailure(REASON_RATE_LIMITED, 'rate_limited:' + (scope || ''), licenseKey || '', hwid || '', clientIp || '', { retry_after: retryAfterSeconds })
        .catch(() => {});
    auditLog.logV2({
        action: 'license.validate',
        license_key: licenseKey || '',
        hwid: hwid || '',
        source_ip: clientIp || '',
        decision: 'deny',
        reason_code: 'rate_limited:' + String(scope || ''),
        extra: { retry_after: retryAfterSeconds || 0 },
    }).catch(() => {});
    const r = buildEauthResult();
    if (process.env.AIDA_DEBUG_EAUTH_HEADER !== '0') {
        r.headers = Object.assign({}, r.headers || {}, { 'X-Debug-Reason': 'rate_limited:' + String(scope || '') });
    }
    return r;
}

function collapseHeartbeatDeny(reasonCode, licenseKey, hwid, clientIp, extra) {
    console.warn('[heartbeat-reject] reason=' + String(reasonCode || 'heartbeat_deny')
        + ' key_prefix=' + String(licenseKey || '').slice(0, 14)
        + ' hwid_prefix=' + String(hwid || '').slice(0, 12)
        + ' ip=' + String(clientIp || ''));
    auditLog.logV2({
        action: 'license.heartbeat',
        license_key: licenseKey || '',
        hwid: hwid || '',
        source_ip: clientIp || '',
        decision: 'deny',
        reason_code: String(reasonCode || 'heartbeat_deny'),
        extra: extra || {},
    }).catch(() => {});
    const r = buildEauthResult();
    if (process.env.AIDA_DEBUG_EAUTH_HEADER !== '0') {
        r.headers = Object.assign({}, r.headers || {}, { 'X-Debug-Reason': 'hb:' + String(reasonCode || 'heartbeat_deny') });
    }
    return r;
}

function constantTimeKeyMatch(submitted, expected) {
    const saltSource = process.env.SERVER_HMAC_SALT
        || process.env.ARC_MASTER_SECRET
        || 'aida-admin-cmp-v1';
    const salt = Buffer.from(String(saltSource), 'utf8');
    const a = crypto.createHmac('sha256', salt).update(String(submitted || ''), 'utf8').digest();
    const b = crypto.createHmac('sha256', salt).update(String(expected || ''), 'utf8').digest();
    return fixedLengthTimingSafeEqual(a, b);
}

function hashSessionToken(token) {
    return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

function computeHwidHash(hwid) {
    return crypto.createHash('sha256').update(String(hwid || ''), 'utf8').digest('hex');
}

function parseHexBuf(value, expectedLen) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(trimmed)) return null;
    if (expectedLen && trimmed.length !== expectedLen) return null;
    return Buffer.from(trimmed, 'hex');
}


const SESSION_TTL_SECONDS = 3600;
const SESSION_TTL_GRACE_FACTOR = 1.1;
const CHALLENGE_TTL_SECONDS = 30;
const NONCE_REPLAY_TTL_SECONDS = parseInt(process.env.NONCE_REPLAY_TTL_SECONDS || '60', 10);
const CHALLENGE_REQUIRED = (process.env.CHALLENGE_REQUIRED || '1') !== '0';
const HEARTBEAT_NONCE_MAX_AGE_SECONDS = 60;
const BIND_PROOF_HISTORY_LIMIT = 32;
const DRIVER_PROOF_REQUIRED_AFTER_SECONDS = 1800;
const DRIVER_PROOF_ABSENT_KILL_STREAK = 3;
const ENTERPRISE_PLAN_TIER = 'enterprise';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';
const TELEGRAM_BOT_TOKEN  = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID    = process.env.TELEGRAM_CHAT_ID || '';
const SLACK_WEBHOOK_URL   = process.env.SLACK_WEBHOOK_URL || '';
const TPM_REQUIRED_TIERS  = new Set((process.env.TPM_REQUIRED_TIERS || '').split(',').map(s => s.trim()).filter(Boolean));
const ANOMALY_DISABLED    = (process.env.ANOMALY_DISABLED || '0') === '1';
const ACTIVATION_WEBHOOK_URL = process.env.ACTIVATION_WEBHOOK_URL || DISCORD_WEBHOOK_URL;

const ED25519_KEY_ROTATION_NOT_BEFORE = parseInt(process.env.ED25519_KEY_NOT_BEFORE || '0', 10) || 0;
const ED25519_NEXT_PUBKEY_B64 = process.env.ED25519_NEXT_PUBKEY_B64 || '';
const ED25519_NEXT_NOT_BEFORE = parseInt(process.env.ED25519_NEXT_NOT_BEFORE || '0', 10) || 0;
const ED25519_NEXT_NEXT_PUBKEY_B64 = process.env.ED25519_NEXT_NEXT_PUBKEY_B64 || '';
const ED25519_NEXT_NEXT_NOT_BEFORE = parseInt(process.env.ED25519_NEXT_NEXT_NOT_BEFORE || '0', 10) || 0;

const CHALLENGE_SIGNING_SECRET = process.env.CHALLENGE_SIGNING_SECRET
    || process.env.ARC_MASTER_SECRET
    || '';

const HONEYPOT_POOL = [
    'NtProtectVirtualMemoryEx', 'RtlpSilentSuspend', 'DbgkpHiddenTrace',
    'KiEnableDebugHook', 'PspInvisibleTerminate', 'RtlSuppressPageTable',
    'MmGhostMap', 'CmRegisterSilentCallback', 'ObFilterHandleStripped',
    'PspRemapWithoutPeb', 'IoSealDispatch', 'RtlpFrontendTeleport',
];

const NON_ENFORCING_BAN_REASONS = new Set([
    'anomaly_auto_kill',
    'cross_session_anomaly_ban',
]);


function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function normalizeExpiryEpoch(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return Math.floor(value);
    if (typeof value === 'bigint') {
        const n = Number(value);
        return Number.isFinite(n) ? Math.floor(n) : 0;
    }
    if (typeof value === 'string' && value.trim() !== '') {
        const n = Number(value.trim());
        return Number.isFinite(n) ? Math.floor(n) : 0;
    }
    return 0;
}

function isLicenseExpired(data, nowSeconds = Math.floor(Date.now() / 1000)) {
    if (!data) return false;
    const epoch = normalizeExpiryEpoch(data.expires_epoch);
    if (epoch > 0) return nowSeconds > epoch;
    const expires = data.expires === undefined || data.expires === null ? '' : String(data.expires).trim();
    if (expires === '') return false;
    const parsed = parseExpiryInput(expires);
    if (parsed.ok && parsed.epoch > 0) return nowSeconds > parsed.epoch;
    return expires < todayStr();
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateServerNonce() {
    return crypto.randomBytes(16).toString('hex');
}

function decryptSessionRow(row) {
    if (!row) return row;
    const uuid = typeof row.session_uuid === 'string' ? row.session_uuid : '';
    if (!uuid) return row;
    if (typeof row.session_token === 'string' && columnCrypt.isCiphertext(row.session_token)) {
        try {
            row.session_token = columnCrypt.decrypt(uuid, 'sessions/session_token', row.session_token);
        } catch (err) {
            console.error('[license] session_token decrypt failed for', row.license_key, err && err.message);
            row.session_token = '';
        }
    }
    if (typeof row.last_proof_token === 'string' && row.last_proof_token.length > 0
        && columnCrypt.isCiphertext(row.last_proof_token)) {
        try {
            row.last_proof_token = columnCrypt.decrypt(uuid, 'sessions/last_proof_token', row.last_proof_token);
        } catch (err) {
            console.error('[license] last_proof_token decrypt failed for', row.license_key, err && err.message);
            row.last_proof_token = '';
        }
    }
    return row;
}

function sessionAuthHmacKeyBase64(session) {
    if (!session) return '';
    const raw = session.auth_hmac_key;
    if (Buffer.isBuffer(raw)) {
        return raw.length === 32 ? raw.toString('base64') : '';
    }
    if (typeof raw === 'string') {
        const text = raw.trim();
        if (/^[0-9a-fA-F]{64}$/.test(text)) {
            return Buffer.from(text, 'hex').toString('base64');
        }
        try {
            const decoded = Buffer.from(text, 'base64');
            return decoded.length === 32 ? decoded.toString('base64') : '';
        } catch (_) {
            return '';
        }
    }
    return '';
}

function encryptSessionToken(uuid, plaintext) {
    return columnCrypt.encrypt(uuid, 'sessions/session_token', plaintext);
}

function encryptProofToken(uuid, plaintext) {
    if (!plaintext || plaintext.length === 0) return '';
    return columnCrypt.encrypt(uuid, 'sessions/last_proof_token', plaintext);
}

function isHexNonce(value, minLength = 16, maxLength = 128) {
    return typeof value === 'string'
        && value.length >= minLength
        && value.length <= maxLength
        && /^[a-fA-F0-9]+$/.test(value);
}

function sanitizeReason(reason) {
    return typeof reason === 'string'
        ? reason.slice(0, 128).replace(/[^a-zA-Z0-9_ :\-]/g, '')
        : 'unknown';
}

function isNonEnforcingBanReason(reason) {
    return NON_ENFORCING_BAN_REASONS.has(String(reason || '').trim());
}

function normalizeBanCheckHwids(body) {
    const values = [];
    const append = value => {
        if (typeof value !== 'string') return;
        const trimmed = value.trim();
        if (trimmed.length < 8 || trimmed.length > 256) return;
        if (!values.includes(trimmed)) values.push(trimmed);
    };
    append(body && body.hwid);
    if (body && Array.isArray(body.hwids)) {
        for (const hwid of body.hwids.slice(0, 8)) append(hwid);
    }
    return values;
}

const FNV_OFFSET_64 = 0xCBF29CE484222325n;
const FNV_PRIME_64 = 0x00000100000001B3n;
const U64_MASK = 0xFFFFFFFFFFFFFFFFn;

function fnv1a64Hex(input) {
    const buf = Buffer.from(String(input || ''), 'utf8');
    let hash = FNV_OFFSET_64;
    for (let i = 0; i < buf.length; i++) {
        hash ^= BigInt(buf[i]);
        hash = (hash * FNV_PRIME_64) & U64_MASK;
    }
    return hash.toString(16).padStart(16, '0');
}

function buildProofTokenMessage(sessionToken, hwid, heartbeatCounter, codeHashHex) {
    const sessionFnv = fnv1a64Hex(sessionToken);
    const hwidFnv = fnv1a64Hex(hwid);
    const counter = Number.isFinite(heartbeatCounter) ? Math.max(0, Math.floor(heartbeatCounter)) : 0;
    const ch = typeof codeHashHex === 'string' ? codeHashHex.trim().toLowerCase() : '';
    const codeHash16 = /^[0-9a-f]{1,16}$/.test(ch) ? ch.padStart(16, '0') : '0000000000000000';
    return `${sessionFnv}|${hwidFnv}|${counter}|${codeHash16}`;
}

function parseProofTokenFirst8(value) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim().toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(trimmed)) return null;
    return Buffer.from(trimmed, 'hex');
}

function evaluateHeartbeatContinuity(session, body) {
    const proofToken = typeof body.proof_token === 'string' ? body.proof_token : '';
    const lastProofToken = typeof session.last_proof_token === 'string' ? session.last_proof_token : '';
    const rawHeartbeatCount = body.heartbeat_count;
    const heartbeatCount = typeof rawHeartbeatCount === 'number' && Number.isFinite(rawHeartbeatCount)
        ? Math.max(0, Math.floor(rawHeartbeatCount))
        : null;
    const serverCountRaw = Number(session.heartbeat_count || 0);
    const serverCount = Number.isFinite(serverCountRaw) ? Math.max(0, Math.floor(serverCountRaw)) : 0;
    const continuityReasons = [];

    if (!proofToken) {
        continuityReasons.push('missing_proof_token');
    } else if (lastProofToken && proofToken === lastProofToken) {
        continuityReasons.push('replayed_proof_token');
    }

    if (heartbeatCount !== null) {
        const expectedCount = serverCount + 1;
        if (heartbeatCount < expectedCount) {
            continuityReasons.push('heartbeat_count_regression');
        } else if (heartbeatCount > expectedCount + 5) {
            continuityReasons.push('heartbeat_count_skip');
        }
    }

    return {
        proof_token_to_store: proofToken.length > 0 ? proofToken : lastProofToken,
        continuity_reasons: continuityReasons,
        violation_reasons: [],
    };
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.ip
        || 'unknown';
}

function normalizeIp(ip) {
    return typeof ip === 'string' ? ip.replace(/[.:]/g, '_') : 'unknown';
}

function pickHoneypotExport() {
    const idx = crypto.randomInt(0, HONEYPOT_POOL.length);
    const salt = crypto.randomBytes(3).toString('hex');
    return `${HONEYPOT_POOL[idx]}_${salt}`;
}

function signChallenge(challengeId, challengeNonce, issuedAt, ttl) {
    if (!CHALLENGE_SIGNING_SECRET) return '';
    const canonical = `${challengeId}|${challengeNonce}|${issuedAt}|${ttl}`;
    return crypto.createHmac('sha256', CHALLENGE_SIGNING_SECRET)
        .update(canonical)
        .digest('hex');
}

async function createChallenge(clientIp) {
    const challengeId = crypto.randomBytes(12).toString('hex');
    const challengeNonce = crypto.randomBytes(16).toString('hex');
    const issuedAt = Math.floor(Date.now() / 1000);

    await pool.query(`
        INSERT INTO challenges (challenge_id, challenge_nonce, issued_at, ttl_seconds, client_ip, consumed)
        VALUES ($1, $2, $3, $4, $5, false)
    `, [challengeId, challengeNonce, issuedAt, CHALLENGE_TTL_SECONDS, clientIp || '']);

    const signature = signChallenge(challengeId, challengeNonce, issuedAt, CHALLENGE_TTL_SECONDS);
    return { challenge_id: challengeId, challenge_nonce: challengeNonce, issued_at: issuedAt, ttl: CHALLENGE_TTL_SECONDS, signature };
}

function compareHexConstantTime(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    const ba = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

async function consumeChallenge(challengeId, clientSignature, clientIp, licenseKey, rawBody) {
    if (!challengeId || typeof challengeId !== 'string' || !/^[a-fA-F0-9]{16,48}$/.test(challengeId)) {
        return { ok: false, reason: 'invalid_challenge_id' };
    }
    const { rows } = await pool.query('SELECT * FROM challenges WHERE challenge_id = $1', [challengeId]);
    if (rows.length === 0) return { ok: false, reason: 'challenge_not_found' };
    const ch = rows[0];
    if (ch.consumed) return { ok: false, reason: 'challenge_consumed' };

    const now = Math.floor(Date.now() / 1000);
    if (now > (ch.issued_at + ch.ttl_seconds)) {
        return { ok: false, reason: 'challenge_expired' };
    }

    if (CHALLENGE_SIGNING_SECRET) {
        if (typeof clientSignature !== 'string' || clientSignature.length === 0) {
            return { ok: false, reason: 'challenge_signature_mismatch' };
        }
        const expectedServerCanonical = signChallenge(ch.challenge_id, ch.challenge_nonce, ch.issued_at, ch.ttl_seconds);
        let matched = compareHexConstantTime(clientSignature, expectedServerCanonical);
        if (!matched && typeof rawBody === 'string') {
            const expectedClientHmacBody = crypto.createHmac('sha256', ch.challenge_nonce).update(rawBody).digest('hex');
            matched = compareHexConstantTime(clientSignature, expectedClientHmacBody);
        }
        if (!matched) {
            return { ok: false, reason: 'challenge_signature_mismatch' };
        }
    }

    await pool.query(
        'UPDATE challenges SET consumed = true, consumed_at = $1, license_key = $2 WHERE challenge_id = $3',
        [now, licenseKey || null, challengeId]
    );
    return { ok: true, challenge_nonce: ch.challenge_nonce };
}

async function purgeExpiredChallenges() {
    const cutoff = Math.floor(Date.now() / 1000) - (CHALLENGE_TTL_SECONDS * 10);
    try {
        await pool.query('DELETE FROM challenges WHERE issued_at < $1', [cutoff]);
    } catch (_) { }
}

setInterval(purgeExpiredChallenges, 60 * 1000).unref();

const TRANSIENT_PG_CODES = new Set(['57P01', '53300', '08006', '08001', '08003', '08004', '08P01', 'ECONNRESET', 'ETIMEDOUT']);

function isTransientError(err) {
    if (!err) return false;
    if (TRANSIENT_PG_CODES.has(err.code)) return true;
    if (typeof err.message === 'string' &&
        (err.message.includes('timeout') ||
         err.message.includes('Connection terminated') ||
         err.message.includes('connect ECONNREFUSED'))) return true;
    return false;
}

async function withPgRetry(fn) {
    try {
        return await fn();
    } catch (err) {
        if (isTransientError(err)) {
            await new Promise(r => setTimeout(r, 250));
            return await fn();
        }
        throw err;
    }
}

async function enforceChallenge(body, clientIp, licenseKey) {
    const challengeId = (body && body.challenge_id)
        || (body && body.__challenge_id_header)
        || '';
    const challengeSig = (body && body.challenge_signature)
        || (body && body.__challenge_signature_header)
        || '';
    const rawBody = (body && typeof body.__raw_body === 'string') ? body.__raw_body : '';
    if (!challengeId) {
        if (CHALLENGE_REQUIRED) return { ok: false, reason: 'missing_challenge' };
        return { ok: true, skipped: true };
    }
    return consumeChallenge(challengeId, challengeSig, clientIp, licenseKey, rawBody);
}

function buildRotationBlock() {
    const block = {};
    if (ED25519_KEY_ROTATION_NOT_BEFORE > 0) block.key_not_before = ED25519_KEY_ROTATION_NOT_BEFORE;
    if (ED25519_NEXT_PUBKEY_B64) {
        block.next_key_pubkey = ED25519_NEXT_PUBKEY_B64;
        block.next_key_not_before = ED25519_NEXT_NOT_BEFORE;
    }
    if (ED25519_NEXT_NEXT_PUBKEY_B64) {
        block.next_next_key_pubkey = ED25519_NEXT_NEXT_PUBKEY_B64;
        block.next_next_key_not_before = ED25519_NEXT_NEXT_NOT_BEFORE;
    }
    return block;
}


async function sendDiscordWebhook(title, fields, color = 0xFF4444) {
    if (!DISCORD_WEBHOOK_URL) return;
    try {
        const embed = {
            title,
            color,
            fields: fields.map(f => ({
                name: f.name,
                value: String(f.value).slice(0, 1024),
                inline: f.inline !== false,
            })),
            timestamp: new Date().toISOString(),
            footer: { text: 'AiDA Anti-RE System' },
        };
        await fetch(DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) {  }
}


async function sendTelegramAlert(title, fields) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
    try {
        let text = `<b>${title}</b>\n\n`;
        for (const f of fields) {
            text += `<b>${f.name}:</b> ${String(f.value).slice(0, 512)}\n`;
        }
        text += `\n<i>${new Date().toISOString()}</i>`;

        const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
        await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: TELEGRAM_CHAT_ID,
                text,
                parse_mode: 'HTML',
                disable_web_page_preview: true,
            }),
        });
    } catch (_) {  }
}


async function sendSlackAlert(title, fields, severity) {
    if (!SLACK_WEBHOOK_URL) return;
    try {
        const blocks = [
            { type: 'header', text: { type: 'plain_text', text: String(title).slice(0, 150) } },
        ];
        const fieldElems = fields.map(f => ({
            type: 'mrkdwn',
            text: `*${f.name}*\n${String(f.value).slice(0, 300)}`,
        }));
        while (fieldElems.length > 0) {
            const chunk = fieldElems.splice(0, 10);
            blocks.push({ type: 'section', fields: chunk });
        }
        const fallback = `${title} severity=${severity || 'warn'}`;
        await fetch(SLACK_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: fallback, blocks }),
        });
    } catch (_) { }
}


async function fetchGeolocation(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1') {
        return { country: 'localhost', countryCode: '', city: 'localhost', region: '', zip: '', lat: null, lon: null, timezone: '', isp: '', org: '', as: '', asname: '', mobile: false, proxy: false, hosting: false };
    }
    try {
        const fields = [
            'status',
            'country',
            'countryCode',
            'regionName',
            'city',
            'zip',
            'lat',
            'lon',
            'timezone',
            'isp',
            'org',
            'as',
            'asname',
            'mobile',
            'proxy',
            'hosting',
            'query',
        ].join(',');
        const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${encodeURIComponent(fields)}`, {
            signal: AbortSignal.timeout(3000),
        });
        if (!resp.ok) return { country: 'unknown', countryCode: '', city: 'unknown', region: '', zip: '', lat: null, lon: null, timezone: '', isp: '', org: '', as: '', asname: '', mobile: false, proxy: false, hosting: false };
        const data = await resp.json();
        if (data.status !== 'success') return { country: 'unknown', countryCode: '', city: 'unknown', region: '', zip: '', lat: null, lon: null, timezone: '', isp: '', org: '', as: '', asname: '', mobile: false, proxy: false, hosting: false };
        const lat = Number(data.lat);
        const lon = Number(data.lon);
        return {
            country: data.country || '',
            countryCode: data.countryCode || '',
            city: data.city || '',
            region: data.regionName || '',
            zip: data.zip || '',
            lat: Number.isFinite(lat) ? lat : null,
            lon: Number.isFinite(lon) ? lon : null,
            timezone: data.timezone || '',
            isp: data.isp || '',
            org: data.org || '',
            as: data.as || '',
            asname: data.asname || '',
            mobile: data.mobile === true,
            proxy: data.proxy === true,
            hosting: data.hosting === true,
        };
    } catch (_) {
        return { country: 'lookup_failed', countryCode: '', city: '', region: '', zip: '', lat: null, lon: null, timezone: '', isp: '', org: '', as: '', asname: '', mobile: false, proxy: false, hosting: false };
    }
}


function cleanWebhookText(value, maxLen = 256) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, maxLen);
}

function cleanDiscordId(value) {
    const cleaned = cleanWebhookText(value, 32);
    return /^[0-9]{15,25}$/.test(cleaned) ? cleaned : '';
}

function cleanDiscordUsername(value) {
    return cleanWebhookText(value, 96);
}

function maskLicenseKeyForWebhook(licenseKey) {
    const key = cleanWebhookText(licenseKey, 128);
    if (!key) return 'N/A';
    return key;
}

function formatDiscordUser(id, username) {
    const cleanId = cleanDiscordId(id);
    const cleanName = cleanDiscordUsername(username);
    if (cleanName && cleanId) return `${cleanName} (${cleanId})`;
    return cleanName || cleanId || 'N/A';
}

function formatCoordinates(geo) {
    if (!geo || !Number.isFinite(geo.lat) || !Number.isFinite(geo.lon)) return 'N/A';
    return `${geo.lat.toFixed(6)}, ${geo.lon.toFixed(6)}`;
}

function formatNetworkFlags(geo) {
    const flags = [];
    if (geo && geo.mobile) flags.push('mobile');
    if (geo && geo.proxy) flags.push('proxy');
    if (geo && geo.hosting) flags.push('hosting');
    return flags.length ? flags.join(', ') : 'none';
}

function activationDiscordMatch(discordInfo) {
    const keyId = cleanDiscordId(discordInfo && discordInfo.key && discordInfo.key.id);
    const localId = cleanDiscordId(discordInfo && discordInfo.local && discordInfo.local.id);
    if (!keyId || !localId) return 'unknown';
    return keyId === localId ? 'match' : 'mismatch';
}

async function sendActivationWebhook(details) {
    if (!ACTIVATION_WEBHOOK_URL) return;
    try {
        const success = !!details.success;
        const licenseKey = cleanWebhookText(details.licenseKey, 128);
        const hwid = cleanWebhookText(details.hwid, 1024);
        const clientIp = cleanWebhookText(details.clientIp, 96);
        const desktopName = cleanWebhookText(details.desktopName, 128);
        const failReason = cleanWebhookText(details.failReason, 256);
        const plan = cleanWebhookText(details.plan, 64);
        const discordInfo = details.discord || {};
        const keyDiscord = discordInfo.key || {};
        const localDiscord = discordInfo.local || {};
        const clientLatRaw = details.clientLat != null ? parseFloat(String(details.clientLat)) : NaN;
        const clientLonRaw = details.clientLon != null ? parseFloat(String(details.clientLon)) : NaN;
        const hasClientCoords = Number.isFinite(clientLatRaw) && Number.isFinite(clientLonRaw)
            && Math.abs(clientLatRaw) <= 90 && Math.abs(clientLonRaw) <= 180;
        const geo = await fetchGeolocation(clientIp);
        const geoStr = [geo.city, geo.region, geo.country].filter(Boolean).join(', ') || 'unknown';
        const color = success ? 0x00FF88 : 0xFF4444;
        const title = success ? 'License Activation Success' : 'License Activation Failed';
        const orgAsn = [geo.org, geo.asname, geo.as].filter(Boolean).join(' / ') || 'N/A';
        const liveCoords = hasClientCoords
            ? `${clientLatRaw.toFixed(6)}, ${clientLonRaw.toFixed(6)} (device)`
            : formatCoordinates(geo);
        const fields = [
            { name: 'Discord Username (Key)', value: cleanDiscordUsername(keyDiscord.username) || 'N/A', inline: true },
            { name: 'Discord User ID (Key)', value: cleanDiscordId(keyDiscord.id) || 'N/A', inline: true },
            { name: 'Discord Username (Local)', value: cleanDiscordUsername(localDiscord.username) || 'N/A', inline: true },
            { name: 'Discord User ID (Local)', value: cleanDiscordId(localDiscord.id) || 'N/A', inline: true },
            { name: 'Discord Match', value: activationDiscordMatch(discordInfo), inline: true },
            { name: 'Discord Summary', value: `Key: ${formatDiscordUser(keyDiscord.id, keyDiscord.username)}\nLocal: ${formatDiscordUser(localDiscord.id, localDiscord.username)}`, inline: false },
            { name: 'Desktop Name', value: desktopName || 'N/A', inline: true },
            { name: 'IP Address', value: clientIp || 'N/A', inline: true },
            { name: 'Geolocation', value: geoStr, inline: true },
            { name: 'Live Coordinates', value: liveCoords, inline: true },
            { name: 'Timezone', value: geo.timezone || 'N/A', inline: true },
            { name: 'ZIP / Country Code', value: [geo.zip, geo.countryCode].filter(Boolean).join(' / ') || 'N/A', inline: true },
            { name: 'ISP', value: geo.isp || 'N/A', inline: true },
            { name: 'Org / ASN', value: orgAsn, inline: true },
            { name: 'Network Flags', value: formatNetworkFlags(geo), inline: true },
            { name: 'License Key', value: maskLicenseKeyForWebhook(licenseKey), inline: true },
            { name: 'Plan', value: plan || 'N/A', inline: true },
            { name: 'HWID', value: hwid || 'N/A', inline: false },
        ];
        if (!success && failReason) {
            fields.push({ name: 'Failure Reason', value: failReason, inline: false });
        }
        const embed = {
            title,
            color,
            fields: fields.map(f => ({
                name: f.name,
                value: String(f.value).slice(0, 1024),
                inline: f.inline !== false,
            })),
            timestamp: new Date().toISOString(),
            footer: { text: 'AiDA License Activation Monitor' },
        };
        await fetch(ACTIVATION_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) { }
}


async function lookupDiscordUsername(discordId) {
    const cleanId = cleanDiscordId(discordId);
    if (!cleanId) return '';
    try {
        const { rows } = await pool.query(
            'SELECT payload FROM bot_command_log WHERE discord_id = $1 ORDER BY received_at DESC LIMIT 1',
            [cleanId]
        );
        if (rows.length > 0 && rows[0].payload) {
            const p = typeof rows[0].payload === 'string' ? JSON.parse(rows[0].payload) : rows[0].payload;
            return cleanDiscordUsername(p.discord_username || p.created_by || '');
        }
    } catch (_) { }
    return '';
}

async function resolveActivationDiscordInfo(licenseKey, body) {
    const info = {
        key: { id: '', username: '' },
        local: {
            id: cleanDiscordId(body && (body.local_discord_id || body.discord_id)),
            username: cleanDiscordUsername(body && (body.local_discord_username || body.discord_username)),
        },
    };
    try {
        const { rows } = await pool.query(
            'SELECT discord_id, discord_username, created_by FROM licenses WHERE key = $1',
            [licenseKey]
        );
        if (rows.length > 0) {
            info.key.id = cleanDiscordId(rows[0].discord_id);
            info.key.username = cleanDiscordUsername(rows[0].discord_username || rows[0].created_by || '');
        }
    } catch (_) { }
    if (info.key.id && !info.key.username) {
        info.key.username = await lookupDiscordUsername(info.key.id);
    }
    if (info.local.id && !info.local.username) {
        info.local.username = await lookupDiscordUsername(info.local.id);
    }
    return info;
}


function isTpmRequiredForLicense(lic) {
    void lic;
    return false;
}


function combineHardwareIdWithTpm(existingHwid, tpmHwidComponent) {
    if (!tpmHwidComponent) return existingHwid;
    if (!existingHwid) return tpmHwidComponent;
    return crypto.createHash('sha256')
        .update(String(existingHwid))
        .update('|tpm-bound|')
        .update(String(tpmHwidComponent))
        .digest('hex');
}


async function persistTpmAttestation(licenseKey, verifyResult, sealPayload) {
    const now = Math.floor(Date.now() / 1000);
    try {
        await pool.query(
            `UPDATE licenses SET
                tpm_ek_fingerprint  = $1,
                tpm_ek_vendor       = $2,
                tpm_pcr_digest      = $3,
                tpm_attest_count    = tpm_attest_count + 1,
                tpm_last_attest_at  = $4,
                tpm_seal_payload    = COALESCE($5, tpm_seal_payload)
             WHERE key = $6`,
            [
                verifyResult.ekCertFingerprint,
                verifyResult.ekVendor || '',
                verifyResult.pcrDigestHex,
                now,
                sealPayload ? JSON.stringify(sealPayload) : null,
                licenseKey,
            ]
        );
    } catch (err) {
        console.error('[tpm] persistTpmAttestation failed:', err && err.message ? err.message : err);
    }
}


function buildTpmSealedPayload(lic, verifyResult, sessionToken) {
    if (!verifyResult || !verifyResult.ekPublicKey) return null;
    if (!lic || !lic.witness_key_wrapped) return null;
    let kw;
    try { kw = kwWrap.unwrap(lic.witness_key_wrapped, 'kw/v1'); }
    catch (_) { return null; }
    const subkey = kwWrap.deriveKwSubkey(kw, 'tpm_seal/v1');
    const wrappingMaterial = crypto.createHmac('sha256', subkey)
        .update(String(sessionToken || ''))
        .update('|')
        .update(String(verifyResult.ekCertFingerprint || ''))
        .digest();
    const indices = tpmQuote.REQUIRED_PCR_INDICES;
    const pcrMap = {};
    for (const idx of indices) pcrMap[idx] = Buffer.from('00'.repeat(32), 'hex');
    try {
        return tpmQuote.sealLicenseKeyForClient(wrappingMaterial, verifyResult.ekPublicKey, pcrMap);
    } catch (err) {
        console.error('[tpm] buildTpmSealedPayload failed:', err && err.message ? err.message : err);
        return null;
    }
}


async function applyAnomalyDecision(licenseKey, hwid, clientIp, body, decision) {
    if (!decision) return null;
    const now = Math.floor(Date.now() / 1000);
    try {
        await pool.query(
            `UPDATE licenses SET
                anomaly_last_score  = $1,
                anomaly_last_action = $2,
                anomaly_last_at     = $3
             WHERE key = $4`,
            [decision.score, decision.action, now, licenseKey]
        );
    } catch (err) {
        console.warn('[anomaly] persist last-decision failed:', err && err.message ? err.message : err);
    }

    if (decision.action === 'flag') {
        try {
            await pool.query(
                `UPDATE licenses SET
                    flagged        = true,
                    flagged_reason = $1,
                    flagged_at     = $2,
                    flagged_score  = $3
                 WHERE key = $4`,
                [decision.reason || 'anomaly_flag', now, decision.score, licenseKey]
            );
        } catch (err) {
            console.warn('[anomaly] flag persist failed:', err && err.message ? err.message : err);
        }
        await anomalyScore.getDefaultEngine().dispatchAlerts(decision, licenseKey, hwid).catch(() => {});
        return { action: 'flag', score: decision.score };
    }

    if (decision.action === 'revoke') {
        const reason = `anomaly_revoke:${decision.score.toFixed(3)}`;
        try {
            await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [licenseKey]);
        } catch (_) { }
        try {
            await revokeLicenseAndSession(licenseKey, reason, body && body.plugin_version, hwid);
        } catch (err) {
            console.error('[anomaly] revoke failed:', err && err.message ? err.message : err);
        }
        try {
            await recordBan(hwid, clientIp, reason, body && body.plugin_version, {
                route: 'license',
                action: 'anomaly',
                license_key: licenseKey,
                reasons: ['anomaly_auto_revoke'],
                evidence: {
                    score: decision.score,
                    perMetric: decision.perMetric,
                    metrics: decision.metrics,
                    sample_count: decision.sampleCount,
                },
            });
        } catch (_) { }
        await anomalyScore.getDefaultEngine().dispatchAlerts(decision, licenseKey, hwid).catch(() => {});
        return { action: 'revoke', score: decision.score, reason };
    }

    return { action: decision.action, score: decision.score };
}


async function ingestHeartbeatAnomaly(licenseKey, hwid, clientIp, body, session) {
    if (ANOMALY_DISABLED) return null;
    if (!licenseKey) return null;
    const metrics = anomalyScore.extractMetricsFromHeartbeat(body, session);
    if (Object.keys(metrics).length === 0) return null;
    const engine = anomalyScore.getDefaultEngine();
    const decision = engine.evaluate(licenseKey, metrics);
    engine.record(licenseKey, metrics, Date.now());
    if (decision.action === 'observe' || decision.action === 'warmup') {
        return { decision, applied: { action: decision.action, score: decision.score } };
    }
    const applied = await applyAnomalyDecision(licenseKey, hwid, clientIp, body, decision);
    return { decision, applied };
}


async function ensureLicenseSecrets(licenseKey, data) {
    if (!data || typeof data !== 'object') return data;
    let mutated = false;
    let installSecretWrapped = data.install_secret_wrapped;
    let witnessKeyWrapped = data.witness_key_wrapped;

    if (!installSecretWrapped || (Buffer.isBuffer(installSecretWrapped) && installSecretWrapped.length === 0)) {
        try {
            const installSecret = kwWrap.generateInstallSecret();
            installSecretWrapped = kwWrap.wrap(installSecret, 'install_secret/v1');
            mutated = true;
        } catch (err) {
            console.error('[license] backfill install_secret_wrapped failed:', err && err.message ? err.message : err);
        }
    }

    if (!witnessKeyWrapped || (Buffer.isBuffer(witnessKeyWrapped) && witnessKeyWrapped.length === 0)) {
        try {
            const kw = kwWrap.generateWitnessKey();
            witnessKeyWrapped = kwWrap.wrap(kw, 'kw/v1');
            mutated = true;
        } catch (err) {
            console.error('[license] backfill witness_key_wrapped failed:', err && err.message ? err.message : err);
        }
    }

    if (mutated) {
        try {
            await pool.query(
                `UPDATE licenses
                    SET install_secret_wrapped = COALESCE($1, install_secret_wrapped),
                        witness_key_wrapped    = COALESCE($2, witness_key_wrapped)
                  WHERE key = $3`,
                [installSecretWrapped, witnessKeyWrapped, licenseKey]
            );
            data.install_secret_wrapped = installSecretWrapped;
            data.witness_key_wrapped = witnessKeyWrapped;
            console.log('[license] backfilled install_secret_wrapped/witness_key_wrapped for key', licenseKey.slice(0, 12) + '...');
        } catch (err) {
            console.error('[license] backfill UPDATE failed:', err && err.message ? err.message : err);
        }
    }
    return data;
}

async function lookupLicense(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') {
        console.warn('[lookupLicense] missing_key type=' + typeof licenseKey);
        return { valid: false, reason: 'missing_key' };
    }
    console.warn('[lookupLicense] in_key len=' + licenseKey.length
        + ' prefix=' + licenseKey.slice(0, 14)
        + ' is_format2_candidate=' + keyFormat.format2IsCandidate(licenseKey)
        + ' is_modern=' + keyFormat.isModernKey(licenseKey)
        + ' is_legacy=' + keyFormat.isLegacyKey(licenseKey));
    if (keyFormat.format2IsCandidate(licenseKey)) {
        const verdict = keyFormat.format2Decode(licenseKey);
        if (!verdict.ok) {
            console.warn('[lookupLicense] format2_decode_failed reason=' + verdict.reason);
            if (verdict.reason === 'format2_crc') {
                replayCounter.recordFormat2CrcFail(licenseKey, { reason: verdict.reason }).catch(() => {});
            }
            return { valid: false, reason: 'invalid_format' };
        }
    }
    const normalized = keyFormat.normalizeForLookup(licenseKey);
    if (!normalized) {
        console.warn('[lookupLicense] normalizeForLookup_returned_empty raw_key=' + JSON.stringify(licenseKey));
        return { valid: false, reason: 'invalid_format' };
    }

    const { rows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [normalized]
    );
    if (rows.length === 0) {
        console.warn('[lookupLicense] not_found normalized=' + normalized);
        return { valid: false, reason: 'not_found' };
    }

    const data = rows[0];

    if (!data.active) {
        return { valid: false, reason: 'revoked', data };
    }
    if (isLicenseExpired(data)) {
        return { valid: false, reason: 'expired', data };
    }

    await ensureLicenseSecrets(normalized, data);

    return { valid: true, data };
}

function parseHwidFactors(value) {
    if (!value) return {};
    if (typeof value === 'object' && !Buffer.isBuffer(value)) return value;
    try {
        return JSON.parse(typeof value === 'string' ? value : value.toString('utf8'));
    } catch (_) {
        return {};
    }
}

function deriveHwidFactors(body) {
    const factors = {};
    const append = (label, raw) => {
        if (typeof raw !== 'string' || raw.length === 0) return;
        factors[label] = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
    };
    append('smbios_uuid', body && body.smbios_uuid_hash);
    append('baseboard', body && body.baseboard_serial_hash);
    append('disk_vpd', body && body.disk_vpd_hash);
    append('machine_guid', body && body.machine_guid_hash);
    append('hardware_id', body && body.hardware_id_sha256);
    append('hwid', body && body.hwid);
    if (Object.keys(factors).length === 0 && body && typeof body.hwid === 'string' && body.hwid.length > 0) {
        factors.hwid = crypto.createHash('sha256').update(body.hwid, 'utf8').digest('hex');
    }
    return factors;
}

function compareHwidFactors(prev, current) {
    if (!prev || !current) {
        return { changed: 99, changed_keys: [], total: 0 };
    }
    const keys = new Set([...Object.keys(prev), ...Object.keys(current)]);
    const changedKeys = [];
    for (const k of keys) {
        if (prev[k] && current[k] && prev[k] !== current[k]) changedKeys.push(k);
        else if (!prev[k] && current[k]) changedKeys.push(k);
        else if (prev[k] && !current[k]) changedKeys.push(k);
    }
    return { changed: changedKeys.length, changed_keys: changedKeys, total: keys.size };
}

async function persistHwidFactors(licenseKey, factors) {
    try {
        await pool.query(
            'UPDATE licenses SET hwid_factors = $1::jsonb WHERE key = $2',
            [JSON.stringify(factors || {}), licenseKey]
        );
    } catch (_) { }
}

async function verifyOrBindHwid(licenseKey, hwid, existingHwid, options) {
    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 256) {
        return { ok: false, reason: 'invalid_hwid' };
    }

    if (!existingHwid || existingHwid === '') {

        await pool.query(
            'UPDATE licenses SET hwid = $1 WHERE key = $2 AND hwid = $3',
            [hwid, licenseKey, '']
        );
        if (options && options.factors) {
            await persistHwidFactors(licenseKey, options.factors);
        }
        return { ok: true, reason: 'bound' };
    }

    if (existingHwid !== hwid) {
        if (options && options.factors && options.licenseRow) {
            const prevFactors = parseHwidFactors(options.licenseRow.hwid_factors);
            const comparison = compareHwidFactors(prevFactors, options.factors);
            const graceUsedAt = Number(options.licenseRow.hwid_grace_used_at || 0);
            const now = Math.floor(Date.now() / 1000);
            const withinCooldown = graceUsedAt > 0 && (now - graceUsedAt) < HWID_GRACE_WINDOW_SECONDS;
            if (comparison.changed === 1 && !withinCooldown) {
                try {
                    await pool.query(
                        'UPDATE licenses SET hwid = $1, hwid_factors = $2::jsonb, hwid_grace_used_at = $3 WHERE key = $4',
                        [hwid, JSON.stringify(options.factors), now, licenseKey]
                    );
                } catch (_) { }
                auditLog.logServerEvent('license.hwid_grace_accepted', licenseKey, {
                    changed_keys: comparison.changed_keys,
                    previous_hwid_prefix: typeof existingHwid === 'string' ? existingHwid.slice(0, 16) : '',
                    new_hwid_prefix: hwid.slice(0, 16),
                }).catch(() => {});
                return { ok: true, reason: 'grace_accepted' };
            }
        }
        return { ok: false, reason: 'hwid_mismatch' };
    }

    if (options && options.factors) {
        const prevFactors = parseHwidFactors(options.licenseRow && options.licenseRow.hwid_factors);
        if (Object.keys(prevFactors).length === 0) {
            await persistHwidFactors(licenseKey, options.factors);
        }
    }

    return { ok: true, reason: 'match' };
}

async function storeSession(licenseKey, sessionData) {
    const sessionUuid = columnCrypt.generateRowUuid();
    const sessionTokenWrapped = encryptSessionToken(sessionUuid, sessionData.session_token);
    const authHmacKey = sessionData.auth_hmac_key_buf || crypto.randomBytes(32);
    const bindContribution = sessionData.bind_contribution || Buffer.alloc(0);
    const bindResponseHash = sessionData.bind_response_hash || '';
    const sessionKeyFingerprint = sessionData.session_key_fingerprint || '';
    await pool.query(`
        INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat, kill_flag, heartbeat_count, last_proof_token, last_code_hash, ip_history, heartbeat_times, honeypot_export, challenge_id, last_chain_tag, session_uuid, column_crypt_version, auth_hmac_key, anomaly_score, driver_proof_absent_streak, bind_contribution, bind_response_hash, session_key_fingerprint, sentinel_bind_token_hash, sentinel_bind_consumed, sentinel_bind_issued_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, 0, '', '', ARRAY[$7]::TEXT[], ARRAY[]::BIGINT[], $10, $11, '', $12, 1, $13, 0, 0, $14, $15, $16, '', false, 0)
        ON CONFLICT (license_key) DO UPDATE SET
            session_token             = EXCLUDED.session_token,
            server_nonce              = EXCLUDED.server_nonce,
            issued_at                 = EXCLUDED.issued_at,
            ttl                       = EXCLUDED.ttl,
            hwid                      = EXCLUDED.hwid,
            ip                        = EXCLUDED.ip,
            plugin_version            = EXCLUDED.plugin_version,
            last_heartbeat            = EXCLUDED.last_heartbeat,
            kill_flag                 = false,
            heartbeat_count           = 0,
            last_proof_token          = '',
            last_code_hash            = '',
            ip_history                = ARRAY[EXCLUDED.ip]::TEXT[],
            heartbeat_times           = ARRAY[]::BIGINT[],
            honeypot_export           = EXCLUDED.honeypot_export,
            challenge_id              = EXCLUDED.challenge_id,
            last_chain_tag            = '',
            last_gate_bitmap          = 0,
            session_uuid              = EXCLUDED.session_uuid,
            column_crypt_version      = 1,
            auth_hmac_key             = EXCLUDED.auth_hmac_key,
            anomaly_score             = 0,
            driver_proof_absent_streak = 0,
            bind_contribution         = EXCLUDED.bind_contribution,
            bind_response_hash        = EXCLUDED.bind_response_hash,
            session_key_fingerprint   = EXCLUDED.session_key_fingerprint,
            sentinel_bind_token_hash  = '',
            sentinel_bind_consumed    = false,
            sentinel_bind_issued_at   = 0
    `, [
        licenseKey,
        sessionTokenWrapped,
        sessionData.server_nonce,
        sessionData.issued_at,
        sessionData.ttl,
        sessionData.hwid,
        sessionData.ip,
        sessionData.plugin_version,
        sessionData.last_heartbeat,
        sessionData.honeypot_export || '',
        sessionData.challenge_id || '',
        sessionUuid,
        authHmacKey,
        bindContribution,
        bindResponseHash,
        sessionKeyFingerprint,
    ]);
    return { authHmacKey };
}

function deriveLicenseSecret(licenseRow) {
    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }
    const witness = licenseRow && licenseRow.witness_key_wrapped
        ? (Buffer.isBuffer(licenseRow.witness_key_wrapped)
            ? licenseRow.witness_key_wrapped
            : Buffer.from(licenseRow.witness_key_wrapped))
        : Buffer.alloc(0);
    const install = licenseRow && licenseRow.install_secret_wrapped
        ? (Buffer.isBuffer(licenseRow.install_secret_wrapped)
            ? licenseRow.install_secret_wrapped
            : Buffer.from(licenseRow.install_secret_wrapped))
        : Buffer.alloc(0);
    return crypto.createHmac('sha256', Buffer.from(masterSecret, 'utf8'))
        .update('license_secret|', 'utf8')
        .update(String(licenseRow && licenseRow.key || ''), 'utf8')
        .update('|', 'utf8')
        .update(witness)
        .update('|', 'utf8')
        .update(install)
        .digest();
}

function deriveBindResponse(licenseSecret, nonceC2, hwid, issuedAt, bindContribution) {
    const mac = crypto.createHmac('sha256', licenseSecret)
        .update('bind|', 'utf8')
        .update(String(nonceC2 || ''), 'utf8')
        .update('|', 'utf8')
        .update(String(hwid || ''), 'utf8')
        .update('|', 'utf8')
        .update(String(issuedAt || 0), 'utf8')
        .digest();
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
        out[i] = mac[i] ^ (bindContribution[i] || 0);
    }
    return { bind_response: out, server_hmac: mac };
}

async function getSession(licenseKey) {
    const { rows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (rows.length === 0) return null;
    return decryptSessionRow(rows[0]);
}

async function updateLastProofToken(licenseKey, plaintextProof) {
    const { rows } = await pool.query(
        'SELECT session_uuid FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (rows.length === 0) return false;
    const uuid = rows[0].session_uuid;
    const wrapped = encryptProofToken(uuid, plaintextProof || '');
    await pool.query(
        'UPDATE sessions SET last_proof_token = $1 WHERE license_key = $2',
        [wrapped, licenseKey]
    );
    return true;
}

async function checkBans(hwid, clientIp) {
    if (hwid) {
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND value = $2',
            ['hwid', hwid]
        );
        const activeBan = rows.find(row => !isNonEnforcingBanReason(row.reason));
        if (activeBan) {
            return { banned: true, reason: 'hwid_banned', data: activeBan };
        }
    }
    if (clientIp && clientIp !== 'unknown') {
        const normalized = normalizeIp(clientIp);
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND (value = $2 OR value = $3)',
            ['ip', clientIp, normalized]
        );
        const activeBan = rows.find(row => !isNonEnforcingBanReason(row.reason));
        if (activeBan) {
            return { banned: true, reason: 'ip_banned', data: activeBan };
        }
    }
    return { banned: false };
}

async function handleBanCheck(body, clientIp) {
    const ipBan = await checkBans('', clientIp);
    if (ipBan.banned) {
        return {
            status: 200,
            body: {
                status: 'banned',
                banned: true,
                reason: ipBan.reason,
                ban_reason: ipBan.data && ipBan.data.reason ? ipBan.data.reason : '',
                ban_type: ipBan.data && ipBan.data.ban_type ? ipBan.data.ban_type : 'ip',
            },
        };
    }

    const hwids = normalizeBanCheckHwids(body);
    for (const hwid of hwids) {
        const hwidBan = await checkBans(hwid, '');
        if (hwidBan.banned) {
            return {
                status: 200,
                body: {
                    status: 'banned',
                    banned: true,
                    reason: hwidBan.reason,
                    ban_reason: hwidBan.data && hwidBan.data.reason ? hwidBan.data.reason : '',
                    ban_type: hwidBan.data && hwidBan.data.ban_type ? hwidBan.data.ban_type : 'hwid',
                },
            };
        }
    }

    return { status: 200, body: { status: 'ok', banned: false } };
}

async function revokeLicenseAndSession(licenseKey, reason, version, hwid) {
    if (!licenseKey) return;
    const now = Math.floor(Date.now() / 1000);

    await pool.query(`
        UPDATE licenses SET
            active = false,
            revoked_at = $1,
            revoked_at_iso = $2,
            revoked_reason = $3,
            revoked_version = $4,
            revoked_hwid = $5
        WHERE key = $6
    `, [now, new Date().toISOString(), reason || 'violation', version || 'unknown', hwid || '', licenseKey]);

    await pool.query('DELETE FROM sessions WHERE license_key = $1', [licenseKey]);
}

async function recordBan(hwid, clientIp, reason, version, context = {}) {
    const now = Math.floor(Date.now() / 1000);
    const isoNow = new Date().toISOString();
    const sanitized = reason || 'violation';


    if (hwid) {
        await pool.query(`
            INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, ip)
            VALUES ('hwid', $1, $2, $3, $4, $5, $6)
            ON CONFLICT (ban_type, value) DO UPDATE SET
                reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                banned_at_iso = EXCLUDED.banned_at_iso, plugin_version = EXCLUDED.plugin_version
        `, [hwid, sanitized, now, isoNow, version || 'unknown', clientIp || 'unknown']);
    }


    if (clientIp && clientIp !== 'unknown') {
        const normalized = normalizeIp(clientIp);
        await pool.query(`
            INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, hwid, original_ip)
            VALUES ('ip', $1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (ban_type, value) DO UPDATE SET
                reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                banned_at_iso = EXCLUDED.banned_at_iso, plugin_version = EXCLUDED.plugin_version
        `, [normalized, sanitized, now, isoNow, version || 'unknown', hwid || 'unknown', clientIp]);
    }


    await pool.query(`
        INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, [hwid || 'unknown', clientIp || 'unknown', sanitized, now, isoNow, version || 'unknown']);


    let deletedKeys = [];
    if (hwid) {
        const { rows } = await pool.query(
            'SELECT key FROM licenses WHERE hwid = $1',
            [hwid]
        );
        deletedKeys = rows.map(r => r.key);

        if (deletedKeys.length > 0) {
            await pool.query('DELETE FROM sessions WHERE license_key = ANY($1)', [deletedKeys]);
            await pool.query('DELETE FROM licenses WHERE key = ANY($1)', [deletedKeys]);
        }
    }


    const fields = [
        { name: '\uD83D\uDEA8 Reason', value: sanitized },
        { name: 'Route', value: context.route || 'license' },
        { name: 'Action', value: context.action || 'enforce' },
        { name: 'License', value: context.license_key ? `\`${context.license_key}\`` : 'unknown' },
        { name: '\uD83D\uDDA5\uFE0F HWID', value: `\`${hwid || 'unknown'}\`` },
        { name: '\uD83C\uDF10 IP', value: `\`${clientIp || 'unknown'}\`` },
        { name: '\uD83D\uDCE6 Version', value: version || 'unknown' },
    ];
    if (context.session_token) {
        fields.push({ name: 'Session', value: `\`${String(context.session_token).slice(0, 16)}...\`` });
    }
    if (Array.isArray(context.reasons) && context.reasons.length > 0) {
        fields.push({ name: 'Signals', value: context.reasons.join(', ') });
    }
    if (context.evidence) {
        fields.push({ name: 'Evidence', value: typeof context.evidence === 'string' ? context.evidence : JSON.stringify(context.evidence) });
    }
    if (deletedKeys.length > 0) {
        fields.push({
            name: '\uD83D\uDDD1\uFE0F Deleted Keys',
            value: deletedKeys.map(k => `\`${k}\``).join(', '),
        });
    }
    await sendDiscordWebhook('\uD83D\uDEA8 AiDA Violation Detected', fields, 0xFF0000);
    await sendTelegramAlert('\uD83D\uDEA8 AiDA Violation Detected', fields);
}


async function handleValidate(body, clientIp) {
    const { license_key, hwid, client_nonce, plugin_version } = body;

    if (!license_key || !hwid || !client_nonce) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    if (!isHexNonce(client_nonce)) {
        return { status: 400, body: { status: 'error', reason: 'invalid_nonce' } };
    }


    if (body.timestamp && typeof body.timestamp === 'number') {
        const driftMs = Math.abs(Date.now() - (body.timestamp * 1000));
        if (driftMs > REQ_TIME_WINDOW_MS) {
            await replayCounter.recordSignatureInvalid(license_key, '', { reason: 'validate_clock_drift', drift_ms: driftMs, limit_ms: REQ_TIME_WINDOW_MS });
            return collapseInvalid('clock_drift', license_key, hwid, clientIp);
        }
    }

    if (typeof body.req_ts_ms === 'number' && Number.isFinite(body.req_ts_ms)) {
        const driftMs = Math.abs(Date.now() - Math.floor(body.req_ts_ms));
        if (driftMs > REQ_TIME_WINDOW_MS) {
            await replayCounter.recordSignatureInvalid(license_key, '', { reason: 'validate_req_ts_drift', drift_ms: driftMs, limit_ms: REQ_TIME_WINDOW_MS });
            return collapseInvalid('req_ts_drift', license_key, hwid, clientIp);
        }
    }

    const rl = await licenseRateLimit.check(license_key, {});
    if (!rl.ok) {
        return collapseRateLimited(rl.scope, rl.retry_after, license_key, hwid, clientIp);
    }

    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return collapseBanned(banCheck.reason, license_key, hwid, clientIp);
    }


    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return collapseInvalid('lookup:' + (lookup.reason || 'unknown'), license_key, hwid, clientIp);
    }
    const normalizedLicenseKey = lookup.data.key;


    const chResult = await enforceChallenge(body, clientIp, normalizedLicenseKey);
    if (!chResult.ok) {
        return collapseInvalid('challenge:' + (chResult.reason || 'unknown'), normalizedLicenseKey, hwid, clientIp);
    }


    let tpmVerify = null;
    let effectiveHwid = hwid;
    const tpmBundle = body && body.tpm_attest;
    if (tpmBundle && typeof tpmBundle === 'object') {
        const enriched = Object.assign({}, tpmBundle, {
            existingAnchorString: hwid,
            expectedNonce: tpmBundle.expectedNonce || tpmBundle.expected_nonce || client_nonce,
        });
        const result = tpmQuote.verifyTpmQuote(enriched);
        if (!result.ok) {
            return collapseInvalid('tpm_quote_invalid:' + (result.reason || 'unknown'), normalizedLicenseKey, hwid, clientIp);
        }
        tpmVerify = result;
        effectiveHwid = combineHardwareIdWithTpm(hwid, result.hwidComponentHex);
        if (lookup.data.tpm_ek_fingerprint && lookup.data.tpm_ek_fingerprint !== result.ekCertFingerprint) {
            return collapseInvalid('tpm_ek_mismatch', normalizedLicenseKey, hwid, clientIp);
        }
    } else if (isTpmRequiredForLicense(lookup.data)) {
        return collapseInvalid('tpm_attest_required', normalizedLicenseKey, hwid, clientIp);
    }


    const hwidFactors = deriveHwidFactors(Object.assign({}, body, { hwid: effectiveHwid }));
    const hwidResult = await verifyOrBindHwid(normalizedLicenseKey, effectiveHwid, lookup.data.hwid || '', {
        factors: hwidFactors,
        licenseRow: lookup.data,
    });
    if (!hwidResult.ok) {
        return collapseInvalid('hwid:' + (hwidResult.reason || 'unknown'), normalizedLicenseKey, hwid, clientIp);
    }

    const capsuleResult = await enforceStandaloneCapsuleProof('validate', lookup.data, body, {
        license_key: normalizedLicenseKey,
        hwid,
    });
    if (!capsuleResult.ok) {
        return collapseInvalid('capsule:' + (capsuleResult.reason || 'invalid'), normalizedLicenseKey, hwid, clientIp);
    }

    try {
        const peerState = await peerCodeHash.getSessionPeerState(normalizedLicenseKey);
        if (peerState && Number(peerState.peer_attest_divergence_streak || 0) >= 5) {
            await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [normalizedLicenseKey]);
            return collapseInvalid('peer_code_hash_divergent', normalizedLicenseKey, hwid, clientIp);
        }
    } catch (_) { }

    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = SESSION_TTL_SECONDS;
    const honeypotExport = pickHoneypotExport();
    const hwidHashForSeal = computeHwidHash(effectiveHwid);
    const tierForSeal = lookup.data.tier || lookup.data.plan || 'standard';
    const sessionToken = sessionAead.seal(normalizedLicenseKey, hwidHashForSeal, issuedAt, ttl, tierForSeal);
    const serverNonce = generateServerNonce();

    let licenseSecret = null;
    try {
        licenseSecret = deriveLicenseSecret(lookup.data);
    } catch (err) {
        console.error('[license] deriveLicenseSecret failed:', err && err.message ? err.message : err);
        return collapseInvalid('license_secret_unavailable', normalizedLicenseKey, hwid, clientIp);
    }

    let bindContributionBuf = parseHexBuf(body.bind_contribution, 64);
    if (!bindContributionBuf) {
        bindContributionBuf = Buffer.alloc(32);
    }
    const bindDerivation = deriveBindResponse(licenseSecret, body.client_nonce_c2 || body.client_nonce, effectiveHwid, issuedAt, bindContributionBuf);
    const sessionKey = sessionAead.deriveSessionKey(licenseSecret, sessionToken, effectiveHwid, issuedAt);
    const authHmacKey = sessionAead.deriveAuthHmacKey(sessionKey);
    const sessionKeyFingerprint = crypto.createHash('sha256').update(sessionKey).digest('hex').slice(0, 16);

    const sessionStore = await storeSession(normalizedLicenseKey, {
        session_token: sessionToken,
        server_nonce: serverNonce,
        issued_at: issuedAt,
        ttl,
        hwid: effectiveHwid,
        ip: clientIp,
        plugin_version: plugin_version || 'unknown',
        last_heartbeat: issuedAt,
        honeypot_export: honeypotExport,
        challenge_id: (body && body.challenge_id) || '',
        auth_hmac_key_buf: authHmacKey,
        bind_contribution: bindContributionBuf,
        bind_response_hash: crypto.createHash('sha256').update(bindDerivation.bind_response).digest('hex'),
        session_key_fingerprint: sessionKeyFingerprint,
    });

    await rateLimit.registerNonce(normalizedLicenseKey, sessionToken, 'issued:' + serverNonce, NONCE_REPLAY_TTL_SECONDS);

    let tpmSealed = null;
    if (tpmVerify) {
        tpmSealed = buildTpmSealedPayload(lookup.data, tpmVerify, sessionToken);
        await persistTpmAttestation(normalizedLicenseKey, tpmVerify, tpmSealed);
    }

    const keySeed = deriveKeySeed(sessionToken, effectiveHwid, issuedAt);

    let bindProofHex = '';
    try {
        const bindProof = arcLicenseBind.deriveBindProof(lookup.data, sessionToken, effectiveHwid, issuedAt, 0n);
        bindProofHex = bindProof.toString('hex');
    } catch (err) {
        console.error('[license] bind_proof derivation failed:', err && err.message ? err.message : err);
        bindProofHex = '';
    }

    const initialHbNonce = generateServerNonce();
    const tpmDigestSeed = tpmVerify ? (tpmVerify.pcrDigestHex || '')
        : (lookup.data && typeof lookup.data.tpm_pcr_digest === 'string' ? lookup.data.tpm_pcr_digest : '');
    let rotatingBindProofHex = '';
    try {
        const proof = arcLicenseBind.deriveRotatingBindProof(
            lookup.data, sessionToken, effectiveHwid, 0n, initialHbNonce, tpmDigestSeed);
        rotatingBindProofHex = proof.toString('hex');
    } catch (err) {
        console.error('[license] rotating bind_proof derivation failed:', err && err.message ? err.message : err);
    }

    let initialChallenge = null;
    try {
        initialChallenge = await createChallenge(clientIp);
    } catch (err) {
        console.warn('[license] validate next-challenge create failed:', err && err.message ? err.message : err);
    }

    const sentinelBindToken = crypto.createHmac('sha256', licenseSecret)
        .update('attest|', 'utf8')
        .update(sessionToken, 'utf8')
        .update('|', 'utf8')
        .update(client_nonce, 'utf8')
        .digest();
    const sentinelBindTokenHex = sentinelBindToken.toString('hex');
    const sentinelBindTokenHash = crypto.createHash('sha256').update(sentinelBindToken).digest('hex');

    try {
        await pool.query(`
            UPDATE sessions SET
                heartbeat_nonce = $1,
                heartbeat_nonce_issued_at = $2,
                bind_proof_current = $3,
                bind_proof_epoch = $4,
                bind_proof_history = '{}'::TEXT[],
                challenge_sealed = $5,
                tpm_quote_digest = $6,
                challenge_id = $8,
                sentinel_bind_token_hash = $9,
                sentinel_bind_consumed   = false,
                sentinel_bind_issued_at  = $2
            WHERE license_key = $7
        `, [
            initialHbNonce,
            issuedAt,
            rotatingBindProofHex,
            0,
            !!tpmVerify,
            tpmDigestSeed,
            normalizedLicenseKey,
            initialChallenge ? initialChallenge.challenge_id : '',
            sentinelBindTokenHash,
        ]);
    } catch (err) {
        console.warn('[license] validate session-rotation update failed:', err && err.message ? err.message : err);
    }

    if (rotatingBindProofHex) {
        try {
            await pool.query(`
                INSERT INTO bind_proof_rotations (license_key, session_token, epoch, bind_proof, issued_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (session_token, epoch) DO UPDATE SET bind_proof = EXCLUDED.bind_proof, issued_at = EXCLUDED.issued_at
            `, [normalizedLicenseKey, sessionToken, 0, rotatingBindProofHex, issuedAt]);
        } catch (err) {
            console.warn('[license] validate bind_proof_rotations insert failed:', err && err.message ? err.message : err);
        }
    }

    await rateLimit.registerNonce(normalizedLicenseKey, sessionToken, 'hbnonce:' + initialHbNonce, HEARTBEAT_NONCE_MAX_AGE_SECONDS);

    const sigPayload = {
        status: 'valid',
        license_key: normalizedLicenseKey,
        hwid: effectiveHwid,
        plan: lookup.data.plan || 'standard',
        tier: lookup.data.tier || lookup.data.plan || 'standard',
        session_token: sessionToken,
        ttl,
        issued_at: issuedAt,
        server_nonce: serverNonce,
        client_nonce,
        key_seed: keySeed.toString('hex'),
        honeypot_export: honeypotExport,
        ttl_grace_factor: SESSION_TTL_GRACE_FACTOR,
        nonce_replay_ttl: NONCE_REPLAY_TTL_SECONDS,
        rotated_heartbeat_nonce: initialHbNonce,
        rotated_heartbeat_nonce_issued_at: issuedAt,
        rotated_heartbeat_nonce_max_age: HEARTBEAT_NONCE_MAX_AGE_SECONDS,
        rotated_bind_proof: rotatingBindProofHex,
        rotated_bind_proof_epoch: 0,
        challenge_required: CHALLENGE_REQUIRED,
        challenge_ttl: CHALLENGE_TTL_SECONDS,
        bind_response: bindDerivation.bind_response.toString('hex'),
        bind_token: sentinelBindTokenHex,
        auth_hmac_key_b64: authHmacKey.toString('base64'),
        session_key_fingerprint: sessionKeyFingerprint,
    };
    if (initialChallenge) {
        sigPayload.next_challenge_id = initialChallenge.challenge_id;
        sigPayload.next_challenge_nonce = initialChallenge.challenge_nonce;
        sigPayload.next_challenge_issued_at = initialChallenge.issued_at;
        sigPayload.next_challenge_ttl = initialChallenge.ttl;
        if (initialChallenge.signature) sigPayload.next_challenge_signature = initialChallenge.signature;
    }
    if (bindProofHex) sigPayload.bind_proof = bindProofHex;
    if (tpmVerify) {
        sigPayload.tpm_bound = true;
        sigPayload.tpm_ek_vendor = tpmVerify.ekVendor || '';
        sigPayload.tpm_ek_fingerprint = tpmVerify.ekCertFingerprint;
        sigPayload.tpm_pcr_digest = tpmVerify.pcrDigestHex;
    }
    if (tpmSealed) sigPayload.tpm_sealed_key = tpmSealed;
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);

    if (SESSION_RATCHET_ENABLED) {
        try {
            await sessionRatchet.bootstrapForSession(sessionToken, normalizedLicenseKey);
        } catch (err) {
            console.warn('[license] session_ratchet bootstrap failed:', err && err.message ? err.message : err);
        }
    }

    resolveActivationDiscordInfo(normalizedLicenseKey, body).then(info => {
        sendActivationWebhook({
            success: true,
            licenseKey: normalizedLicenseKey,
            hwid: effectiveHwid,
            clientIp,
            discord: info,
            desktopName: body.desktop_name || '',
            failReason: null,
            plan: lookup.data.plan || lookup.data.tier || 'standard',
            clientLat: body.client_lat != null ? body.client_lat : null,
            clientLon: body.client_lon != null ? body.client_lon : null,
        }).catch(() => {});
    }).catch(() => {});

    return envelopeResponse(200, sigPayload);
}


function maskToken(t) {
    if (typeof t !== 'string' || t.length === 0) return '<empty>';
    if (t.length <= 8) return t.slice(0, 2) + '***';
    return t.slice(0, 6) + '...' + t.slice(-4) + `(len=${t.length})`;
}

function dbgHb(stage, fields) {
    try {
        const parts = [];
        for (const [k, v] of Object.entries(fields || {})) {
            let rendered;
            if (v === null || v === undefined) { rendered = '<null>'; }
            else if (typeof v === 'string') { rendered = v.length > 80 ? `${v.slice(0, 76)}...` : v; }
            else if (typeof v === 'object') { rendered = JSON.stringify(v).slice(0, 200); }
            else { rendered = String(v); }
            parts.push(`${k}=${rendered}`);
        }
        console.log(`[heartbeat][${stage}] ${parts.join(' ')}`);
    } catch (logErr) {
        console.warn('[heartbeat][dbg] log_render_failed:', logErr && logErr.message);
    }
}

async function handleHeartbeat(body, clientIp) {
    const { license_key, session_token, hwid, code_hash } = body;
    dbgHb('enter', {
        license_key: maskToken(license_key),
        session_token: maskToken(session_token),
        hwid: maskToken(hwid),
        client_ip: clientIp,
        body_keys: Object.keys(body || {}).join(','),
        has_proof_token: typeof body.proof_token === 'string' && body.proof_token.length > 0,
        has_driver_proof: typeof body.driver_proof === 'string' && body.driver_proof.length > 0,
        has_code_hash: typeof code_hash === 'string' && code_hash.length > 0,
        code_hash_value: typeof code_hash === 'string' ? code_hash.slice(0, 32) : '<absent>',
        heartbeat_count: body.heartbeat_count,
        gate_bitmap: body.gate_bitmap,
        plugin_version: body.plugin_version,
        timestamp: body.timestamp,
    });

    if (!license_key || !session_token) {
        dbgHb('reject_missing_fields', { license_key: !!license_key, session_token: !!session_token });
        return collapseHeartbeatDeny('missing_fields', license_key, hwid, clientIp);
    }

    const perLicenseRl = await licenseRateLimit.check(license_key, {});
    if (!perLicenseRl.ok) {
        dbgHb('per_license_rate_limited', { scope: perLicenseRl.scope, retry_after: perLicenseRl.retry_after });
        auditLog.logValidationFailure(REASON_RATE_LIMITED, 'heartbeat_rate_limited:' + (perLicenseRl.scope || ''), license_key, hwid, clientIp, { retry_after: perLicenseRl.retry_after })
            .catch(() => {});
        return collapseHeartbeatDeny('rate_limited:' + (perLicenseRl.scope || ''), license_key, hwid, clientIp, { retry_after: perLicenseRl.retry_after });
    }

    const rl = await rateLimit.checkAndRegisterHeartbeat(license_key, session_token);
    if (!rl.ok) {
        dbgHb('rate_limited', { reason: rl.reason, retryAfter: rl.retryAfter });
        await replayCounter.recordRateLimitExceeded(license_key, session_token, { reason: rl.reason, retry_after: rl.retryAfter });
        return collapseHeartbeatDeny('rate_limited:' + (rl.reason || ''), license_key, hwid, clientIp, { retry_after: rl.retryAfter || 0 });
    }

    const replayVerdict = await replayCounter.checkAndAdvance(body, { required: true });
    if (!replayVerdict.ok) {
        dbgHb('replay_blocked', { reason: replayVerdict.reason });
        return collapseHeartbeatDeny('replay:' + (replayVerdict.reason || 'replay_blocked'), license_key, hwid, clientIp);
    }

    const banCheck = await checkBans(hwid, clientIp);
    dbgHb('ban_check', { banned: banCheck.banned, reason: banCheck.reason });
    if (banCheck.banned) {
        return collapseHeartbeatDeny('banned:' + (banCheck.reason || ''), license_key, hwid, clientIp);
    }

    if (body.timestamp && typeof body.timestamp === 'number') {
        const driftMs = Math.abs(Date.now() - (body.timestamp * 1000));
        if (driftMs > REQ_TIME_WINDOW_MS) {
            dbgHb('clock_drift', { drift_ms: driftMs, limit_ms: REQ_TIME_WINDOW_MS });
            await replayCounter.recordSignatureInvalid(license_key, session_token, { reason: 'heartbeat_clock_drift', drift_ms: driftMs, limit_ms: REQ_TIME_WINDOW_MS });
            return collapseHeartbeatDeny('clock_drift', license_key, hwid, clientIp);
        }
    }

    if (!isHexNonce(body.heartbeat_nonce || '', 16, 128)) {
        dbgHb('invalid_heartbeat_nonce', { len: (body.heartbeat_nonce || '').length });
        return collapseHeartbeatDeny('invalid_heartbeat_nonce', license_key, hwid, clientIp);
    }

    if (typeof body.echoed_server_nonce === 'string' && body.echoed_server_nonce.length > 0) {
        const echoed = body.echoed_server_nonce.trim().toLowerCase();
        if (!/^[0-9a-f]{16,128}$/.test(echoed)) {
            dbgHb('invalid_echoed_server_nonce', { len: echoed.length });
            return collapseHeartbeatDeny('invalid_echoed_server_nonce', license_key, hwid, clientIp);
        }
        const nonceCheck = await rateLimit.registerNonce(license_key, session_token, 'echo:' + echoed, NONCE_REPLAY_TTL_SECONDS);
        if (!nonceCheck.ok) {
            dbgHb('nonce_replay', { echoed: echoed.slice(0, 16) });
            return collapseHeartbeatDeny('nonce_replay', license_key, hwid, clientIp);
        }
    }

    const lookup = await lookupLicense(license_key);
    dbgHb('lookup_license', {
        valid: lookup.valid,
        reason: lookup.reason || '<none>',
        plan: lookup.data ? lookup.data.plan : '<no-data>',
    });
    if (!lookup.valid) {
        return collapseHeartbeatDeny('lookup:' + (lookup.reason || 'unknown'), license_key, hwid, clientIp);
    }

    const session = await getSession(license_key);
    dbgHb('session_lookup', {
        found: !!session,
        token_match: session ? session.session_token === session_token : false,
        session_token_db: session ? maskToken(session.session_token) : '<no-session>',
        session_token_body: maskToken(session_token),
        hwid_db: session ? session.hwid : '<no-session>',
        issued_at: session ? session.issued_at : null,
        ttl: session ? session.ttl : null,
        kill_flag: session ? session.kill_flag : null,
        heartbeat_count: session ? session.heartbeat_count : null,
        last_code_hash: session ? maskToken(session.last_code_hash || '') : '<no-session>',
        last_proof_token: session ? maskToken(session.last_proof_token || '') : '<no-session>',
        last_gate_bitmap: session ? session.last_gate_bitmap : null,
    });
    if (!session || session.session_token !== session_token) {
        return collapseHeartbeatDeny('session_mismatch', license_key, hwid, clientIp);
    }

    if (session.kill_flag) {
        dbgHb('kill_flag_set', { license_key: maskToken(license_key) });
        return collapseHeartbeatDeny('server_kill', license_key, hwid, clientIp);
    }

    try {
        const peerState = await peerCodeHash.getSessionPeerState(license_key);
        if (peerState) {
            const streak = Number(peerState.peer_attest_divergence_streak || 0);
            if (streak >= 5) {
                dbgHb('peer_attest_revoked', { streak });
                await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
                return collapseHeartbeatDeny('peer_code_hash_divergent', license_key, hwid, clientIp);
            }
        }
    } catch (err) {
        dbgHb('peer_attest_check_failed', { err: err && err.message ? err.message : 'unknown' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * SESSION_TTL_GRACE_FACTOR);
        if (now > expiresAt) {
            dbgHb('session_expired', { now, issued_at: session.issued_at, ttl: session.ttl, expiresAt });
            return collapseHeartbeatDeny('session_expired', license_key, hwid, clientIp);
        }
    }

    if (hwid && session.hwid && hwid !== session.hwid) {
        dbgHb('hwid_mismatch', { body_hwid: maskToken(hwid), session_hwid: maskToken(session.hwid) });
        await replayCounter.recordHwidMismatch(license_key, session_token, { body_hwid_prefix: (hwid || '').slice(0, 16), session_hwid_prefix: (session.hwid || '').slice(0, 16) });
        return collapseHeartbeatDeny('hwid_mismatch', license_key, hwid, clientIp);
    }

    const capsuleResult = await enforceStandaloneCapsuleProof('heartbeat', lookup.data, body, {
        license_key,
        hwid: hwid || session.hwid || '',
    });
    if (!capsuleResult.ok) {
        dbgHb('capsule_reject', { reason: capsuleResult.reason || 'invalid' });
        return collapseHeartbeatDeny('capsule:' + (capsuleResult.reason || 'invalid'), license_key, hwid, clientIp);
    }

    const sessionStoredHbNonce = typeof session.heartbeat_nonce === 'string' ? session.heartbeat_nonce.trim().toLowerCase() : '';
    const sessionStoredHbNonceIssuedAt = Number(session.heartbeat_nonce_issued_at || 0);
    if (sessionStoredHbNonce.length > 0) {
        const echoedRaw = typeof body.echoed_server_nonce === 'string' ? body.echoed_server_nonce.trim().toLowerCase() : '';
        if (echoedRaw.length === 0 || echoedRaw !== sessionStoredHbNonce) {
            dbgHb('echoed_server_nonce_mismatch', {
                expected_prefix: sessionStoredHbNonce.slice(0, 16),
                provided_prefix: echoedRaw.slice(0, 16),
            });
            return collapseHeartbeatDeny('nonce_stale', license_key, hwid, clientIp);
        }
        const ageS = now - sessionStoredHbNonceIssuedAt;
        if (sessionStoredHbNonceIssuedAt <= 0 || ageS > HEARTBEAT_NONCE_MAX_AGE_SECONDS || ageS < -HEARTBEAT_NONCE_MAX_AGE_SECONDS) {
            dbgHb('nonce_stale', { age: ageS, issued_at: sessionStoredHbNonceIssuedAt, limit: HEARTBEAT_NONCE_MAX_AGE_SECONDS });
            return collapseHeartbeatDeny('nonce_stale', license_key, hwid, clientIp);
        }
    }

    const echoedBindProofRaw = typeof body.echoed_bind_proof === 'string' ? body.echoed_bind_proof.trim().toLowerCase() : '';
    if (echoedBindProofRaw.length > 0) {
        if (!/^[0-9a-f]{32,128}$/.test(echoedBindProofRaw)) {
            return collapseHeartbeatDeny('bind_proof_format', license_key, hwid, clientIp);
        }
        const sessionCurrentBindProof = typeof session.bind_proof_current === 'string' ? session.bind_proof_current.trim().toLowerCase() : '';
        if (sessionCurrentBindProof.length > 0 && echoedBindProofRaw !== sessionCurrentBindProof) {
            dbgHb('bind_proof_mismatch', {
                provided_prefix: echoedBindProofRaw.slice(0, 16),
                expected_prefix: sessionCurrentBindProof.slice(0, 16),
            });
            return collapseHeartbeatDeny('bind_proof_mismatch', license_key, hwid, clientIp);
        }
        const history = Array.isArray(session.bind_proof_history) ? session.bind_proof_history : [];
        if (history.length > 0) {
            const reuseHit = history.some(entry => typeof entry === 'string' && entry.trim().toLowerCase() === echoedBindProofRaw);
            if (sessionCurrentBindProof !== echoedBindProofRaw && reuseHit) {
                dbgHb('bind_proof_reuse', { proof_prefix: echoedBindProofRaw.slice(0, 16) });
                return collapseHeartbeatDeny('bind_proof_reuse', license_key, hwid, clientIp);
            }
        }
    }


    const chHbResult = await enforceChallenge(body, clientIp, license_key);
    if (!chHbResult.ok) {
        return collapseHeartbeatDeny('challenge:' + (chHbResult.reason || 'unknown'), license_key, hwid, clientIp);
    }


    if (session.honeypot_export && Array.isArray(body.called_honeypot_names)) {
        for (const nm of body.called_honeypot_names) {
            if (typeof nm === 'string' && nm === session.honeypot_export) {
                await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
                await revokeLicenseAndSession(license_key, 'honeypot_export_called', body.plugin_version, hwid || session.hwid);
                await recordBan(hwid || session.hwid, clientIp, 'honeypot_export_called', body.plugin_version, {
                    route: 'license',
                    action: 'heartbeat',
                    license_key,
                    session_token,
                    reasons: ['honeypot_export_called'],
                    evidence: { honeypot_export: session.honeypot_export },
                });
                return collapseHeartbeatDeny('honeypot', license_key, hwid, clientIp);
            }
        }
    }

    const continuity = evaluateHeartbeatContinuity(session, body);
    dbgHb('continuity', {
        proof_token_to_store: maskToken(continuity.proof_token_to_store || ''),
        continuity_reasons: continuity.continuity_reasons,
        last_proof_token_db: maskToken(session.last_proof_token || ''),
        body_proof_token: maskToken(body.proof_token || ''),
        body_heartbeat_count: body.heartbeat_count,
        server_heartbeat_count: session.heartbeat_count || 0,
    });
    const violationReasons = [];
    const violationEvidence = {};

    const clientProofFirst8 = parseProofTokenFirst8(body.proof_token);
    dbgHb('arc_proof_check_pre', {
        proof_token_present: !!clientProofFirst8,
        proof_token_raw_len: typeof body.proof_token === 'string' ? body.proof_token.length : 0,
    });
    if (clientProofFirst8) {
        const expectedHbCount = Number.isFinite(Number(body.heartbeat_count))
            ? Math.max(0, Math.floor(Number(body.heartbeat_count)))
            : Math.max(0, Math.floor(Number(session.heartbeat_count || 0)) + 1);
        const proofMessage = buildProofTokenMessage(
            session.session_token,
            session.hwid || hwid || '',
            expectedHbCount,
            typeof code_hash === 'string' ? code_hash : ''
        );
        const proofOk = arcLicenseBind.verifyArcProofToken(lookup.data, proofMessage, clientProofFirst8);
        dbgHb('arc_proof_check_post', {
            proof_message: proofMessage,
            client_first8_hex: clientProofFirst8.toString('hex'),
            proof_ok: proofOk,
            expected_hb_count: expectedHbCount,
        });
        if (!proofOk) {
            violationReasons.push('arc_proof_token_mismatch');
            violationEvidence.proof_token_message = proofMessage;
            violationEvidence.proof_token_first8 = clientProofFirst8.toString('hex');
        }
    }

    const driverProofRaw = body.driver_proof;
    const driverProofPresent = typeof driverProofRaw === 'string'
        && driverProofRaw.length >= 16
        && /^[0-9a-fA-F]+$/.test(driverProofRaw);
    const issuedAtNum = Number(session.issued_at || 0);
    const sessionAgeSeconds = Number.isFinite(issuedAtNum) && issuedAtNum > 0 ? (now - issuedAtNum) : 0;
    const prevDriverProofAbsentStreak = Math.max(0, Math.floor(Number(session.driver_proof_absent_streak || 0)) || 0);
    let driverProofAbsentStreak = 0;
    if (sessionAgeSeconds > DRIVER_PROOF_REQUIRED_AFTER_SECONDS) {
        driverProofAbsentStreak = driverProofPresent ? 0 : (prevDriverProofAbsentStreak + 1);
    }
    const driverProofMissingConfirmed = !driverProofPresent
        && sessionAgeSeconds > DRIVER_PROOF_REQUIRED_AFTER_SECONDS
        && driverProofAbsentStreak >= DRIVER_PROOF_ABSENT_KILL_STREAK;
    dbgHb('driver_proof_check', {
        present: driverProofPresent,
        driver_proof_len: typeof driverProofRaw === 'string' ? driverProofRaw.length : 0,
        session_age_s: sessionAgeSeconds,
        threshold_s: DRIVER_PROOF_REQUIRED_AFTER_SECONDS,
        absent_streak: driverProofAbsentStreak,
        kill_streak: DRIVER_PROOF_ABSENT_KILL_STREAK,
        will_violate_if_missing: driverProofMissingConfirmed,
    });
    if (driverProofMissingConfirmed) {
        violationReasons.push('arc_driver_proof_missing');
        violationEvidence.session_age_seconds = sessionAgeSeconds;
        violationEvidence.driver_proof_len = typeof driverProofRaw === 'string' ? driverProofRaw.length : 0;
        violationEvidence.driver_proof_absent_streak = driverProofAbsentStreak;
    }

    const codeHashStored = session.last_code_hash || '';
    const codeHashIncoming = typeof code_hash === 'string' ? code_hash : '';
    const codeHashMatch = codeHashStored === codeHashIncoming;
    const codeHashEnforce = codeHashStored.length > 0 && codeHashIncoming.length > 0 && !codeHashMatch;
    dbgHb('code_hash_check', {
        stored: codeHashStored ? codeHashStored.slice(0, 32) : '<empty>',
        incoming: codeHashIncoming ? codeHashIncoming.slice(0, 32) : '<empty>',
        match: codeHashMatch,
        will_violate: codeHashEnforce,
    });
    if (typeof code_hash === 'string' && code_hash.length > 0) {
        if (codeHashEnforce) {
            violationReasons.push('code_hash_mismatch');
            violationEvidence.previous_code_hash = codeHashStored;
            violationEvidence.current_code_hash = codeHashIncoming;
        }
    }


    const prevGateBitmap = Number(session.last_gate_bitmap || 0);
    const rawGateBitmap = Number(body.gate_bitmap || 0);
    let curGateBitmap = Number.isFinite(rawGateBitmap) ? (rawGateBitmap | 0) : 0;
    let gateBitmapToStore = prevGateBitmap;
    if (Number.isFinite(rawGateBitmap) && curGateBitmap >= 0 && curGateBitmap < (1 << 24)) {
        if (prevGateBitmap !== 0 && (curGateBitmap & prevGateBitmap) !== prevGateBitmap) {
            violationReasons.push('gate_bitmap_regression');
            violationEvidence.previous_gate_bitmap = prevGateBitmap;
            violationEvidence.current_gate_bitmap = curGateBitmap;
        }
        gateBitmapToStore = Math.max(prevGateBitmap, curGateBitmap & ((1 << 24) - 1));
    } else if (body.gate_bitmap !== undefined) {
        violationReasons.push('gate_bitmap_invalid');
        violationEvidence.raw_gate_bitmap = body.gate_bitmap;
        curGateBitmap = 0;
    }

    const ipHistory = session.ip_history || [];
    let newIpHistory = ipHistory;
    if (clientIp && clientIp !== 'unknown') {
        const lastIp = ipHistory.length > 0 ? ipHistory[ipHistory.length - 1] : '';
        if (lastIp !== clientIp) {
            newIpHistory = [...ipHistory, clientIp].slice(-16);
        }
    }

    const hbTimes = session.heartbeat_times || [];
    const newHbTimes = [...hbTimes, now].slice(-20);

    if (violationReasons.length > 0) {
        const violationReason = sanitizeReason(`heartbeat_${violationReasons.join('_')}`);
        const effectiveHwid = hwid || session.hwid;
        dbgHb('killing_session', {
            reasons: violationReasons,
            combined_reason: violationReason,
            effective_hwid: maskToken(effectiveHwid),
            evidence_keys: Object.keys(violationEvidence),
            evidence: violationEvidence,
            continuity_reasons: continuity.continuity_reasons,
        });
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
        await revokeLicenseAndSession(license_key, violationReason, body.plugin_version, effectiveHwid);
        await recordBan(effectiveHwid, clientIp, violationReason, body.plugin_version, {
            route: 'license',
            action: 'heartbeat',
            license_key,
            session_token,
            reasons: violationReasons,
            evidence: {
                ...violationEvidence,
                continuity_reasons: continuity.continuity_reasons,
                heartbeat_count: body.heartbeat_count,
                server_heartbeat_count: session.heartbeat_count || 0,
            },
        });
        return collapseHeartbeatDeny('violation:' + violationReason, license_key, hwid, clientIp, { evidence_keys: Object.keys(violationEvidence) });
    }
    dbgHb('accept', {
        next_hb_count: (Number(session.heartbeat_count) || 0) + 1,
        next_code_hash: codeHashIncoming ? codeHashIncoming.slice(0, 32) : codeHashStored.slice(0, 32),
        proof_token_to_store: maskToken(continuity.proof_token_to_store || ''),
        new_gate_bitmap: gateBitmapToStore,
    });

    const proofTokenWrapped = encryptProofToken(session.session_uuid, continuity.proof_token_to_store || '');
    await pool.query(`
        UPDATE sessions SET
            last_heartbeat    = $1,
            heartbeat_count   = heartbeat_count + 1,
            last_proof_token  = $2,
            last_code_hash    = $3,
            ip_history        = $4,
            heartbeat_times   = $5,
            last_gate_bitmap  = $7,
            driver_proof_absent_streak = $8
        WHERE license_key = $6
    `, [
        now,
        proofTokenWrapped,
        (typeof code_hash === 'string' ? code_hash : session.last_code_hash || ''),
        newIpHistory,
        newHbTimes,
        license_key,
        gateBitmapToStore,
        driverProofAbsentStreak,
    ]);

    const anomalyEffectiveHwid = hwid || session.hwid || '';
    let anomalyResult = null;
    try {
        anomalyResult = await ingestHeartbeatAnomaly(license_key, anomalyEffectiveHwid, clientIp, body, session);
    } catch (err) {
        console.warn('[anomaly] ingestHeartbeatAnomaly failed:', err && err.message ? err.message : err);
    }
    if (anomalyResult && anomalyResult.applied && anomalyResult.applied.action === 'revoke') {
        return collapseHeartbeatDeny('anomaly:' + (anomalyResult.applied.reason || 'auto_revoke'), license_key, hwid, clientIp, { anomaly_score: anomalyResult.applied.score });
    }

    const heartbeatNonce = body.heartbeat_nonce || '';
    const serverNonce = generateServerNonce();
    const pageEpoch = (session.heartbeat_count || 0) + 1;
    const rotatedHbNonce = generateServerNonce();
    const rotatedHbNonceIssuedAt = now;

    let nextChallenge = null;
    try {
        nextChallenge = await createChallenge(clientIp);
    } catch (err) {
        console.warn('[license] heartbeat next-challenge create failed:', err && err.message ? err.message : err);
    }

    let rotatedBindProofHex = '';
    try {
        const tpmDigestForBind = typeof session.tpm_quote_digest === 'string' && session.tpm_quote_digest.length > 0
            ? session.tpm_quote_digest
            : (lookup.data && typeof lookup.data.tpm_pcr_digest === 'string' ? lookup.data.tpm_pcr_digest : '');
        const proof = arcLicenseBind.deriveRotatingBindProof(
            lookup.data,
            session_token,
            anomalyEffectiveHwid,
            BigInt(pageEpoch),
            rotatedHbNonce,
            tpmDigestForBind
        );
        rotatedBindProofHex = proof.toString('hex');
    } catch (err) {
        console.warn('[license] rotating bind_proof derivation failed:', err && err.message ? err.message : err);
    }

    const previousHistory = Array.isArray(session.bind_proof_history) ? session.bind_proof_history.slice() : [];
    const previousCurrent = typeof session.bind_proof_current === 'string' ? session.bind_proof_current : '';
    if (previousCurrent && !previousHistory.includes(previousCurrent)) {
        previousHistory.push(previousCurrent);
    }
    const trimmedHistory = previousHistory.slice(-BIND_PROOF_HISTORY_LIMIT);

    try {
        await pool.query(`
            UPDATE sessions SET
                heartbeat_nonce = $1,
                heartbeat_nonce_issued_at = $2,
                bind_proof_current = $3,
                bind_proof_epoch = $4,
                bind_proof_history = $5::TEXT[],
                challenge_id = $7
            WHERE license_key = $6
        `, [
            rotatedHbNonce,
            rotatedHbNonceIssuedAt,
            rotatedBindProofHex,
            pageEpoch,
            trimmedHistory,
            license_key,
            nextChallenge ? nextChallenge.challenge_id : (session.challenge_id || ''),
        ]);
    } catch (err) {
        console.warn('[license] heartbeat session rotation update failed:', err && err.message ? err.message : err);
    }

    if (rotatedBindProofHex) {
        try {
            await pool.query(`
                INSERT INTO bind_proof_rotations (license_key, session_token, epoch, bind_proof, issued_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (session_token, epoch) DO UPDATE SET bind_proof = EXCLUDED.bind_proof, issued_at = EXCLUDED.issued_at
            `, [license_key, session_token, pageEpoch, rotatedBindProofHex, now]);
        } catch (err) {
            console.warn('[license] bind_proof_rotations insert failed:', err && err.message ? err.message : err);
        }
    }

    await rateLimit.registerNonce(license_key, session_token, 'issued:' + serverNonce, NONCE_REPLAY_TTL_SECONDS);
    await rateLimit.registerNonce(license_key, session_token, 'hbnonce:' + rotatedHbNonce, HEARTBEAT_NONCE_MAX_AGE_SECONDS);

    const counter = (Number(session.heartbeat_count) || 0) + 1;
    const sigPayload = {
        status: 'valid',
        alive: true,
        license_key,
        session_token,
        hwid: anomalyEffectiveHwid,
        plan: lookup.data.plan || 'standard',
        ttl: SESSION_TTL_SECONDS,
        issued_at: now,
        heartbeat_nonce: heartbeatNonce,
        server_nonce: serverNonce,
        rotated_heartbeat_nonce: rotatedHbNonce,
        rotated_heartbeat_nonce_issued_at: rotatedHbNonceIssuedAt,
        rotated_heartbeat_nonce_max_age: HEARTBEAT_NONCE_MAX_AGE_SECONDS,
        rotated_bind_proof: rotatedBindProofHex,
        rotated_bind_proof_epoch: pageEpoch,
        page_epoch: pageEpoch,
        ratchet_counter: counter,
        ttl_grace_factor: SESSION_TTL_GRACE_FACTOR,
        nonce_replay_ttl: NONCE_REPLAY_TTL_SECONDS,
        auth_hmac_key_b64: sessionAuthHmacKeyBase64(session),
        session_key_fingerprint: session.session_key_fingerprint || '',
    };
    if (nextChallenge) {
        sigPayload.next_challenge_id = nextChallenge.challenge_id;
        sigPayload.next_challenge_nonce = nextChallenge.challenge_nonce;
        sigPayload.next_challenge_issued_at = nextChallenge.issued_at;
        sigPayload.next_challenge_ttl = nextChallenge.ttl;
        if (nextChallenge.signature) sigPayload.next_challenge_signature = nextChallenge.signature;
    }
    if (anomalyResult && anomalyResult.applied) {
        sigPayload.anomaly_score = anomalyResult.applied.score;
        sigPayload.anomaly_action = anomalyResult.applied.action;
    }
    try {
        const { rows: killRows } = await pool.query(
            'SELECT kill_at_epoch, reason FROM telemetry_kill_directives WHERE license_key = $1',
            [license_key]
        );
        if (killRows.length > 0 && Number.isFinite(Number(killRows[0].kill_at_epoch))) {
            sigPayload.kill_at_epoch = Number(killRows[0].kill_at_epoch);
            if (killRows[0].reason) sigPayload.kill_reason = String(killRows[0].reason).slice(0, 64);
        }
    } catch (_) { }
    try {
        const forceVio = await replayCounter.isForceViolation(license_key);
        if (forceVio) {
            sigPayload.force_violation = true;
            await replayCounter.clearForceViolation(license_key);
        }
    } catch (_) { }
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);

    try {
        if (body && (body.subaction === 'tool_exec' || body.tool_exec === true || typeof body.tool_call_id !== 'undefined')) {
            const toolBind = await bindToolCallToken(license_key, session_token, anomalyEffectiveHwid, body);
            if (toolBind && toolBind.ok) {
                sigPayload.tool_call_id = toolBind.tool_call_id;
                sigPayload.tool_call_token = toolBind.tool_call_token_hex;
                sigPayload.tool_call_issued_at = toolBind.issued_at;
            }
        }
    } catch (err) {
        console.warn('[license] tool_call_token bind failed:', err && err.message ? err.message : err);
    }

    auditLog.logV2({
        action: 'license.heartbeat',
        license_key,
        hwid: anomalyEffectiveHwid,
        source_ip: clientIp,
        decision: 'accept',
        reason_code: 'ok',
        extra: { heartbeat_count: counter, page_epoch: pageEpoch },
    }).catch(() => {});

    return envelopeResponse(200, sigPayload);
}

async function bindToolCallToken(licenseKey, sessionToken, hwid, body) {
    if (!licenseKey || !sessionToken) return { ok: false, reason: 'missing_args' };
    const rawCallId = (body && typeof body.tool_call_id !== 'undefined') ? body.tool_call_id : null;
    let toolCallId;
    if (rawCallId === null || rawCallId === undefined || rawCallId === '') {
        try {
            const { rows } = await pool.query(
                `UPDATE session_ratchet
                    SET last_tool_call_id = COALESCE(last_tool_call_id, 0) + 1,
                        updated_at = $2
                  WHERE license_key = $1
                RETURNING last_tool_call_id`,
                [licenseKey, Math.floor(Date.now() / 1000)]
            );
            if (rows.length === 0) {
                toolCallId = 1;
            } else {
                toolCallId = Number(rows[0].last_tool_call_id || 1);
            }
        } catch (err) {
            toolCallId = Math.floor(Date.now() / 1000);
        }
    } else {
        const n = Number(rawCallId);
        if (!Number.isFinite(n) || n < 0) return { ok: false, reason: 'invalid_call_id' };
        toolCallId = Math.floor(n);
    }
    const issuedAt = Math.floor(Date.now() / 1000);
    const masterSeed = process.env.ARC_MASTER_SECRET || process.env.SERVER_MASTER_KEY_B64 || 'aida-tool-bind-fallback';
    const prk = crypto.createHmac('sha256', Buffer.from(String(masterSeed), 'utf8'))
        .update(Buffer.from(String(sessionToken || ''), 'utf8'))
        .update(Buffer.from('|tool|', 'utf8'))
        .update(Buffer.from(String(hwid || ''), 'utf8'))
        .digest();
    const token = crypto.createHmac('sha256', prk)
        .update(Buffer.from('tool_call|', 'utf8'))
        .update(Buffer.from(String(toolCallId), 'utf8'))
        .update(Buffer.from('|', 'utf8'))
        .update(Buffer.from(String(issuedAt), 'utf8'))
        .digest();
    try {
        await pool.query(
            `UPDATE session_ratchet
                SET last_tool_call_id = $2,
                    last_tool_call_token = $3,
                    updated_at = $4
              WHERE license_key = $1`,
            [licenseKey, toolCallId, token, issuedAt]
        );
    } catch (err) {
        return { ok: false, reason: 'persist_failed' };
    }
    return {
        ok: true,
        tool_call_id: toolCallId,
        tool_call_token_hex: token.toString('hex'),
        issued_at: issuedAt,
    };
}


async function handleTpmAttest(body, clientIp) {
    const { license_key, hwid, session_token } = body || {};
    if (!license_key) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return collapseInvalid('tpm_attest_lookup:' + (lookup.reason || 'unknown'), license_key, hwid, clientIp);
    }
    const tpmBundle = body.tpm_attest || body;
    if (!tpmBundle || typeof tpmBundle !== 'object') {
        return { status: 400, body: { status: 'error', reason: 'missing_tpm_bundle' } };
    }
    const enriched = Object.assign({}, tpmBundle, {
        existingAnchorString: hwid || '',
    });
    const result = tpmQuote.verifyTpmQuote(enriched);
    if (!result.ok) {
        return collapseInvalid('tpm_quote_invalid:' + (result.reason || 'unknown'), lookup.data.key, hwid, clientIp);
    }
    if (lookup.data.tpm_ek_fingerprint && lookup.data.tpm_ek_fingerprint !== result.ekCertFingerprint) {
        return collapseInvalid('tpm_ek_mismatch', lookup.data.key, hwid, clientIp);
    }
    const sessionTokenForSeal = (session_token && typeof session_token === 'string') ? session_token : '';
    const sealed = sessionTokenForSeal ? buildTpmSealedPayload(lookup.data, result, sessionTokenForSeal) : null;
    await persistTpmAttestation(lookup.data.key, result, sealed);

    const responsePayload = {
        status: 'valid',
        license_key: lookup.data.key,
        ek_vendor: result.ekVendor || '',
        ek_fingerprint: result.ekCertFingerprint,
        pcr_digest: result.pcrDigestHex,
        hwid_component: result.hwidComponentHex,
    };
    if (sealed) responsePayload.tpm_sealed_key = sealed;
    return envelopeResponse(200, responsePayload);
}


async function handleKillSwitch(body, clientIp) {
    const { admin_key, target_license, target_hwid, target_global, reason } = body;

    const expectedKey = process.env.ADMIN_API_KEY || '';
    const adminOk = expectedKey
        && typeof admin_key === 'string'
        && admin_key.length > 0
        && constantTimeKeyMatch(admin_key, expectedKey);

    let botAuthorized = false;
    if (!adminOk) {
        const sigPresent = body && body.__bot_signature_present === true;
        if (sigPresent && body && body.__bot_verified === true) {
            botAuthorized = true;
        }
    }

    if (!adminOk && !botAuthorized) {
        return buildEauthResult();
    }

    const sanitized = sanitizeReason(reason || 'admin_kill');
    const createdBy = adminOk ? 'admin' : 'bot:' + (body && body.discord_id ? String(body.discord_id) : 'unknown');
    let killed = 0;
    let switchesAdded = 0;

    if (target_license) {
        const { rowCount } = await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
            [target_license]
        );
        killed += rowCount;
        const add = await killSwitchModule.addKill('license_key', target_license, sanitized, createdBy, null);
        if (add.ok) switchesAdded += 1;
    }

    if (target_hwid) {
        const { rowCount } = await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE hwid = $1',
            [target_hwid]
        );
        killed += rowCount;
        const hwidHashHex = killSwitchModule.hashHwid(target_hwid);
        const add = await killSwitchModule.addKill('hwid_hash', hwidHashHex, sanitized, createdBy, null);
        if (add.ok) switchesAdded += 1;
    }

    if (target_global === true || target_global === 'on' || target_global === 1) {
        const add = await killSwitchModule.addKill('global', null, sanitized, createdBy, null);
        if (add.ok) switchesAdded += 1;
    }

    if (target_global === false || target_global === 'off' || target_global === 0) {
        await killSwitchModule.removeKill('global', null);
    }

    const target_version = body.target_version;
    if (target_version && typeof target_version === 'string' && target_version.trim()) {
        const versionStr = target_version.trim().toLowerCase();
        const add = await killSwitchModule.addKill('plugin_version', versionStr, sanitized, createdBy, null);
        if (add.ok) switchesAdded += 1;
        const { rowCount } = await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE plugin_version = $1',
            [target_version.trim()]
        );
        killed += rowCount;
    }

    if (killed > 0 || switchesAdded > 0) {
        const fields = [
            { name: 'Action', value: 'Kill Switch Activated' },
            { name: 'Target License', value: target_license || 'N/A' },
            { name: 'Target HWID', value: target_hwid || 'N/A' },
            { name: 'Target Version', value: target_version || 'N/A' },
            { name: 'Global', value: target_global ? String(target_global) : 'N/A' },
            { name: 'Reason', value: sanitized },
            { name: 'Sessions Killed', value: String(killed) },
            { name: 'Switches Added', value: String(switchesAdded) },
            { name: 'Triggered By', value: createdBy + ' (' + clientIp + ')' },
        ];
        await sendDiscordWebhook('\uD83D\uDCA3 Kill Switch Activated', fields, 0xFF0000);
        await sendTelegramAlert('\uD83D\uDCA3 Kill Switch Activated', fields);
    }

    auditLog.logV2({
        action: 'license.kill_switch',
        license_key: target_license || '',
        hwid: target_hwid || '',
        source_ip: clientIp,
        decision: 'accept',
        reason_code: sanitized,
        extra: { switches_added: switchesAdded, killed, global: !!target_global, created_by: createdBy },
    }).catch(() => {});

    return { status: 200, body: { status: 'ok', killed, switches_added: switchesAdded } };
}


async function verifyReportBindProof(session, body) {
    if (!session || !session.auth_hmac_key) return { ok: false, reason: 'no_session_key' };
    const provided = body && body.bind_proof;
    if (typeof provided !== 'string' || provided.length < 32) return { ok: false, reason: 'missing_bind_proof' };
    const canonicalSubset = {};
    const keys = Object.keys(body).filter(k => k !== 'bind_proof' && k !== '__challenge_id_header' && k !== '__challenge_signature_header' && k !== '__raw_body').sort();
    for (const k of keys) canonicalSubset[k] = body[k];
    const canonical = JSON.stringify(canonicalSubset);
    const expected = crypto.createHmac('sha256', session.auth_hmac_key)
        .update('report|', 'utf8')
        .update(canonical, 'utf8')
        .digest();
    const expectedHex = expected.toString('hex');
    const providedNorm = provided.trim().toLowerCase();
    if (providedNorm.length !== expectedHex.length) return { ok: false, reason: 'bind_proof_length' };
    const a = Buffer.from(providedNorm, 'utf8');
    const b = Buffer.from(expectedHex, 'utf8');
    if (a.length !== b.length) return { ok: false, reason: 'bind_proof_length' };
    if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'bind_proof_mismatch' };
    return { ok: true };
}

async function handleReportViolation(body, clientIp) {
    const { hwid, reason, version, license_key, session_token, driver_proof } = body || {};

    const respondOk = () => envelopeResponse(200, { status: 'ok' });

    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 64) {
        return respondOk();
    }
    if (!license_key || !session_token) {
        return respondOk();
    }

    const sanitizedReason = sanitizeReason(reason);

    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        auditLog.logServerEvent('report_violation.reject', license_key, { reason: 'lookup_failed' }).catch(() => {});
        return respondOk();
    }
    const normalizedLicenseKey = lookup.data.key;

    const session = await getSession(normalizedLicenseKey);
    if (!session || session.session_token !== session_token) {
        auditLog.logServerEvent('report_violation.reject', normalizedLicenseKey, { reason: 'session_mismatch' }).catch(() => {});
        return respondOk();
    }
    if (session.hwid && session.hwid !== hwid) {
        auditLog.logServerEvent('report_violation.reject', normalizedLicenseKey, { reason: 'hwid_mismatch' }).catch(() => {});
        return respondOk();
    }

    const bindCheck = await verifyReportBindProof(session, body);
    if (!bindCheck.ok) {
        auditLog.logServerEvent('report_violation.reject', normalizedLicenseKey, { reason: 'bind_proof:' + (bindCheck.reason || 'unknown') }).catch(() => {});
        return respondOk();
    }

    const driverProofPresent = typeof driver_proof === 'string'
        && driver_proof.length >= 16
        && /^[0-9a-fA-F]+$/.test(driver_proof);
    const storedProofToken = typeof session.last_proof_token === 'string' ? session.last_proof_token : '';
    if (!driverProofPresent || !storedProofToken || driver_proof !== storedProofToken) {
        auditLog.logServerEvent('report_violation.reject', normalizedLicenseKey, { reason: 'driver_proof_missing_or_mismatch' }).catch(() => {});
        return respondOk();
    }

    await revokeLicenseAndSession(normalizedLicenseKey, sanitizedReason, version, hwid);
    await recordBan(hwid, clientIp, sanitizedReason, version, {
        route: 'license',
        action: 'report_violation',
        license_key: normalizedLicenseKey,
        session_token,
        reasons: [sanitizedReason],
        evidence: { client_reason: sanitizedReason, bind_proof_verified: true, driver_proof_verified: true },
    });

    return respondOk();
}


async function handleHoneypotTrip(body, clientIp) {
    const { event, trap, hwid, timestamp, cpuid, tsc, license_key, session_token, driver_proof } = body || {};

    const respondOk = () => envelopeResponse(200, { status: 'ok' });

    if (event !== 'honeypot_trip' || !trap || !hwid) {
        return respondOk();
    }

    if (license_key && session_token) {
        const lookup = await lookupLicense(license_key);
        if (!lookup.valid) {
            auditLog.logServerEvent('honeypot_trip.reject', license_key, { reason: 'lookup_failed' }).catch(() => {});
            return respondOk();
        }
        const session = await getSession(lookup.data.key);
        if (!session || session.session_token !== session_token) {
            auditLog.logServerEvent('honeypot_trip.reject', lookup.data.key, { reason: 'session_mismatch' }).catch(() => {});
            return respondOk();
        }
        const bindCheck = await verifyReportBindProof(session, body);
        if (!bindCheck.ok) {
            auditLog.logServerEvent('honeypot_trip.reject', lookup.data.key, { reason: 'bind_proof:' + (bindCheck.reason || 'unknown') }).catch(() => {});
            return respondOk();
        }
        const driverProofPresent = typeof driver_proof === 'string'
            && driver_proof.length >= 16
            && /^[0-9a-fA-F]+$/.test(driver_proof);
        const storedProofToken = typeof session.last_proof_token === 'string' ? session.last_proof_token : '';
        if (!driverProofPresent || !storedProofToken || driver_proof !== storedProofToken) {
            auditLog.logServerEvent('honeypot_trip.reject', lookup.data.key, { reason: 'driver_proof_missing_or_mismatch' }).catch(() => {});
            return respondOk();
        }
    } else {
        auditLog.logServerEvent('honeypot_trip.reject', license_key || '', { reason: 'unauthenticated' }).catch(() => {});
        return respondOk();
    }

    const sanitizedTrap = sanitizeReason(trap);


    const now = Math.floor(Date.now() / 1000);
    await pool.query(`
        INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, [
        hwid,
        clientIp,
        `honeypot:${sanitizedTrap}`,
        now,
        new Date().toISOString(),
        'honeypot',
    ]);


    await pool.query('UPDATE sessions SET kill_flag = true WHERE hwid = $1', [hwid]);


    const { rows: licenseRows } = await pool.query(
        'SELECT key FROM licenses WHERE hwid = $1 AND active = true',
        [hwid]
    );
    for (const row of licenseRows) {
        await revokeLicenseAndSession(row.key, `honeypot:${sanitizedTrap}`, 'honeypot', hwid);
    }


    await recordBan(hwid, clientIp, `honeypot:${sanitizedTrap}`, 'honeypot');


    const fields = [
        { name: '\uD83C\uDFAF Trap', value: sanitizedTrap },
        { name: '\uD83D\uDDA5\uFE0F HWID', value: `\`${hwid}\`` },
        { name: '\uD83C\uDF10 IP', value: `\`${clientIp}\`` },
        { name: '\u23F0 TSC', value: tsc ? String(tsc) : 'N/A' },
        { name: 'CPUID', value: cpuid ? String(cpuid) : 'N/A' },
    ];
    await sendDiscordWebhook('\uD83C\uDFAF HONEYPOT TRIGGERED — Cracker Detected', fields, 0xFF0000);
    await sendTelegramAlert('\uD83C\uDFAF HONEYPOT TRIGGERED — Cracker Detected', fields);


    return envelopeResponse(200, { status: 'ok' });
}


async function handleDriverProof(body, clientIp) {
    const { license_key, session_token, hwid, driver_proof, server_nonce, tsc_drift } = body;

    if (!license_key || !session_token || !driver_proof) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }

    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return { status: 200, body: { status: 'invalid', reason: 'session_mismatch' } };
    }

    if (session.kill_flag) {
        return { status: 200, body: { status: 'killed', alive: false } };
    }


    const proofNum = BigInt(`0x${driver_proof}`);
    if (proofNum === 0n) {
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
        await revokeLicenseAndSession(license_key, 'zero_driver_proof', body.plugin_version, hwid || session.hwid);
        await recordBan(hwid || session.hwid, clientIp, 'zero_driver_proof', body.plugin_version, {
            route: 'license',
            action: 'driver_proof',
            license_key,
            session_token,
            reasons: ['zero_driver_proof'],
            evidence: { driver_proof: String(driver_proof).slice(0, 64), proof_version: body.proof_version || 0 },
        });
        return { status: 200, body: { status: 'killed', alive: false, reason: 'zero_driver_proof' } };
    }


    if (typeof tsc_drift === 'number' && tsc_drift > 1000000) {
        await sendDiscordWebhook('Driver Proof Timing Drift', [
            { name: 'License', value: `\`${license_key}\`` },
            { name: 'HWID', value: `\`${hwid || session.hwid || 'unknown'}\`` },
            { name: 'IP', value: `\`${clientIp}\`` },
            { name: 'Action', value: 'driver_proof' },
            { name: 'Drift', value: String(tsc_drift) },
        ], 0xFFA500);
    }


    if (body.proof_version === 3) {
        const lic = await lookupLicense(license_key);
        if (!lic || !lic.witness_key_wrapped) {
            return { status: 200, body: { status: 'invalid', reason: 'kw_not_issued' } };
        }
        let kw;
        try { kw = kwWrap.unwrap(lic.witness_key_wrapped, 'kw/v1'); }
        catch (_) { return { status: 200, body: { status: 'invalid', reason: 'kw_unwrap_failed' } }; }

        const { token_hash, tsc, cr3, boot_nonce, hardware_id } = body;
        if (!token_hash || !boot_nonce || !hardware_id) {
            return { status: 400, body: { status: 'error', reason: 'proof_v3_missing_fields' } };
        }
        if (lic.hardware_id_sha256 && lic.hardware_id_sha256 !== hardware_id) {
            return { status: 200, body: { status: 'invalid', reason: 'hardware_mismatch' } };
        }
        const subkey = kwWrap.deriveKwSubkey(kw, 'driver_proof/v3');
        const canonical = `${token_hash}|${server_nonce || session.server_nonce}|${tsc || 0}|${cr3 || 0}|${boot_nonce}|${hardware_id}`;
        const expected = crypto.createHmac('sha256', subkey).update(canonical).digest('hex');
        const aBuf = Buffer.from(expected, 'utf8');
        const bBuf = Buffer.from(String(driver_proof), 'utf8');
        if (aBuf.length !== bBuf.length || !crypto.timingSafeEqual(aBuf, bBuf)) {
            await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
            await revokeLicenseAndSession(license_key, 'proof_v3_mismatch', body.plugin_version, hwid || session.hwid);
            await recordBan(hwid || session.hwid, clientIp, 'proof_v3_mismatch', body.plugin_version, {
                route: 'license',
                action: 'driver_proof',
                license_key,
                session_token,
                reasons: ['proof_v3_mismatch'],
                evidence: {
                    proof_version: 3,
                    token_hash: token_hash || '',
                    server_nonce: server_nonce || session.server_nonce || '',
                    tsc: tsc || 0,
                    cr3: cr3 || 0,
                    boot_nonce: boot_nonce || '',
                    hardware_id: hardware_id || '',
                },
            });
            return { status: 200, body: { status: 'killed', alive: false, reason: 'proof_v3_mismatch' } };
        }
    }


    await updateLastProofToken(license_key, driver_proof);

    const newNonce = generateServerNonce();
    return envelopeResponse(200, { status: 'valid', server_nonce: newNonce });
}


async function sendEauth(res, startedAt, debugReason) {
    await applyEauthBudget(startedAt);
    res.removeHeader && res.removeHeader('X-Powered-By');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', String(EAUTH_BODY_LENGTH));
    res.setHeader('Cache-Control', 'no-store');
    if (debugReason && process.env.AIDA_DEBUG_EAUTH_HEADER !== '0') {
        res.setHeader('X-Debug-Reason', String(debugReason).slice(0, 160));
    }
    return res.status(401).send(EAUTH_BODY_JSON);
}

router.post('/', async (req, res) => {
    const body = req.body;
    const dispatchStartedAt = Date.now();

    if (!body || typeof body !== 'object') {
        return sendEauth(res, dispatchStartedAt);
    }

    const headers = req.headers || {};
    body.__challenge_id_header = (typeof headers['x-challenge-id'] === 'string') ? headers['x-challenge-id'] : '';
    body.__challenge_signature_header = (typeof headers['x-challenge-signature'] === 'string') ? headers['x-challenge-signature'] : '';
    body.__raw_body = (typeof req.rawBody === 'string') ? req.rawBody : '';

    const clientIp = getClientIp(req);
    const action = body.action;

    if (action === 'kill') {
        const sig = req.headers['x-bot-signature'];
        if (typeof sig === 'string' && sig.length > 0) {
            const verify = botAuth.verifyBotRequest(req);
            body.__bot_signature_present = true;
            body.__bot_verified = !!(verify && verify.ok);
        }
    }

    if (SESSION_RATCHET_ENABLED && SESSION_RATCHET_AUTHENTICATED_ACTIONS.has(action)) {
        const middleware = sessionRatchet.enforce({ required: true });
        let nextCalled = false;
        const ratchetDone = new Promise((resolve) => {
            const nextFn = () => { nextCalled = true; resolve(); };
            try {
                const ret = middleware(req, res, nextFn);
                if (ret && typeof ret.then === 'function') {
                    ret.then(() => resolve(), () => resolve());
                }
            } catch (_) {
                resolve();
            }
            res.on('finish', () => resolve());
            res.on('close', () => resolve());
        });
        await ratchetDone;
        if (!nextCalled || res.headersSent || res.writableEnded) {
            return;
        }
    }

    try {
        let result;

        switch (action) {
            case 'ban_check':
                result = await withPgRetry(() => handleBanCheck(body, clientIp));
                break;
            case 'validate':
                result = await withPgRetry(() => handleValidate(body, clientIp));
                if (result && result.eauth === true) {
                    const failReason = (result.headers && result.headers['X-Debug-Reason']) || 'unknown';
                    resolveActivationDiscordInfo(body.license_key || '', body).then(info => {
                        sendActivationWebhook({
                            success: false,
                            licenseKey: body.license_key || '',
                            hwid: body.hwid || '',
                            clientIp,
                            discord: info,
                            desktopName: body.desktop_name || '',
                            failReason,
                            plan: null,
                            clientLat: body.client_lat != null ? body.client_lat : null,
                            clientLon: body.client_lon != null ? body.client_lon : null,
                        }).catch(() => {});
                    }).catch(() => {});
                }
                break;
            case 'heartbeat':
                result = await withPgRetry(() => handleHeartbeat(body, clientIp));
                break;
            case 'report_violation':
                result = await handleReportViolation(body, clientIp);
                break;
            case 'kill':
                result = await handleKillSwitch(body, clientIp);
                break;
            case 'driver_proof':
                result = await handleDriverProof(body, clientIp);
                break;
            case 'tpm_attest':
                result = await withPgRetry(() => handleTpmAttest(body, clientIp));
                break;
            default:
                return sendEauth(res, dispatchStartedAt);
        }

        if (result && result.eauth === true) {
            const dbgReason = result.headers && result.headers['X-Debug-Reason'];
            return sendEauth(res, dispatchStartedAt, dbgReason);
        }

        if (result && result.headers && typeof result.headers === 'object') {
            for (const [hk, hv] of Object.entries(result.headers)) {
                if (hk && hv !== undefined && hv !== null) res.setHeader(hk, String(hv));
            }
        }
        await applyTimingBudget(dispatchStartedAt);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error(`[license] Error processing ${action}:`, err);
        return sendEauth(res, dispatchStartedAt);
    }
});


router.post('/honeypot', async (req, res) => {
    const clientIp = getClientIp(req);
    try {
        const result = await handleHoneypotTrip(req.body || {}, clientIp);
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error('[sentinel] Honeypot handler error:', err);
        return res.status(200).json({ status: 'ok' });
    }
});

router.get('/challenge', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const challenge = await withPgRetry(() => createChallenge(clientIp));
        return res.status(200).json({ status: 'ok', ...challenge });
    } catch (err) {
        console.error('[challenge] Error:', err);
        return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
    }
});

function verifyAdminKey(submittedKey) {
    const expectedAdminKey = process.env.ADMIN_API_KEY || '';
    if (!expectedAdminKey || !submittedKey || typeof submittedKey !== 'string') {
        return false;
    }
    const hmacKey = Buffer.from('aida-keygen-cmp-v1');
    const submittedHmac = crypto.createHmac('sha256', hmacKey).update(submittedKey).digest();
    const expectedHmac  = crypto.createHmac('sha256', hmacKey).update(expectedAdminKey).digest();
    try {
        return crypto.timingSafeEqual(submittedHmac, expectedHmac);
    } catch (_) {
        return false;
    }
}

function parseDiscordId(value) {
    if (value === undefined || value === null || value === '') {
        return { ok: true, value: '' };
    }
    let str;
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) return { ok: false, reason: 'invalid_discord_id_number' };
        str = Math.trunc(value).toString();
    } else if (typeof value === 'string') {
        str = value.trim();
    } else if (typeof value === 'bigint') {
        str = value.toString();
    } else {
        return { ok: false, reason: 'invalid_discord_id_type' };
    }
    if (str === '') return { ok: true, value: '' };
    if (!/^\d{15,22}$/.test(str)) {
        return { ok: false, reason: 'invalid_discord_id_format' };
    }
    return { ok: true, value: str };
}

function parseExpiryInput(input) {
    if (input === undefined || input === null || input === '') {
        return { ok: true, date_str: '', epoch: 0 };
    }

    let epochSeconds = 0;
    if (typeof input === 'number') {
        if (!Number.isFinite(input) || input < 0) {
            return { ok: false, reason: 'invalid_expiry_number' };
        }
        epochSeconds = input >= 1e11 ? Math.floor(input / 1000) : Math.floor(input);
    } else if (typeof input === 'bigint') {
        const n = Number(input);
        if (!Number.isFinite(n) || n < 0) {
            return { ok: false, reason: 'invalid_expiry_number' };
        }
        epochSeconds = n >= 1e11 ? Math.floor(n / 1000) : Math.floor(n);
    } else if (typeof input === 'string') {
        const trimmed = input.trim();
        if (trimmed === '') return { ok: true, date_str: '', epoch: 0 };

        if (/^\d+$/.test(trimmed)) {
            const n = Number(trimmed);
            if (!Number.isFinite(n) || n < 0) {
                return { ok: false, reason: 'invalid_expiry_number' };
            }
            epochSeconds = n >= 1e11 ? Math.floor(n / 1000) : Math.floor(n);
        } else if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
            const d = new Date(trimmed + 'T23:59:59Z');
            if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== trimmed) {
                return { ok: false, reason: 'invalid_expiry_date' };
            }
            return { ok: true, date_str: trimmed, epoch: Math.floor(d.getTime() / 1000) };
        } else {
            const d = new Date(trimmed);
            if (isNaN(d.getTime())) {
                return { ok: false, reason: 'invalid_expiry_format' };
            }
            epochSeconds = Math.floor(d.getTime() / 1000);
        }
    } else {
        return { ok: false, reason: 'invalid_expiry_type' };
    }

    if (epochSeconds <= 0) {
        return { ok: false, reason: 'invalid_expiry_value' };
    }

    const date = new Date(epochSeconds * 1000);
    if (isNaN(date.getTime())) {
        return { ok: false, reason: 'invalid_expiry_value' };
    }
    const date_str = date.toISOString().slice(0, 10);
    return { ok: true, date_str, epoch: epochSeconds };
}

function epochToIsoOrNull(epoch) {
    if (!epoch || epoch <= 0) return null;
    const d = new Date(epoch * 1000);
    if (isNaN(d.getTime())) return null;
    return d.toISOString();
}

async function authorizeAdminOrBot(req, expectedAction) {
    const body = req.body || {};
    const adminKey = body.admin_key;
    if (typeof adminKey === 'string' && adminKey.length > 0 && verifyAdminKey(adminKey)) {
        return { ok: true, mode: 'admin' };
    }
    const botSig = req.headers['x-bot-signature'];
    if (typeof botSig === 'string' && botSig.length > 0) {
        const verify = botAuth.verifyBotRequest(req);
        if (!verify.ok) {
            return { ok: false, reason: verify.reason || 'bot_unauthorized' };
        }
        if (expectedAction && body.action && body.action !== expectedAction) {
            return { ok: false, reason: 'bot_action_mismatch' };
        }
        try {
            const nonce = typeof body.nonce === 'string' ? body.nonce : '';
            if (!nonce) return { ok: false, reason: 'bot_nonce_missing' };
            await pool.query(
                `INSERT INTO bot_command_log (nonce_hex, action, discord_id, received_at, payload)
                 VALUES ($1, $2, $3, $4, $5::jsonb)`,
                [nonce, expectedAction || body.action || 'unknown', String(body.discord_id || ''), Math.floor(Date.now() / 1000), JSON.stringify(body || {})]
            );
        } catch (err) {
            if (err && err.code === '23505') {
                return { ok: false, reason: 'bot_nonce_replay' };
            }
        }
        return { ok: true, mode: 'bot' };
    }
    return { ok: false, reason: 'unauthorized' };
}

async function generateLicenseSecrets() {
    let installSecretWrapped = null;
    let witnessKeyWrapped = null;
    let ioctlSeedWrapped = null;
    const installSecret = kwWrap.generateInstallSecret();
    installSecretWrapped = kwWrap.wrap(installSecret, 'install_secret/v1');
    const kw = kwWrap.generateWitnessKey();
    witnessKeyWrapped = kwWrap.wrap(kw, 'kw/v1');
    const ioctlSeed = crypto.randomBytes(16);
    ioctlSeedWrapped = kwWrap.wrap(ioctlSeed, 'ioctl_seed/v1');
    return { installSecretWrapped, witnessKeyWrapped, ioctlSeedWrapped };
}

async function createLicenseRow(opts) {
    const safeNote = (typeof opts.note === 'string' ? opts.note : '').slice(0, 512).replace(/[^\x20-\x7E]/g, '');
    const safeCreatedBy = (typeof opts.created_by === 'string' ? opts.created_by : 'payment_system').slice(0, 128).replace(/[^\x20-\x7E]/g, '');
    const safeDiscordUsername = cleanDiscordUsername(opts.discord_username || safeCreatedBy);
    const planValue = typeof opts.plan === 'string' && opts.plan.length > 0 ? opts.plan : 'pro';
    const tierValue = typeof opts.tier === 'string' && opts.tier.length > 0 ? opts.tier : (planValue || 'standard');
    const requestedNum = Number(opts.key_format);
    const formatRequested = requestedNum === keyFormat.FORMAT_MODERN ? keyFormat.FORMAT_MODERN : keyFormat.FORMAT_LEGACY;
    const key = formatRequested === keyFormat.FORMAT_MODERN ? keyFormat.generateModernKey() : keyFormat.generateLegacyKey();
    const now = Math.floor(Date.now() / 1000);

    const secrets = await generateLicenseSecrets();
    const discordLinkedAt = opts.discord_id ? now : 0;

    await pool.query(
        `INSERT INTO licenses (key, active, hwid, expires, expires_epoch, plan, tier, key_format, note, created_at, created_by, install_secret_wrapped, witness_key_wrapped, ioctl_seed_wrapped, discord_id, discord_username, discord_id_linked_at)
         VALUES ($1, true, '', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [
            key,
            opts.expires_date_str || '',
            opts.expires_epoch || 0,
            planValue,
            tierValue,
            formatRequested,
            safeNote,
            now,
            safeCreatedBy,
            secrets.installSecretWrapped,
            secrets.witnessKeyWrapped,
            secrets.ioctlSeedWrapped,
            opts.discord_id || '',
            safeDiscordUsername,
            discordLinkedAt,
        ]
    );
    return { key, created_at: now, plan: planValue, tier: tierValue, key_format: formatRequested };
}

router.post('/create', async (req, res) => {
    const body = req.body || {};
    const { plan, note, expires, expiry_time, discord_id, discord_username, created_by, key_format: keyFormatRequest } = body;

    const auth = await authorizeAdminOrBot(req, 'create');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }

    if (plan && plan !== 'pro') {
        return res.status(400).json({ status: 'error', reason: 'invalid_plan', valid_plans: ['pro'] });
    }

    const expiryInput = (expiry_time !== undefined && expiry_time !== null && expiry_time !== '')
        ? expiry_time
        : expires;
    const expiryParsed = parseExpiryInput(expiryInput);
    if (!expiryParsed.ok) {
        return res.status(400).json({ status: 'error', reason: expiryParsed.reason });
    }

    const discordParsed = parseDiscordId(discord_id);
    if (!discordParsed.ok) {
        return res.status(400).json({ status: 'error', reason: discordParsed.reason });
    }

    try {
        const created = await createLicenseRow({
            plan: plan || 'pro',
            tier: body.tier || plan || 'pro',
            note,
            created_by,
            discord_id: discordParsed.value,
            discord_username,
            expires_date_str: expiryParsed.date_str,
            expires_epoch: expiryParsed.epoch,
            key_format: keyFormatRequest,
        });
        return res.status(200).json({
            status: 'ok',
            key: created.key,
            plan: created.plan,
            tier: created.tier,
            key_format: created.key_format,
            expires: expiryParsed.date_str || null,
            expires_epoch: expiryParsed.epoch || null,
            expires_iso: epochToIsoOrNull(expiryParsed.epoch),
            discord_id: discordParsed.value || null,
            created_at: created.created_at,
        });
    } catch (err) {
        console.error('[license/create] failure:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/bulk_create', async (req, res) => {
    const body = req.body || {};
    const auth = await authorizeAdminOrBot(req, 'bulk_create');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }
    const count = Math.max(1, Math.min(50, Number(body.count) || 0));
    if (!count) {
        return res.status(400).json({ status: 'error', reason: 'invalid_count' });
    }
    if (body.plan && body.plan !== 'pro') {
        return res.status(400).json({ status: 'error', reason: 'invalid_plan' });
    }
    const expiryInput = (body.expiry_time !== undefined && body.expiry_time !== null && body.expiry_time !== '')
        ? body.expiry_time
        : body.expires;
    const expiryParsed = parseExpiryInput(expiryInput);
    if (!expiryParsed.ok) {
        return res.status(400).json({ status: 'error', reason: expiryParsed.reason });
    }
    const discordParsed = parseDiscordId(body.discord_id);
    if (!discordParsed.ok) {
        return res.status(400).json({ status: 'error', reason: discordParsed.reason });
    }
    const keys = [];
    try {
        for (let i = 0; i < count; i++) {
            const created = await createLicenseRow({
                plan: body.plan || 'pro',
                tier: body.tier || body.plan || 'pro',
                note: body.note,
                created_by: body.created_by,
                discord_id: discordParsed.value,
                discord_username: body.discord_username,
                expires_date_str: expiryParsed.date_str,
                expires_epoch: expiryParsed.epoch,
                key_format: body.key_format,
            });
            keys.push(created.key);
        }
    } catch (err) {
        console.error('[license/bulk_create] failure:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
    return res.status(200).json({
        status: 'ok',
        count: keys.length,
        keys,
        expires: expiryParsed.date_str || null,
        expires_epoch: expiryParsed.epoch || null,
        expires_iso: epochToIsoOrNull(expiryParsed.epoch),
        discord_id: discordParsed.value || null,
    });
});

router.post('/reset_hwid', async (req, res) => {
    const body = req.body || {};
    const auth = await authorizeAdminOrBot(req, 'reset_hwid');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }
    const key = typeof body.key === 'string' ? body.key.trim() : '';
    const normalized = keyFormat.normalizeForLookup(key);
    if (!normalized) {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }
    try {
        const { rowCount } = await pool.query(
            "UPDATE licenses SET hwid = '', hwid_factors = '{}'::jsonb, hwid_grace_used_at = 0 WHERE key = $1",
            [normalized]
        );
        if (rowCount === 0) {
            return res.status(404).json({ status: 'error', reason: 'license_not_found' });
        }
        await pool.query('DELETE FROM sessions WHERE license_key = $1', [normalized]);
        return res.status(200).json({ status: 'ok', key: normalized });
    } catch (err) {
        console.error('[license/reset_hwid] failure:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/transfer', async (req, res) => {
    const body = req.body || {};
    const auth = await authorizeAdminOrBot(req, 'transfer');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }
    const key = typeof body.key === 'string' ? body.key.trim() : '';
    const normalized = keyFormat.normalizeForLookup(key);
    if (!normalized) {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }
    const newHwid = typeof body.new_hwid === 'string' ? body.new_hwid.trim() : '';
    if (newHwid.length < 8 || newHwid.length > 256) {
        return res.status(400).json({ status: 'error', reason: 'invalid_new_hwid' });
    }
    try {
        const { rowCount } = await pool.query(
            "UPDATE licenses SET hwid = $1, hwid_factors = '{}'::jsonb, hwid_grace_used_at = 0 WHERE key = $2",
            [newHwid, normalized]
        );
        if (rowCount === 0) {
            return res.status(404).json({ status: 'error', reason: 'license_not_found' });
        }
        await pool.query('DELETE FROM sessions WHERE license_key = $1', [normalized]);
        return res.status(200).json({ status: 'ok', key: normalized, new_hwid: newHwid });
    } catch (err) {
        console.error('[license/transfer] failure:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/revoke', async (req, res) => {
    const body = req.body || {};
    const auth = await authorizeAdminOrBot(req, 'revoke');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }
    const key = typeof body.key === 'string' ? body.key.trim() : '';
    const normalized = keyFormat.normalizeForLookup(key);
    if (!normalized) {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }
    const reason = sanitizeReason(body.reason || 'admin_revoke');
    try {
        const now = Math.floor(Date.now() / 1000);
        const { rowCount } = await pool.query(
            `UPDATE licenses
             SET active = false, revoked_at = $1, revoked_at_iso = $2, revoked_reason = $3, revoked_version = 'admin'
             WHERE key = $4`,
            [now, new Date(now * 1000).toISOString(), reason, normalized]
        );
        if (rowCount === 0) {
            return res.status(404).json({ status: 'error', reason: 'license_not_found' });
        }
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [normalized]);
        return res.status(200).json({ status: 'ok', key: normalized, reason });
    } catch (err) {
        console.error('[license/revoke] failure:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/kill', async (req, res) => {
    const startedAt = Date.now();
    const body = req.body || {};
    const auth = await authorizeAdminOrBot(req, 'kill');
    if (!auth.ok) {
        await applyEauthBudget(startedAt);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', String(EAUTH_BODY_LENGTH));
        res.setHeader('Cache-Control', 'no-store');
        return res.status(401).send(EAUTH_BODY_JSON);
    }
    if (auth.mode === 'bot') {
        body.__bot_signature_present = true;
        body.__bot_verified = true;
    }
    const clientIp = getClientIp(req);
    const result = await handleKillSwitch(body, clientIp);
    if (result && result.eauth === true) {
        await applyEauthBudget(startedAt);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', String(EAUTH_BODY_LENGTH));
        res.setHeader('Cache-Control', 'no-store');
        return res.status(401).send(EAUTH_BODY_JSON);
    }
    return res.status(result.status).json(result.body);
});

router.post('/update', async (req, res) => {
    const body = req.body || {};
    const { key } = body;

    const auth = await authorizeAdminOrBot(req, 'update');
    if (!auth.ok) {
        return res.status(403).json({ status: 'error', reason: auth.reason || 'unauthorized' });
    }

    if (typeof key !== 'string') {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }
    const normalizedKey = keyFormat.normalizeForLookup(key);
    if (!normalizedKey) {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }

    const updates = [];
    const params = [];
    let placeholderIdx = 1;
    const pushUpdate = (column, value) => {
        updates.push(`${column} = $${placeholderIdx++}`);
        params.push(value);
    };

    const responseEcho = {};

    if (body.discord_id !== undefined) {
        const parsed = parseDiscordId(body.discord_id);
        if (!parsed.ok) {
            return res.status(400).json({ status: 'error', reason: parsed.reason });
        }
        pushUpdate('discord_id', parsed.value);
        pushUpdate('discord_id_linked_at', parsed.value ? Math.floor(Date.now() / 1000) : 0);
        responseEcho.discord_id = parsed.value || null;
    }

    if (body.discord_username !== undefined) {
        pushUpdate('discord_username', cleanDiscordUsername(body.discord_username));
        responseEcho.discord_username = cleanDiscordUsername(body.discord_username) || null;
    }

    const hasExpiryTime = body.expiry_time !== undefined && body.expiry_time !== null && body.expiry_time !== '';
    const hasExpires    = body.expires    !== undefined && body.expires    !== null && body.expires    !== '';
    const clearExpiry   = (body.expiry_time === null || body.expiry_time === '' || body.expires === null || body.expires === '');

    if (hasExpiryTime || hasExpires) {
        const parsed = parseExpiryInput(hasExpiryTime ? body.expiry_time : body.expires);
        if (!parsed.ok) {
            return res.status(400).json({ status: 'error', reason: parsed.reason });
        }
        pushUpdate('expires', parsed.date_str);
        pushUpdate('expires_epoch', parsed.epoch);
        responseEcho.expires = parsed.date_str || null;
        responseEcho.expires_epoch = parsed.epoch || null;
        responseEcho.expires_iso = epochToIsoOrNull(parsed.epoch);
    } else if (clearExpiry && (body.expiry_time !== undefined || body.expires !== undefined)) {
        pushUpdate('expires', '');
        pushUpdate('expires_epoch', 0);
        responseEcho.expires = null;
        responseEcho.expires_epoch = null;
        responseEcho.expires_iso = null;
    }

    if (body.note !== undefined) {
        if (typeof body.note !== 'string') {
            return res.status(400).json({ status: 'error', reason: 'invalid_note_type' });
        }
        const safeNote = body.note.slice(0, 512).replace(/[^\x20-\x7E]/g, '');
        pushUpdate('note', safeNote);
        responseEcho.note = safeNote;
    }

    if (body.plan !== undefined) {
        if (body.plan !== 'pro') {
            return res.status(400).json({ status: 'error', reason: 'invalid_plan', valid_plans: ['pro'] });
        }
        pushUpdate('plan', body.plan);
        responseEcho.plan = body.plan;
    }

    if (body.active !== undefined) {
        if (typeof body.active !== 'boolean') {
            return res.status(400).json({ status: 'error', reason: 'invalid_active_type' });
        }
        pushUpdate('active', body.active);
        responseEcho.active = body.active;
        if (body.active === false) {
            const nowTs = Math.floor(Date.now() / 1000);
            pushUpdate('revoked_at', nowTs);
            pushUpdate('revoked_at_iso', new Date(nowTs * 1000).toISOString());
            const reason = typeof body.revoked_reason === 'string'
                ? body.revoked_reason.slice(0, 256).replace(/[^\x20-\x7E]/g, '')
                : 'admin_update';
            pushUpdate('revoked_reason', reason);
            responseEcho.revoked_at = nowTs;
            responseEcho.revoked_reason = reason;
        } else {
            pushUpdate('revoked_at', null);
            pushUpdate('revoked_at_iso', null);
            pushUpdate('revoked_reason', null);
        }
    }

    if (updates.length === 0) {
        return res.status(400).json({ status: 'error', reason: 'no_updatable_fields' });
    }

    params.push(normalizedKey);
    const sql = `UPDATE licenses SET ${updates.join(', ')} WHERE key = $${placeholderIdx} RETURNING key, active, hwid, plan, note, expires, expires_epoch, discord_id, discord_username, discord_id_linked_at, created_at, created_by`;

    let row;
    try {
        const result = await pool.query(sql, params);
        if (!result || result.rowCount === 0) {
            return res.status(404).json({ status: 'error', reason: 'license_not_found' });
        }
        row = result.rows[0];
    } catch (err) {
        console.error('[license/update] DB update error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }

    return res.status(200).json({
        status: 'ok',
        key: row.key,
        active: row.active,
        plan: row.plan,
        note: row.note,
        expires: row.expires || null,
        expires_epoch: row.expires_epoch ? Number(row.expires_epoch) : null,
        expires_iso: epochToIsoOrNull(row.expires_epoch ? Number(row.expires_epoch) : 0),
        discord_id: row.discord_id || null,
        discord_username: row.discord_username || null,
        discord_id_linked_at: row.discord_id_linked_at ? Number(row.discord_id_linked_at) : null,
        hwid: row.hwid || null,
        created_at: row.created_at ? Number(row.created_at) : null,
        created_by: row.created_by || null,
        updated_fields: Object.keys(responseEcho),
    });
});

router.get('/lookup/:key', async (req, res) => {
    if (!verifyAdminKey(req.query.admin_key || req.headers['x-admin-key'])) {
        return res.status(403).json({ status: 'error', reason: 'unauthorized' });
    }
    const rawKey = req.params.key || '';
    const key = keyFormat.normalizeForLookup(rawKey);
    if (!key) {
        return res.status(400).json({ status: 'error', reason: 'invalid_key_format' });
    }
    try {
        const result = await pool.query(
            `SELECT key, active, hwid, plan, note, expires, expires_epoch, discord_id, discord_username, discord_id_linked_at, created_at, created_by, revoked_at, revoked_at_iso, revoked_reason
             FROM licenses WHERE key = $1`,
            [key]
        );
        if (!result || result.rowCount === 0) {
            return res.status(404).json({ status: 'error', reason: 'license_not_found' });
        }
        const row = result.rows[0];
        return res.status(200).json({
            status: 'ok',
            key: row.key,
            active: row.active,
            plan: row.plan,
            note: row.note || null,
            expires: row.expires || null,
            expires_epoch: row.expires_epoch ? Number(row.expires_epoch) : null,
            expires_iso: epochToIsoOrNull(row.expires_epoch ? Number(row.expires_epoch) : 0),
            discord_id: row.discord_id || null,
            discord_username: row.discord_username || null,
            discord_id_linked_at: row.discord_id_linked_at ? Number(row.discord_id_linked_at) : null,
            hwid: row.hwid || null,
            created_at: row.created_at ? Number(row.created_at) : null,
            created_by: row.created_by || null,
            revoked_at: row.revoked_at ? Number(row.revoked_at) : null,
            revoked_at_iso: row.revoked_at_iso || null,
            revoked_reason: row.revoked_reason || null,
        });
    } catch (err) {
        console.error('[license/lookup] DB error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.get('/by_discord/:discord_id', async (req, res) => {
    if (!verifyAdminKey(req.query.admin_key || req.headers['x-admin-key'])) {
        return res.status(403).json({ status: 'error', reason: 'unauthorized' });
    }
    const parsed = parseDiscordId(req.params.discord_id);
    if (!parsed.ok || !parsed.value) {
        return res.status(400).json({ status: 'error', reason: parsed.reason || 'invalid_discord_id_format' });
    }
    try {
        const result = await pool.query(
            `SELECT key, active, hwid, plan, expires, expires_epoch, discord_id, discord_username, discord_id_linked_at, created_at
             FROM licenses WHERE discord_id = $1 ORDER BY created_at DESC`,
            [parsed.value]
        );
        const licenses = (result.rows || []).map((row) => ({
            key: row.key,
            active: row.active,
            plan: row.plan,
            hwid: row.hwid || null,
            expires: row.expires || null,
            expires_epoch: row.expires_epoch ? Number(row.expires_epoch) : null,
            expires_iso: epochToIsoOrNull(row.expires_epoch ? Number(row.expires_epoch) : 0),
            discord_id: row.discord_id || null,
            discord_username: row.discord_username || null,
            discord_id_linked_at: row.discord_id_linked_at ? Number(row.discord_id_linked_at) : null,
            created_at: row.created_at ? Number(row.created_at) : null,
        }));
        return res.status(200).json({ status: 'ok', count: licenses.length, licenses });
    } catch (err) {
        console.error('[license/by_discord] DB error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router._internal = {
    evaluateHeartbeatContinuity,
    isNonEnforcingBanReason,
    normalizeBanCheckHwids,
    buildProofTokenMessage,
    isLicenseExpired,
    parseProofTokenFirst8,
    fnv1a64Hex,
    decryptSessionRow,
    encryptSessionToken,
    encryptProofToken,
    updateLastProofToken,
    rateLimit,
    handleTpmAttest,
    handleValidate,
    handleHeartbeat,
    isTpmRequiredForLicense,
    combineHardwareIdWithTpm,
    ingestHeartbeatAnomaly,
    applyAnomalyDecision,
    persistTpmAttestation,
    buildTpmSealedPayload,
    buildStandaloneCapsuleProofMessage,
    enforceStandaloneCapsuleProof,
    verifyStandaloneCapsuleProof,
    sendSlackAlert,
    storeSession,
};

module.exports = router;
module.exports.decryptSessionRow = decryptSessionRow;
module.exports.encryptSessionToken = encryptSessionToken;
module.exports.encryptProofToken = encryptProofToken;
module.exports.updateLastProofToken = updateLastProofToken;
module.exports.rateLimit = rateLimit;
