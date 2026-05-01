

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

const router = express.Router();


const SESSION_TTL_SECONDS = 3600;
const SESSION_TTL_GRACE_FACTOR = 1.1;
const CHALLENGE_TTL_SECONDS = 30;
const NONCE_REPLAY_TTL_SECONDS = parseInt(process.env.NONCE_REPLAY_TTL_SECONDS || '60', 10);
const CHALLENGE_REQUIRED = (process.env.CHALLENGE_REQUIRED || '1') !== '0';
const HEARTBEAT_NONCE_MAX_AGE_SECONDS = 60;
const BIND_PROOF_HISTORY_LIMIT = 32;
const ENTERPRISE_PLAN_TIER = 'enterprise';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';
const TELEGRAM_BOT_TOKEN  = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID    = process.env.TELEGRAM_CHAT_ID || '';
const SLACK_WEBHOOK_URL   = process.env.SLACK_WEBHOOK_URL || '';
const TPM_REQUIRED_TIERS  = new Set((process.env.TPM_REQUIRED_TIERS || '').split(',').map(s => s.trim()).filter(Boolean));
const ANOMALY_DISABLED    = (process.env.ANOMALY_DISABLED || '0') === '1';

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

async function consumeChallenge(challengeId, clientSignature, clientIp, licenseKey) {
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
        const expected = signChallenge(ch.challenge_id, ch.challenge_nonce, ch.issued_at, ch.ttl_seconds);
        if (typeof clientSignature !== 'string' || clientSignature.length !== expected.length) {
            return { ok: false, reason: 'challenge_signature_mismatch' };
        }
        const a = Buffer.from(clientSignature, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        if (!crypto.timingSafeEqual(a, b)) {
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
    const challengeId = body && body.challenge_id;
    const challengeSig = body && body.challenge_signature;
    if (!challengeId) {
        if (CHALLENGE_REQUIRED) return { ok: false, reason: 'missing_challenge' };
        return { ok: true, skipped: true };
    }
    return consumeChallenge(challengeId, challengeSig, clientIp, licenseKey);
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
        return { valid: false, reason: 'missing_key' };
    }
    if (!/^[A-Za-z0-9\-]{10,40}$/.test(licenseKey)) {
        return { valid: false, reason: 'invalid_format' };
    }

    const { rows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [licenseKey]
    );
    if (rows.length === 0) {
        return { valid: false, reason: 'not_found' };
    }

    const data = rows[0];

    if (!data.active) {
        return { valid: false, reason: 'revoked', data };
    }
    if (data.expires && data.expires !== '' && data.expires < todayStr()) {
        return { valid: false, reason: 'expired', data };
    }

    await ensureLicenseSecrets(licenseKey, data);

    return { valid: true, data };
}

async function verifyOrBindHwid(licenseKey, hwid, existingHwid) {
    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 256) {
        return { ok: false, reason: 'invalid_hwid' };
    }

    if (!existingHwid || existingHwid === '') {

        await pool.query(
            'UPDATE licenses SET hwid = $1 WHERE key = $2 AND hwid = $3',
            [hwid, licenseKey, '']
        );
        return { ok: true, reason: 'bound' };
    }

    if (existingHwid !== hwid) {
        return { ok: false, reason: 'hwid_mismatch' };
    }

    return { ok: true, reason: 'match' };
}

async function storeSession(licenseKey, sessionData) {
    const sessionUuid = columnCrypt.generateRowUuid();
    const sessionTokenWrapped = encryptSessionToken(sessionUuid, sessionData.session_token);
    const authHmacKey = crypto.randomBytes(32);
    await pool.query(`
        INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat, kill_flag, heartbeat_count, last_proof_token, last_code_hash, ip_history, heartbeat_times, honeypot_export, challenge_id, last_chain_tag, session_uuid, column_crypt_version, auth_hmac_key, anomaly_score)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, 0, '', '', ARRAY[$7]::TEXT[], ARRAY[]::BIGINT[], $10, $11, '', $12, 1, $13, 0)
        ON CONFLICT (license_key) DO UPDATE SET
            session_token        = EXCLUDED.session_token,
            server_nonce         = EXCLUDED.server_nonce,
            issued_at            = EXCLUDED.issued_at,
            ttl                  = EXCLUDED.ttl,
            hwid                 = EXCLUDED.hwid,
            ip                   = EXCLUDED.ip,
            plugin_version       = EXCLUDED.plugin_version,
            last_heartbeat       = EXCLUDED.last_heartbeat,
            kill_flag            = false,
            heartbeat_count      = 0,
            last_proof_token     = '',
            last_code_hash       = '',
            ip_history           = ARRAY[EXCLUDED.ip]::TEXT[],
            heartbeat_times      = ARRAY[]::BIGINT[],
            honeypot_export      = EXCLUDED.honeypot_export,
            challenge_id         = EXCLUDED.challenge_id,
            last_chain_tag       = '',
            session_uuid         = EXCLUDED.session_uuid,
            column_crypt_version = 1,
            auth_hmac_key        = EXCLUDED.auth_hmac_key,
            anomaly_score        = 0
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
    ]);
    return { authHmacKey };
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
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return { status: 200, body: { status: 'invalid', reason: 'clock_drift' } };
        }
    }


    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return { status: 200, body: { status: 'banned', reason: banCheck.reason } };
    }


    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return { status: 200, body: { status: 'invalid', reason: lookup.reason } };
    }


    const chResult = await enforceChallenge(body, clientIp, license_key);
    if (!chResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: chResult.reason } };
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
            return { status: 200, body: { status: 'invalid', reason: 'tpm_quote_invalid', detail: result.reason } };
        }
        tpmVerify = result;
        effectiveHwid = combineHardwareIdWithTpm(hwid, result.hwidComponentHex);
        if (lookup.data.tpm_ek_fingerprint && lookup.data.tpm_ek_fingerprint !== result.ekCertFingerprint) {
            return { status: 200, body: { status: 'invalid', reason: 'tpm_ek_mismatch' } };
        }
    } else if (isTpmRequiredForLicense(lookup.data)) {
        return { status: 200, body: { status: 'invalid', reason: 'tpm_attest_required' } };
    }


    const hwidResult = await verifyOrBindHwid(license_key, effectiveHwid, lookup.data.hwid || '');
    if (!hwidResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: hwidResult.reason } };
    }


    const sessionToken = generateSessionToken();
    const serverNonce = generateServerNonce();
    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = SESSION_TTL_SECONDS;
    const honeypotExport = pickHoneypotExport();

    const sessionStore = await storeSession(license_key, {
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
    });

    await rateLimit.registerNonce(license_key, sessionToken, 'issued:' + serverNonce, NONCE_REPLAY_TTL_SECONDS);

    let tpmSealed = null;
    if (tpmVerify) {
        tpmSealed = buildTpmSealedPayload(lookup.data, tpmVerify, sessionToken);
        await persistTpmAttestation(license_key, tpmVerify, tpmSealed);
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
                challenge_id = $8
            WHERE license_key = $7
        `, [
            initialHbNonce,
            issuedAt,
            rotatingBindProofHex,
            0,
            !!tpmVerify,
            tpmDigestSeed,
            license_key,
            initialChallenge ? initialChallenge.challenge_id : '',
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
            `, [license_key, sessionToken, 0, rotatingBindProofHex, issuedAt]);
        } catch (err) {
            console.warn('[license] validate bind_proof_rotations insert failed:', err && err.message ? err.message : err);
        }
    }

    await rateLimit.registerNonce(license_key, sessionToken, 'hbnonce:' + initialHbNonce, HEARTBEAT_NONCE_MAX_AGE_SECONDS);

    const sigPayload = {
        status: 'valid',
        license_key,
        hwid: effectiveHwid,
        plan: lookup.data.plan || 'standard',
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
    };
    if (initialChallenge) {
        sigPayload.next_challenge_id = initialChallenge.challenge_id;
        sigPayload.next_challenge_nonce = initialChallenge.challenge_nonce;
        sigPayload.next_challenge_issued_at = initialChallenge.issued_at;
        sigPayload.next_challenge_ttl = initialChallenge.ttl;
        if (initialChallenge.signature) sigPayload.next_challenge_signature = initialChallenge.signature;
    }
    if (bindProofHex) sigPayload.bind_proof = bindProofHex;
    if (sessionStore && sessionStore.authHmacKey) {
        sigPayload.auth_hmac_key_b64 = sessionStore.authHmacKey.toString('base64');
    }
    if (tpmVerify) {
        sigPayload.tpm_bound = true;
        sigPayload.tpm_ek_vendor = tpmVerify.ekVendor || '';
        sigPayload.tpm_ek_fingerprint = tpmVerify.ekCertFingerprint;
        sigPayload.tpm_pcr_digest = tpmVerify.pcrDigestHex;
    }
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);
    const kidInfo = getActiveKidInfo();
    sigPayload.kid = kidInfo.active_kid;
    const { signature, next_signature, next_kid } = dualSignPayload(sigPayload);

    const responseBody = { ...sigPayload, signature };
    if (next_signature) responseBody.next_signature = next_signature;
    if (next_kid) responseBody.next_kid = next_kid;
    if (tpmSealed) responseBody.tpm_sealed_key = tpmSealed;

    return {
        status: 200,
        body: responseBody,
    };
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
        has_driver_proof_message: typeof body.driver_proof_message === 'string' && body.driver_proof_message.length > 0,
        has_code_hash: typeof code_hash === 'string' && code_hash.length > 0,
        code_hash_value: typeof code_hash === 'string' ? code_hash.slice(0, 32) : '<absent>',
        heartbeat_count: body.heartbeat_count,
        gate_bitmap: body.gate_bitmap,
        plugin_version: body.plugin_version,
        timestamp: body.timestamp,
    });

    if (!license_key || !session_token) {
        dbgHb('reject_missing_fields', { license_key: !!license_key, session_token: !!session_token });
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }

    const rl = await rateLimit.checkAndRegisterHeartbeat(license_key, session_token);
    if (!rl.ok) {
        dbgHb('rate_limited', { reason: rl.reason, retryAfter: rl.retryAfter });
        return {
            status: 429,
            body: { status: 'error', reason: rl.reason || 'rate_limited', retry_after: rl.retryAfter || 0 },
            headers: { 'Retry-After': String(rl.retryAfter || 1) },
        };
    }

    const banCheck = await checkBans(hwid, clientIp);
    dbgHb('ban_check', { banned: banCheck.banned, reason: banCheck.reason });
    if (banCheck.banned) {
        return { status: 200, body: { status: 'banned', reason: banCheck.reason } };
    }

    if (body.timestamp && typeof body.timestamp === 'number') {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            dbgHb('clock_drift', { drift, limit: 300 });
            return { status: 200, body: { status: 'invalid', reason: 'clock_drift' } };
        }
    }

    if (!isHexNonce(body.heartbeat_nonce || '', 16, 128)) {
        dbgHb('invalid_heartbeat_nonce', { len: (body.heartbeat_nonce || '').length });
        return { status: 200, body: { status: 'invalid', reason: 'invalid_heartbeat_nonce' } };
    }

    if (typeof body.echoed_server_nonce === 'string' && body.echoed_server_nonce.length > 0) {
        const echoed = body.echoed_server_nonce.trim().toLowerCase();
        if (!/^[0-9a-f]{16,128}$/.test(echoed)) {
            dbgHb('invalid_echoed_server_nonce', { len: echoed.length });
            return { status: 401, body: { status: 'error', reason: 'invalid_echoed_server_nonce' } };
        }
        const nonceCheck = await rateLimit.registerNonce(license_key, session_token, 'echo:' + echoed, NONCE_REPLAY_TTL_SECONDS);
        if (!nonceCheck.ok) {
            dbgHb('nonce_replay', { echoed: echoed.slice(0, 16) });
            return { status: 401, body: { status: 'error', reason: 'nonce_replay' } };
        }
    }

    const lookup = await lookupLicense(license_key);
    dbgHb('lookup_license', {
        valid: lookup.valid,
        reason: lookup.reason || '<none>',
        plan: lookup.data ? lookup.data.plan : '<no-data>',
    });
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: lookup.reason === 'revoked' ? 'revoked' : 'invalid', reason: lookup.reason },
        };
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
        return { status: 200, body: { status: 'invalid', reason: 'session_mismatch' } };
    }

    if (session.kill_flag) {
        dbgHb('kill_flag_set', { license_key: maskToken(license_key) });
        return { status: 200, body: { status: 'killed', alive: false, reason: 'server_kill' } };
    }

    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * SESSION_TTL_GRACE_FACTOR);
        if (now > expiresAt) {
            dbgHb('session_expired', { now, issued_at: session.issued_at, ttl: session.ttl, expiresAt });
            return { status: 200, body: { status: 'invalid', reason: 'session_expired' } };
        }
    }

    if (hwid && session.hwid && hwid !== session.hwid) {
        dbgHb('hwid_mismatch', { body_hwid: maskToken(hwid), session_hwid: maskToken(session.hwid) });
        return { status: 200, body: { status: 'invalid', reason: 'hwid_mismatch' } };
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
            return { status: 401, body: { status: 'invalid', reason: 'nonce_stale' } };
        }
        const ageS = now - sessionStoredHbNonceIssuedAt;
        if (sessionStoredHbNonceIssuedAt <= 0 || ageS > HEARTBEAT_NONCE_MAX_AGE_SECONDS || ageS < -HEARTBEAT_NONCE_MAX_AGE_SECONDS) {
            dbgHb('nonce_stale', { age: ageS, issued_at: sessionStoredHbNonceIssuedAt, limit: HEARTBEAT_NONCE_MAX_AGE_SECONDS });
            return { status: 401, body: { status: 'invalid', reason: 'nonce_stale' } };
        }
    }

    const echoedBindProofRaw = typeof body.echoed_bind_proof === 'string' ? body.echoed_bind_proof.trim().toLowerCase() : '';
    if (echoedBindProofRaw.length > 0) {
        if (!/^[0-9a-f]{32,128}$/.test(echoedBindProofRaw)) {
            return { status: 401, body: { status: 'invalid', reason: 'bind_proof_format' } };
        }
        const sessionCurrentBindProof = typeof session.bind_proof_current === 'string' ? session.bind_proof_current.trim().toLowerCase() : '';
        if (sessionCurrentBindProof.length > 0 && echoedBindProofRaw !== sessionCurrentBindProof) {
            dbgHb('bind_proof_mismatch', {
                provided_prefix: echoedBindProofRaw.slice(0, 16),
                expected_prefix: sessionCurrentBindProof.slice(0, 16),
            });
            return { status: 401, body: { status: 'invalid', reason: 'bind_proof_mismatch' } };
        }
        const history = Array.isArray(session.bind_proof_history) ? session.bind_proof_history : [];
        if (history.length > 0) {
            const reuseHit = history.some(entry => typeof entry === 'string' && entry.trim().toLowerCase() === echoedBindProofRaw);
            if (sessionCurrentBindProof !== echoedBindProofRaw && reuseHit) {
                dbgHb('bind_proof_reuse', { proof_prefix: echoedBindProofRaw.slice(0, 16) });
                return { status: 401, body: { status: 'invalid', reason: 'bind_proof_reuse' } };
            }
        }
    }


    const chHbResult = await enforceChallenge(body, clientIp, license_key);
    if (!chHbResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: chHbResult.reason } };
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
                return { status: 200, body: { status: 'killed', alive: false, reason: 'honeypot' } };
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
    const driverProofMessageRaw = body.driver_proof_message;
    const driverProofPresent = typeof driverProofRaw === 'string' && driverProofRaw.length > 0
        && typeof driverProofMessageRaw === 'string' && driverProofMessageRaw.length > 0;
    const issuedAtNum = Number(session.issued_at || 0);
    const sessionAgeSeconds = Number.isFinite(issuedAtNum) && issuedAtNum > 0 ? (now - issuedAtNum) : 0;
    dbgHb('driver_proof_check', {
        present: driverProofPresent,
        driver_proof_len: typeof driverProofRaw === 'string' ? driverProofRaw.length : 0,
        message_len: typeof driverProofMessageRaw === 'string' ? driverProofMessageRaw.length : 0,
        session_age_s: sessionAgeSeconds,
        threshold_s: 1800,
        will_violate_if_missing: !driverProofPresent && sessionAgeSeconds > 1800,
    });
    if (driverProofPresent) {
        const driverProofResult = arcLicenseBind.verifyDriverProof(lookup.data, driverProofMessageRaw, driverProofRaw);
        dbgHb('driver_proof_verify', { result: driverProofResult });
        if (driverProofResult === false) {
            violationReasons.push('arc_driver_proof_invalid');
            violationEvidence.driver_proof_message = driverProofMessageRaw;
            violationEvidence.driver_proof_signature = driverProofRaw;
        }
    } else {
        if (sessionAgeSeconds > 1800) {
            violationReasons.push('arc_driver_proof_missing');
            violationEvidence.session_age_seconds = sessionAgeSeconds;
        }
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
        return { status: 200, body: { status: 'killed', alive: false, reason: violationReason } };
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
            last_gate_bitmap  = $7
        WHERE license_key = $6
    `, [
        now,
        proofTokenWrapped,
        (typeof code_hash === 'string' ? code_hash : session.last_code_hash || ''),
        newIpHistory,
        newHbTimes,
        license_key,
        gateBitmapToStore,
    ]);

    const anomalyEffectiveHwid = hwid || session.hwid || '';
    let anomalyResult = null;
    try {
        anomalyResult = await ingestHeartbeatAnomaly(license_key, anomalyEffectiveHwid, clientIp, body, session);
    } catch (err) {
        console.warn('[anomaly] ingestHeartbeatAnomaly failed:', err && err.message ? err.message : err);
    }
    if (anomalyResult && anomalyResult.applied && anomalyResult.applied.action === 'revoke') {
        return {
            status: 200,
            body: {
                status: 'killed',
                alive: false,
                reason: anomalyResult.applied.reason || 'anomaly_auto_revoke',
                anomaly_score: anomalyResult.applied.score,
            },
        };
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

    const sigPayload = {
        status: 'valid',
        alive: true,
        license_key,
        hwid: anomalyEffectiveHwid,
        plan: lookup.data.plan || 'standard',
        ttl: SESSION_TTL_SECONDS,
        heartbeat_nonce: heartbeatNonce,
        server_nonce: serverNonce,
        rotated_heartbeat_nonce: rotatedHbNonce,
        rotated_heartbeat_nonce_issued_at: rotatedHbNonceIssuedAt,
        rotated_heartbeat_nonce_max_age: HEARTBEAT_NONCE_MAX_AGE_SECONDS,
        rotated_bind_proof: rotatedBindProofHex,
        rotated_bind_proof_epoch: pageEpoch,
        page_epoch: pageEpoch,
        ttl_grace_factor: SESSION_TTL_GRACE_FACTOR,
        nonce_replay_ttl: NONCE_REPLAY_TTL_SECONDS,
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
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);
    const kidInfo = getActiveKidInfo();
    sigPayload.kid = kidInfo.active_kid;
    const { signature, next_signature, next_kid } = dualSignPayload(sigPayload);

    const responseBody = { ...sigPayload, signature };
    if (next_signature) responseBody.next_signature = next_signature;
    if (next_kid) responseBody.next_kid = next_kid;

    return {
        status: 200,
        body: responseBody,
    };
}


async function handleTpmAttest(body, clientIp) {
    const { license_key, hwid, session_token } = body || {};
    if (!license_key) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }
    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return { status: 200, body: { status: 'invalid', reason: lookup.reason } };
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
        return { status: 200, body: { status: 'invalid', reason: 'tpm_quote_invalid', detail: result.reason } };
    }
    if (lookup.data.tpm_ek_fingerprint && lookup.data.tpm_ek_fingerprint !== result.ekCertFingerprint) {
        return { status: 200, body: { status: 'invalid', reason: 'tpm_ek_mismatch' } };
    }
    const sessionTokenForSeal = (session_token && typeof session_token === 'string') ? session_token : '';
    const sealed = sessionTokenForSeal ? buildTpmSealedPayload(lookup.data, result, sessionTokenForSeal) : null;
    await persistTpmAttestation(license_key, result, sealed);

    const responsePayload = {
        status: 'valid',
        license_key,
        ek_vendor: result.ekVendor || '',
        ek_fingerprint: result.ekCertFingerprint,
        pcr_digest: result.pcrDigestHex,
        hwid_component: result.hwidComponentHex,
    };
    if (sealed) responsePayload.tpm_sealed_key = sealed;
    const kidInfo = getActiveKidInfo();
    responsePayload.kid = kidInfo.active_kid;
    const { signature, next_signature, next_kid } = dualSignPayload({
        status: responsePayload.status,
        license_key,
        ek_fingerprint: responsePayload.ek_fingerprint,
        pcr_digest: responsePayload.pcr_digest,
        hwid_component: responsePayload.hwid_component,
        kid: kidInfo.active_kid,
    });
    responsePayload.signature = signature;
    if (next_signature) responsePayload.next_signature = next_signature;
    if (next_kid) responsePayload.next_kid = next_kid;
    return { status: 200, body: responsePayload };
}


async function handleKillSwitch(body, clientIp) {
    const { admin_key, target_license, target_hwid, reason } = body;

    const expectedKey = process.env.ADMIN_API_KEY || '';
    if (!expectedKey || !admin_key || typeof admin_key !== 'string') {
        return { status: 403, body: { status: 'error', reason: 'unauthorized' } };
    }
    if (!crypto.timingSafeEqual(Buffer.from(admin_key), Buffer.from(expectedKey))) {
        return { status: 403, body: { status: 'error', reason: 'unauthorized' } };
    }

    const sanitized = sanitizeReason(reason || 'admin_kill');
    let killed = 0;

    if (target_license) {
        const { rowCount } = await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
            [target_license]
        );
        killed += rowCount;
    }

    if (target_hwid) {
        const { rowCount } = await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE hwid = $1',
            [target_hwid]
        );
        killed += rowCount;
    }

    if (killed > 0) {
        const fields = [
            { name: 'Action', value: 'Kill Switch Activated' },
            { name: 'Target License', value: target_license || 'N/A' },
            { name: 'Target HWID', value: target_hwid || 'N/A' },
            { name: 'Reason', value: sanitized },
            { name: 'Sessions Killed', value: String(killed) },
            { name: 'Triggered By', value: clientIp },
        ];
        await sendDiscordWebhook('\uD83D\uDCA3 Kill Switch Activated', fields, 0xFF0000);
        await sendTelegramAlert('\uD83D\uDCA3 Kill Switch Activated', fields);
    }

    return { status: 200, body: { status: 'ok', killed } };
}


async function handleReportViolation(body, clientIp) {
    const { hwid, reason, version, license_key, session_token } = body;


    if (!hwid || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 64) {
        return { status: 200, body: { status: 'ok' } };
    }
    if (!license_key || !session_token) {
        return { status: 200, body: { status: 'ok' } };
    }

    const sanitizedReason = sanitizeReason(reason);

    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return { status: 200, body: { status: 'ok' } };
    }

    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return { status: 200, body: { status: 'ok' } };
    }
    if (session.hwid && session.hwid !== hwid) {
        return { status: 200, body: { status: 'ok' } };
    }

    await revokeLicenseAndSession(license_key, sanitizedReason, version, hwid);
    await recordBan(hwid, clientIp, sanitizedReason, version, {
        route: 'license',
        action: 'report_violation',
        license_key,
        session_token,
        reasons: [sanitizedReason],
        evidence: { client_reason: sanitizedReason },
    });

    return { status: 200, body: { status: 'ok' } };
}


async function handleHoneypotTrip(body, clientIp) {
    const { event, trap, hwid, timestamp, cpuid, tsc } = body;

    if (event !== 'honeypot_trip' || !trap || !hwid) {
        return { status: 200, body: { status: 'ok' } };
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


    return { status: 200, body: { status: 'ok' } };
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
    return {
        status: 200,
        body: { status: 'valid', server_nonce: newNonce },
    };
}


router.post('/', async (req, res) => {
    const body = req.body;
    if (!body || typeof body !== 'object') {
        return res.status(400).json({ status: 'error', reason: 'invalid_body' });
    }

    const clientIp = getClientIp(req);
    const action = body.action;

    try {
        let result;

        switch (action) {
            case 'ban_check':
                result = await withPgRetry(() => handleBanCheck(body, clientIp));
                break;
            case 'validate':
                result = await withPgRetry(() => handleValidate(body, clientIp));
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
                return res.status(400).json({ status: 'error', reason: 'unknown_action' });
        }

        if (result && result.headers && typeof result.headers === 'object') {
            for (const [hk, hv] of Object.entries(result.headers)) {
                if (hk && hv !== undefined && hv !== null) res.setHeader(hk, String(hv));
            }
        }
        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error(`[license] Error processing ${action}:`, err);
        const statusCode = isTransientError(err) ? 503 : 500;
        return res.status(statusCode).json({ status: 'error', reason: 'internal_error' });
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

router.post('/create', async (req, res) => {
    const expectedAdminKey = process.env.ADMIN_API_KEY || '';
    const { admin_key, plan, note, expires, created_by } = req.body || {};

    if (!expectedAdminKey || !admin_key || typeof admin_key !== 'string') {
        return res.status(403).json({ status: 'error', reason: 'unauthorized' });
    }

    const hmacKey = Buffer.from('aida-keygen-cmp-v1');
    const submittedHmac = crypto.createHmac('sha256', hmacKey).update(admin_key).digest();
    const expectedHmac  = crypto.createHmac('sha256', hmacKey).update(expectedAdminKey).digest();
    if (!crypto.timingSafeEqual(submittedHmac, expectedHmac)) {
        return res.status(403).json({ status: 'error', reason: 'unauthorized' });
    }

    if (plan !== 'pro') {
        return res.status(400).json({ status: 'error', reason: 'invalid_plan', valid_plans: ['pro'] });
    }

    if (expires !== undefined && expires !== null && expires !== '') {
        if (typeof expires !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_expires_format' });
        }
        const d = new Date(expires + 'T00:00:00Z');
        if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== expires) {
            return res.status(400).json({ status: 'error', reason: 'invalid_expires_date' });
        }
    }

    const safeNote = (typeof note === 'string' ? note : '').slice(0, 512).replace(/[^\x20-\x7E]/g, '');
    const safeCreatedBy = (typeof created_by === 'string' ? created_by : 'payment_system').slice(0, 128).replace(/[^\x20-\x7E]/g, '');

    const segments = [
        crypto.randomBytes(2).toString('hex').toUpperCase(),
        crypto.randomBytes(2).toString('hex').toUpperCase(),
        crypto.randomBytes(2).toString('hex').toUpperCase(),
        crypto.randomBytes(2).toString('hex').toUpperCase(),
    ];
    const key = 'AIDA-' + segments.join('-');
    const now = Math.floor(Date.now() / 1000);

    let installSecretWrapped = null;
    let witnessKeyWrapped = null;
    try {
        const installSecret = kwWrap.generateInstallSecret();
        installSecretWrapped = kwWrap.wrap(installSecret, 'install_secret/v1');
    } catch (err) {
        console.error('[license/create] install_secret wrap failed:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'install_secret_wrap_failed' });
    }
    try {
        const kw = kwWrap.generateWitnessKey();
        witnessKeyWrapped = kwWrap.wrap(kw, 'kw/v1');
    } catch (err) {
        console.error('[license/create] witness_key wrap failed:', err && err.message ? err.message : err);
        return res.status(500).json({ status: 'error', reason: 'witness_key_wrap_failed' });
    }

    try {
        await pool.query(
            `INSERT INTO licenses (key, active, hwid, expires, plan, note, created_at, created_by, install_secret_wrapped, witness_key_wrapped)
             VALUES ($1, true, '', $2, $3, $4, $5, $6, $7, $8)`,
            [key, expires || '', plan, safeNote, now, safeCreatedBy, installSecretWrapped, witnessKeyWrapped]
        );
    } catch (err) {
        console.error('[license/create] DB insert error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }

    return res.status(200).json({ status: 'ok', key, plan, expires: expires || null });
});

router._internal = {
    evaluateHeartbeatContinuity,
    isNonEnforcingBanReason,
    normalizeBanCheckHwids,
    buildProofTokenMessage,
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
    sendSlackAlert,
};

module.exports = router;
module.exports.decryptSessionRow = decryptSessionRow;
module.exports.encryptSessionToken = encryptSessionToken;
module.exports.encryptProofToken = encryptProofToken;
module.exports.updateLastProofToken = updateLastProofToken;
module.exports.rateLimit = rateLimit;
