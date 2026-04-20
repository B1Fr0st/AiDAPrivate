

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload, dualSignPayload } = require('../crypto/signing');
const { deriveKeySeed } = require('../crypto/arc-encrypt');
const kwWrap = require('../crypto/kw_wrap');

const router = express.Router();


const SESSION_TTL_SECONDS = 3600;
const SESSION_TTL_GRACE_FACTOR = 1.1;
const CHALLENGE_TTL_SECONDS = 10;
const CHALLENGE_REQUIRED = (process.env.CHALLENGE_REQUIRED || '0') === '1';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';
const TELEGRAM_BOT_TOKEN  = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID    = process.env.TELEGRAM_CHAT_ID || '';

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


function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateServerNonce() {
    return crypto.randomBytes(16).toString('hex');
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

        const url = `https:
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
    await pool.query(`
        INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat, kill_flag, heartbeat_count, last_proof_token, last_code_hash, anomaly_score, ip_history, heartbeat_times, honeypot_export, challenge_id, step_up_pending, last_chain_tag)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, 0, '', '', 0, ARRAY[$7]::TEXT[], ARRAY[]::BIGINT[], $10, $11, false, '')
        ON CONFLICT (license_key) DO UPDATE SET
            session_token     = EXCLUDED.session_token,
            server_nonce      = EXCLUDED.server_nonce,
            issued_at         = EXCLUDED.issued_at,
            ttl               = EXCLUDED.ttl,
            hwid              = EXCLUDED.hwid,
            ip                = EXCLUDED.ip,
            plugin_version    = EXCLUDED.plugin_version,
            last_heartbeat    = EXCLUDED.last_heartbeat,
            kill_flag         = false,
            heartbeat_count   = 0,
            last_proof_token  = '',
            last_code_hash    = '',
            anomaly_score     = 0,
            ip_history        = ARRAY[EXCLUDED.ip]::TEXT[],
            heartbeat_times   = ARRAY[]::BIGINT[],
            honeypot_export   = EXCLUDED.honeypot_export,
            challenge_id      = EXCLUDED.challenge_id,
            step_up_pending   = false,
            last_chain_tag    = ''
    `, [
        licenseKey,
        sessionData.session_token,
        sessionData.server_nonce,
        sessionData.issued_at,
        sessionData.ttl,
        sessionData.hwid,
        sessionData.ip,
        sessionData.plugin_version,
        sessionData.last_heartbeat,
        sessionData.honeypot_export || '',
        sessionData.challenge_id || '',
    ]);
}

async function getSession(licenseKey) {
    const { rows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    return rows.length > 0 ? rows[0] : null;
}

async function checkBans(hwid, clientIp) {
    if (hwid) {
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND value = $2',
            ['hwid', hwid]
        );
        if (rows.length > 0) {
            return { banned: true, reason: 'hwid_banned', data: rows[0] };
        }
    }
    if (clientIp && clientIp !== 'unknown') {
        const normalized = normalizeIp(clientIp);
        const { rows } = await pool.query(
            'SELECT * FROM bans WHERE ban_type = $1 AND (value = $2 OR value = $3)',
            ['ip', clientIp, normalized]
        );
        if (rows.length > 0) {
            return { banned: true, reason: 'ip_banned', data: rows[0] };
        }
    }
    return { banned: false };
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

async function recordBan(hwid, clientIp, reason, version) {
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
        { name: '\uD83D\uDDA5\uFE0F HWID', value: `\`${hwid || 'unknown'}\`` },
        { name: '\uD83C\uDF10 IP', value: `\`${clientIp || 'unknown'}\`` },
        { name: '\uD83D\uDCE6 Version', value: version || 'unknown' },
    ];
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


    const hwidResult = await verifyOrBindHwid(license_key, hwid, lookup.data.hwid || '');
    if (!hwidResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: hwidResult.reason } };
    }


    const sessionToken = generateSessionToken();
    const serverNonce = generateServerNonce();
    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = SESSION_TTL_SECONDS;
    const honeypotExport = pickHoneypotExport();

    await storeSession(license_key, {
        session_token: sessionToken,
        server_nonce: serverNonce,
        issued_at: issuedAt,
        ttl,
        hwid,
        ip: clientIp,
        plugin_version: plugin_version || 'unknown',
        last_heartbeat: issuedAt,
        honeypot_export: honeypotExport,
        challenge_id: (body && body.challenge_id) || '',
    });


    const keySeed = deriveKeySeed(sessionToken, hwid, issuedAt);

    const sigPayload = {
        status: 'valid',
        license_key,
        hwid,
        plan: lookup.data.plan || 'standard',
        session_token: sessionToken,
        ttl,
        issued_at: issuedAt,
        server_nonce: serverNonce,
        client_nonce,
        key_seed: keySeed.toString('hex'),
        honeypot_export: honeypotExport,
        ttl_grace_factor: SESSION_TTL_GRACE_FACTOR,
    };
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);
    const { signature, next_signature } = dualSignPayload(sigPayload);

    const responseBody = { ...sigPayload, signature };
    if (next_signature) responseBody.next_signature = next_signature;

    return {
        status: 200,
        body: responseBody,
    };
}


async function handleHeartbeat(body, clientIp) {
    const { license_key, session_token, hwid, proof_token, heartbeat_count, code_hash } = body;

    if (!license_key || !session_token) {
        return { status: 400, body: { status: 'error', reason: 'missing_fields' } };
    }

    const banCheck = await checkBans(hwid, clientIp);
    if (banCheck.banned) {
        return { status: 200, body: { status: 'banned', reason: banCheck.reason } };
    }

    if (body.timestamp && typeof body.timestamp === 'number') {
        const drift = Math.abs(Math.floor(Date.now() / 1000) - body.timestamp);
        if (drift > 300) {
            return { status: 200, body: { status: 'invalid', reason: 'clock_drift' } };
        }
    }

    if (!isHexNonce(body.heartbeat_nonce || '', 16, 128)) {
        return { status: 200, body: { status: 'invalid', reason: 'invalid_heartbeat_nonce' } };
    }

    const lookup = await lookupLicense(license_key);
    if (!lookup.valid) {
        return {
            status: 200,
            body: { status: lookup.reason === 'revoked' ? 'revoked' : 'invalid', reason: lookup.reason },
        };
    }

    const session = await getSession(license_key);
    if (!session || session.session_token !== session_token) {
        return { status: 200, body: { status: 'invalid', reason: 'session_mismatch' } };
    }

    if (session.kill_flag) {
        return { status: 200, body: { status: 'killed', alive: false, reason: 'server_kill' } };
    }

    const now = Math.floor(Date.now() / 1000);
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * SESSION_TTL_GRACE_FACTOR);
        if (now > expiresAt) {
            return { status: 200, body: { status: 'invalid', reason: 'session_expired' } };
        }
    }

    if (hwid && session.hwid && hwid !== session.hwid) {
        return { status: 200, body: { status: 'invalid', reason: 'hwid_mismatch' } };
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
                await recordBan(hwid || session.hwid, clientIp, 'honeypot_export_called', body.plugin_version);
                return { status: 200, body: { status: 'killed', alive: false, reason: 'honeypot' } };
            }
        }
    }

    let anomalyDelta = 0;
    const anomalyReasons = [];

    if (typeof proof_token === 'string' && proof_token.length > 0) {
        if (session.last_proof_token && proof_token === session.last_proof_token) {
            anomalyDelta += 30;
            anomalyReasons.push('replayed_proof_token');
        }
    } else {
        anomalyDelta += 15;
        anomalyReasons.push('missing_proof_token');
    }

    if (typeof heartbeat_count === 'number' && heartbeat_count >= 0) {
        const expectedCount = (session.heartbeat_count || 0) + 1;
        if (heartbeat_count < expectedCount) {
            anomalyDelta += 25;
            anomalyReasons.push('heartbeat_count_regression');
        } else if (heartbeat_count > expectedCount + 5) {
            anomalyDelta += 10;
            anomalyReasons.push('heartbeat_count_skip');
        }
    }

    if (typeof code_hash === 'string' && code_hash.length > 0) {
        if (session.last_code_hash && session.last_code_hash !== '' && code_hash !== session.last_code_hash) {
            anomalyDelta += 50;
            anomalyReasons.push('code_hash_mismatch');
        }
    }


    const prevGateBitmap = Number(session.last_gate_bitmap || 0);
    const curGateBitmap  = Number(body.gate_bitmap || 0) | 0;
    if (curGateBitmap >= 0 && curGateBitmap < (1 << 24)) {
        if (prevGateBitmap !== 0 && (curGateBitmap & prevGateBitmap) !== prevGateBitmap) {
            anomalyDelta += 35;
            anomalyReasons.push('gate_bitmap_regression');
        }
    } else if (body.gate_bitmap !== undefined) {
        anomalyDelta += 10;
        anomalyReasons.push('gate_bitmap_invalid');
    }

    const ipHistory = session.ip_history || [];
    let newIpHistory = ipHistory;
    if (clientIp && clientIp !== 'unknown') {
        const lastIp = ipHistory.length > 0 ? ipHistory[ipHistory.length - 1] : '';
        if (lastIp !== clientIp) {
            newIpHistory = [...ipHistory, clientIp].slice(-16);
            const uniqueIps = new Set(newIpHistory);
            if (uniqueIps.size > 5) {
                anomalyDelta += 20;
                anomalyReasons.push('excessive_ip_changes');
            } else if (uniqueIps.size > 2) {
                anomalyDelta += 5;
            }
        }
    }

    const hbTimes = session.heartbeat_times || [];
    const newHbTimes = [...hbTimes, now].slice(-20);
    if (newHbTimes.length >= 3) {
        const intervals = [];
        for (let i = 1; i < newHbTimes.length; i++) {
            intervals.push(newHbTimes[i] - newHbTimes[i - 1]);
        }
        const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((a, b) => a + (b - avg) ** 2, 0) / intervals.length;
        if (variance < 0.5 && intervals.length >= 5) {
            anomalyDelta += 15;
            anomalyReasons.push('bot_like_regularity');
        }
        const minInterval = Math.min(...intervals);
        if (minInterval < 5) {
            anomalyDelta += 20;
            anomalyReasons.push('heartbeat_flood');
        }
    }

    const stepUpOk = !session.step_up_pending
        || (typeof body.step_up_response === 'string' && body.step_up_response.length >= 32);
    if (session.step_up_pending && !stepUpOk) {
        anomalyDelta += 10;
        anomalyReasons.push('step_up_missing');
    }

    const priorScore = Number(session.anomaly_score || 0);
    let nextScore = priorScore + anomalyDelta;
    if (anomalyDelta === 0) {
        nextScore = Math.max(0, priorScore - 2);
    }
    nextScore = Math.max(0, Math.min(100, nextScore));

    let stepUpPending = session.step_up_pending || false;
    let stepUpNonce = '';
    let degradationFactor = 0.0;
    let tierLabel = 'clean';
    if (nextScore >= 100) tierLabel = 'nuclear';
    else if (nextScore >= 80) {
        tierLabel = 'degrade';
        degradationFactor = Math.min(1.0, (nextScore - 80) / 20.0);
    } else if (nextScore >= 60) {
        tierLabel = 'stepup';
        if (!stepUpPending) {
            stepUpPending = true;
            stepUpNonce = crypto.randomBytes(16).toString('hex');
        }
    } else if (nextScore >= 40) {
        tierLabel = 'silent';
    } else {
        stepUpPending = false;
    }

    if (stepUpOk && session.step_up_pending && nextScore < 60) {
        stepUpPending = false;
    }

    let crossSessionSum = Number(lookup.data.hwid_anomaly_sum || 0);
    if (anomalyDelta > 0) {
        crossSessionSum += anomalyDelta;
        await pool.query(
            'UPDATE licenses SET hwid_anomaly_sum = $1 WHERE key = $2',
            [crossSessionSum, license_key]
        );
    }

    await pool.query(`
        UPDATE sessions SET
            last_heartbeat    = $1,
            heartbeat_count   = heartbeat_count + 1,
            last_proof_token  = $2,
            last_code_hash    = $3,
            anomaly_score     = $4,
            ip_history        = $5,
            heartbeat_times   = $6,
            step_up_pending   = $7,
            last_gate_bitmap  = $9
        WHERE license_key = $8
    `, [
        now,
        (typeof proof_token === 'string' ? proof_token : ''),
        (typeof code_hash === 'string' ? code_hash : session.last_code_hash || ''),
        nextScore,
        newIpHistory,
        newHbTimes,
        stepUpPending,
        license_key,
        Math.max(prevGateBitmap, curGateBitmap & ((1 << 24) - 1)),
    ]);

    if (nextScore >= 80 && anomalyDelta > 0) {
        const fields = [
            { name: 'License', value: `\`${license_key}\`` },
            { name: 'HWID', value: `\`${hwid || session.hwid || 'unknown'}\`` },
            { name: 'IP', value: `\`${clientIp}\`` },
            { name: 'Score', value: `${nextScore}/100` },
            { name: 'Tier', value: tierLabel },
            { name: 'CrossSession', value: `${crossSessionSum}` },
            { name: 'Flags', value: anomalyReasons.join(', ') || 'accumulated' },
        ];
        await sendDiscordWebhook('\u26A0\uFE0F Anomaly Threshold Reached', fields, 0xFFA500);
        await sendTelegramAlert('\u26A0\uFE0F Anomaly Threshold Reached', fields);
    }

    if (nextScore >= 100 || crossSessionSum >= 300) {
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
        const killReason = crossSessionSum >= 300 ? 'cross_session_anomaly_ban' : 'anomaly_auto_kill';
        await revokeLicenseAndSession(license_key, killReason, body.plugin_version, hwid || session.hwid);
        await recordBan(hwid || session.hwid, clientIp, killReason, body.plugin_version);
        return { status: 200, body: { status: 'killed', alive: false, reason: killReason } };
    }

    const heartbeatNonce = body.heartbeat_nonce || '';
    const serverNonce = generateServerNonce();
    const pageEpoch = (session.heartbeat_count || 0) + 1;

    const sigPayload = {
        status: 'valid',
        alive: true,
        license_key,
        hwid: hwid || session.hwid || '',
        plan: lookup.data.plan || 'standard',
        ttl: SESSION_TTL_SECONDS,
        heartbeat_nonce: heartbeatNonce,
        server_nonce: serverNonce,
        page_epoch: pageEpoch,
        anomaly_score: nextScore,
        anomaly_tier: tierLabel,
        degradation_factor: degradationFactor,
        ttl_grace_factor: SESSION_TTL_GRACE_FACTOR,
    };
    if (stepUpPending && stepUpNonce) sigPayload.step_up_nonce = stepUpNonce;
    const rotationBlock = buildRotationBlock();
    Object.assign(sigPayload, rotationBlock);
    const { signature, next_signature } = dualSignPayload(sigPayload);

    const responseBody = { ...sigPayload, signature };
    if (next_signature) responseBody.next_signature = next_signature;

    return {
        status: 200,
        body: responseBody,
    };
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
    await recordBan(hwid, clientIp, sanitizedReason, version);

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

        const newScore = Math.min(100, (session.anomaly_score || 0) + 40);
        await pool.query(
            'UPDATE sessions SET anomaly_score = $1 WHERE license_key = $2',
            [newScore, license_key]
        );
        if (newScore >= 100) {
            await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
            await revokeLicenseAndSession(license_key, 'zero_driver_proof', body.plugin_version, hwid);
            await recordBan(hwid, clientIp, 'zero_driver_proof', body.plugin_version);
            return { status: 200, body: { status: 'killed', alive: false } };
        }
        return { status: 200, body: { status: 'warning', anomaly_score: newScore } };
    }


    if (typeof tsc_drift === 'number' && tsc_drift > 1000000) {
        const newScore = Math.min(100, (session.anomaly_score || 0) + 25);
        await pool.query(
            'UPDATE sessions SET anomaly_score = $1 WHERE license_key = $2',
            [newScore, license_key]
        );
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
            const newScore = Math.min(100, (session.anomaly_score || 0) + 50);
            await pool.query('UPDATE sessions SET anomaly_score = $1 WHERE license_key = $2', [newScore, license_key]);
            if (newScore >= 100) {
                await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
                await revokeLicenseAndSession(license_key, 'proof_v3_mismatch', body.plugin_version, hwid);
                await recordBan(hwid, clientIp, 'proof_v3_mismatch', body.plugin_version);
                return { status: 200, body: { status: 'killed', alive: false } };
            }
            return { status: 200, body: { status: 'invalid', reason: 'proof_v3_mismatch', anomaly_score: newScore } };
        }
    }


    await pool.query(
        'UPDATE sessions SET last_proof_token = $1 WHERE license_key = $2',
        [driver_proof, license_key]
    );

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
            case 'validate':
                result = await handleValidate(body, clientIp);
                break;
            case 'heartbeat':
                result = await handleHeartbeat(body, clientIp);
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
            default:
                return res.status(400).json({ status: 'error', reason: 'unknown_action' });
        }

        return res.status(result.status).json(result.body);
    } catch (err) {
        console.error(`[license] Error processing ${action}:`, err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
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
        const challenge = await createChallenge(clientIp);
        return res.status(200).json({ status: 'ok', ...challenge });
    } catch (err) {
        console.error('[challenge] Error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
