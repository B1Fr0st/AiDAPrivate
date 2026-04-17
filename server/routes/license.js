

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');
const { deriveKeySeed } = require('../crypto/arc-encrypt');

const router = express.Router();


const SESSION_TTL_SECONDS = 3600;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';
const TELEGRAM_BOT_TOKEN  = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID    = process.env.TELEGRAM_CHAT_ID || '';


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
        INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat, kill_flag, heartbeat_count, last_proof_token, last_code_hash, anomaly_score, ip_history, heartbeat_times)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, 0, '', '', 0, ARRAY[$7]::TEXT[], ARRAY[]::BIGINT[])
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
            heartbeat_times   = ARRAY[]::BIGINT[]
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


    const hwidResult = await verifyOrBindHwid(license_key, hwid, lookup.data.hwid || '');
    if (!hwidResult.ok) {
        return { status: 200, body: { status: 'invalid', reason: hwidResult.reason } };
    }


    const sessionToken = generateSessionToken();
    const serverNonce = generateServerNonce();
    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = SESSION_TTL_SECONDS;

    await storeSession(license_key, {
        session_token: sessionToken,
        server_nonce: serverNonce,
        issued_at: issuedAt,
        ttl,
        hwid,
        ip: clientIp,
        plugin_version: plugin_version || 'unknown',
        last_heartbeat: issuedAt,
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
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: { ...sigPayload, signature },
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
        const expiresAt = session.issued_at + Math.floor(session.ttl * 1.5);
        if (now > expiresAt) {
            return { status: 200, body: { status: 'invalid', reason: 'session_expired' } };
        }
    }

    if (hwid && session.hwid && hwid !== session.hwid) {
        return { status: 200, body: { status: 'invalid', reason: 'hwid_mismatch' } };
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

    const newAnomalyScore = Math.min(100, (session.anomaly_score || 0) + anomalyDelta);

    await pool.query(`
        UPDATE sessions SET
            last_heartbeat    = $1,
            heartbeat_count   = heartbeat_count + 1,
            last_proof_token  = $2,
            last_code_hash    = $3,
            anomaly_score     = $4,
            ip_history        = $5,
            heartbeat_times   = $6
        WHERE license_key = $7
    `, [
        now,
        (typeof proof_token === 'string' ? proof_token : ''),
        (typeof code_hash === 'string' ? code_hash : session.last_code_hash || ''),
        newAnomalyScore,
        newIpHistory,
        newHbTimes,
        license_key,
    ]);

    if (newAnomalyScore >= 80) {
        const fields = [
            { name: 'License', value: `\`${license_key}\`` },
            { name: 'HWID', value: `\`${hwid || session.hwid || 'unknown'}\`` },
            { name: 'IP', value: `\`${clientIp}\`` },
            { name: 'Score', value: `${newAnomalyScore}/100` },
            { name: 'Flags', value: anomalyReasons.join(', ') || 'accumulated' },
        ];
        await sendDiscordWebhook('\u26A0\uFE0F Anomaly Threshold Reached', fields, 0xFFA500);
        await sendTelegramAlert('\u26A0\uFE0F Anomaly Threshold Reached', fields);
    }

    if (newAnomalyScore >= 100) {
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
        await revokeLicenseAndSession(license_key, 'anomaly_auto_kill', body.plugin_version, hwid || session.hwid);
        await recordBan(hwid || session.hwid, clientIp, 'anomaly_auto_kill', body.plugin_version);
        return { status: 200, body: { status: 'killed', alive: false, reason: 'anomaly' } };
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
    };
    const signature = signPayload(sigPayload);

    return {
        status: 200,
        body: { ...sigPayload, signature },
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

module.exports = router;
