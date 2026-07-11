'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const hmacAuth = require('../middleware/hmac_auth');
const canonicalResponse = require('../crypto/canonical_response');

const router = express.Router();
router.use(hmacAuth.authenticate);

const DISCORD_VIOLATION_WEBHOOK = process.env.DISCORD_VIOLATION_WEBHOOK_URL || '';

function clientIp(req) {
    const xf = String(req.headers['x-forwarded-for'] || '');
    if (xf) {
        const parts = xf.split(',');
        const ip = parts[0].trim();
        if (ip) return ip;
    }
    return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '';
}

async function sendDiscordNotification(embed) {
    if (!DISCORD_VIOLATION_WEBHOOK) return;
    try {
        const resp = await fetch(DISCORD_VIOLATION_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
        if (!resp || !resp.ok) {
            console.warn('[honeypot] discord notification failed:', resp ? resp.status : 'no response');
        }
    } catch (err) {
        console.error('[honeypot] discord notification error:', err.message);
    }
}

router.post('/patch-attempt', async (req, res) => {
    const body = req.body || {};
    const hwid = String(body.hwid || '');
    const licenseKey = String(body.license_key || '');
    const watermark = String(body.watermark || 'aida_standalone');
    const patchLocation = String(body.patch_location || '');
    const patchBytes = String(body.patch_bytes || '');
    const decoyId = parseInt(body.decoy_id, 10);
    const bugCode = parseInt(body.bug_code, 10) || 0;
    const patchType = parseInt(body.patch_type, 10) || 0;
    const computedCrc = String(body.computed_crc || '');
    const storedCrc = String(body.stored_crc || '');
    const ip = clientIp(req);
    const now = Math.floor(Date.now() / 1000);
    const nowIso = new Date().toISOString();

    if (!Number.isFinite(decoyId) || decoyId < -1) {
        return res.status(400).json({ status: 'error', reason: 'invalid_decoy_id' });
    }

    let revoked = false;

    try {
        await pool.query(
            `INSERT INTO patch_attempts
                (hwid, license_key, watermark, patch_location, patch_bytes,
                 decoy_id, bug_code, patch_type, computed_crc, stored_crc,
                 timestamp, timestamp_iso, ip, revoked)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [hwid, licenseKey, watermark, patchLocation, patchBytes,
             decoyId, bugCode, patchType, computedCrc, storedCrc,
             now, nowIso, ip, false]
        );
    } catch (err) {
        console.error('[honeypot] patch_attempt insert error:', err.message);
    }

    if (patchType === 1 && licenseKey) {
        try {
            await pool.query(
                `UPDATE licenses
                    SET active = false,
                        revoked_at = $1,
                        revoked_reason = $2,
                        revoked_version = 'honeypot_patch'
                 WHERE key = $3`,
                [now, `honeypot_patch:decoy_${decoyId}:bug_0x${bugCode.toString(16)}`, licenseKey]
            );

            await pool.query(
                `UPDATE sessions
                    SET kill_flag = true
                 WHERE license_key = $1`,
                [licenseKey]
            );

            await pool.query(
                `UPDATE patch_attempts SET revoked = true
                 WHERE hwid = $1 AND decoy_id = $2 AND timestamp = $3`,
                [hwid, decoyId, now]
            );

            revoked = true;
        } catch (err) {
            console.error('[honeypot] revocation error:', err.message);
        }
    }

    const embed = {
        title: `[HONEYPOT] Canary Patch Detected — decoy_${decoyId}`,
        color: 0xff0000,
        fields: [
            { name: 'License', value: `\`${licenseKey || 'unknown'}\``, inline: true },
            { name: 'HWID', value: `\`${hwid || 'unknown'}\``, inline: true },
            { name: 'IP', value: `\`${ip}\``, inline: true },
            { name: 'Bug Code', value: `\`0x${bugCode.toString(16)}\``, inline: true },
            { name: 'Patch Type', value: `\`${patchType === 1 ? 'CRC_VALID_PATCH' : 'CRC_INVALID_CORRUPTION'}\``, inline: true },
            { name: 'Revoked', value: `\`${revoked}\``, inline: true },
            { name: 'Location', value: `\`${patchLocation}\``, inline: false },
            { name: 'Bytes', value: `\`${patchBytes}\``, inline: false },
        ],
        timestamp: nowIso,
    };
    sendDiscordNotification(embed);

    const responsePayload = { status: 'ok', revoked };
    const signed = canonicalResponse.sign(responsePayload);
    return res.json(signed);
});

router.post('/honeypot-access', async (req, res) => {
    const body = req.body || {};
    const hwid = String(body.hwid || '');
    const licenseKey = String(body.license_key || '');
    const watermark = String(body.watermark || 'aida_standalone');
    const rip = String(body.rip || '');
    const accessedAddr = String(body.accessed_addr || '');
    const pid = String(body.pid || '');
    const bugCode = parseInt(body.bug_code, 10) || 0xA1DA0001;
    const ip = clientIp(req);
    const now = Math.floor(Date.now() / 1000);
    const nowIso = new Date().toISOString();

    let revoked = false;

    try {
        await pool.query(
            `INSERT INTO patch_attempts
                (hwid, license_key, watermark, patch_location, patch_bytes,
                 decoy_id, bug_code, patch_type, computed_crc, stored_crc,
                 timestamp, timestamp_iso, ip, revoked)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
            [hwid, licenseKey, watermark,
             `honeypot_string_access rip=${rip} addr=${accessedAddr}`,
             `pid=${pid}`,
             -1, bugCode, 1, '', '',
             now, nowIso, ip, false]
        );
    } catch (err) {
        console.error('[honeypot] honeypot_access insert error:', err.message);
    }

    if (licenseKey) {
        try {
            await pool.query(
                `UPDATE licenses
                    SET active = false,
                        revoked_at = $1,
                        revoked_reason = $2,
                        revoked_version = 'honeypot'
                 WHERE key = $3`,
                [now, `honeypot_string_access:pid_${pid}:bug_0x${bugCode.toString(16)}`, licenseKey]
            );

            await pool.query(
                `UPDATE sessions
                    SET kill_flag = true
                 WHERE license_key = $1`,
                [licenseKey]
            );

            await pool.query(
                `UPDATE patch_attempts SET revoked = true
                 WHERE hwid = $1 AND bug_code = $2 AND timestamp = $3`,
                [hwid, bugCode, now]
            );

            revoked = true;
        } catch (err) {
            console.error('[honeypot] revocation error:', err.message);
        }
    }

    const embed = {
        title: `[HONEYPOT] String External Access — PID ${pid}`,
        color: 0xff0000,
        fields: [
            { name: 'License', value: `\`${licenseKey || 'unknown'}\``, inline: true },
            { name: 'HWID', value: `\`${hwid || 'unknown'}\``, inline: true },
            { name: 'IP', value: `\`${ip}\``, inline: true },
            { name: 'RIP', value: `\`${rip}\``, inline: true },
            { name: 'Addr', value: `\`${accessedAddr}\``, inline: true },
            { name: 'Bug Code', value: `\`0x${bugCode.toString(16)}\``, inline: true },
            { name: 'Revoked', value: `\`${revoked}\``, inline: true },
        ],
        timestamp: nowIso,
    };
    sendDiscordNotification(embed);

    const responsePayload = { status: 'ok', revoked };
    const signed = canonicalResponse.sign(responsePayload);
    return res.json(signed);
});

router.get('/patch-attempts', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    try {
        const { rows } = await pool.query(
            `SELECT id, hwid, license_key, patch_location, decoy_id, bug_code,
                    patch_type, timestamp, timestamp_iso, ip, revoked
             FROM patch_attempts
             ORDER BY timestamp DESC
             LIMIT $1 OFFSET $2`,
            [limit, offset]
        );
        return res.json({ status: 'ok', count: rows.length, attempts: rows });
    } catch (err) {
        console.error('[honeypot] patch_attempts query error:', err.message);
        return res.status(500).json({ status: 'error', reason: 'db_error' });
    }
});

module.exports = router;
