'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const hmacAuth = require('../middleware/hmac_auth');

const router = express.Router();

router.use(hmacAuth.authenticate);

const CLIENT_PUBKEY_B64 = process.env.CLIENT_TELEMETRY_PUBKEY_B64 || '';
const DISCORD_WEBHOOK = process.env.DISCORD_TELEMETRY_WEBHOOK || '';
const DISCORD_VIOLATION_WEBHOOK = process.env.DISCORD_VIOLATION_WEBHOOK_URL || '';
const FORWARD_MIN_SEVERITY = (process.env.TELEMETRY_FORWARD_MIN_SEVERITY || 'warn').toLowerCase();
const MAX_PAYLOAD_FIELDS = 32;
const MAX_FIELD_LEN = 512;
const SEVERITIES = { debug: 0, info: 1, warn: 2, critical: 3 };

const g_forward_tokens = { count: 5, last_refill: Date.now() };
const FORWARD_RATE_PER_MIN = 10;
const FORWARD_BURST = 5;

let g_digest_buffer = [];
let g_digest_timer = null;

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function loadClientPubkey() {
    if (!CLIENT_PUBKEY_B64) return null;
    const raw = Buffer.from(CLIENT_PUBKEY_B64, 'base64');
    if (raw.length !== 32) return null;
    const spki = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        raw,
    ]);
    try {
        return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch (_) {
        return null;
    }
}

function verifyClientSignature(body, sigB64) {
    const pub = loadClientPubkey();
    if (!pub || !sigB64) return false;
    const canonical = JSON.stringify(sortKeys(body));
    try {
        return crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, Buffer.from(sigB64, 'base64'));
    } catch (_) {
        return false;
    }
}

function sortKeys(obj) {
    if (Array.isArray(obj)) return obj.map(sortKeys);
    if (obj && typeof obj === 'object') {
        const out = {};
        for (const k of Object.keys(obj).sort()) out[k] = sortKeys(obj[k]);
        return out;
    }
    return obj;
}

function sanitizeEvent(ev) {
    if (!ev || typeof ev !== 'object') return null;
    const out = {};
    const keys = Object.keys(ev).slice(0, MAX_PAYLOAD_FIELDS);
    for (const k of keys) {
        const v = ev[k];
        if (v === null || v === undefined) continue;
        if (typeof v === 'string') out[k] = v.slice(0, MAX_FIELD_LEN);
        else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
        else if (typeof v === 'object') out[k] = JSON.stringify(v).slice(0, MAX_FIELD_LEN);
    }
    return out;
}

function tryConsumeToken() {
    const now = Date.now();
    const elapsedSec = (now - g_forward_tokens.last_refill) / 1000;
    const refill = elapsedSec * (FORWARD_RATE_PER_MIN / 60);
    g_forward_tokens.count = Math.min(FORWARD_BURST, g_forward_tokens.count + refill);
    g_forward_tokens.last_refill = now;
    if (g_forward_tokens.count >= 1) {
        g_forward_tokens.count -= 1;
        return true;
    }
    return false;
}

async function postToDiscord(embed) {
    if (!DISCORD_WEBHOOK) return;
    try {
        await fetch(DISCORD_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) { }
}

function scheduleDigestFlush() {
    if (g_digest_timer) return;
    g_digest_timer = setTimeout(async () => {
        g_digest_timer = null;
        const batch = g_digest_buffer.splice(0, g_digest_buffer.length);
        if (batch.length === 0) return;
        if (!tryConsumeToken()) { scheduleDigestFlush(); return; }
        const fields = batch.slice(0, 20).map(ev => ({
            name: `[${ev.severity}] ${ev.type}`,
            value: `\`${ev.license_key || 'unknown'}\` — ${JSON.stringify(ev.payload || {}).slice(0, 200)}`,
            inline: false,
        }));
        await postToDiscord({
            title: `Telemetry digest (${batch.length} events, rate-limited)`,
            color: 0xffaa00,
            fields,
            timestamp: new Date().toISOString(),
        });
    }, 30 * 1000);
    g_digest_timer.unref();
}

async function maybeForwardEvent(ev) {
    const evSev = SEVERITIES[ev.severity] || 0;
    const minSev = SEVERITIES[FORWARD_MIN_SEVERITY] || 2;
    if (evSev < minSev) return;
    if (!DISCORD_WEBHOOK) return;

    if (!tryConsumeToken()) {
        g_digest_buffer.push(ev);
        if (g_digest_buffer.length > 256) g_digest_buffer.splice(0, g_digest_buffer.length - 256);
        scheduleDigestFlush();
        return;
    }

    const color = ev.severity === 'critical' ? 0xff0000 : ev.severity === 'warn' ? 0xffaa00 : 0x00aaff;
    const payloadSummary = JSON.stringify(ev.payload || {}).slice(0, 900);
    await postToDiscord({
        title: `[${ev.severity.toUpperCase()}] ${ev.type}`,
        color,
        fields: [
            { name: 'License', value: `\`${ev.license_key || 'unknown'}\``, inline: true },
            { name: 'HWID',    value: `\`${ev.hwid || 'unknown'}\``, inline: true },
            { name: 'IP',      value: `\`${ev.client_ip || 'unknown'}\``, inline: true },
            { name: 'Payload', value: `\`\`\`json\n${payloadSummary}\n\`\`\`` },
        ],
        timestamp: new Date().toISOString(),
    });
}

async function persistEvent(ev) {
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `INSERT INTO sentinel_events (license_key, quorum_id, event_type, severity, payload, received_at, client_ip)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
        [ev.license_key || '', '', ev.type || 'telemetry', ev.severity || 'info', JSON.stringify(ev.payload || {}), now, ev.client_ip || '']
    );
}


router.post('/', async (req, res) => {
    try {
        const { license_key, events, signature } = req.body || {};

        if (!license_key || typeof license_key !== 'string') {
            return res.status(400).json({ status: 'error', reason: 'missing_license_key' });
        }
        if (!Array.isArray(events) || events.length === 0) {
            return res.status(400).json({ status: 'error', reason: 'missing_events' });
        }

        if (CLIENT_PUBKEY_B64) {
            const payloadForSig = { license_key, events };
            if (!verifyClientSignature(payloadForSig, signature)) {
                return res.status(403).json({ status: 'error', reason: 'bad_signature' });
            }
        }

        const { rows: licRows } = await pool.query('SELECT hwid, active FROM licenses WHERE key = $1', [license_key]);
        if (licRows.length === 0) return res.status(403).json({ status: 'error', reason: 'license_not_found' });
        const lic = licRows[0];
        if (!lic.active) return res.status(403).json({ status: 'error', reason: 'license_inactive' });

        const ip = clientIp(req);
        let accepted = 0;
        let rejected = 0;

        for (const raw of events.slice(0, 64)) {
            const ev = {
                license_key,
                hwid: lic.hwid || '',
                client_ip: ip,
                type: String(raw.type || 'unknown').slice(0, 64),
                severity: ['debug', 'info', 'warn', 'critical'].includes(raw.severity) ? raw.severity : 'info',
                payload: sanitizeEvent(raw.payload),
            };
            try {
                await persistEvent(ev);
                await maybeForwardEvent(ev);
                accepted++;
            } catch (err) {
                console.error('[telemetry] persist error:', err.message);
                rejected++;
            }
        }

        return res.json({ status: 'ok', accepted, rejected });
    } catch (err) {
        console.error('[telemetry] POST /api/telemetry error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

const g_critical_tokens = new Map();
const CRITICAL_RATE_PER_MIN = 60;

function checkCriticalRate(license_key) {
    const now = Date.now();
    let entry = g_critical_tokens.get(license_key);
    if (!entry) {
        entry = { count: 0, window_start: now };
        g_critical_tokens.set(license_key, entry);
    }
    if (now - entry.window_start > 60000) {
        entry.window_start = now;
        entry.count = 0;
    }
    entry.count++;
    return entry.count <= CRITICAL_RATE_PER_MIN;
}

router.post('/critical_webhook', async (req, res) => {
    try {
        const { license_key, events, signature } = req.body || {};

        if (!license_key || typeof license_key !== 'string') {
            return res.status(400).json({ status: 'error', reason: 'missing_license_key' });
        }
        if (!Array.isArray(events) || events.length === 0) {
            return res.status(400).json({ status: 'error', reason: 'missing_events' });
        }
        if (!checkCriticalRate(license_key)) {
            return res.status(429).json({ status: 'error', reason: 'rate_limited' });
        }

        if (CLIENT_PUBKEY_B64) {
            const payloadForSig = { license_key, events };
            if (!verifyClientSignature(payloadForSig, signature)) {
                return res.status(403).json({ status: 'error', reason: 'bad_signature' });
            }
        }

        const { rows: licRows } = await pool.query(
            'SELECT hwid, active FROM licenses WHERE key = $1', [license_key]);
        if (licRows.length === 0)
            return res.status(403).json({ status: 'error', reason: 'license_not_found' });
        const lic = licRows[0];
        if (!lic.active)
            return res.status(403).json({ status: 'error', reason: 'license_inactive' });

        const ip = clientIp(req);
        let forwarded = 0;

        for (const raw of events.slice(0, 8)) {
            const ev = {
                license_key,
                hwid: lic.hwid || '',
                client_ip: ip,
                type: String(raw.type || 'critical_webhook').slice(0, 64),
                severity: 'critical',
                payload: sanitizeEvent(raw.payload),
            };

            try {
                await persistEvent(ev);
            } catch (err) {
                console.error('[critical_webhook] persist error:', err.message);
            }

            const p = ev.payload || {};
            const payloadSummary = JSON.stringify(p).slice(0, 1500);
            const sigMask = (typeof p.signal_mask === 'number') ? p.signal_mask : 0;
            const embed = {
                title: `[CRITICAL] RE Detection \u2014 ${p.reason || ev.type}`,
                color: 0xff0000,
                fields: [
                    { name: 'License', value: `\`${license_key}\``, inline: true },
                    { name: 'HWID',    value: `\`${lic.hwid || 'unknown'}\``, inline: true },
                    { name: 'IP',      value: `\`${ip}\``, inline: true },
                    { name: 'Signal Mask', value: `\`0x${sigMask.toString(16)}\``, inline: true },
                    { name: 'Computer', value: `\`${p.computer || 'unknown'}\``, inline: true },
                    { name: 'User',    value: `\`${p.user || 'unknown'}\``, inline: true },
                    { name: 'Payload', value: `\`\`\`json\n${payloadSummary}\n\`\`\`` },
                ],
                timestamp: new Date().toISOString(),
            };

            const target = DISCORD_VIOLATION_WEBHOOK || DISCORD_WEBHOOK;
            if (target) {
                try {
                    const resp = await fetch(target, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ embeds: [embed] }),
                    });
                    if (resp && resp.ok) forwarded++;
                } catch (err) {
                    console.error('[critical_webhook] forward error:', err.message);
                }
            }
        }

        return res.json({ status: 'ok', forwarded });
    } catch (err) {
        console.error('[telemetry] POST /api/telemetry/critical_webhook error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
