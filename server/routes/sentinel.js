'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');
const kw = require('../crypto/kw_wrap');
const hmacAuth = require('../middleware/hmac_auth');
const canonicalResponse = require('../crypto/canonical_response');
const peerCodeHash = require('../crypto/peer_code_hash');

let columnCrypt = null;
try { columnCrypt = require('../crypto/column_crypt'); } catch (_) { columnCrypt = null; }

const router = express.Router();

async function verifyAttestBindToken(req) {
    const body = req.body || {};
    const provided = typeof body.bind_token === 'string' ? body.bind_token.trim().toLowerCase() : '';
    const licenseKey = typeof body.license_key === 'string' ? body.license_key.trim() : '';
    if (!provided || !/^[0-9a-f]{32,128}$/.test(provided)) {
        return { ok: false, reason: 'bind_token_missing' };
    }
    if (!licenseKey) {
        return { ok: false, reason: 'license_missing' };
    }
    try {
        const { rows } = await pool.query(
            'SELECT sentinel_bind_token_hash, sentinel_bind_consumed, sentinel_bind_issued_at FROM sessions WHERE license_key = $1',
            [licenseKey]
        );
        if (rows.length === 0) {
            return { ok: false, reason: 'session_not_found' };
        }
        const row = rows[0];
        const expected = String(row.sentinel_bind_token_hash || '').trim().toLowerCase();
        if (!expected || expected.length !== 64) {
            return { ok: false, reason: 'bind_token_not_issued' };
        }
        const providedHash = crypto.createHash('sha256').update(provided, 'hex').digest('hex');
        const a = Buffer.from(providedHash, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            return { ok: false, reason: 'bind_token_mismatch' };
        }
        if (row.sentinel_bind_consumed) {
            return { ok: false, reason: 'bind_token_consumed' };
        }
        const issuedAt = Number(row.sentinel_bind_issued_at || 0);
        const ageSec = Math.floor(Date.now() / 1000) - issuedAt;
        if (!issuedAt || ageSec > 86400 || ageSec < -300) {
            return { ok: false, reason: 'bind_token_expired' };
        }
        return { ok: true };
    } catch (err) {
        return { ok: false, reason: 'bind_token_lookup_failed' };
    }
}

router.use(async (req, res, next) => {
    if (req.path === '/attest') {
        const lic = req.body && typeof req.body === 'object' ? req.body.license_key : '';
        if (typeof lic === 'string' && lic.length > 0) {
            try {
                const { rows } = await pool.query('SELECT install_secret_wrapped FROM licenses WHERE key = $1', [lic]);
                if (rows.length > 0 && rows[0].install_secret_wrapped) {
                    const verdict = await verifyAttestBindToken(req);
                    if (!verdict.ok) {
                        return res.status(403).json({ status: 'error', reason: 'attest_bind_token_invalid', detail: verdict.reason });
                    }
                    req._attestBindOk = true;
                }
            } catch (_) {
                return res.status(503).json({ status: 'error', reason: 'attest_lookup_failed' });
            }
        }
        return next();
    }
    return hmacAuth.authenticate(req, res, next);
});

const ATTEST_HMAC_LABEL = 'aida/attest/v1';
const KW_ISSUANCE_LABEL = 'aida/kw_issuance/v1';
const RING_BUFFER_MAX = parseInt(process.env.SENTINEL_RING_MAX || '2048', 10);
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function sigSignOrFallback(payloadObj) {
    try {
        return signPayload(payloadObj);
    } catch (_) {
        return '';
    }
}

async function lookupLicense(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') return null;
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [licenseKey]);
    return rows[0] || null;
}

async function recordSentinelEvent(licenseKey, quorumId, eventType, severity, payload, ip, hvci, ntBuild, bootCount) {
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `INSERT INTO sentinel_events (license_key, quorum_id, event_type, severity, payload, hvci_enabled, nt_build, boot_count, received_at, client_ip)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)`,
        [licenseKey, quorumId || '', eventType, severity || 'info', JSON.stringify(payload || {}), hvci === undefined ? null : !!hvci, ntBuild || null, bootCount || null, now, ip || '']
    );
    await pool.query('DELETE FROM sentinel_events WHERE id IN (SELECT id FROM sentinel_events WHERE license_key = $1 ORDER BY id DESC OFFSET $2)', [licenseKey, RING_BUFFER_MAX]);
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
            footer: { text: 'AiDA Sentinel' },
        };
        await fetch(DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ embeds: [embed] }),
        });
    } catch (_) { }
}

async function recordSentinelViolation(licenseKey, quorumId, reason, evidence, ip, hvci, ntBuild, bootCount) {
    await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [licenseKey]);
    await recordSentinelEvent(licenseKey, quorumId, reason, 'critical', evidence, ip, hvci, ntBuild, bootCount);
    await sendDiscordWebhook('AiDA Sentinel Violation Detected', [
        { name: 'Route', value: 'sentinel' },
        { name: 'Action', value: 'heartbeat' },
        { name: 'Reason', value: reason },
        { name: 'License', value: `\`${licenseKey}\`` },
        { name: 'Quorum', value: `\`${quorumId || 'unknown'}\`` },
        { name: 'IP', value: `\`${ip || 'unknown'}\`` },
        { name: 'NT Build', value: ntBuild || 'unknown' },
        { name: 'Evidence', value: JSON.stringify(evidence || {}) },
    ], 0xFF0000);
}

async function upsertQuorumSeen(licenseKey, quorumId, ntBuild, hvci) {
    if (!quorumId) return;
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `INSERT INTO sentinel_quorum (license_key, quorum_id, last_seen_at, nt_build, hvci_enabled)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (license_key, quorum_id) DO UPDATE SET
            last_seen_at = EXCLUDED.last_seen_at,
            nt_build     = EXCLUDED.nt_build,
            hvci_enabled = EXCLUDED.hvci_enabled`,
        [licenseKey, quorumId, now, ntBuild || null, hvci === undefined ? null : !!hvci]
    );
}

function verifyInstallSecretHmac(installSecret, hardwareId, licenseKey, bootTs, expectedHex) {
    const mac = crypto.createHmac('sha256', installSecret)
        .update(`${hardwareId}|${licenseKey}|${bootTs}`)
        .digest('hex');
    const a = Buffer.from(mac, 'utf8');
    const b = Buffer.from(String(expectedHex || ''), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}


router.post('/attest', async (req, res) => {
    try {
        const {
            license_key,
            hardware_id,
            smbios_uuid_hash,
            baseboard_serial_hash,
            disk_vpd_hash,
            machine_guid_hash,
            boot_nonce,
            boot_ts,
            attest_hmac,
            hvci_enabled,
            nt_build,
        } = req.body || {};

        if (!license_key || !hardware_id || !boot_nonce || !boot_ts) {
            return res.status(400).json({ status: 'error', reason: 'missing_fields' });
        }

        const lic = await lookupLicense(license_key);
        if (!lic) return res.status(403).json({ status: 'error', reason: 'license_not_found' });
        if (!lic.active) return res.status(403).json({ status: 'error', reason: 'license_inactive' });

        const ip = clientIp(req);

        let installSecret;
        let isFirstActivation = false;

        if (!lic.install_secret_wrapped) {
            installSecret = kw.generateInstallSecret();
            const wrapped = kw.wrap(installSecret, 'install_secret/v1');
            await pool.query(
                `UPDATE licenses SET
                    install_secret_wrapped = $1,
                    hardware_id_sha256     = $2,
                    smbios_uuid_hash       = $3,
                    baseboard_serial_hash  = $4,
                    disk_vpd_hash          = $5,
                    machine_guid_hash      = $6
                 WHERE key = $7`,
                [wrapped, hardware_id, smbios_uuid_hash || '', baseboard_serial_hash || '', disk_vpd_hash || '', machine_guid_hash || '', license_key]
            );
            isFirstActivation = true;
        } else {
            try {
                installSecret = kw.unwrap(lic.install_secret_wrapped, 'install_secret/v1');
            } catch (err) {
                console.error('[sentinel] install_secret unwrap failed:', err.message);
                return res.status(500).json({ status: 'error', reason: 'unwrap_failed' });
            }

            if (lic.hardware_id_sha256 && lic.hardware_id_sha256 !== hardware_id) {
                await recordSentinelEvent(license_key, '', 'attest_hardware_mismatch', 'critical',
                    { expected: lic.hardware_id_sha256, got: hardware_id }, ip, hvci_enabled, nt_build, 0);
                return res.status(403).json({ status: 'error', reason: 'hardware_mismatch' });
            }

            if (!verifyInstallSecretHmac(installSecret, hardware_id, license_key, boot_ts, attest_hmac)) {
                await recordSentinelEvent(license_key, '', 'attest_hmac_fail', 'critical',
                    { boot_ts }, ip, hvci_enabled, nt_build, 0);
                return res.status(403).json({ status: 'error', reason: 'attest_hmac_fail' });
            }
        }

        const witnessKey = kw.generateWitnessKey();
        const witnessWrapped = kw.wrap(witnessKey, 'kw/v1');

        const issuanceSubkey = crypto.createHmac('sha256', installSecret)
            .update(`${hardware_id}|${boot_nonce}|${boot_ts}`)
            .digest();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', issuanceSubkey, iv);
        const encKw = Buffer.concat([cipher.update(witnessKey), cipher.final()]);
        const tag = cipher.getAuthTag();

        const ioctlSeed = crypto.randomBytes(16);
        const ioctlSeedIv = crypto.randomBytes(12);
        const ioctlCipher = crypto.createCipheriv('aes-256-gcm', issuanceSubkey, ioctlSeedIv);
        const ioctlEnc = Buffer.concat([ioctlCipher.update(ioctlSeed), ioctlCipher.final()]);
        const ioctlTag = ioctlCipher.getAuthTag();

        const now = Math.floor(Date.now() / 1000);
        await pool.query(
            `UPDATE licenses SET
                witness_key_wrapped   = $1,
                boot_nonce_last       = $2,
                attest_count          = attest_count + 1,
                last_attest_at        = $3,
                hvci_enabled          = $4,
                ioctl_seed_wrapped    = $5
             WHERE key = $6`,
            [witnessWrapped, boot_nonce, now, hvci_enabled === undefined ? null : !!hvci_enabled, kw.wrap(ioctlSeed, 'ioctl_seed/v1'), license_key]
        );

        await recordSentinelEvent(license_key, '', isFirstActivation ? 'attest_first' : 'attest_ok', 'info',
            { boot_ts, nt_build }, ip, hvci_enabled, nt_build, 0);

        const response = {
            status: 'ok',
            kw_iv: iv.toString('hex'),
            kw_tag: tag.toString('hex'),
            kw_ciphertext: encKw.toString('hex'),
            ioctl_seed_iv: ioctlSeedIv.toString('hex'),
            ioctl_seed_tag: ioctlTag.toString('hex'),
            ioctl_seed_ciphertext: ioctlEnc.toString('hex'),
            issued_at: now,
            first_activation: isFirstActivation,
            install_secret_fingerprint: crypto.createHash('sha256').update(installSecret).digest('hex').slice(0, 16),
        };

        if (req._attestBindOk) {
            try {
                await pool.query(
                    'UPDATE sessions SET sentinel_bind_consumed = true WHERE license_key = $1',
                    [license_key]
                );
            } catch (_) { }
        }

        return res.json(canonicalResponse.buildEnvelope(response));
    } catch (err) {
        console.error('[sentinel] /attest error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


async function recordPeerCodeHash(licenseKey, quorumId, peerHashHex, hvci, ntBuild, ip) {
    if (!licenseKey || !peerHashHex) return;
    const cleaned = String(peerHashHex || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(cleaned)) return;
    const now = Math.floor(Date.now() / 1000);
    const expectedHash = peerCodeHash.getExpected();
    const matched = expectedHash ? (expectedHash === cleaned) : false;
    let sessionToken = '';
    try {
        const { rows } = await pool.query(
            'SELECT session_token, session_uuid FROM sessions WHERE license_key = $1',
            [licenseKey]
        );
        if (rows.length > 0) {
            let stored = rows[0].session_token || '';
            const uuid = rows[0].session_uuid || '';
            if (uuid && typeof stored === 'string' && columnCrypt && columnCrypt.isCiphertext && columnCrypt.isCiphertext(stored)) {
                try { stored = columnCrypt.decrypt(uuid, 'sessions/session_token', stored); } catch (_) { stored = ''; }
            }
            sessionToken = stored || '';
        }
    } catch (_) { }
    try {
        await pool.query(
            `INSERT INTO sentinel_attestations
                (license_key, session_token, quorum_id, peer_code_hash, peer_code_hash_received_at,
                 expected_hash_at_receive, matched, nt_build, hvci_enabled, client_ip)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [licenseKey, sessionToken, quorumId || '', cleaned, now, expectedHash || '', matched, ntBuild || null, hvci === undefined ? null : !!hvci, ip || '']
        );
    } catch (err) {
        console.warn('[sentinel] peer_code_hash persist failed:', err && err.message ? err.message : err);
    }
    if (expectedHash) {
        try {
            if (matched) {
                await pool.query(
                    `UPDATE sessions
                        SET peer_attest_divergence_streak = 0,
                            peer_attest_last_hash         = $1,
                            peer_attest_last_matched_at   = $2,
                            peer_attest_degraded          = false
                      WHERE license_key = $3`,
                    [cleaned, now, licenseKey]
                );
            } else {
                await pool.query(
                    `UPDATE sessions
                        SET peer_attest_divergence_streak = peer_attest_divergence_streak + 1,
                            peer_attest_last_hash         = $1
                      WHERE license_key = $2`,
                    [cleaned, licenseKey]
                );
                const { rows } = await pool.query(
                    'SELECT peer_attest_divergence_streak FROM sessions WHERE license_key = $1',
                    [licenseKey]
                );
                const streak = rows.length > 0 ? Number(rows[0].peer_attest_divergence_streak || 0) : 0;
                if (streak >= 2 && streak < 5) {
                    await pool.query(
                        'UPDATE sessions SET peer_attest_degraded = true WHERE license_key = $1',
                        [licenseKey]
                    );
                    await recordSentinelEvent(licenseKey, quorumId || '', 'peer_code_hash_degraded', 'warn',
                        { streak, expected: expectedHash, observed: cleaned }, ip, hvci, ntBuild, 0);
                } else if (streak >= 5) {
                    await recordSentinelViolation(licenseKey, quorumId || '', 'peer_code_hash_divergent',
                        { streak, expected: expectedHash, observed: cleaned }, ip, hvci, ntBuild, 0);
                }
            }
        } catch (err) {
            console.warn('[sentinel] peer_code_hash streak update failed:', err && err.message ? err.message : err);
        }
    }
}

router.post('/heartbeat', async (req, res) => {
    try {
        const {
            license_key,
            quorum_id,
            events,
            hvci_enabled,
            nt_build,
            boot_count,
            sensors,
            peer_code_hash,
        } = req.body || {};

        if (!license_key || !quorum_id) {
            return res.status(400).json({ status: 'error', reason: 'missing_fields' });
        }

        const lic = await lookupLicense(license_key);
        if (!lic || !lic.active) return res.status(403).json({ status: 'error', reason: 'license_inactive' });

        const ip = clientIp(req);
        await upsertQuorumSeen(license_key, quorum_id, nt_build, hvci_enabled);
        if (typeof peer_code_hash === 'string' && peer_code_hash.length > 0) {
            await recordPeerCodeHash(license_key, quorum_id, peer_code_hash, hvci_enabled, nt_build, ip);
        }

        const evArr = Array.isArray(events) ? events : [];
        for (const ev of evArr.slice(0, 64)) {
            if (!ev || typeof ev !== 'object') continue;
            const type = String(ev.type || 'unknown').slice(0, 64);
            const sev = ['info', 'warn', 'critical'].includes(ev.severity) ? ev.severity : 'info';
            await recordSentinelEvent(license_key, quorum_id, type, sev, ev.payload || {}, ip, hvci_enabled, nt_build, boot_count);
        }

        const sensorDeviations = [];
        if (sensors && typeof sensors === 'object' && lic.last_sensor_snapshot) {
            try {
                const prev = typeof lic.last_sensor_snapshot === 'string'
                    ? JSON.parse(lic.last_sensor_snapshot)
                    : lic.last_sensor_snapshot;
                const checkFields = ['cr4_smep', 'cr4_smap', 'hal_crc', 'ki_service_table_crc', 'lstar_msr', 'idt_crc', 'eprocess_protection'];
                for (const f of checkFields) {
                    if (prev[f] !== undefined && sensors[f] !== undefined && prev[f] !== sensors[f]) {
                        sensorDeviations.push({ field: f, prev: prev[f], now: sensors[f] });
                    }
                }
                if (prev.hvci_enabled === true && sensors.hvci_enabled === false) {
                    sensorDeviations.push({ field: 'hvci_enabled', prev: true, now: false });
                }
            } catch (_) { }
        }

        if (sensors && typeof sensors === 'object') {
            await pool.query(
                'UPDATE licenses SET last_sensor_snapshot = $1::jsonb WHERE key = $2',
                [JSON.stringify(sensors), license_key]
            );
        }

        if (sensorDeviations.length > 0) {
            await recordSentinelViolation(license_key, quorum_id, 'sensor_deviation',
                { deviations: sensorDeviations },
                ip, hvci_enabled, nt_build, boot_count);
            const response = {
                status: 'killed',
                live_quorum: 0,
                required_quorum: 2,
                kill_flag: true,
                reason: 'sensor_deviation',
                next_interval_seconds: 0,
            };
            return res.json(canonicalResponse.buildEnvelope(response));
        }

        const quorumWindow = 120;
        const since = Math.floor(Date.now() / 1000) - quorumWindow;
        const { rows: qRows } = await pool.query(
            'SELECT COUNT(DISTINCT quorum_id) AS live FROM sentinel_quorum WHERE license_key = $1 AND last_seen_at > $2',
            [license_key, since]
        );
        const liveQuorum = parseInt(qRows[0].live, 10) || 0;

        let killFlag = false;
        if (liveQuorum === 0) {
            killFlag = true;
            await recordSentinelViolation(license_key, quorum_id, 'quorum_lost',
                { live: 0, required: 2 }, ip, hvci_enabled, nt_build, boot_count);
        } else if (liveQuorum === 1) {
            await recordSentinelEvent(license_key, quorum_id, 'quorum_observed_1', 'warn',
                { live: 1, required: 2 }, ip, hvci_enabled, nt_build, boot_count);
        }

        const response = {
            status: 'ok',
            live_quorum: liveQuorum,
            required_quorum: 2,
            kill_flag: killFlag,
            next_interval_seconds: liveQuorum >= 2 ? 45 : 20,
        };
        return res.json(canonicalResponse.buildEnvelope(response));
    } catch (err) {
        console.error('[sentinel] /heartbeat error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


router.post('/honeypot', async (req, res) => {
    try {
        const { license_key, quorum_id, trap_name, stack_hash } = req.body || {};
        if (!license_key || !trap_name) {
            return res.status(400).json({ status: 'error', reason: 'missing_fields' });
        }
        const ip = clientIp(req);
        await recordSentinelEvent(license_key, quorum_id || '', 'honeypot_hit', 'critical',
            { trap_name: String(trap_name).slice(0, 128), stack_hash: String(stack_hash || '').slice(0, 128) }, ip);
        await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
        return res.json({ status: 'ok', killed: true });
    } catch (err) {
        console.error('[sentinel] /honeypot error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});


router.get('/events/:license_key', async (req, res) => {
    try {
        const adminKey = req.headers['x-admin-key'];
        if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) {
            return res.status(403).json({ status: 'error', reason: 'forbidden' });
        }
        const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
        const { rows } = await pool.query(
            'SELECT * FROM sentinel_events WHERE license_key = $1 ORDER BY id DESC LIMIT $2',
            [req.params.license_key, limit]
        );
        return res.json({ status: 'ok', events: rows });
    } catch (err) {
        console.error('[sentinel] /events error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
