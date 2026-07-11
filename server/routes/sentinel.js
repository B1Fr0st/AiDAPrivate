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

const CLONE_MIN_FEATURES = 3;

async function checkSentinelCloneDetection(licenseKey, ip, body) {
    const toolRegistry = body && body.tool_registry;
    if (!toolRegistry || typeof toolRegistry !== 'object' || !Array.isArray(toolRegistry.tool_names)) {
        return { ok: true };
    }

    const toolNames = toolRegistry.tool_names.filter(n => typeof n === 'string' && n.length > 0);
    if (toolNames.length < CLONE_MIN_FEATURES) return { ok: true };

    const sortedNames = [...toolNames].sort();
    const toolNamesHash = crypto.createHash('sha256').update(sortedNames.join('|'), 'utf8').digest('hex');
    const registrationOrderHash = crypto.createHash('sha256').update(toolNames.join('|'), 'utf8').digest('hex');

    let schemasHash = '';
    if (toolRegistry.param_schemas && typeof toolRegistry.param_schemas === 'object') {
        const canonical = JSON.stringify(toolRegistry.param_schemas, Object.keys(toolRegistry.param_schemas).sort());
        schemasHash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
    }

    const fingerprintHash = crypto.createHash('sha256')
        .update(toolNamesHash + schemasHash + registrationOrderHash, 'utf8')
        .digest('hex');

    const matchedFeatures = [
        toolNamesHash ? 1 : 0,
        schemasHash ? 1 : 0,
        registrationOrderHash ? 1 : 0,
    ].filter(x => x === 1).length;

    const now = Math.floor(Date.now() / 1000);
    const buildVersion = typeof toolRegistry.build_version === 'string' ? toolRegistry.build_version : '';
    let isKnownClone = false;

    try {
        const { rows: fpRows } = await pool.query(
            'SELECT * FROM protocol_fingerprints WHERE fingerprint_hash = $1',
            [fingerprintHash]
        );
        if (fpRows.length > 0) {
            isKnownClone = !!fpRows[0].is_known_clone;
            await pool.query(
                'UPDATE protocol_fingerprints SET last_seen_at = $1 WHERE fingerprint_hash = $2',
                [now, fingerprintHash]
            );
        } else {
            await pool.query(
                `INSERT INTO protocol_fingerprints (fingerprint_hash, tool_names_hash, tool_schemas_hash, registration_order_hash, build_version, tool_count, tool_names, first_seen_at, last_seen_at, is_known_clone)
                 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, false)
                 ON CONFLICT DO NOTHING`,
                [fingerprintHash, toolNamesHash, schemasHash, registrationOrderHash, buildVersion, toolNames.length, JSON.stringify(toolNames), now, now]
            );
        }
    } catch (err) {
        if (err && err.code === '42P01') return { ok: true };
        console.warn('[sentinel] protocol fingerprint check failed:', err && err.message ? err.message : err);
        return { ok: true };
    }

    if (isKnownClone) {
        await recordSentinelEvent(licenseKey, '', 'known_clone_fingerprint', 'critical',
            { fingerprint_hash: fingerprintHash, tool_count: toolNames.length, ip }, ip, undefined, undefined, 0);
        return { ok: false, reason: 'known_clone_fingerprint', kill: true };
    }

    let hasValidLicense = false;
    if (licenseKey) {
        try {
            const { rows: licRows } = await pool.query(
                'SELECT active FROM licenses WHERE key = $1 AND active = true',
                [licenseKey]
            );
            hasValidLicense = licRows.length > 0;
        } catch (_) { }
    }

    if (!hasValidLicense && matchedFeatures >= CLONE_MIN_FEATURES) {
        try {
            await pool.query(
                `INSERT INTO clone_detection_log (source_ip, license_key, tool_names_hash, registration_order_hash, matched_known_build, has_valid_license, has_valid_session, detected_at, evidence)
                 VALUES ($1, $2, $3, $4, $5, false, false, $6, $7::jsonb)`,
                [ip || '', licenseKey || '', toolNamesHash, registrationOrderHash, true, now,
                 JSON.stringify({ fingerprint_hash: fingerprintHash, tool_count: toolNames.length, build_version: buildVersion, matched_features: matchedFeatures })]
            );
            const normalizedIp = (ip || '').replace(/[.:]/g, '_');
            if (normalizedIp) {
                await pool.query(
                    `INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, ip, original_ip, banned_by)
                     VALUES ('ip', $1, 'clone_detection_no_license', $2, $3, 'unknown', $4, $4, 'system')
                     ON CONFLICT (ban_type, value) DO UPDATE SET reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at`,
                    [normalizedIp, now, new Date().toISOString(), ip || '']
                );
            }
        } catch (err) {
            if (err && err.code === '42P01') return { ok: true };
            console.warn('[sentinel] clone detection log failed:', err && err.message ? err.message : err);
        }
        await recordSentinelEvent(licenseKey, '', 'clone_detected_no_license', 'critical',
            { fingerprint_hash: fingerprintHash, tool_count: toolNames.length, ip, matched_features: matchedFeatures }, ip, undefined, undefined, 0);
        return { ok: false, reason: 'clone_detected_no_license', block_ip: true };
    }

    return { ok: true };
}

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
const REASON_SELF_ANALYSIS_ATTEMPT = 0xAE40;
const SELF_ANALYSIS_EVENT_TYPE = 'self_analysis_attempt';

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

async function recordSelfAnalysisAttempt(licenseKey, quorumId, eventPayload, ip) {
    const hwidHash = typeof eventPayload.hwid_hash === 'string' ? eventPayload.hwid_hash.slice(0, 64) : '';
    const licenseKeyHashInput = typeof eventPayload.license_key_hash === 'string' ? eventPayload.license_key_hash.trim().toLowerCase() : '';
    const licenseKeyHash = licenseKeyHashInput && /^[0-9a-f]{64}$/.test(licenseKeyHashInput)
        ? licenseKeyHashInput
        : (licenseKey ? crypto.createHash('sha256').update(licenseKey).digest('hex') : null);
    const toolName = typeof eventPayload.tool_name === 'string' ? eventPayload.tool_name.slice(0, 128) : null;
    const detectionType = typeof eventPayload.detection_type === 'number' && Number.isFinite(eventPayload.detection_type)
        ? Math.floor(eventPayload.detection_type) : 0;
    const targetPid = typeof eventPayload.target_pid === 'number' && Number.isFinite(eventPayload.target_pid)
        ? Math.floor(eventPayload.target_pid) : null;
    const targetAddress = typeof eventPayload.target_address === 'number' && Number.isFinite(eventPayload.target_address)
        ? Math.floor(eventPayload.target_address) : null;

    if (!hwidHash) return;

    try {
        await pool.query(
            `INSERT INTO self_analysis_attempts (hwid_hash, license_key_hash, tool_name, detection_type, target_pid, target_address)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [hwidHash, licenseKeyHash, toolName, detectionType, targetPid, targetAddress]
        );
    } catch (err) {
        console.warn('[sentinel] self_analysis_attempt persist failed:', err && err.message ? err.message : err);
    }

    if (licenseKey) {
        try {
            const now = Math.floor(Date.now() / 1000);
            await pool.query(
                `UPDATE licenses
                    SET flagged = true,
                        flagged_reason = $1,
                        flagged_at = $2,
                        flagged_score = 1.0
                  WHERE key = $3`,
                [`self_analysis_attempt:tool=${toolName || 'unknown'}:type=${detectionType}`, now, licenseKey]
            );
            await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [licenseKey]);
        } catch (err) {
            console.warn('[sentinel] self_analysis_attempt license flag failed:', err && err.message ? err.message : err);
        }
    }

    await sendDiscordWebhook('AiDA Self-Analysis Attempt Detected', [
        { name: 'Tool', value: toolName || 'unknown' },
        { name: 'Detection Type', value: String(detectionType) },
        { name: 'HWID', value: `\`${hwidHash.slice(0, 32)}...\`` },
        { name: 'License', value: licenseKey ? `\`${licenseKey}\`` : 'unknown' },
        { name: 'IP', value: `\`${ip || 'unknown'}\`` },
        { name: 'Target PID', value: targetPid !== null ? String(targetPid) : 'n/a' },
        { name: 'Target Address', value: targetAddress !== null ? `0x${targetAddress.toString(16)}` : 'n/a' },
    ], 0xFF0044);
}

async function getSelfAnalysisBlocklist() {
    try {
        const now = Math.floor(Date.now() / 1000);
        const { rows } = await pool.query(
            `SELECT image_hash, watermark, name_pattern, flags, blocklist_epoch, expires_at
               FROM self_analysis_blocklist
              WHERE active = true
                AND (expires_at = 0 OR expires_at > $1)
              ORDER BY blocklist_epoch DESC, id ASC
              LIMIT 64`,
            [now]
        );
        if (rows.length === 0) return null;
        const maxEpoch = rows.reduce((mx, r) => Math.max(mx, Number(r.blocklist_epoch || 0)), 0);
        const entries = rows.map(r => ({
            image_hash: String(r.image_hash || ''),
            watermark: String(r.watermark || ''),
            name_pattern: String(r.name_pattern || ''),
            flags: Number(r.flags || 0),
            expires_at: Number(r.expires_at || 0),
        }));
        return { blocklist_epoch: maxEpoch, entries };
    } catch (err) {
        console.warn('[sentinel] blocklist query failed:', err && err.message ? err.message : err);
        return null;
    }
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

const INTEGRITY_ATTEST_NONCE_TTL_MS = 10 * 60 * 1000;
const INTEGRITY_ATTEST_TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;
const KNOWN_INTEGRITY_NONCES = new Map();

async function getBuildTextHash(buildId) {
    if (!buildId || typeof buildId !== 'string') return null;
    try {
        const { rows } = await pool.query(
            'SELECT expected_text_sha256 FROM builds WHERE build_id = $1 AND (retired IS NULL OR retired = false)',
            [buildId]
        );
        if (rows.length > 0 && rows[0].expected_text_sha256) {
            return rows[0].expected_text_sha256;
        }
    } catch (err) {
        console.warn('[sentinel] getBuildTextHash failed:', err && err.message ? err.message : err);
    }
    return null;
}

async function storeIntegrityAttestation(hwidHash, nonce, usermodeCodeHash, buildId, timestamp) {
    try {
        await pool.query(
            `INSERT INTO attestation_records
                (hwid_hash, nonce, usermode_code_hash, build_id, timestamp, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [hwidHash, nonce, usermodeCodeHash, buildId, timestamp]
        );
    } catch (err) {
        console.warn('[sentinel] storeIntegrityAttestation failed:', err && err.message ? err.message : err);
    }
}

router.post('/integrity-attest', async (req, res) => {
    try {
        const body = req.body || {};
        const {
            nonce,
            usermode_code_hash,
            timestamp,
            hardware_id,
            build_id,
            hmac,
        } = body;

        if (!nonce || typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_nonce' });
        }
        if (!usermode_code_hash || typeof usermode_code_hash !== 'string' || !/^[0-9a-f]{64}$/.test(usermode_code_hash)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_usermode_code_hash' });
        }
        if (typeof timestamp !== 'number' && typeof timestamp !== 'string') {
            return res.status(400).json({ status: 'error', reason: 'invalid_timestamp' });
        }
        if (!hardware_id || typeof hardware_id !== 'string' || !/^[0-9a-f]{64}$/.test(hardware_id)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_hardware_id' });
        }
        if (!build_id || typeof build_id !== 'string' || !/^[0-9a-f]{32}$/.test(build_id)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_build_id' });
        }
        if (!hmac || typeof hmac !== 'string' || !/^[0-9a-f]{64}$/.test(hmac)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_hmac' });
        }

        const { rows: licRows } = await pool.query(
            'SELECT key, active, witness_key_wrapped FROM licenses WHERE hardware_id_sha256 = $1',
            [hardware_id]
        );
        if (licRows.length === 0) {
            return res.status(403).json({ status: 'error', reason: 'license_not_found' });
        }
        const lic = licRows[0];
        if (!lic.active) {
            return res.status(403).json({ status: 'error', reason: 'license_inactive' });
        }

        let witnessKey;
        try {
            witnessKey = kw.unwrap(lic.witness_key_wrapped, 'kw/v1');
        } catch (err) {
            console.error('[sentinel] integrity-attest witness key unwrap failed:', err.message);
            return res.status(500).json({ status: 'error', reason: 'witness_key_unwrap_failed' });
        }

        const tsVal = typeof timestamp === 'string' ? timestamp : String(timestamp);
        const tsBigInt = BigInt(tsVal);
        const WINDOWS_EPOCH_DIFF_MS = 11644473600000;
        const tsMs = Math.floor(Number(tsBigInt / 10000n) - BigInt(WINDOWS_EPOCH_DIFF_MS));
        const hmacInput = Buffer.concat([
            Buffer.from(nonce, 'hex'),
            Buffer.from(usermode_code_hash, 'hex'),
            Buffer.from(new BigInt64Array([tsBigInt]).buffer),
            Buffer.from(hardware_id, 'hex'),
            Buffer.from(build_id, 'hex'),
        ]);
        const expectedHmac = crypto.createHmac('sha256', witnessKey)
            .update(hmacInput)
            .digest('hex');

        const hmacA = Buffer.from(expectedHmac, 'hex');
        const hmacB = Buffer.from(hmac, 'hex');
        if (hmacA.length !== hmacB.length || !crypto.timingSafeEqual(hmacA, hmacB)) {
            await recordSentinelEvent(lic.key, '', 'integrity_attest_hmac_fail', 'critical',
                { hardware_id, build_id }, clientIp(req), undefined, undefined, 0);
            return res.status(403).json({ status: 'error', reason: 'attestation_hmac_invalid' });
        }

        const nonceKey = `${hardware_id}:${nonce}`;
        const now = Date.now();
        if (KNOWN_INTEGRITY_NONCES.has(nonceKey)) {
            await recordSentinelEvent(lic.key, '', 'integrity_attest_nonce_replay', 'critical',
                { nonce, hardware_id }, clientIp(req), undefined, undefined, 0);
            return res.status(409).json({ status: 'error', reason: 'nonce_replay' });
        }
        KNOWN_INTEGRITY_NONCES.set(nonceKey, now);
        for (const [k, ts] of KNOWN_INTEGRITY_NONCES) {
            if (now - ts > INTEGRITY_ATTEST_NONCE_TTL_MS) KNOWN_INTEGRITY_NONCES.delete(k);
        }

        if (Math.abs(now - tsMs) > INTEGRITY_ATTEST_TIMESTAMP_WINDOW_MS) {
            await recordSentinelEvent(lic.key, '', 'integrity_attest_timestamp_stale', 'warn',
                { timestamp: tsMs, server_now: now }, clientIp(req), undefined, undefined, 0);
            return res.status(409).json({ status: 'error', reason: 'timestamp_stale' });
        }

        const expectedHash = await getBuildTextHash(build_id);
        if (!expectedHash) {
            await recordSentinelEvent(lic.key, '', 'integrity_attest_unknown_build', 'warn',
                { build_id }, clientIp(req), undefined, undefined, 0);
            return res.status(400).json({ status: 'error', reason: 'unknown_build_version' });
        }

        if (usermode_code_hash !== expectedHash) {
            await recordSentinelEvent(lic.key, '', 'integrity_violation', 'critical',
                { expected: expectedHash, observed: usermode_code_hash, build_id, hardware_id },
                clientIp(req), undefined, undefined, 0);
            try {
                await pool.query(
                    'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
                    [lic.key]
                );
            } catch (_) {}
            try {
                await pool.query(
                    'UPDATE licenses SET active = false WHERE key = $1',
                    [lic.key]
                );
            } catch (_) {}
            return res.status(403).json({ status: 'error', reason: 'integrity_violation' });
        }

        await storeIntegrityAttestation(hardware_id, nonce, usermode_code_hash, build_id, tsMs);

        await recordSentinelEvent(lic.key, '', 'integrity_attest_ok', 'info',
            { build_id, hardware_id }, clientIp(req), undefined, undefined, 0);

        return res.json(canonicalResponse.buildEnvelope({
            status: 'ok',
            verified_at: Math.floor(now / 1000),
            build_id,
        }));
    } catch (err) {
        console.error('[sentinel] /integrity-attest error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

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

        const cloneCheck = await checkSentinelCloneDetection(license_key, ip, req.body || {});
        if (!cloneCheck.ok) {
            if (cloneCheck.kill) {
                await pool.query('UPDATE sessions SET kill_flag = true WHERE license_key = $1', [license_key]);
                return res.status(403).json({ status: 'error', reason: cloneCheck.reason || 'clone_detected' });
            }
            return res.status(403).json({ status: 'error', reason: cloneCheck.reason || 'clone_detected' });
        }

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

            const evReason = typeof ev.reason === 'number' ? ev.reason : (ev.payload && typeof ev.payload.reason === 'number' ? ev.payload.reason : null);
            const isSelfAnalysis = type === SELF_ANALYSIS_EVENT_TYPE
                || evReason === REASON_SELF_ANALYSIS_ATTEMPT
                || (ev.payload && ev.payload.self_analysis === true);
            if (isSelfAnalysis) {
                await recordSelfAnalysisAttempt(license_key, quorum_id, ev.payload || {}, ip);
            }
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

        const blocklist = await getSelfAnalysisBlocklist();
        if (blocklist) {
            response.blocklist = blocklist;
        }

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


const VALID_DMA_ATTACK_TYPES = new Set([
    'iommu_bypass', 'unknown_pcie', 'ept_hook', 'pte_tamper', 'canary_hit',
]);

router.post('/dma-report', async (req, res) => {
    try {
        const body = req.body || {};
        const licenseKey = req.aidaSession ? req.aidaSession.license_key : '';
        const sessionHwid = req.aidaSession ? req.aidaSession.hwid : '';

        if (!licenseKey) {
            return res.status(403).json({ status: 'error', reason: 'auth_required' });
        }

        const hwid = typeof body.hwid === 'string' ? body.hwid.trim() : (sessionHwid || '');
        if (!hwid || hwid.length > 128) {
            return res.status(400).json({ status: 'error', reason: 'invalid_hwid' });
        }

        const attackType = typeof body.attack_type === 'string' ? body.attack_type.trim().toLowerCase() : '';
        if (!VALID_DMA_ATTACK_TYPES.has(attackType)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_attack_type' });
        }

        const detectionType = typeof body.detection_type === 'number' && Number.isFinite(body.detection_type)
            ? Math.floor(body.detection_type) : 0;
        if (detectionType < 0 || detectionType > 65535) {
            return res.status(400).json({ status: 'error', reason: 'invalid_detection_type' });
        }

        const tier = typeof body.tier === 'number' && Number.isFinite(body.tier)
            ? Math.floor(body.tier) : 0;
        if (tier < 0 || tier > 2) {
            return res.status(400).json({ status: 'error', reason: 'invalid_tier' });
        }

        const evidenceHash = typeof body.evidence_hash === 'number' && Number.isFinite(body.evidence_hash)
            ? Math.floor(body.evidence_hash) : null;

        const licenseKeyHashInput = typeof body.license_key_hash === 'string' ? body.license_key_hash.trim().toLowerCase() : '';
        const licenseKeyHash = licenseKeyHashInput && /^[0-9a-f]{64}$/.test(licenseKeyHashInput)
            ? licenseKeyHashInput
            : crypto.createHash('sha256').update(licenseKey).digest('hex');

        const ip = clientIp(req);

        await pool.query(
            `INSERT INTO dma_attack_log (hwid_hash, license_key_hash, attack_type, detection_type, tier, evidence_hash)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [hwid.slice(0, 64), licenseKeyHash, attackType, detectionType, tier, evidenceHash]
        );

        const shouldFlag = (attackType === 'canary_hit' && tier === 2) || tier === 2;

        if (shouldFlag) {
            const now = Math.floor(Date.now() / 1000);
            await pool.query(
                `UPDATE licenses
                    SET flagged = true,
                        flagged_reason = $1,
                        flagged_at = $2,
                        flagged_score = 1.0
                  WHERE key = $3`,
                [`dma_attack:${attackType}:tier${tier}`, now, licenseKey]
            );
            await pool.query(
                'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
                [licenseKey]
            );
            await sendDiscordWebhook('AiDA DMA Attack Detected', [
                { name: 'Attack Type', value: attackType },
                { name: 'Tier', value: String(tier) },
                { name: 'Detection', value: String(detectionType) },
                { name: 'License', value: `\`${licenseKey}\`` },
                { name: 'HWID', value: `\`${hwid.slice(0, 32)}...\`` },
                { name: 'IP', value: `\`${ip}\`` },
                { name: 'Evidence Hash', value: evidenceHash !== null ? `0x${evidenceHash.toString(16)}` : 'none' },
            ], 0xFF0066);
        }

        return res.json(canonicalResponse.buildEnvelope({
            status: 'ok',
            logged: true,
            flagged: shouldFlag,
        }));
    } catch (err) {
        console.error('[sentinel] /dma-report error:', err);
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
