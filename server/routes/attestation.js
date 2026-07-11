'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const { signPayload } = require('../crypto/signing');
const canonicalResponse = require('../crypto/canonical_response');

const router = express.Router();

const NONCE_TTL_SECONDS = 30;
const PROOF_REPLAY_WINDOW = 600;
const MAX_HISTORY_RECORDS = 256;
const REVOCATION_TRIP_COUNT = 3;
const KNOWN_ATTEST_NONCES = new Map();
const TEMPLATE_GRACE_PERIOD_SEC = 2592000;

async function checkAttestationTemplateVersion(licenseKey, body) {
    const clientTemplateVersion = typeof body.template_version === 'string' ? body.template_version.trim() : '';
    if (!clientTemplateVersion) return { ok: true };

    let activeTemplate = null;
    try {
        const { rows } = await pool.query(
            'SELECT version, uploaded_at FROM build_templates WHERE is_active = true LIMIT 1'
        );
        if (rows.length > 0) activeTemplate = rows[0];
    } catch (err) {
        if (err && err.code === '42P01') return { ok: true };
        return { ok: true };
    }

    if (!activeTemplate) return { ok: true };

    const activeVersion = String(activeTemplate.version || '').trim();
    if (!activeVersion || activeVersion === clientTemplateVersion) return { ok: true };

    const uploadedAt = Number(activeTemplate.uploaded_at || 0);
    const now = Math.floor(Date.now() / 1000);
    const ageSec = uploadedAt > 0 ? (now - uploadedAt) : 0;

    if (ageSec < TEMPLATE_GRACE_PERIOD_SEC) {
        return { ok: true, logging: { template_old: true, client_version: clientTemplateVersion, active_version: activeVersion, age_sec: ageSec } };
    }

    return { ok: false, reason: 'template_update_required', client_version: clientTemplateVersion, active_version: activeVersion, age_sec: ageSec };
}

const PCR_LENGTH_HEX = 64;
const TIMESTAMP_FRESHNESS_SECONDS = 300;
const BUILD_ID_HEX_LENGTH = 32;
const USERMODE_CODE_HASH_HEX_LENGTH = 64;

const ATTESTATION_HMAC_LABEL = 'aida/attest/v1';
const ATTESTATION_HMAC_SECRET = process.env.ATTESTATION_HMAC_SECRET
    || process.env.ARC_MASTER_SECRET
    || '';

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function isHexString(value, length) {
    return typeof value === 'string'
        && (length == null || value.length === length)
        && /^[a-fA-F0-9]+$/.test(value);
}

function timingSafeHexCompare(aHex, bHex) {
    if (typeof aHex !== 'string' || typeof bHex !== 'string') return false;
    if (aHex.length !== bHex.length) return false;
    const a = Buffer.from(aHex, 'utf8');
    const b = Buffer.from(bHex, 'utf8');
    return crypto.timingSafeEqual(a, b);
}

function generateNonce() {
    return crypto.randomBytes(32).toString('hex');
}

function hmacAttest(content) {
    if (!ATTESTATION_HMAC_SECRET) return '';
    return crypto.createHmac('sha256', ATTESTATION_HMAC_SECRET)
        .update(`${ATTESTATION_HMAC_LABEL}|${content}`)
        .digest('hex');
}

function pruneHistoryArray(arr) {
    if (!Array.isArray(arr)) return [];
    if (arr.length > MAX_HISTORY_RECORDS) {
        return arr.slice(arr.length - MAX_HISTORY_RECORDS);
    }
    return arr;
}

function createTablesIfNeeded() {
    return pool.query(`
        CREATE TABLE IF NOT EXISTS attestation_state (
            license_key       TEXT      PRIMARY KEY,
            counter_max       BIGINT    NOT NULL DEFAULT 0,
            last_pcr16        TEXT      NOT NULL DEFAULT '',
            last_code_hash    TEXT      NOT NULL DEFAULT '',
            last_qpc          BIGINT    NOT NULL DEFAULT 0,
            anomaly_count     INTEGER   NOT NULL DEFAULT 0,
            history           JSONB     NOT NULL DEFAULT '[]'::jsonb,
            updated_at        BIGINT    NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS attestation_nonces (
            nonce_hex         TEXT      PRIMARY KEY,
            license_key       TEXT      NOT NULL,
            issued_at         BIGINT    NOT NULL,
            expires_at        BIGINT    NOT NULL,
            consumed          BOOLEAN   NOT NULL DEFAULT false
        );
        CREATE INDEX IF NOT EXISTS idx_attest_nonces_lic ON attestation_nonces (license_key);
        CREATE INDEX IF NOT EXISTS idx_attest_nonces_expires ON attestation_nonces (expires_at);
        CREATE TABLE IF NOT EXISTS dma_state_log (
            hwid_hash         VARCHAR(64) PRIMARY KEY,
            license_key       TEXT,
            dma_state_hex     TEXT        NOT NULL DEFAULT '',
            tier1_refused     BOOLEAN     NOT NULL DEFAULT false,
            tier2_bsod_armed  BOOLEAN     NOT NULL DEFAULT false,
            canary_count      INTEGER     NOT NULL DEFAULT 0,
            canary_hits       INTEGER     NOT NULL DEFAULT 0,
            pcie_unknown      INTEGER     NOT NULL DEFAULT 0,
            ept_anomaly       BOOLEAN     NOT NULL DEFAULT false,
            updated_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_dma_state_hwid ON dma_state_log(hwid_hash);
        CREATE TABLE IF NOT EXISTS attestation_records (
            id                  SERIAL      PRIMARY KEY,
            hwid_hash           VARCHAR(64) NOT NULL,
            nonce               VARCHAR(64) NOT NULL,
            usermode_code_hash  VARCHAR(64) NOT NULL,
            build_id            VARCHAR(32) NOT NULL,
            timestamp           BIGINT      NOT NULL,
            created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_attest_records_hwid ON attestation_records(hwid_hash);
        CREATE INDEX IF NOT EXISTS idx_attest_records_nonce ON attestation_records(nonce);
        CREATE INDEX IF NOT EXISTS idx_attest_records_build ON attestation_records(build_id);
        CREATE TABLE IF NOT EXISTS builds (
            build_id            VARCHAR(32) PRIMARY KEY,
            expected_text_sha256 VARCHAR(64) NOT NULL,
            retired             BOOLEAN     NOT NULL DEFAULT false,
            created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    `);
}

createTablesIfNeeded().catch(() => {});

async function getStateRow(licenseKey) {
    const { rows } = await pool.query(
        'SELECT * FROM attestation_state WHERE license_key = $1',
        [licenseKey]
    );
    return rows[0] || null;
}

async function ensureStateRow(licenseKey) {
    const now = Math.floor(Date.now() / 1000);
    await pool.query(
        `INSERT INTO attestation_state (license_key, updated_at)
         VALUES ($1, $2)
         ON CONFLICT (license_key) DO NOTHING`,
        [licenseKey, now]
    );
}

async function purgeExpiredNonces() {
    const now = Math.floor(Date.now() / 1000);
    await pool.query('DELETE FROM attestation_nonces WHERE expires_at < $1', [now - 60]);
}

async function trackAnomaly(licenseKey, reason, details, currentRow) {
    const now = Math.floor(Date.now() / 1000);
    const history = pruneHistoryArray(currentRow ? currentRow.history : []);
    history.push({ at: now, reason, details: details || {} });

    const newAnomalyCount = (currentRow ? currentRow.anomaly_count : 0) + 1;
    const shouldRevoke = newAnomalyCount >= REVOCATION_TRIP_COUNT;

    await pool.query(
        `UPDATE attestation_state
         SET anomaly_count = $1, history = $2::jsonb, updated_at = $3
         WHERE license_key = $4`,
        [newAnomalyCount, JSON.stringify(history), now, licenseKey]
    );

    if (shouldRevoke) {
        await pool.query(
            'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
            [licenseKey]
        );
        await pool.query(
            'UPDATE licenses SET active = false WHERE key = $1',
            [licenseKey]
        );
    }
    return shouldRevoke;
}

async function getBuildExpectedHash(buildId) {
    if (!buildId || typeof buildId !== 'string') return null;
    try {
        const { rows } = await pool.query(
            'SELECT expected_text_sha256, retired FROM builds WHERE build_id = $1',
            [buildId]
        );
        if (rows.length === 0) return null;
        const row = rows[0];
        const hash = typeof row.expected_text_sha256 === 'string'
            ? row.expected_text_sha256.trim().toLowerCase() : '';
        if (!/^[0-9a-f]{64}$/.test(hash)) return null;
        return { hash, retired: !!row.retired };
    } catch (err) {
        console.warn('[attestation] getBuildExpectedHash failed:',
            err && err.message ? err.message : err);
        return null;
    }
}

async function killSessionForViolation(licenseKey, reason) {
    if (!licenseKey) return;
    try {
        const nowSec = Math.floor(Date.now() / 1000);
        await pool.query(
            'UPDATE sessions SET kill_flag = true, force_violation = true WHERE license_key = $1',
            [licenseKey]
        );
        await pool.query(
            'UPDATE licenses SET active = false, revoked_reason = $1, revoked_at = $2 WHERE key = $3',
            [reason, nowSec, licenseKey]
        );
    } catch (err) {
        console.warn('[attestation] killSessionForViolation failed:',
            err && err.message ? err.message : err);
    }
}

router.post('/nonce', async (req, res) => {
    try {
        const { license_key } = req.body || {};
        if (typeof license_key !== 'string' || license_key.length < 4 || license_key.length > 128) {
            return res.status(400).json({ status: 'error', reason: 'invalid_license' });
        }

        const { rows: licRows } = await pool.query(
            'SELECT key, active FROM licenses WHERE key = $1',
            [license_key]
        );
        if (licRows.length === 0 || !licRows[0].active) {
            return res.status(401).json({ status: 'error', reason: 'license_invalid' });
        }

        await ensureStateRow(license_key);
        await purgeExpiredNonces();

        const nonce = generateNonce();
        const issuedAt = Math.floor(Date.now() / 1000);
        const expiresAt = issuedAt + NONCE_TTL_SECONDS;

        await pool.query(
            `INSERT INTO attestation_nonces (nonce_hex, license_key, issued_at, expires_at, consumed)
             VALUES ($1, $2, $3, $4, false)`,
            [nonce, license_key, issuedAt, expiresAt]
        );

        return res.json(canonicalResponse.buildEnvelope({
            status: 'ok',
            nonce,
            expires_at: expiresAt,
            ttl: NONCE_TTL_SECONDS,
            label: ATTESTATION_HMAC_LABEL,
        }));
    } catch (err) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

async function processDmaState(licenseKey, hwid, dmaStateHex) {
    if (!dmaStateHex || typeof dmaStateHex !== 'string') return null;
    const cleaned = dmaStateHex.trim().toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(cleaned)) return null;
    const bytes = Buffer.from(cleaned, 'hex');
    if (bytes.length < 8) return null;

    const tier1Refused = bytes[0] !== 0;
    const tier2BsodArmed = bytes[1] !== 0;
    const canaryCount = bytes[2];
    const canaryHits = bytes[3];
    const pcieUnknown = bytes[4];
    const eptAnomaly = bytes[5] !== 0;

    await pool.query(
        `INSERT INTO dma_state_log
            (hwid_hash, license_key, dma_state_hex, tier1_refused, tier2_bsod_armed,
             canary_count, canary_hits, pcie_unknown, ept_anomaly, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
         ON CONFLICT (hwid_hash) DO UPDATE SET
            license_key       = EXCLUDED.license_key,
            dma_state_hex     = EXCLUDED.dma_state_hex,
            tier1_refused     = EXCLUDED.tier1_refused,
            tier2_bsod_armed  = EXCLUDED.tier2_bsod_armed,
            canary_count      = EXCLUDED.canary_count,
            canary_hits       = EXCLUDED.canary_hits,
            pcie_unknown      = EXCLUDED.pcie_unknown,
            ept_anomaly       = EXCLUDED.ept_anomaly,
            updated_at        = NOW()`,
        [hwid.slice(0, 64), licenseKey, cleaned, tier1Refused, tier2BsodArmed,
         canaryCount, canaryHits, pcieUnknown, eptAnomaly]
    );

    const attackIndicated = canaryHits > 0 || eptAnomaly || pcieUnknown >= 2;
    const noBsodTriggered = !tier2BsodArmed;

    if (attackIndicated && noBsodTriggered) {
        const now = Math.floor(Date.now() / 1000);
        const reasonParts = [];
        if (canaryHits > 0) reasonParts.push(`canary_hits=${canaryHits}`);
        if (eptAnomaly) reasonParts.push('ept_anomaly');
        if (pcieUnknown >= 2) reasonParts.push(`pcie_unknown=${pcieUnknown}`);
        await pool.query(
            `UPDATE licenses
                SET flagged = true,
                    flagged_reason = $1,
                    flagged_at = $2,
                    flagged_score = 0.8
              WHERE key = $3`,
            [`dma_state_attestation:${reasonParts.join(':')}`, now, licenseKey]
        );
    }

    return { tier1Refused, tier2BsodArmed, canaryCount, canaryHits, pcieUnknown, eptAnomaly };
}

router.post('/verify', async (req, res) => {
    try {
        const body = req.body || {};
        const { license_key, nonce, code_hash, hwid, boot_state, proof_token } = body;
        const tpmCounter = body.tpm_monotonic_counter;
        const pcr16 = body.tpm_pcr16;
        const tpmQuote = body.tpm_attest_quote;
        const tpmSig = body.tpm_attest_signature;
        const qpcSequence = body.qpc_sequence;
        const dmaState = body.dma_state;
        const usermodeCodeHash = body.usermode_code_hash;
        const buildId = body.build_id;
        const clientTimestamp = body.timestamp;
        const clientAttestHmac = body.attest_hmac;

        if (typeof license_key !== 'string' || !isHexString(nonce, 64)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_request' });
        }
        if (!isHexString(code_hash) || code_hash.length < 16 || code_hash.length > 128) {
            return res.status(400).json({ status: 'error', reason: 'invalid_code_hash' });
        }
        if (typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 256) {
            return res.status(400).json({ status: 'error', reason: 'invalid_hwid' });
        }
        if (typeof boot_state !== 'string' || boot_state.length > 256) {
            return res.status(400).json({ status: 'error', reason: 'invalid_boot_state' });
        }
        if (!isHexString(proof_token) || proof_token.length < 16) {
            return res.status(400).json({ status: 'error', reason: 'invalid_proof_token' });
        }

        const { rows: licRows } = await pool.query(
            'SELECT key, active FROM licenses WHERE key = $1',
            [license_key]
        );
        if (licRows.length === 0 || !licRows[0].active) {
            return res.status(401).json({ status: 'error', reason: 'license_invalid' });
        }

        const templateResult = await checkAttestationTemplateVersion(license_key, body);
        if (!templateResult.ok) {
            return res.status(426).json({ status: 'error', reason: templateResult.reason || 'template_update_required' });
        }

        const { rows: nonceRows } = await pool.query(
            'SELECT * FROM attestation_nonces WHERE nonce_hex = $1 AND license_key = $2',
            [nonce, license_key]
        );
        if (nonceRows.length === 0) {
            return res.status(400).json({ status: 'error', reason: 'unknown_nonce' });
        }
        const nonceRow = nonceRows[0];
        const now = Math.floor(Date.now() / 1000);
        if (nonceRow.consumed) {
            await ensureStateRow(license_key);
            const stRow = await getStateRow(license_key);
            await trackAnomaly(license_key, 'replayed_nonce',
                { nonce_hex: nonce, age_seconds: now - nonceRow.issued_at }, stRow);
            return res.status(409).json({ status: 'error', reason: 'replayed_nonce' });
        }
        if (nonceRow.expires_at < now) {
            return res.status(410).json({ status: 'error', reason: 'nonce_expired' });
        }
        if (now - nonceRow.issued_at > NONCE_TTL_SECONDS) {
            return res.status(410).json({ status: 'error', reason: 'nonce_window_expired' });
        }

        await pool.query('UPDATE attestation_nonces SET consumed = true WHERE nonce_hex = $1', [nonce]);

        await ensureStateRow(license_key);
        const state = await getStateRow(license_key);

        const expectedHash = crypto.createHash('sha256');
        expectedHash.update(Buffer.from(nonce, 'hex'));
        expectedHash.update(Buffer.from(code_hash, 'hex'));
        expectedHash.update(Buffer.from(hwid, 'utf8'));
        expectedHash.update(Buffer.from(boot_state, 'utf8'));
        const expectedDigest = expectedHash.digest('hex');

        if (state.last_code_hash && state.last_code_hash !== code_hash) {
            await trackAnomaly(license_key, 'code_hash_drift',
                { previous: state.last_code_hash, observed: code_hash }, state);
        }

        if (typeof tpmCounter === 'number' && Number.isFinite(tpmCounter)) {
            const counterInt = Math.floor(tpmCounter);
            const stored = parseInt(state.counter_max, 10) || 0;
            if (counterInt < stored) {
                await trackAnomaly(license_key, 'tpm_counter_rollback',
                    { observed: counterInt, expected_min: stored + 1 }, state);
                return res.status(409).json({ status: 'error', reason: 'rollback_detected' });
            }
            await pool.query(
                `UPDATE attestation_state SET counter_max = $1, updated_at = $2 WHERE license_key = $3`,
                [Math.max(stored, counterInt), now, license_key]
            );
        }

        if (typeof pcr16 === 'string' && pcr16.length > 0) {
            if (!isHexString(pcr16, PCR_LENGTH_HEX)) {
                await trackAnomaly(license_key, 'pcr_invalid_format',
                    { length: pcr16.length }, state);
                return res.status(400).json({ status: 'error', reason: 'invalid_pcr16' });
            }
            if (state.last_pcr16 && state.last_pcr16 !== pcr16) {
                await trackAnomaly(license_key, 'pcr_drift',
                    { previous: state.last_pcr16, observed: pcr16 }, state);
            }
            await pool.query(
                `UPDATE attestation_state SET last_pcr16 = $1, updated_at = $2 WHERE license_key = $3`,
                [pcr16, now, license_key]
            );
        }

        if (typeof qpcSequence === 'number' && Number.isFinite(qpcSequence)) {
            const seqInt = Math.floor(qpcSequence);
            const stored = parseInt(state.last_qpc, 10) || 0;
            if (stored > 0 && seqInt < stored) {
                await trackAnomaly(license_key, 'qpc_drift',
                    { observed: seqInt, expected_min: stored }, state);
            }
            await pool.query(
                `UPDATE attestation_state SET last_qpc = $1, updated_at = $2 WHERE license_key = $3`,
                [Math.max(stored, seqInt), now, license_key]
            );
        }

        const proofKey = `${license_key}:${proof_token}`;
        if (KNOWN_ATTEST_NONCES.has(proofKey)) {
            await trackAnomaly(license_key, 'replayed_proof_token',
                { proof_token, nonce_hex: nonce }, state);
            return res.status(409).json({ status: 'error', reason: 'replayed_proof_token' });
        }
        KNOWN_ATTEST_NONCES.set(proofKey, now);
        for (const [k, ts] of KNOWN_ATTEST_NONCES) {
            if (now - ts > PROOF_REPLAY_WINDOW) KNOWN_ATTEST_NONCES.delete(k);
        }

        let buildValidationResult = null;

        if (typeof clientTimestamp !== 'undefined' && clientTimestamp !== null) {
            const tsValue = typeof clientTimestamp === 'number'
                ? clientTimestamp
                : parseInt(clientTimestamp, 10);
            if (!Number.isFinite(tsValue) || Math.abs(now - tsValue) > TIMESTAMP_FRESHNESS_SECONDS) {
                await trackAnomaly(license_key, 'timestamp_stale',
                    { server_time: now, client_time: tsValue }, state);
                return res.status(400).json({ status: 'error', reason: 'timestamp_stale' });
            }
        }

        if (typeof buildId === 'string' && buildId.length > 0) {
            if (!isHexString(buildId, BUILD_ID_HEX_LENGTH)) {
                return res.status(400).json({ status: 'error', reason: 'invalid_build_id' });
            }
            if (!isHexString(usermodeCodeHash, USERMODE_CODE_HASH_HEX_LENGTH)) {
                return res.status(400).json({ status: 'error', reason: 'invalid_usermode_code_hash' });
            }

            if (typeof clientAttestHmac === 'string' && clientAttestHmac.length > 0 && ATTESTATION_HMAC_SECRET) {
                const attestCanonical = `${license_key}|${nonce}|${usermodeCodeHash}|${buildId}|${hwid}|${clientTimestamp || ''}`;
                const expectedAttestHmac = hmacAttest(attestCanonical);
                if (!timingSafeHexCompare(expectedAttestHmac, clientAttestHmac)) {
                    await trackAnomaly(license_key, 'attestation_hmac_invalid',
                        { build_id: buildId }, state);
                    return res.status(401).json({ status: 'error', reason: 'attestation_hmac_invalid' });
                }
            }

            const buildInfo = await getBuildExpectedHash(buildId);
            if (!buildInfo) {
                await trackAnomaly(license_key, 'unknown_build_version',
                    { build_id: buildId }, state);
                return res.status(400).json({ status: 'error', reason: 'unknown_build_version' });
            }

            const usermodeHashNormalized = usermodeCodeHash.trim().toLowerCase();
            if (!timingSafeHexCompare(usermodeHashNormalized, buildInfo.hash)) {
                await trackAnomaly(license_key, 'integrity_violation',
                    { expected: buildInfo.hash, observed: usermodeHashNormalized, build_id: buildId }, state);
                await killSessionForViolation(license_key, 'integrity_violation');
                return res.status(403).json({ status: 'error', reason: 'integrity_violation' });
            }

            buildValidationResult = {
                build_id: buildId,
                verified: true,
                retired: buildInfo.retired,
            };

            const hwidHash = crypto.createHash('sha256')
                .update(String(hwid || ''), 'utf8')
                .digest('hex');
            const recordTimestamp = (typeof clientTimestamp === 'number' && Number.isFinite(clientTimestamp))
                ? Math.floor(clientTimestamp)
                : (typeof clientTimestamp === 'string' && /^[0-9]+$/.test(clientTimestamp)
                    ? parseInt(clientTimestamp, 10)
                    : now);

            await pool.query(
                `INSERT INTO attestation_records
                    (hwid_hash, nonce, usermode_code_hash, build_id, timestamp)
                 VALUES ($1, $2, $3, $4, $5)`,
                [hwidHash, nonce, usermodeHashNormalized, buildId, recordTimestamp]
            );
        }

        await pool.query(
            `UPDATE attestation_state SET last_code_hash = $1, updated_at = $2 WHERE license_key = $3`,
            [code_hash, now, license_key]
        );

        let dmaStateResult = null;
        if (typeof dmaState === 'string' && dmaState.length > 0) {
            try {
                dmaStateResult = await processDmaState(license_key, hwid, dmaState);
            } catch (dmaErr) {
                console.warn('[attestation] dma_state processing failed:', dmaErr && dmaErr.message ? dmaErr.message : dmaErr);
            }
        }

        const tpmQuoteAccepted = typeof tpmQuote === 'string'
            && tpmQuote.length >= 64
            && /^[a-fA-F0-9]+$/.test(tpmQuote)
            && typeof tpmSig === 'string'
            && tpmSig.length >= 32
            && /^[a-fA-F0-9]+$/.test(tpmSig);

        const responsePayload = {
            status: 'ok',
            license_key,
            nonce,
            verified_at: now,
            anomaly_count: state.anomaly_count,
            tpm_quote_accepted: tpmQuoteAccepted,
            digest: expectedDigest,
            hmac: hmacAttest(`${license_key}|${nonce}|${code_hash}|${expectedDigest}`),
            dma_state_recorded: dmaStateResult !== null,
            dma_attack_flagged: dmaStateResult !== null && (dmaStateResult.canaryHits > 0 || dmaStateResult.eptAnomaly || dmaStateResult.pcieUnknown >= 2) && !dmaStateResult.tier2BsodArmed,
            build_validation: buildValidationResult,
        };

        return res.json(canonicalResponse.buildEnvelope(responsePayload));
    } catch (err) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/anti-rollback/check', async (req, res) => {
    try {
        const { license_key, counter_value } = req.body || {};
        if (typeof license_key !== 'string') {
            return res.status(400).json({ status: 'error', reason: 'invalid_license' });
        }
        if (typeof counter_value !== 'number' || !Number.isFinite(counter_value)) {
            return res.status(400).json({ status: 'error', reason: 'invalid_counter' });
        }
        await ensureStateRow(license_key);
        const state = await getStateRow(license_key);
        const counterInt = Math.floor(counter_value);
        const stored = parseInt(state.counter_max, 10) || 0;
        if (counterInt < stored) {
            return res.status(409).json({
                status: 'error',
                reason: 'rollback_detected',
                expected_min: stored + 1,
                observed: counterInt,
            });
        }
        return res.json(canonicalResponse.buildEnvelope({
            status: 'ok',
            counter_max: stored,
            advanced: counterInt > stored,
        }));
    } catch (_e) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.get('/state/:license_key', async (req, res) => {
    try {
        const licenseKey = req.params.license_key;
        if (typeof licenseKey !== 'string' || licenseKey.length < 4) {
            return res.status(400).json({ status: 'error', reason: 'invalid_license' });
        }
        const row = await getStateRow(licenseKey);
        if (!row) return res.status(404).json({ status: 'error', reason: 'not_found' });
        return res.json(canonicalResponse.buildEnvelope({
            status: 'ok',
            license_key: licenseKey,
            counter_max: row.counter_max,
            last_pcr16: row.last_pcr16,
            last_code_hash: row.last_code_hash,
            anomaly_count: row.anomaly_count,
            history: pruneHistoryArray(row.history),
            updated_at: row.updated_at,
        }));
    } catch (_e) {
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = router;
