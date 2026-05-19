'use strict';

const pool = require('../db/pool');
const columnCrypt = require('../crypto/column_crypt');
const auditLog = require('./audit_log');
const keyFormat = require('../crypto/key_format');

const REQ_TIME_WINDOW_MS = keyFormat.REQ_TIME_WINDOW_MS;
const REQ_SEQ_SKIP_THRESHOLD = keyFormat.REQ_SEQ_SKIP_THRESHOLD;

function normalizeReqSeq(value) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && Math.floor(value) === value) {
        return BigInt(value);
    }
    if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
        try { return BigInt(value); } catch (_) { return null; }
    }
    return null;
}

function decryptSessionTokenCol(row) {
    if (!row) return row;
    const uuid = typeof row.session_uuid === 'string' ? row.session_uuid : '';
    if (!uuid) return row;
    if (typeof row.session_token === 'string' && columnCrypt.isCiphertext(row.session_token)) {
        try {
            row.session_token = columnCrypt.decrypt(uuid, 'sessions/session_token', row.session_token);
        } catch (err) {
            row.session_token = '';
        }
    }
    return row;
}

async function loadSessionRow(licenseKey) {
    if (!licenseKey || typeof licenseKey !== 'string') return null;
    const { rows } = await pool.query(
        'SELECT license_key, session_token, session_uuid, last_req_seq, kill_flag, hwid FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (rows.length === 0) return null;
    return decryptSessionTokenCol(rows[0]);
}

async function recordSessionAuditEvent(licenseKey, sessionToken, kind) {
    if (!licenseKey || !kind) return;
    try {
        await pool.query(
            'INSERT INTO session_audit_recent (license_key, session_token, event_kind, occurred_at) VALUES ($1,$2,$3,$4)',
            [licenseKey, sessionToken || '', kind, Math.floor(Date.now() / 1000)]
        );
    } catch (_) { }
}

async function purgeStaleAuditEvents() {
    try {
        const cutoff = Math.floor(Date.now() / 1000) - 600;
        await pool.query('DELETE FROM session_audit_recent WHERE occurred_at < $1', [cutoff]);
    } catch (_) { }
}

async function maybeBanFromAuditBurst(licenseKey, sessionToken) {
    if (!licenseKey) return false;
    try {
        const since = Math.floor(Date.now() / 1000) - 60;
        const { rows } = await pool.query(
            `SELECT COUNT(*)::int AS cnt FROM session_audit_recent
              WHERE license_key = $1
                AND occurred_at >= $2
                AND event_kind IN ('replay_blocked', 'signature_invalid', 'hwid_mismatch')`,
            [licenseKey, since]
        );
        const cnt = rows.length > 0 ? Number(rows[0].cnt) : 0;
        if (cnt >= 5) {
            await pool.query(
                "UPDATE licenses SET active = false, flagged = true, flagged_reason = 'audit_burst_kill_switch', flagged_at = $2 WHERE key = $1",
                [licenseKey, Math.floor(Date.now() / 1000)]
            );
            await pool.query(
                'UPDATE sessions SET kill_flag = true, force_violation = true WHERE license_key = $1',
                [licenseKey]
            );
            await auditLog.logServerEvent('license.kill_switch_triggered', licenseKey, {
                reason: 'audit_burst_5_in_60s',
                session_token_prefix: (sessionToken || '').slice(0, 16),
                burst_count: cnt,
            });
            return true;
        }
    } catch (_) { }
    return false;
}

async function recordAuditEvent(eventKind, licenseKey, sessionToken, details) {
    await recordSessionAuditEvent(licenseKey, sessionToken, eventKind);
    await auditLog.appendAuditEntry({
        action: 'session.' + eventKind,
        target: licenseKey || '',
        details: Object.assign({
            session_token_prefix: (sessionToken || '').slice(0, 16),
        }, details || {}),
    });
    purgeStaleAuditEvents().catch(() => {});
    await maybeBanFromAuditBurst(licenseKey, sessionToken);
}

async function checkAndAdvance(body, options) {
    const opts = options || {};
    const required = opts.required !== false;
    const licenseKey = (body && typeof body.license_key === 'string') ? body.license_key.trim() : '';
    const sessionToken = (body && typeof body.session_token === 'string') ? body.session_token.trim() : '';
    const candidateSeq = normalizeReqSeq(body ? body.req_seq : null);

    if (!licenseKey) {
        if (!required) return { ok: true, skipped: true };
        return { ok: false, status: 400, reason: 'replay_license_missing' };
    }

    if (candidateSeq === null) {
        if (!required) return { ok: true, skipped: true };
        return { ok: false, status: 400, reason: 'req_seq_missing' };
    }

    const row = await loadSessionRow(licenseKey);
    if (!row) {
        if (!required) return { ok: true, skipped: true };
        return { ok: false, status: 401, reason: 'session_not_found' };
    }

    if (sessionToken && row.session_token && sessionToken !== row.session_token) {
        await recordAuditEvent('signature_invalid', licenseKey, sessionToken, {
            reason: 'session_token_mismatch',
        });
        return { ok: false, status: 401, reason: 'session_mismatch', session: row };
    }

    const storedSeq = (() => {
        try { return BigInt(row.last_req_seq || 0); }
        catch (_) { return 0n; }
    })();

    if (candidateSeq <= storedSeq) {
        await recordAuditEvent('replay_blocked', licenseKey, row.session_token || sessionToken, {
            stored_seq: storedSeq.toString(),
            candidate_seq: candidateSeq.toString(),
        });
        return { ok: false, status: 401, reason: 'replay_blocked', session: row, last_req_seq: storedSeq.toString() };
    }

    if (storedSeq > 0n && (candidateSeq - storedSeq) > BigInt(REQ_SEQ_SKIP_THRESHOLD)) {
        await recordAuditEvent('replay_seq_skip', licenseKey, row.session_token || sessionToken, {
            stored_seq: storedSeq.toString(),
            candidate_seq: candidateSeq.toString(),
            jump: (candidateSeq - storedSeq).toString(),
        });
    }

    if (typeof body.req_ts_ms === 'number' && Number.isFinite(body.req_ts_ms)) {
        const drift = Math.abs(Date.now() - Math.floor(body.req_ts_ms));
        if (drift > REQ_TIME_WINDOW_MS) {
            await recordAuditEvent('signature_invalid', licenseKey, row.session_token || sessionToken, {
                reason: 'req_ts_drift',
                drift_ms: drift,
                limit_ms: REQ_TIME_WINDOW_MS,
            });
            return { ok: false, status: 401, reason: 'request_time_drift', session: row };
        }
    }

    try {
        const updated = await pool.query(
            'UPDATE sessions SET last_req_seq = $1 WHERE license_key = $2 AND last_req_seq < $1 RETURNING last_req_seq',
            [candidateSeq.toString(), licenseKey]
        );
        if (updated.rows.length === 0) {
            await recordAuditEvent('replay_blocked', licenseKey, row.session_token || sessionToken, {
                reason: 'concurrent_update_lost',
                stored_seq: storedSeq.toString(),
                candidate_seq: candidateSeq.toString(),
            });
            return { ok: false, status: 401, reason: 'replay_blocked', session: row };
        }
    } catch (err) {
        return { ok: false, status: 503, reason: 'replay_persist_failed' };
    }

    row.last_req_seq = candidateSeq.toString();
    return { ok: true, session: row, req_seq: candidateSeq.toString() };
}

function enforce(options) {
    return async function replayCounterMiddleware(req, res, next) {
        try {
            const verdict = await checkAndAdvance(req.body || {}, options);
            if (!verdict.ok) {
                if (verdict.reason === 'replay_persist_failed') {
                    return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
                }
                return res.status(verdict.status || 401).json({
                    status: 'error',
                    reason: verdict.reason || 'replay_blocked',
                });
            }
            req.replayCounter = verdict;
            return next();
        } catch (err) {
            console.warn('[replay_counter] enforce failed:', err && err.message ? err.message : err);
            return res.status(500).json({ status: 'error', reason: 'internal_error' });
        }
    };
}

async function recordSignatureInvalid(licenseKey, sessionToken, details) {
    await recordAuditEvent('signature_invalid', licenseKey, sessionToken, details || {});
}

async function recordHwidMismatch(licenseKey, sessionToken, details) {
    await recordAuditEvent('hwid_mismatch', licenseKey, sessionToken, details || {});
}

async function recordRateLimitExceeded(licenseKey, sessionToken, details) {
    await recordAuditEvent('rate_limit_exceeded', licenseKey, sessionToken, details || {});
}

async function recordCbcPaddingOracle(licenseKey, sessionToken, details) {
    await recordAuditEvent('cbc_padding_oracle_attempt', licenseKey, sessionToken, details || {});
}

async function recordFormat2CrcFail(submittedSample, details) {
    await auditLog.appendAuditEntry({
        action: 'session.format2_crc_fail',
        target: '',
        details: Object.assign({
            sample_prefix: typeof submittedSample === 'string' ? submittedSample.slice(0, 16) : '',
        }, details || {}),
    });
}

async function isForceViolation(licenseKey) {
    if (!licenseKey) return false;
    try {
        const { rows } = await pool.query(
            'SELECT force_violation FROM sessions WHERE license_key = $1',
            [licenseKey]
        );
        if (rows.length === 0) return false;
        return rows[0].force_violation === true;
    } catch (_) {
        return false;
    }
}

async function clearForceViolation(licenseKey) {
    if (!licenseKey) return;
    try {
        await pool.query(
            'UPDATE sessions SET force_violation = false WHERE license_key = $1',
            [licenseKey]
        );
    } catch (_) { }
}

module.exports = {
    enforce,
    checkAndAdvance,
    recordAuditEvent,
    recordSignatureInvalid,
    recordHwidMismatch,
    recordRateLimitExceeded,
    recordCbcPaddingOracle,
    recordFormat2CrcFail,
    isForceViolation,
    clearForceViolation,
    maybeBanFromAuditBurst,
    purgeStaleAuditEvents,
    REQ_TIME_WINDOW_MS,
    REQ_SEQ_SKIP_THRESHOLD,
};
