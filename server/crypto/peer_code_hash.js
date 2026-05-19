'use strict';

const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');

const DIR = path.join(__dirname, '..', 'expected_code_hashes');
const REFRESH_INTERVAL_MS = 30000;

let cachedHash = '';
let cachedMtime = 0;
let cachedScanAt = 0;

function refresh() {
    try {
        if (!fs.existsSync(DIR)) {
            cachedHash = '';
            return;
        }
        const entries = fs.readdirSync(DIR).filter(f => /^aida_standalone_v.*\.json$/i.test(f));
        if (entries.length === 0) {
            cachedHash = '';
            return;
        }
        entries.sort();
        const latest = entries[entries.length - 1];
        const fullPath = path.join(DIR, latest);
        const st = fs.statSync(fullPath);
        if (cachedHash && st.mtimeMs === cachedMtime) return;
        const parsed = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
        const h = String(parsed && parsed.peer_code_hash ? parsed.peer_code_hash : '').trim().toLowerCase();
        if (/^[0-9a-f]{64}$/.test(h)) {
            cachedHash = h;
            cachedMtime = st.mtimeMs;
        } else {
            cachedHash = '';
        }
    } catch (err) {
        console.warn('[peer_code_hash] refresh failed:', err && err.message ? err.message : err);
        cachedHash = '';
    }
}

function getExpected() {
    const now = Date.now();
    if (now - cachedScanAt > REFRESH_INTERVAL_MS) {
        cachedScanAt = now;
        refresh();
    }
    return cachedHash;
}

async function getLatestForLicense(licenseKey) {
    if (!licenseKey) return null;
    try {
        const { rows } = await pool.query(
            `SELECT peer_code_hash, peer_code_hash_received_at, matched, expected_hash_at_receive
               FROM sentinel_attestations
              WHERE license_key = $1
              ORDER BY peer_code_hash_received_at DESC
              LIMIT 1`,
            [licenseKey]
        );
        return rows.length > 0 ? rows[0] : null;
    } catch (_) {
        return null;
    }
}

async function getSessionPeerState(licenseKey) {
    if (!licenseKey) return null;
    try {
        const { rows } = await pool.query(
            `SELECT peer_attest_divergence_streak, peer_attest_last_hash,
                    peer_attest_last_matched_at, peer_attest_degraded
               FROM sessions
              WHERE license_key = $1`,
            [licenseKey]
        );
        return rows.length > 0 ? rows[0] : null;
    } catch (_) {
        return null;
    }
}

module.exports = {
    getExpected,
    getLatestForLicense,
    getSessionPeerState,
};
