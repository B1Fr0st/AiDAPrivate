'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const capturedQueries = [];
const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async (sql, params) => {
            capturedQueries.push({ sql, params });
            return { rows: [], rowCount: 0 };
        },
        end: async () => {},
    },
};

const expressPath = require.resolve('express');
require.cache[expressPath] = {
    id: expressPath,
    filename: expressPath,
    loaded: true,
    exports: {
        Router: () => ({
            post: () => {},
            get: () => {},
        }),
    },
};

const licenseRouter = require('../routes/license.js');

test('heartbeat continuity findings are non-enforcing telemetry', () => {
    const result = licenseRouter._internal.evaluateHeartbeatContinuity(
        { heartbeat_count: 7, last_proof_token: 'ABCDEF0123456789' },
        { heartbeat_count: 0 }
    );

    assert.deepEqual(result.violation_reasons, []);
    assert.deepEqual(result.continuity_reasons, ['missing_proof_token', 'heartbeat_count_regression']);
    assert.equal(result.proof_token_to_store, 'ABCDEF0123456789');
});

test('replayed heartbeat proof is idempotent for transport retries', () => {
    const result = licenseRouter._internal.evaluateHeartbeatContinuity(
        { heartbeat_count: 3, last_proof_token: 'FEEDFACECAFEBEEF' },
        { heartbeat_count: 3, proof_token: 'FEEDFACECAFEBEEF' }
    );

    assert.deepEqual(result.violation_reasons, []);
    assert.ok(result.continuity_reasons.includes('replayed_proof_token'));
    assert.ok(result.continuity_reasons.includes('heartbeat_count_regression'));
    assert.equal(result.proof_token_to_store, 'FEEDFACECAFEBEEF');
});

test('legacy heuristic ban reasons are not enforcement bans', () => {
    assert.equal(licenseRouter._internal.isNonEnforcingBanReason('anomaly_auto_kill'), true);
    assert.equal(licenseRouter._internal.isNonEnforcingBanReason('cross_session_anomaly_ban'), true);
    assert.equal(licenseRouter._internal.isNonEnforcingBanReason('honeypot_export_called'), false);
});

test('license expiry prefers exact epoch over legacy date string', () => {
    const now = 2000000000;
    assert.equal(licenseRouter._internal.isLicenseExpired({
        expires: '2000-01-01',
        expires_epoch: now + 60,
    }, now), false);
    assert.equal(licenseRouter._internal.isLicenseExpired({
        expires: '2999-01-01',
        expires_epoch: now - 1,
    }, now), true);
});

test('license expiry keeps legacy date keys valid through the UTC expiry day', () => {
    const sameDay = Math.floor(Date.parse('2026-05-24T12:00:00Z') / 1000);
    const nextDay = Math.floor(Date.parse('2026-05-25T00:00:00Z') / 1000);
    assert.equal(licenseRouter._internal.isLicenseExpired({
        expires: '2026-05-24',
        expires_epoch: 0,
    }, sameDay), false);
    assert.equal(licenseRouter._internal.isLicenseExpired({
        expires: '2026-05-24',
        expires_epoch: 0,
    }, nextDay), true);
});

test('startup ban check accepts unique current and legacy hwids', () => {
    const hwids = licenseRouter._internal.normalizeBanCheckHwids({
        hwid: 'CURRENT-HWID-1234',
        hwids: ['CURRENT-HWID-1234', 'LEGACY-HWID-5678', 'short', 1234],
    });

    assert.deepEqual(hwids, ['CURRENT-HWID-1234', 'LEGACY-HWID-5678']);
});

test('storeSession upsert resets last_gate_bitmap to prevent cross-session regression false positives', async () => {
    capturedQueries.length = 0;
    await licenseRouter._internal.storeSession('AIDA-TEST-0000-0000-0000', {
        session_token: 'stub_session_token_for_test',
        server_nonce: '00112233445566778899aabbccddeeff',
        issued_at: 1700000000,
        ttl: 3600,
        hwid: 'TESTHWID00000001',
        ip: '127.0.0.1',
        plugin_version: 'aida-test',
        last_heartbeat: 1700000000,
        honeypot_export: 'noop_honeypot_aabbcc',
        challenge_id: '',
    });

    const upsert = capturedQueries.find(q =>
        typeof q.sql === 'string' &&
        q.sql.includes('INSERT INTO sessions') &&
        q.sql.includes('ON CONFLICT (license_key) DO UPDATE SET'));
    assert.ok(upsert, 'storeSession must emit an INSERT ... ON CONFLICT upsert');

    const updateClause = upsert.sql.split('DO UPDATE SET')[1] || '';
    assert.match(updateClause, /last_gate_bitmap\s*=\s*0/,
        'ON CONFLICT DO UPDATE clause must reset last_gate_bitmap to 0 — otherwise a stale bitmap from a previous session causes a false-positive heartbeat_gate_bitmap_regression on the next activation');
    assert.match(updateClause, /heartbeat_count\s*=\s*0/,
        'ON CONFLICT DO UPDATE clause must reset heartbeat_count alongside last_gate_bitmap so all monotonic per-session fields are zeroed together');
    assert.match(updateClause, /driver_proof_absent_streak\s*=\s*0/,
        'ON CONFLICT DO UPDATE clause must reset driver_proof_absent_streak to 0 — a stale streak from a previous session would let a single early proofless heartbeat trip arc_driver_proof_missing');
});
