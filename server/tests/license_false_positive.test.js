'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async () => ({ rows: [], rowCount: 0 }),
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

test('startup ban check accepts unique current and legacy hwids', () => {
    const hwids = licenseRouter._internal.normalizeBanCheckHwids({
        hwid: 'CURRENT-HWID-1234',
        hwids: ['CURRENT-HWID-1234', 'LEGACY-HWID-5678', 'short', 1234],
    });

    assert.deepEqual(hwids, ['CURRENT-HWID-1234', 'LEGACY-HWID-5678']);
});
