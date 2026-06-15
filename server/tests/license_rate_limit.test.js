'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.LICENSE_RL_PER_MINUTE = '2';
process.env.LICENSE_RL_PER_HOUR = '3';
process.env.LICENSE_RL_PER_DAY = '10';
process.env.LICENSE_HEARTBEAT_RL_PER_MINUTE = '4';
process.env.LICENSE_HEARTBEAT_RL_PER_HOUR = '420';
process.env.LICENSE_HEARTBEAT_RL_PER_DAY = '7500';

const state = {
    windows: new Map(),
    params: [],
};

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async (sql, params) => {
            const text = String(sql);
            if (/DELETE FROM license_request_rate/i.test(text))
                return { rows: [], rowCount: 0 };
            if (/INSERT INTO license_request_rate/i.test(text)) {
                state.params.push(params.slice());
                const key = `${params[0]}|${params[1]}|${params[2]}`;
                const next = (state.windows.get(key) || 0) + 1;
                state.windows.set(key, next);
                return { rows: [{ count: next }], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
        },
        end: async () => {},
    },
};

const licenseRateLimit = require('../middleware/license_rate_limit');

test.beforeEach(() => {
    state.windows.clear();
    state.params.length = 0;
});

test('validate and heartbeat use independent per-license buckets', async () => {
    const licenseKey = `AIDA-LRLB-${Date.now()}`;

    const validateA = await licenseRateLimit.check(licenseKey, {
        bucket: 'validate',
        per_minute: 1,
        per_hour: 10,
        per_day: 10,
    });
    assert.equal(validateA.ok, true);

    const validateB = await licenseRateLimit.check(licenseKey, {
        bucket: 'validate',
        per_minute: 1,
        per_hour: 10,
        per_day: 10,
    });
    assert.equal(validateB.ok, false);
    assert.equal(validateB.scope, 'minute');
    assert.equal(validateB.bucket, 'validate');

    const heartbeatA = await licenseRateLimit.check(licenseKey, {
        bucket: 'heartbeat',
        per_minute: 2,
        per_hour: 10,
        per_day: 10,
    });
    const heartbeatB = await licenseRateLimit.check(licenseKey, {
        bucket: 'heartbeat',
        per_minute: 2,
        per_hour: 10,
        per_day: 10,
    });

    assert.equal(heartbeatA.ok, true);
    assert.equal(heartbeatB.ok, true);
    assert.ok(state.params.some(params => params[0] === `${licenseKey}|validate`));
    assert.ok(state.params.some(params => params[0] === `${licenseKey}|heartbeat`));
});

test('heartbeat defaults allow normal hourly cadence without consuming validate quota', async () => {
    assert.equal(licenseRateLimit.DEFAULT_HEARTBEAT_PER_HOUR, 420);
    assert.equal(licenseRateLimit.rateKeyFor('AIDA-X', 'heartbeat'), 'AIDA-X|heartbeat');
    assert.equal(licenseRateLimit.rateKeyFor('AIDA-X', 'bad bucket value'), 'AIDA-X');
});
