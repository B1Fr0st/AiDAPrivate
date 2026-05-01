'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

delete process.env.REDIS_URL;
process.env.HEARTBEAT_MIN_INTERVAL_SECONDS = '2';
process.env.HEARTBEAT_WINDOW_SECONDS = '30';
process.env.HEARTBEAT_WINDOW_MAX_EVENTS = '2';
process.env.NONCE_REPLAY_TTL_SECONDS = '2';

const rateLimit = require('../middleware/rate_limit');

test.afterEach(async () => {
    await rateLimit.shutdownForTests();
});

test('first heartbeat in interval succeeds, second is throttled', async () => {
    const lk = 'AIDA-RL-FIRST-' + Date.now();
    const st = 'tok-' + Date.now();

    const a = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(a.ok, true);

    const b = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(b.ok, false);
    assert.equal(b.reason, 'heartbeat_too_fast');
    assert.ok(b.retryAfter > 0);
});

test('throttle releases after the interval expires', async () => {
    const lk = 'AIDA-RL-RELEASE-' + Date.now();
    const st = 'tok-' + Date.now();

    const a = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(a.ok, true);
    await new Promise(r => setTimeout(r, 2200));
    const b = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(b.ok, true);
});

test('twelve rapid heartbeats: first succeeds, the next eleven are 429', async () => {
    const lk = 'AIDA-RL-RAPID-' + Date.now();
    const st = 'tok-' + Date.now();

    let okCount = 0;
    let throttledCount = 0;
    for (let i = 0; i < 12; i++) {
        const r = await rateLimit.checkAndRegisterHeartbeat(lk, st);
        if (r.ok) okCount++;
        else if (r.reason === 'heartbeat_too_fast' || r.reason === 'heartbeat_window_exceeded') throttledCount++;
    }
    assert.equal(okCount, 1);
    assert.equal(throttledCount, 11);
});

test('different sessions on the same license have independent buckets', async () => {
    const lk = 'AIDA-RL-INDEP-' + Date.now();
    const a = await rateLimit.checkAndRegisterHeartbeat(lk, 'session-a-' + Date.now());
    const b = await rateLimit.checkAndRegisterHeartbeat(lk, 'session-b-' + Date.now());
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
});

test('sliding window flags more-than-max events within window', async () => {
    const lk = 'AIDA-RL-WINDOW-' + Date.now();
    const st = 'tok-window-' + Date.now();

    const r1 = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(r1.ok, true);
    await new Promise(r => setTimeout(r, 2200));
    const r2 = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(r2.ok, true);
    await new Promise(r => setTimeout(r, 2200));
    const r3 = await rateLimit.checkAndRegisterHeartbeat(lk, st);
    assert.equal(r3.ok, false);
    assert.equal(r3.reason, 'heartbeat_window_exceeded');
});

test('missing identifiers reject', async () => {
    const r = await rateLimit.checkAndRegisterHeartbeat('', '');
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'missing_identifiers');
});
