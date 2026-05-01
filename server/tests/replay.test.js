'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

delete process.env.REDIS_URL;
process.env.NONCE_REPLAY_TTL_SECONDS = '2';

const rateLimit = require('../middleware/rate_limit');

test.afterEach(async () => {
    await rateLimit.shutdownForTests();
});

test('first registration of a nonce succeeds; replay rejected as nonce_replay', async () => {
    const lk = 'AIDA-NC-FIRST-' + Date.now();
    const st = 'tok-' + Date.now();
    const nonce = 'fa1afe1' + Date.now().toString(16);

    const a = await rateLimit.registerNonce(lk, st, 'issued:' + nonce, 60);
    assert.equal(a.ok, true);

    const b = await rateLimit.registerNonce(lk, st, 'issued:' + nonce, 60);
    assert.equal(b.ok, false);
    assert.equal(b.reason, 'nonce_replay');
});

test('different nonces under the same session are independent', async () => {
    const lk = 'AIDA-NC-DIFF-' + Date.now();
    const st = 'tok-' + Date.now();

    const a = await rateLimit.registerNonce(lk, st, 'echo:abc1', 60);
    const b = await rateLimit.registerNonce(lk, st, 'echo:def2', 60);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
});

test('nonce expires after TTL', async () => {
    const lk = 'AIDA-NC-TTL-' + Date.now();
    const st = 'tok-' + Date.now();
    const nonce = 'expiring' + Date.now().toString(16);

    const a = await rateLimit.registerNonce(lk, st, 'issued:' + nonce, 1);
    assert.equal(a.ok, true);
    await new Promise(r => setTimeout(r, 1200));
    const b = await rateLimit.registerNonce(lk, st, 'issued:' + nonce, 1);
    assert.equal(b.ok, true);
});

test('nonceSeen returns true only for live nonces', async () => {
    const lk = 'AIDA-NC-SEEN-' + Date.now();
    const st = 'tok-' + Date.now();
    const nonce = 'seenable' + Date.now().toString(16);

    assert.equal(await rateLimit.nonceSeen(lk, st, 'issued:' + nonce), false);
    await rateLimit.registerNonce(lk, st, 'issued:' + nonce, 5);
    assert.equal(await rateLimit.nonceSeen(lk, st, 'issued:' + nonce), true);
});

test('isolated namespace: same nonce under different (license, session) tuples does not collide', async () => {
    const nonce = 'shared' + Date.now().toString(16);
    const lkA = 'AIDA-NC-NS-A-' + Date.now();
    const lkB = 'AIDA-NC-NS-B-' + Date.now();
    const stA = 'tok-A-' + Date.now();
    const stB = 'tok-B-' + Date.now();

    const a = await rateLimit.registerNonce(lkA, stA, 'issued:' + nonce, 60);
    const b = await rateLimit.registerNonce(lkB, stB, 'issued:' + nonce, 60);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
});
