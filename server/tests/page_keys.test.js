'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || ('a'.repeat(32) + 'page-keys-test-secret-only');
process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');

const pageKeys = require('../crypto/page_keys.js');

test('page key derivation is deterministic for stable inputs', () => {
    const license = 'AIDA-TEST-PAGE-KEY-0001';
    const session = 'session-token-page-keys-1';
    const hwid = 'HWID-PAGE-KEYS-1';
    const epoch = pageKeys.currentEpoch(1700000000);
    const nonce1 = pageKeys.epochNonce(epoch, session, hwid);
    const nonce2 = pageKeys.epochNonce(epoch, session, hwid);
    assert.deepEqual(nonce1, nonce2);
    const key1 = pageKeys.derivePageKey(license, session, hwid, 7, nonce1);
    const key2 = pageKeys.derivePageKey(license, session, hwid, 7, nonce2);
    assert.deepEqual(key1, key2);
    assert.equal(key1.length, 32);
});

test('different epochs produce different page keys', () => {
    const license = 'AIDA-TEST-PAGE-KEY-0002';
    const session = 'session-token-page-keys-2';
    const hwid = 'HWID-PAGE-KEYS-2';
    const epochA = 1700000000;
    const epochB = epochA + pageKeys.EPOCH_INTERVAL_SECONDS;
    const nonceA = pageKeys.epochNonce(epochA, session, hwid);
    const nonceB = pageKeys.epochNonce(epochB, session, hwid);
    const keyA = pageKeys.derivePageKey(license, session, hwid, 0, nonceA);
    const keyB = pageKeys.derivePageKey(license, session, hwid, 0, nonceB);
    assert.notDeepEqual(keyA, keyB);
});

test('different page indices produce different keys for the same epoch', () => {
    const license = 'AIDA-TEST-PAGE-KEY-0003';
    const session = 'session-token-page-keys-3';
    const hwid = 'HWID-PAGE-KEYS-3';
    const epoch = pageKeys.currentEpoch(1700000000);
    const nonce = pageKeys.epochNonce(epoch, session, hwid);
    const key0 = pageKeys.derivePageKey(license, session, hwid, 0, nonce);
    const key1 = pageKeys.derivePageKey(license, session, hwid, 1, nonce);
    const key2 = pageKeys.derivePageKey(license, session, hwid, 0xDEAD, nonce);
    assert.notDeepEqual(key0, key1);
    assert.notDeepEqual(key0, key2);
    assert.notDeepEqual(key1, key2);
});

test('encryptPage is reversible with derived key', () => {
    const license = 'AIDA-TEST-PAGE-ENC-0001';
    const session = 'session-encryption-test-token';
    const hwid = 'HWID-ENC-TEST-1';
    const pageIndex = 13;
    const epoch = pageKeys.currentEpoch(1700001234);
    const plaintext = crypto.randomBytes(1500);

    const enc = pageKeys.encryptPage(plaintext, license, session, hwid, pageIndex, epoch);
    const nonce = pageKeys.epochNonce(epoch, session, hwid);
    const key = pageKeys.derivePageKey(license, session, hwid, pageIndex, nonce);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, enc.iv);
    decipher.setAuthTag(enc.authTag);
    const recovered = Buffer.concat([decipher.update(enc.ciphertext), decipher.final()]);
    assert.deepEqual(recovered, plaintext);
});

test('encryptPage with rotated epoch produces a key that does not decrypt prior ciphertext', () => {
    const license = 'AIDA-TEST-PAGE-EPOCH-ROT-0001';
    const session = 'session-rotation-test-token';
    const hwid = 'HWID-ROTATION-TEST-1';
    const pageIndex = 0;
    const epochA = 1700000000;
    const epochB = epochA + pageKeys.EPOCH_INTERVAL_SECONDS;
    const plaintext = Buffer.from('rotation test page content');

    const encA = pageKeys.encryptPage(plaintext, license, session, hwid, pageIndex, epochA);
    const nonceB = pageKeys.epochNonce(epochB, session, hwid);
    const keyB = pageKeys.derivePageKey(license, session, hwid, pageIndex, nonceB);
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyB, encA.iv);
    decipher.setAuthTag(encA.authTag);
    assert.throws(() => {
        decipher.update(encA.ciphertext);
        decipher.final();
    });
});

test('splitIntoPages divides into 4096-byte chunks with last short page', () => {
    const buf = crypto.randomBytes(pageKeys.PAGE_SIZE_BYTES * 3 + 7);
    const pages = pageKeys.splitIntoPages(buf);
    assert.equal(pages.length, 4);
    for (let i = 0; i < 3; i++) assert.equal(pages[i].length, pageKeys.PAGE_SIZE_BYTES);
    assert.equal(pages[3].length, 7);
    assert.equal(pageKeys.getPageCount(buf.length), 4);
});

test('deriveFunctionKey is deterministic and binds to nonce', () => {
    const license = 'AIDA-TEST-FN-KEY-0001';
    const hwid = 'HWID-FN-1';
    const fnHash = crypto.createHash('sha256').update('arc_heartbeat').digest('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const k1 = pageKeys.deriveFunctionKey(license, hwid, fnHash, nonce, 1700000000);
    const k2 = pageKeys.deriveFunctionKey(license, hwid, fnHash, nonce, 1700000000);
    assert.deepEqual(k1, k2);
    assert.equal(k1.length, 32);
    const nonce2 = crypto.randomBytes(16).toString('hex');
    const k3 = pageKeys.deriveFunctionKey(license, hwid, fnHash, nonce2, 1700000000);
    assert.notDeepEqual(k1, k3);
});

test('deriveFunctionToken is deterministic and binds to expiry', () => {
    const license = 'AIDA-TEST-FN-TOKEN-0001';
    const hwid = 'HWID-FN-TOKEN-1';
    const fnHash = crypto.createHash('sha256').update('arc_init').digest('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const issued = 1700000000;
    const expires = issued + 10;
    const t1 = pageKeys.deriveFunctionToken(license, hwid, fnHash, nonce, issued, expires);
    const t2 = pageKeys.deriveFunctionToken(license, hwid, fnHash, nonce, issued, expires);
    assert.deepEqual(t1, t2);
    const t3 = pageKeys.deriveFunctionToken(license, hwid, fnHash, nonce, issued, expires + 1);
    assert.notDeepEqual(t1, t3);
});

test('encryptPrologue round-trips with derivePrologueKey', () => {
    const license = 'AIDA-TEST-PROLOGUE-0001';
    const hwid = 'HWID-PROLOGUE-1';
    const fnHash = crypto.createHash('sha256').update('arc_unseal_feature').digest('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const plaintext = crypto.randomBytes(20);
    const enc = pageKeys.encryptPrologue(plaintext, license, hwid, fnHash, nonce);
    const key = pageKeys.derivePrologueKey(license, hwid, fnHash, nonce);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, enc.iv);
    decipher.setAuthTag(enc.authTag);
    const recovered = Buffer.concat([decipher.update(enc.ciphertext), decipher.final()]);
    assert.deepEqual(recovered, plaintext);
});

test('constantTimeEqualHex matches identical strings and rejects different ones', () => {
    const a = 'deadbeefcafef00d';
    const b = 'deadbeefcafef00d';
    const c = 'deadbeefcafef00e';
    assert.equal(pageKeys.constantTimeEqualHex(a, b), true);
    assert.equal(pageKeys.constantTimeEqualHex(a, c), false);
    assert.equal(pageKeys.constantTimeEqualHex(a, ''), false);
    assert.equal(pageKeys.constantTimeEqualHex(a, null), false);
    assert.equal(pageKeys.constantTimeEqualHex(null, b), false);
});

test('pageBoundsForBlob clamps last page', () => {
    const total = pageKeys.PAGE_SIZE_BYTES * 2 + 100;
    const b0 = pageKeys.pageBoundsForBlob(total, 0);
    const b1 = pageKeys.pageBoundsForBlob(total, 1);
    const b2 = pageKeys.pageBoundsForBlob(total, 2);
    const b3 = pageKeys.pageBoundsForBlob(total, 3);
    assert.equal(b0.start, 0);
    assert.equal(b0.end, pageKeys.PAGE_SIZE_BYTES);
    assert.equal(b1.start, pageKeys.PAGE_SIZE_BYTES);
    assert.equal(b1.end, pageKeys.PAGE_SIZE_BYTES * 2);
    assert.equal(b2.start, pageKeys.PAGE_SIZE_BYTES * 2);
    assert.equal(b2.end, total);
    assert.equal(b3, null);
});
