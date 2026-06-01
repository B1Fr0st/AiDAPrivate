'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.SESSION_AEAD_KEY = crypto.randomBytes(32).toString('hex');

const sessionAead = require('../crypto/session_aead');
sessionAead.clearKeyCacheForTests();

const sessionRatchet = require('../middleware/session_ratchet');

test('session ratchet accepts server-issued sealed session tokens over legacy hex length', () => {
    const token = sessionAead.seal(
        'AIDA-' + 'A'.repeat(96),
        'b'.repeat(128),
        1700000000,
        3600,
        'enterprise-hardened'
    );

    assert.ok(token.length > 256);
    assert.equal(sessionRatchet._internal.isSessionTokenFormat(token), true);
});

test('session ratchet rejects forged hex and overlong token formats', () => {
    assert.equal(sessionRatchet._internal.isSessionTokenFormat('a'.repeat(64)), false);
    assert.equal(sessionRatchet._internal.isSessionTokenFormat('A'.repeat(
        sessionRatchet._internal.MAX_SESSION_TOKEN_LEN + 1)), false);
});
