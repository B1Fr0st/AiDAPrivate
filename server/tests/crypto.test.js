'use strict';

// Phase 6: server crypto unit tests. Uses Node's built-in node:test runner
// so no new dependencies are required. Run with `npm test` from /server.

const test    = require('node:test');
const assert  = require('node:assert/strict');
const crypto  = require('crypto');

// Environment setup — must happen BEFORE requiring modules that read env at import.
process.env.ARC_MASTER_SECRET    = process.env.ARC_MASTER_SECRET
    || 'a'.repeat(32) + 'test-secret-only-for-unit-tests';
process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');

// Generate a fresh Ed25519 keypair for signing tests (in DER/PKCS8 to match
// signing.js expectations).
{
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
}

const arc     = require('../crypto/arc-encrypt.js');
const kwWrap  = require('../crypto/kw_wrap.js');
const signing = require('../crypto/signing.js');

// ─── arc-encrypt round-trip ───────────────────────────────────────────────────

test('arc encrypt → decrypt yields original plaintext', () => {
    const pt = Buffer.from('hello-aida-fortress-phase6', 'utf8');
    const sess = 'session-token-abc';
    const hwid = 'hwid-xyz';
    const issuedAt = 1700000000;

    const { encrypted, iv, authTag, hash } = arc.encryptArc(pt, sess, hwid, issuedAt);
    assert.ok(Buffer.isBuffer(encrypted) && encrypted.length > 0);
    assert.equal(iv.length, 12);
    assert.equal(authTag.length, 16);

    // Manual decrypt using the same derivation:
    const key = arc.deriveSessionKey(sess, hwid, issuedAt);
    const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
    dec.setAuthTag(authTag);
    const out = Buffer.concat([dec.update(encrypted), dec.final()]);

    assert.equal(out.toString('utf8'), pt.toString('utf8'));
    assert.equal(hash, crypto.createHash('sha256').update(pt).digest('hex'));
});

test('arc decrypt fails on tampered authTag', () => {
    const pt = Buffer.from('payload', 'utf8');
    const { encrypted, iv, authTag } = arc.encryptArc(pt, 's', 'h', 1);
    const tampered = Buffer.from(authTag);
    tampered[0] ^= 0xFF;

    const key = arc.deriveSessionKey('s', 'h', 1);
    const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
    dec.setAuthTag(tampered);
    assert.throws(() => {
        dec.update(encrypted);
        dec.final();
    });
});

// ─── Kw wrap / unwrap ─────────────────────────────────────────────────────────

test('kw_wrap.wrap then unwrap recovers plaintext', () => {
    const kw = crypto.randomBytes(32);
    const blob = kwWrap.wrap(kw, 'kw_wrap/v1');
    assert.ok(Buffer.isBuffer(blob));
    assert.ok(blob.length >= kw.length + 12 + 16);

    const recovered = kwWrap.unwrap(blob, 'kw_wrap/v1');
    assert.equal(recovered.toString('hex'), kw.toString('hex'));
});

test('kw_wrap.unwrap fails with wrong label', () => {
    const kw = crypto.randomBytes(32);
    const blob = kwWrap.wrap(kw, 'label_a');
    assert.throws(() => kwWrap.unwrap(blob, 'label_b'));
});

test('kw_wrap.unwrap fails on truncated blob', () => {
    const kw = crypto.randomBytes(32);
    const blob = kwWrap.wrap(kw);
    assert.throws(() => kwWrap.unwrap(blob.subarray(0, 10)));
});

// ─── Signing round-trip ───────────────────────────────────────────────────────

test('signPayload produces verifiable Ed25519 signature', () => {
    const payload = {
        status: 'valid',
        license_key: 'TESTKEY',
        ttl: 3600,
        nonce: 'abc',
    };
    const hex = signing.signPayload(payload);
    assert.equal(typeof hex, 'string');
    const sig = Buffer.from(hex, 'hex');
    assert.equal(sig.length, 64);

    // Verify using the same private key's derived public key.
    const priv = signing.getSigningPrivateKey();
    const pub  = crypto.createPublicKey(priv);
    const canonical = JSON.stringify(signing.sortObjectKeys(payload));
    const ok = crypto.verify(null, Buffer.from(canonical, 'utf8'), pub, sig);
    assert.equal(ok, true);
});

test('signPayload rejects tampered payload', () => {
    const payload = { a: 1, b: 2 };
    const hex = signing.signPayload(payload);
    const sig = Buffer.from(hex, 'hex');
    const priv = signing.getSigningPrivateKey();
    const pub  = crypto.createPublicKey(priv);

    const tampered = JSON.stringify(signing.sortObjectKeys({ a: 1, b: 3 }));
    const ok = crypto.verify(null, Buffer.from(tampered, 'utf8'), pub, sig);
    assert.equal(ok, false);
});

// ─── Canonical key ordering (required for cross-platform verification) ────────

test('sortObjectKeys is stable regardless of input order', () => {
    const a = signing.sortObjectKeys({ c: 3, a: 1, b: 2 });
    const b = signing.sortObjectKeys({ a: 1, b: 2, c: 3 });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
});

// ─── dualSignPayload ──────────────────────────────────────────────────────────

test('dualSignPayload returns single signature when no next key configured', () => {
    delete process.env.ED25519_NEXT_PRIVATE_KEY_B64;
    delete process.env.ED25519_NEXT_NOT_BEFORE;
    signing.clearKeyCache();

    const payload = { action: 'validate', key: 'TEST' };
    const result = signing.dualSignPayload(payload);

    assert.equal(typeof result.signature, 'string');
    assert.equal(Buffer.from(result.signature, 'hex').length, 64);
    assert.equal(result.next_signature, undefined);
});

test('dualSignPayload returns both signatures during overlap window', () => {
    // Generate a second keypair for the next key
    const { privateKey: nextPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_NEXT_PRIVATE_KEY_B64 = nextPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
    // Set next key activation to 12h from now (inside the 24h overlap)
    process.env.ED25519_NEXT_NOT_BEFORE = String(
        Math.floor(Date.now() / 1000) + 43200
    );
    signing.clearKeyCache();

    const payload = { action: 'heartbeat', key: 'HB' };
    const result = signing.dualSignPayload(payload);

    assert.equal(typeof result.signature, 'string');
    assert.equal(typeof result.next_signature, 'string');
    assert.equal(Buffer.from(result.signature, 'hex').length, 64);
    assert.equal(Buffer.from(result.next_signature, 'hex').length, 64);
    assert.notEqual(result.signature, result.next_signature);

    // Verify the next signature with the next key's public
    const nextPub = crypto.createPublicKey(nextPriv);
    const canonical = JSON.stringify(signing.sortObjectKeys(payload));
    const ok = crypto.verify(
        null, Buffer.from(canonical, 'utf8'), nextPub,
        Buffer.from(result.next_signature, 'hex')
    );
    assert.equal(ok, true);

    // Cleanup
    delete process.env.ED25519_NEXT_PRIVATE_KEY_B64;
    delete process.env.ED25519_NEXT_NOT_BEFORE;
    signing.clearKeyCache();
});

test('dualSignPayload omits next_signature when outside overlap window', () => {
    const { privateKey: nextPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_NEXT_PRIVATE_KEY_B64 = nextPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
    // Set activation far in the future (beyond 24h overlap)
    process.env.ED25519_NEXT_NOT_BEFORE = String(
        Math.floor(Date.now() / 1000) + 200000
    );
    signing.clearKeyCache();

    const result = signing.dualSignPayload({ test: true });
    assert.equal(result.next_signature, undefined);

    delete process.env.ED25519_NEXT_PRIVATE_KEY_B64;
    delete process.env.ED25519_NEXT_NOT_BEFORE;
    signing.clearKeyCache();
});

test('clearKeyCache forces re-read of env vars', () => {
    const payload = { x: 1 };
    const sig1 = signing.dualSignPayload(payload).signature;

    // Generate a completely new primary key
    const { privateKey: newPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = newPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
    signing.clearKeyCache();

    const sig2 = signing.dualSignPayload(payload).signature;
    assert.notEqual(sig1, sig2, 'Signature should differ after key rotation');
});

// ─── TLS exporter ─────────────────────────────────────────────────────────────

const tls = require('../crypto/tls_exporter.js');

test('deriveExpected produces deterministic HMAC from hex secret', () => {
    const secretHex = crypto.randomBytes(32).toString('hex');
    const a = tls.deriveExpected(secretHex);
    const b = tls.deriveExpected(secretHex);
    assert.equal(a, b);
    assert.equal(typeof a, 'string');
    assert.equal(a.length, 64); // sha256 hex = 64 chars
});

test('deriveExpected returns null for invalid inputs', () => {
    assert.equal(tls.deriveExpected(null), null);
    assert.equal(tls.deriveExpected(''), null);
    assert.equal(tls.deriveExpected('not-hex!!'), null);
    assert.equal(tls.deriveExpected('ab'), null); // too short
    assert.equal(tls.deriveExpected(123), null);
});

test('deriveExpected different secrets produce different results', () => {
    const a = tls.deriveExpected(crypto.randomBytes(32).toString('hex'));
    const b = tls.deriveExpected(crypto.randomBytes(32).toString('hex'));
    assert.notEqual(a, b);
});
