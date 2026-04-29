'use strict';


const test    = require('node:test');
const assert  = require('node:assert/strict');
const crypto  = require('crypto');


process.env.ARC_MASTER_SECRET    = process.env.ARC_MASTER_SECRET
    || 'a'.repeat(32) + 'test-secret-only-for-unit-tests';
process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');


{
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
}

const arc     = require('../crypto/arc-encrypt.js');
const kwWrap  = require('../crypto/kw_wrap.js');
const signing = require('../crypto/signing.js');


test('arc encrypt → decrypt yields original plaintext', () => {
    const pt = Buffer.from('hello-aida-fortress-phase6', 'utf8');
    const sess = 'session-token-abc';
    const hwid = 'hwid-xyz';
    const issuedAt = 1700000000;

    const { encrypted, iv, authTag, hash } = arc.encryptArc(pt, sess, hwid, issuedAt);
    assert.ok(Buffer.isBuffer(encrypted) && encrypted.length > 0);
    assert.equal(iv.length, 12);
    assert.equal(authTag.length, 16);


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


test('sortObjectKeys is stable regardless of input order', () => {
    const a = signing.sortObjectKeys({ c: 3, a: 1, b: 2 });
    const b = signing.sortObjectKeys({ a: 1, b: 2, c: 3 });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
});


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

    const { privateKey: nextPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_NEXT_PRIVATE_KEY_B64 = nextPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');

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


    const nextPub = crypto.createPublicKey(nextPriv);
    const canonical = JSON.stringify(signing.sortObjectKeys(payload));
    const ok = crypto.verify(
        null, Buffer.from(canonical, 'utf8'), nextPub,
        Buffer.from(result.next_signature, 'hex')
    );
    assert.equal(ok, true);


    delete process.env.ED25519_NEXT_PRIVATE_KEY_B64;
    delete process.env.ED25519_NEXT_NOT_BEFORE;
    signing.clearKeyCache();
});

test('dualSignPayload omits next_signature when outside overlap window', () => {
    const { privateKey: nextPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_NEXT_PRIVATE_KEY_B64 = nextPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');

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


    const { privateKey: newPriv } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = newPriv.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
    signing.clearKeyCache();

    const sig2 = signing.dualSignPayload(payload).signature;
    assert.notEqual(sig1, sig2, 'Signature should differ after key rotation');
});


const tls = require('../crypto/tls_exporter.js');

test('deriveExpected produces deterministic HMAC from hex secret', () => {
    const secretHex = crypto.randomBytes(32).toString('hex');
    const a = tls.deriveExpected(secretHex);
    const b = tls.deriveExpected(secretHex);
    assert.equal(a, b);
    assert.equal(typeof a, 'string');
    assert.equal(a.length, 64);
});

test('deriveExpected returns null for invalid inputs', () => {
    assert.equal(tls.deriveExpected(null), null);
    assert.equal(tls.deriveExpected(''), null);
    assert.equal(tls.deriveExpected('not-hex!!'), null);
    assert.equal(tls.deriveExpected('ab'), null);
    assert.equal(tls.deriveExpected(123), null);
});

test('deriveExpected different secrets produce different results', () => {
    const a = tls.deriveExpected(crypto.randomBytes(32).toString('hex'));
    const b = tls.deriveExpected(crypto.randomBytes(32).toString('hex'));
    assert.notEqual(a, b);
});


const arcLicenseBind = require('../crypto/arc-license-bind.js');

test('feature blob entry stride is 44 bytes (matches ARC C++ struct)', () => {
    const installSecret = crypto.randomBytes(32);
    const wrappedInstall = kwWrap.wrap(installSecret, 'install_secret/v1');
    const licenseRow = {
        key: 'AIDA-TEST-FEAT-LAYOUT-0001',
        install_secret_wrapped: wrappedInstall,
        boot_nonce_last: null,
    };
    const sessionRow = { session_token: 'a'.repeat(64) };

    const blob = arcLicenseBind.assembleFeatureBlob(licenseRow, sessionRow);
    assert.equal(blob.length, 4096);

    const FEAT_MAGIC = 0x46454154;
    const FEAT_HEADER_SIZE = 16;
    const FEAT_ENTRY_SIZE_CPP = 44;
    assert.equal(blob.readUInt32LE(0x000), FEAT_MAGIC);
    assert.equal(blob.readUInt32LE(0x004), 1);
    const entryCount = blob.readUInt32LE(0x008);
    assert.equal(entryCount, 1);
    const totalSize = blob.readUInt32LE(0x00C);
    assert.equal(totalSize, FEAT_HEADER_SIZE + entryCount * FEAT_ENTRY_SIZE_CPP + 32);

    const entryOffset = FEAT_HEADER_SIZE;
    const featureId = blob.readUInt32LE(entryOffset + 0);
    const ciphertextOffset = blob.readUInt32LE(entryOffset + 4);
    const ciphertextLen = blob.readUInt32LE(entryOffset + 8);
    assert.equal(featureId, 1);
    assert.equal(ciphertextLen, 32);
    assert.equal(ciphertextOffset, FEAT_HEADER_SIZE + entryCount * FEAT_ENTRY_SIZE_CPP);

    const iv = blob.subarray(entryOffset + 16, entryOffset + 28);
    const tag = blob.subarray(entryOffset + 28, entryOffset + 44);
    const ciphertext = blob.subarray(ciphertextOffset, ciphertextOffset + ciphertextLen);

    const tagFromAfterCiphertext = blob.subarray(ciphertextOffset, ciphertextOffset + 4);
    const lastFourTagBytes = tag.subarray(12, 16);
    assert.notDeepEqual(
        Buffer.from(lastFourTagBytes),
        Buffer.from(tagFromAfterCiphertext),
        'Tag last 4 bytes must NOT alias ciphertext start; this catches the FEAT_ENTRY_SIZE=40 regression');

    const bindSecretInstall = kwWrap.unwrap(licenseRow.install_secret_wrapped, 'install_secret/v1');
    const bindSecret = Buffer.from(crypto.hkdfSync(
        'sha256', bindSecretInstall, Buffer.alloc(8, 0),
        Buffer.from('arc-bind-secret', 'utf8'), 32));
    const nonce = Buffer.alloc(32, 0);
    Buffer.from(sessionRow.session_token, 'utf8').copy(nonce, 0, 0, 32);
    const featureKey = crypto.hkdfSync(
        'sha256', bindSecret, nonce,
        Buffer.from('feature:1', 'utf8'), 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(featureKey), iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    assert.equal(plaintext.length, 32);
});

test('applyLicenseTransform writes a feature blob the C++ struct can decrypt', () => {
    const installSecret = crypto.randomBytes(32);
    const wrappedInstall = kwWrap.wrap(installSecret, 'install_secret/v1');
    const licenseRow = {
        key: 'AIDA-TEST-FEAT-ROUNDTRIP-0001',
        install_secret_wrapped: wrappedInstall,
        boot_nonce_last: null,
    };
    const sessionRow = { session_token: 'b'.repeat(64) };

    const dosSize = 64;
    const ntSize = 248;
    const sectionTableSize = 40 * 2;
    const headerSize = 4096;
    const licbindOffset = headerSize;
    const featOffset = headerSize + 4096;
    const blobLen = featOffset + 4096;
    const pe = Buffer.alloc(blobLen, 0);
    pe[0] = 0x4D; pe[1] = 0x5A;
    pe.writeUInt32LE(dosSize, 0x3C);
    pe[dosSize + 0] = 0x50;
    pe[dosSize + 1] = 0x45;
    pe[dosSize + 2] = 0x00;
    pe[dosSize + 3] = 0x00;
    pe.writeUInt16LE(2, dosSize + 6);
    pe.writeUInt16LE(ntSize - 24, dosSize + 20);

    const sectionTableOffset = dosSize + 24 + (ntSize - 24);
    const licSectionHdr = sectionTableOffset;
    Buffer.from('.licbind', 'utf8').copy(pe, licSectionHdr, 0, 8);
    pe.writeUInt32LE(32, licSectionHdr + 16);
    pe.writeUInt32LE(licbindOffset, licSectionHdr + 20);
    const featSectionHdr = sectionTableOffset + 40;
    Buffer.from('.feat', 'utf8').copy(pe, featSectionHdr, 0, 5);
    pe.writeUInt32LE(4096, featSectionHdr + 16);
    pe.writeUInt32LE(featOffset, featSectionHdr + 20);

    const out = arcLicenseBind.applyLicenseTransform(pe, licenseRow, sessionRow);
    const featBlob = out.subarray(featOffset, featOffset + 4096);

    assert.equal(featBlob.readUInt32LE(0), 0x46454154);
    const entryCount = featBlob.readUInt32LE(8);
    assert.equal(entryCount, 1);

    const entryOffset = 16;
    const ciphertextOffset = featBlob.readUInt32LE(entryOffset + 4);
    const ciphertextLen = featBlob.readUInt32LE(entryOffset + 8);
    const iv = featBlob.subarray(entryOffset + 16, entryOffset + 28);
    const tag = featBlob.subarray(entryOffset + 28, entryOffset + 44);
    const ciphertext = featBlob.subarray(ciphertextOffset, ciphertextOffset + ciphertextLen);

    const realBindSecretInstall = kwWrap.unwrap(licenseRow.install_secret_wrapped, 'install_secret/v1');
    const realBindSecret = Buffer.from(crypto.hkdfSync(
        'sha256', realBindSecretInstall, Buffer.alloc(8, 0),
        Buffer.from('arc-bind-secret', 'utf8'), 32));
    const nonce = Buffer.alloc(32, 0);
    Buffer.from(sessionRow.session_token, 'utf8').copy(nonce, 0, 0, 32);
    const featureKey = crypto.hkdfSync(
        'sha256', realBindSecret, nonce,
        Buffer.from('feature:1', 'utf8'), 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(featureKey), iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    assert.equal(plaintext.length, 32);
});
