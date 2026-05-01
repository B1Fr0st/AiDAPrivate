'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP_HSM = path.join(os.tmpdir(), 'aida-test-hsm-' + crypto.randomBytes(6).toString('hex') + '.bin');

process.env.LOCAL_HSM_PATH = TMP_HSM;
process.env.LOCAL_HSM_PASSPHRASE = 'unit-test-passphrase-32-bytes-long-xx';
process.env.LOCAL_HSM_FORCE_SCRYPT = '1';
delete process.env.KMS_KEY_ID;
delete process.env.KMS_DATA_KEY_B64;
process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET || 'a'.repeat(48);

const columnCrypt = require('../crypto/column_crypt');

test.after(() => {
    try { fs.unlinkSync(TMP_HSM); } catch (_) { }
});

test('column_crypt round-trips plaintext via per-row UUID key', () => {
    const uuid = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(uuid, 'sessions/session_token', 'deadbeef-token-1234567890');
    assert.ok(blob.startsWith('v1:'));
    assert.ok(columnCrypt.isCiphertext(blob));
    const out = columnCrypt.decrypt(uuid, 'sessions/session_token', blob);
    assert.equal(out, 'deadbeef-token-1234567890');
});

test('column_crypt rejects ciphertext used with the wrong row UUID', () => {
    const uuid1 = columnCrypt.generateRowUuid();
    const uuid2 = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(uuid1, 'sessions/session_token', 'value');
    assert.throws(() => columnCrypt.decrypt(uuid2, 'sessions/session_token', blob));
});

test('column_crypt rejects ciphertext used with the wrong column label', () => {
    const uuid = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(uuid, 'sessions/session_token', 'value');
    assert.throws(() => columnCrypt.decrypt(uuid, 'sessions/last_proof_token', blob));
});

test('column_crypt detects bit-flip in ciphertext via GCM tag', () => {
    const uuid = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(uuid, 'sessions/session_token', 'sensitive');
    const parts = blob.split(':');
    const ct = Buffer.from(parts[3], 'hex');
    ct[0] ^= 0x01;
    const tampered = `${parts[0]}:${parts[1]}:${parts[2]}:${ct.toString('hex')}`;
    assert.throws(() => columnCrypt.decrypt(uuid, 'sessions/session_token', tampered));
});

test('column_crypt isCiphertext only matches v1: prefix with hex parts', () => {
    assert.equal(columnCrypt.isCiphertext('plain-token'), false);
    assert.equal(columnCrypt.isCiphertext(''), false);
    assert.equal(columnCrypt.isCiphertext('v1:abc:def:ghi'), false);
    assert.equal(columnCrypt.isCiphertext(null), false);
    const uuid = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(uuid, 'sessions/session_token', 'plaintext');
    assert.equal(columnCrypt.isCiphertext(blob), true);
});

test('column_crypt empty input round-trips as empty string', () => {
    const uuid = columnCrypt.generateRowUuid();
    assert.equal(columnCrypt.encrypt(uuid, 'sessions/last_proof_token', ''), '');
    assert.equal(columnCrypt.decrypt(uuid, 'sessions/last_proof_token', ''), '');
});

test('column_crypt deriveColumnKey requires valid UUID format', () => {
    assert.throws(() => columnCrypt.encrypt('not-a-uuid', 'sessions/session_token', 'x'));
});

test('column_crypt produces blobs that look like hex (psql-visible only as ciphertext)', () => {
    const uuid = columnCrypt.generateRowUuid();
    const plaintext = 'AIDA-PLAIN-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const blob = columnCrypt.encrypt(uuid, 'sessions/session_token', plaintext);
    assert.ok(/^v1:[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/.test(blob));
    assert.equal(blob.includes(plaintext), false);
    assert.equal(blob.indexOf('AIDA-PLAIN'), -1);
});

test('column_crypt different rows with the same plaintext produce different ciphertext', () => {
    const u1 = columnCrypt.generateRowUuid();
    const u2 = columnCrypt.generateRowUuid();
    const a = columnCrypt.encrypt(u1, 'sessions/session_token', 'same-plaintext');
    const b = columnCrypt.encrypt(u2, 'sessions/session_token', 'same-plaintext');
    assert.notEqual(a, b);
});

test('column_crypt with the same row produces fresh IVs per call', () => {
    const u = columnCrypt.generateRowUuid();
    const a = columnCrypt.encrypt(u, 'sessions/session_token', 'same-plaintext');
    const b = columnCrypt.encrypt(u, 'sessions/session_token', 'same-plaintext');
    assert.notEqual(a, b);
    assert.equal(columnCrypt.decrypt(u, 'sessions/session_token', a), 'same-plaintext');
    assert.equal(columnCrypt.decrypt(u, 'sessions/session_token', b), 'same-plaintext');
});

test('local_hsm file lives at LOCAL_HSM_PATH with 0o600 perms after first init', () => {
    const u = columnCrypt.generateRowUuid();
    columnCrypt.encrypt(u, 'sessions/session_token', 'force-init');
    assert.ok(fs.existsSync(TMP_HSM), 'HSM file must be created on first encrypt');
    const stat = fs.statSync(TMP_HSM);
    if (process.platform !== 'win32') {
        const mode = stat.mode & 0o777;
        assert.equal(mode, 0o600, `HSM file mode must be 0o600 on POSIX; got 0o${mode.toString(8)}`);
    }
    const buf = fs.readFileSync(TMP_HSM);
    assert.ok(buf.length >= 64, 'HSM envelope must be ≥64 bytes');
    assert.equal(buf.subarray(0, 4).toString('utf8'), 'AHSM');
    assert.equal(buf[4], 1);
    assert.equal(buf[5], 1);
});

test('local_hsm survives a restart: same KEK derived after cache clear', () => {
    const u = columnCrypt.generateRowUuid();
    const blob = columnCrypt.encrypt(u, 'sessions/session_token', 'persistence-check');
    columnCrypt.clearKeyCache();
    const recovered = columnCrypt.decrypt(u, 'sessions/session_token', blob);
    assert.equal(recovered, 'persistence-check');
});
