'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const arcLicenseBind = require('../crypto/arc-license-bind');
const kwWrap = require('../crypto/kw_wrap');

function makeLicenseRow(overrides = {}) {
    process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
        || Buffer.alloc(32, 0xA1).toString('base64');
    const installSecret = kwWrap.generateInstallSecret();
    const wrapped = kwWrap.wrap(installSecret, 'install_secret/v1');
    return Object.assign({
        key: 'AIDA-1111-2222-3333-4444',
        install_secret_wrapped: wrapped,
        boot_nonce_last: '',
    }, overrides);
}

test('rotating bind_proof differs across epochs', () => {
    const license = makeLicenseRow();
    const session = 'sess-token-aaaa1111';
    const hwid = 'HW-DEADBEEF-1234';
    const a = arcLicenseBind.deriveRotatingBindProof(license, session, hwid, 1n, 'nonceA', '');
    const b = arcLicenseBind.deriveRotatingBindProof(license, session, hwid, 2n, 'nonceB', '');
    assert.equal(a.length, 32);
    assert.equal(b.length, 32);
    assert.notEqual(a.toString('hex'), b.toString('hex'));
});

test('rotating bind_proof differs when nonce differs but epoch matches', () => {
    const license = makeLicenseRow();
    const a = arcLicenseBind.deriveRotatingBindProof(license, 'sess', 'HW', 7n, 'nonceX', '');
    const b = arcLicenseBind.deriveRotatingBindProof(license, 'sess', 'HW', 7n, 'nonceY', '');
    assert.notEqual(a.toString('hex'), b.toString('hex'));
});

test('rotating bind_proof reproducible for identical inputs', () => {
    const license = makeLicenseRow();
    const a = arcLicenseBind.deriveRotatingBindProof(license, 'sess', 'HW', 1n, 'nonce1', 'aa'.repeat(32));
    const b = arcLicenseBind.deriveRotatingBindProof(license, 'sess', 'HW', 1n, 'nonce1', 'aa'.repeat(32));
    assert.equal(a.toString('hex'), b.toString('hex'));
});

test('signCodePage and verifyCodePage round-trip succeeds', () => {
    const license = makeLicenseRow();
    const session = { session_token: 'tok-1234567890abcdef', issued_at: 100000 };
    const page = Buffer.alloc(4096, 0x42);
    const r = arcLicenseBind.signCodePage(license, session, 'HWID-X', 5, page);
    const sigHex = r.signature.toString('hex');
    assert.equal(arcLicenseBind.verifyCodePage(license, session, 'HWID-X', 5, page, sigHex), true);
});

test('signCodePage signature is bound to HWID', () => {
    const license = makeLicenseRow();
    const session = { session_token: 'tok-zzz', issued_at: 1 };
    const page = Buffer.alloc(64, 0x11);
    const a = arcLicenseBind.signCodePage(license, session, 'HW-A', 0, page).signature.toString('hex');
    const b = arcLicenseBind.signCodePage(license, session, 'HW-B', 0, page).signature.toString('hex');
    assert.notEqual(a, b);
});

test('signCodePage signature is bound to page index', () => {
    const license = makeLicenseRow();
    const session = { session_token: 'tok', issued_at: 1 };
    const page = Buffer.alloc(64, 0x11);
    const a = arcLicenseBind.signCodePage(license, session, 'HW', 0, page).signature.toString('hex');
    const b = arcLicenseBind.signCodePage(license, session, 'HW', 1, page).signature.toString('hex');
    assert.notEqual(a, b);
});

test('signCodePage signature is bound to ciphertext content', () => {
    const license = makeLicenseRow();
    const session = { session_token: 'tok', issued_at: 1 };
    const a = arcLicenseBind.signCodePage(license, session, 'HW', 0, Buffer.alloc(8, 1)).signature.toString('hex');
    const b = arcLicenseBind.signCodePage(license, session, 'HW', 0, Buffer.alloc(8, 2)).signature.toString('hex');
    assert.notEqual(a, b);
});

test('deriveLicenseeId is deterministic per license key', () => {
    const a = arcLicenseBind.deriveLicenseeId({ key: 'AIDA-AAAA' });
    const b = arcLicenseBind.deriveLicenseeId({ key: 'AIDA-AAAA' });
    const c = arcLicenseBind.deriveLicenseeId({ key: 'AIDA-BBBB' });
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.equal(a.length, 64);
});

test('deriveLicenseeId honours explicit licensee_id when provided', () => {
    const id = arcLicenseBind.deriveLicenseeId({ key: 'AIDA-X', licensee_id: 'ent-customer-42' });
    assert.equal(id, 'ent-customer-42');
});
