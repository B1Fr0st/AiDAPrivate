'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');
process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || 'aida-test-arc-master-secret-fixed-32x';

if (!process.env.ED25519_PRIVATE_KEY_B64) {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
}

const tpmQuote = require('../crypto/tpm_quote');
const ekRoots = require('../crypto/ek_roots');

function buildSyntheticEkCert(rootCa, ekKeyPair) {
    const rootName = Buffer.from('AIDA-SYNTHETIC-EK-ROOT', 'utf8');
    const subjectName = Buffer.from('AIDA-SYNTHETIC-EK-LEAF', 'utf8');

    const ekSpki = ekKeyPair.publicKey.export({ type: 'spki', format: 'der' });

    function lengthBytes(len) {
        if (len < 0x80) return Buffer.from([len]);
        const tmp = [];
        let n = len;
        while (n > 0) { tmp.unshift(n & 0xFF); n >>>= 8; }
        return Buffer.concat([Buffer.from([0x80 | tmp.length]), Buffer.from(tmp)]);
    }
    function tlv(tag, content) {
        return Buffer.concat([Buffer.from([tag]), lengthBytes(content.length), content]);
    }

    const version = tlv(0xA0, tlv(0x02, Buffer.from([0x02])));
    const serial = tlv(0x02, Buffer.from([0x01]));
    const sigAlgOid = Buffer.from([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]);
    const sigAlgNull = Buffer.from([0x05, 0x00]);
    const sigAlg = tlv(0x30, Buffer.concat([sigAlgOid, sigAlgNull]));
    const issuer = tlv(0x30, tlv(0x31, tlv(0x30, Buffer.concat([
        Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
        tlv(0x0C, rootName),
    ]))));
    const validity = tlv(0x30, Buffer.concat([
        tlv(0x17, Buffer.from('200101000000Z', 'utf8')),
        tlv(0x17, Buffer.from('400101000000Z', 'utf8')),
    ]));
    const subject = tlv(0x30, tlv(0x31, tlv(0x30, Buffer.concat([
        Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
        tlv(0x0C, subjectName),
    ]))));
    const spki = ekSpki;

    const tbs = tlv(0x30, Buffer.concat([
        version, serial, sigAlg, issuer, validity, subject, spki,
    ]));

    const signer = crypto.createSign('sha256');
    signer.update(tbs);
    signer.end();
    const sigBytes = signer.sign({ key: rootCa.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
    const sigBitstring = tlv(0x03, Buffer.concat([Buffer.from([0x00]), sigBytes]));

    const cert = tlv(0x30, Buffer.concat([tbs, sigAlg, sigBitstring]));
    return cert;
}

function generateSyntheticEnvironment() {
    const rootKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const ekKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

    const rootCert = buildSyntheticEkCert(
        { privateKey: rootKeyPair.privateKey, publicKey: rootKeyPair.publicKey },
        rootKeyPair
    );
    const fingerprint = crypto.createHash('sha256').update(rootCert).digest('hex');
    ekRoots.injectSyntheticRootForTests({
        vendor: 'TestSynthetic',
        productName: 'AIDA Synthetic EK Root',
        pem: '-----BEGIN CERTIFICATE-----\n' + rootCert.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n',
        der: rootCert,
        publicKey: rootKeyPair.publicKey,
        fingerprint,
    });

    const ekCertDer = buildSyntheticEkCert(rootKeyPair, ekKeyPair);
    return {
        rootKeyPair,
        ekKeyPair,
        rootCert,
        ekCertDer,
    };
}

function makePcrValues(seed) {
    const out = {};
    for (const idx of tpmQuote.REQUIRED_PCR_INDICES) {
        out[idx] = crypto.createHash('sha256').update('pcr-' + idx + '-' + seed).digest();
    }
    return out;
}

test('verifyTpmQuote accepts a valid synthetic TPM2_Quote', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const pcrMap = makePcrValues('clean');
    const quote = tpmQuote.buildSyntheticQuote(env.ekKeyPair.privateKey, env.ekCertDer, pcrMap, {
        extraData: Buffer.from('test-server-nonce', 'utf8'),
    });
    const result = tpmQuote.verifyTpmQuote({
        ekCert: env.ekCertDer,
        attest: quote.attest,
        signature: quote.signature,
        pcrValues: quote.pcrValues,
        expectedNonce: 'test-server-nonce',
    });
    assert.equal(result.ok, true, `expected ok, got ${result.reason}`);
    assert.equal(result.ekVendor, 'TestSynthetic');
    assert.equal(typeof result.hwidComponentHex, 'string');
    assert.equal(result.hwidComponentHex.length, 64);
});

test('verifyTpmQuote rejects a quote whose EK cert was signed by an unknown CA', () => {
    ekRoots.clearForTests();
    const trusted = generateSyntheticEnvironment();
    const ekKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rogueRoot = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rogueEkCert = buildSyntheticEkCert(rogueRoot, ekKeyPair);
    const pcrMap = makePcrValues('rogue');
    const quote = tpmQuote.buildSyntheticQuote(ekKeyPair.privateKey, rogueEkCert, pcrMap);
    const result = tpmQuote.verifyTpmQuote({
        ekCert: rogueEkCert,
        attest: quote.attest,
        signature: quote.signature,
        pcrValues: quote.pcrValues,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'ek_cert_no_root_match');
    assert.ok(trusted);
});

test('verifyTpmQuote rejects a quote whose attest signature was tampered', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const pcrMap = makePcrValues('tampered');
    const quote = tpmQuote.buildSyntheticQuote(env.ekKeyPair.privateKey, env.ekCertDer, pcrMap);
    const tamperedAttest = Buffer.from(quote.attest);
    tamperedAttest[tamperedAttest.length - 1] ^= 0x01;
    const result = tpmQuote.verifyTpmQuote({
        ekCert: env.ekCertDer,
        attest: tamperedAttest,
        signature: quote.signature,
        pcrValues: quote.pcrValues,
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /tpm_quote_(rsassa|rsapss|ecdsa)_verify_failed|tpm_attest_/);
});

test('verifyTpmQuote rejects when expected_nonce does not match attest extraData', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const pcrMap = makePcrValues('nonce-mismatch');
    const quote = tpmQuote.buildSyntheticQuote(env.ekKeyPair.privateKey, env.ekCertDer, pcrMap, {
        extraData: Buffer.from('correct-nonce', 'utf8'),
    });
    const result = tpmQuote.verifyTpmQuote({
        ekCert: env.ekCertDer,
        attest: quote.attest,
        signature: quote.signature,
        pcrValues: quote.pcrValues,
        expectedNonce: 'wrong-nonce',
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'tpm_nonce_mismatch');
});

test('verifyTpmQuote rejects when PCR values do not match attest digest', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const goodPcrs = makePcrValues('a');
    const quote = tpmQuote.buildSyntheticQuote(env.ekKeyPair.privateKey, env.ekCertDer, goodPcrs);
    const wrongPcrs = makePcrValues('b');
    const result = tpmQuote.verifyTpmQuote({
        ekCert: env.ekCertDer,
        attest: quote.attest,
        signature: quote.signature,
        pcrValues: Object.fromEntries(tpmQuote.REQUIRED_PCR_INDICES.map(i => [String(i), wrongPcrs[i].toString('hex')])),
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'tpm_pcr_digest_mismatch');
});

test('sealLicenseKeyForClient produces a structurally valid sealed payload', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const pcrMap = makePcrValues('seal');
    const sealed = tpmQuote.sealLicenseKeyForClient(crypto.randomBytes(32), env.ekKeyPair.publicKey, pcrMap);
    assert.equal(typeof sealed.policyDigest, 'string');
    assert.equal(sealed.policyDigest.length, 64);
    assert.ok(sealed.wrappedEphemeral.length > 64);
    assert.ok(sealed.ciphertext.length > 0);
    assert.equal(sealed.iv.length, 24);
    assert.equal(sealed.tag.length, 32);
    assert.deepEqual(sealed.pcrIndices, tpmQuote.REQUIRED_PCR_INDICES);
});

test('hwid component derivation includes EK + PCR + existing anchor', () => {
    ekRoots.clearForTests();
    const env = generateSyntheticEnvironment();
    const pcrMap = makePcrValues('hwid');
    const a = tpmQuote.deriveTpmHwidComponent(env.ekKeyPair.publicKey, pcrMap, 'anchor-A');
    const b = tpmQuote.deriveTpmHwidComponent(env.ekKeyPair.publicKey, pcrMap, 'anchor-B');
    const c = tpmQuote.deriveTpmHwidComponent(env.ekKeyPair.publicKey, pcrMap, 'anchor-A');
    assert.notEqual(a, b);
    assert.equal(a, c);
});
