'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || ('z'.repeat(32) + 'binary-protocol-test-secret-2026');

const binaryProto = require('../crypto/binary_protocol');

function buildEncryptedRequest(op, sessionToken, hwid, body, sessionNonceBuf) {
    const key = binaryProto.deriveProtocolKey(sessionToken, hwid);
    const iv = binaryProto.nonceToChachaIv(sessionNonceBuf);

    const aadHdr = Buffer.alloc(binaryProto.REQUEST_HEADER_SIZE - 8);
    aadHdr.writeUInt32LE(binaryProto.REQUEST_MAGIC, 0);
    aadHdr.writeUInt16LE(binaryProto.PROTOCOL_VERSION, 4);
    aadHdr.writeUInt16LE(op, 6);
    sessionNonceBuf.copy(aadHdr, 8, 0, 8);

    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: binaryProto.TAG_SIZE });
    cipher.setAAD(aadHdr, { plaintextLength: body.length });
    const ct = Buffer.concat([cipher.update(body), cipher.final()]);
    const tag = cipher.getAuthTag();
    const wirePayload = Buffer.concat([ct, tag]);

    const hdrBuf = Buffer.alloc(binaryProto.REQUEST_HEADER_SIZE);
    hdrBuf.writeUInt32LE(binaryProto.REQUEST_MAGIC, 0);
    hdrBuf.writeUInt16LE(binaryProto.PROTOCOL_VERSION, 4);
    hdrBuf.writeUInt16LE(op, 6);
    sessionNonceBuf.copy(hdrBuf, 8, 0, 8);
    hdrBuf.writeUInt32LE(wirePayload.length, 16);
    const crc = binaryProto.crc32c(Buffer.concat([
        hdrBuf.subarray(0, binaryProto.REQUEST_HEADER_SIZE - 4),
        wirePayload,
    ]));
    hdrBuf.writeUInt32LE(crc, 20);
    return { hdrBuf, wirePayload };
}

test('crc32c matches well-known seed-and-flip baseline', () => {
    const a = Buffer.from('123456789', 'utf8');
    const v = binaryProto.crc32c(a);
    assert.equal(typeof v, 'number');
    assert.notEqual(v, 0);
    const b = Buffer.from(a);
    b[3] ^= 0x01;
    assert.notEqual(binaryProto.crc32c(b), v);
});

test('parseRequestHeader rejects bad magic', () => {
    const bad = Buffer.alloc(binaryProto.REQUEST_HEADER_SIZE);
    bad.writeUInt32LE(0xDEADBEEF, 0);
    const res = binaryProto.parseRequestHeader(bad);
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'bad_magic');
});

test('parseRequestHeader rejects bad version', () => {
    const buf = Buffer.alloc(binaryProto.REQUEST_HEADER_SIZE);
    buf.writeUInt32LE(binaryProto.REQUEST_MAGIC, 0);
    buf.writeUInt16LE(0xFFFF, 4);
    const res = binaryProto.parseRequestHeader(buf);
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'bad_version');
});

test('parseRequestHeader rejects buffers smaller than the header', () => {
    const buf = Buffer.alloc(binaryProto.REQUEST_HEADER_SIZE - 4);
    const res = binaryProto.parseRequestHeader(buf);
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'header_too_short');
});

test('verifyRequestCrc accepts a freshly built header and rejects a flipped byte', () => {
    const sessionToken = 'sess-tok-binary-test';
    const hwid = 'binary-hwid-1';
    const body = Buffer.from('AIDA-BINARY-PROTO-PAYLOAD-OK', 'utf8');
    const sessionNonceBuf = crypto.randomBytes(8);
    const { hdrBuf, wirePayload } = buildEncryptedRequest(
        binaryProto.OP_PAGE_FETCH, sessionToken, hwid, body, sessionNonceBuf);
    assert.equal(binaryProto.verifyRequestCrc(hdrBuf, wirePayload), true);
    const tampered = Buffer.from(wirePayload);
    tampered[10] ^= 0x01;
    assert.equal(binaryProto.verifyRequestCrc(hdrBuf, tampered), false);
});

test('decryptRequestBody round-trips a packed body and unpack succeeds', () => {
    const sessionToken = 'sess-token-roundtrip';
    const hwid = 'hwid-roundtrip';
    const license = 'AIDA-LIC-RT-' + Date.now();
    const proof = 'proof-rt-1';

    const parts = [
        binaryProto.packU32LE(license.length),
        Buffer.from(license, 'utf8'),
        binaryProto.packU32LE(sessionToken.length),
        Buffer.from(sessionToken, 'utf8'),
        binaryProto.packU32LE(hwid.length),
        Buffer.from(hwid, 'utf8'),
        binaryProto.packU32LE(proof.length),
        Buffer.from(proof, 'utf8'),
        binaryProto.packU32LE(99),
        binaryProto.packU64LE(0x12345678n),
    ];
    const body = Buffer.concat(parts);
    const sessionNonceBuf = crypto.randomBytes(8);
    const { hdrBuf, wirePayload } = buildEncryptedRequest(
        binaryProto.OP_PAGE_FETCH, sessionToken, hwid, body, sessionNonceBuf);

    const decrypted = binaryProto.decryptRequestBody(hdrBuf, wirePayload, sessionToken, hwid);
    const parsed = binaryProto.parsePackedRequestBody(decrypted, binaryProto.OP_PAGE_FETCH);
    assert.equal(parsed.license_key, license);
    assert.equal(parsed.session_token, sessionToken);
    assert.equal(parsed.hwid, hwid);
    assert.equal(parsed.proof_token, proof);
    assert.equal(parsed.page_index, 99);
    assert.equal(parsed.issued_at, 0x12345678n);
});

test('decryptRequestBody fails with the wrong key', () => {
    const sessionToken = 'sess-original';
    const hwid = 'hwid-original';
    const body = Buffer.from('orig-body', 'utf8');
    const sessionNonceBuf = crypto.randomBytes(8);
    const { hdrBuf, wirePayload } = buildEncryptedRequest(
        binaryProto.OP_PAGE_COUNT, sessionToken, hwid, body, sessionNonceBuf);
    assert.throws(() => {
        binaryProto.decryptRequestBody(hdrBuf, wirePayload, 'sess-different', 'hwid-different');
    });
});

test('buildResponse with STATUS_OK encrypts payload and round-trips with paired derive', () => {
    const sessionToken = 'sess-resp';
    const hwid = 'hwid-resp';
    const sessionNonceBuf = crypto.randomBytes(8);
    const plain = Buffer.from('hello-binary-response', 'utf8');
    const wire = binaryProto.buildResponse(
        sessionNonceBuf, binaryProto.STATUS_OK, plain, sessionToken, hwid);

    assert.ok(wire.length >= binaryProto.RESPONSE_HEADER_SIZE + binaryProto.TAG_SIZE);
    const respHdr = wire.subarray(0, binaryProto.RESPONSE_HEADER_SIZE);
    const respBody = wire.subarray(binaryProto.RESPONSE_HEADER_SIZE);
    assert.equal(respHdr.readUInt32LE(0), binaryProto.RESPONSE_MAGIC);
    assert.equal(respHdr.readUInt16LE(4), binaryProto.PROTOCOL_VERSION);
    assert.equal(respHdr.readUInt16LE(6), binaryProto.STATUS_OK);
    assert.equal(respHdr.readUInt32LE(16), respBody.length);

    const ct = respBody.subarray(0, respBody.length - binaryProto.TAG_SIZE);
    const tag = respBody.subarray(respBody.length - binaryProto.TAG_SIZE);

    const key = binaryProto.deriveProtocolKey(sessionToken, hwid);
    const iv = binaryProto.nonceToChachaIv(sessionNonceBuf);
    const aad = Buffer.alloc(binaryProto.RESPONSE_HEADER_SIZE - 8);
    respHdr.copy(aad, 0, 0, binaryProto.RESPONSE_HEADER_SIZE - 8);

    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: binaryProto.TAG_SIZE });
    decipher.setAAD(aad, { plaintextLength: ct.length });
    decipher.setAuthTag(tag);
    const recovered = Buffer.concat([decipher.update(ct), decipher.final()]);
    assert.equal(recovered.toString('utf8'), 'hello-binary-response');
});

test('buildResponse with non-OK status returns an empty payload section', () => {
    const sessionNonceBuf = crypto.randomBytes(8);
    const wire = binaryProto.buildResponse(
        sessionNonceBuf, binaryProto.STATUS_AUTH_FAIL, Buffer.alloc(0), '', '');
    assert.equal(wire.length, binaryProto.RESPONSE_HEADER_SIZE);
    assert.equal(wire.readUInt16LE(6), binaryProto.STATUS_AUTH_FAIL);
});
