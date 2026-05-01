'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const tablesEnsured = { v: false };
const fakeDb = {
    licenses: new Map(),
    sessions: new Map(),
    fetches: new Map(),
    prologues: new Map(),
    violations: [],
};

function fetchKey(licKey, sessTok, fnHash, fetchId) {
    return `${licKey}|${sessTok}|${fnHash}|${fetchId}`;
}

function pgMockQuery(sql, params) {
    const trimmed = sql.replace(/\s+/g, ' ').trim();

    if (/^CREATE TABLE/i.test(trimmed) || /^CREATE INDEX/i.test(trimmed) || /^ALTER TABLE/i.test(trimmed)) {
        tablesEnsured.v = true;
        return Promise.resolve({ rows: [], rowCount: 0 });
    }

    if (trimmed.startsWith('SELECT * FROM licenses WHERE key =')) {
        const lic = fakeDb.licenses.get(params[0]);
        return Promise.resolve({ rows: lic ? [lic] : [], rowCount: lic ? 1 : 0 });
    }

    if (trimmed.startsWith('SELECT * FROM sessions WHERE license_key =')) {
        const key = `${params[0]}|${params[1]}`;
        const sess = fakeDb.sessions.get(key);
        return Promise.resolve({ rows: sess ? [sess] : [], rowCount: sess ? 1 : 0 });
    }

    if (/SELECT COUNT\(\*\)::INT AS c FROM stolen_bytes_fetches/i.test(trimmed)) {
        const [licKey, sessTok, fnHash, since] = params;
        let c = 0;
        for (const row of fakeDb.fetches.values()) {
            if (row.license_key === licKey && row.session_token === sessTok
                && row.function_hash === fnHash && row.issued_at >= since) {
                c++;
            }
        }
        return Promise.resolve({ rows: [{ c }], rowCount: 1 });
    }

    if (/SELECT consumed FROM stolen_bytes_fetches/i.test(trimmed)) {
        const [licKey, sessTok, fnHash, fetchId] = params;
        const row = fakeDb.fetches.get(fetchKey(licKey, sessTok, fnHash, fetchId));
        if (!row) return Promise.resolve({ rows: [], rowCount: 0 });
        return Promise.resolve({ rows: [{ consumed: row.consumed }], rowCount: 1 });
    }

    if (/INSERT INTO stolen_bytes_fetches/i.test(trimmed)) {
        const [licKey, sessTok, fnHash, fetchId, clientNonce, issuedAt, validUntil] = params;
        fakeDb.fetches.set(fetchKey(licKey, sessTok, fnHash, fetchId), {
            license_key: licKey,
            session_token: sessTok,
            function_hash: fnHash,
            fetch_id: fetchId,
            client_nonce: clientNonce,
            issued_at: issuedAt,
            valid_until: validUntil,
            consumed: true,
            consumed_at: issuedAt,
        });
        return Promise.resolve({ rows: [], rowCount: 1 });
    }

    if (/SELECT prologue FROM stolen_bytes_prologues/i.test(trimmed)) {
        const [licKey, fnHash] = params;
        const buf = fakeDb.prologues.get(`${licKey}|${fnHash}`);
        if (!buf) return Promise.resolve({ rows: [], rowCount: 0 });
        return Promise.resolve({ rows: [{ prologue: buf }], rowCount: 1 });
    }

    if (/INSERT INTO stolen_bytes_prologues/i.test(trimmed)) {
        const [licKey, fnHash, prologueBuf] = params;
        fakeDb.prologues.set(`${licKey}|${fnHash}`, prologueBuf);
        return Promise.resolve({ rows: [], rowCount: 1 });
    }

    if (/UPDATE licenses SET stolen_bytes_flag_count/i.test(trimmed)) {
        const [, licKey] = params;
        const lic = fakeDb.licenses.get(licKey);
        if (lic) {
            lic.stolen_bytes_flag_count = (lic.stolen_bytes_flag_count || 0) + 1;
            lic.stolen_bytes_status = 'flagged';
        }
        return Promise.resolve({ rows: [], rowCount: 1 });
    }

    if (/INSERT INTO violations/i.test(trimmed)) {
        fakeDb.violations.push(params);
        return Promise.resolve({ rows: [], rowCount: 1 });
    }

    if (/^DELETE FROM stolen_bytes_fetches/i.test(trimmed)) {
        return Promise.resolve({ rows: [], rowCount: 0 });
    }

    return Promise.resolve({ rows: [], rowCount: 0 });
}

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: { query: pgMockQuery, end: async () => {} },
};

const signingPath = require.resolve('../crypto/signing');
require.cache[signingPath] = {
    id: signingPath,
    filename: signingPath,
    loaded: true,
    exports: {
        signPayload: () => 'sig_test_stub_64bytes_'.padEnd(128, '0'),
        dualSignPayload: () => ({ signature: 'sig_test_stub_64bytes_'.padEnd(128, '0') }),
        getSigningPrivateKey: () => null,
        getNextSigningPrivateKey: () => null,
        sortObjectKeys: o => o,
        clearKeyCache: () => {},
    },
};

const expressPath = require.resolve('express');
require.cache[expressPath] = {
    id: expressPath,
    filename: expressPath,
    loaded: true,
    exports: {
        Router: () => ({
            post: () => {},
            get: () => {},
            use: () => {},
        }),
    },
};

process.env.STOLEN_BYTES_MASTER_SECRET = 'test_master_secret_for_stolen_bytes_at_least_32bytes_in_length_xx';
process.env.ADMIN_API_KEY = 'admin_test_key_for_register';

const stolenBytesRouter = require('../routes/stolen_bytes.js');

const TEST_LICENSE = 'AIDA-AAAA-BBBB-CCCC-DDDD';
const TEST_SESSION_TOKEN = 'session_token_for_stolen_bytes_test_64chars_aaaaaaaaaaaaaaaaaa';
const TEST_FN_HASH = '0123456789abcdef';
const TEST_PROLOGUE = Buffer.from([0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xC1, 0x90, 0x90, 0x90]);

function seedFakeDb() {
    fakeDb.licenses.set(TEST_LICENSE, {
        key: TEST_LICENSE,
        active: true,
        plan: 'pro',
        hwid: 'TEST-HWID-1234',
    });
    const issuedAt = Math.floor(Date.now() / 1000) - 60;
    fakeDb.sessions.set(`${TEST_LICENSE}|${TEST_SESSION_TOKEN}`, {
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        kill_flag: false,
        issued_at: issuedAt,
        ttl: 3600,
        hwid: 'TEST-HWID-1234',
    });
}

function clearFakeDb() {
    fakeDb.licenses.clear();
    fakeDb.sessions.clear();
    fakeDb.fetches.clear();
    fakeDb.prologues.clear();
    fakeDb.violations.length = 0;
}

test('stolen_bytes /register stores plaintext prologue for license', async () => {
    clearFakeDb();
    seedFakeDb();
    const result = await stolenBytesRouter._internal.handleRegister({
        admin_key: 'admin_test_key_for_register',
        license_key: TEST_LICENSE,
        function_hash: TEST_FN_HASH,
        prologue_b64: TEST_PROLOGUE.toString('base64'),
    }, '127.0.0.1');
    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'ok');
    assert.equal(result.body.registered, true);
    assert.deepEqual(fakeDb.prologues.get(`${TEST_LICENSE}|${TEST_FN_HASH}`), TEST_PROLOGUE);
});

test('stolen_bytes /fetch returns AES-GCM encrypted prologue on first call', async () => {
    clearFakeDb();
    seedFakeDb();
    fakeDb.prologues.set(`${TEST_LICENSE}|${TEST_FN_HASH}`, TEST_PROLOGUE);

    const nonce = crypto.randomBytes(8).toString('hex');
    const result = await stolenBytesRouter._internal.handleFetch({
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: TEST_FN_HASH,
        nonce,
    }, '127.0.0.1');

    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'ok');
    assert.equal(result.body.prologue_len, TEST_PROLOGUE.length);
    assert.ok(typeof result.body.ciphertext_b64 === 'string' && result.body.ciphertext_b64.length > 0);
    assert.ok(typeof result.body.tag_b64 === 'string' && result.body.tag_b64.length > 0);
    assert.ok(typeof result.body.iv_b64 === 'string' && result.body.iv_b64.length > 0);
    assert.ok(typeof result.body.ephemeral_key_b64 === 'string' && result.body.ephemeral_key_b64.length > 0);

    const ct = Buffer.from(result.body.ciphertext_b64, 'base64');
    const tag = Buffer.from(result.body.tag_b64, 'base64');
    const iv = Buffer.from(result.body.iv_b64, 'base64');
    const key = Buffer.from(result.body.ephemeral_key_b64, 'base64');
    assert.equal(ct.length, TEST_PROLOGUE.length);
    assert.equal(tag.length, 16);
    assert.equal(iv.length, 12);
    assert.equal(key.length, 32);

    const fnHashBuf = Buffer.from(TEST_FN_HASH, 'hex');
    const fetchIdBuf = Buffer.from(result.body.fetch_id, 'hex').slice(0, 8);
    const sessionEpochBuf = Buffer.alloc(8);
    sessionEpochBuf.writeBigUInt64LE(BigInt(fakeDb.sessions.get(`${TEST_LICENSE}|${TEST_SESSION_TOKEN}`).issued_at), 0);
    const aad = Buffer.concat([fnHashBuf, fetchIdBuf, sessionEpochBuf]);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    assert.deepEqual(plaintext, TEST_PROLOGUE);
});

test('stolen_bytes rapid repeat fetches flag the license for review', async () => {
    clearFakeDb();
    seedFakeDb();
    fakeDb.prologues.set(`${TEST_LICENSE}|${TEST_FN_HASH}`, TEST_PROLOGUE);

    const baseBody = {
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: TEST_FN_HASH,
    };

    let firstStatus = '';
    for (let i = 0; i < stolenBytesRouter._internal.RAPID_REPEAT_THRESHOLD; ++i) {
        const r = await stolenBytesRouter._internal.handleFetch({
            ...baseBody,
            nonce: crypto.randomBytes(8).toString('hex'),
        }, '127.0.0.1');
        if (i === 0) firstStatus = r.body.status;
    }
    assert.equal(firstStatus, 'ok');

    const flagged = await stolenBytesRouter._internal.handleFetch({
        ...baseBody,
        nonce: crypto.randomBytes(8).toString('hex'),
    }, '127.0.0.1');

    assert.equal(flagged.status, 200);
    assert.equal(flagged.body.status, 'flagged');
    assert.equal(flagged.body.reason, 'rapid_repeat_fetch');
    assert.ok(flagged.body.recent_fetches >= stolenBytesRouter._internal.RAPID_REPEAT_THRESHOLD);

    assert.equal(fakeDb.licenses.get(TEST_LICENSE).stolen_bytes_status, 'flagged');
    assert.ok(fakeDb.licenses.get(TEST_LICENSE).stolen_bytes_flag_count >= 1);
});

test('stolen_bytes rejects missing fields and invalid nonce/function_hash', async () => {
    clearFakeDb();
    seedFakeDb();

    let r = await stolenBytesRouter._internal.handleFetch({}, '127.0.0.1');
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'missing_fields');

    r = await stolenBytesRouter._internal.handleFetch({
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: 'tooshort',
        nonce: '0123456789abcdef',
    }, '127.0.0.1');
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'invalid_function_hash');

    r = await stolenBytesRouter._internal.handleFetch({
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: TEST_FN_HASH,
        nonce: 'XYZ',
    }, '127.0.0.1');
    assert.equal(r.status, 400);
    assert.equal(r.body.reason, 'invalid_nonce');
});

test('stolen_bytes rejects fetch when license is revoked', async () => {
    clearFakeDb();
    seedFakeDb();
    fakeDb.prologues.set(`${TEST_LICENSE}|${TEST_FN_HASH}`, TEST_PROLOGUE);
    fakeDb.licenses.get(TEST_LICENSE).active = false;

    const result = await stolenBytesRouter._internal.handleFetch({
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: TEST_FN_HASH,
        nonce: crypto.randomBytes(8).toString('hex'),
    }, '127.0.0.1');

    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'invalid');
    assert.equal(result.body.reason, 'license_revoked');
});

test('stolen_bytes rejects fetch when prologue is not registered', async () => {
    clearFakeDb();
    seedFakeDb();

    const result = await stolenBytesRouter._internal.handleFetch({
        license_key: TEST_LICENSE,
        session_token: TEST_SESSION_TOKEN,
        function_hash: TEST_FN_HASH,
        nonce: crypto.randomBytes(8).toString('hex'),
    }, '127.0.0.1');

    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'invalid');
    assert.equal(result.body.reason, 'prologue_not_registered');
});

test('stolen_bytes /register requires admin auth', async () => {
    clearFakeDb();
    seedFakeDb();
    const r = await stolenBytesRouter._internal.handleRegister({
        admin_key: 'wrong-key',
        license_key: TEST_LICENSE,
        function_hash: TEST_FN_HASH,
        prologue_b64: TEST_PROLOGUE.toString('base64'),
    }, '127.0.0.1');
    assert.equal(r.status, 403);
    assert.equal(r.body.reason, 'unauthorized');
});
