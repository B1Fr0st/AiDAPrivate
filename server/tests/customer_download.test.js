'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const botKeys = crypto.generateKeyPairSync('ed25519');
const serverKeys = crypto.generateKeyPairSync('ed25519');
process.env.BOT_ED25519_PUBLIC_KEY_B64 = botKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
process.env.ED25519_PRIVATE_KEY_B64 = serverKeys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
process.env.SERVER_MASTER_KEY_B64 = crypto.randomBytes(32).toString('base64');
process.env.AIDA_PUBLIC_ORIGIN = 'https://api.aidapro.net';
process.env.AIDA_CUSTOMER_DOWNLOAD_TOKEN_TTL_SECONDS = '300';
process.env.AIDA_STANDALONE_BASE_VERSION = '2026.6.test';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-customer-download-'));
const basePath = path.join(tmpDir, 'AiDAStandalone.base.exe');
process.env.AIDA_STANDALONE_BASE_EXE = basePath;

function makeProtectedBase() {
    const buf = Buffer.alloc(0x800, 0);
    buf.writeUInt16LE(0x5A4D, 0);
    buf.writeUInt32LE(0x80, 0x3c);
    buf.writeUInt32LE(0x00004550, 0x80);
    buf.writeUInt16LE(0x8664, 0x84);
    buf.writeUInt16LE(1, 0x86);
    buf.writeUInt16LE(0xF0, 0x94);
    buf.writeUInt16LE(0x020B, 0x98);
    const sec = 0x80 + 24 + 0xF0;
    Buffer.from('.packed\0', 'ascii').copy(buf, sec);
    buf.writeUInt32LE(0x400, sec + 8);
    buf.writeUInt32LE(0x1000, sec + 12);
    buf.writeUInt32LE(0x400, sec + 16);
    buf.writeUInt32LE(0x200, sec + 20);
    const packed = 0x200;
    const aux = 0x280;
    buf.writeUInt32LE(0x41504B44, packed);
    buf.writeUInt32LE(0x00030000, packed + 4);
    buf.writeUInt32LE(aux - packed, packed + 60);
    buf.writeUInt32LE(368, packed + 64);
    buf.writeUInt32LE(0x4D585541, aux);
    buf.writeUInt32LE(0x00030000, aux + 4);
    Buffer.alloc(16, 0x11).copy(buf, aux + 24);
    Buffer.alloc(32, 0x22).copy(buf, aux + 40);
    return buf;
}

const baseExe = makeProtectedBase();
fs.writeFileSync(basePath, baseExe);

const state = {
    queries: [],
    botNonces: new Set(),
    tokenRow: null,
    capsuleRows: [],
    downloads: [],
    licenses: [],
    updateRowCount: 1,
};

function futureEpoch() {
    return Math.floor(Date.now() / 1000) + 86400;
}

function resetState() {
    state.queries.length = 0;
    state.botNonces = new Set();
    state.tokenRow = null;
    state.capsuleRows = [];
    state.downloads = [];
    state.licenses = [{
        key: 'AIDA-1111-2222-3333-4444',
        active: true,
        hwid: 'a'.repeat(64),
        expires: '',
        expires_epoch: futureEpoch(),
        revoked_at: null,
        plan: 'pro',
        tier: 'customer',
        discord_id: '1515754127110438922',
    }];
    state.updateRowCount = 1;
    customer._resetForTests();
}

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async (sql, params) => {
            const text = String(sql);
            state.queries.push({ sql: text, params });
            if (/CREATE TABLE IF NOT EXISTS customer_download_tokens/i.test(text)) return { rows: [], rowCount: 0 };
            if (/CREATE TABLE IF NOT EXISTS standalone_customer_capsules/i.test(text)) return { rows: [], rowCount: 0 };
            if (/ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_/i.test(text)) return { rows: [], rowCount: 0 };
            if (/CREATE INDEX IF NOT EXISTS idx_customer_/i.test(text)) return { rows: [], rowCount: 0 };
            if (/INSERT INTO bot_command_log/i.test(text)) {
                if (state.botNonces.has(params[0])) {
                    const err = new Error('duplicate');
                    err.code = '23505';
                    throw err;
                }
                state.botNonces.add(params[0]);
                return { rows: [], rowCount: 1 };
            }
            if (/FROM licenses\s+WHERE discord_id = \$1/i.test(text)) {
                const rows = state.licenses.filter(row => row.discord_id === params[0]).map(row => Object.assign({}, row));
                return { rows, rowCount: rows.length };
            }
            if (/INSERT INTO customer_download_tokens/i.test(text)) {
                state.tokenRow = {
                    token_id: params[0],
                    token_hmac: params[1],
                    license_key: params[2],
                    discord_id: params[3],
                    customer_role_id: params[4],
                    issued_at: params[5],
                    expires_at: params[6],
                    consumed: false,
                    source_ip: params[7],
                    user_agent_hash: params[8],
                    capsule_id: '',
                };
                return { rows: [], rowCount: 1 };
            }
            if (/SELECT \* FROM customer_download_tokens WHERE token_id = \$1/i.test(text)) {
                if (state.tokenRow && state.tokenRow.token_id === params[0]) {
                    return { rows: [Object.assign({}, state.tokenRow)], rowCount: 1 };
                }
                return { rows: [], rowCount: 0 };
            }
            if (/INSERT INTO standalone_customer_capsules/i.test(text)) {
                state.capsuleRows.push({ params });
                return { rows: [], rowCount: 1 };
            }
            if (/UPDATE customer_download_tokens/i.test(text)) {
                if (/SET capsule_id/i.test(text)) {
                    if (state.tokenRow && state.tokenRow.token_id === params[1]) {
                        state.tokenRow.capsule_id = params[0];
                        return { rows: [], rowCount: 1 };
                    }
                    return { rows: [], rowCount: 0 };
                }
                const ok = state.updateRowCount === 1
                    && state.tokenRow
                    && state.tokenRow.token_id === params[1]
                    && state.tokenRow.token_hmac === params[2]
                    && !state.tokenRow.consumed
                    && state.tokenRow.expires_at >= params[0];
                if (ok) {
                    state.tokenRow.consumed = true;
                    state.tokenRow.consumed_at = params[0];
                    return { rows: [], rowCount: 1 };
                }
                return { rows: [], rowCount: 0 };
            }
            if (/UPDATE licenses\s+SET standalone_capsule_required/i.test(text)) {
                return { rows: [], rowCount: 1 };
            }
            if (/INSERT INTO downloads/i.test(text)) {
                state.downloads.push({ params });
                return { rows: [], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
        },
        end: async () => {},
    },
};

const botAuth = require('../middleware/bot_auth');
const customerModule = require('../routes/customer_download');
const customer = customerModule._internal;
const capsuleHelper = require('../crypto/customer_capsule');

function nonce() {
    return crypto.randomBytes(32).toString('hex');
}

function signedReq(body, key) {
    const canonical = botAuth.canonicalize(body);
    const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), key || botKeys.privateKey).toString('base64');
    return {
        body,
        headers: {
            'x-bot-signature': signature,
            'user-agent': 'node-test',
        },
        ip: '127.0.0.1',
        socket: { remoteAddress: '127.0.0.1' },
    };
}

function issueBody(overrides) {
    return Object.assign({
        action: customer.ACTION,
        customer_role_id: customer.CUSTOMER_ROLE_ID,
        discord_id: '1515754127110438922',
        nonce: nonce(),
        ts: Math.floor(Date.now() / 1000),
    }, overrides || {});
}

function extractToken(url) {
    const m = /\/d\/a\/(AIDADL\.v1\.[0-9a-f]{32}\.[0-9a-f]{64})$/i.exec(url);
    assert.ok(m);
    return m[1];
}

test.beforeEach(() => {
    resetState();
});

test('issue rejects invalid bot auth, action mismatch, and missing customer role', async () => {
    let result = await customer.issueRequest(signedReq(issueBody(), serverKeys.privateKey), '127.0.0.1', 'ua');
    assert.equal(result.status, 403);
    assert.deepEqual(result.body, { status: 'error', reason: 'EAUTH' });

    result = await customer.issueRequest(signedReq(issueBody({ action: 'other_action' })), '127.0.0.1', 'ua');
    assert.equal(result.status, 403);
    assert.deepEqual(result.body, { status: 'error', reason: 'EAUTH' });

    result = await customer.issueRequest(signedReq(issueBody({ customer_role_id: '1' })), '127.0.0.1', 'ua');
    assert.equal(result.status, 403);
    assert.deepEqual(result.body, { status: 'error', reason: 'EAUTH' });
});

test('issue fails closed generically for no, multiple, inactive, revoked, and expired licenses', async () => {
    for (const rows of [
        [],
        [
            Object.assign({}, state.licenses[0], { key: 'AIDA-AAAA-BBBB-CCCC-DDDD' }),
            Object.assign({}, state.licenses[0], { key: 'AIDA-EEEE-FFFF-GGGG-HHHH' }),
        ],
        [Object.assign({}, state.licenses[0], { active: false })],
        [Object.assign({}, state.licenses[0], { revoked_at: 1 })],
        [Object.assign({}, state.licenses[0], { expires_epoch: Math.floor(Date.now() / 1000) - 1 })],
    ]) {
        resetState();
        state.licenses = rows;
        const result = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
        assert.equal(result.status, 403);
        assert.deepEqual(result.body, { status: 'error', reason: 'EAUTH' });
    }
});

test('issue stores only token HMAC and returns no license key', async () => {
    const result = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    assert.equal(result.status, 200);
    assert.equal(result.body.status, 'ok');
    assert.match(result.body.url, /^https:\/\/api\.aidapro\.net\/d\/a\/AIDADL\.v1\./);
    assert.equal(result.body.expires_in, 300);
    assert.match(state.tokenRow.token_hmac, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(state.tokenRow).includes(extractToken(result.body.url)), false);
    assert.equal(JSON.stringify(result.body).includes(state.licenses[0].key), false);
});

test('landing page does not consume the one-time token', async () => {
    const issued = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    const token = extractToken(issued.body.url);
    const landing = await customer.landingRequest(token);
    assert.equal(landing.status, 200);
    assert.match(landing.body, /AiDA Standalone/);
    assert.equal(state.tokenRow.consumed, false);
    assert.equal(state.queries.some(q => /UPDATE customer_download_tokens/i.test(q.sql)), false);
});

test('redeem consumes exactly once and replay fails generically', async () => {
    const issued = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    const token = extractToken(issued.body.url);
    const first = await customer.redeemRequest({ token }, '127.0.0.1', 'ua');
    assert.equal(first.status, 200);
    assert.ok(Buffer.isBuffer(first.body));
    assert.equal(state.tokenRow.consumed, true);
    assert.equal(state.capsuleRows.length, 1);

    const second = await customer.redeemRequest({ token }, '127.0.0.1', 'ua');
    assert.equal(second.status, 401);
    assert.deepEqual(second.body, { status: 'error', reason: 'EAUTH' });
});

test('expired token redemption fails generically without consuming', async () => {
    const issued = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    const token = extractToken(issued.body.url);
    state.tokenRow.expires_at = Math.floor(Date.now() / 1000) - 1;
    const result = await customer.redeemRequest({ token }, '127.0.0.1', 'ua');
    assert.equal(result.status, 401);
    assert.deepEqual(result.body, { status: 'error', reason: 'EAUTH' });
    assert.equal(state.tokenRow.consumed, false);
    assert.equal(state.capsuleRows.length, 0);
});

test('redeem output keeps base prefix, appends signed capsule, omits full license, and patches aux', async () => {
    const issued = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    const token = extractToken(issued.body.url);
    const result = await customer.redeemRequest({ token }, '127.0.0.1', 'ua');
    assert.equal(result.status, 200);
    assert.equal(result.body.subarray(0, 0x200).equals(baseExe.subarray(0, 0x200)), true);
    assert.equal(result.body.length > baseExe.length, true);

    const footer = capsuleHelper.parseFooter(result.body);
    assert.ok(footer);
    assert.equal(footer.footer_version, 1);
    assert.equal(footer.signature_alg, 'Ed25519');
    assert.match(footer.signature_hex, /^[0-9a-f]+$/);
    assert.equal(footer.capsule.base_sha256, crypto.createHash('sha256').update(result.body.subarray(0, baseExe.length)).digest('hex'));
    assert.equal(footer.base_sha256, footer.capsule.base_sha256);
    assert.equal(footer.capsule_sha256, state.capsuleRows[0].params[12]);
    assert.equal(footer.capsule.base_size, baseExe.length);
    assert.equal(footer.capsule.base_version, '2026.6.test');
    assert.equal(footer.capsule.aux_patched, true);
    assert.equal(JSON.stringify(footer).includes(state.licenses[0].key), false);
    assert.match(footer.capsule.license_identity_hash, /^[0-9a-f]{64}$/);
    assert.match(footer.capsule.discord_identity_hash, /^[0-9a-f]{64}$/);
    assert.match(footer.capsule.hwid_hash, /^[0-9a-f]{64}$/);
    assert.match(footer.capsule.secret_b64u, /^[A-Za-z0-9_-]+$/);
    assert.match(footer.capsule.secret_b64, /^[A-Za-z0-9+/]+={0,2}$/);
    assert.equal(footer.capsule.signature_kid, 1);
    assert.equal(footer.capsule.kid, 1);

    const aux = 0x280;
    const marker = Buffer.from(footer.capsule.marker_hex, 'hex');
    assert.equal(result.body.subarray(aux + 24, aux + 40).equals(marker), true);
    const markerHash = crypto.createHash('sha256').update(marker).digest();
    assert.equal(result.body.subarray(aux + 40, aux + 72).equals(markerHash), true);
});
