'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const botKeys = crypto.generateKeyPairSync('ed25519');
const serverKeys = crypto.generateKeyPairSync('ed25519');
process.env.BOT_ED25519_PUBLIC_KEY_B64 = botKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
process.env.ED25519_PRIVATE_KEY_B64 = serverKeys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
process.env.SERVER_MASTER_KEY_B64 = crypto.randomBytes(32).toString('base64');
process.env.AIDA_PUBLIC_ORIGIN = 'https://api.aidapro.net';
process.env.AIDA_CUSTOMER_DOWNLOAD_TOKEN_TTL_SECONDS = '300';

const state = {
    queries: [],
    botNonces: new Set(),
    tokenRow: null,
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
                };
                return { rows: [], rowCount: 1 };
            }
            if (/SELECT \* FROM customer_download_tokens WHERE token_id = \$1/i.test(text)) {
                if (state.tokenRow && state.tokenRow.token_id === params[0]) {
                    return { rows: [Object.assign({}, state.tokenRow)], rowCount: 1 };
                }
                return { rows: [], rowCount: 0 };
            }
            if (/UPDATE customer_download_tokens/i.test(text)) {
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
    assert.equal(result.body.delivery, 'approved_bootstrap');
    assert.equal(result.body.bootstrap_url, 'https://api.aidapro.net');
    assert.equal(result.body.public_standalone_executable, false);
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
    assert.match(landing.body, /AiDA Bootstrap/);
    assert.match(landing.body, /Show Bootstrap Command/);
    assert.equal(state.tokenRow.consumed, false);
    assert.equal(state.queries.some(q => /UPDATE customer_download_tokens/i.test(q.sql)), false);
});

test('redeem consumes exactly once and replay fails generically', async () => {
    const issued = await customer.issueRequest(signedReq(issueBody()), '127.0.0.1', 'ua');
    const token = extractToken(issued.body.url);
    const first = await customer.redeemRequest({ token }, '127.0.0.1', 'ua');
    assert.equal(first.status, 200);
    assert.equal(first.body.status, 'ok');
    assert.equal(first.body.delivery, 'approved_bootstrap');
    assert.equal(first.body.bootstrap_url, 'https://api.aidapro.net');
    assert.equal(first.body.bootstrap_script_url, 'https://api.aidapro.net');
    assert.equal(first.body.bootstrap_command, 'irm https://api.aidapro.net | iex');
    assert.equal(first.body.public_standalone_executable, false);
    assert.equal(first.body.delivery_model, 'disk_backed_bootstrap_with_verified_camoufox_sidecar');
    assert.equal(state.tokenRow.consumed, true);
    assert.equal(state.downloads.length, 1);
    assert.equal(state.downloads[0].params[3], 'bootstrap');

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
    assert.equal(state.downloads.length, 0);
});
