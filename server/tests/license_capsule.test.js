'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');

process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || Buffer.alloc(32, 0xC7).toString('base64');
process.env.LOCAL_HSM_PATH = process.env.LOCAL_HSM_PATH
    || path.join(os.tmpdir(), `aida-local-hsm-capsule-${process.pid}.bin`);
process.env.LOCAL_HSM_PASSPHRASE = process.env.LOCAL_HSM_PASSPHRASE
    || 'license-capsule-test-passphrase';

const state = { rows: [] };
const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async (sql) => {
            if (String(sql).includes('standalone_customer_capsules')) {
                return { rows: state.rows, rowCount: state.rows.length };
            }
            return { rows: [], rowCount: 0 };
        },
        end: async () => {},
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
        }),
    },
};

const kwWrap = require('../crypto/kw_wrap');
const licenseRouter = require('../routes/license.js');

const key = 'AIDA-CAPSULE-TEST-0001';
const hwid = 'HWID-CAPSULE-TEST';
const capsuleId = 'cap-test-0001';
const baseSha = '11'.repeat(32);
const capsuleSha = '22'.repeat(32);
const secret = Buffer.from('capsule proof secret material 0001', 'utf8');

function row(overrides = {}) {
    return Object.assign({
        license_key: key,
        capsule_id: capsuleId,
        base_sha256: baseSha,
        capsule_sha256: capsuleSha,
        capsule_secret_wrapped: kwWrap.wrap(secret, 'standalone_capsule_secret/v1'),
        active: true,
    }, overrides);
}

function proofFor(action, body, overrides = {}) {
    const proof = Object.assign({
        capsule_id: capsuleId,
        base_sha256: baseSha,
        capsule_sha256: capsuleSha,
        proof_nonce: 'aa'.repeat(16),
        proof_ts: Math.floor(Date.now() / 1000),
    }, overrides);
    const fields = {
        license_key: key,
        hwid,
        client_nonce: body.client_nonce || '',
        session_token: body.session_token || '',
        heartbeat_nonce: body.heartbeat_nonce || '',
        heartbeat_count: action === 'heartbeat' ? String(Math.max(0, Math.floor(Number(body.heartbeat_count || 0)))) : '',
        req_seq: action === 'heartbeat' ? String(body.req_seq || '') : '',
        capsule_id: proof.capsule_id,
        base_sha256: proof.base_sha256,
        capsule_sha256: proof.capsule_sha256,
        proof_nonce: proof.proof_nonce,
        proof_ts: String(proof.proof_ts),
    };
    proof.proof = crypto.createHmac('sha256', secret)
        .update(licenseRouter._internal.buildStandaloneCapsuleProofMessage(action, fields), 'utf8')
        .digest('hex');
    return proof;
}

test('required standalone capsule missing fails generically', async () => {
    state.rows = [row()];
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key, standalone_capsule_required: true },
        { license_key: key, hwid, client_nonce: '01'.repeat(16) },
        { license_key: key, hwid }
    );
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capsule_missing');
});

test('active standalone capsule row enforces even without license flag', async () => {
    state.rows = [row()];
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key },
        { license_key: key, hwid, client_nonce: '02'.repeat(16) },
        { license_key: key, hwid }
    );
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capsule_missing');
});

test('standalone capsule wrong id fails generically', async () => {
    state.rows = [row()];
    const body = { license_key: key, hwid, client_nonce: '03'.repeat(16) };
    body.standalone_capsule = proofFor('validate', body, { capsule_id: 'cap-wrong-0001' });
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key, standalone_capsule_required: true },
        body,
        { license_key: key, hwid }
    );
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capsule_id_mismatch');
});

test('standalone capsule wrong base fails generically', async () => {
    state.rows = [row()];
    const body = { license_key: key, hwid, client_nonce: '04'.repeat(16) };
    body.standalone_capsule = proofFor('validate', body, { base_sha256: '33'.repeat(32) });
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key, standalone_capsule_required: true },
        body,
        { license_key: key, hwid }
    );
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capsule_base_mismatch');
});

test('standalone capsule wrong proof fails generically', async () => {
    state.rows = [row()];
    const body = { license_key: key, hwid, client_nonce: '05'.repeat(16) };
    body.standalone_capsule = proofFor('validate', body);
    body.standalone_capsule.proof = '00'.repeat(32);
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key, standalone_capsule_required: true },
        body,
        { license_key: key, hwid }
    );
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'capsule_proof_mismatch');
});

test('standalone capsule valid validate proof succeeds', async () => {
    state.rows = [row()];
    const body = { license_key: key, hwid, client_nonce: '06'.repeat(16) };
    body.standalone_capsule = proofFor('validate', body);
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'validate',
        { key, standalone_capsule_required: true },
        body,
        { license_key: key, hwid }
    );
    assert.equal(result.ok, true);
    assert.equal(result.enforced, true);
    assert.equal(result.capsule_id, capsuleId);
});

test('standalone capsule valid heartbeat proof succeeds', async () => {
    state.rows = [row()];
    const body = {
        license_key: key,
        session_token: 'session-token-capsule-test',
        hwid,
        heartbeat_nonce: '07'.repeat(16),
        heartbeat_count: 9,
        req_seq: '44',
    };
    body.standalone_capsule = proofFor('heartbeat', body);
    const result = await licenseRouter._internal.enforceStandaloneCapsuleProof(
        'heartbeat',
        { key, standalone_capsule_required: true },
        body,
        { license_key: key, hwid }
    );
    assert.equal(result.ok, true);
    assert.equal(result.enforced, true);
    assert.equal(result.capsule_id, capsuleId);
});
