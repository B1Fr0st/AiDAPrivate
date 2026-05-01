'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || ('a'.repeat(32) + 'functions-route-test-secret');
process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');
{
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-prologue-'));
const prologuePath = path.join(tmpDir, 'aida_core_prologues.json');
const fnHash = crypto.createHash('sha256').update('arc_heartbeat').digest('hex');
const prologueBytes = Buffer.from('aabbccddeeff11223344', 'hex');
fs.writeFileSync(prologuePath, JSON.stringify({
    functions: {
        [fnHash]: {
            name: 'arc_heartbeat',
            bytes: prologueBytes.toString('hex'),
        },
    },
}));
process.env.ARC_PROLOGUE_PATH = prologuePath;
process.env.ARC_BLOB_PATH = path.join(tmpDir, 'aida_core.bin');

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        query: async () => ({ rows: [], rowCount: 0 }),
        end: async () => {},
    },
};

const expressPath = require.resolve('express');
require.cache[expressPath] = {
    id: expressPath,
    filename: expressPath,
    loaded: true,
    exports: Object.assign(() => ({}), {
        Router: () => ({
            post: () => {},
            get: () => {},
            use: () => {},
        }),
    }),
};

const functionsRouter = require('../routes/functions.js');

test('functionAllowed accepts default critical exports', () => {
    assert.equal(functionsRouter._internal.functionAllowed('arc_init'), true);
    assert.equal(functionsRouter._internal.functionAllowed('arc_heartbeat'), true);
    assert.equal(functionsRouter._internal.functionAllowed('arc_validate_tool_exec'), true);
    assert.equal(functionsRouter._internal.functionAllowed('arc_unseal_feature'), true);
    assert.equal(functionsRouter._internal.functionAllowed('arc_internal_helper'), false);
    assert.equal(functionsRouter._internal.functionAllowed(''), false);
    assert.equal(functionsRouter._internal.functionAllowed(null), false);
});

test('lookupPrologue returns the registered bytes for a known hash', () => {
    const prologue = functionsRouter._internal.lookupPrologue(fnHash);
    assert.ok(prologue);
    assert.deepEqual(prologue.bytes, prologueBytes);
    assert.equal(prologue.name, 'arc_heartbeat');
});

test('lookupPrologue returns null for unknown hash', () => {
    const otherHash = crypto.randomBytes(32).toString('hex');
    const result = functionsRouter._internal.lookupPrologue(otherHash);
    assert.equal(result, null);
});

test('purgeExpiredFunctionRecords runs without throwing', async () => {
    await functionsRouter._internal.purgeExpiredFunctionRecords();
    assert.ok(true);
});

test('loadCriticalFunctions honours ARC_CRITICAL_FUNCTIONS env override', () => {
    const original = process.env.ARC_CRITICAL_FUNCTIONS;
    process.env.ARC_CRITICAL_FUNCTIONS = ' arc_x , arc_y ,arc_z, ';
    const list = functionsRouter._internal.loadCriticalFunctions();
    assert.deepEqual(list, ['arc_x', 'arc_y', 'arc_z']);
    if (original === undefined) {
        delete process.env.ARC_CRITICAL_FUNCTIONS;
    } else {
        process.env.ARC_CRITICAL_FUNCTIONS = original;
    }
});
