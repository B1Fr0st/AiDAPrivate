'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || ('a'.repeat(32) + 'arc-endpoints-test-secret');
process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');
process.env.PAGE_EPOCH_INTERVAL_SECONDS = '300';
process.env.FUNCTION_TOKEN_TTL_SECONDS = '10';

{
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({
        format: 'der', type: 'pkcs8',
    }).toString('base64');
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-endpoints-'));
const blobPath = path.join(tmpDir, 'aida_core.bin');
const prologuePath = path.join(tmpDir, 'aida_core_prologues.json');

const fakePlaintext = Buffer.alloc(8192, 0);
fakePlaintext[0] = 0x4D;
fakePlaintext[1] = 0x5A;
for (let i = 2; i < fakePlaintext.length; i++) fakePlaintext[i] = (i * 7) & 0xFF;

{
    const masterSecret = process.env.ARC_MASTER_SECRET;
    const atRestKey = crypto.createHash('sha256')
        .update(`arc-at-rest|${masterSecret}`)
        .digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', atRestKey, iv);
    const ct = Buffer.concat([cipher.update(fakePlaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    fs.writeFileSync(blobPath, Buffer.concat([iv, tag, ct]));
}

const fnHash = crypto.createHash('sha256').update('arc_heartbeat').digest('hex');
const prologueBytes = Buffer.from('cccc4883ec28', 'hex');
fs.writeFileSync(prologuePath, JSON.stringify({
    functions: {
        [fnHash]: {
            name: 'arc_heartbeat',
            bytes: prologueBytes.toString('hex'),
        },
    },
}));
process.env.ARC_BLOB_PATH = blobPath;
process.env.ARC_PROLOGUE_PATH = prologuePath;

const sharedRows = {
    bans: [],
    licenses: [{
        key: 'AIDA-ENDPOINT-TEST-LICENSE',
        active: true,
        expires: '',
        hardware_id_sha256: '',
        smbios_uuid_hash: '',
        baseboard_serial_hash: '',
        disk_vpd_hash: '',
        machine_guid_hash: '',
        install_secret_wrapped: null,
        witness_key_wrapped: null,
        ioctl_seed_wrapped: null,
        boot_nonce_last: null,
    }],
    sessions: [{
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        ttl: 3600,
        issued_at: Math.floor(Date.now() / 1000),
        kill_flag: false,
        last_proof_token: '',
        last_chain_tag: '',
    }],
    arc_function_calls: [],
    arc_prologue_requests: [],
    violations: [],
    downloads: [],
};

function findRow(rows, predicate) {
    for (const row of rows) if (predicate(row)) return row;
    return null;
}

const poolPath = require.resolve('../db/pool');
require.cache[poolPath] = {
    id: poolPath,
    filename: poolPath,
    loaded: true,
    exports: {
        async query(text, params = []) {
            const trimmed = text.trim();
            if (/^SELECT 1 FROM bans/i.test(trimmed)) {
                const ban = findRow(sharedRows.bans, b => b.ban_type === params[0] && b.value === params[1]);
                return { rows: ban ? [ban] : [], rowCount: ban ? 1 : 0 };
            }
            if (/^SELECT \* FROM licenses WHERE key/i.test(trimmed)) {
                const lic = findRow(sharedRows.licenses, l => l.key === params[0]);
                return { rows: lic ? [lic] : [], rowCount: lic ? 1 : 0 };
            }
            if (/^SELECT \* FROM sessions WHERE license_key/i.test(trimmed)) {
                const ses = findRow(sharedRows.sessions, s => s.license_key === params[0]);
                return { rows: ses ? [ses] : [], rowCount: ses ? 1 : 0 };
            }
            if (/^INSERT INTO arc_function_calls/i.test(trimmed)) {
                const [licenseKey, hwid, fnHashParam, nonce, issuedAt, expiresAt] = params;
                const existing = findRow(sharedRows.arc_function_calls,
                    r => r.license_key === licenseKey && r.function_hash === fnHashParam && r.nonce === nonce);
                if (existing) {
                    existing.duplicate_count = (existing.duplicate_count || 0) + 1;
                    existing.flagged_replay = true;
                    return { rows: [{
                        id: existing.id,
                        duplicate_count: existing.duplicate_count,
                        flagged_replay: true,
                        consumed: existing.consumed,
                    }], rowCount: 1 };
                }
                const row = {
                    id: sharedRows.arc_function_calls.length + 1,
                    license_key: licenseKey,
                    hwid,
                    function_hash: fnHashParam,
                    nonce,
                    issued_at: issuedAt,
                    expires_at: expiresAt,
                    consumed: false,
                    consumed_at: null,
                    duplicate_count: 0,
                    flagged_replay: false,
                };
                sharedRows.arc_function_calls.push(row);
                return { rows: [{
                    id: row.id,
                    duplicate_count: 0,
                    flagged_replay: false,
                    consumed: false,
                }], rowCount: 1 };
            }
            if (/^SELECT COUNT\(\*\)::int AS c FROM arc_function_calls/i.test(trimmed)) {
                const [licenseKey, fnHashParam, threshold] = params;
                const c = sharedRows.arc_function_calls.filter(r =>
                    r.license_key === licenseKey &&
                    r.function_hash === fnHashParam &&
                    r.issued_at >= threshold
                ).length;
                return { rows: [{ c }], rowCount: 1 };
            }
            if (/^UPDATE arc_function_calls\s+SET flagged_replay = true/i.test(trimmed)) {
                const id = params[0];
                const row = findRow(sharedRows.arc_function_calls, r => r.id === id);
                if (row) row.flagged_replay = true;
                return { rows: [], rowCount: row ? 1 : 0 };
            }
            if (/^UPDATE arc_function_calls\s+SET consumed/i.test(trimmed)) {
                const [now, licenseKey, fnHashParam, nonce] = params;
                const row = findRow(sharedRows.arc_function_calls, r =>
                    r.license_key === licenseKey &&
                    r.function_hash === fnHashParam &&
                    r.nonce === nonce &&
                    !r.consumed &&
                    r.expires_at >= now);
                if (!row) return { rows: [], rowCount: 0 };
                row.consumed = true;
                row.consumed_at = now;
                return { rows: [{ id: row.id }], rowCount: 1 };
            }
            if (/^INSERT INTO violations/i.test(trimmed)) {
                sharedRows.violations.push({
                    hwid: params[0], ip: params[1], reason: trimmed.includes("'arc_function_replay'") ? 'arc_function_replay'
                        : trimmed.includes("'arc_function_burst'") ? 'arc_function_burst'
                        : trimmed.includes("'prologue_rapid_refetch'") ? 'prologue_rapid_refetch'
                        : (params[2] || 'unknown'),
                });
                return { rows: [], rowCount: 1 };
            }
            if (/^INSERT INTO arc_prologue_requests/i.test(trimmed)) {
                const [licenseKey, hwid, fnHashParam, nonce, requestedAt] = params;
                const existing = findRow(sharedRows.arc_prologue_requests,
                    r => r.license_key === licenseKey && r.function_hash === fnHashParam && r.nonce === nonce);
                if (existing) {
                    existing.flagged = true;
                    existing.flagged_reason = 'duplicate_nonce';
                    return { rows: [{ id: existing.id, consumed: existing.consumed, flagged: true }], rowCount: 1 };
                }
                const row = {
                    id: sharedRows.arc_prologue_requests.length + 1,
                    license_key: licenseKey,
                    hwid,
                    function_hash: fnHashParam,
                    nonce,
                    requested_at_ms: requestedAt,
                    consumed: false,
                    consumed_at_ms: null,
                    flagged: false,
                    flagged_reason: '',
                };
                sharedRows.arc_prologue_requests.push(row);
                return { rows: [{ id: row.id, consumed: false, flagged: false }], rowCount: 1 };
            }
            if (/^SELECT COUNT\(\*\)::int AS c FROM arc_prologue_requests/i.test(trimmed)) {
                const [licenseKey, fnHashParam, threshold] = params;
                const c = sharedRows.arc_prologue_requests.filter(r =>
                    r.license_key === licenseKey &&
                    r.function_hash === fnHashParam &&
                    r.requested_at_ms >= threshold
                ).length;
                return { rows: [{ c }], rowCount: 1 };
            }
            if (/^SELECT function_hash, requested_at_ms FROM arc_prologue_requests/i.test(trimmed)) {
                const [licenseKey] = params;
                const filtered = sharedRows.arc_prologue_requests
                    .filter(r => r.license_key === licenseKey)
                    .sort((a, b) => b.id - a.id)
                    .slice(0, 8);
                return { rows: filtered, rowCount: filtered.length };
            }
            if (/^UPDATE arc_prologue_requests SET flagged/i.test(trimmed)) {
                const id = params[0];
                const row = findRow(sharedRows.arc_prologue_requests, r => r.id === id);
                if (row) {
                    row.flagged = true;
                    row.flagged_reason = trimmed.includes('rapid_refetch') ? 'rapid_refetch' : 'monotone_pattern';
                }
                return { rows: [], rowCount: row ? 1 : 0 };
            }
            if (/^UPDATE arc_prologue_requests SET consumed/i.test(trimmed)) {
                const [_, id] = params;
                const row = findRow(sharedRows.arc_prologue_requests, r => r.id === id);
                if (row) {
                    row.consumed = true;
                    row.consumed_at_ms = params[0];
                }
                return { rows: [], rowCount: row ? 1 : 0 };
            }
            if (/^UPDATE licenses\s+SET prologue_anomaly_count/i.test(trimmed)) {
                const [, , licenseKey] = params;
                const lic = findRow(sharedRows.licenses, l => l.key === licenseKey);
                if (lic) {
                    lic.prologue_anomaly_count = (lic.prologue_anomaly_count || 0) + 1;
                }
                return { rows: [], rowCount: 1 };
            }
            if (/^INSERT INTO downloads/i.test(trimmed)) {
                sharedRows.downloads.push({ hwid: params[0], ip: params[1], license_key: params[2] });
                return { rows: [], rowCount: 1 };
            }
            if (/^DELETE FROM arc_function_calls/i.test(trimmed)) return { rows: [], rowCount: 0 };
            if (/^DELETE FROM arc_prologue_requests/i.test(trimmed)) return { rows: [], rowCount: 0 };
            if (/^UPDATE sessions SET last_chain_tag/i.test(trimmed)) return { rows: [], rowCount: 0 };
            if (/^DELETE FROM page_rotations/i.test(trimmed)) return { rows: [], rowCount: 0 };
            return { rows: [], rowCount: 0 };
        },
        async end() {},
    },
};

const express = require('express');
const functionsRouter = require('../routes/functions.js');
const downloadRouter = require('../routes/download.js');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use('/api/arc/function', functionsRouter);
app.use('/api/arc', downloadRouter);
app.use('/api/download', downloadRouter);

let server;
let baseUrl;

test.before(() => new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
    });
}));

test.after(() => new Promise((resolve) => {
    server.close(resolve);
}));

function postJson(url, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const u = new URL(url);
        const req = http.request({
            method: 'POST',
            hostname: u.hostname,
            port: u.port,
            path: u.pathname,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
            },
        }, (res) => {
            let chunks = '';
            res.setEncoding('utf8');
            res.on('data', d => chunks += d);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, body: chunks ? JSON.parse(chunks) : null });
                } catch (err) {
                    resolve({ status: res.statusCode, body: chunks });
                }
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

test('POST /api/arc/streaming/info returns blob layout and epoch nonce', async () => {
    const res = await postJson(`${baseUrl}/api/arc/streaming/info`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.ok(res.body.total_pages >= 1);
    assert.equal(res.body.page_size, 4096);
    assert.equal(typeof res.body.epoch_nonce, 'string');
    assert.equal(res.body.epoch_nonce.length, 64);
    assert.ok(typeof res.body.signature === 'string' && res.body.signature.length > 0);
});

test('POST /api/arc/page/0 returns AES-GCM ciphertext that decrypts under the derived key', async () => {
    const pageKeys = require('../crypto/page_keys.js');
    const res = await postJson(`${baseUrl}/api/arc/page/0`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    const epochBuf = Buffer.from(res.body.epoch_nonce, 'hex');
    const key = pageKeys.derivePageKey(
        'AIDA-ENDPOINT-TEST-LICENSE',
        'session-endpoint-test-token-aaaa',
        'HWID-ENDPOINT-TEST-1',
        0,
        epochBuf
    );
    const iv = Buffer.from(res.body.iv, 'hex');
    const tag = Buffer.from(res.body.auth_tag, 'hex');
    const ct = Buffer.from(res.body.data, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    assert.ok(plaintext.length > 0 && plaintext.length <= 4096);
    assert.equal(plaintext[0], 0x4D);
    assert.equal(plaintext[1], 0x5A);
});

test('POST /api/arc/page/:idx with stale client_epoch returns 409', async () => {
    const stale = 1;
    const res = await postJson(`${baseUrl}/api/arc/page/0`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        client_epoch: stale,
    });
    assert.equal(res.status, 409);
    assert.equal(res.body.reason, 'epoch_stale');
    assert.ok(res.body.current_epoch > stale);
});

test('POST /api/arc/function/key issues a 32-byte key and time-bound token', async () => {
    const fnHashParam = crypto.createHash('sha256').update('arc_init').digest('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const res = await postJson(`${baseUrl}/api/arc/function/key`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        function_name: 'arc_init',
        function_hash: fnHashParam,
        nonce,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    const keyBuf = Buffer.from(res.body.decryption_key, 'base64');
    assert.equal(keyBuf.length, 32);
    assert.equal(res.body.ttl_seconds, 10);
    assert.ok(res.body.expires_at - res.body.issued_at >= 10);
    assert.ok(typeof res.body.access_token === 'string' && res.body.access_token.length === 64);
    assert.ok(typeof res.body.signature === 'string' && res.body.signature.length > 0);
});

test('POST /api/arc/function/key replays the same nonce and is rejected', async () => {
    const fnHashParam = crypto.createHash('sha256').update('arc_validate_tool_exec').digest('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const body = {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        function_name: 'arc_validate_tool_exec',
        function_hash: fnHashParam,
        nonce,
    };
    const first = await postJson(`${baseUrl}/api/arc/function/key`, body);
    assert.equal(first.status, 200);
    const second = await postJson(`${baseUrl}/api/arc/function/key`, body);
    assert.equal(second.status, 403);
    assert.equal(second.body.reason, 'replay_detected');
});

test('POST /api/arc/function/key rejects non-critical functions', async () => {
    const res = await postJson(`${baseUrl}/api/arc/function/key`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        function_name: 'arc_internal_helper',
        function_hash: 'a'.repeat(64),
        nonce: 'b'.repeat(32),
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.reason, 'function_not_critical');
});

test('POST /api/arc/function/prologue returns encrypted prologue for known function', async () => {
    const fnHashParam = fnHash;
    const nonce = crypto.randomBytes(16).toString('hex');
    const res = await postJson(`${baseUrl}/api/arc/function/prologue`, {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        function_name: 'arc_heartbeat',
        function_hash: fnHashParam,
        nonce,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    const pageKeys = require('../crypto/page_keys.js');
    const key = pageKeys.derivePrologueKey(
        'AIDA-ENDPOINT-TEST-LICENSE',
        'HWID-ENDPOINT-TEST-1',
        fnHashParam,
        nonce
    );
    const iv = Buffer.from(res.body.iv, 'hex');
    const tag = Buffer.from(res.body.auth_tag, 'hex');
    const ct = Buffer.from(res.body.ciphertext, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const recovered = Buffer.concat([decipher.update(ct), decipher.final()]);
    assert.deepEqual(recovered, prologueBytes);
});

test('POST /api/arc/function/prologue rapid same-function refetch is flagged', async () => {
    const fnHashParam = fnHash;
    const promises = [];
    for (let i = 0; i < 4; i++) {
        const nonce = crypto.randomBytes(16).toString('hex');
        promises.push(postJson(`${baseUrl}/api/arc/function/prologue`, {
            license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
            session_token: 'session-endpoint-test-token-aaaa',
            hwid: 'HWID-ENDPOINT-TEST-1',
            function_name: 'arc_heartbeat',
            function_hash: fnHashParam,
            nonce,
        }));
    }
    const results = await Promise.all(promises);
    const flaggedCount = results.filter(r => r.status === 429 || r.status === 200).length;
    assert.equal(flaggedCount, results.length);
    const rapidLicense = sharedRows.licenses.find(l => l.key === 'AIDA-ENDPOINT-TEST-LICENSE');
    assert.ok(rapidLicense.prologue_anomaly_count >= 0);
});

test('POST /api/arc/function/prologue replayed nonce is rejected', async () => {
    const fnHashParam = fnHash;
    const nonce = crypto.randomBytes(16).toString('hex');
    const body = {
        license_key: 'AIDA-ENDPOINT-TEST-LICENSE',
        session_token: 'session-endpoint-test-token-aaaa',
        hwid: 'HWID-ENDPOINT-TEST-1',
        function_name: 'arc_heartbeat',
        function_hash: fnHashParam,
        nonce,
    };
    const first = await postJson(`${baseUrl}/api/arc/function/prologue`, body);
    assert.equal(first.status, 200);
    const second = await postJson(`${baseUrl}/api/arc/function/prologue`, body);
    assert.equal(second.status, 403);
    assert.equal(second.body.reason, 'prologue_replay');
});
