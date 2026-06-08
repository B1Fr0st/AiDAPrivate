'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const keyPair = crypto.generateKeyPairSync('ed25519');
process.env.ED25519_PRIVATE_KEY_B64 = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
process.env.SERVER_MASTER_KEY_B64 = crypto.randomBytes(32).toString('base64');
process.env.AIDA_PUBLIC_ORIGIN = 'https://aidapro.net';
process.env.AIDA_BOOTSTRAP_SCRIPT_SLUG = 'opaque-20260603-test-route';
process.env.AIDA_BOOTSTRAP_ROOT_NEGOTIATION = '1';
process.env.AIDA_BOOTSTRAP_LEGACY_ROUTE_ENABLED = '0';
process.env.AIDA_BOOTSTRAP_ARTIFACT_URL = 'https://downloads.aidapro.net/bootstrap-artifacts/AiDAStandalone-2026.6.3.pkg';
process.env.AIDA_BOOTSTRAP_ARTIFACT_SHA256 = 'a'.repeat(64);
process.env.AIDA_BOOTSTRAP_ARTIFACT_VERSION = '2026.6.3';
process.env.AIDA_BOOTSTRAP_ARTIFACT_SIZE = '4096';
process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT = 'encrypted-cbc-hmac-v1';
process.env.AIDA_BOOTSTRAP_PACKAGE_SHA256 = 'b'.repeat(64);
process.env.AIDA_BOOTSTRAP_PACKAGE_SIZE = '8192';
process.env.AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64 = Buffer.alloc(32, 1).toString('base64');
process.env.AIDA_BOOTSTRAP_PACKAGE_MAC_KEY_B64 = Buffer.alloc(32, 2).toString('base64');
process.env.AIDA_BOOTSTRAP_SIGNER_THUMBPRINT = '0123456789ABCDEF0123456789ABCDEF01234567';
process.env.AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER = '1';
process.env.AIDA_BOOTSTRAP_REQUIRE_TLS_PIN = '0';
process.env.BOOTSTRAP_TOKEN_TTL_SECONDS = '180';

const state = {
    queries: [],
    tokenRow: null,
    updateRowCount: 1,
    license: {
        key: 'AIDA-1111-2222-3333-4444',
        active: true,
        expires: '2999-01-01',
        expires_epoch: 0,
    },
    killRows: [],
    rateLimitThrows: false,
};

function resetState() {
    state.queries.length = 0;
    state.tokenRow = null;
    state.updateRowCount = 1;
    state.license.active = true;
    state.license.expires = '2999-01-01';
    state.license.expires_epoch = 0;
    state.killRows = [];
    state.rateLimitThrows = false;
    if (killSwitch && killSwitch.invalidateCache) killSwitch.invalidateCache();
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
            if (/CREATE TABLE IF NOT EXISTS bootstrap_delivery_tokens/i.test(text)) return { rows: [], rowCount: 0 };
            if (/CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens/i.test(text)) return { rows: [], rowCount: 0 };
            if (/DELETE FROM license_request_rate/i.test(text)) return { rows: [], rowCount: 0 };
            if (/INSERT INTO license_request_rate/i.test(text) && state.rateLimitThrows) throw new Error('rate-store-offline');
            if (/INSERT INTO license_request_rate/i.test(text)) return { rows: [{ count: 1 }], rowCount: 1 };
            if (/SELECT reason FROM bans/i.test(text)) return { rows: [], rowCount: 0 };
            if (/SELECT target_type, target_value\s+FROM kill_switch/i.test(text)) return { rows: state.killRows.slice(), rowCount: state.killRows.length };
            if (/SELECT \* FROM licenses WHERE key = \$1/i.test(text)) {
                if (params[0] === state.license.key) return { rows: [Object.assign({}, state.license)], rowCount: 1 };
                return { rows: [], rowCount: 0 };
            }
            if (/INSERT INTO bootstrap_delivery_tokens/i.test(text)) {
                state.tokenRow = {
                    token_id: params[0],
                    token_hmac: params[1],
                    license_key: params[2],
                    client_nonce: params[3],
                    issued_at: params[4],
                    expires_at: params[5],
                    consumed: false,
                    source_ip: params[6],
                    user_agent_hash: params[7],
                    manifest_version: params[8],
                    artifact_sha256: params[9],
                };
                return { rows: [], rowCount: 1 };
            }
            if (/SELECT \* FROM bootstrap_delivery_tokens WHERE token_id = \$1/i.test(text)) {
                if (state.tokenRow && params[0] === state.tokenRow.token_id) return { rows: [Object.assign({}, state.tokenRow)], rowCount: 1 };
                return { rows: [], rowCount: 0 };
            }
            if (/UPDATE bootstrap_delivery_tokens/i.test(text)) {
                const rowCount = state.updateRowCount;
                if (rowCount === 1 && state.tokenRow) {
                    state.tokenRow.consumed = true;
                    state.tokenRow.consumed_at = params[0];
                }
                return { rows: [], rowCount };
            }
            if (/INSERT INTO downloads/i.test(text)) return { rows: [], rowCount: 1 };
            if (/INSERT INTO audit_log_v2/i.test(text)) return { rows: [], rowCount: 1 };
            return { rows: [], rowCount: 0 };
        },
        end: async () => {},
    },
};

const auditPath = require.resolve('../middleware/audit_log');
require.cache[auditPath] = {
    id: auditPath,
    filename: auditPath,
    loaded: true,
    exports: {
        logV2: async () => ({ ok: true }),
    },
};

const bootstrap = require('../routes/bootstrap')._internal;
const killSwitch = require('../middleware/kill_switch');

test('release config fails closed for API artifact routes', () => {
    const prevUrl = process.env.AIDA_BOOTSTRAP_ARTIFACT_URL;
    process.env.AIDA_BOOTSTRAP_ARTIFACT_URL = 'https://aidapro.net/api/download/AiDAStandalone.exe';
    const cfg = bootstrap.getReleaseConfig();
    process.env.AIDA_BOOTSTRAP_ARTIFACT_URL = prevUrl;
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'artifact_api_route_disallowed');
});

test('release config allows same-host encrypted package routes outside the API surface', () => {
    const prevUrl = process.env.AIDA_BOOTSTRAP_ARTIFACT_URL;
    process.env.AIDA_BOOTSTRAP_ARTIFACT_URL = 'https://aidapro.net/bootstrap-artifacts/AiDAStandalone.pkg';
    const cfg = bootstrap.getReleaseConfig();
    process.env.AIDA_BOOTSTRAP_ARTIFACT_URL = prevUrl;
    assert.equal(cfg.ok, true);
});

test('release config rejects plain artifact mode', () => {
    const prevFormat = process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT;
    process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT = 'plain';
    const cfg = bootstrap.getReleaseConfig();
    process.env.AIDA_BOOTSTRAP_ARTIFACT_FORMAT = prevFormat;
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'artifact_format_invalid');
});

test('release config fails closed when encrypted package keys are missing', () => {
    const prevKey = process.env.AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64;
    process.env.AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64 = '';
    const cfg = bootstrap.getReleaseConfig();
    process.env.AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64 = prevKey;
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'artifact_package_config_missing');
});

test('release config rejects oversized encrypted packages', () => {
    const prevSize = process.env.AIDA_BOOTSTRAP_PACKAGE_SIZE;
    const prevMax = process.env.AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES;
    process.env.AIDA_BOOTSTRAP_PACKAGE_SIZE = '8192';
    process.env.AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES = '4096';
    delete require.cache[require.resolve('../routes/bootstrap')];
    const fresh = require('../routes/bootstrap')._internal;
    const cfg = fresh.getReleaseConfig();
    process.env.AIDA_BOOTSTRAP_PACKAGE_SIZE = prevSize;
    if (prevMax === undefined) delete process.env.AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES;
    else process.env.AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES = prevMax;
    delete require.cache[require.resolve('../routes/bootstrap')];
    require('../routes/bootstrap');
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'artifact_package_size_too_large');
});

test('bootstrap script routes prefer opaque or root negotiation and keep legacy disabled by default', () => {
    const cfg = bootstrap.getScriptRouteConfig();
    assert.equal(cfg.script_path, '/b/opaque-20260603-test-route.ps1');
    assert.equal(cfg.root_content_negotiation, true);
    assert.equal(cfg.legacy_route_enabled, false);
    assert.equal(bootstrap.acceptsBootstrapScript({ headers: { accept: 'application/vnd.aida.bootstrap' } }), true);
    assert.equal(bootstrap.acceptsBootstrapScript({ headers: { accept: 'text/html' } }), false);
    assert.equal(bootstrap.acceptsBootstrapScript({ headers: { 'user-agent': 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1', accept: '*/*' } }), true);
    assert.equal(bootstrap.acceptsBootstrapScript({ headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19041; en-US) PowerShell/7.4.1', accept: '*/*' } }), true);
    assert.equal(bootstrap.acceptsBootstrapScript({ headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', accept: 'text/html' } }), false);
});

test('authorize issues a short-lived token and stores only a token HMAC', async () => {
    resetState();
    bootstrap._resetForTests();
    const nonce = 'b'.repeat(64);
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(result.status, 200);
    assert.equal(result.body.ok, true);
    assert.match(result.body.token, /^AIDABOOT\.v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/);
    assert.equal(state.tokenRow.license_key, state.license.key);
    assert.equal(state.tokenRow.client_nonce, nonce);
    const parsed = bootstrap.parseToken(result.body.token);
    assert.notEqual(state.tokenRow.token_hmac, parsed.secret);
    assert.equal(bootstrap.timingSafeHexEqual(state.tokenRow.token_hmac, bootstrap.hashTokenSecret(parsed.token_id, parsed.secret)), true);
});

test('authorize fails closed when the bootstrap rate store is unavailable', async () => {
    resetState();
    bootstrap._resetForTests();
    state.rateLimitThrows = true;
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: 'f'.repeat(64),
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(result.eauth, true);
});

test('manifest consumes the bootstrap token once and returns signed metadata without a license key', async () => {
    resetState();
    bootstrap._resetForTests();
    const nonce = 'c'.repeat(64);
    const auth = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    const manifest = await bootstrap.manifestRequest({
        token: auth.body.token,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(manifest.status, 200);
    assert.equal(manifest.body.ok, true);
    assert.equal(manifest.body.artifact.url, 'https://downloads.aidapro.net/bootstrap-artifacts/AiDAStandalone-2026.6.3.pkg');
    assert.equal(manifest.body.artifact.sha256, 'a'.repeat(64));
    assert.equal(manifest.body.artifact.package.sha256, 'b'.repeat(64));
    assert.equal(manifest.body.artifact.package.format, 'encrypted-cbc-hmac-v1');
    assert.equal(manifest.body.artifact.package.enc_key_b64, Buffer.alloc(32, 1).toString('base64'));
    assert.equal(manifest.body.policy.encrypted_public_artifact, true);
    assert.match(manifest.body.manifest_mac, /^[0-9a-f]{64}$/);
    const parsed = bootstrap.parseToken(auth.body.token);
    assert.equal(manifest.body.manifest_mac, bootstrap.createManifestMac(parsed.secret, manifest.body));
    assert.equal(typeof manifest.body.signature, 'string');
    assert.equal(Buffer.from(manifest.body.signature, 'hex').length, 64);
    assert.equal(manifest.body.manifest_sig_alg, 'ECDSA_P256_SHA256_P1363');
    assert.equal(Buffer.from(manifest.body.manifest_sig_p256, 'hex').length, 64);
    assert.equal(Object.prototype.hasOwnProperty.call(manifest.body, 'license_key'), false);
    assert.equal(state.tokenRow.consumed, true);
});

test('manifest rejects normalized kill-switch license matches', async () => {
    resetState();
    bootstrap._resetForTests();
    killSwitch.invalidateCache();
    state.killRows = [{ target_type: 'license_key', target_value: state.license.key.toLowerCase() }];
    const nonce = 'e'.repeat(64);
    const auth = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    const manifest = await bootstrap.manifestRequest({
        token: auth.body.token,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(manifest.eauth, true);
    state.killRows = [];
    killSwitch.invalidateCache();
});

test('manifest rejects replayed or already-consumed bootstrap tokens', async () => {
    resetState();
    bootstrap._resetForTests();
    const nonce = 'd'.repeat(64);
    const auth = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    state.updateRowCount = 0;
    const manifest = await bootstrap.manifestRequest({
        token: auth.body.token,
        client_nonce: nonce,
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(manifest.eauth, true);
});

test('bootstrap script contains encrypted package verification and parses as PowerShell text', () => {
    const script = bootstrap.buildBootstrapScript();
    assert.match(script, /Decrypt-AidaPackageBytes/);
    assert.match(script, /Get-AidaPackageBytesWithProgress/);
    assert.match(script, /IO\.MemoryStream/);
    assert.match(script, /Write-AidaStatus/);
    assert.match(script, /Enable-AidaPinnedTls/);
    assert.match(script, /Get-AidaManifestMacInput/);
    assert.match(script, /Get-AidaTokenParts/);
    assert.match(script, /manifest_mac/);
    assert.match(script, /manifest_sig_p256/);
    assert.match(script, /Test-AidaP256Signature/);
    assert.match(script, /manifest signature verification failed/);
    assert.match(script, /Downloading and verifying encrypted package/);
    assert.match(script, /HMACSHA256/);
    assert.match(script, /Decrypt-AidaPackageBytesToMemory/);
    assert.match(script, /Invoke-AidaPEInMemory/);
    assert.match(script, /VirtualAlloc/);
    assert.match(script, /WaitForSingleObject/);
    assert.doesNotMatch(script, /Assert-AidaAuthenticode/);
    assert.doesNotMatch(script, /AidaInstallRoot/);
    assert.doesNotMatch(script, /Move-Item/);
    assert.doesNotMatch(script, /Start-Process/);
    assert.doesNotMatch(script, /Get-FileHash/);
    assert.doesNotMatch(script, /\.download/);
    assert.doesNotMatch(script, /tmpDownload/);
    assert.doesNotMatch(script, /Save-AidaFileWithProgress/);
    assert.doesNotMatch(script, /Get-Item -LiteralPath \$PackagePath/);
    assert.doesNotMatch(script, /Unblock-File/);
    assert.doesNotMatch(script, /ExecutionPolicy/);
    assert.doesNotMatch(script, /AIDA-1111-2222-3333-4444/);
});
