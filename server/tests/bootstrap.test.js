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
process.env.AIDA_CAMOUFOX_SIDECAR_URL = 'https://downloads.aidapro.net/bootstrap-artifacts/aida-camoufox-sidecar-2026.6.8.zip';
process.env.AIDA_CAMOUFOX_SIDECAR_SHA256 = 'c'.repeat(64);
process.env.AIDA_CAMOUFOX_SIDECAR_SIZE = '16384';
process.env.AIDA_CAMOUFOX_SIDECAR_VERSION = '2026.6.8';
process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL = 'deps\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe';
process.env.AIDA_CAMOUFOX_SIDECAR_PYTHON_REL = '';
process.env.AIDA_CAMOUFOX_MCP_URL = 'https://downloads.aidapro.net/bootstrap-artifacts/AiDA_CamoufoxReverseMcp-2026.6.10.exe';
process.env.AIDA_CAMOUFOX_MCP_SHA256 = 'd'.repeat(64);
process.env.AIDA_CAMOUFOX_MCP_SIZE = '72396462';
process.env.AIDA_CAMOUFOX_MCP_VERSION = '2026.6.10';
process.env.AIDA_CAMOUFOX_MCP_REL = 'deps\\AiDA_CamoufoxReverseMcp.exe';
process.env.AIDA_BOOTSTRAP_SIGNER_THUMBPRINT = '0123456789ABCDEF0123456789ABCDEF01234567';
process.env.AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER = '1';
process.env.AIDA_BOOTSTRAP_REQUIRE_TLS_PIN = '0';
process.env.BOOTSTRAP_TOKEN_TTL_SECONDS = '180';

const TEST_HWID = 'e'.repeat(64);

const state = {
    queries: [],
    tokenRow: null,
    updateRowCount: 1,
    currentHwid: TEST_HWID,
    license: {
        key: 'AIDA-1111-2222-3333-4444',
        active: true,
        expires: '2999-01-01',
        expires_epoch: 0,
        hwid: TEST_HWID,
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
    state.license.hwid = TEST_HWID;
    state.currentHwid = TEST_HWID;
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

test('camoufox sidecar config is optional but fails closed when configured unsafely', () => {
    const prevUrl = process.env.AIDA_CAMOUFOX_SIDECAR_URL;
    const prevSha = process.env.AIDA_CAMOUFOX_SIDECAR_SHA256;
    process.env.AIDA_CAMOUFOX_SIDECAR_URL = '';
    let cfg = bootstrap.getCamoufoxSidecarConfig();
    assert.equal(cfg.ok, true);
    assert.equal(cfg.configured, false);
    process.env.AIDA_CAMOUFOX_SIDECAR_URL = 'https://aidapro.net/api/camoufox.zip';
    cfg = bootstrap.getCamoufoxSidecarConfig();
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_sidecar_api_route_disallowed');
    process.env.AIDA_CAMOUFOX_SIDECAR_URL = prevUrl;
    process.env.AIDA_CAMOUFOX_SIDECAR_SHA256 = 'bad';
    cfg = bootstrap.getCamoufoxSidecarConfig();
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_sidecar_sha256_invalid');
    process.env.AIDA_CAMOUFOX_SIDECAR_SHA256 = prevSha;
});

test('camoufox MCP patch config is optional but fails closed when configured unsafely', () => {
    const prevUrl = process.env.AIDA_CAMOUFOX_MCP_URL;
    const prevSha = process.env.AIDA_CAMOUFOX_MCP_SHA256;
    process.env.AIDA_CAMOUFOX_MCP_URL = '';
    let cfg = bootstrap.getCamoufoxMcpPatchConfig();
    assert.equal(cfg.ok, true);
    assert.equal(cfg.configured, false);
    process.env.AIDA_CAMOUFOX_MCP_URL = 'https://aidapro.net/api/camoufox-mcp.exe';
    cfg = bootstrap.getCamoufoxMcpPatchConfig();
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_mcp_api_route_disallowed');
    process.env.AIDA_CAMOUFOX_MCP_URL = 'https://downloads.aidapro.net/bootstrap-artifacts/camoufox-mcp.zip';
    cfg = bootstrap.getCamoufoxMcpPatchConfig();
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_mcp_extension_invalid');
    process.env.AIDA_CAMOUFOX_MCP_URL = prevUrl;
    process.env.AIDA_CAMOUFOX_MCP_SHA256 = 'bad';
    cfg = bootstrap.getCamoufoxMcpPatchConfig();
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_mcp_sha256_invalid');
    process.env.AIDA_CAMOUFOX_MCP_SHA256 = prevSha;
});

test('camoufox relative paths preserve separators across slash-safe and legacy metadata', () => {
    const prevExeRel = process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL;
    const prevMcpRel = process.env.AIDA_CAMOUFOX_MCP_REL;
    try {
        process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL = 'deps/camoufox-135.0.1-beta.24-win.x86_64/camoufox.exe';
        process.env.AIDA_CAMOUFOX_MCP_REL = 'deps/AiDA_CamoufoxReverseMcp.exe';
        let cfg = bootstrap.getCamoufoxSidecarConfig();
        assert.equal(cfg.ok, true);
        assert.equal(cfg.executable_rel, 'deps\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe');
        assert.equal(cfg.mcp.rel, 'deps\\AiDA_CamoufoxReverseMcp.exe');

        process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL = 'depscamoufox-135.0.1-beta.24-win.x86_64camoufox.exe';
        process.env.AIDA_CAMOUFOX_MCP_REL = 'depsAiDA_CamoufoxReverseMcp.exe';
        cfg = bootstrap.getCamoufoxSidecarConfig();
        assert.equal(cfg.ok, true);
        assert.equal(cfg.executable_rel, 'deps\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe');
        assert.equal(cfg.mcp.rel, 'deps\\AiDA_CamoufoxReverseMcp.exe');
    } finally {
        process.env.AIDA_CAMOUFOX_SIDECAR_EXE_REL = prevExeRel;
        process.env.AIDA_CAMOUFOX_MCP_REL = prevMcpRel;
    }
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

test('root bootstrap stage0 fetches the opaque script and authenticates its hash', () => {
    const full = bootstrap.buildBootstrapScript();
    const stage0 = bootstrap.buildBootstrapStage0Script();
    const expectedHash = crypto.createHash('sha256').update(full, 'utf8').digest('hex');
    assert.match(stage0, /\[Net\.ServicePointManager\]::SecurityProtocol = \[Net\.SecurityProtocolType\]::Tls12/);
    assert.match(stage0, /\$u = 'https:\/\/aidapro\.net\/b\/opaque-20260603-test-route\.ps1'/);
    assert.match(stage0, /\$req\.Accept = "application\/vnd\.aida\.bootstrap"/);
    assert.match(stage0, /AiDA bootstrap stage authentication failed/);
    assert.match(stage0, /Invoke-Expression \$s/);
    assert.match(stage0, new RegExp(expectedHash));
    assert.ok(stage0.length < full.length / 10);
});

test('authorize issues a short-lived token and stores only a token HMAC', async () => {
    resetState();
    bootstrap._resetForTests();
    const nonce = 'b'.repeat(64);
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        hwid: state.currentHwid,
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

test('authorize allows an unbound license to continue to in-app first binding', async () => {
    resetState();
    bootstrap._resetForTests();
    state.license.hwid = '';
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        hwid: state.currentHwid,
        client_nonce: 'a'.repeat(64),
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(result.status, 200);
    assert.equal(result.body.ok, true);
});

test('authorize refuses a bound license from a different bootstrap HWID', async () => {
    resetState();
    bootstrap._resetForTests();
    state.license.hwid = 'f'.repeat(64);
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        hwid: state.currentHwid,
        client_nonce: '9'.repeat(64),
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(result.eauth, true);
    assert.equal(state.tokenRow, null);
});

test('authorize fails closed when bootstrap HWID is missing', async () => {
    resetState();
    bootstrap._resetForTests();
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        client_nonce: '8'.repeat(64),
        timestamp: Date.now(),
    }, '203.0.113.10', 'aida-test');
    assert.equal(result.eauth, true);
    assert.equal(state.tokenRow, null);
});

test('authorize fails closed when the bootstrap rate store is unavailable', async () => {
    resetState();
    bootstrap._resetForTests();
    state.rateLimitThrows = true;
    const result = await bootstrap.authorizeRequest({
        license_key: state.license.key,
        hwid: state.currentHwid,
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
        hwid: state.currentHwid,
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
    assert.equal(manifest.body.camoufox.configured, true);
    assert.equal(manifest.body.camoufox.url, 'https://downloads.aidapro.net/bootstrap-artifacts/aida-camoufox-sidecar-2026.6.8.zip');
    assert.equal(manifest.body.camoufox.sha256, 'c'.repeat(64));
    assert.equal(manifest.body.camoufox.size, 16384);
    assert.equal(manifest.body.camoufox.executable_rel, 'deps\\camoufox-135.0.1-beta.24-win.x86_64\\camoufox.exe');
    assert.equal(manifest.body.camoufox.python_rel, '');
    assert.equal(manifest.body.camoufox.mcp.configured, true);
    assert.equal(manifest.body.camoufox.mcp.url, 'https://downloads.aidapro.net/bootstrap-artifacts/AiDA_CamoufoxReverseMcp-2026.6.10.exe');
    assert.equal(manifest.body.camoufox.mcp.sha256, 'd'.repeat(64));
    assert.equal(manifest.body.camoufox.mcp.size, 72396462);
    assert.equal(manifest.body.camoufox.mcp.rel, 'deps\\AiDA_CamoufoxReverseMcp.exe');
    assert.equal(manifest.body.policy.encrypted_public_artifact, true);
    assert.equal(manifest.body.policy.camoufox_sidecar_hash_required, true);
    assert.equal(manifest.body.policy.camoufox_mcp_hash_required, true);
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
        hwid: state.currentHwid,
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
        hwid: state.currentHwid,
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
    assert.match(script, /\$AidaBootstrapLogPath = Join-Path \(\[IO\.Path\]::GetTempPath\(\)\) "aida_bootstrap\.log"/);
    assert.match(script, /Write-AidaBootstrapLog/);
    assert.match(script, /direct_log_ready/);
    assert.match(script, /Initialize-AidaFilelessDebugLog/);
    assert.match(script, /aida_debug_fileless\.log/);
    assert.match(script, /AIDA_FILELESS_DEBUG_LOG_PATH/);
    assert.match(script, /AIDA_FILELESS_NO_DISK_WRITE/);
    assert.match(script, /Test-AidaNoStandaloneDiskArtifact/);
    assert.match(script, /no_disk_write_validation/);
    assert.match(script, /Invoke-AidaPEInMemory/);
    assert.match(script, /Launching AiDA in memory \(no disk write\)/);
    assert.match(script, /launch_inmemory_enter/);
    assert.match(script, /fatal_error/);
    assert.match(script, /Enable-AidaPinnedTls/);
    assert.match(script, /Get-AidaManifestMacInput/);
    assert.match(script, /Get-AidaTokenParts/);
    assert.match(script, /manifest_mac/);
    assert.match(script, /manifest_sig_p256/);
    assert.match(script, /Test-AidaP256Signature/);
    assert.match(script, /manifest signature verification failed/);
    assert.match(script, /Install-AidaCamoufoxSidecar/);
    assert.match(script, /Install-AidaCamoufoxMcpPatch/);
    assert.match(script, /Get-AidaBootstrapHwid/);
    assert.match(script, /hwid = \$currentHwid/);
    assert.match(script, /hwid_v2_ready/);
    assert.match(script, /Invoke-AidaElevatedBootstrap/);
    assert.match(script, /Start-Process -FilePath \$ps -Verb RunAs/);
    assert.match(script, /-NoExit/);
    assert.match(script, /intercept_certificates_checked/);
    assert.match(script, /intercept_processes_checked/);
    assert.match(script, /Test-AidaProcessPathIndicatesInterceptor/);
    assert.match(script, /\$__exactProcessNames = @\("charles"\)/);
    assert.match(script, /source=path/);
    assert.match(script, /http_response_error/);
    assert.match(script, /Invoke-AidaAntiForensics/);
    assert.match(script, /pre_launch_wipe_done/);
    assert.match(script, /post_launch_wipe_done/);
    assert.match(script, /wevtutil/);
    assert.match(script, /FeatureSettingsOverride/);
    assert.match(script, /Parsec/);
    assert.match(script, /Save-AidaVerifiedSidecarFile/);
    assert.match(script, /Test-AidaVerifiedSidecarFile/);
    assert.match(script, /camoufox_sidecar_hash_required/);
    assert.match(script, /camoufox_mcp_hash_required/);
    assert.match(script, /camoufox_mcp_patch_current_ok/);
    assert.match(script, /camoufox_mcp_patch_installed/);
    assert.match(script, /Downloading Camoufox sidecar/);
    assert.match(script, /camoufox_sidecar_download_attempt attempt=/);
    assert.match(script, /camoufox_sidecar_download_attempt_incomplete/);
    assert.match(script, /camoufox_sidecar_download_attempt_error/);
    assert.match(script, /camoufox_sidecar_download_progress bytes=/);
    assert.match(script, /camoufox_sidecar_range_unsupported_restart/);
    assert.match(script, /camoufox_sidecar_download_complete bytes=.*attempts=/);
    assert.match(script, /Expand-Archive/);
    assert.match(script, /Get-AidaLocalAppDataDirectory/);
    assert.match(script, /\$localRoot = Join-Path \(Get-AidaLocalAppDataDirectory\) "AiDA\\Standalone"/);
    assert.match(script, /\$root = Join-Path \$localRoot "camoufox"/);
    assert.doesNotMatch(script, /\$root = Join-Path \$tempRoot "AiDA\\camoufox"/);
    assert.match(script, /Find-AidaCamoufoxMcpExecutable/);
    assert.match(script, /AIDA_CAMOUFOX_MCP_EXECUTABLE/);
    assert.match(script, /AIDA_CAMOUFOX_EXECUTABLE/);
    assert.match(script, /AIDA_CAMOUFOX_ALLOW_SYSTEM_PYTHON/);
    assert.match(script, /AIDA_CAMOUFOX_ALLOW_SETUP_BOOTSTRAP/);
    const existingPatch = script.indexOf('$patchedMcp = Install-AidaCamoufoxMcpPatch $Manifest $current $exePath');
    const existingAccept = script.indexOf('camoufox_sidecar_existing_usable exe=');
    const freshPatch = script.indexOf('$stageMcp = Install-AidaCamoufoxMcpPatch $Manifest $staging $stageExe');
    const freshValidate = script.indexOf('AiDA Camoufox sidecar contents are incomplete.');
    assert.ok(existingPatch >= 0 && existingAccept > existingPatch);
    assert.ok(freshPatch >= 0 && freshValidate > freshPatch);
    assert.match(script, /Downloading and verifying encrypted package/);
    assert.match(script, /\$req\.ReadWriteTimeout = 900000/);
    assert.match(script, /package_download_progress bytes=/);
    assert.match(script, /package_download_attempt attempt=/);
    assert.match(script, /package_download_attempt_incomplete/);
    assert.match(script, /AddRange/);
    assert.match(script, /package_download_error bytes=/);
    assert.match(script, /rate_bps=/);
    assert.match(script, /HMACSHA256/);
    assert.match(script, /Decrypt-AidaPackageBytesToMemory/);
    assert.match(script, /Invoke-AidaPEInMemory \$exeBytes/);
    assert.match(script, /Resolve-AidaMappedVa/);
    assert.match(script, /Z3 bootstrap preload skipped/);
    assert.doesNotMatch(script, /Install-AidaZ3Preload/);
    assert.doesNotMatch(script, /AIDA_Z3_PRELOAD_DIR/);
    assert.doesNotMatch(script, /Z3 LoadLibrary exit/);
    assert.match(script, /TlsAlloc/);
    assert.match(script, /Find-AidaStaticTlsIndex/);
    assert.match(script, /TLS preferred static slot occupied/);
    assert.match(script, /TLS selected static index=/);
    assert.match(script, /TLS index selected static=/);
    assert.match(script, /TLS dynamic set value exit/);
    assert.match(script, /TLS slot initialized/);
    assert.match(script, /NtQueryInformationProcess/);
    assert.match(script, /NtQueryInformationThread/);
    assert.match(script, /GetCurrentThreadId/);
    assert.match(script, /RtlAllocateHeap/);
    assert.match(script, /RtlFreeHeap/);
    assert.match(script, /Set-AidaStaticTlsForThread/);
    assert.match(script, /TLS heap alloc exit/);
    assert.match(script, /TLS static vector thread before/);
    assert.match(script, /TLS static vector thread after/);
    assert.match(script, /TLS current thread initialized/);
    assert.match(script, /TLS existing thread propagation skipped/);
    assert.match(script, /PEB image base patch enter/);
    assert.match(script, /PEB image base after/);
    assert.match(script, /KernelBase\.dll/);
    assert.match(script, /step7c1 LDR main before/);
    assert.match(script, /step7c1 LDR main after/);
    assert.match(script, /\$preferredBase=if\(\$imgBase -ne 0\)/);
    assert.match(script, /preferred VirtualAlloc failed/);
    assert.match(script, /preferred image base unavailable and relocation directory is stripped/);
    assert.match(script, /step6 relocations applied delta=.*count=/);
    assert.match(script, /step8 direct_entry_enter/);
    assert.match(script, /step9 direct_entry_return/);
    assert.match(script, /AIDA_PAYLOAD_TRACE/);
    assert.match(script, /direct_entry_exception/);
    assert.match(script, /process-exit APIs left unmodified/);
    assert.match(script, /SetProcessValidCallTargets/);
    assert.match(script, /CFG call targets registered=/);
    assert.doesNotMatch(script, /CreateThread/);
    assert.doesNotMatch(script, /ResumeThread/);
    assert.doesNotMatch(script, /CREATE_SUSPENDED/);
    assert.doesNotMatch(script, /step10 wait_probe/);
    assert.doesNotMatch(script, /RtlAddVectoredExceptionHandler/);
    assert.doesNotMatch(script, /native_veh code=/);
    assert.doesNotMatch(script, /ExitProcess\+RtlExitUserProcess patched/);
    assert.doesNotMatch(script, /Save-AidaVerifiedExecutable/);
    assert.doesNotMatch(script, /Join-Path \$dir "aida_debug\.log"/);
    assert.doesNotMatch(script, /Start-AidaVerifiedExecutable/);
    assert.doesNotMatch(script, /Start-Transcript/);
    assert.doesNotMatch(script, /Stop-Transcript/);
    assert.doesNotMatch(script, /Get-FileHash/);
    assert.doesNotMatch(script, /\.download/);
    assert.doesNotMatch(script, /tmpDownload/);
    assert.doesNotMatch(script, /Save-AidaFileWithProgress/);
    assert.doesNotMatch(script, /Get-Item -LiteralPath \$PackagePath/);
    assert.doesNotMatch(script, /Unblock-File/);
    assert.doesNotMatch(script, /ExecutionPolicy/);
    assert.doesNotMatch(script, /Get-AuthenticodeSignature/);
    assert.doesNotMatch(script, /\$__texts\.Add\(\[string\]\$__proc\.Path\)/);
    assert.doesNotMatch(script, /\$__needles = @\([^)]*"charles"[^)]*\)/);
    assert.doesNotMatch(script, /hwid_v2_ready len=.*prefix=/);
    assert.doesNotMatch(script, /AIDA-1111-2222-3333-4444/);
    assert.doesNotMatch(script, /\$env:TEMPaida_bootstrap\.log/);
    assert.doesNotMatch(script, /Start-Transcript -Path "\$env:TEMP\\aida_bootstrap\.log"/);
});
