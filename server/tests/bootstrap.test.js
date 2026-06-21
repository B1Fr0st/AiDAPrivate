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

test('release config fails closed when the Camoufox sidecar is missing', () => {
    const prevUrl = process.env.AIDA_CAMOUFOX_SIDECAR_URL;
    process.env.AIDA_CAMOUFOX_SIDECAR_URL = '';
    const cfg = bootstrap.getReleaseConfig();
    process.env.AIDA_CAMOUFOX_SIDECAR_URL = prevUrl;
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_sidecar_config_missing');
});

test('release config uses Camoufox as the bootstrap delivery identity', () => {
    const cfg = bootstrap.getReleaseConfig();
    assert.equal(cfg.ok, true);
    assert.equal(cfg.sha256, 'c'.repeat(64));
    assert.equal(cfg.version, '2026.6.8');
    assert.equal(cfg.package, null);
    assert.equal(cfg.url, '');
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

test('release config rejects oversized Camoufox sidecar packages', () => {
    const prevSize = process.env.AIDA_CAMOUFOX_SIDECAR_SIZE;
    const prevMax = process.env.AIDA_CAMOUFOX_SIDECAR_MAX_BYTES;
    process.env.AIDA_CAMOUFOX_SIDECAR_SIZE = '8192';
    process.env.AIDA_CAMOUFOX_SIDECAR_MAX_BYTES = '4096';
    delete require.cache[require.resolve('../routes/bootstrap')];
    const fresh = require('../routes/bootstrap')._internal;
    const cfg = fresh.getReleaseConfig();
    process.env.AIDA_CAMOUFOX_SIDECAR_SIZE = prevSize;
    if (prevMax === undefined) delete process.env.AIDA_CAMOUFOX_SIDECAR_MAX_BYTES;
    else process.env.AIDA_CAMOUFOX_SIDECAR_MAX_BYTES = prevMax;
    delete require.cache[require.resolve('../routes/bootstrap')];
    require('../routes/bootstrap');
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason, 'camoufox_sidecar_size_invalid');
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
    assert.equal(manifest.body.artifact.url, '');
    assert.equal(manifest.body.artifact.sha256, '');
    assert.equal(Object.prototype.hasOwnProperty.call(manifest.body.artifact, 'package'), false);
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
    assert.equal(manifest.body.policy.encrypted_public_artifact, false);
    assert.equal(manifest.body.policy.artifact_https_required, false);
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

test('bootstrap script installs only the verified Camoufox package and parses as PowerShell text', () => {
    const script = bootstrap.buildBootstrapScript();
    assert.doesNotMatch(script, /Decrypt-AidaPackageBytes/);
    assert.doesNotMatch(script, /Get-AidaPackageBytesWithProgress/);
    assert.doesNotMatch(script, /IO\.MemoryStream/);
    assert.match(script, /Write-AidaStatus/);
    assert.match(script, /\$AidaBootstrapLogPath = Join-Path \(\[IO\.Path\]::GetTempPath\(\)\) "aida_bootstrap\.log"/);
    assert.match(script, /Write-AidaBootstrapLog/);
    assert.match(script, /direct_log_ready/);
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
    assert.match(script, /http_response_error/);
    assert.match(script, /camoufox_delivery_preflight_done/);
    assert.match(script, /camoufox_only_delivery_complete/);
    assert.doesNotMatch(script, /Invoke-AidaElevatedBootstrap/);
    assert.doesNotMatch(script, /Start-Process -FilePath \$ps -Verb RunAs/);
    assert.doesNotMatch(script, /-NoExit/);
    assert.doesNotMatch(script, /intercept_certificates_checked/);
    assert.doesNotMatch(script, /intercept_processes_checked/);
    assert.doesNotMatch(script, /Test-AidaProcessPathIndicatesInterceptor/);
    assert.doesNotMatch(script, /Invoke-AidaAntiForensics/);
    assert.doesNotMatch(script, /pre_launch_wipe_done/);
    assert.doesNotMatch(script, /post_launch_wipe_done/);
    assert.doesNotMatch(script, /wevtutil/);
    assert.doesNotMatch(script, /FeatureSettingsOverride/);
    assert.doesNotMatch(script, /Parsec/);
    assert.match(script, /Save-AidaVerifiedSidecarFile/);
    assert.match(script, /Test-AidaVerifiedSidecarFile/);
    assert.match(script, /Get-AidaFileState/);
    assert.match(script, /Get-AidaCamoufoxMcpExpected/);
    assert.match(script, /Get-AidaCamoufoxMcpLogSuffix/);
    assert.match(script, /Test-AidaCamoufoxMcpMatchesManifest/);
    assert.match(script, /camoufox_sidecar_hash_required/);
    assert.match(script, /camoufox_mcp_hash_required/);
    assert.match(script, /camoufox_mcp_manifest_check/);
    assert.match(script, /camoufox_mcp_manifest_ok/);
    assert.match(script, /camoufox_mcp_manifest_path_mismatch/);
    assert.match(script, /camoufox_mcp_patch_current_ok/);
    assert.match(script, /camoufox_mcp_patch_redownload reason=manifest_mismatch/);
    assert.match(script, /camoufox_mcp_patch_installed/);
    assert.match(script, /camoufox_mcp_static_onedir_runtime_disallowed/);
    assert.match(script, /camoufox_mcp_static_self_contained_too_small/);
    assert.match(script, /expected_size=.*actual_size=.*expected_sha256=.*actual_sha256/);
    assert.match(script, /camoufox_sidecar_cache_probe/);
    assert.match(script, /mcp_sha256/);
    assert.match(script, /mcp_size/);
    assert.match(script, /mcp_version/);
    assert.match(script, /mcp_rel/);
    assert.match(script, /camoufox_sidecar_current_accept source=/);
    assert.match(script, /camoufox_sidecar_current_redownload source=/);
    assert.match(script, /camoufox_sidecar_installed source=redownload/);
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
    const existingManifestCheck = script.indexOf('Test-AidaCamoufoxSidecarInstalled $Manifest $current $exePath $pythonPath $mcpPath $currentSource');
    const existingAccept = script.indexOf('camoufox_sidecar_current_accept source=');
    const cachedProbe = script.indexOf('camoufox_sidecar_cache_probe cached=');
    const cachedMcpStamp = script.indexOf('$mcpStampOk = ([string]$stamp.mcp_sha256).ToLowerInvariant()');
    const freshPatch = script.indexOf('$stageMcp = Install-AidaCamoufoxMcpPatch $Manifest $staging $stageExe');
    const freshManifestCheck = script.indexOf('Test-AidaCamoufoxSidecarInstalled $Manifest $staging $stageExe $stagePython $stageMcp "redownload"');
    const finalManifestCheck = script.indexOf('Test-AidaCamoufoxSidecarInstalled $Manifest $current $exePath $pythonPath $mcpPath "redownload-final"');
    const freshValidate = script.indexOf('AiDA Camoufox sidecar contents are incomplete.');
    assert.ok(cachedProbe >= 0 && cachedMcpStamp >= 0);
    assert.ok(existingPatch >= 0 && existingManifestCheck > existingPatch && existingAccept > existingManifestCheck);
    assert.ok(freshPatch >= 0 && freshManifestCheck > freshPatch && freshValidate > freshManifestCheck);
    assert.ok(finalManifestCheck > freshValidate);
    assert.doesNotMatch(script, /Test-AidaCamoufoxSidecarInstalled \$current \$exePath/);
    assert.doesNotMatch(script, /Test-AidaCamoufoxSidecarInstalled \$staging \$stageExe/);
    assert.doesNotMatch(script, /if \(\$McpPath -and \(Test-AidaCamoufoxMcpExecutable \$McpPath \$ExePath \$Root\)\) \{ return \$true \}/);
    assert.match(script, /rate_bps=/);
    assert.match(script, /HMACSHA256/);
    assert.doesNotMatch(script, /Downloading and verifying encrypted package/);
    assert.doesNotMatch(script, /Get-AidaPackageBytesWithProgress/);
    assert.doesNotMatch(script, /package_download_progress bytes=/);
    assert.doesNotMatch(script, /package_download_attempt attempt=/);
    assert.doesNotMatch(script, /package_download_attempt_incomplete/);
    assert.doesNotMatch(script, /package_download_error bytes=/);
    assert.doesNotMatch(script, /Decrypt-AidaPackageBytesToMemory/);
    assert.doesNotMatch(script, /Invoke-AidaPEInMemory/);
    assert.doesNotMatch(script, /Resolve-AidaMappedVa/);
    assert.doesNotMatch(script, /AIDA_FILELESS_LAUNCH/);
    assert.doesNotMatch(script, /AIDA_FILELESS_NO_DISK_WRITE/);
    assert.doesNotMatch(script, /AIDA_FILELESS_DEBUG_LOG_PATH/);
    assert.doesNotMatch(script, /Initialize-AidaFilelessDebugLog/);
    assert.doesNotMatch(script, /Test-AidaNoStandaloneDiskArtifact/);
    assert.doesNotMatch(script, /launch_inmemory_enter/);
    assert.doesNotMatch(script, /Z3 bootstrap preload skipped/);
    assert.doesNotMatch(script, /Install-AidaZ3Preload/);
    assert.doesNotMatch(script, /AIDA_Z3_PRELOAD_DIR/);
    assert.doesNotMatch(script, /Z3 LoadLibrary exit/);
    assert.doesNotMatch(script, /TlsAlloc/);
    assert.doesNotMatch(script, /Find-AidaStaticTlsIndex/);
    assert.doesNotMatch(script, /NtQueryInformationProcess/);
    assert.doesNotMatch(script, /NtQueryInformationThread/);
    assert.doesNotMatch(script, /RtlAllocateHeap/);
    assert.doesNotMatch(script, /Set-AidaStaticTlsForThread/);
    assert.doesNotMatch(script, /PEB image base patch enter/);
    assert.doesNotMatch(script, /KernelBase\.dll/);
    assert.doesNotMatch(script, /preferred VirtualAlloc failed/);
    assert.doesNotMatch(script, /step8 direct_entry_enter/);
    assert.doesNotMatch(script, /step9 direct_entry_return/);
    assert.doesNotMatch(script, /AIDA_PAYLOAD_TRACE/);
    assert.doesNotMatch(script, /direct_entry_exception/);
    assert.doesNotMatch(script, /process-exit APIs left unmodified/);
    assert.doesNotMatch(script, /SetProcessValidCallTargets/);
    assert.doesNotMatch(script, /CFG call targets registered=/);
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
