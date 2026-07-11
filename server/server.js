

(function loadEnvFile() {
    const fs = require('fs'), path = require('path');
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;
    const overrideKeys = new Set([
        'ED25519_PRIVATE_KEY_B64',
        'ED25519_PUBLIC_KEY_B64',
        'ED25519_NEXT_PRIVATE_KEY_B64',
        'ED25519_NEXT_PUBKEY_B64',
        'ARC_MASTER_SECRET',
        'SERVER_MASTER_KEY_B64',
        'CHALLENGE_SIGNING_SECRET',
        'CLIENT_TELEMETRY_PUBKEY_B64',
        'AIDA_PUBLIC_ORIGIN',
        'AIDA_BOOTSTRAP_ARTIFACT_URL',
        'AIDA_BOOTSTRAP_ARTIFACT_SHA256',
        'AIDA_BOOTSTRAP_ARTIFACT_VERSION',
        'AIDA_BOOTSTRAP_ARTIFACT_NAME',
        'AIDA_BOOTSTRAP_ARTIFACT_SIZE',
        'AIDA_BOOTSTRAP_ARTIFACT_FORMAT',
        'AIDA_BOOTSTRAP_ARTIFACT_DIR',
        'AIDA_BOOTSTRAP_PACKAGE_SHA256',
        'AIDA_BOOTSTRAP_PACKAGE_SIZE',
        'AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64',
        'AIDA_BOOTSTRAP_PACKAGE_MAC_KEY_B64',
        'AIDA_BOOTSTRAP_SIGNER_THUMBPRINT',
        'AIDA_BOOTSTRAP_REQUIRE_AUTHENTICODE',
        'AIDA_BOOTSTRAP_ACCEPT_PINNED_PRIVATE_CA_SIGNER',
        'AIDA_BOOTSTRAP_REQUIRE_TLS_PIN',
        'AIDA_BOOTSTRAP_TLS_CERT_SHA256',
        'AIDA_BOOTSTRAP_TLS_SPKI_SHA256',
        'AIDA_BOOTSTRAP_SCRIPT_PATH',
        'AIDA_BOOTSTRAP_SCRIPT_SLUG',
        'AIDA_BOOTSTRAP_ROOT_NEGOTIATION',
        'AIDA_BOOTSTRAP_LEGACY_ROUTE_ENABLED',
        'AIDA_BOOTSTRAP_SCRIPT_RATE_LIMIT_PER_MINUTE',
        'AIDA_BOOTSTRAP_ARTIFACT_RATE_LIMIT_PER_10MIN',
        'AIDA_BOOTSTRAP_API_RATE_LIMIT_PER_MINUTE',
        'AIDA_BOOTSTRAP_PACKAGE_MAX_BYTES',
        'AIDA_CAMOUFOX_SIDECAR_URL',
        'AIDA_CAMOUFOX_SIDECAR_SHA256',
        'AIDA_CAMOUFOX_SIDECAR_VERSION',
        'AIDA_CAMOUFOX_SIDECAR_SIZE',
        'AIDA_CAMOUFOX_SIDECAR_EXE_REL',
        'AIDA_CAMOUFOX_SIDECAR_PYTHON_REL',
        'AIDA_CAMOUFOX_SIDECAR_MAX_BYTES',
        'AIDA_CAMOUFOX_SIDECAR_ALLOW_HTTP',
        'AIDA_CAMOUFOX_MCP_URL',
        'AIDA_CAMOUFOX_MCP_SHA256',
        'AIDA_CAMOUFOX_MCP_VERSION',
        'AIDA_CAMOUFOX_MCP_SIZE',
        'AIDA_CAMOUFOX_MCP_REL',
        'AIDA_CAMOUFOX_MCP_MAX_BYTES',
        'BOOTSTRAP_TOKEN_SECRET_B64',
        'BOOTSTRAP_TOKEN_TTL_SECONDS',
        'BOOTSTRAP_TOKEN_BIND_IP',
        'AIDA_BUILD_MASTER_KEY_B64',
        'ADMIN_HMAC_SECRET_B64',
        'AIDA_PERSONALIZER_PATH',
        'AIDA_PERSONALIZER_SHA256',
        'AIDA_TEMPLATE_DIR',
        'AIDA_OUTPUT_DIR',
        'AIDA_BUILD_TMP_DIR',
        'AIDA_BUILD_TIMEOUT_SECONDS',
        'AIDA_BUILD_ADAPTIVE_EXTENSION_SECONDS',
        'AIDA_OUTPUT_TTL_SECONDS',
        'AIDA_BUILD_CLEANUP_INTERVAL_SECONDS',
        'AIDA_BUILD_API_RATE_LIMIT_PER_MINUTE',
        'AIDA_BUILD_RATE_LIMIT_PER_HOUR',
        'AIDA_STRICT_TEMPLATE_VERSION',
    ]);
    for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const idx = t.indexOf('=');
        if (idx < 0) continue;
        const k = t.substring(0, idx).trim();
        const v = t.substring(idx + 1).trim();
        if (!k) continue;
        if (overrideKeys.has(k) || !(k in process.env)) {
            const before = process.env[k];
            process.env[k] = v;
            if (overrideKeys.has(k) && before !== undefined && before !== v) {
                console.warn(`[server] env override: ${k} (was cached, replaced from .env)`);
            }
        }
    }
})();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const licenseRoutes = require('./routes/license');
const downloadRoutes = require('./routes/download');
const functionsRoutes = require('./routes/functions');
const sentinelRoutes = require('./routes/sentinel');
const telemetryRoutes = require('./routes/telemetry');
const stolenBytesRoutes = require('./routes/stolen_bytes');
const attestationRoutes = require('./routes/attestation');
const serverInfoRoutes = require('./routes/server_info');
const bootstrapRoutes = require('./routes/bootstrap');
const customerDownloadRoutes = require('./routes/customer_download');
const buildRoutes = require('./routes/build');
const honeypotRoutes = require('./routes/honeypot');
const tlsExporter = require('./crypto/tls_exporter');
const killSwitch = require('./middleware/kill_switch');

if (process.env.NODE_APP_INSTANCE && parseInt(process.env.NODE_APP_INSTANCE, 10) > 0) {
    console.error('[server] FATAL: server must run as a single PM2 instance (NODE_APP_INSTANCE=' + process.env.NODE_APP_INSTANCE + '); in-process rotation state breaks under cluster mode.');
    process.exit(1);
}

const app = express();

app.disable('x-powered-by');

app.set('trust proxy', (ip) => {
    if (typeof ip !== 'string' || ip.length === 0) return false;
    if (ip === '127.0.0.1' || ip === '::1') return true;
    if (ip === '::ffff:127.0.0.1') return true;
    return false;
});

function clientIp(req) {
    return (req && (req.ip || (req.socket && req.socket.remoteAddress))) || 'unknown';
}

function positiveIntEnv(name, fallback) {
    const n = parseInt(process.env[name] || '', 10);
    if (Number.isFinite(n) && n > 0) return n;
    return fallback;
}

app.use(helmet());

const corsOriginEnv = (process.env.CORS_ORIGIN || 'https://aidapro.net').trim();
const corsOrigins = corsOriginEnv === '*' ? '*' : corsOriginEnv.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
    origin: corsOrigins,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-TLS-Exporter', 'X-Challenge-Id', 'X-Challenge-Signature', 'X-Sentinel-Token', 'X-Bot-Signature', 'X-Admin-Signature'],
}));
app.use(express.json({
    limit: '1mb',
    verify: (req, _res, buf) => {
        try { req.rawBody = buf && buf.length ? buf.toString('utf8') : ''; }
        catch (_) { req.rawBody = ''; }
    },
}));

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    skip: (req) => {
        const url = req.originalUrl || req.url || '';
        return url.startsWith('/api/download/');
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'rate_limited' });
    },
});

const downloadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 2000,
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        const body = req.body;
        if (body && typeof body === 'object' && typeof body.license_key === 'string' && body.license_key.length > 0) {
            return 'lic:' + body.license_key;
        }
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'download_rate_limited' });
    },
});

app.use('/api/', limiter);
app.use('/api/download/', downloadLimiter);

app.use('/api/license', killSwitch.middleware);
app.use('/api/download', killSwitch.middleware);
app.use('/api/arc', killSwitch.middleware);
app.use('/api/bootstrap', killSwitch.middleware);
app.use('/api/customer-download', killSwitch.middleware);
app.use('/api/build', killSwitch.middleware);
app.use('/validateLicense', killSwitch.middleware);

app.use('/api/', tlsExporter.middleware);
app.use('/validateLicense', tlsExporter.middleware);

const killLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'kill_rate_limited' });
    },
});

const bootstrapScriptLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: positiveIntEnv('AIDA_BOOTSTRAP_SCRIPT_RATE_LIMIT_PER_MINUTE', 30),
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'bootstrap_script_rate_limited' });
    },
});

const bootstrapArtifactLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: positiveIntEnv('AIDA_BOOTSTRAP_ARTIFACT_RATE_LIMIT_PER_10MIN', 12),
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'bootstrap_artifact_rate_limited' });
    },
});

const bootstrapApiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: positiveIntEnv('AIDA_BOOTSTRAP_API_RATE_LIMIT_PER_MINUTE', 20),
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'bootstrap_api_rate_limited' });
    },
});

const buildApiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: positiveIntEnv('AIDA_BUILD_API_RATE_LIMIT_PER_MINUTE', 20),
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: false,
    skipFailedRequests: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        return clientIp(req);
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'build_api_rate_limited' });
    },
});

app.use((req, res, next) => {
    if (req.path === '/' || req.path === '/kill') {
        const bodyAction = (req.body && typeof req.body === 'object') ? req.body.action : null;
        if (bodyAction === 'kill') return killLimiter(req, res, next);
    }
    next();
});


app.use('/validateLicense', licenseRoutes);
app.use('/api/license', licenseRoutes);
app.use('/api/sentinel', sentinelRoutes);
app.use('/api/telemetry', telemetryRoutes);
app.use('/api/stolen_bytes', stolenBytesRoutes);
app.use('/api/attestation', attestationRoutes);
app.use('/api/server_info', serverInfoRoutes);
app.use('/api/bootstrap', bootstrapApiLimiter, bootstrapRoutes.router);
app.use('/api/customer-download', customerDownloadRoutes.router);
app.use('/api/build', buildApiLimiter, buildRoutes.router);
const bootstrapScriptRoutes = bootstrapRoutes.getScriptRouteConfig();
if (bootstrapScriptRoutes.root_content_negotiation) {
    app.get('/', bootstrapScriptLimiter, bootstrapRoutes.rootScriptHandler);
}
if (bootstrapScriptRoutes.script_path) {
    app.get(bootstrapScriptRoutes.script_path, bootstrapScriptLimiter, bootstrapRoutes.scriptHandler);
}
if (bootstrapScriptRoutes.legacy_route_enabled) {
    app.get(bootstrapScriptRoutes.legacy_path, bootstrapScriptLimiter, bootstrapRoutes.scriptHandler);
}
app.get('/bootstrap-artifacts/:name', bootstrapArtifactLimiter, bootstrapRoutes.artifactHandler);
app.get('/d/a/:token', customerDownloadRoutes.landingHandler);


app.use('/api/download', downloadRoutes);
app.use('/api/arc', downloadRoutes);
app.use('/api/arc/function', functionsRoutes);
app.use('/api/honeypot', honeypotRoutes);


app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

const buildQueue = require('./workers/build_queue');
buildQueue.start();


app.use((_req, res) => {
    res.status(404).json({ status: 'error', reason: 'not_found' });
});


app.use((err, _req, res, _next) => {
    console.error('[server] Unhandled error:', err);
    res.status(500).json({ status: 'error', reason: 'internal_error' });
});


const PORT = parseInt(process.env.PORT, 10) || 3001;
const BIND_HOST = process.env.BIND_HOST || process.env.AIDA_BIND_HOST || '127.0.0.1';
app.listen(PORT, BIND_HOST, () => {
    console.log(`[server] AiDA License Server listening on ${BIND_HOST}:${PORT}`);
    console.log(`[server] License endpoint: POST /validateLicense & /api/license`);
    console.log(`[server] ARC download:     POST /api/download/arc`);
    console.log(`[server] Health check:     GET  /health`);
});

module.exports = app;
