

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
const sentinelRoutes = require('./routes/sentinel');
const telemetryRoutes = require('./routes/telemetry');
const tlsExporter = require('./crypto/tls_exporter');

if (process.env.NODE_APP_INSTANCE && parseInt(process.env.NODE_APP_INSTANCE, 10) > 0) {
    console.error('[server] FATAL: server must run as a single PM2 instance (NODE_APP_INSTANCE=' + process.env.NODE_APP_INSTANCE + '); in-process rotation state breaks under cluster mode.');
    process.exit(1);
}

const app = express();


app.set('trust proxy', 1);
app.use(helmet());

const corsOriginEnv = (process.env.CORS_ORIGIN || 'https://aidapro.net').trim();
const corsOrigins = corsOriginEnv === '*' ? '*' : corsOriginEnv.split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
    origin: corsOrigins,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-TLS-Exporter', 'X-Challenge-Id', 'X-Challenge-Signature', 'X-Sentinel-Token'],
}));
app.use(express.json({ limit: '1mb' }));

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
            || req.ip
            || 'unknown';
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
    keyGenerator: (req) => {
        const body = req.body;
        if (body && typeof body === 'object' && typeof body.license_key === 'string' && body.license_key.length > 0) {
            return 'lic:' + body.license_key;
        }
        return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
            || req.ip
            || 'unknown';
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'download_rate_limited' });
    },
});

app.use('/api/', limiter);
app.use('/api/download/', downloadLimiter);
app.use('/api/', tlsExporter.middleware);
app.use('/validateLicense', tlsExporter.middleware);

const killLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
            || req.ip
            || 'unknown';
    },
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'kill_rate_limited' });
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


app.use('/api/download', downloadRoutes);


app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});


app.use((_req, res) => {
    res.status(404).json({ status: 'error', reason: 'not_found' });
});


app.use((err, _req, res, _next) => {
    console.error('[server] Unhandled error:', err);
    res.status(500).json({ status: 'error', reason: 'internal_error' });
});


const PORT = parseInt(process.env.PORT, 10) || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] AiDA License Server listening on port ${PORT}`);
    console.log(`[server] License endpoint: POST /validateLicense & /api/license`);
    console.log(`[server] ARC download:     POST /api/download/arc`);
    console.log(`[server] AiDA download:    GET  /api/download/aida`);
    console.log(`[server] Health check:     GET  /health`);
});

module.exports = app;
