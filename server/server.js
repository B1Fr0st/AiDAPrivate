

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
    handler: (_req, res) => {
        res.status(429).json({ status: 'error', reason: 'rate_limited' });
    },
});

app.use('/api/', limiter);
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
