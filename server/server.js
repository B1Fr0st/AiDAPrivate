// ============================================================================
// AiDA License Server — Main Entry Point
// ============================================================================
// Express application with Helmet security headers, CORS, rate limiting,
// and the license + download routes.
//
// Usage:
//   NODE_ENV=production node server.js
//   pm2 start ecosystem.config.js
// ============================================================================

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const licenseRoutes = require('./routes/license');
const downloadRoutes = require('./routes/download');

const app = express();

// ─── Security Middleware ────────────────────────────────────────────────────

app.set('trust proxy', 1); // Trust first proxy (Nginx)
app.use(helmet());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '1mb' }));

// ─── Rate Limiting ──────────────────────────────────────────────────────────
// 30 requests per minute per IP — matches Firebase function behavior.

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

// ─── Routes ─────────────────────────────────────────────────────────────────

// License validation — identical endpoint semantics to Firebase.
// The AiDA client POSTs to /validateLicense for backward compatibility;
// new path /api/license also works.
app.use('/validateLicense', licenseRoutes);
app.use('/api/license', licenseRoutes);

// ARC + binary downloads
app.use('/api/download', downloadRoutes);

// Health check
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

// 404 catch-all
app.use((_req, res) => {
    res.status(404).json({ status: 'error', reason: 'not_found' });
});

// Global error handler
app.use((err, _req, res, _next) => {
    console.error('[server] Unhandled error:', err);
    res.status(500).json({ status: 'error', reason: 'internal_error' });
});

// ─── Start ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT, 10) || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] AiDA License Server listening on port ${PORT}`);
    console.log(`[server] License endpoint: POST /validateLicense & /api/license`);
    console.log(`[server] ARC download:     POST /api/download/arc`);
    console.log(`[server] AiDA download:    GET  /api/download/aida`);
    console.log(`[server] Health check:     GET  /health`);
});

module.exports = app;
