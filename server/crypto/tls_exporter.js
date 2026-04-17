
const crypto = require('crypto');

const HEADER_NAME = 'x-tls-exporter';
const REQUIRED = (process.env.TLS_EXPORTER_REQUIRED || '0') === '1';
const LABEL = process.env.TLS_EXPORTER_LABEL || 'aida/v1';

function deriveExpected(exporterSecretHex) {
    if (!exporterSecretHex || typeof exporterSecretHex !== 'string') return null;
    if (!/^[a-fA-F0-9]+$/.test(exporterSecretHex)) return null;
    if (exporterSecretHex.length < 32 || exporterSecretHex.length > 256) return null;
    const secret = Buffer.from(exporterSecretHex, 'hex');
    return crypto.createHmac('sha256', secret).update(LABEL).digest('hex');
}

function readExporterSecret(req) {
    const sock = req.socket || req.connection;
    if (!sock || typeof sock.exportKeyingMaterial !== 'function') return null;
    try {
        const material = sock.exportKeyingMaterial(32, LABEL);
        return material ? material.toString('hex') : null;
    } catch (_) {
        return null;
    }
}

function middleware(req, res, next) {
    const provided = (req.headers[HEADER_NAME] || '').toString().trim().toLowerCase();
    const serverSecret = readExporterSecret(req);

    if (!provided) {
        if (REQUIRED && serverSecret) {
            return res.status(400).json({ status: 'error', reason: 'missing_tls_exporter' });
        }
        req.tlsExporterVerified = false;
        return next();
    }

    if (!serverSecret) {
        req.tlsExporterVerified = false;
        if (REQUIRED) {
            return res.status(500).json({ status: 'error', reason: 'tls_exporter_unavailable' });
        }
        return next();
    }

    const expected = deriveExpected(serverSecret);
    if (!expected) {
        req.tlsExporterVerified = false;
        return next();
    }

    const a = Buffer.from(provided, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res.status(403).json({ status: 'error', reason: 'tls_exporter_mismatch' });
    }

    req.tlsExporterVerified = true;
    next();
}

module.exports = {
    middleware,
    deriveExpected,
    readExporterSecret,
    HEADER_NAME,
    LABEL,
};
