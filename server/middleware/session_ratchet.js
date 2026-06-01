'use strict';

const crypto = require('crypto');
const pool = require('../db/pool');
const canonicalResponse = require('../crypto/canonical_response');
const sessionAead = require('../crypto/session_aead');

const RATCHET_VERIFY_LABEL = Buffer.from('auth', 'utf8');
const RATCHET_INFO_LABEL = 'ratchet|';
const RATCHET_BOOTSTRAP_LABEL = Buffer.from('aida_session_ratchet/v1/bootstrap', 'utf8');
const RATCHET_VERIFY_TOKEN_LABEL = Buffer.from('aida_session_ratchet/v1/verify', 'utf8');
const MAX_SESSION_TOKEN_LEN = 1024;

function isSessionTokenFormat(value) {
    if (typeof value !== 'string') return false;
    if (value.length < 32 || value.length > MAX_SESSION_TOKEN_LEN) return false;
    return sessionAead.isSealedFormat(value);
}

function deriveBootstrapSecret(sessionToken) {
    return crypto.createHmac('sha256', RATCHET_BOOTSTRAP_LABEL)
        .update(Buffer.from(String(sessionToken || ''), 'utf8'))
        .digest();
}

function deriveExpectedToken(secret, sessionToken) {
    const mac = crypto.createHmac('sha256', secret).update(RATCHET_VERIFY_LABEL).digest();
    const bind = crypto.createHmac('sha256', RATCHET_VERIFY_TOKEN_LABEL)
        .update(Buffer.from(String(sessionToken || ''), 'utf8'))
        .digest();
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; ++i) out[i] = mac[i] ^ bind[i];
    return out.toString('hex');
}

function hkdfNext(secret, counter, serverNonceHex) {
    const info = Buffer.from(RATCHET_INFO_LABEL + String(counter) + '|' + String(serverNonceHex || ''), 'utf8');
    const derived = crypto.hkdfSync('sha256', secret, Buffer.alloc(0), info, 32);
    return Buffer.isBuffer(derived) ? derived : Buffer.from(derived);
}

async function loadOrBootstrap(sessionToken, licenseKey) {
    if (!sessionToken || typeof sessionToken !== 'string') return null;
    const sessionId = sessionToken;
    const { rows } = await pool.query(
        'SELECT session_id, license_key, current_token_secret, request_counter, last_server_nonce, created_at, updated_at FROM session_ratchet WHERE session_id = $1',
        [sessionId]
    );
    if (rows.length > 0) {
        const row = rows[0];
        row.current_token_secret = Buffer.isBuffer(row.current_token_secret)
            ? row.current_token_secret
            : Buffer.from(row.current_token_secret);
        row.last_server_nonce = Buffer.isBuffer(row.last_server_nonce)
            ? row.last_server_nonce
            : Buffer.from(row.last_server_nonce || '');
        return row;
    }
    const bootstrap = deriveBootstrapSecret(sessionToken);
    const now = Math.floor(Date.now() / 1000);
    try {
        await pool.query(
            `INSERT INTO session_ratchet
                (session_id, license_key, current_token_secret, request_counter, last_server_nonce, created_at, updated_at)
             VALUES ($1, $2, $3, 0, $4, $5, $5)
             ON CONFLICT (session_id) DO NOTHING`,
            [sessionId, licenseKey || '', bootstrap, Buffer.alloc(0), now]
        );
    } catch (err) {
        console.warn('[session_ratchet] bootstrap failed:', err && err.message ? err.message : err);
        return null;
    }
    return {
        session_id: sessionId,
        license_key: licenseKey || '',
        current_token_secret: bootstrap,
        request_counter: '0',
        last_server_nonce: Buffer.alloc(0),
        created_at: now,
        updated_at: now,
    };
}

async function advance(row, sessionToken) {
    const counter = (() => {
        try { return BigInt(row.request_counter || 0); }
        catch (_) { return 0n; }
    })();
    const nextCounter = counter + 1n;
    const serverNonce = crypto.randomBytes(16);
    const serverNonceHex = serverNonce.toString('hex');
    const nextSecret = hkdfNext(row.current_token_secret, nextCounter.toString(), serverNonceHex);
    const now = Math.floor(Date.now() / 1000);
    try {
        await pool.query(
            `UPDATE session_ratchet
                SET current_token_secret = $1,
                    request_counter      = $2,
                    last_server_nonce    = $3,
                    updated_at           = $4
              WHERE session_id = $5`,
            [nextSecret, nextCounter.toString(), serverNonce, now, row.session_id]
        );
    } catch (err) {
        console.warn('[session_ratchet] advance persist failed:', err && err.message ? err.message : err);
        return null;
    }
    return {
        server_nonce: serverNonceHex,
        next_counter: nextCounter.toString(),
        token_hint: deriveExpectedToken(nextSecret, sessionToken),
    };
}

function wrapResponseJson(res, ratchetCtx) {
    const originalJson = res.json.bind(res);
    res.json = function ratchetEnvelopeJson(body) {
        if (!ratchetCtx || !body || typeof body !== 'object') {
            return originalJson(body);
        }
        if (typeof body.payload === 'string' && typeof body.sig === 'string') {
            const decoded = canonicalResponse.unpackPayload(body.payload);
            if (decoded && typeof decoded === 'object') {
                decoded.session_ratchet_nonce = ratchetCtx.server_nonce;
                decoded.session_ratchet_counter = ratchetCtx.next_counter;
                decoded.session_ratchet_token_hint = ratchetCtx.token_hint;
                return originalJson(canonicalResponse.buildEnvelope(decoded));
            }
            return originalJson(body);
        }
        body.session_ratchet_nonce = ratchetCtx.server_nonce;
        body.session_ratchet_counter = ratchetCtx.next_counter;
        body.session_ratchet_token_hint = ratchetCtx.token_hint;
        return originalJson(body);
    };
}

function enforce(options) {
    const opts = options || {};
    const required = opts.required !== false;
    return async function sessionRatchetMiddleware(req, res, next) {
        try {
            const body = req.body || {};
            const sessionToken = typeof body.session_token === 'string' ? body.session_token.trim() : '';
            const licenseKey = typeof body.license_key === 'string' ? body.license_key.trim() : '';
            if (!sessionToken) {
                if (!required) return next();
                return res.status(401).json({ error: 'session_ratchet_mismatch' });
            }
            if (!isSessionTokenFormat(sessionToken)) {
                return res.status(401).json({ error: 'session_ratchet_mismatch' });
            }
            const row = await loadOrBootstrap(sessionToken, licenseKey);
            if (!row) {
                return res.status(401).json({ error: 'session_ratchet_mismatch' });
            }
            if (!Buffer.isBuffer(row.current_token_secret) || row.current_token_secret.length !== 32) {
                return res.status(401).json({ error: 'session_ratchet_mismatch' });
            }
            if (licenseKey && row.license_key && licenseKey !== row.license_key) {
                return res.status(401).json({ error: 'session_ratchet_mismatch' });
            }
            const ratchetCtx = await advance(row, sessionToken);
            if (!ratchetCtx) {
                return res.status(503).json({ error: 'session_ratchet_unavailable' });
            }
            req.sessionRatchet = ratchetCtx;
            wrapResponseJson(res, ratchetCtx);
            return next();
        } catch (err) {
            console.warn('[session_ratchet] enforce error:', err && err.message ? err.message : err);
            return res.status(500).json({ error: 'session_ratchet_internal' });
        }
    };
}

async function bootstrapForSession(sessionToken, licenseKey) {
    if (!sessionToken) return null;
    return loadOrBootstrap(sessionToken, licenseKey);
}

module.exports = {
    enforce,
    bootstrapForSession,
    deriveBootstrapSecret,
    deriveExpectedToken,
    _internal: {
        isSessionTokenFormat,
        MAX_SESSION_TOKEN_LEN,
    },
};
