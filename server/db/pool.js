// ============================================================================
// AiDA License Server — PostgreSQL Connection Pool
// ============================================================================
// Provides a shared pg.Pool instance backed by DATABASE_URL.
// All queries go through pool.query() for automatic connection management.
// ============================================================================

const path = require('path');
const fs = require('fs');

// Load .env if not already loaded by PM2 ecosystem
(function loadDotEnv() {
    if (process.env.DATABASE_URL) return;
    const envPath = path.join(__dirname, '..', '.env');
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
            const key = trimmed.substring(0, eqIdx);
            if (!process.env[key]) {
                process.env[key] = trimmed.substring(eqIdx + 1);
            }
        }
    }
})();

const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    ssl: false,
});

pool.on('error', (err) => {
    console.error('[db] Unexpected pool error:', err.message);
});

pool.on('connect', () => {
    console.log('[db] New client connected to PostgreSQL');
});

module.exports = pool;
