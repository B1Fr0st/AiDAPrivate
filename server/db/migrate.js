'use strict';

const fs = require('fs');
const path = require('path');

(function loadDotEnv() {
    if (process.env.DATABASE_URL && process.env.ARC_MASTER_SECRET) return;
    const envPath = path.join(__dirname, '..', '.env');
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
            const key = trimmed.substring(0, eqIdx).trim();
            const value = trimmed.substring(eqIdx + 1).trim();
            if (!process.env[key]) process.env[key] = value;
        }
    }
})();

const pool = require('./pool');
const columnCrypt = require('../crypto/column_crypt');
const localHsm = require('../crypto/local_hsm');

async function ensurePgcrypto() {
    await pool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
    console.log('[migrate] ensured pgcrypto extension');
}

async function applyBaseSchema() {
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    await pool.query(schemaSql);
    console.log('[migrate] applied base schema.sql');
}

async function applyDirectoryMigrations() {
    const dir = path.join(__dirname, 'migrations');
    if (!fs.existsSync(dir)) {
        console.log('[migrate] no migrations directory present at', dir);
        return;
    }
    const entries = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith('.sql')).sort();
    for (const entry of entries) {
        const full = path.join(dir, entry);
        const sql = fs.readFileSync(full, 'utf8');
        try {
            await pool.query(sql);
            console.log('[migrate] applied migration', entry);
        } catch (err) {
            console.error('[migrate] migration failed:', entry, err && err.message ? err.message : err);
            throw err;
        }
    }
}

async function applyColumnEncryptionSchema() {
    const stmts = [
        `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_uuid UUID NOT NULL DEFAULT gen_random_uuid()`,
        `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS column_crypt_version INTEGER NOT NULL DEFAULT 0`,
        `CREATE INDEX IF NOT EXISTS idx_sessions_uuid ON sessions (session_uuid)`,
        `DROP INDEX IF EXISTS idx_sessions_token`,
        `CREATE TABLE IF NOT EXISTS column_crypt_meta (
            key      TEXT PRIMARY KEY,
            value    TEXT NOT NULL,
            updated  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT)
        )`,
    ];
    for (const sql of stmts) {
        await pool.query(sql);
    }
    console.log('[migrate] applied column-encryption schema additions');
}

async function rewrapExistingRows() {
    const { rows } = await pool.query(
        `SELECT license_key, session_uuid, session_token, last_proof_token, column_crypt_version
           FROM sessions
          WHERE column_crypt_version = 0`
    );
    let total = 0;
    for (const row of rows) {
        const sessionTokenStored = typeof row.session_token === 'string' ? row.session_token : '';
        const proofStored = typeof row.last_proof_token === 'string' ? row.last_proof_token : '';
        const sessionTokenWrapped = columnCrypt.isCiphertext(sessionTokenStored)
            ? sessionTokenStored
            : columnCrypt.encrypt(row.session_uuid, 'sessions/session_token', sessionTokenStored);
        const proofWrapped = proofStored.length === 0
            ? ''
            : (columnCrypt.isCiphertext(proofStored)
                ? proofStored
                : columnCrypt.encrypt(row.session_uuid, 'sessions/last_proof_token', proofStored));
        await pool.query(
            `UPDATE sessions
                SET session_token = $1,
                    last_proof_token = $2,
                    column_crypt_version = 1
              WHERE license_key = $3`,
            [sessionTokenWrapped, proofWrapped, row.license_key]
        );
        total += 1;
    }
    console.log(`[migrate] re-wrapped ${total} session row(s) under column encryption v1`);
}

async function recordHsmStamp() {
    const stamp = {
        path: localHsm.exportEnvelopePathForDocs(),
        kms_key_id: process.env.KMS_KEY_ID || '',
        recorded_at: Math.floor(Date.now() / 1000),
    };
    await pool.query(
        `INSERT INTO column_crypt_meta (key, value, updated)
         VALUES ('hsm/v1', $1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated = EXCLUDED.updated`,
        [JSON.stringify(stamp), Math.floor(Date.now() / 1000)]
    );
    console.log('[migrate] recorded HSM stamp at column_crypt_meta.hsm/v1');
}

async function main() {
    try {
        await applyBaseSchema();
        await ensurePgcrypto();
        await applyColumnEncryptionSchema();
        await applyDirectoryMigrations();
        await localHsm.initializeColumnRootKeyAsync();
        await rewrapExistingRows();
        await recordHsmStamp();
        console.log('[migrate] complete');
    } catch (err) {
        console.error('[migrate] failed:', err && err.message ? err.message : err);
        process.exitCode = 1;
    } finally {
        try { await pool.end(); } catch (_) { }
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    ensurePgcrypto,
    applyBaseSchema,
    applyDirectoryMigrations,
    applyColumnEncryptionSchema,
    rewrapExistingRows,
    recordHsmStamp,
};
