#!/usr/bin/env node
// ============================================================================
// AiDA — Firebase RTDB → PostgreSQL Migration Script
// ============================================================================
// Exports ALL data from Firebase (licenses, sessions, bans, violations) and
// inserts it into the PostgreSQL database on the new server.
//
// Usage:
//   node migrate-firebase-to-pg.js
//
// Environment variables (or uses hardcoded defaults for AiDA):
//   FIREBASE_DB_URL   — Firebase RTDB URL
//   FIREBASE_SECRET   — Database secret for admin access
//   DATABASE_URL      — PostgreSQL connection string
// ============================================================================

const { Pool } = require('pg');

// ─── Configuration ──────────────────────────────────────────────────────────

const FIREBASE_DB_URL = process.env.FIREBASE_DB_URL
    || 'https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app';
const FIREBASE_SECRET = process.env.FIREBASE_SECRET
    || 'bWLmMKBhD3TE7iYMnKizIjOrt4jXd9R1m0CVCj6P';
const DATABASE_URL    = process.env.DATABASE_URL
    || 'postgresql://ruar:EhF3NbwCQ4ch2NxtkqP7@23.88.62.199:5432/aida_db';

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: false,
});

// ─── Firebase REST helpers ──────────────────────────────────────────────────

function fbUrl(path) {
    return `${FIREBASE_DB_URL}/${path}.json?auth=${FIREBASE_SECRET}`;
}

async function fbGet(path) {
    const res = await fetch(fbUrl(path));
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Firebase GET ${path} failed: ${res.status} — ${body}`);
    }
    return res.json();
}

// ─── Migration Functions ────────────────────────────────────────────────────

async function migrateLicenses() {
    console.log('\n── Migrating licenses ─────────────────────────────────────');
    const licenses = await fbGet('licenses');
    if (!licenses) {
        console.log('  No licenses found in Firebase.');
        return 0;
    }

    const entries = Object.entries(licenses);
    console.log(`  Found ${entries.length} license(s) in Firebase.`);

    let migrated = 0;
    let skipped = 0;

    for (const [key, data] of entries) {
        try {
            // Firebase stores created_at as either a date string "2025-04-09" or
            // an epoch number.  Normalize to epoch bigint.
            let createdAt;
            if (typeof data.created_at === 'number') {
                createdAt = data.created_at;
            } else if (typeof data.created_at === 'string' && data.created_at) {
                const d = new Date(data.created_at);
                createdAt = Number.isNaN(d.getTime()) ? Math.floor(Date.now() / 1000) : Math.floor(d.getTime() / 1000);
            } else {
                createdAt = Math.floor(Date.now() / 1000);
            }

            // Normalize revoked_at the same way
            let revokedAt = null;
            if (typeof data.revoked_at === 'number') {
                revokedAt = data.revoked_at;
            } else if (typeof data.revoked_at === 'string' && data.revoked_at) {
                const d = new Date(data.revoked_at);
                revokedAt = Number.isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
            }

            await pool.query(
                `INSERT INTO licenses (key, active, hwid, expires, plan, note, created_at, created_by,
                                       revoked_at, revoked_at_iso, revoked_reason, revoked_version, revoked_hwid)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                 ON CONFLICT (key) DO UPDATE SET
                     active = EXCLUDED.active,
                     hwid = EXCLUDED.hwid,
                     expires = EXCLUDED.expires,
                     plan = EXCLUDED.plan,
                     note = EXCLUDED.note,
                     created_at = EXCLUDED.created_at,
                     created_by = EXCLUDED.created_by,
                     revoked_at = EXCLUDED.revoked_at,
                     revoked_at_iso = EXCLUDED.revoked_at_iso,
                     revoked_reason = EXCLUDED.revoked_reason,
                     revoked_version = EXCLUDED.revoked_version,
                     revoked_hwid = EXCLUDED.revoked_hwid`,
                [
                    key,
                    data.active !== false,
                    data.hwid || '',
                    data.expires || '',
                    data.plan || 'standard',
                    data.note || '',
                    createdAt,
                    data.created_by || '',
                    revokedAt,
                    data.revoked_at_iso || null,
                    data.revoked_reason || null,
                    data.revoked_version || null,
                    data.revoked_hwid || null,
                ]
            );
            migrated++;
            console.log(`  ✅ ${key} — ${data.plan || 'standard'} — ${data.note || '(no note)'}`);
        } catch (err) {
            console.error(`  ❌ ${key}: ${err.message}`);
            skipped++;
        }
    }

    console.log(`  Migrated: ${migrated}, Skipped: ${skipped}`);
    return migrated;
}

async function migrateSessions() {
    console.log('\n── Migrating sessions ─────────────────────────────────────');
    const sessions = await fbGet('sessions');
    if (!sessions) {
        console.log('  No sessions found in Firebase.');
        return 0;
    }

    const entries = Object.entries(sessions);
    console.log(`  Found ${entries.length} session(s) in Firebase.`);

    let migrated = 0;
    let skipped = 0;

    for (const [licenseKey, data] of entries) {
        try {
            // Check that the license exists in PG (foreign key constraint)
            const check = await pool.query('SELECT 1 FROM licenses WHERE key = $1', [licenseKey]);
            if (check.rows.length === 0) {
                console.log(`  ⚠️  ${licenseKey}: license not in PG, skipping session`);
                skipped++;
                continue;
            }

            await pool.query(
                `INSERT INTO sessions (license_key, session_token, server_nonce, issued_at, ttl, hwid, ip, plugin_version, last_heartbeat)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (license_key) DO UPDATE SET
                     session_token = EXCLUDED.session_token,
                     server_nonce = EXCLUDED.server_nonce,
                     issued_at = EXCLUDED.issued_at,
                     ttl = EXCLUDED.ttl,
                     hwid = EXCLUDED.hwid,
                     ip = EXCLUDED.ip,
                     plugin_version = EXCLUDED.plugin_version,
                     last_heartbeat = EXCLUDED.last_heartbeat`,
                [
                    licenseKey,
                    data.session_token || '',
                    data.server_nonce || '',
                    data.issued_at || Math.floor(Date.now() / 1000),
                    data.ttl || 3600,
                    data.hwid || '',
                    data.ip || '',
                    data.plugin_version || 'unknown',
                    data.last_heartbeat || data.issued_at || Math.floor(Date.now() / 1000),
                ]
            );
            migrated++;
            console.log(`  ✅ Session for ${licenseKey}`);
        } catch (err) {
            console.error(`  ❌ ${licenseKey}: ${err.message}`);
            skipped++;
        }
    }

    console.log(`  Migrated: ${migrated}, Skipped: ${skipped}`);
    return migrated;
}

async function migrateBans() {
    console.log('\n── Migrating bans ─────────────────────────────────────────');

    let total = 0;

    // HWID bans
    const hwidBans = await fbGet('bans/hwid');
    if (hwidBans) {
        const entries = Object.entries(hwidBans);
        console.log(`  Found ${entries.length} HWID ban(s).`);
        for (const [hwid, data] of entries) {
            try {
                await pool.query(
                    `INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, ip, hwid, original_ip, banned_by)
                     VALUES ('hwid', $1, $2, $3, $4, $5, $6, '', '', $7)
                     ON CONFLICT (ban_type, value) DO UPDATE SET
                         reason = EXCLUDED.reason,
                         banned_at = EXCLUDED.banned_at,
                         banned_at_iso = EXCLUDED.banned_at_iso,
                         plugin_version = EXCLUDED.plugin_version,
                         ip = EXCLUDED.ip,
                         banned_by = EXCLUDED.banned_by`,
                    [
                        hwid,
                        data.reason || 'violation',
                        data.banned_at || Math.floor(Date.now() / 1000),
                        data.banned_at_iso || '',
                        data.plugin_version || 'unknown',
                        data.ip || '',
                        data.banned_by || 'system',
                    ]
                );
                total++;
                console.log(`  ✅ HWID ban: ${hwid.slice(0, 16)}…`);
            } catch (err) {
                console.error(`  ❌ HWID ban ${hwid}: ${err.message}`);
            }
        }
    } else {
        console.log('  No HWID bans found.');
    }

    // IP bans
    const ipBans = await fbGet('bans/ip');
    if (ipBans) {
        const entries = Object.entries(ipBans);
        console.log(`  Found ${entries.length} IP ban(s).`);
        for (const [normalizedIp, data] of entries) {
            try {
                await pool.query(
                    `INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, plugin_version, ip, hwid, original_ip, banned_by)
                     VALUES ('ip', $1, $2, $3, $4, $5, '', $6, $7, $8)
                     ON CONFLICT (ban_type, value) DO UPDATE SET
                         reason = EXCLUDED.reason,
                         banned_at = EXCLUDED.banned_at,
                         banned_at_iso = EXCLUDED.banned_at_iso,
                         plugin_version = EXCLUDED.plugin_version,
                         hwid = EXCLUDED.hwid,
                         original_ip = EXCLUDED.original_ip,
                         banned_by = EXCLUDED.banned_by`,
                    [
                        normalizedIp,
                        data.reason || 'violation',
                        data.banned_at || Math.floor(Date.now() / 1000),
                        data.banned_at_iso || '',
                        data.plugin_version || 'unknown',
                        data.hwid || '',
                        data.original_ip || '',
                        data.banned_by || 'system',
                    ]
                );
                total++;
                console.log(`  ✅ IP ban: ${data.original_ip || normalizedIp}`);
            } catch (err) {
                console.error(`  ❌ IP ban ${normalizedIp}: ${err.message}`);
            }
        }
    } else {
        console.log('  No IP bans found.');
    }

    console.log(`  Total bans migrated: ${total}`);
    return total;
}

async function migrateViolations() {
    console.log('\n── Migrating violations ───────────────────────────────────');
    const violations = await fbGet('violations');
    if (!violations) {
        console.log('  No violations found in Firebase.');
        return 0;
    }

    const entries = Object.entries(violations);
    console.log(`  Found ${entries.length} violation(s) in Firebase.`);

    let migrated = 0;

    for (const [, data] of entries) {
        try {
            await pool.query(
                `INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version, license_key)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                    data.hwid || 'unknown',
                    data.ip || 'unknown',
                    data.reason || 'violation',
                    data.timestamp || Math.floor(Date.now() / 1000),
                    data.timestamp_iso || '',
                    data.plugin_version || 'unknown',
                    data.license_key || null,
                ]
            );
            migrated++;
        } catch (err) {
            console.error(`  ❌ Violation: ${err.message}`);
        }
    }

    console.log(`  Migrated: ${migrated} violation(s)`);
    return migrated;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
    console.log('============================================================');
    console.log('  AiDA — Firebase → PostgreSQL Migration');
    console.log('============================================================');
    console.log(`  Firebase:   ${FIREBASE_DB_URL}`);
    console.log(`  PostgreSQL: ${DATABASE_URL.replace(/:[^@]+@/, ':***@')}`);
    console.log('============================================================');

    try {
        // Test PG connection
        const pgTest = await pool.query('SELECT 1 AS ok');
        if (pgTest.rows[0].ok !== 1) throw new Error('PG connection test failed');
        console.log('\n✅ PostgreSQL connection OK');

        // Test Firebase connection by fetching the licenses root
        const fbTest = await fbGet('licenses');
        const fbKeyCount = fbTest ? Object.keys(fbTest).length : 0;
        console.log(`✅ Firebase connection OK (${fbKeyCount} license keys found)`);

        // Run migrations in order (licenses first due to FK constraints)
        const licensesCount   = await migrateLicenses();
        const sessionsCount   = await migrateSessions();
        const bansCount       = await migrateBans();
        const violationsCount = await migrateViolations();

        console.log('\n============================================================');
        console.log('  Migration Summary');
        console.log('============================================================');
        console.log(`  Licenses:   ${licensesCount}`);
        console.log(`  Sessions:   ${sessionsCount}`);
        console.log(`  Bans:       ${bansCount}`);
        console.log(`  Violations: ${violationsCount}`);
        console.log('============================================================');

        // Verify counts
        const verifyLicenses = await pool.query('SELECT count(*) FROM licenses');
        const verifySessions = await pool.query('SELECT count(*) FROM sessions');
        const verifyBans     = await pool.query('SELECT count(*) FROM bans');
        const verifyViolations = await pool.query('SELECT count(*) FROM violations');
        console.log('\n  PostgreSQL row counts:');
        console.log(`    licenses:   ${verifyLicenses.rows[0].count}`);
        console.log(`    sessions:   ${verifySessions.rows[0].count}`);
        console.log(`    bans:       ${verifyBans.rows[0].count}`);
        console.log(`    violations: ${verifyViolations.rows[0].count}`);
        console.log('\n✅ Migration complete!');

    } catch (err) {
        console.error('\n❌ Migration failed:', err.message);
        console.error(err.stack);
        process.exitCode = 1;
    } finally {
        await pool.end();
    }
}

main();
