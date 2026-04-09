-- ============================================================================
-- AiDA License Server — PostgreSQL Schema
-- ============================================================================
-- Run once on the aidapro.net server:
--   psql -U aida_api -d aida_prod -f schema.sql
-- ============================================================================

BEGIN;

-- ─── Licenses ───────────────────────────────────────────────────────────────
-- Each row is one license key (format: AIDA-XXXX-XXXX-XXXX-XXXX).
-- Maps 1:1 to Firebase /licenses/{key}.

CREATE TABLE IF NOT EXISTS licenses (
    key             TEXT        PRIMARY KEY,
    active          BOOLEAN     NOT NULL DEFAULT true,
    hwid            TEXT        NOT NULL DEFAULT '',
    expires         TEXT        NOT NULL DEFAULT '',      -- 'YYYY-MM-DD' or '' for perpetual
    plan            TEXT        NOT NULL DEFAULT 'standard',
    note            TEXT        NOT NULL DEFAULT '',
    created_at      BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    created_by      TEXT        NOT NULL DEFAULT '',
    revoked_at      BIGINT,
    revoked_at_iso  TEXT,
    revoked_reason  TEXT,
    revoked_version TEXT,
    revoked_hwid    TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_hwid   ON licenses (hwid) WHERE hwid != '';
CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses (active);
CREATE INDEX IF NOT EXISTS idx_licenses_plan   ON licenses (plan);

-- ─── Sessions ───────────────────────────────────────────────────────────────
-- One active session per license key.
-- Maps 1:1 to Firebase /sessions/{key}.

CREATE TABLE IF NOT EXISTS sessions (
    license_key     TEXT        PRIMARY KEY REFERENCES licenses(key) ON DELETE CASCADE,
    session_token   TEXT        NOT NULL,
    server_nonce    TEXT        NOT NULL,
    issued_at       BIGINT      NOT NULL,
    ttl             INTEGER     NOT NULL DEFAULT 3600,
    hwid            TEXT        NOT NULL DEFAULT '',
    ip              TEXT        NOT NULL DEFAULT '',
    plugin_version  TEXT        NOT NULL DEFAULT 'unknown',
    last_heartbeat  BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions (session_token);

-- ─── Bans ───────────────────────────────────────────────────────────────────
-- Two ban types: 'hwid' and 'ip'.
-- Maps to Firebase /bans/hwid/{value} and /bans/ip/{normalized}.

CREATE TABLE IF NOT EXISTS bans (
    id              SERIAL      PRIMARY KEY,
    ban_type        TEXT        NOT NULL CHECK (ban_type IN ('hwid', 'ip')),
    value           TEXT        NOT NULL,
    reason          TEXT        NOT NULL DEFAULT 'violation',
    banned_at       BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    banned_at_iso   TEXT        NOT NULL DEFAULT '',
    plugin_version  TEXT        NOT NULL DEFAULT 'unknown',
    ip              TEXT        NOT NULL DEFAULT '',       -- cross-ref: IP when banning an HWID
    hwid            TEXT        NOT NULL DEFAULT '',       -- cross-ref: HWID when banning an IP
    original_ip     TEXT        NOT NULL DEFAULT '',
    banned_by       TEXT        NOT NULL DEFAULT 'system',
    UNIQUE (ban_type, value)
);

CREATE INDEX IF NOT EXISTS idx_bans_type_value ON bans (ban_type, value);

-- ─── Violations ─────────────────────────────────────────────────────────────
-- Audit trail for all anti-RE detections and ban events.
-- Maps to Firebase /violations/{hwid}_{timestamp}.

CREATE TABLE IF NOT EXISTS violations (
    id              SERIAL      PRIMARY KEY,
    hwid            TEXT        NOT NULL DEFAULT 'unknown',
    ip              TEXT        NOT NULL DEFAULT 'unknown',
    reason          TEXT        NOT NULL DEFAULT 'violation',
    timestamp       BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    timestamp_iso   TEXT        NOT NULL DEFAULT '',
    plugin_version  TEXT        NOT NULL DEFAULT 'unknown',
    license_key     TEXT
);

CREATE INDEX IF NOT EXISTS idx_violations_hwid      ON violations (hwid);
CREATE INDEX IF NOT EXISTS idx_violations_timestamp  ON violations (timestamp DESC);

-- ─── Downloads ──────────────────────────────────────────────────────────────
-- Tracks every AiDA binary or ARC module download for auditing.

CREATE TABLE IF NOT EXISTS downloads (
    id              SERIAL      PRIMARY KEY,
    hwid            TEXT        NOT NULL DEFAULT '',
    ip              TEXT        NOT NULL DEFAULT '',
    license_key     TEXT        NOT NULL DEFAULT '',
    artifact        TEXT        NOT NULL DEFAULT 'arc' CHECK (artifact IN ('aida', 'arc')),
    downloaded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_downloads_hwid      ON downloads (hwid);
CREATE INDEX IF NOT EXISTS idx_downloads_timestamp ON downloads (downloaded_at DESC);

COMMIT;
