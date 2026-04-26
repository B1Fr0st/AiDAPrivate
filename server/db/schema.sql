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

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS active          BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid            TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires         TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS plan            TEXT    NOT NULL DEFAULT 'standard';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS note            TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_at      BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT);
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_by      TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_at      BIGINT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_at_iso  TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_reason  TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_version TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked_hwid    TEXT;

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
    last_heartbeat  BIGINT      NOT NULL,
    kill_flag       BOOLEAN     NOT NULL DEFAULT false,
    heartbeat_count INTEGER     NOT NULL DEFAULT 0,
    last_proof_token TEXT       NOT NULL DEFAULT '',
    last_code_hash  TEXT        NOT NULL DEFAULT '',
    ip_history      TEXT[]      NOT NULL DEFAULT '{}',
    heartbeat_times BIGINT[]    NOT NULL DEFAULT '{}'
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_token    TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS server_nonce     TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS issued_at        BIGINT   NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ttl              INTEGER  NOT NULL DEFAULT 3600;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS hwid             TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip               TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS plugin_version   TEXT     NOT NULL DEFAULT 'unknown';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_heartbeat   BIGINT   NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS kill_flag        BOOLEAN  NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS heartbeat_count  INTEGER  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_proof_token TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_code_hash   TEXT     NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_history       TEXT[]   NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS heartbeat_times  BIGINT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions (session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_kill  ON sessions (kill_flag) WHERE kill_flag = true;

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

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_rotation_ts  BIGINT NOT NULL DEFAULT 0;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS honeypot_export TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS challenge_id    TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_chain_tag  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_gate_bitmap INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id    TEXT        PRIMARY KEY,
    challenge_nonce TEXT        NOT NULL,
    issued_at       BIGINT      NOT NULL,
    ttl_seconds     INTEGER     NOT NULL DEFAULT 10,
    client_ip       TEXT        NOT NULL DEFAULT '',
    consumed        BOOLEAN     NOT NULL DEFAULT false,
    consumed_at     BIGINT,
    license_key     TEXT
);

CREATE INDEX IF NOT EXISTS idx_challenges_issued_at ON challenges (issued_at);
CREATE INDEX IF NOT EXISTS idx_challenges_consumed  ON challenges (consumed) WHERE consumed = false;

CREATE TABLE IF NOT EXISTS page_rotations (
    session_token   TEXT        NOT NULL,
    epoch           BIGINT      NOT NULL,
    rotation_nonce  TEXT        NOT NULL,
    rotation_key    TEXT        NOT NULL,
    rotated_at      BIGINT      NOT NULL,
    expires_at      BIGINT      NOT NULL,
    PRIMARY KEY (session_token, epoch)
);

CREATE INDEX IF NOT EXISTS idx_page_rotations_expires ON page_rotations (expires_at);

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hardware_id_sha256     TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS smbios_uuid_hash       TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS baseboard_serial_hash  TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS disk_vpd_hash          TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS machine_guid_hash      TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS install_secret_wrapped BYTEA;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS witness_key_wrapped    BYTEA;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS boot_nonce_last        TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hardware_anchor_count  INTEGER NOT NULL DEFAULT 9;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hvci_enabled           BOOLEAN;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS attest_count           INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_attest_at         BIGINT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS ioctl_seed_wrapped     BYTEA;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_sensor_snapshot   JSONB;

CREATE INDEX IF NOT EXISTS idx_licenses_hardware_id ON licenses (hardware_id_sha256) WHERE hardware_id_sha256 != '';

CREATE TABLE IF NOT EXISTS sentinel_events (
    id              BIGSERIAL   PRIMARY KEY,
    license_key     TEXT        NOT NULL,
    quorum_id       TEXT        NOT NULL DEFAULT '',
    event_type      TEXT        NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'info',
    payload         JSONB,
    hvci_enabled    BOOLEAN,
    nt_build        INTEGER,
    boot_count      INTEGER,
    received_at     BIGINT      NOT NULL,
    client_ip       TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sentinel_events_lic ON sentinel_events (license_key, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_sentinel_events_sev ON sentinel_events (severity) WHERE severity IN ('warn','critical');

CREATE TABLE IF NOT EXISTS sentinel_quorum (
    license_key     TEXT        NOT NULL,
    quorum_id       TEXT        NOT NULL,
    last_seen_at    BIGINT      NOT NULL,
    nt_build        INTEGER,
    hvci_enabled    BOOLEAN,
    PRIMARY KEY (license_key, quorum_id)
);

COMMIT;
