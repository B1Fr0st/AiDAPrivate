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

CREATE TABLE IF NOT EXISTS bootstrap_delivery_tokens (
    token_id         TEXT    PRIMARY KEY,
    token_hmac       TEXT    NOT NULL,
    license_key      TEXT    NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    client_nonce     TEXT    NOT NULL,
    issued_at        BIGINT  NOT NULL,
    expires_at       BIGINT  NOT NULL,
    consumed         BOOLEAN NOT NULL DEFAULT false,
    consumed_at      BIGINT,
    source_ip        TEXT    NOT NULL DEFAULT '',
    user_agent_hash  TEXT    NOT NULL DEFAULT '',
    manifest_version TEXT    NOT NULL DEFAULT '',
    artifact_sha256  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_license ON bootstrap_delivery_tokens (license_key, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expiry  ON bootstrap_delivery_tokens (expires_at) WHERE consumed = false;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_rotation_ts  BIGINT NOT NULL DEFAULT 0;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS honeypot_export TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS challenge_id    TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_chain_tag  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_gate_bitmap INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS driver_proof_absent_streak INTEGER NOT NULL DEFAULT 0;

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

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tier                   TEXT    NOT NULL DEFAULT 'standard';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_required           BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_ek_fingerprint     TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_ek_vendor          TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_pcr_digest         TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_attest_count       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_last_attest_at     BIGINT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tpm_seal_payload       JSONB;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS flagged                BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS flagged_reason         TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS flagged_at             BIGINT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS flagged_score          DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS anomaly_last_score     DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS anomaly_last_action    TEXT    NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS anomaly_last_at        BIGINT;

CREATE INDEX IF NOT EXISTS idx_licenses_hardware_id ON licenses (hardware_id_sha256) WHERE hardware_id_sha256 != '';
CREATE INDEX IF NOT EXISTS idx_licenses_tpm_ek ON licenses (tpm_ek_fingerprint) WHERE tpm_ek_fingerprint != '';
CREATE INDEX IF NOT EXISTS idx_licenses_flagged ON licenses (flagged) WHERE flagged = true;

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

CREATE TABLE IF NOT EXISTS arc_function_calls (
    id                  BIGSERIAL   PRIMARY KEY,
    license_key         TEXT        NOT NULL,
    hwid                TEXT        NOT NULL,
    function_hash       TEXT        NOT NULL,
    nonce               TEXT        NOT NULL,
    issued_at           BIGINT      NOT NULL,
    expires_at          BIGINT      NOT NULL,
    consumed            BOOLEAN     NOT NULL DEFAULT false,
    consumed_at         BIGINT,
    duplicate_count     INTEGER     NOT NULL DEFAULT 0,
    flagged_replay      BOOLEAN     NOT NULL DEFAULT false,
    UNIQUE (license_key, function_hash, nonce)
);

CREATE INDEX IF NOT EXISTS idx_arc_function_calls_lic_hash ON arc_function_calls (license_key, function_hash, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_arc_function_calls_expires ON arc_function_calls (expires_at);

CREATE TABLE IF NOT EXISTS arc_prologue_requests (
    id                  BIGSERIAL   PRIMARY KEY,
    license_key         TEXT        NOT NULL,
    hwid                TEXT        NOT NULL,
    function_hash       TEXT        NOT NULL,
    nonce               TEXT        NOT NULL,
    requested_at_ms     BIGINT      NOT NULL,
    consumed            BOOLEAN     NOT NULL DEFAULT false,
    consumed_at_ms      BIGINT,
    flagged             BOOLEAN     NOT NULL DEFAULT false,
    flagged_reason      TEXT        NOT NULL DEFAULT '',
    UNIQUE (license_key, function_hash, nonce)
);

CREATE INDEX IF NOT EXISTS idx_arc_prologue_requests_lic_hash ON arc_prologue_requests (license_key, function_hash, requested_at_ms DESC);

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS prologue_anomaly_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS prologue_last_anomaly_at BIGINT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS prologue_last_anomaly_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS heartbeat_nonce         TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS heartbeat_nonce_issued_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_proof_history      TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_proof_current      TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_proof_epoch        BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS challenge_sealed        BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tpm_quote_digest        TEXT  NOT NULL DEFAULT '';

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS licensee_id             TEXT  NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS code_binding_pubkey     TEXT  NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS code_binding_privkey    BYTEA;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS vbs_required            BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS code_page_signatures (
    license_key     TEXT        NOT NULL,
    page_index      INTEGER     NOT NULL,
    page_digest     TEXT        NOT NULL,
    page_signature  TEXT        NOT NULL,
    issued_at       BIGINT      NOT NULL,
    PRIMARY KEY (license_key, page_index)
);

CREATE INDEX IF NOT EXISTS idx_code_page_sig_issued ON code_page_signatures (issued_at);

CREATE TABLE IF NOT EXISTS bind_proof_rotations (
    license_key     TEXT        NOT NULL,
    session_token   TEXT        NOT NULL,
    epoch           BIGINT      NOT NULL,
    bind_proof      TEXT        NOT NULL,
    issued_at       BIGINT      NOT NULL,
    PRIMARY KEY (session_token, epoch)
);

CREATE INDEX IF NOT EXISTS idx_bind_proof_session ON bind_proof_rotations (session_token, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_bind_proof_proof   ON bind_proof_rotations (bind_proof);

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_uuid          UUID    NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS column_crypt_version  INTEGER NOT NULL DEFAULT 0;

DROP INDEX IF EXISTS idx_sessions_token;
CREATE INDEX IF NOT EXISTS idx_sessions_uuid ON sessions (session_uuid);

CREATE TABLE IF NOT EXISTS column_crypt_meta (
    key      TEXT PRIMARY KEY,
    value    TEXT   NOT NULL,
    updated  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT        PRIMARY KEY,
    ts              BIGINT      NOT NULL,
    actor_id        TEXT        NOT NULL DEFAULT '',
    actor_tag       TEXT        NOT NULL DEFAULT '',
    action          TEXT        NOT NULL,
    target          TEXT        NOT NULL DEFAULT '',
    details         JSONB,
    prev_chain_hash TEXT        NOT NULL,
    chain_hash      TEXT        NOT NULL,
    hmac            TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor  ON audit_log (actor_id);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log rows are immutable (% on row id=%)', TG_OP, COALESCE(OLD.id, NEW.id);
END;
$$;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log;
CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

DO $bot_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aida_bot_ro') THEN
        BEGIN
            CREATE ROLE aida_bot_ro NOLOGIN;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'skipping CREATE ROLE aida_bot_ro: insufficient_privilege (current role lacks CREATEROLE)';
                RETURN;
            WHEN duplicate_object THEN
                NULL;
        END;
    END IF;
    BEGIN
        GRANT USAGE ON SCHEMA public TO aida_bot_ro;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO aida_bot_ro;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO aida_bot_ro;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'skipping GRANTs to aida_bot_ro: insufficient_privilege';
    END;
END
$bot_role$;

CREATE TABLE IF NOT EXISTS server_nonce_replay (
    nonce_b64       TEXT        PRIMARY KEY,
    license_key     TEXT        NOT NULL DEFAULT '',
    seen_at         BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_server_nonce_replay_seen ON server_nonce_replay (seen_at);

CREATE TABLE IF NOT EXISTS telemetry_kill_directives (
    license_key     TEXT        PRIMARY KEY REFERENCES licenses(key) ON DELETE CASCADE,
    kill_at_epoch   BIGINT      NOT NULL,
    reason          TEXT        NOT NULL DEFAULT '',
    issued_at       BIGINT      NOT NULL,
    issued_by       TEXT        NOT NULL DEFAULT 'server'
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_hmac_key BYTEA;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS anomaly_score INTEGER NOT NULL DEFAULT 0;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS honeypot_strike_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_id    TEXT   NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_id_linked_at BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_licenses_discord_id ON licenses (discord_id) WHERE discord_id != '';
CREATE INDEX IF NOT EXISTS idx_licenses_expires_epoch ON licenses (expires_epoch) WHERE expires_epoch > 0;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_factors   JSONB    NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_format     SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_grace_used_at BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_licenses_key_format ON licenses (key_format);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_contribution        BYTEA;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_response_hash       TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_key_fingerprint  TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_token_hash TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_consumed   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_issued_at  BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS license_request_rate (
    license_key     TEXT     NOT NULL,
    window_kind     TEXT     NOT NULL CHECK (window_kind IN ('minute','hour','day')),
    window_start    BIGINT   NOT NULL,
    count           INTEGER  NOT NULL DEFAULT 0,
    PRIMARY KEY (license_key, window_kind, window_start)
);

CREATE INDEX IF NOT EXISTS idx_license_request_rate_ws ON license_request_rate (window_kind, window_start);

CREATE TABLE IF NOT EXISTS bot_command_log (
    nonce_hex       TEXT     PRIMARY KEY,
    action          TEXT     NOT NULL,
    discord_id      TEXT     NOT NULL DEFAULT '',
    received_at     BIGINT   NOT NULL,
    payload         JSONB    NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_bot_command_log_received ON bot_command_log (received_at DESC);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_req_seq      BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tool_call_counter BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS force_violation   BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS license_key_format SMALLINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_licenses_key_format2 ON licenses (license_key_format);

CREATE TABLE IF NOT EXISTS session_audit_recent (
    license_key   TEXT     NOT NULL,
    session_token TEXT     NOT NULL,
    event_kind    TEXT     NOT NULL,
    occurred_at   BIGINT   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_audit_recent_ses ON session_audit_recent (session_token, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_audit_recent_lic ON session_audit_recent (license_key, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_audit_recent_kind ON session_audit_recent (event_kind, occurred_at DESC);

CREATE TABLE IF NOT EXISTS bot_user_issuance (
    discord_id    TEXT     NOT NULL,
    issued_at     BIGINT   NOT NULL,
    license_key   TEXT     NOT NULL DEFAULT '',
    action        TEXT     NOT NULL DEFAULT 'create'
);

CREATE INDEX IF NOT EXISTS idx_bot_user_issuance_did ON bot_user_issuance (discord_id, issued_at DESC);

ALTER TABLE kill_switch DROP CONSTRAINT IF EXISTS kill_switch_target_type_check;
ALTER TABLE kill_switch ADD CONSTRAINT kill_switch_target_type_check
    CHECK (target_type IN ('license_key', 'hwid_hash', 'session_id', 'global', 'plugin_version'));

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_username TEXT NOT NULL DEFAULT '';

COMMIT;
