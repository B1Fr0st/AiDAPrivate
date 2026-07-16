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

CREATE TABLE IF NOT EXISTS customer_download_tokens (
    token_id          TEXT PRIMARY KEY,
    token_hmac        TEXT NOT NULL,
    license_key       TEXT NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id        TEXT NOT NULL,
    customer_role_id  TEXT NOT NULL,
    issued_at         BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    consumed          BOOLEAN NOT NULL DEFAULT false,
    consumed_at       BIGINT,
    source_ip         TEXT NOT NULL DEFAULT '',
    user_agent_hash   TEXT NOT NULL DEFAULT '',
    capsule_id        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_license ON customer_download_tokens (license_key, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_discord ON customer_download_tokens (discord_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_download_tokens_expiry ON customer_download_tokens (expires_at) WHERE consumed = false;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_capsule_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_capsule_id TEXT NOT NULL DEFAULT '';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS standalone_base_sha256 TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS standalone_customer_capsules (
    capsule_id             TEXT PRIMARY KEY,
    token_id               TEXT NOT NULL REFERENCES customer_download_tokens(token_id) ON DELETE CASCADE,
    license_key            TEXT NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id             TEXT NOT NULL,
    license_identity_hash  TEXT NOT NULL,
    discord_identity_hash  TEXT NOT NULL,
    hwid_hash              TEXT NOT NULL DEFAULT '',
    base_sha256            TEXT NOT NULL,
    base_size              BIGINT NOT NULL,
    base_version           TEXT NOT NULL,
    aux_patched            BOOLEAN NOT NULL DEFAULT false,
    marker_hex             TEXT NOT NULL,
    capsule_sha256         TEXT NOT NULL,
    secret_wrapped         BYTEA NOT NULL,
    issued_at              BIGINT NOT NULL,
    expires_at             BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_standalone_customer_capsules_license ON standalone_customer_capsules (license_key, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_standalone_customer_capsules_discord ON standalone_customer_capsules (discord_id, issued_at DESC);

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
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS wbaes_table_hash VARCHAR(64);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS fallback_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS fallback_count INTEGER NOT NULL DEFAULT 0;

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

CREATE TABLE IF NOT EXISTS dma_attack_log (
    id              SERIAL      PRIMARY KEY,
    hwid_hash       VARCHAR(64) NOT NULL,
    license_key_hash VARCHAR(64),
    attack_type     VARCHAR(32) NOT NULL,
    detection_type  INTEGER     NOT NULL DEFAULT 0,
    tier            INTEGER     NOT NULL DEFAULT 0,
    evidence_hash   BIGINT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dma_attack_hwid ON dma_attack_log(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_dma_attack_type ON dma_attack_log(attack_type);

CREATE TABLE IF NOT EXISTS dma_state_log (
    hwid_hash         VARCHAR(64) PRIMARY KEY,
    license_key       TEXT,
    dma_state_hex     TEXT        NOT NULL DEFAULT '',
    tier1_refused     BOOLEAN     NOT NULL DEFAULT false,
    tier2_bsod_armed  BOOLEAN     NOT NULL DEFAULT false,
    canary_count      INTEGER     NOT NULL DEFAULT 0,
    canary_hits       INTEGER     NOT NULL DEFAULT 0,
    pcie_unknown      INTEGER     NOT NULL DEFAULT 0,
    ept_anomaly       BOOLEAN     NOT NULL DEFAULT false,
    updated_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dma_state_hwid ON dma_state_log(hwid_hash);

CREATE TABLE IF NOT EXISTS self_analysis_attempts (
    id SERIAL PRIMARY KEY,
    hwid_hash VARCHAR(64) NOT NULL,
    license_key_hash VARCHAR(64),
    tool_name VARCHAR(128),
    detection_type INTEGER NOT NULL DEFAULT 0,
    target_pid INTEGER,
    target_address BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_self_analysis_hwid ON self_analysis_attempts(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_self_analysis_created ON self_analysis_attempts(created_at DESC);

CREATE TABLE IF NOT EXISTS self_analysis_blocklist (
    id SERIAL PRIMARY KEY,
    image_hash VARCHAR(64) NOT NULL,
    watermark TEXT,
    name_pattern VARCHAR(64),
    flags INTEGER NOT NULL DEFAULT 0,
    blocklist_epoch BIGINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_self_analysis_blocklist_epoch ON self_analysis_blocklist(blocklist_epoch);
CREATE INDEX IF NOT EXISTS idx_self_analysis_blocklist_active ON self_analysis_blocklist(active) WHERE active = true;

CREATE TABLE IF NOT EXISTS builds (
    build_id             TEXT        PRIMARY KEY,
    expected_text_sha256 TEXT        NOT NULL DEFAULT '',
    retired              BOOLEAN     NOT NULL DEFAULT false,
    created_at           BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    last_session_at      BIGINT      NOT NULL DEFAULT 0,
    retired_at           BIGINT
);

ALTER TABLE builds ADD COLUMN IF NOT EXISTS build_id             TEXT NOT NULL DEFAULT '';
ALTER TABLE builds ADD COLUMN IF NOT EXISTS expected_text_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE builds ADD COLUMN IF NOT EXISTS retired              BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS created_at           BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT);
ALTER TABLE builds ADD COLUMN IF NOT EXISTS last_session_at     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS retired_at           BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS expected_watermark   TEXT    NOT NULL DEFAULT '';
ALTER TABLE builds ADD COLUMN IF NOT EXISTS expected_wbaes_table_hash VARCHAR(64) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_builds_retired ON builds (retired) WHERE retired = false;
CREATE INDEX IF NOT EXISTS idx_builds_last_session ON builds (last_session_at);

ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS watermark_state VARCHAR(64);
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS watermark_verified BOOLEAN;
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS driver_proof VARCHAR(128);
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS driver_proof_verified BOOLEAN;
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS clone_flagged BOOLEAN;

CREATE TABLE IF NOT EXISTS mcp_tool_calls (
    id              BIGSERIAL   PRIMARY KEY,
    license_key     TEXT        NOT NULL,
    hwid            TEXT        NOT NULL DEFAULT '',
    session_token   TEXT        NOT NULL DEFAULT '',
    tool_name       TEXT        NOT NULL,
    tool_params_hash TEXT       NOT NULL DEFAULT '',
    called_at       BIGINT      NOT NULL,
    called_at_hour  SMALLINT    NOT NULL DEFAULT 0,
    client_ip       TEXT        NOT NULL DEFAULT '',
    source          TEXT        NOT NULL DEFAULT 'mcp'
);

CREATE INDEX IF NOT EXISTS idx_mcp_calls_license_time ON mcp_tool_calls (license_key, called_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_hwid_time ON mcp_tool_calls (hwid, called_at DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_calls_tool ON mcp_tool_calls (tool_name);

CREATE TABLE IF NOT EXISTS behavioral_profiles (
    license_key         TEXT        PRIMARY KEY REFERENCES licenses(key) ON DELETE CASCADE,
    tool_frequency      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    tool_sequence_hash  TEXT        NOT NULL DEFAULT '',
    hour_histogram      JSONB       NOT NULL DEFAULT '[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]'::jsonb,
    total_calls         INTEGER     NOT NULL DEFAULT 0,
    training_complete   BOOLEAN     NOT NULL DEFAULT false,
    first_call_at       BIGINT      NOT NULL DEFAULT 0,
    last_updated_at     BIGINT      NOT NULL DEFAULT 0,
    hwids_seen          TEXT[]      NOT NULL DEFAULT '{}',
    ips_seen            TEXT[]      NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_behavioral_profiles_training ON behavioral_profiles (training_complete) WHERE training_complete = false;

CREATE TABLE IF NOT EXISTS protocol_fingerprints (
    fingerprint_hash       TEXT        PRIMARY KEY,
    tool_names_hash        TEXT        NOT NULL,
    tool_schemas_hash      TEXT        NOT NULL,
    registration_order_hash TEXT       NOT NULL,
    build_version          TEXT        NOT NULL,
    tool_count             INTEGER     NOT NULL,
    tool_names             JSONB       NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at          BIGINT      NOT NULL,
    last_seen_at           BIGINT      NOT NULL DEFAULT 0,
    is_known_clone         BOOLEAN     NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS clone_detection_log (
    id                  BIGSERIAL   PRIMARY KEY,
    source_ip           TEXT        NOT NULL,
    license_key         TEXT        NOT NULL DEFAULT '',
    tool_names_hash     TEXT        NOT NULL DEFAULT '',
    registration_order_hash TEXT    NOT NULL DEFAULT '',
    matched_known_build BOOLEAN     NOT NULL DEFAULT false,
    has_valid_license   BOOLEAN     NOT NULL DEFAULT false,
    has_valid_session   BOOLEAN     NOT NULL DEFAULT false,
    detected_at         BIGINT      NOT NULL,
    evidence            JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_clone_detection_ip ON clone_detection_log (source_ip, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_clone_detection_hash ON clone_detection_log (tool_names_hash, detected_at DESC);

CREATE TABLE IF NOT EXISTS hwid_rate_counters (
    hwid             TEXT        NOT NULL,
    window_kind      TEXT        NOT NULL CHECK (window_kind IN ('minute', 'hour', 'day')),
    window_start     BIGINT      NOT NULL,
    count            INTEGER     NOT NULL DEFAULT 0,
    license_key      TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (hwid, window_kind, window_start)
);

CREATE INDEX IF NOT EXISTS idx_hwid_rate_window ON hwid_rate_counters (window_kind, window_start);

CREATE TABLE IF NOT EXISTS build_templates (
    id              SERIAL      PRIMARY KEY,
    version         INTEGER     NOT NULL UNIQUE,
    filename        TEXT        NOT NULL,
    file_path       TEXT        NOT NULL,
    file_sha256     TEXT        NOT NULL,
    file_size       BIGINT      NOT NULL,
    metadata_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    uploaded_at     BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    uploaded_by     TEXT        NOT NULL DEFAULT '',
    active          BOOLEAN     NOT NULL DEFAULT false,
    activated_at    BIGINT,
    archived_at     BIGINT,
    CHECK (active = true OR archived_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_build_templates_active ON build_templates (active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_build_templates_uploaded ON build_templates (uploaded_at DESC);

CREATE TABLE IF NOT EXISTS customer_watermarks (
    watermark_id     TEXT        PRIMARY KEY,
    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id       TEXT        NOT NULL DEFAULT '',
    assigned_at      BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    template_version INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_customer_watermarks_license ON customer_watermarks (license_key);
CREATE INDEX IF NOT EXISTS idx_customer_watermarks_discord ON customer_watermarks (discord_id);

CREATE TABLE IF NOT EXISTS build_requests (
    build_id         TEXT        PRIMARY KEY,
    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id       TEXT        NOT NULL DEFAULT '',
    template_version INTEGER     NOT NULL,
    watermark_id     TEXT        NOT NULL REFERENCES customer_watermarks(watermark_id) ON DELETE CASCADE,
    status           TEXT        NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'building', 'ready', 'failed', 'expired')),
    output_filename  TEXT        NOT NULL DEFAULT '',
    output_sha256    TEXT        NOT NULL DEFAULT '',
    output_size      BIGINT      NOT NULL DEFAULT 0,
    requested_at     BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    started_at       BIGINT,
    completed_at     BIGINT,
    error_message    TEXT        NOT NULL DEFAULT '',
    downloaded_at    BIGINT,
    download_count   INTEGER     NOT NULL DEFAULT 0,
    progress_pct     INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_build_requests_license ON build_requests (license_key, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_build_requests_discord ON build_requests (discord_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_build_requests_status ON build_requests (status) WHERE status IN ('queued', 'building');
CREATE INDEX IF NOT EXISTS idx_build_requests_requested ON build_requests (requested_at DESC);

CREATE TABLE IF NOT EXISTS patch_attempts (
    id              SERIAL      PRIMARY KEY,
    hwid            TEXT        NOT NULL DEFAULT '',
    license_key     TEXT        NOT NULL DEFAULT '',
    watermark       TEXT        NOT NULL DEFAULT '',
    patch_location  TEXT        NOT NULL DEFAULT '',
    patch_bytes     TEXT        NOT NULL DEFAULT '',
    decoy_id        INTEGER     NOT NULL DEFAULT -1,
    bug_code        INTEGER     NOT NULL DEFAULT 0,
    patch_type      INTEGER     NOT NULL DEFAULT 0,
    computed_crc    TEXT        NOT NULL DEFAULT '',
    stored_crc      TEXT        NOT NULL DEFAULT '',
    timestamp       BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    timestamp_iso   TEXT        NOT NULL DEFAULT '',
    ip              TEXT        NOT NULL DEFAULT '',
    revoked         BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_patch_attempts_hwid ON patch_attempts (hwid);
CREATE INDEX IF NOT EXISTS idx_patch_attempts_license ON patch_attempts (license_key);
CREATE INDEX IF NOT EXISTS idx_patch_attempts_timestamp ON patch_attempts (timestamp DESC);

CREATE TABLE IF NOT EXISTS prologue_hashes (
    id SERIAL PRIMARY KEY,
    function_name VARCHAR(128) NOT NULL,
    module VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    os_build INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prologue_hashes_os_build ON prologue_hashes(os_build);
CREATE INDEX IF NOT EXISTS idx_prologue_hashes_active ON prologue_hashes(active);

CREATE TABLE IF NOT EXISTS ce_driver_hashes (
    hash VARCHAR(64) NOT NULL UNIQUE,
    driver_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ce_driver_hashes_active ON ce_driver_hashes(active);

CREATE TABLE IF NOT EXISTS re_tool_hashes (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(64) NOT NULL UNIQUE,
    tool_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_re_tool_hashes_active ON re_tool_hashes(active);
CREATE INDEX IF NOT EXISTS idx_re_tool_hashes_hash ON re_tool_hashes(hash);

CREATE TABLE IF NOT EXISTS werfault_hashes (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(64) NOT NULL UNIQUE,
    tool_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_werfault_hashes_active ON werfault_hashes(active);
CREATE INDEX IF NOT EXISTS idx_werfault_hashes_hash ON werfault_hashes(hash);

COMMIT;
