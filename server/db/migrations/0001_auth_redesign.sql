-- ============================================================================
-- 0001_auth_redesign.sql — STAGE 2 auth redesign
-- Idempotent. Safe to apply repeatedly.
-- ============================================================================

BEGIN;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_factors   JSONB   NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_format     SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS hwid_grace_used_at BIGINT NOT NULL DEFAULT 0;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_contribution        BYTEA;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bind_response_hash       TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_key_fingerprint  TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_token_hash TEXT  NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_consumed   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sentinel_bind_issued_at  BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_licenses_key_format ON licenses (key_format);

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

COMMIT;
