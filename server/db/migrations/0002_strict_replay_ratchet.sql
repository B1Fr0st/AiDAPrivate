BEGIN;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_req_seq      BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tool_call_counter BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS force_violation   BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS license_key_format SMALLINT NOT NULL DEFAULT 1;

UPDATE licenses
SET license_key_format = COALESCE(NULLIF(license_key_format, 0), key_format, 1)
WHERE license_key_format IS NULL OR license_key_format = 0;

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

COMMIT;
