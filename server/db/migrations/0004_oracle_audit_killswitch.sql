BEGIN;

CREATE TABLE IF NOT EXISTS kill_switch (
    id           SERIAL       PRIMARY KEY,
    target_type  TEXT         NOT NULL CHECK (target_type IN ('license_key', 'hwid_hash', 'session_id', 'global')),
    target_value TEXT,
    reason       TEXT         NOT NULL,
    created_by   TEXT         NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_kill_switch_target
    ON kill_switch (target_type, target_value);

CREATE INDEX IF NOT EXISTS idx_kill_switch_expires
    ON kill_switch (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_log_v2 (
    id               BIGSERIAL    PRIMARY KEY,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    action           TEXT         NOT NULL,
    license_key_hmac TEXT         NOT NULL,
    hwid_hash        TEXT,
    source_ip        INET,
    user_agent_hash  TEXT,
    decision         TEXT         NOT NULL,
    reason_code      TEXT         NOT NULL,
    extra            JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_v2_ts  ON audit_log_v2 (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_v2_key ON audit_log_v2 (license_key_hmac);
CREATE INDEX IF NOT EXISTS idx_audit_log_v2_action_decision ON audit_log_v2 (action, decision);

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'session_ratchet' AND column_name = 'last_tool_call_id'
    ) THEN
        ALTER TABLE session_ratchet ADD COLUMN last_tool_call_id BIGINT;
        ALTER TABLE session_ratchet ADD COLUMN last_tool_call_token BYTEA;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS bot_command_rate (
    discord_user_id  TEXT         NOT NULL,
    window_kind      TEXT         NOT NULL CHECK (window_kind IN ('minute', 'hour', 'day', 'burst')),
    window_start     BIGINT       NOT NULL,
    count            INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (discord_user_id, window_kind, window_start)
);

CREATE INDEX IF NOT EXISTS idx_bot_command_rate_start
    ON bot_command_rate (window_kind, window_start);

CREATE TABLE IF NOT EXISTS bot_user_lockout (
    discord_user_id  TEXT         PRIMARY KEY,
    locked_until     BIGINT       NOT NULL,
    reason           TEXT         NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bot_user_lockout_until
    ON bot_user_lockout (locked_until);

COMMIT;
