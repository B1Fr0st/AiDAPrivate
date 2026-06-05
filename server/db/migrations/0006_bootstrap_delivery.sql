BEGIN;

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

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_license
    ON bootstrap_delivery_tokens (license_key, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_expiry
    ON bootstrap_delivery_tokens (expires_at)
    WHERE consumed = false;

COMMIT;
