BEGIN;

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

COMMIT;
