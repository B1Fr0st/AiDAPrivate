BEGIN;

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

COMMIT;
