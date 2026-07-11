BEGIN;

DROP TABLE IF EXISTS build_requests CASCADE;
DROP TABLE IF EXISTS build_templates CASCADE;

CREATE TABLE build_templates (
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

CREATE INDEX idx_build_templates_active ON build_templates (active) WHERE active = true;
CREATE INDEX idx_build_templates_uploaded ON build_templates (uploaded_at DESC);

CREATE TABLE IF NOT EXISTS customer_watermarks (
    watermark_id     TEXT        PRIMARY KEY,
    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id       TEXT        NOT NULL DEFAULT '',
    assigned_at      BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    template_version INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_customer_watermarks_license ON customer_watermarks (license_key);
CREATE INDEX IF NOT EXISTS idx_customer_watermarks_discord ON customer_watermarks (discord_id);

CREATE TABLE build_requests (
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

CREATE INDEX idx_build_requests_license ON build_requests (license_key, requested_at DESC);
CREATE INDEX idx_build_requests_discord ON build_requests (discord_id, requested_at DESC);
CREATE INDEX idx_build_requests_status ON build_requests (status) WHERE status IN ('queued', 'building');
CREATE INDEX idx_build_requests_requested ON build_requests (requested_at DESC);

COMMIT;
