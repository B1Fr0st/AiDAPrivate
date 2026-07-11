BEGIN;

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

CREATE TABLE IF NOT EXISTS build_requests (
    request_id       TEXT        PRIMARY KEY,
    license_key      TEXT        NOT NULL REFERENCES licenses(key) ON DELETE CASCADE,
    discord_id       TEXT        NOT NULL,
    capsule_id       TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    base_template_version TEXT    NOT NULL DEFAULT '',
    output_path      TEXT        NOT NULL DEFAULT '',
    output_sha256    TEXT        NOT NULL DEFAULT '',
    error_message    TEXT        NOT NULL DEFAULT '',
    requested_at     BIGINT      NOT NULL,
    processing_started_at BIGINT,
    completed_at     BIGINT,
    bot_nonce        TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_build_requests_license ON build_requests (license_key, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_build_requests_discord ON build_requests (discord_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_build_requests_status ON build_requests (status) WHERE status IN ('pending', 'processing');

CREATE TABLE IF NOT EXISTS build_templates (
    template_id      TEXT        PRIMARY KEY,
    version          TEXT        NOT NULL,
    template_path    TEXT        NOT NULL,
    template_sha256  TEXT        NOT NULL,
    uploaded_at      BIGINT      NOT NULL,
    uploaded_by      TEXT        NOT NULL DEFAULT '',
    is_active        BOOLEAN     NOT NULL DEFAULT false,
    metadata         JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_build_templates_active ON build_templates (is_active) WHERE is_active = true;

COMMIT;
