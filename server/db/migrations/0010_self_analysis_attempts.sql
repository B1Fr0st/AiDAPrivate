BEGIN;

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

COMMIT;
