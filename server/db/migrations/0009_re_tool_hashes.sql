CREATE TABLE IF NOT EXISTS re_tool_hashes (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(64) NOT NULL UNIQUE,
    tool_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    updated_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_re_tool_hashes_active ON re_tool_hashes(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_re_tool_hashes_hash ON re_tool_hashes(hash);
