CREATE TABLE IF NOT EXISTS werfault_hashes (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(64) NOT NULL UNIQUE,
    tool_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
    updated_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_werfault_hashes_active ON werfault_hashes(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_werfault_hashes_hash ON werfault_hashes(hash);
