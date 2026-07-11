CREATE TABLE IF NOT EXISTS ce_driver_hashes (
    hash VARCHAR(64) NOT NULL UNIQUE,
    driver_name VARCHAR(128),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ce_driver_hashes_active ON ce_driver_hashes(active);
