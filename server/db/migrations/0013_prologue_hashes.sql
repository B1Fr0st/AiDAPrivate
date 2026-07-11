CREATE TABLE IF NOT EXISTS prologue_hashes (
    id SERIAL PRIMARY KEY,
    function_name VARCHAR(128) NOT NULL,
    module VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    os_build INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prologue_hashes_os_build ON prologue_hashes(os_build);
CREATE INDEX IF NOT EXISTS idx_prologue_hashes_active ON prologue_hashes(active);
