BEGIN;

CREATE TABLE IF NOT EXISTS dma_attack_log (
    id              SERIAL      PRIMARY KEY,
    hwid_hash       VARCHAR(64) NOT NULL,
    license_key_hash VARCHAR(64),
    attack_type     VARCHAR(32) NOT NULL,
    detection_type  INTEGER     NOT NULL DEFAULT 0,
    tier            INTEGER     NOT NULL DEFAULT 0,
    evidence_hash   BIGINT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dma_attack_hwid ON dma_attack_log(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_dma_attack_type ON dma_attack_log(attack_type);

CREATE TABLE IF NOT EXISTS dma_state_log (
    hwid_hash         VARCHAR(64) PRIMARY KEY,
    license_key       TEXT,
    dma_state_hex     TEXT        NOT NULL DEFAULT '',
    tier1_refused     BOOLEAN     NOT NULL DEFAULT false,
    tier2_bsod_armed  BOOLEAN     NOT NULL DEFAULT false,
    canary_count      INTEGER     NOT NULL DEFAULT 0,
    canary_hits       INTEGER     NOT NULL DEFAULT 0,
    pcie_unknown      INTEGER     NOT NULL DEFAULT 0,
    ept_anomaly       BOOLEAN     NOT NULL DEFAULT false,
    updated_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dma_state_hwid ON dma_state_log(hwid_hash);

COMMIT;
