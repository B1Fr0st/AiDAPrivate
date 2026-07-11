BEGIN;

CREATE TABLE IF NOT EXISTS attestation_records (
    id                  SERIAL      PRIMARY KEY,
    hwid_hash           VARCHAR(64) NOT NULL,
    nonce               VARCHAR(32) NOT NULL,
    usermode_code_hash  VARCHAR(64) NOT NULL,
    build_id            VARCHAR(32) NOT NULL,
    timestamp           BIGINT      NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attest_records_hwid ON attestation_records(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_attest_records_nonce ON attestation_records(nonce);
CREATE INDEX IF NOT EXISTS idx_attest_records_build ON attestation_records(build_id);

CREATE TABLE IF NOT EXISTS builds (
    build_id            VARCHAR(32) PRIMARY KEY,
    expected_text_sha256 VARCHAR(64) NOT NULL,
    retired             BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMIT;
