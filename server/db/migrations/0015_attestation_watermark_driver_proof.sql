BEGIN;

ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS watermark_state VARCHAR(64);
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS watermark_verified BOOLEAN;
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS driver_proof VARCHAR(128);
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS driver_proof_verified BOOLEAN;
ALTER TABLE attestation_records ADD COLUMN IF NOT EXISTS clone_flagged BOOLEAN;

ALTER TABLE builds ADD COLUMN IF NOT EXISTS expected_watermark TEXT NOT NULL DEFAULT '';

COMMIT;
