BEGIN;

CREATE TABLE IF NOT EXISTS sentinel_attestations (
    license_key                 TEXT     NOT NULL,
    session_token               TEXT     NOT NULL DEFAULT '',
    quorum_id                   TEXT     NOT NULL DEFAULT '',
    peer_code_hash              TEXT     NOT NULL,
    peer_code_hash_received_at  BIGINT   NOT NULL,
    expected_hash_at_receive    TEXT     NOT NULL DEFAULT '',
    matched                     BOOLEAN  NOT NULL DEFAULT false,
    nt_build                    INTEGER,
    hvci_enabled                BOOLEAN,
    client_ip                   TEXT     NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sentinel_attestations_license_recv
    ON sentinel_attestations (license_key, peer_code_hash_received_at DESC);

CREATE INDEX IF NOT EXISTS idx_sentinel_attestations_session_recv
    ON sentinel_attestations (session_token, peer_code_hash_received_at DESC);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS peer_attest_divergence_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS peer_attest_last_hash         TEXT    NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS peer_attest_last_matched_at   BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS peer_attest_degraded          BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS session_ratchet (
    session_id              TEXT     PRIMARY KEY,
    license_key             TEXT     NOT NULL DEFAULT '',
    current_token_secret    BYTEA    NOT NULL,
    request_counter         BIGINT   NOT NULL DEFAULT 0,
    last_server_nonce       BYTEA    NOT NULL DEFAULT '\x'::bytea,
    created_at              BIGINT   NOT NULL,
    updated_at              BIGINT   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_ratchet_license ON session_ratchet (license_key);

COMMIT;
