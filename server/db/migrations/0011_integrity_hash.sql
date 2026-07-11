BEGIN;

CREATE TABLE IF NOT EXISTS builds (
    build_id             TEXT        PRIMARY KEY,
    expected_text_sha256 TEXT        NOT NULL DEFAULT '',
    retired              BOOLEAN     NOT NULL DEFAULT false,
    created_at           BIGINT      NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    last_session_at      BIGINT      NOT NULL DEFAULT 0,
    retired_at           BIGINT
);

ALTER TABLE builds ADD COLUMN IF NOT EXISTS build_id             TEXT NOT NULL DEFAULT '';
ALTER TABLE builds ADD COLUMN IF NOT EXISTS expected_text_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE builds ADD COLUMN IF NOT EXISTS retired              BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS created_at           BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT);
ALTER TABLE builds ADD COLUMN IF NOT EXISTS last_session_at     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS retired_at           BIGINT;

CREATE INDEX IF NOT EXISTS idx_builds_retired ON builds (retired) WHERE retired = false;
CREATE INDEX IF NOT EXISTS idx_builds_last_session ON builds (last_session_at);

COMMIT;
