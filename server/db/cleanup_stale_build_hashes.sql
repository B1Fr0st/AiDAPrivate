-- cleanup_stale_build_hashes.sql
-- Scheduled job: mark builds as retired (NOT delete) after 30-day zero-session window.
-- Retired builds still serve expected_text_sha256 lookups but are flagged for admin review.
-- Run periodically via cron or pg_cron:
--   SELECT cron.schedule('cleanup_stale_build_hashes', '0 3 * * *', $$CALL cleanup_stale_build_hashes()$$);
-- Or run manually:
--   psql -U aida_api -d aida_prod -f cleanup_stale_build_hashes.sql

BEGIN;

CREATE OR REPLACE FUNCTION cleanup_stale_build_hashes()
RETURNS TABLE(build_id TEXT, retired_at BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    cutoff_epoch BIGINT;
    build_rec RECORD;
BEGIN
    cutoff_epoch := EXTRACT(EPOCH FROM (now() - INTERVAL '30 days'))::BIGINT;

    FOR build_rec IN
        SELECT build_id
          FROM builds
         WHERE retired = false
           AND last_session_at > 0
           AND last_session_at < cutoff_epoch
    LOOP
        UPDATE builds
           SET retired = true,
               retired_at = EXTRACT(EPOCH FROM now())::BIGINT
         WHERE build_id = build_rec.build_id
           AND retired = false;

        IF FOUND THEN
            build_id := build_rec.build_id;
            retired_at := EXTRACT(EPOCH FROM now())::BIGINT;
            RETURN NEXT;
        END IF;
    END LOOP;

    RETURN;
END;
$$;

COMMIT;
