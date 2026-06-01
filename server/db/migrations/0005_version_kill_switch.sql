BEGIN;

ALTER TABLE kill_switch DROP CONSTRAINT IF EXISTS kill_switch_target_type_check;
ALTER TABLE kill_switch ADD CONSTRAINT kill_switch_target_type_check
    CHECK (target_type IN ('license_key', 'hwid_hash', 'session_id', 'global', 'plugin_version'));

ALTER TABLE licenses ADD COLUMN IF NOT EXISTS discord_username TEXT NOT NULL DEFAULT '';

COMMIT;
