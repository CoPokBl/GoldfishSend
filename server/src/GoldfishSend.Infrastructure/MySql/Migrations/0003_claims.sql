-- When a retry worker's claim on a held message runs out. Wake-ups (verification, rotation, recovery, re-probes) skip
-- claimed rows: making one due again would let a second worker push it while the first is still on it.
ALTER TABLE pending_messages
    ADD COLUMN claimed_until DATETIME NULL;
