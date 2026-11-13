-- Endpoint re-probing: a mailbox whose push endpoint looked gone is probed again later with backoff, by re-sending its
-- oldest held message, instead of staying parked until every message expires.
ALTER TABLE mailboxes
    ADD COLUMN reprobe_at DATETIME NULL,
    ADD COLUMN reprobe_count SMALLINT NOT NULL DEFAULT 0,
    ADD INDEX ix_mailboxes_reprobe (reprobe_at);
