-- Mailboxes: one per (recipient, contact) pair. Nothing in here identifies a person or a device:
-- the id is a peppered hash of the send secret and the endpoint is sealed under a key derived from it.
CREATE TABLE mailboxes (
    id                BINARY(32)      NOT NULL,
    owner_hash        BINARY(32)      NOT NULL,
    sealed_endpoint   VARBINARY(2304) NOT NULL,
    pending_endpoint  VARBINARY(2304) NULL,
    state             TINYINT         NOT NULL,
    verify_hash       BINARY(32)      NULL,
    verify_attempts   TINYINT         NOT NULL DEFAULT 0,
    verify_expires_at DATETIME        NULL,
    expires_at        DATE            NOT NULL,
    PRIMARY KEY (id),
    INDEX ix_mailboxes_expires (expires_at),
    INDEX ix_mailboxes_verify (verify_expires_at)
) ENGINE = InnoDB;

-- Messages that couldn't be handed to a push server yet. Rows are encrypted under a daily epoch key that is
-- destroyed after the maximum TTL (crypto-shredding), so deleted rows left in redo logs or on disk become unreadable.
CREATE TABLE pending_messages (
    id              BINARY(16)      NOT NULL,
    mailbox_id      BINARY(32)      NOT NULL,
    key_epoch       INT             NOT NULL,
    payload         VARBINARY(4200) NOT NULL,
    attempts        SMALLINT        NOT NULL DEFAULT 0,
    next_attempt_at DATETIME        NOT NULL,
    expires_at      DATETIME        NOT NULL,
    PRIMARY KEY (id),
    INDEX ix_pending_due (next_attempt_at),
    INDEX ix_pending_mailbox (mailbox_id),
    INDEX ix_pending_expires (expires_at)
) ENGINE = InnoDB;

-- Daily data-encryption keys, wrapped by the configured EpochKek. Deleted once no message could still need them.
CREATE TABLE epoch_keys (
    epoch       INT           NOT NULL,
    wrapped_key VARBINARY(64) NOT NULL,
    PRIMARY KEY (epoch)
) ENGINE = InnoDB;
