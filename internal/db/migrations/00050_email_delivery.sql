-- +goose Up

-- Durable email outbox. The jobs row owns retry scheduling; this table owns
-- the immutable message, provider idempotency key, and operator-visible state.
CREATE TABLE email_deliveries (
    id              TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    recipient       TEXT NOT NULL,
    subject         TEXT NOT NULL,
    message_json    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'retrying', 'accepted', 'failed')),
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    accepted_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE server_settings ADD COLUMN email_verified_at TEXT NOT NULL DEFAULT '';
ALTER TABLE server_settings ADD COLUMN email_last_error  TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE server_settings DROP COLUMN email_last_error;
ALTER TABLE server_settings DROP COLUMN email_verified_at;
DROP TABLE IF EXISTS email_deliveries;
