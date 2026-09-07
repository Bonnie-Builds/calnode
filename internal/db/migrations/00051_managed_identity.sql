-- +goose Up
-- Managed identity contract (Bonnie-managed Calnode, Phase 0):
--   * users gain an optional company_ref (exact Bonnie company), managed_subject
--     (stable BetterAuth subject), and is_managed_member flag.
--   * managed_assertions records consumed one-time assertion jti values so a
--     signed ManagedCalnodeSessionAssertionV1 can never be replayed.
--   * sessions gain a managed flag so deprovision can scope session deletion and
--     so native (30d) vs managed (<=1h) sessions are distinguishable.
--   * bookings gain an opaque, non-authorizing correlation_ref for the stable
--     reusable-link fragment contract.

ALTER TABLE users ADD COLUMN company_ref TEXT;
ALTER TABLE users ADD COLUMN managed_subject TEXT;
ALTER TABLE users ADD COLUMN is_managed_member INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_managed_subject
    ON users (managed_subject) WHERE managed_subject IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_company_ref
    ON users (company_ref) WHERE company_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS managed_assertions (
    jti        TEXT PRIMARY KEY,
    sub        TEXT NOT NULL,
    consumed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

ALTER TABLE sessions ADD COLUMN managed INTEGER NOT NULL DEFAULT 0;

ALTER TABLE bookings ADD COLUMN correlation_ref TEXT;
CREATE INDEX IF NOT EXISTS idx_bookings_correlation_ref
    ON bookings (correlation_ref) WHERE correlation_ref IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_bookings_correlation_ref;
ALTER TABLE bookings DROP COLUMN correlation_ref;
ALTER TABLE sessions DROP COLUMN managed;
DROP TABLE IF EXISTS managed_assertions;
DROP INDEX IF EXISTS idx_users_company_ref;
DROP INDEX IF EXISTS idx_users_managed_subject;
ALTER TABLE users DROP COLUMN is_managed_member;
ALTER TABLE users DROP COLUMN managed_subject;
ALTER TABLE users DROP COLUMN company_ref;
