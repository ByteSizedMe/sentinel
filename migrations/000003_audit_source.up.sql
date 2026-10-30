-- Record where each decision came from: a fresh database read or the cache.
-- Adding a column does not UPDATE any row, so the append-only triggers on
-- audit_log are untouched and keep rejecting UPDATE, DELETE and TRUNCATE.
-- Rows written before this migration were all database reads, hence the default.
ALTER TABLE audit_log
    ADD COLUMN source TEXT NOT NULL DEFAULT 'db'
    CHECK (source IN ('db', 'cache'));
