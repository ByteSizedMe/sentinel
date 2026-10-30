-- One row per authorization decision. Append-only: the triggers below make
-- UPDATE, DELETE and TRUNCATE fail at the database level, so even buggy
-- application code (or a stray manual query) cannot rewrite history.
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    caller     TEXT    NOT NULL, -- who asked: the JWT subject
    user_id    TEXT    NOT NULL, -- the user the decision was about
    action     TEXT    NOT NULL,
    resource   TEXT    NOT NULL,
    allowed    BOOLEAN NOT NULL,
    reason     TEXT    NOT NULL
);
CREATE INDEX idx_audit_log_user_id_created_at ON audit_log (user_id, created_at);

CREATE FUNCTION audit_log_reject_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

-- Row-level trigger: fires once per row for UPDATE and DELETE.
CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change();

-- TRUNCATE does not fire row triggers, so it needs its own statement-level one.
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change();
