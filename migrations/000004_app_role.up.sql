-- The role the running service connects as. It can read and write policy data
-- and can only ADD rows to audit_log, so a compromised or buggy service cannot
-- rewrite history, even by dropping the append-only triggers (only a table
-- owner can do that, and sentinel_app owns nothing).
--
-- No password is set here: the role cannot log in until `make db-app-role`
-- gives it one from APP_DB_PASSWORD. Roles belong to the whole database
-- cluster, not to one database, hence the existence check.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        CREATE ROLE sentinel_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

-- Start from nothing: PUBLIC gets no table or sequence access, and nobody
-- but the owner may create objects in the schema (older Postgres versions let
-- PUBLIC do that by default).
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO sentinel_app;

-- Policy data: full read/write. There is deliberately no TRUNCATE, REFERENCES
-- or TRIGGER. schema_migrations is not listed, so the app cannot see it.
GRANT SELECT, INSERT, UPDATE, DELETE
    ON roles, resources, permissions, role_permissions, user_roles
    TO sentinel_app;
GRANT USAGE ON SEQUENCE roles_id_seq, resources_id_seq, permissions_id_seq TO sentinel_app;

-- Audit log: read and append, nothing else.
GRANT SELECT, INSERT ON audit_log TO sentinel_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO sentinel_app;

-- Any table added by a later migration needs its own explicit GRANT; there are
-- no default privileges on purpose (deny by default).
