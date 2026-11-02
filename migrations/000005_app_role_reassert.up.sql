-- Makes sure sentinel_app is what migration 000004 meant it to be, even if the
-- role already existed before 000004 ran (000004 only creates a missing role and
-- leaves an existing one as it was) or was changed by hand since.
--
-- Safe to run more than once. It does not touch the role's password or its LOGIN
-- attribute, and it grants exactly what 000004 grants, nothing more.
-- Changing a superuser role needs a superuser, so run migrations as the owner
-- (a superuser, or on a managed service its admin role).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        RETURN;
    END IF;

    ALTER ROLE sentinel_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

    -- Start from nothing, then grant again.
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sentinel_app;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sentinel_app;
    REVOKE ALL ON SCHEMA public FROM sentinel_app;

    GRANT USAGE ON SCHEMA public TO sentinel_app;
    GRANT SELECT, INSERT, UPDATE, DELETE
        ON roles, resources, permissions, role_permissions, user_roles
        TO sentinel_app;
    GRANT USAGE ON SEQUENCE roles_id_seq, resources_id_seq, permissions_id_seq TO sentinel_app;
    GRANT SELECT, INSERT ON audit_log TO sentinel_app;
    GRANT USAGE ON SEQUENCE audit_log_id_seq TO sentinel_app;
END
$$;
