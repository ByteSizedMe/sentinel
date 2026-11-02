-- Take back everything 000004 granted, then drop the role. The role may not
-- exist (someone dropped it by hand), so every step is inside the check.
-- DROP OWNED BY also removes any privilege that was added to the role by hand
-- in this database, which would otherwise make DROP ROLE fail.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        DROP OWNED BY sentinel_app;
        DROP ROLE sentinel_app;
    END IF;
END
$$;
