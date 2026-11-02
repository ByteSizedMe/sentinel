-- Gives the sentinel_app role a login password. Run by `make db-app-role`, and
-- by CI, with this file on psql's STANDARD INPUT.
--
-- The password is never written in this file or on a command line. psql reads it
-- from the APP_DB_PASSWORD environment variable into the variable pw, and the
-- statement uses it as :'pw', which psql quotes safely as a string literal.
\set ON_ERROR_STOP on
\set pw `printenv APP_DB_PASSWORD`

SELECT length(:'pw') >= 16 AS pw_ok \gset
\if :pw_ok
    ALTER ROLE sentinel_app LOGIN PASSWORD :'pw';
\else
    DO $$ BEGIN RAISE EXCEPTION 'APP_DB_PASSWORD must be set and at least 16 characters'; END $$;
\endif
