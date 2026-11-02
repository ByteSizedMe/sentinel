-- Gives the sentinel_app role a login password. Run by `make db-app-role`, and
-- by CI, with this file on psql's STANDARD INPUT.
--
-- The password is never written in this file or on a command line. psql reads it
-- from the APP_DB_PASSWORD environment variable into the variable pw, and the
-- statement uses it as :'pw', which psql quotes safely as a string literal.
\set ON_ERROR_STOP on
\set pw `printenv APP_DB_PASSWORD`

-- The placeholders from .env.example are public, so they are refused by name
-- (a clearer message than the length check below, and still refused if a
-- placeholder is ever lengthened).
SELECT :'pw' IN ('change-me', 'change-me-app-password') AS pw_placeholder,
       length(:'pw') >= 16 AS pw_long \gset
\if :pw_placeholder
    DO $$ BEGIN RAISE EXCEPTION 'APP_DB_PASSWORD is still the placeholder from .env.example; set your own'; END $$;
\elif :pw_long
    ALTER ROLE sentinel_app LOGIN PASSWORD :'pw';
\else
    DO $$ BEGIN RAISE EXCEPTION 'APP_DB_PASSWORD must be set and at least 16 characters'; END $$;
\endif
