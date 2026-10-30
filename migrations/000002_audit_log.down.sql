-- DROP TABLE is not blocked by the triggers (they only guard row changes and
-- TRUNCATE), and it removes the triggers with the table.
DROP TABLE IF EXISTS audit_log;
DROP FUNCTION IF EXISTS audit_log_reject_change();
