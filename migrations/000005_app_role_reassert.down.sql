-- Nothing to undo: 000005 only re-applies what 000004 granted. Reverting it must
-- not weaken the role, so this does not revoke anything or drop the role (000004's
-- down migration does that). A statement is still needed so the file is not empty.
SELECT 1;
