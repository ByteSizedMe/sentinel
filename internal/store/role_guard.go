package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RowQuerier is the one method of *pgxpool.Pool the guard needs. Tests pass a fake.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrPrivilegedRole means the connection is not the low-privilege app role.
var ErrPrivilegedRole = errors.New("store: the database role is privileged")

// roleSQL asks the database who we are connected as: whether that role is a
// superuser, and whether it owns audit_log or holds the owner's privileges
// through role membership (pg_has_role ... 'USAGE' is also true for a superuser,
// which is fine because that is refused anyway). to_regclass is null when the
// table does not exist yet, so an unmigrated database does not cause an error here.
const roleSQL = `
SELECT r.rolsuper,
       EXISTS (SELECT 1 FROM pg_class c
               WHERE c.oid = to_regclass('public.audit_log')
                 AND pg_has_role(r.oid, c.relowner, 'USAGE'))
FROM pg_roles r
WHERE r.rolname = current_user`

// CheckRole refuses a connection that could rewrite the audit log: a superuser,
// or the owner of audit_log (or a member of the owner's role). Those can drop the
// append-only triggers, so the service must run as the sentinel_app role instead
// (see the README, "Database roles").
//
// With allow set, a privileged role is accepted and CheckRole returns a warning
// to log. Neither the warning nor the error includes the connection string, the
// role name or any other secret.
func CheckRole(ctx context.Context, q RowQuerier, allow bool) (warning string, err error) {
	var super, owner bool
	if err := q.QueryRow(ctx, roleSQL).Scan(&super, &owner); err != nil {
		return "", fmt.Errorf("store: cannot check the database role: %w", err)
	}
	var why string
	switch {
	case super && owner:
		why = "a superuser and the owner of audit_log"
	case super:
		why = "a superuser"
	case owner:
		why = "the owner of audit_log (or inherits the owner's privileges)"
	default:
		return "", nil
	}
	if allow {
		return "WARNING: running as a privileged database role (ALLOW_PRIVILEGED_DB_ROLE is set); the audit log is not protected from this service", nil
	}
	return "", fmt.Errorf("%w: DATABASE_URL connects as %s; use the sentinel_app role (see the README, Database roles), "+
		"or set ALLOW_PRIVILEGED_DB_ROLE=true for local development only", ErrPrivilegedRole, why)
}
