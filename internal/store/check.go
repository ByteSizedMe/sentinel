package store

import (
	"context"
	"errors"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/jackc/pgx/v5"
)

// checkPermissionSQL is the whole authorization decision, in one query.
//
// Read it left to right: take the user's role assignments, follow them to the
// permissions those roles grant, and keep only the permission whose action and
// resource name match the request. If at least one row comes back, a grant
// exists. If none does, there is no grant, and the answer is "deny".
//
// $1 = user id, $2 = action, $3 = resource name. All three are bound
// parameters, never concatenated into the text.
//
// ORDER BY ... LIMIT 1 only makes the reported role deterministic when several
// roles grant the same thing; it does not change allow/deny.
const checkPermissionSQL = `
SELECT r.name
FROM user_roles ur
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p       ON p.id = rp.permission_id
JOIN resources res       ON res.id = p.resource_id
JOIN roles r             ON r.id = ur.role_id
WHERE ur.user_id = $1
  AND p.action   = $2
  AND res.name   = $3
ORDER BY r.name
LIMIT 1`

// CheckPermission runs checkPermissionSQL. Deny by default: the only way to
// get Allowed=true is for the query to return a row.
func (s *Postgres) CheckPermission(ctx context.Context, userID, action, resource string) (rbac.Decision, error) {
	var role string
	err := s.pool.QueryRow(ctx, checkPermissionSQL, userID, action, resource).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.Decision{Allowed: false}, nil // no grant found: a normal "deny"
	}
	if err != nil {
		// Could not answer. Return a zero Decision (Allowed=false) alongside
		// the error so a caller that forgets to check err still denies.
		return rbac.Decision{}, mapErr(err)
	}
	return rbac.Decision{Allowed: true, MatchedRole: role}, nil
}
