package store

import (
	"context"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// GrantPermission links a permission to a role. ErrNotFound if either does
// not exist, ErrConflict if already granted.
func (s *Postgres) GrantPermission(ctx context.Context, roleID, permissionID int64) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`,
		roleID, permissionID)
	return mapErr(err)
}

// RevokePermission removes a grant. ErrNotFound if the grant did not exist.
func (s *Postgres) RevokePermission(ctx context.Context, roleID, permissionID int64) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`,
		roleID, permissionID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return rbac.ErrNotFound
	}
	return nil
}

func (s *Postgres) ListRolePermissions(ctx context.Context, roleID int64) ([]rbac.Permission, error) {
	return s.queryPermissions(ctx,
		`SELECT p.id, p.action, p.resource_id, p.created_at
		 FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1
		 ORDER BY p.id`, roleID)
}

// AssignRole gives a user a role. ErrNotFound if the role does not exist,
// ErrConflict if the user already has it.
func (s *Postgres) AssignRole(ctx context.Context, userID string, roleID int64) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
		userID, roleID)
	return mapErr(err)
}

// RemoveRole takes a role away from a user. ErrNotFound if they did not have it.
func (s *Postgres) RemoveRole(ctx context.Context, userID string, roleID int64) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`,
		userID, roleID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return rbac.ErrNotFound
	}
	return nil
}

func (s *Postgres) ListUserRoles(ctx context.Context, userID string) ([]rbac.Role, error) {
	return s.queryRoles(ctx,
		`SELECT r.id, r.name, r.description, r.created_at
		 FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = $1
		 ORDER BY r.id`, userID)
}
