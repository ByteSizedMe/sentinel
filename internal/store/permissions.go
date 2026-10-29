package store

import (
	"context"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// CreatePermission returns ErrNotFound if the resource does not exist
// (foreign key violation) and ErrConflict if the pair already exists.
func (s *Postgres) CreatePermission(ctx context.Context, action string, resourceID int64) (rbac.Permission, error) {
	var p rbac.Permission
	err := s.pool.QueryRow(ctx,
		`INSERT INTO permissions (action, resource_id) VALUES ($1, $2)
		 RETURNING id, action, resource_id, created_at`,
		action, resourceID).Scan(&p.ID, &p.Action, &p.ResourceID, &p.CreatedAt)
	return p, mapErr(err)
}

func (s *Postgres) GetPermission(ctx context.Context, id int64) (rbac.Permission, error) {
	var p rbac.Permission
	err := s.pool.QueryRow(ctx,
		`SELECT id, action, resource_id, created_at FROM permissions WHERE id = $1`,
		id).Scan(&p.ID, &p.Action, &p.ResourceID, &p.CreatedAt)
	return p, mapErr(err)
}

func (s *Postgres) ListPermissions(ctx context.Context) ([]rbac.Permission, error) {
	return s.queryPermissions(ctx,
		`SELECT id, action, resource_id, created_at FROM permissions ORDER BY id`)
}

func (s *Postgres) DeletePermission(ctx context.Context, id int64) error {
	return s.deleteByID(ctx, `DELETE FROM permissions WHERE id = $1`, id)
}

// queryPermissions runs a SELECT that returns permission columns.
func (s *Postgres) queryPermissions(ctx context.Context, query string, args ...any) ([]rbac.Permission, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := []rbac.Permission{}
	for rows.Next() {
		var p rbac.Permission
		if err := rows.Scan(&p.ID, &p.Action, &p.ResourceID, &p.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}
