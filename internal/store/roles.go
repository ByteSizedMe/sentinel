package store

import (
	"context"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// All queries use $1, $2... placeholders: values are sent separately from the
// SQL text, so user input can never change the query's structure.

func (s *Postgres) CreateRole(ctx context.Context, name, description string) (rbac.Role, error) {
	var r rbac.Role
	err := s.pool.QueryRow(ctx,
		`INSERT INTO roles (name, description) VALUES ($1, $2)
		 RETURNING id, name, description, created_at`,
		name, description).Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	return r, mapErr(err)
}

func (s *Postgres) GetRole(ctx context.Context, id int64) (rbac.Role, error) {
	var r rbac.Role
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM roles WHERE id = $1`,
		id).Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	return r, mapErr(err)
}

func (s *Postgres) ListRoles(ctx context.Context) ([]rbac.Role, error) {
	return s.queryRoles(ctx, `SELECT id, name, description, created_at FROM roles ORDER BY id`)
}

// DeleteRole also removes the role's grants and user assignments (ON DELETE CASCADE).
func (s *Postgres) DeleteRole(ctx context.Context, id int64) error {
	return s.deleteByID(ctx, `DELETE FROM roles WHERE id = $1`, id)
}

// queryRoles runs a SELECT that returns role columns.
func (s *Postgres) queryRoles(ctx context.Context, query string, args ...any) ([]rbac.Role, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	roles := []rbac.Role{} // non-nil so JSON encodes as [] rather than null
	for rows.Next() {
		var r rbac.Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		roles = append(roles, r)
	}
	return roles, mapErr(rows.Err())
}

// deleteByID runs a single-row DELETE and reports ErrNotFound if nothing matched.
func (s *Postgres) deleteByID(ctx context.Context, query string, id int64) error {
	tag, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return rbac.ErrNotFound
	}
	return nil
}
