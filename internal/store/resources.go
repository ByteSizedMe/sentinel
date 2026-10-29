package store

import (
	"context"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

func (s *Postgres) CreateResource(ctx context.Context, name, description string) (rbac.Resource, error) {
	var r rbac.Resource
	err := s.pool.QueryRow(ctx,
		`INSERT INTO resources (name, description) VALUES ($1, $2)
		 RETURNING id, name, description, created_at`,
		name, description).Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	return r, mapErr(err)
}

func (s *Postgres) GetResource(ctx context.Context, id int64) (rbac.Resource, error) {
	var r rbac.Resource
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, description, created_at FROM resources WHERE id = $1`,
		id).Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	return r, mapErr(err)
}

func (s *Postgres) ListResources(ctx context.Context) ([]rbac.Resource, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, created_at FROM resources ORDER BY id`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := []rbac.Resource{}
	for rows.Next() {
		var r rbac.Resource
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

// DeleteResource also removes its permissions and their role grants (cascade).
func (s *Postgres) DeleteResource(ctx context.Context, id int64) error {
	return s.deleteByID(ctx, `DELETE FROM resources WHERE id = $1`, id)
}
