package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres writes audit entries to the audit_log table.
type Postgres struct {
	pool *pgxpool.Pool
}

var _ Logger = (*Postgres)(nil)

// NewPostgres wraps an open pool. The caller owns the pool and closes it.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// Record inserts one row. Parameterized SQL, like everything else.
func (p *Postgres) Record(ctx context.Context, e Entry) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO audit_log (caller, user_id, action, resource, allowed, reason)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.Caller, e.UserID, e.Action, e.Resource, e.Allowed, e.Reason)
	if err != nil {
		return fmt.Errorf("audit: record entry: %w", err)
	}
	return nil
}
