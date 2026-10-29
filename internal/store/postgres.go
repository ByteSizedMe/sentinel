package store

import (
	"errors"
	"fmt"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the PostgreSQL-backed PolicyStore.
type Postgres struct {
	pool *pgxpool.Pool
}

// Compile-time check that Postgres satisfies the interface.
var _ rbac.PolicyStore = (*Postgres)(nil)

// NewPostgres wraps an open pool. The caller owns the pool and closes it.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

// PostgreSQL error codes we translate (SQLSTATE values from the Postgres docs).
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// mapErr turns driver errors into rbac sentinel errors so callers never see
// raw database messages. Unknown errors are wrapped and returned as-is; the
// HTTP layer logs them and responds with a generic 500.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgUniqueViolation:
			return rbac.ErrConflict
		case pgForeignKeyViolation:
			// The row we tried to link to does not exist.
			return rbac.ErrNotFound
		}
	}
	return fmt.Errorf("store: %w", err)
}
