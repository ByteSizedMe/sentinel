package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a real, migrated Postgres (make up, make migrate-up) and
// skip when DATABASE_URL is unset or unreachable.
//
// NOTE: the audit log is append-only, so the rows these tests insert can never
// be deleted. They are tagged caller = "audit-test" and are harmless;
// `make migrate-down` followed by `make migrate-up` wipes them.

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		t.Skipf("database not reachable; skipping Postgres tests")
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestPostgresRecordAndAppendOnly(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	user := fmt.Sprintf("user-%d", time.Now().UnixNano())

	// 1. Record works and stores every field.
	l := NewPostgres(pool)
	err := l.Record(ctx, Entry{Caller: "audit-test", UserID: user, Action: "read", Resource: "invoices", Allowed: true, Reason: "permission granted"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	var caller, action, resource, reason string
	var allowed bool
	err = pool.QueryRow(ctx,
		`SELECT caller, action, resource, allowed, reason FROM audit_log WHERE user_id = $1`, user).
		Scan(&caller, &action, &resource, &allowed, &reason)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if caller != "audit-test" || action != "read" || resource != "invoices" || !allowed || reason != "permission granted" {
		t.Errorf("stored row = %q %q %q %v %q", caller, action, resource, allowed, reason)
	}

	// 2. The database itself rejects changes, whatever the application does.
	tests := []struct {
		name string
		sql  string
		args []any
	}{
		{"update", `UPDATE audit_log SET allowed = true WHERE user_id = $1`, []any{user}},
		{"update every row", `UPDATE audit_log SET allowed = true`, nil},
		{"delete one row", `DELETE FROM audit_log WHERE user_id = $1`, []any{user}},
		{"delete every row", `DELETE FROM audit_log`, nil},
		{"truncate", `TRUNCATE audit_log`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tt.sql, tt.args...)
			if err == nil {
				t.Fatal("statement succeeded; audit_log must be append-only")
			}
			if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("error = %v, want the append-only trigger error", err)
			}
		})
	}

	// 3. The row is still there, unchanged.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND allowed`, user).Scan(&n); err != nil || n != 1 {
		t.Errorf("row count after rejected changes = %d, err = %v; want 1", n, err)
	}
}

func TestMemoryLogger(t *testing.T) {
	m := &Memory{}
	if err := m.Record(context.Background(), Entry{UserID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if got := m.Entries(); len(got) != 1 || got[0].UserID != "u1" {
		t.Errorf("entries = %+v", got)
	}

	m.Err = fmt.Errorf("boom")
	if err := m.Record(context.Background(), Entry{UserID: "u2"}); err == nil {
		t.Error("expected error")
	}
	if len(m.Entries()) != 1 {
		t.Error("failed Record must not store the entry")
	}
}
