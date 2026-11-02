//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/bytesizedme/sentinel/internal/store"
)

// Migration 000005 puts a tampered or pre-existing sentinel_app role back to what
// 000004 intended. The test tampers with the role through the owner connection
// (MIGRATE_DATABASE_URL, which must be a superuser here), runs the real
// migration file, checks the result, and runs the file again at the end so the
// role is left clean.
func TestMigration5CorrectsAPreExistingRole(t *testing.T) {
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		skipOrFail(t, "MIGRATE_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := store.Connect(ctx, url)
	if err != nil {
		skipOrFail(t, "owner connection failed (%v)", err)
	}
	t.Cleanup(pool.Close)

	up, err := os.ReadFile("../../migrations/000005_app_role_reassert.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	apply := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("running 000005: %v", err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, string(up)) })

	var loginBefore bool
	if err := pool.QueryRow(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname = 'sentinel_app'`).Scan(&loginBefore); err != nil {
		t.Fatalf("sentinel_app must exist (run make migrate-up): %v", err)
	}

	// Make the role as bad as a hand-made one could be.
	for _, stmt := range []string{
		`ALTER ROLE sentinel_app SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS`,
		`GRANT UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON audit_log TO sentinel_app`,
		`GRANT ALL ON schema_migrations TO sentinel_app`,
		`GRANT CREATE ON SCHEMA public TO sentinel_app`,
		`GRANT ALL ON roles TO sentinel_app`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	apply()

	var super, createDB, createRole, repl, bypass, login bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'sentinel_app'`).
		Scan(&super, &createDB, &createRole, &repl, &bypass, &login); err != nil {
		t.Fatal(err)
	}
	if super || createDB || createRole || repl || bypass {
		t.Errorf("attributes after 000005: superuser=%v createdb=%v createrole=%v replication=%v bypassrls=%v; all must be false",
			super, createDB, createRole, repl, bypass)
	}
	if login != loginBefore {
		t.Errorf("LOGIN changed from %v to %v; 000005 must not touch it", loginBefore, login)
	}

	want := map[string]map[string]bool{
		"audit_log":         {"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false, "TRUNCATE": false, "TRIGGER": false, "REFERENCES": false},
		"roles":             {"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "TRUNCATE": false, "TRIGGER": false, "REFERENCES": false},
		"schema_migrations": {"SELECT": false, "INSERT": false, "UPDATE": false, "DELETE": false},
	}
	for table, privs := range want {
		for priv, wantHas := range privs {
			var has bool
			if err := pool.QueryRow(ctx, `SELECT has_table_privilege('sentinel_app', $1, $2)`, "public."+table, priv).Scan(&has); err != nil {
				t.Fatal(err)
			}
			if has != wantHas {
				t.Errorf("%s on %s = %v, want %v", priv, table, has, wantHas)
			}
		}
	}
	var canCreate, canUse bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege('sentinel_app', 'public', 'CREATE'), has_schema_privilege('sentinel_app', 'public', 'USAGE')`).Scan(&canCreate, &canUse); err != nil {
		t.Fatal(err)
	}
	if canCreate || !canUse {
		t.Errorf("schema public: CREATE=%v USAGE=%v, want false, true", canCreate, canUse)
	}

	// Running it again changes nothing (idempotent).
	apply()
}
