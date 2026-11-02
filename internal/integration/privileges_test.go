//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests connect as the least-privilege role created by migration 000004
// (sentinel_app) and check both sides of it: the service still works, and the
// database refuses everything an attacker who took over the service would try.
//
// They need APP_DATABASE_URL, the sentinel_app connection (make db-app-role sets
// its password). `make test-integration` defaults it to DATABASE_URL. They skip
// when it is unset.

const pgInsufficientPrivilege = "42501"

// appEnv connects as the app role and fails loudly if the URL points at some
// other role, because then every "must fail" check below would prove nothing.
func appEnv(t *testing.T) *env {
	t.Helper()
	e := newEnvFor(t, "APP_DATABASE_URL")
	var user string
	var super bool
	err := e.pool.QueryRow(context.Background(),
		`SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&user, &super)
	if err != nil {
		t.Fatal(err)
	}
	if user != "sentinel_app" || super {
		t.Fatalf("APP_DATABASE_URL connects as %q (superuser=%v), want the non-superuser role sentinel_app", user, super)
	}
	return e
}

// The whole service runs on the app role: policy CRUD, role assignment,
// authorize and the audit insert behind it.
func TestAppRoleRunsTheService(t *testing.T) {
	e := appEnv(t)
	srv := httptest.NewServer(e.router(t, nil))
	t.Cleanup(srv.Close)
	c := &client{t: t, base: srv.URL, token: token(t, "svc-privileges")}

	suffix := time.Now().UnixNano()
	user := fmt.Sprintf("user-%d", suffix)
	var role, res, perm idResp
	c.call("POST", "/v1/roles", fmt.Sprintf(`{"name":"role-%d"}`, suffix), 201, &role)
	c.call("POST", "/v1/resources", fmt.Sprintf(`{"name":"res-%d"}`, suffix), 201, &res)
	t.Cleanup(func() {
		c.call("DELETE", fmt.Sprintf("/v1/roles/%d", role.ID), "", 204, nil)
		c.call("DELETE", fmt.Sprintf("/v1/resources/%d", res.ID), "", 204, nil)
	})
	c.call("POST", "/v1/permissions", fmt.Sprintf(`{"action":"read","resource_id":%d}`, res.ID), 201, &perm)
	c.call("POST", fmt.Sprintf("/v1/roles/%d/permissions", role.ID), fmt.Sprintf(`{"permission_id":%d}`, perm.ID), 201, nil)
	c.call("POST", fmt.Sprintf("/v1/users/%s/roles", user), fmt.Sprintf(`{"role_id":%d}`, role.ID), 201, nil)
	c.call("GET", "/v1/roles", "", 200, nil)

	if !c.authorize(user, "read", fmt.Sprintf("res-%d", suffix)) {
		t.Error("authorize = deny, want allow")
	}
	c.call("DELETE", fmt.Sprintf("/v1/roles/%d/permissions/%d", role.ID, perm.ID), "", 204, nil)
	if c.authorize(user, "read", fmt.Sprintf("res-%d", suffix)) {
		t.Error("authorize after revoke = allow, want deny")
	}

	rows := e.auditRows(t, user)
	if len(rows) != 2 || !rows[0].Allowed || rows[1].Allowed {
		t.Errorf("audit rows = %+v, want one allow then one deny", rows)
	}
}

// What the app role may and may not do to audit_log and to the schema.
func TestAppRolePrivileges(t *testing.T) {
	e := appEnv(t)
	ctx := context.Background()
	user := fmt.Sprintf("user-%d", time.Now().UnixNano())

	// INSERT and SELECT are the two things it is allowed to do to audit_log.
	if _, err := e.pool.Exec(ctx,
		`INSERT INTO audit_log (caller, user_id, action, resource, allowed, reason, source)
		 VALUES ('privileges-test', $1, 'read', 'x', false, 'no matching grant', 'db')`, user); err != nil {
		t.Fatalf("INSERT INTO audit_log as the app role: %v", err)
	}
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1`, user).Scan(&n); err != nil || n != 1 {
		t.Fatalf("SELECT from audit_log: count = %d, err = %v; want 1, nil", n, err)
	}

	denied := []struct{ name, sql string }{
		{"UPDATE audit_log", `UPDATE audit_log SET allowed = true WHERE user_id = $1`},
		{"DELETE FROM audit_log", `DELETE FROM audit_log WHERE user_id = $1`},
		{"TRUNCATE audit_log", `TRUNCATE audit_log`},
		{"DROP TRIGGER on audit_log", `DROP TRIGGER audit_log_no_update_delete ON audit_log`},
		{"DROP the truncate trigger", `DROP TRIGGER audit_log_no_truncate ON audit_log`},
		{"DISABLE TRIGGER on audit_log", `ALTER TABLE audit_log DISABLE TRIGGER ALL`},
		{"ALTER audit_log", `ALTER TABLE audit_log ADD COLUMN extra TEXT`},
		{"DROP TABLE audit_log", `DROP TABLE audit_log`},
		{"DROP TABLE roles", `DROP TABLE roles`},
		{"CREATE TABLE", `CREATE TABLE public.privileges_test_table (id int)`},
		{"CREATE INDEX on audit_log", `CREATE INDEX privileges_test_idx ON audit_log (reason)`},
		{"CREATE FUNCTION", `CREATE FUNCTION public.privileges_test_fn() RETURNS int AS 'SELECT 1' LANGUAGE sql`},
		{"COPY TO PROGRAM", `COPY (SELECT 1) TO PROGRAM 'true'`},
		{"SELECT schema_migrations", `SELECT version FROM schema_migrations`},
		{"UPDATE schema_migrations", `UPDATE schema_migrations SET dirty = true`},
	}
	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.name == "UPDATE audit_log" || tt.name == "DELETE FROM audit_log" {
				_, err = e.pool.Exec(ctx, tt.sql, user)
			} else {
				_, err = e.pool.Exec(ctx, tt.sql)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != pgInsufficientPrivilege {
				t.Fatalf("error = %v, want a permission error (SQLSTATE %s)", err, pgInsufficientPrivilege)
			}
		})
	}

	// Becoming the table owner is refused too.
	var owner string
	if err := e.pool.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.audit_log'::regclass`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	t.Run("SET ROLE to the owner", func(t *testing.T) {
		_, err := e.pool.Exec(ctx, `SET ROLE `+pgx.Identifier{owner}.Sanitize())
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != pgInsufficientPrivilege {
			t.Fatalf("error = %v, want a permission error (SQLSTATE %s)", err, pgInsufficientPrivilege)
		}
	})

	// The role has no dangerous attributes.
	var super, createRole, createDB, replication, bypassRLS bool
	if err := e.pool.QueryRow(ctx,
		`SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&super, &createRole, &createDB, &replication, &bypassRLS); err != nil {
		t.Fatal(err)
	}
	if super || createRole || createDB || replication || bypassRLS {
		t.Errorf("role attributes: superuser=%v createrole=%v createdb=%v replication=%v bypassrls=%v; all must be false",
			super, createRole, createDB, replication, bypassRLS)
	}

	// A GRANT by a role without grant option is not an error in Postgres (it only
	// warns), so check the result instead: the role still has exactly SELECT and
	// INSERT on audit_log, whatever it tried.
	_, _ = e.pool.Exec(ctx, `GRANT UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES ON audit_log TO sentinel_app`)
	for priv, want := range map[string]bool{
		"SELECT": true, "INSERT": true,
		"UPDATE": false, "DELETE": false, "TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
	} {
		var has bool
		if err := e.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'audit_log', $1)`, priv).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if has != want {
			t.Errorf("has %s on audit_log = %v, want %v", priv, has, want)
		}
	}

	// The refused statements changed nothing.
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND NOT allowed`, user).Scan(&n); err != nil || n != 1 {
		t.Errorf("row after the refused statements: count = %d, err = %v; want 1, nil", n, err)
	}
}
