package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a real, migrated Postgres (make up, make migrate-up).
// They skip when DATABASE_URL is unset or the database is unreachable.
// Every test uses unique names and cleans up after itself, so it is safe to
// run against your local dev database.

func testStore(t *testing.T) (*Postgres, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres tests")
	}
	pool, err := Connect(context.Background(), url)
	if err != nil {
		t.Skipf("database not reachable (%v); skipping Postgres tests", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgres(pool), pool
}

// uniq makes names that will not collide with other data or earlier runs.
func uniq(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestRoleLifecycle(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	name := uniq("role")
	role, err := s.CreateRole(ctx, name, "desc")
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteRole(ctx, role.ID) })

	if role.ID == 0 || role.Name != name || role.Description != "desc" || role.CreatedAt.IsZero() {
		t.Errorf("unexpected role: %+v", role)
	}

	got, err := s.GetRole(ctx, role.ID)
	if err != nil || got.Name != name {
		t.Errorf("GetRole = %+v, %v", got, err)
	}

	roles, err := s.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	found := false
	for _, r := range roles {
		found = found || r.ID == role.ID
	}
	if !found {
		t.Error("created role missing from ListRoles")
	}

	if err := s.DeleteRole(ctx, role.ID); err != nil {
		t.Errorf("DeleteRole: %v", err)
	}
	if _, err := s.GetRole(ctx, role.ID); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("GetRole after delete: err = %v, want ErrNotFound", err)
	}
}

func TestErrorMapping(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	role, err := s.CreateRole(ctx, uniq("role"), "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.CreateResource(ctx, uniq("res"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteRole(ctx, role.ID); _ = s.DeleteResource(ctx, res.ID) })

	const missing = int64(1) << 60 // an ID that cannot exist

	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"duplicate role name", func() error { _, err := s.CreateRole(ctx, role.Name, ""); return err }, rbac.ErrConflict},
		{"duplicate resource name", func() error { _, err := s.CreateResource(ctx, res.Name, ""); return err }, rbac.ErrConflict},
		{"get missing role", func() error { _, err := s.GetRole(ctx, missing); return err }, rbac.ErrNotFound},
		{"get missing resource", func() error { _, err := s.GetResource(ctx, missing); return err }, rbac.ErrNotFound},
		{"get missing permission", func() error { _, err := s.GetPermission(ctx, missing); return err }, rbac.ErrNotFound},
		{"delete missing role", func() error { return s.DeleteRole(ctx, missing) }, rbac.ErrNotFound},
		{"permission on missing resource", func() error { _, err := s.CreatePermission(ctx, "read", missing); return err }, rbac.ErrNotFound},
		{"grant with missing role", func() error { return s.GrantPermission(ctx, missing, missing) }, rbac.ErrNotFound},
		{"assign missing role", func() error { return s.AssignRole(ctx, "u-test", missing) }, rbac.ErrNotFound},
		{"revoke missing grant", func() error { return s.RevokePermission(ctx, role.ID, missing) }, rbac.ErrNotFound},
		{"remove unassigned role", func() error { return s.RemoveRole(ctx, "u-test", role.ID) }, rbac.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// Granting, assigning and the cascade when a role is deleted.
func TestGrantAssignAndCascade(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()
	user := uniq("user")

	role, err := s.CreateRole(ctx, uniq("role"), "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.CreateResource(ctx, uniq("res"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DeleteRole(ctx, role.ID); _ = s.DeleteResource(ctx, res.ID) })

	perm, err := s.CreatePermission(ctx, "read", res.ID)
	if err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if _, err := s.CreatePermission(ctx, "read", res.ID); !errors.Is(err, rbac.ErrConflict) {
		t.Errorf("duplicate permission: err = %v, want ErrConflict", err)
	}

	if err := s.GrantPermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if err := s.GrantPermission(ctx, role.ID, perm.ID); !errors.Is(err, rbac.ErrConflict) {
		t.Errorf("duplicate grant: err = %v, want ErrConflict", err)
	}
	perms, err := s.ListRolePermissions(ctx, role.ID)
	if err != nil || len(perms) != 1 || perms[0].ID != perm.ID {
		t.Errorf("ListRolePermissions = %+v, %v", perms, err)
	}

	if err := s.AssignRole(ctx, user, role.ID); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := s.AssignRole(ctx, user, role.ID); !errors.Is(err, rbac.ErrConflict) {
		t.Errorf("duplicate assign: err = %v, want ErrConflict", err)
	}
	roles, err := s.ListUserRoles(ctx, user)
	if err != nil || len(roles) != 1 || roles[0].ID != role.ID {
		t.Errorf("ListUserRoles = %+v, %v", roles, err)
	}

	// Deleting the role must remove its grants and assignments.
	if err := s.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	counts := []struct{ name, query string }{
		{"role_permissions", `SELECT count(*) FROM role_permissions WHERE role_id = $1`},
		{"user_roles", `SELECT count(*) FROM user_roles WHERE role_id = $1`},
	}
	for _, c := range counts {
		var n int
		if err := pool.QueryRow(ctx, c.query, role.ID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s rows left after role delete: n=%d err=%v", c.name, n, err)
		}
	}
	// The permission itself survives; only the grant is gone.
	if _, err := s.GetPermission(ctx, perm.ID); err != nil {
		t.Errorf("permission should survive role deletion: %v", err)
	}

	// Deleting the resource removes its permissions.
	if err := s.DeleteResource(ctx, res.ID); err != nil {
		t.Fatalf("DeleteResource: %v", err)
	}
	if _, err := s.GetPermission(ctx, perm.ID); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("permission after resource delete: err = %v, want ErrNotFound", err)
	}
}

func TestRevokeAndRemove(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	user := uniq("user")

	role, _ := s.CreateRole(ctx, uniq("role"), "")
	res, _ := s.CreateResource(ctx, uniq("res"), "")
	t.Cleanup(func() { _ = s.DeleteRole(ctx, role.ID); _ = s.DeleteResource(ctx, res.ID) })
	perm, err := s.CreatePermission(ctx, "write", res.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.GrantPermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePermission(ctx, role.ID, perm.ID); err != nil {
		t.Errorf("RevokePermission: %v", err)
	}
	if err := s.RevokePermission(ctx, role.ID, perm.ID); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("second revoke: err = %v, want ErrNotFound", err)
	}

	if err := s.AssignRole(ctx, user, role.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRole(ctx, user, role.ID); err != nil {
		t.Errorf("RemoveRole: %v", err)
	}
	if err := s.RemoveRole(ctx, user, role.ID); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("second remove: err = %v, want ErrNotFound", err)
	}
}

// Hostile input must be stored verbatim, never executed (parameterized SQL).
func TestSQLInjectionStringIsInert(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	evil := uniq("x'); DROP TABLE roles;--")
	role, err := s.CreateRole(ctx, evil, "")
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteRole(ctx, role.ID) })

	got, err := s.GetRole(ctx, role.ID)
	if err != nil || got.Name != evil {
		t.Errorf("GetRole = %+v, %v; want name stored verbatim", got, err)
	}
}

// CheckPermission is the heart of the service, so test it against real SQL.
func TestCheckPermission(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	user := uniq("user")

	role, err := s.CreateRole(ctx, uniq("editor"), "")
	if err != nil {
		t.Fatal(err)
	}
	invoices, _ := s.CreateResource(ctx, uniq("invoices"), "")
	reports, _ := s.CreateResource(ctx, uniq("reports"), "")
	t.Cleanup(func() {
		_ = s.DeleteRole(ctx, role.ID)
		_ = s.DeleteResource(ctx, invoices.ID)
		_ = s.DeleteResource(ctx, reports.ID)
	})
	perm, err := s.CreatePermission(ctx, "read", invoices.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantPermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, user, role.ID); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                   string
		user, action, resource string
		wantAllowed            bool
		wantRole               string
	}{
		{"granted", user, "read", invoices.Name, true, role.Name},
		{"other action on same resource", user, "write", invoices.Name, false, ""},
		{"same action on other resource", user, "read", reports.Name, false, ""},
		{"unknown resource", user, "read", uniq("nope"), false, ""},
		{"unknown action", user, uniq("nope"), invoices.Name, false, ""},
		{"unknown user", uniq("nobody"), "read", invoices.Name, false, ""},
		{"case differs", user, "READ", invoices.Name, false, ""},
		{"injection attempt in user id", "' OR '1'='1", "read", invoices.Name, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := s.CheckPermission(ctx, tt.user, tt.action, tt.resource)
			if err != nil {
				t.Fatalf("CheckPermission: %v", err)
			}
			if d.Allowed != tt.wantAllowed || d.MatchedRole != tt.wantRole {
				t.Errorf("decision = %+v, want allowed=%v role=%q", d, tt.wantAllowed, tt.wantRole)
			}
		})
	}

	// Removing the grant flips the answer to deny.
	if err := s.RevokePermission(ctx, role.ID, perm.ID); err != nil {
		t.Fatal(err)
	}
	if d, err := s.CheckPermission(ctx, user, "read", invoices.Name); err != nil || d.Allowed {
		t.Errorf("after revoke: decision = %+v, err = %v; want denied", d, err)
	}
}

// A failing database must produce an error AND a denying decision.
func TestCheckPermissionDatabaseErrorFailsClosed(t *testing.T) {
	s, pool := testStore(t)
	pool.Close() // every query on a closed pool errors

	d, err := s.CheckPermission(context.Background(), "u1", "read", "invoices")
	if err == nil {
		t.Fatal("expected an error from a closed pool")
	}
	if d.Allowed {
		t.Error("decision must not be Allowed when the query failed")
	}
}
