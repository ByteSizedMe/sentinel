package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/rbac"
)

// errSecret looks like a real driver error: it must never reach a client.
var errSecret = errors.New(`pq: password authentication failed for user "sentinel" at 10.0.0.5`)

// brokenStore fails every call. It embeds the fake only to satisfy the parts
// of the interface it does not override (none are left, but the embedding
// keeps the type valid if the interface grows).
type brokenStore struct{ *fakeStore }

func (brokenStore) CreateRole(context.Context, string, string) (rbac.Role, error) {
	return rbac.Role{}, errSecret
}
func (brokenStore) GetRole(context.Context, int64) (rbac.Role, error) { return rbac.Role{}, errSecret }
func (brokenStore) ListRoles(context.Context) ([]rbac.Role, error)    { return nil, errSecret }
func (brokenStore) DeleteRole(context.Context, int64) error           { return errSecret }
func (brokenStore) CreateResource(context.Context, string, string) (rbac.Resource, error) {
	return rbac.Resource{}, errSecret
}
func (brokenStore) GetResource(context.Context, int64) (rbac.Resource, error) {
	return rbac.Resource{}, errSecret
}
func (brokenStore) ListResources(context.Context) ([]rbac.Resource, error) { return nil, errSecret }
func (brokenStore) DeleteResource(context.Context, int64) error            { return errSecret }
func (brokenStore) CreatePermission(context.Context, string, int64) (rbac.Permission, error) {
	return rbac.Permission{}, errSecret
}
func (brokenStore) GetPermission(context.Context, int64) (rbac.Permission, error) {
	return rbac.Permission{}, errSecret
}
func (brokenStore) ListPermissions(context.Context) ([]rbac.Permission, error) {
	return nil, errSecret
}
func (brokenStore) DeletePermission(context.Context, int64) error       { return errSecret }
func (brokenStore) GrantPermission(context.Context, int64, int64) error { return errSecret }
func (brokenStore) RevokePermission(context.Context, int64, int64) error {
	return errSecret
}
func (brokenStore) ListRolePermissions(context.Context, int64) ([]rbac.Permission, error) {
	return nil, errSecret
}
func (brokenStore) AssignRole(context.Context, string, int64) error { return errSecret }
func (brokenStore) RemoveRole(context.Context, string, int64) error { return errSecret }
func (brokenStore) ListUserRoles(context.Context, string) ([]rbac.Role, error) {
	return nil, errSecret
}
func (brokenStore) CheckPermission(context.Context, string, string, string) (rbac.Decision, error) {
	return rbac.Decision{Allowed: true}, errSecret // Allowed=true must be ignored
}

// With a correct token and a working request, a failing store must give every
// route the same generic 500: no driver text, and (for authorize) no decision.
func TestEveryRouteHidesStoreErrors(t *testing.T) {
	for _, rt := range scopedRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			captureLog(t) // the cause is logged; keep it out of the test output

			h := newTestRouter(t, brokenStore{newFakeStore()}, &audit.Memory{})
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testTokenScoped(t, "svc-x", rt.scope))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"internal server error"}` {
				t.Errorf("body = %q, want the generic message", got)
			}
		})
	}
}
