package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// step is one HTTP request in a scenario, with the expected response.
type step struct {
	method, path, body string
	wantStatus         int
	wantBody           string // substring of the response body; empty = don't check
}

// Each case runs its steps in order against a fresh router + fake store, so
// later steps can depend on earlier ones (each table numbers its rows 1, 2, 3... like Postgres).
func TestHandlers(t *testing.T) {
	post, get, del := http.MethodPost, http.MethodGet, http.MethodDelete

	tests := []struct {
		name  string
		steps []step
	}{
		{"create and fetch role", []step{
			{post, "/v1/roles", `{"name":"editor","description":"can edit"}`, 201, `"name":"editor"`},
			{get, "/v1/roles/1", "", 200, `"id":1`},
			{get, "/v1/roles", "", 200, `"editor"`},
		}},
		{"duplicate role name conflicts", []step{
			{post, "/v1/roles", `{"name":"editor"}`, 201, ""},
			{post, "/v1/roles", `{"name":"editor"}`, 409, `"already exists"`},
		}},
		{"role validation", []step{
			{post, "/v1/roles", `{"name":""}`, 400, "name is required"},
			{post, "/v1/roles", `{}`, 400, ""},
			{post, "/v1/roles", `{"name":"has space"}`, 400, "invalid character"},
			{post, "/v1/roles", `{"name":"` + strings.Repeat("a", 65) + `"}`, 400, "at most 64"},
			{post, "/v1/roles", `{"name":"ok","description":"` + strings.Repeat("a", 257) + `"}`, 400, "description"},
			{post, "/v1/roles", `{"name":"ok","extra":1}`, 400, ""},
			{post, "/v1/roles", `not json`, 400, ""},
			{post, "/v1/roles", `{"name":"a"}{"name":"b"}`, 400, ""},
			{get, "/v1/roles", "", 200, `[]`}, // nothing was created
		}},
		{"role id handling", []step{
			{get, "/v1/roles/abc", "", 400, ""},
			{get, "/v1/roles/0", "", 400, ""},
			{get, "/v1/roles/-1", "", 400, ""},
			{get, "/v1/roles/99", "", 404, `"not found"`},
			{del, "/v1/roles/99", "", 404, ""},
		}},
		{"delete role", []step{
			{post, "/v1/roles", `{"name":"editor"}`, 201, ""},
			{del, "/v1/roles/1", "", 204, ""},
			{get, "/v1/roles/1", "", 404, ""},
		}},
		{"resources crud", []step{
			{post, "/v1/resources", `{"name":"invoices"}`, 201, `"name":"invoices"`},
			{post, "/v1/resources", `{"name":"invoices"}`, 409, ""},
			{post, "/v1/resources", `{"name":"bad name"}`, 400, ""},
			{get, "/v1/resources/1", "", 200, `"invoices"`},
			{get, "/v1/resources", "", 200, `"invoices"`},
			{del, "/v1/resources/1", "", 204, ""},
			{del, "/v1/resources/1", "", 404, ""},
		}},
		{"permissions crud", []step{
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 404, ""}, // no such resource
			{post, "/v1/resources", `{"name":"invoices"}`, 201, ""},
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 201, `"action":"read"`},
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 409, ""},
			{post, "/v1/permissions", `{"action":"","resource_id":1}`, 400, ""},
			{post, "/v1/permissions", `{"action":"read","resource_id":0}`, 400, "resource_id"},
			{post, "/v1/permissions", `{"action":"read; DROP TABLE x","resource_id":1}`, 400, ""},
			{get, "/v1/permissions/1", "", 200, `"resource_id":1`},
			{get, "/v1/permissions", "", 200, `"read"`},
			{del, "/v1/permissions/1", "", 204, ""},
			{get, "/v1/permissions/1", "", 404, ""},
		}},
		{"grant and revoke permission", []step{
			{post, "/v1/roles", `{"name":"editor"}`, 201, ""},
			{post, "/v1/resources", `{"name":"invoices"}`, 201, ""},
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 201, ""},
			{post, "/v1/roles/1/permissions", `{"permission_id":1}`, 201, `"permission_id":1`},
			{post, "/v1/roles/1/permissions", `{"permission_id":1}`, 409, ""},
			{post, "/v1/roles/1/permissions", `{"permission_id":99}`, 404, ""},
			{post, "/v1/roles/99/permissions", `{"permission_id":1}`, 404, ""},
			{post, "/v1/roles/1/permissions", `{"permission_id":0}`, 400, ""},
			{get, "/v1/roles/1/permissions", "", 200, `"read"`},
			{get, "/v1/roles/99/permissions", "", 404, ""},
			{del, "/v1/roles/1/permissions/1", "", 204, ""},
			{del, "/v1/roles/1/permissions/1", "", 404, ""},
			{get, "/v1/roles/1/permissions", "", 200, `[]`},
		}},
		{"assign and remove user role", []step{
			{post, "/v1/roles", `{"name":"editor"}`, 201, ""},
			{post, "/v1/users/u1/roles", `{"role_id":1}`, 201, `"user_id":"u1"`},
			{post, "/v1/users/u1/roles", `{"role_id":1}`, 409, ""},
			{post, "/v1/users/u1/roles", `{"role_id":99}`, 404, ""},
			{post, "/v1/users/u1/roles", `{"role_id":0}`, 400, ""},
			{post, "/v1/users/bad$id/roles", `{"role_id":1}`, 400, ""},
			{get, "/v1/users/u1/roles", "", 200, `"editor"`},
			{get, "/v1/users/nobody/roles", "", 200, `[]`},
			{del, "/v1/users/u1/roles/1", "", 204, ""},
			{del, "/v1/users/u1/roles/1", "", 404, ""},
		}},
		{"deleting a role removes its grants and assignments", []step{
			{post, "/v1/roles", `{"name":"editor"}`, 201, ""},
			{post, "/v1/resources", `{"name":"invoices"}`, 201, ""},
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 201, ""},
			{post, "/v1/roles/1/permissions", `{"permission_id":1}`, 201, ""},
			{post, "/v1/users/u1/roles", `{"role_id":1}`, 201, ""},
			{del, "/v1/roles/1", "", 204, ""},
			{get, "/v1/users/u1/roles", "", 200, `[]`},
			{post, "/v1/roles", `{"name":"editor2"}`, 201, ""}, // new role (id 2) must not inherit old grants
			{get, "/v1/roles/2/permissions", "", 200, `[]`},
		}},
		{"deleting a resource removes its permissions", []step{
			{post, "/v1/resources", `{"name":"invoices"}`, 201, ""},
			{post, "/v1/permissions", `{"action":"read","resource_id":1}`, 201, ""},
			{del, "/v1/resources/1", "", 204, ""},
			{get, "/v1/permissions", "", 200, `[]`},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewRouter(newFakeStore())
			for i, s := range tt.steps {
				req := httptest.NewRequest(s.method, s.path, strings.NewReader(s.body))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				if rec.Code != s.wantStatus {
					t.Fatalf("step %d (%s %s): status = %d, want %d; body: %s",
						i+1, s.method, s.path, rec.Code, s.wantStatus, rec.Body.String())
				}
				if s.wantBody != "" && !strings.Contains(rec.Body.String(), s.wantBody) {
					t.Fatalf("step %d (%s %s): body %q does not contain %q",
						i+1, s.method, s.path, rec.Body.String(), s.wantBody)
				}
			}
		})
	}
}

// errStore makes every call fail with a raw, "secret" error, to prove the
// HTTP layer never leaks internal error text.
type errStore struct{ *fakeStore }

func (errStore) ListRoles(context.Context) ([]rbac.Role, error) {
	return nil, errors.New(`pq: password authentication failed for user "sentinel" at 10.0.0.5`)
}

func TestInternalErrorsAreNotLeaked(t *testing.T) {
	h := NewRouter(errStore{newFakeStore()})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/roles", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "password") || strings.Contains(body, "10.0.0.5") {
		t.Errorf("response leaks internal error: %s", body)
	}
	if !strings.Contains(body, "internal server error") {
		t.Errorf("body = %s, want generic message", body)
	}
}
