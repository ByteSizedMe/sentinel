package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/cache"
)

// cstep is one request in a scenario. A request to /v1/authorize also checks
// the decision and where it came from.
type cstep struct {
	method, path, body string
	wantStatus         int
	wantAllowed        bool   // authorize only
	wantSource         string // authorize only: "db" or "cache"
}

const authorizeU1 = `{"user_id":"u1","action":"read","resource":"invoices"}`

// Steps that build: role 1 "editor", resource 1 "invoices", permission 1 "read".
var catalog = []cstep{
	{method: "POST", path: "/v1/roles", body: `{"name":"editor"}`, wantStatus: 201},
	{method: "POST", path: "/v1/resources", body: `{"name":"invoices"}`, wantStatus: 201},
	{method: "POST", path: "/v1/permissions", body: `{"action":"read","resource_id":1}`, wantStatus: 201},
}

// Steps that give user u1 the permission.
var grantAndAssign = []cstep{
	{method: "POST", path: "/v1/roles/1/permissions", body: `{"permission_id":1}`, wantStatus: 201},
	{method: "POST", path: "/v1/users/u1/roles", body: `{"role_id":1}`, wantStatus: 201},
}

// ask is an authorize step with its expected outcome.
func ask(allowed bool, source string) cstep {
	return cstep{method: "POST", path: "/v1/authorize", body: authorizeU1, wantStatus: 200, wantAllowed: allowed, wantSource: source}
}

// join concatenates step lists.
func join(lists ...[]cstep) []cstep {
	var out []cstep
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// mutate is a write step that must succeed.
func mutate(method, path, body string, status int) []cstep {
	return []cstep{{method: method, path: path, body: body, wantStatus: status}}
}

// TestStalePermissionsDoNotSurvive proves that after any policy change, the
// very next /authorize reflects it, even though the cache was warm before.
// Every scenario first asks twice and checks the second answer came from the
// cache, so we know the cache really was warm.
func TestStalePermissionsDoNotSurvive(t *testing.T) {
	tests := []struct {
		name  string
		steps []cstep
	}{
		{"grant: a cached denial turns into an allow", join(catalog,
			mutate("POST", "/v1/users/u1/roles", `{"role_id":1}`, 201), // role held, grants nothing yet
			[]cstep{ask(false, "db"), ask(false, "cache")},
			mutate("POST", "/v1/roles/1/permissions", `{"permission_id":1}`, 201),
			[]cstep{ask(true, "db"), ask(true, "cache")},
		)},
		{"revoke: a cached allow turns into a denial", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/roles/1/permissions/1", "", 204),
			[]cstep{ask(false, "db"), ask(false, "cache")},
		)},
		{"delete the role", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/roles/1", "", 204),
			[]cstep{ask(false, "db")},
		)},
		{"remove the user-role assignment", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/users/u1/roles/1", "", 204),
			[]cstep{ask(false, "db")},
		)},
		{"delete the permission", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/permissions/1", "", 204),
			[]cstep{ask(false, "db")},
		)},
		{"delete the resource", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/resources/1", "", 204),
			[]cstep{ask(false, "db")},
		)},
		{"assign: a cached denial turns into an allow when the role is assigned", join(catalog,
			mutate("POST", "/v1/roles/1/permissions", `{"permission_id":1}`, 201), // granted, but u1 holds no role
			[]cstep{ask(false, "db"), ask(false, "cache")},
			mutate("POST", "/v1/users/u1/roles", `{"role_id":1}`, 201),
			[]cstep{ask(true, "db")},
		)},
		{"revoke then grant again flips back", join(catalog, grantAndAssign,
			[]cstep{ask(true, "db"), ask(true, "cache")},
			mutate("DELETE", "/v1/roles/1/permissions/1", "", 204),
			[]cstep{ask(false, "db")},
			mutate("POST", "/v1/roles/1/permissions", `{"permission_id":1}`, 201),
			[]cstep{ask(true, "db"), ask(true, "cache")},
		)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, audits := newCachedRouter(t)
			runSteps(t, h, audits, tt.steps)
		})
	}
}

// Another user's cached allow must never answer for this user.
func TestCachedAllowIsNotSharedBetweenUsers(t *testing.T) {
	h, audits := newCachedRouter(t)
	runSteps(t, h, audits, join(catalog, grantAndAssign, []cstep{ask(true, "db"), ask(true, "cache")}))

	// u2 holds nothing; asking the same question must hit the database and be denied.
	body := `{"user_id":"u2","action":"read","resource":"invoices"}`
	runSteps(t, h, audits, []cstep{
		{method: "POST", path: "/v1/authorize", body: body, wantStatus: 200, wantAllowed: false, wantSource: "db"},
		{method: "POST", path: "/v1/authorize", body: body, wantStatus: 200, wantAllowed: false, wantSource: "cache"},
	})
}

// With the cache unreachable, decisions are still right and still audited as db reads.
func TestAuthorizeWorksWhenCacheIsDown(t *testing.T) {
	mem := cache.NewMemory(time.Minute)
	mem.Err = http.ErrServerClosed // any error will do
	store := newFakeStore()
	audits := &audit.Memory{}
	v, _ := auth.NewValidator(testSecret, testIssuer, testAudience)
	h := NewRouter(cache.NewStore(store, mem, time.Minute), audits, v)

	runSteps(t, h, audits, join(catalog, grantAndAssign, []cstep{
		ask(true, "db"), ask(true, "db"),
		{method: "POST", path: "/v1/authorize", body: `{"user_id":"nobody","action":"read","resource":"invoices"}`, wantStatus: 200, wantAllowed: false, wantSource: "db"},
	}))
	mem.Err = nil
	// Policy changes while the cache is down must also take effect immediately.
	runSteps(t, h, audits, join(
		mutate("DELETE", "/v1/roles/1/permissions/1", "", 204),
		[]cstep{ask(false, "db")},
	))
}

// newCachedRouter builds the real router around CachedStore + in-memory cache.
func newCachedRouter(t *testing.T) (http.Handler, *audit.Memory) {
	t.Helper()
	audits := &audit.Memory{}
	v, err := auth.NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	store := cache.NewStore(newFakeStore(), cache.NewMemory(time.Minute), time.Minute)
	return NewRouter(store, audits, v), audits
}

// runSteps sends each step, checking status and, for authorize, the decision
// and its recorded source.
func runSteps(t *testing.T, h http.Handler, audits *audit.Memory, steps []cstep) {
	t.Helper()
	token := testToken(t, "svc-test")
	for i, s := range steps {
		req := httptest.NewRequest(s.method, s.path, strings.NewReader(s.body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		before := len(audits.Entries())
		h.ServeHTTP(rec, req)

		if s.wantStatus != 0 && rec.Code != s.wantStatus {
			t.Fatalf("step %d (%s %s): status = %d, want %d; body: %s", i+1, s.method, s.path, rec.Code, s.wantStatus, rec.Body.String())
		}
		if s.path != "/v1/authorize" {
			continue
		}

		var resp authorizeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("step %d: bad authorize response: %v", i+1, err)
		}
		entries := audits.Entries()
		if len(entries) != before+1 {
			t.Fatalf("step %d: audit rows = %d, want %d (every decision is recorded, cache hits too)", i+1, len(entries), before+1)
		}
		last := entries[len(entries)-1]
		if resp.Allowed != s.wantAllowed {
			t.Fatalf("step %d: allowed = %v, want %v (source %s)", i+1, resp.Allowed, s.wantAllowed, last.Source)
		}
		if last.Source != s.wantSource {
			t.Fatalf("step %d: audit source = %q, want %q", i+1, last.Source, s.wantSource)
		}
		if last.Allowed != resp.Allowed {
			t.Fatalf("step %d: audit row disagrees with the response", i+1)
		}
	}
}
