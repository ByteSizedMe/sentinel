package httpapi

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// scopedRoute is one /v1 endpoint as the tests expect it: the scope it needs,
// a request that works, and the status that request gets from the handler when
// the scope check passes. This table is written out by hand and is separate
// from the one in router.go on purpose, so a wrong scope in the router is caught.
type scopedRoute struct {
	method, path string // path is a concrete URL; pattern is the Chi route
	pattern      string
	body         string
	scope        string
	wantOK       int // handler result against limitsStore (role 1, resource 1, permission 1)
}

const (
	authz = auth.ScopeAuthorize
	read  = auth.ScopeRead
	admin = auth.ScopeAdmin
)

var scopedRoutes = []scopedRoute{
	{"POST", "/v1/authorize", "/v1/authorize", `{"user_id":"u1","action":"read","resource":"invoices"}`, authz, 200},

	{"POST", "/v1/roles", "/v1/roles", `{"name":"auditor"}`, admin, 201},
	{"GET", "/v1/roles", "/v1/roles", ``, read, 200},
	{"GET", "/v1/roles/1", "/v1/roles/{roleID}", ``, read, 200},
	{"DELETE", "/v1/roles/1", "/v1/roles/{roleID}", ``, admin, 204},
	{"GET", "/v1/roles/1/permissions", "/v1/roles/{roleID}/permissions", ``, read, 200},
	{"POST", "/v1/roles/1/permissions", "/v1/roles/{roleID}/permissions", `{"permission_id":1}`, admin, 201},
	{"DELETE", "/v1/roles/1/permissions/1", "/v1/roles/{roleID}/permissions/{permissionID}", ``, admin, 404}, // nothing granted yet

	{"POST", "/v1/resources", "/v1/resources", `{"name":"reports"}`, admin, 201},
	{"GET", "/v1/resources", "/v1/resources", ``, read, 200},
	{"GET", "/v1/resources/1", "/v1/resources/{resourceID}", ``, read, 200},
	{"DELETE", "/v1/resources/1", "/v1/resources/{resourceID}", ``, admin, 204},

	{"POST", "/v1/permissions", "/v1/permissions", `{"action":"write","resource_id":1}`, admin, 201},
	{"GET", "/v1/permissions", "/v1/permissions", ``, read, 200},
	{"GET", "/v1/permissions/1", "/v1/permissions/{permissionID}", ``, read, 200},
	{"DELETE", "/v1/permissions/1", "/v1/permissions/{permissionID}", ``, admin, 204},

	{"GET", "/v1/users/u1/roles", "/v1/users/{userID}/roles", ``, read, 200},
	{"POST", "/v1/users/u1/roles", "/v1/users/{userID}/roles", `{"role_id":1}`, admin, 201},
	{"DELETE", "/v1/users/u1/roles/1", "/v1/users/{userID}/roles/{roleID}", ``, admin, 404}, // not assigned yet
}

// claimToken signs a token with the given scope claim. includeScope=false
// leaves the claim out entirely. Mint cannot make an empty-but-present claim
// or a non-string one, so this builds the claims by hand.
func claimToken(t *testing.T, subject string, includeScope bool, scope any) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": testIssuer,
		"sub": subject,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if includeScope {
		c["scope"] = scope
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// storeState is a cheap fingerprint of everything a handler could change.
func storeState(f *fakeStore) string {
	return fmt.Sprint(len(f.roles), len(f.resources), len(f.permissions), len(f.grants), len(f.assigns))
}

// otherScopes returns the two known scopes that are not `scope`.
func otherScopes(scope string) string {
	var out []string
	for _, s := range auth.AllScopes {
		if s != scope {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// Every route, five kinds of token: (a) no scope claim, (b) empty scope,
// (c) only the other two scopes, (d) the right scope plus unknown extras,
// (e) the right scope alone. Plus (f) no token at all, which stays a 401.
func TestRouteScopeMatrix(t *testing.T) {
	for _, rt := range scopedRoutes {
		tests := []struct {
			name      string
			token     string // "" = send no Authorization header
			want      int
			forbidden bool
		}{
			{"no scope claim", claimToken(t, "svc-x", false, nil), 403, true},
			{"empty scope", claimToken(t, "svc-x", true, ""), 403, true},
			{"only the wrong scopes", testTokenScoped(t, "svc-x", otherScopes(rt.scope)), 403, true},
			{"right scope plus unknown extras", testTokenScoped(t, "svc-x", "profile  "+rt.scope+" email"), rt.wantOK, false},
			{"right scope only", testTokenScoped(t, "svc-x", rt.scope), rt.wantOK, false},
			{"no token", "", 401, false},
		}
		for _, tt := range tests {
			t.Run(rt.method+" "+rt.path+"/"+tt.name, func(t *testing.T) {
				f := limitsStore(t)
				audits := &audit.Memory{}
				h := newTestRouter(t, f, audits)
				before := storeState(f)

				req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
				req.Header.Set("Content-Type", "application/json")
				if tt.token != "" {
					req.Header.Set("Authorization", "Bearer "+tt.token)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				if rec.Code != tt.want {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.want, rec.Body.String())
				}
				if tt.forbidden {
					if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"forbidden"}` {
						t.Errorf("body = %q, want the fixed forbidden body", got)
					}
					// A refused request must change nothing and leave no audit row.
					if storeState(f) != before {
						t.Errorf("store changed by a forbidden request: %s -> %s", before, storeState(f))
					}
					if n := len(audits.Entries()); n != 0 {
						t.Errorf("%d audit entries written for a forbidden request", n)
					}
				}
			})
		}
	}
}

// walkV1 returns "METHOD pattern" for every route Chi has under /v1.
func walkV1(t *testing.T, h http.Handler) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/v1") {
			got[method+" "+route] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A future /v1 route cannot be added without a scope: every route Chi knows
// about must be in the router's table with a non-empty scope AND in the
// expected table above with the same scope, and the two must match exactly.
func TestEveryV1RouteHasAScope(t *testing.T) {
	h := newTestRouter(t, newFakeStore(), &audit.Memory{})
	walked := walkV1(t, h)

	declared := map[string]string{} // "METHOD /v1/pattern" -> scope, from router.go
	for _, rt := range (&api{}).v1Routes() {
		declared[rt.method+" /v1"+rt.pattern] = rt.scope
	}
	expected := map[string]string{} // from the test table
	for _, rt := range scopedRoutes {
		expected[rt.method+" "+rt.pattern] = rt.scope
	}

	if len(expected) != 19 {
		t.Fatalf("test table has %d routes, want 19", len(expected))
	}
	for key := range walked {
		scope, ok := declared[key]
		if !ok || scope == "" {
			t.Errorf("route %q is registered without a required scope", key)
		}
		if _, ok := expected[key]; !ok {
			t.Errorf("route %q is not in the expected-scope table", key)
		}
	}
	for key, want := range expected {
		if !walked[key] {
			t.Errorf("expected route %q is not registered", key)
		}
		if declared[key] != want {
			t.Errorf("route %q requires %q, want %q", key, declared[key], want)
		}
	}
	if len(walked) != len(expected) {
		t.Errorf("router has %d /v1 routes, want %d", len(walked), len(expected))
	}
}

// A route declared with no scope must answer 403 to a token that holds every
// scope, never run its handler, and never be open.
func TestRouteWithoutScopeFailsClosed(t *testing.T) {
	v, err := auth.NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	r := chi.NewRouter()
	r.Use(auth.Middleware(v))
	r.With(requireScope("")).Get("/unscoped", func(http.ResponseWriter, *http.Request) { ran = true })

	req := httptest.NewRequest(http.MethodGet, "/unscoped", nil)
	req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-x")) // all three scopes
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || ran {
		t.Errorf("status = %d, handler ran = %v; want 403, false", rec.Code, ran)
	}
}

// /health must stay public even though /v1 now needs scopes.
func TestHealthNeedsNoScope(t *testing.T) {
	h := newTestRouter(t, newFakeStore(), &audit.Memory{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health status = %d, want 200", rec.Code)
	}
}

// The 403 log line has the route pattern and the subject, quoted, and nothing
// else: no token, no scope names, no raw path.
func TestForbiddenLogLine(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		path    string
		want    string
	}{
		{"plain subject", "svc-x", "/v1/roles/1", `httpapi: forbidden route "/v1/roles/{roleID}" sub "svc-x"`},
		{"subject with a newline", "svc-x\nFORGED", "/v1/roles/1", `sub "svc-x\nFORGED"`},
		{"path with a newline", "svc-x", "/v1/roles/1%0AFORGED", `route "/v1/roles/{roleID}"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			orig := log.Writer()
			log.SetOutput(&buf)
			t.Cleanup(func() { log.SetOutput(orig) })

			// Admin only, calling a read route: authenticated but not allowed.
			token := testTokenScoped(t, tt.subject, auth.ScopeAdmin)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			newTestRouter(t, newFakeStore(), &audit.Memory{}).ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			out := buf.String()
			if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("log must be exactly one line, got %q", out)
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("log %q does not contain %q", out, tt.want)
			}
			for _, secret := range []string{token, "sentinel:", "%0A", "Bearer"} {
				if strings.Contains(out, secret) {
					t.Errorf("log leaks %q: %q", secret, out)
				}
			}
		})
	}
}
