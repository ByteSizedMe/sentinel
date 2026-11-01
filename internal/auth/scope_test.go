package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseScopes(t *testing.T) {
	long := strings.Repeat("x ", 1500) // 3,000 bytes of unknown entries

	tests := []struct {
		name  string
		claim any
		want  []string
	}{
		{"missing claim", nil, nil},
		{"empty string", "", nil},
		{"one scope", "sentinel:read", []string{"sentinel:read"}},
		{"all three", "sentinel:authorize sentinel:read sentinel:admin", []string{"sentinel:authorize", "sentinel:read", "sentinel:admin"}},
		{"unknown scopes are ignored", "profile sentinel:read email", []string{"sentinel:read"}},
		{"only unknown scopes", "profile email", nil},
		{"leading space", " sentinel:read", []string{"sentinel:read"}},
		{"trailing space", "sentinel:read ", []string{"sentinel:read"}},
		{"double space", "sentinel:read  sentinel:admin", []string{"sentinel:read", "sentinel:admin"}},
		{"only spaces", "    ", nil},
		{"uppercase does not match", "SENTINEL:READ Sentinel:Admin", nil},
		{"tab is not a separator", "sentinel:read\tsentinel:admin", nil},
		{"newline is not a separator", "sentinel:read\nsentinel:admin", nil},
		{"tab glued to a scope does not match", "sentinel:read\t", nil},
		{"carriage return does not match", "sentinel:read\r", nil},
		{"prefix of a scope does not match", "sentinel:rea", nil},
		{"scope with a suffix does not match", "sentinel:reader", nil},
		{"very long string, valid scope last", long + "sentinel:admin", []string{"sentinel:admin"}},
		{"number", float64(1), nil},
		{"boolean", true, nil},
		{"array of strings", []any{"sentinel:read", "sentinel:admin"}, nil},
		{"object", map[string]any{"sentinel:read": true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseScopes(tt.claim); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseScopes(%#v) = %v, want %v", tt.claim, got, tt.want)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	withScopes := context.WithValue(context.Background(), scopesKey{}, []string{ScopeRead})

	tests := []struct {
		name  string
		ctx   context.Context
		scope string
		want  bool
	}{
		{"held", withScopes, ScopeRead, true},
		{"not held", withScopes, ScopeAdmin, false},
		{"empty scope is never held", withScopes, "", false},
		{"no scopes in context", context.Background(), ScopeRead, false},
		{"wrong type in context", context.WithValue(context.Background(), scopesKey{}, "sentinel:read"), ScopeRead, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScope(tt.ctx, tt.scope); got != tt.want {
				t.Errorf("HasScope = %v, want %v", got, tt.want)
			}
		})
	}
}

// signWithScope signs a token whose "scope" claim is any JSON value, which
// Mint (string only) cannot produce.
func signWithScope(t *testing.T, scope any) string {
	t.Helper()
	c := tokenClaims{RegisteredClaims: claimsFor(nil), Scope: scope}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A token with an odd scope claim is still a VALID token (200 from the
// middleware); it just carries no scopes. The route-level check then says 403.
func TestMiddlewareStoresScopes(t *testing.T) {
	v, _ := NewValidator(testSecret, testIssuer, testAudience)
	mint := func(scope string) string {
		tok, err := Mint(testSecret, testIssuer, testAudience, "svc-a", scope, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantRead   bool
		wantAdmin  bool
	}{
		{"scope read", mint("sentinel:read"), http.StatusOK, true, false},
		{"scope read plus unknown", mint("foo sentinel:read bar"), http.StatusOK, true, false},
		{"scope admin only", mint("sentinel:admin"), http.StatusOK, false, true},
		{"no scope claim", mint(""), http.StatusOK, false, false},
		{"scope is a number", signWithScope(t, 7), http.StatusOK, false, false},
		{"scope is an array", signWithScope(t, []string{"sentinel:read"}), http.StatusOK, false, false},
		{"scope is an object", signWithScope(t, map[string]bool{"sentinel:read": true}), http.StatusOK, false, false},
		{"scope is null", signWithScope(t, nil), http.StatusOK, false, false},
		{"scope with a tab", mint("sentinel:read\tsentinel:admin"), http.StatusOK, false, false},
		{
			// Under the 4,096-byte token limit: still accepted, scope still found.
			name:       "long scope under the token limit",
			token:      mint(strings.Repeat("x ", 1000) + "sentinel:read"),
			wantStatus: http.StatusOK,
			wantRead:   true,
		},
		{
			// Over the limit: the existing size check rejects it before parsing.
			name:       "long scope over the token limit",
			token:      mint(strings.Repeat("x ", 4000) + "sentinel:read"),
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotRead, gotAdmin bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotRead = HasScope(r.Context(), ScopeRead)
				gotAdmin = HasScope(r.Context(), ScopeAdmin)
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rec := httptest.NewRecorder()
			Middleware(v)(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if gotRead != tt.wantRead || gotAdmin != tt.wantAdmin {
				t.Errorf("read = %v, admin = %v; want %v, %v", gotRead, gotAdmin, tt.wantRead, tt.wantAdmin)
			}
		})
	}
}
