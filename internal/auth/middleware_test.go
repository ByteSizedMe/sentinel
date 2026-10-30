package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddleware(t *testing.T) {
	v, _ := NewValidator(testSecret, testIssuer, testAudience)
	good, _ := Mint(testSecret, testIssuer, testAudience, "svc-a", time.Hour)
	bad, _ := Mint("another-secret-that-is-also-32-bytes-long", testIssuer, testAudience, "svc-a", time.Hour)

	tests := []struct {
		name       string
		header     string // value of the Authorization header; "" = not sent
		wantStatus int
	}{
		{"valid bearer token", "Bearer " + good, http.StatusOK},
		{"scheme is case-insensitive", "bearer " + good, http.StatusOK},
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + good, http.StatusUnauthorized},
		{"token without scheme", good, http.StatusUnauthorized},
		{"empty token", "Bearer ", http.StatusUnauthorized},
		{"tampered token", "Bearer " + good[:len(good)-2] + "xx", http.StatusUnauthorized},
		{"wrong signature", "Bearer " + bad, http.StatusUnauthorized},
		{"oversized token", "Bearer " + strings.Repeat("a", maxTokenLen+1), http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			var gotSubject string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				gotSubject, _ = SubjectFromContext(r.Context())
			})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			Middleware(v)(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusOK {
				if !reached || gotSubject != "svc-a" {
					t.Errorf("reached = %v, subject = %q; want true, svc-a", reached, gotSubject)
				}
				return
			}
			// Failures: handler must not run, message must be generic.
			if reached {
				t.Error("next handler ran despite failed authentication")
			}
			if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"unauthorized"}` {
				t.Errorf("body = %q, want the generic message", got)
			}
			if rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Error("missing WWW-Authenticate header")
			}
		})
	}
}

func TestSubjectFromContextEmpty(t *testing.T) {
	if s, ok := SubjectFromContext(httptest.NewRequest(http.MethodGet, "/", nil).Context()); ok || s != "" {
		t.Errorf("got %q, %v; want empty, false", s, ok)
	}
}
