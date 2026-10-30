package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func TestRoutes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string // trimmed; empty means "don't check"
	}{
		{"health ok", http.MethodGet, "/health", http.StatusOK, `{"status":"ok"}`},
		{"health wrong method", http.MethodPost, "/health", http.StatusMethodNotAllowed, ""},
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound, ""},
	}

	h := newTestRouter(t, newFakeStore(), &audit.Memory{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" {
				if got := strings.TrimSpace(rec.Body.String()); got != tt.wantBody {
					t.Errorf("body = %q, want %q", got, tt.wantBody)
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
			}
		})
	}
}

// A panicking handler must yield a 500, not crash the server.
func TestRecovererMiddleware(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// Every /v1 route must reject missing or bad tokens; /health must stay public.
func TestV1RequiresToken(t *testing.T) {
	h := newTestRouter(t, newFakeStore(), &audit.Memory{})
	good := testToken(t, "svc-test")
	tampered := good[:len(good)-2] + "xx"

	routes := []struct{ method, path string }{
		{http.MethodPost, "/v1/authorize"},
		{http.MethodGet, "/v1/roles"},
		{http.MethodPost, "/v1/roles"},
		{http.MethodGet, "/v1/roles/1"},
		{http.MethodDelete, "/v1/roles/1"},
		{http.MethodGet, "/v1/resources"},
		{http.MethodGet, "/v1/permissions"},
		{http.MethodPost, "/v1/roles/1/permissions"},
		{http.MethodGet, "/v1/users/u1/roles"},
		{http.MethodPost, "/v1/users/u1/roles"},
		{http.MethodGet, "/v1/does-not-exist"},
	}
	headers := []struct{ name, value string }{
		{"no token", ""},
		{"tampered token", "Bearer " + tampered},
		{"not a token", "Bearer abc"},
		{"wrong scheme", "Basic " + good},
	}

	for _, rt := range routes {
		for _, hd := range headers {
			t.Run(rt.method+" "+rt.path+" "+hd.name, func(t *testing.T) {
				req := httptest.NewRequest(rt.method, rt.path, strings.NewReader("{}"))
				if hd.value != "" {
					req.Header.Set("Authorization", hd.value)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("status = %d, want 401", rec.Code)
				}
			})
		}
	}

	// And /health works with no token at all.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health status = %d, want 200", rec.Code)
	}
}
