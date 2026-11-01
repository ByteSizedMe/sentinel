package httpapi

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/go-chi/chi/v5"
)

// captureLog sends the standard logger's output to a buffer until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

// failWith returns a handler that reports err through writeError, the same way
// every real handler does for an unexpected failure (the 500 path).
func failWith(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { writeError(w, r, err) }
}

// The real handlers reject a path with a newline in it (400) before they reach
// the store, so these cases mount writeError on a small Chi router and send the
// hostile request straight at it. Chi fills in the route pattern exactly as it
// does in the real router.
func TestUnexpectedErrorLogCannotBeForged(t *testing.T) {
	const forged = "FORGED-LOG-LINE"

	tests := []struct {
		name      string
		serve     func(w http.ResponseWriter, r *http.Request)
		path      string
		wantInLog []string // substrings the line must contain
	}{
		{
			name: "newline in the request path",
			serve: func(w http.ResponseWriter, r *http.Request) {
				c := chi.NewRouter()
				c.Get("/v1/roles/{roleID}", failWith(errors.New("boom")))
				c.ServeHTTP(w, r)
			},
			path:      "/v1/roles/1%0A" + forged,
			wantInLog: []string{`"GET" "/v1/roles/{roleID}": "boom"`},
		},
		{
			name: "newline in the error text",
			serve: func(w http.ResponseWriter, r *http.Request) {
				c := chi.NewRouter()
				c.Get("/v1/roles/{roleID}", failWith(errors.New("bad input:\n"+forged)))
				c.ServeHTTP(w, r)
			},
			path:      "/v1/roles/1",
			wantInLog: []string{`"/v1/roles/{roleID}"`, `\n` + forged},
		},
		{
			name:      "no route context",
			serve:     failWith(errors.New("boom")),
			path:      "/v1/roles/1%0A" + forged,
			wantInLog: []string{`"GET" "unmatched": "boom"`},
		},
		{
			name: "real router, store failure",
			serve: func(w http.ResponseWriter, r *http.Request) {
				newTestRouter(t, errStore{newFakeStore()}, &audit.Memory{}).ServeHTTP(w, r)
			},
			path:      "/v1/roles/",
			wantInLog: []string{`"GET" "/v1/roles"`, `password authentication failed`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureLog(t)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-test"))
			rec := httptest.NewRecorder()
			tt.serve(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
			out := buf.String()
			if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("log must be exactly one line, got %q", out)
			}
			for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
				if strings.HasPrefix(line, forged) {
					t.Errorf("injected text became its own log line: %q", out)
				}
			}
			for _, want := range tt.wantInLog {
				if !strings.Contains(out, want) {
					t.Errorf("log %q does not contain %q", out, want)
				}
			}
			// The raw client path must never be logged, only the pattern.
			if strings.Contains(out, "%0") {
				t.Errorf("log contains the raw request path: %q", out)
			}
			if tt.name == "newline in the request path" && strings.Contains(out, forged) {
				t.Errorf("log contains client path text: %q", out)
			}
		})
	}
}
