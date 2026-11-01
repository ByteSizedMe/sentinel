package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/audit"
)

// Tests for decodeJSON's three guards (body size, unknown fields, trailing
// data) on every endpoint that reads a JSON body. /v1/authorize has its own
// 4 KB limit and is covered in authorize_test.go.

// bodyEndpoint is one endpoint that reads a JSON body. validBody succeeds
// against the store built by limitsStore, with wantOK as its status.
type bodyEndpoint struct {
	name      string
	path      string
	validBody string
	wantOK    int
}

// bodyEndpoints lists the five JSON-body endpoints under /v1 (all POST).
var bodyEndpoints = []bodyEndpoint{
	{"roles", "/v1/roles", `{"name":"auditor"}`, http.StatusCreated},
	{"resources", "/v1/resources", `{"name":"reports"}`, http.StatusCreated},
	{"permissions", "/v1/permissions", `{"action":"write","resource_id":1}`, http.StatusCreated},
	{"role permission grants", "/v1/roles/1/permissions", `{"permission_id":1}`, http.StatusCreated},
	{"user role assignments", "/v1/users/u9/roles", `{"role_id":1}`, http.StatusCreated},
}

// limitsStore holds role 1, resource 1 and permission 1, so that every valid
// body in bodyEndpoints is accepted. That lets a test prove a rejection came
// from the guard under test and not from a missing reference.
func limitsStore(t *testing.T) *fakeStore {
	t.Helper()
	ctx := context.Background()
	f := newFakeStore()
	if _, err := f.CreateRole(ctx, "editor", ""); err != nil {
		t.Fatal(err)
	}
	res, err := f.CreateResource(ctx, "invoices", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreatePermission(ctx, "read", res.ID); err != nil {
		t.Fatal(err)
	}
	return f
}

// post sends one authenticated POST with the given body to a fresh router
// wrapped around f, and returns the recorded response.
func post(t *testing.T, f *fakeStore, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := newTestRouter(t, f, &audit.Memory{})
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-test"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// withExtra turns `{"a":1}` into `{"a":1,<extra>}`.
func withExtra(body, extra string) string {
	return strings.TrimSuffix(body, "}") + "," + extra + "}"
}

func TestBodyOverLimitIsRejected(t *testing.T) {
	const wantBody = `{"error":"request body too large"}`
	// One byte over the limit. The padding sits inside a string value, so the
	// body is valid JSON up to the point where the limit cuts it off.
	big := `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`

	for _, e := range bodyEndpoints {
		t.Run(e.name, func(t *testing.T) {
			if len(big) <= maxBodyBytes {
				t.Fatalf("test body is %d bytes, must exceed %d", len(big), maxBodyBytes)
			}
			f := limitsStore(t)
			rec := post(t, f, e.path, big)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413; body: %s", rec.Code, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != wantBody {
				t.Errorf("body = %s, want %s", got, wantBody)
			}
		})
	}
}

func TestUnknownFieldIsRejected(t *testing.T) {
	for _, e := range bodyEndpoints {
		t.Run(e.name, func(t *testing.T) {
			f := limitsStore(t)
			rec := post(t, f, e.path, withExtra(e.validBody, `"extra":1`))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}

			// Control: the same body without the extra field is accepted, and
			// not as a duplicate, so the rejected request changed nothing.
			rec = post(t, f, e.path, e.validBody)
			if rec.Code != e.wantOK {
				t.Fatalf("control request: status = %d, want %d; body: %s", rec.Code, e.wantOK, rec.Body.String())
			}
		})
	}
}

func TestTrailingJSONIsRejected(t *testing.T) {
	for _, e := range bodyEndpoints {
		t.Run(e.name, func(t *testing.T) {
			f := limitsStore(t)
			rec := post(t, f, e.path, e.validBody+e.validBody)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "single JSON object") {
				t.Errorf("body = %s, want the single-object message", rec.Body.String())
			}
		})
	}
}
