package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/rbac"
)

// Test-only JWT settings (not a real secret).
const (
	testSecret   = "test-secret-that-is-at-least-32-bytes-long"
	testIssuer   = "sentinel-test"
	testAudience = "sentinel-api"
)

// newTestRouter builds the real router around the given store and audit logger.
func newTestRouter(t *testing.T, store rbac.PolicyStore, audits audit.Logger) http.Handler {
	t.Helper()
	v, err := auth.NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(store, audits, v)
}

// testToken mints a valid token whose subject is the given caller.
func testToken(t *testing.T, subject string) string {
	t.Helper()
	tok, err := auth.Mint(testSecret, testIssuer, testAudience, subject, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
