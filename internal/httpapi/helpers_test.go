package httpapi

import (
	"net/http"
	"strings"
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
	return NewRouter(store, audits, v, Limits{})
}

// testToken mints a valid token whose subject is the given caller, holding all
// three scopes so tests that are not about scopes can call any route.
func testToken(t *testing.T, subject string) string {
	t.Helper()
	return testTokenScoped(t, subject, strings.Join(auth.AllScopes, " "))
}

// testTokenScoped is testToken with an exact "scope" claim ("" = no claim).
func testTokenScoped(t *testing.T, subject, scope string) string {
	t.Helper()
	tok, err := auth.Mint(testSecret, testIssuer, testAudience, subject, scope, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
