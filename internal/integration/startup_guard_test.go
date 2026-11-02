//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/bytesizedme/sentinel/internal/store"
)

// The startup guard against the real database: the owner connection is refused,
// the app role is accepted, and the override turns the refusal into a warning.
func TestStartupGuardOnRealRoles(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, envVar string, allow bool) (string, error) {
		t.Helper()
		url := os.Getenv(envVar)
		if url == "" {
			skipOrFail(t, "%s is not set", envVar)
		}
		pool, err := store.Connect(ctx, url)
		if err != nil {
			skipOrFail(t, "%s: cannot connect (%v)", envVar, err)
		}
		t.Cleanup(pool.Close)
		return store.CheckRole(ctx, pool, allow)
	}

	t.Run("the owner is refused", func(t *testing.T) {
		warn, err := check(t, "MIGRATE_DATABASE_URL", false)
		if !errors.Is(err, store.ErrPrivilegedRole) || warn != "" {
			t.Fatalf("warning=%q err=%v, want ErrPrivilegedRole", warn, err)
		}
	})
	t.Run("the owner with the override gets one warning", func(t *testing.T) {
		warn, err := check(t, "MIGRATE_DATABASE_URL", true)
		if err != nil || warn == "" {
			t.Fatalf("warning=%q err=%v, want a warning and no error", warn, err)
		}
	})
	t.Run("the app role starts", func(t *testing.T) {
		warn, err := check(t, "APP_DATABASE_URL", false)
		if err != nil || warn != "" {
			t.Fatalf("warning=%q err=%v, want neither", warn, err)
		}
	})
}
