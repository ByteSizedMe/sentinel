//go:build integration

// Package integration tests the whole service against real Postgres and Redis
// (the ones from docker-compose). Run with `make test-integration`.
// The tests skip themselves unless DATABASE_URL and REDIS_URL are both set.
package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/cache"
	"github.com/bytesizedme/sentinel/internal/httpapi"
	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/bytesizedme/sentinel/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Test-only JWT settings (not a real secret).
const (
	testSecret   = "integration-secret-that-is-at-least-32-bytes"
	testIssuer   = "sentinel-integration"
	testAudience = "sentinel-api"
	cacheTTL     = 60 * time.Second
)

// env holds what a test needs. Fields are filled by newEnv.
type env struct {
	pool  *pgxpool.Pool
	redis *redis.Client
	pg    *store.Postgres
}

// newEnv connects to Postgres and Redis, or skips the test if either is not
// configured or not reachable.
func newEnv(t testing.TB) *env {
	t.Helper()
	return newEnvFor(t, "DATABASE_URL")
}

// inCI reports whether the tests run in CI (GitHub Actions sets CI=true).
func inCI() bool { return os.Getenv("CI") == "true" }

// skipOrFail ends the test because something it needs is missing. Locally that
// is a skip with a clear message, so `go test` works without Docker. In CI a
// skip would let a broken setup (for example the app-role login not working)
// pass unnoticed, so there it is a failure.
func skipOrFail(t testing.TB, format string, args ...any) {
	t.Helper()
	if inCI() {
		t.Fatalf("CI is set, so this test must not be skipped: "+format, args...)
	}
	t.Skipf(format+"; skipping", args...)
}

// newEnvFor is newEnv with the database taken from the named variable, so a
// test can choose DATABASE_URL (the app role) or APP_DATABASE_URL explicitly.
func newEnvFor(t testing.TB, dbVar string) *env {
	t.Helper()
	dbURL, redisURL := os.Getenv(dbVar), os.Getenv("REDIS_URL")
	if dbURL == "" || redisURL == "" {
		skipOrFail(t, "%s and REDIS_URL must both be set", dbVar)
	}

	pool, err := store.Connect(context.Background(), dbURL)
	if err != nil {
		skipOrFail(t, "Postgres not reachable (%v)", err)
	}
	t.Cleanup(pool.Close)

	client, err := cache.NewRedisClient(redisURL)
	if err != nil {
		t.Fatalf("REDIS_URL: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		skipOrFail(t, "Redis not reachable (%v)", err)
	}

	return &env{pool: pool, redis: client, pg: store.NewPostgres(pool)}
}

// router builds the real HTTP handler with the real (Postgres) audit log. The
// policy store is Postgres, fronted by the given cache (or used directly when
// c is nil).
func (e *env) router(t testing.TB, c cache.Cache) http.Handler {
	t.Helper()
	return e.routerWith(t, c, audit.NewPostgres(e.pool))
}

// routerWith is router with a chosen audit logger (benchmarks use a fast one
// to isolate the cost of the decision itself).
func (e *env) routerWith(t testing.TB, c cache.Cache, audits audit.Logger) http.Handler {
	t.Helper()
	var policy rbac.PolicyStore = e.pg
	if c != nil {
		policy = cache.NewStore(e.pg, c, cacheTTL)
	}
	v, err := auth.NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	return httpapi.NewRouter(policy, audits, v, httpapi.Limits{}) // limiters off: the tests send many requests from one address
}

func token(t testing.TB, subject string) string {
	t.Helper()
	tok, err := auth.Mint(testSecret, testIssuer, testAudience, subject, strings.Join(auth.AllScopes, " "), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
