//go:build integration

// Package integration tests the whole service against real Postgres and Redis
// (the ones from docker-compose). Run with `make test-integration`.
// The tests skip themselves unless DATABASE_URL and REDIS_URL are both set.
package integration

import (
	"context"
	"net/http"
	"os"
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
	dbURL, redisURL := os.Getenv("DATABASE_URL"), os.Getenv("REDIS_URL")
	if dbURL == "" || redisURL == "" {
		t.Skip("DATABASE_URL and REDIS_URL must both be set; skipping integration test")
	}

	pool, err := store.Connect(context.Background(), dbURL)
	if err != nil {
		t.Skipf("Postgres not reachable (%v); skipping", err)
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
		t.Skipf("Redis not reachable (%v); skipping", err)
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
	return httpapi.NewRouter(policy, audits, v)
}

func token(t testing.TB, subject string) string {
	t.Helper()
	tok, err := auth.Mint(testSecret, testIssuer, testAudience, subject, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
