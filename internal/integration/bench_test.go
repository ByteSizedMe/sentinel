//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/cache"
	"github.com/bytesizedme/sentinel/internal/rbac"
)

// Benchmarks compare answering with a warm cache against going to Postgres
// every time. Run with `make bench`.
//
// NOTE: BenchmarkAuthorize writes one audit_log row per request, exactly like
// the real service. The log is append-only, so these rows stay; clear them
// with `make migrate-down` then `make migrate-up` if you care.

// seedUser creates a role, resource and permission and a user holding them,
// and returns the user and resource names. Cleanup removes everything except
// the audit rows.
func seedUser(b *testing.B, e *env) (user, resource string) {
	b.Helper()
	ctx := context.Background()
	n := time.Now().UnixNano()
	user, resource = fmt.Sprintf("bench-user-%d", n), fmt.Sprintf("bench-res-%d", n)

	role, err := e.pg.CreateRole(ctx, fmt.Sprintf("bench-role-%d", n), "")
	if err != nil {
		b.Fatal(err)
	}
	res, err := e.pg.CreateResource(ctx, resource, "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = e.pg.DeleteRole(ctx, role.ID); _ = e.pg.DeleteResource(ctx, res.ID) })
	perm, err := e.pg.CreatePermission(ctx, "read", res.ID)
	if err != nil {
		b.Fatal(err)
	}
	if err := e.pg.GrantPermission(ctx, role.ID, perm.ID); err != nil {
		b.Fatal(err)
	}
	if err := e.pg.AssignRole(ctx, user, role.ID); err != nil {
		b.Fatal(err)
	}
	return user, resource
}

// BenchmarkCheckPermission measures only the decision lookup.
func BenchmarkCheckPermission(b *testing.B) {
	e := newEnv(b)
	user, resource := seedUser(b, e)
	ctx := context.Background()

	cases := []struct {
		name  string
		store rbac.PolicyStore
	}{
		{"postgres_only", e.pg},
		{"cache_warm", cache.NewStore(e.pg, cache.NewRedis(e.redis, cacheTTL), cacheTTL)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			if _, err := c.store.CheckPermission(ctx, user, "read", resource); err != nil { // warm up
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d, err := c.store.CheckPermission(ctx, user, "read", resource)
				if err != nil || !d.Allowed {
					b.Fatalf("decision = %+v, err = %v", d, err)
				}
			}
		})
	}
}

// BenchmarkRoundTrip is the floor: the cost of one trivial request to each
// service. On Windows with Docker Desktop this is dominated by the port
// forwarding between the host and the Linux VM, and it explains the results of
// the benchmarks below.
func BenchmarkRoundTrip(b *testing.B) {
	e := newEnv(b)
	ctx := context.Background()

	b.Run("postgres_select_1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var n int
			if err := e.pool.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("redis_ping", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := e.redis.Ping(ctx).Err(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkAuthorize measures the whole POST /v1/authorize path: JWT check,
// JSON decoding, decision, audit log, response. The audit log is part of the
// real service, so "audit_postgres" is the realistic number. "audit_memory"
// swaps the Postgres insert for an in-memory one, to show the cost of the
// decision on its own.
func BenchmarkAuthorize(b *testing.B) {
	e := newEnv(b)
	user, resource := seedUser(b, e)
	body := fmt.Sprintf(`{"user_id":%q,"action":"read","resource":%q}`, user, resource)
	bearer := "Bearer " + token(b, "svc-bench")

	audits := []struct {
		name string
		l    func() audit.Logger
	}{
		{"audit_postgres", func() audit.Logger { return audit.NewPostgres(e.pool) }},
		{"audit_memory", func() audit.Logger { return &audit.Memory{} }},
	}
	caches := []struct {
		name string
		c    cache.Cache
	}{
		{"cache_disabled", nil},
		{"cache_warm", cache.NewRedis(e.redis, cacheTTL)},
	}
	for _, a := range audits {
		for _, tc := range caches {
			b.Run(a.name+"/"+tc.name, func(b *testing.B) {
				h := e.routerWith(b, tc.c, a.l())
				send := func() int {
					req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
					req.Header.Set("Authorization", bearer)
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					return rec.Code
				}
				send() // warm up
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if code := send(); code != http.StatusOK {
						b.Fatalf("status = %d", code)
					}
				}
			})
		}
	}
}
