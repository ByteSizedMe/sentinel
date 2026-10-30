//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/cache"
)

// client is a tiny JSON-over-HTTP helper bound to one running test server.
type client struct {
	t     *testing.T
	base  string
	token string
}

// call sends a request and decodes the JSON response into out (if non-nil).
func (c *client) call(method, path, body string, wantStatus int, out any) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		c.t.Fatalf("%s %s: status = %d, want %d", method, path, resp.StatusCode, wantStatus)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
}

type idResp struct {
	ID int64 `json:"id"`
}

func (c *client) authorize(user, action, resource string) bool {
	c.t.Helper()
	var r struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	body := fmt.Sprintf(`{"user_id":%q,"action":%q,"resource":%q}`, user, action, resource)
	c.call("POST", "/v1/authorize", body, 200, &r)
	return r.Allowed
}

// auditRow is one row of audit_log.
type auditRow struct {
	Caller, Reason, Source string
	Allowed                bool
}

func (e *env) auditRows(t *testing.T, user string) []auditRow {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT caller, allowed, reason, source FROM audit_log WHERE user_id = $1 ORDER BY id`, user)
	if err != nil {
		t.Fatalf("query audit_log (has make migrate-up been run?): %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Caller, &r.Allowed, &r.Reason, &r.Source); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// TestFullFlow walks the whole life of a permission through the real stack:
// create, grant, assign, authorize (twice), revoke, authorize (twice), then
// checks the audit log row by row.
func TestFullFlow(t *testing.T) {
	// "redis unreachable" points the cache at a port nothing listens on: the
	// service must still answer correctly, from Postgres only.
	deadRedis, err := cache.NewRedisClient("redis://127.0.0.1:1/0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = deadRedis.Close() })

	tests := []struct {
		name string
		// cacheFor returns the cache to use, or nil for none.
		cacheFor func(e *env) cache.Cache
		// wantSources are the expected audit sources of the 4 authorize calls.
		wantSources [4]string
	}{
		{"cache enabled", func(e *env) cache.Cache { return cache.NewRedis(e.redis, cacheTTL) }, [4]string{"db", "cache", "db", "cache"}},
		{"cache disabled", func(e *env) cache.Cache { return nil }, [4]string{"db", "db", "db", "db"}},
		{"redis unreachable", func(e *env) cache.Cache { return cache.NewRedis(deadRedis, cacheTTL) }, [4]string{"db", "db", "db", "db"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			srv := httptest.NewServer(e.router(t, tt.cacheFor(e)))
			// t.Cleanup runs last-in-first-out, so registering the server first
			// means it is still up when the catalog cleanup below calls it.
			t.Cleanup(srv.Close)
			c := &client{t: t, base: srv.URL, token: token(t, "svc-integration")}

			// Unique names so reruns and parallel runs never collide.
			suffix := time.Now().UnixNano()
			user := fmt.Sprintf("user-%d", suffix)
			roleName, resName := fmt.Sprintf("role-%d", suffix), fmt.Sprintf("res-%d", suffix)

			var role, res, perm idResp
			c.call("POST", "/v1/roles", fmt.Sprintf(`{"name":%q}`, roleName), 201, &role)
			c.call("POST", "/v1/resources", fmt.Sprintf(`{"name":%q}`, resName), 201, &res)
			// Tidy up the catalog afterwards. Audit rows stay: the log is append-only.
			t.Cleanup(func() {
				c.call("DELETE", fmt.Sprintf("/v1/roles/%d", role.ID), "", 204, nil)
				c.call("DELETE", fmt.Sprintf("/v1/resources/%d", res.ID), "", 204, nil)
			})
			c.call("POST", "/v1/permissions", fmt.Sprintf(`{"action":"read","resource_id":%d}`, res.ID), 201, &perm)
			c.call("POST", fmt.Sprintf("/v1/roles/%d/permissions", role.ID), fmt.Sprintf(`{"permission_id":%d}`, perm.ID), 201, nil)
			c.call("POST", fmt.Sprintf("/v1/users/%s/roles", user), fmt.Sprintf(`{"role_id":%d}`, role.ID), 201, nil)

			got := []bool{
				c.authorize(user, "read", resName), // allowed, read from Postgres
				c.authorize(user, "read", resName), // allowed, from the cache when enabled
			}
			c.call("DELETE", fmt.Sprintf("/v1/roles/%d/permissions/%d", role.ID, perm.ID), "", 204, nil)
			got = append(got,
				c.authorize(user, "read", resName), // must be denied immediately
				c.authorize(user, "read", resName),
			)

			if want := []bool{true, true, false, false}; fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("decisions = %v, want %v", got, want)
			}

			rows := e.auditRows(t, user)
			if len(rows) != 4 {
				t.Fatalf("audit rows = %d, want 4 (one per decision, cache hits included)", len(rows))
			}
			for i, r := range rows {
				wantAllowed := i < 2
				if r.Allowed != wantAllowed || r.Source != tt.wantSources[i] || r.Caller != "svc-integration" {
					t.Errorf("audit row %d = %+v, want allowed=%v source=%s caller=svc-integration", i+1, r, wantAllowed, tt.wantSources[i])
				}
			}
		})
	}
}

// Everything the cache writes to Redis is namespaced and has a TTL.
func TestRedisKeysHaveNamespaceAndTTL(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(e.router(t, cache.NewRedis(e.redis, cacheTTL)))
	t.Cleanup(srv.Close)
	c := &client{t: t, base: srv.URL, token: token(t, "svc-integration")}

	// Any decision (even a denial) creates a cache entry.
	c.authorize(fmt.Sprintf("user-%d", time.Now().UnixNano()), "read", "no-such-resource")

	ctx := context.Background()
	var cursor uint64
	seen := 0
	for {
		keys, next, err := e.redis.Scan(ctx, cursor, "sentinel:*", 100).Result()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			seen++
			if !strings.HasPrefix(k, "sentinel:v1:") {
				t.Errorf("key %q is not in the sentinel:v1: namespace", k)
			}
			if ttl, err := e.redis.TTL(ctx, k).Result(); err != nil || ttl <= 0 {
				t.Errorf("key %q has no TTL (ttl=%v err=%v)", k, ttl, err)
			}
		}
		if cursor = next; cursor == 0 {
			break
		}
	}
	if seen == 0 {
		t.Error("expected the authorize call to leave at least one sentinel key")
	}
}
