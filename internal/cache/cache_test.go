package cache

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/redis/go-redis/v9"
)

const testTTL = 60 * time.Second

// harness lets the same test run against every Cache implementation.
type harness struct {
	name    string
	c       Cache
	advance func(time.Duration) // move time forward (entries expire)
	fail    func()              // make every later call fail, like Redis going down
}

// implementations are the Cache types every contract test runs against.
var implementations = []string{"memory", "redis"}

// newHarness builds a fresh instance. The Redis one talks to an in-process
// Redis server (miniredis), so no Docker is needed.
func newHarness(t *testing.T, impl string) harness {
	t.Helper()

	if impl == "memory" {
		mem := NewMemory(testTTL)
		now := time.Now()
		mem.SetClock(func() time.Time { return now })
		return harness{
			name:    impl,
			c:       mem,
			advance: func(d time.Duration) { now = now.Add(d) },
			fail:    func() { mem.Err = errors.New("cache down") },
		}
	}

	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr(), MaxRetries: -1, DialTimeout: time.Second})
	t.Cleanup(func() { _ = client.Close() })
	return harness{
		name:    impl,
		c:       NewRedis(client, testTTL),
		advance: srv.FastForward,
		fail:    srv.Close,
	}
}

var (
	ctx     = context.Background()
	allowed = rbac.Decision{Allowed: true, MatchedRole: "editor"}
	denied  = rbac.Decision{Allowed: false}
)

// get is a test shortcut that fails the test on a cache error.
func get(t *testing.T, c Cache, user, action, resource string) Result {
	t.Helper()
	r, err := c.Get(ctx, user, action, resource)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return r
}

// store does Get (to learn the generation) then Set, as CachedStore does.
func store(t *testing.T, c Cache, user, action, resource string, d rbac.Decision) {
	t.Helper()
	r := get(t, c, user, action, resource)
	if err := c.Set(ctx, user, action, resource, d, r.Gen); err != nil {
		t.Fatalf("Set: %v", err)
	}
}

func TestCacheContract(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, h harness)
	}{
		{"miss on an empty cache", func(t *testing.T, h harness) {
			r := get(t, h.c, "u1", "read", "invoices")
			if r.Hit {
				t.Error("unexpected hit")
			}
			if r.Gen == 0 {
				t.Error("a miss must still report the generation")
			}
		}},
		{"hit after set returns the stored decision", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			r := get(t, h.c, "u1", "read", "invoices")
			if !r.Hit || r.Decision != allowed {
				t.Errorf("result = %+v, want a hit with %+v", r, allowed)
			}
		}},
		{"denials are cached too", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", denied)
			r := get(t, h.c, "u1", "read", "invoices")
			if !r.Hit || r.Decision.Allowed {
				t.Errorf("result = %+v, want a cached denial", r)
			}
		}},
		{"still a hit just before the TTL", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			h.advance(testTTL - time.Second)
			if !get(t, h.c, "u1", "read", "invoices").Hit {
				t.Error("entry expired too early")
			}
		}},
		{"miss after the TTL", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			h.advance(testTTL + time.Second)
			if get(t, h.c, "u1", "read", "invoices").Hit {
				t.Error("entry survived past its TTL")
			}
		}},
		{"invalidate makes every entry a miss", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			store(t, h.c, "u2", "write", "reports", allowed)
			before := get(t, h.c, "u1", "read", "invoices").Gen

			if err := h.c.Invalidate(ctx); err != nil {
				t.Fatal(err)
			}
			for _, k := range [][3]string{{"u1", "read", "invoices"}, {"u2", "write", "reports"}} {
				r := get(t, h.c, k[0], k[1], k[2])
				if r.Hit {
					t.Errorf("%v still served after Invalidate", k)
				}
				if r.Gen == before {
					t.Error("generation did not change")
				}
			}
		}},
		{"an entry stamped with an old generation is never served", func(t *testing.T, h harness) {
			// A slow request: it learned the generation, then policy changed
			// while it was still reading Postgres, then it tried to store.
			stale := get(t, h.c, "u1", "read", "invoices").Gen
			if err := h.c.Invalidate(ctx); err != nil {
				t.Fatal(err)
			}
			if err := h.c.Set(ctx, "u1", "read", "invoices", allowed, stale); err != nil {
				t.Fatal(err)
			}
			if get(t, h.c, "u1", "read", "invoices").Hit {
				t.Error("stale entry was served: a revoked permission could come back")
			}
		}},
		{"entries are per user", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			if get(t, h.c, "u2", "read", "invoices").Hit {
				t.Error("u2 was served u1's entry")
			}
		}},
		{"entries are per action and per resource", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			if get(t, h.c, "u1", "write", "invoices").Hit || get(t, h.c, "u1", "read", "reports").Hit {
				t.Error("an entry answered a different action or resource")
			}
		}},
		{"fields that run together cannot collide", func(t *testing.T, h harness) {
			// Naive "user:action:resource" keys would make all of these equal.
			store(t, h.c, "a:b", "c", "d", allowed)
			for _, k := range [][3]string{{"a", "b:c", "d"}, {"a", "b", "c:d"}, {"a:b:c", "", "d"}} {
				if get(t, h.c, k[0], k[1], k[2]).Hit {
					t.Errorf("key collision with %v", k)
				}
			}
		}},
		{"the source label is never stored", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", rbac.Decision{Allowed: true, MatchedRole: "editor", Source: rbac.SourceDB})
			if got := get(t, h.c, "u1", "read", "invoices").Decision.Source; got != "" {
				t.Errorf("stored Source = %q, want empty (the caller sets it)", got)
			}
		}},
		{"a failing cache reports errors", func(t *testing.T, h harness) {
			store(t, h.c, "u1", "read", "invoices", allowed)
			h.fail()
			if _, err := h.c.Get(ctx, "u1", "read", "invoices"); err == nil {
				t.Error("Get: expected an error")
			}
			if err := h.c.Set(ctx, "u1", "read", "invoices", allowed, 1); err == nil {
				t.Error("Set: expected an error")
			}
			if err := h.c.Invalidate(ctx); err == nil {
				t.Error("Invalidate: expected an error")
			}
		}},
	}

	for _, impl := range implementations {
		for _, tt := range tests {
			t.Run(impl+"/"+tt.name, func(t *testing.T) {
				tt.run(t, newHarness(t, impl)) // fresh instance: cases never depend on each other
			})
		}
	}
}

// ---- Redis-specific behaviour ----

func newRedisForTest(t *testing.T) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedis(client, testTTL), srv
}

// Everything we write must be namespaced and must expire.
func TestRedisKeysAreNamespacedWithTTL(t *testing.T) {
	r, srv := newRedisForTest(t)
	store(t, r, "u1", "read", "invoices", allowed)
	store(t, r, "u2", "read", "invoices", denied)
	if err := r.Invalidate(ctx); err != nil {
		t.Fatal(err)
	}

	keys := srv.Keys()
	if len(keys) < 3 {
		t.Fatalf("keys = %v, expected two decisions and the generation", keys)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "sentinel:v1:") {
			t.Errorf("key %q is not namespaced", k)
		}
		if srv.TTL(k) <= 0 {
			t.Errorf("key %q has no TTL", k)
		}
		if strings.Contains(k, "u1") || strings.Contains(k, "invoices") {
			t.Errorf("key %q reveals request data", k)
		}
	}
}

func TestRedisCorruptEntryIsAMiss(t *testing.T) {
	r, srv := newRedisForTest(t)
	store(t, r, "u1", "read", "invoices", allowed)
	srv.Set(decisionKey("u1", "read", "invoices"), "{not json")
	if get(t, r, "u1", "read", "invoices").Hit {
		t.Error("a corrupt entry was treated as a hit")
	}
}

// If the generation key disappears (expiry, flush), old entries must not
// become valid again under a recycled number.
func TestRedisLostGenerationDoesNotRevive(t *testing.T) {
	r, srv := newRedisForTest(t)
	store(t, r, "u1", "read", "invoices", allowed)
	old := get(t, r, "u1", "read", "invoices").Gen

	srv.Del(genKey)
	r.now = func() time.Time { return time.Now().Add(time.Hour) } // time only moves forward

	res := get(t, r, "u1", "read", "invoices")
	if res.Hit {
		t.Error("an entry was revived after the generation key vanished")
	}
	if res.Gen == old {
		t.Error("new generation equals the old one")
	}
}

func TestRedisGenerationExpiryStartsNewEpoch(t *testing.T) {
	r, srv := newRedisForTest(t)
	store(t, r, "u1", "read", "invoices", allowed)
	srv.FastForward(genTTL + time.Second) // generation and entries all expire
	if get(t, r, "u1", "read", "invoices").Hit {
		t.Error("hit after everything expired")
	}
	store(t, r, "u1", "read", "invoices", allowed) // and it works again
	if !get(t, r, "u1", "read", "invoices").Hit {
		t.Error("cache did not recover after the generation expired")
	}
}
