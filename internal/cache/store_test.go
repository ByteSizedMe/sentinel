package cache

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// stubStore is a minimal inner store. Embedding the interface (left nil) means
// any method the test does not override panics, so a test can never touch
// something by accident.
type stubStore struct {
	rbac.PolicyStore
	events *[]string // shared log of what happened, in order

	decision rbac.Decision
	checkErr error
	checks   int // how many times CheckPermission reached the "database"
	writeErr error
}

func (s *stubStore) log(e string) {
	if s.events != nil {
		*s.events = append(*s.events, e)
	}
}

func (s *stubStore) CheckPermission(context.Context, string, string, string) (rbac.Decision, error) {
	s.checks++
	if s.checkErr != nil {
		return rbac.Decision{}, s.checkErr
	}
	d := s.decision
	d.Source = rbac.SourceDB
	return d, nil
}

func (s *stubStore) write() error { s.log("write"); return s.writeErr }

func (s *stubStore) DeleteRole(context.Context, int64) error              { return s.write() }
func (s *stubStore) DeleteResource(context.Context, int64) error          { return s.write() }
func (s *stubStore) DeletePermission(context.Context, int64) error        { return s.write() }
func (s *stubStore) GrantPermission(context.Context, int64, int64) error  { return s.write() }
func (s *stubStore) RevokePermission(context.Context, int64, int64) error { return s.write() }
func (s *stubStore) AssignRole(context.Context, string, int64) error      { return s.write() }
func (s *stubStore) RemoveRole(context.Context, string, int64) error      { return s.write() }
func (s *stubStore) CreateRole(context.Context, string, string) (rbac.Role, error) {
	return rbac.Role{}, s.write()
}
func (s *stubStore) CreateResource(context.Context, string, string) (rbac.Resource, error) {
	return rbac.Resource{}, s.write()
}
func (s *stubStore) CreatePermission(context.Context, string, int64) (rbac.Permission, error) {
	return rbac.Permission{}, s.write()
}

// fakeClock is shared by the store and the in-memory cache so "time passes" for both.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// newTestStore wires CachedStore around a stub, with a shared fake clock.
func newTestStore(inner *stubStore, c Cache) (*CachedStore, *fakeClock) {
	clk := &fakeClock{t: time.Now()}
	if m, ok := c.(*Memory); ok {
		m.SetClock(clk.Now)
	}
	s := NewStore(inner, c, testTTL)
	s.now = clk.Now
	return s, clk
}

func check(t *testing.T, s *CachedStore, user string) rbac.Decision {
	t.Helper()
	d, err := s.CheckPermission(ctx, user, "read", "invoices")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	return d
}

func TestCacheAside(t *testing.T) {
	tests := []struct {
		name       string
		decision   rbac.Decision
		wantChecks int // database reads after three identical calls
	}{
		{"an allow is read once, then served from the cache", allowed, 1},
		{"a denial is read once, then served from the cache", denied, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := &stubStore{decision: tt.decision}
			s, _ := newTestStore(inner, NewMemory(testTTL))

			first := check(t, s, "u1")
			second := check(t, s, "u1")
			third := check(t, s, "u1")

			if first.Source != rbac.SourceDB || second.Source != rbac.SourceCache || third.Source != rbac.SourceCache {
				t.Errorf("sources = %s, %s, %s; want db, cache, cache", first.Source, second.Source, third.Source)
			}
			for _, d := range []rbac.Decision{first, second, third} {
				if d.Allowed != tt.decision.Allowed || d.MatchedRole != tt.decision.MatchedRole {
					t.Errorf("decision = %+v, want %+v", d, tt.decision)
				}
			}
			if inner.checks != tt.wantChecks {
				t.Errorf("database reads = %d, want %d", inner.checks, tt.wantChecks)
			}
		})
	}
}

func TestCachedEntryExpires(t *testing.T) {
	inner := &stubStore{decision: allowed}
	s, clk := newTestStore(inner, NewMemory(testTTL))

	check(t, s, "u1")
	clk.Advance(testTTL + time.Second)
	if d := check(t, s, "u1"); d.Source != rbac.SourceDB {
		t.Errorf("source after TTL = %s, want db", d.Source)
	}
	if inner.checks != 2 {
		t.Errorf("database reads = %d, want 2", inner.checks)
	}
}

func TestUsersDoNotShareEntries(t *testing.T) {
	inner := &stubStore{decision: allowed}
	s, _ := newTestStore(inner, NewMemory(testTTL))

	check(t, s, "u1") // caches an allow for u1
	inner.decision = denied
	if d := check(t, s, "u2"); d.Allowed || d.Source != rbac.SourceDB {
		t.Errorf("u2 got %+v; it must be read from the database and denied", d)
	}
}

func TestDatabaseErrorsAreNotCached(t *testing.T) {
	inner := &stubStore{checkErr: errors.New("db down")}
	s, _ := newTestStore(inner, NewMemory(testTTL))

	for i := 0; i < 2; i++ {
		d, err := s.CheckPermission(ctx, "u1", "read", "invoices")
		if err == nil || d.Allowed {
			t.Fatalf("call %d: decision = %+v, err = %v; want an error and no allow", i, d, err)
		}
	}
	if inner.checks != 2 {
		t.Errorf("database reads = %d, want 2 (a failure must not be cached)", inner.checks)
	}
}

// A broken cache must never change an answer, and must never allow.
func TestCacheErrorFallsBackToDatabase(t *testing.T) {
	tests := []struct {
		name      string
		decision  rbac.Decision
		breakWhen string // "always", or "set" (Get works, Set fails)
	}{
		{"cache down, user is allowed", allowed, "always"},
		{"cache down, user is denied", denied, "always"},
		{"only storing fails, user is denied", denied, "set"},
		{"only storing fails, user is allowed", allowed, "set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := &stubStore{decision: tt.decision}
			var c Cache = NewMemory(testTTL)
			if tt.breakWhen == "always" {
				c.(*Memory).Err = errors.New("redis: connection refused 10.0.0.9")
			} else {
				c = &setFailsCache{Cache: c}
			}
			s, _ := newTestStore(inner, c)

			d, err := s.CheckPermission(ctx, "u1", "read", "invoices")
			if err != nil {
				t.Fatalf("a cache problem must not become an error: %v", err)
			}
			if d.Allowed != tt.decision.Allowed {
				t.Errorf("allowed = %v, want %v (what the database said)", d.Allowed, tt.decision.Allowed)
			}
			if d.Source != rbac.SourceDB {
				t.Errorf("source = %s, want db", d.Source)
			}
		})
	}
}

// setFailsCache reads fine but cannot store.
type setFailsCache struct{ Cache }

func (setFailsCache) Set(context.Context, string, string, string, rbac.Decision, Generation) error {
	return errors.New("set failed")
}

// After a cache failure the store goes straight to the database for a while
// instead of hammering a dead Redis, then tries the cache again.
func TestCooldownAfterCacheFailure(t *testing.T) {
	inner := &stubStore{decision: allowed}
	mem := NewMemory(testTTL)
	mem.Err = errors.New("down")
	s, clk := newTestStore(inner, mem)

	check(t, s, "u1") // fails once, starts the cooldown
	mem.Err = nil     // Redis comes back...
	check(t, s, "u1") // ...but we are still cooling down: no caching yet
	if d := check(t, s, "u1"); d.Source != rbac.SourceDB {
		t.Errorf("served from cache during the cooldown (source %s)", d.Source)
	}

	clk.Advance(errorCooldown + time.Second)
	check(t, s, "u1") // cooldown over: reads Postgres and stores
	if d := check(t, s, "u1"); d.Source != rbac.SourceCache {
		t.Errorf("cache not used again after the cooldown (source %s)", d.Source)
	}
}

// failingInvalidate lets everything work except discarding entries.
type failingInvalidate struct{ Cache }

func (failingInvalidate) Invalidate(context.Context) error { return errors.New("redis down") }

// If we cannot invalidate, old entries could be served. The store must stop
// using the cache until every old entry has expired.
func TestFailedInvalidationBypassesCacheForOneTTL(t *testing.T) {
	inner := &stubStore{decision: allowed}
	mem := NewMemory(testTTL)
	s, clk := newTestStore(inner, failingInvalidate{mem})
	mem.SetClock(clk.Now) // the wrapper hides mem from newTestStore, so share the clock by hand

	check(t, s, "u1") // warm: allow is cached
	if d := check(t, s, "u1"); d.Source != rbac.SourceCache {
		t.Fatal("precondition: expected a cache hit")
	}

	inner.decision = denied // the revoke commits in the database...
	if err := s.RevokePermission(ctx, 1, 1); err != nil {
		t.Fatal(err)
	} // ...but the cache could not be told.

	if d := check(t, s, "u1"); d.Allowed || d.Source != rbac.SourceDB {
		t.Errorf("after a failed invalidation got %+v; want a fresh database denial", d)
	}

	clk.Advance(testTTL + time.Second) // every old entry has now expired
	if d := check(t, s, "u1"); d.Allowed {
		t.Errorf("stale allow served after the bypass ended: %+v", d)
	}
}

// ---- Invalidation: every write that can change a decision ----

// invalidating maps each method that must invalidate to a call of it.
var invalidating = map[string]func(*CachedStore) error{
	"DeleteRole":       func(s *CachedStore) error { return s.DeleteRole(ctx, 1) },
	"DeleteResource":   func(s *CachedStore) error { return s.DeleteResource(ctx, 1) },
	"DeletePermission": func(s *CachedStore) error { return s.DeletePermission(ctx, 1) },
	"GrantPermission":  func(s *CachedStore) error { return s.GrantPermission(ctx, 1, 1) },
	"RevokePermission": func(s *CachedStore) error { return s.RevokePermission(ctx, 1, 1) },
	"AssignRole":       func(s *CachedStore) error { return s.AssignRole(ctx, "u1", 1) },
	"RemoveRole":       func(s *CachedStore) error { return s.RemoveRole(ctx, "u1", 1) },
}

// orderedCache records "invalidate" in the same log as the stub's "write".
type orderedCache struct {
	Cache
	events *[]string
}

func (c orderedCache) Invalidate(ctx context.Context) error {
	*c.events = append(*c.events, "invalidate")
	return c.Cache.Invalidate(ctx)
}

func TestWritesInvalidateAfterTheDatabaseChange(t *testing.T) {
	for name, call := range invalidating {
		t.Run(name, func(t *testing.T) {
			var events []string
			inner := &stubStore{events: &events}
			s, _ := newTestStore(inner, orderedCache{Cache: NewMemory(testTTL), events: &events})

			if err := call(s); err != nil {
				t.Fatal(err)
			}
			if want := []string{"write", "invalidate"}; !reflect.DeepEqual(events, want) {
				t.Errorf("events = %v, want %v (invalidate only AFTER the write)", events, want)
			}
		})
	}
}

func TestInvalidationDependsOnTheOutcome(t *testing.T) {
	tests := []struct {
		name           string
		writeErr       error
		wantInvalidate bool
	}{
		{"success", nil, true},
		{"not found: nothing changed", rbac.ErrNotFound, false},
		{"conflict: nothing changed", rbac.ErrConflict, false},
		{"invalid input: nothing changed", rbac.ErrInvalidInput, false},
		{"unknown error: it may have committed, so invalidate", errors.New("connection reset"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := NewMemory(testTTL)
			s, _ := newTestStore(&stubStore{writeErr: tt.writeErr}, mem)

			err := s.GrantPermission(ctx, 1, 1)
			if !errors.Is(err, tt.writeErr) {
				t.Errorf("error = %v, want %v passed through", err, tt.writeErr)
			}
			if got := mem.Invalidations() == 1; got != tt.wantInvalidate {
				t.Errorf("invalidated = %v, want %v", got, tt.wantInvalidate)
			}
		})
	}
}

func TestCreatesDoNotInvalidate(t *testing.T) {
	mem := NewMemory(testTTL)
	s, _ := newTestStore(&stubStore{}, mem)

	_, _ = s.CreateRole(ctx, "r", "")
	_, _ = s.CreateResource(ctx, "r", "")
	_, _ = s.CreatePermission(ctx, "read", 1)
	if mem.Invalidations() != 0 {
		t.Error("creating a role, resource or permission cannot change a decision, so it must not flush the cache")
	}
}

// Fails when someone adds a method to rbac.PolicyStore without deciding what
// it means for the cache. (CachedStore itself already refuses to compile.)
func TestEveryStoreMethodIsClassified(t *testing.T) {
	classified := map[string]bool{
		"CheckPermission": true, // cached
		// writes that cannot change a decision
		"CreateRole": true, "CreateResource": true, "CreatePermission": true,
		// plain reads
		"GetRole": true, "ListRoles": true, "GetResource": true, "ListResources": true,
		"GetPermission": true, "ListPermissions": true, "ListRolePermissions": true, "ListUserRoles": true,
	}
	for name := range invalidating {
		classified[name] = true
	}

	iface := reflect.TypeOf((*rbac.PolicyStore)(nil)).Elem()
	var unclassified []string
	for i := 0; i < iface.NumMethod(); i++ {
		if name := iface.Method(i).Name; !classified[name] {
			unclassified = append(unclassified, name)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("PolicyStore methods with no cache classification: %v", unclassified)
	}
}
