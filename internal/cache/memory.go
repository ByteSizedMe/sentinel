package cache

import (
	"context"
	"sync"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// Memory is an in-memory Cache for tests. It follows the same rules as the
// Redis one: TTL expiry, generation stamps, one key per (user, action, resource).
// Set Err to make every call fail, like an unreachable Redis.
type Memory struct {
	Err error // when non-nil, Get, Set and Invalidate all return it

	mu            sync.Mutex
	ttl           time.Duration
	now           func() time.Time
	gen           Generation
	entries       map[string]memEntry
	invalidations int
}

type memEntry struct {
	decision rbac.Decision
	gen      Generation
	expires  time.Time
}

var _ Cache = (*Memory)(nil)

// NewMemory returns an empty cache whose entries live for ttl. Tests can
// replace the clock with SetClock to test expiry without sleeping.
func NewMemory(ttl time.Duration) *Memory {
	return &Memory{ttl: ttl, now: time.Now, gen: 1, entries: map[string]memEntry{}}
}

// SetClock replaces the time source (tests only).
func (m *Memory) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// Invalidations reports how many times Invalidate succeeded (tests only).
func (m *Memory) Invalidations() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invalidations
}

func (m *Memory) Get(_ context.Context, userID, action, resource string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return Result{}, m.Err
	}
	e, ok := m.entries[decisionKey(userID, action, resource)]
	if !ok || e.gen != m.gen || !m.now().Before(e.expires) {
		return Result{Gen: m.gen}, nil
	}
	return Result{Hit: true, Decision: e.decision, Gen: m.gen}, nil
}

func (m *Memory) Set(_ context.Context, userID, action, resource string, d rbac.Decision, gen Generation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.entries[decisionKey(userID, action, resource)] = memEntry{
		decision: rbac.Decision{Allowed: d.Allowed, MatchedRole: d.MatchedRole}, // never keep Source
		gen:      gen,
		expires:  m.now().Add(m.ttl),
	}
	return nil
}

func (m *Memory) Invalidate(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.gen++
	m.invalidations++
	return nil
}
