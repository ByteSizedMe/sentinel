package audit

import (
	"context"
	"sync"
)

// Memory is an in-memory Logger for tests. Set Err to make Record fail.
type Memory struct {
	mu      sync.Mutex
	entries []Entry
	Err     error
}

var _ Logger = (*Memory)(nil)

// Record stores the entry, or returns Err (and stores nothing) if it is set.
func (m *Memory) Record(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	m.entries = append(m.entries, e)
	return nil
}

// Entries returns a copy of everything recorded so far.
func (m *Memory) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Entry(nil), m.entries...)
}
