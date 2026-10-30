package cache

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// errorCooldown is how long we skip the cache after it fails, so a dead Redis
// costs one slow call, not one per request.
const errorCooldown = 5 * time.Second

// invalidateTimeout bounds the cache bump that follows a database write.
const invalidateTimeout = time.Second

// CachedStore is a rbac.PolicyStore that puts a cache in front of
// CheckPermission and discards the cache whenever policy changes.
//
// Every PolicyStore method is written out below on purpose (no embedding).
// If someone adds a method to the interface, this file stops compiling until
// they decide what it does to the cache, and TestEveryStoreMethodIsClassified
// checks the decision is recorded. That is how "a write path forgot to
// invalidate" is made hard to do.
//
// SAFETY RULES
//   - The cache is only ever an optimisation. Any cache error falls through to
//     the inner store, so a cache problem can never produce an allow.
//   - A decision read from the cache is only trusted if its generation matches
//     (see package doc), and only Postgres answers are ever stored.
//   - Invalidation happens AFTER the database write has returned, i.e. after
//     it committed, never before.
//   - If invalidation itself fails, stale entries could still be served, so the
//     cache is bypassed for one TTL (long enough for every entry to expire).
type CachedStore struct {
	inner rbac.PolicyStore
	cache Cache
	ttl   time.Duration
	now   func() time.Time

	mu          sync.Mutex
	bypassUntil time.Time // cache is skipped until this time
}

var _ rbac.PolicyStore = (*CachedStore)(nil)

// NewStore wraps inner. ttl must match the TTL the cache uses for entries.
func NewStore(inner rbac.PolicyStore, c Cache, ttl time.Duration) *CachedStore {
	return &CachedStore{inner: inner, cache: c, ttl: ttl, now: time.Now}
}

// CheckPermission is cache-aside: look in the cache, on a miss ask the inner
// store and remember the answer.
func (s *CachedStore) CheckPermission(ctx context.Context, userID, action, resource string) (rbac.Decision, error) {
	if s.bypassed() {
		return s.inner.CheckPermission(ctx, userID, action, resource)
	}

	// The lookup also tells us the current generation. We read it BEFORE
	// asking Postgres, so if policy changes meanwhile, the entry we store is
	// stamped with an out-of-date generation and will never be served.
	res, err := s.cache.Get(ctx, userID, action, resource)
	if err != nil {
		s.bypassFor(errorCooldown, "lookup")
		return s.inner.CheckPermission(ctx, userID, action, resource)
	}
	if res.Hit {
		d := res.Decision
		d.Source = rbac.SourceCache
		return d, nil
	}

	d, err := s.inner.CheckPermission(ctx, userID, action, resource)
	if err != nil {
		return rbac.Decision{}, err // never cache a failure
	}
	// Re-check: another request may have started a bypass while we waited on Postgres.
	if !s.bypassed() {
		if err := s.cache.Set(ctx, userID, action, resource, d, res.Gen); err != nil {
			s.bypassFor(errorCooldown, "store")
		}
	}
	return d, nil
}

// invalidate is the ONE place cached decisions are discarded. Every method
// that can change an answer calls it, with the error from the database write.
func (s *CachedStore) invalidate(ctx context.Context, writeErr error) {
	if !mayHaveChanged(writeErr) {
		return
	}
	// The write has already happened, so finish the bump even if the client
	// disconnected (WithoutCancel keeps the values but drops the cancellation).
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), invalidateTimeout)
	defer cancel()
	if err := s.cache.Invalidate(ictx); err != nil {
		s.bypassFor(s.ttl, "invalidate")
	}
}

// mayHaveChanged is false only when the database clearly did nothing (not
// found, duplicate, bad input). An unknown error is ambiguous: the write may
// have committed before the connection broke, so we invalidate to be safe.
func mayHaveChanged(err error) bool {
	return !(errors.Is(err, rbac.ErrNotFound) || errors.Is(err, rbac.ErrConflict) || errors.Is(err, rbac.ErrInvalidInput))
}

func (s *CachedStore) bypassed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Before(s.bypassUntil)
}

// bypassFor skips the cache for d. It logs once when a bypass starts, and the
// message names only the operation: no keys, users or error details.
func (s *CachedStore) bypassFor(d time.Duration, op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if until := now.Add(d); until.After(s.bypassUntil) {
		if !now.Before(s.bypassUntil) {
			log.Printf("cache: %s failed; using the database only for %s", op, d)
		}
		s.bypassUntil = until
	}
}

// ---- Writes that can change a decision: each one invalidates. ----

func (s *CachedStore) DeleteRole(ctx context.Context, id int64) error {
	err := s.inner.DeleteRole(ctx, id)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) DeleteResource(ctx context.Context, id int64) error {
	err := s.inner.DeleteResource(ctx, id)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) DeletePermission(ctx context.Context, id int64) error {
	err := s.inner.DeletePermission(ctx, id)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) GrantPermission(ctx context.Context, roleID, permissionID int64) error {
	err := s.inner.GrantPermission(ctx, roleID, permissionID)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) RevokePermission(ctx context.Context, roleID, permissionID int64) error {
	err := s.inner.RevokePermission(ctx, roleID, permissionID)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) AssignRole(ctx context.Context, userID string, roleID int64) error {
	err := s.inner.AssignRole(ctx, userID, roleID)
	s.invalidate(ctx, err)
	return err
}

func (s *CachedStore) RemoveRole(ctx context.Context, userID string, roleID int64) error {
	err := s.inner.RemoveRole(ctx, userID, roleID)
	s.invalidate(ctx, err)
	return err
}

// ---- Writes that cannot change any decision: a new role, resource or
// permission has no grants or assignments yet. No invalidation needed. ----

func (s *CachedStore) CreateRole(ctx context.Context, name, description string) (rbac.Role, error) {
	return s.inner.CreateRole(ctx, name, description)
}

func (s *CachedStore) CreateResource(ctx context.Context, name, description string) (rbac.Resource, error) {
	return s.inner.CreateResource(ctx, name, description)
}

func (s *CachedStore) CreatePermission(ctx context.Context, action string, resourceID int64) (rbac.Permission, error) {
	return s.inner.CreatePermission(ctx, action, resourceID)
}

// ---- Reads: straight through. ----

func (s *CachedStore) GetRole(ctx context.Context, id int64) (rbac.Role, error) {
	return s.inner.GetRole(ctx, id)
}

func (s *CachedStore) ListRoles(ctx context.Context) ([]rbac.Role, error) {
	return s.inner.ListRoles(ctx)
}

func (s *CachedStore) GetResource(ctx context.Context, id int64) (rbac.Resource, error) {
	return s.inner.GetResource(ctx, id)
}

func (s *CachedStore) ListResources(ctx context.Context) ([]rbac.Resource, error) {
	return s.inner.ListResources(ctx)
}

func (s *CachedStore) GetPermission(ctx context.Context, id int64) (rbac.Permission, error) {
	return s.inner.GetPermission(ctx, id)
}

func (s *CachedStore) ListPermissions(ctx context.Context) ([]rbac.Permission, error) {
	return s.inner.ListPermissions(ctx)
}

func (s *CachedStore) ListRolePermissions(ctx context.Context, roleID int64) ([]rbac.Permission, error) {
	return s.inner.ListRolePermissions(ctx, roleID)
}

func (s *CachedStore) ListUserRoles(ctx context.Context, userID string) ([]rbac.Role, error) {
	return s.inner.ListUserRoles(ctx, userID)
}
