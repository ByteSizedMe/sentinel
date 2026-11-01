// Package ratelimit is a small in-process token-bucket rate limiter keyed by
// string (an IP address, a caller name, ...).
//
// Each key owns a bucket that holds up to Burst tokens and refills at Rate
// tokens per second. A call spends one token; with none left the call is
// refused and the limiter says how long to wait.
//
// Memory is bounded: at most MaxKeys buckets are kept, and the least recently
// seen key is evicted to make room. Cleanup happens lazily inside normal calls,
// so there is no background goroutine to leak or shut down.
//
// The state lives in this process only. With several instances each one has its
// own counters, so the effective limit is multiplied by the instance count.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// defaultSweepEvery is how many calls pass between sweeps of idle keys.
const defaultSweepEvery = 1024

// Config describes one limiter.
type Config struct {
	Rate       float64          // tokens added per second; zero or less disables the limiter
	Burst      int              // bucket size; the number of calls allowed at once (at least 1)
	MaxKeys    int              // most keys tracked at once (at least 1)
	Now        func() time.Time // clock; nil means time.Now. Tests inject a fake one.
	SweepEvery int              // calls between idle-key sweeps; zero means 1024
}

// bucket is one key's state. elem is its place in the recency list.
type bucket struct {
	key    string
	tokens float64
	last   time.Time // when tokens was last brought up to date
	elem   *list.Element
}

// Limiter is a set of token buckets. The zero value and a nil *Limiter both
// allow everything. Safe for concurrent use.
type Limiter struct {
	rate       float64
	burst      float64
	maxKeys    int
	now        func() time.Time
	sweepEvery int
	idleAfter  time.Duration // a bucket unused this long is full again, so it can be dropped

	mu      sync.Mutex
	buckets map[string]*bucket
	recent  *list.List // front = most recently seen, back = least
	calls   int
}

// New builds a Limiter. Out-of-range values are clamped rather than rejected
// (the caller validates user input; see internal/config).
func New(cfg Config) *Limiter {
	l := &Limiter{
		rate:       cfg.Rate,
		burst:      float64(max(cfg.Burst, 1)),
		maxKeys:    max(cfg.MaxKeys, 1),
		now:        cfg.Now,
		sweepEvery: cfg.SweepEvery,
		buckets:    map[string]*bucket{},
		recent:     list.New(),
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.sweepEvery <= 0 {
		l.sweepEvery = defaultSweepEvery
	}
	if l.rate > 0 {
		l.idleAfter = time.Duration(math.Ceil(l.burst / l.rate * float64(time.Second)))
	}
	return l
}

// Enabled reports whether the limiter ever refuses a call.
func (l *Limiter) Enabled() bool { return l != nil && l.rate > 0 }

// Len is the number of keys currently tracked (for tests and monitoring).
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Allow spends one token for key. It returns true if the call may go ahead.
// If not, retryAfter is how long until a token is available.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if !l.Enabled() {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.calls++
	if l.calls%l.sweepEvery == 0 {
		l.sweep(now)
	}

	b := l.buckets[key]
	if b == nil {
		// A new key starts with a full bucket. Make room first if we are at the cap.
		for len(l.buckets) >= l.maxKeys {
			l.evictOldest()
		}
		b = &bucket{key: key, tokens: l.burst, last: now}
		b.elem = l.recent.PushFront(b)
		l.buckets[key] = b
	} else {
		l.recent.MoveToFront(b.elem)
		// Refill for the time that has passed. A clock that went backwards adds
		// nothing and does not move last backwards.
		if elapsed := now.Sub(b.last); elapsed > 0 {
			b.tokens = math.Min(l.burst, b.tokens+elapsed.Seconds()*l.rate)
			b.last = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := (1 - b.tokens) / l.rate // seconds until one whole token exists
	return false, time.Duration(math.Ceil(wait * float64(time.Second)))
}

// evictOldest drops the least recently seen key. The caller holds l.mu.
func (l *Limiter) evictOldest() {
	back := l.recent.Back()
	if back == nil {
		return
	}
	l.remove(back.Value.(*bucket))
}

// sweep drops keys idle long enough to be back at a full bucket: forgetting
// them changes nothing, because a new bucket starts full too. It walks from the
// least recently seen end and stops at the first key that is still active.
// The caller holds l.mu.
func (l *Limiter) sweep(now time.Time) {
	for e := l.recent.Back(); e != nil; e = l.recent.Back() {
		b := e.Value.(*bucket)
		if now.Sub(b.last) < l.idleAfter {
			return
		}
		l.remove(b)
	}
}

func (l *Limiter) remove(b *bucket) {
	l.recent.Remove(b.elem)
	delete(l.buckets, b.key)
}
