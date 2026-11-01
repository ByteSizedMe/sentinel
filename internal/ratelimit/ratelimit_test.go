package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a clock the test moves by hand, so nothing ever sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// step is one call to Allow after moving the clock forward by `after`.
type step struct {
	after     time.Duration
	key       string
	wantOK    bool
	wantRetry time.Duration // only checked when wantOK is false
}

func TestAllow(t *testing.T) {
	const sec = time.Second
	tests := []struct {
		name  string
		cfg   Config
		steps []step
	}{
		{"burst is allowed, then denied", Config{Rate: 1, Burst: 3, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", true, 0}, {0, "a", true, 0},
			{0, "a", false, sec},
		}},
		{"a burst of one", Config{Rate: 1, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", false, sec},
		}},
		{"refill over time", Config{Rate: 1, Burst: 2, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", true, 0}, {0, "a", false, sec},
			{sec, "a", true, 0},
			{0, "a", false, sec},
		}},
		{"retry-after shrinks as time passes", Config{Rate: 2, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0},
			{0, "a", false, 500 * time.Millisecond},
			{250 * time.Millisecond, "a", false, 250 * time.Millisecond},
			{250 * time.Millisecond, "a", true, 0},
		}},
		{"slow rate gives a long retry-after", Config{Rate: 0.5, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", false, 2 * sec},
		}},
		{"refill never goes above the burst", Config{Rate: 1, Burst: 2, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", true, 0},
			{time.Hour, "a", true, 0}, {0, "a", true, 0}, {0, "a", false, sec},
		}},
		{"keys are independent", Config{Rate: 1, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", false, sec},
			{0, "b", true, 0}, {0, "b", false, sec},
			{0, "a", false, sec},
		}},
		{"a partial token is not enough", Config{Rate: 1, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {900 * time.Millisecond, "a", false, 100 * time.Millisecond},
		}},
		{"zero rate disables the limiter", Config{Rate: 0, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", true, 0}, {0, "a", true, 0},
		}},
		{"negative rate disables the limiter", Config{Rate: -1, Burst: 1, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", true, 0},
		}},
		{"burst below one is clamped to one", Config{Rate: 1, Burst: 0, MaxKeys: 10}, []step{
			{0, "a", true, 0}, {0, "a", false, sec},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			tt.cfg.Now = clock.Now
			l := New(tt.cfg)
			for i, s := range tt.steps {
				clock.Advance(s.after)
				ok, retry := l.Allow(s.key)
				if ok != s.wantOK {
					t.Fatalf("step %d (%q): allowed = %v, want %v", i+1, s.key, ok, s.wantOK)
				}
				if !ok && retry != s.wantRetry {
					t.Errorf("step %d (%q): retryAfter = %v, want %v", i+1, s.key, retry, s.wantRetry)
				}
				if ok && retry != 0 {
					t.Errorf("step %d (%q): retryAfter = %v on an allowed call, want 0", i+1, s.key, retry)
				}
			}
		})
	}
}

func TestDisabledLimiters(t *testing.T) {
	var nilLimiter *Limiter
	tests := []struct {
		name string
		l    *Limiter
	}{
		{"nil limiter", nilLimiter},
		{"zero value", &Limiter{}},
		{"rate zero", New(Config{Rate: 0, Burst: 1, MaxKeys: 10})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.l.Enabled() {
				t.Error("Enabled() = true, want false")
			}
			for i := 0; i < 100; i++ {
				if ok, retry := tt.l.Allow("a"); !ok || retry != 0 {
					t.Fatalf("call %d: ok=%v retry=%v, want true, 0", i, ok, retry)
				}
			}
			if n := tt.l.Len(); n != 0 {
				t.Errorf("Len = %d, want 0 (a disabled limiter tracks nothing)", n)
			}
		})
	}
}

func TestClockGoingBackwardsAddsNoTokens(t *testing.T) {
	clock := newClock()
	l := New(Config{Rate: 1, Burst: 1, MaxKeys: 10, Now: clock.Now})
	l.Allow("a") // drains the bucket
	clock.Advance(-time.Hour)
	if ok, _ := l.Allow("a"); ok {
		t.Error("allowed after the clock moved backwards, want denied")
	}
}

func TestEvictionKeepsTheCap(t *testing.T) {
	clock := newClock()
	l := New(Config{Rate: 1, Burst: 1, MaxKeys: 3, Now: clock.Now})
	for i := 0; i < 1000; i++ {
		l.Allow(string(rune('a' + i%26)))
		l.Allow("key-" + string(rune('0'+i%10)) + string(rune('a'+i/10%26)))
		if n := l.Len(); n > 3 {
			t.Fatalf("after %d calls Len = %d, want at most 3", i+1, n)
		}
	}
}

// The key evicted is the one seen least recently, not the oldest created.
func TestEvictionDropsTheLeastRecentlySeen(t *testing.T) {
	clock := newClock()
	l := New(Config{Rate: 1, Burst: 1, MaxKeys: 3, Now: clock.Now})

	steps := []step{
		{0, "a", true, 0}, {0, "b", true, 0}, {0, "c", true, 0}, // recency, newest first: c b a
		{0, "a", false, time.Second}, // touching a (now drained) makes order: a c b
		{0, "d", true, 0},            // new key at the cap: b is evicted. Order: d a c
		{0, "b", true, 0},            // b starts fresh (full bucket). Evicts c. Order: b d a
		{0, "a", false, time.Second}, // a was kept, so it is still drained
	}
	for i, s := range steps {
		ok, retry := l.Allow(s.key)
		if ok != s.wantOK || (!ok && retry != s.wantRetry) {
			t.Fatalf("step %d (%q): ok=%v retry=%v, want ok=%v retry=%v", i+1, s.key, ok, retry, s.wantOK, s.wantRetry)
		}
	}
	if n := l.Len(); n != 3 {
		t.Errorf("Len = %d, want 3", n)
	}
}

func TestIdleSweep(t *testing.T) {
	tests := []struct {
		name       string
		sweepEvery int
		run        func(l *Limiter, c *fakeClock)
		want       int // keys left after the run
	}{
		{"all idle keys are dropped", 4, func(l *Limiter, c *fakeClock) {
			l.Allow("k1")
			l.Allow("k2")
			l.Allow("k3")
			c.Advance(10 * time.Second) // idleAfter is 2s, so all three are idle
			l.Allow("k4")               // 4th call: the sweep runs first, then k4 is added
		}, 1},
		{"the sweep stops at the first active key", 3, func(l *Limiter, c *fakeClock) {
			l.Allow("k1")
			c.Advance(1500 * time.Millisecond)
			l.Allow("k2")
			c.Advance(1000 * time.Millisecond) // k1 idle 2.5s (dropped), k2 idle 1s (kept)
			l.Allow("k3")                      // 3rd call: sweep
		}, 2},
		{"no sweep before the interval", 4, func(l *Limiter, c *fakeClock) {
			l.Allow("k1")
			c.Advance(10 * time.Second)
			l.Allow("k2") // only the 2nd call, interval is 4
		}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			// rate 1, burst 2: a bucket is full again after 2 seconds of silence.
			l := New(Config{Rate: 1, Burst: 2, MaxKeys: 100, Now: clock.Now, SweepEvery: tt.sweepEvery})
			tt.run(l, clock)
			if got := l.Len(); got != tt.want {
				t.Errorf("Len = %d, want %d", got, tt.want)
			}
		})
	}
}

// Dropping an idle key must not change any decision: it would be full anyway.
func TestSweepDoesNotChangeDecisions(t *testing.T) {
	clock := newClock()
	l := New(Config{Rate: 1, Burst: 2, MaxKeys: 100, Now: clock.Now, SweepEvery: 1})
	l.Allow("a")
	l.Allow("a") // drained
	clock.Advance(2 * time.Second)
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("call %d after the idle period was denied, want allowed", i+1)
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Error("third call after the idle period was allowed, want denied (burst is 2)")
	}
}

func TestNewClampsBadConfig(t *testing.T) {
	l := New(Config{Rate: 1, Burst: -5, MaxKeys: -5})
	if !l.Enabled() {
		t.Fatal("limiter should be enabled")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Error("first call denied, want allowed (burst clamped to 1)")
	}
	l.Allow("b")
	if n := l.Len(); n != 1 {
		t.Errorf("Len = %d, want 1 (MaxKeys clamped to 1)", n)
	}
}

// With a frozen clock nothing refills, so across any number of goroutines the
// number of allowed calls must be exactly the burst, per key.
func TestConcurrentFrozenClock(t *testing.T) {
	const (
		burst      = 50
		goroutines = 64
		perG       = 100
	)
	clock := newClock()

	tests := []struct {
		name string
		keys func(g int) string
		want int64
	}{
		{"one shared key", func(int) string { return "shared" }, burst},
		{"a key per goroutine", func(g int) string { return "key-" + string(rune('A'+g)) }, burst * goroutines},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(Config{Rate: 1, Burst: burst, MaxKeys: 1000, Now: clock.Now})
			var allowed atomic.Int64
			var wg sync.WaitGroup
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < perG; i++ {
						if ok, _ := l.Allow(tt.keys(g)); ok {
							allowed.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			if got := allowed.Load(); got != tt.want {
				t.Errorf("allowed = %d, want exactly %d", got, tt.want)
			}
		})
	}
}

// With the real clock tokens do refill while the goroutines run, so the bound
// is burst plus what the elapsed time could have refilled. No sleeping: the
// loop just runs as fast as it can. Run with -race in CI.
func TestConcurrentRealClock(t *testing.T) {
	const (
		rate       = 100.0
		burst      = 20
		goroutines = 32
		perG       = 500
	)
	l := New(Config{Rate: rate, Burst: burst, MaxKeys: 10})

	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if ok, _ := l.Allow("shared"); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// +1 for rounding at the edges of the measured window.
	limit := int64(burst) + int64(elapsed.Seconds()*rate) + 1
	if got := allowed.Load(); got > limit {
		t.Errorf("allowed %d calls in %v, more than the limit of %d", got, elapsed, limit)
	}
	if got := allowed.Load(); got < burst {
		t.Errorf("allowed %d calls, fewer than the burst of %d", got, burst)
	}
}

// Many goroutines on many keys, with a tiny cap so eviction and sweeping run
// constantly while others read and write. The point is the race detector and
// the cap, not the counts.
func TestConcurrentEvictionStaysBounded(t *testing.T) {
	l := New(Config{Rate: 1000, Burst: 2, MaxKeys: 8, SweepEvery: 3})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				l.Allow(string(rune('a' + (g*7+i)%40)))
				if n := l.Len(); n > 8 {
					t.Errorf("Len = %d, want at most 8", n)
					return
				}
			}
		}()
	}
	wg.Wait()
}
