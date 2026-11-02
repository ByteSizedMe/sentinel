package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/clientip"
	"github.com/bytesizedme/sentinel/internal/ratelimit"
)

// limitClock is a clock moved by hand, so no test sleeps.
type limitClock struct {
	mu sync.Mutex
	t  time.Time
}

func newLimitClock() *limitClock {
	return &limitClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *limitClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *limitClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// bucketCfg is a limiter setting; the zero value means "limiter off".
type bucketCfg struct {
	rate  float64
	burst int
}

// limited is a real router with limiters built from the given settings, plus
// the pieces tests look at.
type limited struct {
	h      http.Handler
	clock  *limitClock
	limits Limits
}

const defaultAddr = "192.0.2.1:4000"

func newLimited(t *testing.T, ip, caller bucketCfg) *limited {
	t.Helper()
	return newLimitedBehind(t, ip, caller, nil)
}

// newLimitedBehind is newLimited with a set of trusted proxies.
func newLimitedBehind(t *testing.T, ip, caller bucketCfg, proxies *clientip.Trusted) *limited {
	t.Helper()
	clk := newLimitClock()
	mk := func(c bucketCfg) *ratelimit.Limiter {
		return ratelimit.New(ratelimit.Config{Rate: c.rate, Burst: c.burst, MaxKeys: 1000, Now: clk.Now})
	}
	v, err := auth.NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	l := Limits{IP: mk(ip), Caller: mk(caller), Proxies: proxies}
	return &limited{h: newRouter(newFakeStore(), &audit.Memory{}, v, l, clk.Now), clock: clk, limits: l}
}

// req describes one request to the limited router.
type req struct {
	method, path string
	token        string            // bearer token; "" sends none
	addr         string            // RemoteAddr; "" uses defaultAddr
	headers      map[string]string // extra headers
}

func (l *limited) do(r req) *httptest.ResponseRecorder {
	if r.method == "" {
		r.method = http.MethodGet
	}
	if r.path == "" {
		r.path = "/v1/roles"
	}
	hr := httptest.NewRequest(r.method, r.path, nil)
	hr.RemoteAddr = defaultAddr
	if r.addr != "" {
		hr.RemoteAddr = r.addr
	}
	if r.token != "" {
		hr.Header.Set("Authorization", "Bearer "+r.token)
	}
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	l.h.ServeHTTP(rec, hr)
	return rec
}

// statuses sends the same request n times and returns the status codes.
func (l *limited) statuses(n int, r req) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = l.do(r).Code
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRateLimitResponse(t *testing.T) {
	const wantBody = `{"error":"too many requests"}`
	good := testToken(t, "svc-a")

	tests := []struct {
		name        string
		ip, caller  bucketCfg
		wait        time.Duration // clock movement after the budget is spent
		wantRetryIn string
	}{
		{"per-IP limiter", bucketCfg{1, 2}, bucketCfg{}, 0, "1"},
		{"per-caller limiter", bucketCfg{}, bucketCfg{1, 2}, 0, "1"},
		{"retry-after rounds up to whole seconds", bucketCfg{}, bucketCfg{0.25, 2}, 0, "4"},
		{"retry-after is at least one second", bucketCfg{}, bucketCfg{1, 2}, 950 * time.Millisecond, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLimited(t, tt.ip, tt.caller)
			if got := l.statuses(2, req{token: good}); !equalInts(got, []int{200, 200}) {
				t.Fatalf("first two calls = %v, want [200 200]", got)
			}
			l.clock.Advance(tt.wait)
			rec := l.do(req{token: good})

			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rec.Code)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != wantBody {
				t.Errorf("body = %q, want %q", got, wantBody)
			}
			if got := rec.Header().Get("Retry-After"); got != tt.wantRetryIn {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryIn)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
		})
	}
}

// 429 comes from the IP limiter BEFORE the token is even looked at.
func TestIPLimitAppliesBeforeAuth(t *testing.T) {
	good := testToken(t, "svc-a")
	l := newLimited(t, bucketCfg{1, 3}, bucketCfg{})

	if got := l.statuses(3, req{token: "not-a-token"}); !equalInts(got, []int{401, 401, 401}) {
		t.Fatalf("first three invalid-token calls = %v, want 401 each", got)
	}
	tests := []struct {
		name string
		r    req
		want int
	}{
		{"another invalid token from the same IP", req{token: "still-not-a-token"}, 429},
		{"no token from the same IP", req{}, 429},
		{"a VALID token from the same IP", req{token: good}, 429},
		{"a different IP is unaffected", req{token: "not-a-token", addr: "192.0.2.77:4000"}, 401},
		{"a different IP with a valid token", req{token: good, addr: "192.0.2.78:4000"}, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.do(tt.r).Code; got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCallerLimitIsPerSubject(t *testing.T) {
	l := newLimited(t, bucketCfg{}, bucketCfg{1, 2})
	a, b := testToken(t, "svc-a"), testToken(t, "svc-b")

	steps := []struct {
		name  string
		token string
		want  int
	}{
		{"a 1", a, 200}, {"a 2", a, 200}, {"a 3 is over budget", a, 429},
		{"b has its own budget 1", b, 200}, {"b 2", b, 200}, {"b 3 is over budget", b, 429},
		{"a is still over budget", a, 429},
	}
	for _, s := range steps {
		if got := l.do(req{token: s.token}).Code; got != s.want {
			t.Fatalf("%s: status = %d, want %d", s.name, got, s.want)
		}
	}

	// After a second a gets one token back; b is not affected by a's refill.
	l.clock.Advance(time.Second)
	if got := l.do(req{token: a}).Code; got != 200 {
		t.Errorf("a after 1s: status = %d, want 200", got)
	}
	if got := l.do(req{token: a}).Code; got != 429 {
		t.Errorf("a again: status = %d, want 429", got)
	}
}

// The caller limiter sits BEFORE the scope check, so 403s spend the budget.
func TestForbiddenRequestsConsumeCallerBudget(t *testing.T) {
	l := newLimited(t, bucketCfg{}, bucketCfg{1, 2})
	// Holds only the authorize scope, so every GET is a 403.
	token := testTokenScoped(t, "svc-a", auth.ScopeAuthorize)

	if got := l.statuses(2, req{token: token}); !equalInts(got, []int{403, 403}) {
		t.Fatalf("first two = %v, want [403 403]", got)
	}
	if got := l.do(req{token: token}).Code; got != 429 {
		t.Errorf("third forbidden call = %d, want 429", got)
	}
	// The budget is shared, so even a call this token IS allowed to make is refused.
	if got := l.do(req{method: http.MethodPost, path: "/v1/authorize", token: token}).Code; got != 429 {
		t.Errorf("allowed call after the budget is spent = %d, want 429", got)
	}
}

func TestInvalidTokensSpendNoCallerBudget(t *testing.T) {
	l := newLimited(t, bucketCfg{}, bucketCfg{1, 2})
	good := testToken(t, "svc-a")

	garbage := []req{
		{token: "not-a-token"},
		{token: good[:len(good)-2] + "xx"}, // tampered signature
		{},                                 // no token
		{headers: map[string]string{"Authorization": "Basic abc"}},
	}
	for i := 0; i < 5; i++ {
		for _, g := range garbage {
			if got := l.do(g).Code; got != 401 {
				t.Fatalf("invalid token: status = %d, want 401", got)
			}
		}
	}
	if n := l.limits.Caller.Len(); n != 0 {
		t.Errorf("caller limiter tracks %d keys after only invalid tokens, want 0", n)
	}
	if got := l.statuses(3, req{token: good}); !equalInts(got, []int{200, 200, 429}) {
		t.Errorf("valid caller after the flood = %v, want [200 200 429]", got)
	}
}

func TestHealthIsNeverLimited(t *testing.T) {
	l := newLimited(t, bucketCfg{1, 1}, bucketCfg{1, 1})
	for i := 0; i < 100; i++ {
		if got := l.do(req{path: "/health"}).Code; got != 200 {
			t.Fatalf("call %d: /health = %d, want 200", i+1, got)
		}
	}
	if l.limits.IP.Len() != 0 || l.limits.Caller.Len() != 0 {
		t.Error("/health created limiter entries, want none")
	}
	// And /health traffic does not use up the budget of /v1.
	if got := l.do(req{token: testToken(t, "svc-a")}).Code; got != 200 {
		t.Errorf("first /v1 call after the /health calls = %d, want 200", got)
	}
}

// Only the TCP peer address is the key. The proxy headers are client-controlled,
// so changing them must neither dodge the limit nor hit someone else's.
func TestProxyHeadersDoNotChangeTheKey(t *testing.T) {
	good := testToken(t, "svc-a")

	t.Run("changing the headers does not give a fresh budget", func(t *testing.T) {
		l := newLimited(t, bucketCfg{1, 2}, bucketCfg{})
		spoofed := []map[string]string{
			{"X-Forwarded-For": "203.0.113.1"},
			{"X-Forwarded-For": "203.0.113.2, 198.51.100.9", "X-Real-IP": "203.0.113.3"},
			{"Forwarded": "for=203.0.113.4", "X-Real-IP": "203.0.113.5"},
			{"X-Forwarded-For": "203.0.113.6"},
		}
		want := []int{200, 200, 429, 429}
		for i, h := range spoofed {
			if got := l.do(req{token: good, headers: h}).Code; got != want[i] {
				t.Errorf("call %d with %v: status = %d, want %d", i+1, h, got, want[i])
			}
		}
		if n := l.limits.IP.Len(); n != 1 {
			t.Errorf("IP limiter tracks %d keys, want 1 (the peer address)", n)
		}
	})

	t.Run("a victim's address in the headers is not charged", func(t *testing.T) {
		l := newLimited(t, bucketCfg{1, 1}, bucketCfg{})
		l.statuses(3, req{token: good, headers: map[string]string{"X-Forwarded-For": "192.0.2.99"}})
		// 192.0.2.99 never connected, so it still has a full budget.
		if got := l.do(req{token: good, addr: "192.0.2.99:5000"}).Code; got != 200 {
			t.Errorf("victim's first real call = %d, want 200", got)
		}
	})
}

func TestIPKeyIgnoresThePort(t *testing.T) {
	l := newLimited(t, bucketCfg{1, 2}, bucketCfg{})
	good := testToken(t, "svc-a")
	// Same host, a new source port each time (as new connections would have).
	for i, want := range []int{200, 200, 429, 429} {
		addr := "192.0.2.5:" + string(rune('0'+i)) + "000"
		if got := l.do(req{token: good, addr: addr}).Code; got != want {
			t.Errorf("call %d from %s: status = %d, want %d", i+1, addr, got, want)
		}
	}
}

func TestDisabledLimitersNeverRefuse(t *testing.T) {
	tests := []struct {
		name string
		l    func(t *testing.T) http.Handler
	}{
		{"zero Limits", func(t *testing.T) http.Handler {
			return newTestRouter(t, newFakeStore(), &audit.Memory{})
		}},
		{"rate 0 limiters", func(t *testing.T) http.Handler {
			return newLimited(t, bucketCfg{0, 1}, bucketCfg{0, 1}).h
		}},
	}
	good := testToken(t, "svc-a")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.l(t)
			for i := 0; i < 300; i++ {
				r := httptest.NewRequest(http.MethodGet, "/v1/roles", nil)
				r.RemoteAddr = defaultAddr
				r.Header.Set("Authorization", "Bearer "+good)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				if rec.Code != 200 {
					t.Fatalf("call %d: status = %d, want 200", i+1, rec.Code)
				}
			}
		})
	}
}

// A request that reaches the caller limiter without a subject is refused, not
// waved through.
func TestCallerLimiterWithoutSubjectFailsClosed(t *testing.T) {
	ran := false
	h := limitByCaller(ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1, MaxKeys: 10}), newRejectLog(time.Now))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("status = %d, handler ran = %v; want 401, false", rec.Code, ran)
	}
}

func TestRetryAfterHeaderRoundsUp(t *testing.T) {
	tests := []struct {
		retry time.Duration
		want  string
	}{
		{0, "1"},
		{time.Millisecond, "1"},
		{time.Second, "1"},
		{time.Second + time.Nanosecond, "2"},
		{2500 * time.Millisecond, "3"},
		{90 * time.Second, "90"},
	}
	for _, tt := range tests {
		t.Run(tt.retry.String(), func(t *testing.T) {
			rec := httptest.NewRecorder()
			tooManyRequests(rec, tt.retry)
			if got := rec.Header().Get("Retry-After"); got != tt.want {
				t.Errorf("Retry-After for %v = %q, want %q", tt.retry, got, tt.want)
			}
		})
	}
}

// Rejections are logged at most once per key per minute, with a quoted key and
// the route pattern, and never the token or the raw path.
func TestRejectionLogging(t *testing.T) {
	good := testToken(t, "svc-a")

	t.Run("one line per IP per minute", func(t *testing.T) {
		buf := captureLog(t)
		l := newLimited(t, bucketCfg{1, 2}, bucketCfg{})
		l.statuses(50, req{token: good, path: "/v1/roles/1%0AFORGED"}) // 2 pass, 48 refused

		out := buf.String()
		if n := strings.Count(out, "\n"); n != 1 {
			t.Fatalf("got %d log lines for 48 refusals, want 1:\n%s", n, out)
		}
		for _, want := range []string{`rate limited route "`, `ip "192.0.2.1"`} {
			if !strings.Contains(out, want) {
				t.Errorf("log %q does not contain %q", out, want)
			}
		}
		for _, bad := range []string{good, "FORGED", "%0A", "Bearer"} {
			if strings.Contains(out, bad) {
				t.Errorf("log leaks %q: %q", bad, out)
			}
		}

		// A minute later the key gets another line, once.
		l.clock.Advance(rejectLogEvery + time.Second)
		l.statuses(50, req{token: good})
		if n := strings.Count(buf.String(), "\n"); n != 2 {
			t.Errorf("after a minute: %d log lines, want 2", n)
		}
	})

	t.Run("different keys log separately", func(t *testing.T) {
		buf := captureLog(t)
		l := newLimited(t, bucketCfg{1, 1}, bucketCfg{})
		for _, addr := range []string{"192.0.2.10:1", "192.0.2.11:1", "192.0.2.12:1"} {
			l.statuses(5, req{token: good, addr: addr})
		}
		if n := strings.Count(buf.String(), "\n"); n != 3 {
			t.Errorf("got %d log lines, want 3 (one per IP):\n%s", n, buf.String())
		}
	})

	t.Run("caller limiter logs the quoted subject", func(t *testing.T) {
		buf := captureLog(t)
		l := newLimited(t, bucketCfg{}, bucketCfg{1, 1})
		token := testToken(t, "svc-x\nFORGED-LINE")
		l.statuses(10, req{token: token})

		out := buf.String()
		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Fatalf("log must be exactly one line, got %q", out)
		}
		if !strings.Contains(out, `sub "svc-x\nFORGED-LINE"`) {
			t.Errorf("log %q does not contain the quoted subject", out)
		}
		if strings.Contains(out, token) {
			t.Error("log contains the token")
		}
	})
}
