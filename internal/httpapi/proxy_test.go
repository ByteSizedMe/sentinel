package httpapi

import (
	"testing"

	"github.com/bytesizedme/sentinel/internal/clientip"
)

// Behind a trusted proxy the limiter charges the client named by
// X-Forwarded-For, not the proxy. The proxy is 10.0.0.1 in these tests.
func TestTrustedProxyKeysByClient(t *testing.T) {
	const proxy = "10.0.0.1:4000"
	good := testToken(t, "svc-a")
	trusted, err := clientip.Parse("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	xff := func(v string) map[string]string { return map[string]string{"X-Forwarded-For": v} }

	t.Run("two clients behind one proxy get separate budgets", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, trusted)
		a := req{token: good, addr: proxy, headers: xff("203.0.113.1")}
		b := req{token: good, addr: proxy, headers: xff("203.0.113.2")}
		if got, want := l.statuses(3, a), []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("client A statuses = %v, want %v", got, want)
		}
		if got, want := l.statuses(3, b), []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("client B statuses = %v, want %v", got, want)
		}
		if n := l.limits.IP.Len(); n != 2 {
			t.Errorf("IP limiter tracks %d keys, want 2 (one per client)", n)
		}
	})

	t.Run("two requests from the same client share one budget", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, trusted)
		// Different proxies, same client: still one key.
		first := req{token: good, addr: "10.0.0.1:4000", headers: xff("203.0.113.1")}
		second := req{token: good, addr: "10.0.0.2:4001", headers: xff("203.0.113.1")}
		got := []int{l.do(first).Code, l.do(second).Code, l.do(first).Code}
		if want := []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("statuses = %v, want %v", got, want)
		}
	})

	t.Run("a spoofed leftmost entry does not buy a fresh budget", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, trusted)
		var got []int
		for _, h := range []string{"1.1.1.1, 203.0.113.1", "2.2.2.2, 203.0.113.1", "3.3.3.3, 203.0.113.1"} {
			got = append(got, l.do(req{token: good, addr: proxy, headers: xff(h)}).Code)
		}
		if want := []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("statuses = %v, want %v", got, want)
		}
	})

	t.Run("a client that is not a trusted proxy cannot choose its key", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, trusted)
		var got []int
		for _, h := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
			got = append(got, l.do(req{token: good, addr: "198.51.100.7:5000", headers: xff(h)}).Code)
		}
		if want := []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("statuses = %v, want %v", got, want)
		}
		if n := l.limits.IP.Len(); n != 1 {
			t.Errorf("IP limiter tracks %d keys, want 1 (the peer)", n)
		}
	})

	t.Run("a bad header from a trusted proxy falls back to the proxy address", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, trusted)
		var got []int
		for _, h := range []string{"nonsense", "203.0.113.2, nonsense", ""} {
			got = append(got, l.do(req{token: good, addr: proxy, headers: xff(h)}).Code)
		}
		if want := []int{200, 200, 429}; !equalInts(got, want) {
			t.Errorf("statuses = %v, want %v", got, want)
		}
	})

	t.Run("the caller limiter still keys on the token subject", func(t *testing.T) {
		l := newLimitedBehind(t, bucketCfg{}, bucketCfg{1, 1}, trusted)
		// Different clients, same subject: one caller budget.
		a := l.do(req{token: good, addr: proxy, headers: xff("203.0.113.1")}).Code
		b := l.do(req{token: good, addr: proxy, headers: xff("203.0.113.2")}).Code
		if a != 200 || b != 429 {
			t.Errorf("statuses = %d, %d; want 200, 429", a, b)
		}
	})
}

// With nothing trusted (the default) changing X-Forwarded-For changes nothing,
// even when the peer happens to be a proxy address.
func TestNoTrustedProxiesIgnoresForwardedFor(t *testing.T) {
	good := testToken(t, "svc-a")
	l := newLimitedBehind(t, bucketCfg{1, 2}, bucketCfg{}, nil)
	var got []int
	for _, v := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		got = append(got, l.do(req{token: good, addr: "10.0.0.1:4000", headers: map[string]string{"X-Forwarded-For": v}}).Code)
	}
	if want := []int{200, 200, 429}; !equalInts(got, want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
}
