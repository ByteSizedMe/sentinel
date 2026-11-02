// Package clientip works out which client IP the per-IP rate limiter should
// charge. By default that is the TCP peer address. Only when the peer is one of
// the operator's own, explicitly listed proxies is X-Forwarded-For believed.
package clientip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	// MaxTrusted caps TRUSTED_PROXIES so the list stays small and reviewable.
	MaxTrusted = 64
	// maxHops is the most X-Forwarded-For entries we will look at. A longer
	// chain is not something a sane deployment produces, so it is not trusted.
	maxHops = 20
)

// ErrInvalidTrusted is wrapped with the position of the offending entry. The
// message never repeats the entry itself.
var ErrInvalidTrusted = errors.New("invalid trusted proxy list")

// Trusted is a set of proxy addresses. A nil *Trusted trusts nobody, which is
// the safe default.
type Trusted struct {
	prefixes []netip.Prefix
}

// Parse reads a comma-separated list of IPs and CIDRs (IPv4 and IPv6). An empty
// or blank list returns nil. It refuses entries it cannot parse, empty entries,
// ranges that cover every address (/0, which would make the header fully
// spoofable) and lists longer than MaxTrusted.
func Parse(list string) (*Trusted, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	parts := strings.Split(list, ",")
	if len(parts) > MaxTrusted {
		return nil, fmt.Errorf("%w: more than %d entries", ErrInvalidTrusted, MaxTrusted)
	}
	t := &Trusted{}
	for i, part := range parts {
		p, err := parseEntry(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d %v", ErrInvalidTrusted, i+1, err)
		}
		t.prefixes = append(t.prefixes, p)
	}
	return t, nil
}

// parseEntry turns one entry into a prefix. A bare IP becomes a single-address
// prefix. The error text names the rule, not the entry.
func parseEntry(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, errors.New("is empty")
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, errors.New("is not an IP address or CIDR range")
		}
		a = normalize(a)
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errors.New("is not an IP address or CIDR range")
	}
	switch {
	case p.Addr().Zone() != "":
		return netip.Prefix{}, errors.New("must not have an IPv6 zone")
	case p.Addr().Is4In6():
		// Matching is done on unmapped addresses, so write these as plain IPv4.
		return netip.Prefix{}, errors.New("must be written as IPv4, not IPv4-mapped IPv6")
	case p.Bits() == 0:
		return netip.Prefix{}, errors.New("covers every address (/0), which would trust every client")
	}
	return p.Masked(), nil
}

// normalize drops an IPv6 zone and unmaps IPv4-in-IPv6, so one client has one
// spelling and therefore one rate-limit key.
func normalize(a netip.Addr) netip.Addr {
	return a.WithZone("").Unmap()
}

func (t *Trusted) contains(a netip.Addr) bool {
	if t == nil {
		return false
	}
	for _, p := range t.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Len is the number of trusted ranges.
func (t *Trusted) Len() int {
	if t == nil {
		return 0
	}
	return len(t.prefixes)
}

// Key returns the string the per-IP limiter should use for this request.
//
// The default is the host part of r.RemoteAddr. Only if that peer is trusted is
// X-Forwarded-For read: the lines are joined, the list is walked from the right
// (the hop closest to us, which our own proxy appended), trusted hops are
// skipped, and the first untrusted one is the client. Entries further left were
// written by the client or earlier hops and are never consulted.
//
// Anything odd (no header, an empty or unparseable entry, more than 20 entries,
// every hop trusted) falls back to the peer address, so a bad header can never
// pick the key. X-Real-IP and Forwarded are never read.
func (t *Trusted) Key(r *http.Request) string {
	peer := hostOf(r.RemoteAddr)
	if t == nil {
		return peer
	}
	pa, err := netip.ParseAddr(peer)
	if err != nil || !t.contains(normalize(pa)) {
		return peer
	}
	if ip, ok := t.fromForwardedFor(r.Header.Values("X-Forwarded-For")); ok {
		return ip
	}
	return peer
}

// fromForwardedFor returns the rightmost untrusted hop, normalized.
func (t *Trusted) fromForwardedFor(lines []string) (string, bool) {
	hops := 0
	for _, l := range lines {
		hops += strings.Count(l, ",") + 1
	}
	if hops == 0 || hops > maxHops {
		return "", false
	}
	// Parse every entry first: one bad entry anywhere means the header as a
	// whole cannot be trusted.
	addrs := make([]netip.Addr, 0, hops)
	for _, l := range lines {
		for _, part := range strings.Split(l, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				return "", false
			}
			addrs = append(addrs, normalize(a))
		}
	}
	for i := len(addrs) - 1; i >= 0; i-- {
		if !t.contains(addrs[i]) {
			return addrs[i].String(), true
		}
	}
	return "", false
}

// hostOf is the host part of a RemoteAddr: the TCP peer, without the port.
func hostOf(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // no port to strip
	}
	return host
}
