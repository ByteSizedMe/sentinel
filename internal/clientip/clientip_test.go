package clientip

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	sixtyFour := strings.TrimSuffix(strings.Repeat("10.0.0.1,", MaxTrusted), ",")
	tests := []struct {
		name    string
		in      string
		wantLen int
		wantErr bool
	}{
		{"empty", "", 0, false},
		{"only spaces", "   ", 0, false},
		{"bare IPv4", "10.0.0.1", 1, false},
		{"bare IPv6", "2001:db8::1", 1, false},
		{"bare IPv4-mapped IPv6 is unmapped", "::ffff:10.0.0.1", 1, false},
		{"IPv4 CIDR", "10.0.0.0/8", 1, false},
		{"IPv6 CIDR", "2001:db8::/32", 1, false},
		{"IPv4 /32", "10.0.0.1/32", 1, false},
		{"host bits set are masked", "10.1.2.3/8", 1, false},
		{"mixed list", "10.0.0.0/8,192.0.2.7,2001:db8::/32", 3, false},
		{"whitespace around entries", "  10.0.0.1 ,\t192.0.2.0/24  ", 2, false},
		{"exactly the cap", sixtyFour, MaxTrusted, false},

		{"over the cap", sixtyFour + ",10.0.0.2", 0, true},
		{"IPv4 /0", "0.0.0.0/0", 0, true},
		{"IPv6 /0", "::/0", 0, true},
		{"/0 hidden in a list", "10.0.0.1,0.0.0.0/0", 0, true},
		{"bad CIDR", "10.0.0.0/33", 0, true},
		{"bad CIDR text", "10.0.0.0/x", 0, true},
		{"not an IP", "proxy.example.com", 0, true},
		{"IP with port", "10.0.0.1:8080", 0, true},
		{"empty entry in the middle", "10.0.0.1,,10.0.0.2", 0, true},
		{"trailing comma", "10.0.0.1,", 0, true},
		{"leading comma", ",10.0.0.1", 0, true},
		{"only a comma", ",", 0, true},
		{"IPv4-mapped CIDR", "::ffff:10.0.0.0/104", 0, true},
		{"zone in a CIDR", "fe80::1%eth0/64", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidTrusted) {
					t.Fatalf("error = %v, want ErrInvalidTrusted", err)
				}
				if got != nil {
					t.Errorf("got a list alongside the error")
				}
				// The message names the position or rule, never the raw entry.
				if strings.Contains(err.Error(), "proxy.example.com") {
					t.Errorf("error repeats the entry: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Len() != tt.wantLen {
				t.Errorf("Len = %d, want %d", got.Len(), tt.wantLen)
			}
		})
	}
}

func TestNilTrustedTrustsNobody(t *testing.T) {
	var tr *Trusted
	if tr.Len() != 0 {
		t.Errorf("nil Len = %d, want 0", tr.Len())
	}
	r := request("10.0.0.1:1234", "203.0.113.9")
	if got := tr.Key(r); got != "10.0.0.1" {
		t.Errorf("Key = %q, want the peer address", got)
	}
}

// request builds a request from the given peer with one X-Forwarded-For line
// per argument (none if no lines are given).
func request(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, l := range xff {
		r.Header.Add("X-Forwarded-For", l)
	}
	return r
}

func TestKey(t *testing.T) {
	const trusted = "10.0.0.0/8,192.0.2.7,2001:db8:ffff::/48"
	tooLong := strings.TrimSuffix(strings.Repeat("203.0.113.5,", maxHops+1), ",")
	exactlyMax := strings.TrimSuffix(strings.Repeat("10.0.0.9,", maxHops-1), ",") + ",203.0.113.5"

	tests := []struct {
		name   string
		remote string
		xff    []string
		extra  map[string]string // other headers that must make no difference
		want   string
	}{
		// The peer is not trusted: headers are ignored, whatever they say.
		{"untrusted peer, spoofed header", "198.51.100.1:5000", []string{"203.0.113.9"}, nil, "198.51.100.1"},
		{"untrusted peer, spoofed chain", "198.51.100.1:5000", []string{"203.0.113.9, 10.0.0.1"}, nil, "198.51.100.1"},
		{"untrusted peer, no header", "198.51.100.1:5000", nil, nil, "198.51.100.1"},
		{"untrusted IPv6 peer", "[2001:db8::5]:443", []string{"203.0.113.9"}, nil, "2001:db8::5"},
		{"unparseable peer", "@", []string{"203.0.113.9"}, nil, "@"},
		{"peer with no port", "198.51.100.1", []string{"203.0.113.9"}, nil, "198.51.100.1"},

		// The peer is trusted: the rightmost untrusted hop is the client.
		{"trusted peer, one client", "10.0.0.1:5000", []string{"203.0.113.9"}, nil, "203.0.113.9"},
		{"trusted single-IP peer", "192.0.2.7:5000", []string{"203.0.113.9"}, nil, "203.0.113.9"},
		{"trusted peer, client then proxy", "10.0.0.1:5000", []string{"203.0.113.9, 10.0.0.2"}, nil, "203.0.113.9"},
		{"several trusted proxies in a row", "10.0.0.1:5000", []string{"203.0.113.9, 10.0.0.2, 10.0.0.3, 192.0.2.7"}, nil, "203.0.113.9"},
		{"spoofed entries on the left are ignored", "10.0.0.1:5000", []string{"1.1.1.1, 2.2.2.2, 203.0.113.9"}, nil, "203.0.113.9"},
		{"spoofed trusted address on the left", "10.0.0.1:5000", []string{"10.0.0.50, 203.0.113.9"}, nil, "203.0.113.9"},
		{"untrusted hop in the middle wins over the left", "10.0.0.1:5000", []string{"1.1.1.1, 203.0.113.9, 10.0.0.2"}, nil, "203.0.113.9"},
		{"spaces and tabs around entries", "10.0.0.1:5000", []string{" 203.0.113.9 ,\t10.0.0.2 "}, nil, "203.0.113.9"},
		{"exactly 20 entries", "10.0.0.1:5000", []string{exactlyMax}, nil, "203.0.113.5"},

		// Several header lines count as one list, in order.
		{"two lines", "10.0.0.1:5000", []string{"1.1.1.1", "203.0.113.9, 10.0.0.2"}, nil, "203.0.113.9"},
		{"client on the first line, proxy on the second", "10.0.0.1:5000", []string{"203.0.113.9", "10.0.0.2"}, nil, "203.0.113.9"},
		{"spoofed first line, real second line", "10.0.0.1:5000", []string{"1.1.1.1", "203.0.113.9"}, nil, "203.0.113.9"},

		// IPv6 and IPv4-mapped IPv6.
		{"IPv6 client", "10.0.0.1:5000", []string{"2001:db8::9"}, nil, "2001:db8::9"},
		{"IPv6 client is written in canonical form", "10.0.0.1:5000", []string{"2001:0DB8:0:0:0:0:0:9"}, nil, "2001:db8::9"},
		{"IPv6 zone is stripped", "10.0.0.1:5000", []string{"fe80::9%eth0"}, nil, "fe80::9"},
		{"IPv4-mapped client is unmapped", "10.0.0.1:5000", []string{"::ffff:203.0.113.9"}, nil, "203.0.113.9"},
		{"IPv4-mapped trusted proxy is skipped", "10.0.0.1:5000", []string{"203.0.113.9, ::ffff:10.0.0.2"}, nil, "203.0.113.9"},
		{"IPv6 trusted peer", "[2001:db8:ffff::1]:443", []string{"203.0.113.9"}, nil, "203.0.113.9"},
		{"IPv4-mapped peer address", "[::ffff:10.0.0.1]:5000", []string{"203.0.113.9"}, nil, "203.0.113.9"},
		{"IPv6 trusted proxy in the chain", "10.0.0.1:5000", []string{"203.0.113.9, 2001:db8:ffff::7"}, nil, "203.0.113.9"},

		// Anything odd falls back to the peer address.
		{"no header", "10.0.0.1:5000", nil, nil, "10.0.0.1"},
		{"empty header", "10.0.0.1:5000", []string{""}, nil, "10.0.0.1"},
		{"blank header", "10.0.0.1:5000", []string{"   "}, nil, "10.0.0.1"},
		{"only a comma", "10.0.0.1:5000", []string{","}, nil, "10.0.0.1"},
		{"garbage", "10.0.0.1:5000", []string{"not-an-ip"}, nil, "10.0.0.1"},
		{"bad entry on the left", "10.0.0.1:5000", []string{"garbage, 203.0.113.9"}, nil, "10.0.0.1"},
		{"bad entry on the right", "10.0.0.1:5000", []string{"203.0.113.9, garbage"}, nil, "10.0.0.1"},
		{"empty entry in the chain", "10.0.0.1:5000", []string{"203.0.113.9,,10.0.0.2"}, nil, "10.0.0.1"},
		{"trailing comma", "10.0.0.1:5000", []string{"203.0.113.9,"}, nil, "10.0.0.1"},
		{"entry with a port", "10.0.0.1:5000", []string{"203.0.113.9:4444"}, nil, "10.0.0.1"},
		{"entry that looks like a hostname", "10.0.0.1:5000", []string{"client.example.com"}, nil, "10.0.0.1"},
		{"quoted entry", "10.0.0.1:5000", []string{`"203.0.113.9"`}, nil, "10.0.0.1"},
		{"newline-ish control characters", "10.0.0.1:5000", []string{"203.0.113.9\x00"}, nil, "10.0.0.1"},
		{"21 entries", "10.0.0.1:5000", []string{tooLong}, nil, "10.0.0.1"},
		{"21 entries over two lines", "10.0.0.1:5000", []string{strings.Repeat("203.0.113.5,", 11), strings.Repeat("203.0.113.5,", 9) + "203.0.113.5"}, nil, "10.0.0.1"},
		{"every hop trusted", "10.0.0.1:5000", []string{"10.0.0.2, 192.0.2.7, 2001:db8:ffff::2"}, nil, "10.0.0.1"},
		{"a single trusted entry", "10.0.0.1:5000", []string{"10.0.0.2"}, nil, "10.0.0.1"},

		// Other headers never matter.
		{"X-Real-IP is ignored", "10.0.0.1:5000", nil, map[string]string{"X-Real-IP": "203.0.113.9"}, "10.0.0.1"},
		{"Forwarded is ignored", "10.0.0.1:5000", nil, map[string]string{"Forwarded": "for=203.0.113.9"}, "10.0.0.1"},
		{"X-Real-IP and Forwarded do not beat X-Forwarded-For", "10.0.0.1:5000", []string{"203.0.113.9"},
			map[string]string{"X-Real-IP": "198.51.100.77", "Forwarded": "for=198.51.100.78"}, "203.0.113.9"},
		{"lowercase header name is the same header", "10.0.0.1:5000", nil, map[string]string{"x-forwarded-for": "203.0.113.9"}, "203.0.113.9"},
	}
	tr, err := Parse(trusted)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := request(tt.remote, tt.xff...)
			for k, v := range tt.extra {
				r.Header.Set(k, v)
			}
			if got := tr.Key(r); got != tt.want {
				t.Errorf("Key = %q, want %q (peer %s, header %q)", got, tt.want, tt.remote, tt.xff)
			}
		})
	}
}

// With no list at all the key is the peer, byte for byte, as before this
// feature existed.
func TestEmptyListKeepsTheOldBehavior(t *testing.T) {
	tests := []struct{ remote, want string }{
		{"192.0.2.1:1234", "192.0.2.1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"[::ffff:192.0.2.1]:8080", "::ffff:192.0.2.1"}, // not normalized: unchanged behavior
		{"192.0.2.1", "192.0.2.1"},
		{"@", "@"},
		{"", ""},
	}
	tr, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.remote), func(t *testing.T) {
			r := request(tt.remote, "203.0.113.9")
			if got := tr.Key(r); got != tt.want {
				t.Errorf("Key = %q, want %q", got, tt.want)
			}
		})
	}
}
