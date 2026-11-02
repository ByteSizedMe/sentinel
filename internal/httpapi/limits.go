package httpapi

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/clientip"
	"github.com/bytesizedme/sentinel/internal/ratelimit"
)

// Limits are the two rate limiters in front of /v1. A nil limiter (or one built
// with a rate of 0) is off. See internal/ratelimit.
type Limits struct {
	IP     *ratelimit.Limiter // per client IP, before authentication
	Caller *ratelimit.Limiter // per token subject, after authentication

	// Proxies are the proxies whose X-Forwarded-For header may name the client
	// for the IP limiter. Nil trusts nobody: the key is the TCP peer address.
	Proxies *clientip.Trusted
}

// Rejections are logged at most once per key per minute, and at most this many
// keys are remembered for that purpose.
const (
	rejectLogEvery   = time.Minute
	rejectLogMaxKeys = 1000
)

// rejectLog writes one generic line per key per minute, using a limiter of its
// own, so a flood of rejected requests cannot flood the log as well.
type rejectLog struct{ gate *ratelimit.Limiter }

func newRejectLog(now func() time.Time) *rejectLog {
	return &rejectLog{gate: ratelimit.New(ratelimit.Config{
		Rate:    1 / rejectLogEvery.Seconds(),
		Burst:   1,
		MaxKeys: rejectLogMaxKeys,
		Now:     now,
	})}
}

// rejected logs a refusal. who is "ip" or "sub" and key is the value. The line
// has the route pattern (never the raw path) and the key, both quoted so no
// control character can forge a log line. It never contains a token.
func (l *rejectLog) rejected(r *http.Request, who, key string) {
	if ok, _ := l.gate.Allow(who + "\x00" + key); !ok {
		return
	}
	log.Printf("httpapi: rate limited route %s %s %s", strconv.Quote(routePattern(r)), who, strconv.Quote(key))
}

// tooManyRequests sends the same fixed 429 for both limiters, so the response
// does not reveal which one fired or what the limits are. Retry-After is in
// whole seconds, at least 1.
func tooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int((retryAfter + time.Second - 1) / time.Second) // round up
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
}

// limitByIP runs BEFORE authentication, so floods of requests with bad or
// missing tokens are slowed down too.
//
// The key is the TCP peer address unless that peer is one of the trusted
// proxies, in which case it is the client named by X-Forwarded-For (see
// internal/clientip). With no trusted proxies the headers are never read, so a
// client cannot choose its own key.
func limitByIP(l *ratelimit.Limiter, proxies *clientip.Trusted, logs *rejectLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := proxies.Key(r)
			if ok, retry := l.Allow(ip); !ok {
				logs.rejected(r, "ip", ip)
				tooManyRequests(w, retry)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitByCaller runs AFTER authentication and BEFORE the scope check. The key
// is the token's subject, which is why a request with an invalid token never
// spends anyone's budget, and why a caller that keeps getting 403 spends its own.
func limitByCaller(l *ratelimit.Limiter, logs *rejectLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub, ok := auth.SubjectFromContext(r.Context())
			if !ok {
				// auth.Middleware always sets a subject; if it is missing the
				// route was wired wrongly, so refuse rather than skip the limit.
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			if ok, retry := l.Allow(sub); !ok {
				logs.rejected(r, "sub", sub)
				tooManyRequests(w, retry)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
