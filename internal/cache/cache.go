// Package cache caches authorization decisions in Redis (cache-aside) and
// makes sure a changed policy is never answered from stale data.
//
// # Key design
//
// Two kinds of key are written, and both always have a TTL:
//
//	sentinel:v1:dec:<sha256 hex>   one authorization decision
//	sentinel:v1:gen                the current "generation" number
//
// The prefix "sentinel:v1:" namespaces every key and versions the format: if
// the stored shape ever changes, bump v1 to v2 and old entries are ignored.
//
// The decision key is a hash of (user, action, resource). Each field is
// length-prefixed before hashing, so ("a:b", "c") and ("a", "b:c") can never
// produce the same key, and one user's entry cannot be served for another
// user. The hash also keeps user IDs out of `redis-cli KEYS`.
//
// The value is only what Postgres answered: allowed and the matched role.
// Nothing from the request or the JWT is ever stored as data.
//
// # Invalidation: the generation counter
//
// Every cached entry is stamped with the generation that was current when its
// lookup began. Any change that can alter a decision bumps the generation, so
// all older entries stop matching at once and are ignored (they then expire by
// TTL). Compared with deleting individual users' keys this is simpler, needs no
// "which users hold this role?" lookup, and has no gap in which a slow reader
// could re-store an old answer: such a reader holds the OLD generation, so what
// it stores is already unreachable. The cost is that any policy change empties
// the whole cache, which is fine because policy changes are rare compared with
// authorization checks.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// keyPrefix namespaces and versions every key Sentinel writes to Redis.
const keyPrefix = "sentinel:v1:"

// Generation identifies one "epoch" of policy. It only ever changes by moving
// to a value that no earlier epoch used.
type Generation int64

// Result is what Get returns.
type Result struct {
	Hit      bool          // true only for a valid entry from the current generation
	Decision rbac.Decision // meaningful only when Hit is true
	Gen      Generation    // the generation observed by this lookup, hit or miss
}

// Cache stores decisions. Implementations must treat any problem (an expired
// entry, a corrupt entry, an entry from an older generation) as a miss, and
// report real failures (e.g. Redis unreachable) as errors.
type Cache interface {
	// Get looks up a decision. The returned Gen must be passed to Set.
	Get(ctx context.Context, userID, action, resource string) (Result, error)

	// Set stores a decision read from Postgres, stamped with the generation
	// that Get returned BEFORE Postgres was queried. If the policy changed in
	// between, the stamp is out of date and the entry is never served.
	Set(ctx context.Context, userID, action, resource string, d rbac.Decision, gen Generation) error

	// Invalidate makes every existing entry unreachable.
	Invalidate(ctx context.Context) error
}

// decisionKey builds the Redis key for one decision (see "Key design" in the package doc).
func decisionKey(userID, action, resource string) string {
	h := sha256.New()
	for _, field := range []string{userID, action, resource} {
		// Length prefix: the boundary between fields is unambiguous.
		fmt.Fprintf(h, "%d:%s;", len(field), field)
	}
	return keyPrefix + "dec:" + hex.EncodeToString(h.Sum(nil))
}
