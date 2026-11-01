package auth

import (
	"context"
	"strings"
)

// The scopes Sentinel understands. They are independent: holding one never
// implies another.
const (
	ScopeAuthorize = "sentinel:authorize" // POST /v1/authorize
	ScopeRead      = "sentinel:read"      // every GET under /v1
	ScopeAdmin     = "sentinel:admin"     // every POST and DELETE under /v1 except authorize
)

// AllScopes lists every known scope (used by cmd/tokengen for local dev tokens).
var AllScopes = []string{ScopeAuthorize, ScopeRead, ScopeAdmin}

// parseScopes reads the OAuth2-style "scope" claim: ONE string with scopes
// separated by single spaces. It is deliberately strict:
//   - a claim that is missing, a number, an array or anything else but a string
//     means no scopes;
//   - the string is split on the space character only, so a tab or newline
//     stays inside an entry and that entry matches nothing;
//   - matching is exact and case-sensitive, and unknown or empty entries are
//     dropped.
//
// Only known scopes are returned.
func parseScopes(claim any) []string {
	s, ok := claim.(string)
	if !ok {
		return nil
	}
	var out []string
	for _, entry := range strings.Split(s, " ") {
		for _, known := range AllScopes {
			if entry == known {
				out = append(out, entry)
			}
		}
	}
	return out
}

// scopesKey is unexported so no other package can read or overwrite the value.
type scopesKey struct{}

// HasScope reports whether the authenticated caller's token carries scope.
// Without a token that passed Middleware the answer is always false.
func HasScope(ctx context.Context, scope string) bool {
	scopes, _ := ctx.Value(scopesKey{}).([]string)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
