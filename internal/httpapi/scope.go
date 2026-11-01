package httpapi

import (
	"log"
	"net/http"
	"strconv"

	"github.com/bytesizedme/sentinel/internal/auth"
)

// requireScope lets a request through only if its (already authenticated)
// token carries the given scope. It runs after auth.Middleware, so a missing or
// invalid token has already been answered with 401.
//
// Deny by default: an empty required scope can never be satisfied, so a route
// declared without a scope answers 403 to everyone instead of being open.
func requireScope(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if required == "" || !auth.HasScope(r.Context(), required) {
				forbidden(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forbidden sends the same fixed 403 for every missing-scope case. The body
// never says which scope was needed or which the token has, since that would
// only help someone probing with a stolen token.
//
// The log line names the route pattern (not the raw path) and the caller's
// subject, both quoted. It never contains the token or its scope list. It is
// not an audit_log entry: that table only records authorization decisions.
func forbidden(w http.ResponseWriter, r *http.Request) {
	sub, _ := auth.SubjectFromContext(r.Context())
	log.Printf("httpapi: forbidden route %s sub %s", strconv.Quote(routePattern(r)), strconv.Quote(sub))
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
}
