package auth

import (
	"context"
	"net/http"
	"strings"
)

// maxTokenLen rejects absurdly long Authorization values before parsing them.
const maxTokenLen = 4096

// ctxKey is unexported so no other package can read or overwrite our value.
type ctxKey struct{}

// SubjectFromContext returns the authenticated caller's subject, if the
// request passed through Middleware.
func SubjectFromContext(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(ctxKey{}).(string)
	return s, ok && s != ""
}

// Middleware rejects requests that lack a valid "Authorization: Bearer <jwt>"
// header. On success it stores the token's subject in the request context.
func Middleware(v *Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				unauthorized(w)
				return
			}
			subject, err := v.ValidateToken(raw)
			if err != nil {
				// Deliberately not logged and not described: the reason could
				// help an attacker, and logging risks leaking the token.
				unauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenLen {
		return "", false
	}
	return token, true
}

// unauthorized sends the same generic 401 for every failure.
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
}
