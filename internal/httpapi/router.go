// Package httpapi wires up Sentinel's HTTP routes and middleware.
package httpapi

import (
	"net/http"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// api holds what the handlers need. Depending on the rbac.PolicyStore
// interface (not Postgres) is what lets tests swap in a fake.
type api struct {
	store  rbac.PolicyStore
	audits audit.Logger
}

// route is one /v1 endpoint together with the scope a token needs to call it.
type route struct {
	method  string
	pattern string // relative to /v1
	scope   string // required scope; "" is never satisfied (see requireScope)
	handler http.HandlerFunc
}

// v1Routes is the ONLY place /v1 routes are declared, so every route has to
// name its scope right next to its handler:
//
//	authorize -> sentinel:authorize
//	GET       -> sentinel:read
//	POST, DELETE (everything else) -> sentinel:admin
//
// The scopes are independent: admin does not imply read or authorize.
func (a *api) v1Routes() []route {
	const (
		authz = auth.ScopeAuthorize
		read  = auth.ScopeRead
		admin = auth.ScopeAdmin
	)
	return []route{
		{http.MethodPost, "/authorize", authz, a.authorize},

		{http.MethodPost, "/roles", admin, a.createRole},
		{http.MethodGet, "/roles", read, a.listRoles},
		{http.MethodGet, "/roles/{roleID}", read, a.getRole},
		{http.MethodDelete, "/roles/{roleID}", admin, a.deleteRole},
		{http.MethodGet, "/roles/{roleID}/permissions", read, a.listRolePermissions},
		{http.MethodPost, "/roles/{roleID}/permissions", admin, a.grantPermission},
		{http.MethodDelete, "/roles/{roleID}/permissions/{permissionID}", admin, a.revokePermission},

		{http.MethodPost, "/resources", admin, a.createResource},
		{http.MethodGet, "/resources", read, a.listResources},
		{http.MethodGet, "/resources/{resourceID}", read, a.getResource},
		{http.MethodDelete, "/resources/{resourceID}", admin, a.deleteResource},

		{http.MethodPost, "/permissions", admin, a.createPermission},
		{http.MethodGet, "/permissions", read, a.listPermissions},
		{http.MethodGet, "/permissions/{permissionID}", read, a.getPermission},
		{http.MethodDelete, "/permissions/{permissionID}", admin, a.deletePermission},

		{http.MethodGet, "/users/{userID}/roles", read, a.listUserRoles},
		{http.MethodPost, "/users/{userID}/roles", admin, a.assignRole},
		{http.MethodDelete, "/users/{userID}/roles/{roleID}", admin, a.removeRole},
	}
}

// NewRouter builds the HTTP handler for the whole service.
// GET /health is public; everything under /v1 requires a valid JWT (401) that
// also carries the scope the route needs (403).
func NewRouter(store rbac.PolicyStore, audits audit.Logger, tokens *auth.Validator) http.Handler {
	a := &api{store: store, audits: audits}
	r := chi.NewRouter()

	// RequestID tags each request so log lines can be correlated.
	// Recoverer turns a panic in a handler into a 500 instead of crashing
	// the whole server. RequestID goes first so panics are tagged too.
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/health", health)

	r.Route("/v1", func(r chi.Router) {
		// Every /v1 route, including ones that do not exist, needs a token.
		r.Use(auth.Middleware(tokens))

		for _, rt := range a.v1Routes() {
			// With() puts the scope check in front of this one handler only.
			r.With(requireScope(rt.scope)).Method(rt.method, rt.pattern, rt.handler)
		}
	})
	return r
}

// health is a liveness check: it only says the process is up.
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
