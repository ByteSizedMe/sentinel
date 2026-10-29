// Package httpapi wires up Sentinel's HTTP routes and middleware.
package httpapi

import (
	"net/http"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// api holds what the handlers need. Depending on the rbac.PolicyStore
// interface (not Postgres) is what lets tests swap in a fake.
type api struct {
	store rbac.PolicyStore
}

// NewRouter builds the HTTP handler for the whole service.
//
// NOTE: the /v1 endpoints are NOT authenticated yet (JWT middleware comes in a
// later batch). Do not expose this server beyond localhost.
func NewRouter(store rbac.PolicyStore) http.Handler {
	a := &api{store: store}
	r := chi.NewRouter()

	// RequestID tags each request so log lines can be correlated.
	// Recoverer turns a panic in a handler into a 500 instead of crashing
	// the whole server. RequestID goes first so panics are tagged too.
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/health", health)

	r.Route("/v1", func(r chi.Router) {
		r.Route("/roles", func(r chi.Router) {
			r.Post("/", a.createRole)
			r.Get("/", a.listRoles)
			r.Get("/{roleID}", a.getRole)
			r.Delete("/{roleID}", a.deleteRole)

			r.Get("/{roleID}/permissions", a.listRolePermissions)
			r.Post("/{roleID}/permissions", a.grantPermission)
			r.Delete("/{roleID}/permissions/{permissionID}", a.revokePermission)
		})

		r.Route("/resources", func(r chi.Router) {
			r.Post("/", a.createResource)
			r.Get("/", a.listResources)
			r.Get("/{resourceID}", a.getResource)
			r.Delete("/{resourceID}", a.deleteResource)
		})

		r.Route("/permissions", func(r chi.Router) {
			r.Post("/", a.createPermission)
			r.Get("/", a.listPermissions)
			r.Get("/{permissionID}", a.getPermission)
			r.Delete("/{permissionID}", a.deletePermission)
		})

		r.Route("/users/{userID}/roles", func(r chi.Router) {
			r.Get("/", a.listUserRoles)
			r.Post("/", a.assignRole)
			r.Delete("/{roleID}", a.removeRole)
		})
	})
	return r
}

// health is a liveness check: it only says the process is up.
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
