// Package httpapi wires up Sentinel's HTTP routes and middleware.
package httpapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewRouter builds the HTTP handler for the whole service.
func NewRouter() http.Handler {
	r := chi.NewRouter()

	// RequestID tags each request so log lines can be correlated.
	// Recoverer turns a panic in a handler into a 500 instead of crashing
	// the whole server. RequestID goes first so panics are tagged too.
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/health", health)
	return r
}

// health is a liveness check: it only says the process is up.
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// writeJSON sends v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers are already sent, so all we can do is log.
		log.Printf("httpapi: encode response: %v", err)
	}
}
