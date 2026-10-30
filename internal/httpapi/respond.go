package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/go-chi/chi/v5"
)

// errBodyTooLarge is returned by decodeJSON when the body exceeds its limit.
var errBodyTooLarge = errors.New("request body too large")

// maxBodyBytes caps request bodies so a client cannot make us read gigabytes.
const maxBodyBytes = 64 << 10

// writeJSON sends v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers are already sent, so all we can do is log.
		log.Printf("httpapi: encode response: %v", err)
	}
}

// writeError maps an error to a status code and a safe message. Only our own
// validation messages and fixed strings are ever sent to the client: unexpected
// errors (which might contain SQL or connection details) are logged, not returned.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	status, msg := http.StatusInternalServerError, "internal server error"
	switch {
	case errors.Is(err, errBodyTooLarge):
		status, msg = http.StatusRequestEntityTooLarge, "request body too large"
	case errors.Is(err, rbac.ErrInvalidInput):
		status, msg = http.StatusBadRequest, err.Error()
	case errors.Is(err, rbac.ErrNotFound):
		status, msg = http.StatusNotFound, "not found"
	case errors.Is(err, rbac.ErrConflict):
		status, msg = http.StatusConflict, "already exists"
	default:
		log.Printf("httpapi: %s %s: %v", r.Method, r.URL.Path, err)
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a JSON body into dst. Unknown fields are rejected so typos
// like {"nmae": "x"} fail loudly instead of being silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return errBodyTooLarge
		}
		return fmt.Errorf("%w: request body must be valid JSON with known fields", rbac.ErrInvalidInput)
	}
	// A second value after the first object (e.g. "{}{}") is also invalid.
	if dec.More() {
		return fmt.Errorf("%w: request body must contain a single JSON object", rbac.ErrInvalidInput)
	}
	return nil
}

// pathID parses a positive integer URL parameter such as {roleID}.
func pathID(r *http.Request, param string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, param), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %s must be a positive integer", rbac.ErrInvalidInput, param)
	}
	return id, nil
}
