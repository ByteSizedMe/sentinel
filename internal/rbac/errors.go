package rbac

import "errors"

// Sentinel errors. Stores return these (never raw database errors) so the
// HTTP layer can map them to status codes with errors.Is.
var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrInvalidInput = errors.New("invalid input")
)
