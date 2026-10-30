// Package audit records every authorization decision in an append-only log.
package audit

import "context"

// Entry is one authorization decision.
type Entry struct {
	Caller   string // JWT subject of the service that asked
	UserID   string // the user the decision was about
	Action   string
	Resource string
	Allowed  bool
	Reason   string
}

// Logger appends decisions to the audit log. There is deliberately no way to
// read, change or delete entries through this interface.
type Logger interface {
	Record(ctx context.Context, e Entry) error
}
