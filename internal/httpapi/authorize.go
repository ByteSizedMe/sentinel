package httpapi

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/rbac"
)

// maxAuthorizeBodyBytes is far smaller than the general limit: a valid
// authorize request is a few hundred bytes at most.
const maxAuthorizeBodyBytes = 4 << 10

// Reasons returned to callers. They are fixed strings on purpose: a reason
// that named the user's roles or the missing permission would leak policy.
const (
	reasonGranted = "permission granted"
	reasonNoGrant = "no matching grant"
)

type authorizeRequest struct {
	UserID   string `json:"user_id"`  // the user being checked (NOT the caller)
	Action   string `json:"action"`   // e.g. "read"
	Resource string `json:"resource"` // resource name, e.g. "invoices"
}

type authorizeResponse struct {
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
	MatchedRole string `json:"matched_role,omitempty"` // only present when allowed
}

// authorize handles POST /v1/authorize.
//
// Flow: validate input -> ask the store -> record the decision in the audit
// log -> respond. It FAILS CLOSED at every step:
//   - invalid input        -> 400, no decision
//   - store error          -> 500, no decision (never "allowed")
//   - audit write fails    -> 500, the decision is NOT returned
//
// The audit rule is deliberate: a decision that cannot be recorded must not
// take effect, otherwise someone could act without leaving a trace.
func (a *api) authorize(w http.ResponseWriter, r *http.Request) {
	// The caller is whoever the JWT says it is. The middleware guarantees a
	// subject exists; this check is a second lock in case a route is ever
	// registered outside the middleware by mistake.
	caller, ok := auth.SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	req, err := decodeAuthorizeRequest(w, r)
	if err != nil {
		writeError(w, r, err)
		return
	}

	decision, err := a.store.CheckPermission(r.Context(), req.UserID, req.Action, req.Resource)
	if err != nil {
		writeError(w, r, err) // logs the cause, sends a generic 500
		return
	}

	resp := authorizeResponse{Allowed: decision.Allowed, Reason: reasonNoGrant}
	if decision.Allowed {
		resp.Reason = reasonGranted
		resp.MatchedRole = decision.MatchedRole
	}

	// Record BEFORE responding. If this fails we return 500 and drop the decision.
	err = a.audits.Record(r.Context(), audit.Entry{
		Caller:   caller,
		UserID:   req.UserID,
		Action:   req.Action,
		Resource: req.Resource,
		Allowed:  resp.Allowed,
		Reason:   resp.Reason,
	})
	if err != nil {
		log.Printf("httpapi: audit write failed, withholding decision: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// decodeAuthorizeRequest reads and strictly validates the request body.
func decodeAuthorizeRequest(w http.ResponseWriter, r *http.Request) (authorizeRequest, error) {
	// Tighter than the global limit; decodeJSON wraps this reader again.
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeBodyBytes)

	var req authorizeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return req, err
	}
	if err := rbac.ValidateUserID(req.UserID); err != nil {
		return req, err
	}
	if err := rbac.ValidateName("action", req.Action); err != nil {
		return req, err
	}
	if err := rbac.ValidateName("resource", req.Resource); err != nil {
		return req, fmt.Errorf("%w", err)
	}
	return req, nil
}
