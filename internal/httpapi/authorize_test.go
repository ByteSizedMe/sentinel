package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytesizedme/sentinel/internal/audit"
	"github.com/bytesizedme/sentinel/internal/rbac"
)

// seededStore returns a store with this policy:
//
//	role "editor" grants "read" on "invoices"; user u1 holds editor
//	role "viewer" grants nothing;               user u2 holds viewer
func seededStore(t *testing.T) *fakeStore {
	t.Helper()
	ctx := context.Background()
	f := newFakeStore()

	editor, _ := f.CreateRole(ctx, "editor", "")
	viewer, _ := f.CreateRole(ctx, "viewer", "")
	invoices, _ := f.CreateResource(ctx, "invoices", "")
	read, _ := f.CreatePermission(ctx, "read", invoices.ID)

	if err := f.GrantPermission(ctx, editor.ID, read.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.AssignRole(ctx, "u1", editor.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.AssignRole(ctx, "u2", viewer.ID); err != nil {
		t.Fatal(err)
	}
	return f
}

// failingCheckStore answers CheckPermission with an error. It also returns
// Allowed=true, to prove the handler ignores the decision when err != nil.
type failingCheckStore struct{ *fakeStore }

func (failingCheckStore) CheckPermission(context.Context, string, string, string) (rbac.Decision, error) {
	return rbac.Decision{Allowed: true, MatchedRole: "editor"},
		errors.New(`pq: connection to 10.0.0.5 refused (password=hunter2)`)
}

func TestAuthorize(t *testing.T) {
	const secretDetail = "hunter2"

	tests := []struct {
		name        string
		body        string
		store       func(*fakeStore) rbac.PolicyStore // nil = use the fake as is
		auditErr    error
		wantStatus  int
		wantAllowed bool   // checked only when status is 200
		wantReason  string // checked only when status is 200
		wantRole    string // checked only when status is 200
		wantAudited int    // number of audit rows expected
	}{
		{
			name:       "allow: user holds a role that grants it",
			body:       `{"user_id":"u1","action":"read","resource":"invoices"}`,
			wantStatus: 200, wantAllowed: true, wantReason: "permission granted", wantRole: "editor", wantAudited: 1,
		},
		{
			name:       "deny: user has a role but it grants nothing",
			body:       `{"user_id":"u2","action":"read","resource":"invoices"}`,
			wantStatus: 200, wantAllowed: false, wantReason: "no matching grant", wantAudited: 1,
		},
		{
			name:       "deny: unknown user",
			body:       `{"user_id":"ghost","action":"read","resource":"invoices"}`,
			wantStatus: 200, wantAllowed: false, wantReason: "no matching grant", wantAudited: 1,
		},
		{
			name:       "deny: unknown resource",
			body:       `{"user_id":"u1","action":"read","resource":"nothing"}`,
			wantStatus: 200, wantAllowed: false, wantReason: "no matching grant", wantAudited: 1,
		},
		{
			name:       "deny: unknown action",
			body:       `{"user_id":"u1","action":"launch","resource":"invoices"}`,
			wantStatus: 200, wantAllowed: false, wantReason: "no matching grant", wantAudited: 1,
		},
		{
			name:       "deny: action differs only by case",
			body:       `{"user_id":"u1","action":"READ","resource":"invoices"}`,
			wantStatus: 200, wantAllowed: false, wantReason: "no matching grant", wantAudited: 1,
		},
		{
			name:       "store error fails closed with 500 and no audit row",
			body:       `{"user_id":"u1","action":"read","resource":"invoices"}`,
			store:      func(f *fakeStore) rbac.PolicyStore { return failingCheckStore{f} },
			wantStatus: 500, wantAudited: 0,
		},
		{
			name:       "audit failure fails closed with 500",
			body:       `{"user_id":"u1","action":"read","resource":"invoices"}`,
			auditErr:   errors.New("audit database down " + secretDetail),
			wantStatus: 500, wantAudited: 0,
		},
		{
			name:       "audit failure also hides a deny decision",
			body:       `{"user_id":"ghost","action":"read","resource":"invoices"}`,
			auditErr:   errors.New("audit database down"),
			wantStatus: 500, wantAudited: 0,
		},
		// Input validation: 400 and nothing is decided or audited.
		{name: "missing user_id", body: `{"action":"read","resource":"invoices"}`, wantStatus: 400},
		{name: "missing action", body: `{"user_id":"u1","resource":"invoices"}`, wantStatus: 400},
		{name: "missing resource", body: `{"user_id":"u1","action":"read"}`, wantStatus: 400},
		{name: "empty body object", body: `{}`, wantStatus: 400},
		{name: "not json", body: `nope`, wantStatus: 400},
		{name: "unknown field", body: `{"user_id":"u1","action":"read","resource":"invoices","admin":true}`, wantStatus: 400},
		{name: "two json values", body: `{"user_id":"u1","action":"read","resource":"invoices"}{}`, wantStatus: 400},
		{name: "wrong type", body: `{"user_id":1,"action":"read","resource":"invoices"}`, wantStatus: 400},
		{name: "bad character in user_id", body: `{"user_id":"u1; DROP","action":"read","resource":"invoices"}`, wantStatus: 400},
		{name: "bad character in action", body: `{"user_id":"u1","action":"re ad","resource":"invoices"}`, wantStatus: 400},
		{name: "bad character in resource", body: `{"user_id":"u1","action":"read","resource":"inv/oices"}`, wantStatus: 400},
		{name: "user_id too long", body: `{"user_id":"` + strings.Repeat("a", 129) + `","action":"read","resource":"invoices"}`, wantStatus: 400},
		{name: "action too long", body: `{"user_id":"u1","action":"` + strings.Repeat("a", 65) + `","resource":"invoices"}`, wantStatus: 400},
		{name: "resource too long", body: `{"user_id":"u1","action":"read","resource":"` + strings.Repeat("a", 65) + `"}`, wantStatus: 400},
		{name: "body over size limit", body: `{"user_id":"u1","action":"read","resource":"invoices","pad":"` + strings.Repeat("a", maxAuthorizeBodyBytes) + `"}`, wantStatus: 413},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var store rbac.PolicyStore = seededStore(t)
			if tt.store != nil {
				store = tt.store(seededStore(t))
			}
			audits := &audit.Memory{Err: tt.auditErr}
			h := newTestRouter(t, store, audits)

			req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-caller"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
			}

			if tt.wantStatus == 200 {
				if body["allowed"] != tt.wantAllowed {
					t.Errorf("allowed = %v, want %v", body["allowed"], tt.wantAllowed)
				}
				if body["reason"] != tt.wantReason {
					t.Errorf("reason = %v, want %q", body["reason"], tt.wantReason)
				}
				role, hasRole := body["matched_role"]
				if tt.wantAllowed && role != tt.wantRole {
					t.Errorf("matched_role = %v, want %q", role, tt.wantRole)
				}
				if !tt.wantAllowed && hasRole {
					t.Error("matched_role must be absent on a denial")
				}
			} else {
				// Any failure: no decision leaks out and nothing internal is revealed.
				if _, ok := body["allowed"]; ok {
					t.Errorf("error response contains a decision: %s", rec.Body.String())
				}
				for _, leak := range []string{secretDetail, "10.0.0.5", "pq:", "audit database"} {
					if strings.Contains(rec.Body.String(), leak) {
						t.Errorf("response leaks %q: %s", leak, rec.Body.String())
					}
				}
			}

			if got := len(audits.Entries()); got != tt.wantAudited {
				t.Errorf("audit rows = %d, want %d", got, tt.wantAudited)
			}
		})
	}
}

// The audit row must record the caller (from the token) and the checked user
// (from the body) as separate things, plus the exact decision.
func TestAuthorizeAuditEntryContents(t *testing.T) {
	audits := &audit.Memory{}
	h := newTestRouter(t, seededStore(t), audits)

	do := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-billing"))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	do(`{"user_id":"u1","action":"read","resource":"invoices"}`)
	do(`{"user_id":"u2","action":"read","resource":"invoices"}`)

	want := []audit.Entry{
		{Caller: "svc-billing", UserID: "u1", Action: "read", Resource: "invoices", Allowed: true, Reason: "permission granted", Source: "db"},
		{Caller: "svc-billing", UserID: "u2", Action: "read", Resource: "invoices", Allowed: false, Reason: "no matching grant", Source: "db"},
	}
	got := audits.Entries()
	if len(got) != len(want) {
		t.Fatalf("entries = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A denial must not reveal the user's roles or anything else about policy.
func TestAuthorizeDenialDoesNotLeakPolicy(t *testing.T) {
	h := newTestRouter(t, seededStore(t), &audit.Memory{})
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize",
		strings.NewReader(`{"user_id":"u2","action":"read","resource":"invoices"}`))
	req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-caller"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, secret := range []string{"viewer", "editor", "role"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("denial body mentions %q: %s", secret, rec.Body.String())
		}
	}
}

// After the grant is removed, the same request flips from allow to deny.
func TestAuthorizeReflectsRevokedGrant(t *testing.T) {
	store := seededStore(t)
	h := newTestRouter(t, store, &audit.Memory{})
	call := func() bool {
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize",
			strings.NewReader(`{"user_id":"u1","action":"read","resource":"invoices"}`))
		req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-caller"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var r authorizeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r.Allowed
	}

	if !call() {
		t.Fatal("expected allow before revoke")
	}
	if err := store.RevokePermission(context.Background(), 1, 1); err != nil { // editor, read
		t.Fatal(err)
	}
	if call() {
		t.Error("expected deny after the grant was removed")
	}
}
