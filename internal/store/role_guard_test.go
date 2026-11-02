package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeRow and fakeQuerier stand in for the database.
type fakeRow struct {
	super, owner bool
	err          error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.super
	*dest[1].(*bool) = r.owner
	return nil
}

type fakeQuerier struct{ row fakeRow }

func (q fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return q.row }

func TestCheckRole(t *testing.T) {
	tests := []struct {
		name         string
		super, owner bool
		allow        bool
		wantErr      bool
		wantWarning  bool
		wantInErr    string
	}{
		{"normal role starts", false, false, false, false, false, ""},
		{"normal role with the override set is silent", false, false, true, false, false, ""},
		{"superuser is refused", true, false, false, true, false, "a superuser"},
		{"owner is refused", false, true, false, true, false, "the owner of audit_log"},
		{"superuser and owner is refused", true, true, false, true, false, "a superuser and the owner"},
		{"superuser with the override warns", true, false, true, false, true, ""},
		{"owner with the override warns", false, true, true, false, true, ""},
		{"both with the override warns", true, true, true, false, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warn, err := CheckRole(context.Background(), fakeQuerier{fakeRow{super: tt.super, owner: tt.owner}}, tt.allow)
			if tt.wantErr {
				if !errors.Is(err, ErrPrivilegedRole) {
					t.Fatalf("error = %v, want ErrPrivilegedRole", err)
				}
				if !strings.Contains(err.Error(), tt.wantInErr) {
					t.Errorf("error %q does not contain %q", err, tt.wantInErr)
				}
				if warn != "" {
					t.Errorf("warning %q returned alongside an error", warn)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if (warn != "") != tt.wantWarning {
				t.Errorf("warning = %q, wantWarning = %v", warn, tt.wantWarning)
			}
			if strings.ContainsAny(warn, "\n\r") || strings.Contains(warn, "://") {
				t.Errorf("warning must be one plain line, got %q", warn)
			}
		})
	}
}

// A failed check is an error, never a pass: the service does not start blind.
func TestCheckRoleQueryFailureFailsClosed(t *testing.T) {
	boom := errors.New("connection reset")
	for _, allow := range []bool{false, true} {
		warn, err := CheckRole(context.Background(), fakeQuerier{fakeRow{err: boom}}, allow)
		if !errors.Is(err, boom) || warn != "" {
			t.Errorf("allow=%v: warning=%q err=%v, want the query error", allow, warn, err)
		}
	}
}

// The error text names no connection string or password.
func TestCheckRoleMessageHasNoSecrets(t *testing.T) {
	_, err := CheckRole(context.Background(), fakeQuerier{fakeRow{super: true}}, false)
	for _, bad := range []string{"postgres://", "password", "@"} {
		if strings.Contains(strings.ToLower(err.Error()), bad) {
			t.Errorf("error %q contains %q", err, bad)
		}
	}
}
