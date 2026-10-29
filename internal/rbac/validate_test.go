package rbac

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "editor", true},
		{"allowed punctuation", "billing_admin.v2:eu-west", true},
		{"max length", strings.Repeat("a", 64), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 65), false},
		{"space", "my role", false},
		{"sql-ish", "x'; DROP TABLE roles;--", false},
		{"unicode", "rôle", false},
		{"newline", "a\nb", false},
		{"at sign not allowed", "a@b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName("name", tt.input)
			if tt.valid && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrInvalidInput) {
				t.Errorf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestValidateUserID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "u1", true},
		{"email", "alice@example.com", true},
		{"uuid", "123e4567-e89b-12d3-a456-426614174000", true},
		{"max length", strings.Repeat("a", 128), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 129), false},
		{"slash", "a/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserID(tt.input)
			if tt.valid != (err == nil) {
				t.Errorf("valid = %v, err = %v", tt.valid, err)
			}
		})
	}
}

func TestValidateDescription(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"empty is fine", "", true},
		{"normal text", "Can edit documents (not delete).", true},
		{"max length", strings.Repeat("é", 256), true},
		{"too long", strings.Repeat("a", 257), false},
		{"control char", "bad\x00text", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDescription(tt.input); tt.valid != (err == nil) {
				t.Errorf("valid = %v, err = %v", tt.valid, err)
			}
		})
	}
}
