package rbac

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Length limits, enforced before anything reaches the database.
const (
	maxNameLen        = 64
	maxDescriptionLen = 256
	maxUserIDLen      = 128
)

// ValidateName checks role/resource names and permission actions:
// 1-64 characters from letters, digits and _ . : -
func ValidateName(field, v string) error {
	return validateToken(field, v, maxNameLen, false)
}

// ValidateUserID is like ValidateName but also allows @ (emails) and a longer length.
func ValidateUserID(v string) error {
	return validateToken("user_id", v, maxUserIDLen, true)
}

// ValidateDescription allows empty text up to 256 characters, with no control characters.
func ValidateDescription(v string) error {
	if utf8.RuneCountInString(v) > maxDescriptionLen {
		return fmt.Errorf("%w: description must be at most %d characters", ErrInvalidInput, maxDescriptionLen)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: description must not contain control characters", ErrInvalidInput)
		}
	}
	return nil
}

// validateToken uses an allow-list of characters (safer than trying to block bad ones).
func validateToken(field, v string, max int, allowAt bool) error {
	if v == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidInput, field)
	}
	if len(v) > max { // len counts bytes; only ASCII is allowed, so bytes == characters
		return fmt.Errorf("%w: %s must be at most %d characters", ErrInvalidInput, field, max)
	}
	for _, r := range v {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '.' || r == ':' || r == '-' || (allowAt && r == '@')
		if !ok {
			return fmt.Errorf("%w: %s contains an invalid character", ErrInvalidInput, field)
		}
	}
	return nil
}
