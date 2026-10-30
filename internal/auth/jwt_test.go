package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret   = "test-secret-that-is-at-least-32-bytes-long"
	testIssuer   = "sentinel-test"
	testAudience = "sentinel-api"
)

// claimsFor builds valid claims; tests tweak one field at a time.
func claimsFor(mutate func(*jwt.RegisteredClaims)) jwt.RegisteredClaims {
	c := jwt.RegisteredClaims{
		Issuer:    testIssuer,
		Subject:   "svc-a",
		Audience:  jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

// sign signs claims with the given method and key.
func sign(t *testing.T, method jwt.SigningMethod, key any, c jwt.RegisteredClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, c).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestValidateToken(t *testing.T) {
	v, err := NewValidator(testSecret, testIssuer, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(testSecret)

	tests := []struct {
		name      string
		token     string
		wantSub   string
		wantCause error // specific reason expected inside ErrInvalidToken; nil = must succeed
	}{
		{
			name:    "valid token",
			token:   sign(t, jwt.SigningMethodHS256, key, claimsFor(nil)),
			wantSub: "svc-a",
		},
		{
			name: "expired within clock skew is still accepted",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Second))
			})),
			wantSub: "svc-a",
		},
		{
			name: "expired beyond clock skew",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			})),
			wantCause: jwt.ErrTokenExpired,
		},
		{
			name:      "wrong signature (different secret)",
			token:     sign(t, jwt.SigningMethodHS256, []byte("another-secret-that-is-also-32-bytes-long"), claimsFor(nil)),
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "wrong issuer",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.Issuer = "someone-else"
			})),
			wantCause: jwt.ErrTokenInvalidIssuer,
		},
		{
			name: "missing issuer",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.Issuer = ""
			})),
			wantCause: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "wrong audience",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.Audience = jwt.ClaimStrings{"other-api"}
			})),
			wantCause: jwt.ErrTokenInvalidAudience,
		},
		{
			name: "missing audience",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.Audience = nil
			})),
			wantCause: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "missing exp",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.ExpiresAt = nil
			})),
			wantCause: jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name: "missing subject",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.Subject = ""
			})),
			wantCause: ErrInvalidToken,
		},
		{
			name: "not yet valid (nbf in the future)",
			token: sign(t, jwt.SigningMethodHS256, key, claimsFor(func(c *jwt.RegisteredClaims) {
				c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
			})),
			wantCause: jwt.ErrTokenNotValidYet,
		},
		{
			// An unsigned token claiming alg "none". Must never be accepted.
			name:      "alg none",
			token:     sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claimsFor(nil)),
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{
			// Signed with the CORRECT secret but a different HMAC algorithm.
			// If the allow-list were missing this would validate, so rejection
			// proves the algorithm check works.
			name:      "wrong algorithm HS384 with correct secret",
			token:     sign(t, jwt.SigningMethodHS384, key, claimsFor(nil)),
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{
			name:      "wrong algorithm HS512 with correct secret",
			token:     sign(t, jwt.SigningMethodHS512, key, claimsFor(nil)),
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{
			// Algorithm confusion: header says RS256 (asymmetric) but there is
			// no real RSA signature. Must be rejected before any key is used.
			name:      "alg RS256 header",
			token:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYSJ9.AAAA",
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "tampered payload",
			token: func() string {
				parts := strings.Split(sign(t, jwt.SigningMethodHS256, key, claimsFor(nil)), ".")
				// Replace the payload with a different (valid base64) one.
				parts[1] = "eyJzdWIiOiJhZG1pbiJ9"
				return strings.Join(parts, ".")
			}(),
			wantCause: jwt.ErrTokenSignatureInvalid,
		},
		{name: "garbage", token: "not-a-jwt", wantCause: jwt.ErrTokenMalformed},
		{name: "empty", token: "", wantCause: jwt.ErrTokenMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := v.ValidateToken(tt.token)

			if tt.wantCause == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if sub != tt.wantSub {
					t.Errorf("subject = %q, want %q", sub, tt.wantSub)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error = %v, want ErrInvalidToken", err)
			}
			if !errors.Is(err, tt.wantCause) {
				t.Errorf("error = %v, want cause %v", err, tt.wantCause)
			}
			if sub != "" {
				t.Errorf("subject = %q on failure, want empty", sub)
			}
		})
	}
}

func TestNewValidatorRequiresAllSettings(t *testing.T) {
	tests := []struct{ name, secret, iss, aud string }{
		{"no secret", "", "i", "a"},
		{"no issuer", "s", "", "a"},
		{"no audience", "s", "i", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewValidator(tt.secret, tt.iss, tt.aud); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// Tokens made by Mint must pass the validator (this is what cmd/tokengen uses).
func TestMintRoundTrip(t *testing.T) {
	v, _ := NewValidator(testSecret, testIssuer, testAudience)
	tok, err := Mint(testSecret, testIssuer, testAudience, "svc-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := v.ValidateToken(tok)
	if err != nil || sub != "svc-b" {
		t.Errorf("ValidateToken = %q, %v; want svc-b, nil", sub, err)
	}
}
