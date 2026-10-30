// Package auth validates JWTs and protects routes with them.
//
// The caller of Sentinel is a service holding a signed token. The token only
// tells us WHO IS ASKING (the "sub" claim); it never decides which user an
// authorization check is about.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// clockSkew is how far our clock and the token issuer's clock may disagree
// before exp/nbf checks fail.
const clockSkew = 30 * time.Second

// ErrInvalidToken is returned for every token failure. Callers get this one
// generic error; the wrapped cause is only for tests and debugging and must
// never be sent to clients.
var ErrInvalidToken = errors.New("auth: invalid token")

// Validator checks tokens against one signing key, issuer and audience.
type Validator struct {
	secret []byte
	parser *jwt.Parser
}

// NewValidator builds a Validator. All three arguments are required.
// (Minimum secret length is enforced earlier, when config is loaded.)
func NewValidator(secret, issuer, audience string) (*Validator, error) {
	if secret == "" || issuer == "" || audience == "" {
		return nil, errors.New("auth: secret, issuer and audience are all required")
	}
	return &Validator{
		secret: []byte(secret),
		parser: jwt.NewParser(
			// Allow-list of algorithms: ONLY HS256. This is what blocks
			// alg "none" and "algorithm confusion" attacks, where an attacker
			// picks a weaker algorithm than the one we intended.
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(), // a token with no exp would live forever
			jwt.WithIssuer(issuer),
			jwt.WithAudience(audience),
			jwt.WithLeeway(clockSkew),
		),
	}, nil
}

// ValidateToken verifies the signature, algorithm, exp, iss and aud of a raw
// token string and returns its subject (the caller's identity).
// Any failure returns an error wrapping ErrInvalidToken.
func (v *Validator) ValidateToken(raw string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := v.parser.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		// Only reached after the algorithm allow-list check passed.
		return v.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	// We use the subject as the caller identity, so it must exist.
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	return claims.Subject, nil
}

// Mint creates a signed HS256 token. It exists for local development
// (cmd/tokengen) and for tests; the server itself never mints tokens.
func Mint(secret, issuer, audience, subject string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}
