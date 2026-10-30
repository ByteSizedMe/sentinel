// Package config loads Sentinel's settings from environment variables.
package config

import (
	"errors"
	"strings"
)

// MinJWTSecretLen is the shortest JWT_SECRET we accept (in bytes). HS256 uses
// a 256-bit key, so anything shorter than 32 bytes weakens the signature.
const MinJWTSecretLen = 32

// Config holds every setting the service needs. No hosts or paths are
// hard-coded elsewhere; they all come from here.
type Config struct {
	Addr        string // HTTP listen address, e.g. ":8080"
	DatabaseURL string // PostgreSQL connection string (secret: never log it)
	RedisAddr   string // Redis host:port

	JWTSecret   string // HS256 signing key (secret: never log it)
	JWTIssuer   string // required "iss" claim value
	JWTAudience string // required "aud" claim value
}

// Errors returned by Load for missing or weak required settings.
var (
	ErrMissingDatabaseURL = errors.New("config: DATABASE_URL is required")
	ErrMissingJWTSecret   = errors.New("config: JWT_SECRET is required")
	ErrWeakJWTSecret      = errors.New("config: JWT_SECRET must be at least 32 characters")
	ErrMissingJWTIssuer   = errors.New("config: JWT_ISSUER is required")
	ErrMissingJWTAudience = errors.New("config: JWT_AUDIENCE is required")
)

// Load builds a Config using getenv to read variables. Passing the lookup
// function in (instead of calling os.Getenv directly) lets tests supply a
// fake environment without touching the real one.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        valueOr(getenv("SENTINEL_ADDR"), ":8080"),
		DatabaseURL: strings.TrimSpace(getenv("DATABASE_URL")),
		RedisAddr:   valueOr(getenv("REDIS_ADDR"), "localhost:6379"),
		JWTSecret:   strings.TrimSpace(getenv("JWT_SECRET")),
		JWTIssuer:   strings.TrimSpace(getenv("JWT_ISSUER")),
		JWTAudience: strings.TrimSpace(getenv("JWT_AUDIENCE")),
	}

	// None of these have a default on purpose: silently falling back to some
	// database, or to a well-known signing key, would be a security risk.
	switch {
	case cfg.DatabaseURL == "":
		return Config{}, ErrMissingDatabaseURL
	case cfg.JWTSecret == "":
		return Config{}, ErrMissingJWTSecret
	case len(cfg.JWTSecret) < MinJWTSecretLen:
		return Config{}, ErrWeakJWTSecret
	case cfg.JWTIssuer == "":
		return Config{}, ErrMissingJWTIssuer
	case cfg.JWTAudience == "":
		return Config{}, ErrMissingJWTAudience
	}
	return cfg, nil
}

// valueOr returns def when v is empty or only whitespace.
func valueOr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}
