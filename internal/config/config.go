// Package config loads Sentinel's settings from environment variables.
package config

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// MinJWTSecretLen is the shortest JWT_SECRET we accept (in bytes). HS256 uses
// a 256-bit key, so anything shorter than 32 bytes weakens the signature.
const MinJWTSecretLen = 32

// Cache TTL bounds. 0 turns the cache off. The upper limit keeps a stale
// entry (the worst case if invalidation ever failed) from living long.
const (
	DefaultCacheTTLSeconds = 60
	MaxCacheTTLSeconds     = 3600
)

// Config holds every setting the service needs. No hosts or paths are
// hard-coded elsewhere; they all come from here.
type Config struct {
	Addr        string        // HTTP listen address, e.g. ":8080"
	DatabaseURL string        // PostgreSQL connection string (secret: never log it)
	RedisURL    string        // Redis connection URL (may contain a password: never log it)
	CacheTTL    time.Duration // how long a cached decision lives; 0 disables the cache

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
	ErrInvalidCacheTTL    = errors.New("config: CACHE_TTL_SECONDS must be a whole number from 0 to 3600")
)

// Load builds a Config using getenv to read variables. Passing the lookup
// function in (instead of calling os.Getenv directly) lets tests supply a
// fake environment without touching the real one.
func Load(getenv func(string) string) (Config, error) {
	ttl, err := parseCacheTTL(getenv("CACHE_TTL_SECONDS"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Addr:        valueOr(getenv("SENTINEL_ADDR"), ":8080"),
		DatabaseURL: strings.TrimSpace(getenv("DATABASE_URL")),
		RedisURL:    valueOr(getenv("REDIS_URL"), "redis://localhost:6379/0"),
		CacheTTL:    ttl,
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

// parseCacheTTL reads CACHE_TTL_SECONDS. Empty means the default; anything
// that is not a whole number in range is an error rather than a silent default,
// so a typo cannot quietly change how long permissions are cached.
func parseCacheTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return DefaultCacheTTLSeconds * time.Second, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > MaxCacheTTLSeconds {
		return 0, ErrInvalidCacheTTL
	}
	return time.Duration(n) * time.Second, nil
}
