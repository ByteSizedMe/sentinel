// Package config loads Sentinel's settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bytesizedme/sentinel/internal/clientip"
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

// Rate limit defaults and bounds. A requests-per-second value of 0 turns that
// limiter off. The upper bound only catches typos that would overflow.
const (
	DefaultIPRPS        = 20
	DefaultIPBurst      = 40
	DefaultCallerRPS    = 50
	DefaultCallerBurst  = 100
	DefaultRateMaxKeys  = 10000
	MinRateMaxKeys      = 100
	maxRateLimitSetting = 1_000_000
)

// RateLimit holds the settings of the two in-process limiters (see
// internal/ratelimit): one per client IP before authentication, one per caller
// (JWT subject) after it.
type RateLimit struct {
	IPRPS       int // requests per second per IP; 0 disables the IP limiter
	IPBurst     int // requests an IP may send at once
	CallerRPS   int // requests per second per caller; 0 disables the caller limiter
	CallerBurst int // requests a caller may send at once
	MaxKeys     int // most IPs (and most callers) tracked at once
}

// Config holds every setting the service needs. No hosts or paths are
// hard-coded elsewhere; they all come from here.
type Config struct {
	Addr        string        // HTTP listen address, e.g. ":8080"
	DatabaseURL string        // PostgreSQL connection string (secret: never log it)
	RedisURL    string        // Redis connection URL (may contain a password: never log it)
	CacheTTL    time.Duration // how long a cached decision lives; 0 disables the cache

	RateLimit RateLimit

	// AllowPrivilegedDBRole lets the server start even though DATABASE_URL
	// connects as a superuser or the audit_log owner. Local development only.
	AllowPrivilegedDBRole bool

	// TrustedProxies are the proxies whose X-Forwarded-For header the per-IP rate
	// limiter believes. Nil (the default) trusts nobody.
	TrustedProxies *clientip.Trusted

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

	// ErrInvalidRateLimit is wrapped with the name of the offending variable.
	// The message never includes the value that was set.
	ErrInvalidRateLimit = errors.New("config: invalid rate limit setting")

	ErrInvalidAllowPrivileged = errors.New("config: ALLOW_PRIVILEGED_DB_ROLE must be true or false")

	// ErrInvalidTrustedProxies wraps the reason from clientip.Parse. The message
	// never includes the list that was set.
	ErrInvalidTrustedProxies = errors.New("config: invalid TRUSTED_PROXIES")
)

// Load builds a Config using getenv to read variables. Passing the lookup
// function in (instead of calling os.Getenv directly) lets tests supply a
// fake environment without touching the real one.
func Load(getenv func(string) string) (Config, error) {
	ttl, err := parseCacheTTL(getenv("CACHE_TTL_SECONDS"))
	if err != nil {
		return Config{}, err
	}
	limits, err := parseRateLimit(getenv)
	if err != nil {
		return Config{}, err
	}
	proxies, err := clientip.Parse(getenv("TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %w", ErrInvalidTrustedProxies, err)
	}
	allowPrivileged, err := parseAllowPrivileged(getenv("ALLOW_PRIVILEGED_DB_ROLE"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		AllowPrivilegedDBRole: allowPrivileged,
		RateLimit:             limits,
		TrustedProxies:        proxies,
		Addr:                  valueOr(getenv("SENTINEL_ADDR"), ":8080"),
		DatabaseURL:           strings.TrimSpace(getenv("DATABASE_URL")),
		RedisURL:              valueOr(getenv("REDIS_URL"), "redis://localhost:6379/0"),
		CacheTTL:              ttl,
		JWTSecret:             strings.TrimSpace(getenv("JWT_SECRET")),
		JWTIssuer:             strings.TrimSpace(getenv("JWT_ISSUER")),
		JWTAudience:           strings.TrimSpace(getenv("JWT_AUDIENCE")),
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

// parseAllowPrivileged reads ALLOW_PRIVILEGED_DB_ROLE. Only an exact "true"
// turns the override on; empty means off, and anything else is an error rather
// than a guess, so a typo cannot quietly change the safety setting either way.
func parseAllowPrivileged(v string) (bool, error) {
	switch strings.TrimSpace(v) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, ErrInvalidAllowPrivileged
}

// valueOr returns def when v is empty or only whitespace.
func valueOr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// parseRateLimit reads the RATE_LIMIT_* variables. Like the cache TTL, a value
// that is not valid is an error and never a silent default, so a typo cannot
// quietly turn a limit off or make it absurdly loose. Errors name the variable
// and the rule, not the value.
func parseRateLimit(getenv func(string) string) (RateLimit, error) {
	var rl RateLimit
	fields := []struct {
		name string
		def  int
		dst  *int
	}{
		{"RATE_LIMIT_IP_RPS", DefaultIPRPS, &rl.IPRPS},
		{"RATE_LIMIT_IP_BURST", DefaultIPBurst, &rl.IPBurst},
		{"RATE_LIMIT_CALLER_RPS", DefaultCallerRPS, &rl.CallerRPS},
		{"RATE_LIMIT_CALLER_BURST", DefaultCallerBurst, &rl.CallerBurst},
		{"RATE_LIMIT_MAX_KEYS", DefaultRateMaxKeys, &rl.MaxKeys},
	}
	for _, f := range fields {
		n, err := parseWholeNumber(getenv(f.name), f.def)
		if err != nil {
			return RateLimit{}, fmt.Errorf("%w: %s must be a whole number from 0 to %d", ErrInvalidRateLimit, f.name, maxRateLimitSetting)
		}
		*f.dst = n
	}

	// A burst below 1 would refuse everything, so it is only allowed while the
	// limiter it belongs to is off (RPS 0).
	if rl.IPRPS > 0 && rl.IPBurst < 1 {
		return RateLimit{}, fmt.Errorf("%w: RATE_LIMIT_IP_BURST must be at least 1 when RATE_LIMIT_IP_RPS is above 0", ErrInvalidRateLimit)
	}
	if rl.CallerRPS > 0 && rl.CallerBurst < 1 {
		return RateLimit{}, fmt.Errorf("%w: RATE_LIMIT_CALLER_BURST must be at least 1 when RATE_LIMIT_CALLER_RPS is above 0", ErrInvalidRateLimit)
	}
	if rl.MaxKeys < MinRateMaxKeys {
		return RateLimit{}, fmt.Errorf("%w: RATE_LIMIT_MAX_KEYS must be at least %d", ErrInvalidRateLimit, MinRateMaxKeys)
	}
	return rl, nil
}

// parseWholeNumber returns def for an empty value, and an error for anything
// that is not a whole number from 0 to maxRateLimitSetting.
func parseWholeNumber(v string, def int) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > maxRateLimitSetting {
		return 0, ErrInvalidRateLimit
	}
	return n, nil
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
