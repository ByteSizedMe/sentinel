// Package config loads Sentinel's settings from environment variables.
package config

import (
	"errors"
	"strings"
)

// Config holds every setting the service needs. No hosts or paths are
// hard-coded elsewhere; they all come from here.
type Config struct {
	Addr        string // HTTP listen address, e.g. ":8080"
	DatabaseURL string // PostgreSQL connection string (secret: never log it)
	RedisAddr   string // Redis host:port
}

// ErrMissingDatabaseURL is returned when DATABASE_URL is unset or blank.
var ErrMissingDatabaseURL = errors.New("config: DATABASE_URL is required")

// Load builds a Config using getenv to read variables. Passing the lookup
// function in (instead of calling os.Getenv directly) lets tests supply a
// fake environment without touching the real one.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        valueOr(getenv("SENTINEL_ADDR"), ":8080"),
		DatabaseURL: strings.TrimSpace(getenv("DATABASE_URL")),
		RedisAddr:   valueOr(getenv("REDIS_ADDR"), "localhost:6379"),
	}

	// DATABASE_URL has no default on purpose: silently falling back to some
	// database would be a security and correctness risk.
	if cfg.DatabaseURL == "" {
		return Config{}, ErrMissingDatabaseURL
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
