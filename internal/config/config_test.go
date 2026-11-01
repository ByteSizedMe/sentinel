package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validSecret is exactly the minimum length.
var validSecret = strings.Repeat("s", MinJWTSecretLen)

// defaultRateLimit is what Load returns when no RATE_LIMIT_* variable is set.
var defaultRateLimit = RateLimit{IPRPS: 20, IPBurst: 40, CallerRPS: 50, CallerBurst: 100, MaxKeys: 10000}

// baseEnv returns a complete, valid environment; tests override single keys.
func baseEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"DATABASE_URL": "postgres://u:p@localhost:5433/db",
		"JWT_SECRET":   validSecret,
		"JWT_ISSUER":   "sentinel-test",
		"JWT_AUDIENCE": "sentinel-api",
	}
	for k, v := range overrides {
		env[k] = v
	}
	return env
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr error
	}{
		{
			name: "defaults applied when only required values set",
			env:  baseEnv(nil),
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgres://u:p@localhost:5433/db",
				RedisURL:    "redis://localhost:6379/0",
				CacheTTL:    60 * time.Second,
				RateLimit:   defaultRateLimit,
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
		{
			name: "all values overridden",
			env: baseEnv(map[string]string{
				"SENTINEL_ADDR":     ":9090",
				"DATABASE_URL":      "postgres://x",
				"REDIS_URL":         "redis://redis:6380/1",
				"CACHE_TTL_SECONDS": "5",
			}),
			want: Config{
				Addr:        ":9090",
				DatabaseURL: "postgres://x",
				RedisURL:    "redis://redis:6380/1",
				CacheTTL:    5 * time.Second,
				RateLimit:   defaultRateLimit,
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
		{
			name: "blank optional values fall back to defaults",
			env:  baseEnv(map[string]string{"SENTINEL_ADDR": "  ", "REDIS_URL": ""}),
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgres://u:p@localhost:5433/db",
				RedisURL:    "redis://localhost:6379/0",
				CacheTTL:    60 * time.Second,
				RateLimit:   defaultRateLimit,
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
		{"cache disabled with 0", baseEnv(map[string]string{"CACHE_TTL_SECONDS": "0"}), Config{
			Addr: ":8080", DatabaseURL: "postgres://u:p@localhost:5433/db", RedisURL: "redis://localhost:6379/0",
			CacheTTL: 0, RateLimit: defaultRateLimit, JWTSecret: validSecret, JWTIssuer: "sentinel-test", JWTAudience: "sentinel-api",
		}, nil},
		{"CACHE_TTL_SECONDS not a number", baseEnv(map[string]string{"CACHE_TTL_SECONDS": "soon"}), Config{}, ErrInvalidCacheTTL},
		{"CACHE_TTL_SECONDS negative", baseEnv(map[string]string{"CACHE_TTL_SECONDS": "-1"}), Config{}, ErrInvalidCacheTTL},
		{"CACHE_TTL_SECONDS too large", baseEnv(map[string]string{"CACHE_TTL_SECONDS": "3601"}), Config{}, ErrInvalidCacheTTL},
		{"CACHE_TTL_SECONDS fractional", baseEnv(map[string]string{"CACHE_TTL_SECONDS": "1.5"}), Config{}, ErrInvalidCacheTTL},
		{"missing DATABASE_URL", baseEnv(map[string]string{"DATABASE_URL": ""}), Config{}, ErrMissingDatabaseURL},
		{"whitespace-only DATABASE_URL", baseEnv(map[string]string{"DATABASE_URL": "   "}), Config{}, ErrMissingDatabaseURL},
		{"missing JWT_SECRET", baseEnv(map[string]string{"JWT_SECRET": ""}), Config{}, ErrMissingJWTSecret},
		{"JWT_SECRET one char too short", baseEnv(map[string]string{"JWT_SECRET": validSecret[:MinJWTSecretLen-1]}), Config{}, ErrWeakJWTSecret},
		{"placeholder JWT_SECRET is rejected", baseEnv(map[string]string{"JWT_SECRET": "change-me"}), Config{}, ErrWeakJWTSecret},
		{"missing JWT_ISSUER", baseEnv(map[string]string{"JWT_ISSUER": ""}), Config{}, ErrMissingJWTIssuer},
		{"missing JWT_AUDIENCE", baseEnv(map[string]string{"JWT_AUDIENCE": " "}), Config{}, ErrMissingJWTAudience},
		{"nothing set at all", map[string]string{}, Config{}, ErrMissingDatabaseURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(func(k string) string { return tt.env[k] })
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("config = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadRateLimit(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    RateLimit
		wantErr string // name of the variable the error must mention; "" = must succeed
	}{
		{"defaults", nil, defaultRateLimit, ""},
		{"all overridden", map[string]string{
			"RATE_LIMIT_IP_RPS": "5", "RATE_LIMIT_IP_BURST": "10",
			"RATE_LIMIT_CALLER_RPS": "7", "RATE_LIMIT_CALLER_BURST": "9",
			"RATE_LIMIT_MAX_KEYS": "500",
		}, RateLimit{IPRPS: 5, IPBurst: 10, CallerRPS: 7, CallerBurst: 9, MaxKeys: 500}, ""},
		{"blank values use the defaults", map[string]string{"RATE_LIMIT_IP_RPS": "  ", "RATE_LIMIT_MAX_KEYS": ""}, defaultRateLimit, ""},
		{"IP limiter off with RPS 0", map[string]string{"RATE_LIMIT_IP_RPS": "0"},
			RateLimit{IPRPS: 0, IPBurst: 40, CallerRPS: 50, CallerBurst: 100, MaxKeys: 10000}, ""},
		{"caller limiter off with RPS 0", map[string]string{"RATE_LIMIT_CALLER_RPS": "0"},
			RateLimit{IPRPS: 20, IPBurst: 40, CallerRPS: 0, CallerBurst: 100, MaxKeys: 10000}, ""},
		{"burst 0 is fine while that limiter is off", map[string]string{"RATE_LIMIT_IP_RPS": "0", "RATE_LIMIT_IP_BURST": "0"},
			RateLimit{IPRPS: 0, IPBurst: 0, CallerRPS: 50, CallerBurst: 100, MaxKeys: 10000}, ""},
		{"MAX_KEYS exactly the minimum", map[string]string{"RATE_LIMIT_MAX_KEYS": "100"},
			RateLimit{IPRPS: 20, IPBurst: 40, CallerRPS: 50, CallerBurst: 100, MaxKeys: 100}, ""},

		{"IP RPS not a number", map[string]string{"RATE_LIMIT_IP_RPS": "fast"}, RateLimit{}, "RATE_LIMIT_IP_RPS"},
		{"IP RPS negative", map[string]string{"RATE_LIMIT_IP_RPS": "-1"}, RateLimit{}, "RATE_LIMIT_IP_RPS"},
		{"IP RPS fractional", map[string]string{"RATE_LIMIT_IP_RPS": "1.5"}, RateLimit{}, "RATE_LIMIT_IP_RPS"},
		{"IP RPS absurdly large", map[string]string{"RATE_LIMIT_IP_RPS": "1000001"}, RateLimit{}, "RATE_LIMIT_IP_RPS"},
		{"IP burst not a number", map[string]string{"RATE_LIMIT_IP_BURST": "lots"}, RateLimit{}, "RATE_LIMIT_IP_BURST"},
		{"IP burst negative", map[string]string{"RATE_LIMIT_IP_BURST": "-5"}, RateLimit{}, "RATE_LIMIT_IP_BURST"},
		{"IP burst below 1 while enabled", map[string]string{"RATE_LIMIT_IP_BURST": "0"}, RateLimit{}, "RATE_LIMIT_IP_BURST"},
		{"caller RPS not a number", map[string]string{"RATE_LIMIT_CALLER_RPS": "x"}, RateLimit{}, "RATE_LIMIT_CALLER_RPS"},
		{"caller RPS negative", map[string]string{"RATE_LIMIT_CALLER_RPS": "-2"}, RateLimit{}, "RATE_LIMIT_CALLER_RPS"},
		{"caller burst not a number", map[string]string{"RATE_LIMIT_CALLER_BURST": "?"}, RateLimit{}, "RATE_LIMIT_CALLER_BURST"},
		{"caller burst negative", map[string]string{"RATE_LIMIT_CALLER_BURST": "-1"}, RateLimit{}, "RATE_LIMIT_CALLER_BURST"},
		{"caller burst below 1 while enabled", map[string]string{"RATE_LIMIT_CALLER_BURST": "0"}, RateLimit{}, "RATE_LIMIT_CALLER_BURST"},
		{"MAX_KEYS not a number", map[string]string{"RATE_LIMIT_MAX_KEYS": "many"}, RateLimit{}, "RATE_LIMIT_MAX_KEYS"},
		{"MAX_KEYS negative", map[string]string{"RATE_LIMIT_MAX_KEYS": "-100"}, RateLimit{}, "RATE_LIMIT_MAX_KEYS"},
		{"MAX_KEYS below 100", map[string]string{"RATE_LIMIT_MAX_KEYS": "99"}, RateLimit{}, "RATE_LIMIT_MAX_KEYS"},
		{"MAX_KEYS zero", map[string]string{"RATE_LIMIT_MAX_KEYS": "0"}, RateLimit{}, "RATE_LIMIT_MAX_KEYS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv(tt.env)
			got, err := Load(func(k string) string { return env[k] })

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.RateLimit != tt.want {
					t.Errorf("RateLimit = %+v, want %+v", got.RateLimit, tt.want)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRateLimit) {
				t.Fatalf("error = %v, want ErrInvalidRateLimit", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not name %s", err, tt.wantErr)
			}
			if got != (Config{}) {
				t.Errorf("config = %+v on error, want the zero Config", got)
			}
			// The message names the variable but never echoes what was set.
			for _, v := range env {
				if v != "" && len(v) > 2 && strings.Contains(err.Error(), v) {
					t.Errorf("error %q echoes the value %q", err, v)
				}
			}
		})
	}
}
