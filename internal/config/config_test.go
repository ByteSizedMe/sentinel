package config

import (
	"errors"
	"strings"
	"testing"
)

// validSecret is exactly the minimum length.
var validSecret = strings.Repeat("s", MinJWTSecretLen)

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
				RedisAddr:   "localhost:6379",
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
		{
			name: "all values overridden",
			env: baseEnv(map[string]string{
				"SENTINEL_ADDR": ":9090",
				"DATABASE_URL":  "postgres://x",
				"REDIS_ADDR":    "redis:6380",
			}),
			want: Config{
				Addr:        ":9090",
				DatabaseURL: "postgres://x",
				RedisAddr:   "redis:6380",
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
		{
			name: "blank optional values fall back to defaults",
			env:  baseEnv(map[string]string{"SENTINEL_ADDR": "  ", "REDIS_ADDR": ""}),
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgres://u:p@localhost:5433/db",
				RedisAddr:   "localhost:6379",
				JWTSecret:   validSecret,
				JWTIssuer:   "sentinel-test",
				JWTAudience: "sentinel-api",
			},
		},
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
