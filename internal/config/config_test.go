package config

import (
	"errors"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr error
	}{
		{
			name: "defaults applied when only DATABASE_URL set",
			env:  map[string]string{"DATABASE_URL": "postgres://u:p@localhost:5433/db"},
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgres://u:p@localhost:5433/db",
				RedisAddr:   "localhost:6379",
			},
		},
		{
			name: "all values overridden",
			env: map[string]string{
				"SENTINEL_ADDR": ":9090",
				"DATABASE_URL":  "postgres://x",
				"REDIS_ADDR":    "redis:6380",
			},
			want: Config{Addr: ":9090", DatabaseURL: "postgres://x", RedisAddr: "redis:6380"},
		},
		{
			name: "blank optional values fall back to defaults",
			env:  map[string]string{"DATABASE_URL": "postgres://x", "SENTINEL_ADDR": "  ", "REDIS_ADDR": ""},
			want: Config{Addr: ":8080", DatabaseURL: "postgres://x", RedisAddr: "localhost:6379"},
		},
		{
			name:    "missing DATABASE_URL is an error",
			env:     map[string]string{},
			wantErr: ErrMissingDatabaseURL,
		},
		{
			name:    "whitespace-only DATABASE_URL is an error",
			env:     map[string]string{"DATABASE_URL": "   "},
			wantErr: ErrMissingDatabaseURL,
		},
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
