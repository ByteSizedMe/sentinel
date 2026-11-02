//go:build integration

package integration

import (
	"fmt"
	"testing"
)

// recorder is a testing.TB that remembers whether the test was failed or
// skipped, so the decision in skipOrFail can be checked without ending the
// real test. FailNow and SkipNow end the goroutine, as the real ones do.
type recorder struct {
	testing.TB
	failed, skipped bool
	msg             string
}

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed, r.msg = true, fmt.Sprintf(format, args...)
	panic(r)
}
func (r *recorder) Skipf(format string, args ...any) {
	r.skipped, r.msg = true, fmt.Sprintf(format, args...)
	panic(r)
}

// run calls skipOrFail and recovers the panic the recorder uses to stop it.
func run(r *recorder) {
	defer func() { _ = recover() }()
	skipOrFail(r, "%s is not set", "APP_DATABASE_URL")
}

func TestSkipOrFail(t *testing.T) {
	tests := []struct {
		name               string
		ci                 string
		wantFail, wantSkip bool
	}{
		{"CI=true fails", "true", true, false},
		{"CI unset skips", "", false, true},
		{"CI=false skips", "false", false, true},
		{"CI=1 is not the GitHub value and skips", "1", false, true},
		{"CI=TRUE is not the GitHub value and skips", "TRUE", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CI", tt.ci)
			r := &recorder{}
			run(r)
			if r.failed != tt.wantFail || r.skipped != tt.wantSkip {
				t.Fatalf("failed=%v skipped=%v, want failed=%v skipped=%v (%s)", r.failed, r.skipped, tt.wantFail, tt.wantSkip, r.msg)
			}
			if r.msg == "" {
				t.Error("no message given")
			}
		})
	}
}
