package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A malformed ID or user ID in the path is a 400 on every route that has one,
// and the store is never reached.
func TestBadPathParametersAreRejected(t *testing.T) {
	tests := []struct{ method, path string }{
		{"GET", "/v1/roles/abc"},
		{"DELETE", "/v1/roles/abc"},
		{"GET", "/v1/roles/abc/permissions"},
		{"POST", "/v1/roles/abc/permissions"},
		{"DELETE", "/v1/roles/abc/permissions/1"},
		{"DELETE", "/v1/roles/1/permissions/abc"},
		{"GET", "/v1/resources/abc"},
		{"DELETE", "/v1/resources/abc"},
		{"GET", "/v1/permissions/abc"},
		{"DELETE", "/v1/permissions/abc"},
		{"GET", "/v1/users/bad%20user/roles"},
		{"DELETE", "/v1/users/bad%20user/roles/1"},
		{"DELETE", "/v1/users/u1/roles/abc"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			h := newTestRouter(t, brokenStore{newFakeStore()}, nil)
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+testToken(t, "svc-x"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
