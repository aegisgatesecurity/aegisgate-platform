// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Posture Check HTTP endpoint tests (D19, P1 #8)
// =========================================================================
//
// Tests for the posture HTTP endpoints added in D19. Uses a stub
// license manager so tests don't require a real license. The
// posture check itself is tested in pkg/posture/check_test.go;
// these tests cover the HTTP wiring (routing, method check, auth,
// response shape, error handling).
// =========================================================================

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/posture"
)

// stubLicenseMgrForTests creates a license manager with the embedded
// public key. Returns nil only if the manager cannot be initialized
// (test environment problem). The posture check only needs the
// manager to exist; the license key can be anything.
func stubLicenseMgrForTests(t *testing.T) *license.Manager {
	t.Helper()
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("license.NewManager: %v", err)
	}
	return mgr
}

// authMiddlewareForTests builds a permissive auth middleware
// that accepts any bearer token. This isolates the posture
// tests from auth-specific test infrastructure.
func authMiddlewareForTests() *auth.Middleware {
	return auth.NewMiddleware(&auth.Config{RequireAuth: false})
}

func TestHandlePostureJSON_MethodNotAllowed(t *testing.T) {
	mgr := stubLicenseMgrForTests(t)
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wirePostureHandlers(mux, authMW, mgr, "production")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posture", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/posture: got status %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlePostureJSON_OK(t *testing.T) {
	mgr := stubLicenseMgrForTests(t)
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wirePostureHandlers(mux, authMW, mgr, "production")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posture", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/posture: got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// Parse the response and verify it's a posture.Report.
	var report posture.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal posture.Report: %v", err)
	}
	if report.Overall == "" {
		t.Error("Overall field is empty in response")
	}
}

func TestHandlePostureVerbose_OK(t *testing.T) {
	mgr := stubLicenseMgrForTests(t)
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wirePostureHandlers(mux, authMW, mgr, "production")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posture/verbose", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/posture/verbose: got status %d, want %d", rr.Code, http.StatusOK)
	}
	var report posture.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal posture.Report: %v", err)
	}
}

func TestHandlePostureText_OK(t *testing.T) {
	mgr := stubLicenseMgrForTests(t)
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wirePostureHandlers(mux, authMW, mgr, "production")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posture/text", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/posture/text: got status %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	// Text should be non-empty.
	body := rr.Body.String()
	if len(body) < 10 {
		t.Errorf("posture text response too short (%d bytes): %q", len(body), body)
	}
}

func TestHandlePostureText_NotFound(t *testing.T) {
	// Verify the 3 routes are actually registered (no 404s).
	mgr := stubLicenseMgrForTests(t)
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wirePostureHandlers(mux, authMW, mgr, "production")

	for _, path := range []string{"/api/v1/posture", "/api/v1/posture/verbose", "/api/v1/posture/text"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Errorf("route %s returned 404 (not registered)", path)
		}
	}
}
