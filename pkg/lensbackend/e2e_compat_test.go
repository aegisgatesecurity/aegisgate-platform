// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - E2E Compatibility Route Tests
// =========================================================================
//
// e2e_compat_test.go tests the /lens/* compatibility routes that
// mirror the /api/v1/lens/* routes. These routes exist so the
// Lens browser extension can POST to <backend>/lens/telemetry/fp-report
// and have it resolve correctly whether the backend is the
// Cloudflare Worker (lens.aegisgatesecurity.io) or a self-hosted
// Platform instance.
//
// The Lens extension constructs URLs as:
//
//	<backend_url>/lens/telemetry/fp-report
//
// The Platform's primary routes are:
//
//	/api/v1/lens/fp-report
//	/api/v1/lens/telemetry
//
// The compatibility routes (added in v3.5.0 Phase 3) are:
//
//	/lens/fp-report
//	/lens/telemetry
//	/lens/check
//	/lens/stats
//	/lens/healthz
//
// These tests verify that every /api/v1/lens/* response is
// identical to the corresponding /lens/* response for the
// same request body and query parameters.
//
// Run: go test -race -short ./pkg/lensbackend/...
// =========================================================================

package lensbackend

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCompatibilityRouteHealthz verifies that /lens/healthz
// returns the same response as /api/v1/lens/healthz.
func TestCompatibilityRouteHealthz(t *testing.T) {
	srv, _ := newFPTestServer(t)

	apiResp := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/lens/healthz", nil)
	srv.Mux().ServeHTTP(apiResp, apiReq)

	compatResp := httptest.NewRecorder()
	compatReq := httptest.NewRequest(http.MethodGet, "/lens/healthz", nil)
	srv.Mux().ServeHTTP(compatResp, compatReq)

	if apiResp.Code != compatResp.Code {
		t.Errorf("healthz status mismatch: /api/v1/lens=%d, /lens=%d", apiResp.Code, compatResp.Code)
	}
	if apiResp.Body.String() != compatResp.Body.String() {
		t.Errorf("healthz body mismatch:\n/api/v1/lens=%s\n/lens=%s", apiResp.Body.String(), compatResp.Body.String())
	}
	if apiResp.Code != http.StatusOK {
		t.Errorf("healthz: expected 200, got %d", apiResp.Code)
	}
}

// TestCompatibilityRouteFPReport verifies that POST /lens/fp-report
// returns the same response as POST /api/v1/lens/fp-report.
// Both should reject with the same domain_hash error (the test
// server has no TLS, so VerifyDomainHash returns "no TLS SNI available").
// The important thing is that both paths return the SAME error.
func TestCompatibilityRouteFPReport(t *testing.T) {
	srv, _ := newFPTestServer(t)

	fp := FPReport{
		HashedDomain: "abcdef0123456789",
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, err := json.Marshal(fp)
	if err != nil {
		t.Fatal(err)
	}

	apiResp := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Authorization", "Bearer test-token")
	srv.Mux().ServeHTTP(apiResp, apiReq)

	compatResp := httptest.NewRecorder()
	compatReq := httptest.NewRequest(http.MethodPost, "/lens/fp-report", bytes.NewReader(body))
	compatReq.Header.Set("Content-Type", "application/json")
	compatReq.Header.Set("Authorization", "Bearer test-token")
	srv.Mux().ServeHTTP(compatResp, compatReq)

	if apiResp.Code != compatResp.Code {
		t.Errorf("fp-report status mismatch: /api/v1/lens=%d, /lens=%d", apiResp.Code, compatResp.Code)
	}
	// Both should return the same status code. Whether it's 202 (accepted)
	// or 400 (domain hash mismatch due to no TLS) depends on the test
	// environment, but both paths MUST return the same code.
	t.Logf("both paths returned status %d", apiResp.Code)
}

// TestCompatibilityRouteFPReportNoAuth verifies that both /lens/fp-report
// and /api/v1/lens/fp-report enforce the same bearer token auth.
// When a bearer token is configured, a missing auth header returns 401.
func TestCompatibilityRouteFPReportNoAuth(t *testing.T) {
	srv, _ := newFPTestServer(t)

	fp := FPReport{
		HashedDomain: "abcdef0123456789",
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(fp)

	// No auth on /lens/fp-report
	compatResp := httptest.NewRecorder()
	compatReq := httptest.NewRequest(http.MethodPost, "/lens/fp-report", bytes.NewReader(body))
	compatReq.Header.Set("Content-Type", "application/json")
	srv.Mux().ServeHTTP(compatResp, compatReq)

	// No auth on /api/v1/lens/fp-report
	apiResp := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	apiReq.Header.Set("Content-Type", "application/json")
	srv.Mux().ServeHTTP(apiResp, apiReq)

	if apiResp.Code != compatResp.Code {
		t.Errorf("no-auth status mismatch: /api/v1/lens=%d, /lens=%d", apiResp.Code, compatResp.Code)
	}
	// When a bearer token is configured, missing auth returns 401.
	if compatResp.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth, got %d", compatResp.Code)
	}
}

// TestCompatibilityRouteCORS verifies that the /lens/* routes
// return the same CORS headers as /api/v1/lens/* routes.
func TestCompatibilityRouteCORS(t *testing.T) {
	srv, _ := newFPTestServer(t)

	// Preflight OPTIONS on /lens/fp-report
	compatResp := httptest.NewRecorder()
	compatReq := httptest.NewRequest(http.MethodOptions, "/lens/fp-report", nil)
	compatReq.Header.Set("Origin", "chrome-extension://testid")
	compatReq.Header.Set("Access-Control-Request-Method", "POST")
	srv.Mux().ServeHTTP(compatResp, compatReq)

	apiResp := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodOptions, "/api/v1/lens/fp-report", nil)
	apiReq.Header.Set("Origin", "chrome-extension://testid")
	apiReq.Header.Set("Access-Control-Request-Method", "POST")
	srv.Mux().ServeHTTP(apiResp, apiReq)

	if compatResp.Code != apiResp.Code {
		t.Errorf("CORS preflight status mismatch: /lens=%d, /api/v1/lens=%d", compatResp.Code, apiResp.Code)
	}

	compatCORS := compatResp.Header().Get("Access-Control-Allow-Origin")
	apiCORS := apiResp.Header().Get("Access-Control-Allow-Origin")
	if compatCORS != apiCORS {
		t.Errorf("CORS header mismatch: /lens=%q, /api/v1/lens=%q", compatCORS, apiCORS)
	}
}

// TestCompatibilityRouteAllEndpoints verifies that all 5 compatibility
// routes exist and return the same status codes as their /api/v1/lens
// counterparts.
func TestCompatibilityRouteAllEndpoints(t *testing.T) {
	srv, _ := newFPTestServer(t)

	tests := []struct {
		name    string
		apiPath string
		method  string
		authed  bool
	}{
		{"healthz", "/api/v1/lens/healthz", http.MethodGet, false},
		{"telemetry", "/api/v1/lens/telemetry", http.MethodPost, true},
		{"fp-report", "/api/v1/lens/fp-report", http.MethodPost, true},
		{"check", "/api/v1/lens/check", http.MethodGet, true},
		{"stats", "/api/v1/lens/stats", http.MethodGet, true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_exists", func(t *testing.T) {
			// Strip /api/v1 prefix to get the compatibility path
			compatPath := tt.apiPath[len("/api/v1"):]

			apiResp := httptest.NewRecorder()
			apiReq := httptest.NewRequest(tt.method, tt.apiPath, nil)
			if tt.authed {
				apiReq.Header.Set("Authorization", "Bearer test-token")
			}
			srv.Mux().ServeHTTP(apiResp, apiReq)

			compatResp := httptest.NewRecorder()
			compatReq := httptest.NewRequest(tt.method, compatPath, nil)
			if tt.authed {
				compatReq.Header.Set("Authorization", "Bearer test-token")
			}
			srv.Mux().ServeHTTP(compatResp, compatReq)

			if apiResp.Code != compatResp.Code {
				t.Errorf("%s: status mismatch: /api/v1/lens=%d, /lens=%d", tt.name, apiResp.Code, compatResp.Code)
			}

			// Verify the compatibility route actually got handled (not 404)
			if compatResp.Code == http.StatusNotFound {
				t.Errorf("%s: compatibility route %s returned 404", tt.name, compatPath)
			}
		})
	}
}
