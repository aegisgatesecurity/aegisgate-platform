// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Attestation HTTP endpoint tests (D19, P1 #8)
// =========================================================================
//
// Tests for the attestation HTTP endpoints added in D19. Verifies
// routing, method checks, response shape, and error handling. The
// underlying envelope verification is tested in
// pkg/attestation/attestation_test.go; these tests cover the HTTP
// wiring only.
// =========================================================================

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleAttestationVerify_MethodNotAllowed(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAttestationHandlers(mux, authMW)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/attestation/verify", strings.NewReader("{}"))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/v1/attestation/verify: got status %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestHandleAttestationVerify_InvalidJSON(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAttestationHandlers(mux, authMW)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestation/verify", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Bad JSON should give 400, not 500.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST /api/v1/attestation/verify (bad JSON): got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rr.Body.String(), "error") {
		t.Errorf("response should contain 'error' field, got: %s", rr.Body.String())
	}
}

func TestHandleAttestationVerifyOnline_MethodNotAllowed(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAttestationHandlers(mux, authMW)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/verify-online", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/v1/attestation/verify-online: got status %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleAttestationRoutes_Registered(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAttestationHandlers(mux, authMW)

	// Verify both routes are registered (no 404s).
	for _, path := range []string{"/api/v1/attestation/verify", "/api/v1/attestation/verify-online"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		// 400 = bad request (empty envelope), NOT 404.
		if rr.Code == http.StatusNotFound {
			t.Errorf("route %s returned 404 (not registered)", path)
		}
	}
}
