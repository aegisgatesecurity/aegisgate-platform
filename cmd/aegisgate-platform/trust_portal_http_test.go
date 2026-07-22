// SPDX-License-Identifier: Apache-2.0
// Tests for the trust portal HTTP wiring in cmd/aegisgate-platform.
//
// These tests verify that wireTrustPortalHandlers mounts the
// /trust/* routes on the mux with no auth middleware (the trust
// portal is a public page), and that the routes are reachable
// without a license key. The handler-level logic is tested in
// pkg/trustportal/portal_test.go; these tests cover the wire-up.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWireTrustPortalHandlers_PublicAccess(t *testing.T) {
	mux := http.NewServeMux()
	wireTrustPortalHandlers(mux)

	// The trust portal routes should be reachable WITHOUT any
	// auth header. (The auth middleware in posture/attestation
	// returns 401 when no auth header is set; the trust portal
	// must NOT do that.)
	req := httptest.NewRequest(http.MethodGet, "/trust", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /trust without auth: status = %d, want 200 (trust portal is public)", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestWireTrustPortalHandlers_AllJSONRoutes(t *testing.T) {
	mux := http.NewServeMux()
	wireTrustPortalHandlers(mux)

	jsonRoutes := []struct {
		path    string
		wantKey string
	}{
		{"/trust/api/posture", "overall_status"},
		{"/trust/api/frameworks", "frameworks"},
		{"/trust/api/uptime", "uptime_badge"},
	}
	for _, r := range jsonRoutes {
		t.Run(r.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, r.path, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
			}
			ct := rr.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			// Decode and check the expected key is present.
			var m map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, ok := m[r.wantKey]; !ok {
				t.Errorf("response missing expected key %q, got keys: %v", r.wantKey, mapKeys(m))
			}
		})
	}
}

func TestWireTrustPortalHandlers_TrailingSlash(t *testing.T) {
	mux := http.NewServeMux()
	wireTrustPortalHandlers(mux)

	// /trust/ should also serve the page
	req := httptest.NewRequest(http.MethodGet, "/trust/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /trust/ status = %d, want 200", rr.Code)
	}
}

func TestWireTrustPortalHandlers_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	wireTrustPortalHandlers(mux)

	req := httptest.NewRequest(http.MethodPost, "/trust/api/posture", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /trust/api/posture: status = %d, want 405", rr.Code)
	}
}

func TestWireTrustPortalHandlers_FrameworksList(t *testing.T) {
	// Sanity check: the frameworks endpoint returns the expected
	// 8 modules (7 with HasImplementation=true, 1 reserved).
	mux := http.NewServeMux()
	wireTrustPortalHandlers(mux)

	req := httptest.NewRequest(http.MethodGet, "/trust/api/frameworks", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var snap struct {
		TotalCount int `json:"total_count"`
		Tier1Count int `json:"tier1_count"`
		Frameworks []struct {
			Key               string `json:"key"`
			DisplayName       string `json:"display_name"`
			Tier1             bool   `json:"tier1"`
			HasImplementation bool   `json:"has_implementation"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The trust portal should always return 8 modules (the 6
	// billable + EU AI Act + the reserved Trust Framework).
	// This locks in the expected module count so a future
	// addition of a new module is a deliberate change.
	if snap.TotalCount != 8 {
		t.Errorf("total_count = %d, want 8 (6 billable + EU AI Act + reserved Trust Framework)", snap.TotalCount)
	}
	// 7 modules have HasImplementation=true (the Trust Framework
	// module is reserved for future use and has no implementation
	// yet, so it counts as Tier1=false).
	if snap.Tier1Count != 7 {
		t.Errorf("tier1_count = %d, want 7 (all except reserved Trust Framework)", snap.Tier1Count)
	}
}

// mapKeys returns the keys of a map for use in test error messages.
func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
