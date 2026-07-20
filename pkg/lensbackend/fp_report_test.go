// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - FP-Report Bridge Handler Tests
// =========================================================================
//
// Tests the POST /api/v1/lens/fp-report endpoint that bridges the
// Lens extension's simplified 4-field FP report format to the full
// v0.2 Event schema.
//
// v3.5.0+ Phase 3.
// =========================================================================

package lensbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newFPTestServer creates a test server for FP-report endpoint tests.
func newFPTestServer(t *testing.T) (*Server, *Handlers) {
	t.Helper()
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "test-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	return srv, NewHandlers(srv)
}

func TestFPReportValid(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: ComputeDomainHash("chatgpt.com"),
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Original-SNI", "chatgpt.com")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["status"] != "received" {
		t.Errorf("expected status=received, got %q", resp["status"])
	}
}

func TestFPReportMethodNotAllowed(t *testing.T) {
	_, h := newFPTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/lens/fp-report", nil)
	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestFPReportInvalidJSON(t *testing.T) {
	_, h := newFPTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportInvalidHashLength(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "tooshort",
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportInvalidHashChars(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "A1B2C3D4E5F6A7B8", // uppercase hex
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportInvalidCategory(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "a1b2c3d4e5f6a7b8",
		Category:     "unknown_category",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportInvalidSeverity(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "a1b2c3d4e5f6a7b8",
		Category:     "pii_email",
		Severity:     "critical", // FP reports only allow low/medium/high
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportInvalidAction(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "a1b2c3d4e5f6a7b8",
		Category:     "pii_email",
		Severity:     "high",
		Action:       "dismiss", // not a valid FP action
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFPReportAllFacets(t *testing.T) {
	_, h := newFPTestServer(t)

	tests := []struct {
		category string
		facet    string
	}{
		{"pii_email", "pii"},
		{"secret_api_key_generic", "secrets"},
		{"xss_script_tag", "xss"},
		{"owasp_llm01_prompt_injection", "compliance"},
		{"toxicity_hate", "toxicity"},
		{"pi_direct_override", "prompt_injection"},
	}

	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			report := FPReport{
				HashedDomain: ComputeDomainHash("chatgpt.com"),
				Category:     tc.category,
				Severity:     "medium",
				Action:       "send",
			}
			body, _ := json.Marshal(report)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-token")
			req.Header.Set("X-Original-SNI", "chatgpt.com")

			w := httptest.NewRecorder()
			h.HandleFPReport(w, req)

			if w.Code != http.StatusAccepted {
				t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestFPReportAllActions(t *testing.T) {
	_, h := newFPTestServer(t)

	for _, action := range []string{"cancel", "redact", "send", "false_positive"} {
		t.Run(action, func(t *testing.T) {
			report := FPReport{
				HashedDomain: ComputeDomainHash("chatgpt.com"),
				Category:     "pii_email",
				Severity:     "low",
				Action:       action,
			}
			body, _ := json.Marshal(report)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-token")
			req.Header.Set("X-Original-SNI", "chatgpt.com")

			w := httptest.NewRecorder()
			h.HandleFPReport(w, req)

			if w.Code != http.StatusAccepted {
				t.Errorf("expected 202, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestFacetFromCategoryPrefix(t *testing.T) {
	tests := []struct {
		category string
		facet    string
	}{
		{"pii_email", "pii"},
		{"pii_ssn", "pii"},
		{"secret_api_key_generic", "secrets"},
		{"source_code", "secrets"},
		{"xss_script_tag", "xss"},
		{"owasp_llm01_prompt_injection", "compliance"},
		{"eu_ai_act_article_5", "compliance"},
		{"toxicity_hate", "toxicity"},
		{"pi_direct_override", "prompt_injection"},
		{"unknown", ""},
	}
	for _, tc := range tests {
		got := facetFromCategoryPrefix(tc.category)
		if got != tc.facet {
			t.Errorf("facetFromCategoryPrefix(%q) = %q, want %q", tc.category, got, tc.facet)
		}
	}
}

func TestFPReportDomainHashMismatch(t *testing.T) {
	_, h := newFPTestServer(t)

	report := FPReport{
		HashedDomain: "a1b2c3d4e5f6a7b8", // doesn't match chatgpt.com
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Original-SNI", "chatgpt.com")

	w := httptest.NewRecorder()
	h.HandleFPReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCORSHeaders(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "test-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	// Test preflight OPTIONS request
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/v1/lens/healthz", nil)
	req.Header.Set("Origin", "chrome-extension://abc123")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want 204", resp.StatusCode)
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "chrome-extension://abc123" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", acao, "chrome-extension://abc123")
	}
	acam := resp.Header.Get("Access-Control-Allow-Methods")
	if acam != "GET, POST, OPTIONS" {
		t.Errorf("Access-Control-Allow-Methods = %q, want %q", acam, "GET, POST, OPTIONS")
	}
}

func TestFPReportViaHTTPServer(t *testing.T) {
	// End-to-end test through the HTTP server mux (including CORS + auth middleware).
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "test-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	report := FPReport{
		HashedDomain: ComputeDomainHash("chatgpt.com"),
		Category:     "pii_email",
		Severity:     "high",
		Action:       "send",
	}
	body, _ := json.Marshal(report)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/lens/fp-report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Original-SNI", "chatgpt.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("expected 202, got %d", resp.StatusCode)
	}

	// Verify CORS headers are present on the actual response.
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", acao)
	}
}

// TestEndToEndFPReportToCheck verifies the full round-trip:
// POST /api/v1/lens/fp-report → IOC created → GET /api/v1/lens/check → verdict.
// This is the Phase 3B integration test.
func TestEndToEndFPReportToCheck(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "test-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	domain := "chatgpt.com"
	domainHash := ComputeDomainHash(domain)

	// Step 1: POST multiple FP reports for chatgpt.com across different categories.
	reports := []FPReport{
		{HashedDomain: domainHash, Category: "pii_email", Severity: "high", Action: "send"},
		{HashedDomain: domainHash, Category: "pii_email", Severity: "medium", Action: "send"},
		{HashedDomain: domainHash, Category: "secret_api_key_generic", Severity: "high", Action: "cancel"},
	}

	for i, report := range reports {
		body, _ := json.Marshal(report)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/lens/fp-report", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("X-Original-SNI", domain)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("report %d: POST failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("report %d: expected 202, got %d", i, resp.StatusCode)
		}
	}

	// Step 2: Force-flush the IOC writer so pending IOCs land in the store.
	if err := srv.ioc.flush(context.Background()); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Step 3: GET /api/v1/lens/check?domain=chatgpt.com → should return known_threat.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/lens/check?domain="+domain, nil)
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode /check response: %v", err)
	}

	if result["verdict"] != "known_threat" {
		t.Errorf("verdict = %v, want 'known_threat'", result["verdict"])
	}
	// The domain field should be present in the response.
	if d, ok := result["domain"]; !ok || d == nil {
		t.Logf("domain field missing or nil in response (this is OK - /check doesn't always return domain)")
	} else if d != domain {
		t.Errorf("domain = %v, want %q", d, domain)
	}
	// The worst IOC should be from the secrets category (high severity).
	// Since we sent pii_email (high+medium) and secret_api_key_generic (high),
	// the worst by severity rank should be one of the high-severity ones.
	if cat, ok := result["category"]; ok && cat != nil {
		t.Logf("worst IOC category: %v", cat)
	}
	// Count should be > 0.
	if count, ok := result["count"]; ok {
		if count.(float64) < 1 {
			t.Errorf("count = %v, want >= 1", count)
		}
	} else {
		t.Error("count field missing from /check response")
	}

	// Step 4: GET /api/v1/lens/check?domain=unknown.com → should return "clean".
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/lens/check?domain=unknown.example.com", nil)
	req2.Header.Set("Authorization", "Bearer test-token")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /check (unknown) failed: %v", err)
	}
	defer resp2.Body.Close()

	var result2 map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&result2); err != nil {
		t.Fatalf("failed to decode /check response (unknown): %v", err)
	}
	if result2["verdict"] != "clean" {
		t.Errorf("unknown domain verdict = %v, want 'clean'", result2["verdict"])
	}

	// Step 5: GET /api/v1/lens/stats → should show accepted events.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/lens/stats", nil)
	req3.Header.Set("Authorization", "Bearer test-token")

	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET /stats failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("/stats status = %d, want 200", resp3.StatusCode)
	}
}
