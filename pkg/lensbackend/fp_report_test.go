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
	"encoding/json"
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
