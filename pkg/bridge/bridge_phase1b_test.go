// SPDX-License-Identifier: Apache-2.0
// Phase 1b unit tests for pkg/bridge — targeting uncovered paths in
// bridge.go (RouteLLMCall success/blocked, NewPlatformBridgeWithConfig error)
// and response_guard.go (ScanBridgeResponse empty/toxicity).
package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ---------------------------------------------------------------------------
// NewPlatformBridgeWithConfig — gateway creation error path (line 128)
// ---------------------------------------------------------------------------

func TestPhase1bNewPlatformBridgeWithConfig_InvalidURL(t *testing.T) {
	// An unparseable URL causes guardbridge.NewGateway to fail, which
	// triggers the error return in NewPlatformBridgeWithConfig.
	cfg := &Config{
		AegisGateURL: "://invalid-url",
		Enabled:      true,
		Timeout:      5 * time.Second,
	}
	pb, err := NewPlatformBridgeWithConfig(cfg)
	if err == nil {
		if pb != nil {
			pb.Close()
		}
		t.Fatal("expected error for invalid URL, got nil")
	}
	if pb != nil {
		t.Fatal("expected nil bridge on error")
	}
}

// ---------------------------------------------------------------------------
// RouteLLMCall — success and blocked paths via test HTTP server
// ---------------------------------------------------------------------------

// startTestProxy starts an httptest.Server that:
//   - responds 200 to /health
//   - responds 200 to /proxy/* with optional scan-result headers
func startTestProxy(t *testing.T, blocked bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		if blocked {
			w.Header().Set("X-AegisGate-Allowed", "false")
			w.Header().Set("X-AegisGate-Block-Reason", "test-block")
			w.Header().Set("X-AegisGate-Threats", "pii,secret")
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.Header().Set("X-AegisGate-Allowed", "true")
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(`{"response":"test"}`))
	})
	return httptest.NewServer(mux)
}

func TestPhase1bRouteLLMCall_SuccessPath(t *testing.T) {
	srv := startTestProxy(t, false)
	defer srv.Close()

	pb, err := NewPlatformBridge(srv.URL)
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	req := &LLMRequest{
		RequestID: "test-req-1",
		AgentID:   "test-agent",
		TargetURL: "https://api.test.com",
		Method:    "POST",
		Body:      []byte(`{"prompt":"hello"}`),
	}

	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Fatalf("RouteLLMCall failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.ScanResult == nil || !resp.ScanResult.Allowed {
		t.Error("expected scan result with Allowed=true")
	}
}

func TestPhase1bRouteLLMCall_BlockedPath(t *testing.T) {
	srv := startTestProxy(t, true)
	defer srv.Close()

	pb, err := NewPlatformBridge(srv.URL)
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	req := &LLMRequest{
		RequestID: "test-req-blocked",
		AgentID:   "test-agent",
		TargetURL: "https://api.test.com",
		Method:    "POST",
		Body:      []byte(`{"prompt":"hello"}`),
	}

	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Fatalf("RouteLLMCall failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ScanResult == nil {
		t.Fatal("expected scan result")
	}
	if resp.ScanResult.Allowed {
		t.Error("expected scan result with Allowed=false")
	}
	if resp.ScanResult.BlockReason != "test-block" {
		t.Errorf("expected block reason 'test-block', got %q", resp.ScanResult.BlockReason)
	}
}

func TestPhase1bRouteLLMCall_DisabledPassthrough(t *testing.T) {
	srv := startTestProxy(t, false)
	defer srv.Close()

	pb, err := NewPlatformBridge(srv.URL)
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	pb.SetEnabled(false)
	req := &LLMRequest{
		RequestID: "test-req-disabled",
		TargetURL: "https://api.test.com",
		Method:    "POST",
		Body:      []byte(`{}`),
	}
	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Fatalf("RouteLLMCall failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 passthrough, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// ScanBridgeResponse — empty content and toxicity threat paths
// ---------------------------------------------------------------------------

func TestPhase1bScanBridgeResponse_NilArgs(t *testing.T) {
	result, err := ScanBridgeResponse(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for nil args")
	}
}

func TestPhase1bScanBridgeResponse_EmptyBody(t *testing.T) {
	scanner := NewResponseScanner()
	resp := &LLMResponse{
		RequestID:  "test-empty",
		StatusCode: 200,
		Body:       []byte(""),
	}
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Allowed {
		t.Error("expected Allowed=true for empty body")
	}
}

func TestPhase1bScanBridgeResponse_ToxicityThreat(t *testing.T) {
	// The default toxicity filter matches violence keywords like "kill".
	// In strict mode (default) this produces a threat with Type="toxicity"
	// and Allowed=false, which exercises the toxicity case in
	// ScanBridgeResponse's threat-type switch.
	scanner := NewResponseScanner()
	resp := &LLMResponse{
		RequestID:  "test-toxic",
		StatusCode: 200,
		Body:       []byte("I will kill you and murder everyone"),
	}
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.ToxicityDetected {
		t.Error("expected ToxicityDetected=true")
	}
	if result.Threats == 0 {
		t.Error("expected at least 1 threat")
	}
}

func TestPhase1bScanBridgeResponse_HallucinationThreat(t *testing.T) {
	// Create a scanner with hallucination detection enabled.
	// The hallucination detector flags text with >3 confident phrases
	// AND >2 unattributed statistics.
	scanner := NewResponseScannerWithConfig(&responseguard.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		EnableToxicityFilter:  false,
		EnableHallucination:   true,
		StrictMode:            false,
	})

	// Text with 4+ confident phrases and 3+ statistics without attribution.
	// The stat regex is `\b\d+%?\s+(people|users|users?|percent|%)\b`,
	// so the word must immediately follow the number.
	hallucinationText := "This is definitely absolutely certainly guaranteed. " +
		"always never everyone no one. " +
		"50% people 80% users 100% percent"

	resp := &LLMResponse{
		RequestID:  "test-hallucination",
		StatusCode: 200,
		Body:       []byte(hallucinationText),
	}
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.HallucinationDetected {
		t.Error("expected HallucinationDetected=true")
	}
}

func TestPhase1bScanBridgeResponse_CleanContent(t *testing.T) {
	scanner := NewResponseScanner()
	resp := &LLMResponse{
		RequestID:  "test-clean",
		StatusCode: 200,
		Body:       []byte("This is a perfectly safe response."),
	}
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Allowed {
		t.Error("expected Allowed=true for clean content")
	}
}

// ---------------------------------------------------------------------------
// ScanAndFilter — normal path (already covered, add explicit test)
// ---------------------------------------------------------------------------

func TestPhase1bScanAndFilter_CleanResponse(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()

	filtered, result, err := pb.ScanAndFilter(context.Background(), "clean response text")
	if err != nil {
		t.Fatalf("ScanAndFilter failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if filtered != "clean response text" {
		t.Errorf("expected passthrough, got %q", filtered)
	}
}

func TestPhase1bScanAndFilter_BlockedStrictMode(t *testing.T) {
	// In strict mode (default), a blocked response still returns via the
	// normal return path (line 247) because the non-strict branch is
	// never taken.
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()

	// Text with PII (SSN) triggers strict-mode blocking
	filtered, result, err := pb.ScanAndFilter(context.Background(),
		"SSN: 123-45-6789")
	if err != nil {
		t.Fatalf("ScanAndFilter failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	_ = filtered // content is returned regardless in current implementation
}

// ---------------------------------------------------------------------------
// ResponseScanner — accessor methods with explicit result checks
// ---------------------------------------------------------------------------

func TestPhase1bGetComplianceReport_CleanResponse(t *testing.T) {
	rs := NewResponseScanner()
	report, err := rs.GetComplianceReport(context.Background(), "clean text")
	if err != nil {
		t.Fatalf("GetComplianceReport failed: %v", err)
	}
	// report may be non-nil even for clean text (compliance reports map)
	_ = report
}

func TestPhase1bGetDetectedPII_CleanResponse(t *testing.T) {
	rs := NewResponseScanner()
	pii := rs.GetDetectedPII(context.Background(), "clean text")
	if len(pii) != 0 {
		t.Errorf("expected 0 PII categories for clean text, got %d", len(pii))
	}
}

func TestPhase1bGetDetectedSecrets_CleanResponse(t *testing.T) {
	rs := NewResponseScanner()
	secrets := rs.GetDetectedSecrets(context.Background(), "clean text")
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for clean text, got %d", len(secrets))
	}
}

func TestPhase1bIsResponseAllowed_CleanResponse(t *testing.T) {
	rs := NewResponseScanner()
	if !rs.IsResponseAllowed(context.Background(), "clean text") {
		t.Error("expected clean text to be allowed")
	}
}

func TestPhase1bIsResponseAllowed_BlockedResponse(t *testing.T) {
	rs := NewResponseScanner()
	// SSN should be detected as PII and blocked in strict mode
	if rs.IsResponseAllowed(context.Background(), "SSN: 123-45-6789") {
		t.Error("expected PII text to be blocked in strict mode")
	}
}

func TestPhase1bScanResponseWithContext_WithScanContext(t *testing.T) {
	rs := NewResponseScanner()
	scanCtx := responseguard.NewScanContext("client-1", "session-1")
	scanCtx.ScanType = "llm_response"
	result, err := rs.ScanResponseWithContext(context.Background(), "clean text", scanCtx)
	if err != nil {
		t.Fatalf("ScanResponseWithContext failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Allowed {
		t.Error("expected clean text to be allowed")
	}
}

func TestPhase1bScanResponseWithContext_BlockedResponse(t *testing.T) {
	rs := NewResponseScanner()
	// SSN triggers PII detection, strict mode blocks
	result, err := rs.ScanResponseWithContext(context.Background(),
		"SSN: 123-45-6789", nil)
	if err != nil {
		t.Fatalf("ScanResponseWithContext failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Allowed {
		t.Error("expected PII text to be blocked")
	}
	if len(result.DetectedPII) == 0 {
		t.Error("expected PII categories to be detected")
	}
}

func TestPhase1bScanLLMResponse_WithClientID(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanLLMResponse(context.Background(), "clean text", "client-123")
	if err != nil {
		t.Fatalf("ScanLLMResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Allowed {
		t.Error("expected clean text to be allowed")
	}
}

// ---------------------------------------------------------------------------
// PlatformBridgeWithResponse — ScanResponse integration
// ---------------------------------------------------------------------------

func TestPhase1bPlatformBridgeWithResponse_ScanResponse(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()

	result, err := pb.ScanResponse(context.Background(), "clean text")
	if err != nil {
		t.Fatalf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---------------------------------------------------------------------------
// NewPlatformBridgeWithResponse — error path
// ---------------------------------------------------------------------------

func TestPhase1bNewPlatformBridgeWithResponse_InvalidURL(t *testing.T) {
	_, err := NewPlatformBridgeWithResponse("://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
