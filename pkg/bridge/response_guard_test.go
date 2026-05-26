// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 AegisGate Security
// =========================================================================
// Bridge Response Guard Tests - Coverage for pkg/bridge/response_guard.go
// =========================================================================

package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// ResponseScanner Tests
// ============================================================================

func TestNewResponseScanner(t *testing.T) {
	rs := NewResponseScanner()
	if rs == nil {
		t.Fatal("NewResponseScanner returned nil")
	}
	if rs.guard == nil {
		t.Error("ResponseScanner.guard should not be nil")
	}
}

func TestNewResponseScannerWithConfig(t *testing.T) {
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:        true,
		EnableSecretDetection:   true,
		EnableToxicityFilter:    true,
		EnableHallucination:     true,
		MaxResponseTokens:       10000,
		MaxResponseLatencyMS:   1000,
	}

	rs := NewResponseScannerWithConfig(config)
	if rs == nil {
		t.Fatal("NewResponseScannerWithConfig returned nil")
	}
	if rs.guard == nil {
		t.Error("ResponseScanner.guard should not be nil")
	}
}

func TestResponseScanner_ScanResponse(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "Normal response content")
	if err != nil {
		t.Errorf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanResponse returned nil result")
	}
	t.Logf("Result: Allowed=%v", result.Allowed)
}

func TestResponseScanner_ScanResponseWithPII(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "Contact: test@example.com")
	if err != nil {
		t.Errorf("ScanResponse with PII failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanResponse returned nil result")
	}
	t.Logf("PII result: Allowed=%v, DetectedPII=%v", result.Allowed, result.DetectedPII)
}

func TestResponseScanner_ScanResponseWithSecrets(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "Token: sk_live_1234567890abcdef")
	if err != nil {
		t.Errorf("ScanResponse with secrets failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanResponse returned nil result")
	}
	t.Logf("Secret result: Allowed=%v, DetectedSecrets=%v", result.Allowed, result.DetectedSecrets)
}

func TestResponseScanner_ScanLLMResponse(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanLLMResponse(context.Background(), "LLM response content", "client-123")
	if err != nil {
		t.Errorf("ScanLLMResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanLLMResponse returned nil result")
	}
	t.Logf("LLM Response: Allowed=%v", result.Allowed)
}

func TestResponseScanner_IsResponseAllowed(t *testing.T) {
	rs := NewResponseScanner()
	allowed := rs.IsResponseAllowed(context.Background(), "Normal response")
	t.Logf("IsResponseAllowed (normal): %v", allowed)
	allowedPII := rs.IsResponseAllowed(context.Background(), "Email: user@domain.com")
	t.Logf("IsResponseAllowed (with PII): %v", allowedPII)
	allowedSecret := rs.IsResponseAllowed(context.Background(), "Key: Bearer xyz123secret")
	t.Logf("IsResponseAllowed (with secret): %v", allowedSecret)
}

func TestResponseScanner_GetComplianceReport(t *testing.T) {
	rs := NewResponseScanner()
	reports, err := rs.GetComplianceReport(context.Background(), "Test compliance content")
	if err != nil {
		t.Errorf("GetComplianceReport failed: %v", err)
	}
	if reports == nil {
		t.Error("GetComplianceReport returned nil")
	}
	t.Logf("Compliance reports: %d categories", len(reports))
}

func TestResponseScanner_GetDetectedPII(t *testing.T) {
	rs := NewResponseScanner()
	pii := rs.GetDetectedPII(context.Background(), "Email: john@example.com")
	t.Logf("Detected PII: %v", pii)
	multiPII := rs.GetDetectedPII(context.Background(), "John, SSN: 123-45-6789, john@email.com")
	t.Logf("Multiple PII: %v", multiPII)
}

func TestResponseScanner_GetDetectedSecrets(t *testing.T) {
	rs := NewResponseScanner()
	secrets := rs.GetDetectedSecrets(context.Background(), "Key: sk_test_1234567890")
	t.Logf("Detected secrets: %v", secrets)
}

func TestResponseScanner_ScanResponseWithContext(t *testing.T) {
	rs := NewResponseScanner()
	scanCtx := responseguard.NewScanContext("test-client", "test-session")
	result, err := rs.ScanResponseWithContext(context.Background(), "Test with context", scanCtx)
	if err != nil {
		t.Errorf("ScanResponseWithContext failed: %v", err)
	}
	t.Logf("ScanResponseWithContext: Allowed=%v", result.Allowed)
}

// ============================================================================
// BridgeResponseScanner Tests
// ============================================================================

func TestNewPlatformBridgeWithResponse(t *testing.T) {
	bridge, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Logf("NewPlatformBridgeWithResponse error: %v", err)
		return
	}
	if bridge == nil {
		t.Fatal("NewPlatformBridgeWithResponse returned nil on success")
	}
	t.Log("Bridge with response scanning created")
}

func TestScanBridgeResponse(t *testing.T) {
	resp := &LLMResponse{Body: []byte("Test response content"), RequestID: "test-req-123"}
	scanner := NewResponseScanner()
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanBridgeResponse returned nil")
	}
	t.Logf("Bridge response scan: Allowed=%v", result.Allowed)
}

func TestScanBridgeResponse_PII(t *testing.T) {
	resp := &LLMResponse{Body: []byte("SSN: 123-45-6789"), RequestID: "test-pii"}
	scanner := NewResponseScanner()
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse PII failed: %v", err)
	}
	t.Logf("Bridge PII scan: Allowed=%v", result.Allowed)
}

func TestScanBridgeResponse_Secret(t *testing.T) {
	resp := &LLMResponse{Body: []byte("Token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), RequestID: "test-secret"}
	scanner := NewResponseScanner()
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse secret failed: %v", err)
	}
	t.Logf("Bridge secret scan: Allowed=%v", result.Allowed)
}

func TestScanBridgeResponse_Empty(t *testing.T) {
	resp := &LLMResponse{Body: []byte(""), RequestID: "test-empty"}
	scanner := NewResponseScanner()
	result, err := ScanBridgeResponse(context.Background(), resp, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse empty failed: %v", err)
	}
	t.Logf("Empty response: Allowed=%v", result.Allowed)
}

func TestScanBridgeResponse_NilResponse(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := ScanBridgeResponse(context.Background(), nil, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse nil failed: %v", err)
	}
	t.Logf("Nil response: result=%v", result)
}

func TestScanBridgeResponse_NilScanner(t *testing.T) {
	resp := &LLMResponse{Body: []byte("Test"), RequestID: "test-nil-scanner"}
	result, err := ScanBridgeResponse(context.Background(), resp, nil)
	if err != nil {
		t.Errorf("ScanBridgeResponse nil scanner failed: %v", err)
	}
	t.Logf("Nil scanner: result=%v", result)
}

// ============================================================================
// PlatformBridgeWithResponse Tests
// ============================================================================

func TestPlatformBridgeWithResponse_ScanResponse(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Logf("Bridge creation error: %v", err)
		return
	}
	result, err := pb.ScanResponse(context.Background(), "Test content")
	if err != nil {
		t.Logf("ScanResponse error: %v", err)
	} else {
		t.Logf("ScanResponse: Allowed=%v", result.Allowed)
	}
}

func TestPlatformBridgeWithResponse_ScanAndFilter(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Logf("Bridge creation error: %v", err)
		return
	}
	filtered, result, err := pb.ScanAndFilter(context.Background(), "Normal content")
	if err != nil {
		t.Logf("ScanAndFilter error: %v", err)
	} else {
		t.Logf("ScanAndFilter: filtered=%s, Allowed=%v", filtered, result.Allowed)
	}
}

// ============================================================================
// Concurrency Tests
// ============================================================================

func TestResponseScanner_ConcurrentScans(t *testing.T) {
	rs := NewResponseScanner()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			content := "Concurrent response " + string(rune('0'+id%10))
			rs.ScanResponse(context.Background(), content)
		}(i)
	}
	wg.Wait()
	t.Log("Completed concurrent scans")
}

func TestResponseScanner_ConcurrentGetPII(t *testing.T) {
	rs := NewResponseScanner()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs.GetDetectedPII(context.Background(), "Email: test@test.com")
		}()
	}
	wg.Wait()
	t.Log("Completed concurrent PII detection")
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestResponseScanner_EmptyResponse(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "")
	if err != nil {
		t.Errorf("Empty response scan failed: %v", err)
	}
	t.Logf("Empty response: Allowed=%v", result.Allowed)
}

func TestResponseScanner_UnicodeResponse(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "Unicode: 日本語 alpha")
	if err != nil {
		t.Errorf("Unicode response scan failed: %v", err)
	}
	t.Logf("Unicode response: Allowed=%v", result.Allowed)
}

func TestResponseScanner_VeryLongResponse(t *testing.T) {
	rs := NewResponseScanner()
	longContent := make([]byte, 10000)
	for i := range longContent {
		longContent[i] = byte('A' + (i % 26))
	}
	result, err := rs.ScanResponse(context.Background(), string(longContent))
	if err != nil {
		t.Logf("Long response error: %v", err)
	} else {
		t.Logf("Long response: Allowed=%v", result.Allowed)
	}
}

func TestResponseScanner_MixedContent(t *testing.T) {
	rs := NewResponseScanner()
	mixed := "Name: John " + "Email: john@example.com " + "SSN: 123-45-6789 " + "Token: sk_live_abc"
	result, err := rs.ScanResponse(context.Background(), mixed)
	if err != nil {
		t.Errorf("Mixed content scan failed: %v", err)
	}
	t.Logf("Mixed content: Allowed=%v", result.Allowed)
}

// ============================================================================
// HTTP Handler Tests
// ============================================================================

func TestResponseScanner_HttpHandler(t *testing.T) {
	rs := NewResponseScanner()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := rs.ScanResponse(r.Context(), "HTTP response content")
		if err != nil {
			http.Error(w, "Scan failed", http.StatusInternalServerError)
			return
		}
		if !result.Allowed {
			http.Error(w, "Blocked: "+result.BlockReason, http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	t.Logf("HTTP handler response: %d", w.Code)
}
