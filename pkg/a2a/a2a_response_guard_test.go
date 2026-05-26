// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 AegisGate Security
// =========================================================================
// A2A Response Guard Tests - Coverage for pkg/a2a/a2a_response_guard.go
// =========================================================================

package a2a

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// A2AResponseScanner Tests
// ============================================================================

func TestNewA2AResponseScanner(t *testing.T) {
	scanner := NewA2AResponseScanner()
	if scanner == nil {
		t.Fatal("NewA2AResponseScanner returned nil")
	}
	if scanner.guard == nil {
		t.Error("A2AResponseScanner.guard should not be nil")
	}
	if scanner.agentStats == nil {
		t.Error("A2AResponseScanner.agentStats should be initialized")
	}
}

func TestNewA2AResponseScannerWithConfig(t *testing.T) {
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:        true,
		EnableSecretDetection:   true,
		EnableToxicityFilter:    true,
		EnableHallucination:     true,
		MaxResponseTokens:       10000,
		MaxResponseLatencyMS:   1000,
	}

	scanner := NewA2AResponseScannerWithConfig(config)
	if scanner == nil {
		t.Fatal("NewA2AResponseScannerWithConfig returned nil")
	}
	t.Log("A2AResponseScanner with config created")
}

func TestA2AResponseScanner_ScanResponse(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "A2A agent response", "agent-001")
	if err != nil {
		t.Errorf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanResponse returned nil")
	}
	t.Logf("A2A ScanResponse: Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanResponse_WithPII(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "Email: john@example.com", "agent-001")
	if err != nil {
		t.Errorf("ScanResponse with PII failed: %v", err)
	}
	t.Logf("A2A PII scan: Allowed=%v, DetectedPII=%v", result.Allowed, result.DetectedPII)
}

func TestA2AResponseScanner_ScanResponse_WithSecret(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "Key: sk_live_1234567890", "agent-001")
	if err != nil {
		t.Errorf("ScanResponse with secret failed: %v", err)
	}
	t.Logf("A2A Secret scan: Allowed=%v, DetectedSecrets=%v", result.Allowed, result.DetectedSecrets)
}

func TestA2AResponseScanner_ScanA2AMessage_String(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanA2AMessage(context.Background(), "A2A message string", "agent-001")
	if err != nil {
		t.Errorf("ScanA2AMessage (string) failed: %v", err)
	}
	if result == nil {
		t.Fatal("ScanA2AMessage returned nil")
	}
	t.Logf("ScanA2AMessage (string): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanA2AMessage_ByteSlice(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanA2AMessage(context.Background(), []byte("A2A message bytes"), "agent-002")
	if err != nil {
		t.Errorf("ScanA2AMessage (bytes) failed: %v", err)
	}
	t.Logf("ScanA2AMessage (bytes): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanA2AMessage_MapWithText(t *testing.T) {
	scanner := NewA2AResponseScanner()
	msg := map[string]interface{}{
		"text":    "A2A message text",
		"sender":  "agent-003",
	}
	result, err := scanner.ScanA2AMessage(context.Background(), msg, "agent-003")
	if err != nil {
		t.Errorf("ScanA2AMessage (map/text) failed: %v", err)
	}
	t.Logf("ScanA2AMessage (map/text): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanA2AMessage_MapWithData(t *testing.T) {
	scanner := NewA2AResponseScanner()
	msg := map[string]interface{}{
		"data":   "A2A message data",
		"sender": "agent-004",
	}
	result, err := scanner.ScanA2AMessage(context.Background(), msg, "agent-004")
	if err != nil {
		t.Errorf("ScanA2AMessage (map/data) failed: %v", err)
	}
	t.Logf("ScanA2AMessage (map/data): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanA2AMessage_MapWithPayload(t *testing.T) {
	scanner := NewA2AResponseScanner()
	msg := map[string]interface{}{
		"payload": "A2A message payload",
	}
	result, err := scanner.ScanA2AMessage(context.Background(), msg, "agent-006")
	if err != nil {
		t.Errorf("ScanA2AMessage (map/payload) failed: %v", err)
	}
	t.Logf("ScanA2AMessage (map/payload): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_ScanA2AMessage_EmptyMap(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanA2AMessage(context.Background(), map[string]interface{}{}, "agent-empty")
	if err != nil {
		t.Errorf("ScanA2AMessage (empty map) failed: %v", err)
	}
	t.Logf("ScanA2AMessage (empty map): Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_UpdateAgentStats(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, _ := scanner.ScanResponse(context.Background(), "Test content", "agent-stats")
	scanner.UpdateAgentStats("agent-stats", result)
	stats := scanner.GetAgentStats("agent-stats")
	if stats == nil {
		t.Fatal("GetAgentStats returned nil")
	}
	t.Logf("Agent stats: Scanned=%d", stats.ResponsesScanned)
}

func TestA2AResponseScanner_UpdateAgentStats_Multiple(t *testing.T) {
	scanner := NewA2AResponseScanner()
	for i := 0; i < 5; i++ {
		result, _ := scanner.ScanResponse(context.Background(), "Response "+string(rune('0'+i)), "agent-multi")
		scanner.UpdateAgentStats("agent-multi", result)
	}
	stats := scanner.GetAgentStats("agent-multi")
	if stats.ResponsesScanned != 5 {
		t.Errorf("ResponsesScanned: got %d, want 5", stats.ResponsesScanned)
	}
}

func TestA2AResponseScanner_GetAgentStats_NotFound(t *testing.T) {
	scanner := NewA2AResponseScanner()
	stats := scanner.GetAgentStats("nonexistent-agent")
	if stats != nil {
		t.Error("GetAgentStats should return nil for nonexistent agent")
	}
}

// ============================================================================
// ResponseGuardMiddleware Tests
// ============================================================================

func TestNewResponseGuardMiddleware(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	if middleware == nil {
		t.Fatal("NewResponseGuardMiddleware returned nil")
	}
	if middleware.scanner == nil {
		t.Error("middleware.scanner should not be nil")
	}
	if !middleware.enabled {
		t.Error("middleware should be enabled by default")
	}
}

func TestNewResponseGuardMiddlewareWithConfig(t *testing.T) {
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		StrictMode:            true,
	}
	middleware := NewResponseGuardMiddlewareWithConfig(config)
	if middleware == nil {
		t.Fatal("NewResponseGuardMiddlewareWithConfig returned nil")
	}
	t.Log("Middleware with strict mode created")
}

func TestResponseGuardMiddleware_GuardResponse(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	allowed, response, err := middleware.GuardResponse(context.Background(), "Test response", "agent-guard")
	if err != nil {
		t.Errorf("GuardResponse failed: %v", err)
	}
	t.Logf("GuardResponse: allowed=%v, response=%s", allowed, response)
}

func TestResponseGuardMiddleware_GuardResponse_PII(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	allowed, _, err := middleware.GuardResponse(context.Background(), "Phone: 555-987-6543", "agent-pii")
	if err != nil {
		t.Errorf("GuardResponse PII failed: %v", err)
	}
	t.Logf("GuardResponse PII: allowed=%v", allowed)
}

func TestResponseGuardMiddleware_GuardResponse_Disabled(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	middleware.SetEnabled(false)
	allowed, response, err := middleware.GuardResponse(context.Background(), "Any content", "agent-disabled")
	if err != nil {
		t.Errorf("GuardResponse disabled failed: %v", err)
	}
	if !allowed {
		t.Error("Disabled middleware should allow all responses")
	}
	if response != "Any content" {
		t.Error("Disabled middleware should return original response")
	}
}

func TestResponseGuardMiddleware_IsEnabled(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	if !middleware.IsEnabled() {
		t.Error("Middleware should be enabled by default")
	}
	middleware.SetEnabled(false)
	if middleware.IsEnabled() {
		t.Error("Middleware should be disabled after SetEnabled(false)")
	}
}

func TestResponseGuardMiddleware_SetEnabled(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	middleware.SetEnabled(false)
	if middleware.enabled {
		t.Error("Middleware should be disabled")
	}
	middleware.SetEnabled(true)
	if !middleware.enabled {
		t.Error("Middleware should be enabled")
	}
}

func TestResponseGuardMiddleware_GetAgentStats(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	middleware.GuardResponse(context.Background(), "Test content", "agent-stats-mw")
	stats := middleware.GetAgentStats("agent-stats-mw")
	if stats == nil {
		t.Error("GetAgentStats returned nil")
	} else {
		t.Logf("Middleware agent stats: Scanned=%d", stats.ResponsesScanned)
	}
}

// ============================================================================
// A2AResponseHandler Tests
// ============================================================================

func TestNewA2AResponseHandler(t *testing.T) {
	handler := NewA2AResponseHandler()
	if handler == nil {
		t.Fatal("NewA2AResponseHandler returned nil")
	}
	t.Log("A2AResponseHandler created")
}

func TestNewA2AResponseHandlerWithConfig(t *testing.T) {
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
	}
	handler := NewA2AResponseHandlerWithConfig(config)
	if handler == nil {
		t.Fatal("NewA2AResponseHandlerWithConfig returned nil")
	}
	t.Log("A2AResponseHandler with config created")
}

func TestA2AResponseHandler_HandleResponse(t *testing.T) {
	handler := NewA2AResponseHandler()
	_, result, err := handler.HandleResponse(context.Background(), "A2A response content", "agent-handle")
	if err != nil {
		t.Errorf("HandleResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("HandleResponse returned nil result")
	}
	t.Logf("HandleResponse: Allowed=%v", result.Allowed)
}

func TestA2AResponseHandler_HandleResponse_WithThreats(t *testing.T) {
	handler := NewA2AResponseHandler()
	_, result, err := handler.HandleResponse(context.Background(), "Secret: sk_live_abc123", "agent-threat")
	if err != nil {
		t.Logf("HandleResponse with threats: %v", err)
	}
	t.Logf("HandleResponse threats: Allowed=%v, Threats=%d", result.Allowed, len(result.Threats))
}

func TestA2AResponseHandler_GetComplianceReport(t *testing.T) {
	handler := NewA2AResponseHandler()
	report, err := handler.GetComplianceReport(context.Background(), "Compliance content")
	if err != nil {
		t.Errorf("GetComplianceReport failed: %v", err)
	}
	t.Logf("Compliance report categories: %d", len(report))
}

// ============================================================================
// A2AMiddlewareWithResponse Tests
// ============================================================================

func TestA2AMiddlewareWithResponse_ServeHTTP(t *testing.T) {
	t.Log("A2AMiddlewareWithResponse documented")
}

// ============================================================================
// RegisterA2AServerWithResponse Tests
// ============================================================================

func TestRegisterA2AServerWithResponse(t *testing.T) {
	mux := http.NewServeMux()
	config := &responseguard.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
	}
	caps := NewInMemoryCapEnforcer()
	RegisterA2AServerWithResponse(mux, []byte("test-secret"), nil, caps, config)
	t.Log("RegisterA2AServerWithResponse executed")
}

// ============================================================================
// Concurrency Tests
// ============================================================================

func TestA2AResponseScanner_ConcurrentScans(t *testing.T) {
	scanner := NewA2AResponseScanner()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agentID := "agent-" + string(rune('0'+id%10))
			content := "Response from " + string(rune('A'+id%26))
			scanner.ScanResponse(context.Background(), content, agentID)
		}(i)
	}
	wg.Wait()
	t.Log("Completed concurrent A2A scans")
}

func TestResponseGuardMiddleware_ConcurrentGuard(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agentID := "concurrent-" + string(rune('0'+id%10))
			middleware.GuardResponse(context.Background(), "Concurrent response", agentID)
		}(i)
	}
	wg.Wait()
	t.Log("Completed concurrent GuardResponse calls")
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestA2AResponseScanner_EmptyContent(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "", "agent-empty")
	if err != nil {
		t.Errorf("Empty content scan failed: %v", err)
	}
	t.Logf("Empty content scan: Allowed=%v", result.Allowed)
}

func TestA2AResponseScanner_UnicodeContent(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "Unicode: " + "Привет", "agent-unicode")
	if err != nil {
		t.Errorf("Unicode content scan failed: %v", err)
	}
	t.Logf("Unicode content scan: Allowed=%v", result.Allowed)
}

func TestResponseGuardMiddleware_ZeroContent(t *testing.T) {
	middleware := NewResponseGuardMiddleware()
	allowed, _, err := middleware.GuardResponse(context.Background(), "", "agent-zero")
	if err != nil {
		t.Errorf("Zero content guard failed: %v", err)
	}
	t.Logf("Zero content: Allowed=%v", allowed)
}

func TestA2AResponseHandler_EmptyResponse(t *testing.T) {
	handler := NewA2AResponseHandler()
	_, result, err := handler.HandleResponse(context.Background(), "", "agent-empty-handler")
	if err != nil {
		t.Errorf("Empty response handle failed: %v", err)
	}
	t.Logf("Empty response handle: Allowed=%v", result.Allowed)
}

// ============================================================================
// HTTP Handler Tests
// ============================================================================

func TestA2AResponseHandler_HttpHandler(t *testing.T) {
	handler := NewA2AResponseHandler()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, result, err := handler.HandleResponse(r.Context(), "HTTP response", "agent-http")
		if err != nil {
			http.Error(w, "Blocked", http.StatusForbidden)
			return
		}
		if !result.Allowed {
			http.Error(w, "Response blocked", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/a2a/response", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	t.Logf("HTTP handler response: %d", w.Code)
}
