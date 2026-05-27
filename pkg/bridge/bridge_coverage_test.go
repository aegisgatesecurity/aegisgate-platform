package bridge

import (
	"context"
	"testing"
)

func TestLLMRequest_Fields(t *testing.T) {
	req := LLMRequest{
		AgentID:  "agent-1",
		Endpoint: "/v1/chat/completions",
		Model:    "gpt-4",
		Headers:  map[string]string{"Authorization": "Bearer test"},
	}
	if req.AgentID != "agent-1" {
		t.Errorf("AgentID mismatch")
	}
	if req.Endpoint != "/v1/chat/completions" {
		t.Errorf("Endpoint mismatch")
	}
}

func TestLLMResponse_Fields(t *testing.T) {
	resp := LLMResponse{
		Model:   "gpt-4",
		Content: "Hello world",
		Usage:   Usage{Tokens: 100},
	}
	if resp.Model != "gpt-4" {
		t.Errorf("Model mismatch")
	}
}

func TestScanResult_Allowed(t *testing.T) {
	result := ScanResult{
		Allowed:   true,
		ScannedAt: "2024-01-01",
	}
	if !result.Allowed {
		t.Error("Should be allowed")
	}
}

func TestThreat_AllFields(t *testing.T) {
	threat := Threat{
		Type:     "injection",
		Severity: ThreatSeverityCritical,
		Message:  "Prompt injection detected",
		Location: "user_message",
	}
	if threat.Type != "injection" {
		t.Errorf("Type mismatch")
	}
	if threat.Severity != ThreatSeverityCritical {
		t.Errorf("Severity mismatch")
	}
}

func TestComplianceViolation_Fields(t *testing.T) {
	violation := ComplianceViolation{
		Framework: "HIPAA",
		Rule:      "phi_disclosure",
		Severity:  ThreatSeverityHigh,
	}
	if violation.Framework != "HIPAA" {
		t.Errorf("Framework mismatch")
	}
}

func TestStats_Fields(t *testing.T) {
	stats := Stats{
		TotalRequests:   1000,
		BlockedRequests: 50,
		ThreatsDetected: 10,
	}
	if stats.TotalRequests != 1000 {
		t.Errorf("TotalRequests mismatch")
	}
}

func TestLLMToolContext_Fields(t *testing.T) {
	ctx := LLMToolContext{
		ToolName: "web_search",
		AgentID:  "agent-1",
	}
	if ctx.ToolName != "web_search" {
		t.Errorf("ToolName mismatch")
	}
}

func TestPlatformBridgeResponseScanner(t *testing.T) {
	rs := NewResponseScanner()
	if rs == nil {
		t.Error("Scanner should not be nil")
	}
}

func TestPlatformBridgeResponseScannerWithConfig(t *testing.T) {
	rs := NewResponseScannerWithConfig(nil)
	if rs == nil {
		t.Error("Scanner should not be nil")
	}
}

func TestResponseScanner_Scan(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "Clean response")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestResponseScanner_IsAllowed(t *testing.T) {
	rs := NewResponseScanner()
	allowed := rs.IsResponseAllowed(context.Background(), "Clean text")
	if !allowed {
		t.Error("Should be allowed")
	}
}

func TestResponseScanner_GetStats(t *testing.T) {
	rs := NewResponseScanner()
	stats := rs.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}
}

func TestResponseScanner_ScanAndFilter(t *testing.T) {
	rs := NewResponseScanner()
	result := rs.ScanAndFilter(context.Background(), "Filtered text")
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestResponseScanner_GetComplianceReport(t *testing.T) {
	rs := NewResponseScanner()
	report := rs.GetComplianceReport()
	if report == nil {
		t.Error("Report should not be nil")
	}
}

func TestResponseScanner_GetDetectedPII(t *testing.T) {
	rs := NewResponseScanner()
	pii := rs.GetDetectedPII()
	if pii == nil {
		t.Error("PII list should not be nil")
	}
}

func TestResponseScanner_GetDetectedSecrets(t *testing.T) {
	rs := NewResponseScanner()
	secrets := rs.GetDetectedSecrets()
	if secrets == nil {
		t.Error("Secrets list should not be nil")
	}
}

func TestPlatformBridge_WithResponse(t *testing.T) {
	pb := NewPlatformBridgeWithResponse(nil)
	if pb == nil {
		t.Error("Bridge should not be nil")
	}
}

func TestPlatformBridge_GetResponseScanner(t *testing.T) {
	pb := NewPlatformBridgeWithResponse(nil)
	rs := pb.GetResponseScanner()
	if rs == nil {
		t.Error("ResponseScanner should not be nil")
	}
}

func TestPlatformBridge_RouteLLMCall(t *testing.T) {
	pb := NewPlatformBridge()
	pb.SetEnabled(true)
	resp, err := pb.RouteLLMCall(context.Background(), &LLMRequest{
		AgentID:  "agent-1",
		Endpoint: "/v1/chat/completions",
	})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("Response should not be nil")
	}
}

func TestPlatformBridge_Disabled(t *testing.T) {
	pb := NewPlatformBridge()
	pb.SetEnabled(false)
	resp, err := pb.RouteLLMCall(context.Background(), &LLMRequest{AgentID: "agent-1"})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("Response should not be nil")
	}
}

func TestPlatformBridge_GetStats(t *testing.T) {
	pb := NewPlatformBridge()
	stats := pb.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}
}

func TestPlatformBridge_Close(t *testing.T) {
	pb := NewPlatformBridge()
	err := pb.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestBridge_IsLLMCall(t *testing.T) {
	pb := NewPlatformBridge()
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"/v1/chat/completions", true},
		{"/v1/completions", true},
		{"/v1/embeddings", true},
		{"/health", false},
		{"/metrics", false},
	}
	for _, tt := range tests {
		result := pb.IsLLMCall(&LLMRequest{Endpoint: tt.endpoint})
		if result != tt.expected {
			t.Errorf("IsLLMCall(%s) = %v, want %v", tt.endpoint, result, tt.expected)
		}
	}
}

func TestBridgeConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Error("Config should not be nil")
	}
}

func TestUsage_Fields(t *testing.T) {
	usage := Usage{Tokens: 100}
	if usage.Tokens != 100 {
		t.Errorf("Tokens mismatch")
	}
}
