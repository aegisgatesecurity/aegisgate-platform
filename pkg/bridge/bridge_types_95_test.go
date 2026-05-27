package bridge_test

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
)

func TestNewResponseScanner_WithNilConfig(t *testing.T) {
	scanner := bridge.NewResponseScannerWithConfig(nil)
	if scanner == nil {
		t.Fatal("Scanner should not be nil")
	}
}

func TestScanResponse_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	result, err := scanner.ScanResponse(ctx, "Clean response")
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestScanResponseWithContext_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	result, err := scanner.ScanResponseWithContext(ctx, "Clean response", nil)
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestScanLLMResponse_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	result, err := scanner.ScanLLMResponse(ctx, "Clean LLM response", "client-1")
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestIsResponseAllowed_True(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	allowed := scanner.IsResponseAllowed(ctx, "clean response")
	_ = allowed
}

func TestGetComplianceReport_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	report, err := scanner.GetComplianceReport(ctx, "clean response")
	if err != nil {
		t.Errorf("Should not error: %v", err)
	}
	if report == nil {
		t.Fatal("Expected report")
	}
}

func TestGetDetectedPII_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	pii := scanner.GetDetectedPII(ctx, "clean response")
	_ = pii
}

func TestGetDetectedSecrets_Clean(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	secrets := scanner.GetDetectedSecrets(ctx, "clean response")
	_ = secrets
}

func TestLLMRequest_TypeExport(t *testing.T) {
	req := bridge.LLMRequest{
		RequestID: "req-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		TargetURL: "https://api.example.com",
		Method:    "POST",
		Headers:   map[string]string{"Content-Type": "application/json"},
	}
	if req.RequestID != "req-1" {
		t.Errorf("RequestID should be 'req-1', got '%s'", req.RequestID)
	}
}

func TestLLMResponse_TypeExport(t *testing.T) {
	resp := bridge.LLMResponse{
		RequestID:  "req-1",
		StatusCode: 200,
		Body:       []byte("response body"),
	}
	if resp.RequestID != "req-1" {
		t.Errorf("RequestID should be 'req-1', got '%s'", resp.RequestID)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode should be 200, got %d", resp.StatusCode)
	}
}

func TestScanResult_TypeExport(t *testing.T) {
	result := bridge.ScanResult{}
	_ = result.Allowed
}

func TestThreat_TypeExport(t *testing.T) {
	threat := bridge.Threat{}
	_ = threat.Type
	_ = threat.Severity
}

func TestComplianceViolation_TypeExport(t *testing.T) {
	violation := bridge.ComplianceViolation{}
	_ = violation.Framework
	_ = violation.Severity
}

func TestStats_TypeExport(t *testing.T) {
	stats := bridge.Stats{
		TotalRequests:   100,
		BlockedRequests: 5,
	}
	if stats.TotalRequests != 100 {
		t.Errorf("TotalRequests should be 100, got %d", stats.TotalRequests)
	}
}

func TestLLMToolContext_TypeExport(t *testing.T) {
	ctx := bridge.LLMToolContext{
		ToolName: "web_search",
		AgentID:  "agent-1",
	}
	if ctx.ToolName != "web_search" {
		t.Errorf("ToolName should be 'web_search', got '%s'", ctx.ToolName)
	}
}

func TestSeverityConstants_Values(t *testing.T) {
	_ = bridge.SeverityInfo
	_ = bridge.SeverityLow
	_ = bridge.SeverityMedium
	_ = bridge.SeverityHigh
	_ = bridge.SeverityCritical
}

func TestDefaultConfig_Export(t *testing.T) {
	cfg := bridge.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should not return nil")
	}
}
