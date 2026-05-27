package bridge

import (
	"context"
	"testing"
)

// ============================================================================
// BRIDGE COVERAGE TESTS
// ============================================================================

func TestBridgeConfigCreation(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should return non-nil")
	}
}

func TestBridgeSeverityConstants(t *testing.T) {
	_ = SeverityInfo
	_ = SeverityLow
	_ = SeverityMedium
	_ = SeverityHigh
	_ = SeverityCritical
}

func TestBridgeLLMRequestType(t *testing.T) {
	req := LLMRequest{
		AgentID:   "test-agent",
		SessionID: "test-session",
	}
	if req.AgentID != "test-agent" {
		t.Errorf("AgentID mismatch")
	}
}

func TestBridgeLLMResponseType(t *testing.T) {
	resp := LLMResponse{}
	_ = resp
}

func TestBridgeScanResultType(t *testing.T) {
	result := ScanResult{
		Allowed: true,
	}
	if !result.Allowed {
		t.Error("Allowed should be true")
	}
}

func TestBridgeThreatType(t *testing.T) {
	threat := Threat{
		Type:     "prompt_injection",
		Severity: SeverityHigh,
	}
	if threat.Type != "prompt_injection" {
		t.Errorf("Type mismatch")
	}
}

func TestBridgeComplianceViolationType(t *testing.T) {
	violation := ComplianceViolation{
		Framework: "SOC2",
		Severity:  SeverityMedium,
	}
	if violation.Framework != "SOC2" {
		t.Errorf("Framework mismatch")
	}
}

func TestBridgeStatsType(t *testing.T) {
	stats := Stats{}
	if stats.TotalRequests != 0 {
		t.Error("TotalRequests should be 0 by default")
	}
}

func TestBridgeLLMToolContextType(t *testing.T) {
	ctx := LLMToolContext{
		ToolName: "web_search",
		AgentID:  "agent-1",
	}
	if ctx.ToolName != "web_search" {
		t.Errorf("ToolName mismatch")
	}
}

func TestNewPlatformBridgeWithConfig(t *testing.T) {
	pb, err := NewPlatformBridgeWithConfig(nil)
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithConfig(nil) failed: %v", err)
	}
	if pb == nil {
		t.Fatal("Should create with nil config")
	}
}

func TestPlatformBridgeSetEnabled(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	pb.SetEnabled(true)
	pb.SetEnabled(false)
}

func TestPlatformBridgeGetStats(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	stats := pb.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}
}

func TestPlatformBridgeClose(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	err := pb.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestPlatformBridgeRouteLLMCallDisabled(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	pb.SetEnabled(false)

	req := &LLMRequest{
		AgentID:   "agent-1",
		SessionID: "session-1",
	}

	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Errorf("Disabled bridge should not error: %v", err)
	}
	if resp == nil {
		t.Error("Response should not be nil")
	}
}

func TestPlatformBridgeIsEnabled(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	pb.SetEnabled(true)
	if !pb.IsEnabled() {
		t.Error("Should be enabled")
	}
	pb.SetEnabled(false)
	if pb.IsEnabled() {
		t.Error("Should be disabled")
	}
}

func TestPlatformBridgeIsLLMCall(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)

	tests := []struct {
		toolName string
		args     map[string]interface{}
	}{
		{"chat.complete", nil},
		{"unknown.tool", nil},
	}

	for _, tt := range tests {
		result := pb.IsLLMCall(tt.toolName, tt.args)
		_ = result // Just call it
	}
}

func TestPlatformBridgeGateway(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	gw := pb.Gateway()
	if gw == nil {
		t.Error("Gateway should not be nil")
	}
}

func TestNewPlatformBridge(t *testing.T) {
	pb, err := NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	if pb == nil {
		t.Fatal("Should create with URL")
	}
	pb.Close()
}

func TestPlatformBridgeRouteLLMCallEnabled(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)
	pb.SetEnabled(true)

	req := &LLMRequest{
		AgentID:   "agent-1",
		SessionID: "session-1",
	}

	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Errorf("Enabled bridge should not error: %v", err)
	}
	if resp == nil {
		t.Error("Response should not be nil")
	}
}

func TestPlatformBridgeMultipleOperations(t *testing.T) {
	pb, _ := NewPlatformBridgeWithConfig(nil)

	pb.SetEnabled(true)
	if !pb.IsEnabled() {
		t.Error("Should be enabled")
	}
	pb.SetEnabled(false)
	if pb.IsEnabled() {
		t.Error("Should be disabled")
	}

	stats := pb.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}

	pb.Close()
}
