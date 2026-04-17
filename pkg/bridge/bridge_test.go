// SPDX-License-Identifier: MIT
// Package bridge_test verifies the platform bridge wiring to upstream modules.
package bridge_test

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	// Verify we can also import the upstream types directly
	guardbridge "github.com/aegisguardsecurity/aegisguard/pkg/bridge"
)

func TestNewPlatformBridge(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("expected bridge to be enabled by default")
	}
}

func TestNewPlatformBridgeWithConfig(t *testing.T) {
	cfg := &bridge.Config{
		AegisGateURL:  "http://localhost:9090",
		Timeout:       10 * time.Second,
		Enabled:       true,
		MaxRetries:    2,
		RetryInterval: 200 * time.Millisecond,
		SkipTLSVerify: true,
		DefaultTarget: "https://api.anthropic.com",
	}

	pb, err := bridge.NewPlatformBridgeWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithConfig failed: %v", err)
	}
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("expected bridge to be enabled")
	}
}

func TestPlatformBridgeRouteWhenDisabled(t *testing.T) {
	cfg := bridge.DefaultConfig()
	cfg.Enabled = false

	pb, err := bridge.NewPlatformBridgeWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithConfig failed: %v", err)
	}
	defer pb.Close()

	req := &bridge.LLMRequest{
		RequestID: "test-123",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		TargetURL: "https://api.openai.com/v1/chat/completions",
		Method:    "POST",
		Headers:   map[string]string{"Authorization": "Bearer test-key"},
		Body:      []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`),
		Timestamp: time.Now(),
	}

	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Fatalf("RouteLLMCall when disabled should not error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status 200 when disabled, got %d", resp.StatusCode)
	}
}

func TestPlatformBridgeSetEnabled(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("expected bridge to start enabled")
	}

	pb.SetEnabled(false)
	if pb.IsEnabled() {
		t.Error("expected bridge to be disabled after SetEnabled(false)")
	}

	pb.SetEnabled(true)
	if !pb.IsEnabled() {
		t.Error("expected bridge to be re-enabled after SetEnabled(true)")
	}
}

func TestPlatformBridgeIsLLMCall(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	tests := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		want     bool
	}{
		{
			name:     "openai_chat_tool",
			toolName: "openai_chat",
			args:     map[string]interface{}{"model": "gpt-4"},
			want:     true,
		},
		{
			name:     "file_read_tool",
			toolName: "file_read",
			args:     map[string]interface{}{"path": "/tmp/test.txt"},
			want:     false,
		},
		{
			name:     "llm_with_prompt",
			toolName: "ai_assistant",
			args:     map[string]interface{}{"prompt": "explain this"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pb.IsLLMCall(tt.toolName, tt.args)
			if got != tt.want {
				t.Errorf("IsLLMCall(%q, %v) = %v, want %v", tt.toolName, tt.args, got, tt.want)
			}
		})
	}
}

func TestUpstreamTypeCompatibility(t *testing.T) {
	// Verify that platform bridge re-exported types are identical to upstream
	var _ bridge.Config = guardbridge.Config{}
	var _ bridge.LLMRequest = guardbridge.LLMRequest{}
	var _ bridge.LLMResponse = guardbridge.LLMResponse{}
	var _ bridge.ScanResult = guardbridge.ScanResult{}
	var _ bridge.Threat = guardbridge.Threat{}
	var _ bridge.ComplianceViolation = guardbridge.ComplianceViolation{}

	// Verify severity constants match
	if bridge.SeverityInfo != guardbridge.SeverityInfo {
		t.Error("SeverityInfo mismatch")
	}
	if bridge.SeverityCritical != guardbridge.SeverityCritical {
		t.Error("SeverityCritical mismatch")
	}
}

func TestPlatformBridgeGetStats(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	stats := pb.GetStats()
	if stats == nil {
		t.Error("expected non-nil stats")
	}
}

func TestPlatformBridgeGatewayAccess(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	gw := pb.Gateway()
	if gw == nil {
		t.Error("expected non-nil gateway")
	}
}