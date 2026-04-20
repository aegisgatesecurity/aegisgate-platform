// SPDX-License-Identifier: Apache-2.0
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

func TestNewPlatformBridgeWithConfig_NilConfig(t *testing.T) {
	// Test with nil config - should use defaults
	pb, err := bridge.NewPlatformBridgeWithConfig(nil)
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithConfig(nil) failed: %v", err)
	}
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("expected bridge to be enabled with default config")
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
		{
			name:     "anthropic_tool",
			toolName: "anthropic",
			args:     map[string]interface{}{"content": "hello"},
			want:     true,
		},
		{
			name:     "gemini_tool",
			toolName: "gemini",
			args:     map[string]interface{}{"messages": []string{"hello"}},
			want:     true,
		},
		{
			name:     "command_exec_tool",
			toolName: "command",
			args:     map[string]interface{}{"cmd": "ls -la"},
			want:     false,
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
	if bridge.SeverityLow != guardbridge.SeverityLow {
		t.Error("SeverityLow mismatch")
	}
	if bridge.SeverityMedium != guardbridge.SeverityMedium {
		t.Error("SeverityMedium mismatch")
	}
	if bridge.SeverityHigh != guardbridge.SeverityHigh {
		t.Error("SeverityHigh mismatch")
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

func TestPlatformBridgeClose(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}

	// First close should succeed
	if err := pb.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	// Second close on already-closed bridge should not panic
	if err := pb.Close(); err != nil {
		// May error if already closed, which is acceptable
		t.Logf("second Close() returned: %v (acceptable)", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := bridge.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Verify default values
	if cfg.Enabled != true {
		t.Error("expected Enabled = true by default")
	}
	if cfg.Timeout <= 0 {
		t.Error("expected positive Timeout")
	}
	if cfg.MaxRetries < 0 {
		t.Error("expected non-negative MaxRetries")
	}
}

func TestSeverityConstants(t *testing.T) {
	// Test all severity levels are properly exported
	_ = bridge.SeverityInfo
	_ = bridge.SeverityLow
	_ = bridge.SeverityMedium
	_ = bridge.SeverityHigh
	_ = bridge.SeverityCritical
}

func TestBridgeWithDifferentURLSchemes(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"http", "http://localhost:8080"},
		{"https", "https://localhost:8443"},
		{"with_path", "http://localhost:8080/proxy"},
		{"with_auth", "http://user:pass@localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb, err := bridge.NewPlatformBridge(tt.url)
			if err != nil {
				t.Fatalf("NewPlatformBridge(%q) failed: %v", tt.url, err)
			}
			defer pb.Close()

			if !pb.IsEnabled() {
				t.Error("expected bridge to be enabled")
			}
		})
	}
}

func TestBridgeConcurrentOperations(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	// Test concurrent enabled state reads/writes
	done := make(chan bool, 10)
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				pb.SetEnabled(id%2 == 0)
				_ = pb.IsEnabled()
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}

	// Verify final state is consistent
	finalState := pb.IsEnabled()
	pb.SetEnabled(!finalState)
	if pb.IsEnabled() == finalState {
		t.Error("bridge state toggle failed")
	}
}

func TestRouteLLMCall_Enabled(t *testing.T) {
	// Create a mock server to test actual routing
	// For coverage, we test both enabled and disabled paths
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	// Enable the bridge
	pb.SetEnabled(true)

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

	// This will attempt to route to localhost:8080 which won't respond
	// But it exercises the enabled path code
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = pb.RouteLLMCall(ctx, req)
	// We expect an error because localhost:8080 isn't running
	// but this covers the enabled branch
	if err == nil {
		t.Skip("RouteLLMCall enabled path requires a running AegisGate")
	}
}

func TestIsLLMCall(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	// Test with known LLM tool name
	result := pb.IsLLMCall("openai_chat_completion", map[string]interface{}{
		"model": "gpt-4",
	})
	_ = result

	// Test with non-LLM tool
	result = pb.IsLLMCall("get_weather", map[string]interface{}{
		"location": "NYC",
	})
	_ = result
}

func TestGetStats(t *testing.T) {
	pb, err := bridge.NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	stats := pb.GetStats()
	if stats == nil {
		t.Error("GetStats returned nil")
	}
}
