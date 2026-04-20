// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security - Bridge Integration Tests
//
// =========================================================================
//
// These tests demonstrate the AegisGate bridge integration.
//
// =========================================================================

package mcp

import (
	"context"
	"testing"
)

// TestLLMCallDetection tests LLM tool call detection
func TestLLMCallDetection(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		args      map[string]interface{}
		expectLLM bool
	}{
		{
			name:      "OpenAI tool",
			toolName:  "openai_chat",
			args:      map[string]interface{}{"model": "gpt-4", "messages": []interface{}{}},
			expectLLM: true,
		},
		{
			name:      "Anthropic tool",
			toolName:  "claude_complete",
			args:      map[string]interface{}{"model": "claude-3", "prompt": "Hello"},
			expectLLM: true,
		},
		{
			name:      "URL with OpenAI endpoint",
			toolName:  "api_call",
			args:      map[string]interface{}{"url": "https://api.openai.com/v1/chat/completions"},
			expectLLM: true,
		},
		{
			name:      "Azure OpenAI endpoint",
			toolName:  "azure_llm",
			args:      map[string]interface{}{"endpoint": "https://example.openai.azure.com/openai/deployments/gpt-4"},
			expectLLM: true,
		},
		{
			name:      "Bedrock tool",
			toolName:  "bedrock_invoke",
			args:      map[string]interface{}{"model": "anthropic.claude-v2"},
			expectLLM: true,
		},
		{
			name:      "Non-LLM tool - file read",
			toolName:  "file_read",
			args:      map[string]interface{}{"path": "/etc/passwd"},
			expectLLM: false,
		},
		{
			name:      "Non-LLM tool - shell command",
			toolName:  "shell_exec",
			args:      map[string]interface{}{"command": "ls -la"},
			expectLLM: false,
		},
		{
			name:      "Database query",
			toolName:  "database_query",
			args:      map[string]interface{}{"sql": "SELECT * FROM users"},
			expectLLM: false,
		},
		{
			name:      "Git operations",
			toolName:  "git_commit",
			args:      map[string]interface{}{"message": "Fix bug", "path": "."},
			expectLLM: false,
		},
		{
			name:      "Unknown tool with no LLM indicators",
			toolName:  "custom_tool",
			args:      map[string]interface{}{"action": "do_something"},
			expectLLM: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLLMCall(tt.toolName, tt.args)
			if result != tt.expectLLM {
				t.Errorf("IsLLMCall(%q, %v) = %v, want %v",
					tt.toolName, tt.args, result, tt.expectLLM)
			}
		})
	}
}

// TestBridgeIntegrationDisabled tests bridge when disabled
func TestBridgeIntegrationDisabled(t *testing.T) {
	config := &BridgeConfig{
		Enabled: false,
	}

	bi, err := NewBridgeIntegration(config)
	if err != nil {
		t.Fatalf("NewBridgeIntegration() error = %v", err)
	}

	if bi.IsEnabled() {
		t.Error("Expected bridge to be disabled")
	}

	// ShouldIntercept should return false when disabled
	if bi.ShouldIntercept("openai_chat", nil) {
		t.Error("ShouldIntercept() should return false when bridge is disabled")
	}
}

// TestBridgeIntegrationEnabled tests bridge initialization when enabled
func TestBridgeIntegrationEnabled(t *testing.T) {
	config := &BridgeConfig{
		Enabled:       true,
		AegisGateURL:  "http://localhost:8080",
		SkipTLSVerify: true,
	}

	bi, err := NewBridgeIntegration(config)
	if err != nil {
		t.Fatalf("NewBridgeIntegration() error = %v", err)
	}

	if !bi.IsEnabled() {
		t.Error("Expected bridge to be enabled")
	}

	// Cleanup
	bi.Close()
}

// TestBridgeEnabledHandler tests the bridge-enabled handler creation
func TestBridgeEnabledHandler(t *testing.T) {
	handlerConfig := &AegisGuardHandlerConfig{}
	bridgeConfig := &BridgeConfig{
		Enabled: false, // Disabled for test
	}

	handler, err := NewBridgeEnabledHandler(handlerConfig, bridgeConfig)
	if err != nil {
		t.Fatalf("NewBridgeEnabledHandler() error = %v", err)
	}

	// When bridge is disabled in config, handler should report it disabled
	if handler.IsBridgeEnabled() {
		t.Error("Expected bridge to be disabled when configured as disabled")
	}

	// Health status should include bridge info
	status := handler.HealthStatus()
	if status["bridge"] != "disabled" {
		t.Errorf("Expected bridge status 'disabled', got %q", status["bridge"])
	}

	// Cleanup
	handler.Close()
}

// TestShouldIntercept tests intercept decision logic
func TestShouldIntercept(t *testing.T) {
	bi := &BridgeIntegration{enabled: true}

	tests := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		should   bool
	}{
		{
			name:     "LLM tool should be intercepted",
			toolName: "openai",
			args:     map[string]interface{}{"model": "gpt-4"},
			should:   true,
		},
		{
			name:     "Non-LLM tool should not be intercepted",
			toolName: "file_read",
			args:     nil,
			should:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bi.ShouldIntercept(tt.toolName, tt.args)
			if result != tt.should {
				t.Errorf("ShouldIntercept(%q) = %v, want %v",
					tt.toolName, result, tt.should)
			}
		})
	}
}

// TestBuildLLMToolContext tests context building
func TestBuildLLMToolContext(t *testing.T) {
	bi := &BridgeIntegration{enabled: true}

	ctx := bi.BuildLLMToolContext(
		"conn-123",
		"session-456",
		"agent-789",
		"openai_chat",
		map[string]interface{}{"model": "gpt-4"},
	)

	if ctx.AgentID != "agent-789" {
		t.Errorf("Expected AgentID 'agent-789', got %q", ctx.AgentID)
	}
	if ctx.SessionID != "session-456" {
		t.Errorf("Expected SessionID 'session-456', got %q", ctx.SessionID)
	}
	if ctx.ToolName != "openai_chat" {
		t.Errorf("Expected ToolName 'openai_chat', got %q", ctx.ToolName)
	}
	if ctx.ToolArgs["model"] != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got %v", ctx.ToolArgs["model"])
	}
}

// TestBuildLLMRequestBody tests LLM request body building
func TestBuildLLMRequestBody(t *testing.T) {
	args := map[string]interface{}{
		"model":       "gpt-4",
		"messages":    []interface{}{map[string]string{"role": "user", "content": "Hello"}},
		"temperature": 0.7,
		"max_tokens":  100,
	}

	data, contentType, err := BuildLLMRequestBody(args)
	if err != nil {
		t.Fatalf("BuildLLMRequestBody() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty data")
	}

	if contentType != "application/json" {
		t.Errorf("Expected contentType 'application/json', got %q", contentType)
	}
}

// TestBridgeStats tests bridge statistics
func TestBridgeStats(t *testing.T) {
	stats := &BridgeStats{
		TotalRequests:   100,
		AllowedRequests: 95,
		BlockedRequests: 3,
		FailedRequests:  2,
		ThreatsDetected: 5,
	}

	if stats.TotalRequests != 100 {
		t.Errorf("Expected TotalRequests 100, got %d", stats.TotalRequests)
	}

	if stats.AllowedRequests != 95 {
		t.Errorf("Expected AllowedRequests 95, got %d", stats.AllowedRequests)
	}
}

// TestDefaultBridgeConfig tests default configuration
func TestDefaultBridgeConfig(t *testing.T) {
	config := DefaultBridgeConfig()

	if config.AegisGateURL != "http://localhost:8080" {
		t.Errorf("Expected AegisGateURL 'http://localhost:8080', got %q", config.AegisGateURL)
	}

	if config.Timeout != 30*1e9 { // 30 seconds in nanoseconds
		t.Errorf("Expected Timeout 30s, got %v", config.Timeout)
	}

	if config.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries 3, got %d", config.MaxRetries)
	}

	if config.SkipTLSVerify != true {
		t.Error("Expected SkipTLSVerify to be true by default")
	}
}

// TestLLMToolResult tests LLM tool result structure
func TestLLMToolResult(t *testing.T) {
	result := &LLMToolResult{
		Content: []ContentBlock{
			{Type: "text", Text: "Hello, world!"},
		},
		IsError:      false,
		Blocked:      false,
		RiskScore:    0.25,
		ScannedBy:    "aegisgate",
		ScanDuration: 50,
	}

	if result.Blocked {
		t.Error("Expected Blocked to be false")
	}

	if result.ScannedBy != "aegisgate" {
		t.Errorf("Expected ScannedBy 'aegisgate', got %q", result.ScannedBy)
	}

	if len(result.Content) != 1 {
		t.Errorf("Expected 1 content block, got %d", len(result.Content))
	}
}

// TestContextBuilding tests context building from MCP call
func TestContextBuilding(t *testing.T) {
	// Simulate MCP tool call
	toolName := "openai_complete"
	args := map[string]interface{}{
		"model":      "gpt-4",
		"prompt":     "What is the capital of France?",
		"max_tokens": 100,
	}

	// Detect if LLM call
	if !IsLLMCall(toolName, args) {
		t.Error("Expected IsLLMCall to return true for OpenAI tool")
	}

	// Build context (would be done by handler)
	bi := &BridgeIntegration{enabled: true}
	ctx := bi.BuildLLMToolContext("conn-1", "session-1", "agent-1", toolName, args)

	if ctx.ToolArgs["model"] != "gpt-4" {
		t.Error("Context should preserve model argument")
	}
}

// BenchmarkLLMCallDetection benchmarks LLM call detection
func BenchmarkLLMCallDetection(b *testing.B) {
	toolName := "openai_chat"
	args := map[string]interface{}{
		"model":       "gpt-4",
		"messages":    []interface{}{},
		"temperature": 0.7,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsLLMCall(toolName, args)
	}
}

// BenchmarkShouldIntercept benchmarks intercept decision
func BenchmarkShouldIntercept(b *testing.B) {
	bi := &BridgeIntegration{enabled: true}
	args := map[string]interface{}{"model": "gpt-4"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bi.ShouldIntercept("openai_chat", args)
	}
}

// Example_integrationWorkflow demonstrates integration workflow
func Example_integrationWorkflow() {
	ctx := context.Background()

	// 1. Create bridge configuration
	bridgeConfig := &BridgeConfig{
		Enabled:      true,
		AegisGateURL: "http://localhost:8080",
		Timeout:      30,
	}

	// 2. Create handler with bridge
	handlerConfig := &AegisGuardHandlerConfig{}
	handler, err := NewBridgeEnabledHandler(handlerConfig, bridgeConfig)
	if err != nil {
		panic(err)
	}
	defer handler.Close()

	// 3. Check if bridge is enabled
	if handler.IsBridgeEnabled() {
		// Get stats
		stats := handler.GetBridgeStats()
		if stats != nil {
			println("Total requests:", stats.TotalRequests)
		}

		// Check health
		status := handler.HealthStatus()
		println("Bridge status:", status["bridge"])
	}

	// 4. Process MCP request (bridge will automatically intercept LLM calls)
	_ = ctx // Use context in actual request processing
}
