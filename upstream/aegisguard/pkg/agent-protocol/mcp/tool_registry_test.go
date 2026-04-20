// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// Tool Registry Tests
// =========================================================================

package mcp

import (
	"context"
	"sync"
	"testing"
)

// TestToolRegistryRegistration tests basic tool registration
func TestToolRegistryRegistration(t *testing.T) {
	registry := NewToolRegistry()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"path": map[string]interface{}{"type": "string"},
		},
	}

	err := registry.Register("file_read", "Read a file", 10, schema)
	if err != nil {
		t.Fatalf("Failed to register tool: %v", err)
	}

	// Verify tool is registered
	tools := registry.ListTools()
	if len(tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(tools))
	}

	if tools[0] != "file_read" {
		t.Errorf("Expected tool 'file_read', got '%s'", tools[0])
	}
}

// TestToolRegistryDuplicateRegistration tests that duplicate registration fails
func TestToolRegistryDuplicateRegistration(t *testing.T) {
	registry := NewToolRegistry()

	schema := map[string]interface{}{"type": "object"}

	err := registry.Register("test_tool", "A test tool", 10, schema)
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	err = registry.Register("test_tool", "A test tool", 10, schema)
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}
}

// TestToolRegistryEmptyName tests that empty tool names are rejected
func TestToolRegistryEmptyName(t *testing.T) {
	registry := NewToolRegistry()

	err := registry.Register("", "A tool", 10, nil)
	if err == nil {
		t.Error("Expected error for empty tool name")
	}
}

// TestToolRegistryGetTool tests retrieving a registered tool
func TestToolRegistryGetTool(t *testing.T) {
	registry := NewToolRegistry()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"url": map[string]interface{}{"type": "string"},
		},
	}

	registry.Register("http_get", "Make HTTP GET request", 40, schema)

	tool, ok := registry.GetTool("http_get")
	if !ok {
		t.Fatal("Expected to find tool 'http_get'")
	}

	if tool.Name != "http_get" {
		t.Errorf("Expected tool name 'http_get', got '%s'", tool.Name)
	}

	if tool.Description != "Make HTTP GET request" {
		t.Errorf("Expected description 'Make HTTP GET request', got '%s'", tool.Description)
	}

	if tool.RiskLevel != 40 {
		t.Errorf("Expected risk level 40, got %d", tool.RiskLevel)
	}
}

// TestToolRegistryGetToolNotFound tests retrieving a non-existent tool
func TestToolRegistryGetToolNotFound(t *testing.T) {
	registry := NewToolRegistry()

	_, ok := registry.GetTool("nonexistent")
	if ok {
		t.Error("Expected tool not to be found")
	}
}

// TestToolRegistryHandlerRegistration tests registering tool handlers
func TestToolRegistryHandlerRegistration(t *testing.T) {
	registry := NewToolRegistry()

	handler := func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "success", nil
	}

	err := registry.RegisterHandler("my_tool", handler)
	if err != nil {
		t.Fatalf("Failed to register handler: %v", err)
	}

	// Verify handler is registered
	storedHandler, ok := registry.GetHandler("my_tool")
	if !ok {
		t.Fatal("Expected to find handler 'my_tool'")
	}

	result, err := storedHandler(context.Background(), nil)
	if err != nil {
		t.Errorf("Handler execution failed: %v", err)
	}
	if result != "success" {
		t.Errorf("Expected 'success', got '%v'", result)
	}
}

// TestToolRegistryHandlerNotFound tests executing a non-existent handler
func TestToolRegistryHandlerNotFound(t *testing.T) {
	registry := NewToolRegistry()

	_, err := registry.Execute(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Error("Expected error for non-existent handler")
	}
}

// TestToolRegistryExecute tests tool execution with parameters
func TestToolRegistryExecute(t *testing.T) {
	registry := NewToolRegistry()

	handler := func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		path, ok := params["path"].(string)
		if !ok {
			return nil, nil
		}
		return "Reading: " + path, nil
	}

	registry.RegisterHandler("read", handler)
	registry.Register("read", "Read a file", 10, nil)

	result, err := registry.Execute(context.Background(), "read", map[string]interface{}{
		"path": "/tmp/test.txt",
	})

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result != "Reading: /tmp/test.txt" {
		t.Errorf("Expected 'Reading: /tmp/test.txt', got '%v'", result)
	}
}

// TestToolRegistryToMCPFormat tests conversion to MCP format
func TestToolRegistryToMCPFormat(t *testing.T) {
	registry := NewToolRegistry()

	registry.Register("tool1", "First tool", 20, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param1": map[string]interface{}{"type": "string"},
		},
	})

	registry.Register("tool2", "Second tool", 30, map[string]interface{}{
		"type": "object",
	})

	tools := registry.ToMCPFormat()

	if len(tools) != 2 {
		t.Fatalf("Expected 2 tools, got %d", len(tools))
	}

	// Check that the tools have the expected names
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}

	if !names["tool1"] {
		t.Error("Expected tool1 in MCP format")
	}
	if !names["tool2"] {
		t.Error("Expected tool2 in MCP format")
	}
}

// TestToolRegistryCount tests tool count
func TestToolRegistryCount(t *testing.T) {
	registry := NewToolRegistry()

	if registry.Count() != 0 {
		t.Errorf("Expected 0 tools, got %d", registry.Count())
	}

	registry.Register("tool1", "Tool 1", 10, nil)
	if registry.Count() != 1 {
		t.Errorf("Expected 1 tool, got %d", registry.Count())
	}

	registry.Register("tool2", "Tool 2", 20, nil)
	if registry.Count() != 2 {
		t.Errorf("Expected 2 tools, got %d", registry.Count())
	}
}

// TestToolRegistryGetRiskLevel tests risk level retrieval
func TestToolRegistryGetRiskLevel(t *testing.T) {
	registry := NewToolRegistry()

	registry.Register("low_risk", "Low risk tool", 10, nil)
	registry.Register("medium_risk", "Medium risk tool", 50, nil)
	registry.Register("high_risk", "High risk tool", 90, nil)

	tests := []struct {
		name     string
		toolName string
		expected int
	}{
		{"LowRisk", "low_risk", 10},
		{"MediumRisk", "medium_risk", 50},
		{"HighRisk", "high_risk", 90},
		{"UnknownTool", "unknown", 100}, // Unknown tools default to high risk
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := registry.GetRiskLevel(tt.toolName)
			if risk != tt.expected {
				t.Errorf("Expected risk %d, got %d", tt.expected, risk)
			}
		})
	}
}

// TestToolRegistryDefaultTools tests default tool registration
func TestToolRegistryDefaultTools(t *testing.T) {
	registry := NewToolRegistry()
	registry.RegisterDefaultTools()

	// Updated to include all 25 default tools (8 original + 17 new)
	expectedTools := []string{
		// Original tools
		"file_read",
		"file_write",
		"file_exists",
		"web_search",
		"http_request",
		"shell_command",
		"code_search",
		"ping",
		// Database tools
		"db_query",
		"db_list",
		"db_schema",
		// Code execution tools
		"code_execute_go",
		"code_execute_py",
		"code_execute_js",
		// System tools
		"process_list",
		"memory_stats",
		"network_connections",
		"system_info",
		// File management tools
		"file_copy",
		"file_move",
		"file_delete",
		"file_mkdir",
		// Git tools
		"git_status",
		"git_log",
		"git_diff",
	}

	tools := registry.ListTools()
	if len(tools) != len(expectedTools) {
		t.Errorf("Expected %d default tools, got %d", len(expectedTools), len(tools))
	}

	// Verify each expected tool exists
	toolMap := make(map[string]bool)
	for _, name := range tools {
		toolMap[name] = true
	}

	for _, expected := range expectedTools {
		if !toolMap[expected] {
			t.Errorf("Expected default tool '%s' not found", expected)
		}
	}
}

// TestToolRegistryConcurrentAccess tests thread safety
func TestToolRegistryConcurrentAccess(t *testing.T) {
	registry := NewToolRegistry()

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	// Concurrent registrations
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			registry.Register(
				"tool_"+string(rune('a'+index%26)),
				"Concurrent tool",
				10,
				nil,
			)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify no crashes occurred
	count := registry.Count()
	t.Logf("Successfully registered %d tools concurrently", count)
}

// TestToolRegistryConcurrentReads tests concurrent read operations
func TestToolRegistryConcurrentReads(t *testing.T) {
	registry := NewToolRegistry()

	// Pre-populate with some tools
	for i := 0; i < 10; i++ {
		registry.Register("tool_"+string(rune('0'+i)), "Tool", 10, nil)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Perform various read operations
			registry.ListTools()
			registry.Count()
			registry.GetTool("tool_5")
			registry.GetRiskLevel("tool_3")
			registry.ToMCPFormat()
		}()
	}

	wg.Wait()
	// If we get here without panic, the test passes
}

// TestToolRegistryListToolsOrder tests that ListTools returns all tools
func TestToolRegistryListToolsOrder(t *testing.T) {
	registry := NewToolRegistry()

	tools := []struct {
		name string
		risk int
	}{
		{"alpha", 10},
		{"beta", 20},
		{"gamma", 30},
	}

	for _, tool := range tools {
		registry.Register(tool.name, tool.name+" tool", tool.risk, nil)
	}

	listed := registry.ListTools()

	if len(listed) != len(tools) {
		t.Errorf("Expected %d tools, got %d", len(tools), len(listed))
	}

	// Verify all tools are present
	toolSet := make(map[string]bool)
	for _, name := range listed {
		toolSet[name] = true
	}

	for _, tool := range tools {
		if !toolSet[tool.name] {
			t.Errorf("Tool '%s' not found in list", tool.name)
		}
	}
}

// TestToolRegistrySchemaPreservation tests that schemas are preserved
func TestToolRegistrySchemaPreservation(t *testing.T) {
	registry := NewToolRegistry()

	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"command": map[string]interface{}{
				"type":        "string",
				"description": "Command to execute",
			},
			"timeout": map[string]interface{}{
				"type":    "integer",
				"default": 30,
			},
		},
		"required": []string{"command"},
	}

	registry.Register("exec", "Execute command", 90, schema)

	tool, ok := registry.GetTool("exec")
	if !ok {
		t.Fatal("Tool not found")
	}

	// Verify schema is preserved
	if tool.InputSchema == nil {
		t.Fatal("InputSchema is nil")
	}

	props, ok := tool.InputSchema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("Properties not found in schema")
	}

	if _, ok := props["command"]; !ok {
		t.Error("Command property not found in schema")
	}
}

// TestGenerateRequestID tests request ID generation
func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	// IDs should be generated
	if id1 == "" {
		t.Error("Generated ID should not be empty")
	}

	// IDs should have the expected prefix
	expectedPrefix := "req-"
	if len(id1) < len(expectedPrefix) || id1[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("ID should start with '%s', got '%s'", expectedPrefix, id1)
	}

	// Different calls should produce (likely) different IDs
	t.Logf("Generated IDs: %s, %s", id1, id2)
}
