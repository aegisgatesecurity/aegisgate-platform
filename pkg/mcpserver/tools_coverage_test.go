package mcpserver

import (
	"context"
	"sync"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// TestRegisterBuiltInTools_Comprehensive tests that all built-in tools are correctly registered
func TestRegisterBuiltInTools_Comprehensive(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{
		Registry: registry,
	}
	RegisterBuiltInTools(handler, tier.TierCommunity)

	toolCount := registry.Count()
	if toolCount != 17 {
		t.Errorf("Expected 17 tools registered, got %d", toolCount)
	}

	expectedTools := []string{
		"process_list",
		"memory_stats",
		"network_connections",
		"system_info",
		"git_status",
		"git_log",
		"git_diff",
		"file_read",
		"web_search",
		"http_request",
		"json_fetch",
		"code_search",
	}

	for _, name := range expectedTools {
		if _, ok := registry.GetTool(name); !ok {
			t.Errorf("Tool %s should be registered", name)
		}
	}
}

// TestRegisterBuiltInTools_ErrorPaths tests error handling in registerTool
func TestRegisterBuiltInTools_ErrorPaths(t *testing.T) {
	registry := mcp.NewToolRegistry()

	err := registry.Register("test_tool", "Test tool", 10, map[string]interface{}{})
	if err != nil {
		t.Fatalf("First register failed: %v", err)
	}

	err = registry.Register("test_tool", "Duplicate", 10, map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}

	executor := func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return nil, nil
	}

	err = registry.RegisterHandler("test_tool", executor)
	if err != nil {
		t.Errorf("RegisterHandler failed: %v", err)
	}

	if h, ok := registry.GetHandler("test_tool"); !ok {
		t.Error("Handler should be registered")
	} else if h == nil {
		t.Error("Handler should not be nil")
	}
}

// TestRegisterBuiltInTools_RaceCondition tests concurrent registration
func TestRegisterBuiltInTools_RaceCondition(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{
		Registry: registry,
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterBuiltInTools(handler, tier.TierCommunity)
		}()
	}

	wg.Wait()

	if registry == nil {
		t.Fatal("Registry should not be nil")
	}

	toolCount := registry.Count()
	if toolCount != 17 {
		t.Errorf("Expected 17 tools after concurrent registration, got %d", toolCount)
	}
}

// TestRegisterTool_Functionality tests registerTool helper function directly
func TestRegisterTool_Functionality(t *testing.T) {
	registry := mcp.NewToolRegistry()

	toolSchema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}

	executor := func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return nil, nil
	}
	registerTool(registry, "test_register", "Test description", 10, toolSchema, executor)

	tool, ok := registry.GetTool("test_register")
	if !ok {
		t.Error("Tool should be registered")
	} else {
		if tool.Description != "Test description" {
			t.Errorf("Expected description 'Test description', got '%s'", tool.Description)
		}
		if tool.RiskLevel != 10 {
			t.Errorf("Expected risk level 10, got %d", tool.RiskLevel)
		}
	}
}

// TestRegisterBuiltInTools_TierBasedVerification verifies tier-specific tool availability
func TestRegisterBuiltInTools_TierBasedVerification(t *testing.T) {
	registry1 := mcp.NewToolRegistry()
	handler1 := &mcp.RequestHandler{
		Registry: registry1,
	}
	RegisterBuiltInTools(handler1, tier.TierCommunity)
	communityTools := registry1.Count()

	registry2 := mcp.NewToolRegistry()
	handler2 := &mcp.RequestHandler{
		Registry: registry2,
	}
	RegisterBuiltInTools(handler2, tier.TierEnterprise)
	enterpriseTools := registry2.Count()

	if communityTools != enterpriseTools {
		t.Errorf("Expected same tool count for both tiers, got %d vs %d",
			communityTools, enterpriseTools)
	}
}

// TestRegisterBuiltInTools_NoPanics tests that registration doesn't panic
func TestRegisterBuiltInTools_NoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RegisterBuiltInTools panicked: %v", r)
		}
	}()

	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{
		Registry: registry,
	}
	RegisterBuiltInTools(handler, tier.TierCommunity)
}

// TestRegisterTool_InvalidToolNames tests handling of various tool names
func TestRegisterTool_InvalidToolNames(t *testing.T) {
	registry := mcp.NewToolRegistry()

	invalidNames := []string{
		"",            // empty
		"   ",         // whitespace only
		"tool-name",   // hyphen
		"tool.name",   // dot
		"tool name",   // space
	}

	for _, name := range invalidNames {
		executor := func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, nil
		}
		registerTool(registry, name, "Test", 10, map[string]interface{}{}, executor)
	}
}
