//go:build !race

// SPDX-License-Identifier: Apache-2.0
package mcpserver

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// TestOnSessionDestroy_WithSession exercises OnSessionDestroy
func TestOnSessionDestroy_WithSession(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-destroy")

	// Create session via OnSessionCreate
	g.OnSessionCreate("test-session", "agent1", "client1")

	// Verify session exists
	if _, exists := g.sessions["test-session"]; !exists {
		t.Fatal("session should exist after OnSessionCreate")
	}

	// Now destroy it
	g.OnSessionDestroy("test-session")

	// Session should be removed
	if _, exists := g.sessions["test-session"]; exists {
		t.Error("session should be removed")
	}
}

// TestOnToolCallWithAuth_Matrix exercises OnToolCallWithAuth with a real Matrix
func TestOnToolCallWithAuth_Matrix(t *testing.T) {
	matrix := toolauth.NewMatrix()
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-matrix")
	g.toolAuth = matrix

	err := g.OnToolCallWithAuth("session-1", "agent-1", "process_list")
	if err != nil {
		t.Logf("OnToolCallWithAuth result: %v", err)
	}
}

// TestOnToolCallWithAuth_DeniedTool exercises OnToolCallWithAuth with a denied tool
func TestOnToolCallWithAuth_DeniedTool(t *testing.T) {
	matrix := toolauth.NewMatrix()
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-denied")
	g.toolAuth = matrix

	err := g.OnToolCallWithAuth("session-1", "agent-1", "shell_command")
	if err == nil {
		t.Error("shell_command should be denied for Developer tier")
	}
}

// TestOnMemoryUsage exercises OnMemoryUsage
func TestOnMemoryUsage_Basic(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-memory")
	g.OnSessionCreate("s1", "agent1", "client1")
	g.OnMemoryUsage("s1", 256)
	t.Log("OnMemoryUsage completed")
}

// TestOnMemoryUsage_ExceedLimit exercises OnMemoryUsage exceeding limit
func TestOnMemoryUsage_ExceedLimit(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-memory-exceed")
	g.OnSessionCreate("s1", "agent1", "client1")
	// Developer tier has 512MB limit
	g.OnMemoryUsage("s1", 1024)
	t.Log("OnMemoryUsage exceeding limit completed")
}

// TestRegisterBuiltInTools_AllTiers exercises RegisterBuiltInTools at all tier levels
func TestRegisterBuiltInTools_AllTiers(t *testing.T) {
	tiers := []tier.Tier{tier.TierCommunity, tier.TierDeveloper, tier.TierProfessional, tier.TierEnterprise}

	for _, tierLevel := range tiers {
		registry := mcp.NewToolRegistry()
		handler := &mcp.RequestHandler{Registry: registry}
		RegisterBuiltInTools(handler, tierLevel)
	}
}

// TestRegisterBuiltInTools_EnterpriseShellCommand exercises Enterprise-tier shell_command
func TestRegisterBuiltInTools_EnterpriseShellCommand(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierEnterprise)

	_, ok := registry.GetHandler("shell_command")
	if !ok {
		t.Error("shell_command should be registered for Enterprise")
	}
}

// TestRegisterBuiltInTools_EnterpriseOnlyTools exercises Enterprise-only tools
func TestRegisterBuiltInTools_EnterpriseOnlyTools(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierEnterprise)

	// These tools should be registered for Enterprise
	tools := []string{"shell_command", "code_execute"}
	for _, tool := range tools {
		_, ok := registry.GetHandler(tool)
		if !ok {
			t.Errorf("%s should be registered for Enterprise", tool)
		}
	}
}
