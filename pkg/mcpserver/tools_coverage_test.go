// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Tools Coverage Tests
// =========================================================================
// Targeted tests for uncovered branches in tools.go (47.4% → target 80%)
// =========================================================================

package mcpserver

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// mockToolsAuthorizer is a minimal mock for creating a RequestHandler.
type mockToolsAuthorizer struct{}

func (m *mockToolsAuthorizer) Authorize(_ context.Context, _ *mcp.AuthorizationCall) (*mcp.AuthorizationDecision, error) {
	return &mcp.AuthorizationDecision{Allowed: true}, nil
}

// mockToolsAuditLogger is a minimal mock for creating a RequestHandler.
type mockToolsAuditLogger struct{}

func (m *mockToolsAuditLogger) Log(_ context.Context, _ *mcp.AuditEntry) error {
	return nil
}

// mockToolsSessionMgr is a minimal mock for creating a RequestHandler.
type mockToolsSessionMgr struct{}

func (m *mockToolsSessionMgr) CreateSession(_ context.Context, agentID string) (*mcp.Session, error) {
	return &mcp.Session{ID: "test-session", AgentID: agentID}, nil
}

func (m *mockToolsSessionMgr) GetSession(_ context.Context, sessionID string) (*mcp.Session, error) {
	return &mcp.Session{ID: sessionID}, nil
}

func (m *mockToolsSessionMgr) DeleteSession(_ context.Context, _ string) error {
	return nil
}

// helper to create a RequestHandler with mocks
func newTestHandler() *mcp.RequestHandler {
	return mcp.NewRequestHandler(
		&mockToolsAuthorizer{},
		&mockToolsAuditLogger{},
		&mockToolsSessionMgr{},
	)
}

// TestRegisterBuiltInTools_All17Registered verifies that all 17 built-in tools
// are registered into the handler's registry.
func TestRegisterBuiltInTools_All17Registered(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	count := handler.Registry.Count()
	if count != 17 {
		t.Errorf("Registry.Count() = %d, want 17", count)
	}
}

// TestRegisterBuiltInTools_SpecificToolNames verifies each expected tool name
// is present in the registry.
func TestRegisterBuiltInTools_SpecificToolNames(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	safeTools := []string{
		"process_list", "memory_stats", "network_connections", "system_info",
		"git_status", "git_log", "git_diff",
		"file_read", "web_search", "http_request", "json_fetch", "code_search",
	}
	blockedTools := []string{
		"shell_command", "code_execute", "file_write", "file_delete", "database_query",
	}

	for _, name := range safeTools {
		if _, ok := handler.Registry.GetTool(name); !ok {
			t.Errorf("safe tool %q not found in registry", name)
		}
	}

	for _, name := range blockedTools {
		if _, ok := handler.Registry.GetTool(name); !ok {
			t.Errorf("blocked tool %q not found in registry", name)
		}
	}
}

// TestRegisterBuiltInTools_TierGating verifies tools exist for different tiers.
// The tools are always registered; tier gating happens at the guardrail/authorizer level.
func TestRegisterBuiltInTools_TierGating(t *testing.T) {
	tiers := []tier.Tier{
		tier.TierCommunity,
		tier.TierDeveloper,
		tier.TierProfessional,
		tier.TierEnterprise,
	}

	for _, t2 := range tiers {
		t.Run(t2.String(), func(t *testing.T) {
			handler := newTestHandler()
			RegisterBuiltInTools(handler, t2)

			// All tiers should get all 17 tools (gating is at auth/guardrail level)
			count := handler.Registry.Count()
			if count != 17 {
				t.Errorf("tier %s: Registry.Count() = %d, want 17", t2.String(), count)
			}
		})
	}
}

// TestRegisterBuiltInTools_HandlersRegistered verifies that handlers are
// registered alongside tool definitions by checking GetHandler.
func TestRegisterBuiltInTools_HandlersRegistered(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	// Check that a few representative tools have handlers
	for _, name := range []string{"process_list", "memory_stats", "file_read", "shell_command"} {
		if _, ok := handler.Registry.GetHandler(name); !ok {
			t.Errorf("tool %q has no handler registered", name)
		}
	}
}

// TestRegisterBuiltInTools_RiskLevels verifies risk levels are set correctly.
func TestRegisterBuiltInTools_RiskLevels(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	// Safe tools should have low risk levels
	for _, name := range []string{"process_list", "memory_stats", "system_info"} {
		risk := handler.Registry.GetRiskLevel(name)
		if risk <= 0 {
			t.Errorf("tool %q risk level = %d, expected > 0", name, risk)
		}
	}

	// Blocked (security) tools should have high risk levels
	for _, name := range []string{"shell_command", "code_execute", "file_delete"} {
		risk := handler.Registry.GetRiskLevel(name)
		if risk < 50 {
			t.Errorf("blocked tool %q risk level = %d, expected >= 50", name, risk)
		}
	}
}

// TestRegisterBuiltInTools_ToMCPFormat verifies tools can be exported in MCP format.
func TestRegisterBuiltInTools_ToMCPFormat(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	tools := handler.Registry.ToMCPFormat()
	if len(tools) != 17 {
		t.Errorf("ToMCPFormat() returned %d tools, want 17", len(tools))
	}
}

// TestRegisterTool_DuplicateName verifies that registering a duplicate
// tool name doesn't panic (the error is logged and skipped).
func TestRegisterTool_DuplicateName(t *testing.T) {
	registry := mcp.NewToolRegistry()

	// First registration succeeds
	err := registry.Register("test_tool", "A test tool", 10, nil)
	if err != nil {
		t.Fatalf("first Register() error: %v", err)
	}

	// Second registration with same name should return error
	err = registry.Register("test_tool", "Duplicate", 10, nil)
	if err == nil {
		t.Error("duplicate Register() should return error, got nil")
	}
}

// TestRegisterBuiltInTools_NoDuplicateNames verifies no duplicate tool names
// across the full built-in set.
func TestRegisterBuiltInTools_NoDuplicateNames(t *testing.T) {
	handler := newTestHandler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	// List all tools and check for duplicates
	toolList := handler.Registry.ListTools()
	seen := make(map[string]bool)
	for _, name := range toolList {
		if seen[name] {
			t.Errorf("duplicate tool name: %q", name)
		}
		seen[name] = true
	}
}
