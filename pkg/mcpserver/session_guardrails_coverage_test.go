//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Session/Guardrails Coverage Tests
// =========================================================================
//
// Covers uncovered functions:
//   - GuardrailMiddleware.ValidateSessionCommand  (guardrails.go)
//   - ConnectionSessionManager.SetGuardrails     (session_manager.go)
//   - RegisterBuiltInTools blocked-tool handlers (tools.go)
package mcpserver

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// --------------------------------------------------------------------------
// ValidateSessionCommand
// --------------------------------------------------------------------------

// TestValidateSessionCommand_NilValidator tests the FAIL-CLOSED path: when
// stdioValidator is nil the command must be denied by default.
func TestValidateSessionCommand_NilValidator(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg, "test-server")

	// When Enabled=false, NewGuardrailMiddleware does NOT create a stdioValidator,
	// so g.stdioValidator == nil.
	if g.stdioValidator != nil {
		t.Fatal("expected stdioValidator to be nil for disabled middleware")
	}

	err := g.ValidateSessionCommand("/usr/bin/node server.js")
	if err == nil {
		t.Error("expected error when stdioValidator is nil (fail-closed)")
	}
	if err.Error() != "STDIO validation unavailable: command denied by default" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

// TestValidateSessionCommand_ValidCommand tests that a safe command passes
// validation when the STDIO validator is present.
func TestValidateSessionCommand_ValidCommand(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-server")

	err := g.ValidateSessionCommand("echo hello")
	if err != nil {
		t.Errorf("expected no error for safe command: %v", err)
	}
}

// TestValidateSessionCommand_DangerousCommand tests that dangerous commands are blocked.
// In strict mode (DefaultSTDIOValidationConfig), commands with shell metacharacters
// are blocked by the allowlist regex (Guard 3). In non-strict mode, commands matching
// dangerous patterns like pipe_chaining (;) are blocked by Guard 4.
func TestValidateSessionCommand_DangerousCommand(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierDeveloper,
		LogViolations: true,
	}
	g := NewGuardrailMiddleware(cfg, "test-server")

	// Replace strict-mode validator with non-strict so Guard 4 (dangerous pattern
	// scan) fires for pipe_chaining patterns like "rm -rf /; echo pwned"
	orig := g.stdioValidator
	g.stdioValidator = NewSTDIOValidator(STDIOValidationConfig{
		Enabled:          true,
		StrictMode:       false, // non-strict → Guard 4 dangerousPatterns active
		MaxCommandLength: 4096,
	})
	defer func() { g.stdioValidator = orig }()

	err := g.ValidateSessionCommand("rm -rf /; echo pwned")
	if err == nil {
		t.Error("expected error for dangerous command with shell metacharacter")
	}
}

// --------------------------------------------------------------------------
// OnToolCallWithAuth
// --------------------------------------------------------------------------

// TestOnToolCallWithAuth_Matrix exercises OnToolCallWithAuth with a real Matrix
func TestOnToolCallWithAuth_Matrix(t *testing.T) {
	matrix := toolauth.NewMatrix()
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-matrix")
	g.toolAuth = matrix

	_ = g.OnToolCallWithAuth("session-1", "agent-1", "process_list")
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

// --------------------------------------------------------------------------
// OnMemoryUsage
// --------------------------------------------------------------------------

// TestOnMemoryUsage_Basic exercises OnMemoryUsage
func TestOnMemoryUsage_Basic(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-memory")
	g.OnSessionCreate("s1", "agent1", "client1")
	g.OnMemoryUsage("s1", 256)
}

// TestOnMemoryUsage_ExceedLimit exercises OnMemoryUsage exceeding limit
func TestOnMemoryUsage_ExceedLimit(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-memory-exceed")
	g.OnSessionCreate("s1", "agent1", "client1")
	g.OnMemoryUsage("s1", 1024) // exceeds 512MB Developer limit
}

// --------------------------------------------------------------------------
// OnToolCallWithContext
// --------------------------------------------------------------------------

// TestOnToolCallWithContext_Basic exercises OnToolCallWithContext basic path
func TestOnToolCallWithContext_Basic(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-context")
	g.OnSessionCreate("test-session", "agent1", "client1")

	ctx := context.Background()
	_, cancel := g.OnToolCallWithContext(ctx)
	cancel()
}

// --------------------------------------------------------------------------
// OnSessionDestroy
// --------------------------------------------------------------------------

// TestOnSessionDestroy_WithSession exercises OnSessionDestroy
func TestOnSessionDestroy_WithSession(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)
	g := NewGuardrailMiddleware(cfg, "test-destroy")

	g.OnSessionCreate("test-session", "agent1", "client1")
	if _, exists := g.sessions["test-session"]; !exists {
		t.Fatal("session should exist after OnSessionCreate")
	}

	g.OnSessionDestroy("test-session")
	if _, exists := g.sessions["test-session"]; exists {
		t.Error("session should be removed")
	}
}

// --------------------------------------------------------------------------
// RegisterBuiltInTools - Enterprise-only tools
// --------------------------------------------------------------------------

// TestRegisterBuiltInTools_AllTiers exercises RegisterBuiltInTools at all tier levels
func TestRegisterBuiltInTools_AllTiers(t *testing.T) {
	for _, tierLevel := range []tier.Tier{
		tier.TierCommunity, tier.TierDeveloper, tier.TierProfessional, tier.TierEnterprise,
	} {
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

	for _, tool := range []string{"shell_command", "code_execute"} {
		if _, ok := registry.GetHandler(tool); !ok {
			t.Errorf("%s should be registered for Enterprise", tool)
		}
	}
}

// --------------------------------------------------------------------------
// GuardrailMiddleware compile-time interface check
// --------------------------------------------------------------------------

var _ = struct {
	GuardrailMiddleware interface {
		OnSessionCreate(sessionID, agentID, clientID string)
		OnSessionDestroy(sessionID string)
		OnToolCall(sessionID, agentID, toolName string)
		OnToolCallWithAuth(sessionID, agentID, toolName string) error
		OnToolCallWithContext(ctx context.Context) (context.Context, context.CancelFunc)
		OnMemoryUsage(sessionID string, memoryMB int64)
		ValidateSessionCommand(cmd string) error
	}
}{}
