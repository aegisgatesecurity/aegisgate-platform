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
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
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
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	if g.stdioValidator == nil {
		t.Fatal("expected stdioValidator to be initialized for enabled middleware")
	}

	err := g.ValidateSessionCommand("node")
	if err != nil {
		t.Errorf("safe command should pass validation, got: %v", err)
	}
}

// TestValidateSessionCommand_DangerousCommand tests that a command with shell
// metacharacters is blocked when the STDIO validator is present.
func TestValidateSessionCommand_DangerousCommand(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	// Pipe metacharacter — classic injection vector
	err := g.ValidateSessionCommand("rm -rf / ; cat /etc/passwd")
	if err == nil {
		t.Error("dangerous command with semicolon should be blocked")
	}
}

// TestValidateSessionCommand_EmptyCommand tests the empty-command guard.
func TestValidateSessionCommand_EmptyCommand(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	err := g.ValidateSessionCommand("")
	if err == nil {
		t.Error("empty command should be blocked")
	}
}

// TestValidateSessionCommand_WhitespaceCommand tests the whitespace-only guard.
func TestValidateSessionCommand_WhitespaceCommand(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	err := g.ValidateSessionCommand("   ")
	if err == nil {
		t.Error("whitespace-only command should be blocked")
	}
}

// TestValidateSessionCommand_NewlineInjection tests newline injection blocking.
func TestValidateSessionCommand_NewlineInjection(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	err := g.ValidateSessionCommand("node\nrm -rf /")
	if err == nil {
		t.Error("command with newline injection should be blocked")
	}
}

// TestValidateSessionCommand_DelegatesToValidator verifies that
// ValidateSessionCommand delegates to the STDIO validator by checking that
// a command containing a pipe (dangerous metacharacter) is blocked.
func TestValidateSessionCommand_DelegatesToValidator(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")

	// A command with a pipe metacharacter should be blocked by the STDIO validator.
	err := g.ValidateSessionCommand("cat /etc/passwd | tee /tmp/pwned")
	if err == nil {
		t.Error("command with pipe metacharacter should be blocked")
	}
}

// TestValidateSessionCommand_MultipleTiers verifies ValidateSessionCommand
// works consistently across tiers (guardrails enabled → validator present).
func TestValidateSessionCommand_MultipleTiers(t *testing.T) {
	tiers := []tier.Tier{
		tier.TierCommunity,
		tier.TierDeveloper,
		tier.TierProfessional,
		tier.TierEnterprise,
	}
	for _, t2 := range tiers {
		t.Run(t2.String(), func(t *testing.T) {
			cfg := DefaultGuardrailConfig(t2)
			g := NewGuardrailMiddleware(cfg, "test-server")

			// Safe command should pass
			err := g.ValidateSessionCommand("node")
			if err != nil {
				t.Errorf("safe command blocked for %s tier: %v", t2.String(), err)
			}

			// Dangerous command should be blocked
			err = g.ValidateSessionCommand("node;rm -rf /")
			if err == nil {
				t.Errorf("dangerous command allowed for %s tier", t2.String())
			}
		})
	}
}

// --------------------------------------------------------------------------
// SetGuardrails
// --------------------------------------------------------------------------

// TestSetGuardrails_Nil tests that SetGuardrails(nil) stores nil without panicking.
func TestSetGuardrails_Nil(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create RBAC manager: %v", err)
	}
	sm := NewConnectionSessionManager(rbacMgr)

	sm.SetGuardrails(nil)
	if sm.guardrails != nil {
		t.Error("expected guardrails to be nil after SetGuardrails(nil)")
	}
}

// TestSetGuardrails_NonNil tests that SetGuardrails stores the middleware reference.
func TestSetGuardrails_NonNil(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create RBAC manager: %v", err)
	}
	sm := NewConnectionSessionManager(rbacMgr)

	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")
	sm.SetGuardrails(g)

	if sm.guardrails != g {
		t.Error("expected guardrails pointer to match the one passed to SetGuardrails")
	}
}

// TestSetGuardrails_IntegrationWithCloseSession verifies that setting
// guardrails enables session-tracking cleanup in CloseSession.
func TestSetGuardrails_IntegrationWithCloseSession(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create RBAC manager: %v", err)
	}
	sm := NewConnectionSessionManager(rbacMgr)

	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg, "test-server")
	sm.SetGuardrails(g)

	// Create a session via the guardrail middleware so it is tracked
	err = g.OnSessionCreate("conn-1", "agent-1", "10.0.0.1:1234")
	if err != nil {
		t.Fatalf("failed to create guardrail session: %v", err)
	}
	stats := g.Stats()
	if stats.ActiveSessions != 1 {
		t.Fatalf("expected 1 active session before close, got %d", stats.ActiveSessions)
	}

	// Manually track the session in the session manager (bypass CreateSession
	// which requires an agent to exist in RBAC).
	sm.mu.Lock()
	sm.conns["conn-1"] = &MCPSession{
		ConnectionID: "conn-1",
		RBACSession:  &rbac.AgentSession{ID: "sess-1", ExpiresAt: time.Now().Add(24 * time.Hour)},
		Agent:        nil,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	sm.mu.Unlock()

	// Close the session — this should notify guardrails via OnSessionDestroy
	err = sm.CloseSession("conn-1")
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	stats = g.Stats()
	if stats.ActiveSessions != 0 {
		t.Errorf("expected 0 active sessions after CloseSession (guardrails notified), got %d", stats.ActiveSessions)
	}
}

// TestSetGuardrails_Overwrite tests that calling SetGuardrails replaces the
// previous value.
func TestSetGuardrails_Overwrite(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create RBAC manager: %v", err)
	}
	sm := NewConnectionSessionManager(rbacMgr)

	cfg1 := DefaultGuardrailConfig(tier.TierCommunity)
	g1 := NewGuardrailMiddleware(cfg1, "server-1")

	cfg2 := DefaultGuardrailConfig(tier.TierDeveloper)
	g2 := NewGuardrailMiddleware(cfg2, "server-2")

	sm.SetGuardrails(g1)
	if sm.guardrails != g1 {
		t.Error("first SetGuardrails did not take effect")
	}

	sm.SetGuardrails(g2)
	if sm.guardrails != g2 {
		t.Error("second SetGuardrails should replace the first")
	}
}

// --------------------------------------------------------------------------
// RegisterBuiltInTools — blocked-tool handlers
// --------------------------------------------------------------------------

// TestRegisterBuiltInTools_BlockedToolHandlers verifies that the always-blocked
// tools (shell_command, code_execute, file_write, file_delete, database_query)
// return security-policy errors when called.
func TestRegisterBuiltInTools_BlockedToolHandlers(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierCommunity)

	blockedTools := []struct {
		name           string
		expectedSubstr string
		params         map[string]interface{}
	}{
		{
			name:           "shell_command",
			expectedSubstr: "shell commands are blocked by security policy",
			params:         map[string]interface{}{"command": "ls"},
		},
		{
			name:           "code_execute",
			expectedSubstr: "code execution is blocked by security policy",
			params:         map[string]interface{}{"code": "print('hi')", "language": "python"},
		},
		{
			name:           "file_write",
			expectedSubstr: "file writes are blocked by security policy",
			params:         map[string]interface{}{"path": "/tmp/x", "content": "data"},
		},
		{
			name:           "file_delete",
			expectedSubstr: "file deletion is blocked by security policy",
			params:         map[string]interface{}{"path": "/tmp/x"},
		},
		{
			name:           "database_query",
			expectedSubstr: "database access is blocked by security policy",
			params:         map[string]interface{}{"query": "SELECT 1"},
		},
	}

	for _, bt := range blockedTools {
		t.Run(bt.name, func(t *testing.T) {
			fn, ok := registry.GetHandler(bt.name)
			if !ok {
				t.Fatalf("handler for %q not found in registry", bt.name)
			}
			result, err := fn(context.Background(), bt.params)
			if err == nil {
				t.Errorf("blocked tool %q should return an error", bt.name)
			}
			if result != nil {
				t.Errorf("blocked tool %q should return nil result, got %v", bt.name, result)
			}
			if err != nil && bt.expectedSubstr != "" {
				if got := err.Error(); got != bt.expectedSubstr {
					t.Errorf("blocked tool %q error = %q, want %q", bt.name, got, bt.expectedSubstr)
				}
			}
		})
	}
}

// TestRegisterBuiltInTools_AllToolHandlersRegistered confirms every tool
// name registered has a corresponding handler.
func TestRegisterBuiltInTools_AllToolHandlersRegistered(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierCommunity)

	allTools := []string{
		// Community tier safe tools
		"process_list", "memory_stats", "network_connections", "system_info",
		"git_status", "git_log", "git_diff",
		"file_read",
		"web_search", "http_request", "json_fetch",
		"code_search",
		// Always-blocked tools
		"shell_command", "code_execute", "file_write", "file_delete", "database_query",
	}

	for _, name := range allTools {
		t.Run(name, func(t *testing.T) {
			_, toolOK := registry.GetTool(name)
			if !toolOK {
				t.Errorf("tool definition %q not registered", name)
			}
			_, handlerOK := registry.GetHandler(name)
			if !handlerOK {
				t.Errorf("tool handler %q not registered", name)
			}
		})
	}
}

// TestRegisterBuiltInTools_SafeToolHandlersExec checks that safe (community)
// tool handlers are callable — they should not return the "blocked by
// security policy" errors.
func TestRegisterBuiltInTools_SafeToolHandlersExec(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierCommunity)

	// We only verify that the handler is callable and returns an error
	// from the executor (not a "blocked" policy error). Tool executors may
	// fail in a test environment (no repo, no network, etc.) which is fine —
	// we just verify it's NOT the "security policy" error.
	safeTools := []struct {
		name   string
		params map[string]interface{}
	}{
		{"process_list", map[string]interface{}{}},
		{"memory_stats", map[string]interface{}{}},
		{"system_info", map[string]interface{}{}},
		{"network_connections", map[string]interface{}{}},
	}

	for _, st := range safeTools {
		t.Run(st.name, func(t *testing.T) {
			fn, ok := registry.GetHandler(st.name)
			if !ok {
				t.Fatalf("handler for %q not found", st.name)
			}
			_, err := fn(context.Background(), st.params)
			// In a test environment the executor may fail, but it should
			// NEVER say "blocked by security policy" — that's for the
			// always-blocked tools only.
			if err != nil {
				if msg := err.Error(); msg == "shell commands are blocked by security policy" ||
					msg == "code execution is blocked by security policy" ||
					msg == "file writes are blocked by security policy" ||
					msg == "file deletion is blocked by security policy" ||
					msg == "database access is blocked by security policy" {
					t.Errorf("safe tool %q returned security-policy block error: %v", st.name, err)
				}
			}
		})
	}
}

// TestRegisterBuiltInTools_EnterpriseStillBlocked verifies that blocked tools
// remain blocked even at the Enterprise tier.
func TestRegisterBuiltInTools_EnterpriseStillBlocked(t *testing.T) {
	registry := mcp.NewToolRegistry()
	handler := &mcp.RequestHandler{Registry: registry}
	RegisterBuiltInTools(handler, tier.TierEnterprise)

	_, ok := registry.GetHandler("shell_command")
	if !ok {
		t.Fatal("shell_command handler should be registered for Enterprise")
	}

	fn, _ := registry.GetHandler("shell_command")
	_, err := fn(context.Background(), map[string]interface{}{"command": "ls"})
	if err == nil {
		t.Error("shell_command should be blocked even at Enterprise tier")
	}
}
