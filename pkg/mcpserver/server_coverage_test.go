// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - Embedded MCP Server Adapter Coverage Tests
// =========================================================================
//
// Covers the unexported adapter types in server.go that bridge platform
// components to the MCP handler interfaces:
//   - authorizerAdapter       (Authorize — 0%)
//   - sessionManagerAdapter   (CreateSession, GetSession, DeleteSession — 0%)
//   - auditLoggerAdapter      (Log — 80%, gaps: tool_denied + empty Error,
//     tool_error + non-empty Error)
//
// Strategy: construct each adapter with a controlled upstream instance,
// call the adapter method, and verify the adapted output. Compile-time
// interface checks at the bottom ensure the adapters stay in sync with
// the MCP interfaces.
// =========================================================================

package mcpserver

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
	"github.com/aegisguardsecurity/aegisguard/pkg/audit"
	"github.com/aegisguardsecurity/aegisguard/pkg/authorization"
	"github.com/aegisguardsecurity/aegisguard/pkg/context-isolator"
)

// ============================================================================
// authorizerAdapter tests
// ============================================================================

func TestAuthorizerAdapter_Allow(t *testing.T) {
	authz := authorization.NewAuthorizer()
	// file_read has Allow:true in DefaultPolicies
	adapter := &authorizerAdapter{authz: authz}

	decision, err := adapter.Authorize(context.Background(), &mcp.AuthorizationCall{
		ID:         "call-1",
		Name:       "file_read",
		Parameters: map[string]interface{}{"path": "/etc/hosts"},
		SessionID:  "sess-1",
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Authorize returned unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected Allowed=true for file_read, got false (reason=%q)", decision.Reason)
	}
	if decision.Reason == "" {
		t.Error("expected non-empty Reason on allow")
	}
}

func TestAuthorizerAdapter_Deny(t *testing.T) {
	authz := authorization.NewAuthorizer()
	// shell_command has Allow:false in DefaultPolicies
	adapter := &authorizerAdapter{authz: authz}

	decision, err := adapter.Authorize(context.Background(), &mcp.AuthorizationCall{
		ID:         "call-2",
		Name:       "shell_command",
		Parameters: map[string]interface{}{"command": "rm -rf /"},
		SessionID:  "sess-1",
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Authorize returned unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected Allowed=false for shell_command, got true")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty denial Reason")
	}
}

func TestAuthorizerAdapter_DefaultDeny(t *testing.T) {
	authz := authorization.NewAuthorizer()
	adapter := &authorizerAdapter{authz: authz}

	// unknown_tool is not in DefaultPolicies → default deny
	decision, err := adapter.Authorize(context.Background(), &mcp.AuthorizationCall{
		ID:         "call-3",
		Name:       "unknown_tool",
		Parameters: map[string]interface{}{},
		SessionID:  "sess-1",
		AgentID:    "agent-1",
	})
	if err != nil {
		t.Fatalf("Authorize returned unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected default deny for unknown tool, got Allowed=true")
	}
}

func TestAuthorizerAdapter_FieldMapping(t *testing.T) {
	// Verify that all fields of AuthorizationCall are forwarded correctly
	// and that the adapter maps result.Allow → decision.Allowed,
	// result.Reason → decision.Reason, result.RiskScore → decision.RiskScore,
	// result.MatchedRule → decision.MatchedRule.
	authz := authorization.NewAuthorizer()
	authz.AddRule(authorization.AuthorizationRule{
		Name:      "test-rule",
		MatchTool: "mapped_tool",
		Decision: authorization.AuthorizationDecision{
			Allow:       true,
			Reason:      "matched test rule",
			RiskScore:   42,
			MatchedRule: "test-rule",
		},
	})

	adapter := &authorizerAdapter{authz: authz}
	decision, err := adapter.Authorize(context.Background(), &mcp.AuthorizationCall{
		ID:         "call-map",
		Name:       "mapped_tool",
		Parameters: map[string]interface{}{"key": "val"},
		SessionID:  "sess-map",
		AgentID:    "agent-map",
	})
	if err != nil {
		t.Fatalf("Authorize returned unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected Allowed=true for mapped_tool")
	}
	if decision.Reason != "matched test rule" {
		t.Errorf("expected Reason='matched test rule', got %q", decision.Reason)
	}
	if decision.RiskScore != 42 {
		t.Errorf("expected RiskScore=42, got %d", decision.RiskScore)
	}
	if decision.MatchedRule != "test-rule" {
		t.Errorf("expected MatchedRule='test-rule', got %q", decision.MatchedRule)
	}
}

// ============================================================================
// sessionManagerAdapter tests
// ============================================================================

func TestSessionManagerAdapter_CreateSession(t *testing.T) {
	mgr := contextisolator.NewSessionManager()
	adapter := &sessionManagerAdapter{mgr: mgr}

	session, err := adapter.CreateSession(context.Background(), "agent-42")
	if err != nil {
		t.Fatalf("CreateSession returned unexpected error: %v", err)
	}
	if session.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if session.AgentID != "agent-42" {
		t.Errorf("expected AgentID='agent-42', got %q", session.AgentID)
	}
}

func TestSessionManagerAdapter_GetSession(t *testing.T) {
	mgr := contextisolator.NewSessionManager()
	adapter := &sessionManagerAdapter{mgr: mgr}

	created, err := adapter.CreateSession(context.Background(), "agent-get")
	if err != nil {
		t.Fatalf("CreateSession returned unexpected error: %v", err)
	}

	got, err := adapter.GetSession(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetSession returned unexpected error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected session ID %q, got %q", created.ID, got.ID)
	}
	if got.AgentID != "agent-get" {
		t.Errorf("expected AgentID='agent-get', got %q", got.AgentID)
	}
}

func TestSessionManagerAdapter_GetSession_NotFound(t *testing.T) {
	mgr := contextisolator.NewSessionManager()
	adapter := &sessionManagerAdapter{mgr: mgr}

	_, err := adapter.GetSession(context.Background(), "nonexistent-session")
	if err == nil {
		t.Error("expected error for nonexistent session, got nil")
	}
}

func TestSessionManagerAdapter_DeleteSession(t *testing.T) {
	mgr := contextisolator.NewSessionManager()
	adapter := &sessionManagerAdapter{mgr: mgr}

	created, err := adapter.CreateSession(context.Background(), "agent-del")
	if err != nil {
		t.Fatalf("CreateSession returned unexpected error: %v", err)
	}

	err = adapter.DeleteSession(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("DeleteSession returned unexpected error: %v", err)
	}

	// Verify session is gone
	_, err = adapter.GetSession(context.Background(), created.ID)
	if err == nil {
		t.Error("expected error after deletion, got nil")
	}
}

func TestSessionManagerAdapter_DeleteSession_NotFound(t *testing.T) {
	mgr := contextisolator.NewSessionManager()
	adapter := &sessionManagerAdapter{mgr: mgr}

	err := adapter.DeleteSession(context.Background(), "nonexistent-session")
	if err == nil {
		t.Error("expected error deleting nonexistent session, got nil")
	}
}

// ============================================================================
// auditLoggerAdapter tests
// ============================================================================

func TestAuditLoggerAdapter_ToolAllowed(t *testing.T) {
	// Baseline: normal entry with no deny/error → Allowed=true
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_success",
		SessionID: "sess-audit-1",
		AgentID:   "agent-audit",
		ToolName:  "file_read",
		Error:     "",
		RiskScore: 10,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}
}

func TestAuditLoggerAdapter_ToolDenied_EmptyError(t *testing.T) {
	// Covers the branch: entry.Type == "tool_denied" && entry.Error == ""
	// → reason should become "Tool denied by policy", Allowed=false
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_denied",
		SessionID: "sess-denied",
		AgentID:   "agent-denied",
		ToolName:  "shell_command",
		Error:     "", // empty — triggers the "Tool denied by policy" branch
		RiskScore: 80,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}

	// Verify the audit entry was recorded with Allowed=false and reason set
	entries := logger.GetEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	last := entries[len(entries)-1]
	if last.Allowed {
		t.Error("expected Allowed=false for tool_denied entry, got true")
	}
	if last.Reason != "Tool denied by policy" {
		t.Errorf("expected Reason='Tool denied by policy', got %q", last.Reason)
	}
}

func TestAuditLoggerAdapter_ToolDenied_WithNonEmptyError(t *testing.T) {
	// Covers the branch: entry.Type == "tool_denied" && entry.Error != ""
	// → reason stays as entry.Error (non-empty takes precedence over
	//   "Tool denied by policy"), Allowed=false
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_denied",
		SessionID: "sess-denied2",
		AgentID:   "agent-denied2",
		ToolName:  "shell_command",
		Error:     "blocked by security policy rule #42",
		RiskScore: 90,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}

	entries := logger.GetEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	last := entries[len(entries)-1]
	if last.Allowed {
		t.Error("expected Allowed=false for tool_denied with error, got true")
	}
	// Since Error is non-empty, reason = entry.Error, NOT "Tool denied by policy"
	if last.Reason != "blocked by security policy rule #42" {
		t.Errorf("expected Reason='blocked by security policy rule #42', got %q", last.Reason)
	}
}

func TestAuditLoggerAdapter_ToolError_WithNonEmptyError(t *testing.T) {
	// Covers the branch: entry.Type == "tool_error" && entry.Error != ""
	// → Allowed=false, Reason = entry.Error
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_error",
		SessionID: "sess-err",
		AgentID:   "agent-err",
		ToolName:  "code_execute",
		Error:     "compilation failed: syntax error",
		RiskScore: 60,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}

	entries := logger.GetEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	last := entries[len(entries)-1]
	if last.Allowed {
		t.Error("expected Allowed=false for tool_error entry, got true")
	}
	if last.Reason != "compilation failed: syntax error" {
		t.Errorf("expected Reason='compilation failed: syntax error', got %q", last.Reason)
	}
}

func TestAuditLoggerAdapter_NormalEntry_AllowedTrue(t *testing.T) {
	// Covers: entry.Type is not "tool_denied" or "tool_error", Error is empty
	// → Allowed=true, Reason=""
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_call",
		SessionID: "sess-normal",
		AgentID:   "agent-normal",
		ToolName:  "web_search",
		Error:     "",
		RiskScore: 5,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}

	entries := logger.GetEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	last := entries[len(entries)-1]
	if !last.Allowed {
		t.Error("expected Allowed=true for normal tool_call entry, got false")
	}
}

func TestAuditLoggerAdapter_TypeAndSessionFieldMapping(t *testing.T) {
	// Verify the adapter maps entry fields to Action fields correctly:
	//   entry.Type → action.Type, entry.SessionID → action.SessionID,
	//   entry.AgentID → action.AgentID, entry.ToolName → action.ToolName,
	//   entry.RiskScore → action.RiskScore
	logger := audit.NewLogger()
	adapter := &auditLoggerAdapter{logger: logger}

	entry := &mcp.AuditEntry{
		Type:      "tool_call",
		SessionID: "sess-fields",
		AgentID:   "agent-fields",
		ToolName:  "git_status",
		Error:     "",
		RiskScore: 25,
	}

	err := adapter.Log(context.Background(), entry)
	if err != nil {
		t.Fatalf("Log returned unexpected error: %v", err)
	}

	entries := logger.GetEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}
	last := entries[len(entries)-1]
	if last.Type != "tool_call" {
		t.Errorf("expected Type='tool_call', got %q", last.Type)
	}
	if last.SessionID != "sess-fields" {
		t.Errorf("expected SessionID='sess-fields', got %q", last.SessionID)
	}
	if last.AgentID != "agent-fields" {
		t.Errorf("expected AgentID='agent-fields', got %q", last.AgentID)
	}
	if last.ToolName != "git_status" {
		t.Errorf("expected ToolName='git_status', got %q", last.ToolName)
	}
	if last.RiskScore != 25 {
		t.Errorf("expected RiskScore=25, got %d", last.RiskScore)
	}
}

// ============================================================================
// Compile-time interface satisfaction checks
// ============================================================================
// If a method signature drifts, these will fail to compile.

var _ mcp.ToolAuthorizer = (*authorizerAdapter)(nil)
var _ mcp.SessionManager = (*sessionManagerAdapter)(nil)
var _ mcp.AuditLoggerImpl = (*auditLoggerAdapter)(nil)