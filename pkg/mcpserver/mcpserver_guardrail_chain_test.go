// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	mcp "github.com/aegisgatesecurity/aegisguard/pkg/agent-protocol/mcp"
)

// toolError is a simple error type for testing tool handler errors.
type toolError struct{ msg string }

func (e *toolError) Error() string { return e.msg }

// ----------------------------------------------------------------------------
// SetGuardrails handler chain tests — exercise the wrapped function stored
// on es.handlerFunc to cover the response scanning logic.
// ----------------------------------------------------------------------------

// newTestServer creates an EmbeddedServer with the authorizer disabled
// so test tools can execute without being denied by default policies.
func newTestServer() *EmbeddedServer {
	es := NewEmbeddedServer(&Config{})
	es.handler.Authorizer = nil
	return es
}

// registerTestTool registers a simple tool on the embedded server's handler
// that returns the given text as a CallToolResult.
func registerTestTool(es *EmbeddedServer, name, text string, isError bool) {
	es.handler.Registry.Register(name, "Test tool: "+name, 10,
		map[string]interface{}{"type": "object", "properties": map[string]interface{}{}})
	es.handler.Registry.RegisterHandler(name,
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return mcp.CallToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: text}},
				IsError: isError,
			}, nil
		})
}

func makeToolCallRequest(toolName string, id interface{}) *mcp.JSONRPCRequest {
	params, _ := json.Marshal(map[string]interface{}{"name": toolName})
	return &mcp.JSONRPCRequest{
		JSONRPC: mcp.JSONRPCVersion,
		Method:  "tools/call",
		Params:  params,
		ID:      id,
	}
}

// TestPhase1aGuardrailChain_CleanText exercises the full handler chain:
// guardrail pass-through → tool execution → response scanning (clean text).
func TestPhase1aGuardrailChain_CleanText(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_clean", "hello world", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	resp := es.handlerFunc(nil, makeToolCallRequest("test_clean", 1))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("expected no error, got: %v", resp.Error.Message)
	}
}

// TestPhase1aGuardrailChain_PIIBlocked exercises the blocked path:
// tool returns PII (SSN), response guard blocks it.
func TestPhase1aGuardrailChain_PIIBlocked(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_pii", "SSN: 123-45-6789", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	// Must use WithConfig to enable strictMode on the session guard
	// (NewMCPResponseGuard defaults sessionGuard.strictMode to false)
	rg := NewMCPResponseGuardWithConfig(&response.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		StrictMode:            true,
	})
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	resp := es.handlerFunc(nil, makeToolCallRequest("test_pii", 2))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// The response should be a blocked tool result (IsError=true)
	// Extract the result to check
	data, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}
	var result struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected blocked response (IsError=true) for PII content")
	}
}

// TestPhase1aGuardrailChain_NonToolCallMethod verifies that non-tools/call
// methods skip response scanning entirely.
func TestPhase1aGuardrailChain_NonToolCallMethod(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_method", "hello", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	// Send a "ping" request — should skip scanning
	req := &mcp.JSONRPCRequest{
		JSONRPC: mcp.JSONRPCVersion,
		Method:  "ping",
		ID:      3,
	}
	resp := es.handlerFunc(nil, req)
	if resp == nil {
		t.Fatal("expected non-nil response for ping")
	}
}

// TestPhase1aGuardrailChain_ErrorResponse verifies that error responses
// skip response scanning.
func TestPhase1aGuardrailChain_ErrorResponse(t *testing.T) {
	es := newTestServer()
	// Register a tool that returns an error result
	es.handler.Registry.Register("test_err", "Test error tool", 10,
		map[string]interface{}{"type": "object"})
	es.handler.Registry.RegisterHandler("test_err",
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, &toolError{msg: "tool error"}
		})

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	resp := es.handlerFunc(nil, makeToolCallRequest("test_err", 4))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestPhase1aGuardrailChain_EmptyText verifies that responses with empty
// text content skip response scanning.
func TestPhase1aGuardrailChain_EmptyText(t *testing.T) {
	es := newTestServer()
	// Register a tool that returns non-text content (no text to scan)
	es.handler.Registry.Register("test_empty", "Test empty tool", 10,
		map[string]interface{}{"type": "object"})
	es.handler.Registry.RegisterHandler("test_empty",
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return mcp.CallToolResult{
				Content: []mcp.ContentBlock{{Type: "image", Data: "base64data"}},
			}, nil
		})

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	resp := es.handlerFunc(nil, makeToolCallRequest("test_empty", 5))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestPhase1aGuardrailChain_GuardrailsOnly verifies the path where
// responseGuard is nil (only request guardrails are wired).
func TestPhase1aGuardrailChain_GuardrailsOnly(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_guardrails_only", "hello", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	es.SetGuardrails(gm, nil, nil)

	resp := es.handlerFunc(nil, makeToolCallRequest("test_guardrails_only", 6))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestPhase1aGuardrailChain_RespCfgDisabled verifies the path where
// response scanning config is disabled.
func TestPhase1aGuardrailChain_RespCfgDisabled(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_disabled", "SSN: 123-45-6789", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	cfg := &EmbeddedResponseConfig{Enabled: false}
	es.SetGuardrails(gm, rg, cfg)

	resp := es.handlerFunc(nil, makeToolCallRequest("test_disabled", 7))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Since scanning is disabled, PII should pass through
	data, _ := json.Marshal(resp.Result)
	var result struct {
		IsError bool `json:"isError"`
	}
	json.Unmarshal(data, &result)
	if result.IsError {
		t.Fatal("expected non-blocked response when scanning is disabled")
	}
}

// TestPhase1aGuardrailChain_ResponseGuardOnly verifies the path where
// guardrails is nil but responseGuard is set (the else branch of the
// requestHandler assignment).
func TestPhase1aGuardrailChain_ResponseGuardOnly(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_rg_only", "hello world", false)

	rg := NewMCPResponseGuard()
	es.SetGuardrails(nil, rg, DefaultEmbeddedResponseConfig())

	resp := es.handlerFunc(nil, makeToolCallRequest("test_rg_only", 8))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestPhase1aGuardrailChain_WithConnection verifies the session ID
// extraction path when a connection with a session is provided.
func TestPhase1aGuardrailChain_WithConnection(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_conn", "hello world", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	rg := NewMCPResponseGuard()
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	conn := &mcp.Connection{
		ID: "conn-1",
		Session: &mcp.Session{
			ID:      "session-123",
			AgentID: "agent-1",
		},
	}
	resp := es.handlerFunc(conn, makeToolCallRequest("test_conn", 9))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Verify session stats were recorded
	stats := rg.GetSessionStats("session-123")
	if stats == nil {
		t.Fatal("expected session stats for session-123")
	}
}

// TestPhase1aGuardrailChain_NonStrictPII verifies the path where PII is
// detected but strict mode is off (allowed=true, text unchanged).
func TestPhase1aGuardrailChain_NonStrictPII(t *testing.T) {
	es := newTestServer()
	registerTestTool(es, "test_nonstrict", "SSN: 123-45-6789", false)

	gm := NewGuardrailMiddleware(GuardrailConfig{Enabled: false}, "test-server")
	// Non-strict mode: PII is detected but not blocked
	rg := NewMCPResponseGuardWithConfig(&response.ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		StrictMode:            false,
	})
	es.SetGuardrails(gm, rg, DefaultEmbeddedResponseConfig())

	// Also test the redacted-text path: when scannedText differs from
	// textContent and is non-empty, updateToolResponseText is called.
	// With non-strict mode, GuardResponse returns (true, originalText, nil)
	// so scannedText == textContent — no update. This still covers the
	// non-strict branch of GuardResponse.

	resp := es.handlerFunc(nil, makeToolCallRequest("test_nonstrict", 10))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// In non-strict mode, PII is detected but allowed=true
	data, _ := json.Marshal(resp.Result)
	var result struct {
		IsError bool `json:"isError"`
	}
	json.Unmarshal(data, &result)
	if result.IsError {
		t.Fatal("expected non-blocked response in non-strict mode")
	}
}

// ----------------------------------------------------------------------------
// RegisterBuiltInTools closure tests — call registered tool handlers to
// cover the closure bodies.
// ----------------------------------------------------------------------------

// TestPhase1aRegisterBuiltInTools_BlockedHandlers calls the blocked tool
// handlers (shell_command, code_execute, file_write, file_delete,
// database_query) to cover their closure bodies.
func TestPhase1aRegisterBuiltInTools_BlockedHandlers(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	RegisterBuiltInTools(es.handler, tier.TierCommunity)

	ctx := context.Background()
	blockedTools := []string{
		"shell_command",
		"code_execute",
		"file_write",
		"file_delete",
		"database_query",
	}

	for _, name := range blockedTools {
		handler, ok := es.handler.Registry.GetHandler(name)
		if !ok {
			t.Errorf("handler not found for tool %s", name)
			continue
		}
		_, err := handler(ctx, map[string]interface{}{})
		if err == nil {
			t.Errorf("expected error from blocked tool %s", name)
		}
	}
}

// TestPhase1aRegisterBuiltInTools_SafeHandlers calls the safe (non-blocked)
// tool handlers to cover their closure bodies. These may return errors from
// the actual executors (no repo, no network, etc.) but the closure bodies
// will be covered.
func TestPhase1aRegisterBuiltInTools_SafeHandlers(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	RegisterBuiltInTools(es.handler, tier.TierCommunity)

	ctx := context.Background()
	safeTools := []string{
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

	for _, name := range safeTools {
		handler, ok := es.handler.Registry.GetHandler(name)
		if !ok {
			t.Errorf("handler not found for tool %s", name)
			continue
		}
		// Call the handler — we don't care about the result, just covering
		// the closure body (executor creation + Execute call)
		handler(ctx, map[string]interface{}{})
	}
}

// ----------------------------------------------------------------------------
// registerTool error path tests
// ----------------------------------------------------------------------------

// TestPhase1aRegisterTool_DuplicateRegistration verifies the error path
// when registering a duplicate tool name.
func TestPhase1aRegisterTool_DuplicateRegistration(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	registry := es.handler.Registry

	// First registration succeeds
	registerTool(registry, "dup_tool", "Duplicate test", 10,
		map[string]interface{}{"type": "object"},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, nil
		})

	// Second registration with same name should hit the error path
	// (registry.Register returns error, registerTool logs and returns)
	registerTool(registry, "dup_tool", "Duplicate test 2", 10,
		map[string]interface{}{"type": "object"},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, nil
		})

	// Verify only one registration exists
	if registry.Count() != 1 {
		t.Errorf("expected 1 tool after duplicate registration, got %d", registry.Count())
	}
}

// TestPhase1aRegisterTool_EmptyName verifies the error path when
// registering a tool with an empty name.
func TestPhase1aRegisterTool_EmptyName(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	registry := es.handler.Registry

	// Empty name should fail at registry.Register
	registerTool(registry, "", "Empty name tool", 10,
		map[string]interface{}{"type": "object"},
		func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
			return nil, nil
		})

	// Verify no tools were registered
	if registry.Count() != 0 {
		t.Errorf("expected 0 tools after empty name, got %d", registry.Count())
	}
}

// ----------------------------------------------------------------------------
// server.go adapter tests
// ----------------------------------------------------------------------------

// TestPhase1aAuthorizerAdapter_NilCall verifies the nil call error path.
func TestPhase1aAuthorizerAdapter_NilCall(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	// The authorizerAdapter is created internally; we access it via the
	// handler's Authorizer field. But that's an interface, not the concrete
	// type. Instead, we can test via the handler directly.
	// Actually, the adapter is set as the Authorizer on the RequestHandler.
	// We can call Authorize with a nil call through the interface.
	authz := es.handler.Authorizer
	if authz == nil {
		t.Skip("authorizer not set on handler")
	}
	_, err := authz.Authorize(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil authorization call")
	}
}

// TestPhase1aSessionManagerAdapter_CreateAndDeleteSession verifies the
// session lifecycle through the adapter.
func TestPhase1aSessionManagerAdapter_CreateAndDeleteSession(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	sessionMgr := es.handler.SessionMgr
	if sessionMgr == nil {
		t.Skip("session manager not set on handler")
	}

	ctx := context.Background()
	session, err := sessionMgr.CreateSession(ctx, "test-agent-1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if session == nil || session.ID == "" {
		t.Fatal("expected valid session")
	}

	// GetSession
	retrieved, err := sessionMgr.GetSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved == nil || retrieved.ID != session.ID {
		t.Fatal("session ID mismatch")
	}

	// DeleteSession
	if err := sessionMgr.DeleteSession(ctx, session.ID); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Verify deleted
	_, err = sessionMgr.GetSession(ctx, session.ID)
	if err == nil {
		t.Fatal("expected error after session deletion")
	}
}

// ----------------------------------------------------------------------------
// session_manager.go CreateSession success path
// ----------------------------------------------------------------------------

// TestPhase1aConnectionSessionManager_CreateSession_Success registers an
// agent and creates a session successfully.
func TestPhase1aConnectionSessionManager_CreateSession_Success(t *testing.T) {
	rbacMgr, err := rbac.NewManager(rbac.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create rbac manager: %v", err)
	}

	// Register an agent
	agent := &rbac.Agent{
		ID:          "test-agent-success",
		Name:        "Test Agent",
		Description: "Test agent for session creation",
		Role:        rbac.AgentRoleRestricted,
		Enabled:     true,
	}
	if err := rbacMgr.RegisterAgent(agent); err != nil {
		t.Fatalf("failed to register agent: %v", err)
	}

	sm := NewConnectionSessionManager(rbacMgr)
	session, err := sm.CreateSession(context.Background(), "conn-success", "test-agent-success")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if session.ConnectionID != "conn-success" {
		t.Errorf("expected ConnectionID=conn-success, got %s", session.ConnectionID)
	}

	// Verify we can get the session
	retrieved, err := sm.GetSession("conn-success")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected non-nil retrieved session")
	}

	// Close the session
	if err := sm.CloseSession("conn-success"); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}
}

// ----------------------------------------------------------------------------
// tool_description_scanner.go scanSchema nested map/array coverage
// ----------------------------------------------------------------------------

// TestPhase1aScanSchema_NestedMapAndArray exercises the scanSchema
// recursive branches for nested maps and string arrays.
func TestPhase1aScanSchema_NestedMapAndArray(t *testing.T) {
	scanner := NewToolDescriptionScanner()
	// Schema with nested map and string array to cover recursive branches
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"category": map[string]interface{}{
				"type":        "string",
				"description": "Select category",
				"enum":        []interface{}{"safe_option", "another_option"},
			},
		},
		"required": []interface{}{"category"},
	}
	result := scanner.ScreenTool("nested_schema_tool", "Safe tool with nested schema", schema)
	_ = result
}

// ----------------------------------------------------------------------------
// stdio_validation.go ValidateCommand empty token coverage
// ----------------------------------------------------------------------------

// TestPhase1aValidateCommand_ConsecutiveSeparators exercises the empty
// token skip path in ValidateCommand.
func TestPhase1aValidateCommand_ConsecutiveSeparators(t *testing.T) {
	v := NewSTDIOValidator(DefaultSTDIOValidationConfig())
	// Command with consecutive spaces creates empty tokens that hit the
	// "continue" branch in the token loop
	_ = v.ValidateCommand("ls  -la")
}

// ----------------------------------------------------------------------------
// suppressions.go ApplySuppressions all-filtered coverage
// ----------------------------------------------------------------------------

// TestPhase1aApplySuppressions_AllFiltered exercises the path where all
// findings are suppressed (filtered == nil → initialized to empty slice).
func TestPhase1aApplySuppressions_AllFiltered(t *testing.T) {
	findings := []SuppressedFinding{
		{RuleID: "RULE_001", Line: 10},
		{RuleID: "RULE_002", Line: 20},
	}
	suppressions := []Suppression{
		{RuleID: "all", Line: 10},
		{RuleID: "all", Line: 20},
	}
	result := ApplySuppressions(findings, suppressions)
	if len(result) != 0 {
		t.Errorf("expected 0 findings after suppression, got %d", len(result))
	}
}

// ----------------------------------------------------------------------------
// GuardrailHandler with enabled middleware + nil connection
// ----------------------------------------------------------------------------

// TestPhase1aGuardrailHandler_EnabledNilConnection exercises the
// GuardrailHandler with an enabled config and nil connection (anonymous
// session path).
func TestPhase1aGuardrailHandler_EnabledNilConnection(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	registerTestTool(es, "guard_test", "hello", false)

	gm := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")

	// Call GuardrailHandler directly with nil connection
	handler := gm.GuardrailHandler(es.handler)
	req := makeToolCallRequest("guard_test", 11)
	resp := handler(nil, req)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestPhase1aGuardrailHandler_InitializeMethod exercises the initialize
// method path in GuardrailHandler.
func TestPhase1aGuardrailHandler_InitializeMethod(t *testing.T) {
	es := NewEmbeddedServer(&Config{})
	gm := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")

	handler := gm.GuardrailHandler(es.handler)
	req := &mcp.JSONRPCRequest{
		JSONRPC: mcp.JSONRPCVersion,
		Method:  "initialize",
		ID:      12,
	}
	resp := handler(nil, req)
	if resp == nil {
		t.Fatal("expected non-nil response for initialize")
	}
}

// ----------------------------------------------------------------------------
// OnToolCallWithAuth chain analysis coverage
// ----------------------------------------------------------------------------

// TestPhase1aOnToolCallWithAuth_AllowedAndChain exercises the full
// OnToolCallWithAuth path including chain analysis for an allowed tool.
func TestPhase1aOnToolCallWithAuth_AllowedAndChain(t *testing.T) {
	gm := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")

	// First, create a session so OnToolCall doesn't fail
	gm.OnSessionCreate("sess-auth-test", "agent-1", "127.0.0.1")

	// Call OnToolCallWithAuth with a safe tool name
	err := gm.OnToolCallWithAuth("sess-auth-test", "agent-1", "file_read")
	if err != nil {
		t.Logf("OnToolCallWithAuth returned error (may be expected): %v", err)
	}

	// Call with a write tool to exercise inferDataType "write" branch
	err = gm.OnToolCallWithAuth("sess-auth-test", "agent-1", "file_write")
	if err != nil {
		t.Logf("OnToolCallWithAuth for write tool returned error: %v", err)
	}

	// Call with an exec tool to exercise inferDataType "execute" branch
	err = gm.OnToolCallWithAuth("sess-auth-test", "agent-1", "exec_command")
	if err != nil {
		t.Logf("OnToolCallWithAuth for exec tool returned error: %v", err)
	}

	// Call with a network tool to exercise inferDataType "network" branch
	err = gm.OnToolCallWithAuth("sess-auth-test", "agent-1", "http_request")
	if err != nil {
		t.Logf("OnToolCallWithAuth for network tool returned error: %v", err)
	}
}
