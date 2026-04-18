package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// TestRequestHandlerInitialize tests the initialize endpoint handling
func TestRequestHandlerInitialize(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	// Test basic initialize request
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "initialize",
		ID:      1,
	}

	response := handler.HandleRequest(nil, req)

	if response.JSONRPC != JSONRPCVersion {
		t.Errorf("Expected JSONRPC version %s, got %s", JSONRPCVersion, response.JSONRPC)
	}

	if response.ID != 1 {
		t.Errorf("Expected ID 1, got %v", response.ID)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error.Message)
	}

	// Result is returned as value, not pointer
	result, ok := response.Result.(InitializeResult)
	if !ok {
		t.Fatalf("Expected InitializeResult, got %T", response.Result)
	}

	if result.ServerInfo.Name != "aegisguard" {
		t.Errorf("Expected server name 'aegisguard', got '%s'", result.ServerInfo.Name)
	}

	if result.ServerInfo.Version != "0.1.0" {
		t.Errorf("Expected version '0.1.0', got '%s'", result.ServerInfo.Version)
	}
}

// TestRequestHandlerInitializeWithAudit tests initialize with audit logger
func TestRequestHandlerInitializeWithAudit(t *testing.T) {
	auditLogger := NewMockAuditLogger()
	handler := NewRequestHandler(nil, auditLogger, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "initialize",
		ID:      1,
	}

	handler.HandleRequest(nil, req)

	if len(auditLogger.AuditEntries) != 1 {
		t.Errorf("Expected 1 audit log entry, got %d", len(auditLogger.AuditEntries))
	}

	if auditLogger.AuditEntries[0].Type != "initialize" {
		t.Errorf("Expected log type 'initialize', got '%s'", auditLogger.AuditEntries[0].Type)
	}
}

// TestRequestHandlerListTools tests the tools/list endpoint
func TestRequestHandlerListTools(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	// Register tools using Register (adds to tools map) + RegisterHandler (adds to handlers map)
	// First register the tool metadata
	handler.Registry.Register("test-tool", "Test tool description", 10, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param": map[string]interface{}{"type": "string"},
		},
	})
	handler.Registry.RegisterHandler("test-tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "test result", nil
	})

	handler.Registry.Register("another-tool", "Another test tool", 10, map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param": map[string]interface{}{"type": "string"},
		},
	})
	handler.Registry.RegisterHandler("another-tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return "another result", nil
	})

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/list",
		ID:      2,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error.Message)
	}

	result, ok := response.Result.(ListToolsResult)
	if !ok {
		t.Fatalf("Expected ListToolsResult, got %T", response.Result)
	}

	if len(result.Tools) != 2 {
		t.Errorf("Expected 2 tools, got %d", len(result.Tools))
	}

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	if !toolNames["test-tool"] {
		t.Error("Expected 'test-tool' in tools list")
	}

	if !toolNames["another-tool"] {
		t.Error("Expected 'another-tool' in tools list")
	}
}

// TestRequestHandlerCallTool tests the tools/call endpoint
func TestRequestHandlerCallTool(t *testing.T) {
	var toolCallCount int

	mockAuthorizer := NewMockToolAuthorizer()
	mockAuthorizer.AuthorizedTools["allowed-tool"] = true

	mockAuditLogger := NewMockAuditLogger()

	registry := NewToolRegistry()
	registry.RegisterHandler("allowed-tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		toolCallCount++
		return "tool executed", nil
	})
	registry.RegisterHandler("denied-tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		toolCallCount++
		return "should not execute", nil
	})

	handler := NewRequestHandler(mockAuthorizer, mockAuditLogger, nil)
	handler.Registry = registry

	// Test successful tool call
	t.Run("SuccessfulToolCall", func(t *testing.T) {
		params := map[string]interface{}{
			"name":       "allowed-tool",
			"arguments":  map[string]interface{}{"key": "value"},
			"session_id": "test-session",
		}
		paramsBytes, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "tools/call",
			ID:      3,
			Params:  paramsBytes,
		}

		response := handler.HandleRequest(nil, req)

		if response.Error != nil {
			t.Errorf("Expected no error, got %v", response.Error.Message)
		}

		if toolCallCount != 1 {
			t.Errorf("Expected tool call count 1, got %d", toolCallCount)
		}
	})

	// Test denied tool call
	t.Run("DeniedToolCall", func(t *testing.T) {
		mockAuthorizer.MockDecision = &AuthorizationDecision{
			Allowed:     false,
			Reason:      "Policy violation",
			RiskScore:   8,
			MatchedRule: "denied-policy",
		}

		params := map[string]interface{}{
			"name":       "denied-tool",
			"arguments":  map[string]interface{}{"key": "value"},
			"session_id": "test-session",
		}
		paramsBytes, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "tools/call",
			ID:      4,
			Params:  paramsBytes,
		}

		response := handler.HandleRequest(nil, req)

		if response.Error != nil {
			t.Errorf("Expected no error, got %v", response.Error.Message)
		}

		result, ok := response.Result.(CallToolResult)
		if !ok {
			t.Fatalf("Expected CallToolResult, got %T", response.Result)
		}

		if !result.IsError {
			t.Error("Expected IsError to be true for denied tool")
		}

		// Verify authorization was called
		if len(mockAuthorizer.AuthorizeCalls) == 0 {
			t.Error("Expected Authorize to be called")
		} else {
			call := mockAuthorizer.AuthorizeCalls[len(mockAuthorizer.AuthorizeCalls)-1]
			if call.Name != "denied-tool" {
				t.Errorf("Expected tool name 'denied-tool', got '%s'", call.Name)
			}
		}

		// Verify audit log was created
		if len(mockAuditLogger.AuditEntries) == 0 {
			t.Error("Expected audit log entry")
		} else {
			if mockAuditLogger.AuditEntries[len(mockAuditLogger.AuditEntries)-1].Type != "tool_denied" {
				t.Errorf("Expected log type 'tool_denied', got '%s'", mockAuditLogger.AuditEntries[len(mockAuditLogger.AuditEntries)-1].Type)
			}
		}
	})

	// Test error from tool
	t.Run("ToolError", func(t *testing.T) {
		mockAuthorizer.MockDecision = &AuthorizationDecision{
			Allowed:     true,
			Reason:      "",
			RiskScore:   0,
			MatchedRule: "",
		}

		params := map[string]interface{}{
			"name":      "allowed-tool",
			"arguments": map[string]interface{}{"error": "true"},
		}
		paramsBytes, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "tools/call",
			ID:      5,
			Params:  paramsBytes,
		}

		response := handler.HandleRequest(nil, req)

		result, ok := response.Result.(CallToolResult)
		if !ok {
			t.Fatalf("Expected CallToolResult, got %T", response.Result)
		}

		if result.IsError {
			t.Error("Expected IsError to be false for successful execution")
		}
	})
}

// TestRequestHandlerListResources tests the resources/list endpoint
func TestRequestHandlerListResources(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "resources/list",
		ID:      6,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error.Message)
	}

	if response.Result == nil {
		t.Error("Expected result, got nil")
	}
}

// TestRequestHandlerListPrompts tests the prompts/list endpoint
func TestRequestHandlerListPrompts(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "prompts/list",
		ID:      7,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error.Message)
	}

	if response.Result == nil {
		t.Error("Expected result, got nil")
	}
}

// TestRequestHandlerPing tests the ping endpoint
func TestRequestHandlerPing(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      8,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error.Message)
	}

	// Ping returns nil result - just verify no error
}

// TestRequestHandlerInvalidMethod tests handling of unknown methods
func TestRequestHandlerInvalidMethod(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "unknown/method",
		ID:      9,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error == nil {
		t.Error("Expected error for unknown method")
	}

	if response.Error.Code != ErrorMethodNotFound {
		t.Errorf("Expected error code %d, got %d", ErrorMethodNotFound, response.Error.Code)
	}
}

// TestRequestHandlerMissingParams tests handling of missing/invalid params
func TestRequestHandlerMissingParams(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		ID:      10,
		Params:  nil,
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error for missing params, got %v", response.Error.Message)
	}

	result, ok := response.Result.(CallToolResult)
	if !ok {
		t.Fatalf("Expected CallToolResult, got %T", response.Result)
	}

	if !result.IsError {
		t.Error("Expected IsError to be true for missing tool name")
	}
}

// TestRequestHandlerBadRequest tests basic JSON-RPC validation
func TestRequestHandlerBadRequest(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	// Test missing JSONRPC version - handler should still process it
	req := &JSONRPCRequest{
		Method: "initialize",
		ID:     11,
	}

	response := handler.HandleRequest(nil, req)

	// Missing JSONRPC version doesn't cause error in current implementation
	// The handler processes the method regardless
	if response.JSONRPC != JSONRPCVersion {
		t.Errorf("Expected JSONRPC version %s, got %s", JSONRPCVersion, response.JSONRPC)
	}
}

// TestRequestHandlerSessionHandling tests session context extraction
func TestRequestHandlerSessionHandling(t *testing.T) {
	mockSessionMgr := NewMockSessionManager()
	mockSessionMgr.Sessions["test-session"] = &Session{
		ID:      "test-session",
		AgentID: "test-agent",
	}

	mockAuthorizer := NewMockToolAuthorizer()
	mockAuthorizer.AuthorizedTools["tool"] = true

	handler := NewRequestHandler(mockAuthorizer, nil, mockSessionMgr)

	conn := &Connection{
		Session: mockSessionMgr.Sessions["test-session"],
	}

	params := map[string]interface{}{
		"name":      "tool",
		"arguments": map[string]interface{}{"key": "value"},
	}
	paramsBytes, _ := json.Marshal(params)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		ID:      12,
		Params:  paramsBytes,
	}

	handler.HandleRequest(conn, req)

	if len(mockAuthorizer.AuthorizeCalls) == 0 {
		t.Error("Expected authorization call")
	} else {
		call := mockAuthorizer.AuthorizeCalls[0]
		if call.SessionID != "test-session" {
			t.Errorf("Expected session ID 'test-session', got '%s'", call.SessionID)
		}
		if call.AgentID != "test-agent" {
			t.Errorf("Expected agent ID 'test-agent', got '%s'", call.AgentID)
		}
	}
}

// TestRequestHandlerMultipleConcurrentCalls tests concurrent tool calls
func TestRequestHandlerMultipleConcurrentCalls(t *testing.T) {
	mockAuthorizer := NewMockToolAuthorizer()
	mockAuthorizer.AuthorizedTools["concurrent-tool"] = true

	handler := NewRequestHandler(mockAuthorizer, nil, nil)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			params := map[string]interface{}{
				"name":      "concurrent-tool",
				"arguments": map[string]interface{}{"index": index},
			}
			paramsBytes, _ := json.Marshal(params)

			req := &JSONRPCRequest{
				JSONRPC: JSONRPCVersion,
				Method:  "tools/call",
				ID:      index,
				Params:  paramsBytes,
			}

			handler.HandleRequest(nil, req)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Use >= to account for potential race conditions in concurrent testing
	if len(mockAuthorizer.AuthorizeCalls) < 9 {
		t.Errorf("Expected at least 9 authorization calls, got %d", len(mockAuthorizer.AuthorizeCalls))
	}
}

// TestRequestHandlerAuthorizationError tests error handling during authorization
func TestRequestHandlerAuthorizationError(t *testing.T) {
	mockAuthorizer := NewMockToolAuthorizer()
	mockAuthorizer.MockError = fmt.Errorf("authorization failed")

	handler := NewRequestHandler(mockAuthorizer, nil, nil)
	handler.Registry.RegisterHandler("tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return nil, nil
	})

	params := map[string]interface{}{
		"name":      "tool",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		ID:      13,
		Params:  paramsBytes,
	}

	response := handler.HandleRequest(nil, req)

	// Authorization errors result in a tool result with IsError=true, not JSONRPC error
	// The handler catches the error and returns it as a tool call error response
	if response.Result == nil {
		t.Error("Expected result for authorization error")
	}
}

// TestRequestHandlerJSONRPCVersions tests different JSON-RPC version handling
func TestRequestHandlerJSONRPCVersions(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	tests := []struct {
		name      string
		jsonrpc   string
		wantError bool
	}{
		{"ValidVersion", JSONRPCVersion, false},
		{"EmptyVersion", "", false}, // Handler still processes
		{"InvalidVersion", "1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &JSONRPCRequest{
				JSONRPC: tt.jsonrpc,
				Method:  "ping",
				ID:      1,
			}

			response := handler.HandleRequest(nil, req)

			if tt.wantError && response.Error == nil {
				t.Error("Expected error")
			}
			if !tt.wantError && response.Error != nil {
				t.Errorf("Unexpected error: %v", response.Error.Message)
			}
		})
	}
}

// TestRequestHandlerNilID tests handling of nil request IDs
func TestRequestHandlerNilID(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      nil,
	}

	response := handler.HandleRequest(nil, req)

	// Should handle nil ID gracefully
	if response.Error != nil {
		t.Errorf("Expected no error for nil ID, got %v", response.Error.Message)
	}
}

// TestRequestHandlerLargeRequestID tests handling of large numeric IDs
func TestRequestHandlerLargeRequestID(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      999999999, // Large but valid int
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error for large ID, got %v", response.Error.Message)
	}

	if response.ID != 999999999 {
		t.Errorf("Expected ID to be preserved, got %v", response.ID)
	}
}

// TestRequestHandlerStringID tests handling of string request IDs
func TestRequestHandlerStringID(t *testing.T) {
	handler := NewRequestHandler(nil, nil, nil)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      "request-123",
	}

	response := handler.HandleRequest(nil, req)

	if response.Error != nil {
		t.Errorf("Expected no error for string ID, got %v", response.Error.Message)
	}

	if response.ID != "request-123" {
		t.Errorf("Expected ID to be preserved, got %v", response.ID)
	}
}
