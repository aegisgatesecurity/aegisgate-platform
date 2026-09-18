// SPDX-License-Identifier: Apache-2.0
package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	mcp "github.com/aegisgatesecurity/aegisguard/pkg/agent-protocol/mcp"
)

func TestSetGuardrails_NilBoth(t *testing.T) {
	es := NewEmbeddedServer(DefaultConfig())
	// Should be a no-op, handlerFunc stays nil
	es.SetGuardrails(nil, nil, nil)
	if es.handlerFunc != nil {
		t.Error("handlerFunc should be nil when both guardrails and responseGuard are nil")
	}
}

func TestSetGuardrails_OnlyGuardrails(t *testing.T) {
	es := NewEmbeddedServer(DefaultConfig())
	guardrails := NewGuardrailMiddleware(DefaultGuardrailConfig(testTier()), "test-server")

	es.SetGuardrails(guardrails, nil, nil)
	if es.handlerFunc == nil {
		t.Fatal("handlerFunc should be set when guardrails is non-nil")
	}

	// The handlerFunc should be callable (it wraps the inner handler)
	if es.handlerFunc == nil {
		t.Fatal("handlerFunc is nil")
	}
}

func TestSetGuardrails_OnlyResponseGuard(t *testing.T) {
	es := NewEmbeddedServer(DefaultConfig())
	rg := NewMCPResponseGuard()

	es.SetGuardrails(nil, rg, DefaultEmbeddedResponseConfig())
	if es.handlerFunc == nil {
		t.Fatal("handlerFunc should be set when responseGuard is non-nil")
	}
}

func TestSetGuardrails_Both(t *testing.T) {
	es := NewEmbeddedServer(DefaultConfig())
	guardrails := NewGuardrailMiddleware(DefaultGuardrailConfig(testTier()), "test-server")
	rg := NewMCPResponseGuard()

	es.SetGuardrails(guardrails, rg, DefaultEmbeddedResponseConfig())
	if es.handlerFunc == nil {
		t.Fatal("handlerFunc should be set when both are non-nil")
	}
}

func TestSetGuardrails_StartPassesHandleFunc(t *testing.T) {
	// We can't actually Start() (it binds a port), but we can verify
	// that Start() would pass handlerFunc by checking the field is set.
	es := NewEmbeddedServer(&Config{
		Address:      ":19999", // unlikely to conflict
		ReadTimeout:  1,
		WriteTimeout: 1,
		IdleTimeout:  1,
	})
	guardrails := NewGuardrailMiddleware(DefaultGuardrailConfig(testTier()), "test-server")
	rg := NewMCPResponseGuard()

	es.SetGuardrails(guardrails, rg, nil)
	if es.handlerFunc == nil {
		t.Fatal("handlerFunc should be set")
	}
}

func TestExtractToolResponseText_Empty(t *testing.T) {
	resp := &mcp.JSONRPCResponse{}
	if text := extractToolResponseText(resp); text != "" {
		t.Errorf("expected empty string, got %q", text)
	}
}

func TestExtractToolResponseText_WithContent(t *testing.T) {
	resp := &mcp.JSONRPCResponse{
		Result: mcp.CallToolResult{
			Content: []mcp.ContentBlock{
				{Type: "text", Text: "file contents here"},
			},
		},
	}
	text := extractToolResponseText(resp)
	if text == "" {
		t.Error("expected non-empty text from tool response")
	}
	if text != "file contents here\n" {
		t.Errorf("expected 'file contents here\\n', got %q", text)
	}
}

func TestExtractToolResponseText_MultipleBlocks(t *testing.T) {
	resp := &mcp.JSONRPCResponse{
		Result: mcp.CallToolResult{
			Content: []mcp.ContentBlock{
				{Type: "text", Text: "first block"},
				{Type: "text", Text: "second block"},
			},
		},
	}
	text := extractToolResponseText(resp)
	if text == "" {
		t.Error("expected non-empty text")
	}
	// Should contain both blocks
	if text != "first block\nsecond block\n" {
		t.Errorf("expected both blocks, got %q", text)
	}
}

func TestExtractToolResponseText_NonTextContent(t *testing.T) {
	resp := &mcp.JSONRPCResponse{
		Result: mcp.CallToolResult{
			Content: []mcp.ContentBlock{
				{Type: "image", Data: "base64data"},
			},
		},
	}
	text := extractToolResponseText(resp)
	if text != "" {
		t.Errorf("expected empty string for non-text content, got %q", text)
	}
}

func TestUpdateToolResponseText(t *testing.T) {
	resp := &mcp.JSONRPCResponse{
		Result: mcp.CallToolResult{
			Content: []mcp.ContentBlock{
				{Type: "text", Text: "original content"},
			},
		},
	}

	updateToolResponseText(resp, "redacted content")

	data, _ := json.Marshal(resp.Result)
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
	}
	_ = json.Unmarshal(data, &result)

	if len(result.Content) == 0 || result.Content[0].Text != "redacted content" {
		t.Errorf("expected 'redacted content', got %v", result.Content)
	}
}

func TestMCPBlockedToolResult(t *testing.T) {
	resp := mcpBlockedToolResult("test-id", "sensitive data detected")
	if resp.ID != "test-id" {
		t.Errorf("expected ID 'test-id', got %v", resp.ID)
	}

	data, _ := json.Marshal(resp.Result)
	var result mcp.CallToolResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if !result.IsError {
		t.Error("expected IsError=true")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected at least one content block")
	}
	if result.Content[0].Type != "text" {
		t.Errorf("expected text type, got %s", result.Content[0].Type)
	}
}

func TestDefaultEmbeddedResponseConfig(t *testing.T) {
	cfg := DefaultEmbeddedResponseConfig()
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if !cfg.BlockOnPII {
		t.Error("expected BlockOnPII=true")
	}
	if !cfg.BlockOnSecrets {
		t.Error("expected BlockOnSecrets=true")
	}
	if cfg.BlockOnToxicity {
		t.Error("expected BlockOnToxicity=false (toxicity is subjective for tool output)")
	}
}

func TestGuardrailHandlerFunc_NonToolCallMethod(t *testing.T) {
	// For non-tool-call methods (like "initialize", "tools/list"),
	// response scanning should be skipped entirely.
	es := NewEmbeddedServer(DefaultConfig())
	rg := NewMCPResponseGuard()
	es.SetGuardrails(nil, rg, DefaultEmbeddedResponseConfig())

	// Simulate a non-tool-call request
	req := &mcp.JSONRPCRequest{
		JSONRPC: mcp.JSONRPCVersion,
		Method:  "tools/list",
		ID:      "1",
	}

	// handlerFunc should process this without attempting response scanning
	// (it won't crash because the method is not tools/call)
	resp := es.handlerFunc(nil, req)
	// Response may be nil if the handler returns nil for nil conn,
	// but it should NOT panic
	_ = resp
}

// testTier returns a Community tier for testing.
func testTier() tier.Tier {
	return tier.TierCommunity
}
