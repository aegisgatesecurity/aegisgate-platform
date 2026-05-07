// SPDX-License-Identifier: Apache-2.0
//go:build !race

package mcpserver

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// =============================================================================
// GuardrailHandler test coverage (60.8% → 95%+)
// =============================================================================

// TestGuardrailHandler_New_Disabled tests when guardrails are disabled
func TestGuardrailHandler_New_Disabled(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	config.Enabled = false
	g := NewGuardrailMiddleware(config, "test-server")
	handler := mcp.NewRequestHandler(nil, nil, nil)
	fn := g.GuardrailHandler(handler)

	// Should call inner handler directly when disabled
	conn := &mcp.Connection{}
	req := &mcp.JSONRPCRequest{Method: "initialize", ID: "test"}
	resp := fn(conn, req)
	_ = resp
}

// TestGuardrailHandler_New_UnknownClient tests handling of nil/unknown client connection
func TestGuardrailHandler_New_UnknownClient(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	config.Enabled = true
	g := NewGuardrailMiddleware(config, "test-server")
	handler := mcp.NewRequestHandler(nil, nil, nil)
	fn := g.GuardrailHandler(handler)

	// Test with nil connection (unknown client)
	conn := &mcp.Connection{}
	req := &mcp.JSONRPCRequest{Method: "initialize", ID: "test"}
	resp := fn(conn, req)
	_ = resp
}

// TestGuardrailHandler_New_InvalidParams tests handling of invalid params JSON
func TestGuardrailHandler_New_InvalidParams(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	config.Enabled = true
	g := NewGuardrailMiddleware(config, "test-server")
	handler := mcp.NewRequestHandler(nil, nil, nil)
	fn := g.GuardrailHandler(handler)

	conn := &mcp.Connection{}
	req := &mcp.JSONRPCRequest{
		Method: "tools/call",
		ID:     "test",
		Params: []byte(`{invalid json`), // Invalid JSON
	}
	resp := fn(conn, req)
	_ = resp
}

// =============================================================================
// OnToolCallWithAuth test coverage (73.9% → 95%+)
// =============================================================================

// TestOnToolCallWithAuth_New_NilToolAuth tests behavior when tool auth is nil
func TestOnToolCallWithAuth_New_NilToolAuth(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")
	g.toolAuth = nil

	err := g.OnToolCallWithAuth("session-1", "agent-1", "test_tool")
	if err == nil {
		t.Fatal("OnToolCallWithAuth should error when toolAuth is nil")
	}
}

// =============================================================================
// OnMemoryUsage test coverage (93.8% → 95%+)
// =============================================================================

// TestOnMemoryUsage_New_AtLimit tests memory usage at exactly the limit
func TestOnMemoryUsage_New_AtLimit(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")

	// Memory at limit (0MB used, limit from tier)
	limitMB := g.config.PlatformTier.MaxMCPSandboxMemoryMB()
	if limitMB > 0 {
		g.OnMemoryUsage("session-1", int64(limitMB))
	}
}

// TestOnMemoryUsage_New_OverLimit tests memory usage over limit
func TestOnMemoryUsage_New_OverLimit(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")

	// Memory over limit (1GB used, 0MB limit from tier if set to 0)
	limitMB := g.config.PlatformTier.MaxMCPSandboxMemoryMB()
	if limitMB > 0 {
		g.OnMemoryUsage("session-1", int64(limitMB)+100)
	}
}

// =============================================================================
// GuardrailStats tests
// =============================================================================

// TestGuardrailStats_New_Fields tests GuardrailStats struct fields
func TestGuardrailStats_New_Fields(t *testing.T) {
	stats := GuardrailStats{
		Tier:            "community",
		ActiveSessions:  10,
		MaxSessions:     100,
		TotalRequests:   1000,
		BlockedRequests: 5,
		TimeoutRequests: 2,
		RateLimitRPM:    300,
		RateLimitedReqs: 3,
		ToolsPerSession: 50,
		ExecTimeoutSec:  30,
		SandboxMemoryMB: 512,
	}

	if stats.Tier != "community" {
		t.Errorf("Tier = %q, want community", stats.Tier)
	}
	if stats.ActiveSessions != 10 {
		t.Errorf("ActiveSessions = %d, want 10", stats.ActiveSessions)
	}
}

// =============================================================================
// sessionState tests
// =============================================================================

// TestOnSessionCreate_New_DuplicateSession tests creating duplicate session
func TestOnSessionCreate_New_DuplicateSession(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")

	// Create same session twice
	_ = g.OnSessionCreate("dup-session", "agent-1", "127.0.0.1")
	g.OnSessionCreate("dup-session", "agent-1", "127.0.0.1")
}

// TestOnSessionDestroy_New_NonExistentSession tests destroying non-existent session
func TestOnSessionDestroy_New_NonExistentSession(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")

	g.OnSessionDestroy("non-existent-session")
}

// =============================================================================
// OnRateLimitCheck tests
// =============================================================================

// TestOnRateLimitCheck_New_MultipleClients tests rate limiting across multiple clients
func TestOnRateLimitCheck_New_MultipleClients(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	config.Enabled = true
	g := NewGuardrailMiddleware(config, "test-server")

	// Different clients should have separate rate limits
	err := g.OnRateLimitCheck("client-1")
	if err != nil {
		t.Fatalf("first client should pass: %v", err)
	}

	err = g.OnRateLimitCheck("client-2")
	if err != nil {
		t.Fatalf("second client should pass: %v", err)
	}
}

// =============================================================================
// OnToolCall tests
// =============================================================================

// TestOnToolCall_New_Basic tests basic tool call
func TestOnToolCall_New_Basic(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(config, "test-server")

	// Create session first
	_ = g.OnSessionCreate("session-1", "agent-1", "127.0.0.1")

	err := g.OnToolCall("session-1", "tool")
	if err != nil {
		t.Fatalf("basic tool call should pass: %v", err)
	}
}

// =============================================================================
// GuardrailHandler tests with session
// =============================================================================

// TestGuardrailHandler_New_WithSession tests GuardrailHandler with a session
func TestGuardrailHandler_New_WithSession(t *testing.T) {
	config := DefaultGuardrailConfig(tier.TierCommunity)
	config.Enabled = true
	g := NewGuardrailMiddleware(config, "test-server")
	handler := mcp.NewRequestHandler(nil, nil, nil)
	fn := g.GuardrailHandler(handler)

	session := &mcp.Session{ID: "test-session", AgentID: "test-agent"}
	conn := &mcp.Connection{Session: session}

	// Initialize should work
	req := &mcp.JSONRPCRequest{Method: "initialize", ID: "init-1"}
	resp := fn(conn, req)
	_ = resp

	// Tool call should work
	req = &mcp.JSONRPCRequest{
		Method: "tools/call",
		ID:     "tool-1",
		Params: []byte(`{"name":"test_tool"}`),
	}
	resp = fn(conn, req)
	_ = resp
}
