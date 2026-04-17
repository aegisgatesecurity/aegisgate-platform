// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform - MCP Guardrail Middleware Tests
// =========================================================================

package mcpserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// --------------------------------------------------------------------------
// Config & construction
// --------------------------------------------------------------------------

func TestDefaultGuardrailConfig(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	if !cfg.Enabled {
		t.Error("Default config should be enabled")
	}
	if cfg.PlatformTier != tier.TierCommunity {
		t.Error("Platform tier mismatch")
	}
	if !cfg.LogViolations {
		t.Error("LogViolations should default true")
	}
	if !cfg.AuditViolations {
		t.Error("AuditViolations should default true")
	}
}

func TestNewGuardrailMiddleware_Enabled(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)
	if !g.config.Enabled {
		t.Error("Should be enabled")
	}
	stats := g.Stats()
	if stats.Tier != "community" {
		t.Errorf("Expected tier 'community', got '%s'", stats.Tier)
	}
	if !stats.GuardrailsEnabled {
		t.Error("Guardrails should be enabled")
	}
}

func TestNewGuardrailMiddleware_Disabled(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)
	if g.config.Enabled {
		t.Error("Should be disabled")
	}
	stats := g.Stats()
	if stats.GuardrailsEnabled {
		t.Error("Guardrails should report disabled")
	}
}

// --------------------------------------------------------------------------
// Guard 1: Concurrent session limit
// --------------------------------------------------------------------------

func TestSessionCreate_Allowed(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	err := g.OnSessionCreate("s1", "agent1")
	if err != nil {
		t.Errorf("First session should be allowed, got: %v", err)
	}
	stats := g.Stats()
	if stats.ActiveSessions != 1 {
		t.Errorf("Expected 1 active session, got %d", stats.ActiveSessions)
	}
}

func TestSessionCreate_MaxReached(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	// Fill up to max
	for i := 0; i < 5; i++ {
		g.OnSessionCreate("s"+string(rune('1'+i)), "agent")
	}

	// 6th session should be blocked
	err := g.OnSessionCreate("s_overflow", "agent")
	if err == nil {
		t.Error("Expected error when max sessions exceeded")
	}
}

func TestSessionCreate_Unlimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierEnterprise) // -1 = unlimited
	g := NewGuardrailMiddleware(cfg)

	// Create many sessions — all should succeed
	for i := 0; i < 200; i++ {
		err := g.OnSessionCreate("s_enterprise_"+string(rune(i)), "agent")
		if err != nil {
			t.Errorf("Enterprise session %d should be allowed, got: %v", i, err)
		}
	}
}

func TestSessionCreate_Destroy_Reuse(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	// Fill to max
	for i := 0; i < 5; i++ {
		g.OnSessionCreate("s"+string(rune('1'+i)), "agent")
	}

	// 6th blocked
	err := g.OnSessionCreate("s6", "agent")
	if err == nil {
		t.Error("Expected error at max capacity")
	}

	// Destroy one
	g.OnSessionDestroy("s1")

	// Now should succeed
	err = g.OnSessionCreate("s6", "agent")
	if err != nil {
		t.Errorf("Should allow after destroy, got: %v", err)
	}
}

func TestSessionDestroy_Idempotent(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)

	g.OnSessionCreate("s1", "agent")
	g.OnSessionDestroy("s1")
	g.OnSessionDestroy("s1") // double-destroy should not panic
	stats := g.Stats()
	if stats.ActiveSessions != 0 {
		t.Errorf("Expected 0 active, got %d", stats.ActiveSessions)
	}
}

func TestSessionCreate_DisabledMiddleware(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)

	// Even at "max", should not block
	for i := 0; i < 100; i++ {
		err := g.OnSessionCreate("s_disabled_"+string(rune(i)), "agent")
		if err != nil {
			t.Errorf("Disabled middleware should not block, got: %v", err)
		}
	}
}

// --------------------------------------------------------------------------
// Guard 2: Per-session tool count limit
// --------------------------------------------------------------------------

func TestToolCall_Allowed(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 20 tools/session
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	err := g.OnToolCall("s1", "process_list")
	if err != nil {
		t.Errorf("Tool call within limit should be allowed, got: %v", err)
	}
}

func TestToolCall_MaxReached(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 20 tools/session
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	// Make 20 tool calls
	for i := 0; i < 20; i++ {
		g.OnToolCall("s1", "process_list")
	}

	// 21st should be blocked
	err := g.OnToolCall("s1", "process_list")
	if err == nil {
		t.Error("Expected error when tool limit exceeded")
	}
}

func TestToolCall_Unlimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierProfessional) // -1 = unlimited
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	for i := 0; i < 500; i++ {
		err := g.OnToolCall("s1", "process_list")
		if err != nil {
			t.Errorf("Professional tool call %d should be allowed, got: %v", i, err)
		}
	}
}

func TestToolCall_UntrackedSession(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)

	// Call tool on session that was never registered
	err := g.OnToolCall("unknown_session", "process_list")
	if err != nil {
		t.Errorf("Untracked session should be allowed (not gatechecked), got: %v", err)
	}
}

func TestToolCall_DisabledMiddleware(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)

	err := g.OnToolCall("s1", "process_list")
	if err != nil {
		t.Errorf("Disabled middleware should not block, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// Guard 3: Execution timeout
// --------------------------------------------------------------------------

func TestToolCallWithContext_TimeoutSet(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 30s timeout
	g := NewGuardrailMiddleware(cfg)

	ctx := context.Background()
	newCtx, cancel := g.OnToolCallWithContext(ctx)
	defer cancel()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Error("Expected context to have a deadline")
	}
	if deadline.Before(time.Now().Add(29*time.Second)) || deadline.After(time.Now().Add(31*time.Second)) {
		t.Errorf("Deadline approximately 30s expected, got %v", deadline)
	}
}

func TestToolCallWithContext_Unlimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierEnterprise) // -1 = unlimited
	g := NewGuardrailMiddleware(cfg)

	ctx := context.Background()
	newCtx, cancel := g.OnToolCallWithContext(ctx)
	defer cancel()

	_, ok := newCtx.Deadline()
	if ok {
		t.Error("Enterprise (unlimited) should have no deadline")
	}
}

func TestToolCallWithContext_DisabledMiddleware(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)

	ctx := context.Background()
	newCtx, cancel := g.OnToolCallWithContext(ctx)
	defer cancel()

	_, ok := newCtx.Deadline()
	if ok {
		t.Error("Disabled middleware should not add deadline")
	}
}

// --------------------------------------------------------------------------
// Guard 4: Memory advisory
// --------------------------------------------------------------------------

func TestMemoryUsage_WithinLimit(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 256MB limit
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	// Should not panic or error — advisory only
	g.OnMemoryUsage("s1", 128)
}

func TestMemoryUsage_ExceedsLimit(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 256MB limit
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	// Exceeds limit — advisory only, should not panic
	g.OnMemoryUsage("s1", 512)
}

func TestMemoryUsage_Unlimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierEnterprise) // -1 = unlimited
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")

	// Should not panic even with huge value
	g.OnMemoryUsage("s1", 99999)
}

// --------------------------------------------------------------------------
// GuardrailHandler (wrapping HandleRequest)
// --------------------------------------------------------------------------

func TestGuardrailHandler_Initialize(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	// Create a minimal inner handler
	innerHandler := mcp.NewRequestHandler(nil, nil, nil)
	wrapped := g.GuardrailHandler(innerHandler)

	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	resp := wrapped(nil, req)
	if resp.Error != nil {
		t.Errorf("Initialize should succeed, got error: %v", resp.Error)
	}
	stats := g.Stats()
	if stats.ActiveSessions != 1 {
		t.Errorf("Expected 1 active session after initialize, got %d", stats.ActiveSessions)
	}
}

func TestGuardrailHandler_MaxSessionsBlock(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	innerHandler := mcp.NewRequestHandler(nil, nil, nil)
	wrapped := g.GuardrailHandler(innerHandler)

	// Fill sessions manually
	for i := 0; i < 5; i++ {
		g.OnSessionCreate("s"+string(rune('1'+i)), "agent")
	}

	// Next initialize should be blocked
	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      99,
		Method:  "initialize",
	}

	resp := wrapped(nil, req)
	if resp.Error == nil {
		t.Error("Expected error when max sessions exceeded")
	}
}

func TestGuardrailHandler_Disabled(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)

	innerHandler := mcp.NewRequestHandler(nil, nil, nil)
	wrapped := g.GuardrailHandler(innerHandler)

	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	_ = wrapped(nil, req)
	// Should delegate directly — no session tracking
	if g.Stats().ActiveSessions != 0 {
		t.Error("Disabled guardrail should not track sessions")
	}
}

// --------------------------------------------------------------------------
// Stats
// --------------------------------------------------------------------------

func TestStats_ReflectsState(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper) // max 25 sessions, 50 tools
	g := NewGuardrailMiddleware(cfg)

	g.OnSessionCreate("s1", "agent1")
	g.OnSessionCreate("s2", "agent2")
	g.OnToolCall("s1", "process_list")
	g.OnToolCall("s1", "git_status")
	g.OnToolCall("s2", "file_read")

	stats := g.Stats()
	if stats.Tier != "developer" {
		t.Errorf("Expected 'developer', got '%s'", stats.Tier)
	}
	if stats.ActiveSessions != 2 {
		t.Errorf("Expected 2 sessions, got %d", stats.ActiveSessions)
	}
	if stats.MaxSessions != 25 {
		t.Errorf("Expected 25 max, got %d", stats.MaxSessions)
	}
	if stats.ToolsPerSession != 50 {
		t.Errorf("Expected 50 tools/session, got %d", stats.ToolsPerSession)
	}
}

func TestStats_BlockedRequests(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // max 5
	g := NewGuardrailMiddleware(cfg)

	// Fill to max
	for i := 0; i < 5; i++ {
		g.OnSessionCreate("s"+string(rune('1'+i)), "agent")
	}

	// This should be blocked
	g.OnSessionCreate("s_overflow", "agent")

	stats := g.Stats()
	if stats.BlockedRequests != 1 {
		t.Errorf("Expected 1 blocked request, got %d", stats.BlockedRequests)
	}
}

// --------------------------------------------------------------------------
// Tier differentiation
// --------------------------------------------------------------------------

func TestTierDifferentiation(t *testing.T) {
	tests := []struct {
		name         string
		t            tier.Tier
		maxSessions  int
		maxTools     int
		timeoutSec   int
		sandboxMemMB int
	}{
		{"Community", tier.TierCommunity, 5, 20, 30, 256},
		{"Developer", tier.TierDeveloper, 25, 50, 60, 512},
		{"Professional", tier.TierProfessional, 100, 0, 300, 2048}, // 0 = unlimited
		{"Enterprise", tier.TierEnterprise, 0, 0, -1, -1},          // 0 = unlimited
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultGuardrailConfig(tt.t)
			g := NewGuardrailMiddleware(cfg)
			stats := g.Stats()

			if stats.MaxSessions != tt.maxSessions {
				t.Errorf("%s: max sessions = %d, expected %d", tt.name, stats.MaxSessions, tt.maxSessions)
			}
			if stats.ToolsPerSession != tt.maxTools {
				t.Errorf("%s: tools/session = %d, expected %d", tt.name, stats.ToolsPerSession, tt.maxTools)
			}
			if stats.ExecTimeoutSec != tt.timeoutSec {
				t.Errorf("%s: timeout = %d, expected %d", tt.name, stats.ExecTimeoutSec, tt.timeoutSec)
			}
			if stats.SandboxMemoryMB != tt.sandboxMemMB {
				t.Errorf("%s: sandbox memory = %d, expected %d", tt.name, stats.SandboxMemoryMB, tt.sandboxMemMB)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Close
// --------------------------------------------------------------------------

func TestClose(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)
	g.OnSessionCreate("s1", "agent")
	g.Close() // should not panic
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func TestGuardrailErrorResponse(t *testing.T) {
	resp := guardrailErrorResponse(42, ErrMaxSessions, "test error")
	if resp.ID != 42 {
		t.Errorf("Expected ID 42, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("Expected non-nil error")
	}
	if resp.Error.Code != -32000 {
		t.Errorf("Expected error code -32000, got %d", resp.Error.Code)
	}
}

func TestParseJSONParams(t *testing.T) {
	raw := json.RawMessage(`{"name": "test", "arguments": {"key": "value"}}`)
	var result map[string]interface{}
	err := parseJSONParams(raw, &result)
	if err != nil {
		t.Errorf("Failed to parse valid JSON: %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("Expected name='test', got %v", result["name"])
	}
}

func TestParseJSONParams_Invalid(t *testing.T) {
	raw := json.RawMessage(`not valid json`)
	var result map[string]interface{}
	err := parseJSONParams(raw, &result)
	if err == nil {
		t.Error("Expected error parsing invalid JSON")
	}
}