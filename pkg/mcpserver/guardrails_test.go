// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Guardrail Middleware Tests
// =========================================================================

package mcpserver

import (
	"context"
	"encoding/json"
	"net"
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
		rateLimitRPM int
	}{
		{"Community", tier.TierCommunity, 5, 20, 30, 256, 60},
		{"Developer", tier.TierDeveloper, 25, 50, 60, 512, 300},
		{"Professional", tier.TierProfessional, 100, 0, 300, 2048, 1500}, // 0 = unlimited
		{"Enterprise", tier.TierEnterprise, 0, 0, -1, -1, 0},             // 0 = unlimited (shown as 0)
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
			if stats.RateLimitRPM != tt.rateLimitRPM {
				t.Errorf("%s: rate limit RPM = %d, expected %d", tt.name, stats.RateLimitRPM, tt.rateLimitRPM)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Guard 5: Per-client RPM rate limiting
// --------------------------------------------------------------------------

func TestRateLimit_Allowed(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 60 RPM
	g := NewGuardrailMiddleware(cfg)

	// Requests within RPM should pass
	for i := 0; i < 60; i++ {
		err := g.OnRateLimitCheck("192.168.1.100:1234")
		if err != nil {
			t.Fatalf("Request %d should be allowed, got: %v", i+1, err)
		}
	}
}

func TestRateLimit_Exceeded(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 60 RPM
	g := NewGuardrailMiddleware(cfg)

	// Fill up to RPM limit
	for i := 0; i < 60; i++ {
		g.OnRateLimitCheck("10.0.0.1:5678")
	}

	// Request over limit should be blocked
	err := g.OnRateLimitCheck("10.0.0.1:5678")
	if err == nil {
		t.Error("Expected error when RPM exceeded")
	}

	stats := g.Stats()
	if stats.RateLimitedReqs != 1 {
		t.Errorf("Expected 1 rate-limited request, got %d", stats.RateLimitedReqs)
	}
	if stats.BlockedRequests < 1 {
		t.Errorf("Expected blocked request counter incremented, got %d", stats.BlockedRequests)
	}
}

func TestRateLimit_DifferentClients(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 60 RPM per client
	g := NewGuardrailMiddleware(cfg)

	// Each client gets their own bucket — use different subnets so
	// SanitizeClientID produces distinct keys (it masks last 2 octets,
	// so 10.x.x.x and 192.168.x.x become different buckets)
	for i := 0; i < 60; i++ {
		g.OnRateLimitCheck("10.0.0.1:1234")
	}

	// Client 1 is at limit, but client 2 should be fine (different sanitized bucket)
	err := g.OnRateLimitCheck("192.168.0.1:5678")
	if err != nil {
		t.Errorf("Different client should be allowed, got: %v", err)
	}

	// Client 1 should still be blocked (same sanitized bucket)
	err = g.OnRateLimitCheck("10.0.0.1:1234")
	if err == nil {
		t.Error("Original client should still be rate-limited")
	}
}

func TestRateLimit_Unlimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierEnterprise) // -1 = unlimited
	g := NewGuardrailMiddleware(cfg)

	// Enterprise should never be rate limited
	for i := 0; i < 500; i++ {
		err := g.OnRateLimitCheck("10.0.0.1:1234")
		if err != nil {
			t.Fatalf("Enterprise request %d should never be limited, got: %v", i, err)
		}
	}

	stats := g.Stats()
	if stats.RateLimitedReqs != 0 {
		t.Errorf("Enterprise should have 0 rate-limited requests, got %d", stats.RateLimitedReqs)
	}
}

func TestRateLimit_DisabledMiddleware(t *testing.T) {
	cfg := GuardrailConfig{Enabled: false, PlatformTier: tier.TierCommunity}
	g := NewGuardrailMiddleware(cfg)

	// Disabled middleware should never rate limit
	for i := 0; i < 200; i++ {
		err := g.OnRateLimitCheck("10.0.0.1:1234")
		if err != nil {
			t.Errorf("Disabled middleware should not limit, got: %v", err)
		}
	}
}

func TestRateLimit_StatsRPM(t *testing.T) {
	tests := []struct {
		name string
		t    tier.Tier
		rpm  int
	}{
		{"Community", tier.TierCommunity, 60},
		{"Developer", tier.TierDeveloper, 300},
		{"Professional", tier.TierProfessional, 1500},
		{"Enterprise", tier.TierEnterprise, 0}, // 0 = unlimited (shown as 0 in stats)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultGuardrailConfig(tt.t)
			g := NewGuardrailMiddleware(cfg)
			stats := g.Stats()
			if stats.RateLimitRPM != tt.rpm {
				t.Errorf("%s: RateLimitRPM = %d, expected %d", tt.name, stats.RateLimitRPM, tt.rpm)
			}
		})
	}
}

func TestRateLimitCleanup(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)

	// Create a rate limit bucket with an expired window
	g.rateMu.Lock()
	g.rateLimits["expired_client"] = &mcpClientBucket{
		count:   1,
		resetAt: time.Now().Add(-time.Minute), // expired
	}
	g.rateLimits["active_client"] = &mcpClientBucket{
		count:   1,
		resetAt: time.Now().Add(time.Minute), // still active
	}
	g.rateMu.Unlock()

	g.RateLimitCleanup()

	g.rateMu.Lock()
	_, expiredExists := g.rateLimits["expired_client"]
	_, activeExists := g.rateLimits["active_client"]
	g.rateMu.Unlock()

	if expiredExists {
		t.Error("Expired bucket should have been cleaned up")
	}
	if !activeExists {
		t.Error("Active bucket should still exist")
	}
}

func TestExpireRateLimitBuckets(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	g := NewGuardrailMiddleware(cfg)

	// Exhaust the limit
	for i := 0; i < 60; i++ {
		g.OnRateLimitCheck("10.0.0.1:1111")
	}

	// Should be limited
	err := g.OnRateLimitCheck("10.0.0.1:1111")
	if err == nil {
		t.Fatal("Should be rate-limited")
	}

	// Force expire all buckets
	g.ExpireRateLimitBuckets()

	// Cleanup to remove expired entries
	g.RateLimitCleanup()

	// Should now be allowed (new window)
	err = g.OnRateLimitCheck("10.0.0.1:1111")
	if err != nil {
		t.Errorf("After ExpireRateLimitBuckets + cleanup, request should be allowed, got: %v", err)
	}
}

func TestGuardrailHandler_RateLimited(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity) // 60 RPM
	g := NewGuardrailMiddleware(cfg)

	innerHandler := mcp.NewRequestHandler(nil, nil, nil)
	wrapped := g.GuardrailHandler(innerHandler)

	// Create a fake connection with a net.Conn
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	conn := &mcp.Connection{
		ID:   "test-conn",
		Conn: serverConn,
	}

	// Fill up to RPM limit
	for i := 0; i < 60; i++ {
		req := &mcp.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      i,
			Method:  "ping",
		}
		wrapped(conn, req)
	}

	// 61st request should be rate-limited
	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      99,
		Method:  "ping",
	}
	resp := wrapped(conn, req)
	if resp.Error == nil {
		t.Error("Expected error when rate limit exceeded via GuardrailHandler")
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

	// Also verify rate limit error response
	rlResp := guardrailErrorResponse(99, ErrRateLimitExceeded, "rate limit hit")
	if rlResp.Error == nil {
		t.Fatal("Expected non-nil rate limit error")
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

// TestGuardrailHandler_Comprehensive covers all guardrail scenarios including error paths
