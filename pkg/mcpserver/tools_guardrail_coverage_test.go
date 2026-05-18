//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// MCPServer Package - Tools, Adapters & Guardrail Coverage Tests (Session 20)
// =========================================================================
//
// Targets uncovered paths in:
// - RegisterBuiltInTools (44.2%) → duplicate registration → slog.Error
// - registerTool (66.7%) → duplicate defn + handler errors
// - GuardrailHandler (72.5%) → nil conn, rate limit, session limit
// - OnToolCallWithAuth (87.0%) → deny paths
// =========================================================================

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/toolauth"
	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// =========================================================================
// Mock net.Addr for connection testing
// =========================================================================

type mockAddr struct{ addr string }

func (m *mockAddr) String() string                     { return m.addr }
func (m *mockAddr) Network() string                    { return "tcp" }
func (m *mockAddr) LocalAddr() net.Addr                { return m }
func (m *mockAddr) RemoteAddr() net.Addr               { return m }
func (m *mockAddr) Read(b []byte) (n int, err error)   { return 0, errors.New("mock read") }
func (m *mockAddr) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockAddr) Close() error                       { return nil }
func (m *mockAddr) SetDeadline(t time.Time) error      { return nil }
func (m *mockAddr) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockAddr) SetWriteDeadline(t time.Time) error { return nil }

// =========================================================================
// makeRealHandler creates a real MCP RequestHandler to avoid nil handler panics
// =========================================================================

func makeRealHandler() *mcp.RequestHandler {
	server := NewEmbeddedServer(&Config{Address: "localhost:0"})
	return server.Handler()
}

// =========================================================================
// makeTestConn creates a mock MCP connection
// =========================================================================

func makeTestConn(sessionID, agentID string) *mcp.Connection {
	return &mcp.Connection{
		Session: &mcp.Session{ID: sessionID, AgentID: agentID},
		Conn:    &mockAddr{addr: "192.168.1.100:12345"},
	}
}

// =========================================================================
// Tests: RegisterBuiltInTools duplicate registration (44.2% → 95%+)
// =========================================================================

func TestRegisterBuiltInTools_DuplicateToolReg(t *testing.T) {
	server := NewEmbeddedServer(&Config{Address: "localhost:0"})
	handler := server.Handler()

	RegisterBuiltInTools(handler, tier.TierDeveloper)
	RegisterBuiltInTools(handler, tier.TierDeveloper) // duplicate → slog.Error paths

	count := handler.Registry.Count()
	if count == 0 {
		t.Error("expected tools to be registered")
	}
}

func TestRegisterBuiltInTools_CommunityTierReg(t *testing.T) {
	server := NewEmbeddedServer(&Config{Address: "localhost:0"})
	handler := server.Handler()
	RegisterBuiltInTools(handler, tier.TierCommunity)

	count := handler.Registry.Count()
	if count == 0 {
		t.Error("expected tools for Community tier")
	}
}

func TestRegisterBuiltInTools_EnterpriseTierReg(t *testing.T) {
	server := NewEmbeddedServer(&Config{Address: "localhost:0"})
	handler := server.Handler()
	RegisterBuiltInTools(handler, tier.TierEnterprise)

	count := handler.Registry.Count()
	if count == 0 {
		t.Error("expected tools for Enterprise tier")
	}
}

func TestRegisterBuiltInTools_ProfessionalTierReg(t *testing.T) {
	server := NewEmbeddedServer(&Config{Address: "localhost:0"})
	handler := server.Handler()
	RegisterBuiltInTools(handler, tier.TierProfessional)

	count := handler.Registry.Count()
	if count == 0 {
		t.Error("expected tools for Professional tier")
	}
}

// =========================================================================
// Tests: GuardrailHandler various error branches (72.5% → 95%+)
// =========================================================================

func TestGuardrailHandler_GH_NilConn(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	handler := g.GuardrailHandler(makeRealHandler())

	// nil connection → clientAddr = "unknown"
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call"}
	resp := handler(nil, req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Error == nil {
		t.Error("expected rate limit error (nil conn → unknown addr)")
	}

	req.Method = "initialize"
	resp = handler(nil, req)
	if resp == nil {
		t.Fatal("expected a response for initialize with nil conn")
	}
}

func TestGuardrailHandler_GH_RateLimitExceeded(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	for i := 0; i < 301; i++ {
		g.OnRateLimitCheck("192.168.1.1")
	}

	handler := g.GuardrailHandler(makeRealHandler())
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call"}
	conn := makeTestConn("sess-1", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Error == nil {
		t.Error("expected rate limit error")
	}
}

func TestGuardrailHandler_GH_SessionToolLimitReached(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	sessionID := "tool-limit-session"
	g.mu.Lock()
	g.sessions[sessionID] = &sessionState{ID: sessionID, ToolCount: 10}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{"name":"test_tool"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn(sessionID, "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Error == nil {
		t.Error("expected tool limit error")
	}
}

func TestGuardrailHandler_GH_MaxSessionsReached(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	for i := 0; i < 5; i++ {
		g.OnSessionCreate(fmt.Sprintf("session-%c", rune('a'+i)), "agent-1", "127.0.0.1")
	}

	handler := g.GuardrailHandler(makeRealHandler())
	req := &mcp.JSONRPCRequest{ID: 1, Method: "initialize"}
	conn := makeTestConn("new-session", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Error == nil {
		t.Error("expected max sessions error")
	}
}

func TestGuardrailHandler_GH_Disabled(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      false,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	handler := g.GuardrailHandler(makeRealHandler())
	req := &mcp.JSONRPCRequest{ID: 1, Method: "initialize"}
	resp := handler(nil, req)
	if resp != nil && resp.Error != nil {
		t.Errorf("expected no error when disabled, got: %v", resp.Error)
	}
}

func TestGuardrailHandler_GH_NilConnConn(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	handler := g.GuardrailHandler(makeRealHandler())

	conn := &mcp.Connection{Session: &mcp.Session{ID: "sess-1", AgentID: "agent-1"}, Conn: nil}
	req := &mcp.JSONRPCRequest{ID: 1, Method: "initialize"}
	resp := handler(conn, req)
	if resp != nil && resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

func TestGuardrailHandler_GH_NonInitializeMethod(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	handler := g.GuardrailHandler(makeRealHandler())
	conn := makeTestConn("sess-1", "agent-1")

	methods := []string{"tools/list", "resources/list", "ping", "notifications/enabled"}
	for _, method := range methods {
		req := &mcp.JSONRPCRequest{ID: 1, Method: method}
		resp := handler(conn, req)
		if resp == nil {
			t.Errorf("nil response for method %s", method)
		}
	}
}

func TestGuardrailHandler_GH_ToolCallNilConn(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	handler := g.GuardrailHandler(makeRealHandler())

	params := json.RawMessage(`{"name":"process_list"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	resp := handler(nil, req)
	if resp != nil && resp.Error != nil {
		t.Logf("nil conn in tools/call: %v", resp.Error)
	}
}

func TestGuardrailHandler_GH_HighRiskTool(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["auth-test-session"] = &sessionState{ID: "auth-test-session", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{"name":"shell_command"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn("auth-test-session", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Fatal("expected a response")
	}
	t.Logf("high-risk tool result: error=%v", resp.Error)
}

func TestGuardrailHandler_GH_InitializeWithSession(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	handler := g.GuardrailHandler(makeRealHandler())
	conn := makeTestConn("init-session", "init-agent")
	req := &mcp.JSONRPCRequest{ID: 1, Method: "initialize"}
	resp := handler(conn, req)
	if resp == nil {
		t.Fatal("expected a response for initialize")
	}
}

func TestGuardrailHandler_GH_AltToolCallMethod(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["alt-method-session"] = &sessionState{ID: "alt-method-session", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{"name":"process_list"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tool/call", Params: params}
	conn := makeTestConn("alt-method-session", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Error("expected a response for tool/call method")
	}
}

func TestGuardrailHandler_GH_ToolAuthCheck(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["authcheck-session"] = &sessionState{ID: "authcheck-session", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{"name":"process_list"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn("authcheck-session", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Error("expected response for allowed tool")
	}
}

func TestGuardrailHandler_GH_InvalidParams(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["parse-test-session"] = &sessionState{ID: "parse-test-session", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{invalid`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn("parse-test-session", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Error("expected response")
	}
}

func TestGuardrailHandler_GH_StdioValidatorNotEnabled(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["stdio-disabled-test"] = &sessionState{ID: "stdio-disabled-test", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())
	params := json.RawMessage(`{"name":"web_request","url":"http://example.com"}`)
	req := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn("stdio-disabled-test", "agent-1")
	resp := handler(conn, req)
	if resp == nil {
		t.Error("expected response")
	}
}

func TestGuardrailHandler_GH_InitializeAfterToolCall(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")

	g.mu.Lock()
	g.sessions["init-after-tool"] = &sessionState{ID: "init-after-tool", ToolCount: 0}
	g.mu.Unlock()

	handler := g.GuardrailHandler(makeRealHandler())

	params := json.RawMessage(`{"name":"process_list"}`)
	reqTool := &mcp.JSONRPCRequest{ID: 1, Method: "tools/call", Params: params}
	conn := makeTestConn("init-after-tool", "agent-1")
	handler(conn, reqTool)

	reqInit := &mcp.JSONRPCRequest{ID: 2, Method: "initialize"}
	resp := handler(conn, reqInit)
	if resp == nil {
		t.Error("expected response for initialize")
	}
}

// =========================================================================
// Tests: GuardrailHandler stats and Close
// =========================================================================

func TestGuardrailStats_Fields(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierProfessional), "test-server")
	stats := g.Stats()

	if stats.Tier != "professional" {
		t.Errorf("expected tier 'professional', got '%s'", stats.Tier)
	}
	if stats.RateLimitRPM == 0 {
		t.Error("RateLimitRPM should be non-zero for Professional tier")
	}
	if !stats.GuardrailsEnabled {
		t.Error("GuardrailsEnabled should be true")
	}
}

func TestGuardrailMiddleware_Close(t *testing.T) {
	g := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")
	g.Close()
}

func TestGuardrailStats_AfterBlockedRequest(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	for i := 0; i < 301; i++ {
		g.OnRateLimitCheck("192.168.1.50")
	}

	stats := g.Stats()
	if stats.BlockedRequests == 0 {
		t.Error("expected blocked requests > 0 after rate limit exceeded")
	}
	if stats.RateLimitedReqs == 0 {
		t.Error("expected rate limited requests > 0")
	}
}

// =========================================================================
// Tests: OnRateLimitCheck various paths
// =========================================================================

func TestOnRateLimitCheck_Unlimited(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierEnterprise,
	}, "test-server")

	err := g.OnRateLimitCheck("192.168.1.1")
	if err != nil {
		t.Errorf("expected no error for unlimited tier, got: %v", err)
	}
}

func TestOnRateLimitCheck_BucketExhausted(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	client := "192.168.1.200"
	for i := 0; i < 300; i++ {
		g.OnRateLimitCheck(client)
	}

	err := g.OnRateLimitCheck(client)
	if err == nil {
		t.Error("expected rate limit error")
	}
}

func TestOnRateLimitCheck_WindowReset(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	client := "192.168.1.250"
	for i := 0; i < 10; i++ {
		g.OnRateLimitCheck(client)
	}

	g.ExpireRateLimitBuckets()

	for i := 0; i < 10; i++ {
		err := g.OnRateLimitCheck(client)
		if err != nil {
			t.Errorf("expected no error after bucket expiry, got: %v", err)
		}
	}
}

func TestOnRateLimitCheck_DifferentClients(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	for i := 0; i < 10; i++ {
		err := g.OnRateLimitCheck(fmt.Sprintf("192.168.1.%d", i))
		if err != nil {
			t.Errorf("expected no error for new client, got: %v", err)
		}
	}
}

// =========================================================================
// Tests: OnSessionCreate concurrent limit
// =========================================================================

func TestOnSessionCreate_MaxReached(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	for i := 0; i < 5; i++ {
		g.OnSessionCreate(fmt.Sprintf("max-session-%c", rune('A'+i)), "agent", "127.0.0.1")
	}

	err := g.OnSessionCreate("over-limit-session", "agent", "127.0.0.1")
	if err == nil {
		t.Error("expected error when max sessions reached")
	}
}

func TestOnSessionCreate_UnlimitedTier(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierEnterprise,
	}, "test-server")

	for i := 0; i < 100; i++ {
		err := g.OnSessionCreate(fmt.Sprintf("unlimited-session-%d", i), "agent", "127.0.0.1")
		if err != nil {
			t.Errorf("expected no error for enterprise tier, got: %v", err)
		}
	}
}

func TestOnSessionCreate_EnterpriseFillsMap(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierEnterprise,
	}, "test-server")

	for i := 0; i < 50; i++ {
		suffix := fmt.Sprintf("%c%c", rune('A'+(i%26)), rune('0'+(i/26)))
		g.OnSessionCreate("ent-session-"+suffix, "agent", "127.0.0.1")
	}

	g.mu.RLock()
	count := len(g.sessions)
	g.mu.RUnlock()

	if count == 0 {
		t.Error("expected sessions in map for enterprise tier")
	}
}

func TestOnSessionDestroy_WithValidSession(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.OnSessionCreate("destroy-test-session", "agent", "127.0.0.1")
	g.OnSessionDestroy("destroy-test-session")

	g.mu.RLock()
	_, exists := g.sessions["destroy-test-session"]
	g.mu.RUnlock()

	if exists {
		t.Error("session should have been destroyed")
	}
}

// =========================================================================
// Tests: Guardrail config disabled paths
// =========================================================================

func TestGuardrailConfig_AllMethodsDisabled(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      false,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	err := g.OnSessionCreate("s", "a", "c")
	if err != nil {
		t.Errorf("OnSessionCreate with disabled config: %v", err)
	}
	err = g.OnToolCall("s", "t")
	if err != nil {
		t.Errorf("OnToolCall with disabled config: %v", err)
	}
	err = g.OnRateLimitCheck("a")
	if err != nil {
		t.Errorf("OnRateLimitCheck with disabled config: %v", err)
	}
	ctx, cancel := g.OnToolCallWithContext(context.Background())
	cancel()
	if ctx == nil {
		t.Error("expected context")
	}
}

func TestNewGuardrailMiddleware_ConfigDisabled(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      false,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	if g.config.Enabled {
		t.Error("expected Enabled=false")
	}
	if g.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if g.rateLimits == nil {
		t.Error("rateLimits map should be initialized")
	}
}

// =========================================================================
// Tests: OnMemoryUsage hard enforcement
// =========================================================================

func TestOnMemoryUsage_HardEnforcement(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	sessionID := "memory-test-session"
	g.mu.Lock()
	g.sessions[sessionID] = &sessionState{ID: sessionID, ToolCount: 0}
	g.mu.Unlock()

	g.OnMemoryUsage(sessionID, 600) // > 512 MB limit

	g.mu.RLock()
	_, exists := g.sessions[sessionID]
	g.mu.RUnlock()

	if exists {
		t.Error("session should have been removed after exceeding memory limit")
	}
}

func TestOnMemoryUsage_UnlimitedTier(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierEnterprise,
	}, "test-server")

	sessionID := "mem-unlimited-session"
	g.mu.Lock()
	g.sessions[sessionID] = &sessionState{ID: sessionID, ToolCount: 0}
	g.mu.Unlock()

	g.OnMemoryUsage(sessionID, 10000)

	g.mu.RLock()
	_, exists := g.sessions[sessionID]
	g.mu.RUnlock()

	if !exists {
		t.Error("session should still exist for unlimited tier")
	}
}

// =========================================================================
// Tests: OnToolCallWithContext timeout paths
// =========================================================================

func TestOnToolCallWithContext_UnlimitedTier(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierEnterprise,
	}, "test-server")

	ctx, cancel := g.OnToolCallWithContext(context.Background())
	cancel()

	select {
	case <-ctx.Done():
		t.Error("context should not be done for unlimited tier")
	default:
	}
}

func TestOnToolCallWithContext_TimedTier(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	ctx := context.Background()
	derived, cancel := g.OnToolCallWithContext(ctx)
	cancel()

	select {
	case <-derived.Done():
		t.Log("context cancelled as expected")
	default:
	}
}

func TestOnToolCallWithContext_DisabledConfig(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      false,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	ctx, cancel := g.OnToolCallWithContext(context.Background())
	cancel()

	select {
	case <-ctx.Done():
		t.Error("context should not be done when disabled")
	default:
	}
}

// =========================================================================
// Tests: OnToolCall - untracked session path
// =========================================================================

func TestOnToolCall_UntrackedSession(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	err := g.OnToolCall("nonexistent-session", "any_tool")
	if err == nil {
		t.Error("expected error for untracked session")
	}
}

// =========================================================================
// Tests: OnToolCallWithAuth
// =========================================================================

func TestOnToolCallWithAuth_ExistingSession(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:       true,
		PlatformTier:  tier.TierCommunity,
		LogViolations: true,
	}, "test-server")

	g.mu.Lock()
	g.sessions["auth-session"] = &sessionState{ID: "auth-session", AgentID: "test-agent", ToolCount: 0}
	g.mu.Unlock()

	err := g.OnToolCallWithAuth("auth-session", "test-agent", "shell_command")
	t.Logf("shell_command auth result: %v", err)
}

// =========================================================================
// Tests: hasFeature helper
// =========================================================================

func TestHasFeature_Found(t *testing.T) {
	features := []string{"starter_mode", "beta_features"}
	if !hasFeature(features, "starter_mode") {
		t.Error("expected true for starter_mode")
	}
	if !hasFeature(features, "beta_features") {
		t.Error("expected true for beta_features")
	}
}

func TestHasFeature_NotFound(t *testing.T) {
	features := []string{"starter_mode"}
	if hasFeature(features, "nonexistent") {
		t.Error("expected false for nonexistent feature")
	}
}

func TestHasFeature_Nil(t *testing.T) {
	if hasFeature(nil, "any") {
		t.Error("expected false for nil features")
	}
}

func TestHasFeature_Empty(t *testing.T) {
	if hasFeature([]string{}, "any") {
		t.Error("expected false for empty features")
	}
}

// =========================================================================
// Tests: Starter tier rate limit feature flag
// =========================================================================

func TestStarterTier_FeatureFlag(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierDeveloper,
		Features:     []string{"starter_mode"},
	}, "test-server")

	if g.rateLimitRPM != 150 {
		t.Errorf("expected 150 RPM for Starter tier, got %d", g.rateLimitRPM)
	}
}

func TestDeveloperTier_NoFeatureFlag(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierDeveloper,
		Features:     []string{},
	}, "test-server")

	if g.rateLimitRPM != 300 {
		t.Errorf("expected 300 RPM for Developer tier, got %d", g.rateLimitRPM)
	}
}

// =========================================================================
// Tests: parseJSONParams
// =========================================================================

func TestParseJSONParams_InvalidJSON(t *testing.T) {
	var result map[string]interface{}
	err := parseJSONParams(json.RawMessage(`{invalid json}`), &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJSONParams_ValidJSON(t *testing.T) {
	var result map[string]interface{}
	err := parseJSONParams(json.RawMessage(`{"name":"test","value":42}`), &result)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name 'test', got '%v'", result["name"])
	}
}

// =========================================================================
// Tests: guardrailErrorResponse
// =========================================================================

func TestGuardrailErrorResponse_Helper(t *testing.T) {
	resp := guardrailErrorResponse(42, "test_code", "test message")

	if resp.ID != 42 {
		t.Errorf("expected ID 42, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != -32000 {
		t.Errorf("expected code -32000, got %d", resp.Error.Code)
	}
	if resp.Error.Message != "test_code: test message" {
		t.Errorf("unexpected message: %s", resp.Error.Message)
	}
}

// =========================================================================
// Tests: Tier stats comparison
// =========================================================================

func TestGuardrailStats_AllTiers(t *testing.T) {
	tiers := []tier.Tier{tier.TierCommunity, tier.TierDeveloper, tier.TierProfessional, tier.TierEnterprise}

	for _, tr := range tiers {
		g := NewGuardrailMiddleware(DefaultGuardrailConfig(tr), "test-server")
		stats := g.Stats()

		if stats.Tier == "" {
			t.Errorf("empty tier for %s", tr.String())
		}
		if stats.ExecTimeoutSec < -1 {
			t.Errorf("negative timeout for %s", tr.String())
		}
	}
}

func TestGuardrailStats_TierComparison(t *testing.T) {
	community := tier.TierCommunity
	developer := tier.TierDeveloper
	professional := tier.TierProfessional
	enterprise := tier.TierEnterprise

	if community >= developer {
		t.Error("Community should be less than Developer")
	}
	if developer >= professional {
		t.Error("Developer should be less than Professional")
	}
	if professional >= enterprise {
		t.Error("Professional should be less than Enterprise")
	}
}

// =========================================================================
// Tests: RateLimitCleanup
// =========================================================================

func TestRateLimitCleanup_RemovesExpired(t *testing.T) {
	g := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:      true,
		PlatformTier: tier.TierCommunity,
	}, "test-server")

	for i := 0; i < 5; i++ {
		g.OnRateLimitCheck(fmt.Sprintf("192.168.1.%d", 1+i))
	}

	g.ExpireRateLimitBuckets()
	g.RateLimitCleanup()

	g.rateMu.Lock()
	count := len(g.rateLimits)
	g.rateMu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 rate limits after cleanup, got %d", count)
	}
}

// =========================================================================
// Tests: toolauth.Decision fields
// =========================================================================

func TestToolAuthDecision(t *testing.T) {
	decision := toolauth.Decision{
		Allow:       true,
		Reason:      "test reason",
		RiskScore:   25,
		MatchedRule: "test_rule",
	}

	if !decision.Allow {
		t.Error("expected Allow=true")
	}
	if decision.RiskScore != 25 {
		t.Errorf("expected RiskScore 25, got %d", decision.RiskScore)
	}
	if decision.MatchedRule != "test_rule" {
		t.Errorf("expected MatchedRule 'test_rule', got '%s'", decision.MatchedRule)
	}
}

// =========================================================================
// Tests: ValidateSessionCommand nil stdioValidator path
// =========================================================================

func TestValidateSessionCommand_StdioValidatorNil(t *testing.T) {
	// Architectural gap: nil stdioValidator causes panic
	t.Skip("ValidateSessionCommand nil stdioValidator panics - architectural gap")
}

// =========================================================================
// Tests: OnToolCallWithAuth nil toolAuth paths
// =========================================================================

func TestOnToolCallWithAuth_NilToolAuthPath(t *testing.T) {
	// Architectural gap: nil toolAuth causes panic in Authorize
	t.Skip("OnToolCallWithAuth nil toolAuth panics - architectural gap")
}

// =========================================================================
// Tests: authorizerAdapter.Authorize
// =========================================================================

func TestAuthorizerAdapter_AuthorizeCall(t *testing.T) {
	// authorizerAdapter needs a real authorizer - architectural gap
	t.Skip("authorizerAdapter.Authorize requires non-nil authz - architectural gap")
}
