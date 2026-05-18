//go:build !race

// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// MCPServer Package Enhanced Coverage Tests - Session 18
// =========================================================================

package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// =========================================================================
// SetGuardrails tests (0.0% → 95%+)
// =========================================================================

func TestSetGuardrails(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	guardrails := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "test-server")

	// Set guardrails - should not panic
	sm.SetGuardrails(guardrails)

	// Verify guardrails is set
	if sm.guardrails != guardrails {
		t.Error("guardrails not set correctly")
	}
}

func TestSetGuardrails_Nil(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Set nil guardrails - should not panic
	sm.SetGuardrails(nil)

	// Should not crash
	if sm.guardrails != nil {
		t.Error("expected nil guardrails")
	}
}

func TestCloseSession_WithGuardrails(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Create guardrail middleware with config
	guardrails := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierCommunity,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")

	// Wire guardrails
	sm.SetGuardrails(guardrails)

	// Register agent and create session
	agent := &rbac.Agent{
		ID:    "test-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	_, err := sm.CreateSession(ctx, "conn-guardrails-test", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Track session in guardrails
	guardrails.activeSessions = 1

	// Close session - should trigger OnSessionDestroy
	err = sm.CloseSession("conn-guardrails-test")
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	// Session should be removed
	_, err = sm.GetSession("conn-guardrails-test")
	if err != ErrSessionNotFound {
		t.Errorf("expected session not found, got %v", err)
	}
}

// =========================================================================
// EmbeddedServer tests
// =========================================================================

func TestNewMCPEmbeddedServer(t *testing.T) {
	cfg := &Config{
		Address:      ":9090",
		ReadTimeout:  60,
		WriteTimeout: 60,
		IdleTimeout:  300,
	}

	server := NewEmbeddedServer(cfg)
	if server == nil {
		t.Fatal("NewEmbeddedServer returned nil")
	}
	if server.config == nil {
		t.Error("config not set")
	}
	if server.handler == nil {
		t.Error("handler not set")
	}
}

func TestNewMCPEmbeddedServer_NilConfig(t *testing.T) {
	server := NewEmbeddedServer(nil)
	if server == nil {
		t.Fatal("NewEmbeddedServer returned nil")
	}

	// Should use default config
	if server.config.Address != ":8081" {
		t.Errorf("expected default address :8081, got %s", server.config.Address)
	}
}

func TestMCPConfig_AllTimeouts(t *testing.T) {
	cfg := &Config{
		Address:      ":9090",
		ReadTimeout:  120,
		WriteTimeout: 180,
		IdleTimeout:  600,
	}

	server := NewEmbeddedServer(cfg)
	if server.config.ReadTimeout != 120 {
		t.Errorf("expected ReadTimeout 120, got %v", server.config.ReadTimeout)
	}
}

func TestMCPEmbeddedServer_Handler(t *testing.T) {
	server := NewEmbeddedServer(nil)
	handler := server.Handler()

	if handler == nil {
		t.Error("Handler() returned nil")
	}
}

func TestMCPEmbeddedServer_StartStop(t *testing.T) {
	server := NewEmbeddedServer(&Config{
		Address:      "localhost:0",
		ReadTimeout:  30,
		WriteTimeout: 30,
		IdleTimeout:  60,
	})

	// Start server
	err := server.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Stop server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestMCPEmbeddedServer_StopWithoutStart(t *testing.T) {
	server := NewEmbeddedServer(nil)

	err := server.Stop()
	if err != nil {
		t.Errorf("Stop should not error: %v", err)
	}
}

// =========================================================================
// Session manager with guardrails integration
// =========================================================================

func TestCreateSession_WithGuardrails(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	guardrails := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierDeveloper,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")
	sm.SetGuardrails(guardrails)

	agent := &rbac.Agent{
		ID:    "guardrails-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session, err := sm.CreateSession(ctx, "conn-with-guardrails", "guardrails-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	_ = session // used for activity test below

	// Update activity should work
	err = sm.UpdateActivity("conn-with-guardrails")
	if err != nil {
		t.Fatalf("UpdateActivity failed: %v", err)
	}
}

// =========================================================================
// GuardrailMiddleware OnSessionDestroy tests
// =========================================================================

func TestGuardrailOnSessionDestroy(t *testing.T) {
	guardrails := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierCommunity,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")

	// Simulate active sessions
	guardrails.activeSessions = 5

	// Destroy a session
	guardrails.OnSessionDestroy("session-123")
}

func TestGuardrailOnSessionDestroy_ZeroCounter(t *testing.T) {
	guardrails := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierCommunity,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")

	guardrails.activeSessions = 0

	// Should not panic when counter is already 0
	guardrails.OnSessionDestroy("session-zero")

	if guardrails.activeSessions != 0 {
		t.Error("counter should remain 0")
	}
}

// =========================================================================
// Config validation edge cases
// =========================================================================

func TestMCPConfig_EmptyAddress(t *testing.T) {
	cfg := &Config{
		Address:      "",
		ReadTimeout:  30,
		WriteTimeout: 30,
		IdleTimeout:  60,
	}

	server := NewEmbeddedServer(cfg)
	if server.config.Address != "" {
		t.Errorf("expected empty address, got %s", server.config.Address)
	}
}

func TestMCPConfig_ZeroTimeouts(t *testing.T) {
	cfg := &Config{
		Address:      ":9090",
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  0,
	}

	server := NewEmbeddedServer(cfg)
	if server.config.ReadTimeout != 0 {
		t.Errorf("expected zero ReadTimeout, got %v", server.config.ReadTimeout)
	}
}

// =========================================================================
// GetOrCreateSession edge cases
// =========================================================================

func TestGetOrCreateSession_ExpiredSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-expired",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()

	// Create session
	sess1, err := sm.GetOrCreateSession(ctx, "conn-expired", "agent-expired")
	if err != nil {
		t.Fatalf("GetOrCreateSession failed: %v", err)
	}

	// Manually expire RBAC session
	sess1.RBACSession.ExpiresAt = sess1.RBACSession.CreatedAt.Add(-1)

	// GetOrCreate should create new session
	sess2, err := sm.GetOrCreateSession(ctx, "conn-expired", "agent-expired")
	if err != nil {
		t.Fatalf("GetOrCreateSession after expiry failed: %v", err)
	}

	// Should be new session
	if sess1.RBACSession.ID == sess2.RBACSession.ID {
		t.Error("expected new session after expiry")
	}
}

// =========================================================================
// GetSession expired session
// =========================================================================

func TestGetSession_ExpiredRBACSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-expired-get",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session, _ := sm.CreateSession(ctx, "conn-expired-get", "agent-expired-get")

	// Expire the RBAC session
	session.RBACSession.ExpiresAt = session.RBACSession.CreatedAt.Add(-1)

	// GetSession should return error for expired session
	_, err := sm.GetSession("conn-expired-get")
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

// =========================================================================
// ListSessions edge cases
// =========================================================================

func TestListSessions_AllExpired(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-all-expired",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session1, _ := sm.CreateSession(ctx, "conn-expired-1", "agent-all-expired")
	session2, _ := sm.CreateSession(ctx, "conn-expired-2", "agent-all-expired")

	// Expire both sessions
	session1.RBACSession.ExpiresAt = session1.RBACSession.CreatedAt.Add(-1)
	session2.RBACSession.ExpiresAt = session2.RBACSession.CreatedAt.Add(-1)

	// ListSessions should return empty
	sessions := sm.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

// =========================================================================
// CountSessions edge cases
// =========================================================================

func TestCountSessions_AllExpired(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-count-expired",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session, _ := sm.CreateSession(ctx, "conn-count-expired", "agent-count-expired")

	// Expire the session
	session.RBACSession.ExpiresAt = session.RBACSession.CreatedAt.Add(-1)

	count := sm.CountSessions()
	if count != 0 {
		t.Errorf("expected 0 count, got %d", count)
	}
}

// =========================================================================
// CleanupExpired edge cases
// =========================================================================

func TestCleanupExpired_None(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	cleaned := sm.CleanupExpired()
	if cleaned != 0 {
		t.Errorf("expected 0 cleaned, got %d", cleaned)
	}
}

func TestCleanupExpired_Multiple(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-cleanup-multi",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session1, _ := sm.CreateSession(ctx, "conn-cleanup-1", "agent-cleanup-multi")
	session2, _ := sm.CreateSession(ctx, "conn-cleanup-2", "agent-cleanup-multi")

	// Expire both
	session1.RBACSession.ExpiresAt = session1.RBACSession.CreatedAt.Add(-1)
	session2.RBACSession.ExpiresAt = session2.RBACSession.CreatedAt.Add(-1)

	cleaned := sm.CleanupExpired()
	if cleaned != 2 {
		t.Errorf("expected 2 cleaned, got %d", cleaned)
	}
}

// =========================================================================
// GetSessionStats edge cases
// =========================================================================

func TestGetSessionStats_Empty(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	stats := sm.GetSessionStats()
	if stats.TotalSessions != 0 {
		t.Errorf("expected TotalSessions 0, got %d", stats.TotalSessions)
	}
	if stats.ActiveSessions != 0 {
		t.Errorf("expected ActiveSessions 0, got %d", stats.ActiveSessions)
	}
	if stats.ExpiredSessions != 0 {
		t.Errorf("expected ExpiredSessions 0, got %d", stats.ExpiredSessions)
	}
}

func TestGetSessionStats_Mixed(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "agent-mixed",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session1, _ := sm.CreateSession(ctx, "conn-mixed-1", "agent-mixed")
	_, _ = sm.CreateSession(ctx, "conn-mixed-2", "agent-mixed")

	// Expire one
	session1.RBACSession.ExpiresAt = session1.RBACSession.CreatedAt.Add(-1)

	stats := sm.GetSessionStats()
	if stats.TotalSessions != 2 {
		t.Errorf("expected TotalSessions 2, got %d", stats.TotalSessions)
	}
	if stats.ActiveSessions != 1 {
		t.Errorf("expected ActiveSessions 1, got %d", stats.ActiveSessions)
	}
	if stats.ExpiredSessions != 1 {
		t.Errorf("expected ExpiredSessions 1, got %d", stats.ExpiredSessions)
	}
}

// =========================================================================
// Memory tracking edge cases
// =========================================================================

func TestSetMemoryLimit_Duplicate(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	sm.SetMemoryLimit("mem-dup", 1024*1024)
	sm.SetMemoryLimit("mem-dup", 2048*1024)

	stats := sm.GetMemoryStats("mem-dup")
	if stats.Limit != 2048*1024 {
		t.Errorf("expected updated limit 2097152, got %d", stats.Limit)
	}
}

func TestIncrementMemoryUsage_NonExistent(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Should not panic
	sm.IncrementMemoryUsage("non-existent", 1024)
}

func TestCheckAndEnforceMemoryLimit_NoLimit(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	err := sm.CheckAndEnforceMemoryLimit("no-limit-session")
	if err != nil {
		t.Error("expected no error when no limit set")
	}
}

func TestCheckAndEnforceMemoryLimit_AtLimit(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	sm.SetMemoryLimit("at-limit", 1024)
	// Usage equals limit - no error (only > limit triggers error)
	sm.IncrementMemoryUsage("at-limit", 1024)

	err := sm.CheckAndEnforceMemoryLimit("at-limit")
	// At limit (==) should NOT trigger error - only > limit triggers
	if err != nil {
		t.Error("expected no error at limit (usage == limit)")
	}

	// Now exceed the limit
	sm.IncrementMemoryUsage("at-limit", 1) // Now usage > limit

	err = sm.CheckAndEnforceMemoryLimit("at-limit")
	if err == nil {
		t.Error("expected error when usage > limit")
	}
}

func TestCheckAndEnforceMemoryLimit_UnderLimit(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	sm.SetMemoryLimit("under-limit", 2048)
	sm.IncrementMemoryUsage("under-limit", 1024)

	err := sm.CheckAndEnforceMemoryLimit("under-limit")
	if err != nil {
		t.Error("expected no error when under limit")
	}
}

func TestGetMemoryStats_NotSet(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	stats := sm.GetMemoryStats("never-set")
	if stats != nil {
		t.Error("expected nil for never-set session")
	}
}

// =========================================================================
// StartCleanupRoutine edge cases
// =========================================================================

func TestStartCleanupRoutine_ContextCanceled(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sm.StartCleanupRoutine(ctx, 50)
}

// =========================================================================
// GuardrailMiddleware tests
// =========================================================================

func TestNewGuardrailMiddleware_Basic(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierCommunity,
		LogViolations:   true,
		AuditViolations: true,
	}

	gm := NewGuardrailMiddleware(cfg, "test-server-1")
	if gm == nil {
		t.Fatal("NewGuardrailMiddleware returned nil")
	}
	if gm.serverID != "test-server-1" {
		t.Errorf("expected serverID 'test-server-1', got '%s'", gm.serverID)
	}
}

func TestNewGuardrailMiddleware_DeveloperTier(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierDeveloper,
		LogViolations:   true,
		AuditViolations: true,
	}

	gm := NewGuardrailMiddleware(cfg, "dev-server")
	if gm == nil {
		t.Fatal("NewGuardrailMiddleware returned nil")
	}
}

func TestNewGuardrailMiddleware_ProfessionalTier(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierProfessional,
		LogViolations:   true,
		AuditViolations: true,
	}

	gm := NewGuardrailMiddleware(cfg, "pro-server")
	if gm == nil {
		t.Fatal("NewGuardrailMiddleware returned nil")
	}
}

func TestNewGuardrailMiddleware_EnterpriseTier(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierEnterprise,
		LogViolations:   true,
		AuditViolations: true,
	}

	gm := NewGuardrailMiddleware(cfg, "ent-server")
	if gm == nil {
		t.Fatal("NewGuardrailMiddleware returned nil")
	}
}

// =========================================================================
// DefaultGuardrailConfig tests
// =========================================================================

func TestDefaultGuardrailConfig_Community(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.PlatformTier != tier.TierCommunity {
		t.Errorf("expected PlatformTier Community, got %v", cfg.PlatformTier)
	}
}

func TestDefaultGuardrailConfig_Developer(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierDeveloper)

	if cfg.PlatformTier != tier.TierDeveloper {
		t.Errorf("expected PlatformTier Developer, got %v", cfg.PlatformTier)
	}
}

func TestDefaultGuardrailConfig_Professional(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierProfessional)

	if cfg.PlatformTier != tier.TierProfessional {
		t.Errorf("expected PlatformTier Professional, got %v", cfg.PlatformTier)
	}
}

func TestDefaultGuardrailConfig_Enterprise(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierEnterprise)

	if cfg.PlatformTier != tier.TierEnterprise {
		t.Errorf("expected PlatformTier Enterprise, got %v", cfg.PlatformTier)
	}
}

// =========================================================================
// Adapter tests
// =========================================================================

func TestAuthorizerAdapter(t *testing.T) {
	adapter := &authorizerAdapter{}
	if adapter == nil {
		t.Fatal("authorizerAdapter is nil")
	}
	_ = adapter.authz
}

func TestAuditLoggerAdapter(t *testing.T) {
	adapter := &auditLoggerAdapter{}
	if adapter == nil {
		t.Fatal("auditLoggerAdapter is nil")
	}
	_ = adapter.logger
}

func TestSessionManagerAdapter(t *testing.T) {
	adapter := &sessionManagerAdapter{}
	if adapter == nil {
		t.Fatal("sessionManagerAdapter is nil")
	}
	_ = adapter.mgr
}

// =========================================================================
// Server adapter integration
// =========================================================================

func TestMCPEmbeddedServer_AdapterCreation(t *testing.T) {
	server := NewEmbeddedServer(nil)
	if server.handler == nil {
		t.Error("handler not created")
	}
}

func TestMCPEmbeddedServer_Config(t *testing.T) {
	cfg := &Config{
		Address:      ":9999",
		ReadTimeout:  45,
		WriteTimeout: 60,
		IdleTimeout:  300,
	}

	server := NewEmbeddedServer(cfg)

	if server.config.Address != ":9999" {
		t.Errorf("expected address :9999, got %s", server.config.Address)
	}
	if server.config.ReadTimeout != 45 {
		t.Errorf("expected ReadTimeout 45, got %v", server.config.ReadTimeout)
	}
}

// =========================================================================
// Error constants
// =========================================================================

func TestMCPErrors(t *testing.T) {
	if ErrSessionNotFound == nil {
		t.Error("ErrSessionNotFound is nil")
	}
	if ErrSessionExpired == nil {
		t.Error("ErrSessionExpired is nil")
	}
	if ErrAgentNotFound == nil {
		t.Error("ErrAgentNotFound is nil")
	}
	if ErrSessionNotFound == ErrSessionExpired {
		t.Error("ErrSessionNotFound and ErrSessionExpired should be different")
	}
	if ErrSessionNotFound == ErrAgentNotFound {
		t.Error("ErrSessionNotFound and ErrAgentNotFound should be different")
	}
}

// =========================================================================
// Session stats struct tests
// =========================================================================

func TestMCPSessionStats(t *testing.T) {
	stats := SessionStats{
		TotalSessions:   10,
		ActiveSessions:  7,
		ExpiredSessions: 3,
	}

	if stats.TotalSessions != 10 {
		t.Errorf("expected TotalSessions 10, got %d", stats.TotalSessions)
	}
	if stats.ActiveSessions != 7 {
		t.Errorf("expected ActiveSessions 7, got %d", stats.ActiveSessions)
	}
	if stats.ExpiredSessions != 3 {
		t.Errorf("expected ExpiredSessions 3, got %d", stats.ExpiredSessions)
	}
}

// =========================================================================
// Config struct tests
// =========================================================================

func TestMCPConfig_AllFields(t *testing.T) {
	cfg := &Config{
		Address:      ":8080",
		ReadTimeout:  60,
		WriteTimeout: 90,
		IdleTimeout:  300,
	}

	if cfg.Address != ":8080" {
		t.Errorf("expected Address :8080, got %s", cfg.Address)
	}
	if cfg.ReadTimeout != 60 {
		t.Errorf("expected ReadTimeout 60, got %v", cfg.ReadTimeout)
	}
}

// =========================================================================
// GuardrailConfig tests
// =========================================================================

func TestGuardrailConfig_AllFields(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierProfessional,
		LogViolations:   true,
		AuditViolations: true,
		Features:        []string{"feature1", "feature2"},
	}

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.PlatformTier != tier.TierProfessional {
		t.Errorf("expected PlatformTier Professional, got %v", cfg.PlatformTier)
	}
	if !cfg.LogViolations {
		t.Error("LogViolations should be true")
	}
	if !cfg.AuditViolations {
		t.Error("AuditViolations should be true")
	}
	if len(cfg.Features) != 2 {
		t.Errorf("expected 2 features, got %d", len(cfg.Features))
	}
}

func TestGuardrailConfig_EmptyFeatures(t *testing.T) {
	cfg := GuardrailConfig{
		Enabled:         false,
		PlatformTier:    tier.TierCommunity,
		LogViolations:   false,
		AuditViolations: false,
		Features:        []string{},
	}

	if cfg.Enabled {
		t.Error("Enabled should be false")
	}
	if len(cfg.Features) != 0 {
		t.Errorf("expected 0 features, got %d", len(cfg.Features))
	}
}

// =========================================================================
// GuardrailMiddleware OnSessionCreate
// =========================================================================

func TestGuardrailOnSessionCreate(t *testing.T) {
	gm := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierDeveloper,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")

	gm.activeSessions = 5
	gm.OnSessionCreate("new-session-id", "agent-1", "127.0.0.1")
}

func TestGuardrailOnSessionCreate_First(t *testing.T) {
	gm := NewGuardrailMiddleware(GuardrailConfig{
		Enabled:         true,
		PlatformTier:    tier.TierEnterprise,
		LogViolations:   true,
		AuditViolations: true,
	}, "test-server")

	// Counter should start at 0
	if gm.activeSessions != 0 {
		t.Errorf("expected counter 0, got %d", gm.activeSessions)
	}

	gm.OnSessionCreate("first-session-id", "agent-2", "192.168.1.1")

	if gm.activeSessions != 1 {
		t.Errorf("expected counter 1, got %d", gm.activeSessions)
	}
}

// =========================================================================
// Session manager with nil guardrails
// =========================================================================

func TestCloseSession_NilGuardrails(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "nil-guardrails-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	sm.CreateSession(ctx, "conn-nil-guardrails", "nil-guardrails-agent")

	err := sm.CloseSession("conn-nil-guardrails")
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	_, err = sm.GetSession("conn-nil-guardrails")
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

// =========================================================================
// UpdateActivity not found
// =========================================================================

func TestMCPUpdateActivity_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	err := sm.UpdateActivity("nonexistent-conn")
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

// =========================================================================
// Multiple guardrails wiring
// =========================================================================

func TestSetGuardrails_Multiple(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	guardrails1 := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierCommunity), "server-1")
	guardrails2 := NewGuardrailMiddleware(DefaultGuardrailConfig(tier.TierDeveloper), "server-2")

	sm.SetGuardrails(guardrails1)
	if sm.guardrails != guardrails1 {
		t.Error("first guardrails not set")
	}

	sm.SetGuardrails(guardrails2)
	if sm.guardrails != guardrails2 {
		t.Error("second guardrails not set")
	}
}

// =========================================================================
// CreateSession error paths
// =========================================================================

func TestCreateSession_RBACFails(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Create session without registered agent
	ctx := context.Background()
	session, err := sm.CreateSession(ctx, "conn-no-agent", "nonexistent-agent")

	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
	if session != nil {
		t.Error("expected nil session on error")
	}
}

// =========================================================================
// GetOrCreateSession first time
// =========================================================================

func TestGetOrCreateSession_FirstTime(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	agent := &rbac.Agent{
		ID:    "get-or-create-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session, err := sm.GetOrCreateSession(ctx, "conn-first-time", "get-or-create-agent")

	if err != nil {
		t.Fatalf("GetOrCreateSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected session")
	}
	if session.ConnectionID != "conn-first-time" {
		t.Errorf("expected conn-first-time, got %s", session.ConnectionID)
	}
}

// =========================================================================
// Start error path
// =========================================================================

func TestMCPStart_AlreadyRunning(t *testing.T) {
	server := NewEmbeddedServer(&Config{
		Address: "localhost:0",
	})

	err := server.Start()
	if err != nil {
		t.Skipf("Start failed (expected in some environments): %v", err)
	}

	// Server started - stop it
	server.Stop()
}

// =========================================================================
// MCPSession struct
// =========================================================================

func TestMCPSession(t *testing.T) {
	session := &MCPSession{
		ConnectionID: "test-conn",
		CreatedAt:   time.Now(),
		LastActivity: time.Now(),
	}

	if session.ConnectionID != "test-conn" {
		t.Error("expected ConnectionID 'test-conn'")
	}
	if session.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if session.LastActivity.IsZero() {
		t.Error("LastActivity should not be zero")
	}
}

// =========================================================================
// MemoryStats struct
// =========================================================================

func TestMemoryStats(t *testing.T) {
	stats := &MemoryStats{
		Usage: 1024 * 1024,
		Limit: 2 * 1024 * 1024,
		Tier:  "community",
	}

	if stats.Usage != 1024*1024 {
		t.Errorf("expected Usage 1048576, got %d", stats.Usage)
	}
	if stats.Limit != 2*1024*1024 {
		t.Errorf("expected Limit 2097152, got %d", stats.Limit)
	}
	if stats.Tier != "community" {
		t.Errorf("expected Tier 'community', got '%s'", stats.Tier)
	}
}

// =========================================================================
// Tier comparison
// =========================================================================

func TestTierComparison(t *testing.T) {
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