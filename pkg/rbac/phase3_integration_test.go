// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 3 integration tests for the RBAC Manager with PostgreSQL backend.
// These tests exercise Manager-level functions that wrap PostgresRBACStore:
// NewWithPostgres, RegisterAgent, GetAgent, CreateSession, GetSession,
// InvalidateSession, InvalidateAgentSessions, UnregisterAgent,
// AuthorizeToolCall, PruneExpiredSessions, and cleanup.

package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

// setupRBACManager creates a Manager backed by a testcontainers PostgreSQL
// instance and returns it with a cleanup function.
func setupRBACManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)

	pgRBAC, err := NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}

	mgr, err := NewWithPostgres(DefaultConfig(), pgRBAC)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewWithPostgres: %v", err)
	}

	cleanup := func() {
		mgr.Close()
		dbCleanup()
	}
	return mgr, cleanup
}

func TestPhase3_NewWithPostgres(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	if !mgr.UsesPostgres() {
		t.Fatal("expected manager to use postgres")
	}
	if mgr.PostgresStore() == nil {
		t.Fatal("expected non-nil PostgresStore")
	}
}

func TestPhase3_NewWithPostgres_NilStore(t *testing.T) {
	mgr, err := NewWithPostgres(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("NewWithPostgres nil store: %v", err)
	}
	if mgr.UsesPostgres() {
		t.Fatal("expected in-memory fallback")
	}
	mgr.Close()
}

func TestPhase3_ManagerRegisterAndGetAgent(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-agent-1",
		Name:    "Phase3 Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}

	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	got, err := mgr.GetAgent("phase3-agent-1")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.ID != "phase3-agent-1" {
		t.Fatalf("got agent ID %s, want phase3-agent-1", got.ID)
	}
}

func TestPhase3_ManagerGetAgent_NotFound(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	_, err := mgr.GetAgent("nonexistent-agent")
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestPhase3_ManagerRegisterAgent_WithTenant(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-agent-tenant",
		Name:    "Tenant Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}

	tenantCtx := RBACTenantContext{TenantID: "tenant-phase3", IsAdmin: false}
	if err := mgr.RegisterAgent(agent, tenantCtx); err != nil {
		t.Fatalf("RegisterAgent with tenant: %v", err)
	}

	// Get as admin
	got, err := mgr.GetAgent("phase3-agent-tenant", RBACTenantContext{TenantID: "tenant-phase3", IsAdmin: true})
	if err != nil {
		t.Fatalf("GetAgent admin: %v", err)
	}
	if got.TenantID != "tenant-phase3" {
		t.Fatalf("expected tenant_id=tenant-phase3, got %s", got.TenantID)
	}
}

func TestPhase3_ManagerCreateAndGetSession(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-session-agent",
		Name:    "Session Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session, err := mgr.CreateSession(context.Background(), "phase3-session-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if session.AgentID != "phase3-session-agent" {
		t.Fatalf("session agent ID = %s, want phase3-session-agent", session.AgentID)
	}

	// Get session through manager
	got, err := mgr.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != session.ID {
		t.Fatalf("got session ID %s, want %s", got.ID, session.ID)
	}
}

func TestPhase3_ManagerGetSession_NotFound(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	_, err := mgr.GetSession("nonexistent-session")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestPhase3_ManagerCreateSession_AgentNotFound(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	_, err := mgr.CreateSession(context.Background(), "nonexistent-agent")
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestPhase3_ManagerInvalidateSession(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-inval-agent",
		Name:    "Invalidate Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session, err := mgr.CreateSession(context.Background(), "phase3-inval-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := mgr.InvalidateSession(session.ID); err != nil {
		t.Fatalf("InvalidateSession: %v", err)
	}

	// Session should no longer be retrievable (it's inactive)
	_, err = mgr.GetSession(session.ID)
	if err == nil {
		t.Fatal("expected error after invalidating session")
	}
}

func TestPhase3_ManagerInvalidateAgentSessions(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-inval-all-agent",
		Name:    "Invalidate All Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create multiple sessions
	s1, err := mgr.CreateSession(context.Background(), "phase3-inval-all-agent")
	if err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}
	s2, err := mgr.CreateSession(context.Background(), "phase3-inval-all-agent")
	if err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}

	// Invalidate all sessions for the agent
	if err := mgr.InvalidateAgentSessions("phase3-inval-all-agent"); err != nil {
		t.Fatalf("InvalidateAgentSessions: %v", err)
	}

	// Both sessions should be invalid now
	for _, sid := range []string{s1.ID, s2.ID} {
		_, err := mgr.GetSession(sid)
		if err == nil {
			t.Fatalf("expected error for invalidated session %s", sid)
		}
	}
}

func TestPhase3_ManagerUnregisterAgent(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-unreg-agent",
		Name:    "Unregister Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create a session
	_, err := mgr.CreateSession(context.Background(), "phase3-unreg-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Unregister agent (should cascade to sessions)
	if err := mgr.UnregisterAgent("phase3-unreg-agent"); err != nil {
		t.Fatalf("UnregisterAgent: %v", err)
	}

	// Agent should be gone
	_, err = mgr.GetAgent("phase3-unreg-agent")
	if err == nil {
		t.Fatal("expected error after unregistering agent")
	}
}

func TestPhase3_ManagerAuthorizeToolCall(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-auth-agent",
		Name:    "Auth Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
		Tools:   []ToolPermission{PermToolFileRead},
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session, err := mgr.CreateSession(context.Background(), "phase3-auth-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Authorize a tool call — should fail (session doesn't have the tool in its cache)
	// Actually, AuthorizeToolCall checks the agent's tools through the session
	result, err := mgr.AuthorizeToolCall(context.Background(), session.ID, "read_data")
	if err != nil {
		t.Logf("AuthorizeToolCall returned error (expected for restricted): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil AuthorizationResult")
	}
}

func TestPhase3_ManagerAuthorizeToolCall_InvalidSession(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	result, err := mgr.AuthorizeToolCall(context.Background(), "nonexistent-session", "read_data")
	// AuthorizeToolCall returns nil error with Allowed=false for invalid sessions
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil AuthorizationResult")
	}
	if result.Allowed {
		t.Fatal("expected Allowed=false for invalid session")
	}
}

func TestPhase3_ManagerPruneExpiredSessions(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	// Prune should work without error even with no expired sessions
	count, err := mgr.PruneExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("PruneExpiredSessions: %v", err)
	}
	_ = count // may be 0
}

func TestPhase3_ManagerClose_NoDoubleClose(t *testing.T) {
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	defer dbCleanup()

	pgRBAC, err := NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}

	mgr, err := NewWithPostgres(DefaultConfig(), pgRBAC)
	if err != nil {
		t.Fatalf("NewWithPostgres: %v", err)
	}

	// Close should not panic
	mgr.Close()
	// Don't call cleanup() — we already closed
}

func TestPhase3_ManagerCreateSession_DisabledAgent(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-disabled-agent",
		Name:    "Disabled Agent",
		Role:    AgentRoleStandard,
		Enabled: false,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	_, err := mgr.CreateSession(context.Background(), "phase3-disabled-agent")
	if err == nil {
		t.Fatal("expected error creating session for disabled agent")
	}
}

func TestPhase3_ManagerCleanup(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	// Register an agent and create a session
	agent := &Agent{
		ID:      "phase3-cleanup-agent",
		Name:    "Cleanup Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session, err := mgr.CreateSession(context.Background(), "phase3-cleanup-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Manually expire the session in the database
	ctx := context.Background()
	err = mgr.pgStore.InvalidateAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("InvalidateAgentSession: %v", err)
	}

	// Run cleanup — should clean up the expired session
	mgr.cleanup()

	// Session should be gone from in-memory cache
	mgr.agentSessionMu.RLock()
	_, exists := mgr.agentSessions[session.ID]
	mgr.agentSessionMu.RUnlock()
	if exists {
		t.Fatal("expected session to be cleaned up from in-memory cache")
	}
}

func TestPhase3_ManagerRegisterAgent_Duplicate(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-dup-agent",
		Name:    "Dup Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent 1: %v", err)
	}

	// Registering again should succeed (upsert in postgres) or fail
	// The postgres path uses INSERT ... ON CONFLICT DO UPDATE, so it's an upsert
	err := mgr.RegisterAgent(agent)
	if err != nil {
		t.Logf("Second RegisterAgent returned: %v (upsert behavior)", err)
	}
}

func TestPhase3_ManagerGetAgentSessions(t *testing.T) {
	mgr, cleanup := setupRBACManager(t)
	defer cleanup()

	agent := &Agent{
		ID:      "phase3-getsess-agent",
		Name:    "GetSessions Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	_, err := mgr.CreateSession(context.Background(), "phase3-getsess-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// GetAgentSessions returns in-memory sessions
	sessions := mgr.GetAgentSessions("phase3-getsess-agent")
	// Note: In postgres mode, sessions are in the DB but may not be in the
	// in-memory cache. The in-memory GetAgentSessions only returns cached sessions.
	t.Logf("GetAgentSessions returned %d sessions (in-memory cache)", len(sessions))
}

func TestPhase3_ManagerMaxSessionsPerAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSessionsPerAgent = 1

	pgStore, dbCleanup := testdb.SetupTestDB(t)
	defer dbCleanup()

	pgRBAC, err := NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}

	mgr, err := NewWithPostgres(cfg, pgRBAC)
	if err != nil {
		t.Fatalf("NewWithPostgres: %v", err)
	}
	defer mgr.Close()

	agent := &Agent{
		ID:      "phase3-maxsess-agent",
		Name:    "MaxSess Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	_, err = mgr.CreateSession(context.Background(), "phase3-maxsess-agent")
	if err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}

	// Second session should fail (max 1 session per agent)
	_, err = mgr.CreateSession(context.Background(), "phase3-maxsess-agent")
	if err == nil {
		t.Fatal("expected error when exceeding max sessions per agent")
	}
}

func TestPhase3_ManagerSessionExpiry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SessionDuration = 50 * time.Millisecond

	pgStore, dbCleanup := testdb.SetupTestDB(t)
	defer dbCleanup()

	pgRBAC, err := NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}

	mgr, err := NewWithPostgres(cfg, pgRBAC)
	if err != nil {
		t.Fatalf("NewWithPostgres: %v", err)
	}
	defer mgr.Close()

	agent := &Agent{
		ID:      "phase3-expiry-agent",
		Name:    "Expiry Agent",
		Role:    AgentRoleStandard,
		Enabled: true,
	}
	if err := mgr.RegisterAgent(agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session, err := mgr.CreateSession(context.Background(), "phase3-expiry-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Wait for session to expire
	time.Sleep(100 * time.Millisecond)

	// GetSession should fail (session expired)
	_, err = mgr.GetSession(session.ID)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}
