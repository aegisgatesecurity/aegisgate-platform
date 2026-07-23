// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL RBAC Store Integration Tests
// =========================================================================
//
// Integration tests that verify PostgresRBACStore persists agent registrations,
// agent sessions, and user sessions correctly against a real PostgreSQL
// database spun up via testcontainers.
//
// Run:
//
//	go test -v -tags=integration ./pkg/rbac/
//
// Requires Docker for testcontainers.
// =========================================================================

//go:build integration

package rbac

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

// =====================================================================
// Helpers
// =====================================================================

// setupStore creates a PostgresRBACStore backed by an ephemeral
// testcontainers PostgreSQL instance. Returns the store and a cleanup
// function that must be deferred by the caller.
func setupStore(t *testing.T) (*PostgresRBACStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	store, err := NewPostgresRBACStore(pgStore, nil)
	if err != nil {
		cleanup()
		t.Fatalf("NewPostgresRBACStore: %v", err)
	}
	return store, func() {
		store.Close()
		cleanup()
	}
}

// newTestAgent builds a realistic Agent with a unique ID derived from the
// supplied suffix.
func newTestAgent(suffix string) *Agent {
	return &Agent{
		ID:          fmt.Sprintf("agent-%s", suffix),
		Name:        fmt.Sprintf("Test Agent %s", suffix),
		Description: fmt.Sprintf("Agent created for integration testing (%s)", suffix),
		Role:        AgentRoleStandard,
		Tools:       []ToolPermission{PermToolFileRead, PermToolCodeSearch},
		Tags: map[string]string{
			"environment": "test",
			"source":      "integration",
		},
		Metadata: map[string]interface{}{
			"version": "1.0.0",
			"team":    "platform",
		},
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// newTestAgentSession builds a realistic AgentSession with a unique ID.
func newTestAgentSession(agentID, suffix string) *AgentSession {
	now := time.Now().UTC()
	s := &AgentSession{
		ID:          fmt.Sprintf("as-%s", suffix),
		AgentID:     agentID,
		IPAddress:   "10.0.0.42",
		ContextHash: "sha256:abc123def456",
		Tags: map[string]string{
			"origin":  "integration-test",
			"channel": "mcp",
		},
		Active:    true,
		CreatedAt: now,
	}
	s.ExpiresAt = now.Add(1 * time.Hour)
	s.SetLastActivity(now)
	return s
}

// newTestUserSession builds a realistic UserSession with a unique ID.
func newTestUserSession(suffix string) *UserSession {
	now := time.Now().UTC()
	s := &UserSession{
		ID:        fmt.Sprintf("us-%s", suffix),
		UserID:    fmt.Sprintf("user-%s", suffix),
		IPAddress: "192.168.1.100",
		Tags: map[string]string{
			"auth_method": "oidc",
		},
		Active:    true,
		CreatedAt: now,
		User: &User{
			ID:   fmt.Sprintf("user-%s", suffix),
			Role: UserRoleAdmin,
			Permissions: []Permission{
				{Resource: ResourceDashboard, Action: ActionRead},
				{Resource: ResourceAudit, Action: ActionManage},
			},
		},
	}
	s.ExpiresAt = now.Add(2 * time.Hour)
	s.SetLastActivity(now)
	return s
}

// =====================================================================
// Agent CRUD Tests
// =====================================================================

func TestIntegration_RegisterAndGetAgent(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("crud-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	got, err := store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgent returned nil — expected agent")
	}

	if got.ID != agent.ID {
		t.Errorf("ID = %q, want %q", got.ID, agent.ID)
	}
	if got.Name != agent.Name {
		t.Errorf("Name = %q, want %q", got.Name, agent.Name)
	}
	if got.Role != agent.Role {
		t.Errorf("Role = %q, want %q", got.Role, agent.Role)
	}
	if got.Enabled != agent.Enabled {
		t.Errorf("Enabled = %v, want %v", got.Enabled, agent.Enabled)
	}
	if len(got.Tools) != len(agent.Tools) {
		t.Errorf("Tools length = %d, want %d", len(got.Tools), len(agent.Tools))
	}
	if got.Tags["environment"] != "test" {
		t.Errorf("Tags[environment] = %q, want %q", got.Tags["environment"], "test")
	}
}

func TestIntegration_RegisterAgent_Upsert(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("upsert-1")
	agent.Role = AgentRoleRestricted
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent (initial): %v", err)
	}

	// Re-register with updated fields
	agent.Role = AgentRoleAdmin
	agent.Name = "Updated Upsert Agent"
	agent.Enabled = true
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent (upsert): %v", err)
	}

	got, err := store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Role != AgentRoleAdmin {
		t.Errorf("Role after upsert = %q, want %q", got.Role, AgentRoleAdmin)
	}
	if got.Name != "Updated Upsert Agent" {
		t.Errorf("Name after upsert = %q, want %q", got.Name, "Updated Upsert Agent")
	}
}

func TestIntegration_RegisterAgent_WithTenantContext(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("tenant-1")
	tenantCtx := RBACTenantContext{TenantID: "tenant-acme", IsAdmin: false}
	if err := store.RegisterAgent(ctx, agent, tenantCtx); err != nil {
		t.Fatalf("RegisterAgent with tenant: %v", err)
	}

	// Retrieve as admin — should find it regardless of tenant
	got, err := store.GetAgent(ctx, agent.ID, RBACTenantContext{TenantID: "tenant-other", IsAdmin: true})
	if err != nil {
		t.Fatalf("GetAgent as admin: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgent (admin) returned nil")
	}

	// Retrieve with matching tenant — should find it
	got, err = store.GetAgent(ctx, agent.ID, RBACTenantContext{TenantID: "tenant-acme", IsAdmin: false})
	if err != nil {
		t.Fatalf("GetAgent with matching tenant: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgent (matching tenant) returned nil")
	}
}

func TestIntegration_UpdateAgent(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("update-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	updates := &AgentUpdates{
		Name:        "Updated Agent Name",
		Description: "Updated description",
		Role:        AgentRolePrivileged,
	}

	if err := store.UpdateAgent(ctx, agent.ID, updates); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}

	got, err := store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent after update: %v", err)
	}
	if got.Name != "Updated Agent Name" {
		t.Errorf("Name after update = %q, want %q", got.Name, "Updated Agent Name")
	}
	if got.Description != "Updated description" {
		t.Errorf("Description after update = %q, want %q", got.Description, "Updated description")
	}
	if got.Role != AgentRolePrivileged {
		t.Errorf("Role after update = %q, want %q", got.Role, AgentRolePrivileged)
	}
}

func TestIntegration_UpdateAgent_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.UpdateAgent(ctx, "nonexistent-agent-id", &AgentUpdates{Name: "x"})
	if err == nil {
		t.Fatal("UpdateAgent on nonexistent agent should return error")
	}
}

func TestIntegration_UnregisterAgent(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("unreg-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	if err := store.UnregisterAgent(ctx, agent.ID); err != nil {
		t.Fatalf("UnregisterAgent: %v", err)
	}

	got, err := store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent after unregister: %v", err)
	}
	if got != nil {
		t.Error("GetAgent after unregister should return nil")
	}
}

func TestIntegration_UnregisterAgent_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.UnregisterAgent(ctx, "ghost-agent")
	if err == nil {
		t.Fatal("UnregisterAgent on nonexistent agent should return error")
	}
}

func TestIntegration_ListAgents(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		agent := newTestAgent(fmt.Sprintf("list-%d", i))
		if err := store.RegisterAgent(ctx, agent); err != nil {
			t.Fatalf("RegisterAgent list-%d: %v", i, err)
		}
	}

	agents, err := store.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) < 3 {
		t.Errorf("ListAgents returned %d agents, want at least 3", len(agents))
	}
}

func TestIntegration_ListAgents_TenantFilter(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Register agent in tenant-alpha
	agentA := newTestAgent("tenant-alpha-1")
	if err := store.RegisterAgent(ctx, agentA, RBACTenantContext{TenantID: "tenant-alpha"}); err != nil {
		t.Fatalf("RegisterAgent tenant-alpha: %v", err)
	}

	// Register agent in tenant-beta
	agentB := newTestAgent("tenant-beta-1")
	if err := store.RegisterAgent(ctx, agentB, RBACTenantContext{TenantID: "tenant-beta"}); err != nil {
		t.Fatalf("RegisterAgent tenant-beta: %v", err)
	}

	// List as tenant-alpha — should only see alpha's agent
	alphaAgents, err := store.ListAgents(ctx, RBACTenantContext{TenantID: "tenant-alpha", IsAdmin: false})
	if err != nil {
		t.Fatalf("ListAgents (tenant-alpha): %v", err)
	}
	if len(alphaAgents) != 1 {
		t.Errorf("tenant-alpha agents = %d, want 1", len(alphaAgents))
	}

	// List as admin — should see all agents
	allAgents, err := store.ListAgents(ctx, RBACTenantContext{IsAdmin: true})
	if err != nil {
		t.Fatalf("ListAgents (admin): %v", err)
	}
	if len(allAgents) < 2 {
		t.Errorf("admin agents = %d, want at least 2", len(allAgents))
	}
}

// =====================================================================
// Agent Session Tests
// =====================================================================

func TestIntegration_CreateAndGetAgentSession(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("sess-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session := newTestAgentSession(agent.ID, "sess-1")
	if err := store.CreateAgentSession(ctx, session); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	got, err := store.GetAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetAgentSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgentSession returned nil")
	}
	if got.ID != session.ID {
		t.Errorf("Session ID = %q, want %q", got.ID, session.ID)
	}
	if got.AgentID != agent.ID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, agent.ID)
	}
	if got.IPAddress != session.IPAddress {
		t.Errorf("IPAddress = %q, want %q", got.IPAddress, session.IPAddress)
	}
	if got.ContextHash != session.ContextHash {
		t.Errorf("ContextHash = %q, want %q", got.ContextHash, session.ContextHash)
	}
	if !got.Active {
		t.Error("Session should be active")
	}
	if got.Tags["origin"] != "integration-test" {
		t.Errorf("Tags[origin] = %q, want %q", got.Tags["origin"], "integration-test")
	}
}

func TestIntegration_CreateAgentSession_WithTenantContext(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("sess-tenant-1")
	if err := store.RegisterAgent(ctx, agent, RBACTenantContext{TenantID: "tenant-gamma"}); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session := newTestAgentSession(agent.ID, "sess-tenant-1")
	if err := store.CreateAgentSession(ctx, session, RBACTenantContext{TenantID: "tenant-gamma"}); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	// Retrieve as admin
	got, err := store.GetAgentSession(ctx, session.ID, RBACTenantContext{IsAdmin: true})
	if err != nil {
		t.Fatalf("GetAgentSession (admin): %v", err)
	}
	if got == nil {
		t.Fatal("GetAgentSession (admin) returned nil")
	}
}

func TestIntegration_RefreshAgentSession(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("refresh-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session := newTestAgentSession(agent.ID, "refresh-1")
	if err := store.CreateAgentSession(ctx, session); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	// Refresh by 30 minutes
	if err := store.RefreshAgentSession(ctx, session.ID, 30*time.Minute); err != nil {
		t.Fatalf("RefreshAgentSession: %v", err)
	}

	got, err := store.GetAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetAgentSession after refresh: %v", err)
	}
	if got == nil {
		t.Fatal("GetAgentSession after refresh returned nil")
	}
	// The refreshed session should still be valid (not expired)
	if !got.IsValid() {
		t.Error("Refreshed session should be valid")
	}
}

func TestIntegration_RefreshAgentSession_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	err := store.RefreshAgentSession(ctx, "nonexistent-session-id", time.Hour)
	if err == nil {
		t.Fatal("RefreshAgentSession on nonexistent session should return error")
	}
}

func TestIntegration_InvalidateAgentSession(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("inval-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	session := newTestAgentSession(agent.ID, "inval-1")
	if err := store.CreateAgentSession(ctx, session); err != nil {
		t.Fatalf("CreateAgentSession: %v", err)
	}

	if err := store.InvalidateAgentSession(ctx, session.ID); err != nil {
		t.Fatalf("InvalidateAgentSession: %v", err)
	}

	// Invalidated sessions should not be returned by GetAgentSession
	// (it filters on active = TRUE AND expires_at > NOW())
	got, err := store.GetAgentSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetAgentSession after invalidation: %v", err)
	}
	if got != nil {
		t.Error("GetAgentSession should return nil for invalidated session")
	}
}

func TestIntegration_InvalidateAgentSessions(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("inval-multi-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create multiple sessions for the same agent
	for i := 0; i < 3; i++ {
		session := newTestAgentSession(agent.ID, fmt.Sprintf("inval-multi-1-%d", i))
		if err := store.CreateAgentSession(ctx, session); err != nil {
			t.Fatalf("CreateAgentSession %d: %v", i, err)
		}
	}

	count, err := store.InvalidateAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("InvalidateAgentSessions: %v", err)
	}
	if count != 3 {
		t.Errorf("InvalidateAgentSessions count = %d, want 3", count)
	}

	// All sessions should now be inactive
	sessions, err := store.GetAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgentSessions after invalidation: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("GetAgentSessions after invalidation = %d, want 0", len(sessions))
	}
}

func TestIntegration_GetAgentSessions(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("getsess-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	for i := 0; i < 2; i++ {
		session := newTestAgentSession(agent.ID, fmt.Sprintf("getsess-1-%d", i))
		if err := store.CreateAgentSession(ctx, session); err != nil {
			t.Fatalf("CreateAgentSession %d: %v", i, err)
		}
	}

	sessions, err := store.GetAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgentSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("GetAgentSessions count = %d, want 2", len(sessions))
	}

	for _, s := range sessions {
		if s.AgentID != agent.ID {
			t.Errorf("Session AgentID = %q, want %q", s.AgentID, agent.ID)
		}
	}
}

// =====================================================================
// User Session Tests
// =====================================================================

func TestIntegration_CreateAndGetUserSession(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	session := newTestUserSession("user-1")
	if err := store.CreateUserSession(ctx, session); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}

	got, err := store.GetUserSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetUserSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetUserSession returned nil")
	}
	if got.ID != session.ID {
		t.Errorf("Session ID = %q, want %q", got.ID, session.ID)
	}
	if got.UserID != session.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, session.UserID)
	}
	if got.IPAddress != session.IPAddress {
		t.Errorf("IPAddress = %q, want %q", got.IPAddress, session.IPAddress)
	}
	if !got.Active {
		t.Error("Session should be active")
	}
	if got.User == nil {
		t.Fatal("User should not be nil")
	}
	if got.User.Role != UserRoleAdmin {
		t.Errorf("User Role = %q, want %q", got.User.Role, UserRoleAdmin)
	}
	if len(got.User.Permissions) != 2 {
		t.Errorf("User Permissions length = %d, want 2", len(got.User.Permissions))
	}
}

func TestIntegration_InvalidateUserSession(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	session := newTestUserSession("user-inval-1")
	if err := store.CreateUserSession(ctx, session); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}

	if err := store.InvalidateUserSession(ctx, session.ID); err != nil {
		t.Fatalf("InvalidateUserSession: %v", err)
	}

	got, err := store.GetUserSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetUserSession after invalidation: %v", err)
	}
	if got != nil {
		t.Error("GetUserSession should return nil for invalidated session")
	}
}

func TestIntegration_GetUserSession_Expired(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create a session that is already expired
	session := newTestUserSession("user-exp-1")
	session.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour) // expired 1 hour ago
	if err := store.CreateUserSession(ctx, session); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}

	// GetUserSession filters on expires_at > NOW(), so expired sessions return nil
	got, err := store.GetUserSession(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetUserSession for expired: %v", err)
	}
	if got != nil {
		t.Error("GetUserSession should return nil for expired session")
	}
}

// =====================================================================
// Count Tests
// =====================================================================

func TestIntegration_CountAgents(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	// Count enabled agents before registration
	initialCount, err := store.CountAgents(ctx)
	if err != nil {
		t.Fatalf("CountAgents (initial): %v", err)
	}

	for i := 0; i < 3; i++ {
		agent := newTestAgent(fmt.Sprintf("count-%d", i))
		agent.Enabled = true
		if err := store.RegisterAgent(ctx, agent); err != nil {
			t.Fatalf("RegisterAgent count-%d: %v", i, err)
		}
	}

	count, err := store.CountAgents(ctx)
	if err != nil {
		t.Fatalf("CountAgents: %v", err)
	}
	if count < initialCount+3 {
		t.Errorf("CountAgents = %d, want at least %d", count, initialCount+3)
	}

	// Register a disabled agent — should not be counted
	disabledAgent := newTestAgent("count-disabled")
	disabledAgent.Enabled = false
	if err := store.RegisterAgent(ctx, disabledAgent); err != nil {
		t.Fatalf("RegisterAgent (disabled): %v", err)
	}

	newCount, err := store.CountAgents(ctx)
	if err != nil {
		t.Fatalf("CountAgents after disabled: %v", err)
	}
	if newCount != count {
		t.Errorf("CountAgents after disabled = %d, want %d (disabled should not be counted)", newCount, count)
	}
}

func TestIntegration_CountActiveSessions(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("cnt-sess-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	for i := 0; i < 2; i++ {
		session := newTestAgentSession(agent.ID, fmt.Sprintf("cnt-sess-1-%d", i))
		if err := store.CreateAgentSession(ctx, session); err != nil {
			t.Fatalf("CreateAgentSession %d: %v", i, err)
		}
	}

	count, err := store.CountActiveSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("CountActiveSessions: %v", err)
	}
	if count != 2 {
		t.Errorf("CountActiveSessions = %d, want 2", count)
	}

	// Invalidate one session
	sessions, err := store.GetAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgentSessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("GetAgentSessions returned no sessions")
	}
	if err := store.InvalidateAgentSession(ctx, sessions[0].ID); err != nil {
		t.Fatalf("InvalidateAgentSession: %v", err)
	}

	count, err = store.CountActiveSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("CountActiveSessions after invalidation: %v", err)
	}
	if count != 1 {
		t.Errorf("CountActiveSessions after invalidation = %d, want 1", count)
	}
}

// =====================================================================
// Prune Expired Sessions Test
// =====================================================================

func TestIntegration_PruneExpiredSessions(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("prune-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create an already-expired agent session
	expiredSession := newTestAgentSession(agent.ID, "prune-exp-1")
	expiredSession.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	if err := store.CreateAgentSession(ctx, expiredSession); err != nil {
		t.Fatalf("CreateAgentSession (expired): %v", err)
	}

	// Create an already-expired user session
	expiredUserSession := newTestUserSession("prune-user-exp-1")
	expiredUserSession.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	if err := store.CreateUserSession(ctx, expiredUserSession); err != nil {
		t.Fatalf("CreateUserSession (expired): %v", err)
	}

	// Create an active session that should NOT be pruned
	activeSession := newTestAgentSession(agent.ID, "prune-active-1")
	if err := store.CreateAgentSession(ctx, activeSession); err != nil {
		t.Fatalf("CreateAgentSession (active): %v", err)
	}

	pruned, err := store.PruneExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredSessions: %v", err)
	}
	if pruned < 2 {
		t.Errorf("PruneExpiredSessions pruned %d sessions, want at least 2", pruned)
	}

	// Active session should still be retrievable
	got, err := store.GetAgentSession(ctx, activeSession.ID)
	if err != nil {
		t.Fatalf("GetAgentSession after prune: %v", err)
	}
	if got == nil {
		t.Error("Active session should not have been pruned")
	}
}

// =====================================================================
// Cross-Method Integration Tests
// =====================================================================

func TestIntegration_AgentLifecycle_RegisterSessionsUnregister(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	agent := newTestAgent("lifecycle-1")
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	// Create sessions
	for i := 0; i < 3; i++ {
		session := newTestAgentSession(agent.ID, fmt.Sprintf("lifecycle-1-%d", i))
		if err := store.CreateAgentSession(ctx, session); err != nil {
			t.Fatalf("CreateAgentSession %d: %v", i, err)
		}
	}

	// Verify agent and sessions
	got, err := store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got == nil {
		t.Fatal("Agent should exist")
	}

	sessions, err := store.GetAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgentSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("Session count = %d, want 3", len(sessions))
	}

	// Unregister agent cascades to sessions
	if err := store.UnregisterAgent(ctx, agent.ID); err != nil {
		t.Fatalf("UnregisterAgent: %v", err)
	}

	got, err = store.GetAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgent after unregister: %v", err)
	}
	if got != nil {
		t.Error("Agent should be deleted after unregister")
	}

	// Cascaded: sessions for deleted agent should be gone
	sessions, err = store.GetAgentSessions(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetAgentSessions after unregister: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("Session count after agent unregister = %d, want 0 (cascade)", len(sessions))
	}
}

func TestIntegration_NilAgentAndSessionValidation(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.RegisterAgent(ctx, nil); err == nil {
		t.Error("RegisterAgent(nil) should return error")
	}
	if err := store.CreateAgentSession(ctx, nil); err == nil {
		t.Error("CreateAgentSession(nil) should return error")
	}
	if err := store.CreateUserSession(ctx, nil); err == nil {
		t.Error("CreateUserSession(nil) should return error")
	}
}

func TestIntegration_GetAgent_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetAgent(ctx, "nonexistent-agent")
	if err != nil {
		t.Fatalf("GetAgent for nonexistent: %v", err)
	}
	if got != nil {
		t.Error("GetAgent should return nil for nonexistent agent")
	}
}

func TestIntegration_GetAgentSession_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetAgentSession(ctx, "nonexistent-session")
	if err != nil {
		t.Fatalf("GetAgentSession for nonexistent: %v", err)
	}
	if got != nil {
		t.Error("GetAgentSession should return nil for nonexistent session")
	}
}

func TestIntegration_GetUserSession_NotFound(t *testing.T) {
	store, cleanup := setupStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetUserSession(ctx, "nonexistent-user-session")
	if err != nil {
		t.Fatalf("GetUserSession for nonexistent: %v", err)
	}
	if got != nil {
		t.Error("GetUserSession should return nil for nonexistent session")
	}
}
