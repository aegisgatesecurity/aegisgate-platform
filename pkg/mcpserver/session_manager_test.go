// SPDX-License-Identifier: Apache-2.0
package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

func TestNewConnectionSessionManager(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	if sm == nil {
		t.Fatal("NewConnectionSessionManager returned nil")
	}
	if sm.manager != rbacMgr {
		t.Error("manager not set correctly")
	}
	if sm.conns == nil {
		t.Error("conns map not initialized")
	}
}

func TestCreateSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register an agent first
	agent := &rbac.Agent{
		ID:   "test-agent",
		Role: rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{
			rbac.PermToolFileRead,
			rbac.PermToolFileWrite,
		},
	}
	err := rbacMgr.RegisterAgent(agent)
	if err != nil {
		t.Fatalf("Failed to register agent: %v", err)
	}

	ctx := context.Background()
	session, err := sm.CreateSession(ctx, "conn-1", "test-agent")

	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("CreateSession returned nil session")
	}
	if session.ConnectionID != "conn-1" {
		t.Errorf("ConnectionID = %v, want conn-1", session.ConnectionID)
	}
	if session.Agent == nil {
		t.Error("Agent is nil")
	}
	if session.RBACSession == nil {
		t.Error("RBACSession is nil")
	}
	if session.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if session.LastActivity.IsZero() {
		t.Error("LastActivity is zero")
	}
}

func TestCreateSession_AgentNotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	ctx := context.Background()
	session, err := sm.CreateSession(ctx, "conn-1", "nonexistent-agent")

	if err == nil {
		t.Error("Expected error for nonexistent agent, got nil")
	}
	if session != nil {
		t.Error("Expected nil session on error")
	}
}

func TestGetSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent and create session
	agent := &rbac.Agent{
		ID:    "test-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	_, err := sm.CreateSession(ctx, "conn-1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get the session
	session, err := sm.GetSession("conn-1")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("GetSession returned nil")
	}
	if session.ConnectionID != "conn-1" {
		t.Errorf("ConnectionID = %v, want conn-1", session.ConnectionID)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	session, err := sm.GetSession("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
	if session != nil {
		t.Error("Expected nil session on not found")
	}
	if err != ErrSessionNotFound {
		t.Errorf("Error = %v, want ErrSessionNotFound", err)
	}
}

func TestGetOrCreateSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent
	agent := &rbac.Agent{
		ID:    "test-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()

	// Create new session
	session1, err := sm.GetOrCreateSession(ctx, "conn-1", "test-agent")
	if err != nil {
		t.Fatalf("GetOrCreateSession failed: %v", err)
	}

	// Get existing session
	session2, err := sm.GetOrCreateSession(ctx, "conn-1", "test-agent")
	if err != nil {
		t.Fatalf("GetOrCreateSession failed: %v", err)
	}

	if session1.RBACSession.ID != session2.RBACSession.ID {
		t.Error("GetOrCreateSession created duplicate sessions")
	}
}

func TestUpdateActivity(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent and create session
	agent := &rbac.Agent{
		ID:    "test-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	_, err := sm.CreateSession(ctx, "conn-1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get initial activity time
	session, _ := sm.GetSession("conn-1")
	initialActivity := session.LastActivity

	// Wait a bit and update
	time.Sleep(10 * time.Millisecond)
	err = sm.UpdateActivity("conn-1")
	if err != nil {
		t.Fatalf("UpdateActivity failed: %v", err)
	}

	// Check activity updated
	session, _ = sm.GetSession("conn-1")
	if !session.LastActivity.After(initialActivity) {
		t.Error("LastActivity not updated")
	}
}

func TestUpdateActivity_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	err := sm.UpdateActivity("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
	if err != ErrSessionNotFound {
		t.Errorf("Error = %v, want ErrSessionNotFound", err)
	}
}

func TestCloseSession(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent and create session
	agent := &rbac.Agent{
		ID:    "test-agent",
		Role:  rbac.AgentRoleStandard,
		Tools: []rbac.ToolPermission{rbac.PermToolFileRead},
	}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	_, err := sm.CreateSession(ctx, "conn-1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Close the session
	err = sm.CloseSession("conn-1")
	if err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	// Verify session is gone
	_, err = sm.GetSession("conn-1")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after close, got %v", err)
	}
}

func TestCloseSession_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	err := sm.CloseSession("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
	if err != ErrSessionNotFound {
		t.Errorf("Error = %v, want ErrSessionNotFound", err)
	}
}

func TestListSessions(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agents
	agent1 := &rbac.Agent{ID: "agent-1", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	agent2 := &rbac.Agent{ID: "agent-2", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	rbacMgr.RegisterAgent(agent1)
	rbacMgr.RegisterAgent(agent2)

	ctx := context.Background()
	sm.CreateSession(ctx, "conn-1", "agent-1")
	sm.CreateSession(ctx, "conn-2", "agent-2")

	sessions := sm.ListSessions()
	if len(sessions) != 2 {
		t.Errorf("ListSessions returned %d sessions, want 2", len(sessions))
	}
}

func TestCountSessions(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agents
	agent1 := &rbac.Agent{ID: "agent-1", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	agent2 := &rbac.Agent{ID: "agent-2", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	rbacMgr.RegisterAgent(agent1)
	rbacMgr.RegisterAgent(agent2)

	ctx := context.Background()
	sm.CreateSession(ctx, "conn-1", "agent-1")
	sm.CreateSession(ctx, "conn-2", "agent-2")

	count := sm.CountSessions()
	if count != 2 {
		t.Errorf("CountSessions = %d, want 2", count)
	}
}

func TestCleanupExpired(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent
	agent := &rbac.Agent{ID: "test-agent", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	rbacMgr.RegisterAgent(agent)

	ctx := context.Background()
	session, _ := sm.CreateSession(ctx, "conn-1", "test-agent")

	// Manually expire the session
	session.RBACSession.ExpiresAt = time.Now().Add(-time.Hour)

	// Cleanup
	cleaned := sm.CleanupExpired()
	if cleaned != 1 {
		t.Errorf("CleanupExpired cleaned %d sessions, want 1", cleaned)
	}

	// Verify session is gone
	count := sm.CountSessions()
	if count != 0 {
		t.Errorf("CountSessions after cleanup = %d, want 0", count)
	}
}

func TestGetSessionStats(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agents
	agent1 := &rbac.Agent{ID: "agent-1", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	agent2 := &rbac.Agent{ID: "agent-2", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	rbacMgr.RegisterAgent(agent1)
	rbacMgr.RegisterAgent(agent2)

	ctx := context.Background()
	session1, _ := sm.CreateSession(ctx, "conn-1", "agent-1")
	sm.CreateSession(ctx, "conn-2", "agent-2")

	// Expire one session
	session1.RBACSession.ExpiresAt = time.Now().Add(-time.Hour)

	stats := sm.GetSessionStats()
	if stats.TotalSessions != 2 {
		t.Errorf("TotalSessions = %d, want 2", stats.TotalSessions)
	}
	if stats.ActiveSessions != 1 {
		t.Errorf("ActiveSessions = %d, want 1", stats.ActiveSessions)
	}
	if stats.ExpiredSessions != 1 {
		t.Errorf("ExpiredSessions = %d, want 1", stats.ExpiredSessions)
	}
}

func TestStartCleanupRoutine(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Register agent
	agent := &rbac.Agent{ID: "test-agent", Role: rbac.AgentRoleStandard, Tools: []rbac.ToolPermission{rbac.PermToolFileRead}}
	rbacMgr.RegisterAgent(agent)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup routine
	sm.StartCleanupRoutine(ctx, 50*time.Millisecond)

	// Create and expire a session
	session, _ := sm.CreateSession(ctx, "conn-1", "test-agent")
	session.RBACSession.SetExpiresAt(time.Now().Add(-time.Hour))

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Check session was cleaned up
	count := sm.CountSessions()
	if count != 0 {
		t.Errorf("CountSessions after cleanup routine = %d, want 0", count)
	}
}

// TestSetMemoryLimit tests memory limit configuration
func TestSetMemoryLimit(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	sm.SetMemoryLimit("session1", 1024*1024) // 1MB

	stats := sm.GetMemoryStats("session1")
	if stats == nil {
		t.Fatal("Expected memory stats to exist")
	}
	if stats.Limit != 1024*1024 {
		t.Errorf("Expected limit 1048576, got %d", stats.Limit)
	}
	if stats.Usage != 0 {
		t.Errorf("Expected initial usage 0, got %d", stats.Usage)
	}
	if stats.Tier != "community" {
		t.Errorf("Expected tier 'community', got '%s'", stats.Tier)
	}

	// Test overriding existing limit
	sm.SetMemoryLimit("session1", 2048*1024) // 2MB
	stats = sm.GetMemoryStats("session1")
	if stats.Limit != 2048*1024 {
		t.Errorf("Expected updated limit 2097152, got %d", stats.Limit)
	}
}

// TestGetMemoryStats tests memory stats retrieval
func TestGetMemoryStats(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Non-existent session
	stats := sm.GetMemoryStats("nonexistent")
	if stats != nil {
		t.Errorf("Expected nil for nonexistent session, got %v", stats)
	}

	// Set and retrieve
	sm.SetMemoryLimit("session1", 512*1024)
	stats = sm.GetMemoryStats("session1")
	if stats == nil {
		t.Fatal("Expected memory stats to exist")
	}
	if stats.Limit != 512*1024 {
		t.Errorf("Expected limit 524288, got %d", stats.Limit)
	}
}

// TestCheckAndEnforceMemoryLimit tests memory limit enforcement
func TestCheckAndEnforceMemoryLimit(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Set limit
	sm.SetMemoryLimit("session1", 1024) // 1KB

	// Within limit - should return nil
	err := sm.CheckAndEnforceMemoryLimit("session1")
	if err != nil {
		t.Errorf("Within limit should not error, got: %v", err)
	}

	// Increment usage
	sm.IncrementMemoryUsage("session1", 2048) // 2KB (exceeds 1KB)

	// Exceeds limit - should return error
	err = sm.CheckAndEnforceMemoryLimit("session1")
	if err == nil {
		t.Error("Exceeding limit should return error")
	}

	// Non-existent session - should return nil (no enforcement needed)
	err = sm.CheckAndEnforceMemoryLimit("nonexistent")
	if err != nil {
		t.Errorf("Non-existent session should not error, got: %v", err)
	}
}

// TestIncrementMemoryUsage tests memory usage increment
func TestIncrementMemoryUsage(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(rbac.DefaultConfig())
	sm := NewConnectionSessionManager(rbacMgr)

	// Set limit first
	sm.SetMemoryLimit("session1", 1024*1024)

	// Increment usage
	sm.IncrementMemoryUsage("session1", 512)

	stats := sm.GetMemoryStats("session1")
	if stats == nil {
		t.Fatal("Expected memory stats to exist")
	}
	if stats.Usage != 512 {
		t.Errorf("Expected usage 512, got %d", stats.Usage)
	}

	// Increment again
	sm.IncrementMemoryUsage("session1", 256)
	stats = sm.GetMemoryStats("session1")
	if stats.Usage != 768 {
		t.Errorf("Expected usage 768, got %d", stats.Usage)
	}

	// Increment non-existent session - should not panic
	sm.IncrementMemoryUsage("nonexistent", 100)
	// No way to verify this without exposing internal state, but should not panic
}

// TestTruncateSessionID tests session ID truncation helper
func TestTruncateSessionID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},
		{"exactly12ch", "exactly12ch"},
		{"123456789abc", "123456789abc"},
		{"123456789abcd", "123456789abc..."},
		{"this_is_a_very_long_session_id", "this_is_a_ve..."},
	}

	for _, tt := range tests {
		result := truncateSessionID(tt.input)
		if result != tt.expected {
			t.Errorf("truncateSessionID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
