// SPDX-License-Identifier: Apache-2.0
//go:build !race

package rbac

import (
	"context"
	"testing"
	"time"
)

// TestAgentSession_SetExpiresAt covers the 0% SetExpiresAt method
func TestAgentSession_SetExpiresAt(t *testing.T) {
	now := time.Now()
	s := &AgentSession{
		ID:        "test-session",
		AgentID:   "agent-1",
		Active:    true,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	newExpiry := now.Add(24 * time.Hour)
	s.SetExpiresAt(newExpiry)

	if !s.ExpiresAt.Equal(newExpiry) {
		t.Errorf("SetExpiresAt: got %v, want %v", s.ExpiresAt, newExpiry)
	}

	// Verify it updates correctly for past times (expiry)
	s.SetExpiresAt(now.Add(-1 * time.Hour))
	if !s.IsExpired() {
		t.Error("SetExpiresAt to past time should make session expired")
	}

	// Verify concurrent safety (basic test)
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			s.SetExpiresAt(now.Add(time.Duration(i) * time.Minute))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			_ = s.IsExpired()
		}
		done <- true
	}()
	<-done
	<-done
}

// TestManager_Cleanup covers the 0% cleanup method
func TestManager_Cleanup(t *testing.T) {
	m, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Register an agent
	agent := &Agent{
		ID:      "agent-1",
		Role:    AgentRoleRestricted,
		Enabled: true,
		Tools:   []ToolPermission{PermToolFileRead},
	}
	err = m.RegisterAgent(agent)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create sessions — one expired, one active
	expiredSess, err := m.CreateSession(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Expire the session
	expiredSess.SetExpiresAt(time.Now().Add(-1 * time.Hour))
	expiredSess.Active = false

	// Create another active session
	activeSess, err := m.CreateSession(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Run cleanup
	m.cleanup()

	// Verify expired session was removed
	_, err = m.GetSession(expiredSess.ID)
	if err == nil {
		t.Error("Expired session should have been cleaned up")
	}

	// Verify active session still exists
	_, err = m.GetSession(activeSess.ID)
	if err != nil {
		t.Errorf("Active session should still exist: %v", err)
	}
}

// TestManager_Cleanup_NoExpired covers cleanup with no expired sessions
func TestManager_Cleanup_NoExpired(t *testing.T) {
	m, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	agent := &Agent{
		ID:      "agent-2",
		Role:    AgentRoleStandard,
		Enabled: true,
		Tools:   []ToolPermission{PermToolFileRead, PermToolWebSearch},
	}
	err = m.RegisterAgent(agent)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	sess, err := m.CreateSession(context.Background(), "agent-2")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Run cleanup on active session
	m.cleanup()

	// Session should still exist
	_, err = m.GetSession(sess.ID)
	if err != nil {
		t.Errorf("Active session should not be removed by cleanup: %v", err)
	}
}

// TestManager_Cleanup_EmptyManager covers cleanup with no sessions
func TestManager_Cleanup_EmptyManager(t *testing.T) {
	m, err := NewManager(DefaultConfig())
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Should not panic
	m.cleanup()

	// Create agent but no sessions
	agent := &Agent{
		ID:      "agent-empty",
		Role:    AgentRoleRestricted,
		Enabled: true,
		Tools:   []ToolPermission{PermToolFileRead},
	}
	err = m.RegisterAgent(agent)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	m.cleanup() // No sessions to clean
}