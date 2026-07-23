// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - RBAC PostgreSQL Store Panic-Recovery Unit Tests
//
// Tests input validation paths, closed-state paths, and pool-call paths
// via panic recovery without requiring a live PostgreSQL connection.
//go:build !integration

package rbac

import (
	"context"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// Constructor validation
// --------------------------------------------------------------------

func TestRBACNewPostgresRBACStore_NilStore(t *testing.T) {
	store, err := NewPostgresRBACStore(nil, nil)
	if store != nil {
		t.Fatal("expected nil store")
	}
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestRBACNewPostgresRBACStore_NilConfig(t *testing.T) {
	// Can't create a real PostgresStore without DB, so test that nil config
	// defaults to DefaultConfig when store is non-nil.
	// We verify the default config path indirectly:
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig should not return nil")
	}
}

// --------------------------------------------------------------------
// Closed-state tests (no pool access needed)
// --------------------------------------------------------------------

func TestRBACRegisterAgent_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.RegisterAgent(context.Background(), &Agent{ID: "test"})
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACGetAgent_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.GetAgent(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACUpdateAgent_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.UpdateAgent(context.Background(), "test", &AgentUpdates{})
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACUnregisterAgent_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.UnregisterAgent(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACListAgents_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.ListAgents(context.Background())
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACCreateAgentSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.CreateAgentSession(context.Background(), &AgentSession{ID: "test"})
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACGetAgentSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.GetAgentSession(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACRefreshAgentSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.RefreshAgentSession(context.Background(), "test", time.Hour)
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACInvalidateAgentSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.InvalidateAgentSession(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACInvalidateAgentSessions_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.InvalidateAgentSessions(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACGetAgentSessions_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.GetAgentSessions(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACCreateUserSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.CreateUserSession(context.Background(), &UserSession{ID: "test"})
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACGetUserSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.GetUserSession(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACInvalidateUserSession_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.InvalidateUserSession(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACPruneExpiredSessions_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.PruneExpiredSessions(context.Background())
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACCountAgents_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.CountAgents(context.Background())
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestRBACCountActiveSessions_Closed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	_, err := s.CountActiveSessions(context.Background(), "test-agent")
	if err == nil {
		t.Fatal("expected error on closed store")
	}
}

// --------------------------------------------------------------------
// Input validation tests (before pool access)
// --------------------------------------------------------------------

func TestRBACRegisterAgent_NilAgent(t *testing.T) {
	s := &PostgresRBACStore{closed: false}
	err := s.RegisterAgent(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil agent")
	}
}

func TestRBACUpdateAgent_NilUpdates(t *testing.T) {
	s := &PostgresRBACStore{closed: false}
	// UpdateAgent with nil updates returns nil (no-op)
	err := s.UpdateAgent(context.Background(), "test", nil)
	if err != nil {
		t.Fatalf("expected nil for nil updates, got: %v", err)
	}
}

func TestRBACCreateAgentSession_NilSession(t *testing.T) {
	s := &PostgresRBACStore{closed: false}
	err := s.CreateAgentSession(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

// --------------------------------------------------------------------
// Panic-recovery tests (exercise code paths up to pool access)
// --------------------------------------------------------------------

func TestRBACRegisterAgent_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	agent := &Agent{
		ID:   "test-agent-1",
		Name: "Test Agent",
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.RegisterAgent(ctx, agent)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestRBACRegisterAgent_WithTenantCtx(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	agent := &Agent{
		ID:   "test-agent-2",
		Name: "Test Agent",
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.RegisterAgent(ctx, agent, RBACTenantContext{TenantID: "t1", IsAdmin: false})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool with tenant ctx")
	}
}

func TestRBACGetAgent_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = s.GetAgent(ctx, "test-agent")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in GetAgent")
	}
}

func TestRBACGetAgent_WithTenantCtx(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = s.GetAgent(ctx, "test-agent", RBACTenantContext{TenantID: "t1", IsAdmin: true})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in GetAgent with tenant ctx")
	}
}

func TestRBACUnregisterAgent_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.UnregisterAgent(ctx, "test-agent")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in UnregisterAgent")
	}
}

func TestRBACListAgents_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = s.ListAgents(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in ListAgents")
	}
}

func TestRBACCreateAgentSession_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	session := &AgentSession{
		ID:      "test-session-1",
		AgentID: "test-agent",
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.CreateAgentSession(ctx, session)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in CreateAgentSession")
	}
}

func TestRBACRefreshAgentSession_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.RefreshAgentSession(ctx, "test-session", time.Hour)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in RefreshAgentSession")
	}
}

func TestRBACInvalidateAgentSession_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = s.InvalidateAgentSession(ctx, "test-session")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in InvalidateAgentSession")
	}
}

func TestRBACClose_NilPool(t *testing.T) {
	// Close() doesn't access the pool — it just sets closed=true and logs
	s := &PostgresRBACStore{closed: false, pool: nil}
	err := s.Close()
	if err != nil {
		t.Fatalf("expected nil from Close, got: %v", err)
	}
	if !s.closed {
		t.Fatal("expected closed=true after Close()")
	}
}

func TestRBACClose_AlreadyClosed(t *testing.T) {
	s := &PostgresRBACStore{closed: true}
	err := s.Close()
	if err != nil {
		t.Fatalf("expected nil from double-Close, got: %v", err)
	}
}

func TestRBACCountAgents_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = s.CountAgents(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in CountAgents")
	}
}

func TestRBACCountActiveSessions_PanicsOnNilPool(t *testing.T) {
	s := &PostgresRBACStore{closed: false, pool: nil}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = s.CountActiveSessions(ctx, "test-agent")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in CountActiveSessions")
	}
}
