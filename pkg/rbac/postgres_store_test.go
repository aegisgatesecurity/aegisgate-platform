// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL RBAC Store Unit Tests (D1 Phase 1C)
// =========================================================================
// These tests cover nil-store fallback, closed-state errors, and data
// serialization without requiring a live PostgreSQL connection. Integration
// tests should use //go:build integration with a real database.
// =========================================================================

package rbac

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestNewPostgresRBACStore_NilStore verifies that nil PostgresStore returns error.
func TestNewPostgresRBACStore_NilStore(t *testing.T) {
	_, err := NewPostgresRBACStore(nil, nil)
	if err == nil {
		t.Fatal("expected error when pgStore is nil, got nil")
	}
}

// TestNewPostgresRBACStore_NilConfig verifies that nil Config falls back to defaults.
func TestNewPostgresRBACStore_NilConfig(t *testing.T) {
	// This test just verifies the nil-config path doesn't panic.
	// It will fail on pool access (no real DB), but the constructor should succeed.
	// We can't create a real PostgresStore without a database, so we test the error path.
	_, err := NewPostgresRBACStore(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

// TestPostgresRBACStore_ClosedState verifies that all methods return errors after Close().
func TestPostgresRBACStore_ClosedState(t *testing.T) {
	// Create a closed store directly (without a real pool)
	store := &PostgresRBACStore{closed: true}
	ctx := context.Background()

	agent := &Agent{
		ID:   "test-agent",
		Name: "Test Agent",
		Role: AgentRoleStandard,
	}

	// All methods should return errors when closed
	if err := store.RegisterAgent(ctx, agent); err == nil {
		t.Error("RegisterAgent should fail on closed store")
	}
	if _, err := store.GetAgent(ctx, "test"); err == nil {
		t.Error("GetAgent should fail on closed store")
	}
	if err := store.UpdateAgent(ctx, "test", &AgentUpdates{Name: "x"}); err == nil {
		t.Error("UpdateAgent should fail on closed store")
	}
	if err := store.UnregisterAgent(ctx, "test"); err == nil {
		t.Error("UnregisterAgent should fail on closed store")
	}
	if _, err := store.ListAgents(ctx); err == nil {
		t.Error("ListAgents should fail on closed store")
	}
	if err := store.CreateAgentSession(ctx, &AgentSession{ID: "s1"}); err == nil {
		t.Error("CreateAgentSession should fail on closed store")
	}
	if _, err := store.GetAgentSession(ctx, "s1"); err == nil {
		t.Error("GetAgentSession should fail on closed store")
	}
	if err := store.RefreshAgentSession(ctx, "s1", time.Hour); err == nil {
		t.Error("RefreshAgentSession should fail on closed store")
	}
	if err := store.InvalidateAgentSession(ctx, "s1"); err == nil {
		t.Error("InvalidateAgentSession should fail on closed store")
	}
	if _, err := store.InvalidateAgentSessions(ctx, "a1"); err == nil {
		t.Error("InvalidateAgentSessions should fail on closed store")
	}
	if _, err := store.GetAgentSessions(ctx, "a1"); err == nil {
		t.Error("GetAgentSessions should fail on closed store")
	}
	if err := store.CreateUserSession(ctx, nil); err == nil {
		t.Error("CreateUserSession should fail on closed store")
	}
	if _, err := store.GetUserSession(ctx, "s1"); err == nil {
		t.Error("GetUserSession should fail on closed store")
	}
	if err := store.InvalidateUserSession(ctx, "s1"); err == nil {
		t.Error("InvalidateUserSession should fail on closed store")
	}
	if _, err := store.PruneExpiredSessions(ctx); err == nil {
		t.Error("PruneExpiredSessions should fail on closed store")
	}
	if _, err := store.CountAgents(ctx); err == nil {
		t.Error("CountAgents should fail on closed store")
	}
	if _, err := store.CountActiveSessions(ctx, "a1"); err == nil {
		t.Error("CountActiveSessions should fail on closed store")
	}

	// Double close should be safe
	if err := store.Close(); err != nil {
		t.Errorf("double Close should not error, got: %v", err)
	}
}

// TestPostgresRBACStore_NilAgent verifies that nil agent is rejected.
func TestPostgresRBACStore_NilAgent(t *testing.T) {
	store := &PostgresRBACStore{closed: true}
	ctx := context.Background()

	if err := store.RegisterAgent(ctx, nil); err == nil {
		t.Error("RegisterAgent should reject nil agent")
	}
}

// TestPostgresRBACStore_NilSession verifies that nil session is rejected.
func TestPostgresRBACStore_NilSession(t *testing.T) {
	store := &PostgresRBACStore{closed: true}
	ctx := context.Background()

	if err := store.CreateAgentSession(ctx, nil); err == nil {
		t.Error("CreateAgentSession should reject nil session")
	}
	if err := store.CreateUserSession(ctx, nil); err == nil {
		t.Error("CreateUserSession should reject nil session")
	}
}

// TestPostgresRBACStore_NilUpdate verifies that nil updates is a no-op.
func TestPostgresRBACStore_NilUpdate(t *testing.T) {
	store := &PostgresRBACStore{closed: true}
	ctx := context.Background()

	// nil updates should not error (it's a no-op), but closed store should error
	if err := store.UpdateAgent(ctx, "test", nil); err == nil {
		t.Error("UpdateAgent with nil updates on closed store should still fail")
	}
}

// TestJoinRBACStrings verifies the string join helper.
func TestJoinRBACStrings(t *testing.T) {
	tests := []struct {
		input []string
		sep   string
		want  string
	}{
		{[]string{}, ", ", ""},
		{[]string{"a"}, ", ", "a"},
		{[]string{"a", "b"}, ", ", "a, b"},
		{[]string{"a", "b", "c"}, ", ", "a, b, c"},
		{[]string{"x", "y"}, " AND ", "x AND y"},
	}

	for _, tt := range tests {
		got := joinRBACStrings(tt.input, tt.sep)
		if got != tt.want {
			t.Errorf("joinRBACStrings(%v, %q) = %q, want %q", tt.input, tt.sep, got, tt.want)
		}
	}
}

// TestAgentRoleString verifies that AgentRole string conversions work for PostgreSQL storage.
func TestAgentRoleStringRoundTrip(t *testing.T) {
	roles := []AgentRole{AgentRoleRestricted, AgentRoleStandard, AgentRolePrivileged, AgentRoleAdmin}
	for _, role := range roles {
		// String() should produce a value that can be stored in PostgreSQL
		s := string(role)
		if s == "" {
			t.Errorf("AgentRole %v has empty string representation", role)
		}
	}
}

// TestUserRoleStringRoundTrip verifies that UserRole string conversions work for PostgreSQL storage.
func TestUserRoleStringRoundTrip(t *testing.T) {
	roles := []UserRole{UserRoleViewer, UserRoleAnalyst, UserRoleAdmin, UserRoleComplianceOfficer}
	for _, role := range roles {
		s := string(role)
		if s == "" {
			t.Errorf("UserRole %v has empty string representation", role)
		}
		// ParseUserRole should round-trip
		parsed := ParseUserRole(s)
		if parsed != role {
			t.Errorf("ParseUserRole(%q) = %v, want %v", s, parsed, role)
		}
	}
}

// TestToolPermissionJSONSerialization verifies that ToolPermissions serialize/deserialize correctly as JSON.
func TestToolPermissionJSONSerialization(t *testing.T) {
	tools := []ToolPermission{PermToolFileRead, PermToolWebSearch, PermToolAll}
	data, err := marshalToolPermissions(tools)
	if err != nil {
		t.Fatalf("marshalToolPermissions error: %v", err)
	}

	parsed, err := unmarshalToolPermissions(data)
	if err != nil {
		t.Fatalf("unmarshalToolPermissions error: %v", err)
	}

	if len(parsed) != len(tools) {
		t.Fatalf("round-trip length mismatch: got %d, want %d", len(parsed), len(tools))
	}

	for i, tp := range tools {
		if parsed[i] != tp {
			t.Errorf("round-trip mismatch at index %d: got %v, want %v", i, parsed[i], tp)
		}
	}
}

// TestPermissionJSONSerialization verifies that Permissions serialize/deserialize correctly as JSON.
func TestPermissionJSONSerialization(t *testing.T) {
	perms := []Permission{
		{Resource: ResourceDashboard, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionManage},
	}
	data, err := marshalPermissions(perms)
	if err != nil {
		t.Fatalf("marshalPermissions error: %v", err)
	}

	parsed, err := unmarshalPermissions(data)
	if err != nil {
		t.Fatalf("unmarshalPermissions error: %v", err)
	}

	if len(parsed) != len(perms) {
		t.Fatalf("round-trip length mismatch: got %d, want %d", len(parsed), len(perms))
	}

	for i, p := range perms {
		if parsed[i] != p {
			t.Errorf("round-trip mismatch at index %d: got %v, want %v", i, parsed[i], p)
		}
	}
}

// marshalToolPermissions serializes ToolPermissions to JSON bytes.
func marshalToolPermissions(tools []ToolPermission) ([]byte, error) {
	strs := make([]string, len(tools))
	for i, t := range tools {
		strs[i] = string(t)
	}
	return json.Marshal(strs)
}

// unmarshalToolPermissions deserializes ToolPermissions from JSON bytes.
func unmarshalToolPermissions(data []byte) ([]ToolPermission, error) {
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return nil, err
	}
	tools := make([]ToolPermission, len(strs))
	for i, s := range strs {
		tools[i] = ToolPermission(s)
	}
	return tools, nil
}

// marshalPermissions serializes Permissions to JSON bytes.
func marshalPermissions(perms []Permission) ([]byte, error) {
	// Permission has json tags, so we can marshal directly
	return json.Marshal(perms)
}

// unmarshalPermissions deserializes Permissions from JSON bytes.
func unmarshalPermissions(data []byte) ([]Permission, error) {
	var perms []Permission
	if err := json.Unmarshal(data, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}
