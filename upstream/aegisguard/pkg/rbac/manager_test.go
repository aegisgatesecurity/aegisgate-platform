// Package rbac - Tests for RBAC system
package rbac

import (
	"context"
	"testing"
	"time"
)

// TestAgentRoleAtLeast tests role hierarchy
func TestAgentRoleAtLeast(t *testing.T) {
	tests := []struct {
		role     AgentRole
		required AgentRole
		expected bool
	}{
		{AgentRoleRestricted, AgentRoleRestricted, true},
		{AgentRoleRestricted, AgentRoleStandard, false},
		{AgentRoleStandard, AgentRoleRestricted, true},
		{AgentRoleStandard, AgentRolePrivileged, false},
		{AgentRolePrivileged, AgentRoleStandard, true},
		{AgentRolePrivileged, AgentRoleAdmin, false},
		{AgentRoleAdmin, AgentRoleRestricted, true},
		{AgentRoleAdmin, AgentRoleAdmin, true},
	}

	for _, tt := range tests {
		result := tt.role.AtLeast(tt.required)
		if result != tt.expected {
			t.Errorf("role %s.AtLeast(%s) = %v, want %v", tt.role, tt.required, result, tt.expected)
		}
	}
}

// TestAgentHasToolPermission tests permission checking
func TestAgentHasToolPermission(t *testing.T) {
	agent := &Agent{
		ID:    "test-agent",
		Role:  AgentRoleStandard,
		Tools: []ToolPermission{PermToolFileRead, PermToolFileWrite},
	}

	if !agent.HasToolPermission(PermToolFileRead) {
		t.Error("agent should have PermToolFileRead")
	}

	if !agent.HasToolPermission(PermToolFileWrite) {
		t.Error("agent should have PermToolFileWrite")
	}

	if agent.HasToolPermission(PermToolShellCommand) {
		t.Error("agent should NOT have PermToolShellCommand")
	}
}

// TestAgentCanExecuteTool tests tool execution permission
func TestAgentCanExecuteTool(t *testing.T) {
	// Admin can execute anything
	admin := &Agent{ID: "admin", Role: AgentRoleAdmin}
	if !admin.CanExecuteTool("shell_command") {
		t.Error("admin should be able to execute shell_command")
	}
	if !admin.CanExecuteTool("file_read") {
		t.Error("admin should be able to execute file_read")
	}

	// Restricted with explicit permission can execute that tool
	restricted := &Agent{ID: "restricted", Role: AgentRoleRestricted, Tools: []ToolPermission{PermToolFileRead}}
	if !restricted.CanExecuteTool("file_read") {
		t.Error("restricted with file_read perm should be able to execute file_read")
	}

	// Without permission, restricted cannot execute shell
	if restricted.CanExecuteTool("shell_command") {
		t.Error("restricted without shell permission should NOT execute shell_command")
	}

	// Standard role can execute file operations (role defaults)
	standard := &Agent{ID: "standard", Role: AgentRoleStandard}
	if !standard.CanExecuteTool("file_write") {
		t.Error("standard role should be able to execute file_write (role default)")
	}
}

// TestSessionLifecycle tests session creation and expiration
func TestSessionLifecycle(t *testing.T) {
	config := &Config{
		SessionDuration: 24 * time.Hour,
		MaxAgents:       100,
		MaxSessions:     10,
		CleanupInterval: 1 * time.Hour,
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer manager.Close()

	// Register agent
	agent := &Agent{
		ID:   "session-test-agent",
		Name: "Test Session Agent",
		Role: AgentRoleStandard,
	}
	if err := manager.RegisterAgent(agent); err != nil {
		t.Fatalf("failed to register agent: %v", err)
	}

	// Create session
	session, err := manager.CreateSession(context.Background(), agent.ID)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Session should be valid
	if !session.IsValid() {
		t.Error("session should be valid")
	}

	// Session should not be expired
	if session.IsExpired() {
		t.Error("session should not be expired")
	}

	// Get session should work
	retrieved, err := manager.GetSession(session.ID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if retrieved.ID != session.ID {
		t.Errorf("session ID mismatch")
	}

	// Invalidate session
	if err := manager.InvalidateSession(session.ID); err != nil {
		t.Fatalf("failed to invalidate session: %v", err)
	}

	// Session should now be invalid
	if session.IsValid() {
		t.Error("session should be invalid after invalidation")
	}
}

// TestAgentManagement tests agent CRUD operations
func TestAgentManagement(t *testing.T) {
	config := &Config{
		MaxAgents:       100,
		CleanupInterval: 1 * time.Hour,
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer manager.Close()

	// Register agent
	agent := &Agent{
		ID:   "mgmt-test-agent",
		Name: "Test Agent",
		Role: AgentRoleStandard,
	}
	if err := manager.RegisterAgent(agent); err != nil {
		t.Fatalf("failed to register agent: %v", err)
	}

	// Get agent
	retrieved, err := manager.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("failed to get agent: %v", err)
	}
	if retrieved.Name != "Test Agent" {
		t.Errorf("agent name = %s, want Test Agent", retrieved.Name)
	}

	// Update agent
	if err := manager.UpdateAgent(agent.ID, &AgentUpdates{
		Name: "Updated Agent",
	}); err != nil {
		t.Fatalf("failed to update agent: %v", err)
	}

	// Verify update
	retrieved, _ = manager.GetAgent(agent.ID)
	if retrieved.Name != "Updated Agent" {
		t.Errorf("agent name = %s, want Updated Agent", retrieved.Name)
	}

	// Unregister agent
	if err := manager.UnregisterAgent(agent.ID); err != nil {
		t.Fatalf("failed to unregister agent: %v", err)
	}

	// Agent should not be found
	_, err = manager.GetAgent(agent.ID)
	if err == nil {
		t.Error("expected error for unregistered agent")
	}
}

// TestAuthorization tests authorization decisions
func TestAuthorization(t *testing.T) {
	config := &Config{
		SessionDuration: 24 * time.Hour,
		MaxAgents:       100,
		MaxSessions:     10,
		CleanupInterval: 1 * time.Hour,
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer manager.Close()

	// Register agent with explicit permission
	agent := &Agent{
		ID:    "auth-test-agent",
		Role:  AgentRoleRestricted,
		Tools: []ToolPermission{"tool:file_read"}, // Explicit permission
	}
	if err := manager.RegisterAgent(agent); err != nil {
		t.Fatalf("failed to register agent: %v", err)
	}

	// Create session
	session, err := manager.CreateSession(context.Background(), agent.ID)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Should be able to read files (has explicit permission)
	result, err := manager.AuthorizeToolCall(context.Background(), session.ID, "file_read")
	if err != nil {
		t.Fatalf("authorization error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("agent with file_read permission should be able to read files: %s", result.Reason)
	}

	// Should NOT be able to run shell commands (no permission)
	result, err = manager.AuthorizeToolCall(context.Background(), session.ID, "shell_command")
	if err != nil {
		t.Fatalf("authorization error: %v", err)
	}
	if result.Allowed {
		t.Error("agent without shell permission should NOT be able to run shell commands")
	}

	// Now give the agent shell permission (and ensure it's enabled)
	manager.UpdateAgent(agent.ID, &AgentUpdates{
		Tools:   []ToolPermission{"tool:file_read", "tool:shell_command"},
		Enabled: true,
	})

	// Should now be able to run shell commands
	result, err = manager.AuthorizeToolCall(context.Background(), session.ID, "shell_command")
	if err != nil {
		t.Fatalf("authorization error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("agent with shell permission should be able to run shell commands: %s", result.Reason)
	}
}

// TestDefaultPermissions tests role defaults
func TestDefaultPermissions(t *testing.T) {
	restricted := GetPermissionsForRole(AgentRoleRestricted)
	if len(restricted) == 0 {
		t.Error("restricted role should have default permissions")
	}

	admin := GetPermissionsForRole(AgentRoleAdmin)
	if len(admin) == 0 {
		t.Error("admin role should have default permissions")
	}
}

// TestDuplicateRegistration tests duplicate handling
func TestDuplicateRegistration(t *testing.T) {
	config := &Config{
		MaxAgents:       100,
		CleanupInterval: 1 * time.Hour,
	}
	manager, _ := NewManager(config)
	defer manager.Close()

	agent := &Agent{ID: "dup-agent", Name: "Duplicate"}
	manager.RegisterAgent(agent)

	// Second registration should fail
	err := manager.RegisterAgent(agent)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

// TestSessionRefresh tests refresh functionality
func TestSessionRefresh(t *testing.T) {
	config := &Config{
		SessionDuration: 1 * time.Hour,
		MaxAgents:       100,
		MaxSessions:     10,
		CleanupInterval: 1 * time.Hour,
	}
	manager, _ := NewManager(config)
	defer manager.Close()

	agent := &Agent{ID: "refresh-agent", Role: AgentRoleStandard}
	manager.RegisterAgent(agent)

	session, _ := manager.CreateSession(context.Background(), agent.ID)
	originalExpiry := session.ExpiresAt

	time.Sleep(10 * time.Millisecond)
	manager.RefreshSession(session.ID)

	if !session.ExpiresAt.After(originalExpiry) {
		t.Error("session expiry should be extended after refresh")
	}
}

// TestInvalidSession tests invalid session handling
func TestInvalidSession(t *testing.T) {
	config := &Config{
		CleanupInterval: 1 * time.Hour,
	}
	manager, _ := NewManager(config)
	defer manager.Close()

	// Non-existent session
	_, err := manager.GetSession("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent session")
	}

	// Non-existent agent
	_, err = manager.CreateSession(context.Background(), "nonexistent-agent")
	if err == nil {
		t.Error("expected error for non-existent agent")
	}
}

// TestDisabledAgent tests disabled agent handling
func TestDisabledAgent(t *testing.T) {
	config := &Config{
		CleanupInterval: 1 * time.Hour,
	}
	manager, _ := NewManager(config)
	defer manager.Close()

	agent := &Agent{ID: "disabled-agent", Role: AgentRoleStandard, Enabled: false}
	manager.RegisterAgent(agent)

	// Disabled agent cannot create session
	_, err := manager.CreateSession(context.Background(), agent.ID)
	if err == nil {
		t.Error("expected error for disabled agent")
	}
}

// TestAgentTags tests agent tagging
func TestAgentTags(t *testing.T) {
	agent := &Agent{
		ID:   "tagged-agent",
		Role: AgentRoleStandard,
		Tags: map[string]string{
			"environment": "production",
		},
	}

	if agent.Tags["environment"] != "production" {
		t.Error("agent should have environment tag")
	}
}
