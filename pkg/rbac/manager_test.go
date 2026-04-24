// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — RBAC Manager Tests (Chunk 1)

package rbac

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	cfg := DefaultConfig()
	cfg.CleanupInterval = 1 * time.Hour
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return m
}

func testAgent(role AgentRole) *Agent {
	return &Agent{
		ID:          "agent-1",
		Name:        "Test Agent",
		Description: "A test agent",
		Role:        role,
		Tools:       GetPermissionsForRole(role),
		Tags:        map[string]string{"env": "test"},
		Enabled:     true,
	}
}

func TestNewManager(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	if m.config == nil {
		t.Fatal("Manager.config is nil")
	}
	if m.agents == nil {
		t.Fatal("Manager.agents is nil")
	}
	if m.agentSessions == nil {
		t.Fatal("Manager.agentSessions is nil")
	}
	if m.users == nil {
		t.Fatal("Manager.users is nil")
	}
	if m.userSessions == nil {
		t.Fatal("Manager.userSessions is nil")
	}

	// Test nil config defaults
	m2, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager(nil) error: %v", err)
	}
	m2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	defer m2.Close()
	if m2.config == nil {
		t.Fatal("NewManager(nil).config is nil")
	}
	if m2.config.SessionDuration != 24*time.Hour {
		t.Errorf("default session duration = %v, want 24h", m2.config.SessionDuration)
	}
}

func TestManager_Close(t *testing.T) {
	m := testManager(t)
	_ = m.RegisterAgent(testAgent(AgentRoleRestricted))
	_, _ = m.CreateSession(context.Background(), "agent-1")
	m.Close()

	if len(m.agents) != 0 {
		t.Errorf("agents not cleared after Close: got %d", len(m.agents))
	}
	if len(m.agentSessions) != 0 {
		t.Errorf("agent sessions not cleared after Close: got %d", len(m.agentSessions))
	}
	if len(m.users) != 0 {
		t.Errorf("users not cleared after Close: got %d", len(m.users))
	}
	if len(m.userSessions) != 0 {
		t.Errorf("user sessions not cleared after Close: got %d", len(m.userSessions))
	}
}

// ============================================================================
// AGENT MANAGEMENT TESTS
// ============================================================================

func TestManager_RegisterAgent(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	// Success
	a1 := testAgent(AgentRoleRestricted)
	if err := m.RegisterAgent(a1); err != nil {
		t.Fatalf("RegisterAgent error: %v", err)
	}
	if a1.CreatedAt.IsZero() {
		t.Error("agent CreatedAt not set")
	}
	if !a1.Enabled {
		t.Error("agent Enabled should be true by default")
	}

	// Empty ID
	a2 := &Agent{ID: ""}
	if err := m.RegisterAgent(a2); err == nil {
		t.Error("RegisterAgent should error for empty ID")
	}

	// Duplicate
	if err := m.RegisterAgent(a1); err == nil {
		t.Error("RegisterAgent should error for duplicate agent")
	}

	// Max agents
	cfg := DefaultConfig()
	cfg.MaxAgents = 1
	m2, _ := NewManager(cfg)
	m2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	defer m2.Close()
	_ = m2.RegisterAgent(&Agent{ID: "agent-max"})
	if err := m2.RegisterAgent(&Agent{ID: "agent-overflow"}); err == nil {
		t.Error("RegisterAgent should error when max agents reached")
	}

	// Default role
	a3 := &Agent{ID: "agent-default"}
	_ = m.RegisterAgent(a3)
	if a3.Role != AgentRoleRestricted {
		t.Errorf("default role = %v, want restricted", a3.Role)
	}

	// Default tools set from role
	if len(a3.Tools) == 0 {
		t.Error("default tools should be set from role")
	}

	// Tags initialized
	if a3.Tags == nil {
		t.Error("Tags should be initialized")
	}
}

func TestManager_GetAgent(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)

	got, err := m.GetAgent(a.ID)
	if err != nil {
		t.Fatalf("GetAgent error: %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("GetAgent ID = %v, want %v", got.ID, a.ID)
	}

	_, err = m.GetAgent("nonexistent")
	if err == nil {
		t.Error("GetAgent should error for nonexistent agent")
	}
}

func TestManager_UpdateAgent(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleRestricted)
	_ = m.RegisterAgent(a)

	// Update name and description
	if err := m.UpdateAgent(a.ID, &AgentUpdates{Name: "Updated", Description: "Updated desc"}); err != nil {
		t.Fatalf("UpdateAgent error: %v", err)
	}
	if a.Name != "Updated" {
		t.Errorf("Name = %v, want Updated", a.Name)
	}

	// Update role
	if err := m.UpdateAgent(a.ID, &AgentUpdates{Role: AgentRoleStandard}); err != nil {
		t.Fatalf("UpdateAgent role error: %v", err)
	}
	if a.Role != AgentRoleStandard {
		t.Errorf("Role = %v, want standard", a.Role)
	}

	// Update with explicit tools
	if err := m.UpdateAgent(a.ID, &AgentUpdates{Tools: []ToolPermission{PermToolFileRead}}); err != nil {
		t.Fatalf("UpdateAgent tools error: %v", err)
	}
	if len(a.Tools) != 1 || a.Tools[0] != PermToolFileRead {
		t.Errorf("Tools not updated correctly: %v", a.Tools)
	}

	// Update tags
	if err := m.UpdateAgent(a.ID, &AgentUpdates{Tags: map[string]string{"region": "us"}}); err != nil {
		t.Fatalf("UpdateAgent tags error: %v", err)
	}
	if a.Tags["region"] != "us" {
		t.Errorf("Tag not merged: %v", a.Tags)
	}

	// Invalid role
	if err := m.UpdateAgent(a.ID, &AgentUpdates{Role: "bogus"}); err == nil {
		t.Error("UpdateAgent should error for invalid role")
	}

	// Not found
	if err := m.UpdateAgent("no-such-id", &AgentUpdates{Name: "X"}); err == nil {
		t.Error("UpdateAgent should error for missing agent")
	}
}

func TestManager_UnregisterAgent(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleRestricted)
	_ = m.RegisterAgent(a)
	_, _ = m.CreateSession(context.Background(), a.ID)

	if err := m.UnregisterAgent(a.ID); err != nil {
		t.Fatalf("UnregisterAgent error: %v", err)
	}

	if _, err := m.GetAgent(a.ID); err == nil {
		t.Error("agent should be removed after unregister")
	}

	if len(m.agentSessions) != 0 {
		t.Errorf("agent sessions should be invalidated: got %d", len(m.agentSessions))
	}

	if err := m.UnregisterAgent("nonexistent"); err == nil {
		t.Error("UnregisterAgent should error for missing agent")
	}
}

func TestManager_ListAgents(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	agents := m.ListAgents()
	if len(agents) != 0 {
		t.Errorf("ListAgents() = %d, want 0", len(agents))
	}

	_ = m.RegisterAgent(testAgent(AgentRoleRestricted))
	_ = m.RegisterAgent(&Agent{ID: "agent-2", Name: "Agent 2", Role: AgentRoleStandard})

	agents = m.ListAgents()
	if len(agents) != 2 {
		t.Errorf("ListAgents() = %d, want 2", len(agents))
	}
}

// ============================================================================
// SESSION MANAGEMENT TESTS
// ============================================================================

func TestManager_CreateSession(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleRestricted)
	_ = m.RegisterAgent(a)

	ctx := context.Background()

	// Success
	sess, err := m.CreateSession(ctx, a.ID)
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID is empty")
	}
	if sess.AgentID != a.ID {
		t.Errorf("session AgentID = %v, want %v", sess.AgentID, a.ID)
	}
	if !sess.Active {
		t.Error("session should be active")
	}
	if sess.ExpiresAt.Before(time.Now()) {
		t.Error("session already expired")
	}

	// With options
	s2, err := m.CreateSession(ctx, a.ID,
		WithSessionTags(map[string]string{"key": "val"}),
		WithSessionIP("127.0.0.1"),
		WithSessionContextHash("abc123"))
	if err != nil {
		t.Fatalf("CreateSession with options error: %v", err)
	}
	if s2.Tags["key"] != "val" {
		t.Errorf("session tag = %v, want val", s2.Tags["key"])
	}
	if s2.IPAddress != "127.0.0.1" {
		t.Errorf("session IP = %v, want 127.0.0.1", s2.IPAddress)
	}
	if s2.ContextHash != "abc123" {
		t.Errorf("session ContextHash = %v, want abc123", s2.ContextHash)
	}

	// Agent not found
	_, err = m.CreateSession(ctx, "fake")
	if err == nil {
		t.Error("CreateSession should error for missing agent")
	}

	// Agent disabled
	a2 := &Agent{ID: "agent-disabled", Name: "Disabled", Role: AgentRoleRestricted, Enabled: true}
	_ = m.RegisterAgent(a2)
	a2.Enabled = false
	_, err = m.CreateSession(ctx, a2.ID)
	if err == nil {
		t.Error("CreateSession should error for disabled agent")
	}

	// Max sessions
	cfg := DefaultConfig()
	cfg.MaxSessionsPerAgent = 1
	m3, _ := NewManager(cfg)
	m3.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	defer m3.Close()
	_ = m3.RegisterAgent(&Agent{ID: "agent-max", Name: "Max", Role: AgentRoleRestricted, Enabled: true})
	_, _ = m3.CreateSession(ctx, "agent-max")
	_, err = m3.CreateSession(ctx, "agent-max")
	if err == nil {
		t.Error("CreateSession should error when max sessions reached")
	}
}

func TestManager_GetSession(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	s, _ := m.CreateSession(context.Background(), a.ID)

	got, err := m.GetSession(s.ID)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if got.ID != s.ID {
		t.Errorf("GetSession ID = %v, want %v", got.ID, s.ID)
	}

	_, err = m.GetSession("nonexistent")
	if err == nil {
		t.Error("GetSession should error for missing session")
	}

	// Expire the session manually
	s.ExpiresAt = time.Now().Add(-1 * time.Hour)
	_, err = m.GetSession(s.ID)
	if err == nil {
		t.Error("GetSession should error for expired session")
	}
}

func TestManager_GetAgentSessions(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	_, _ = m.CreateSession(context.Background(), a.ID)
	_, _ = m.CreateSession(context.Background(), a.ID)

	sessions := m.GetAgentSessions(a.ID)
	if len(sessions) != 2 {
		t.Errorf("GetAgentSessions() = %d, want 2", len(sessions))
	}
}

func TestManager_RefreshSession(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	s, _ := m.CreateSession(context.Background(), a.ID)
	s.ExpiresAt = time.Now().Add(1 * time.Hour)

	if err := m.RefreshSession(s.ID); err != nil {
		t.Fatalf("RefreshSession error: %v", err)
	}
	if s.ExpiresAt.Before(time.Now().Add(2 * time.Hour)) {
		t.Error("RefreshSession should extend expiration")
	}

	if err := m.RefreshSession("nonexistent"); err == nil {
		t.Error("RefreshSession should error for missing session")
	}

	s.Active = false
	if err := m.RefreshSession(s.ID); err == nil {
		t.Error("RefreshSession should error for inactive session")
	}
}

func TestManager_InvalidateSession(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	s, _ := m.CreateSession(context.Background(), a.ID)

	if err := m.InvalidateSession(s.ID); err != nil {
		t.Fatalf("InvalidateSession error: %v", err)
	}
	if s.Active {
		t.Error("session should be inactive after invalidation")
	}

	if err := m.InvalidateSession("nonexistent"); err == nil {
		t.Error("InvalidateSession should error for missing session")
	}
}

func TestManager_InvalidateAgentSessions(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	_, _ = m.CreateSession(context.Background(), a.ID)
	_, _ = m.CreateSession(context.Background(), a.ID)

	if err := m.InvalidateAgentSessions(a.ID); err != nil {
		t.Fatalf("InvalidateAgentSessions error: %v", err)
	}

	if len(m.agentSessions) != 0 {
		t.Errorf("sessions not cleared: got %d", len(m.agentSessions))
	}
}

// ============================================================================
// AUTHORIZATION TESTS
// ============================================================================

func TestManager_AuthorizeToolCall(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)
	s, _ := m.CreateSession(context.Background(), a.ID)

	// Allowed
	res, err := m.AuthorizeToolCall(context.Background(), s.ID, "file_write")
	if err != nil {
		t.Fatalf("AuthorizeToolCall error: %v", err)
	}
	if !res.Allowed {
		t.Errorf("AuthorizeToolCall.Allowed = false, want true")
	}

	// Invalid session
	res, _ = m.AuthorizeToolCall(context.Background(), "bad-id", "file_write")
	if res.Allowed {
		t.Error("should be denied for invalid session")
	}

	// No permission
	restricted := &Agent{ID: "r-1", Name: "R", Role: AgentRoleRestricted, Enabled: true}
	_ = m.RegisterAgent(restricted)
	rs, _ := m.CreateSession(context.Background(), restricted.ID)
	res, _ = m.AuthorizeToolCall(context.Background(), rs.ID, "shell_command")
	if res.Allowed {
		t.Error("should be denied for restricted agent on privileged tool")
	}
	if res.RequiresApproval {
		t.Error("should not require approval if already denied by role")
	}

	// Agent disabled
	restricted.Enabled = false
	res, _ = m.AuthorizeToolCall(context.Background(), rs.ID, "file_read")
	if res.Allowed {
		t.Error("should be denied for disabled agent")
	}

	// High risk tool requires privileged
	a.Enabled = true
	privileged := &Agent{ID: "p-1", Name: "P", Role: AgentRolePrivileged, Enabled: true, Tools: GetPermissionsForRole(AgentRolePrivileged)}
	_ = m.RegisterAgent(privileged)
	ps, _ := m.CreateSession(context.Background(), privileged.ID)
	res, _ = m.AuthorizeToolCall(context.Background(), ps.ID, "shell_command")
	if !res.Allowed {
		t.Errorf("privileged agent should be allowed for shell_command: %s", res.Reason)
	}

	// Approval required but insufficient role
	cfg := DefaultConfig()
	cfg.RequireApproval = true
	m2, _ := NewManager(cfg)
	m2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	defer m2.Close()
	r2 := &Agent{ID: "r2", Name: "R2", Role: AgentRoleStandard, Enabled: true, Tools: []ToolPermission{PermToolShellCommand}}
	_ = m2.RegisterAgent(r2)
	rs2, _ := m2.CreateSession(context.Background(), r2.ID)
	res, _ = m2.AuthorizeToolCall(context.Background(), rs2.ID, "shell_command")
	if res.Allowed {
		t.Error("should be denied for approval-required tool when role is insufficient")
	}
	if !res.RequiresApproval {
		t.Error("should flag RequiresApproval for privileged tool needing approval")
	}
}

func TestManager_AuthorizeAgent(t *testing.T) {
	m := testManager(t)
	defer m.Close()

	a := testAgent(AgentRoleStandard)
	_ = m.RegisterAgent(a)

	res, err := m.AuthorizeAgent(context.Background(), a.ID, PermToolFileRead)
	if err != nil {
		t.Fatalf("AuthorizeAgent error: %v", err)
	}
	if !res.Allowed {
		t.Errorf("AuthorizeAgent.Allowed = false for permitted tool")
	}

	res, _ = m.AuthorizeAgent(context.Background(), a.ID, PermToolShellCommand)
	if res.Allowed {
		t.Error("should be denied for missing permission")
	}

	res, _ = m.AuthorizeAgent(context.Background(), "missing", PermToolFileRead)
	if res.Allowed {
		t.Error("should be denied for missing agent")
	}

	a.Enabled = false
	res, _ = m.AuthorizeAgent(context.Background(), a.ID, PermToolFileRead)
	if res.Allowed {
		t.Error("should be denied for disabled agent")
	}
}

// ============================================================================
// HELPER TESTS
// ============================================================================

func Test_generateID(t *testing.T) {
	id, err := generateID()
	if err != nil {
		t.Fatalf("generateID error: %v", err)
	}
	if len(id) == 0 {
		t.Error("generateID returned empty string")
	}
	id2, _ := generateID()
	if id == id2 {
		t.Error("generateID should generate unique IDs")
	}
}

func Test_truncateID(t *testing.T) {
	if got := truncateID("12345678"); got != "12345678" {
		t.Errorf("truncateID(8) = %v, want exact", got)
	}
	if got := truncateID("1234567890abcdef"); got != "12345678..." {
		t.Errorf("truncateID(16) = %v, want 12345678...", got)
	}
}

func Test_toolRequiresApproval(t *testing.T) {
	if !toolRequiresApproval("shell_command") {
		t.Error("shell_command should require approval")
	}
	if !toolRequiresApproval("bash") {
		t.Error("bash should require approval")
	}
	if !toolRequiresApproval("code_execute") {
		t.Error("code_execute should require approval")
	}
	if !toolRequiresApproval("database_query") {
		t.Error("database_query should require approval")
	}
	if toolRequiresApproval("file_write") {
		t.Error("file_write should not require approval")
	}
}

func Test_getMinimumRoleForTool(t *testing.T) {
	tests := []struct {
		tool string
		want AgentRole
	}{
		{"shell_command", AgentRolePrivileged},
		{"bash", AgentRolePrivileged},
		{"code_execute_go", AgentRolePrivileged},
		{"code_execute_python", AgentRolePrivileged},
		{"code_execute_javascript", AgentRolePrivileged},
		{"database_query", AgentRolePrivileged},
		{"file_write", AgentRoleStandard},
		{"file_delete", AgentRoleStandard},
		{"web_search", AgentRoleRestricted},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			if got := getMinimumRoleForTool(tt.tool); got != tt.want {
				t.Errorf("getMinimumRoleForTool(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}
