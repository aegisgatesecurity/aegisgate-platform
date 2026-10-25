// SPDX-License-Identifier: Apache-2.0
package agentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/a2a"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// --- A2AAdapter Tests ---

func TestNewA2AAdapter_Nil(t *testing.T) {
	a := NewA2AAdapter(nil)
	if a == nil {
		t.Fatal("NewA2AAdapter returned nil")
	}
	agents := a.KnownAgents()
	if agents != nil {
		t.Errorf("KnownAgents with nil caps = %v; want nil", agents)
	}
}

func TestNewA2AAdapter_WithCaps(t *testing.T) {
	caps := a2a.NewInMemoryCapEnforcer()
	caps.SetCapabilities("agent-a", []string{"tool:read", "tool:write"})
	caps.SetCapabilities("agent-b", []string{"tool:read"})

	a := NewA2AAdapter(caps)
	agents := a.KnownAgents()
	if len(agents) != 2 {
		t.Fatalf("KnownAgents returned %d agents; want 2", len(agents))
	}

	found := make(map[string][]string)
	for _, ai := range agents {
		found[ai.AgentID] = ai.Capabilities
	}
	if len(found["agent-a"]) != 2 {
		t.Errorf("agent-a caps = %v; want 2", found["agent-a"])
	}
	if len(found["agent-b"]) != 1 {
		t.Errorf("agent-b caps = %v; want 1", found["agent-b"])
	}
}

func TestNewA2AAdapter_PersistentEnforcer(t *testing.T) {
	tmpDir := t.TempDir()
	capsFile := tmpDir + "/caps.json"
	pc, err := a2a.NewPersistentCapEnforcer(capsFile)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer: %v", err)
	}
	pc.SetCapabilities("agent-p1", []string{"tool:exec"})

	a := NewA2AAdapter(pc)
	agents := a.KnownAgents()
	if len(agents) != 1 {
		t.Fatalf("KnownAgents returned %d; want 1", len(agents))
	}
	if agents[0].AgentID != "agent-p1" {
		t.Errorf("AgentID = %q; want agent-p1", agents[0].AgentID)
	}
	if len(agents[0].Capabilities) != 1 {
		t.Errorf("Capabilities = %v; want 1", agents[0].Capabilities)
	}
}

func TestA2AAdapter_KnownAgents_Empty(t *testing.T) {
	caps := a2a.NewInMemoryCapEnforcer()
	a := NewA2AAdapter(caps)
	agents := a.KnownAgents()
	if len(agents) != 0 {
		t.Errorf("KnownAgents on empty enforcer = %d; want 0", len(agents))
	}
}

// --- CorrelationAdapter Tests ---

func TestNewCorrelationAdapter_Nil(t *testing.T) {
	a := NewCorrelationAdapter(nil)
	if a == nil {
		t.Fatal("NewCorrelationAdapter returned nil")
	}
	events, err := a.RecentEventsByAgent("agent-x", time.Now().Add(-time.Hour))
	if err == nil && len(events) != 0 {
		t.Errorf("RecentEventsByAgent with nil engine = %v; want empty", events)
	}
	count, err := a.AgentEventCount("agent-x")
	if err == nil && count != 0 {
		t.Errorf("AgentEventCount with nil engine = %d; want 0", count)
	}
}

func TestNewCorrelationAdapter_WithEngine(t *testing.T) {
	engine := correlation.NewEngine()
	a := NewCorrelationAdapter(engine)

	since := time.Now().Add(-time.Hour)
	events, err := a.RecentEventsByAgent("agent-none", since)
	if err != nil {
		t.Fatalf("RecentEventsByAgent error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("RecentEventsByAgent on empty engine = %d; want 0", len(events))
	}
	count, err := a.AgentEventCount("agent-none")
	if err != nil {
		t.Fatalf("AgentEventCount error: %v", err)
	}
	if count != 0 {
		t.Errorf("AgentEventCount on empty engine = %d; want 0", count)
	}
}

func TestCorrelationAdapter_WithEvents(t *testing.T) {
	engine := correlation.NewEngine()
	evt := correlation.NewEvent("mcp", "tool_call", "agent-test", "sess-1")
	evt.Severity = "high"
	_ = engine.RecordEvent(context.Background(), evt)

	a := NewCorrelationAdapter(engine)

	count, err := a.AgentEventCount("agent-test")
	if err != nil {
		t.Fatalf("AgentEventCount error: %v", err)
	}
	if count != 1 {
		t.Errorf("AgentEventCount = %d; want 1", count)
	}

	events, err := a.RecentEventsByAgent("agent-test", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("RecentEventsByAgent error: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("RecentEventsByAgent = %d; want 1", len(events))
	}
	if events[0].EventType != "tool_call" {
		t.Errorf("Event EventType = %q; want tool_call", events[0].EventType)
	}
}

func TestCorrelationAdapter_WithEvents_OldSinceFilter(t *testing.T) {
	engine := correlation.NewEngine()
	evt := correlation.NewEvent("mcp", "tool_call", "agent-test", "sess-1")
	_ = engine.RecordEvent(context.Background(), evt)

	a := NewCorrelationAdapter(engine)
	// Use a future "since" — should return 0 events.
	events, err := a.RecentEventsByAgent("agent-test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("RecentEventsByAgent error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("RecentEventsByAgent with future since = %d; want 0", len(events))
	}
}

// --- AIBOMAdapter Tests ---

func TestNewAIBOMAdapter_Nil(t *testing.T) {
	a := NewAIBOMAdapter(nil)
	if a == nil {
		t.Fatal("NewAIBOMAdapter returned nil")
	}
	names := a.AgentNames()
	if names != nil {
		t.Errorf("AgentNames with nil AIBOM = %v; want nil", names)
	}
	ts := a.AIBOMGeneratedAt()
	if !ts.IsZero() {
		t.Errorf("AIBOMGeneratedAt with nil AIBOM = %v; want zero", ts)
	}
}

func TestNewAIBOMAdapter_WithData(t *testing.T) {
	now := time.Now().UTC()
	aibomData := &aibom.AIBOM{
		GeneratedAt: now,
		A2A: aibom.A2AComponent{
			AgentNames: []string{"agent-alpha", "agent-beta"},
		},
	}

	a := NewAIBOMAdapter(aibomData)

	names := a.AgentNames()
	if len(names) != 2 {
		t.Fatalf("AgentNames = %d; want 2", len(names))
	}
	if names[0] != "agent-alpha" {
		t.Errorf("names[0] = %q; want agent-alpha", names[0])
	}
	if names[1] != "agent-beta" {
		t.Errorf("names[1] = %q; want agent-beta", names[1])
	}

	ts := a.AIBOMGeneratedAt()
	if !ts.Equal(now) {
		t.Errorf("AIBOMGeneratedAt = %v; want %v", ts, now)
	}
}

func TestNewAIBOMAdapter_EmptyAgentNames(t *testing.T) {
	aibomData := &aibom.AIBOM{
		GeneratedAt: time.Now(),
	}
	a := NewAIBOMAdapter(aibomData)
	names := a.AgentNames()
	if len(names) != 0 {
		t.Errorf("AgentNames with empty A2A = %d; want 0", len(names))
	}
}

// --- extractMCPActivity Tests ---

func TestExtractMCPActivity_Nil(t *testing.T) {
	activity := extractMCPActivity(nil)
	if len(activity) != 0 {
		t.Errorf("extractMCPActivity(nil) = %d; want 0", len(activity))
	}
}

func TestExtractMCPProtocolCount_Nil(t *testing.T) {
	count := extractMCPProtocolCount(nil, "agent-x")
	if count != 0 {
		t.Errorf("extractMCPProtocolCount(nil) = %d; want 0", count)
	}
}
// =====================================================================
// extractMCPActivity / extractMCPProtocolCount — with real sessions
// =====================================================================

// TestExtractMCPActivity_WithSessions verifies activity extraction
// from real MCP sessions.
func TestExtractMCPActivity_WithSessions(t *testing.T) {
	rbacMgr, err := rbac.NewManager(nil)
	if err != nil {
		t.Fatalf("rbac.NewManager: %v", err)
	}
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "mcp-act-1", Name: "Act1", Role: rbac.AgentRoleStandard, Enabled: true})
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "mcp-act-2", Name: "Act2", Role: rbac.AgentRoleStandard, Enabled: true})

	sm := mcpserver.NewConnectionSessionManager(rbacMgr)
	ctx := context.Background()

	_, err = sm.CreateSession(ctx, "conn-a1", "mcp-act-1")
	if err != nil {
		t.Fatalf("CreateSession(conn-a1): %v", err)
	}
	_, err = sm.CreateSession(ctx, "conn-a2", "mcp-act-1")
	if err != nil {
		t.Fatalf("CreateSession(conn-a2): %v", err)
	}
	_, err = sm.CreateSession(ctx, "conn-b1", "mcp-act-2")
	if err != nil {
		t.Fatalf("CreateSession(conn-b1): %v", err)
	}

	activity := extractMCPActivity(sm)
	if len(activity) != 2 {
		t.Fatalf("len(activity) = %d, want 2", len(activity))
	}

	// Find each agent in the results
	found := make(map[string]bool)
	for _, a := range activity {
		found[a.AgentID] = true
		if a.Active != true {
			t.Errorf("agent %s: Active = false, want true", a.AgentID)
		}
		if a.LastActivity.IsZero() {
			t.Errorf("agent %s: LastActivity is zero", a.AgentID)
		}
	}
	if !found["mcp-act-1"] {
		t.Error("mcp-act-1 not found in activity")
	}
	if !found["mcp-act-2"] {
		t.Error("mcp-act-2 not found in activity")
	}
}

// TestExtractMCPActivity_NoSessions verifies that an empty session
// manager returns an empty (but non-nil) slice.
func TestExtractMCPActivity_NoSessions(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	sm := mcpserver.NewConnectionSessionManager(rbacMgr)

	activity := extractMCPActivity(sm)
	if len(activity) != 0 {
		t.Errorf("len(activity) = %d, want 0", len(activity))
	}
}

// TestExtractMCPProtocolCount_WithSessions verifies protocol counting.
func TestExtractMCPProtocolCount_WithSessions(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "count-agent", Name: "Count", Role: rbac.AgentRoleStandard, Enabled: true})

	sm := mcpserver.NewConnectionSessionManager(rbacMgr)
	ctx := context.Background()

	_, _ = sm.CreateSession(ctx, "conn-c1", "count-agent")
	_, _ = sm.CreateSession(ctx, "conn-c2", "count-agent")
	_, _ = sm.CreateSession(ctx, "conn-c3", "count-agent")

	count := extractMCPProtocolCount(sm, "count-agent")
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

// TestExtractMCPProtocolCount_AgentNotInSessions verifies that an
// agent with no sessions returns 0.
func TestExtractMCPProtocolCount_AgentNotInSessions(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "has-sessions", Name: "Has", Role: rbac.AgentRoleStandard, Enabled: true})

	sm := mcpserver.NewConnectionSessionManager(rbacMgr)
	_, _ = sm.CreateSession(context.Background(), "conn-x1", "has-sessions")

	count := extractMCPProtocolCount(sm, "no-sessions-agent")
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

// TestRBACAgentToRecord verifies the conversion from RBAC agent to
// agent registry record.
func TestRBACAgentToRecord(t *testing.T) {
	now := time.Now().UTC()
	agent := &rbac.Agent{
		ID:          "convert-agent",
		Name:        "Convert",
		Description: "Test conversion",
		Role:        rbac.AgentRolePrivileged,
		Tools:       []rbac.ToolPermission{"read", "write"},
		Enabled:     true,
		TenantID:    "tenant-x",
		Tags:        map[string]string{"env": "test"},
		CreatedAt:   now,
	}

	record := rbacAgentToRecord(agent)
	if record.ID != "convert-agent" {
		t.Errorf("ID = %q, want %q", record.ID, "convert-agent")
	}
	if record.Name != "Convert" {
		t.Errorf("Name = %q, want %q", record.Name, "Convert")
	}
	if record.Description != "Test conversion" {
		t.Errorf("Description = %q, want %q", record.Description, "Test conversion")
	}
	if record.Role != string(rbac.AgentRolePrivileged) {
		t.Errorf("Role = %q, want %q", record.Role, rbac.AgentRolePrivileged)
	}
	if len(record.Tools) != 2 {
		t.Errorf("Tools len = %d, want 2", len(record.Tools))
	}
	if record.Tools[0] != "read" || record.Tools[1] != "write" {
		t.Errorf("Tools = %v, want [read write]", record.Tools)
	}
	if !record.Enabled {
		t.Error("Enabled should be true")
	}
	if record.TenantID != "tenant-x" {
		t.Errorf("TenantID = %q, want %q", record.TenantID, "tenant-x")
	}
	if record.Tags["env"] != "test" {
		t.Errorf("Tags[env] = %q, want %q", record.Tags["env"], "test")
	}
	if record.Status != StatusProvisioned {
		t.Errorf("Status = %q, want %q", record.Status, StatusProvisioned)
	}
	if !contains(record.DiscoverySources, "rbac") {
		t.Error("DiscoverySources should contain rbac")
	}
	if record.CreatedAt != now {
		t.Errorf("CreatedAt = %v, want %v", record.CreatedAt, now)
	}
}

// TestRBACAgentToRecord_NoTools verifies conversion with no tools.
func TestRBACAgentToRecord_NoTools(t *testing.T) {
	agent := &rbac.Agent{
		ID:   "no-tools-agent",
		Name: "No Tools",
		Role: rbac.AgentRoleRestricted,
	}

	record := rbacAgentToRecord(agent)
	if len(record.Tools) != 0 {
		t.Errorf("Tools len = %d, want 0", len(record.Tools))
	}
}

// =====================================================================
// AgentEventCount error path
// =====================================================================

// TestCorrelationAdapter_AgentEventCount_Error verifies that the adapter
// propagates errors from the correlation engine.
func TestCorrelationAdapter_AgentEventCount_Error(t *testing.T) {
	// Create a real correlation engine — ListEventsByAgent returns
	// an error when agentID is empty.
	engine := correlation.NewEngine()
	adapter := NewCorrelationAdapter(engine)

	_, err := adapter.AgentEventCount("")
	if err == nil {
		t.Error("AgentEventCount(empty) should return error")
	}
}

// TestCorrelationAdapter_AgentEventCount_NilEngine verifies that a nil
// engine returns 0 with no error.
func TestCorrelationAdapter_AgentEventCount_NilEngine(t *testing.T) {
	adapter := NewCorrelationAdapter(nil)
	count, err := adapter.AgentEventCount("agent-x")
	if err != nil {
		t.Errorf("AgentEventCount with nil engine: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}
