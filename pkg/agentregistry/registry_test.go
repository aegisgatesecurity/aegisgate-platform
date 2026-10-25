package agentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// mockRBACManager is a minimal RBAC manager for testing the Registry
// without the full RBAC stack. It implements only the methods the
// Registry uses: ListAgents, GetAgentSessions.
type mockRBACManager struct {
	agents   []*rbac.Agent
	sessions map[string][]*rbac.AgentSession // keyed by agentID
}

func (m *mockRBACManager) ListAgents() []*rbac.Agent { return m.agents }

func (m *mockRBACManager) GetAgentSessions(agentID string) []*rbac.AgentSession {
	return m.sessions[agentID]
}

// mockA2ASource is a test A2AAgentSource.
type mockA2ASource struct {
	agents []A2AAgentInfo
}

func (m *mockA2ASource) KnownAgents() []A2AAgentInfo { return m.agents }

// mockAIBOMSource is a test AIBOMSource.
type mockAIBOMSource struct {
	names      []string
	generatedAt time.Time
}

func (m *mockAIBOMSource) AgentNames() []string    { return m.names }
func (m *mockAIBOMSource) AIBOMGeneratedAt() time.Time { return m.generatedAt }

// mockCorrelationSource is a test CorrelationSource.
type mockCorrelationSource struct {
	eventCounts map[string]int64
}

func (m *mockCorrelationSource) RecentEventsByAgent(_ string, _ time.Time) ([]CorrelationEventInfo, error) {
	return nil, nil
}
func (m *mockCorrelationSource) AgentEventCount(agentID string) (int64, error) {
	return m.eventCounts[agentID], nil
}

// mockCorrelationSource is a test CorrelationSource.
// agents from the RBAC manager as the identity baseline.
func TestRegistryDiscoverFromRBAC(t *testing.T) {
	// Save and restore nowFunc
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	mockRBAC := &mockRBACManager{
		agents: []*rbac.Agent{
			{ID: "agent-1", Name: "Research Agent", Role: rbac.AgentRoleStandard, Enabled: true},
			{ID: "agent-2", Name: "Code Agent", Role: rbac.AgentRolePrivileged, Enabled: true},
		},
		sessions: map[string][]*rbac.AgentSession{},
	}

	reg, err := New(Config{
		Store: NewInMemoryStore(),
		RBAC:  nil, // will set below
	})
	if err != nil {
		// Config requires RBAC which is *rbac.Manager, not our mock.
		// We need to test with the real RBAC manager or adjust the design.
		// For now, this test documents the limitation.
		t.Skip("Registry requires *rbac.Manager concrete type; mock-based test requires interface extraction")
	}
	_ = reg
	_ = mockRBAC
}

// TestRegistryWithRealRBAC tests discovery using a real in-memory RBAC
// manager, which is how the Registry will be used in production.
func TestRegistryWithRealRBAC(t *testing.T) {
	originalNow := nowFunc
	testTime := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return testTime }
	defer func() { nowFunc = originalNow }()

	// Create a real RBAC manager (in-memory mode)
	rbacMgr, _ := (rbac.NewManager(nil))

	// Register agents
	agent1 := &rbac.Agent{
		ID:      "research-agent",
		Name:    "Research Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	}
	agent2 := &rbac.Agent{
		ID:      "code-agent",
		Name:    "Code Agent",
		Role:    rbac.AgentRolePrivileged,
		Enabled: true,
	}
	_ = rbacMgr.RegisterAgent(agent1)
	_ = rbacMgr.RegisterAgent(agent2)

	// Create registry
	reg, err := New(Config{
		Store:       NewInMemoryStore(),
		RBAC:        rbacMgr,
		A2ASource:   &mockA2ASource{agents: []A2AAgentInfo{{AgentID: "research-agent"}}},
		AIBOMSource: &mockAIBOMSource{names: []string{"research-agent", "code-agent"}},
		Correlation: &mockCorrelationSource{eventCounts: map[string]int64{"research-agent": 42}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Run discovery
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// Verify agent-1
	got1, err := reg.Get("research-agent")
	if err != nil {
		t.Fatalf("Get research-agent failed: %v", err)
	}
	if got1.Name != "Research Agent" {
		t.Errorf("Name = %q, want %q", got1.Name, "Research Agent")
	}
	if got1.Role != string(rbac.AgentRoleStandard) {
		t.Errorf("Role = %q, want %q", got1.Role, rbac.AgentRoleStandard)
	}
	if !got1.InAIBOM {
		t.Error("research-agent should be in AIBOM")
	}
	if !hasProtocol(got1.Protocols, ProtocolA2A) {
		t.Error("research-agent should have A2A protocol")
	}
	if got1.TotalEvents != 42 {
		t.Errorf("TotalEvents = %d, want 42", got1.TotalEvents)
	}
	if !contains(got1.DiscoverySources, "rbac") {
		t.Error("research-agent should have rbac as discovery source")
	}
	if !contains(got1.DiscoverySources, "a2a") {
		t.Error("research-agent should have a2a as discovery source")
	}
	if !contains(got1.DiscoverySources, "correlation") {
		t.Error("research-agent should have correlation as discovery source")
	}

	// Verify agent-2
	got2, err := reg.Get("code-agent")
	if err != nil {
		t.Fatalf("Get code-agent failed: %v", err)
	}
	if got2.Name != "Code Agent" {
		t.Errorf("Name = %q, want %q", got2.Name, "Code Agent")
	}
	if !got2.InAIBOM {
		t.Error("code-agent should be in AIBOM")
	}
	if hasProtocol(got2.Protocols, ProtocolA2A) {
		t.Error("code-agent should NOT have A2A protocol")
	}
}

// TestRegistryTransition verifies manual lifecycle transitions.
func TestRegistryTransition(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := (rbac.NewManager(nil))
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "test-agent",
		Name:    "Test",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	reg, _ := New(Config{
		Store: NewInMemoryStore(),
		RBAC:  rbacMgr,
	})
	_ = reg.Discover(context.Background())

	// Should start as provisioned (no activity)
	got, _ := reg.Get("test-agent")
	if got.Status != StatusProvisioned {
		t.Errorf("initial status = %q, want %q", got.Status, StatusProvisioned)
	}

	// Transition to active
	if err := reg.Transition("test-agent", StatusActive, "test"); err != nil {
		t.Fatalf("Transition to active failed: %v", err)
	}
	got, _ = reg.Get("test-agent")
	if got.Status != StatusActive {
		t.Errorf("status after transition = %q, want %q", got.Status, StatusActive)
	}

	// Transition to dormant
	_ = reg.Transition("test-agent", StatusDormant, "test")
	got, _ = reg.Get("test-agent")
	if got.Status != StatusDormant {
		t.Errorf("status after transition = %q, want %q", got.Status, StatusDormant)
	}
	if got.DormantSince.IsZero() {
		t.Error("DormantSince should be set when transitioning to dormant")
	}

	// Transition back to active should clear DormantSince
	_ = reg.Transition("test-agent", StatusActive, "test")
	got, _ = reg.Get("test-agent")
	if !got.DormantSince.IsZero() {
		t.Error("DormantSince should be cleared when transitioning to active")
	}

	// No-op transition (same status)
	err := reg.Transition("test-agent", StatusActive, "test")
	if err != nil {
		t.Errorf("same-status transition should be no-op, got error: %v", err)
	}

	// Transition non-existent agent
	err = reg.Transition("nonexistent", StatusActive, "test")
	if err == nil {
		t.Error("Transition non-existent agent should fail")
	}
}

// TestRegistryLifecycleEvent verifies that the lifecycle event callback
// is invoked on status transitions.
func TestRegistryLifecycleEvent(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := (rbac.NewManager(nil))
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "test-agent",
		Name:    "Test",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	reg, _ := New(Config{
		Store: NewInMemoryStore(),
		RBAC:  rbacMgr,
	})
	_ = reg.Discover(context.Background())

	var events []LifecycleEvent
	reg.SetLifecycleEventCallback(func(e LifecycleEvent) {
		events = append(events, e)
	})

	_ = reg.Transition("test-agent", StatusActive, "test")
	_ = reg.Transition("test-agent", StatusDormant, "test")
	_ = reg.Transition("test-agent", StatusQuarantined, "test")

	if len(events) != 3 {
		t.Fatalf("expected 3 lifecycle events, got %d", len(events))
	}

	if events[0].OldStatus != StatusProvisioned || events[0].NewStatus != StatusActive {
		t.Errorf("event 0: %s → %s, want %s → %s",
			events[0].OldStatus, events[0].NewStatus, StatusProvisioned, StatusActive)
	}
	if events[1].OldStatus != StatusActive || events[1].NewStatus != StatusDormant {
		t.Errorf("event 1: %s → %s, want %s → %s",
			events[1].OldStatus, events[1].NewStatus, StatusActive, StatusDormant)
	}
	if events[2].OldStatus != StatusDormant || events[2].NewStatus != StatusQuarantined {
		t.Errorf("event 2: %s → %s, want %s → %s",
			events[2].OldStatus, events[2].NewStatus, StatusDormant, StatusQuarantined)
	}
}

// TestRegistryReconcile verifies AIBOM-to-runtime drift detection.
func TestRegistryReconcile(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := (rbac.NewManager(nil))
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "agent-a", Name: "Agent A", Role: rbac.AgentRoleStandard, Enabled: true})
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "agent-b", Name: "Agent B", Role: rbac.AgentRoleStandard, Enabled: true})

	// AIBOM declares agent-a and agent-c (but agent-c is not running)
	reg, _ := New(Config{
		Store:       NewInMemoryStore(),
		RBAC:        rbacMgr,
		AIBOMSource: &mockAIBOMSource{names: []string{"agent-a", "agent-c"}},
	})
	_ = reg.Discover(context.Background())

	report, err := reg.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// agent-a: in both AIBOM and runtime → matched
	if report.Matched != 1 {
		t.Errorf("Matched = %d, want 1", report.Matched)
	}

	// agent-b: in runtime but not AIBOM → active_not_in_aibom
	if len(report.ActiveNotInAIBOM) != 1 {
		t.Errorf("ActiveNotInAIBOM = %d, want 1", len(report.ActiveNotInAIBOM))
	} else {
		if report.ActiveNotInAIBOM[0].AgentID != "agent-b" {
			t.Errorf("ActiveNotInAIBOM[0].AgentID = %q, want %q", report.ActiveNotInAIBOM[0].AgentID, "agent-b")
		}
	}

	// agent-c: in AIBOM but not runtime → in_aibom_not_active
	if len(report.InAIBOMNotActive) != 1 {
		t.Errorf("InAIBOMNotActive = %d, want 1", len(report.InAIBOMNotActive))
	} else {
		if report.InAIBOMNotActive[0].AgentID != "agent-c" {
			t.Errorf("InAIBOMNotActive[0].AgentID = %q, want %q", report.InAIBOMNotActive[0].AgentID, "agent-c")
		}
	}
}

// TestRegistryListByStatus verifies filtering by lifecycle status.
func TestRegistryListByStatus(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := (rbac.NewManager(nil))
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "a1", Name: "A1", Role: rbac.AgentRoleStandard, Enabled: true})
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "a2", Name: "A2", Role: rbac.AgentRoleStandard, Enabled: true})
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "a3", Name: "A3", Role: rbac.AgentRoleStandard, Enabled: true})

	reg, _ := New(Config{
		Store: NewInMemoryStore(),
		RBAC:  rbacMgr,
	})
	_ = reg.Discover(context.Background())

	// All should be provisioned initially
	provisioned, _ := reg.ListByStatus(StatusProvisioned)
	if len(provisioned) != 3 {
		t.Errorf("provisioned count = %d, want 3", len(provisioned))
	}

	// Transition one to active
	_ = reg.Transition("a1", StatusActive, "test")

	active, _ := reg.ListByStatus(StatusActive)
	if len(active) != 1 {
		t.Errorf("active count = %d, want 1", len(active))
	}
	provisioned, _ = reg.ListByStatus(StatusProvisioned)
	if len(provisioned) != 2 {
		t.Errorf("provisioned count = %d, want 2", len(provisioned))
	}
}

// TestRegistryNewValidation verifies that New rejects invalid configs.
func TestRegistryNewValidation(t *testing.T) {
	// Nil store
	_, err := New(Config{
		Store: nil,
		RBAC:  func() *rbac.Manager { m, _ := rbac.NewManager(nil); return m }(),
	})
	if err == nil {
		t.Error("New with nil Store should fail")
	}

	// Nil RBAC
	_, err = New(Config{
		Store: NewInMemoryStore(),
		RBAC:  nil,
	})
	if err == nil {
		t.Error("New with nil RBAC should fail")
	}

	// Valid config
	_, err = New(Config{
		Store: NewInMemoryStore(),
		RBAC:  func() *rbac.Manager { m, _ := rbac.NewManager(nil); return m }(),
	})
	if err != nil {
		t.Errorf("New with valid config should succeed, got: %v", err)
	}
}

// TestRegistryStartStop verifies the background refresh goroutine
// lifecycle.
func TestRegistryStartStop(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := (rbac.NewManager(nil))
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "test", Name: "Test", Role: rbac.AgentRoleStandard, Enabled: true})

	reg, _ := New(Config{
		Store:           NewInMemoryStore(),
		RBAC:            rbacMgr,
		RefreshInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := reg.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Double start should fail
	if err := reg.Start(ctx); err == nil {
		t.Error("Double Start should fail")
	}

	// Wait for at least one refresh cycle
	time.Sleep(250 * time.Millisecond)

	// Stop
	reg.Stop()

	// Double stop should be safe
	reg.Stop()
}