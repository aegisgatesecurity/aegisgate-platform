package agentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// mockExecutor records all actions for verification.
type mockExecutor struct {
	notifications []string
	playbooks     []string
	quarantines   []string
	revocations   []string
	tags          map[string]string
	failOnAction  string
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{tags: make(map[string]string)}
}

func (m *mockExecutor) Notify(_ context.Context, agentID string, _ PolicyAction) error {
	m.notifications = append(m.notifications, agentID)
	return nil
}

func (m *mockExecutor) TriggerPlaybook(_ context.Context, agentID, playbookID string, _ map[string]string) error {
	m.playbooks = append(m.playbooks, agentID+":"+playbookID)
	return nil
}

func (m *mockExecutor) Quarantine(_ context.Context, agentID string) error {
	if m.failOnAction == "quarantine" {
		return errMock{}
	}
	m.quarantines = append(m.quarantines, agentID)
	return nil
}

func (m *mockExecutor) Revoke(_ context.Context, agentID string) error {
	if m.failOnAction == "revoke" {
		return errMock{}
	}
	m.revocations = append(m.revocations, agentID)
	return nil
}

func (m *mockExecutor) Tag(_ context.Context, agentID, key, value string) error {
	m.tags[agentID+":"+key] = value
	return nil
}

type errMock struct{}

func (errMock) Error() string { return "mock error" }

func TestPolicyEnforce(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	// Set up RBAC with an agent
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "dormant-agent",
		Name:    "Dormant Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	policyStore := NewInMemoryPolicyStore()

	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Manually set the agent's last activity to 65 days ago (dormant)
	record, _ := reg.Get("dormant-agent")
	record.LastActivity = nowFunc().Add(-65 * 24 * time.Hour)
	_ = store.Upsert(context.Background(), record)

	// Create a dormancy policy
	policy := &LifecyclePolicy{
		ID:                "test-policy",
		Name:              "Test Dormancy",
		Enabled:           true,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant: []PolicyAction{
			{Type: "notify", Target: "email"},
			{Type: "tag", Target: "flagged-for-review=true"},
		},
	}
	_ = policyStore.UpsertPolicy(context.Background(), policy)

	executor := newMockExecutor()
	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	engine := NewPolicyEngine(reg, dormancy, executor, policyStore, nil)

	results, err := engine.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	// Should have 2 actions: notify + tag
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify notify was called
	if len(executor.notifications) != 1 || executor.notifications[0] != "dormant-agent" {
		t.Errorf("notifications = %v, want [dormant-agent]", executor.notifications)
	}

	// Verify tag was set
	if executor.tags["dormant-agent:flagged-for-review"] != "true" {
		t.Errorf("tag not set correctly: %v", executor.tags)
	}

	// Verify agent status was transitioned to dormant
	updated, _ := reg.Get("dormant-agent")
	if updated.Status != StatusDormant {
		t.Errorf("agent status = %q, want %q", updated.Status, StatusDormant)
	}
}

func TestPolicyEnforceQuarantineAndRevoke(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "old-agent", Name: "Old", Role: rbac.AgentRoleStandard, Enabled: true})

	store := NewInMemoryStore()
	policyStore := NewInMemoryPolicyStore()

	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Set agent activity to 91 days ago (exceeds auto-revoke)
	record, _ := reg.Get("old-agent")
	record.LastActivity = nowFunc().Add(-91 * 24 * time.Hour)
	_ = store.Upsert(context.Background(), record)

	policy := &LifecyclePolicy{
		ID:                  "strict-policy",
		Name:                "Strict",
		Enabled:             true,
		DormancyThreshold:   60 * 24 * time.Hour,
		QuarantineThreshold: 75 * 24 * time.Hour,
		AutoRevokeThreshold: 90 * 24 * time.Hour,
		OnRevoke: []PolicyAction{
			{Type: "revoke"},
			{Type: "notify", Target: "pagerduty"},
		},
	}
	_ = policyStore.UpsertPolicy(context.Background(), policy)

	executor := newMockExecutor()
	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	engine := NewPolicyEngine(reg, dormancy, executor, policyStore, nil)

	results, err := engine.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	// Should execute revoke + notify
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify revoke was called
	if len(executor.revocations) != 1 || executor.revocations[0] != "old-agent" {
		t.Errorf("revocations = %v, want [old-agent]", executor.revocations)
	}

	// Verify agent status transitioned to revoked
	updated, _ := reg.Get("old-agent")
	if updated.Status != StatusRevoked {
		t.Errorf("agent status = %q, want %q", updated.Status, StatusRevoked)
	}
}

func TestPolicyEnforceNoActionsWhenActive(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "active-agent", Name: "Active", Role: rbac.AgentRoleStandard, Enabled: true})

	store := NewInMemoryStore()
	policyStore := NewInMemoryPolicyStore()

	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Agent has recent activity (1 hour ago)
	record, _ := reg.Get("active-agent")
	record.LastActivity = nowFunc().Add(-1 * time.Hour)
	_ = store.Upsert(context.Background(), record)

	policy := &LifecyclePolicy{
		ID:                "test",
		Name:              "Test",
		Enabled:           true,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant:         []PolicyAction{{Type: "notify"}},
	}
	_ = policyStore.UpsertPolicy(context.Background(), policy)

	executor := newMockExecutor()
	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	engine := NewPolicyEngine(reg, dormancy, executor, policyStore, nil)

	results, err := engine.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for active agent, got %d", len(results))
	}
}

func TestPolicyEnforceDisabledPolicy(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "agent", Name: "Agent", Role: rbac.AgentRoleStandard, Enabled: true})

	store := NewInMemoryStore()
	policyStore := NewInMemoryPolicyStore()

	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Agent is dormant but policy is disabled
	record, _ := reg.Get("agent")
	record.LastActivity = nowFunc().Add(-65 * 24 * time.Hour)
	_ = store.Upsert(context.Background(), record)

	policy := &LifecyclePolicy{
		ID:                "disabled",
		Name:              "Disabled",
		Enabled:           false,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant:         []PolicyAction{{Type: "notify"}},
	}
	_ = policyStore.UpsertPolicy(context.Background(), policy)

	executor := newMockExecutor()
	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	engine := NewPolicyEngine(reg, dormancy, executor, policyStore, nil)

	results, _ := engine.Enforce(context.Background())

	if len(results) != 0 {
		t.Errorf("disabled policy should produce 0 results, got %d", len(results))
	}
}

func TestPolicyFilters(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	// Test that policy filters correctly match/exclude agents
	record := &AgentRecord{
		ID:        "agent-1",
		Role:      "standard",
		TenantID:  "tenant-a",
		Protocols: []Protocol{ProtocolMCP, ProtocolA2A},
		Tags:      map[string]string{"env": "prod", "team": "research"},
	}

	tests := []struct {
		name    string
		filters *PolicyFilters
		want    bool
	}{
		{"nil filters", nil, true},
		{"matching protocol", &PolicyFilters{Protocols: []Protocol{ProtocolMCP}}, true},
		{"non-matching protocol", &PolicyFilters{Protocols: []Protocol{ProtocolHTTP}}, false},
		{"matching role", &PolicyFilters{Roles: []string{"standard"}}, true},
		{"non-matching role", &PolicyFilters{Roles: []string{"admin"}}, false},
		{"matching tag", &PolicyFilters{Tags: map[string]string{"env": "prod"}}, true},
		{"non-matching tag", &PolicyFilters{Tags: map[string]string{"env": "dev"}}, false},
		{"matching tenant", &PolicyFilters{TenantIDs: []string{"tenant-a"}}, true},
		{"non-matching tenant", &PolicyFilters{TenantIDs: []string{"tenant-b"}}, false},
		{"multi-match (all match)", &PolicyFilters{Protocols: []Protocol{ProtocolMCP}, Roles: []string{"standard"}, Tags: map[string]string{"env": "prod"}}, true},
		{"multi-match (one fails)", &PolicyFilters{Protocols: []Protocol{ProtocolMCP}, Roles: []string{"admin"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &LifecyclePolicy{Filters: tt.filters}
			got := policyMatches(record, policy)
			if got != tt.want {
				t.Errorf("policyMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyCRUD(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	reg, _ := New(Config{Store: NewInMemoryStore(), RBAC: rbacMgr})
	policyStore := NewInMemoryPolicyStore()
	engine := NewPolicyEngine(reg, NewDormancyEngine(60*24*time.Hour, nil), newMockExecutor(), policyStore, nil)

	ctx := context.Background()

	// Add
	policy := &LifecyclePolicy{
		ID:                "p1",
		Name:              "Test",
		Enabled:           true,
		DormancyThreshold: 30 * 24 * time.Hour,
	}
	if err := engine.AddPolicy(ctx, policy); err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}

	// List
	policies, err := engine.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("ListPolicies returned %d, want 1", len(policies))
	}

	// Update
	policy.Name = "Updated"
	_ = engine.AddPolicy(ctx, policy)
	policies, _ = engine.ListPolicies(ctx)
	if policies[0].Name != "Updated" {
		t.Errorf("Name after update = %q, want %q", policies[0].Name, "Updated")
	}

	// Remove
	if err := engine.RemovePolicy(ctx, "p1"); err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}
	policies, _ = engine.ListPolicies(ctx)
	if len(policies) != 0 {
		t.Errorf("ListPolicies after remove = %d, want 0", len(policies))
	}
}

func TestParseTagTarget(t *testing.T) {
	tests := []struct {
		target   string
		wantKey  string
		wantVal  string
	}{
		{"flagged=true", "flagged", "true"},
		{"env=prod", "env", "prod"},
		{"noequals", "noequals", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			k, v := parseTagTarget(tt.target)
			if k != tt.wantKey || v != tt.wantVal {
				t.Errorf("parseTagTarget(%q) = (%q, %q), want (%q, %q)",
					tt.target, k, v, tt.wantKey, tt.wantVal)
			}
		})
	}
}