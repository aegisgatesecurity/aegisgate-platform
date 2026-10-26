// SPDX-License-Identifier: Apache-2.0
package agentregistry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// =====================================================================
// Error-injecting Store and PolicyStore implementations for coverage
// =====================================================================

// errorStore wraps an InMemoryStore but can fail on specific operations.
type errorStore struct {
	inner      *InMemoryStore
	failUpsert bool
	failList   bool
	failGet    bool
	mu         sync.Mutex
}

func (s *errorStore) Get(ctx context.Context, agentID string) (*AgentRecord, error) {
	s.mu.Lock()
	fail := s.failGet
	s.mu.Unlock()
	if fail {
		return nil, fmt.Errorf("mock: get failed")
	}
	return s.inner.Get(ctx, agentID)
}

func (s *errorStore) List(ctx context.Context, filter *ListFilter) ([]*AgentRecord, error) {
	s.mu.Lock()
	fail := s.failList
	s.mu.Unlock()
	if fail {
		return nil, fmt.Errorf("mock: list failed")
	}
	return s.inner.List(ctx, filter)
}

func (s *errorStore) Upsert(ctx context.Context, record *AgentRecord) error {
	s.mu.Lock()
	fail := s.failUpsert
	s.mu.Unlock()
	if fail {
		return fmt.Errorf("mock: upsert failed")
	}
	return s.inner.Upsert(ctx, record)
}

func (s *errorStore) Delete(ctx context.Context, agentID string) error {
	return s.inner.Delete(ctx, agentID)
}

func (s *errorStore) Close() error { return s.inner.Close() }

// errorPolicyStore wraps an InMemoryPolicyStore but can fail on ListPolicies.
type errorPolicyStore struct {
	inner          *InMemoryPolicyStore
	failList       bool
	failListCalled bool
}

func (s *errorPolicyStore) GetPolicy(ctx context.Context, id string) (*LifecyclePolicy, error) {
	return s.inner.GetPolicy(ctx, id)
}

func (s *errorPolicyStore) ListPolicies(ctx context.Context) ([]*LifecyclePolicy, error) {
	if s.failList {
		s.failListCalled = true
		return nil, fmt.Errorf("mock: list policies failed")
	}
	return s.inner.ListPolicies(ctx)
}

func (s *errorPolicyStore) UpsertPolicy(ctx context.Context, p *LifecyclePolicy) error {
	return s.inner.UpsertPolicy(ctx, p)
}

func (s *errorPolicyStore) DeletePolicy(ctx context.Context, id string) error {
	return s.inner.DeletePolicy(ctx, id)
}

func (s *errorPolicyStore) Close() error { return s.inner.Close() }

// =====================================================================
// nonFlusherRW is an http.ResponseWriter that does NOT implement
// http.Flusher, used to test the HandleSSE streaming-unsupported path.
// =====================================================================

type nonFlusherRW struct {
	header http.Header
	body   []byte
	status int
}

func (w *nonFlusherRW) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *nonFlusherRW) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *nonFlusherRW) WriteHeader(code int) { w.status = code }

// =====================================================================
// DormancyEngine coverage gaps
// =====================================================================

func TestDormancyEvaluate_NilRecord(t *testing.T) {
	engine := NewDormancyEngine(60*24*time.Hour, nil)
	status, dur := engine.Evaluate(nil, nil)
	if status != StatusProvisioned {
		t.Errorf("Evaluate(nil) status = %s; want %s", status, StatusProvisioned)
	}
	if dur != 0 {
		t.Errorf("Evaluate(nil) duration = %v; want 0", dur)
	}
}

func TestDormancyClassify_Revoked(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	engine := NewDormancyEngine(60*24*time.Hour, nil)
	policy := &LifecyclePolicy{
		AutoRevokeThreshold: 90 * 24 * time.Hour,
	}

	// Agent active 100 days ago — exceeds auto-revoke threshold
	records := []*AgentRecord{
		{
			ID:           "revoked-agent",
			Name:         "Revoked Agent",
			Status:       StatusActive,
			LastActivity: nowFunc().Add(-100 * 24 * time.Hour),
		},
	}

	report := engine.Classify(records, policy)
	if report.Revoked != 1 {
		t.Errorf("Revoked = %d; want 1", report.Revoked)
	}
	if len(report.Agents) != 1 {
		t.Fatalf("Agents len = %d; want 1", len(report.Agents))
	}
	if report.Agents[0].Status != StatusRevoked {
		t.Errorf("Agent status = %s; want %s", report.Agents[0].Status, StatusRevoked)
	}
}

func TestDormancyEvaluate_StickyStates(t *testing.T) {
	engine := NewDormancyEngine(60*24*time.Hour, nil)
	policy := &LifecyclePolicy{
		DormancyThreshold: 60 * 24 * time.Hour,
	}

	tests := []struct {
		name   string
		status AgentStatus
		want   AgentStatus
	}{
		{"quarantined is sticky", StatusQuarantined, StatusQuarantined},
		{"revoked is sticky", StatusRevoked, StatusRevoked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &AgentRecord{
				Status:       tt.status,
				LastActivity: time.Now().Add(-100 * 24 * time.Hour),
			}
			got, _ := engine.Evaluate(record, policy)
			if got != tt.want {
				t.Errorf("Evaluate() = %s; want %s", got, tt.want)
			}
		})
	}
}

func TestDormancyEvaluate_ProvisionedNeverActive(t *testing.T) {
	engine := NewDormancyEngine(60*24*time.Hour, nil)
	record := &AgentRecord{
		Status:       StatusProvisioned,
		LastActivity: time.Time{}, // zero = never active
	}
	got, _ := engine.Evaluate(record, nil)
	if got != StatusProvisioned {
		t.Errorf("Evaluate() = %s; want %s", got, StatusProvisioned)
	}
}

func TestDormancyEvaluate_QuarantineThreshold(t *testing.T) {
	engine := NewDormancyEngine(60*24*time.Hour, nil)
	policy := &LifecyclePolicy{
		DormancyThreshold:   60 * 24 * time.Hour,
		QuarantineThreshold: 75 * 24 * time.Hour,
	}
	record := &AgentRecord{
		Status:       StatusActive,
		LastActivity: time.Now().Add(-80 * 24 * time.Hour), // > quarantine, < revoke
	}
	got, _ := engine.Evaluate(record, policy)
	if got != StatusQuarantined {
		t.Errorf("Evaluate() = %s; want %s", got, StatusQuarantined)
	}
}

// =====================================================================
// PolicyEngine coverage gaps
// =====================================================================

func TestPolicyEnforce_ListPoliciesError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "test-agent",
		Name:    "Test Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	executor := newMockExecutor()
	pStore := &errorPolicyStore{inner: NewInMemoryPolicyStore(), failList: true}
	engine := NewPolicyEngine(reg, dormancy, executor, pStore, testSSELogger())

	results, err := engine.Enforce(context.Background())
	if err == nil {
		t.Fatal("Enforce should return error when ListPolicies fails")
	}
	if results != nil {
		t.Errorf("Results should be nil on error; got %d", len(results))
	}
	if !pStore.failListCalled {
		t.Error("ListPolicies was not called")
	}
}

func TestPolicyEnforce_RegistryListError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "test-agent",
		Name:    "Test Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := &errorStore{inner: NewInMemoryStore(), failList: true}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})

	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	executor := newMockExecutor()
	pStore := NewInMemoryPolicyStore()
	engine := NewPolicyEngine(reg, dormancy, executor, pStore, testSSELogger())

	_, err := engine.Enforce(context.Background())
	if err == nil {
		t.Fatal("Enforce should return error when registry List fails")
	}
}

func TestPolicyEnforce_NoTransitionNeeded(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "active-agent",
		Name:    "Active Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Manually set recent activity and status so agent is already active
	rec, _ := store.Get(context.Background(), "active-agent")
	rec.LastActivity = nowFunc().Add(-1 * time.Hour)
	rec.Status = StatusActive
	_ = store.Upsert(context.Background(), rec)

	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	executor := newMockExecutor()
	pStore := NewInMemoryPolicyStore()
	_ = pStore.UpsertPolicy(context.Background(), &LifecyclePolicy{
		ID:                "test-policy",
		Name:              "Test Policy",
		Enabled:           true,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant:         []PolicyAction{{Type: "notify"}},
	})

	engine := NewPolicyEngine(reg, dormancy, executor, pStore, testSSELogger())

	results, err := engine.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	// Agent is active, policy says dormant at 60d — but agent was active 1h ago
	// so recommended == current (active) → no transition, no actions
	if len(results) != 0 {
		t.Errorf("Expected 0 results (no transition needed); got %d", len(results))
	}
	if len(executor.notifications) != 0 {
		t.Errorf("Expected 0 notifications; got %d", len(executor.notifications))
	}
}

func TestPolicyEnforce_TransitionError(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "dormant-agent",
		Name:    "Dormant Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	// Use errorStore that succeeds on initial Discover, then fails on Upsert
	store := &errorStore{inner: NewInMemoryStore()}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Set agent to active with old activity so dormancy recommends dormant
	rec, _ := store.inner.Get(context.Background(), "dormant-agent")
	rec.LastActivity = nowFunc().Add(-65 * 24 * time.Hour)
	rec.Status = StatusActive
	_ = store.inner.Upsert(context.Background(), rec)

	// Now fail Upsert so Transition fails
	store.mu.Lock()
	store.failUpsert = true
	store.mu.Unlock()

	dormancy := NewDormancyEngine(60*24*time.Hour, nil)
	executor := newMockExecutor()
	pStore := NewInMemoryPolicyStore()
	_ = pStore.UpsertPolicy(context.Background(), &LifecyclePolicy{
		ID:                "test-policy",
		Name:              "Test Policy",
		Enabled:           true,
		DormancyThreshold: 60 * 24 * time.Hour,
		OnDormant:         []PolicyAction{{Type: "notify"}},
	})

	engine := NewPolicyEngine(reg, dormancy, executor, pStore, testSSELogger())

	results, err := engine.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	// Should have 1 notify result + 1 failed transition result
	foundFailed := false
	for _, r := range results {
		if r.Status == "failed" {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Errorf("Expected a failed transition result; got %d results: %+v", len(results), results)
	}
}

// =====================================================================
// Registry coverage gaps
// =====================================================================

func TestRegistryDiscover_UpsertError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := &errorStore{inner: NewInMemoryStore(), failUpsert: true}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr, Logger: testSSELogger()})

	// Discover should return error when ALL upserts fail
	err := reg.Discover(context.Background())
	if err == nil {
		t.Fatal("Discover should return error when all upserts fail")
	}
}

func TestRegistryStart_DiscoveryError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := &errorStore{inner: NewInMemoryStore(), failUpsert: true}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr, RefreshInterval: 1 * time.Hour, Logger: testSSELogger()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should not fail even if initial discovery fails (it logs the error)
	err := reg.Start(ctx)
	if err != nil {
		t.Fatalf("Start should not return error for discovery failure: %v", err)
	}
	defer reg.Stop()
}

func TestRegistryRefreshLoop_RefreshError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := &errorStore{inner: NewInMemoryStore()}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr, RefreshInterval: 50 * time.Millisecond, Logger: testSSELogger()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start succeeds (initial Discover works)
	if err := reg.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Let one refresh succeed
	time.Sleep(80 * time.Millisecond)

	// Now fail all upserts — subsequent refresh should hit the error path
	store.mu.Lock()
	store.failUpsert = true
	store.mu.Unlock()

	// Wait for at least one failed refresh
	time.Sleep(120 * time.Millisecond)

	// Stop and verify no panic
	reg.Stop()
}

func TestRegistryReconcile_ListError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	store := &errorStore{inner: NewInMemoryStore(), failList: true}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr, AIBOMSource: &mockAIBOMSource{names: []string{"agent-1"}}})

	_, err := reg.Reconcile(context.Background())
	if err == nil {
		t.Fatal("Reconcile should return error when store.List fails")
	}
}

func TestRegistryTransition_UpsertError(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := &errorStore{inner: NewInMemoryStore()}
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Now fail Upsert so Transition fails
	store.mu.Lock()
	store.failUpsert = true
	store.mu.Unlock()

	err := reg.Transition("agent-1", StatusDormant, "test")
	if err == nil {
		t.Fatal("Transition should return error when Upsert fails")
	}
}

func TestRegistryStart_AlreadyRunning(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr, RefreshInterval: 1 * time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := reg.Start(ctx); err != nil {
		t.Fatalf("First Start: %v", err)
	}
	defer reg.Stop()

	// Second Start should fail
	err := reg.Start(ctx)
	if err == nil {
		t.Fatal("Second Start should return error")
	}
}

func TestRegistryStop_NotRunning(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})

	// Stop when not running should be a no-op (no panic)
	reg.Stop()
}

func TestRegistryTransition_SameStatus(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Transition to same status should be a no-op
	err := reg.Transition("agent-1", StatusActive, "no-op test")
	if err != nil {
		t.Fatalf("Transition to same status should be no-op: %v", err)
	}
}

func TestRegistryTransition_NotFound(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})

	err := reg.Transition("nonexistent", StatusDormant, "test")
	if err == nil {
		t.Fatal("Transition should fail for nonexistent agent")
	}
}

func TestRegistrySetLifecycleEventCallback(t *testing.T) {
	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "Agent One",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	var capturedEvent LifecycleEvent
	reg.SetLifecycleEventCallback(func(e LifecycleEvent) {
		capturedEvent = e
	})

	err := reg.Transition("agent-1", StatusDormant, "callback test")
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if capturedEvent.AgentID != "agent-1" {
		t.Errorf("Callback AgentID = %s; want agent-1", capturedEvent.AgentID)
	}
	if capturedEvent.NewStatus != StatusDormant {
		t.Errorf("Callback NewStatus = %s; want %s", capturedEvent.NewStatus, StatusDormant)
	}
}

// =====================================================================
// SSE coverage gaps
// =====================================================================

func TestEventBroadcaster_Broadcast_AfterStop(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	b.Stop()

	// Broadcast after stop should be a no-op (not panic)
	b.Broadcast(SSEEventAgentLifecycle, map[string]string{"agent_id": "post-stop"})
}

func TestEventBroadcaster_HandleSSE_StreamingUnsupported(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	w := &nonFlusherRW{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/stream", nil)

	b.HandleSSE(w, req)

	if w.status != http.StatusInternalServerError {
		t.Errorf("Status = %d; want %d", w.status, http.StatusInternalServerError)
	}
	if !strings.Contains(string(w.body), "streaming unsupported") {
		t.Errorf("Body = %q; want streaming unsupported error", string(w.body))
	}
}

func TestEventBroadcaster_HandleSSE_ChannelClosed(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.HandleSSE(w, req)
		close(done)
	}()

	// Give the handler time to subscribe
	time.Sleep(50 * time.Millisecond)

	// Force-close the subscriber's channel by accessing internals.
	// This simulates the broadcaster being stopped while a client is connected.
	b.mu.Lock()
	for id, ch := range b.subs {
		close(ch)
		delete(b.subs, id)
	}
	b.mu.Unlock()

	// Handler should exit because channel was closed (!open)
	select {
	case <-done:
		// Good — handler exited
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSSE did not exit after channel closed")
	}

	cancel()
}

func TestEventBroadcaster_HeartbeatLoop_StopCh(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()

	// Stop quickly — heartbeatLoop should pick up stopCh
	b.Stop()

	// Give the goroutine time to process stopCh and exit
	time.Sleep(50 * time.Millisecond)

	// If we get here without hanging, the heartbeatLoop exited via stopCh
}

func TestEventBroadcaster_HeartbeatLoop_TickerFires(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.SetHeartbeatInterval(50 * time.Millisecond)
	b.Start()
	defer b.Stop()

	// Subscribe so we can observe the heartbeat
	ch := b.Subscribe("hb-test")
	defer b.Unsubscribe("hb-test")

	// Wait for at least one heartbeat tick
	select {
	case event := <-ch:
		if event.Type != SSEEventHeartbeat {
			t.Errorf("Event type = %s; want %s", event.Type, SSEEventHeartbeat)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive heartbeat within 2s")
	}
}

func TestWriteAgentSSEEvent_MarshalError(t *testing.T) {
	w := httptest.NewRecorder()
	// Pass data that json.Marshal cannot handle (a channel)
	event := &SSEEvent{
		Type: SSEEventAgentLifecycle,
		Data: make(chan int), // channels cannot be JSON-marshaled
		ID:   "1",
	}

	// Should not panic, just return without writing
	writeAgentSSEEvent(w, w, event)

	// Body should be empty because marshal failed before any write
	if w.Body.Len() > 0 {
		t.Errorf("Body should be empty on marshal error; got %d bytes", w.Body.Len())
	}
}

// =====================================================================
// Adapters coverage gaps
// =====================================================================

func TestCorrelationAdapter_NilEngine(t *testing.T) {
	adapter := &CorrelationAdapter{engine: nil}
	events, err := adapter.RecentEventsByAgent("test-agent", time.Time{})
	if err != nil {
		t.Errorf("nil engine should return nil error; got %v", err)
	}
	if events != nil {
		t.Errorf("nil engine should return nil events; got %v", events)
	}

	count, err := adapter.AgentEventCount("test-agent")
	if err != nil {
		t.Errorf("nil engine should return nil error; got %v", err)
	}
	if count != 0 {
		t.Errorf("nil engine should return 0 count; got %d", count)
	}
}

func TestExtractMCPActivity_NilSessionManager(t *testing.T) {
	result := extractMCPActivity(nil)
	if result != nil {
		t.Errorf("extractMCPActivity(nil) = %v; want nil", result)
	}
}

func TestExtractMCPProtocolCount_NilSessionManager(t *testing.T) {
	result := extractMCPProtocolCount(nil, "any-agent")
	if result != 0 {
		t.Errorf("extractMCPProtocolCount(nil) = %d; want 0", result)
	}
}

// =====================================================================
// Types coverage gaps
// =====================================================================

func TestTypesMatches_TagMismatch(t *testing.T) {
	filter := &ListFilter{
		Tag: map[string]string{"env": "prod"},
	}
	record := &AgentRecord{
		Status: StatusActive,
		Tags:   map[string]string{"env": "staging"},
	}
	if filter.matches(record) {
		t.Error("matches should return false when tag value differs")
	}
}

func TestTypesMatches_AllFieldsMatch(t *testing.T) {
	filter := &ListFilter{
		Status:   StatusActive,
		Protocol: ProtocolMCP,
		Owner:    "team-a",
		TenantID: "tenant-1",
		Tag:      map[string]string{"env": "prod"},
	}
	record := &AgentRecord{
		Status:    StatusActive,
		Protocols: []Protocol{ProtocolMCP},
		Owner:     "team-a",
		TenantID:  "tenant-1",
		Tags:      map[string]string{"env": "prod"},
	}
	if !filter.matches(record) {
		t.Error("matches should return true when all fields match")
	}
}

func TestTypesMatches_NilFilter(t *testing.T) {
	var filter *ListFilter
	record := &AgentRecord{Status: StatusActive}
	if !filter.matches(record) {
		t.Error("nil filter should match all records")
	}
}

func TestTypesMatches_StatusMismatch(t *testing.T) {
	filter := &ListFilter{Status: StatusDormant}
	record := &AgentRecord{Status: StatusActive}
	if filter.matches(record) {
		t.Error("matches should return false on status mismatch")
	}
}

func TestTypesMatches_ProtocolMismatch(t *testing.T) {
	filter := &ListFilter{Protocol: ProtocolA2A}
	record := &AgentRecord{Status: StatusActive, Protocols: []Protocol{ProtocolMCP}}
	if filter.matches(record) {
		t.Error("matches should return false on protocol mismatch")
	}
}

func TestTypesMatches_OwnerMismatch(t *testing.T) {
	filter := &ListFilter{Owner: "team-a"}
	record := &AgentRecord{Status: StatusActive, Owner: "team-b"}
	if filter.matches(record) {
		t.Error("matches should return false on owner mismatch")
	}
}

func TestTypesMatches_TenantMismatch(t *testing.T) {
	filter := &ListFilter{TenantID: "tenant-1"}
	record := &AgentRecord{Status: StatusActive, TenantID: "tenant-2"}
	if filter.matches(record) {
		t.Error("matches should return false on tenant mismatch")
	}
}

// =====================================================================
// Registry: Discover with A2A-only agent (drift condition)
// =====================================================================

func TestRegistryDiscover_A2AOnlyAgent(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	// Don't register the A2A agent in RBAC — it's drift
	store := NewInMemoryStore()
	a2aSource := &mockA2ASource{
		agents: []A2AAgentInfo{
			{AgentID: "a2a-only-agent", LastSeen: nowFunc().Add(-1 * time.Hour)},
		},
	}

	reg, _ := New(Config{
		Store:     store,
		RBAC:      rbacMgr,
		A2ASource: a2aSource,
	})

	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	records, _ := store.List(context.Background(), nil)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record; got %d", len(records))
	}
	if records[0].ID != "a2a-only-agent" {
		t.Errorf("ID = %s; want a2a-only-agent", records[0].ID)
	}
	if !contains(records[0].DiscoverySources, "a2a") {
		t.Errorf("DiscoverySources should contain 'a2a'; got %v", records[0].DiscoverySources)
	}
	if !hasProtocol(records[0].Protocols, ProtocolA2A) {
		t.Errorf("Protocols should contain A2A; got %v", records[0].Protocols)
	}
}

// =====================================================================
// Registry: Reconcile with AIBOM drift
// =====================================================================

func TestRegistryReconcile_WithDrift(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-in-runtime",
		Name:    "Runtime Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	reg, _ := New(Config{
		Store:       store,
		RBAC:        rbacMgr,
		AIBOMSource: &mockAIBOMSource{names: []string{"agent-in-aibom-only"}},
	})

	_ = reg.Discover(context.Background())

	report, err := reg.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report == nil {
		t.Fatal("Report is nil")
	}
	// agent-in-runtime is in registry but not in AIBOM → ActiveNotInAIBOM
	if len(report.ActiveNotInAIBOM) == 0 {
		t.Error("Expected ActiveNotInAIBOM to have entries")
	}
	// agent-in-aibom-only is in AIBOM but not in registry → InAIBOMNotActive
	if len(report.InAIBOMNotActive) == 0 {
		t.Error("Expected InAIBOMNotActive to have entries")
	}
}

// =====================================================================
// Registry: Discover with correlation events
// =====================================================================

func TestRegistryDiscover_WithCorrelation(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "correlated-agent",
		Name:    "Correlated Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	corrSource := &mockCorrelationSourceWithEvents{
		count: 42,
		events: []CorrelationEventInfo{
			{EventType: "request", Severity: "info", Timestamp: nowFunc().Add(-30 * time.Minute), Protocol: "mcp"},
		},
	}

	reg, _ := New(Config{
		Store:       store,
		RBAC:        rbacMgr,
		Correlation: corrSource,
	})

	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	rec, err := store.Get(context.Background(), "correlated-agent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.TotalEvents != 42 {
		t.Errorf("TotalEvents = %d; want 42", rec.TotalEvents)
	}
	if !contains(rec.DiscoverySources, "correlation") {
		t.Errorf("DiscoverySources should contain 'correlation'; got %v", rec.DiscoverySources)
	}
	// LastActivity should be enriched from correlation event
	if !rec.LastActivity.Equal(nowFunc().Add(-30 * time.Minute)) {
		t.Errorf("LastActivity = %v; want %v", rec.LastActivity, nowFunc().Add(-30*time.Minute))
	}
}

// =====================================================================
// Registry: Discover with AIBOM match
// =====================================================================

func TestRegistryDiscover_WithAIBOMMatch(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "aibom-agent",
		Name:    "AIBOM Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	store := NewInMemoryStore()
	aibomSource := &mockAIBOMSource{
		names:       []string{"aibom-agent"},
		generatedAt: nowFunc(),
	}

	reg, _ := New(Config{
		Store:       store,
		RBAC:        rbacMgr,
		AIBOMSource: aibomSource,
	})

	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	rec, err := store.Get(context.Background(), "aibom-agent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !rec.InAIBOM {
		t.Error("InAIBOM should be true when agent is in AIBOM")
	}
}

// =====================================================================
// Registry: Discover with RBAC session activity
// =====================================================================

func TestRegistryDiscover_WithRBACSessions(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{
		ID:      "session-agent",
		Name:    "Session Agent",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})

	// Create a real RBAC session for the agent
	session, err := rbacMgr.CreateSession(context.Background(), "session-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Set last activity to a specific time
	session.SetLastActivity(nowFunc().Add(-30 * time.Minute))

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})

	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	rec, err := store.Get(context.Background(), "session-agent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Should have HTTP protocol from RBAC sessions
	if !hasProtocol(rec.Protocols, ProtocolHTTP) {
		t.Errorf("Protocols should contain HTTP; got %v", rec.Protocols)
	}
	// ActiveSessions should reflect the session
	if rec.ActiveSessions < 1 {
		t.Errorf("ActiveSessions = %d; want >= 1", rec.ActiveSessions)
	}
}

// =====================================================================
// Registry: List with filter
// =====================================================================

func TestRegistryList_WithFilter(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	rbacMgr, _ := rbac.NewManager(nil)
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "agent-a", Name: "A", Role: rbac.AgentRoleStandard, Enabled: true})
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "agent-b", Name: "B", Role: rbac.AgentRoleStandard, Enabled: true})

	store := NewInMemoryStore()
	reg, _ := New(Config{Store: store, RBAC: rbacMgr})
	_ = reg.Discover(context.Background())

	// Transition agent-b to dormant
	_ = reg.Transition("agent-b", StatusDormant, "test")

	// List with status filter
	results, err := reg.List(&ListFilter{Status: StatusDormant})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 dormant agent; got %d", len(results))
	}
	if results[0].ID != "agent-b" {
		t.Errorf("Expected agent-b; got %s", results[0].ID)
	}
}

// =====================================================================
// Avoid unused import warnings
// =====================================================================

var _ = io.Discard
var _ = slog.New

// =====================================================================
// joinStrings coverage (postgres_store.go helper)
// =====================================================================

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		name   string
		parts  []string
		sep    string
		expect string
	}{
		{"empty", []string{}, ", ", ""},
		{"single", []string{"a"}, ", ", "a"},
		{"multiple", []string{"a", "b", "c"}, ", ", "a, b, c"},
		{"semicolon sep", []string{"x", "y"}, ";", "x;y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinStrings(tt.parts, tt.sep)
			if got != tt.expect {
				t.Errorf("joinStrings(%v, %q) = %q; want %q", tt.parts, tt.sep, got, tt.expect)
			}
		})
	}
}

// =====================================================================
// CorrelationAdapter error path coverage
// =====================================================================

func TestCorrelationAdapterRecentEventsByAgentError(t *testing.T) {
	engine := correlation.NewEngine()
	adapter := NewCorrelationAdapter(engine)

	// Empty agentID triggers an error from the engine.
	_, err := adapter.RecentEventsByAgent("", time.Time{})
	if err == nil {
		t.Error("RecentEventsByAgent should return error for empty agent ID")
	}
}

// =====================================================================
// heartbeatLoop default interval coverage
// =====================================================================

func TestEventBroadcaster_HeartbeatLoop_DefaultInterval(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	// Don't set a custom heartbeat interval — default 15s should be used.
	b.Start()

	// Give the goroutine time to start and execute the default interval path.
	time.Sleep(100 * time.Millisecond)

	b.Stop()

	// Give the goroutine time to exit via stopCh.
	time.Sleep(100 * time.Millisecond)
}

func TestExtractMCPActivity_DriftAgentNotInRBAC(t *testing.T) {
	// Drift scenario: an MCP session exists for an agent NOT in RBAC.
	sessions := []*mcpserver.MCPSession{
		{
			ConnectionID: "conn-drift",
			Agent:        &rbac.Agent{ID: "ghost-agent", Name: "Ghost", Role: rbac.AgentRoleStandard, Enabled: true},
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
		},
	}
	activity := extractMCPActivity(sessions)
	if len(activity) != 1 {
		t.Fatalf("len(activity) = %d, want 1", len(activity))
	}
	if activity[0].AgentID != "ghost-agent" {
		t.Errorf("AgentID = %q, want %q", activity[0].AgentID, "ghost-agent")
	}
}

// TestEventBroadcaster_HeartbeatLoop_ZeroInterval covers the default
// interval path (line 306 in sse.go). NewEventBroadcaster sets
// heartbeatInterval to 15s, so the if interval == 0 branch is never
// taken via the public constructor. We construct an EventBroadcaster
// directly with a zero heartbeatInterval to exercise this path.
func TestEventBroadcaster_HeartbeatLoop_ZeroInterval(t *testing.T) {
	b := &EventBroadcaster{
		subs:   make(map[string]chan *SSEEvent),
		logger: testSSELogger(),
		stopCh: make(chan struct{}),
		// heartbeatInterval left as zero value — triggers default 15s path
	}
	b.Start()

	// Give the goroutine time to enter heartbeatLoop, execute the
	// `if interval == 0 { interval = 15 * time.Second }` branch, and
	// block on the select.
	time.Sleep(100 * time.Millisecond)

	b.Stop()
	time.Sleep(100 * time.Millisecond)
}

// TestEventBroadcaster_HandleSSE_StopCh covers the stopCh branch in
// HandleSSE's select loop (line 273 in sse.go). Other tests cover the
// ctx.Done() and channel-closed branches; this one triggers b.Stop()
// while a client is connected.
func TestEventBroadcaster_HandleSSE_StopCh(t *testing.T) {
	b := NewEventBroadcaster(testSSELogger())
	b.Start()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		b.HandleSSE(w, req)
		close(done)
	}()

	// Give the handler time to subscribe and enter the select loop.
	time.Sleep(100 * time.Millisecond)

	// Stop the broadcaster — heartbeatLoop and HandleSSE should both
	// pick up stopCh and exit.
	b.Stop()

	select {
	case <-done:
		// Good — HandleSSE exited via stopCh
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSSE did not exit after broadcaster Stop()")
	}
}

// TestDiscover_MCPDrift_InjectedSession exercises the MCP drift path
// in Discover() (lines 149-158 in registry.go) by injecting a session
// with a valid RBACSession but an Agent.ID that is NOT in RBAC. This
// simulates a scenario where the MCP session's cached Agent pointer
// references an agent that was never registered (or was removed) from
// RBAC. We use unsafe to access the private conns map since
// CreateSession prevents this scenario and ListSessions filters by
// RBACSession.IsValid().
func TestDiscover_MCPDrift_InjectedSession(t *testing.T) {
	rbacMgr, err := rbac.NewManager(nil)
	if err != nil {
		t.Fatalf("rbac.NewManager: %v", err)
	}
	// Register a "real" agent that will have a valid RBAC session.
	_ = rbacMgr.RegisterAgent(&rbac.Agent{ID: "real-agent", Name: "Real", Role: rbac.AgentRoleStandard, Enabled: true})

	sm := mcpserver.NewConnectionSessionManager(rbacMgr)
	ctx := context.Background()

	// Create a valid session for real-agent.
	_, err = sm.CreateSession(ctx, "conn-real", "real-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Now use unsafe to inject a second session into the private conns
	// map. This session has a valid RBACSession (copied from the real
	// session) but its Agent.ID is "ghost-agent" — NOT in RBAC. This
	// triggers the drift path in Discover().
	smVal := reflect.ValueOf(sm).Elem()
	connsField := smVal.FieldByName("conns")

	// Access the private conns map via unsafe pointer (reflect cannot
	// SetMapIndex on unexported fields). We read the map pointer and
	// manipulate the Go map directly.
	connsPtr := unsafe.Pointer(connsField.UnsafeAddr())
	connsMap := *(*map[string]*mcpserver.MCPSession)(connsPtr)

	// Find an existing valid session to copy its RBACSession.
	var validSession *mcpserver.MCPSession
	for _, s := range connsMap {
		if s.RBACSession != nil && s.RBACSession.IsValid() {
			validSession = s
			break
		}
	}
	if validSession == nil {
		t.Fatal("no valid session found to copy")
	}

	// Construct a drift session: valid RBACSession, but Agent.ID
	// points to an agent NOT in RBAC.
	driftSession := &mcpserver.MCPSession{
		ConnectionID: "conn-drift",
		RBACSession:  validSession.RBACSession,
		Agent:        &rbac.Agent{ID: "ghost-agent", Name: "Ghost", Role: rbac.AgentRoleStandard, Enabled: true},
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	// Inject directly into the conns map.
	connsMap["conn-drift"] = driftSession

	// Build a registry and discover.
	reg, err := New(Config{
		Store:       NewInMemoryStore(),
		RBAC:        rbacMgr,
		MCPSessions: sm,
		Logger:      testSSELogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := reg.Discover(ctx); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	records, err := reg.List(nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	var foundDrift, foundReal bool
	for _, r := range records {
		if r.ID == "ghost-agent" {
			foundDrift = true
			if !contains(r.DiscoverySources, "mcp") {
				t.Errorf("ghost-agent DiscoverySources = %v; want 'mcp'", r.DiscoverySources)
			}
		}
		if r.ID == "real-agent" {
			foundReal = true
		}
	}
	if !foundDrift {
		t.Error("ghost-agent not found in records; drift path did not fire")
	}
	if !foundReal {
		t.Error("real-agent not found in records")
	}
}
