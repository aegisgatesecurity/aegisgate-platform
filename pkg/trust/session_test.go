// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Session Manager tests (v3.2.0 Phase 4.2)
//
// Tests the request-lifecycle session wrapper on top of score.Engine.

package trust

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// discardSession returns a Manager with a small cap for testing.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	engine := score.NewEngine(nil)
	return NewManager(engine, &ManagerConfig{
		MaxSessions:   100,
		MaxSessionAge: 1 * time.Hour,
	})
}

func TestManager_Start_AssignsIDAndInitialScore(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, err := m.Start(ctx, "agent-1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID is empty")
	}
	if sess.AgentID != "agent-1" {
		t.Errorf("agentID = %q, want agent-1", sess.AgentID)
	}
	if sess.StartedAt.IsZero() {
		t.Error("StartedAt is zero")
	}
	if sess.EndedAt.IsZero() == false {
		t.Error("EndedAt is set on a fresh session")
	}
	if !sess.IsActive() {
		t.Error("freshly-started session is not IsActive()")
	}
	if sess.InitialScore != 100.0 {
		// Default initial score is 100.0; engine returns that for a
		// new agent (no events yet, no anomalies).
		t.Errorf("InitialScore = %v, want 100.0", sess.InitialScore)
	}
}

func TestManager_Start_RejectsEmptyAgentID(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Start(context.Background(), "")
	if err == nil {
		t.Error("Start with empty agent ID returned no error")
	}
}

func TestManager_Start_GeneratesUniqueIDs(t *testing.T) {
	m := newTestManager(t)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, _ := m.Start(context.Background(), "agent")
		if seen[s.ID] {
			t.Fatalf("duplicate session ID: %s", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestManager_Get_FoundAndNotFound(t *testing.T) {
	m := newTestManager(t)
	sess, _ := m.Start(context.Background(), "agent")
	got, err := m.Get(sess.ID)
	if err != nil {
		t.Errorf("Get(%s): %v", sess.ID, err)
	}
	if got.ID != sess.ID {
		t.Errorf("got.ID = %q, want %q", got.ID, sess.ID)
	}
	_, err = m.Get("nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestManager_End_ClosesSession(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	closed, err := m.End(ctx, sess.ID)
	if err != nil {
		t.Fatalf("End: %v", err)
	}
	if closed.EndedAt.IsZero() {
		t.Error("EndedAt is zero after End")
	}
	if closed.IsActive() {
		t.Error("closed session is still IsActive()")
	}
}

func TestManager_End_ErrorsOnUnknownID(t *testing.T) {
	m := newTestManager(t)
	_, err := m.End(context.Background(), "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestManager_End_ErrorsOnAlreadyEnded(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	_, _ = m.End(ctx, sess.ID)
	_, err := m.End(ctx, sess.ID)
	if !errors.Is(err, ErrSessionAlreadyEnded) {
		t.Errorf("expected ErrSessionAlreadyEnded, got %v", err)
	}
}

func TestManager_Record_AppendsAndForwards(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	ev, err := m.Record(ctx, sess.ID, score.EventCapabilityAllowed, "read", 1, "test event")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ev.ID == "" {
		t.Error("recorded event has no ID")
	}
	if ev.AgentID != "agent" {
		t.Errorf("event.AgentID = %q, want agent", ev.AgentID)
	}
	if sess.EventCount() != 1 {
		t.Errorf("EventCount = %d, want 1", sess.EventCount())
	}
	// Recording more events.
	for i := 0; i < 5; i++ {
		_, _ = m.Record(ctx, sess.ID, score.EventCapabilityAllowed, "read", 1, "test")
	}
	if sess.EventCount() != 6 {
		t.Errorf("EventCount = %d, want 6", sess.EventCount())
	}
}

func TestManager_Record_ErrorsOnClosedSession(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	_, _ = m.End(ctx, sess.ID)
	_, err := m.Record(ctx, sess.ID, score.EventCapabilityAllowed, "read", 1, "test")
	if !errors.Is(err, ErrSessionAlreadyEnded) {
		t.Errorf("expected ErrSessionAlreadyEnded, got %v", err)
	}
}

func TestManager_Record_ErrorsOnUnknownSession(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Record(context.Background(), "nonexistent", score.EventCapabilityAllowed, "read", 1, "test")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestManager_Score_ReturnsLifetimeScore(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	ts, err := m.Score(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if ts == nil {
		t.Fatal("Score returned nil")
	}
	if ts.AgentID != "agent" {
		t.Errorf("TrustScore.AgentID = %q, want agent", ts.AgentID)
	}
}

func TestManager_ScoreDelta_TracksChangeDuringSession(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	initialDelta, err := m.ScoreDelta(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ScoreDelta: %v", err)
	}
	if initialDelta != 0 {
		t.Errorf("initial ScoreDelta = %v, want 0 (no events yet)", initialDelta)
	}
	// Record a denied event (negative impact on score).
	_, _ = m.Record(ctx, sess.ID, score.EventCapabilityDenied, "write", 8, "denied")
	delta, err := m.ScoreDelta(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ScoreDelta after Record: %v", err)
	}
	// Delta should be negative (denied events erode trust).
	if delta >= 0 {
		t.Errorf("ScoreDelta after denied = %v, want < 0", delta)
	}
}

func TestManager_StartWithMetadata(t *testing.T) {
	m := newTestManager(t)
	sess, err := m.StartWithMetadata(context.Background(), "agent", map[string]string{
		"source_ip": "10.0.0.1",
		"protocol":  "mcp",
	})
	if err != nil {
		t.Fatalf("StartWithMetadata: %v", err)
	}
	if sess.Metadata["source_ip"] != "10.0.0.1" {
		t.Errorf("metadata[source_ip] = %q, want 10.0.0.1", sess.Metadata["source_ip"])
	}
	if sess.Metadata["protocol"] != "mcp" {
		t.Errorf("metadata[protocol] = %q, want mcp", sess.Metadata["protocol"])
	}
}

func TestManager_List_AllAndActiveOnly(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	// 3 active sessions.
	s1, _ := m.Start(ctx, "agent-1")
	s2, _ := m.Start(ctx, "agent-2")
	s3, _ := m.Start(ctx, "agent-3")
	// Close one.
	_, _ = m.End(ctx, s1.ID)
	all := m.List(false)
	if len(all) != 3 {
		t.Errorf("List(all) returned %d, want 3", len(all))
	}
	active := m.List(true)
	if len(active) != 2 {
		t.Errorf("List(active) returned %d, want 2", len(active))
	}
	// Verify s1 is the closed one.
	for _, s := range all {
		if s.ID == s1.ID && s.IsActive() {
			t.Error("s1 should be closed but IsActive()=true")
		}
	}
	// Suppress unused warning.
	_ = s2.ID
	_ = s3.ID
}

func TestManager_ListByAgent(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	m.Start(ctx, "agent-1")
	m.Start(ctx, "agent-1")
	m.Start(ctx, "agent-2")
	got := m.ListByAgent("agent-1", false)
	if len(got) != 2 {
		t.Errorf("ListByAgent(agent-1) = %d, want 2", len(got))
	}
	for _, s := range got {
		if s.AgentID != "agent-1" {
			t.Errorf("got session with agentID %q, want agent-1", s.AgentID)
		}
	}
}

func TestManager_ActiveCount(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	if got := m.ActiveCount(); got != 0 {
		t.Errorf("ActiveCount = %d, want 0", got)
	}
	s1, _ := m.Start(ctx, "agent")
	m.Start(ctx, "agent")
	if got := m.ActiveCount(); got != 2 {
		t.Errorf("ActiveCount = %d, want 2", got)
	}
	_, _ = m.End(ctx, s1.ID)
	if got := m.ActiveCount(); got != 1 {
		t.Errorf("ActiveCount after End = %d, want 1", got)
	}
}

func TestManager_EvictionAtMaxSessions(t *testing.T) {
	engine := score.NewEngine(nil)
	m := NewManager(engine, &ManagerConfig{
		MaxSessions:   3, // tiny cap to trigger eviction
		MaxSessionAge: 1 * time.Hour,
	})
	ctx := context.Background()
	// Create 5 sessions (all closed, all eligible for eviction).
	for i := 0; i < 5; i++ {
		s, _ := m.Start(ctx, "agent")
		_, _ = m.End(ctx, s.ID)
		// Sleep a bit to ensure distinct EndedAt timestamps.
		time.Sleep(1 * time.Millisecond)
	}
	// Should have evicted down to 3.
	if m.TotalCount() != 3 {
		t.Errorf("TotalCount = %d, want 3 (after eviction)", m.TotalCount())
	}
}

func TestSession_Duration(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	sess, _ := m.Start(ctx, "agent")
	time.Sleep(10 * time.Millisecond)
	if d := sess.Duration(); d < 10*time.Millisecond {
		t.Errorf("Duration = %v, want >= 10ms", d)
	}
	_, _ = m.End(ctx, sess.ID)
	d1 := sess.Duration()
	time.Sleep(5 * time.Millisecond)
	d2 := sess.Duration()
	if d1 != d2 {
		t.Errorf("closed session duration changed: %v -> %v", d1, d2)
	}
}

func TestSession_IsActive(t *testing.T) {
	// A zero-value session is not active.
	var s Session
	if s.IsActive() {
		t.Error("zero-value Session is IsActive()=true (should be false)")
	}
	s.StartedAt = time.Now()
	if !s.IsActive() {
		t.Error("Session with only StartedAt should be IsActive()")
	}
	s.EndedAt = time.Now()
	if s.IsActive() {
		t.Error("Session with EndedAt set should not be IsActive()")
	}
}

func TestManager_Engine_ReturnsUnderlyingEngine(t *testing.T) {
	engine := score.NewEngine(nil)
	m := NewManager(engine, nil)
	if m.Engine() != engine {
		t.Error("Engine() did not return the wrapped engine")
	}
}

func TestManager_NilConfigUsesDefaults(t *testing.T) {
	engine := score.NewEngine(nil)
	m := NewManager(engine, nil) // nil config
	if m.maxSessions != 10000 {
		t.Errorf("default MaxSessions = %d, want 10000", m.maxSessions)
	}
	if m.maxSessionAge != 24*time.Hour {
		t.Errorf("default MaxSessionAge = %v, want 24h", m.maxSessionAge)
	}
}

func TestManager_NilEngineCreatesDefault(t *testing.T) {
	m := NewManager(nil, nil) // nil engine
	if m.Engine() == nil {
		t.Error("NewManager(nil, nil) should create a default engine")
	}
}

// TestManager_ConcurrentAccess is a stress test for the race detector.
// It runs many goroutines creating/recording/ending sessions to
// catch any race in the mutex-protected paths.
func TestManager_ConcurrentAccess(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			agentID := "agent-" + string(rune('0'+idx))
			sess, err := m.Start(ctx, agentID)
			if err != nil {
				t.Errorf("Start: %v", err)
				return
			}
			for j := 0; j < 10; j++ {
				_, _ = m.Record(ctx, sess.ID, score.EventCapabilityAllowed, "read", 1, "test")
			}
			_, _ = m.End(ctx, sess.ID)
		}(i)
	}
	wg.Wait()
	// 10 active sessions (all just created and ended, all in memory
	// because MaxSessionAge is 1h).
	if m.TotalCount() != 10 {
		t.Errorf("TotalCount = %d, want 10", m.TotalCount())
	}
}

// TestManager_SessionIDFormat verifies the ID is a UUID (8-4-4-4-12).
// This is a sanity check on the uuid library import.
func TestManager_SessionIDFormat(t *testing.T) {
	m := newTestManager(t)
	sess, _ := m.Start(context.Background(), "agent")
	parts := strings.Split(sess.ID, "-")
	if len(parts) != 5 {
		t.Errorf("session ID %q is not a UUID (expected 5 parts, got %d)", sess.ID, len(parts))
	}
}
