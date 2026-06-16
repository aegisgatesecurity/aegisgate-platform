// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Incident Timeline tests (TODO-502)
//
// doc_test.go covers the SOC timeline:
//   - GetTimeline with various engine responses
//   - The Engine interface (mocked)
//   - TimelineEvent methods
//   - Error paths (nil engine, empty sessionID)
//   - Sorting by timestamp

package soc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// =====================================================================
// Mock Engine
// =====================================================================

// mockEngine is a test double for the Engine
// interface. It stores events in a map and returns
// them on ListEventsBySession.
type mockEngine struct {
	mu     sync.Mutex
	events map[string][]*correlation.Event
	// err, if non-nil, is returned by
	// ListEventsBySession. Used to test error
	// propagation.
	err error
}

func newMockEngine() *mockEngine {
	return &mockEngine{events: make(map[string][]*correlation.Event)}
}

func (m *mockEngine) addEvent(sessionID string, evt *correlation.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evt.SessionID = sessionID
	m.events[sessionID] = append(m.events[sessionID], evt)
}

func (m *mockEngine) ListEventsBySession(_ context.Context, sessionID string) ([]*correlation.Event, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.events[sessionID]
	// Return a copy (the engine returns a copy in
	// production to prevent caller mutation).
	result := make([]*correlation.Event, len(events))
	copy(result, events)
	return result, nil
}

// makeTestEvent creates a correlation.Event with the
// given fields.
func makeTestEvent(protocol, eventType, sessionID string, ts time.Time) *correlation.Event {
	return &correlation.Event{
		ID:        "evt-" + sessionID + "-" + eventType,
		Protocol:  protocol,
		AgentID:   "agent-1",
		SessionID: sessionID,
		EventType: eventType,
		Timestamp: ts,
		Severity:  "low",
	}
}

// =====================================================================
// GetTimeline
// =====================================================================

func TestGetTimeline_EmptySessionID(t *testing.T) {
	eng := newMockEngine()
	_, err := GetTimeline(context.Background(), eng, "")
	if err == nil {
		t.Errorf("GetTimeline with empty sessionID should fail")
	}
	if !strings.Contains(err.Error(), "sessionID") {
		t.Errorf("Error should mention 'sessionID', got: %v", err)
	}
}

func TestGetTimeline_NilEngine(t *testing.T) {
	_, err := GetTimeline(context.Background(), nil, "session-1")
	if err == nil {
		t.Errorf("GetTimeline with nil engine should fail")
	}
}

func TestGetTimeline_NoEvents(t *testing.T) {
	eng := newMockEngine()
	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result == nil {
		t.Fatalf("Result is nil")
	}
	if result.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", result.TotalCount)
	}
	if result.HasCriticalEvents {
		t.Errorf("HasCriticalEvents should be false for empty timeline")
	}
}

func TestGetTimeline_SingleEvent(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now))

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.TotalCount != 1 {
		t.Errorf("TotalCount = %d, want 1", result.TotalCount)
	}
	if result.StartTime != now {
		t.Errorf("StartTime = %v, want %v", result.StartTime, now)
	}
	if result.EndTime != now {
		t.Errorf("EndTime = %v, want %v", result.EndTime, now)
	}
	if result.ProtocolCounts["http"] != 1 {
		t.Errorf("ProtocolCounts[http] = %d, want 1", result.ProtocolCounts["http"])
	}
}

func TestGetTimeline_MultipleEventsSorted(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	// Add events out of order; GetTimeline should
	// sort by timestamp ascending.
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now.Add(2*time.Second)))
	eng.addEvent("session-1", makeTestEvent("mcp", "error", "session-1", now))
	eng.addEvent("session-1", makeTestEvent("a2a", "message", "session-1", now.Add(1*time.Second)))

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.TotalCount != 3 {
		t.Fatalf("TotalCount = %d, want 3", result.TotalCount)
	}
	// Verify sort order.
	if !result.Events[0].Timestamp.Equal(now) {
		t.Errorf("Events[0] timestamp = %v, want %v", result.Events[0].Timestamp, now)
	}
	if !result.Events[1].Timestamp.Equal(now.Add(1 * time.Second)) {
		t.Errorf("Events[1] timestamp = %v, want %v", result.Events[1].Timestamp, now.Add(1*time.Second))
	}
	if !result.Events[2].Timestamp.Equal(now.Add(2 * time.Second)) {
		t.Errorf("Events[2] timestamp = %v, want %v", result.Events[2].Timestamp, now.Add(2*time.Second))
	}
}

func TestGetTimeline_CrossProtocolCounts(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now))
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now.Add(time.Second)))
	eng.addEvent("session-1", makeTestEvent("mcp", "request", "session-1", now.Add(2*time.Second)))
	eng.addEvent("session-1", makeTestEvent("a2a", "message", "session-1", now.Add(3*time.Second)))

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.ProtocolCounts["http"] != 2 {
		t.Errorf("ProtocolCounts[http] = %d, want 2", result.ProtocolCounts["http"])
	}
	if result.ProtocolCounts["mcp"] != 1 {
		t.Errorf("ProtocolCounts[mcp] = %d, want 1", result.ProtocolCounts["mcp"])
	}
	if result.ProtocolCounts["a2a"] != 1 {
		t.Errorf("ProtocolCounts[a2a] = %d, want 1", result.ProtocolCounts["a2a"])
	}
}

func TestGetTimeline_CriticalEvents(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	// Add a critical event.
	critEvt := makeTestEvent("http", "attack", "session-1", now)
	critEvt.Severity = "critical"
	eng.addEvent("session-1", critEvt)
	// Add a low-severity event.
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now.Add(time.Second)))

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if !result.HasCriticalEvents {
		t.Errorf("HasCriticalEvents should be true")
	}
}

func TestGetTimeline_HighSeverityCountsAsCritical(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	highEvt := makeTestEvent("http", "alert", "session-1", now)
	highEvt.Severity = "high"
	eng.addEvent("session-1", highEvt)

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if !result.HasCriticalEvents {
		t.Errorf("HasCriticalEvents should be true for high severity")
	}
}

func TestGetTimeline_AgentID(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	evt := makeTestEvent("http", "request", "session-1", now)
	evt.AgentID = "agent-42"
	eng.addEvent("session-1", evt)

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.AgentID != "agent-42" {
		t.Errorf("AgentID = %q, want %q", result.AgentID, "agent-42")
	}
}

func TestGetTimeline_EngineError(t *testing.T) {
	eng := newMockEngine()
	eng.err = errors.New("engine failure")
	_, err := GetTimeline(context.Background(), eng, "session-1")
	if err == nil {
		t.Errorf("GetTimeline should propagate engine error")
	}
	if !strings.Contains(err.Error(), "engine failure") {
		t.Errorf("Error should contain 'engine failure', got: %v", err)
	}
}

func TestGetTimeline_CancelledContext(t *testing.T) {
	eng := newMockEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := GetTimeline(ctx, eng, "session-1")
	if err == nil {
		t.Errorf("GetTimeline with cancelled context should fail")
	}
}

// =====================================================================
// TimelineEvent methods
// =====================================================================

func TestTimelineEvent_IsCritical_Critical(t *testing.T) {
	e := &TimelineEvent{Severity: "critical"}
	if !e.IsCritical() {
		t.Errorf("IsCritical should return true for 'critical'")
	}
}

func TestTimelineEvent_IsCritical_High(t *testing.T) {
	e := &TimelineEvent{Severity: "high"}
	if !e.IsCritical() {
		t.Errorf("IsCritical should return true for 'high'")
	}
}

func TestTimelineEvent_IsCritical_Medium(t *testing.T) {
	e := &TimelineEvent{Severity: "medium"}
	if e.IsCritical() {
		t.Errorf("IsCritical should return false for 'medium'")
	}
}

func TestTimelineEvent_IsCritical_Low(t *testing.T) {
	e := &TimelineEvent{Severity: "low"}
	if e.IsCritical() {
		t.Errorf("IsCritical should return false for 'low'")
	}
}

func TestTimelineEvent_IsCritical_NilEvent(t *testing.T) {
	var e *TimelineEvent
	if e.IsCritical() {
		t.Errorf("IsCritical should return false for nil event")
	}
}

// =====================================================================
// convertEvent
// =====================================================================

func TestConvertEvent_Nil(t *testing.T) {
	if got := convertEvent(nil); got != nil {
		t.Errorf("convertEvent(nil) = %v, want nil", got)
	}
}

func TestConvertEvent_HappyPath(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	ce := &correlation.Event{
		ID:        "evt-1",
		Protocol:  "http",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "request",
		Timestamp: now,
		Severity:  "low",
		Decision:  "allow",
		Metadata:  map[string]string{"foo": "bar"},
	}
	got := convertEvent(ce)
	if got == nil {
		t.Fatalf("convertEvent returned nil")
	}
	if got.ID != "evt-1" {
		t.Errorf("ID = %q, want %q", got.ID, "evt-1")
	}
	if got.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "http")
	}
	if !got.Timestamp.Equal(now) {
		t.Errorf("Timestamp mismatch")
	}
	if got.Metadata["foo"] != "bar" {
		t.Errorf("Metadata[foo] = %q, want %q", got.Metadata["foo"], "bar")
	}
}

// =====================================================================
// WrapEngine
// =====================================================================

func TestWrapEngine(t *testing.T) {
	corr := correlation.NewEngine()
	eng := WrapEngine(corr)
	if eng == nil {
		t.Errorf("WrapEngine returned nil")
	}
	// Verify the wrapped engine satisfies the
	// interface (ListEventsBySession works).
	_, err := eng.ListEventsBySession(context.Background(), "session-1")
	if err != nil {
		t.Errorf("Wrapped engine ListEventsBySession: %v", err)
	}
}

func TestWrapEngine_Roundtrip(t *testing.T) {
	corr := correlation.NewEngine()
	eng := WrapEngine(corr)

	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	evt := &correlation.Event{
		ID:        "evt-rt-1",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		EventType: "request",
		Timestamp: now,
		Severity:  "low",
	}
	_ = corr.RecordEvent(context.Background(), evt)

	// Fetch via the wrapped engine and the SOC API.
	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	// The event was stored under key
	// "agent-1:session-1" by RecordEvent. The
	// sessionID field is empty here (we didn't set
	// it before RecordEvent). Let's check what the
	// engine stored.
	if result.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0 (sessionID was empty when recorded)", result.TotalCount)
	}
}

// =====================================================================
// Edge cases
// =====================================================================

func TestGetTimeline_LargeSession(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	// 1000 events
	for i := 0; i < 1000; i++ {
		evt := makeTestEvent("http", "request", "session-1", now.Add(time.Duration(i)*time.Millisecond))
		eng.addEvent("session-1", evt)
	}
	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.TotalCount != 1000 {
		t.Errorf("TotalCount = %d, want 1000", result.TotalCount)
	}
	// Verify sort order.
	for i := 0; i < 1000-1; i++ {
		if result.Events[i].Timestamp.After(result.Events[i+1].Timestamp) {
			t.Errorf("Events not sorted at index %d", i)
			break
		}
	}
}

func TestGetTimeline_SessionFilterIsolation(t *testing.T) {
	// Events from one session should not leak to
	// another.
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	eng.addEvent("session-1", makeTestEvent("http", "request", "session-1", now))
	eng.addEvent("session-2", makeTestEvent("mcp", "request", "session-2", now))

	r1, _ := GetTimeline(context.Background(), eng, "session-1")
	r2, _ := GetTimeline(context.Background(), eng, "session-2")

	if r1.TotalCount != 1 {
		t.Errorf("session-1 TotalCount = %d, want 1", r1.TotalCount)
	}
	if r2.TotalCount != 1 {
		t.Errorf("session-2 TotalCount = %d, want 1", r2.TotalCount)
	}
	if r1.Events[0].Protocol != "http" {
		t.Errorf("session-1 first event protocol = %q, want http", r1.Events[0].Protocol)
	}
	if r2.Events[0].Protocol != "mcp" {
		t.Errorf("session-2 first event protocol = %q, want mcp", r2.Events[0].Protocol)
	}
}

func TestGetTimeline_EmptyProtocolAndSeverity(t *testing.T) {
	eng := newMockEngine()
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	evt := makeTestEvent("", "", "session-1", now)
	evt.Severity = ""
	eng.addEvent("session-1", evt)

	result, err := GetTimeline(context.Background(), eng, "session-1")
	if err != nil {
		t.Fatalf("GetTimeline: %v", err)
	}
	if result.TotalCount != 1 {
		t.Errorf("TotalCount = %d, want 1", result.TotalCount)
	}
	// Protocol and severity counts should include
	// the empty string keys.
	if result.ProtocolCounts[""] != 1 {
		t.Errorf("ProtocolCounts[''] = %d, want 1", result.ProtocolCounts[""])
	}
}
