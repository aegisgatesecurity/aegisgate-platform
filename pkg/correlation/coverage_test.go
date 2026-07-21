// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Correlation coverage tests (D24, audit P2 #10)
//
// coverage_test.go covers the previously-untested paths
// in pkg/correlation/engine.go:
//   - ListEventsBySession (was 0%)
//   - containsPattern (was 50% — missing the false return path)
//
// These complement the existing engine_test.go with targeted
// coverage of the small-surface functions.
//
// Gotcha: RecordEvent triggers a cleanup on the FIRST call
// (lastCleanup is the zero time, so time.Since(zero) > 5min is true).
// The cleanup drops events older than 2 * CorrelationWindow. So
// RecordEvent tests must use timestamps within the last
// CorrelationWindow or events will silently be dropped.

package correlation

import (
	"context"
	"testing"
	"time"
)

// TestListEventsBySession_EmptySessionID covers the
// "sessionID is required" defense path.
func TestListEventsBySession_EmptySessionID(t *testing.T) {
	e := NewEngine()
	_, err := e.ListEventsBySession(context.Background(), "")
	if err == nil {
		t.Error("ListEventsBySession(\"\") should return an error")
	}
}

// TestListEventsBySession_NoEvents covers the "no events
// recorded" path.
func TestListEventsBySession_NoEvents(t *testing.T) {
	e := NewEngine()
	events, err := e.ListEventsBySession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("ListEventsBySession: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %d events, want 0", len(events))
	}
}

// TestListEventsBySession_HappyPath covers the main path:
// record events under multiple sessions, then list
// one session's events and verify only those are returned.
func TestListEventsBySession_HappyPath(t *testing.T) {
	e := NewEngine()
	now := time.Now().UTC()

	// Record 3 events across 2 sessions.
	// Timestamps must be within CorrelationWindow (default 15 min)
	// because RecordEvent triggers a cleanup that drops older events
	// on its first call (lastCleanup is zero on the first call).
	correlationWindow := e.cfg.CorrelationWindow
	if err := e.RecordEvent(context.Background(), &Event{
		Timestamp: now.Add(-correlationWindow + 1*time.Minute),
		AgentID:   "agent-1",
		SessionID: "sess-A",
		Protocol:  "mcp",
		EventType: "request",
		Severity:  "info",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("RecordEvent 1: %v", err)
	}
	if err := e.RecordEvent(context.Background(), &Event{
		Timestamp: now.Add(-2 * time.Minute),
		AgentID:   "agent-1",
		SessionID: "sess-A",
		Protocol:  "mcp",
		EventType: "response",
		Severity:  "info",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("RecordEvent 2: %v", err)
	}
	if err := e.RecordEvent(context.Background(), &Event{
		Timestamp: now.Add(-30 * time.Second),
		AgentID:   "agent-2",
		SessionID: "sess-B",
		Protocol:  "a2a",
		EventType: "message",
		Severity:  "info",
		Decision:  "allow",
	}); err != nil {
		t.Fatalf("RecordEvent 3: %v", err)
	}

	// List events for sess-A (expect 2)
	aEvents, err := e.ListEventsBySession(context.Background(), "sess-A")
	if err != nil {
		t.Fatalf("ListEventsBySession(sess-A): %v", err)
	}
	if len(aEvents) != 2 {
		t.Errorf("sess-A: got %d events, want 2", len(aEvents))
	}
	for _, evt := range aEvents {
		if evt.SessionID != "sess-A" {
			t.Errorf("event has sessionID %q, want sess-A", evt.SessionID)
		}
	}

	// List events for sess-B (expect 1)
	bEvents, err := e.ListEventsBySession(context.Background(), "sess-B")
	if err != nil {
		t.Fatalf("ListEventsBySession(sess-B): %v", err)
	}
	if len(bEvents) != 1 {
		t.Errorf("sess-B: got %d events, want 1", len(bEvents))
	}

	// List events for non-existent session (expect 0, not error)
	noneEvents, err := e.ListEventsBySession(context.Background(), "sess-NONE")
	if err != nil {
		t.Fatalf("ListEventsBySession(sess-NONE): %v", err)
	}
	if len(noneEvents) != 0 {
		t.Errorf("sess-NONE: got %d events, want 0", len(noneEvents))
	}
}

// TestContainsPattern_Found covers the "pattern present in
// slice" return path (true).
func TestContainsPattern_Found(t *testing.T) {
	if !containsPattern([]string{"a", "b", "c"}, "b") {
		t.Error("containsPattern should return true when pattern exists")
	}
}

// TestContainsPattern_NotFound covers the "pattern absent"
// return path (false).
func TestContainsPattern_NotFound(t *testing.T) {
	if containsPattern([]string{"a", "b", "c"}, "z") {
		t.Error("containsPattern should return false when pattern is absent")
	}
}

// TestContainsPattern_Empty covers the "empty slice" edge case.
func TestContainsPattern_Empty(t *testing.T) {
	if containsPattern([]string{}, "a") {
		t.Error("containsPattern should return false on empty slice")
	}
}
