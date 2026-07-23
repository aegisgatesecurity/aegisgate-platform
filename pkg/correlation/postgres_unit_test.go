// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Correlation PostgreSQL Store Unit Tests
//
// Tests input validation, constructor, and nil/closed paths
// without requiring a live PostgreSQL connection.
//go:build !integration

package correlation

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNewPostgresCorrelationStore_NilPool(t *testing.T) {
	// Constructor accepts nil pool — it's a simple struct literal
	store := NewPostgresCorrelationStore(nil)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	// Close is always a no-op
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPostgresCorrelationStore_RecordEvent_NilEvent(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	// RecordEvent with nil event should return error before hitting pool
	err := store.RecordEvent(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil event")
	}
	if err.Error() != "correlation: RecordEvent: event is nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPostgresCorrelationStore_ListEventsBySession_EmptyID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsBySession(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestPostgresCorrelationStore_ListEventsByAgent_EmptyID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgent(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresCorrelationStore_ListEventsByAgentAndSession_EmptyAgentID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgentAndSession(context.Background(), "", "session-1")
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresCorrelationStore_ListEventsByAgentAndSession_EmptySessionID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.ListEventsByAgentAndSession(context.Background(), "agent-1", "")
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestPostgresCorrelationStore_Analyze_EmptyAgentID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.Analyze(context.Background(), "", "session-1", 0)
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestPostgresCorrelationStore_Analyze_EmptySessionID(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	_, err := store.Analyze(context.Background(), "agent-1", "", 0)
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestPostgresCorrelationStore_Close_NoOp(t *testing.T) {
	store := NewPostgresCorrelationStore(nil)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Double close should also work
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPostgresCorrelationStore_RecordEvent_ValidEvent_NilPool(t *testing.T) {
	// A non-nil event with nil pool will panic on pool.Exec.
	// We can't test this without a mock pool, but we verify the
	// nil event path works. Valid events need integration tests.
	t.Skip("valid event with nil pool panics; needs integration test")
}

func TestInMemoryCorrelationStore_RecordAndList(t *testing.T) {
	engine := NewEngine()
	store := NewInMemoryCorrelationStore(engine)

	ctx := context.Background()
	event := &Event{
		ID:        "evt-1",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "request",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"key": "value"},
		Severity:  "low",
		Decision:  "allow",
		Metadata:  map[string]string{"source": "test"},
	}

	if err := store.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// List by session
	events, err := store.ListEventsBySession(ctx, "session-1")
	if err != nil {
		t.Fatalf("ListEventsBySession: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// List by agent
	events, err = store.ListEventsByAgent(ctx, "agent-1")
	if err != nil {
		t.Fatalf("ListEventsByAgent: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// List by agent and session
	events, err = store.ListEventsByAgentAndSession(ctx, "agent-1", "session-1")
	if err != nil {
		t.Fatalf("ListEventsByAgentAndSession: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestInMemoryCorrelationStore_Analyze(t *testing.T) {
	engine := NewEngine()
	store := NewInMemoryCorrelationStore(engine)
	ctx := context.Background()

	event := &Event{
		ID:        "evt-2",
		Protocol:  "a2a",
		AgentID:   "agent-2",
		SessionID: "session-2",
		EventType: "message",
		Timestamp: time.Now(),
		Severity:  "medium",
		Decision:  "allow",
	}
	if err := store.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// Analyze with 1 hour window
	events, err := store.Analyze(ctx, "agent-2", "session-2", time.Hour)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestInMemoryCorrelationStore_Prune(t *testing.T) {
	engine := NewEngine()
	store := NewInMemoryCorrelationStore(engine)
	ctx := context.Background()

	// Record an old event
	oldEvent := &Event{
		ID:        "evt-old",
		Protocol:  "mcp",
		AgentID:   "agent-3",
		SessionID: "session-3",
		EventType: "request",
		Timestamp: time.Now().Add(-2 * time.Hour), // 2 hours ago
		Severity:  "low",
		Decision:  "allow",
	}
	if err := store.RecordEvent(ctx, oldEvent); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// Prune events older than 1 hour
	pruned, err := store.Prune(ctx, time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}

	// Verify it's gone from agent index
	events, err := store.ListEventsByAgent(ctx, "agent-3")
	if err != nil {
		t.Fatalf("ListEventsByAgent: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events after prune, got %d", len(events))
	}
}

func TestInMemoryCorrelationStore_Close(t *testing.T) {
	engine := NewEngine()
	store := NewInMemoryCorrelationStore(engine)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Engine edge case tests to improve coverage

func TestEngine_RecordEvent_NilEvent(t *testing.T) {
	engine := NewEngine()
	err := engine.RecordEvent(context.Background(), nil)
	if err != nil {
		t.Fatalf("RecordEvent(nil) should return nil, got: %v", err)
	}
}

func TestEngine_Analyze_EmptyStore(t *testing.T) {
	engine := NewEngine()
	result, err := engine.Analyze(context.Background(), "agent-1", "session-1")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestEngine_ListEventsBySession_EmptySession(t *testing.T) {
	engine := NewEngine()
	_, err := engine.ListEventsBySession(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestEngine_PatternMatching_MultipleEvents(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Record MCP error
	engine.RecordEvent(ctx, &Event{
		ID:        "evt-m1",
		Protocol:  "mcp",
		AgentID:   "agent-a",
		SessionID: "session-a",
		EventType: "error",
		Severity:  "high",
		Decision:  "block",
		Timestamp: time.Now(),
	})

	// Record A2A request (should trigger mcp_error_injection pattern)
	engine.RecordEvent(ctx, &Event{
		ID:        "evt-a1",
		Protocol:  "a2a",
		AgentID:   "agent-a",
		SessionID: "session-a",
		EventType: "request",
		Severity:  "medium",
		Decision:  "allow",
		Timestamp: time.Now(),
	})

	result, err := engine.Analyze(ctx, "agent-a", "session-a")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(result.MatchedPatterns) == 0 {
		t.Error("expected at least one matched pattern")
	}
}

func TestEngine_RateAnomaly(t *testing.T) {
	engine := NewEngineWithConfig(&Config{
		EnablePatternMatching:   true,
		MinPatternWeight:        0.5,
		EnableRateCorrelation:   true,
		RateThresholdMultiplier: 2.0,
		CorrelationWindow:       5 * time.Minute,
	})
	ctx := context.Background()

	// Create 6 MCP events (>50% protocol concentration with rate threshold)
	for i := 0; i < 6; i++ {
		engine.RecordEvent(ctx, &Event{
			ID:        fmt.Sprintf("evt-rate-%d", i),
			Protocol:  "mcp",
			AgentID:   "agent-r",
			SessionID: "session-r",
			EventType: "request",
			Severity:  "high",
			Decision:  "block",
			Timestamp: time.Now(),
		})
	}

	result, err := engine.Analyze(ctx, "agent-r", "session-r")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Should detect rate anomaly
	if result.Metadata["rate_anomaly_protocol"] != "mcp" {
		t.Errorf("expected rate_anomaly_protocol=mcp, got %s", result.Metadata["rate_anomaly_protocol"])
	}
}

func TestNewEvent_CreatesDefaults(t *testing.T) {
	evt := NewEvent("mcp", "request", "agent-1", "session-1")
	if evt.Protocol != "mcp" {
		t.Errorf("expected protocol=mcp, got %s", evt.Protocol)
	}
	if evt.EventType != "request" {
		t.Errorf("expected eventType=request, got %s", evt.EventType)
	}
	if evt.Severity != "low" {
		t.Errorf("expected severity=low, got %s", evt.Severity)
	}
	if evt.Data == nil {
		t.Error("expected non-nil Data")
	}
	if evt.Metadata == nil {
		t.Error("expected non-nil Metadata")
	}
}

func TestNewCorrelationResult_Defaults(t *testing.T) {
	result := NewCorrelationResult()
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
	if result.MatchedPatterns == nil {
		t.Error("expected non-nil MatchedPatterns")
	}
	if result.Metadata == nil {
		t.Error("expected non-nil Metadata")
	}
}
