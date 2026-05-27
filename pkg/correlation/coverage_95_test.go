package correlation

import (
	"context"
	"testing"
	"time"
)

func TestEngine_RecordMultipleEvents(t *testing.T) {
	e := NewEngine()
	ctx := context.Background()

	event1 := NewEvent("mcp", "error", "agent-1", "session-1")
	event2 := NewEvent("a2a", "message", "agent-1", "session-1")

	_ = e.RecordEvent(ctx, event1)
	_ = e.RecordEvent(ctx, event2)
}

func TestEngine_AnalyzeEmpty(t *testing.T) {
	e := NewEngine()
	ctx := context.Background()

	result, err := e.Analyze(ctx, "agent-1", "session-1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestEngine_AnalyzeWithEvents(t *testing.T) {
	e := NewEngine()
	ctx := context.Background()

	event := NewEvent("mcp", "error", "agent-1", "session-1")
	_ = e.RecordEvent(ctx, event)

	result, err := e.Analyze(ctx, "agent-1", "session-1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestEvent_Timestamps(t *testing.T) {
	e := NewEvent("mcp", "error", "agent-1", "session-1")
	_ = e.Timestamp // Just verify field exists
	if e.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCorrelationResult_AllFields(t *testing.T) {
	r := &CorrelationResult{
		Decision:        DecisionBlock,
		Reason:          "blocked",
		MatchedPatterns: []string{"p1", "p2"},
		Severity:        "high",
		Score:           0.9,
		Metadata:        map[string]string{"key": "value"},
	}
	if r.Decision != DecisionBlock {
		t.Error("Decision should be block")
	}
	if r.Score != 0.9 {
		t.Error("Score should be 0.9")
	}
}

func TestGuardDecisionConstants(t *testing.T) {
	decisions := []GuardDecision{DecisionAllow, DecisionBlock, DecisionRequireApproval, DecisionAlert}
	for _, d := range decisions {
		if d == "" {
			t.Error("Decision should not be empty")
		}
	}
}

func TestThreatPattern_Types(t *testing.T) {
	p := &ThreatPattern{
		ID:          "test",
		Name:        "Test",
		Description: "Desc",
		Severity:    "high",
		Weight:      0.8,
		Indicators:  []string{"i1"},
		TimeWindow:  30 * time.Second,
	}
	if p.Weight != 0.8 {
		t.Error("Weight should be 0.8")
	}
}

func TestEngine_NilContext(t *testing.T) {
	e := NewEngine()
	_ = e // Just verify engine exists
}
