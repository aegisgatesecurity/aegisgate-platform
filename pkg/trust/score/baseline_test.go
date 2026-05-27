package score

import (
	"context"
	"testing"
)

func TestNewBaselineEngine(t *testing.T) {
	engine := NewBaselineEngine(100)
	if engine == nil {
		t.Fatal("NewBaselineEngine returned nil")
	}
}

func TestBaselineEngine_RecordEvent(t *testing.T) {
	engine := NewBaselineEngine(100)
	ctx := context.Background()
	err := engine.RecordEvent(ctx, &BehaviorEvent{ID: "e1", AgentID: "a1", Type: EventCapabilityAllowed})
	if err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}
}

func TestBaselineEngine_RecordEvent_MissingEventID(t *testing.T) {
	engine := NewBaselineEngine(100)
	err := engine.RecordEvent(context.Background(), &BehaviorEvent{ID: "", AgentID: "a1", Type: EventCapabilityAllowed})
	if err == nil {
		t.Error("Expected error for missing event ID")
	}
}

func TestBaselineEngine_RecordEvent_MissingAgentID(t *testing.T) {
	engine := NewBaselineEngine(100)
	err := engine.RecordEvent(context.Background(), &BehaviorEvent{ID: "e1", AgentID: "", Type: EventCapabilityAllowed})
	if err == nil {
		t.Error("Expected error for missing agent ID")
	}
}

func TestBaselineEngine_GetBaseline_NewAgent(t *testing.T) {
	engine := NewBaselineEngine(100)
	baseline, err := engine.GetBaseline(context.Background(), "new-agent")
	if err != nil {
		t.Fatalf("GetBaseline failed: %v", err)
	}
	if baseline.AgentID != "new-agent" {
		t.Errorf("AgentID mismatch: %s", baseline.AgentID)
	}
}

func TestBaselineEngine_GetBaseline_AfterEvents(t *testing.T) {
	engine := NewBaselineEngine(100)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{ID: "e" + string(rune('0'+i)), AgentID: "a1", Type: EventCapabilityAllowed})
	}
	baseline, _ := engine.GetBaseline(ctx, "a1")
	if baseline.TotalEvents != 5 {
		t.Errorf("Expected 5 events, got %d", baseline.TotalEvents)
	}
}

func TestBaselineEngine_CalculateDeviation_NoData(t *testing.T) {
	engine := NewBaselineEngine(100)
	dev, err := engine.CalculateDeviation(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0 deviation, got %f", dev)
	}
}

func TestBaselineEngine_GetRecentEvents(t *testing.T) {
	engine := NewBaselineEngine(100)
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{ID: "e" + string(rune('a'+i)), AgentID: "a1", Type: EventCapabilityAllowed})
	}
	events, _ := engine.GetRecentEvents(ctx, "a1", 10)
	if len(events) != 10 {
		t.Errorf("Expected 10 events, got %d", len(events))
	}
}

func TestBaselineEngine_GetRecentEvents_Empty(t *testing.T) {
	engine := NewBaselineEngine(100)
	events, _ := engine.GetRecentEvents(context.Background(), "unknown", 10)
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}
