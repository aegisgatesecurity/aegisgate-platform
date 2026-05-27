// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Baseline Coverage Tests (95%+ target)
// ============================================================================

package score

import (
	"context"
	"testing"
)

// TestCalculateDeviation_InsufficientEvents tests when events < 10
func TestCalculateDeviation_InsufficientEvents(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "event-" + string(rune('0'+i)),
			AgentID: "agent-few",
			Type:    EventCapabilityAllowed,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-few")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0.0 for insufficient events, got %v", dev)
	}
}

// TestCalculateDeviation_ExactThreshold tests exactly 10 events
func TestCalculateDeviation_ExactThreshold(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 10; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "event-10-" + string(rune('0'+i)),
			AgentID: "agent-ten",
			Type:    EventCapabilityAllowed,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-ten")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev < 0 {
		t.Errorf("Deviation should not be negative: %v", dev)
	}
}

// TestCalculateDeviation_NoDeniedEvents tests pure allowed events
func TestCalculateDeviation_NoDeniedEvents(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 20; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "allow-" + string(rune(i)),
			AgentID: "agent-clean",
			Type:    EventCapabilityAllowed,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-clean")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0.0 for no denied events, got %v", dev)
	}
}

// TestCalculateDeviation_AllDenied tests all denied events
func TestCalculateDeviation_AllDenied(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 20; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "deny-" + string(rune(i)),
			AgentID: "agent-bad",
			Type:    EventCapabilityDenied,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-bad")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev < 0 {
		t.Errorf("Deviation should not be negative: %v", dev)
	}
}

// TestCalculateDeviation_MixedEvents tests mixed denied and allowed
func TestCalculateDeviation_MixedEvents(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 10; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "allow-mix-" + string(rune(i)),
			AgentID: "agent-mixed",
			Type:    EventCapabilityAllowed,
		})
	}
	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "deny-mix-" + string(rune(i)),
			AgentID: "agent-mixed",
			Type:    EventCapabilityDenied,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-mixed")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev < 0 {
		t.Errorf("Deviation should not be negative: %v", dev)
	}
}

// TestCalculateDeviation_WithAnomalyEvents tests anomaly events impact
func TestCalculateDeviation_WithAnomalyEvents(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 15; i++ {
		et := EventCapabilityAllowed
		if i > 12 {
			et = EventAnomalyDetected
		}
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "anomaly-" + string(rune(i)),
			AgentID: "agent-anomaly",
			Type:    et,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-anomaly")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev < 0 {
		t.Errorf("Deviation should not be negative: %v", dev)
	}
}

// TestCalculateDeviation_NonExistentAgent tests agent with no history
func TestCalculateDeviation_NonExistentAgent(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	dev, err := engine.CalculateDeviation(ctx, "agent-nonexistent")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0.0 for non-existent agent, got %v", dev)
	}
}

// TestCalculateDeviation_ManyEvents tests with many events
func TestCalculateDeviation_ManyEvents(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 50; i++ {
		et := EventCapabilityAllowed
		if i%5 == 0 {
			et = EventCapabilityDenied
		}
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "many-" + string(rune(i)),
			AgentID: "agent-many",
			Type:    et,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-many")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev < 0 {
		t.Errorf("Deviation should not be negative: %v", dev)
	}
}

// TestCalculateDeviation_ZeroBaseline tests with baseline having zero total
func TestCalculateDeviation_ZeroBaseline(t *testing.T) {
	ctx := context.Background()
	engine := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-zero": {
				AgentID:     "agent-zero",
				TotalEvents: 0,
				DeniedCount: 0,
			},
		},
		events: make(map[string][]*BehaviorEvent),
		window: 100,
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-zero")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0.0 for zero baseline, got %v", dev)
	}
}

// TestCalculateDeviation_AllDeniedBaseline tests with all denied baseline
func TestCalculateDeviation_AllDeniedBaseline(t *testing.T) {
	ctx := context.Background()
	engine := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-all-denied": {
				AgentID:     "agent-all-denied",
				TotalEvents: 50,
				DeniedCount: 50,
			},
		},
		events: map[string][]*BehaviorEvent{
			"agent-all-denied": {},
		},
		window: 100,
	}

	for i := 0; i < 20; i++ {
		engine.events["agent-all-denied"] = append(engine.events["agent-all-denied"], &BehaviorEvent{
			ID:      "current-" + string(rune(i)),
			AgentID: "agent-all-denied",
			Type:    EventCapabilityDenied,
		})
	}

	dev, err := engine.CalculateDeviation(ctx, "agent-all-denied")
	if err != nil {
		t.Fatalf("CalculateDeviation failed: %v", err)
	}
	if dev != 0.0 {
		t.Errorf("Expected 0.0 when rates match, got %v", dev)
	}
}

// TestUpdateBaseline_EmptyAgent tests update with no history
func TestUpdateBaseline_EmptyAgent(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	err := engine.UpdateBaseline(ctx, "agent-no-history")
	if err != nil {
		t.Fatalf("UpdateBaseline failed: %v", err)
	}

	baseline, err := engine.GetBaseline(ctx, "agent-no-history")
	if err != nil {
		t.Fatalf("GetBaseline failed: %v", err)
	}
	if baseline.AgentID != "agent-no-history" {
		t.Errorf("AgentID mismatch")
	}
}

// TestUpdateBaseline_MultipleTimes tests updating baseline repeatedly
func TestUpdateBaseline_MultipleTimes(t *testing.T) {
	ctx := context.Background()
	engine := NewBaselineEngine(100)

	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(ctx, &BehaviorEvent{
			ID:      "update-" + string(rune(i)),
			AgentID: "agent-update",
			Type:    EventCapabilityAllowed,
		})
	}

	for i := 0; i < 3; i++ {
		err := engine.UpdateBaseline(ctx, "agent-update")
		if err != nil {
			t.Fatalf("UpdateBaseline attempt %d failed: %v", i, err)
		}
	}

	baseline, err := engine.GetBaseline(ctx, "agent-update")
	if err != nil {
		t.Fatalf("GetBaseline failed: %v", err)
	}
	if baseline.TotalEvents != 5 {
		t.Errorf("Expected 5 events, got %d", baseline.TotalEvents)
	}
}
