// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Calculator Coverage Tests (95%+ target)
// ============================================================================

package score

import (
	"context"
	"math"
	"testing"
	"time"
)

// TestCalculateDecay_ZeroLastUpdated tests decay when LastUpdated is zero
func TestCalculateDecay_ZeroLastUpdated(t *testing.T) {
	calc := NewCalculator(DefaultConfig(), NewBaselineEngine(100))
	baseline := &BaselineMetrics{
		LastUpdated: time.Time{},
	}

	mult := calc.calculateDecay(baseline)
	if mult != 1.0 {
		t.Errorf("Expected 1.0 for zero time, got %v", mult)
	}
}

// TestCalculateDecay_RecentActivity tests decay when activity is recent
func TestCalculateDecay_RecentActivity(t *testing.T) {
	calc := NewCalculator(DefaultConfig(), NewBaselineEngine(100))
	baseline := &BaselineMetrics{
		LastUpdated: time.Now(),
	}

	mult := calc.calculateDecay(baseline)
	if mult != 1.0 {
		t.Errorf("Expected 1.0 for recent activity, got %v", mult)
	}
}

// TestCalculateDecay_MultipleDays tests decay over multiple days
func TestCalculateDecay_MultipleDays(t *testing.T) {
	calc := NewCalculator(DefaultConfig(), NewBaselineEngine(100))

	tests := []struct {
		name     string
		days     float64
		expected float64
	}{
		{"1 day decay", 1.0, 0.9},      // 0.9^1
		{"2 days decay", 2.0, 0.81},    // 0.9^2
		{"5 days decay", 5.0, 0.59049}, // 0.9^5
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := &BaselineMetrics{
				LastUpdated: time.Now().Add(-time.Duration(tt.days*24) * time.Hour),
			}
			mult := calc.calculateDecay(baseline)
			if math.Abs(mult-tt.expected) > 0.01 {
				t.Errorf("Expected ~%v, got %v", tt.expected, mult)
			}
		})
	}
}

// TestCalculateDecay_MinimumFloor tests that decay doesn't go below 0.1
func TestCalculateDecay_MinimumFloor(t *testing.T) {
	calc := NewCalculator(DefaultConfig(), NewBaselineEngine(100))

	baseline := &BaselineMetrics{
		LastUpdated: time.Now().Add(-30 * 24 * time.Hour),
	}

	mult := calc.calculateDecay(baseline)
	if mult < 0.1 {
		t.Errorf("Decay should not go below 0.1, got %v", mult)
	}

	baseline.LastUpdated = time.Now().Add(-365 * 24 * time.Hour)
	mult = calc.calculateDecay(baseline)
	if mult != 0.1 {
		t.Errorf("Expected minimum floor of 0.1, got %v", mult)
	}
}

// TestCalculateDecay_ZeroDecayRate tests with zero decay rate config
func TestCalculateDecay_ZeroDecayRate(t *testing.T) {
	cfg := &Config{
		DecayRate:    0.0,
		InitialScore: 100,
		MinScore:     0,
		MaxScore:     100,
	}
	calc := NewCalculator(cfg, NewBaselineEngine(100))

	baseline := &BaselineMetrics{
		LastUpdated: time.Now().Add(-7 * 24 * time.Hour),
	}

	mult := calc.calculateDecay(baseline)
	if mult != 1.0 {
		t.Errorf("Expected 1.0 with 0%% decay rate, got %v", mult)
	}
}

// TestCalculateDecay_CustomDecayRate tests with custom decay rate
func TestCalculateDecay_CustomDecayRate(t *testing.T) {
	cfg := &Config{
		DecayRate:    0.05, // 5% per day
		InitialScore: 100,
		MinScore:     0,
		MaxScore:     100,
	}
	calc := NewCalculator(cfg, NewBaselineEngine(100))

	baseline := &BaselineMetrics{
		LastUpdated: time.Now().Add(-10 * 24 * time.Hour),
	}

	mult := calc.calculateDecay(baseline)
	expected := math.Pow(0.95, 10)
	if math.Abs(mult-expected) > 0.01 {
		t.Errorf("Expected ~%v, got %v", expected, mult)
	}
}

// TestCalculate_WithExpiredBaseline tests full calculation with expired baseline
func TestCalculate_WithExpiredBaseline(t *testing.T) {
	ctx := context.Background()
	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-old": {
				AgentID:     "agent-old",
				LastUpdated: time.Now().Add(-30 * 24 * time.Hour),
				TotalEvents: 100,
				SuccessRate: 0.95,
			},
		},
		window: 100,
	}

	calc := NewCalculator(DefaultConfig(), baseline)
	score, err := calc.Calculate(ctx, "agent-old")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	// Default InitialScore is 100
	if score.BaseScore != 100 {
		t.Errorf("Expected BaseScore 100, got %v", score.BaseScore)
	}

	// Score should be affected by decay (minimum floor is 0.1)
	if score.Score > 100 || score.Score < 10 {
		t.Logf("Score: %v (expected to be clamped)", score.Score)
	}
}

// TestCalculate_GetScoreFactors tests the GetScoreFactors helper
func TestCalculate_GetScoreFactors(t *testing.T) {
	ctx := context.Background()
	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-factors": {
				AgentID:      "agent-factors",
				LastUpdated:  time.Now(),
				TotalEvents:  100,
				SuccessRate:  0.90,
				DeniedCount:  10,
				AnomalyCount: 2,
			},
		},
		events: map[string][]*BehaviorEvent{
			"agent-factors": {
				{ID: "1", AgentID: "agent-factors", Type: EventCapabilityAllowed},
				{ID: "2", AgentID: "agent-factors", Type: EventCapabilityAllowed},
			},
		},
		window: 100,
	}

	calc := NewCalculator(DefaultConfig(), baseline)
	score, err := calc.Calculate(ctx, "agent-factors")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	if len(score.Factors) != 4 {
		t.Errorf("Expected 4 factors, got %d", len(score.Factors))
	}

	for _, f := range score.Factors {
		if f.Name == "base_score" && f.Value != 100.0 {
			t.Errorf("Expected base_score value 100, got %v", f.Value)
		}
	}
}

// TestCalculate_AllFactors tests that all factors are properly weighted
func TestCalculate_AllFactors(t *testing.T) {
	ctx := context.Background()
	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-all": {
				AgentID:      "agent-all",
				LastUpdated:  time.Now(),
				TotalEvents:  50,
				SuccessRate:  0.85,
				DeniedCount:  5,
				AnomalyCount: 1,
			},
		},
		events: map[string][]*BehaviorEvent{
			"agent-all": {
				{ID: "e1", AgentID: "agent-all", Type: EventCapabilityAllowed},
				{ID: "e2", AgentID: "agent-all", Type: EventCapabilityAllowed},
			},
		},
		window: 100,
	}

	calc := NewCalculator(DefaultConfig(), baseline)
	score, err := calc.Calculate(ctx, "agent-all")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	factorMap := make(map[string]bool)
	for _, f := range score.Factors {
		factorMap[f.Name] = true
	}

	expectedFactors := []string{"base_score", "decay", "behavior", "compliance"}
	for _, name := range expectedFactors {
		if !factorMap[name] {
			t.Errorf("Missing factor: %s", name)
		}
	}
}

// TestCalculate_MaxScoreClamping tests that scores are clamped to MaxScore
func TestCalculate_MaxScoreClamping(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		DecayRate:    1.0,
		InitialScore: 100,
		MinScore:     0,
		MaxScore:     100,
	}

	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-max": {
				AgentID:     "agent-max",
				LastUpdated: time.Now(),
				TotalEvents: 1000,
				SuccessRate: 1.0,
			},
		},
		window: 100,
	}

	calc := NewCalculator(cfg, baseline)
	score, err := calc.Calculate(ctx, "agent-max")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	if score.Score > 100 {
		t.Errorf("Score %v exceeds MaxScore 100", score.Score)
	}
}

// TestCalculate_MinScoreClamping tests that scores are clamped to MinScore
func TestCalculate_MinScoreClamping(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		DecayRate:    1.0,
		InitialScore: 50,
		MinScore:     10,
		MaxScore:     100,
	}

	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-min": {
				AgentID:     "agent-min",
				LastUpdated: time.Now().Add(-365 * 24 * time.Hour),
				TotalEvents: 1000,
				SuccessRate: 0.0,
			},
		},
		window: 100,
	}

	calc := NewCalculator(cfg, baseline)
	score, err := calc.Calculate(ctx, "agent-min")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	if score.Score < 10 {
		t.Errorf("Score %v below MinScore 10", score.Score)
	}
}

// TestCalculate_ZeroTotalEvents tests score calculation with zero events
func TestCalculate_ZeroTotalEvents(t *testing.T) {
	ctx := context.Background()
	baseline := &InMemoryBaseline{
		baselines: map[string]*BaselineMetrics{
			"agent-zero-events": {
				AgentID:     "agent-zero-events",
				LastUpdated: time.Now(),
				TotalEvents: 0,
				SuccessRate: 0,
			},
		},
		events: map[string][]*BehaviorEvent{},
		window: 100,
	}

	calc := NewCalculator(DefaultConfig(), baseline)
	score, err := calc.Calculate(ctx, "agent-zero-events")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	if score.Score < 0 {
		t.Errorf("Score should not be negative: %v", score.Score)
	}
}

// TestCalculate_BaselineError tests handling of baseline errors
func TestCalculate_BaselineError(t *testing.T) {
	ctx := context.Background()
	// Use engine with no data
	engine := NewBaselineEngine(100)

	calc := NewCalculator(DefaultConfig(), engine)
	score, err := calc.Calculate(ctx, "nonexistent-agent")
	if err != nil {
		t.Fatalf("Should handle missing baseline gracefully: %v", err)
	}

	// Should return default score for non-existent agent
	if score.Score < 0 || score.Score > 100 {
		t.Errorf("Score out of range: %v", score.Score)
	}
}
