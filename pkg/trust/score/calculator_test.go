// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Calculator Tests

package score

import (
	"context"
	"testing"
)

func TestNewCalculator(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)
	if calc == nil {
		t.Fatal("NewCalculator returned nil")
	}
}

func TestNewCalculator_NilConfig(t *testing.T) {
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(nil, baseline)
	if calc == nil {
		t.Fatal("NewCalculator returned nil")
	}
}

func TestCalculator_Calculate_NewAgent(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)

	score, err := calc.Calculate(context.Background(), "new-agent")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}
	if score.AgentID != "new-agent" {
		t.Errorf("AgentID mismatch")
	}
	if score.Level != ScoreLevelTrusted {
		t.Errorf("New agent should be trusted, got %s", score.Level)
	}
}

func TestCalculator_Calculate_WithEvents(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)

	events := []*BehaviorEvent{
		{ID: "e1", AgentID: "agent-1", Type: EventCapabilityAllowed, Severity: 1},
		{ID: "e2", AgentID: "agent-1", Type: EventCapabilityAllowed, Severity: 1},
		{ID: "e3", AgentID: "agent-1", Type: EventCapabilityDenied, Severity: 5},
	}

	score, err := calc.CalculateWithEvents(context.Background(), "agent-1", events)
	if err != nil {
		t.Fatalf("CalculateWithEvents failed: %v", err)
	}
	if score.AgentID != "agent-1" {
		t.Error("AgentID mismatch")
	}
}

func TestCalculator_GetScoreFactors(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)

	factors, err := calc.GetScoreFactors(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("GetScoreFactors failed: %v", err)
	}
	if len(factors) == 0 {
		t.Error("Should have at least one factor")
	}
}

func TestCompareScores(t *testing.T) {
	score1 := &TrustScore{AgentID: "a", Score: 80.0}
	score2 := &TrustScore{AgentID: "b", Score: 90.0}

	if CompareScores(score1, score2) != -1 {
		t.Error("score1 should be less than score2")
	}
	if CompareScores(score2, score1) != 1 {
		t.Error("score2 should be greater than score1")
	}
	if CompareScores(score1, score1) != 0 {
		t.Error("Same score should be equal")
	}
}
