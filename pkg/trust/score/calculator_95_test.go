// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package score

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculator_calculateDecayWithBaseline(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := baseline.RecordEvent(ctx, &BehaviorEvent{
			ID:       "decay-evt-" + string(rune('0'+i)),
			AgentID:  "agent-decay",
			Type:     EventCapabilityAllowed,
			Severity: 2,
		})
		assert.NoError(t, err)
	}

	bl, err := baseline.GetBaseline(ctx, "agent-decay")
	require.NoError(t, err)
	decay := calc.calculateDecay(bl)
	assert.GreaterOrEqual(t, decay, 0.0)
	assert.LessOrEqual(t, decay, 1.0)
}

func TestCalculator_determineLevelData(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)

	tests := []struct {
		score    float64
		expected ScoreLevel
	}{
		{10, ScoreLevelCritical},
		{30, ScoreLevelLow},
		{60, ScoreLevelMedium},
		{80, ScoreLevelHigh},
		{95, ScoreLevelTrusted},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			level := calc.determineLevel(tt.score)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestCalculator_GetScoreFactorsData(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := baseline.RecordEvent(ctx, &BehaviorEvent{
			ID:       "factors-evt-" + string(rune('0'+i)),
			AgentID:  "agent-factors",
			Type:     EventCapabilityAllowed,
			Severity: 1,
		})
		assert.NoError(t, err)
	}

	factors, err := calc.GetScoreFactors(ctx, "agent-factors")
	require.NoError(t, err)
	assert.NotNil(t, factors)
	assert.Greater(t, len(factors), 0)
}

func TestCalculator_CalculateWithEventsData(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)
	ctx := context.Background()

	events := []*BehaviorEvent{
		{ID: "calc-1", AgentID: "agent-calc", Type: EventCapabilityAllowed, Severity: 1},
		{ID: "calc-2", AgentID: "agent-calc", Type: EventCapabilityAllowed, Severity: 2},
		{ID: "calc-3", AgentID: "agent-calc", Type: EventCompliancePass, Severity: 1},
	}

	score, err := calc.CalculateWithEvents(ctx, "agent-calc", events)
	require.NoError(t, err)
	assert.NotNil(t, score)
	assert.Greater(t, score.Score, 0.0)
}

func TestCalculator_CalculateWithEmptyEvents(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)
	ctx := context.Background()

	events := []*BehaviorEvent{}
	score, err := calc.CalculateWithEvents(ctx, "agent-empty", events)
	require.NoError(t, err)
	assert.NotNil(t, score)
}

func TestCalculator_CalculateWithDenials(t *testing.T) {
	config := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(config, baseline)
	ctx := context.Background()

	events := []*BehaviorEvent{
		{ID: "deny-1", AgentID: "agent-deny", Type: EventCapabilityDenied, Severity: 8},
		{ID: "deny-2", AgentID: "agent-deny", Type: EventCapabilityDenied, Severity: 9},
		{ID: "deny-3", AgentID: "agent-deny", Type: EventCapabilityDenied, Severity: 10},
	}

	score, err := calc.CalculateWithEvents(ctx, "agent-deny", events)
	require.NoError(t, err)
	assert.NotNil(t, score)
	assert.Less(t, score.Score, 100.0)
}
