// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package score

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselineEngine_UpdateBaselineData(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		err := be.RecordEvent(ctx, &BehaviorEvent{
			ID:        "evt-" + string(rune('0'+i)),
			AgentID:   "agent-baseline",
			Type:      EventCapabilityAllowed,
			Severity:  1,
			Timestamp: time.Now(),
		})
		assert.NoError(t, err)
	}

	err := be.UpdateBaseline(ctx, "agent-baseline")
	assert.NoError(t, err)

	baseline, err := be.GetBaseline(ctx, "agent-baseline")
	require.NoError(t, err)
	assert.NotNil(t, baseline)
}

func TestBaselineEngine_UpdateBaselineNonExistent(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()
	err := be.UpdateBaseline(ctx, "non-existent")
	assert.NoError(t, err)
}

func TestBaselineEngine_CalculateDeviationData(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := be.RecordEvent(ctx, &BehaviorEvent{
			ID:        "evt-dev-" + string(rune('0'+i)),
			AgentID:   "agent-deviation",
			Type:      EventCapabilityAllowed,
			Severity:  3,
			Timestamp: time.Now(),
		})
		assert.NoError(t, err)
	}

	deviation, err := be.CalculateDeviation(ctx, "agent-deviation")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deviation, float64(0))
}

func TestBaselineEngine_CalculateDeviationNonExistent(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	deviation, err := be.CalculateDeviation(ctx, "non-existent")
	require.NoError(t, err)
	assert.Equal(t, 0.0, deviation)
}

func TestBaselineEngine_NewEngineDefaults(t *testing.T) {
	be := NewBaselineEngine(0)
	assert.NotNil(t, be)
	be2 := NewBaselineEngine(-1)
	assert.NotNil(t, be2)
}

func TestBaselineEngine_GetRecentEventsData(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		err := be.RecordEvent(ctx, &BehaviorEvent{
			ID:        "evt-recent-" + string(rune('0'+i)),
			AgentID:   "agent-recent",
			Type:      EventCapabilityAllowed,
			Severity:  2,
			Timestamp: time.Now().Add(-time.Duration(i) * time.Hour),
		})
		assert.NoError(t, err)
	}

	events, err := be.GetRecentEvents(ctx, "agent-recent", 10)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(events), 10)
}

func TestBaselineEngine_GetRecentEventsAll(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		err := be.RecordEvent(ctx, &BehaviorEvent{
			ID:        "evt-recent-all-" + string(rune('0'+i)),
			AgentID:   "agent-recent-all",
			Type:      EventCapabilityAllowed,
			Severity:  2,
			Timestamp: time.Now(),
		})
		assert.NoError(t, err)
	}

	// Get all events - limit 0 returns all
	allEvents, err := be.GetRecentEvents(ctx, "agent-recent-all", 0)
	require.NoError(t, err)
	// Should return all 10 events
	assert.Equal(t, 10, len(allEvents))
}

func TestBaselineEngine_GetRecentEventsNonExistent(t *testing.T) {
	be := NewBaselineEngine(100)
	ctx := context.Background()

	events, err := be.GetRecentEvents(ctx, "non-existent", 10)
	require.NoError(t, err)
	assert.True(t, events == nil || len(events) == 0)
}
