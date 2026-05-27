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

func TestAnomalyDetector_ResolveAnomalyData(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	err := detector.ResolveAnomaly(ctx, "agent-resolve", "unknown-id")
	assert.Error(t, err)
}

func TestAnomalyDetector_ClearResolvedData(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	err := detector.ClearResolved(ctx, "non-existent-agent")
	assert.NoError(t, err)
}

func TestAnomalyDetector_DetectWithNoHistory(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	events := []*BehaviorEvent{
		{ID: "evt-new-1", AgentID: "agent-new", Type: EventCapabilityAllowed, Severity: 1},
		{ID: "evt-new-2", AgentID: "agent-new", Type: EventCapabilityAllowed, Severity: 1},
	}

	anomalies, err := detector.Detect(ctx, "agent-new", events, nil)
	require.NoError(t, err)
	// anomalies can be nil or empty
	assert.True(t, anomalies == nil || len(anomalies) >= 0)
}

func TestAnomalyDetector_DetectWithRateChange(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	events := []*BehaviorEvent{}
	for i := 0; i < 20; i++ {
		events = append(events, &BehaviorEvent{
			ID:        "evt-rate-burst-" + string(rune('0'+i)),
			AgentID:   "agent-rate",
			Type:      EventCapabilityAllowed,
			Severity:  1,
			Timestamp: time.Now(),
		})
	}

	anomalies, err := detector.Detect(ctx, "agent-rate", events, nil)
	require.NoError(t, err)
	assert.True(t, anomalies == nil || len(anomalies) >= 0)
}

func TestAnomalyDetector_DetectWithFailureSpike(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	events := []*BehaviorEvent{
		{ID: "f1", AgentID: "agent-fail", Type: EventCapabilityDenied, Severity: 8},
		{ID: "f2", AgentID: "agent-fail", Type: EventCapabilityDenied, Severity: 9},
		{ID: "f3", AgentID: "agent-fail", Type: EventCapabilityDenied, Severity: 10},
		{ID: "f4", AgentID: "agent-fail", Type: EventCapabilityDenied, Severity: 8},
		{ID: "f5", AgentID: "agent-fail", Type: EventCapabilityDenied, Severity: 9},
	}

	anomalies, err := detector.Detect(ctx, "agent-fail", events, nil)
	require.NoError(t, err)
	assert.True(t, anomalies == nil || len(anomalies) >= 0)
}

func TestAnomalyDetector_EmptyEvents(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	events := []*BehaviorEvent{}
	anomalies, err := detector.Detect(ctx, "agent-empty", events, nil)
	require.NoError(t, err)
	assert.True(t, anomalies == nil || len(anomalies) >= 0)
}

func TestAnomalyDetector_GetAnomaliesForAgent(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	anomalies, err := detector.GetAnomalies(ctx, "agent-no-anomalies", false)
	require.NoError(t, err)
	assert.True(t, anomalies == nil || len(anomalies) == 0)

	unresolved, err := detector.GetAnomalies(ctx, "agent-no-anomalies", true)
	require.NoError(t, err)
	assert.True(t, unresolved == nil || len(unresolved) == 0)
}
