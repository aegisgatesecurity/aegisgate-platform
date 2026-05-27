// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package score

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearAnomalies_ForAgent(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	_ = engine.RecordEvent(context.Background(), "agent-123", EventAnomalyDetected, "test", 5, "Test anomaly")

	err := engine.ClearAnomalies(context.Background(), "agent-123")
	assert.NoError(t, err)

	anomalies, err := engine.GetAnomalies(context.Background(), "agent-123", false)
	require.NoError(t, err)
	assert.Empty(t, anomalies)
}

func TestClearAnomalies_NonExistent(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	err := engine.ClearAnomalies(context.Background(), "non-existent-agent")
	assert.NoError(t, err)
}

func TestRecordAnomaly_BasicOperation(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	err := engine.RecordAnomaly(context.Background(), "agent-123", 5, "Test anomaly")
	assert.NoError(t, err)

	// Trigger score calculation to ensure anomalies are processed
	_, err = engine.GetScore(context.Background(), "agent-123")
	require.NoError(t, err)
}

func TestRecordAnomaly_AllSeverities(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	severities := []int{1, 3, 5, 7, 10}
	for _, sev := range severities {
		err := engine.RecordAnomaly(context.Background(), "agent-sev-test", sev, "Test severity")
		assert.NoError(t, err)
	}
}

func TestRecordAllowedDenied_Helpers(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	err := engine.RecordAllowed(context.Background(), "agent-helper", "read")
	assert.NoError(t, err)
	err = engine.RecordDenied(context.Background(), "agent-helper", "write", "not allowed")
	assert.NoError(t, err)
	err = engine.RecordCompliance(context.Background(), "agent-helper", true)
	assert.NoError(t, err)
	err = engine.RecordCompliance(context.Background(), "agent-helper", false)
	assert.NoError(t, err)
}

func TestGetAllScores_Empty(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	scores, err := engine.GetAllScores(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, scores)
}

func TestGetAnomalies_WithInactiveFlag(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	_ = engine.RecordAnomaly(context.Background(), "agent-active-test", 5, "Test")

	active, err := engine.GetAnomalies(context.Background(), "agent-active-test", true)
	require.NoError(t, err)
	all, err := engine.GetAnomalies(context.Background(), "agent-active-test", false)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(active), len(all))
}

func TestGetBaseline_NonExistent(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	baseline, err := engine.GetBaseline(context.Background(), "agent-baseline-test")
	require.NoError(t, err)
	assert.NotNil(t, baseline)
}

func TestResetScore_Operation(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	_ = engine.RecordEvent(context.Background(), "agent-reset", EventCapabilityAllowed, "read", 1, "Allowed")

	err := engine.ResetScore(context.Background(), "agent-reset")
	assert.NoError(t, err)

	score, err := engine.GetScore(context.Background(), "agent-reset")
	require.NoError(t, err)
	assert.NotNil(t, score)
}

func TestGetScore_NonExistent(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	score, err := engine.GetScore(context.Background(), "non-existent")
	require.NoError(t, err)
	assert.NotNil(t, score)
}

func TestGetScore_Stale(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	_, _ = engine.GetScore(context.Background(), "agent-stale")
}
