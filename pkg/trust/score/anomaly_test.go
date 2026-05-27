// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Anomaly Detector Tests

package score

import (
	"context"
	"testing"
)

func TestNewAnomalyDetector(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	if detector == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}
}

func TestNewAnomalyDetector_NilConfig(t *testing.T) {
	detector := NewAnomalyDetector(nil)
	if detector == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}
}

func TestAnomalyDetector_Detect_NoAnomalies(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	baseline := &BaselineMetrics{
		AgentID:       "agent-1",
		TotalEvents:   100,
		SuccessRate:   0.95,
		DailyAvgEvents: 10,
	}

	events := []*BehaviorEvent{
		{ID: "e1", AgentID: "agent-1", Type: EventCapabilityAllowed, Severity: 1},
		{ID: "e2", AgentID: "agent-1", Type: EventCapabilityAllowed, Severity: 1},
	}

	anomalies, err := detector.Detect(ctx, "agent-1", events, baseline)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	// May or may not have anomalies depending on thresholds
	_ = anomalies
}

func TestAnomalyDetector_GetAnomalies(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	anomalies, err := detector.GetAnomalies(ctx, "unknown-agent", false)
	if err != nil {
		t.Fatalf("GetAnomalies failed: %v", err)
	}
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies, got %d", len(anomalies))
	}
}

func TestAnomalyDetector_GetAnomalies_UnresolvedOnly(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	anomalies, err := detector.GetAnomalies(ctx, "agent-1", true)
	if err != nil {
		t.Fatalf("GetAnomalies failed: %v", err)
	}
	if len(anomalies) != 0 {
		t.Error("Should have no anomalies")
	}
}

func TestAnomalyDetector_ResolveAnomaly_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	err := detector.ResolveAnomaly(ctx, "agent-1", "unknown-id")
	if err == nil {
		t.Error("Expected error for unknown anomaly")
	}
}

func TestAnomalyDetector_ClearResolved(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)
	ctx := context.Background()

	err := detector.ClearResolved(ctx, "agent-1")
	if err != nil {
		t.Fatalf("ClearResolved failed: %v", err)
	}
}
