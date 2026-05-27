// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Score Types Tests

package score

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.InitialScore != 100.0 {
		t.Errorf("InitialScore should be 100, got %f", cfg.InitialScore)
	}
	if cfg.MinScore != 0.0 {
		t.Errorf("MinScore should be 0, got %f", cfg.MinScore)
	}
	if cfg.MaxScore != 100.0 {
		t.Errorf("MaxScore should be 100, got %f", cfg.MaxScore)
	}
	if cfg.DecayRate != 0.1 {
		t.Errorf("DecayRate should be 0.1, got %f", cfg.DecayRate)
	}
	if cfg.BaselineWindow != 100 {
		t.Errorf("BaselineWindow should be 100, got %d", cfg.BaselineWindow)
	}
	if cfg.AnomalyThreshold != 3.0 {
		t.Errorf("AnomalyThreshold should be 3.0, got %f", cfg.AnomalyThreshold)
	}
}

func TestScoreLevelConstants(t *testing.T) {
	if ScoreLevelCritical != "critical" {
		t.Error("ScoreLevelCritical should be 'critical'")
	}
	if ScoreLevelLow != "low" {
		t.Error("ScoreLevelLow should be 'low'")
	}
	if ScoreLevelMedium != "medium" {
		t.Error("ScoreLevelMedium should be 'medium'")
	}
	if ScoreLevelHigh != "high" {
		t.Error("ScoreLevelHigh should be 'high'")
	}
	if ScoreLevelTrusted != "trusted" {
		t.Error("ScoreLevelTrusted should be 'trusted'")
	}
}

func TestEventTypeConstants(t *testing.T) {
	events := []EventType{
		EventCapabilityAllowed,
		EventCapabilityDenied,
		EventCapabilityAppr,
		EventRateLimited,
		EventAnomalyDetected,
		EventCompliancePass,
		EventComplianceFail,
		EventContractViolated,
		EventIdentityVerified,
		EventIdentityFailed,
		EventError,
	}
	for _, e := range events {
		if e == "" {
			t.Error("EventType constant should not be empty")
		}
	}
}

func TestTrustScore(t *testing.T) {
	ts := &TrustScore{
		AgentID:              "agent-123",
		Score:                85.5,
		Level:                ScoreLevelHigh,
		BehaviorMultiplier:   1.2,
		ComplianceMultiplier: 1.0,
		BaseScore:            100.0,
	}
	if ts.Score != 85.5 {
		t.Errorf("Score should be 85.5, got %f", ts.Score)
	}
	if ts.Level != ScoreLevelHigh {
		t.Errorf("Level should be high, got %s", ts.Level)
	}
}

func TestScoreFactor(t *testing.T) {
	sf := ScoreFactor{
		Name:       "test_factor",
		Weight:     0.5,
		Value:      0.8,
		Multiplier: 1.2,
	}
	if sf.Name != "test_factor" {
		t.Error("Name mismatch")
	}
}

func TestBehaviorEvent(t *testing.T) {
	be := BehaviorEvent{
		ID:          "event-123",
		AgentID:    "agent-456",
		Type:       EventCapabilityAllowed,
		Capability: "file:read",
		Severity:   2,
		Description: "Allowed file read",
	}
	if be.ID != "event-123" {
		t.Error("ID mismatch")
	}
	if be.Type != EventCapabilityAllowed {
		t.Error("Type mismatch")
	}
}

func TestAnomaly(t *testing.T) {
	a := Anomaly{
		ID:          "anomaly-123",
		AgentID:    "agent-456",
		Type:        "rate_change",
		Severity:    6,
		Description: "Unusual event rate",
		Deviation:   0.75,
		Resolved:    false,
	}
	if a.Severity != 6 {
		t.Error("Severity mismatch")
	}
	if a.Resolved {
		t.Error("Resolved should be false")
	}
}

func TestBaselineMetrics(t *testing.T) {
	bm := BaselineMetrics{
		AgentID:      "agent-123",
		TotalEvents:  1000,
		AllowedCount: 950,
		DeniedCount:  50,
		SuccessRate:  0.95,
	}
	if bm.SuccessRate != 0.95 {
		t.Errorf("SuccessRate should be 0.95, got %f", bm.SuccessRate)
	}
	if bm.TotalEvents != 1000 {
		t.Errorf("TotalEvents should be 1000, got %d", bm.TotalEvents)
	}
}
