package agentregistry

import (
	"testing"
	"time"
)

func TestDormancyEvaluate(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	engine := NewDormancyEngine(60*24*time.Hour, nil)
	policy := &LifecyclePolicy{
		DormancyThreshold:   60 * 24 * time.Hour,
		QuarantineThreshold: 75 * 24 * time.Hour,
		AutoRevokeThreshold: 90 * 24 * time.Hour,
	}

	tests := []struct {
		name      string
		record    *AgentRecord
		wantStatus AgentStatus
	}{
		{
			"provisioned (never active)",
			&AgentRecord{Status: StatusProvisioned, LastActivity: time.Time{}},
			StatusProvisioned,
		},
		{
			"active (recent activity)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-1 * time.Hour)},
			StatusActive,
		},
		{
			"active (just under threshold)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-59 * 24 * time.Hour)},
			StatusActive,
		},
		{
			"dormant (just over threshold)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-61 * 24 * time.Hour)},
			StatusDormant,
		},
		{
			"dormant (well over threshold, under quarantine)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-70 * 24 * time.Hour)},
			StatusDormant,
		},
		{
			"quarantined (over quarantine threshold)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-76 * 24 * time.Hour)},
			StatusQuarantined,
		},
		{
			"revoked (over auto-revoke threshold)",
			&AgentRecord{Status: StatusActive, LastActivity: nowFunc().Add(-91 * 24 * time.Hour)},
			StatusRevoked,
		},
		{
			"quarantined stays quarantined",
			&AgentRecord{Status: StatusQuarantined, LastActivity: nowFunc().Add(-1 * time.Hour)},
			StatusQuarantined,
		},
		{
			"revoked stays revoked",
			&AgentRecord{Status: StatusRevoked, LastActivity: nowFunc().Add(-1 * time.Hour)},
			StatusRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := engine.Evaluate(tt.record, policy)
			if got != tt.wantStatus {
				t.Errorf("Evaluate() = %q, want %q", got, tt.wantStatus)
			}
		})
	}
}

func TestDormancyEvaluateNilPolicy(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	engine := NewDormancyEngine(30*24*time.Hour, nil)

	// With nil policy, only dormancy threshold (engine default) applies
	record := &AgentRecord{
		Status:       StatusActive,
		LastActivity: nowFunc().Add(-31 * 24 * time.Hour),
	}
	got, _ := engine.Evaluate(record, nil)
	if got != StatusDormant {
		t.Errorf("with nil policy, 31 days inactive should be dormant, got %q", got)
	}

	// Under threshold
	record.LastActivity = nowFunc().Add(-29 * 24 * time.Hour)
	got, _ = engine.Evaluate(record, nil)
	if got != StatusActive {
		t.Errorf("with nil policy, 29 days inactive should be active, got %q", got)
	}
}

func TestDormancyEvaluateSkipQuarantine(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	engine := NewDormancyEngine(60*24*time.Hour, nil)
	// No quarantine threshold — go straight from dormant to revoked
	policy := &LifecyclePolicy{
		DormancyThreshold:   60 * 24 * time.Hour,
		AutoRevokeThreshold: 90 * 24 * time.Hour,
	}

	// 70 days: dormant (no quarantine step)
	record := &AgentRecord{
		Status:       StatusActive,
		LastActivity: nowFunc().Add(-70 * 24 * time.Hour),
	}
	got, _ := engine.Evaluate(record, policy)
	if got != StatusDormant {
		t.Errorf("70 days with no quarantine threshold: want dormant, got %q", got)
	}

	// 91 days: revoked (skip quarantine)
	record.LastActivity = nowFunc().Add(-91 * 24 * time.Hour)
	got, _ = engine.Evaluate(record, policy)
	if got != StatusRevoked {
		t.Errorf("91 days with no quarantine threshold: want revoked, got %q", got)
	}
}

func TestDormancyClassify(t *testing.T) {
	originalNow := nowFunc
	nowFunc = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	defer func() { nowFunc = originalNow }()

	engine := NewDormancyEngine(60*24*time.Hour, nil)
	policy := &LifecyclePolicy{
		DormancyThreshold: 60 * 24 * time.Hour,
	}

	records := []*AgentRecord{
		{ID: "a1", Status: StatusActive, LastActivity: nowFunc().Add(-1 * time.Hour)},
		{ID: "a2", Status: StatusActive, LastActivity: nowFunc().Add(-61 * 24 * time.Hour)},
		{ID: "a3", Status: StatusProvisioned, LastActivity: time.Time{}},
		{ID: "a4", Status: StatusQuarantined, LastActivity: nowFunc().Add(-80 * 24 * time.Hour)},
	}

	report := engine.Classify(records, policy)

	if report.Total != 4 {
		t.Errorf("Total = %d, want 4", report.Total)
	}
	if report.Active != 1 {
		t.Errorf("Active = %d, want 1", report.Active)
	}
	if report.Dormant != 1 {
		t.Errorf("Dormant = %d, want 1", report.Dormant)
	}
	if report.Provisioned != 1 {
		t.Errorf("Provisioned = %d, want 1", report.Provisioned)
	}
	if report.Quarantined != 1 {
		t.Errorf("Quarantined = %d, want 1", report.Quarantined)
	}

	if len(report.Agents) != 4 {
		t.Errorf("Agents count = %d, want 4", len(report.Agents))
	}
}