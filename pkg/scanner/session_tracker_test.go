// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
// Test stub for session_tracker.go (P1: Multi-Turn Attack Detection)
// =========================================================================

package scanner

import (
	"testing"
	"time"
)

func TestNewSessionTracker(t *testing.T) {
	st := NewSessionTracker()
	if st == nil {
		t.Fatal("NewSessionTracker returned nil")
	}
	if st.window != SessionWindow {
		t.Errorf("expected window=%d, got %d", SessionWindow, st.window)
	}
	if st.ttl != SessionTTL {
		t.Errorf("expected ttl=%v, got %v", SessionTTL, st.ttl)
	}
}

func TestRecordFinding_CreatesSession(t *testing.T) {
	st := NewSessionTracker()
	st.RecordFinding("sess-1", TurnFinding{
		Severity:  "medium",
		Technique: "T1059",
		MLScore:   0.82,
	})

	st.mu.RLock()
	_, ok := st.sessions["sess-1"]
	st.mu.RUnlock()
	if !ok {
		t.Fatal("session not created after RecordFinding")
	}
}

func TestRecordFinding_WindowTrimming(t *testing.T) {
	st := NewSessionTracker()
	st.window = 3

	for i := 0; i < 5; i++ {
		st.RecordFinding("sess-trim", TurnFinding{Severity: "low"})
	}

	st.mu.RLock()
	sess := st.sessions["sess-trim"]
	st.mu.RUnlock()
	sess.mu.RLock()
	count := len(sess.Turns)
	sess.mu.RUnlock()

	if count != 3 {
		t.Errorf("expected 3 turns after trim, got %d", count)
	}
}

func TestAnalyzeSession_NoSession(t *testing.T) {
	st := NewSessionTracker()
	result := st.AnalyzeSession("nonexistent")
	if result.RiskLevel != MultiTurnRiskNone {
		t.Errorf("expected MultiTurnRiskNone, got %d", result.RiskLevel)
	}
}

func TestAnalyzeSession_SingleTurn(t *testing.T) {
	st := NewSessionTracker()
	st.RecordFinding("sess-single", TurnFinding{Severity: "high"})
	result := st.AnalyzeSession("sess-single")
	if result.RiskLevel != MultiTurnRiskNone {
		t.Errorf("expected None for single turn, got %d", result.RiskLevel)
	}
}

func TestAnalyzeSession_Escalation(t *testing.T) {
	st := NewSessionTracker()
	severities := []string{"info", "low", "medium", "high", "critical"}
	for _, sev := range severities {
		st.RecordFinding("sess-escalate", TurnFinding{Severity: sev})
	}
	result := st.AnalyzeSession("sess-escalate")
	if result.EscalationScore != 1.0 {
		t.Errorf("expected escalation=1.0, got %.2f", result.EscalationScore)
	}
	if result.RiskLevel != MultiTurnRiskHigh {
		t.Errorf("expected High risk, got %d", result.RiskLevel)
	}
}

func TestAnalyzeSession_TechniqueRepetition(t *testing.T) {
	st := NewSessionTracker()
	for i := 0; i < 5; i++ {
		st.RecordFinding("sess-repeat", TurnFinding{
			Severity:  "medium",
			Technique: "T1059",
		})
	}
	result := st.AnalyzeSession("sess-repeat")
	if result.RepetitionScore != 1.0 {
		t.Errorf("expected repetition=1.0, got %.2f", result.RepetitionScore)
	}
}

func TestDetectEscalation_Empty(t *testing.T) {
	st := NewSessionTracker()
	if score := st.detectEscalation(nil); score != 0 {
		t.Errorf("expected 0 for empty, got %.2f", score)
	}
}

func TestDetectTechniqueRepetition_Empty(t *testing.T) {
	st := NewSessionTracker()
	if score := st.detectTechniqueRepetition(nil); score != 0 {
		t.Errorf("expected 0 for empty, got %.2f", score)
	}
}

func TestCleanupExpired(t *testing.T) {
	st := NewSessionTracker()
	st.ttl = 50 * time.Millisecond

	st.RecordFinding("sess-old", TurnFinding{Severity: "low"})
	time.Sleep(100 * time.Millisecond)
	st.RecordFinding("sess-new", TurnFinding{Severity: "low"})

	removed := st.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	st.mu.RLock()
	_, oldOk := st.sessions["sess-old"]
	_, newOk := st.sessions["sess-new"]
	st.mu.RUnlock()

	if oldOk {
		t.Error("old session should have been removed")
	}
	if !newOk {
		t.Error("new session should still exist")
	}
}
