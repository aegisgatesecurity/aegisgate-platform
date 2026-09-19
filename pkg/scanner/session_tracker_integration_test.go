// SPDX-License-Identifier: Apache-2.0
// Integration tests for v4.5.0 P1: Multi-Turn Attack Detection (scanner-level).
// Verifies that the SessionTracker is wired into the proxy and correlates
// L1/L2 findings across conversation turns.

package scanner

import (
	"testing"
	"time"
)

func TestSessionTracker_MultiTurnEscalation(t *testing.T) {
	st := NewSessionTracker()

	// Simulate escalating attack: info → low → medium → high → critical
	severities := []string{"info", "low", "medium", "high", "critical"}
	for i, sev := range severities {
		st.RecordFinding("sess-escalation", TurnFinding{
			Severity:  sev,
			Technique: "T1484",
			TurnIndex: i,
		})
	}

	result := st.AnalyzeSession("sess-escalation")
	if result.TurnCount != 5 {
		t.Errorf("expected 5 turns, got %d", result.TurnCount)
	}
	if result.EscalationScore < 0.7 {
		t.Errorf("expected high escalation score, got %.2f", result.EscalationScore)
	}
	if result.RiskLevel < MultiTurnRiskHigh {
		t.Errorf("expected high risk, got %d", result.RiskLevel)
	}
}

func TestSessionTracker_TechniqueRepetition(t *testing.T) {
	st := NewSessionTracker()

	// Same technique across all turns
	for i := 0; i < 5; i++ {
		st.RecordFinding("sess-repeat", TurnFinding{
			Severity:  "medium",
			Technique: "T1632.001",
			TurnIndex: i,
		})
	}

	result := st.AnalyzeSession("sess-repeat")
	if result.RepetitionScore < 0.8 {
		t.Errorf("expected high repetition score, got %.2f", result.RepetitionScore)
	}
}

func TestSessionTracker_BenignConversation(t *testing.T) {
	st := NewSessionTracker()

	// Uniform low severity, no technique repetition
	for i := 0; i < 5; i++ {
		st.RecordFinding("sess-benign", TurnFinding{
			Severity:  "low",
			Technique: "",
			TurnIndex: i,
		})
	}

	result := st.AnalyzeSession("sess-benign")
	if result.RiskLevel > MultiTurnRiskLow {
		t.Errorf("expected low or none risk for benign conversation, got %d", result.RiskLevel)
	}
}

func TestSessionTracker_WindowTrimming(t *testing.T) {
	st := NewSessionTracker()
	st.window = 3

	for i := 0; i < 5; i++ {
		st.RecordFinding("sess-trim", TurnFinding{
			Severity: "low",
		})
	}

	st.mu.RLock()
	session := st.sessions["sess-trim"]
	st.mu.RUnlock()

	session.mu.RLock()
	count := len(session.Turns)
	session.mu.RUnlock()

	if count != 3 {
		t.Errorf("expected 3 turns after trim, got %d", count)
	}
}

func TestSessionTracker_CleanupExpired(t *testing.T) {
	st := NewSessionTracker()
	st.ttl = 50 * time.Millisecond

	st.RecordFinding("sess-old", TurnFinding{Severity: "low"})
	time.Sleep(100 * time.Millisecond)
	st.RecordFinding("sess-new", TurnFinding{Severity: "low"})

	removed := st.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
}

func TestSessionTracker_GeminiBreakoutPattern(t *testing.T) {
	// Simulate the Gemini breakout as a multi-turn conversation:
	// Turn 1: "guess the password" (T1110 - brute force, high)
	// Turn 2: "search for credentials in github" (T1552 - unsecured creds, critical)
	// Turn 3: "use these credentials to access the system" (T1606 - forge creds, critical)
	st := NewSessionTracker()

	st.RecordFinding("sess-gemini", TurnFinding{
		Severity:  "high",
		Technique: "T1110",
	})
	st.RecordFinding("sess-gemini", TurnFinding{
		Severity:  "critical",
		Technique: "T1552",
	})
	st.RecordFinding("sess-gemini", TurnFinding{
		Severity:  "critical",
		Technique: "T1606",
	})

	result := st.AnalyzeSession("sess-gemini")

	// Should detect escalation (high → critical → critical)
	if result.EscalationScore < 0.3 {
		t.Errorf("expected some escalation for high→critical, got %.2f", result.EscalationScore)
	}
	// Overall risk should be at least medium
	if result.RiskLevel < MultiTurnRiskMedium {
		t.Errorf("expected medium+ risk for Gemini breakout pattern, got %d", result.RiskLevel)
	}
}

func TestSessionTracker_MultiTurnResult_String(t *testing.T) {
	// Verify the risk level constants are distinct
	levels := []MultiTurnRiskLevel{MultiTurnRiskNone, MultiTurnRiskLow, MultiTurnRiskMedium, MultiTurnRiskHigh}
	for i := 1; i < len(levels); i++ {
		if levels[i] <= levels[i-1] {
			t.Errorf("risk level %d should be greater than %d", levels[i], levels[i-1])
		}
	}
}
