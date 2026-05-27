package score

import (
	"context"
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine(nil)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
}

func TestEngine_GetScore_NewAgent(t *testing.T) {
	engine := NewEngine(nil)
	score, err := engine.GetScore(context.Background(), "new-agent")
	if err != nil {
		t.Fatalf("GetScore failed: %v", err)
	}
	if score.AgentID != "new-agent" {
		t.Error("AgentID mismatch")
	}
	if score.Level != ScoreLevelTrusted {
		t.Errorf("New agent should be trusted, got %s", score.Level)
	}
}

func TestEngine_RecordEvent(t *testing.T) {
	engine := NewEngine(nil)
	err := engine.RecordEvent(context.Background(), "a1", EventCapabilityAllowed, "file:read", 1, "Allowed")
	if err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}
}

func TestEngine_GetBaseline(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()
	_ = engine.RecordEvent(ctx, "a1", EventCapabilityAllowed, "", 1, "")
	baseline, _ := engine.GetBaseline(ctx, "a1")
	if baseline.AgentID != "a1" {
		t.Error("AgentID mismatch")
	}
}

func TestEngine_GetAnomalies(t *testing.T) {
	engine := NewEngine(nil)
	anomalies, _ := engine.GetAnomalies(context.Background(), "a1", false)
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies, got %d", len(anomalies))
	}
}

func TestEngine_Analyze(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()
	_ = engine.RecordEvent(ctx, "a1", EventCapabilityAllowed, "", 1, "")
	score, _, _ := engine.Analyze(ctx, "a1")
	if score.AgentID != "a1" {
		t.Error("AgentID mismatch")
	}
}

func TestEngine_ResetScore(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()
	_ = engine.RecordEvent(ctx, "a1", EventCapabilityAllowed, "", 1, "")
	err := engine.ResetScore(ctx, "a1")
	if err != nil {
		t.Fatalf("ResetScore failed: %v", err)
	}
}

func TestEngine_GetAllScores(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()
	_ = engine.RecordEvent(ctx, "a1", EventCapabilityAllowed, "", 1, "")
	_ = engine.RecordEvent(ctx, "a2", EventCapabilityAllowed, "", 1, "")
	scores, _ := engine.GetAllScores(ctx)
	if len(scores) < 2 {
		t.Errorf("Expected at least 2 scores, got %d", len(scores))
	}
}

func TestEngine_RecordAllowed(t *testing.T) {
	engine := NewEngine(nil)
	err := engine.RecordAllowed(context.Background(), "a1", "file:read")
	if err != nil {
		t.Fatalf("RecordAllowed failed: %v", err)
	}
}

func TestEngine_RecordDenied(t *testing.T) {
	engine := NewEngine(nil)
	err := engine.RecordDenied(context.Background(), "a1", "file:delete", "Not allowed")
	if err != nil {
		t.Fatalf("RecordDenied failed: %v", err)
	}
}

func TestEngine_RecordCompliance(t *testing.T) {
	engine := NewEngine(nil)
	ctx := context.Background()
	_ = engine.RecordCompliance(ctx, "a1", true)
	_ = engine.RecordCompliance(ctx, "a1", false)
}
