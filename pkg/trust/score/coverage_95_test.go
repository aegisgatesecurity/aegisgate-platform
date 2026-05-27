package score

import (
	"context"
	"testing"
	"time"
)

func TestAnomalyDetectorDetect(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)

	events := []*BehaviorEvent{
		{AgentID: "agent-1", Type: EventCapabilityAllowed, Timestamp: time.Now()},
	}

	anomalies, err := detector.Detect(context.Background(), "agent-1", events, nil)
	if err != nil {
		t.Errorf("Detect failed: %v", err)
	}
	_ = anomalies
}

func TestAnomalyDetectorGetAnomalies(t *testing.T) {
	cfg := DefaultConfig()
	detector := NewAnomalyDetector(cfg)

	anomalies, err := detector.GetAnomalies(context.Background(), "agent-1", false)
	if err != nil {
		t.Errorf("GetAnomalies failed: %v", err)
	}
	_ = anomalies
}

func TestBaselineGetBaseline(t *testing.T) {
	engine := NewBaselineEngine(100)

	baseline, err := engine.GetBaseline(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("GetBaseline failed: %v", err)
	}
	_ = baseline
}

func TestBaselineUpdateBaseline(t *testing.T) {
	engine := NewBaselineEngine(100)

	err := engine.UpdateBaseline(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("UpdateBaseline failed: %v", err)
	}
}

func TestBaselineCalculateDeviation(t *testing.T) {
	engine := NewBaselineEngine(100)

	dev, err := engine.CalculateDeviation(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("CalculateDeviation failed: %v", err)
	}
	_ = dev
}

func TestBaselineGetRecentEvents(t *testing.T) {
	engine := NewBaselineEngine(100)

	events, err := engine.GetRecentEvents(context.Background(), "agent-1", 10)
	if err != nil {
		t.Errorf("GetRecentEvents failed: %v", err)
	}
	_ = events
}

func TestCalculatorCalculate(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)

	score, err := calc.Calculate(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("Calculate failed: %v", err)
	}
	_ = score
}

func TestCalculatorCalculateWithEvents(t *testing.T) {
	cfg := DefaultConfig()
	baseline := NewBaselineEngine(100)
	calc := NewCalculator(cfg, baseline)

	events := []*BehaviorEvent{
		{AgentID: "agent-1", Type: EventCapabilityAllowed, Timestamp: time.Now(), Description: "test"},
	}

	score, err := calc.CalculateWithEvents(context.Background(), "agent-1", events)
	if err != nil {
		t.Errorf("CalculateWithEvents failed: %v", err)
	}
	_ = score
}
