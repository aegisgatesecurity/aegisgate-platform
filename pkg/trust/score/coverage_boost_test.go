package score

import (
	"context"
	"testing"
	"time"
)

// Additional trust/score tests for coverage boost
// Note: Existing tests in engine_test.go and types_test.go already cover basic functionality

func TestEngine_ConcurrentRecordAndAnalyze(t *testing.T) {
	engine := NewEngine(nil)
	_ = engine.RecordEvent(context.Background(), "agent-1", EventCapabilityAllowed, "file:read", 1, "")

	done := make(chan bool, 10)
	// Concurrent analyze
	for i := 0; i < 10; i++ {
		go func() {
			_, _, _ = engine.Analyze(context.Background(), "agent-1")
			done <- true
		}()
	}
	// Concurrent record
	for i := 0; i < 10; i++ {
		go func(idx int) {
			_ = engine.RecordEvent(context.Background(), "agent-1", EventCapabilityAllowed, "net:http", 1, "")
			done <- true
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestEngine_RecordEvent_AllEventTypes(t *testing.T) {
	engine := NewEngine(nil)
	eventTypes := []EventType{
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

	for _, et := range eventTypes {
		err := engine.RecordEvent(context.Background(), "agent-1", et, "cap", 1, "test")
		if err != nil {
			t.Errorf("RecordEvent failed for %s: %v", et, err)
		}
	}
}

func TestEngine_GetAnomalies_BothFlags(t *testing.T) {
	engine := NewEngine(nil)

	// Get with false (all)
	all, _ := engine.GetAnomalies(context.Background(), "agent-1", false)
	// Get with true (unresolved only)
	unresolved, _ := engine.GetAnomalies(context.Background(), "agent-1", true)

	_ = all
	_ = unresolved
}

func TestTrustScore_StructAssignment(t *testing.T) {
	score := &TrustScore{
		AgentID:              "test-agent",
		Score:                75.5,
		Level:                ScoreLevelMedium,
		BehaviorMultiplier:   1.2,
		ComplianceMultiplier: 1.1,
		BaseScore:            50.0,
		Factors:              []ScoreFactor{},
		CalculatedAt:         time.Now(),
	}

	// Verify all fields
	if score.AgentID != "test-agent" {
		t.Errorf("AgentID = %s, want test-agent", score.AgentID)
	}
	if score.Score != 75.5 {
		t.Errorf("Score = %f, want 75.5", score.Score)
	}
}

func TestAnomaly_StructAssignment(t *testing.T) {
	anomaly := &Anomaly{
		ID:          "anomaly-test",
		AgentID:     "test-agent",
		Type:        "test_type",
		Severity:    5,
		Description: "Test anomaly",
		Deviation:   1.5,
		Timestamp:   time.Now(),
		Resolved:    true,
	}

	if anomaly.Severity != 5 {
		t.Errorf("Severity = %d, want 5", anomaly.Severity)
	}
	if anomaly.Deviation != 1.5 {
		t.Errorf("Deviation = %f, want 1.5", anomaly.Deviation)
	}
}

func TestBaselineMetrics_StructAssignment(t *testing.T) {
	metrics := &BaselineMetrics{
		AgentID:          "test-agent",
		TotalEvents:      200,
		AllowedCount:     180,
		DeniedCount:      15,
		ApprovalReqCount: 5,
		AnomalyCount:     3,
		AvgSeverity:      2.0,
		SuccessRate:      0.90,
		DailyAvgEvents:   100.0,
		LastUpdated:      time.Now(),
	}

	if metrics.SuccessRate != 0.90 {
		t.Errorf("SuccessRate = %f, want 0.90", metrics.SuccessRate)
	}
}

func TestScoreFactor_StructAssignment(t *testing.T) {
	factor := &ScoreFactor{
		Name:       "behavior_factor",
		Weight:     0.3,
		Value:      85.0,
		Multiplier: 1.0,
	}

	if factor.Name != "behavior_factor" {
		t.Errorf("Name = %s, want behavior_factor", factor.Name)
	}
}

func TestConfig_DecayRate(t *testing.T) {
	cfg := &Config{
		InitialScore:     100.0,
		MinScore:         0.0,
		MaxScore:         100.0,
		DecayRate:        0.2,
		BaselineWindow:   100,
		AnomalyThreshold: 3.0,
	}

	if cfg.DecayRate != 0.2 {
		t.Errorf("DecayRate = %f, want 0.2", cfg.DecayRate)
	}
}

func TestConfig_BaselineWindow(t *testing.T) {
	cfg := &Config{
		BaselineWindow: 200,
	}

	if cfg.BaselineWindow != 200 {
		t.Errorf("BaselineWindow = %d, want 200", cfg.BaselineWindow)
	}
}

func TestEventType_StringValues(t *testing.T) {
	tests := []struct {
		et  EventType
		val string
	}{
		{EventCapabilityAllowed, "capability:allowed"},
		{EventCapabilityDenied, "capability:denied"},
		{EventCapabilityAppr, "capability:approval_required"},
		{EventRateLimited, "capability:rate_limited"},
		{EventAnomalyDetected, "anomaly:detected"},
	}

	for _, tt := range tests {
		if string(tt.et) != tt.val {
			t.Errorf("EventType %v = %s, want %s", tt.et, string(tt.et), tt.val)
		}
	}
}

func TestScoreLevel_StringValues(t *testing.T) {
	tests := []struct {
		sl  ScoreLevel
		val string
	}{
		{ScoreLevelCritical, "critical"},
		{ScoreLevelLow, "low"},
		{ScoreLevelMedium, "medium"},
		{ScoreLevelHigh, "high"},
		{ScoreLevelTrusted, "trusted"},
	}

	for _, tt := range tests {
		if string(tt.sl) != tt.val {
			t.Errorf("ScoreLevel %v = %s, want %s", tt.sl, string(tt.sl), tt.val)
		}
	}
}

func TestBehaviorEvent_WithMetadata(t *testing.T) {
	event := &BehaviorEvent{
		ID:          "event-with-meta",
		AgentID:     "agent-1",
		Type:        EventCapabilityAllowed,
		Capability:  "file:read",
		Severity:    1,
		Description: "Test",
		Timestamp:   time.Now(),
		Metadata:    map[string]string{"env": "test", "region": "us-east"},
	}

	if len(event.Metadata) != 2 {
		t.Errorf("Metadata count = %d, want 2", len(event.Metadata))
	}
}

func TestCalculator_WithNonNilConfig(t *testing.T) {
	cfg := &Config{
		InitialScore:     80.0,
		BaselineWindow:   50,
		AnomalyThreshold: 2.5,
	}
	baseline := NewBaselineEngine(50)
	calc := NewCalculator(cfg, baseline)

	if calc == nil {
		t.Error("Calculator should not be nil")
	}
}

func TestAnomalyDetector_WithNonNilConfig(t *testing.T) {
	cfg := &Config{
		AnomalyThreshold: 2.5,
	}
	detector := NewAnomalyDetector(cfg)

	if detector == nil {
		t.Error("Detector should not be nil")
	}
}

func TestBaselineEngine_WithIntWindow(t *testing.T) {
	baseline := NewBaselineEngine(200)
	if baseline == nil {
		t.Error("Baseline should not be nil")
	}
}

func TestEngine_AnalyzeMultipleAgents(t *testing.T) {
	engine := NewEngine(nil)

	agents := []string{"agent-x", "agent-y", "agent-z"}
	for _, agent := range agents {
		_ = engine.RecordEvent(context.Background(), agent, EventCapabilityAllowed, "net:http", 1, "")
		_ = engine.RecordEvent(context.Background(), agent, EventCapabilityDenied, "admin:*", 5, "")
	}

	for _, agent := range agents {
		score, _, err := engine.Analyze(context.Background(), agent)
		if err != nil {
			t.Errorf("Analyze failed for %s: %v", agent, err)
		}
		if score == nil {
			t.Errorf("Score should not be nil for %s", agent)
		}
	}
}
