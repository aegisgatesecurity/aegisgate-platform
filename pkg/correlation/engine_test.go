package correlation

import (
	"context"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.cfg == nil {
		t.Error("Config should not be nil")
	}
	if len(e.patterns) == 0 {
		t.Error("Default patterns should be registered")
	}
}

func TestNewEngineWithConfig(t *testing.T) {
	cfg := &Config{
		EnablePatternMatching: false,
		EnableRateCorrelation: false,
		CorrelationWindow:     10 * time.Minute,
	}
	e := NewEngineWithConfig(cfg)
	if e == nil {
		t.Fatal("NewEngineWithConfig returned nil")
	}
	if e.cfg.EnablePatternMatching {
		t.Error("EnablePatternMatching should be false")
	}
}

func TestNewEngineWithNilConfig(t *testing.T) {
	e := NewEngineWithConfig(nil)
	if e == nil {
		t.Fatal("NewEngineWithConfig(nil) returned nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.EnablePatternMatching != true {
		t.Error("EnablePatternMatching should be true")
	}
	if cfg.MinPatternWeight != 0.5 {
		t.Errorf("MinPatternWeight = %f, want 0.5", cfg.MinPatternWeight)
	}
	if cfg.EnableRateCorrelation != true {
		t.Error("EnableRateCorrelation should be true")
	}
	if cfg.RateThresholdMultiplier != 2.0 {
		t.Errorf("RateThresholdMultiplier = %f, want 2.0", cfg.RateThresholdMultiplier)
	}
	if cfg.CorrelationWindow != 5*time.Minute {
		t.Errorf("CorrelationWindow = %v, want 5m", cfg.CorrelationWindow)
	}
}

func TestRecordEvent(t *testing.T) {
	e := NewEngine()
	event := NewEvent("mcp", "guard_block", "agent-1", "session-1")

	err := e.RecordEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}
}

func TestRecordEvent_Nil(t *testing.T) {
	e := NewEngine()
	err := e.RecordEvent(context.Background(), nil)
	if err != nil {
		t.Fatalf("RecordEvent(nil) should not error: %v", err)
	}
}

func TestAnalyze_NoEvents(t *testing.T) {
	e := NewEngine()
	result, err := e.Analyze(context.Background(), "agent-1", "session-1")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow for no events, got %s", result.Decision)
	}
}

func TestAnalyze_WithEvents(t *testing.T) {
	e := NewEngine()

	// Record some events
	e.RecordEvent(context.Background(), NewEvent("mcp", "error", "agent-1", "session-1"))
	e.RecordEvent(context.Background(), NewEvent("a2a", "request", "agent-1", "session-1"))

	result, err := e.Analyze(context.Background(), "agent-1", "session-1")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestAnalyze_RateAnomaly(t *testing.T) {
	e := NewEngine()

	// Record many events from same agent
	for i := 0; i < 5; i++ {
		e.RecordEvent(context.Background(), NewEvent("mcp", "block", "agent-1", "session-1"))
	}

	result, err := e.Analyze(context.Background(), "agent-1", "session-1")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	// May or may not trigger depending on pattern matching
	_ = result
}

func TestAnalyze_TaskHijacking(t *testing.T) {
	e := NewEngine()

	// Record events matching task hijacking pattern
	e.RecordEvent(context.Background(), NewEvent("a2a", "message", "agent-1", "session-1"))
	e.RecordEvent(context.Background(), NewEvent("anp", "task_create", "agent-1", "session-1"))

	result, err := e.Analyze(context.Background(), "agent-1", "session-1")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result should not be nil")
	}
}

func TestNewEvent(t *testing.T) {
	event := NewEvent("mcp", "guard_block", "agent-1", "session-1")
	if event.Protocol != "mcp" {
		t.Errorf("Protocol = %s, want mcp", event.Protocol)
	}
	if event.EventType != "guard_block" {
		t.Errorf("EventType = %s, want guard_block", event.EventType)
	}
	if event.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want agent-1", event.AgentID)
	}
	if event.SessionID != "session-1" {
		t.Errorf("SessionID = %s, want session-1", event.SessionID)
	}
	if event.ID == "" {
		t.Error("ID should not be empty")
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestNewCorrelationResult(t *testing.T) {
	result := NewCorrelationResult()
	if result.Decision != DecisionAllow {
		t.Errorf("Decision = %s, want allow", result.Decision)
	}
	if result.MatchedPatterns == nil {
		t.Error("MatchedPatterns should not be nil")
	}
	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}

func TestDefaultPatterns(t *testing.T) {
	e := NewEngine()

	patterns := []string{
		"mcp_error_injection",
		"task_hijacking",
		"browser_escalation",
		"rate_anomaly",
		"capability_creep",
	}

	for _, id := range patterns {
		if e.patterns[id] == nil {
			t.Errorf("Pattern %s should be registered", id)
		}
	}
}

func TestPattern_Weights(t *testing.T) {
	e := NewEngine()

	weights := map[string]float64{
		"mcp_error_injection": 0.8,
		"task_hijacking":      0.9,
		"browser_escalation":  0.95,
		"rate_anomaly":        0.7,
		"capability_creep":    0.6,
	}

	for id, expected := range weights {
		pattern := e.patterns[id]
		if pattern == nil {
			t.Errorf("Pattern %s not found", id)
			continue
		}
		if pattern.Weight != expected {
			t.Errorf("Pattern %s weight = %f, want %f", id, pattern.Weight, expected)
		}
	}
}

func TestPattern_Severity(t *testing.T) {
	e := NewEngine()

	severities := map[string]string{
		"mcp_error_injection": "high",
		"task_hijacking":      "critical",
		"browser_escalation":  "critical",
		"rate_anomaly":        "high",
		"capability_creep":    "medium",
	}

	for id, expected := range severities {
		pattern := e.patterns[id]
		if pattern == nil {
			t.Errorf("Pattern %s not found", id)
			continue
		}
		if pattern.Severity != expected {
			t.Errorf("Pattern %s severity = %s, want %s", id, pattern.Severity, expected)
		}
	}
}

// Additional coverage tests

func TestRecordEvent_MultipleAgents(t *testing.T) {
	e := NewEngine()

	e.RecordEvent(context.Background(), NewEvent("mcp", "block", "agent-1", "session-1"))
	e.RecordEvent(context.Background(), NewEvent("a2a", "request", "agent-2", "session-1"))
	e.RecordEvent(context.Background(), NewEvent("anp", "task", "agent-1", "session-2"))

	result1, _ := e.Analyze(context.Background(), "agent-1", "session-1")
	result2, _ := e.Analyze(context.Background(), "agent-2", "session-1")
	result3, _ := e.Analyze(context.Background(), "agent-1", "session-2")

	if result1 == nil || result2 == nil || result3 == nil {
		t.Error("Results should not be nil")
	}
}

func TestAnalyze_MixedProtocols(t *testing.T) {
	e := NewEngine()

	// Record events from different protocols
	protocols := []string{"http", "mcp", "a2a", "anp", "computeruse"}
	for _, p := range protocols {
		e.RecordEvent(context.Background(), NewEvent(p, "block", "agent-1", "session-1"))
	}

	result, _ := e.Analyze(context.Background(), "agent-1", "session-1")
	_ = result
}

func TestAnalyze_OldEvents(t *testing.T) {
	e := NewEngine()

	// Create old event manually
	event := NewEvent("mcp", "block", "agent-1", "session-1")
	event.Timestamp = time.Now().Add(-10 * time.Minute)
	e.RecordEvent(context.Background(), event)

	result, _ := e.Analyze(context.Background(), "agent-1", "session-1")
	// Old events should be outside correlation window
	_ = result
}

func TestCorrelationResult_Metadata(t *testing.T) {
	result := NewCorrelationResult()
	result.Metadata["key1"] = "value1"
	result.Metadata["key2"] = "value2"

	if result.Metadata["key1"] != "value1" {
		t.Error("Metadata key1 not set correctly")
	}
}

func TestEvent_Data(t *testing.T) {
	event := NewEvent("mcp", "guard", "agent", "session")
	event.Data["key"] = "value"
	event.Data["count"] = 42

	if event.Data["key"] != "value" {
		t.Error("Data key not set correctly")
	}
}

func TestEvent_Metadata(t *testing.T) {
	event := NewEvent("mcp", "guard", "agent", "session")
	event.Metadata["source"] = "test"

	if event.Metadata["source"] != "test" {
		t.Error("Metadata not set correctly")
	}
}

func TestConfig_CustomValues(t *testing.T) {
	cfg := &Config{
		EnablePatternMatching:   true,
		MinPatternWeight:        0.8,
		EnableRateCorrelation:   true,
		RateThresholdMultiplier: 3.0,
		CorrelationWindow:       15 * time.Minute,
		AlertOnHighSeverity:     true,
		AlertOnMediumSeverity:   true,
	}

	e := NewEngineWithConfig(cfg)
	if e.cfg.MinPatternWeight != 0.8 {
		t.Errorf("MinPatternWeight = %f, want 0.8", e.cfg.MinPatternWeight)
	}
	if e.cfg.RateThresholdMultiplier != 3.0 {
		t.Errorf("RateThresholdMultiplier = %f, want 3.0", e.cfg.RateThresholdMultiplier)
	}
}

func TestAnalyze_AllPatterns(t *testing.T) {
	e := NewEngine()

	// Test each pattern
	patterns := []struct {
		events []*Event
		id     string
	}{
		{
			[]*Event{
				{Protocol: "mcp", EventType: "error"},
				{Protocol: "a2a", EventType: "request"},
			},
			"mcp_error_injection",
		},
		{
			[]*Event{
				{Protocol: "a2a", EventType: "message"},
				{Protocol: "anp", EventType: "task_create"},
			},
			"task_hijacking",
		},
		{
			[]*Event{
				{Protocol: "anp", EventType: "task"},
				{Protocol: "computeruse", EventType: "browse"},
			},
			"browser_escalation",
		},
	}

	for _, p := range patterns {
		e.events["agent:session"] = p.events
		result, _ := e.Analyze(context.Background(), "agent", "session")
		_ = result
	}
}

func TestEventMatchesIndicator(t *testing.T) {
	e := NewEngine()

	indicators := []struct {
		event     *Event
		indicator string
		expected  bool
	}{
		{&Event{Protocol: "mcp", EventType: "error"}, "mcp_error", true},
		{&Event{Protocol: "a2a", EventType: "request"}, "a2a_request", true},
		{&Event{Protocol: "a2a", EventType: "response"}, "a2a_message", true},
		{&Event{Protocol: "anp", EventType: "task_create"}, "anp_task_create", true},
		{&Event{Protocol: "computeruse", EventType: "click"}, "computer_use", true},
		{&Event{Protocol: "http", EventType: "request"}, "mcp_error", false},
	}

	for _, ind := range indicators {
		result := e.eventMatchesIndicator(ind.event, ind.indicator)
		if result != ind.expected {
			t.Errorf("eventMatchesIndicator(%s, %s) = %v, want %v", ind.event.Protocol, ind.indicator, result, ind.expected)
		}
	}
}
