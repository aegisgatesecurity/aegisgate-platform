package dashboard

import (
	"testing"
	"time"
)

func TestNewDashboard_NilEngine(t *testing.T) {
	dash := NewDashboard(nil)
	if dash == nil {
		t.Fatal("NewDashboard should return dashboard even with nil engine")
	}
}

func TestNewEventFeed_ZeroMaxSize(t *testing.T) {
	ef := NewEventFeed(0)
	if ef.maxSize != 1000 {
		t.Errorf("Zero maxSize should default to 1000, got %d", ef.maxSize)
	}
}

func TestNewEventFeed_NegativeMaxSize(t *testing.T) {
	ef := NewEventFeed(-5)
	if ef.maxSize != 1000 {
		t.Errorf("Negative maxSize should default to 1000, got %d", ef.maxSize)
	}
}

func TestEventFeed_PublishEventNilListener(t *testing.T) {
	ef := NewEventFeed(100)
	ef.PublishEvent(Event{Type: "test", AgentID: "agent-1"})
}

func TestEventFeed_PublishEventWithListeners(t *testing.T) {
	ef := NewEventFeed(100)
	ch := ef.Subscribe("sub-1")
	go func() {
		time.Sleep(10 * time.Millisecond)
		ef.PublishEvent(Event{Type: "test", AgentID: "agent-1"})
	}()
	select {
	case ev := <-ch:
		if ev.Type != "test" {
			t.Errorf("Expected 'test', got '%s'", ev.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event")
	}
}

func TestEventFeed_MultipleSubscribers(t *testing.T) {
	ef := NewEventFeed(100)
	ch1 := ef.Subscribe("sub-1")
	ch2 := ef.Subscribe("sub-2")

	event := Event{Type: "multi", AgentID: "agent-1"}
	ef.PublishEvent(event)

	select {
	case ev := <-ch1:
		if ev.Type != "multi" {
			t.Errorf("Subscriber 1 expected 'multi', got '%s'", ev.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event on subscriber 1")
	}

	select {
	case ev := <-ch2:
		if ev.Type != "multi" {
			t.Errorf("Subscriber 2 expected 'multi', got '%s'", ev.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event on subscriber 2")
	}

	ef.Unsubscribe("sub-1")
	ef.Unsubscribe("sub-2")
}

func TestEventFeed_UnsubscribeNonExistent(t *testing.T) {
	ef := NewEventFeed(100)
	ef.Unsubscribe("non-existent")
}

func TestEventFeed_GetRecentEvents_Empty(t *testing.T) {
	ef := NewEventFeed(100)
	events := ef.GetRecentEvents(10)
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}
}

func TestEventFeed_GetRecentEvents_LessThanRequested(t *testing.T) {
	ef := NewEventFeed(100)
	ef.PublishEvent(Event{Type: "one"})
	ef.PublishEvent(Event{Type: "two"})
	events := ef.GetRecentEvents(10)
	if len(events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(events))
	}
}

func TestEventFeed_GetRecentEvents_MoreThanAvailable(t *testing.T) {
	ef := NewEventFeed(100)
	ef.PublishEvent(Event{Type: "one"})
	events := ef.GetRecentEvents(100)
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
}

func TestEventFeed_MaxSizeEnforcement(t *testing.T) {
	ef := NewEventFeed(5)
	for i := 0; i < 10; i++ {
		ef.PublishEvent(Event{Type: "event"})
	}
	events := ef.GetRecentEvents(10)
	if len(events) > 5 {
		t.Errorf("Should not exceed maxSize of 5, got %d", len(events))
	}
}

func TestDashboardStats_AllFields(t *testing.T) {
	stats := DashboardStats{
		TotalAgents:     10,
		OnlineAgents:    8,
		AvgTrustScore:   85.5,
		TotalAnomalies:  5,
		CriticalThreats: 1,
		ComplianceScore: 92.0,
	}
	if stats.TotalAgents != 10 {
		t.Errorf("TotalAgents should be 10, got %d", stats.TotalAgents)
	}
	if stats.ComplianceScore != 92.0 {
		t.Errorf("ComplianceScore should be 92.0, got %f", stats.ComplianceScore)
	}
}

func TestComplianceStatus_AllFields(t *testing.T) {
	status := ComplianceStatus{
		Overall: "compliant",
		Score:   95.5,
		Frameworks: []FrameworkStatus{
			{Name: "SOC2", Status: "pass", Score: 98.0, Controls: 10, ControlsPass: 10},
			{Name: "HIPAA", Status: "pass", Score: 92.0, Controls: 5, ControlsPass: 5},
		},
		LastAudit: time.Now(),
		NextAudit: time.Now().Add(24 * time.Hour),
	}
	if status.Overall != "compliant" {
		t.Errorf("Overall should be 'compliant', got '%s'", status.Overall)
	}
	if len(status.Frameworks) != 2 {
		t.Errorf("Should have 2 frameworks, got %d", len(status.Frameworks))
	}
}

func TestFrameworkStatus_AllFields(t *testing.T) {
	fs := FrameworkStatus{
		Name:         "PCI-DSS",
		Status:       "pass",
		Score:        100.0,
		Controls:     12,
		ControlsPass: 12,
	}
	if fs.Name != "PCI-DSS" {
		t.Errorf("Name should be 'PCI-DSS', got '%s'", fs.Name)
	}
	if fs.Score != 100.0 {
		t.Errorf("Score should be 100.0, got %f", fs.Score)
	}
}

func TestAgentSummary_AllFields(t *testing.T) {
	summary := AgentSummary{
		ID:             "agent-1",
		Name:           "Test Agent",
		TrustLevel:     "high",
		Score:          95.0,
		Capabilities:   []string{"read", "write"},
		LastSeen:       time.Now(),
		IsOnline:       true,
		RiskLevel:      "low",
		TotalRequests:  1000,
		DeniedRequests: 10,
	}
	if summary.ID != "agent-1" {
		t.Errorf("ID should be 'agent-1', got '%s'", summary.ID)
	}
	if !summary.IsOnline {
		t.Error("IsOnline should be true")
	}
	if summary.TotalRequests != 1000 {
		t.Errorf("TotalRequests should be 1000, got %d", summary.TotalRequests)
	}
}

func TestThreatEvent_AllFields(t *testing.T) {
	event := ThreatEvent{
		ID:          "threat-1",
		Severity:    5,
		Type:        "injection",
		Description: "Prompt injection detected",
		Source:      "scanner",
		Timestamp:   time.Now(),
		Remediated:  false,
	}
	if event.Severity != 5 {
		t.Errorf("Severity should be 5, got %d", event.Severity)
	}
	if event.Type != "injection" {
		t.Errorf("Type should be 'injection', got '%s'", event.Type)
	}
}

func TestEvent_AllFields(t *testing.T) {
	event := Event{
		Type:      "capability_allowed",
		AgentID:   "agent-1",
		Timestamp: time.Now(),
		Data:      map[string]string{"capability": "file:read"},
	}
	if event.Type != "capability_allowed" {
		t.Errorf("Type should be 'capability_allowed', got '%s'", event.Type)
	}
	if event.AgentID != "agent-1" {
		t.Errorf("AgentID should be 'agent-1', got '%s'", event.AgentID)
	}
}

func TestDashboardData_AllFields(t *testing.T) {
	data := DashboardData{
		Agents:       []*AgentSummary{},
		TrustScores:  nil,
		Anomalies:    nil,
		ThreatFeed:   []ThreatEvent{},
		Compliance:   ComplianceStatus{Overall: "compliant"},
		RecentEvents: []Event{},
		Stats:        DashboardStats{TotalAgents: 0},
	}
	if data.Compliance.Overall != "compliant" {
		t.Errorf("Compliance.Overall should be 'compliant', got '%s'", data.Compliance.Overall)
	}
}

func TestEventFeed_Clear(t *testing.T) {
	ef := NewEventFeed(100)
	for i := 0; i < 50; i++ {
		ef.PublishEvent(Event{Type: "test"})
	}
	events := ef.GetRecentEvents(100)
	if len(events) != 50 {
		t.Errorf("Expected 50 events before clear, got %d", len(events))
	}
}

func TestComplianceStatus_WithNilFrameworks(t *testing.T) {
	status := ComplianceStatus{
		Overall:    "compliant",
		Score:      100.0,
		Frameworks: nil,
		LastAudit:  time.Now(),
		NextAudit:  time.Now().Add(24 * time.Hour),
	}
	if status.Score != 100.0 {
		t.Errorf("Score should be 100.0, got %f", status.Score)
	}
}

func TestEvent_DataTypes(t *testing.T) {
	e1 := Event{Type: "test", Data: "string data"}
	if e1.Data != "string data" {
		t.Error("String data not stored correctly")
	}

	e2 := Event{Type: "test", Data: map[string]int{"count": 42}}
	if e2.Data == nil {
		t.Error("Map data should be stored")
	}

	e3 := Event{Type: "test", Data: struct{ Name string }{Name: "test"}}
	if e3.Data == nil {
		t.Error("Struct data should be stored")
	}
}

func TestDashboard_EmptyAgentList(t *testing.T) {
	dash := NewDashboard(nil)
	if dash == nil {
		t.Error("Dashboard should be created even with nil engine")
	}
}

func TestDashboardStats_Zero(t *testing.T) {
	stats := DashboardStats{}
	if stats.TotalAgents != 0 {
		t.Errorf("Zero stats should have 0 agents, got %d", stats.TotalAgents)
	}
}

func TestThreatEvent_Remediated(t *testing.T) {
	event := ThreatEvent{
		ID:          "threat-1",
		Severity:    3,
		Type:        "injection",
		Description: "Resolved",
		Source:      "scanner",
		Timestamp:   time.Now(),
		Remediated:  true,
	}
	if !event.Remediated {
		t.Error("Remediated should be true")
	}
}

func TestComplianceStatus_NotCompliant(t *testing.T) {
	status := ComplianceStatus{
		Overall: "non-compliant",
		Score:   65.0,
	}
	if status.Overall != "non-compliant" {
		t.Error("Should be non-compliant")
	}
}
