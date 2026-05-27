package dashboard

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

func TestNewDashboard(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)
	if dash == nil {
		t.Fatal("NewDashboard returned nil")
	}
}

func TestNewEventFeed(t *testing.T) {
	ef := NewEventFeed(100)
	if ef == nil {
		t.Fatal("NewEventFeed returned nil")
	}
	if ef.maxSize != 100 {
		t.Errorf("maxSize should be 100, got %d", ef.maxSize)
	}
}

func TestEventFeed_PublishEvent(t *testing.T) {
	ef := NewEventFeed(100)
	ef.PublishEvent(Event{Type: "test", AgentID: "agent-1"})
	events := ef.GetRecentEvents(10)
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
}

func TestEventFeed_Subscribe(t *testing.T) {
	ef := NewEventFeed(100)
	ch := ef.Subscribe("sub-1")
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}
	ef.Unsubscribe("sub-1")
}

func TestEventFeed_GetRecentEvents(t *testing.T) {
	ef := NewEventFeed(100)
	for i := 0; i < 50; i++ {
		ef.PublishEvent(Event{Type: "test"})
	}
	events := ef.GetRecentEvents(10)
	if len(events) != 10 {
		t.Errorf("Expected 10 events, got %d", len(events))
	}
}

func TestDashboard_GetDashboardData(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)
	_ = engine.RecordEvent(context.Background(), "agent-1", score.EventCapabilityAllowed, "file:read", 1, "")
	data, err := dash.GetDashboardData(context.Background())
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}
	if data == nil {
		t.Fatal("GetDashboardData returned nil")
	}
	if data.Stats.TotalAgents < 1 {
		t.Error("Should have at least 1 agent")
	}
}

func TestDashboardStats(t *testing.T) {
	stats := DashboardStats{
		TotalAgents:   10,
		OnlineAgents:  8,
		AvgTrustScore: 85.5,
	}
	if stats.TotalAgents != 10 {
		t.Errorf("TotalAgents should be 10, got %d", stats.TotalAgents)
	}
}

func TestComplianceStatus(t *testing.T) {
	status := ComplianceStatus{
		Overall: "compliant",
		Score:   95.0,
		Frameworks: []FrameworkStatus{
			{Name: "GDPR", Status: "compliant", Score: 98.0},
		},
	}
	if status.Overall != "compliant" {
		t.Errorf("Overall should be compliant, got %s", status.Overall)
	}
}
