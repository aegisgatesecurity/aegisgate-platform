package dashboard

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

func TestEventFeedPublish(t *testing.T) {
	feed := NewEventFeed(100)
	event := Event{
		Type:      "test_event",
		AgentID:   "agent-1",
		Timestamp: time.Now(),
	}
	feed.PublishEvent(event)
}

func TestEventFeedSubscribe(t *testing.T) {
	feed := NewEventFeed(100)
	ch := feed.Subscribe("sub-1")
	if ch == nil {
		t.Error("Subscribe should return channel")
	}
	feed.Unsubscribe("sub-1")
}

func TestEventFeedUnsubscribe(t *testing.T) {
	feed := NewEventFeed(100)
	feed.Subscribe("sub-1")
	feed.Unsubscribe("sub-1")
}

func TestEventFeedGetRecentEvents(t *testing.T) {
	feed := NewEventFeed(100)
	feed.PublishEvent(Event{AgentID: "agent-1", Type: "test", Timestamp: time.Now()})
	events := feed.GetRecentEvents(10)
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
}

func TestEventFeedGetRecentEventsLimit(t *testing.T) {
	feed := NewEventFeed(10)
	for i := 0; i < 20; i++ {
		feed.PublishEvent(Event{AgentID: "agent-1", Type: "test", Timestamp: time.Now()})
	}
	events := feed.GetRecentEvents(5)
	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}
}

func TestDashboardServeHTTP(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)
}

func TestDashboardServeScores(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/dashboard/scores", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)
}

func TestDashboardServeAnomalies(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/dashboard/anomalies", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)
}

func TestDashboardServeCompliance(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/dashboard/compliance", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)
}
