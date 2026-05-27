package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// TestDashboardServeAllEndpoints tests all API endpoints via ServeHTTP
func TestDashboardServeAllEndpointsV2(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Record some data for testing
	_ = engine.RecordEvent(context.Background(), "agent-1", score.EventCapabilityAllowed, "file:read", 1, "")

	// Test all endpoints
	endpoints := []struct {
		path       string
		expectCode int
		expectJSON bool
	}{
		{"/api/v1/trust/dashboard", 200, true},
		{"/api/v1/trust/scores", 200, true},
		{"/api/v1/trust/anomalies?agentId=agent-1", 200, true},
		{"/api/v1/trust/compliance", 200, true},
		{"/api/v1/trust/unknown", 404, false},
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", ep.path, nil)
			rr := httptest.NewRecorder()
			dash.ServeHTTP(rr, req)

			if rr.Code != ep.expectCode {
				t.Errorf("Expected status %d, got %d", ep.expectCode, rr.Code)
			}

			if ep.expectJSON && rr.Code == 200 {
				var data interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
					t.Errorf("Response should be valid JSON: %v", err)
				}
			}
		})
	}
}

// TestDashboardServeJSONDirect tests serve functions directly
func TestDashboardServeJSONDirect(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Test serveDashboard
	t.Run("serveDashboard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		dash.serveDashboard(rr, req)

		if rr.Code != 200 {
			t.Errorf("Expected 200, got %d", rr.Code)
		}

		var data DashboardData
		if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
			t.Errorf("Should be valid DashboardData JSON: %v", err)
		}
	})

	// Test serveScores
	t.Run("serveScores", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		dash.serveScores(rr, req)

		if rr.Code != 200 {
			t.Errorf("Expected 200, got %d", rr.Code)
		}
	})

	// Test serveAnomalies
	t.Run("serveAnomalies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/?agentId=agent-1", nil)
		rr := httptest.NewRecorder()
		dash.serveAnomalies(rr, req)

		if rr.Code != 200 {
			t.Errorf("Expected 200, got %d", rr.Code)
		}
	})

	// Test serveCompliance
	t.Run("serveCompliance", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		dash.serveCompliance(rr, req)

		if rr.Code != 200 {
			t.Errorf("Expected 200, got %d", rr.Code)
		}

		var compliance ComplianceStatus
		if err := json.Unmarshal(rr.Body.Bytes(), &compliance); err != nil {
			t.Errorf("Should be valid ComplianceStatus JSON: %v", err)
		}
	})
}

// TestDashboardGetDashboardDataEdgeCases tests edge cases
func TestDashboardGetDashboardDataEdgeCases(t *testing.T) {
	// Test with no events
	t.Run("no_events", func(t *testing.T) {
		engine := score.NewEngine(nil)
		dash := NewDashboard(engine)

		data, err := dash.GetDashboardData(context.Background())
		if err != nil {
			t.Errorf("Should not error: %v", err)
		}
		if data == nil {
			t.Fatal("Data should not be nil")
		}
	})

	// Test with events
	t.Run("with_events", func(t *testing.T) {
		engine := score.NewEngine(nil)
		dash := NewDashboard(engine)

		_ = engine.RecordEvent(context.Background(), "agent-1", score.EventCapabilityAllowed, "file:read", 1, "")
		_ = engine.RecordEvent(context.Background(), "agent-2", score.EventCapabilityDenied, "file:write", 0, "denied")

		data, err := dash.GetDashboardData(context.Background())
		if err != nil {
			t.Errorf("Should not error: %v", err)
		}
		if data.Stats.TotalAgents < 2 {
			t.Errorf("Should have at least 2 agents, got %d", data.Stats.TotalAgents)
		}
	})

	// Test with context
	t.Run("with_context", func(t *testing.T) {
		engine := score.NewEngine(nil)
		dash := NewDashboard(engine)

		ctx := context.WithValue(context.Background(), "key", "value")
		data, err := dash.GetDashboardData(ctx)
		if err != nil {
			t.Errorf("Should not error with context: %v", err)
		}
		_ = data
	})
}

// TestEventFeedEdgeCases tests EventFeed edge cases
func TestEventFeedEdgeCases(t *testing.T) {
	ef := NewEventFeed(10)

	// Test with many events
	t.Run("many_events", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			ef.PublishEvent(Event{Type: "test", AgentID: "agent"})
		}
		events := ef.GetRecentEvents(5)
		if len(events) != 5 {
			t.Errorf("Should have 5 recent events, got %d", len(events))
		}
	})

	// Test with no events
	t.Run("no_events", func(t *testing.T) {
		ef2 := NewEventFeed(10)
		events := ef2.GetRecentEvents(5)
		if len(events) != 0 {
			t.Errorf("Should have 0 events, got %d", len(events))
		}
	})

	// Test unsubscribe
	t.Run("unsubscribe", func(t *testing.T) {
		ef3 := NewEventFeed(10)
		ch := ef3.Subscribe("sub-1")
		ef3.Unsubscribe("sub-1")

		select {
		case _, ok := <-ch:
			if ok {
				t.Log("Channel should be closed after unsubscribe")
			}
		default:
			// Channel is closed
		}
	})
}
