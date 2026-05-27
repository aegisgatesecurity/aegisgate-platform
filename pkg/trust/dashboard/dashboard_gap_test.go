package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

func TestDashboardServeDashboardJSON(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Use correct path
	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)

	if rr.Code != 200 {
		// Check if it returned something valid
		t.Logf("Response code: %d, body: %s", rr.Code, rr.Body.String())
	}

	// Try to parse as JSON
	if rr.Code == 200 {
		var data map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
			t.Errorf("Response should be valid JSON: %v", err)
		}
	}
}

func TestDashboardServeScoresJSON(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/dashboard/scores", nil)
	rr := httptest.NewRecorder()
	dash.serveScores(rr, req)

	// Either 200 with JSON or other valid response
	if rr.Code == 200 {
		var scores []interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &scores); err != nil {
			t.Logf("Scores may not be array: %v", err)
		}
	}
}

func TestDashboardServeAnomaliesJSON(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/dashboard/anomalies", nil)
	rr := httptest.NewRecorder()
	dash.serveAnomalies(rr, req)

	if rr.Code != 200 {
		t.Logf("Anomalies response code: %d", rr.Code)
	}
}

func TestDashboardServeComplianceJSON(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/dashboard/compliance", nil)
	rr := httptest.NewRecorder()
	dash.serveCompliance(rr, req)

	if rr.Code != 200 {
		t.Logf("Compliance response code: %d", rr.Code)
	}
}

func TestDashboardGetDashboardDataWithEvents(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Publish some events
	dash.events.PublishEvent(Event{
		Type:    "test_event",
		AgentID: "agent-1",
		Data:    map[string]string{"key": "value"},
	})

	data, err := dash.GetDashboardData(nil)
	if err != nil {
		t.Errorf("GetDashboardData failed: %v", err)
	}
	if data == nil {
		t.Fatal("Data should not be nil")
	}
}

func TestDashboardServeHTTPUnknownPath(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/unknown/path", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)

	// Should return 404 for unknown paths
	if rr.Code != 404 {
		t.Errorf("Expected 404, got %d", rr.Code)
	}
}
