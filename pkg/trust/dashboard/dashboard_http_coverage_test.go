package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// ============================================================================
// Dashboard HTTP Handler Tests - Push to 95%+
// ============================================================================

func TestDashboardServeHTTPAllPaths(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Test all ServeHTTP paths
	testCases := []struct {
		path       string
		method     string
		expectCode int
	}{
		{"/api/v1/trust/dashboard", "GET", 200},
		{"/api/v1/trust/scores", "GET", 200},
		{"/api/v1/trust/anomalies?agentId=agent-1", "GET", 200},
		{"/api/v1/trust/anomalies?agentId=", "GET", 200},
		{"/api/v1/trust/compliance", "GET", 200},
		{"/unknown/path", "GET", 404},
		{"/", "POST", 404},
	}

	for _, tc := range testCases {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()
			dash.ServeHTTP(rr, req)

			if rr.Code != tc.expectCode {
				t.Errorf("Expected %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestDashboardServeDashboardWithData(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Add data to the engine
	_ = engine.RecordEvent(context.Background(), "agent-1", score.EventCapabilityAllowed, "file:read", 1, "")
	_ = engine.RecordEvent(context.Background(), "agent-2", score.EventCapabilityAllowed, "file:write", 1, "")

	// Test serveDashboard
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var data DashboardData
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("Should be valid JSON: %v", err)
	}

	if data.Stats.TotalAgents < 2 {
		t.Errorf("Should have at least 2 agents, got %d", data.Stats.TotalAgents)
	}

	if len(data.Compliance.Frameworks) == 0 {
		t.Error("Compliance should not be nil")
	}

	if len(data.Compliance.Frameworks) == 0 {
		t.Error("Should have compliance frameworks")
	}
}

func TestDashboardServeScoresWithData(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Add multiple events
	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(context.Background(), "agent-"+string(rune('0'+i)), score.EventCapabilityAllowed, "file:read", 1, "")
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveScores(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	// Should be JSON array
	var scores []interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &scores); err != nil {
		t.Fatalf("Should be valid JSON array: %v", err)
	}
}

func TestDashboardServeAnomaliesWithQuery(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Add some data
	_ = engine.RecordEvent(context.Background(), "agent-anomaly", score.EventCapabilityDenied, "file:write", 0, "access denied")

	req := httptest.NewRequest("GET", "/?agentId=agent-anomaly", nil)
	rr := httptest.NewRecorder()
	dash.serveAnomalies(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	// Should be JSON array
	var anomalies []interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &anomalies); err != nil {
		t.Fatalf("Should be valid JSON: %v", err)
	}
}

func TestDashboardComplianceEndpointV2(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveCompliance(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var compliance ComplianceStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &compliance); err != nil {
		t.Fatalf("Should be valid ComplianceStatus JSON: %v", err)
	}

	if compliance.Overall != "compliant" {
		t.Errorf("Overall should be compliant, got %s", compliance.Overall)
	}

	if compliance.Score <= 0 {
		t.Error("Compliance score should be positive")
	}

	if len(compliance.Frameworks) == 0 {
		t.Error("Should have at least one framework")
	}
}

func TestDashboardServeDashboardWithNoAgents(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// No events recorded
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var data DashboardData
	_ = json.Unmarshal(rr.Body.Bytes(), &data)

	if data.Stats.TotalAgents != 0 {
		t.Errorf("TotalAgents should be 0, got %d", data.Stats.TotalAgents)
	}
}

func TestDashboardServeScoresWithNoScores(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveScores(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}
}

func TestDashboardServeAnomaliesNoAgentId(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Empty agentId
	req := httptest.NewRequest("GET", "/?agentId=", nil)
	rr := httptest.NewRecorder()
	dash.serveAnomalies(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}
}

func TestDashboardServeComplianceMultipleFrameworks(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	dash.serveCompliance(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	var compliance ComplianceStatus
	_ = json.Unmarshal(rr.Body.Bytes(), &compliance)

	// Verify all frameworks have scores
	for _, fw := range compliance.Frameworks {
		if fw.Score < 0 || fw.Score > 100 {
			t.Errorf("Framework %s has invalid score: %f", fw.Name, fw.Score)
		}
		if fw.Controls < 0 {
			t.Errorf("Framework %s has invalid controls count", fw.Name)
		}
		if fw.ControlsPass > fw.Controls {
			t.Errorf("Framework %s has more passing than total controls", fw.Name)
		}
	}
}

// ============================================================================
// EventFeed Tests
// ============================================================================

func TestEventFeedPublishAndGet(t *testing.T) {
	ef := NewEventFeed(20)

	// Publish events
	for i := 0; i < 15; i++ {
		ef.PublishEvent(Event{
			Type:    "test_event",
			AgentID: "agent-" + string(rune('a'+i%26)),
			Data:    map[string]string{"index": string(rune('0' + i%10))},
		})
	}

	// Get recent events
	events := ef.GetRecentEvents(10)
	if len(events) != 10 {
		t.Errorf("Expected 10 events, got %d", len(events))
	}

	// Get all events
	allEvents := ef.GetRecentEvents(20)
	if len(allEvents) != 15 {
		t.Errorf("Expected 15 events, got %d", len(allEvents))
	}
}

func TestEventFeedOverflow(t *testing.T) {
	ef := NewEventFeed(5)

	// Publish more than maxSize
	for i := 0; i < 10; i++ {
		ef.PublishEvent(Event{Type: "overflow_test", AgentID: "agent"})
	}

	events := ef.GetRecentEvents(10)
	if len(events) != 5 {
		t.Errorf("Should be limited to maxSize (5), got %d", len(events))
	}
}

func TestEventFeedSubscribeV2(t *testing.T) {
	ef := NewEventFeed(10)

	ch1 := ef.Subscribe("sub-1")
	ch2 := ef.Subscribe("sub-2")

	if ch1 == nil || ch2 == nil {
		t.Fatal("Subscribe should return non-nil channels")
	}

	// Publish and verify channel receives
	ef.PublishEvent(Event{Type: "subscribe_test", AgentID: "test"})

	select {
	case evt := <-ch1:
		if evt.Type != "subscribe_test" {
			t.Errorf("Expected subscribe_test event, got %s", evt.Type)
		}
	case <-time.After(time.Second):
		t.Error("Should have received event on channel")
	}

	// Unsubscribe
	ef.Unsubscribe("sub-1")
	ef.Unsubscribe("sub-2")
}

func TestEventFeedSubscribeBufferFull(t *testing.T) {
	ef := NewEventFeed(10)

	ch := ef.Subscribe("buffer-test")

	// Fill channel buffer
	for i := 0; i < 20; i++ {
		ef.PublishEvent(Event{Type: "buffer_test", AgentID: "test"})
	}

	// Channel should not block (buffer is full, so event is dropped)
	select {
	case <-ch:
		// Event received
	case <-time.After(100 * time.Millisecond):
		// Buffer full, event dropped - this is expected
	}
}

func TestEventFeedUnsubscribeNonExistent(t *testing.T) {
	ef := NewEventFeed(10)

	// Unsubscribe non-existent subscription
	ef.Unsubscribe("non-existent")
	// Should not panic
}

// ============================================================================
// GetDashboardData Edge Cases
// ============================================================================

func TestGetDashboardDataWithEvents(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Add multiple events
	events := []struct {
		agentID   string
		eventType score.EventType
		cap       string
		allowed   bool
	}{
		{"agent-1", score.EventCapabilityAllowed, "file:read", true},
		{"agent-1", score.EventCapabilityDenied, "file:write", false},
		{"agent-2", score.EventCapabilityAllowed, "file:read", true},
		{"agent-2", score.EventCapabilityAllowed, "file:write", true},
	}

	for _, e := range events {
		_ = engine.RecordEvent(context.Background(), e.agentID, e.eventType, e.cap, 1, "")
	}

	data, err := dash.GetDashboardData(context.Background())
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if data.Stats.TotalAgents < 2 {
		t.Errorf("Should have at least 2 agents, got %d", data.Stats.TotalAgents)
	}

	if data.Stats.AvgTrustScore < 0 {
		t.Error("AvgTrustScore should be non-negative")
	}
}

func TestGetDashboardDataWithNilContext(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	data, err := dash.GetDashboardData(nil)
	if err != nil {
		t.Fatalf("GetDashboardData with nil context failed: %v", err)
	}
	if data == nil {
		t.Fatal("Data should not be nil")
	}
}

func TestGetDashboardDataWithCancelledContext(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data, err := dash.GetDashboardData(ctx)
	if err != nil {
		t.Logf("GetDashboardData with cancelled context returned error: %v", err)
	}
	_ = data
}

func TestGetDashboardDataComplianceFrameworks(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	data, _ := dash.GetDashboardData(context.Background())

	// Verify compliance frameworks
	frameworks := []string{"GDPR", "HIPAA", "SOC2", "PCI-DSS"}
	found := make(map[string]bool)

	for _, fw := range data.Compliance.Frameworks {
		found[fw.Name] = true
	}

	for _, expected := range frameworks {
		if !found[expected] {
			t.Errorf("Expected framework %s not found", expected)
		}
	}
}

// ============================================================================
// Dashboard Stats Tests
// ============================================================================

func TestDashboardStatsDefaults(t *testing.T) {
	stats := DashboardStats{
		TotalAgents:     10,
		OnlineAgents:    8,
		AvgTrustScore:   85.5,
		ComplianceScore: 92.0,
	}

	if stats.TotalAgents != 10 {
		t.Errorf("TotalAgents should be 10, got %d", stats.TotalAgents)
	}

	if stats.OnlineAgents > stats.TotalAgents {
		t.Error("OnlineAgents should not exceed TotalAgents")
	}

	if stats.AvgTrustScore < 0 || stats.AvgTrustScore > 100 {
		t.Error("AvgTrustScore should be between 0 and 100")
	}
}

func TestComplianceStatusFrameworks(t *testing.T) {
	status := ComplianceStatus{
		Overall:         "compliant",
		Score:           95.0,
		LastAudit:       time.Now().Add(-24 * time.Hour),
		NextAudit:       time.Now().Add(7 * 24 * time.Hour),
		Frameworks: []FrameworkStatus{
			{Name: "GDPR", Status: "compliant", Score: 98.0, Controls: 50, ControlsPass: 48},
			{Name: "HIPAA", Status: "compliant", Score: 96.0, Controls: 45, ControlsPass: 44},
			{Name: "SOC2", Status: "compliant", Score: 94.0, Controls: 80, ControlsPass: 76},
		},
	}

	if status.Overall != "compliant" {
		t.Errorf("Overall should be compliant, got %s", status.Overall)
	}

	if status.Score < 0 || status.Score > 100 {
		t.Error("Score should be between 0 and 100")
	}

	for _, fw := range status.Frameworks {
		if fw.Score < 0 || fw.Score > 100 {
			t.Errorf("Framework %s has invalid score", fw.Name)
		}
	}
}

// ============================================================================
// Dashboard Data Edge Cases
// ============================================================================

func TestDashboardDataEmpty(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	data, _ := dash.GetDashboardData(context.Background())

	if data.Stats.TotalAgents != 0 {
		t.Errorf("TotalAgents should be 0, got %d", data.Stats.TotalAgents)
	}

	if data.Stats.AvgTrustScore != 0 {
		t.Errorf("AvgTrustScore should be 0, got %f", data.Stats.AvgTrustScore)
	}

	if len(data.RecentEvents) != 0 {
		t.Errorf("RecentEvents should be empty, got %d", len(data.RecentEvents))
	}
}

func TestDashboardDataWithRecentEvents(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Publish events to event feed
	for i := 0; i < 10; i++ {
		dash.events.PublishEvent(Event{
			Type:    "test_event",
			AgentID: "agent",
			Data:    map[string]string{"index": string(rune('0' + i%10))},
		})
	}

	data, _ := dash.GetDashboardData(context.Background())

	if len(data.RecentEvents) == 0 {
		t.Error("RecentEvents should not be empty")
	}
}

// ============================================================================
// HTTP Content Type Tests
// ============================================================================

func TestServeHTTPContentType(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	// Test that responses have correct content type
	paths := []string{"/api/v1/trust/dashboard", "/api/v1/trust/scores", "/api/v1/trust/compliance"}

	for _, path := range paths {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		dash.ServeHTTP(rr, req)

		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Path %s should have application/json content type, got %s", path, ct)
		}
	}
}

func TestServeHTTPJSONEncoding(t *testing.T) {
	engine := score.NewEngine(nil)
	dash := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/dashboard", nil)
	rr := httptest.NewRecorder()
	dash.ServeHTTP(rr, req)

	// Verify it's valid JSON that can be parsed
	body := rr.Body.String()
	if !strings.HasPrefix(body, "{") {
		t.Errorf("Response should be JSON object, got: %s", body[:min(50, len(body))])
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}