// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Dashboard HTTP Endpoint Tests
// ============================================================================

package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// TestServeHTTP_DashboardEndpoint tests /api/v1/trust/dashboard
func TestServeHTTP_DashboardEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	_ = engine.RecordEvent(nil, "agent-test", score.EventCapabilityAllowed, "cap-1", 1, "test")

	req := httptest.NewRequest("GET", "/api/v1/trust/dashboard", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json, got %s", w.Header().Get("Content-Type"))
	}

	// Verify JSON is valid
	body, _ := io.ReadAll(w.Body)
	var data DashboardData
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("Invalid JSON response: %v", err)
	}
}

// TestServeHTTP_ScoresEndpoint tests /api/v1/trust/scores
func TestServeHTTP_ScoresEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	_ = engine.RecordEvent(nil, "score-agent", score.EventCapabilityAllowed, "cap-1", 1, "test")

	req := httptest.NewRequest("GET", "/api/v1/trust/scores", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify valid JSON
	body, _ := io.ReadAll(w.Body)
	var scores []*score.TrustScore
	if err := json.Unmarshal(body, &scores); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}

// TestServeHTTP_AnomaliesEndpoint tests /api/v1/trust/anomalies
func TestServeHTTP_AnomaliesEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/anomalies?agentId=test-agent", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	var anomalies []*score.Anomaly
	if err := json.Unmarshal(body, &anomalies); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}

// TestServeHTTP_ComplianceEndpoint tests /api/v1/trust/compliance
func TestServeHTTP_ComplianceEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/compliance", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	var compliance ComplianceStatus
	if err := json.Unmarshal(body, &compliance); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}

// TestServeHTTP_UnknownEndpoint tests unknown path returns 404
func TestServeHTTP_UnknownEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/unknown", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

// TestServeHTTP_RootPath tests root path
func TestServeHTTP_RootPath(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for root path, got %d", w.Code)
	}
}

// TestServeDashboard_MultipleRequests tests multiple dashboard requests
func TestServeDashboard_MultipleRequests(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	for i := 0; i < 5; i++ {
		_ = engine.RecordEvent(nil, "agent-"+string(rune('0'+i)), score.EventCapabilityAllowed, "cap", 1, "test")

		req := httptest.NewRequest("GET", "/api/v1/trust/dashboard", nil)
		w := httptest.NewRecorder()
		d.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i, w.Code)
		}
	}
}

// TestServeScores_WithScores tests scores endpoint with recorded scores
func TestServeScores_WithScores(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	// Record events to generate scores
	agents := []string{"agent-a", "agent-b", "agent-c"}
	for _, a := range agents {
		_ = engine.RecordEvent(nil, a, score.EventCapabilityAllowed, "file:read", 1, "read operation")
		_ = engine.RecordEvent(nil, a, score.EventCapabilityDenied, "file:write", 1, "denied write")
	}

	req := httptest.NewRequest("GET", "/api/v1/trust/scores", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	var scores []*score.TrustScore
	if err := json.Unmarshal(body, &scores); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if len(scores) != 3 {
		t.Logf("Expected 3 scores, got %d", len(scores))
	}
}

// TestServeAnomalies_NoParams tests anomalies without agentId param
func TestServeAnomalies_NoParams(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/anomalies", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

// TestServeCompliance_EmptyState tests compliance in empty state
func TestServeCompliance_EmptyState(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("GET", "/api/v1/trust/compliance", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	var compliance ComplianceStatus
	if err := json.Unmarshal(body, &compliance); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
}

// TestServeHTTP_PostMethod tests POST to dashboard endpoint
func TestServeHTTP_PostMethod(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("POST", "/api/v1/trust/dashboard", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	// POST should also work (handled by same handler)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for POST, got %d", w.Code)
	}
}

// TestServeHTTP_PutMethod tests PUT to scores endpoint
func TestServeHTTP_PutMethod(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := httptest.NewRequest("PUT", "/api/v1/trust/scores", nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for PUT, got %d", w.Code)
	}
}
