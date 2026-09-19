// SPDX-License-Identifier: Apache-2.0
// Integration tests for v4.5.0 P4: API Key Behavioral Baselining wired into
// auth middleware. Verifies that anomaly detection is initialized, records
// usage on successful API token auth, and detects anomalous patterns.

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_AnomalyDetectorInitialized(t *testing.T) {
	m := NewMiddleware(DefaultConfig())
	if m.anomalyDetector == nil {
		t.Fatal("anomalyDetector should be initialized in NewMiddleware")
	}
}

func TestMiddleware_AnomalyDetectorAccessor(t *testing.T) {
	m := NewMiddleware(DefaultConfig())
	if m.AnomalyDetector() == nil {
		t.Error("AnomalyDetector() should return non-nil")
	}
}

func TestMiddleware_RecordAndCheckAnomaly_RecordsUsage(t *testing.T) {
	m := NewMiddleware(DefaultConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	m.recordAndCheckAnomaly(req, "test-key-1")

	baseline, ok := m.anomalyDetector.GetBaseline("test-key-1")
	if !ok {
		t.Fatal("baseline should be created after recordAndCheckAnomaly")
	}
	if baseline.RequestCount != 1 {
		t.Errorf("expected 1 request, got %d", baseline.RequestCount)
	}
}

func TestMiddleware_RecordAndCheckAnomaly_DetectsNewTool(t *testing.T) {
	m := NewMiddleware(DefaultConfig())
	// Build a baseline with 10+ samples on one endpoint
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/normal", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		m.recordAndCheckAnomaly(req, "test-key-newtool")
	}

	// Now call with a different endpoint (new "tool")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sensitive", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	m.recordAndCheckAnomaly(req, "test-key-newtool")

	baseline, _ := m.anomalyDetector.GetBaseline("test-key-newtool")
	if baseline.RequestCount != 13 {
		t.Errorf("expected 13 requests, got %d", baseline.RequestCount)
	}
}

func TestMiddleware_RecordAndCheckAnomaly_DetectsNewIP(t *testing.T) {
	m := NewMiddleware(DefaultConfig())
	// Build baseline from one IP
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		m.recordAndCheckAnomaly(req, "test-key-geo")
	}

	// Now call from a new IP
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.RemoteAddr = "192.168.99.99:54321"
	m.recordAndCheckAnomaly(req, "test-key-geo")

	baseline, _ := m.anomalyDetector.GetBaseline("test-key-geo")
	if len(baseline.SourceIPs) != 2 {
		t.Errorf("expected 2 source IPs, got %d", len(baseline.SourceIPs))
	}
}

func TestMiddleware_RecordAndCheckAnomaly_NilDetector_NoPanic(t *testing.T) {
	m := &Middleware{config: DefaultConfig()}
	// anomalyDetector is nil — should not panic
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	m.recordAndCheckAnomaly(req, "test-key")
}

func TestAnomalyTypeNames(t *testing.T) {
	tests := []struct {
		types []AnomalyType
		want  string
	}{
		{[]AnomalyType{AnomalyVolumeSpike}, "volume_spike"},
		{[]AnomalyType{AnomalyOffHours}, "off_hours"},
		{[]AnomalyType{AnomalyGeoShift}, "geo_shift"},
		{[]AnomalyType{AnomalyNewTool}, "new_tool"},
		{[]AnomalyType{AnomalyRateExceeded}, "rate_exceeded"},
		{[]AnomalyType{AnomalyVolumeSpike, AnomalyGeoShift}, "volume_spike,geo_shift"},
		{[]AnomalyType{}, ""},
	}
	for _, tt := range tests {
		got := anomalyTypeNames(tt.types)
		if got != tt.want {
			t.Errorf("anomalyTypeNames(%v) = %q, want %q", tt.types, got, tt.want)
		}
	}
}

func TestMiddleware_RequireAuth_APIToken_RecordsAnomaly(t *testing.T) {
	cfg := &Config{
		APIAuthToken: "test-token-12345",
		RequireAuth:  true,
	}
	m := NewMiddleware(cfg)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	wrapped := m.RequireAuth(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
	req.Header.Set("Authorization", "token test-token-12345")
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if !handlerCalled {
		t.Fatal("handler should have been called with valid token")
	}

	// Verify usage was recorded
	baseline, ok := m.anomalyDetector.GetBaseline("api-service")
	if !ok {
		t.Fatal("baseline should be created for api-service")
	}
	if baseline.RequestCount != 1 {
		t.Errorf("expected 1 request recorded, got %d", baseline.RequestCount)
	}
}
