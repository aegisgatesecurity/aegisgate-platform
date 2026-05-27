// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDashboardRequest(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

func getDashboardResponseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	return body
}

func TestDashboardServeHTTP_DashboardEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/dashboard")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	body := getDashboardResponseBody(t, w)
	assert.Contains(t, body, "trustScores")
	assert.Contains(t, body, "stats")
}

func TestDashboardServeHTTP_ScoresEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/scores")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestDashboardServeHTTP_AnomaliesEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/anomalies")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardServeHTTP_AnomaliesWithAgentID(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/anomalies?agentId=agent-123")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardServeHTTP_ComplianceEndpoint(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/compliance")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := getDashboardResponseBody(t, w)
	assert.Contains(t, body, "overall")
}

func TestDashboardServeHTTP_NotFound(t *testing.T) {
	engine := score.NewEngine(nil)
	d := NewDashboard(engine)

	req := newDashboardRequest("GET", "/api/v1/trust/unknown")
	w := httptest.NewRecorder()

	d.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNewEventFeed_Limits(t *testing.T) {
	ef := NewEventFeed(5)
	for i := 0; i < 10; i++ {
		ef.PublishEvent(Event{Type: "test", AgentID: "agent-" + string(rune('0'+i))})
	}
	events := ef.GetRecentEvents(10)
	assert.LessOrEqual(t, len(events), 5)
}

func TestEventFeed_SubscribeUnsubscribe(t *testing.T) {
	ef := NewEventFeed(100)
	ch := ef.Subscribe("subscriber-1")
	assert.NotNil(t, ch)
	ef.PublishEvent(Event{Type: "test", AgentID: "agent-123"})
	ef.Unsubscribe("subscriber-1")
	ef.Unsubscribe("non-existent")
}

func TestPublishEvent_ChannelFull(t *testing.T) {
	ef := NewEventFeed(100)
	ch := ef.Subscribe("buffer-test")
	for i := 0; i < 150; i++ {
		ef.PublishEvent(Event{Type: "test", AgentID: "agent"})
	}
	select {
	case <-ch:
	default:
	}
	ef.Unsubscribe("buffer-test")
}

func TestGetRecentEvents_Limit(t *testing.T) {
	ef := NewEventFeed(100)
	for i := 0; i < 20; i++ {
		ef.PublishEvent(Event{Type: "test", AgentID: "agent"})
	}
	events := ef.GetRecentEvents(5)
	assert.Equal(t, 5, len(events))
	events = ef.GetRecentEvents(50)
	assert.Equal(t, 20, len(events))
	// When limit <= 0, GetRecentEvents returns all events (implementation behavior)
	events = ef.GetRecentEvents(0)
	assert.Equal(t, 20, len(events))
}
