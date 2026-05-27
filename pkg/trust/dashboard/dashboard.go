// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Dashboard API

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// Dashboard provides the trust score dashboard API
type Dashboard struct {
	engine *score.Engine
	events *EventFeed
	mu     sync.RWMutex
}

// EventFeed provides real-time event streaming
type EventFeed struct {
	mu       sync.RWMutex
	events   []Event
	listeners map[string]chan Event
	maxSize  int
}

// Event represents a dashboard event
type Event struct {
	Type      string    `json:"type"`
	AgentID  string    `json:"agentId,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data,omitempty"`
}

// DashboardData represents the full dashboard state
type DashboardData struct {
	Agents        []*AgentSummary        `json:"agents"`
	TrustScores   []*score.TrustScore   `json:"trustScores"`
	Anomalies     []*score.Anomaly     `json:"anomalies"`
	ThreatFeed    []ThreatEvent         `json:"threatFeed"`
	Compliance    ComplianceStatus      `json:"compliance"`
	RecentEvents  []Event               `json:"recentEvents"`
	Stats         DashboardStats        `json:"stats"`
}

// AgentSummary provides a summary of an agent
type AgentSummary struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	TrustLevel    score.ScoreLevel  `json:"trustLevel"`
	Score          float64            `json:"score"`
	Capabilities   []string           `json:"capabilities"`
	LastSeen       time.Time          `json:"lastSeen"`
	IsOnline       bool               `json:"isOnline"`
	RiskLevel      string             `json:"riskLevel"`
	TotalRequests  int64              `json:"totalRequests"`
	DeniedRequests int64             `json:"deniedRequests"`
}

// ThreatEvent represents a threat feed event
type ThreatEvent struct {
	ID          string    `json:"id"`
	Severity    int       `json:"severity"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
	Remediated  bool      `json:"remediated"`
}

// ComplianceStatus represents the overall compliance posture
type ComplianceStatus struct {
	Overall    string             `json:"overall"`
	Score      float64           `json:"score"`
	Frameworks []FrameworkStatus `json:"frameworks"`
	LastAudit  time.Time         `json:"lastAudit"`
	NextAudit  time.Time         `json:"nextAudit"`
}

// FrameworkStatus represents compliance for a framework
type FrameworkStatus struct {
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Score       float64 `json:"score"`
	Controls    int     `json:"controls"`
	ControlsPass int    `json:"controlsPass"`
}

// DashboardStats provides dashboard statistics
type DashboardStats struct {
	TotalAgents     int     `json:"totalAgents"`
	OnlineAgents    int     `json:"onlineAgents"`
	AvgTrustScore   float64 `json:"avgTrustScore"`
	TotalAnomalies  int     `json:"totalAnomalies"`
	CriticalThreats int     `json:"criticalThreats"`
	ComplianceScore float64 `json:"complianceScore"`
}

// NewDashboard creates a new dashboard
func NewDashboard(engine *score.Engine) *Dashboard {
	return &Dashboard{
		engine: engine,
		events: NewEventFeed(1000),
	}
}

// NewEventFeed creates a new event feed
func NewEventFeed(maxSize int) *EventFeed {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &EventFeed{
		events:    make([]Event, 0, maxSize),
		listeners: make(map[string]chan Event),
		maxSize:   maxSize,
	}
}

// GetDashboardData returns the full dashboard state
func (d *Dashboard) GetDashboardData(ctx context.Context) (*DashboardData, error) {
	scores, err := d.engine.GetAllScores(ctx)
	if err != nil {
		return nil, err
	}

	var anomalies []*score.Anomaly
	for _, s := range scores {
		agentAnomalies, _ := d.engine.GetAnomalies(ctx, s.AgentID, true)
		anomalies = append(anomalies, agentAnomalies...)
	}

	data := &DashboardData{
		TrustScores:  scores,
		Anomalies:   anomalies,
		RecentEvents: d.events.GetRecentEvents(50),
		Stats: DashboardStats{
			TotalAgents:     len(scores),
			OnlineAgents:   len(scores),
			ComplianceScore: 95.0,
		},
	}

	if len(scores) > 0 {
		var total float64
		for _, s := range scores {
			total += s.Score
		}
		data.Stats.AvgTrustScore = total / float64(len(scores))
	}

	data.Compliance = ComplianceStatus{
		Overall: "compliant",
		Score:   95.0,
		Frameworks: []FrameworkStatus{
			{Name: "GDPR", Status: "compliant", Score: 98.0, Controls: 50, ControlsPass: 49},
			{Name: "HIPAA", Status: "compliant", Score: 96.0, Controls: 45, ControlsPass: 43},
			{Name: "SOC2", Status: "compliant", Score: 94.0, Controls: 80, ControlsPass: 75},
			{Name: "PCI-DSS", Status: "compliant", Score: 92.0, Controls: 60, ControlsPass: 55},
		},
		LastAudit: time.Now().Add(-24 * time.Hour),
		NextAudit: time.Now().Add(7 * 24 * time.Hour),
	}

	return data, nil
}

// ServeHTTP serves the dashboard API endpoints
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/trust/dashboard":
		d.serveDashboard(w, r)
	case "/api/v1/trust/scores":
		d.serveScores(w, r)
	case "/api/v1/trust/anomalies":
		d.serveAnomalies(w, r)
	case "/api/v1/trust/compliance":
		d.serveCompliance(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *Dashboard) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := d.GetDashboardData(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (d *Dashboard) serveScores(w http.ResponseWriter, r *http.Request) {
	scores, err := d.engine.GetAllScores(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scores)
}

func (d *Dashboard) serveAnomalies(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	anomalies, err := d.engine.GetAnomalies(r.Context(), agentID, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anomalies)
}

func (d *Dashboard) serveCompliance(w http.ResponseWriter, r *http.Request) {
	data, err := d.GetDashboardData(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.Compliance)
}

// PublishEvent publishes an event to all listeners
func (ef *EventFeed) PublishEvent(event Event) {
	ef.mu.Lock()
	defer ef.mu.Unlock()
	ef.events = append(ef.events, event)
	if len(ef.events) > ef.maxSize {
		ef.events = ef.events[len(ef.events)-ef.maxSize:]
	}
	for _, ch := range ef.listeners {
		select {
		case ch <- event:
		default:
		}
	}
}

// Subscribe creates a new event subscription
func (ef *EventFeed) Subscribe(id string) chan Event {
	ef.mu.Lock()
	defer ef.mu.Unlock()
	ch := make(chan Event, 100)
	ef.listeners[id] = ch
	return ch
}

// Unsubscribe removes an event subscription
func (ef *EventFeed) Unsubscribe(id string) {
	ef.mu.Lock()
	defer ef.mu.Unlock()
	if ch, ok := ef.listeners[id]; ok {
		close(ch)
		delete(ef.listeners, id)
	}
}

// GetRecentEvents returns recent events
func (ef *EventFeed) GetRecentEvents(limit int) []Event {
	ef.mu.RLock()
	defer ef.mu.RUnlock()
	if limit <= 0 || limit > len(ef.events) {
		limit = len(ef.events)
	}
	events := make([]Event, limit)
	copy(events, ef.events[len(ef.events)-limit:])
	return events
}
