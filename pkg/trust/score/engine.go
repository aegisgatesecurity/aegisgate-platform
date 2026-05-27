// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Score Engine

package score

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine is the main trust score engine that coordinates all components
type Engine struct {
	mu        sync.RWMutex
	calculator *Calculator
	baseline   BaselineEngine
	detector  *AnomalyDetector
	scores    map[string]*TrustScore
	config    *Config
}

// NewEngine creates a new trust score engine
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	baseline := NewBaselineEngine(config.BaselineWindow)
	calculator := NewCalculator(config, baseline)
	detector := NewAnomalyDetector(config)

	return &Engine{
		calculator: calculator,
		baseline:   baseline,
		detector:  detector,
		scores:    make(map[string]*TrustScore),
		config:    config,
	}
}

// RecordEvent records a behavior event and updates the score
func (e *Engine) RecordEvent(ctx context.Context, agentID string, eventType EventType, capability string, severity int, description string) error {
	event := &BehaviorEvent{
		ID:         uuid.New().String(),
		AgentID:    agentID,
		Type:       eventType,
		Capability: capability,
		Severity:   severity,
		Description: description,
		Timestamp:  time.Now().UTC(),
	}

	// Record in baseline
	if err := e.baseline.RecordEvent(ctx, event); err != nil {
		return err
	}

	// Update score
	_, err := e.calculateAndStoreScore(ctx, agentID)
	return err
}

// GetScore returns the current trust score for an agent
func (e *Engine) GetScore(ctx context.Context, agentID string) (*TrustScore, error) {
	e.mu.RLock()
	score, exists := e.scores[agentID]
	e.mu.RUnlock()

	if !exists {
		return e.calculateAndStoreScore(ctx, agentID)
	}

	// Recalculate if score is stale (older than 5 minutes)
	if time.Since(score.CalculatedAt) > 5*time.Minute {
		return e.calculateAndStoreScore(ctx, agentID)
	}

	return score, nil
}

// GetBaseline returns the baseline metrics for an agent
func (e *Engine) GetBaseline(ctx context.Context, agentID string) (*BaselineMetrics, error) {
	return e.baseline.GetBaseline(ctx, agentID)
}

// GetAnomalies returns detected anomalies for an agent
func (e *Engine) GetAnomalies(ctx context.Context, agentID string, unresolvedOnly bool) ([]*Anomaly, error) {
	return e.detector.GetAnomalies(ctx, agentID, unresolvedOnly)
}

// Analyze performs a full analysis for an agent and returns score with anomalies
func (e *Engine) Analyze(ctx context.Context, agentID string) (*TrustScore, []*Anomaly, error) {
	// Get baseline
	baseline, err := e.baseline.GetBaseline(ctx, agentID)
	if err != nil {
		return nil, nil, err
	}

	// Get recent events
	events, err := e.baseline.GetRecentEvents(ctx, agentID, e.config.BaselineWindow)
	if err != nil {
		return nil, nil, err
	}

	// Detect anomalies
	anomalies, err := e.detector.Detect(ctx, agentID, events, baseline)
	if err != nil {
		return nil, nil, err
	}

	// Calculate score
	trustScore, err := e.calculator.Calculate(ctx, agentID)
	if err != nil {
		return nil, anomalies, err
	}

	// Store score
	e.mu.Lock()
	e.scores[agentID] = trustScore
	e.mu.Unlock()

	return trustScore, anomalies, nil
}

// ResetScore resets the trust score for an agent
func (e *Engine) ResetScore(ctx context.Context, agentID string) error {
	e.mu.Lock()
	delete(e.scores, agentID)
	e.mu.Unlock()

	// Recalculate from baseline
	_, err := e.calculateAndStoreScore(ctx, agentID)
	return err
}

// ClearAnomalies clears all anomalies for an agent
func (e *Engine) ClearAnomalies(ctx context.Context, agentID string) error {
	return e.detector.ClearResolved(ctx, agentID)
}

// GetAllScores returns all current trust scores
func (e *Engine) GetAllScores(ctx context.Context) ([]*TrustScore, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	scores := make([]*TrustScore, 0, len(e.scores))
	for _, score := range e.scores {
		scores = append(scores, score)
	}

	return scores, nil
}

func (e *Engine) calculateAndStoreScore(ctx context.Context, agentID string) (*TrustScore, error) {
	trustScore, err := e.calculator.Calculate(ctx, agentID)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.scores[agentID] = trustScore
	e.mu.Unlock()

	return trustScore, nil
}

// Event helper methods

// RecordAllowed records a capability allowed event
func (e *Engine) RecordAllowed(ctx context.Context, agentID, capability string) error {
	return e.RecordEvent(ctx, agentID, EventCapabilityAllowed, capability, 1, "Capability allowed")
}

// RecordDenied records a capability denied event
func (e *Engine) RecordDenied(ctx context.Context, agentID, capability, reason string) error {
	return e.RecordEvent(ctx, agentID, EventCapabilityDenied, capability, 5, reason)
}

// RecordAnomaly records an anomaly detection event
func (e *Engine) RecordAnomaly(ctx context.Context, agentID string, severity int, description string) error {
	return e.RecordEvent(ctx, agentID, EventAnomalyDetected, "", severity, description)
}

// RecordCompliance records a compliance event
func (e *Engine) RecordCompliance(ctx context.Context, agentID string, passed bool) error {
	eventType := EventCompliancePass
	severity := 1
	if !passed {
		eventType = EventComplianceFail
		severity = 7
	}
	return e.RecordEvent(ctx, agentID, eventType, "", severity, "Compliance check")
}
