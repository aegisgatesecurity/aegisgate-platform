// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Behavioral Baseline Engine

package score

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BaselineEngine tracks and calculates behavioral baselines for agents
type BaselineEngine interface {
	RecordEvent(ctx context.Context, event *BehaviorEvent) error
	GetBaseline(ctx context.Context, agentID string) (*BaselineMetrics, error)
	UpdateBaseline(ctx context.Context, agentID string) error
	CalculateDeviation(ctx context.Context, agentID string) (float64, error)
	GetRecentEvents(ctx context.Context, agentID string, limit int) ([]*BehaviorEvent, error)
}

// InMemoryBaseline implements BaselineEngine with in-memory storage
type InMemoryBaseline struct {
	mu        sync.RWMutex
	baselines map[string]*BaselineMetrics
	events    map[string][]*BehaviorEvent
	window    int
}

// NewBaselineEngine creates a new baseline engine
func NewBaselineEngine(window int) BaselineEngine {
	if window <= 0 {
		window = 100
	}
	return &InMemoryBaseline{
		baselines: make(map[string]*BaselineMetrics),
		events:    make(map[string][]*BehaviorEvent),
		window:    window,
	}
}

func (b *InMemoryBaseline) RecordEvent(ctx context.Context, event *BehaviorEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if event.ID == "" {
		return fmt.Errorf("event ID is required")
	}
	if event.AgentID == "" {
		return fmt.Errorf("agent ID is required")
	}

	b.events[event.AgentID] = append(b.events[event.AgentID], event)

	if len(b.events[event.AgentID]) > b.window {
		b.events[event.AgentID] = b.events[event.AgentID][len(b.events[event.AgentID])-b.window:]
	}

	b.updateBaselineLocked(event.AgentID)
	return nil
}

func (b *InMemoryBaseline) GetBaseline(ctx context.Context, agentID string) (*BaselineMetrics, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	baseline, exists := b.baselines[agentID]
	if !exists {
		return &BaselineMetrics{AgentID: agentID, LastUpdated: time.Now().UTC()}, nil
	}
	return baseline, nil
}

func (b *InMemoryBaseline) UpdateBaseline(ctx context.Context, agentID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.updateBaselineLocked(agentID)
	return nil
}

func (b *InMemoryBaseline) CalculateDeviation(ctx context.Context, agentID string) (float64, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	baseline, exists := b.baselines[agentID]
	if !exists || baseline.TotalEvents < 10 {
		return 0.0, nil
	}

	events := b.events[agentID]
	if len(events) == 0 {
		return 0.0, nil
	}

	var currentDenied, currentAnomaly int64
	for _, e := range events {
		if e.Type == EventCapabilityDenied {
			currentDenied++
		}
		if e.Type == EventAnomalyDetected {
			currentAnomaly++
		}
	}

	currentDeniedRate := float64(currentDenied) / float64(len(events))
	baselineDeniedRate := float64(baseline.DeniedCount) / float64(baseline.TotalEvents)

	deviation := currentDeniedRate - baselineDeniedRate
	if deviation < 0 {
		deviation = -deviation
	}
	return deviation, nil
}

func (b *InMemoryBaseline) GetRecentEvents(ctx context.Context, agentID string, limit int) ([]*BehaviorEvent, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 {
		limit = 10
	}

	events := b.events[agentID]
	if len(events) == 0 {
		return []*BehaviorEvent{}, nil
	}

	start := 0
	if len(events) > limit {
		start = len(events) - limit
	}
	return events[start:], nil
}

func (b *InMemoryBaseline) updateBaselineLocked(agentID string) {
	events := b.events[agentID]
	if len(events) == 0 {
		return
	}

	baseline := b.baselines[agentID]
	if baseline == nil {
		baseline = &BaselineMetrics{AgentID: agentID}
	}

	baseline.TotalEvents = 0
	baseline.AllowedCount = 0
	baseline.DeniedCount = 0
	baseline.ApprovalReqCount = 0
	baseline.AnomalyCount = 0
	var totalSeverity int64

	for _, e := range events {
		baseline.TotalEvents++
		totalSeverity += int64(e.Severity)

		switch e.Type {
		case EventCapabilityAllowed, EventIdentityVerified, EventCompliancePass:
			baseline.AllowedCount++
		case EventCapabilityDenied, EventIdentityFailed:
			baseline.DeniedCount++
		case EventCapabilityAppr:
			baseline.ApprovalReqCount++
		case EventAnomalyDetected, EventContractViolated:
			baseline.AnomalyCount++
		}
	}

	if baseline.TotalEvents > 0 {
		baseline.AvgSeverity = float64(totalSeverity) / float64(baseline.TotalEvents)
		baseline.SuccessRate = float64(baseline.AllowedCount) / float64(baseline.TotalEvents)
	}

	baseline.LastUpdated = time.Now().UTC()
	b.baselines[agentID] = baseline
}
