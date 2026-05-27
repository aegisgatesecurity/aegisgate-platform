// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Anomaly Detection Engine

package score

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AnomalyDetector detects anomalies in agent behavior
type AnomalyDetector struct {
	mu        sync.RWMutex
	anomalies map[string][]*Anomaly
	config    *Config
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *Config) *AnomalyDetector {
	if config == nil {
		config = DefaultConfig()
	}
	return &AnomalyDetector{
		anomalies: make(map[string][]*Anomaly),
		config:    config,
	}
}

// AnomalyType represents the type of anomaly
type AnomalyType string

const (
	AnomalyTypeRateChange AnomalyType = "rate_change"
	AnomalyTypeCapability AnomalyType = "capability_change"
	AnomalyTypeBehavior   AnomalyType = "behavior_drift"
	AnomalyTypeFailure    AnomalyType = "failure_spike"
	AnomalyTypeUnknown    AnomalyType = "unknown"
)

// Detect analyzes recent events and returns detected anomalies
func (d *AnomalyDetector) Detect(ctx context.Context, agentID string, recentEvents []*BehaviorEvent, baseline *BaselineMetrics) ([]*Anomaly, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var anomalies []*Anomaly

	// Check for rate changes
	if rateAnomaly := d.detectRateChange(agentID, recentEvents, baseline); rateAnomaly != nil {
		anomalies = append(anomalies, rateAnomaly)
	}

	// Check for capability changes
	if capAnomaly := d.detectCapabilityChange(agentID, recentEvents, baseline); capAnomaly != nil {
		anomalies = append(anomalies, capAnomaly)
	}

	// Check for failure spikes
	if failAnomaly := d.detectFailureSpike(agentID, recentEvents, baseline); failAnomaly != nil {
		anomalies = append(anomalies, failAnomaly)
	}

	// Check for behavior drift
	if driftAnomaly := d.detectBehaviorDrift(agentID, recentEvents, baseline); driftAnomaly != nil {
		anomalies = append(anomalies, driftAnomaly)
	}

	// Store anomalies
	if len(anomalies) > 0 {
		d.anomalies[agentID] = append(d.anomalies[agentID], anomalies...)
	}

	return anomalies, nil
}

// detectRateChange detects if the rate of events has changed significantly
func (d *AnomalyDetector) detectRateChange(agentID string, events []*BehaviorEvent, baseline *BaselineMetrics) *Anomaly {
	if baseline == nil || baseline.DailyAvgEvents == 0 {
		return nil
	}

	// Calculate current rate
	if len(events) == 0 {
		return nil
	}

	currentRate := float64(len(events))
	baselineRate := baseline.DailyAvgEvents

	// Check if current rate is significantly different (more than 3x or less than 1/3)
	if currentRate > baselineRate*3 || currentRate < baselineRate/3 {
		return &Anomaly{
			ID:          uuid.New().String(),
			AgentID:     agentID,
			Type:        string(AnomalyTypeRateChange),
			Severity:    5,
			Description: fmt.Sprintf("Event rate changed significantly: current=%.1f, baseline=%.1f", currentRate, baselineRate),
			Deviation:   math.Abs(currentRate-baselineRate) / baselineRate,
			Timestamp:   time.Now().UTC(),
			Resolved:    false,
		}
	}

	return nil
}

// detectCapabilityChange detects if agent is using different capabilities
func (d *AnomalyDetector) detectCapabilityChange(agentID string, events []*BehaviorEvent, baseline *BaselineMetrics) *Anomaly {
	if len(events) < 5 {
		return nil
	}

	// Count capabilities in recent events
	capCount := make(map[string]int)
	for _, e := range events {
		if e.Capability != "" {
			capCount[e.Capability]++
		}
	}

	// If agent is suddenly using many new capabilities, flag it
	if len(capCount) > 10 {
		return &Anomaly{
			ID:          uuid.New().String(),
			AgentID:     agentID,
			Type:        string(AnomalyTypeCapability),
			Severity:    7,
			Description: fmt.Sprintf("Agent using %d different capabilities (unusual pattern)", len(capCount)),
			Deviation:   float64(len(capCount)) / 10.0,
			Timestamp:   time.Now().UTC(),
			Resolved:    false,
		}
	}

	return nil
}

// detectFailureSpike detects sudden increase in failures
func (d *AnomalyDetector) detectFailureSpike(agentID string, events []*BehaviorEvent, baseline *BaselineMetrics) *Anomaly {
	if len(events) == 0 {
		return nil
	}

	// Count failures
	var failures int
	for _, e := range events {
		if e.Type == EventCapabilityDenied || e.Type == EventIdentityFailed || e.Type == EventError {
			failures++
		}
	}

	failureRate := float64(failures) / float64(len(events))
	baselineFailureRate := 0.05 // Default 5% baseline

	if baseline != nil && baseline.TotalEvents > 0 {
		baselineFailureRate = float64(baseline.DeniedCount) / float64(baseline.TotalEvents)
	}

	// If failure rate is more than 5x baseline, flag it
	if failureRate > baselineFailureRate*5 && failureRate > 0.3 {
		return &Anomaly{
			ID:          uuid.New().String(),
			AgentID:     agentID,
			Type:        string(AnomalyTypeFailure),
			Severity:    8,
			Description: fmt.Sprintf("Failure spike detected: %.1f%% failures (baseline: %.1f%%)", failureRate*100, baselineFailureRate*100),
			Deviation:   failureRate / baselineFailureRate,
			Timestamp:   time.Now().UTC(),
			Resolved:    false,
		}
	}

	return nil
}

// detectBehaviorDrift detects gradual changes in behavior patterns
func (d *AnomalyDetector) detectBehaviorDrift(agentID string, events []*BehaviorEvent, baseline *BaselineMetrics) *Anomaly {
	if baseline == nil || baseline.TotalEvents < 20 {
		return nil
	}

	// Calculate average severity in recent events
	if len(events) == 0 {
		return nil
	}

	var totalSev int
	for _, e := range events {
		totalSev += e.Severity
	}
	avgSev := float64(totalSev) / float64(len(events))

	// If average severity has increased significantly
	if avgSev > baseline.AvgSeverity*2 && avgSev > 5 {
		return &Anomaly{
			ID:          uuid.New().String(),
			AgentID:     agentID,
			Type:        string(AnomalyTypeBehavior),
			Severity:    6,
			Description: fmt.Sprintf("Behavior drift detected: avg severity %.1f (baseline: %.1f)", avgSev, baseline.AvgSeverity),
			Deviation:   (avgSev - baseline.AvgSeverity) / baseline.AvgSeverity,
			Timestamp:   time.Now().UTC(),
			Resolved:    false,
		}
	}

	return nil
}

// GetAnomalies returns all anomalies for an agent
func (d *AnomalyDetector) GetAnomalies(ctx context.Context, agentID string, unresolvedOnly bool) ([]*Anomaly, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	anomalies := d.anomalies[agentID]
	if unresolvedOnly {
		var unresolved []*Anomaly
		for _, a := range anomalies {
			if !a.Resolved {
				unresolved = append(unresolved, a)
			}
		}
		return unresolved, nil
	}

	return anomalies, nil
}

// ResolveAnomaly marks an anomaly as resolved
func (d *AnomalyDetector) ResolveAnomaly(ctx context.Context, agentID, anomalyID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	anomalies := d.anomalies[agentID]
	for _, a := range anomalies {
		if a.ID == anomalyID {
			a.Resolved = true
			return nil
		}
	}

	return fmt.Errorf("anomaly not found: %s", anomalyID)
}

// ClearResolved removes resolved anomalies from storage
func (d *AnomalyDetector) ClearResolved(ctx context.Context, agentID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var unresolved []*Anomaly
	for _, a := range d.anomalies[agentID] {
		if !a.Resolved {
			unresolved = append(unresolved, a)
		}
	}
	d.anomalies[agentID] = unresolved

	return nil
}
