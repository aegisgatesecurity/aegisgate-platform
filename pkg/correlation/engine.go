// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Correlation Engine
// ============================================================================

package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Engine provides cross-protocol threat correlation
type Engine struct {
	cfg         *Config
	logger      *slog.Logger
	mu          sync.RWMutex
	events      map[string][]*Event
	patterns    map[string]*ThreatPattern
	lastCleanup time.Time
}

// NewEngine creates a new correlation engine
func NewEngine() *Engine {
	return NewEngineWithConfig(DefaultConfig())
}

// NewEngineWithConfig creates engine with custom configuration
func NewEngineWithConfig(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	e := &Engine{
		cfg:      cfg,
		logger:   slog.Default().With("component", "correlation-engine"),
		events:   make(map[string][]*Event),
		patterns: make(map[string]*ThreatPattern),
	}

	// Register default patterns
	e.registerDefaultPatterns()

	return e
}

// registerDefaultPatterns registers built-in threat patterns
func (e *Engine) registerDefaultPatterns() {
	e.patterns["mcp_error_injection"] = &ThreatPattern{
		ID:          "mcp_error_injection",
		Name:        "MCP Error Injection",
		Description: "MCP error followed by A2A request",
		Severity:    "high",
		Weight:      0.8,
		Indicators:  []string{"mcp_error", "a2a_request"},
		TimeWindow:  30 * time.Second,
	}

	e.patterns["task_hijacking"] = &ThreatPattern{
		ID:          "task_hijacking",
		Name:        "Task Hijacking",
		Description: "A2A message triggers ANP task creation",
		Severity:    "critical",
		Weight:      0.9,
		Indicators:  []string{"a2a_message", "anp_task_create"},
		TimeWindow:  1 * time.Minute,
	}

	e.patterns["browser_escalation"] = &ThreatPattern{
		ID:          "browser_escalation",
		Name:        "Browser Escalation",
		Description: "ANP task enables browser control",
		Severity:    "critical",
		Weight:      0.95,
		Indicators:  []string{"anp_task", "computer_use"},
		TimeWindow:  2 * time.Minute,
	}

	e.patterns["rate_anomaly"] = &ThreatPattern{
		ID:          "rate_anomaly",
		Name:        "Rate Anomaly",
		Description: "Coordinated attack across protocols",
		Severity:    "high",
		Weight:      0.7,
		Indicators:  []string{"rate_spike"},
		TimeWindow:  1 * time.Minute,
	}

	e.patterns["capability_creep"] = &ThreatPattern{
		ID:          "capability_creep",
		Name:        "Capability Creep",
		Description: "Agent uses more capabilities over time",
		Severity:    "medium",
		Weight:      0.6,
		Indicators:  []string{"capability_delta"},
		TimeWindow:  10 * time.Minute,
	}
}

// RecordEvent records a security event for correlation
func (e *Engine) RecordEvent(ctx context.Context, event *Event) error {
	if event == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Store event
	key := event.AgentID + ":" + event.SessionID
	e.events[key] = append(e.events[key], event)

	// Cleanup old events periodically
	if time.Since(e.lastCleanup) > 5*time.Minute {
		e.cleanup()
		e.lastCleanup = time.Now()
	}

	e.logger.Debug("Event recorded", "protocol", event.Protocol, "type", event.EventType, "agent", event.AgentID)

	return nil
}

// Analyze performs correlation analysis on recent events
func (e *Engine) Analyze(ctx context.Context, agentID, sessionID string) (*CorrelationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := NewCorrelationResult()
	key := agentID + ":" + sessionID

	events, exists := e.events[key]
	if !exists || len(events) == 0 {
		return result, nil
	}

	// Get events within correlation window
	windowStart := time.Now().Add(-e.cfg.CorrelationWindow)
	recentEvents := make([]*Event, 0)
	for _, evt := range events {
		if evt.Timestamp.After(windowStart) {
			recentEvents = append(recentEvents, evt)
		}
	}

	// Check for patterns
	if e.cfg.EnablePatternMatching {
		e.matchPatterns(recentEvents, result)
	}

	// Check for rate anomalies
	if e.cfg.EnableRateCorrelation {
		e.checkRateAnomaly(recentEvents, result)
	}

	return result, nil
}

// ListEventsBySession returns all events for the
// given session ID, across all agents. The events
// are returned in insertion order (the caller is
// expected to sort by timestamp if needed).
//
// This is the data source for the SOC incident
// timeline (TODO-502). The engine stores events
// keyed by `agentID:sessionID`; this method scans
// all keys and filters by session ID match.
//
// Returns nil (not an error) if no events match.
// The caller is responsible for sorting.
func (e *Engine) ListEventsBySession(_ context.Context, sessionID string) ([]*Event, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("correlation: ListEventsBySession: sessionID is required")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	var result []*Event
	for _, events := range e.events {
		for _, evt := range events {
			if evt.SessionID == sessionID {
				result = append(result, evt)
			}
		}
	}
	return result, nil
}

// matchPatterns matches events against threat patterns
func (e *Engine) matchPatterns(events []*Event, result *CorrelationResult) {
	for _, pattern := range e.patterns {
		if pattern.Weight < e.cfg.MinPatternWeight {
			continue
		}

		if e.matchesPattern(events, pattern) {
			result.MatchedPatterns = append(result.MatchedPatterns, pattern.ID)
			result.Score += pattern.Weight

			if pattern.Severity == "critical" {
				result.Decision = DecisionBlock
				result.Reason = fmt.Sprintf("Critical threat pattern: %s", pattern.Name)
				result.Severity = "critical"
			} else if pattern.Severity == "high" && result.Severity != "critical" {
				if result.Decision != DecisionBlock {
					result.Decision = DecisionAlert
					result.Reason = fmt.Sprintf("High threat pattern: %s", pattern.Name)
					result.Severity = "high"
				}
			}
		}
	}
}

// matchesPattern checks if events match a pattern
func (e *Engine) matchesPattern(events []*Event, pattern *ThreatPattern) bool {
	if len(events) < len(pattern.Indicators) {
		return false
	}

	windowStart := time.Now().Add(-pattern.TimeWindow)
	indicatorMatches := make(map[string]bool)

	for _, evt := range events {
		if evt.Timestamp.Before(windowStart) {
			continue
		}
		for _, indicator := range pattern.Indicators {
			if e.eventMatchesIndicator(evt, indicator) {
				indicatorMatches[indicator] = true
			}
		}
	}

	// All indicators must match
	for _, indicator := range pattern.Indicators {
		if !indicatorMatches[indicator] {
			return false
		}
	}

	return true
}

// eventMatchesIndicator checks if an event matches an indicator
func (e *Engine) eventMatchesIndicator(event *Event, indicator string) bool {
	switch indicator {
	case "mcp_error":
		return event.Protocol == "mcp" && (event.EventType == "error" || event.Decision == "block")
	case "a2a_request":
		return event.Protocol == "a2a" && event.EventType == "request"
	case "a2a_message":
		return event.Protocol == "a2a"
	case "anp_task_create":
		return event.Protocol == "anp" && event.EventType == "task_create"
	case "anp_task":
		return event.Protocol == "anp"
	case "computer_use":
		return event.Protocol == "computeruse"
	case "rate_spike":
		return event.Severity == "high" && event.Decision == "block"
	case "capability_delta":
		return event.EventType == "capability_change"
	}
	return false
}

// checkRateAnomaly checks for rate anomalies across protocols
func (e *Engine) checkRateAnomaly(events []*Event, result *CorrelationResult) {
	if len(events) < 5 {
		return
	}

	// Count events by protocol
	protocolCounts := make(map[string]int)
	for _, evt := range events {
		protocolCounts[evt.Protocol]++
	}

	// Check if any protocol has unusual activity
	for protocol, count := range protocolCounts {
		if count >= 3 && float64(count)/float64(len(events)) > 0.5 {
			if !containsPattern(result.MatchedPatterns, "rate_anomaly") {
				result.MatchedPatterns = append(result.MatchedPatterns, "rate_anomaly")
				result.Score += 0.3
			}
			result.Metadata["rate_anomaly_protocol"] = protocol
			result.Metadata["rate_anomaly_count"] = fmt.Sprintf("%d", count)
		}
	}
}

// cleanup removes old events
func (e *Engine) cleanup() {
	cutoff := time.Now().Add(-e.cfg.CorrelationWindow * 2)

	for key, events := range e.events {
		filtered := make([]*Event, 0)
		for _, evt := range events {
			if evt.Timestamp.After(cutoff) {
				filtered = append(filtered, evt)
			}
		}
		if len(filtered) == 0 {
			delete(e.events, key)
		} else {
			e.events[key] = filtered
		}
	}
}

func containsPattern(patterns []string, pattern string) bool {
	for _, p := range patterns {
		if p == pattern {
			return true
		}
	}
	return false
}
