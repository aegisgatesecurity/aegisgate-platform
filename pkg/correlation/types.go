// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Cross-Protocol Threat Correlation
// ============================================================================

package correlation

import (
	"fmt"
	"time"
)

// Event represents a security event from any protocol
type Event struct {
	ID        string
	Protocol  string // "http", "mcp", "a2a", "anp", "computeruse"
	AgentID   string
	SessionID string
	EventType string
	Timestamp time.Time
	Data      map[string]interface{}
	Severity  string
	Decision  string
	Metadata  map[string]string
}

// NewEvent creates a new security event
func NewEvent(protocol, eventType, agentID, sessionID string) *Event {
	return &Event{
		ID:        fmt.Sprintf("evt_%d_%s", time.Now().UnixNano(), protocol),
		Protocol:  protocol,
		AgentID:   agentID,
		SessionID: sessionID,
		EventType: eventType,
		Timestamp: time.Now(),
		Data:      make(map[string]interface{}),
		Severity:  "low",
		Metadata:  make(map[string]string),
	}
}

// ThreatPattern represents a correlated threat pattern
type ThreatPattern struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Weight      float64
	Indicators  []string
	TimeWindow  time.Duration
}

// GuardDecision represents the decision of correlation analysis
type GuardDecision string

const (
	DecisionAllow           GuardDecision = "allow"
	DecisionBlock           GuardDecision = "block"
	DecisionRequireApproval GuardDecision = "require_approval"
	DecisionAlert           GuardDecision = "alert"
)

// CorrelationResult represents the result of correlation analysis
type CorrelationResult struct {
	Decision        GuardDecision
	Reason          string
	MatchedPatterns []string
	Severity        string
	Score           float64
	Metadata        map[string]string
}

// NewCorrelationResult creates a new correlation result
func NewCorrelationResult() *CorrelationResult {
	return &CorrelationResult{
		Decision:        DecisionAllow,
		MatchedPatterns: []string{},
		Metadata:        make(map[string]string),
	}
}

// Config holds correlation engine configuration
type Config struct {
	// Pattern matching
	EnablePatternMatching bool
	MinPatternWeight      float64

	// Rate correlation
	EnableRateCorrelation   bool
	RateThresholdMultiplier float64

	// Time window for correlation
	CorrelationWindow time.Duration

	// Alert settings
	AlertOnHighSeverity   bool
	AlertOnMediumSeverity bool
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		EnablePatternMatching:   true,
		MinPatternWeight:        0.5,
		EnableRateCorrelation:   true,
		RateThresholdMultiplier: 2.0,
		CorrelationWindow:       5 * time.Minute,
		AlertOnHighSeverity:     true,
		AlertOnMediumSeverity:   false,
	}
}
