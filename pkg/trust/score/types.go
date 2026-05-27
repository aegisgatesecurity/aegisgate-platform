// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Score Types

package score

import (
	"time"
)

// ScoreLevel represents the trust score level
type ScoreLevel string

const (
	ScoreLevelCritical ScoreLevel = "critical" // 0-25
	ScoreLevelLow      ScoreLevel = "low"      // 26-50
	ScoreLevelMedium   ScoreLevel = "medium"   // 51-75
	ScoreLevelHigh     ScoreLevel = "high"     // 76-90
	ScoreLevelTrusted  ScoreLevel = "trusted"  // 91-100
)

// EventType represents the type of behavior event
type EventType string

const (
	EventCapabilityAllowed EventType = "capability:allowed"
	EventCapabilityDenied  EventType = "capability:denied"
	EventCapabilityAppr    EventType = "capability:approval_required"
	EventRateLimited       EventType = "capability:rate_limited"
	EventAnomalyDetected   EventType = "anomaly:detected"
	EventCompliancePass    EventType = "compliance:pass"
	EventComplianceFail    EventType = "compliance:fail"
	EventContractViolated  EventType = "contract:violated"
	EventIdentityVerified  EventType = "identity:verified"
	EventIdentityFailed    EventType = "identity:failed"
	EventError             EventType = "error:occurred"
)

// TrustScore represents a calculated trust score
type TrustScore struct {
	AgentID              string        `json:"agentId"`
	Score                float64       `json:"score"`                // 0-100
	Level                ScoreLevel    `json:"level"`                // critical/low/medium/high/trusted
	BehaviorMultiplier   float64       `json:"behaviorMultiplier"`   // 0.0-1.5
	ComplianceMultiplier float64       `json:"complianceMultiplier"` // 0.0-1.5
	BaseScore            float64       `json:"baseScore"`            // starting score
	Factors              []ScoreFactor `json:"factors"`              // breakdown of factors
	CalculatedAt         time.Time     `json:"calculatedAt"`
}

// ScoreFactor represents a factor contributing to the trust score
type ScoreFactor struct {
	Name       string  `json:"name"`
	Weight     float64 `json:"weight"`     // contribution weight
	Value      float64 `json:"value"`      // factor value
	Multiplier float64 `json:"multiplier"` // applied multiplier
}

// BehaviorEvent represents a recorded behavior event
type BehaviorEvent struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agentId"`
	Type        EventType         `json:"type"`
	Capability  string            `json:"capability,omitempty"`
	Severity    int               `json:"severity"` // 1-10
	Description string            `json:"description"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agentId"`
	Type        string    `json:"type"`
	Severity    int       `json:"severity"` // 1-10
	Description string    `json:"description"`
	Deviation   float64   `json:"deviation"` // how far from baseline
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
}

// BaselineMetrics represents baseline behavior metrics for an agent
type BaselineMetrics struct {
	AgentID          string    `json:"agentId"`
	TotalEvents      int64     `json:"totalEvents"`
	AllowedCount     int64     `json:"allowedCount"`
	DeniedCount      int64     `json:"deniedCount"`
	ApprovalReqCount int64     `json:"approvalReqCount"`
	AnomalyCount     int64     `json:"anomalyCount"`
	AvgSeverity      float64   `json:"avgSeverity"`
	SuccessRate      float64   `json:"successRate"` // allowed / total
	DailyAvgEvents   float64   `json:"dailyAvgEvents"`
	LastUpdated      time.Time `json:"lastUpdated"`
}

// Config contains trust score engine configuration
type Config struct {
	// Base score for new agents
	InitialScore float64 `json:"initialScore"`
	// Minimum score an agent can have
	MinScore float64 `json:"minScore"`
	// Maximum score an agent can have
	MaxScore float64 `json:"maxScore"`
	// How quickly scores decay over time (per day)
	DecayRate float64 `json:"decayRate"`
	// Number of events to consider for baseline
	BaselineWindow int `json:"baselineWindow"`
	// Anomaly threshold (standard deviations)
	AnomalyThreshold float64 `json:"anomalyThreshold"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		InitialScore:     100.0,
		MinScore:         0.0,
		MaxScore:         100.0,
		DecayRate:        0.1, // 10% decay per day of inactivity
		BaselineWindow:   100, // consider last 100 events
		AnomalyThreshold: 3.0, // 3 standard deviations
	}
}
